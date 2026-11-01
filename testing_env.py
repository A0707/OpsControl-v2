"""Isolation des tests : base, journal SSH et dossier SSH temporaires AVANT tout import d'app.

app.py ouvre sa base (COCKPIT_DB) dès son import. Sous « unittest discover », le premier
module de test qui importe app fixe donc la base pour toute la suite : test_platform
posait bien une base temporaire, mais test_app_context (importé avant lui, ordre
alphabétique) avait déjà lié app à data/state.sqlite3. Les tests écrivaient alors dans la
VRAIE base de l'instance, réglage d'actualisation compris (constaté le 06/10 : passé de
manuel à 60 s, d'où des collectes automatiques non voulues sur le parc).

Chaque module de test qui importe app importe ce module en premier. Les valeurs déjà
définies ne sont conservées que si elles restent dans le dossier temporaire.
"""
import atexit
import os
import shutil
import tempfile
from pathlib import Path

import re

DIRECTORY = tempfile.mkdtemp(prefix='opscontrol-tests-')
atexit.register(shutil.rmtree, DIRECTORY, ignore_errors=True)
# Le parc local et une variable d’exploitation ne doivent jamais entrer dans les tests.
INVENTORY = Path(DIRECTORY) / 'hosts.yaml'
shutil.copyfile(Path(__file__).with_name('hosts.example.yaml'), INVENTORY)
os.environ['INFRAOPS_INVENTORY'] = str(INVENTORY)
# Référentiel des batchs : l'exemple fictif, jamais data/batch_catalog.yaml.
os.environ['INFRAOPS_BATCH_CATALOG'] = str(Path(__file__).with_name('batch_catalog.example.yaml'))
TEMPORARY_ROOT = Path(tempfile.gettempdir()).resolve()


def _test_root():
    """Seule racine acceptée pour les chemins hérités : le dossier de CETTE suite, ou celui
    de la suite parente pour un sous-processus de test. Toute la racine TEMP ne suffit
    plus : un autre dossier temporaire peut appartenir à une instance (OC-AUDIT-019)."""
    inherited = os.environ.get('OPSCONTROL_TEST_ROOT')
    if inherited:
        path = Path(inherited).resolve()
        if path.name.startswith('opscontrol-tests-') and path.parent == TEMPORARY_ROOT and path.is_dir():
            return path
    return Path(DIRECTORY).resolve()


TEST_ROOT = _test_root()
os.environ['OPSCONTROL_TEST_ROOT'] = str(TEST_ROOT)


def _isolated(name, default):
    """Une valeur déjà posée n'est conservée que si elle reste sous le dossier de la suite :
    un shell d'exploitation (COCKPIT_DB=/opt/infraops/data/state.sqlite3) ne doit jamais
    rediriger la suite de tests vers la vraie base (audit DB-10)."""
    value = os.environ.get(name)
    if value:
        try:
            Path(value).resolve().relative_to(TEST_ROOT)
            return
        except ValueError:
            pass
    os.environ[name] = default


_isolated('COCKPIT_DB', os.path.join(DIRECTORY, 'test.sqlite3'))
_isolated('COCKPIT_AUDIT', os.path.join(DIRECTORY, 'audit.log'))
_isolated('COCKPIT_SSH_DIR', DIRECTORY)
# Valeurs imposées, jamais héritées : un shell d'exploitation (INFRAOPS_AUTO_INTERVAL=60)
# réactivait sinon les collectes automatiques pendant les tests (OC-AUDIT-019).
os.environ['INFRAOPS_AUTO_INTERVAL'] = '0'
os.environ['INFRAOPS_INCIDENT_SYNC'] = '0'
os.environ['GLPI_STATUS_SYNC_SECONDS'] = '0'
# Coffre DPAPI factice : app.py charge le coffre de LOCALAPPDATA à l'import, celui du
# compte courant sur un poste d'exploitation. Les navigateurs de Playwright restent trouvés.
_real_local = os.environ.get('LOCALAPPDATA')
if _real_local and 'PLAYWRIGHT_BROWSERS_PATH' not in os.environ:
    os.environ['PLAYWRIGHT_BROWSERS_PATH'] = os.path.join(_real_local, 'ms-playwright')
os.environ['LOCALAPPDATA'] = os.path.join(DIRECTORY, 'localappdata')
# Identifiants hérités du shell retirés : chaque test pose les siens (patch.dict).
SECRET_NAME = re.compile(r'^(INFRAOPS|OPSCONTROL|GLPI|COCKPIT|BACULA|ZABBIX|WAZUH|PROXMOX|ELASTIC)\w*'
                         r'(AUTH|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_?KEY)\w*$', re.I)
for _name in [n for n in os.environ if SECRET_NAME.match(n)]:
    del os.environ[_name]


# --- Garde-fou réseau (audit TST-01) ---------------------------------------------------
# AGENTS.md interdit tout appel réseau réel dans les tests ; jusqu'ici, seule la discipline
# de chaque test le garantissait. Toute connexion TCP/UDP ou résolution DNS vers une adresse
# non locale échoue désormais immédiatement, quel que soit le test qui l'oublie. Les
# sous-processus (ssh, ping) restent à simuler dans chaque test : ils ne passent pas par ici.
import ipaddress
import socket

_LOCAL_NAMES = {'localhost', 'localhost.localdomain', ''}


class RealNetworkForbidden(OSError):
    pass


def _is_local(host) -> bool:
    if host is None:
        return True
    host = host.decode() if isinstance(host, bytes) else str(host)
    if host.lower() in _LOCAL_NAMES:
        return True
    try:
        address = ipaddress.ip_address(host.split('%')[0])
    except ValueError:
        return False
    return address.is_loopback or address.is_unspecified


def _guarded_connect(original):
    def connect(self, address):
        if isinstance(address, tuple) and not _is_local(address[0]):
            raise RealNetworkForbidden(f'Appel réseau réel interdit pendant les tests : {address[0]}')
        return original(self, address)
    return connect


def _guarded_lookup(original):
    def lookup(host, *args, **kwargs):
        literal = False
        try:
            ipaddress.ip_address(str(host).split('%')[0])
            literal = True
        except ValueError:
            pass
        if not literal and not _is_local(host):
            raise socket.gaierror(socket.EAI_NONAME, f'Résolution DNS réelle interdite pendant les tests : {host}')
        return original(host, *args, **kwargs)
    return lookup


if not getattr(socket.socket.connect, '_opscontrol_guard', False):
    socket.socket.connect = _guarded_connect(socket.socket.connect)
    socket.socket.connect_ex = _guarded_connect(socket.socket.connect_ex)
    socket.socket.connect._opscontrol_guard = True
    socket.getaddrinfo = _guarded_lookup(socket.getaddrinfo)
    socket.gethostbyname = _guarded_lookup(socket.gethostbyname)
    # DNS inverse (découverte réseau) : même une adresse littérale interroge le résolveur.
    _reverse = socket.gethostbyaddr

    def _guarded_reverse(host):
        if not _is_local(host):
            raise socket.herror(1, f'DNS inverse réel interdit pendant les tests : {host}')
        return _reverse(host)
    socket.gethostbyaddr = _guarded_reverse

    # UDP sans connect() (syslog, DNS, SNMP) : sendto/sendmsg échappaient au garde-fou (OC-AUDIT-018).
    def _refuse_remote(address):
        if isinstance(address, tuple) and not _is_local(address[0]):
            raise RealNetworkForbidden(f'Envoi réseau réel interdit pendant les tests : {address[0]}')
    _sendto = socket.socket.sendto

    def _guarded_sendto(self, data, *rest):   # sendto(data, address) ou (data, flags, address)
        _refuse_remote(rest[-1] if rest else None)
        return _sendto(self, data, *rest)
    socket.socket.sendto = _guarded_sendto
    _sendmsg = getattr(socket.socket, 'sendmsg', None)   # absent sous Windows
    if _sendmsg is not None:
        def _guarded_sendmsg(self, *args):    # sendmsg(buffers, ancdata, flags, address)
            _refuse_remote(args[3] if len(args) > 3 else None)
            return _sendmsg(self, *args)
        socket.socket.sendmsg = _guarded_sendmsg


# --- Outils réseau externes (audit OC-AUDIT-018) ---------------------------------------------
# Un test qui oublie de simuler subprocess lançait un vrai ssh ou ping vers le parc. Ces
# outils sont refusés à la source (Popen), sauf les lectures de configuration locales
# (ssh -G, ssh -V). Un test qui simule subprocess.run n'atteint jamais ce point.
import subprocess

NETWORK_TOOLS = {'ssh', 'ping', 'ping6', 'scp', 'sftp', 'ssh-keyscan', 'curl', 'wget', 'nc', 'ncat',
                 'telnet', 'nslookup', 'dig', 'host', 'tracert', 'traceroute', 'tracepath', 'nmap'}


def network_tool(args) -> str | None:
    """Nom de l'outil réseau qu'une commande lancerait réellement, sinon None."""
    if isinstance(args, (str, bytes)):        # commande shell : premier mot, puis ses options
        argv = os.fsdecode(args).split()
    elif isinstance(args, os.PathLike):
        argv = [os.fspath(args)]
    else:
        argv = [os.fsdecode(a) if isinstance(a, (str, bytes, os.PathLike)) else str(a) for a in (args or [])]
    if not argv:
        return None
    name = re.sub(r'\.exe$', '', os.path.basename(argv[0].strip('"')).lower())
    if name not in NETWORK_TOOLS:
        return None
    rest = argv[1:]
    if name == 'ssh' and any(a in ('-G', '-V') for a in rest):
        return None
    return name


if not getattr(subprocess.Popen, '_opscontrol_guard', False):
    class _GuardedPopen(subprocess.Popen):
        _opscontrol_guard = True

        def __init__(self, args, *rest, **kwargs):
            tool = network_tool(args)
            if tool:
                raise RealNetworkForbidden(f'Outil réseau réel interdit pendant les tests : {tool} (simuler subprocess)')
            super().__init__(args, *rest, **kwargs)
    subprocess.Popen = _GuardedPopen
