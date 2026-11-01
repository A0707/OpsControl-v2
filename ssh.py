"""
Runner SSH en lecture seule pour le Cockpit Example Organization (v2.0).

Principe de sécurité central :
le client ne transmet JAMAIS de commande brute. Il choisit une opération
nommée (df, cron, os, ...) que ce module mappe vers une commande fixe,
non paramétrable par l'appelant. Toute tentative d'opération hors allowlist
lève une erreur. Chaque exécution est journalisée (audit BAM).
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import threading
import time
import subprocess
import shutil
import re
import signal
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

try:
    import paramiko
except ImportError:
    paramiko = None

# --- Allowlist : nom d'opération -> commande fixe (lecture seule) -----------
OPERATIONS: dict[str, str] = {
    "metrics": "LC_ALL=C; export LC_ALL; head -n 1 /proc/stat; sleep 1; head -n 1 /proc/stat; cat /proc/meminfo",
    "services": "LC_ALL=C systemctl list-units --all --type=service --no-pager --no-legend --plain",
    "os":       "cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null",
    "df":       "df -hP",
    "cron":     "crontab -l 2>/dev/null",
    "uptime":   "uptime",
    "loglarge": (
        "find /var/batch -type f -name '*.log' -size +100M "
        "-printf '%TY-%Tm-%Td %10s %p\\n' 2>/dev/null | sort"
    ),
}

AUDIT_PATH = Path(os.environ.get("COCKPIT_AUDIT", "audit.log"))
# Rotation du journal : 10 Mo par fichier, 30 archives conservees (310 Mo au plus).
# Avec 5 archives et la commande complete dans chaque ligne, l'historique ne couvrait
# qu'environ 24 h (mesure du 05/10) : trop court pour enqueter sur un incident.
AUDIT_MAX_BYTES = int(os.environ.get("COCKPIT_AUDIT_MAX_BYTES", 10 * 1024 * 1024))
AUDIT_KEEP = int(os.environ.get("COCKPIT_AUDIT_KEEP", 30))
_audit_lock = threading.Lock()


def audit(host: str, op: str, cmd: str, rc, duration_ms: int,
          requester: str, ok: bool, err: str = "", user=None, port=None) -> None:
    """Journalise chaque appel SSH en JSON lines (horodatage UTC).

    La commande est identifiee par l'operation (liste fermee OPERATIONS) et son empreinte
    `cmd_sha` (12 premiers caracteres du SHA-256) : la meme commande, longue et fixe,
    n'est plus recopiee dans chaque ligne. Le texte d'erreur passe par redact().
    """
    from audit_engine import redact  # import tardif : audit_engine importe ce module
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "requester": requester,
        "host": host,
        "ssh_user": user,
        "ssh_port": port,
        "op": op,
        "cmd_sha": hashlib.sha256(str(cmd).encode("utf-8")).hexdigest()[:12],
        "rc": rc,
        "ok": ok,
        "duration_ms": duration_ms,
        "err": redact(err)[:300] if err else "",
    }
    with _audit_lock:
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        _rotate_audit()
        with AUDIT_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _rotate_audit() -> None:
    """Fait tourner le journal d'audit au-delà de AUDIT_MAX_BYTES.

    Appelé sous _audit_lock. Sans rotation, ce fichier grossit indéfiniment :
    mesuré à 24 Mo en quelques jours d'exploitation sur 84 serveurs. On conserve
    AUDIT_KEEP archives (.1 la plus récente) ; la preuve d'audit reste donc
    disponible, mais bornée.
    """
    try:
        if not AUDIT_PATH.exists() or AUDIT_PATH.stat().st_size < AUDIT_MAX_BYTES:
            return
        oldest = AUDIT_PATH.with_suffix(AUDIT_PATH.suffix + '.%d' % AUDIT_KEEP)
        if oldest.exists():
            oldest.unlink()
        for index in range(AUDIT_KEEP - 1, 0, -1):
            source = AUDIT_PATH.with_suffix(AUDIT_PATH.suffix + '.%d' % index)
            if source.exists():
                source.replace(AUDIT_PATH.with_suffix(AUDIT_PATH.suffix + '.%d' % (index + 1)))
        AUDIT_PATH.replace(AUDIT_PATH.with_suffix(AUDIT_PATH.suffix + '.1'))
    except OSError:
        # Une rotation impossible (fichier verrouillé, disque plein) ne doit
        # jamais empêcher d'écrire la ligne d'audit elle-même.
        pass


@dataclass
class SSHConfig:
    user: str
    key_path: str
    port: int = 22
    timeout: int = 6
    strict_host_key: bool = True
    users: tuple[str, ...] = ()
    ports: tuple[int, ...] = ()
    transport: str = "openssh"
    target: str = ""
    config_path: str = ""


@dataclass
class RunResult:
    ok: bool
    rc: int | None
    stdout: str
    stderr: str
    duration_ms: int
    error_kind: str = ""


def tcp_reachable(ip: str, port: int, timeout: float = 2.0, details: dict | None = None):
    """Sonde TCP rapide (avant tentative SSH) -> (joignable, latence_ms).

    `details` (facultatif) reçoit la cause d'un échec (audit UI du 31/10, fiche 08.1) :
    « refused » (port fermé, RST), « timeout » (filtré ou hôte muet), « unreachable ».
    """
    t0 = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True, int((time.perf_counter() - t0) * 1000)
    except OSError as exc:
        if details is not None:
            details['failure'] = ('refused' if isinstance(exc, ConnectionRefusedError)
                                  else 'timeout' if isinstance(exc, TimeoutError) else 'unreachable')
        return False, None


def _client(cfg: SSHConfig) -> paramiko.SSHClient:
    c = paramiko.SSHClient()
    c.load_system_host_keys()
    # En prod : RejectPolicy (l'hôte doit être dans known_hosts).
    policy = paramiko.RejectPolicy()
    c.set_missing_host_key_policy(policy)
    return c


def run_paramiko(ip: str, op: str, cfg: SSHConfig, requester: str = "local") -> RunResult:
    if op not in OPERATIONS:
        audit(ip, op, "", None, 0, requester, False, "Opération refusée", cfg.user, cfg.port)
        raise ValueError(f"opération non autorisée: {op!r}")

    cmd = OPERATIONS[op]
    if paramiko is None:
        raise RuntimeError('Paramiko indisponible. Utiliser transport: openssh.')
    key = Path(os.path.expanduser(cfg.key_path))
    t0 = time.perf_counter()
    client = None
    try:
        audit(ip, op, cmd, None, 0, requester, True, "Début", cfg.user, cfg.port)
        client = _client(cfg)
        client.connect(
            ip, port=cfg.port, username=cfg.user, key_filename=str(key),
            timeout=cfg.timeout, banner_timeout=cfg.timeout, auth_timeout=cfg.timeout,
            allow_agent=False, look_for_keys=False,
        )
        _stdin, stdout, stderr = client.exec_command(cmd, timeout=cfg.timeout)
        channel = stdout.channel
        outbuf, errbuf = bytearray(), bytearray()
        deadline = time.monotonic() + cfg.timeout + 3
        while True:
            if channel.recv_ready(): outbuf.extend(channel.recv(65536))
            if channel.recv_stderr_ready(): errbuf.extend(channel.recv_stderr(65536))
            if len(outbuf) + len(errbuf) > 2097152: raise ValueError("Sortie SSH trop volumineuse")
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready(): break
            if time.monotonic() > deadline: raise TimeoutError("Délai commande SSH dépassé")
            time.sleep(0.01)
        rc = channel.recv_exit_status()
        out = outbuf.decode("utf-8", "replace")
        err = errbuf.decode("utf-8", "replace")
        dur = int((time.perf_counter() - t0) * 1000)
        res = RunResult(rc == 0, rc, out, err, dur)
        audit(ip, op, cmd, rc, dur, requester, res.ok, err, cfg.user, cfg.port)
        return res
    except Exception as e:  # timeout, auth, host key, réseau
        dur = int((time.perf_counter() - t0) * 1000)
        audit(ip, op, cmd, None, dur, requester, False, str(e), cfg.user, cfg.port)
        kind = "auth" if isinstance(e, paramiko.AuthenticationException) else "network" if isinstance(e, (paramiko.ssh_exception.NoValidConnectionsError, socket.timeout, ConnectionError)) else "ssh"
        return RunResult(False, None, "", str(e), dur, kind)
    finally:
        if client: client.close()


def parse_df(text: str) -> list[dict]:
    """Parse la sortie de `df -hP` (une ligne par système de fichiers)."""
    rows = []
    lines = [l for l in text.splitlines() if l.strip()]
    for line in lines[1:]:  # saute l'en-tête
        parts = line.split()
        if len(parts) < 6:
            continue
        fs, size, used, avail, usep = parts[:5]
        mount = " ".join(parts[5:])
        try:
            pct = int(usep.rstrip("%"))
        except ValueError:
            pct = None
        rows.append({
            "fs": fs, "size": size, "used": used, "avail": avail,
            "use_pct": pct, "mount": mount, "warn": (pct is not None and pct >= 80),
        })
    return rows


def pretty_os(text: str) -> str:
    """Extrait PRETTY_NAME d'os-release, sinon la 1re ligne (redhat-release)."""
    for line in text.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    first = text.strip().splitlines()
    return first[0].strip() if first else ""


def persistent_config(cfg):
    """Use persistent known hosts with strict verification, including ProxyJump."""
    import hashlib
    # Surchargeable au meme titre que COCKPIT_DB et COCKPIT_AUDIT : sans cela, la
    # suite de tests ecrit dans le dossier de donnees de production, ou chaque
    # execution laisse un fichier de plus (31 constates, dont 30 issus des tests).
    folder = Path(os.environ.get('COCKPIT_SSH_DIR') or (Path(__file__).resolve().parent / 'data'))
    source = Path(cfg.config_path).expanduser().resolve() if cfg.config_path else Path.home()/'.ssh/config'
    system = Path(os.environ.get('PROGRAMDATA', 'C:/ProgramData'))/'ssh/ssh_config' if os.name == 'nt' else Path('/etc/ssh/ssh_config')
    def quoted(path):
        value = str(path).replace('\\', '/')
        if any(c in value for c in ['"','\n','\r']): raise ValueError('Chemin de configuration SSH invalide')
        return '"' + value + '"'
    content = 'Host *\n    StrictHostKeyChecking yes\n    UserKnownHostsFile ' + quoted(folder/'known_hosts') + ' ' + quoted(Path.home()/'.ssh/known_hosts') + '\n'
    if cfg.config_path or source.is_file(): content += 'Include ' + quoted(source) + '\n'
    if system.is_file(): content += 'Include ' + quoted(system) + '\n'
    dest = folder/('ssh-config-' + hashlib.sha256(str(source).encode()).hexdigest()[:12])
    with _audit_lock:
        folder.mkdir(parents=True, exist_ok=True)
        if not dest.exists() or dest.read_text(encoding='utf-8') != content:
            dest.write_text(content, encoding='utf-8')
    return dest


def native_args(ip, cfg):
    executable = shutil.which('ssh')
    if not executable:
        raise FileNotFoundError('Client OpenSSH ssh introuvable dans PATH')
    target = cfg.target or ip
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]*', target):
        raise ValueError('Cible SSH invalide')
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', cfg.user):
        raise ValueError('Compte SSH invalide')
    # Chemins en '/' uniquement : avec de nombreux arguments (-o repetes), le client
    # ssh MSYS/Git pour Windows perd silencieusement les antislashs d'un chemin passe
    # a -F/-i, qui redevient alors introuvable ("Can't open user config file").
    args = [executable, '-F', str(persistent_config(cfg)).replace('\\', '/')]
    # OpenSSH reads the user's config (including ProxyJump) by default.
    # -a/-x et ForwardAgent/ForwardX11=no : un « ForwardAgent yes » de la configuration
    # utilisateur incluse ne doit jamais exposer l'agent à un serveur supervisé (audit SSH-02).
    args += ['-T', '-a', '-x', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
             '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no',
             '-o', 'PermitLocalCommand=no', '-o', 'ClearAllForwardings=yes',
             '-o', 'RemoteCommand=none', '-o', 'RequestTTY=no',
             '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
             '-o', 'ConnectionAttempts=1', '-o', f'ConnectTimeout={cfg.timeout}',
             '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2',
             '-i', os.path.expanduser(cfg.key_path).replace('\\', '/'), '-p', str(cfg.port),
             '-l', cfg.user, target]
    return args


def native_error(text):
    value = text.lower()
    if 'host identification has changed' in value or ('host key for ' in value and 'has changed' in value):
        return 'host_key', 'Clé SSH différente de celle enregistrée. Vérifier l’empreinte depuis la console du serveur avant de remplacer la clé connue. diagnostic_ssh.py permet de reproduire le contrôle ; une connexion terminal avec StrictHostKeyChecking=no peut masquer ce changement.'
    if 'no host key is known' in value or re.search(r'no \S+ host key is known', value):
        return 'host_key', 'Clé SSH absente des magasins InfraOps. Comparer l’empreinte avec la console du serveur puis utiliser register_host_key.py pour la mémoriser. Une connexion terminal utilisant /dev/null ne conserve pas la clé.'
    if any(t in value for t in ['host key verification failed', 'host identification has changed', 'no host key is known']):
        return 'host_key', 'Empreinte absente ou différente dans les magasins InfraOps. Vérifier avec diagnostic_ssh.py puis enregistrer une clé confirmée avec register_host_key.py. Une connexion manuelle utilisant /dev/null ne mémorise pas la clé.'
    if 'permission denied' in value or 'authentication failed' in value:
        return 'auth', 'Authentification refusée sur la cible ou le bastion. Vérifier compte, clé et agent SSH.'
    if any(t in value for t in ['timed out', 'connection refused', 'no route to host', 'network is unreachable', 'could not resolve hostname']):
        return 'network', 'Cible ou bastion inaccessible : vérifier VPN, route, port et configuration SSH.'
    return 'ssh', 'Échec OpenSSH. Consulter le détail de la tentative.'


_SECRET_NAME = re.compile(r'AUTH|TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY', re.I)


def ssh_environment():
    """Environnement transmis à ssh et à son ProxyCommand : sans les jetons API ni les secrets
    du service. Ils ne sortaient que via un SendEnv, mais n'ont rien à faire là (audit SSH-09).
    SSH_AUTH_SOCK reste : l'agent sert à l'authentification sur le poste d'exploitation."""
    return {k: v for k, v in os.environ.items() if k == 'SSH_AUTH_SOCK' or not _SECRET_NAME.search(k)}


# Plafond global de sessions ssh simultanées, tous chemins confondus (collecte, batch,
# empreintes, tests de connexion) : les pools indépendants pouvaient saturer le bastion
# (MaxStartups) et produire de faux « réseau » (audit SSH-08).
MAX_SESSIONS = int(os.environ.get('INFRAOPS_SSH_MAX_SESSIONS', '24'))
SESSIONS = threading.BoundedSemaphore(MAX_SESSIONS)


def stop_native(proc):
    """Stop this owned SSH process tree, including a ProxyJump subprocess."""
    if proc.poll() is not None: return
    if os.name == 'nt':
        try:
            subprocess.run(['taskkill', '/PID', str(proc.pid), '/T', '/F'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=5, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        except (OSError, subprocess.TimeoutExpired):
            pass
        if proc.poll() is None:
            proc.kill()
    else:
        try: os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError: pass


def run_operation(ip: str, op: str, cfg: SSHConfig, requester: str = 'local') -> RunResult:
    """Exécute une opération de la liste fermée, sous le plafond global de sessions."""
    with SESSIONS:
        return _run_operation(ip, op, cfg, requester)


def _run_operation(ip: str, op: str, cfg: SSHConfig, requester: str = 'local') -> RunResult:
    if cfg.transport == 'paramiko':
        return run_paramiko(ip, op, cfg, requester)
    if op not in OPERATIONS:
        audit(ip, op, '', None, 0, requester, False, 'Opération refusée', cfg.user, cfg.port)
        raise ValueError('Opération non autorisée')
    cmd = OPERATIONS[op]
    start = time.monotonic()
    audit(ip, op, cmd, None, 0, requester, True, 'Début OpenSSH', cfg.user, cfg.port)
    proc = None
    try:
        argv = native_args(ip, cfg) + [cmd]
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, env=ssh_environment(),
                                stderr=subprocess.PIPE, shell=False,
                                start_new_session=os.name != 'nt',
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        buffers = [bytearray(), bytearray()]
        oversized = threading.Event()
        def drain(stream, buf):
            while True:
                chunk = stream.read(4096)
                if not chunk: break
                if len(buf) + len(chunk) > 1048576:
                    oversized.set()
                    stop_native(proc)
                    break
                buf.extend(chunk)
        readers = [threading.Thread(target=drain, args=(stream, buf), daemon=True)
                   for stream, buf in zip((proc.stdout, proc.stderr), buffers)]
        for reader in readers: reader.start()
        try:
            rc = proc.wait(timeout=cfg.timeout * 3 + 10)
        except subprocess.TimeoutExpired:
            stop_native(proc)
            proc.wait(timeout=5)
            raise TimeoutError('Délai global SSH dépassé (cible ou bastion)')
        finally:
            for reader in readers: reader.join(timeout=2)
        if oversized.is_set(): raise ValueError('Sortie SSH trop volumineuse')
        out, err = [b.decode('utf-8', 'replace') for b in buffers]
        duration = int((time.monotonic() - start) * 1000)
        kind, hint = native_error(err) if rc == 255 else ('', '')
        if hint: err = hint + '\n' + err
        result = RunResult(rc == 0, None if rc == 255 else rc, out, err, duration, kind)
    except Exception as exc:
        result = RunResult(False, None, '', str(exc), int((time.monotonic()-start)*1000), 'network' if isinstance(exc, TimeoutError) else 'local')
    finally:
        if proc:
            if proc.poll() is None: stop_native(proc)
            for stream in (proc.stdout, proc.stderr):
                if stream: stream.close()
    audit(ip, op, cmd, result.rc, result.duration_ms, requester, result.ok, result.stderr, cfg.user, cfg.port)
    return result
