"""Découverte des machines d'une plage réseau privée, et ajout des nouvelles à l'inventaire.

Pour chaque adresse : ping (avec TTL), quelques ports TCP, bannière SSH (lue telle que le
serveur l'annonce, AVANT toute authentification) et nom DNS inverse. On en déduit un type
et un système probables, sans jamais se connecter ni s'authentifier. Seules lectures :
écho ICMP, ouverture de connexion TCP, lecture de la première ligne SSH.

    GET  /api/discovery            état du balayage en cours et derniers résultats
    POST /api/discovery/scan       lance un balayage (admin ; quota « collecte complète »)
    POST /api/discovery/add        ajoute à l'inventaire des adresses du dernier balayage (admin)

Un balayage est actif et visible du réseau (IDS, Wazuh, pare-feu) : il ne part que sur
demande explicite, sur une plage privée de 1024 adresses au plus, avec une liste de ports
courte. Les machines ajoutées passent ensuite, comme toutes, par la confirmation de leur
empreinte SSH (host_access.py) : rien n'est approuvé automatiquement.
"""
from __future__ import annotations

import logging
import os
import re
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import Annotated

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field

PORTS = (22, 3300, 80, 443, 3389, 445, 8006)
SSH_PORTS = (22, 3300)
MAX_ADDRESSES = 1024
RFC1918 = tuple(ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
WORKERS = 48
DEFAULT_RANGE = '10.77.0.0/24'
_NOWINDOW = {'creationflags': getattr(subprocess, 'CREATE_NO_WINDOW', 0)}
ADD_MAX_AGE_HOURS = 24
_HOSTNAME = re.compile(r'(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?')


def valid_hostname(value) -> bool:
    """Nom d'hôte RFC 1123 (lettres, chiffres, tirets, points) ; rien d'autre n'est repris d'un PTR."""
    return isinstance(value, str) and bool(_HOSTNAME.fullmatch(value))
_dns_pool = ThreadPoolExecutor(max_workers=8)
# Requêtes DNS en vol ou en attente : au-delà, le nom est simplement « non résolu ».
_dns_slots = threading.BoundedSemaphore(32)


def validate_range(value: str):
    try:
        net = ip_network(value.strip(), strict=False)
    except ValueError:
        raise ValueError('Plage invalide : notation CIDR attendue, par exemple 10.77.0.0/24') from None
    # Liste blanche explicite : `is_private` accepte aussi 0.0.0.0/8 (la VM elle-même),
    # 198.18/15, 240/4 ou 255.255.255.255 (audit NET-01).
    if net.version != 4 or not any(net.subnet_of(p) for p in RFC1918):
        raise ValueError('Plage refusée : IPv4 privée uniquement (10/8, 172.16/12, 192.168/16)')
    if net.num_addresses > MAX_ADDRESSES:
        raise ValueError(f'Plage trop large : {MAX_ADDRESSES} adresses au plus (un /22)')
    return net


def ping_executable():
    """Chemin absolu du ping système. Sous Windows, shutil.which cherche d'abord dans le
    dossier courant : un ping.exe déposé là aurait été exécuté par le service (audit NET-06)."""
    if os.name == 'nt':
        candidates = [os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'PING.EXE')]
    else:
        candidates = ['/usr/bin/ping', '/bin/ping', '/usr/sbin/ping', '/sbin/ping']
    return next((c for c in candidates if os.path.isfile(c)), None)


def ping_ttl(ip: str, timeout_s: float = 1.0):
    """(répond, ttl) par un seul écho ICMP. TTL : indice du système (64 Unix, 128 Windows, 255 réseau)."""
    exe = ping_executable()
    if not exe:
        return None, None
    args = [exe, '-n', '1', '-w', str(int(timeout_s * 1000)), ip] if os.name == 'nt' \
        else [exe, '-c', '1', '-W', str(max(1, int(timeout_s))), ip]
    try:
        r = subprocess.run(args, capture_output=True, text=True, errors='replace', timeout=timeout_s + 3, **_NOWINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return None, None
    from network_audit import TTL_RE, icmp_reply   # même règle que la collecte et la voie rapide
    m = TTL_RE.search(r.stdout)
    return icmp_reply(r.returncode, r.stdout), int(m[1]) if m else None


def tcp_open(ip: str, port: int, timeout: float = 0.8) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def ssh_banner(ip: str, port: int, timeout: float = 2.0):
    """Première ligne envoyée par le serveur SSH (ex. SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(256)
    except OSError:
        return None
    line = data.split(b'\n', 1)[0].decode('ascii', 'replace').strip()
    return line[:120] if line.startswith('SSH-') else None


def reverse_dns(ip: str, timeout: float = 2.0):
    """Nom inverse, ou None ; travaux en cours ET en file réellement bornés."""
    slots = _dns_slots
    if not slots.acquire(blocking=False):
        return None
    try:
        future = _dns_pool.submit(socket.gethostbyaddr, ip)
    except RuntimeError:  # pool arrêté : aucune tâche ne rendrait cette place
        slots.release()
        return None
    future.add_done_callback(lambda _f: slots.release())
    try:
        return future.result(timeout=timeout)[0]
    except (OSError, FutureTimeout, UnicodeError):
        # cancel() rendait la place avant le retrait réel du travail de la file.
        # Au délai, conserver la place jusqu'à la fin empêche l'accumulation.
        return None


UBUNTU_BY_OPENSSH = {'7.6': '18.04', '8.2': '20.04', '8.9': '22.04', '9.6': '24.04'}


def os_from_banner(banner):
    """Système probable d'après la bannière SSH (annoncée par le paquet OpenSSH de la distribution)."""
    if not banner:
        return None
    b = banner.lower()
    deb = re.search(r'deb(\d+)u', b)
    if deb:
        return f'Debian {deb[1]}'
    if 'debian' in b:
        return 'Debian'
    if 'ubuntu' in b:
        version = re.search(r'openssh_(\d+\.\d+)', b)
        return 'Ubuntu ' + UBUNTU_BY_OPENSSH[version[1]] if version and version[1] in UBUNTU_BY_OPENSSH else 'Ubuntu'
    if 'freebsd' in b:
        return 'FreeBSD'
    if 'windows' in b:
        return 'Windows (OpenSSH)'
    if 'openssh' in b:
        return 'Linux / Unix (OpenSSH)'
    return 'SSH ' + banner.split('-', 2)[-1][:40]


def classify(ports, ttl, banner):
    """(type, système) probables ; « probable » : aucune authentification, seulement des indices."""
    system = os_from_banner(banner)
    if 8006 in ports:
        return 'Hyperviseur Proxmox', system or 'Debian (Proxmox VE)'
    if 3389 in ports or (445 in ports and not system):
        return 'Serveur Windows', 'Windows'
    if system:
        return ('Serveur ' + ('web ' if {80, 443} & set(ports) else '') + 'Linux/Unix').replace('  ', ' '), system
    if ttl and ttl > 128:
        return 'Équipement réseau', None
    if ttl and ttl > 64:
        return 'Windows probable', 'Windows'
    if {80, 443} & set(ports):
        return 'Équipement ou appliance web', None
    return 'Inconnu', None


def probe(ip: str) -> dict | None:
    alive, ttl = ping_ttl(ip)
    ports = [p for p in PORTS if tcp_open(ip, p)]
    if not alive and not ports:
        return None
    ssh_port = next((p for p in SSH_PORTS if p in ports), None)
    banner = ssh_banner(ip, ssh_port) if ssh_port else None
    kind, system = classify(ports, ttl, banner)
    return {'ip': ip, 'ping': bool(alive), 'ttl': ttl, 'ports': ports, 'ssh_port': ssh_port, 'ssh_banner': banner,
            'dns': reverse_dns(ip), 'type': kind, 'os': system}


class Scan(BaseModel):
    model_config = ConfigDict(extra='forbid')
    range: str = Field(default=DEFAULT_RANGE, max_length=43)


class Add(BaseModel):
    model_config = ConfigDict(extra='forbid')
    ips: list[Annotated[str, Field(min_length=1, max_length=45)]] = Field(min_length=1, max_length=MAX_ADDRESSES)
    use_proxmox_names: bool = False


def host_key_for(ip: str) -> str:
    return 'net-' + ip.replace('.', '-')


def proxmox_proposals(items, connections):
    from asset_registry import connection_evidence
    from synchronization import fresh

    def aliases(name):
        name = str(name or '').lower().rstrip('.')
        return {name, name.split('.')[0]} - {''}

    guests = []
    for source in connections:
        if source.get('provider') != 'Proxmox':
            continue
        result = connection_evidence(source)
        for node in (result.get('inventory') or {}).get('nodes', []):
            for guest in node.get('guests', []):
                guests.append((guest, node.get('name'), source, result))
    for item in items:
        matches = []
        for guest, node, source, result in guests:
            by_ip = item['ip'] in (guest.get('addresses') or [])
            by_name = bool(aliases(item.get('dns')) & aliases(guest.get('name')))
            if by_ip or by_name:
                matches.append({'name': guest.get('name'), 'node': node, 'vmid': guest.get('vmid'),
                                'connection_key': source.get('key'), 'source': source.get('name'),
                                'basis': 'ip' if by_ip else 'dns', 'collected_at': result.get('collected_at'),
                                'fresh': result.get('status') == 'observed' and fresh(result.get('collected_at'))})
        item['proxmox_matches'] = matches
        item['proxmox_proposal'] = matches[0] if len(matches) == 1 else None
    return items


def install(app, context):
    import discovery_history
    from fastapi import APIRouter
    router = APIRouter()
    lock = threading.Lock()
    job = {'running': False, 'range': None, 'total': 0, 'completed': 0, 'started_at': None, 'finished_at': None, 'error': None}

    def annotate(items):
        known = {h['ip']: h for h in context.HOSTS}
        for item in items:
            h = known.get(item['ip'])
            item['inventory'] = {'key': h['key'], 'name': h.get('name')} if h else None
            item['status'] = 'inventory' if h else ('new_ssh' if item['ssh_port'] else 'new')
        return proxmox_proposals(items, context.api_connections())

    def run(net):
        started = time.monotonic()
        found = []
        try:
            with ThreadPoolExecutor(max_workers=WORKERS) as pool:
                for item in pool.map(probe, [str(ip) for ip in net.hosts()]):
                    with lock:
                        job['completed'] += 1
                    if item:
                        found.append(item)
            found.sort(key=lambda x: ip_address(x['ip']))
            discovery_history.save(context.connect, str(net), datetime.now(timezone.utc).isoformat(),
                                   round(time.monotonic() - started, 1), found)
        except Exception as exc:  # noqa: BLE001 — un balayage raté ne doit pas tuer le processus
            with lock:
                # Détail dans le journal du service seulement (audit SEC-06).
                logging.getLogger('opscontrol.discovery').exception('Balayage %s en échec', net)
                job['error'] = f'{type(exc).__name__} : détail dans le journal du service'
            try:
                discovery_history.save(context.connect, str(net), datetime.now(timezone.utc).isoformat(),
                                       round(time.monotonic() - started, 1), found,
                                       status='failed', error=job['error'])
            except Exception:
                with lock:
                    job['error'] += ' ; historique non enregistré (base indisponible).'
        finally:
            with lock:
                job['running'] = False
                job['finished_at'] = datetime.now(timezone.utc).isoformat()

    @router.get('/api/discovery')
    def discovery_state():
        snapshot = discovery_history.latest(context.connect)
        with lock:
            out = {**snapshot, 'job': dict(job), 'default_range': DEFAULT_RANGE, 'ports': list(PORTS)}
        failed = (snapshot.get('last_attempt') or {}).get('status') == 'failed'
        if failed and not out['job']['running'] and not out['job']['error']:
            out['job']['error'] = snapshot['last_attempt']['error']
        out['inventory_missing'] = [] if failed else discovery_history.missing_inventory(snapshot, context.HOSTS)
        out['items'] = annotate(snapshot['items'])
        out['counts'] = {k: sum(i['status'] == k for i in out['items']) for k in ('inventory', 'new_ssh', 'new')}
        return out

    @router.get('/api/discovery/history')
    def discovery_history_list(limit: int = 50, before_id: int | None = None):
        if not 1 <= limit <= 100 or (before_id is not None and before_id < 1):
            raise HTTPException(422, 'Limite de 1 à 100 ; curseur positif attendu.')
        return discovery_history.history(context.connect, limit, before_id)

    @router.post('/api/discovery/scan', status_code=202)
    def discovery_scan(request: Scan):
        try:
            net = validate_range(request.range)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        with lock:
            if job['running']:
                # 409 explicite plutôt qu'un 202 ambigu qui laissait croire à un nouveau scan (audit NET-05).
                raise HTTPException(409, f"Balayage de {job.get('range')} déjà en cours : attendre sa fin.")
            job.update(running=True, range=str(net), total=net.num_addresses - (2 if net.prefixlen < 31 else 0),
                       completed=0, started_at=datetime.now(timezone.utc).isoformat(), finished_at=None, error=None)
            threading.Thread(target=run, args=(net,), name='decouverte-reseau', daemon=True).start()
            return dict(job)

    @router.post('/api/discovery/add')
    def discovery_add(request: Add):
        snapshot = discovery_history.latest(context.connect)
        # Une IP vue il y a des semaines a pu être réattribuée : type, DNS et port SSH seraient
        # ceux d'une autre machine. Au-delà, relancer un balayage (audit NET-03).
        try:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(snapshot.get('at') or '')).total_seconds()
        except ValueError:
            age = None
        if age is None or age > ADD_MAX_AGE_HOURS * 3600:
            raise HTTPException(409, f'Dernier balayage absent ou de plus de {ADD_MAX_AGE_HOURS} h : '
                                     'relancer un balayage avant d’ajouter des serveurs.')
        seen = {i['ip']: i for i in annotate(snapshot['items'])}
        missing = [ip for ip in request.ips if ip not in seen]
        if missing:
            raise HTTPException(422, 'Adresses absentes du dernier balayage : ' + ', '.join(missing[:10]))
        known = {h['ip'] for h in context.HOSTS}
        additions = []
        for ip in dict.fromkeys(request.ips):
            if ip in known:
                continue
            item = seen[ip]
            # PTR fourni par le réseau, pas par un administrateur : n'entre dans l'inventaire que
            # s'il a la forme d'un nom d'hôte (RFC 1123), sinon l'IP sert de nom (audit NET-04).
            fqdn = item.get('dns') if valid_hostname(item.get('dns')) else None
            name = (fqdn or '').split('.')[0] or ip
            item = {**item, 'dns': fqdn}
            entry = {'key': host_key_for(ip), 'name': name[:120], 'ip': ip, 'role': 'À renseigner',
                     'environment': 'À renseigner', 'services': [], 'criticality': 'standard',
                     'discovered_from': 'scan-reseau', 'fqdn': item.get('dns'),
                     'inventory_warnings': [f"Découvert par balayage réseau : {item['type']}"
                                            + (f", {item['os']}" if item.get('os') else '') + ' (probable).']}
            proposal = item.get('proxmox_proposal')
            # Nom, nœud et vmid Proxmox repris seulement sur correspondance par IP : un PTR
            # homonyme (DNS dynamique d'un poste) ne doit pas suffire à adopter une VM (NET-04).
            if request.use_proxmox_names and proposal and proposal['fresh'] and proposal.get('basis') == 'ip':
                entry.update(name=str(proposal['name'])[:120], node=proposal['node'],
                             vmid=proposal['vmid'], proxmox_connection_key=proposal['connection_key'])
            if item.get('ssh_port') and item['ssh_port'] != 22:
                entry['port'] = item['ssh_port']
            additions.append(entry)
        if not additions:
            return {'added': [], 'skipped': list(request.ips)}
        # Ajout accepté pendant une collecte : les lots en cours travaillent sur une copie
        # figée de l'inventaire (jobs.launch) ; les nouveaux serveurs entrent au lot suivant.
        added = context.add_discovered_hosts(additions)
        return {'added': [{'key': a['key'], 'name': a['name'], 'ip': a['ip']} for a in added],
                'note': 'Serveurs ajoutés avec le rôle « À renseigner ». Leur empreinte SSH est à confirmer '
                        '(Empreintes SSH à confirmer) avant le premier audit.'}

    app.include_router(router)
