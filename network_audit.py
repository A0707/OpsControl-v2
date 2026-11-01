"""Diagnostic reseau en lecture seule : ping ICMP, port(s) TCP et presence de la
cle hote SSH dans known_hosts, pour chaque serveur de l'inventaire.

Objectif : distinguer, pour un serveur qui ne repond pas en SSH, une cause reseau
(pas de route, port ferme) d'une cle hote jamais enregistree - sans jamais tenter
de connexion SSH ni ajouter la moindre cle. L'enregistrement d'une cle reste un
geste manuel et verifie (voir register_host_key.py), jamais automatique ici.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from ssh import tcp_reachable

IP_RE = re.compile(r'^(\d{1,3})(\.\d{1,3}){3}$')
_NOWINDOW = {'creationflags': getattr(subprocess, 'CREATE_NO_WINDOW', 0)}


TTL_RE = re.compile(r'ttl[=:](\d+)', re.I)


def icmp_reply(returncode: int, stdout: str) -> bool:
    """Vraie réponse d'écho de la cible : code 0 ET ligne TTL (FR/EN, Windows/Linux).

    Windows renvoie 0 pour « Impossible de joindre l'hôte de destination » émis par
    une passerelle : le code seul faisait passer une panne pour « up » (OC-AUDIT-006)."""
    return returncode == 0 and bool(TTL_RE.search(stdout or ''))


def ping(ip: str, timeout_s: float = 1.5) -> bool | None:
    """Une requete ICMP (echo) en lecture seule. None si non determinable localement."""
    if not IP_RE.match(ip):
        return None
    exe = shutil.which('ping')
    if not exe:
        return None
    args = [exe, '-n', '1', '-w', str(int(timeout_s * 1000)), ip] if os.name == 'nt' \
        else [exe, '-c', '1', '-W', str(max(1, int(timeout_s))), ip]
    try:
        result = subprocess.run(args, capture_output=True, text=True, errors='replace', timeout=timeout_s + 3, **_NOWINDOW)
        return icmp_reply(result.returncode, result.stdout)
    except (OSError, subprocess.TimeoutExpired):
        return None


def known_hosts_files() -> list[Path]:
    # Même magasin que la plateforme, y compris avec COCKPIT_SSH_DIR (audit SSH-06).
    from host_access import known_hosts_path
    return [known_hosts_path(Path(__file__).resolve().parent), Path.home() / '.ssh' / 'known_hosts']


def host_key_known(ip: str, candidate) -> bool | None:
    """Interroge known_hosts (ssh-keygen -F) sans se connecter ni rien modifier."""
    exe = shutil.which('ssh-keygen')
    if not exe:
        return None
    target = candidate.target or ip
    lookup = target if candidate.port == 22 else f'[{target}]:{candidate.port}'
    for f in known_hosts_files():
        if not f.is_file():
            continue
        try:
            result = subprocess.run([exe, '-F', lookup, '-f', str(f)], capture_output=True,
                                     text=True, timeout=5, **_NOWINDOW)
            if result.returncode == 0 and result.stdout.strip():
                return True
        except (OSError, subprocess.TimeoutExpired):
            return None
    return False


def collect_network(host: dict, cfg) -> dict:
    from config import candidates
    ip = host.get('ip')
    row = {'ip': ip, 'collected_at': datetime.now(timezone.utc).isoformat(),
           'ping': None, 'ports': [], 'ssh_key_known': None}
    if not ip:
        return row
    row['ping'] = ping(ip)
    seen_ports, key_known = set(), None
    for candidate in candidates(cfg, host):
        if candidate.port not in seen_ports:
            details = {}
            ok, latency = tcp_reachable(ip, candidate.port, timeout=2.0, details=details)
            row['ports'].append({'port': candidate.port, 'ok': ok, 'latency_ms': latency, 'failure': details.get('failure')})
            seen_ports.add(candidate.port)
        if key_known is not True:
            status = host_key_known(ip, candidate)
            if status:
                key_known = True
            elif key_known is None and status is False:
                key_known = False
    row['ssh_key_known'] = key_known
    return row
