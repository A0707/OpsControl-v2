"""Chargement de configuration : inventaire depuis hosts.yaml,
secrets (user/clé SSH) surchargeables par variables d'environnement."""
from __future__ import annotations

import os
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None
import json

from ssh import SSHConfig
from dataclasses import replace

def candidates(cfg, host):
    users = [host['user']] if host.get('user') else cfg.users or (cfg.user,)
    ports = [host['port']] if host.get('port') else cfg.ports or (cfg.port,)
    for port in ports:
        for user in users:
            yield replace(cfg, user=user, port=int(port), key_path=host.get('key_path', cfg.key_path), target=host.get('ssh_host', ''), config_path=host.get('ssh_config', cfg.config_path))


def inventory_path(default: str | Path = "hosts.yaml") -> Path:
    """Un chemin explicite permet de garder l’inventaire hors du dépôt."""
    configured = os.environ.get('INFRAOPS_INVENTORY', '').strip()
    return Path(configured or default).expanduser().resolve()


def load_config(path: str | Path | None = None) -> tuple[SSHConfig, list[dict]]:
    selected = inventory_path() if path is None else Path(path).expanduser()
    if not selected.is_file():
        raise RuntimeError(
            f'Inventaire introuvable : {selected}. Copier hosts.example.yaml vers hosts.yaml '
            'ou définir INFRAOPS_INVENTORY avec le chemin d’un inventaire existant.'
        )
    raw = selected.read_text(encoding='utf-8-sig')
    if raw.lstrip().startswith('{'):
        data = json.loads(raw)
    elif yaml:
        data = yaml.safe_load(raw) or {}
    else:
        raise RuntimeError('Installer PyYAML pour lire une configuration YAML non JSON')
    s = data.get("ssh", {})
    users = [os.environ['COCKPIT_SSH_USER']] if os.environ.get('COCKPIT_SSH_USER') else s.get('users', [s.get('user', 'infraops')])  # défaut : compte de service (docs/SERVICE-ACCOUNT.md)
    ports = s.get('ports', [s.get('port', 22)])
    if not isinstance(users, list) or not users or any(not isinstance(u, str) or not u.strip() for u in users):
        raise ValueError('ssh.users doit être une liste non vide de comptes')
    if not isinstance(ports, list) or not ports or any(not 1 <= int(p) <= 65535 for p in ports):
        raise ValueError('ssh.ports doit contenir des ports de 1 à 65535')
    cfg = SSHConfig(
        user=users[0],
        key_path=os.environ.get("COCKPIT_SSH_KEY", s.get("key_path", "~/.ssh/id_rsa")),
        port=int(ports[0]),
        users=tuple(users), ports=tuple(int(p) for p in ports),
        transport=s.get('transport', 'openssh'),
        config_path=os.environ.get('COCKPIT_SSH_CONFIG', s.get('config_path', '')),
        timeout=int(s.get("timeout", 6)),
        strict_host_key=bool(s.get("strict_host_key", True)),
    )
    hosts = data.get("hosts", [])
    if cfg.transport not in ('openssh', 'paramiko'): raise ValueError('Transport SSH invalide')
    for h in hosts:
        h.setdefault('role', 'À renseigner')
        if 'port' in h and not 1 <= int(h['port']) <= 65535: raise ValueError('Port hôte invalide')
        if 'user' in h and (not isinstance(h['user'], str) or not h['user'].strip()): raise ValueError('Compte hôte invalide')
    return cfg, hosts
