"""Relevé Proxmox en lecture seule pour l'inventaire complet (inventaire_complet.py).

Complète le cache d'OpsControl (/cluster/resources, rafraîchi par le service)
avec ce qu'il ne porte pas : versions PVE et noyau des nœuds, matériel,
état du cluster et de Ceph, configuration de chaque VM (disques, cartes
réseau, VLAN, agent QEMU).

Lecture seule stricte : uniquement des GET avec la connexion « Proxmox »
d'OpsControl (URL, certificat épinglé, jeton du coffre DPAPI). Les droits
PVEAuditor suffisent. Une route refusée ou en erreur est notée, jamais
contournée.

Pourquoi une liste blanche de clés de configuration : la description d'une VM
et les champs cloud-init (cipassword, sshkeys…) peuvent contenir des secrets.
Seules les clés techniques utiles à l'inventaire sont conservées.

Usage :
    python inventaire_proxmox.py [sortie.json]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from export_proxmox_stockage import ClientProxmox, connexion_proxmox, date_creation, disques

BASE = Path(__file__).resolve().parent

CLES_CONFIG = re.compile(r'^(cores|sockets|vcpus|cpu|memory|balloon|ostype|agent|onboot|bios|machine|'
                         r'scsihw|boot|tags|protection|startup|hotplug|numa|name|hostname|arch|swap|'
                         r'net\d+)$')
CARTE = re.compile(r'^net\d+$')


def config_filtree(config: dict | None) -> dict:
    """Clés techniques seulement : jamais description, cipassword, sshkeys, ciuser…"""
    return {k: v for k, v in (config or {}).items() if CLES_CONFIG.match(k)}


def cartes_reseau(config: dict | None) -> list[dict]:
    """« net0: virtio=AA:BB:…,bridge=vmbr1,tag=20,firewall=1 » -> carte structurée."""
    cartes = []
    for cle, valeur in sorted((config or {}).items()):
        if not CARTE.match(cle) or not isinstance(valeur, str):
            continue
        champs = dict(p.split('=', 1) for p in valeur.split(',') if '=' in p)
        modele = next((m for m in ('virtio', 'e1000', 'e1000e', 'vmxnet3', 'rtl8139', 'name') if m in champs), '')
        cartes.append({'carte': cle, 'modele': modele, 'mac': champs.get(modele, '') if modele != 'name' else '',
                       'bridge': champs.get('bridge', ''), 'vlan': champs.get('tag', ''),
                       'pare_feu': champs.get('firewall') == '1', 'ip': champs.get('ip', '')})
    return cartes


def interface_disque(cle: str) -> str:
    return re.sub(r'\d+$', '', cle)


def agent_actif(config: dict | None) -> bool | None:
    valeur = str((config or {}).get('agent', ''))
    if not valeur:
        return None
    return valeur.split(',', 1)[0] in ('1', 'enabled=1')


def lire(client, chemin: str, erreurs: list) -> object:
    try:
        return client.get(chemin)
    except Exception as exc:  # route refusée ou absente : notée, jamais contournée
        erreurs.append({'route': chemin, 'erreur': type(exc).__name__, 'detail': str(exc)[:160]})
        return None


def collecter(client) -> dict:
    erreurs: list[dict] = []
    debut = datetime.now(timezone.utc)
    ressources = lire(client, '/cluster/resources', erreurs) or []
    noeuds = []
    for item in ressources:
        if item.get('type') != 'node':
            continue
        nom = quote(item['node'], safe='')
        version = lire(client, f'/nodes/{nom}/version', erreurs) or {}
        statut = lire(client, f'/nodes/{nom}/status', erreurs) or {}
        cpu = statut.get('cpuinfo') or {}
        noeuds.append({'nom': item['node'], 'etat': item.get('status'), 'version': version.get('version'),
                       'release': version.get('release'), 'repoid': version.get('repoid'),
                       'noyau': statut.get('kversion'), 'pve_manager': statut.get('pveversion'),
                       'cpu_modele': cpu.get('model'), 'cpu_sockets': cpu.get('sockets'),
                       'cpu_coeurs': cpu.get('cores'), 'cpu_threads': cpu.get('cpus'),
                       'ram_totale': (statut.get('memory') or {}).get('total'),
                       'ram_utilisee': (statut.get('memory') or {}).get('used'),
                       'uptime': statut.get('uptime'), 'boot_mode': (statut.get('boot-info') or {}).get('mode'),
                       'rootfs': statut.get('rootfs')})
    cluster = lire(client, '/cluster/status', erreurs) or []
    ceph = lire(client, '/cluster/ceph/status', erreurs)
    invites = []
    for item in ressources:
        if item.get('type') not in ('qemu', 'lxc'):
            continue
        chemin = '/nodes/{}/{}/{}/config'.format(quote(item['node'], safe=''), item['type'], int(item['vmid']))
        config = lire(client, chemin, erreurs)
        liste_disques = disques(config, item['type']) if config else None
        for d in liste_disques or []:
            d['interface'] = interface_disque(d['cle'])
        invites.append({'vmid': item['vmid'], 'nom': item.get('name'), 'type': item['type'], 'noeud': item['node'],
                        'etat': item.get('status'), 'template': bool(item.get('template')), 'pool': item.get('pool'),
                        'tags': item.get('tags'), 'maxcpu': item.get('maxcpu'), 'maxmem': item.get('maxmem'),
                        'maxdisk': item.get('maxdisk'), 'cpu': item.get('cpu'), 'mem': item.get('mem'),
                        'uptime': item.get('uptime'), 'config': config_filtree(config),
                        'config_lue': config is not None, 'disques': liste_disques,
                        'cartes': cartes_reseau(config), 'agent_qemu': agent_actif(config),
                        'ctime': date_creation(config)})
    stockages = [{k: s.get(k) for k in ('storage', 'node', 'plugintype', 'shared', 'status', 'disk', 'maxdisk', 'content')}
                 for s in ressources if s.get('type') == 'storage']
    ceph_resume = None
    if isinstance(ceph, dict):
        sante = ceph.get('health') or {}
        ceph_resume = {'sante': sante.get('status'), 'alertes': sorted((sante.get('checks') or {}).keys()),
                       'pgmap': {k: (ceph.get('pgmap') or {}).get(k) for k in ('bytes_total', 'bytes_used', 'bytes_avail', 'num_pgs')},
                       'osdmap': ceph.get('osdmap'), 'fsid': ceph.get('fsid')}
    return {'collecte_le': debut.isoformat(timespec='seconds'), 'methode': 'API Proxmox, GET uniquement (PVEAuditor)',
            'noeuds': noeuds, 'cluster': cluster, 'ceph': ceph_resume, 'stockages': stockages,
            'invites': invites, 'erreurs': erreurs}


def main(argv=None) -> int:
    a = argparse.ArgumentParser(description='Relevé Proxmox en lecture seule (GET)')
    a.add_argument('sortie', nargs='?', default=str(BASE / 'data' / 'inventaire' / 'proxmox-live.json'))
    args = a.parse_args(argv)
    releve = collecter(ClientProxmox(connexion_proxmox()))
    sortie = Path(args.sortie)
    sortie.parent.mkdir(parents=True, exist_ok=True)
    sortie.write_text(json.dumps(releve, ensure_ascii=False, indent=1), encoding='utf-8')
    print(f"{sortie} : {len(releve['noeuds'])} nœud(s), {len(releve['invites'])} invité(s), "
          f"{len(releve['erreurs'])} route(s) en erreur.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
