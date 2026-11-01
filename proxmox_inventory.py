"""Normalize the read-only Proxmox ``/cluster/resources`` response.

The endpoint already exposes enough information for a useful monitoring view:
nodes, guests, storage usage and cumulative guest I/O.  Keeping the normalizer
limited to that single endpoint is deliberate; displaying the V2 dashboard
must never require a mutating Proxmox permission.
"""
import math
from ipaddress import ip_interface


def guest_addresses(resource):
    """Conserver uniquement les IP fournies ; /cluster/resources n’en fournit pas toujours."""
    values = resource.get('addresses', [])
    values = list(values) if isinstance(values, list) else []
    values.extend(resource.get(key) for key in ('ip', 'ip_address') if resource.get(key))
    addresses = set()
    for value in values:
        if not isinstance(value, str):
            continue
        try:
            address = ip_interface(value.strip()).ip
        except ValueError:
            continue
        if not (address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified):
            addresses.add(str(address))
    return sorted(addresses)


def cluster_info(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get('data'), list):
        return None
    item = next((x for x in payload['data'] if isinstance(x, dict) and x.get('type') == 'cluster'), None)
    if item is None:
        return None
    return {'name': str(item.get('name') or '')[:200],
            'quorate': bool(item['quorate']) if item.get('quorate') in (0, 1) else None}


def unique_storage_list(nodes):
    """Stockages comptés une fois (audit UI du 31/10, fiche 07.1).

    Un stockage partagé (Ceph, NFS…) est listé sur chaque nœud qui le voit ; l'additionner
    par nœud multipliait la capacité physique. Partagé : une fois par nom ; local : par nœud.
    """
    unique = {}
    for group in nodes or []:
        for storage in group.get('storages') or []:
            identity = (storage.get('name'), None) if storage.get('shared') else (storage.get('name'), group.get('name'))
            unique.setdefault(identity, storage)
    return list(unique.values())


def unique_storage_totals(nodes):
    """(utilisé, total, nombre) sur les stockages uniques ; None si aucune valeur."""
    items = unique_storage_list(nodes)
    used = [s['used_bytes'] for s in items if s.get('used_bytes') is not None]
    total = [s['total_bytes'] for s in items if s.get('total_bytes') is not None]
    return (sum(used) if used else None), (sum(total) if total else None), len(items)


def inventory(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get('data'), list):
        raise ValueError('Proxmox resources response invalid')
    nodes = {}
    counts = {'qemu': 0, 'lxc': 0, 'running': 0, 'stopped': 0, 'unknown': 0,
              'storage': 0, 'storage_unavailable': 0}
    ignored = 0

    def text(value):
        return str(value)[:200] if value is not None else None

    def number(value):
        return value if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0 else None

    def node(name):
        return nodes.setdefault(name, {'name': name, 'status': 'unknown', 'reported': False,
                                       'cpu_pct': None, 'memory_bytes': None, 'memory_total_bytes': None,
                                       'cpu_capacity': None, 'disk_bytes': None,
                                       'disk_total_bytes': None, 'uptime_seconds': None,
                                       'guests': [], 'storages': []})

    for resource in payload['data']:
        if not isinstance(resource, dict):
            ignored += 1
            continue
        kind = resource.get('type')
        if kind not in ('node', 'qemu', 'lxc', 'storage'):
            continue
        name = text(resource.get('node')) or 'Nœud non renseigné'
        group = node(name)
        cpu = number(resource.get('cpu'))
        metrics = {'cpu_pct': round(cpu * 100, 2) if cpu is not None and cpu <= 1 else None,
                   'memory_bytes': number(resource.get('mem')), 'memory_total_bytes': number(resource.get('maxmem')),
                   'uptime_seconds': number(resource.get('uptime'))}
        if kind == 'node':
            group.update(metrics, reported=True,
                         cpu_capacity=number(resource.get('maxcpu')),
                         disk_bytes=number(resource.get('disk')),
                         disk_total_bytes=number(resource.get('maxdisk')),
                         status=resource.get('status') if resource.get('status') in ('online', 'offline') else 'unknown')
        elif kind == 'storage':
            storage_status = resource.get('status')
            if storage_status not in ('available', 'unavailable'):
                storage_status = 'unknown'
            group['storages'].append({
                'name': text(resource.get('storage')) or 'Stockage non renseigné',
                'status': storage_status,
                'type': text(resource.get('plugintype')),
                'shared': bool(resource.get('shared')) if resource.get('shared') in (0, 1, True, False) else None,
                'used_bytes': number(resource.get('disk')),
                'total_bytes': number(resource.get('maxdisk')),
            })
            counts['storage'] += 1
            counts['storage_unavailable'] += storage_status == 'unavailable'
        else:
            vmid = resource.get('vmid')
            if not isinstance(vmid, int) or isinstance(vmid, bool) or vmid < 1:
                ignored += 1
                continue
            status = resource.get('status') if resource.get('status') in ('running', 'stopped') else 'unknown'
            group['guests'].append({'vmid': vmid, 'name': text(resource.get('name')) or str(vmid), 'type': kind,
                                    'addresses': guest_addresses(resource),
                                    'status': status, 'node': name, 'disk_capacity_bytes': number(resource.get('maxdisk')),
                                    # Proxmox renvoie disk=0 pour une VM QEMU : il ne lit pas le
                                    # système de fichiers invité. Ce 0 n'est pas une mesure
                                    # (audit UI du 31/10, fiche 07.2) ; les conteneurs LXC le sont.
                                    'disk_used_bytes': None if kind == 'qemu' and resource.get('disk') in (0, None)
                                    else number(resource.get('disk')),
                                    'disk_read_bytes': number(resource.get('diskread')),
                                    'disk_write_bytes': number(resource.get('diskwrite')),
                                    'network_in_bytes': number(resource.get('netin')),
                                    'network_out_bytes': number(resource.get('netout')),
                                    'cpu_capacity': number(resource.get('maxcpu')),
                                    'pool': text(resource.get('pool')), **metrics})
            counts[kind] += 1
            counts[status] += 1
    for group in nodes.values():
        group['guests'].sort(key=lambda guest: (guest['vmid'], guest['type']))
        group['storages'].sort(key=lambda storage: storage['name'])
    all_nodes = list(nodes.values())
    all_guests = [guest for group in all_nodes for guest in group['guests']]
    unique_storages = unique_storage_list(all_nodes)

    def total(items, key):
        values = [item[key] for item in items if item.get(key) is not None]
        return sum(values) if values else None

    measured_cpu = [group['cpu_pct'] for group in all_nodes if group['cpu_pct'] is not None]
    summary = {
        'nodes_online': sum(group['status'] == 'online' for group in all_nodes),
        'cpu_pct': round(sum(measured_cpu) / len(measured_cpu), 2) if measured_cpu else None,
        'memory_bytes': total(all_nodes, 'memory_bytes'),
        'memory_total_bytes': total(all_nodes, 'memory_total_bytes'),
        'storage_used_bytes': total(unique_storages, 'used_bytes'),
        'storage_total_bytes': total(unique_storages, 'total_bytes'),
        'storage_unique_count': len(unique_storages),
        'storage_method': 'Stockage partagé compté une fois ; stockage local compté par nœud.',
        'network_in_bytes': total(all_guests, 'network_in_bytes'),
        'network_out_bytes': total(all_guests, 'network_out_bytes'),
        'disk_read_bytes': total(all_guests, 'disk_read_bytes'),
        'disk_write_bytes': total(all_guests, 'disk_write_bytes'),
    }
    return {'nodes': sorted(nodes.values(), key=lambda group: group['name']), 'counts': counts,
            'nodes_count': len(nodes), 'ignored_resources': ignored, 'summary': summary,
            'scope': 'Ressources visibles par ce compte et ce jeton ; les permissions peuvent limiter le résultat.',
            'empty': not nodes}
