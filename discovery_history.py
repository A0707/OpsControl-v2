"""Persistance et différences des scans manuels, sans opération réseau."""
import json
from ipaddress import ip_address, ip_network


def save(connect, network, at, duration, items, status='completed', error=None):
    # Métadonnées et réponses sont atomiques : aucun scan complet partiellement enregistré.
    with connect() as db:
        cursor = db.execute('INSERT INTO discovery_scans(range,at,duration_s,status,error) '
                            'VALUES(?,?,?,?,?)', (network, at, duration, status, error))
        scan = cursor.lastrowid
        db.executemany('INSERT INTO discovery_hosts(scan, ip, ports, ttl, banner, dns, type, os, ping, ssh_port) '
                       'VALUES(?,?,?,?,?,?,?,?,?,?)', [
            (scan, item['ip'], json.dumps(sorted(item['ports'])), item.get('ttl'),
             item.get('ssh_banner'), item.get('dns'), item.get('type'), item.get('os'),
             int(bool(item.get('ping'))), item.get('ssh_port')) for item in items])
        return scan


def hosts(db, scan):
    return [{'ip': ip, 'ports': json.loads(ports), 'ttl': ttl, 'ssh_banner': banner,
             'dns': dns, 'type': kind, 'os': system, 'ping': bool(ping), 'ssh_port': ssh_port}
            for ip, ports, ttl, banner, dns, kind, system, ping, ssh_port in db.execute(
                'SELECT ip,ports,ttl,banner,dns,type,os,ping,ssh_port '
                'FROM discovery_hosts WHERE scan=? ORDER BY ip', (scan,))]


def latest(connect):
    with connect() as db:
        attempt = db.execute('SELECT id,at,status,error FROM discovery_scans ORDER BY id DESC LIMIT 1').fetchone()
        last_attempt = dict(zip(('id', 'at', 'status', 'error'), attempt)) if attempt else None
        row = db.execute("SELECT id,range,at,duration_s FROM discovery_scans "
                         "WHERE status='completed' ORDER BY id DESC LIMIT 1").fetchone()
        if not row:
            return {'items': [], 'range': None, 'at': None, 'scan_id': None, 'last_attempt': last_attempt}
        scan, network, at, duration = row
        return {'items': hosts(db, scan), 'range': network, 'at': at,
                'duration_s': duration, 'scan_id': scan, 'last_attempt': last_attempt}


def differences(current, previous):
    after = {item['ip']: set(item['ports']) for item in current}
    before = {item['ip']: set(item['ports']) for item in previous}
    order = lambda values: sorted(values, key=ip_address)
    return {'appeared': order(after.keys() - before.keys()),
            'disappeared': order(before.keys() - after.keys()),
            'ports_changed': [{'ip': ip, 'before': sorted(before[ip]), 'after': sorted(after[ip])}
                              for ip in order(before.keys() & after.keys()) if before[ip] != after[ip]]}


def history(connect, limit=50, before_id=None):
    with connect() as db:
        where, params = ('WHERE id < ?', [before_id]) if before_id is not None else ('', [])
        rows = db.execute('SELECT id,range,at,duration_s,status,error FROM discovery_scans '
                          + where + ' ORDER BY id DESC LIMIT ?', (*params, limit + 1)).fetchall()
        scans = []
        for scan, network, at, duration, status, error in rows[:limit]:
            current = hosts(db, scan)
            previous = db.execute("SELECT id FROM discovery_scans WHERE range=? "
                                  "AND status='completed' AND id<? ORDER BY id DESC LIMIT 1",
                                  (network, scan)).fetchone() if status == 'completed' else None
            comparison = differences(current, hosts(db, previous[0])) if previous else None
            scans.append({'id': scan, 'range': network, 'at': at, 'duration_s': duration,
                          'status': status, 'error': error, 'hosts_count': len(current),
                          'previous_scan_id': previous[0] if previous else None, 'changes': comparison})
        return {'scans': scans, 'next_before_id': scans[-1]['id'] if len(rows) > limit else None,
                'scope': 'Différences entre scans terminés de la même plage. Non observé ne signifie pas arrêté.'}


def missing_inventory(snapshot, inventory):
    if not snapshot.get('range'):
        return []
    network = ip_network(snapshot['range'])
    observed = {item['ip'] for item in snapshot['items']}
    missing = []
    for host in inventory:
        try:
            address = ip_address(host['ip'])
        except (ValueError, KeyError):
            continue
        if address in network and str(address) not in observed:
            missing.append({'key': host['key'], 'name': host.get('name'), 'ip': host['ip']})
    return missing
