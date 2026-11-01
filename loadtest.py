"""Test de charge hors production : parc synthétique de N serveurs (lot 7).

Le code est copié dans un répertoire temporaire avec un inventaire, une base SQLite et des
sources API entièrement synthétiques : ni hosts.yaml, ni data/, ni secret de l'instance réelle
ne sont lus ou modifiés. Aucune connexion SSH ni requête réseau n'est émise (le cycle de vie,
donc le planificateur, n'est pas démarré). Les routes sont appelées en ASGI, dans le processus.

    python loadtest.py 100 500 1000          # résultats : data/loadtest/<horodatage>.json

Mesures par taille : médiane de 3 appels par route (ms), taille de réponse, puis 8 clients
simultanés sur /api/overview (débit), mémoire du processus.
"""
from __future__ import annotations

import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE = Path(__file__).parent
ROUTES = ['/api/overview', '/api/daily', '/api/alerts', '/api/sync', '/api/incidents', '/api/self-monitoring',
          '/api/hosts/srv00001', '/api/hosts/srv00001/observability', '/api/services', '/api/findings',
          '/api/v2/cockpit', '/api/network', '/api/connections?compact=true', '/api/health']


def iso(dt):
    return dt.isoformat()


def synthetic_inventory(n, rnd):
    roles = ['Web', 'BDD', 'Applicatif', 'Elasticsearch', 'Batch', 'WAF']
    hosts = []
    for i in range(1, n + 1):
        hosts.append({'key': f'srv{i:05d}', 'name': f'srv{i:05d}', 'ip': f'10.{i // 65536}.{i // 256 % 256}.{i % 256}',
                      'environment': 'PROD' if i % 3 else 'REC', 'role': rnd.choice(roles), 'criticality': 'standard',
                      'services': ['nginx.service'] if i % 4 == 0 else []})
    return {'ssh': {'users': ['audit-test'], 'port': 22, 'transport': 'openssh', 'strict_host_key': True}, 'hosts': hosts}


def synthetic_connections(hosts, now, rnd):
    n = len(hosts)
    names = [h['name'] for h in hosts]
    guests = [{'vmid': 100 + i, 'name': name, 'type': 'qemu', 'status': 'running' if i % 17 else 'stopped', 'node': f'pve{i % 6:02d}',
               'disk_capacity_bytes': 5e10, 'disk_used_bytes': 2e10, 'disk_read_bytes': 1, 'disk_write_bytes': 1, 'network_in_bytes': 1,
               'network_out_bytes': 1, 'cpu_capacity': 4, 'pool': None, 'cpu_pct': rnd.random() * 60, 'memory_bytes': 4e9,
               'memory_total_bytes': 8e9, 'uptime_seconds': 86400} for i, name in enumerate(names)]
    nodes = [{'name': f'pve{k:02d}', 'status': 'online', 'reported': True, 'cpu_pct': 30.0, 'memory_bytes': 1e11, 'memory_total_bytes': 2e11,
              'cpu_capacity': 64, 'disk_bytes': 1e11, 'disk_total_bytes': 1e12, 'uptime_seconds': 999,
              'guests': [g for g in guests if g['node'] == f'pve{k:02d}'],
              'storages': [{'name': 'local', 'status': 'available', 'type': 'dir', 'shared': False, 'used_bytes': 1e11, 'total_bytes': 1e12}]}
             for k in range(6)]
    collected = iso(now - timedelta(minutes=2))

    def conn(key, provider, inventory, indicators):
        return {'key': key, 'name': provider + ' synthétique', 'provider': provider, 'url': f'https://{key}.example.test/api',
                'last_result': {'collected_at': collected, 'status': 'observed', 'inventory': inventory,
                                'summary': {'type': 'json', 'entries': n, 'bytes': 1}, 'indicators': indicators}}
    problems = [{'triggerid': str(i), 'description': f'Problème {i}', 'priority': '4', 'severity_key': 'critical' if i % 5 == 0 else 'warning',
                 'severity_label': 'High', 'severity': 'critical' if i % 5 == 0 else 'warning', 'hosts': [names[i % n]],
                 'last_change': str(int(now.timestamp()) - 3600), 'measurement_at': collected} for i in range(n // 5)]
    jobs = [{'jobid': i, 'name': f'backup-{names[i % n]}', 'client': f'{names[i % n]}-fd', 'level': 'I', 'status_code': 'T',
             'status_label': 'Terminé', 'severity': 'ok' if i % 9 else 'critical', 'endtime': collected, 'bytes': 1, 'files': 1} for i in range(500)]
    return [
        conn('pve', 'Proxmox', {'nodes': nodes, 'counts': {'qemu': n, 'lxc': 0, 'running': n - n // 17, 'stopped': n // 17, 'unknown': 0, 'storage': 6, 'storage_unavailable': 0},
                                'nodes_count': 6, 'ignored_resources': 0, 'summary': {'nodes_online': 6, 'cpu_pct': 30.0, 'memory_bytes': 6e11, 'memory_total_bytes': 1.2e12,
                                'storage_used_bytes': 6e11, 'storage_total_bytes': 6e12, 'network_in_bytes': 1, 'network_out_bytes': 1, 'disk_read_bytes': 1, 'disk_write_bytes': 1},
                                'scope': 'synthétique', 'empty': False, 'cluster': {'name': 'pve-test', 'quorate': True}}, {'resources': n, 'running': n, 'stopped': 0}),
        conn('zbx', 'Zabbix', {'hosts': [{'hostid': str(i), 'host': name, 'name': name, 'status': '0', 'addresses': [hosts[i]['ip']]} for i, name in enumerate(names)],
                               'counts': {'monitored': n, 'unmonitored': 0, 'unknown': 0}, 'hosts_count': n, 'ignored': 0, 'scope': 'synthétique', 'empty': False,
                               'problems': problems, 'problem_counts': {'critical': n // 25, 'warning': n // 5 - n // 25, 'unknown': 0},
                               'problems_count': len(problems), 'problems_scope': 'synthétique'}, {'monitored_hosts': n, 'unmonitored_hosts': 0}),
        conn('wazuh', 'Wazuh', {'daemons': [{'name': f'wazuh-d{i}', 'status': 'running'} for i in range(17)], 'counts': {'running': 17, 'stopped': 0, 'failed': 0, 'unknown': 0},
                                'daemons_count': 17, 'agents': {'states': [{'key': 'active', 'label': 'Actif', 'count': n}], 'total': n, 'scope': 'x'},
                                'manager': {'version': 'v4.7.0', 'compilation_date': None, 'type': 'server', 'path': '/var/ossec', 'max_agents': 'unlimited', 'openssl_support': 'yes'},
                                'empty': False, 'scope': 'synthétique',
                                'agents_inventory': [{'id': f'{i:03d}', 'name': name, 'ip': hosts[i]['ip'], 'status': 'active', 'version': 'v4.7.0', 'lastKeepAlive': collected} for i, name in enumerate(names)],
                                'agents_inventory_total': n, 'agents_inventory_scope': 'synthétique'}, {'running_daemons': 17, 'stopped_daemons': 0}),
        conn('bacula', 'Bacula', {'jobs': jobs, 'jobs_truncated': 0, 'latest': jobs[: min(len(jobs), int(n * .7))],
                                  'latest_counts': {'ok': 400, 'warning': 0, 'critical': 50, 'running': 0, 'pending': 0, 'unknown': 0}, 'history_since': collected,
                                  'counts': {'ok': 450, 'warning': 0, 'critical': 50, 'running': 0, 'pending': 0, 'unknown': 0}, 'jobs_count': 500,
                                  'last_success': collected, 'scope': 'synthétique', 'empty': False}, {'jobs_total': 500, 'jobs_ok': 450, 'jobs_warning': 0, 'jobs_error': 50, 'jobs_running': 0}),
        conn('es', 'Elasticsearch', {}, {'number_of_nodes': 3, 'number_of_data_nodes': 3, 'active_shards': 300, 'unassigned_shards': 0,
                                         'active_shards_percent_as_number': 100.0, 'cluster_status': 'green'}),
    ]


CHILD = r'''
import asyncio, json, os, random, sys, threading, time, ctypes
from datetime import datetime, timedelta, timezone
sys.path.insert(0, os.getcwd())
started = time.perf_counter()
import app
import_seconds = time.perf_counter() - started
N = int(sys.argv[1]); routes = json.loads(sys.argv[2]); rnd = random.Random(7)
now = datetime.now(timezone.utc)

def payload(h, i, at):
    checks = [{'id': f'c{k}', 'title': f'Contrôle {k}', 'status': 'pass' if (i + k) % 11 else 'fail', 'evidence': 'x' * 300, 'command': 'cmd --lecture'} for k in range(15)]
    findings = [{'id': f'f{k}', 'title': f'Constat {k}', 'domain': 'stockage' if k else 'services', 'severity': 'warning' if k else 'critical',
                 'evidence': 'preuve ' * 30, 'check_command': 'df -h', 'solution_command': 'à adapter', 'precaution': 'p', 'scope': 's',
                 'requires_adaptation': True, 'executable': False} for k in range(i % 4)]
    return {'status': 'ok' if not findings else ('critical' if i % 7 == 0 else 'warning'), 'issues': [f['title'] for f in findings],
            'cpu': rnd.random() * 90, 'ram': rnd.random() * 95, 'disk_max': rnd.randint(10, 97),
            'filesystems': [{'fs': f'/dev/sd{k}', 'size': '50G', 'used': '20G', 'avail': '30G', 'use_pct': 40 + k, 'mount': f'/m{k}', 'warn': False} for k in range(8)],
            'service_states': [{'name': 'nginx.service', 'status': 'active'}], 'collected_at': at.isoformat(),
            'attempts': [{'user': 'audit-test', 'port': 22, 'ok': True, 'error_kind': None, 'error': None, 'duration_ms': 900}],
            'ssh_user': 'audit-test', 'ssh_port': 22,
            'all_services': [{'name': f'unit{k}.service', 'status': 'active' if k % 31 else 'failed', 'configured': k == 0} for k in range(120)],
            'os': 'Debian 12', 'uptime': '12 days', 'checks': checks, 'findings': findings, 'audit_version': 5,
            'storage': {'filesystems': [], 'remote_shares': [], 'exports': [], 'lvm': [], 'zfs': [], 'smart': [], 'io': {'devices': [], 'iowait_pct': 1.0},
                        'top_processes': [], 'listening_ports': 12, 'firewall': None, 'fail2ban': None, 'ssh_failed_24h': 0, 'scope': 'synthétique'},
            'coverage': {'measured': 14, 'total': 15}, 'fingerprint': app.fingerprint(h)}

t0 = time.perf_counter()
with app.connect() as db:
    for i, h in enumerate(app.HOSTS):
        fresh = i % 10 != 0
        at = now - (timedelta(minutes=3) if fresh else timedelta(hours=30))
        p = payload(h, i, at)
        db.execute('INSERT OR REPLACE INTO states(key, ip, payload) VALUES(?,?,?)', (h['key'], h['ip'], json.dumps(p)))
        for s in range(24):
            db.execute('INSERT OR REPLACE INTO audit_snapshots(key, ts, payload) VALUES(?,?,?)', (h['key'], (at - timedelta(hours=s)).isoformat(), json.dumps(p)))
        for s in range(50):
            db.execute('INSERT INTO history(key,ts,status,summary) VALUES(?,?,?,?)', (h['key'], (at - timedelta(minutes=10 * s)).isoformat(), p['status'], json.dumps({'issues': p['issues']})))
        db.execute('INSERT OR REPLACE INTO network(key, ip, payload) VALUES(?,?,?)', (h['key'], h['ip'], json.dumps({'collected_at': (now - timedelta(minutes=1)).isoformat(), 'ping': i % 23 != 0, 'ports': [{'port': 22, 'ok': True}], 'ssh_key_known': True})))
seed_seconds = time.perf_counter() - t0
app.enroll_assets()

def call(method, path):
    sent = []
    p, _, q = path.partition('?')
    scope = {'type': 'http', 'asgi': {'version': '3.0'}, 'http_version': '1.1', 'method': method, 'scheme': 'http', 'path': p, 'raw_path': p.encode(),
             'query_string': q.encode(), 'headers': [(b'host', b'127.0.0.1'), (b'x-cockpit-request', b'1')], 'client': ('127.0.0.1', 1), 'server': ('127.0.0.1', 8001), 'root_path': ''}
    msgs = [{'type': 'http.request', 'body': b'', 'more_body': False}]
    async def receive(): return msgs.pop(0) if msgs else {'type': 'http.disconnect'}
    async def send(m): sent.append(m)
    asyncio.run(app.app(scope, receive, send))
    status = next(m for m in sent if m['type'] == 'http.response.start')['status']
    return status, sum(len(m.get('body', b'')) for m in sent if m['type'] == 'http.response.body')

call('POST', '/api/incidents/sync')
if os.environ.get('LOADTEST_PROFILE'):
    import cProfile, pstats, io
    for route in os.environ['LOADTEST_PROFILE'].split(','):
        # « fn:overview » : la fonction de route seule, sans ASGI ni sérialisation (profil lisible).
        target = (lambda: getattr(app, route[3:])()) if route.startswith('fn:') else (lambda: call('GET', route))
        target()
        t = time.perf_counter(); target(); sys.stderr.write(chr(10) + 'durée sans profil ' + route + ' : ' + str(round((time.perf_counter() - t) * 1000)) + ' ms')
        prof = cProfile.Profile(); prof.enable(); target(); prof.disable()
        buf = io.StringIO(); pstats.Stats(prof, stream=buf).sort_stats('cumulative').print_stats(28)
        sys.stderr.write(chr(10) + '##### ' + route + chr(10) + buf.getvalue())
    print(json.dumps({'profile': True})); sys.exit(0)
results = {}
for route in routes:
    times = []
    for _ in range(3):
        t = time.perf_counter(); status, size = call('GET', route); times.append((time.perf_counter() - t) * 1000)
    times.sort()
    results[route] = {'status': status, 'median_ms': round(times[1], 1), 'max_ms': round(times[2], 1), 'bytes': size}

def worker(out, k):
    for _ in range(k):
        t = time.perf_counter(); call('GET', '/api/overview'); out.append((time.perf_counter() - t) * 1000)
lat = []; threads = [threading.Thread(target=worker, args=(lat, 3)) for _ in range(8)]
t = time.perf_counter(); [x.start() for x in threads]; [x.join() for x in threads]; wall = time.perf_counter() - t
lat.sort()

rss = None
if os.name == 'nt':
    from ctypes import wintypes
    class PMC(ctypes.Structure):
        _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD)] + [(n, ctypes.c_size_t) for n in ('PeakWorkingSetSize', 'WorkingSetSize', 'QuotaPeakPagedPoolUsage', 'QuotaPagedPoolUsage', 'QuotaPeakNonPagedPoolUsage', 'QuotaNonPagedPoolUsage', 'PagefileUsage', 'PeakPagefileUsage')]
    k32 = ctypes.WinDLL('kernel32')
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    k32.K32GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PMC), wintypes.DWORD]
    c = PMC(); c.cb = ctypes.sizeof(PMC)
    if k32.K32GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(c), c.cb): rss = c.PeakWorkingSetSize
else:
    import resource
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
print(json.dumps({'hosts': N, 'import_s': round(import_seconds, 2), 'seed_s': round(seed_seconds, 2), 'routes': results,
                  'concurrency': {'clients': 8, 'requests': len(lat), 'wall_s': round(wall, 2), 'rps': round(len(lat) / wall, 2),
                                  'p50_ms': round(lat[len(lat) // 2], 1), 'p95_ms': round(lat[int(len(lat) * .95) - 1], 1)},
                  'peak_memory_mb': round(rss / 2**20) if rss else None, 'db_mb': round(os.path.getsize(os.environ['COCKPIT_DB']) / 2**20, 1)}))
'''


def run(n):
    rnd = random.Random(n)
    now = datetime.now(timezone.utc)
    with tempfile.TemporaryDirectory(prefix='opscontrol-charge-', ignore_cleanup_errors=True) as tmp:
        root = Path(tmp)
        for py in BASE.glob('*.py'):
            if not py.name.startswith('test_') and py.name != 'loadtest.py':
                shutil.copy2(py, root / py.name)
        shutil.copytree(BASE / 'routers', root / 'routers', ignore=shutil.ignore_patterns('__pycache__'))
        (root / 'web').mkdir()
        (root / 'data').mkdir()
        inv = synthetic_inventory(n, rnd)
        (root / 'hosts.yaml').write_text(json.dumps(inv, ensure_ascii=False), encoding='utf-8')
        (root / 'data' / 'api-connections.json').write_text(json.dumps(synthetic_connections(inv['hosts'], now, rnd), ensure_ascii=False), encoding='utf-8')
        env = {k: v for k, v in os.environ.items() if not k.startswith(('INFRAOPS_', 'COCKPIT_', 'OPSCONTROL_'))}
        env.update(COCKPIT_DB=str(root / 'data' / 'state.sqlite3'), INFRAOPS_INCIDENT_SYNC='0', INFRAOPS_ALLOWED_HOSTS='*',
                   INFRAOPS_LOCAL_ROLE='admin', PYTHONIOENCODING='utf-8',
                   # Coffre de secrets introuvable : aucun identifiant réel n'est chargé dans le processus de test.
                   LOCALAPPDATA=str(root / 'aucun-coffre'))
        out = subprocess.run([sys.executable, '-c', CHILD, str(n), json.dumps(ROUTES)], cwd=root, env=env, capture_output=True,
                             text=True, encoding='utf-8', timeout=3600)
        if out.returncode:
            raise RuntimeError(out.stderr[-3000:])
        if os.environ.get('LOADTEST_PROFILE'):
            sys.stdout.write(out.stderr)
        return json.loads(out.stdout.strip().splitlines()[-1])


def main(sizes):
    report = {'generated_at': datetime.now(timezone.utc).isoformat(), 'runs': []}
    for n in sizes:
        t = time.perf_counter()
        result = run(n)
        if result.get('profile'):
            return
        result['total_s'] = round(time.perf_counter() - t, 1)
        report['runs'].append(result)
        print(f"\n== {n} serveurs · import {result['import_s']} s · base {result['db_mb']} Mo · mémoire crête {result['peak_memory_mb']} Mo")
        for route, r in result['routes'].items():
            print(f"  {route:38} {r['status']}  médiane {r['median_ms']:>8} ms  max {r['max_ms']:>8} ms  {r['bytes'] / 1024:>9.1f} Ko")
        c = result['concurrency']
        print(f"  8 clients /api/overview : {c['rps']} req/s · p50 {c['p50_ms']} ms · p95 {c['p95_ms']} ms")
    target = BASE / 'data' / 'loadtest'
    target.mkdir(parents=True, exist_ok=True)
    path = target / (datetime.now().strftime('%Y%m%d-%H%M%S') + '.json')
    path.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding='utf-8')
    print('\nRésultats :', path)


if __name__ == '__main__':
    main([int(x) for x in sys.argv[1:]] or [100, 500, 1000])
