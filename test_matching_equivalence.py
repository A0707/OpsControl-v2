"""Lot 7 : les rapprochements indexés donnent exactement les mêmes résultats que l'ancien code.

Les implémentations d'origine (balayage O(n²)) sont conservées ici telles quelles, comme
référence, et comparées aux nouvelles sur des parcs aléatoires comportant des homonymes,
des IP partagées, des VM ambiguës et des agents inconnus. Aucune association ne doit apparaître
ou disparaître : seule la complexité change.
"""
import contextlib
import json
import random
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import asset_registry
import batch_monitor
import synchronization
from asset_registry import connection_evidence, names
from synchronization import fresh


# ----------------------------------------------------------------------------- références (code d'origine)
def federate_ref(hosts, connections, network=None):
    from asset_registry import connection_evidence
    assets = [{**h, 'proxmox_matches': []} for h in hosts]
    unmatched = []
    sources = []
    for c in connections:
        r = connection_evidence(c)
        sources.append({'key': c['key'], 'name': c['name'], 'provider': c['provider'],
                        'collected_at': r.get('collected_at'), 'fresh': r.get('status') == 'observed' and fresh(r.get('collected_at')),
                        'status': r.get('status', 'unknown'), 'error': r.get('error'),
                        'auth_configured': c.get('auth_configured')})
        if c['provider'] != 'Proxmox':
            continue
        for n in r.get('inventory', {}).get('nodes', []):
            for g in n.get('guests', []):
                evidence = {**g, 'connection_key': c['key'], 'cluster': c['name'],
                            'collected_at': r.get('collected_at'), 'fresh': r.get('status') == 'observed' and fresh(r.get('collected_at'))}
                candidates = []
                for h in assets:
                    names = {str(h.get(k) or '').lower().rstrip('.') for k in ('name', 'fqdn', 'key')}
                    exact_name = bool(g.get('name')) and g['name'].lower().rstrip('.') in names
                    exact_id = h.get('vmid') == g['vmid'] and h.get('node') == n['name']
                    if exact_name or exact_id:
                        candidates.append(h)
                if len(candidates) == 1:
                    candidates[0]['proxmox_matches'].append(evidence)
                else:
                    unmatched.append({**evidence, 'reason': 'Correspondance ambiguë' if candidates else 'Serveur absent de l’inventaire SSH'})
    for h in assets:
        h['association'] = 'unique' if len(h['proxmox_matches']) == 1 else 'ambiguous' if h['proxmox_matches'] else 'unmatched'
    network_by_key = {row['key']: row for row in (network or [])}
    for h in assets:
        net = network_by_key.get(h['key'], {})
        net_valid = net.get('ip') == h.get('ip') and fresh(net.get('collected_at'))
        h['network_evidence'] = {'ping': net.get('ping') if net_valid else None,
                                 'fresh': net_valid, 'collected_at': net.get('collected_at')}
        matches = h['proxmox_matches']
        if h['association'] != 'unique':
            reason = 'Association Proxmox absente ou ambiguë'
        elif not matches[0]['fresh']:
            reason = 'Collecte Proxmox ancienne ou en échec'
        elif matches[0].get('status') != 'running':
            reason = 'VM non démarrée dans Proxmox'
        elif not net_valid:
            reason = 'Ping ancien ou non mesuré pour cette IP'
        elif net.get('ping') is not True:
            reason = 'Ping sans réponse (ICMP peut être filtré)'
        else:
            reason = None
        h['active_scope'] = reason is None
        h['scope_reason'] = reason
        h['source_links'] = []
        names = {str(h.get(k) or '').lower().rstrip('.') for k in ('key', 'name', 'fqdn')}
        names.discard('')
        for c in connections:
            r = connection_evidence(c)
            linked = c.get('host_key') == h['key']
            if c.get('provider') == 'Zabbix':
                for z in (r.get('inventory') or {}).get('hosts', []):
                    if h.get('ip') in z.get('addresses', []) or names.intersection(
                            str(z.get(k) or '').lower().rstrip('.') for k in ('host', 'name')):
                        # A shared IP/name is evidence, not a forced identity merge.
                        linked = True
            if linked:
                h['source_links'].append({'key': c['key'], 'provider': c['provider'],
                                         'fresh': r.get('status') == 'observed' and fresh(r.get('collected_at'))})
    return {'assets': assets, 'unmatched_guests': unmatched, 'sources': sources,
            'scope_counts': {'active': sum(h['active_scope'] for h in assets),
                             'excluded': sum(not h['active_scope'] for h in assets)},
            # Ne proposer que des produits réellement supportés par
            # management.Connection : annoncer « à raccorder » une source que le
            # formulaire refuserait serait une promesse que l'interface ne tient pas.
            'missing_providers': [p for p in ('Proxmox', 'Wazuh', 'Zabbix', 'Elasticsearch', 'Bacula') if not any(c['provider'] == p for c in connections)]}



def source_details_ref(host, hosts, connections):
    """Keep per-host evidence separate from infrastructure-wide aggregates."""
    from synchronization import fresh
    result = []
    name_owners = {}
    for asset in hosts:
        for name in names(asset):
            name_owners.setdefault(name, set()).add(asset['key'])
    for source in connections:
        r = connection_evidence(source)
        inv = r.get('inventory') or {}
        provider = source['provider']
        evidence = {}
        if provider == 'Zabbix':
            matches = [z for z in inv.get('hosts', []) if host['ip'] in z.get('addresses', []) or names(host) & names(z, ('host', 'name'))]
            if len(matches) == 1:
                z = matches[0]
                owners = [h for h in hosts if h['ip'] in z.get('addresses', []) or names(h) & names(z, ('host', 'name'))]
                if len(owners) == 1:
                    evidence = {'host': z, 'problems': [p for p in (inv.get('problems') or []) if names(z, ('host', 'name')) & {str(n).lower().rstrip('.') for n in p.get('hosts', [])}],
                                'problems_measured': isinstance(inv.get('problems'), list),
                                'problems_scope': inv.get('problems_scope'), 'problems_error': inv.get('problems_error')}
        elif provider == 'Bacula':
            from bacula_inventory import latest_jobs
            matched = []
            for job in latest_jobs(inv):
                client = str(job.get('client') or '').lower().rstrip('.')
                aliases = {client, client[:-3] if client.endswith('-fd') else client} - {''}
                owners = set().union(*(name_owners.get(alias, set()) for alias in aliases))
                if owners == {host['key']}:
                    matched.append(job)
            if matched:
                evidence = {'jobs_count': len(matched), 'latest_jobs': matched,
                            'recent_jobs': sorted(matched, key=lambda j: j.get('jobid') or 0, reverse=True)[:10]}
        elif provider == 'Wazuh':
            matched = [a for a in inv.get('agents_inventory', []) if a.get('ip') == host['ip'] or names(host) & names(a, ('name',))]
            if len(matched) == 1:
                a = matched[0]
                owners = [h for h in hosts if a.get('ip') == h['ip'] or names(h) & names(a, ('name',))]
                if len(owners) == 1:
                    evidence = {'agent': a}
        if evidence or source.get('host_key') == host['key']:
            result.append({'provider': provider, 'key': source['key'], 'collected_at': r.get('collected_at'),
                           'fresh': r.get('status') == 'observed' and fresh(r.get('collected_at')),
                           'error': r.get('error'), 'evidence': evidence,
                           'scope': 'serveur' if evidence else 'Source hébergée ; indicateurs globaux, pas une preuve de couverture de ce serveur'})
    return result



def snapshot_ref(context):
    from synchronization import fresh
    from asset_registry import connection_evidence, names
    with context.connect() as db:
        saved = {(k, ip):json.loads(p) for k,ip,p in db.execute('SELECT key,ip,payload FROM batch_states')}
    jobs, coverage = [], []
    hosts = list(context.HOSTS)
    for host in hosts:
        last = saved.get((host['key'], host['ip']), {})
        current = last.get('status') == 'observed' and fresh(last.get('collected_at'))
        evidence = last if last.get('status') == 'observed' else last.get('last_observation', last)
        coverage.append({'host_key':host['key'], 'name':host['name'], 'ip':host['ip'], 'status':last.get('status','unknown'),
                         'fresh':current, 'collected_at':last.get('collected_at'),
                         'limitations':last.get('limitations', ['Inventaire Batch non collecté'])})
        for job in evidence.get('jobs', []):
            jobs.append({**job, 'host_key':host['key'], 'host_name':host['name'], 'ip':host['ip'],
                         'collected_at':evidence.get('collected_at'), 'fresh':current})
    # One row per latest Bacula job name and client, preserving source identity.
    for source in context.api_connections():
        if source['provider'] != 'Bacula':
            continue
        r = connection_evidence(source)
        latest = {}
        for job in (r.get('inventory') or {}).get('jobs', []):
            key = (job.get('name'), job.get('client'))
            if (job.get('jobid') or 0) > (latest.get(key,{}).get('jobid') or -1):
                latest[key] = job
        for (name, client), job in latest.items():
            alias = str(client or '').lower().rstrip('.')
            aliases = {alias, alias[:-3] if alias.endswith('-fd') else alias} - {''}
            matched = [h for h in hosts if names(h) & aliases]
            host = matched[0] if len(matched)==1 else {}
            jobs.append({'id':source['key']+':'+str(job.get('jobid')), 'name':name,'kind':'bacula',
                         'source':source['name'], 'host_key':host.get('key'), 'host_name':host.get('name') or client or 'Client non rapproché',
                         'ip':host.get('ip'), 'state':{'ok':'success','critical':'failed','running':'running','warning':'warning'}.get(job.get('severity'),'unknown'),
                         'schedule':'Horaire planifié non collecté via cette API', 'next_run':None,
                         'last_run':job.get('endtime'), 'timezone':'Fuseau du Director non mesuré',
                         'collected_at':r.get('collected_at'), 'fresh':r.get('status')=='observed' and fresh(r.get('collected_at')),
                         'evidence':job.get('status_label'), 'owner':'Compte du job non mesuré'})
    # Récence du passage (audit UI du 31/10, fiche 06.2) : règle reprise telle quelle.
    for job in jobs:
        job['run_recent'] = batch_monitor.run_recent(job.get('last_run'))
    return {'jobs':jobs, 'coverage':coverage, 'counts':{s:sum(j['state']==s for j in jobs) for s in ('running','failed','success','scheduled','warning','unknown')},
            'fresh_failures':sum(j['state']=='failed' and j['fresh'] and j['run_recent'] is not False for j in jobs)}




# ----------------------------------------------------------------------------- jeux aléatoires
def dataset(seed, n=60):
    rnd = random.Random(seed)
    now = datetime.now(timezone.utc)
    stamp = (now - timedelta(minutes=rnd.choice([2, 2, 2, 40]))).isoformat()
    pool = [f'srv{i:03d}' for i in range(n)]
    hosts = []
    for i in range(n):
        name = rnd.choice(pool) if rnd.random() < .08 else pool[i]          # homonymes
        ip = f'10.0.0.{rnd.randrange(n)}' if rnd.random() < .1 else f'10.1.{i // 250}.{i % 250}'  # IP partagées
        h = {'key': f'k{i:03d}', 'name': name, 'ip': ip, 'environment': 'PROD'}
        if rnd.random() < .3:
            h['fqdn'] = name + '.corp.test.'
        if rnd.random() < .3:
            h['vmid'], h['node'] = 100 + rnd.randrange(n), f'pve{rnd.randrange(3)}'
        hosts.append(h)
    guests = [{'vmid': 100 + i, 'name': rnd.choice(pool + ['inconnu', 'SRV001', 'srv002.']), 'status': rnd.choice(['running', 'stopped'])} for i in range(n)]
    nodes = [{'name': f'pve{k}', 'guests': [g for j, g in enumerate(guests) if j % 3 == k]} for k in range(3)]
    zhosts = [{'host': rnd.choice(pool + ['zbx-seul']), 'name': rnd.choice(pool + ['']),
               'addresses': [f'10.1.0.{rnd.randrange(n)}'] if rnd.random() < .7 else []} for _ in range(n)]
    agents = [{'name': rnd.choice(pool + ['agent-x']), 'ip': rnd.choice([f'10.1.0.{rnd.randrange(n)}', None, 'any'])} for _ in range(n)]
    jobs = [{'jobid': j, 'name': f'job{j % 9}', 'client': rnd.choice(pool + ['inconnu']) + rnd.choice(['-fd', '']),
             'severity': rnd.choice(['ok', 'critical']), 'endtime': stamp} for j in range(n)]

    def conn(key, provider, inventory, host_key=None):
        status = rnd.choice(['observed', 'observed', 'unknown'])
        c = {'key': key, 'name': key, 'provider': provider, 'last_result': {'status': status, 'collected_at': stamp, 'inventory': inventory}}
        if status != 'observed' and rnd.random() < .5:
            c['last_success_result'] = {'status': 'observed', 'collected_at': stamp, 'inventory': inventory}
            c['last_result'] = {'status': 'unknown', 'collected_at': stamp, 'error': 'échec'}
        if host_key:
            c['host_key'] = host_key
        return c
    connections = [conn('pve', 'Proxmox', {'nodes': nodes}),
                   conn('zbx', 'Zabbix', {'hosts': zhosts, 'problems': [{'hosts': [z['host']], 'description': 'p'} for z in zhosts[:10]]}, hosts[0]['key']),
                   conn('wazuh', 'Wazuh', {'agents_inventory': agents}),
                   conn('bacula', 'Bacula', {'jobs': jobs, 'latest': jobs})]
    network = [{'key': h['key'], 'ip': h['ip'], 'ping': rnd.choice([True, False, None]), 'collected_at': stamp} for h in hosts if rnd.random() < .8]
    return hosts, connections, network


class EquivalenceTests(unittest.TestCase):
    SEEDS = range(40)

    def test_federate_identical(self):
        for seed in self.SEEDS:
            hosts, connections, network = dataset(seed)
            self.assertEqual(synchronization.federate(hosts, connections, network),
                             federate_ref(hosts, connections, network), f'graine {seed}')

    def test_source_details_identical_with_and_without_shared_index(self):
        for seed in self.SEEDS:
            hosts, connections, network = dataset(seed)
            assets = synchronization.federate(hosts, connections, network)['assets']
            index = asset_registry.MatchIndex(assets)
            for host in assets:
                expected = source_details_ref(host, assets, connections)
                self.assertEqual(asset_registry.source_details(host, assets, connections), expected, f'graine {seed} {host["key"]}')
                self.assertEqual(asset_registry.source_details(host, assets, connections, index), expected,
                                 f'graine {seed} {host["key"]} (index partagé)')

    def test_batch_snapshot_identical(self):
        for seed in range(15):
            hosts, connections, _ = dataset(seed)
            db = sqlite3.connect(':memory:')
            db.execute('CREATE TABLE batch_states(key TEXT PRIMARY KEY, ip TEXT, payload TEXT)')

            @contextlib.contextmanager
            def connect():
                yield db
            ctx = SimpleNamespace(HOSTS=hosts, connect=connect, api_connections=lambda: connections)
            self.assertEqual(batch_monitor.snapshot(ctx), snapshot_ref(ctx), f'graine {seed}')
            db.close()

    def test_datasets_exercise_ambiguous_and_unique_cases(self):
        # Garde-fou du test lui-même : les jeux contiennent bien des cas uniques ET ambigus.
        seen = set()
        for seed in self.SEEDS:
            result = federate_ref(*dataset(seed))
            seen.update(h['association'] for h in result['assets'])
            seen.update(g['reason'] for g in result['unmatched_guests'])
        self.assertTrue({'unique', 'unmatched', 'Correspondance ambiguë'} <= seen, seen)

    def test_ambiguity_is_preserved(self):
        hosts = [{'key': 'a', 'name': 'web', 'ip': '10.0.0.1'}, {'key': 'b', 'name': 'web', 'ip': '10.0.0.2'}]
        connections = [{'key': 'pve', 'name': 'pve', 'provider': 'Proxmox', 'last_result': {'status': 'observed', 'collected_at': datetime.now(timezone.utc).isoformat(),
                        'inventory': {'nodes': [{'name': 'n', 'guests': [{'vmid': 1, 'name': 'web', 'status': 'running'}]}]}}}]
        result = synchronization.federate(hosts, connections, [])
        self.assertEqual([h['proxmox_matches'] for h in result['assets']], [[], []], 'VM homonyme : aucune association inventée')
        self.assertEqual(result['unmatched_guests'][0]['reason'], 'Correspondance ambiguë')


if __name__ == '__main__':
    unittest.main()
