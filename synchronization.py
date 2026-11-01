"""Read-only federation: retain source identity and never infer health from coverage."""
import threading
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

from audit_engine import redact


def time_now_bucket(seconds=5):
    return int(datetime.now(timezone.utc).timestamp() // seconds)


def fresh(timestamp):
    try:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(timestamp)).total_seconds()
        return 0 <= age <= 900
    except (TypeError, ValueError):
        return False


def federate(hosts, connections, network=None):
    from asset_registry import connection_evidence
    assets = [{**h, 'proxmox_matches': []} for h in hosts]
    unmatched = []
    sources = []
    # Lot 7 : index construits une fois (noms, vmid/nœud, preuves par source). Les règles de
    # rapprochement sont inchangées ; le balayage complet du parc par élément (O(n²)) disparaît.
    evidence_of = {id(c): connection_evidence(c) for c in connections}
    by_name, by_id = {}, {}
    for position, h in enumerate(assets):
        for name in {str(h.get(k) or '').lower().rstrip('.') for k in ('name', 'fqdn', 'key')}:
            by_name.setdefault(name, []).append(position)
        try:
            by_id.setdefault((h.get('vmid'), h.get('node')), []).append(position)
        except TypeError:  # vmid/nœud non hachables : pas d'association par identifiant
            pass
    for c in connections:
        r = evidence_of[id(c)]
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
                positions = set(by_name.get(g['name'].lower().rstrip('.'), [])) if g.get('name') else set()
                try:
                    positions.update(by_id.get((g['vmid'], n['name']), []))
                except TypeError:
                    pass
                candidates = [assets[p] for p in sorted(positions)]
                if len(candidates) == 1:
                    candidates[0]['proxmox_matches'].append(evidence)
                else:
                    unmatched.append({**evidence, 'reason': 'Correspondance ambiguë' if candidates else 'Serveur absent de l’inventaire SSH'})
    for h in assets:
        h['association'] = 'unique' if len(h['proxmox_matches']) == 1 else 'ambiguous' if h['proxmox_matches'] else 'unmatched'
    network_by_key = {row['key']: row for row in (network or [])}
    # Liens Zabbix : ensemble des adresses et des noms par source, au lieu d'un balayage par serveur.
    zabbix_index = {}
    for c in connections:
        if c.get('provider') == 'Zabbix':
            addresses, znames = set(), set()
            for z in (evidence_of[id(c)].get('inventory') or {}).get('hosts', []):
                addresses.update(a for a in z.get('addresses', []) if isinstance(a, str))
                znames.update(str(z.get(k) or '').lower().rstrip('.') for k in ('host', 'name'))
            zabbix_index[id(c)] = (addresses, znames)
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
            r = evidence_of[id(c)]
            linked = c.get('host_key') == h['key']
            if c.get('provider') == 'Zabbix':
                addresses, znames = zabbix_index[id(c)]
                # A shared IP/name is evidence, not a forced identity merge.
                if h.get('ip') in addresses or names & znames:
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


# Champs Proxmox lus par la page Synchronisation (colonnes « Cluster / nœud / VMID » et
# « État API »). L'allègement des listes retire `proxmox_matches` complet (adresses,
# disques…) ; sans ce résumé, la page levait « reading map » sur un champ absent.
SYNC_MATCH_FIELDS = ('cluster', 'node', 'vmid', 'status', 'fresh')


def sync_row(host):
    from payload_slim import slim
    row = slim(host)
    row['proxmox_matches'] = [{k: m.get(k) for k in SYNC_MATCH_FIELDS}
                              for m in host.get('proxmox_matches') or []]
    return row


def install(app, context):
    from fastapi import APIRouter
    router = APIRouter()
    guard = threading.Lock()
    state = {'running': False, 'completed': 0, 'total': 0, 'errors': [], 'started_at': None}

    def run(keys):
        def collect(key):
            try:
                result = context.collect_api_connection(key)
                error = result.get('error')
            except Exception as exc:
                # collect_api_connection already turns expected API/network failures into
                # a safe message (never raising); reaching here means an unexpected local
                # bug. Keep it debuggable but still redact anything secret-shaped.
                error = getattr(exc, 'detail', None) if hasattr(exc, 'status_code') else None
                error = error or ('Collecte API impossible : ' + redact(exc))
            with guard:
                state['completed'] += 1
                if error:
                    state['errors'].append({'key': key, 'error': error})
        try:
            with ThreadPoolExecutor(max_workers=3) as pool:
                list(pool.map(collect, keys))
            from asset_registry import discover, enroll
            if hasattr(context, 'connect'):
                # Inscription durable après la collecte (les routes GET ne font qu'annoter).
                assets = federate(context.rows(), context.api_connections(), context.network_rows())['assets']
                with context.connect() as db:
                    enroll(db, assets)
            additions, pending = discover(context.HOSTS, context.api_connections())
            added = context.add_discovered_hosts(additions) if hasattr(context, 'add_discovered_hosts') else []
            with guard:
                state['discovery'] = {'added': [h['key'] for h in added], 'pending': pending,
                                      'deferred': len(additions) - len(added)}
            if hasattr(context, 'collection_done'):
                context.collection_done('api')
            if added:
                context.launch(added, 'decouverte-api', 'nouveaux')
                context.launch_network(context.HOSTS, 'decouverte-api')
        finally:
            with guard:
                state['running'] = False

    def launch():
        with guard:
            if not state['running']:
                keys = [c['key'] for c in context.api_connections()]
                state.update(running=True, completed=0, total=len(keys), errors=[], started_at=datetime.now(timezone.utc).isoformat())
                threading.Thread(target=run, args=(keys,), daemon=True).start()
            return dict(state)

    def job_snapshot():
        with guard:
            return dict(state)

    context.api_sync_state = job_snapshot
    context.launch_api_sync = launch

    import response_cache

    @router.get('/api/sync')
    @response_cache.cached_json('sync', lambda: context.data_revision() if hasattr(context, 'data_revision') else str(time_now_bucket()))
    def snapshot():
        result = federate(context.rows(), context.api_connections(), context.network_rows())
        if hasattr(context, 'connect'):
            from asset_registry import annotate
            with context.connect() as db:annotate(db,result['assets'])
        with guard:
            result['job'] = dict(state)
        with context.lock:
            result['ssh_job'] = dict(context.job)
        with context.net_lock:
            result['network_job'] = dict(context.net_job)
        # Page interrogée toutes les 5 s : même allègement que la Vue globale,
        # en gardant le résumé Proxmox que cette page affiche.
        result['assets'] = [sync_row(h) for h in result['assets']]
        return result

    @router.post('/api/sync', status_code=202)
    def synchronize():
        return {'api': launch(), 'ssh': context.launch(context.HOSTS, 'synchronisation-locale', 'all'),
                'network': context.launch_network(context.HOSTS, 'synchronisation-locale')}

    @router.post('/api/availability/refresh', status_code=202)
    def refresh_availability():
        return {'api': launch(),
                'network': context.launch_network(context.HOSTS, 'disponibilite-locale')}
    app.include_router(router)  # routes de ce module : APIRouter, inclus en fin d'installation
