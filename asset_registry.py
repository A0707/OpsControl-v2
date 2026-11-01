"""Durable enrollment, independent of a server's current reachability."""
from datetime import datetime, timezone
from ipaddress import ip_address
import hashlib
import sqlite3


from migrations import MODULE_TABLES

# Définition unique (migrations.py) ; enroll() la garantit encore pour les bases de test.
SCHEMA = MODULE_TABLES['registered_assets']


def admitted(host):
    # Import existing production machines already successfully reached by SSH.
    # Un ajout par un administrateur (formulaire ou import de découverte) inscrit aussi le
    # serveur, sans preuve de collecte : il doit apparaître dans le parc tout de suite,
    # « première collecte en attente ». Cela n'approuve aucune empreinte SSH (audit A5).
    return bool(host.get('active_scope') or host.get('admin_enrolled_at') or (host.get('ssh_user') and
                str(host.get('environment', '')).lower() in ('prod', 'production')))


def _known(db):
    try:
        return {key: (ip, stamp) for key, ip, stamp in db.execute('SELECT key,ip,first_seen FROM registered_assets')}
    except sqlite3.OperationalError:  # table pas encore créée : aucune inscription enregistrée
        return {}


def annotate(db, assets):
    """Lecture seule (routes GET) : marque `registered` sans rien écrire.

    Un hôte admissible mais pas encore inscrit est présenté comme inscrit, sans date
    (`registered_at` à None) : l'inscription durable a lieu après la prochaine collecte
    (`enroll`). Avant, chaque GET de la vue globale écrivait dans la base.
    """
    known = _known(db)
    for host in assets:
        record = known.get(host['key'])
        recorded = bool(record and record[0] == host['ip'])
        host['registered'] = recorded or admitted(host)
        host['registered_at'] = record[1] if recorded else None
    return assets


def enroll(db, assets):
    """Écriture : appelée après les collectes (SSH, réseau, API), jamais par un GET."""
    db.execute(SCHEMA)
    known = _known(db)
    now = datetime.now(timezone.utc).isoformat()
    for host in assets:
        if admitted(host) and (host['key'] not in known or known[host['key']][0] != host['ip']):
            db.execute('INSERT OR REPLACE INTO registered_assets(key, ip, first_seen) VALUES(?,?,?)', (host['key'], host['ip'], now))
            known[host['key']] = (host['ip'], now)
        record = known.get(host['key'])
        host['registered'] = bool(record and record[0] == host['ip'])
        host['registered_at'] = record[1] if host['registered'] else None
    return assets


def names(item, fields=('key', 'name', 'fqdn')):
    return {str(item.get(k) or '').lower().rstrip('.') for k in fields} - {''}


def _hashable(value):
    try:
        hash(value)
        return True
    except TypeError:
        return False


class MatchIndex:
    """Index de rapprochement, construit une fois par requête (lot 7).

    Les recherches « quel serveur porte ce nom / cette IP ? » balayaient tout le parc pour
    chaque élément de chaque source : O(serveurs × éléments), puis O(n²) pour /api/daily qui
    rapproche chaque serveur. Les règles sont inchangées (mêmes noms, mêmes IP, unicité exigée) ;
    seul le coût change. Un élément ambigu reste ambigu : aucune association n'est inventée.
    """

    def __init__(self, hosts):
        self.name_owners, self.ip_owners = {}, {}
        for asset in hosts:
            for name in names(asset):
                self.name_owners.setdefault(name, set()).add(asset['key'])
            ip = asset.get('ip')
            if _hashable(ip):
                self.ip_owners.setdefault(ip, set()).add(asset['key'])
        self._sources = {}

    def owners(self, item_names=(), ips=()):
        found = set()
        for name in item_names:
            found |= self.name_owners.get(name, set())
        for ip in ips:
            if _hashable(ip):
                found |= self.ip_owners.get(ip, set())
        return found

    def source_items(self, source, kind, items, ip_field, name_fields):
        """Éléments d'une source (hôtes Zabbix, agents Wazuh) indexés par IP et par nom."""
        cache_key = (source.get('key'), kind)
        if cache_key not in self._sources:
            by_ip, by_name, entries = {}, {}, []
            for position, item in enumerate(items):
                item_ips = item.get(ip_field, []) if ip_field == 'addresses' else [item.get(ip_field)]
                if not isinstance(item_ips, list):
                    item_ips = []
                item_names = names(item, name_fields)
                entries.append((item, item_names, item_ips))
                for ip in item_ips:
                    if _hashable(ip):
                        by_ip.setdefault(ip, []).append(position)
                for name in item_names:
                    by_name.setdefault(name, []).append(position)
            self._sources[cache_key] = (entries, by_ip, by_name)
        return self._sources[cache_key]

    def bacula_jobs(self, source, inventory):
        """Derniers jobs Bacula par serveur propriétaire unique (calculé une fois par source)."""
        cache_key = (source.get('key'), 'bacula')
        if cache_key not in self._sources:
            from bacula_inventory import latest_jobs
            by_owner = {}
            for job in latest_jobs(inventory):
                client = str(job.get('client') or '').lower().rstrip('.')
                aliases = {client, client[:-3] if client.endswith('-fd') else client} - {''}
                owners = self.owners(aliases)
                if len(owners) == 1:
                    by_owner.setdefault(next(iter(owners)), []).append(job)
            self._sources[cache_key] = by_owner
        return self._sources[cache_key]

    def zabbix_problems(self, source, problems, host_names):
        """Problèmes Zabbix dont un hôte porte l'un de ces noms (index par nom, une fois par source)."""
        cache_key = (source.get('key'), 'zabbix-problems')
        if cache_key not in self._sources:
            by_name = {}
            for position, problem in enumerate(problems):
                for name in {str(n).lower().rstrip('.') for n in problem.get('hosts', [])}:
                    by_name.setdefault(name, []).append(position)
            self._sources[cache_key] = by_name
        by_name = self._sources[cache_key]
        positions = set()
        for name in host_names:
            positions.update(by_name.get(name, []))
        return [problems[p] for p in sorted(positions)]

    def items_for(self, host, source, kind, items, ip_field, name_fields):
        entries, by_ip, by_name = self.source_items(source, kind, items, ip_field, name_fields)
        positions = set(by_ip.get(host.get('ip'), []) if _hashable(host.get('ip')) else [])
        for name in names(host):
            positions.update(by_name.get(name, []))
        return [entries[p] for p in sorted(positions)]


def initial_audit_hosts(hosts):
    return [h for h in hosts if not h.get('audit_recorded') and h.get('collect_enabled', True)]


def connection_evidence(source):
    last = source.get('last_result') or {}
    prior = source.get('last_success_result')
    if last.get('status') != 'observed' and prior:
        return {**prior, 'status': 'unknown', 'error': last.get('error'),
                'last_attempt_at': last.get('collected_at')}
    return last


def discover(hosts, connections):
    """Require independent, fresh Proxmox and Zabbix evidence; never guess an IP."""
    from synchronization import fresh
    zabbix = []
    guests = []
    for source in connections:
        result = source.get('last_result') or {}
        if result.get('status') != 'observed' or not fresh(result.get('collected_at')):
            continue
        inv = result.get('inventory') or {}
        if source['provider'] == 'Zabbix':
            zabbix.extend(inv.get('hosts', []))
        if source['provider'] == 'Proxmox':
            for node in inv.get('nodes', []):
                guests.extend((g, node['name'], source['key']) for g in node.get('guests', []) if g.get('status') == 'running')
    additions, pending = [], []
    for guest, node, source in guests:
        name = str(guest.get('name') or '').lower().rstrip('.')
        if not name or any(name in names(h) for h in hosts):
            continue
        reason = None
        candidates = [z for z in zabbix if name in names(z, ('name', 'host')) and z.get('status') == 'monitored']
        addresses = candidates[0].get('addresses', []) if len(candidates) == 1 else []
        valid = set()
        for address in addresses:
            try:
                ip = ip_address(address)
                if not (ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local):
                    valid.add(str(ip))
            except ValueError:
                pass
        if len(str(guest['name'])) > 120:
            reason = 'Nom trop long pour l’inventaire'
        elif sum(1 for g, _, _ in guests if str(g.get('name') or '').lower().rstrip('.') == name) != 1:
            reason = 'Nom Proxmox ambigu'
        elif len(candidates) != 1 or len(valid) != 1:
            reason = 'Adresse unique non confirmée par Zabbix'
        elif any(h['ip'] == next(iter(valid)) for h in hosts + additions):
            reason = 'Adresse déjà associée à un autre serveur'
        if reason:
            pending.append({'name': name, 'vmid': guest.get('vmid'), 'reason': reason})
            continue
        key = 'discovered-' + hashlib.sha256(f'{source}:{guest["vmid"]}'.encode()).hexdigest()[:16]
        if any(h['key'] == key for h in hosts + additions):
            continue
        additions.append({'key': key, 'name': guest['name'], 'ip': next(iter(valid)),
                          'role': 'À renseigner', 'environment': 'À renseigner', 'services': [],
                          'criticality': 'standard', 'collect_enabled': True, 'vmid': guest['vmid'],
                          'node': node, 'discovered_from': source})
    return additions, pending


def source_details(host, hosts, connections, index=None):
    """Keep per-host evidence separate from infrastructure-wide aggregates.

    `index` (MatchIndex) est partagé quand l'appelant rapproche plusieurs serveurs.
    """
    from synchronization import fresh
    result = []
    index = index or MatchIndex(hosts)
    for source in connections:
        r = connection_evidence(source)
        inv = r.get('inventory') or {}
        provider = source['provider']
        evidence = {}
        if provider == 'Zabbix':
            matches = index.items_for(host, source, 'zabbix', inv.get('hosts', []), 'addresses', ('host', 'name'))
            if len(matches) == 1:
                z, z_names, z_ips = matches[0]
                owners = index.owners(z_names, z_ips)
                if len(owners) == 1:
                    evidence = {'host': z, 'problems': index.zabbix_problems(source, inv.get('problems') or [], z_names),
                                'problems_measured': isinstance(inv.get('problems'), list),
                                'problems_scope': inv.get('problems_scope'), 'problems_error': inv.get('problems_error')}
        elif provider == 'Bacula':
            matched = index.bacula_jobs(source, inv).get(host['key'], [])
            if matched:
                evidence = {'jobs_count': len(matched), 'latest_jobs': matched,
                            'recent_jobs': sorted(matched, key=lambda j: j.get('jobid') or 0, reverse=True)[:10]}
        elif provider == 'Wazuh':
            matched = index.items_for(host, source, 'wazuh', inv.get('agents_inventory', []), 'ip', ('name',))
            if len(matched) == 1:
                a, a_names, a_ips = matched[0]
                owners = index.owners(a_names, a_ips)
                if len(owners) == 1:
                    evidence = {'agent': a}
        if evidence or source.get('host_key') == host['key']:
            result.append({'provider': provider, 'key': source['key'], 'collected_at': r.get('collected_at'),
                           'fresh': r.get('status') == 'observed' and fresh(r.get('collected_at')),
                           'error': r.get('error'), 'evidence': evidence,
                           'scope': 'serveur' if evidence else 'Source hébergée ; indicateurs globaux, pas une preuve de couverture de ce serveur'})
    return result


def backup_summaries(hosts, connections):
    """Compact server evidence, indexed once; a missing match is not a failed backup."""
    from bacula_inventory import latest_jobs
    from synchronization import fresh
    owners, matched = {}, {h['key']: [] for h in hosts}
    for host in hosts:
        for name in names(host):
            owners.setdefault(name, set()).add(host['key'])
    for source in connections:
        if source.get('provider') != 'Bacula':
            continue
        result = connection_evidence(source)
        recent = result.get('status') == 'observed' and fresh(result.get('collected_at'))
        for job in latest_jobs(result.get('inventory') or {}):
            client = str(job.get('client') or '').lower().rstrip('.')
            aliases = {client, client[:-3] if client.endswith('-fd') else client} - {''}
            candidates = set().union(*(owners.get(n, set()) for n in aliases))
            if len(candidates) == 1:
                matched[next(iter(candidates))].append((source['key'], result.get('collected_at'), recent, job))
    rank = {'critical': 0, 'warning': 1, 'unknown': 2, 'running': 3, 'pending': 4, 'ok': 5}
    summaries = {}
    for key, entries in matched.items():
        stamps = [e[1] for e in entries if e[1]]
        successes = [e[3].get('endtime') for e in entries if e[3].get('severity') == 'ok' and e[3].get('endtime')]
        summaries[key] = {'matched': bool(entries), 'jobs_count': len(entries),
                          'severity': min((e[3].get('severity', 'unknown') for e in entries), key=lambda s: rank.get(s, 2), default='unknown'),
                          'fresh': bool(entries) and all(e[2] for e in entries),
                          'collected_at': min(stamps) if stamps else None,
                          'last_success': max(successes) if successes else None,
                          'sources_count': len({e[0] for e in entries}),
                          'scope': 'Dernier passage connu par job et client associé sans ambiguïté. Ne prouve pas la restaurabilité ni le respect du planning.'}
    return summaries
