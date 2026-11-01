"""Daily operating summary; source health never substitutes for host evidence."""
from datetime import datetime, timezone
from synchronization import federate, fresh
from asset_registry import annotate, connection_evidence, source_details, MatchIndex
from server_alerts import build as host_alerts


SEVERITY_RANK = {'critical': 0, 'unreachable': 1, 'warning': 2}
GROUP_SAMPLES = 12


def summarize_issue(message):
    """Ramene un message de collecte a sa cause, sans la sortie brute de l'outil.

    Les 35 entrees de « Couverture a completer » portaient chacune 200 caracteres
    de sortie OpenSSH (« channel 0: open failed… Connection closed by UNKNOWN
    port 65535 »), repetee a l'identique. L'information utile tient en quelques
    mots ; le detail reste consultable dans la fiche du serveur.
    """
    texte = (message or '').strip()
    if not texte:
        return 'Cause non renseignee'
    causes = [
        ('No route to host', 'Aucune route vers l hote'),
        ('timed out', 'Delai depasse'),
        ('Connection refused', 'Connexion refusee'),
        ('Permission denied', 'Authentification refusee'),
        ('Host key verification', 'Empreinte SSH non verifiee'),
        ('Audit initial requis', 'Audit initial requis'),
    ]
    for motif, libelle in causes:
        if motif.lower() in texte.lower():
            return libelle
    # Cause inconnue : on garde le debut du message, jamais les 200 caracteres.
    court = texte.split(':')[0].strip()
    return (court[:70] + '…') if len(court) > 70 else (court or texte[:70])


def group_attention(attention):
    """Regroupe les serveurs sans audit par cause, comme les priorites."""
    groups = {}
    for host in attention:
        cause = summarize_issue((host.get('issues') or [None])[0])
        group = groups.get(cause)
        if group is None:
            group = groups[cause] = {'cause': cause, 'total': 0, 'hosts': []}
        group['total'] += 1
        if len(group['hosts']) < GROUP_SAMPLES:
            group['hosts'].append({k: host[k] for k in ('key', 'name', 'ip')})
    ordered = sorted(groups.values(), key=lambda g: -g['total'])
    for group in ordered:
        group['truncated'] = group['total'] > len(group['hosts'])
    return ordered


def group_priorities(priorities):
    """Regroupe les anomalies par cause, avec le total EXACT de chaque cause.

    Une panne qui touche 26 serveurs est un evenement, pas 26. Sans ce
    regroupement, la troncature alphabetique de la liste plate remplissait les
    30 places avec un seul message repete et masquait toutes les autres causes :
    mesure faite en exploitation, 30 entrees pour 1 seule cause reelle.

    `hosts` est un echantillon borne ; `total` reste le compte reel, pour que
    l'interface n'annonce jamais un chiffre tronque.
    """
    groups = {}
    for p in priorities:
        key = (p.get('source', 'SSH'), p['severity'], p['title'])
        group = groups.get(key)
        if group is None:
            group = groups[key] = {'severity': p['severity'], 'title': p['title'], 'domain': p.get('domain'), 'source': p.get('source', 'SSH'),
                                   'total': 0, 'stale_total': 0, 'recent': None, 'hosts': []}
        group['total'] += 1
        group['stale_total'] += bool(p['stale'])
        if p.get('collected_at') and (group['recent'] is None or p['collected_at'] > group['recent']):
            group['recent'] = p['collected_at']
        if len(group['hosts']) < GROUP_SAMPLES:
            group['hosts'].append({k: p[k] for k in ('host_key', 'host_name', 'collected_at', 'stale')})
    ordered = sorted(groups.values(),
                     key=lambda g: (g['stale_total'] >= g['total'], SEVERITY_RANK.get(g['severity'], 9), -g['total']))
    for group in ordered:
        group['truncated'] = group['total'] > len(group['hosts'])
    return ordered


def diversified(priorities, limit):
    """Tronque en laissant chaque cause representee, au lieu du premier arrive.

    Tour de role entre causes : une cause massive ne peut plus occuper toutes
    les places et effacer les anomalies reellement mesurees.
    """
    if len(priorities) <= limit:
        return priorities
    par_cause = {}
    for p in priorities:
        par_cause.setdefault((p.get('source', 'SSH'), p['severity'], p['title']), []).append(p)
    files = list(par_cause.values())
    retenus, index = [], 0
    while len(retenus) < limit and any(files):
        progression = False
        for file in files:
            if index < len(file):
                retenus.append(file[index])
                progression = True
                if len(retenus) >= limit:
                    break
        if not progression:
            break
        index += 1
    return retenus


def build(context):
    connections = context.api_connections()
    data = federate(context.rows(), connections, context.network_rows())
    hosts = data['assets']
    with context.connect() as db:
        annotate(db, hosts)  # lecture seule : la page est interrogée en GET
    priorities = []
    index = MatchIndex(hosts)
    for host in hosts:
        attributed = {**host, 'source_details': source_details(host, hosts, connections, index)}
        for finding in host_alerts(attributed)['items']:
            if finding.get('severity') not in ('critical','warning','unreachable'):
                continue
            priorities.append({'host_key':host['key'], 'host_name':host['name'], 'title':finding.get('title'),
                               'severity':finding['severity'], 'domain':finding.get('source'),
                               'source':finding['source'], 'alert_id':finding['id'],
                               'collected_at':finding.get('observed_at'), 'stale':not finding['fresh']})
    priorities.sort(key=lambda p:(p['stale'],p['severity'] not in ('critical','unreachable'),p['host_name']))
    priority_groups = group_priorities(priorities)
    source_rows = []
    for source in connections:
        r = connection_evidence(source)
        inv = r.get('inventory') or {}
        source_rows.append({'key':source['key'], 'name':source['name'], 'provider':source['provider'],
                            'fresh':r.get('status')=='observed' and fresh(r.get('collected_at')),
                            'collected_at':r.get('collected_at'), 'error':r.get('error'),
                            'last_attempt_at':r.get('last_attempt_at'),
                            'auth_configured':source.get('auth_configured'), 'indicators':r.get('indicators',{}),
                            'counts':inv.get('counts',{}), 'scope':inv.get('scope'),
                            'problem_counts':inv.get('problem_counts'),
                            'problems_count':inv.get('problems_count'),
                            'secondary_errors':r.get('secondary_errors',{})})
    batch = context.batch_snapshot()
    registered = [h for h in hosts if h.get('registered')]
    attention = [{'key':h['key'],'name':h['name'],'ip':h['ip'], 'audit_recorded':h.get('audit_recorded',False),
                  'coverage':h.get('coverage',{}), 'availability':h.get('scope_reason'),
                  'issues':h.get('issues',[])[:3]} for h in hosts if not h.get('audit_recorded')]
    attention_groups = group_attention(attention)
    return {'generated_at':datetime.now(timezone.utc).isoformat(),
            'counts':{'inventory':len(hosts),'registered':len(registered),'online':sum(h['active_scope'] for h in hosts),
                      'audit_recorded':sum(bool(h.get('audit_recorded')) for h in hosts),
                      'audit_missing':len(attention), 'critical_recent':sum(p['severity']=='critical' and not p['stale'] for p in priorities),
                      # Une anomalie critique ne cesse pas de l'etre parce que sa preuve a
                      # vingt minutes. L'ancien compteur n'affichait que les preuves fraiches
                      # et annoncait « 6 » alors que 33 serveurs etaient critiques : un disque
                      # plein disparaissait de la synthese en attendant le prochain audit.
                      # On expose les deux chiffres ; l'interface dit lequel est confirme.
                      'critical_total':sum(p['severity']=='critical' for p in priorities),
                      'critical_stale':sum(p['severity']=='critical' and p['stale'] for p in priorities),
                      'api_fresh':sum(s['fresh'] for s in source_rows), 'api_total':len(source_rows)},
            'priorities':diversified(priorities, 30), 'priorities_total':len(priorities),
            'priority_groups':priority_groups, 'sources':source_rows,
            'attention':attention, 'attention_groups':attention_groups, 'batches':{'counts':batch['counts'], 'fresh_failures':batch['fresh_failures'],
                        'measured_hosts':sum(c['status']=='observed' for c in batch['coverage']),
                        'fresh_hosts':sum(c['fresh'] for c in batch['coverage']), 'hosts_total':len(hosts)},
            'discovery':context.api_sync_state().get('discovery',{}),
            'policy':'Audits SSH initiaux conservés ; API, disponibilité et Batch actualisés périodiquement. Réaudit manuel possible.'}


def install(app, context):
    from fastapi import APIRouter
    router = APIRouter()
    import response_cache

    @router.get('/api/daily')
    @response_cache.cached_json('daily', lambda: context.data_revision() if hasattr(context, 'data_revision') else None)
    def daily():
        return build(context)

    @router.post('/api/daily/refresh', status_code=202)
    def refresh():
        from asset_registry import initial_audit_hosts
        hosts = initial_audit_hosts(context.rows())
        return {'ssh': context.launch(hosts, 'vue-quotidienne', 'nouveaux') if hosts else {'running': False},
                'api': context.launch_api_sync(),
                'network': context.launch_network(context.HOSTS, 'vue-quotidienne'),
                'batch': context.launch_batches()}
    app.include_router(router)  # routes de ce module : APIRouter, inclus en fin d'installation
