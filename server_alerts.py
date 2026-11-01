"""Per-server alerts with attributed timestamps, without inferring uptime or recovery."""
from datetime import datetime, timezone


def instant(value):
    try:
        if str(value).isdigit():
            return datetime.fromtimestamp(int(value), timezone.utc) if int(value) > 0 else None
        date = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return date if date.tzinfo else None
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def build(host, snapshots=(), now=None):
    now = now or datetime.now(timezone.utc)
    alerts = []

    def add(source, identity, title, severity, observed, fresh=False, start=None,
            basis='Début non mesuré', evidence=None):
        seen, begin = instant(observed), instant(start)
        end = now if fresh else seen
        if begin and (not end or begin > end):
            begin = None
        alerts.append({'id': f'{source}:{identity}', 'source': source, 'title': title,
                       'severity': severity, 'observed_at': observed, 'fresh': bool(fresh),
                       'started_at': begin.isoformat() if begin else None,
                       'time_basis': basis if begin else 'Début non mesuré',
                       'duration_seconds': int((end-begin).total_seconds()) if begin else None,
                       'duration_until': end.isoformat() if end else None,
                       'evidence': evidence})

    for finding in host.get('findings', []):
        if finding.get('severity') not in ('critical', 'warning', 'unreachable'):
            continue
        first = host.get('collected_at')
        # Only consecutive measured snapshots for this exact configuration/IP.
        # This is the first retained observation, never an asserted onset time.
        for previous in sorted(snapshots, key=lambda s: s.get('collected_at') or '', reverse=True):
            if previous.get('fingerprint') != host.get('fingerprint'):
                break
            if not instant(previous.get('collected_at')) or instant(previous['collected_at']) > (instant(first) or now):
                continue
            if not any(f.get('id') == finding.get('id') for f in previous.get('findings', [])):
                break
            first = previous['collected_at']
        # A collector login failure is a visibility problem, not proof of an outage.
        collection_failure = finding.get('id') == 'ssh'
        add('SSH', finding.get('id'), finding.get('title'), 'warning' if collection_failure else finding.get('severity'),
            host.get('collected_at'), not host.get('stale', True), first,
            'Première observation conservée · début réel inconnu', finding.get('evidence'))
        alerts[-1]['category'] = 'collection' if collection_failure else 'observation'

    attempt = host.get('last_attempt') or {}
    if attempt:
        add('SSH', 'last-attempt', 'Dernière collecte SSH en échec', 'warning',
            attempt.get('collected_at'), evidence=' · '.join(attempt.get('issues') or []))

    for source in host.get('source_details', []):
        e = source.get('evidence') or {}
        stamp, fresh = source.get('collected_at'), source.get('fresh', False)
        provider, key = source['provider'], source['key']
        if source.get('error'):
            add(provider, key+':collection', 'Collecte de la source en échec', 'warning', stamp,
                evidence=source['error'])
        if provider == 'Zabbix':
            for problem in e.get('problems') or []:
                add(provider, key+':'+str(problem.get('triggerid')), problem['description'],
                    problem.get('severity', 'unknown'), stamp, fresh, problem.get('last_change'),
                    'Dernier changement du trigger Zabbix', problem.get('severity_label'))
        elif provider == 'Wazuh':
            agent = e.get('agent') or {}
            if agent.get('status') in ('disconnected', 'never_connected', 'pending'):
                add(provider, key+':agent', 'Agent Wazuh : '+agent['status'], 'warning', stamp,
                    fresh, evidence='Dernier contact : '+str(agent.get('lastKeepAlive') or agent.get('last_keep_alive') or 'Non mesuré'))
        elif provider == 'Bacula':
            latest = {}
            for job in e.get('latest_jobs', e.get('recent_jobs')) or []:
                latest.setdefault((job.get('name'), job.get('client')), job)
            for identity, job in latest.items():
                if job.get('severity') in ('critical', 'warning'):
                    add(provider, key+':'+str(job.get('jobid')), str(job.get('name'))+' : '+str(job.get('status_label')),
                        job['severity'], stamp, fresh, evidence='Fin du job : '+str(job.get('endtime') or 'Non mesurée'))
    rank = {'critical': 0, 'unreachable': 1, 'warning': 2, 'unknown': 3}
    alerts.sort(key=lambda a: (not a['fresh'], rank.get(a['severity'], 4), a['started_at'] or '9999', a['id']))
    return {'items': alerts, 'counts': {'total': len(alerts),
            'recent': sum(a['fresh'] for a in alerts), 'old': sum(not a['fresh'] for a in alerts)},
            'generated_at': now.isoformat(),
            'scope': 'Alertes visibles dans les sources associées. Aucune résolution déduite d’une collecte absente. Durées anciennes arrêtées à la dernière observation.'}
