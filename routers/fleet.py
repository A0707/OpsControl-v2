"""Vue globale du parc, services et constats complets (lecture seule, réponses en cache)."""
from typing import Literal

from fastapi import APIRouter, Query

import response_cache

router = APIRouter()
context = None


def overview():
    from synchronization import federate
    from asset_registry import annotate, backup_summaries
    from payload_slim import slim
    connections = context.api_connections()
    snapshot = federate(context.rows(), connections, context.network_rows())
    hosts = snapshot['assets']
    with context.connect() as db:
        annotate(db, hosts)  # lecture seule : inscription après collecte
    backups = backup_summaries(hosts, connections)
    for h in hosts:
        h['backup_summary'] = backups[h['key']]
    counts = {s: sum(h['status'] == s for h in hosts) for s in ['ok', 'critical', 'warning', 'unreachable', 'unknown']}
    with context.lock:
        progress = dict(context.job)
        monitoring = dict(context.monitor)
    with context.net_lock:
        network_progress = dict(context.net_job)
    api_progress = context.api_sync_state()
    reasons = {}
    for h in hosts:
        if h.get('scope_reason'):
            reasons[h['scope_reason']] = reasons.get(h['scope_reason'], 0) + 1
    # Sources dont la variable d'environnement est déclarée mais absente de CE processus :
    # aucune de leurs collectes ne peut aboutir. Remonté une fois, globalement, au lieu de
    # laisser l'opérateur constater cinq échecs distincts sans en comprendre la cause commune.
    missing_auth = [c['name'] for c in connections if c.get('auth_configured') is False]
    # Liste allégée (payload_slim) : la fiche serveur /api/hosts/{clé} garde tout le détail.
    return {'hosts': [slim(h) for h in hosts], 'counts': counts, 'job': progress,
            'monitoring': {**monitoring, 'critical_interval': 10},
            'missing_auth': missing_auth,
            'jobs': {'ssh': progress, 'network': network_progress, 'api': api_progress, 'batch': context.batch_job()},
            'availability': {'exclusions': reasons, 'sources': snapshot['sources']},
            # Révision des sources API de cet instantané : le flux temps réel la compare à son
            # premier message au lieu de supposer un changement et de tout recharger.
            'api_revision': context.api_revision() if hasattr(context, 'api_revision') else None}


def services_all():
    """Toutes les unités observées, par serveur : la page Services (retirées de /api/overview)."""
    from payload_slim import services
    return services(context.rows())


UNITS_MAX = 500


def services_units(status='failed', q='', hosts='', offset=0, limit=100, freshness='all'):
    """Unités à plat, filtrées et paginées CÔTÉ SERVEUR (page Services).

    La page recevait toutes les unités de tout le parc (7,6 Mo à 1000 serveurs) et les
    rendait en un seul tableau ; par défaut, seules les unités en échec sont demandées."""
    wanted = {k for k in hosts.split(',') if k} if hosts else None
    needle = q.strip().lower()
    from synchronization import fresh
    items, failed_total = [], 0
    from alert_policy import service as service_policy
    summary = {'observed': 0, 'failed_recent': 0, 'active': 0, 'inactive': 0,
               'configured': 0, 'stale': 0, 'hosts': 0, 'unmeasured_hosts': 0,
               'expected_down': 0, 'accessory_failed': 0}
    for host in context.rows():
        key = host['key']
        if wanted is not None and key not in wanted:
            continue
        units = [s for s in host.get('all_services', []) if isinstance(s, dict)]
        summary['hosts'] += 1
        summary['unmeasured_hosts'] += not bool(units)
        recent = not any(host.get(flag) for flag in ('stale', 'audit_retained', 'configuration_changed')) and fresh(host.get('collected_at'))
        declared = {str(n).removesuffix('.service') for n in host.get('services') or []}
        for s in units:
            failed = s.get('status') == 'failed'
            failed_total += failed
            if freshness == 'recent' and not recent or freshness == 'stale' and recent:
                continue
            if needle and needle not in str(s.get('name', '')).lower():
                continue
            summary['observed'] += 1
            summary['failed_recent'] += failed and recent
            summary['active'] += s.get('status') == 'active'
            summary['inactive'] += s.get('status') == 'inactive'
            summary['configured'] += bool(s.get('configured'))
            summary['stale'] += not recent
            # Attendu / observé (audit UI du 31/10, fiche 04.1) : un service déclaré pour ce serveur
            # et non actif est une panne attendue ; une unité hors inventaire en échec est un
            # service accessoire ; une unité déclarée sans état relevé est un contrôle manquant.
            state = s.get('status') or 'unknown'
            reading = (('missing_check' if state == 'unknown' else 'expected_down' if state != 'active' else 'expected_up')
                       if s.get('configured') else 'accessory_failed' if state == 'failed' else None)
            summary['expected_down'] += reading == 'expected_down'
            summary['accessory_failed'] += reading == 'accessory_failed'
            level, reasons = service_policy(str(s.get('name') or ''), declared)
            if status == 'critical' and not s.get('configured'):
                continue
            if status not in ('all', 'critical') and s.get('status', 'unknown') != status:
                continue
            items.append({'host_key': key, 'name': s.get('name'), 'status': s.get('status'),
                          'configured': bool(s.get('configured')), 'substate': s.get('substate'),
                          'reading': reading, 'level': level, 'level_source': reasons[0] if reasons else None,
                          'fresh': recent, 'collected_at': host.get('collected_at')})
    items.sort(key=lambda u: (not u['fresh'], u['status'] != 'failed', not u['configured'], u['host_key'], str(u['name'])))
    limit = max(1, min(int(limit), UNITS_MAX))
    offset = max(0, int(offset))
    return {'items': items[offset:offset + limit], 'total': len(items), 'failed_total': failed_total,
            'offset': offset, 'limit': limit, 'status': status, 'summary': summary}


def findings_all():
    """Constats complets, chargés uniquement par les vues Problèmes et Sécurité."""
    from payload_slim import findings
    return findings(context.rows())


def _revision():
    return context.data_revision()


# Routes servies depuis le cache de réponses (lot 7) ; les fonctions ci-dessus restent
# appelables directement (tests, autres modules).
@router.get('/api/overview')
@response_cache.cached_json('overview', _revision)
def overview_route():
    return overview()


@router.get('/api/services')
@response_cache.cached_json('services', _revision)
def services_route():
    return services_all()


@router.get('/api/services/units')
def services_units_route(status: Literal['failed', 'all', 'active', 'inactive', 'critical', 'unknown'] = 'failed', q: str = Query('', max_length=120),
                         hosts: str = Query('', max_length=20000), offset: int = Query(0, ge=0),
                         limit: int = Query(100, ge=1, le=UNITS_MAX),
                         freshness: Literal['all', 'recent', 'stale'] = 'all'):
    return services_units(status, q, hosts, offset, limit, freshness)


@router.get('/api/findings')
@response_cache.cached_json('findings', _revision)
def findings_route():
    return findings_all()


def install(app, ctx):
    global context
    context = ctx
    app.include_router(router)
