"""OpsControl V2 : synthèse compacte des sources pour le cockpit.

Pourquoi ce module
------------------
La Vue globale V2 affiche l'état de chaque intégration (Proxmox, Zabbix, Wazuh,
Elasticsearch, Bacula). /api/connections renvoie l'inventaire complet de chaque
source (≈ 250 Ko : toutes les VM, tous les agents, tous les jobs) ; le recharger
toutes les minutes pour afficher cinq tuiles serait du gaspillage.

Ce module ne fait AUCUNE collecte et aucun appel distant : il relit le dernier
résultat enregistré par management.py et en extrait une liste blanche de
champs. Rien d'autre ne sort — un champ inattendu ajouté plus tard à un
inventaire (ou un secret présent par erreur dans une réponse produit) ne peut
pas fuiter par ici.

Règles de véracité reprises du reste de la plateforme :
- une source en échec garde ses dernières données, marquées « retained » et
  jamais « fresh » ;
- une valeur absente reste None (affichée « Non mesuré »), jamais 0 ;
- l'absence de problème remonté n'est pas présentée comme une absence de
  problème : `measured` dit si la mesure existe.
"""
from __future__ import annotations

import math
from datetime import datetime, timezone

VERSION = '2.0'
# Même budget que synchronization.fresh : 15 minutes.
FRESH_SECONDS = 900
PROVIDERS = ('Proxmox', 'Zabbix', 'Wazuh', 'Elasticsearch', 'Bacula')


def _num(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value if math.isfinite(value) and value >= 0 else None


def _text(value, limit=200):
    return str(value)[:limit] if value is not None else None


def _counts(value, keys):
    value = value if isinstance(value, dict) else {}
    return {k: _num(value.get(k)) for k in keys}


def age_seconds(timestamp, now=None):
    try:
        observed = datetime.fromisoformat(str(timestamp))
    except (TypeError, ValueError):
        return None
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    return int(((now or datetime.now(timezone.utc)) - observed).total_seconds())


def evidence(connection):
    """Dernier résultat exploitable ; un échec ne rend jamais une donnée ancienne saine."""
    last = connection.get('last_result') or {}
    if last.get('status') == 'observed' or not connection.get('last_success_result'):
        return last, False
    retained = dict(connection['last_success_result'])
    retained.update(status='unknown', error=last.get('error'), error_kind=last.get('error_kind'),
                    http_status=last.get('http_status'), last_attempt_at=last.get('collected_at'))
    return retained, True


def _proxmox(inv):
    summary = inv.get('summary') if isinstance(inv.get('summary'), dict) else {}
    if 'storage_unique_count' not in summary and isinstance(inv.get('nodes'), list):
        # Collecte antérieure au calcul de capacité unique : recalcul sur les nœuds enregistrés.
        from proxmox_inventory import unique_storage_totals
        used, total, _ = unique_storage_totals(inv['nodes'])
        summary = {**summary, 'storage_used_bytes': used, 'storage_total_bytes': total}
    cluster = inv.get('cluster') if isinstance(inv.get('cluster'), dict) else {}
    quorate = cluster.get('quorate')
    return {
        'cluster_name': _text(cluster.get('name')),
        'quorate': quorate if isinstance(quorate, bool) else None,
        'cluster_error': _text(inv.get('cluster_error'), 300),
        'nodes_count': _num(inv.get('nodes_count')),
        'counts': _counts(inv.get('counts'), ('qemu', 'lxc', 'running', 'stopped', 'unknown',
                                              'storage', 'storage_unavailable')),
        'capacity': {k: _num(summary.get(k)) for k in (
            'nodes_online', 'cpu_pct', 'memory_bytes', 'memory_total_bytes',
            'storage_used_bytes', 'storage_total_bytes')},
    }


def _zabbix(inv):
    return {'counts': _counts(inv.get('counts'), ('monitored', 'unmonitored', 'unknown')),
            'problem_counts': _counts(inv.get('problem_counts'), ('critical', 'warning', 'unknown')),
            'problems_count': _num(inv.get('problems_count')),
            'problems_measured': inv.get('problems') is not None or inv.get('problems_count') is not None}


def _wazuh(inv):
    agents = inv.get('agents') if isinstance(inv.get('agents'), dict) else {}
    states = {}
    for item in agents.get('states') or []:
        if isinstance(item, dict) and isinstance(item.get('key'), str):
            states[item['key'][:40]] = _num(item.get('count'))
    manager = inv.get('manager') if isinstance(inv.get('manager'), dict) else {}
    return {'daemons': _counts(inv.get('counts'), ('running', 'stopped', 'failed', 'unknown')),
            'agents': {'total': _num(agents.get('total')), 'states': states} if agents else None,
            'manager_version': _text(manager.get('version'), 40)}


def _elastic(indicators):
    status = indicators.get('cluster_status')
    return {'cluster_status': status if status in ('green', 'yellow', 'red') else None,
            **{k: _num(indicators.get(k)) for k in (
                'number_of_nodes', 'number_of_data_nodes', 'active_shards',
                'unassigned_shards', 'active_shards_percent_as_number')}}


def _bacula(inv):
    families = ('ok', 'warning', 'critical', 'running', 'pending', 'unknown')
    from bacula_inventory import overdue
    try:
        late = overdue(inv)
    except (TypeError, ValueError, AttributeError):
        late = None   # non mesuré : jamais « 0 retard »
    return {'latest_counts': _counts(inv.get('latest_counts'), families),
            # Dernière réussite trop ancienne : la tuile ne doit plus être verte (audit SUP-19).
            'overdue_count': len(late) if late is not None else None,
            'jobs_count': _num(inv.get('jobs_count')),
            'last_success': _text(inv.get('last_success'), 40),
            'history_since': _text(inv.get('history_since'), 40)}


def summarize(connection, now=None):
    provider = connection.get('provider')
    result, retained = evidence(connection)
    inv = result.get('inventory') if isinstance(result.get('inventory'), dict) else {}
    indicators = result.get('indicators') if isinstance(result.get('indicators'), dict) else {}
    age = age_seconds(result.get('collected_at'), now)
    observed = result.get('status') == 'observed'
    row = {
        'key': _text(connection.get('key'), 80), 'name': _text(connection.get('name')),
        'provider': _text(provider, 40),
        'status': 'observed' if observed else ('retained' if retained else 'unknown'),
        'fresh': bool(observed and age is not None and 0 <= age <= FRESH_SECONDS),
        'collected_at': _text(result.get('collected_at'), 40), 'age_seconds': age,
        'last_attempt_at': _text(result.get('last_attempt_at'), 40),
        'error': _text(result.get('error'), 400), 'error_kind': _text(result.get('error_kind'), 40),
        'http_status': _num(result.get('http_status')),
        'warning': _text(result.get('warning'), 400),
        'scope': _text(inv.get('scope'), 300),
        'secondary_errors': sorted(str(k)[:40] for k in (result.get('secondary_errors') or {})),
        'auth_configured': connection.get('auth_configured'),
        'has_data': bool(inv or indicators),
    }
    detail = {'Proxmox': lambda: _proxmox(inv), 'Zabbix': lambda: _zabbix(inv),
              'Wazuh': lambda: _wazuh(inv), 'Elasticsearch': lambda: _elastic(indicators),
              'Bacula': lambda: _bacula(inv)}.get(provider)
    row['detail'] = detail() if detail and row['has_data'] else None
    return row


def build(connections, now=None):
    now = now or datetime.now(timezone.utc)
    rows = [summarize(c, now) for c in connections]
    present = {r['provider'] for r in rows}
    return {'version': VERSION, 'generated_at': now.isoformat(), 'fresh_budget_seconds': FRESH_SECONDS,
            'sources': rows, 'missing_providers': [p for p in PROVIDERS if p not in present],
            'read_only': True,
            'policy': 'Synthèse des dernières collectes enregistrées. Aucune requête vers les produits '
                      'n’est émise par cet endpoint ; une source ancienne ou en échec n’est jamais comptée saine.'}


def install(app, context):
    from fastapi import APIRouter
    router = APIRouter()
    @router.get('/api/v2/cockpit')
    def cockpit():
        # api_connections() ajoute déjà auth_configured (booléen, jamais la valeur).
        return build(context.api_connections())

    @router.get('/api/v2/version')
    def version():
        return {'product': 'OpsControl', 'version': VERSION, 'read_only': True}

    started_at = datetime.now(timezone.utc).isoformat()

    @router.get('/api/health')
    def health():
        """Vivacité : le processus répond et sa base locale est lisible. Aucun appel distant.

        Sert au contrôle post-déploiement (deploy/release.py) : un échec déclenche le rollback.
        """
        release = None
        marker = getattr(context, 'BASE', None)
        if marker is not None and (marker / 'RELEASE').is_file():
            try:
                import json
                release = json.loads((marker / 'RELEASE').read_text(encoding='utf-8')).get('id')
            except (OSError, ValueError):
                release = 'illisible'
        try:
            with context.connect() as db:
                db.execute('SELECT 1').fetchone()
            database = 'ok'
        except Exception:  # noqa: BLE001
            database = 'unavailable'
        return {'status': 'ok' if database == 'ok' else 'degraded', 'version': VERSION, 'release': release,
                'started_at': started_at, 'database': database}
    app.include_router(router)  # routes de ce module : APIRouter, inclus en fin d'installation
