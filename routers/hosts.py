"""Collecte SSH, fiche serveur, audits conservés et tendances d'un serveur."""
import json

from fastapi import APIRouter, HTTPException, Request

import response_cache

router = APIRouter()
context = None


def requester(request: Request) -> str:
    return request.client.host if request.client else 'local'


def known(key):
    if not any(h['key'] == key for h in context.HOSTS):
        raise HTTPException(404, 'Serveur inconnu')


@router.post('/api/refresh', status_code=202)
def global_refresh(request: Request):
    return context.launch(context.HOSTS, requester(request), 'all')


@router.post('/api/hosts/{key}/refresh', status_code=202)
def host_refresh(key: str, request: Request):
    selected = [h for h in context.HOSTS if h['key'] == key]
    if not selected:
        raise HTTPException(404, 'Serveur inconnu')
    return context.launch(selected, requester(request), key)


def federated():
    """Parc fédéré partagé entre fiches serveur (lot 7) : même révision, durée de vie 5 s.
    Lecture seule : chaque fiche travaille sur une copie de son serveur."""
    from synchronization import federate

    def build():
        connections = context.api_connections()
        return connections, federate(context.rows(), connections, context.network_rows())['assets']
    return response_cache.CACHE.get_object('federated', context.data_revision(), build)


@router.get('/api/hosts/{key}')
def detail(key: str):
    from asset_registry import source_details
    from server_alerts import build as server_alerts
    from payload_slim import without_local_ssh
    connections, assets = federated()
    for shared in assets:
        if shared['key'] != key:
            continue
        h = without_local_ssh(shared)
        with context.connect() as db:
            h['history'] = [{'ts': ts, 'status': status, **json.loads(summary)} for ts, status, summary in db.execute(
                'SELECT ts,status,summary FROM history WHERE key=? ORDER BY id DESC LIMIT 20', (key,))]
        h['source_details'] = source_details(h, assets, connections)
        batches = context.batch_snapshot()
        h['batches'] = [j for j in batches['jobs'] if j.get('host_key') == key]
        h['batch_coverage'] = next((c for c in batches['coverage'] if c['host_key'] == key), {})
        with context.connect() as db:
            snapshots = [json.loads(payload) for payload, in db.execute(
                'SELECT payload FROM audit_snapshots WHERE key=? ORDER BY ts DESC LIMIT 20', (key,))]
        h['audit_versions'] = [{'collected_at': s.get('collected_at'), 'status': s.get('status')} for s in snapshots]
        from storage_model import assess
        h['storage_assessment'] = assess(h, snapshots)
        h['alerts'] = server_alerts(h, snapshots)
        # Enregistrements publiés vers ce serveur par le WAF, et serveur visé par chaque cible
        # des sites de ce serveur (lecture des relevés déjà collectés, aucune connexion).
        from copy import deepcopy
        from published_sites import annotate_targets, published_to
        if isinstance(h.get('applications'), dict):
            h['applications'] = deepcopy(h['applications'])   # copie : le parc fédéré est partagé
            annotate_targets(h, assets)
        h['published_sites'] = published_to(h, assets)
        return h
    raise HTTPException(404, 'Serveur inconnu')


@router.get('/api/hosts/{key}/audits')
def saved_audit(key: str, at: str):
    known(key)
    with context.connect() as db:
        row = db.execute('SELECT payload FROM audit_snapshots WHERE key=? AND ts=?', (key, at)).fetchone()
    if row is None:
        raise HTTPException(404, 'Audit absent')
    return json.loads(row[0])


@router.get('/api/hosts/{key}/observability')
def host_observability(key: str):
    """Compact 7-day trends, loaded only when the operator opens that tab."""
    from observability import build
    known(key)
    with context.connect() as db:
        # Borné : build() n'utilise au plus que les 336 derniers points.
        snapshots = [json.loads(payload) for payload, in db.execute(
            'SELECT payload FROM audit_snapshots WHERE key=? ORDER BY ts DESC LIMIT 336', (key,))]
    return build(snapshots[::-1])


def install(app, ctx):
    global context
    context = ctx
    app.include_router(router)
