"""Sondes réseau : ping, ports TCP, empreintes SSH connues (lecture seule côté serveurs)."""
from fastapi import APIRouter, HTTPException, Request

from routers.hosts import requester

router = APIRouter()
context = None


@router.get('/api/network')
def network_overview():
    with context.net_lock:
        progress = dict(context.net_job)
    return {'hosts': context.network_rows(), 'job': progress}


@router.post('/api/network/refresh', status_code=202)
def network_refresh(request: Request):
    return context.launch_network(context.HOSTS, requester(request))


@router.post('/api/network/hosts/{key}/refresh', status_code=202)
def network_host_refresh(key: str, request: Request):
    selected = [h for h in context.HOSTS if h['key'] == key]
    if not selected:
        raise HTTPException(404, 'Serveur inconnu')
    return context.launch_network(selected, requester(request))


def install(app, ctx):
    global context
    context = ctx
    app.include_router(router)
