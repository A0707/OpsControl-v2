"""Server-Sent Events : pousse les changements d'état vers l'interface.

Pourquoi SSE et pas WebSocket : le flux est strictement descendant (le serveur
notifie, le client ne publie rien), SSE passe les proxys HTTP sans négociation,
se reconnecte tout seul, et ne demande aucune dépendance supplémentaire. Un
WebSocket n'apporterait ici qu'un canal montant dont personne n'a besoin.

Pourquoi pas Celery/Redis : la collecte tourne déjà dans des threads de ce
processus (app.scheduler + ThreadPoolExecutor). Sur un parc de ~84 hôtes et un
seul opérateur, ajouter un courtier de messages et un worker séparé ajouterait
deux services à exploiter, deux sources de panne et un déploiement, sans rien
résoudre. Le jour où la collecte devra survivre au redémarrage de l'API ou
s'étaler sur plusieurs machines, la question se reposera — pas avant.

Ce module ne collecte rien : il observe l'état déjà produit et signale qu'il a
changé. L'interface décide ensuite quoi recharger.
"""
import asyncio
import json
import os
import threading

from fastapi import Request
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.concurrency import run_in_threadpool

# Cadence d'observation de l'état en mémoire. Ce n'est PAS une fréquence de
# collecte : aucune requête SSH ni API n'est déclenchée ici.
WATCH_SECONDS = 1.0
# Commentaire de maintien : traverse les proxys qui coupent une connexion
# inactive, et permet au client de détecter une rupture.
KEEPALIVE_SECONDS = 15.0
# Plafonds de flux simultanés : chaque flux relit l'état chaque seconde sur la boucle
# asynchrone (processus unique). Sans plafond, un seul lecteur ouvrant des dizaines
# d'onglets ou de connexions dégradait le service de tous.
MAX_STREAMS = int(os.getenv('INFRAOPS_SSE_MAX', '50'))
# 3 par acteur (un onglet + reconnexions) : dix lecteurs ne peuvent plus occuper tout le
# plafond global à eux seuls (audit SEC-08).
MAX_PER_ACTOR = int(os.getenv('INFRAOPS_SSE_MAX_PER_ACTOR', '3'))
RETRY_AFTER_SECONDS = 30
_streams = {}
_streams_lock = threading.Lock()


def _actor(request):
    """Identité authentifiée (access_policy) si présente, sinon adresse du client."""
    who = getattr(getattr(request, 'state', None), 'principal', None) or {}
    if who.get('user'):
        return 'user:' + who['user'].lower()
    client = getattr(request, 'client', None)
    return 'client:' + (client.host if client else 'local')


def _reserve(actor):
    """Contrôle des plafonds ET réservation sous le même verrou ; False si saturé.

    Le contrôle et l'incrément étaient séparés par l'attente du premier état (dans le
    générateur) : des ouvertures simultanées passaient toutes, sans borne (audit A3, 15/10 :
    douze flux acceptés pour un plafond de trois). La place est prise ici, avant tout await,
    et rendue une seule fois par _Reservation, que le flux ait démarré ou non."""
    with _streams_lock:
        if sum(_streams.values()) >= MAX_STREAMS or _streams.get(actor, 0) >= MAX_PER_ACTOR:
            return False
        _streams[actor] = _streams.get(actor, 0) + 1
        return True


def _open(actor):
    with _streams_lock:
        _streams[actor] = _streams.get(actor, 0) + 1


def _close(actor):
    with _streams_lock:
        restant = _streams.get(actor, 0) - 1
        if restant > 0:
            _streams[actor] = restant
        else:
            _streams.pop(actor, None)


class _Reservation:
    """Place réservée par _reserve : libérée une seule fois, quel que soit le chemin."""

    def __init__(self, actor):
        self.actor, self.lock, self.released = actor, threading.Lock(), False

    def release(self):
        with self.lock:
            if self.released:
                return
            self.released = True
        _close(self.actor)


class _ReservedStream(StreamingResponse):
    """Rend la place même si le corps n'est jamais itéré (client parti avant l'envoi,
    erreur d'envoi) : un générateur jamais démarré n'exécute pas son `finally`."""

    def __init__(self, content, reservation, **kwargs):
        super().__init__(content, **kwargs)
        self.reservation = reservation

    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            self.reservation.release()


def install(app, context):
    """Enregistre /api/events. `context` est le module applicatif (app.py)."""
    from fastapi import APIRouter
    router = APIRouter()

    def snapshot():
        """Empreinte compacte de ce qui justifie un rafraîchissement d'écran.

        On ne sérialise pas l'état complet : il pèse plusieurs centaines de Ko
        pour 84 hôtes, et le recalculer chaque seconde coûterait plus cher que
        le sondage qu'on cherche à remplacer. On compare uniquement les
        compteurs de progression et l'horodatage des collectes.
        """
        with context.lock:
            jobs = {'ssh': dict(context.job), 'monitoring': dict(context.monitor)}
        with context.net_lock:
            jobs['network'] = dict(context.net_job)
        if hasattr(context, 'batch_job'):
            jobs['batch'] = context.batch_job()
        try:
            jobs['api'] = context.api_sync_state()
        except Exception:
            # Une extension absente ou en cours d'initialisation ne doit pas
            # interrompre le flux : on signale simplement l'inconnue.
            jobs['api'] = None
        digest = {
            name: None if job is None else {k: job.get(k) for k in ('running', 'completed', 'total', 'error', 'next_at')}
            for name, job in jobs.items()
        }
        if hasattr(context, 'api_revision'):
            digest['api_revision'] = context.api_revision()
        if hasattr(context, 'api_change'):
            digest['api_change'] = context.api_change()
        return json.dumps(digest, sort_keys=True, default=str)

    @router.get('/api/events')
    async def events(request: Request):
        """Flux SSE. Émet `state` à chaque changement, `ping` sinon."""
        actor = _actor(request)
        if not _reserve(actor):
            # L'interface reprend seule (reconnexion progressive, sondage de secours).
            return JSONResponse({'detail': 'Trop de flux temps réel ouverts : réessayer plus tard.'},
                                status_code=503, headers={'Retry-After': str(RETRY_AFTER_SECONDS)})

        async def stream():
            # On part de l'état courant, et non de None : sinon chaque connexion
            # — donc chaque reconnexion après coupure réseau — émettrait un
            # « changement » qui n'en est pas un, et provoquerait un rechargement
            # complet inutile côté client.
            # snapshot() prend context.lock, net_lock et api_lock : un verrou tenu pendant une
            # écriture (YAML, SQLite) gelait toute la boucle d'événements, /health compris.
            # Hors boucle, seul ce flux attend (audit BE-04).
            previous = await run_in_threadpool(snapshot)
            idle = 0.0
            # Voie rapide : on POUSSE l'état lui-même (quelques Ko), pas un simple
            # signal de changement. Le client n'a rien à recharger : une panne
            # d'un serveur critique arrive à l'écran dans la seconde qui suit la sonde.
            tier0 = getattr(context, 'tier0_snapshot', None)
            tier0_seen = None
            # Compteur de connexions temps réel (self_monitor) : décrémenté même sur coupure.
            from self_monitor import MONITOR
            MONITOR.sse_open()
            try:
                # Premier message immédiat : le client sait que le canal est ouvert
                # et n'attend pas le premier changement pour afficher quelque chose.
                yield 'event: ready\ndata: {}\n\n'
                while True:
                    if await request.is_disconnected():
                        return
                    if tier0 is not None:
                        etat = await run_in_threadpool(tier0)
                        marque = (etat.get('revision'), etat.get('last_probe_at'))
                        if marque != tier0_seen:
                            tier0_seen = marque
                            idle = 0.0
                            yield 'event: tier0\ndata: ' + json.dumps(etat, default=str) + '\n\n'
                    current = await run_in_threadpool(snapshot)
                    if current != previous:
                        previous = current
                        idle = 0.0
                        yield 'event: state\ndata: ' + current + '\n\n'
                    else:
                        idle += WATCH_SECONDS
                        if idle >= KEEPALIVE_SECONDS:
                            idle = 0.0
                            yield ': ping\n\n'
                    await asyncio.sleep(WATCH_SECONDS)
            finally:
                MONITOR.sse_close()

        async def reserved():
            # Place rendue aussi quand le premier état (avant le try du flux) lève une exception.
            inner = stream()
            try:
                async for chunk in inner:
                    yield chunk
            finally:
                try:
                    await inner.aclose()
                finally:
                    reservation.release()

        reservation = _Reservation(actor)
        return _ReservedStream(reserved(), reservation, media_type='text/event-stream', headers={
            'Cache-Control': 'no-store',
            # Neutralise la mise en tampon d'un reverse-proxy nginx éventuel :
            # sans cela le flux arrive par paquets et le temps réel disparaît.
            'X-Accel-Buffering': 'no',
        })
    app.include_router(router)  # routes de ce module : APIRouter, inclus en fin d'installation
