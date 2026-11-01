"""Voie rapide (tier 0) : les serveurs déclarés `critical`, surveillés en continu.

Ce que la voie normale ne pouvait pas garantir : savoir en moins de 15 s qu'un
serveur batch est tombé. Trois signaux indépendants, pour qu'aucune panne
unique ne rende l'écran aveugle :

1. Sonde directe toutes les 5 s — ICMP, complété par TCP sur le port SSH (sans
   session) quand l'ICMP échoue et toutes les 5 min en confirmation. Ne dépend ni de Zabbix ni de l'audit SSH : si Zabbix tombe, on sait
   encore si les serveurs batch répondent (« homme mort »).
2. Webhook Zabbix — Zabbix POUSSE chaque événement dès qu'un trigger change.
   Le webhook déclenche aussi une collecte Zabbix immédiate : tout l'écran se
   met à jour en quelques secondes, sans attendre le cycle suivant.
3. Cycle Zabbix de 10 s (critical_monitor) — filet si le webhook se tait.

Anti-battement : un serveur n'est déclaré HORS SERVICE qu'après deux sondes
consécutives où ICMP et TCP échouent tous les deux (10 s). Une seule perte
donne « dégradé ». Un faux « hors service » réveillerait quelqu'un pour rien.

Lecture seule : aucune commande n'est exécutée sur les serveurs surveillés.
"""
from __future__ import annotations

import hmac
import json
import logging
import os
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from fastapi import HTTPException, Request
from starlette.concurrency import run_in_threadpool

PROBE_SECONDS = 5
LIVE_SECONDS = 10           # lecture des dernières valeurs Zabbix (item.get)
TCP_CONFIRM_SECONDS = 300  # TCP re-sondé au plus toutes les 5 min tant que l'ICMP répond
DOWN_AFTER = 2             # sondes consécutives en échec total avant « hors service »
PING_TIMEOUT = 2.5          # sous charge, lancer ping.exe prend déjà ~1 s sur le poste
TCP_TIMEOUT = 3.0
# Référence du même réseau, sondée quand un serveur critique ne répond plus :
# le serveur Zabbix (Server= des agents). Surchargeable.
REFERENCE_ENV = 'INFRAOPS_TIER0_REFERENCE'
REFERENCE_DEFAULT = '10.77.0.11'
WEBHOOK_MAX_BYTES = 64 * 1024
WEBHOOK_KEEP = 300          # événements conservés en mémoire
COLLECT_MIN_GAP = 5         # secondes entre deux collectes Zabbix déclenchées par webhook
TOKEN_ENV = 'INFRAOPS_WEBHOOK_TOKEN'
# Même exigence que le secret du reverse proxy : secrets_env.py en génère 64 caractères.
MIN_TOKEN_LENGTH = 32


def _now():
    return datetime.now(timezone.utc).isoformat()


def critical_hosts(hosts):
    return [h for h in hosts if h.get('criticality') == 'critical' and h.get('collect_enabled', True)]


def evaluate(previous, ping_ok, tcp_ok, checked_at, observateur_ok=True):
    """Nouvel état d'un hôte à partir de la sonde. Pur : testable sans réseau.

    `observateur_ok` : la référence (même réseau, autre machine) répondait-elle
    au même moment ? Sinon c'est le CHEMIN de mesure qui est perturbé (poste,
    VPN, rafale de collectes), pas le serveur : on ne compte pas l'échec.
    Constaté le 26/09 : les 3 serveurs critiques « tombaient » ensemble chaque
    minute, à la seconde où la collecte réseau des 87 serveurs démarrait.
    """
    state = dict(previous or {})
    if not observateur_ok and ping_ok is not True:
        # Rien n'est conclu sur le serveur ; un « hors service » déjà établi le reste.
        state['perturbed'] = True
        if state.get('status') != 'down':
            if state.get('status') != 'unknown':
                state['changed_at'] = checked_at
            state['status'] = 'unknown'
        return state
    state['perturbed'] = False
    échec_total = ping_ok is not True and tcp_ok is not True
    state['failures'] = state.get('failures', 0) + 1 if échec_total else 0
    if échec_total and state['failures'] >= DOWN_AFTER:
        statut = 'down'
    elif échec_total or ping_ok is False or tcp_ok is False:
        statut = 'degraded'
    else:
        statut = 'up'
    if statut == 'down' and state.get('status') != 'down':
        state['down_since'] = state.get('first_failure_at') or checked_at
    if statut != 'down':
        state['down_since'] = None
    state['first_failure_at'] = (state.get('first_failure_at') or checked_at) if échec_total else None
    if statut != state.get('status'):
        state['changed_at'] = checked_at
    state['status'] = statut
    return state


def install(app, context):
    from fastapi import APIRouter
    router = APIRouter()
    lock = threading.Lock()
    states, events, active = {}, deque(maxlen=WEBHOOK_KEEP), {}
    meta = {'running': False, 'live_running': False, 'revision': 0, 'last_probe_at': None, 'observer': {},
            'webhook_last_at': None, 'webhook_count': 0, 'collect_last': 0.0}
    live, live_meta = {}, {'fetched_at': None, 'error': None, 'duration_ms': None, 'source': None}
    enabled = os.getenv('INFRAOPS_TIER0', '1') != '0'
    pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix='tier0')
    next_at, live_next = [0.0], [0.0]

    def bump():
        meta['revision'] += 1

    def probe(host, avant):
        """ICMP à chaque sonde ; TCP seulement quand il apporte une information.

        Une connexion TCP au port SSH sans session laisse une ligne dans les
        journaux sshd (« Connection closed … [preauth] »). Toutes les 5 s, cela
        ferait ~17 000 lignes par jour et par serveur, et pourrait compter pour
        un fail2ban en mode agressif. TCP n'est donc sondé que si l'ICMP échoue
        (pour distinguer ICMP filtré et serveur tombé) ou pour confirmation
        toutes les TCP_CONFIRM_SECONDS.
        """
        from network_audit import ping
        from ssh import tcp_reachable
        port = int(host.get('port') or getattr(context.cfg, 'port', 22) or 22)
        ping_ok = ping(host['ip'], PING_TIMEOUT)
        dernier = (avant or {}).get('tcp_mono')
        # Seul un TCP RÉUSSI est réutilisé. Un échec est retesté à la sonde
        # suivante : sinon un échec ponctuel (constaté au démarrage, pendant la
        # rafale d'audits) figeait le serveur en « dégradé » pendant 5 minutes.
        if (ping_ok is True and (avant or {}).get('tcp') is True and dernier is not None
                and time.monotonic() - dernier < TCP_CONFIRM_SECONDS):
            return host, ping_ok, avant.get('tcp'), avant.get('tcp_ms'), port, avant.get('tcp_checked_at'), dernier
        tcp_ok, tcp_ms = tcp_reachable(host['ip'], port, TCP_TIMEOUT)
        return host, ping_ok, tcp_ok, tcp_ms, port, _now(), time.monotonic()

    def run(hosts):
        try:
            with lock:
                precedents = {k: dict(v) for k, v in states.items()}
            resultats = list(pool.map(lambda h: probe(h, precedents.get(h['key'])), hosts))
            # Un serveur ne répond plus à l'ICMP : la référence répond-elle, elle ?
            observateur_ok, reference = True, os.getenv(REFERENCE_ENV, REFERENCE_DEFAULT)
            if reference and any(r[1] is not True for r in resultats):
                from network_audit import ping
                observateur_ok = ping(reference, PING_TIMEOUT) is True
            checked_at = _now()
            with lock:
                for host, ping_ok, tcp_ok, tcp_ms, port, tcp_at, tcp_mono in resultats:
                    avant = states.get(host['key'], {})
                    apres = evaluate(avant, ping_ok, tcp_ok, checked_at, observateur_ok)
                    apres.update(key=host['key'], name=host.get('name') or host['key'], ip=host['ip'],
                                 checked_at=checked_at, ping=ping_ok, tcp=tcp_ok, tcp_ms=tcp_ms, port=port,
                                 tcp_checked_at=tcp_at, tcp_mono=tcp_mono)
                    if apres['status'] != avant.get('status'):
                        bump()
                    states[host['key']] = apres
                # Hôtes retirés de la voie rapide : on ne garde pas un état fantôme.
                for cle in set(states) - {h['key'] for h in hosts}:
                    states.pop(cle)
                    bump()
                meta['last_probe_at'] = checked_at
                if meta['observer'].get('ok') != observateur_ok:
                    bump()
                meta['observer'] = {'ok': observateur_ok, 'reference': reference, 'checked_at': checked_at}
        finally:
            with lock:
                meta['running'] = False

    def run_live(hosts):
        """Dernières valeurs Zabbix (item.get) des serveurs critiques."""
        import zabbix_live
        try:
            try:
                data, info = zabbix_live.collect(context.api_connections(), hosts)
            except Exception as exc:  # noqa: BLE001 — une panne Zabbix se voit, elle n'arrête rien
                data, info = None, {'error': str(exc)[:200] or type(exc).__name__}
            with lock:
                # Échec : on garde les dernières valeurs, datées ; elles vieillissent
                # à l'écran au lieu de disparaître ou de passer pour fraîches.
                if data is not None:
                    live.clear()
                    live.update(data)
                live_meta.update(info, fetched_at=_now())
                bump()
        finally:
            with lock:
                meta['live_running'] = False

    def tick(now=None):
        """Appelé chaque seconde par le planificateur de app.py."""
        if not enabled:
            return
        now = time.monotonic() if now is None else now
        lancer = []
        with lock:
            hosts = critical_hosts(context.HOSTS)
            if hosts and not meta['running'] and now >= next_at[0]:
                next_at[0] = now + PROBE_SECONDS
                meta['running'] = True
                lancer.append((run, 'tier0-probe'))
            # Voie Zabbix indépendante : un Zabbix lent ne retarde jamais la sonde.
            if hosts and not meta['live_running'] and now >= live_next[0]:
                live_next[0] = now + LIVE_SECONDS
                meta['live_running'] = True
                lancer.append((run_live, 'tier0-zabbix-live'))
        for cible, nom in lancer:
            _start(cible, (hosts,), nom)

    def trigger_collect():
        """Collecte Zabbix immédiate après un webhook, bornée à une toutes les 5 s."""
        with lock:
            if time.monotonic() - meta['collect_last'] < COLLECT_MIN_GAP:
                return
            meta['collect_last'] = time.monotonic()
        try:
            keys = [c['key'] for c in context.api_connections()
                    if c.get('provider') == 'Zabbix' and c.get('auth_configured') is not False]
        except Exception:
            return
        for key in keys:
            _start(_safe, (context.collect_api_connection, key), 'tier0-zabbix')

    def snapshot():
        """État compact poussé par SSE à chaque changement (quelques Ko)."""
        with lock:
            return {'revision': meta['revision'], 'probe_seconds': PROBE_SECONDS,
                    'last_probe_at': meta['last_probe_at'], 'enabled': enabled, 'observer': dict(meta['observer']),
                    'hosts': [dict(v) for v in states.values()],
                    'webhook': {'configured': bool(os.getenv(TOKEN_ENV)), 'last_at': meta['webhook_last_at'],
                                'count': meta['webhook_count']},
                    'push_problems': [dict(v) for v in active.values()],
                    'live': {k: dict(v) for k, v in live.items()}, 'live_meta': dict(live_meta),
                    'live_seconds': LIVE_SECONDS}

    context.tier0_tick = tick
    context.tier0_snapshot = snapshot
    context.tier0_revision = lambda: meta['revision']

    @router.post('/api/webhooks/zabbix', status_code=202)
    async def zabbix_webhook(request: Request):
        """Réception d'un événement poussé par le type de média webhook Zabbix.

        Authentification par jeton dédié (en-tête Authorization: Bearer). Sans
        jeton configuré sur le serveur, l'endpoint est FERMÉ : on n'ouvre jamais
        une entrée réseau sans secret. Le contenu est une donnée affichée, jamais
        une commande : rien n'est exécuté à partir d'un événement reçu.
        """
        attendu = os.getenv(TOKEN_ENV, '')
        if not attendu:
            raise HTTPException(503, 'Webhook non configuré : définir ' + TOKEN_ENV + ' sur le serveur InfraOps')
        if len(attendu) < MIN_TOKEN_LENGTH:
            raise HTTPException(503, f'Webhook fermé : {TOKEN_ENV} doit compter au moins {MIN_TOKEN_LENGTH} caractères')
        fourni = request.headers.get('authorization', '').removeprefix('Bearer ').strip()
        if not hmac.compare_digest(fourni.encode(), attendu.encode()):
            raise HTTPException(401, 'Jeton webhook invalide')
        # Lecture bornée : refus sur la taille annoncée, puis arrêt dès la limite franchie,
        # au lieu de charger tout le corps en mémoire avant de le mesurer.
        annonce = request.headers.get('content-length', '')
        if annonce.isdigit() and int(annonce) > WEBHOOK_MAX_BYTES:
            raise HTTPException(413, 'Événement trop volumineux')
        brut = bytearray()
        async for morceau in request.stream():
            brut += morceau
            if len(brut) > WEBHOOK_MAX_BYTES:
                raise HTTPException(413, 'Événement trop volumineux')
        brut = bytes(brut)
        try:
            data = json.loads(brut)
            if not isinstance(data, dict):
                raise ValueError
        except ValueError:
            raise HTTPException(422, 'Corps JSON attendu')
        evenement = normalize(data)
        with lock:
            events.appendleft(evenement)
            if evenement['status'] == 'resolved':
                active.pop(evenement['eventid'], None)
            else:
                active[evenement['eventid']] = evenement
            meta['webhook_last_at'] = evenement['received_at']
            meta['webhook_count'] += 1
            bump()
        # trigger_collect lit api-connections.json sous api_lock : hors boucle d'événements (audit BE-04).
        await run_in_threadpool(trigger_collect)
        return {'accepted': True, 'eventid': evenement['eventid']}

    @router.get('/api/tier0')
    def tier0():
        return build(context, snapshot())

    @router.get('/api/webhooks/zabbix/events')
    def webhook_events():
        with lock:
            return {'events': list(events)[:100], 'configured': bool(os.getenv(TOKEN_ENV))}
    app.include_router(router)  # routes de ce module : APIRouter, inclus en fin d'installation


def _start(target, args, name):
    """Lance un travail de fond. Point unique, remplaçable dans les tests."""
    from jobs import spawn  # producteur enregistré : attendu à l'arrêt (OC-AUDIT-013)
    spawn(target, args, name)


def _safe(fn, *args):
    try:
        fn(*args)
    except Exception:  # noqa: BLE001 — une collecte échouée se voit dans l'état de la source
        logging.getLogger('opscontrol.tier0').exception('Travail de fond de la voie rapide en échec')


def _text(value, limit=300):
    return str(value)[:limit] if value is not None else None


def normalize(data):
    """Événement Zabbix -> forme stable. Champs attendus du modèle de message
    fourni dans deploy/zabbix-webhook.md ; tout champ absent reste None."""
    statut = str(data.get('status') or data.get('event_status') or '').lower()
    resolu = statut in ('resolved', 'ok', '0') or str(data.get('event_value', '')) == '0'
    return {'eventid': _text(data.get('eventid') or data.get('event_id'), 64) or ('sans-id-' + _now()),
            'status': 'resolved' if resolu else 'problem',
            'host': _text(data.get('host') or data.get('host_name'), 200),
            'host_ip': _text(data.get('host_ip'), 64),
            'trigger': _text(data.get('trigger') or data.get('name') or data.get('event_name')),
            'severity': _text(data.get('severity') or data.get('event_severity'), 40),
            'event_time': _text(data.get('event_time') or data.get('clock'), 40),
            'received_at': _now()}


def build(context, snap):
    """Vue complète d'un serveur critique : sonde, Zabbix, batchs, dernier audit."""
    from asset_registry import connection_evidence, names
    from synchronization import fresh
    import alert_policy as policy

    rows = {h['key']: h for h in context.rows()}
    zabbix_problems, zabbix_at = [], None
    for c in context.api_connections():
        if c.get('provider') == 'Zabbix':
            r = connection_evidence(c)
            zabbix_at = r.get('collected_at')
            zabbix_problems += (r.get('inventory') or {}).get('problems') or []
    try:
        with context.connect() as db:
            batchs = {k: json.loads(p) for k, p in db.execute('SELECT key, payload FROM batch_states')}
    except Exception:
        batchs = {}

    hotes = []
    sondes = {s['key']: s for s in snap['hosts']}
    for h in critical_hosts(context.HOSTS):
        alias = names(h) | {h['ip']}
        row = rows.get(h['key'], {})
        problemes = []
        for p in zabbix_problems:
            if any(str(n).lower() in alias or str(n).lower().split('.')[0] in alias for n in p.get('hosts') or []):
                niveau, raison, _ = policy.zabbix(p.get('description'), p.get('severity'))
                problemes.append({'description': p.get('description'), 'severity': niveau if niveau != 'disk' else 'preventive',
                                  'source_severity': p.get('severity_label'), 'since': p.get('last_change')})
        pousses = [e for e in snap['push_problems']
                   if str(e.get('host') or '').lower() in alias or (e.get('host_ip') or '') == h['ip']
                   or str(e.get('host') or '').lower().split('.')[0] in alias]
        batch = batchs.get(h['key'], {})
        jobs = batch.get('jobs') or (batch.get('last_observation') or {}).get('jobs') or []
        # Résultats réels remontés par infraops-batch-report via Zabbix (zabbix_live).
        resultats = ((snap.get('live') or {}).get(h['key']) or {}).get('batches') or []
        hotes.append({
            'key': h['key'], 'name': h.get('name') or h['key'], 'ip': h['ip'], 'role': h.get('role'),
            'probe': sondes.get(h['key']),
            'live': (snap.get('live') or {}).get(h['key']),
            'zabbix': {'problems': problemes, 'collected_at': zabbix_at, 'fresh': fresh(zabbix_at)},
            'push': pousses,
            'batch': {'collected_at': batch.get('collected_at'), 'status': batch.get('status', 'unknown'),
                      'declared': len(jobs), 'failed': sum(j.get('state') == 'failed' for j in jobs),
                      'running': sum(j.get('state') == 'running' for j in jobs),
                      'limitations': batch.get('limitations') or [],
                      'results': resultats,
                      'results_failed': sum(r['state'] == 'failed' for r in resultats),
                      'results_running': sum(r['state'] == 'running' for r in resultats),
                      # Sans compte-rendu du batch lui-même, on ne connaît que sa planification.
                      'results_measured': bool(resultats) or any(j.get('last_run') for j in jobs)},
            'audit': {'collected_at': row.get('collected_at'), 'status': row.get('status'), 'stale': row.get('stale', True),
                      'cpu': row.get('cpu'), 'ram': row.get('ram'), 'disk_max': row.get('disk_max')},
        })
    # Âge de chaque source, pour le bandeau de fraîcheur de l'interface.
    sources = []
    for c in context.api_connections():
        r = connection_evidence(c)
        sources.append({'name': c.get('name'), 'provider': c.get('provider'), 'collected_at': r.get('collected_at'),
                        'ok': r.get('status') == 'observed' and not r.get('error')})
    return {**{k: v for k, v in snap.items() if k != 'hosts'}, 'hosts': hotes, 'sources': sources, 'generated_at': _now(),
            'scope': ('Sonde directe ICMP + TCP toutes les ' + str(snap['probe_seconds']) + ' s, sans session SSH. '
                      '« Hors service » après deux échecs consécutifs des deux sondes. '
                      'Les métriques CPU/RAM/disque viennent du dernier audit SSH, datées ; '
                      'le résultat d’un batch n’est connu que s’il est remonté (zabbix_sender) ou mesuré.')}
