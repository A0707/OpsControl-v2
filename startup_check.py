"""Contrôle au démarrage et bilan à l'ouverture de l'interface.

Deux trous constatés dans la chaîne d'alerte :

1. Au démarrage, en mode manuel (intervalle 0), rien n'était recollecté : les
   sources API et la disponibilité réseau restaient celles de la veille. Or une
   alerte critique n'interrompt l'opérateur que si sa preuve est RÉCENTE ; un
   serveur tombé pendant la nuit apparaissait donc « à reconfirmer », sans
   bandeau ni notification, précisément au moment où l'on ouvre l'application.
   D'où un passage unique, quelques secondes après le démarrage : sources API
   (lecture seule) et sondes réseau. Les audits SSH n'en font PAS partie :
   87 sessions imposées à chaque redémarrage restent une décision d'opérateur.
   INFRAOPS_STARTUP_SWEEP=0 le désactive.

2. En ouvrant l'interface, il fallait parcourir l'accueil, les alertes, les
   sources et la santé d'OpsControl pour savoir s'il y a un problème grave ET
   si l'on peut se fier à l'absence d'alerte. /api/briefing répond aux deux en
   une lecture : incidents critiques récents, critiques à reconfirmer, angles
   morts (source en échec ou périmée, sonde muette, audits SSH anciens) et
   santé du collecteur lui-même.

Lecture seule : ce module ne fait que relancer les collectes de lecture déjà
existantes et relire ce qui est enregistré. Aucune commande n'est envoyée aux
serveurs supervisés.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timezone

ENV = 'INFRAOPS_STARTUP_SWEEP'
# Laisse le tunnel applicatif et la voie rapide s'établir avant les premières lectures.
SWEEP_DELAY_SECONDS = 5
# Au-delà, un passage de démarrage bloqué ne doit pas faire attendre l'interface indéfiniment.
SWEEP_TIMEOUT_SECONDS = 300
# Un audit SSH plus ancien ne prouve plus rien sur les disques, la mémoire et les services.
SSH_COVERAGE_HOURS = 24
# Nombre d'éléments détaillés par section : le bilan doit se lire d'un coup d'œil.
SECTION_MAX = 8

LEVELS = ('critical', 'warning', 'unverified', 'ok')
HEADLINES = {
    'critical': 'Problème critique en cours : intervention immédiate',
    'warning': 'Points à vérifier avant de se fier à l’écran',
    'unverified': 'Aucun incident critique observé, mais la détection a des angles morts',
    'ok': 'Aucun problème critique : sources récentes et collecte saine',
}

log = logging.getLogger('opscontrol.startup')


def _instant(value):
    try:
        date = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return date if date.tzinfo else date.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _cibles(alerte):
    noms = [t.get('name') for t in alerte.get('targets') or [] if t.get('name')]
    reste = alerte.get('count', len(noms)) - len(noms[:5])
    return ', '.join(noms[:5]) + (f' et {reste} autre(s)' if reste > 0 else '')


def _item_alerte(alerte):
    cibles = alerte.get('targets') or []
    return {'id': alerte.get('id'), 'source': alerte.get('source'), 'title': alerte.get('title'),
            'detail': _cibles(alerte) or alerte.get('evidence'), 'count': alerte.get('count'),
            'observed_at': alerte.get('observed_at'),
            'host_key': cibles[0].get('host_key') if len(cibles) == 1 else None}


def _en_maintenance(alerte, fenetres):
    """Même règle que l'interface : source et cible facultatives, fenêtre active."""
    noms = {str(v).lower() for t in alerte.get('targets') or []
            for v in (t.get('name'), t.get('host_key')) if v}
    for f in fenetres:
        if not f.get('active') or (f.get('source') and f['source'] != alerte.get('source')):
            continue
        cible = str(f.get('target') or '').lower()
        if not cible or cible in noms:
            return True
    return False


def _maintenances(context, now):
    connect = getattr(context, 'connect', None)
    if connect is None:
        return []
    try:
        from incident_center import maintenance_windows
        with connect() as db:
            return maintenance_windows(db, now, include_future=False)
    except Exception:  # noqa: BLE001 — table absente : aucune maintenance, les alertes restent actives
        return []


def _section(key, title, severity, items, page, note=None):
    return {'key': key, 'title': title, 'severity': severity, 'count': len(items),
            'items': items[:SECTION_MAX], 'page': page, 'note': note}


def build(context, startup=None, now=None, monitor=None):
    """Bilan à l'ouverture. Relit les collectes enregistrées ; ne collecte rien."""
    import alert_center
    import self_monitor

    now = now or datetime.now(timezone.utc)
    monitor = monitor or self_monitor.MONITOR
    centre = alert_center.build(context, now)
    fenetres = _maintenances(context, now)
    alertes = [a for a in centre['alerts'] if not a.get('chronic')]
    critiques = [a for a in alertes if a['severity'] == 'critical']
    actives = [a for a in critiques if a.get('fresh') and not a.get('ack') and not _en_maintenance(a, fenetres)]
    a_reconfirmer = [a for a in critiques if not a.get('fresh') and not a.get('ack')]
    sections = []
    if actives:
        sections.append(_section('critical', 'Incidents critiques en cours', 'critical',
                                 [_item_alerte(a) for a in actives], 'Alertes'))
    if a_reconfirmer:
        sections.append(_section(
            'reconfirm', 'Incidents critiques à reconfirmer', 'warning', [_item_alerte(a) for a in a_reconfirmer],
            'Alertes', 'Preuve ancienne : le problème était présent à la dernière lecture, rien ne dit qu’il est résolu.'))

    # --- Angles morts : sans eux, « aucune alerte » ne veut pas dire « aucun problème ».
    aveugles = []
    sources = centre.get('sources') or []
    if not sources:
        aveugles.append({'title': 'Aucune source API configurée',
                         'detail': 'Zabbix, Proxmox, Wazuh, Elastic et Bacula ne sont pas lus.', 'page': 'Sources'})
    for s in sources:
        nom = s.get('name') or s.get('provider')
        if s.get('error'):
            aveugles.append({'title': f'Source {nom} en échec', 'detail': str(s['error'])[:300],
                             'observed_at': s.get('collected_at'), 'page': 'Sources'})
        elif not s.get('collected_at'):
            aveugles.append({'title': f'Source {nom} jamais collectée', 'detail': 'Ses alertes sont inconnues.',
                             'page': 'Sources'})
        elif not s.get('fresh'):
            aveugles.append({'title': f'Source {nom} périmée',
                             'detail': 'Dernière lecture trop ancienne : ses alertes sont à reconfirmer.',
                             'observed_at': s.get('collected_at'), 'page': 'Sources'})
    sonde = [a for a in alertes if a.get('source') == 'Sonde directe' and a.get('id', '').startswith('Sonde directe:observer')]
    for a in sonde:
        aveugles.append({'title': a['title'], 'detail': a.get('evidence'), 'observed_at': a.get('observed_at'),
                         'page': 'Vue globale'})
    monitor_state = getattr(context, 'monitor', None)
    if isinstance(monitor_state, dict) and not monitor_state.get('interval'):
        # En mode manuel, une lecture Zabbix n'est récente que 30 s : sans cycle automatique,
        # tout incident redevient « à reconfirmer » et n'interrompt plus personne.
        aveugles.append({'title': 'Actualisation automatique désactivée',
                         'detail': 'Sources et sondes réseau ne sont relues qu’à la demande : '
                                   'un nouvel incident ne sera ni détecté ni notifié entre deux actualisations. '
                                   'Choisir 60 s, 5 min ou 15 min dans le sélecteur d’actualisation.',
                         'page': 'Synchronisation'})
    hotes = [h for h in context.rows() if h.get('collect_enabled', True)]
    seuil = now.timestamp() - SSH_COVERAGE_HOURS * 3600
    anciens = [h for h in hotes if (_instant(h.get('collected_at')) or datetime.min.replace(tzinfo=timezone.utc)).timestamp() < seuil]
    if anciens:
        noms = ', '.join(str(h.get('name') or h.get('key')) for h in anciens[:5])
        aveugles.append({'title': f'{len(anciens)} serveur(s) sur {len(hotes)} sans audit SSH depuis {SSH_COVERAGE_HOURS} h',
                         'detail': 'Disques, mémoire et services non vérifiés : ' + noms + (' …' if len(anciens) > 5 else ''),
                         'count': len(anciens), 'page': 'Audit'})
    if aveugles:
        sections.append(_section('blind', 'Angles morts de la détection', 'unverified', aveugles, 'Sources'))

    # --- Santé d'OpsControl : un collecteur arrêté rend tout l'écran faux, sans le dire.
    sante = []
    pret, raisons = self_monitor.readiness(context, monitor)
    for r in raisons:
        sante.append({'title': r, 'detail': 'Les collectes automatiques ne tournent plus.', 'page': 'Santé d’OpsControl'})
    for c in monitor.snapshot()['collectors']:
        if c['kind'] != 'api' and c['state'] == 'failing':
            sante.append({'title': f"{c['label']} en échec ({c['consecutive_failures']} fois de suite)",
                          'detail': c.get('last_error'), 'observed_at': c.get('last_failure'),
                          'page': 'Santé d’OpsControl'})
    if sante:
        sections.append(_section('opscontrol', 'Santé d’OpsControl', 'warning', sante, 'Santé d’OpsControl'))

    niveau = ('critical' if actives else 'warning' if a_reconfirmer or sante
              else 'unverified' if aveugles else 'ok')
    startup = dict(startup or {})
    return {
        'generated_at': now.isoformat(),
        'level': niveau,
        'headline': HEADLINES[niveau],
        'checking': startup.get('status') in ('pending', 'running'),
        'startup': startup,
        'sections': sections,
        'counts': {'critical': len(actives), 'reconfirm': len(a_reconfirmer), 'blind_spots': len(aveugles),
                   'opscontrol': len(sante),
                   'acknowledged': sum(1 for a in critiques if a.get('fresh') and a.get('ack')),
                   'maintenance': sum(1 for a in critiques if a.get('fresh') and not a.get('ack')
                                      and _en_maintenance(a, fenetres)),
                   'chronic': centre['counts'].get('chronic', 0)},
        'scope': ('Bilan relu dans les collectes enregistrées : incidents critiques récents (ni pris en charge, '
                  'ni en maintenance, ni chroniques), critiques à reconfirmer, angles morts et santé d’OpsControl. '
                  'Aucune collecte n’est déclenchée par cette lecture et aucune action n’est exécutée.'),
    }


def install(app, context):
    from fastapi import APIRouter
    router = APIRouter()
    guard = threading.Lock()
    actif = os.getenv(ENV, '1') != '0'
    state = {'status': 'pending' if actif else 'disabled', 'started_at': None, 'finished_at': None,
             'steps': [], 'note': None if actif else f'Désactivé par {ENV}=0.'}
    origine = {'monotonic': time.monotonic(), 'started': None}

    def tick(now=None):
        """Appelé par le planificateur chaque seconde ; ne lance le passage qu'une fois."""
        now = time.monotonic() if now is None else now
        with guard:
            statut = state['status']
            if statut == 'pending' and now - origine['monotonic'] >= SWEEP_DELAY_SECONDS:
                state.update(status='running', started_at=datetime.now(timezone.utc).isoformat())
                origine['started'] = now
                statut = 'launch'
        if statut == 'launch':
            # Les deux lancements sont idempotents : si le cycle normal vient de démarrer
            # les mêmes collectes, ils renvoient l'état en cours sans les doubler.
            etapes = []
            for nom, lancer in (('Sources API', lambda: context.launch_api_sync()),
                                ('Disponibilité réseau', lambda: context.launch_network(context.HOSTS, 'demarrage'))):
                try:
                    lancer()
                    etapes.append({'name': nom, 'launched': True})
                except Exception as exc:  # noqa: BLE001 — une étape en échec n'empêche pas l'autre
                    log.exception('Contrôle de démarrage : %s', nom)
                    etapes.append({'name': nom, 'launched': False, 'error': type(exc).__name__})
            with guard:
                state['steps'] = etapes
            return
        if statut == 'running':
            _terminer_si_fini(now)

    def _en_cours():
        api = context.api_sync_state() if hasattr(context, 'api_sync_state') else {}
        with context.net_lock:
            reseau = bool(context.net_job.get('running'))
        return bool(api.get('running')) or reseau

    def _terminer_si_fini(now):
        depasse = now - (origine['started'] or now) > SWEEP_TIMEOUT_SECONDS
        if not depasse and _en_cours():
            return
        with guard:
            if state['status'] == 'running':
                state.update(status='timeout' if depasse else 'done',
                             finished_at=datetime.now(timezone.utc).isoformat(),
                             note='Collectes de démarrage encore en cours après '
                                  f'{SWEEP_TIMEOUT_SECONDS // 60} min : bilan établi sans elles.' if depasse else None)

    def snapshot():
        with guard:
            return {**state, 'steps': [dict(s) for s in state['steps']]}

    context.startup_tick = tick
    context.startup_state = snapshot

    @router.get('/api/briefing')
    def briefing():
        return build(context, snapshot())

    app.include_router(router)  # routes de ce module : APIRouter, inclus en fin d'installation
