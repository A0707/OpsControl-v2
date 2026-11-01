"""Apache santé & saturation : niveaux, corrélation, alertes et historique local.

Fonctions pures (sauf record/history qui écrivent la base locale d'OpsControl).
Aucune action distante : on interprète la sonde apache_probe.py et la section
`sockets` de waf_probe.py. Une donnée absente reste None (« N/A ») : aucun
niveau n'est calculé sur une valeur manquante.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

LEVELS = ('ok', 'yellow', 'orange', 'red', 'critical', 'unknown')
TONE = {'ok': 'ok', 'yellow': 'warning', 'orange': 'warning', 'red': 'critical', 'critical': 'critical', 'unknown': 'unknown'}
LABEL = {'ok': 'OK', 'yellow': 'Vigilance', 'orange': 'Risque', 'red': 'Critique', 'critical': 'APACHE SATURATION', 'unknown': 'N/A'}
WORKER_THRESHOLDS = (60, 75, 90)          # % d'utilisation : jaune, orange, rouge
# CLOSE_WAIT Apache : > 200 jaune, > 300 orange, > 1000 rouge. Calibré sur 7 jours de prdlabwaf03
# (864 collectes, docs/WAF-SEUILS.md) : hors épisode lent p50 84, p95 172, p99 216 ; pendant les
# épisodes lents p50 242, max 316. L'ancienne échelle 20/50/100 classait 36 % des collectes normales en rouge.
CLOSE_WAIT_THRESHOLDS = (200, 300, 1000)
# Backend injoignable depuis plus de 24 h : chronique (vhost abandonné ou en attente), signalé en
# « Vigilance » au lieu de « Risque » : les mêmes 8 backends restaient « down » toute la semaine et
# maintenaient l'état global orange dans 97 % des collectes, sans valeur d'alerte.
BACKEND_CHRONIC_HOURS = 24
SLOW_AVG_THRESHOLDS = (1, 3, 5)           # secondes : jaune, orange, rouge
SLOW10_CRITICAL_SHARE = 0.10              # ≥ 10 s sur plus de 10 % du trafic : critique
SLOW5_MANY_SHARE = 0.10                   # « requêtes lentes > 5 s nombreuses »
HISTORY_DAYS = 7


def _num(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def _data(sections, name):
    s = (sections or {}).get(name) or {}
    return s.get('data') if s.get('status') == 'observed' and isinstance(s.get('data'), dict) else None


def _error(sections, name):
    s = (sections or {}).get(name) or {}
    return None if s.get('status') == 'observed' else (s.get('error') or 'Non collecté')


def level_up(value, thresholds, strictly=False):
    if value is None:
        return 'unknown'
    a, b, c = thresholds
    gt = (lambda x, t: x > t) if strictly else (lambda x, t: x >= t)
    return 'red' if gt(value, c) else 'orange' if gt(value, b) else 'yellow' if gt(value, a) else 'ok'


def worst(*levels):
    order = {'critical': 5, 'red': 4, 'orange': 3, 'yellow': 2, 'ok': 1, 'unknown': 0}
    return max(levels, key=lambda l: order.get(l, 0)) if levels else 'unknown'


def evaluate(apache, waf_sections, previous=None, now=None):
    """apache = {'sections': …} de apache_probe ; waf_sections = sections de waf_probe."""
    now = now or datetime.now(timezone.utc)
    sections = (apache or {}).get('sections') or {}
    status, config, saturation, backends, access = (_data(sections, k) for k in ('status', 'config', 'saturation', 'backends', 'access'))
    sockets = _data(waf_sections, 'sockets')

    # --- Workers
    busy = _num((status or {}).get('BusyWorkers'))
    max_workers = _num((config or {}).get('effective_max_workers'))
    util = round(busy / max_workers * 100, 1) if busy is not None and max_workers else None
    sat_counts = (saturation or {}).get('counts') or {}
    sat_last = (saturation or {}).get('last') or {}
    saturation_seen = any((sat_counts.get(c) or 0) > 0 for c in ('AH00484', 'AH10159', 'AH03490'))
    confirmed = any((sat_counts.get(c) or 0) > 0 for c in ('AH00484', 'AH03490'))
    worker_level = level_up(util, WORKER_THRESHOLDS)
    if (busy is not None and max_workers and busy >= max_workers) or saturation_seen:
        worker_level = 'critical'
    last_saturation = max((v for v in sat_last.values() if v), default=None)

    # --- CLOSE_WAIT (Apache seulement quand le processus est visible)
    cw = None
    if sockets:
        by_process = dict(map(tuple, sockets.get('by_process') or []))
        cw = by_process.get('apache2') if sockets.get('process_visible') else sockets.get('close_wait_total')
        cw = cw if cw is not None else 0 if sockets.get('process_visible') else None
    cw_level = level_up(cw, CLOSE_WAIT_THRESHOLDS, strictly=True)
    cw_delta = cw - previous['close_wait'] if cw is not None and previous and _num(previous.get('close_wait')) is not None else None

    # --- Requêtes lentes
    total = _num((access or {}).get('total'))
    avg = _num((access or {}).get('avg'))
    slow5, slow10 = _num((access or {}).get('slow5')), _num((access or {}).get('slow10'))
    share10 = slow10 / total if total and slow10 is not None else None
    share5 = slow5 / total if total and slow5 is not None else None
    slow_level = level_up(avg, SLOW_AVG_THRESHOLDS)
    slow_massive = share10 is not None and share10 > SLOW10_CRITICAL_SHARE
    # « critical » est réservé à la saturation des workers (libellé APACHE SATURATION) : des requêtes
    # lentes avec des workers libres sont « Critique » (rouge), pas une saturation.
    if slow_massive:
        slow_level = 'red'
    conc = (access or {}).get('concurrency') or {}
    peak10 = _num(conc.get('peak_10m'))
    conc_util = round(peak10 / max_workers * 100, 1) if peak10 is not None and max_workers else None
    conc_level = level_up(conc_util, WORKER_THRESHOLDS)

    # --- Backends
    backend_rows = (backends or {}).get('backends') or []
    down = [b for b in backend_rows if b.get('state') in ('NETWORK DOWN', 'TCP DOWN')]
    slow_backends = [b for b in backend_rows if b.get('state') == 'HTTP SLOW']
    errors = [b for b in backend_rows if b.get('state') == 'HTTP STATUS ERROR']
    since_before = (previous or {}).get('down_since') or {}
    down_since = {b['backend']: since_before.get(b['backend'], now.isoformat()) for b in down}
    chronic_limit = (now - timedelta(hours=BACKEND_CHRONIC_HOURS)).isoformat()
    chronic = [b for b in down if down_since[b['backend']] <= chronic_limit]
    fresh_down = [b for b in down if b not in chronic]
    backend_level = ('unknown' if not backend_rows else 'red' if fresh_down else 'orange' if (slow_backends or errors)
                     else 'yellow' if chronic else 'ok')
    ttfbs = [b['ttfb_ms'] for b in backend_rows if _num(b.get('ttfb_ms')) is not None]

    # --- ModSecurity / bots
    bots = (access or {}).get('bots') or {}
    blocks = _num(bots.get('s403'))
    modsec_denied = _num((saturation or {}).get('modsecurity_denied'))
    rps = _num((access or {}).get('rps'))

    # --- Corrélation (cas 1 à 5), jamais une cause affirmée sans preuve
    diagnostics = []
    busy_high = util is not None and util >= 90
    if confirmed:
        diagnostics.append({'case': 5, 'level': 'critical', 'text': 'Confirmed Apache saturation event.',
                            'detail': 'AH00484 / AH03490 présent dans error.log sur les '
                                      + str((saturation or {}).get('window_seconds', 1800) // 60) + ' dernières minutes (dernière occurrence : '
                                      + (last_saturation or 'N/A') + ').'})
    if busy_high and share5 is not None and share5 >= SLOW5_MANY_SHARE:
        diagnostics.append({'case': 1, 'level': 'critical', 'text': 'Apache saturation likely caused by slow backend/application requests.',
                            'detail': f'{util} % des workers occupés et {round(share5 * 100, 1)} % des requêtes ≥ 5 s.'})
    rps_ref = _num((previous or {}).get('rps_reference'))
    if busy_high and avg is not None and avg < 1 and rps is not None and rps_ref and rps >= 2 * rps_ref:
        diagnostics.append({'case': 2, 'level': 'critical', 'text': 'Apache saturation likely caused by traffic/concurrency spike.',
                            'detail': f'{rps} req/s contre {rps_ref} req/s habituellement (médiane de l’historique), réponses rapides (moyenne {avg} s).'})
    cw_high = cw is not None and cw > CLOSE_WAIT_THRESHOLDS[0]
    if cw_high and util is not None and util < 75:
        diagnostics.append({'case': 3, 'level': 'warning', 'text': 'Persistent backend CLOSE_WAIT detected, but no current Apache worker saturation.',
                            'detail': f'{cw} connexions backend CLOSE_WAIT persistantes, {util} % des workers occupés.'})
    backend_is_slow = bool(slow_backends) or (avg is not None and avg >= 3)
    if cw_high and util is not None and util >= 75 and backend_is_slow:
        diagnostics.append({'case': 4, 'level': 'critical', 'text': 'Backend connection handling may contribute to Apache saturation.',
                            'detail': f'{cw} CLOSE_WAIT, {util} % des workers occupés, backend lent (moyenne {avg} s'
                                      + (', ' + ', '.join(b['backend'] for b in slow_backends[:3]) + ' en HTTP SLOW' if slow_backends else '') + ').'})

    # Un backend injoignable (souvent un vhost peu utilisé) ne rend pas Apache critique : plafond « Risque ».
    # Un CLOSE_WAIT élevé sans charge des workers reste un avertissement.
    overall = worst(worker_level, cw_level if cw_level != 'red' or (util or 0) >= 75 else 'orange', slow_level,
                    {'red': 'orange', 'unknown': 'ok'}.get(backend_level, backend_level))
    # worst() classe « unknown » sous « ok » : sans cette règle, un seul contrôle mesuré suffisait à
    # afficher OK alors que les workers, le CLOSE_WAIT, les latences, les backends ou error.log n'étaient pas mesurés.
    incomplete = None in (status, config, saturation, backends, access, sockets)
    if overall == 'ok' and (incomplete or 'unknown' in (worker_level, cw_level, slow_level)):
        overall = 'unknown'
    cards = [
        {'key': 'workers', 'title': 'APACHE WORKERS', 'value': _fmt_ratio(busy, max_workers), 'level': worker_level,
         'note': 'BusyWorkers / MaxRequestWorkers effectif'},
        {'key': 'load', 'title': 'WORKER LOAD', 'value': _fmt(util, ' %'), 'level': worker_level,
         'note': 'Seuils 60 / 75 / 90 %'},
        {'key': 'close_wait', 'title': 'CLOSE_WAIT', 'value': _fmt(cw), 'level': cw_level,
         'note': ('Δ ' + ('+' if cw_delta > 0 else '') + str(cw_delta) + ' depuis la collecte précédente') if cw_delta is not None else 'Connexions backend persistantes'},
        {'key': 'slow', 'title': 'SLOW REQUEST AVG', 'value': _fmt(avg, ' s'), 'level': slow_level,
         'note': (f'{round(share10 * 100, 1)} % ≥ 10 s sur 10 min' if share10 is not None else 'Journaux avec %D requis')},
        {'key': 'concurrency', 'title': 'PEAK CONCURRENCY', 'value': _fmt_ratio(peak10, max_workers), 'level': conc_level,
         'note': 'Pic 10 min estimé depuis %t + %D'},
        # Compteur informatif : un 403 n'est pas forcément un refus ModSecurity (ancien titre « MODSEC BLOCKS »).
        {'key': 'modsec', 'title': 'HTTP 403 · 10 MIN', 'value': _fmt(blocks),
         'level': 'unknown' if blocks is None else 'info',
         'note': 'Réponses 403 du journal d’accès, toutes origines'
                 + (f' · {modsec_denied} refus ModSecurity sur 30 min (error.log et journaux des vhosts'
                    + ('' if ((saturation or {}).get('modsecurity_vhosts') or {}).get('complete', True) else ', couverture partielle : minimum')
                    + ')' if modsec_denied is not None else '')},
    ]
    top_ip = ((access or {}).get('top_ips') or [{}])[0].get('ip')
    top_uri = ((access or {}).get('top_uris') or [{}])[0].get('uri')
    return {
        'evaluated_at': now.isoformat(), 'overall': overall, 'cards': cards, 'diagnostics': diagnostics,
        'summary': summary_lines(worker_level, busy, max_workers, util, cw, backend_rows, down, slow_backends, slow_level,
                                 avg, share10, confirmed, access, last_saturation, chronic),
        'workers': {'busy': busy, 'max': max_workers, 'utilization': util, 'level': worker_level,
                    'saturation_seen': saturation_seen, 'confirmed': confirmed, 'last_saturation': last_saturation,
                    'idle': _num((status or {}).get('IdleWorkers')), 'processes': _num((status or {}).get('Processes'))},
        'close_wait': {'value': cw, 'level': cw_level, 'delta': cw_delta, 'thresholds': list(CLOSE_WAIT_THRESHOLDS)},
        'slow': {'level': slow_level, 'avg': avg, 'share10': share10, 'share5': share5},
        'concurrency': {'peak_10m': peak10, 'utilization': conc_util, 'level': conc_level},
        'backends': {'level': backend_level, 'down': len(down), 'chronic': len(chronic), 'chronic_list': [b['backend'] for b in chronic],
                     'slow': len(slow_backends), 'errors': len(errors),
                     'max_ttfb_ms': max(ttfbs) if ttfbs else None},
        'errors': {k: _error(sections, k) for k in ('status', 'config', 'saturation', 'backends', 'access') if _error(sections, k)},
        'findings': findings(worker_level, util, busy, max_workers, last_saturation, confirmed, cw, cw_level, slow_level, avg, share10, down,
                             diagnostics, slow_massive, chronic),
        'sample': {'ts': now.isoformat(), 'busy': busy, 'max_workers': max_workers, 'utilization': util, 'close_wait': cw,
                   'req_per_sec_status': _num((status or {}).get('ReqPerSec')), 'rps': rps, 'requests_10m': total,
                   'slow5': slow5, 'slow10': slow10, 'avg': avg, 'peak_concurrency': peak10,
                   'backend_max_ttfb_ms': max(ttfbs) if ttfbs else None, 'backends_down': len(down),
                   'top_ip': top_ip, 'top_uri': top_uri, 'ah00484': (sat_counts.get('AH00484') or 0) > 0,
                   'ah03490': (sat_counts.get('AH03490') or 0) > 0, 'level': overall, 'down_since': down_since},
    }


def _fmt(v, suffix=''):
    return 'N/A' if v is None else (f'{v:g}' if isinstance(v, float) else str(v)) + suffix


def _fmt_ratio(a, b):
    return 'N/A' if a is None else f'{a} / {b if b else "N/A"}'


def summary_lines(worker_level, busy, max_workers, util, cw, backend_rows, down, slow_backends, slow_level, avg, share10,
                  confirmed, access, last_saturation, chronic=()):
    lines = []
    if worker_level == 'critical':
        lines.append('CRITICAL: Apache worker saturation detected.')
        if busy is not None and max_workers and busy >= max_workers:
            lines.append('MaxRequestWorkers reached.')
        if confirmed:
            lines.append(f'Saturation confirmed in error.log (last: {last_saturation}).')
        top = ((access or {}).get('top_vhosts') or [])
        total = (access or {}).get('total') or 0
        if top and total and top[0][1] / total >= 0.5:
            lines.append(f'{top[0][0]} traffic represents the majority of logged requests ({round(top[0][1] / total * 100)} %).')
    elif busy is None or util is None:
        lines.append('Apache worker state N/A (server-status or MaxRequestWorkers unavailable).')
    else:
        lines.append('Apache healthy.' if worker_level == 'ok' else f'Apache worker load elevated ({util} %).')
        lines.append(f'{busy}/{max_workers or "N/A"} workers busy.')
    if cw is not None and cw > 0:
        lines.append(f'{cw} persistent backend CLOSE_WAIT detected.')
    if backend_rows:
        fresh = [b for b in down if b not in chronic]
        if fresh:
            lines.append('Backend unreachable: ' + ', '.join(b['backend'] for b in fresh[:3]) + '.')
        if chronic:
            lines.append(f'{len(chronic)} backend(s) unreachable for more than {BACKEND_CHRONIC_HOURS} h (chronic: abandoned vhost or pending repair): '
                         + ', '.join(b['backend'] for b in chronic[:3]) + ('…' if len(chronic) > 3 else '') + '.')
        if not down and slow_backends:
            lines.append('Backend slow: ' + ', '.join(b['backend'] for b in slow_backends[:3]) + '.')
        elif not down:
            hosts = sorted({b['backend'].rsplit(':', 1)[0] for b in backend_rows})
            lines.append('Backends responding (' + ', '.join(hosts[:3]) + (', …' if len(hosts) > 3 else '') + ').')
    if slow_level in ('critical', 'red', 'orange'):
        lines.append('High number of slow requests detected' + (f' ({round(share10 * 100, 1)} % ≥ 10 s, avg {avg} s).' if share10 is not None else '.'))
        if worker_level == 'critical':
            lines.append('Investigate backend latency and traffic sources.')
    elif avg is not None:
        lines.append('Slow-request rate is currently normal.' if slow_level == 'ok' else f'Slow requests to watch (avg {avg} s).')
    else:
        lines.append('Slow-request analysis N/A (access logs without %D).')
    return lines


def findings(worker_level, util, busy, max_workers, last_saturation, confirmed, cw, cw_level, slow_level, avg, share10, down, diagnostics,
             slow_massive=False, chronic=()):
    out = []

    def add(key, title, severity, evidence, check, advice):
        out.append({'id': 'waf:apache:' + key, 'title': title, 'severity': severity, 'domain': 'WAF / Apache',
                    'evidence': evidence, 'check_command': check, 'solution_command': '# ' + advice,
                    'precaution': 'Observation uniquement : aucune action automatique. Vérifier la preuve et sa date.',
                    'scope': 'Apache du WAF', 'requires_adaptation': True, 'executable': False})

    if worker_level == 'critical':
        add('saturation', 'APACHE SATURATION', 'critical',
            f'Workers {busy}/{max_workers} ({util} %)' + (f' · dernière occurrence AH00484/AH03490 : {last_saturation}' if last_saturation else ''),
            'curl -s --max-time 3 http://127.0.0.1/server-status?auto',
            'Identifier la cause (backend lent, pic de trafic) avant toute modification de MaxRequestWorkers.')
    elif worker_level in ('red', 'orange'):
        add('workers', f'Charge des workers Apache élevée ({util} %)', 'warning', f'{busy}/{max_workers} workers occupés (seuils 60/75/90 %).',
            'curl -s --max-time 3 http://127.0.0.1/server-status?auto', 'Surveiller l’évolution et les requêtes lentes.')
    if cw is not None and cw > CLOSE_WAIT_THRESHOLDS[0]:
        high = util is not None and util >= 75
        add('close_wait', 'Connexions backend CLOSE_WAIT persistantes', 'critical' if high else 'warning',
            f'{cw} sockets Apache en CLOSE_WAIT (seuils {"/".join(map(str, CLOSE_WAIT_THRESHOLDS))}) · workers occupés : {util if util is not None else "N/A"} %.',
            'sudo ss -tanp state close-wait',
            'Corréler avec la réutilisation des connexions du proxy et les timeouts backend ; aucune conclusion sur l’état des workers sans server-status.')
    if slow_massive:
        add('slow', 'Requêtes lentes : plus de 10 % ≥ 10 s', 'critical', f'{round(share10 * 100, 1)} % des requêtes des 10 dernières minutes ≥ 10 s (moyenne {avg} s).',
            'sudo tail -n 200 /var/log/apache2/error.log', 'Identifier l’URL et le backend concernés dans le bloc « URL les plus lentes ».')
    elif slow_level in ('red', 'orange'):
        add('slow', f'Temps de réponse moyen élevé ({avg} s)', 'warning', f'Moyenne {avg} s sur 10 min (seuils 1/3/5 s).', '', 'Consulter le bloc « URL les plus lentes ».')
    for b in down[:5]:
        add('backend:' + b['backend'], f'Backend {b["state"]} : {b["backend"]}' + (' (chronique, > 24 h)' if b in chronic else ''),
            'warning', b.get('detail') or '',
            nc_command(b['backend']), 'Vérifier le service backend et la route réseau.')
    return out


def nc_command(backend):
    """Commande de test TCP à copier, ou '' si l'hôte du ProxyPass n'est ni une IP ni un nom
    d'hôte : la valeur vient de la configuration Apache du WAF, jamais recopiée telle quelle
    dans un terminal (audit WAF-03). IPv6 entre crochets prise en charge."""
    import re
    import shlex
    from ipaddress import ip_address
    text = str(backend or '')
    match = re.fullmatch(r'\[([0-9A-Fa-f:.]+)\]:(\d{1,5})|([^:\[\]]+):(\d{1,5})', text)
    if not match:
        return ''
    host, port = (match[1], match[2]) if match[1] else (match[3], match[4])
    try:
        ip_address(host)
    except ValueError:
        if not re.fullmatch(r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
                            r'(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*', host):
            return ''
    if not 1 <= int(port) <= 65535:
        return ''
    return f'nc -vz -w 3 {shlex.quote(host)} {int(port)}'


# --------------------------------------------------------------------------- historique local
def ensure_table(db):
    """Chemin d'écriture (après collecte) seulement ; la table vient de la migration core_v4."""
    from migrations import MODULE_TABLES
    db.execute(MODULE_TABLES['apache_samples'])


def previous_sample(db, key):
    ensure_table(db)
    row = db.execute('SELECT payload FROM apache_samples WHERE key=? ORDER BY ts DESC LIMIT 1', (key,)).fetchone()
    previous = json.loads(row[0]) if row else {}
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    values = sorted(json.loads(p).get('rps') for (p,) in db.execute(
        'SELECT payload FROM apache_samples WHERE key=? AND ts>=?', (key, since)).fetchall() if isinstance(json.loads(p).get('rps'), (int, float)))
    if len(values) >= 6:
        previous['rps_reference'] = values[len(values) // 2]
    return previous


def record(connect, key, waf):
    """Évalue la collecte WAF, l'annote et conserve un échantillon chiffré (7 jours)."""
    if not waf or not waf.get('apache'):
        return None
    with connect() as db:
        previous = previous_sample(db, key)
        result = evaluate(waf['apache'], waf.get('sections') or {}, previous)
        db.execute('INSERT OR REPLACE INTO apache_samples(key, ts, payload) VALUES(?,?,?)', (key, result['sample']['ts'], json.dumps(result['sample'])))
        cutoff = (datetime.now(timezone.utc) - timedelta(days=HISTORY_DAYS)).isoformat()
        db.execute('DELETE FROM apache_samples WHERE key=? AND ts<?', (key, cutoff))
    waf['apache_health'] = result
    return result


def history(connect, key, hours=24, limit=500):
    since = (datetime.now(timezone.utc) - timedelta(hours=max(1, min(hours, 24 * HISTORY_DAYS)))).isoformat()
    # Route GET : aucune écriture, pas même un CREATE ; table absente = aucun historique.
    try:
        with connect() as db:
            rows = db.execute('SELECT payload FROM apache_samples WHERE key=? AND ts>=? ORDER BY ts DESC LIMIT ?',
                              (key, since, limit)).fetchall()
    except sqlite3.OperationalError:
        return []
    return [json.loads(p) for (p,) in rows]


def install(app, context):
    from fastapi import APIRouter
    router = APIRouter()
    from fastapi import HTTPException

    @router.get('/api/waf/{key}/apache-history')
    def apache_history(key: str, hours: int = 24):
        if not any(h['key'] == key for h in context.HOSTS):
            raise HTTPException(404, 'Serveur inconnu')
        return {'samples': history(context.connect, key, hours), 'retention_days': HISTORY_DAYS,
                'scope': 'Un échantillon par collecte WAF : compteurs, top IP et top URL sans paramètres.'}
    app.include_router(router)  # routes de ce module : APIRouter, inclus en fin d'installation
