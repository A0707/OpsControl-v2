"""Référentiel des batchs métier rapproché de ce qui est observé sur les serveurs.

Le référentiel (fichier hors Git, `data/batch_catalog.yaml`) dit ce qui DEVRAIT
tourner : script, serveur, horaire, responsable, statut. L'inventaire SSH
(batch_monitor) et les résultats Zabbix (infraops-batch-report) disent ce qui
est VU. Ce module compare les deux et ne conclut jamais au-delà de ses preuves :
sans crontab root lisible, une planification absente reste « non vérifiable ».
"""
from __future__ import annotations

import json
import os
import posixpath
import re
import time
from collections import Counter
from pathlib import Path

try:
    import yaml
except ImportError:  # PyYAML est dans requirements.txt ; repli JSON pour les postes minimaux
    yaml = None

DEFAULT_PATH = Path(__file__).with_name('data') / 'batch_catalog.yaml'
MAX_ENTRIES = 500
TEXT_FIELDS = {
    'nom': 160, 'responsable': 120, 'serveur': 64, 'properties': 600, 'envoi_mail': 200,
    'horaire': 200, 'commentaire': 600, 'langage': 60, 'cree_le': 40, 'mise_en_production': 120,
    'migration': 40, 'statut': 60, 'validation': 120, 'attendu': 10,
}
SCRIPT_EXT = ('.sh', '.py', '.jar', '.pl', '.php', '.ksh')
# Comptes dont la crontab porte les batchs de /var/batch (cf. deploy/batch-setup.md).
BATCH_ACCOUNTS = {'root', 'batchuser'}


def catalog_path() -> Path:
    """Un chemin explicite permet de garder le référentiel hors du dépôt."""
    configured = os.environ.get('INFRAOPS_BATCH_CATALOG', '').strip()
    return Path(configured).expanduser() if configured else DEFAULT_PATH


def _text(value, limit):
    if value is None:
        return ''
    return str(value).strip()[:limit]


def _slug(name, used):
    base = re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')[:60] or 'batch'
    slug, n = base, 2
    while slug in used:
        slug, n = f'{base}-{n}', n + 1
    used.add(slug)
    return slug


def normalize(raw: dict, used: set) -> dict:
    """Une fiche du référentiel, bornée et typée. Les champs inconnus sont ignorés."""
    entry = {k: _text(raw.get(k), n) for k, n in TEXT_FIELDS.items()}
    if not entry['nom']:
        raise ValueError('fiche sans nom')
    scripts = raw.get('scripts') or []
    if isinstance(scripts, str):
        scripts = [scripts]
    entry['scripts'] = [s for s in (_text(s, 300) for s in scripts[:6]) if s.startswith('/')]
    criticite = raw.get('criticite')
    entry['criticite'] = int(criticite) if str(criticite or '').isdigit() else None
    # Statut « Désactivé » ou attendu explicite : le batch ne doit plus tourner.
    if entry['attendu'] not in ('actif', 'arrete'):
        entry['attendu'] = 'arrete' if entry['statut'].lower().startswith('désactiv') else 'actif'
    entry['id'] = _slug(entry['nom'], used)
    return entry


def load(path: Path | None = None) -> dict:
    """Lit le référentiel. Absent ou invalide : message explicite, jamais d'exception."""
    path = path or catalog_path()
    if not path.is_file():
        return {'available': False, 'entries': [], 'source': path.name,
                'error': 'Référentiel absent : copier batch_catalog.example.yaml vers data/batch_catalog.yaml '
                         'ou définir INFRAOPS_BATCH_CATALOG.'}
    try:
        raw = path.read_text(encoding='utf-8-sig')
        if raw.lstrip().startswith('{'):
            data = json.loads(raw)
        elif yaml:
            data = yaml.safe_load(raw) or {}
        else:
            raise ValueError('PyYAML absent')
        items = data.get('batchs') if isinstance(data, dict) else None
        if not isinstance(items, list):
            raise ValueError('clé « batchs » absente')
        used: set = set()
        entries = [normalize(item, used) for item in items[:MAX_ENTRIES] if isinstance(item, dict)]
    except Exception as error:  # yaml.YAMLError compris, sans dépendre de l'import
        return {'available': False, 'entries': [], 'source': path.name,
                'error': f'Référentiel illisible ({error.__class__.__name__}) : vérifier la syntaxe du fichier.'}
    return {'available': True, 'entries': entries, 'source': path.name, 'error': None,
            'truncated': len(items) > MAX_ENTRIES}


# ---------------------------------------------------------------------------
# Horaires : texte libre du référentiel contre expression cron observée.

def expected_times(text: str):
    """Heures attendues (h, m) lues dans le texte du référentiel, ou None si ambigu.

    « 06-18:00 » = toutes les heures de 6 h à 18 h. « Chaque 2 heures » n'indique
    pas la minute : non comparable plutôt que deviné.
    """
    text = (text or '').strip()
    if not text:
        return None
    plage = re.match(r'^(\d{1,2})\s*-\s*(\d{1,2})[:h](\d{2})', text)
    if plage:
        debut, fin, minute = int(plage.group(1)), int(plage.group(2)), int(plage.group(3))
        if debut <= fin <= 23:
            return {(h, minute) for h in range(debut, fin + 1)}
    times = {(int(h), int(m)) for h, m in re.findall(r'\b(\d{1,2})[:h](\d{2})\b', text)}
    return {t for t in times if t[0] < 24 and t[1] < 60} or None


def _cron_field(field, low, high):
    values = set()
    for part in field.split(','):
        step = 1
        if '/' in part:
            part, raw_step = part.split('/', 1)
            if not raw_step.isdigit() or int(raw_step) == 0:
                return None
            step = int(raw_step)
        if part == '*':
            start, end = low, high
        elif re.fullmatch(r'\d+-\d+', part):
            start, end = map(int, part.split('-'))
        elif part.isdigit():
            start = end = int(part)
            if step > 1:
                end = high
        else:
            return None
        if start < low or end > high or start > end:
            return None
        values.update(range(start, end + 1, step))
    return values


def cron_times(schedule: str):
    """Heures (h, m) d'une expression cron à cinq champs, ou None si non comparable."""
    schedule = (schedule or '').strip()
    special = {'@daily': {(0, 0)}, '@midnight': {(0, 0)}, '@hourly': {(h, 0) for h in range(24)}}
    if schedule.lower() in special:
        return special[schedule.lower()]
    fields = schedule.split()
    if len(fields) != 5 or fields[0] == '*':
        return None
    minutes, hours = _cron_field(fields[0], 0, 59), _cron_field(fields[1], 0, 23)
    if not minutes or not hours:
        return None
    return {(h, m) for h in hours for m in minutes}


def _hhmm(times):
    return ', '.join(f'{h:02d}:{m:02d}' for h, m in sorted(times)[:12]) + (' …' if len(times) > 12 else '')


# ---------------------------------------------------------------------------
# Rapprochement script par script.

def _batch_dir(script):
    """/var/batch/batch_catalog/scripts/x.sh -> /var/batch/batch_catalog."""
    m = re.match(r'^(/var/batch/[^/]+)', script)
    return m.group(1) if m else posixpath.dirname(script)


def _is_directory(script):
    return script.endswith('/') or not script.endswith(SCRIPT_EXT)


def path_matches(observed: str | None, script: str) -> bool:
    """Le chemin observé correspond-il au script du référentiel ?

    Tolère « script/ » contre « scripts/ » : même dossier de batch et même nom de fichier.
    """
    if not observed:
        return False
    if _is_directory(script):
        return observed.startswith(script.rstrip('/') + '/')
    return observed == script or (posixpath.basename(observed) == posixpath.basename(script)
                                  and observed.startswith(_batch_dir(script) + '/'))


def wrapper_name(script: str) -> str:
    """Nom donné par deploy/wrap_crontab.py : dossier du batch + script sans extension."""
    dossier = re.search(r'/var/batch/([A-Za-z0-9_.-]+)', script)
    stem = posixpath.splitext(posixpath.basename(script.rstrip('/')))[0]
    base = '.'.join(p for p in ((dossier.group(1) if dossier else ''), '' if _is_directory(script) else stem) if p)
    return re.sub(r'[^A-Za-z0-9_.-]', '_', base)[:60]


def _result_matches(name, script):
    base = wrapper_name(script)
    return bool(base) and (name == base or re.fullmatch(re.escape(base) + r'_\d+', name or '') is not None)


# Batch quotidien sans passage depuis plus de 26 h : probablement pas lancé.
STALE_DAILY = 26 * 3600
NON_DAILY = re.compile(r'lundi|mardi|mercredi|jeudi|vendredi|samedi|dimanche|mois|month|monday|semaine|week|hebdo', re.I)
CAUSE = re.compile(r'ERROR|FATAL|SEVERE|Exception|Caused by|Traceback|refus|denied|introuvable|not found|No such|timeout',
                   re.I)


def _run_verdict(run):
    """État d'un passage lu dans l'enveloppe : même règle que zabbix_live.batches."""
    rc, fin, debut = run.get('rc'), run.get('finished') or None, run.get('started') or None
    if debut and (fin is None or debut > fin):
        return 'running'
    if rc is None or rc < 0 or fin is None:
        return 'unknown'
    return 'success' if rc == 0 else 'failed'


def _cause(lines):
    """La ligne qui explique le mieux un échec : la dernière qui ressemble à une erreur."""
    for line in reversed(lines or []):
        if CAUSE.search(line):
            return line
    return (lines or [None])[-1]


def _log_stem(name):
    return re.sub(r'([.](log|out|err).*|[._-][0-9]{4}-?[0-9]{2}-?[0-9]{2}.*)$', '', name).lower()


def pick_log(logs, scripts, cron_logs, dir_count):
    """Journal le plus probable d'un batch, et pourquoi il a été choisi.

    Ordre : journal désigné par la ligne cron, journal au nom du script, puis
    le plus récent du dossier (signalé s'il est partagé par plusieurs batchs).
    """
    by_path = {log.get('path'): log for log in logs}
    for path in cron_logs:
        if path in by_path:
            return by_path[path], 'Journal désigné par la ligne cron'
    dirs = {s.rstrip('/') if _is_directory(s) else _batch_dir(s) for s in scripts}
    candidates = [log for log in logs if any(str(log.get('path', '')).startswith(d + '/') for d in dirs)]
    if not candidates:
        return None, None
    stems = {posixpath.splitext(posixpath.basename(s))[0].lower() for s in scripts if not _is_directory(s)}
    exact = [log for log in candidates if _log_stem(posixpath.basename(log['path'])) in stems]
    named = exact or [log for log in candidates
                      if any(stem and stem in posixpath.basename(log['path']).lower() for stem in stems)]
    best = max(named or candidates, key=lambda log: log.get('mtime') or 0)
    if named:
        return best, 'Journal au nom du script'
    if max(dir_count.get(d, 0) for d in dirs) > 1:
        return best, 'Journal le plus récent du dossier, partagé par plusieurs batchs : à confirmer'
    return best, 'Journal le plus récent du dossier du batch'


def outcome_of(wrapped, results, log):
    """Résultat du dernier passage et sa cause, de la preuve la plus forte à la plus faible.

    1. enveloppe lue par la sonde (code retour + fin de sortie d'erreur) ;
    2. enveloppe remontée par Zabbix (code retour seul) ;
    3. journal du batch (verdict déduit : statut Spring Batch ou marqueurs).
    """
    log_lines = []
    if log and log.get('readable'):
        log_lines = list(log.get('errors') or []) + [x for x in log.get('last_lines') or []
                                                     if x not in (log.get('errors') or [])]
    if wrapped:
        run = max(wrapped, key=lambda r: r.get('started') or 0)
        verdict, lines = _run_verdict(run), list(run.get('tail') or [])[-12:]
        rc = run.get('rc') if (run.get('rc') is not None and run['rc'] >= 0) else None
        source, at, duration = 'Enveloppe (fin de sortie d’erreur)', run.get('finished') or run.get('started'), run.get('duration')
        # Pendant un passage, « finished » est encore la fin du passage précédent.
        started, finished = run.get('started') or None, None if verdict == 'running' else run.get('finished') or None
    elif results:
        run = max(results, key=lambda r: r.get('finished_at') or r.get('started_at') or 0)
        verdict, rc, lines = run.get('state', 'unknown'), run.get('rc'), log_lines
        source, at, duration = 'Zabbix (enveloppe)', run.get('finished_at') or run.get('started_at'), run.get('duration_s')
        started, finished = run.get('started_at'), None if verdict == 'running' else run.get('finished_at')
    elif log and log.get('readable'):
        verdict, rc, lines = log.get('verdict', 'unknown'), None, log_lines
        source, at, duration = 'Journal du batch', log.get('mtime'), None
        # Un journal ne date que sa dernière écriture : la fin approchée, jamais le début.
        started, finished = None, log.get('mtime')
    else:
        return None
    if verdict == 'failed':
        cause = _cause(lines)
        reason = (f'Code retour {rc}' if rc is not None else 'Erreur dans le journal') + (f' — {cause}' if cause else '')
    elif verdict == 'success':
        reason = 'Code retour 0' if rc == 0 else (log or {}).get('strength') or 'Fin normale'
    elif verdict == 'running':
        reason = 'Passage en cours'
    else:
        reason = 'Journal lu : ni fin normale ni erreur reconnue' if source == 'Journal du batch' else 'Aucun passage terminé'
    return {'source': source, 'verdict': verdict, 'at': at, 'rc': rc,
            'started_at': started, 'finished_at': finished,
            'duration': duration if verdict != 'running' else None, 'reason': reason[:300], 'lines': lines[:15]}


def _observation(saved):
    return saved if saved.get('status') == 'observed' else (saved.get('last_observation') or {})


def reconcile(catalog: dict, hosts: list, saved: dict, results: dict, is_fresh=lambda _at: False,
              now: float | None = None) -> dict:
    """Compare chaque fiche à l'observation. Pur : testable sans SSH ni Zabbix.

    hosts   : inventaire (key, name, ip) ;
    saved   : {host_key: payload batch_states} ;
    results : {host_key: [résultats infraops-batch-report via Zabbix]}.
    """
    by_ip = {h['ip']: h for h in hosts}
    now = time.time() if now is None else now
    servers, used_jobs, used_results, used_runs = {}, set(), set(), set()
    # Dossiers de batch partagés par plusieurs fiches : un journal commun ne vaut pas pour chacune.
    dir_count = Counter(d for e in catalog.get('entries', [])
                        for d in {s.rstrip('/') if _is_directory(s) else _batch_dir(s) for s in e['scripts']})

    def server(ip):
        if ip in servers:
            return servers[ip]
        host = by_ip.get(ip)
        obs = _observation(saved.get(host['key'], {})) if host else {}
        files = obs.get('batch_files') if isinstance(obs.get('batch_files'), dict) else None
        crontabs = obs.get('crontabs_read')
        runs = obs.get('batch_runs') if isinstance(obs.get('batch_runs'), dict) else {}
        servers[ip] = {
            'ip': ip, 'host_key': host and host['key'], 'name': (host or {}).get('name') or ip,
            'in_inventory': bool(host), 'collected_at': obs.get('collected_at'),
            'fresh': bool(obs) and is_fresh(obs.get('collected_at')),
            'jobs': obs.get('jobs') or [],
            # Ancienne sonde (avant ce champ) : on ne sait pas quelles crontabs ont été lues.
            'crontabs_read': crontabs if isinstance(crontabs, list) else None,
            'files': [f[0] for f in (files or {}).get('files') or [] if isinstance(f, list) and f],
            'mtimes': {f[0]: f[1] for f in (files or {}).get('files') or [] if isinstance(f, list) and len(f) > 1},
            'dirs': (files or {}).get('dirs') or [],
            'files_checked': bool(files and files.get('readable')),
            'files_truncated': bool(files and files.get('truncated')),
            'results': results.get(host['key'], []) if host else [],
            'runs': [r for r in runs.get('runs') or [] if isinstance(r, dict)],
            'runs_readable': runs.get('readable') if runs else None,
            'logs': [d for d in obs.get('batch_logs') or [] if isinstance(d, dict)],
        }
        return servers[ip]

    entries = []
    for fiche in catalog.get('entries', []):
        srv = server(fiche['serveur']) if re.fullmatch(r'\d+\.\d+\.\d+\.\d+', fiche['serveur']) else None
        scripts, findings = fiche['scripts'], []
        crons, running, runs, wrapped, present, mtime, log, log_why = [], [], [], [], None, None, None, None
        if srv:
            for job in srv['jobs']:
                path = job.get('script') or job.get('executable')
                if not any(path_matches(path, s) for s in scripts):
                    continue
                used_jobs.add((srv['ip'], job.get('id')))
                if job.get('kind') == 'process':
                    running.append({'pid': job.get('pid'), 'elapsed_seconds': job.get('elapsed_seconds'),
                                    'owner': job.get('owner')})
                elif job.get('kind') in ('cron', 'systemd'):
                    crons.append({'schedule': job.get('schedule'), 'source': job.get('source'),
                                  'owner': job.get('owner'), 'line': job.get('line'), 'script': path,
                                  'log': job.get('log')})
            for res in srv['results']:
                if any(_result_matches(res.get('name'), s) for s in scripts):
                    used_results.add((srv['ip'], res.get('name')))
                    runs.append(res)
            for run in srv['runs']:
                if any(_result_matches(run.get('name'), s) for s in scripts):
                    used_runs.add((srv['ip'], run.get('name')))
                    wrapped.append(run)
            log, log_why = pick_log(srv['logs'], scripts, [c['log'] for c in crons if c.get('log')], dir_count)
            if srv['files_checked'] and scripts:
                hits = [f for f in srv['files'] if any(path_matches(f, s) for s in scripts)]
                hits += [d for d in srv['dirs'] if any(_is_directory(s) and d == s.rstrip('/') for s in scripts)]
                present = bool(hits) or (None if srv['files_truncated'] else False)
                mtime = max((srv['mtimes'].get(f, 0) for f in hits), default=0) or None

        attendu = expected_times(fiche['horaire'])
        observed = set()
        for c in crons:
            observed |= cron_times(c['schedule']) or set()
        root_read = srv and srv['crontabs_read'] is not None and bool(BATCH_ACCOUNTS & set(srv['crontabs_read']))

        # Constats, du plus grave au plus informatif.
        last = sorted(runs, key=lambda r: -(r.get('finished_at') or 0))[0] if runs else None
        outcome = outcome_of(wrapped, runs, log)
        verdict = (outcome or {}).get('verdict')
        if fiche['attendu'] == 'arrete' and (crons or running):
            findings.append(('critical', 'Arrêt demandé dans le référentiel mais encore '
                             + ('en cours d’exécution' if running else 'planifié')))
        if verdict == 'failed':
            findings.append(('critical', f"Dernier passage en échec : {outcome['reason']}"[:300]))
        elif verdict == 'success' and outcome['source'] != 'Journal du batch' and log and log.get('verdict') == 'failed':
            findings.append(('warning', f"Code retour 0 mais erreur dans le journal : {_cause(log.get('errors'))}"[:300]))
        daily = attendu and not NON_DAILY.search(fiche['horaire'])
        if fiche['attendu'] == 'actif' and daily and outcome and outcome.get('at') and verdict != 'running' \
                and now - outcome['at'] > STALE_DAILY:
            age = int((now - outcome['at']) // 3600)
            findings.append(('warning', (f'Journal non mis à jour depuis {age} h' if outcome['source'] == 'Journal du batch'
                                         else f'Aucun passage depuis {age} h') + ' (batch quotidien) : lancement manqué ?'))
        if log and not log.get('readable'):
            findings.append(('info', 'Journal présent mais illisible par le compte d’audit'))
        if present is False:
            findings.append(('warning', 'Script du référentiel introuvable sur le serveur'))
        if fiche['attendu'] == 'actif' and srv and not crons:
            if root_read:
                findings.append(('warning', 'Aucune planification trouvée dans les crontabs lues'))
        if crons and attendu and observed and observed != attendu:
            findings.append(('warning', f'Horaire observé {_hhmm(observed)} ≠ attendu {_hhmm(attendu)}'))
        if not fiche['serveur']:
            findings.append(('info', 'Serveur non renseigné'))
        elif not srv:
            findings.append(('info', f"Hors inventaire SSH ({fiche['serveur']}) : rapprochement impossible"))
        elif srv and not srv['in_inventory']:
            findings.append(('info', 'Serveur absent de l’inventaire OpsControl'))
        if not scripts and srv:
            findings.append(('info', 'Chemin du script non renseigné'))
        if fiche['attendu'] == 'actif' and not fiche['horaire']:
            findings.append(('info', 'Horaire attendu non renseigné'))
        if not fiche['responsable'] or fiche['responsable'] in ('-', '?'):
            findings.append(('info', 'Responsable non renseigné'))
        if fiche['validation'].lower().startswith('non'):
            findings.append(('info', 'Non validé par le responsable'))

        if srv and not crons and srv['in_inventory'] and not root_read:
            planning = 'Non vérifiable : crontab root non lue par le compte d’audit'
        elif not crons:
            planning = 'Aucune planification observée' if srv and srv['in_inventory'] else 'Non mesuré'
        elif attendu and observed:
            planning = 'Concordant' if observed == attendu else 'Différent'
        else:
            planning = 'Planifié · horaire non comparable'

        levels = {lvl for lvl, _ in findings}
        if fiche['attendu'] == 'arrete' and root_read and not (crons or running):
            state = 'stopped'
        elif verdict == 'failed':
            state = 'failed'
        elif levels & {'critical', 'warning'}:
            state = 'drift'
        elif running or verdict == 'running':
            state = 'running'
        elif verdict == 'success' or planning == 'Concordant':
            state = 'ok'
        else:
            state = 'unknown'
        entries.append({
            **fiche, 'state': state, 'planning': planning,
            'host_key': srv and srv['host_key'], 'host_name': srv['name'] if srv else fiche['serveur'] or '—',
            'observed_schedules': crons, 'running': running, 'last_result': last, 'outcome': outcome,
            'log': dict(log, why=log_why) if log else None,
            'expected_times': _hhmm(attendu) if attendu else None,
            'script_present': present, 'script_mtime': mtime,
            'collected_at': srv and srv['collected_at'], 'fresh': bool(srv and srv['fresh']),
            'findings': [{'level': lvl, 'text': txt} for lvl, txt in findings],
        })

    # Batchs vus sous /var/batch mais absents du référentiel : à documenter.
    unreferenced = []
    for srv in servers.values():
        for job in srv['jobs']:
            path = job.get('script') or job.get('executable') or ''
            if job.get('kind') in ('cron', 'systemd', 'process') and path.startswith('/var/batch/') \
                    and (srv['ip'], job.get('id')) not in used_jobs:
                unreferenced.append({'name': job.get('name'), 'script': path, 'kind': job.get('kind'),
                                     'schedule': job.get('schedule'), 'owner': job.get('owner'),
                                     'host_key': srv['host_key'], 'host_name': srv['name']})
        for run in srv['runs']:
            if (srv['ip'], run.get('name')) not in used_runs:
                unreferenced.append({'name': run.get('name'), 'script': None, 'kind': 'enveloppe',
                                     'schedule': None, 'owner': None, 'state': _run_verdict(run),
                                     'host_key': srv['host_key'], 'host_name': srv['name']})
        for res in srv['results']:
            if (srv['ip'], res.get('name')) not in used_results and \
                    (srv['ip'], res.get('name')) not in used_runs and \
                    res.get('name') not in {r.get('name') for r in srv['runs']}:
                unreferenced.append({'name': res.get('name'), 'script': None, 'kind': 'zabbix',
                                     'schedule': None, 'owner': None, 'state': res.get('state'),
                                     'host_key': srv['host_key'], 'host_name': srv['name']})

    counts = {s: sum(e['state'] == s for e in entries) for s in ('failed', 'drift', 'running', 'ok', 'unknown', 'stopped')}
    counts['total'] = len(entries)
    counts['measured'] = sum((e['outcome'] or {}).get('verdict') in ('success', 'failed', 'running') for e in entries)
    counts['unverifiable'] = sum(e['planning'].startswith('Non vérifiable') for e in entries)
    counts['incomplete'] = sum(any(f['level'] == 'info' and 'non renseigné' in f['text'] for f in e['findings'])
                               for e in entries)
    return {
        'available': catalog.get('available', False), 'error': catalog.get('error'), 'source': catalog.get('source'),
        'entries': entries, 'unreferenced': unreferenced[:300], 'counts': counts,
        'servers': [{**{k: v for k, v in s.items() if k not in ('jobs', 'files', 'mtimes', 'dirs', 'results', 'runs', 'logs')},
                     'logs_read': sum(bool(log.get('readable')) for log in s['logs']), 'runs_count': len(s['runs'])}
                    for s in servers.values()],
    }


def snapshot(context) -> dict:
    """Référentiel rapproché, à partir des états enregistrés (aucune collecte lancée)."""
    from synchronization import fresh
    with context.connect() as db:
        saved = {k: json.loads(p) for k, p in db.execute('SELECT key, payload FROM batch_states')}
    results = {}
    tier0 = getattr(context, 'tier0_snapshot', None)
    if tier0:
        try:
            results = {k: (v or {}).get('batches') or [] for k, v in (tier0().get('live') or {}).items()}
        except Exception:  # la vue critique ne doit jamais casser la page Batch
            results = {}
    return reconcile(load(), list(context.HOSTS), saved, results, fresh)
