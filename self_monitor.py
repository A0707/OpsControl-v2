"""Supervision d'OpsControl lui-même : santé, collecteurs, sources, fraîcheur.

Quatre questions distinctes, jamais confondues dans l'interface :
1. OpsControl est-il disponible ?           processus, base locale, planificateur ;
2. ses collecteurs fonctionnent-ils ?      dernière exécution, durée, succès/échecs ;
3. les sources distantes répondent-elles ? dernière lecture API réussie, erreur ;
4. les données sont-elles fraîches ?       part des preuves récentes (SSH, réseau, API).

Un collecteur peut tourner sans erreur alors que la source distante est en panne,
et une source joignable peut fournir des données anciennes : chaque niveau a son état.
Aucune requête distante n'est émise ici ; tout est lu en mémoire ou dans la base locale.
(À ne pas confondre avec observability.py : tendances par serveur issues des audits.)
"""
from __future__ import annotations

import logging
import os
import re
import threading
import time
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timezone

FRESH_SECONDS = 900
SCHEDULER_TICK_SECONDS = 1
SCHEDULER_LAG_WARNING = 10  # au-delà, le planificateur est considéré bloqué
ERROR_BUFFER = 50
COLLECTOR_LABELS = {'ssh': 'Audits SSH', 'network': 'Sondes réseau', 'api': 'Lectures API', 'batch': 'Inventaire Batch',
                    'incidents': 'Rapprochement des incidents', 'retention': 'Rétention des données locales'}


def _iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat() if ts else None


def clean(text, limit=300):
    """Message d'erreur sans secret ni chemin local."""
    from audit_engine import redact
    value = redact(str(text or ''))
    value = re.sub(r'(?i)\b[a-z]:\\[^\s"\']+', '[chemin]', value)
    value = re.sub(r'(?<![\w.])/(?:home|opt|etc|var|usr|root|tmp|Users)/[^\s"\']+', '[chemin]', value)
    return value[:limit]


def _new_job():
    return {'runs': 0, 'success': 0, 'failure': 0, 'consecutive_failures': 0, 'last_started': None,
            'last_finished': None, 'last_success': None, 'last_failure': None, 'last_duration_ms': None,
            'last_error': None, 'last_items': None, 'running': 0, 'skipped': 0}


class Monitor:
    def __init__(self, clock=time.time):
        self.clock = clock
        self.lock = threading.Lock()
        self.started_at = clock()
        self.jobs = {}          # (kind, key) -> état
        self.heartbeats = {}    # nom -> (horodatage, intervalle attendu)
        self.errors = deque(maxlen=ERROR_BUFFER)
        self.sse_clients = 0
        self.sse_total = 0

    # --- collecteurs
    def begin(self, kind, key=None):
        with self.lock:
            job = self.jobs.setdefault((kind, key), _new_job())
            job['running'] += 1
            job['last_started'] = self.clock()
            return job['last_started']

    def end(self, kind, ok, key=None, error=None, started=None, items=None):
        now = self.clock()
        with self.lock:
            job = self.jobs.setdefault((kind, key), _new_job())
            job['running'] = max(0, job['running'] - 1)
            job['runs'] += 1
            job['last_finished'] = now
            begun = started or job['last_started']
            job['last_duration_ms'] = int((now - begun) * 1000) if begun else None
            if items is not None:
                job['last_items'] = items
            if ok:
                job['success'] += 1
                job['consecutive_failures'] = 0
                job['last_success'] = now
            else:
                job['failure'] += 1
                job['consecutive_failures'] += 1
                job['last_failure'] = now
                job['last_error'] = clean(error or 'Échec sans détail')
        if not ok:
            self.error(f'{COLLECTOR_LABELS.get(kind, kind)}{" · " + key if key else ""} : {error or "échec"}', source=kind)

    def skip(self, kind, key=None):
        """Exécution non faite (collecte identique déjà en cours) : ni succès ni échec."""
        with self.lock:
            job = self.jobs.setdefault((kind, key), _new_job())
            job['running'] = max(0, job['running'] - 1)
            job['skipped'] += 1

    @contextmanager
    def track(self, kind, key=None):
        started = self.begin(kind, key)
        outcome = {'ok': True, 'error': None, 'items': None}
        try:
            yield outcome
        except Exception as exc:
            outcome.update(ok=False, error=type(exc).__name__ + ' : ' + str(exc))
            raise
        finally:
            self.end(kind, outcome['ok'], key, outcome['error'], started, outcome['items'])

    # --- planificateur, SSE, erreurs
    def heartbeat(self, name, interval=SCHEDULER_TICK_SECONDS):
        with self.lock:
            self.heartbeats[name] = (self.clock(), interval)

    def sse_open(self):
        with self.lock:
            self.sse_clients += 1
            self.sse_total += 1

    def sse_close(self):
        with self.lock:
            self.sse_clients = max(0, self.sse_clients - 1)

    def error(self, message, source='application'):
        with self.lock:
            self.errors.appendleft({'at': _iso(self.clock()), 'source': source, 'message': clean(message)})

    def snapshot(self):
        now = self.clock()
        with self.lock:
            jobs = {k: dict(v) for k, v in self.jobs.items()}
            beats = dict(self.heartbeats)
            errors = list(self.errors)
            sse = (self.sse_clients, self.sse_total)
        collectors = []
        for (kind, key), j in sorted(jobs.items(), key=lambda x: (x[0][0], x[0][1] or '')):
            collectors.append({'kind': kind, 'key': key, 'label': COLLECTOR_LABELS.get(kind, kind), 'runs': j['runs'],
                               'success': j['success'], 'failure': j['failure'], 'skipped': j['skipped'], 'consecutive_failures': j['consecutive_failures'],
                               'running': j['running'] > 0, 'last_started': _iso(j['last_started']),
                               'last_finished': _iso(j['last_finished']), 'last_success': _iso(j['last_success']),
                               'last_failure': _iso(j['last_failure']), 'last_duration_ms': j['last_duration_ms'],
                               'last_items': j['last_items'], 'last_error': j['last_error'],
                               'state': 'running' if j['running'] else 'never' if not j['runs'] else
                               'failing' if j['consecutive_failures'] else 'ok'})
        heartbeats = {name: {'last': _iso(ts), 'lag_seconds': round(max(0.0, now - ts - interval), 1),
                             'healthy': now - ts <= interval + SCHEDULER_LAG_WARNING} for name, (ts, interval) in beats.items()}
        return {'collectors': collectors, 'heartbeats': heartbeats, 'errors': errors,
                'sse': {'clients': sse[0], 'total_since_start': sse[1]},
                'uptime_seconds': int(now - self.started_at), 'started_at': _iso(self.started_at)}


MONITOR = Monitor()


class _ErrorLog(logging.Handler):
    """Copie les WARNING/ERROR des journaux applicatifs dans le tampon (messages nettoyés)."""

    def emit(self, record):
        try:
            if record.levelno >= logging.WARNING and not record.name.startswith('uvicorn.access'):
                MONITOR.error(record.getMessage(), source=record.name)
        except Exception:  # noqa: BLE001
            pass


def sqlite_size(db_path):
    total, files = 0, {}
    for suffix in ('', '-wal', '-shm'):
        try:
            size = os.path.getsize(str(db_path) + suffix)
            files[suffix or 'db'] = size
            total += size
        except OSError:
            pass
    return {'bytes': total, 'files': files}


def _fresh(ts, now, budget=FRESH_SECONDS):
    try:
        observed = datetime.fromisoformat(str(ts))
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=timezone.utc)
        return 0 <= (now - observed).total_seconds() <= budget
    except (TypeError, ValueError):
        return False


def readiness(context, monitor=MONITOR):
    reasons = []
    try:
        with context.connect() as db:
            db.execute('SELECT 1').fetchone()
    except Exception:  # noqa: BLE001
        reasons.append('Base locale illisible')
    if getattr(context, 'lifespan_started', False):
        snap = monitor.snapshot()
        beat = snap['heartbeats'].get('scheduler')
        if not beat:
            # Pas encore de battement : démarrage (non prêt, mais pas une panne) ou planificateur bloqué.
            reasons.append('Démarrage en cours : planificateur pas encore actif' if snap['uptime_seconds'] < 15
                           else 'Planificateur arrêté (aucun battement)')
        elif not beat['healthy']:
            reasons.append('Planificateur en retard')
    return not reasons, reasons


def build(context, monitor=MONITOR):
    """Instantané complet ; aucune requête distante."""
    now = datetime.now(timezone.utc)
    snap = monitor.snapshot()
    # 1. OpsControl disponible
    try:
        with context.connect() as db:
            db.execute('SELECT 1').fetchone()
            journal = db.execute('PRAGMA journal_mode').fetchone()[0]
            try:
                import migrations
                schema = migrations.status(db)
            except Exception:  # noqa: BLE001
                schema = []
        database = {'status': 'ok', 'journal_mode': journal,
                    'migrations': {'applied': sum(1 for m in schema if m['applied_at']),
                                   'pending_core': [m['name'] for m in schema if m['core'] and not m['applied_at']]}}
    except Exception as exc:  # noqa: BLE001
        database = {'status': 'unavailable', 'error': clean(exc)}
    lifespan = getattr(context, 'lifespan_started', False)
    scheduler = snap['heartbeats'].get('scheduler') or {
        'healthy': not lifespan, 'last': None, 'lag_seconds': None,
        'note': 'Planificateur non démarré (instance sans cycle de vie)' if not lifespan else 'Aucun battement reçu'}
    process = {'status': 'ok', 'uptime_seconds': snap['uptime_seconds'], 'started_at': snap['started_at'],
               'database': database, 'database_size': sqlite_size(getattr(context, 'DB', '')),
               'scheduler': scheduler, 'single_instance': bool(getattr(context, 'instance_lock', None)),
               'sse': snap['sse']}
    try:  # tunnel Bacula local : requis seulement si une connexion l'utilise
        from run_infraops import port_open
        from management import BACULA_TUNNEL_URL
        required = any(c.get('url') == BACULA_TUNNEL_URL for c in context.api_connections())
        process['tunnel'] = {'required': required, 'open': port_open() if required else None}
    except Exception:  # noqa: BLE001
        process['tunnel'] = {'required': None, 'open': None}
    # 2. Collecteurs
    collectors = snap['collectors']
    info = getattr(context, 'incident_sync_info', None)
    if info:
        i = info()
        collectors.append({'kind': 'incidents', 'key': None, 'label': COLLECTOR_LABELS['incidents'],
                           'last_finished': i.get('at'), 'last_duration_ms': i.get('duration_ms'),
                           'last_error': clean(i['error']) if i.get('error') else None,
                           'state': 'failing' if i.get('error') else 'ok' if i.get('at') else 'never'})
    jobs = {}
    for name, attr in (('ssh', 'job'), ('network', 'net_job')):
        value = getattr(context, attr, None)
        if isinstance(value, dict):
            jobs[name] = {k: value.get(k) for k in ('running', 'completed', 'total')}
            jobs[name]['error'] = clean(value['error']) if value.get('error') else None
    if hasattr(context, 'batch_job'):
        b = context.batch_job()
        jobs['batch'] = {k: b.get(k) for k in ('running', 'completed', 'total')}
        jobs['batch']['error'] = clean(b['error']) if b.get('error') else None
    # 3. Sources distantes
    sources = []
    for c in context.api_connections():
        last = c.get('last_result') or {}
        prior = c.get('last_success_result') or {}
        observed = last.get('status') == 'observed'
        sources.append({'key': c.get('key'), 'name': c.get('name'), 'provider': c.get('provider'),
                        'reachable': True if observed else (False if last else None),
                        'last_attempt': last.get('collected_at'),
                        'last_success': last.get('collected_at') if observed else prior.get('collected_at'),
                        'fresh': bool(observed and _fresh(last.get('collected_at'), now)),
                        'error': clean(last.get('error')) if last.get('error') else None,
                        'error_kind': last.get('error_kind'), 'credentials_loaded': c.get('auth_configured')})
    # 4. Fraîcheur des données
    rows = context.rows()
    net = context.network_rows()
    freshness = {'hosts': len(rows),
                 'ssh_fresh': sum(1 for h in rows if _fresh(h.get('collected_at'), now)
                                  and not h.get('stale') and (h.get('coverage') or {}).get('measured', 0) > 0),
                 'ssh_measured': sum(1 for h in rows if (h.get('coverage') or {}).get('measured')),
                 # Une tentative échouée n'est pas un audit exploitable : conserver
                 # son compteur séparé pour que le SLO ne passe pas faussement au vert.
                 'ssh_attempted_24h': sum(1 for h in rows if _fresh(h.get('collected_at'), now, 86400)),
                 'ssh_24h': sum(1 for h in rows if _fresh(h.get('collected_at'), now, 86400)
                                and (h.get('coverage') or {}).get('measured', 0) > 0),
                 'ssh_complete_24h': sum(1 for h in rows if _fresh(h.get('collected_at'), now, 86400)
                                         and (h.get('coverage') or {}).get('total', 0) > 0
                                         and (h.get('coverage') or {}).get('measured', 0)
                                         == (h.get('coverage') or {}).get('total')),
                 'network_fresh': sum(1 for h in net if _fresh(h.get('collected_at'), now)),
                 'api_fresh': sum(s['fresh'] for s in sources), 'api_total': len(sources), 'budget_seconds': FRESH_SECONDS}
    ready, reasons = readiness(context, monitor)
    return {'generated_at': now.isoformat(), 'ready': ready, 'not_ready_reasons': reasons, 'opscontrol': process,
            'collectors': collectors, 'jobs': jobs, 'sources': sources, 'freshness': freshness, 'errors': snap['errors'],
            'scope': 'Mesures internes du processus OpsControl depuis son démarrage (remises à zéro au redémarrage) ; '
                     'états des sources lus dans les dernières collectes enregistrées.'}


def prometheus(data):
    lines, declared = [], set()

    def metric(name, value, help_text, labels=None, kind='gauge'):
        if value is None:
            return
        if name not in declared:
            declared.add(name)
            lines.extend([f'# HELP {name} {help_text}', f'# TYPE {name} {kind}'])
        label = ('{' + ','.join(f'{k}="{str(v).replace(chr(34), "")}"' for k, v in labels.items()) + '}') if labels else ''
        lines.append(f'{name}{label} {float(value):g}')
    metric('opscontrol_up', 1, 'Processus OpsControl disponible')
    metric('opscontrol_ready', int(data['ready']), 'Prêt à servir (base lisible, planificateur actif)')
    metric('opscontrol_uptime_seconds', data['opscontrol']['uptime_seconds'], 'Durée depuis le démarrage')
    metric('opscontrol_sqlite_bytes', data['opscontrol']['database_size']['bytes'], 'Taille de la base SQLite (WAL compris)')
    metric('opscontrol_sse_clients', data['opscontrol']['sse']['clients'], 'Connexions temps réel ouvertes')
    metric('opscontrol_scheduler_lag_seconds', data['opscontrol']['scheduler'].get('lag_seconds'), 'Retard du planificateur')
    for c in data['collectors']:
        labels = {'kind': c['kind'], 'key': c.get('key') or ''}
        metric('opscontrol_collector_runs_total', c.get('runs'), 'Exécutions de collecteur', labels, 'counter')
        metric('opscontrol_collector_failures_total', c.get('failure'), 'Échecs de collecteur', labels, 'counter')
        if c.get('last_duration_ms') is not None:
            metric('opscontrol_collector_duration_seconds', c['last_duration_ms'] / 1000, 'Durée de la dernière exécution', labels)
    for s in data['sources']:
        labels = {'provider': s['provider'], 'key': s['key']}
        metric('opscontrol_source_reachable', None if s['reachable'] is None else int(s['reachable']), 'Dernière lecture API réussie', labels)
        metric('opscontrol_source_fresh', int(s['fresh']), 'Lecture API réussie de moins de 15 min', labels)
    f = data['freshness']
    metric('opscontrol_hosts', f['hosts'], 'Serveurs en inventaire')
    metric('opscontrol_hosts_ssh_fresh', f['ssh_fresh'], 'Serveurs avec audit SSH récent')
    metric('opscontrol_hosts_network_fresh', f['network_fresh'], 'Serveurs avec sonde réseau récente')
    metric('opscontrol_hosts_ssh_24h', f.get('ssh_24h'), 'Serveurs avec au moins un contrôle SSH renseigné depuis moins de 24 h (SLO)')
    metric('opscontrol_hosts_ssh_attempted_24h', f.get('ssh_attempted_24h'), 'Serveurs avec tentative SSH depuis moins de 24 h')
    metric('opscontrol_hosts_ssh_complete_24h', f.get('ssh_complete_24h'), 'Serveurs avec tous les contrôles SSH renseignés depuis moins de 24 h')
    import http_metrics  # latence, volumes et erreurs HTTP (SLO)
    lines.extend(http_metrics.HTTP.prometheus())
    return '\n'.join(lines) + '\n'


def install(app, context):
    from fastapi import APIRouter
    router = APIRouter()
    from fastapi import HTTPException
    from fastapi.responses import JSONResponse, PlainTextResponse

    if not any(isinstance(h, _ErrorLog) for h in logging.getLogger().handlers):
        logging.getLogger().addHandler(_ErrorLog())

    original = getattr(context, 'collect_api_connection', None)
    if original is not None and not getattr(original, '_observed', False):
        def observed(key, *args, **kwargs):
            item = next((c for c in context.api_connections() if c.get('key') == key), {})
            label = f"{item.get('provider', '?')}:{key}"
            started = MONITOR.begin('api', label)
            try:
                result = original(key, *args, **kwargs)
            except Exception as exc:
                MONITOR.end('api', False, label, getattr(exc, 'detail', None) or type(exc).__name__, started)
                raise
            if isinstance(result, dict) and result.get('status') == 'busy':
                MONITOR.skip('api', label)  # collecte identique déjà en cours : pas un échec
                return result
            ok = isinstance(result, dict) and result.get('status') == 'observed'
            MONITOR.end('api', ok, label, None if ok else (result or {}).get('error'), started)
            return result
        observed._observed = True
        context.collect_api_connection = observed

    @router.get('/health/live')
    def live():
        return {'status': 'ok', 'uptime_seconds': MONITOR.snapshot()['uptime_seconds']}

    @router.get('/health/ready')
    def ready():
        ok, reasons = readiness(context)
        return JSONResponse({'status': 'ready' if ok else 'not_ready', 'reasons': reasons}, status_code=200 if ok else 503)

    @router.get('/api/self-monitoring')
    def self_monitoring():
        return build(context)

    @router.get('/api/metrics')
    def metrics():
        if os.environ.get('INFRAOPS_METRICS') != '1':
            raise HTTPException(404, 'Métriques Prometheus désactivées (INFRAOPS_METRICS=1 pour les activer).')
        return PlainTextResponse(prometheus(build(context)), media_type='text/plain; version=0.0.4')
    app.include_router(router)  # routes de ce module : APIRouter, inclus en fin d'installation


# --------------------------------------------------------------------------- instance unique
def acquire_instance_lock(path):
    """Verrou exclusif du fichier : un seul processus OpsControl par base.

    Les tâches, verrous et planificateurs vivent en mémoire : deux processus
    (plusieurs workers uvicorn, deux lancements) dupliqueraient toutes les
    collectes et se marcheraient dessus. Renvoie le descripteur à conserver ouvert.
    """
    handle = open(path, 'a+')
    try:
        if os.name == 'nt':
            import msvcrt
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        raise RuntimeError('Une autre instance OpsControl utilise déjà cette base ('
                           + os.path.basename(str(path)) + ') : un seul processus est autorisé '
                           '(tâches et planificateur en mémoire). Arrêter l’autre instance ou utiliser --workers 1.') from None
    return handle


def release_instance_lock(handle):
    if handle is None:
        return
    try:
        if os.name == 'nt':
            import msvcrt
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    except OSError:
        pass
    handle.close()
