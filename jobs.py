"""Collectes en tâche de fond et planificateur d'OpsControl (extraits d'app.py, lot J60-J90).

Le module ne garde AUCUN état : l'état des tâches (job, net_job, monitor…), les verrous,
la base (connect), l'inventaire (HOSTS) et les fonctions des autres modules vivent dans le
module app, passé ici comme contexte (bind). Chaque fonction lit le contexte AU MOMENT DE
L'APPEL : un remplacement dans app (tests : app.collect, app.launch, app.job…) est vu,
exactement comme avant l'extraction. app réexporte ces fonctions sous leurs noms
historiques ; le contrat de contexte (app_context.CONTRACT) est inchangé.

Aucune collecte n'écrit sur un serveur supervisé : seules la base locale et l'état en
mémoire sont mis à jour.
"""
import json
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

ctx = None
# Fils producteurs (collectes, rétention, planificateur, boucles de fond) : l'arrêt les
# attend avant de rendre le verrou d'instance. Sans ce registre, une collecte lente
# écrivait encore après la fin du lifespan, pendant qu'une nouvelle instance démarrait
# sur la même base (OC-AUDIT-013).
_producers = set()
_producers_lock = threading.Lock()


def bind(context):
    global ctx
    ctx = context


def spawn(target, args=(), name=None):
    """Démarre un fil producteur enregistré ; il se retire du registre en terminant."""
    def run():
        try:
            target(*args)
        finally:
            with _producers_lock:
                _producers.discard(threading.current_thread())
    thread = threading.Thread(target=run, name=name, daemon=True)
    with _producers_lock:
        _producers.add(thread)
    try:
        thread.start()
    except BaseException:
        with _producers_lock:
            _producers.discard(thread)
        raise
    return thread


def drain(timeout):
    """Attend la fin des producteurs pendant `timeout` secondes au plus ; noms des restants."""
    end = time.monotonic() + max(0.0, timeout)
    while True:
        with _producers_lock:
            alive = [t for t in _producers if t.is_alive() and t is not threading.current_thread()]
        left = end - time.monotonic()
        if not alive or left <= 0:
            return sorted(t.name for t in alive)
        alive[0].join(min(left, 0.5))


def _waf_summary(waf):
    sections = waf.get('sections', {})
    summary = {name: sections.get(section, {}).get('data', {}).get(field) for name, section, field in [
        ('banned', 'fail2ban', 'currently_banned'), ('requests', 'traffic', 'requests'),
        ('errors_5xx_pct', 'traffic', 'errors_5xx_pct'), ('alerts', 'modsecurity', 'alert_lines'),
        ('close_wait', 'sockets', 'close_wait_total'), ('close_wait_outbound', 'sockets', 'close_wait_outbound'),
        ('established', 'sockets', 'states')]}
    if isinstance(summary.get('established'), dict):
        summary['established'] = summary['established'].get('ESTAB')
    return summary


def refresh(selected, requester):
    """Audit `selected` hosts concurrently (up to WORKERS at a time) and persist
    each result plus a trimmed (20-entry) history. Runs in its own thread,
    started by `launch`; `job` is the only channel back to the API/UI."""
    c = ctx
    started = c.MONITOR.begin('ssh')
    failed, lost = None, []
    try:
        with ThreadPoolExecutor(max_workers=c.WORKERS) as pool:
            futures = {pool.submit(c.collect, h, c.cfg, requester): h for h in selected}
            for future in as_completed(futures):
                h = futures[future]
                try:
                    result = c.sanitize(future.result())
                except Exception as exc:
                    result = {'status': 'unknown', 'issues': ['Erreur locale : ' + c.redact(exc)], 'checks': [],
                              'findings': [], 'collected_at': datetime.now(timezone.utc).isoformat(),
                              'coverage': {'measured': 0, 'total': 15}}
                # Un enregistrement en échec (base occupée, réponse WAF malformée) ne coûte plus
                # que CE serveur : avant, il abandonnait les résultats de tout le lot (audit BE-05).
                if not _persist_host(c, h, result, _store_audit):
                    lost.append(h.get('name') or h['key'])
                with c.lock:
                    c.job['completed'] += 1
        if lost:
            failed = f'{len(lost)} serveur(s) non enregistré(s) : ' + ', '.join(lost[:10])
            with c.lock:
                c.job['error'] = failed
        c.enroll_assets()
        c.collection_done('ssh')
    except Exception as exc:
        failed = c.redact(exc)
        with c.lock:
            c.job['error'] = failed
    finally:
        with c.lock:
            c.job['running'] = False
        c.MONITOR.end('ssh', failed is None, error=failed, started=started, items=len(selected))


def _superseded(c, h, access_only):
    """Serveur retiré ou reconfiguré pendant le lot : son résultat, obtenu avec l'ancienne
    configuration, n'est pas enregistré. Les ajouts et modifications ne sont plus refusés
    pendant une collecte ; c'est ici, à la fin de chaque mesure, qu'ils prennent effet."""
    inventory = getattr(c, 'HOSTS', None)
    if inventory is None:  # contexte sans inventaire (outils, tests unitaires) : rien à comparer
        return False
    current = next((x for x in inventory if x.get('key') == h.get('key')), None)
    if current is None:
        return True
    return access_only and any(current.get(k) != h.get(k) for k in ('ip', 'port', 'user', 'collect_enabled'))


def _persist_host(c, h, result, store):
    """Enregistre un résultat ; une seule nouvelle tentative si la base est occupée."""
    # Audit SSH : le résultat d'une configuration modifiée reste enregistré, avec
    # l'empreinte de la configuration utilisée (affiché « configuration modifiée »).
    # Disponibilité réseau : remplacée sous 60 s, on ne garde pas une mesure d'un ancien port.
    if _superseded(c, h, access_only=store is _store_network):
        return True
    for attempt in (1, 2):
        try:
            store(c, h, result)
            return True
        except sqlite3.OperationalError as exc:
            if attempt == 1 and 'locked' in str(exc).lower():
                time.sleep(1)
                continue
            c.MONITOR.error(f"Enregistrement de {h['key']} : " + c.redact(exc), source='collecte')
        except Exception as exc:
            c.MONITOR.error(f"Enregistrement de {h['key']} : " + c.redact(exc), source='collecte')
        return False
    return False


def _store_audit(c, h, result):
    result['fingerprint'] = c.fingerprint(h)
    if result.get('waf'):
        try:
            import apache_health
            apache_health.record(c.connect, h['key'], result['waf'])
        except Exception as exc:
            result['waf']['apache_health_error'] = c.redact(exc)
        try:
            # Transaction séparée : l'historique des bans ne doit jamais empêcher
            # l'enregistrement de l'audit lui-même (audit WAF-01).
            import waf_bans
            with c.connect() as db:
                waf_bans.observe(db, h['key'], h['ip'], result['waf'])
        except Exception as exc:
            result['waf']['ban_history_error'] = c.redact(exc)
    summary = {'issues': result['issues'], 'coverage': result.get('coverage', {}),
               'findings_count': len(result.get('findings', []))}
    if result.get('waf'):
        summary['waf'] = _waf_summary(result['waf'])
    with c.connect() as db:
        previous = db.execute('SELECT ip,payload FROM states WHERE key=?', (h['key'],)).fetchone()
        retained = c.retain_attempt(result, json.loads(previous[1]) if previous and previous[0] == h['ip'] else None)
        db.execute('INSERT OR REPLACE INTO states(key, ip, payload) VALUES(?,?,?)', (h['key'], h['ip'], json.dumps(retained)))
        db.execute('INSERT OR REPLACE INTO audit_snapshots(key, ts, payload) VALUES(?,?,?)',
                   (h['key'], result['collected_at'], json.dumps(result)))
        # Rétention : les 20 derniers audits, plus UN par heure sur 7 jours. Avec un
        # réaudit toutes les 10 min, 20 audits ne couvraient que 3 h : trop peu pour
        # la tendance de remplissage des disques (alert_policy exige 12 h).
        cutoff = (datetime.now(timezone.utc) - timedelta(days=c.SNAPSHOT_DAYS)).isoformat()
        db.execute('DELETE FROM audit_snapshots WHERE key=? AND ts NOT IN (SELECT ts FROM audit_snapshots '
                   'WHERE key=? ORDER BY ts DESC LIMIT 20) AND (ts<? OR ts NOT IN (SELECT min(ts) FROM '
                   'audit_snapshots WHERE key=? GROUP BY substr(ts,1,13)))', (h['key'], h['key'], cutoff, h['key']))
        db.execute('INSERT INTO history(key,ts,status,summary) VALUES(?,?,?,?)',
                   (h['key'], result['collected_at'], result['status'], json.dumps(summary)))
        db.execute('DELETE FROM history WHERE key=? AND id NOT IN (SELECT id FROM history WHERE key=? '
                   'ORDER BY id DESC LIMIT 100)', (h['key'], h['key']))


def _store_network(c, h, result):
    with c.connect() as db:
        db.execute('INSERT OR REPLACE INTO network(key, ip, payload) VALUES(?,?,?)', (h['key'], h['ip'], json.dumps(result)))


def collection_done(kind):
    """Rappels après collecte (rapprochement des incidents…) : les routes GET ne déclenchent
    plus d'écriture, ce sont les collectes qui font avancer l'état dérivé."""
    for hook in list(ctx.collection_hooks):
        try:
            hook(kind)
        except Exception as exc:
            ctx.MONITOR.error('Rappel après collecte ' + kind + ' : ' + ctx.redact(exc), source='collecte')


def enroll_assets():
    """Inscription durable après une collecte : les routes GET n'écrivent plus (asset_registry.annotate)."""
    from synchronization import federate
    from asset_registry import enroll
    assets = federate(ctx.rows(), ctx.api_connections(), ctx.network_rows())['assets']
    with ctx.connect() as db:
        enroll(db, assets)


def launch(selected, requester, scope):
    """Start `refresh` in a background thread unless one is already running for
    this job (batches never overlap); returns the (possibly already-running) job state."""
    c = ctx
    # Copie figée : le lot garde la configuration de son départ, même si l'inventaire est
    # modifié pendant son exécution (enregistrement accepté pendant une collecte).
    selected = [dict(h) for h in selected]
    with c.lock:
        if c.job['running']:
            return dict(c.job)
        c.job.update(running=True, completed=0, total=len(selected), error=None, scope=scope,
                     started_at=datetime.now(timezone.utc).isoformat())
        spawn(c.refresh, (selected, requester), 'collecte-ssh')
        return dict(c.job)


def refresh_network(selected, requester):
    c = ctx
    started = c.MONITOR.begin('network')
    failed, lost = None, []
    try:
        with ThreadPoolExecutor(max_workers=c.WORKERS) as pool:
            futures = {pool.submit(c.collect_network, h, c.cfg): h for h in selected}
            for future in as_completed(futures):
                h = futures[future]
                try:
                    result = c.sanitize(future.result())
                except Exception as exc:
                    result = {'collected_at': datetime.now(timezone.utc).isoformat(), 'ping': None, 'ports': [],
                              'ssh_key_known': None, 'error': c.redact(exc)}
                if not _persist_host(c, h, result, _store_network):
                    lost.append(h.get('name') or h['key'])
                with c.net_lock:
                    c.net_job['completed'] += 1
        if lost:
            failed = f'{len(lost)} serveur(s) non enregistré(s) : ' + ', '.join(lost[:10])
            with c.net_lock:
                c.net_job['error'] = failed
        c.enroll_assets()
        c.collection_done('network')
    except Exception as exc:
        failed = c.redact(exc)
        with c.net_lock:
            c.net_job['error'] = failed
    finally:
        with c.net_lock:
            c.net_job['running'] = False
        c.MONITOR.end('network', failed is None, error=failed, started=started, items=len(selected))


def launch_network(selected, requester):
    c = ctx
    selected = [dict(h) for h in selected]  # copie figée, comme launch
    with c.net_lock:
        if c.net_job['running']:
            return dict(c.net_job)
        c.net_job.update(running=True, completed=0, total=len(selected), error=None)
        spawn(c.refresh_network, (selected, requester), 'collecte-reseau')
        return dict(c.net_job)


def run_retention():
    """Purge locale bornée (retention.py), suivie comme un collecteur dans la santé d'OpsControl."""
    import retention
    c = ctx
    with c.MONITOR.track('retention') as outcome:
        with c.connect() as db:
            counts = retention.sweep(db, [h['key'] for h in c.HOSTS], slim=False)
        # Allègement à part, par lots courts : les collectes s'intercalent entre deux lots (audit DB-03).
        counts['audit_snapshots_slimmed'] = retention.slim_in_batches(c.connect)
        # Espace libéré rendu au disque (sans effet tant que maintenance.py vacuum n'a pas activé le mode incrémental).
        with c.connect() as db:
            counts['free_pages_left'] = retention.reclaim(db)
        outcome['items'] = sum(v for k, v in counts.items() if k != 'free_pages_left')
        c.retention_last_counts.clear()
        c.retention_last_counts.update(counts)
    return counts


def scheduler():
    """Fil de fond démarré avec l'application, déclenché à chaque intervalle.

    Il n'audite PAS tout le parc en SSH : seulement les hôtes nouvellement
    découverts (initial_audit_hosts). Les audits existants sont conservés, et
    leur réactualisation reste une action explicite de l'opérateur — 87 sessions
    SSH périodiques sont une charge qu'on ne s'impose pas sans le décider.
    Disponibilité réseau, sources API et traitements sont, eux, rafraîchis ici."""
    c = ctx
    while not c.stop.wait(1):
        c.MONITOR.heartbeat('scheduler')
        with c.lock:
            critical_enabled = bool(c.monitor['interval'])
            due = c.monitor['interval'] and c.monitor['next_at'] and time.time() >= c.monitor['next_at']
            if due:
                c.monitor['next_at'] = time.time() + c.monitor['interval']
        _guarded('voie critique', c.critical_tick, critical_enabled)
        # Voie rapide : toujours active, indépendante de l'intervalle choisi.
        if hasattr(c, 'tier0_tick'):
            _guarded('voie rapide', c.tier0_tick)
        # Contrôle de démarrage (startup_check.py) : un passage unique, même en mode manuel,
        # pour que les alertes critiques soient récentes quand on ouvre l'interface.
        if hasattr(c, 'startup_tick'):
            _guarded('contrôle de démarrage', c.startup_tick)
        # Réaudit SSH en rotation (ssh_refresh.py) : réglage distinct, désactivé par défaut.
        if hasattr(c, 'ssh_refresh_tick'):
            _guarded('rotation SSH', c.ssh_refresh_tick)
        # Sécurité (security_cve.py) : veille et relevé des paquets, chacun désactivé par défaut.
        if hasattr(c, 'security_tick'):
            _guarded('sécurité', c.security_tick)
        if due:
            _guarded('découverte', _discover_and_audit)
            _guarded('collecte réseau', c.launch_network, c.HOSTS, 'monitoring-local')
            _guarded('sources API', c.launch_api_sync)
            # Inventaire batch : 87 connexions SSH par passage, pour des planifications qui
            # changent rarement. Relancé chaque minute (intervalle 60 s), il occupait le
            # bastion en continu et, avec la rotation SSH, provoquait des « banner exchange
            # timeout » (constaté le 26/09). Au plus toutes les 30 min ; le bouton reste immédiat.
            if time.time() - c.batch_last[0] >= c.BATCH_EVERY:
                c.batch_last[0] = time.time()
                _guarded('traitements batch', c.launch_batches)
        if time.time() - c.retention_last[0] >= c.RETENTION_EVERY:
            c.retention_last[0] = time.time()
            _guarded('rétention', launch_retention)


def _guarded(step, function, *args):
    """Exécute une étape du planificateur sans jamais le laisser mourir.

    Le planificateur est l'unique moteur des collectes automatiques : une seule exception
    non rattrapée arrêtait tout (réseau, API, voie rapide, rétention) alors que le
    processus restait vivant — systemd ne pouvait donc pas le relancer (audit BE-01).
    L'erreur reste visible dans la santé d'OpsControl."""
    try:
        return function(*args)
    except Exception as exc:
        ctx.MONITOR.error(f'Planificateur, étape « {step} » : ' + ctx.redact(exc), source='planificateur')
        return None


def _discover_and_audit():
    from asset_registry import discover, initial_audit_hosts
    c = ctx
    additions, _ = discover(c.HOSTS, c.api_connections())
    if additions:
        c.add_discovered_hosts(additions)
    selected = initial_audit_hosts(c.rows())
    if selected:
        c.launch(selected, 'audit-initial', 'nouveaux')


# Seul état propre au module : empêcher deux purges simultanées si l'une dépasse l'heure.
_retention_running = threading.Lock()


def launch_retention():
    """Rétention dans son propre fil : allégée de plusieurs milliers d'audits, elle pouvait
    occuper le planificateur assez longtemps pour suspendre la voie rapide et faire
    échouer /health/ready (audit BE-02)."""
    if not _retention_running.acquire(blocking=False):
        return False

    def run():
        try:
            ctx.run_retention()
        except Exception as exc:
            # Déjà comptée en échec par MONITOR.track ; on garde la cause lisible.
            ctx.MONITOR.error('Rétention : ' + ctx.redact(exc), source='planificateur')
        finally:
            _retention_running.release()
    spawn(run, name='retention')
    return True
