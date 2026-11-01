"""Short Zabbix cycle, independent of SSH audits and slow source batches."""
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor

INTERVAL_SECONDS = 10


def install(context):
    guard = threading.Lock()
    state = {'running': False, 'completed': 0, 'total': 0, 'error': None}
    next_at = 0.0

    def run(keys):
        def collect(key):
            try:
                result = context.collect_api_connection(key)
                error = result.get('error')
            except Exception:
                logging.getLogger('opscontrol.critical').exception('Collecte rapide Zabbix %s en échec', key)
                error = 'Collecte rapide Zabbix indisponible ; consulter la source.'
            with guard:
                state['completed'] += 1
                if error:
                    state['error'] = error
        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                list(pool.map(collect, keys))
        finally:
            with guard:
                state['running'] = False

    def tick(enabled, now=None):
        nonlocal next_at
        now = time.monotonic() if now is None else now
        with guard:
            if not enabled:
                next_at = 0.0
                return
            if state['running'] or now < next_at:
                return
            next_at = now + INTERVAL_SECONDS
            try:
                keys = [c['key'] for c in context.api_connections()
                        if c.get('provider') == 'Zabbix' and c.get('auth_configured') is not False]
            except Exception:
                logging.getLogger('opscontrol.critical').exception('Liste des sources Zabbix illisible')
                state['error'] = 'Configuration des sources indisponible.'
                return
            if not keys:
                return
            state.update(running=True, completed=0, total=len(keys), error=None)
            threading.Thread(target=run, args=(keys,), daemon=True, name='critical-zabbix').start()

    def snapshot():
        with guard:
            return {**state, 'interval': INTERVAL_SECONDS}

    context.critical_tick = tick
    context.critical_job = snapshot
