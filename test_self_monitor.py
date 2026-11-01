"""Lot 2 : supervision d'OpsControl, WAL, GET sans écriture, instance unique."""
import testing_env  # noqa: F401 — base temporaire AVANT tout import d'app (testing_env.py)
import contextlib
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault('INFRAOPS_INCIDENT_SYNC', '0')

import asset_registry
import self_monitor as sm
from test_access_policy import call, proxy, SECRET

WRITES = ('INSERT', 'UPDATE', 'DELETE', 'REPLACE', 'CREATE', 'DROP', 'ALTER')


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.m = sm.Monitor(self.clock)

    def test_success_then_failures_are_counted_and_durations_measured(self):
        with self.m.track('api', 'Zabbix:z1') as outcome:
            self.clock.now += 2.5
            outcome['items'] = 12
        for _ in range(2):
            started = self.m.begin('api', 'Zabbix:z1')
            self.clock.now += 1
            self.m.end('api', False, 'Zabbix:z1', 'HTTP 503', started)
        c = self.m.snapshot()['collectors'][0]
        self.assertEqual((c['runs'], c['success'], c['failure'], c['consecutive_failures']), (3, 1, 2, 2))
        self.assertEqual(c['state'], 'failing')
        self.assertEqual(c['last_duration_ms'], 1000)
        self.assertEqual(c['last_items'], 12)
        self.assertIsNotNone(c['last_success'])
        self.assertEqual(self.m.snapshot()['errors'][0]['source'], 'api')

    def test_exception_in_tracked_block_is_a_failure_and_propagates(self):
        with self.assertRaises(ValueError):
            with self.m.track('ssh'):
                raise ValueError('boom')
        c = self.m.snapshot()['collectors'][0]
        self.assertEqual((c['failure'], c['state']), (1, 'failing'))

    def test_busy_skip_is_neither_success_nor_failure(self):
        self.m.begin('api', 'Zabbix:z1')
        self.m.skip('api', 'Zabbix:z1')
        c = self.m.snapshot()['collectors'][0]
        self.assertEqual((c['runs'], c['failure'], c['skipped'], c['state']), (0, 0, 1, 'never'))
        self.assertEqual(self.m.snapshot()['errors'], [])

    def test_never_run_collector_is_not_ok(self):
        self.m.begin('network')
        self.assertEqual(self.m.snapshot()['collectors'][0]['state'], 'running')

    def test_scheduler_lag_detected(self):
        self.m.heartbeat('scheduler')
        self.clock.now += 0.5
        self.assertTrue(self.m.snapshot()['heartbeats']['scheduler']['healthy'])
        self.clock.now += 60
        beat = self.m.snapshot()['heartbeats']['scheduler']
        self.assertFalse(beat['healthy'])
        self.assertGreater(beat['lag_seconds'], 50)

    def test_sse_counter_never_negative(self):
        self.m.sse_open(); self.m.sse_open(); self.m.sse_close(); self.m.sse_close(); self.m.sse_close()
        self.assertEqual(self.m.snapshot()['sse'], {'clients': 0, 'total_since_start': 2})

    def test_errors_are_cleaned_of_secrets_and_paths(self):
        self.m.error(r'échec password=Sup3rS3cret! dans C:\Users\admin\infraops\data\state.sqlite3 et /opt/infraops/secrets.env')
        message = self.m.snapshot()['errors'][0]['message']
        for leak in ('Sup3rS3cret', 'C:\\Users', '/opt/infraops', 'secrets.env'):
            self.assertNotIn(leak, message)
        self.assertIn('[chemin]', message)

    def test_error_buffer_bounded(self):
        for i in range(sm.ERROR_BUFFER + 20):
            self.m.error(f'e{i}')
        errors = self.m.snapshot()['errors']
        self.assertEqual(len(errors), sm.ERROR_BUFFER)
        self.assertEqual(errors[0]['message'], f'e{sm.ERROR_BUFFER + 19}')


def fake_context(db_path, connections, lifespan=False, hosts=None, network=None):
    @contextlib.contextmanager
    def connect():
        db = sqlite3.connect(db_path)
        try:
            with db:
                yield db
        finally:
            db.close()
    return SimpleNamespace(connect=connect, DB=Path(db_path), api_connections=lambda: connections,
                           rows=lambda: hosts or [], network_rows=lambda: network or [], lifespan_started=lifespan,
                           job={'running': False, 'completed': 3, 'total': 3, 'error': None},
                           net_job={'running': True, 'completed': 1, 'total': 4, 'error': r'échec C:\secret\path'})


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = os.path.join(self.tmp.name, 'state.sqlite3')
        sqlite3.connect(self.db).close()
        now = datetime.now(timezone.utc)
        self.connections = [
            {'key': 'z', 'name': 'Zabbix', 'provider': 'Zabbix', 'auth_configured': True,
             'last_result': {'status': 'observed', 'collected_at': now.isoformat()}},
            {'key': 'w', 'name': 'Wazuh', 'provider': 'Wazuh', 'auth_configured': True,
             'last_result': {'status': 'unknown', 'collected_at': now.isoformat(), 'error': 'token=abcdef123456 refusé'},
             'last_success_result': {'collected_at': (now - timedelta(days=2)).isoformat()}},
            {'key': 'b', 'name': 'Bacula', 'provider': 'Bacula', 'auth_configured': False},  # jamais collectée
            {'key': 'e', 'name': 'Elastic', 'provider': 'Elasticsearch', 'auth_configured': True,
             'last_result': {'status': 'observed', 'collected_at': (now - timedelta(hours=3)).isoformat()}},
        ]

    def tearDown(self):
        self.tmp.cleanup()

    def test_sources_absent_failed_or_old_are_never_ok(self):
        data = sm.build(fake_context(self.db, self.connections), sm.Monitor())
        src = {s['key']: s for s in data['sources']}
        self.assertEqual((src['z']['reachable'], src['z']['fresh']), (True, True))
        self.assertEqual((src['w']['reachable'], src['w']['fresh']), (False, False))
        self.assertIsNotNone(src['w']['last_success'], 'dernière réussite conservée, avec sa date d’origine')
        self.assertEqual((src['b']['reachable'], src['b']['fresh']), (None, False), 'source jamais lue : inconnue, pas OK')
        self.assertEqual((src['e']['reachable'], src['e']['fresh']), (True, False), 'lecture ancienne : pas fraîche')
        self.assertEqual(data['freshness']['api_fresh'], 1)

    def test_payload_has_no_secret_nor_local_path(self):
        monitor = sm.Monitor()
        monitor.error(r'lecture impossible C:\Users\localadmin\x\hosts.yaml')
        text = json.dumps(sm.build(fake_context(self.db, self.connections), monitor))
        for leak in ('abcdef123456', 'localadmin', self.tmp.name, 'C:\\\\secret', 'hosts.yaml'):
            self.assertNotIn(leak, text)

    def test_attempt_is_not_a_measured_audit_and_partial_is_not_complete(self):
        now = datetime.now(timezone.utc)
        recent = now.isoformat()
        hosts = [
            {'collected_at': recent, 'coverage': {'measured': 0, 'total': 15}},
            {'collected_at': recent, 'coverage': {'measured': 3, 'total': 15}},
            {'collected_at': recent, 'coverage': {'measured': 15, 'total': 15}},
            {'collected_at': recent},
            {'collected_at': (now-timedelta(days=2)).isoformat(), 'coverage': {'measured': 15, 'total': 15}},
            {'collected_at': (now+timedelta(hours=1)).isoformat(), 'coverage': {'measured': 15, 'total': 15}},
        ]
        data = sm.build(fake_context(self.db, [], hosts=hosts), sm.Monitor())
        f = data['freshness']
        self.assertEqual((f['ssh_attempted_24h'], f['ssh_24h'], f['ssh_complete_24h']), (4, 2, 1))
        self.assertEqual(f['ssh_fresh'], 2)
        text = sm.prometheus(data)
        self.assertIn('opscontrol_hosts_ssh_attempted_24h 4', text)
        self.assertIn('opscontrol_hosts_ssh_complete_24h 1', text)

    def test_without_lifespan_scheduler_not_required(self):
        ok, reasons = sm.readiness(fake_context(self.db, []), sm.Monitor())
        self.assertTrue(ok, reasons)

    def test_ready_fails_when_scheduler_silent(self):
        clock = Clock(); monitor = sm.Monitor(clock)
        ok, reasons = sm.readiness(fake_context(self.db, [], lifespan=True), monitor)
        self.assertFalse(ok)
        self.assertEqual(reasons, ['Démarrage en cours : planificateur pas encore actif'])
        clock.now += 30
        self.assertEqual(sm.readiness(fake_context(self.db, [], lifespan=True), monitor)[1], ['Planificateur arrêté (aucun battement)'])
        monitor.heartbeat('scheduler')
        self.assertTrue(sm.readiness(fake_context(self.db, [], lifespan=True), monitor)[0])
        clock.now += 120
        self.assertFalse(sm.readiness(fake_context(self.db, [], lifespan=True), monitor)[0])

    def test_ready_fails_when_database_unreadable(self):
        ctx = fake_context(os.path.join(self.tmp.name, 'absent', 'x.sqlite3'), [])
        ok, reasons = sm.readiness(ctx, sm.Monitor())
        self.assertFalse(ok)
        self.assertIn('Base locale illisible', reasons)

    def test_prometheus_exposition_format(self):
        text = sm.prometheus(sm.build(fake_context(self.db, self.connections), sm.Monitor()))
        self.assertIn('# TYPE opscontrol_up gauge\nopscontrol_up 1', text)
        self.assertIn('opscontrol_source_reachable{provider="Zabbix",key="z"} 1', text)
        self.assertNotIn('opscontrol_source_reachable{provider="Bacula"', text, 'inconnu : pas de valeur inventée')
        for line in text.strip().splitlines():
            # Valeurs d'étiquette entre guillemets : peuvent contenir des accolades (route="/api/hosts/{key}").
            self.assertRegex(line, r'^(# (HELP|TYPE) \w+ .+|\w+(\{(\w+="[^"]*",?)*\})? (-?[\d.e+-]+|\+Inf))$')


class InstanceLockTests(unittest.TestCase):
    def test_second_instance_refused_then_allowed_after_release(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            path = os.path.join(tmp, 'state.sqlite3.lock')
            first = sm.acquire_instance_lock(path)
            with self.assertRaises(RuntimeError) as caught:
                sm.acquire_instance_lock(path)
            self.assertIn('autre instance', str(caught.exception))
            self.assertNotIn(tmp, str(caught.exception), 'message sans chemin complet')
            sm.release_instance_lock(first)
            sm.release_instance_lock(sm.acquire_instance_lock(path))


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.trace = []
        self.db.set_trace_callback(self.trace.append)

    def tearDown(self):
        self.db.close()

    def writes(self):
        return [s for s in self.trace if s.lstrip().upper().startswith(WRITES)]

    def test_annotate_never_writes_even_without_table(self):
        hosts = [{'key': 'a', 'ip': '192.0.2.1', 'active_scope': True}, {'key': 'b', 'ip': '192.0.2.2'}]
        asset_registry.annotate(self.db, hosts)
        self.assertEqual(self.writes(), [])
        self.assertEqual([(h['registered'], h['registered_at']) for h in hosts], [(True, None), (False, None)])

    def test_enroll_persists_and_annotate_reads_date(self):
        asset_registry.enroll(self.db, [{'key': 'a', 'ip': '192.0.2.1', 'active_scope': True}])
        self.trace.clear()
        hosts = [{'key': 'a', 'ip': '192.0.2.1'}, {'key': 'a2', 'ip': '192.0.2.9'}]
        asset_registry.annotate(self.db, hosts)
        self.assertEqual(self.writes(), [])
        self.assertTrue(hosts[0]['registered'])
        self.assertIsNotNone(hosts[0]['registered_at'])
        self.assertFalse(hosts[1]['registered'])

    def test_annotate_ip_change_not_recorded_registration(self):
        asset_registry.enroll(self.db, [{'key': 'a', 'ip': '192.0.2.1', 'active_scope': True}])
        hosts = [{'key': 'a', 'ip': '192.0.2.77'}]
        asset_registry.annotate(self.db, hosts)
        self.assertEqual((hosts[0]['registered'], hosts[0]['registered_at']), (False, None))


class WalConcurrencyTests(unittest.TestCase):
    def test_four_writers_and_reader_without_lock_error(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            path = os.path.join(tmp, 'c.sqlite3')
            db = sqlite3.connect(path)
            self.assertEqual(db.execute('PRAGMA journal_mode=WAL').fetchone()[0], 'wal')
            db.execute('CREATE TABLE t(id INTEGER PRIMARY KEY, w INT, payload TEXT)')
            db.commit(); db.close()
            errors, reads, stop = [], [], threading.Event()

            def writer(n):
                try:
                    for i in range(50):
                        c = sqlite3.connect(path, timeout=30)
                        c.execute('PRAGMA synchronous=NORMAL')
                        with c:
                            c.execute('INSERT INTO t(w,payload) VALUES(?,?)', (n, 'x' * 2000))
                        c.close()
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc)

            def reader():
                while not stop.is_set():
                    # Même délai d'attente que l'application (connect(), timeout=30) : sous forte charge,
                    # un point de contrôle WAL peut dépasser 1 s (échec intermittent constaté).
                    c = sqlite3.connect(path, timeout=30)
                    try:
                        reads.append(c.execute('SELECT count(*) FROM t').fetchone()[0])
                    except Exception as exc:  # noqa: BLE001
                        errors.append(exc)
                    finally:
                        c.close()
            r = threading.Thread(target=reader); r.start()
            threads = [threading.Thread(target=writer, args=(n,)) for n in range(4)]
            [t.start() for t in threads]; [t.join() for t in threads]
            stop.set(); r.join()
            self.assertEqual(errors, [])
            c = sqlite3.connect(path)
            self.assertEqual(c.execute('SELECT count(*) FROM t').fetchone()[0], 200)
            c.close()
            self.assertTrue(reads and reads == sorted(reads), 'lectures cohérentes pendant les écritures')


class RealAppTests(unittest.TestCase):
    """Application réelle, sans cycle de vie (aucun planificateur, aucune collecte)."""

    @classmethod
    def setUpClass(cls):
        import app as real
        cls.real = real
        cls.app = real.app

    def test_health_endpoints_public_even_with_proxy_auth(self):
        with mock.patch.dict(os.environ, {'INFRAOPS_TRUSTED_PROXY_SECRET': SECRET}):
            status, _, body = call(self.app, 'GET', '/health/live')
            self.assertEqual((status, json.loads(body)['status']), (200, 'ok'))
            status, _, body = call(self.app, 'GET', '/health/ready')
            self.assertIn(status, (200, 503))
            self.assertIn(json.loads(body)['status'], ('ready', 'not_ready'))
            self.assertEqual(call(self.app, 'GET', '/api/self-monitoring')[0], 401, 'détail réservé aux authentifiés')

    def test_self_monitoring_contract_and_no_leak(self):
        with mock.patch.dict(os.environ, {'INFRAOPS_TRUSTED_PROXY_SECRET': SECRET}):
            status, _, body = call(self.app, 'GET', '/api/self-monitoring', proxy('lecteur@ex.test'))
        self.assertEqual(status, 200)
        data = json.loads(body)
        for key in ('opscontrol', 'collectors', 'sources', 'freshness', 'errors', 'ready'):
            self.assertIn(key, data)
        self.assertIn(data['opscontrol']['database']['journal_mode'], ('wal', 'delete'))
        base = str(Path(self.real.__file__).parent)
        self.assertNotIn(base, body)
        self.assertNotIn(base.replace('\\', '\\\\'), body)
        self.assertNotRegex(body, r'(?i)(password|secret|token)\s*[=:]\s*[^\s\[*"]{6,}')
        for s in data['sources']:
            if s['reachable'] is not True:
                self.assertFalse(s['fresh'])

    def test_metrics_disabled_by_default(self):
        self.assertEqual(call(self.app, 'GET', '/api/metrics')[0], 404)
        with mock.patch.dict(os.environ, {'INFRAOPS_METRICS': '1'}):
            status, headers, body = call(self.app, 'GET', '/api/metrics')
        self.assertEqual(status, 200)
        self.assertTrue(headers['content-type'].startswith('text/plain'))
        self.assertIn('opscontrol_up 1', body)

    def test_get_pages_do_not_write_database(self):
        statements = []
        original = self.real.connect

        @contextlib.contextmanager
        def traced():
            with original() as db:
                db.set_trace_callback(statements.append)
                yield db
        with mock.patch.object(self.real, 'connect', traced):
            for path in ('/api/overview', '/api/sync', '/api/daily', '/api/incidents', '/api/incidents/suppressions'):
                status = call(self.app, 'GET', path)[0]
                self.assertEqual(status, 200, path)
        writes = [s for s in statements if s.lstrip().upper().startswith(WRITES)]
        self.assertEqual(writes, [], 'un GET ne doit rien écrire')
        self.assertTrue(statements, 'la trace a bien capté les lectures')

    def test_api_collector_is_instrumented(self):
        self.assertTrue(getattr(self.real.collect_api_connection, '_observed', False))


if __name__ == '__main__':
    unittest.main()
