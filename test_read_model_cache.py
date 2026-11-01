"""Concurrence, fraîcheur et fermeture des synthèses sur une base simulée."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
import sqlite3
import tempfile
from threading import Barrier, Event
import unittest

from read_model_cache import ReadModelCache, WriteRevisions


class WriteRevisionsTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.writes = WriteRevisions()
        for table in ('sec_vulns', 'states', 'api_snapshots'):
            self.db.execute('CREATE TABLE ' + table + '(value INTEGER)')

    def tearDown(self):
        self.db.close()

    def test_security_commit_invalidates_both_views_after_commit_only(self):
        with self.writes.track(self.db):
            with self.db:
                self.db.execute('INSERT INTO sec_vulns VALUES(1)')
                self.assertEqual(self.writes.revision('summary'), 0)
        self.assertEqual(self.writes.revision('summary'), 1)
        self.assertEqual(self.writes.revision('recommendations'), 1)

    def test_unrelated_collectors_do_not_invalidate_security_and_audit_is_scoped(self):
        with self.writes.track(self.db):
            with self.db:
                self.db.execute('INSERT INTO api_snapshots VALUES(1)')
        self.assertEqual(self.writes.revision('summary'), 0)
        self.assertEqual(self.writes.revision('recommendations'), 0)
        with self.writes.track(self.db):
            with self.db:
                self.db.execute('INSERT INTO states VALUES(1)')
        self.assertEqual(self.writes.revision('summary'), 0)
        self.assertEqual(self.writes.revision('recommendations'), 1)

    def test_rollback_and_read_or_noop_never_publish(self):
        with self.assertRaises(ValueError):
            with self.writes.track(self.db):
                with self.db:
                    self.db.execute('INSERT INTO sec_vulns VALUES(1)')
                    raise ValueError('Échec simulé')
        with self.writes.track(self.db):
            with self.db:
                self.db.execute('SELECT count(*) FROM sec_vulns').fetchone()
                self.db.execute('UPDATE sec_vulns SET value=2 WHERE value=99')
        self.assertEqual(self.writes.revision('summary'), 0)
        self.assertEqual(self.db.execute('SELECT count(*) FROM sec_vulns').fetchone()[0], 0)


class ReadModelCacheTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / 'simulated.sqlite3'
        with self.connect() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE facts(value INTEGER)')
            db.execute('INSERT INTO facts VALUES(1)')
        self.time = 10.0
        self.revision = 'inventory-one'
        self.cache = ReadModelCache(lambda: self.path, clock=lambda: self.time)
        self.calls = 0

        @self.cache.cached('test', lambda: self.revision)
        def build():
            self.calls += 1
            with self.connect() as db:
                return {'value': db.execute('SELECT value FROM facts').fetchone()[0]}
        self.read = build

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path)
        try:
            with db:
                yield db
        finally:
            db.close()

    def tearDown(self):
        self.cache.close()
        self.temporary.cleanup()

    def test_commit_from_another_connection_invalidates_immediately(self):
        self.assertEqual(self.read(), {'value': 1})
        self.read()
        self.assertEqual(self.calls, 1)
        with self.connect() as db:
            db.execute('UPDATE facts SET value=2')
        self.assertEqual(self.read(), {'value': 2})
        self.assertEqual(self.calls, 2)

    def test_time_and_inventory_also_invalidate_without_database_write(self):
        self.read()
        self.time += 4.999
        self.read()
        self.assertEqual(self.calls, 1)
        self.time = 15.0
        self.read()
        self.assertEqual(self.calls, 2)
        self.revision = 'inventory-two'
        self.read()
        self.assertEqual(self.calls, 3)

    def test_parallel_readers_share_one_build(self):
        barrier, started, release = Barrier(5), Event(), Event()

        @self.cache.cached('parallel', lambda: self.revision)
        def build():
            self.calls += 1
            started.set()
            if not release.wait(3):
                raise TimeoutError('Le test doit libérer la construction')
            return 42

        def read():
            barrier.wait(timeout=3)
            return build()

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(read) for _ in range(4)]
            barrier.wait(timeout=3)
            self.assertTrue(started.wait(3))
            release.set()
            self.assertEqual([f.result(timeout=3) for f in futures], [42] * 4)
        self.assertEqual(self.calls, 1)

    def test_missing_database_is_not_served_from_old_cache(self):
        self.read()
        self.path = self.path.parent / 'missing.sqlite3'
        with self.assertRaises(FileNotFoundError):
            self.read()

    def test_replaced_database_and_close_drop_prior_generation(self):
        self.read()
        old_generation = self.cache.generation()
        self.cache.close()
        self.assertIsNone(self.cache.connection)
        self.assertEqual(self.cache.cache.entries, {})
        self.assertNotEqual(old_generation, self.cache.generation())
        self.path = self.path.parent / 'other.sqlite3'
        with self.connect() as db:
            db.execute('CREATE TABLE facts(value INTEGER)')
            db.execute('INSERT INTO facts VALUES(99)')
        self.assertEqual(self.read(), {'value': 99})

    def test_failed_rebuild_never_returns_old_value(self):
        self.read()
        with self.connect() as db:
            db.execute('DROP TABLE facts')
        with self.assertRaises(sqlite3.OperationalError):
            self.read()

    def test_observer_only_reads_and_holds_no_transaction(self):
        self.read()
        trace = []
        self.cache.connection.set_trace_callback(trace.append)
        self.read()
        self.assertEqual(trace, ['PRAGMA data_version'])
        self.assertFalse(self.cache.connection.in_transaction)

    def test_context_without_file_bypasses_cache(self):
        cache = ReadModelCache(lambda: None)
        try:
            calls = []

            @cache.cached('memory', lambda: 'same')
            def read():
                calls.append(1)
                return len(calls)

            self.assertEqual((read(), read()), (1, 2))
        finally:
            cache.close()
