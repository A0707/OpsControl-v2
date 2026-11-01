"""Arrêt : les producteurs sont attendus avant de rendre le verrou d'instance (OC-AUDIT-013)."""
import testing_env  # noqa: F401 — base temporaire AVANT tout import d'app (testing_env.py)
import asyncio
import os
import threading
import unittest
from pathlib import Path
from unittest import mock

import app
import jobs
import self_monitor


class DrainTests(unittest.TestCase):
    def test_spawned_thread_leaves_registry_when_done(self):
        thread = jobs.spawn(lambda: None, name='court')
        thread.join(2)
        self.assertEqual(jobs.drain(0), [])

    def test_drain_reports_producers_still_running(self):
        release = threading.Event()
        self.addCleanup(release.set)
        jobs.spawn(release.wait, (5,), 'collecte-lente')
        self.assertEqual(jobs.drain(0.1), ['collecte-lente'])
        release.set()
        self.assertEqual(jobs.drain(2), [])

    def test_scheduled_collections_are_registered(self):
        source = Path(jobs.__file__).read_text(encoding='utf-8')
        self.assertNotIn('threading.Thread(target=c.', source, 'toute collecte passe par spawn()')
        self.assertEqual(source.count('threading.Thread('), 1, 'seul spawn() crée des fils')


class LifespanTests(unittest.TestCase):
    def run_lifespan(self, during):
        async def scenario():
            async with app.lifespan(app.app):
                during()
        with mock.patch.dict(os.environ, {'INFRAOPS_SINGLE_INSTANCE': '1', 'INFRAOPS_STOP_SECONDS': '0.3'}):
            asyncio.run(scenario())

    def lock_is_free(self):
        try:
            handle = self_monitor.acquire_instance_lock(str(app.DB) + '.lock')
        except RuntimeError:
            return False
        self_monitor.release_instance_lock(handle)
        return True

    def test_lock_released_after_producers_finish(self):
        done = threading.Event()
        self.run_lifespan(lambda: jobs.spawn(lambda: done.wait(0.1) or done.set(), name='collecte-courte'))
        self.assertTrue(done.is_set(), 'producteur terminé avant la fin du lifespan')
        self.assertTrue(self.lock_is_free())

    def test_lock_kept_while_a_producer_still_writes(self):
        release = threading.Event()
        self.addCleanup(release.set)
        with self.assertLogs('opscontrol', 'WARNING') as logs:
            self.run_lifespan(lambda: jobs.spawn(release.wait, (10,), 'collecte-bloquee'))
        self.assertIn('collecte-bloquee', ' '.join(logs.output))
        self.assertFalse(self.lock_is_free(), 'une nouvelle instance ne démarre pas sous un producteur actif')
        release.set()
        self.assertEqual(jobs.drain(2), [])
        self_monitor.release_instance_lock(app.verrous_conserves.pop())
        self.assertTrue(self.lock_is_free())


class SecondInstanceTests(unittest.TestCase):
    """OC-AUDIT-014 : un second processus sur la même base est refusé avant tout DDL."""

    SCRIPT = '\n'.join((
        'import testing_env, asyncio, sqlite3, app',
        'tables = sqlite3.connect(app.DB).execute("SELECT count(*) FROM sqlite_master").fetchone()[0]',
        'async def start():',
        '    async with app.lifespan(app.app): pass',
        'try:',
        '    asyncio.run(start()); refused = False',
        'except RuntimeError:',
        '    refused = True',
        'print(app.SCHEMA_DEFERRED, tables, refused)'))

    def test_second_import_does_not_migrate_and_lifespan_refuses(self):
        import subprocess
        import sys
        import tempfile
        from pathlib import Path
        db = Path(tempfile.mkdtemp(prefix='second-', dir=testing_env.DIRECTORY)) / 'state.sqlite3'
        held = self_monitor.acquire_instance_lock(str(db) + '.lock')
        self.addCleanup(self_monitor.release_instance_lock, held)
        env = {**os.environ, 'COCKPIT_DB': str(db), 'INFRAOPS_SINGLE_INSTANCE': '1', 'PYTHONIOENCODING': 'utf-8'}
        result = subprocess.run([sys.executable, '-c', self.SCRIPT], capture_output=True, text=True, timeout=120,
                                cwd=Path(app.__file__).parent, env=env)
        self.assertEqual(result.returncode, 0, result.stderr[-1500:])
        self.assertEqual(result.stdout.split()[-3:], ['True', '0', 'True'], 'aucune table créée, démarrage refusé')


if __name__ == '__main__':
    unittest.main()
