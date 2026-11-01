"""Planificateur : une étape en échec ne doit jamais arrêter les collectes (audit BE-01/BE-02).

Contexte simulé (SimpleNamespace) : aucun import d'app, aucune collecte, aucun réseau.
"""
import threading
import time
import unittest
from types import SimpleNamespace

import jobs


class Stop:
    """Événement d'arrêt qui laisse passer `ticks` tours de boucle."""

    def __init__(self, ticks):
        self.ticks = ticks

    def wait(self, _seconds):
        self.ticks -= 1
        return self.ticks < 0


class Monitor:
    def __init__(self):
        self.errors, self.beats = [], 0

    def heartbeat(self, _name):
        self.beats += 1

    def error(self, message, source='application'):
        self.errors.append((source, message))


def context(ticks, **overrides):
    calls = {'tier0': 0, 'network': 0, 'api': 0, 'retention': 0}

    def count(name):
        def call(*_args):
            calls[name] += 1
        return call

    c = SimpleNamespace(
        stop=Stop(ticks), lock=threading.Lock(), MONITOR=Monitor(), redact=str,
        monitor={'interval': 60, 'next_at': time.time() - 1},
        critical_tick=lambda _enabled: None, tier0_tick=count('tier0'),
        HOSTS=[], api_connections=lambda: [], add_discovered_hosts=lambda _a: None, rows=lambda: [],
        launch=lambda *_a: None, launch_network=count('network'), launch_api_sync=count('api'),
        batch_last=[time.time()], BATCH_EVERY=1800, launch_batches=lambda: None,
        retention_last=[0], RETENTION_EVERY=3600, run_retention=count('retention'))
    for name, value in overrides.items():
        setattr(c, name, value)
    return c, calls


class SchedulerTests(unittest.TestCase):
    def setUp(self):
        self.previous = jobs.ctx
        self.addCleanup(jobs.bind, self.previous)

    def run_scheduler(self, c):
        jobs.bind(c)
        jobs.scheduler()

    def test_etape_en_echec_ne_stoppe_pas_les_suivantes_ni_les_tours(self):
        def boom(*_args):
            raise RuntimeError('database is locked')
        c, calls = context(3, critical_tick=boom, launch_api_sync=boom)
        self.run_scheduler(c)
        self.assertEqual(c.MONITOR.beats, 3)
        self.assertEqual(calls['tier0'], 3)          # la voie rapide continue à chaque tour
        self.assertEqual(calls['network'], 1)        # l'étape après la source API en échec a tourné
        sources = {source for source, _ in c.MONITOR.errors}
        self.assertEqual(sources, {'planificateur'})
        self.assertTrue(any('sources API' in m and 'database is locked' in m for _, m in c.MONITOR.errors))

    def test_retention_en_echec_dans_son_fil_ne_stoppe_pas_le_planificateur(self):
        finished = threading.Event()

        def failing_retention():
            finished.set()
            raise RuntimeError('database is locked')
        c, calls = context(3, run_retention=failing_retention)
        self.run_scheduler(c)
        self.assertTrue(finished.wait(2))
        self.assertEqual(calls['tier0'], 3)
        deadline = time.time() + 2
        while not c.MONITOR.errors and time.time() < deadline:
            time.sleep(0.01)
        self.assertTrue(any('Rétention' in m for _, m in c.MONITOR.errors))

    def test_retention_ne_bloque_pas_le_planificateur_et_ne_se_chevauche_pas(self):
        release, started = threading.Event(), threading.Event()
        runs = []

        def slow_retention():
            runs.append(1)
            started.set()
            release.wait(2)
        c, calls = context(2, run_retention=slow_retention)
        jobs.bind(c)
        self.assertTrue(jobs.launch_retention())
        self.assertTrue(started.wait(2))
        self.assertFalse(jobs.launch_retention())    # purge déjà en cours : pas de second fil
        jobs.scheduler()                             # ne reste pas bloqué derrière la purge lente
        self.assertEqual(calls['tier0'], 2)
        release.set()
        deadline = time.time() + 2
        while jobs._retention_running.locked() and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(len(runs), 1)


if __name__ == '__main__':
    unittest.main()


class PerHostPersistenceTests(unittest.TestCase):
    """Audit BE-05/WAF-01 : un enregistrement en échec ne coûte que son serveur."""

    def setUp(self):
        self.previous = jobs.ctx
        self.addCleanup(jobs.bind, self.previous)

    def context(self):
        class Monitor:
            def __init__(self):
                self.errors, self.ended = [], None

            def begin(self, _kind):
                return 0

            def end(self, kind, ok, error=None, started=None, items=None):
                self.ended = (kind, ok, error)

            def error(self, message, source='application'):
                self.errors.append(message)
        hosts = [{'key': k, 'name': k, 'ip': f'10.0.0.{i}'} for i, k in enumerate(('a', 'b', 'c'), 1)]
        c = SimpleNamespace(
            MONITOR=Monitor(), WORKERS=2, cfg=None, lock=threading.Lock(), redact=str,
            job={'running': True, 'completed': 0, 'error': None},
            collect=lambda h, cfg, who: {'status': 'ok', 'issues': [], 'collected_at': '2026-10-08T00:00:00+00:00'},
            sanitize=lambda r: r, enroll_assets=lambda: None, collection_done=lambda kind: None)
        return c, hosts

    def test_un_serveur_en_echec_n_empeche_pas_les_autres(self):
        c, hosts = self.context()
        saved = []

        def store(ctx, h, result):
            if h['key'] == 'b':
                raise ValueError('réponse WAF malformée')
            saved.append(h['key'])
        jobs.bind(c)
        original = jobs._store_audit
        jobs._store_audit = store
        try:
            jobs.refresh(hosts, 'test')
        finally:
            jobs._store_audit = original
        self.assertEqual(sorted(saved), ['a', 'c'])
        self.assertEqual(c.job['completed'], 3)
        self.assertIn('1 serveur(s) non enregistré(s) : b', c.job['error'])
        self.assertEqual(c.MONITOR.ended[:2], ('ssh', False))
        self.assertTrue(any('Enregistrement de b' in e for e in c.MONITOR.errors))

    def test_lot_fige_et_resultats_d_une_configuration_remplacee(self):
        # Audit A1 : l'inventaire peut changer pendant un lot. Le lot garde sa copie figée ;
        # le résultat d'un serveur retiré n'est pas enregistré, ni une mesure réseau d'un
        # ancien port ; l'audit SSH d'une configuration modifiée garde son empreinte.
        c, hosts = self.context()
        c.HOSTS = [dict(h) for h in hosts]
        started = []
        c.refresh = lambda selected, who: started.append(selected)
        jobs.bind(c)
        c.job['running'] = False
        original_spawn = jobs.spawn
        jobs.spawn = lambda target, args=(), name=None: target(*args)
        try:
            jobs.launch(c.HOSTS, 'test', 'all')
        finally:
            jobs.spawn = original_spawn
        snapshot = started[0]
        c.HOSTS[0] = {**c.HOSTS[0], 'port': 2222}
        self.assertNotIn('port', snapshot[0], 'copie figée au départ du lot')
        del c.HOSTS[2]
        saved = []
        store = lambda ctx, h, result: saved.append(h['key'])
        self.assertTrue(jobs._persist_host(c, snapshot[2], {}, store))
        self.assertEqual(saved, [], 'serveur retiré pendant le lot')
        self.assertTrue(jobs._persist_host(c, snapshot[0], {}, store))
        self.assertEqual(saved, ['a'], 'audit SSH conservé avec son empreinte')
        saved.clear()
        self.assertTrue(jobs._persist_host(c, snapshot[0], {}, jobs._store_network))
        self.assertTrue(jobs._persist_host(c, snapshot[1], {}, lambda ctx, h, r: saved.append(h['key'])))
        self.assertEqual(saved, ['b'])

    def test_base_occupee_une_nouvelle_tentative(self):
        import sqlite3
        c, hosts = self.context()
        attempts = []

        def store(ctx, h, result):
            attempts.append(1)
            if len(attempts) == 1:
                raise sqlite3.OperationalError('database is locked')
        original_sleep = jobs.time.sleep
        jobs.time.sleep = lambda _s: None
        try:
            self.assertTrue(jobs._persist_host(c, hosts[0], {}, store))
        finally:
            jobs.time.sleep = original_sleep
        self.assertEqual(len(attempts), 2)
