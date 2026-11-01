"""Lot 7 : cache des réponses lourdes — révision, durée de vie, construction unique, sérialisation."""
import testing_env  # noqa: F401 — base temporaire AVANT tout import d'app (testing_env.py)
import json
import os
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

os.environ.setdefault('INFRAOPS_INCIDENT_SYNC', '0')

import response_cache as rc


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.cache = rc.ResponseCache(self.clock)
        self.builds = 0

    def build(self):
        self.builds += 1
        return {'n': self.builds}

    def test_same_revision_within_ttl_is_served_once(self):
        a = self.cache.get('x', 'rev1', self.build)
        self.clock.now += 4
        self.assertEqual(self.cache.get('x', 'rev1', self.build), a)
        self.assertEqual(self.builds, 1)
        self.assertEqual(self.cache.stats['x']['hits'], 1)

    def test_new_revision_rebuilds_immediately(self):
        self.cache.get('x', 'rev1', self.build)
        self.assertEqual(json.loads(self.cache.get('x', 'rev2', self.build)), {'n': 2}, 'une écriture invalide aussitôt')

    def test_ttl_bounds_staleness(self):
        self.cache.get('x', 'rev1', self.build)
        self.clock.now += rc.DEFAULT_TTL + 0.01
        self.cache.get('x', 'rev1', self.build)
        self.assertEqual(self.builds, 2, 'au-delà de la durée de vie, recalcul même sans écriture')

    def test_routes_are_isolated(self):
        self.cache.get('a', 'r', self.build)
        self.cache.get('b', 'r', self.build)
        self.assertEqual(self.builds, 2)

    def test_concurrent_requests_share_one_build(self):
        cache, calls, results = rc.ResponseCache(), [], []

        def slow():
            calls.append(1)
            time.sleep(0.2)
            return {'ok': True}
        threads = [threading.Thread(target=lambda: results.append(cache.get('o', 'r', slow))) for _ in range(8)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(len(calls), 1, 'construction unique pour les requêtes simultanées')
        self.assertEqual(len(set(results)), 1)

    def test_build_failure_is_not_cached(self):
        def boom():
            raise RuntimeError('panne')
        with self.assertRaises(RuntimeError):
            self.cache.get('x', 'r', boom)
        self.assertEqual(json.loads(self.cache.get('x', 'r', self.build)), {'n': 1})

    def test_serialization_matches_fastapi_conventions(self):
        at = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)
        body = json.loads(rc.dumps({'at': at, 's': {1}, 't': (1, 2), 'p': Path('a'), 'é': 'ü'}))
        self.assertEqual(body['at'], '2026-10-04T12:00:00+00:00')
        self.assertEqual(body['s'], [1])
        self.assertEqual(body['é'], 'ü')
        with self.assertRaises(TypeError):
            rc.dumps({'x': object()})
        with self.assertRaises(ValueError):
            rc.dumps({'x': float('nan')})


class AppIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app
        cls.app = app

    def test_overview_route_cached_and_invalidated_by_a_write(self):
        from test_access_policy import call
        rc.CACHE.invalidate()
        status, headers, first = call(self.app.app, 'GET', '/api/overview')
        self.assertEqual(status, 200)
        self.assertTrue(headers['content-type'].startswith('application/json'))
        builds = rc.CACHE.stats['overview']['builds']
        self.assertEqual(call(self.app.app, 'GET', '/api/overview')[2], first)
        self.assertEqual(rc.CACHE.stats['overview']['builds'], builds, 'deuxième lecture servie depuis le cache')
        self.assertIsInstance(json.loads(first)['hosts'], list)
        # L'invalidation par écriture est vérifiée sur une base isolée (test suivant) : aucune
        # écriture, même annulée, sur la base de l'instance.

    def test_unchanged_view_is_answered_304_without_body(self):
        # Audit UI du 31/10 (performances) : ETag sur le corps, 304 si la page le connaît déjà.
        from test_access_policy import call
        rc.CACHE.invalidate()
        status, headers, first = call(self.app.app, 'GET', '/api/overview')
        etag = headers['etag']
        self.assertEqual(etag, rc.etag_of(first.encode('utf-8')))
        status, headers, body = call(self.app.app, 'GET', '/api/overview', {'If-None-Match': etag})
        self.assertEqual((status, body, headers['etag']), (304, '', etag))
        self.assertEqual(headers['cache-control'], 'no-store')
        status, _, body = call(self.app.app, 'GET', '/api/overview', {'If-None-Match': '"autre"'})
        self.assertEqual((status, body), (200, first))

    def test_host_detail_never_mutates_the_shared_federation(self):
        from test_access_policy import call
        rc.CACHE.invalidate()
        connections, assets = self.app.federated()
        if not assets:
            self.skipTest('inventaire vide')
        key = assets[0]['key']
        status, _, body = call(self.app.app, 'GET', '/api/hosts/' + key)
        self.assertEqual(status, 200)
        self.assertIn('source_details', json.loads(body))
        _, shared = self.app.federated()
        self.assertIs(shared, assets, 'même objet partagé (cache)')
        for field in ('history', 'source_details', 'batches', 'audit_versions', 'alerts'):
            self.assertNotIn(field, shared[0], 'la fiche a modifié le parc partagé : ' + field)

    def test_revision_tracks_collection_tables(self):
        import sqlite3
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            db_path = Path(tmp) / 's.sqlite3'
            db = sqlite3.connect(db_path)
            for table in ('states', 'network', 'batch_states', 'registered_assets'):
                db.execute(f'CREATE TABLE {table}(key TEXT PRIMARY KEY, ip TEXT, payload TEXT)')
            db.commit()
            with mock.patch.object(self.app, 'DB', db_path):
                before = self.app.data_revision()
                db.execute("INSERT OR REPLACE INTO states VALUES('a','192.0.2.1','{}')"); db.commit()
                after_insert = self.app.data_revision()
                db.execute("INSERT OR REPLACE INTO states VALUES('a','192.0.2.1','{\"x\":1}')"); db.commit()
                after_replace = self.app.data_revision()
                db.execute("INSERT OR REPLACE INTO network VALUES('a','192.0.2.1','{}')"); db.commit()
                after_network = self.app.data_revision()
            db.close()
        self.assertEqual(len({before, after_insert, after_replace, after_network}), 4, 'chaque écriture change la révision')


if __name__ == '__main__':
    unittest.main()


class StaticCacheTests(unittest.TestCase):
    def test_versioned_assets_are_immutable_and_the_page_is_revalidated(self):
        # Audit UI du 31/10 (performances) : fichier ?v=<empreinte> immuable ; page et API inchangées.
        import app
        from test_access_policy import call
        version = __import__('re').search(r'/style\.css\?v=([0-9a-f]{8})', (Path(app.__file__).parent / 'web/index.html').read_text(encoding='utf-8'))[1]
        scope_call = lambda path, query: call(app.app, 'GET', path) if not query else _call_query(app.app, path, query)
        self.assertEqual(scope_call('/style.css', 'v=' + version)[1]['cache-control'], 'public, max-age=31536000, immutable')
        self.assertEqual(scope_call('/style.css', '')[1]['cache-control'], 'no-cache')
        self.assertEqual(scope_call('/', '')[1]['cache-control'], 'no-cache')
        self.assertEqual(scope_call('/api/overview', 'v=' + version)[1]['cache-control'], 'no-store')


def _call_query(asgi, path, query):
    """Variante de test_access_policy.call avec une chaîne de requête."""
    import asyncio
    sent = []
    scope = {'type': 'http', 'asgi': {'version': '3.0'}, 'http_version': '1.1', 'method': 'GET', 'scheme': 'http',
             'path': path, 'raw_path': path.encode(), 'query_string': query.encode(), 'headers': [(b'host', b'127.0.0.1:8001')],
             'client': ('127.0.0.1', 50000), 'server': ('127.0.0.1', 8001), 'root_path': ''}
    messages = [{'type': 'http.request', 'body': b'', 'more_body': False}]

    async def receive():
        return messages.pop(0) if messages else {'type': 'http.disconnect'}

    async def send(message):
        sent.append(message)
    asyncio.run(asgi(scope, receive, send))
    start = next(m for m in sent if m['type'] == 'http.response.start')
    return start['status'], {k.decode().lower(): v.decode() for k, v in start['headers']}


class EtagTests(unittest.TestCase):
    def test_build_time_does_not_change_the_etag_and_is_sent_on_304(self):
        # /api/alerts : seul generated_at change entre deux constructions à données égales.
        first = b'{"alerts":[1],"generated_at":"2026-10-31T22:15:15+00:00","x":2}'
        later = b'{"alerts":[1],"generated_at":"2026-10-31T22:15:22+00:00","x":2}'
        self.assertEqual(rc.etag_of(first), rc.etag_of(later))
        self.assertNotEqual(rc.etag_of(first), rc.etag_of(b'{"alerts":[2],"generated_at":"2026-10-31T22:15:22+00:00","x":2}'))
        cache = rc.ResponseCache()
        built = iter([{'alerts': [1], 'generated_at': 'B'}])
        route = rc.cached_json('t', lambda: 1, cache=cache)(lambda: next(built))
        from types import SimpleNamespace
        etag = route().headers['etag']
        answer = route(SimpleNamespace(headers={'if-none-match': etag}))
        self.assertEqual((answer.status_code, answer.headers['x-generated-at']), (304, 'B'))
