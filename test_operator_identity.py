"""Identité opérateur : seul le reverse proxy de confiance peut la transmettre."""
from routers import all_routes  # routes des APIRouter inclus (FastAPI ne les recopie plus dans app.routes)
import contextlib
import json
import os
import sqlite3
import unittest
from types import SimpleNamespace
from unittest import mock

from fastapi import FastAPI, HTTPException
from starlette.datastructures import Headers

import alert_center
import operator_identity as oi
from test_alert_ack import probleme, zabbix

SECRET = 'a' * 24 + 'proxy-secret-de-test-0123456789'


def request(**headers):
    return SimpleNamespace(headers=Headers(headers))


class ResolveTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {oi.SECRET_ENV: SECRET})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_trusted_proxy_identity(self):
        ident = oi.resolve(Headers({'X-OpsControl-User': 'jdoe@example.test', 'X-OpsControl-Proxy': SECRET}))
        self.assertEqual((ident['mode'], ident['authenticated'], ident['user']), ('proxy', True, 'jdoe@example.test'))

    def test_direct_uvicorn_header_is_ignored(self):
        ident = oi.resolve(Headers({'X-OpsControl-User': 'admin'}))
        self.assertFalse(ident['authenticated'])
        self.assertIsNone(ident['user'])
        self.assertTrue(ident['ignored_identity_header'])
        self.assertIn('non authentifiée', ident['label'])

    def test_wrong_secret_is_ignored(self):
        ident = oi.resolve(Headers({'X-OpsControl-User': 'admin', 'X-OpsControl-Proxy': SECRET[:-1] + 'x'}))
        self.assertEqual(ident['mode'], 'local')

    def test_short_or_missing_secret_never_trusts(self):
        with mock.patch.dict(os.environ, {oi.SECRET_ENV: 'court'}):
            self.assertEqual(oi.resolve(Headers({'X-OpsControl-User': 'a', 'X-OpsControl-Proxy': 'court'}))['mode'], 'local')
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(oi.resolve(Headers({'X-OpsControl-User': 'a', 'X-OpsControl-Proxy': ''}))['mode'], 'local')

    def test_invalid_identity_value_refused(self):
        for bad in ('', 'a b', 'x' * 121, 'admin\r\nX: y'):
            self.assertFalse(oi.resolve(Headers({'X-OpsControl-User': bad, 'X-OpsControl-Proxy': SECRET}))['authenticated'], bad)

    def test_fastapi_injects_the_request_object(self):
        """Régression : une annotation Request non résolue devenait un paramètre de requête obligatoire (422)."""
        app = FastAPI()
        oi.install(app)
        db = sqlite3.connect(':memory:', check_same_thread=False)
        self.addCleanup(db.close)
        alert_center.install(app, SimpleNamespace(rows=lambda: [], connect=lambda: contextlib.nullcontext(db), api_connections=lambda: []))
        for path in ('/api/whoami', '/api/alerts/ack'):
            route = next(r for r in all_routes(app) if getattr(r, 'path', '') == path)
            self.assertEqual(route.dependant.request_param_name, 'request', path)
            self.assertNotIn('request', [q.name for q in route.dependant.query_params], path)

    def test_whoami_never_exposes_secret(self):
        app = FastAPI()
        oi.install(app)
        route = next(r for r in all_routes(app) if getattr(r, 'path', '') == '/api/whoami')
        body = route.endpoint(request(**{'X-OpsControl-User': 'jdoe', 'X-OpsControl-Proxy': SECRET}))
        self.assertEqual(body['user'], 'jdoe')
        self.assertNotIn(SECRET, json.dumps(body))
        self.assertNotIn('ignored_identity_header', body)


class AckIdentityTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {oi.SECRET_ENV: SECRET})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.db = sqlite3.connect(':memory:', check_same_thread=False)
        self.addCleanup(self.db.close)
        import migrations
        migrations.apply(self.db)  # comme au démarrage : alert_acks vient de la migration core_v4

        @contextlib.contextmanager
        def connect():
            with self.db:
                yield self.db
        self.ctx = SimpleNamespace(rows=lambda: [], connect=connect,
                                   api_connections=lambda: [zabbix(probleme('X is down', 'x', 0.1))])
        app = FastAPI()
        alert_center.install(app, self.ctx)
        self.routes = {r.path: r.endpoint for r in all_routes(app) if hasattr(r, 'endpoint')}
        self.alert_id = alert_center.build(self.ctx)['alerts'][0]['id']

    def test_proxy_identity_replaces_declared_name(self):
        ack = alert_center.Ack(id=self.alert_id, by='quelqu-un-d-autre')
        result = self.routes['/api/alerts/ack'](ack, request(**{'X-OpsControl-User': 'jdoe@example.test', 'X-OpsControl-Proxy': SECRET}))
        self.assertEqual((result['by'], result['authenticated']), ('jdoe@example.test', True))
        stored = alert_center.build(self.ctx)['alerts'][0]['ack']
        self.assertEqual((stored['by'], stored['authenticated']), ('jdoe@example.test', True))

    def test_local_mode_keeps_declared_name_marked_unauthenticated(self):
        ack = alert_center.Ack(id=self.alert_id, by='Operator')
        result = self.routes['/api/alerts/ack'](ack, request(**{'X-OpsControl-User': 'usurpation'}))
        self.assertEqual((result['by'], result['authenticated']), ('Operator', False))

    def test_local_mode_requires_a_name(self):
        with mock.patch.dict(os.environ, {oi.LOCAL_NAME_ENV: ''}):
            with self.assertRaises(HTTPException) as err:
                self.routes['/api/alerts/ack'](alert_center.Ack(id=self.alert_id), request())
        self.assertEqual(err.exception.status_code, 422)

    def test_local_default_name_fills_empty_field_only(self):
        with mock.patch.dict(os.environ, {oi.LOCAL_NAME_ENV: 'operator'}):
            result = self.routes['/api/alerts/ack'](alert_center.Ack(id=self.alert_id), request())
            self.assertEqual((result['by'], result['authenticated']), ('operator', False))
            # Un nom saisi l'emporte ; le proxy authentifié l'emporte sur tout.
            self.assertEqual(oi.actor(Headers({}), 'Autre'), ('Autre', 'local'))
            proxied = Headers({'X-OpsControl-User': 'jdoe', 'X-OpsControl-Proxy': SECRET})
            self.assertEqual(oi.actor(proxied, ''), ('jdoe', 'proxy'))

    def test_invalid_local_default_name_ignored(self):
        for bad in ('x' * 61, 'a\r\nb', '<script>'):
            with mock.patch.dict(os.environ, {oi.LOCAL_NAME_ENV: bad}):
                self.assertIsNone(oi.local_default(), bad)
                self.assertEqual(oi.actor(Headers({}), ''), ('', 'local'))

    def test_whoami_exposes_default_name_only_in_local_mode(self):
        app = FastAPI()
        oi.install(app)
        route = next(r for r in all_routes(app) if getattr(r, 'path', '') == '/api/whoami')
        with mock.patch.dict(os.environ, {oi.LOCAL_NAME_ENV: 'operator'}):
            self.assertEqual(route.endpoint(request())['default_name'], 'operator')
            proxied = route.endpoint(request(**{'X-OpsControl-User': 'jdoe', 'X-OpsControl-Proxy': SECRET}))
            self.assertIsNone(proxied['default_name'])

    def test_migration_of_existing_ack_table(self):
        db = sqlite3.connect(':memory:', check_same_thread=False)
        db.execute('CREATE TABLE alert_acks(id TEXT PRIMARY KEY, count INTEGER, by TEXT, note TEXT, at TEXT, until TEXT)')
        db.execute("INSERT INTO alert_acks VALUES('old', 1, 'Ancien', '', '2026-01-01', '2999-01-01')")
        db.commit()

        @contextlib.contextmanager
        def connect():
            with db:
                yield db
        # La colonne auth est ajoutée par la migration versionnée core_v4 (démarrage), une seule fois.
        import migrations
        self.assertIn('core_v4_module_tables', migrations.apply(db))
        self.assertEqual(db.execute("SELECT auth FROM alert_acks WHERE id='old'").fetchone()[0], 'local')
        self.assertEqual(migrations.apply(db), [])
        alert_center.install(FastAPI(), SimpleNamespace(rows=lambda: [], connect=connect, api_connections=lambda: []))
        db.close()


if __name__ == '__main__':
    unittest.main()
