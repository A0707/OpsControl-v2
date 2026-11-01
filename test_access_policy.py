"""Politique d'accès : authentification proxy, rôles, CSRF, quotas, audit, en-têtes, secrets."""
import testing_env  # noqa: F401 — base temporaire AVANT tout import d'app (testing_env.py)
import asyncio
import contextlib
import json
import os
import re
import sqlite3
import unittest
from pathlib import Path
from unittest import mock

from fastapi import FastAPI
from pydantic import ValidationError

import access_policy as ap
import management

SECRET = 's' * 20 + 'secret-proxy-de-test-0123456789'
os.environ.setdefault('INFRAOPS_INCIDENT_SYNC', '0')


def call(app, method, path, headers=None, body=b'', host='127.0.0.1:8001'):
    """Client ASGI minimal : traverse toute la pile de middlewares, sans dépendance externe."""
    sent = []
    raw = [(b'host', host.encode())] + [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    scope = {'type': 'http', 'asgi': {'version': '3.0'}, 'http_version': '1.1', 'method': method, 'scheme': 'http',
             'path': path, 'raw_path': path.encode(), 'query_string': b'', 'headers': raw,
             'client': ('127.0.0.1', 50000), 'server': ('127.0.0.1', 8001), 'root_path': ''}
    messages = [{'type': 'http.request', 'body': body, 'more_body': False}]

    async def receive():
        return messages.pop(0) if messages else {'type': 'http.disconnect'}

    async def send(message):
        sent.append(message)
    asyncio.run(app(scope, receive, send))
    start = next(m for m in sent if m['type'] == 'http.response.start')
    payload = b''.join(m.get('body', b'') for m in sent if m['type'] == 'http.response.body')
    return start['status'], {k.decode().lower(): v.decode() for k, v in start['headers']}, payload.decode('utf-8', 'replace')


def proxy(user):
    return {'X-OpsControl-User': user, 'X-OpsControl-Proxy': SECRET}


MUTATE = {'X-Cockpit-Request': '1', 'Content-Type': 'application/json'}


def mini_app(test_case):
    db = sqlite3.connect(':memory:', check_same_thread=False)
    test_case.addCleanup(db.close)

    @contextlib.contextmanager
    def connect():
        with db:
            yield db
    app = FastAPI()
    ap.install(app, connect)

    @app.get('/api/overview')
    def overview():
        return {'ok': True}

    @app.get('/api/health')
    def health():
        return {'status': 'ok'}

    @app.post('/api/refresh')
    def refresh():
        return {'started': True}

    @app.post('/api/hosts/{key}/refresh')
    def host_refresh(key: str):
        return {'key': key}

    @app.post('/api/manage/hosts')
    def manage():
        return {'saved': True}

    @app.post('/api/incidents/ack')
    def ack():
        return {'ack': True}

    @app.post('/api/nouvelle-route')
    def unclassified():
        return {'x': True}

    @app.get('/api/boom')
    def boom():
        raise OSError('Échec de lecture C:\\Users\\localadmin\\secret\\fichier.pem')

    @app.get('/')
    def index():
        return {'page': True}
    return app, db


class Env(unittest.TestCase):
    env = {}

    def setUp(self):
        patcher = mock.patch.dict(os.environ, self.env, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        for key in ('INFRAOPS_TRUSTED_PROXY_SECRET', 'INFRAOPS_LOCAL_ROLE', 'INFRAOPS_ADMINS', 'INFRAOPS_OPERATORS',
                    'INFRAOPS_DEFAULT_ROLE', 'INFRAOPS_REQUIRE_PROXY'):
            if key not in self.env:
                os.environ.pop(key, None)
        self.app, self.db = mini_app(self)


class LocalDesktopTests(Env):
    """Sans secret proxy (poste Windows) : usage local historique préservé, mais tracé « local »."""

    def test_local_admin_by_default_and_audited(self):
        status, headers, _ = call(self.app, 'POST', '/api/manage/hosts', MUTATE)
        self.assertEqual(status, 200)
        row = self.db.execute('SELECT mode, role, outcome, path FROM mutation_audit').fetchone()
        self.assertEqual(row, ('local', 'admin', 'ok', '/api/manage/hosts'))

    def test_local_off_refuses_mutations_but_allows_reading(self):
        with mock.patch.dict(os.environ, {'INFRAOPS_LOCAL_ROLE': 'off'}):
            self.assertEqual(call(self.app, 'GET', '/api/overview')[0], 200)
            status, _, body = call(self.app, 'POST', '/api/refresh', MUTATE)
        self.assertEqual(status, 403)
        self.assertIn('non authentifiée', json.loads(body)['detail'])


class ProxyModeTests(Env):
    env = {'INFRAOPS_TRUSTED_PROXY_SECRET': SECRET, 'INFRAOPS_ADMINS': 'admin@ex.test', 'INFRAOPS_OPERATORS': 'ops@ex.test'}

    def test_anonymous_direct_access_refused(self):
        for method, path, headers in (('GET', '/api/overview', {}), ('POST', '/api/refresh', MUTATE)):
            status, _, body = call(self.app, method, path, headers)
            self.assertEqual(status, 401, path)
            self.assertNotIn(SECRET, body)
        self.assertEqual(call(self.app, 'GET', '/api/health')[0], 200, 'santé publique pour la supervision')
        self.assertEqual(call(self.app, 'GET', '/')[0], 200, 'interface statique servie ; ses appels API restent refusés')

    def test_forged_proxy_headers_refused(self):
        forged = {'X-OpsControl-User': 'admin@ex.test', 'X-OpsControl-Proxy': 'faux-secret-' + 'x' * 30}
        self.assertEqual(call(self.app, 'POST', '/api/manage/hosts', {**MUTATE, **forged})[0], 401)
        self.assertEqual(call(self.app, 'POST', '/api/manage/hosts', {**MUTATE, 'X-OpsControl-User': 'admin@ex.test'})[0], 401)

    def test_roles(self):
        viewer, operator, admin = proxy('lecteur@ex.test'), proxy('ops@ex.test'), proxy('admin@ex.test')
        self.assertEqual(call(self.app, 'GET', '/api/overview', viewer)[0], 200)
        self.assertEqual(call(self.app, 'POST', '/api/incidents/ack', {**MUTATE, **viewer})[0], 403)
        self.assertEqual(call(self.app, 'POST', '/api/incidents/ack', {**MUTATE, **operator})[0], 200)
        status, _, body = call(self.app, 'POST', '/api/manage/hosts', {**MUTATE, **operator})
        self.assertEqual(status, 403)
        self.assertIn('administrateur', json.loads(body)['detail'])
        self.assertEqual(call(self.app, 'POST', '/api/manage/hosts', {**MUTATE, **admin})[0], 200)
        actors = self.db.execute('SELECT actor, role, outcome FROM mutation_audit ORDER BY seq').fetchall()
        self.assertIn(('ops@ex.test', 'operator', 'forbidden'), actors)
        self.assertIn(('admin@ex.test', 'admin', 'ok'), actors)

    def test_unclassified_post_requires_admin(self):
        self.assertEqual(call(self.app, 'POST', '/api/nouvelle-route', {**MUTATE, **proxy('ops@ex.test')})[0], 403)
        self.assertEqual(call(self.app, 'POST', '/api/nouvelle-route', {**MUTATE, **proxy('admin@ex.test')})[0], 200)

    def test_explicit_local_role_for_tunnel_troubleshooting(self):
        with mock.patch.dict(os.environ, {'INFRAOPS_LOCAL_ROLE': 'viewer'}):
            self.assertEqual(call(self.app, 'GET', '/api/overview')[0], 200)
            self.assertEqual(call(self.app, 'POST', '/api/refresh', MUTATE)[0], 403)

    def test_invalid_user_from_trusted_proxy_never_gets_local_role(self):
        # Audit SEC-10 : même pendant un dépannage (rôle local admin), une identité invalide
        # présentée avec le bon secret est refusée au lieu d'hériter du rôle local.
        with mock.patch.dict(os.environ, {'INFRAOPS_LOCAL_ROLE': 'admin'}):
            for user in ('', 'nom avec espace', 'x' * 121):
                status, _, body = call(self.app, 'POST', '/api/manage/hosts', {**MUTATE, **proxy(user)})
                self.assertEqual(status, 401, repr(user))
                self.assertNotIn(SECRET, body)


class RequiredProxyTests(unittest.TestCase):
    """Audit SEC-01 : sur la VM (INFRAOPS_REQUIRE_PROXY=1), jamais d'ouverture silencieuse en admin."""

    def setUp(self):
        patcher = mock.patch.dict(os.environ, {'INFRAOPS_REQUIRE_PROXY': '1'})
        patcher.start()
        self.addCleanup(patcher.stop)
        for key in ('INFRAOPS_TRUSTED_PROXY_SECRET', 'INFRAOPS_LOCAL_ROLE'):
            os.environ.pop(key, None)

    def test_demarrage_refuse_sans_secret_ou_avec_secret_trop_court(self):
        for secret in (None, 's' * 31):
            with self.subTest(longueur=None if secret is None else len(secret)):
                if secret is None:
                    os.environ.pop('INFRAOPS_TRUSTED_PROXY_SECRET', None)
                else:
                    os.environ['INFRAOPS_TRUSTED_PROXY_SECRET'] = secret
                with self.assertRaises(RuntimeError) as raised:
                    mini_app(self)
                self.assertNotIn('s' * 31, str(raised.exception))

    def test_requete_bloquee_si_le_secret_disparait_apres_demarrage(self):
        os.environ['INFRAOPS_TRUSTED_PROXY_SECRET'] = SECRET
        app, _ = mini_app(self)
        os.environ['INFRAOPS_TRUSTED_PROXY_SECRET'] = SECRET[:31]  # trop court
        os.environ['INFRAOPS_LOCAL_ROLE'] = 'admin'
        headers = {**MUTATE, 'X-Forwarded-For': '203.0.113.9'}
        self.assertEqual(call(app, 'POST', '/api/manage/hosts', headers)[0], 401)
        self.assertEqual(call(app, 'GET', '/api/overview')[0], 401)

    def test_proxy_valide_fonctionne(self):
        os.environ['INFRAOPS_TRUSTED_PROXY_SECRET'] = SECRET
        app, _ = mini_app(self)
        self.assertEqual(call(app, 'GET', '/api/overview', proxy('lecteur@ex.test'))[0], 200)

    def test_unite_systemd_declare_le_proxy_obligatoire(self):
        unit = (Path(__file__).with_name('deploy') / 'infraops.service').read_text(encoding='utf-8')
        self.assertIn('Environment=INFRAOPS_REQUIRE_PROXY=1', unit)


class CsrfTests(Env):
    def test_header_origin_and_fetch_site(self):
        self.assertEqual(call(self.app, 'POST', '/api/incidents/ack', {'Content-Type': 'application/json'})[0], 403)
        self.assertEqual(call(self.app, 'POST', '/api/incidents/ack', {**MUTATE, 'Origin': 'https://evil.test'})[0], 403)
        self.assertEqual(call(self.app, 'POST', '/api/incidents/ack', {**MUTATE, 'Sec-Fetch-Site': 'cross-site'})[0], 403)
        self.assertEqual(call(self.app, 'POST', '/api/incidents/ack', {**MUTATE, 'Origin': 'http://127.0.0.1:8001',
                                                                      'Sec-Fetch-Site': 'same-origin'})[0], 200)
        outcomes = [r[0] for r in self.db.execute('SELECT outcome FROM mutation_audit ORDER BY seq')]
        self.assertEqual(outcomes, ['csrf', 'csrf', 'csrf', 'ok'])


class RateLimitTests(Env):
    def test_full_collection_once_per_minute(self):
        self.assertEqual(call(self.app, 'POST', '/api/refresh', MUTATE)[0], 200)
        status, headers, body = call(self.app, 'POST', '/api/refresh', MUTATE)
        self.assertEqual(status, 429)
        self.assertGreater(int(headers['retry-after']), 0)
        self.assertIn('Collecte complète déjà demandée', json.loads(body)['detail'])

    def test_limiter_window_and_scope(self):
        clock = {'t': 0.0}
        limiter = ap.RateLimiter({'g': (2, 10, 'actor'), 'all': (1, 60, 'global')}, clock=lambda: clock['t'])
        self.assertIsNone(limiter.check('g', 'a'))
        self.assertIsNone(limiter.check('g', 'a'))
        self.assertIsNotNone(limiter.check('g', 'a'))
        self.assertIsNone(limiter.check('g', 'b'), 'quota par acteur')
        self.assertIsNone(limiter.check('all', 'a'))
        self.assertIsNotNone(limiter.check('all', 'b'), 'quota global partagé')
        clock['t'] = 61
        self.assertIsNone(limiter.check('g', 'a'))
        self.assertIsNone(limiter.check('all', 'b'))


class ResponseHygieneTests(Env):
    def test_request_id_security_headers_and_cache(self):
        status, headers, _ = call(self.app, 'GET', '/api/overview', {'X-Request-ID': 'trace-12345678'})
        self.assertEqual(headers['x-request-id'], 'trace-12345678')
        self.assertIn("base-uri 'none'", headers['content-security-policy'])
        self.assertIn("frame-ancestors 'none'", headers['content-security-policy'])
        self.assertEqual(headers['referrer-policy'], 'no-referrer')
        self.assertEqual(headers['cache-control'], 'no-store')
        self.assertEqual(call(self.app, 'GET', '/')[1]['cache-control'], 'no-cache')
        bad = call(self.app, 'GET', '/api/overview', {'X-Request-ID': 'x<script>'})[1]['x-request-id']
        self.assertRegex(bad, r'^[0-9a-f]{32}$')

    def test_internal_error_hides_paths(self):
        status, _, body = call(self.app, 'GET', '/api/boom')
        self.assertEqual(status, 500)
        self.assertNotIn('localadmin', body)
        self.assertNotIn('\\', body)
        self.assertIn('request_id', json.loads(body))

    def test_whoami_describes_role_without_secret(self):
        with mock.patch.dict(os.environ, {'INFRAOPS_TRUSTED_PROXY_SECRET': SECRET, 'INFRAOPS_OPERATORS': 'ops@ex.test'}):
            info = ap.describe({'x-opscontrol-user': 'ops@ex.test', 'x-opscontrol-proxy': SECRET})
            local = ap.describe({})
        self.assertEqual((info['role'], info['can_operate'], info['can_admin']), ('operator', True, False))
        self.assertEqual(local['role'], 'off')
        self.assertNotIn(SECRET, json.dumps([info, local]))


class TokenEnvTests(unittest.TestCase):
    def test_secret_exfiltration_refused(self):
        for name in ('INFRAOPS_TRUSTED_PROXY_SECRET', 'INFRAOPS_WEBHOOK_TOKEN', 'PATH', 'INFRAOPS_PROXMOX_AUTH'):
            with self.assertRaises(ValidationError, msg=name):
                management.Connection(key='x', name='X', provider='Zabbix', url='https://evil.test/', token_env=name)
        management.Connection(key='x', name='X', provider='Zabbix', url='https://zbx.test/api_jsonrpc.php', token_env='INFRAOPS_ZABBIX_AUTH')
        management.Connection(key='x', name='X', provider='Elasticsearch', url='https://es.test/', token_env='INFRAOPS_ELASTIC_AUTH_LOGS')

    def test_collect_revalidates_hand_edited_connections(self):
        with self.assertRaises(ValueError):
            management.token_env_allowed('INFRAOPS_TRUSTED_PROXY_SECRET', 'JSON')


class RealAppTests(unittest.TestCase):
    """Contrats sur l'application réelle (sans lifespan : aucun planificateur démarré)."""

    @classmethod
    def setUpClass(cls):
        import app as real
        cls.app = real.app

    def test_every_mutation_route_is_explicitly_classified(self):
        unclassified = []
        from routers import all_routes  # sans cela, les routes des routeurs inclus étaient ignorées
        for route in all_routes(self.app):
            for method in getattr(route, 'methods', None) or ():
                if method in ('GET', 'HEAD'):
                    continue
                path = re.sub(r'\{[^}]+\}', 'x', route.path)
                if path in ap.WEBHOOKS:
                    continue
                if not any(re.fullmatch(p, path) for p, _, _ in ap.POST_RULES):
                    unclassified.append(route.path)
        self.assertEqual(unclassified, [], 'route de mutation sans rôle explicite (elle serait réservée à admin)')

    def test_runtime_is_admin_and_leaks_no_path(self):
        with mock.patch.dict(os.environ, {'INFRAOPS_TRUSTED_PROXY_SECRET': SECRET, 'INFRAOPS_OPERATORS': 'ops@ex.test',
                                          'INFRAOPS_ADMINS': 'admin@ex.test'}):
            self.assertEqual(call(self.app, 'GET', '/api/runtime', proxy('ops@ex.test'))[0], 403)
            status, _, body = call(self.app, 'GET', '/api/runtime', proxy('admin@ex.test'))
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertFalse(any('\\' in str(v) or '/' in str(v) for v in data.values()), data)
        self.assertNotIn(os.path.expanduser('~'), body)

    def test_trusted_host_and_docs_disabled(self):
        self.assertEqual(call(self.app, 'GET', '/api/health', host='evil.test')[0], 400)
        self.assertEqual(call(self.app, 'GET', '/api/health')[0], 200)
        self.assertEqual(call(self.app, 'GET', '/openapi.json')[0], 404)

    def test_no_secret_in_public_responses(self):
        with mock.patch.dict(os.environ, {'INFRAOPS_TRUSTED_PROXY_SECRET': SECRET}):
            for path in ('/api/health', '/api/whoami'):
                _, _, body = call(self.app, 'GET', path, proxy('quelqu-un@ex.test'))
                self.assertNotIn(SECRET, body)



class JournalAccesTests(Env):
    """Ligne d'accès JSON (opscontrol.http) : corrélée par request_id, sans secret."""

    def capture(self):
        import io
        import logging
        import logging_setup
        flux = io.StringIO()
        handler = logging.StreamHandler(flux)
        handler.setFormatter(logging_setup.JsonFormatter())
        journal = logging.getLogger('opscontrol.http')
        journal.addHandler(handler)
        niveau = journal.level
        journal.setLevel('INFO')
        self.addCleanup(journal.removeHandler, handler)
        self.addCleanup(journal.setLevel, niveau)
        return flux

    def test_une_ligne_json_par_requete_api(self):
        flux = self.capture()
        with mock.patch.dict(os.environ, {'INFRAOPS_ACCESS_LOG': '1'}):
            _, headers, _ = call(self.app, 'GET', '/api/overview', {'X-Request-ID': 'corr-12345678'})
        ligne = json.loads(flux.getvalue().strip().splitlines()[-1])
        self.assertEqual(ligne['request_id'], 'corr-12345678')
        self.assertEqual((ligne['method'], ligne['path'], ligne['status']), ('GET', '/api/overview', 200))
        self.assertEqual(ligne['role'], 'admin')
        self.assertIn('duration_ms', ligne)
        self.assertTrue(ligne['ts'].endswith('+00:00'))

    def test_coupable_par_variable(self):
        flux = self.capture()
        with mock.patch.dict(os.environ, {'INFRAOPS_ACCESS_LOG': '0'}):
            call(self.app, 'GET', '/api/overview')
        self.assertEqual(flux.getvalue(), '')

    def test_fichiers_statiques_non_journalises(self):
        flux = self.capture()
        call(self.app, 'GET', '/')
        self.assertEqual(flux.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
