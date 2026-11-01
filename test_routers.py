"""Routes du cœur déplacées dans routers/ : mêmes chemins, mêmes méthodes, même comportement."""
import testing_env  # noqa: F401 — base temporaire AVANT tout import d'app (testing_env.py)
import json
import os
import re
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault('INFRAOPS_INCIDENT_SYNC', '0')

from routers import all_routes
from test_access_policy import call, MUTATE

MOVED = {
    ('POST', '/api/refresh'): ('routers.hosts', 202), ('POST', '/api/hosts/{key}/refresh'): ('routers.hosts', 202),
    ('GET', '/api/hosts/{key}'): ('routers.hosts', None), ('GET', '/api/hosts/{key}/audits'): ('routers.hosts', None),
    ('GET', '/api/hosts/{key}/observability'): ('routers.hosts', None),
    ('POST', '/api/monitoring'): ('routers.system', None), ('GET', '/api/inventory-report'): ('routers.system', None),
    ('GET', '/api/runtime'): ('routers.system', None),
    ('GET', '/api/network'): ('routers.network', None), ('POST', '/api/network/refresh'): ('routers.network', 202),
    ('POST', '/api/network/hosts/{key}/refresh'): ('routers.network', 202),
    ('GET', '/api/overview'): ('routers.fleet', None), ('GET', '/api/services'): ('routers.fleet', None),
    ('GET', '/api/findings'): ('routers.fleet', None),
    ('GET', '/api/services/units'): ('routers.fleet', None),
}


class RouterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app
        cls.module = app
        cls.app = app.app
        cls.routes = [r for r in all_routes(app.app) if getattr(r, 'methods', None)]

    def test_every_moved_route_exists_once_in_its_router(self):
        for (method, path), (module, status) in MOVED.items():
            found = [r for r in self.routes if r.path == path and method in r.methods]
            self.assertEqual(len(found), 1, f'{method} {path}')
            self.assertEqual(found[0].endpoint.__module__, module, f'{method} {path}')
            if status:
                self.assertEqual(found[0].status_code, status, f'{method} {path}')

    def test_no_route_is_registered_twice(self):
        pairs = [(m, r.path) for r in self.routes for m in r.methods if m != 'HEAD']
        self.assertEqual(sorted(p for p in set(pairs) if pairs.count(p) > 1), [])

    def test_itsm_routes_are_reachable_before_static_mount(self):
        with mock.patch.dict(os.environ, {'INFRAOPS_LOCAL_ROLE': 'admin',
                                         'INFRAOPS_REQUIRE_PROXY': '0',
                                         'INFRAOPS_TRUSTED_PROXY_SECRET': ''}):
            status, _, payload = call(self.app, 'GET', '/api/itsm/status')
            self.assertEqual(status, 200)
            # `configured` / `transport` dépendent de l'environnement GLPI du poste.
            data = json.loads(payload)
            self.assertEqual((data['available'], data['protocol']), (True, 1))
            self.assertNotIn('base', data)
            for action in ('take', 'preview', 'create', 'reconcile'):
                status, _, _ = call(self.app, 'POST', '/api/itsm/' + action,
                                    headers=MUTATE, body=b'{}')
                self.assertEqual(status, 422, action)

    def test_app_py_defines_no_route_itself(self):
        text = (Path(self.module.__file__)).read_text(encoding='utf-8')
        self.assertEqual(re.findall(r'^@app\.(?:get|post|put|patch|delete)\(', text, re.M), [],
                         'les routes du cœur vivent dans routers/')

    def test_no_module_registers_routes_on_app_directly(self):
        # Toutes les routes passent par un APIRouter ; seul le middleware d'accès reste sur app.
        base = Path(self.module.__file__).parent
        offenders = [f'{p.name}:{text[:m.start()].count(chr(10)) + 1}'
                     for p in [*base.glob('*.py'), *base.glob('routers/*.py')] if not p.name.startswith('test_')
                     for text in [p.read_text(encoding='utf-8')]
                     for m in re.finditer(r'^\s*@app\.(?:get|post|put|patch|delete|api_route)\(', text, re.M)]
        self.assertEqual(offenders, [])

    def test_every_route_comes_from_a_router(self):
        flat = [r.path for r in self.app.routes if getattr(r, 'methods', None)]
        self.assertEqual(flat, [], 'route enregistrée hors APIRouter')
        self.assertGreaterEqual(len(self.routes), 60)

    def test_functions_stay_importable_from_app(self):
        for name in ('overview', 'services_all', 'findings_all', 'federated'):
            self.assertTrue(callable(getattr(self.module, name)), name)

    def test_behaviour_unchanged(self):
        status, _, body = call(self.app, 'GET', '/api/network')
        self.assertEqual(status, 200)
        self.assertEqual(set(json.loads(body)), {'hosts', 'job'})
        self.assertEqual(call(self.app, 'GET', '/api/hosts/serveur-inexistant')[0], 404)
        self.assertEqual(call(self.app, 'GET', '/api/hosts/serveur-inexistant/observability')[0], 404)
        self.assertEqual(call(self.app, 'POST', '/api/hosts/serveur-inexistant/refresh', MUTATE)[0], 404)
        self.assertEqual(call(self.app, 'POST', '/api/network/hosts/serveur-inexistant/refresh', MUTATE)[0], 404)
        # Intervalle refusé AVANT toute écriture du réglage.
        status, _, body = call(self.app, 'POST', '/api/monitoring', MUTATE, b'{"interval": 7}')
        self.assertEqual(status, 422)
        self.assertIn('Intervalle autorisé', body)
        status, _, body = call(self.app, 'GET', '/api/runtime')
        self.assertEqual(status, 200)
        self.assertIn('ssh_client_found', json.loads(body))
        self.assertIn('key_permissions', json.loads(body))

    def test_runtime_permissions_are_read_only_and_explicit(self):
        # Audit UI du 31/10 (fiche 16.2) : droits lus sans modification, limite Windows annoncée.
        import tempfile
        from routers import system
        with tempfile.TemporaryDirectory() as folder:
            key = Path(folder) / 'id_test'
            key.write_text('x', encoding='utf-8')
            self.assertEqual(system.permissions(Path(folder) / 'absente', 0o077), 'absent')
            with mock.patch.object(system.os, 'name', 'nt'):
                self.assertEqual(system.permissions(key, 0o077), 'non vérifiés (ACL Windows)')
            with mock.patch.object(system.os, 'name', 'posix'), mock.patch.object(system.stat, 'S_IMODE', return_value=0o644):
                self.assertEqual(system.permissions(key, 0o077), 'trop ouverts')
            with mock.patch.object(system.os, 'name', 'posix'), mock.patch.object(system.stat, 'S_IMODE', return_value=0o600):
                self.assertEqual(system.permissions(key, 0o077), 'restreints')
        status, headers, _ = call(self.app, 'GET', '/api/overview')
        self.assertEqual(status, 200)
        self.assertTrue(headers['content-type'].startswith('application/json'))

    def test_router_reads_context_at_call_time(self):
        from unittest import mock
        fake = [{'key': 'a', 'name': 'Source factice', 'provider': 'Proxmox', 'auth_configured': False}]
        with mock.patch.object(self.module, 'api_connections', lambda: fake):
            self.assertEqual(self.module.overview()['missing_auth'], ['Source factice'])

    def test_missing_inventory_report_does_not_require_local_data(self):
        import tempfile
        from types import SimpleNamespace
        from unittest import mock
        from routers import system
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(system, 'context', SimpleNamespace(BASE=Path(directory))):
                report = system.inventory_report()
        self.assertFalse(report['available'])
        self.assertIn('non généré', report['policy'])
        self.assertNotIn('hosts', report)


if __name__ == '__main__':
    unittest.main()
