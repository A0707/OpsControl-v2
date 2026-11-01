"""OpsControl V2 : synthèse cockpit, compatibilité et garantie de lecture seule."""
from routers import all_routes  # routes des APIRouter inclus (FastAPI ne les recopie plus dans app.routes)
import ast
import json
import re
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import cockpit_v2

BASE = Path(__file__).resolve().parent
NOW = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)
SECRET = 'SECRET-V2-NE-DOIT-PAS-SORTIR'


def at(minutes):
    return (NOW - timedelta(minutes=minutes)).isoformat()


def proxmox(status='observed', minutes=1, **extra):
    return {'key': 'pve', 'name': 'PVE', 'provider': 'Proxmox', 'auth_configured': True,
            'last_result': {'status': status, 'collected_at': at(minutes), 'password': SECRET,
                            'inventory': {'nodes_count': 2, 'nodes': [{'name': 'n1', 'token': SECRET}],
                                          'counts': {'running': 3, 'stopped': 1, 'qemu': 4, 'secret': SECRET},
                                          'summary': {'nodes_online': 2, 'cpu_pct': 12.5, 'memory_bytes': 10,
                                                      'memory_total_bytes': 20, 'api_key': SECRET},
                                          'cluster': {'name': 'C', 'quorate': True, 'ticket': SECRET},
                                          'scope': 'Ressources visibles'}, **extra}}


class CockpitSummaryTests(unittest.TestCase):
    def test_whitelist_never_leaks_unexpected_fields(self):
        result = cockpit_v2.build([proxmox()], NOW)
        text = json.dumps(result)
        self.assertNotIn(SECRET, text)
        self.assertNotIn('nodes', result['sources'][0]['detail'])  # inventaire complet jamais renvoyé
        detail = result['sources'][0]['detail']
        self.assertEqual(detail['capacity']['cpu_pct'], 12.5)
        self.assertTrue(detail['quorate'])
        self.assertEqual(set(detail['counts']), {'qemu', 'lxc', 'running', 'stopped', 'unknown', 'storage', 'storage_unavailable'})

    def test_fresh_stale_and_retained_states(self):
        row = cockpit_v2.summarize(proxmox(minutes=5), NOW)
        self.assertEqual((row['status'], row['fresh']), ('observed', True))
        row = cockpit_v2.summarize(proxmox(minutes=60), NOW)
        self.assertEqual((row['status'], row['fresh']), ('observed', False))
        failed = {**proxmox(), 'last_success_result': proxmox()['last_result'],
                  'last_result': {'status': 'unknown', 'collected_at': at(0), 'error': 'Échec de vérification TLS.',
                                  'error_kind': 'tls_certificate'}}
        row = cockpit_v2.summarize(failed, NOW)
        self.assertEqual(row['status'], 'retained')
        self.assertFalse(row['fresh'], 'une donnée conservée après échec ne doit jamais être récente')
        self.assertEqual(row['error_kind'], 'tls_certificate')
        self.assertEqual(row['detail']['capacity']['cpu_pct'], 12.5)

    def test_permissions_error_without_data(self):
        row = cockpit_v2.summarize({'key': 'z', 'name': 'Z', 'provider': 'Zabbix',
                                    'last_result': {'status': 'unknown', 'collected_at': at(1), 'http_status': 403,
                                                    'error': 'Accès refusé (403)'}}, NOW)
        self.assertEqual((row['status'], row['fresh'], row['has_data'], row['detail']), ('unknown', False, False, None))
        self.assertEqual(row['http_status'], 403)

    def test_legacy_incomplete_payloads(self):
        legacy = [
            {'key': 'a', 'name': 'Jamais collecté', 'provider': 'Wazuh'},
            {'key': 'b', 'name': 'Ancien Bacula', 'provider': 'Bacula',
             'last_result': {'status': 'observed', 'collected_at': 'date illisible', 'inventory': {'jobs_count': 'x'}}},
            {'key': 'c', 'name': 'Elastic', 'provider': 'Elasticsearch',
             'last_result': {'status': 'observed', 'collected_at': at(1), 'indicators': {'cluster_status': 'purple', 'number_of_nodes': -3}}},
            {'key': 'd', 'name': 'Zabbix', 'provider': 'Zabbix',
             'last_result': {'status': 'observed', 'collected_at': at(1), 'inventory': {'counts': None}}},
        ]
        result = cockpit_v2.build(legacy, NOW)
        rows = {r['key']: r for r in result['sources']}
        self.assertFalse(rows['a']['fresh'])
        self.assertIsNone(rows['a']['detail'])
        self.assertIsNone(rows['b']['age_seconds'])
        self.assertFalse(rows['b']['fresh'])
        self.assertIsNone(rows['b']['detail']['jobs_count'])
        self.assertIsNone(rows['c']['detail']['cluster_status'])
        self.assertIsNone(rows['c']['detail']['number_of_nodes'], 'valeur négative non affichée comme mesure')
        self.assertIsNone(rows['d']['detail']['counts']['monitored'])
        self.assertEqual(result['missing_providers'], ['Proxmox'])

    def test_missing_measure_is_none_not_zero(self):
        row = cockpit_v2.summarize({'key': 'w', 'name': 'W', 'provider': 'Wazuh',
                                    'last_result': {'status': 'observed', 'collected_at': at(1),
                                                    'inventory': {'counts': {'running': 5}}}}, NOW)
        self.assertEqual(row['detail']['daemons']['running'], 5)
        self.assertIsNone(row['detail']['daemons']['failed'])
        self.assertIsNone(row['detail']['agents'])


class ReadOnlyGuaranteeTests(unittest.TestCase):
    """Aucun appel de mutation vers les produits supervisés."""

    def test_cockpit_module_makes_no_remote_call(self):
        source = (BASE / 'cockpit_v2.py').read_text(encoding='utf-8')
        for forbidden in ('urllib', 'requests', 'http.client', 'socket', 'subprocess', 'ssh'):
            self.assertNotRegex(source, r'\bimport\s+' + re.escape(forbidden))

    def test_only_documented_posts_in_collectors(self):
        tree = ast.parse((BASE / 'management.py').read_text(encoding='utf-8'))
        posts = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                for call in ast.walk(node):
                    if isinstance(call, ast.Call) and any(k.arg == 'method' for k in call.keywords):
                        method = next(k.value for k in call.keywords if k.arg == 'method')
                        posts.append((node.name, getattr(method, 'value', None)))
        # Seuls le JSON-RPC Zabbix (corps figés) et l'authentification Wazuh utilisent POST.
        self.assertEqual(sorted(set(posts)), [('rpc_request', 'POST'), ('wazuh_token', 'POST')])

    def test_zabbix_rpc_methods_are_read_only(self):
        import management
        methods = [body['method'] for _, body in management.READ_ONLY_RPC['Zabbix']['calls']]
        methods += re.findall(r"'method':\s*'([a-z]+\.[a-z]+)'", (BASE / 'zabbix_live.py').read_text(encoding='utf-8'))
        self.assertIn('host.get', methods)
        self.assertTrue(all(m.endswith('.get') for m in methods), methods)

    def test_frontend_has_no_proxmox_management_action(self):
        web = '\n'.join(p.read_text(encoding='utf-8') for p in (BASE / 'web').glob('*.js'))
        pattern = r'/status/(start|stop|reboot|shutdown|suspend|resume)|/migrate|(qm|pct) (start|stop|reboot|shutdown|migrate|destroy)'
        match = re.search(pattern, web)
        self.assertIsNone(match, match and match.group(0))

    def test_no_public_cdn_and_no_inline_style(self):
        html = (BASE / 'web/index.html').read_text(encoding='utf-8')
        self.assertNotRegex(html, r'(src|href)="https?://')
        for p in (BASE / 'web').glob('*.js'):
            self.assertNotIn('style="', p.read_text(encoding='utf-8'), p.name + ' : style en ligne bloqué par la CSP')

    def test_shell_extensions_loaded_last(self):
        html = (BASE / 'web/index.html').read_text(encoding='utf-8')
        # Ordre des scripts applicatifs : ceux du gabarit chargé par frontend-bootstrap.js.
        legacy = html.split('<template id="legacy-scripts">', 1)[1].split('</template>', 1)[0]
        scripts = re.findall(r'<script src="/([^"?]+)', legacy)
        self.assertEqual(scripts[0], 'app.js')
        # Démarrage (audit transversal du 01/11) : boot.js, synchrone, avant les feuilles de style.
        self.assertLess(html.index('<script src="/boot.js'), html.index('<link rel="stylesheet"'))
        self.assertEqual(scripts[-2:], ['v2.js', 'parc-next.js'])
        self.assertNotIn('v2-ui.js', scripts, 'composant ES importé par le point d’entrée')
        self.assertIn('<script type="module" src="/frontend-bootstrap.js', html)
        self.assertIn('<template id="legacy-scripts">', html)
        bootstrap = (BASE / 'web/frontend-bootstrap.js').read_text(encoding='utf-8')
        self.assertIn("from '/v2-ui.js", bootstrap)

    def test_premium_look_is_opt_in_and_loaded_last(self):
        # Apparence premium : feuille chargée en dernier, inerte tant que le poste ne l'a pas choisie.
        html = (BASE / 'web/index.html').read_text(encoding='utf-8')
        sheets = re.findall(r'<link rel="stylesheet" href="/([^"?]+)', html)
        self.assertEqual(sheets[-1], 'premium.css')
        css = (BASE / 'web/premium.css').read_text(encoding='utf-8')
        selectors = [s.strip() for s in re.findall(r'([^{};]+){', re.sub(r'/\*.*?\*/', '', css, flags=re.S))]
        global_rules = [s for s in selectors if not s.startswith(('@', ':root[data-look=premium]'))]
        self.assertTrue(global_rules and all(r.startswith('.oc-gauge') for r in global_rules), global_rules)
        self.assertNotIn('var(--v)', css, 'largeur par classe .v2-wN : style en ligne interdit par la CSP')
        self.assertIn("prefs.look === 'premium'", (BASE / 'web/boot.js').read_text(encoding='utf-8'))
        self.assertIn('data-v2-look', (BASE / 'web/v2.js').read_text(encoding='utf-8'))
        self.assertIn('oc-gauge" data-level="', (BASE / 'web/proxmox.js').read_text(encoding='utf-8'))

    def test_heavy_source_pages_are_lazy(self):
        html = (BASE / 'web/index.html').read_text(encoding='utf-8')
        app = (BASE / 'web/app.js').read_text(encoding='utf-8')
        for script, page in [('proxmox.js', 'Proxmox'), ('elastic.js', 'Elasticsearch'),
                             ('wazuh.js', 'Wazuh'), ('zabbix.js', 'Zabbix'),
                             ('shares.js', 'Partages')]:
            self.assertNotIn(f'<script src="/{script}', html)
            self.assertRegex(app, rf"{re.escape(page)}\s*:\s*'/{re.escape(script)}")

    def test_phase44_operational_modules_are_lazy(self):
        html = (BASE / 'web/index.html').read_text(encoding='utf-8')
        app = (BASE / 'web/app.js').read_text(encoding='utf-8')
        for script in ('storage.js', 'sync.js', 'inventory-completion.js', 'connections.js', 'api-help.js', 'connections-v2.js'):
            self.assertNotIn(f'<script src="/{script}', html)
            self.assertIn('/' + script, app)
        self.assertIn("detailRenderers.storage=storageView", (BASE / 'web/storage.js').read_text(encoding='utf-8'))
        self.assertNotRegex((BASE / 'web/storage.js').read_text(encoding='utf-8'), r'\b(?:render|detailView)\s*=')

    def test_phase45_v2_is_split_and_detail_is_lazy(self):
        html = (BASE / 'web/index.html').read_text(encoding='utf-8')
        shell = (BASE / 'web/v2.js').read_text(encoding='utf-8')
        dashboard = (BASE / 'web/v2-dashboard.js').read_text(encoding='utf-8')
        detail = (BASE / 'web/v2-detail.js').read_text(encoding='utf-8')
        self.assertIn('<script src="/v2-dashboard.js', html)
        self.assertNotIn('<script src="/v2-detail.js', html)
        self.assertIn("v2:'/v2-detail.js", (BASE / 'web/app.js').read_text(encoding='utf-8'))
        self.assertIn('function v2RefreshOps', dashboard)
        self.assertIn('function v2HostSummary', detail)
        self.assertNotIn('function v2HostSummary', shell)
        self.assertNotRegex(detail, r'\bdetailView\s*=')


class EndpointTests(unittest.TestCase):
    def test_endpoint_uses_recorded_connections_only(self):
        from fastapi import FastAPI

        class Context:
            @staticmethod
            def api_connections():
                return [proxmox(minutes=0)]

        app = FastAPI()
        cockpit_v2.install(app, Context)
        routes = {r.path: r for r in all_routes(app) if hasattr(r, 'methods')}
        self.assertEqual(routes['/api/v2/cockpit'].methods, {'GET'})
        body = routes['/api/v2/cockpit'].endpoint()
        self.assertTrue(body['read_only'])
        self.assertNotIn(SECRET, json.dumps(body))
        self.assertEqual(routes['/api/v2/version'].endpoint()['version'], '2.0')

if __name__ == '__main__':
    unittest.main()
