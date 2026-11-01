from routers import all_routes  # routes des APIRouter inclus (FastAPI ne les recopie plus dans app.routes)
import json
import ssl
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import sqlite3
from fastapi import FastAPI, HTTPException
from pydantic import ValidationError
import management as m


class ManagementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        (base/'hosts.yaml').write_text(json.dumps({'ssh': {'user': 'test'}, 'hosts': []}))
        @contextmanager
        def connect():
            db = sqlite3.connect(base/'test.db')
            try:
                with db:
                    for table in ('network', 'states', 'history'):
                        db.execute(f'CREATE TABLE IF NOT EXISTS {table}(key TEXT)')
                    yield db
            finally:
                db.close()
        self.context = SimpleNamespace(BASE=base, HOSTS=[], lock=threading.Lock(), net_lock=threading.Lock(), job={'running':False}, net_job={'running':False}, connect=connect)
        app = FastAPI()
        m.install(app, self.context)
        self.routes = {(r.path, next(iter(r.methods))):r.endpoint for r in all_routes(app) if r.path.startswith('/api/')}

    def call(self, path, *args, method='POST'):
        return self.routes[path, method](*args)

    def test_bacula_php_dom_error_is_precise_and_preserves_last_success(self):
        from unittest.mock import Mock
        self.call('/api/connections', m.Connection(key='bacula-dom', name='Bacula', provider='Bacula',
                                                  url='https://bacula.test/api/v2/jobs'))
        target = self.context.BASE/'data/api-connections.json'
        items = json.loads(target.read_text())
        items[0]['last_success_result'] = {'status': 'observed', 'inventory': {'jobs': []}}
        target.write_text(json.dumps(items))
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=None)
        response.read.return_value = b'<!DOCTYPE html><html>Prado\\Exceptions\\TInvalidOperationException: DOMDocument /private/path</html>'
        opener = Mock()
        opener.open.return_value = response
        with patch.object(m, 'api_opener', return_value=opener):
            result = self.call('/api/connections/{key}/collect', 'bacula-dom')
        self.assertEqual(result['status'], 'unknown')
        self.assertEqual(result['error_kind'], 'bacula_php_dom')
        self.assertNotIn('/private/path', result['error'])
        self.assertNotIn('URL cible', result['error'])
        self.assertEqual(json.loads(target.read_text())[0]['last_success_result']['status'], 'observed')

    def test_bacula_json_data_containing_dom_text_is_not_misclassified(self):
        from unittest.mock import Mock
        self.call('/api/connections', m.Connection(key='bacula-json', name='Bacula', provider='Bacula',
                                                  url='https://bacula.test/api/v2/jobs'))
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=None)
        response.read.return_value = b'{"error":0,"output":[],"note":"DOMDocument TInvalidOperationException"}'
        opener = Mock()
        opener.open.return_value = response
        with patch.object(m, 'api_opener', return_value=opener):
            result = self.call('/api/connections/{key}/collect', 'bacula-json')
        self.assertEqual(result['status'], 'observed')

    def test_bacula_window_requested_then_full_read_when_window_is_not_conclusive(self):
        # Audit UI du 31/10 (fiche 09.3) : fenêtre limitée construite par le code, URL configurée
        # inchangée ; une fenêtre qui ne recouvre pas l'inventaire déclenche une lecture complète.
        from unittest.mock import Mock
        from datetime import datetime, timezone
        self.call('/api/connections', m.Connection(key='bacula-win', name='Bacula', provider='Bacula',
                                                  url='https://bacula.test/api/v2/jobs'))
        target = self.context.BASE/'data/api-connections.json'
        items = json.loads(target.read_text())
        base = {'jobs': [], 'latest': [], 'counts': {}, 'jobs_count': 3, 'max_jobid': 3,
                'full_at': datetime.now(timezone.utc).isoformat()}
        items[0]['last_result'] = {'status': 'observed', 'inventory': base}
        target.write_text(json.dumps(items))
        urls = []

        def answer(request, timeout=None):
            urls.append(request.full_url)
            rows = ([{'jobid': 9, 'name': 'B', 'jobstatus': 'T'}] if 'limit=' in request.full_url
                    else [{'jobid': i, 'name': 'B', 'jobstatus': 'T'} for i in range(1, 10)])
            body = json.dumps({'error': 0, 'output': [] if 'clients' in request.full_url else rows}).encode()
            response = Mock()
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=None)
            response.read.return_value = body
            return response
        opener = Mock()
        opener.open.side_effect = answer
        with patch.object(m, 'api_opener', return_value=opener):
            result = self.call('/api/connections/{key}/collect', 'bacula-win')
        self.assertEqual(urls[0], 'https://bacula.test/api/v2/jobs?limit=500')
        self.assertIn('https://bacula.test/api/v2/jobs', urls[2:])
        self.assertEqual(result['status'], 'observed')
        self.assertIn('trou possible', result['collection_note'])
        stored = json.loads(target.read_text(encoding='utf-8'))[0]['last_result']['inventory']
        self.assertEqual((stored['jobs_count'], stored['collection']), (9, 'complète'))
        self.assertIn('window_unsupported_at', stored)

    def test_connection_identity_change_discards_old_observation(self):
        connection = m.Connection(key='api', name='API', provider='JSON', url='https://example.test/a')
        self.call('/api/connections', connection)
        target = self.context.BASE/'data/api-connections.json'
        stored = json.loads(target.read_text())
        stored[0].update(last_result={'status':'observed'}, last_success_result={'status':'observed'})
        target.write_text(json.dumps(stored))
        renamed = self.call('/api/connections', connection.model_copy(update={'name':'Renamed'}))
        self.assertIn('last_result', renamed)
        moved = self.call('/api/connections', connection.model_copy(update={'url':'https://example.test/b'}))
        self.assertNotIn('last_result', moved)
        self.assertNotIn('last_success_result', moved)

    def test_connections_can_be_filtered_and_compacted_server_side(self):
        self.call('/api/connections', m.Connection(key='pve', name='PVE', provider='Proxmox', url='https://pve.test'))
        self.call('/api/connections', m.Connection(key='bacula', name='Bacula', provider='Bacula', url='https://bacula.test'))
        target = self.context.BASE/'data/api-connections.json'
        stored = json.loads(target.read_text())
        stored[0]['last_result'] = {'status': 'observed', 'collected_at': '2026-01-01T00:00:00Z',
                                    'summary': {'bytes': 42}, 'inventory': {'large': ['payload']}}
        target.write_text(json.dumps(stored))
        endpoint = self.routes['/api/connections', 'GET']
        interne = SimpleNamespace(state=SimpleNamespace())  # hors middleware : appel interne, complet
        filtered = endpoint(interne, provider='Proxmox')
        self.assertEqual([item['key'] for item in filtered], ['pve'])
        compact = endpoint(interne, provider='Proxmox', compact=True)
        self.assertEqual(compact[0]['last_result']['summary'], {'bytes': 42})
        self.assertNotIn('inventory', compact[0]['last_result'])
        self.assertGreaterEqual(self.context.api_change()['revision'], 2)
        # Lecteur et opérateur : résultats visibles, configuration d'administration retirée.
        for role in ('viewer', 'operator'):
            lecteur = SimpleNamespace(state=SimpleNamespace(principal={'role': role}))
            item = endpoint(lecteur, provider='Proxmox')[0]
            self.assertEqual(item['last_result']['status'], 'observed')
            for champ in ('url', 'ca_bundle', 'token_env'):
                self.assertNotIn(champ, item)
        admin = SimpleNamespace(state=SimpleNamespace(principal={'role': 'admin'}))
        self.assertEqual(endpoint(admin, provider='Proxmox')[0]['url'], 'https://pve.test')
        # Appels internes (context.api_connections) : toujours complets.
        self.assertIn('url', self.context.api_connections()[0])

    def test_inventory_persists_and_preserves_metadata(self):
        self.call('/api/manage/hosts', m.Server(key='test', name='Test', ip='10.77.0.200'))
        self.context.HOSTS[0]['node'] = 'pve01'
        self.call('/api/manage/hosts', m.Server(key='test', name='Updated', ip='10.77.0.200', services=['nginx']))
        saved = json.loads((self.context.BASE/'hosts.yaml').read_text())
        self.assertEqual(saved['hosts'][0]['node'], 'pve01')
        self.assertEqual(saved['hosts'][0]['services'], ['nginx'])
        self.call('/api/manage/hosts/{key}/delete', 'test')
        self.assertEqual(self.context.HOSTS, [])

    def test_inventory_changes_target_selected_file(self):
        local = self.context.BASE / 'hosts.yaml'
        selected = self.context.BASE / 'external.yaml'
        original = local.read_bytes()
        selected.write_bytes(original)
        self.context.INVENTORY = selected
        self.call('/api/manage/hosts', m.Server(key='demo', name='Démo', ip='192.0.2.10'))
        self.assertEqual(local.read_bytes(), original)
        self.assertEqual(json.loads(selected.read_text())['hosts'][0]['key'], 'demo')

    def test_duplicate_and_busy_rejected(self):
        self.call('/api/manage/hosts', m.Server(key='a', name='A', ip='10.77.0.200'))
        with self.assertRaises(HTTPException):
            self.call('/api/manage/hosts', m.Server(key='b', name='B', ip='10.77.0.200'))
        self.context.net_job['running'] = True
        with self.assertRaises(HTTPException):
            self.call('/api/manage/hosts/{key}/delete', 'a')

    def test_save_accepted_during_collection_applies_next_batch(self):
        # Audit A1 : pendant une collecte SSH ou réseau, l'enregistrement est accepté et dit
        # qu'il s'applique au lot suivant ; le lot en cours garde sa copie figée.
        self.call('/api/manage/hosts', m.Server(key='a', name='A', ip='10.77.0.200'))
        self.context.job['running'] = True
        item = self.call('/api/manage/hosts', m.Server(key='a', name='A', ip='10.77.0.201', mode='update'))
        self.assertEqual((item['ip'], item['applies'], item['saved']), ('10.77.0.201', 'next_batch', True))
        self.assertIn('prochain lot', item['message'])
        self.context.job['running'], self.context.net_job['running'] = False, True
        created = self.call('/api/manage/hosts', m.Server(key='nouveau', name='N', ip='10.77.0.202', mode='create'))
        self.assertEqual(created['applies'], 'next_batch')
        self.assertEqual([h['key'] for h in self.context.HOSTS], ['a', 'nouveau'])

    def test_create_never_overwrites_existing_key(self):
        # Audit A2 : « Original, 192.0.2.10 » ne devient plus « Nouveau, 192.0.2.11 ».
        self.call('/api/manage/hosts', m.Server(key='srv', name='Original', ip='192.0.2.10', mode='create'))
        with self.assertRaises(HTTPException) as e:
            self.call('/api/manage/hosts', m.Server(key='srv', name='Nouveau', ip='192.0.2.11', mode='create'))
        self.assertEqual(e.exception.status_code, 409)
        self.assertIn('Original', e.exception.detail)
        self.assertEqual([(h['name'], h['ip']) for h in self.context.HOSTS], [('Original', '192.0.2.10')])
        # Nouvelle tentative identique (double clic) : même résultat, aucun doublon.
        again = self.call('/api/manage/hosts', m.Server(key='srv', name='Original', ip='192.0.2.10', mode='create'))
        self.assertTrue(again['unchanged'])
        self.assertEqual(len(self.context.HOSTS), 1)

    def test_update_detects_concurrent_change_and_missing_server(self):
        self.call('/api/manage/hosts', m.Server(key='srv', name='A', ip='192.0.2.10'))
        revision = self.call('/api/manage/hosts/{key}', 'srv', method='GET')['revision']
        self.call('/api/manage/hosts', m.Server(key='srv', name='B', ip='192.0.2.10', mode='update', revision=revision))
        with self.assertRaises(HTTPException) as e:
            self.call('/api/manage/hosts', m.Server(key='srv', name='C', ip='192.0.2.10', mode='update', revision=revision))
        self.assertEqual(e.exception.status_code, 409)
        self.assertEqual(self.context.HOSTS[0]['name'], 'B')
        with self.assertRaises(HTTPException) as e:
            self.call('/api/manage/hosts', m.Server(key='absent', name='X', ip='192.0.2.20', mode='update'))
        self.assertEqual(e.exception.status_code, 404)
        self.assertEqual(len(self.context.HOSTS), 1)

    def test_port_inherited_from_ssh_profile_is_preserved(self):
        # Audit A3 : port global 3300 ; modifier seulement le nom ne fige pas le port à 22.
        import config
        from ssh import SSHConfig
        self.context.cfg = SSHConfig(user='audit', key_path='~/.ssh/id', port=3300, users=('audit',), ports=(3300,))
        self.call('/api/manage/hosts', m.Server(key='srv', name='A', ip='192.0.2.10', mode='create'))
        view = self.call('/api/manage/hosts/{key}', 'srv', method='GET')
        self.assertNotIn('port', view['host'])
        self.assertEqual((view['effective']['ports'], view['effective']['port_origin']), ([3300], 'profil'))
        self.call('/api/manage/hosts', m.Server(key='srv', name='Renommé', ip='192.0.2.10', mode='update',
                                                revision=view['revision']))
        saved = json.loads((self.context.BASE/'hosts.yaml').read_text())['hosts'][0]
        self.assertNotIn('port', saved)
        self.assertEqual([c.port for c in config.candidates(self.context.cfg, saved)], [3300])
        # Port spécifique explicite : conservé et annoncé comme tel.
        self.call('/api/manage/hosts', m.Server(key='srv', name='Renommé', ip='192.0.2.10', port=2222))
        view = self.call('/api/manage/hosts/{key}', 'srv', method='GET')
        self.assertEqual((view['effective']['ports'], view['effective']['port_origin']), ([2222], 'serveur'))
        self.assertEqual(self.call('/api/manage/ssh-profile', method='GET')['effective']['ports'], [3300])

    def test_cache_failure_after_save_is_reported_not_refused(self):
        # Audit A4 : SQLite en panne APRÈS l'écriture de hosts.yaml : pas d'annonce d'échec.
        @contextmanager
        def broken():
            raise sqlite3.OperationalError('database is locked')
            yield
        self.context.connect = broken
        item = self.call('/api/manage/hosts', m.Server(key='srv', name='A', ip='192.0.2.10', mode='create'))
        self.assertTrue(item['saved'])
        self.assertTrue(item['sync_pending'])
        self.assertIn('en attente', item['message'])
        self.assertEqual(json.loads((self.context.BASE/'hosts.yaml').read_text())['hosts'][0]['key'], 'srv')
        removed = self.call('/api/manage/hosts/{key}/delete', 'srv')
        self.assertTrue(removed['sync_pending'])
        self.assertEqual(self.context.HOSTS, [])

    def test_admin_added_server_is_enrolled_without_ssh_proof(self):
        # Audit A5 : visible tout de suite dans le parc, sans preuve SSH ni Proxmox.
        import asset_registry
        item = self.call('/api/manage/hosts', m.Server(key='srv', name='A', ip='192.0.2.10', environment='PREPROD', mode='create'))
        self.assertTrue(item['admin_enrolled_at'])
        self.assertTrue(asset_registry.admitted(dict(self.context.HOSTS[0])))
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        annotated = asset_registry.annotate(db, [dict(self.context.HOSTS[0])])
        self.assertTrue(annotated[0]['registered'])
        # Une simple modification ne change pas la date d'inscription.
        again = self.call('/api/manage/hosts', m.Server(key='srv', name='B', ip='192.0.2.10', environment='PREPROD'))
        self.assertEqual(again['admin_enrolled_at'], item['admin_enrolled_at'])

    def test_retry_identical_create_retries_pending_cache(self):
        request = m.Server(key='retry', name='Fixture', ip='192.0.2.30', mode='create')
        with patch.object(self.context, 'connect', side_effect=sqlite3.OperationalError('fixture')):
            first = self.call('/api/manage/hosts', request)
            second = self.call('/api/manage/hosts', request)
        self.assertTrue(first['saved'])
        self.assertTrue(second['unchanged'])
        self.assertTrue(second['sync_pending'], 'le conflit de cache existe encore')
        done = self.call('/api/manage/hosts', request)
        self.assertFalse(done['sync_pending'])
        self.assertEqual(len(self.context.HOSTS), 1)

    def test_retry_identical_update_after_lost_response(self):
        self.call('/api/manage/hosts', m.Server(key='retry', name='A', ip='192.0.2.30', mode='create'))
        version = self.call('/api/manage/hosts/{key}', 'retry', method='GET')['revision']
        request = m.Server(key='retry', name='B', ip='192.0.2.30', mode='update', revision=version)
        self.call('/api/manage/hosts', request)
        self.assertTrue(self.call('/api/manage/hosts', request)['unchanged'])
        self.assertEqual(self.context.HOSTS[0]['name'], 'B')

    def test_configuration_reads_are_admin_only(self):
        import access_policy
        from test_access_policy import SECRET, call, proxy
        guarded = FastAPI()
        access_policy.install(guarded)
        m.install(guarded, self.context)
        with patch.dict('os.environ', {'INFRAOPS_TRUSTED_PROXY_SECRET': SECRET,
                        'INFRAOPS_ADMINS': 'admin', 'INFRAOPS_OPERATORS': 'operator'}):
            for name in ('viewer', 'operator'):
                for path in ('/api/manage/ssh-profile', '/api/manage/hosts/absent'):
                    self.assertEqual(call(guarded, 'GET', path, proxy(name))[0], 403)
            self.assertEqual(call(guarded, 'GET', '/api/manage/ssh-profile', proxy('admin'))[0], 200)

    def test_ip_spaces_normalized_and_dns_rejected_clearly(self):
        server = m.Server(key=' srv ', name=' A ', ip=' 192.0.2.10 ')
        self.assertEqual((server.key, server.name, server.ip), ('srv', 'A', '192.0.2.10'))
        with self.assertRaises(ValidationError) as e:
            m.Server(key='srv', name='A', ip='srv.example.test')
        self.assertIn('nom DNS', str(e.exception))

    def test_validation(self):
        for ip in ('bad', '10.77.0.1;id'):
            with self.assertRaises(ValidationError):m.Server(key='a', name='A', ip=ip)
        with self.assertRaises(ValidationError):m.Server(key='a', name='A', ip='127.0.0.1', services=['nginx;id'])
        for url in ('http://example.org', 'https://user:secret@example.org', 'https://example.org/?token=secret'):
            with self.assertRaises(ValidationError):m.Connection(key='a', name='A', url=url)

    def test_waf_command_preview(self):
        self.context.HOSTS.append({'key': 'waf01', 'ip': '10.77.0.131', 'role': 'WAF ModSecurity'})
        preview=self.call('/api/waf/commands',m.WafCommand(ip='192.0.2.1',action='ban',host_key='waf01'))
        self.assertFalse(preview['executable'])
        self.assertEqual(preview['execution_host'],'10.77.0.131')
        with self.assertRaises(HTTPException):
            self.call('/api/waf/commands',m.WafCommand(ip='192.0.2.1; id',action='ban',host_key='waf01'))

    def test_waf_command_rejects_non_waf_host(self):
        self.context.HOSTS.append({'key': 'app01', 'ip': '10.77.0.9', 'role': 'À renseigner'})
        with self.assertRaises(HTTPException):
            self.call('/api/waf/commands',m.WafCommand(ip='192.0.2.1',action='ban',host_key='app01'))
        with self.assertRaises(HTTPException):
            self.call('/api/waf/commands',m.WafCommand(ip='192.0.2.1',action='ban',host_key='inconnu'))

    def test_ssl_context_for_routes_pinned_vs_file_vs_default(self):
        self.assertIsInstance(m.ssl_context_for({'ca_bundle': ''}), ssl.SSLContext)
        with self.assertRaises(FileNotFoundError):
            m.ssl_context_for({'ca_bundle': str(self.context.BASE / 'missing.pem')})
        with self.assertRaises(ssl.SSLError):
            m.ssl_context_for({'ca_bundle': '-----BEGIN CERTIFICATE-----\nbm90cmVhbA==\n-----END CERTIFICATE-----'})

    def test_pinned_certificate_keeps_full_verification(self):
        """Épingler ne doit jamais désactiver une vérification.

        Un certificat auto-signé sans CA:TRUE est une ancre légitime pour le
        serveur qui le présente (OpenSSL l'accepte) : on ne le pré-refuse plus.
        Mais chaîne, nom d'hôte et validité restent contrôlés.
        """
        # Fixture versionnée (certificat public seul, CN/SAN exemple.test, CA:FALSE,
        # valable jusqu'en 2126) : le test ne dépend plus d'openssl.exe sur le PATH.
        pem = Path(__file__).resolve().parent / 'test_fixtures/tls/leaf-exemple-test.pem'
        text = pem.read_text(encoding='ascii')
        self.assertNotIn('PRIVATE KEY', text)
        for source in (text, str(pem)):  # PEM collé ou chemin de fichier .pem
            context = m.ssl_context_for({'ca_bundle': source})
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(context.check_hostname)
            # get_ca_certs() ne liste que les certificats CA:TRUE ; la feuille épinglée compte dans le magasin.
            self.assertEqual(context.cert_store_stats()['x509'], 1)

    def test_certificate_fixture_can_be_regenerated_when_openssl_exists(self):
        """Régénération facultative : absence d'openssl = test ignoré, jamais en échec."""
        import shutil
        import subprocess
        import tempfile
        openssl = shutil.which('openssl')
        if not openssl:
            self.skipTest('openssl absent du PATH : la fixture versionnée suffit')
        with tempfile.TemporaryDirectory() as tmp:
            try:
                generated = subprocess.run(
                    [openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-days', '2', '-nodes',
                     '-keyout', 'k.pem', '-out', 'c.pem', '-subj', '/CN=exemple.test',
                     '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'subjectAltName=DNS:exemple.test'],
                    capture_output=True, timeout=60, cwd=tmp)
            except (OSError, subprocess.TimeoutExpired):
                self.skipTest('openssl non exécutable dans cet environnement')
            if generated.returncode != 0:
                self.skipTest('openssl présent mais génération refusée : ' + generated.stderr.decode(errors='replace')[-120:])
            self.assertEqual(m.ssl_context_for({'ca_bundle': (Path(tmp) / 'c.pem').read_text()}).verify_mode, ssl.CERT_REQUIRED)

    def test_connection_ca_bundle_rejects_incomplete_pem(self):
        with self.assertRaises(ValidationError):
            m.Connection(key='a', name='A', url='https://example.org', ca_bundle='-----BEGIN CERTIFICATE-----\nnotclosed')

    def test_probe_certificate_fingerprint_and_graceful_fallback(self):
        fake_der = b'not-a-real-certificate-but-bytes'
        class FakeSock:
            def __enter__(self): return self
            def __exit__(self, *a): return False
        class FakeSSLSock(FakeSock):
            def getpeercert(self, binary_form=False):
                return fake_der if binary_form else {}
        class FakeUnverifiedCtx:
            def wrap_socket(self, sock, server_hostname=None): return FakeSSLSock()
        with patch.object(m, 'connect_checked', return_value=FakeSock()), \
             patch.object(m.ssl, '_create_unverified_context', return_value=FakeUnverifiedCtx()):
            result = m.probe_certificate('example.test', 443)
        self.assertEqual(result['hostname'], 'example.test')
        self.assertEqual(result['sha256_fingerprint'].count(':'), 31)
        self.assertIsNone(result['subject_cn'])

    def test_certificate_endpoint_rejects_non_https(self):
        with self.assertRaises(HTTPException):
            self.call('/api/connections/certificate', m.CertificateProbe(url='http://example.org'))

    def test_wazuh_token_exchange_and_bad_credentials(self):
        response = unittest.mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"data":{"token":"jwt-abc"}}'
        opener = unittest.mock.MagicMock()
        opener.open.return_value = response
        with patch.object(m.urllib.request, 'build_opener', return_value=opener):
            token = m.wazuh_token('https://wazuh.example:55000/manager/status', 'wazuh-wui:secret', m.ssl.create_default_context(), 10)
        self.assertEqual(token, 'jwt-abc')
        sent_request = opener.open.call_args.args[0]
        self.assertEqual(sent_request.full_url, 'https://wazuh.example:55000/security/user/authenticate')
        self.assertTrue(sent_request.get_header('Authorization').startswith('Basic '))
        with self.assertRaises(ValueError):
            m.wazuh_token('https://wazuh.example:55000/manager/status', 'no-colon', m.ssl.create_default_context(), 10)

    def test_wazuh_collection_reauthenticates_every_time(self):
        self.call('/api/connections', m.Connection(key='waz', name='Waz', provider='Wazuh', url='https://wazuh.example:55000/manager/status', token_env='INFRAOPS_WAZUH_AUTH_TEST'))
        auth_response = unittest.mock.MagicMock()
        auth_response.__enter__.return_value.read.return_value = b'{"data":{"token":"fresh-jwt"}}'
        data_response = unittest.mock.MagicMock()
        data_response.__enter__.return_value.read.return_value = b'{"data":{"affected_items":[{"status":"running"}]}}'
        opener = unittest.mock.MagicMock()
        opener.open.side_effect = [auth_response, data_response]
        with patch.dict('os.environ', {'INFRAOPS_WAZUH_AUTH_TEST': 'wazuh-wui:secret'}), \
             patch.object(m.urllib.request, 'build_opener', return_value=opener):
            result = self.call('/api/connections/{key}/collect', 'waz')
        self.assertEqual(result['status'], 'observed')
        second_call_headers = opener.open.call_args_list[1].args[0].headers
        self.assertEqual(second_call_headers.get('Authorization'), 'Bearer fresh-jwt')
        self.assertNotIn('secret', json.dumps(result))

    def test_api_collect_and_secret_exclusion(self):
        self.call('/api/connections', m.Connection(key='elastic', name='Elastic', provider='Elasticsearch', url='https://example.org/_cluster/health'))
        response = unittest.mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"status":"yellow","number_of_nodes":3,"token":"private"}'
        opener = unittest.mock.MagicMock()
        opener.open.return_value = response
        with patch.object(m.urllib.request, 'build_opener', return_value=opener):
            result = self.call('/api/connections/{key}/collect', 'elastic')
        self.assertEqual(result['indicators']['cluster_status'], 'yellow')
        self.assertNotIn('private', json.dumps(result))
        self.assertEqual(opener.open.call_args.args[0].get_method(), 'GET')

    def test_relative_ca_bundle_result_is_saved(self):
        # OC-AUDIT-009 : la CA relative rendue absolue pour le transport faisait échouer la
        # comparaison avec la configuration enregistrée : last_result et révision figés.
        (self.context.BASE / 'data' / 'ca').mkdir(parents=True)
        (self.context.BASE / 'data' / 'ca' / 'root.pem').write_text('fixture')
        self.call('/api/connections', m.Connection(key='es', name='ES', provider='Elasticsearch',
                                                   url='https://es.test/_cluster/health', ca_bundle='root.pem'))
        before = self.context.api_change()['revision']
        response = unittest.mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"status":"green","number_of_nodes":3}'
        opener = unittest.mock.MagicMock()
        opener.open.return_value = response
        with patch.object(m, 'ssl_context_for', return_value=m.ssl.create_default_context()) as tls, \
                patch.object(m.urllib.request, 'build_opener', return_value=opener):
            self.call('/api/connections/{key}/collect', 'es')
        self.assertEqual(Path(tls.call_args.args[0]['ca_bundle']), self.context.BASE / 'data' / 'ca' / 'root.pem')
        saved = self.call('/api/connections', SimpleNamespace(state=SimpleNamespace()), method='GET')
        self.assertEqual(saved[0]['ca_bundle'], 'root.pem', 'configuration enregistrée inchangée')
        self.assertEqual(saved[0]['last_result']['status'], 'observed')
        self.assertGreater(self.context.api_change()['revision'], before)

    def test_non_finite_or_boolean_indicators_never_break_connections_list(self):
        # OC-AUDIT-020 : NaN / Infinity / booléens d'une source → erreur de CETTE source, liste toujours JSON valide.
        from fastapi.encoders import jsonable_encoder
        from starlette.responses import JSONResponse
        self.assertEqual(m.indicators('Elasticsearch', {'active_shards': float('nan'), 'number_of_nodes': True,
                                                        'unassigned_shards': -1, 'number_of_data_nodes': float('inf'),
                                                        'active_shards_percent_as_number': 250, 'status': 'green'}),
                         {'cluster_status': 'green'})
        self.call('/api/connections', m.Connection(key='es', name='ES', provider='Elasticsearch', url='https://es.test/_cluster/health'))
        self.call('/api/connections', m.Connection(key='ok', name='OK', provider='Elasticsearch', url='https://ok.test/_cluster/health'))
        for key, body in (('es', b'{"status":"green","active_shards":NaN,"number_of_nodes":true}'),
                          ('ok', b'{"status":"yellow","active_shards":12,"number_of_nodes":3}')):
            response = unittest.mock.MagicMock()
            response.__enter__.return_value.read.return_value = body
            opener = unittest.mock.MagicMock()
            opener.open.return_value = response
            with patch.object(m.urllib.request, 'build_opener', return_value=opener):
                self.call('/api/connections/{key}/collect', key)
        saved = {c['key']: c for c in self.call('/api/connections', SimpleNamespace(state=SimpleNamespace()), method='GET')}
        self.assertEqual(saved['es']['last_result']['status'], 'unknown')
        self.assertEqual(saved['ok']['last_result']['indicators'], {'active_shards': 12, 'number_of_nodes': 3, 'cluster_status': 'yellow'})
        JSONResponse(jsonable_encoder(list(saved.values())))   # lèverait ValueError sur un NaN enregistré

    def test_api_failure_not_ok(self):
        self.call('/api/connections', m.Connection(key='a', name='A', url='https://example.org'))
        with patch.object(m.urllib.request, 'build_opener', side_effect=OSError('secret')):
            result = self.call('/api/connections/{key}/collect', 'a')
        self.assertEqual(result['status'], 'unknown')
        self.assertNotIn('secret', json.dumps(result))

    def test_collecteur_refuse_un_changement_dns_vers_la_boucle_locale(self):
        self.call('/api/connections', m.Connection(key='rebind', name='Fixture', provider='JSON',
                  url='https://fixture.test/data', token_env='INFRAOPS_JSON_AUTH_FIXTURE'))
        replies = [[(2, 1, 6, '', ('10.0.0.2', 443))], [(2, 1, 6, '', ('127.0.0.1', 443))]]
        with patch.dict('os.environ', {'INFRAOPS_JSON_AUTH_FIXTURE': 'identifiant-simule'}), \
                patch('socket.getaddrinfo', side_effect=replies), patch('socket.socket') as create:
            result = self.call('/api/connections/{key}/collect', 'rebind')
        self.assertEqual(result['status'], 'unknown')
        self.assertEqual(result['error_kind'], 'destination')
        self.assertNotIn('identifiant-simule', json.dumps(result))
        create.assert_not_called()

    def test_proxmox_collection_refreshes_network(self):
        from unittest.mock import Mock
        self.context.launch_network = Mock()
        self.call('/api/connections', m.Connection(key='pve-ping', name='PVE', provider='Proxmox',
                  url='https://pve.test/resources'))
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, *args): return b'{"data":[]}'
        opener = Mock()
        opener.open.return_value = Response()
        with patch.object(m.urllib.request, 'build_opener', return_value=opener):
            result = self.call('/api/connections/{key}/collect', 'pve-ping')
        self.assertEqual(result['status'], 'observed')
        self.context.launch_network.assert_called_once_with([], 'collecte-proxmox')

    def test_proxmox_details_persist(self):
        self.call('/api/connections',m.Connection(key='pve',name='Cluster',url='https://pve.example/api2/json/cluster/resources',provider='Proxmox'))
        response=unittest.mock.MagicMock()
        response.__enter__.return_value.read.return_value=b'{"data":[{"type":"qemu","vmid":101,"node":"pve01","name":"web","status":"running"}]}'
        opener=unittest.mock.MagicMock();opener.open.return_value=response
        with patch.object(m.urllib.request,'build_opener',return_value=opener):
            result=self.call('/api/connections/{key}/collect','pve')
        self.assertEqual(result['inventory']['nodes'][0]['guests'][0]['vmid'],101)
        saved=self.call('/api/connections',SimpleNamespace(state=SimpleNamespace()),method='GET')
        self.assertEqual(saved[0]['last_result']['inventory'],result['inventory'])


if __name__ == '__main__':
    unittest.main()
