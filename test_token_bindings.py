"""Jetons API liés à leur hôte (SEC-01) et destinations interdites (SSRF)."""
from routers import all_routes  # routes des APIRouter inclus
import json
import sqlite3
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import FastAPI, HTTPException
from pydantic import ValidationError

import management as m


def response_for(body):
    handle = MagicMock()
    handle.__enter__.return_value.read.return_value = json.dumps(body).encode()
    return handle


def public_dns(host, port):
    return [(2, 1, 6, '', ('203.0.113.10', 0))]


class RegistreTests(unittest.TestCase):
    """Audit A2 : absent = premier usage ; illisible, corrompu ou mal structuré = refus."""

    def setUp(self):
        self.dossier = tempfile.TemporaryDirectory()
        self.addCleanup(self.dossier.cleanup)
        self.path = Path(self.dossier.name) / 'token-bindings.json'
        self.registre = m.TokenBindings(self.path)

    def refus(self):
        return self.registre.refusal('INFRAOPS_ZABBIX_AUTH', 'https://autre.example.test/api')

    def test_absent_vaut_premier_usage(self):
        self.assertIsNone(self.refus())
        self.registre.check_and_bind('INFRAOPS_ZABBIX_AUTH', 'https://zbx.example.test/api')
        self.assertIn('zbx.example.test:443', self.refus())

    def test_contenus_invalides_refuses_et_conserves(self):
        for contenu in ('{broken', '{"A": {"endpoint": "x:1"}', '[1, 2]', '{"A": "x:1"}',
                        '{"A": {"endpoint": 5}}', '{"A": {"endpoint": "pas de port"}}'):
            with self.subTest(contenu=contenu):
                self.path.write_text(contenu, encoding='utf-8')
                self.registre = m.TokenBindings(self.path)  # une trace par état et par instance
                with self.assertLogs('opscontrol.security', 'ERROR'):
                    self.assertIn('collectes authentifiées suspendues', self.refus())
                with self.assertRaises(ValueError):
                    self.registre.check_and_bind('INFRAOPS_ZABBIX_AUTH', 'https://autre.example.test/api')
                self.assertEqual(self.path.read_text(encoding='utf-8'), contenu)

    def test_fichier_illisible_refuse(self):
        self.path.write_text('{}', encoding='utf-8')
        with patch.object(Path, 'read_text', side_effect=PermissionError('refusé')),                 self.assertLogs('opscontrol.security', 'ERROR'):
            self.assertIn('illisible (PermissionError)', self.refus())

    def test_ipv6_et_sans_jeton(self):
        self.path.write_text('{"INFRAOPS_ZABBIX_AUTH": {"endpoint": "2001:db8::1:443"}}', encoding='utf-8')
        self.assertIn('2001:db8::1:443', self.refus())
        self.assertIsNone(self.registre.refusal(None, 'https://autre.example.test/api'))


class DestinationTests(unittest.TestCase):
    def test_adresses_interdites(self):
        for ip in ('127.0.0.1', '::1', '169.254.169.254', 'fe80::1%eth0', '0.0.0.0', '224.0.0.1'):
            self.assertTrue(m.forbidden_ip(ip), ip)
        for ip in ('10.1.2.3', '10.77.0.10', '203.0.113.10', 'pve.example'):
            self.assertFalse(m.forbidden_ip(ip), ip)

    def test_nom_resolu_vers_la_boucle_locale(self):
        local = lambda host, port: [(2, 1, 6, '', ('127.0.0.1', 0))]
        self.assertIsNotNone(m.destination_refused('https://piege.example/api', resolve=local))
        self.assertIsNone(m.destination_refused('https://pve.example:8006/api2/json', resolve=public_dns))

    def test_tunnel_bacula_seule_exception(self):
        self.assertIsNone(m.destination_refused(m.BACULA_TUNNEL_URL))

    def test_url_litterale_refusee_a_l_enregistrement(self):
        with self.assertRaises(ValidationError):
            m.Connection(key='x', name='X', provider='JSON', url='https://169.254.169.254/latest/meta-data')

    def test_endpoint(self):
        self.assertEqual(m.endpoint_of('https://PVE.example/api2/json'), 'pve.example:443')
        self.assertEqual(m.endpoint_of('https://pve.example:8006/x'), 'pve.example:8006')


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        (self.base / 'hosts.yaml').write_text(json.dumps({'ssh': {'user': 'test'}, 'hosts': []}))

        @contextmanager
        def connect():
            db = sqlite3.connect(self.base / 'test.db')
            try:
                with db:
                    yield db
            finally:
                db.close()

        context = SimpleNamespace(BASE=self.base, HOSTS=[], lock=threading.Lock(), net_lock=threading.Lock(),
                                  job={'running': False}, net_job={'running': False}, connect=connect)
        app = FastAPI()
        m.install(app, context)
        self.routes = {(r.path, next(iter(r.methods))): r.endpoint for r in all_routes(app) if r.path.startswith('/api/')}
        patcher = patch.object(m.socket, 'getaddrinfo', side_effect=public_dns)
        patcher.start()
        self.addCleanup(patcher.stop)

    def save(self, url):
        return self.routes['/api/connections', 'POST'](m.Connection(
            key='es', name='Elastic', provider='Elasticsearch', url=url, token_env='INFRAOPS_ELASTIC_AUTH_TEST'))

    def collect(self, opener):
        with patch.dict('os.environ', {'INFRAOPS_ELASTIC_AUTH_TEST': 'ApiKey secret-elastic'}), \
             patch.object(m.urllib.request, 'build_opener', return_value=opener):
            return self.routes['/api/connections/{key}/collect', 'POST']('es')

    def test_premier_usage_lie_puis_changement_d_hote_refuse(self):
        self.save('https://es.example:9200/_cluster/health')
        opener = MagicMock()
        opener.open.return_value = response_for({'status': 'green', 'number_of_nodes': 3})
        self.collect(opener)
        liaisons = json.loads((self.base / 'data/token-bindings.json').read_text(encoding='utf-8'))
        self.assertEqual(liaisons['INFRAOPS_ELASTIC_AUTH_TEST']['endpoint'], 'es.example:9200')
        self.assertNotIn('secret-elastic', json.dumps(liaisons))

        # L'interface ne peut plus déplacer le jeton vers un autre hôte...
        with self.assertRaises(HTTPException) as e:
            self.save('https://attaquant.example/_cluster/health')
        self.assertEqual(e.exception.status_code, 422)

        # ... ni un fichier de connexions modifié à la main.
        api = self.base / 'data/api-connections.json'
        items = json.loads(api.read_text(encoding='utf-8'))
        items[0]['url'] = 'https://attaquant.example/_cluster/health'
        api.write_text(json.dumps(items), encoding='utf-8')
        opener = MagicMock()
        with self.assertRaises(HTTPException) as e:
            self.collect(opener)
        self.assertEqual(e.exception.status_code, 422)
        self.assertIn('es.example:9200', e.exception.detail)
        opener.open.assert_not_called()  # le jeton n'est jamais parti

    def test_registre_corrompu_bloque_la_collecte_sans_reecrire(self):
        """Audit A2 : un registre invalide n'est jamais lu comme « aucune liaison »."""
        self.save('https://es.example:9200/_cluster/health')
        registre = self.base / 'data/token-bindings.json'
        registre.write_text('{"INFRAOPS_ELASTIC_AUTH_TEST": {"endpoint": "es.example:9200"}, "AUTRE"', encoding='utf-8')
        opener = MagicMock()
        with self.assertLogs('opscontrol.security', 'ERROR'), self.assertRaises(HTTPException) as e:
            self.collect(opener)
        self.assertEqual(e.exception.status_code, 422)
        self.assertIn('collectes authentifiées suspendues', e.exception.detail)
        opener.open.assert_not_called()  # le jeton n'est jamais parti
        self.assertTrue(registre.read_text(encoding='utf-8').endswith('"AUTRE"'))  # rien d'effacé

    def test_meme_hote_autre_chemin_accepte(self):
        self.save('https://es.example:9200/_cluster/health')
        opener = MagicMock()
        opener.open.return_value = response_for({'status': 'green'})
        self.collect(opener)
        self.save('https://es.example:9200/_cluster/health?pretty'.split('?')[0])

    def test_collecte_refusee_vers_une_destination_locale(self):
        self.save('https://es.example:9200/_cluster/health')
        opener = MagicMock()
        with patch.object(m.socket, 'getaddrinfo', side_effect=lambda h, p: [(2, 1, 6, '', ('127.0.0.1', 0))]):
            with self.assertRaises(HTTPException) as e:
                self.collect(opener)
        self.assertEqual(e.exception.status_code, 422)
        opener.open.assert_not_called()


if __name__ == '__main__':
    unittest.main()
