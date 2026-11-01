"""Reliquats sécurité J60-J90 : sonde de certificat, ca_bundle en chemin, balayage après collecte Proxmox."""
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

import management as m


def public_dns(host, port):
    return [(2, 1, 6, '', ('203.0.113.10', 0))]


class Harness(unittest.TestCase):
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

        self.sweeps = []
        self.context = SimpleNamespace(BASE=self.base, HOSTS=[], lock=threading.Lock(), net_lock=threading.Lock(),
                                       job={'running': False}, net_job={'running': False}, connect=connect,
                                       launch_network=lambda hosts, who: self.sweeps.append(who))
        app = FastAPI()
        m.install(app, self.context)
        self.routes = {(r.path, next(iter(r.methods))): r.endpoint for r in all_routes(app) if r.path.startswith('/api/')}
        patcher = patch.object(m.socket, 'getaddrinfo', side_effect=public_dns)
        patcher.start()
        self.addCleanup(patcher.stop)

    def post(self, path, *args):
        return self.routes[path, 'POST'](*args)


class CertificateProbeTests(Harness):
    def test_port_hors_liste_refuse_sans_connexion(self):
        with patch.object(m, 'probe_certificate') as probe:
            for url in ('https://interne.example:22/', 'https://interne.example:3306/', 'https://interne.example:6379/'):
                with self.assertRaises(HTTPException) as e:
                    self.post('/api/connections/certificate', m.CertificateProbe(url=url))
                self.assertEqual(e.exception.status_code, 422)
            probe.assert_not_called()

    def test_ports_d_api_et_port_deja_configure_acceptes(self):
        self.post('/api/connections', m.Connection(key='x', name='X', provider='JSON', url='https://api.example:7443/v1'))
        with patch.object(m, 'probe_certificate', return_value={'ok': True}) as probe:
            for url in ('https://pve.example:8006/', 'https://wazuh.example:55000/', 'https://api.example:7443/'):
                self.assertEqual(self.post('/api/connections/certificate', m.CertificateProbe(url=url)), {'ok': True})
        self.assertEqual(probe.call_count, 3)

    def test_destination_locale_refusee(self):
        with patch.object(m, 'probe_certificate') as probe, \
                patch.object(m.socket, 'getaddrinfo', side_effect=lambda h, p: [(2, 1, 6, '', ('127.0.0.1', 0))]):
            with self.assertRaises(HTTPException):
                self.post('/api/connections/certificate', m.CertificateProbe(url='https://piege.example/'))
            probe.assert_not_called()


class CaBundlePathTests(Harness):
    def test_fonction(self):
        self.assertIsNone(m.ca_file_refused(self.base, ''))
        self.assertIsNone(m.ca_file_refused(self.base, '-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----'))
        self.assertIsNone(m.ca_file_refused(self.base, 'proxmox-ca.pem'))
        for refuse in ('../../hosts.yaml', '/etc/passwd', 'C:/Windows/win.ini', str(self.base / 'hosts.yaml')):
            self.assertIsNotNone(m.ca_file_refused(self.base, refuse), refuse)

    def test_enregistrement_refuse_hors_data_ca(self):
        with self.assertRaises(HTTPException) as e:
            self.post('/api/connections', m.Connection(key='p', name='P', provider='Proxmox',
                                                       url='https://pve.example:8006/api2/json', ca_bundle='~/.ssh/id_rsa'))
        self.assertEqual(e.exception.status_code, 422)


class ProxmoxSweepTests(Harness):
    def test_un_seul_balayage_par_fenetre(self):
        self.post('/api/connections', m.Connection(key='pve', name='Cluster', provider='Proxmox',
                                                   url='https://pve.example/api2/json/cluster/resources'))
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b'{"data":[{"type":"qemu","vmid":101,"node":"n","name":"w","status":"running"}]}'
        opener = MagicMock()
        opener.open.return_value = response
        with patch.object(m.urllib.request, 'build_opener', return_value=opener):
            for _ in range(3):
                self.post('/api/connections/{key}/collect', 'pve')
        self.assertEqual(self.sweeps, ['collecte-proxmox'], 'trois collectes, un seul balayage du parc')


if __name__ == '__main__':
    unittest.main()
