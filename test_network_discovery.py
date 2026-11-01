"""Découverte réseau (network_discovery.py) : plage, indices de système, balayage et ajout."""
from routers import all_routes  # routes des APIRouter inclus
import os
import sqlite3
import tempfile
import threading
from contextlib import contextmanager, closing
from pathlib import Path
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import FastAPI, HTTPException

import network_discovery as nd


class RangeTests(unittest.TestCase):
    def test_plages(self):
        self.assertEqual(str(nd.validate_range('10.77.0.10/24')), '10.77.0.0/24')
        self.assertEqual(nd.validate_range('10.0.0.0/22').num_addresses, 1024)
        for bad in ('8.8.8.0/24', '10.0.0.0/21', '127.0.0.0/24', '169.254.0.0/24', 'fd00::/120', 'pas une plage',
                    # Audit NET-01 : « privées » pour Python, mais hors RFC 1918.
                    '0.0.0.0/32', '198.18.0.0/24', '240.0.0.0/24', '255.255.255.255/32', '100.64.0.0/24',
                    '192.0.2.0/24'):
            with self.assertRaises(ValueError, msg=bad):
                nd.validate_range(bad)


class ClassifyTests(unittest.TestCase):
    def test_systemes(self):
        self.assertEqual(nd.os_from_banner('SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3'), 'Debian 12')
        self.assertEqual(nd.os_from_banner('SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10'), 'Ubuntu 22.04')
        self.assertEqual(nd.os_from_banner('SSH-2.0-OpenSSH_9.0'), 'Linux / Unix (OpenSSH)')
        self.assertIsNone(nd.os_from_banner(None))

    def test_types(self):
        self.assertEqual(nd.classify([22, 8006], 64, 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3')[0], 'Hyperviseur Proxmox')
        self.assertEqual(nd.classify([3389, 445], 128, None), ('Serveur Windows', 'Windows'))
        self.assertEqual(nd.classify([22, 443], 64, 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3'), ('Serveur web Linux/Unix', 'Debian 12'))
        self.assertEqual(nd.classify([], 255, None)[0], 'Équipement réseau')
        self.assertEqual(nd.classify([], None, None)[0], 'Inconnu')


FAKE = {
    '10.77.0.10': (True, 64, [22], 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3', 'srv10.example.lan'),
    '10.77.0.11': (True, 128, [3389], None, None),
    '10.77.0.20': (True, 64, [22], 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3', 'connu.example.lan'),
    '10.77.0.30': (False, None, [3300], 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10', None),
}


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.added = []
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        database = self.database = Path(temporary.name) / 'discovery.sqlite3'
        import migrations
        with closing(sqlite3.connect(database)) as db:
            migrations.apply(db)
        @contextmanager
        def connect():
            with closing(sqlite3.connect(database)) as db:
                with db:
                    yield db
        self.context = SimpleNamespace(
            HOSTS=[{'key': 'connu', 'name': 'connu', 'ip': '10.77.0.20'}], job={'running': False}, net_job={'running': False},
            connect=connect, api_connections=lambda: [],
            add_discovered_hosts=lambda items: self.added.extend(items) or items)
        app = FastAPI()
        nd.install(app, self.context)
        self.routes = {(r.path, next(iter(r.methods))): r.endpoint for r in all_routes(app) if r.path.startswith('/api/')}
        patches = [patch.object(nd, 'ping_ttl', side_effect=lambda ip: FAKE[ip][:2] if ip in FAKE else (False, None)),
                   patch.object(nd, 'tcp_open', side_effect=lambda ip, port: ip in FAKE and port in FAKE[ip][2]),
                   patch.object(nd, 'ssh_banner', side_effect=lambda ip, port: FAKE[ip][3]),
                   patch.object(nd, 'reverse_dns', side_effect=lambda ip: FAKE.get(ip, (None,) * 5)[4])]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def scan(self, rng='10.77.0.0/26'):
        self.routes['/api/discovery/scan', 'POST'](nd.Scan(range=rng))
        for _ in range(200):
            state = self.routes['/api/discovery', 'GET']()
            if not state['job']['running']:
                return state
            time.sleep(0.02)
        self.fail('balayage non terminé')

    def test_balayage_et_statuts(self):
        state = self.scan()
        items = {i['ip']: i for i in state['items']}
        self.assertEqual(sorted(items), sorted(FAKE), 'seules les machines qui répondent')
        self.assertEqual(state['job']['total'], 62)
        self.assertEqual((items['10.77.0.10']['status'], items['10.77.0.10']['os']), ('new_ssh', 'Debian 12'))
        self.assertEqual(items['10.77.0.11']['status'], 'new')
        self.assertEqual(items['10.77.0.20']['status'], 'inventory')
        self.assertEqual(items['10.77.0.30']['ssh_port'], 3300, 'SSH sur port alternatif, sans ping')
        self.assertEqual(state['counts'], {'inventory': 1, 'new_ssh': 2, 'new': 1})

    def test_ajout(self):
        self.scan()
        r = self.routes['/api/discovery/add', 'POST'](nd.Add(ips=['10.77.0.10', '10.77.0.30', '10.77.0.20']))
        self.assertEqual([a['key'] for a in r['added']], ['net-10-77-0-10', 'net-10-77-0-30'], 'machine déjà connue ignorée')
        first, second = self.added
        self.assertEqual((first['name'], first['role'], first['discovered_from']), ('srv10', 'À renseigner', 'scan-reseau'))
        self.assertNotIn('port', first, 'port 22 : réglage global')
        self.assertEqual(second['port'], 3300)

    def test_ajout_refuse(self):
        self.scan()
        with self.assertRaises(HTTPException) as e:
            self.routes['/api/discovery/add', 'POST'](nd.Add(ips=['10.77.0.99']))
        self.assertEqual(e.exception.status_code, 422, 'adresse hors du dernier balayage')
        # Pendant une collecte, l'ajout est accepté : il entre au lot suivant (audit A1).
        self.context.job['running'] = True
        r = self.routes['/api/discovery/add', 'POST'](nd.Add(ips=['10.77.0.10']))
        self.assertEqual([a['key'] for a in r['added']], ['net-10-77-0-10'])

    def test_plage_refusee(self):
        with self.assertRaises(HTTPException) as e:
            self.routes['/api/discovery/scan', 'POST'](nd.Scan(range='8.8.8.0/24'))
        self.assertEqual(e.exception.status_code, 422)

    def test_scan_deja_en_cours_409(self):
        # Audit NET-05 : un second lancement n'est plus confondu avec un nouveau scan.
        release = threading.Event()
        with patch.object(nd, 'probe', side_effect=lambda ip: release.wait(2) and None):
            self.routes['/api/discovery/scan', 'POST'](nd.Scan(range='10.77.0.0/30'))
            with self.assertRaises(HTTPException) as e:
                self.routes['/api/discovery/scan', 'POST'](nd.Scan(range='10.77.0.0/30'))
            release.set()
        self.assertEqual(e.exception.status_code, 409)
        for _ in range(200):
            if not self.routes['/api/discovery', 'GET']()['job']['running']:
                break
            time.sleep(0.02)

    def test_ajout_refuse_si_balayage_ancien_ou_absent(self):
        # Audit NET-03 : une IP vue il y a longtemps a pu changer de machine.
        with self.assertRaises(HTTPException) as e:
            self.routes['/api/discovery/add', 'POST'](nd.Add(ips=['10.77.0.10']))
        self.assertEqual(e.exception.status_code, 409)
        self.scan()
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute("UPDATE discovery_scans SET at='2026-01-01T00:00:00+00:00'")
        with self.assertRaises(HTTPException) as e:
            self.routes['/api/discovery/add', 'POST'](nd.Add(ips=['10.77.0.10']))
        self.assertEqual(e.exception.status_code, 409)
        self.assertEqual(self.added, [])

    def test_ptr_invalide_non_repris(self):
        # Audit NET-04 : un PTR qui n'a pas la forme d'un nom d'hôte n'entre pas dans l'inventaire.
        self.assertTrue(nd.valid_hostname('srv10.exemple.local'))
        for bad in ('<b>x', 'nom avec espace', '-x.local', 'a' * 64 + '.local', '', None):
            self.assertFalse(nd.valid_hostname(bad), bad)
        with patch.object(nd, 'reverse_dns', side_effect=lambda ip: '<img src=x>' if ip == '10.77.0.10' else None):
            self.scan()
        self.routes['/api/discovery/add', 'POST'](nd.Add(ips=['10.77.0.10']))
        self.assertEqual((self.added[0]['name'], self.added[0]['fqdn']), ('10.77.0.10', None))


class LocalToolsTests(unittest.TestCase):
    def test_ping_par_chemin_absolu(self):
        # Audit NET-06 : jamais un ping.exe du dossier courant.
        exe = nd.ping_executable()
        if exe is not None:
            self.assertTrue(os.path.isabs(exe))
        with patch('os.path.isfile', return_value=False):
            self.assertIsNone(nd.ping_executable())

    def test_dns_inverse_borne_et_abandonne_au_delai(self):
        # Audit NET-02 : file bornée ; au-delà, le nom est simplement non résolu.
        release = threading.Event()
        with patch('socket.gethostbyaddr', side_effect=lambda ip: release.wait(3) and ('x', [], [])):
            started = time.monotonic()
            results = [nd.reverse_dns(f'10.0.0.{i}', timeout=0.05) for i in range(40)]
            elapsed = time.monotonic() - started
            release.set()
        self.assertEqual(set(results), {None})
        self.assertLess(elapsed, 5, 'les requêtes au-delà de la file ne sont pas attendues')

    def test_dns_file_reste_bornee_sur_plusieurs_vagues_expirees(self):
        # Une future annulée reste en file : vérifier les travaux réels, pas seulement le délai.
        pool = ThreadPoolExecutor(max_workers=8)
        slots = threading.BoundedSemaphore(32)
        release = threading.Event()

        def lookup(_ip):
            release.wait(10)
            return ('fixture.test', [], [])

        with patch.object(nd, '_dns_pool', pool), patch.object(nd, '_dns_slots', slots), \
                patch('socket.gethostbyaddr', side_effect=lookup):
            try:
                results = [nd.reverse_dns(f'192.0.2.{i + 1}', timeout=0.002) for i in range(96)]
                self.assertEqual(set(results), {None})
                self.assertLessEqual(pool._work_queue.qsize(), 32)
                self.assertFalse(slots.acquire(blocking=False), 'les travaux expirés gardent leur place')
            finally:
                release.set()
                pool.shutdown(wait=True)
            self.assertTrue(all(slots.acquire(blocking=False) for _ in range(32)))
            self.assertFalse(slots.acquire(blocking=False), 'aucune place rendue en double')

    def test_dns_pool_arrete_ne_perd_pas_de_place(self):
        slots = threading.BoundedSemaphore(1)
        with patch.object(nd, '_dns_slots', slots), \
                patch.object(nd._dns_pool, 'submit', side_effect=RuntimeError('arrêt')):
            self.assertIsNone(nd.reverse_dns('192.0.2.1'))
        self.assertTrue(slots.acquire(blocking=False))


if __name__ == '__main__':
    unittest.main()
