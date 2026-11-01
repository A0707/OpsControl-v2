"""Sauvegarde locale (deploy/backup_state.py) : copie cohérente, aucun secret, rotation."""
import json
import sqlite3
import sys
import tarfile
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / 'deploy'))
import backup_state  # noqa: E402


class BackupTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name) / 'instance'
        (self.base / 'data').mkdir(parents=True)
        self.db = self.base / 'data/state.sqlite3'
        db = sqlite3.connect(self.db)
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('CREATE TABLE states(key TEXT PRIMARY KEY, payload TEXT)')
        db.executemany('INSERT INTO states VALUES(?,?)', [(f'h{i}', '{}') for i in range(25)])
        db.commit()
        self.ouverte = db  # base ouverte pendant la sauvegarde, comme en service
        (self.base / 'hosts.yaml').write_text('hosts:\n- key: h1\n  ip: 10.0.0.1\n', encoding='utf-8')
        (self.base / 'data/api-connections.json').write_text(
            json.dumps([{'key': 'p', 'provider': 'Proxmox', 'token_env': 'INFRAOPS_PROXMOX_AUTH'}]), encoding='utf-8')
        self.dest = Path(self._tmp.name) / 'sauvegardes'

    def tearDown(self):
        self.ouverte.close()
        self._tmp.cleanup()

    def test_archive_complete_et_verifiable(self):
        status = backup_state.backup(self.base, self.dest, self.db)
        archive = self.dest / status['archive']
        self.assertTrue(archive.is_file())
        empreinte = (self.dest / (status['archive'] + '.sha256')).read_text(encoding='utf-8').split()[0]
        self.assertEqual(empreinte, backup_state.sha256(archive))
        with tarfile.open(archive) as t:
            noms = t.getnames()
            self.assertIn('opscontrol/data/state.sqlite3', noms)
            self.assertIn('opscontrol/hosts.yaml', noms)
            # extractfile plutôt qu'extract(filter=…), absent de Python 3.11.2 (Debian 12).
            (Path(self._tmp.name) / 'restauree.sqlite3').write_bytes(t.extractfile('opscontrol/data/state.sqlite3').read())
        copie = sqlite3.connect(Path(self._tmp.name) / 'restauree.sqlite3')
        try:
            self.assertEqual(copie.execute('SELECT count(*) FROM states').fetchone()[0], 25)
        finally:
            copie.close()
        self.assertIn('data/known_hosts', status['missing'])

    def test_secret_dans_la_configuration_refuse(self):
        (self.base / 'hosts.yaml').write_text('note: "Bearer ' + 'a' * 40 + '"\n', encoding='utf-8')
        with self.assertRaises(backup_state.BackupError):
            backup_state.backup(self.base, self.dest, self.db)
        self.assertEqual(list(self.dest.glob('*.tar.gz')), [])

    def test_champ_secret_dans_les_connexions_refuse(self):
        (self.base / 'data/api-connections.json').write_text(json.dumps([{'key': 'p', 'token': 'x'}]), encoding='utf-8')
        with self.assertRaises(backup_state.BackupError):
            backup_state.backup(self.base, self.dest, self.db)

    def test_base_absente(self):
        with self.assertRaises(backup_state.BackupError):
            backup_state.backup(self.base, self.dest, self.base / 'data/absente.sqlite3')

    def test_etiquette_invalide(self):
        with self.assertRaises(backup_state.BackupError):
            backup_state.backup(self.base, self.dest, self.db, tag='../evasion')

    def test_etat_garde_le_dernier_succes_apres_un_echec(self):
        self.assertEqual(backup_state.main(['--base', str(self.base), '--dest', str(self.dest)]), 0)
        succes = json.loads((self.dest / backup_state.STATUS).read_text(encoding='utf-8'))
        self.assertTrue(succes['ok'])
        self.assertEqual(backup_state.main(['--base', str(self.base), '--dest', str(self.dest),
                                            '--db', str(self.base / 'data/absente.sqlite3')]), 1)
        echec = json.loads((self.dest / backup_state.STATUS).read_text(encoding='utf-8'))
        self.assertFalse(echec['ok'])
        self.assertEqual(echec['last_success_epoch'], succes['last_success_epoch'])
        self.assertEqual(echec['last_success_archive'], succes['archive'])


class RotationTests(unittest.TestCase):
    def test_politique_quotidienne_hebdomadaire_mensuelle_et_etiquetees(self):
        noms = []
        # Deux sauvegardes par jour pendant 120 jours, plus 7 étiquetées.
        for jour in range(120):
            d = datetime(2026, 10, 5).toordinal() - jour
            date = datetime.fromordinal(d)
            noms += [f'opscontrol-{date:%Y%m%d}-023000.tar.gz', f'opscontrol-{date:%Y%m%d}-143000.tar.gz']
        noms += [f'opscontrol-2026090{i}-120000-pre-r{i}.tar.gz' for i in range(1, 8)]
        garder = backup_state.keep_set(noms + ['autre-fichier.tar.gz'])
        ordinaires = {n for n in garder if '-pre-' not in n}
        self.assertIn('opscontrol-20261005-143000.tar.gz', garder)       # la plus récente du jour
        self.assertNotIn('opscontrol-20261005-023000.tar.gz', garder)    # une seule par jour
        self.assertLessEqual(len(ordinaires), backup_state.KEEP_DAILY + backup_state.KEEP_WEEKLY + backup_state.KEEP_MONTHLY)
        self.assertGreaterEqual(len(ordinaires), backup_state.KEEP_DAILY)
        # Un mois en arrière reste couvert par la rétention mensuelle.
        self.assertTrue(any(n.startswith('opscontrol-202608') for n in ordinaires))
        self.assertEqual(len([n for n in garder if '-pre-' in n]), backup_state.KEEP_TAGGED)
        self.assertNotIn('autre-fichier.tar.gz', garder)

    def test_rotation_supprime_aussi_les_empreintes(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp)
            for jour in range(1, 31):
                for heure in ('023000', '143000'):
                    nom = f'opscontrol-202609{jour:02d}-{heure}.tar.gz'
                    (dest / nom).write_bytes(b'x')
                    (dest / (nom + '.sha256')).write_text('x', encoding='utf-8')
            supprimees = backup_state.rotate(dest)
            self.assertTrue(supprimees)
            for nom in supprimees:
                self.assertFalse((dest / nom).exists())
                self.assertFalse((dest / (nom + '.sha256')).exists())
            restantes = {p.name for p in dest.glob('*.tar.gz')}
            self.assertEqual(restantes, backup_state.keep_set(list(restantes)))


if __name__ == '__main__':
    unittest.main()
