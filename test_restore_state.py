"""Restauration (deploy/restore_state.py) : vérification sans effet, application service arrêté."""
import io
import json
import sqlite3
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / 'deploy'))
import backup_state  # noqa: E402
import restore_state  # noqa: E402


def make_instance(base, rows):
    (base / 'data').mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(base / 'data/state.sqlite3')
    db.execute('CREATE TABLE IF NOT EXISTS states(key TEXT PRIMARY KEY)')
    db.execute('DELETE FROM states')
    db.executemany('INSERT INTO states VALUES(?)', [(f'h{i}',) for i in range(rows)])
    db.commit()
    db.close()
    (base / 'hosts.yaml').write_text(f'hosts: {rows}\n', encoding='utf-8')


class RestoreTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name) / 'instance'
        self.dest = Path(self._tmp.name) / 'sauvegardes'
        self.db = self.base / 'data/state.sqlite3'
        make_instance(self.base, 10)
        self.archive = self.dest / backup_state.backup(self.base, self.dest, self.db)['archive']

    def count(self):
        db = sqlite3.connect(self.db)
        try:
            return db.execute('SELECT count(*) FROM states').fetchone()[0]
        finally:
            db.close()

    def test_verify_sans_effet(self):
        avant = sorted(p.name for p in self.dest.iterdir())
        r = restore_state.verify(self.archive)
        self.assertEqual(r['tables']['states'], 10)
        self.assertIn('hosts.yaml', r['files'])
        self.assertEqual(sorted(p.name for p in self.dest.iterdir()), avant)
        self.assertEqual(restore_state.latest(self.dest), self.archive)

    def test_sauvegarde_d_une_version_plus_recente_refusee(self):
        # Audit DB-04 : ce code ne connaît pas le schéma d'une version future.
        db = sqlite3.connect(self.db)
        db.execute('CREATE TABLE schema_migrations(name TEXT PRIMARY KEY, applied_at TEXT)')
        db.execute("INSERT INTO schema_migrations(name, applied_at) VALUES('core_v99_futur', 'x')")
        db.commit(); db.close()
        archive = self.dest / backup_state.backup(self.base, self.dest, self.db, tag='futur')['archive']
        with self.assertRaises(restore_state.RestoreError) as e:
            restore_state.verify(archive)
        self.assertIn('core_v99_futur', str(e.exception))

    def test_archive_alteree_refusee(self):
        with open(self.archive, 'ab') as f:
            f.write(b'x')
        with self.assertRaises(restore_state.RestoreError):
            restore_state.verify(self.archive)

    def test_membre_hors_dossier_refuse(self):
        piege = self.dest / 'opscontrol-20260101-000000.tar.gz'
        with tarfile.open(piege, 'w:gz') as tar:
            data = b'x'
            info = tarfile.TarInfo('opscontrol/../../evasion.txt')
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        (self.dest / (piege.name + '.sha256')).write_text(backup_state.sha256(piege) + '  ' + piege.name, encoding='utf-8')
        with self.assertRaises(restore_state.RestoreError):
            restore_state.verify(piege)
        self.assertFalse((Path(self._tmp.name) / 'evasion.txt').exists())

    def test_apply_sans_confirmation_ne_touche_a_rien(self):
        make_instance(self.base, 3)
        plan = restore_state.apply(self.archive, self.base, self.db)
        self.assertFalse(plan['applied'])
        self.assertEqual(self.count(), 3)

    def test_apply_restaure_et_sauvegarde_l_etat_precedent(self):
        make_instance(self.base, 3)
        Path(str(self.db) + '-wal').write_bytes(b'ancien journal')
        plan = restore_state.apply(self.archive, self.base, self.db, confirm=True)
        self.assertTrue(plan['applied'])
        self.assertEqual(self.count(), 10)
        self.assertEqual((self.base / 'hosts.yaml').read_text(encoding='utf-8'), 'hosts: 10\n')
        self.assertFalse(Path(str(self.db) + '-wal').exists(), 'un -wal ancien rejoué corromprait la base')
        self.assertIn('avant-restauration', plan['safety_backup'])
        avant = restore_state.verify(self.dest / plan['safety_backup'])
        self.assertEqual(avant['tables']['states'], 3)

    def test_apply_base_seule(self):
        make_instance(self.base, 3)
        restore_state.apply(self.archive, self.base, self.db, only_db=True, confirm=True)
        self.assertEqual(self.count(), 10)
        self.assertEqual((self.base / 'hosts.yaml').read_text(encoding='utf-8'), 'hosts: 3\n')

    def test_apply_refuse_si_le_service_tourne(self):
        with restore_state.InstanceLock(self.db):
            # Un second verrou (autre descripteur) échoue comme le ferait l'application.
            with self.assertRaises(restore_state.RestoreError):
                restore_state.apply(self.archive, self.base, self.db, confirm=True)


if __name__ == '__main__':
    unittest.main()


class ManifestTests(unittest.TestCase):
    """Audit A1 : CA de data/ca/ et liaisons de jetons survivent à une reprise sur machine vierge."""

    PEM = '-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n'

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.racine = Path(self._tmp.name)
        self.base = self.racine / 'instance'
        self.dest = self.racine / 'sauvegardes'
        make_instance(self.base, 4)
        (self.base / 'data/ca/interne').mkdir(parents=True)
        (self.base / 'data/ca/zabbix.pem').write_text(self.PEM, encoding='utf-8')
        (self.base / 'data/ca/interne/racine.crt').write_text(self.PEM, encoding='utf-8')
        (self.base / 'data/ca/notes.txt').write_text('hors manifeste', encoding='utf-8')
        (self.base / 'data/token-bindings.json').write_text(
            '{"INFRAOPS_ZABBIX_AUTH": {"endpoint": "zbx.example.test:443"}}', encoding='utf-8')

    def test_reprise_vierge_conserve_ca_et_liaisons(self):
        status = backup_state.backup(self.base, self.dest, self.base / 'data/state.sqlite3')
        for rel in ('data/ca/zabbix.pem', 'data/ca/interne/racine.crt', 'data/token-bindings.json'):
            self.assertIn(rel, status['files'])
        self.assertNotIn('data/ca/notes.txt', status['files'])
        vierge = self.racine / 'vierge'
        vierge.mkdir()
        restore_state.apply(self.dest / status['archive'], vierge, vierge / 'data/state.sqlite3', confirm=True)
        self.assertEqual((vierge / 'data/ca/zabbix.pem').read_text(encoding='utf-8'), self.PEM)
        self.assertTrue((vierge / 'data/ca/interne/racine.crt').is_file())
        self.assertIn('zbx.example.test:443', (vierge / 'data/token-bindings.json').read_text(encoding='utf-8'))

    def test_cle_privee_dans_data_ca_refusee(self):
        (self.base / 'data/ca/zabbix.pem').write_text('-' * 5 + 'BEGIN ' + 'PRIVATE KEY' + '-' * 5 + '\nx\n', encoding='utf-8')
        with self.assertRaises(backup_state.BackupError) as e:
            backup_state.backup(self.base, self.dest, self.base / 'data/state.sqlite3')
        self.assertIn('data/ca/zabbix.pem', str(e.exception))

    def test_lien_sortant_de_data_ca_ignore(self):
        ailleurs = self.racine / 'etranger.pem'
        ailleurs.write_text(self.PEM, encoding='utf-8')
        try:
            (self.base / 'data/ca/lien.pem').symlink_to(ailleurs)
        except OSError:
            self.skipTest('liens symboliques non autorisés sur ce poste')
        status = backup_state.backup(self.base, self.dest, self.base / 'data/state.sqlite3')
        self.assertNotIn('data/ca/lien.pem', status['files'])

    def test_archive_hors_manifeste_refusee(self):
        piege = self.dest / 'opscontrol-20260101-000000.tar.gz'
        self.dest.mkdir(parents=True)
        with tarfile.open(piege, 'w:gz') as tar:
            for nom, contenu in (('opscontrol/data/state.sqlite3', (self.base / 'data/state.sqlite3').read_bytes()),
                                 ('opscontrol/app.py', b'print("remplace")\n')):
                info = tarfile.TarInfo(nom)
                info.size = len(contenu)
                tar.addfile(info, io.BytesIO(contenu))
        (self.dest / (piege.name + '.sha256')).write_text(backup_state.sha256(piege) + '  ' + piege.name, encoding='utf-8')
        with self.assertRaises(restore_state.RestoreError) as e:
            restore_state.verify(piege)
        self.assertIn('hors du manifeste', str(e.exception))


class UniteSauvegardeTests(unittest.TestCase):
    """La sauvegarde quotidienne de la VM teste elle-même la restauration (audit OC-AUD-014)."""

    def test_verification_apres_la_sauvegarde_sur_le_meme_dossier(self):
        unite = (Path(__file__).resolve().parent / 'deploy/infraops-backup.service').read_bytes()
        self.assertNotIn(b'\r\n', unite)  # unité exécutée sous Linux : fins de ligne LF
        lignes = dict(ligne.split('=', 1) for ligne in unite.decode('utf-8').splitlines()
                      if ligne.startswith(('ExecStart=', 'ExecStartPost=')))
        dest = lignes['ExecStart'].split('--dest ', 1)[1].split()[0]
        self.assertTrue(lignes['ExecStartPost'].endswith('deploy/restore_state.py verify --latest ' + dest + ' --record'))


class ResultatDuTestTests(unittest.TestCase):
    """verify --record : résultat dans last-backup.json, champs de la sauvegarde conservés."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name) / 'instance'
        self.dest = Path(self._tmp.name) / 'sauvegardes'
        make_instance(self.base, 3)
        self.assertEqual(backup_state.main(['--base', str(self.base), '--dest', str(self.dest)]), 0)

    def etat(self):
        return json.loads((self.dest / backup_state.STATUS).read_text(encoding='utf-8'))

    def test_succes_enregistre(self):
        avant = self.etat()
        self.assertEqual(restore_state.main(['verify', '--latest', str(self.dest), '--record']), 0)
        apres = self.etat()
        self.assertTrue(apres['restore_test_ok'])
        self.assertIsNone(apres['restore_test_error'])
        self.assertEqual(apres['restore_test_archive'], avant['archive'])
        self.assertEqual({k: apres[k] for k in avant}, avant)

    def test_archive_alteree_enregistree_en_echec(self):
        archive = self.dest / self.etat()['archive']
        archive.write_bytes(archive.read_bytes() + b'x')
        self.assertEqual(restore_state.main(['verify', '--latest', str(self.dest), '--record']), 1)
        apres = self.etat()
        self.assertFalse(apres['restore_test_ok'])
        self.assertIn('RestoreError', apres['restore_test_error'])
        self.assertTrue(apres['ok'])  # la sauvegarde elle-même reste décrite telle quelle

    def test_sans_record_rien_n_est_ecrit(self):
        avant = (self.dest / backup_state.STATUS).read_bytes()
        self.assertEqual(restore_state.main(['verify', '--latest', str(self.dest)]), 0)
        self.assertEqual((self.dest / backup_state.STATUS).read_bytes(), avant)
