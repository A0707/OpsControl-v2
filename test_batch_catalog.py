"""Référentiel des batchs : lecture du fichier, horaires et rapprochement (sans SSH ni Zabbix)."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import batch_catalog as bc
import batch_remote as probe

HOSTS = [{'key': 'job', 'name': 'srv-job', 'ip': '192.0.2.10'}]
SCRIPT = '/var/batch/batch_factures/script/runBatchFactures.sh'


def catalog(**fiche):
    base = {'nom': 'Import des factures', 'responsable': 'Équipe', 'serveur': '192.0.2.10',
            'scripts': [SCRIPT], 'horaire': '02:30', 'statut': 'En prod', 'validation': 'Oui'}
    base.update(fiche)
    return {'available': True, 'entries': [bc.normalize(base, set())], 'source': 'test.yaml'}


def saved(jobs=(), crontabs=('root',), files=(SCRIPT,)):
    obs = {'status': 'observed', 'collected_at': '2026-10-30T10:00:00+00:00', 'jobs': list(jobs),
           'crontabs_read': list(crontabs),
           'batch_files': {'readable': True, 'files': [[f, 1700000000] for f in files], 'dirs': [], 'truncated': False}}
    return {'job': obs}


def cron(schedule='30 2 * * *', script=SCRIPT, job_id='c1'):
    return {'id': job_id, 'kind': 'cron', 'script': script, 'schedule': schedule, 'owner': 'root', 'source': 'crontab:root'}


class Horaires(unittest.TestCase):
    def test_texte_du_referentiel(self):
        self.assertEqual(bc.expected_times('17:30'), {(17, 30)})
        self.assertEqual(bc.expected_times('08:00, 10:00, 22:50'), {(8, 0), (10, 0), (22, 50)})
        self.assertEqual(bc.expected_times('08:00 et 20h00 chaque jour'), {(8, 0), (20, 0)})
        self.assertEqual(bc.expected_times('06-18:00 (Every hour from 6 through 18)'), {(h, 0) for h in range(6, 19)})
        self.assertEqual(bc.expected_times('05:00 (on day of month 1)'), {(5, 0)})
        # Minute inconnue : non comparable plutôt que deviné.
        self.assertIsNone(bc.expected_times('Chaque 2 heures'))
        self.assertIsNone(bc.expected_times(''))

    def test_expression_cron(self):
        self.assertEqual(bc.cron_times('30 2 * * *'), {(2, 30)})
        self.assertEqual(bc.cron_times('0 6-18 * * *'), {(h, 0) for h in range(6, 19)})
        self.assertEqual(bc.cron_times('0,30 8 * * 1-5'), {(8, 0), (8, 30)})
        self.assertEqual(bc.cron_times('0 */6 * * *'), {(0, 0), (6, 0), (12, 0), (18, 0)})
        self.assertEqual(bc.cron_times('@daily'), {(0, 0)})
        self.assertIsNone(bc.cron_times('* 2 * * *'))
        self.assertIsNone(bc.cron_times('0 0 1 ? 1/1 TUE#2'))  # Quartz, cron ne l'exécute pas


class Chemins(unittest.TestCase):
    def test_script_et_dossier(self):
        self.assertTrue(bc.path_matches(SCRIPT, SCRIPT))
        # « script/ » contre « scripts/ » : même dossier de batch, même fichier.
        self.assertTrue(bc.path_matches('/var/batch/batch_factures/scripts/runBatchFactures.sh', SCRIPT))
        self.assertFalse(bc.path_matches('/var/batch/batch_autre/script/runBatchFactures.sh', SCRIPT))
        self.assertTrue(bc.path_matches('/var/batch/batch_bilan/run.sh', '/var/batch/batch_bilan/'))
        self.assertTrue(bc.path_matches('/var/batch/batch_source/x.py', '/var/batch/batch_source'))
        self.assertFalse(bc.path_matches(None, SCRIPT))

    def test_nom_de_l_enveloppe(self):
        self.assertEqual(bc.wrapper_name(SCRIPT), 'batch_factures.runBatchFactures')
        self.assertEqual(bc.wrapper_name('/var/batch/batch_import/demo-import-batch.jar'), 'batch_import.demo-import-batch')
        self.assertEqual(bc.wrapper_name('/var/batch/batch_bilan/'), 'batch_bilan')


class Lecture(unittest.TestCase):
    def test_exemple_versionne(self):
        data = bc.load(Path(__file__).with_name('batch_catalog.example.yaml'))
        self.assertTrue(data['available'], data['error'])
        self.assertEqual([e['attendu'] for e in data['entries']], ['actif', 'actif', 'arrete'])
        self.assertEqual(len({e['id'] for e in data['entries']}), 3)

    def test_fichier_absent_ou_invalide(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = bc.load(Path(directory) / 'absent.yaml')
            self.assertFalse(missing['available'])
            self.assertIn('Référentiel absent', missing['error'])
            broken = Path(directory) / 'casse.yaml'
            broken.write_text('batchs: [nom: : :', encoding='utf-8')
            self.assertFalse(bc.load(broken)['available'])
            sans_nom = Path(directory) / 'sans_nom.json'
            sans_nom.write_text(json.dumps({'batchs': [{'responsable': 'x'}]}), encoding='utf-8')
            self.assertIn('ValueError', bc.load(sans_nom)['error'])

    def test_variable_d_environnement(self):
        with mock.patch.dict(os.environ, {'INFRAOPS_BATCH_CATALOG': '/tmp/ailleurs.yaml'}):
            self.assertEqual(bc.catalog_path().name, 'ailleurs.yaml')

    def test_champs_bornes(self):
        entry = bc.normalize({'nom': 'x' * 500, 'scripts': 'relatif.sh', 'criticite': 'haute'}, set())
        self.assertEqual(len(entry['nom']), 160)
        self.assertEqual(entry['scripts'], [])
        self.assertIsNone(entry['criticite'])


class Rapprochement(unittest.TestCase):
    def one(self, cat, state, results=None):
        return bc.reconcile(cat, HOSTS, state, results or {}, lambda _at: True)

    def test_concordant(self):
        e = self.one(catalog(), saved([cron()]))['entries'][0]
        self.assertEqual((e['state'], e['planning'], e['script_present']), ('ok', 'Concordant', True))
        self.assertEqual(e['findings'], [])

    def test_horaire_different(self):
        e = self.one(catalog(), saved([cron('0 3 * * *')]))['entries'][0]
        self.assertEqual((e['state'], e['planning']), ('drift', 'Différent'))
        self.assertIn('03:00', e['findings'][0]['text'])

    def test_crontab_root_non_lue(self):
        # Sans lecture root, l'absence de planification n'est pas un écart.
        e = self.one(catalog(), saved([], crontabs=('audit',)))['entries'][0]
        self.assertEqual(e['state'], 'unknown')
        self.assertTrue(e['planning'].startswith('Non vérifiable'))
        self.assertEqual([f for f in e['findings'] if f['level'] != 'info'], [])

    def test_absente_des_crontabs_lues(self):
        e = self.one(catalog(), saved([]))['entries'][0]
        self.assertEqual(e['state'], 'drift')
        self.assertIn('Aucune planification', e['findings'][0]['text'])

    def test_arret_demande_mais_planifie(self):
        r = self.one(catalog(statut='Désactivé'), saved([cron()]))
        self.assertEqual(r['entries'][0]['findings'][0]['level'], 'critical')
        arrete = self.one(catalog(statut='Désactivé'), saved([]))['entries'][0]
        self.assertEqual(arrete['state'], 'stopped')
        inconnu = self.one(catalog(attendu='arrete'), saved([], crontabs=()))['entries'][0]
        self.assertEqual(inconnu['state'], 'unknown')

    def test_script_introuvable(self):
        e = self.one(catalog(), saved([cron()], files=('/var/batch/batch_autre/x.sh',)))['entries'][0]
        self.assertIs(e['script_present'], False)
        self.assertEqual(e['state'], 'drift')

    def test_resultat_zabbix_en_echec(self):
        res = {'job': [{'name': 'batch_factures.runBatchFactures', 'state': 'failed', 'rc': 2, 'finished_at': 10},
                       {'name': 'batch_inconnu.run', 'state': 'success', 'rc': 0, 'finished_at': 5}]}
        r = self.one(catalog(), saved([cron()]), res)
        self.assertEqual(r['entries'][0]['state'], 'failed')
        self.assertEqual(r['entries'][0]['last_result']['rc'], 2)
        self.assertEqual([u['name'] for u in r['unreferenced']], ['batch_inconnu.run'])

    def test_non_references_et_hors_inventaire(self):
        autre = cron(script='/var/batch/batch_nouveau/run.sh', job_id='c2')
        systeme = {'id': 'c3', 'kind': 'cron', 'script': '/usr/bin/freshclam', 'schedule': '0 1 * * *'}
        r = self.one(catalog(), saved([cron(), autre, systeme]))
        self.assertEqual([u['script'] for u in r['unreferenced']], ['/var/batch/batch_nouveau/run.sh'])
        swarm = self.one(catalog(serveur='SWARM', scripts=[]), saved([]))['entries'][0]
        self.assertEqual(swarm['planning'], 'Non mesuré')
        self.assertIn('Hors inventaire SSH', swarm['findings'][0]['text'])

    def test_snapshot_ne_casse_pas_sans_vue_critique(self):
        import sqlite3

        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        db.execute('CREATE TABLE batch_states(key TEXT, ip TEXT, payload TEXT)')
        db.execute('INSERT INTO batch_states VALUES(?,?,?)', ('job', '192.0.2.10', json.dumps(saved([cron()])['job'])))

        class Context:
            HOSTS = HOSTS

            def connect(self):
                return db

            def tier0_snapshot(self):
                raise RuntimeError('vue critique indisponible')

        with mock.patch.object(bc, 'load', return_value=catalog()):
            r = bc.snapshot(Context())
        self.assertEqual(r['counts']['total'], 1)


class Sonde(unittest.TestCase):
    def test_java_jar(self):
        meta = probe.command_metadata('/usr/bin/java -Xmx512m -jar /var/batch/batch_import/demo-import-batch.jar --secret x')
        self.assertEqual(meta['script'], '/var/batch/batch_import/demo-import-batch.jar')

    def test_scripts_presents_sans_journaux(self):
        with tempfile.TemporaryDirectory() as root:
            for rel in ('batch_a/script/run.sh', 'batch_a/logs/old.sh', 'batch_b/app.jar', 'batch_b/notes.txt'):
                path = Path(root, rel)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('x', encoding='utf-8')
            found = probe.batch_files(root.replace('\\', '/'))
            names = sorted(Path(f[0]).name for f in found['files'])
            self.assertEqual(names, ['app.jar', 'run.sh'])
            self.assertEqual(len(found['dirs']), 2)
            self.assertFalse(probe.batch_files(root + '/absent')['readable'])


if __name__ == '__main__':
    unittest.main()
