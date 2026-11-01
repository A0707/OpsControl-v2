"""Résultat et cause du dernier passage de chaque batch : journaux, enveloppe, Zabbix."""
import tempfile
import unittest
from pathlib import Path

import batch_catalog as bc
import batch_remote as probe

HOSTS = [{'key': 'job', 'name': 'srv-job', 'ip': '192.0.2.10'}]
SCRIPT = '/var/batch/batch_factures/script/runBatchFactures.sh'
NOW = 1_800_000_000


def catalog(*fiches):
    used = set()
    base = {'nom': 'Factures', 'responsable': 'Équipe', 'serveur': '192.0.2.10', 'scripts': [SCRIPT],
            'horaire': '02:30', 'statut': 'En prod', 'validation': 'Oui'}
    return {'available': True, 'entries': [bc.normalize({**base, **f}, used) for f in fiches or [{}]]}


def saved(logs=(), runs=(), jobs=()):
    return {'job': {'status': 'observed', 'collected_at': '2026-10-31T08:00:00+00:00', 'jobs': list(jobs),
                    'crontabs_read': ['audit'], 'batch_logs': list(logs),
                    'batch_runs': {'readable': True, 'runs': list(runs)}}}


def log(path, verdict, mtime=NOW - 3600, errors=(), last=('fin',), strength=None):
    return {'path': path, 'mtime': mtime, 'size': 10, 'readable': True, 'verdict': verdict,
            'strength': strength, 'errors': list(errors), 'last_lines': list(last)}


def one(state, *fiches, results=None):
    return bc.reconcile(catalog(*fiches), HOSTS, state, results or {}, lambda _at: True, now=NOW)['entries']


class Journal(unittest.TestCase):
    def digest(self, text):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, 'batch.log')
            path.write_text(text, encoding='utf-8')
            return probe.log_digest(str(path))

    def test_statut_spring_batch_fait_foi(self):
        ok = self.digest('ERROR ancienne\nJob: [x] completed with the following status: [COMPLETED]\n')
        self.assertEqual((ok['verdict'], ok['strength']), ('success', 'Statut Spring Batch COMPLETED'))
        ko = self.digest('INFO debut\nJob: [x] completed with the following status: [FAILED]\n')
        self.assertEqual(ko['verdict'], 'failed')

    def test_erreur_apres_la_derniere_fin(self):
        d = self.digest('Fin du batch\nINFO reprise\nERROR Connexion refusée password=s3cret\n'
                        'Caused by: java.sql.SQLException: jdbc://user:motdepasse@db\n')  # pragma: allowlist secret -- valeurs factices du test de masquage
        self.assertEqual(d['verdict'], 'failed')
        texte = ' '.join(d['errors'])
        self.assertNotIn('s3cret', texte)
        self.assertNotIn('motdepasse', texte)
        self.assertIn('password=***', texte)
        self.assertEqual(self.digest('ERROR x\nFin du batch\n')['verdict'], 'success')
        self.assertEqual(self.digest('INFO rien\n')['verdict'], 'unknown')

    def test_journal_illisible(self):
        self.assertFalse(probe.log_digest('/chemin/absent.log')['readable'])

    def test_fin_de_gros_journal_seulement(self):
        d = self.digest('x' * 70000 + '\nERROR finale\n')
        self.assertEqual(d['errors'], ['ERROR finale'])

    def test_masquage(self):
        self.assertEqual(probe.mask('Authorization: Bearer abc.def'), 'Authorization: ***')
        self.assertEqual(probe.mask('token=' + 'a' * 50), 'token=***')
        self.assertEqual(probe.mask('\x1b[31mERROR\x1b[0m'), '[31mERROR [0m')

    def test_cible_de_redirection_cron(self):
        self.assertEqual(probe.log_target('cd /var/batch/x && ./run.sh >> /var/batch/x/log/run.log 2>&1'),
                         '/var/batch/x/log/run.log')
        self.assertEqual(probe.log_target('/var/batch/x/run.sh >/var/log/x.log'), '/var/log/x.log')
        self.assertEqual(probe.log_target("/bin/sh -c '/var/batch/x/run.sh >> /tmp/a.log'"), '/tmp/a.log')
        self.assertIsNone(probe.log_target('/var/batch/x/run.sh > /dev/null 2>&1'))

    def test_journaux_par_dossier(self):
        with tempfile.TemporaryDirectory() as root:
            for rel in ('batch_a/log/a.log', 'batch_a/log/a.log.1', 'batch_a/log/a.log.gz', 'batch_a/run.sh',
                        'batch_b/sortie.out', 'batch_b/archive/vieux.log'):
                Path(root, rel).parent.mkdir(parents=True, exist_ok=True)
                Path(root, rel).write_text('x', encoding='utf-8')
            found = probe.batch_files(root.replace('\\', '/'))
            noms = sorted(Path(f[0]).name for f in found['logs'])
            self.assertEqual(noms, ['a.log', 'a.log.1', 'sortie.out'])
            self.assertEqual([Path(f[0]).name for f in found['files']], ['run.sh'])

    def test_etats_de_l_enveloppe(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, 'b.run.state').write_text('started=10\nfinished=12\nrc=2\nduration=2\nautre=x\n', encoding='utf-8')
            Path(folder, 'b.run.tail').write_text('ERROR quota token=abc\n', encoding='utf-8')
            Path(folder, '..cache.state').write_text('rc=0\n', encoding='utf-8')
            runs = probe.wrapper_runs(folder)
        self.assertEqual(runs['runs'], [{'started': 10, 'finished': 12, 'rc': 2, 'duration': 2,
                                         'name': 'b.run', 'tail': ['ERROR quota token=***']}])


class Resultat(unittest.TestCase):
    def test_enveloppe_donne_le_code_et_la_cause(self):
        run = {'name': 'batch_factures.runBatchFactures', 'started': NOW - 100, 'finished': NOW - 50, 'rc': 1,
               'duration': 50, 'tail': ['INFO debut', 'ERROR Table FACTURE verrouillée', 'fin anormale']}
        e = one(saved(runs=[run]))[0]
        self.assertEqual(e['state'], 'failed')
        self.assertEqual(e['outcome']['source'], 'Enveloppe (fin de sortie d’erreur)')
        self.assertEqual(e['outcome']['reason'], 'Code retour 1 — ERROR Table FACTURE verrouillée')
        self.assertIn('Dernier passage en échec', e['findings'][0]['text'])

    def test_journal_seul(self):
        ko = log('/var/batch/batch_factures/log/runBatchFactures.log', 'failed', errors=['ERROR SFTP refusé'])
        e = one(saved(logs=[ko]))[0]
        self.assertEqual((e['state'], e['outcome']['source']), ('failed', 'Journal du batch'))
        self.assertEqual(e['outcome']['reason'], 'Erreur dans le journal — ERROR SFTP refusé')
        self.assertEqual(e['log']['why'], 'Journal au nom du script')
        ok = log('/var/batch/batch_factures/log/runBatchFactures.log', 'success', strength='Statut Spring Batch COMPLETED')
        e = one(saved(logs=[ok]))[0]
        self.assertEqual((e['state'], e['outcome']['reason']), ('ok', 'Statut Spring Batch COMPLETED'))

    def test_code_zero_mais_erreur_au_journal(self):
        run = {'name': 'batch_factures.runBatchFactures', 'started': NOW - 100, 'finished': NOW - 50, 'rc': 0, 'tail': []}
        ko = log('/var/batch/batch_factures/log/runBatchFactures.log', 'failed', errors=['ERROR 3 lignes rejetées'])
        e = one(saved(logs=[ko], runs=[run]))[0]
        self.assertEqual(e['outcome']['verdict'], 'success')
        self.assertEqual(e['state'], 'drift')
        self.assertIn('Code retour 0 mais erreur dans le journal', e['findings'][0]['text'])

    def test_zabbix_complete_par_le_journal(self):
        res = {'job': [{'name': 'batch_factures.runBatchFactures', 'state': 'failed', 'rc': 2, 'finished_at': NOW - 60}]}
        ko = log('/var/batch/batch_factures/log/runBatchFactures.log', 'failed', errors=['ERROR disque plein'])
        e = one(saved(logs=[ko]), results=res)[0]
        self.assertEqual(e['outcome']['source'], 'Zabbix (enveloppe)')
        self.assertEqual(e['outcome']['reason'], 'Code retour 2 — ERROR disque plein')

    def test_passage_manque(self):
        vieux = log('/var/batch/batch_factures/log/runBatchFactures.log', 'success', mtime=NOW - 30 * 3600)
        e = one(saved(logs=[vieux]))[0]
        self.assertEqual(e['state'], 'drift')
        self.assertIn('non mis à jour depuis 30 h', e['findings'][0]['text'])
        mensuel = one(saved(logs=[vieux]), {'horaire': '05:00 (le 1er du mois)'})[0]
        self.assertEqual(mensuel['state'], 'ok')

    def test_journal_partage_ou_designe_par_cron(self):
        shared = [log('/var/batch/batch_catalog/log/catalog.log', 'success')]
        fiches = ({'nom': 'Catalog', 'scripts': ['/var/batch/batch_catalog/scripts/batchCatalog.sh']},
                  {'nom': 'Catalog Dz', 'scripts': ['/var/batch/batch_catalog/scripts/batchCatalogDz.sh']})
        entries = one(saved(logs=shared), *fiches)
        self.assertTrue(all('partagé par plusieurs batchs' in e['log']['why'] for e in entries))
        cron = {'id': 'c', 'kind': 'cron', 'script': SCRIPT, 'schedule': '30 2 * * *',
                'log': '/var/log/factures.log', 'owner': 'root'}
        e = one(saved(logs=[log('/var/log/factures.log', 'success'),
                            log('/var/batch/batch_factures/log/runBatchFactures.log', 'failed')], jobs=[cron]))[0]
        self.assertEqual((e['log']['path'], e['log']['why']), ('/var/log/factures.log', 'Journal désigné par la ligne cron'))

    def test_enveloppe_non_referencee(self):
        run = {'name': 'batch_nouveau.run', 'started': 1, 'finished': 2, 'rc': 0, 'tail': []}
        r = bc.reconcile(catalog(), HOSTS, saved(runs=[run]), {}, lambda _at: True, now=NOW)
        self.assertEqual([(u['name'], u['kind'], u['state']) for u in r['unreferenced']],
                         [('batch_nouveau.run', 'enveloppe', 'success')])


if __name__ == '__main__':
    unittest.main()
