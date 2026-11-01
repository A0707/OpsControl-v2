import ast
from testing_tools import run_tool, shell_path
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / 'deploy'))
import wrap_crontab as w  # noqa: E402

CRONTAB = """MAILTO=ops@example.test
# batch de nuit
30 2 * * * cd /var/batch/batch_demo-trade && ./run_import.sh >> /var/log/demo-trade.log 2>&1
0 */4 * * 1-5 /var/batch/batch_demoapp_impayes/relance.py --mode 'complet'
15 3 1 * * /var/batch/batch_bilan/mensuel.sh "arg avec espaces"
0 5 * * * /var/batch/batch_bilan/mensuel.sh
0 0 1 ? 1/1 TUE#2 /var/batch/batch_x/q.sh
0 6 * * * date +%Y%m%d > /tmp/jour
@daily /var/batch/batch_catalog/purge.sh
"""


class WrapTests(unittest.TestCase):
    def test_wraps_batches_and_keeps_everything_else(self):
        sortie, rapport = w.envelopper(CRONTAB)
        lignes = sortie.splitlines()
        self.assertEqual(lignes[0], 'MAILTO=ops@example.test')
        self.assertEqual(lignes[1], '# batch de nuit')
        self.assertTrue(lignes[2].startswith('30 2 * * * /usr/local/bin/infraops-batch-report batch_demo-trade.run_import /bin/sh -c '))
        self.assertIn('infraops-batch-report batch_bilan.mensuel.2 ', lignes[5])  # nom rendu unique
        self.assertTrue(lignes[8].startswith('@daily /usr/local/bin/infraops-batch-report batch_catalog.purge '))
        self.assertEqual(len(lignes), len(CRONTAB.splitlines()))

    def test_refuses_quartz_and_percent_and_reports_them(self):
        sortie, rapport = w.envelopper(CRONTAB)
        self.assertIn('0 0 1 ? 1/1 TUE#2 /var/batch/batch_x/q.sh', sortie)
        self.assertIn('0 6 * * * date +%Y%m%d > /tmp/jour', sortie)
        texte = '\n'.join(rapport)
        self.assertIn('cron ne l’exécute PAS', texte)
        self.assertIn('contient « % »', texte)

    def test_idempotent(self):
        une_fois, _ = w.envelopper(CRONTAB)
        deux_fois, rapport = w.envelopper(une_fois)
        self.assertEqual(une_fois, deux_fois)
        self.assertTrue(any('déjà enveloppée' in r for r in rapport))

    def test_system_crontab_keeps_user_column_and_filter(self):
        texte = '17 * * * * root cd / && run-parts --report /etc/cron.hourly\n0 1 * * * batch /var/batch/b/x.sh\n'
        sortie, _ = w.envelopper(texte, systeme=True, filtre='/var/batch')
        lignes = sortie.splitlines()
        self.assertEqual(lignes[0], '17 * * * * root cd / && run-parts --report /etc/cron.hourly')
        self.assertTrue(lignes[1].startswith('0 1 * * * batch /usr/local/bin/infraops-batch-report b.x /bin/sh -c '))

    def test_runs_on_python_36(self):
        ast.parse(Path(w.__file__).read_text(encoding='utf-8'), feature_version=(3, 6))
        lignes = Path(w.__file__).read_text(encoding='utf-8').splitlines()
        self.assertFalse(any(l.startswith('from __future__ import annotations') for l in lignes))

    def test_wrapped_command_behaves_exactly_like_original(self):
        """La commande enveloppée, exécutée par un shell, produit la même chose."""
        shell = shell_path(self, 'sh')
        dossier = Path(tempfile.mkdtemp())
        faux = dossier / 'wrapper.sh'
        faux.write_text('#!/bin/sh\nshift\nexec "$@"\n', encoding='utf-8')  # ignore le NOM, exécute la suite
        original = "echo 'un' \"deux trois\" && echo quatre | tr a-z A-Z; exit 3"
        ligne, _ = w.envelopper('0 1 * * * ' + original + '\n')
        commande = ligne.strip().split(None, 5)[5].replace(w.WRAPPER, 'sh ' + faux.as_posix())
        attendu = run_tool(self, [shell, '-c', original], kind='sh', capture_output=True, text=True)
        obtenu = run_tool(self, [shell, '-c', commande], kind='sh', capture_output=True, text=True)
        self.assertEqual((obtenu.stdout, obtenu.returncode), (attendu.stdout, attendu.returncode))
        self.assertEqual(obtenu.returncode, 3)

    def test_report_keeps_masked_error_tail_without_changing_the_batch(self):
        """L'enveloppe garde la fin de la sortie d'erreur, masquée ; sorties et code inchangés."""
        import os
        shell = shell_path(self, 'sh')
        dossier = Path(tempfile.mkdtemp())
        script = Path(__file__).parent / 'deploy' / 'infraops-batch-report.sh'
        batch = 'echo resultat; echo "ERROR refus password=s3cret" >&2; echo "jdbc://u:pw@h" >&2; exit 3'  # pragma: allowlist secret -- valeurs factices du test de masquage
        env = {**os.environ, 'INFRAOPS_BATCH_DIR': dossier.as_posix()}
        r = run_tool(self, [shell, script.as_posix(), 'essai', shell, '-c', batch], kind='sh',
                     capture_output=True, text=True, env=env)
        self.assertEqual((r.returncode, r.stdout), (3, 'resultat\n'))
        self.assertIn('password=s3cret', r.stderr)  # la destination d'origine reçoit tout
        self.assertIn('rc=3', (dossier / 'essai.state').read_text(encoding='utf-8'))
        if not (dossier / 'essai.tail').exists():
            # sh sans /dev/stderr (Windows) : exécution directe vérifiée ci-dessus.
            self.skipTest('/dev/stderr absent : capture vérifiée sous Linux (CI)')
        tail = (dossier / 'essai.tail').read_text(encoding='utf-8')
        self.assertEqual(tail, 'ERROR refus password=***\njdbc://u:***@h\n')
        self.assertIn('rc=3', (dossier / 'essai.state').read_text(encoding='utf-8'))
        ok = run_tool(self, [shell, script.as_posix(), 'ok', 'true'], kind='sh', capture_output=True, text=True, env=env)
        self.assertEqual(ok.returncode, 0)
        self.assertEqual((dossier / 'ok.tail').read_text(encoding='utf-8'), '')


if __name__ == '__main__':
    unittest.main()
