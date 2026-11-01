"""Portée progressive et niveaux de Ruff ; Git et Ruff sont simulés."""
import contextlib
import json
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from deploy import ci


class RuffScopeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        for name in ('changed.py', 'new.py', 'unchanged.py', 'release/old.py',
                     '.venv/old.py', '.graphify-packages/old.py'):
            path = self.base/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('pass\n')
        base = patch.object(ci, 'BASE', self.base)
        base.start()
        self.addCleanup(base.stop)
        env = patch.dict(os.environ, {'INFRAOPS_RUFF_BASE':''})
        env.start()
        self.addCleanup(env.stop)

    def test_worktree_and_untracked_exclude_legacy_and_deleted_files(self):
        answers = [subprocess.CompletedProcess([],0,stdout='changed.py\0deleted.py\0release/old.py\0.venv/old.py\0'),
                   subprocess.CompletedProcess([],0,stdout='new.py\0.graphify-packages/old.py\0note.md\0')]
        with patch.object(ci.subprocess, 'run', side_effect=answers):
            self.assertEqual(ci.changed_python_files(), ['changed.py','new.py'])

    def test_hook_only_checks_staged_files(self):
        answer = subprocess.CompletedProcess([],0,stdout='changed.py\0')
        with patch.object(ci.subprocess,'run',return_value=answer) as run:
            self.assertEqual(ci.changed_python_files(staged=True), ['changed.py'])
        self.assertEqual(run.call_count,1)
        self.assertIn('--cached',run.call_args.args[0])

    def test_ci_compares_base_and_head(self):
        base = 'a'*40
        answer = subprocess.CompletedProcess([],0,stdout='new.py\0')
        with patch.dict(os.environ, {'INFRAOPS_RUFF_BASE':base}), patch.object(ci.subprocess,'run',return_value=answer) as run:
            self.assertEqual(ci.changed_python_files(), ['new.py'])
        self.assertIn(base,run.call_args.args[0])
        self.assertIn('HEAD',run.call_args.args[0])

    def test_base_absente_apres_force_push(self):
        # Audit CI-06 : commit de base réécrit → comparaison avec le commit précédent.
        base = 'b'*40
        answers = [subprocess.CompletedProcess([],128,stdout='',stderr='bad object'),
                   subprocess.CompletedProcess([],0,stdout='new.py\0')]
        with patch.dict(os.environ, {'INFRAOPS_RUFF_BASE':base}), patch.object(ci.subprocess,'run',side_effect=answers) as run, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ci.changed_python_files(), ['new.py'])
        self.assertIn('HEAD~1', run.call_args.args[0])

    def test_initial_push_lists_tracked_files(self):
        answer = subprocess.CompletedProcess([],0,stdout='changed.py\0release/old.py\0')
        with patch.dict(os.environ, {'INFRAOPS_RUFF_BASE':'0'*40}), patch.object(ci.subprocess,'run',return_value=answer) as run:
            self.assertEqual(ci.changed_python_files(), ['changed.py'])
        self.assertEqual(run.call_args.args[0],['git','ls-files','-z'])

    def test_orphan_public_history_checks_all_tracked_files(self):
        answers = [subprocess.CompletedProcess([], 128, stdout='', stderr='bad object'),
                   subprocess.CompletedProcess([], 128, stdout='', stderr='unknown HEAD~1'),
                   subprocess.CompletedProcess([], 0, stdout='changed.py\0unchanged.py\0')]
        with patch.dict(os.environ, {'INFRAOPS_RUFF_BASE': 'b' * 40}), \
                patch.object(ci.subprocess, 'run', side_effect=answers) as run, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ci.changed_python_files(), ['changed.py', 'unchanged.py'])
        self.assertEqual(run.call_args.args[0], ['git', 'ls-files', '-z'])

    def test_invalid_base_fails_without_invoking_git(self):
        with patch.dict(os.environ, {'INFRAOPS_RUFF_BASE':'--invalid'}), patch.object(ci.subprocess,'run') as run:
            with self.assertRaises(ValueError):
                ci.changed_python_files()
        run.assert_not_called()


class RuffLevelsTests(unittest.TestCase):
    def test_style_is_informative_and_no_file_is_changed(self):
        with patch.object(ci.subprocess,'run',return_value=subprocess.CompletedProcess([],0)) as run, contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(ci.run_ruff(['demo.py']))
        blocking, style = [call.args[0] for call in run.call_args_list]
        self.assertIn('E9,F', blocking)
        self.assertIn('--exit-zero', style)
        self.assertIn('--statistics', style)
        for command in (blocking,style):
            self.assertIn('--no-fix',command)
            self.assertNotIn('--fix',command)
            self.assertNotIn('format',command)
            self.assertEqual(command[-1],'demo.py')

    def test_real_errors_fail_ci(self):
        answers = [subprocess.CompletedProcess([],1), subprocess.CompletedProcess([],0)]
        with patch.object(ci.subprocess,'run',side_effect=answers), contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(ci.run_ruff(['demo.py']))

    def test_no_changes_do_not_lint_the_whole_repository(self):
        with patch.object(ci.subprocess,'run') as run, contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(ci.run_ruff([]))
        run.assert_not_called()


class BanditOutcomeTests(unittest.TestCase):
    """Audit A4 : seul un rapport complet de Bandit peut valider la chaîne."""

    def bandit(self, code, stdout, stderr=''):
        output = io.StringIO()
        result = subprocess.CompletedProcess(['bandit'], code, stdout=stdout, stderr=stderr)
        with patch.object(ci.subprocess, 'run', return_value=result),                 patch.object(ci, 'git_files', return_value=['module.py']), contextlib.redirect_stdout(output):
            ok = ci.run_bandit()
        return ok, output.getvalue()

    def constat(self, severity, confidence):
        return {'issue_severity': severity, 'issue_confidence': confidence, 'test_id': 'B000',
                'filename': 'module.py', 'line_number': 1, 'issue_text': 'exemple'}

    def test_echec_de_l_outil_bloque(self):
        for code, stdout in ((2, ''), (2, '{"results": []}'), (0, ''), (1, 'pas du json'),
                             (0, '[]'), (0, '{"errors": []}')):
            with self.subTest(code=code, stdout=stdout):
                ok, text = self.bandit(code, stdout, 'scanner en panne')
                self.assertFalse(ok)
                self.assertIn('ÉCHEC de Bandit', text)

    def test_analyse_partielle_bloque(self):
        rapport = json.dumps({'results': [], 'errors': [{'filename': 'module.py', 'reason': 'syntax error'}]})
        ok, text = self.bandit(0, rapport)
        self.assertFalse(ok)
        self.assertIn('NON ANALYSÉ module.py', text)

    def test_seuils_appliques_aux_analyses_completes(self):
        self.assertTrue(self.bandit(0, json.dumps({'results': [], 'errors': []}))[0])
        self.assertTrue(self.bandit(1, json.dumps({'results': [self.constat('LOW', 'HIGH')], 'errors': []}))[0])
        ok, text = self.bandit(1, json.dumps({'results': [self.constat('MEDIUM', 'HIGH')], 'errors': []}))
        self.assertFalse(ok)
        self.assertIn('BLOQUANT B000', text)


class MissingToolTests(unittest.TestCase):
    """Audit CI-02 : un outil absent donne un échec lisible, jamais une trace Python."""

    def run_quiet(self, step, *args):
        output = io.StringIO()
        with patch.object(ci.subprocess, 'run', side_effect=FileNotFoundError('outil')), \
                patch.object(ci, 'git_files', return_value=['module.py']), contextlib.redirect_stdout(output):
            ok = step(*args)
        return ok, output.getvalue()

    def test_bandit_absent(self):
        ok, text = self.run_quiet(ci.run_bandit)
        self.assertFalse(ok)
        self.assertIn('Bandit indisponible', text)

    def test_detect_secrets_absent(self):
        ok, text = self.run_quiet(ci.run_secrets, ['module.py'])
        self.assertFalse(ok)
        self.assertIn('detect-secrets indisponible', text)

    def test_pip_audit_absent(self):
        ok, text = self.run_quiet(ci.run_pip_audit)
        self.assertFalse(ok)
        self.assertIn('pip-audit indisponible', text)

    def test_ruff_absent(self):
        ok, text = self.run_quiet(ci.run_ruff, ['module.py'])
        self.assertFalse(ok)
        self.assertIn('Ruff indisponible', text)


class UiStepTests(unittest.TestCase):
    """Audit CI-03 : tests navigateur simulés lancés par ci.py --ui, recette réelle exclue."""

    def test_selection_et_echec(self):
        calls = []

        def fake(argv, **kwargs):
            calls.append(argv[1])
            return subprocess.CompletedProcess(argv, 1 if argv[1] == 'test_ui_v2.cjs' else 0, '', 'AssertionError: x')
        output = io.StringIO()
        with patch.object(ci.subprocess, 'run', side_effect=fake), contextlib.redirect_stdout(output):
            ok = ci.run_ui()
        self.assertFalse(ok)
        self.assertNotIn('test_ui.cjs', calls)
        self.assertNotIn('test_ui_proxmox.cjs', calls)
        self.assertIn('test_ui_false_green.cjs', calls)
        self.assertIn('ÉCHEC test_ui_v2.cjs', output.getvalue())

    def test_node_absent(self):
        output = io.StringIO()
        with patch.object(ci.subprocess, 'run', side_effect=FileNotFoundError('node')), contextlib.redirect_stdout(output):
            self.assertFalse(ci.run_ui())
        self.assertIn('Node.js indisponible', output.getvalue())
