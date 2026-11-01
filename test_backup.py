"""Contrôle de sauvegarde déduit des unités déjà collectées en SSH."""
import unittest

import audit_engine as a


def evaluate(units, timers_evidence=''):
    checks = [{'id': 'timers', 'evidence': timers_evidence}] if timers_evidence else []
    findings = []
    a.backup_check({'key': 'h'}, {'all_services': units}, checks, findings)
    backup = next(c for c in checks if c['id'] == 'backups')
    return backup, findings


class BackupCheckTests(unittest.TestCase):
    def test_units_not_read_concludes_nothing(self):
        """Le cas des 69 serveurs non collectés : surtout ne rien déduire."""
        backup, findings = evaluate(None)
        self.assertEqual(backup['status'], 'unknown')
        self.assertFalse(backup['executed'])
        self.assertIn('pas évaluable', backup['evidence'])
        self.assertEqual(findings[0]['severity'], 'unknown')
        self.assertIn("Absence de mesure n'est pas absence de sauvegarde", findings[0]['precaution'])

    def test_active_agent_is_observed_not_ok(self):
        backup, findings = evaluate([{'name': 'bacula-fd.service', 'status': 'active'},
                                     {'name': 'nginx.service', 'status': 'active'}])
        # 'observed' et non 'pass' : on a vu l'agent tourner, pas une sauvegarde réussie.
        self.assertEqual(backup['status'], 'observed')
        self.assertIn('Bacula File Daemon (active)', backup['evidence'])
        self.assertEqual(findings, [])

    def test_stopped_agent_raises_a_real_finding(self):
        backup, findings = evaluate([{'name': 'bacula-fd.service', 'status': 'inactive'}])
        self.assertEqual(backup['status'], 'fail')
        self.assertEqual(findings[0]['severity'], 'warning')
        self.assertIn('restaurable', findings[0]['precaution'])

    def test_inactive_oneshot_is_not_a_failed_backup(self):
        backup, findings = evaluate([{'name':'restic.service','status':'inactive'}])
        self.assertEqual(backup['status'],'observed')
        self.assertEqual(findings,[])
        self.assertIn('non déduit',backup['evidence'])

    def test_failed_agent_is_critical(self):
        backup, findings = evaluate([{'name': 'borgmatic.service', 'status': 'failed'}])
        self.assertEqual(findings[0]['severity'], 'critical')
        self.assertIn('Borgmatic', findings[0]['title'])

    def test_no_agent_never_claims_the_server_is_unprotected(self):
        """Une VM sauvegardée par son hyperviseur n'expose aucun agent."""
        backup, findings = evaluate([{'name': 'nginx.service', 'status': 'active'}])
        self.assertEqual(backup['status'], 'unknown')
        self.assertTrue(backup['executed'])
        self.assertEqual(findings[0]['severity'], 'unknown')
        self.assertNotIn('pas sauvegardé', findings[0]['title'])
        self.assertIn('hyperviseur', findings[0]['precaution'])

    def test_scheduled_timer_is_reported_as_evidence(self):
        backup, _ = evaluate([{'name': 'nginx.service', 'status': 'active'}],
                             timers_evidence='Mon 03:00 borgmatic.timer\nTue 04:00 apt-daily.timer')
        self.assertIn('borgmatic.timer', backup['evidence'])

    def test_unknown_unit_names_are_not_guessed(self):
        """« backup-maison.service » ne doit pas être pris pour un agent reconnu."""
        backup, findings = evaluate([{'name': 'backup-maison.service', 'status': 'active'}])
        self.assertEqual(backup['status'], 'unknown')
        self.assertIn('aucun agent de sauvegarde reconnu', backup['evidence'])


if __name__ == '__main__':
    unittest.main()


class AuditLogRotationTests(unittest.TestCase):
    """Le journal d'audit ne doit pas croitre sans limite (24 Mo constates)."""

    def test_rotation_bounds_the_log_and_keeps_archives(self):
        """On patche les constantes du module plutot que de le recharger :
        importlib.reload(ssh) remettrait OPERATIONS a son etat de base et
        effacerait les sondes ajoutees a l'import par audit_engine et waf_audit."""
        import tempfile, ssh
        from pathlib import Path
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as folder:
            journal = Path(folder) / 'audit.log'
            with patch.object(ssh, 'AUDIT_PATH', journal),                  patch.object(ssh, 'AUDIT_MAX_BYTES', 2000),                  patch.object(ssh, 'AUDIT_KEEP', 2):
                for _ in range(200):
                    ssh.audit('192.0.2.1', 'df', 'df -hP', 0, 5, 'test', True, 'x' * 50)
                archives = sorted(Path(folder).glob('audit.log.*'))
                self.assertLess(journal.stat().st_size, 20000, 'le journal actif doit rester borne')
                self.assertTrue(archives, 'au moins une archive doit exister')
                self.assertLessEqual(len(archives), 2, 'pas plus de AUDIT_KEEP archives')
                # La preuve reste lisible : chaque ligne est un JSON valide.
                self.assertIn('"op": "df"', journal.read_text(encoding='utf-8').splitlines()[0])

    def test_rotation_failure_never_blocks_the_audit_line(self):
        """Une rotation impossible ne doit pas faire perdre la preuve d'audit."""
        import tempfile, ssh
        from pathlib import Path
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as folder:
            journal = Path(folder) / 'audit.log'
            with patch.object(ssh, 'AUDIT_PATH', journal),                  patch.object(ssh, 'AUDIT_MAX_BYTES', 1),                  patch.object(ssh, '_rotate_audit', side_effect=OSError('disque plein')):
                with self.assertRaises(OSError):
                    ssh.audit('192.0.2.1', 'df', 'df -hP', 0, 5, 'test', True)
            # La vraie implementation, elle, avale l'erreur systeme.
            with patch.object(ssh, 'AUDIT_PATH', journal), patch.object(ssh, 'AUDIT_MAX_BYTES', 1),                  patch.object(Path, 'replace', side_effect=OSError('verrouille')):
                ssh.audit('192.0.2.1', 'df', 'df -hP', 0, 5, 'test', True)
            self.assertIn('"op": "df"', journal.read_text(encoding='utf-8'))
