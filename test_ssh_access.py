import unittest
from unittest.mock import patch

import audit_engine
import batch_monitor
import ssh
from verify_ssh_access import verify


class SSHAccessTests(unittest.TestCase):
    def test_changed_key_is_distinguished_from_missing_key(self):
        kind, message = ssh.native_error('WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! Host key verification failed.')
        self.assertEqual(kind, 'host_key')
        self.assertIn('différente', message)
        self.assertIn('console du serveur', message)
        self.assertIn('absente', ssh.native_error('No ED25519 host key is known')[1])
        self.assertNotIn('différente', ssh.native_error('No ED25519 host key is known')[1])

    def setUp(self):
        self.host = {'key':'server', 'name':'Server', 'ip':'192.0.2.1'}
        self.cfg = ssh.SSHConfig(user='audit', key_path='unused', users=('audit','root'), ports=(22,3300))

    def test_port_failure_skips_other_users_but_tries_next_port(self):
        with patch('verify_ssh_access.run_operation', side_effect=[
            ssh.RunResult(False,None,'','',1,'network'),
            ssh.RunResult(True,0,'Linux','',1,'')]) as run:
            result = verify(self.host,self.cfg)
        self.assertEqual(result['status'],'connected')
        self.assertEqual(result['port'],3300)
        self.assertEqual([c.args[2].port for c in run.call_args_list],[22,3300])

    def test_authentication_failure_tries_only_configured_users(self):
        with patch('verify_ssh_access.run_operation', side_effect=[
            ssh.RunResult(False,None,'','',1,'auth'),
            ssh.RunResult(True,0,'Linux','',1,'')]) as run:
            result = verify(self.host,self.cfg)
        self.assertEqual(result['user'],'root')
        self.assertEqual([c.args[2].user for c in run.call_args_list],['audit','root'])

    def test_unknown_key_not_hidden_by_secondary_port_failure(self):
        responses=[ssh.RunResult(False,None,'','',1,'host_key'),ssh.RunResult(False,None,'','',1,'network')]
        with patch('verify_ssh_access.run_operation', side_effect=responses):
            self.assertEqual(verify(self.host,self.cfg)['status'],'host_key')
        with patch.object(ssh,'run_operation',side_effect=responses):
            result=batch_monitor.collect_host(self.host,self.cfg)
        self.assertIn('Clé SSH',result['limitations'][0])

    def test_batch_uses_alternate_configured_port(self):
        with patch.object(ssh,'run_operation',side_effect=[
            ssh.RunResult(False,None,'','',1,'network'),
            ssh.RunResult(True,0,'{"jobs":[],"limitations":[]}','',1,'')]):
            self.assertEqual(batch_monitor.collect_host(self.host,self.cfg)['status'],'observed')

    def test_disabled_hosts_are_not_contacted(self):
        with patch('verify_ssh_access.run_operation') as run:
            self.assertEqual(verify({**self.host,'collect_enabled':False},self.cfg)['status'],'disabled')
        run.assert_not_called()

    def test_failed_connection_guide_uses_platform_diagnostic(self):
        result={'status':'critical','issues':['Unknown host key'],'attempts':[{'error_kind':'host_key'}]}
        finding=audit_engine.enrich(self.host,self.cfg,result)['findings'][0]
        self.assertEqual(finding['check_command'],'python diagnostic_ssh.py 192.0.2.1')
        self.assertEqual(finding['solution_command'],'python register_host_key.py 192.0.2.1')
        self.assertFalse(finding['executable'])


if __name__ == '__main__':
    unittest.main()


class TcpFailureCauseTests(unittest.TestCase):
    """Audit UI du 31/10 (fiche 08.1) : « refusé » et « délai dépassé » ne se confondent pas."""

    def test_failure_cause_is_reported_without_changing_the_result(self):
        for error, expected in ((ConnectionRefusedError(), 'refused'), (TimeoutError(), 'timeout'),
                                (OSError(113, 'No route to host'), 'unreachable')):
            details = {}
            with patch('ssh.socket.create_connection', side_effect=error):
                self.assertEqual(ssh.tcp_reachable('192.0.2.1', 22, 0.1, details=details), (False, None))
            self.assertEqual(details['failure'], expected)
        with patch('ssh.socket.create_connection', side_effect=TimeoutError()):
            self.assertEqual(ssh.tcp_reachable('192.0.2.1', 22, 0.1), (False, None))
