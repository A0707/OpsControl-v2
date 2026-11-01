"""Les délais Windows ignorent un outil bloqué, sans masquer un résultat incorrect."""
import subprocess
import unittest
from unittest.mock import patch

import testing_tools as tools


class ToolRunnerTests(unittest.TestCase):
    def setUp(self):
        tools._states.clear()
        tools._linux_shell_available.cache_clear()

    def tearDown(self):
        tools._states.clear()
        tools._linux_shell_available.cache_clear()

    def test_windows_warms_once_then_uses_short_timeout(self):
        result = subprocess.CompletedProcess([], 0, stdout='ok')
        with (
            patch.object(tools, 'WINDOWS', True),
            patch.object(tools.subprocess, 'run', return_value=result) as run,
        ):
            tools.run_tool(self, ['ssh', '-G', '192.0.2.1'], kind='ssh', timeout=10)
            tools.run_tool(self, ['ssh', '-G', '192.0.2.2'], kind='ssh', timeout=10)
        self.assertEqual(run.call_args_list[0].args[0], ['ssh', '-V'])
        self.assertEqual([c.kwargs['timeout'] for c in run.call_args_list], [180, 30, 30])

    def test_warmup_timeout_gets_a_second_chance(self):
        timeout = subprocess.TimeoutExpired('bash', 180)
        result = subprocess.CompletedProcess([], 0)
        with (
            patch.object(tools, 'WINDOWS', True),
            patch.object(tools.subprocess, 'run', side_effect=[timeout, result, result]) as run,
        ):
            tools.run_tool(self, ['bash', '-n', 'example.sh'], kind='bash', timeout=20)
        self.assertEqual([c.kwargs['timeout'] for c in run.call_args_list], [180, 30, 30])
        self.assertEqual(run.call_args_list[1].args[0], ['bash', '-c', 'exit 0'])

    def test_unresponsive_warmup_skips_with_cached_reason(self):
        with (
            patch.object(tools, 'WINDOWS', True),
            patch.object(tools.subprocess, 'run',
                         side_effect=subprocess.TimeoutExpired('bash', 180)) as run,
        ):
            for _ in range(2):
                with self.assertRaisesRegex(unittest.SkipTest, 'lancement à blanc.*180 s puis 30 s'):
                    tools.run_tool(self, ['bash', '-n', 'example.sh'], kind='bash')
        self.assertEqual(run.call_count, 2)

    def test_timeout_after_warmup_skips_with_phase_and_budget(self):
        result = subprocess.CompletedProcess([], 0)
        with (
            patch.object(tools, 'WINDOWS', True),
            patch.object(tools.subprocess, 'run',
                         side_effect=[result, subprocess.TimeoutExpired('ssh', 30)]) as run,
        ):
            for _ in range(2):
                with self.assertRaisesRegex(unittest.SkipTest, 'commande de test.*30 s.*lancement à blanc'):
                    tools.run_tool(self, ['ssh', '-G', '192.0.2.1'], kind='ssh', timeout=10)
        self.assertEqual(run.call_count, 2)

    def test_real_exit_status_is_returned_unchanged(self):
        results = [subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 2, stdout='')]
        with (
            patch.object(tools, 'WINDOWS', True),
            patch.object(tools.subprocess, 'run', side_effect=results),
        ):
            result = tools.run_tool(self, ['bash', 'reader.sh'], kind='bash')
        self.assertEqual(result.returncode, 2)

    def test_linux_keeps_original_timeout_and_exception(self):
        timeout = subprocess.TimeoutExpired('ssh', 10)
        with (
            patch.object(tools, 'WINDOWS', False),
            patch.object(tools.subprocess, 'run', side_effect=timeout) as run,
        ):
            with self.assertRaises(subprocess.TimeoutExpired):
                tools.run_tool(self, ['ssh', '-G', '192.0.2.1'], kind='ssh', timeout=10, capture_output=True)
        run.assert_called_once_with(['ssh', '-G', '192.0.2.1'], timeout=10, capture_output=True)

    def test_missing_shell_has_explicit_skip_reason(self):
        with patch.object(tools.shutil, 'which', return_value=None):
            with self.assertRaisesRegex(unittest.SkipTest, 'bash absent du PATH'):
                tools.shell_path(self)

    def test_windows_initialization_failure_has_explicit_reason(self):
        with (
            patch.object(tools, 'WINDOWS', True),
            patch.object(tools.subprocess, 'run', side_effect=OSError()),
        ):
            with self.assertRaisesRegex(unittest.SkipTest, 'lancement à blanc impossible.*OSError'):
                tools.run_tool(self, ['bash', '-n', 'example.sh'], kind='bash')


class IsolationTests(unittest.TestCase):
    """Audit DB-10 : un shell d'exploitation ne redirige jamais les tests vers la vraie base."""

    def test_chemins_hors_dossier_temporaire_remplaces(self):
        import json
        import os
        import sys
        import tempfile
        from pathlib import Path
        production = {'COCKPIT_DB': '/opt/infraops/data/state.sqlite3', 'COCKPIT_AUDIT': '/opt/infraops/audit.log',
                      'COCKPIT_SSH_DIR': '/opt/infraops/data'}
        code = ('import json, os, testing_env; '
                'print(json.dumps({k: os.environ[k] for k in ("COCKPIT_DB", "COCKPIT_AUDIT", "COCKPIT_SSH_DIR")}))')
        out = subprocess.run([sys.executable, '-c', code], env={**os.environ, **production},
                             cwd=Path(__file__).parent, capture_output=True, text=True, timeout=60, check=True).stdout
        values = json.loads(out.strip().splitlines()[-1])
        root = Path(tempfile.gettempdir()).resolve()
        for name, value in values.items():
            self.assertNotEqual(value, production[name])
            Path(value).resolve().relative_to(root)   # lève si hors du dossier temporaire


class NetworkGuardTests(unittest.TestCase):
    """Audit TST-01 : aucune connexion ni résolution réelle possible pendant les tests."""

    def test_connexion_et_dns_externes_refuses_local_autorise(self):
        import socket
        import testing_env
        with self.assertRaises(testing_env.RealNetworkForbidden):
            socket.create_connection(('192.0.2.1', 22), timeout=1)
        with self.assertRaises(socket.gaierror):
            socket.getaddrinfo('infraops.example.test', 443)
        with self.assertRaises(socket.herror):
            socket.gethostbyaddr('10.77.0.11')
        self.assertTrue(socket.getaddrinfo('localhost', 80))
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        try:
            client = socket.create_connection(server.getsockname(), timeout=2)
            client.close()
        finally:
            server.close()


class HermeticEnvironmentTests(unittest.TestCase):
    """OC-AUDIT-018/019 : UDP, outils réseau, intervalles, coffre et secrets hérités."""

    def test_udp_et_outils_reseau_refuses(self):
        import socket
        import subprocess
        import testing_env
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            with self.assertRaises(testing_env.RealNetworkForbidden):
                udp.sendto(b'x', ('192.0.2.1', 514))
            with self.assertRaises(testing_env.RealNetworkForbidden):
                udp.sendto(b'x', 0, ('192.0.2.1', 514))
            udp.sendto(b'x', ('127.0.0.1', 9))   # boucle locale : autorisée
        finally:
            udp.close()
        for args in (['ping', '-n', '1', '192.0.2.1'], [r'C:\Windows\System32\PING.EXE', '192.0.2.1'],
                     ['/usr/bin/ssh', 'root@192.0.2.1', 'uptime'], 'ssh-keyscan 192.0.2.1', ['curl', 'https://x']):
            with self.subTest(args=args), self.assertRaises(testing_env.RealNetworkForbidden):
                subprocess.run(args, capture_output=True, timeout=5)
        self.assertIsNone(testing_env.network_tool(['ssh', '-G', '192.0.2.1']), 'lecture de configuration locale')
        self.assertIsNone(testing_env.network_tool([r'C:\Program Files\Git\bin\bash.exe', '-n', 'x.sh']))

    def test_valeurs_d_exploitation_heritees_remplacees(self):
        import json
        import os
        import sys
        import tempfile
        from pathlib import Path
        other_temp = tempfile.mkdtemp(prefix='instance-')   # sous TEMP mais hors de la suite
        hostile = {'INFRAOPS_AUTO_INTERVAL': '60', 'INFRAOPS_INCIDENT_SYNC': '1', 'GLPI_STATUS_SYNC_SECONDS': '900',
                   'COCKPIT_DB': str(Path(other_temp) / 'state.sqlite3'), 'LOCALAPPDATA': other_temp,
                   'INFRAOPS_ZABBIX_AUTH': 'sentinelle-exploitation', 'GLPI_USER_TOKEN': 'sentinelle-glpi'}
        env = {k: v for k, v in os.environ.items() if k != 'OPSCONTROL_TEST_ROOT'}
        code = ('import json, os, testing_env, secret_store; print(json.dumps({k: os.environ.get(k) for k in '
                + repr(sorted(hostile)) + '} | {"vault": str(secret_store.DOSSIER)}))')
        out = subprocess.run([sys.executable, '-c', code], env={**env, **hostile}, cwd=Path(__file__).parent,
                             capture_output=True, text=True, timeout=60, check=True).stdout
        values = json.loads(out.strip().splitlines()[-1])
        self.assertEqual((values['INFRAOPS_AUTO_INTERVAL'], values['INFRAOPS_INCIDENT_SYNC'],
                          values['GLPI_STATUS_SYNC_SECONDS']), ('0', '0', '0'))
        self.assertNotEqual(values['COCKPIT_DB'], hostile['COCKPIT_DB'], 'autre dossier TEMP refusé')
        self.assertIsNone(values['INFRAOPS_ZABBIX_AUTH'])
        self.assertIsNone(values['GLPI_USER_TOKEN'])
        self.assertNotIn(other_temp, values['vault'])
        self.assertNotIn(other_temp, values['LOCALAPPDATA'])
