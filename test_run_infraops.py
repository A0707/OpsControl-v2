import unittest
from unittest.mock import MagicMock, patch
import run_infraops as r


class TunnelTests(unittest.TestCase):
    def test_direct_app_owns_tunnel_and_closes_on_exit(self):
        import threading
        called=threading.Event()
        connection={'provider':'Bacula','url':'http://127.0.0.1:19096/api/v2/jobs','auth_configured':True}
        with patch.dict(r.os.environ, {'INFRAOPS_TUNNEL_SUPERVISED':'0'}), patch.object(r,'Tunnel') as factory:
            factory.return_value.tick.side_effect=called.set
            with r.application_tunnel(lambda:[connection]):
                self.assertTrue(called.wait(2))
            factory.return_value.close.assert_called_once()

    def test_supervised_app_does_not_start_second_owner(self):
        with patch.dict(r.os.environ, {'INFRAOPS_TUNNEL_SUPERVISED':'1'}), patch.object(r,'Tunnel') as factory:
            with r.application_tunnel(lambda:[]):pass
            factory.assert_not_called()

    def test_other_connections_do_not_open_tunnel(self):
        with patch.dict(r.os.environ, {'INFRAOPS_TUNNEL_SUPERVISED':'0'}), patch.object(r,'Tunnel') as factory:
            with r.application_tunnel(lambda:[{'provider':'Bacula','auth_configured':False}]):pass
            factory.return_value.tick.assert_not_called()

    @patch.object(r, 'port_open', return_value=True)
    @patch.object(r.subprocess, 'Popen')
    def test_existing_tunnel_not_owned(self, popen, port):
        tunnel = r.Tunnel()
        tunnel.tick()
        tunnel.close()
        popen.assert_not_called()

    @patch.dict(r.os.environ, {'INFRAOPS_BACULA_TUNNEL_TARGET': 'infraops@10.77.0.148'})
    @patch.object(r.Path, 'exists', return_value=True)
    @patch.object(r, 'port_open', return_value=False)
    @patch.object(r.subprocess, 'Popen')
    def test_reconnect_and_cleanup(self, popen, port, exists):
        first, second = MagicMock(), MagicMock()
        first.poll.return_value = None
        second.poll.return_value = None
        popen.side_effect = [first, second]
        tunnel = r.Tunnel()
        tunnel.tick()
        args = popen.call_args.args[0]
        self.assertEqual(args[-1], 'infraops@10.77.0.148')
        self.assertIn('StrictHostKeyChecking=yes', args)
        self.assertIn('127.0.0.1:19096:127.0.0.1:9096', args)
        tunnel.tick()
        self.assertEqual(popen.call_count, 1)
        first.poll.return_value = 255
        tunnel.tick()
        self.assertEqual(popen.call_count, 1)
        tunnel.retry_at = 0
        tunnel.tick()
        self.assertEqual(popen.call_count, 2)
        tunnel.close()
        second.terminate.assert_called_once()
        first.terminate.assert_not_called()


class PortabilityTests(unittest.TestCase):
    """La VM est sous Linux : le tunnel Bacula ne doit plus dépendre de Windows."""

    def test_linux_uses_ssh_from_path(self):
        with patch.object(r.os, 'name', 'posix'), patch.object(r.shutil, 'which', return_value='/usr/bin/ssh'):
            self.assertEqual(r.ssh_client(), '/usr/bin/ssh')

    def test_missing_client_retries_without_crashing(self):
        with patch.object(r, 'ssh_client', return_value=None), patch.object(r, 'port_open', return_value=False), \
                patch.object(r.subprocess, 'Popen') as popen:
            tunnel = r.Tunnel()
            tunnel.tick()
            popen.assert_not_called()
            self.assertGreater(tunnel.retry_at, 0)

    def test_tunnel_target_configurable_and_validated(self):
        with patch.dict(r.os.environ, {'INFRAOPS_BACULA_TUNNEL_TARGET': 'infraops@10.77.0.148'}):
            self.assertEqual(r.tunnel_target(), 'infraops@10.77.0.148')
        with patch.dict(r.os.environ, {'INFRAOPS_BACULA_TUNNEL_TARGET': '-oProxyCommand=x@h'}):
            with self.assertRaises(ValueError):
                r.tunnel_target()
        with patch.dict(r.os.environ, {}, clear=False):
            r.os.environ.pop('INFRAOPS_BACULA_TUNNEL_TARGET', None)
            self.assertIsNone(r.tunnel_target(), 'aucune valeur par défaut nominative')
