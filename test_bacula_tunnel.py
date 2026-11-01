import json
from unittest.mock import MagicMock, patch
from pydantic import ValidationError
from test_management import ManagementTests
import management as m


class BaculaTunnelTests(ManagementTests):
    def test_jobs_resolve_client_ids_and_keep_latest_outside_history(self):
        self.call('/api/connections', m.Connection(key='b', name='Backup', provider='Bacula',
                  url=m.BACULA_TUNNEL_URL, token_env='INFRAOPS_BACULA_AUTH_TEST'))
        jobs = {'error':0, 'output':[
            {'jobid':1,'name':'Weekly','clientid':7,'jobstatus':'R','starttime':'2026-10-06 02:00:00'},
            *[{'jobid':i,'name':'Daily','clientid':8,'jobstatus':'T'} for i in range(2,503)]]}
        clients = {'error':0,'output':[{'clientid':7,'name':'web-fd'}, {'clientid':8,'name':'db-fd'}]}
        responses = []
        for payload in (jobs, clients):
            response = MagicMock()
            response.__enter__.return_value.read.return_value = json.dumps(payload).encode()
            responses.append(response)
        opener = MagicMock()
        opener.open.side_effect = responses
        with patch.dict('os.environ', {'INFRAOPS_BACULA_AUTH_TEST':'Basic dTpw'}), patch.object(
                m.urllib.request, 'build_opener', return_value=opener):
            result = self.call('/api/connections/{key}/collect', 'b')
        self.assertEqual(result['status'], 'observed')
        self.assertEqual(len(result['inventory']['jobs']), 500)
        weekly = next(j for j in result['inventory']['latest'] if j['name']=='Weekly')
        self.assertEqual(weekly['client'], 'web-fd')
        self.assertEqual(weekly['clientid'], 7)
        self.assertEqual(weekly['starttime'], '2026-10-06 02:00:00')
        self.assertEqual([c.args[0].full_url for c in opener.open.call_args_list],
                         [m.BACULA_TUNNEL_URL, 'http://127.0.0.1:19096/api/v2/clients'])
        self.assertTrue(all(c.args[0].get_method()=='GET' for c in opener.open.call_args_list))

    def test_loopback_exception_is_exact_and_bacula_only(self):
        m.Connection(key='b', name='Backup', provider='Bacula', url=m.BACULA_TUNNEL_URL)
        for provider, url in [('JSON', m.BACULA_TUNNEL_URL),
                              ('Bacula', 'http://10.77.0.148:9096/api/v2/jobs'),
                              ('Bacula', m.BACULA_TUNNEL_URL + '?x=1')]:
            with self.assertRaises(ValidationError):
                m.Connection(key='b', name='Backup', provider=provider, url=url)

    def test_local_get_disables_proxy_and_accepts_large_history(self):
        self.call('/api/connections', m.Connection(key='b', name='Backup', provider='Bacula',
                  url=m.BACULA_TUNNEL_URL, token_env='INFRAOPS_BACULA_AUTH_TEST'))
        response = MagicMock()
        payload = {'error': 0, 'output': [{'jobid': i, 'jobstatus': 'T', 'name': 'x' * 100} for i in range(11869)]}
        response.__enter__.return_value.read.return_value = json.dumps(payload).encode()
        opener = MagicMock()
        opener.open.return_value = response
        with patch.dict('os.environ', {'INFRAOPS_BACULA_AUTH_TEST': 'Basic dTpw'}), patch.object(
                m.urllib.request, 'build_opener', return_value=opener) as build:
            result = self.call('/api/connections/{key}/collect', 'b')
        self.assertEqual(result['status'], 'observed')
        self.assertEqual(result['inventory']['jobs_count'], 11869)
        self.assertTrue(any(isinstance(h, m.urllib.request.ProxyHandler) and h.proxies == {}
                            for h in build.call_args.args))
        self.assertIn(m.NoRedirect, build.call_args.args)
        self.assertEqual(opener.open.call_args.args[0].get_method(), 'GET')
        self.assertNotIn('dTpw', json.dumps(result))
