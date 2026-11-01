from routers import all_routes  # routes des APIRouter inclus (FastAPI ne les recopie plus dans app.routes)
import unittest
from datetime import datetime, timezone
from synchronization import federate, fresh


class SynchronizationTests(unittest.TestCase):
    def source(self, key='pve'):
        return {'key': key, 'name': key, 'provider': 'Proxmox', 'last_result': {
            'collected_at': datetime.now(timezone.utc).isoformat(), 'status': 'observed',
            'inventory': {'nodes': [{'name': 'node1', 'guests': [{'name': 'web', 'vmid': 101, 'status': 'running'}]}]}}}

    def test_unique_match_does_not_change_ssh(self):
        h={'key':'web','name':'web','ip':'192.0.2.1','status':'unknown'}
        r=federate([h],[self.source()])
        self.assertEqual(r['assets'][0]['association'],'unique')
        self.assertEqual(r['assets'][0]['ip'],h['ip'])
        self.assertEqual(r['assets'][0]['status'],'unknown')
        self.assertNotIn('proxmox_matches',h)

    def test_duplicate_clusters_are_ambiguous(self):
        r=federate([{'key':'web','name':'web'}],[self.source(),self.source('pve2')])
        self.assertEqual(r['assets'][0]['association'],'ambiguous')

    def test_duplicate_hosts_not_merged(self):
        r=federate([{'key':'a','name':'web'},{'key':'b','name':'web'}],[self.source()])
        self.assertEqual(len(r['unmatched_guests']),1)
        self.assertTrue(all(not h['proxmox_matches'] for h in r['assets']))

    def test_failed_source_and_stale_data_are_not_healthy(self):
        s=self.source();s['last_result']={'status':'unknown','error':'TLS'}
        r=federate([], [s])
        self.assertFalse(r['sources'][0]['fresh'])
        self.assertEqual(r['sources'][0]['error'],'TLS')
        self.assertIn('Zabbix',r['missing_providers'])
        for value in (None,'bad','2020-01-01T00:00:00','2020-01-01T00:00:00+00:00'):
            self.assertFalse(fresh(value))


class SyncPayloadTests(unittest.TestCase):
    def test_sync_row_keeps_proxmox_summary_only(self):
        # Régression audit 31/10 (fiche 12.1) : l'allègement retirait proxmox_matches
        # et la page Synchronisation levait une exception à l'ouverture.
        from synchronization import sync_row
        asset = federate([{'key': 'web', 'name': 'web'}], [SynchronizationTests().source()])['assets'][0]
        asset['proxmox_matches'][0]['addresses'] = ['192.0.2.1']
        row = sync_row(asset)
        self.assertEqual(row['proxmox_matches'], [{'cluster': 'pve', 'node': None, 'vmid': 101,
                                                   'status': 'running', 'fresh': True}])
        self.assertTrue(row['detail_trimmed'])
        self.assertEqual(sync_row({'key': 'x'})['proxmox_matches'], [])


class ActiveScopeTests(unittest.TestCase):
    def setup_data(self):
        host = {'key': 'web', 'name': 'web', 'ip': '192.0.2.1'}
        source = SynchronizationTests().source()
        network = {'key': 'web', 'ip': host['ip'], 'ping': True,
                   'collected_at': datetime.now(timezone.utc).isoformat()}
        return host, source, network

    def test_running_and_recent_ping_required(self):
        h, s, n = self.setup_data()
        self.assertTrue(federate([h], [s], [n])['assets'][0]['active_scope'])
        for ping in (False, None):
            n['ping'] = ping
            self.assertFalse(federate([h], [s], [n])['assets'][0]['active_scope'])

    def test_old_wrong_ip_or_missing_ping_excluded(self):
        h, s, n = self.setup_data()
        for net in ([], [{**n, 'ip': '192.0.2.99'}], [{**n, 'collected_at': '2000-01-01T00:00:00+00:00'}]):
            self.assertFalse(federate([h], [s], net)['assets'][0]['active_scope'])

    def test_stopped_failed_stale_ambiguous_proxmox_excluded(self):
        h, s, n = self.setup_data()
        self.assertFalse(federate([h], [s, s], [n])['assets'][0]['active_scope'])
        s['last_result']['inventory']['nodes'][0]['guests'][0]['status'] = 'stopped'
        self.assertFalse(federate([h], [s], [n])['assets'][0]['active_scope'])
        s['last_result']['inventory']['nodes'][0]['guests'][0]['status'] = 'running'
        s['last_result']['status'] = 'unknown'
        self.assertFalse(federate([h], [s], [n])['assets'][0]['active_scope'])
        s['last_result']['status'] = 'observed'
        s['last_result']['collected_at'] = '2000-01-01T00:00:00+00:00'
        self.assertFalse(federate([h], [s], [n])['assets'][0]['active_scope'])


class AvailabilityRefreshTests(unittest.TestCase):
    def test_refresh_runs_network_and_api_without_ssh(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        from fastapi import FastAPI
        from synchronization import install
        context = SimpleNamespace(api_connections=Mock(return_value=[]), HOSTS=[],
                                  launch_network=Mock(return_value={'running': True}),
                                  launch=Mock())
        app = FastAPI()
        install(app, context)
        endpoint = next(r.endpoint for r in all_routes(app) if r.path == '/api/availability/refresh')
        result = endpoint()
        context.launch_network.assert_called_once_with([], 'disponibilite-locale')
        context.launch.assert_not_called()
        self.assertIn('api', result)
        self.assertIn('network', result)
