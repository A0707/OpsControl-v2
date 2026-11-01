"""Scans persistants, comparaison de périmètres et rapprochement sans réseau."""
import sqlite3
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import FastAPI
from routers import all_routes
import discovery_history as store
import migrations
import network_discovery as discovery
import proxmox_inventory
import retention


def host(ip, ports=(22,)):
    return {'ip': ip, 'ports': list(ports), 'ttl': 64, 'ssh_banner': 'SSH-2.0-Test',
            'dns': 'demo.example.test', 'type': 'Linux probable', 'os': 'Test',
            'ping': True, 'ssh_port': 22 if 22 in ports else None}


class DiscoveryHistoryTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        migrations.apply(self.db)
        @contextmanager
        def connect():
            with self.db:
                yield self.db
        self.connect = connect
        self.at = datetime.now(timezone.utc).isoformat()

    def save(self, rows, network='192.0.2.0/29', **kwargs):
        return store.save(self.connect, network, self.at, 1.25, rows, **kwargs)

    def test_same_range_differences_and_restart(self):
        first = self.save([host('192.0.2.1'), host('192.0.2.2')])
        self.save([host('192.0.2.1', (22, 443)), host('192.0.2.3')])
        result = store.history(self.connect)['scans'][0]
        self.assertEqual(result['previous_scan_id'], first)
        self.assertEqual(result['changes'], {'appeared':['192.0.2.3'], 'disappeared':['192.0.2.2'],
                         'ports_changed':[{'ip':'192.0.2.1','before':[22],'after':[22,443]}]})
        context = SimpleNamespace(connect=self.connect, HOSTS=[
            {'key':'missing','name':'Démo absente','ip':'192.0.2.2'},
            {'key':'outside','ip':'198.51.100.2'}], api_connections=lambda:[])
        app = FastAPI()
        with patch.object(discovery, 'probe') as probe:
            discovery.install(app, context)
            routes = {(r.path,next(iter(r.methods))):r.endpoint for r in all_routes(app) if r.path.startswith('/api/')}
            state = routes['/api/discovery','GET']()
        probe.assert_not_called()
        self.assertEqual(len(state['items']), 2)
        self.assertEqual([h['key'] for h in state['inventory_missing']], ['missing'])
        self.assertFalse(state['job']['running'])

    def test_different_range_and_failed_scan_are_not_compared(self):
        self.save([host('192.0.2.1')])
        self.save([host('198.51.100.1')], '198.51.100.0/29')
        self.save([], status='failed', error='Sonde simulée interrompue')
        scans = store.history(self.connect)['scans']
        self.assertTrue(all(s['changes'] is None for s in scans))
        self.assertEqual(store.latest(self.connect)['range'], '198.51.100.0/29')
        self.assertEqual(store.latest(self.connect)['last_attempt']['status'], 'failed')

    def test_empty_scan_and_pagination(self):
        self.save([host('192.0.2.1')])
        self.save([])
        page = store.history(self.connect, limit=1)
        self.assertEqual(page['scans'][0]['changes']['disappeared'], ['192.0.2.1'])
        older = store.history(self.connect, limit=1, before_id=page['next_before_id'])
        self.assertEqual(len(older['scans']), 1)
        self.assertIsNone(older['next_before_id'])

    def test_purge_children_and_metadata(self):
        old = (datetime.now(timezone.utc)-timedelta(days=31)).isoformat()
        store.save(self.connect, '192.0.2.0/29', old, 1, [host('192.0.2.1')])
        self.save([host('192.0.2.2')])
        counts = retention.sweep(self.db, [])
        self.assertEqual(counts['discovery_scans'], 1)
        self.assertEqual(counts['discovery_hosts'], 1)
        self.assertEqual(self.db.execute('SELECT ip FROM discovery_hosts').fetchall(), [('192.0.2.2',)])
        self.assertEqual(migrations.apply(self.db), [])


class ProxmoxProposalTests(unittest.TestCase):
    def source(self, guests):
        return {'key':'pve','name':'Cluster fictif','provider':'Proxmox','last_result':{
            'status':'observed','collected_at':(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat(),
            'inventory':{'nodes':[{'name':'node-test','guests':guests}]}}}

    def test_name_ip_and_ambiguity(self):
        guest = {'vmid':1,'name':'demo','addresses':['192.0.2.1']}
        result = discovery.proxmox_proposals([host('192.0.2.1')], [self.source([guest])])[0]
        self.assertEqual(result['proxmox_proposal']['node'], 'node-test')
        self.assertEqual(result['proxmox_proposal']['basis'], 'ip')
        self.assertTrue(result['proxmox_proposal']['fresh'])
        result = discovery.proxmox_proposals([host('192.0.2.2')], [self.source([guest])])[0]
        self.assertEqual(result['proxmox_proposal']['basis'], 'dns')
        result = discovery.proxmox_proposals([host('192.0.2.1')], [self.source([guest, {**guest,'vmid':2}])])[0]
        self.assertIsNone(result['proxmox_proposal'])
        self.assertEqual(len(result['proxmox_matches']), 2)

    def test_normalizer_keeps_only_supplied_valid_addresses(self):
        result = proxmox_inventory.inventory({'data':[{'type':'qemu','node':'test','vmid':1,
            'name':'demo','addresses':['192.0.2.1/24','invalid','127.0.0.1']} ]})
        self.assertEqual(result['nodes'][0]['guests'][0]['addresses'], ['192.0.2.1'])
