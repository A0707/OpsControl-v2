import unittest
from unittest.mock import patch

from fastapi import FastAPI

import tier0
import zabbix_live as zl
from test_tier0 import make_context


def item(hostid, key, value, clock=1000, delay='1m', state='0', error=''):
    return {'itemid': key, 'hostid': hostid, 'key_': key, 'lastvalue': str(value), 'lastclock': str(clock),
            'delay': delay, 'state': state, 'error': error}


class SummarizeTests(unittest.TestCase):
    def test_metrics_from_real_template_keys(self):
        m = zl.summarize([
            item('1', 'system.cpu.util[,idle]', 88.3, 1010), item('1', 'system.cpu.util[,iowait]', 1.3),
            item('1', 'vm.memory.size[available]', 4, 1020), item('1', 'vm.memory.size[total]', 8, 900, '1h'),
            item('1', 'vfs.fs.size[/,pfree]', 17.1, 1030), item('1', 'vfs.fs.size[/var,pfree]', 20.8),
            item('1', 'vfs.fs.size[/var,pused]', 79.2), item('1', 'agent.ping', 1, 1005),
            item('1', 'system.cpu.load[percpu,avg1]', 0.39), item('1', 'proc.num[,,run]', 2),
        ])['1']
        self.assertEqual(m['cpu_pct'], (11.7, 1010))
        self.assertEqual(m['ram_pct'], (50.0, 1020))
        self.assertEqual(m['disk_max'], {'mount': '/', 'used_pct': 82.9, 'at': 1030})
        self.assertEqual(len(m['disks']), 2)  # /var relevé en pused ET pfree : une seule ligne
        self.assertEqual((m['measured_at'], m['oldest_at'], m['delay_s']), (1030, 900, 60))
        self.assertEqual(m['agent_ping'], (1.0, 1005))

    def test_unsupported_item_reported_never_invented(self):
        m = zl.summarize([item('1', 'vm.memory.size[available]', 0, state='1', error='Cannot obtain memory')])['1']
        self.assertIsNone(m['ram_pct'])
        self.assertIn('Cannot obtain memory', m['errors'][0])

    def test_never_measured_item_ignored(self):
        m = zl.summarize([item('1', 'agent.ping', 0, clock=0)])['1']
        self.assertIsNone(m['agent_ping'])
        self.assertIsNone(m['measured_at'])

    def test_delay_parsing(self):
        self.assertEqual([zl.delay_seconds(d) for d in ('1m', '30s', '10', '1h', '{$DELAY}', '1m;50s/1-5,09:00-18:00')],
                         [60, 30, 10, 3600, None, 60])


class RequestTests(unittest.TestCase):
    def test_body_is_fixed_and_hostids_validated(self):
        b = zl.body(['10452', '10390'])
        self.assertEqual(b['method'], 'item.get')
        self.assertEqual(b['params']['hostids'], ['10452', '10390'])
        self.assertEqual(b['params']['search']['key_'], zl.LIVE_KEYS)
        for mauvais in ([], ['10452 OR 1'], ['*']):
            with self.assertRaises(ValueError):
                zl.body(mauvais)

    def test_matching_by_ip_then_short_name(self):
        conn = {'provider': 'Zabbix', 'name': 'ZABBIX', 'last_result': {'status': 'observed', 'inventory': {'hosts': [
            {'hostid': '10452', 'host': 'autre-nom', 'name': 'autre-nom', 'addresses': ['10.77.0.167']},
            {'hostid': '10390', 'host': 'prddcyjob02.host.example.test', 'name': 'x', 'addresses': []}]}}}
        critiques = [{'key': 'job06', 'name': 'prdlabjob06', 'ip': '10.77.0.167'},
                     {'key': 'job02', 'name': 'prddcyjob02', 'ip': '10.9.9.9'},
                     {'key': 'absent', 'name': 'inconnu', 'ip': '10.0.0.1'}]
        with patch.object(zl, 'fetch', return_value=[item('10452', 'agent.ping', 1)]) as fetch:
            live, meta = zl.collect([conn], critiques)
        self.assertEqual(fetch.call_args.args[1], ['10390', '10452'])
        self.assertEqual(live['job06']['agent_ping'], (1.0, 1000))
        self.assertEqual(live['job02']['errors'], ['Aucun item correspondant sur cet hôte'])
        self.assertEqual(meta['unmatched'], ['absent'])


class LaneTests(unittest.TestCase):
    def start(self, ctx):
        tier0.install(FastAPI(), ctx)

    def test_live_lane_independent_of_probe_and_keeps_values_on_failure(self):
        ctx = make_context(self)
        self.start(ctx)
        with patch.object(tier0, '_start') as start:
            ctx.tier0_tick(now=0)
        noms = [c.args[2] for c in start.call_args_list]
        self.assertEqual(noms, ['tier0-probe', 'tier0-zabbix-live'])
        live_run = next(c.args for c in start.call_args_list if c.args[2] == 'tier0-zabbix-live')
        with patch('zabbix_live.collect', return_value=({'job06': {'cpu_pct': (12.0, 1000)}}, {'error': None})):
            live_run[0](*live_run[1])
        self.assertEqual(ctx.tier0_snapshot()['live']['job06']['cpu_pct'], (12.0, 1000))
        with patch('zabbix_live.collect', side_effect=TimeoutError('timed out')):
            live_run[0](*live_run[1])
        snap = ctx.tier0_snapshot()
        self.assertEqual(snap['live']['job06']['cpu_pct'], (12.0, 1000))  # valeur conservée, datée
        self.assertIn('timed out', snap['live_meta']['error'])

    def test_slow_zabbix_does_not_block_next_probe(self):
        ctx = make_context(self)
        self.start(ctx)
        with patch.object(tier0, '_start') as start:
            ctx.tier0_tick(now=0)
            probe = next(c.args for c in start.call_args_list if c.args[2] == 'tier0-probe')
            with patch('network_audit.ping', return_value=True), patch('ssh.tcp_reachable', return_value=(True, 5)):
                probe[0](*probe[1])     # la sonde se termine ; Zabbix est toujours « en cours »
            start.reset_mock()
            ctx.tier0_tick(now=6)
        self.assertEqual([c.args[2] for c in start.call_args_list], ['tier0-probe'])


if __name__ == '__main__':
    unittest.main()


class BatchResultTests(unittest.TestCase):
    """Fichiers d'état de deploy/infraops-batch-report.sh, lus par l'agent Zabbix."""

    def lots(self, *items):
        return zl.summarize([item('1', 'agent.ping', 1, 5000)] + list(items))['1']

    def batch(self, nom, rc, started, finished, duration=10):
        return [item('1', f'infraops.batch.rc[{nom}]', rc), item('1', f'infraops.batch.started[{nom}]', started),
                item('1', f'infraops.batch.finished[{nom}]', finished), item('1', f'infraops.batch.duration[{nom}]', duration)]

    def test_success_failure_running_and_never_run(self):
        m = self.lots(*self.batch('a.ok', 0, 3900, 4000, 99), *self.batch('b.ko', 2, 4050, 4100),
                      *self.batch('c.long', 0, 4200, 3000), *self.batch('d.neuf', -1, 4300, 0, 0),
                      *self.batch('e.jamais', -1, 0, 0, 0))
        etats = {b['name']: (b['state'], b['rc']) for b in m['batches']}
        self.assertEqual(etats, {'a.ok': ('success', 0), 'b.ko': ('failed', 2), 'c.long': ('running', 0),
                                 'd.neuf': ('running', None), 'e.jamais': ('unknown', None)})
        self.assertEqual(m['batches'][0]['name'], 'b.ko')  # les échecs d'abord
        self.assertEqual(next(b for b in m['batches'] if b['name'] == 'a.ok')['duration_s'], 99)

    def test_running_batch_keeps_previous_result_visible(self):
        m = self.lots(*self.batch('x', 3, 5000, 4000))
        self.assertEqual((m['batches'][0]['state'], m['batches'][0]['rc']), ('running', 3))

    def test_batch_clocks_do_not_age_system_metrics(self):
        m = self.lots(*[dict(i, lastclock='10') for i in self.batch('vieux', 0, 1, 2)])
        self.assertEqual((m['measured_at'], m['oldest_at']), (5000, 5000))

    def test_batch_triggers_are_critical_in_policy(self):
        import alert_policy
        for titre in ('Batch batch_demo-trade.run_import en échec (code 2)', 'Batch batch_bilan.mensuel non exécuté depuis 26h'):
            self.assertEqual(alert_policy.zabbix(titre, 'warning')[0], 'critical', titre)

    def test_tier0_view_exposes_results(self):
        ctx = make_context(self)
        tier0.install(FastAPI(), ctx)
        snap = ctx.tier0_snapshot()
        snap['live'] = {'job06': {'batches': [{'name': 'a', 'state': 'failed', 'rc': 1}, {'name': 'b', 'state': 'success', 'rc': 0}]}}
        vue = tier0.build(ctx, snap)['hosts'][0]['batch']
        self.assertEqual((vue['results_failed'], vue['results_measured'], len(vue['results'])), (1, True, 2))

    def test_template_and_agent_config_use_the_same_keys(self):
        from pathlib import Path
        base = Path(__file__).parent / 'deploy'
        modele = (base / 'zabbix-template-batch.yaml').read_text(encoding='utf-8')
        agent = (base / 'zabbix-agent-infraops-batch.conf').read_text(encoding='utf-8')
        for champ in ('rc', 'started', 'finished', 'duration'):
            self.assertIn(f"infraops.batch.{champ}[{{#BATCH}}]", modele)
            self.assertIn(f'UserParameter=infraops.batch.{champ}[*]', agent)
            self.assertIn(f'infraops.batch.{champ}[*]', zl.LIVE_KEYS)


class FastPathGuardTests(unittest.TestCase):
    """Audit SEC-04/05 : la voie rapide applique les garde-fous de la collecte principale."""

    def conn(self, **extra):
        return {'key': 'z', 'provider': 'Zabbix', 'url': 'https://zabbix.example.test/api_jsonrpc.php',
                'token_env': 'INFRAOPS_ZABBIX_AUTH', **extra}

    def refused(self, connection, bindings=None):
        import management
        import os
        with patch.object(management, 'ACTIVE_BINDINGS', bindings), \
                patch.dict(os.environ, {'INFRAOPS_ZABBIX_AUTH': 'x' * 40, 'INFRAOPS_OTHER': 'y' * 40}), \
                patch('urllib.request.OpenerDirector.open') as opened, \
                patch('socket.getaddrinfo', return_value=[(0, 0, 0, '', ('192.0.2.10', 0))]):
            with self.assertRaises(PermissionError) as raised:
                zl.fetch(connection, ['1'])
        opened.assert_not_called()
        return str(raised.exception)

    def test_variable_https_destination_et_liaison(self):
        self.assertIn('Variable de jeton refusée', self.refused(self.conn(token_env='INFRAOPS_OTHER')))
        self.assertIn('HTTPS', self.refused(self.conn(url='http://zabbix.example.test/api_jsonrpc.php')))
        self.assertIn('locale', self.refused(self.conn(url='https://[::ffff:127.0.0.1]/api_jsonrpc.php')))

        class Bound:
            def refusal(self, token_env, url):
                return 'Jeton lié à autre.example.test:443'
        self.assertIn('lié', self.refused(self.conn(), Bound()))

    def test_ca_resolved_and_confined_like_main_collector(self):
        # OC-AUDIT-010 : CA relative lue sous <base>/data/ca/, chemin hors de data/ca/ refusé, comme la collecte.
        import os
        import tempfile
        from pathlib import Path
        import management
        base = Path(tempfile.mkdtemp())
        (base / 'data' / 'ca').mkdir(parents=True)
        (base / 'data' / 'ca' / 'root.pem').write_text('fixture')
        outside = base / 'ailleurs.pem'
        outside.write_text('fixture')
        with patch.object(management, 'ACTIVE_BASE', base):
            self.assertIn('data/ca', self.refused(self.conn(ca_bundle=str(outside))))
            self.assertIn('data/ca', self.refused(self.conn(ca_bundle='../ailleurs.pem')))
            with patch.object(management, 'ACTIVE_BINDINGS', None), \
                    patch.dict(os.environ, {'INFRAOPS_ZABBIX_AUTH': 'x' * 40}), \
                    patch('socket.getaddrinfo', return_value=[(0, 0, 0, '', ('192.0.2.10', 0))]), \
                    patch.object(management, 'ssl_context_for', side_effect=ValueError('arrêt après TLS')) as tls:
                with self.assertRaises(ValueError):
                    zl.fetch(self.conn(ca_bundle='root.pem'), ['1'])
            self.assertEqual(Path(tls.call_args.args[0]['ca_bundle']), base / 'data' / 'ca' / 'root.pem')
        with patch.object(management, 'ACTIVE_BASE', None):
            self.assertIn('racine', self.refused(self.conn(ca_bundle='root.pem')))

    def test_ipv4_encapsulee_refusee(self):
        import management
        for value in ('::ffff:127.0.0.1', '::ffff:169.254.169.254', '127.0.0.1'):
            self.assertTrue(management.forbidden_ip(value), value)
        self.assertFalse(management.forbidden_ip('::ffff:192.0.2.1'))
