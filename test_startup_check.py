"""Contrôle de démarrage et bilan à l'ouverture : niveaux, angles morts, passage unique."""
import contextlib
import sqlite3
import threading
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi import FastAPI

import self_monitor
from routers import all_routes  # routes des APIRouter inclus (FastAPI ne les recopie plus dans app.routes)
import startup_check

NOW = datetime(2026, 10, 15, 8, 0, tzinfo=timezone.utc)
RECENT = (NOW - timedelta(minutes=5)).isoformat()
OLD = (NOW - timedelta(days=3)).isoformat()


def alerte(id_, severity='critical', fresh=True, **extra):
    return {'id': id_, 'source': 'Zabbix', 'severity': severity, 'title': 'Titre ' + id_, 'fresh': fresh,
            'chronic': False, 'ack': None, 'count': 1, 'observed_at': RECENT, 'evidence': None,
            'targets': [{'name': 'srv-' + id_, 'host_key': 'srv-' + id_}], **extra}


def source(name='Zabbix', fresh=True, collected_at=RECENT, error=None):
    return {'name': name, 'provider': name, 'fresh': fresh, 'collected_at': collected_at, 'error': error}


def context(rows=None, interval=60):
    @contextlib.contextmanager
    def connect():
        db = sqlite3.connect(':memory:')
        try:
            yield db
        finally:
            db.close()
    return SimpleNamespace(connect=connect, rows=lambda: rows if rows is not None else [{'key': 'a', 'collected_at': RECENT}],
                           monitor={'interval': interval}, lifespan_started=False)


class BriefingTests(unittest.TestCase):
    def build(self, alerts=(), sources=(source(),), ctx=None, monitor=None, maintenance=()):
        centre = {'alerts': list(alerts), 'sources': list(sources), 'counts': {'chronic': 2}}
        with patch('alert_center.build', return_value=centre), \
             patch.object(startup_check, '_maintenances', return_value=list(maintenance)):
            return startup_check.build(ctx or context(), {'status': 'done'}, NOW,
                                       monitor or self_monitor.Monitor())

    def test_all_fresh_and_healthy_is_ok(self):
        data = self.build()
        self.assertEqual(data['level'], 'ok')
        self.assertEqual(data['sections'], [])
        self.assertFalse(data['checking'])

    def test_fresh_critical_interrupts_but_ack_maintenance_and_chronic_do_not(self):
        data = self.build([alerte('a'), alerte('b', ack={'by': 'x'}), alerte('c', chronic=True), alerte('d'),
                           alerte('e', severity='warning')],
                          maintenance=[{'active': True, 'source': 'Zabbix', 'target': 'srv-d'}])
        self.assertEqual(data['level'], 'critical')
        section = data['sections'][0]
        self.assertEqual((section['key'], [i['id'] for i in section['items']]), ('critical', ['a']))
        self.assertEqual(section['items'][0]['host_key'], 'srv-a')
        self.assertEqual((data['counts']['acknowledged'], data['counts']['maintenance'], data['counts']['chronic']), (1, 1, 2))

    def test_stale_critical_is_never_silent_on_opening(self):
        data = self.build([alerte('nuit', fresh=False)])
        self.assertEqual(data['level'], 'warning')
        self.assertEqual(data['sections'][0]['key'], 'reconfirm')
        self.assertIn('rien ne dit qu’il est résolu', data['sections'][0]['note'])

    def test_blind_spots_prevent_a_false_green(self):
        rows = [{'key': 'a', 'collected_at': RECENT}, {'key': 'b', 'collected_at': OLD}, {'key': 'c'},
                {'key': 'off', 'collect_enabled': False}]
        data = self.build(sources=[source('Zabbix', error='Délai dépassé'), source('Bacula', collected_at=None, fresh=False),
                                   source('Wazuh', fresh=False, collected_at=OLD)],
                          ctx=context(rows, interval=0))
        self.assertEqual(data['level'], 'unverified')
        titres = [i['title'] for i in data['sections'][0]['items']]
        self.assertEqual(titres, ['Source Zabbix en échec', 'Source Bacula jamais collectée', 'Source Wazuh périmée',
                                  'Actualisation automatique désactivée',
                                  '2 serveur(s) sur 3 sans audit SSH depuis 24 h'])

    def test_no_source_and_silent_probe_are_blind_spots(self):
        sonde = alerte('x', severity='warning', id='Sonde directe:observer:warning', source='Sonde directe',
                       evidence='Dernière sonde il y a 40 s')
        data = self.build([sonde], sources=[])
        titres = [i['title'] for i in data['sections'][0]['items']]
        self.assertEqual(titres[0], 'Aucune source API configurée')
        self.assertIn('Titre x', titres)

    def test_failing_collector_or_stopped_scheduler_is_reported(self):
        monitor = self_monitor.Monitor()
        monitor.end('network', False, error='ping absent')
        monitor.end('network', False, error='ping absent')
        monitor.end('api', False, key='z', error='source déjà comptée')
        data = self.build(monitor=monitor)
        self.assertEqual(data['level'], 'warning')
        items = data['sections'][0]['items']
        self.assertEqual(len(items), 1)
        self.assertIn('2 fois de suite', items[0]['title'])

    def test_sections_are_bounded(self):
        data = self.build([alerte(str(i)) for i in range(12)])
        self.assertEqual((data['sections'][0]['count'], len(data['sections'][0]['items'])), (12, startup_check.SECTION_MAX))


class SweepTests(unittest.TestCase):
    def install(self, env='1'):
        api = {'running': False}
        ctx = SimpleNamespace(HOSTS=[{'key': 'a'}], net_lock=threading.Lock(), net_job={'running': False},
                              api_sync_state=lambda: dict(api), launch_api_sync=Mock(), launch_network=Mock())
        app = FastAPI()
        with patch.dict('os.environ', {startup_check.ENV: env}), patch.object(startup_check.time, 'monotonic', return_value=100):
            startup_check.install(app, ctx)
        return ctx, api, app

    def test_single_pass_after_delay_without_ssh(self):
        ctx, api, _ = self.install()
        ctx.startup_tick(now=101)
        ctx.launch_api_sync.assert_not_called()
        ctx.startup_tick(now=106)
        ctx.launch_api_sync.assert_called_once_with()
        ctx.launch_network.assert_called_once_with(ctx.HOSTS, 'demarrage')
        self.assertFalse(hasattr(ctx, 'launch') and isinstance(ctx.launch, Mock))
        api['running'] = True
        ctx.startup_tick(now=107)
        self.assertEqual(ctx.startup_state()['status'], 'running')
        api['running'] = False
        ctx.startup_tick(now=108)
        self.assertEqual(ctx.startup_state()['status'], 'done')
        ctx.startup_tick(now=500)
        ctx.launch_api_sync.assert_called_once()

    def test_failed_step_does_not_block_the_other_and_timeout_ends_the_wait(self):
        ctx, _, _ = self.install()
        ctx.launch_api_sync.side_effect = RuntimeError('boom')
        ctx.net_job['running'] = True
        with self.assertLogs('opscontrol.startup', 'ERROR'):
            ctx.startup_tick(now=106)
        ctx.launch_network.assert_called_once()
        self.assertEqual([s['launched'] for s in ctx.startup_state()['steps']], [False, True])
        ctx.startup_tick(now=106 + startup_check.SWEEP_TIMEOUT_SECONDS + 1)
        self.assertEqual(ctx.startup_state()['status'], 'timeout')

    def test_disabled_by_environment(self):
        ctx, _, _ = self.install(env='0')
        ctx.startup_tick(now=1000)
        ctx.launch_api_sync.assert_not_called()
        self.assertEqual(ctx.startup_state()['status'], 'disabled')

    def test_route_reports_checking_while_pending(self):
        ctx, _, app = self.install()
        with patch.object(startup_check, 'build', side_effect=lambda c, s: {'checking': s['status'] == 'pending'}):
            route = next(r for r in all_routes(app) if getattr(r, 'path', None) == '/api/briefing')
            self.assertEqual(route.endpoint(), {'checking': True})


class EndToEndTests(unittest.TestCase):
    def test_real_alert_center_feeds_the_briefing(self):
        """Sans simulation du centre d'alertes : un trigger Zabbix réel devient un incident du bilan."""
        import migrations
        db = sqlite3.connect(':memory:', check_same_thread=False)
        self.addCleanup(db.close)
        migrations.apply(db)

        @contextlib.contextmanager
        def connect():
            with db:
                yield db
        lu = datetime.now(timezone.utc) - timedelta(seconds=1)
        zabbix = {'key': 'z', 'name': 'ZABBIX', 'provider': 'Zabbix',
                  'last_result': {'status': 'observed', 'collected_at': lu.isoformat(), 'inventory': {'problems': [
                      {'description': 'PostgreSQL service not running', 'severity': 'high', 'severity_label': 'Haute',
                       'hosts': ['pg01'], 'last_change': str(int(lu.timestamp()) - 60)}]}}}
        ctx = SimpleNamespace(rows=lambda: [{'key': 'pg01', 'name': 'pg01', 'ip': '192.0.2.5',
                                             'collected_at': lu.isoformat(), 'status': 'ok', 'findings': []}],
                              connect=connect, api_connections=lambda: [zabbix], monitor={'interval': 60},
                              lifespan_started=False)
        data = startup_check.build(ctx, {'status': 'done'}, monitor=self_monitor.Monitor())
        self.assertEqual(data['level'], 'critical')
        self.assertEqual(data['sections'][0]['items'][0]['title'], 'PostgreSQL service not running')


if __name__ == '__main__':
    unittest.main()
