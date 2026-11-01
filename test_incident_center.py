"""Journal d'incidents : cycle de vie, suppressions, sources en panne, migrations, API."""
from routers import all_routes  # routes des APIRouter inclus (FastAPI ne les recopie plus dans app.routes)
import contextlib
import json
import os
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

from fastapi import FastAPI, HTTPException
from starlette.datastructures import Headers

import incident_center as ic
import operator_identity

T0 = datetime(2026, 9, 29, 8, 0, tzinfo=timezone.utc)


def alert(source='SSH', kind='service:postfix.service', severity='critical', targets=None, chronic=False, evidence=None):
    return {'id': f'{source}:{kind}:{severity}' + (':chronique' if chronic else ''), 'source': source, 'severity': severity,
            'title': 'Service postfix.service en échec', 'evidence': evidence, 'rule': 'Services', 'chronic': chronic,
            'targets': targets if targets is not None else [{'name': 'web01', 'host_key': 'web01', 'fresh': True,
                                                             'observed_at': T0.isoformat(), 'detail': 'service de production'}]}


HOST_OK = [{'key': 'web01', 'name': 'web01', 'collected_at': T0.isoformat(), 'stale': False, 'coverage': {'measured': 12},
            'checks': [{'id': 'services', 'status': 'pass'}]}]
HOST_STALE = [{**HOST_OK[0], 'stale': True}]
ZBX_OK = [{'provider': 'Zabbix', 'name': 'ZABBIX', 'fresh': True, 'error': None}]
ZBX_KO = [{'provider': 'Zabbix', 'name': 'ZABBIX', 'fresh': False, 'error': 'Délai dépassé'}]


class Base(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        ic.migrate(self.db)

    def run_sync(self, alerts, rows=HOST_OK, sources=ZBX_OK, at=T0):
        return ic.reconcile(self.db, ic.observations(alerts), ic.source_status(sources, rows), at)

    def incident(self, incident_id='SSH|web01|service:postfix.service'):
        return ic.Repository(None).get(self.db, incident_id)

    def events(self, incident_id='SSH|web01|service:postfix.service'):
        return [r[0] for r in self.db.execute('SELECT kind FROM incident_events WHERE incident_id=? ORDER BY seq', (incident_id,))]


class LifecycleTests(Base):
    def test_stable_id_without_severity(self):
        self.assertEqual(ic.incident_type('SSH:service:postfix.service:critical', 'SSH'), 'service:postfix.service')
        self.assertEqual(ic.incident_type('Zabbix:X is down:critical:chronique', 'Zabbix'), 'X is down')
        obs = ic.observations([alert(targets=[{'name': 'a', 'host_key': 'a'}, {'name': 'b', 'host_key': 'b'}])])
        self.assertEqual(sorted(o['id'] for o in obs), ['SSH|a|service:postfix.service', 'SSH|b|service:postfix.service'])
        self.assertEqual(ic.observations([alert(source='Elastic', kind='cluster', targets=[])])[0]['id'], 'Elastic|global|cluster')

    def test_open_ack_resolve_reopen_cycle(self):
        self.assertEqual(self.run_sync([alert()])['opened'], 1)
        self.assertEqual(self.incident()['state'], 'open')
        ic.act(self.db, 'SSH|web01|service:postfix.service', 'ack', 'jdoe', 'proxy', 'redémarrage prévu', '24h', T0)
        inc = self.incident()
        self.assertEqual((inc['state'], inc['owner'], inc['owner_auth']), ('acknowledged', 'jdoe', 'proxy'))
        self.assertEqual(self.run_sync([], at=T0 + timedelta(minutes=5))['resolved'], 1)
        inc = self.incident()
        self.assertEqual(inc['state'], 'resolved')
        self.assertIsNotNone(inc['resolved_at'])
        self.assertEqual(self.run_sync([alert()], at=T0 + timedelta(minutes=10))['reopened'], 1)
        inc = self.incident()
        self.assertEqual((inc['state'], inc['reopen_count'], inc['owner']), ('reopened', 1, None))
        self.assertIsNotNone(inc['reopened_at'])
        self.assertEqual(self.events(), ['opened', 'ack', 'resolved', 'reopened'])

    def test_investigation_is_owned_traced_and_expires(self):
        self.run_sync([alert()])
        ic.act(self.db, 'SSH|web01|service:postfix.service', 'investigate', 'Operator', 'local',
               'analyse des journaux', '24h', T0)
        inc = self.incident()
        self.assertEqual((inc['state'], inc['owner'], inc['note']),
                         ('investigating', 'Operator', 'analyse des journaux'))
        self.assertEqual(ic._parse(inc['investigation_at']), T0)
        self.run_sync([alert()], at=T0 + timedelta(hours=25))
        self.assertEqual(self.incident()['state'], 'open')
        self.assertEqual(self.events(), ['opened', 'investigation_started', 'investigation_expired'])

    def test_severity_change_keeps_incident_and_history(self):
        self.run_sync([alert(severity='warning')])
        self.run_sync([alert(severity='critical')], at=T0 + timedelta(minutes=1))
        self.run_sync([alert(severity='warning')], at=T0 + timedelta(minutes=2))
        inc = self.incident()
        self.assertEqual((inc['severity'], inc['severity_max']), ('warning', 'critical'))
        self.assertEqual(self.events().count('severity_changed'), 2)
        self.assertEqual(self.db.execute('SELECT count(*) FROM incidents').fetchone()[0], 1)

    def test_since_uses_source_start_only_when_declared(self):
        zbx = alert(source='Zabbix', kind='X down', targets=[{'name': 'db01', 'host_key': None, 'fresh': True,
                                                              'started_at': str(int((T0 - timedelta(days=3)).timestamp()))}])
        self.run_sync([zbx, alert()])
        declared = ic.present(self.incident('Zabbix|db01|X down'), T0)
        self.assertEqual((declared['since_basis'], ic._parse(declared['since'])), ('source', T0 - timedelta(days=3)))
        self.assertEqual(declared['duration_seconds'], 3 * 86400)
        tracked = ic.present(self.incident(), T0)
        self.assertEqual(tracked['since_basis'], 'journal', 'sans début déclaré : jamais d’âge inventé')
        self.assertIsNone(tracked['first_observed_at'])

    def test_reconcile_is_idempotent(self):
        self.run_sync([alert()])
        before = self.events()
        self.run_sync([alert()], at=T0 + timedelta(seconds=30))
        self.assertEqual(self.events(), before)


class SourceFailureTests(Base):
    def test_stale_ssh_audit_never_resolves(self):
        self.run_sync([alert()])
        stats = self.run_sync([], rows=HOST_STALE, at=T0 + timedelta(minutes=5))
        self.assertEqual((stats['resolved'], stats['blocked']), (0, 1))
        inc = self.incident()
        self.assertEqual(inc['state'], 'open')
        self.assertIn('ancien', inc['confirmation_blocked_reason'])
        self.assertEqual(self.events(), ['opened', 'resolution_blocked'])
        self.run_sync([], rows=HOST_STALE, at=T0 + timedelta(minutes=6))
        self.assertEqual(self.events().count('resolution_blocked'), 1, 'blocage journalisé une seule fois')
        self.run_sync([], rows=HOST_OK, at=T0 + timedelta(minutes=7))
        self.assertEqual(self.incident()['state'], 'resolved')

    def test_partial_ssh_collect_does_not_resolve_unmeasured_control(self):
        # OC-AUDIT-003 : disque critique, puis collecte où seul le CPU est lu (1/15).
        disk = alert(kind='disk', evidence='/ : 97 %')
        self.run_sync([disk])
        partial = [{**HOST_OK[0], 'coverage': {'measured': 1, 'total': 15}, 'cpu': 12, 'disk_max': None,
                    'checks': [{'id': 'cpu', 'status': 'pass'}, {'id': 'disk_max', 'status': 'unknown'}]}]
        stats = self.run_sync([], rows=partial, at=T0 + timedelta(minutes=5))
        self.assertEqual((stats['resolved'], stats['blocked']), (0, 1))
        inc = self.incident('SSH|web01|disk')
        self.assertEqual(inc['state'], 'open')
        self.assertIn('non mesuré', inc['confirmation_blocked_reason'])
        healthy = [{**partial[0], 'filesystems': [{'fs': '/dev/sda1', 'mount': '/', 'use_pct': 40}]}]
        self.run_sync([], rows=healthy, at=T0 + timedelta(minutes=6))
        self.assertEqual(self.incident('SSH|web01|disk')['state'], 'resolved')

    def test_each_ssh_control_needs_its_own_measurement(self):
        import alert_center
        empty = {'checks': [{'id': 'cpu', 'status': 'pass'}, {'id': 'storage', 'status': 'unknown'}], 'cpu': 5}
        for kind in ('disk', 'inodes', 'memory', 'uptime', 'zfs', 'smart', 'service:nginx.service', 'ntp',
                     'perms:/etc/shadow', 'backup:bacula', 'journal', 'inconnu'):
            self.assertFalse(alert_center.controle_mesure(empty, kind), kind)
        measured = {'ram': 30, 'uptime': 100, 'storage': {'filesystems': [{'mount': '/', 'use_pct': 3, 'inodes_use_pct': 1}]},
                    'checks': [{'id': i, 'status': s} for i, s in (('storage', 'observed'), ('services', 'fail'),
                                                                     ('clock', 'pass'), ('permissions', 'pass'),
                                                                     ('backups', 'observed'), ('errors', 'observed'))]}
        for kind in ('disk', 'inodes', 'memory', 'uptime', 'zfs', 'smart', 'service:nginx.service', 'ntp',
                     'perms:/etc/shadow', 'backup:bacula', 'journal', 'unreachable:timeout'):
            self.assertTrue(alert_center.controle_mesure(measured, kind), kind)

    def test_failed_api_source_never_resolves(self):
        zbx = alert(source='Zabbix', kind='X is down', targets=[{'name': 'db01', 'host_key': None, 'fresh': True}])
        self.run_sync([zbx])
        self.run_sync([], sources=ZBX_KO, at=T0 + timedelta(minutes=5))
        inc = self.incident('Zabbix|db01|X is down')
        self.assertEqual(inc['state'], 'open')
        self.assertIn('Délai dépassé', inc['confirmation_blocked_reason'])
        self.run_sync([], sources=[], at=T0 + timedelta(minutes=6))
        self.assertEqual(self.incident('Zabbix|db01|X is down')['state'], 'open', 'source absente = pas de résolution')

    def test_unknown_source_or_unlinked_target_never_resolves(self):
        self.run_sync([alert(source='Partages', kind='nfs', targets=[{'name': '192.0.2.5:/x', 'host_key': None}]),
                       alert(source='Inventée', kind='k')])
        self.run_sync([], at=T0 + timedelta(minutes=5))
        states = dict(self.db.execute('SELECT id, state FROM incidents').fetchall())
        self.assertEqual(set(states.values()), {'open'})

    def probe(self, at, observer_ok=True, host_at=None):
        return {'enabled': True, 'observer_ok': observer_ok, 'observer_checked_at': at.isoformat(),
                'hosts': {'db01': (host_at or at).isoformat()}}

    def sync_probe(self, alerts, probe, at):
        status = ic.source_status(ZBX_OK, HOST_OK, probe, at)
        return ic.reconcile(self.db, ic.observations(alerts), status, at)

    def test_sonde_directe_resolue_sur_mesure_recente(self):
        # Audit SUP-03 : un serveur critique revenu doit fermer son incident « HORS SERVICE ».
        down = alert(source='Sonde directe', kind='down', targets=[{'name': 'db01', 'host_key': 'db01', 'fresh': True}])
        self.sync_probe([down], self.probe(T0), T0)
        later = T0 + timedelta(minutes=1)
        self.sync_probe([], self.probe(later), later)
        self.assertEqual(self.incident('Sonde directe|db01|down')['state'], 'resolved')

    def test_sonde_directe_ancienne_ou_perturbee_ne_resout_pas(self):
        down = alert(source='Sonde directe', kind='down', targets=[{'name': 'db01', 'host_key': 'db01', 'fresh': True}])
        self.sync_probe([down], self.probe(T0), T0)
        later = T0 + timedelta(minutes=5)
        self.sync_probe([], self.probe(later, host_at=T0), later)
        inc = self.incident('Sonde directe|db01|down')
        self.assertEqual(inc['state'], 'open')
        self.assertIn('ancienne', inc['confirmation_blocked_reason'])
        self.sync_probe([], self.probe(later, observer_ok=False), later)
        self.assertEqual(self.incident('Sonde directe|db01|down')['state'], 'open')
        self.sync_probe([], None, later)
        self.assertEqual(self.incident('Sonde directe|db01|down')['state'], 'open')

    def test_toutes_les_cibles_restent_ouvertes_quel_que_soit_l_ordre(self):
        # Audit SUP-02 : 30 cibles dans un ordre variable → 30 incidents stables, aucune fausse résolution.
        targets = [{'name': f'h{i:02}', 'host_key': None, 'fresh': True} for i in range(30)]
        zbx = lambda t: alert(source='Zabbix', kind='VM not running', targets=t)
        self.run_sync([zbx(targets)])
        stats = self.run_sync([zbx(list(reversed(targets)))], at=T0 + timedelta(minutes=1))
        self.assertEqual(stats['resolved'], 0)
        opened = self.db.execute("SELECT COUNT(*) FROM incidents WHERE state='open'").fetchone()[0]
        self.assertEqual(opened, 30)

    def test_blocked_flag_cleared_when_seen_again(self):
        self.run_sync([alert()])
        self.run_sync([], rows=HOST_STALE, at=T0 + timedelta(minutes=5))
        self.run_sync([alert()], at=T0 + timedelta(minutes=6))
        self.assertIsNone(self.incident()['confirmation_blocked_since'])


class SuppressionTests(Base):
    def test_durations(self):
        self.run_sync([alert()])
        for duration, delta in (('24h', timedelta(hours=24)), ('7d', timedelta(days=7))):
            inc = ic.act(self.db, 'SSH|web01|service:postfix.service', 'suppress', 'jdoe', 'local', 'fenêtre', duration, T0)
            self.assertEqual(inc['state'], 'suppressed')
            self.assertEqual(ic._parse(inc['suppressed_until']), T0 + delta)
            self.run_sync([alert()], at=T0 + delta - timedelta(minutes=1))
            self.assertEqual(self.incident()['state'], 'suppressed')
            stats = self.run_sync([alert()], at=T0 + delta + timedelta(minutes=1))
            self.assertEqual(stats['expired'], 1)
            self.assertEqual(self.incident()['state'], 'open')

    def test_masking_requires_a_reason(self):
        # Audit UI du 31/10 (fiche 02.2) : masquer sans motif est refusé.
        self.run_sync([alert()])
        with self.assertRaisesRegex(ValueError, 'Motif requis'):
            ic.act(self.db, 'SSH|web01|service:postfix.service', 'suppress', 'jdoe', 'local', '  ', '24h', T0)
        self.assertNotEqual(self.incident()['state'], 'suppressed')

    def test_permanent_suppression_until_explicit_reactivation(self):
        self.run_sync([alert()])
        ic.act(self.db, 'SSH|web01|service:postfix.service', 'suppress', 'jdoe', 'local', 'maintenance planifiée', 'permanent', T0)
        self.run_sync([alert()], at=T0 + timedelta(days=400))
        inc = self.incident()
        self.assertEqual((inc['state'], inc['suppressed_until']), ('suppressed', None))
        ic.act(self.db, 'SSH|web01|service:postfix.service', 'reactivate', 'jdoe', 'local', 'fin de maintenance', None, T0)
        self.assertEqual(self.incident()['state'], 'open')
        self.assertIn('reactivated', self.events())

    def test_ack_expiry(self):
        self.run_sync([alert()])
        ic.act(self.db, 'SSH|web01|service:postfix.service', 'ack', 'jdoe', 'local', '', '24h', T0)
        self.run_sync([alert()], at=T0 + timedelta(hours=25))
        self.assertEqual(self.incident()['state'], 'open')
        self.assertIn('ack_expired', self.events())

    def test_suppression_does_not_resolve_and_resolution_still_needs_complete_source(self):
        self.run_sync([alert()])
        ic.act(self.db, 'SSH|web01|service:postfix.service', 'suppress', 'jdoe', 'local', 'maintenance planifiée', 'permanent', T0)
        self.run_sync([], rows=HOST_STALE, at=T0 + timedelta(minutes=5))
        self.assertEqual(self.incident()['state'], 'suppressed')
        self.run_sync([], rows=HOST_OK, at=T0 + timedelta(minutes=6))
        self.assertEqual(self.incident()['state'], 'resolved')

    def test_invalid_actions(self):
        self.run_sync([alert()])
        with self.assertRaises(ValueError):
            ic.act(self.db, 'SSH|web01|service:postfix.service', 'ack', 'a', 'local', '', '3d', T0)
        with self.assertRaises(ValueError):
            ic.act(self.db, 'SSH|web01|service:postfix.service', 'reactivate', 'a', 'local', '', None, T0)
        with self.assertRaises(KeyError):
            ic.act(self.db, 'inconnu', 'ack', 'a', 'local', '', '24h', T0)
        self.run_sync([], at=T0 + timedelta(minutes=1))
        with self.assertRaises(ValueError):
            ic.act(self.db, 'SSH|web01|service:postfix.service', 'ack', 'a', 'local', '', '24h', T0)


class MaintenanceTests(Base):
    def add_window(self, *, source=None, target=None, start=None, end=None, name='Patch production'):
        self.db.execute('''INSERT INTO maintenance_windows
            (name,starts_at,ends_at,source,target,note,actor,actor_auth,created_at)
            VALUES(?,?,?,?,?,?,?,?,?)''',
            (name, ic._iso(start or T0 - timedelta(minutes=5)), ic._iso(end or T0 + timedelta(hours=1)),
             source, target, 'changement planifié', 'Operator', 'local', ic._iso(T0)))

    def test_scoped_active_window_annotates_without_changing_incident(self):
        self.run_sync([alert()])
        self.add_window(source='SSH', target='web01')
        windows = ic.maintenance_windows(self.db, T0, include_future=False)
        match = ic.incident_maintenance(self.incident(), windows)
        self.assertEqual(match['name'], 'Patch production')
        self.assertTrue(match['active'])
        self.assertEqual(self.incident()['state'], 'open', 'une maintenance ne modifie pas le cycle de vie')

    def test_scope_and_future_window_do_not_match(self):
        self.run_sync([alert()])
        self.add_window(source='Zabbix')
        self.add_window(target='db01')
        self.add_window(start=T0 + timedelta(hours=1), end=T0 + timedelta(hours=2), name='Future')
        current = ic.maintenance_windows(self.db, T0, include_future=False)
        self.assertIsNone(ic.incident_maintenance(self.incident(), current))
        all_windows = ic.maintenance_windows(self.db, T0)
        self.assertEqual(len(all_windows), 3)
        self.assertFalse(next(w for w in all_windows if w['name'] == 'Future')['active'])

    def test_global_window_matches_every_source(self):
        self.run_sync([alert()])
        self.add_window()
        self.assertIsNotNone(ic.incident_maintenance(self.incident(), ic.maintenance_windows(self.db, T0, False)))


class MigrationTests(unittest.TestCase):
    def test_migration_is_recorded_and_idempotent(self):
        db = sqlite3.connect(':memory:')
        self.assertTrue(ic.migrate(db))
        self.assertFalse(ic.migrate(db))
        self.assertEqual({r[0] for r in db.execute("SELECT name FROM schema_migrations")},
                         {'incidents_v1', 'incidents_v2_source_start', 'incidents_v3_workflow_maintenance'})
        columns = {r[1] for r in db.execute('PRAGMA table_info(incidents)')}
        for column in ('opened_at', 'last_seen_at', 'acknowledged_at', 'resolved_at', 'reopened_at', 'owner', 'note',
                       'severity_max', 'suppressed_until', 'confirmation_blocked_reason', 'investigation_at'):
            self.assertIn(column, columns)
        self.assertEqual(db.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='maintenance_windows'").fetchone()[0], 1)
        db.close()


class MigrationV2Tests(unittest.TestCase):
    def test_v1_start_values_are_cleared_once(self):
        db = sqlite3.connect(':memory:')
        db.execute('CREATE TABLE schema_migrations(name TEXT PRIMARY KEY, applied_at TEXT)')
        ic._migrate_v1(db)
        db.execute("INSERT INTO incidents(id, source, target, type, title, state, severity, severity_max, opened_at, "
                   "first_observed_at, last_seen_at, updated_at) VALUES('a','SSH','t','k','x','open','critical','critical',"
                   "'2026-09-29T09:00:00+00:00','2026-09-29T08:00:00+00:00','2026-09-29T09:00:00+00:00','2026-09-29T09:00:00+00:00')")
        self.assertTrue(ic.migrate(db))
        self.assertIsNone(db.execute('SELECT first_observed_at FROM incidents').fetchone()[0])
        self.assertFalse(ic.migrate(db))
        db.close()


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:', check_same_thread=False)
        self.addCleanup(self.db.close)

        @contextlib.contextmanager
        def connect():
            with self.db:
                yield self.db
        self.alerts = [alert(evidence='mot_de_passe=' + 'x' * 2000)]
        self.ctx = SimpleNamespace(connect=connect, rows=lambda: HOST_OK, api_connections=lambda: [])
        self.app = FastAPI()
        patcher = mock.patch('alert_center.build', lambda context, now=None, for_incidents=False: {'alerts': self.alerts, 'sources': ZBX_OK})
        patcher.start()
        self.addCleanup(patcher.stop)
        ic.install(self.app, self.ctx, start_thread=False)
        self.routes = {(r.path, tuple(sorted(r.methods))): r for r in all_routes(self.app) if hasattr(r, 'methods')}

    def sync(self):
        # Le rapprochement est explicite (fil de fond, collecte ou POST) : un GET ne l'exécute plus.
        return self.call('/api/incidents/sync', 'POST')

    def call(self, path, method='GET', *args, **kw):
        return self.routes[(path, (method,))].endpoint(*args, **kw)

    def test_saved_views_unowned_mine_and_stale_evidence(self):
        # Audit UI du 31/10 (fiche 02.1) : « sans responsable », « à moi », « preuve ancienne ».
        self.sync()
        q = lambda **kw: self.call('/api/incidents', 'GET', **{'state': 'all', 'chronic': 'include', **kw})['total']
        total = q()
        self.assertEqual(q(owner='__none__'), total)
        self.call('/api/incidents/ack', 'POST', ic.Action(id='SSH|web01|service:postfix.service', by='Operator'),
                  SimpleNamespace(headers=Headers({})))
        self.assertEqual(q(owner='__none__'), total - 1)
        self.assertEqual(q(owner='Operator'), 1)
        self.assertLessEqual(q(evidence='stale'), total)
        with self.assertRaises(HTTPException):
            q(evidence='autre')

    def test_request_injection_and_list(self):
        self.sync()
        for path in ('/api/incidents/ack', '/api/incidents/investigate', '/api/incidents/suppress',
                     '/api/incidents/reactivate', '/api/incidents/maintenance', '/api/incidents/maintenance/delete'):
            self.assertEqual(self.routes[(path, ('POST',))].dependant.request_param_name, 'request')
        body = self.call('/api/incidents', 'GET', 'active', '', '', '', 'exclude', 100, 0)
        self.assertEqual(body['total'], 1)
        item = body['items'][0]
        self.assertLessEqual(len(item['evidence']), ic.EVIDENCE_MAX)
        self.assertEqual(item['link'], {'host_key': 'web01'})
        self.assertEqual(body['counts']['open'], 1)

    def test_host_filter_matches_key_name_and_fqdn_only(self):
        # Zabbix ne connaît que le FQDN (sans host_key) ; « web01x » et « web011 » ne sont pas web01.
        fqdn = alert('Zabbix', 'Free disk space', 'warning', [{'name': 'web01.host.example.test', 'fresh': True}])
        others = [alert('Zabbix', 'cpu', 'warning', [{'name': name, 'fresh': True}]) for name in ('web01x', 'web011.host')]
        self.alerts = [self.alerts[0], fqdn, *others]
        self.sync()
        body = self.call('/api/incidents', 'GET', 'active', '', '', '', 'include', 100, 0, 'web01')
        self.assertEqual(sorted(i['source'] + ':' + i['target'] for i in body['items']),
                         ['SSH:web01', 'Zabbix:web01.host.example.test'])
        self.assertEqual(self.call('/api/incidents', 'GET', 'active', '', '', '', 'include', 100, 0, 'web0_')['total'], 0)
        # Nom Zabbix rapproché par IP sur la fiche (alias) : inclus sur demande.
        body = self.call('/api/incidents', 'GET', 'active', '', '', '', 'include', 100, 0, 'web01', 'web01x')
        self.assertEqual(body['total'], 3)

    def test_local_actions_with_identity(self):
        self.sync()
        self.call('/api/incidents', 'GET', 'active', '', '', '', 'exclude', 100, 0)
        local = SimpleNamespace(headers=Headers({}))
        with self.assertRaises(HTTPException) as err:
            self.call('/api/incidents/ack', 'POST', ic.Action(id='SSH|web01|service:postfix.service'), local)
        self.assertEqual(err.exception.status_code, 422)
        result = self.call('/api/incidents/ack', 'POST', ic.Action(id='SSH|web01|service:postfix.service', by='Operator', duration='7d'), local)
        self.assertEqual((result['state'], result['owner'], result['owner_authenticated']), ('acknowledged', 'Operator', False))
        with mock.patch.dict(os.environ, {operator_identity.SECRET_ENV: 's' * 40}):
            proxy = SimpleNamespace(headers=Headers({'X-OpsControl-User': 'jdoe@example.test', 'X-OpsControl-Proxy': 's' * 40}))
            result = self.call('/api/incidents/suppress', 'POST', ic.Action(id='SSH|web01|service:postfix.service', by='ignoré', duration='permanent', note='migration en cours'), proxy)
        self.assertEqual((result['state'], result['owner'], result['owner_authenticated']), ('suppressed', 'jdoe@example.test', True))
        self.assertEqual(len(self.call('/api/incidents/suppressions')['items']), 1)
        events = self.call('/api/incidents/events', 'GET', 'SSH|web01|service:postfix.service', 100)['events']
        self.assertEqual([e['kind'] for e in events][:3], ['suppress', 'ack', 'opened'])
        with self.assertRaises(HTTPException) as err:
            self.call('/api/incidents/ack', 'POST', ic.Action(id='inconnu-xyz', by='A'), local)
        self.assertEqual(err.exception.status_code, 404)

    def test_recent_order_before_pagination_uses_occurrence_not_refresh(self):
        self.alerts = [alert(kind=kind, severity=severity) for kind, severity in
                       [('old', 'critical'), ('new', 'warning'), ('again', 'critical'),
                        ('offset', 'warning'), ('source', 'warning')]]
        self.sync()
        for kind, opened in [('old', '2026-10-20T10:00:00Z'), ('new', '2026-10-27T09:00:00Z'),
                             ('again', '2026-10-21T10:00:00Z'), ('offset', '2026-10-27T10:00:00+01:00'),
                             ('source', '2026-10-27T10:30:00Z')]:
            self.db.execute('UPDATE incidents SET opened_at=?,last_seen_at=?,updated_at=? WHERE type=?',
                            (opened, '2026-10-30T12:00:00Z', '2026-10-30T12:00:00Z', kind))
        self.db.execute("UPDATE incidents SET reopened_at='2026-10-27T09:30:00Z' WHERE type='again'")
        self.db.execute("UPDATE incidents SET first_observed_at='2026-10-22T10:00:00Z' WHERE type='source'")
        result = self.call('/api/incidents', chronic='include')
        self.assertEqual(result['order'], 'recent')
        self.assertEqual([i['type'] for i in result['items']], ['again', 'new', 'offset', 'source', 'old'])
        self.assertEqual(result['items'][0]['event_kind'], 'reopened')
        self.assertEqual(result['items'][0]['event_at'], '2026-10-27T09:30:00+00:00')
        pages = [self.call('/api/incidents', chronic='include', limit=2, offset=n)['items'] for n in (0, 2, 4)]
        self.assertEqual([i['id'] for page in pages for i in page], [i['id'] for i in result['items']])
        oldest = self.call('/api/incidents', order='oldest')['items']
        self.assertEqual([i['type'] for i in oldest], ['old', 'source', 'new', 'offset', 'again'])
        severity = self.call('/api/incidents', order='severity')['items']
        self.assertEqual([i['type'] for i in severity][:2], ['again', 'old'])
        self.db.execute("UPDATE incidents SET state='resolved',resolved_at='2026-10-27T12:00:00Z' WHERE type='old'")
        resolved = self.call('/api/incidents', state='all')['items'][0]
        self.assertEqual((resolved['type'], resolved['event_kind']), ('old', 'resolved'))

    def test_observed_order_unknown_date_last_and_invalid_order_rejected(self):
        self.alerts = [alert(kind=k) for k in ('a', 'b', 'c')]
        self.sync()
        self.db.execute("UPDATE incidents SET observed_at=CASE type WHEN 'a' THEN NULL "
                        "WHEN 'b' THEN '2026-10-27T10:00:00+01:00' ELSE '2026-10-27T09:00:01Z' END")
        result = self.call('/api/incidents', order='observed')
        self.assertEqual([i['type'] for i in result['items']], ['c', 'b', 'a'])
        with self.assertRaises(HTTPException) as err:
            self.call('/api/incidents', order='recent; DROP TABLE incidents')
        self.assertEqual(err.exception.status_code, 422)

    def test_recency_filters_counts_and_state_are_independent(self):
        self.alerts = [alert(kind=k) for k in ('new', 'old', 'missing', 'future', 'again')]
        self.sync()
        at = datetime(2026, 10, 27, 12, tzinfo=timezone.utc)
        values = {'new': at-timedelta(hours=23), 'old': at-timedelta(hours=25),
                  'missing': None, 'future': at+timedelta(hours=1), 'again': at-timedelta(days=2)}
        for kind, value in values.items():
            self.db.execute('UPDATE incidents SET opened_at=? WHERE type=?',
                            (value.isoformat() if value else 'invalid', kind))
        self.db.execute("UPDATE incidents SET state='reopened',reopened_at=? WHERE type='again'",
                        ((at-timedelta(hours=1)).isoformat(),))
        with mock.patch.object(ic, 'now_utc', return_value=at):
            body = self.call('/api/incidents', age='recent', limit=1)
            self.assertEqual(body['recency_counts'], {'recent': 2, 'old': 1, 'unknown': 2})
            self.assertEqual(body['total'], 2)
            self.assertEqual(body['items'][0]['type'], 'again')
            self.assertEqual(body['items'][0]['state'], 'reopened')
            self.assertEqual(body['items'][0]['recency'], 'recent')
            self.assertEqual(self.call('/api/incidents', age='old')['items'][0]['type'], 'old')
            self.assertEqual(self.call('/api/incidents', age='unknown')['total'], 2)
            with self.assertRaises(HTTPException):
                self.call('/api/incidents', age='bad')

    def test_investigation_and_maintenance_api(self):
        self.sync()
        self.call('/api/incidents', 'GET', 'active', '', '', '', 'exclude', 100, 0)
        local = SimpleNamespace(headers=Headers({}))
        result = self.call('/api/incidents/investigate', 'POST',
                           ic.Action(id='SSH|web01|service:postfix.service', by='Operator', duration='24h'), local)
        self.assertEqual((result['state'], result['owner']), ('investigating', 'Operator'))

        now = datetime.now(timezone.utc)
        body = ic.Maintenance(name='Patch production', starts_at=(now - timedelta(minutes=1)).isoformat(),
                              ends_at=(now + timedelta(hours=2)).isoformat(), source='SSH', target='web01', by='Operator')
        window = self.call('/api/incidents/maintenance', 'POST', body, local)
        self.assertTrue(window['active'])
        self.assertEqual(self.call('/api/incidents/maintenance')['active'], 1)
        listed = self.call('/api/incidents', 'GET', 'active', '', '', '', 'exclude', 100, 0)
        self.assertEqual(listed['maintenance_active'], 1)
        self.assertEqual(listed['items'][0]['maintenance']['id'], window['id'])
        self.assertEqual(listed['active_by_severity'], {}, 'la maintenance retire le bruit actionnable uniquement')
        self.assertEqual(listed['items'][0]['state'], 'investigating', 'les preuves et le cycle restent visibles')
        deleted = self.call('/api/incidents/maintenance/delete', 'POST',
                            ic.MaintenanceDelete(id=window['id'], by='Operator'), local)
        self.assertTrue(deleted['deleted'])

    def test_maintenance_api_rejects_invalid_duration(self):
        local = SimpleNamespace(headers=Headers({}))
        now = datetime.now(timezone.utc)
        body = ic.Maintenance(name='Trop longue', starts_at=now.isoformat(),
                              ends_at=(now + timedelta(days=31)).isoformat(), by='Operator')
        with self.assertRaises(HTTPException) as err:
            self.call('/api/incidents/maintenance', 'POST', body, local)
        self.assertEqual(err.exception.status_code, 422)
        naive = ic.Maintenance(name='Sans fuseau', starts_at=now.replace(tzinfo=None).isoformat(),
                               ends_at=(now + timedelta(hours=1)).replace(tzinfo=None).isoformat(), by='Operator')
        with self.assertRaises(HTTPException) as err:
            self.call('/api/incidents/maintenance', 'POST', naive, local)
        self.assertEqual(err.exception.status_code, 422)
        past = ic.Maintenance(name='Déjà finie', starts_at=(now - timedelta(hours=2)).isoformat(),
                              ends_at=(now - timedelta(hours=1)).isoformat(), by='Operator')
        with self.assertRaises(HTTPException) as err:
            self.call('/api/incidents/maintenance', 'POST', past, local)
        self.assertEqual(err.exception.status_code, 422)

    def test_chronic_filter(self):
        self.alerts = [alert(), alert(source='Zabbix', kind='old', chronic=True, targets=[{'name': 'x', 'host_key': None}])]
        self.sync()
        body = self.call('/api/incidents', 'GET', 'active', '', '', '', 'exclude', 100, 0)
        self.assertEqual((body['total'], body['chronic_active']), (1, 1))
        self.assertEqual(self.call('/api/incidents', 'GET', 'active', '', '', '', 'only', 100, 0)['total'], 1)

    def test_get_never_reconciles_nor_writes(self):
        trace = []
        self.db.set_trace_callback(trace.append)
        body = self.call('/api/incidents', 'GET', 'active', '', '', '', 'exclude', 100, 0)
        self.call('/api/incidents/suppressions')
        self.db.set_trace_callback(None)
        self.assertEqual(body['total'], 0, 'journal non encore rapproché : vide, pas inventé')
        self.assertIsNone(body['sync']['at'], 'absence de rapprochement visible')
        writes = [q for q in trace if q.lstrip().upper().startswith(('INSERT', 'UPDATE', 'DELETE', 'REPLACE', 'CREATE'))]
        self.assertEqual(writes, [])

    def test_collection_hook_reconciles(self):
        hooks = []
        ctx = SimpleNamespace(connect=self.ctx.connect, rows=self.ctx.rows, api_connections=self.ctx.api_connections,
                              collection_hooks=hooks)
        app = FastAPI()
        ic.install(app, ctx, start_thread=False)
        self.assertEqual(len(hooks), 1)
        hooks[0]('ssh')
        self.assertIsNotNone(ctx.incident_sync_info()['at'])
        self.assertEqual(self.db.execute("SELECT count(*) FROM incidents WHERE state='open'").fetchone()[0], 1)

    def test_fil_demarre_par_le_lifespan_et_non_a_l_import(self):
        # Audit BE-03 : install() ne lance aucun fil ; le lifespan le démarre après le verrou d'instance.
        import threading
        ctx = SimpleNamespace(connect=self.ctx.connect, rows=self.ctx.rows, api_connections=self.ctx.api_connections,
                              collection_hooks=[])
        before = {t.ident for t in threading.enumerate() if t.name == 'incident-sync'}
        ic.install(FastAPI(), ctx, start_thread=True)
        self.assertEqual({t.ident for t in threading.enumerate() if t.name == 'incident-sync'}, before)
        with mock.patch('alert_center.build', lambda context, now=None, for_incidents=False: {'alerts': [], 'sources': []}):
            self.assertTrue(ctx.start_incident_sync())
            self.assertFalse(ctx.start_incident_sync(), 'jamais deux fils')
            ctx.stop_incident_sync()
            started = [t for t in threading.enumerate() if t.name == 'incident-sync' and t.ident not in before]
            for t in started:
                t.join(2)
            self.assertFalse(any(t.is_alive() for t in started))
        disabled = SimpleNamespace(connect=self.ctx.connect, rows=self.ctx.rows,
                                   api_connections=self.ctx.api_connections, collection_hooks=[])
        ic.install(FastAPI(), disabled, start_thread=False)
        self.assertFalse(disabled.start_incident_sync())

    def test_sync_failure_changes_nothing(self):
        self.sync()
        self.call('/api/incidents', 'GET', 'active', '', '', '', 'exclude', 100, 0)
        with mock.patch('alert_center.build', side_effect=RuntimeError('base occupée')):
            info = self.call('/api/incidents/sync', 'POST')
        self.assertIn('RuntimeError', info['error'])
        self.assertEqual(self.db.execute('SELECT state FROM incidents').fetchone()[0], 'open')

    def test_evidence_is_redacted_and_bounded(self):
        self.sync()
        body = json.dumps(self.call('/api/incidents', 'GET', 'active', '', '', '', 'exclude', 100, 0), ensure_ascii=False)
        self.assertNotIn('x' * 20, body, 'valeur masquée avant persistance')
        self.assertIn('[MASQUÉ]', body)
        stored = self.db.execute('SELECT evidence FROM incidents').fetchone()[0]
        self.assertNotIn('xxxx', stored)


if __name__ == '__main__':
    unittest.main()
