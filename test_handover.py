"""Passation : ce qui a changé sur la période, qui fait quoi — lecture seule du journal."""
import contextlib
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from fastapi import FastAPI

import handover
import incident_center as ic
import itsm
from routers import all_routes

AT = datetime(2026, 10, 21, 8, 0, tzinfo=timezone.utc)


def h(hours):
    return AT - timedelta(hours=hours)


def incident(db, ident, opened, severity='critical', chronic=False, source='SSH', target='web01'):
    stamp = opened.isoformat()
    db.execute('''INSERT INTO incidents(id, source, target, target_key, type, title, state, severity, severity_max,
        opened_at, last_seen_at, chronic, link, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
               (ident, source, target, target, 'type', 'Titre ' + ident, 'open', severity, severity, stamp, stamp,
                int(chronic), json.dumps({'host_key': target}), stamp))
    ic.Repository.event(db, ident, opened, 'opened', severity=severity)


def resolve(db, ident, at):
    ic.Repository.update(db, ident, state='resolved', resolved_at=at.isoformat(), ack_until=None, updated_at=at.isoformat())
    ic.Repository.event(db, ident, at, 'resolved', reason='Absent d’une collecte complète')


def case(db, ident, taken, created=None, remote_id=None, status='pending', title='Disque plein'):
    db.execute('INSERT INTO itsm_cases(id,origin,origin_id,kind,snapshot,owner,owner_auth,taken_at,reference,status,'
               'remote_id,remote_base,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
               (ident, 'incident', 'B-' + ident, 'Ticket',
                json.dumps({'title': title, 'target': 'db01', 'severity': 'warning', 'source': 'Zabbix'}),
                'Operator', 'local', taken.isoformat(), 'OC-' + ident.upper(), status, remote_id,
                'https://glpi.example.test' if remote_id else None, created and created.isoformat(), taken.isoformat()))


def seed(db):
    ic.migrate(db)
    itsm.migrate(db)
    incident(db, 'A', h(30))                                   # orphelin depuis 30 h
    incident(db, 'B', h(2), severity='warning', source='Zabbix', target='db01')
    ic.act(db, 'B', 'ack', 'Operator', 'local', 'purge prévue password=Sup3rS3cret', '24h', at=h(1))
    incident(db, 'C', h(40))
    ic.act(db, 'C', 'investigate', 'jdoe', 'proxy', '', '24h', at=h(20))   # expire dans 4 h
    incident(db, 'D', h(10), severity='warning')
    resolve(db, 'D', h(3))
    incident(db, 'E', h(50), chronic=True)                    # chronique : compté, non listé
    incident(db, 'F', h(12))                                   # récent : pas encore orphelin
    incident(db, 'G', h(60))
    ic.act(db, 'G', 'ack', 'Sara', 'local', '', '24h', at=h(36))   # prise en charge expirée, non rapprochée
    incident(db, 'OLD', h(100))
    resolve(db, 'OLD', h(80))                                  # hors période
    case(db, 't1', h(5), created=h(4), remote_id=1234, status='linked')
    case(db, 't2', h(3), title='Service arrêté')               # demandé, sans numéro GLPI
    case(db, 't3', h(70), created=h(69), remote_id=99, status='linked')  # hors période


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        seed(self.db)
        self.report = handover.build(self.db, 24, at=AT)

    def ids(self, section):
        return [i['id'] for i in self.report[section]]

    def test_changes_on_period(self):
        r = self.report
        self.assertEqual(sorted(self.ids('new')), ['B', 'D', 'F'])
        self.assertEqual(self.ids('resolved'), ['D'])
        self.assertFalse(r['resolved'][0]['reappeared'])
        self.assertEqual([(i['id'], i['action'], i['actor']) for i in r['taken']],
                         [('B', 'ack', 'Operator'), ('C', 'investigation_started', 'jdoe')])
        self.assertEqual(r['by_actor'], {'Operator': 1, 'jdoe': 1})
        self.assertFalse(r['taken'][0]['actor_authenticated'])
        self.assertTrue(r['taken'][1]['actor_authenticated'])

    def test_what_remains_to_do(self):
        r = self.report
        # Orphelins > 24 h, y compris une prise en charge expirée ; jamais les chroniques ni les récents.
        self.assertEqual(self.ids('unowned'), ['G', 'A'])
        self.assertEqual(r['unowned'][0]['expired_owner'], 'Sara')
        self.assertEqual(r['chronic_unowned'], 1)
        self.assertEqual(self.ids('expiring'), ['C'])
        self.assertEqual(r['expiring'][0]['owner'], 'jdoe')

    def test_tickets(self):
        r = self.report
        self.assertEqual([(t['reference'], t['glpi_id']) for t in r['tickets']], [('OC-T1', 1234)])
        self.assertEqual([t['reference'] for t in r['tickets_pending']], ['OC-T2'])
        self.assertNotIn('remote_base', r['tickets'][0])
        self.assertNotIn('glpi.example.test', json.dumps(r))

    def test_period_is_bounded(self):
        short = handover.build(self.db, 1, at=AT)
        self.assertEqual(short['counts']['new'], 0)
        self.assertEqual(short['counts']['unowned'], 2)     # état courant, indépendant de la période
        week = handover.build(self.db, 10_000, at=AT)
        self.assertEqual(week['period']['hours'], handover.MAX_HOURS)
        self.assertEqual(sorted(i['id'] for i in week['new']), ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'OLD'])

    def test_text_ready_to_paste_without_secret(self):
        text = self.report['text']
        for expected in ('Passation OpsControl', 'À TRAITER', 'CE QUI A CHANGÉ', 'Operator (déclaratif)', 'jdoe :',
                         'GLPI ticket n° 1234', 'OC-T2', 'Sans responsable depuis plus de 24 h (2)',
                         'prise en charge de Sara expirée', '1 anomalie(s) chronique(s)'):
            self.assertIn(expected, text)
        self.assertNotIn('Sup3rS3cret', text)
        self.assertNotIn('Sup3rS3cret', json.dumps(self.report))
        self.assertNotRegex(text, r'<[a-zA-Z/]')   # texte brut, sans balise

    def test_reappeared_after_resolution(self):
        self.db.execute("UPDATE incidents SET state='reopened', reopen_count=1 WHERE id='D'")
        self.assertTrue(handover.build(self.db, 24, at=AT)['resolved'][0]['reappeared'])

    def test_read_only(self):
        before = self.db.total_changes
        handover.build(self.db, 48, at=AT)
        self.assertEqual(self.db.total_changes, before)


class CsvTests(unittest.TestCase):
    def test_csv_for_excel_without_formula(self):
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        seed(db)
        db.execute("UPDATE incidents SET title='=HYPERLINK(\"x\")' WHERE id='A'")
        out = handover.csv_text(handover.build(db, 24, at=AT))
        self.assertTrue(out.startswith('﻿rubrique;date;gravite;incident'))
        self.assertIn("'=HYPERLINK", out)
        self.assertNotIn(';=HYPERLINK', out)
        self.assertIn('Ticket GLPI', out)
        self.assertIn('OC-T1 · GLPI n° 1234', out)
        self.assertNotIn('Sup3rS3cret', out)


class RouteTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = temp.name + '/test.sqlite3'
        with self.connect() as db:
            seed(db)
        sync = {'at': AT.isoformat(), 'stats': {}, 'error': None, 'duration_ms': 3, 'interval_seconds': 60}
        context = SimpleNamespace(connect=self.connect, incident_sync_info=lambda: sync)
        app = FastAPI()
        handover.install(app, context)
        self.routes = {r.path: r.endpoint for r in all_routes(app)}

    @contextlib.contextmanager
    def connect(self):
        db = sqlite3.connect(self.path)
        try:
            yield db
            db.commit()
        finally:
            db.close()

    def test_json_and_csv(self):
        report = self.routes['/api/handover'](hours=24, format='json')
        self.assertEqual(report['sync'], {'at': AT.isoformat(), 'error': None})
        self.assertIn('Journal rapproché', report['text'])
        response = self.routes['/api/handover'](hours=24, format='csv')
        self.assertEqual(response.media_type, 'text/csv; charset=utf-8')
        self.assertIn('attachment; filename="passation-', response.headers['content-disposition'])

    def test_get_is_viewer_readable(self):
        import access_policy
        self.assertEqual(access_policy.classify('GET', '/api/handover')[0], 'viewer')


if __name__ == '__main__':
    unittest.main()
