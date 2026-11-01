from routers import all_routes  # routes des APIRouter inclus (FastAPI ne les recopie plus dans app.routes)
import contextlib
import sqlite3
import time
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from fastapi import FastAPI, HTTPException

import alert_center

# Requête sans en-tête : accès direct, mode local non authentifié.
LOCAL = SimpleNamespace(headers={})

def zabbix(*problems):
    # La collecte précède la lecture : ni vieillie à l’import, ni future pour build().
    observed = datetime.now(timezone.utc) - timedelta(seconds=1)
    return {'key': 'z', 'name': 'ZABBIX', 'provider': 'Zabbix',
            'last_result': {'status': 'observed', 'collected_at': observed.isoformat(), 'inventory': {'problems': list(problems)}}}


def probleme(description, hote, jours):
    return {'description': description, 'severity': 'critical', 'severity_label': 'Haute', 'hosts': [hote],
            'last_change': str(int(time.time() - jours * 86400))}


def contexte(test_case, problems):
    db = sqlite3.connect(':memory:', check_same_thread=False)
    test_case.addCleanup(db.close)
    import migrations
    migrations.apply(db)  # comme au démarrage : alert_acks vient de la migration core_v4

    @contextlib.contextmanager
    def connect():
        with db:
            yield db
    etat = {'problems': list(problems)}
    ctx = SimpleNamespace(rows=lambda: [], connect=connect,
                          api_connections=lambda: [zabbix(*etat['problems'])])
    ctx.etat = etat
    app = FastAPI()
    alert_center.install(app, ctx)
    routes = {r.path: r.endpoint for r in all_routes(app) if hasattr(r, 'endpoint')}
    return ctx, routes


class ChronicTests(unittest.TestCase):
    def test_years_old_trigger_is_chronic_and_not_an_incident(self):
        ctx, _ = contexte(self, [probleme('DEMOAPP IS DOWN', 'demoapp.example.test', 2049),
                           probleme('DemoApp_9 is not reachable', 'DemoApp_9', 3)])
        r = alert_center.build(ctx)
        chronique = {a['title']: a['chronic'] for a in r['alerts']}
        self.assertEqual(chronique, {'DEMOAPP IS DOWN': True, 'DemoApp_9 is not reachable': False})
        self.assertEqual((r['counts']['critical'], r['counts']['chronic']), (1, 1))
        self.assertFalse(r['alerts'][0]['chronic'])  # les incidents actifs d'abord

    def test_new_occurrence_of_old_problem_stays_an_incident(self):
        ctx, _ = contexte(self, [probleme('Service down', 'a', 400), probleme('Service down', 'b', 0.1)])
        groupes = {a['id']: a['count'] for a in alert_center.build(ctx)['alerts']}
        self.assertEqual(groupes, {'Zabbix:Service down:critical': 1, 'Zabbix:Service down:critical:chronique': 1})

    def test_undated_evidence_is_never_chronic(self):
        ctx, _ = contexte(self, [{'description': 'X is down', 'severity': 'critical', 'hosts': ['x']}])
        self.assertFalse(alert_center.build(ctx)['alerts'][0]['chronic'])


class AckTests(unittest.TestCase):
    def test_ack_shared_and_counted_then_released(self):
        ctx, routes = contexte(self, [probleme('X is down', 'x', 0.1)])
        ident = alert_center.build(ctx)['alerts'][0]['id']
        prise = routes['/api/alerts/ack'](alert_center_ack(ident, 'Operator', 'redémarrage en cours'), LOCAL)
        self.assertEqual((prise['by'], prise['count']), ('Operator', 1))
        r = alert_center.build(ctx)
        self.assertEqual((r['alerts'][0]['ack']['note'], r['counts']['acknowledged']), ('redémarrage en cours', 1))
        routes['/api/alerts/unack'](alert_center_release(ident))
        self.assertIsNone(alert_center.build(ctx)['alerts'][0]['ack'])

    def test_ack_lapses_when_alert_spreads(self):
        ctx, routes = contexte(self, [probleme('X is down', 'x', 0.1)])
        ident = alert_center.build(ctx)['alerts'][0]['id']
        routes['/api/alerts/ack'](alert_center_ack(ident, 'A', ''), LOCAL)
        ctx.etat['problems'].append(probleme('X is down', 'y', 0.1))  # nouvelle cible touchée
        self.assertIsNone(alert_center.build(ctx)['alerts'][0]['ack'])

    def test_ack_lapses_when_a_new_target_replaces_a_fixed_one(self):
        # Audit SUP-11 : x réparé, y touché ; même nombre de cibles mais information nouvelle.
        ctx, routes = contexte(self, [probleme('X is down', 'x', 0.1)])
        ident = alert_center.build(ctx)['alerts'][0]['id']
        routes['/api/alerts/ack'](alert_center_ack(ident, 'A', ''), LOCAL)
        ctx.etat['problems'][:] = [probleme('X is down', 'y', 0.1)]
        alerte = alert_center.build(ctx)['alerts'][0]
        self.assertEqual(alerte['count'], 1)
        self.assertIsNone(alerte['ack'])

    def test_ack_kept_when_a_covered_target_is_fixed(self):
        ctx, routes = contexte(self, [probleme('X is down', 'x', 0.1), probleme('X is down', 'y', 0.1)])
        ident = alert_center.build(ctx)['alerts'][0]['id']
        routes['/api/alerts/ack'](alert_center_ack(ident, 'A', ''), LOCAL)
        ctx.etat['problems'][:] = [probleme('X is down', 'y', 0.1)]
        self.assertIsNotNone(alert_center.build(ctx)['alerts'][0]['ack'])

    def test_ack_expires(self):
        ctx, routes = contexte(self, [probleme('X is down', 'x', 0.1)])
        ident = alert_center.build(ctx)['alerts'][0]['id']
        routes['/api/alerts/ack'](alert_center_ack(ident, 'A', '', hours=1), LOCAL)
        plus_tard = datetime.now(timezone.utc) + timedelta(hours=2)
        self.assertIsNone(alert_center.build(ctx, plus_tard)['alerts'][0]['ack'])

    def test_unknown_alert_refused_and_bounds(self):
        ctx, routes = contexte(self, [probleme('X is down', 'x', 0.1)])
        with self.assertRaises(HTTPException) as e:
            routes['/api/alerts/ack'](alert_center_ack('Zabbix:inventé:critical', 'A', ''), LOCAL)
        self.assertEqual(e.exception.status_code, 404)
        with self.assertRaises(Exception):
            alert_center_ack('Zabbix:x:critical', 'A', '', hours=500)


def alert_center_ack(ident, by, note, hours=8):
    return alert_center.Ack(id=ident, by=by, note=note, hours=hours)


def alert_center_release(ident):
    return alert_center.Release(id=ident)


if __name__ == '__main__':
    unittest.main()
