from routers import all_routes  # routes des APIRouter inclus (FastAPI ne les recopie plus dans app.routes)
import threading
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from fastapi import FastAPI

import ssh_refresh

NOW = datetime(2026, 9, 26, 12, 0, tzinfo=timezone.utc)


def ago(minutes):
    return (NOW - timedelta(minutes=minutes)).isoformat()


def fleet(n, age_min, **extra):
    hosts = [{'key': f'h{i:02d}', 'criticality': 'standard'} for i in range(n)]
    rows = [{'key': h['key'], 'collected_at': ago(age_min), 'status': 'warning', **extra} for h in hosts]
    return hosts, rows


class DueHostsTests(unittest.TestCase):
    def test_manual_means_nothing(self):
        hosts, rows = fleet(10, 999)
        self.assertEqual(ssh_refresh.due_hosts(rows, hosts, 0, NOW.timestamp()), [])

    def test_quota_spreads_the_fleet_over_the_interval(self):
        hosts, rows = fleet(87, 60)
        lot = ssh_refresh.due_hosts(rows, hosts, 600, NOW.timestamp())
        self.assertEqual(len(lot), 10)  # ceil(87 * 60 / 600) + 1 : le parc en ~10 min, pas d'un coup

    def test_recent_measure_not_due_oldest_first(self):
        hosts, rows = fleet(3, 5)
        rows[1]['collected_at'] = ago(40)
        rows[2]['collected_at'] = ago(20)
        lot = ssh_refresh.due_hosts(rows, hosts, 600, NOW.timestamp())
        self.assertEqual([h['key'] for h in lot], ['h01', 'h02'])

    def test_critical_first_and_every_5_min(self):
        hosts, rows = fleet(3, 6)
        hosts[2]['criticality'] = 'critical'
        lot = ssh_refresh.due_hosts(rows, hosts, 3600, NOW.timestamp())
        self.assertEqual([h['key'] for h in lot], ['h02'])  # seul le critique est dû à 6 min

    def test_unreachable_waits_30_min(self):
        hosts, rows = fleet(2, 15, status='unreachable')
        self.assertEqual(ssh_refresh.due_hosts(rows, hosts, 600, NOW.timestamp()), [])
        rows[0]['collected_at'] = ago(31)
        self.assertEqual([h['key'] for h in ssh_refresh.due_hosts(rows, hosts, 600, NOW.timestamp())], ['h00'])

    def test_failed_attempt_counts_as_activity(self):
        hosts, rows = fleet(1, 120)
        rows[0]['last_attempt'] = {'collected_at': ago(2)}
        self.assertEqual(ssh_refresh.due_hosts(rows, hosts, 600, NOW.timestamp()), [])

    def test_never_audited_and_disabled(self):
        hosts = [{'key': 'neuf'}, {'key': 'off', 'collect_enabled': False}]
        self.assertEqual([h['key'] for h in ssh_refresh.due_hosts([], hosts, 600, NOW.timestamp())], ['neuf'])


class TickTests(unittest.TestCase):
    def make(self, setting=None, running=False):
        hosts, rows = fleet(4, 60)
        # tick() compare à l'heure réelle : mesures datées d'une heure avant maintenant.
        for r in rows:
            r['collected_at'] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        store ={} if setting is None else {ssh_refresh.SETTING: str(setting)}
        launched = []
        ctx = SimpleNamespace(HOSTS=hosts, rows=lambda: rows, lock=threading.Lock(), job={'running': running},
                              read_setting=store.get, write_setting=lambda k, v: store.__setitem__(k, str(v)),
                              launch=lambda sel, who, scope: launched.append((len(sel), who, scope)))
        app = FastAPI()
        ssh_refresh.install(app, ctx)
        routes = {(r.path, tuple(r.methods)): r.endpoint for r in all_routes(app) if hasattr(r, 'methods')}
        return ctx, launched, store, routes

    def test_disabled_by_default(self):
        ctx, launched, _, _ = self.make()
        ctx.ssh_refresh_tick(now=0)
        self.assertEqual(launched, [])

    def test_persisted_choice_launches_one_batch_per_minute(self):
        ctx, launched, _, _ = self.make(600)
        ctx.ssh_refresh_tick(now=0)
        ctx.ssh_refresh_tick(now=30)   # même minute : rien
        # 4 serveurs à 10 min : quota de 2 par minute, pas les 4 d'un coup.
        self.assertEqual(launched, [(2, 'audit-periodique', 'rotation')])

    def test_never_on_top_of_a_running_audit(self):
        ctx, launched, _, _ = self.make(600, running=True)
        ctx.ssh_refresh_tick(now=0)
        self.assertEqual(launched, [])

    def test_api_validates_and_persists(self):
        ctx, _, store, routes = self.make()
        choix = routes[('/api/ssh-refresh', ('POST',))]
        self.assertEqual(choix(ssh_refresh.Choice(interval=1800))['interval'], 1800)
        self.assertEqual(store[ssh_refresh.SETTING], '1800')
        with self.assertRaises(Exception):
            choix(ssh_refresh.Choice(interval=5))

    def test_api_reports_unsaved_choice(self):
        # OC-AUDIT-015 : base verrouillée ou disque plein → 503, jamais « enregistré ».
        from fastapi import HTTPException
        ctx, _, store, routes = self.make()
        ctx.write_setting = lambda k, v: False
        with self.assertRaises(HTTPException) as raised:
            routes[('/api/ssh-refresh', ('POST',))](ssh_refresh.Choice(interval=600))
        self.assertEqual(raised.exception.status_code, 503)
        self.assertIn('non enregistré', raised.exception.detail)
        self.assertNotIn(ssh_refresh.SETTING, store)


if __name__ == '__main__':
    unittest.main()
