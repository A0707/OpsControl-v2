"""A failed collection must not erase evidence or pretend it is current."""
import testing_env  # noqa: F401 — base temporaire AVANT tout import d'app (testing_env.py)
import json
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

from audit_retention import display_audit, retain_attempt


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.good = {'collected_at': self.now.isoformat(), 'fingerprint': 'cfg',
                     'status': 'warning', 'coverage': {'measured': 13, 'total': 16},
                     'cpu': 12, 'ram': 35, 'issues': ['Disque 85%'], 'findings': []}
        self.failure = {'collected_at': (self.now + timedelta(seconds=1)).isoformat(),
                        'fingerprint': 'cfg', 'status': 'critical', 'cpu': None,
                        'coverage': {'measured': 0, 'total': 16},
                        'issues': ['Clé hôte inconnue'], 'findings': []}

    def test_repeated_failures_preserve_date_and_latest_error_without_nesting(self):
        saved = self.good
        for _ in range(25):
            saved = retain_attempt(self.failure, saved)
        row = display_audit(saved, 'cfg', self.now)
        self.assertEqual(row['cpu'], 12)
        self.assertEqual(row['collected_at'], self.good['collected_at'])
        self.assertEqual(row['last_attempt']['issues'], self.failure['issues'])
        self.assertTrue(row['audit_recorded'])
        self.assertTrue(row['stale'])
        self.assertEqual(row['status'], 'unknown')
        self.assertNotIn('last_observation', saved['last_observation'])
        self.assertNotIn('last_observation', row)
        self.assertNotIn('last_attempt', self.good)

    def test_recovery_replaces_retained_observation(self):
        saved = retain_attempt(self.failure, self.good)
        recovered = dict(self.good, cpu=2)
        saved = retain_attempt(recovered, saved)
        row = display_audit(saved, 'cfg', self.now)
        self.assertNotIn('last_observation', saved)
        self.assertNotIn('last_attempt', row)
        self.assertEqual(row['cpu'], 2)
        self.assertFalse(row['stale'])

    def test_changed_configuration_keeps_evidence_but_requires_new_audit(self):
        row = display_audit(self.good, 'new-config', self.now)
        self.assertEqual(row['cpu'], 12)
        self.assertTrue(row['audit_available'])
        self.assertTrue(row['configuration_changed'])
        self.assertTrue(row['stale'])
        self.assertFalse(row['audit_recorded'])

    def test_stale_reason_names_the_cause(self):
        # Audit UI du 31/10 (fiche 05.1) : « à actualiser » dit pourquoi.
        self.assertIsNone(display_audit(self.good, 'cfg', self.now)['stale_reason'])
        self.assertEqual(display_audit(self.good, 'new-config', self.now)['stale_reason'], 'configuration_changed')
        failed = retain_attempt(self.failure, self.good)
        self.assertEqual(display_audit(failed, 'cfg', self.now)['stale_reason'], 'attempt_failed')
        later = self.now + timedelta(minutes=16)
        self.assertEqual(display_audit(self.good, 'cfg', later)['stale_reason'], 'age')
        self.assertIsNone(display_audit(self.good, 'cfg', self.now + timedelta(minutes=5))['stale_reason'])

    def test_missing_audit_and_invalid_dates_are_not_fresh(self):
        self.assertFalse(display_audit(None, 'cfg')['audit_available'])
        for date in ('invalid', '2026-01-01T00:00:00', None):
            self.assertTrue(display_audit(dict(self.good, collected_at=date), 'cfg')['stale'])

    def test_database_failure_persistence_and_ip_isolation(self):
        import app
        host = {'key': 'test', 'name': 'test', 'ip': '192.0.2.1', 'role': 'test'}
        with tempfile.TemporaryDirectory() as directory, patch.object(app, 'DB', Path(directory)/'state.db'), patch.object(app, 'HOSTS', [host]), patch.object(app, 'job', {'completed': 0}), patch.object(app, 'collect') as collect:
            with app.connect() as db:
                db.execute('CREATE TABLE states(key TEXT PRIMARY KEY,ip TEXT,payload TEXT)')
                db.execute('CREATE TABLE history(id INTEGER PRIMARY KEY,key TEXT,ts TEXT,status TEXT,summary TEXT)')
                db.execute('CREATE TABLE audit_snapshots(key TEXT,ts TEXT,payload TEXT,PRIMARY KEY(key,ts))')
            collect.return_value = dict(self.good)
            app.refresh([host], 'test')
            collect.return_value = dict(self.failure)
            app.refresh([host], 'test')
            self.assertEqual(app.rows()[0]['cpu'], 12)
            self.assertTrue(app.rows()[0]['audit_retained'])
            with app.connect() as db:
                snapshot = json.loads(db.execute('SELECT payload FROM audit_snapshots ORDER BY ts DESC LIMIT 1').fetchone()[0])
            self.assertNotIn('last_observation', snapshot)
            self.assertIsNone(snapshot['cpu'])
            host['ip'] = '192.0.2.2'
            self.assertFalse(app.rows()[0]['audit_available'])
            app.refresh([host], 'test')
            self.assertFalse(app.rows()[0]['audit_available'])
            with app.connect() as db:
                self.assertNotIn('last_observation', json.loads(db.execute('SELECT payload FROM states').fetchone()[0]))


if __name__ == '__main__':
    unittest.main()
