"""Âge métier, état de traitement et notifications sur des dates synthétiques."""
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import incident_timing as timing

NOW = datetime(2026, 10, 27, 12, tzinfo=timezone.utc)


class TimingTests(unittest.TestCase):
    def test_direct_probe_requires_a_proof_within_thirty_seconds(self):
        alert = {'id': 'Sonde directe:down:critical', 'source': 'Sonde directe', 'severity': 'critical', 'fresh': True}
        row = {'state': 'open', 'opened_at': NOW.isoformat()}
        journal = {'Sonde directe|web01|down': row}
        for seconds, expected in ((30, 1), (31, 0)):
            target = self.target(NOW, NOW-timedelta(seconds=seconds))
            result = timing.summarize(alert, [target], journal, True, NOW)
            self.assertEqual(result['notification_events_count'], expected)
        for state in ('acknowledged', 'investigating', 'suppressed', 'resolved'):
            row['state'] = state
            self.assertEqual(timing.summarize(alert, [self.target(NOW)], journal, True, NOW)['notification_events_count'], 0)

    def target(self, start=None, proof=NOW):
        return {'name': 'web01', 'host_key': 'web01', 'fresh': True,
                'started_at': start.isoformat() if start else None,
                'observed_at': proof.isoformat()}

    def summarize(self, target, row=None, available=True):
        alert = {'id': 'SSH:disk:critical', 'source': 'SSH', 'severity': 'critical', 'fresh': True}
        journal = {'SSH|web01|disk': row} if row else {}
        return timing.summarize(alert, [target], journal, available, NOW)

    def test_refresh_does_not_rejuvenate_old_incident(self):
        result = self.summarize(self.target(), {'state': 'open', 'opened_at': (NOW-timedelta(days=2)).isoformat()})
        self.assertEqual(result['recency_counts'], {'recent': 0, 'old': 1, 'unknown': 0})
        self.assertEqual(result['notification_events'], [])

    def test_reopening_is_a_new_episode_with_a_new_signature(self):
        row = {'state': 'reopened', 'opened_at': (NOW-timedelta(days=2)).isoformat(),
               'reopened_at': (NOW-timedelta(minutes=1)).isoformat()}
        result = self.summarize(self.target(), row)
        self.assertEqual(result['state_counts'], {'reopened': 1})
        self.assertEqual(result['notification_events'][0]['kind'], 'reopened')
        self.assertEqual(result['notification_events'][0]['at'], row['reopened_at'])

    def test_notification_requires_recent_event_fresh_proof_and_open_state(self):
        for minutes in (16, 1440):
            self.assertEqual(self.summarize(self.target(NOW-timedelta(minutes=minutes)))['notification_events'], [])
        for state in ('acknowledged', 'investigating', 'suppressed', 'resolved'):
            row = {'state': state, 'opened_at': (NOW-timedelta(minutes=1)).isoformat()}
            self.assertEqual(self.summarize(self.target(), row)['notification_events'], [], state)
        old_proof = self.target(NOW-timedelta(minutes=1), NOW-timedelta(hours=1))
        self.assertEqual(self.summarize(old_proof)['notification_events'], [])
        self.assertEqual(self.summarize(self.target(NOW-timedelta(minutes=1)), available=False)['notification_events'], [])

    def test_missing_future_and_invalid_dates_are_unknown_and_silent(self):
        for start in (None, NOW+timedelta(minutes=1)):
            result = self.summarize(self.target(start))
            self.assertEqual(result['notification_events'], [])
            self.assertEqual(result['recency_counts']['unknown'], 1)
        self.assertIsNone(timing.instant('invalid'))
        self.assertEqual(timing.recency((NOW-timedelta(days=1)).isoformat(), NOW), 'recent')
        self.assertEqual(timing.recency((NOW-timedelta(days=1, seconds=1)).isoformat(), NOW), 'old')

    def test_all_targets_including_non_sampled_are_counted(self):
        targets = [self.target(NOW-timedelta(days=3)) for _ in range(25)]
        targets.append({**self.target(NOW-timedelta(minutes=1)), 'name': 'new01', 'host_key': 'new01'})
        alert = {'id': 'SSH:disk:critical', 'source': 'SSH', 'severity': 'critical', 'fresh': True}
        result = timing.summarize(alert, targets, {}, True, NOW)
        self.assertEqual(result['recency_counts'], {'recent': 1, 'old': 25, 'unknown': 0})
        self.assertEqual([e['name'] for e in result['notification_events']], ['new01'])

    def test_missing_journal_fails_closed(self):
        self.assertEqual(timing.journal_snapshot(SimpleNamespace()), ({}, False))
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        self.assertEqual(timing.journal_snapshot(SimpleNamespace(connect=lambda: db)), ({}, False))
