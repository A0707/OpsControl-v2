import unittest
from observability import build


def snap(at, status='ok', cpu=20, ram=30, disk=40, service='active', fingerprint='a'):
    return {'collected_at': at, 'status': status, 'cpu': cpu, 'ram': ram, 'disk_max': disk,
            'fingerprint': fingerprint,
            'all_services': [{'name': 'nginx.service', 'status': service}]}


class ObservabilityTests(unittest.TestCase):
    def test_series_are_bounded_sorted_and_missing_is_not_zero(self):
        rows = [snap('2026-10-03T11:00:00+00:00', cpu=None), snap('2026-10-03T10:00:00+00:00', cpu=10)]
        result = build(rows)
        self.assertEqual([p['at'] for p in result['points']], sorted(p['at'] for p in result['points']))
        self.assertIsNone(result['points'][-1]['cpu'])
        self.assertEqual(result['trends']['cpu']['samples'], 1)

    def test_changes_are_explainable_and_threshold_based(self):
        rows = [snap('2026-10-03T10:00:00+00:00'),
                snap('2026-10-03T11:00:00+00:00', status='warning', disk=85, service='failed', fingerprint='b')]
        result = build(rows)
        kinds = {change['kind'] for change in result['changes']}
        self.assertEqual(kinds, {'configuration', 'status', 'threshold', 'service'})
        disk = next(c for c in result['changes'] if c['kind'] == 'threshold')
        self.assertEqual((disk['severity'], disk['evidence']), ('warning', '40 % → 85 %'))

    def test_invalid_metrics_never_become_measurements(self):
        result = build([snap('2026-10-03T10:00:00+00:00', cpu='secret', ram=200, disk=-1)])
        self.assertEqual(result['points'][0]['cpu'], None)
        self.assertEqual(result['points'][0]['ram'], None)
        self.assertEqual(result['points'][0]['disk'], None)


if __name__ == '__main__':
    unittest.main()
