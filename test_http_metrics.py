"""Métriques HTTP (http_metrics) et lecture de /api/metrics par l'agent local."""
import os
import unittest
from types import SimpleNamespace
from unittest import mock

import access_policy
import http_metrics


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class StatsTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.stats = http_metrics.HttpStats(clock=self.clock)

    def test_p95_volume_et_taux_de_5xx(self):
        for i in range(100):
            self.stats.record('/api/overview', 500 if i < 2 else 200, (i + 1) / 1000, '/api/overview')
        w = self.stats.recent()
        self.assertEqual(w['requests'], 100)
        self.assertAlmostEqual(w['p95_seconds'], 0.096)
        self.assertAlmostEqual(w['error_ratio'], 0.02)

    def test_fenetre_glissante_et_exclusions(self):
        self.stats.record('/api/overview', 200, 0.01, '/api/overview')
        self.stats.record('/api/events', 200, 30.0, '/api/events')    # flux SSE : hors fenêtre
        self.stats.record('statique', 200, 0.001, '/app.js')           # hors /api/ : hors fenêtre
        self.assertEqual(self.stats.recent()['requests'], 1)
        self.clock.t += http_metrics.WINDOW_SECONDS + 1
        self.assertEqual(self.stats.recent(), {'requests': 0, 'p95_seconds': None, 'error_ratio': None})

    def test_export_prometheus(self):
        self.stats.record('/api/hosts/{key}', 200, 0.02, '/api/hosts/web01')
        self.stats.record('/api/hosts/{key}', 503, 2.0, '/api/hosts/web02')
        text = '\n'.join(self.stats.prometheus())
        self.assertIn('opscontrol_http_requests_total{route="/api/hosts/{key}",code="2xx"} 1', text)
        self.assertIn('opscontrol_http_requests_total{route="/api/hosts/{key}",code="5xx"} 1', text)
        self.assertIn('opscontrol_http_request_duration_seconds_bucket{route="/api/hosts/{key}",le="0.025"} 1', text)
        self.assertIn('opscontrol_http_request_duration_seconds_bucket{route="/api/hosts/{key}",le="+Inf"} 2', text)
        self.assertIn('opscontrol_http_5xx_ratio_window 0.5', text)
        self.assertNotIn('web01', text, 'gabarit de route, jamais la clé du serveur')


class LocalMetricsAccessTests(unittest.TestCase):
    def request(self, host='127.0.0.1', headers=None):
        return SimpleNamespace(client=SimpleNamespace(host=host), headers=headers or {})

    def test_agent_local_autorise_si_active(self):
        with mock.patch.dict(os.environ, {'INFRAOPS_METRICS': '1'}):
            self.assertTrue(access_policy.local_metrics(self.request(), 'GET', '/api/metrics'))
            self.assertTrue(access_policy.local_metrics(self.request('::1'), 'GET', '/api/metrics'))

    def test_refus(self):
        with mock.patch.dict(os.environ, {'INFRAOPS_METRICS': '1'}):
            self.assertFalse(access_policy.local_metrics(self.request('10.0.0.5'), 'GET', '/api/metrics'))
            # Requête passée par nginx (X-Forwarded-For toujours posé) : rôle exigé comme avant.
            self.assertFalse(access_policy.local_metrics(self.request(headers={'x-forwarded-for': '127.0.0.1'}), 'GET', '/api/metrics'))
            self.assertFalse(access_policy.local_metrics(self.request(), 'GET', '/api/overview'))
            self.assertFalse(access_policy.local_metrics(self.request(), 'POST', '/api/metrics'))
        with mock.patch.dict(os.environ, {'INFRAOPS_METRICS': '0'}):
            self.assertFalse(access_policy.local_metrics(self.request(), 'GET', '/api/metrics'))


if __name__ == '__main__':
    unittest.main()
