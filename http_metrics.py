"""Métriques HTTP d'OpsControl : volumes, erreurs et latence, pour les SLO (Zabbix, Prometheus).

Alimenté par le middleware d'access_policy (une mesure par requête), exporté par
/api/metrics au format texte Prometheus. Deux familles :

- cumulatives depuis le démarrage : compteurs par route et classe de statut, histogramme
  de latence par route (route = gabarit FastAPI, ex. /api/hosts/{key} : cardinalité bornée) ;
- fenêtre glissante de WINDOW_SECONDS sur les requêtes /api/* : p95 de latence, volume et
  taux de 5xx, directement comparables aux SLO sans moteur de requêtes côté Zabbix.

Le flux SSE /api/events est exclu de la fenêtre : sa « durée » est celle de l'ouverture
du flux, pas d'une réponse. Tout vit en mémoire et repart de zéro au redémarrage.
"""
from __future__ import annotations

import threading
import time
from collections import deque

BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
WINDOW_SECONDS = 300
WINDOW_MAX = 100_000
EXCLUDED_FROM_WINDOW = ('/api/events',)


class HttpStats:
    def __init__(self, clock=time.monotonic):
        self.clock, self.lock = clock, threading.Lock()
        self.counts = {}      # (route, classe) -> nombre
        self.histo = {}       # route -> [compteurs par seau..., +Inf], somme
        self.window = deque(maxlen=WINDOW_MAX)   # (instant, secondes, est_5xx)

    def record(self, route: str, status: int, seconds: float, path: str = '') -> None:
        klass = f'{status // 100}xx'
        with self.lock:
            self.counts[(route, klass)] = self.counts.get((route, klass), 0) + 1
            buckets, total = self.histo.get(route, ([0] * (len(BUCKETS) + 1), 0.0))
            for i, bound in enumerate(BUCKETS):
                if seconds <= bound:
                    buckets[i] += 1
            buckets[-1] += 1
            self.histo[route] = (buckets, total + seconds)
            if path.startswith('/api/') and path not in EXCLUDED_FROM_WINDOW:
                self.window.append((self.clock(), seconds, status >= 500))

    def recent(self) -> dict:
        """p95 (s), volume et taux de 5xx sur la fenêtre glissante ; None sans requête."""
        limit = self.clock() - WINDOW_SECONDS
        with self.lock:
            while self.window and self.window[0][0] < limit:
                self.window.popleft()
            durations = sorted(d for _, d, _ in self.window)
            errors = sum(1 for _, _, e in self.window if e)
        n = len(durations)
        if not n:
            return {'requests': 0, 'p95_seconds': None, 'error_ratio': None}
        return {'requests': n, 'p95_seconds': durations[min(n - 1, int(0.95 * n))], 'error_ratio': errors / n}

    def prometheus(self) -> list[str]:
        with self.lock:
            counts, histo = dict(self.counts), {k: (list(v[0]), v[1]) for k, v in self.histo.items()}
        lines = ['# HELP opscontrol_http_requests_total Requêtes HTTP par route et classe de statut',
                 '# TYPE opscontrol_http_requests_total counter']
        lines += [f'opscontrol_http_requests_total{{route="{_label(r)}",code="{c}"}} {n}' for (r, c), n in sorted(counts.items())]
        lines += ['# HELP opscontrol_http_request_duration_seconds Latence des réponses HTTP par route',
                  '# TYPE opscontrol_http_request_duration_seconds histogram']
        for route, (buckets, total) in sorted(histo.items()):
            r = _label(route)
            lines += [f'opscontrol_http_request_duration_seconds_bucket{{route="{r}",le="{b:g}"}} {n}'
                      for b, n in zip(BUCKETS, buckets)]
            lines += [f'opscontrol_http_request_duration_seconds_bucket{{route="{r}",le="+Inf"}} {buckets[-1]}',
                      f'opscontrol_http_request_duration_seconds_sum{{route="{r}"}} {total:.6f}',
                      f'opscontrol_http_request_duration_seconds_count{{route="{r}"}} {buckets[-1]}']
        w = self.recent()
        gauges = (('opscontrol_http_requests_window', w['requests'], f'Requêtes /api/* sur {WINDOW_SECONDS} s'),
                  ('opscontrol_http_p95_seconds_window', w['p95_seconds'], f'Latence p95 /api/* sur {WINDOW_SECONDS} s'),
                  ('opscontrol_http_5xx_ratio_window', w['error_ratio'], f'Part de 5xx /api/* sur {WINDOW_SECONDS} s'))
        for name, value, text in gauges:
            if value is not None:
                lines += [f'# HELP {name} {text}', f'# TYPE {name} gauge', f'{name} {value:g}']
        return lines


def _label(value: str) -> str:
    return str(value).replace('\\', '').replace('"', '').replace('\n', ' ')[:200]


HTTP = HttpStats()
