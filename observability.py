"""Compact, explainable per-host trends and changes from retained SSH audits.

This module never collects anything and never mutates a remote system.  It only
projects already-retained audit snapshots into a small browser payload.
"""
from datetime import datetime


LIMITS = {'cpu': (90, 98), 'ram': (90, 97), 'disk_max': (80, 90)}
LABELS = {'cpu': 'CPU', 'ram': 'RAM', 'disk_max': 'Disque'}


def _number(value):
    if isinstance(value, bool):
        return None
    try:
        number = round(float(value), 2)
    except (TypeError, ValueError, OverflowError):
        return None
    return number if 0 <= number <= 100 else None


def _instant(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return parsed if parsed.tzinfo else None
    except (TypeError, ValueError):
        return None


def _band(metric, value):
    if value is None:
        return 'unknown'
    warning, critical = LIMITS[metric]
    return 'critical' if value >= critical else 'warning' if value >= warning else 'ok'


def _services(snapshot):
    return {str(row.get('name')): row.get('status') for row in
            snapshot.get('all_services', snapshot.get('service_states', []))
            if row.get('name') and row.get('status')}


def build(snapshots, limit=168):
    """Return bounded series and significant changes, oldest point first."""
    ordered = sorted((s for s in snapshots if _instant(s.get('collected_at'))),
                     key=lambda s: _instant(s['collected_at']))[-max(2, min(limit, 336)):]
    points = [{'at': s['collected_at'], 'status': s.get('status', 'unknown'),
               'cpu': _number(s.get('cpu')), 'ram': _number(s.get('ram')),
               'disk': _number(s.get('disk_max'))} for s in ordered]
    changes = []

    def add(at, kind, title, severity='info', evidence=None):
        changes.append({'at': at, 'kind': kind, 'source': 'Audit SSH', 'title': title,
                        'severity': severity, 'evidence': evidence})

    for before, after in zip(ordered, ordered[1:]):
        at = after['collected_at']
        if before.get('fingerprint') and after.get('fingerprint') and before['fingerprint'] != after['fingerprint']:
            add(at, 'configuration', 'Configuration d’audit modifiée', 'unknown',
                'Les observations antérieures appartiennent à une autre configuration.')
        old_status, new_status = before.get('status'), after.get('status')
        if old_status and new_status and old_status != new_status:
            severity = new_status if new_status in ('critical', 'warning', 'unreachable') else 'ok' if new_status == 'ok' else 'unknown'
            add(at, 'status', f'État SSH : {old_status} → {new_status}', severity)
        for metric in LIMITS:
            old, new = _number(before.get(metric)), _number(after.get(metric))
            old_band, new_band = _band(metric, old), _band(metric, new)
            if old_band != new_band and 'unknown' not in (old_band, new_band):
                add(at, 'threshold', f'{LABELS[metric]} : seuil {old_band} → {new_band}',
                    new_band, f'{old:g} % → {new:g} %')
        old_services, new_services = _services(before), _services(after)
        for name in sorted(old_services.keys() & new_services.keys()):
            if old_services[name] != new_services[name]:
                state = new_services[name]
                severity = 'critical' if state == 'failed' else 'warning' if state == 'inactive' else 'ok'
                add(at, 'service', f'Service {name} : {old_services[name]} → {state}', severity)

    trends = {}
    for key, point_key in [('cpu', 'cpu'), ('ram', 'ram'), ('disk_max', 'disk')]:
        measured = [(p['at'], p[point_key]) for p in points if p[point_key] is not None]
        first, last = (measured[0][1], measured[-1][1]) if measured else (None, None)
        delta = round(last-first, 2) if len(measured) > 1 else None
        trends[point_key] = {'first': first, 'last': last, 'delta': delta,
                             'direction': 'up' if delta is not None and delta >= 2 else
                                          'down' if delta is not None and delta <= -2 else 'stable',
                             'samples': len(measured)}
    changes.sort(key=lambda row: row['at'], reverse=True)
    return {'points': points, 'trends': trends, 'changes': changes[:60],
            'range_days': 7, 'samples': len(points),
            'scope': 'Audits SSH conservés : 20 derniers puis au plus un point par heure sur 7 jours. '
                     'Un changement indique deux observations différentes, pas sa cause.'}
