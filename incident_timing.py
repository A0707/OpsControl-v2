"""Âge des occurrences et notifications : une nouvelle preuve ne recrée pas une panne."""
from datetime import datetime, timezone
import sqlite3

NEW_SECONDS = 24 * 3600
NOTIFY_SECONDS = 15 * 60


def instant(value):
    try:
        if value is None or value == '':
            return None
        if str(value).replace('.', '', 1).isdigit():
            return datetime.fromtimestamp(float(value), timezone.utc)
        parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def occurrence(row):
    tracked, declared = instant(row.get('opened_at')), instant(row.get('first_observed_at'))
    source = declared is not None and (tracked is None or declared < tracked)
    start = declared if source else tracked
    reopened = instant(row.get('reopened_at'))
    resolved = instant(row.get('resolved_at')) if row.get('state') == 'resolved' else None
    event = resolved or reopened or start
    return {'since': start.isoformat() if start else None, 'since_basis': 'source' if source else 'journal',
            'event_at': event.isoformat() if event else None,
            'event_kind': 'resolved' if resolved else 'reopened' if reopened else 'source' if source else 'journal'}


def recency(value, now):
    at = instant(value)
    age = (now - at).total_seconds() if at else None
    return 'unknown' if age is None or age < 0 else 'recent' if age <= NEW_SECONDS else 'old'


def journal_snapshot(context):
    try:
        with context.connect() as db:
            cur = db.execute('SELECT id,state,opened_at,first_observed_at,reopened_at,resolved_at FROM incidents')
            columns = [c[0] for c in cur.description]
            return {r[0]: dict(zip(columns, r)) for r in cur.fetchall()}, True
    except (sqlite3.Error, AttributeError):
        # Journal absent ou indisponible : aucune notification extrapolée de la collecte.
        return {}, False


def summarize(alert, targets, journal, available, now):
    from incident_center import incident_type
    counts = {'recent': 0, 'old': 0, 'unknown': 0}
    states, events, candidates = {}, [], []
    for target in targets or [{}]:
        name = target.get('name') or target.get('host_key') or 'global'
        key = '|'.join((alert['source'], target.get('host_key') or name,
                        incident_type(alert['id'], alert['source'])))[:400]
        tracked = journal.get(key)
        native = instant(target.get('started_at'))
        row = dict(tracked or {})
        if native:
            row['first_observed_at'] = native.isoformat()
        info = occurrence(row)
        event = instant(info['event_at'])
        state = row.get('state') or ('open' if native else 'unknown')
        counts[recency(info['event_at'], now)] += 1
        states[state] = states.get(state, 0) + 1
        target.update(state=state, recency=recency(info['event_at'], now),
                      event_at=info['event_at'], event_kind=info['event_kind'])
        if event and event <= now:
            events.append((event, info['event_kind']))
        observed = instant(target.get('observed_at') or alert.get('observed_at'))
        proof_age = (now - observed).total_seconds() if observed else None
        age = (now - event).total_seconds() if event else None
        budget = 30 if alert['source'] in ('Zabbix', 'Sonde directe') else 900
        fresh = target.get('fresh', alert.get('fresh'))
        if (available and alert['severity'] == 'critical' and state in ('open', 'reopened')
                and fresh and age is not None and 0 <= age <= NOTIFY_SECONDS
                and proof_age is not None and 0 <= proof_age <= budget):
            candidates.append({'id': key, 'at': info['event_at'], 'kind': info['event_kind'],
                               'name': name, 'host_key': target.get('host_key'),
                               'observed_at': observed.isoformat(), 'max_age_seconds': budget})
    latest = max(events, default=None)
    return {'recency_counts': counts, 'state_counts': states,
            'latest_event_at': latest[0].isoformat() if latest else None,
            'latest_event_kind': latest[1] if latest else None,
            'notification_events': sorted(candidates, key=lambda c: (c['at'], c['id']), reverse=True)[:25],
            'notification_events_count': len(candidates)}
