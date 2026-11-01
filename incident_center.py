"""Journal d'incidents persistant (SQLite), alimenté par le centre d'alertes.

Un incident = une source + une cible + un type d'anomalie. Identifiant stable
(sans la gravité : un passage de « majeur » à « critique » reste le même incident).

Cycle de vie :
    open ──ack──▶ acknowledged ──investigate──▶ investigating
      │                │
      └──suppress──▶ suppressed ──(expiration / réactivation)──▶ open
    (toute cible absente d'une collecte COMPLÈTE) ──▶ resolved ──(réapparition)──▶ reopened

Règles de véracité :
- un incident n'est JAMAIS résolu si la collecte de sa source est incomplète,
  ancienne ou en échec : il reste ouvert avec « confirmation impossible » ;
- une suppression masque, elle ne résout pas : l'incident reste suivi ;
- toute écriture est locale à OpsControl (aucune action vers les produits supervisés).

Aucun secret n'est stocké : preuve masquée et tronquée, identité opérateur, note.
"""
from __future__ import annotations

import json
import logging
import re
import threading
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from audit_engine import redact
import incident_timing

SCHEMA = 'incidents_v1'
STATES = ('open', 'acknowledged', 'investigating', 'resolved', 'reopened', 'suppressed')
ACTIVE = ('open', 'acknowledged', 'investigating', 'reopened', 'suppressed')
SEVERITIES = ('critical', 'warning', 'preventive', 'info')
DURATIONS = {'24h': timedelta(hours=24), '7d': timedelta(days=7), 'permanent': None}
API_PROVIDERS = {'Zabbix': 'Zabbix', 'Wazuh': 'Wazuh', 'Elastic': 'Elasticsearch', 'Elasticsearch': 'Elasticsearch',
                 'Bacula': 'Bacula', 'Proxmox': 'Proxmox'}
HOST_SOURCES = ('SSH', 'Partages')
PROBE_SOURCE = 'Sonde directe'
# La sonde tourne toutes les 5 s (tier0.PROBE_SECONDS) ; une minute absorbe un ping lent.
PROBE_FRESH_SECONDS = 60
EVIDENCE_MAX = 600
SYNC_MIN_SECONDS = 15
SEVERITY_RANK = {'critical': 0, 'warning': 1, 'preventive': 2, 'info': 3}
# Le rapprochement actualise last_seen_at chaque minute : ce n'est pas un nouvel incident.
START_SQL = ("CASE WHEN julianday(first_observed_at) IS NOT NULL AND "
             "(julianday(opened_at) IS NULL OR julianday(first_observed_at) < julianday(opened_at)) "
             "THEN first_observed_at ELSE opened_at END")
EVENT_SQL = ("CASE WHEN state='resolved' THEN COALESCE(julianday(resolved_at),julianday(reopened_at),"
             "julianday(" + START_SQL + ")) ELSE COALESCE(julianday(reopened_at),julianday(" + START_SQL + ")) END")


def now_utc():
    return datetime.now(timezone.utc)


def _iso(value):
    return value.isoformat() if value else None


def _parse(value):
    try:
        parsed = datetime.fromisoformat(str(value))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- migrations
def migrate(db):
    db.execute('CREATE TABLE IF NOT EXISTS schema_migrations(name TEXT PRIMARY KEY, applied_at TEXT)')
    applied = {r[0] for r in db.execute('SELECT name FROM schema_migrations')}
    changed = False
    if SCHEMA not in applied:
        _migrate_v1(db)
        changed = True
    if 'incidents_v2_source_start' not in applied:
        # v1 stockait la dernière mesure comme « première observation » : ce n'est pas un début.
        # On l'efface ; le rapprochement suivant renseigne le vrai début si la source le déclare.
        db.execute('UPDATE incidents SET first_observed_at=NULL')
        db.execute('INSERT INTO schema_migrations(name, applied_at) VALUES(?,?)', ('incidents_v2_source_start', now_utc().isoformat()))
        changed = True
    if 'incidents_v3_workflow_maintenance' not in applied:
        columns = {row[1] for row in db.execute('PRAGMA table_info(incidents)')}
        if 'investigation_at' not in columns:
            db.execute('ALTER TABLE incidents ADD COLUMN investigation_at TEXT')
        db.execute('''CREATE TABLE IF NOT EXISTS maintenance_windows(
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, starts_at TEXT NOT NULL, ends_at TEXT NOT NULL,
            source TEXT, target TEXT, note TEXT, actor TEXT NOT NULL, actor_auth TEXT NOT NULL, created_at TEXT NOT NULL)''')
        db.execute('CREATE INDEX IF NOT EXISTS maintenance_active ON maintenance_windows(starts_at, ends_at)')
        db.execute('INSERT INTO schema_migrations(name, applied_at) VALUES(?,?)', ('incidents_v3_workflow_maintenance', now_utc().isoformat()))
        changed = True
    return changed


def _migrate_v1(db):
    db.execute('''CREATE TABLE IF NOT EXISTS incidents(
        id TEXT PRIMARY KEY, source TEXT NOT NULL, target TEXT NOT NULL, target_key TEXT, type TEXT NOT NULL,
        title TEXT NOT NULL, state TEXT NOT NULL, severity TEXT NOT NULL, severity_max TEXT NOT NULL,
        opened_at TEXT NOT NULL, first_observed_at TEXT, last_seen_at TEXT NOT NULL,
        acknowledged_at TEXT, ack_until TEXT, suppressed_at TEXT, suppressed_until TEXT,
        resolved_at TEXT, reopened_at TEXT, reopen_count INTEGER NOT NULL DEFAULT 0,
        owner TEXT, owner_auth TEXT, note TEXT, evidence TEXT, observed_at TEXT, fresh INTEGER,
        chronic INTEGER NOT NULL DEFAULT 0, rule TEXT, link TEXT,
        confirmation_blocked_since TEXT, confirmation_blocked_reason TEXT, updated_at TEXT NOT NULL)''')
    db.execute('CREATE INDEX IF NOT EXISTS incidents_state ON incidents(state, severity)')
    db.execute('''CREATE TABLE IF NOT EXISTS incident_events(
        seq INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, at TEXT NOT NULL,
        kind TEXT NOT NULL, actor TEXT, actor_auth TEXT, detail TEXT)''')
    db.execute('CREATE INDEX IF NOT EXISTS incident_events_id ON incident_events(incident_id, seq)')
    db.execute('INSERT INTO schema_migrations(name, applied_at) VALUES(?,?)', (SCHEMA, now_utc().isoformat()))


# --------------------------------------------------------------------------- observations
def incident_type(alert_id: str, source: str) -> str:
    """ID d'alerte « Source:type…:gravité[:chronique] » → type sans source ni gravité."""
    value = re.sub(r':chronique$', '', alert_id)
    value = re.sub(r':(critical|warning|preventive|info)$', '', value)
    prefix = source + ':'
    return value[len(prefix):] if value.startswith(prefix) else value


def _source_start(value):
    """Epoch (Zabbix) ou ISO → ISO UTC ; None si absent ou illisible (jamais inventé)."""
    from alert_center import _instant
    seconds = _instant(value)
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat() if seconds else None


def observations(alerts: list) -> list:
    """Décompose les alertes regroupées par cause en une observation par cible."""
    out = {}
    for alert in alerts or []:
        source = str(alert.get('source') or 'Inconnue')
        kind = incident_type(str(alert.get('id') or alert.get('title') or ''), source)
        targets = alert.get('targets') or [{}]
        for target in targets:
            name = target.get('name') or target.get('host_key') or 'global'
            key = target.get('host_key')
            incident_id = '|'.join((source, key or name, kind))[:400]
            severity = alert.get('severity') if alert.get('severity') in SEVERITIES else 'info'
            previous = out.get(incident_id)
            if previous and SEVERITY_RANK[previous['severity']] <= SEVERITY_RANK[severity]:
                continue
            evidence = alert.get('evidence') or target.get('detail') or alert.get('source_severity')
            out[incident_id] = {
                'id': incident_id, 'source': source, 'target': str(name)[:200], 'target_key': key,
                'type': kind[:300], 'title': str(alert.get('title') or kind)[:300], 'severity': severity,
                # Masquage avant persistance : le journal conserve la preuve longtemps.
                'evidence': redact(evidence)[:EVIDENCE_MAX] if evidence else None,
                'observed_at': target.get('observed_at') or alert.get('observed_at'),
                # Début réel déclaré par la source (Zabbix last_change, partage injoignable depuis…) ; sinon None.
                'started_at': _source_start(target.get('started_at')),
                'fresh': target.get('fresh') if target.get('fresh') is not None else alert.get('fresh'),
                'chronic': bool(alert.get('chronic')), 'rule': alert.get('rule'),
                'link': json.dumps({'host_key': key} if key else {'page': source}),
            }
    return list(out.values())


def _probe_status(probe: dict | None, at: datetime | None) -> dict:
    """Sonde directe : une absence de panne ne vaut résolution que sur une mesure récente
    (moins de PROBE_FRESH_SECONDS) avec un chemin de mesure sain. Sans cet état, un incident
    « serveur critique HORS SERVICE » restait ouvert indéfiniment (audit SUP-03)."""
    if not probe:
        return {}
    at = at or now_utc()

    def recent(stamp):
        try:
            age = (at - datetime.fromisoformat(stamp)).total_seconds()
        except (TypeError, ValueError):
            return False
        return 0 <= age <= PROBE_FRESH_SECONDS
    if probe.get('enabled') is False:
        return {'observer': (False, 'Sonde directe désactivée')}
    observer_ok = probe.get('observer_ok') is not False
    status = {'observer': (observer_ok and recent(probe.get('observer_checked_at')),
                           None if observer_ok else 'Chemin de mesure de la sonde perturbé')}
    if not status['observer'][0] and observer_ok:
        status['observer'] = (False, 'Mesure du chemin de sonde ancienne')
    for key, checked_at in (probe.get('hosts') or {}).items():
        if not key:
            continue
        if not observer_ok:
            status[str(key).lower()] = (False, 'Chemin de mesure de la sonde perturbé')
        elif not recent(checked_at):
            status[str(key).lower()] = (False, 'Sonde directe ancienne pour ce serveur')
        else:
            status[str(key).lower()] = (True, None)
    return status


def source_status(alert_sources: list, rows: list, probe: dict | None = None, at: datetime | None = None,
                  batch: dict | None = None) -> dict:
    """Complétude de la dernière collecte, par source d'API, par serveur (SSH) et pour la sonde directe."""
    providers = {}
    for s in alert_sources or []:
        provider = s.get('provider')
        ok = bool(s.get('fresh')) and not s.get('error')
        current = providers.get(provider, (True, []))
        providers[provider] = (current[0] and ok, current[1] + ([] if ok else [f"{s.get('name')} : {s.get('error') or 'collecte ancienne'}"]))
    hosts, audits = {}, {}
    for row in rows or []:
        measured = (row.get('coverage') or {}).get('measured') or 0
        ok = bool(row.get('collected_at')) and not row.get('stale') and measured > 0
        reason = None if ok else ('Audit SSH ancien' if row.get('stale') else 'Audit SSH absent ou sans mesure')
        for ident in {row.get('key'), row.get('name'), row.get('ip'), row.get('fqdn')} - {None, ''}:
            hosts[str(ident).lower()] = (ok, reason)
            audits[str(ident).lower()] = row
    return {'providers': providers, 'hosts': hosts, 'audits': audits, 'probe': _probe_status(probe, at),
            'batch': batch or {}}


def can_confirm_absence(incident: dict, status: dict) -> tuple[bool, str | None]:
    """Une absence n'est une résolution que si la source a réellement tout mesuré."""
    source = incident['source']
    if source in HOST_SOURCES:
        key = (incident.get('target_key') or '').lower()
        if not key:
            return False, 'Cible non rattachée à un serveur : absence non vérifiable'
        ok, reason = status['hosts'].get(key, (False, 'Serveur absent de l’inventaire'))
        if ok and source == 'SSH':
            # Collecte récente ET contrôle concerné mesuré : une autre mesure réussie
            # (CPU lu, disque illisible) ne prouve pas le retour à la normale.
            from alert_center import controle_mesure
            if not controle_mesure((status.get('audits') or {}).get(key) or {}, incident.get('type')):
                return False, 'Contrôle concerné non mesuré lors de la dernière collecte SSH'
        return ok, reason
    if source == 'Batch':
        # Plus d'échec observé : résolu seulement si l'inventaire batch du serveur est récent.
        key = (incident.get('target_key') or '').lower()
        if not key:
            return False, 'Batch hors inventaire SSH : absence d’échec non vérifiable'
        return (status.get('batch') or {}).get(key, (False, 'Inventaire batch du serveur non collecté'))
    if source == PROBE_SOURCE:
        probe = status.get('probe') or {}
        key = (incident.get('target_key') or '').lower()
        if not probe:
            return False, 'Sonde directe sans état de mesure'
        if not key:   # incident global « chemin de mesure perturbé »
            return probe.get('observer', (False, 'Sonde directe sans état de mesure'))
        return probe.get(key, (False, 'Serveur absent de la sonde directe'))
    provider = API_PROVIDERS.get(source)
    if provider is None:
        return False, f'Source « {source} » sans état de collecte connu'
    ok, reasons = status['providers'].get(provider, (False, [f'Aucune collecte {provider} disponible']))
    return ok, None if ok else '; '.join(reasons)[:300]


# --------------------------------------------------------------------------- dépôt
class Repository:
    def __init__(self, connect):
        self.connect = connect

    @staticmethod
    def _row(cursor, row):
        return {d[0]: v for d, v in zip(cursor.description, row)}

    def get(self, db, incident_id):
        cur = db.execute('SELECT * FROM incidents WHERE id=?', (incident_id,))
        row = cur.fetchone()
        return self._row(cur, row) if row else None

    @staticmethod
    def event(db, incident_id, at, kind, actor=None, actor_auth=None, **detail):
        db.execute('INSERT INTO incident_events(incident_id, at, kind, actor, actor_auth, detail) VALUES(?,?,?,?,?,?)',
                   (incident_id, _iso(at), kind, actor, actor_auth, json.dumps(detail, ensure_ascii=False) if detail else None))

    @staticmethod
    def update(db, incident_id, **fields):
        assignments = ', '.join(f'{k}=?' for k in fields)
        db.execute(f'UPDATE incidents SET {assignments} WHERE id=?', (*fields.values(), incident_id))


def _expire(db, repo, incident, at):
    """Fin d'une prise en charge ou d'une suppression temporaire : retour à l'état actif."""
    if incident['state'] in ('acknowledged', 'investigating') and incident['ack_until'] and _parse(incident['ack_until']) <= at:
        prior = incident['state']
        repo.update(db, incident['id'], state='reopened' if incident['reopen_count'] else 'open',
                    ack_until=None, updated_at=_iso(at))
        repo.event(db, incident['id'], at, 'investigation_expired' if prior == 'investigating' else 'ack_expired')
        return True
    if incident['state'] == 'suppressed' and incident['suppressed_until'] and _parse(incident['suppressed_until']) <= at:
        repo.update(db, incident['id'], state='reopened' if incident['reopen_count'] else 'open',
                    suppressed_until=None, updated_at=_iso(at))
        repo.event(db, incident['id'], at, 'suppression_expired')
        return True
    return False


def reconcile(db, observed: list, status: dict, at=None) -> dict:
    """Applique une collecte au journal. Idempotent : rejouer la même collecte ne change rien."""
    at = at or now_utc()
    repo = Repository(None)
    stamp = _iso(at)
    stats = {'opened': 0, 'reopened': 0, 'resolved': 0, 'blocked': 0, 'updated': 0, 'expired': 0}
    seen = set()
    for obs in observed:
        seen.add(obs['id'])
        current = repo.get(db, obs['id'])
        if current is None:
            db.execute('''INSERT INTO incidents(id, source, target, target_key, type, title, state, severity, severity_max,
                opened_at, first_observed_at, last_seen_at, evidence, observed_at, fresh, chronic, rule, link, updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                       (obs['id'], obs['source'], obs['target'], obs['target_key'], obs['type'], obs['title'], 'open',
                        obs['severity'], obs['severity'], stamp, obs.get('started_at'), stamp,
                        obs['evidence'], obs['observed_at'], None if obs['fresh'] is None else int(bool(obs['fresh'])),
                        int(obs['chronic']), obs['rule'], obs['link'], stamp))
            repo.event(db, obs['id'], at, 'opened', severity=obs['severity'], evidence=obs['evidence'])
            stats['opened'] += 1
            continue
        fields = {'last_seen_at': stamp, 'title': obs['title'], 'evidence': obs['evidence'], 'observed_at': obs['observed_at'],
                  **({'first_observed_at': obs['started_at']} if obs.get('started_at') else {}),
                  'fresh': None if obs['fresh'] is None else int(bool(obs['fresh'])), 'chronic': int(obs['chronic']),
                  'confirmation_blocked_since': None, 'confirmation_blocked_reason': None, 'updated_at': stamp}
        if current['state'] == 'resolved':
            fields.update(state='reopened', reopened_at=stamp, reopen_count=current['reopen_count'] + 1, resolved_at=None,
                          acknowledged_at=None, investigation_at=None, ack_until=None, owner=None, owner_auth=None)
            repo.event(db, obs['id'], at, 'reopened', severity=obs['severity'])
            stats['reopened'] += 1
        if obs['severity'] != current['severity']:
            fields['severity'] = obs['severity']
            if SEVERITY_RANK[obs['severity']] < SEVERITY_RANK[current['severity_max']]:
                fields['severity_max'] = obs['severity']
            repo.event(db, obs['id'], at, 'severity_changed', previous=current['severity'], severity=obs['severity'])
        repo.update(db, obs['id'], **fields)
        stats['updated'] += 1
    cur = db.execute(f"SELECT * FROM incidents WHERE state IN ({','.join('?' * len(ACTIVE))})", ACTIVE)
    for row in [Repository._row(cur, r) for r in cur.fetchall()]:
        if _expire(db, repo, row, at):
            stats['expired'] += 1
            row = repo.get(db, row['id'])
        if row['id'] in seen:
            continue
        ok, reason = can_confirm_absence(row, status)
        if ok:
            repo.update(db, row['id'], state='resolved', resolved_at=stamp, ack_until=None, suppressed_until=None,
                        confirmation_blocked_since=None, confirmation_blocked_reason=None, updated_at=stamp)
            repo.event(db, row['id'], at, 'resolved', reason='Absent d’une collecte complète de ' + row['source'])
            stats['resolved'] += 1
        else:
            if not row['confirmation_blocked_since']:
                repo.event(db, row['id'], at, 'resolution_blocked', reason=reason)
            repo.update(db, row['id'], confirmation_blocked_since=row['confirmation_blocked_since'] or stamp,
                        confirmation_blocked_reason=reason, updated_at=stamp)
            stats['blocked'] += 1
    return stats


def act(db, incident_id, action, actor, actor_auth, note='', duration=None, at=None) -> dict:
    """Actions locales : reconnaissance, investigation, suppression, réactivation."""
    at = at or now_utc()
    repo = Repository(None)
    incident = repo.get(db, incident_id)
    if incident is None:
        raise KeyError(incident_id)
    stamp = _iso(at)
    note = (note or '').strip()[:300]
    # Masquer sans motif rendait l'incident invisible sans trace de la raison (audit UI du
    # 31/10, fiche 02.2) : le motif est exigé, l'échéance l'était déjà.
    if action == 'suppress' and not note:
        raise ValueError('Motif requis pour masquer un incident')
    if action in ('ack', 'investigate', 'suppress'):
        if incident['state'] == 'resolved':
            raise ValueError('Incident résolu : rien à prendre en charge')
        if duration not in DURATIONS:
            raise ValueError('Durée attendue : 24h, 7d ou permanent')
        until = _iso(at + DURATIONS[duration]) if DURATIONS[duration] else None
        if action == 'ack':
            repo.update(db, incident_id, state='acknowledged', acknowledged_at=stamp, ack_until=until,
                        suppressed_until=None, suppressed_at=None, owner=actor, owner_auth=actor_auth, note=note, updated_at=stamp)
        elif action == 'investigate':
            repo.update(db, incident_id, state='investigating', investigation_at=stamp, acknowledged_at=incident['acknowledged_at'] or stamp,
                        ack_until=until, suppressed_until=None, suppressed_at=None, owner=actor, owner_auth=actor_auth,
                        note=note, updated_at=stamp)
        else:
            repo.update(db, incident_id, state='suppressed', suppressed_at=stamp, suppressed_until=until,
                        owner=actor, owner_auth=actor_auth, note=note, updated_at=stamp)
        repo.event(db, incident_id, at, 'investigation_started' if action == 'investigate' else action,
                   actor, actor_auth, duration=duration, until=until, note=note)
    elif action == 'reactivate':
        if incident['state'] not in ('acknowledged', 'investigating', 'suppressed'):
            raise ValueError('Seul un incident reconnu, en investigation ou supprimé peut être réactivé')
        repo.update(db, incident_id, state='reopened' if incident['reopen_count'] else 'open', ack_until=None,
                    suppressed_until=None, acknowledged_at=None, suppressed_at=None, owner=None, owner_auth=None,
                    note=None, updated_at=stamp)
        repo.event(db, incident_id, at, 'reactivated', actor, actor_auth, note=note)
    else:
        raise ValueError('Action inconnue')
    return repo.get(db, incident_id)


def maintenance_windows(db, at=None, include_future=True):
    """Return bounded current/future windows; maintenance annotates but never resolves."""
    at = at or now_utc()
    clause = 'ends_at>?' if include_future else 'starts_at<=? AND ends_at>?'
    args = (at.isoformat(),) if include_future else (at.isoformat(), at.isoformat())
    cur = db.execute(f'SELECT id,name,starts_at,ends_at,source,target,note,actor,actor_auth,created_at '
                     f'FROM maintenance_windows WHERE {clause} ORDER BY starts_at LIMIT 100', args)
    return [{'id': i, 'name': n, 'starts_at': start, 'ends_at': end, 'source': source, 'target': target,
             'note': note, 'actor': actor, 'actor_authenticated': auth == 'proxy', 'created_at': created,
             'active': bool((_parse(start) or at) <= at < (_parse(end) or at))}
            for i, n, start, end, source, target, note, actor, auth, created in cur.fetchall()]


def incident_maintenance(incident, windows):
    matches = []
    for window in windows:
        source_ok = not window.get('source') or window['source'] == incident.get('source')
        target = str(window.get('target') or '').lower()
        target_ok = not target or target in {str(incident.get('target') or '').lower(), str(incident.get('target_key') or '').lower()}
        if window.get('active') and source_ok and target_ok:
            matches.append(window)
    return matches[0] if matches else None


def present(row: dict, at=None) -> dict:
    """Vue API : durées calculées, lien décodé, états lisibles."""
    at = at or now_utc()
    tracked = _parse(row['opened_at'])
    declared = _parse(row.get('first_observed_at'))
    # « Depuis » : début déclaré par la source s'il est antérieur, sinon début du suivi par OpsControl.
    opened = declared if declared and tracked and declared < tracked else tracked
    out = dict(row)
    out.update(incident_timing.occurrence(row))
    out['recency'] = incident_timing.recency(out['event_at'], at)
    out['fresh'] = None if row['fresh'] is None else bool(row['fresh'])
    out['chronic'] = bool(row['chronic'])
    out['link'] = json.loads(row['link']) if row.get('link') else {}
    out['owner_authenticated'] = row.get('owner_auth') == 'proxy'
    end = _parse(row['resolved_at']) if row['state'] == 'resolved' else at
    out['duration_seconds'] = int((end - opened).total_seconds()) if opened and end else None
    out['confirmation_blocked'] = bool(row.get('confirmation_blocked_since'))
    return out


# --------------------------------------------------------------------------- API
class Action(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: str = Field(min_length=3, max_length=400)
    by: str = Field(default='', max_length=60)
    note: str = Field(default='', max_length=300)
    duration: str = Field(default='24h', pattern='^(24h|7d|permanent)$')


class Reactivate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: str = Field(min_length=3, max_length=400)
    by: str = Field(default='', max_length=60)
    note: str = Field(default='', max_length=300)


class Maintenance(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(min_length=3, max_length=120)
    starts_at: str = Field(min_length=10, max_length=40)
    ends_at: str = Field(min_length=10, max_length=40)
    source: str = Field(default='', max_length=60)
    target: str = Field(default='', max_length=200)
    note: str = Field(default='', max_length=300)
    by: str = Field(default='', max_length=60)


class MaintenanceDelete(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: int = Field(gt=0)
    by: str = Field(default='', max_length=60)


def install(app, context, start_thread=True):
    from fastapi import APIRouter
    router = APIRouter()
    import alert_center
    import operator_identity

    if not getattr(context, 'SCHEMA_DEFERRED', False):  # autre instance active : aucun DDL (OC-AUDIT-014)
        with context.connect() as db:
            migrate(db)
    lock = threading.Lock()
    last = {'at': None, 'stats': None, 'error': None, 'duration_ms': None}
    background = {'running': False}

    def sync(force=False):
        # Avec le fil de fond, une lecture n'attend jamais un rapprochement (sauf le tout premier) :
        # le journal a au plus 60 s de retard sur le centre d'alertes, et la réponse reste rapide.
        if not force and last['at'] and (background['running'] or
                                          (now_utc() - last['at']).total_seconds() < SYNC_MIN_SECONDS):
            return last
        with lock:
            if not force and last['at'] and (now_utc() - last['at']).total_seconds() < SYNC_MIN_SECONDS:
                return last
            at = now_utc()
            started = datetime.now(timezone.utc)
            try:
                built = alert_center.build(context, at, for_incidents=True)
                observed = observations(built['alerts'])
                status = source_status(built.get('sources'), context.rows(), built.get('probe'), at,
                                       built.get('batch_status'))
                with context.connect() as db:
                    stats = reconcile(db, observed, status, at)
                last.update(at=at, stats=stats, error=None,
                            duration_ms=int((datetime.now(timezone.utc) - started).total_seconds() * 1000))
            except Exception as exc:  # noqa: BLE001 — un échec de synchronisation ne résout ni ne ferme rien
                # Le détail (chemins, requêtes) reste dans le journal du service ; la réponse,
                # lisible par tout viewer, ne porte que la nature de l'erreur (audit SEC-06).
                logging.getLogger('opscontrol.incidents').exception('Rapprochement des incidents en échec')
                last.update(at=at, error=type(exc).__name__ + ' : détail dans le journal du service')
            return last

    context.sync_incidents = sync
    # Les lectures (GET) ne rapprochent plus : le journal avance par le fil de fond (60 s),
    # après chaque collecte (SSH, réseau, API) et sur demande explicite (POST /api/incidents/sync).
    hooks = getattr(context, 'collection_hooks', None)
    if isinstance(hooks, list):
        hooks.append(lambda kind: sync(force=True))

    # Le fil n'est plus lancé à l'import : il démarre dans le lifespan, APRÈS le verrou
    # d'instance, et s'arrête avec lui. Un second lancement refusé par le verrou n'écrit
    # donc plus d'incidents dans la base de l'instance active (audit BE-03).
    stop = threading.Event()

    def start_background():
        if not start_thread or background['running']:
            return False
        stop.clear()

        def loop():
            try:
                sync(force=True)  # premier rapprochement dès le démarrage
                while not stop.wait(60):
                    sync(force=True)
            finally:
                background['running'] = False
        background['running'] = True
        from jobs import spawn  # producteur enregistré : attendu à l'arrêt (OC-AUDIT-013)
        spawn(loop, name='incident-sync')
        return True

    def stop_background():
        stop.set()

    context.start_incident_sync = start_background
    context.stop_incident_sync = stop_background

    def sync_info():
        return {'at': _iso(last['at']), 'stats': last['stats'], 'error': last['error'], 'duration_ms': last['duration_ms'],
                'interval_seconds': 60 if background['running'] else None}

    context.incident_sync_info = sync_info  # lu par self_monitor (santé des collecteurs)

    @router.get('/api/incidents')
    def list_incidents(state: str = 'active', severity: str = '', source: str = '', q: str = '',
                       chronic: str = 'exclude', limit: int = 100, offset: int = 0, host: str = '',
                       alias: str = '', order: str = 'recent', age: str = 'all',
                       owner: str = '', evidence: str = 'all'):
        if order not in {'recent', 'oldest', 'severity', 'observed'}:
            raise HTTPException(422, 'Tri inconnu : recent, oldest, severity ou observed attendu.')
        if age not in {'all', 'recent', 'old', 'unknown'}:
            raise HTTPException(422, 'Ancienneté inconnue.')
        if evidence not in {'all', 'stale'}:
            raise HTTPException(422, 'Preuve attendue : all ou stale.')
        at = now_utc()
        limit, offset = max(1, min(limit, 500)), max(0, offset)
        where, args = [], []
        if state == 'active':
            where.append(f"state IN ({','.join('?' * len(ACTIVE))})")
            args += ACTIVE
        elif state in STATES:
            where.append('state=?')
            args.append(state)
        if severity in SEVERITIES:
            where.append('severity=?')
            args.append(severity)
        if source:
            where.append('source=?')
            args.append(source)
        # Vues enregistrées (audit UI du 31/10, fiche 02.1) : « sans responsable », « à moi »,
        # « preuve ancienne » ; mêmes filtres que les compteurs de la passation.
        if owner == '__none__':
            where.append("(owner IS NULL OR owner='')")
        elif owner:
            where.append('owner=?')
            args.append(owner[:120])
        if evidence == 'stale':
            where.append('fresh=0')
        # Chroniques (déclencheurs Zabbix ouverts depuis plus de 30 jours) : exclues par défaut, jamais masquées du total.
        if chronic == 'exclude':
            where.append('chronic=0')
        elif chronic == 'only':
            where.append('chronic=1')
        if q:
            where.append('(title LIKE ? OR target LIKE ? OR type LIKE ?)')
            args += [f'%{q[:100]}%'] * 3
        if host:
            # Fiche serveur : par clé, par nom, ou par FQDN quand la source (Zabbix) ne
            # connaît pas la clé d'inventaire (reclabswr04.host.example.test -> reclabswr04).
            names = {host[:200].lower()}
            rows = context.rows() if hasattr(context, 'rows') else []
            row = next((h for h in rows if h.get('key') == host), None)
            if row and row.get('name'):
                names.add(str(row['name']).lower())
            # Noms du même serveur dans les sources, rapprochés par IP sur la fiche (ex. hôte
            # Zabbix prdlabsci01 pour « Data Sience ») : simple filtre de lecture, borné.
            names |= {a.strip().lower()[:200] for a in alias.split(',')[:10] if a.strip()}
            marks = ','.join('?' * len(names))
            where.append(f"(lower(target_key) IN ({marks}) OR lower(target) IN ({marks})"
                         + " OR lower(target) LIKE ? ESCAPE '!'" * len(names) + ')')
            args += [*names, *names,
                     *(n.replace('!', '!!').replace('%', '!%').replace('_', '!_') + '.%' for n in names)]
        base_clause = ('WHERE ' + ' AND '.join(where)) if where else ''
        now_jd = at.timestamp() / 86400 + 2440587.5
        age_conditions = {
            'recent': f'{EVENT_SQL} BETWEEN ? AND ?',
            'old': f'{EVENT_SQL} < ?',
            'unknown': f'({EVENT_SQL} IS NULL OR {EVENT_SQL} > ?)',
        }
        age_args = {'recent': [now_jd - 1, now_jd], 'old': [now_jd - 1], 'unknown': [now_jd]}
        base_args = list(args)
        if age != 'all':
            where.append(age_conditions[age])
            args += age_args[age]
        clause = ('WHERE ' + ' AND '.join(where)) if where else ''
        ranking = {
            'recent': f'{EVENT_SQL} DESC',
            'oldest': f'{EVENT_SQL} IS NULL, {EVENT_SQL} ASC',
            'severity': ("CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 "
                         f"WHEN 'preventive' THEN 2 ELSE 3 END, {EVENT_SQL} DESC"),
            'observed': f'julianday(observed_at) DESC, {EVENT_SQL} DESC',
        }
        # Liste fermée et identifiant final : tri stable avant LIMIT/OFFSET, même à date égale.
        ordering = 'ORDER BY ' + ranking[order] + ', id ASC'
        with context.connect() as db:
            recency_counts = {k: db.execute(f'SELECT count(*) FROM incidents {base_clause}'
                                            + (' AND ' if base_clause else ' WHERE ') + cond,
                                            (*base_args, *age_args[k])).fetchone()[0]
                              for k, cond in age_conditions.items()}
            cur = db.execute(f'SELECT * FROM incidents {clause} {ordering} LIMIT ? OFFSET ?', (*args, limit, offset))
            items = [present(Repository._row(cur, r), at) for r in cur.fetchall()]
            total = db.execute(f'SELECT count(*) FROM incidents {clause}', args).fetchone()[0]
            counts = dict(db.execute('SELECT state, count(*) FROM incidents GROUP BY state').fetchall())
            active_windows = maintenance_windows(db, at, include_future=False)
            actionable_cur = db.execute("SELECT * FROM incidents WHERE chronic=0 AND state IN ('open','reopened','acknowledged','investigating')")
            actionable = [Repository._row(actionable_cur, row) for row in actionable_cur.fetchall()]
            by_severity = {}
            for incident in actionable:
                if not incident_maintenance(incident, active_windows):
                    by_severity[incident['severity']] = by_severity.get(incident['severity'], 0) + 1
            sources = [r[0] for r in db.execute('SELECT DISTINCT source FROM incidents ORDER BY source')]
            chronic_active = db.execute(f"SELECT count(*) FROM incidents WHERE chronic=1 AND state IN ({','.join('?' * len(ACTIVE))})", ACTIVE).fetchone()[0]
        for item in items:
            item['maintenance'] = incident_maintenance(item, active_windows)
        return {'items': items, 'total': total, 'limit': limit, 'offset': offset, 'order': order,
                'age': age, 'recency_counts': recency_counts,
                'counts': {s: counts.get(s, 0) for s in STATES}, 'active_by_severity': by_severity,
                'sources': sources, 'chronic_active': chronic_active, 'maintenance_active': len(active_windows), 'sync': sync_info(),
                'policy': 'Résolution seulement si la source a réalisé une collecte complète et récente sans l’observer. '
                          'Une suppression ou une maintenance réduit le bruit sans résoudre l’incident.'}

    @router.get('/api/incidents/events')
    def incident_events(id: str, limit: int = 100):
        with context.connect() as db:
            if Repository(None).get(db, id) is None:
                raise HTTPException(404, 'Incident inconnu')
            rows = db.execute('SELECT at, kind, actor, actor_auth, detail FROM incident_events WHERE incident_id=? '
                              'ORDER BY seq DESC LIMIT ?', (id, max(1, min(limit, 500)))).fetchall()
        return {'id': id, 'events': [{'at': a, 'kind': k, 'actor': u, 'actor_authenticated': m == 'proxy',
                                      'detail': json.loads(d) if d else {}} for a, k, u, m, d in rows]}

    @router.get('/api/incidents/suppressions')
    def suppressions():
        at = now_utc()
        with context.connect() as db:
            cur = db.execute("SELECT * FROM incidents WHERE state='suppressed' ORDER BY suppressed_until IS NOT NULL, suppressed_until")
            return {'items': [present(Repository._row(cur, r), at) for r in cur.fetchall()]}

    def perform(request, action, body, duration=None):
        actor, mode = operator_identity.actor(request.headers, body.by)
        if not actor:
            raise HTTPException(422, 'Nom requis en mode local non authentifié')
        with context.connect() as db:
            try:
                return present(act(db, body.id, action, actor, mode, body.note, duration))
            except KeyError:
                raise HTTPException(404, 'Incident inconnu') from None
            except ValueError as exc:
                raise HTTPException(409, str(exc)) from None

    @router.post('/api/incidents/ack')
    def acknowledge(body: Action, request: Request):
        return perform(request, 'ack', body, body.duration)

    @router.post('/api/incidents/investigate')
    def investigate(body: Action, request: Request):
        return perform(request, 'investigate', body, body.duration)

    @router.post('/api/incidents/suppress')
    def suppress(body: Action, request: Request):
        return perform(request, 'suppress', body, body.duration)

    @router.post('/api/incidents/reactivate')
    def reactivate(body: Reactivate, request: Request):
        return perform(request, 'reactivate', body)

    @router.get('/api/incidents/maintenance')
    def list_maintenance():
        at = now_utc()
        with context.connect() as db:
            rows = maintenance_windows(db, at)
        return {'items': rows, 'active': sum(row['active'] for row in rows),
                'policy': 'Une maintenance réduit le bruit opérationnel ; elle ne masque pas les preuves et ne résout aucun incident.'}

    @router.post('/api/incidents/maintenance')
    def create_maintenance(body: Maintenance, request: Request):
        actor, mode = operator_identity.actor(request.headers, body.by)
        if not actor:
            raise HTTPException(422, 'Nom requis en mode local non authentifié')
        try:
            raw_start, raw_end = datetime.fromisoformat(body.starts_at), datetime.fromisoformat(body.ends_at)
        except ValueError:
            raw_start = raw_end = None
        if not raw_start or not raw_end or raw_start.utcoffset() is None or raw_end.utcoffset() is None:
            raise HTTPException(422, 'Dates ISO avec fuseau horaire requises')
        start, end, current = raw_start.astimezone(timezone.utc), raw_end.astimezone(timezone.utc), now_utc()
        if end <= start or end - start > timedelta(days=30):
            raise HTTPException(422, 'La fin doit suivre le début, pour une durée maximale de 30 jours')
        if end <= current:
            raise HTTPException(422, 'La fin de la maintenance doit être dans le futur')
        with context.connect() as db:
            cur = db.execute('INSERT INTO maintenance_windows(name,starts_at,ends_at,source,target,note,actor,actor_auth,created_at) '
                             'VALUES(?,?,?,?,?,?,?,?,?)', (body.name.strip(), _iso(start), _iso(end), body.source.strip() or None,
                             body.target.strip() or None, body.note.strip(), actor, mode, _iso(now_utc())))
            ident = cur.lastrowid
            return next(row for row in maintenance_windows(db, current) if row['id'] == ident)

    @router.post('/api/incidents/maintenance/delete')
    def delete_maintenance(body: MaintenanceDelete, request: Request):
        actor, _ = operator_identity.actor(request.headers, body.by)
        if not actor:
            raise HTTPException(422, 'Nom requis en mode local non authentifié')
        with context.connect() as db:
            cur = db.execute('DELETE FROM maintenance_windows WHERE id=?', (body.id,))
            if not cur.rowcount:
                raise HTTPException(404, 'Fenêtre de maintenance inconnue')
        return {'id': body.id, 'deleted': True, 'by': actor}

    @router.post('/api/incidents/sync')
    def force_sync():
        """Rejoue le rapprochement local sur les dernières collectes ; aucune collecte distante."""
        sync(force=True)
        return sync_info()
    app.include_router(router)  # routes de ce module : APIRouter, inclus en fin d'installation
