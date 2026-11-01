"""Rétention des données locales (lot 7) : purge horaire, règles explicites et bornées.

Déjà bornées ailleurs : history (100 par serveur), audit_snapshots (20 + 1/h sur 7 jours,
purgés à chaque audit du serveur), apache_samples (7 jours), alert_acks expirées,
mutation_audit (90 jours). Ici, ce qui grossissait sans limite :

- incidents résolus depuis plus de INCIDENT_DAYS (180 j par défaut) et leurs événements ;
  un incident ouvert, réapparu, pris en charge, en investigation ou supprimé n'est jamais purgé ;
- événements d'un même incident au-delà des EVENTS_PER_INCIDENT plus récents ;
- fenêtres de maintenance terminées depuis plus de MAINTENANCE_DAYS ;
- instantanés et historique des serveurs retirés de l'inventaire depuis plus de ORPHAN_DAYS
  (les serveurs de l'inventaire gardent leurs règles propres).

Les états courants (states, network, batch_states) et les inscriptions durables
(registered_assets) ne sont pas purgés : bornés par l'inventaire, ils restituent le dernier
état connu si un serveur revient. Aucune donnée distante n'est touchée.
"""
from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone


def _days(name, default):
    try:
        value = int(os.environ.get(name, default))
    except ValueError:
        value = default
    return max(1, value)


def policy():
    return {'incident_days': _days('INFRAOPS_INCIDENT_RETENTION_DAYS', 180),
            'events_per_incident': _days('INFRAOPS_INCIDENT_EVENTS_MAX', 500),
            'maintenance_days': _days('INFRAOPS_MAINTENANCE_RETENTION_DAYS', 90),
            'orphan_days': _days('INFRAOPS_ORPHAN_RETENTION_DAYS', 30),
            'discovery_days': _days('INFRAOPS_DISCOVERY_RETENTION_DAYS', 30),
            'waf_ban_days': _days('INFRAOPS_WAF_BAN_RETENTION_DAYS', 30)}


# --- Allègement des anciens audits ---------------------------------------------------
# audit_snapshots pesait 85 % de la base (70 Mo pour 88 serveurs, 14 Ko par audit) et
# relire tout l'historique prenait ~16 s (mesuré le 06/10). Au-delà des FULL_SNAPSHOTS
# plus récents de chaque serveur (fiche, versions consultables, alertes serveur), les
# lecteurs n'utilisent que ces champs : tendances (observability), CPU soutenu et
# remplissage des disques (alert_center), changements de services et de configuration.
FULL_SNAPSHOTS = 20
SLIM_BATCH = 5000
SLIM_STEP = 200   # audits allégés par transaction
SLIM_MARK = '_slim'


def slim_snapshot(payload: dict) -> dict:
    """Projection conservée pour un audit ancien (aucun champ inventé)."""
    out = {k: payload[k] for k in ('collected_at', 'status', 'cpu', 'ram', 'disk_max', 'fingerprint') if k in payload}
    services = payload.get('all_services', payload.get('service_states'))
    if isinstance(services, list):
        out['service_states'] = [{'name': s['name'], 'status': s['status']} for s in services
                                 if isinstance(s, dict) and s.get('name') and s.get('status')]
    storage = payload.get('storage')
    if isinstance(storage, dict) and isinstance(storage.get('filesystems'), list):
        out['storage'] = {'filesystems': [{k: f.get(k) for k in ('mount', 'used_kb', 'total_kb')}
                                          for f in storage['filesystems'] if isinstance(f, dict)]}
    out[SLIM_MARK] = True
    return out


def _has_slim_flag(db) -> bool:
    return 'slim' in {row[1] for row in db.execute('PRAGMA table_info(audit_snapshots)')}


def slim_snapshots(db: sqlite3.Connection, keep: int = FULL_SNAPSHOTS, limit: int | None = SLIM_BATCH) -> int:
    """Allège les audits au-delà des `keep` plus récents de chaque serveur ; borné par `limit`.

    Avec la colonne `slim` (migration core_v8), la sélection ne lit que (key, ts) par l'index
    au lieu de parcourir tous les payloads (~70 Mo) à chaque passage (audit DB-03)."""
    import json
    if not _table(db, 'audit_snapshots'):
        return 0
    flag = _has_slim_flag(db)
    if flag:
        query = ('SELECT key, ts FROM (SELECT key, ts, slim, ROW_NUMBER() OVER '
                 '(PARTITION BY key ORDER BY ts DESC) AS rang FROM audit_snapshots) WHERE rang > ? AND slim = 0')
    else:
        query = ('SELECT key, ts FROM (SELECT key, ts, payload, ROW_NUMBER() OVER '
                 '(PARTITION BY key ORDER BY ts DESC) AS rang FROM audit_snapshots) '
                 "WHERE rang > ? AND instr(payload, '\"" + SLIM_MARK + "\"') = 0")
    rows = db.execute(query + (' LIMIT ?' if limit else ''), (keep, limit) if limit else (keep,)).fetchall()
    done = 0
    for key, ts in rows:
        found = db.execute('SELECT payload FROM audit_snapshots WHERE key=? AND ts=?', (key, ts)).fetchone()
        try:
            parsed = json.loads(found[0]) if found else None
        except ValueError:
            parsed = None
        if not isinstance(parsed, dict):
            if flag:   # illisible : ne plus le reproposer à chaque passage
                db.execute('UPDATE audit_snapshots SET slim=1 WHERE key=? AND ts=?', (key, ts))
            continue
        if flag:
            db.execute('UPDATE audit_snapshots SET payload=?, slim=1 WHERE key=? AND ts=?',
                       (json.dumps(slim_snapshot(parsed)), key, ts))
        else:
            db.execute('UPDATE audit_snapshots SET payload=? WHERE key=? AND ts=?',
                       (json.dumps(slim_snapshot(parsed)), key, ts))
        done += 1
    return done


def slim_in_batches(connect, batch: int = SLIM_STEP, max_batches: int = SLIM_BATCH // SLIM_STEP) -> int:
    """Allègement par lots courts, chacun dans sa propre transaction : le verrou d'écriture
    n'est plus tenu pendant tout le passage, et les collectes s'intercalent (audit DB-03)."""
    total = 0
    for _ in range(max_batches):
        with connect() as db:
            done = slim_snapshots(db, limit=batch)
        total += done
        if done < batch:
            break
    return total


def _table(db, name):
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def sweep(db: sqlite3.Connection, inventory_keys, now=None, rules=None, slim=True) -> dict:
    """Purge selon les règles ; renvoie le nombre de lignes supprimées par catégorie.

    `slim=False` : l'allègement est fait à part, par lots courts (slim_in_batches)."""
    now = now or datetime.now(timezone.utc)
    rules = rules or policy()
    counts = {}
    iso = lambda days: (now - timedelta(days=days)).isoformat()
    if _table(db, 'waf_ban_history'):
        counts['waf_ban_history'] = db.execute('DELETE FROM waf_ban_history WHERE last_seen < ?',
                                             (iso(rules.get('waf_ban_days', 30)),)).rowcount
        counts['waf_ban_sources'] = db.execute('DELETE FROM waf_ban_sources WHERE last_at < ?',
                                             (iso(rules.get('waf_ban_days', 30)),)).rowcount
    if _table(db, 'discovery_scans'):
        cutoff = iso(rules.get('discovery_days', 30))
        # Supprimer les enfants explicitement : toutes les connexions historiques n’activent pas les FK.
        counts['discovery_hosts'] = db.execute(
            'DELETE FROM discovery_hosts WHERE scan IN (SELECT id FROM discovery_scans WHERE at < ?)',
            (cutoff,)).rowcount
        counts['discovery_scans'] = db.execute('DELETE FROM discovery_scans WHERE at < ?', (cutoff,)).rowcount
    if _table(db, 'incidents'):
        cutoff = iso(rules['incident_days'])
        old = "SELECT id FROM incidents WHERE state='resolved' AND resolved_at IS NOT NULL AND resolved_at < ?"
        if _table(db, 'incident_events'):
            counts['incident_events_of_purged'] = db.execute(f'DELETE FROM incident_events WHERE incident_id IN ({old})', (cutoff,)).rowcount
        counts['incidents_resolved'] = db.execute(old.replace('SELECT id FROM', 'DELETE FROM'), (cutoff,)).rowcount
    if _table(db, 'incident_events'):
        counts['incident_events_capped'] = db.execute(
            'DELETE FROM incident_events WHERE seq IN (SELECT seq FROM (SELECT seq, ROW_NUMBER() OVER '
            '(PARTITION BY incident_id ORDER BY seq DESC) AS rang FROM incident_events) WHERE rang > ?)',
            (rules['events_per_incident'],)).rowcount
    if _table(db, 'alert_acks'):   # prises en charge expirées : purgées même sans nouvel acquittement
        counts['alert_acks_expired'] = db.execute('DELETE FROM alert_acks WHERE until <= ?', (now.isoformat(),)).rowcount
    if _table(db, 'maintenance_windows'):
        counts['maintenance_ended'] = db.execute('DELETE FROM maintenance_windows WHERE ends_at < ?', (iso(rules['maintenance_days']),)).rowcount
    keys = sorted({str(k) for k in inventory_keys})
    if keys:   # inventaire vide (lecture ratée) : on ne purge aucun serveur « orphelin »
        db.execute('CREATE TEMP TABLE IF NOT EXISTS retention_inventory(key TEXT PRIMARY KEY)')
        db.execute('DELETE FROM retention_inventory')
        db.executemany('INSERT INTO retention_inventory(key) VALUES(?)', [(k,) for k in keys])
        cutoff = iso(rules['orphan_days'])
        for table in ('audit_snapshots', 'history', 'apache_samples'):
            if _table(db, table):
                counts[table + '_orphans'] = db.execute(
                    f'DELETE FROM {table} WHERE ts < ? AND key NOT IN (SELECT key FROM retention_inventory)', (cutoff,)).rowcount
        if _table(db, 'batch_states'):   # pas d'horodatage : un état batch suit son serveur (DB-05)
            counts['batch_states_orphans'] = db.execute(
                'DELETE FROM batch_states WHERE key NOT IN (SELECT key FROM retention_inventory)').rowcount
        db.execute('DELETE FROM retention_inventory')
    if _table(db, 'audit_snapshots') and slim:
        counts['audit_snapshots_slimmed'] = slim_snapshots(db)
    return counts


def reclaim(db: sqlite3.Connection, pages: int = 4096) -> int:
    """Rend au système l'espace libéré, si la base est en auto_vacuum INCREMENTAL.

    Le mode s'active une fois, service arrêté : deploy/maintenance.py vacuum. Avant, la
    base ne rétrécit pas (pages libres réutilisées). Renvoie le nombre de pages libres restantes."""
    if db.execute('PRAGMA auto_vacuum').fetchone()[0] != 2:
        return 0
    db.execute(f'PRAGMA incremental_vacuum({int(pages)})').fetchall()
    return db.execute('PRAGMA freelist_count').fetchone()[0]
