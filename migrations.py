"""Migrations de schéma versionnées (lot 7).

Chaque migration a un nom unique, s'exécute une seule fois et est enregistrée dans
schema_migrations (table déjà utilisée par access_policy et incident_center, même format).
Une migration et son enregistrement forment une seule transaction : en cas d'échec, rien
n'est appliqué ni enregistré, et le démarrage s'arrête avec un message clair.

Les modules qui gèrent leur propre schéma (incident_center, access_policy, alert_center,
apache_health, batch_monitor) gardent leurs migrations ; celles du cœur sont ici, au lieu
d'instructions CREATE exécutées à chaque démarrage dans app.py.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

SCHEMA_TABLE = 'CREATE TABLE IF NOT EXISTS schema_migrations(name TEXT PRIMARY KEY, applied_at TEXT)'


def core_v1_tables(db):
    """Tables historiques du cœur (identiques au schéma créé auparavant par app.py)."""
    db.execute('CREATE TABLE IF NOT EXISTS states(key TEXT PRIMARY KEY, ip TEXT, payload TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT, ts TEXT, status TEXT, summary TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS network(key TEXT PRIMARY KEY, ip TEXT, payload TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS settings(name TEXT PRIMARY KEY, value TEXT)')
    db.execute('CREATE TABLE IF NOT EXISTS audit_snapshots(key TEXT, ts TEXT, payload TEXT, PRIMARY KEY(key,ts))')
    # Purge et fiche serveur filtrent l'historique par clé : sans index, balayage complet à chaque audit.
    db.execute('CREATE INDEX IF NOT EXISTS history_key ON history(key,id)')


def core_v2_snapshot_backfill(db):
    """Une fois : verse les derniers audits enregistrés dans audit_snapshots (bases antérieures).

    S'exécutait auparavant à chaque démarrage et relisait tous les audits.
    """
    for key, payload in db.execute('SELECT key,payload FROM states').fetchall():
        try:
            recorded = json.loads(payload)
        except (TypeError, ValueError):
            continue
        if isinstance(recorded, dict) and recorded.get('collected_at'):
            db.execute('INSERT OR IGNORE INTO audit_snapshots(key, ts, payload) VALUES(?,?,?)', (key, recorded['collected_at'], payload))


def core_v3_retention_indexes(db):
    """Index des requêtes de rétention (retention.py) : purges sans balayage complet."""
    db.execute('CREATE INDEX IF NOT EXISTS audit_snapshots_ts ON audit_snapshots(ts)')
    db.execute('CREATE INDEX IF NOT EXISTS history_ts ON history(ts)')


# Tables des modules, autrefois créées à l'installation du module ou à chaque appel (dont
# une route GET pour apache_samples). Définitions UNIQUES, réutilisées par ces modules
# là où ils doivent encore garantir la table (écritures après collecte, bases de test).
MODULE_TABLES = {
    'registered_assets': 'CREATE TABLE IF NOT EXISTS registered_assets(key TEXT PRIMARY KEY, ip TEXT, first_seen TEXT)',
    'batch_states': 'CREATE TABLE IF NOT EXISTS batch_states(key TEXT PRIMARY KEY, ip TEXT, payload TEXT)',
    'apache_samples': 'CREATE TABLE IF NOT EXISTS apache_samples(key TEXT, ts TEXT, payload TEXT, PRIMARY KEY(key, ts))',
    'alert_acks': ("CREATE TABLE IF NOT EXISTS alert_acks(id TEXT PRIMARY KEY, count INTEGER, by TEXT, note TEXT, "
                   "at TEXT, until TEXT, auth TEXT NOT NULL DEFAULT 'local')"),
}


def core_v4_module_tables(db):
    """Tables des modules alertes, batchs, santé Apache et inscriptions, en une migration.

    Bases existantes : CREATE IF NOT EXISTS ne touche pas aux tables présentes ; la colonne
    alert_acks.auth (ajoutée auparavant par alert_center à chaque démarrage) est ajoutée
    si elle manque, les prises en charge existantes restant « local »."""
    for ddl in MODULE_TABLES.values():
        db.execute(ddl)
    if 'auth' not in {row[1] for row in db.execute('PRAGMA table_info(alert_acks)')}:
        db.execute("ALTER TABLE alert_acks ADD COLUMN auth TEXT NOT NULL DEFAULT 'local'")


def core_v5_discovery(db):
    """Historique local des scans manuels ; garder les scans interrompus séparément."""
    db.execute('CREATE TABLE discovery_scans(id INTEGER PRIMARY KEY AUTOINCREMENT, '
               'range TEXT NOT NULL, at TEXT NOT NULL, duration_s REAL NOT NULL, '
               'status TEXT NOT NULL, error TEXT)')
    db.execute('CREATE TABLE discovery_hosts(scan INTEGER NOT NULL REFERENCES discovery_scans(id) '
               'ON DELETE CASCADE, ip TEXT NOT NULL, ports TEXT NOT NULL, ttl INTEGER, '
               'banner TEXT, dns TEXT, type TEXT, os TEXT, ping INTEGER, ssh_port INTEGER, '
               'PRIMARY KEY(scan, ip))')
    db.execute('CREATE INDEX discovery_scans_at ON discovery_scans(at)')
    db.execute('CREATE INDEX discovery_scans_range ON discovery_scans(range, status, id)')


def core_v6_waf_bans(db):
    """Chronologie observée par WAF et IP ; ne pas mélanger deux adresses de WAF."""
    db.execute('CREATE TABLE waf_ban_history(host_key TEXT, host_ip TEXT, ip TEXT, '
               'first_seen TEXT, last_seen TEXT, current_since TEXT, ban_epoch TEXT, '
               'active INTEGER, rebans INTEGER NOT NULL DEFAULT 0, '
               'PRIMARY KEY(host_key,host_ip,ip))')
    db.execute('CREATE TABLE waf_ban_sources(host_key TEXT, host_ip TEXT, last_at TEXT, '
               'PRIMARY KEY(host_key,host_ip))')
    db.execute('CREATE INDEX waf_ban_history_last_seen ON waf_ban_history(last_seen)')


def core_v7_ack_targets(db):
    """Cibles couvertes par une prise en charge : une NOUVELLE cible sur la même cause doit
    réapparaître même si le nombre de cibles est inchangé (audit SUP-11)."""
    if 'targets' not in {row[1] for row in db.execute('PRAGMA table_info(alert_acks)')}:
        db.execute('ALTER TABLE alert_acks ADD COLUMN targets TEXT')


def core_v8_snapshot_slim_flag(db):
    """Marqueur d'allègement indexé : la rétention choisit les audits à alléger sans relire
    tous les payloads (audit DB-03). Rétroremplissage unique des audits déjà allégés."""
    if 'slim' not in {row[1] for row in db.execute('PRAGMA table_info(audit_snapshots)')}:
        db.execute('ALTER TABLE audit_snapshots ADD COLUMN slim INTEGER NOT NULL DEFAULT 0')
    db.execute("UPDATE audit_snapshots SET slim=1 WHERE instr(payload, '\"_slim\"') > 0")
    db.execute('CREATE INDEX IF NOT EXISTS audit_snapshots_slim ON audit_snapshots(slim, key, ts)')


MIGRATIONS = [
    ('core_v1_tables', core_v1_tables),
    ('core_v2_snapshot_backfill', core_v2_snapshot_backfill),
    ('core_v3_retention_indexes', core_v3_retention_indexes),
    ('core_v4_module_tables', core_v4_module_tables),
    ('core_v5_discovery', core_v5_discovery),
    ('core_v6_waf_bans', core_v6_waf_bans),
    ('core_v7_ack_targets', core_v7_ack_targets),
    ('core_v8_snapshot_slim_flag', core_v8_snapshot_slim_flag),
]


class MigrationError(RuntimeError):
    pass


def applied(db) -> dict:
    db.execute(SCHEMA_TABLE)
    return dict(db.execute('SELECT name, applied_at FROM schema_migrations').fetchall())


def apply(db: sqlite3.Connection, migrations=MIGRATIONS, now=None) -> list[str]:
    """Applique, dans l'ordre, les migrations absentes ; renvoie leurs noms."""
    names = [name for name, _ in migrations]
    if len(names) != len(set(names)):
        raise MigrationError('Nom de migration dupliqué')
    if db.in_transaction:
        db.commit()
    done = applied(db)
    db.commit()
    # Base migrée par une version plus récente (retour arrière de release sans restauration) :
    # ce code ne connaît pas son schéma et l'écrirait de travers. Arrêt explicite (audit DB-04).
    newer = sorted(n for n in done if n.startswith('core_') and n not in names)
    if newer and migrations is MIGRATIONS:
        raise MigrationError('Base migrée par une version plus récente d’OpsControl (' + ', '.join(newer) + ') : '
                             'restaurer la sauvegarde « pre-<release> » (docs/RESTORE.md) ou redéployer cette version.')
    ran = []
    for name, migration in migrations:
        if name in done:
            continue
        stamp = (now or datetime.now(timezone.utc)).isoformat()
        try:
            db.execute('BEGIN')
            migration(db)
            db.execute('INSERT INTO schema_migrations(name, applied_at) VALUES(?,?)', (name, stamp))
            db.commit()
        except Exception as exc:
            db.rollback()
            raise MigrationError(f'Migration « {name} » interrompue : {type(exc).__name__} : {exc}') from exc
        ran.append(name)
    return ran


def status(db) -> list[dict]:
    """Migrations connues et appliquées (pour la supervision d'OpsControl)."""
    done = applied(db)
    known = [{'name': name, 'applied_at': done.get(name), 'core': True} for name, _ in MIGRATIONS]
    others = [{'name': name, 'applied_at': at, 'core': False} for name, at in sorted(done.items()) if name not in dict(MIGRATIONS)]
    return known + others
