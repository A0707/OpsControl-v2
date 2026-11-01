"""Lot 7 : migrations versionnées et rétention bornée (bases SQLite temporaires uniquement)."""
import json
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone

import migrations
import retention

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)
iso = lambda **delta: (NOW - timedelta(**delta)).isoformat()


def tables(db):
    return {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type IN ('table','index')")}


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')

    def tearDown(self):
        self.db.close()

    def test_fresh_database_gets_every_core_migration_once(self):
        ran = migrations.apply(self.db, now=NOW)
        self.assertEqual(ran, [name for name, _ in migrations.MIGRATIONS])
        self.assertTrue({'states', 'history', 'network', 'settings', 'audit_snapshots', 'history_key',
                         'audit_snapshots_ts', 'history_ts', 'schema_migrations'} <= tables(self.db))
        self.assertEqual(migrations.apply(self.db), [], 'idempotent : rien à rejouer')
        self.assertEqual(self.db.execute('SELECT count(*) FROM schema_migrations').fetchone()[0], len(migrations.MIGRATIONS))

    def test_legacy_database_upgrades_and_backfills_once(self):
        # Base antérieure : tables créées par l'ancien app.py, aucune trace de migration.
        self.db.execute('CREATE TABLE states(key TEXT PRIMARY KEY, ip TEXT, payload TEXT)')
        self.db.execute('CREATE TABLE audit_snapshots(key TEXT, ts TEXT, payload TEXT, PRIMARY KEY(key,ts))')
        self.db.execute("INSERT INTO states VALUES('a','192.0.2.1',?)", (json.dumps({'collected_at': iso(hours=1), 'status': 'ok'}),))
        self.db.execute("INSERT INTO states VALUES('b','192.0.2.2','pas du json')")
        self.db.commit()
        migrations.apply(self.db, now=NOW)
        self.assertEqual(self.db.execute('SELECT key FROM audit_snapshots').fetchall(), [('a',)])
        self.db.execute('DELETE FROM audit_snapshots'); self.db.commit()
        migrations.apply(self.db)
        self.assertEqual(self.db.execute('SELECT count(*) FROM audit_snapshots').fetchone()[0], 0, 'rattrapage exécuté une seule fois')

    def test_failed_migration_is_rolled_back_and_not_recorded(self):
        def broken(db):
            db.execute('CREATE TABLE partielle(x)')
            raise RuntimeError('panne simulée')
        with self.assertRaises(migrations.MigrationError) as caught:
            migrations.apply(self.db, migrations=[('ok_v1', lambda db: db.execute('CREATE TABLE t1(x)')), ('ko_v2', broken)])
        self.assertIn('ko_v2', str(caught.exception))
        self.assertIn('t1', tables(self.db))
        self.assertNotIn('partielle', tables(self.db), 'DDL de la migration en échec annulé')
        self.assertEqual([r[0] for r in self.db.execute('SELECT name FROM schema_migrations')], ['ok_v1'])

    def test_existing_module_migrations_are_preserved(self):
        migrations.applied(self.db)
        self.db.execute("INSERT INTO schema_migrations VALUES('incidents_v1','2026-09-29')"); self.db.commit()
        migrations.apply(self.db)
        names = {m['name']: m for m in migrations.status(self.db)}
        self.assertFalse(names['incidents_v1']['core'])
        self.assertTrue(all(names[n]['applied_at'] for n, _ in migrations.MIGRATIONS))

    def test_base_d_une_version_plus_recente_refusee(self):
        # Audit DB-04 : retour arrière de release sans restauration.
        migrations.apply(self.db)
        self.db.execute("INSERT INTO schema_migrations(name, applied_at) VALUES('core_v99_futur','2026-12-01')")
        self.db.commit()
        with self.assertRaises(migrations.MigrationError) as e:
            migrations.apply(self.db)
        self.assertIn('core_v99_futur', str(e.exception))

    def test_duplicate_names_refused(self):
        with self.assertRaises(migrations.MigrationError):
            migrations.apply(self.db, migrations=[('x', lambda db: None), ('x', lambda db: None)])


class RetentionTests(unittest.TestCase):
    RULES = {'incident_days': 180, 'events_per_incident': 3, 'maintenance_days': 90, 'orphan_days': 30}

    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        migrations.apply(self.db)
        self.addCleanup(self.db.close)
        d = self.db
        d.execute('CREATE TABLE incidents(id TEXT PRIMARY KEY, state TEXT, resolved_at TEXT)')
        d.execute('CREATE TABLE incident_events(seq INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT, at TEXT, kind TEXT)')
        d.execute('CREATE TABLE maintenance_windows(id INTEGER PRIMARY KEY, ends_at TEXT)')
        rows = [('vieux-résolu', 'resolved', iso(days=200)), ('récent-résolu', 'resolved', iso(days=10)),
                ('vieux-ouvert', 'open', None), ('vieux-réapparu', 'reopened', iso(days=400)), ('pris', 'acknowledged', iso(days=300))]
        d.executemany('INSERT INTO incidents VALUES(?,?,?)', rows)
        for incident, *_ in rows:
            # seq croît avec le temps (insertion chronologique, comme en exploitation).
            d.executemany('INSERT INTO incident_events(incident_id, at, kind) VALUES(?,?,?)', [(incident, iso(days=k), 'e') for k in range(4, -1, -1)])
        d.executemany('INSERT INTO maintenance_windows VALUES(?,?)', [(1, iso(days=100)), (2, iso(days=5)), (3, (NOW + timedelta(days=1)).isoformat())])
        for key in ('srv-inventaire', 'srv-retiré'):
            d.executemany('INSERT INTO audit_snapshots(key, ts, payload) VALUES(?,?,?)', [(key, iso(days=k), '{}') for k in (1, 40, 90)])
            d.executemany('INSERT INTO history(key, ts, status, summary) VALUES(?,?,?,?)', [(key, iso(days=k), 'ok', '{}') for k in (1, 40)])
        d.commit()

    def test_donnees_des_serveurs_retires_et_prises_expirees(self):
        # Audit DB-05 : tables jamais purgées pour les serveurs retirés.
        d = self.db
        for key in ('srv-inventaire', 'srv-retiré'):
            d.execute('INSERT INTO apache_samples(key, ts, payload) VALUES(?,?,?)', (key, iso(days=40), '{}'))
            d.execute('INSERT INTO batch_states(key, ip, payload) VALUES(?,?,?)', (key, '192.0.2.1', '{}'))
        d.execute("INSERT INTO alert_acks(id, count, by, note, at, until, auth) VALUES('vieille', 1, 'a', '', ?, ?, 'local')",
                  (iso(days=3), iso(days=2)))
        d.execute("INSERT INTO alert_acks(id, count, by, note, at, until, auth) VALUES('active', 1, 'a', '', ?, ?, 'local')",
                  (iso(days=1), (NOW + timedelta(hours=1)).isoformat()))
        d.commit()
        counts = retention.sweep(d, ['srv-inventaire'], NOW, self.RULES)
        self.assertEqual((counts['apache_samples_orphans'], counts['batch_states_orphans'], counts['alert_acks_expired']), (1, 1, 1))
        self.assertEqual([r[0] for r in d.execute('SELECT key FROM batch_states')], ['srv-inventaire'])
        self.assertEqual([r[0] for r in d.execute('SELECT id FROM alert_acks')], ['active'])

    def ids(self, sql):
        return sorted(r[0] for r in self.db.execute(sql))

    def test_rules(self):
        counts = retention.sweep(self.db, ['srv-inventaire'], NOW, self.RULES)
        self.assertEqual(self.ids('SELECT id FROM incidents'), sorted(['récent-résolu', 'vieux-ouvert', 'vieux-réapparu', 'pris']),
                         'seul le résolu ancien part ; ouvert, réapparu et pris en charge restent')
        self.assertEqual(self.db.execute("SELECT count(*) FROM incident_events WHERE incident_id='vieux-résolu'").fetchone()[0], 0)
        per = dict(self.db.execute('SELECT incident_id, count(*) FROM incident_events GROUP BY incident_id').fetchall())
        self.assertTrue(all(n == 3 for n in per.values()), per)
        kept = self.ids("SELECT at FROM incident_events WHERE incident_id='vieux-ouvert'")
        self.assertEqual(kept, sorted([iso(days=0), iso(days=1), iso(days=2)]), 'les événements les plus récents sont gardés')
        self.assertEqual(self.ids('SELECT id FROM maintenance_windows'), [2, 3])
        self.assertEqual(self.db.execute("SELECT count(*) FROM audit_snapshots WHERE key='srv-inventaire'").fetchone()[0], 3, 'inventaire intact')
        self.assertEqual(self.ids("SELECT ts FROM audit_snapshots WHERE key='srv-retiré'"), [iso(days=1)], 'orphelin : seul le récent reste')
        self.assertEqual(self.ids("SELECT ts FROM history WHERE key='srv-retiré'"), [iso(days=1)])
        self.assertEqual(counts['incidents_resolved'], 1)
        self.assertEqual(counts['maintenance_ended'], 1)
        self.assertEqual(retention.sweep(self.db, ['srv-inventaire'], NOW, self.RULES).get('incidents_resolved'), 0, 'deuxième passage : rien')

    def test_empty_inventory_never_purges_servers(self):
        retention.sweep(self.db, [], NOW, self.RULES)
        self.assertEqual(self.db.execute('SELECT count(*) FROM audit_snapshots').fetchone()[0], 6, 'lecture d’inventaire vide : aucune purge de serveur')

    def test_missing_tables_are_tolerated(self):
        db = sqlite3.connect(':memory:')
        self.assertEqual(retention.sweep(db, ['a'], NOW, self.RULES), {})
        db.close()

    def test_policy_from_environment_is_bounded(self):
        from unittest import mock
        with mock.patch.dict('os.environ', {'INFRAOPS_INCIDENT_RETENTION_DAYS': '0', 'INFRAOPS_ORPHAN_RETENTION_DAYS': 'abc'}):
            p = retention.policy()
        self.assertEqual(p['incident_days'], 1, 'jamais 0 jour')
        self.assertEqual(p['orphan_days'], 30, 'valeur invalide : défaut')


if __name__ == '__main__':
    unittest.main()
