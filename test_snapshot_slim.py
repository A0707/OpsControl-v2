"""Allègement des anciens audits (retention.slim_snapshots) et compactage (deploy/maintenance.py)."""
import contextlib
import json
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent / 'deploy'))
import alert_center  # noqa: E402
import maintenance  # noqa: E402
import migrations  # noqa: E402
import observability  # noqa: E402
import retention  # noqa: E402
import restore_state  # noqa: E402

T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)


def payload(i, fingerprint='fp1'):
    return {'collected_at': (T0 + timedelta(hours=i)).isoformat(), 'status': 'ok', 'cpu': 10 + i, 'ram': 40, 'disk_max': 50 + i % 3,
            'fingerprint': fingerprint, 'checks': [{'name': 'x', 'output': 'y' * 2000}], 'findings': [{'id': 'f'}],
            'all_services': [{'name': 'nginx', 'status': 'failed' if i == 3 else 'active', 'description': 'z' * 200}],
            'storage': {'filesystems': [{'mount': '/', 'used_kb': 100 + i, 'total_kb': 1000, 'fs': 'ext4'}],
                        'shares': ['volumineux'] * 50}}


def make_db(path, n=30, keys=('a', 'b')):
    db = sqlite3.connect(path)
    db.execute('CREATE TABLE audit_snapshots(key TEXT, ts TEXT, payload TEXT, PRIMARY KEY(key,ts))')
    for key in keys:
        for i in range(n):
            p = payload(i)
            db.execute('INSERT INTO audit_snapshots(key, ts, payload) VALUES(?,?,?)', (key, p['collected_at'], json.dumps(p)))
    db.commit()
    return db


class SlimTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / 'state.sqlite3'
        self.db = make_db(self.path)
        self.addCleanup(self.db.close)

    def snapshots(self, key):
        return [json.loads(p) for p, in self.db.execute('SELECT payload FROM audit_snapshots WHERE key=? ORDER BY ts DESC', (key,))]

    def test_projection_garde_les_champs_lus_et_rien_d_autre(self):
        s = retention.slim_snapshot(payload(3))
        self.assertEqual(set(s), {'collected_at', 'status', 'cpu', 'ram', 'disk_max', 'fingerprint', 'service_states', 'storage', '_slim'})
        self.assertEqual(s['service_states'], [{'name': 'nginx', 'status': 'failed'}])
        self.assertEqual(s['storage'], {'filesystems': [{'mount': '/', 'used_kb': 103, 'total_kb': 1000}]})

    def test_les_20_plus_recents_restent_complets(self):
        self.assertEqual(retention.slim_snapshots(self.db), 20)  # 10 anciens par serveur
        snaps = self.snapshots('a')
        self.assertTrue(all('checks' in s for s in snaps[:20]))
        self.assertTrue(all(s.get('_slim') and 'checks' not in s for s in snaps[20:]))
        self.assertEqual(retention.slim_snapshots(self.db), 0, 'idempotent')

    def test_limite_par_passage(self):
        self.assertEqual(retention.slim_snapshots(self.db, limit=7), 7)

    def test_tendances_identiques_avant_et_apres(self):
        avant = observability.build(self.snapshots('a'))
        retention.slim_snapshots(self.db)
        self.assertEqual(observability.build(self.snapshots('a')), avant)

    def test_historique_disque_et_cpu_identique(self):
        context = SimpleNamespace(connect=lambda: _Conn(self.path))
        alert_center._cache.clear()
        avant = alert_center.historique(context)
        retention.slim_snapshots(self.db)
        self.db.commit()
        alert_center._cache.clear()
        self.assertEqual(alert_center.historique(context), avant)

    def test_sweep_compte_les_audits_alleges(self):
        counts = retention.sweep(self.db, ['a', 'b'])
        self.assertEqual(counts['audit_snapshots_slimmed'], 20)

    def connect(self):
        @contextlib.contextmanager
        def opened():
            db = sqlite3.connect(self.path)
            try:
                with db:
                    yield db
            finally:
                db.close()
        return opened()

    def test_migration_marque_les_audits_deja_alleges(self):
        retention.slim_snapshots(self.db)            # base antérieure : allégés sans marqueur
        migrations.core_v8_snapshot_slim_flag(self.db)
        self.db.commit()
        marked = self.db.execute('SELECT count(*) FROM audit_snapshots WHERE slim=1').fetchone()[0]
        self.assertEqual(marked, 20)
        self.assertEqual(retention.slim_snapshots(self.db), 0, 'rien à refaire après rétroremplissage')

    def test_allegement_par_lots_courts_commites(self):
        # Audit DB-03 : chaque lot dans sa propre transaction, sélection par le marqueur indexé.
        migrations.core_v8_snapshot_slim_flag(self.db)
        self.db.commit()
        self.assertEqual(retention.slim_in_batches(self.connect, batch=7), 20)
        self.db.rollback()
        self.assertEqual(self.db.execute('SELECT count(*) FROM audit_snapshots WHERE slim=1').fetchone()[0], 20)
        self.assertEqual(retention.slim_in_batches(self.connect, batch=7), 0)
        self.assertTrue(all('checks' in s for s in self.snapshots('a')[:20]))

    def test_sweep_sans_allegement_quand_fait_a_part(self):
        self.assertNotIn('audit_snapshots_slimmed', retention.sweep(self.db, ['a', 'b'], slim=False))

    def test_reclaim_sans_effet_hors_mode_incremental(self):
        self.assertEqual(retention.reclaim(self.db), 0)


class _Conn:
    """Gestionnaire de contexte minimal, comme app.connect()."""

    def __init__(self, path):
        self.db = sqlite3.connect(path)

    def __enter__(self):
        return self.db

    def __exit__(self, *exc):
        self.db.close()


class VacuumTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        (self.base / 'data').mkdir()
        self.db = self.base / 'data/state.sqlite3'
        make_db(self.db, n=120).close()

    def test_mesure_sans_confirmation(self):
        avant = self.db.stat().st_size
        r = maintenance.vacuum(self.base, self.db)
        self.assertEqual(r['before']['snapshots_to_slim'], 200)
        self.assertNotIn('after', r)
        self.assertEqual(self.db.stat().st_size, avant)

    def test_vacuum_compacte_et_active_le_mode_incremental(self):
        avant = maintenance.size(self.db)
        r = maintenance.vacuum(self.base, self.db, confirm=True)
        self.assertEqual(r['slimmed'], 200)
        self.assertEqual(r['after']['auto_vacuum'], 'INCREMENTAL')
        self.assertEqual(r['after']['snapshots_to_slim'], 0)
        self.assertLess(r['after']['bytes'], avant / 2)
        self.assertIn('avant-vacuum', r['safety_backup'])
        self.assertTrue((self.base / 'backups' / r['safety_backup']).is_file())

    def test_refus_si_le_service_tourne(self):
        with restore_state.InstanceLock(self.db):
            with self.assertRaises(restore_state.RestoreError):
                maintenance.vacuum(self.base, self.db, confirm=True)


if __name__ == '__main__':
    unittest.main()
