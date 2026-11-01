"""Migration core_v4_module_tables : tables des modules regroupées et versionnées."""
import contextlib
import sqlite3
import unittest

import apache_health
import migrations


def tables(db):
    return {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}


class SchemaV4Tests(unittest.TestCase):
    def test_base_neuve(self):
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        migrations.apply(db)
        self.assertLessEqual(set(migrations.MODULE_TABLES), tables(db))
        cols = {r[1] for r in db.execute('PRAGMA table_info(alert_acks)')}
        self.assertIn('auth', cols)

    def test_base_existante_sans_colonne_auth(self):
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        db.execute('CREATE TABLE alert_acks(id TEXT PRIMARY KEY, count INTEGER, by TEXT, note TEXT, at TEXT, until TEXT)')
        db.execute("INSERT INTO alert_acks VALUES('a', 1, 'x', '', 't', 'u')")
        db.commit()
        self.assertIn('core_v4_module_tables', migrations.apply(db))
        self.assertEqual(db.execute('SELECT auth FROM alert_acks').fetchone()[0], 'local', 'prises en charge existantes : local')
        self.assertEqual(migrations.apply(db), [], 'une seule fois')

    def test_historique_apache_sans_ecriture(self):
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)

        @contextlib.contextmanager
        def connect():
            yield db
        self.assertEqual(apache_health.history(connect, 'waf'), [])
        self.assertNotIn('apache_samples', tables(db), 'une route GET ne crée plus de table')


if __name__ == '__main__':
    unittest.main()
