"""Lot 7 : contrat du contexte applicatif (app_context.CONTRACT) respecté par tous les modules."""
import testing_env  # noqa: F401 — base temporaire AVANT tout import d'app (testing_env.py)
import os
import re
import unittest
from pathlib import Path

os.environ.setdefault('INFRAOPS_INCIDENT_SYNC', '0')

from app_context import CONTRACT

BASE = Path(__file__).parent
# Objets SSL nommés « context » dans les modules réseau : sans rapport avec le contexte applicatif.
NOT_APP_CONTEXT = {'wrap_socket', 'verify_flags', 'check_hostname', 'verify_mode', 'load_verify_locations', 'load_cert_chain'}


def scan():
    used, assigned = {}, {}
    for path in [*BASE.glob('*.py'), *BASE.glob('routers/*.py')]:
        if path.name.startswith('test_') or path.name in ('app.py', 'loadtest.py', 'app_context.py'):
            continue
        text = path.read_text(encoding='utf-8')
        for m in re.finditer(r'\bcontext\.([A-Za-z_]\w*)\s*(=(?!=))?', text):
            if m.group(1) in NOT_APP_CONTEXT:
                continue
            (assigned if m.group(2) else used).setdefault(m.group(1), set()).add(path.stem)
    return used, assigned


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app
        cls.app = app
        cls.used, cls.assigned = scan()

    def test_every_attribute_used_by_a_module_is_declared(self):
        undeclared = {name: sorted(mods) for name, mods in self.used.items() if name not in CONTRACT}
        self.assertEqual(undeclared, {}, 'attribut de contexte non déclaré dans app_context.CONTRACT')

    def test_every_declared_attribute_exists_once_assembled(self):
        missing = [name for name in CONTRACT if not hasattr(self.app, name)]
        self.assertEqual(missing, [])

    def test_declared_providers_are_the_actual_providers(self):
        wrong = {}
        for name, (provider, _) in CONTRACT.items():
            actual = self.assigned.get(name, set())
            if provider == 'app' and actual:
                wrong[name] = ('app', sorted(actual))
            elif provider != 'app' and provider not in actual:
                wrong[name] = (provider, sorted(actual))
        self.assertEqual(wrong, {}, 'fournisseur déclaré ≠ module qui installe l’attribut')

    def test_contract_has_no_dead_entries(self):
        # Lu par un module (context.x, getattr/hasattr(context, 'x')) ou par app.py lui-même.
        texts = [p.read_text(encoding='utf-8') for p in [*BASE.glob('*.py'), *BASE.glob('routers/*.py')] if not p.name.startswith('test_') and p.name not in ('loadtest.py', 'app_context.py')]
        app_text = (BASE / 'app.py').read_text(encoding='utf-8')
        # Planificateur et collectes extraits d'app.py (jobs.py) : ils lisent le contexte par « c. ».
        jobs_text = (BASE / 'jobs.py').read_text(encoding='utf-8')
        def read(name):
            if name in self.used:
                return True
            if any(re.search(r"(getattr|hasattr)\(context,\s*'" + name + "'", t) for t in texts):
                return True
            if re.search(r'\bc\.' + name + r'\(', jobs_text) or ("hasattr(c, '" + name + "')") in jobs_text:
                return True
            return re.search(r'(?<![\w.])' + name + r'\(', app_text) is not None or ("'" + name + "' in globals()") in app_text
        dead = [name for name in CONTRACT if not read(name)]
        self.assertEqual(dead, [], 'entrée du contrat qu’aucun module ne lit')


class ConnectionTests(unittest.TestCase):
    def test_cles_etrangeres_actives(self):
        # Audit DB-02 : sans ce PRAGMA, ON DELETE CASCADE de discovery_hosts était sans effet.
        import app
        with app.connect() as db:
            self.assertEqual(db.execute('PRAGMA foreign_keys').fetchone()[0], 1)
            scan = db.execute("INSERT INTO discovery_scans(range,at,duration_s,status) "
                              "VALUES('10.0.0.0/30','2026-01-01T00:00:00+00:00',1,'completed')").lastrowid
            db.execute("INSERT INTO discovery_hosts(scan,ip,ports) VALUES(?,'10.0.0.1','[]')", (scan,))
            db.execute('DELETE FROM discovery_scans WHERE id=?', (scan,))
            self.assertEqual(db.execute('SELECT count(*) FROM discovery_hosts WHERE scan=?', (scan,)).fetchone()[0], 0)


if __name__ == '__main__':
    unittest.main()
