"""Artefact de CI autonome : aucune donnée locale ni empreinte personnelle."""
import contextlib
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml
from deploy import package_vm


class CodeOnlyPackageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        (self.base/'app.py').write_bytes(b'print("synthetic")\r\n')
        (self.base/'requirements.txt').write_text('PyYAML==6.0.3\n')
        (self.base/'hosts.example.yaml').write_text('hosts: []\n')
        (self.base/'requirements-dev.txt').write_text('bandit==1.9.4\n')

    def package(self):
        with patch.object(package_vm, 'BASE', self.base), \
                patch.object(package_vm, 'DIST', self.base/'dist'), \
                patch.object(package_vm, 'copie_base') as copy_db, \
                patch.object(package_vm, 'serveur_actif') as network, \
                patch.object(Path, 'home', side_effect=AssertionError('Profil personnel interdit')), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(package_vm.main(['--code-only']), 0)
        copy_db.assert_not_called()
        network.assert_not_called()
        return next((self.base/'dist').glob('*.tar.gz'))

    def test_without_inventory_or_data_and_with_manifest(self):
        archive = self.package()
        with tarfile.open(archive) as bundle:
            names = bundle.getnames()
            self.assertIn('infraops/hosts.example.yaml', names)
            self.assertIn('infraops/requirements-dev.txt', names)
            self.assertNotIn('infraops/hosts.yaml', names)
            self.assertFalse(any('/data/' in name or '/ssh/' in name for name in names))
            self.assertNotIn(b'\r\n', bundle.extractfile('infraops/app.py').read())
            manifest = bundle.extractfile('infraops/MANIFEST.sha256').read().decode()
            for line in manifest.splitlines():
                digest, relative = line.split('  ',1)
                self.assertEqual(hashlib.sha256(bundle.extractfile('infraops/'+relative).read()).hexdigest(), digest)

    def test_existing_operational_data_is_never_embedded(self):
        (self.base/'hosts.yaml').write_text('hosts: [LOCAL_STATE_SENTINEL]\n')
        (self.base/'data').mkdir()
        (self.base/'data/state.sqlite3').write_bytes(b'LOCAL_STATE_SENTINEL')
        (self.base/'data/api-connections.json').write_text(json.dumps([{'name':'LOCAL_STATE_SENTINEL'}]))
        with tarfile.open(self.package()) as bundle:
            for name in bundle.getnames():
                self.assertNotIn(b'LOCAL_STATE_SENTINEL', bundle.extractfile(name).read())


class WorkflowTests(unittest.TestCase):
    def test_events_permissions_and_required_checks(self):
        workflow = Path(__file__).parent/'.github/workflows/ci.yml'
        data = yaml.load(workflow.read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
        self.assertEqual(set(data['on']), {'push','pull_request'})
        self.assertEqual(data['permissions'], {'contents':'read'})
        steps = data['jobs']['validation']['steps']
        setup = next(s for s in steps if s.get('uses','').startswith('actions/setup-python@'))
        self.assertEqual(setup['with']['python-version'], '3.11')
        # Audit CI-04 : une étiquette peut être déplacée ; seul un SHA complet fige le code exécuté.
        for step in steps:
            if 'uses' in step:
                self.assertRegex(step['uses'], r'^[\w.-]+/[\w.-]+@[0-9a-f]{40}$', step['uses'])
        commands = '\n'.join(s.get('run','') for s in steps)
        for required in ('pip install -r requirements.txt -r requirements-dev.txt',
                         'python deploy/ci.py --ui', 'playwright@1.63.0', 'bash -n', 'visudo -cf',
                         'zabbix-template-opscontrol.yaml', 'package_vm.py --code-only', 'cyclonedx-json'):
            self.assertIn(required, commands)
        self.assertNotIn('secrets.', workflow.read_text())
