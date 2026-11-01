"""Un clone neuf utilise uniquement l’inventaire synthétique pendant les tests."""
import testing_env  # noqa: F401 — inventaire et base temporaires avant un import d’app
import os
import tempfile
import unittest
from ipaddress import ip_address, ip_network
from pathlib import Path
from unittest.mock import patch

from config import inventory_path, load_config


class InventoryTests(unittest.TestCase):
    def test_example_contains_only_documentation_addresses(self):
        cfg, hosts = load_config(Path(__file__).with_name('hosts.example.yaml'))
        ranges = [ip_network(s) for s in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24')]
        self.assertIn(len(hosts), (3, 4))
        self.assertTrue(cfg.users)
        self.assertTrue(cfg.ports)
        for host in hosts:
            self.assertTrue(any(ip_address(host['ip']) in network for network in ranges))
            self.assertFalse(host['collect_enabled'])

    def test_testing_inventory_is_a_temporary_copy(self):
        source = Path(__file__).with_name('hosts.example.yaml')
        target = testing_env.INVENTORY
        self.assertNotEqual(source.resolve(), target.resolve())
        self.assertEqual(target.read_bytes(), source.read_bytes())

    def test_environment_selects_external_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'external.yaml'
            target.write_bytes(Path(__file__).with_name('hosts.example.yaml').read_bytes())
            with patch.dict(os.environ, {'INFRAOPS_INVENTORY': str(target)}):
                self.assertEqual(inventory_path(), target.resolve())
                self.assertEqual(load_config()[1][0]['key'], 'demo-web')

    def test_explicit_path_is_not_overridden_by_environment(self):
        with patch.dict(os.environ, {'INFRAOPS_INVENTORY': 'absent-external.yaml'}):
            self.assertEqual(len(load_config(Path(__file__).with_name('hosts.example.yaml'))[1]), 3)

    def test_missing_inventory_explains_how_to_start(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {'INFRAOPS_INVENTORY': ''}):
                missing = inventory_path(Path(directory) / 'hosts.yaml')
                with self.assertRaisesRegex(RuntimeError, 'hosts.example.yaml.*INFRAOPS_INVENTORY'):
                    load_config(missing)

