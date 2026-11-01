import re
import unittest
from pathlib import Path

import payload_slim

HOTE = {'key': 'a', 'name': 'a', 'status': 'critical', 'stale': False, 'findings': [{'id': 'disk_max'}],
        'checks': [{'id': 'cpu', 'command': 'x' * 500}], 'storage': {'filesystems': []}, 'filesystems': [{'mount': '/'}],
        'attempts': [{'rc': 0}], 'waf': {'sections': {'large': 'payload'}},
        'documented': {'backup': {'paths': '/var'}}, 'proxmox_matches': [],
        'all_services': [{'name': 'ssh', 'status': 'active'}, {'name': 'tomcat', 'status': 'failed'},
                         {'name': 'kdump', 'status': 'inactive'}],
        'last_attempt': {'collected_at': 't', 'issues': ['timeout'], 'checks': [{'x': 1}], 'status': 'unreachable'}}


class SlimTests(unittest.TestCase):
    def test_detail_only_fields_removed_and_flagged(self):
        s = payload_slim.slim(HOTE)
        for champ in payload_slim.DETAIL_ONLY:
            self.assertNotIn(champ, s)
        self.assertTrue(s['detail_trimmed'])
        # Seule la documentation backup reste ; constats et rapprochement sont détaillés ailleurs.
        self.assertEqual(s['documented'], HOTE['documented'])
        self.assertNotIn('proxmox_matches', s)

    def test_failed_services_kept_for_the_fleet_table(self):
        s = payload_slim.slim(HOTE)
        self.assertEqual([x['name'] for x in s['all_services']], ['tomcat'])
        self.assertEqual(s['services_total'], 3)
        self.assertEqual(sum(x['status'] == 'failed' for x in s['all_services']), 1)  # colonne « Services »

    def test_last_attempt_keeps_what_lists_show(self):
        self.assertEqual(payload_slim.slim(HOTE)['last_attempt'],
                         {'collected_at': 't', 'issues': ['timeout'], 'status': 'unreachable'})

    def test_main_cause_and_missing_controls_survive_slimming(self):
        # Audit UI du 31/10 (fiches 03.3 et 05.1) : cause d'une ligne critique et contrôles absents.
        host = {**HOTE, 'findings': [{'severity': 'critical', 'title': 'Service tomcat en échec'},
                                     {'severity': 'warning', 'title': 'Disque 85 %'}],
                'checks': [{'id': 'cpu', 'title': 'CPU', 'status': 'pass'},
                           {'id': 'firewall', 'title': 'Pare-feu', 'status': 'unknown'}]}
        s = payload_slim.slim(host)
        self.assertEqual(s['status_reason'], 'Service tomcat en échec')
        self.assertEqual(s['coverage_missing'], ['Pare-feu'])
        # Audit ancien : la cause reste celle de la gravité mesurée (audit_status).
        old = payload_slim.slim({**host, 'status': 'unknown', 'audit_status': 'warning'})
        self.assertEqual(old['status_reason'], 'Disque 85 %')
        self.assertNotIn('status_reason', payload_slim.slim({**host, 'status': 'ok'}))

    def test_original_row_untouched_for_the_detail_endpoint(self):
        payload_slim.slim(HOTE)
        self.assertIn('checks', HOTE)
        self.assertEqual(len(HOTE['all_services']), 3)

    def test_services_endpoint_returns_everything(self):
        self.assertEqual(len(payload_slim.services([HOTE])['a']), 3)

    def test_findings_endpoint_returns_everything(self):
        self.assertEqual(payload_slim.findings([HOTE])['a'], HOTE['findings'])

    def test_removed_fields_are_not_read_by_list_views(self):
        """Garde-fou : un champ retiré ne doit être lu que dans la fiche serveur.

        storage.js et la fonction checks()/l'onglet audit d'app.js sont des vues
        de fiche (h = hostDetail). Si une vue de LISTE se met à lire ces champs,
        ce test échoue : il faudra les rendre à la liste ou passer par l'API.
        """
        web = Path(__file__).parent / 'web'
        autorises = {'storage.js'}
        for fichier in web.glob('*.js'):
            if fichier.name in autorises:
                continue
            texte = fichier.read_text(encoding='utf-8')
            for champ in ('storage', 'filesystems'):
                self.assertIsNone(re.search(r'\bh\.' + champ + r'\b', texte), f'{fichier.name} lit h.{champ}')


if __name__ == '__main__':
    unittest.main()


class EnvironmentTests(unittest.TestCase):
    def test_prod_variants_are_one_filter_value(self):
        # Audit UI du 31/10 (fiche 03.1) : PROD et Prod donnent une seule valeur, brute conservée.
        for raw in ('PROD', 'Prod', ' production ', 'prd'):
            self.assertEqual(payload_slim.slim({**HOTE, 'environment': raw})['environment'], 'PROD')
        prod = payload_slim.slim({**HOTE, 'environment': 'Prod'})
        self.assertEqual(prod['environment_raw'], 'Prod')
        self.assertNotIn('environment_raw', payload_slim.slim({**HOTE, 'environment': 'PROD'}))
        self.assertEqual(payload_slim.canonical_environment('Préprod'), 'PRÉPROD')
        self.assertEqual(payload_slim.canonical_environment('Bac à sable'), 'Bac à sable')
        self.assertEqual(payload_slim.canonical_environment('à renseigner'), 'À renseigner')
        self.assertIsNone(payload_slim.canonical_environment(None))
