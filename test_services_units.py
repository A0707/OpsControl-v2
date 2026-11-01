"""Page Services : unités filtrées et paginées côté serveur (routers/fleet.services_units)."""
import unittest
from types import SimpleNamespace

from routers import fleet


def rows():
    return [
        {'key': 'web', 'all_services': [{'name': 'nginx.service', 'status': 'failed', 'configured': True},
                                        {'name': 'cron.service', 'status': 'active'}] +
                                       [{'name': f'u{i}.service', 'status': 'inactive'} for i in range(250)]},
        {'key': 'db', 'all_services': [{'name': 'postgresql.service', 'status': 'failed'}, 'non-dict ignoré']},
        {'key': 'vide'},
    ]


class ServicesUnitsTests(unittest.TestCase):
    def setUp(self):
        self.previous = fleet.context
        fleet.context = SimpleNamespace(rows=rows)

    def tearDown(self):
        fleet.context = self.previous

    def test_par_defaut_les_seuls_echecs(self):
        r = fleet.services_units()
        self.assertEqual([(u['host_key'], u['name']) for u in r['items']],
                         [('web', 'nginx.service'), ('db', 'postgresql.service')])
        self.assertEqual((r['total'], r['failed_total']), (2, 2))
        self.assertTrue(r['items'][0]['configured'])

    def test_pagination_bornee(self):
        r = fleet.services_units('all', offset=100, limit=100)
        self.assertEqual(r['total'], 253)  # 2 + 250 (web) + 1 (db) ; l'entrée non-dict est ignorée
        self.assertEqual(len(r['items']), 100)
        self.assertEqual(r['items'][0]['status'], 'inactive', 'échecs en tête, donc hors de la 2e page')
        self.assertEqual(fleet.services_units('all', limit=10_000)['limit'], fleet.UNITS_MAX)

    def test_recherche_et_restriction_aux_serveurs_affiches(self):
        self.assertEqual(fleet.services_units('all', q='CRON')['total'], 1)
        r = fleet.services_units('failed', hosts='web')
        self.assertEqual([u['host_key'] for u in r['items']], ['web'])
        self.assertEqual(r['failed_total'], 1, 'compté sur les seuls serveurs affichés')


if __name__ == '__main__':
    unittest.main()

class ServicesEvidenceTests(unittest.TestCase):
    def setUp(self):
        from datetime import datetime, timezone
        self.previous = fleet.context
        now = datetime.now(timezone.utc).isoformat()
        self.hosts = [
            {'key': 'fresh', 'collected_at': now, 'all_services': [
                {'name': 'nginx', 'status': 'failed', 'substate': 'failed', 'configured': True},
                {'name': 'oneshot', 'status': 'active', 'substate': 'exited'},
                {'name': 'off', 'status': 'inactive'}]},
            {'key': 'old', 'stale': True, 'collected_at': now, 'all_services': [
                {'name': 'old-failure', 'status': 'failed', 'configured': True}]},
            {'key': 'missing'},
        ]
        fleet.context = SimpleNamespace(rows=lambda: self.hosts)

    def tearDown(self):
        fleet.context = self.previous

    def test_sous_etat_et_fraicheur_independants_du_statut(self):
        result = fleet.services_units('all')
        oneshot = next(u for u in result['items'] if u['name'] == 'oneshot')
        self.assertEqual(oneshot['substate'], 'exited')
        self.assertTrue(oneshot['fresh'])
        self.assertEqual(result['summary']['failed_recent'], 1)
        self.assertEqual(result['summary']['stale'], 1)
        self.assertEqual(result['summary']['unmeasured_hosts'], 1)
        self.assertFalse(self.hosts[0]['all_services'][0].get('fresh', False), 'source intacte')

    def test_filtres_et_compteurs_portent_sur_le_meme_perimetre(self):
        r = fleet.services_units('critical', hosts='fresh', freshness='recent')
        self.assertEqual([u['name'] for u in r['items']], ['nginx'])
        self.assertEqual(r['summary']['observed'], 3)
        self.assertEqual(fleet.services_units('inactive')['items'][0]['name'], 'off')
        self.assertEqual(fleet.services_units('all', freshness='stale')['total'], 1)
        self.assertEqual(fleet.services_units('all', q='missing')['total'], 0)


class ExpectedObservedTests(unittest.TestCase):
    """Audit UI du 31/10 (fiche 04.1) : attendu / observé et provenance de la criticité."""

    def setUp(self):
        self.previous = fleet.context
        fleet.context = SimpleNamespace(rows=lambda: [{'key': 'web', 'services': ['nginx'], 'all_services': [
            {'name': 'nginx.service', 'status': 'failed', 'configured': True},
            {'name': 'postgresql.service', 'status': 'failed'},
            {'name': 'logrotate.service', 'status': 'failed'},
            {'name': 'tomcat9.service', 'status': 'unknown', 'configured': True}]}])

    def tearDown(self):
        fleet.context = self.previous

    def test_reading_and_level_source(self):
        r = fleet.services_units('all')
        by = {u['name']: u for u in r['items']}
        self.assertEqual(by['nginx.service']['reading'], 'expected_down')
        self.assertEqual(by['nginx.service']['level_source'], 'service déclaré critique dans l’inventaire')
        self.assertEqual(by['postgresql.service']['reading'], 'accessory_failed')
        self.assertEqual(by['postgresql.service']['level'], 'critical', 'non déclaré, mais classe de production')
        self.assertEqual(by['logrotate.service']['level'], 'preventive')
        self.assertEqual(by['tomcat9.service']['reading'], 'missing_check')
        self.assertEqual((r['summary']['expected_down'], r['summary']['accessory_failed']), (1, 2))
