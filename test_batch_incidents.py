"""Exécutions des batchs (début, fin) et incident ouvert sur un échec ou un passage manqué."""
import unittest
from types import SimpleNamespace
from unittest import mock

import alert_center
import batch_catalog as bc
import incident_center as ic

NOW = 1_800_000_000


def entry(nom, verdict=None, findings=(), criticite=None, host_key='job', **outcome):
    o = {'verdict': verdict, 'reason': 'Code retour 2 — ERROR SFTP refusé', 'source': 'Enveloppe',
         'started_at': NOW - 120, 'finished_at': NOW - 60, 'at': NOW - 60, **outcome} if verdict else None
    return {'id': nom.lower().replace(' ', '-'), 'nom': nom, 'host_name': 'srv-job', 'host_key': host_key,
            'criticite': criticite, 'outcome': o, 'collected_at': '2027-01-15T08:00:00+00:00', 'fresh': True,
            'findings': [{'level': 'warning', 'text': t} for t in findings]}


class Dates(unittest.TestCase):
    def test_debut_et_fin_selon_la_source(self):
        fini = bc.outcome_of([{'started': 100, 'finished': 160, 'rc': 0, 'duration': 60}], [], None)
        self.assertEqual((fini['started_at'], fini['finished_at'], fini['duration']), (100, 160, 60))
        # En cours : « finished » est la fin du passage PRÉCÉDENT, jamais affichée comme fin.
        encours = bc.outcome_of([{'started': 200, 'finished': 160, 'rc': 0}], [], None)
        self.assertEqual((encours['verdict'], encours['started_at'], encours['finished_at']), ('running', 200, None))
        zabbix = bc.outcome_of([], [{'state': 'failed', 'rc': 1, 'started_at': 10, 'finished_at': 20}], None)
        self.assertEqual((zabbix['started_at'], zabbix['finished_at']), (10, 20))
        journal = bc.outcome_of([], [], {'readable': True, 'verdict': 'success', 'mtime': 500, 'errors': [], 'last_lines': []})
        self.assertEqual((journal['started_at'], journal['finished_at']), (None, 500))


class Alertes(unittest.TestCase):
    def build(self, entries):
        lots = {'entries': entries, 'servers': [{'host_key': 'job', 'fresh': True}]}
        ctx = SimpleNamespace(rows=lambda: [], api_connections=lambda: [])
        with mock.patch.object(alert_center, '_batchs', return_value=lots):
            return alert_center.build(ctx, for_incidents=True)

    def test_echec_et_passage_manque_ouvrent_un_incident(self):
        built = self.build([entry('Export banque', 'failed'), entry('Impayes', 'failed', criticite=3),
                            entry('Factures', 'success'), entry('Catalog', 'success', findings=[
                                'Aucun passage depuis 30 h (batch quotidien) : lancement manqué ?'])])
        alerts = {a['id']: a for a in built['alerts'] if a['source'] == 'Batch'}
        self.assertEqual(sorted(alerts), ['Batch:echec:export-banque:warning', 'Batch:echec:impayes:critical',
                                          'Batch:manque:catalog:warning'])
        cible = alerts['Batch:echec:export-banque:warning']['targets'][0]
        self.assertEqual((cible['host_key'], cible['started_at']), ('job', '2027-01-15T07:59:00+00:00'))
        observed = ic.observations(built['alerts'])
        ids = sorted(o['id'] for o in observed if o['source'] == 'Batch')
        self.assertEqual(ids, ['Batch|job|echec:export-banque', 'Batch|job|echec:impayes', 'Batch|job|manque:catalog'])
        self.assertIn('ERROR SFTP refusé', next(o for o in observed if o['id'] == ids[0])['evidence'])
        self.assertEqual(built['batch_status'], {'job': (True, None)})

    def test_regle_affichee(self):
        self.assertTrue(any(r['domain'] == 'Batch' for r in alert_center.policy.RULES))

    def test_referentiel_illisible_sans_alerte(self):
        ctx = SimpleNamespace(rows=lambda: [], api_connections=lambda: [])
        self.assertEqual(alert_center._batchs(ctx), {'entries': [], 'servers': []})


class Resolution(unittest.TestCase):
    def test_absence_d_echec_confirmee_par_un_inventaire_recent(self):
        incident = {'source': 'Batch', 'target_key': 'job'}
        ok = ic.source_status([], [], batch={'job': (True, None)})
        self.assertEqual(ic.can_confirm_absence(incident, ok), (True, None))
        ancien = ic.source_status([], [], batch={'job': (False, 'Inventaire batch ancien ou non collecté')})
        self.assertFalse(ic.can_confirm_absence(incident, ancien)[0])
        self.assertFalse(ic.can_confirm_absence(incident, ic.source_status([], []))[0])
        self.assertFalse(ic.can_confirm_absence({'source': 'Batch', 'target_key': None}, ok)[0])


if __name__ == '__main__':
    unittest.main()
