from routers import all_routes  # routes des APIRouter inclus (FastAPI ne les recopie plus dans app.routes)
import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI, HTTPException

import inventory_completion as ic


def h(key, role='À renseigner', env='PROD', services=None, **extra):
    return {'key': key, 'name': key, 'ip': '10.0.0.' + str(len(key)), 'role': role, 'environment': env,
            'services': services or [], **extra}


def row(key, *actifs):
    return {'key': key, 'collected_at': 't', 'all_services': [{'name': s + '.service', 'status': 'active'} for s in actifs]
            + [{'name': 'arret.service', 'status': 'inactive'}]}


PARC = [h('prdlabswr0' + str(i), 'SWARM') for i in range(1, 4)] + [
    h('prdlabswr09'),                       # nom seul : SWARM appris
    h('prdlablog01'),                       # service seul : elasticsearch
    h('prdlabswr08'),                       # conflit : nom SWARM, service PostgreSQL
    h('reclabcha02', env='À renseigner'),   # environnement appris du préfixe
    h('rec1', 'DB', 'PREPROD'), h('rec2', 'DB', 'PREPROD'),
    h('recdcybdd01', 'DB', 'PREPROD'),
]
ROWS = [row('prdlablog01', 'elasticsearch', 'postfix@-', 'sshd', 'networking'),
        row('prdlabswr08', 'postgresql@16-main', 'docker'), row('recdcybdd01', 'postgresql-9.6', 'httpd')]


class SuggestTests(unittest.TestCase):
    def setUp(self):
        self.r = ic.suggest(PARC, ROWS)
        self.par = {p['key']: p for p in self.r['suggestions']}

    def test_naming_convention_learned_from_inventory(self):
        self.assertEqual(self.r['conventions']['codes'], {'swr': 'SWARM'})
        p = self.par['prdlabswr09']['role']
        self.assertEqual((p['value'], p['confidence']), ('SWARM', 'moyenne'))
        self.assertIn('3 serveur(s) déjà classé(s) SWARM', p['evidence'][0])

    def test_running_service_is_strong_evidence(self):
        p = self.par['prdlablog01']['role']
        self.assertEqual((p['value'], p['confidence']), ('ELASTIC', 'élevée'))

    def test_conflict_proposes_nothing_and_shows_both(self):
        p = self.par['prdlabswr08']['role']
        self.assertEqual((p['value'], p['confidence']), (None, 'conflit'))
        self.assertIn('lectures divergentes : DB (services) / SWARM (nom)', p['evidence'])

    def test_environment_from_prefix(self):
        self.assertEqual(self.par['reclabcha02']['environment']['value'], 'PREPROD')

    def test_critical_services_exclude_generic_tooling(self):
        self.assertEqual(self.par['prdlablog01']['services']['value'], ['elasticsearch'])
        self.assertEqual(self.par['recdcybdd01']['services']['value'], ['httpd', 'postgresql-9.6'])

    def test_classified_hosts_keep_their_role(self):
        self.assertNotIn('role', self.par['recdcybdd01'])


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.dossier = Path(tempfile.mkdtemp())
        self.hosts = [h('prdlablog01', fqdn='prdlablog01.host', vmid=12, documented={'backup': {'paths': '/x'}}),
                      h('autre', 'DB')]
        (self.dossier / 'hosts.yaml').write_text(json.dumps({'ssh': {'users': ['u']}, 'hosts': self.hosts}), encoding='utf-8')
        self.ctx = SimpleNamespace(BASE=self.dossier, HOSTS=[dict(x) for x in self.hosts], rows=lambda: [],
                                   lock=threading.Lock(), net_lock=threading.Lock(),
                                   job={'running': False}, net_job={'running': False})
        app = FastAPI()
        ic.install(app, self.ctx)
        self.apply = next(r.endpoint for r in all_routes(app) if getattr(r, 'path', '') == '/api/inventory/apply')

    def test_merge_preserves_every_other_field(self):
        self.apply(ic.Batch(changes=[ic.Change(key='prdlablog01', role='ELASTIC', services=['elasticsearch'])]))
        doc = json.loads((self.dossier / 'hosts.yaml').read_text(encoding='utf-8'))
        hote = doc['hosts'][0]
        self.assertEqual((hote['role'], hote['services'], hote['fqdn'], hote['vmid'], hote['documented']),
                         ('ELASTIC', ['elasticsearch'], 'prdlablog01.host', 12, {'backup': {'paths': '/x'}}))
        self.assertEqual(doc['ssh'], {'users': ['u']})
        self.assertEqual(doc['hosts'][1], self.hosts[1])
        self.assertEqual(self.ctx.HOSTS[0]['role'], 'ELASTIC')  # en mémoire aussi, sans redémarrage

    def test_services_are_added_not_replaced(self):
        self.ctx.HOSTS[0]['services'] = ['existant']
        doc = json.loads((self.dossier / 'hosts.yaml').read_text(encoding='utf-8'))
        doc['hosts'][0]['services'] = ['existant']
        (self.dossier / 'hosts.yaml').write_text(json.dumps(doc), encoding='utf-8')
        self.apply(ic.Batch(changes=[ic.Change(key='prdlablog01', services=['elasticsearch', 'existant'])]))
        self.assertEqual(self.ctx.HOSTS[0]['services'], ['existant', 'elasticsearch'])

    def test_refusals(self):
        with self.assertRaises(HTTPException) as e:
            self.apply(ic.Batch(changes=[ic.Change(key='inconnu', role='X')]))
        self.assertEqual(e.exception.status_code, 404)
        with self.assertRaises(HTTPException) as e:
            self.apply(ic.Batch(changes=[ic.Change(key='autre', services=['rm -rf /'])]))
        self.assertEqual(e.exception.status_code, 422)

    def test_provenance_distinguishes_proposal_and_operator_entry(self):
        self.apply(ic.Batch(changes=[ic.Change(key='prdlablog01', role='ELASTIC')]))
        self.assertEqual(self.ctx.HOSTS[0]['classification_source'], 'Validé par l’opérateur (proposition InfraOps)')
        self.apply(ic.Batch(changes=[ic.Change(key='prdlablog01', role='ANSIBLE / OUTILS INFRA', source='operateur')]))
        doc = json.loads((self.dossier / 'hosts.yaml').read_text(encoding='utf-8'))
        self.assertEqual(doc['hosts'][0]['classification_source'], 'Saisi par l’opérateur')
        self.assertEqual(self.ctx.HOSTS[0]['classification_source'], 'Saisi par l’opérateur')
        with self.assertRaises(Exception):
            ic.Change(key='x', role='y', source='autre')

    def test_allowed_while_collections_run(self):
        # Rôle et services ne changent pas l'accès au serveur : pas de refus pendant
        # une collecte (constaté : 12 refus d'affilée avec la rotation SSH à 60 s).
        self.ctx.job['running'] = self.ctx.net_job['running'] = True
        self.assertEqual(self.apply(ic.Batch(changes=[ic.Change(key='autre', role='X')]))['updated'], ['autre'])


if __name__ == '__main__':
    unittest.main()
