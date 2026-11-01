"""Inventaire par VM : base et inventaire temporaires, aucun réseau."""
import testing_env  # noqa: F401 — garde-fou réseau et données isolées (AGENTS.md)
import json
import sqlite3
import tempfile
from contextlib import closing
import unittest
from pathlib import Path

import export_inventaire_vm as export
from export_enregistrements_waf import charger

HOSTS = [{'key': 'waf', 'name': 'waf', 'ip': '10.0.0.131'},
         {'key': 'app01', 'name': 'app01', 'ip': '10.0.0.5', 'role': 'Web', 'node': 'pve1', 'vmid': 101},
         {'key': 'bdd01', 'name': 'bdd01', 'ip': '10.0.0.7'},
         {'key': 'neuf', 'name': 'neuf', 'ip': '10.0.0.9'}]
MESURE = {'collected_at': '2026-10-12T09:00:00+00:00', 'coverage': {'measured': 10, 'total': 15}}
WAF = {**MESURE, 'status': 'ok', 'applications': {'status': 'observed', 'elements': [], 'ports': ['443'], 'sites': [
    {'nom': 'portail.exemple.ma', 'url': 'https://portail.exemple.ma/', 'https': True, 'dns': {'statut': 'en_ligne'},
     'cibles': [{'chemin': '/', 'hote': '10.0.0.5', 'port': 3000, 'chemin_cible': '/'}]}]}}
APP01 = {**MESURE, 'status': 'ok', 'os': 'Debian 12', 'uptime': '10:00 up 12 days, 1:00', 'cpu': 3, 'ram': 40,
         'storage': {'filesystems': [{'mount': '/', 'device': '/dev/sda1', 'fstype': 'ext4', 'total_kb': 41943040,
                                      'use_pct': 30},
                                     {'mount': '/run', 'device': 'tmpfs', 'fstype': 'tmpfs', 'total_kb': 1024}]},
         'applications': {'status': 'observed', 'ports': ['22', '3000'], 'docker': '1 conteneur(s)', 'elements': [
             {'categorie': 'Conteneur', 'source': 'Docker', 'nom': 'portail',
              'detail': 'image p:1 ; ports 0.0.0.0:3000->3000/tcp', 'etat': 'Up'},
             {'categorie': 'Agent', 'source': 'Service systemd', 'nom': 'zabbix-agent', 'etat': 'Démarré'}]}}
# Dernier audit en échec : le relevé réussi précédent est conservé dans last_observation.
BDD01 = {'status': 'unreachable', 'collected_at': '2026-10-13T08:00:00+00:00', 'coverage': {'measured': 0},
         'last_observation': {**MESURE, 'status': 'ok', 'applications': {
             'status': 'observed', 'ports': ['22', '5432', '1521'], 'elements': [
                 {'categorie': 'Base de données', 'source': 'Service systemd', 'nom': 'postgresql',
                  'detail': 'PostgreSQL', 'etat': 'Démarré'},
                 {'categorie': 'Processus applicatif', 'source': 'Java', 'nom': 'facturation.jar'}]}}}


class InventaireVmTests(unittest.TestCase):
    def setUp(self):
        dossier = tempfile.TemporaryDirectory()
        self.addCleanup(dossier.cleanup)
        self.base = Path(dossier.name)
        self.inventaire = self.base / 'hosts.yaml'
        self.inventaire.write_text(json.dumps({'hosts': HOSTS}), encoding='utf-8')
        self.db = self.base / 'state.sqlite3'
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('CREATE TABLE states(key TEXT PRIMARY KEY, ip TEXT, payload TEXT)')
            db.executemany('INSERT INTO states(key, ip, payload) VALUES(?,?,?)',
                           [('waf', '10.0.0.131', json.dumps(WAF)), ('app01', '10.0.0.5', json.dumps(APP01)),
                            ('bdd01', '10.0.0.7', json.dumps(BDD01))])

    def vms(self):
        vms, details, disques = export.construire(*charger(self.db, self.inventaire))
        return {v['serveur']: v for v in vms}, details, disques

    def test_conteneur_publie_identifie(self):
        vms, _details, disques = self.vms()
        app = vms['app01']
        self.assertEqual(app['statut'], export.IDENTIFIE)
        self.assertEqual(app['enregistrements'], 'portail.exemple.ma → :3000')
        self.assertEqual((app['noeud'], app['vmid'], app['uptime']), ('pve1', 101, 12))
        self.assertEqual([d['point'] for d in disques if d['serveur'] == 'app01'], ['/'], 'tmpfs exclu')
        self.assertNotIn('zabbix-agent', app['heberge'], 'un agent n’est pas une application hébergée')

    def test_injoignable_garde_le_dernier_releve(self):
        vms, _details, _disques = self.vms()
        bdd = vms['bdd01']
        self.assertEqual(bdd['etat'], 'Injoignable au dernier audit')
        self.assertEqual(bdd['statut'], export.A_CONFIRMER, 'application maison à qualifier')
        self.assertIn('facturation.jar', bdd['maison'])
        self.assertIn('PostgreSQL (Démarré)', bdd['bdd'])
        self.assertIn('Oracle ? (port 1521', bdd['bdd'])
        self.assertNotIn('PostgreSQL ?', bdd['bdd'], 'port déjà expliqué par un service reconnu')

    def test_partage_nfs_hors_capacite(self):
        obs = {'storage': {'filesystems': [
            {'mount': '/', 'device': '/dev/sda1', 'fstype': 'xfs', 'total_kb': 10485760, 'use_pct': 10},
            {'mount': '/mnt/partage', 'device': 'nas:/vol', 'fstype': 'nfs4', 'total_kb': 10737418240, 'use_pct': 50}]}}
        ligne, _elements, disques = export.ligne_vm({'key': 'x', 'ip': '10.0.0.2'}, obs, [])
        self.assertEqual(ligne['capacite'], '10 Go', 'un partage monté sur 20 VM ne compte pas 20 fois')
        self.assertEqual([d['nature'] for d in disques], ['Local', 'Réseau ou agrégé'])

    def test_vue_globale(self):
        vms, details, disques = self.vms()
        sections = {titre: lignes for titre, _entetes, lignes in
                    export.vue_globale(list(vms.values()), export.par_application(details), disques)}
        cles = dict(sections['Chiffres clés'])
        self.assertEqual(cles['VM inventoriées'], 4)
        self.assertEqual(cles['VM sans relevé des applications'], 1)
        self.assertIn('Points d’attention', sections)

    def test_sans_releve(self):
        vms, _details, _disques = self.vms()
        self.assertEqual(vms['neuf']['statut'], export.NON_RELEVE)

    def test_en_ligne_seulement_les_vm_qui_repondent(self):
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('CREATE TABLE network(key TEXT PRIMARY KEY, ip TEXT, payload TEXT)')
            db.executemany('INSERT INTO network VALUES(?,?,?)', [
                ('app01', '10.0.0.5', json.dumps({'ping': True, 'collected_at': '2026-10-13T08:09:00+00:00'})),
                ('bdd01', '10.0.0.7', json.dumps({'ping': False}))])
        hotes, etats = charger(self.db, self.inventaire)
        vms, _details, disques = export.construire(hotes, etats, export.pings(self.db), en_ligne=True)
        self.assertEqual([v['serveur'] for v in vms], ['app01'], 'ni « ne répond pas », ni « non testé »')
        self.assertEqual(vms[0]['enregistrements'], 'portail.exemple.ma → :3000', 'WAF lu même hors filtre')
        self.assertEqual({d['serveur'] for d in disques}, {'app01'})
        tous = {v['serveur']: v['ping'] for v in export.construire(hotes, etats, export.pings(self.db))[0]}
        self.assertEqual(tous, {'app01': 'Répond', 'bdd01': 'Ne répond pas', 'neuf': 'Non testé', 'waf': 'Non testé'})

    def test_par_application(self):
        _vms, details, _disques = self.vms()
        details.append({**details[-1], 'serveur': 'bdd02', 'ip': '10.0.0.8', 'nom': 'postgresql-15',
                        'categorie': 'Base de données', 'source': 'Service systemd', 'detail': 'PostgreSQL',
                        'statut': export.IDENTIFIE, 'sites_publies': []})
        apps = {a['application']: a for a in export.par_application(details)}
        self.assertNotIn('zabbix-agent', apps, 'socle exclu')
        self.assertEqual(apps['PostgreSQL']['nb'], 2, 'produit regroupé quelle que soit la version')
        self.assertEqual(apps['PostgreSQL']['serveurs'], 'bdd01 (10.0.0.7), bdd02 (10.0.0.8)')
        self.assertEqual(apps['PostgreSQL']['composants'], 'postgresql, postgresql-15')
        self.assertEqual(apps['portail']['sites'], 'portail.exemple.ma', 'enregistrement du WAF rattaché')
        self.assertEqual(apps['portail']['statut'], export.IDENTIFIE)
        self.assertEqual(apps['facturation.jar']['statut'], export.A_CONFIRMER)

    def test_processus_produit_tomcat_et_nom_generique(self):
        def processus(serveur, nom):
            e = {'serveur': serveur, 'ip': '10.0.0.1', 'categorie': 'Processus applicatif', 'source': 'Java', 'nom': nom}
            statut, justification = export.classer(e, set())
            return {**e, 'statut': statut, 'justification': justification}
        service = {'serveur': 'ela01', 'ip': '10.0.0.1', 'categorie': 'Recherche / journaux', 'source': 'Service systemd',
                   'nom': 'elasticsearch', 'detail': 'Elasticsearch', 'statut': export.IDENTIFIE, 'justification': 'x'}
        details = [service, processus('ela01', 'elasticsearch'), processus('srv1', 'tomcat-demoapp-9.0.43'),
                   processus('srv1', 'app.jar'), processus('srv2', 'app.jar')]
        apps = {a['application']: a for a in export.par_application(details)}
        self.assertEqual((apps['Elasticsearch']['nb'], apps['Elasticsearch']['statut']), (1, export.IDENTIFIE),
                         'service et processus du même produit : une seule ligne')
        self.assertEqual(apps['tomcat-demoapp-9.0.43']['statut'], export.IDENTIFIE)
        self.assertIn('app.jar sur srv1', apps, 'nom générique : jamais regroupé entre VM')
        self.assertIn('app.jar sur srv2', apps)

    def test_classeur(self):
        try:
            import openpyxl
        except ImportError:
            self.skipTest('openpyxl absent de cet environnement (requirements-tools.txt)')
        sortie = self.base / 'vm.xlsx'
        export.ecrire(sortie, *export.construire(*charger(self.db, self.inventaire)))
        classeur = openpyxl.load_workbook(sortie)
        self.assertEqual(classeur.sheetnames, ['Vue globale', 'Inventaire par VM', 'Par application', 'Détail applications', 'Disques',
                                               'Source et limites'])
        self.assertFalse(any(c.data_type == 'f' for f in classeur for ligne in f.iter_rows() for c in ligne))


if __name__ == '__main__':
    unittest.main()
