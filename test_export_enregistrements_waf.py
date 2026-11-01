"""Classeur des enregistrements du WAF par serveur : base et inventaire temporaires, aucun réseau."""
import testing_env  # noqa: F401 — garde-fou réseau et données isolées (AGENTS.md)
import json
import sqlite3
import tempfile
from contextlib import closing
import unittest
from pathlib import Path

import export_enregistrements_waf as export

HOSTS = [{'key': 'waf03', 'name': 'WAF03', 'ip': '10.0.0.131'},
         {'key': 'app01', 'name': 'app01', 'ip': '10.0.0.5', 'role': 'Web'},
         {'key': 'app02', 'name': 'app02', 'ip': '10.0.0.6'}]
WAF = {'applications': {'status': 'observed', 'collected_at': '2026-10-12T10:28:00+00:00', 'sites': [
    {'nom': 'portail.exemple.ma', 'url': 'https://portail.exemple.ma/', 'https': True,
     'dns': {'statut': 'en_ligne', 'adresses': ['203.0.113.9']}, 'fichiers': ['/etc/apache2/sites-enabled/p.conf'],
     'cibles': [{'chemin': '/', 'hote': '10.0.0.5', 'port': 3000, 'chemin_cible': '/', 'cible': '10.0.0.5:3000/'}]},
    {'nom': 'crm.exemple.local', 'url': 'http://crm.exemple.local/', 'https': False, 'dns': {'statut': 'interne'},
     'fichiers': ['/etc/apache2/sites-enabled/c.conf'],
     'cibles': [{'chemin': '/', 'hote': '10.0.0.6', 'port': 8080, 'chemin_cible': '/crm', 'cible': '10.0.0.6:8080/crm'}]},
    {'nom': '=HYPERLINK("http://x")', 'url': 'http://x/', 'https': False, 'dns': {}, 'fichiers': [],
     'cibles': [{'chemin': '/', 'hote': '10.9.9.9', 'port': 80, 'chemin_cible': '/', 'cible': '10.9.9.9:80/'}]},
    {'nom': 'statique.exemple.ma', 'url': 'https://statique.exemple.ma/', 'https': True, 'dns': {}, 'cibles': [],
     'racines': ['/var/www/statique'], 'fichiers': []}]}}
APP01 = {'applications': {'status': 'observed', 'collected_at': '2026-10-12T09:00:00+00:00', 'ports': ['22'],
                          'elements': [{'categorie': 'Conteneur', 'nom': 'portail',
                                        'detail': 'image p:1 ; ports 0.0.0.0:3000->3000/tcp'}]}}


class ExportTests(unittest.TestCase):
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
                           [('waf03', '10.0.0.131', json.dumps(WAF)), ('app01', '10.0.0.5', json.dumps(APP01)),
                            ('app02', '10.0.0.6', json.dumps({'status': 'ok'}))])

    def test_par_serveur_hors_inventaire_et_sans_cible(self):
        hotes, etats = export.charger(self.db, self.inventaire)
        publies, hors, sans_cible, _releve = export.lignes(hotes, etats, export.trouver_waf(hotes, '10.0.0.131'))
        par_site = {p['site']: p for p in publies}
        self.assertEqual(par_site['portail.exemple.ma']['serveur'], 'app01')
        self.assertEqual(par_site['portail.exemple.ma']['application'], 'Conteneur Docker portail')
        self.assertEqual(par_site['portail.exemple.ma']['dns'], 'En ligne (IP publique)')
        self.assertIn('indisponible', par_site['crm.exemple.local']['application'], 'jamais une application supposée')
        self.assertEqual([h['cible'] for h in hors], ['10.9.9.9:80'])
        self.assertEqual([s['site'] for s in sans_cible], ['statique.exemple.ma'])

    def test_classeur_sans_formule(self):
        try:
            import openpyxl
        except ImportError:
            self.skipTest('openpyxl absent de cet environnement (requirements-tools.txt)')
        sortie = self.base / 'sortie.xlsx'
        hotes, etats = export.charger(self.db, self.inventaire)
        waf = export.trouver_waf(hotes, 'waf03')
        export.ecrire(sortie, *export.lignes(hotes, etats, waf), waf)
        classeur = openpyxl.load_workbook(sortie)
        self.assertEqual(classeur.sheetnames, ['Par serveur', 'Synthèse par serveur', 'Hors inventaire',
                                               'Sites sans cible', 'Source et limites'])
        self.assertFalse(any(c.data_type == 'f' for f in classeur for ligne in f.iter_rows() for c in ligne))

    def test_waf_sans_releve_refuse(self):
        hotes, etats = export.charger(self.db, self.inventaire)
        etats['waf03'] = {'applications': {'status': 'unknown'}}
        with self.assertRaises(SystemExit):
            export.lignes(hotes, etats, export.trouver_waf(hotes, 'waf03'))


if __name__ == '__main__':
    unittest.main()
