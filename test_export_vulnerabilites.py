"""Classeur d'audit des vulnérabilités et des correctifs : base et inventaire temporaires, aucun réseau."""
import testing_env  # noqa: F401 — garde-fou réseau et données isolées (AGENTS.md)
import json
import sqlite3
import tempfile
from contextlib import closing
import unittest
from pathlib import Path

import export_vulnerabilites as export
import security_cve as sc

HOSTS = [{'key': 'deb01', 'name': 'deb01', 'ip': '10.0.0.5', 'environment': 'PROD', 'vmid': 115, 'node': 'pve04',
          'services': ['apache2']},
         {'key': 'deb02', 'name': 'deb02', 'ip': '10.0.0.6', 'environment': 'RECETTE'}]
PAQUETS = [{'name': 'libssl3', 'version': '3.0.20-1~deb12u2', 'source': 'openssl', 'source_version': '3.0.20-1~deb12u2'},
           {'name': 'linux-libc-dev', 'version': '6.1.174-1', 'source': 'linux', 'source_version': '6.1.174-1'},
           {'name': 'linux-image-6.1.0-13-amd64', 'version': '6.1.55-1', 'source': 'linux-signed-amd64',
            'source_version': '6.1.55+1'},
           {'name': 'linux-image-6.1.0-50-amd64', 'version': '6.1.176-1', 'source': 'linux-signed-amd64',
            'source_version': '6.1.176+1'},
           {'name': 'linux-image-amd64', 'version': '6.1.176-1', 'source': 'linux-signed-amd64', 'source_version': '6.1.176+1'}]
RELEVE = {'os': {'id': 'debian', 'version_id': '12', 'pretty': 'Debian GNU/Linux 12 (bookworm)'}, 'kernel': '6.1.0-13-amd64',
          'reboot_required': False, 'manager': 'dpkg', 'packages': PAQUETS}
SANS_DEPOT = 'Version corrigée non proposée par les dépôts configurés (dépôt security absent ou cache apt ancien)'


def vuln(host, cve, package, installed, fixed, binaires, depot=SANS_DEPOT):
    evidence = {'manager': 'dpkg', 'binaries': list(binaires), 'binary_versions': binaires, 'repository': depot,
                'confidence': 'confirmé'}
    return (sc.vuln_id(host, cve), host, cve, package, installed, fixed, '["debian"]', 'confirmé', json.dumps(evidence),
            'open', '2026-10-01T00:00:00+00:00', '2026-10-30T00:00:00+00:00', '2026-10-30T00:00:00+00:00')


class ExportTests(unittest.TestCase):
    def setUp(self):
        dossier = tempfile.TemporaryDirectory()
        self.addCleanup(dossier.cleanup)
        self.base = Path(dossier.name)
        self.inventaire = self.base / 'hosts.yaml'
        self.inventaire.write_text(json.dumps({'hosts': HOSTS}), encoding='utf-8')
        self.db = self.base / 'state.sqlite3'
        ssl = {'libssl3': '3.0.20-1~deb12u2'}
        with closing(sqlite3.connect(self.db)) as db, db:
            sc.migrate(db)
            db.executemany('INSERT INTO sec_vulns(id, host_key, cve, package, installed, fixed, sources, confidence, evidence, '
                           'status, first_seen, last_seen, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)', [
                               vuln('deb01', 'CVE-2026-0001', 'openssl', '3.0.20-1~deb12u2', '3.0.22-1~deb12u1', ssl),
                               vuln('deb01', 'CVE-2026-0002', 'openssl', '3.0.20-1~deb12u2', '3.0.22-1~deb12u2', ssl,
                                    'Correctif disponible dans les dépôts configurés : 3.0.22-1~deb12u1 (oldstable-security)'),
                               vuln('deb01', 'CVE-2026-0003', 'linux', '6.1.174-1', '6.1.190-1', {'linux-libc-dev': '6.1.174-1'}),
                               vuln('deb02', 'CVE-2026-0001', 'openssl', '3.0.20-1~deb12u2', '3.0.22-1~deb12u1', ssl)])
            db.executemany('INSERT INTO sec_cve(cve, cvss, description, kev, kev_due) VALUES(?,?,?,?,?)', [
                ('CVE-2026-0001', 9.8, '=HYPERLINK("http://x")', 1, '2026-11-10'),
                ('CVE-2026-0002', 7.5, 'TLS', 0, None), ('CVE-2026-0003', 5.5, 'noyau', 0, None)])
            db.execute('INSERT INTO sec_inventory(host_key, host_ip, collected_at, complete, payload) VALUES(?,?,?,?,?)',
                       ('deb01', '10.0.0.5', '2026-10-30T09:31:43+00:00', 1, json.dumps(RELEVE)))

    def donnees(self, serveurs=()):
        hotes, vulns, releves = export.charger(self.db, self.inventaire, serveurs)
        lignes = export.paquets(vulns, releves, hotes)
        return hotes, vulns, lignes, export.serveurs(lignes, releves, hotes)

    def test_version_cible_depots_et_noyau(self):
        _hotes, _vulns, lignes, _synthese = self.donnees()
        par_cle = {(g['cle'], g['paquet']): g for g in lignes}
        ssl = par_cle[('deb01', 'openssl')]
        self.assertEqual(ssl['cible'], '3.0.22-1~deb12u2', 'plus haute version corrigée : couvre toutes les CVE')
        self.assertTrue(ssl['disponible'].startswith('Partiel'), 'candidat des dépôts inférieur à la cible')
        self.assertEqual(ssl['commande'], 'sudo apt-get install --only-upgrade libssl3')
        noyau = par_cle[('deb01', 'linux')]
        self.assertIn('linux-image-amd64', noyau['noms'], 'métapaquet ajouté : sinon seuls les en-têtes sont mis à jour')
        self.assertEqual(noyau['prise'], 'reboot')
        self.assertEqual(par_cle[('deb02', 'openssl')]['disponible'], 'Non : dépôt security absent ou cache apt ancien')

    def test_ordre_et_synthese(self):
        _hotes, _vulns, _lignes, synthese = self.donnees()
        self.assertEqual([s['cle'] for s in synthese], ['deb01', 'deb02'], 'KEV et production en premier')
        deb01 = synthese[0]
        self.assertEqual(deb01['redemarrage'], 'Oui')
        self.assertIn('Redémarrage en attente', deb01['noyau'])
        self.assertEqual(deb01['instantane'], 'VM 115 sur pve04')
        self.assertTrue(deb01['commande'].startswith('sudo apt-get update && sudo apt-get install --only-upgrade'))
        self.assertEqual(synthese[1]['noyau'], 'Non relevé')

    def test_plan_texte_seulement(self):
        _hotes, _vulns, _lignes, synthese = self.donnees()
        etapes = export.plan(synthese[0], '20261031')
        commandes = [e['commande'] for e in etapes]
        self.assertIn('qm snapshot 115 avant-patch-20261031 --description "OpsControl correctifs 20261031"', commandes)
        self.assertIn('sudo needrestart -r l', commandes)
        self.assertIn('sudo systemctl reboot', commandes, 'noyau : redémarrage proposé, jamais exécuté')
        self.assertIn('qm rollback 115 avant-patch-20261031', commandes)
        self.assertEqual([e['n'] for e in etapes], list(range(1, len(etapes) + 1)))
        self.assertTrue(any("ge 3.0.22-1~deb12u2 && echo 'CORRIGÉ openssl'" in c for c in commandes))

    def test_selection_serveur(self):
        _hotes, vulns, _lignes, synthese = self.donnees(['10.0.0.6'])
        self.assertEqual({v['host_key'] for v in vulns}, {'deb02'})
        self.assertEqual(len(synthese), 1)
        with self.assertRaises(SystemExit):
            self.donnees(['inconnu'])

    def test_classeur_sans_formule(self):
        try:
            import openpyxl
        except ImportError:
            self.skipTest('openpyxl absent de cet environnement (requirements-tools.txt)')
        _hotes, vulns, lignes, synthese = self.donnees()
        sortie = self.base / 'sortie.xlsx'
        export.ecrire(sortie, synthese, lignes, vulns, stamp='20261031')
        classeur = openpyxl.load_workbook(sortie)
        self.assertEqual(classeur.sheetnames, ['Synthèse serveurs', 'Paquets à corriger', 'Plan de correction',
                                               'Détail CVE', 'Source et limites'])
        self.assertFalse(any(c.data_type == 'f' for f in classeur for ligne in f.iter_rows() for c in ligne))
        self.assertEqual(classeur['Détail CVE'].max_row, len(vulns) + 1)
        export.ecrire(sortie, synthese, lignes, vulns, detail=False)
        self.assertNotIn('Détail CVE', openpyxl.load_workbook(sortie).sheetnames)


if __name__ == '__main__':
    unittest.main()
