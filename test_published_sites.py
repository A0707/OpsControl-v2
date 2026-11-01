"""Enregistrements du WAF publiés vers chaque serveur (published_sites.py). Données simulées."""
import unittest

import published_sites as ps


def waf(sites):
    return {'key': 'waf01', 'name': 'WAF01', 'ip': '10.0.0.2',
            'applications': {'status': 'observed', 'collected_at': '2026-10-10T08:00:00+00:00', 'sites': sites}}


def site(nom, cibles, statut='en_ligne'):
    return {'nom': nom, 'url': f'https://{nom}/', 'https': True, 'dns': {'statut': statut, 'adresses': ['203.0.113.9']},
            'cibles': cibles}


APP = {'key': 'app01', 'name': 'app01', 'ip': '10.0.0.5', 'fqdn': 'app01.exemple.local',
       'applications': {'status': 'observed', 'ports': ['22', '8080'], 'elements': [
           {'categorie': 'Conteneur', 'nom': 'portail', 'detail': 'image portail:2 ; ports 0.0.0.0:3000->3000/tcp'},
           {'categorie': 'Application web (Tomcat)', 'nom': 'crm', 'detail': ''}]}}


class PublishedSitesTests(unittest.TestCase):
    def test_enregistrements_vers_le_serveur_par_ip_et_par_nom(self):
        assets = [APP, waf([
            site('portail.exemple.ma', [{'chemin': '/', 'cible': '10.0.0.5:3000/', 'hote': '10.0.0.5', 'port': 3000,
                                         'chemin_cible': '/'}]),
            site('crm.exemple.local', [{'chemin': '/crm', 'cible': 'app01:8080/crm'}], 'interne'),   # relevé antérieur
            site('autre.exemple.ma', [{'chemin': '/', 'cible': '10.0.0.99:80/', 'hote': '10.0.0.99', 'port': 80}]),
            site('local.exemple.ma', [{'chemin': '/', 'cible': '127.0.0.1:8080/', 'hote': '127.0.0.1', 'port': 8080}])])]
        publies = {p['site']: p for p in ps.published_to(APP, assets)}
        self.assertEqual(set(publies), {'portail.exemple.ma', 'crm.exemple.local'},
                         'cibles locales du WAF et autres serveurs exclues')
        self.assertEqual(publies['portail.exemple.ma']['application'], 'Conteneur Docker portail')
        self.assertEqual((publies['crm.exemple.local']['port'], publies['crm.exemple.local']['application']),
                         (8080, 'Application Tomcat crm'))
        self.assertEqual(publies['portail.exemple.ma']['via'], {'key': 'waf01', 'name': 'WAF01'})
        self.assertEqual(publies['crm.exemple.local']['dns']['statut'], 'interne')

    def test_port_non_en_ecoute_et_releve_absent(self):
        cible = [{'chemin': '/', 'cible': '10.0.0.5:9090/', 'hote': '10.0.0.5', 'port': 9090}]
        self.assertIn('non en écoute', ps.published_to(APP, [APP, waf([site('x.exemple', cible)])])[0]['application'])
        sans_releve = {**APP, 'applications': {'status': 'unknown'}}
        p = ps.published_to(sans_releve, [sans_releve, waf([site('x.exemple', cible)])])[0]
        self.assertIn('indisponible', p['application'], 'jamais une application supposée')

    def test_waf_sans_releve_ignore(self):
        muet = {'key': 'waf02', 'applications': {'status': 'unknown', 'sites': [site('y', [{'cible': '10.0.0.5:80/'}])]}}
        self.assertEqual(ps.published_to(APP, [APP, muet]), [])

    def test_cibles_du_waf_annotees_avec_le_serveur(self):
        source = waf([site('portail.exemple.ma', [{'chemin': '/', 'cible': 'app01.exemple.local:3000/'}])])
        ps.annotate_targets(source, [APP, source])
        self.assertEqual(source['applications']['sites'][0]['cibles'][0]['serveur'], {'key': 'app01', 'name': 'app01'})


if __name__ == '__main__':
    unittest.main()
