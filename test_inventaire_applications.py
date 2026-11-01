import testing_env  # noqa: F401 — garde-fou réseau et données isolées (AGENTS.md)
import re
import unittest
from unittest import mock

import inventaire_applications as inv
import ssh

SORTIE = """##OS
Debian GNU/Linux 12 (bookworm)
##RUNNING
ssh.service
cron.service
tomcat9.service
postgresql@15-main.service
zabbix-agent2.service
facturation.service
##ENABLED
ssh.service
mariadb.service
rhel-readonly.service
facturation.service
##PORTS
0.0.0.0:22
[::]:8080
127.0.0.1:5432
##JAVA
-Dcatalina.base=/var/lib/tomcat9/
-jar /opt/facturation/facturation-2.1.jar
##NODE
##PYTHON
##PHP
php-fpm: pool www
##DOCKER
RC|0
web|nginx:1.25|Up 3 days|0.0.0.0:80->80/tcp
##SWARM
##VHOSTS
/etc/apache2/sites-enabled/app.conf:    ServerName app.exemple.ma
/etc/apache2/sites-enabled/app-ssl.conf:    ServerName app.exemple.ma
/etc/nginx/sites-enabled/default:    server_name _ api.exemple.ma;
##WEBAPPS
1640000000|/var/lib/tomcat9/webapps/ROOT
1645000000|/var/lib/tomcat9/webapps/facture.war
1646000000|/var/lib/tomcat9/webapps/facture
##DIRS
/opt/facturation
\x1b[92m Bannière de fin de session \x1b[0m
"""


class AnalyseTests(unittest.TestCase):
    def setUp(self):
        self.resultat = inv.analyser(SORTIE)
        self.par_nom = {(e['source'], e['nom']): e for e in self.resultat['elements']}

    def test_services_metier_connus_et_socle_ignore(self):
        self.assertEqual(self.par_nom[('Service systemd', 'tomcat9')]['categorie'], "Serveur d'applications")
        self.assertEqual(self.par_nom[('Service systemd', 'facturation')]['categorie'],
                         'Service spécifique (à qualifier)')
        self.assertEqual(self.par_nom[('Service systemd', 'zabbix-agent2')]['categorie'], 'Agent')
        # Produit connu activé mais arrêté : signalé comme tel.
        self.assertEqual(self.par_nom[('Service systemd', 'mariadb')]['etat'], 'Activé mais arrêté')
        noms = {e['nom'] for e in self.resultat['elements']}
        self.assertFalse({'ssh', 'cron', 'rhel-readonly'} & noms)

    def test_conteneurs_sites_webapps_et_processus(self):
        self.assertEqual(self.resultat['docker'], '1 conteneur(s)')
        self.assertIn('nginx:1.25', self.par_nom[('Docker', 'web')]['detail'])
        sites = [e['nom'] for e in self.resultat['elements'] if e['categorie'] == 'Site web']
        self.assertEqual(sites, ['api.exemple.ma', 'app.exemple.ma'])
        webapps = [e['nom'] for e in self.resultat['elements'] if e['source'] == 'Tomcat']
        self.assertEqual(webapps, ['facture'])
        self.assertIn(('Java', 'facturation-2.1.jar'), self.par_nom)
        self.assertIn(('Java', 'tomcat9'), self.par_nom)
        self.assertIn(('PHP-FPM', 'www'), self.par_nom)

    def test_ports_os_et_banniere_filtree(self):
        self.assertEqual(self.resultat['ports'], ['22', '5432', '8080'])
        self.assertEqual(self.resultat['os'], 'Debian GNU/Linux 12 (bookworm)')
        self.assertEqual(self.resultat['dossiers'], ['/opt/facturation'])

    def test_docker_refuse_n_est_pas_une_absence(self):
        sortie = '##DOCKER\nRC|1\npermission denied while trying to connect to the Docker daemon socket\n'
        self.assertEqual(inv.analyser(sortie)['docker'], 'Accès refusé (droits)')
        self.assertEqual(inv.analyser('##DOCKER\nABSENT\n')['docker'], 'Absent')


class DatesApplicationsTests(unittest.TestCase):
    SORTIE = """##RUNNING
tomcat9.service
postgresql@15-main.service
facturation.service
legacy.service
##UNITFILES
1650000000|/lib/systemd/system/tomcat9.service
1700000000|/etc/systemd/system/tomcat9.service
1660000000|/lib/systemd/system/postgresql@.service
1690000000|/etc/systemd/system/facturation.service
1600000000|/etc/init.d/legacy
##JAVA
-jar /opt/facturation/facturation-2.1.jar|1695000000
-Dcatalina.base=/var/lib/tomcat9/|
##DOCKER
RC|0
web|nginx:1.25|Up 3 days|0.0.0.0:80->80/tcp|2024-01-06 12:00:00 +0100 CET
##VHOSTS
/etc/apache2/sites-enabled/app.conf:    ServerName app.exemple.ma
##VHOSTFILES
1680000000|/etc/apache2/sites-enabled/app.conf
##WEBAPPS
1640000000|/var/lib/tomcat9/webapps/facture
1645000000|/var/lib/tomcat9/webapps/facture.war
1600000000|/var/lib/tomcat9/webapps/ROOT
"""

    def test_chaque_application_porte_sa_date_et_sa_nature(self):
        elements = {(e['source'], e['nom']): e for e in inv.analyser(self.SORTIE)['elements']}
        # Fichier du paquet prioritaire sur l'override de /etc ; instance -> modèle ; init.d en repli.
        self.assertEqual(elements[('Service systemd', 'tomcat9')]['date'], 1650000000)
        self.assertEqual(elements[('Service systemd', 'tomcat9')]['nature_date'], inv.NATURE_SERVICE)
        self.assertEqual(elements[('Service systemd', 'postgresql@15-main')]['date'], 1660000000)
        self.assertEqual(elements[('Service systemd', 'facturation')]['date'], 1690000000)
        self.assertEqual(elements[('Service systemd', 'legacy')]['date'], 1600000000)
        self.assertEqual(elements[('Java', 'facturation-2.1.jar')]['date'], 1695000000)
        self.assertIsNone(elements[('Java', 'tomcat9')]['date'])
        self.assertEqual(elements[('Java', 'tomcat9')]['nature_date'], '')
        self.assertEqual(elements[('Docker', 'web')]['date'], 1704538800)
        self.assertEqual(elements[('Docker', 'web')]['nature_date'], inv.NATURE_CONTENEUR)
        self.assertEqual(elements[('Apache', 'app.exemple.ma')]['date'], 1680000000)
        # Le .war prévaut sur le dossier déployé ; ROOT est ignoré.
        self.assertEqual(elements[('Tomcat', 'facture')]['date'], 1645000000)
        self.assertNotIn(('Tomcat', 'ROOT'), elements)


class InstallationTests(unittest.TestCase):
    def test_source_la_plus_fiable_et_valeurs_invalides_ignorees(self):
        self.assertEqual(inv.date_installation(['RPM|1588204566', 'ROOT|1700000000']),
                         (1588204566, 'Paquet basesystem (rpm)'))
        self.assertEqual(inv.date_installation(['INSTALLER|1694461233', 'ROOT|0'])[1],
                         "Journal de l'installeur Debian/Ubuntu")
        # stat %W sans support : 0 ou « - » ; horloge non réglée : avant 2005.
        self.assertEqual(inv.date_installation(['ROOT|-', 'ROOT|0', 'RPM|86400']), (None, ''))
        self.assertEqual(inv.analyser('##INSTALL\nROOT|1700000000\n')['installation'], 1700000000)

    def test_memorisation_fusionne_avec_le_releve_precedent(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as dossier:
            fichier = Path(dossier) / 'installation.json'
            ancien = {'hote': {'key': 'a', 'vmid': 1}, 'collecte': 'OK', 'installation': 1600000000,
                      'installation_source': 'x', 'elements': [{'categorie': 'Base de données', 'nom': 'mariadb',
                                                                'detail': 'jamais conservé', 'date': 1650000000}]}
            inv.memoriser_releve([ancien], fichier)
            injoignable = {'hote': {'key': 'a', 'vmid': 1}, 'collecte': 'Injoignable'}
            nouveau = {'hote': {'key': 'b', 'vmid': 2}, 'collecte': 'OK', 'installation': None, 'elements': []}
            connues = inv.memoriser_releve([injoignable, nouveau], fichier)
        self.assertEqual(connues['a']['installation'], 1600000000)
        self.assertEqual(connues['a']['applications'][0]['date'], 1650000000)
        self.assertNotIn('detail', connues['a']['applications'][0])
        self.assertEqual(connues['b']['vmid'], 2)


class CommandeTests(unittest.TestCase):
    def test_operation_figee_en_lecture_seule(self):
        commande = ssh.OPERATIONS['apps']
        self.assertIs(commande, inv.COMMAND)
        self.assertNotIn('sudo', commande)
        for interdit in (r'\bsystemctl (start|stop|restart|enable|disable)', r'docker (rm|stop|kill|exec|run)',
                         r'\brm ', r'(?<![2&])>\s*/(?!dev/null)'):
            self.assertIsNone(re.search(interdit, commande), interdit)
        # Jamais de ligne de commande complète : chaque lecture de ps finit par un grep -o.
        lectures = [suite.split(';', 1)[0] for suite in commande.split(inv._PS)[1:]]
        self.assertEqual(len(lectures), 4)
        for lecture in lectures:
            self.assertIn('grep -o', lecture)

    def test_releve_essaie_le_compte_connu_en_premier(self):
        cfg = ssh.SSHConfig(user='a', key_path='k', users=('a', 'b'), ports=(22,))
        hote = {'key': 'srv', 'ip': '10.0.0.1'}
        reponse = ssh.RunResult(True, 0, SORTIE, '', 10)
        with mock.patch.object(ssh, 'run_operation', return_value=reponse) as appel:
            resultat = inv.relever(hote, cfg, ('b', 22))
        self.assertEqual(resultat['collecte'], 'OK')
        self.assertEqual(resultat['compte'], 'b:22')
        self.assertEqual(appel.call_count, 1)
        self.assertEqual(appel.call_args.args[1], 'apps')

    def test_serveur_injoignable_signale(self):
        cfg = ssh.SSHConfig(user='a', key_path='k', users=('a',), ports=(22,))
        echec = ssh.RunResult(False, None, '', 'Cible inaccessible', 10, 'network')
        with mock.patch.object(ssh, 'run_operation', return_value=echec):
            resultat = inv.relever({'key': 'srv', 'ip': '10.0.0.1'}, cfg)
        self.assertEqual(resultat['collecte'], 'Injoignable')
        self.assertEqual(inv.relever({'key': 'x'}, cfg)['collecte'], 'Désactivée')


class SortieInattendueTests(unittest.TestCase):
    """Audit GIT-01 : une connexion établie sans sortie de sonde n'est jamais « OK »."""

    def test_compte_nologin_ou_sortie_tronquee(self):
        cfg = ssh.SSHConfig(user='a', key_path='k', users=('a',), ports=(22,))
        hote = {'key': 'srv', 'ip': '10.0.0.1'}
        for reponse in (ssh.RunResult(False, 1, 'This account is currently not available.', '', 5),
                        ssh.RunResult(True, 0, '##OS\nDebian\n##RUNNING\n', '', 5),
                        ssh.RunResult(False, 127, '', 'sh: systemctl: not found', 5)):
            with self.subTest(sortie=reponse.stdout or reponse.stderr), \
                    mock.patch.object(ssh, 'run_operation', return_value=reponse):
                resultat = inv.relever(hote, cfg)
            self.assertEqual(resultat['collecte'], 'Sortie inattendue')
            self.assertTrue(resultat['erreur'])

    def test_releve_precedent_conserve(self):
        import json
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as dossier:
            fichier = Path(dossier) / 'releve.json'
            fichier.write_text(json.dumps({'srv': {'name': 'srv', 'applications': [{'nom': 'tomcat'}]}}), encoding='utf-8')
            inv.memoriser_releve([{'hote': {'key': 'srv'}, 'collecte': 'Sortie inattendue'}], fichier)
            self.assertEqual(json.loads(fichier.read_text(encoding='utf-8'))['srv']['applications'], [{'nom': 'tomcat'}])


class PaquetsTests(unittest.TestCase):
    def test_liste_fermee_lue_sans_root(self):
        commande = inv.COMMAND
        self.assertIn("dpkg-query -W", commande)
        self.assertIn("rpm -qa --qf", commande)
        self.assertNotRegex(commande, r'\b(apt|apt-get|yum|dnf|zypper)\b', 'jamais de gestionnaire qui écrit')
        filtre = re.compile('^(' + inv._PAQUETS + ')$')
        for nom in ('openjdk-17-jre-headless', 'java-11-openjdk-headless', 'tomcat9', 'postgresql-15',
                    'mariadb-server', 'php8.2-fpm', 'docker-ce', 'zabbix-agent2', 'openssl'):
            self.assertRegex(nom, filtre)
        for nom in ('curl', 'libapache2-mod-php', 'postgresql-client-15', 'linux-image-amd64'):
            self.assertNotRegex(nom, filtre)

    def test_analyse_et_lignes_inattendues_ignorees(self):
        sortie = ('##OS\nDebian\n##PAQUETS\nKERNEL|6.1.0-25-amd64\ndpkg|postgresql-15|15.8-0+deb12u1\n'
                  'dpkg|apache2|2.4.62-1~deb12u2\ndpkg|=HYPERLINK("x")|1\nrpm|nginx|1.20 ; rm\n##DIRS\n')
        releve = inv.analyser(sortie)
        self.assertEqual(releve['noyau'], '6.1.0-25-amd64')
        self.assertEqual([(p['nom'], p['version']) for p in releve['paquets']],
                         [('apache2', '2.4.62-1~deb12u2'), ('postgresql-15', '15.8-0+deb12u1')])

    def test_releve_ancien_sans_section(self):
        releve = inv.analyser('##OS\nDebian\n##DIRS\n')
        self.assertIsNone(releve['paquets'], 'section absente : non relevé, pas « aucun »')


class ClasseurTests(unittest.TestCase):
    """Audit NEW-01 : une valeur venue d'un serveur n'est jamais une formule dans le classeur."""

    def test_formule_ecrite_comme_texte(self):
        try:
            import openpyxl
        except ImportError:
            self.skipTest('openpyxl absent de cet environnement (requirements-tools.txt)')
        import tempfile
        from pathlib import Path
        sortie = SORTIE.replace('##VHOSTS', '##VHOSTS\n/etc/apache2/sites-enabled/x.conf:ServerName =HYPERLINK("http://x")')
        resultat = {'hote': {'key': 'srv', 'name': 'srv', 'ip': '10.0.0.1'}, 'collecte': 'OK', 'compte': 'a:22',
                    'erreur': '', **inv.analyser(sortie)}
        with tempfile.TemporaryDirectory() as dossier:
            chemin = Path(dossier) / 'apps.xlsx'
            inv.ecrire(chemin, [resultat])
            classeur = openpyxl.load_workbook(chemin)
            formules = [c.coordinate for feuille in classeur for ligne in feuille.iter_rows() for c in ligne
                        if c.data_type == 'f']
        self.assertEqual(formules, [])


if __name__ == '__main__':
    unittest.main()


class AuditSshTests(unittest.TestCase):
    """Relevé des applications pendant l'audit SSH (onglet « Applications » de la fiche)."""

    def setUp(self):
        self.cfg = ssh.SSHConfig(user='a', key_path='k', users=('a',), ports=(22,))
        self.hote = {'key': 'srv', 'ip': '10.0.0.1'}
        self.systeme = {'ssh_user': 'b', 'ssh_port': 2222}

    def test_releve_complet_avec_le_compte_qui_a_reussi(self):
        import collector
        with mock.patch.object(collector, 'run_operation', return_value=ssh.RunResult(True, 0, SORTIE, '', 5)) as appel:
            apps = collector.collect_applications(self.hote, self.cfg, self.systeme, 'test')
        self.assertEqual(apps['status'], 'observed')
        self.assertTrue(apps['elements'])
        self.assertIn('collected_at', apps)
        ip, operation, candidat, _ = appel.call_args.args
        self.assertEqual((ip, operation, candidat.user, candidat.port), ('10.0.0.1', 'apps', 'b', 2222))

    def test_sortie_incomplete_jamais_aucune_application(self):
        import collector
        for reponse in (ssh.RunResult(False, 1, 'This account is currently not available.', '', 5),
                        ssh.RunResult(False, None, '', 'Délai dépassé', 5, 'network')):
            with self.subTest(r=reponse.stdout or reponse.stderr), \
                    mock.patch.object(collector, 'run_operation', return_value=reponse):
                apps = collector.collect_applications(self.hote, self.cfg, self.systeme, 'test')
            self.assertEqual(apps['status'], 'unknown')
            self.assertNotIn('elements', apps)
            self.assertIn('indisponible', apps['error'])

    def test_retire_des_listes_garde_dans_la_fiche(self):
        import payload_slim
        hote = {'key': 'srv', 'applications': {'status': 'observed', 'elements': [{'nom': 'nginx'}]}}
        self.assertNotIn('applications', payload_slim.slim(hote))


class SitesWebTests(unittest.TestCase):
    """Sites web : lien, application qui sert le site, et portée DNS (interne / en ligne)."""

    CONF = ['/etc/apache2/sites-enabled/app.conf:<VirtualHost *:443>',
            '/etc/apache2/sites-enabled/app.conf:  ServerName app.exemple.local',
            '/etc/apache2/sites-enabled/app.conf:  ServerAlias *.joker.local',
            '/etc/apache2/sites-enabled/app.conf:  SSLEngine on',
            '/etc/apache2/sites-enabled/app.conf:  ProxyPass /api http://127.0.0.1:8080/api',
            # Identifiants factices : le test vérifie qu'ils sont retirés.
            '/etc/apache2/sites-enabled/app.conf:  ProxyPass / http://utilisateur:motdepasse@127.0.0.1:3000/',  # pragma: allowlist secret
            '/etc/nginx/sites-enabled/portail:    listen 80;',
            '/etc/nginx/sites-enabled/portail:    server_name portail.exemple.ma;',
            '/etc/nginx/sites-enabled/portail:    root /var/www/portail;',
            '/etc/nginx/sites-enabled/portail:    proxy_pass http://127.0.0.1:9999;']

    def test_application_retrouvee_par_le_port_et_identifiants_retires(self):
        sites = {s['nom']: s for s in inv.sites_web(self.CONF, ['RC|0', 'web|img:1|Up|0.0.0.0:3000->3000/tcp|x'],
                                                      ['api'], ['22', '443', '8080'])}
        self.assertEqual(set(sites), {'app.exemple.local', 'portail.exemple.ma'}, 'joker sans lien')
        app = sites['app.exemple.local']
        self.assertEqual(app['url'], 'https://app.exemple.local/')
        self.assertEqual([c['application'] for c in app['cibles']], ['Application Tomcat api', 'Conteneur Docker web'])
        self.assertNotIn('motdepasse', str(app))
        portail = sites['portail.exemple.ma']
        self.assertEqual(portail['url'], 'http://portail.exemple.ma/')
        self.assertEqual(portail['racines'], ['/var/www/portail'])
        self.assertIn('non en écoute', portail['cibles'][0]['application'])

    def test_portee_dns(self):
        import collector
        # Adresses privées ou de documentation (non routables) : DNS interne.
        for adresse in ('10.1.2.3', '192.168.1.5', '203.0.113.9'):
            with self.subTest(adresse=adresse), mock.patch('socket.getaddrinfo', return_value=[(2, 1, 6, '', (adresse, 0))]):
                self.assertEqual(collector.dns_scope('site.exemple')['statut'], 'interne')
        with mock.patch('socket.getaddrinfo', return_value=[(2, 1, 6, '', ('8.8.8.8', 0))]):
            self.assertEqual(collector.dns_scope('site.exemple'), {'statut': 'en_ligne', 'adresses': ['8.8.8.8']})
        with mock.patch('socket.getaddrinfo', side_effect=OSError('NXDOMAIN')):
            self.assertEqual(collector.dns_scope('absent.exemple')['statut'], 'non_resolu')

    def test_resolveur_bloque_ne_fait_pas_croitre_la_file(self):
        # OC-AUDIT-012 : 30 délais dépassés sur un résolveur figé → au plus DNS_MAX_PENDING travaux.
        import threading
        from concurrent.futures import ThreadPoolExecutor
        import collector
        libere, bloques = threading.Event(), []

        def fige(*_args):
            bloques.append(1)
            libere.wait(10)
            return [(2, 1, 6, '', ('10.0.0.1', 0))]
        pool = ThreadPoolExecutor(max_workers=4)
        self.addCleanup(pool.shutdown, wait=True)
        self.addCleanup(libere.set)
        with mock.patch.object(collector, '_dns_pool', pool), \
                mock.patch.object(collector, '_dns_slots', threading.BoundedSemaphore(collector.DNS_MAX_PENDING)), \
                mock.patch.object(collector, 'DNS_TIMEOUT', 0.001), mock.patch('socket.getaddrinfo', side_effect=fige):
            resultats = [collector.dns_scope(f's{i}.exemple') for i in range(30)]
            en_attente = pool._work_queue.qsize()
            satures = [r for r in resultats if 'saturé' in r.get('raison', '')]
            self.assertEqual(len(satures), 30 - collector.DNS_MAX_PENDING)
            self.assertLessEqual(en_attente, collector.DNS_MAX_PENDING - 4)
            self.assertTrue(all(r['statut'] == 'non_resolu' for r in resultats))
            libere.set()
            pool.shutdown(wait=True)
            # Places rendues à la fin réelle des résolutions : toutes de nouveau disponibles.
            self.assertTrue(all(collector._dns_slots.acquire(blocking=False) for _ in range(collector.DNS_MAX_PENDING)))

    def test_dns_rattache_a_chaque_site_du_releve(self):
        import collector
        sortie = SORTIE.replace('##WEBAPPS', '##VHOSTCONF\n' + '\n'.join(self.CONF) + '\n##WEBAPPS')
        cfg = ssh.SSHConfig(user='a', key_path='k', users=('a',), ports=(22,))
        with mock.patch.object(collector, 'run_operation', return_value=ssh.RunResult(True, 0, sortie, '', 5)), \
                mock.patch.object(collector, 'dns_scope', return_value={'statut': 'interne', 'adresses': ['10.0.0.5']}):
            apps = collector.collect_applications({'key': 's', 'ip': '10.0.0.1'}, cfg, {'ssh_user': 'a', 'ssh_port': 22}, 't')
        self.assertTrue(apps['sites'])
        self.assertTrue(all(s['dns']['statut'] == 'interne' for s in apps['sites']))


class ProxyFormesReellesTests(unittest.TestCase):
    """Formes relevées sur le WAF : options après l'URL, répartiteurs, exclusions."""

    def test_options_apres_l_url_balancer_et_upstream(self):
        conf = ['/etc/apache2/sites-enabled/a.conf:<VirtualHost *:443>',
                '/etc/apache2/sites-enabled/a.conf:  ServerName crm.exemple.ma',
                '/etc/apache2/sites-enabled/a.conf:  ProxyPass / http://10.77.0.28:8080/ retry=0 timeout=60',
                '/etc/apache2/sites-enabled/a.conf:  ProxyPass /static !',
                '/etc/apache2/sites-enabled/a.conf:  ProxyPassMatch ^/api/(.*)$ http://10.77.0.29:9000/$1',
                '/etc/apache2/sites-enabled/b.conf:<VirtualHost *:80>',
                '/etc/apache2/sites-enabled/b.conf:  ServerName lb.exemple.ma',
                '/etc/apache2/sites-enabled/b.conf:<Proxy balancer://grappe>',
                '/etc/apache2/sites-enabled/b.conf:  BalancerMember http://10.77.0.40:8080',
                '/etc/apache2/sites-enabled/b.conf:  BalancerMember http://app2:8080 route=2',
                '/etc/apache2/sites-enabled/b.conf:  ProxyPass /app balancer://grappe/app keepalive=on',
                '/etc/nginx/conf.d/u.conf:upstream back {',
                '/etc/nginx/conf.d/u.conf:    server 10.0.0.7:3000;',
                '/etc/nginx/sites-enabled/n:server {',
                '/etc/nginx/sites-enabled/n:    listen 443 ssl;',
                '/etc/nginx/sites-enabled/n:    server_name n.exemple.ma;',
                '/etc/nginx/sites-enabled/n:    proxy_pass http://back;']
        sites = {s['nom']: [(c['chemin'], c['hote'], c['port'], c['repartiteur']) for c in s['cibles']]
                 for s in inv.sites_web(conf, [], [], [])}
        self.assertEqual(sites['crm.exemple.ma'], [('/', '10.77.0.28', 8080, None),
                                                   ('^/api/(.*)$', '10.77.0.29', 9000, None)],
                         '« retry=0 » n’est pas une cible ; « ! » est une exclusion')
        self.assertEqual(sites['lb.exemple.ma'], [('/app', '10.77.0.40', 8080, 'grappe'), ('/app', 'app2', 8080, 'grappe')])
        self.assertEqual(sites['n.exemple.ma'], [('/', '10.0.0.7', 3000, 'back')])

    def test_valeurs_qui_ne_sont_pas_des_urls(self):
        for valeur in ('retry=0', 'keepalive=on', 'http://retry=0', 'unix:/run/app.sock|http://x', '$backend'):
            self.assertIsNone(inv._cible(valeur), valeur)
