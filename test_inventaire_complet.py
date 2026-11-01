import testing_env  # noqa: F401 — garde-fou réseau et données isolées (AGENTS.md)
import csv
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

import inventaire_complet as ic
import inventaire_complet_rendu as rendu
import inventaire_proxmox as ip

GIB = 1024 ** 3
AUJOURDHUI = date(2026, 10, 22)


class ProxmoxTests(unittest.TestCase):
    def test_configuration_filtree_ne_garde_jamais_les_champs_sensibles(self):
        config = {'cores': 4, 'memory': '8192', 'net0': 'virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr1,tag=20,firewall=1',
                  'description': 'mot de passe admin : xxx', 'cipassword': 'x', 'sshkeys': 'ssh-rsa AAA', 'ciuser': 'root'}
        filtree = ip.config_filtree(config)
        self.assertEqual(set(filtree), {'cores', 'memory', 'net0'})

    def test_carte_reseau_structuree(self):
        cartes = ip.cartes_reseau({'net0': 'virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr1,tag=20,firewall=1',
                                   'net1': 'e1000=11:22:33:44:55:66,bridge=vmbr0'})
        self.assertEqual(cartes[0], {'carte': 'net0', 'modele': 'virtio', 'mac': 'AA:BB:CC:DD:EE:FF', 'bridge': 'vmbr1',
                                     'vlan': '20', 'pare_feu': True, 'ip': ''})
        self.assertEqual((cartes[1]['modele'], cartes[1]['vlan'], cartes[1]['pare_feu']), ('e1000', '', False))

    def test_agent_qemu(self):
        self.assertTrue(ip.agent_actif({'agent': '1'}))
        self.assertTrue(ip.agent_actif({'agent': 'enabled=1,fstrim_cloned_disks=1'}))
        self.assertFalse(ip.agent_actif({'agent': '0'}))
        self.assertIsNone(ip.agent_actif({}))

    def test_collecte_note_une_route_refusee_sans_l_interrompre(self):
        class Client:
            def get(self, chemin):
                if chemin == '/cluster/resources':
                    return [{'type': 'node', 'node': 'n1', 'status': 'online'},
                            {'type': 'qemu', 'node': 'n1', 'vmid': 100, 'name': 'vm1', 'status': 'running'}]
                if chemin.endswith('/config'):
                    raise PermissionError('403')
                return {}
        releve = ip.collecter(Client())
        self.assertEqual(len(releve['invites']), 1)
        self.assertFalse(releve['invites'][0]['config_lue'])
        self.assertIn('/nodes/n1/qemu/100/config', [e['route'] for e in releve['erreurs']])


class SupportTests(unittest.TestCase):
    def test_versions_majeures(self):
        self.assertEqual(ic.version_majeure('PHP', '8.2.7-1+deb12u3'), '8.2')
        self.assertEqual(ic.version_majeure('PostgreSQL', '15.8-1.pgdg120+1'), '15')
        self.assertEqual(ic.version_majeure('PostgreSQL', '9.6.16-2PGDG.rhel7'), '9.6')
        self.assertEqual(ic.version_majeure('Python', '3.11.2-1+b1'), '3.11')
        self.assertEqual(ic.version_majeure('Node.js', '18.19.0+dfsg-6'), '18')

    def test_fin_de_support_des_technologies(self):
        self.assertEqual(ic.fin_support_tech('PHP', '7.4.33', AUJOURDHUI), ('Fin de vie', '2022-11-28'))
        self.assertEqual(ic.fin_support_tech('PHP', '8.2.29', AUJOURDHUI)[0], 'Fin de vie < 6 mois')
        self.assertEqual(ic.fin_support_tech('PHP', '8.3.1', AUJOURDHUI)[0], 'Supportée')
        self.assertEqual(ic.fin_support_tech('Redis', '7.0', AUJOURDHUI), ('', ''))

    def test_support_des_systemes(self):
        self.assertEqual(ic.support_os('centos', '7', AUJOURDHUI)['statut'], 'Fin de vie')
        self.assertEqual(ic.support_os('debian', '12', AUJOURDHUI)['statut'], 'Support étendu (LTS) seulement')
        self.assertEqual(ic.support_os('debian', '11', AUJOURDHUI)['statut'], 'Fin de vie')
        self.assertEqual(ic.support_os('ubuntu', '20.04', AUJOURDHUI)['statut'], 'Fin du support standard (ESM payant requis)')
        self.assertEqual(ic.support_os('plan9', '4', AUJOURDHUI)['confiance'], ic.INCONNU)

    def test_os_depuis_texte(self):
        self.assertEqual(ic.os_depuis_texte('Debian GNU/Linux 12 (bookworm)'), ('debian', '12'))
        self.assertEqual(ic.os_depuis_texte('CentOS Linux 7 (Core)'), ('centos', '7'))
        self.assertEqual(ic.os_depuis_texte('Ubuntu 22.04.4 LTS'), ('ubuntu', '22.04'))


class SauvegardeTests(unittest.TestCase):
    def test_job_en_cours_n_est_pas_une_erreur(self):
        jobs = [{'name': 'Backup-vm1', 'severity': 'ok'}, {'name': 'copy-Backup-vm1', 'severity': 'running'}]
        self.assertEqual(ic.etat_sauvegarde(jobs), 'OK')

    def test_aucun_job_termine(self):
        jobs = [{'name': 'copy-Backup-vm1', 'severity': 'running'}, {'name': 'Backup-vm1', 'severity': 'pending'}]
        self.assertEqual(ic.etat_sauvegarde(jobs), 'Job en cours au relevé (Backup-vm1)')

    def test_erreur_terminee_reste_une_erreur(self):
        jobs = [{'name': 'Backup-vm1', 'severity': 'running'}, {'name': 'copy-Backup-vm1', 'severity': 'critical'}]
        self.assertEqual(ic.etat_sauvegarde(jobs), 'Dernier job en erreur (copy-Backup-vm1)')
        self.assertEqual(ic.etat_sauvegarde([]), 'Aucun job Bacula identifié')


class ReseauxTests(unittest.TestCase):
    def test_ip_des_noeuds_et_vm_ne_sont_pas_hors_inventaire(self):
        noeuds = [{'nom': 'pve1', 'ip_management': '10.0.0.1', 'version': '8.4.1'}]
        vms = [{'cle': 'Cluster/100', 'ip': '10.0.0.20'}]
        base = {'decouverte': [{'ip': '10.0.0.1', 'ports': [22, 8006]}, {'ip': '10.0.0.20', 'ports': [22]},
                               {'ip': '10.0.0.30', 'ports': [445]}, {'ip': '10.0.0.40', 'ports': [80]}]}
        lignes = ic.construire_reseaux([], noeuds, base, [{'ip': '10.0.0.40'}], vms)
        types = {x['ip']: (x['type'], x['confiance']) for x in lignes if x['type'].startswith('Découverte')}
        self.assertEqual(types['10.0.0.1'], ('Découverte réseau', ic.CONFIRME))
        self.assertEqual(types['10.0.0.20'], ('Découverte réseau', ic.CONFIRME))
        self.assertEqual(types['10.0.0.40'], ('Découverte réseau', ic.CONFIRME))
        self.assertEqual(types['10.0.0.30'], ('Découverte réseau (hors inventaire)', ic.DEDUIT))


class TechnologiesTests(unittest.TestCase):
    def test_installe_n_est_pas_utilise(self):
        obs = {'all_services': [{'name': 'apache2.service', 'status': 'active'},
                                {'name': 'php8.2-fpm.service', 'status': 'inactive'}],
               'applications': {'elements': [{'categorie': 'Processus applicatif', 'source': 'Java', 'nom': 'app.jar'}]}}
        paquets = {'manager': 'dpkg', 'collecte_le': '2026-10-22', 'packages': [
            {'name': 'php8.2-cli', 'version': '8.2.7-1'}, {'name': 'php8.2-fpm', 'version': '8.2.7-1'},
            {'name': 'apache2', 'version': '2.4.62-1'}, {'name': 'openjdk-17-jre-headless', 'version': '17.0.12'},
            {'name': 'libphp-embed', 'version': '1'}, {'name': 'python3.11', 'version': '3.11.2-6'}]}
        techs = {t['technologie']: t for t in ic.technologies_hote('h1', obs, paquets)}
        self.assertEqual(techs['PHP']['usage'], 'Installé, usage non vérifié')
        self.assertEqual(techs['PHP']['paquets'], 'php8.2-cli, php8.2-fpm')
        self.assertEqual(techs['Apache HTTP Server']['usage'], 'Utilisé')
        self.assertEqual(techs['Java (OpenJDK)']['usage'], 'Utilisé')
        self.assertEqual(techs['Python']['usage'], 'Installé (socle système)')

    def test_technologies_d_une_application(self):
        techs = [{'technologie': 'Java (OpenJDK)', 'version': '17.0.12', 'usage': 'Utilisé'},
                 {'technologie': 'Apache HTTP Server', 'version': '2.4.62-1', 'usage': 'Utilisé'},
                 {'technologie': 'PHP', 'version': '7.4.33-1', 'usage': 'Installé, usage non vérifié'}]
        tomcat = ic.technos_element({'categorie': 'Application web (Tomcat)', 'source': 'Tomcat', 'nom': 'DemoApp'},
                                    techs, AUJOURDHUI)
        self.assertIn(('Java (OpenJDK) 17.0.12', ic.CONFIRME), tomcat)
        self.assertIn(ic.INCONNU, {c for _, c in tomcat})  # Tomcat hors paquet : version à relever
        site = ic.technos_element({'categorie': 'Site web', 'source': 'Apache', 'nom': 'www.exemple.ma'}, techs, AUJOURDHUI)
        self.assertEqual(site[0], ('Apache HTTP Server 2.4.62', ic.CONFIRME))
        self.assertEqual(site[1][1], ic.DEDUIT)
        self.assertIn('fin de vie', site[1][0])

    def test_php_common_n_est_pas_une_version_de_php(self):
        paquets = {'manager': 'dpkg', 'packages': [{'name': 'php-common', 'version': '2:93'},
                                                   {'name': 'php8.2-cli', 'version': '8.2.29-1'}]}
        techs = ic.technologies_hote('h1', {}, paquets)
        self.assertEqual([t['version'] for t in techs if t['technologie'] == 'PHP'], ['8.2.29-1'])

    def test_repli_sur_les_paquets_cles_de_l_audit(self):
        obs = {'applications': {'collected_at': '2026-10-22', 'paquets': [{'nom': 'nginx', 'version': '1.22.1'}]},
               'all_services': [{'name': 'nginx.service', 'status': 'active'}]}
        techs = ic.technologies_hote('h1', obs, None)
        self.assertEqual([(t['technologie'], t['usage'], t['source']) for t in techs],
                         [('Nginx', 'Utilisé', 'Paquets clés (audit SSH)')])


class CorrelationTests(unittest.TestCase):
    def test_rattachement_par_nom_puis_ip_deduite(self):
        hotes = [{'host': 'web01.host.example.test', 'name': 'web01', 'addresses': ['10.0.0.1']},
                 {'host': 'alias-db', 'name': 'alias-db', 'addresses': ['10.0.0.2']}]
        index = ic.Index(hotes, lambda h: [h['host'], h['name']], lambda h: h['addresses'])
        self.assertEqual(index.trouver('web01.host.example.test', '10.9.9.9')[1], ic.CONFIRME)
        trouve, confiance, _ = index.trouver('prddb01', '10.0.0.2')
        self.assertEqual((trouve['host'], confiance), ('alias-db', ic.DEDUIT))
        self.assertEqual(index.trouver('autre', None)[1], ic.INCONNU)

    def test_stockage_partage_compte_une_seule_fois(self):
        proxmox = {'stockages': [
            {'storage': 'myceph', 'node': 'n1', 'plugintype': 'rbd', 'shared': 1, 'status': 'available', 'disk': 80 * GIB, 'maxdisk': 100 * GIB},
            {'storage': 'myceph', 'node': 'n2', 'plugintype': 'rbd', 'shared': 1, 'status': 'available', 'disk': 80 * GIB, 'maxdisk': 100 * GIB},
            {'storage': 'local', 'node': 'n1', 'plugintype': 'dir', 'shared': 0, 'status': 'available', 'disk': 95 * GIB, 'maxdisk': 100 * GIB},
            {'storage': 'local', 'node': 'n2', 'plugintype': 'dir', 'shared': 0, 'status': 'available', 'disk': 1 * GIB, 'maxdisk': 100 * GIB}]}
        disques = [{'vm': 'C/1', 'nom': 'a', 'noeud': 'n1', 'stockage': 'local', 'taille_go': 10.0},
                   {'vm': 'C/2', 'nom': 'b', 'noeud': 'n2', 'stockage': 'myceph', 'taille_go': 20.0}]
        s = {x['cle']: x for x in ic.construire_stockages(proxmox, [], disques)}
        self.assertEqual(set(s), {'myceph', 'local@n1', 'local@n2'})
        self.assertEqual((s['myceph']['total_go'], s['myceph']['noeuds']), (100.0, 'n1, n2'))
        self.assertEqual((s['local@n1']['nb_vms'], s['local@n2']['nb_vms']), (1, 0))
        self.assertEqual(s['local@n1']['risque_saturation'], 'Critique')

    def test_changements_detectes(self):
        ancien = {'meta': {'genere_le': '2026-10-09'}, 'vms': [
            {'cle': 'C/1', 'nom_court': 'a', 'noeud': 'n1'}, {'cle': 'C/2', 'nom_court': 'b', 'noeud': 'n1'}],
            'noeuds': [{'nom': 'n1', 'version': '8.4.1'}], 'technologies': []}
        courant = {'meta': {'genere_le': '2026-10-22'}, 'vms': [
            {'cle': 'C/1', 'nom_court': 'a', 'noeud': 'n2'}, {'cle': 'C/3', 'nom_court': 'c', 'noeud': 'n1'}],
            'noeuds': [{'nom': 'n1', 'version': '9.0.3'}], 'technologies': []}
        types = sorted(c['type'] for c in ic.changements(courant, ancien))
        self.assertEqual(types, ['VM ajoutée', 'VM déplacée', 'VM supprimée', 'Version PVE modifiée'])

    def test_annotations_preservees(self):
        with tempfile.TemporaryDirectory() as d:
            chemin = Path(d) / 'annotations.csv'
            with chemin.open('w', encoding='utf-8-sig', newline='') as f:
                w = csv.DictWriter(f, fieldnames=ic.COLONNES_ANNOTATIONS, delimiter=';')
                w.writeheader()
                w.writerow({'cle': 'C/1', 'nom': 'a', 'equipe': 'Infra', 'criticite': 'Critique'})
            existantes = ic.charger_annotations(chemin)
            ajoutees = ic.completer_modele_annotations(chemin, [{'cle': 'C/1', 'nom_court': 'a'},
                                                                {'cle': 'C/2', 'nom_court': 'b'}], existantes)
            relues = ic.charger_annotations(chemin)
        self.assertEqual(ajoutees, 1)
        self.assertEqual(relues['C/1'], {'nom': 'a', 'equipe': 'Infra', 'criticite': 'Critique'})
        self.assertIn('C/2', relues)


class ExploitationTests(unittest.TestCase):
    def test_taches_systeme_et_batchs_metier(self):
        self.assertTrue(ic.tache_systeme({'name': 'test', 'executable': 'test', 'source': '/etc/crontab'}))
        self.assertTrue(ic.tache_systeme({'name': 'command', 'executable': 'command', 'source': '/etc/cron.d/sysstat'}))
        self.assertTrue(ic.tache_systeme({'name': 'dpkg', 'executable': '/etc/cron.daily/dpkg', 'source': '/etc/cron.daily'}))
        self.assertTrue(ic.tache_systeme({'name': 'apt-daily.timer', 'executable': '/usr/lib/apt/apt.systemd.daily'}))
        self.assertFalse(ic.tache_systeme({'name': 'demoapp-qa.timer', 'executable': '/opt/demoapp-qa/run.sh',
                                           'source': 'demoapp-qa.service'}))
        self.assertFalse(ic.tache_systeme({'name': 'export.sh', 'executable': '/opt/batch/export.sh', 'source': '/etc/cron.d/export'}))

    def test_batchs_et_risques_d_exploitation(self):
        cron = {'h1': {'collected_at': '2026-10-22T10:00:00', 'timezone': 'Europe/Paris', 'jobs': [
            {'kind': 'systemd', 'name': 'export.timer', 'executable': '/opt/export.sh', 'source': 'export.service',
             'state': 'failed', 'exit_code': '1', 'last_run': 'hier'}]}}
        hotes = [{'key': 'h1', 'name': 'srv1', 'ip': '10.0.0.1'}]
        batchs = ic.construire_batchs(cron, hotes, [])
        self.assertEqual((batchs[0]['type'], batchs[0]['resultat'], batchs[0]['systeme']), ('Timer systemd', 'Échec', 'Non'))
        montages = [{'serveur': 'srv1', 'etat': 'Bloqué (stale)', 'point': '/data', 'source': 'nfs:/x', 'fs': 'nfs4'}]
        services = [{'serveur': 'srv1', 'service': 'tomcat', 'etat': 'En échec'}]
        dns = [{'enregistrement': 'old.exemple.ma', 'dns': 'Non résolu', 'nature': 'Publié', 'cible': ''}]
        r = ic.risques_exploitation(dns, batchs, montages, services)
        self.assertEqual(sorted(x['categorie'] for x in r), ['Batchs', 'DNS / WAF', 'Exploitation', 'Stockage'])
        self.assertEqual(next(x for x in r if x['categorie'] == 'Stockage')['priorite'], 'P1')


class RenduTests(unittest.TestCase):
    def test_classeur_et_rapports_depuis_un_inventaire_minimal(self):
        vm = {k: '' for k in ('id', 'nom_proxmox', 'hostname', 'ip', 'environnement', 'os', 'support_os', 'zabbix',
                              'wazuh', 'bacula', 'responsable', 'criticite', 'applications')}
        vm.update({'cle': 'Cluster/100', 'vmid': 100, 'nom_court': 'vm1', 'etat': 'Démarrée', 'vcpu': 2, 'ram_go': 4,
                   'provisionne_go': 32, 'releve_ssh': '2026-10-22', 'environnement': 'PROD', 'responsable': 'À compléter'})
        inv = {'meta': {'genere_le': '2026-10-22T00:00:00+00:00', 'cluster': 'Cluster', 'methode': 'test',
                        'sources': [{'source': 's', 'methode': 'm', 'date': 'd', 'perimetre': 'p', 'statut': 'OK', 'confiance': 'CONFIRMÉ'}]},
               'noeuds': [{'nom': 'n1', 'ip_management': '10.0.0.1', 'version': '8.4.1', 'noyau': 'Linux 6.8.12-4-pve #1',
                           'cpu_modele': 'EPYC', 'cpu_coeurs': 16, 'cpu_threads': 32, 'ram_totale_go': 256, 'nb_vm': 1,
                           'nb_demarrees': 1}],
               'hors_cluster': [], 'vms': [vm], 'disques': [], 'cartes_reseau': [], 'reseaux': [], 'applications': [],
               'technologies': [], 'services_ports': [], 'docker': [], 'bases': [], 'sauvegardes': [], 'supervision': [],
               'certificats': [], 'dependances': [{'source': 'vm1', 'type_source': 'VM', 'relation': 'hébergée sur', 'cible': 'n1',
                                                  'type_cible': 'Nœud Proxmox', 'preuve': 'API', 'confiance': 'CONFIRMÉ'}],
               'vue_globale': [{'id': 'VM-100', 'vmid': 100, 'nom': 'vm1', 'etat': 'Démarrée', 'tech_PHP': '8.2.29 (utilisé)'}],
               'impact': [], 'risques': [{'id': 'R-001', 'categorie': 'Capacité', 'serveur': 'vm1', 'description': 'd',
                                          'gravite': 'Critique', 'preuve': 'p', 'impact': 'i', 'recommandation': 'r',
                                          'priorite': 'P1', 'responsable': 'Infra', 'statut': 'Ouvert', 'source': 's', 'confiance': 'CONFIRMÉ'}],
               'stockages': [{'cle': 'myceph', 'type': 'rbd', 'partage': 'Partagé', 'total_go': 100, 'occupation_pct': 80,
                              'nb_vms': 1, 'provisionne_go': 32, 'redondance': 'r'}],
               'incoherences': [], 'non_couverts': [], 'erreurs_collecte': [], 'changements': [], 'ceph': None}
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'inventaire_brut.json').write_text(json.dumps(inv), encoding='utf-8')
            self.assertEqual(rendu.main([d]), 0)
            from openpyxl import load_workbook
            wb = load_workbook(Path(d) / rendu.CLASSEUR)
            onglets = [t for t, _, _ in rendu.ONGLETS]
            self.assertEqual(wb.sheetnames, ['00_Dashboard', 'Vue_Globale', 'Fiche_VM', *onglets, 'Listes'])
            self.assertEqual(wb['Fiche_VM']['B3'].value, 'vm1')
            self.assertIn('MATCH($B$3', wb['Fiche_VM']['B6'].value)
            self.assertEqual(wb['03_VMs'].freeze_panes, 'C2')
            self.assertTrue(wb['03_VMs'].auto_filter.ref)
            formules = [c.value for row in wb['00_Dashboard'].iter_rows() for c in row if isinstance(c.value, str) and c.value.startswith('=')]
            self.assertTrue(any('COUNTIFS' in f for f in formules))
            self.assertIn('R-001', (Path(d) / 'plan_actions_priorise.md').read_text(encoding='utf-8'))
            with (Path(d) / 'matrice_dependances.csv').open(encoding='utf-8-sig') as stream:
                self.assertEqual(len(list(csv.reader(stream, delimiter=';'))), 2)


if __name__ == '__main__':
    unittest.main()
