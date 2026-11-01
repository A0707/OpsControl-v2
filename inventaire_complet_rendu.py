"""Livrables de l'inventaire complet à partir de `inventaire_brut.json`.

Produit, dans le dossier de l'inventaire :
  - EXAMPLE_Inventaire_Infrastructure_Complet.xlsx (21 onglets, filtres, listes,
    formules de synthèse et graphiques) ;
  - rapport_audit_infrastructure.md, plan_actions_priorise.md ;
  - matrice_dependances.csv.

Aucune donnée n'est recalculée ici : tout vient du JSON produit par
inventaire_complet.py, pour que le classeur et les rapports disent la même chose.

Usage :
    python inventaire_complet_rendu.py data/inventaire/AAAA-MM-JJ
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

A_COMPLETER = 'À compléter'
CONTROLE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]|[\x00-\x08\x0b\x0c\x0e-\x1f]')
CLASSEUR = 'EXAMPLE_Inventaire_Infrastructure_Complet.xlsx'
POLICE = 'Arial'
BLEU, GRIS = '1F3864', 'F2F2F2'
COULEURS_ENV = {'PROD': 'F8CBAD', 'PREPROD': 'FFE699', 'RECETTE': 'FFE699', 'DEV': 'C6EFCE', 'TEST': 'C6EFCE', 'LAB': 'C6EFCE'}
COULEURS_GRAVITE = {'Critique': 'C00000', 'Élevée': 'FF8C00', 'Moyenne': 'FFD966', 'Faible': 'A9D08E'}
HORIZON = {'P1': '30 jours', 'P2': '90 jours', 'P3': '6 mois'}

LISTES = {
    'environnement': ['PROD', 'PREPROD', 'RECETTE', 'DEV', 'TEST', 'LAB', A_COMPLETER],
    'criticite': ['Critique', 'Haute', 'Standard', 'Faible', A_COMPLETER],
    'gravite': ['Critique', 'Élevée', 'Moyenne', 'Faible'],
    'priorite': ['P1', 'P2', 'P3'],
    'statut': ['Ouvert', 'En cours', 'Accepté', 'Corrigé', 'Faux positif'],
    'confiance': ['CONFIRMÉ', 'DÉCLARÉ', 'DÉDUIT', 'INCONNU'],
}

# (onglet, clé du JSON, [(en-tête, champ, largeur, liste déroulante)])
C = tuple
ONGLETS = [
    ('01_Serveurs_Physiques', 'physiques', [
        C(('Nom', 'nom', 18)), C(('Nature', 'nature', 34)), C(('IP', 'ip', 16)), C(('Fournisseur', 'fournisseur', 18)),
        C(('Site', 'site', 14)), C(('Modèle CPU', 'cpu_modele', 34)), C(('Cœurs / threads', 'cpu', 14)),
        C(('RAM (Go)', 'ram_totale_go', 10)), C(('OS / hyperviseur', 'os', 30)), C(('Rôle', 'role', 18)),
        C(('Environnement', 'environnement', 14, 'environnement')), C(('Relevé', 'releve', 12)),
        C(('Confiance', 'confiance', 12, 'confiance'))]),
    ('02_Proxmox_Clusters', 'noeuds', [
        C(('Nœud', 'nom', 14)), C(('Cluster', 'cluster', 10)), C(('Site', 'site', 12)), C(('État', 'etat', 9)),
        C(('IP management', 'ip_management', 16)), C(('Version PVE', 'version', 11)), C(('pve-manager', 'pve_manager', 26)),
        C(('Noyau', 'noyau', 44)), C(('Modèle CPU', 'cpu_modele', 32)), C(('Sockets', 'cpu_sockets', 8)),
        C(('Cœurs/socket', 'cpu_coeurs', 10)), C(('Threads', 'cpu_threads', 8)), C(('RAM totale (Go)', 'ram_totale_go', 12)),
        C(('RAM utilisée (Go)', 'ram_utilisee_go', 12)), C(('VM', 'nb_vm', 6)), C(('LXC', 'nb_lxc', 6)),
        C(('Démarrées', 'nb_demarrees', 10)), C(('vCPU alloués (démarrées)', 'vcpu_alloues', 12)),
        C(('RAM allouée démarrées (Go)', 'ram_allouee_go', 14)), C(('Stockages', 'stockages', 36)),
        C(('Fournisseur', 'fournisseur', 18))]),
    ('03_VMs', 'vms', [
        C(('ID', 'id', 9)), C(('VMID', 'vmid', 7)), C(('Nom Proxmox', 'nom_proxmox', 30)), C(('Hostname', 'hostname', 30)),
        C(('IPv4', 'ip', 15)), C(('Confiance IP', 'ip_confiance', 11, 'confiance')), C(('IPv6', 'ipv6', 10)),
        C(('Type', 'type', 11)), C(('État', 'etat', 10)), C(('Environnement', 'environnement', 16, 'environnement')),
        C(('Site', 'site', 18)), C(('Cluster', 'cluster', 9)), C(('Nœud', 'noeud', 12)), C(('Équipe', 'equipe', 14)),
        C(('Responsable applicatif', 'responsable', 16)), C(('Fonction', 'fonction', 30)),
        C(('Criticité', 'criticite', 11, 'criticite')), C(('vCPU', 'vcpu', 6)), C(('RAM (Go)', 'ram_go', 8)),
        C(('RAM utilisée (Go)', 'ram_utilisee_go', 9)), C(('CPU %', 'cpu_pct', 7)), C(('Disques', 'nb_disques', 7)),
        C(('Provisionné (Go)', 'provisionne_go', 10)), C(('Occupé dans l’OS (Go)', 'occupe_os_go', 10)),
        C(('FS le plus plein %', 'fs_max_pct', 9)), C(('Stockages', 'stockages', 22)), C(('Bridges', 'bridges', 10)),
        C(('VLAN', 'vlans', 10)), C(('OS', 'os', 30)), C(('Source OS', 'os_source', 18)), C(('Noyau', 'noyau', 26)),
        C(('Support OS', 'support_os', 22)), C(('Fin support standard', 'fin_support_os', 12)),
        C(('Fin LTS / étendu', 'fin_lts_os', 12)), C(('Redémarrage requis', 'reboot_requis', 10)),
        C(('MAJ disponibles', 'maj_disponibles', 9)), C(('Agent QEMU (config)', 'agent_qemu_config', 12)),
        C(('Zabbix', 'zabbix', 11)), C(('Wazuh', 'wazuh', 13)), C(('Bacula', 'bacula', 22)),
        C(('Pare-feu Proxmox', 'pare_feu_proxmox', 9)), C(('Ports en écoute', 'ports', 26)),
        C(('Applications / services hébergés', 'applications', 50)), C(('CVE critiques', 'cve_critiques', 8)),
        C(('CVE hautes', 'cve_hautes', 8)), C(('CVE exploitées (KEV)', 'cve_kev', 8)),
        C(('Démarrage auto', 'onboot', 8)), C(('Créée le (Proxmox)', 'ctime', 11)),
        C(('Relevé SSH', 'releve_ssh', 11)), C(('Inventaire déclaré', 'inventaire_declare', 16))]),
    ('04_Disques_VM', 'disques', [
        C(('VM', 'vm', 13)), C(('VMID', 'vmid', 7)), C(('Nom', 'nom', 18)), C(('Nœud', 'noeud', 12)), C(('Disque', 'disque', 9)),
        C(('Interface', 'interface', 9)), C(('Storage ID', 'stockage', 14)), C(('Backend', 'support', 24)),
        C(('Volume', 'volume', 40)), C(('Taille provisionnée (Go)', 'taille_go', 12)), C(('Détaché (unused)', 'detache', 10)),
        C(('Confiance', 'confiance', 12, 'confiance'))]),
    ('05_Applications', 'applications', [
        C(('Application / service', 'application', 30)), C(('Catégorie', 'categorie', 22)), C(('Fonction', 'fonction', 18)),
        C(('Serveurs (IP)', 'serveurs', 40)), C(('Nb serveurs', 'nb_serveurs', 8)), C(('Composants', 'composants', 30)),
        C(('Méthode de déploiement', 'methode', 18)), C(('État', 'etat', 12)), C(('URL / FQDN publiés', 'url', 34)),
        C(('Technologies et versions [confiance]', 'technologies', 60)), C(('Technologie en fin de vie', 'fin_de_vie', 10)),
        C(('Environnements', 'environnements', 14)), C(('Base de données', 'bdd', 14)), C(('Responsable', 'responsable', 14)),
        C(('Criticité', 'criticite', 11, 'criticite')), C(('Identification', 'statut_identification', 12)),
        C(('Justification', 'justification', 40)), C(('Confiance', 'confiance', 11, 'confiance'))]),
    ('06_Technologies', 'technologies', [
        C(('Serveur', 'nom', 18)), C(('VM', 'vm', 13)), C(('Technologie', 'technologie', 20)), C(('Famille', 'famille', 16)),
        C(('Version installée', 'version', 26)), C(('Version majeure', 'version_majeure', 9)), C(('Paquets', 'paquets', 30)),
        C(('Usage', 'usage', 22)), C(('Preuve d’usage', 'preuve_usage', 40)), C(('Support éditeur', 'support', 18)),
        C(('Fin de support', 'fin_support', 11)), C(('Source', 'source', 18)), C(('Collecté le', 'collecte_le', 18)),
        C(('Confiance', 'confiance', 11, 'confiance'))]),
    ('07_Services_Ports', 'services_ports', [
        C(('Serveur', 'serveur', 18)), C(('IP', 'ip', 15)), C(('VM', 'vm', 13)), C(('Port', 'port', 7)),
        C(('Protocole', 'protocole', 8)), C(('Service probable', 'service_probable', 26)), C(('Processus', 'processus', 18)),
        C(('Exposition', 'exposition', 14)), C(('Relevé le', 'releve_le', 11)), C(('Confiance', 'confiance', 11, 'confiance'))]),
    ('08_Docker_Swarm', 'docker', [
        C(('Serveur', 'serveur', 18)), C(('IP', 'ip', 15)), C(('Rôle déclaré', 'role_declare', 12)), C(('Docker', 'docker', 34)),
        C(('Version moteur', 'version', 12)), C(('État Swarm', 'swarm', 12)), C(('Manager', 'manager', 10)),
        C(('Conteneurs', 'nb_conteneurs', 9)), C(('Images', 'nb_images', 8)), C(('Services Swarm', 'nb_services', 9)),
        C(('Services systemd liés', 'services_systemd', 26)), C(('Relevé le', 'releve_le', 11)),
        C(('Confiance', 'confiance', 11, 'confiance'))]),
    ('09_Conteneurs', 'conteneurs', [
        C(('Serveur', 'serveur', 18)), C(('Objet', 'objet', 12)), C(('Nom / dépôt', 'nom', 40)), C(('Image / tag', 'image', 30)),
        C(('État / détail', 'etat', 40)), C(('Confiance', 'confiance', 11, 'confiance'))]),
    ('10_Stockages', 'stockages', [
        C(('Stockage', 'cle', 22)), C(('Libellé', 'libelle', 24)), C(('Type', 'type', 9)), C(('Portée', 'partage', 9)),
        C(('Nœuds', 'noeuds', 40)), C(('État', 'etat', 10)), C(('Total (Go)', 'total_go', 11)), C(('Utilisé (Go)', 'utilise_go', 11)),
        C(('Libre (Go)', 'libre_go', 11)), C(('Occupation %', 'occupation_pct', 10)), C(('Provisionné VM (Go)', 'provisionne_go', 12)),
        C(('Ratio provisionné / total', 'surprovisionnement', 10)), C(('Nb VM', 'nb_vms', 7)), C(('Nb disques', 'nb_disques', 8)),
        C(('VM hébergées', 'vms', 50)), C(('Redondance', 'redondance', 40)), C(('Santé', 'sante', 12)),
        C(('Risque de saturation', 'risque_saturation', 11)), C(('Socle de', 'socle_de', 10))]),
    ('11_Reseaux', 'reseaux', [
        C(('Type', 'type', 26)), C(('Objet', 'objet', 22)), C(('IP', 'ip', 16)), C(('Interface', 'interface', 9)),
        C(('Bridge', 'bridge', 9)), C(('VLAN', 'vlan', 9)), C(('MAC', 'mac', 18)), C(('Détail', 'detail', 60)),
        C(('Confiance', 'confiance', 11, 'confiance'))]),
    ('12_Bases_Donnees', 'bases', [
        C(('Serveur', 'serveur', 18)), C(('IP', 'ip', 15)), C(('VM', 'vm', 13)), C(('SGBD', 'sgbd', 20)), C(('Service', 'service', 22)),
        C(('Version', 'version', 26)), C(('État', 'etat', 24)), C(('Port', 'port', 9)), C(('Environnement', 'environnement', 12)),
        C(('Applications dépendantes', 'applications_dependantes', 22)), C(('Source', 'source', 24)),
        C(('Confiance', 'confiance', 11, 'confiance'))]),
    ('13_Sauvegardes', 'sauvegardes', [
        C(('Job', 'job', 40)), C(('Type', 'type', 11)), C(('Client', 'client', 34)), C(('VM', 'vm', 14)), C(('Niveau', 'niveau', 12)),
        C(('Statut', 'statut', 18)), C(('Gravité', 'gravite', 9)), C(('Début', 'debut', 17)), C(('Fin', 'fin', 17)),
        C(('Octets', 'octets', 14)), C(('Fichiers', 'fichiers', 9)), C(('Fréquence', 'frequence', 20)),
        C(('Destination', 'destination', 14)), C(('Outil / détail', 'outil', 40)), C(('Confiance', 'confiance', 11, 'confiance'))]),
    ('14_Supervision', 'supervision', [
        C(('Objet', 'objet', 13)), C(('Nom', 'nom', 30)), C(('État VM', 'etat_vm', 16)), C(('Zabbix', 'zabbix', 12)),
        C(('Rattachement Zabbix', 'zabbix_rattachement', 12, 'confiance')), C(('Wazuh', 'wazuh', 15)),
        C(('Version Wazuh', 'wazuh_version', 13)), C(('Rattachement Wazuh', 'wazuh_rattachement', 12, 'confiance')),
        C(('Elastic Agent', 'elastic_agent', 11)), C(('Bacula', 'bacula', 24)), C(('Agent QEMU', 'agent_qemu', 12)),
        C(('Audit SSH', 'audit_ssh', 14))]),
    ('15_Certificats', 'certificats', [
        C(('Serveur', 'serveur', 14)), C(('Sujet', 'sujet', 30)), C(('Émetteur', 'emetteur', 40)), C(('Début', 'debut', 11)),
        C(('Expiration', 'expiration', 11)), C(('Jours restants', 'jours_restants', 9)), C(('Alerte', 'alerte', 16)),
        C(('Fichier', 'fichier', 36)), C(('Utilisé par (vhosts)', 'utilise_par', 50)), C(('Empreinte SHA-256', 'empreinte_sha256', 30)),
        C(('Relevé le', 'releve_le', 11)), C(('Confiance', 'confiance', 11, 'confiance'))]),
    # Matrice d'impact ; les arêtes détaillées sont dans matrice_dependances.csv.
    ('16_Dependances', 'impact', [
        C(('Composant', 'composant', 26)), C(('Type', 'type', 22)), C(('Service métier associé', 'service_metier', 22)),
        C(('Dépendances', 'dependances', 44)), C(('Nb VM impactées', 'nb_vm', 9)), C(('VM impactées', 'vm_impactees', 50)),
        C(('Applications impactées', 'applications_impactees', 50)), C(('Criticité max', 'criticite', 11, 'criticite')),
        C(('Point unique de défaillance', 'spof', 36)), C(('Confiance', 'confiance', 11, 'confiance'))]),
    ('17_Risques', 'risques', [
        C(('ID', 'id', 7)), C(('Catégorie', 'categorie', 13)), C(('Serveur / composant', 'serveur', 20)),
        C(('Description', 'description', 50)), C(('Gravité', 'gravite', 10, 'gravite')), C(('Preuve technique', 'preuve', 50)),
        C(('Impact potentiel', 'impact', 34)), C(('Recommandation', 'recommandation', 40)), C(('Priorité', 'priorite', 8, 'priorite')),
        C(('Responsable proposé', 'responsable', 18)), C(('Statut', 'statut', 10, 'statut')), C(('Source', 'source', 22)),
        C(('Confiance', 'confiance', 11, 'confiance'))]),
    ('18_Plan_Actions', 'actions', [
        C(('Action', 'id', 7)), C(('Priorité', 'priorite', 8, 'priorite')), C(('Horizon', 'horizon', 10)),
        C(('Catégorie', 'categorie', 13)), C(('Action recommandée', 'recommandation', 50)), C(('Gravité max', 'gravite', 10, 'gravite')),
        C(('Nb risques', 'nb', 8)), C(('Périmètre', 'perimetre', 60)), C(('Risques liés', 'risques', 30)),
        C(('Responsable proposé', 'responsable', 18)), C(('Statut', 'statut', 12)), C(('Échéance', 'echeance', 11))]),
    ('19_Sources', 'sources_tout', [
        C(('Rubrique', 'rubrique', 22)), C(('Objet / source', 'objet', 34)), C(('Méthode / type', 'methode', 50)),
        C(('Date', 'date', 22)), C(('Périmètre / détail', 'detail', 60)), C(('Statut / action', 'statut', 50)),
        C(('Confiance', 'confiance', 11, 'confiance'))]),
    ('20_Changements', 'changements', [
        C(('Date', 'date', 11)), C(('Objet', 'objet', 34)), C(('Type', 'type', 22)), C(('Avant', 'avant', 30)),
        C(('Après', 'apres', 30)), C(('Détail', 'detail', 30))]),
    ('21_DNS_WAF', 'enregistrements', [
        C(('Enregistrement DNS', 'enregistrement', 34)), C(('URL', 'url', 40)), C(('HTTPS', 'https', 7)),
        C(('Résolution DNS', 'dns', 20)), C(('Adresses DNS', 'adresses_dns', 18)), C(('Frontal (WAF / serveur web)', 'frontal', 18)),
        C(('IP frontal', 'ip_frontal', 15)), C(('Rôle frontal', 'role_frontal', 16)), C(('Chemin', 'chemin', 14)),
        C(('Cible proxy', 'cible', 26)), C(('Répartiteur', 'repartiteur', 16)), C(('Serveur cible', 'serveur_cible', 18)),
        C(('IP cible', 'ip_cible', 15)), C(('Application cible', 'application', 34)),
        C(('Environnement', 'environnement', 12, 'environnement')), C(('Nature', 'nature', 30)),
        C(('Certificat', 'certificat', 30)), C(('Expiration certificat', 'expiration_certificat', 11)),
        C(('Jours restants', 'jours_restants', 8)), C(('Racine', 'racine', 26)), C(('Fichier de configuration', 'fichier_conf', 44)),
        C(('Relevé le', 'releve_le', 11)), C(('Confiance', 'confiance', 11, 'confiance'))]),
    ('22_Batchs', 'batchs', [
        C(('Serveur', 'serveur', 18)), C(('IP', 'ip', 15)), C(('VM', 'vm', 13)), C(('Environnement', 'environnement', 12, 'environnement')),
        C(('Type', 'type', 16)), C(('Tâche', 'nom', 30)), C(('Planification', 'planification', 30)), C(('Fuseau', 'fuseau', 13)),
        C(('Commande', 'commande', 40)), C(('Script', 'script', 34)), C(('Compte', 'compte', 16)), C(('Déclarée dans', 'source', 30)),
        C(('Dernier résultat', 'resultat', 12)), C(('Code retour', 'code_retour', 8)),
        C(('Dernière exécution', 'derniere_execution', 22)), C(('Prochaine exécution', 'prochaine_execution', 22)),
        C(('Tâche système', 'systeme', 9)), C(('Preuve', 'preuve', 40)), C(('Relevé le', 'releve_le', 11)),
        C(('Confiance', 'confiance', 11, 'confiance'))]),
    ('23_Montages_Partages', 'montages', [
        C(('Serveur', 'serveur', 18)), C(('IP', 'ip', 15)), C(('VM', 'vm', 13)), C(('Type', 'type', 24)),
        C(('Point de montage / chemin', 'point', 40)), C(('Source / périphérique', 'source', 44)), C(('FS', 'fs', 9)),
        C(('Taille (Go)', 'taille_go', 9)), C(('Utilisé %', 'utilise_pct', 8)), C(('Inodes %', 'inodes_pct', 8)),
        C(('État', 'etat', 14)), C(('Accès', 'acces', 12)), C(('Relevé le', 'releve_le', 11)), C(('Confiance', 'confiance', 11, 'confiance'))]),
    ('24_Services_Systemd', 'services_systemd', [
        C(('Serveur', 'serveur', 18)), C(('IP', 'ip', 15)), C(('Service', 'service', 40)), C(('État', 'etat', 11)),
        C(('Activé au démarrage', 'active_au_demarrage', 10)), C(('Relevé le', 'releve_le', 11)),
        C(('Confiance', 'confiance', 11, 'confiance'))]),
    ('25_Problemes_Zabbix', 'problemes_zabbix', [
        C(('Problème', 'probleme', 60)), C(('Gravité Zabbix', 'gravite_zabbix', 13)), C(('Gravité', 'gravite', 10, 'gravite')),
        C(('Hôtes Zabbix', 'hotes', 34)), C(('VM', 'vm', 16)), C(('Depuis', 'depuis', 11)), C(('Jours', 'jours', 7)),
        C(('Mesuré le', 'mesure_le', 22)), C(('Confiance', 'confiance', 11, 'confiance'))]),
]


# Vue globale « tout en un » : (famille, couleur, colonnes). Une ligne par VM.
TECHS_VUE = ['PHP', 'Java', 'Python', 'Node.js', 'Apache', 'Nginx', 'Tomcat', 'PostgreSQL', 'MariaDB / MySQL',
             'Redis', 'Docker', 'Elasticsearch']
FAMILLES_VUE = [
    ('Identification', '1F3864', [('ID', 'id', 8), ('VMID', 'vmid', 6), ('VM', 'nom', 16), ('Hostname', 'hostname', 26),
                                  ('IPv4', 'ip', 14), ('Environnement', 'environnement', 14, 'environnement'),
                                  ('Criticité', 'criticite', 10, 'criticite'), ('Fonction', 'fonction', 24),
                                  ('Équipe', 'equipe', 12), ('Responsable', 'responsable', 14)]),
    ('Hébergement', '2E75B6', [('Site', 'site', 16), ('Cluster', 'cluster', 9), ('Nœud', 'noeud', 12), ('État', 'etat', 10)]),
    ('Stockage', '7F6000', [('Stockages', 'stockages', 20), ('Disques (VM → disque → storage → taille)', 'disques', 40),
                            ('Provisionné (Go)', 'provisionne_go', 10), ('Occupé OS (Go)', 'occupe_os_go', 9),
                            ('FS max %', 'fs_max_pct', 7)]),
    ('Ressources', '548235', [('vCPU', 'vcpu', 6), ('RAM (Go)', 'ram_go', 7), ('RAM utilisée (Go)', 'ram_utilisee_go', 8),
                              ('CPU %', 'cpu_pct', 6)]),
    ('Système', '7030A0', [('OS', 'os', 26), ('Support OS', 'support_os', 18), ('Fin LTS', 'fin_lts_os', 10),
                           ('Noyau', 'noyau', 20), ('Redémarrage requis', 'reboot_requis', 9), ('MAJ dispo', 'maj_disponibles', 7)]),
    ('Applications', 'C55A11', [('Applications / services hébergés', 'applications', 46),
                                ('Sites publiés (WAF)', 'sites_publies', 34),
                                ('Enregistrements DNS servis', 'enregistrements_dns', 34), ('Bases de données', 'bases', 30),
                                ('Conteneurs / Swarm', 'conteneurs', 28), ('Batchs métier', 'batchs', 34),
                                ('Batchs en échec', 'batchs_echec', 8)]),
    ('Technologies (version : utilisée / installée seule)', '833C0B',
     [(t, f'tech_{t}', 18) for t in TECHS_VUE] + [('Autres technologies utilisées', 'tech_autres', 34)]),
    ('Réseau', '2F5597', [('Ports en écoute', 'ports', 22), ('Bridges', 'bridges', 9), ('VLAN', 'vlans', 9)]),
    ('Protection', '375623', [('Sauvegarde Bacula', 'bacula', 20), ('Zabbix', 'zabbix', 11), ('Wazuh', 'wazuh', 12),
                              ('Agent QEMU', 'agent_qemu', 10)]),
    ('Risques', 'C00000', [('Risques critiques', 'risques_critiques', 8), ('Risques élevés', 'risques_eleves', 8),
                           ('Total risques', 'risques_total', 7), ('Risques P1', 'risques_p1', 20),
                           ('CVE exploitées (KEV)', 'cve_kev', 8), ('Relevé SSH', 'releve_ssh', 11)]),
]
COLONNES_VUE = [C(col) for _, _, cols in FAMILLES_VUE for col in cols]
BANDES_VUE = [(nom, len(cols), couleur) for nom, couleur, cols in FAMILLES_VUE]
ONGLETS_TOUS = [('Vue_Globale', 'vue_globale', COLONNES_VUE, BANDES_VUE)] + [(t, c, cols, None) for t, c, cols in ONGLETS]


def ecrire_fiche_vm(ws, inv: dict, lettres: dict, remplissage, bord) -> None:
    """Fiche d'une VM : on choisit son nom en B3, tout le reste se remplit par INDEX/EQUIV."""
    from openpyxl.styles import Alignment, Font
    from openpyxl.worksheet.datavalidation import DataValidation

    vues = inv.get('vue_globale') or []
    fin = max(len(vues) + 2, 3)
    nom = lettres['nom']
    ws['A1'] = 'Fiche VM — choisir la VM dans la liste (cellule jaune)'
    ws['A1'].font = Font(name=POLICE, bold=True, size=14, color=BLEU)
    ws['A3'] = 'VM'
    ws['A3'].font = Font(name=POLICE, bold=True)
    premiere = next((v['nom'] for v in vues if v.get('etat') == 'Démarrée'), vues[0]['nom'] if vues else '')
    ws['B3'] = premiere
    ws['B3'].fill = remplissage('FFFF00')
    ws['B3'].font = Font(name=POLICE, bold=True, size=12)
    dv = DataValidation(type='list', formula1=f'=Vue_Globale!${nom}$3:${nom}${fin}', allow_blank=False)
    ws.add_data_validation(dv)
    dv.add('B3')
    ligne = 5
    for famille, couleur, colonnes in FAMILLES_VUE:
        ws.cell(ligne, 1, famille).font = Font(name=POLICE, bold=True, color='FFFFFF')
        ws.cell(ligne, 1).fill = remplissage(couleur)
        ws.cell(ligne, 2).fill = remplissage(couleur)
        ligne += 1
        for col in colonnes:
            lettre = lettres[col[1]]
            source = f'Vue_Globale!${lettre}$3:${lettre}${fin}'
            cle = f'Vue_Globale!${nom}$3:${nom}${fin}'
            ws.cell(ligne, 1, col[0]).font = Font(name=POLICE, size=10)
            c = ws.cell(ligne, 2, f'=IFERROR(IF(INDEX({source},MATCH($B$3,{cle},0))="","",'
                                  f'INDEX({source},MATCH($B$3,{cle},0))),"VM introuvable")')
            c.font = Font(name=POLICE, size=10)
            c.alignment = Alignment(wrap_text=True, vertical='top')
            for cellule in (ws.cell(ligne, 1), c):
                cellule.border = bord
            ligne += 1
        ligne += 1
    ws.column_dimensions['A'].width = 34
    ws.column_dimensions['B'].width = 110
    ws.freeze_panes = 'A4'


# ---------------------------------------------------------------- préparation

def preparer(inv: dict) -> dict:
    """Lignes dérivées du JSON pour les onglets qui regroupent plusieurs rubriques."""
    physiques = [{'nom': n['nom'], 'nature': 'Serveur physique (nœud Proxmox)', 'ip': n.get('ip_management'),
                  'fournisseur': n.get('fournisseur'), 'site': n.get('site'), 'cpu_modele': n.get('cpu_modele'),
                  'cpu': f"{n.get('cpu_coeurs')} / {n.get('cpu_threads')}", 'ram_totale_go': n.get('ram_totale_go'),
                  'os': f"Proxmox VE {n.get('version')}", 'role': 'Hyperviseur', 'environnement': 'PROD',
                  'releve': (inv['meta']['genere_le'] or '')[:10], 'confiance': 'CONFIRMÉ'} for n in inv['noeuds']]
    physiques += [{'nom': h['nom'], 'nature': h['nature'], 'ip': h['ip'], 'fournisseur': A_COMPLETER, 'site': A_COMPLETER,
                   'cpu_modele': A_COMPLETER, 'cpu': '', 'ram_totale_go': None, 'os': h['os'], 'role': h['role'],
                   'environnement': h['environnement'], 'releve': h['releve_ssh'], 'confiance': h['confiance']}
                  for h in inv['hors_cluster']]
    conteneurs = []
    for d in inv['docker']:
        for c in d.get('conteneurs') or []:
            conteneurs.append({'serveur': d['serveur'], 'objet': 'Conteneur', 'nom': c.get('name') or c.get('names'),
                               'image': c.get('image'), 'etat': c.get('status') or c.get('state'), 'confiance': 'CONFIRMÉ'})
        for s in d.get('services') or []:
            conteneurs.append({'serveur': d['serveur'], 'objet': 'Service Swarm', 'nom': s.get('name'), 'image': s.get('image'),
                               'etat': f"réplicas {s.get('replicas')}", 'confiance': 'CONFIRMÉ'})
        for i in d.get('images') or []:
            conteneurs.append({'serveur': d['serveur'], 'objet': 'Image', 'nom': i.get('repository'), 'image': i.get('tag'),
                               'etat': f"créée {i.get('created')}", 'confiance': 'CONFIRMÉ'})
        if d['confiance'] != 'CONFIRMÉ':
            conteneurs.append({'serveur': d['serveur'], 'objet': 'Non collecté', 'nom': A_COMPLETER, 'image': A_COMPLETER,
                               'etat': d['docker'], 'confiance': 'INCONNU'})
    # Plan d'actions : une action par recommandation et catégorie, les risques regroupés.
    groupes = defaultdict(list)
    for r in inv['risques']:
        groupes[(r['priorite'], r['categorie'], r['recommandation'])].append(r)
    ordre = {'Critique': 0, 'Élevée': 1, 'Moyenne': 2, 'Faible': 3}
    actions = []
    for (prio, cat, reco), rs in sorted(groupes.items(), key=lambda g: (g[0][0], min(ordre[r['gravite']] for r in g[1]), -len(g[1]))):
        actions.append({'priorite': prio, 'horizon': HORIZON.get(prio, ''), 'categorie': cat, 'recommandation': reco,
                        'gravite': min((r['gravite'] for r in rs), key=lambda g: ordre[g]), 'nb': len(rs),
                        'perimetre': ', '.join(sorted({str(r['serveur']) for r in rs}))[:1000],
                        'risques': ', '.join(r['id'] for r in rs)[:400], 'responsable': rs[0]['responsable'],
                        'statut': 'À planifier', 'echeance': A_COMPLETER})
    for i, a in enumerate(actions, 1):
        a['id'] = f'A-{i:02d}'
    sources_tout = [{'rubrique': 'Source de collecte', 'objet': s['source'], 'methode': s['methode'], 'date': s['date'],
                     'detail': s['perimetre'], 'statut': s['statut'], 'confiance': s['confiance']} for s in inv['meta']['sources']]
    sources_tout += [{'rubrique': 'Périmètre non couvert', 'objet': f"{n['objet']} {n.get('nom') or ''}".strip(),
                      'methode': n['perimetre'], 'date': '', 'detail': n['raison'], 'statut': n['action'], 'confiance': 'INCONNU'}
                     for n in inv['non_couverts']]
    sources_tout += [{'rubrique': 'Incohérence', 'objet': i['objet'], 'methode': i['type'], 'date': '', 'detail': i['detail'],
                      'statut': i['action'], 'confiance': 'CONFIRMÉ'} for i in inv['incoherences']]
    sources_tout += [{'rubrique': 'Erreur de collecte', 'objet': e['route'], 'methode': e['erreur'], 'date': '',
                      'detail': e['detail'], 'statut': 'Route non lue', 'confiance': 'INCONNU'} for e in inv['erreurs_collecte']]
    return {**inv, 'physiques': physiques, 'conteneurs': conteneurs, 'actions': actions, 'sources_tout': sources_tout}


# ---------------------------------------------------------------- Excel

def ecrire_classeur(chemin: Path, inv: dict) -> None:
    from openpyxl import Workbook
    from openpyxl.chart import BarChart, PieChart, Reference
    from openpyxl.formatting.rule import CellIsRule, FormulaRule
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.utils import get_column_letter
    from openpyxl.worksheet.datavalidation import DataValidation

    def remplissage(c):
        return PatternFill('solid', start_color=c, end_color=c)

    trait = Side(style='thin', color='D9D9D9')
    bord = Border(left=trait, right=trait, top=trait, bottom=trait)
    wb = Workbook()
    dash = wb.active
    dash.title = '00_Dashboard'
    lettres = {}

    # Feuille « Listes » cachée : source des listes déroulantes normalisées.
    listes = wb.create_sheet('Listes')
    for j, (nom, valeurs) in enumerate(LISTES.items(), 1):
        listes.cell(1, j, nom)
        for i, v in enumerate(valeurs, 2):
            listes.cell(i, j, v)
    listes.sheet_state = 'hidden'
    plage_liste = {nom: f"Listes!${get_column_letter(j)}$2:${get_column_letter(j)}${len(v) + 1}"
                   for j, (nom, v) in enumerate(LISTES.items(), 1)}

    for titre, cle, colonnes, bandes in ONGLETS_TOUS:
        ws = wb.create_sheet(titre)
        lignes = inv.get(cle) or []
        # Vue globale : une ligne de familles (Hébergement, Stockage…) au-dessus des en-têtes.
        h = 2 if bandes else 1
        if bandes:
            debut = 1
            for nom_bande, nombre, couleur in bandes:
                ws.merge_cells(start_row=1, start_column=debut, end_row=1, end_column=debut + nombre - 1)
                c = ws.cell(1, debut, nom_bande)
                c.font = Font(name=POLICE, bold=True, color='FFFFFF', size=10)
                c.alignment = Alignment(horizontal='center', vertical='center')
                for j in range(debut, debut + nombre):
                    ws.cell(1, j).fill = remplissage(couleur)
                debut += nombre
            ws.row_dimensions[1].height = 20
        for j, col in enumerate(colonnes, 1):
            entete, _, largeur = col[:3]
            c = ws.cell(h, j, entete)
            c.font = Font(name=POLICE, bold=True, color='FFFFFF', size=10)
            c.fill = remplissage(BLEU)
            c.alignment = Alignment(wrap_text=True, vertical='center')
            ws.column_dimensions[get_column_letter(j)].width = largeur
        lettres[titre] = {col[1]: get_column_letter(j) for j, col in enumerate(colonnes, 1)}
        for i, ligne in enumerate(lignes, h + 1):
            for j, col in enumerate(colonnes, 1):
                v = ligne.get(col[1])
                if isinstance(v, (list, dict)):
                    v = json.dumps(v, ensure_ascii=False)
                if v is None or v == '':
                    v = None
                # Valeurs relevées sur les serveurs : codes ANSI retirés, jamais évaluées comme formule.
                c = ws.cell(i, j, CONTROLE.sub('', v)[:32000] if isinstance(v, str) else v)
                if c.data_type == 'f':
                    c.data_type = 's'
                c.font = Font(name=POLICE, size=9)
                c.border = bord
                c.alignment = Alignment(vertical='top', wrap_text=False)
        p1 = h + 1
        dernier = max(len(lignes) + h, p1)
        ws.row_dimensions[h].height = 32
        ws.freeze_panes = f'D{p1}' if bandes else 'C2' if titre in ('03_VMs', '17_Risques') else 'A2'
        fin_col = get_column_letter(len(colonnes))
        ws.auto_filter.ref = f'A{h}:{fin_col}{dernier}'
        zone = f'A{p1}:{fin_col}{max(dernier, 500)}'
        # Information manquante mise en évidence partout.
        ws.conditional_formatting.add(zone, CellIsRule(operator='equal', formula=[f'"{A_COMPLETER}"'],
                                                       fill=remplissage('FFF2CC'), font=Font(name=POLICE, size=9, italic=True, color='9C5700')))
        if bandes:
            ws.conditional_formatting.add(zone, FormulaRule(formula=[f'ISNUMBER(SEARCH("FIN DE VIE",A{p1}))'],
                                                            fill=remplissage('F4B084'), stopIfTrue=True))
            ws.conditional_formatting.add(zone, CellIsRule(operator='equal', formula=['"Non relevé"'], fill=remplissage('EDEDED')))
        for j, col in enumerate(colonnes, 1):
            lettre = get_column_letter(j)
            plage = f'{lettre}{p1}:{lettre}{max(dernier, 500)}'
            if len(col) > 3:
                dv = DataValidation(type='list', formula1=f'={plage_liste[col[3]]}', allow_blank=True,
                                    showErrorMessage=False)
                ws.add_data_validation(dv)
                dv.add(plage)
            if col[1] == 'environnement' or (len(col) > 3 and col[3] == 'environnement'):
                for env, couleur in COULEURS_ENV.items():
                    ws.conditional_formatting.add(plage, FormulaRule(formula=[f'LEFT({lettre}{p1},{len(env)})="{env}"'],
                                                                     fill=remplissage(couleur), stopIfTrue=True))
            if col[1] in ('gravite', 'criticite'):
                for g, couleur in {**COULEURS_GRAVITE, 'Haute': 'FF8C00'}.items():
                    ws.conditional_formatting.add(plage, CellIsRule(operator='equal', formula=[f'"{g}"'], fill=remplissage(couleur),
                                                                    font=Font(name=POLICE, size=9, bold=True,
                                                                              color='FFFFFF' if g in ('Critique', 'Élevée', 'Haute') else '000000')))
            if col[1] in ('occupation_pct', 'fs_max_pct'):
                ws.conditional_formatting.add(plage, CellIsRule(operator='greaterThanOrEqual', formula=['90'], fill=remplissage('F4B084')))
                ws.conditional_formatting.add(plage, CellIsRule(operator='between', formula=['80', '89.99'], fill=remplissage('FFE699')))
            if col[1] in ('risques_critiques', 'cve_kev', 'batchs_echec'):
                ws.conditional_formatting.add(plage, CellIsRule(operator='greaterThan', formula=['0'], fill=remplissage('F4B084')))
            if col[1] in ('support_os', 'support', 'alerte', 'bacula', 'zabbix', 'wazuh', 'fin_de_vie', 'resultat',
                          'dns', 'etat'):
                for texte, couleur in (('Fin de vie', 'F4B084'), ('Expiré', 'F4B084'), ('Moins de 30', 'F4B084'),
                                       ('Échec', 'F4B084'), ('Non résolu', 'F4B084'), ('Bloqué', 'F4B084'),
                                       ('Absent', 'F4B084'), ('Aucun', 'F4B084'), ('erreur', 'F4B084'), ('Oui', 'F4B084'),
                                       ('never_connected', 'FFE699'), ('disconnected', 'FFE699'), ('unmonitored', 'FFE699'),
                                       ('LTS', 'FFE699'), ('Moins de 60', 'FFE699')):
                    if texte == 'Oui' and col[1] != 'fin_de_vie':
                        continue
                    ws.conditional_formatting.add(plage, FormulaRule(formula=[f'ISNUMBER(SEARCH("{texte}",{lettre}{p1}))'],
                                                                     fill=remplissage(couleur), stopIfTrue=True))
            if col[1] == 'confiance' or (len(col) > 3 and col[3] == 'confiance'):
                for texte, couleur in (('DÉDUIT', 'FFF2CC'), ('INCONNU', 'EDEDED'), ('DÉCLARÉ', 'DDEBF7')):
                    ws.conditional_formatting.add(plage, CellIsRule(operator='equal', formula=[f'"{texte}"'], fill=remplissage(couleur)))

    ecrire_fiche_vm(wb.create_sheet('Fiche_VM'), inv, lettres['Vue_Globale'], remplissage, bord)
    for position, titre in enumerate(('Vue_Globale', 'Fiche_VM'), 1):
        wb.move_sheet(titre, offset=position - wb.sheetnames.index(titre))

    # ------------------------------------------------ tableau de bord (formules)
    def f(onglet, champ, critere=None, *autres):
        col = f"'{onglet}'!${lettres[onglet][champ]}:${lettres[onglet][champ]}"
        if critere is None:
            return f'=COUNTA({col})-1'
        if not autres:
            return f'=COUNTIF({col},"{critere}")'
        parties = [f'{col},"{critere}"']
        for champ2, crit2 in zip(autres[::2], autres[1::2]):
            parties.append(f"'{onglet}'!${lettres[onglet][champ2]}:${lettres[onglet][champ2]},\"{crit2}\"")
        return f"=COUNTIFS({','.join(parties)})"

    dash['A1'] = 'EXAMPLE — Inventaire de l’infrastructure'
    dash['A1'].font = Font(name=POLICE, bold=True, size=16, color=BLEU)
    dash['A2'] = (f"Généré le {inv['meta']['genere_le']} — lecture seule, aucune action sur le parc. "
                  'Les indicateurs sont des formules sur les onglets : ils suivent les filtres et corrections.')
    dash['A2'].font = Font(name=POLICE, italic=True, size=9, color='595959')
    blocs = [
        ('Parc', [('Nœuds Proxmox', f('02_Proxmox_Clusters', 'nom')),
                  ('Serveurs hors cluster (à qualifier)', '=COUNTIF(\'01_Serveurs_Physiques\'!$B:$B,"Hors*")+COUNTIF(\'01_Serveurs_Physiques\'!$B:$B,"VMID*")'),
                  ('VM / conteneurs', f('03_VMs', 'id')), ('VM démarrées', f('03_VMs', 'etat', 'Démarrée')),
                  ('VM arrêtées', f('03_VMs', 'etat', 'Arrêtée')),
                  ('vCPU alloués (démarrées)', f"=SUMIF('03_VMs'!${lettres['03_VMs']['etat']}:${lettres['03_VMs']['etat']},\"Démarrée\",'03_VMs'!${lettres['03_VMs']['vcpu']}:${lettres['03_VMs']['vcpu']})"),
                  ('RAM allouée démarrées (Go)', f"=SUMIF('03_VMs'!${lettres['03_VMs']['etat']}:${lettres['03_VMs']['etat']},\"Démarrée\",'03_VMs'!${lettres['03_VMs']['ram_go']}:${lettres['03_VMs']['ram_go']})"),
                  ('Disque provisionné (To)', f"=ROUND(SUM('03_VMs'!${lettres['03_VMs']['provisionne_go']}:${lettres['03_VMs']['provisionne_go']})/1024,1)")]),
        ('Environnements (VM démarrées)', [(e, f('03_VMs', 'environnement', f'{e}*', 'etat', 'Démarrée'))
                                           for e in ('PROD', 'PREPROD', 'RECETTE')]
         + [('À compléter', f('03_VMs', 'environnement', A_COMPLETER, 'etat', 'Démarrée'))]),
        ('Systèmes (VM démarrées)', [('Fin de vie', f('03_VMs', 'support_os', 'Fin de vie', 'etat', 'Démarrée')),
                                     ('Support LTS seulement', f('03_VMs', 'support_os', 'Support étendu*', 'etat', 'Démarrée')),
                                     ('Supporté', f('03_VMs', 'support_os', 'Supporté', 'etat', 'Démarrée')),
                                     ('OS inconnu', f('03_VMs', 'support_os', A_COMPLETER, 'etat', 'Démarrée')),
                                     ('Redémarrage requis', f('03_VMs', 'reboot_requis', 'Oui'))]),
        ('Protection (VM démarrées)', [('Supervisées Zabbix', f('03_VMs', 'zabbix', 'monitored', 'etat', 'Démarrée')),
                                       ('Sans Zabbix', f('03_VMs', 'zabbix', 'Absent', 'etat', 'Démarrée')),
                                       ('Wazuh actif', f('03_VMs', 'wazuh', 'active', 'etat', 'Démarrée')),
                                       ('Wazuh absent ou déconnecté', f"=COUNTIFS('03_VMs'!${lettres['03_VMs']['etat']}:${lettres['03_VMs']['etat']},\"Démarrée\")-B{{active}}"),
                                       ('Sauvegarde Bacula OK', f('03_VMs', 'bacula', 'OK', 'etat', 'Démarrée')),
                                       ('Sans sauvegarde Bacula identifiée', f('03_VMs', 'bacula', 'Aucun*', 'etat', 'Démarrée'))]),
        ('Risques par gravité', [(g, f('17_Risques', 'gravite', g)) for g in ('Critique', 'Élevée', 'Moyenne', 'Faible')]),
        ('Risques par priorité', [(p, f('17_Risques', 'priorite', p)) for p in ('P1', 'P2', 'P3')]),
        ('Exposition et exploitation', [
            ('Enregistrements publiés par les WAF', f('21_DNS_WAF', 'nature', 'Publié*')),
            ('Enregistrements DNS non résolus', f('21_DNS_WAF', 'dns', 'Non résolu')),
            ('Cibles WAF hors inventaire', f('21_DNS_WAF', 'nature', 'Cible absente*')),
            ('Batchs métier relevés', f('22_Batchs', 'systeme', 'Non')),
            ('Batchs en échec', f('22_Batchs', 'resultat', 'Échec')),
            ('Montages réseau bloqués (stale)', f('23_Montages_Partages', 'etat', 'Bloqué*')),
            ('Services systemd en échec', f('24_Services_Systemd', 'etat', 'En échec')),
            ('Problèmes Zabbix critiques', f('25_Problemes_Zabbix', 'gravite', 'Critique'))]),
        ('Qualité des données', [('Champs « À compléter » (VM)', f"=COUNTIF('03_VMs'!A:AZ,\"{A_COMPLETER}\")"),
                                 ('VM sans responsable', f('03_VMs', 'responsable', A_COMPLETER)),
                                 ('Applications à confirmer', f('05_Applications', 'statut_identification', 'À confirmer')),
                                 ('Incohérences entre sources', "=COUNTIF('19_Sources'!$A:$A,\"Incohérence\")"),
                                 ('Périmètres non couverts', "=COUNTIF('19_Sources'!$A:$A,\"Périmètre non couvert\")")]),
    ]
    ligne = 4
    positions = {}
    for titre, mesures in blocs:
        dash.cell(ligne, 1, titre).font = Font(name=POLICE, bold=True, color='FFFFFF')
        dash.cell(ligne, 1).fill = remplissage(BLEU)
        dash.cell(ligne, 2).fill = remplissage(BLEU)
        positions[titre] = (ligne + 1, ligne + len(mesures))
        for k, (libelle, formule) in enumerate(mesures, 1):
            if '{active}' in formule:
                formule = formule.replace('{active}', str(ligne + k - 1))
            dash.cell(ligne + k, 1, libelle).font = Font(name=POLICE, size=10)
            c = dash.cell(ligne + k, 2, formule)
            c.font = Font(name=POLICE, size=10, bold=True)
            c.border = bord
            dash.cell(ligne + k, 1).border = bord
        ligne += len(mesures) + 2
    dash.column_dimensions['A'].width = 38
    dash.column_dimensions['B'].width = 12
    # Occupation des stockages : liens vers 10_Stockages.
    st = lettres['10_Stockages']
    dash.cell(ligne, 1, 'Occupation des stockages (%)').font = Font(name=POLICE, bold=True, color='FFFFFF')
    dash.cell(ligne, 1).fill = remplissage(BLEU)
    dash.cell(ligne, 2).fill = remplissage(BLEU)
    debut_st = ligne + 1
    for k in range(len(inv['stockages'])):
        dash.cell(debut_st + k, 1, f"='10_Stockages'!{st['cle']}{k + 2}").font = Font(name=POLICE, size=10, color='008000')
        dash.cell(debut_st + k, 2, f"='10_Stockages'!{st['occupation_pct']}{k + 2}").font = Font(name=POLICE, size=10, color='008000')
    fin_st = debut_st + len(inv['stockages']) - 1
    note = fin_st + 2
    dash.cell(note, 1, 'Légende : jaune = « À compléter » ; orange = alerte ; rouge = critique. '
                       'Annotations (équipe, responsable, criticité) : data/inventaire/annotations.csv.').font = Font(name=POLICE, italic=True, size=9)

    def graphique(type_, titre, bloc, ancre, couleur='1F3864'):
        g = BarChart() if type_ == 'bar' else PieChart()
        g.title = titre
        a, b = positions[bloc] if isinstance(bloc, str) else bloc
        g.add_data(Reference(dash, min_col=2, min_row=a, max_row=b), titles_from_data=False)
        g.set_categories(Reference(dash, min_col=1, min_row=a, max_row=b))
        g.height, g.width = 7, 12
        if type_ == 'bar':
            g.legend = None
            g.series[0].graphicalProperties.solidFill = couleur
        dash.add_chart(g, ancre)

    graphique('pie', 'VM démarrées par environnement', 'Environnements (VM démarrées)', 'D4')
    graphique('bar', 'Risques par gravité', 'Risques par gravité', 'L4', 'C00000')
    graphique('bar', 'Systèmes (VM démarrées)', 'Systèmes (VM démarrées)', 'D19')
    graphique('bar', 'Protection des VM démarrées', 'Protection (VM démarrées)', 'L19', '2E75B6')
    graphique('bar', 'Occupation des stockages (%)', (debut_st, fin_st), 'D34', '7F6000')
    graphique('bar', 'Risques par priorité', 'Risques par priorité', 'L34', 'ED7D31')
    wb.move_sheet('Listes', offset=len(wb.sheetnames))
    wb.save(chemin)


# ---------------------------------------------------------------- rapports

def tableau_md(entetes, lignes):
    sortie = ['| ' + ' | '.join(entetes) + ' |', '|' + '---|' * len(entetes)]
    for l in lignes:
        sortie.append('| ' + ' | '.join(str(x if x not in (None, '') else '—').replace('|', '/').replace('\n', ' ') for x in l) + ' |')
    return '\n'.join(sortie)


def rapport(inv: dict) -> str:
    vms, dem = inv['vms'], [v for v in inv['vms'] if v['etat'] == 'Démarrée']
    meta = inv['meta']
    gr = Counter(r['gravite'] for r in inv['risques'])
    pr = Counter(r['priorite'] for r in inv['risques'])
    os_c = Counter(v['os'] for v in dem)
    sup = Counter(v['support_os'] for v in dem)
    t = ["# Rapport d’audit de l’infrastructure EXAMPLE\n",
         f"Généré le {meta['genere_le']} à partir de `inventaire_brut.json`. {meta['methode']}\n",
         '## 1. Synthèse\n',
         f"- **{len(inv['noeuds'])} nœuds Proxmox** dans le cluster « {meta['cluster']} » ; "
         f"**{len(vms)} VM** ({len(dem)} démarrées, {len(vms) - len(dem)} arrêtées) ; "
         f"{len(inv['hors_cluster'])} serveur(s) déclaré(s) hors cluster.",
         f"- Ressources des VM démarrées : {sum(v['vcpu'] or 0 for v in dem)} vCPU, "
         f"{round(sum(v['ram_go'] or 0 for v in dem))} Go de RAM alloués ; "
         f"{round(sum(v['provisionne_go'] or 0 for v in vms) / 1024, 1)} To provisionnés au total.",
         f"- Système invité relevé (audit SSH) sur {sum(1 for v in dem if v['releve_ssh'])}/{len(dem)} VM démarrées ; "
         f"les autres sont listées en « Périmètres non couverts ».",
         f"- **{len(inv['risques'])} risques** : " + ', '.join(f"{g} {gr[g]}" for g in ('Critique', 'Élevée', 'Moyenne', 'Faible'))
         + ' ; ' + ', '.join(f"{p} {pr[p]}" for p in ('P1', 'P2', 'P3')) + '.',
         f"- {len(inv['incoherences'])} incohérences entre Proxmox et l’inventaire déclaré.\n",
         '## 2. Sources et méthode\n',
         tableau_md(['Source', 'Méthode', 'Date', 'Périmètre', 'Statut'],
                    [(s['source'], s['methode'], s['date'], s['perimetre'], s['statut']) for s in meta['sources']]),
         '\nAucune commande n’a été exécutée sur les serveurs pendant cet audit. Les seuls accès réseau sont des '
         'requêtes GET sur l’API Proxmox (jeton PVEAuditor). Les données SSH, Zabbix, Wazuh et Bacula proviennent '
         'des collectes en lecture seule déjà réalisées par OpsControl, datées ci-dessus.\n',
         '## 3. Hyperviseurs\n',
         tableau_md(['Nœud', 'IP', 'PVE', 'Noyau', 'CPU', 'RAM (Go)', 'VM (démarrées)'],
                    [(n['nom'], n['ip_management'], n['version'], str(n['noyau'] or '').split(' ')[1] if n.get('noyau') else '',
                      f"{n['cpu_modele']} ({n['cpu_threads']} threads)", n['ram_totale_go'], f"{n['nb_vm']} ({n['nb_demarrees']})")
                     for n in inv['noeuds']]),
         f"\nCeph (myceph) : **{(inv.get('ceph') or {}).get('sante', A_COMPLETER)}** — alertes : "
         f"{', '.join((inv.get('ceph') or {}).get('alertes') or []) or 'aucune'}.\n",
         '## 4. Stockages\n',
         tableau_md(['Stockage', 'Type', 'Portée', 'Total (Go)', 'Occupation', 'VM', 'Provisionné (Go)', 'Redondance'],
                    [(s['cle'], s['type'], s['partage'], s['total_go'], f"{s['occupation_pct']} %", s['nb_vms'], s['provisionne_go'], s['redondance'])
                     for s in inv['stockages']]),
         '\nCapacité « provisionnée » = taille déclarée des disques ; « utilisé » = consommation vue par Proxmox sur le '
         'support ; l’occupation dans les systèmes de fichiers invités figure à part (03_VMs). Les trois ne sont pas comparables.\n',
         '## 5. Systèmes d’exploitation (VM démarrées)\n',
         tableau_md(['OS', 'VM'], os_c.most_common()),
         '\n' + tableau_md(['Statut de support', 'VM'], sup.most_common()),
         '\nLes dates de fin de support sont celles des calendriers éditeurs (référence endoflife.date) : niveau DÉCLARÉ, à revérifier '
         'avant décision.\n',
         '## 6. Risques prioritaires (P1)\n',
         tableau_md(['ID', 'Composant', 'Description', 'Gravité', 'Preuve'],
                    [(r['id'], r['serveur'], r['description'], r['gravite'], r['preuve'][:160]) for r in inv['risques'] if r['priorite'] == 'P1']),
         '\n## 7. Incohérences entre sources\n',
         tableau_md(['Objet', 'Type', 'Détail', 'Action'], [(i['objet'], i['type'], i['detail'], i['action']) for i in inv['incoherences']]) or 'Aucune.',
         '\n## 8. Périmètres non couverts\n',
         'Aucun serveur de cette liste n’a été audité : les informations correspondantes restent « À compléter ».\n',
         tableau_md(['Objet', 'Périmètre', 'Raison', 'Action'],
                    [(f"{n['objet']} {n.get('nom') or ''}", n['perimetre'], n['raison'], n['action']) for n in inv['non_couverts']]),
         '\n## 9. Actualisation\n',
         '```bash\n'
         '.venv/Scripts/python.exe inventaire_proxmox.py data/inventaire/proxmox-live-AAAA-MM-JJ.json\n'
         '.venv/Scripts/python.exe inventaire_complet.py --proxmox data/inventaire/proxmox-live-AAAA-MM-JJ.json\n'
         '.venv/Scripts/python.exe inventaire_complet_rendu.py data/inventaire/AAAA-MM-JJ\n```\n',
         'Les annotations manuelles (data/inventaire/annotations.csv) sont relues à chaque génération et jamais écrasées ; '
         'l’onglet 20_Changements compare à l’inventaire précédent (VM ajoutées, supprimées, déplacées, versions modifiées). '
         'Voir docs/INVENTAIRE.md.\n']
    return '\n'.join(t)


def plan_actions(inv: dict) -> str:
    t = ['# Plan d’actions priorisé — infrastructure EXAMPLE\n',
         f"Généré le {inv['meta']['genere_le']}. Recommandations seulement : aucune n’a été appliquée. "
         'Chaque action renvoie aux risques de l’onglet 17_Risques.\n']
    for p in ('P1', 'P2', 'P3'):
        t.append(f"## {p} — horizon {HORIZON[p]}\n")
        t.append(tableau_md(['Action', 'Catégorie', 'Recommandation', 'Gravité max', 'Nb', 'Périmètre', 'Risques', 'Responsable proposé'],
                            [(a['id'], a['categorie'], a['recommandation'], a['gravite'], a['nb'], a['perimetre'][:300],
                              a['risques'][:200], a['responsable'])
                             for a in inv['actions'] if a['priorite'] == p]))
        t.append('')
    return '\n'.join(t)


def ecrire_csv(chemin: Path, inv: dict) -> None:
    champs = ['source', 'type_source', 'relation', 'cible', 'type_cible', 'preuve', 'confiance']
    with chemin.open('w', encoding='utf-8-sig', newline='') as f:
        w = csv.DictWriter(f, fieldnames=champs, delimiter=';', extrasaction='ignore')
        w.writeheader()
        w.writerows(inv['dependances'])


def main(argv=None) -> int:
    a = argparse.ArgumentParser(description='Livrables de l’inventaire complet')
    a.add_argument('dossier')
    args = a.parse_args(argv)
    dossier = Path(args.dossier)
    inv = preparer(json.loads((dossier / 'inventaire_brut.json').read_text(encoding='utf-8')))
    try:
        ecrire_classeur(dossier / CLASSEUR, inv)
    except PermissionError:
        raise SystemExit(f'{dossier / CLASSEUR} est ouvert (Excel ?) : le fermer puis relancer.') from None
    (dossier / 'rapport_audit_infrastructure.md').write_text(rapport(inv), encoding='utf-8')
    (dossier / 'plan_actions_priorise.md').write_text(plan_actions(inv), encoding='utf-8')
    ecrire_csv(dossier / 'matrice_dependances.csv', inv)
    print(f'{dossier} : classeur, rapport, plan d’actions et matrice écrits ({len(inv["actions"])} actions).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
