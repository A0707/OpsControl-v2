"""Contrat du contexte applicatif (lot 7).

Les modules reçoivent le module app comme « contexte » (install(app, context)). Ce contrat
rend l'interface explicite : chaque attribut lu par un module y est déclaré, avec son rôle
et son fournisseur. test_app_context.py vérifie qu'aucun module n'utilise un attribut non
déclaré, et que chaque attribut déclaré existe bien une fois l'application assemblée.

Fournisseur « app » : défini dans app.py ; sinon, le module qui l'installe.
Exportés mais lus par aucun module (non contractuels) : critical_job, tier0_revision,
ssh_refresh_state, sync_incidents, refresh_itsm. Lus par app.py seul (lifespan) :
start_incident_sync, stop_incident_sync, start_itsm_sync, stop_itsm_sync.
"""

CONTRACT = {
    # Données et persistance locale
    'DB': ('app', 'Chemin SQLite local ; vérifie la séparation des bases IA.'),
    'connect': ('app', 'Connexion SQLite (gestionnaire de contexte, WAL).'),
    'rows': ('app', 'Inventaire joint au dernier audit SSH de chaque serveur.'),
    'network_rows': ('app', 'Dernière sonde réseau de chaque serveur.'),
    'read_setting': ('app', 'Lecture d’un réglage local.'),
    'write_setting': ('app', 'Écriture d’un réglage local.'),
    'data_revision': ('app', 'Révision bon marché des données servies (cache de réponses).'),
    'read_model_revision': ('app', 'Génération des écritures validées par synthèse de sécurité.'),
    # Inventaire et configuration
    'BASE': ('app', 'Répertoire de l’application (données, inventaire).'),
    'INVENTORY': ('app', 'Chemin de l’inventaire sélectionné par INFRAOPS_INVENTORY ou hosts.yaml.'),
    'HOSTS': ('app', 'Inventaire chargé (liste partagée, modifiée sous verrou).'),
    'cfg': ('app', 'Configuration SSH (lecture seule).'),
    'WORKERS': ('app', 'Parallélisme maximal des collectes.'),
    # Collectes SSH / réseau et leur état
    'job': ('app', 'État de la collecte SSH en cours (lire sous lock).'),
    'lock': ('app', 'Verrou de job et monitor.'),
    'net_job': ('app', 'État de la sonde réseau en cours (lire sous net_lock).'),
    'net_lock': ('app', 'Verrou de net_job.'),
    'monitor': ('app', 'Intervalle d’actualisation choisi par l’opérateur.'),
    'launch': ('app', 'Lance une collecte SSH (jamais deux en parallèle).'),
    'launch_network': ('app', 'Lance une sonde réseau.'),
    'collection_done': ('app', 'Rappels après collecte (rapprochement des incidents…).'),
    # Sources API
    'api_connections': ('management', 'Connexions API déclarées, avec leur dernier résultat.'),
    'api_revision': ('management', 'Révision des connexions (change à chaque collecte API).'),
    'api_change': ('management', 'Dernière source modifiée (rafraîchissement ciblé du temps réel).'),
    'collect_api_connection': ('management', 'Collecte en lecture d’une source (instrumentée par self_monitor).'),
    'add_discovered_hosts': ('management', 'Ajoute à l’inventaire des serveurs découverts et prouvés.'),
    'api_sync_state': ('synchronization', 'État de la synchronisation API.'),
    'launch_api_sync': ('synchronization', 'Lance la synchronisation API.'),
    # Traitements, voie rapide, incidents
    'batch_job': ('batch_monitor', 'État de l’inventaire batch.'),
    'batch_snapshot': ('batch_monitor', 'Traitements batch rapprochés des serveurs.'),
    'launch_batches': ('batch_monitor', 'Lance l’inventaire batch.'),
    'tier0_snapshot': ('tier0', 'État de la voie rapide (serveurs de niveau 0).'),
    'tier0_tick': ('tier0', 'Battement de la voie rapide.'),
    'ssh_refresh_tick': ('ssh_refresh', 'Battement du réaudit en rotation.'),
    'incident_sync_info': ('incident_center', 'Dernier rapprochement (santé d’OpsControl).'),
    # Sécurité & CVE
    'security_tick': ('security_cve', 'Battement de la veille sécurité et du relevé des paquets.'),
    'security_vuln_snapshot': ('security_cve', 'Vulnérabilité validée relue côté serveur pour un dossier ITSM.'),
    'security_vuln_states': ('security_cve', 'État des vulnérabilités d’origine des dossiers ITSM.'),
    'security_center_alerts': ('security_cve', 'Alertes de veille critiques non lues, pour le centre d’alertes.'),
    'security_read_cache_close': ('security_cve', 'Fermeture du cache de synthèses et de son observateur SQLite à l’arrêt.'),
}
