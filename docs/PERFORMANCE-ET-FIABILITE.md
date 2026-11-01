# Performance et fiabilité — lot du 28 octobre 2026

## Synthèses sécurité

`/api/security/summary` et `/api/security/recommendations` partagent désormais leur
résultat pendant cinq secondes au maximum. Une seule construction par route est
effectuée lorsque plusieurs lecteurs demandent la même génération. Les routes de
détail et les décisions d'opérateurs restent servies par leurs lectures habituelles.

La clé inclut la génération des écritures pertinentes, l'empreinte de l'inventaire
déclaré et l'état des travaux de sécurité. Les connexions de l'application observent
les tables modifiées via l'autoriseur SQLite ; aucune nouvelle table ni aucun trigger
n'est ajouté. Toutes les tables `sec_*` invalident les deux synthèses après commit.
Les audits `states` et les réglages invalident aussi les recommandations. Les
écritures réseau/API sans effet sur ces vues ne provoquent pas de nouveau calcul.
Un échec de transaction ne publie pas de nouvelle génération.

Les écritures réalisées directement par un programme externe, hors des connexions
de l'application, sont prises en compte à l'expiration de cinq secondes au plus.
Les contextes ne disposant pas de ce suivi utilisent `PRAGMA data_version` sur une
connexion de lecture conservée : toute écriture SQLite invalide alors la synthèse.
Les changements liés au temps sont recalculés au plus tard après cinq secondes.
`generated_at` reste la date réelle de construction, sans date artificiellement rafraîchie.

Le cache est borné aux deux synthèses, en mémoire, propre à l'instance. Il ne persiste
aucun résultat et n'exporte aucune donnée. La connexion d'observation ouvre la base
en lecture seule, ne conserve pas de transaction et se ferme à l'arrêt du lifespan.
Un changement de fichier est détecté par son identité ; un fichier inaccessible ou
une reconstruction en échec ne sont jamais remplacés par une ancienne synthèse.
Sans chemin de base, notamment pour un contexte de test en mémoire, le cache est contourné.

La première lecture après invalidation calcule toujours le résultat. Ce mécanisme
réduit les calculs répétés et simultanés, mais ne garantit pas à lui seul la latence
du premier calcul sur tous les volumes. Les mesures à froid et à chaud doivent rester
distinctes dans le suivi du SLO.

La synthèse SQL conserve les priorités et règles Wazuh, tout en remplaçant la jointure
avec les noms JSON du parc par une recherche déterministe dans un dictionnaire.
Les agrégats et les dix priorités partagent une seule lecture des preuves, matérialisée
en faits légers dans SQLite. Les versions corrigées identiques ne sont plus comparées
à nouveau pour chaque CVE du même paquet. Les comparaisons pures de versions sont
partagées dans un cache borné à 4 096 couples, sans modifier les règles dpkg/RPM
ni rendre valide une version illisible. Les recommandations n'injectent plus les milliers de CVE sans rapport avec le serveur
dans ses faits de classement. Les bulletins pertinents, y compris sans score NVD,
restent pris en compte.

## Qualité de collecte

Trois nombres différents figurent dans `/api/self-monitoring` et les métriques :

- `ssh_attempted_24h` : tentative datée de moins de 24 heures ;
- `ssh_24h` : même fenêtre, avec au moins un contrôle renseigné ;
- `ssh_complete_24h` : même fenêtre, tous les contrôles attendus renseignés et total positif.

`ssh_fresh` exige également au moins une mesure et une date dans le budget de
fraîcheur. `ssh_measured` reste le nombre d'hôtes ayant au moins un contrôle renseigné,
quel que soit l'âge. Un résultat incomplet ou absent ne prouve pas un serveur sain.
Voir `SLO.md` pour les compteurs et leur changement de sens.

## Notification commune

La transition « hors service » de la sonde directe réveille la lecture normale des
alertes. Le journal, l'ancienneté, les prises en charge et les maintenances s'appliquent
ainsi à cette voie. La preuve de sonde, comme celle de Zabbix, doit avoir au plus
30 secondes. Le début de l'occurrence reste limité à 15 minutes. Les anciens incidents
restent dans les listes opérationnelles.

Les notifications Windows restent liées au navigateur ouvert et à sa permission.
Une livraison persistante vers un canal externe constitue un lot distinct : aucune
garantie de livraison navigateur fermé n'est introduite par cette évolution.

## Vérifications de non-régression

Tests sur SQLite temporaires et événements simulés : invalidation après écriture,
expiration, changement d'inventaire, partage entre lecteurs concurrents, base indisponible,
reconstruction en échec, fermeture de l'observateur, conservation du classement et des
compteurs ; refus d'interruption pour les incidents déjà pris en charge, masqués ou
résolus, y compris après une transition de la sonde. Aucun test ne doit joindre le parc.
