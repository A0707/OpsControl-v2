# Services, applications et traitements

## Fiche serveur

L'onglet **Services & applications** contient cinq vues ; seule la vue choisie est
construite. Les sélections et recherches sont conservées par serveur :

| Vue | Utilité |
| --- | --- |
| Synthèse de fonctionnement | Unités à vérifier, criticité configurée, anomalies Batch récentes, résultats inconnus et couverture |
| Unités systemd | Recherche, états actifs / inactifs / failed / unknown, criticité, sous-état et observation SSH |
| Batchs & planification | Traitements de ce serveur, recherche par nom / chemin / horaire / compte, type et pagination de 50 lignes |
| Applications | Relevé applicatif, sites locaux, conteneurs et filtres déjà disponibles |
| Sites publiés | Enregistrements WAF / proxy renvoyant vers ce serveur, port et cible observés |

Le lien vers la page Batch conserve le serveur sélectionné. Les preuves d'audit
restent accessibles à tout moment. Une unité `active/exited` peut être normale
pour un oneshot ; `active` ne valide pas le résultat HTTP, SQL ou métier. Les
services inactifs non critiques peuvent être volontairement arrêtés. Aucun
rapprochement application → unité → batch n'est inventé à partir de leurs noms.

## Page Services

La pagination reste calculée côté serveur, à raison de 100 unités par page dans
l'interface (maximum API : 500). Le GET existant `/api/services/units` accepte les
états `failed`, `all`, `active`, `inactive`, `critical` (criticité configurée) et
`unknown`, ainsi que `freshness=all|recent|stale`. La recherche du nom est bornée
à 120 caractères. Aucune route d'écriture supplémentaire.

Les compteurs concernent le périmètre de serveurs, la recherche et la fraîcheur
sélectionnés, avant le filtre d'état : échecs récents, unités critiques déclarées,
observations anciennes, serveurs sans relevé d'unités. Le compteur des serveurs
sans unités porte sur les serveurs sélectionnés, indépendamment de la recherche
d'un nom d'unité. Une absence de relevé n'est pas une preuve d'absence de service.
Un filtre qui ne sélectionne aucun serveur ne déclenche pas un chargement du parc.

Chaque ligne conserve l'état, le sous-état et la date de collecte. Les audits de
plus de 15 minutes, retenus après un échec ou antérieurs à une modification de
configuration sont neutres : le dernier état reste consultable, à reconfirmer.
Le bouton **Unités et preuves** ouvre la fiche du serveur dans la vue correspondante.

## Page Batch / Planification

### Référentiel des batchs métier (vue par défaut)

La page s'ouvre sur le **référentiel** : la liste des batchs qui devraient tourner
(nom, responsable, serveur, script, fichiers properties, envoi de mail, horaire
attendu, statut, validation, commentaires). Il est lu dans `data/batch_catalog.yaml`
(hors Git, pré-rempli depuis le document « batch.pdf ») ou dans le fichier désigné
par `INFRAOPS_BATCH_CATALOG`. Le format est décrit dans `batch_catalog.example.yaml`.
Le fichier est relu à chaque affichage : une modification ne demande pas de redémarrage.

Chaque fiche est rapprochée des preuves déjà collectées, sans nouvelle connexion :

| Constat | Preuve utilisée |
|---|---|
| Planification concordante ou horaire différent | Ligne cron dont le script correspond au chemin du référentiel (`script/` et `scripts/` tolérés) |
| Planification non vérifiable | La crontab de root / batchuser n'a pas été lue par le compte d'audit |
| Script présent ou introuvable | Liste des scripts présents sous `/var/batch` (chemin et date, jamais le contenu) |
| Dernier résultat | Fichier d'état `infraops-batch-report` remonté par Zabbix (`deploy/batch-setup.md`) |
| Arrêt demandé mais encore planifié | Statut « Désactivé », `attendu: arrete` ou ligne cron observée |
| Non référencé | Script de `/var/batch` planifié ou en cours, absent du référentiel |

**Résultat et cause du dernier passage** (colonne « Dernier résultat », détail
« Pourquoi ») — de la preuve la plus forte à la plus faible :

1. enveloppe lue par la sonde SSH : code retour, durée et 40 dernières lignes
   masquées de la sortie d'erreur (`/var/lib/infraops-batch/NOM.tail`) ;
2. enveloppe remontée par Zabbix : code retour, complété par le journal ;
3. journal du batch : verdict déduit (statut Spring Batch, sinon erreur après le
   dernier marqueur de fin). Le journal retenu est celui de la ligne cron, sinon
   celui au nom du script, sinon le plus récent du dossier (signalé « à confirmer »
   quand plusieurs batchs partagent le dossier).

Constats associés : passage en échec (avec la ligne qui l'explique), code retour 0
mais erreur dans le journal, et batch quotidien sans passage ni journal mis à jour
depuis plus de 26 h (lancement manqué). Voir `deploy/batch-setup.md`.

**Vue Exécutions** : un batch par ligne, du passage le plus récent au plus ancien,
avec début d'exécution, fin, durée, résultat, source, cause et incident. Le début
n'est connu qu'avec l'enveloppe (ou Zabbix) : un journal ne date que sa dernière
écriture, affichée comme fin approchée.

**Incidents** : la source « Batch » du centre d'alertes ouvre un incident par batch
en échec au dernier passage (majeur ; critique si `criticite` ≥ 3 dans le
référentiel) et par batch quotidien sans passage depuis plus de 26 h (majeur).
L'incident porte la cause en preuve et se résout seul au passage réussi suivant,
à condition que l'inventaire batch du serveur soit récent ; sinon il reste ouvert
(absence d'échec non vérifiable). Un batch hors inventaire SSH (Swarm) n'en
ouvre pas.

Vues : **Référentiel**, **Exécutions**, **Écarts à traiter** (échecs et écarts hors informations à
compléter) et **Non référencés**. Un batch « À confirmer » n'est pas conforme : il
manque une preuve. Tant que la crontab root n'est pas lue, les absences de
planification ne sont jamais présentées comme des écarts. Les batchs hébergés sur
Swarm restent hors rapprochement SSH.

### Inventaire relevé

Les vues **Inventaire relevé** (anciennement Tous les traitements), **Priorités récentes**, **En cours**,
**Planifications**, **Résultats observés** et **Couverture par serveur** utilisent
les données déjà collectées. Les filtres serveur, type, état, recherche et fraîcheur
restent actifs lors des changements de vue. Le tableau est paginé par 50 lignes.

- Un cron **planifié** signifie que l'horaire est déclaré ; le résultat reste inconnu.
- Un processus **en cours** ne garantit ni sa progression ni sa réussite finale.
- Les résultats observés proviennent du dernier résultat systemd ou des jobs Bacula.
- Les priorités montrent uniquement les échecs et avertissements récents.
- Un résultat ancien n'est pas présenté comme une panne actuelle.

Les détails **Preuves et exécution** exposent le code retour, le PID et la durée
observée seulement lorsque la sonde les a fournis. Le code retour `0` est conservé.
Cette durée est celle du processus au relevé, pas une durée finale. Les horaires
conservent le fuseau de chaque source. Aucune prochaine exécution cron ni retard
métier ne sont calculés sans données suffisantes. Les arguments des scripts ne
sont pas collectés car ils peuvent contenir des secrets.

L'inventaire peut manquer les comptes privés, scripts inactifs non planifiés,
ordonnanceurs applicatifs et logs non accessibles. La vue Couverture explique ces
limites par serveur. L'actualisation SSH reste un bouton explicite ; la navigation,
les filtres et l'ouverture des preuves ne démarrent aucun traitement ni collecte.

## Mise en service et validation

Aucune migration de base ni changement de sonde distante pour cette évolution.
Le sous-état systemd apparaît avec les audits réalisés par la nouvelle version du
collecteur. L'API Services nécessite le rechargement du processus OpsControl ;
les ressources web doivent également être rechargées dans le navigateur.

```powershell
.venv/Scripts/python.exe deploy/assets_version.py
$env:OPS_BROWSER_CHANNEL = 'msedge'
.venv/Scripts/python.exe deploy/ci.py --offline --ui
```

Les tests utilisent uniquement un parc simulé et couvrent les filtres, la
pagination, les observations anciennes, les unités `active/exited`, les résultats
inconnus, le code retour zéro, l'échappement HTML, la navigation sans POST et les
formats desktop / mobile.
