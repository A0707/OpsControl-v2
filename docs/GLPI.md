# GLPI 11 — gestion ITSM volontaire

## Audit préalable et architecture

Le dépôt utilise FastAPI 0.141.1, Uvicorn 0.52.4, Pydantic 2 et SQLite WAL,
avec JavaScript vanilla et des registres frontend (`pageRenderers`, `hostSection`).
Les dépendances sont épinglées dans `requirements.txt`. Aucune dépendance ajoutée.

- `incident_center.py` possède les incidents stables, la prise en charge, les dates,
  les preuves expurgées et `incident_events`. Les rapprochements des sources peuvent
  résoudre ou rouvrir un incident ; ils ne font aucun appel GLPI.
- `web/app.js` / `web/findings-full.js` présentent sous « Problèmes » des constats
  SSH, pas des problèmes ITIL persistants. La qualification récurrente ou structurelle
  est donc une décision humaine explicite, conservée dans un dossier ITSM.
- `access_policy.py` centralise authentification, CSRF, quotas et journal des mutations.
  `operator_identity.py` distingue identité proxy authentifiée et nom local déclaratif.
- `management.py`, `synchronization.py`, les connecteurs Zabbix/Wazuh/Proxmox,
  les sondes et les règles WAF restent indépendants du workflow ITSM.
- Les modules appliquent leurs migrations locales au démarrage ; `itsm_v1` suit cette
  convention. Le dépôt ne contenait pas de connecteur GLPI.
- `deploy/ci.py` couvre tests, sécurité, versions des assets et navigateur simulé.

L'implémentation ajoute `glpi_connector.py`, `itsm.py`, `web/itsm.js` et les tests
`test_itsm.py` / `test_ui_itsm.cjs`. Les seules adaptations des modules existants sont
l'installation, les règles POST et les points d'entrée d'interface.

## API vérifiée

GLPI 11 possède aussi une nouvelle API High-Level avec une autre authentification.
Ce connecteur utilise explicitement **REST V1**, disponible dans GLPI 11 et adaptée
aux jetons App/User demandés. Activer cette API dans GLPI ; ne pas utiliser une URL
High-Level à sa place.

Références officielles consultées :

- [REST V1 dans la branche GLPI 11](https://github.com/glpi-project/glpi/blob/11.0/bugfixes/apirest.md)
- [Présentation de la High-Level API](https://glpi-developer-documentation.readthedocs.io/en/master/devapi/hlapi/index.html)
- [Acteurs ITIL GLPI 11](https://github.com/glpi-project/glpi/blob/11.0/bugfixes/src/CommonITILObject.php)

Sessions : `GET initSession` avec Authorization `user_token`, App-Token ; fermeture
`GET killSession` dans un `finally`. Création via `POST Ticket/` (type 1 : incident)
ou `POST Problem/`. Aucun champ de date GLPI n'est envoyé.
Les relations `Group_Ticket` / `Group_Problem` utilisent `type=3` (observateur),
`groups_id` et respectivement `tickets_id` / `problems_id`. Elles sont relues avant
et après ajout. Le groupe configuré doit correspondre à le groupe observateur choisi ; son nom
n'est pas supposé à partir de son ID. Vérifier droits et relation sur la préproduction.

## Configuration serveur

Déclarer dans l'environnement protégé du service, jamais dans Git ni le navigateur :

```dotenv
GLPI_ENABLED=false
GLPI_BASE_URL=https://glpi.example.test
GLPI_ENTITY_ID=0
GLPI_REQUESTER_ID=1
GLPI_OBSERVER_GROUP_ID=1
GLPI_VERIFY_TLS=true
GLPI_TIMEOUT_SECONDS=15
OPSCONTROL_PUBLIC_URL=https://opscontrol.example.test
GLPI_STATUS_SYNC_SECONDS=900
GLPI_AUTO_RESOLVE=true
GLPI_AUTO_RESOLVE_DELAY_SECONDS=600
```

Définir séparément `GLPI_APP_TOKEN` et `GLPI_USER_TOKEN` avec des jetons neufs.
Les identifiants sont des exemples fictifs à remplacer, sans valeur de repli dans le code.
La base est l'URL de l'application (sous-répertoire autorisé), sans `/apirest.php`.
Le connecteur ajoute ce chemin. HTTPS et vérification TLS sont obligatoires ; les
redirections sont refusées pour éviter la transmission des jetons à une autre origine.
Installer la CA interne dans le magasin de confiance Python si nécessaire.
Le délai est borné à 1–60 secondes, les IDs demandeur/groupe doivent être positifs.
Une configuration absente ou invalide désactive les opérations GLPI sans empêcher
la supervision. Les paramètres se modifient via l'environnement serveur uniquement.

Après installation du code, redémarrer le processus OpsControl lors d'une fenêtre
autorisée : les scripts web sont servis depuis le disque, mais les routes Python
restent celles chargées au démarrage. Un frontend récent avec un ancien processus
peut afficher un formulaire puis obtenir 405 sur le POST. Le dialogue vérifie
désormais `GET /api/itsm/status` et bloque la soumission si le backend est absent.
Un simple rechargement du navigateur ne suffit pas à charger les routes Python.

Créer un compte GLPI dédié avec lecture/création Ticket et Problem, accès à l'entité,
au demandeur et au groupe observateur, et recherche des objets créés. Vérifier les
modèles/règles GLPI pouvant imposer d'autres champs. Aucun ancien webhook Zabbix ou
ancien jeton ne doit être restauré. L'activation nécessite une validation d'exploitation.

### GLPI interne sans HTTPS (dérogation)

Si GLPI n'est joignable qu'en HTTP (ex. `http://glpi.example.test:9090`), la dérogation
doit être double et explicite :

```dotenv
GLPI_BASE_URL=http://glpi.example.test:9090
GLPI_ALLOW_HTTP=true
GLPI_HTTP_HOSTS=glpi.example.test
```

Les jetons App/User et le contenu des tickets traversent alors le réseau **en clair** :
réserver ce mode à un réseau interne de confiance, et passer GLPI en HTTPS dès que
possible (puis retirer les deux lignes `GLPI_ALLOW_HTTP` / `GLPI_HTTP_HOSTS`). Le dialogue
ITSM signale « liaison GLPI en HTTP non chiffré ». Un autre hôte en HTTP reste refusé.

### Poste Windows

Créer `data\glpi.env` (hors Git) avec les lignes `GLPI_*` non secrètes ci-dessus
(`GLPI_ENABLED=true`, URL, `GLPI_ENTITY_ID`, `GLPI_REQUESTER_ID`, `GLPI_OBSERVER_GROUP_ID`…),
puis relancer `.\LANCER-INFRAOPS.ps1 -Force`. Le lanceur demande une fois `GLPI_APP_TOKEN`
et `GLPI_USER_TOKEN` et les conserve dans le coffre chiffré Windows ; pour les remplacer :
`.\LANCER-INFRAOPS.ps1 -Force -UpdateSources GLPI`.

## Utilisation et permissions

Points d'entrée : détail d'un incident (journal Incidents), constat d'audit (Problèmes),
bouton « Ticket GLPI » de chaque alerte (page Alertes, hors informations) et de chaque
problème (page Zabbix). Pour une alerte ou un problème Zabbix, le serveur relit l'élément
dans ses propres données au moment de la prise en charge ; une occurrence déjà transmise
rouvre son dossier, une nouvelle occurrence de la même cause ouvre un nouveau dossier.

1. Dans le journal Incidents, reconnaître ou investiguer l'incident.
2. Ouvrir son détail, puis « Gestion ITSM / GLPI » et prendre en charge le dossier.
   Depuis Audit / Problèmes, sélectionner le constat et prendre en charge son dossier.
3. Choisir Incident ponctuel ou Problème récurrent/structurel. Pour un problème,
   expliquer la qualification (au moins 10 caractères).
4. Prévisualiser : génération et journalisation locales, aucun appel GLPI.
5. Vérifier le contenu, l'entité, le demandeur et l'ID du groupe, puis confirmer.
6. Le lien GLPI et le dernier résultat apparaissent dans le dossier.
   « Dossiers ITSM » permet de retrouver les associations et leur historique.

Les quatre POST `/api/itsm/take`, `/preview`, `/create`, `/reconcile` exigent admin,
avec quota `mutation` et contrôles backend. Les GET sont accessibles aux viewers.
En mode local, le nom est obligatoire et marqué déclaratif ; `INFRAOPS_LOCAL_OPERATOR`
(fichier `data\poste.env` sur le poste Windows) le préremplit et le fournit si le champ
est vide. L'authentification proxy
reste recommandée en production. Les paramètres ne sont pas modifiables par HTTP.
Le champ « Votre nom pour cette opération » reste visible dans le détail du dossier,
y compris après réouverture ; il reprend le dernier nom saisi sur ce navigateur.
Il identifie l'action courante et ne réattribue pas le responsable historique du dossier.

## Statut à la création, suivi et résolution automatique

Chaque alerte, problème Zabbix et incident de la fiche serveur lié à un dossier affiche
un badge « GLPI #28 · Nouveau » (tous rôles), qui ouvre le dossier. Sans numéro GLPI
confirmé, le badge indique « Dossier OC-… » et l'état du dossier. Pour une alerte ou un
problème Zabbix, c'est le dossier le plus récent de la même cause qui est affiché.
`GET /api/itsm/links` fournit cette correspondance (origine, identifiant source, numéro
et statut GLPI, état de l'anomalie, incohérence) sans URL ni destination GLPI.

À la création, le ticket est envoyé avec `status=2` (« En cours (attribué) ») et
assigné au groupe `GLPI_OBSERVER_GROUP_ID` (`_groups_id_assign`), qui reste aussi
observateur : GLPI remet à « Nouveau » un ticket « En cours » sans assigné. La
prévisualisation l'indique.

Un fil de fond relit les tickets associés toutes les `GLPI_STATUS_SYNC_SECONDS` secondes
(900 par défaut, borné à 300–86 400, `0` désactive ; premier passage une minute après le
démarrage). Il lit par `GET initSession`, `GET Ticket/<id>` ou `GET Problem/<id>` et
`GET killSession`. Au plus
200 tickets par passage ; un ticket clos n'est relu qu'une fois par jour. Chaque
changement de statut entre dans l'historique du dossier (« OpsControl (relecture GLPI) »).
Connecteur désactivé ou session refusée : statut précédent conservé, aucun dossier modifié.
Le bouton « Lire le statut GLPI » du dossier reste disponible pour une relecture immédiate.

**Preuve de résolution.** Problème Zabbix : seule une liste de problèmes récente (moins
de 15 min) et non plafonnée (moins de 500 triggers) prouve qu'un trigger n'est plus en
anomalie ; sinon l'état reste inconnu et aucune solution n'est envoyée. Alerte SSH : la
dernière collecte doit être récente ET avoir mesuré le contrôle concerné (disque,
mémoire, service…), pas seulement une autre mesure.

**Résolution automatique** (`GLPI_AUTO_RESOLVE=true` par défaut, `false` la désactive) :
quand l'anomalie d'origine est résolue dans OpsControl depuis au moins
`GLPI_AUTO_RESOLVE_DELAY_SECONDS` (600 s par défaut, 0 à 86 400) et que le ticket est
encore ouvert, le passage suivant ajoute une solution (`POST ITILSolution/`, texte
« Résolu automatiquement par OpsControl… », date de fin observée, référence) : GLPI passe
le ticket à « Résolu ». C'est la seule écriture du fil de fond ; il ne clôt, ne rouvre et
ne supprime jamais rien. Une seule tentative par résolution, réservée avant l'appel (pas
de doublon) ; un échec (droits, réseau) est noté dans l'historique, le ticket reste
signalé en incohérence et doit être résolu à la main. Si l'anomalie revient puis se
résout de nouveau, une nouvelle tentative est permise. Délai maximal entre la résolution
dans OpsControl et GLPI : délai de confirmation + intervalle de relecture (25 min par
défaut ; réduire `GLPI_STATUS_SYNC_SECONDS` jusqu'à 300 pour aller plus vite).
« Résolue » suit les règles ci-dessous : un état inconnu ne résout jamais un ticket.
Le compte de service GLPI doit pouvoir ajouter une solution (droit « Résoudre » sur les
tickets et problèmes de l'entité) ; si GLPI exige l'approbation de la solution par le
demandeur, le ticket passe à « Résolu » et sa clôture suit les règles GLPI.

Statuts : 1 Nouveau, 2 En cours (attribué), 3 En cours (planifié), 4 En attente,
5 Résolu, 6 Clos. Incohérences signalées en orange (badge et page « Dossiers ITSM ») :

- anomalie résolue dans OpsControl alors que le ticket est ouvert (1 à 4) ;
- ticket résolu ou clos alors que l'anomalie est toujours active.

L'état d'un incident est lu en direct dans le journal. Celui d'une alerte ou d'un
problème Zabbix est relu à chaque passage : une alerte absente ne vaut « résolue » que
si sa source a tout mesuré (même règle que le journal d'incidents), un problème Zabbix
seulement si la dernière collecte de sa connexion a réussi. Sinon l'état reste inconnu et
aucune incohérence n'est supposée. Une alerte affichée est toujours considérée active.
Une incohérence « ticket clos, anomalie active » n'est jamais corrigée automatiquement :
OpsControl ne rouvre pas de ticket.

## Persistance, reprise et limites

`itsm_cases` conserve le type et l'ID source, le type GLPI, une référence UUID unique,
un instantané expurgé, le responsable et la date, les états, l'ID et la destination
distante, l'observateur configuré, l'empreinte de prévisualisation et la dernière erreur.
Unicité `(origin, origin_id, kind)` et `(kind, remote_base, remote_id)`. La migration
`itsm_v2` ajoute `remote_checked_at` (dernière relecture GLPI), `origin_state` et
`origin_checked_at` (état de l'alerte ou du problème Zabbix d'origine),
`origin_resolved_at` (début de résolution observé) et `auto_resolve_at` (tentative de solution).
`itsm_events` conserve auteur, date, action et résultat. Les historiques restent locaux
et ne suivent pas la rétention des preuves brutes. Prévoir leur conservation dans
les sauvegardes SQLite et les règles internes de protection des identités.

Une transaction `BEGIN IMMEDIATE` réserve l'opération ; elle est validée avant le
réseau. Deux clics concurrents ne peuvent pas envoyer deux POST de création.
L'ID confirmé est sauvegardé **avant** la lecture et l'ajout d'observateur.

- `failed` : refus explicite ou erreur avant POST ; nouvelle prévisualisation possible.
- `uncertain` : timeout, 5xx ou réponse de création sans ID valide ; création bloquée.
- `partial` : ID connu, vérification ou observateur incomplet ; reprise sur ce même ID.
- `creating` : requête en cours ; après arrêt brutal, rapprochement après cinq minutes.
- `linked` : objet et observateur vérifiés ; nouvelle création retourne l'association.

Le rapprochement cherche la référence dans le titre puis relit l'objet. Zéro ou
plusieurs résultats ne permettent pas de prouver l'absence : **aucune réinitialisation
automatique** n'est fournie. Un dossier sans correspondance unique reste bloqué pour
investigation manuelle GLPI (visibilité des entités, corbeille, journaux, permissions).
Cette restriction conservatrice évite un doublon lorsque la recherche est incomplète.
Un échec d'observateur reprend la lecture des relations avant tout nouvel ajout.
Un changement de destination GLPI sur un dossier commencé bloque la reprise.

Les dossiers Audit sont des instantanés, et la date d'audit n'est pas présentée comme
un début de panne confirmé. Seules les preuves disponibles sont exportées. Les
diagnostics et impacts inconnus restent explicitement à qualifier. Les changements
de collecte ne modifient pas GLPI ; un rétablissement confirmé résout le ticket par une
solution (voir ci-dessus), sans jamais le clore. Le statut GLPI est relu périodiquement
ou sur action humaine. Le lien retour ouvre OpsControl ; la référence
permet de retrouver le dossier dans « Dossiers ITSM ».

## Validation manuelle et rollback

Sur une instance de préproduction GLPI autorisée :

1. Sauvegarder la base OpsControl et configurer un compte dédié sans droits superflus.
2. Tester admin et viewer ; vérifier le refus d'un incident sans prise en charge.
3. Vérifier la prévisualisation et l'absence de ticket avant confirmation.
4. Créer un Incident puis un Problem qualifié ; contrôler entité, demandeur,
   groupe observateur, HTML, référence, lien et dates natives GLPI.
5. Double cliquer et vérifier un seul ID ; redémarrer OpsControl puis retrouver le lien.
6. Simuler coupure après POST et refus de relation en environnement isolé ; vérifier
   le rapprochement, l'ID conservé et le blocage d'une nouvelle création incertaine.
7. Simuler rétablissement Zabbix : vérifier qu'aucun ticket n'est créé ni clôturé, et
   qu'après le délai de confirmation une solution passe le ticket lié à « Résolu ».

Validation automatisée : `.venv/Scripts/python.exe deploy/ci.py --offline --ui`
avec `OPS_BROWSER_CHANNEL=msedge` si nécessaire. Les tests n'utilisent aucun GLPI réel.

Rollback : mettre `GLPI_ENABLED=false`, puis restaurer la version applicative précédente
après validation d'exploitation. Les deux tables ajoutées sont compatibles avec l'ancien
code et doivent être conservées pour éviter de perdre les références anti-doublons.
Ne pas restaurer une ancienne base par-dessus les associations récentes et ne pas
supprimer les tickets GLPI. Aucune migration, publication ou intervention de production
n'est exécutée par cette livraison.
