# Migration progressive du frontend vers les modules ES

## Objectif et contrat de livraison

Conserver JavaScript vanilla, les URL et la CSP actuelles, sans imposer de bundler.
Une étape ne migre que les fichiers indiqués ; les scripts restants continuent de
fonctionner. Ne pas mélanger cette migration avec une refonte UX ou des endpoints.

Avant et après **chaque étape** : exécuter tous les `test_ui*.cjs`, puis
`python deploy/ci.py --offline`. `test_ui_v2.cjs` doit conserver son assertion
d’absence de requête non-GET pendant la navigation. Les actions explicites
d’opérateur restent testées séparément : aucun module ne lance un POST à l’import.
Pas d’erreur JavaScript, de doublon d’écouteur, de régression mobile/clavier ou
de perte des valeurs saisies. Les requêtes GET concurrentes restent dédupliquées.

Les fixtures navigateur simulent les API ; les parcours exigeant une instance
utilisent une instance locale synthétique, jamais le parc réel. Conserver les
assertions métier et de sécurité lors de l’adaptation des tests de structure.

## État de départ

`app.js` déclare les utilitaires, l’état, le routage, les registres de rendu et le
planificateur. Les extensions lisent ces symboles par leur environnement global
et s’enregistrent à leur chargement. `index.html` impose leur ordre, notamment
`app.js`, `freshness.js`, `v2-ui.js`, puis les pages et le shell `v2.js`/`parc-next.js`.
Les pages lourdes sont déjà chargées paresseusement : cette propriété doit rester.

## Étapes

| Étape | Fichiers et contrat | Critères propres à l’étape |
|---|---|---|
| **1 — utilitaires et composants purs** | Extraire `esc`, `escAttr`, `api`, `post`, `SEVERITY` dans `frontend-utils.js`. Convertir `v2-ui.js` avec des imports explicites et une fabrique recevant `freshnessMarkup`. Installer un point d’entrée ES `frontend-bootstrap.js` et un pont temporaire limité à ces exports et `ui`. Les pages restent classiques. | Échappement et valeurs absentes identiques ; jauges/CSP inchangées ; messages 401/403/429 et headers POST conservés ; un GET concurrent n’est émis qu’une fois. Le chargement de tous les scripts classiques précède le démarrage des données et du planificateur. Retard de chargement testé. Tous les tests navigateur au vert, dont la navigation GET uniquement. |
| 2 — fraîcheur | Convertir `freshness.js`, importer ses fonctions dans `v2-ui.js`, retirer son injection temporaire. | Âges, grisage, retour d’onglet visible et absence de faux rafraîchissement d’une preuve ; même planificateur, aucun nouvel intervalle. Suite navigateur complète. |
| 3 — services du noyau | Extraire progressivement d’`app.js` les détails ouverts, notifications, identité/rôles, puis `poll` et ses registres, un module à la fois. | Un seul intervalle ; noms de tâches uniques ; pas de chevauchement ; quotas/401/403/429 visibles ; droits appliqués après rendu ; tests lifecycle/access/notifications et suite complète. |
| 4 — état et navigation | Module d’état explicite (`state`, sélection, filtres, révision), puis routage et registres (`renderHooks`, `navigationHooks`, `pageRenderers`, `sourceLoaders`, `hostSection`). Les modules consomment des fonctions d’accès à l’état, pas une copie figée. | Filtres et focus conservés lors du polling, liens profonds/Retour/Suivant et onglets serveur identiques ; hooks sans double inscription. Tests host_tabs/lifecycle/lazy/v2 et suite complète. |
| 5 — shell V2 | Migrer `v2-dashboard.js`, puis `v2.js`, puis `parc-next.js` et le module paresseux `v2-detail.js`, chacun dans une livraison. | Navigation/hubs, chronologie, liens profonds, tables paginées et rôles inchangés ; `v2-detail.js` reste paresseux. Suite complète, GET uniquement pendant la navigation. |
| 6 — pages de sources | Migrer une source à la fois : `source-ui.js`, `proxmox.js`, `elastic.js`, `zabbix.js`, `wazuh.js`, `bacula.js`, `shares.js`. Remplacer les chargeurs de ces seuls fichiers par `import()`. | Requêtes seulement à l’ouverture de la page, aucune collecte POST implicite ; cache/requêtes/scope des sources identiques ; tests sources/proxmox/lazy et suite complète. |
| 7 — exploitation | Migrer séparément `daily.js`, `alerts.js`, `incidents.js`, `critical.js`, `ssh-refresh.js`, `self-monitor.js`, `services-full.js`, `findings-full.js`, `realtime.js`. | Acquittements exclusivement explicites, restauration DOM, SSE sans polling concurrent inutile, mêmes limites et états inconnus ; tests dédiés puis suite complète. |
| 8 — WAF et fiches | Migrer un fichier par livraison : `waf.js`, `waf-controls.js`, `waf-bans.js`, `waf-apache.js`, `server-detail.js`, puis `storage.js`. | Commandes restent du texte, CSV sûr, données anciennes signalées, jauges/réseau/stockage inchangés ; tests WAF/host_tabs/histories et suite complète. |
| 9 — formulaires | Migrer `manage.js`, `host-access.js`, `discovery.js`, `connections.js`, `connections-v2.js`, `api-help.js`, `sync.js`, `inventory-completion.js`, un à un. | Dialogues hors polling, saisies non enregistrées conservées, confirmations d’empreintes, rôle/quota et découverte exclusivement manuelle ; tests ssh_params/histories/access et suite complète. |
| 10 — retrait du pont | Lorsque plus aucun consommateur classique ne subsiste, retirer les alias globaux, le manifeste classique et les adaptateurs. | Recherche sans référence aux alias retirés ; démarrage uniquement par imports ; aucune modification de l’API. Suite complète et CI hors ligne au vert. |

## Première étape : mécanisme transitoire

`index.html` charge un seul point d’entrée `type="module"`. Le manifeste des
scripts classiques reste lisible dans un `<template>` inerte : le navigateur
ne les exécute pas à partir du template. Le point d’entrée installe le pont,
charge les scripts classiques séquentiellement, puis démarre l’application.
Le pont est un adaptateur de transition, pas une nouvelle API globale à étendre.

`v2-ui.js` importe ses échappements et reçoit explicitement la fonction de
fraîcheur ; il ne lit pas les registres ou l’état de l’application.
Les utilitaires HTTP restent indépendants du DOM et conservent leur cache privé
de GET en cours. Aucun import ne déclenche de requête applicative.

Les versions `?v=` concernent aussi les imports ES. `assets_version.py` les met
à jour dans l’ordre des dépendances : utilitaires → composants → point d’entrée
→ HTML, après les références paresseuses. Aucun CDN ni `unsafe-inline` n’est ajouté.

## Validation et retour arrière

Exécuter les tests navigateur séquentiellement pour éviter la concurrence des
fixtures et des captures. Conserver le bilan de chaque script et le nombre de
requêtes non-GET du parcours V2. Un échec bloque l’étape ; ne pas poursuivre la
migration suivante pour contourner une régression.

Le retour arrière d’une étape remet ses imports, son chargement et son pont dans
le même commit, puis recalcule les versions avec `python deploy/assets_version.py`.
Il ne nécessite ni migration de base ni modification du parc.

**Périmètre de cette livraison : étape 1 uniquement.** Les étapes 2 à 10 sont un plan.

### Bilan de la première étape

Les 21 scripts navigateur existants ont passé un lancement complet séquentiel
sur fixtures locales synthétiques, y compris `test_ui_v2.cjs` et son assertion
GET uniquement. `test_ui_modules.cjs` vérifie en plus les imports ES réels, le
retard du point d’entrée, l’identité du pont, la déduplication GET, l’échappement,
les erreurs HTTP et les headers du POST explicite.

Deux fixtures ont été complétées pour renvoyer `{hosts: []}` sur l’endpoint des
empreintes ; aucune assertion métier n’a été supprimée. Le démarrage déterministe
a révélé un bouton réactivé après verrouillage : le noyau réapplique maintenant
le verrou et groupe les droits des vues partielles en microtâche.
