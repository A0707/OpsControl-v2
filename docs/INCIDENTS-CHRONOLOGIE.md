# Incidents : chronologie et dates exactes

Le journal s'ouvre sur les incidents actifs, sans les chroniques, avec les événements
les plus récents en premier. Les filtres permettent d'inclure les chroniques et les
incidents résolus. Les compteurs conservent leur périmètre global ; le nombre de lignes
du tableau décrit les critères appliqués.

Le menu **Trier** propose :

- **Plus récents d'abord** : date de réapparition, sinon début déclaré par la source
  s'il précède le premier suivi OpsControl, sinon premier suivi. Pour un incident résolu,
  la date de résolution s'applique. Ce n'est pas la date d'une action de prise en charge.
- **Gravité puis plus récents** : criticité en premier puis la même chronologie.
- **Dernière preuve reçue** : date de l'observation ; date absente en fin de liste.
- **Plus anciens d'abord** : chronologie ascendante.

Le tri est réalisé avant la pagination de 20 lignes. L'identifiant départage les dates
égales. Les dates ISO avec décalage sont comparées comme des instants, pas comme du texte.
`last_seen_at` et `updated_at` avancent au rapprochement : ils ne servent pas à fabriquer
une nouvelle occurrence. Un changement de filtre ou de tri repart à la première page.

Chaque ligne sépare **Événement** et **Dernière preuve**. Le début initial reste indiqué,
et le détail conserve le premier suivi, la dernière présence dans OpsControl et l'historique.
Les dates affichent jour, mois, année, heures, minutes, secondes et décalage UTC pour
**Africa/Casablanca**, indépendamment du fuseau du poste. Le décalage suit la date,
y compris les changements saisonniers. Une date absente, invalide ou sans décalage reste
inconnue. Les cas de test historiques utilisent les [règles IANA](https://github.com/eggert/tz/blob/main/africa)
plutôt qu'un décalage UTC fixe.

Les alertes en direct sont regroupées par cause et triées par dernière occurrence ou premier suivi,
avec les débuts inconnus en fin de liste et jamais masqués par le filtre de période.
Un groupe affiche séparément le plus ancien début connu de toutes ses cibles, y compris celles
hors échantillon d'affichage ; les dates manquantes sont signalées. Ce choix est indiqué, et la
dernière preuve ou lecture API possède une date distincte. La période initiale de sept
jours et l'accès **Toutes les dates** restent disponibles. Les incidents de la fiche
serveur suivent aussi la chronologie du journal et montrent événement et preuve.

Pour les filtres Nouveaux/Anciens, les états par cible et les notifications limitées
aux occurrences critiques de 15 minutes, voir [Ancienneté et notifications](INCIDENTS-CLASSIFICATION.md).

En cas d'échec de lecture, les dernières lignes reçues sont conservées avec un avertissement
explicite : les critères affichés sont à reconfirmer. Une page devenue vide après un
rapprochement revient à la dernière page disponible. La résolution dépend toujours d'une
collecte complète et récente ; ces changements ne résolvent ni ne masquent aucun incident.

API de lecture : `/api/incidents?order=recent|severity|observed|oldest`. Valeur par défaut :
`recent`. Les réponses ajoutent `order`, `event_at` et `event_kind` (`source`, `journal`,
`reopened`, `resolved`). Les autres champs et les routes d'action restent inchangés.
Les groupes de `/api/alerts` ajoutent `started_at` et `started_at_complete` pour que
le navigateur ne déduise pas le début du groupe de son seul échantillon de cibles.
