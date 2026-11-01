# Ancienneté, traitement et notifications

## Deux informations distinctes

L'ancienneté décrit la dernière occurrence de l'incident : déclenchement déclaré,
réapparition, ou premier suivi si la source ne connaît pas le début. Le badge
**Nouveau suivi** distingue ce dernier cas d'un début de panne certain.

- **Nouveau · moins de 24 h** : occurrence entre maintenant et les dernières 24 heures.
- **Ancien · plus de 24 h** : occurrence antérieure à cette fenêtre.
- **Ancienneté inconnue** : date absente, invalide ou future ; aucune ancienneté inventée.

Le traitement indique séparément : ouvert, réapparu, pris en charge, en investigation,
masqué temporairement, résolu. Une alerte peut être ancienne et toujours ouverte,
ou récente et déjà prise en charge. Pour un incident résolu, l'ancienneté porte
sur la résolution affichée. Une réapparition utilise son nouvel instant, sans
effacer le début initial ou l'historique.

Les boutons d'ancienneté du journal filtrent avant pagination et conservent les
critères d'état, de source et de gravité. Les compteurs d'ancienneté correspondent
à ces critères avant le filtre d'ancienneté ; les KPI de traitement restent globaux.
Les chroniques restent consultables avec le filtre existant.

Dans les alertes regroupées, les états sont comptés par cible. Un groupe peut
contenir des cibles récentes et anciennes : cette mixité est indiquée. La dernière
occurrence connue sert au classement et à la période ; le plus ancien début déclaré
reste visible séparément. Le filtre d'ancienneté sélectionne les groupes contenant
une occurrence récente, puis les anciens, puis ceux sans aucune date exploitable.
Le choix d'une ancienneté passe sur toutes les dates pour laisser consulter les anciennes.

## Notifications : critiques de moins de 15 minutes

Une notification automatique nécessite simultanément :

- gravité critique ; état ouvert ou réapparu, sans prise en charge ni investigation
  ni suppression locale dans le journal ; pas de prise en charge du groupe d'alertes ;
- occurrence connue de **15 minutes au plus**, jamais une date de collecte substituée
  au début ; une première détection récente dans le journal est admise et nommée comme telle ;
- preuve récente sur la cible (30 s Zabbix et sonde directe, 15 min autres sources) ;
- cible hors maintenance, pas de notification déjà envoyée pour cette occurrence,
  et permission de notification accordée dans le navigateur.

Le rapprochement au journal est une lecture. Son indisponibilité bloque les candidats,
elle ne crée pas un nouveau début. Une transition de la voie rapide déclenche une
lecture du centre, qui applique ces mêmes critères ; aucune notification indépendante
ne contourne désormais une prise en charge ou une suppression dans le journal.

La déduplication est persistante par cible et date d'occurrence. Changer la preuve,
rafraîchir la page ou conserver le même nombre d'alertes ne crée pas une notification.
Une autre cible ou une réapparition datée possède une autre signature. Le regroupement
des notifications sur cinq minutes reste actif. « Marquer comme vues » ne résout
ni ne masque l'incident.

Le bandeau et la pastille d'interruption suivent cette même fenêtre récente. Les
anciennes alertes restent visibles dans les listes et les compteurs opérationnels.
Les seuils sont explicitement affichés : 24 h pour la lecture, 15 min pour l'interruption.

API de lecture : `/api/incidents?age=all|recent|old|unknown`, compteurs `recency_counts`
et champ `recency`. Les groupes d'alertes ajoutent `state_counts`, `recency_counts`,
`latest_event_at`, `latest_event_kind` et une liste bornée `notification_events`.
Aucune nouvelle route d'écriture ni commande sur les serveurs supervisés.
