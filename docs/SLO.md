# Objectifs de service (SLO) d'OpsControl

Outil interne d'une équipe Infra / NOC : aucun engagement contractuel (SLA). Les objectifs
ci-dessous servent à décider quand la fiabilité passe avant les évolutions.

| Indicateur (SLI) | Objectif (SLO) | Mesure | Alerte Zabbix |
|---|---|---|---|
| Disponibilité : `/health/ready` = ready | ≥ 99,5 % sur 30 jours (~3 h 36 de budget) | agent local, chaque minute | « pas prêt depuis 3 min », « ne répond plus depuis 5 min » |
| Latence p95 des API (`/api/*`, hors flux SSE) | < 300 ms | `opscontrol_http_p95_seconds_window` (5 min glissantes) | p95 > 300 ms pendant 15 min (WARNING) |
| Erreurs serveur | < 0,5 % de 5xx | `opscontrol_http_5xx_ratio_window` | > 0,5 % pendant 15 min, ≥ 20 requêtes (HIGH) |
| Fraîcheur des audits SSH exploitables | ≥ 90 % du parc avec au moins un contrôle renseigné depuis moins de 24 h | `opscontrol_hosts_ssh_24h` / `opscontrol_hosts` | sous 90 % pendant 1 h (WARNING) |
| Disponibilité mesurée (réseau) | ≥ 90 % du parc sondé depuis moins de 15 min | `opscontrol_hosts_network_fresh` | sous 90 % pendant 30 min (WARNING) |
| Fraîcheur des sources API | toutes les sources lues depuis moins de 15 min | `opscontrol_source_fresh` (somme / nombre) | une source ancienne pendant 30 min (WARNING) |
| Sauvegarde | une sauvegarde réussie par 24 h | `last-backup.json` | > 26 h (HIGH) |

Les métriques viennent de `/api/metrics` (format Prometheus), activé par
`INFRAOPS_METRICS=1` (service de la VM), lu **en local** par l'agent Zabbix et bloqué par
nginx depuis l'extérieur. Elles repartent de zéro au redémarrage du service ; l'historique
est dans Zabbix (90 jours).

Depuis le 28/10/2026, `opscontrol_hosts_ssh_24h` exclut les tentatives sans aucun
contrôle renseigné. Une baisse lors de la livraison peut donc révéler une couverture
déjà manquante. `opscontrol_hosts_ssh_attempted_24h` compte les tentatives récentes,
et `opscontrol_hosts_ssh_complete_24h` les audits dont tous les contrôles attendus
sont renseignés. « Renseigné » ne signifie pas « sain » : un contrôle critique reste
une mesure valide. Les dates futures ne sont jamais récentes. Les champs JSON associés
sont `ssh_attempted_24h`, `ssh_24h` et `ssh_complete_24h` dans `freshness`.

## Budget d'erreur

Sur 30 jours glissants, 0,5 % d'indisponibilité ≈ 3 h 36.
- Moins de 50 % consommé : livraisons normales.
- Plus de 50 % : les changements risqués (migrations, refontes) attendent ; priorité aux
  causes des incidents.
- Budget épuisé : gel des évolutions jusqu'au retour sous l'objectif, revue des incidents.

## Ce que ces objectifs ne couvrent pas

- La justesse des données des produits supervisés (Zabbix, Proxmox…) : OpsControl affiche
  l'âge de chaque mesure et ne la rend jamais « récente » artificiellement.
- Le délai total entre une panne réelle et son affichage : il dépend aussi de la cadence des
  items Zabbix et de leurs déclencheurs.
