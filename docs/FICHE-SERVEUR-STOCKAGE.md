# Fiche serveur et stockage

La fiche conserve huit onglets visibles : **Synthèse**, **Incidents**, **Stockage**,
**Performances**, **Services & applications**, **Réseau & accès**, **Sauvegardes**,
**Sécurité**. L'action **Preuves et historique** ouvre les audits enregistrés,
les contrôles, les sources et les informations documentaires. Les anciennes clés
`applications`, `observability`, `checks`, `history` et `inventory` sont redirigées.

## Où chercher

| Besoin | Emplacement |
| --- | --- |
| Identifier le volume qui nécessite une vérification | Synthèse → Volumes et inodes |
| Capacité, espace disponible, inodes libres et utilisés | Stockage → Volumes & inodes |
| NFS/CIFS consommés, exports NFS et déclarations Samba | Stockage → Partages |
| VG/LV, thin pool, Data %, Metadata %, état ZFS | Stockage → Topologie |
| SMART, débits disque et iowait | Stockage → Santé & I/O |
| Évolution d'un montage sur un périphérique donné | Stockage → Historique |
| CPU, mémoire, processus et mesures API Proxmox | Performances |
| Unités systemd, sous-état, tâches, applications et sites publiés | Services & applications |
| Connectivité et accès SSH | Réseau & accès |
| Pare-feu local, Fail2ban, échecs SSH | Sécurité |

## Interpréter les mesures

`GET /api/hosts/{key}` calcule `storage_assessment` sur une copie de la fiche et
les 20 derniers snapshots conservés. Aucun appel au parc n'est réalisé par cette
projection ni par la navigation entre vues. Aucun changement de schéma SQLite.

Les relevés détaillés priment sur les valeurs arrondies de l'ancien `df -h`.
Chaque volume garde montage, périphérique, type, capacité, utilisé, disponible,
inodes total / utilisés / libres et pourcentage d'inodes. Une valeur absente reste
non mesurée ; zéro est une mesure valide. Les inodes peuvent ne pas être applicables.

La gravité des volumes utilise `alert_policy.disk` et `alert_policy.inodes`, comme
le centre d'alertes : seuils 80 / 90 / 95 %, croisés avec l'espace libre absolu.
Le seuil seul ne détermine donc pas toute la gravité. La projection de saturation
exige au moins trois mesures comparables sur 12 h ; une lacune, un autre disque
ou une extension invalide la continuité. Une projection reste une estimation.
Les preuves d'audits historiques conservent leurs constats et leur grille d'origine.

Les volumes techniques (tmpfs, squashfs, loop, overlay, etc.) restent consultables,
mais sont exclus du maximum utile. Les montages distants sont traités séparément
de la capacité locale. Le résumé nomme le volume retenu au lieu d'un maximum anonyme.
Les anciens relevés sans identité du volume restent explicitement non rapprochés.

La fraîcheur du stockage est évaluée séparément : date SSH de moins de 15 minutes,
ni relevé retenu après échec, ni configuration modifiée. Une mesure ancienne est
affichée comme telle, avec une gravité visuelle neutre. Actualiser les API ne
renouvelle pas le relevé SSH. L'audit SSH reste une action explicite de l'opérateur.

## Collecte et limites

L'opération existante `storage` reste une commande figée dans l'allowlist SSH.
`df -lPT` et `df -lPiT` visent les volumes locaux. Les sondes `stat -f` distantes
sont bornées et distinguent délai dépassé et erreur de sonde. Le budget global
est de 25 s, avec signal de terminaison forcée après une seconde supplémentaire ;
les sections déjà émises sont conservées et la fiche signale une interruption.
Un processus bloqué dans le noyau sur NFS peut survivre aux signaux : le budget
ne garantit pas la terminaison de toute opération au niveau système.

Les nouveaux compteurs et colonnes LVM apparaissent lors du prochain audit
explicitement demandé. Les anciennes données restent lisibles sans migration.
Des groupes LVM ou une section ZFS vides ne prouvent ni leur absence ni leur santé.
Une commande absente, un droit insuffisant ou une interruption peuvent expliquer
une section vide ; les preuves restent nécessaires.

Les options `ro/rw` sont celles du montage, pas des droits applicatifs vérifiés.
Les clients d'exports NFS sont autorisés dans la configuration, pas nécessairement
connectés. Aucune écriture de test n'est effectuée. Les déclarations Samba ne
prouvent pas que le partage est effectivement servi.

L'inventaire LVM/ZFS n'établit pas encore les liens PV → disque physique ni la
chaîne complète VM → datastore → pool. Les datasets, snapshots, RAID, multipath,
quotas et erreurs de scrubbing ne sont pas collectés. SMART peut rester inaccessible
sans privilèges et n'atteste pas la santé du matériel de l'hyperviseur.
L'I/O est un échantillon d'environ une seconde : latences, IOPS et files d'attente
restent à instrumenter. Une unité systemd active, notamment `active/exited`, ne
prouve pas le fonctionnement HTTP, SQL ou métier.

## Vérification

Les tests unitaires couvrent la gravité partagée, les inodes indépendants de la
capacité, les volumes techniques et distants, les tailles LVM décimales, les
collectes partielles et les projections interrompues. Les tests navigateur
simulent entièrement les API : huit onglets, cinq vues du stockage, recherche
conservée, historique par disque, lacunes, extensions, données échappées, CSP,
formats 1440 / 390 / 320 px et absence de POST lors de la navigation.

Validation depuis la racine, avec le Python du projet :

```powershell
.venv/Scripts/python.exe deploy/assets_version.py
$env:OPS_BROWSER_CHANNEL = 'msedge'
.venv/Scripts/python.exe deploy/ci.py --offline --ui
```
