# Suivi des traitements batch

OpsControl rapproche un référentiel local, les planifications visibles et les
preuves d'exécution déjà disponibles. Le cockpit ne modifie ni les crontabs,
ni les scripts, ni les comptes des serveurs supervisés.

## Référentiel

Partir de `batch_catalog.example.yaml`, qui contient uniquement des exemples.
Placer la copie adaptée dans `data/batch_catalog.yaml`, hors Git, ou choisir un
chemin avec `INFRAOPS_BATCH_CATALOG`. Les chemins, hôtes et responsables réels
ne doivent pas être publiés dans une issue ou une pull request.

## Droits de lecture

Le compte d'audit doit pouvoir lire les éléments nécessaires à son périmètre.
La visibilité sur la crontab d'un compte ne prouve rien sur celle des autres.
`root` et `batchuser` sont les comptes d'exemple du catalogue livré ; qualifier
ce périmètre avant d'adapter le déploiement. Ne pas accorder un sudo général.

Quand une planification n'est pas visible, conserver le statut **non vérifiable**.
L'absence de résultat ou l'ancienneté d'une mesure ne signifie pas qu'un job a réussi.

## Résultats existants et télémétrie facultative

Les journaux existants peuvent fournir une preuve de résultat, avec leur date,
leur source et leur niveau de confiance. Leur lecture doit rester bornée, et les
extraits doivent être expurgés des secrets avant affichage.

`infraops-batch-report.sh`, `zabbix-agent-infraops-batch.conf` et
`zabbix-template-batch.yaml` sont des composants de télémétrie facultatifs.
Leur installation et l'enveloppement de jobs relèvent d'une intervention séparée,
approuvée et testée par l'équipe d'exploitation. Ils ne sont pas déployés par
OpsControl et ne sont pas nécessaires à la démo publique.

`wrap_crontab.py` produit une proposition de texte à relire ; ne jamais appliquer
sa sortie automatiquement. Prévoir une sauvegarde de configuration et un retour
arrière avant toute modification effectuée hors du cockpit.

## Validation en laboratoire

Utiliser des jobs fictifs et vérifier succès, échec, absence de résultat, exécution
ancienne, crontab invisible et interruption du reporting. Confirmer que les permissions
empêchent un autre compte de fabriquer un résultat réussi. Vérifier aussi le masquage
des secrets, la stabilité du code retour et le comportement si le stockage est plein.

Les tests publics simulent ces situations sans accès réseau réel. Les versions des
agents, ports et conventions de nommage doivent être qualifiés dans votre environnement.
