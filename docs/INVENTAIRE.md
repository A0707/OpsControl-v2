# Inventaire complet de l'infrastructure

Référentiel DSI : nœuds, VM, disques, stockages, applications, technologies, ports,
sauvegardes, supervision, certificats, dépendances, risques et plan d'actions.

## Principe : lecture seule

| Étape | Accès au parc | Détail |
|---|---|---|
| `inventaire_proxmox.py` | GET API Proxmox | Jeton PVEAuditor du coffre DPAPI, connexion « Proxmox » d'OpsControl. |
| `inventaire_complet.py` | Aucun | Base OpsControl ouverte en lecture seule (`mode=ro`), `api-connections.json`, `hosts.yaml`. |
| `inventaire_complet_rendu.py` | Aucun | Génère les fichiers depuis `inventaire_brut.json`. |

Les données SSH, Zabbix, Wazuh et Bacula proviennent des collectes qu'OpsControl réalise
déjà en lecture seule. Quand la dernière collecte API a échoué (VPN coupé, par exemple),
le script reprend le dernier succès conservé (`last_success_result`) et la feuille
`19_Sources` indique sa date.

Aucun secret n'est lu ni écrit. La configuration des VM passe par une liste blanche de
clés : la description et les champs cloud-init sont exclus. Les chaînes de connexion des
applications ne sont pas lues ; le lien entre une application et sa base reste
« À compléter » ou « DÉDUIT », selon les cas.

## Actualiser

```sh
.venv/Scripts/python.exe -m pip install -r requirements-tools.txt   # openpyxl, une fois
.venv/Scripts/python.exe inventaire_proxmox.py data/inventaire/proxmox-live-AAAA-MM-JJ.json
.venv/Scripts/python.exe inventaire_complet.py --proxmox data/inventaire/proxmox-live-AAAA-MM-JJ.json
.venv/Scripts/python.exe inventaire_complet_rendu.py data/inventaire/AAAA-MM-JJ
```

Les sorties sont écrites dans `data/inventaire/AAAA-MM-JJ/` (hors Git) :
`EXAMPLE_Inventaire_Infrastructure_Complet.xlsx`, `inventaire_brut.json`,
`rapport_audit_infrastructure.md`, `plan_actions_priorise.md` et `matrice_dependances.csv`.

## Lire le classeur

- `Vue_Globale` : une ligne par VM, avec tout ce qui la concerne, regroupé par familles
  (Hébergement, Stockage, Système, Applications, Technologies, Protection, Risques).
  Une colonne technologie indique par exemple « 8.2.29 (utilisé) » ou « 7.4.33 (installé
  seul, FIN DE VIE) ». Une technologie n'est dite utilisée que si un service actif ou un
  processus relevé le prouve.
- `Fiche_VM` : choisir la VM dans la cellule jaune ; toutes ses informations s'affichent.
- `05_Applications` : chaque application avec les technologies et versions sur lesquelles
  elle repose, chacune avec son niveau de confiance (par exemple, Java d'une instance Tomcat
  CONFIRMÉ, PHP d'un site web DÉDUIT).
- `21_DNS_WAF` : chaque enregistrement DNS → frontal (WAF ou répartiteur) → serveur:port →
  application, avec la résolution DNS et le certificat.
- `22_Batchs` : tâches planifiées (crontabs système, `/etc/cron.*`, timers systemd, processus
  batch). La colonne « Tâche système » sépare la maintenance des paquets des batchs métier.
  Les crontabs des comptes utilisateurs exigent root et ne sont pas lues.
- `23_Montages_Partages`, `24_Services_Systemd`, `25_Problemes_Zabbix` : montages et partages,
  services et problèmes de supervision ouverts.
- Les autres onglets (00 à 20) donnent le détail par domaine.

## Annotations manuelles

`data/inventaire/annotations.csv` (séparateur `;`, ouvrable dans Excel) contient une ligne
par VM, avec la clé `Cluster/VMID`. Ce fichier sert à renseigner l'environnement, la
criticité, la fonction, l'équipe, le responsable applicatif et le site. Les nouvelles VM y
sont ajoutées à chaque génération, et les lignes déjà saisies ne sont jamais modifiées.
Une valeur saisie l'emporte sur la valeur déduite et apparaît au niveau DÉCLARÉ.

## Niveaux de confiance

- **CONFIRMÉ** : lu dans une source technique (API, audit SSH, configuration).
- **DÉCLARÉ** : documentation (`hosts.yaml`, annotations, calendriers de fin de support).
- **DÉDUIT** : inférence à valider, par exemple un rattachement par IP seule, le service
  associé à un port standard, ou un environnement déduit du préfixe du nom.
- **INCONNU** / « À compléter » : information indisponible.

## Historisation

Chaque génération est comparée à l'inventaire précédent (`data/inventaire/*/inventaire_brut.json`)
et liste les VM ajoutées, supprimées, déplacées ou renommées, ainsi que les changements
d'OS, de noyau, de version PVE et de version logicielle (onglet `20_Changements`). Pour la
première génération, `--reference proxmox-vm-stockage-AAAA-MM-JJ.xlsx` sert de point de
départ. Les routes refusées sont journalisées dans `19_Sources`, comme les périmètres non
couverts et les incohérences entre sources.

## Périmètres à décider

Docker Swarm (le socket Docker équivaut à root), les processus derrière les ports
(`ss -p` exige root), FortiGate et pfSense, les VM Windows, ainsi que les jobs vzdump/PBS
(`/cluster/backup`, GET à ajouter). Chaque extension demande une autorisation explicite
de la DSI.
