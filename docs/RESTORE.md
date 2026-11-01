# Sauvegarde et restauration

## Ce qui est sauvegardé

`deploy/backup_state.py` produit `opscontrol-AAAAMMJJ-HHMMSS[-étiquette].tar.gz` et son
empreinte `.sha256` :

| Contenu | Source |
|---|---|
| Base (copie cohérente à chaud, `integrity_check` passé) | `data/state.sqlite3` |
| Inventaire | `hosts.yaml` |
| Connexions API (sans aucun jeton) | `data/api-connections.json` |
| Empreintes SSH acceptées | `data/known_hosts`, `data/bacula-known_hosts` |
| Autorité de certification Proxmox | `data/proxmox-ovh-root-ca.pem` |
| Certificats publics des sources (chemin relatif) | `data/ca/**/*.pem`, `*.crt`, `*.cer` (fichiers réguliers, sans lien sortant) |
| Liaisons jeton → hôte:port (aucun secret) | `data/token-bindings.json` |

La liste est le manifeste d'état unique `DATA_FILES` de `deploy/package_vm.py`, commun à la
migration, à la sauvegarde et à la restauration. La restauration refuse toute archive contenant
un fichier hors de ce manifeste (code, configuration système).

**Jamais** : jetons API, `secrets.env`, coffre DPAPI, clés privées SSH. Un contenu
ressemblant à un secret dans la configuration fait échouer la sauvegarde.

Non sauvegardé, à reconstituer : journaux (`audit.log`, journald).

## Fréquence et rétention

| | VM | Poste Windows |
|---|---|---|
| Déclenchement | `infraops-backup.timer`, 02:30 (+0 à 10 min) | tâche planifiée Windows (ci-dessous) |
| Avant chaque bascule de release | automatique, étiquette `pre-<release>` | — |
| Dossier | `/opt/infraops/backups` | `--dest` choisi |
| Rotation | 7 quotidiennes, 4 hebdomadaires, 3 mensuelles ; 5 étiquetées | idem |
| État | `last-backup.json` (surveillé par Zabbix) | idem |

Poste Windows (instance à sauvegarder dans `--base`, destination de préférence sur un
partage d'une autre machine) :

```powershell
Register-ScheduledTask -TaskName "OpsControl - sauvegarde" -Trigger (New-ScheduledTaskTrigger -Daily -At 02:30) -Action (New-ScheduledTaskAction -Execute "<projet>\.venv\Scripts\python.exe" -Argument "deploy\backup_state.py --base ..\opscontrol-legacy --dest <destination>" -WorkingDirectory "<projet>") -Settings (New-ScheduledTaskSettingsSet -StartWhenAvailable)
```

Objectifs : **RPO 24 h** pour la base (l'essentiel se reconstruit par collecte, sauf
incidents, acquittements et historique), **RTO 4 h**.

## Copie hors de la machine — à mettre en place

Le script n'écrit que localement. Une sauvegarde sur le même disque ne protège ni d'une
panne de disque, ni d'une perte de la VM, ni d'un rançongiciel. Brancher le dossier sur
le stockage de sauvegarde de l'équipe (Proxmox Backup Server, partage distinct), avec
rétention et, si possible, immutabilité. Les archives contiennent la cartographie du parc :
stockage chiffré ou accès restreint.

## Test de restauration (sans aucun effet)

Sur la VM, `infraops-backup.service` lance ce test après chaque sauvegarde, sur l'archive
qui vient d'être produite (`ExecStartPost`). Une archive illisible fait passer l'unité en
échec (`failed`) : `systemctl status infraops-backup` le montre. Résultat du dernier test :
`journalctl -u infraops-backup -n 20` (ligne « OK : … intégrité ok » ou l'erreur).
Le résultat est aussi écrit dans `last-backup.json` (`--record`) : `restore_test_ok`,
`restore_test_epoch`, `restore_test_archive`, `restore_test_error`. Le modèle Zabbix
déclenche « la dernière sauvegarde ne se restaure pas » (HIGH) quand `restore_test_ok`
vaut `false`. L'archive en échec reste dans le dossier pour analyse.

Le test manuel reste utile chaque mois sur une archive plus ancienne ou copiée hors de la
VM, ou sur le poste Windows, qui n'a pas d'unité systemd :

```sh
sudo -u infraops /opt/infraops/current/.venv/bin/python \
  /opt/infraops/current/deploy/restore_state.py verify --latest /opt/infraops/backups
```

Vérifie l'empreinte, extrait dans un dossier temporaire, contrôle l'intégrité et affiche
le nombre de lignes par table. Noter le résultat (date, archive, OK) dans le registre
d'exploitation. Un test qui échoue est un incident : la sauvegarde n'est pas fiable.

## Restauration

1. Choisir l'archive (`ls -l /opt/infraops/backups`) et la vérifier (`verify ARCHIVE`).
2. Arrêter le service : `sudo systemctl stop infraops`.
3. Voir ce qui serait fait (sans `--confirm`, rien n'est écrit) :
   ```sh
   sudo -u infraops /opt/infraops/current/.venv/bin/python \
     /opt/infraops/current/deploy/restore_state.py apply /opt/infraops/backups/<archive> --base /opt/infraops
   ```
4. Appliquer, en ajoutant `--confirm`. Options :
   - `--only-db` : la base seule (corruption de base), sans revenir sur l'inventaire ;
   - sans option : base **et** configuration (perte de la VM, suppression accidentelle).

   L'état actuel est d'abord sauvegardé (étiquette `avant-restauration`). La restauration
   prend le verrou d'instance : elle est refusée si OpsControl tourne, et OpsControl ne peut
   pas démarrer pendant qu'elle se fait.
5. Redémarrer : `sudo systemctl start infraops`, puis vérifier `/health/ready` et le bandeau
   de fraîcheur. Lancer une collecte pour rafraîchir l'état observé.

## Scénarios

| Scénario | Procédure |
|---|---|
| Base corrompue | `apply --only-db` depuis la dernière archive vérifiée |
| Migration ratée après déploiement | `release.py rollback`, puis `apply --only-db` depuis `pre-<release>` |
| Retour à une release antérieure sans restaurer la base | Refusé au démarrage : la base contient des migrations `core_*` inconnues de ce code. Restaurer `pre-<release>` ; `verify` refuse aussi une sauvegarde d'une version plus récente |
| Suppression accidentelle (serveur, connexion) | `apply` complet, ou extraction manuelle du seul fichier concerné |
| Perte de la VM | réinstaller (`install-vm.sh`), ressaisir les secrets (`secrets_env.py`), autoriser la nouvelle clé SSH, puis `apply` complet depuis la copie externe |
| Rançongiciel | VM neuve, copie externe **antérieure** à l'attaque, rotation de tous les jetons API et de la clé SSH du service |
