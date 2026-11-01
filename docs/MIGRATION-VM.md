# Checklist de migration vers la VM

Objectif : sortir OpsControl du poste Windows (veille, redémarrages, session) vers une VM
toujours allumée. Procédure détaillée : [deploy/README.md](../deploy/README.md).

## Avant

- [ ] VM Debian 12 : 2 vCPU, 4 Go, **40 Go** (base, journaux 310 Mo max, sauvegardes,
      3 releases), dans 10.77.0.0/24, sur un nœud Proxmox **distinct** des serveurs critiques.
- [ ] HA Proxmox activée pour cette VM (si stockage partagé disponible).
- [ ] Nom DNS `infraops.example.test` et certificat TLS (`/etc/nginx/tls/infraops.crt|key`).
- [ ] Fournisseur d'identité choisi, client OIDC créé, MFA exigée
      (`deploy/oauth2-proxy.cfg.example`).
- [ ] Agent Zabbix sur la VM ; modèle `deploy/zabbix-template-opscontrol.yaml` importé.
- [ ] Destination de la copie externe des sauvegardes décidée.
- [ ] Compte distant `infraops` décidé (ou, en transition, autorisation de la clé du service
      pour le compte actuel) — voir [SECURITY.md](SECURITY.md).

## Haute disponibilité Proxmox (redémarrage automatique sur un autre nœud)

Prérequis : cluster Proxmox avec quorum, disque de la VM sur un **stockage partagé**
(Ceph, NFS…) visible de tous les nœuds candidats ; sans cela, la HA ne peut pas relancer
la VM ailleurs. ❓ À confirmer selon le stockage retenu.

```sh
# Sur un nœud du cluster (VMID = identifiant de la VM OpsControl)
ha-manager groupadd opscontrol --nodes "<nœud1>:2,<nœud2>:1" --restricted 0 --nofailback 1
ha-manager add vm:<VMID> --group opscontrol --state started --max_restart 2 --max_relocate 1
ha-manager status
```

- Choisir des nœuds **différents** de ceux qui hébergent les serveurs critiques supervisés :
  OpsControl doit survivre à la panne qu'il signale.
- `nofailback 1` : pas de retour automatique (évite un second arrêt quand le nœud revient).
- Test (fenêtre de maintenance) : `ha-manager crm-command migrate vm:<VMID> <autre nœud>`,
  puis simulation d'une panne de nœud si l'équipe le pratique déjà. Vérifier ensuite
  `/health/ready`, le bandeau de fraîcheur et l'alerte Zabbix pendant la coupure.
- Durée d'interruption attendue lors d'une panne de nœud : détection (~2 min) + démarrage de
  la VM et d'OpsControl. Les sauvegardes restent le filet en cas de perte du stockage.

## Bascule

- [ ] Arrêter OpsControl sur le PC (**avant** l'archive finale : jamais deux collecteurs).
- [ ] `python deploy/package_vm.py` puis copie de l'archive vers la VM.
- [ ] `sudo bash install-vm.sh --reprendre-donnees` (l'ancien `data/` de la VM est sauvegardé).
- [ ] `secrets_env.py` : jetons API, `INFRAOPS_WEBHOOK_TOKEN`, `INFRAOPS_ADMINS`, `INFRAOPS_OPERATORS`.
- [ ] Clé publique du service autorisée sur les serveurs ; `preflight.py` vert.
- [ ] IP du serveur Zabbix dans `nginx-infraops.conf` (emplacement du webhook), relancer
      `install-vm.sh` pour activer nginx.
- [ ] `setfacl -m u:zabbix:x /opt/infraops /opt/infraops/backups`.

## Après

- [ ] `/health/ready` = ready ; bandeau de fraîcheur vert ; une collecte complète réussie.
- [ ] Accès par le nom public avec MFA ; `/api/whoami` = mode proxy, bon rôle.
- [ ] Accès direct à `127.0.0.1:8000` sans proxy : 401 sur `/api/*`.
- [ ] Alertes Zabbix testées : `systemctl stop infraops` → alerte en moins de 3 min.
- [ ] `systemctl start infraops-backup.service` puis `restore_state.py verify --latest`.
- [ ] Webhook Zabbix : un événement de test apparaît dans la voie rapide.
- [ ] PC : lanceur retiré du démarrage, coffre DPAPI conservé jusqu'à validation puis purgé.
