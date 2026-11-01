# Déploiement InfraOps sur une VM H24

Objectif : la collecte ne dépend plus du PC (veille, redémarrage). Le PC ne garde
qu'un navigateur.

## 0. La VM (à créer par vous sur Proxmox)

| | |
|---|---|
| Système | Debian 12 (Ubuntu 22.04+ possible) |
| Ressources | 2 vCPU, 4 Go RAM, 20 Go disque |
| Réseau | Segmentation dédiée et flux de lecture explicitement autorisés |
| Nœud | pas sur le même nœud que les serveurs qu'elle doit voir tomber en premier |

Vérifier les flux et le compte de service depuis la VM avant toute collecte.
Les adresses des modèles sont fictives et doivent être remplacées.

## 1. Archive (sur le PC)

Le workflow GitHub Actions `.github/workflows/ci.yml` s’exécute sur chaque push
et pull request, sous Python 3.11. Il installe les deux fichiers de dépendances,
lance `python deploy/ci.py` (avec pip-audit), `bash -n` sur les scripts `deploy/*.sh`,
`visudo -cf` sur le sudoers et charge le modèle Zabbix en YAML.

Après réussite des contrôles, l’artefact contient une archive de **code seulement**,
le SBOM CycloneDX des dépendances applicatives et `SHA256SUMS`, conservés 30 jours.
La CI n’accède pas au parc et ne nécessite aucun secret configuré. Les installations
de paquets et audits d’advisories nécessitent un accès Internet du runner.

Pour produire localement cette archive depuis un clone sans données :

```sh
python deploy/package_vm.py --code-only
```

Elle contient `hosts.example.yaml` ; préparer l’inventaire et l’état locaux avant
d’utiliser la procédure de migration VM ci-dessous. L’archive de CI ne remplace
pas une sauvegarde d’exploitation et n’embarque jamais `data/` ou les empreintes SSH.

```powershell
.\.venv\Scripts\python.exe deploy\package_vm.py
scp dist\infraops-vm-*.tar.gz admin@<IP-VM>:/tmp/
```

Code, inventaire, base (copie cohérente à chaud, tout l'historique), sources API,
empreintes SSH. **Aucun secret, aucune clé privée** : le script le vérifie et
refuse sinon.

## 2. Installation (sur la VM)

```sh
tar -xzf /tmp/infraops-vm-*.tar.gz -C /tmp
sudo bash /tmp/infraops/deploy/install-vm.sh
```

Paquets, compte de service `infraops`, code dans `/opt/infraops/releases/<id>`
(lien `/opt/infraops/current`), environnement Python par release, **clé SSH dédiée**
(ed25519), service systemd, site nginx préparé.
Relançable : ne touche jamais aux données, à la clé ni aux secrets existants.

Droits : `/opt/infraops` (root:infraops, 1770), `releases/` et `current` appartiennent
à root ; le compte `infraops` lit le code sans pouvoir le modifier (systemd :
`ReadOnlyPaths=/opt/infraops/releases`). Il écrit seulement `data/`, `backups/`,
`.ssh/`, `hosts.yaml` et `audit.log`.

`--reprendre-donnees` arrête le service avant de remplacer `data/` (copie
cohérente de l'ancienne base, anciens `-wal`/`-shm` retirés) ; il redémarre à la
bascule. En cas d'échec entre les deux, il reste arrêté et le script le signale.

Arrêt du service : les collectes en cours sont attendues `INFRAOPS_STOP_SECONDS`
(20 s par défaut) avant de rendre le verrou d'instance. Au-delà, le journal nomme les
travaux encore actifs et le verrou n'est libéré qu'à la fin du processus : aucune
nouvelle instance ne démarre pendant qu'une ancienne collecte écrit encore.

## 3. Secrets

```sh
sudo python3 /opt/infraops/current/deploy/secrets_env.py        # saisie sans écho
sudo python3 /opt/infraops/current/deploy/secrets_env.py --etat # quelles variables sont renseignées
```

Remplace le coffre DPAPI (Windows seulement). Fichier `/etc/infraops/secrets.env`,
0640 root:infraops. Génère aussi `INFRAOPS_WEBHOOK_TOKEN`.

## 4. Clé SSH du service — décision de votre équipe

`install-vm.sh` affiche la clé publique. Elle doit être autorisée pour le compte
dédié en lecture seule déclaré dans l'inventaire. Un tunnel Bacula éventuel
nécessite une destination définie explicitement. Deux options :

- **Recommandé** : autoriser la clé dédiée (traçable, révocable sans toucher à
  votre accès personnel). Idéalement un compte distant `infraops` en lecture.
- Une autorité SSH ou une autre méthode approuvée peut remplacer la clé dédiée ;
  ne pas copier de clé personnelle sur la VM.

InfraOps étant en lecture seule, il ne déploie pas lui-même de clé sur le parc.

## 5. Contrôle, puis démarrage

```sh
sudo -u infraops /opt/infraops/current/.venv/bin/python /opt/infraops/current/deploy/preflight.py
sudo systemctl restart infraops && journalctl -u infraops -f
```

`preflight.py` teste sans rien modifier : dépendances, base reprise, clé,
empreintes, secrets (noms seulement), port SSH de chaque serveur, API, et une
vraie opération SSH en lecture sur les serveurs critiques.

## 6. Basculement

1. Arrêter InfraOps sur le PC (**avant** l'archive finale : pas deux collecteurs).
2. Refaire l'archive, la copier, puis `sudo bash install-vm.sh --reprendre-donnees`
   (l'ancien `data/` de la VM est sauvegardé avant).
3. `systemctl restart infraops`, vérifier le bandeau de fraîcheur.

## 7. Accès depuis le PC

En attendant TLS et l'authentification : `ssh -L 8000:127.0.0.1:8000 admin@<IP-VM>`
puis http://127.0.0.1:8000.

Ensuite, obligatoire avant toute ouverture réseau (InfraOps n'a **pas**
d'authentification propre) : certificat dans `/etc/nginx/tls/`, oauth2-proxy
ou Authelia sur l'annuaire, IP du serveur Zabbix dans `nginx-infraops.conf`,
puis relancer `install-vm.sh` qui active le site.

## 8. Webhook Zabbix et batchs

- Type de média webhook : `zabbix-webhook.js` (paramètres en tête du script).
- Intervalles à 10 s sur les deux serveurs batch seulement (modèle cloné).
- Résultat des batchs : procédure complète dans `batch-setup.md` (enveloppe
  `infraops-batch-report.sh`, lue par l'agent Zabbix : le port 10051 est fermé
  depuis les serveurs batch, zabbix_sender n'y fonctionne pas).
