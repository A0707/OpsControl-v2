# Runbook NOC — OpsControl

Procédures d'exploitation. Chemins de la VM (`/opt/infraops`) ; sur le poste Windows, le
dossier du projet et le lanceur `LANCER-INFRAOPS.ps1` jouent le même rôle.

OpsControl ne modifie jamais un serveur supervisé : aucune des procédures ci-dessous
n'agit sur le parc, sauf mention explicite.

## 0. Vérifications rapides

```sh
systemctl status infraops --no-pager
curl -s http://127.0.0.1:8000/health/ready        # {"status":"ready"} attendu
curl -s http://127.0.0.1:8000/api/health
journalctl -u infraops -n 100 --no-pager
cat /opt/infraops/backups/last-backup.json
```

Les journaux applicatifs sont des lignes JSON (`logger`, `request_id`, `status`,
`duration_ms`). Pour suivre une requête signalée par un opérateur, chercher le
`request_id` affiché dans le message d'erreur :

```sh
journalctl -u infraops --since "1 hour ago" | grep <request_id>
```

## 0 bis. Bilan à l'ouverture et contrôle de démarrage

À chaque démarrage, OpsControl relit une fois les sources API et la disponibilité réseau, même en
mode manuel. Il ne lance aucun audit SSH. La première page ouverte affiche ensuite le
« Bilan à l'ouverture ».

| Niveau | Signification | Action |
|---|---|---|
| Critique | Incident critique récent, ni pris en charge ni en maintenance | Ouvrir l'alerte ou la fiche serveur ; prendre en charge |
| À vérifier | Critique à preuve ancienne, ou OpsControl lui-même en défaut | « Revérifier maintenant », puis section 2 ou 0 |
| Non confirmé | Aucun incident, mais angle mort (source, sonde, audits, mode manuel) | Rétablir la source (section 2) ou choisir un intervalle |
| Sain | Sources récentes, collecte saine | Aucune |

Lecture directe : `curl -s http://127.0.0.1:8000/api/briefing`. Pour un démarrage sans relecture
(maintenance de la VM, réseau coupé) : `INFRAOPS_STARTUP_SWEEP=0`.

## 0 bis bis. Passation (fin de journée, début de shift)

Le Bilan montre l'état **courant** ; la page **Passation** (onglet du centre Incidents, ou `#/Passation`) montre ce qui a
**changé** sur une période (8 h à 7 jours, 24 h par défaut) et qui fait quoi :

- **À traiter** : incidents sans responsable depuis plus de 24 h (y compris une prise en
  charge expirée), prises en charge qui expirent dans les 12 h, dossiers ITSM sans numéro
  GLPI confirmé. Ces seuils ne dépendent pas de la période choisie. Les anomalies chroniques
  (> 30 jours) sont comptées, pas listées.
- **Ce qui a changé** : nouveaux incidents (ou réapparus), résolutions, prises en charge
  (reconnaissance, investigation, suppression, avec l'auteur ; « déclaratif » = nom saisi en
  mode local), tickets GLPI créés avec leur numéro.

**Copier le texte** donne un texte brut à coller dans Teams ou un mail ; **Exporter CSV**
produit un fichier `;` UTF-8 lisible par Excel. Lecture seule : la page lit le journal
d'incidents et les dossiers ITSM, sans relancer de collecte. Si le dernier rapprochement du
journal a échoué, le texte le signale.

Lecture directe : `curl -s "http://127.0.0.1:8000/api/handover?hours=24"` (`&format=csv`).

## 0 ter. Notifications des incidents critiques (poste Windows, application Edge)

1. Installer OpsControl comme application : Edge › « … » › Applications › Installer ce site
   en tant qu'application.
2. Dans l'application, cliquer sur **Activer les alertes** (barre du haut), puis Autoriser.
   Le bouton devient **Alertes actives** ; un clic envoie une notification de test.
3. Rien ne s'affiche :
   - Paramètres Windows › Système › Notifications : Microsoft Edge (ou l'application
     OpsControl) autorisé, et « Ne pas déranger » désactivé ;
   - **Alertes bloquées** : « … » › Autorisations de l'application › Notifications ›
     Autoriser, puis recharger.
4. Les notifications partent de l'application : elle doit rester ouverte, même réduite, et
   le serveur doit tourner. Pour les deux à l'ouverture de session : raccourci
   `DEMARRER-OPSCONTROL.cmd` dans `shell:startup`, et dans edge://apps › OpsControl ›
   « Démarrer automatiquement à la connexion ».

## 1. Alertes Zabbix du modèle « OpsControl »

| Alerte | Cause probable | Action |
|---|---|---|
| Processus absent (DISASTER) | arrêt, plantage, échec au démarrage | `systemctl status infraops` puis `journalctl -u infraops -n 200`. Redémarrer : `systemctl restart infraops`. Si l'échec suit un déploiement : `python3 /opt/infraops/current/deploy/release.py rollback /opt/infraops`. |
| Pas prêt depuis 3 min | base illisible, planificateur arrêté | `curl -s http://127.0.0.1:8000/health/ready` donne la raison. Base : voir §5. Planificateur : redémarrer le service. |
| /health/ready muet 5 min | gel (boucle bloquée, verrou SQLite) | Relever `journalctl` puis redémarrer. Si récurrent : noter l'heure et les collectes en cours (bandeau) pour analyse. |
| Aucune sauvegarde réussie | timer arrêté, disque plein, base absente | `systemctl status infraops-backup.timer`, `journalctl -u infraops-backup -n 50`, `df -h /opt/infraops`. Relancer : `systemctl start infraops-backup.service`. |
| État des sauvegardes illisible | ACL de l'agent manquante, jamais de sauvegarde | `setfacl -m u:zabbix:x /opt/infraops /opt/infraops/backups` |

## 2. Une source API est « ancienne » ou en échec

1. Page **Sources** : le message d'erreur est affiché par source.
2. « Identifiants absents dans cette instance » : la variable n'est pas chargée.
   - VM : `sudo python3 /opt/infraops/current/deploy/secrets_env.py --etat`, puis
     `secrets_env.py` pour la saisir et `systemctl restart infraops`.
   - Poste Windows : `.\LANCER-INFRAOPS.ps1 -UpdateCredentials`.
3. « Jeton … lié à hôte:port : envoi vers … refusé » : l'URL de la connexion a changé
   d'hôte. C'est une protection (un jeton ne part jamais vers un autre serveur que celui
   de sa première utilisation). Si le changement est **légitime** (migration du serveur) :
   - vérifier avec le responsable du produit que le nouvel hôte est le bon ;
   - sur le serveur OpsControl, retirer l'entrée de cette variable dans
     `data/token-bindings.json` (le fichier ne contient aucun secret) ;
   - relancer la collecte : la nouvelle liaison est enregistrée au premier usage.
   « Registre des liaisons de jetons corrompu / illisible / invalide » : **toutes** les
   collectes authentifiées sont suspendues, car un registre inexploitable ne prouve plus vers
   quel hôte chaque jeton peut partir. Restaurer `data/token-bindings.json` depuis la dernière
   sauvegarde (`restore_state.py`), ou corriger le fichier (objet JSON
   `{"INFRAOPS_…_AUTH": {"endpoint": "hôte:port"}}`, droits de lecture du compte `infraops`).
   Ne pas le supprimer sans vérifier chaque hôte avec le responsable du produit : les liaisons
   seraient recréées au premier usage, vers l'hôte configuré à ce moment.
4. Erreur TLS : certificat expiré ou autorité changée. Page Connexions API →
   « Vérifier le certificat du serveur » (administrateur).
5. Jeton expiré côté produit : le renouveler dans le produit, puis §2.2.
6. « Destination réseau refusée » : vérifier que le DNS de l'API ne renvoie aucune
   adresse de boucle locale, lien local, multicast ou nulle. Le transport contrôle
   toutes les réponses puis connecte directement une adresse validée ; conserver
   le nom présent dans le certificat, sans désactiver TLS.
   Depuis le 24/10/2026, les collectes internes ignorent les proxies d'environnement :
   une route réseau directe ou un VPN est nécessaire. L'exception locale Bacula
   n'autorise que les GET jobs et clients prévus. Voir [SECURITY.md](SECURITY.md).

## 3. Bacula muet

Le tunnel `127.0.0.1:19096` est ouvert par OpsControl.

```sh
ss -ltnp | grep 19096
journalctl -u infraops | grep -i bacula | tail
```

« enregistrer la clé » : l'empreinte du serveur Bacula n'est pas connue
(`data/bacula-known_hosts`). La vérifier depuis la console du serveur avant de l'enregistrer.

## 4. Audits SSH anciens ou « Incomplet »

- Bandeau « Mesure SSH : il y a … » : l'actualisation automatique n'audite que les
  serveurs nouveaux ; le réaudit complet est une action d'opérateur (bouton
  « Actualiser les données ») ou le réaudit en rotation (`/api/ssh-refresh`, admin).
- Échec d'authentification ou d'empreinte sur un serveur : fiche serveur → onglet de
  diagnostic ; `python3 /opt/infraops/current/diagnostic_ssh.py` reproduit le contrôle.
  Une empreinte **changée** se vérifie depuis la console du serveur avant tout
  remplacement (`register_host_key.py`).
- Journal des appels SSH : `/opt/infraops/audit.log` (JSON, un appel par ligne,
  ~3 semaines de rétention par défaut, `COCKPIT_AUDIT_KEEP`).

### Empreintes SSH à confirmer

Utiliser **Serveurs → Empreintes SSH à confirmer** (administrateur) après l’ajout
d’un serveur, ou si une tentative SSH signale une clé absente ou différente.
Sélectionner les serveurs et lire leurs empreintes présentées ; cette lecture
ouvre des connexions SSH par le chemin configuré, bastion compris. Elle utilise
un fichier jetable et ne prouve pas, à elle seule, l’identité du serveur.

Depuis la **console du serveur** ou un accès hors bande déjà reconnu comme fiable,
afficher l’empreinte de sa clé publique :

```sh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

Si la clé présentée est RSA ou ECDSA, utiliser respectivement
`/etc/ssh/ssh_host_rsa_key.pub` ou `/etc/ssh/ssh_host_ecdsa_key.pub`.
Comparer le type et chaque empreinte SHA256 avant de sélectionner les clés
vérifiées et de taper **OUI**. Une lecture porte sur 50 serveurs au plus et expire
après 15 minutes ; après expiration, relancer la lecture et la comparaison.

Une **clé changée** peut venir d’une réinstallation, d’une rotation légitime ou
d’une interception : confirmer la cause et l’identité à la console avant toute
acceptation, puis taper **REMPLACER** (le simple « OUI » est refusé pour une clé déjà
enregistrée). L’acceptation remplace l’ancienne entrée du magasin OpsControl
(`data/known_hosts`, ou `COCKPIT_SSH_DIR/known_hosts`) et conserve une copie `.old`.
Elle ne modifie pas `~/.ssh/known_hosts`. Si l’ancienne clé y reste en conflit,
la retirer manuellement **sur le poste/serveur OpsControl**, seulement après
vérification :

```sh
ssh-keygen -R 192.0.2.10
# Pour un port non standard, adapter l’adresse et le port :
ssh-keygen -R '[192.0.2.10]:2222'
```

Ces adresses sont fictives. Relancer ensuite **Tester la connexion**, puis l’audit
du serveur. Ne pas contourner le contrôle par `StrictHostKeyChecking=no`.

### Tester la connexion

Dans la fiche serveur, **Tester la connexion** est accessible à l’opérateur et
à l’administrateur. Il affiche la **dernière** sonde réseau enregistrée (avec sa
date), vérifie si une empreinte est connue et tente la commande autorisée `uptime`
avec les comptes et ports configurés, jusqu’à une réussite. Ce n’est ni un nouvel
inventaire réseau complet ni un audit complet du serveur.

| Cause affichée | Lecture du diagnostic et suite |
|---|---|
| `host_key` | Empreinte absente ou différente : suivre la procédure de confirmation à la console. |
| `auth` | Compte ou clé refusés : vérifier le compte sélectionné et l’autorisation de la clé publique avec le responsable du serveur. Toute correction distante reste manuelle. |
| `network` | Adresse ou port injoignables : vérifier IP, port SSH, chemin via le bastion et règles d’accès ; actualiser la vue Réseau si sa preuve est ancienne. Un ping muet ne suffit pas à déclarer le serveur arrêté. |
| `ssh` ou cause non classée | Lire le détail de chaque tentative, compte, port et durée ; reproduire le diagnostic local si nécessaire. |

Une réussite prouve uniquement que ce compte a pu exécuter `uptime` à cet instant.
Elle ne garantit ni les droits des autres sondes ni l’état des services.

Dans le formulaire **Modifier le serveur**, **Tester avec ces paramètres** utilise
l’IP, le compte et le port saisis avant enregistrement. Un compte vide choisit le
compte SSH global par défaut. Une seule combinaison est testée ; aucun paramètre
n’est enregistré et le contrôle des empreintes reste strict. Le résultat reste
dans le formulaire, avec les valeurs effectivement testées.

Dans **Modifier plusieurs serveurs**, **Tester la connexion des serveurs cochés**
teste les paramètres **enregistrés** de chaque serveur sélectionné, avec les
diagnostics existants. Cocher de 1 à 10 serveurs : les appels sont séquentiels et
leurs résultats restent individuels. Le quota partagé `collect_one` (10/minute
par acteur) peut limiter le lot si d’autres tests/collectes ont déjà été demandés ;
le refus est affiché pour le serveur concerné. Aucune modification groupée n’est
appliquée par ce bouton.
Pour corriger plusieurs fiches, la **modification groupée** (administrateur)
change uniquement l’inventaire local : rôle, environnement, criticité, compte,
port ou activation de la collecte. Un changement d’accès attend la fin des
collectes SSH/réseau en cours ; retester les connexions après enregistrement.

## 5. Base SQLite

Contrôle d'intégrité sans arrêt (lecture seule) :

```sh
sqlite3 "file:/opt/infraops/data/state.sqlite3?mode=ro" "PRAGMA integrity_check;"
```

Corruption ou perte : restauration, voir [RESTORE.md](RESTORE.md).

Taille : `audit_snapshots` représente l'essentiel (rétention 20 audits + 1/heure sur
7 jours ; au-delà des 20 derniers, seuls les champs utiles aux tendances sont gardés).
Compactage, une fois, service arrêté (sauvegarde préalable automatique) :

```sh
sudo systemctl stop infraops
sudo -u infraops /opt/infraops/current/.venv/bin/python /opt/infraops/current/deploy/maintenance.py \
  vacuum --base /opt/infraops            # mesure seulement ; ajouter --confirm pour agir
sudo systemctl start infraops
```

Ensuite, la purge horaire rend l'espace libéré au disque (auto_vacuum incrémental).

## 6. Disque plein

```sh
df -h /opt/infraops
du -sh /opt/infraops/{data,backups,releases} /opt/infraops/audit.log*
```

Leviers, du moins au plus intrusif : anciennes releases (`release.py` en garde 3),
archives de sauvegarde (rotation 7/4/3 ; vérifier la copie externe avant toute suppression
manuelle), `COCKPIT_AUDIT_KEEP` plus bas, `VACUUM` service arrêté.

## 7. Accès

- Accès normal : `https://infraops.example.test` (oauth2-proxy + annuaire).
- Accès de secours (nginx ou oauth2-proxy en panne) :
  `ssh -L 8000:127.0.0.1:8000 <admin>@<IP-VM>` puis http://127.0.0.1:8000.
  Le secret proxy étant configuré, l'API refuse l'accès direct (401) sauf si
  `INFRAOPS_LOCAL_ROLE` est défini explicitement pour le dépannage — à retirer ensuite.
- Rôles : `INFRAOPS_ADMINS` et `INFRAOPS_OPERATORS` (adresses, séparées par des virgules)
  dans `/etc/infraops/secrets.env` ; tout autre compte authentifié est `viewer`.

## 8. Déploiement et retour arrière

```sh
sudo bash /tmp/infraops/deploy/install-vm.sh          # sauvegarde pre-<release>, contrôle, bascule
sudo python3 /opt/infraops/current/deploy/release.py status /opt/infraops
sudo python3 /opt/infraops/current/deploy/release.py rollback /opt/infraops
```

Le retour arrière ne concerne que le code. Si une migration de base doit être annulée,
restaurer la sauvegarde `pre-<release>` ([RESTORE.md](RESTORE.md)).

## 8 bis. Ajouter ou modifier un serveur

**Serveurs → Ajouter un serveur** (administrateur). Points d’exploitation :

- **Assistant en quatre étapes** : Identité, Accès SSH, Contrôles, Récapitulatif.
  Précédent conserve les valeurs. Entrée avance sans enregistrer ; le récapitulatif
  affiche les paramètres effectifs et les changements avant validation. L'identifiant
  technique est proposé automatiquement, modifiable avant création et stable ensuite.
- **Brouillon de création** : « Garder le brouillon » conserve la saisie dans le même
  onglet, au maximum 24 h. « Reprendre le brouillon » la restitue après rechargement.
  Fermer l'onglet met fin à cette conservation. Aucun serveur n'est enregistré et
  aucune commande ni collecte n'est lancée par cette action. Le brouillon ne contient
  aucun secret et disparaît après un enregistrement réussi. La modification d'un serveur
  existant garde la vérification de révision et n'utilise pas ce brouillon de création.
- **Pendant une collecte**, l’enregistrement est accepté. Le lot en cours garde
  la copie des paramètres prise à son départ. Les nouveaux paramètres s’appliquent au lot
  suivant ; le message de confirmation le précise. Le résultat d’un serveur retiré ou
  la mesure réseau d’un ancien accès ne sont pas enregistrés. L’audit SSH d’une
  configuration remplacée reste visible avec l’avertissement « configuration modifiée ».
  La **suppression** attend toujours la fin des collectes (409).
- **Création ≠ modification** : un identifiant déjà utilisé est refusé (409). Le
  message nomme le serveur existant et propose de l’ouvrir. Une nouvelle tentative
  identique (double clic, réseau coupé) ne crée pas de doublon. En modification, une
  configuration changée entre-temps est refusée (409) : rouvrir le formulaire.
- **Port SSH** : « Hériter du profil SSH » (défaut) n’écrit aucun port dans
  `hosts.yaml` ; les ports globaux `ssh.ports` s’appliquent. « Port spécifique » écrit
  une surcharge. Le formulaire affiche le compte et le port effectifs et leur origine.
  Les anciennes entrées enregistrées avec `port: 22` explicite restent une surcharge :
  choisir « Hériter » pour la retirer.
- **Saisie** : espaces retirés ; le champ IP n’accepte qu’une adresse IPv4/IPv6, pas
  un nom DNS. Les erreurs s’affichent sous le champ concerné, sans perte de saisie.
- **Résultat** : « Configuration enregistrée » signifie que `hosts.yaml` est écrit.
  Si la purge du cache réseau échoue ensuite (SQLite occupé), le message indique
  « synchronisation en attente ». La purge est retentée au prochain enregistrement et la
  prochaine collecte réseau remplace la ligne. L’erreur est visible dans la santé
  d’OpsControl (source `inventaire`).
- **Visibilité** : un serveur ajouté par un administrateur (formulaire ou import de
  découverte) porte `admin_enrolled_at` et apparaît tout de suite dans Serveurs avec
  « Première collecte en attente ». Cette inscription n’approuve aucune empreinte SSH
  et ne dit rien de sa santé.

## 9. Découvrir des serveurs

Dans **Serveurs → Découvrir des serveurs** (administrateur), saisir une plage CIDR
du réseau dont le balayage a été autorisé par l’exploitation. Pour l’exploitation,
utiliser une plage privée RFC 1918 (`10/8`, `172.16/12`, `192.168/16`). La validation
refuse IPv6, les plages publiques, loopback ou lien local et les plages de plus de
**1 024 adresses** (`/22` ou plage plus petite).

Le scan est **actif et visible par les IDS, Wazuh et les pare-feu** : un écho ICMP
par adresse, connexions TCP sur `22, 3300, 80, 443, 3389, 445, 8006`, lecture de la
bannière SSH sur 22/3300 et DNS inverse. Il n’authentifie pas de session SSH et
n’exécute aucune commande distante. Prévenir l’exploitation/sécurité du périmètre
et de l’horaire avant de le lancer ; commencer par la plus petite plage utile.
Il utilise jusqu’à 48 travailleurs ; le quota partagé de collecte complète limite
les lancements à un par minute, et un seul scan de découverte tourne à la fois.

Les types et systèmes affichés sont **probables**. Un hôte absent des résultats
peut filtrer ICMP et les ports testés. Sélectionner les nouvelles machines à suivre
et les ajouter : seules les IP du dernier balayage sont acceptées, les IP déjà
inscrites sont ignorées. L’ajout est accepté pendant une collecte SSH/réseau : les
nouveaux serveurs entrent au lot suivant. Il exige un balayage de moins de 24 h (sinon relancer le balayage). Un nom DNS inverse qui
n’a pas la forme d’un nom d’hôte n’est pas repris ; le nom, le nœud et le vmid Proxmox ne
sont adoptés que sur correspondance par IP. Un second balayage lancé pendant le premier
est refusé (409). Le lancement et l’ajout demandent une confirmation.

Après ajout : compléter rôle, environnement, criticité, compte/port SSH et services
critiques ; confirmer l’empreinte à la console ; tester la connexion ; lancer le
premier audit et vérifier sa couverture. Un ajout à l’inventaire ne prouve ni une
connexion SSH réussie ni un serveur sain, et n’approuve aucune clé automatiquement.

L’onglet **Historique** affiche les scans conservés après redémarrage, y compris
les scans interrompus. Les apparitions, absences et changements de ports sont
comparés au précédent scan **terminé de la même plage**. Une autre plage ou un
scan interrompu ne produit pas de fausse disparition. Les machines de l’inventaire
non observées dans la plage du dernier scan terminé sont signalées ; aucune
suppression d’inventaire ni déclaration d’arrêt n’en découle. Conservation de
30 jours par défaut (`INFRAOPS_DISCOVERY_RETENTION_DAYS`).

Les propositions **Proxmox** lisent les observations API déjà enregistrées, sans
interroger les agents invités : DNS/nom de VM ou IP effectivement fournie par
l’API. Les correspondances ambiguës restent indiquées comme telles. Cocher
« Utiliser les noms et nœuds Proxmox proposés » avant l’ajout pour adopter une
correspondance unique récente ; sinon l’ajout conserve le nom DNS du scan.

## 10. IP bannies

La chronologie conserve les premières/dernières observations et les rebannissements
**observés**, distincts de la date de ban déclarée par Fail2ban. Une disparition
d’une liste complète puis une réapparition, ou une nouvelle date de ban, ouvre
une nouvelle occurrence. Une collecte échouée ou une liste tronquée ne prouve pas
un déban. Les événements entre deux collectes peuvent ne pas être vus. La fenêtre
de conservation est de 30 jours par défaut (`INFRAOPS_WAF_BAN_RETENTION_DAYS`).

L’export **CSV** comprend toute la liste filtrée, au-delà de la page visible.
Les réseaux concentrant des bans reçoivent une recommandation : quand les
user-agents des échantillons indiquent un robot d’indexation de `BOT_PATTERNS`,
préférer une limitation de débit validée par vhost ou une règle ModSecurity
par user-agent à une suite de bans IP. Un user-agent peut être usurpé : aucune
identité de robot n’est certifiée et aucune liste blanche n’est appliquée.

### Localisation des IP bannies et actives

Définir `INFRAOPS_GEOIP_CSV` vers une base CSV locale préparée et tenue à jour,
hors Git. Colonnes : `network,country,city,asn,organization` ; `network` contient
un CIDR IPv4/IPv6, les autres colonnes sont facultatives. Le réseau le plus
spécifique est retenu. Limites : 32 Mio et 250 000 réseaux. Aucun téléchargement
ni envoi des adresses à un tiers n’est effectué par OpsControl.

Le pays, la ville et l’ASN sont approximatifs et décrivent un point de sortie
réseau, pas la position d’une personne. Les IP internes/non publiques ne sont pas
géolocalisées. Sans base exploitable ou sans correspondance, la localisation est
« non mesurée ». Les IP les plus actives sont classées par requêtes dans
l’échantillon lu : ce n’est pas une mesure du débit ni du volume total.
Les octets de réponse sont affichés quand le format du journal les fournit ; ils
portent sur cet échantillon et ne mesurent pas tout le trafic réseau du client.
Ils proviennent de la sonde Apache, avec un LogFormat déclaré contenant `%b`, `%B`
ou `%O`. Sa fenêtre peut différer de l’échantillon WAF comptant les requêtes.

Ouvrir **WAF / HA → IP bannies · analyse** pour le WAF concerné. Les données
proviennent de la dernière collecte enregistrée : vérifier sa date et actualiser
le WAF si elle est ancienne ou si les traces ne sont pas rapprochées. Aucun WHOIS
ni service de géolocalisation n’est interrogé.

| Verdict | Sens et décision |
|---|---|
| Incohérentes (`incoherent`) | IP à la fois bannie et incluse dans `ignoreip` : vérifier cette contradiction de configuration. |
| À vérifier (`verify`) | Adresse privée/locale, serveur de l’inventaire, IP publique sans alerte ModSecurity dans les échantillons (simple trafic HTTP compris), ou activité non rapprochée (collecte ancienne) : confirmer le motif dans `fail2ban.log` avant de décider. |
| Maintenir (`keep`) | Adresse publique avec au moins une alerte ModSecurity dans l’échantillon rapproché : conserver le ban jusqu’à l’analyse du motif. Ce verdict ne constitue pas une preuve d’attaque. |

Les regroupements à partir de trois IP d’un même `/24` IPv4 ou `/64` IPv6 indiquent
une campagne **probable**. Des journaux échantillonnés sans trace ne prouvent pas
l’absence d’activité ; les dates et échéances de ban peuvent ne pas être mesurées.
Vérifier notamment si l’adresse est celle d’un bastion, d’un proxy partagé ou
d’un serveur interne avant toute décision.

Le bouton **Vérifier** (opérateur) prépare un plan de lecture via
`waf_findings.command_plan`. Exemples à copier manuellement **sur le WAF indiqué
par le plan**, en remplaçant l’IP fictive et en adaptant les chemins de journaux :

```sh
sudo fail2ban-client get apache-modsecurity banip --with-time | grep -F -- 192.0.2.10
sudo zgrep -hF -- 192.0.2.10 /var/log/fail2ban.log* | tail -n 20
sudo grep -hF -- 192.0.2.10 /var/log/apache2/error.log | grep -F ModSecurity | tail -n 20
sudo grep -hF -- 192.0.2.10 /var/log/apache2/*access*log | tail -n 20
sudo iptables -n -L f2b-apache-modsecurity | grep -F -- 192.0.2.10
# Si la banaction utilise nftables :
sudo nft list ruleset | grep -F -- 192.0.2.10
```

Après confirmation du motif, de l’identité et de l’impact, le bouton **Débannir**
prépare également du texte. Si le déblocage est justifié, l’opérateur exécute lui-même
la commande sur ce WAF, puis vérifie l’état :

```sh
sudo fail2ban-client set apache-modsecurity unbanip 192.0.2.10
sudo fail2ban-client status apache-modsecurity
sudo fail2ban-client get apache-modsecurity ignoreip
```

L’interface n’exécute **aucune** de ces commandes. Le déblocage ne désactive pas
ModSecurity et ne crée pas d’exception permanente : l’IP peut être bannie à nouveau.
Une exception durable nécessite une analyse et une modification manuelle de la
configuration du jail ; `addignoreip` seul reste une exception active non persistante.

## 10 ter. Applications d'un serveur (fiche serveur)

L'onglet « Applications » de la fiche montre le dernier relevé fait pendant l'audit SSH :
relancer l'audit du serveur pour l'actualiser. « Relevé indisponible » signale un compte
sans shell, une sortie tronquée ou une coupure : ce n'est pas une absence d'application.
Sans root, un port n'indique pas son processus et Docker peut répondre « Accès refusé ».

Sites web : chaque nom déclaré (ServerName, ServerAlias, server_name) a un lien et une
portée DNS résolue par OpsControl : « DNS interne » (adresses privées seulement),
« En ligne (IP publique) » ou « Non résolu ». L'application liée vient de la cible du
proxy (port publié par un conteneur, contexte Tomcat, port local). « Port local non en
écoute » signale un site dont l'application est probablement arrêtée.

Enregistrements publiés : les noms DNS et sites sont déclarés sur le WAF. La fiche de
chaque serveur applicatif liste les enregistrements dont la cible de proxy du WAF est ce
serveur, avec le port visé et l'application qui y écoute. Prérequis : le WAF et le serveur
ont chacun un relevé des applications récent (relancer leur audit). Une cible désignée par
un nom absent de l'inventaire (ni IP, ni clé, ni nom, ni FQDN) n'est pas rapprochée.

## 10 bis. Classeurs d'exploitation (applications, stockage Proxmox)

Scripts lancés à la main depuis la racine, avec le Python du projet après
`python -m pip install -r requirements-tools.txt` (openpyxl) :

- `inventaire_applications.py [sortie.xlsx] [--serveur NOM ...]` : une opération SSH
  figée `apps`, en lecture seule et sans sudo, par serveur. Un serveur n'est « OK » que si
  la sortie de la sonde est complète ; un compte en nologin ou une sortie tronquée donne
  « Sortie inattendue » et conserve le dernier relevé valide (`data/releve-vm.json`).
  Elle lit aussi les paquets clés (liste fermée : Java, Tomcat, serveurs web, PHP, Node,
  Python, bases, Docker, OpenSSL, agents) par `dpkg-query` ou `rpm -qa`, et le noyau par
  `uname -r` : lecture de la base des paquets, sans root. Un produit installé hors
  gestionnaire (archive dans /opt) n'y figure pas ; les relevés antérieurs affichent
  « Non relevé » jusqu'au prochain audit.
- `export_enregistrements_waf.py [sortie.xlsx] [--waf prdlabwaf03]` : méthode rapide, sans
  connexion. Lit le dernier relevé du WAF et des serveurs dans la base locale (lecture
  seule) et produit, par serveur, les enregistrements DNS publiés, le port visé et
  l'application qui y écoute ; feuilles « Hors inventaire » et « Sites sans cible ».
  Auditer d'abord le WAF (et les serveurs) dans OpsControl pour un relevé à jour.
- `export_vulnerabilites.py [sortie.xlsx] [--serveur CLÉ_NOM_OU_IP] [--sans-detail]` : sans
  connexion, audit des vulnérabilités actives et plan de correctifs ciblés par serveur. Ordre de
  passage par risque (CISA KEV, critiques, production), une ligne par paquet source avec sa
  version cible, et un plan copiable (vérifications, instantané, `apt-get install
  --only-upgrade`, needrestart, vérification, retour arrière). Rien n'est exécuté. « Dépôt
  security à vérifier » : le relevé apt ne propose pas le correctif, contrôler les sources apt
  avant la mise à jour. Analyser d'abord les serveurs dans OpsControl > Sécurité.
- `export_inventaire_vm.py [sortie.xlsx] [--en-ligne]` : sans connexion, une ligne par VM. Le classeur
  reprend le système, les services, ports, conteneurs, bases, sites, enregistrements du WAF
  et les applications maison. Chaque VM reçoit un statut : « Identifié », « À confirmer »
  (rôle métier à faire valider par son responsable) ou « Non relevé » (auditer le serveur).
  Un serveur injoignable garde son dernier relevé réussi, signalé dans « État actuel ».
  La feuille « Vue globale » (en tête) résume le parc pour le partage en équipe ; la
  capacité ne compte que les disques locaux (hors NFS et mergerfs).
  La feuille « Par application » donne l'inverse : pour chaque application, les VM qui
  l'hébergent.
  `--en-ligne` ne garde que les VM qui ont répondu au dernier ping fait par OpsControl
  (aucun ping envoyé par le script).
- `export_proxmox_stockage.py [sortie.xlsx]` : GET seulement sur l'API Proxmox, avec la
  connexion et le certificat d'OpsControl, sans proxy d'environnement.

Les classeurs contiennent IP, ports, rôles et applications : à traiter comme des documents
internes. Les valeurs venues des serveurs sont écrites comme du texte, jamais comme des
formules. `data/releve-vm.json` n'a pas de rétention automatique.

## 11. Variables d'environnement

| Variable | Défaut | Effet |
|---|---|---|
| `INFRAOPS_ADMINS`, `INFRAOPS_OPERATORS` | vide | Rôles des identités transmises par le proxy |
| `INFRAOPS_DEFAULT_ROLE` | `viewer` | Rôle des autres identités authentifiées |
| `INFRAOPS_LOCAL_ROLE` | `admin` sans secret proxy | Accès direct à uvicorn ; `off` = lecture seule |
| `INFRAOPS_LOCAL_OPERATOR` | — | Nom déclaratif par défaut des actions locales (poste Windows : `data\poste.env`) ; ignoré en mode proxy |
| `INFRAOPS_TRUSTED_PROXY_SECRET` | — | Secret partagé nginx → OpsControl (≥ 32 car.) |
| `INFRAOPS_REQUIRE_PROXY` | `1` dans l'unité systemd | Proxy obligatoire : démarrage refusé si le secret est absent ou trop court (`journalctl -u infraops` l'indique) |
| `INFRAOPS_WEBHOOK_TOKEN` | — | Jeton du webhook Zabbix (≥ 32 car., sinon webhook fermé) |
| `INFRAOPS_ALLOWED_HOSTS` | boucle locale | En-têtes Host acceptés |
| `INFRAOPS_AUTO_INTERVAL` | 0 | Intervalle initial (0, 60, 300, 900 s) ; le choix de l'opérateur prime |
| `INFRAOPS_STARTUP_SWEEP` | 1 | 0 désactive la relecture unique des sources API et du réseau au démarrage (section 0 bis) |
| `INFRAOPS_SSE_MAX`, `INFRAOPS_SSE_MAX_PER_ACTOR` | 50, 3 | Flux temps réel simultanés (nginx : 6 par adresse) |
| `INFRAOPS_SSH_MAX_SESSIONS` | 24 | Sessions ssh simultanées, tous chemins confondus (bastion protégé) |
| `INFRAOPS_LOG_LEVEL`, `INFRAOPS_ACCESS_LOG` | INFO, 1 | Journaux JSON ; 0 coupe la ligne d'accès HTTP |
| `INFRAOPS_METRICS` | 0 (1 sur la VM) | 1 active `/api/metrics` (Prometheus) ; lisible sans rôle par l'agent local, bloqué par nginx |
| `INFRAOPS_BACULA_TUNNEL_TARGET` | — | `compte@hôte` du tunnel Bacula ; sans valeur, tunnel non ouvert |
| `INFRAOPS_API_DOCS` | 0 | 1 active `/docs` (ne pas activer en production) |
| `COCKPIT_DB`, `COCKPIT_AUDIT` | `data/state.sqlite3`, `audit.log` | Emplacements |
| `INFRAOPS_INVENTORY` | `hosts.yaml` à la racine | Chemin absolu ou relatif au répertoire de lancement ; choisi aussi pour les modifications locales de l’inventaire |
| `COCKPIT_AUDIT_MAX_BYTES`, `COCKPIT_AUDIT_KEEP` | 10 Mo, 30 | Rotation du journal SSH |
| `COCKPIT_SSH_KEY`, `COCKPIT_SSH_USER`, `COCKPIT_SSH_CONFIG` | `hosts.yaml` | Identité SSH de collecte |
| `COCKPIT_WORKERS` | 4 | Collectes SSH parallèles (max 16) |

Un clone neuf ne contient pas `inventory-report.json` : la page de rapprochement indique que le rapport n’est pas généré, sans afficher de compteurs de conflits supposés.

Les tests de scripts et de configuration SSH utilisent `testing_tools.py`.
Sous Windows, chaque exécutable est lancé à blanc une fois avec un délai de 180 s
(Bash/sh : `-c 'exit 0'`, SSH : `-V`). En cas de délai dépassé, une seconde tentative
dispose de 30 s ; les commandes de test suivantes disposent d’au moins 30 s.
Si l’outil ne répond pas, le test est ignoré avec la phase et les délais concernés,
et cette raison est conservée pour les tests suivants du même processus.
Une sortie incorrecte d’une commande de test continue de faire échouer son assertion.
Sous Linux, les délais et les exceptions restent ceux des tests existants.

## Tests navigateur dans la validation

`python deploy/ci.py --offline --ui` ajoute les tests navigateur sur données simulées
(`test_ui_*.cjs`, requêtes interceptées). Prérequis : Node.js et Playwright
(`npm install --prefix data/browser-test playwright@1.63.0 axe-core@4.10.2`, en une seule commande :
un `npm install` séparé retire les paquets absents du `package.json` local) ; sans Chromium Playwright
téléchargé, `OPS_BROWSER_CHANNEL=msedge` utilise Edge. `test_ui.cjs` et
`test_ui_proxmox.cjs` visent une instance réelle (`OPS_URL`) et restent des recettes
manuelles. La CI GitHub installe Playwright et lance `--ui`.

Pendant les tests, `testing_env` refuse toute connexion ou résolution DNS non locale.

## Ruff dans la validation

Installer les outils avec `python -m pip install -r requirements-dev.txt`.
`python deploy/ci.py --offline` lance Ruff sur les fichiers Python modifiés,
indexés ou nouveaux non ignorés ; un fichier historique inchangé n’est pas analysé.
Le crochet `--quick` ne considère que les fichiers indexés.

E9 et F sont bloquants. E/W/I (hors E9) sont affichés sous forme de statistiques
informatives et n’influencent pas le résultat. Une erreur d’installation ou de
configuration de l’outil reste un échec technique. Aucun `--fix` ni `ruff format`
n’est exécuté. Les exclusions sont définies dans `pyproject.toml`.

GitHub Actions fournit `INFRAOPS_RUFF_BASE` : SHA de base de la pull request ou
SHA précédant le push. La comparaison porte sur ce commit et HEAD, avec
`fetch-depth: 0`. Le premier push (SHA nul) considère tous les fichiers suivis
comme nouveaux. Pour reproduire une comparaison localement, définir cette variable
avec un SHA existant. Une base invalide/inaccessible bloque la validation plutôt
que d’ignorer silencieusement des fichiers.
