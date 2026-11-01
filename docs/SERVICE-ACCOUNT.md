# Compte de service `infraops` sur les serveurs supervisés

État constaté (audit du 05/10/2026) : la collecte SSH utilise un compte nominatif sur la
plupart des serveurs, et `root` sur deux d'entre eux. Un compte personnel lie la
supervision à une personne (départ, rotation de clé) et rend la traçabilité ambiguë ;
`root` donne à l'outil bien plus que ce qu'il lit.

Cible : un compte `infraops` dédié, authentifié par la clé propre au service, **sans**
mot de passe, et `sudo` limité aux seules lectures nécessaires — sur les serveurs WAF /
Apache uniquement. L'audit SSH standard n'utilise aucun `sudo`.

OpsControl ne déploie rien lui-même : ces étapes sont exécutées par l'équipe, serveur par
serveur, avec ses outils habituels (Ansible, console). L'ordre permet de revenir en arrière
à tout moment.

## 1. Clé du service

Sur la VM : `install-vm.sh` a généré `/opt/infraops/.ssh/id_ed25519`. Récupérer la clé
**publique** :

```sh
sudo cat /opt/infraops/.ssh/id_ed25519.pub
```

## 2. Sur chaque serveur

```sh
useradd --system --create-home --shell /bin/bash infraops      # shell requis : l'audit lance des commandes
install -d -o infraops -g infraops -m 0700 /home/infraops/.ssh
# Restreindre l'origine : seule la VM OpsControl peut utiliser cette clé. « restrict »
# coupe d'office tous les relais (agent, ports, X11, pty, ~/.ssh/rc) et ceux d'une future
# version d'OpenSSH : une clé volée n'ouvre pas de tunnel (audit SSH-01).
echo 'restrict,from="<IP-VM>" <clé publique>' \
  > /home/infraops/.ssh/authorized_keys
chown infraops:infraops /home/infraops/.ssh/authorized_keys
chmod 0600 /home/infraops/.ssh/authorized_keys
passwd -l infraops                                              # aucun mot de passe utilisable
```

Serveur Bacula : OpsControl y ouvre un tunnel local (127.0.0.1:19096 → 9096), que
`restrict` interdirait. Y rouvrir uniquement ce relais :
`restrict,port-forwarding,permitopen="127.0.0.1:9096",from="<IP-VM>" <clé publique>`.

Une fois chaque serveur basculé, retirer `root` et le compte nominatif de `ssh.users`
dans `hosts.yaml` : sinon la clé de collecte reste un accès root au parc.

Certaines vérifications lisent des fichiers réservés à un groupe (journaux système) : si
une preuve passe en « droits insuffisants » après bascule, ajouter `infraops` au groupe de
lecture concerné (`adm`, `systemd-journal`) plutôt que d'élargir `sudo`.

## 3. Serveurs WAF / Apache uniquement : lecture bornée

```sh
install -o root -g root -m 0755 infraops-read.sh /usr/local/sbin/infraops-read
command -v apache2ctl ss iptables fail2ban-client     # comparer aux chemins du fichier sudoers
install -o root -g root -m 0440 sudoers-infraops /etc/sudoers.d/infraops
visudo -cf /etc/sudoers.d/infraops                    # OBLIGATOIRE : un fichier invalide casse sudo
sudo -l -U infraops                                   # vérifier la liste exacte
```

Fichiers : [deploy/remote/infraops-read.sh](../deploy/remote/infraops-read.sh),
[deploy/remote/sudoers-infraops](../deploy/remote/sudoers-infraops).

Pourquoi un script : dans les arguments d'une règle sudoers, `*` accepte aussi les espaces
et `..` ; une règle `tail -c * -- /var/log/apache2/*` laisserait lire `/etc/shadow`.
`infraops-read` résout le chemin réel, n'accepte que `/etc/apache2` (fichiers de
configuration), `/etc/modsecurity/*.conf`, `/var/log/apache2` et, pour les métadonnées de
certificat, `/etc/ssl`, `/etc/letsencrypt` ; il refuse tout fichier contenant une clé privée.
Les sondes l'utilisent dès qu'il est présent (`/usr/local/sbin/infraops-read`), sinon elles
gardent l'appel `sudo` historique : la transition se fait serveur par serveur.

Contrôles rapides sur le serveur :

```sh
sudo -u infraops sudo -n /usr/local/sbin/infraops-read tail 200 /var/log/apache2/error.log   # OK
sudo -u infraops sudo -n /usr/local/sbin/infraops-read head 200 /etc/shadow                  # refusé (code 2)
sudo -u infraops sudo -n /usr/bin/tail /etc/shadow                                           # refusé par sudo
```

## 4. Bascule dans OpsControl

1. Ajouter le compte en tête de `ssh.users` dans `hosts.yaml` (les comptes sont essayés
   dans l'ordre), ou par serveur avec `user: infraops`.
2. Réauditer le serveur depuis sa fiche ; vérifier que la couverture ne baisse pas.
3. Quand tout le parc est vert : retirer le compte personnel de `ssh.users` et les
   `user: root` de l'inventaire.
4. Tunnel Bacula : `INFRAOPS_BACULA_TUNNEL_TARGET=infraops@<serveur Bacula>` dans
   `deploy/infraops.service` (VM) ou le lanceur (poste Windows).
5. Sur chaque serveur, retirer la clé de la VM des `authorized_keys` du compte personnel
   et de `root`.

## Retour arrière

Remettre l'ancien compte en tête de `ssh.users` : rien n'a été supprimé tant que l'étape
4.5 n'est pas faite. Supprimer `/etc/sudoers.d/infraops` retire immédiatement tout droit
`sudo` du compte.
