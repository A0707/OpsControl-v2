"""Recensement des applications hébergées, relevé directement sur les serveurs.

Le registre des applications (Google Sheet) est tenu à la main : il peut
diverger de ce qui tourne réellement. Ce module relève la « vérité du terrain »
sur chaque serveur de l'inventaire et la restitue dans un classeur Excel.

Décisions de conception :

1. UNE opération SSH figée (`apps`), ajoutée à la liste fermée ssh.OPERATIONS.
   Le client ne choisit ni la commande ni ses paramètres, comme pour les autres
   sondes ; une seule connexion par serveur.

2. Lecture seule et SANS sudo. Les serveurs standards n'ont aucun droit sudo pour
   le compte de supervision (deploy/remote/sudoers-infraops). Conséquence assumée :
   sans root, `ss` ne nomme pas le processus d'un port et `docker ps` peut être
   refusé. Le classeur le dit plutôt que de laisser croire à une absence.

3. Jamais de ligne de commande complète. Les arguments d'un processus peuvent
   contenir des mots de passe (-Dpassword=…, URL JDBC). On n'extrait que des
   motifs d'identification bornés : -jar, catalina.base, nom Spring, script Node.

Usage :
    python inventaire_applications.py [chemin/de/sortie.xlsx] [--serveur NOM ...]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import ssh

BASE = Path(__file__).resolve().parent

# Motifs Java d'identification. Volontairement étroits : un -cp ou une option
# -D quelconque peut porter un secret ou des centaines de chemins.
_JAVA = (r"-Dcatalina\.base=[^ ]+|-jar [^ ]+|-Dspring\.application\.name=[^ ]+|"
         r"-Des\.path\.home=[^ ]+|-Djboss\.home\.dir=[^ ]+|-Dls\.home=[^ ]+|"
         r"kafka\.Kafka|org\.apache\.zookeeper\.server\.quorum\.QuorumPeerMain")

# Liste des processus SANS ceux de cette sonde : les grep du pipeline et le shell
# distant (qui porte toute la commande, marqueurs ## compris) contiennent les motifs
# cherchés et produiraient de faux résultats.
_PS = "ps -eo args= 2>/dev/null | grep -v -e '^grep ' -e '##'"
_CONF_WEB = ("/etc/apache2/sites-enabled/* /etc/httpd/conf.d/*.conf /etc/nginx/sites-enabled/* "
             "/etc/nginx/conf.d/*.conf")
# Ajoute à chaque ligne « |date » du fichier qu'elle désigne quand c'est un chemin absolu
# (.jar, script) ; vide sinon. stat ne lit pas le fichier : aucun droit de lecture requis.
_DATE_FICHIER = ("| while read -r l; do p=${l#-jar }; p=${p#*=}; case \"$p\" in "
                 "/*.jar|/*.js|/*.mjs|/*.cjs|/*.py) echo \"$l|$(stat -c %Y \"$p\" 2>/dev/null)\";; "
                 "*) echo \"$l|\";; esac; done; ")
# Paquets clés : liste FERMÉE de noms (moteurs, bases, serveurs web, agents), pour dater
# les versions sans lister tout le système. Lecture de la base des paquets, sans root.
_PAQUETS = (r"openjdk-[0-9]+-(jre|jdk)(-headless)?|java-[0-9.]+-openjdk(-headless|-devel)?|"
            r"temurin-[0-9]+-(jre|jdk)|tomcat[0-9]*|apache2|httpd|nginx|haproxy|keepalived|"
            r"php[0-9.]*|php[0-9.]*-(fpm|cli)|nodejs|python3|python3\.[0-9]+|python3[0-9]+|"
            r"mariadb-server|mysql-server|mysql-community-server|postgresql-[0-9]+|"
            r"postgresql[0-9]*-server|mongodb-org-server|redis-server|redis|elasticsearch|kibana|"
            r"logstash|rabbitmq-server|docker-ce|docker\.io|containerd\.io|containerd|openssl|"
            r"openssh-server|bacula-(fd|client|director|sd)|zabbix-agent2?|wazuh-agent|elastic-agent")

COMMAND = (
    # /usr/sbin manque au PATH d'une session SSH non interactive sur RHEL/CentOS : ss y est.
    "LC_ALL=C; PATH=$PATH:/usr/sbin:/sbin; export LC_ALL PATH; "
    "echo '##OS'; (. /etc/os-release 2>/dev/null && echo \"$PRETTY_NAME\"); "
    # Services réellement démarrés, puis activés au démarrage (arrêtés compris).
    "echo '##RUNNING'; systemctl list-units --type=service --state=running --no-pager --no-legend --plain "
    "2>/dev/null | awk '{print $1}' | head -n 300; "
    "echo '##ENABLED'; systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend "
    "2>/dev/null | awk '{print $1}' | head -n 300; "
    # Ports TCP en écoute : adresse:port seulement (le processus exige root).
    "echo '##PORTS'; ss -ltn 2>/dev/null | awk 'NR>1 {print $4}' | sort -u | head -n 200; "
    "echo '##JAVA'; " + _PS + " | grep -E '^[^ ]*java ' | grep -oE -e '" + _JAVA + "' "
    "| sort -u | head -n 80 " + _DATE_FICHIER +
    "echo '##NODE'; " + _PS + " | grep -E '^[^ ]*(node|nodejs|PM2)[^ ]* ' "
    "| grep -oE '[^ ]+\\.(js|mjs|cjs)' | sort -u | head -n 40 " + _DATE_FICHIER +
    "echo '##PYTHON'; " + _PS + " | grep -E '^[^ ]*(python[0-9.]*|gunicorn|uwsgi|celery)[^ ]* ' "
    "| grep -oE '[^ ]+\\.py|-m [A-Za-z0-9_.]+|gunicorn|uwsgi|celery' | sort -u | head -n 40 " + _DATE_FICHIER +
    "echo '##PHP'; " + _PS + " | grep -oE 'php-fpm: pool [^ ]+' | sort -u | head -n 40; "
    # Docker : le code retour distingue « absent », « refusé » et « aucun conteneur ».
    "echo '##DOCKER'; if command -v docker >/dev/null 2>&1; then "
    "o=$(timeout 10 docker ps --format '{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}|{{.CreatedAt}}' 2>&1); "
    "echo \"RC|$?\"; printf '%s\\n' \"$o\" | head -n 200; else echo 'ABSENT'; fi; "
    # Services Swarm : ne répond que sur un nœud manager, silencieux ailleurs.
    "echo '##SWARM'; command -v docker >/dev/null 2>&1 && timeout 10 docker service ls "
    "--format '{{.Name}}|{{.Image}}|{{.Mode}}|{{.Replicas}}' 2>/dev/null | head -n 300; "
    # Sites web déclarés (Apache, Nginx) : noms seulement, fichiers lisibles sans root.
    "echo '##VHOSTS'; grep -HiE '^[[:space:]]*(ServerName|ServerAlias|server_name)[[:space:]]' "
    + _CONF_WEB + " 2>/dev/null | head -n 200; "
    # Ce qui sert chaque site : bloc VirtualHost/listen, TLS, proxy vers une application,
    # racine de fichiers. Directives seulement, jamais le reste de la configuration
    # (qui peut contenir des secrets : SetEnv, mots de passe de proxy).
    # <Proxy balancer://…> et BalancerMember : membres réels d'un répartiteur Apache.
    "echo '##VHOSTCONF'; grep -HiE '^[[:space:]]*(<VirtualHost|ServerName|ServerAlias|server_name|listen|"
    "SSLEngine|ssl_certificate|ProxyPass|ProxyPassMatch|proxy_pass|<Proxy|BalancerMember|upstream|server|"
    "DocumentRoot|root)[[:space:]]' "
    + _CONF_WEB + " 2>/dev/null | grep -viE 'ProxyPassReverse|ssl_certificate_key|SSLCertificateKey' "
    "| head -n 800; "
    # Dernière modification de chaque configuration de site (stat -L : sites-enabled contient
    # des liens vers sites-available, c'est le fichier réel qui compte).
    "echo '##VHOSTFILES'; stat -L -c '%Y|%n' " + _CONF_WEB + " 2>/dev/null | head -n 400; "
    # .war ou dossier déployé, avec sa date : celle du dernier déploiement.
    "echo '##WEBAPPS'; stat -c '%Y|%n' /var/lib/tomcat*/webapps/* /usr/share/tomcat*/webapps/* "
    "/opt/*/webapps/* /opt/*/*/webapps/* /var/*/webapps/* 2>/dev/null | head -n 200; "
    # Fichiers de service : ctime = date d'écriture sur le disque, donc installation ou dernière
    # mise à jour du paquet (dpkg et rpm conservent le mtime d'origine, pas le ctime).
    "echo '##UNITFILES'; stat -c '%Z|%n' /etc/systemd/system/*.service /lib/systemd/system/*.service "
    "/usr/lib/systemd/system/*.service /etc/init.d/* 2>/dev/null | head -n 2500; "
    # Date d'installation du système, trois sources par ordre de fiabilité, sans root :
    # paquet basesystem (RHEL/CentOS, premier paquet installé), journal de l'installeur
    # (Debian/Ubuntu), date de naissance de la racine (noyau et coreutils récents).
    "echo '##INSTALL'; t=$(rpm -q --qf '%{INSTALLTIME}' basesystem 2>/dev/null) && echo \"RPM|$t\"; "
    "[ -e /var/log/installer ] && echo \"INSTALLER|$(stat -c %Y /var/log/installer/syslog 2>/dev/null "
    "|| stat -c %Y /var/log/installer 2>/dev/null)\"; "
    "echo \"ROOT|$(stat -c %W / 2>/dev/null)\"; "
    # Paquets clés installés : « gestionnaire|nom|version » ; dpkg seulement s'ils sont
    # réellement installés (état « ii »), pas les paquets retirés mais configurés.
    "echo '##PAQUETS'; echo \"KERNEL|$(uname -r 2>/dev/null)\"; "
    "if command -v dpkg-query >/dev/null 2>&1; then "
    "dpkg-query -W -f='${db:Status-Abbrev}|${Package}|${Version}\\n' 2>/dev/null | grep '^ii' "
    "| cut -d'|' -f2- | grep -E '^(" + _PAQUETS + ")\\|' | sed 's/^/dpkg|/' | head -n 120; "
    "elif command -v rpm >/dev/null 2>&1; then "
    "rpm -qa --qf '%{NAME}|%{VERSION}-%{RELEASE}\\n' 2>/dev/null "
    "| grep -E '^(" + _PAQUETS + ")\\|' | sort -u | sed 's/^/rpm|/' | head -n 120; fi; "
    # DIRS en dernier : une bannière de fin de session peut s'y mêler.
    "echo '##DIRS'; ls -d /opt/* /srv/* /var/www/* 2>/dev/null | head -n 100"
)
ssh.OPERATIONS['apps'] = COMMAND

# Socle système : présent partout, sans valeur pour un registre d'applications.
SYSTEME = re.compile(
    r'^(systemd-.*|dbus.*|cron|crond|ssh|sshd|rsyslog|syslog-ng|.*getty@.*|getty.*|polkit|'
    r'networkd-dispatcher|unattended-upgrades|chrony|chronyd|ntp|ntpd|ntpsec|atd|irqbalance|'
    r'multipathd|snapd|accounts-daemon|udisks2|user@.*|lvm2-.*|blk-availability|auditd|firewalld|'
    r'tuned|NetworkManager|wpa_supplicant|ModemManager|packagekit|iscsid|open-vm-tools|vgauth|'
    r'rpcbind|rpc-.*|nfs-idmapd|nfs-mountd|nfsdcld|smartd|mdmonitor|lxcfs|apparmor|ufw|kdump.*|'
    r'sysstat|upower|rtkit-daemon|avahi-daemon|cups|gdm|thermald|haveged|rngd|console-.*|'
    r'plymouth.*|kmod.*|finalrd|setvtrgb|ifup@.*|networking|dm-event|gssproxy|sssd.*|nscd|nslcd|'
    r'getty-static|e2scrub.*|fstrim|logrotate|man-db|apt-daily.*|motd-news|ondemand|'
    r'cloud-.*|rc-local|systemd|keyboard-setup|resolvconf|ssh-.*|sshd-.*|serial-.*|'
    r'pmcd|pmie|pmlogger|pmproxy|lm-sensors|acpid|mcelog|microcode|cpupower|import-state|'
    r'nftables|iptables|netfilter-persistent|ebtables|ip6tables|selinux-.*|restorecond|'
    r'dracut-.*|grub-.*|ua-.*|ubuntu-.*|secureboot-.*|vmtoolsd|hv-.*|hv_.*|qemu-guest-agent|'
    r'NetworkManager-.*|abrt.*|autovt@.*|dmraid-activation|iscsi.*|open-iscsi|libstoragemgmt|rhel-.*|'
    r'vgauthd|rhsmcertd|rhnsd|ksm|ksmtuned|nis-domainname|anacron|whoopsie|kerneloops|apport.*|'
    r'pollinate|lightdm|display-manager|gpu-manager|smartmontools|mdadm.*|nvmf-.*|emergency|rescue|'
    r'zram.*|fwupd.*|unbound-anchor|rdisc|alsa-.*|bluetooth|colord|switcheroo-control|'
    r'power-profiles-daemon|vmware-tools|vmware-.*|lvm2|multipath.*|sysstat-.*|hddtemp|'
    r'ssh-agent|dbus-.*|getty|debug-shell|quotaon|systemd-.*|syslog|rsyslogd|journald|'
    r'cloud-init.*|snap\..*|ec2-.*|open-vm-.*|run-vmblock.*|uuidd|wtmpdb-.*|man-db|'
    r'dpkg-db-backup|binfmt-support|cryptdisks.*|hwclock|procps|udev|ureadahead|'
    r'irqbalance|lm_sensors|rngd|mcelog|cpupower|tcsd|oddjobd|realmd|certmonger|'
    r'packagekit-offline-update|nfs-blkmap|sshd-keygen.*|import-state|loadmodules|readonly|'
    r'lvm2-.*|blk-availability|kdump|crond|atd|tuned|firewalld|auditd|chronyd|postfix-.*)$')

# Services connus : (catégorie, libellé lisible). Ordre : premier motif gagnant.
CONNUS = [
    (r'^(apache2|httpd)$', 'Serveur web', 'Apache'),
    (r'^nginx$', 'Serveur web', 'Nginx'),
    (r'^(haproxy|traefik|varnish|squid|keepalived)$', 'Répartition / proxy', None),
    (r'.*tomcat.*', "Serveur d'applications", 'Tomcat'),
    (r'^(wildfly|jboss.*|jetty.*)$', "Serveur d'applications", None),
    (r'^php.*-fpm$', "Serveur d'applications", 'PHP-FPM'),
    (r'^pm2-.*', "Serveur d'applications", 'Node.js (PM2)'),
    (r'^(mysql|mysqld|mariadb)$', 'Base de données', 'MySQL / MariaDB'),
    (r'^(rh-)?postgresql.*', 'Base de données', 'PostgreSQL'),
    (r'^(mongod|mongodb)$', 'Base de données', 'MongoDB'),
    (r'^(redis.*|memcached|valkey.*)$', 'Cache', None),
    (r'^(elasticsearch|opensearch)$', 'Recherche / journaux', 'Elasticsearch'),
    (r'^(kibana|logstash|graylog-server|fluentd|td-agent|cerebro)$',
     'Recherche / journaux', None),
    (r'^(rabbitmq-server|kafka|zookeeper|activemq|artemis|mosquitto)$', 'Messagerie', None),
    (r'^(docker|containerd|k3s|kubelet|podman)$', 'Conteneurs', None),
    (r'^(bind9|named|unbound|dnsmasq|pdns.*)$', 'Infrastructure', 'DNS'),
    (r'^(openvpn.*|wg-quick@.*|strongswan.*|ipsec|xl2tpd|nordvpnd)$', 'Infrastructure', 'VPN'),
    (r'^(libvirtd|virtqemud)$', 'Infrastructure', 'Virtualisation'),
    (r'^(postfix|postfix@.*|exim4|sendmail|dovecot)$', 'Infrastructure', 'Messagerie électronique'),
    (r'^(vsftpd|proftpd|pure-ftpd)$', 'Infrastructure', 'FTP'),
    (r'^(nfs-server|nfs-kernel-server|smbd|nmbd|glusterd)$', 'Infrastructure', 'Partage de fichiers'),
    (r'^(slapd|freeradius|krb5kdc)$', 'Infrastructure', 'Annuaire / authentification'),
    (r'^(gitlab-runsvdir|gitea|jenkins|gitlab-runner|nexus|sonarqube)$', 'Outillage', None),
    (r'^(zabbix-server|zabbix-proxy|grafana-server|prometheus|wazuh-manager|wazuh-indexer|'
     r'wazuh-dashboard|alertmanager)$', 'Supervision (serveur)', None),
    (r'^(bacula-dir|bacula-director|bacula-sd|bareos-.*)$', 'Sauvegarde (serveur)', None),
    (r'^(zabbix-agent.*|wazuh-agent|bacula-fd|node_exporter|prometheus-node-exporter|'
     r'fail2ban|ossec.*|falcon-sensor|crowdstrike.*|elastic-agent|osqueryd|snmpd|clamd.*|'
     r'clamav-.*|freshclam|filebeat|metricbeat|auditbeat|heartbeat-elastic)$', 'Agent', None),
]
CONNUS = [(re.compile(motif), categorie, libelle) for motif, categorie, libelle in CONNUS]

# Applications Tomcat livrées par défaut : ce ne sont pas des applications métier.
WEBAPPS_DEFAUT = {'ROOT', 'docs', 'examples', 'host-manager', 'manager'}


# Codes ANSI et caractères de contrôle : certains serveurs affichent une bannière
# colorée en fin de session, qui se mêle à la dernière section.
_CONTROLE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')


def sections(sortie):
    """Découpe la sortie brute en sections ##NOM -> lignes non vides."""
    blocs, courant = {}, None
    for ligne in _CONTROLE.sub('', sortie or '').splitlines():
        if ligne.startswith('##'):
            courant = blocs.setdefault(ligne[2:].strip(), [])
        elif courant is not None and ligne.strip():
            courant.append(ligne.rstrip())
    return blocs


def classer_service(unite):
    """(catégorie, libellé) d'une unité systemd ; None pour le socle système."""
    nom = unite[:-len('.service')] if unite.endswith('.service') else unite
    for motif, categorie, libelle in CONNUS:
        if motif.match(nom):
            return categorie, libelle or nom
    if SYSTEME.match(nom) or nom.endswith('@'):
        return None
    # Ni socle ni produit connu : c'est souvent là que se trouve l'application métier.
    return 'Service spécifique (à qualifier)', nom


# Nature de chaque date : elles ne disent pas toutes la même chose.
NATURE_SERVICE = 'Installation ou dernière mise à jour du service'
NATURE_DEPLOIEMENT = 'Dernier déploiement du fichier'
NATURE_CONTENEUR = 'Création du conteneur'
NATURE_CONFIG = 'Dernière modification de la configuration'


def _horodatage(valeur):
    """Horodatage Unix plausible, ou None (vide, « - », 0, horloge non réglée)."""
    valeur = (valeur or '').strip()
    return int(valeur) if valeur.isdigit() and int(valeur) >= _PLANCHER else None


def _dates_par_chemin(lignes):
    """Lignes « horodatage|chemin » -> {chemin: horodatage}."""
    dates = {}
    for ligne in lignes:
        valeur, _, chemin = ligne.partition('|')
        if chemin.startswith('/'):
            dates[chemin] = _horodatage(valeur)
    return dates


def date_unite(unite, fichiers):
    """Date du fichier d'une unité systemd : paquet d'abord, puis /etc, puis script init.d.

    Le fichier livré par le paquet (/lib, /usr/lib) date l'installation ou la mise à jour ;
    dans /etc on trouve une unité écrite à la main (application maison) ou un lien
    d'activation ; /etc/init.d couvre les services encore lancés par script.
    Une instance « nom@x.service » se rattache à son modèle « nom@.service ».
    """
    nom = unite.removesuffix('.service')
    if '@' in nom:
        nom = nom.split('@', 1)[0] + '@'
    for dossier in ('/lib/systemd/system/', '/usr/lib/systemd/system/', '/etc/systemd/system/'):
        if fichiers.get(dossier + nom + '.service'):
            return fichiers[dossier + nom + '.service']
    return fichiers.get('/etc/init.d/' + nom)


def _date_docker(valeur):
    """« 2024-01-06 12:00:00 +0100 CET » -> horodatage, ou None."""
    try:
        return int(datetime.strptime(valeur.strip()[:25], '%Y-%m-%d %H:%M:%S %z').timestamp())
    except ValueError:
        return None


def _valeur_et_date(ligne):
    """« motif|horodatage » produit par _DATE_FICHIER -> (motif, horodatage ou None)."""
    valeur, _, date = ligne.rpartition('|')
    return (valeur, _horodatage(date)) if valeur else (ligne, None)


def analyser(sortie):
    """Sortie de l'opération `apps` -> éléments détectés et contexte du serveur."""
    blocs = sections(sortie)
    elements = []

    def ajouter(categorie, source, nom, detail='', etat='', date=None, nature=''):
        elements.append({'categorie': categorie, 'source': source, 'nom': nom, 'detail': detail,
                         'etat': etat, 'date': date, 'nature_date': nature if date else ''})

    unites = _dates_par_chemin(blocs.get('UNITFILES', []))
    demarres = set(blocs.get('RUNNING', []))
    actives = set(blocs.get('ENABLED', []))
    for unite in sorted(demarres | actives):
        classe = classer_service(unite)
        if not classe:
            continue
        # Un service activé mais arrêté n'est retenu que s'il s'agit d'un produit
        # connu (base, serveur web…) : pour le reste, ce sont presque toujours des
        # unités « oneshot » de démarrage, du bruit pour un registre d'applications.
        if unite not in demarres and classe[0] == 'Service spécifique (à qualifier)':
            continue
        nom = unite.removesuffix('.service')
        ajouter(classe[0], 'Service systemd', nom, classe[1] if classe[1] != nom else '',
                'Démarré' if unite in demarres else 'Activé mais arrêté',
                date_unite(unite, unites), NATURE_SERVICE)

    docker = blocs.get('DOCKER', [])
    if docker == ['ABSENT'] or not docker:
        etat_docker = 'Absent'
    else:
        code = docker[0].split('|', 1)[1] if docker[0].startswith('RC|') else ''
        lignes = [ligne for ligne in docker[1:] if ligne.count('|') >= 3]
        if code != '0':
            refus = any('permission denied' in ligne.lower() for ligne in docker)
            etat_docker = 'Accès refusé (droits)' if refus else 'Erreur'
        else:
            etat_docker = f'{len(lignes)} conteneur(s)'
        for ligne in lignes:
            nom, image, statut, ports, creation = (ligne.split('|', 4) + [''] * 5)[:5]
            ajouter('Conteneur', 'Docker', nom, f'image {image}' + (f' ; ports {ports}' if ports else ''), statut,
                    _date_docker(creation), NATURE_CONTENEUR)
    for ligne in blocs.get('SWARM', []):
        if ligne.count('|') >= 3:
            nom, image, mode, repliques = ligne.split('|', 3)
            ajouter('Service Swarm', 'Docker Swarm', nom, f'image {image} ; {mode}', repliques)

    configurations = _dates_par_chemin(blocs.get('VHOSTFILES', []))
    sites = {}
    for ligne in blocs.get('VHOSTS', []):
        fichier, _, directive = ligne.partition(':')
        for nom in directive.replace(';', ' ').split()[1:]:
            # Un même nom revient pour le port 80 et le port 443 : une ligne par nom.
            if nom not in ('_', 'localhost', 'default_server') and nom.lower() not in sites:
                sites[nom.lower()] = ('Nginx' if '/nginx/' in fichier else 'Apache', nom, fichier)
    for serveur_web, nom, fichier in sorted(sites.values(), key=lambda site: site[1].lower()):
        ajouter('Site web', serveur_web, nom, fichier, date=configurations.get(fichier), nature=NATURE_CONFIG)

    # Application Tomcat : le .war date le déploiement ; à défaut, le dossier déployé.
    webapps = {}
    for chemin, date in _dates_par_chemin(blocs.get('WEBAPPS', [])).items():
        base, _, nom = chemin.rstrip('/').rpartition('/')
        archive = nom.endswith('.war')
        nom = nom[:-4] if archive else nom
        if nom in WEBAPPS_DEFAUT:
            continue
        connu = webapps.get((base, nom))
        if connu is None or (archive and not connu[2]):
            webapps[(base, nom)] = (chemin, date, archive)
    for (_base, nom), (chemin, date, _archive) in sorted(webapps.items(), key=lambda w: (w[0][1], w[0][0])):
        ajouter('Application web (Tomcat)', 'Tomcat', nom, chemin, date=date, nature=NATURE_DEPLOIEMENT)

    processus_vus = set()
    for ligne in blocs.get('JAVA', []):
        motif, date = _valeur_et_date(ligne)
        valeur = motif.replace('-jar ', '').split('=', 1)[-1].rstrip('/')
        nom = valeur.rsplit('/', 1)[-1] or valeur
        # Plusieurs conteneurs lancent souvent « -jar app.jar » : des lignes identiques
        # n'apprennent rien de plus, une seule suffit.
        if nom in processus_vus:
            continue
        processus_vus.add(nom)
        ajouter('Processus applicatif', 'Java', nom, motif, date=date, nature=NATURE_DEPLOIEMENT)
    for ligne in blocs.get('NODE', []):
        motif, date = _valeur_et_date(ligne)
        ajouter('Processus applicatif', 'Node.js', motif, date=date, nature=NATURE_DEPLOIEMENT)
    for ligne in blocs.get('PYTHON', []):
        motif, date = _valeur_et_date(ligne)
        ajouter('Processus applicatif', 'Python', motif.removeprefix('-m '), date=date, nature=NATURE_DEPLOIEMENT)
    for ligne in blocs.get('PHP', []):
        ajouter('Processus applicatif', 'PHP-FPM', ligne.removeprefix('php-fpm: pool '), 'pool PHP-FPM')

    ports = sorted({p.rsplit(':', 1)[-1] for p in blocs.get('PORTS', []) if ':' in p},
                   key=lambda p: (not p.isdigit(), int(p) if p.isdigit() else 0, p))
    installation, source_installation = date_installation(blocs.get('INSTALL', []))
    # Section absente (sonde antérieure) : None, jamais « aucun paquet ».
    noyau, liste_paquets = paquets(blocs['PAQUETS']) if 'PAQUETS' in blocs else ('', None)
    applications_web = [e['nom'] for e in elements if e['categorie'] == 'Application web (Tomcat)']
    return {'os': (blocs.get('OS') or [''])[0], 'elements': elements, 'ports': ports,
            'sites': sites_web(blocs.get('VHOSTCONF', []), blocs.get('DOCKER', []), applications_web, ports),
            'docker': etat_docker, 'dossiers': [d for d in blocs.get('DIRS', []) if d.startswith('/')],
            'installation': installation, 'installation_source': source_installation,
            'noyau': noyau, 'paquets': liste_paquets}


_PAQUET = re.compile(r'^(dpkg|rpm)\|([A-Za-z0-9][A-Za-z0-9.+_-]{0,99})\|([A-Za-z0-9.:+~_-]{1,100})$')


def paquets(lignes):
    """(noyau, [{nom, version, gestionnaire}]) ; une ligne au format inattendu est ignorée."""
    noyau, liste = '', []
    for ligne in lignes:
        if ligne.startswith('KERNEL|'):
            noyau = ligne[7:].strip()[:100]
        elif m := _PAQUET.match(ligne.strip()):
            liste.append({'gestionnaire': m.group(1), 'nom': m.group(2), 'version': m.group(3)})
    return noyau, sorted(liste, key=lambda p: p['nom'])


_NOM_HOTE = re.compile(r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*')
_PORT_DOCKER = re.compile(r'(?:\d+\.\d+\.\d+\.\d+|\[?::\]?)?:(\d+)->(\d+)/tcp')


def _cible(url):
    """URL de proxy -> (hôte, port, chemin), ou None. Un éventuel « compte:mot de passe@ » est
    écarté. Seule une vraie URL (schéma://hôte) est acceptée : « retry=0 » ou « keepalive=on »,
    options qui suivent l'URL sur une ligne ProxyPass, n'en sont pas."""
    from ipaddress import ip_address
    from urllib.parse import urlsplit
    if '://' not in url:
        return None
    try:
        u = urlsplit(url)
        port = u.port or (443 if u.scheme in ('https', 'wss') else 80)
    except ValueError:
        return None
    if u.scheme not in ('http', 'https', 'ws', 'wss', 'ajp', 'fcgi', 'h2', 'h2c'):
        return None
    hote = u.hostname or ''
    try:
        ip_address(hote)
    except ValueError:
        if not _NOM_HOTE.fullmatch(hote.rstrip('.')):
            return None
    return (hote, port, u.path or '/')


def _url_proxy(cle, valeurs):
    """(chemin, url) d'une directive ProxyPass/ProxyPassMatch/proxy_pass, ou None.

    Apache : « ProxyPass [chemin] url [clé=valeur…] » ; l'URL est le premier mot qui contient
    « :// » (balancer:// compris), PAS le dernier."""
    if cle == 'proxy_pass':
        return ('/', valeurs[0]) if valeurs else None
    url = next((v for v in valeurs if '://' in v), None)
    if url is None:
        return None   # « ProxyPass /chemin ! » : exclusion, pas une cible
    chemin = valeurs[0] if valeurs and valeurs[0] != url else '/'
    return chemin, url


def _developper(proxys, repartiteurs):
    """(chemin, url) -> (chemin, url réelle, répartiteur) : un balancer:// Apache ou un
    upstream Nginx est remplacé par chacun de ses membres ; une cible illisible est écartée."""
    for chemin, url in proxys:
        from urllib.parse import urlsplit
        try:
            u = urlsplit(url)
        except ValueError:
            continue
        cle = (url.split('://', 1)[0].lower() + '://' + (u.hostname or '')) if u.scheme == 'balancer' \
            else 'upstream:' + (u.hostname or '').lower()
        membres = repartiteurs.get(cle.rstrip('/'))
        if u.scheme == 'balancer' or membres:
            for membre in membres or []:
                if _cible(membre):
                    # Chemin du ProxyPass ajouté au membre (« balancer://x/app » -> membre + /app).
                    yield chemin, membre.rstrip('/') + (u.path or '/'), u.hostname
            continue
        if _cible(url):
            yield chemin, url, None


def sites_web(lignes, docker, applications_tomcat, ports_ecoute):
    """Un site par nom déclaré : HTTPS, cibles de proxy et application qui le sert.

    Les directives sont groupées par bloc (« <VirtualHost » pour Apache, « listen » pour
    Nginx). L'application est retrouvée par le port de la cible : conteneur Docker publiant
    ce port, application Tomcat dont le contexte correspond, ou simple port en écoute."""
    conteneurs = {}
    for ligne in docker[1:] if docker and docker[0].startswith('RC|') else []:
        champs = (ligne.split('|', 4) + [''] * 5)[:5]
        for publie, _interne in _PORT_DOCKER.findall(champs[3]):
            conteneurs.setdefault(int(publie), champs[0])
    # Répartiteurs : « <Proxy balancer://nom> » + BalancerMember (Apache), « upstream nom » +
    # « server hôte:port » (Nginx). Membres réels, développés après lecture de tout le relevé.
    repartiteurs, membres_de = {}, None
    blocs, courant = [], None
    for ligne in lignes:
        fichier, _, directive = ligne.partition(':')
        mots = directive.strip().rstrip(';').rstrip('{').strip().split()
        if not mots:
            continue
        cle = mots[0].lower().rstrip('>')
        if cle == '<proxy' and len(mots) > 1 and mots[1].lower().rstrip('>').startswith('balancer://'):
            membres_de = repartiteurs.setdefault(mots[1].rstrip('>').lower().rstrip('/'), [])
            continue
        if cle == 'upstream' and len(mots) > 1:
            membres_de = repartiteurs.setdefault('upstream:' + mots[1].lower(), [])
            continue
        if cle == 'balancermember' and membres_de is not None and len(mots) > 1:
            membres_de.append(mots[1])
            continue
        if cle == 'server':
            if membres_de is not None and len(mots) > 1:
                membres_de.append('http://' + mots[1])   # « server 10.0.0.5:8080 » d'un upstream
            continue   # « server { » : ouverture de bloc Nginx, rien à relever
        membres_de = None if cle not in ('balancermember', 'server') else membres_de
        nouveau = cle == '<virtualhost' or (cle == 'listen' and courant is not None and courant['noms']
                                             and courant['fichier'] == fichier)
        if courant is None or courant['fichier'] != fichier or nouveau:
            courant = {'fichier': fichier, 'noms': [], 'https': False, 'proxys': [], 'racines': []}
            blocs.append(courant)
        valeurs = mots[1:]
        if cle in ('<virtualhost', 'listen'):
            courant['https'] |= any(':443' in v or v == '443' or v == 'ssl' for v in valeurs)
        elif cle in ('servername', 'serveralias', 'server_name'):
            courant['noms'] += [v for v in valeurs if v not in ('_', 'localhost', 'default_server')]
        elif cle in ('sslengine', 'ssl_certificate'):
            courant['https'] |= cle == 'ssl_certificate' or (valeurs[:1] == ['on'])
        elif cle in ('proxypass', 'proxypassmatch', 'proxy_pass'):
            trouve = _url_proxy(cle, valeurs)
            if trouve:
                courant['proxys'].append(trouve)
        elif cle in ('documentroot', 'root') and valeurs:
            courant['racines'].append(valeurs[0].strip('"'))
    sites = {}
    for bloc in blocs:
        for nom in bloc['noms']:
            if not _NOM_HOTE.fullmatch(nom.rstrip('.')):
                continue   # joker (*.exemple), variable ou valeur inattendue : pas de lien
            site = sites.setdefault(nom.lower(), {'nom': nom, 'serveur_web': 'Nginx' if '/nginx/' in bloc['fichier']
                                                   else 'Apache', 'fichiers': [], 'https': False,
                                                   'cibles': [], 'racines': []})
            site['https'] |= bloc['https']
            if bloc['fichier'] not in site['fichiers']:
                site['fichiers'].append(bloc['fichier'])
            site['racines'] += [r for r in bloc['racines'] if r not in site['racines']]
            for chemin, url, repartiteur in _developper(bloc['proxys'], repartiteurs):
                hote, port, cible_chemin = _cible(url)
                contexte = cible_chemin.strip('/').split('/')[0]
                if port in conteneurs:
                    application = 'Conteneur Docker ' + conteneurs[port]
                elif contexte in applications_tomcat:
                    application = 'Application Tomcat ' + contexte
                elif hote in ('127.0.0.1', 'localhost', '::1', '') and str(port) in ports_ecoute:
                    application = f'Service local en écoute sur le port {port}'
                elif hote in ('127.0.0.1', 'localhost', '::1', ''):
                    application = f'Port local {port} non en écoute (application arrêtée ?)'
                else:
                    application = f'Serveur distant {hote}:{port}'
                entree = {'chemin': chemin, 'cible': f'{hote}:{port}{cible_chemin}', 'application': application,
                          'hote': hote, 'port': port, 'chemin_cible': cible_chemin, 'repartiteur': repartiteur}
                if entree not in site['cibles']:
                    site['cibles'].append(entree)
    for site in sites.values():
        site['url'] = ('https://' if site['https'] else 'http://') + site['nom'].rstrip('.') + '/'
    return sorted(sites.values(), key=lambda s: s['nom'].lower())


SOURCES_INSTALLATION = {'RPM': 'Paquet basesystem (rpm)', 'INSTALLER': "Journal de l'installeur Debian/Ubuntu",
                        'ROOT': 'Création du système de fichiers racine'}
# Avant 2005, une date relève d'une horloge non réglée, pas d'une installation réelle.
_PLANCHER = 1104537600


def date_installation(lignes):
    """(horodatage, source) le plus fiable de la section INSTALL, ou (None, '')."""
    valeurs = {}
    for ligne in lignes:
        cle, _, valeur = ligne.partition('|')
        valeur = valeur.strip()
        # stat %W renvoie 0 ou « - » quand le noyau ou coreutils ne connaît pas la date de naissance.
        if cle in SOURCES_INSTALLATION and valeur.isdigit() and int(valeur) >= _PLANCHER:
            valeurs[cle] = int(valeur)
    for cle in SOURCES_INSTALLATION:
        if cle in valeurs:
            return valeurs[cle], SOURCES_INSTALLATION[cle]
    return None, ''


CACHE_RELEVE = BASE / 'data' / 'releve-vm.json'
CHAMPS_ELEMENT = ('categorie', 'source', 'nom', 'etat', 'date', 'nature_date')


def memoriser_releve(resultats, fichier=CACHE_RELEVE):
    """Conserve le relevé de chaque serveur pour l'export Proxmox (rapprochement par VMID) :
    date d'installation du système et applications avec leurs dates.

    Fusion avec le relevé précédent : un serveur injoignable cette fois garde son dernier
    relevé connu, daté par « releve_le » pour qu'on sache de quand il date.
    """
    try:
        connues = json.loads(fichier.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        connues = {}
    maintenant = datetime.now(timezone.utc).isoformat()
    for r in resultats:
        if r.get('collecte') == 'OK':
            hote = r['hote']
            connues[hote['key']] = {'name': hote.get('name'), 'vmid': hote.get('vmid'), 'node': hote.get('node'),
                                    'installation': r.get('installation'), 'source': r.get('installation_source', ''),
                                    'applications': [{k: e.get(k) for k in CHAMPS_ELEMENT}
                                                     for e in r.get('elements', [])],
                                    'releve_le': maintenant}
    fichier.parent.mkdir(parents=True, exist_ok=True)
    # Écriture atomique : une interruption ne laisse pas un relevé tronqué (audit NEW-04).
    temporaire = fichier.with_name(fichier.name + '.tmp')
    temporaire.write_text(json.dumps(connues, ensure_ascii=False, indent=1), encoding='utf-8')
    os.replace(temporaire, fichier)
    return connues


def comptes_connus():
    """Compte SSH qui a déjà fonctionné, par serveur : évite des essais inutiles."""
    try:
        # Même base que le service (COCKPIT_DB sur la VM), en lecture seule (audit NEW-04).
        chemin = Path(os.environ.get('COCKPIT_DB') or BASE / 'data' / 'state.sqlite3').resolve()
        db = sqlite3.connect(chemin.as_uri() + '?mode=ro', uri=True)
    except sqlite3.Error:
        return {}
    try:
        return {cle: (etat.get('ssh_user'), etat.get('ssh_port'))
                for cle, etat in ((k, json.loads(p)) for k, p in db.execute('SELECT key,payload FROM states'))}
    except sqlite3.Error:
        return {}
    finally:
        db.close()


def relever(hote, cfg, connu=None):
    """Exécute `apps` sur un serveur, en essayant chaque couple compte/port."""
    from config import candidates

    resultat = {'hote': hote, 'collecte': 'Non tentée', 'erreur': '', 'compte': ''}
    if not hote.get('ip') or hote.get('collect_enabled') is False:
        resultat['collecte'] = 'Désactivée'
        return resultat
    essais = list(candidates(cfg, hote))
    if connu and connu[0]:
        essais.sort(key=lambda c: (c.user, c.port) != connu)
    ports_morts, echecs = set(), []
    for candidat in essais:
        if candidat.port in ports_morts:
            continue
        reponse = ssh.run_operation(hote['ip'], 'apps', candidat, 'inventaire-applications')
        # Une connexion établie ne prouve pas que la sonde a tourné : compte en nologin, shell
        # non POSIX ou commande introuvable rendent un code non nul sans aucune section.
        # Seule une sortie complète (premier et dernier marqueurs) vaut « OK » (audit GIT-01).
        if reponse.rc is not None and '##OS' in reponse.stdout and '##DIRS' in reponse.stdout:
            resultat.update(analyser(reponse.stdout), collecte='OK', compte=f'{candidat.user}:{candidat.port}')
            return resultat
        if reponse.rc is not None:
            inattendue = (reponse.stdout.strip() or reponse.stderr.strip() or f'code {reponse.rc}')
            resultat['sortie_inattendue'] = inattendue.splitlines()[0][:200]
            continue
        echecs.append(reponse)
        if reponse.error_kind != 'auth':
            ports_morts.add(candidat.port)
    if resultat.get('sortie_inattendue'):
        # Jamais « OK » ni mémorisé : le dernier relevé valide est conservé (memoriser_releve).
        resultat['collecte'] = 'Sortie inattendue'
        resultat['erreur'] = resultat.pop('sortie_inattendue')
        return resultat
    reseau = bool(echecs) and all(e.error_kind == 'network' for e in echecs)
    resultat['collecte'] = 'Injoignable' if reseau else 'Échec SSH'
    resultat['erreur'] = (echecs[-1].stderr.strip().splitlines() or [''])[0][:200] if echecs else ''
    return resultat


def ecrire(chemin, resultats):
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    police = 'Arial'
    titre = Font(name=police, bold=True, color='FFFFFF', size=10)
    fond = PatternFill('solid', fgColor='1F4E78')
    normal = Font(name=police, size=10)

    def tableau(feuille, entetes, lignes, largeur_max=45):
        for colonne, entete in enumerate(entetes, 1):
            cellule = feuille.cell(row=1, column=colonne, value=entete)
            cellule.font, cellule.fill = titre, fond
            cellule.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
        for numero, ligne in enumerate(lignes, 2):
            for colonne, valeur in enumerate(ligne, 1):
                if isinstance(valeur, str):
                    valeur = _CONTROLE.sub('', valeur)
                cellule = feuille.cell(row=numero, column=colonne, value=valeur)
                cellule.font = normal
                # Valeurs venues des serveurs (ServerName, PRETTY_NAME…) : « =… » serait évalué
                # comme formule à l'ouverture du classeur. Toujours du texte (audit NEW-01).
                if cellule.data_type == 'f':
                    cellule.data_type = 's'
        for colonne, entete in enumerate(entetes, 1):
            largeur = max([len(str(entete))] + [len(str(ligne[colonne - 1] or '')) for ligne in lignes])
            feuille.column_dimensions[get_column_letter(colonne)].width = min(max(largeur + 2, 10), largeur_max)
        feuille.freeze_panes = 'A2'
        if lignes:
            feuille.auto_filter.ref = f'A1:{get_column_letter(len(entetes))}{len(lignes) + 1}'

    def identite(hote):
        return [hote.get('name') or hote['key'], hote.get('ip') or '', hote.get('role') or '',
                hote.get('environment') or '']

    def jour(horodatage):
        return datetime.fromtimestamp(horodatage).strftime('%d/%m/%Y') if horodatage else ''

    def registre(hote):
        documente = (hote.get('documented') or {}).get('architecture') or {}
        return documente.get('description') or ''

    resultats = sorted(resultats, key=lambda r: (r['hote'].get('role') or '', r['hote'].get('name') or ''))
    classeur = Workbook()

    # 1. Une ligne par application détectée : la liste à rapprocher du registre.
    feuille = classeur.active
    feuille.title = 'Applications'
    metier = [r for r in resultats if r['collecte'] == 'OK']
    lignes = [identite(r['hote']) + [registre(r['hote']), e['categorie'], e['source'], e['nom'], e['etat'],
                                     jour(e.get('date')), e.get('nature_date', ''), e['detail']]
              for r in metier for e in r['elements'] if e['categorie'] not in ('Agent', 'Site web')]
    tableau(feuille, ['Serveur', 'Adresse IP', 'Rôle', 'Environnement', 'Description au registre',
                      'Catégorie', 'Source', 'Application / composant', 'État', 'Date',
                      'Nature de la date', 'Détail'], lignes)

    # Sites web à part : un répartiteur ou un WAF en déclare des centaines.
    feuille = classeur.create_sheet('Sites web')
    lignes = [identite(r['hote']) + [e['source'], e['nom'], jour(e.get('date')), e['detail']]
              for r in metier for e in r['elements'] if e['categorie'] == 'Site web']
    tableau(feuille, ['Serveur', 'Adresse IP', 'Rôle', 'Environnement', 'Serveur web', 'Nom de site',
                      'Configuration modifiée le', 'Fichier de configuration'], lignes, largeur_max=70)

    # 2. Une ligne par serveur : synthèse et couverture de la collecte.
    feuille = classeur.create_sheet('Par serveur')
    lignes = []
    for r in resultats:
        elements = [e for e in r.get('elements', []) if e['categorie'] != 'Agent']
        principaux = sorted({e['nom'] for e in elements if e['categorie'] not in ('Site web',)})
        sites = sorted({e['nom'] for e in elements if e['categorie'] == 'Site web'})
        lignes.append(identite(r['hote']) + [
            r['hote'].get('vmid') or '', registre(r['hote']), r['collecte'], r.get('os', ''),
            datetime.fromtimestamp(r['installation']).strftime('%d/%m/%Y') if r.get('installation') else '',
            r.get('installation_source', ''),
            len(elements) - len(sites) if r['collecte'] == 'OK' else None, ', '.join(principaux)[:1000],
            len(sites) if r['collecte'] == 'OK' else None, r.get('docker', ''), ', '.join(r.get('ports', []))[:500],
            ', '.join(r.get('dossiers', []))[:500], r.get('noyau', ''),
            ', '.join(f"{q['nom']} {q['version']}" for q in r.get('paquets') or [])[:1500], r['erreur']])
    tableau(feuille, ['Serveur', 'Adresse IP', 'Rôle', 'Environnement', 'VMID', 'Description au registre',
                      'Collecte', 'Système', 'Installation du système', 'Source de la date', 'Nb applications', 'Services et applications détectés',
                      'Nb sites web', 'Docker', 'Ports TCP en écoute', 'Dossiers /opt /srv /var/www',
                      'Noyau', 'Paquets clés', 'Erreur de collecte'], lignes, largeur_max=60)

    # 3. Agents de supervision et de sauvegarde : utile pour vérifier la couverture.
    feuille = classeur.create_sheet('Agents')
    lignes = [identite(r['hote']) + [e['nom'], e['etat']]
              for r in metier for e in r['elements'] if e['categorie'] == 'Agent']
    tableau(feuille, ['Serveur', 'Adresse IP', 'Rôle', 'Environnement', 'Agent', 'État'], lignes)

    # 4. Ce que ce fichier affirme, et ce qu'il n'affirme pas.
    feuille = classeur.create_sheet('Lisez-moi')
    ok = len(metier)
    notes = [
        f"Recensement OpsControl — {datetime.now(timezone.utc).astimezone().strftime('%d/%m/%Y %H:%M')}",
        f"{ok} serveur(s) relevé(s) sur {len(resultats)} ; les autres figurent dans « Par serveur » avec la cause.",
        '',
        "Relevé en lecture seule par SSH, sans sudo : services systemd, conteneurs Docker, services Swarm",
        "(nœuds managers), sites Apache/Nginx déclarés, applications Tomcat, processus Java/Node/Python/PHP,",
        "ports TCP en écoute et dossiers /opt, /srv, /var/www.",
        '',
        "Limites :",
        "- Sans root, le processus derrière un port n'est pas nommé, et Docker peut être refusé",
        "  (colonne « Docker » = « Accès refusé ») : cela ne prouve pas l'absence de conteneurs.",
        "- « Service spécifique (à qualifier) » = service ni système ni produit connu : souvent",
        "  l'application métier elle-même, à confirmer avec son responsable.",
        "- Les lignes de commande complètes ne sont jamais relevées (elles peuvent contenir des secrets).",
        "- « Description au registre » provient de l'inventaire importé du registre : comparer les deux",
        "  colonnes permet de repérer les écarts (application absente du registre ou introuvable).",
        "- Un serveur injoignable n'a pas été relevé : ses applications restent à recenser.",
        "- « Installation du système » : date d'installation de l'OS dans la VM. Elle ne change pas lors",
        "  d'une migration ou d'une restauration ; pour une VM clonée d'un modèle, c'est la date du modèle.",
        "- « Date » d'une application : sa nature est précisée colonne suivante. Service = installation ou",
        "  dernière mise à jour du paquet ; .war/.jar/script = dernier déploiement ; conteneur = création ;",
        "  site web = dernière modification de sa configuration. Une mise à jour rajeunit la date :",
        "  c'est une date « au plus tard depuis », pas toujours la première mise en service.",
    ]
    for decalage, texte in enumerate(notes, 1):
        cellule = feuille.cell(row=decalage, column=1, value=texte)
        cellule.font = Font(name=police, size=10, bold=decalage == 1)
    feuille.column_dimensions['A'].width = 110
    classeur.save(chemin)


def main():
    analyseur = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    analyseur.add_argument('sortie', nargs='?', default='inventaire-applications.xlsx')
    analyseur.add_argument('--serveur', nargs='*', help='Limiter à ces serveurs (nom ou clé)')
    args = analyseur.parse_args()

    from config import load_config
    cfg, hotes = load_config()
    if args.serveur:
        voulus = {s.lower() for s in args.serveur}
        hotes = [h for h in hotes if {str(h.get('key')).lower(), str(h.get('name')).lower()} & voulus]
    connus = comptes_connus()
    # Le plafond global de sessions de ssh.run_operation borne déjà le parallélisme réel.
    with ThreadPoolExecutor(max_workers=12) as pool:
        resultats = list(pool.map(lambda h: relever(h, cfg, connus.get(h.get('key'))), hotes))
    chemin = Path(args.sortie)
    ecrire(chemin, resultats)
    memoriser_releve(resultats)
    ok = sum(r['collecte'] == 'OK' for r in resultats)
    elements = sum(len(r.get('elements', [])) for r in resultats)
    print(f'{ok}/{len(resultats)} serveur(s) relevé(s), {elements} élément(s) détecté(s) -> {chemin.resolve()}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
