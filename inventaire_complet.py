"""Inventaire complet de l'infrastructure : corrélation de toutes les sources OpsControl.

Produit `inventaire_brut.json`, qui alimente ensuite le classeur Excel, les rapports
et la matrice de dépendances (inventaire_complet_rendu.py).

Aucune connexion au parc ici : tout vient
  - du relevé Proxmox en GET (inventaire_proxmox.py, lancé avant) ;
  - de la base OpsControl en lecture seule : audit SSH, paquets, CVE, réseau ;
  - des derniers résultats des connexions API d'OpsControl : Zabbix, Wazuh, Bacula ;
  - de l'inventaire déclaré (hosts.yaml) et des annotations manuelles (annotations.csv).

Règles de corrélation (pourquoi) :
  - une VM est identifiée par cluster + VMID, seule clé stable ; le nom Proxmox sert
    à vérifier, jamais à fusionner seul ;
  - l'inventaire déclaré n'est rattaché que si VMID ET nom court concordent ;
  - Zabbix, Wazuh et Bacula sont rattachés par nom d'hôte exact. Une IP seule donne
    un rattachement « DÉDUIT », car une IP peut avoir été réutilisée.

Niveaux de confiance : CONFIRMÉ (source technique), DÉCLARÉ (documentation),
DÉDUIT (inférence à valider), INCONNU.

Usage :
    python inventaire_complet.py --proxmox data/inventaire/proxmox-live-AAAA-MM-JJ.json
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import date, datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
SORTIES = BASE / 'data' / 'inventaire'

CONFIRME, DECLARE, DEDUIT, INCONNU = 'CONFIRMÉ', 'DÉCLARÉ', 'DÉDUIT', 'INCONNU'
A_COMPLETER = 'À compléter'
GIB = 1024 ** 3

# Fin de support des systèmes et des technologies. Calendriers éditeurs (référence
# endoflife.date), non revérifiés en ligne pendant la collecte : niveau DÉCLARÉ.
# (date de fin de support standard, date de fin de support étendu ou LTS)
FIN_OS = {
    ('debian', '9'): ('2020-07-06', '2022-06-30'), ('debian', '10'): ('2022-09-10', '2024-06-30'),
    ('debian', '11'): ('2024-08-14', '2026-08-31'), ('debian', '12'): ('2026-06-10', '2028-06-30'),
    ('debian', '13'): ('2028-08-09', '2030-06-30'),
    ('centos', '7'): ('2024-06-30', '2024-06-30'), ('centos', '8'): ('2021-12-31', '2021-12-31'),
    ('rhel', '7'): ('2024-06-30', '2028-06-30'), ('rhel', '8'): ('2029-05-31', '2032-05-31'),
    ('rocky', '8'): ('2029-05-31', '2029-05-31'), ('rocky', '9'): ('2032-05-31', '2032-05-31'),
    ('almalinux', '8'): ('2029-05-31', '2029-05-31'), ('almalinux', '9'): ('2032-05-31', '2032-05-31'),
    ('ubuntu', '16.04'): ('2021-04-30', '2026-04-30'), ('ubuntu', '18.04'): ('2023-05-31', '2028-05-31'),
    ('ubuntu', '20.04'): ('2025-05-31', '2030-05-31'), ('ubuntu', '22.04'): ('2027-06-01', '2032-04-30'),
    ('ubuntu', '24.04'): ('2029-05-31', '2034-04-30'),
}
# Ubuntu : le support étendu exige un abonnement ESM, non vérifiable ici.
SANS_EXTENSION_GRATUITE = {'ubuntu', 'rhel'}

FIN_TECH = {
    'PHP': {'5': '2018-12-31', '7.0': '2019-01-10', '7.1': '2019-12-01', '7.2': '2020-11-30',
            '7.3': '2021-12-06', '7.4': '2022-11-28', '8.0': '2023-11-26', '8.1': '2025-12-31',
            '8.2': '2026-12-31', '8.3': '2027-12-31', '8.4': '2028-12-31'},
    'PostgreSQL': {'9.4': '2020-02-13', '9.5': '2021-02-11', '9.6': '2021-11-11', '10': '2022-11-10',
                   '11': '2023-11-09', '12': '2024-11-21', '13': '2025-11-13', '14': '2026-11-12',
                   '15': '2027-11-11', '16': '2028-11-09', '17': '2029-11-08'},
    'Python': {'2.7': '2020-01-01', '3.5': '2020-09-30', '3.6': '2021-12-23', '3.7': '2023-06-27',
               '3.8': '2024-10-07', '3.9': '2025-10-31', '3.10': '2026-10-31', '3.11': '2027-10-31',
               '3.12': '2028-10-31', '3.13': '2029-10-31'},
    'Node.js': {'12': '2022-04-30', '14': '2023-04-30', '16': '2023-09-11', '18': '2025-04-30',
                '20': '2026-04-30', '22': '2027-04-30'},
    'MariaDB': {'10.1': '2020-10-17', '10.3': '2023-05-25', '10.4': '2024-06-18', '10.5': '2025-06-24',
                '10.6': '2026-07-06', '10.11': '2028-02-16', '11.4': '2029-05-29'},
    'MySQL': {'5.6': '2021-02-28', '5.7': '2023-10-31', '8.0': '2026-04-30', '8.4': '2032-04-30'},
    'Tomcat': {'7': '2021-03-31', '8': '2018-06-30', '8.5': '2024-03-31', '9': A_COMPLETER, '10': A_COMPLETER},
    'Proxmox VE': {'7': '2024-07-31', '8': '2026-08-31', '9': A_COMPLETER},
}

# Technologies reconnues par le nom EXACT d'un paquet (pas de bibliothèque libxxx).
TECHNOLOGIES = [(nom, famille, re.compile(motif)) for nom, famille, motif in (
    # « php-common » (Debian) porte la version de l'empaquetage dh-php (« 2:93 »), pas celle de PHP.
    ('PHP', 'Langage', r'^php\d+(\.\d+)?(-(cli|fpm|common))?$|^php(-cli|-fpm)?$|^php\d\d-php-(cli|common|fpm)$'),
    ('Java (OpenJDK)', 'Langage', r'^(openjdk-\d+-(jre|jdk)(-headless)?|java-[\d.]+-openjdk(-headless)?|'
                                  r'temurin-\d+-(jdk|jre)|jdk-\d+|jre\d*)$'),
    ('Python', 'Langage', r'^python3\.\d+$|^python3$|^python3\d+$|^python2\.7$'),
    ('Node.js', 'Langage', r'^nodejs$'),
    ('Apache HTTP Server', 'Serveur web', r'^(apache2|httpd)$'),
    ('Nginx', 'Serveur web', r'^nginx(-core|-full|-light)?$'),
    ('Tomcat', "Serveur d'applications", r'^tomcat\d*$'),
    ('PostgreSQL', 'Base de données', r'^postgresql(\d+)?(-\d+(\.\d+)?)?(-server)?$'),
    ('MariaDB', 'Base de données', r'^(mariadb-server(-[\d.]+)?|MariaDB-server)$'),
    ('MySQL', 'Base de données', r'^mysql-(community-)?server(-[\d.]+)?$'),
    ('Redis', 'Base de données', r'^redis(-server)?$'),
    ('MongoDB', 'Base de données', r'^mongodb-(org-)?server$'),
    ('Docker Engine', 'Conteneurs', r'^(docker-ce|docker\.io|docker-engine)$'),
    ('Elasticsearch', 'Journaux / recherche', r'^elasticsearch$'),
    ('Kibana', 'Journaux / recherche', r'^kibana$'),
    ('Logstash', 'Journaux / recherche', r'^logstash$'),
    ('Elastic Agent', 'Agent', r'^elastic-agent$'),
    ('Filebeat', 'Agent', r'^filebeat$'),
    ('Zabbix Agent', 'Agent', r'^zabbix-agent2?$'),
    ('Zabbix Server', 'Supervision', r'^zabbix-server-(pgsql|mysql)$'),
    ('Wazuh Agent', 'Agent', r'^wazuh-agent$'),
    ('Wazuh Manager', 'Sécurité', r'^wazuh-manager$'),
    ('Bacula File Daemon', 'Agent', r'^bacula-(fd|client)$'),
    ('Bacula Director', 'Sauvegarde', r'^bacula-(director(-pgsql|-mysql)?|dir)$'),
    ('Grafana', 'Supervision', r'^grafana(-enterprise)?$'),
    ('GitLab', 'Outillage', r'^gitlab-(ce|ee)$'),
    ('Keepalived', 'Réseau', r'^keepalived$'),
    ('HAProxy', 'Réseau', r'^haproxy$'),
    ('ModSecurity', 'Sécurité', r'^(libapache2-mod-security2|mod_security)$'),
    ('Fail2ban', 'Sécurité', r'^fail2ban$'),
    ('OpenSSL', 'Socle', r'^openssl$'),
    ('OpenSSH Server', 'Socle', r'^openssh-server$'),
    ('Samba', 'Partage', r'^samba$'),
    ('NFS Server', 'Partage', r'^nfs-kernel-server$'),
    ('BIND', 'Réseau', r'^bind9?$'),
    ('RabbitMQ', 'Messagerie', r'^rabbitmq-server$'),
    ('Memcached', 'Base de données', r'^memcached$'),
    ('Squid', 'Réseau', r'^squid$'),
    ('OpenVPN', 'Réseau', r'^openvpn$'),
    ('Ansible', 'Outillage', r'^ansible(-core)?$'),
    ('Ceph', 'Stockage', r'^ceph-common$'),
)]
# Service systemd qui prouve l'usage d'une technologie (et pas seulement sa présence).
SERVICES_TECH = {
    'PHP': r'^php.*fpm', 'Apache HTTP Server': r'^(apache2|httpd)$', 'Nginx': r'^nginx$',
    'Tomcat': r'^tomcat', 'PostgreSQL': r'^postgresql', 'MariaDB': r'^(mariadb|mysql|mysqld)$',
    'MySQL': r'^(mysql|mysqld)$', 'Redis': r'^redis', 'MongoDB': r'^mongod$',
    'Docker Engine': r'^docker$', 'Elasticsearch': r'^elasticsearch$', 'Kibana': r'^kibana$',
    'Logstash': r'^logstash$', 'Elastic Agent': r'^elastic-agent$', 'Filebeat': r'^filebeat$',
    'Zabbix Agent': r'^zabbix-agent2?$', 'Zabbix Server': r'^zabbix-server$',
    'Wazuh Agent': r'^wazuh-agent$', 'Wazuh Manager': r'^wazuh-manager$',
    'Bacula File Daemon': r'^bacula-fd$', 'Bacula Director': r'^bacula-dir', 'Grafana': r'^grafana',
    'GitLab': r'^gitlab-runsvdir$', 'Keepalived': r'^keepalived$', 'HAProxy': r'^haproxy$',
    'Fail2ban': r'^fail2ban$', 'OpenSSH Server': r'^(ssh|sshd)$', 'Samba': r'^smbd$',
    'NFS Server': r'^nfs-(server|kernel-server)$', 'BIND': r'^(named|bind9)$',
    'RabbitMQ': r'^rabbitmq-server$', 'Memcached': r'^memcached$', 'Squid': r'^squid$',
    'OpenVPN': r'^openvpn', 'Java (OpenJDK)': r'^tomcat',
}
# Processus relevés par l'audit (sans root) qui prouvent l'usage d'un langage.
PROCESSUS_TECH = {'Java': 'Java (OpenJDK)', 'Python': 'Python', 'Node.js': 'Node.js'}

PORTS_CONNUS = {
    '21': 'FTP', '22': 'SSH', '25': 'SMTP', '53': 'DNS', '80': 'HTTP', '111': 'rpcbind (NFS)',
    '123': 'NTP', '139': 'SMB', '161': 'SNMP', '389': 'LDAP', '443': 'HTTPS', '445': 'SMB',
    '636': 'LDAPS', '1194': 'OpenVPN', '1514': 'Wazuh (agents)', '1515': 'Wazuh (enrôlement)',
    '2049': 'NFS', '2377': 'Docker Swarm (gestion)', '3000': 'Grafana ?', '3128': 'Squid',
    '3306': 'MySQL / MariaDB', '3300': 'SSH (port alternatif) / Ceph mon', '5044': 'Logstash Beats',
    '5432': 'PostgreSQL', '5433': 'PostgreSQL (2e instance)', '5601': 'Kibana', '5672': 'RabbitMQ',
    '6379': 'Redis', '7946': 'Docker Swarm (gossip)', '8006': 'Proxmox VE', '8009': 'Tomcat AJP',
    '8080': 'HTTP alternatif / Tomcat', '8443': 'HTTPS alternatif', '9090': 'Prometheus / Cockpit ?',
    '9100': 'node_exporter', '9101': 'Bacula Director', '9102': 'Bacula FD', '9103': 'Bacula SD',
    '9200': 'Elasticsearch HTTP', '9300': 'Elasticsearch transport', '10050': 'Zabbix agent',
    '10051': 'Zabbix server', '11211': 'Memcached', '27017': 'MongoDB', '55000': 'Wazuh API',
}
LIBELLES_STOCKAGE = {'ceph-remote': 'Ceph distant', 'myceph': 'Ceph local', 'nfs-primary': 'NFS (prdlabpve06)',
                     'local': 'Disque local du nœud', 'zfs-primary': 'ZFS local prdlabpve06', 'pbs-primary': 'Proxmox Backup Server'}
# Supports qui ne sont que le socle physique d'un autre (cf. export_proxmox_stockage.SOCLES).
SOCLES = {'zfs-primary': 'nfs-primary'}


# ---------------------------------------------------------------- utilitaires

def court(nom) -> str:
    return str(nom or '').strip().lower().split('.', 1)[0]


def gib(octets) -> float | None:
    return round(octets / GIB, 1) if isinstance(octets, (int, float)) else None


def jour(horodatage: str | None) -> str:
    return str(horodatage or '')[:10]


def maintenant() -> datetime:
    return datetime.now(timezone.utc)


def version_majeure(tech: str, version: str) -> str:
    """'8.2.7-1+deb12u3' -> '8.2' pour PHP ; '15.8-1.pgdg' -> '15' pour PostgreSQL ≥ 10."""
    brute = re.sub(r'^\d+:', '', str(version or ''))
    nombres = re.findall(r'\d+', brute)
    if not nombres:
        return ''
    if tech == 'PostgreSQL' and int(nombres[0]) >= 10:
        return nombres[0]
    if tech in ('Node.js', 'Proxmox VE') or len(nombres) < 2:
        return nombres[0]
    if tech == 'Tomcat' and nombres[0] != '8':
        return nombres[0]
    return f'{nombres[0]}.{nombres[1]}'


def fin_support_tech(tech: str, version: str, aujourdhui: date) -> tuple[str, str]:
    """(statut, date de fin) d'une technologie, ou ('', '') si non suivie."""
    table = FIN_TECH.get(tech)
    if not table:
        return '', ''
    majeure = version_majeure(tech, version)
    fin = table.get(majeure) or table.get(majeure.split('.', 1)[0], '')
    if not fin or fin == A_COMPLETER:
        return ('Supportée (fin non publiée)' if fin == A_COMPLETER else 'Non référencée'), fin or ''
    restant = (date.fromisoformat(fin) - aujourdhui).days
    if restant < 0:
        return 'Fin de vie', fin
    return ('Fin de vie < 6 mois' if restant < 183 else 'Supportée'), fin


def support_os(os_id: str, version_id: str, aujourdhui: date) -> dict:
    os_id = (os_id or '').lower()
    cle = (os_id, version_id if os_id == 'ubuntu' else str(version_id or '').split('.', 1)[0])
    if cle not in FIN_OS:
        return {'statut': 'Non référencé', 'fin_standard': '', 'fin_etendue': '', 'confiance': INCONNU}
    standard, etendue = FIN_OS[cle]
    if aujourdhui <= date.fromisoformat(standard):
        statut = 'Supporté'
    elif aujourdhui <= date.fromisoformat(etendue) and os_id not in SANS_EXTENSION_GRATUITE:
        statut = 'Support étendu (LTS) seulement'
    elif aujourdhui <= date.fromisoformat(etendue):
        statut = 'Fin du support standard (ESM payant requis)'
    else:
        statut = 'Fin de vie'
    return {'statut': statut, 'fin_standard': standard, 'fin_etendue': etendue, 'confiance': DECLARE}


def os_depuis_texte(texte: str) -> tuple[str, str]:
    """('debian', '12') depuis « Debian GNU/Linux 12 (bookworm) » (relevé SSH sans os-release)."""
    t = (texte or '').lower()
    for os_id, motif in (('debian', r'debian.*?(\d+)'), ('centos', r'centos.*?(\d+)'),
                         ('ubuntu', r'ubuntu\s+(\d+\.\d+)'), ('rocky', r'rocky.*?(\d+)'),
                         ('almalinux', r'alma.*?(\d+)'), ('rhel', r'red hat.*?(\d+)')):
        m = re.search(motif, t)
        if m:
            return os_id, m.group(1)
    return '', ''


# ---------------------------------------------------------------- chargement

def lire_json(chemin: Path, defaut=None):
    try:
        return json.loads(Path(chemin).read_text(encoding='utf-8-sig'))
    except (OSError, ValueError):
        return defaut


def connexions_api(chemin: Path) -> dict:
    """{fournisseur: dernier résultat} des connexions API d'OpsControl (secrets jamais lus)."""
    resultat = {}
    for c in lire_json(chemin, []) or []:
        lr = c.get('last_result') or {}
        statut = lr.get('status')
        # Collecte courante en échec (VPN coupé…) : OpsControl garde le dernier succès à part.
        if statut != 'observed' and (c.get('last_success_result') or {}).get('status') == 'observed':
            lr = c['last_success_result']
            statut = f"observed (dernier succès ; collecte suivante en échec : {(c.get('last_result') or {}).get('error_kind') or 'erreur'})"
        resultat[c.get('provider')] = {'nom': c.get('name'), 'url': c.get('url'), 'statut': statut,
                                       'collecte_le': lr.get('collected_at'), 'inventaire': lr.get('inventory') or {}}
    return resultat


def base_ro(chemin: Path) -> sqlite3.Connection:
    return sqlite3.connect(Path(chemin).resolve().as_uri() + '?mode=ro', uri=True)


def charger_base(chemin: Path) -> dict:
    """États SSH, paquets, CVE ouvertes, réseau et découverte (lecture seule)."""
    from export_enregistrements_waf import observation

    db = base_ro(chemin)
    try:
        etats_bruts = {k: json.loads(p) for k, p in db.execute('SELECT key, payload FROM states')}
        paquets = {k: {**json.loads(p), 'collecte_le': at, 'complet': bool(c)}
                   for k, at, c, p in db.execute('SELECT host_key, collected_at, complete, payload FROM sec_inventory')}
        reseau = {k: json.loads(p) for k, p in db.execute('SELECT key, payload FROM network')}
        cron = {k: json.loads(p) for k, p in db.execute('SELECT key, payload FROM batch_states')}
        vulns = defaultdict(Counter)
        for hote, gravite, kev, nombre in db.execute(
                "SELECT s.host_key, COALESCE(c.severity, 'non notée'), COALESCE(c.kev, 0), COUNT(*) "
                "FROM sec_vulns s LEFT JOIN sec_cve c ON c.cve = s.cve WHERE s.status = 'open' "
                "GROUP BY 1, 2, 3"):
            vulns[hote][gravite] += nombre
            if kev:
                vulns[hote]['kev'] += nombre
        decouverte = [dict(zip(('ip', 'ports', 'ttl', 'banniere', 'dns', 'type', 'os', 'ping'), r))
                      for r in db.execute('SELECT ip, ports, ttl, banner, dns, type, os, ping FROM discovery_hosts')]
        scans = db.execute('SELECT range, at, status FROM discovery_scans ORDER BY at DESC').fetchall()
    finally:
        db.close()
    etats = {k: observation(v) for k, v in etats_bruts.items()}
    return {'etats': etats, 'etats_bruts': etats_bruts, 'paquets': paquets, 'reseau': reseau, 'cron': cron,
            'vulns': {k: dict(v) for k, v in vulns.items()}, 'decouverte': decouverte, 'scans': scans}


def charger_annotations(chemin: Path) -> dict:
    """Annotations manuelles (équipe, responsable, criticité…) : jamais écrasées par la collecte."""
    if not chemin.exists():
        return {}
    with chemin.open(encoding='utf-8-sig', newline='') as f:
        return {r['cle']: {k: v.strip() for k, v in r.items() if k != 'cle' and v and v.strip()}
                for r in csv.DictReader(f, delimiter=';') if r.get('cle')}


COLONNES_ANNOTATIONS = ['cle', 'nom', 'environnement', 'criticite', 'fonction', 'equipe',
                        'responsable_applicatif', 'site', 'notes']


def completer_modele_annotations(chemin: Path, vms: list[dict], existantes: dict) -> int:
    """Ajoute au modèle les VM nouvelles, sans toucher aux lignes déjà saisies."""
    nouvelles = [v for v in vms if v['cle'] not in existantes]
    if not nouvelles and chemin.exists():
        return 0
    lignes = [{'cle': c, **a} for c, a in existantes.items()]
    lignes += [{'cle': v['cle'], 'nom': v['nom_court']} for v in nouvelles]
    chemin.parent.mkdir(parents=True, exist_ok=True)
    with chemin.open('w', encoding='utf-8-sig', newline='') as f:
        w = csv.DictWriter(f, fieldnames=COLONNES_ANNOTATIONS, delimiter=';', extrasaction='ignore')
        w.writeheader()
        w.writerows(sorted(lignes, key=lambda r: r['cle']))
    return len(nouvelles)


# ---------------------------------------------------------------- index externes

class Index:
    """Rattachement par nom court exact, puis par IP (DÉDUIT)."""

    def __init__(self, elements, noms, ips):
        self.par_nom, self.par_ip = defaultdict(list), defaultdict(list)
        for e in elements:
            for n in noms(e):
                if court(n):
                    self.par_nom[court(n)].append(e)
            for ip in ips(e):
                if ip and ip != '127.0.0.1':
                    self.par_ip[ip].append(e)

    def trouver(self, nom: str, ip: str | None) -> tuple[dict | None, str, str]:
        par_nom = self.par_nom.get(court(nom)) or []
        if par_nom:
            e = par_nom[0]
            return e, CONFIRME, 'Nom d’hôte identique'
        par_ip = self.par_ip.get(ip or '') or []
        if len(par_ip) == 1:
            return par_ip[0], DEDUIT, 'Même IP, nom différent : à confirmer (IP réutilisable)'
        return None, INCONNU, ''


def index_zabbix(api):
    hotes = (api.get('Zabbix') or {}).get('inventaire', {}).get('hosts') or []
    return Index(hotes, lambda h: [h.get('host'), h.get('name')], lambda h: set(h.get('addresses') or []))


def index_wazuh(api):
    agents = (api.get('Wazuh') or {}).get('inventaire', {}).get('agents_inventory') or []
    return Index(agents, lambda a: [a.get('name')], lambda a: [a.get('ip')])


def bacula_par_client(api) -> dict:
    """{nom court du client: [derniers jobs]} ; un client Bacula est « <fqdn>-fd »."""
    jobs = defaultdict(list)
    for j in (api.get('Bacula') or {}).get('inventaire', {}).get('latest') or []:
        jobs[court(re.sub(r'-fd$', '', str(j.get('client') or '')))].append(j)
    return jobs


def etat_sauvegarde(jobs: list[dict]) -> str:
    """État Bacula d'un client à partir de ses derniers jobs.

    Un job « En cours » ou « Créé, pas encore lancé » n'a pas encore de résultat :
    un relevé pris pendant la fenêtre de sauvegarde ne doit pas le compter en
    erreur. Seuls les jobs terminés décident de l'état.
    """
    if not jobs:
        return 'Aucun job Bacula identifié'
    termines = [j for j in jobs if j.get('severity') not in ('running', 'pending')]
    if not termines:
        return f"Job en cours au relevé ({min(j.get('name') or '' for j in jobs)})"
    pire = min(termines, key=lambda j: {'critical': 0, 'warning': 1}.get(j.get('severity'), 2))
    return 'OK' if all(j.get('severity') == 'ok' for j in termines) else f"Dernier job en erreur ({pire.get('name')})"


def historique_bacula(api) -> dict:
    """{nom du job: [dates de fin]} sur l'historique visible (500 derniers jobs)."""
    dates = defaultdict(list)
    for j in (api.get('Bacula') or {}).get('inventaire', {}).get('jobs') or []:
        if j.get('endtime'):
            dates[j.get('name')].append(j['endtime'])
    return dates


# ---------------------------------------------------------------- technologies

def services_actifs(obs: dict) -> set[str]:
    return {re.sub(r'\.service$', '', str(s.get('name'))) for s in obs.get('all_services') or []
            if s.get('status') == 'active'}


def technologies_hote(cle: str, obs: dict, paquets: dict | None) -> list[dict]:
    """Technologies installées sur un hôte, avec la preuve de leur usage réel.

    Installé ≠ utilisé : PHP présent sans php-fpm actif ni module chargé reste
    « installé, usage non vérifié ». La preuve d'usage vient d'un service actif
    ou d'un processus relevé par l'audit.
    """
    apps = obs.get('applications') or {}
    liste, source, date_releve = [], '', ''
    if paquets and paquets.get('packages'):
        liste = [(p.get('name'), p.get('version')) for p in paquets['packages']]
        source, date_releve = f"Paquets ({paquets.get('manager')})", paquets.get('collecte_le')
    elif isinstance(apps.get('paquets'), list):
        liste = [(p.get('nom'), p.get('version')) for p in apps['paquets']]
        source, date_releve = 'Paquets clés (audit SSH)', apps.get('collected_at')
    actifs = services_actifs(obs)
    processus = {e.get('source') for e in apps.get('elements') or [] if e.get('categorie') == 'Processus applicatif'}
    trouvees = {}
    for nom_paquet, version in liste:
        for tech, famille, motif in TECHNOLOGIES:
            if motif.match(str(nom_paquet or '')):
                # Plusieurs paquets d'une même techno (php8.2-cli, php8.2-fpm) : une ligne par version.
                cle_t = (tech, version_majeure(tech, version) or version)
                trouvees.setdefault(cle_t, {'tech': tech, 'famille': famille, 'paquets': [], 'version': version})
                trouvees[cle_t]['paquets'].append(nom_paquet)
    resultat = []
    for (tech, _), t in sorted(trouvees.items()):
        motif = SERVICES_TECH.get(tech)
        service = sorted(s for s in actifs if motif and re.search(motif, s))
        process = next((p for p, tc in PROCESSUS_TECH.items() if tc == tech and p in processus), '')
        if service:
            usage, preuve = 'Utilisé', f"Service actif : {', '.join(service[:4])}"
        elif process:
            usage, preuve = 'Utilisé', f'Processus {process} relevé par l’audit'
        elif tech in ('OpenSSL', 'Python') and not process:
            usage, preuve = 'Installé (socle système)', 'Dépendance du système : usage applicatif non vérifié'
        else:
            usage, preuve = 'Installé, usage non vérifié', 'Paquet présent, aucun service ni processus associé relevé'
        resultat.append({'hote': cle, 'technologie': tech, 'famille': t['famille'], 'version': t['version'],
                         'version_majeure': version_majeure(tech, t['version']),
                         'paquets': ', '.join(sorted(set(t['paquets']))), 'usage': usage, 'preuve_usage': preuve,
                         'source': source, 'collecte_le': date_releve, 'confiance': CONFIRME})
    return resultat


# ---------------------------------------------------------------- construction

def construire(proxmox: dict, hotes: list[dict], base: dict, api: dict, annotations: dict,
               aujourdhui: date | None = None) -> dict:
    import published_sites as ps
    from export_inventaire_vm import construire as construire_vm, par_application

    aujourdhui = aujourdhui or maintenant().date()
    etats, paquets = base['etats'], base['paquets']
    cluster_nom = next((c.get('name') for c in proxmox.get('cluster') or [] if c.get('type') == 'cluster'), 'Cluster')
    ip_noeuds = {c.get('name'): c.get('ip') for c in proxmox.get('cluster') or [] if c.get('type') == 'node'}
    incoherences, couverture = [], []

    # Inventaire déclaré : par VMID (clé stable) ; le nom court doit concorder.
    declares_vmid = defaultdict(list)
    for h in hotes:
        if h.get('vmid') not in (None, ''):
            declares_vmid[int(h['vmid'])].append(h)
    rattaches = set()

    zbx, wz, bac = index_zabbix(api), index_wazuh(api), bacula_par_client(api)
    hist_bac = historique_bacula(api)
    actifs_ps = [{**h, 'applications': (etats.get(h['key']) or {}).get('applications')} for h in hotes]
    vms_ssh, details_apps, _ = construire_vm(hotes, etats, {k: (r.get('ping'), r.get('collected_at'))
                                                            for k, r in base['reseau'].items()})
    par_identite = {(str(v['serveur']), v['ip']): v for v in vms_ssh}
    ligne_ssh = {h['key']: par_identite.get((str(h.get('name') or h['key']), h.get('ip'))) for h in hotes}

    vms, disques, cartes, technos = [], [], [], []
    for inv in sorted(proxmox.get('invites') or [], key=lambda i: int(i['vmid'])):
        vmid, nom = int(inv['vmid']), inv.get('nom') or ''
        cle = f'{cluster_nom}/{vmid}'
        decl = None
        for h in declares_vmid.get(vmid, []):
            if court(h.get('name')) == court(nom) or court(h.get('fqdn')) == court(nom):
                decl = h
            else:
                incoherences.append({'objet': cle, 'type': 'Nom différent',
                                     'detail': f"VMID {vmid} : Proxmox « {nom} », inventaire déclaré « {h.get('name')} »",
                                     'sources': 'Proxmox / hosts.yaml', 'action': 'Corriger hosts.yaml ou le nom de la VM'})
        if decl:
            rattaches.add(decl['key'])
            if decl.get('node') and decl['node'] != inv['noeud']:
                incoherences.append({'objet': cle, 'type': 'Nœud différent',
                                     'detail': f"Déclaré sur {decl['node']}, hébergée sur {inv['noeud']} (migration ?)",
                                     'sources': 'Proxmox / hosts.yaml', 'action': 'Mettre à jour hosts.yaml'})
        obs = etats.get(decl['key']) if decl else None
        obs = obs or {}
        brut = base['etats_bruts'].get(decl['key']) if decl else None
        pq = paquets.get(decl['key']) if decl else None
        apps = obs.get('applications') or {}
        cfg = inv.get('config') or {}
        ann = annotations.get(cle, {})

        # Système : os-release (paquets) > audit SSH ; jamais déduit de « ostype » Proxmox seul.
        if pq and pq.get('os'):
            os_id, os_ver, os_nom = pq['os'].get('id'), str(pq['os'].get('version_id') or ''), pq['os'].get('pretty')
            os_src = 'os-release (relevé sécurité)'
        elif obs.get('os') or apps.get('os'):
            os_nom = obs.get('os') or apps.get('os')
            os_id, os_ver = os_depuis_texte(os_nom)
            os_src = 'Audit SSH'
        else:
            os_id = os_ver = ''
            os_nom = {'l26': 'Linux (type Proxmox, version inconnue)', 'win10': 'Windows 10/2016/2019 (type Proxmox)',
                      'win11': 'Windows 11/2022/2025 (type Proxmox)', 'other': 'Autre (type Proxmox)'}.get(
                cfg.get('ostype'), A_COMPLETER)
            os_src = 'Type déclaré dans Proxmox (ostype)' if cfg.get('ostype') else ''
        support = support_os(os_id, os_ver, aujourdhui) if os_id else {
            'statut': A_COMPLETER, 'fin_standard': '', 'fin_etendue': '', 'confiance': INCONNU}

        ip_decl = (decl or {}).get('ip') or ''
        ssh_ok = bool(brut and any(a.get('ok') for a in brut.get('attempts') or []))
        mesure = bool(apps.get('status') == 'observed' or obs.get('os'))
        ip_conf = CONFIRME if ssh_ok else (DECLARE if ip_decl else INCONNU)
        zh, zc, zp = zbx.trouver(nom, ip_decl)
        wa, wc, wp = wz.trouver(nom, ip_decl)
        jobs = bac.get(court(nom)) or []
        sauvegarde = etat_sauvegarde(jobs)
        cartes_vm = inv.get('cartes') or []
        liste_disques = [d for d in inv.get('disques') or []]
        taille = sum(d.get('taille') or 0 for d in liste_disques if not d.get('detache'))
        stockages_vm = sorted({d['stockage'] for d in liste_disques})
        fs = [f for f in ((obs.get('storage') or {}).get('filesystems') or [])
              if not str(f.get('mount', '')).startswith(('/run', '/dev', '/sys', '/snap'))]
        occupe = sum(f.get('used_kb') or 0 for f in fs if not re.match(r'^(nfs|cifs|fuse|ceph)', str(f.get('fstype'))))
        fs_max = max((f.get('use_pct') or 0 for f in fs), default=None)
        services_v = sorted({str(e.get('detail') or e.get('nom')) for e in apps.get('elements') or []
                             if e.get('categorie') not in ('Agent', 'Site web', 'Conteneurs')})
        vuln = base['vulns'].get(decl['key'], {}) if decl else {}
        ls = ligne_ssh.get(decl['key']) if decl else {}
        agents_ssh = set(re.split(r',\s*', (ls or {}).get('agents') or '')) - {''}
        environnement = ann.get('environnement') or (decl or {}).get('environment') or ''
        env_conf = DECLARE if (ann.get('environnement') or (environnement and environnement != 'À renseigner')) else INCONNU
        if not environnement or environnement == 'À renseigner':
            prefixe = court(nom)[:3]
            environnement = {'prd': 'PROD (déduit du nom)', 'rec': 'RECETTE (déduit du nom)', 'pre': 'PREPROD (déduit du nom)',
                             'dev': 'DEV (déduit du nom)', 'tst': 'TEST (déduit du nom)'}.get(prefixe, A_COMPLETER)
            env_conf = DEDUIT if environnement != A_COMPLETER else INCONNU
        site = ann.get('site') or ''
        if not site:
            m = re.match(r'^[a-z]{3}(rbx|sbg|gra|bhs|waw|lon|fra|par)', court(nom))
            site = f"OVH {m.group(1).upper()} (déduit du nom)" if m else A_COMPLETER

        vm = {
            'cle': cle, 'id': f'VM-{vmid}', 'vmid': vmid, 'type': 'VM QEMU' if inv['type'] == 'qemu' else 'Conteneur LXC',
            'nom_proxmox': nom, 'nom_court': court(nom), 'hostname': (decl or {}).get('fqdn') or A_COMPLETER,
            'ip': ip_decl or A_COMPLETER, 'ip_confiance': ip_conf, 'ipv6': A_COMPLETER,
            'environnement': environnement, 'environnement_confiance': env_conf, 'site': site,
            'cluster': cluster_nom, 'noeud': inv['noeud'], 'etat': {'running': 'Démarrée', 'stopped': 'Arrêtée'}.get(
                inv.get('etat'), inv.get('etat')), 'template': inv.get('template'),
            'equipe': ann.get('equipe') or A_COMPLETER, 'responsable': ann.get('responsable_applicatif') or A_COMPLETER,
            'fonction': ann.get('fonction') or ((decl or {}).get('documented') or {}).get('architecture', {}).get('description')
            or (decl or {}).get('role') or A_COMPLETER,
            'role_declare': (decl or {}).get('role') or '',
            'criticite': ann.get('criticite') or {'critical': 'Critique', 'standard': 'Standard'}.get(
                (decl or {}).get('criticality'), A_COMPLETER),
            'criticite_confiance': DECLARE if (ann.get('criticite') or decl) else INCONNU,
            'vcpu': int(cfg.get('cores') or 1) * int(cfg.get('sockets') or 1) if cfg else inv.get('maxcpu'),
            'ram_go': round(int(cfg['memory']) / 1024, 1) if str(cfg.get('memory', '')).isdigit() else gib(inv.get('maxmem')),
            'ram_utilisee_go': gib(inv.get('mem')) if inv.get('etat') == 'running' else None,
            'cpu_pct': round((inv.get('cpu') or 0) * 100, 1) if inv.get('etat') == 'running' else None,
            'ram_os_pct': obs.get('ram'), 'cpu_os_pct': obs.get('cpu'),
            'nb_disques': sum(1 for d in liste_disques if not d.get('detache')),
            'disques_detaches': sum(1 for d in liste_disques if d.get('detache')),
            'provisionne_go': gib(taille) if inv.get('disques') is not None else None,
            'occupe_os_go': round(occupe / 1024 / 1024, 1) if occupe else None,
            'fs_max_pct': fs_max, 'stockages': ', '.join(stockages_vm),
            'bridges': ', '.join(sorted({c['bridge'] for c in cartes_vm if c['bridge']})),
            'vlans': ', '.join(sorted({c['vlan'] for c in cartes_vm if c['vlan']})) or 'Aucun tag',
            'os': os_nom or A_COMPLETER, 'os_id': os_id, 'os_version': os_ver, 'os_source': os_src,
            'noyau': (pq or {}).get('kernel') or apps.get('noyau') or '', 'architecture': A_COMPLETER,
            'support_os': support['statut'], 'fin_support_os': support['fin_standard'], 'fin_lts_os': support['fin_etendue'],
            'reboot_requis': {True: 'Oui', False: 'Non'}.get((pq or {}).get('reboot_required'), A_COMPLETER),
            'maj_disponibles': len((pq or {}).get('upgradable') or []) if pq else None,
            'installe_le': (ls or {}).get('installe') or '',
            'agent_qemu_config': {True: 'Activé', False: 'Désactivé', None: 'Non configuré'}[inv.get('agent_qemu')],
            'zabbix': (zh or {}).get('status', 'Absent') if zh else 'Absent', 'zabbix_rattachement': zc,
            'zabbix_nom': (zh or {}).get('host', ''),
            'wazuh': (wa or {}).get('status', 'Absent') if wa else 'Absent', 'wazuh_version': (wa or {}).get('version', ''),
            'wazuh_rattachement': wc, 'agent_wazuh_local': 'Oui' if 'wazuh-agent' in agents_ssh else '',
            'elastic_agent': 'Oui' if 'elastic-agent' in agents_ssh else '',
            'bacula': sauvegarde, 'bacula_jobs': ', '.join(sorted(j.get('name') for j in jobs)),
            'bacula_dernier': max((j.get('endtime') or '' for j in jobs), default=''),
            'bacula_declare': ((decl or {}).get('documented') or {}).get('backup', {}).get('paths', ''),
            'pare_feu_proxmox': 'Oui' if any(c.get('pare_feu') for c in cartes_vm) else 'Non',
            'pare_feu_local': (obs.get('storage') or {}).get('firewall') or ('Non relevé (root requis)' if mesure else ''),
            'ports': ', '.join(apps.get('ports') or []), 'services': ', '.join(services_v)[:1500],
            'applications': (ls or {}).get('heberge', ''), 'statut_applications': (ls or {}).get('statut', ''),
            'docker': apps.get('docker') or '', 'cve_critiques': vuln.get('critical', 0), 'cve_hautes': vuln.get('high', 0),
            'cve_kev': vuln.get('kev', 0), 'cve_total': sum(v for k, v in vuln.items() if k != 'kev'),
            'releve_ssh': jour(obs.get('collected_at')) if mesure else '', 'ssh_ok': ssh_ok,
            'releve_paquets': jour((pq or {}).get('collecte_le')), 'inventaire_declare': decl['key'] if decl else '',
            'ctime': datetime.fromtimestamp(inv['ctime'], timezone.utc).date().isoformat() if inv.get('ctime') else '',
            'tags': inv.get('tags') or '', 'pool': inv.get('pool') or '',
            'onboot': {1: 'Oui', '1': 'Oui', 0: 'Non', '0': 'Non'}.get(cfg.get('onboot'), 'Non'),
            'protection': 'Oui' if str(cfg.get('protection')) == '1' else 'Non',
        }
        if inv.get('etat') == 'running' and not mesure:
            cause = ''
            if brut:
                cause = ((brut.get('attempts') or [{}])[-1].get('error_kind') or '') + ' ' + ((brut.get('issues') or [''])[0] or '')[:120]
            couverture.append({'objet': cle, 'nom': court(nom), 'perimetre': 'Système invité (audit SSH)',
                               'raison': ('Hors inventaire SSH (absente de hosts.yaml)' if not decl
                                          else f'Audit SSH en échec : {cause.strip() or "jamais audité"}'),
                               'action': 'Autoriser et configurer l’accès SSH en lecture seule, ou documenter la VM'})
        vms.append(vm)
        for d in liste_disques:
            disques.append({'vm': cle, 'vmid': vmid, 'nom': court(nom), 'noeud': inv['noeud'], 'disque': d['cle'],
                            'interface': d.get('interface') or re.sub(r'\d+$', '', d['cle']),
                            'stockage': d['stockage'], 'support': LIBELLES_STOCKAGE.get(d['stockage'], d['stockage']),
                            'volume': d['volume'], 'taille_go': gib(d.get('taille')), 'detache': 'Oui' if d.get('detache') else 'Non',
                            'confiance': CONFIRME})
        for c in cartes_vm:
            cartes.append({'vm': cle, 'nom': court(nom), 'noeud': inv['noeud'], **c})
        if decl:
            technos += [{**t, 'vm': cle, 'nom': court(nom)} for t in technologies_hote(decl['key'], obs, pq)]

    # Serveurs déclarés sans VM Proxmox correspondante : physiques ou hors cluster.
    hors_cluster = []
    for h in hotes:
        if h['key'] in rattaches:
            continue
        obs = etats.get(h['key']) or {}
        pq = paquets.get(h['key'])
        hors_cluster.append({'cle': h['key'], 'nom': h.get('name'), 'ip': h.get('ip'), 'role': h.get('role'),
                             'environnement': h.get('environment'), 'os': (pq or {}).get('os', {}).get('pretty') or obs.get('os') or A_COMPLETER,
                             'vmid_declare': h.get('vmid') or '', 'noeud_declare': h.get('node') or '',
                             'releve_ssh': jour(obs.get('collected_at')),
                             'nature': 'VMID déclaré introuvable dans Proxmox' if h.get('vmid') else 'Hors cluster Proxmox : physique ou autre hyperviseur (à qualifier)',
                             'confiance': DECLARE})
        technos += [{**t, 'vm': h['key'], 'nom': h.get('name')} for t in technologies_hote(h['key'], obs, pq)]

    noeuds = []
    stock_par_noeud = defaultdict(list)
    for s in proxmox.get('stockages') or []:
        stock_par_noeud[s.get('node')].append(s.get('storage'))
    for n in proxmox.get('noeuds') or []:
        invites_n = [v for v in vms if v['noeud'] == n['nom']]
        noeuds.append({**n, 'cluster': cluster_nom, 'ip_management': ip_noeuds.get(n['nom'], ''),
                       'ram_totale_go': gib(n.get('ram_totale')), 'ram_utilisee_go': gib(n.get('ram_utilisee')),
                       'nb_vm': sum(1 for v in invites_n if v['type'] == 'VM QEMU'),
                       'nb_lxc': sum(1 for v in invites_n if v['type'] != 'VM QEMU'),
                       'nb_demarrees': sum(1 for v in invites_n if v['etat'] == 'Démarrée'),
                       'vcpu_alloues': sum(v['vcpu'] or 0 for v in invites_n if v['etat'] == 'Démarrée'),
                       'ram_allouee_go': round(sum(v['ram_go'] or 0 for v in invites_n if v['etat'] == 'Démarrée'), 1),
                       'stockages': ', '.join(sorted(stock_par_noeud.get(n['nom'], []))),
                       'site': A_COMPLETER, 'fournisseur': 'OVHcloud (déclaré)' if n['nom'].startswith('ns') else A_COMPLETER})

    stockages = construire_stockages(proxmox, vms, disques)
    applications = construire_applications(par_application(details_apps), details_apps, hotes, actifs_ps, ps,
                                           technos, aujourdhui)
    bases = construire_bases(details_apps, technos, vms, hotes)
    services_ports = construire_ports(vms, hors_cluster, etats, hotes)
    docker = construire_docker(hotes, paquets, etats)
    certificats = construire_certificats(hotes, etats, aujourdhui)
    sauvegardes = construire_sauvegardes(api, vms, hist_bac, hotes)
    supervision = construire_supervision(api, vms, hors_cluster)
    reseaux = construire_reseaux(cartes, noeuds, base, hotes, vms)
    dependances = construire_dependances(vms, disques, stockages, actifs_ps, ps, etats, hotes, bases)
    risques = construire_risques(vms, noeuds, stockages, proxmox, technos, certificats, hors_cluster,
                                 api, couverture, aujourdhui)
    couverture += perimetres_non_couverts(base, api, hotes, etats, paquets)
    enregistrements = construire_enregistrements(hotes, etats, certificats)
    batchs = construire_batchs(base['cron'], hotes, vms)
    montages = construire_montages(etats, hotes, vms)
    services_systemd = construire_services_systemd(etats, hotes)
    risques = numeroter(risques + risques_exploitation(enregistrements, batchs, montages, services_systemd))
    return {
        'meta': {'genere_le': maintenant().isoformat(timespec='seconds'), 'cluster': cluster_nom,
                 'sources': sources(proxmox, base, api, hotes), 'methode': (
                     'Lecture seule : GET API Proxmox, base OpsControl (audit SSH en lecture seule déjà réalisé), '
                     'derniers résultats API Zabbix/Wazuh/Bacula, inventaire déclaré. Aucune commande sur le parc.')},
        'noeuds': noeuds, 'cluster': proxmox.get('cluster'), 'ceph': proxmox.get('ceph'), 'stockages': stockages,
        'vms': vms, 'hors_cluster': hors_cluster, 'disques': disques, 'cartes_reseau': cartes, 'reseaux': reseaux,
        'applications': applications, 'technologies': technos, 'services_ports': services_ports,
        'docker': docker, 'bases': bases, 'sauvegardes': sauvegardes, 'supervision': supervision,
        'certificats': certificats, 'dependances': dependances, 'risques': risques,
        'impact': construire_impact(vms, dependances, stockages, noeuds,
                                    {court(t['nom']) for t in technos if t['technologie'] == 'Keepalived' and t['usage'] == 'Utilisé'}),
        'enregistrements': enregistrements, 'batchs': batchs, 'montages': montages,
        'services_systemd': services_systemd, 'problemes_zabbix': construire_problemes_zabbix(api, vms),
        'vue_globale': construire_vue_globale(vms, disques, technos, bases, docker, dependances, risques, hotes, aujourdhui,
                                              batchs, enregistrements),
        'incoherences': incoherences, 'non_couverts': couverture,
        'erreurs_collecte': proxmox.get('erreurs') or [],
    }


def construire_stockages(proxmox, vms, disques) -> list[dict]:
    """Un support partagé compté une seule fois ; un support local, par nœud."""
    vus = {}
    for s in proxmox.get('stockages') or []:
        partage = bool(s.get('shared'))
        cle = s['storage'] if partage else f"{s['storage']}@{s['node']}"
        if cle in vus:
            vus[cle]['noeuds'].append(s['node'])
            continue
        vus[cle] = {'cle': cle, 'stockage': s['storage'], 'libelle': LIBELLES_STOCKAGE.get(s['storage'], s['storage']),
                    'type': s.get('plugintype'), 'partage': 'Partagé' if partage else 'Local', 'noeuds': [s['node']],
                    'etat': s.get('status'), 'total_go': gib(s.get('maxdisk')), 'utilise_go': gib(s.get('disk')),
                    'contenu': s.get('content')}
    ceph = proxmox.get('ceph') or {}
    for s in vus.values():
        total, utilise = s['total_go'] or 0, s['utilise_go'] or 0
        s['libre_go'] = round(total - utilise, 1) if total else None
        s['occupation_pct'] = round(100 * utilise / total, 1) if total else None
        locaux = [d for d in disques if d['stockage'] == s['stockage']
                  and (s['partage'] == 'Partagé' or d['noeud'] == s['noeuds'][0])]
        s['nb_disques'] = len(locaux)
        s['vms'] = ', '.join(sorted({d['nom'] for d in locaux}))
        s['nb_vms'] = len({d['vm'] for d in locaux})
        s['provisionne_go'] = round(sum(d['taille_go'] or 0 for d in locaux), 1)
        s['noeuds'] = ', '.join(sorted(s['noeuds']))
        s['socle_de'] = SOCLES.get(s['stockage'], '')
        if s['type'] == 'rbd' and s['stockage'] == 'myceph' and ceph:
            s['sante'] = ceph.get('sante')
            s['redondance'] = f"Ceph : {(ceph.get('osdmap') or {}).get('num_up_osds')}/{(ceph.get('osdmap') or {}).get('num_osds')} OSD up ; réplication à confirmer"
        elif s['type'] == 'rbd':
            s['sante'], s['redondance'] = A_COMPLETER, 'Ceph géré par OVHcloud (service distant) : redondance fournisseur, à confirmer'
        elif s['type'] == 'pbs':
            s['sante'], s['redondance'] = A_COMPLETER, 'Proxmox Backup Server (destination de sauvegarde) : réplication à confirmer'
        elif s['type'] == 'nfs':
            s['sante'], s['redondance'] = A_COMPLETER, 'Serveur NFS unique (prdlabpve06 / zfs-primary) : point unique de défaillance'
        else:
            s['sante'], s['redondance'] = A_COMPLETER, 'Disque local : aucune redondance inter-nœuds (RAID local à confirmer)'
        pct = s['occupation_pct'] or 0
        s['risque_saturation'] = 'Critique' if pct >= 90 else 'Élevé' if pct >= 80 else 'Modéré' if pct >= 70 else 'Faible'
        s['surprovisionnement'] = (round(s['provisionne_go'] / total, 2) if total and s['partage'] == 'Partagé' else None)
    return sorted(vus.values(), key=lambda s: s['cle'])


def libelle_tech(t: dict, aujourdhui: date) -> str:
    """« PHP 8.2.29 (fin de vie 2025-12-31) » : version installée et, si suivi, statut éditeur."""
    statut, fin = fin_support_tech(t['technologie'], t['version'], aujourdhui)
    version = re.sub(r'^\d+:', '', str(t['version'] or '')).split('-', 1)[0].split('+', 1)[0]
    suffixe = f' ({statut.lower()} {fin})' if statut.startswith('Fin de vie') else ''
    return f"{t['technologie']} {version}{suffixe}".strip()


def technos_element(e: dict, techs: list[dict], aujourdhui: date) -> list[tuple[str, str]]:
    """Technologies sur lesquelles repose un élément applicatif : [(libellé, confiance)].

    CONFIRMÉ : le relevé désigne le moteur (processus Java, service PostgreSQL…).
    DÉDUIT   : technologie présente sur le même serveur, que l'élément utilise probablement
               (version de Java d'une application Tomcat quand plusieurs JDK sont installés,
               PHP sur un serveur web) : à confirmer avec le responsable applicatif.
    """
    categorie, source = e.get('categorie'), str(e.get('source') or '')
    nom = f"{e.get('nom') or ''} {e.get('detail') or ''}".lower()
    par_tech = defaultdict(list)
    for t in techs:
        par_tech[t['technologie']].append(t)

    def prendre(tech, confiance_si_unique=CONFIRME):
        liste = par_tech.get(tech) or []
        utilises = [t for t in liste if t['usage'] == 'Utilisé'] or liste
        confiance = confiance_si_unique if len(utilises) == 1 else DEDUIT
        return [(libelle_tech(t, aujourdhui), confiance) for t in utilises]

    resultat = []
    if categorie == 'Application web (Tomcat)' or 'tomcat' in nom:
        resultat += prendre('Tomcat') + prendre('Java (OpenJDK)')
        if not par_tech.get('Tomcat'):
            resultat.append(('Tomcat (version non packagée : à relever)', INCONNU))
    elif source == 'Java':
        resultat += prendre('Java (OpenJDK)')
    elif source in ('Python', 'Node.js'):
        resultat += prendre('Python' if source == 'Python' else 'Node.js')
    elif categorie == 'Site web':
        resultat += prendre('Apache HTTP Server' if 'apache' in source.lower() else 'Nginx')
        resultat += [(f'{lib} — usage par ce site non vérifié', DEDUIT) for lib, _ in prendre('PHP', DEDUIT)]
    else:
        for tech in par_tech:
            if tech.split()[0].lower() in nom:
                resultat += prendre(tech)
    if not resultat and source in ('Java', 'Python', 'Node.js'):
        resultat.append((f'{source} (version non relevée)', INCONNU))
    return resultat


def construire_applications(groupes, details, hotes, actifs_ps, ps, technos=(), aujourdhui=None) -> list[dict]:
    aujourdhui = aujourdhui or maintenant().date()
    hote_par_nom = {str(h.get('name') or h['key']): h for h in hotes}
    techs_hote = defaultdict(list)
    for t in technos:
        techs_hote[t['hote']].append(t)
    lignes = []
    for g in groupes:
        elements = [e for e in details if e.get('statut') in ('Identifié', 'À confirmer')
                    and str(e.get('nom')) in g['composants'].split(', ')]
        piles = {}
        for e in elements:
            h = hote_par_nom.get(str(e['serveur'])) or {}
            for libelle, confiance in technos_element(e, techs_hote.get(h.get('key'), []), aujourdhui):
                # CONFIRMÉ l'emporte si deux serveurs donnent la même technologie.
                if piles.get(libelle) != CONFIRME:
                    piles[libelle] = confiance
        methodes = sorted({str(e.get('source')) for e in elements})
        etats = sorted({str(e.get('etat')) for e in elements if e.get('etat')})
        urls = set()
        for nom_serveur in {e['serveur'] for e in elements}:
            h = hote_par_nom.get(nom_serveur)
            if h:
                for p in ps.published_to({**h, 'applications': None}, actifs_ps):
                    if str(p.get('application') or '').endswith(tuple(g['composants'].split(', '))):
                        urls.add(p.get('url') or p.get('site'))
        lignes.append({'application': g['application'], 'categorie': g['categorie'], 'fonction': A_COMPLETER,
                       'serveurs': g['serveurs'], 'nb_serveurs': g['nb'], 'composants': g['composants'],
                       'methode': ', '.join(methodes), 'etat': ', '.join(etats), 'url': ', '.join(sorted(urls)) or g['sites'],
                       'technologies': ' ; '.join(f'{lib} [{conf}]' for lib, conf in sorted(piles.items())) or A_COMPLETER,
                       'fin_de_vie': 'Oui' if any('fin de vie' in lib and 'non vérifié' not in lib for lib in piles) else 'Non',
                       'environnements': g['environnements'], 'bdd': A_COMPLETER, 'responsable': A_COMPLETER,
                       'criticite': A_COMPLETER, 'statut_identification': g['statut'],
                       'justification': g['justification'],
                       'confiance': CONFIRME if g['statut'] == 'Identifié' else DEDUIT})
    return lignes


def construire_bases(details, technos, vms, hotes) -> list[dict]:
    """Instances de SGBD : service relevé (CONFIRMÉ) ou paquet installé seul (DÉDUIT)."""
    nom_vm = {v['inventaire_declare']: v for v in vms if v['inventaire_declare']}
    lignes, vus = [], set()
    for e in details:
        if e.get('categorie') not in ('Base de données', 'Cache'):
            continue
        cle_h = next((h['key'] for h in hotes if str(h.get('name') or h['key']) == e['serveur']), e['serveur'])
        vm = nom_vm.get(cle_h, {})
        produit = str(e.get('detail') or e.get('nom'))
        version = next((t['version'] for t in technos if t['hote'] == cle_h and t['technologie'].split()[0].lower()
                        in produit.lower()), '')
        port = next((p for p, lib in PORTS_CONNUS.items() if produit.split()[0].lower() in lib.lower()
                     and p in (vm.get('ports') or '').split(', ')), '')
        vus.add((cle_h, produit.split()[0].lower()))
        lignes.append({'serveur': e['serveur'], 'ip': e.get('ip'), 'vm': vm.get('cle', ''), 'sgbd': produit,
                       'service': e.get('nom'), 'version': version or A_COMPLETER, 'etat': e.get('etat'),
                       'port': port or A_COMPLETER, 'environnement': e.get('environnement'),
                       'applications_dependantes': A_COMPLETER, 'source': 'Service systemd (audit SSH)',
                       'confiance': CONFIRME})
    for t in technos:
        if t['famille'] != 'Base de données' or (t['hote'], t['technologie'].split()[0].lower()) in vus:
            continue
        if t['usage'] == 'Utilisé':
            continue  # déjà vu comme service
        lignes.append({'serveur': t['nom'], 'ip': '', 'vm': t['vm'], 'sgbd': t['technologie'], 'service': '',
                       'version': t['version'], 'etat': 'Paquet installé, aucun service actif relevé',
                       'port': A_COMPLETER, 'environnement': '', 'applications_dependantes': A_COMPLETER,
                       'source': t['source'], 'confiance': DEDUIT})
    return sorted(lignes, key=lambda r: (str(r['sgbd']).lower(), str(r['serveur'])))


def construire_ports(vms, hors_cluster, etats, hotes) -> list[dict]:
    """Ports en écoute relevés (ss sans root) : le service associé est DÉDUIT du port standard."""
    lignes = []
    nom_par_cle = {v['inventaire_declare']: v for v in vms if v['inventaire_declare']}
    for h in hotes:
        apps = (etats.get(h['key']) or {}).get('applications') or {}
        if apps.get('status') != 'observed':
            continue
        vm = nom_par_cle.get(h['key'], {})
        exposes = {p.get('port') for p in apps.get('ports_details') or []} if apps.get('ports_details') else set()
        for port in apps.get('ports') or []:
            lignes.append({'serveur': h.get('name') or h['key'], 'ip': h.get('ip'), 'vm': vm.get('cle', ''),
                           'port': int(port) if str(port).isdigit() else port, 'protocole': 'TCP',
                           'service_probable': PORTS_CONNUS.get(str(port), A_COMPLETER),
                           'processus': 'Non visible sans root', 'exposition': 'Publié via WAF' if port in exposes else A_COMPLETER,
                           'releve_le': jour(apps.get('collected_at')),
                           'confiance': DEDUIT if str(port) in PORTS_CONNUS else INCONNU})
    return lignes


def construire_docker(hotes, paquets, etats) -> list[dict]:
    lignes = []
    for h in hotes:
        pq = paquets.get(h['key']) or {}
        d = pq.get('docker') or {}
        apps = (etats.get(h['key']) or {}).get('applications') or {}
        conteneurs_apps = [e for e in apps.get('elements') or [] if e.get('categorie') in ('Conteneur', 'Service Swarm', 'Conteneurs')]
        if not d and not conteneurs_apps and h.get('role') != 'SWARM':
            continue
        if d.get('state') == 'absent' and h.get('role') != 'SWARM':
            continue
        swarm = d.get('swarm') or {}
        etat = {'ok': 'Lu', 'denied': 'Accès refusé (groupe docker ou root requis)', 'absent': 'Docker absent',
                'error': 'Erreur de lecture'}.get(d.get('state'), 'Non relevé')
        lignes.append({'serveur': h.get('name'), 'ip': h.get('ip'), 'role_declare': h.get('role'),
                       'docker': etat, 'version': swarm.get('server_version') or '',
                       'swarm': swarm.get('state') or ('Non lisible' if d.get('state') == 'denied' else A_COMPLETER),
                       'manager': {True: 'Oui', False: 'Non'}.get(swarm.get('manager'), A_COMPLETER) if d.get('state') == 'ok' else A_COMPLETER,
                       'nb_conteneurs': len(d.get('containers') or []), 'nb_images': len(d.get('images') or []),
                       'nb_services': len(d.get('services') or []),
                       'conteneurs': d.get('containers') or [], 'images': d.get('images') or [], 'services': d.get('services') or [],
                       'services_systemd': ', '.join(sorted({str(e.get('nom')) for e in conteneurs_apps})),
                       'releve_le': jour(pq.get('collecte_le')) or jour(apps.get('collected_at')),
                       'confiance': CONFIRME if d.get('state') == 'ok' else INCONNU})
    return lignes


def construire_certificats(hotes, etats, aujourdhui) -> list[dict]:
    lignes = []
    for h in hotes:
        waf = (etats.get(h['key']) or {}).get('waf') or {}
        donnees = ((waf.get('sections') or {}).get('certificates') or {}).get('data') or {}
        for c in donnees.get('certificates') or []:
            fin = c.get('not_after') or ''
            reste = (date.fromisoformat(fin[:10]) - aujourdhui).days if fin else None
            lignes.append({'serveur': h.get('name'), 'ip': h.get('ip'), 'fichier': c.get('path'),
                           'sujet': c.get('subject'), 'emetteur': c.get('issuer'), 'debut': jour(c.get('not_before')),
                           'expiration': jour(fin), 'jours_restants': reste,
                           'alerte': ('Expiré' if reste is not None and reste < 0 else 'Moins de 30 jours' if reste is not None and reste < 30
                                      else 'Moins de 60 jours' if reste is not None and reste < 60 else 'OK' if reste is not None else A_COMPLETER),
                           'utilise_par': ', '.join(Path(s).name for s in c.get('sources') or [])[:600],
                           'empreinte_sha256': c.get('fingerprint'), 'releve_le': jour(waf.get('collected_at')),
                           'source': 'Relevé WAF (fichiers référencés par Apache)', 'confiance': CONFIRME})
    return sorted(lignes, key=lambda c: (c['jours_restants'] if c['jours_restants'] is not None else 99999))


def construire_sauvegardes(api, vms, hist_bac, hotes) -> list[dict]:
    lignes = []
    vm_par_nom = {v['nom_court']: v for v in vms}
    for j in (api.get('Bacula') or {}).get('inventaire', {}).get('latest') or []:
        client = court(re.sub(r'-fd$', '', str(j.get('client') or '')))
        dates = sorted(hist_bac.get(j.get('name')) or [])
        frequence = A_COMPLETER
        if len(dates) >= 3:
            ecarts = [(datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds() / 3600
                      for a, b in zip(dates, dates[1:])]
            med = sorted(ecarts)[len(ecarts) // 2]
            frequence = 'Quotidienne (déduite)' if 20 <= med <= 28 else 'Hebdomadaire (déduite)' if 150 <= med <= 190 else f'~{med:.0f} h (déduite)'
        lignes.append({'job': j.get('name'), 'type': 'Copie' if str(j.get('name')).startswith('copy-') else 'Sauvegarde',
                       'client': j.get('client'), 'vm': (vm_par_nom.get(client) or {}).get('cle', 'Hors cluster / non rattaché'),
                       'niveau': {'F': 'Complète', 'I': 'Incrémentale', 'D': 'Différentielle'}.get(j.get('level'), j.get('level')),
                       'statut': j.get('status_label'), 'gravite': j.get('severity'), 'debut': j.get('starttime'),
                       'fin': j.get('endtime'), 'octets': j.get('bytes'), 'fichiers': j.get('files'),
                       'frequence': frequence, 'destination': A_COMPLETER, 'outil': 'Bacula', 'confiance': CONFIRME})
    for h in hotes:
        b = ((h.get('documented') or {}).get('backup') or {})
        if b.get('paths') or b.get('configuration'):
            lignes.append({'job': 'Documentation (hosts.yaml)', 'type': 'Déclaré', 'client': h.get('name'),
                           'vm': next((v['cle'] for v in vms if v['inventaire_declare'] == h['key']), ''),
                           'niveau': '', 'statut': b.get('configuration') or '', 'gravite': '', 'debut': '', 'fin': '',
                           'octets': None, 'fichiers': None, 'frequence': A_COMPLETER,
                           'destination': A_COMPLETER, 'outil': f"Chemins : {b.get('paths')} ; exclusions : {b.get('exclusions')} ; rétention : {b.get('retention') or A_COMPLETER}",
                           'confiance': DECLARE})
    return lignes


def construire_supervision(api, vms, hors_cluster) -> list[dict]:
    lignes = []
    for v in vms:
        lignes.append({'objet': v['cle'], 'nom': v['nom_court'], 'etat_vm': v['etat'], 'zabbix': v['zabbix'],
                       'zabbix_rattachement': v['zabbix_rattachement'], 'wazuh': v['wazuh'], 'wazuh_version': v['wazuh_version'],
                       'wazuh_rattachement': v['wazuh_rattachement'], 'elastic_agent': v['elastic_agent'] or A_COMPLETER,
                       'bacula': v['bacula'], 'agent_qemu': v['agent_qemu_config'], 'audit_ssh': v['releve_ssh'] or 'Non audité'})
    vus_z = {v['zabbix_nom'] for v in vms if v['zabbix_nom']}
    for h in (api.get('Zabbix') or {}).get('inventaire', {}).get('hosts') or []:
        if h.get('host') not in vus_z:
            lignes.append({'objet': 'Zabbix seul', 'nom': h.get('host'), 'etat_vm': 'Sans VM Proxmox rattachée',
                           'zabbix': h.get('status'), 'zabbix_rattachement': CONFIRME, 'wazuh': '', 'wazuh_version': '',
                           'wazuh_rattachement': '', 'elastic_agent': '', 'bacula': '', 'agent_qemu': '',
                           'audit_ssh': ', '.join(h.get('addresses') or [])})
    return lignes


def construire_reseaux(cartes, noeuds, base, hotes, vms) -> list[dict]:
    lignes = [{'type': 'Nœud Proxmox (management)', 'objet': n['nom'], 'ip': n['ip_management'], 'interface': '',
               'bridge': '', 'vlan': '', 'mac': '', 'detail': f"PVE {n.get('version')}", 'confiance': CONFIRME}
              for n in noeuds]
    vm_ip = {v['cle']: v['ip'] for v in vms}
    for c in cartes:
        lignes.append({'type': 'Carte VM', 'objet': c['nom'], 'ip': vm_ip.get(c['vm'], ''), 'interface': c['carte'],
                       'bridge': c['bridge'], 'vlan': c['vlan'] or 'Aucun tag', 'mac': c['mac'],
                       'detail': f"{c['modele']} ; pare-feu Proxmox {'activé' if c['pare_feu'] else 'désactivé'}",
                       'confiance': CONFIRME})
    # Connues = inventaire déclaré ET actifs relevés par Proxmox : sans les IP de
    # management des nœuds et des VM, la découverte les signalait « hors inventaire ».
    connues = ({h.get('ip') for h in hotes} | {n.get('ip_management') for n in noeuds}
               | {ip for ip in vm_ip.values() if ip}) - {None, ''}
    for d in base['decouverte']:
        lignes.append({'type': 'Découverte réseau' + ('' if d['ip'] in connues else ' (hors inventaire)'),
                       'objet': d.get('dns') or d['ip'], 'ip': d['ip'], 'interface': '', 'bridge': '', 'vlan': '',
                       'mac': '', 'detail': f"ports {d.get('ports')} ; {d.get('os') or d.get('type') or ''} ; {d.get('banniere') or ''}"[:300],
                       'confiance': CONFIRME if d['ip'] in connues else DEDUIT})
    return lignes


def construire_dependances(vms, disques, stockages, actifs_ps, ps, etats, hotes, bases) -> list[dict]:
    """Arêtes vérifiables seulement : hébergement, stockage, publication WAF, montage NFS, sauvegarde."""
    deps = []
    for v in vms:
        deps.append({'source': v['nom_court'], 'type_source': 'VM', 'relation': 'hébergée sur', 'cible': v['noeud'],
                     'type_cible': 'Nœud Proxmox', 'preuve': 'API Proxmox', 'confiance': CONFIRME})
        for s in sorted({d['stockage'] for d in disques if d['vm'] == v['cle']}):
            deps.append({'source': v['nom_court'], 'type_source': 'VM', 'relation': 'disques sur', 'cible': s,
                         'type_cible': 'Stockage', 'preuve': 'Configuration VM (API Proxmox)', 'confiance': CONFIRME})
        if v['bacula_jobs']:
            deps.append({'source': v['nom_court'], 'type_source': 'VM', 'relation': 'sauvegardée par', 'cible': 'Bacula',
                         'type_cible': 'Sauvegarde', 'preuve': v['bacula_jobs'][:200], 'confiance': CONFIRME})
    for s in stockages:
        if s.get('socle_de'):
            deps.append({'source': s['socle_de'], 'type_source': 'Stockage', 'relation': 'servi depuis', 'cible': s['stockage'],
                         'type_cible': 'Stockage', 'preuve': 'Même espace libre (constat 09/10/2026)', 'confiance': DEDUIT})
    nom_par_cle = {h['key']: (h.get('name') or h['key']) for h in hotes}
    for h in actifs_ps:
        for p in ps.published_to(h, actifs_ps):
            deps.append({'source': p.get('site'), 'type_source': 'Site publié', 'relation': 'routé par', 'cible': p['via']['name'],
                         'type_cible': 'WAF / répartiteur', 'preuve': f"Configuration Apache du WAF ({p.get('url')})", 'confiance': CONFIRME})
            deps.append({'source': p['via']['name'], 'type_source': 'WAF / répartiteur', 'relation': f"renvoie vers :{p.get('port')}",
                         'cible': nom_par_cle.get(h['key']), 'type_cible': 'Serveur',
                         'preuve': f"{p.get('site')} → {p.get('application') or ''}", 'confiance': CONFIRME})
    nom_ip = {h.get('ip'): (h.get('name') or h['key']) for h in hotes}
    for h in hotes:
        partages = ((etats.get(h['key']) or {}).get('storage') or {}).get('remote_shares') or []
        for r in partages:
            serveur = str(r.get('server') or r.get('source') or r.get('device') or '').split(':', 1)[0]
            deps.append({'source': h.get('name'), 'type_source': 'Serveur', 'relation': f"monte {r.get('fstype') or 'partage'} {r.get('mount') or ''}",
                         'cible': (f'{nom_ip[serveur]} ({serveur})' if serveur in nom_ip and nom_ip[serveur] != serveur
                                   else serveur or A_COMPLETER), 'type_cible': 'Serveur de fichiers', 'preuve': 'Montage relevé (audit SSH)',
                         'confiance': CONFIRME})
    for b in bases:
        if b['confiance'] == CONFIRME:
            deps.append({'source': f"Applications de {b['serveur']}", 'type_source': 'Application', 'relation': 'utilisent ?',
                         'cible': f"{b['sgbd']} ({b['serveur']})", 'type_cible': 'Base de données',
                         'preuve': 'Co-localisation seulement : chaîne de connexion non lue (secret)', 'confiance': DEDUIT})
    return deps


DNS_LIBELLES = {'interne': 'DNS interne', 'en_ligne': 'Public (résolu sur Internet)', 'non_resolu': 'Non résolu'}


def construire_enregistrements(hotes, etats, certificats) -> list[dict]:
    """Enregistrements DNS servis par chaque serveur web : publiés par un WAF ou un
    répartiteur (nom → WAF → serveur:port → application) ou sites locaux.

    Un serveur dont au moins un site a une cible de proxy est traité comme WAF/répartiteur ;
    les cibles sont rapprochées de l'inventaire par export_enregistrements_waf.lignes.
    """
    import export_enregistrements_waf as ewaf

    cert_par_conf = {}
    for c in certificats:
        for conf in str(c['utilise_par'] or '').split(', '):
            cert_par_conf.setdefault((c['serveur'], conf), c)

    def certificat(serveur, fichiers):
        for f in str(fichiers or '').split(', '):
            c = cert_par_conf.get((serveur, Path(f).name))
            if c:
                return c
        return {}

    lignes = []
    for h in hotes:
        apps = (etats.get(h['key']) or {}).get('applications') or {}
        if apps.get('status') != 'observed' or not apps.get('sites'):
            continue
        nom = h.get('name') or h['key']
        commun = {'frontal': nom, 'ip_frontal': h.get('ip'), 'releve_le': jour(apps.get('collected_at'))}
        if any(s.get('cibles') for s in apps['sites']):
            publies, hors, sans_cible, _ = ewaf.lignes(hotes, etats, h)
            groupes = [(p, 'Publié vers un serveur inventorié', CONFIRME) for p in publies]
            groupes += [(p, p.get('motif'), DEDUIT if 'absente' in str(p.get('motif')) else CONFIRME) for p in hors]
            groupes += [(p, 'Site servi par le frontal lui-même (sans proxy)', CONFIRME) for p in sans_cible]
            role = 'WAF / répartiteur'
        else:
            groupes = []
            for s in apps['sites']:
                dns = s.get('dns') or {}
                groupes.append(({'site': s.get('nom'), 'url': s.get('url'), 'https': 'Oui' if s.get('https') else 'Non',
                                 'dns': DNS_LIBELLES.get(dns.get('statut'), 'Non mesuré'),
                                 'adresses': ', '.join(dns.get('adresses') or []), 'fichiers': ', '.join(s.get('fichiers') or []),
                                 'racines': ', '.join(s.get('racines') or [])}, 'Site local (vhost du serveur)', CONFIRME))
            role = 'Serveur web'
        for p, nature, confiance in groupes:
            c = certificat(nom, p.get('fichiers'))
            lignes.append({**commun, 'role_frontal': role, 'enregistrement': p.get('site'), 'url': p.get('url'),
                           'https': p.get('https'), 'dns': p.get('dns'), 'adresses_dns': p.get('adresses'),
                           'chemin': p.get('chemin') or '/', 'cible': p.get('cible') or '', 'repartiteur': p.get('repartiteur') or '',
                           'serveur_cible': p.get('serveur') or ('' if p.get('cible') else nom), 'ip_cible': p.get('ip') or '',
                           'environnement': p.get('environnement') or h.get('environment') or '',
                           'application': p.get('application') or '', 'nature': nature,
                           'racine': p.get('racines') or '', 'fichier_conf': p.get('fichiers'),
                           'certificat': c.get('sujet', ''), 'expiration_certificat': c.get('expiration', ''),
                           'jours_restants': c.get('jours_restants'), 'confiance': confiance})
    return sorted(lignes, key=lambda r: (str(r['enregistrement']).lower(), r['frontal'], str(r['chemin'])))


def construire_batchs(cron: dict, hotes, vms) -> list[dict]:
    """Tâches planifiées relevées : crontabs, timers systemd, processus batch en cours."""
    vm_par_cle = {v['inventaire_declare']: v for v in vms if v['inventaire_declare']}
    lignes = []
    for h in hotes:
        etat = cron.get(h['key']) or {}
        for j in etat.get('jobs') or []:
            resultat = {'success': 'Succès', 'failed': 'Échec', 'scheduled': 'Planifiée', 'running': 'En cours',
                        'unknown': 'Non mesuré'}.get(j.get('state'), j.get('state'))
            lignes.append({'serveur': h.get('name') or h['key'], 'ip': h.get('ip'), 'vm': vm_par_cle.get(h['key'], {}).get('cle', ''),
                           'environnement': h.get('environment') or '',
                           'type': {'cron': 'Cron', 'systemd': 'Timer systemd', 'process': 'Processus en cours'}.get(j.get('kind'), j.get('kind')),
                           'nom': j.get('name'), 'planification': j.get('schedule'), 'fuseau': j.get('timezone') or etat.get('timezone'),
                           'commande': j.get('executable'), 'script': j.get('script') or '', 'compte': j.get('owner'),
                           'source': f"{j.get('source')}{':' + str(j['line']) if j.get('line') else ''}",
                           'resultat': resultat, 'code_retour': j.get('exit_code', ''), 'derniere_execution': j.get('last_run') or '',
                           'prochaine_execution': j.get('next_run') or '', 'preuve': j.get('evidence'),
                           'systeme': 'Oui' if tache_systeme(j) else 'Non',
                           'releve_le': jour(etat.get('collected_at')), 'confiance': CONFIRME})
    return sorted(lignes, key=lambda r: (r['systeme'], r['serveur'], r['type'], str(r['nom'])))


# Timers fournis par le système (rotation, mises à jour…) : utiles mais pas des batchs métier.
SYSTEME_BATCH = ('apt-', 'dpkg-', 'logrotate', 'man-db', 'fstrim', 'e2scrub', 'systemd-tmpfiles', 'exim4',
                 'phpsessionclean', 'motd-news', 'unattended', 'sysstat', 'mlocate', 'plocate', 'certbot', 'snapd',
                 'fwupd', 'ua-timer', 'update-notifier', 'raid-check', 'unbound-anchor', 'dnf-makecache',
                 'yum-makecache', 'mdcheck', 'mdmonitor', 'cd', '0anacron', 'popularity-contest', 'systemd-',
                 '0logwatch', 'mcelog', 'freshclam')
# Scripts que les paquets déposent dans /etc/cron.{hourly,daily,weekly,monthly}.
SCRIPTS_SYSTEME = {'dpkg', 'locate', 'mlocate', 'plocate', 'apt-compat', 'aptitude', 'bsdmainutils', 'passwd', 'man-db',
                   'logrotate', 'sysstat', 'exim4-base', 'popularity-contest', 'apache2', 'php', 'ntp', 'quota',
                   'rkhunter', 'chkrootkit', '0yum-daily.cron', '0yum-hourly.cron', '0hourly', '0anacron', 'makewhatis.cron',
                   'tmpwatch', 'prelink', 'readahead.cron', 'cracklib-runtime', 'mdadm', 'raid-check', 'certwatch',
                   'unbound-anchor', 'e2scrub_all', 'samba', 'spamassassin', 'debsums', 'apt-show-versions', 'fstrim',
                   'google-chrome', 'dnf-automatic', 'yum-cron', 'ubuntu-advantage-tools', 'update-notifier-common'}


def tache_systeme(j: dict) -> bool:
    """Tâche fournie par le système ou un paquet (rotation, index, mises à jour), pas un batch métier."""
    nom = str(j.get('name') or '')
    commande = str(j.get('executable') or '')
    source = str(j.get('source') or '')
    # /etc/cron.d/<paquet> (sysstat, e2scrub_all, certbot…) et lignes « test -x … || run-parts »
    # de /etc/crontab : déposées par les paquets, jamais écrites par une équipe applicative.
    if source.startswith('/etc/cron.d/') and Path(source).name in SCRIPTS_SYSTEME | CRON_D_SYSTEME:
        return True
    if source == '/etc/crontab' and commande == 'test':
        return True
    return (nom.startswith(SYSTEME_BATCH) or commande == 'run-parts' or Path(commande).name in SCRIPTS_SYSTEME
            or nom in SCRIPTS_SYSTEME)


CRON_D_SYSTEME = {'e2scrub_all', 'sysstat', 'certbot', 'debsecan', 'php', 'anacron', 'zfsutils-linux', 'mdadm',
                  'ntpsec', 'popularity-contest', 'unattended-upgrades', '.placeholder', 'raid-check', '0hourly',
                  'clamav-freshclam', 'sa-update'}


def construire_montages(etats, hotes, vms) -> list[dict]:
    """Systèmes de fichiers locaux, montages réseau, partages exportés et volumes LVM."""
    vm_par_cle = {v['inventaire_declare']: v for v in vms if v['inventaire_declare']}
    lignes = []
    for h in hotes:
        obs = etats.get(h['key']) or {}
        s = obs.get('storage') or {}
        base_l = {'serveur': h.get('name') or h['key'], 'ip': h.get('ip'), 'vm': vm_par_cle.get(h['key'], {}).get('cle', ''),
                  'releve_le': jour(obs.get('collected_at')), 'confiance': CONFIRME}
        for f in s.get('filesystems') or []:
            lignes.append({**base_l, 'type': 'Système de fichiers', 'point': f.get('mount'), 'source': f.get('device'),
                           'fs': f.get('fstype'), 'taille_go': round((f.get('total_kb') or 0) / 1048576, 1),
                           'utilise_pct': f.get('use_pct'), 'inodes_pct': f.get('inodes_use_pct'), 'etat': '', 'acces': ''})
        for r in s.get('remote_shares') or []:
            lignes.append({**base_l, 'type': 'Montage réseau (client)', 'point': r.get('mount'), 'source': r.get('source'),
                           'fs': r.get('fstype'), 'taille_go': round((r.get('total_kb') or 0) / 1048576, 1) or None,
                           'utilise_pct': r.get('use_pct'), 'inodes_pct': None,
                           'etat': {'stale': 'Bloqué (stale)', 'accessible': 'Accessible'}.get(r.get('status'), r.get('status')),
                           'acces': r.get('access')})
        for e in s.get('exports') or []:
            lignes.append({**base_l, 'type': f"Partage exporté ({e.get('protocol')})", 'point': e.get('path'),
                           'source': e.get('name') or '', 'fs': e.get('filesystem'), 'taille_go': None,
                           'utilise_pct': e.get('use_pct'), 'inodes_pct': None, 'etat': '', 'acces': e.get('clients') or ''})
        for lv in s.get('lvm') or []:
            lignes.append({**base_l, 'type': 'Volume LVM', 'point': f"{lv.get('vg')}/{lv.get('lv')}", 'source': lv.get('attr'),
                           'fs': 'LVM', 'taille_go': round((lv.get('size_bytes') or 0) / GIB, 1), 'utilise_pct': None,
                           'inodes_pct': None, 'etat': '', 'acces': ''})
    return lignes


def construire_services_systemd(etats, hotes) -> list[dict]:
    lignes = []
    for h in hotes:
        obs = etats.get(h['key']) or {}
        for s in obs.get('all_services') or []:
            lignes.append({'serveur': h.get('name') or h['key'], 'ip': h.get('ip'),
                           'service': re.sub(r'\.service$', '', str(s.get('name'))),
                           'etat': {'active': 'Actif', 'failed': 'En échec', 'inactive': 'Arrêté'}.get(s.get('status'), s.get('status')),
                           'active_au_demarrage': 'Oui' if s.get('configured') else 'Non',
                           'releve_le': jour(obs.get('collected_at')), 'confiance': CONFIRME})
    return lignes


def construire_problemes_zabbix(api, vms) -> list[dict]:
    vm_par_nom = {v['zabbix_nom']: v for v in vms if v['zabbix_nom']}
    lignes = []
    for p in (api.get('Zabbix') or {}).get('inventaire', {}).get('problems') or []:
        depuis = datetime.fromtimestamp(int(p['last_change']), timezone.utc) if str(p.get('last_change') or '').isdigit() else None
        lignes.append({'probleme': p.get('description'), 'gravite_zabbix': p.get('severity_label'),
                       'gravite': {'critical': 'Critique', 'warning': 'Moyenne'}.get(p.get('severity'), 'Faible'),
                       'hotes': ', '.join(p.get('hosts') or []),
                       'vm': ', '.join(vm_par_nom[n]['nom_court'] for n in p.get('hosts') or [] if n in vm_par_nom),
                       'depuis': depuis.date().isoformat() if depuis else '',
                       'jours': (maintenant() - depuis).days if depuis else None,
                       'mesure_le': p.get('measurement_at'), 'confiance': CONFIRME})
    return sorted(lignes, key=lambda r: ({'Critique': 0, 'Moyenne': 1}.get(r['gravite'], 2), -(r['jours'] or 0)))


# Colonnes « technologie » de la vue globale : (en-tête, technologies regroupées).
COLONNES_TECH = [('PHP', ('PHP',)), ('Java', ('Java (OpenJDK)',)), ('Python', ('Python',)), ('Node.js', ('Node.js',)),
                 ('Apache', ('Apache HTTP Server',)), ('Nginx', ('Nginx',)), ('Tomcat', ('Tomcat',)),
                 ('PostgreSQL', ('PostgreSQL',)), ('MariaDB / MySQL', ('MariaDB', 'MySQL')), ('Redis', ('Redis',)),
                 ('Docker', ('Docker Engine',)), ('Elasticsearch', ('Elasticsearch', 'Kibana', 'Logstash'))]
SOCLE_TECH = {'OpenSSL', 'OpenSSH Server', 'Zabbix Agent', 'Wazuh Agent', 'Elastic Agent', 'Bacula File Daemon', 'Filebeat'}


def cellule_tech(liste: list[dict], aujourdhui: date) -> str:
    """« 8.2.29 (utilisé) ; 7.4.33 (installé seul, fin de vie) » pour une colonne technologie."""
    morceaux = []
    for t in liste:
        etat = {'Utilisé': 'utilisé', 'Installé (socle système)': 'socle système'}.get(t['usage'], 'installé seul')
        statut, _ = fin_support_tech(t['technologie'], t['version'], aujourdhui)
        if statut == 'Fin de vie':
            etat += ', FIN DE VIE'
        version = re.sub(r'^\d+:', '', str(t['version'] or '')).split('-', 1)[0].split('+', 1)[0]
        morceaux.append(f'{version} ({etat})')
    return ' ; '.join(dict.fromkeys(morceaux))


def construire_vue_globale(vms, disques, technos, bases, docker, dependances, risques, hotes,
                           aujourdhui: date | None = None, batchs=(), enregistrements=()) -> list[dict]:
    """Une ligne par VM avec TOUT : hébergement, stockage, système, applications, versions
    réellement utilisées, bases, conteneurs, exposition, protection et risques."""
    aujourdhui = aujourdhui or maintenant().date()
    nom_decl = {h['key']: str(h.get('name') or h['key']) for h in hotes}
    disques_vm, techs_vm, risques_vm = defaultdict(list), defaultdict(list), defaultdict(list)
    for d in disques:
        disques_vm[d['vm']].append(d)
    for t in technos:
        techs_vm[t['vm']].append(t)
    for r in risques:
        risques_vm[str(r['serveur'])].append(r)
    sites, bdd, conteneurs = defaultdict(set), defaultdict(list), {}
    for d in dependances:
        if d['type_cible'] == 'Serveur':
            sites[str(d['cible'])].add(str(d['preuve']).split(' → ', 1)[0])
    for b in bases:
        bdd[str(b['serveur'])].append(f"{b['sgbd']} {b['version'] if b['version'] != A_COMPLETER else ''}".strip()
                                      + ('' if b['confiance'] == CONFIRME else ' (paquet seul)'))
    for d in docker:
        conteneurs[str(d['serveur'])] = (f"{d['docker']} ; Swarm {d['swarm']} ; {d['nb_conteneurs']} conteneur(s), "
                                         f"{d['nb_services']} service(s)" if d['confiance'] == CONFIRME else d['docker'])
    # La fiche VM retrouve une VM par son nom : un nom porté par deux VM reçoit son VMID.
    doublons = {n for n, c in Counter(v['nom_court'] for v in vms).items() if c > 1}
    batchs_h, dns_h = defaultdict(list), defaultdict(set)
    for b in batchs:
        batchs_h[str(b['serveur'])].append(b)
    for e in enregistrements:
        # Un nom est rattaché au serveur qui sert réellement l'application (cible du proxy).
        dns_h[str(e['serveur_cible'] or e['frontal'])].add(str(e['enregistrement']))
    lignes = []
    for v in vms:
        nom_h = nom_decl.get(v['inventaire_declare'], v['nom_court'])
        techs = techs_vm.get(v['cle'], [])
        metier = [b for b in batchs_h.get(nom_h, []) if b['systeme'] == 'Non']
        apps = ' | '.join(dict.fromkeys(a for a in (v['applications'] or '').split(' | ') if a))
        ligne = {
            'id': v['id'], 'vmid': v['vmid'], 'hostname': v['hostname'], 'ip': v['ip'],
            'nom': f"{v['nom_court']} ({v['vmid']})" if v['nom_court'] in doublons else v['nom_court'],
            'environnement': v['environnement'], 'criticite': v['criticite'], 'fonction': v['fonction'],
            'equipe': v['equipe'], 'responsable': v['responsable'], 'site': v['site'], 'cluster': v['cluster'],
            'noeud': v['noeud'], 'etat': v['etat'], 'stockages': v['stockages'],
            'disques': ' ; '.join(f"{d['disque']} {d['stockage']} {d['taille_go']} Go" + (' (détaché)' if d['detache'] == 'Oui' else '')
                                  for d in disques_vm.get(v['cle'], [])) or A_COMPLETER,
            'provisionne_go': v['provisionne_go'], 'occupe_os_go': v['occupe_os_go'], 'fs_max_pct': v['fs_max_pct'],
            'vcpu': v['vcpu'], 'ram_go': v['ram_go'], 'ram_utilisee_go': v['ram_utilisee_go'], 'cpu_pct': v['cpu_pct'],
            'os': v['os'], 'support_os': v['support_os'], 'fin_lts_os': v['fin_lts_os'], 'noyau': v['noyau'],
            'reboot_requis': v['reboot_requis'], 'maj_disponibles': v['maj_disponibles'],
            'applications': apps or (A_COMPLETER if v['etat'] == 'Démarrée' else ''),
            'sites_publies': ', '.join(sorted(sites.get(nom_h, ()))),
            'bases': ' ; '.join(bdd.get(nom_h, [])),
            'conteneurs': conteneurs.get(nom_h, 'Docker absent' if v['docker'] == 'Absent' else v['docker'] or ''),
            'enregistrements_dns': ', '.join(sorted(dns_h.get(nom_h, ()))),
            'batchs': (f"{len(metier)} tâche(s) : " + ', '.join(dict.fromkeys(str(b['nom']) for b in metier))[:600]) if metier
            else ('Aucune hors système' if batchs_h.get(nom_h) else ''),
            'batchs_echec': sum(1 for b in metier if b['resultat'] == 'Échec'),
            'ports': v['ports'], 'bridges': v['bridges'], 'vlans': v['vlans'],
            'bacula': v['bacula'], 'zabbix': v['zabbix'], 'wazuh': v['wazuh'], 'agent_qemu': v['agent_qemu_config'],
            'risques_critiques': sum(1 for r in risques_vm.get(v['nom_court'], []) if r['gravite'] == 'Critique'),
            'risques_eleves': sum(1 for r in risques_vm.get(v['nom_court'], []) if r['gravite'] == 'Élevée'),
            'risques_total': len(risques_vm.get(v['nom_court'], [])),
            'risques_p1': ', '.join(r['id'] for r in risques_vm.get(v['nom_court'], []) if r['priorite'] == 'P1'),
            'cve_kev': v['cve_kev'], 'releve_ssh': v['releve_ssh'] or 'Non audité',
        }
        regroupees = set()
        for entete, noms in COLONNES_TECH:
            liste = [t for t in techs if t['technologie'] in noms]
            regroupees.update(noms)
            ligne[f'tech_{entete}'] = cellule_tech(liste, aujourdhui)
        autres = [t for t in techs if t['technologie'] not in regroupees and t['technologie'] not in SOCLE_TECH
                  and t['usage'] == 'Utilisé']
        # Tomcat déployé à la main (archive) : aucun paquet, mais l'instance tourne.
        if not ligne['tech_Tomcat'] and 'tomcat' in apps.lower():
            ligne['tech_Tomcat'] = 'Utilisé (installation manuelle : version à relever)'
        ligne['tech_autres'] =', '.join(sorted({f"{t['technologie']} {cellule_tech([t], aujourdhui)}" for t in autres}))
        if not techs and v['etat'] == 'Démarrée':
            for entete, _ in COLONNES_TECH:
                ligne[f'tech_{entete}'] = 'Non relevé'
        lignes.append(ligne)
    return lignes


def construire_impact(vms, dependances, stockages, noeuds, keepalived=frozenset()) -> list[dict]:
    """Matrice d'impact : ce qui s'arrête si le composant s'arrête (VM démarrées seulement)."""
    demarrees = {v['nom_court']: v for v in vms if v['etat'] == 'Démarrée'}
    ordre = {'Critique': 0, 'Standard': 1}

    def ligne(composant, type_, touchees, dependances_txt, spof, confiance, service=A_COMPLETER):
        vm_t = [demarrees[n] for n in sorted(touchees) if n in demarrees]
        apps = sorted({a.split(' [')[0] for v in vm_t for a in (v['applications'] or '').split(' | ') if a})
        crit = min((v['criticite'] for v in vm_t), key=lambda c: ordre.get(c, 2), default='')
        return {'composant': composant, 'type': type_, 'service_metier': service, 'dependances': dependances_txt,
                'nb_vm': len(vm_t), 'vm_impactees': ', '.join(v['nom_court'] for v in vm_t)[:2000],
                'applications_impactees': ', '.join(apps)[:2000] or A_COMPLETER, 'criticite': crit or A_COMPLETER,
                'spof': spof, 'confiance': confiance}

    lignes = []
    for n in noeuds:
        heberge = [v for v in vms if v['noeud'] == n['nom']]
        locales = [v['nom_court'] for v in heberge if 'local' in v['stockages'] or 'zfs-primary' in v['stockages']]
        lignes.append(ligne(n['nom'], 'Nœud Proxmox', {v['nom_court'] for v in heberge}, f"Stockages : {n['stockages']}",
                            f"Oui pour {len(locales)} VM à disques locaux ({', '.join(locales)})" if locales
                            else 'Non si HA/migration opérationnelle (à confirmer)', CONFIRME))
    for s in stockages:
        if not s['nb_vms']:
            continue
        spof = ('Oui : serveur NFS unique' if s['type'] == 'nfs' else 'Oui : disque local' if s['partage'] == 'Local'
                else 'Redondance interne Ceph ; cluster unique (point de défaillance logique)')
        lignes.append(ligne(s['cle'], f"Stockage {s['type']}", set(s['vms'].split(', ')), s['noeuds'], spof,
                            CONFIRME if s['type'] != 'rbd' else DEDUIT))
    routeurs = defaultdict(lambda: {'cibles': set(), 'sites': set()})
    for d in dependances:
        if d['type_source'] == 'WAF / répartiteur' and d['type_cible'] == 'Serveur':
            routeurs[d['source']]['cibles'].add(court(d['cible']))
        if d['type_cible'] == 'WAF / répartiteur':
            routeurs[d['cible']]['sites'].add(str(d['source']))
    for nom, r in sorted(routeurs.items()):
        lignes.append(ligne(nom, 'WAF / répartiteur', r['cibles'],
                            f"{len(r['sites'])} sites publiés : {', '.join(sorted(r['sites']))[:600]}",
                            'Keepalived actif : VIP partagée probable (bascule à tester)' if court(nom) in keepalived
                            else 'Probable (aucun Keepalived actif relevé)', DEDUIT, service='Publication des sites web'))
    montages = defaultdict(set)
    for d in dependances:
        if d['type_cible'] == 'Serveur de fichiers':
            montages[d['cible']].add(court(d['source']))
    for serveur, clients in sorted(montages.items()):
        lignes.append(ligne(serveur, 'Serveur de fichiers (NFS/CIFS)', clients, 'Montages réseau relevés',
                            'Probable (serveur unique)', CONFIRME))
    return lignes


def risque(liste, serveur, description, gravite, preuve, impact, recommandation, priorite, responsable='À désigner',
           categorie='', source='', confiance=CONFIRME):
    liste.append({'id': '', 'categorie': categorie, 'serveur': serveur, 'description': description, 'gravite': gravite,
                  'preuve': preuve, 'impact': impact, 'recommandation': recommandation, 'priorite': priorite,
                  'responsable': responsable, 'statut': 'Ouvert', 'source': source, 'confiance': confiance})


def construire_risques(vms, noeuds, stockages, proxmox, technos, certificats, hors_cluster, api, couverture, aujourdhui):
    r = []
    for v in vms:
        if v['etat'] != 'Démarrée':
            continue
        if v['support_os'] == 'Fin de vie':
            risque(r, v['nom_court'], f"Système en fin de vie : {v['os']}", 'Critique',
                   f"{v['os_source']} ; fin de support {v['fin_lts_os'] or v['fin_support_os']}",
                   'Plus aucun correctif de sécurité publié', 'Planifier la migration vers une version supportée',
                   'P1', 'Équipe Infrastructure', 'Obsolescence', 'os-release + calendrier éditeur', DECLARE)
        elif v['support_os'].startswith('Support étendu') or v['support_os'].startswith('Fin du support standard'):
            risque(r, v['nom_court'], f"Système hors support standard : {v['os']} ({v['support_os']})", 'Moyenne',
                   f"Fin du support standard {v['fin_support_os']}, fin LTS {v['fin_lts_os']}",
                   'Correctifs limités (LTS : architectures et paquets restreints)',
                   'Inscrire la montée de version au plan annuel', 'P3', 'Équipe Infrastructure', 'Obsolescence',
                   'os-release + calendrier éditeur', DECLARE)
        if v['reboot_requis'] == 'Oui':
            risque(r, v['nom_court'], 'Redémarrage requis pour appliquer des correctifs (noyau ou bibliothèques)', 'Moyenne',
                   f"reboot-required relevé le {v['releve_paquets']}", 'Correctifs installés mais inactifs',
                   'Planifier un redémarrage en fenêtre de maintenance', 'P2', 'Équipe Infrastructure', 'Mises à jour')
        if (v['maj_disponibles'] or 0) >= 50:
            risque(r, v['nom_court'], f"{v['maj_disponibles']} paquets ont une mise à jour disponible", 'Moyenne',
                   f"Relevé des paquets du {v['releve_paquets']}", 'Retard de correctifs, exposition aux CVE publiées',
                   'Appliquer les mises à jour après validation en préproduction', 'P2', 'Équipe Infrastructure', 'Mises à jour')
        if v['cve_kev']:
            risque(r, v['nom_court'], f"{v['cve_kev']} vulnérabilité(s) exploitée(s) activement (CISA KEV) non corrigée(s)", 'Critique',
                   f"OpsControl Sécurité : version installée < version corrigée ({v['cve_critiques']} critiques, {v['cve_hautes']} hautes)",
                   'Exploitation connue dans la nature', 'Appliquer les correctifs ; voir l’onglet Sécurité d’OpsControl',
                   'P1', 'Équipe Infrastructure', 'Sécurité', 'OpsControl sec_vulns (preuve par paquet)')
        if v['fs_max_pct'] is not None and v['fs_max_pct'] >= 90:
            risque(r, v['nom_court'], f"Système de fichiers rempli à {v['fs_max_pct']} %", 'Élevée',
                   f"Audit SSH du {v['releve_ssh']}", 'Arrêt applicatif ou corruption à saturation',
                   'Purger ou étendre le volume', 'P1', 'Équipe Infrastructure', 'Capacité')
        if v['zabbix'] == 'Absent':
            risque(r, v['nom_court'], 'VM démarrée non supervisée par Zabbix (aucun hôte rattaché)', 'Moyenne',
                   'Aucun hôte Zabbix de même nom ni de même IP', 'Panne non détectée',
                   'Ajouter l’hôte à Zabbix ou documenter l’exception', 'P2', 'Équipe Supervision', 'Supervision', 'API Zabbix')
        elif v['zabbix'] == 'unmonitored':
            risque(r, v['nom_court'], 'Hôte Zabbix désactivé (non supervisé)', 'Moyenne', f"Hôte {v['zabbix_nom']} : status unmonitored",
                   'Panne non détectée', 'Réactiver la supervision ou documenter', 'P2', 'Équipe Supervision', 'Supervision', 'API Zabbix')
        if v['wazuh'] in ('Absent', 'never_connected', 'disconnected'):
            risque(r, v['nom_court'], f"Agent Wazuh {'absent' if v['wazuh'] == 'Absent' else v['wazuh']}", 'Moyenne',
                   'Inventaire des agents Wazuh (API)', 'Pas de détection d’intrusion ni d’inventaire de vulnérabilités',
                   'Installer ou reconnecter l’agent Wazuh', 'P2', 'Équipe Sécurité', 'Sécurité', 'API Wazuh')
        if v['bacula'] == 'Aucun job Bacula identifié':
            risque(r, v['nom_court'], 'Aucune sauvegarde Bacula identifiée (PBS non vérifié)', 'Élevée' if v['criticite'] == 'Critique' else 'Moyenne',
                   'Aucun client Bacula de même nom ; jobs vzdump/PBS non lus', 'Perte de données en cas d’incident',
                   'Vérifier la sauvegarde (Bacula, vzdump/PBS) ou documenter son absence', 'P2', 'Équipe Sauvegarde',
                   'Sauvegarde', 'API Bacula', DEDUIT)
        elif v['bacula'].startswith('Dernier job en erreur'):
            risque(r, v['nom_court'], v['bacula'], 'Élevée', f"Dernier job terminé le {v['bacula_dernier']}",
                   'Sauvegarde non garantie', 'Analyser le job en erreur et relancer', 'P1', 'Équipe Sauvegarde', 'Sauvegarde', 'API Bacula')
    for t in technos:
        statut, fin = fin_support_tech(t['technologie'], t['version'], aujourdhui)
        t['support'], t['fin_support'] = statut, fin
        if statut == 'Fin de vie' and t['usage'] == 'Utilisé':
            risque(r, t['nom'], f"{t['technologie']} {t['version_majeure']} en fin de vie et utilisé", 'Élevée',
                   f"{t['paquets']} {t['version']} ; {t['preuve_usage']} ; fin de support {fin}",
                   'Plus de correctifs de sécurité éditeur', f"Migrer {t['technologie']} vers une version supportée",
                   'P2', 'Équipe applicative', 'Obsolescence', 'Paquets + calendrier éditeur', DECLARE)
    for n in noeuds:
        statut, fin = fin_support_tech('Proxmox VE', n.get('version') or '', aujourdhui)
        if statut == 'Fin de vie':
            risque(r, n['nom'], f"Proxmox VE {n.get('version')} : branche 8 hors support depuis {fin}", 'Élevée',
                   f"/nodes/{n['nom']}/version ; noyau {n.get('noyau')}", 'Plus de correctifs de sécurité Proxmox',
                   'Planifier la mise à niveau du cluster vers Proxmox VE 9', 'P2', 'Équipe Infrastructure',
                   'Obsolescence', 'API Proxmox + calendrier éditeur', DECLARE)
    versions = Counter(n.get('version') for n in noeuds)
    if len(versions) > 1:
        risque(r, 'Cluster Proxmox', f"Versions PVE hétérogènes : {dict(versions)}", 'Moyenne',
               '; '.join(f"{n['nom']} {n.get('version')} / {str(n.get('noyau') or '').split()[1] if n.get('noyau') else ''}" for n in noeuds),
               'Comportements différents lors des migrations, correctifs inégaux', 'Aligner les nœuds sur la même version',
               'P3', 'Équipe Infrastructure', 'Cohérence', 'API Proxmox')
    for s in stockages:
        if (s['occupation_pct'] or 0) >= 80:
            risque(r, s['cle'], f"Stockage {s['libelle']} occupé à {s['occupation_pct']} %", 'Critique' if s['occupation_pct'] >= 90 else 'Élevée',
                   f"{s['utilise_go']} Go / {s['total_go']} Go ({s['nb_vms']} VM)", 'Arrêt des VM en écriture à saturation',
                   'Libérer de l’espace, déplacer des disques ou étendre le support', 'P1', 'Équipe Infrastructure', 'Capacité', 'API Proxmox')
        if s['type'] == 'nfs' and s['nb_vms']:
            risque(r, s['cle'], f"{s['nb_vms']} VM dépendent d’un unique serveur NFS", 'Élevée', s['redondance'],
                   'Arrêt de prdlabpve06 = arrêt de toutes ces VM', 'Étudier la réplication ou la répartition sur Ceph',
                   'P2', 'Équipe Infrastructure', 'Résilience', 'API Proxmox', DEDUIT)
        if s['partage'] == 'Local' and s['nb_vms']:
            risque(r, s['cle'], f"{s['nb_vms']} VM ont des disques sur stockage local", 'Moyenne', s['vms'][:300],
                   'Pas de migration à chaud ni de redémarrage sur un autre nœud', 'Déplacer les VM critiques sur stockage partagé',
                   'P3', 'Équipe Infrastructure', 'Résilience', 'API Proxmox')
    ceph = proxmox.get('ceph') or {}
    if ceph.get('sante') and ceph['sante'] != 'HEALTH_OK':
        risque(r, 'Ceph (myceph)', f"Ceph en {ceph['sante']} : {', '.join(ceph.get('alertes') or [])}", 'Élevée',
               '/cluster/ceph/status', 'Dégradation possible des performances ou de la disponibilité',
               'Traiter chaque alerte (MON_DISK_LOW : place disque des moniteurs ; DAEMON_OLD_VERSION : démons à aligner ; '
               'AUTH_INSECURE_GLOBAL_ID_RECLAIM_ALLOWED : désactiver après mise à jour des clients)',
               'P1', 'Équipe Infrastructure', 'Stockage', 'API Proxmox')
    for c in certificats:
        if c['alerte'] in ('Expiré', 'Moins de 30 jours'):
            risque(r, c['serveur'], f"Certificat {c['sujet']} : {c['alerte'].lower()} ({c['expiration']})", 'Critique' if c['alerte'] == 'Expiré' else 'Élevée',
                   c['fichier'], 'Erreurs TLS côté clients, sites indisponibles', 'Renouveler et déployer le certificat',
                   'P1', 'Équipe Infrastructure', 'Certificats', 'Relevé WAF')
    stoppees = [v for v in vms if v['etat'] == 'Arrêtée']
    if stoppees:
        risque(r, 'Cluster Proxmox', f"{len(stoppees)} VM arrêtées conservent {round(sum(v['provisionne_go'] or 0 for v in stoppees) / 1024, 1)} To provisionnés",
               'Faible', ', '.join(v['nom_court'] for v in stoppees)[:500], 'Capacité immobilisée, VM orphelines',
               'Confirmer avec les responsables puis archiver ou supprimer', 'P3', 'Équipe Infrastructure', 'Capacité', 'API Proxmox')
    sans_proprio = [v for v in vms if v['responsable'] == A_COMPLETER]
    if sans_proprio:
        risque(r, 'Parc', f"{len(sans_proprio)} VM sans responsable applicatif identifié", 'Moyenne',
               'Aucune source technique ne porte le propriétaire', 'Décisions bloquées en incident ou en fin de vie',
               'Renseigner data/inventaire/annotations.csv', 'P2', 'DSI', 'Gouvernance', 'Inventaire', DECLARE)
    wz = (api.get('Wazuh') or {}).get('inventaire', {})
    manager = (wz.get('manager') or {}).get('version', '')
    anciens = [a for a in wz.get('agents_inventory') or [] if a.get('version') and manager
               and a.get('version').split()[-1] != manager and a.get('status') == 'active']
    if anciens:
        risque(r, 'Wazuh', f"{len(anciens)} agents actifs dans une version différente du manager ({manager})", 'Faible',
               ', '.join(sorted({a['version'] for a in anciens})), 'Règles et fonctionnalités inégales',
               'Mettre à jour les agents par lots', 'P3', 'Équipe Sécurité', 'Sécurité', 'API Wazuh')
    zp = (api.get('Zabbix') or {}).get('inventaire', {}).get('problems') or []
    anciens_pb = [p for p in zp if p.get('severity') == 'critical' and p.get('last_change')
                  and (maintenant().timestamp() - int(p['last_change'])) > 30 * 86400]
    if anciens_pb:
        risque(r, 'Zabbix', f"{len(anciens_pb)} problèmes critiques ouverts depuis plus de 30 jours", 'Moyenne',
               '; '.join(f"{p.get('description')} ({', '.join(p.get('hosts') or [])})" for p in anciens_pb)[:600],
               'Alertes ignorées : vraie panne noyée dans le bruit', 'Traiter ou requalifier ces déclencheurs',
               'P2', 'Équipe Supervision', 'Supervision', 'API Zabbix')
    if couverture:
        risque(r, 'Parc', f"{len(couverture)} VM démarrées sans relevé du système invité", 'Moyenne',
               ', '.join(c['nom'] for c in couverture)[:600], 'Applications, versions et risques inconnus sur ces VM',
               'Ouvrir un accès SSH en lecture seule (compte d’audit) ou documenter', 'P2', 'Équipe Infrastructure',
               'Couverture', 'OpsControl')
    return numeroter(r)


def numeroter(r: list[dict]) -> list[dict]:
    ordre = {'Critique': 0, 'Élevée': 1, 'Moyenne': 2, 'Faible': 3}
    r.sort(key=lambda x: (x['priorite'], ordre.get(x['gravite'], 9), x['categorie'], str(x['serveur'])))
    for i, x in enumerate(r, 1):
        x['id'] = f'R-{i:03d}'
    return r


def risques_exploitation(enregistrements, batchs, montages, services) -> list[dict]:
    """Risques tirés de l'exposition web, des batchs, des montages et des services."""
    r = []
    for m in montages:
        if m['etat'] == 'Bloqué (stale)':
            risque(r, m['serveur'], f"Montage réseau bloqué : {m['point']}", 'Élevée', f"{m['source']} ({m['fs']}) : stale",
                   'Application en erreur ou processus bloqués en entrée/sortie', 'Vérifier le serveur NFS puis remonter le partage',
                   'P1', 'Équipe Infrastructure', 'Stockage', 'Audit SSH')
    echecs = defaultdict(list)
    for s in services:
        if s['etat'] == 'En échec':
            echecs[s['serveur']].append(s['service'])
    for serveur, liste in sorted(echecs.items()):
        risque(r, serveur, f"{len(liste)} service(s) systemd en échec", 'Moyenne', ', '.join(liste)[:300],
               'Fonction arrêtée sans alerte si non supervisée', 'Analyser (journalctl -u <service>) puis corriger ou désactiver',
               'P2', 'Équipe Infrastructure', 'Exploitation', 'Audit SSH')
    for b in batchs:
        if b['resultat'] == 'Échec':
            risque(r, b['serveur'], f"Tâche planifiée en échec : {b['nom']}", 'Moyenne',
                   f"{b['type']} {b['source']} ; code retour {b['code_retour']} ; dernière exécution {b['derniere_execution']}",
                   'Traitement non réalisé', 'Consulter le journal de la tâche et relancer après correction', 'P2',
                   'Équipe Exploitation', 'Batchs', 'Audit SSH')
    non_resolus = sorted({e['enregistrement'] for e in enregistrements if e['dns'] == 'Non résolu'})
    if non_resolus:
        risque(r, 'WAF', f"{len(non_resolus)} nom(s) configuré(s) sur les WAF ne se résolvent pas en DNS", 'Faible',
               ', '.join(map(str, non_resolus))[:600], 'Configuration morte ou site injoignable',
               'Supprimer les vhosts obsolètes ou corriger le DNS', 'P3', 'Équipe Réseau', 'DNS / WAF', 'Relevé WAF')
    hors = sorted({f"{e['enregistrement']} → {e['cible']}" for e in enregistrements if str(e['nature']).startswith('Cible absente')})
    if hors:
        risque(r, 'WAF', f"{len(hors)} publication(s) WAF vers des serveurs absents de l’inventaire", 'Moyenne',
               ', '.join(hors)[:600], 'Serveurs exposés non supervisés ni audités', 'Inventorier ces cibles ou retirer la publication',
               'P2', 'Équipe Réseau', 'DNS / WAF', 'Relevé WAF', DEDUIT)
    return r


def perimetres_non_couverts(base, api, hotes, etats, paquets) -> list[dict]:
    p = [
        {'objet': 'FortiGate / pfSense', 'nom': '', 'perimetre': 'Pare-feux', 'raison': 'Aucun accès API configuré dans OpsControl',
         'action': 'Fournir un compte API en lecture seule (versions, interfaces) si l’audit doit les couvrir'},
        {'objet': 'Windows', 'nom': '', 'perimetre': 'VM Windows', 'raison': 'Aucune collecte WinRM/WMI (hors périmètre OpsControl)',
         'action': 'Identifier les VM Windows par ostype et définir un mode de collecte en lecture seule'},
        {'objet': 'Docker Swarm', 'nom': '', 'perimetre': 'Stacks, services, réseaux, volumes',
         'raison': 'Socket Docker refusé au compte d’audit sur les nœuds Swarm', 'action':
         'Autorisation explicite requise (groupe docker = équivalent root) : à décider par la DSI'},
        {'objet': 'Ports / processus', 'nom': '', 'perimetre': 'Processus derrière chaque port',
         'raison': '`ss -p` exige root : seul le numéro de port est relevé', 'action': 'Accepter le niveau DÉDUIT ou autoriser sudo restreint'},
        {'objet': 'Sauvegardes vzdump / PBS', 'nom': '', 'perimetre': 'Jobs de sauvegarde Proxmox',
         'raison': 'Route /cluster/backup non lue lors de cette collecte', 'action': 'Ajouter ce GET à la prochaine collecte'},
        {'objet': 'Chaînes de connexion BDD', 'nom': '', 'perimetre': 'Application → base de données',
         'raison': 'Fichiers de configuration applicative contenant des secrets : volontairement non lus',
         'action': 'Faire déclarer les dépendances par les responsables applicatifs'},
        {'objet': 'IPv6, architecture CPU invitée', 'nom': '', 'perimetre': 'VM', 'raison': 'Non collectés par OpsControl',
         'action': 'Agent QEMU (network-get-interfaces) ou audit SSH étendu'},
        {'objet': 'Batchs', 'nom': '', 'perimetre': 'Crontabs des comptes utilisateurs, ordonnanceurs applicatifs',
         'raison': '/var/spool/cron exige root ; seuls /etc/crontab, /etc/cron.*, les timers systemd et les processus '
                   'visibles sont relevés (onglet 22_Batchs)',
         'action': 'Autoriser une lecture root restreinte (sudo sur une commande de lecture) ou faire déclarer les batchs'},
        {'objet': 'Propriétaires, équipes, criticité', 'nom': '', 'perimetre': 'Gouvernance',
         'raison': 'Aucune source technique', 'action': 'Saisir dans data/inventaire/annotations.csv'},
    ]
    if not (api.get('Elasticsearch') or {}).get('inventaire'):
        p.append({'objet': 'Elasticsearch', 'nom': '', 'perimetre': 'Cluster Elastic',
                  'raison': 'Dernier résultat API vide', 'action': 'Vérifier la connexion Elastic dans OpsControl'})
    return p


def sources(proxmox, base, api, hotes) -> list[dict]:
    s = [{'source': 'API Proxmox (GET)', 'methode': proxmox.get('methode'), 'date': proxmox.get('collecte_le'),
          'perimetre': f"{len(proxmox.get('noeuds') or [])} nœuds, {len(proxmox.get('invites') or [])} invités",
          'statut': 'OK' if not proxmox.get('erreurs') else f"{len(proxmox['erreurs'])} route(s) en erreur", 'confiance': CONFIRME}]
    for fournisseur, a in sorted(api.items()):
        inv = a.get('inventaire') or {}
        taille = next((f'{len(v)} {k}' for k, v in inv.items() if isinstance(v, list) and v), 'vide')
        s.append({'source': f"API {fournisseur} ({a.get('nom')})", 'methode': 'Dernier résultat de la collecte OpsControl (lecture seule)',
                  'date': a.get('collecte_le'), 'perimetre': taille, 'statut': a.get('statut'), 'confiance': CONFIRME})
    dates = sorted(jour(e.get('collected_at')) for e in base['etats'].values() if e.get('collected_at'))
    mesures = sum(1 for e in base['etats'].values() if (e.get('applications') or {}).get('status') == 'observed')
    s.append({'source': 'Audit SSH OpsControl', 'methode': 'Commandes de lecture de la liste fermée ssh.OPERATIONS',
              'date': f"{dates[0]} → {dates[-1]}" if dates else '', 'perimetre': f"{mesures}/{len(base['etats'])} hôtes avec relevé des applications",
              'statut': 'OK', 'confiance': CONFIRME})
    s.append({'source': 'Relevé sécurité (paquets)', 'methode': 'Liste des paquets, os-release, reboot-required (lecture seule)',
              'date': max((jour(p.get('collecte_le')) for p in base['paquets'].values()), default=''),
              'perimetre': f"{len(base['paquets'])} hôtes", 'statut': 'OK', 'confiance': CONFIRME})
    s.append({'source': 'Vulnérabilités OpsControl', 'methode': 'Comparaison version installée / version corrigée (DSA, DLA, RHSA, NVD)',
              'date': '', 'perimetre': f"{len(base['vulns'])} hôtes", 'statut': 'OK', 'confiance': CONFIRME})
    if base['scans']:
        rng, at, st = base['scans'][0]
        s.append({'source': 'Découverte réseau OpsControl', 'methode': 'Ping et ports TCP courants (non agressif)', 'date': at,
                  'perimetre': f"{rng} : {len(base['decouverte'])} hôtes", 'statut': st, 'confiance': CONFIRME})
    s.append({'source': 'Inventaire déclaré (hosts.yaml)', 'methode': 'Documentation existante importée dans OpsControl',
              'date': '', 'perimetre': f'{len(hotes)} serveurs', 'statut': 'OK', 'confiance': DECLARE})
    return s


# ---------------------------------------------------------------- historisation

def precedent(dossier_courant: Path) -> dict | None:
    candidats = sorted(p for p in SORTIES.glob('*/inventaire_brut.json') if p.parent != dossier_courant)
    return lire_json(candidats[-1]) if candidats else None


def reference_xlsx(chemin: Path) -> dict | None:
    """Base de comparaison initiale : export proxmox_stockage antérieur (VMID, nom, nœud)."""
    try:
        from openpyxl import load_workbook
        ws = load_workbook(chemin, read_only=True).worksheets[0]
    except Exception:  # export absent ou illisible : pas de comparaison initiale
        return None
    vms = []
    for ligne in ws.iter_rows(min_row=2, values_only=True):
        if isinstance(ligne[0], int):
            vms.append({'cle': f'Cluster/{ligne[0]}', 'nom_court': court(ligne[1]), 'noeud': ligne[3],
                        'provisionne_go': ligne[10]})
    m = re.search(r'(\d{4}-\d{2}-\d{2})', chemin.name)
    return {'meta': {'genere_le': m.group(1) if m else chemin.name}, 'vms': vms, 'noeuds': [], 'technologies': []}


def changements(courant: dict, ancien: dict | None) -> list[dict]:
    if not ancien:
        return [{'date': jour(courant['meta']['genere_le']), 'objet': 'Inventaire', 'type': 'Création',
                 'avant': '', 'apres': f"{len(courant['vms'])} VM", 'detail': 'Inventaire initial (aucune version antérieure)'}]
    d = jour(courant['meta']['genere_le'])
    reference = f"comparé au {jour(ancien['meta']['genere_le'])}"
    av, ap = {v['cle']: v for v in ancien.get('vms') or []}, {v['cle']: v for v in courant['vms']}
    sortie = []
    for cle in sorted(ap.keys() - av.keys(), key=lambda c: int(c.split('/')[-1])):
        sortie.append({'date': d, 'objet': f"{cle} {ap[cle]['nom_court']}", 'type': 'VM ajoutée', 'avant': '',
                       'apres': ap[cle]['noeud'], 'detail': reference})
    for cle in sorted(av.keys() - ap.keys(), key=lambda c: int(c.split('/')[-1])):
        sortie.append({'date': d, 'objet': f"{cle} {av[cle]['nom_court']}", 'type': 'VM supprimée', 'avant': av[cle]['noeud'],
                       'apres': '', 'detail': reference})
    for cle in sorted(ap.keys() & av.keys(), key=lambda c: int(c.split('/')[-1])):
        a, b = av[cle], ap[cle]
        for champ, libelle in (('noeud', 'VM déplacée'), ('nom_court', 'VM renommée'), ('os', 'Système modifié'),
                               ('noyau', 'Noyau modifié'), ('etat', 'État modifié'), ('provisionne_go', 'Disques modifiés')):
            if champ in a and a.get(champ) != b.get(champ) and a.get(champ) not in (None, '') :
                sortie.append({'date': d, 'objet': f"{cle} {b['nom_court']}", 'type': libelle, 'avant': a.get(champ),
                               'apres': b.get(champ), 'detail': reference})
    na = {n['nom']: n for n in ancien.get('noeuds') or []}
    for n in courant['noeuds']:
        if n['nom'] in na and na[n['nom']].get('version') != n.get('version'):
            sortie.append({'date': d, 'objet': n['nom'], 'type': 'Version PVE modifiée', 'avant': na[n['nom']].get('version'),
                           'apres': n.get('version'), 'detail': reference})
    ta = {(t['vm'], t['technologie'], t['paquets']): t['version'] for t in ancien.get('technologies') or []}
    for t in courant['technologies']:
        avant = ta.get((t['vm'], t['technologie'], t['paquets']))
        if avant and avant != t['version']:
            sortie.append({'date': d, 'objet': f"{t['nom']} : {t['technologie']}", 'type': 'Version logicielle modifiée',
                           'avant': avant, 'apres': t['version'], 'detail': reference})
    return sortie or [{'date': d, 'objet': 'Inventaire', 'type': 'Aucun changement', 'avant': '', 'apres': '', 'detail': reference}]


# ---------------------------------------------------------------- point d'entrée

def main(argv=None) -> int:
    from config import inventory_path
    from export_enregistrements_waf import base_donnees

    a = argparse.ArgumentParser(description='Inventaire complet (corrélation en lecture seule)')
    a.add_argument('--proxmox', required=True, help='relevé produit par inventaire_proxmox.py')
    a.add_argument('--sortie', help='dossier de sortie (défaut : data/inventaire/AAAA-MM-JJ)')
    a.add_argument('--reference', help='export proxmox_stockage antérieur, si aucun inventaire précédent')
    args = a.parse_args(argv)
    proxmox = lire_json(Path(args.proxmox))
    if not proxmox:
        raise SystemExit(f'Relevé Proxmox illisible : {args.proxmox}')
    dossier = Path(args.sortie) if args.sortie else SORTIES / maintenant().date().isoformat()
    dossier.mkdir(parents=True, exist_ok=True)
    hotes = lire_json(inventory_path(BASE / 'hosts.yaml'), {}).get('hosts') or []
    fichier_annotations = SORTIES / 'annotations.csv'
    annotations = charger_annotations(fichier_annotations)
    inventaire = construire(proxmox, hotes, charger_base(base_donnees()),
                            connexions_api(BASE / 'data' / 'api-connections.json'), annotations)
    ancien = precedent(dossier) or (reference_xlsx(Path(args.reference)) if args.reference else None)
    inventaire['changements'] = changements(inventaire, ancien)
    ajoutees = completer_modele_annotations(fichier_annotations, inventaire['vms'], annotations)
    (dossier / 'inventaire_brut.json').write_text(json.dumps(inventaire, ensure_ascii=False, indent=1, default=str),
                                                 encoding='utf-8')
    print(f"{dossier / 'inventaire_brut.json'} : {len(inventaire['vms'])} VM, {len(inventaire['risques'])} risques, "
          f"{len(inventaire['incoherences'])} incohérences, {ajoutees} ligne(s) ajoutée(s) aux annotations.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
