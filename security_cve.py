"""Sécurité & gestion des CVE : vulnérabilités par serveur, veille, remédiation, GLPI.

Principes (identiques au reste d'OpsControl) :
- lecture seule vers le parc : UNE opération SSH figée (`security_packages`) ajoutée à la
  liste fermée ssh.OPERATIONS, sans sudo ni paramètre ; Wazuh lu en GET avec le jeton et
  la liaison d'hôte de la collecte principale ; sources publiques en HTTPS vérifié ;
- une vulnérabilité n'est jamais déduite d'un numéro de version « qui semble ancien ».
  Deux preuves seulement ouvrent une vulnérabilité :
    * Debian : version SOURCE installée < version corrigée publiée par Debian (DSA/DLA)
      POUR LA MÊME RELEASE, comparée selon dpkg. Un correctif rétroporté a, par
      construction, une version de la release : il est reconnu ;
    * Wazuh Vulnerability Detection, qui s'appuie sur les flux des éditeurs.
  Une CVE citée dans le changelog du paquet installé rend la détection « à vérifier »
  (correctif probablement rétroporté). Les bulletins amont (PHP, Fortinet, Proxmox,
  CERT-FR sans CVE du parc) restent de la veille, jamais une détection ;
- une vulnérabilité n'est « corrigée » que si TOUTES ses sources ont mesuré le serveur
  sans la retrouver (relevé complet, données de la source disponibles). Une source en
  panne laisse l'état inchangé, comme pour les incidents ;
- les correctifs sont du TEXTE (security_remediation.plan) ; rien n'est exécuté, aucun
  redémarrage ni déploiement automatique.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import os
import re
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field

import security_alerts
import security_correlation as correlation
import security_feeds as feeds
import security_recommendations
import security_queries
import security_remediation
import security_versions
import security_watch
from read_model_cache import ReadModelCache
import ssh
from audit_engine import redact

log = logging.getLogger('opscontrol.security')
SCHEMA = 'security_v1'
KEY = r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$'
CVE_ID = re.compile(r'^CVE-\d{4}-\d{4,7}$')
PACKAGE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9.+_-]{0,99}$')
VERSION = re.compile(r'^[A-Za-z0-9.:+~_^-]{1,100}$')

# Paquets dont le changelog est relu pour y chercher des CVE corrigées (preuve de
# rétroportage). Liste FERMÉE : relire tous les changelogs serait trop lourd.
_CHANGELOG_DEB = ('openssl libssl3 libssl3t64 libssl1.1 apache2 apache2-bin nginx nginx-common openssh-server '
                  'openssh-client sudo libc6 bash curl libcurl4 libcurl4t64 openjdk-17-jre-headless '
                  'mariadb-server postgresql-common tomcat9 tomcat10 docker.io')
_CHANGELOG_RPM = 'openssl openssl-libs httpd nginx openssh-server sudo glibc bash curl libcurl mariadb-server postgresql-server'
# Opération SSH : lecture des bases de paquets et versions, sans root. Sortie bornée
# (head) pour rester sous la limite de 1 Mio de ssh._run_operation.
COMMAND = (
    "LC_ALL=C; export LC_ALL; "
    "echo '##OS'; cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null; "
    "echo '##KERNEL'; uname -r 2>/dev/null; [ -f /var/run/reboot-required ] && echo REBOOT_REQUIRED; "
    "echo '##PKG'; if command -v dpkg-query >/dev/null 2>&1; then "
    "dpkg-query -W -f='${db:Status-Abbrev}|${Package}|${Version}|${source:Package}|${source:Version}|${Architecture}\\n' "
    "2>/dev/null | grep '^ii' | cut -d'|' -f2- | sed 's/^/dpkg|/' | head -n 6000; "
    "elif command -v rpm >/dev/null 2>&1; then "
    "rpm -qa --qf 'rpm|%{NAME}|%{EPOCHNUM}:%{VERSION}-%{RELEASE}|%{NAME}|%{EPOCHNUM}:%{VERSION}-%{RELEASE}|%{ARCH}\\n' "
    "2>/dev/null | head -n 6000; fi; "
    "echo '##UPGRADABLE'; if command -v apt >/dev/null 2>&1; then "
    "timeout 20 apt list --upgradable 2>/dev/null | grep -v '^Listing' | head -n 3000; "
    "elif command -v dnf >/dev/null 2>&1; then timeout 30 dnf -C -q check-update 2>/dev/null | head -n 3000; "
    "elif command -v yum >/dev/null 2>&1; then timeout 30 yum -C -q check-update 2>/dev/null | head -n 3000; fi; "
    "echo '##CHANGELOG'; if command -v dpkg-query >/dev/null 2>&1; then for p in " + _CHANGELOG_DEB + "; do "
    "f=/usr/share/doc/$p/changelog.Debian.gz; [ -f \"$f\" ] && zcat \"$f\" 2>/dev/null "
    "| grep -oE 'CVE-[0-9]{4}-[0-9]{4,7}' | sort -u | awk -v p=\"$p\" '{print p\"|\"$0}'; done | head -n 20000; "
    "elif command -v rpm >/dev/null 2>&1; then for p in " + _CHANGELOG_RPM + "; do "
    "rpm -q --changelog \"$p\" 2>/dev/null | grep -oE 'CVE-[0-9]{4}-[0-9]{4,7}' | sort -u "
    "| awk -v p=\"$p\" '{print p\"|\"$0}'; done | head -n 20000; fi; "
    "echo '##BIN'; command -v php >/dev/null 2>&1 && php -v 2>/dev/null | head -n 1 | sed 's/^/php|/'; "
    "for b in /usr/sbin/apache2 /usr/sbin/httpd; do [ -x $b ] && $b -v 2>/dev/null | head -n 1 | sed 's/^/apache|/'; done; "
    "command -v openssl >/dev/null 2>&1 && openssl version 2>/dev/null | sed 's/^/openssl|/'; "
    "[ -x /usr/sbin/nginx ] && /usr/sbin/nginx -v 2>&1 | head -n 1 | sed 's/^/nginx|/'; "
    "ssh -V 2>&1 | head -n 1 | sed 's/^/openssh|/'; "
    "echo '##DOCKER'; if command -v docker >/dev/null 2>&1; then "
    "o=$(timeout 10 docker ps --format '{{.Names}}|{{.Image}}|{{.Status}}' 2>&1); echo \"RC|$?\"; echo \"$o\" | head -n 200; "
    "echo '##IMAGES'; timeout 10 docker images --format '{{.Repository}}|{{.Tag}}|{{.ID}}|{{.CreatedAt}}' 2>/dev/null | head -n 300; "
    # Nœud Swarm et services (sur un manager) : images réellement déployées par la pile.
    "echo '##SWARM'; timeout 10 docker info --format '{{.Swarm.LocalNodeState}}|{{.Swarm.ControlAvailable}}|{{.ServerVersion}}' 2>/dev/null; "
    "echo '##SERVICES'; timeout 10 docker service ls --format '{{.Name}}|{{.Image}}|{{.Replicas}}' 2>/dev/null | head -n 200; "
    "else echo ABSENT; fi; "
    # WordPress installé hors conteneur : version lue dans le fichier livré par WordPress.
    "echo '##WP'; for f in /var/www/*/wp-includes/version.php /var/www/*/*/wp-includes/version.php "
    "/srv/*/wp-includes/version.php /srv/*/*/wp-includes/version.php /home/*/public_html/wp-includes/version.php; do "
    "[ -r \"$f\" ] && echo \"$f|$(grep -m1 -oE \"wp_version = '[^']+'\" \"$f\" 2>/dev/null)\"; done | head -n 50; "
    "echo '##END'"
)
ssh.OPERATIONS['security_packages'] = COMMAND

STATUSES = ('open', 'validated', 'in_progress', 'resolved', 'false_positive', 'accepted_risk')
STATUS_LABELS = {'open': 'Détectée', 'validated': 'Validée', 'in_progress': 'Correction planifiée',
                 'resolved': 'Corrigée (constatée)', 'false_positive': 'Faux positif', 'accepted_risk': 'Risque accepté'}
ACTIVE = ('open', 'validated', 'in_progress')
SEVERITY_LABELS = {'critical': 'Critique', 'high': 'Élevée', 'medium': 'Moyenne', 'low': 'Faible', 'none': 'Aucune'}
SOURCE_LABELS = {'debian': 'Debian Security Tracker', 'wazuh': 'Wazuh Vulnerability Detection',
                 'upstream': 'Bulletins éditeur / NVD (version amont)', 'manual': 'Confirmée après vérification'}
# Fin du support de sécurité (LTS inclus) : fait daté, publié par l'éditeur. Une version
# hors support n'est pas une vulnérabilité, mais l'absence de correctifs futurs.
OS_EOL = {('debian', '9'): '2022-06-30', ('debian', '10'): '2024-06-30', ('debian', '11'): '2026-08-31',
          ('debian', '12'): '2028-06-30', ('debian', '13'): '2030-06-30',
          ('ubuntu', '18.04'): '2023-05-31', ('ubuntu', '20.04'): '2025-05-31', ('ubuntu', '22.04'): '2027-06-01',
          ('ubuntu', '24.04'): '2029-05-31', ('centos', '7'): '2024-06-30', ('centos', '8'): '2021-12-31',
          ('rhel', '7'): '2024-06-30', ('rhel', '8'): '2029-05-31', ('rhel', '9'): '2032-05-31',
          ('rocky', '8'): '2029-05-31', ('rocky', '9'): '2032-05-31', ('almalinux', '8'): '2029-05-31',
          ('almalinux', '9'): '2032-05-31'}
DEBIAN_CODENAMES = {'9': 'stretch', '10': 'buster', '11': 'bullseye', '12': 'bookworm', '13': 'trixie', '14': 'forky'}
# Images Docker : (dernier segment du dépôt, préfixe de tag, fin de support amont).
IMAGE_EOL = [('php', '5.', '2018-12-31'), ('php', '7.', '2022-11-28'), ('php', '8.0', '2023-11-26'),
             ('php', '8.1', '2025-12-31'), ('node', '14', '2023-04-30'), ('node', '16', '2023-09-11'),
             ('node', '18', '2025-04-30'), ('node', '20', '2026-04-30'), ('python', '2.', '2020-01-01'),
             ('python', '3.7', '2023-06-27'), ('python', '3.8', '2024-10-07'), ('python', '3.9', '2025-10-31'),
             ('debian', '9', '2022-06-30'), ('debian', 'stretch', '2022-06-30'), ('debian', '10', '2024-06-30'),
             ('debian', 'buster', '2024-06-30'), ('debian', '11', '2026-08-31'), ('debian', 'bullseye', '2026-08-31'),
             ('ubuntu', '18.04', '2023-05-31'), ('ubuntu', '20.04', '2025-05-31'), ('centos', '7', '2024-06-30'),
             ('centos', '8', '2021-12-31'), ('mysql', '5.7', '2023-10-31'), ('postgres', '11', '2023-11-09'),
             ('postgres', '12', '2024-11-21'), ('postgres', '13', '2025-11-13'), ('alpine', '3.17', '2024-11-22'),
             ('alpine', '3.18', '2025-05-09'), ('alpine', '3.19', '2025-11-01')]
# Composants affichés dans l'analyse d'un serveur : (libellé, motif du paquet SOURCE).
COMPONENTS = [('OpenSSL', r'openssl'), ('Apache HTTP Server', r'apache2|httpd'), ('nginx', r'nginx'),
              ('PHP', r'php\d*(\.\d+)?'), ('OpenSSH', r'openssh(-server)?'), ('MariaDB', r'mariadb(-\d+(\.\d+)?)?'),
              ('MySQL', r'mysql(-\d+\.\d+)?|mysql-server'), ('PostgreSQL', r'postgresql(-\d+)?'),
              ('Tomcat', r'tomcat\d*'), ('Java (OpenJDK)', r'openjdk-\d+|java-[\d.]+-openjdk'),
              ('Docker', r'docker\.io|docker-ce'), ('sudo', r'sudo'), ('glibc', r'glibc')]
# Mots-clés des bulletins de veille -> motif des paquets sources du parc concernés.
KEYWORDS = [(r'apache http server|apache httpd|\bhttpd\b', r'apache2|httpd', 'Apache HTTP Server'),
            (r'\bphp\b', r'php\d*(\.\d+)?', 'PHP'), (r'openssl', r'openssl', 'OpenSSL'),
            (r'openssh', r'openssh(-server)?', 'OpenSSH'), (r'\bnginx\b', r'nginx', 'nginx'),
            (r'tomcat', r'tomcat\d*', 'Tomcat'), (r'mariadb', r'mariadb.*', 'MariaDB'),
            (r'postgresql', r'postgresql.*', 'PostgreSQL'), (r'\bsudo\b', r'sudo', 'sudo'),
            (r'docker', r'docker\.io|docker-ce', 'Docker')]


def now():
    return datetime.now(timezone.utc)


def iso(moment=None):
    return (moment or now()).isoformat()


def vuln_id(host_key, cve):
    """Une vulnérabilité = un serveur et une CVE : plusieurs paquets binaires du même paquet
    source, ou deux sources (Debian, Wazuh), donnent UNE seule entrée (déduplication)."""
    return hashlib.sha256(f'{host_key}|{cve}'.encode()).hexdigest()[:20]


# --------------------------------------------------------------------------- schéma
def migrate(db):
    db.execute('CREATE TABLE IF NOT EXISTS schema_migrations(name TEXT PRIMARY KEY, applied_at TEXT)')
    applied = {r[0] for r in db.execute('SELECT name FROM schema_migrations')}
    if SCHEMA not in applied:
        _migrate_v1(db)
    if SCHEMA_V2 not in applied:
        _migrate_v2(db)


SCHEMA_V2 = 'security_v2'


def _migrate_v2(db):
    """Veille en ligne : EPSS, configurations NVD, état des sources, applicabilité par
    technologie, historique des modifications de CVE, envoi des notifications par e-mail."""
    def add(table, column, kind):
        if column not in {r[1] for r in db.execute(f'PRAGMA table_info({table})')}:
            db.execute(f'ALTER TABLE {table} ADD COLUMN {column} {kind}')
    for column, kind in (('epss', 'REAL'), ('epss_percentile', 'REAL'), ('epss_date', 'TEXT'), ('epss_at', 'TEXT'),
                         ('nvd_config', 'TEXT'), ('nvd_status', 'TEXT'), ('nvd_modified', 'TEXT')):
        add('sec_cve', column, kind)
    for column, kind in (('severity', 'TEXT'), ('cvss', 'REAL'), ('ranges', 'TEXT'), ('updated', 'TEXT')):
        add('sec_advisories', column, kind)
    for column, kind in (('kind', 'TEXT'), ('emailed_at', 'TEXT'), ('email_error', 'TEXT'), ('priority', 'TEXT')):
        add('sec_notifications', column, kind)
    for statement in (
        'CREATE TABLE IF NOT EXISTS sec_source_state(source TEXT PRIMARY KEY, last_attempt TEXT, last_success TEXT, '
        'status TEXT NOT NULL, failures INTEGER NOT NULL DEFAULT 0, last_error TEXT, etag TEXT, last_modified TEXT, '
        'next_after TEXT, items INTEGER)',
        'CREATE TABLE IF NOT EXISTS sec_matches(id TEXT NOT NULL, cve TEXT NOT NULL, host_key TEXT NOT NULL, tech TEXT NOT NULL, '
        'instance TEXT NOT NULL, version TEXT, origin TEXT NOT NULL, status TEXT NOT NULL, reason TEXT, fixed TEXT, '
        'source TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(id, cve))',
        'CREATE INDEX IF NOT EXISTS sec_matches_cve ON sec_matches(cve, status)',
        'CREATE INDEX IF NOT EXISTS sec_matches_host ON sec_matches(host_key, status)',
        'CREATE TABLE IF NOT EXISTS sec_match_decisions(id TEXT NOT NULL, cve TEXT NOT NULL, decision TEXT NOT NULL, '
        'note TEXT, actor TEXT NOT NULL, auth TEXT NOT NULL, at TEXT NOT NULL, PRIMARY KEY(id, cve))',
        'CREATE TABLE IF NOT EXISTS sec_cve_changes(seq INTEGER PRIMARY KEY AUTOINCREMENT, cve TEXT NOT NULL, at TEXT NOT NULL, '
        'field TEXT NOT NULL, old TEXT, new TEXT)',
        'CREATE INDEX IF NOT EXISTS sec_cve_changes_at ON sec_cve_changes(at)',
    ):
        db.execute(statement)
    db.execute('INSERT INTO schema_migrations(name, applied_at) VALUES(?,?)', (SCHEMA_V2, iso()))


def _migrate_v1(db):
    statements = [
        'CREATE TABLE IF NOT EXISTS sec_inventory(host_key TEXT PRIMARY KEY, host_ip TEXT, collected_at TEXT NOT NULL, '
        'complete INTEGER NOT NULL, payload TEXT NOT NULL)',
        'CREATE TABLE IF NOT EXISTS sec_scans(id INTEGER PRIMARY KEY AUTOINCREMENT, host_key TEXT NOT NULL, at TEXT NOT NULL, '
        'status TEXT NOT NULL, detail TEXT, packages INTEGER, duration_ms INTEGER, actor TEXT)',
        'CREATE INDEX IF NOT EXISTS sec_scans_at ON sec_scans(at)',
        'CREATE TABLE IF NOT EXISTS sec_wazuh(host_key TEXT PRIMARY KEY, connection TEXT, agent_id TEXT, at TEXT NOT NULL, '
        'complete INTEGER NOT NULL, items TEXT NOT NULL)',
        'CREATE TABLE IF NOT EXISTS sec_fixes(origin TEXT NOT NULL, advisory TEXT NOT NULL, release TEXT NOT NULL, '
        'package TEXT NOT NULL, fixed TEXT NOT NULL, cves TEXT NOT NULL, date TEXT, title TEXT, '
        'PRIMARY KEY(advisory, release, package))',
        'CREATE INDEX IF NOT EXISTS sec_fixes_pkg ON sec_fixes(release, package)',
        'CREATE TABLE IF NOT EXISTS sec_cve(cve TEXT PRIMARY KEY, cvss REAL, severity TEXT, vector TEXT, cvss_version TEXT, '
        'description TEXT, published TEXT, nvd_at TEXT, kev INTEGER NOT NULL DEFAULT 0, kev_added TEXT, kev_due TEXT, '
        'kev_action TEXT, kev_ransomware TEXT)',
        'CREATE TABLE IF NOT EXISTS sec_advisories(source TEXT NOT NULL, id TEXT NOT NULL, title TEXT NOT NULL, url TEXT, '
        'published TEXT, summary TEXT, cves TEXT NOT NULL, products TEXT, first_seen TEXT NOT NULL, digest TEXT, '
        'PRIMARY KEY(source, id))',
        'CREATE INDEX IF NOT EXISTS sec_advisories_published ON sec_advisories(published)',
        'CREATE TABLE IF NOT EXISTS sec_vulns(id TEXT PRIMARY KEY, host_key TEXT NOT NULL, cve TEXT NOT NULL, '
        'package TEXT NOT NULL, installed TEXT, fixed TEXT, sources TEXT NOT NULL, confidence TEXT NOT NULL, '
        'evidence TEXT NOT NULL, status TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, '
        'resolved_at TEXT, owner TEXT, owner_auth TEXT, note TEXT, updated_at TEXT NOT NULL)',
        'CREATE INDEX IF NOT EXISTS sec_vulns_host ON sec_vulns(host_key, status)',
        'CREATE INDEX IF NOT EXISTS sec_vulns_cve ON sec_vulns(cve)',
        'CREATE TABLE IF NOT EXISTS sec_events(seq INTEGER PRIMARY KEY AUTOINCREMENT, vuln_id TEXT NOT NULL, at TEXT NOT NULL, '
        'actor TEXT NOT NULL, auth TEXT NOT NULL, action TEXT NOT NULL, detail TEXT)',
        'CREATE INDEX IF NOT EXISTS sec_events_vuln ON sec_events(vuln_id, seq)',
        'CREATE INDEX IF NOT EXISTS sec_events_at ON sec_events(at)',
        'CREATE TABLE IF NOT EXISTS sec_syncs(id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, at TEXT NOT NULL, '
        'status TEXT NOT NULL, items INTEGER, new_items INTEGER, detail TEXT)',
        'CREATE INDEX IF NOT EXISTS sec_syncs_source ON sec_syncs(source, id)',
        'CREATE TABLE IF NOT EXISTS sec_notifications(id INTEGER PRIMARY KEY AUTOINCREMENT, ref TEXT NOT NULL UNIQUE, '
        'at TEXT NOT NULL, level TEXT NOT NULL, title TEXT NOT NULL, detail TEXT, hosts TEXT, cve TEXT, '
        'read_at TEXT, read_by TEXT)',
    ]
    for statement in statements:
        db.execute(statement)
    db.execute('INSERT INTO schema_migrations(name, applied_at) VALUES(?,?)', (SCHEMA, iso()))


# --------------------------------------------------------------------------- relevé SSH
def sections(stdout):
    blocks, current = {}, None
    for line in stdout.splitlines():
        if line.startswith('##') and re.fullmatch(r'##[A-Z]+', line.strip()):
            current = line.strip()[2:]
            blocks.setdefault(current, [])
        elif current:
            blocks[current].append(line.rstrip('\r'))
    return blocks


def release_mismatch(installed, release, os_info=None):
    """Motif de doute sur la release comparée (audit UI du 31/10, fiche 13.2), sinon None.

    Un paquet « +deb12u3 » sur un système annoncé trixie (dépôts mixtes, mise à niveau en
    cours, testing/sid) n'est pas comparable aux correctifs trixie : le déclarer « confirmé »
    transformerait un correctif en migration de distribution.
    """
    built = re.search(r'[+~]deb([0-9]+)', installed or '')
    codename = DEBIAN_CODENAMES.get(built[1]) if built else None
    if codename and release and codename != release:
        return f'paquet construit pour Debian {built[1]} ({codename}) sur un système {release} : dépôts mixtes ou release à vérifier'
    info = os_info or {}
    if info.get('id') == 'debian' and not info.get('version_id'):
        return f'système Debian sans numéro de version ({info.get("pretty") or release}) : testing/sid, correctifs non suivis par release'
    return None


def parse_os(lines):
    values = {}
    for line in lines:
        key, sep, value = line.partition('=')
        if sep and re.fullmatch(r'[A-Z_]+', key):
            values[key] = value.strip().strip('"\'')[:200]
    if not values and lines:
        # /etc/redhat-release : « CentOS Linux release 7.9.2009 (Core) ».
        text = lines[0][:200]
        match = re.search(r'release (\d+)', text)
        family = 'centos' if 'centos' in text.lower() else 'rhel'
        return {'id': family, 'version_id': match[1] if match else '', 'codename': '', 'pretty': text, 'like': 'rhel'}
    os_id = values.get('ID', '').lower()
    version = values.get('VERSION_ID', '')
    major = version.split('.')[0] if os_id not in ('ubuntu',) else version
    codename = values.get('VERSION_CODENAME', '') or (DEBIAN_CODENAMES.get(major, '') if os_id == 'debian' else '')
    return {'id': os_id, 'version_id': version, 'codename': codename.lower(), 'pretty': values.get('PRETTY_NAME', ''),
            'like': values.get('ID_LIKE', '').lower()}


def parse_inventory(stdout):
    """Sortie de `security_packages` -> relevé normalisé. complete=False sans marqueur de fin."""
    blocks = sections(stdout)
    packages, manager = [], None
    for line in blocks.get('PKG', []):
        parts = line.split('|')
        # « gestionnaire|paquet|version|paquet source|version source|architecture »
        if len(parts) != 6 or parts[0] not in ('dpkg', 'rpm'):
            continue
        kind, name, version, source, source_version, arch = parts
        if kind == 'rpm':
            version = source_version = re.sub(r'^0:', '', version)
        source = source or name
        source_version = source_version or version
        if not (PACKAGE.fullmatch(name) and VERSION.fullmatch(version) and PACKAGE.fullmatch(source)
                and VERSION.fullmatch(source_version)):
            continue
        manager = kind
        packages.append({'name': name, 'version': version, 'source': source, 'source_version': source_version,
                         'arch': arch[:20]})
    upgradable = []
    for line in blocks.get('UPGRADABLE', []):
        apt = re.match(r'^([A-Za-z0-9.+_-]+)/(\S+)\s+(\S+)\s+\S+\s+\[upgradable from: ([^\]]+)\]', line)
        if apt:
            upgradable.append({'name': apt[1], 'suite': apt[2][:60], 'candidate': apt[3][:100], 'current': apt[4][:100]})
            continue
        dnf = re.match(r'^([A-Za-z0-9.+_-]+)\.([a-z0-9_]+)\s+(\S+)\s+(\S+)\s*$', line)
        if dnf and VERSION.fullmatch(dnf[3]):
            upgradable.append({'name': dnf[1], 'suite': dnf[4][:60], 'candidate': re.sub(r'^0:', '', dnf[3]), 'current': None})
    changelog = {}
    for line in blocks.get('CHANGELOG', []):
        name, _, cve = line.partition('|')
        if PACKAGE.fullmatch(name) and CVE_ID.fullmatch(cve):
            changelog.setdefault(name, set()).add(cve)
    binaries = {}
    for line in blocks.get('BIN', []):
        name, _, text = line.partition('|')
        if name in ('php', 'apache', 'openssl', 'nginx', 'openssh') and text:
            binaries[name] = redact(text.strip())[:200]
    docker_lines = blocks.get('DOCKER', [])
    docker = {'state': 'absent', 'containers': [], 'images': []}
    if docker_lines and docker_lines[0].startswith('RC|'):
        rc = docker_lines[0][3:].strip()
        rows = [line.split('|') for line in docker_lines[1:] if line.count('|') >= 2]
        denied = any('permission denied' in line.lower() for line in docker_lines)
        docker['state'] = 'denied' if denied else 'ok' if rc == '0' else 'error'
        docker['containers'] = [{'name': r[0][:120], 'image': r[1][:200], 'status': r[2][:120]} for r in rows[:200]] if rc == '0' else []
        docker['images'] = [{'repository': r[0][:200], 'tag': r[1][:120], 'id': r[2][:40], 'created': r[3][:60] if len(r) > 3 else None}
                            for r in (line.split('|') for line in blocks.get('IMAGES', []) if line.count('|') >= 2)][:300]
        swarm = next((line.split('|') for line in blocks.get('SWARM', []) if line.count('|') == 2), None)
        if swarm:
            docker['swarm'] = {'state': swarm[0][:20], 'manager': swarm[1] == 'true', 'server_version': swarm[2][:40] or None}
        docker['services'] = [{'name': r[0][:120], 'image': r[1][:200], 'replicas': r[2][:20]}
                              for r in (line.split('|') for line in blocks.get('SERVICES', []) if line.count('|') == 2)][:200]
    wordpress = []
    for line in blocks.get('WP', []):
        path, _, found = line.partition('|')
        match = re.search(r"wp_version = '([0-9][0-9A-Za-z.-]{0,30})'", found)
        if match and path.startswith('/') and len(path) < 300:
            wordpress.append({'path': path.removesuffix('/wp-includes/version.php'), 'version': match[1]})
    kernel = blocks.get('KERNEL', [])
    return {
        'os': parse_os(blocks.get('OS', [])), 'kernel': (kernel[0][:120] if kernel else None),
        'reboot_required': 'REBOOT_REQUIRED' in kernel, 'manager': manager, 'packages': packages,
        'upgradable': upgradable[:3000], 'changelog': {k: sorted(v) for k, v in changelog.items()},
        'binaries': binaries, 'docker': docker, 'wordpress': wordpress,
        'complete': 'OS' in blocks and 'END' in blocks and bool(packages),
    }


def _ssh_scan(context, host, actor):
    """Relevé des paquets d'un serveur (compte déjà connu en premier, comme les audits)."""
    from config import candidates
    started = time.monotonic()
    if not host.get('ip') or host.get('collect_enabled') is False:
        return {'status': 'disabled', 'detail': 'Collecte désactivée pour ce serveur'}
    row = next((r for r in context.rows() if r['key'] == host['key']), {})
    known = (row.get('ssh_user'), row.get('ssh_port'))
    attempts = list(candidates(context.cfg, host))
    if known[0]:
        attempts.sort(key=lambda c: (c.user, c.port) != known)
    dead, failure = set(), ''
    for candidate in attempts:
        if candidate.port in dead:
            continue
        result = ssh.run_operation(host['ip'], 'security_packages', replace(candidate, timeout=max(candidate.timeout, 10)),
                                   'securite-cve:' + actor)
        if result.rc is not None and '##OS' in result.stdout:
            inventory = parse_inventory(result.stdout)
            inventory['account'] = f'{candidate.user}:{candidate.port}'
            inventory['duration_ms'] = int((time.monotonic() - started) * 1000)
            return {'status': 'ok' if inventory['complete'] else 'partial', 'inventory': inventory,
                    'detail': None if inventory['complete'] else 'Relevé incomplet : aucun paquet lu ou sortie tronquée'}
        failure = (result.stderr.strip().splitlines() or [''])[0][:200] or f'code {result.rc}'
        if result.rc is None and result.error_kind != 'auth':
            dead.add(candidate.port)
    return {'status': 'failed', 'detail': redact(failure) or 'Échec SSH'}


# --------------------------------------------------------------------------- Wazuh
def wazuh_get(connection, path, limit=4 * 1048576, timeout=15, bearer=None):
    """GET sur le même hôte que la connexion Wazuh (ou indexeur), mêmes garde-fous que la
    collecte principale : variable autorisée, HTTPS, destination, CA confinée, liaison."""
    import management
    base = management.ACTIVE_BASE
    ca = str(connection.get('ca_bundle') or '').strip()
    if base is None and ca and not ca.startswith('-----BEGIN CERTIFICATE-----'):
        raise PermissionError('Certificat CA par chemin : racine data/ca/ inconnue de ce processus')
    refusal = management.connection_refusal(connection, base)
    if refusal:
        raise PermissionError(refusal)
    tls = management.ssl_context_for(management.transport_for(connection, base) if base is not None else connection)
    headers = {'Accept': 'application/json'}
    if bearer:
        headers['Authorization'] = 'Bearer ' + bearer
    else:
        token = os.getenv(connection.get('token_env') or '', '')
        if not token:
            raise PermissionError('Jeton de la connexion absent de ce processus')
        headers['Authorization'] = token
    opener = management.api_opener(tls)
    url = urllib.parse.urlsplit(connection['url'])._replace(path=path.split('?')[0],
                                                             query=path.partition('?')[2]).geturl()
    with opener.open(urllib.request.Request(url, headers=headers), timeout=timeout) as response:
        body = response.read(limit + 1)
    if len(body) > limit:
        raise ValueError('Réponse trop volumineuse')
    return management.strict_json(body)


def _wazuh_items(rows):
    """Détections Wazuh (API manager ≤ 4.7 ou indexeur ≥ 4.8) -> forme commune."""
    out = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        src = row.get('_source') if isinstance(row.get('_source'), dict) else None
        if src is not None:
            vuln, package = src.get('vulnerability') or {}, src.get('package') or {}
            cve, name, version = vuln.get('id'), package.get('name'), package.get('version')
            score = (vuln.get('score') or {}).get('base')
            severity, reference, detected = vuln.get('severity'), vuln.get('reference'), vuln.get('detected_at')
            fixed = None
        else:
            if str(row.get('status') or '').upper() == 'SOLVED':
                continue
            cve, name, version = row.get('cve'), row.get('name'), row.get('version')
            score = row.get('cvss3_score') or row.get('cvss2_score')
            severity, detected = row.get('severity'), row.get('detection_time')
            refs = row.get('external_references') or []
            reference = refs[0] if isinstance(refs, list) and refs else None
            match = re.search(r'less than ([A-Za-z0-9.:+~_-]+)', str(row.get('condition') or ''))
            fixed = match[1] if match else None
        if not (CVE_ID.fullmatch(str(cve or '')) and PACKAGE.fullmatch(str(name or ''))):
            continue
        out.append({'cve': cve, 'package': name, 'version': version if VERSION.fullmatch(str(version or '')) else None,
                    'fixed': fixed if fixed and VERSION.fullmatch(fixed) else None,
                    'cvss': float(score) if isinstance(score, (int, float)) else None,
                    'severity': str(severity or '')[:20].lower() or None,
                    'reference': str(reference)[:300] if reference else None, 'detected_at': str(detected or '')[:40] or None})
    return out


def _legacy_vulns(connection, agent, jwt):
    """API du manager Wazuh ≤ 4.7 : /vulnerability/<agent>, paginée (5 000 au plus)."""
    items, offset, total = [], 0, None
    while offset < 5000:
        data = wazuh_get(connection, f'/vulnerability/{agent["id"]}?limit=500&offset={offset}', bearer=jwt)
        page = (data.get('data') or {}) if isinstance(data, dict) else {}
        rows = page.get('affected_items') or []
        total = page.get('total_affected_items', len(rows))
        items += _wazuh_items(rows)
        offset += 500
        if not rows or offset >= (total or 0):
            break
    return items, total is not None and offset >= total


def _indexer_vulns(indexer, agent):
    """Indexeur Wazuh ≥ 4.8 : index wazuh-states-vulnerabilities-*, recherche par agent."""
    data = wazuh_get(indexer, '/wazuh-states-vulnerabilities-*/_search?size=2000&track_total_hits=true'
                     f'&q=agent.id:{agent["id"]}', limit=16 * 1048576)
    hits = (data.get('hits') or {}) if isinstance(data, dict) else {}
    rows = hits.get('hits') or []
    total = hits['total'].get('value', len(rows)) if isinstance(hits.get('total'), dict) else len(rows)
    return _wazuh_items(rows), len(rows) >= total


def sync_wazuh(context, stop=None):
    """Vulnérabilités Wazuh par agent rapproché SANS ambiguïté d'un serveur de l'inventaire."""
    import management
    from asset_registry import MatchIndex
    results = []
    connections = [c for c in context.api_connections() if c.get('provider') == 'Wazuh']
    indexer_key = (context.read_setting('security_wazuh_indexer') or os.getenv('INFRAOPS_WAZUH_INDEXER', '')).strip()
    indexer = next((c for c in context.api_connections() if c.get('key') == indexer_key
                    and c.get('provider') == 'Elasticsearch'), None) if indexer_key else None
    hosts = context.rows()
    index = MatchIndex(hosts)
    for connection in connections:
        last = connection.get('last_result') or connection.get('last_success_result') or {}
        agents = (last.get('inventory') or {}).get('agents_inventory') or []
        summary = {'source': 'wazuh:' + connection['key'], 'agents': 0, 'items': 0, 'errors': 0, 'mode': None, 'error': None}
        mapping = []
        for host in hosts:
            matched = index.items_for(host, connection, 'wazuh', agents, 'ip', ('name',))
            if len(matched) == 1:
                agent, names, ips = matched[0]
                if len(index.owners(names, ips)) == 1 and str(agent.get('id') or '').isdigit() and agent.get('id') != '000':
                    mapping.append((host, agent))
        summary['agents'] = len(mapping)
        if not mapping:
            summary['error'] = 'Aucun agent Wazuh rapproché d’un serveur (collecter Wazuh, vérifier noms et IP)'
            results.append(summary)
            continue
        jwt, auth_error = None, None
        token = os.getenv(connection.get('token_env') or '', '')
        try:
            if not token:
                raise PermissionError('Jeton Wazuh absent de ce processus')
            refusal = management.connection_refusal(connection, management.ACTIVE_BASE)
            if refusal:
                raise PermissionError(refusal)
            tls = management.ssl_context_for(management.transport_for(connection, management.ACTIVE_BASE)
                                             if management.ACTIVE_BASE is not None else connection)
            jwt = management.wazuh_token(connection['url'], token, tls, 10)
        except Exception as exc:  # noqa: BLE001 — l'échec est rapporté, aucune donnée n'est effacée
            auth_error = 'Authentification Wazuh : ' + management.collection_error(exc)['error']
        if jwt is None and indexer is None:
            summary['error'] = auth_error
            results.append(summary)
            continue
        legacy = jwt is not None
        for host, agent in mapping:
            if stop is not None and stop.is_set():
                break
            try:
                items, complete = _legacy_vulns(connection, agent, jwt) if legacy else _indexer_vulns(indexer, agent)
                summary['mode'] = 'API du manager (≤ 4.7)' if legacy else 'Indexeur Wazuh (≥ 4.8)'
            except Exception as exc:  # noqa: BLE001 — repli vers l'indexeur, puis erreur rapportée
                if not (legacy and getattr(exc, 'code', None) == 404):
                    summary['errors'] += 1
                    summary['error'] = ('Agent ' + str(agent.get('id')) + ' : ' if legacy else 'Indexeur Wazuh : ') + \
                        management.collection_error(exc)['error']
                    continue
                # Wazuh ≥ 4.8 : l'API du manager n'expose plus /vulnerability ; l'indexeur prend le relais.
                legacy = False
                if indexer is None:
                    summary['error'] = ('API /vulnerability absente (Wazuh ≥ 4.8) : déclarer l’indexeur Wazuh comme '
                                        'connexion Elasticsearch et la sélectionner dans les réglages Sécurité')
                    break
                try:
                    items, complete = _indexer_vulns(indexer, agent)
                    summary['mode'] = 'Indexeur Wazuh (≥ 4.8)'
                except Exception as exc2:  # noqa: BLE001
                    summary['errors'] += 1
                    summary['error'] = 'Indexeur Wazuh : ' + management.collection_error(exc2)['error']
                    continue
            summary['items'] += len(items)
            with context.connect() as db:
                db.execute('INSERT OR REPLACE INTO sec_wazuh(host_key, connection, agent_id, at, complete, items) VALUES(?,?,?,?,?,?)',
                           (host['key'], connection['key'], str(agent['id']), iso(), int(complete), json.dumps(items)))
        results.append(summary)
    return results


# --------------------------------------------------------------------------- veille
# Collecte en ligne : security_watch.py (état des sources, débit, EPSS, NVD par produit).
_record_sync = security_watch.record_sync
_store_advisories = security_watch.store_advisories


def sync_feeds(context, stop=None, fetch=None, force=False, pacer=None):
    """Synchronise toutes les sources publiques ; chaque source échoue seule."""
    return security_watch.sync(context, stop, fetch, force, pacer)


# --------------------------------------------------------------------------- analyse
def _load_inventory(db, host_key):
    row = db.execute('SELECT host_ip, collected_at, complete, payload FROM sec_inventory WHERE host_key=?', (host_key,)).fetchone()
    if not row:
        return None
    data = json.loads(row[3])
    data.update(host_ip=row[0], collected_at=row[1], complete=bool(row[2]))
    return data


def _load_wazuh(db, host_key):
    row = db.execute('SELECT connection, agent_id, at, complete, items FROM sec_wazuh WHERE host_key=?', (host_key,)).fetchone()
    if not row:
        return None
    return {'connection': row[0], 'agent_id': row[1], 'at': row[2], 'complete': bool(row[3]), 'items': json.loads(row[4])}


def _fresh(stamp, hours):
    try:
        return now() - datetime.fromisoformat(stamp) <= timedelta(hours=hours)
    except (TypeError, ValueError):
        return False


def detect(db, host, inventory, wazuh):
    """Détections actuelles d'un serveur et sources qui l'ont réellement mesuré.

    Renvoie ({cve: détection}, {sources mesurées}). Pure lecture de la base."""
    found, measured = {}, set()
    inv = inventory or {}
    os_info = inv.get('os') or {}
    by_binary = {p['name']: p for p in inv.get('packages') or []}
    by_source = {}
    for p in inv.get('packages') or []:
        by_source.setdefault(p['source'], []).append(p)
    upgradable = {u['name']: u for u in inv.get('upgradable') or []}
    changelog = {name: set(cves) for name, cves in (inv.get('changelog') or {}).items()}
    release = os_info.get('codename') if os_info.get('id') == 'debian' else None
    if release and inv.get('complete') and inv.get('manager') == 'dpkg':
        fixes = db.execute('SELECT advisory, package, fixed, cves, date, origin FROM sec_fixes WHERE release=?', (release,)).fetchall()
        if fixes:
            measured.add('debian')
        for advisory, source, fixed, cves, published, origin in fixes:
            binaries = by_source.get(source)
            if not binaries:
                continue
            installed = binaries[0]['source_version']
            older = security_versions.is_older('dpkg', installed, fixed)
            if not older:
                continue
            doubt = release_mismatch(installed, release, os_info)
            for cve in json.loads(cves) or []:
                names = sorted(b['name'] for b in binaries)
                mentioned = sorted(n for n in names if cve in changelog.get(n, set()))
                candidates = [upgradable[n] for n in names if n in upgradable]
                available = next((c for c in candidates if security_versions.is_older('dpkg', c['candidate'], fixed) is False), None)
                current = found.get(cve)
                if current and security_versions.is_older('dpkg', current['fixed'] or '0', fixed) is False:
                    current['evidence']['advisories'].append(advisory)
                    continue
                # Plusieurs avis pour la même CVE (régression, DLA après DSA) : la version
                # corrigée la plus récente fait foi, les avis précédents restent cités.
                previous = current['evidence']['advisories'] if current else []
                found[cve] = {
                    'cve': cve, 'package': source, 'installed': installed, 'fixed': fixed, 'sources': {'debian'},
                    'evidence': {
                        'manager': 'dpkg', 'release': release, 'advisories': previous + [advisory], 'origin': origin,
                        'source': f'Debian Security Tracker ({advisory}, {release})', 'published': published,
                        'comparison': f'dpkg : {installed} < {fixed} (version corrigée publiée pour {release})',
                        'binaries': names, 'binary_versions': {b['name']: b['version'] for b in binaries},
                        'changelog_mentions': mentioned, 'release_mismatch': doubt,
                        'repository': (f'Correctif disponible dans les dépôts configurés : {available["candidate"]} ({available["suite"]})'
                                       if available else 'Version corrigée non proposée par les dépôts configurés '
                                       '(dépôt security absent ou cache apt ancien)'),
                        'collected_at': inv.get('collected_at'),
                    }}
    if wazuh and wazuh.get('complete') and _fresh(wazuh.get('at'), 72):
        measured.add('wazuh')
    for item in (wazuh or {}).get('items') or []:
        cve = item['cve']
        binary = by_binary.get(item['package'])
        source = binary['source'] if binary else item['package']
        current = found.get(cve)
        wazuh_evidence = {'package': item['package'], 'version': item['version'], 'fixed': item['fixed'],
                          'severity': item['severity'], 'cvss': item['cvss'], 'reference': item['reference'],
                          'detected_at': item['detected_at'], 'agent': wazuh.get('agent_id'), 'at': wazuh.get('at')}
        if current:
            current['sources'].add('wazuh')
            current['evidence']['wazuh'] = wazuh_evidence
            continue
        siblings = sorted(p['name'] for p in by_source.get(source, [])) or [item['package']]
        found[cve] = {
            'cve': cve, 'package': source, 'installed': binary['version'] if binary else item['version'],
            'fixed': item['fixed'], 'sources': {'wazuh'},
            'evidence': {'manager': inv.get('manager'), 'source': 'Wazuh Vulnerability Detection', 'wazuh': wazuh_evidence,
                         'binaries': siblings, 'binary_versions': {p['name']: p['version'] for p in by_source.get(source, [])},
                         'changelog_mentions': sorted(n for n in siblings if cve in changelog.get(n, set())),
                         'version_changed': bool(binary and item['version'] and binary['version'] != item['version']),
                         'collected_at': inv.get('collected_at')}}
    for detection in found.values():
        ev = detection['evidence']
        if ev.get('release_mismatch'):
            confidence, reason = 'à vérifier', ev['release_mismatch']
        elif ev.get('changelog_mentions'):
            confidence, reason = 'à vérifier', ('CVE citée dans le changelog de ' + ', '.join(ev['changelog_mentions']) +
                                                ' : correctif probablement rétroporté')
        elif ev.get('version_changed'):
            confidence, reason = 'à vérifier', 'version installée différente de celle analysée par Wazuh'
        elif detection['sources'] == {'debian', 'wazuh'}:
            confidence, reason = 'confirmé', 'Debian et Wazuh concordent'
        elif 'debian' in detection['sources']:
            confidence, reason = 'confirmé', 'version installée antérieure à la version corrigée de la même release'
        else:
            confidence, reason = 'détecté', 'détection Wazuh'
        ev.update(confidence=confidence, reason=reason)
        detection['confidence'] = confidence
    return found, measured


_notify = security_alerts.notify


def event(db, vid, actor, auth, action, detail=None):
    db.execute('INSERT INTO sec_events(vuln_id, at, actor, auth, action, detail) VALUES(?,?,?,?,?,?)',
               (vid, iso(), actor, auth, action, redact(str(detail))[:1000] if detail else None))


def cve_index(db):
    """CVE corrélables (plages NVD ou avis d'éditeur), indexées par technologie."""
    records = {}
    for cve, config, cvss, kev, epss in db.execute(
            "SELECT cve, nvd_config, cvss, kev, epss FROM sec_cve WHERE nvd_config IS NOT NULL AND nvd_config != '[]'"):
        records[cve] = {'cve': cve, 'nvd_config': json.loads(config), 'advisories': [], 'cvss': cvss, 'kev': bool(kev), 'epss': epss}
    for source, ident, cves, ranges in db.execute('SELECT source, id, cves, ranges FROM sec_advisories WHERE ranges IS NOT NULL'):
        # Avis d'éditeur sans CVE (fréquent chez WordPress) : identifié par son GHSA.
        for key in json.loads(cves) or [ident]:
            entry = records.setdefault(key, {'cve': key, 'nvd_config': [], 'advisories': [], 'cvss': None, 'kev': False, 'epss': None})
            entry['advisories'].append({'source': source, 'label': feeds.SOURCES.get(source, ('', '', source))[2],
                                        'ranges': json.loads(ranges)})
    index = {}
    for record in records.values():
        for tech in correlation.TECHS:
            if correlation.ranges_for(tech, record):
                index.setdefault(tech, []).append(record)
    return index


def correlate_host(db, host, inventory, wazuh, index, stamp):
    """Applicabilité par technologie (sec_matches) ; renvoie les détections confirmées hors
    paquets de distribution (déjà couverts par Debian et Wazuh) et les sources mesurées."""
    insts = correlation.instances(host, inventory)
    facts = correlation.host_context(db, host, inventory, wazuh)
    ids = {correlation.instance_id(host['key'], i['tech'], i['instance']) for i in insts}
    decisions = {(r[0], r[1]): r[2:] for r in db.execute('SELECT id, cve, decision, note, actor FROM sec_match_decisions')
                 if r[0] in ids}
    current = {}
    for inst in insts:
        mid = correlation.instance_id(host['key'], inst['tech'], inst['instance'])
        for record in index.get(inst['tech'], []):
            result = correlation.classify(inst, record, host, facts)
            if not result:
                continue
            decision = decisions.get((mid, record['cve']))
            # Décision humaine : seulement sur une applicabilité restée incertaine.
            if decision and result['status'] == 'potential':
                kind, note, who = decision
                result = {**result, 'status': 'confirmed' if kind == 'confirm' else 'not_applicable', 'decision': kind,
                          'reason': ('Confirmée' if kind == 'confirm' else 'Déclarée non applicable') + f' par {who} après vérification'
                          + (f' : {note}' if note else '') + f' ({result["reason"]})'}
            current[(mid, record['cve'])] = (inst, result)
    for (mid, cve), (inst, r) in current.items():
        db.execute('INSERT INTO sec_matches(id, cve, host_key, tech, instance, version, origin, status, reason, fixed, source, '
                   'first_seen, last_seen, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id, cve) DO UPDATE SET '
                   'version=excluded.version, origin=excluded.origin, status=excluded.status, reason=excluded.reason, '
                   'fixed=excluded.fixed, source=excluded.source, last_seen=excluded.last_seen, updated_at=CASE WHEN '
                   'sec_matches.status != excluded.status THEN excluded.updated_at ELSE sec_matches.updated_at END',
                   (mid, cve, host['key'], inst['tech'], inst['instance'], inst['version'] or (inst['branch'] and inst['branch'] + '.x'),
                    inst['origin'], r['status'], r['reason'][:500], r['fixed'], r['source'], stamp, stamp, stamp))
    complete = bool((inventory or {}).get('complete')) or (not inventory and bool(insts))
    if complete:
        # Instance disparue ou CVE plus concernée : la correspondance est retirée.
        for mid, cve in db.execute('SELECT id, cve FROM sec_matches WHERE host_key=?', (host['key'],)).fetchall():
            if (mid, cve) not in current:
                db.execute('DELETE FROM sec_matches WHERE id=? AND cve=?', (mid, cve))
    upstream = {}
    for (mid, cve), (inst, r) in current.items():
        if r['status'] != 'confirmed' or (inst['origin'] == 'distro' and not r.get('decision')):
            continue
        entry = upstream.setdefault(cve, {
            'cve': cve, 'package': inst['package'] or inst['tech'], 'installed': inst['version'] or (inst['branch'] and inst['branch'] + '.x'),
            'fixed': r['fixed'] if VERSION.fullmatch(str(r['fixed'] or '')) else None, 'sources': set(), 'confidence': 'confirmé',
            'evidence': {'manager': inst['manager'], 'tech': inst['tech'], 'source': r['source'] + ' (version amont)',
                         'reason': r['reason'], 'confidence': 'confirmé', 'instances': [],
                         'binaries': [inst['package']] if inst['package'] else [], 'binary_versions': {},
                         'changelog_mentions': [], 'collected_at': (inventory or {}).get('collected_at')}})
        entry['sources'].add('manual' if r.get('decision') else 'upstream')
        entry['evidence']['instances'].append({'instance': inst['instance'], 'version': inst['version'] or inst['branch'],
                                               'origin': inst['origin'], 'detail': inst['detail'], 'fixed': r['fixed']})
    measured = {'upstream', 'manual'} if complete and index else set()
    return upstream, measured


def analyze_host(db, host, index=None):
    """Applique les détections actuelles : création, mise à jour, réouverture, correction constatée."""
    inventory, wazuh = _load_inventory(db, host['key']), _load_wazuh(db, host['key'])
    found, measured = detect(db, host, inventory, wazuh)
    upstream, measured_upstream = correlate_host(db, host, inventory, wazuh, cve_index(db) if index is None else index, iso())
    for cve, d in upstream.items():
        if cve in found:
            found[cve]['sources'] |= d['sources']
            found[cve]['evidence']['instances'] = d['evidence']['instances']
        else:
            found[cve] = d
    measured |= measured_upstream
    stamp = iso()
    existing = {r[0]: r for r in db.execute('SELECT id, cve, status, sources FROM sec_vulns WHERE host_key=?', (host['key'],))}
    counts = {'new': 0, 'resolved': 0, 'reopened': 0}
    for cve, d in found.items():
        vid = vuln_id(host['key'], cve)
        sources = sorted(d['sources'])
        values = (d['package'], d['installed'], d['fixed'], json.dumps(sources), d['confidence'], json.dumps(d['evidence']), stamp)
        if vid in existing:
            status = existing[vid][2]
            db.execute('UPDATE sec_vulns SET package=?, installed=?, fixed=?, sources=?, confidence=?, evidence=?, last_seen=?, '
                       'updated_at=? WHERE id=?', values + (stamp, vid))
            if status == 'resolved':
                db.execute("UPDATE sec_vulns SET status='open', resolved_at=NULL WHERE id=?", (vid,))
                event(db, vid, 'OpsControl', 'system', 'reopened', 'Vulnérabilité de nouveau détectée : ' + d['evidence']['reason'])
                counts['reopened'] += 1
        else:
            db.execute('INSERT INTO sec_vulns(id, host_key, cve, package, installed, fixed, sources, confidence, evidence, status, '
                       'first_seen, last_seen, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                       (vid, host['key'], cve) + values[:6] + ('open', stamp, stamp, stamp))
            event(db, vid, 'OpsControl', 'system', 'detected', d['evidence']['source'] + ' — ' + d['evidence']['reason'])
            counts['new'] += 1
        db.execute('INSERT OR IGNORE INTO sec_cve(cve) VALUES(?)', (cve,))
    for vid, (_, cve, status, sources) in existing.items():
        if cve in found or status not in ACTIVE:
            continue
        # Correction constatée seulement si CHAQUE source de la détection a mesuré ce serveur.
        if set(json.loads(sources)) <= measured:
            db.execute("UPDATE sec_vulns SET status='resolved', resolved_at=?, updated_at=? WHERE id=?", (stamp, stamp, vid))
            event(db, vid, 'OpsControl', 'system', 'resolved', 'Absente de l’analyse du ' + stamp[:16].replace('T', ' ') +
                  ' (sources : ' + ', '.join(sorted(measured)) + ')')
            counts['resolved'] += 1
    return counts


# Relevé SSH et veille finissent chacun par une analyse : une seule à la fois, sinon la
# seconde attendait le verrou d'écriture SQLite et pouvait échouer (« database is locked »).
_ANALYSIS = threading.Lock()


def analyze(context, keys=None):
    """Analyse de tous les serveurs (ou de `keys`), puis notifications ciblées."""
    with _ANALYSIS:
        return _analyze(context, keys)


def _analyze(context, keys):
    hosts = [h for h in context.HOSTS if keys is None or h['key'] in keys]
    totals = {'hosts': 0, 'new': 0, 'resolved': 0, 'reopened': 0}
    try:
        threshold = float(context.read_setting('security_epss_threshold') or 0.5)
    except ValueError:
        threshold = 0.5
    exposed = security_alerts.exposure(context.rows())
    with context.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        index = cve_index(db)
        for host in hosts:
            counts = analyze_host(db, host, index)
            totals['hosts'] += 1
            for k in ('new', 'resolved', 'reopened'):
                totals[k] += counts[k]
        totals['alerts'] = security_alerts.evaluate(db, context, exposed, threshold)
    return totals


# --------------------------------------------------------------------------- vues
def _decode(row, names):
    item = dict(zip(names, row))
    for key in ('sources', 'evidence'):
        if key in item and isinstance(item[key], str):
            item[key] = json.loads(item[key])
    return item


VULN_COLUMNS = ('id', 'host_key', 'cve', 'package', 'installed', 'fixed', 'sources', 'confidence', 'evidence', 'status',
                'first_seen', 'last_seen', 'resolved_at', 'owner', 'owner_auth', 'note', 'updated_at')


def _severity(item):
    if item.get('cvss') is not None:
        return feeds.severity_of(item['cvss'])
    wazuh = (item.get('evidence') or {}).get('wazuh') or {}
    if wazuh.get('cvss') is not None:
        return feeds.severity_of(wazuh['cvss'])
    return wazuh.get('severity') if wazuh.get('severity') in SEVERITY_LABELS else None


def vulns(db, hosts, where='1=1', params=()):
    names = {h['key']: h for h in hosts}
    cur = db.execute('SELECT ' + ', '.join('v.' + c for c in VULN_COLUMNS) + ', c.cvss, c.kev, c.kev_due, c.description, '
                     'c.vector FROM sec_vulns v LEFT JOIN sec_cve c ON c.cve=v.cve WHERE ' + where, params)  # nosec B608 — fragments internes
    out = []
    for row in cur.fetchall():
        item = _decode(row[:len(VULN_COLUMNS)], VULN_COLUMNS)
        item.update(cvss=row[-5], kev=bool(row[-4]), kev_due=row[-3], description=row[-2], vector=row[-1])
        host = names.get(item['host_key']) or {}
        item.update(host_name=host.get('name') or item['host_key'], host_ip=host.get('ip'), environment=host.get('environment'),
                    in_inventory=bool(host), status_label=STATUS_LABELS.get(item['status'], item['status']))
        item['severity'] = _severity(item)
        item['priority'] = (1000 if item['kev'] else 0) + int((item['cvss'] or (item['evidence'].get('wazuh') or {}).get('cvss') or 0) * 10) + \
            (50 if str(item.get('environment') or '').lower().startswith('prod') else 0)
        out.append(item)
    out.sort(key=lambda v: (-v['priority'], v['host_name'], v['cve']))
    return out


def os_support(os_info, today=None):
    """Fin de support de sécurité connue du système, ou None (jamais deviné)."""
    os_info = os_info or {}
    key = os_info.get('id')
    version = str(os_info.get('version_id') or '')
    major = version if key == 'ubuntu' else version.split('.')[0]
    end = OS_EOL.get((key, major))
    if not end:
        return None
    today = today or date.today()
    return {'until': end, 'expired': date.fromisoformat(end) < today,
            'label': ('Hors support de sécurité depuis le ' if date.fromisoformat(end) < today else 'Support de sécurité jusqu’au ') +
            date.fromisoformat(end).strftime('%d/%m/%Y')}


def image_findings(images, today=None):
    """Images Docker à vérifier : version amont hors support, ou tag non figé."""
    today = today or date.today()
    out = []
    for image in images or []:
        repo, tag = str(image.get('repository') or ''), str(image.get('tag') or '')
        name = repo.rsplit('/', 1)[-1]
        if tag in ('latest', '', '<none>'):
            out.append({**image, 'finding': 'Tag non figé : version réelle à vérifier', 'level': 'unknown'})
            continue
        for image_name, prefix, end in IMAGE_EOL:
            if name == image_name and (tag == prefix or (tag.startswith(prefix) and (prefix.endswith('.') or len(tag) == len(prefix)
                                                                                      or not tag[len(prefix)].isdigit()))):
                if date.fromisoformat(end) < today:
                    out.append({**image, 'finding': f'{name} {prefix.rstrip(".")} hors support amont depuis le '
                                f'{date.fromisoformat(end).strftime("%d/%m/%Y")} : plus de correctifs de sécurité',
                                'level': 'warning'})
                break
    return out


def components(inventory):
    """Composants clés installés (versions des paquets, puis version annoncée par le binaire)."""
    out = []
    packages = (inventory or {}).get('packages') or []
    for label, pattern in COMPONENTS:
        rows = [p for p in packages if re.fullmatch(pattern, p['source']) or re.fullmatch(pattern, p['name'])]
        if rows:
            versions = sorted({p['source_version'] for p in rows})
            out.append({'component': label, 'packages': sorted({p['name'] for p in rows})[:12], 'versions': versions[:6]})
    binaries = (inventory or {}).get('binaries') or {}
    for item in out:
        for key, label in (('php', 'PHP'), ('apache', 'Apache HTTP Server'), ('openssl', 'OpenSSL'), ('nginx', 'nginx'),
                           ('openssh', 'OpenSSH')):
            if item['component'] == label and binaries.get(key):
                item['binary'] = binaries[key]
    return out


# --------------------------------------------------------------------------- ITSM / GLPI
def vuln_snapshot(context, ident):
    """Données du ticket GLPI, relues côté serveur ; refus si la vulnérabilité n'est pas validée."""
    with context.connect() as db:
        rows = vulns(db, context.rows(), 'v.id=?', (ident,))
        inventory = _load_inventory(db, rows[0]['host_key']) if rows else None
        cve = _cve(db, rows[0]['cve']) if rows else None
    if not rows:
        raise HTTPException(404, 'Vulnérabilité inconnue')
    v = rows[0]
    if v['status'] not in ('validated', 'in_progress'):
        raise HTTPException(409, 'Valider la vulnérabilité avant de créer un ticket GLPI')
    host = next((h for h in context.rows() if h['key'] == v['host_key']), {'key': v['host_key'], 'name': v['host_key']})
    procedure = security_remediation.plan(v, host, inventory, cve)
    ev = v['evidence']
    severity = 'critical' if v['kev'] or (v['cvss'] or 0) >= 9 else 'warning' if (v['cvss'] or 0) >= 7 else 'preventive'
    data = {
        'title': f'{v["cve"]} — {v["package"]} {v["installed"] or ""}'.strip() + (' (exploitée, CISA KEV)' if v['kev'] else ''),
        'severity': severity, 'state': STATUS_LABELS[v['status']], 'source': 'OpsControl Sécurité — ' + str(ev.get('source')),
        'target': host.get('name'), 'ip': host.get('ip'), 'environment': host.get('environment'),
        'evidence': '\n'.join(filter(None, [
            f'Paquet : {v["package"]} ({", ".join(ev.get("binaries") or [])})',
            f'Version installée : {v["installed"]} — version corrigée : {v["fixed"] or "non fournie"}',
            ev.get('comparison'), ev.get('repository'), f'Confiance : {v["confidence"]} ({ev.get("reason")})',
            f'CVSS : {v["cvss"]}' if v['cvss'] is not None else None,
            f'CISA KEV : échéance {v["kev_due"]}' if v['kev'] else None])),
        'observed_at': v['last_seen'], 'opened_at': v['first_seen'], 'rule': v['cve'],
        'recommendation': '\n'.join(['Mise à jour : ' + ' ; '.join(procedure['update'] or ['à établir']),
                                     'Vérification : ' + ' ; '.join(procedure['verify'][:3]),
                                     'Retour arrière : ' + ' ; '.join(procedure['rollback'][:2]),
                                     'Sauvegarde : ' + procedure['backup_required'],
                                     'Procédure complète : OpsControl > Sécurité > Correctifs.']),
    }
    if v['owner']:
        data.update(owner=v['owner'], owner_auth=v['owner_auth'] or 'local')
    return v['id'], data


def vuln_states(context, ids):
    """État d'origine des dossiers ITSM : active, resolved ou None (faux positif, risque accepté)."""
    if not ids:
        return {}
    with context.connect() as db:
        marks = ','.join('?' * len(ids))
        rows = db.execute('SELECT id, status FROM sec_vulns WHERE id IN (' + marks + ')', tuple(ids)).fetchall()  # nosec B608
    return {ident: 'active' if status in ACTIVE else 'resolved' if status == 'resolved' else None for ident, status in rows}


def _cve(db, cve):
    row = db.execute('SELECT cvss, severity, vector, cvss_version, description, published, nvd_at, kev, kev_added, kev_due, '
                     'kev_action, kev_ransomware FROM sec_cve WHERE cve=?', (cve,)).fetchone()
    if not row:
        return None
    names = ('cvss', 'severity', 'vector', 'cvss_version', 'description', 'published', 'nvd_at', 'kev', 'kev_added',
             'kev_due', 'kev_action', 'kev_ransomware')
    out = dict(zip(names, row))
    out['kev'] = bool(out['kev'])
    return out


# --------------------------------------------------------------------------- API
class Scan(BaseModel):
    model_config = ConfigDict(extra='forbid')
    host_key: str = Field(default='', max_length=80)
    by: str = Field(default='', max_length=120)


class VulnAction(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: str = Field(pattern=r'^[0-9a-f]{20}$')
    action: Literal['validate', 'start', 'false_positive', 'accept_risk', 'reopen', 'assign', 'note']
    note: str = Field(default='', max_length=2000)
    owner: str = Field(default='', max_length=120)
    by: str = Field(default='', max_length=120)


class NotificationsRead(BaseModel):
    model_config = ConfigDict(extra='forbid')
    ids: list[int] = Field(default_factory=list, max_length=500)
    all: bool = False
    by: str = Field(default='', max_length=120)


class Settings(BaseModel):
    model_config = ConfigDict(extra='forbid')
    feeds_auto: bool = True
    feeds_hours: Literal[1, 3, 6, 12, 24] = 1
    scan_hours: Literal[0, 24, 168] = 0
    wazuh_indexer: str = Field(default='', pattern=r'^(?:[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79})?$')
    # Destinataires (non secrets) ; le serveur SMTP et son mot de passe restent dans l'environnement.
    mail_to: str = Field(default='', max_length=1000, pattern=r'^[A-Za-z0-9._%+@,; -]*$')
    mail_level: Literal['critical', 'warning'] = 'critical'
    epss_threshold: float = Field(default=0.5, ge=0.01, le=1)


class MatchDecision(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: str = Field(pattern=r'^[0-9a-f]{20}$')
    cve: str = Field(pattern=r'^(CVE-\d{4}-\d{4,7}|GHSA(-[a-z0-9]{4}){3})$')
    decision: Literal['confirm', 'not_applicable', 'reset']
    note: str = Field(default='', max_length=2000)
    by: str = Field(default='', max_length=120)


TRANSITIONS = {
    'validate': (('open',), 'validated'),
    'start': (('open', 'validated'), 'in_progress'),
    'false_positive': (('open', 'validated', 'in_progress'), 'false_positive'),
    'accept_risk': (('open', 'validated', 'in_progress'), 'accepted_risk'),
    'reopen': (('false_positive', 'accepted_risk'), 'open'),
}
ACTION_LABELS = {'validate': 'Validée', 'start': 'Correction planifiée', 'false_positive': 'Déclarée faux positif',
                 'accept_risk': 'Risque accepté', 'reopen': 'Rouverte', 'assign': 'Responsable désigné', 'note': 'Note'}
FEEDS_FIRST_DELAY = 300  # première synchronisation 5 min après le démarrage


def feeds_auto(context):
    """Veille automatique : ACTIVE par défaut (GET HTTPS sortants uniquement) ; « 0 » la coupe."""
    return (context.read_setting('security_feeds_auto') or '1') == '1'


def feeds_hours(context):
    try:
        value = int(context.read_setting('security_feeds_hours') or 1)
    except ValueError:
        return 1
    return value if value in (1, 3, 6, 12, 24) else 1


def install(app, context):
    import operator_identity
    router = APIRouter()
    if not getattr(context, 'SCHEMA_DEFERRED', False):  # autre instance active : aucun DDL (OC-AUDIT-014)
        with context.connect() as db:
            migrate(db)
    lock = threading.Lock()
    # Deux travaux INDÉPENDANTS : le relevé SSH du parc (sessions SSH) et la veille (GET HTTPS
    # vers Internet + Wazuh). Un seul de chaque à la fois ; ils ne s'attendent plus l'un
    # l'autre : un relevé de 97 serveurs bloquait la veille, restée « jamais synchronisée ».
    blank = {'running': False, 'kind': None, 'started_at': None, 'finished_at': None, 'completed': 0, 'total': 0,
             'error': None, 'actor': None, 'result': None}
    jobs = {'scan': {**blank, 'kind': 'scan'}, 'sync': {**blank, 'kind': 'sync'}}
    stop = threading.Event()
    # Veille : premier passage FEEDS_FIRST_DELAY après le démarrage, puis selon la fréquence choisie.
    last_auto = {'feeds': time.time() - feeds_hours(context) * 3600 + FEEDS_FIRST_DELAY, 'scan': 0.0}

    def actor(request, declared):
        name, mode = operator_identity.actor(request.headers, declared)
        if not name:
            raise HTTPException(422, 'Nom requis en mode local non authentifié')
        return name, mode

    def hosts_for(keys):
        return [h for h in context.HOSTS if keys is None or h['key'] in keys]

    def scan_hosts(hosts, who):
        def one(host):
            try:
                outcome = _ssh_scan(context, host, who)
            except Exception as exc:  # noqa: BLE001 — un serveur en échec n'arrête pas le lot
                outcome = {'status': 'failed', 'detail': type(exc).__name__}
            with context.connect() as db:
                inv = outcome.get('inventory')
                # Seul un relevé COMPLET remplace le précédent : un relevé tronqué ferait
                # disparaître des paquets, donc « corriger » des vulnérabilités à tort.
                if inv and inv['complete']:
                    db.execute('INSERT OR REPLACE INTO sec_inventory(host_key, host_ip, collected_at, complete, payload) VALUES(?,?,?,?,?)',
                               (host['key'], host.get('ip'), iso(), int(inv['complete']), json.dumps(inv)))
                db.execute('INSERT INTO sec_scans(host_key, at, status, detail, packages, duration_ms, actor) VALUES(?,?,?,?,?,?,?)',
                           (host['key'], iso(), outcome['status'], outcome.get('detail'), len((inv or {}).get('packages') or []),
                            (inv or {}).get('duration_ms'), who))
            with lock:
                jobs['scan']['completed'] += 1
        with ThreadPoolExecutor(max_workers=max(1, min(8, context.WORKERS))) as pool:
            list(pool.map(one, hosts))

    def run(kind, keys, who, force=False):
        job = jobs[kind]
        try:
            if kind == 'scan':
                hosts = hosts_for(keys)
                with lock:
                    job['total'] = len(hosts)
                scan_hosts(hosts, who)
                # Parc entier : Wazuh relu aussi, pour une analyse sur les deux sources.
                result = {'wazuh': sync_wazuh(context, stop) if keys is None else None}
                result['analysis'] = analyze(context, keys)
            else:
                result = {'wazuh': sync_wazuh(context, stop), 'feeds': None}
                result['feeds'] = sync_feeds(context, stop, force=force)
                result['analysis'] = analyze(context)
            # Résumé e-mail des nouvelles alertes (mécanisme absent si SMTP non configuré).
            result['mail'] = security_alerts.dispatch(context)
            with lock:
                job.update(result=result, error=None)
        except Exception as exc:  # noqa: BLE001 — l'état du travail porte l'erreur, rien n'est effacé
            log.exception('Travail sécurité « %s » en échec', kind)
            with lock:
                job['error'] = type(exc).__name__ + ' : détail dans le journal du service'
        finally:
            with lock:
                job.update(running=False, finished_at=iso())

    def launch(kind, keys=None, who='OpsControl', force=False):
        from jobs import spawn  # producteur enregistré : attendu à l'arrêt (OC-AUDIT-013)
        with lock:
            job = jobs[kind]
            if job['running']:
                return False
            job.update(running=True, kind=kind, started_at=iso(), finished_at=None, completed=0,
                       total=0 if kind != 'scan' else len(hosts_for(keys)), error=None, actor=who, result=None)
        spawn(run, (kind, keys, who, force), name='securite-' + kind)
        return True

    def tick():
        """Planificateur (jobs.scheduler) : veille et Wazuh toutes les heures par défaut (fréquence
        réglable, désactivable) ; relevé SSH du parc selon l'intervalle choisi (désactivé par défaut)."""
        if getattr(context, 'SCHEMA_DEFERRED', False):
            return
        moment = time.time()
        if feeds_auto(context) and moment - last_auto['feeds'] >= feeds_hours(context) * 3600:
            # Échéance consommée seulement si la veille a démarré (ou tourne déjà) : avant, un
            # lancement refusé reportait la tentative d'une période entière.
            if launch('sync', who='planificateur') or jobs['sync']['running']:
                last_auto['feeds'] = moment
        try:
            hours = int(context.read_setting('security_scan_hours') or 0)
        except ValueError:
            hours = 0
        if hours in (24, 168) and moment - last_auto['scan'] >= hours * 3600:
            if last_auto['scan'] == 0.0:
                # Premier passage après démarrage : on attend une période entière plutôt que
                # de relancer ~90 sessions SSH à chaque redémarrage du service.
                last_auto['scan'] = moment
                return
            if launch('scan', who='planificateur') or jobs['scan']['running']:
                last_auto['scan'] = moment

    context.security_tick = tick
    context.security_vuln_snapshot = lambda ident: vuln_snapshot(context, ident)
    context.security_vuln_states = lambda ids: vuln_states(context, ids)

    def center_alerts():
        names = {h['key']: h.get('name') or h['key'] for h in context.HOSTS}
        with context.connect() as db:
            return security_alerts.center_alerts(db, names)

    context.security_center_alerts = center_alerts

    def state():
        """État des deux travaux ; les champs de premier niveau décrivent le plus pertinent
        (celui qui tourne, sinon le dernier terminé), pour les vues qui n'en montrent qu'un."""
        with lock:
            copies = {kind: dict(job) for kind, job in jobs.items()}
        running = [j for j in copies.values() if j['running']]
        primary = running[0] if running else max(copies.values(), key=lambda j: j['finished_at'] or '')
        return {**primary, 'running': bool(running), 'scan': copies['scan'], 'sync': copies['sync']}

    read_cache = ReadModelCache(lambda: getattr(context, 'DB', None),
                               revisions=lambda name: context.read_model_revision(name)
                               if hasattr(context, 'read_model_revision') else None)
    context.security_read_cache_close = read_cache.close

    def read_revision():
        # Les états de travaux et l'inventaire déclaratif peuvent évoluer sans
        # écriture des tables de sécurité ; ils font aussi partie de la clé.
        inventory = hashlib.sha256(json.dumps(context.HOSTS, sort_keys=True, default=str).encode()).hexdigest()
        return json.dumps((inventory, state()), sort_keys=True, default=str)

    @router.get('/api/security/summary')
    @read_cache.cached('summary', read_revision)
    def summary():
        hosts = context.rows()
        with context.connect() as db:
            counts, by_severity, top, ids = security_queries.summary(db, hosts)
            items = vulns(db, hosts, 'v.id IN (SELECT value FROM json_each(?))', (json.dumps(ids),))
            scanned = {r[0]: (r[1], bool(r[2])) for r in db.execute('SELECT host_key, collected_at, complete FROM sec_inventory')}
            resolved_30 = db.execute("SELECT count(*) FROM sec_vulns WHERE status='resolved' AND resolved_at >= ?",
                                     (iso(now() - timedelta(days=30)),)).fetchone()[0]
            unread = db.execute('SELECT count(*) FROM sec_notifications WHERE read_at IS NULL').fetchone()[0]
            advisories_7 = db.execute('SELECT count(*) FROM sec_advisories WHERE first_seen >= ?',
                                      (iso(now() - timedelta(days=7)),)).fetchone()[0]
            # Serveurs de l'inventaire courant dont les vulnérabilités Wazuh sont intégrées
            # (audit UI du 31/10, fiche 12.2) : un serveur retiré ne compte plus, et ce total
            # ne dit rien des agents connectés au manager, affichés dans Sources → Wazuh.
            keys = {h['key'] for h in hosts}
            wazuh_hosts = sum(1 for (key,) in db.execute('SELECT host_key FROM sec_wazuh') if key in keys)
            syncs = {r[0]: {'at': r[1], 'status': r[2]} for r in db.execute(
                'SELECT source, at, status FROM sec_syncs WHERE id IN (SELECT max(id) FROM sec_syncs GROUP BY source)')}
        eligible = [h for h in hosts if h.get('ip') and h.get('collect_enabled') is not False]
        return {
            'generated_at': iso(), 'counts': {
                **counts,
                'critical': by_severity.get('critical', 0), 'high': by_severity.get('high', 0),
                'resolved_30d': resolved_30,
                'hosts_scanned': sum(1 for k in scanned if any(h['key'] == k for h in hosts)),
                'hosts_total': len(eligible), 'wazuh_hosts': wazuh_hosts,
                'notifications': unread, 'advisories_7d': advisories_7},
            'by_severity': by_severity, 'top_hosts': top, 'top_vulns': items[:10], 'syncs': syncs, 'job': state(),
            'scope': ('Détections : correctifs Debian (DSA/DLA) non appliqués, comparés à la version de la même release, '
                      'et Wazuh Vulnerability Detection. Un serveur jamais analysé n’est pas « sans vulnérabilité ».'),
        }

    @router.get('/api/security/vulns')
    def list_vulns(host: str = Query(default='', max_length=80), status: str = Query(default='active', max_length=20),
                   severity: str = Query(default='', max_length=20), q: str = Query(default='', max_length=120),
                   kev: bool = False, limit: int = Query(default=500, ge=1, le=5000),
                   offset: int = Query(default=0, ge=0, le=1000000), projection: Literal['full', 'list'] = 'full'):
        where, params = ['1=1'], []
        if host:
            where.append('v.host_key=?')
            params.append(host)
        if status == 'active':
            where.append("v.status IN ('open','validated','in_progress')")
        elif status in STATUSES:
            where.append('v.status=?')
            params.append(status)
        elif status != 'all':
            raise HTTPException(422, 'Statut inconnu')
        if kev:
            where.append('c.kev=1')
        with context.connect() as db:
            hosts = context.rows()
            ids, total = security_queries.page(db, hosts, ' AND '.join(where), tuple(params),
                                               severity=severity, q=q, limit=limit, offset=offset)
            items = vulns(db, hosts, 'v.id IN (SELECT value FROM json_each(?))', (json.dumps(ids),))
        order = {ident: n for n, ident in enumerate(ids)}
        items.sort(key=lambda v: order[v['id']])
        if projection == 'list':
            for item in items:
                item.pop('description', None)
                item.pop('vector', None)
                ev = item['evidence']
                item['evidence'] = {k: ev[k] for k in ('source', 'reason', 'binaries', 'wazuh') if k in ev}
        return {'items': items, 'total': total, 'offset': offset, 'limit': limit}

    def one_vuln(db, ident):
        rows = vulns(db, context.rows(), 'v.id=?', (ident,))
        if not rows:
            raise HTTPException(404, 'Vulnérabilité inconnue')
        return rows[0]

    @router.get('/api/security/vulns/{ident}')
    def vuln_detail(ident: str):
        if not re.fullmatch(r'[0-9a-f]{20}', ident):
            raise HTTPException(404, 'Vulnérabilité inconnue')
        with context.connect() as db:
            item = one_vuln(db, ident)
            item['cve_data'] = _cve(db, item['cve'])
            item['events'] = [dict(zip(('at', 'actor', 'auth', 'action', 'detail'), r)) for r in db.execute(
                'SELECT at, actor, auth, action, detail FROM sec_events WHERE vuln_id=? ORDER BY seq DESC LIMIT 200', (ident,))]
            item['advisories'] = [dict(zip(('source', 'id', 'title', 'url', 'published'), r)) for r in db.execute(
                'SELECT source, id, title, url, published FROM sec_advisories WHERE cves LIKE ? ORDER BY published DESC LIMIT 20',
                ('%"' + item['cve'] + '"%',))]
            try:
                item['itsm'] = [dict(zip(('id', 'reference', 'kind', 'status', 'remote_id', 'remote_status', 'owner', 'taken_at'), r))
                                for r in db.execute('SELECT id, reference, kind, status, remote_id, remote_status, owner, taken_at '
                                                    "FROM itsm_cases WHERE origin='vulnerability' AND origin_id=?", (ident,))]
            except Exception:  # noqa: BLE001 — module ITSM absent : aucun dossier affiché
                item['itsm'] = []
        return item

    @router.get('/api/security/vulns/{ident}/plan')
    def vuln_plan(ident: str):
        if not re.fullmatch(r'[0-9a-f]{20}', ident):
            raise HTTPException(404, 'Vulnérabilité inconnue')
        with context.connect() as db:
            item = one_vuln(db, ident)
            inventory = _load_inventory(db, item['host_key'])
            cve = _cve(db, item['cve'])
        host = next((h for h in context.rows() if h['key'] == item['host_key']), {'key': item['host_key']})
        return {'vuln': {k: item[k] for k in ('id', 'cve', 'host_key', 'host_name', 'status', 'status_label', 'confidence')},
                **security_remediation.plan(item, host, inventory, cve)}

    @router.get('/api/security/hosts')
    def hosts_view():
        rows = context.rows()
        with context.connect() as db:
            inventories = {r[0]: (r[1], bool(r[2]), json.loads(r[3])) for r in db.execute(
                'SELECT host_key, collected_at, complete, payload FROM sec_inventory')}
            counts = {}
            for host, kev, severity in db.execute(
                    "SELECT v.host_key, COALESCE(c.kev,0), c.severity FROM sec_vulns v LEFT JOIN sec_cve c ON c.cve=v.cve "
                    "WHERE v.status IN ('open','validated','in_progress')"):
                entry = counts.setdefault(host, {'open': 0, 'kev': 0, 'critical': 0})
                entry['open'] += 1
                entry['kev'] += kev
                entry['critical'] += int(severity == 'critical')
            last_scan = {r[0]: {'at': r[1], 'status': r[2], 'detail': r[3]} for r in db.execute(
                'SELECT host_key, at, status, detail FROM sec_scans WHERE id IN (SELECT max(id) FROM sec_scans GROUP BY host_key)')}
            wazuh = {r[0]: r[1] for r in db.execute('SELECT host_key, at FROM sec_wazuh')}
        items = []
        for h in rows:
            collected, complete, inv = inventories.get(h['key'], (None, False, {}))
            items.append({'key': h['key'], 'name': h.get('name'), 'ip': h.get('ip'), 'environment': h.get('environment'),
                          'role': h.get('role'), 'os': (inv.get('os') or {}).get('pretty') or h.get('os'),
                          'support': os_support(inv.get('os')), 'packages': len(inv.get('packages') or []),
                          'collected_at': collected, 'complete': complete, 'last_scan': last_scan.get(h['key']),
                          'wazuh_at': wazuh.get(h['key']), 'reboot_required': bool(inv.get('reboot_required')),
                          'docker': (inv.get('docker') or {}).get('state'),
                          'counts': counts.get(h['key'], {'open': 0, 'kev': 0, 'critical': 0}),
                          'collect_enabled': h.get('collect_enabled') is not False and bool(h.get('ip'))})
        items.sort(key=lambda i: (-i['counts']['kev'], -i['counts']['critical'], -i['counts']['open'], str(i['name'])))
        return {'items': items, 'job': state()}

    @router.get('/api/security/hosts/{key}')
    def host_view(key: str):
        host = next((h for h in context.rows() if h['key'] == key), None)
        if not host:
            raise HTTPException(404, 'Serveur inconnu')
        with context.connect() as db:
            inventory = _load_inventory(db, key) or {}
            wazuh = _load_wazuh(db, key)
            items = vulns(db, [host], 'v.host_key=?', (key,))
            scans = [dict(zip(('at', 'status', 'detail', 'packages', 'duration_ms', 'actor'), r)) for r in db.execute(
                'SELECT at, status, detail, packages, duration_ms, actor FROM sec_scans WHERE host_key=? ORDER BY id DESC LIMIT 20', (key,))]
        docker = inventory.get('docker') or {}
        return {
            'host': {k: host.get(k) for k in ('key', 'name', 'ip', 'environment', 'role', 'criticality', 'vmid', 'node')},
            'os': inventory.get('os'), 'support': os_support(inventory.get('os')), 'kernel': inventory.get('kernel'),
            'reboot_required': bool(inventory.get('reboot_required')), 'manager': inventory.get('manager'),
            'collected_at': inventory.get('collected_at'), 'complete': inventory.get('complete', False),
            'account': inventory.get('account'), 'packages_count': len(inventory.get('packages') or []),
            'upgradable_count': len(inventory.get('upgradable') or []), 'components': components(inventory),
            'docker': {'state': docker.get('state'), 'containers': docker.get('containers') or [],
                       'images': docker.get('images') or [], 'findings': image_findings(docker.get('images'))},
            'wazuh': {k: wazuh[k] for k in ('connection', 'agent_id', 'at', 'complete')} | {'items': len(wazuh['items'])} if wazuh else None,
            'vulns': items, 'scans': scans,
            'scope': ('Paquets lus par le compte de supervision, sans sudo. Docker : liste des images, sans analyse de leur '
                      'contenu (utiliser un scanner d’images) ; « hors support » est un fait daté, pas une CVE.'),
        }

    @router.get('/api/security/packages/{key}')
    def host_packages(key: str, q: str = Query(default='', max_length=100)):
        if not any(h['key'] == key for h in context.HOSTS):
            raise HTTPException(404, 'Serveur inconnu')
        with context.connect() as db:
            inventory = _load_inventory(db, key) or {}
        packages = inventory.get('packages') or []
        if q:
            packages = [p for p in packages if q.lower() in p['name'].lower() or q.lower() in p['source'].lower()]
        upgradable = {u['name']: u for u in inventory.get('upgradable') or []}
        return {'collected_at': inventory.get('collected_at'), 'total': len(inventory.get('packages') or []),
                'items': [{**p, 'upgradable': upgradable.get(p['name'])} for p in packages[:1000]]}

    def concern(item, park):
        cves = [c for c in item['cves'] if CVE_ID.fullmatch(c)]
        hosts = sorted({h for c in cves for h in park['by_cve'].get(c, [])})
        if hosts:
            return {'level': 'confirmed', 'label': f'CVE détectée(s) sur {len(hosts)} serveur(s)', 'hosts': hosts}
        text = (item['title'] + ' ' + (item.get('summary') or '') + ' ' + ' '.join(item.get('products') or [])).lower()
        if item['source'] == 'proxmox' or 'proxmox' in text:
            if park['proxmox']:
                return {'level': 'potential', 'label': 'Clusters Proxmox de l’inventaire : version à comparer au bulletin', 'hosts': []}
        if item['source'] == 'fortinet' or re.search(r'forti(os|gate|web|proxy|manager|analyzer)', text):
            if park['forti']:
                return {'level': 'potential', 'label': 'Équipements Fortinet de l’inventaire : version à comparer', 'hosts': park['forti']}
            return {'level': 'unknown', 'label': 'Aucun équipement Fortinet identifié dans l’inventaire', 'hosts': []}
        for keyword, pattern, label in KEYWORDS:
            if re.search(keyword, text):
                hosts = park['components'].get(pattern, [])
                if hosts:
                    return {'level': 'potential', 'label': f'{label} installé sur {len(hosts)} serveur(s) : à vérifier '
                            '(paquets de distribution : correctif rétroporté possible)', 'hosts': hosts}
        return {'level': 'none', 'label': 'Aucun composant du parc identifié', 'hosts': []}

    def park_index(db):
        by_cve = {}
        for cve, host in db.execute("SELECT cve, host_key FROM sec_vulns WHERE status IN ('open','validated','in_progress')"):
            by_cve.setdefault(cve, []).append(host)
        comps = {}
        for host_key, payload in db.execute('SELECT host_key, payload FROM sec_inventory'):
            sources = {p['source'] for p in json.loads(payload).get('packages') or []}
            for _, pattern, _ in KEYWORDS:
                if any(re.fullmatch(pattern, s) for s in sources):
                    comps.setdefault(pattern, []).append(host_key)
        forti = [h['key'] for h in context.HOSTS if re.search(r'forti', (str(h.get('name')) + ' ' + str(h.get('role'))).lower())]
        proxmox = any(c.get('provider') == 'Proxmox' for c in context.api_connections())
        return {'by_cve': by_cve, 'components': comps, 'forti': forti, 'proxmox': proxmox}

    @router.get('/api/security/feeds')
    def feed_items(source: str = Query(default='', max_length=40), concerned: bool = False,
                   days: int = Query(default=60, ge=1, le=730), limit: int = Query(default=300, ge=1, le=2000)):
        since = iso(now() - timedelta(days=days))
        with context.connect() as db:
            rows = db.execute('SELECT source, id, title, url, published, summary, cves, products, first_seen FROM sec_advisories '
                              'WHERE COALESCE(published, first_seen) >= ? ' + ('AND source=? ' if source else '') +
                              'ORDER BY COALESCE(published, first_seen) DESC LIMIT 3000',
                              (since, source) if source else (since,)).fetchall()
            park = park_index(db)
        items = []
        for r in rows:
            item = dict(zip(('source', 'id', 'title', 'url', 'published', 'summary', 'cves', 'products', 'first_seen'), r))
            item['cves'] = [c for c in json.loads(item['cves']) if CVE_ID.fullmatch(c)]
            item['products'] = json.loads(item['products'] or '[]')
            item['source_label'] = feeds.SOURCES.get(item['source'], ('', '', item['source']))[2]
            item['concern'] = concern(item, park)
            if not concerned or item['concern']['level'] in ('confirmed', 'potential'):
                items.append(item)
        return {'items': items[:limit], 'total': len(items),
                'sources': [{'key': k, 'label': v[2], 'enabled': feeds.source_url(k) is not None} for k, v in feeds.SOURCES.items()]}

    @router.get('/api/security/sources')
    def sources_view():
        with context.connect() as db:
            latest = {r[0]: dict(zip(('source', 'at', 'status', 'items', 'new_items', 'detail'), r)) for r in db.execute(
                'SELECT source, at, status, items, new_items, detail FROM sec_syncs WHERE id IN (SELECT max(id) FROM sec_syncs GROUP BY source)')}
            fixes = dict(db.execute('SELECT release, count(*) FROM sec_fixes GROUP BY release').fetchall())
            kev = db.execute('SELECT count(*) FROM sec_cve WHERE kev=1').fetchone()[0]
            status = security_watch.sources_status(db)
        try:
            scan_hours = int(context.read_setting('security_scan_hours') or 0)
        except ValueError:
            scan_hours = 0
        for item in status:
            item['last'] = latest.get(item['key'])
        return {'sources': status, 'keys': {'nvd': bool(os.getenv('NVD_API_KEY', '').strip()),
                                            'github': bool(os.getenv('GITHUB_TOKEN', '').strip())},
                'mail': security_alerts.mail_status(context),
                'wazuh': [{'key': c['key'], 'name': c.get('name')} for c in context.api_connections() if c.get('provider') == 'Wazuh'],
                'indexers': [{'key': c['key'], 'name': c.get('name')} for c in context.api_connections() if c.get('provider') == 'Elasticsearch'],
                'debian_fixes': fixes, 'kev_count': kev, 'job': state(),
                'settings': {'feeds_auto': feeds_auto(context), 'feeds_hours': feeds_hours(context), 'scan_hours': scan_hours,
                             'wazuh_indexer': context.read_setting('security_wazuh_indexer') or os.getenv('INFRAOPS_WAZUH_INDEXER', ''),
                             'mail_to': context.read_setting('security_mail_to') or '',
                             'mail_level': context.read_setting('security_mail_level') or 'critical',
                             'epss_threshold': float(context.read_setting('security_epss_threshold') or 0.5)}}

    @router.get('/api/security/history')
    def history(days: int = Query(default=30, ge=1, le=365)):
        since = iso(now() - timedelta(days=days))
        names = {h['key']: h.get('name') for h in context.HOSTS}
        with context.connect() as db:
            events = [dict(zip(('at', 'actor', 'auth', 'action', 'detail', 'vuln_id', 'cve', 'host_key'), r)) for r in db.execute(
                'SELECT e.at, e.actor, e.auth, e.action, e.detail, e.vuln_id, v.cve, v.host_key FROM sec_events e '
                'LEFT JOIN sec_vulns v ON v.id=e.vuln_id WHERE e.at >= ? ORDER BY e.seq DESC LIMIT 1000', (since,))]
            scans = [dict(zip(('at', 'host_key', 'status', 'detail', 'packages', 'actor'), r)) for r in db.execute(
                'SELECT at, host_key, status, detail, packages, actor FROM sec_scans WHERE at >= ? ORDER BY id DESC LIMIT 1000', (since,))]
            syncs = [dict(zip(('at', 'source', 'status', 'items', 'new_items', 'detail'), r)) for r in db.execute(
                'SELECT at, source, status, items, new_items, detail FROM sec_syncs WHERE at >= ? ORDER BY id DESC LIMIT 500', (since,))]
            trend = [dict(zip(('day', 'detected', 'resolved'), r)) for r in db.execute(
                "SELECT substr(at,1,10) d, sum(action='detected'), sum(action='resolved') FROM sec_events WHERE at >= ? GROUP BY d ORDER BY d",
                (since,))]
        for item in events + scans:
            item['host_name'] = names.get(item.get('host_key'), item.get('host_key'))
        return {'events': events, 'scans': scans, 'syncs': syncs, 'trend': trend, 'days': days}

    @router.get('/api/security/report')
    def report(format: Literal['json', 'csv'] = 'json', status: str = Query(default='active', max_length=20)):
        data = list_vulns(host='', status=status if status in STATUSES + ('active', 'all') else 'active', severity='', q='',
                          kev=False, limit=5000, offset=0)
        if format == 'json':
            return {'generated_at': iso(), **data}
        out = io.StringIO()
        writer = csv.writer(out, delimiter=';')
        writer.writerow(['Serveur', 'IP', 'Environnement', 'CVE', 'CVSS', 'Gravité', 'CISA KEV', 'Paquet', 'Version installée',
                         'Version corrigée', 'Sources', 'Confiance', 'Statut', 'Responsable', 'Première détection', 'Dernière observation'])
        for v in data['items']:
            row = [v['host_name'], v['host_ip'], v['environment'], v['cve'], v['cvss'], SEVERITY_LABELS.get(v['severity'] or '', 'Non évaluée'),
                   'oui' if v['kev'] else 'non', v['package'], v['installed'], v['fixed'], ', '.join(SOURCE_LABELS.get(s, s) for s in v['sources']),
                   v['confidence'], v['status_label'], v['owner'], v['first_seen'], v['last_seen']]
            # Cellules neutralisées pour Excel (=, +, -, @ en tête) : injection de formule.
            writer.writerow(["'" + str(c) if isinstance(c, str) and c[:1] in ('=', '+', '-', '@') else ('' if c is None else c) for c in row])
        stamp = now().strftime('%Y%m%d-%H%M')
        return Response('﻿' + out.getvalue(), media_type='text/csv; charset=utf-8',
                        headers={'Content-Disposition': f'attachment; filename="vulnerabilites-{stamp}.csv"'})

    @router.get('/api/security/notifications')
    def notifications(unread: bool = False, host: str = '', limit: int = 200):
        if len(host) > 80 or not 1 <= limit <= 200:
            raise HTTPException(422, 'Filtre de notifications invalide')
        names = {h['key']: h.get('name') for h in context.HOSTS}
        conditions, params = [], []
        if unread:
            conditions.append('read_at IS NULL')
        if host:
            conditions.append('EXISTS (SELECT 1 FROM json_each(sec_notifications.hosts) WHERE value=?)')
            params.append(host)
        with context.connect() as db:
            rows = db.execute('SELECT id, at, level, title, detail, hosts, cve, read_at, read_by FROM sec_notifications ' +
                              ('WHERE ' + ' AND '.join(conditions) + ' ' if conditions else '') +
                              'ORDER BY at DESC,id DESC LIMIT ?', (*params, limit)).fetchall()
        items = []
        for r in rows:
            item = dict(zip(('id', 'at', 'level', 'title', 'detail', 'hosts', 'cve', 'read_at', 'read_by'), r))
            item['hosts'] = [{'key': k, 'name': names.get(k, k)} for k in json.loads(item['hosts'] or '[]')]
            items.append(item)
        return {'items': items}

    @router.post('/api/security/scan')
    def scan_all(body: Scan, request: Request):
        who, _ = actor(request, body.by)
        if body.host_key:
            raise HTTPException(422, 'Analyse d’un serveur : /api/security/hosts/<clé>/scan')
        if not launch('scan', None, who):
            raise HTTPException(409, 'Un relevé SSH du parc est déjà en cours')
        return state()

    @router.post('/api/security/hosts/{key}/scan')
    def scan_one(key: str, body: Scan, request: Request):
        who, _ = actor(request, body.by)
        if not any(h['key'] == key for h in context.HOSTS):
            raise HTTPException(404, 'Serveur inconnu')
        if not launch('scan', {key}, who):
            raise HTTPException(409, 'Un relevé SSH du parc est déjà en cours')
        return state()

    @router.post('/api/security/sync')
    def sync(body: Scan, request: Request):
        who, _ = actor(request, body.by)
        # Action manuelle : l'espacement après erreur est ignoré, jamais le débit par source.
        if not launch('sync', None, who, force=True):
            raise HTTPException(409, 'Une synchronisation de la veille est déjà en cours')
        return state()

    @router.get('/api/security/job')
    def job_state():
        return state()

    @router.post('/api/security/vulns/action')
    def vuln_action(body: VulnAction, request: Request):
        who, mode = actor(request, body.by)
        note = body.note.strip()
        with context.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT status FROM sec_vulns WHERE id=?', (body.id,)).fetchone()
            if not row:
                raise HTTPException(404, 'Vulnérabilité inconnue')
            stamp = iso()
            if body.action in TRANSITIONS:
                allowed, target = TRANSITIONS[body.action]
                if row[0] not in allowed:
                    raise HTTPException(409, f'Action impossible depuis l’état « {STATUS_LABELS.get(row[0], row[0])} »')
                if body.action in ('false_positive', 'accept_risk') and len(note) < 10:
                    raise HTTPException(422, 'Justification obligatoire (10 caractères minimum)')
                db.execute('UPDATE sec_vulns SET status=?, note=COALESCE(NULLIF(?, \'\'), note), updated_at=? WHERE id=?',
                           (target, note, stamp, body.id))
            elif body.action == 'assign':
                owner = body.owner.strip()
                if not owner:
                    raise HTTPException(422, 'Responsable requis')
                db.execute('UPDATE sec_vulns SET owner=?, owner_auth=?, updated_at=? WHERE id=?',
                           (owner, 'proxy' if mode == 'proxy' and owner == who else 'local', stamp, body.id))
                note = 'Responsable : ' + owner + (' — ' + note if note else '')
            else:
                if not note:
                    raise HTTPException(422, 'Note vide')
                db.execute('UPDATE sec_vulns SET updated_at=? WHERE id=?', (stamp, body.id))
            event(db, body.id, who, mode, body.action, ACTION_LABELS[body.action] + (' — ' + note if note else ''))
            item = one_vuln(db, body.id)
        return item

    @router.post('/api/security/notifications/read')
    def notifications_read(body: NotificationsRead, request: Request):
        who, _ = actor(request, body.by)
        with context.connect() as db:
            if body.all:
                count = db.execute('UPDATE sec_notifications SET read_at=?, read_by=? WHERE read_at IS NULL', (iso(), who)).rowcount
            else:
                count = sum(db.execute('UPDATE sec_notifications SET read_at=?, read_by=? WHERE id=? AND read_at IS NULL',
                                       (iso(), who, i)).rowcount for i in body.ids)
        return {'read': count}

    @router.post('/api/security/settings')
    def save_settings(body: Settings, request: Request):
        who, _ = operator_identity.actor(request.headers, '')
        if body.wazuh_indexer and not any(c.get('key') == body.wazuh_indexer and c.get('provider') == 'Elasticsearch'
                                          for c in context.api_connections()):
            raise HTTPException(422, 'Indexeur inconnu : choisir une connexion Elasticsearch déclarée')
        recipients = [r.strip() for r in body.mail_to.replace(';', ',').split(',') if r.strip()]
        if any(not re.fullmatch(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', r) for r in recipients) or len(recipients) > 20:
            raise HTTPException(422, 'Destinataires : adresses e-mail séparées par des virgules (20 au plus)')
        ok = all((context.write_setting('security_feeds_auto', '1' if body.feeds_auto else '0'),
                  context.write_setting('security_feeds_hours', body.feeds_hours),
                  context.write_setting('security_scan_hours', body.scan_hours),
                  context.write_setting('security_wazuh_indexer', body.wazuh_indexer),
                  context.write_setting('security_mail_to', ', '.join(recipients)),
                  context.write_setting('security_mail_level', body.mail_level),
                  context.write_setting('security_epss_threshold', body.epss_threshold)))
        if not ok:
            raise HTTPException(500, 'Réglages non enregistrés : voir le journal du service')
        log.info('Réglages sécurité modifiés par %s', who or 'local')
        return sources_view()['settings']

    # ----------------------------------------------------------------------- veille en ligne
    MATCH_COLUMNS = ('id', 'cve', 'host_key', 'tech', 'instance', 'version', 'origin', 'status', 'reason', 'fixed', 'source',
                     'first_seen', 'last_seen', 'updated_at')

    def range_text(rng):
        if rng.get('exact'):
            return '= ' + str(rng['exact'])
        low = (str(rng['start']) + (' ≤ ' if rng.get('start_included', True) else ' < ')) if rng.get('start') else ''
        high = ((' ≤ ' if rng.get('end_included') else ' < ') + str(rng['end'])) if rng.get('end') else ''
        return (low + 'v' + high) if (low or high) else 'toutes versions'

    @router.get('/api/security/watch')
    def watch(tech: str = Query(default='', max_length=40), host: str = Query(default='', max_length=80),
              source: str = Query(default='', max_length=40), severity: str = Query(default='', max_length=20),
              status: str = Query(default='', max_length=20), days: int = Query(default=7, ge=1, le=90),
              limit: int = 50, offset: int = 0, cve: str = '', projection: Literal['full', 'list'] = 'full'):
        """Tableau de bord de veille : sources, CVE applicables par serveur et technologie,
        priorité de remédiation, bulletins récents, historique des alertes."""
        rows = context.rows()
        if not isinstance(limit, int) or not 1 <= limit <= 500 or not isinstance(offset, int) or not 0 <= offset <= 1000000:
            raise HTTPException(422, 'Pagination invalide : limite entre 1 et 500, décalage positif')
        if len(cve) > 80:
            raise HTTPException(422, 'Identifiant de veille trop long')
        cve_filter = cve
        names = {h['key']: h.get('name') or h['key'] for h in rows}
        exposed = security_alerts.exposure(rows)
        since = iso(now() - timedelta(days=days))
        with context.connect() as db:
            sources = security_watch.sources_status(db)
            matches = [dict(zip(MATCH_COLUMNS, r)) for r in db.execute('SELECT ' + ', '.join(MATCH_COLUMNS) + ' FROM sec_matches')]  # nosec B608
            vuln_ids = {(r[0], r[1]): r[2] for r in db.execute('SELECT host_key, cve, status FROM sec_vulns')}
            index = {r['cve']: r for records in cve_index(db).values() for r in records}
            cve_rows = {r[0]: r for r in db.execute('SELECT cve, cvss, severity, kev, kev_due, epss, epss_percentile, description, '
                                                    'published, nvd_status, nvd_modified FROM sec_cve')}
            advisories = db.execute('SELECT source, id, title, url, published, cves, severity, cvss, first_seen, ranges '
                                    'FROM sec_advisories WHERE COALESCE(published, first_seen) >= ? ORDER BY COALESCE(published, first_seen) '
                                    'DESC LIMIT 300', (since,)).fetchall()
            cited = {}
            for a in db.execute('SELECT source, id, cves, severity, url FROM sec_advisories WHERE cves != ?', ('[]',)):
                for cve in json.loads(a[2]):
                    cited.setdefault(cve, []).append({'source': a[0], 'id': a[1], 'severity': a[3], 'url': a[4],
                                                      'label': feeds.SOURCES.get(a[0], ('', '', a[0]))[2]})
                if not json.loads(a[2]) or a[0] in feeds.ADVISORY_PRODUCTS:
                    cited.setdefault(a[1], []).append({'source': a[0], 'id': a[1], 'severity': a[3], 'url': a[4],
                                                       'label': feeds.SOURCES.get(a[0], ('', '', a[0]))[2]})
            alerts = [dict(zip(('id', 'ref', 'at', 'level', 'title', 'detail', 'hosts', 'cve', 'kind', 'priority', 'read_at',
                                'emailed_at', 'email_error'), r)) for r in db.execute(
                'SELECT id, ref, at, level, title, detail, hosts, cve, kind, priority, read_at, emailed_at, email_error '
                'FROM sec_notifications ORDER BY at DESC LIMIT 200')]
            changes = [dict(zip(('cve', 'at', 'field', 'old', 'new'), r)) for r in db.execute(
                'SELECT cve, at, field, old, new FROM sec_cve_changes ORDER BY seq DESC LIMIT 100')]
        by_cve = {}
        for m in matches:
            m['host_name'] = names.get(m['host_key'], m['host_key'])
            m['exposed'] = exposed.get(m['host_key'])
            m['tech_label'] = correlation.TECHS.get(m['tech'], {}).get('label', m['tech'])
            m['vuln_status'] = vuln_ids.get((m['host_key'], m['cve']))
            by_cve.setdefault(m['cve'], []).append(m)
        items = []
        for cve, group in by_cve.items():
            row = cve_rows.get(cve) or (cve, None, None, 0, None, None, None, None, None, None, None)
            refs = cited.get(cve, [])
            vendor = next((r['severity'] for r in refs if r.get('severity')), None)
            applicable = [m for m in group if m['status'] != 'not_applicable']
            best = 'confirmed' if any(m['status'] == 'confirmed' for m in group) else 'potential' if applicable else 'not_applicable'
            sev = feeds.severity_of(row[1]) or (vendor if vendor in SEVERITY_LABELS else 'high' if vendor == 'moderate' else None)
            rank, score, why = correlation.priority({'cvss': row[1], 'severity': vendor, 'kev': bool(row[3]), 'epss': row[5],
                                                     'exposed': any(m['exposed'] for m in applicable), 'status': best})
            record = index.get(cve) or {}
            ranges = sorted({f'{correlation.TECHS.get(t, {}).get("label", t)} {range_text(r)}' for t in {m['tech'] for m in group}
                             for _, entries, _ in correlation.ranges_for(t, record) for r in entries})
            items.append({
                'cve': cve, 'cvss': row[1], 'severity': sev, 'vendor_severity': vendor, 'kev': bool(row[3]), 'kev_due': row[4],
                'epss': row[5], 'epss_percentile': row[6], 'description': row[7], 'published': row[8], 'nvd_status': row[9],
                'nvd_modified': row[10], 'status': best, 'priority': {'rank': rank, 'score': score, 'why': why},
                'techs': sorted({m['tech'] for m in group}), 'tech_labels': sorted({m['tech_label'] for m in group}),
                'fixed': sorted({m['fixed'] for m in group if m['fixed']}), 'ranges': ranges[:12], 'advisories': refs[:8],
                'exposed': sorted({m['host_name'] for m in applicable if m['exposed']}),
                'counts': {s: sum(m['status'] == s for m in group) for s in correlation.STATUS_LABELS},
                'hosts': sorted(group, key=lambda m: (['confirmed', 'potential', 'not_applicable'].index(m['status']), m['host_name'])),
                'sources': sorted({r['source'] for r in refs} | ({'nvd'} if record.get('nvd_config') else set())),
            })
        techs = {}
        for m in matches:
            entry = techs.setdefault(m['tech'], {'tech': m['tech'], 'label': m['tech_label'], 'hosts': set(), 'cves': set(),
                                                 'confirmed': 0, 'potential': 0, 'not_applicable': 0})
            entry['hosts'].add(m['host_key'])
            entry['cves'].add(m['cve'])
            entry[m['status']] += 1
        # Filtres (produit, serveur, source, criticité, applicabilité) : sur la liste des CVE.
        shown = [i for i in items if (not tech or tech in i['techs']) and (not host or any(m['host_key'] == host for m in i['hosts']))
                 and (not source or source in i['sources']) and (not severity or (i['severity'] or 'unknown') == severity)
                 and (not status or i['counts'].get(status)) and (not cve_filter or i['cve'] == cve_filter)]
        if host:
            for item in shown:
                item['hosts'] = [m for m in item['hosts'] if m['host_key'] == host]
        shown.sort(key=lambda i: (-i['priority']['score'], i['cve']))
        bulletins = [{'source': a[0], 'source_label': feeds.SOURCES.get(a[0], ('', '', a[0]))[2], 'id': a[1], 'title': a[2],
                      'url': a[3], 'published': a[4], 'cves': [c for c in json.loads(a[5]) if feeds.CVE.fullmatch(c)],
                      'severity': a[6], 'cvss': a[7], 'first_seen': a[8], 'versions': bool(a[9]),
                      'applicable': sorted({m['host_name'] for c in (json.loads(a[5]) or [a[1]]) for m in by_cve.get(c, [])
                                            if m['status'] != 'not_applicable'})}
                     for a in advisories if not source or a[0] == source]
        for alert in alerts:
            alert['hosts'] = [names.get(h, h) for h in json.loads(alert['hosts'] or '[]')]
            alert['kind_label'] = security_alerts.KIND_LABELS.get(alert['kind'], alert['kind'] or 'Notification')
        operational = [s for s in sources if s['key'] in feeds.SOURCES or s['key'] in ('nvd', 'epss')]
        next_at = last_auto['feeds'] + feeds_hours(context) * 3600 if feeds_auto(context) else None
        day = iso(now() - timedelta(days=1))
        page_items = shown[offset:offset + limit]
        if projection == 'list':
            page_items = [{**item, 'hosts': [], 'detail_available': True} for item in page_items]
        return {
            'generated_at': iso(),
            'kpis': {'sources_ok': sum(s['status'] == 'ok' for s in operational),
                     'sources_error': sum(s['status'] == 'error' for s in operational), 'sources_total': len(operational),
                     'bulletins_24h': sum((b['first_seen'] or '') >= day for b in bulletins), 'bulletins': len(bulletins),
                     'confirmed': sum(i['status'] == 'confirmed' for i in items), 'potential': sum(i['status'] == 'potential' for i in items),
                     'not_applicable': sum(i['status'] == 'not_applicable' for i in items),
                     'p1': sum(i['priority']['rank'] == 'P1' and i['status'] != 'not_applicable' for i in items),
                     'alerts_24h': sum(a['at'] >= day for a in alerts), 'alerts_unread': sum(not a['read_at'] for a in alerts),
                     'next_sync': datetime.fromtimestamp(next_at, timezone.utc).isoformat() if next_at else None,
                     'feeds_auto': feeds_auto(context), 'feeds_hours': feeds_hours(context)},
            'sources': sources, 'cves': page_items, 'total': len(shown), 'limit': limit, 'offset': offset,
            'techs': sorted(({**t, 'hosts': len(t['hosts']), 'cves': len(t['cves'])} for t in techs.values()),
                            key=lambda t: (-t['confirmed'], -t['potential'], t['label'])),
            'bulletins': bulletins[:150], 'alerts': alerts[:150], 'changes': changes, 'exposed': exposed,
            'filters': {'techs': [{'key': k, 'label': v['label']} for k, v in correlation.TECHS.items()],
                        'sources': [{'key': k, 'label': v[2]} for k, v in feeds.SOURCES.items()] + [{'key': 'nvd', 'label': 'NVD'}],
                        'hosts': [{'key': h['key'], 'name': h.get('name') or h['key']} for h in rows]},
            'job': state(),
            'scope': ('Applicabilité calculée depuis les versions relevées (paquets, conteneurs, WordPress, Proxmox) et les plages '
                      'publiées par NVD et les éditeurs. « Potentielle » : rétroportage possible ou version incomplète, à vérifier ; '
                      'aucune CVE n’est déduite sans plage publiée.'),
        }

    def one_match(db, ident, cve):
        row = db.execute('SELECT ' + ', '.join(MATCH_COLUMNS) + ' FROM sec_matches WHERE id=? AND cve=?', (ident, cve)).fetchone()  # nosec B608
        if not row:
            raise HTTPException(404, 'Correspondance inconnue')
        return dict(zip(MATCH_COLUMNS, row))

    @router.get('/api/security/matches/plan')
    def match_plan(id: str = Query(pattern=r'^[0-9a-f]{20}$'), cve: str = Query(max_length=40)):
        """« Préparer la correction » pour une correspondance (confirmée ou potentielle)."""
        with context.connect() as db:
            match = one_match(db, id, cve)
            inventory = _load_inventory(db, match['host_key'])
            data = _cve(db, cve)
        host = next((h for h in context.rows() if h['key'] == match['host_key']), {'key': match['host_key']})
        inst = next((i for i in correlation.instances(host, inventory) if
                     correlation.instance_id(host['key'], i['tech'], i['instance']) == id), None)
        if inst is None:
            raise HTTPException(404, 'Instance absente du dernier relevé : relancer l’analyse du serveur')
        pseudo = {'cve': cve, 'package': inst['package'] or inst['tech'], 'installed': match['version'], 'fixed': match['fixed'],
                  'confidence': 'à vérifier' if match['status'] == 'potential' else 'confirmé', 'sources': [match['source'] or 'nvd'],
                  'evidence': {'manager': inst['manager'], 'tech': inst['tech'], 'source': match['source'], 'reason': match['reason'],
                               'binaries': sorted({p['name'] for p in (inventory or {}).get('packages') or []
                                                   if p['source'] == inst['package']}),
                               'binary_versions': {p['name']: p['version'] for p in (inventory or {}).get('packages') or []
                                                   if p['source'] == inst['package']},
                               'instances': [{'instance': inst['instance'], 'version': inst['version'] or inst['branch'],
                                              'origin': inst['origin'], 'detail': inst['detail'], 'fixed': match['fixed']}],
                               'confidence': 'à vérifier' if match['status'] == 'potential' else 'confirmé'}}
        if match['status'] == 'potential':
            pseudo['evidence']['reason'] = 'applicabilité potentielle : ' + str(match['reason'])
        plan = security_remediation.plan(pseudo, host, inventory, data)
        return {'match': {**match, 'status_label': correlation.STATUS_LABELS.get(match['status'], match['status']),
                          'host_name': host.get('name') or host['key']}, **plan}

    @router.post('/api/security/matches/decide')
    def match_decide(body: MatchDecision, request: Request):
        """Décision humaine sur une applicabilité POTENTIELLE : confirmée (entre alors dans le
        workflow : validation, correction, GLPI) ou non applicable, avec justification."""
        who, mode = actor(request, body.by)
        note = body.note.strip()
        if body.decision != 'reset' and len(note) < 10:
            raise HTTPException(422, 'Justification obligatoire (10 caractères minimum) : ce qui a été vérifié')
        with context.connect() as db:
            match = one_match(db, body.id, body.cve)
            if body.decision == 'reset':
                db.execute('DELETE FROM sec_match_decisions WHERE id=? AND cve=?', (body.id, body.cve))
            else:
                if match['status'] != 'potential' and not db.execute(
                        'SELECT 1 FROM sec_match_decisions WHERE id=? AND cve=?', (body.id, body.cve)).fetchone():
                    raise HTTPException(409, 'Seule une applicabilité potentielle se décide : celle-ci est « '
                                        + correlation.STATUS_LABELS.get(match['status'], match['status']) + ' »')
                db.execute('INSERT OR REPLACE INTO sec_match_decisions(id, cve, decision, note, actor, auth, at) VALUES(?,?,?,?,?,?,?)',
                           (body.id, body.cve, body.decision, note, who, mode, iso()))
            event(db, f'm:{body.id}:{body.cve}', who, mode, 'match_' + body.decision,
                  f'{match["instance"]} — ' + {'confirm': 'confirmée après vérification', 'not_applicable': 'non applicable',
                                               'reset': 'décision retirée'}[body.decision] + (f' : {note}' if note else ''))
        analyze(context, {match['host_key']})
        with context.connect() as db:
            updated = one_match(db, body.id, body.cve)
            updated['vuln_id'] = vuln_id(match['host_key'], body.cve) if db.execute(
                'SELECT 1 FROM sec_vulns WHERE id=?', (vuln_id(match['host_key'], body.cve),)).fetchone() else None
        if body.decision == 'confirm' and updated['vuln_id']:
            # Confirmée après vérification : la vulnérabilité est validée d'emblée (GLPI possible).
            with context.connect() as db:
                if db.execute("UPDATE sec_vulns SET status='validated', updated_at=? WHERE id=? AND status='open'",
                              (iso(), updated['vuln_id'])).rowcount:
                    event(db, updated['vuln_id'], who, mode, 'validate', 'Validée lors de la confirmation de l’applicabilité')
        return updated

    # ----------------------------------------------------------------------- recommandations
    def recommendation_vendor(db):
        """La gravité des bulletins est commune au parc : une lecture par requête."""
        vendor = {}
        order = list(correlation.SEVERITY_SCORE)
        for cves, severity in db.execute('SELECT cves, severity FROM sec_advisories WHERE severity IS NOT NULL'):
            for cve in json.loads(cves):
                if severity in order and (cve not in vendor or order.index(severity) < order.index(vendor[cve])):
                    vendor[cve] = severity
        return vendor

    def recommendations_for(db, host, exposed, vendor=None):
        """Plan de correction consolidé d'un serveur (security_recommendations.build)."""
        inventory = _load_inventory(db, host['key']) or {}
        if inventory.get('docker'):
            inventory['docker']['findings'] = image_findings(inventory['docker'].get('images'))
        items = vulns(db, [host], "v.host_key=? AND v.status IN ('open','validated','in_progress')", (host['key'],))
        facts = {r[0]: {'cvss': r[1], 'kev': bool(r[2]), 'epss': r[3]} for r in db.execute(
            'SELECT c.cve, c.cvss, c.kev, c.epss FROM sec_cve c WHERE c.cve IN (SELECT cve FROM sec_matches WHERE host_key=? '
            'UNION SELECT cve FROM sec_vulns WHERE host_key=?)', (host['key'], host['key']))}
        # Gravité de l'éditeur (avis PHP, WordPress…) quand NVD n'a pas encore de score : une CVE
        # « critical » sans CVSS ressortait sinon en P4.
        vendor = recommendation_vendor(db) if vendor is None else vendor
        for v in items:
            v['epss'] = (facts.get(v['cve']) or {}).get('epss')
            if v.get('cvss') is None and not (v.get('evidence') or {}).get('wazuh', {}).get('cvss'):
                v['severity'] = vendor.get(v['cve'], v.get('severity'))
        # Seules les CVE du serveur participent au classement ; recopier tous les
        # bulletins du parc pour chaque hôte multipliait inutilement le travail.
        matches = []
        for row in db.execute("SELECT cve, tech, instance, version, origin, status, reason, fixed FROM sec_matches "
                              "WHERE host_key=? AND status='potential'", (host['key'],)):
            m = dict(zip(('cve', 'tech', 'instance', 'version', 'origin', 'status', 'reason', 'fixed'), row))
            f = facts.get(m['cve']) or {}
            m['rank'] = correlation.priority({'cvss': f.get('cvss'), 'severity': vendor.get(m['cve']), 'kev': f.get('kev'), 'epss': f.get('epss'),
                                              'exposed': bool(exposed), 'status': 'potential'})[0]
            m['package'] = m['instance'].removeprefix('paquet ') if m['origin'] == 'distro' else None
            matches.append(m)
        wazuh = _load_wazuh(db, host['key'])
        columns = ('cvss', 'severity', 'vector', 'cvss_version', 'description', 'published', 'nvd_at', 'kev',
                   'kev_added', 'kev_due', 'kev_action', 'kev_ransomware')
        cve_data = {}
        for row in db.execute('SELECT cve,' + ','.join(columns) +
                              ' FROM sec_cve WHERE cve IN (SELECT value FROM json_each(?))',
                              (json.dumps(list({v['cve'] for v in items})),)):
            cve_data[row[0]] = dict(zip(columns, row[1:]))
            cve_data[row[0]]['kev'] = bool(cve_data[row[0]]['kev'])
        return security_recommendations.build(host, inventory, items, matches, exposed, os_support(inventory.get('os')),
                                              wazuh, cve_data)

    @router.get('/api/security/hosts/{key}/recommendations')
    def host_recommendations(key: str):
        rows = context.rows()
        host = next((h for h in rows if h['key'] == key), None)
        if not host:
            raise HTTPException(404, 'Serveur inconnu')
        exposed = security_alerts.exposure(rows).get(key)
        with context.connect() as db:
            plan = recommendations_for(db, host, exposed)
        return {'host': {k: host.get(k) for k in ('key', 'name', 'ip', 'environment', 'role', 'criticality')},
                'exposed': exposed, **plan}

    @router.get('/api/security/recommendations')
    @read_cache.cached('recommendations', read_revision)
    def fleet_recommendations():
        """Synthèse du parc : par serveur, nombre de recommandations par priorité et les premières."""
        rows = context.rows()
        exposure = security_alerts.exposure(rows)
        items = []
        with context.connect() as db:
            vendor = recommendation_vendor(db)
            for host in rows:
                plan = recommendations_for(db, host, exposure.get(host['key']), vendor)
                items.append({'key': host['key'], 'name': host.get('name') or host['key'], 'environment': host.get('environment'),
                              'exposed': exposure.get(host['key']), 'level': plan['level'], 'counts': plan['counts'],
                              'top': [{'priority': r['priority'], 'title': r['title'], 'kind': r['kind'], 'cves': len(r['cves'])}
                                      for r in plan['recommendations'][:3]], 'total': len(plan['recommendations'])})
        items.sort(key=lambda i: (security_recommendations._rank_value(i['level'] or 'P9'), -i['counts'].get('P1', 0), i['name']))
        return {'items': items, 'generated_at': iso(),
                'counts': {rank: sum(i['level'] == rank for i in items) for rank in security_recommendations.RANKS}}

    @router.post('/api/security/mail/test')
    def mail_test(request: Request):
        """Message de test aux destinataires configurés (administrateur) ; aucun contenu sensible."""
        who, _ = operator_identity.actor(request.headers, '')
        status = security_alerts.mail_status(context)
        if not status['configured']:
            raise HTTPException(422, 'E-mail non configuré : ' + ', '.join(status['missing']))
        try:
            security_alerts.send_mail(security_alerts.mail_settings(context), '[OpsControl] Test des alertes de veille sécurité',
                                      'Message de test envoyé depuis OpsControl (Sécurité > Veille) par ' + (who or 'local') + '.')
        except (OSError, security_alerts.smtplib.SMTPException) as exc:
            raise HTTPException(502, 'Envoi refusé : ' + type(exc).__name__) from None
        return {'sent': True, 'recipients': status['recipients']}

    app.include_router(router)  # routes de ce module : APIRouter, inclus en fin d'installation
