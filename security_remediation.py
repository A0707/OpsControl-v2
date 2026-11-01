"""Assistant de correction : procédure TEXTE construite à partir de données vérifiées.

Aucune commande n'est exécutée par OpsControl : comme `waf_findings.command_plan`, ce
module produit du texte à copier, relu par l'administrateur. Pas de LLM : chaque ligne
découle de faits collectés (gestionnaire de paquets, paquets binaires installés,
version exacte installée, version corrigée publiée, VM Proxmox, services observés).

Les noms et versions viennent de la collecte, mais sont REVALIDÉS ici par une liste
blanche de caractères avant d'entrer dans une commande : une valeur inattendue n'est
jamais recopiée dans un shell, elle est remplacée par un message.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

SAFE_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9.+_-]{0,99}$')
SAFE_VERSION = re.compile(r'^[A-Za-z0-9.:+~_^-]{1,100}$')
SAFE_CVE = re.compile(r'^CVE-\d{4}-\d{4,7}$')

# Impact et précautions par paquet source (ou nom RPM). Les services réellement observés
# sur le serveur sont ajoutés à part : cette table ne décrit que ce que le paquet implique.
IMPACT = {
    'linux': ('Noyau : le correctif n’est actif qu’après redémarrage du serveur.', 'reboot', []),
    'kernel': ('Noyau : le correctif n’est actif qu’après redémarrage du serveur.', 'reboot', []),
    'glibc': ('Bibliothèque C : tous les processus la chargent ; redémarrage du serveur recommandé.', 'reboot', []),
    'systemd': ('systemd : redémarrage du serveur recommandé pour recharger PID 1 et ses services.', 'reboot', []),
    'openssl': ('Bibliothèque TLS : les services déjà lancés gardent l’ancienne version en mémoire '
                'jusqu’à leur redémarrage (Apache, nginx, PHP-FPM, OpenSSH, bases de données…).', 'services', []),
    'openssl-libs': ('Bibliothèque TLS : les services déjà lancés gardent l’ancienne version en mémoire.', 'services', []),
    'apache2': ('Serveur web Apache : rechargement du service, coupure brève des connexions en cours.', 'services', ['apache2']),
    'httpd': ('Serveur web Apache : rechargement du service, coupure brève des connexions en cours.', 'services', ['httpd']),
    'nginx': ('Serveur web nginx : rechargement du service.', 'services', ['nginx']),
    'openssh': ('OpenSSH : les sessions ouvertes restent actives ; tester une NOUVELLE connexion '
                'avant de fermer la session en cours.', 'services', ['ssh']),
    'openssh-server': ('OpenSSH : tester une NOUVELLE connexion avant de fermer la session en cours.', 'services', ['sshd']),
    'sudo': ('sudo : aucun service à redémarrer.', 'none', []),
    'mariadb': ('MariaDB : redémarrage de la base, interruption des connexions applicatives.', 'window', ['mariadb', 'mysql']),
    'mysql-8.0': ('MySQL : redémarrage de la base, interruption des connexions applicatives.', 'window', ['mysql']),
    'postgresql': ('PostgreSQL : redémarrage de la base, interruption des connexions applicatives.', 'window', ['postgresql']),
    'docker.io': ('Docker : le redémarrage du démon arrête les conteneurs sans « live-restore ».', 'window', ['docker']),
    'docker-ce': ('Docker : le redémarrage du démon arrête les conteneurs sans « live-restore ».', 'window', ['docker']),
}
CONFIG_DIRS = {'apache2': '/etc/apache2', 'httpd': '/etc/httpd', 'nginx': '/etc/nginx', 'openssh': '/etc/ssh',
               'openssh-server': '/etc/ssh', 'mariadb': '/etc/mysql', 'postgresql': '/etc/postgresql',
               'openssl': '/etc/ssl', 'sudo': '/etc/sudoers /etc/sudoers.d'}


def _impact_of(package):
    if package in IMPACT:
        return IMPACT[package]
    if re.fullmatch(r'php\d\.\d+', package or '') or package == 'php':
        return ('PHP : redémarrer PHP-FPM ou recharger Apache (mod_php) pour charger la nouvelle version.',
                'services', ['php-fpm', 'apache2', 'httpd'])
    if re.fullmatch(r'postgresql-\d+', package or ''):
        return IMPACT['postgresql']
    if re.fullmatch(r'tomcat\d*', package or ''):
        return ('Tomcat : redémarrage du service, applications indisponibles pendant le démarrage.', 'window', [package])
    return ('Impact à qualifier : vérifier les services qui utilisent ce paquet (needrestart, lsof).', 'unknown', [])


def _safe(values, pattern):
    return [v for v in values if isinstance(v, str) and pattern.fullmatch(v)]


def _escape_deb(version):
    """Nom de fichier .deb : « : » de l'époque encodé « %3a » (convention apt)."""
    return version.replace(':', '%3a')


SAFE_IMAGE = re.compile(r'^[a-z0-9][a-z0-9._/-]{0,199}:[A-Za-z0-9._-]{1,120}$')
SAFE_PATH = re.compile(r'^/[A-Za-z0-9._/-]{1,250}$')
_INSTANCE = re.compile(r'^(conteneur|service Swarm) ([A-Za-z0-9][A-Za-z0-9_.-]{0,127}) \(')


def _first_instance(evidence):
    return (evidence.get('instances') or [{}])[0]


def _image_steps(evidence, installed, fixed, stamp, tag):
    """Conteneur ou service Swarm : nouvelle image au tag corrigé, ancienne image conservée."""
    inst = _first_instance(evidence)
    image = inst.get('detail') if SAFE_IMAGE.fullmatch(str(inst.get('detail') or '')) else None
    match = _INSTANCE.match(str(inst.get('instance') or ''))
    name, swarm = (match[2], match[1] == 'service Swarm') if match else (None, False)
    out = {k: [] for k in ('precheck', 'backup', 'update', 'verify', 'rollback')}
    out['warnings'] = []
    if not image or not name:
        out['warnings'].append('Image ou conteneur non identifié de façon sûre : procédure à établir manuellement.')
        return out
    repo, current = image.rsplit(':', 1)
    target = None
    if fixed and installed and current.startswith(installed):
        target = repo + ':' + fixed + current[len(installed):]
    elif fixed:
        out['warnings'].append(f'Tag cible à choisir : branche {installed or current} → version ≥ {fixed} (aucun correctif dans cette branche ?).')
    new = target or f'{repo}:<TAG_CORRIGÉ ≥ {fixed or "voir bulletin"}>'
    out['impact'] = ('Service Swarm : remplacement progressif des tâches (rolling update).' if swarm else
                     'Conteneur recréé : interruption de quelques secondes ; données dans les volumes conservées.')
    out['restart'] = 'services'
    out['precheck'] = [(f'docker service ps {name} --no-trunc' if swarm else f"docker ps --filter name=^{name}$ --format '{{{{.Names}}}} {{{{.Image}}}} {{{{.Status}}}}'"),
                       f"docker image inspect {image} --format '{{{{.Id}}}} {{{{.Created}}}}'",
                       f'docker pull {new}   # téléchargement seul, rien n’est redémarré' if target else '# Choisir le tag corrigé dans le registre officiel']
    out['backup'] = [(f'docker service inspect {name} > /root/service-{name}-{stamp}.json' if swarm else
                      f'docker inspect {name} > /root/conteneur-{name}-{stamp}.json'),
                     f'docker image tag {image} {repo}:avant-{tag}-{stamp}   # garde l’image actuelle pour le retour arrière',
                     '# Sauvegarder les volumes et la base associée (ex. WordPress : export de la base) avant la bascule']
    if swarm:
        out['update'] = [f'docker service update --image {new} {name}']
        out['rollback'] = [f'docker service rollback {name}   # revient à la définition précédente du service']
    else:
        out['update'] = [f'# docker-compose.yml : remplacer « image: {image} » par « image: {new} »',
                         f'docker compose pull {name} && docker compose up -d {name}']
        out['rollback'] = [f'# docker-compose.yml : remettre « image: {repo}:avant-{tag}-{stamp} » (copie de {image})',
                           f'docker compose up -d {name}']
    probe = 'php -v' if evidence.get('tech') == 'php' else \
        "grep -m1 wp_version /var/www/html/wp-includes/version.php" if evidence.get('tech') == 'wordpress' else None
    out['verify'] = ([f'docker service ps {name}' if swarm else f"docker ps --filter name=^{name}$"] +
                     ([f'docker exec $(docker ps -q -f name={name} | head -n 1) {probe}'] if probe else []))
    return out


def _wordpress_steps(evidence, installed, fixed, stamp, tag):
    """WordPress installé sur le serveur : WP-CLI, base et fichiers sauvegardés avant."""
    inst = _first_instance(evidence)
    path = inst.get('detail') if SAFE_PATH.fullmatch(str(inst.get('detail') or '')) else None
    out = {k: [] for k in ('precheck', 'backup', 'update', 'verify', 'rollback')}
    out['warnings'] = [] if path else ['Chemin WordPress non identifié de façon sûre : procédure à établir manuellement.']
    if not path:
        return out
    wp = f'sudo -u www-data wp --path={path}'
    out['impact'] = 'Mise à jour du cœur WordPress : site en maintenance quelques secondes, extensions à vérifier.'
    out['restart'] = 'none'
    out['precheck'] = [f'{wp} core version', f'{wp} core check-update', f'{wp} plugin list --update=available']
    out['backup'] = [f'{wp} db export /root/wordpress-{tag}-{stamp}.sql', f'sudo tar czf /root/wordpress-fichiers-{stamp}.tgz {path}']
    out['update'] = [f'{wp} core update' + (f' --version={fixed}' if fixed else ''), f'{wp} core update-db']
    out['verify'] = [f'{wp} core version', f'{wp} core verify-checksums']
    out['rollback'] = ([f'{wp} core update --version={installed} --force'] if installed else []) + \
        [f'{wp} db import /root/wordpress-{tag}-{stamp}.sql', f'# En dernier recours : restaurer /root/wordpress-fichiers-{stamp}.tgz']
    return out


def _proxmox_steps(evidence, installed, fixed, stamp, tag):
    """Nœud Proxmox VE : invités migrés avant, mise à jour par les dépôts Proxmox."""
    out = {k: [] for k in ('precheck', 'backup', 'update', 'verify', 'rollback')}
    out['warnings'] = []
    out['impact'] = 'Hyperviseur : migrer les invités avant la mise à jour ; redémarrage si un nouveau noyau est installé.'
    out['restart'] = 'reboot'
    out['precheck'] = ['pveversion -v', 'apt list --upgradable 2>/dev/null | grep -E "^(pve|proxmox|qemu-server)"', 'pvecm status']
    out['backup'] = [f'sudo tar czf /root/etc-pve-{stamp}.tgz /etc/pve /etc/network/interfaces',
                     '# Migrer les VM et conteneurs vers un autre nœud du cluster (qm migrate / pct migrate) ou les arrêter']
    out['update'] = ['sudo apt-get update', 'sudo apt-get dist-upgrade   # dépôts Proxmox : dist-upgrade attendu, jamais upgrade seul']
    out['verify'] = ['pveversion', 'systemctl is-active pveproxy pvedaemon pve-cluster', 'pvecm status']
    out['rollback'] = ([f'sudo apt-get install --allow-downgrades pve-manager={installed}*   # si la version est encore disponible']
                       if installed else []) + ['# Noyau : redémarrer sur l’entrée précédente (proxmox-boot-tool kernel list)']
    return out


def _fortios_steps(evidence, installed, fixed, stamp, tag):
    """FortiGate : procédure à suivre sur la console, version déclarée à confirmer d'abord."""
    out = {k: [] for k in ('precheck', 'backup', 'update', 'verify', 'rollback')}
    out['warnings'] = ['Version FortiOS déclarée dans l’inventaire, non mesurée : la confirmer avec « get system status ».']
    out['impact'] = 'Pare-feu : redémarrage de l’équipement ; en cluster HA, mettre à jour l’esclave puis basculer.'
    out['restart'] = 'reboot'
    out['precheck'] = ['get system status   # console FortiGate, lecture seule', 'diagnose sys ha status',
                       '# Chemin de mise à jour : outil « Upgrade Path » de Fortinet (versions intermédiaires éventuelles)']
    out['backup'] = ['execute backup config ftp|tftp|usb <destination>   # ou Système > Configuration > Sauvegarde',
                     '# Conserver l’image FortiOS actuelle ' + (installed or '') + ' et sa configuration']
    out['update'] = [f'# Charger l’image FortiOS {fixed or "corrigée (voir le bulletin FG-IR)"} via l’interface ou FortiManager, '
                     'dans la fenêtre validée']
    out['verify'] = ['get system status   # la version doit être ' + (fixed or 'celle du bulletin'), 'diagnose sys ha status']
    out['rollback'] = ['execute set-next-reboot secondary   # démarre sur la partition de l’image précédente', 'execute reboot',
                       '# Restaurer ensuite la configuration sauvegardée si nécessaire']
    return out


def _engine_steps(evidence, installed, fixed, stamp, tag):
    """Démon Docker installé par paquet : mise à jour du paquet docker-ce / docker.io."""
    out = {k: [] for k in ('precheck', 'backup', 'update', 'verify', 'rollback')}
    out['warnings'] = []
    out['impact'] = 'Docker : le redémarrage du démon arrête les conteneurs sans « live-restore » ; nœud Swarm : drainer d’abord.'
    out['restart'] = 'window'
    out['precheck'] = ['docker version', "docker info --format '{{.Swarm.LocalNodeState}} {{.LiveRestoreEnabled}}'",
                       'apt-cache policy docker-ce docker.io 2>/dev/null']
    out['backup'] = ['docker node update --availability drain <NŒUD>   # nœud Swarm : vider avant intervention',
                     f'docker ps --format "{{{{.Names}}}} {{{{.Image}}}}" > /root/conteneurs-{stamp}.txt']
    out['update'] = ['sudo apt-get update', 'sudo apt-get install --only-upgrade docker-ce docker-ce-cli containerd.io   # ou docker.io']
    out['verify'] = ['docker version', 'docker ps', 'docker node update --availability active <NŒUD>']
    out['rollback'] = ([f'sudo apt-get install --allow-downgrades docker-ce=*{installed}*'] if installed else []) + \
        ['docker node update --availability active <NŒUD>']
    return out


UPSTREAM_STEPS = {'image': _image_steps, 'file': _wordpress_steps, 'vendor': _proxmox_steps, 'declared': _fortios_steps,
                  'binary': _engine_steps}


def plan(vuln, host, inventory=None, cve=None, at=None):
    """Procédure de correction complète pour une vulnérabilité d'un serveur.

    `vuln` : ligne sec_vulns décodée ; `host` : serveur de l'inventaire (rows()) ;
    `inventory` : dernier relevé des paquets ; `cve` : enrichissement NVD/KEV."""
    at = at or datetime.now(timezone.utc)
    inventory = inventory or {}
    evidence = vuln.get('evidence') or {}
    manager = evidence.get('manager') or inventory.get('manager')
    package = vuln.get('package') or ''
    cve_id = vuln.get('cve') if SAFE_CVE.fullmatch(str(vuln.get('cve') or '')) else None
    installed = vuln.get('installed') if SAFE_VERSION.fullmatch(str(vuln.get('installed') or '')) else None
    fixed = vuln.get('fixed') if SAFE_VERSION.fullmatch(str(vuln.get('fixed') or '')) else None
    binaries = _safe(evidence.get('binaries') or ([package] if package else []), SAFE_NAME)
    versions = {b: v for b, v in (evidence.get('binary_versions') or {}).items()
                if SAFE_NAME.fullmatch(str(b)) and SAFE_VERSION.fullmatch(str(v))}
    warnings = []
    if not SAFE_NAME.fullmatch(package):
        warnings.append('Nom de paquet inattendu : aucune commande générée, procédure à établir manuellement.')
        binaries = []
    if not binaries:
        warnings.append('Paquets binaires installés inconnus : relancer l’analyse SSH du serveur avant d’intervenir.')
    if not fixed:
        warnings.append('Version corrigée non fournie par la source : vérifier le bulletin avant toute mise à jour.')
    if (evidence.get('confidence') or vuln.get('confidence')) == 'à vérifier':
        warnings.append('Détection à vérifier : ' + str(evidence.get('reason') or 'preuve contradictoire') + '.')
    stamp = at.strftime('%Y%m%d')
    tag = (cve_id or 'correctif').lower().replace('cve-', 'cve')
    names = ' '.join(binaries)
    first = binaries[0] if binaries else None
    vm = host.get('vmid') if isinstance(host.get('vmid'), int) or str(host.get('vmid') or '').isdigit() else None
    node = host.get('node') if SAFE_NAME.fullmatch(str(host.get('node') or '')) else None
    description, restart, own_services = _impact_of(package)
    # Services déclarés pour ce serveur : ils départagent un paquet à plusieurs services
    # possibles (PHP : FPM ou mod_php). Sans indication, un seul service évident ou aucun.
    declared = {str(s.get('name') if isinstance(s, dict) else s).removesuffix('.service') for s in host.get('services') or []}
    services = [s for s in own_services if s in declared] or (own_services if len(own_services) == 1 else [])
    services = _safe(services, SAFE_NAME)

    precheck, backup, update, verify, rollback = [], [], [], [], []
    if manager == 'dpkg' and binaries:
        precheck += [f'apt-cache policy {names}',
                     f'apt-get -s install --only-upgrade {names}   # simulation, aucune modification']
        if cve_id and first:
            precheck.append(f'zgrep -c {cve_id} /usr/share/doc/{first}/changelog.Debian.gz   '
                            '# > 0 : correctif déjà présent (rétroporté)')
        backup.append(f"dpkg-query -W -f='${{Package}}=${{Version}}\\n' {names} | sudo tee /root/versions-avant-{tag}-{stamp}.txt")
        if versions:
            backup.append('ls -l ' + ' '.join(f'/var/cache/apt/archives/{b}_{_escape_deb(v)}_*.deb' for b, v in versions.items())
                          + '   # paquets actuels encore en cache : nécessaires au retour arrière')
        update += ['sudo apt-get update', f'sudo apt-get install --only-upgrade {names}']
        if fixed and first:
            verify.append(f"dpkg --compare-versions \"$(dpkg-query -W -f='${{source:Version}}' {first})\" ge {fixed} "
                          "&& echo 'CORRIGÉ' || echo 'TOUJOURS VULNÉRABLE'")
        verify.append(f"dpkg-query -W -f='${{Package}} ${{Version}}\\n' {names}")
        if cve_id and first:
            verify.append(f'zgrep -c {cve_id} /usr/share/doc/{first}/changelog.Debian.gz')
        if versions:
            pinned = ' '.join(f'{b}={v}' for b, v in versions.items())
            rollback += [f'sudo apt-get install --allow-downgrades {pinned}',
                         '# Si la version n’est plus dans les dépôts : depuis le cache local',
                         'sudo dpkg -i ' + ' '.join(f'/var/cache/apt/archives/{b}_{_escape_deb(v)}_*.deb' for b, v in versions.items()),
                         f'sudo apt-mark hold {names}   # empêche une remise à jour le temps de l’analyse ; '
                         f'« sudo apt-mark unhold {names} » ensuite']
        elif installed:
            rollback.append(f'sudo apt-get install --allow-downgrades {first}={installed}   '
                            '# version source : vérifier la version binaire exacte dans /root/versions-avant-*')
    elif manager == 'rpm' and binaries:
        precheck += [f'rpm -q {names}', f'sudo dnf check-update {names}   # ou yum sur EL7']
        if cve_id:
            precheck.append(f'dnf updateinfo list --cves {cve_id}   # avis de sécurité de la distribution')
            precheck.append(f'rpm -q --changelog {first} | grep -c {cve_id}   # > 0 : correctif déjà présent (rétroporté)')
        backup.append(f'rpm -q {names} | sudo tee /root/versions-avant-{tag}-{stamp}.txt')
        update.append(f'sudo dnf upgrade {names}   # EL7 : sudo yum update {names}')
        verify.append(f'rpm -q {names}')
        if cve_id:
            verify.append(f'rpm -q --changelog {first} | grep -c {cve_id}')
        rollback.append(f'sudo dnf history list {first}   # repérer la transaction de mise à jour')
        rollback.append('sudo dnf history undo <ID_DE_LA_TRANSACTION>   # ID lu ci-dessus, à recopier à la main')
        if installed:
            rollback.append(f'sudo dnf downgrade {first}-{installed.split(":", 1)[-1]}   # alternative ciblée')
    elif manager in UPSTREAM_STEPS:
        steps = UPSTREAM_STEPS[manager](evidence, installed, fixed, stamp, tag)
        precheck, backup, update, verify, rollback = (steps[k] for k in ('precheck', 'backup', 'update', 'verify', 'rollback'))
        warnings += steps['warnings']
        restart = steps.get('restart', restart)
        if steps.get('impact'):
            description = steps['impact']
        services = []
    else:
        warnings.append('Gestionnaire de paquets inconnu : lancer l’analyse SSH du serveur pour obtenir une procédure.')

    if vm and node:
        backup.insert(0, f'qm snapshot {vm} avant-{tag}-{stamp} --description "OpsControl {cve_id or package}"   '
                         f'# sur le nœud Proxmox {node}')
        rollback.append(f'qm rollback {vm} avant-{tag}-{stamp}   # DERNIER RECOURS sur le nœud {node} : '
                        'perd toutes les écritures depuis l’instantané')
    elif vm:
        backup.insert(0, f'qm snapshot {vm} avant-{tag}-{stamp}   # sur le nœud Proxmox qui héberge la VM')
    else:
        backup.insert(0, '# VM Proxmox non identifiée : vérifier une sauvegarde récente (Bacula) avant d’intervenir')
    # Configuration locale : seulement pour un paquet du système (pas un conteneur ni WordPress).
    config = CONFIG_DIRS.get(package) or ('/etc/php' if package.startswith('php') else None)
    if config and manager in ('dpkg', 'rpm'):
        backup.append(f'sudo tar czf /root/config-{package}-{stamp}.tgz {config}')

    if restart == 'reboot':
        impact_actions = ['sudo needrestart -r l   # liste seulement, ne redémarre rien',
                          '# Redémarrage du serveur à planifier dans une fenêtre validée (jamais automatique)']
    elif services:
        impact_actions = ['sudo needrestart -r l   # liste les services à relancer, sans rien relancer']
        for service in services:
            if service in ('apache2', 'httpd'):
                impact_actions.append(f'sudo apachectl configtest && sudo systemctl reload {service}')
            elif service == 'nginx':
                impact_actions.append('sudo nginx -t && sudo systemctl reload nginx')
            else:
                impact_actions.append(f'sudo systemctl restart {service}   # dans la fenêtre validée')
        verify += [f'systemctl is-active {s}' for s in services]
    else:
        impact_actions = ['sudo needrestart -r l   # liste les services qui gardent l’ancienne version, sans rien relancer']
    verify.append('Puis relancer « Analyser ce serveur » dans OpsControl : la vulnérabilité passe à « Corrigée » '
                  'uniquement si la version installée est constatée ≥ version corrigée.')
    rollback.append('Vérifier ensuite les services (systemctl is-active …) et relancer l’analyse OpsControl.')

    kev = bool((cve or {}).get('kev'))
    backup_required = ('Oui : instantané Proxmox de la VM et copie de la configuration avant la mise à jour.' if vm else
                       'Oui : sauvegarde récente vérifiée (Bacula) et copie de la configuration avant la mise à jour.')
    if restart == 'reboot':
        backup_required = 'Oui, impérativement : redémarrage requis. ' + backup_required
    sections = [
        ('Vérifications préalables (lecture seule)', precheck),
        ('Sauvegarde nécessaire', backup),
        ('Commandes de mise à jour proposées', update),
        ('Prise en compte (services, redémarrage)', impact_actions),
        ('Vérification après correction', verify),
        ('Procédure de retour arrière', rollback),
    ]
    header = [
        f'Serveur : {host.get("name") or host.get("key")} ({host.get("ip") or "IP inconnue"}) — {host.get("environment") or "environnement non renseigné"}',
        f'CVE : {cve_id or vuln.get("cve")}' + (' — EXPLOITÉE ACTIVEMENT (CISA KEV)' if kev else ''),
        f'Paquet : {package} ({", ".join(binaries) or "binaires inconnus"})',
        f'Version actuelle : {installed or "inconnue"} — version corrigée : {fixed or "non fournie par la source"}',
        f'Source de la détection : {evidence.get("source") or ", ".join(vuln.get("sources") or [])}',
        f'Impact potentiel : {description}',
        f'Sauvegarde : {backup_required}',
    ]
    text = '\n'.join(header + ['AVERTISSEMENT : ' + w for w in warnings]) + '\n\n' + '\n\n'.join(
        '## ' + title + '\n' + '\n'.join(lines or ['(aucune commande : voir les avertissements)']) for title, lines in sections) + \
        '\n\nOpsControl n’exécute aucune de ces commandes. Intervention en production : fenêtre validée, ' \
        'sauvegarde vérifiée, aucun redémarrage automatique.'
    return {
        'server': {'key': host.get('key'), 'name': host.get('name'), 'ip': host.get('ip'),
                   'environment': host.get('environment'), 'vmid': vm, 'node': node},
        'cve': cve_id or vuln.get('cve'), 'kev': kev, 'cvss': (cve or {}).get('cvss'),
        'package': package, 'binaries': binaries, 'installed': installed, 'fixed': fixed, 'manager': manager,
        'impact': description, 'restart': restart, 'services': services, 'backup_required': backup_required,
        'precheck': precheck, 'backup': backup, 'update': update, 'apply': impact_actions,
        'verify': verify, 'rollback': rollback, 'warnings': warnings,
        'generated_at': at.isoformat(), 'generated_from': 'Relevé SSH des paquets, source de détection et inventaire ; aucun LLM.',
        'text': text,
    }
