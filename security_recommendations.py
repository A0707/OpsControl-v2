"""Recommandations de correction par serveur : un plan consolidé, vulnérabilités ET risques.

Une procédure par CVE (security_remediation.plan) ne suffit pas pour intervenir proprement :
dix CVE d'un même serveur se corrigent souvent par UNE mise à jour de paquets, une seule
sauvegarde, un seul redémarrage. Ce module regroupe, pour un serveur :

    packages   paquets vulnérables (dpkg/rpm) : une mise à jour, une vérification par paquet
    upstream   chaque conteneur, service Swarm, WordPress, Proxmox, démon Docker, FortiGate
    verify     CVE potentielles : commandes de vérification (changelog, version réelle)
    os         système hors support (ou proche de la fin) : migration planifiée
    reboot     redémarrage en attente (noyau ou bibliothèques déjà mis à jour)
    pending    mises à jour disponibles hors CVE suivies
    images     images Docker hors support amont ou non figées
    audit      constats de l'audit SSH liés à la sécurité (commandes déjà fournies par l'audit)
    coverage   ce qui empêche de conclure : jamais analysé, relevé ancien, Wazuh absent

Chaque recommandation porte sa priorité (P1-P4, même grille que la veille), ses preuves et
ses étapes : vérification préalable, sauvegarde, application, prise en compte, vérification,
retour arrière. Rien n'est inventé ni exécuté : tout découle des données collectées, et le
résultat est du TEXTE à copier, relu par l'administrateur. Pas de LLM.
"""
from __future__ import annotations

import re
from datetime import date, datetime, timedelta, timezone

import security_correlation as correlation
import security_remediation as remediation
import security_versions as versions

RANKS = ('P1', 'P2', 'P3', 'P4')
RANK_LABELS = {'P1': 'Immédiate', 'P2': 'Sous 7 jours', 'P3': 'Sous 30 jours', 'P4': 'Planifiable'}
SECURITY_FINDING = re.compile(r'sécurité|security|permission|ssh_policy|sshd|firewall|pare-feu|update|mise à jour|'
                              r'auditd|fail2ban|wazuh|apparmor|selinux|firewalld|ufw', re.I)
# Chemins de migration publiés par les éditeurs (une release à la fois pour Debian).
NEXT_RELEASE = {('debian', '9'): 'Debian 10 (buster), puis 11 et 12', ('debian', '10'): 'Debian 11 (bullseye), puis 12 (bookworm)',
                ('debian', '11'): 'Debian 12 (bookworm)', ('debian', '12'): 'Debian 13 (trixie)',
                ('ubuntu', '18.04'): 'Ubuntu 20.04 puis 22.04 LTS', ('ubuntu', '20.04'): 'Ubuntu 22.04 LTS', ('ubuntu', '22.04'): 'Ubuntu 24.04 LTS',
                ('centos', '7'): 'Rocky Linux ou AlmaLinux 8/9 (réinstallation conseillée ; ELevate/Leapp possible)',
                ('centos', '8'): 'Rocky Linux ou AlmaLinux 8 (migrate2rocky / almalinux-deploy)',
                ('rhel', '7'): 'RHEL 8 ou 9 (Leapp)', ('rhel', '8'): 'RHEL 9 (Leapp)'}


def _rank_value(rank):
    return RANKS.index(rank) if rank in RANKS else len(RANKS)


def _best(ranks):
    return min(ranks, key=_rank_value) if ranks else 'P4'


def _vuln_rank(v, exposed):
    rank, _, why = correlation.priority({'cvss': v.get('cvss') if v.get('cvss') is not None else (v.get('evidence') or {}).get('wazuh', {}).get('cvss'),
                                         'severity': v.get('severity'), 'kev': v.get('kev'), 'epss': v.get('epss'),
                                         'exposed': bool(exposed), 'status': 'confirmed'})
    return rank, why


def _uniq(lines):
    return list(dict.fromkeys(line for line in lines if line))


def _rec(kind, rank, title, why, steps=None, cves=(), impact=None, restart=None, extra=None):
    steps = steps or {}
    return {'kind': kind, 'priority': rank, 'priority_label': RANK_LABELS.get(rank, rank), 'title': title, 'why': [w for w in why if w],
            'cves': sorted(set(cves)), 'impact': impact, 'restart': restart,
            'precheck': steps.get('precheck', []), 'backup': steps.get('backup', []), 'apply': steps.get('apply', []),
            'restart_steps': steps.get('restart', []), 'verify': steps.get('verify', []), 'rollback': steps.get('rollback', []),
            **(extra or {})}


def _packages(host, inventory, items, exposed, stamp):
    """Toutes les CVE corrigées par des paquets du système : UNE intervention."""
    manager = (inventory or {}).get('manager')
    if manager not in ('dpkg', 'rpm') or not items:
        return None
    binaries, pinned, fixed, impacts, restart, ranks, why = {}, {}, {}, set(), set(), [], []
    for v in items:
        ev = v.get('evidence') or {}
        for name in remediation._safe(ev.get('binaries') or [v['package']], remediation.SAFE_NAME):
            binaries[name] = v['package']
        for name, version in (ev.get('binary_versions') or {}).items():
            if remediation.SAFE_NAME.fullmatch(name) and remediation.SAFE_VERSION.fullmatch(str(version)):
                pinned[name] = version
        if v.get('fixed') and remediation.SAFE_VERSION.fullmatch(str(v['fixed'])):
            current = fixed.get(v['package'])
            if current is None or (current != v['fixed'] and versions.is_older(manager, current, v['fixed'])):
                fixed[v['package']] = v['fixed']
        description, kind, _ = remediation._impact_of(v['package'])
        impacts.add(description)
        restart.add(kind)
        rank, reasons = _vuln_rank(v, exposed)
        ranks.append(rank)
        if v.get('kev'):
            why.append(f'{v["cve"]} exploitée activement (CISA KEV)')
    if not binaries:
        return None
    names = ' '.join(sorted(binaries))
    rank = _best(ranks)
    sources = sorted(fixed)
    reboot = 'reboot' in restart
    steps = {'backup': [], 'restart': []}
    vm, node = host.get('vmid'), host.get('node')
    if str(vm or '').isdigit():
        steps['backup'].append(f'qm snapshot {vm} avant-maj-{stamp} --description "OpsControl : mise à jour sécurité"'
                               + (f'   # sur le nœud Proxmox {node}' if node and remediation.SAFE_NAME.fullmatch(str(node)) else ''))
    else:
        steps['backup'].append('# VM non identifiée : vérifier une sauvegarde récente (Bacula) avant d’intervenir')
    if manager == 'dpkg':
        steps['precheck'] = [f'apt-cache policy {names}', f'apt-get -s install --only-upgrade {names}   # simulation, aucune modification']
        steps['backup'].append(f"dpkg-query -W -f='${{Package}}=${{Version}}\\n' {names} | sudo tee /root/versions-avant-maj-{stamp}.txt")
        steps['apply'] = ['sudo apt-get update', f'sudo apt-get install --only-upgrade {names}']
        steps['verify'] = [f"dpkg --compare-versions \"$(dpkg-query -W -f='${{source:Version}}' {next(b for b, s in sorted(binaries.items()) if s == src)})\" "
                           f"ge {version} && echo '{src} CORRIGÉ' || echo '{src} À REPRENDRE'"
                           for src, version in sorted(fixed.items())][:40]
        steps['rollback'] = ([f'sudo apt-get install --allow-downgrades {" ".join(f"{b}={v}" for b, v in sorted(pinned.items()))}']
                             if pinned else []) + ['# Versions exactes d’origine : /root/versions-avant-maj-' + stamp + '.txt']
    else:
        steps['precheck'] = [f'rpm -q {names}', f'sudo dnf check-update {names}   # EL7 : yum check-update']
        steps['backup'].append(f'rpm -q {names} | sudo tee /root/versions-avant-maj-{stamp}.txt')
        steps['apply'] = [f'sudo dnf upgrade {names}   # EL7 : sudo yum update {names}']
        steps['verify'] = [f'rpm -q {names}']
        steps['rollback'] = ['sudo dnf history list   # repérer la transaction de mise à jour',
                             'sudo dnf history undo <ID_DE_LA_TRANSACTION>   # EL7 : sudo yum history undo <ID>']
    if reboot:
        steps['restart'] = ['sudo needrestart -r l   # liste seulement', '# Redémarrage du serveur dans la fenêtre validée (noyau / glibc / systemd)']
    else:
        steps['restart'] = ['sudo needrestart -r l   # liste les services qui gardent l’ancienne version, sans rien relancer',
                            '# Relancer les services listés dans la fenêtre validée (systemctl restart <service>)']
    steps['verify'].append('Relancer « Analyser ce serveur » dans OpsControl : les CVE passent à « Corrigée » si la version est constatée.')
    if str(vm or '').isdigit():
        steps['rollback'].append(f'qm rollback {vm} avant-maj-{stamp}   # DERNIER RECOURS : perd les écritures depuis l’instantané')
    return _rec('packages', rank, f'Mettre à jour {len(sources) or len(binaries)} paquet(s) vulnérable(s) — {len(items)} CVE',
                [f'{len(items)} vulnérabilité(s) ouverte(s) corrigée(s) par la distribution'] + why +
                [f'Paquets : {", ".join(sources)}' if sources else None, 'Serveur exposé à Internet' if exposed else None],
                steps, [v['cve'] for v in items], '; '.join(sorted(impacts))[:600], 'reboot' if reboot else 'services',
                {'packages': sorted(binaries), 'targets': fixed})


def _upstream(host, inventory, items, exposed, cve_data):
    """Une recommandation par instance (conteneur, WordPress, Proxmox…), pour toutes ses CVE."""
    groups = {}
    for v in items:
        inst = ((v.get('evidence') or {}).get('instances') or [{}])[0]
        groups.setdefault((v['evidence'].get('manager'), inst.get('instance') or v['package']), []).append(v)
    out = []
    for (manager, label), group in groups.items():
        target = None
        for v in group:
            if v.get('fixed') and versions.UPSTREAM.fullmatch(str(v['fixed'])) and (
                    target is None or versions.upstream_compare(v['fixed'], target['fixed']) > 0):
                target = v
        base = target or group[0]
        procedure = remediation.plan(base, host, inventory, cve_data.get(base['cve']))
        ranks = [_vuln_rank(v, exposed)[0] for v in group]
        out.append(_rec('upstream', _best(ranks), f'{label} : passer en {base.get("fixed") or "version corrigée"} — {len(group)} CVE',
                        [f'{len(group)} vulnérabilité(s) confirmée(s) par la version de l’éditeur', procedure['impact'],
                         'Serveur exposé à Internet' if exposed else None] + procedure['warnings'],
                        {'precheck': procedure['precheck'], 'backup': procedure['backup'], 'apply': procedure['update'],
                         'restart': procedure['apply'], 'verify': procedure['verify'], 'rollback': procedure['rollback']},
                        [v['cve'] for v in group], procedure['impact'], procedure['restart'], {'instance': label}))
    return out


def _verify(host, inventory, matches, exposed):
    """CVE potentielles : vérifier AVANT d'agir (rétroportage, version réelle)."""
    if not matches:
        return None
    manager = (inventory or {}).get('manager')
    binaries_of = {}
    for p in (inventory or {}).get('packages') or []:
        binaries_of.setdefault(p['source'], []).append(p['name'])
    lines, ranks = [], []
    for m in matches[:60]:
        cve = m['cve'] if remediation.SAFE_CVE.fullmatch(str(m['cve'])) else None
        ranks.append(m.get('rank') or 'P3')
        package = m.get('package')
        if m.get('origin') == 'distro' and cve and package in binaries_of:
            first = sorted(binaries_of[package])[0]
            lines.append(f'zgrep -c {cve} /usr/share/doc/{first}/changelog.Debian.gz   # > 0 : corrigé par rétroportage'
                         if manager == 'dpkg' else f'rpm -q --changelog {first} | grep -c {cve}   # > 0 : corrigé par rétroportage')
        elif m.get('origin') == 'image':
            match = remediation._INSTANCE.match(str(m.get('instance') or ''))
            if match:
                probe = 'php -v' if m.get('tech') == 'php' else 'cat /etc/os-release'
                lines.append(f'docker exec $(docker ps -q -f name={match[2]} | head -n 1) {probe}   # version réelle de {m["tech"]}')
        elif m.get('origin') == 'declared':
            lines.append('get system status   # console FortiGate : version FortiOS réelle')
    lines = _uniq(lines)
    # Potentielle : jamais plus urgente que P2, même critique — elle reste à prouver.
    rank = max(_best(ranks), 'P2', key=_rank_value)
    return _rec('verify', rank, f'Vérifier {len(matches)} CVE potentielle(s) avant toute correction',
                ['Version amont dans une plage publiée, mais rétroportage possible ou version incomplète',
                 'Serveur exposé à Internet' if exposed else None],
                {'precheck': lines, 'verify': ['Puis, dans Sécurité > Veille : « Confirmer après vérification » ou « Non applicable », justifié.']},
                [m['cve'] for m in matches])


def _os_risk(host, inventory, support, exposed, has_vulns, today):
    if not support:
        return None
    os_info = (inventory or {}).get('os') or {}
    key = (os_info.get('id'), os_info.get('version_id') if os_info.get('id') == 'ubuntu' else str(os_info.get('version_id') or '').split('.')[0])
    target = NEXT_RELEASE.get(key, 'une version supportée de la distribution')
    until = date.fromisoformat(support['until'])
    if not support['expired'] and until - today > timedelta(days=180):
        return None
    rank = ('P1' if exposed else 'P2') if support['expired'] else 'P3'
    steps = {'precheck': ['cat /etc/os-release', 'systemctl list-units --type=service --state=running --no-pager   # services à reprendre',
                          '# Inventorier applications, dépendances et versions requises avant de choisir la cible'],
             'backup': ['# Sauvegarde complète vérifiée (Bacula) et instantané Proxmox avant la migration',
                        'sudo tar czf /root/etc-avant-migration.tgz /etc'],
             'apply': [f'# Cible : {target}',
                       ('# Debian : une release à la fois (sources.list, apt full-upgrade), après lecture des notes de version'
                        if key[0] == 'debian' else '# Ubuntu : sudo do-release-upgrade' if key[0] == 'ubuntu' else
                        '# Préférer une réinstallation sur la nouvelle version et la reprise des services (moins risqué en production)')],
             'verify': ['cat /etc/os-release', 'Relancer « Analyser ce serveur » : la fin de support doit disparaître des risques.'],
             'rollback': ['# Restaurer l’instantané Proxmox ou la sauvegarde Bacula pris avant la migration']}
    return _rec('os', rank, ('Système hors support : ' if support['expired'] else 'Fin de support proche : ') + (os_info.get('pretty') or ''),
                [support['label'], 'Plus aucun correctif de sécurité publié' if support['expired'] else
                 f'Correctifs jusqu’au {until.strftime("%d/%m/%Y")} seulement', 'Serveur exposé à Internet' if exposed else None,
                 'Des vulnérabilités ouvertes resteront sans correctif' if has_vulns and support['expired'] else None],
                steps, impact='Migration de système : fenêtre de maintenance et tests applicatifs nécessaires.', restart='window')


def build(host, inventory, vulns, matches, exposed, support, wazuh, cve_data=None, today=None, at=None):
    """Plan de correction complet d'un serveur, trié par priorité."""
    today = today or date.today()
    at = at or datetime.now(timezone.utc)
    stamp = at.strftime('%Y%m%d')
    cve_data = cve_data or {}
    inv = inventory or {}
    active = [v for v in vulns if v['status'] in ('open', 'validated', 'in_progress')]
    distro, upstream = [], []
    # Un passage linéaire : comparer chaque dictionnaire à toute la liste des
    # paquets coûtait quadratiquement sur les serveurs ayant des milliers de CVE.
    for vuln in active:
        evidence = vuln.get('evidence') or {}
        target = distro if evidence.get('manager') in ('dpkg', 'rpm', None) and not evidence.get('instances') else upstream
        target.append(vuln)
    recs = []
    package_rec = _packages(host, inv, distro, exposed, stamp)
    if package_rec:
        recs.append(package_rec)
    recs += _upstream(host, inv, upstream, exposed, cve_data)
    potential = [m for m in matches if m['status'] == 'potential']
    verify = _verify(host, inv, potential, exposed)
    if verify:
        recs.append(verify)
    os_risk = _os_risk(host, inv, support, exposed, bool(active), today)
    if os_risk:
        recs.append(os_risk)
    if inv.get('reboot_required'):
        recs.append(_rec('reboot', 'P2' if any(v['package'] in ('linux', 'kernel', 'glibc', 'systemd') for v in active) else 'P3',
                         'Redémarrage en attente', ['/var/run/reboot-required présent : des correctifs déjà installés ne sont pas actifs',
                                                    'Noyau en cours : ' + str(inv.get('kernel') or '—')],
                         {'precheck': ['cat /var/run/reboot-required.pkgs 2>/dev/null', 'sudo needrestart -r l'],
                          'backup': ['# Prévenir les utilisateurs ; vérifier la reprise automatique des services au démarrage'],
                          'restart': ['# Redémarrage dans la fenêtre validée (jamais automatique)'],
                          'verify': ['uname -r', 'systemctl --failed']}, restart='reboot'))
    covered = {b for v in distro for b in (v.get('evidence') or {}).get('binaries') or []}
    pending = [u for u in inv.get('upgradable') or [] if u['name'] not in covered]
    if pending:
        security = [u for u in pending if 'security' in str(u.get('suite') or '')]
        names = ' '.join(sorted({u['name'] for u in pending if remediation.SAFE_NAME.fullmatch(u['name'])})[:80])
        recs.append(_rec('pending', 'P3' if security else 'P4', f'{len(pending)} mise(s) à jour disponible(s) hors CVE suivies',
                         [f'{len(security)} depuis un dépôt de sécurité' if security else 'Mises à jour de maintenance',
                          'Liste lue au dernier relevé (apt list --upgradable / dnf check-update)'],
                         {'precheck': ['apt list --upgradable 2>/dev/null' if inv.get('manager') == 'dpkg' else 'sudo dnf check-update'],
                          'apply': [(f'sudo apt-get install --only-upgrade {names}' if inv.get('manager') == 'dpkg' else f'sudo dnf upgrade {names}')
                                    + '   # dans la fenêtre validée, après sauvegarde'] if names else [],
                          'verify': ['Relancer « Analyser ce serveur » dans OpsControl']}))
    images = (inv.get('docker') or {}).get('findings') or []
    if images:
        recs.append(_rec('images', 'P3' if any(f['level'] == 'warning' for f in images) else 'P4',
                         f'{len(images)} image(s) Docker à renouveler ou à figer',
                         [f'{f["repository"]}:{f["tag"]} — {f["finding"]}' for f in images[:10]],
                         {'precheck': ['docker ps --format "{{.Names}} {{.Image}}"'],
                          'apply': ['# Remplacer chaque image par une version maintenue, au tag figé (jamais « latest » en production)'],
                          'verify': ['docker ps', 'Relancer « Analyser ce serveur »'],
                          'rollback': ['# Conserver l’image actuelle (docker image tag <image> <image>-avant) pour revenir en arrière']}))
    for f in host.get('findings') or []:
        if f.get('severity') not in ('critical', 'warning') or not SECURITY_FINDING.search(f'{f.get("domain")} {f.get("id")} {f.get("title")}'):
            continue
        recs.append(_rec('audit', 'P2' if f['severity'] == 'critical' else 'P3', str(f.get('title') or f.get('id'))[:200],
                         [f'Audit SSH ({f.get("domain")}) : {f.get("evidence") or ""}'[:300], f.get('precaution')],
                         {'precheck': [f['check_command']] if f.get('check_command') else [],
                          'apply': [f['solution_command']] if f.get('solution_command') else [],
                          'verify': ['Relancer « Auditer ce serveur » : le constat doit disparaître.']},
                         extra={'finding': f.get('id'), 'requires_adaptation': bool(f.get('requires_adaptation'))}))
    coverage = []
    if not inv.get('collected_at'):
        coverage.append('Aucun relevé des paquets : aucune conclusion possible sur les vulnérabilités')
    else:
        try:
            age = at - datetime.fromisoformat(inv['collected_at'])
            if age > timedelta(days=7):
                coverage.append(f'Relevé des paquets ancien ({age.days} jours) : relancer l’analyse')
        except (TypeError, ValueError):
            pass
    if not wazuh:
        coverage.append('Aucune détection Wazuh rapprochée : seule la preuve Debian / éditeur est disponible')
    if coverage:
        recs.append(_rec('coverage', 'P2' if not inv.get('collected_at') else 'P4', 'Compléter la couverture d’analyse', coverage,
                         {'apply': ['Sécurité > Analyse par serveur > « Analyser » (relevé SSH en lecture seule)',
                                    'Wazuh ≥ 4.8 : déclarer l’indexeur dans Sécurité > Veille > Sources et réglages']}))
    recs.sort(key=lambda r: (_rank_value(r['priority']), -len(r['cves'])))
    for index, rec in enumerate(recs, 1):
        rec['order'] = index
    counts = {rank: sum(r['priority'] == rank for r in recs) for rank in RANKS}
    level = next((rank for rank in RANKS if counts[rank]), None)
    return {'recommendations': recs, 'counts': counts, 'level': level,
            'summary': (f'{len(recs)} recommandation(s), priorité la plus haute {level} ({RANK_LABELS[level]})' if level
                        else 'Aucune recommandation : rien de prouvé à corriger sur ce serveur avec les données disponibles'),
            'text': text(host, recs, at), 'generated_at': at.isoformat(),
            'generated_from': 'Relevé SSH, vulnérabilités prouvées, veille, audit SSH et inventaire ; aucun LLM, rien n’est exécuté.'}


def text(host, recs, at):
    """Plan complet à copier (ticket, mail, fiche d'intervention)."""
    lines = [f'Plan de correction — {host.get("name") or host.get("key")} ({host.get("ip") or "IP inconnue"}, '
             f'{host.get("environment") or "environnement non renseigné"}) — {at.strftime("%d/%m/%Y %H:%M")} UTC', '']
    for rec in recs:
        lines.append(f'{rec["order"]}. [{rec["priority"]} — {rec["priority_label"]}] {rec["title"]}')
        lines += ['   - ' + w for w in rec['why']]
        if rec['cves']:
            lines.append('   CVE : ' + ', '.join(rec['cves'][:30]) + (' …' if len(rec['cves']) > 30 else ''))
        for title, key in (('Vérifier', 'precheck'), ('Sauvegarder', 'backup'), ('Appliquer', 'apply'), ('Prise en compte', 'restart_steps'),
                           ('Contrôler', 'verify'), ('Retour arrière', 'rollback')):
            if rec[key]:
                lines.append(f'   {title} :')
                lines += ['     ' + step for step in rec[key]]
        lines.append('')
    lines.append('OpsControl n’exécute aucune de ces commandes : fenêtre validée, sauvegarde vérifiée, aucun redémarrage automatique.')
    return '\n'.join(lines)
