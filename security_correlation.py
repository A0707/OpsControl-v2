"""Corrélation CVE ↔ serveurs par technologie, à partir des versions réellement relevées.

Chaque technologie installée sur un serveur (paquet, conteneur, WordPress, Proxmox, FortiGate)
est une « instance » avec une version et une ORIGINE, qui décide de ce qu'on peut conclure :

    image     image Docker officielle : version amont exacte, aucun rétroportage
    file      fichier de version de l'application (WordPress wp-includes/version.php)
    vendor    paquet de l'éditeur lui-même (pve-manager pour Proxmox VE)
    binary    version annoncée par le démon (docker info)
    distro    paquet de distribution : la distribution peut RÉTROPORTER un correctif sans
              changer la version amont ; seul un avis de la distribution (DSA/DLA), Wazuh ou
              le changelog du paquet permet de conclure
    declared  version saisie dans l'inventaire (FortiGate) : jamais mesurée

Plages affectées : configurations NVD (CPE et bornes de version, avec les plateformes
requises — « ET Windows » exclut un serveur Linux) et avis officiels des éditeurs (PHP,
WordPress). Résultat par instance :

    confirmed       version dans une plage affectée, origine fiable, ou avis de distribution
                    publié et non appliqué
    potential       dans une plage mais rétroportage possible, version incomplète (tag « 8.2 »)
                    ou déclarée, ou plateforme requise non vérifiable
    not_applicable  hors plage, plateforme exclue, ou correctif rétroporté prouvé

Aucune donnée n'est inventée : sans plage publiée, la CVE n'est pas corrélée.
"""
from __future__ import annotations

import hashlib
import json
import re

import security_versions as versions

# Technologie -> libellé, CPE NVD (fournisseur, produit), motif des paquets SOURCE, images.
TECHS = {
    'php': {'label': 'PHP', 'cpe': [('php', 'php')], 'packages': r'php\d+(\.\d+)?|php', 'images': ('php',)},
    'wordpress': {'label': 'WordPress', 'cpe': [('wordpress', 'wordpress')], 'packages': r'wordpress', 'images': ('wordpress',)},
    'apache': {'label': 'Apache HTTP Server', 'cpe': [('apache', 'http_server')], 'packages': r'apache2|httpd', 'images': ('httpd',)},
    'modsecurity': {'label': 'ModSecurity', 'cpe': [('trustwave', 'modsecurity'), ('owasp', 'modsecurity')],
                    'packages': r'modsecurity(-apache)?|mod_security|libmodsecurity3?', 'images': ()},
    'postgresql': {'label': 'PostgreSQL', 'cpe': [('postgresql', 'postgresql')], 'packages': r'postgresql(-\d+|\d*-server)?',
                   'images': ('postgres',)},
    'openssl': {'label': 'OpenSSL', 'cpe': [('openssl', 'openssl')], 'packages': r'openssl(\d*)?', 'images': ()},
    'openssh': {'label': 'OpenSSH', 'cpe': [('openbsd', 'openssh')], 'packages': r'openssh(-server)?', 'images': ()},
    'nginx': {'label': 'nginx', 'cpe': [('f5', 'nginx'), ('nginx', 'nginx')], 'packages': r'nginx', 'images': ('nginx',)},
    'docker': {'label': 'Docker Engine', 'cpe': [('docker', 'engine'), ('mobyproject', 'moby'), ('docker', 'docker')],
               'packages': r'docker\.io|docker-ce|moby-engine', 'images': ()},
    'proxmox': {'label': 'Proxmox VE', 'cpe': [('proxmox', 'virtual_environment')], 'packages': r'pve-manager', 'images': (),
                'vendor': True},
    'fortios': {'label': 'FortiOS (FortiGate)', 'cpe': [('fortinet', 'fortios')], 'packages': None, 'images': ()},
}
CPE_TECH = {cpe: tech for tech, spec in TECHS.items() for cpe in spec['cpe']}
ADVISORY_TECH = {'php_advisories': 'php', 'wordpress_advisories': 'wordpress'}
STATUS_LABELS = {'confirmed': 'Confirmée', 'potential': 'Potentielle', 'not_applicable': 'Non applicable'}
SEVERITY_SCORE = {'critical': 9.5, 'high': 8.0, 'medium': 5.5, 'moderate': 5.5, 'low': 3.0}
_VERSION_TAG = re.compile(r'^(\d+(?:\.\d+){0,3})(?:$|[-_.a-z])')


def instance_id(host_key, tech, instance):
    return hashlib.sha256(f'{host_key}|{tech}|{instance}'.encode()).hexdigest()[:20]


def _tag_version(tag):
    """Version portée par un tag d'image : (exacte, branche). « 8.3.30-apache » -> exacte ;
    « 8.2-fpm » -> branche « 8.2 » ; « latest » -> (None, None)."""
    match = _VERSION_TAG.match(str(tag or ''))
    if not match:
        return None, None
    value = match[1]
    return (value, None) if value.count('.') >= 2 else (None, value)


def _image(reference):
    """« registre/dépôt/php:8.3.30-apache@sha256:… » -> (dernier segment, tag)."""
    ref = str(reference or '').split('@')[0]
    name, _, tag = ref.rpartition(':') if ':' in ref.rsplit('/', 1)[-1] else (ref, '', 'latest')
    return name.rsplit('/', 1)[-1].lower(), tag or 'latest'


def instances(host, inventory):
    """Technologies installées sur un serveur, avec version et origine (jamais devinées)."""
    inv = inventory or {}
    out = []
    manager = inv.get('manager')

    def add(tech, label, version, origin, branch=None, package=None, detail=None):
        out.append({'tech': tech, 'instance': label[:160], 'version': version, 'branch': branch, 'origin': origin,
                    'package': package, 'detail': detail, 'manager': manager if origin == 'distro' else origin})
    seen = set()
    for p in inv.get('packages') or []:
        for tech, spec in TECHS.items():
            pattern = spec.get('packages')
            if not pattern or not re.fullmatch(pattern, p['source']) or (tech, p['source']) in seen:
                continue
            seen.add((tech, p['source']))
            origin = 'vendor' if spec.get('vendor') else 'distro'
            add(tech, 'paquet ' + p['source'], versions.upstream_of(manager, p['source_version']), origin,
                package=p['source'], detail=p['source'] + ' ' + p['source_version'])
    containers = (inv.get('docker') or {}).get('containers') or []
    services = (inv.get('docker') or {}).get('services') or []
    for kind, rows in (('conteneur', containers), ('service Swarm', services)):
        for row in rows:
            name, tag = _image(row.get('image'))
            exact, branch = _tag_version(tag)
            for tech, spec in TECHS.items():
                if name in spec['images']:
                    add(tech, f'{kind} {row.get("name")} ({row.get("image")})', exact, 'image', branch=branch, detail=row.get('image'))
            # WordPress officiel : « wordpress:6.8.1-php8.3-apache » porte aussi la branche PHP.
            php = re.search(r'php(\d+\.\d+(?:\.\d+)?)', tag)
            if name == 'wordpress' and php:
                value = php[1]
                add('php', f'{kind} {row.get("name")} ({row.get("image")})', value if value.count('.') >= 2 else None,
                    'image', branch=None if value.count('.') >= 2 else value, detail=row.get('image'))
    for site in inv.get('wordpress') or []:
        add('wordpress', 'WordPress ' + site['path'], site['version'], 'file', detail=site['path'])
    swarm = (inv.get('docker') or {}).get('swarm') or {}
    if swarm.get('server_version'):
        add('docker', 'démon Docker' + (' (nœud Swarm ' + swarm['state'] + ')' if swarm.get('state') == 'active' else ''),
            versions.upstream_of(None, swarm['server_version']), 'binary', detail='docker info')
    if re.search(r'forti', (str(host.get('role')) + ' ' + str(host.get('name'))).lower()):
        declared = str(host.get('firmware_version') or '').strip()
        add('fortios', 'FortiGate ' + str(host.get('name') or host.get('key')),
            declared if versions.UPSTREAM.fullmatch(declared) else None, 'declared', detail='firmware_version (inventaire)')
    return out


def ranges_for(tech, cve):
    """Plages affectées pour une technologie : [(source, plages, plateformes)]."""
    found = []
    for config in cve.get('nvd_config') or []:
        entries = [v for v in config.get('vulnerable') or [] if CPE_TECH.get((v['vendor'], v['product'])) == tech]
        if entries:
            found.append(('NVD', entries, config.get('platforms') or []))
    for advisory in cve.get('advisories') or []:
        if ADVISORY_TECH.get(advisory.get('source')) == tech and advisory.get('ranges'):
            found.append((advisory.get('label') or advisory['source'], advisory['ranges'], []))
    return found


def _platform(platforms, host_os):
    """(applicable?, motif) : une configuration « ET Windows » exclut un serveur Linux."""
    systems = [p for p in platforms if p.get('part') == 'o']
    if not systems:
        return (None, 'plateforme requise non vérifiable : ' + ', '.join(p['vendor'] + ' ' + p['product'] for p in platforms)) \
            if platforms else (True, None)
    linux = (host_os or {}).get('id') not in (None, '', 'windows')
    for p in systems:
        if p['vendor'] in ('microsoft', 'apple') and linux:
            continue
        return True, None
    return False, 'configuration limitée à ' + ', '.join(sorted({p['vendor'] + ' ' + p['product'] for p in systems}))


def _contains(inst, rng):
    """True, False, 'partial' (branche seule) ou None (version inconnue)."""
    if rng.get('exact'):
        if inst['version']:
            return versions.upstream_compare(inst['version'], rng['exact']) == 0
        return 'partial' if inst['branch'] and str(rng['exact']).startswith(inst['branch'] + '.') else None
    if inst['version']:
        return versions.in_range(inst['version'], rng.get('start'), rng.get('start_included', True),
                                 rng.get('end'), rng.get('end_included', False))
    if inst['branch']:
        result = versions.branch_in_range(inst['branch'], rng.get('start'), rng.get('start_included', True),
                                          rng.get('end'), rng.get('end_included', False))
        return {'all': True, 'some': 'partial', 'none': False}.get(result)
    return None


def _fixed(rng):
    if rng.get('fixed'):
        return rng['fixed']
    if rng.get('end') and not rng.get('end_included'):
        return rng['end']
    return ('postérieure à ' + rng['end']) if rng.get('end') else None


def classify(inst, cve, host, facts):
    """Applicabilité d'une CVE à une instance : {status, reason, fixed, source} ou None
    (aucune plage publiée pour cette technologie : rien n'est conclu)."""
    found = ranges_for(inst['tech'], cve)
    if not found:
        return None
    best, partial, unknown, excluded, fixed, source = False, False, False, None, None, None
    for name, entries, platforms in found:
        ok, why = _platform(platforms, facts.get('os'))
        if ok is False:
            excluded = why
            continue
        for rng in entries:
            hit = _contains(inst, rng)
            if hit is True and ok is True:
                best, fixed, source = True, _fixed(rng), name
                break
            if hit is True or hit == 'partial':
                partial, fixed, source = True, fixed or _fixed(rng), source or name
                if why:
                    excluded = excluded or why
            elif hit is None:
                unknown = True
        if best:
            break
    shown = inst['version'] or (inst['branch'] + '.x' if inst['branch'] else 'inconnue')
    if not (best or partial or unknown):
        return {'status': 'not_applicable', 'source': found[0][0], 'fixed': None,
                'reason': excluded or f'version {shown} hors des plages affectées ({", ".join(sorted({f[0] for f in found}))})'}
    if not best:
        reason = ('version incomplète (' + shown + ') : le correctif installé ne peut pas être déterminé' if partial and inst['branch']
                  else excluded if partial and excluded else 'version non relevée sur ce serveur')
        return {'status': 'potential', 'source': source or found[0][0], 'fixed': fixed, 'reason': reason}
    if inst['origin'] == 'distro':
        return _distro(inst, cve, host, facts, fixed, source)
    if inst['origin'] == 'declared':
        return {'status': 'potential', 'source': source, 'fixed': fixed,
                'reason': f'version {shown} déclarée dans l’inventaire, non mesurée : vérifier sur l’équipement'}
    return {'status': 'confirmed', 'source': source, 'fixed': fixed,
            'reason': f'version {shown} ({ORIGIN_LABELS[inst["origin"]]}) dans une plage affectée ({source})'}


ORIGIN_LABELS = {'image': 'image Docker officielle', 'file': 'fichier de version', 'vendor': 'paquet de l’éditeur',
                 'binary': 'version du démon', 'distro': 'paquet de distribution', 'declared': 'version déclarée'}


def _distro(inst, cve, host, facts, fixed, source):
    """Paquet de distribution dans une plage amont : seules les preuves de la distribution
    tranchent (avis publié, changelog, Wazuh) ; sinon la CVE reste potentielle."""
    cve_id = cve['cve']
    release = (facts.get('os') or {}).get('codename')
    for advisory, fix in facts.get('fixes', {}).get((release, inst['package'], cve_id), []):
        older = versions.is_older('dpkg', facts['source_versions'].get(inst['package']) or '', fix)
        if older is False:
            return {'status': 'not_applicable', 'source': advisory, 'fixed': fix,
                    'reason': f'corrigé par rétroportage : {advisory} ({fix}) déjà installé'}
        if older:
            return {'status': 'confirmed', 'source': advisory, 'fixed': fix,
                    'reason': f'correctif de la distribution publié ({advisory}, {fix}) non appliqué'}
    if any(cve_id in cves for name, cves in (facts.get('changelog') or {}).items()
           if name in (facts.get('binaries_of') or {}).get(inst['package'], ())):
        return {'status': 'not_applicable', 'source': 'changelog', 'fixed': None,
                'reason': 'CVE citée dans le changelog du paquet installé : correctif rétroporté'}
    if cve_id in (facts.get('wazuh_cves') or set()):
        return {'status': 'confirmed', 'source': 'Wazuh', 'fixed': fixed, 'reason': 'détectée aussi par Wazuh sur ce serveur'}
    return {'status': 'potential', 'source': source, 'fixed': fixed,
            'reason': (f'version amont {inst["version"]} dans la plage ({source}) mais paquet de distribution : '
                       'correctif rétroporté possible, aucun avis de la distribution relevé')}


def host_context(db, host, inventory, wazuh):
    """Faits du serveur utiles à la décision, lus une fois par analyse."""
    inv = inventory or {}
    os_info = inv.get('os') or {}
    binaries_of, source_versions = {}, {}
    for p in inv.get('packages') or []:
        binaries_of.setdefault(p['source'], set()).add(p['name'])
        source_versions[p['source']] = p['source_version']
    fixes = {}
    if os_info.get('codename'):
        for advisory, package, fixed, cves in db.execute('SELECT advisory, package, fixed, cves FROM sec_fixes WHERE release=?',
                                                         (os_info['codename'],)):
            for cve in json.loads(cves):
                fixes.setdefault((os_info['codename'], package, cve), []).append((advisory, fixed))
    return {'os': os_info, 'fixes': fixes, 'changelog': {k: set(v) for k, v in (inv.get('changelog') or {}).items()},
            'binaries_of': binaries_of, 'source_versions': source_versions,
            'wazuh_cves': {i['cve'] for i in (wazuh or {}).get('items') or []}}


def priority(item):
    """Priorité de remédiation déterministe : (rang P1-P4, score, motifs).

    Gravité (CVSS NVD, sinon gravité de l'éditeur) + exploitation connue (KEV) + probabilité
    d'exploitation (EPSS) + exposition Internet + applicabilité confirmée."""
    base = item.get('cvss')
    if base is None:
        base = SEVERITY_SCORE.get(str(item.get('severity') or '').lower(), 5.0)
    score, why = float(base), [f'gravité {base:.1f}']
    if item.get('kev'):
        score += 3
        why.append('exploitée (CISA KEV)')
    if (item.get('epss') or 0) >= 0.5:
        score += 2
        why.append(f'EPSS {item["epss"]:.0%}')
    elif (item.get('epss') or 0) >= 0.1:
        score += 1
        why.append(f'EPSS {item["epss"]:.0%}')
    if item.get('exposed'):
        score += 2
        why.append('exposée à Internet')
    if item.get('status') == 'confirmed':
        score += 1
        why.append('applicabilité confirmée')
    rank = 'P1' if score >= 12 or (item.get('kev') and item.get('status') == 'confirmed') else \
        'P2' if score >= 10 else 'P3' if score >= 7 else 'P4'
    return rank, round(score, 1), why
