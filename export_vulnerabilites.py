"""Classeur Excel d'audit des vulnérabilités et des correctifs ciblés, serveur par serveur.

Méthode rapide : aucune connexion. Les vulnérabilités actives (Détectée, Validée,
Correction planifiée) et le dernier relevé SSH des paquets sont lus dans la base locale
d'OpsControl, en lecture seule. Rien n'est exécuté : le plan de correction est du TEXTE à
copier, à dérouler dans une fenêtre validée, sauvegarde vérifiée.

Feuilles :
- « Synthèse serveurs » : ordre de passage, volumes par gravité, redémarrage, commande ciblée ;
- « Paquets à corriger » : une ligne par serveur et paquet source, version cible, CVE couvertes ;
- « Plan de correction » : étapes copiables par serveur (contrôles, sauvegarde, mise à jour,
  prise en compte, vérification, retour arrière) ;
- « Détail CVE » : une ligne par vulnérabilité (omise avec --sans-detail) ;
- « Source et limites ».

Usage :
    python export_vulnerabilites.py [sortie.xlsx] [--serveur CLÉ_NOM_OU_IP ...] [--sans-detail]

Pour des données à jour : « Analyser » les serveurs dans OpsControl > Sécurité, puis
relancer ce script. Prérequis : requirements-tools.txt (openpyxl).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone
from functools import cmp_to_key
from pathlib import Path

import security_cve as sc
import security_remediation as sr
import security_versions as sv

BASE = Path(__file__).resolve().parent
GRAVITES = ('critical', 'high', 'medium', 'low')
PRISE_EN_COMPTE = {'reboot': 'Redémarrage du serveur', 'window': 'Redémarrage du service (fenêtre)',
                   'services': 'Rechargement des services', 'none': 'Aucune', 'unknown': 'À qualifier (needrestart)'}
# Métapaquet du noyau : sans lui, « --only-upgrade linux-libc-dev » ne met à jour que les
# en-têtes, et le noyau chargé reste vulnérable.
_META_NOYAU = re.compile(r'^linux-image-(?:cloud-|rt-)?(?:amd64|arm64|686|686-pae)$')
_IMAGE_NOYAU = re.compile(r'^linux-image-\d[A-Za-z0-9.+-]*$')
_CONTROLE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')
CVE_LISTEES = 25


def base_donnees() -> Path:
    return Path(os.environ.get('COCKPIT_DB') or BASE / 'data' / 'state.sqlite3').resolve()


def selection(hotes: list[dict], serveurs: list[str]) -> list[str]:
    """Clés des serveurs demandés (clé, nom ou IP) ; un nom inconnu arrête l'export."""
    cles = []
    for demande in serveurs:
        cible = demande.lower()
        hote = next((h for h in hotes if cible in {str(h.get(c, '')).lower() for c in ('key', 'name', 'ip')}), None)
        if hote is None:
            raise SystemExit(f'Serveur « {demande} » absent de l’inventaire.')
        cles.append(hote['key'])
    return cles


def charger(db_path: Path, inventaire: Path, serveurs=()) -> tuple[list[dict], list[dict], dict]:
    """Inventaire, vulnérabilités actives (triées par priorité) et derniers relevés des paquets."""
    hotes = json.loads(inventaire.read_text(encoding='utf-8-sig'))['hosts']
    cles = selection(hotes, list(serveurs))
    where = 'v.status IN (' + ','.join('?' * len(sc.ACTIVE)) + ')'
    params = tuple(sc.ACTIVE)
    if cles:
        where += ' AND v.host_key IN (' + ','.join('?' * len(cles)) + ')'
        params += tuple(cles)
    db = sqlite3.connect(db_path.as_uri() + '?mode=ro', uri=True)
    try:
        vulns = sc.vulns(db, hotes, where, params)
        releves = {cle: sc._load_inventory(db, cle) for cle in {v['host_key'] for v in vulns}}
    finally:
        db.close()
    return hotes, vulns, releves


def _cvss(v: dict):
    return v['cvss'] if v['cvss'] is not None else ((v['evidence'] or {}).get('wazuh') or {}).get('cvss')


def _plus_recente(manager, a, b):
    if not a or not b:
        return a or b
    try:
        return b if sv.compare(manager, b, a) > 0 else a
    except ValueError:
        return a


def _disponible(groupe: dict) -> str:
    """Le correctif est-il proposé par les dépôts du serveur (relevé apt, sans mise à jour du cache) ?"""
    candidat = groupe['candidat']
    if candidat is None:
        return 'Non mesuré' if not groupe['depot_absent'] else 'Non : dépôt security absent ou cache apt ancien'
    version = candidat.split(' (', 1)[0]
    if groupe['cible'] and sv.is_older(groupe['manager'], version, groupe['cible']):
        return f'Partiel : {candidat} < version cible'
    return f'Oui : {candidat}'


def paquets(vulns: list[dict], releves: dict, hotes: list[dict]) -> list[dict]:
    """Une ligne par serveur et paquet source : version cible = plus haute version corrigée."""
    groupes = {}
    for v in vulns:
        ev = v['evidence'] or {}
        manager = ev.get('manager') or (releves.get(v['host_key']) or {}).get('manager')
        g = groupes.get((v['host_key'], v['package']))
        if g is None:
            g = groupes[(v['host_key'], v['package'])] = {
                'cle': v['host_key'], 'serveur': v['host_name'], 'ip': v['host_ip'], 'environnement': v['environment'],
                'paquet': v['package'], 'manager': manager, 'binaires': {}, 'installee': v['installed'], 'cible': None,
                'cves': [], 'gravites': dict.fromkeys(GRAVITES + ('none',), 0), 'cvss': None, 'kev': 0,
                'kev_echeance': None, 'candidat': None, 'depot_absent': False, 'a_verifier': 0, 'premiere': v}
        for binaire in ev.get('binaries') or []:
            g['binaires'].setdefault(binaire, None)
        g['binaires'].update(ev.get('binary_versions') or {})
        g['cible'] = _plus_recente(manager, g['cible'], v['fixed'])
        g['cves'].append(v['cve'])
        g['gravites'][v['severity'] if v['severity'] in GRAVITES else 'none'] += 1
        cvss = _cvss(v)
        if cvss is not None and (g['cvss'] is None or cvss > g['cvss']):
            g['cvss'] = cvss
        if v['kev']:
            g['kev'] += 1
            if v['kev_due'] and (not g['kev_echeance'] or v['kev_due'] < g['kev_echeance']):
                g['kev_echeance'] = v['kev_due']
        depot = str(ev.get('repository') or '')
        if depot.startswith('Correctif disponible'):
            proposee = depot.split(' : ', 1)[-1]
            courant = g['candidat'].split(' (', 1)[0] if g['candidat'] else None
            if _plus_recente(manager, courant, proposee.split(' (', 1)[0]) != courant:
                g['candidat'] = proposee
        elif depot:
            g['depot_absent'] = True
        if v['confidence'] == 'à vérifier':
            g['a_verifier'] += 1

    par_cle = {h['key']: h for h in hotes}
    for g in groupes.values():
        description, prise, services = sr._impact_of(g['paquet'])
        installes = {p['name'] for p in ((releves.get(g['cle']) or {}).get('packages') or [])}
        noms = sr._safe(sorted(g['binaires']), sr.SAFE_NAME)
        if g['paquet'] == 'linux' and g['manager'] == 'dpkg':
            noms += sorted(n for n in installes if _META_NOYAU.fullmatch(n) and n not in noms)
            prise = 'reboot'
        declares = {str(s.get('name') if isinstance(s, dict) else s).removesuffix('.service')
                    for s in (par_cle.get(g['cle']) or {}).get('services') or []}
        g.update(noms=noms, impact=description, prise=prise, disponible=_disponible(g),
                 services=sr._safe([s for s in services if s in declares] or (services if len(services) == 1 else []),
                                   sr.SAFE_NAME))
        g['commande'] = commande_maj(g, par_cle.get(g['cle']) or {'key': g['cle'], 'name': g['serveur']},
                                     releves.get(g['cle']))
    return sorted(groupes.values(), key=lambda g: (str(g['serveur']).lower(), -g['kev'], -(g['cvss'] or 0),
                                                   -len(g['cves']), g['paquet']))


def commande_maj(g: dict, hote: dict, releve) -> str:
    """Commande de mise à jour ciblée du paquet ; procédure OpsControl pour les autres sources."""
    noms = ' '.join(g['noms'])
    if g['manager'] == 'dpkg' and noms:
        return f'sudo apt-get install --only-upgrade {noms}'
    if g['manager'] == 'rpm' and noms:
        return f'sudo yum update {noms}' if (releve or {}).get('os', {}).get('version_id', '').startswith('7') \
            else f'sudo dnf upgrade {noms}'
    if g['manager'] in sr.UPSTREAM_STEPS:
        etapes = sr.plan(g['premiere'], hote, releve)['update']
        return ' ; '.join(etapes) or 'Procédure à établir : OpsControl > Sécurité > Correctifs'
    return 'Analyse SSH à relancer : gestionnaire de paquets inconnu'


def etat_noyau(releve) -> tuple[str, bool]:
    """(Texte, redémarrage en attente) : noyau chargé comparé au plus récent noyau installé."""
    if not releve:
        return 'Non relevé', False
    noyau = releve.get('kernel') or ''
    attente = bool(releve.get('reboot_required'))
    if releve.get('manager') != 'dpkg':
        return noyau or 'Inconnu', attente
    images = [p for p in releve.get('packages') or [] if _IMAGE_NOYAU.fullmatch(p.get('name', ''))]
    charge = next((p for p in images if p['name'] == f'linux-image-{noyau}'), None)
    if not images or charge is None:
        return f'{noyau} (paquet du noyau non retrouvé)', attente
    recent = max(images, key=cmp_to_key(lambda a, b: sv.debian_compare(a['version'], b['version'])))
    if recent['name'] != charge['name']:
        return (f'Redémarrage en attente : noyau chargé {noyau} ({charge["source_version"]}), '
                f'installé {recent["name"].removeprefix("linux-image-")} ({recent["source_version"]})'), True
    return f'{noyau} ({charge["source_version"]})', attente


def _prod(environnement) -> bool:
    return str(environnement or '').lower().startswith('prod')


def serveurs(lignes: list[dict], releves: dict, hotes: list[dict]) -> list[dict]:
    """Synthèse par serveur, triée dans l'ordre de passage conseillé (risque décroissant)."""
    par_cle = {h['key']: h for h in hotes}
    synthese = {}
    for g in lignes:
        s = synthese.setdefault(g['cle'], {'cle': g['cle'], 'serveur': g['serveur'], 'ip': g['ip'],
                                           'environnement': g['environnement'], 'paquets': [], 'cves': set(),
                                           'gravites': dict.fromkeys(GRAVITES + ('none',), 0), 'kev': 0, 'cvss': None})
        s['paquets'].append(g)
        s['cves'].update(g['cves'])
        for cle, nombre in g['gravites'].items():
            s['gravites'][cle] += nombre
        s['kev'] += g['kev']
        if g['cvss'] is not None and (s['cvss'] is None or g['cvss'] > s['cvss']):
            s['cvss'] = g['cvss']
    resultat = []
    for s in synthese.values():
        releve = releves.get(s['cle']) or {}
        hote = par_cle.get(s['cle']) or {}
        os_info = releve.get('os') or {}
        support = sc.os_support(os_info)
        noyau, attente = etat_noyau(releve or None)
        paquets_ = s['paquets']
        manager = next((g['manager'] for g in paquets_ if g['manager']), releve.get('manager'))
        noms = sorted({n for g in paquets_ for n in g['noms']})
        services = sorted({x for g in paquets_ for x in g['services']})
        redemarrage = attente or any(g['prise'] == 'reboot' for g in paquets_)
        vm, noeud = hote.get('vmid'), hote.get('node')
        if manager == 'dpkg' and noms:
            globale = 'sudo apt-get update && sudo apt-get install --only-upgrade ' + ' '.join(noms)
        else:
            globale = ' ; '.join(g['commande'] for g in paquets_)
        resultat.append({
            **s, 'gravites': s['gravites'], 'nb_cves': len(s['cves']), 'nb_paquets': len(paquets_),
            'os': os_info.get('pretty') or ' '.join(filter(None, (os_info.get('id'), os_info.get('version_id')))) or 'Non relevé',
            'support': (support or {}).get('label') or 'Non référencé', 'noyau': noyau, 'manager': manager,
            'dispo': sum(g['disponible'].startswith('Oui') for g in paquets_),
            'sans_depot': sum(g['disponible'].startswith(('Non :', 'Partiel')) for g in paquets_),
            'redemarrage': 'Oui' if redemarrage else 'Non', 'services': ', '.join(services),
            'fenetre': 'Oui' if redemarrage or any(g['prise'] == 'window' for g in paquets_) else 'Non',
            'instantane': f'VM {vm} sur {noeud}' if vm and noeud else f'VM {vm}' if vm else 'VM non identifiée : sauvegarde Bacula',
            'releve': (releve.get('collected_at') or 'Jamais').replace('T', ' ')[:19], 'commande': globale,
            'a_verifier': sum(g['a_verifier'] for g in paquets_), 'noms': noms, 'vm': vm, 'noeud': noeud,
        })
    resultat.sort(key=lambda s: (-s['kev'], -s['gravites']['critical'], -s['gravites']['high'],
                                 not _prod(s['environnement']), -s['nb_cves'], str(s['serveur']).lower()))
    for ordre, s in enumerate(resultat, 1):
        s['ordre'] = ordre
    return resultat


def plan(s: dict, stamp: str) -> list[dict]:
    """Étapes copiables pour un serveur ; aucune n'est exécutée par OpsControl."""
    etapes = []

    def ajoute(phase, commande, commentaire=''):
        etapes.append({'ordre': s['ordre'], 'serveur': s['serveur'], 'ip': s['ip'], 'n': len(etapes) + 1,
                       'phase': phase, 'commande': commande, 'commentaire': commentaire})

    paquets_ = s['paquets']
    noms = ' '.join(s['noms'])
    dpkg = s['manager'] == 'dpkg'
    rpm = s['manager'] == 'rpm'
    phase = '1. Vérifications (lecture seule)'
    if dpkg:
        ajoute(phase, "grep -rhE '^[^#]*(security\\.debian\\.org|debian-security)' /etc/apt/sources.list "
                      "/etc/apt/sources.list.d/ 2>/dev/null",
               'Résultat vide : dépôt de sécurité absent, à ajouter avant tout' +
               (f' ({s["sans_depot"]} paquet(s) sans correctif dans les dépôts relevés)' if s['sans_depot'] else ''))
        ajoute(phase, 'sudo apt-get update', 'Rafraîchit le cache des dépôts ; ne modifie aucun paquet')
        if noms:
            ajoute(phase, f'apt-get -s install --only-upgrade {noms}', 'Simulation : liste ce qui serait mis à jour')
        ajoute(phase, 'df -h / /boot /var', 'Espace libre (noyau dans /boot, archives dans /var/cache/apt)')
    elif rpm:
        ajoute(phase, 'sudo yum check-update' if s['commande'].startswith('sudo yum') else 'sudo dnf check-update',
               'Correctifs proposés par les dépôts')
        ajoute(phase, 'df -h / /boot /var', 'Espace libre')
    else:
        ajoute(phase, 'Relancer « Analyser ce serveur » dans OpsControl', 'Gestionnaire de paquets non relevé')

    phase = '2. Sauvegarde'
    if s['vm'] and s['noeud']:
        ajoute(phase, f'qm snapshot {s["vm"]} avant-patch-{stamp} --description "OpsControl correctifs {stamp}"',
               f'Sur le nœud Proxmox {s["noeud"]}')
    elif s['vm']:
        ajoute(phase, f'qm snapshot {s["vm"]} avant-patch-{stamp}', 'Sur le nœud Proxmox qui héberge la VM')
    else:
        ajoute(phase, 'Vérifier la dernière sauvegarde Bacula réussie', 'VM Proxmox non identifiée dans l’inventaire')
    if dpkg and noms:
        ajoute(phase, f"dpkg-query -W -f='${{Package}}=${{Version}}\\n' {noms} | sudo tee /root/versions-avant-patch-{stamp}.txt",
               'Versions actuelles : base du retour arrière')
    elif rpm and noms:
        ajoute(phase, f'rpm -q {noms} | sudo tee /root/versions-avant-patch-{stamp}.txt', 'Versions actuelles')
    for g in paquets_:
        config = sr.CONFIG_DIRS.get(g['paquet']) or ('/etc/php' if g['paquet'].startswith('php') else None)
        if config and g['manager'] in ('dpkg', 'rpm'):
            ajoute(phase, f'sudo tar czf /root/config-{g["paquet"]}-{stamp}.tgz {config}', f'Configuration de {g["paquet"]}')

    phase = '3. Mise à jour ciblée'
    for g in sorted(paquets_, key=lambda g: (-g['kev'], -(g['cvss'] or 0), -len(g['cves']))):
        detail = f'{g["paquet"]} {g["installee"] or "?"} → {g["cible"] or "version non fournie"} : {len(g["cves"])} CVE'
        if g['cvss'] is not None:
            detail += f', CVSS max {g["cvss"]}'
        if g['kev']:
            detail += f', {g["kev"]} exploitée(s) (CISA KEV)'
        if not g['disponible'].startswith('Oui'):
            detail += f' — dépôts : {g["disponible"]}'
        ajoute(phase, g['commande'], detail)

    phase = '4. Prise en compte'
    if dpkg or rpm:
        ajoute(phase, 'sudo needrestart -r l', 'Liste les services qui gardent l’ancienne version, sans rien relancer')
    for service in s['services'].split(', ') if s['services'] else []:
        if service in ('apache2', 'httpd'):
            ajoute(phase, f'sudo apachectl configtest && sudo systemctl reload {service}', 'Rechargement Apache')
        elif service == 'nginx':
            ajoute(phase, 'sudo nginx -t && sudo systemctl reload nginx', 'Rechargement nginx')
        else:
            ajoute(phase, f'sudo systemctl restart {service}', 'Dans la fenêtre validée')
    if s['redemarrage'] == 'Oui':
        ajoute(phase, 'sudo systemctl reboot', 'Redémarrage requis (noyau, libc, systemd ou noyau déjà en attente) : '
                                               'uniquement dans la fenêtre validée')

    phase = '5. Vérification'
    for g in paquets_:
        premier = g['noms'][0] if g['noms'] else None
        if dpkg and premier and g['cible'] and sr.SAFE_VERSION.fullmatch(g['cible']):
            ajoute(phase, f"dpkg --compare-versions \"$(dpkg-query -W -f='${{source:Version}}' {premier})\" ge {g['cible']} "
                          f"&& echo 'CORRIGÉ {g['paquet']}' || echo 'TOUJOURS VULNÉRABLE {g['paquet']}'", '')
        elif rpm and g['noms']:
            ajoute(phase, f'rpm -q {" ".join(g["noms"])}', f'Attendu : {g["cible"] or "voir le bulletin"}')
    if s['redemarrage'] == 'Oui':
        ajoute(phase, 'uname -r', 'Après redémarrage : le noyau chargé doit être le plus récent installé')
    for service in s['services'].split(', ') if s['services'] else []:
        ajoute(phase, f'systemctl is-active {service}', '')
    ajoute(phase, 'OpsControl > Sécurité > « Analyser ce serveur »',
           'Une vulnérabilité passe à « Corrigée » seulement si la version installée est constatée ≥ version corrigée')

    phase = '6. Retour arrière (si incident)'
    for g in paquets_:
        versions = {b: v for b, v in g['binaires'].items()
                    if v and sr.SAFE_NAME.fullmatch(b) and sr.SAFE_VERSION.fullmatch(v)}
        if dpkg and versions:
            ajoute(phase, 'sudo apt-get install --allow-downgrades ' + ' '.join(f'{b}={v}' for b, v in versions.items()),
                   f'Versions d’avant pour {g["paquet"]} (sinon depuis /var/cache/apt/archives)')
    if rpm:
        ajoute(phase, 'sudo yum history undo last' if s['commande'].startswith('sudo yum') else 'sudo dnf history undo last',
               'Annule la dernière transaction (vérifier avec « history list »)')
    if s['vm'] and s['noeud']:
        ajoute(phase, f'qm rollback {s["vm"]} avant-patch-{stamp}',
               f'DERNIER RECOURS sur {s["noeud"]} : perd toutes les écritures depuis l’instantané')
    return etapes


def texte(valeur):
    if isinstance(valeur, str):
        return _CONTROLE.sub('', valeur)[:32000]
    return valeur


def tableau(classeur, titre: str, colonnes, donnees) -> None:
    """Feuille en écriture seule (le détail compte des dizaines de milliers de lignes).
    `colonnes` : [(en-tête, clé ou fonction, largeur)]."""
    from openpyxl.cell import WriteOnlyCell
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter
    feuille = classeur.create_sheet(titre)
    for n, (_entete, _cle, largeur) in enumerate(colonnes, 1):
        feuille.column_dimensions[get_column_letter(n)].width = largeur
    feuille.freeze_panes = 'A2'
    if donnees:
        feuille.auto_filter.ref = f'A1:{get_column_letter(len(colonnes))}{len(donnees) + 1}'
    entetes = []
    for entete, _cle, _largeur in colonnes:
        c = WriteOnlyCell(feuille, value=entete)
        c.font = Font(name='Arial', bold=True, color='FFFFFF', size=10)
        c.fill = PatternFill('solid', fgColor='1F4E78')
        c.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
        entetes.append(c)
    feuille.append(entetes)
    for ligne in donnees:
        valeurs = []
        for _entete, cle, _largeur in colonnes:
            valeur = texte(cle(ligne) if callable(cle) else ligne.get(cle))
            if isinstance(valeur, str) and valeur.startswith('='):
                # Valeurs venues des serveurs et des bulletins : jamais évaluées comme formule.
                c = WriteOnlyCell(feuille, value=valeur)
                c.data_type = 's'
                valeur = c
            valeurs.append(valeur)
        feuille.append(valeurs)


def _cves(g: dict) -> str:
    reste = len(g['cves']) - CVE_LISTEES
    return ', '.join(g['cves'][:CVE_LISTEES]) + (f' … (+{reste})' if reste > 0 else '')


def ecrire(chemin: Path, synthese, lignes, vulns, detail=True, stamp=None) -> None:
    from openpyxl import Workbook
    stamp = stamp or datetime.now().strftime('%Y%m%d')
    classeur = Workbook(write_only=True)
    grav = lambda cle: (lambda l: l['gravites'][cle])  # noqa: E731
    tableau(classeur, 'Synthèse serveurs', [
        ('Ordre de passage', 'ordre', 9), ('Serveur', 'serveur', 22), ('IP', 'ip', 15), ('Environnement', 'environnement', 14),
        ('Système', 'os', 28), ('Support de sécurité', 'support', 30), ('Noyau', 'noyau', 40),
        ('CVE actives', 'nb_cves', 9), ('Critiques', grav('critical'), 9), ('Élevées', grav('high'), 9),
        ('Moyennes', grav('medium'), 9), ('Faibles', grav('low'), 9), ('Non évaluées', grav('none'), 9),
        ('Exploitées (CISA KEV)', 'kev', 10), ('CVSS max', 'cvss', 8), ('Détections à vérifier', 'a_verifier', 10),
        ('Paquets à corriger', 'nb_paquets', 9), ('Correctif dans les dépôts', 'dispo', 11),
        ('Dépôt security à vérifier', 'sans_depot', 11), ('Redémarrage requis', 'redemarrage', 10),
        ('Services à relancer', 'services', 18), ('Fenêtre de maintenance', 'fenetre', 11),
        ('Instantané avant patch', 'instantane', 22), ('Dernier relevé SSH', 'releve', 19),
        ('Commande de patch ciblée', 'commande', 90)], synthese)
    tableau(classeur, 'Paquets à corriger', [
        ('Serveur', 'serveur', 22), ('IP', 'ip', 15), ('Environnement', 'environnement', 14), ('Paquet source', 'paquet', 18),
        ('Paquets installés concernés', lambda g: ', '.join(g['noms']), 40), ('Version installée', 'installee', 22),
        ('Version cible (corrigée)', 'cible', 22), ('Correctif dans les dépôts', 'disponible', 40),
        ('Nb CVE', lambda g: len(g['cves']), 8), ('Critiques', grav('critical'), 9), ('Élevées', grav('high'), 9),
        ('Moyennes', grav('medium'), 9), ('Faibles', grav('low'), 9), ('CVSS max', 'cvss', 8),
        ('Exploitées (CISA KEV)', 'kev', 10), ('Échéance KEV', 'kev_echeance', 12), ('Détections à vérifier', 'a_verifier', 10),
        ('Prise en compte', lambda g: PRISE_EN_COMPTE.get(g['prise'], g['prise']), 22), ('Impact', 'impact', 50),
        ('Commande de patch', 'commande', 70), ('CVE corrigées', _cves, 80)], lignes)
    etapes = [e for s in synthese for e in plan(s, stamp)]
    tableau(classeur, 'Plan de correction', [
        ('Ordre de passage', 'ordre', 9), ('Serveur', 'serveur', 22), ('IP', 'ip', 15), ('N°', 'n', 5),
        ('Étape', 'phase', 28), ('Commande ou action', 'commande', 100), ('Commentaire', 'commentaire', 70)], etapes)
    if detail:
        tableau(classeur, 'Détail CVE', [
            ('Serveur', 'host_name', 22), ('IP', 'host_ip', 15), ('Environnement', 'environment', 14), ('CVE', 'cve', 17),
            ('CVSS', _cvss, 7), ('Gravité', lambda v: sc.SEVERITY_LABELS.get(v['severity'] or '', 'Non évaluée'), 11),
            ('CISA KEV', lambda v: 'Oui' if v['kev'] else 'Non', 8), ('Échéance KEV', 'kev_due', 12),
            ('Paquet', 'package', 18), ('Version installée', 'installed', 22), ('Version corrigée', 'fixed', 22),
            ('Correctif dans les dépôts', lambda v: (v['evidence'] or {}).get('repository'), 45),
            ('Sources', lambda v: ', '.join(sc.SOURCE_LABELS.get(x, x) for x in v['sources']), 26),
            ('Confiance', 'confidence', 11), ('Statut', 'status_label', 18), ('Responsable', 'owner', 16),
            ('Première détection', lambda v: (v['first_seen'] or '')[:19].replace('T', ' '), 19),
            ('Dernière observation', lambda v: (v['last_seen'] or '')[:19].replace('T', ' '), 19),
            ('Description', lambda v: (v['description'] or '')[:400], 80)], vulns)
    limites = [
        {'a': 'Généré le', 'b': datetime.now(timezone.utc).isoformat(timespec='seconds')},
        {'a': 'Périmètre', 'b': f'{len(synthese)} serveur(s), {len(lignes)} paquet(s) à corriger, {len(vulns)} vulnérabilité(s) '
                                'actives (Détectée, Validée, Correction planifiée).'},
        {'a': 'Méthode', 'b': 'Aucune connexion : base locale d’OpsControl en lecture seule. Une vulnérabilité n’est retenue que '
                              'sur preuve (version installée < version corrigée publiée par Debian pour la même release, '
                              'ou Wazuh Vulnerability Detection) ; jamais déduite d’un numéro « qui semble ancien ».'},
        {'a': 'Version cible', 'b': 'Plus haute version corrigée parmi les CVE du paquet : l’atteindre corrige toutes ses CVE.'},
        {'a': 'Dépôts', 'b': 'Relevé apt du serveur sans « apt-get update » (lecture seule). « Non : dépôt security absent ou '
                             'cache apt ancien » : vérifier /etc/apt/sources.list (étape 1 du plan) avant de conclure.'},
        {'a': 'Ordre de passage', 'b': 'Risque décroissant : CVE exploitées (CISA KEV), critiques, élevées, production, volume. '
                                       'Valider d’abord le correctif sur un serveur hors production équivalent.'},
        {'a': 'Noyau', 'b': 'Le paquet « linux » (linux-libc-dev) est corrigé avec le métapaquet du noyau ; le correctif n’est '
                            'actif qu’après redémarrage. « Redémarrage en attente » : un noyau plus récent est déjà installé.'},
        {'a': 'Exécution', 'b': 'OpsControl n’exécute aucune de ces commandes. Intervention : fenêtre validée, sauvegarde '
                                'vérifiée, aucun redémarrage automatique. Après correction, relancer l’analyse du serveur.'},
        {'a': 'Actualiser', 'b': 'OpsControl > Sécurité > « Analyser » (tous ou un serveur), puis relancer ce script.'},
    ]
    tableau(classeur, 'Source et limites', [('Rubrique', 'a', 18), ('Détail', 'b', 120)], limites)
    classeur.save(chemin)


def main(argv=None) -> int:
    a = argparse.ArgumentParser(description='Audit des vulnérabilités et plan de correctifs ciblés par serveur (Excel)')
    a.add_argument('sortie', nargs='?', default=f'vulnerabilites-correctifs-{datetime.now():%Y-%m-%d}.xlsx')
    a.add_argument('--serveur', action='append', default=[], help='clé, nom ou IP (répétable) ; par défaut tout le parc')
    a.add_argument('--sans-detail', action='store_true', help='omet la feuille « Détail CVE » (une ligne par CVE)')
    args = a.parse_args(argv)
    from config import inventory_path
    hotes, vulns, releves = charger(base_donnees(), inventory_path(BASE / 'hosts.yaml'), args.serveur)
    if not vulns:
        print('Aucune vulnérabilité active : rien à exporter.')
        return 0
    lignes = paquets(vulns, releves, hotes)
    synthese = serveurs(lignes, releves, hotes)
    sortie = Path(args.sortie).resolve()
    ecrire(sortie, synthese, lignes, vulns, detail=not args.sans_detail)
    print(f'{sortie} : {len(synthese)} serveur(s), {len(lignes)} paquet(s) à corriger, {len(vulns)} vulnérabilité(s) active(s) ; '
          f'{sum(s["redemarrage"] == "Oui" for s in synthese)} serveur(s) à redémarrer.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
