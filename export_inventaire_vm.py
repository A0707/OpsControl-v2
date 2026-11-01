"""Classeur Excel « inventaire par VM » pour le schéma d'architecture (demande DSI).

Une ligne par VM : système (OS, IP, disques, charge), services, ports, conteneurs, sites
web, bases de données, applications « maison » (Tomcat, java -jar, scripts) et une colonne
« Applications / Services hébergés » classée « Identifié » ou « À confirmer ».

Méthode rapide : aucune connexion. Tout vient des relevés déjà faits par l'audit SSH
d'OpsControl (base locale lue en lecture seule) et de l'inventaire ; les enregistrements
DNS viennent du relevé du WAF. Un serveur injoignable lors du dernier audit garde son
dernier relevé réussi, daté dans la colonne « Relevé du ».

Usage :
    python export_inventaire_vm.py [sortie.xlsx] [--en-ligne]

--en-ligne : seulement les VM qui ont répondu au dernier ping d'OpsControl (table
`network`, collecte du service) ; ce script n'envoie lui-même aucun ping.

Prérequis : requirements-tools.txt (openpyxl).
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

import published_sites as ps
from export_enregistrements_waf import BASE, base_donnees, charger, feuille_limites, tableau

IDENTIFIE, A_CONFIRMER, NON_RELEVE = 'Identifié', 'À confirmer', 'Non relevé'

# Produits reconnus par leur nom de service : l'application est nommée sans ambiguïté.
PRODUITS = {'Serveur web', 'Base de données', 'Cache', 'Recherche / journaux', 'Messagerie',
            'Infrastructure', 'Outillage', 'Supervision (serveur)', 'Sauvegarde (serveur)',
            'Répartition / proxy', "Serveur d'applications"}
# Socle et agents : présents partout, ce ne sont pas des applications hébergées.
SOCLE = {'Agent', 'Conteneurs'}

# Bases de données reconnues dans une image Docker ou par leur port standard.
_IMAGE_BDD = re.compile(r'(postgres|mysql|mariadb|mongo|redis|oracle|mssql|sqlserver|'
                        r'elasticsearch|opensearch|cassandra|influxdb|clickhouse|neo4j|couchdb)', re.I)
PORTS_BDD = {'1433': 'SQL Server', '1521': 'Oracle', '3306': 'MySQL / MariaDB', '5432': 'PostgreSQL',
             '6379': 'Redis', '9042': 'Cassandra', '27017': 'MongoDB', '50000': 'DB2'}
_IGNORES_FS = re.compile(r'^(tmpfs|devtmpfs|udev|overlay|shm|squashfs|efivarfs)$')
# Montages partagés : le même volume apparaît sur chaque VM cliente, il ne s'additionne pas.
_RESEAU_FS = re.compile(r'^(nfs4?|cifs|smb3?|fuse\..*|ceph|glusterfs|9p|sshfs)$')


def _jours(uptime: str | None) -> int | None:
    m = re.search(r'up (\d+) day', uptime or '')
    return int(m.group(1)) if m else (0 if uptime and ' up ' in uptime else None)


def _taille(kb) -> str:
    if not isinstance(kb, (int, float)):
        return '?'
    go = kb / 1024 / 1024
    return f'{go / 1024:.1f} To' if go >= 1024 else f'{go:.0f} Go' if go >= 10 else f'{go:.1f} Go'


def disques(obs: dict) -> list[dict]:
    """Systèmes de fichiers montés (pseudo-systèmes exclus)."""
    sortie = []
    for fs in (obs.get('storage') or {}).get('filesystems') or []:
        if _IGNORES_FS.match(str(fs.get('fstype') or '')) or str(fs.get('device', '')).startswith('/dev/loop'):
            continue
        sortie.append({'point': fs.get('mount'), 'peripherique': fs.get('device'), 'type': fs.get('fstype'),
                       'taille': _taille(fs.get('total_kb')), 'utilise': fs.get('use_pct'),
                       'nature': 'Réseau ou agrégé' if _RESEAU_FS.match(str(fs.get('fstype') or '')) else 'Local',
                       'total_kb': 0 if _RESEAU_FS.match(str(fs.get('fstype') or '')) else fs.get('total_kb') or 0,
                       'taille_kb': fs.get('total_kb') or 0})
    if not sortie:   # anciens relevés : sortie de df seulement
        for fs in obs.get('filesystems') or []:
            if not _IGNORES_FS.match(str(fs.get('fs') or '')):
                sortie.append({'point': fs.get('mount'), 'peripherique': fs.get('fs'), 'type': '',
                               'taille': fs.get('size'), 'utilise': fs.get('use_pct'), 'total_kb': 0,
                               'nature': ''})
    return sortie


# Produits lancés directement par Java ou Python (sans service systemd reconnu).
PRODUITS_PROCESSUS = [(re.compile(m, re.I), nom) for m, nom in (
    (r'^elasticsearch', 'Elasticsearch'), (r'^logstash', 'Logstash'), (r'^kafka', 'Kafka'),
    (r'zookeeper', 'ZooKeeper'), (r'^cerebro', 'Cerebro'), (r'wazuh', 'Wazuh'), (r'recoll', 'Recoll'))]
# Noms de fichier qui ne disent rien de l'application : jamais regroupés entre VM.
GENERIQUE = re.compile(r'^(app|application|main|server|index|run|start|service|api)\.(jar|py|js)$|'
                       r'^(gunicorn|uwsgi|celery|ipykernel_launcher)$', re.I)


def produit_processus(e: dict) -> str:
    nom = str(e.get('nom')).rsplit('/', 1)[-1]
    return next((produit for motif, produit in PRODUITS_PROCESSUS if motif.search(nom)), '')


def classer(e: dict, publies_ports: set[str]) -> tuple[str, str]:
    """(statut, justification) d'un élément du relevé des applications."""
    categorie, source = e.get('categorie'), e.get('source')
    if categorie in PRODUITS:
        return IDENTIFIE, f'Produit reconnu par son service ({e.get("detail") or e.get("nom")})'
    if categorie == 'Application web (Tomcat)':
        return IDENTIFIE, 'Application déployée dans Tomcat (nom du contexte)'
    if categorie in ('Conteneur', 'Service Swarm'):
        ports = set(ps._PORT_DOCKER.findall(e.get('detail') or ''))
        if ports & publies_ports:
            return IDENTIFIE, 'Conteneur publié par le WAF (nom DNS connu)'
        return A_CONFIRMER, "Conteneur nommé d'après son image : rôle métier à confirmer"
    if categorie == 'Site web':
        return IDENTIFIE, f'Site déclaré dans la configuration {source}'
    if categorie == 'Processus applicatif':
        if source == 'Java' and 'tomcat' in str(e.get('nom')).lower():
            return IDENTIFIE, 'Instance Tomcat (dossier catalina.base)'
        if produit_processus(e):
            return IDENTIFIE, f'Produit reconnu par son processus ({produit_processus(e)})'
        if GENERIQUE.match(str(e.get('nom'))):
            return A_CONFIRMER, (f'Application maison ({source}) au nom générique : la rattacher par son '
                                 'conteneur, son service ou son dossier')
        return A_CONFIRMER, f'Application maison ({source}) : nom du fichier lancé, rôle métier à confirmer'
    return A_CONFIRMER, 'Service non reconnu (ni socle, ni produit connu) : à qualifier avec son responsable'


def ligne_vm(hote: dict, obs: dict, publies: list[dict]) -> tuple[dict, list[dict], list[dict]]:
    """(ligne de synthèse, éléments détaillés, disques) d'une VM."""
    apps = obs.get('applications') or {}
    base = {'serveur': hote.get('name') or hote['key'], 'ip': hote.get('ip')}
    ligne = {**base, 'fqdn': hote.get('fqdn') or '', 'role': hote.get('role') or '',
             'environnement': hote.get('environment') or '', 'criticite': hote.get('criticality') or '',
             'noeud': hote.get('node') or '', 'vmid': hote.get('vmid') or '',
             'os': obs.get('os') or apps.get('os') or '', 'uptime': _jours(obs.get('uptime')),
             'cpu': obs.get('cpu'), 'ram': obs.get('ram'), 'releve': obs.get('collected_at') or 'Jamais',
             'etat': 'Injoignable au dernier audit' if obs.get('etat_courant') == 'unreachable' else ''}
    fs = disques(obs)
    ligne['disques'] = ' ; '.join(f"{d['point']} {d['taille']} ({d['utilise']} %)" for d in fs)
    # Disques locaux seulement : un partage NFS ou mergerfs compterait une fois par VM cliente.
    ligne['capacite'] = _taille(sum(d['total_kb'] for d in fs)) if any(d['total_kb'] for d in fs) else ''
    if installe := apps.get('installation'):
        ligne['installe'] = datetime.fromtimestamp(installe, timezone.utc).date().isoformat()
    ligne['enregistrements'] = ', '.join(sorted({f"{p['site']} → :{p['port']}" for p in publies}))
    if apps.get('status') != 'observed':
        ligne.update(statut=NON_RELEVE, justification='Pas de relevé des applications : auditer ce serveur '
                     'dans OpsControl (onglet Applications), puis relancer ce script.')
        return ligne, [], [{**base, **d} for d in fs]

    publies_ports = {str(p['port']) for p in publies}
    # Enregistrements du WAF par application locale (conteneur ou contexte Tomcat visé).
    par_cible = {}
    for p in publies:
        par_cible.setdefault(p.get('application'), set()).add(str(p.get('site')))
    elements, groupes = [], {}
    for e in apps.get('elements') or []:
        statut, pourquoi = (('', 'Socle (agent, moteur de conteneurs)') if e.get('categorie') in SOCLE
                            else classer(e, publies_ports))
        # Libellé que published_sites.application_locale donne à cet élément ; les autres
        # catégories ne sont jamais désignées par une cible du WAF (préfixe sans correspondance).
        cible = {'Conteneur': 'Conteneur Docker ', 'Application web (Tomcat)': 'Application Tomcat '}.get(
            e.get('categorie'), 'non publié : ') + str(e.get('nom'))
        elements.append({**base, 'environnement': ligne['environnement'], 'role': ligne['role'],
                         'categorie': e.get('categorie'), 'source': e.get('source'), 'nom': e.get('nom'),
                         'detail': e.get('detail'), 'etat': e.get('etat'), 'statut': statut or 'Socle',
                         'justification': pourquoi, 'sites_publies': sorted(par_cible.get(cible, ()))})
        groupes.setdefault(e.get('categorie'), []).append(e)

    def noms(*categories):
        return ', '.join(dict.fromkeys(str(e.get('nom')) for c in categories for e in groupes.get(c, [])))

    ports = apps.get('ports') or []
    bdd = [f"{e.get('detail') or e.get('nom')} ({e.get('etat')})" for e in groupes.get('Base de données', [])]
    bdd += [f"{e.get('nom')} (cache)" for e in groupes.get('Cache', [])]
    bdd += [f"{e.get('nom')} (conteneur {m.group(1)})" for e in groupes.get('Conteneur', [])
            if (m := _IMAGE_BDD.search(e.get('detail') or ''))]
    deja = ' '.join(bdd).lower()
    bdd += [f'{produit} ? (port {p} en écoute, à confirmer)' for p, produit in PORTS_BDD.items()
            if p in ports and produit.split()[0].lower() not in deja]
    services = [e for c in PRODUITS for e in groupes.get(c, [])]
    ligne.update({
        'services': ', '.join(sorted({str(e.get('detail') or e.get('nom')) for e in services})),
        'agents': noms('Agent'), 'ports': ', '.join(ports), 'noyau': apps.get('noyau') or '',
        # Relevé antérieur à la collecte des paquets : le dire, jamais « aucun ».
        'paquets': (', '.join(f"{q.get('nom')} {q.get('version')}" for q in apps['paquets']) or 'Aucun de la liste')
        if isinstance(apps.get('paquets'), list) else 'Non relevé : relancer l’audit', 'docker': apps.get('docker') or '',
        'conteneurs': noms('Conteneur', 'Service Swarm'), 'bdd': ' ; '.join(bdd),
        'sites': noms('Site web'), 'tomcat': noms('Application web (Tomcat)'),
        'maison': ', '.join(f"{e.get('nom')} ({e.get('source')})" for e in
                            groupes.get('Processus applicatif', []) + groupes.get('Service spécifique (à qualifier)', [])),
    })
    retenus = [e for e in elements if e['statut'] in (IDENTIFIE, A_CONFIRMER) and e['categorie'] != 'Site web']
    ligne['heberge'] = ' | '.join(f"{e['nom']} [{e['statut']}]" for e in retenus)
    a_confirmer = [e for e in retenus if e['statut'] == A_CONFIRMER]
    if a_confirmer:
        ligne.update(statut=A_CONFIRMER, justification=f'{len(a_confirmer)} élément(s) à qualifier : '
                     + ', '.join(str(e['nom']) for e in a_confirmer))
    elif retenus or ligne['sites'] or publies:
        ligne.update(statut=IDENTIFIE, justification='Applications reconnues par service, Tomcat, conteneur publié ou site')
    else:
        ligne.update(statut=A_CONFIRMER, justification='Aucune application détectée hors socle : rôle à confirmer '
                     '(processus lancés par un autre compte invisibles sans root)')
    return ligne, elements, [{**base, **d} for d in fs]


def pings(db_path: Path) -> dict:
    """{clé: (ping, date)} du dernier test réseau fait par OpsControl (lecture seule)."""
    db = sqlite3.connect(db_path.as_uri() + '?mode=ro', uri=True)
    try:
        lignes = db.execute('SELECT key, payload FROM network').fetchall()
    except sqlite3.OperationalError:   # base sans table réseau : aucun test connu
        lignes = []
    finally:
        db.close()
    return {cle: (r.get('ping'), r.get('collected_at')) for cle, r in ((c, json.loads(p)) for c, p in lignes)}


def construire(hotes: list[dict], etats: dict, reseau: dict | None = None,
               en_ligne: bool = False) -> tuple[list[dict], list[dict], list[dict]]:
    """`en_ligne` : seulement les VM dont le dernier ping d'OpsControl a répondu."""
    reseau = reseau or {}
    # Les enregistrements du WAF se rapprochent sur tout le parc, même filtré.
    actifs = [{**h, 'applications': (etats.get(h['key']) or {}).get('applications')} for h in hotes]
    vms, details, tous_disques = [], [], []
    for hote in actifs:
        ping, teste_le = reseau.get(hote['key'], (None, None))
        if en_ligne and ping is not True:
            continue
        obs = etats.get(hote['key']) or {}
        ligne, elements, fs = ligne_vm(hote, obs, ps.published_to(hote, actifs))
        ligne['ping'] = {True: 'Répond', False: 'Ne répond pas'}.get(ping, 'Non testé')
        ligne['ping_le'] = teste_le or ''
        vms.append(ligne)
        details += elements
        tous_disques += fs
    vms.sort(key=lambda l: str(l['serveur']).lower())
    return vms, details, tous_disques


def nom_application(e: dict) -> str:
    """Nom de regroupement : le produit pour un service connu (« PostgreSQL » réunit
    postgresql-9.6 et postgresql-15), le nom relevé sinon (conteneur, .jar, contexte Tomcat)."""
    if e['categorie'] in PRODUITS and e.get('source') == 'Service systemd':
        return str(e.get('detail') or e.get('nom'))
    if e['categorie'] == 'Processus applicatif':
        if produit := produit_processus(e):
            return produit
        if GENERIQUE.match(str(e.get('nom'))):
            return f"{e.get('nom')} sur {e.get('serveur')}"
    return str(e.get('nom'))


def par_application(details: list[dict]) -> list[dict]:
    """Une ligne par application hébergée et les VM qui l'hébergent (socle et sites exclus)."""
    groupes = {}
    for e in details:
        if e['statut'] not in (IDENTIFIE, A_CONFIRMER) or e['categorie'] == 'Site web':
            continue
        # Clé : le nom seul, pour réunir un produit vu comme service ET comme processus.
        g = groupes.setdefault(nom_application(e).lower(), {
            'application': nom_application(e), 'categories': set(), 'vms': {}, 'composants': set(),
            'environnements': set(), 'roles': set(), 'sites': set(), 'statuts': set(), 'justifications': set()})
        g['vms'][e['serveur']] = e.get('ip')
        g['categories'].add(e['categorie'])
        g['composants'].add(str(e.get('nom')))
        g['environnements'].add(e.get('environnement') or '')
        g['roles'].add(e.get('role') or '')
        g['sites'].update(e.get('sites_publies') or [])
        g['statuts'].add(e['statut'])
        g['justifications'].add(e['justification'])

    def liste(valeurs):
        return ', '.join(sorted(v for v in valeurs if v))

    lignes = []
    for g in groupes.values():
        # Un seul serveur où le rôle reste à confirmer suffit : l'application entière est à confirmer.
        statut = A_CONFIRMER if A_CONFIRMER in g['statuts'] else IDENTIFIE
        lignes.append({'application': g['application'], 'categorie': liste(g['categories']), 'statut': statut,
                       'nb': len(g['vms']), 'serveurs': ', '.join(f'{n} ({ip})' for n, ip in sorted(g['vms'].items())),
                       'composants': liste(g['composants']), 'environnements': liste(g['environnements']),
                       'roles': liste(g['roles']), 'sites': liste(g['sites']),
                       'justification': ' ; '.join(sorted(g['justifications']))})
    return sorted(lignes, key=lambda l: (l['categorie'], l['application'].lower()))


COLONNES_APPLICATION = [
    ('Application / service', 'application'), ('Catégorie', 'categorie'), ('Statut', 'statut'),
    ('Nb VM', 'nb'), ('VM hébergeant (IP)', 'serveurs'), ('Composants relevés', 'composants'),
    ('Environnements', 'environnements'), ('Rôles des VM', 'roles'),
    ('Enregistrements DNS publiés (WAF)', 'sites'), ('Justification', 'justification')]


COLONNES_VM = [
    ('Serveur', 'serveur'), ('FQDN', 'fqdn'), ('IP', 'ip'), ('Ping', 'ping'),
    ('Rôle', 'role'), ('Environnement', 'environnement'),
    ('Criticité', 'criticite'), ('Nœud Proxmox', 'noeud'), ('VMID', 'vmid'), ('OS', 'os'),
    ('Installé le', 'installe'), ('Uptime (jours)', 'uptime'), ('CPU %', 'cpu'), ('RAM %', 'ram'),
    ('Capacité disque', 'capacite'), ('Disques (montage taille usage)', 'disques'),
    ('Noyau', 'noyau'), ('Paquets clés', 'paquets'), ('Services', 'services'), ('Ports en écoute', 'ports'), ('Docker', 'docker'), ('Conteneurs', 'conteneurs'),
    ('Bases de données', 'bdd'), ('Sites web (vhosts locaux)', 'sites'),
    ('Enregistrements DNS publiés (WAF)', 'enregistrements'), ('Applications Tomcat', 'tomcat'),
    ('Applications maison (java -jar, scripts, services)', 'maison'),
    ('Applications / Services hébergés', 'heberge'), ('Statut', 'statut'), ('Justification', 'justification'),
    ('Agents', 'agents'), ('Relevé du', 'releve'), ('État actuel', 'etat'),
    ('Ping testé le', 'ping_le')]


SEUIL_DISQUE = 85


def vue_globale(vms: list[dict], applications: list[dict], tous_disques: list[dict]) -> list[tuple]:
    """Sections de la feuille de synthèse : [(titre, en-têtes, lignes)]."""
    def compte(cle, valeur):
        return sum(1 for v in vms if v.get(cle) == valeur)

    capacite = {}
    for d in tous_disques:
        capacite[d['serveur']] = capacite.get(d['serveur'], 0) + (d.get('total_kb') or 0)
    pleins = sorted({f"{d['serveur']} {d['point']} ({d['utilise']} %)" for d in tous_disques
                     if isinstance(d.get('utilise'), (int, float)) and d['utilise'] >= SEUIL_DISQUE})
    publies = {s.strip() for v in vms for s in str(v.get('enregistrements') or '').split(',') if s.strip()}

    def repartition(cle, titre, vide='Non renseigné'):
        groupes = {}
        for v in vms:
            # « Prod » et « PROD » : même environnement, saisi différemment dans l'inventaire.
            valeur = str(v.get(cle) or vide)
            groupes.setdefault(valeur.upper() if cle == 'environnement' else valeur, []).append(v)
        lignes = []
        for nom, membres in sorted(groupes.items(), key=lambda g: (-len(g[1]), g[0].lower())):
            lignes.append([nom, len(membres), sum(1 for v in membres if v.get('ping') == 'Répond'),
                           sum(1 for v in membres if v.get('statut') == IDENTIFIE),
                           sum(1 for v in membres if v.get('statut') == A_CONFIRMER),
                           sum(1 for v in membres if v.get('statut') == NON_RELEVE),
                           _taille(sum(capacite.get(v['serveur'], 0) for v in membres)) if any(
                               capacite.get(v['serveur']) for v in membres) else ''])
        return (titre, [titre.split(' par ')[-1].capitalize(), 'VM', 'Ping OK', 'Identifiées', 'À confirmer',
                        'Non relevées', 'Disques locaux'], lignes)

    return [
        ('Chiffres clés', ['Indicateur', 'Valeur'], [
            ['VM inventoriées', len(vms)],
            ['Répondent au ping', compte('ping', 'Répond')],
            ['Ne répondent pas au ping', compte('ping', 'Ne répond pas')],
            ['VM aux applications identifiées', compte('statut', IDENTIFIE)],
            ['VM aux applications à confirmer', compte('statut', A_CONFIRMER)],
            ['VM sans relevé des applications', compte('statut', NON_RELEVE)],
            ['Applications / services distincts', len(applications)],
            ['Enregistrements DNS publiés par le WAF', len(publies)],
            ['Capacité des disques locaux (hors NFS / mergerfs)', _taille(sum(capacite.values()))],
            [f'Systèmes de fichiers ≥ {SEUIL_DISQUE} %', len(pleins)]]),
        repartition('environnement', 'VM par environnement'),
        repartition('noeud', 'VM par nœud Proxmox'),
        repartition('os', 'VM par système'),
        repartition('role', 'VM par rôle'),
        ('Applications les plus présentes', ['Application', 'VM', 'Statut', 'Catégorie'],
         [[a['application'], a['nb'], a['statut'], a['categorie']]
          for a in sorted(applications, key=lambda a: (-a['nb'], a['application'].lower()))[:20]]),
        ('Points d’attention', ['Sujet', 'Nombre', 'VM concernées'], [
            ['Ne répondent pas au ping', compte('ping', 'Ne répond pas'),
             ', '.join(v['serveur'] for v in vms if v.get('ping') == 'Ne répond pas')],
            ['Injoignables au dernier audit SSH', compte('etat', 'Injoignable au dernier audit'),
             ', '.join(v['serveur'] for v in vms if v.get('etat'))],
            ['Sans relevé des applications', compte('statut', NON_RELEVE),
             ', '.join(v['serveur'] for v in vms if v.get('statut') == NON_RELEVE)],
            [f'Systèmes de fichiers ≥ {SEUIL_DISQUE} %', len(pleins), ', '.join(pleins)]]),
    ]


def ecrire_vue_globale(feuille, sections, sous_titre: str) -> None:
    from openpyxl.styles import Alignment, Font, PatternFill
    from export_enregistrements_waf import texte
    feuille.cell(row=1, column=1, value='Vue globale de l’infrastructure').font = Font(name='Arial', bold=True, size=14)
    feuille.cell(row=2, column=1, value=sous_titre).font = Font(name='Arial', italic=True, size=9, color='595959')
    entete = Font(name='Arial', bold=True, color='FFFFFF', size=10)
    fond = PatternFill('solid', fgColor='1F4E78')
    r = 4
    for titre, entetes, lignes in sections:
        feuille.cell(row=r, column=1, value=titre).font = Font(name='Arial', bold=True, size=11, color='1F4E78')
        r += 1
        for n, valeur in enumerate(entetes, 1):
            c = feuille.cell(row=r, column=n, value=valeur)
            c.font, c.fill = entete, fond
        for ligne in lignes:
            r += 1
            for n, valeur in enumerate(ligne, 1):
                c = feuille.cell(row=r, column=n, value=texte(valeur))
                c.font = Font(name='Arial', size=10)
                c.alignment = Alignment(wrap_text=isinstance(valeur, str) and len(valeur) > 60, vertical='top')
                if c.data_type == 'f':   # valeur venue d'un serveur : jamais une formule
                    c.data_type = 's'
            # Longue liste en dernière colonne : cellule étendue jusqu'à G pour rester lisible.
            if len(ligne) < 7 and isinstance(ligne[-1], str) and len(ligne[-1]) > 60:
                feuille.merge_cells(start_row=r, start_column=len(ligne), end_row=r, end_column=7)
                feuille.row_dimensions[r].height = min(15 * (len(ligne[-1]) // 80 + 1), 300)
        r += 2
    for colonne, largeur in zip('ABCDEFG', (46, 10, 12, 12, 12, 12, 14)):
        feuille.column_dimensions[colonne].width = largeur
    feuille.column_dimensions['C'].width = 14


def ecrire(chemin: Path, vms, details, tous_disques, en_ligne: bool = False) -> None:
    from openpyxl import Workbook
    from openpyxl.styles import PatternFill
    classeur = Workbook()
    synthese = classeur.active
    synthese.title = 'Vue globale'
    ecrire_vue_globale(synthese, vue_globale(vms, par_application(details), tous_disques),
                       f"Généré le {datetime.now(timezone.utc):%d/%m/%Y %H:%M} UTC depuis OpsControl, sans connexion "
                       "aux serveurs. Document interne : contient adresses IP, ports et applications.")
    feuille = classeur.create_sheet('Inventaire par VM')
    tableau(feuille, COLONNES_VM, vms, largeur_max=60)
    couleurs = {IDENTIFIE: 'C6EFCE', A_CONFIRMER: 'FFEB9C', NON_RELEVE: 'D9D9D9'}
    colonne = [c for _e, c in COLONNES_VM].index('statut') + 1
    for r, ligne in enumerate(vms, 2):
        if ligne.get('statut') in couleurs:
            feuille.cell(row=r, column=colonne).fill = PatternFill('solid', fgColor=couleurs[ligne['statut']])
    applications = par_application(details)
    feuille = classeur.create_sheet('Par application')
    tableau(feuille, COLONNES_APPLICATION, applications, largeur_max=70)
    colonne = [c for _e, c in COLONNES_APPLICATION].index('statut') + 1
    for r, ligne in enumerate(applications, 2):
        feuille.cell(row=r, column=colonne).fill = PatternFill('solid', fgColor=couleurs[ligne['statut']])
    tableau(classeur.create_sheet('Détail applications'),
            [('Serveur', 'serveur'), ('IP', 'ip'), ('Catégorie', 'categorie'), ('Source', 'source'), ('Nom', 'nom'),
             ('Détail', 'detail'), ('État', 'etat'), ('Statut', 'statut'), ('Justification', 'justification')],
            details, largeur_max=70)
    tableau(classeur.create_sheet('Disques'),
            [('Serveur', 'serveur'), ('IP', 'ip'), ('Montage', 'point'), ('Périphérique', 'peripherique'),
             ('Type', 'type'), ('Nature', 'nature'), ('Taille', 'taille'), ('Utilisé %', 'utilise')], tous_disques)
    compte = {s: sum(1 for v in vms if v.get('statut') == s) for s in (IDENTIFIE, A_CONFIRMER, NON_RELEVE)}
    feuille_limites(classeur, [
        ('Généré le', datetime.now(timezone.utc).isoformat(timespec='seconds')),
        ('Périmètre', 'VM qui ont répondu au dernier ping d’OpsControl (date dans « Ping testé le »).'
                      if en_ligne else 'Toutes les VM de l’inventaire.'),
        ('Couverture', f"{len(vms)} VM : {compte[IDENTIFIE]} identifiée(s), {compte[A_CONFIRMER]} à confirmer, "
                       f'{compte[NON_RELEVE]} sans relevé des applications.'),
        ('Méthode', 'Aucune connexion : derniers relevés réussis de l’audit SSH OpsControl (base locale en lecture '
                    'seule), inventaire et relevé du WAF pour les noms DNS.'),
        ('Identifié', 'Produit reconnu par son service (Apache, PostgreSQL…), application Tomcat, conteneur publié '
                      'par le WAF ou site déclaré.'),
        ('À confirmer', 'Application maison (java -jar, Python, Node), service inconnu ou conteneur non publié : '
                        'le nom technique est relevé, son rôle métier doit être confirmé par son responsable.'),
        ('Non relevé', 'Serveur jamais audité avec le relevé des applications : l’auditer, puis relancer.'),
        ('CPU / RAM', 'Taux d’utilisation au moment du relevé. Les vCPU et la RAM allouées viennent de Proxmox '
                      '(export_proxmox_stockage.py).'),
        ('Bases de données', 'Services et images Docker reconnus ; un port standard en écoute sans service reconnu '
                             'est signalé « à confirmer ».'),
        ('Limites', 'Sans root, les processus d’un autre compte et le nom du processus derrière un port restent '
                    'invisibles. Paquets : liste fermée de produits clés (dpkg ou rpm) ; un produit installé hors '
                    'gestionnaire (archive dans /opt) n’y figure pas.'),
    ])
    classeur.save(chemin)


def main(argv=None) -> int:
    a = argparse.ArgumentParser(description='Inventaire par VM pour le schéma d’architecture (Excel)')
    a.add_argument('sortie', nargs='?', default='inventaire-vm.xlsx')
    a.add_argument('--en-ligne', action='store_true', help='seulement les VM qui ont répondu au dernier ping')
    args = a.parse_args(argv)
    from config import inventory_path
    hotes, etats = charger(base_donnees(), inventory_path(BASE / 'hosts.yaml'))
    vms, details, tous_disques = construire(hotes, etats, pings(base_donnees()), args.en_ligne)
    sortie = Path(args.sortie).resolve()
    try:
        ecrire(sortie, vms, details, tous_disques, args.en_ligne)
    except PermissionError:
        # Cas courant sous Windows : le classeur précédent est encore ouvert dans Excel.
        raise SystemExit(f'Écriture impossible : {sortie} est ouvert (Excel ?) ou protégé. '
                         'Le fermer, ou indiquer un autre nom de fichier.') from None
    compte = {s: sum(1 for v in vms if v.get('statut') == s) for s in (IDENTIFIE, A_CONFIRMER, NON_RELEVE)}
    print(f'{sortie} : {len(vms)} VM, {compte[IDENTIFIE]} identifiée(s), {compte[A_CONFIRMER]} à confirmer, '
          f'{compte[NON_RELEVE]} sans relevé des applications.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
