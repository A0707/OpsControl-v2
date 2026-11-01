"""Export Excel des VM Proxmox : support de stockage de chaque disque et capacités.

Répond à deux questions d'exploitation :
  1. sur quel support (Ceph OVH, Ceph local, NFS, disque local…) est rangé
     chaque disque de chaque VM, et avec quelle taille allouée ;
  2. quelle est la capacité totale, utilisée et libre de chaque support.

Lecture seule stricte : uniquement des GET sur l'API Proxmox, avec la connexion
« Proxmox » déjà configurée dans OpsControl (URL, certificat épinglé, jeton du
coffre). Les droits PVEAuditor suffisent (VM.Audit, Datastore.Audit).

Pourquoi lire la configuration de chaque VM : /cluster/resources ne donne que
la somme des disques d'une VM, pas leur répartition par support. Seul
/nodes/{nœud}/{qemu|lxc}/{vmid}/config porte les lignes « scsi0: stockage:volume,size=… ».

Usage :
    python export_proxmox_stockage.py [chemin/de/sortie.xlsx]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

BASE = Path(__file__).resolve().parent
GIB = 1024 ** 3
TIB = 1024 ** 4

# Libellés métier des supports du cluster. Un support absent de cette table
# garde son nom technique : on ne devine pas son rôle.
LIBELLES_SUPPORT = {
    'ceph-remote': 'Ceph OVH',
    'myceph': 'Ceph local',
    'nfs-primary': 'Cluster NFS',
    'local': 'Disque local (nœud)',
    'zfs-primary': 'Disque local ZFS (prdlabpve06)',
}

# Clés de configuration qui désignent un disque. Les clés « unusedN » sont des
# volumes détachés mais toujours présents sur le support : ils occupent de la
# place, on les exporte donc en le signalant.
# Supports qui ne sont que le socle physique d'un autre : les additionner
# compterait deux fois la même place. Constaté le 09/10/2026 : nfs-primary et
# zfs-primary annoncent exactement le même espace libre, le partage NFS est servi
# depuis ce pool ZFS, et aucun disque de VM n'est rangé directement sur zfs-primary.
SOCLES = {'zfs-primary': 'nfs-primary'}

DISQUE_QEMU = re.compile(r'^(ide|sata|scsi|virtio|efidisk|tpmstate|unused)\d+$')
DISQUE_LXC = re.compile(r'^(rootfs|mp\d+|unused\d+)$')
TAILLE = re.compile(r'(?:^|,)size=(\d+(?:\.\d+)?)([KMGT]?)(?:,|$)')
UNITES = {'': 1, 'K': 1024, 'M': 1024 ** 2, 'G': GIB, 'T': TIB}


def taille_octets(valeur):
    """Taille déclarée « size=32G » en octets, ou None si absente."""
    trouve = TAILLE.search(valeur)
    if not trouve:
        return None
    return int(float(trouve.group(1)) * UNITES[trouve.group(2)])


def disques(config, kind):
    """Disques d'une configuration de VM ou de conteneur.

    Ignore les lecteurs CD-ROM (ISO montée : pas une allocation de la VM) et
    les points de montage « bind » d'un chemin de l'hôte (pas de stockage Proxmox).
    """
    motif = DISQUE_LXC if kind == 'lxc' else DISQUE_QEMU
    resultat = []
    for cle, valeur in sorted(config.items()):
        if not motif.match(cle) or not isinstance(valeur, str):
            continue
        if 'media=cdrom' in valeur or valeur.split(',', 1)[0] in ('none', 'cdrom'):
            continue
        volume = valeur.split(',', 1)[0]
        if ':' not in volume or volume.startswith('/'):
            continue
        stockage = volume.split(':', 1)[0]
        resultat.append({'cle': cle, 'stockage': stockage, 'volume': volume,
                         'taille': taille_octets(valeur),
                         'detache': cle.startswith('unused')})
    return resultat


def date_creation(config):
    """Horodatage « ctime » de la ligne meta d'une VM QEMU, ou None.

    Proxmox l'écrit à la création, mais aussi à la restauration ou à l'import :
    c'est la date d'arrivée de la VM sur ce cluster, pas forcément sa date d'origine.
    Les conteneurs LXC et les VM plus anciennes que cette fonctionnalité n'en ont pas.
    """
    trouve = re.search(r'(?:^|,)ctime=(\d+)(?:,|$)', (config or {}).get('meta') or '')
    return int(trouve.group(1)) if trouve else None


# Au-delà de ce nombre de VM datées du même jour, il s'agit d'une opération en
# lot : déploiement, migration ou restauration. Proxmox seul ne permet pas de
# trancher ; la date d'installation du système, si elle est relevée, le fait.
# Mesuré le 09/10/2026 : 56 VM sur 65 datées du 06/01/2024, et les 47 qui ont pu
# être jointes ont un système installé ce même jour (déploiement réel, pas migration).
SEUIL_LOT = 5
# Écart toléré entre date Proxmox et installation du système pour les dire concordantes.
TOLERANCE_JOURS = 2


def fiabilite_dates(invites):
    """Libellé de fiabilité de la date de création, par VMID."""
    jours = {}
    for invite in invites:
        if invite.get('ctime'):
            jour = datetime.fromtimestamp(invite['ctime']).date()
            jours[jour] = jours.get(jour, 0) + 1
    resultat = {}
    for invite in invites:
        if not invite.get('ctime'):
            resultat[invite['vmid']] = ('Non renseignée par Proxmox (conteneur LXC)' if invite['type'] == 'lxc'
                                        else 'Non renseignée par Proxmox (VM antérieure à cet enregistrement)')
            continue
        nombre = jours[datetime.fromtimestamp(invite['ctime']).date()]
        resultat[invite['vmid']] = (f'Date commune à {nombre} VM : déploiement, migration ou restauration en lot'
                                    if nombre >= SEUIL_LOT else 'Création sur ce cluster')
    return resultat


def date_retenue(ctime, installation):
    """(horodatage, justification) de la date de création retenue, en croisant les deux sources.

    - mêmes jours : les deux sources se confirment ;
    - système plus ancien : la VM existait avant d'arriver sur ce cluster (migrée ou restaurée),
      sa vraie date est celle du système ;
    - système plus récent : système réinstallé dans une VM existante, la date Proxmox prévaut.
    """
    if ctime and installation:
        ecart = (installation - ctime) / 86400
        if abs(ecart) <= TOLERANCE_JOURS:
            return ctime, 'Confirmée : date Proxmox et installation du système concordent'
        if ecart < 0:
            return installation, 'Système antérieur à la VM Proxmox : VM migrée ou restaurée'
        return ctime, 'Système réinstallé après la création de la VM'
    if ctime:
        return ctime, 'Date Proxmox seule (système non relevé)'
    if installation:
        return installation, "Installation du système seule (pas de date Proxmox)"
    return None, 'Inconnue'


def installations_connues(fichier=None):
    """Relevés des VM par inventaire_applications.py (data/, hors Git) : date d'installation
    du système et applications avec leurs dates."""
    fichier = fichier or BASE / 'data' / 'releve-vm.json'
    try:
        return list(json.loads(fichier.read_text(encoding='utf-8')).values())
    except (OSError, ValueError, AttributeError):
        return []


# Ni applications ni sites : agents de supervision et sites web ont leur propre décompte.
HORS_APPLICATIONS = ('Agent', 'Site web')


def applications_de(releve):
    """Applications métier d'un relevé de VM (sans agents ni sites web)."""
    return [a for a in (releve or {}).get('applications') or [] if a.get('categorie') not in HORS_APPLICATIONS]


def resume_applications(releve):
    """[liste lisible, nb de sites web, date du relevé] pour la ligne de la VM."""
    if not releve or 'applications' not in releve:
        return ['Non relevé (VM injoignable en SSH ou hors inventaire)', None, '']
    noms = sorted({a['nom'] for a in applications_de(releve)}, key=str.lower)
    sites = sum(1 for a in releve['applications'] if a.get('categorie') == 'Site web')
    return [', '.join(noms)[:2000] or 'Aucune application détectée', sites, (releve.get('releve_le') or '')[:10]]


def installation_de(invite, installations):
    """Date d'installation de cette VM : par VMID et nœud d'abord, sinon par nom court.

    Le VMID seul suffirait sur un cluster, mais l'inventaire peut avoir un nœud
    périmé après une migration : on accepte donc le VMID même si le nœud diffère,
    puis le nom court (« prdlabgit01.host.example.test » -> « prdlabgit01 »).
    """
    court = str(invite.get('name') or '').split('.', 1)[0].lower()
    for critere in (lambda i: i.get('vmid') == invite['vmid'] and i.get('node') == invite.get('node'),
                    lambda i: i.get('vmid') == invite['vmid'],
                    lambda i: court and str(i.get('name') or '').split('.', 1)[0].lower() == court):
        trouve = next((i for i in installations if critere(i)), None)
        if trouve:
            return trouve
    return None


def supports(ressources):
    """Capacité par support, chaque support partagé compté UNE seule fois.

    /cluster/resources répète un stockage partagé (Ceph, NFS) sur chaque nœud :
    le sommer naïvement multiplierait sa capacité par le nombre de nœuds. Un
    stockage local, lui, est propre à chaque nœud et s'additionne.
    """
    vus = {}
    for item in ressources:
        if item.get('type') != 'storage' or item.get('status') != 'available':
            continue
        nom, noeud = item.get('storage'), item.get('node')
        partage = bool(item.get('shared'))
        cle = (nom, None) if partage else (nom, noeud)
        if cle in vus:
            vus[cle]['noeuds'].append(noeud)
            continue
        vus[cle] = {'nom': nom, 'type': item.get('plugintype'), 'partage': partage,
                    'noeuds': [noeud], 'total': item.get('maxdisk') or 0,
                    'utilise': item.get('disk') or 0}
    regroupes = {}
    for support in vus.values():
        groupe = regroupes.setdefault(support['nom'], {
            'nom': support['nom'], 'type': support['type'], 'partage': support['partage'],
            'noeuds': [], 'total': 0, 'utilise': 0})
        groupe['noeuds'] += support['noeuds']
        groupe['total'] += support['total']
        groupe['utilise'] += support['utilise']
    return sorted(regroupes.values(), key=lambda s: s['nom'])


class ClientProxmox:
    """Client GET seulement, avec la connexion et le TLS d'OpsControl."""

    def __init__(self, connexion):
        from management import api_opener, ssl_context_for

        jeton = os.environ.get(connexion.get('token_env') or '', '')
        if not jeton:
            import secret_store
            secret_store.charger()
            jeton = os.environ.get(connexion.get('token_env') or '', '')
        if not jeton:
            raise SystemExit(f"Jeton {connexion.get('token_env')} introuvable "
                             "(coffre InfraOps ou variable d'environnement).")
        url = urlsplit(connexion['url'])
        if url.scheme != 'https':
            raise SystemExit('HTTPS requis pour l’API Proxmox.')
        self.racine = url._replace(path='/api2/json', query='').geturl()
        self.entetes = {'Accept': 'application/json', 'Authorization': jeton}
        self.ouvreur = api_opener(ssl_context_for(connexion))

    def get(self, chemin):
        requete = urllib.request.Request(self.racine + chemin, headers=self.entetes)
        with self.ouvreur.open(requete, timeout=15) as reponse:  # nosec B310 - HTTPS vérifié
            return json.loads(reponse.read(8 * 1048576))['data']


def connexion_proxmox():
    fichier = BASE / 'data' / 'api-connections.json'
    for connexion in json.loads(fichier.read_text(encoding='utf-8')):
        if connexion.get('provider') == 'Proxmox':
            return connexion
    raise SystemExit('Aucune connexion Proxmox configurée dans OpsControl.')


def collecter(client):
    """Ressources du cluster puis configuration de chaque VM et conteneur."""
    ressources = client.get('/cluster/resources')
    invites, erreurs = [], []
    for item in ressources:
        if item.get('type') not in ('qemu', 'lxc') or item.get('template'):
            continue
        chemin = '/nodes/{}/{}/{}/config'.format(quote(item['node'], safe=''), item['type'], int(item['vmid']))
        try:
            config = client.get(chemin)
        except Exception as exc:  # une VM illisible ne bloque pas l'export
            erreurs.append((item.get('vmid'), item.get('name'), type(exc).__name__))
            config = None
        invites.append({**item, 'disques': disques(config, item['type']) if config else None,
                        'ctime': date_creation(config)})
    return ressources, invites, erreurs


def libelle(nom):
    return LIBELLES_SUPPORT.get(nom, nom)


def go(octets):
    return round(octets / GIB, 1) if octets is not None else None


def to(octets):
    return round(octets / TIB, 2) if octets is not None else None


def ecrire(chemin, ressources, invites, erreurs):
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    police = 'Arial'
    titre = Font(name=police, bold=True, color='FFFFFF', size=10)
    fond = PatternFill('solid', fgColor='1F4E78')
    normal = Font(name=police, size=10)
    gras = Font(name=police, size=10, bold=True)

    def tableau(feuille, entetes, lignes):
        for colonne, entete in enumerate(entetes, 1):
            cellule = feuille.cell(row=1, column=colonne, value=entete)
            cellule.font, cellule.fill = titre, fond
            cellule.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
        for numero, ligne in enumerate(lignes, 2):
            for colonne, valeur in enumerate(ligne, 1):
                cellule = feuille.cell(row=numero, column=colonne, value=valeur)
                cellule.font = normal
                # Noms de VM, de pools ou d'applications : jamais évalués comme formule (audit NEW-01).
                if cellule.data_type == 'f':
                    cellule.data_type = 's'
        for colonne, entete in enumerate(entetes, 1):
            largeur = max([len(str(entete))] + [len(str(ligne[colonne - 1] or '')) for ligne in lignes])
            feuille.column_dimensions[get_column_letter(colonne)].width = min(max(largeur + 2, 10), 40)
        feuille.freeze_panes = 'A2'
        if lignes:
            feuille.auto_filter.ref = f'A1:{get_column_letter(len(entetes))}{len(lignes) + 1}'

    noms_supports = sorted({d['stockage'] for invite in invites for d in invite['disques'] or []})
    classeur = Workbook()

    # 1. Une ligne par VM, une colonne par support : la vue demandée.
    feuille = classeur.active
    feuille.title = 'VM par support'
    entetes = (['VMID', 'Nom', 'Type', 'Nœud', 'État', 'Pool']
               + [f'{libelle(n)} ({n}) — Go' for n in noms_supports]
               + ['Total alloué — Go', 'Supports utilisés', 'Date de création (Proxmox)',
                  'Fiabilité de la date', 'Installation du système (dans la VM)', 'Source de la date système',
                  'Date de création retenue', 'Justification', 'Applications détectées', 'Nb sites web',
                  'Relevé applicatif du'])
    fiabilite = fiabilite_dates(invites)
    installations = installations_connues()
    lignes = []
    for invite in sorted(invites, key=lambda i: i['vmid']):
        systeme = installation_de(invite, installations)
        retenue = date_retenue(invite.get('ctime'), systeme['installation'] if systeme else None)
        par_support = {}
        for disque in invite['disques'] or []:
            par_support[disque['stockage']] = par_support.get(disque['stockage'], 0) + (disque['taille'] or 0)
        lignes.append([invite['vmid'], invite.get('name'), {'qemu': 'VM', 'lxc': 'LXC'}[invite['type']],
                       invite.get('node'), {'running': 'Démarrée', 'stopped': 'Arrêtée'}.get(invite.get('status'), invite.get('status')),
                       invite.get('pool') or '']
                      + [go(par_support[n]) if n in par_support else None for n in noms_supports]
                      + [go(sum(par_support.values())) if invite['disques'] is not None else 'Config illisible',
                         ', '.join(libelle(n) for n in sorted(par_support)),
                         datetime.fromtimestamp(invite['ctime']).strftime('%d/%m/%Y %H:%M') if invite.get('ctime') else '',
                         fiabilite[invite['vmid']],
                         datetime.fromtimestamp(systeme['installation']).strftime('%d/%m/%Y')
                         if systeme and systeme.get('installation') else '',
                         (systeme.get('source') or 'Aucune source disponible dans la VM') if systeme
                         else 'Non relevée (VM injoignable en SSH ou hors inventaire)']
                      + [datetime.fromtimestamp(retenue[0]).strftime('%d/%m/%Y') if retenue[0] else '', retenue[1]]
                      + resume_applications(systeme))
    tableau(feuille, entetes, lignes)

    # Applications à l'intérieur de chaque VM, avec leur date et la nature de cette date.
    feuille = classeur.create_sheet('Applications par VM')
    lignes = []
    for invite in sorted(invites, key=lambda i: i['vmid']):
        releve = installation_de(invite, installations)
        for a in sorted(applications_de(releve), key=lambda a: (a.get('categorie') or '', str(a.get('nom')).lower())):
            lignes.append([invite['vmid'], invite.get('name'), invite.get('node'), a.get('categorie'), a.get('source'),
                           a.get('nom'), a.get('etat'),
                           datetime.fromtimestamp(a['date']).strftime('%d/%m/%Y') if a.get('date') else '',
                           a.get('nature_date') or '', (releve.get('releve_le') or '')[:10]])
    tableau(feuille, ['VMID', 'VM', 'Nœud', 'Catégorie', 'Source', 'Application / composant', 'État',
                      'Date', 'Nature de la date', 'Relevé du'], lignes)

    # 2. Une ligne par disque : le détail vérifiable.
    feuille = classeur.create_sheet('Détail des disques')
    lignes = [[invite['vmid'], invite.get('name'), invite.get('node'), d['cle'], libelle(d['stockage']),
               d['stockage'], d['volume'], go(d['taille']), 'Oui' if d['detache'] else '']
              for invite in sorted(invites, key=lambda i: i['vmid']) for d in invite['disques'] or []]
    tableau(feuille, ['VMID', 'Nom', 'Nœud', 'Disque', 'Support', 'Stockage Proxmox', 'Volume',
                      'Taille allouée — Go', 'Volume détaché (unused)'], lignes)

    # 3. Capacités des supports, partagés comptés une fois.
    feuille = classeur.create_sheet('Capacité des supports')
    alloue = {}
    for invite in invites:
        for d in invite['disques'] or []:
            alloue[d['stockage']] = alloue.get(d['stockage'], 0) + (d['taille'] or 0)
    lignes = []
    for s in supports(ressources):
        libre = s['total'] - s['utilise']
        socle = SOCLES.get(s['nom'])
        lignes.append([libelle(s['nom']), s['nom'], s['type'], 'Partagé' if s['partage'] else 'Local',
                       ', '.join(sorted(n for n in s['noeuds'] if n)), to(s['total']), to(s['utilise']), to(libre),
                       round(100 * s['utilise'] / s['total'], 1) if s['total'] else None,
                       to(alloue.get(s['nom'], 0)),
                       f'Non — socle de {libelle(socle)} ({socle})' if socle else 'Oui'])
    entetes = ['Support', 'Stockage Proxmox', 'Type', 'Portée', 'Nœuds', 'Capacité totale — To',
               'Utilisé — To', 'Libre — To', 'Utilisé — %', 'Alloué aux VM (provisionné) — To',
               'Compté dans le total']
    tableau(feuille, entetes, lignes)
    total = len(lignes) + 2
    feuille.cell(row=total, column=1, value='TOTAL (sans double comptage)').font = gras
    for colonne in (6, 7, 8, 10):
        lettre = get_column_letter(colonne)
        cellule = feuille.cell(row=total, column=colonne,
                               value=f'=SUMIF(K2:K{total - 1},"Oui",{lettre}2:{lettre}{total - 1})')
        cellule.font = gras
    cellule = feuille.cell(row=total, column=9, value=f'=IF(F{total}=0,"",ROUND(100*G{total}/F{total},1))')
    cellule.font = gras

    notes = [
        f"Export OpsControl — API Proxmox en lecture seule — {datetime.now(timezone.utc).astimezone().strftime('%d/%m/%Y %H:%M')}",
        "Un support partagé (Ceph, NFS) est compté une seule fois, même s'il est visible depuis tous les nœuds.",
        "« local » additionne le disque local de chaque nœud : ce n'est pas un espace commun.",
        "« Alloué aux VM » = somme des tailles déclarées des disques (provisionnement). Avec le thin",
        "provisioning (Ceph, ZFS, qcow2), il peut dépasser l'utilisé réel, voire la capacité.",
        "Capacités Ceph : espace utile vu par Proxmox, après réplication.",
        "Le pool ZFS de prdlabpve06 sert le partage NFS : il est affiché mais exclu du total,",
        "sinon la même place physique serait comptée deux fois.",
        "« Utilisé » sur le disque local inclut aussi le système, les ISO et les sauvegardes du nœud.",
        "« Date de création (Proxmox) » = date d'arrivée de la VM sur ce cluster (création, restauration",
        "ou import). Une date commune à de nombreuses VM signale une opération en lot ; seule la date",
        "d'installation du système permet de distinguer un déploiement réel d'une migration.",
        "« Date de création retenue » croise les deux sources ; la colonne « Justification » dit comment.",
        "« Installation du système » = date d'installation de l'OS relevée dans la VM (inventaire_applications.py) :",
        "insensible aux migrations ; pour une VM clonée d'un modèle, c'est la date du modèle.",
    ]
    for decalage, texte in enumerate(notes):
        cellule = feuille.cell(row=total + 2 + decalage, column=1, value=texte)
        cellule.font = Font(name=police, size=9, italic=decalage > 0, bold=decalage == 0)

    if erreurs:
        feuille = classeur.create_sheet('Non lus')
        tableau(feuille, ['VMID', 'Nom', 'Erreur'], [list(e) for e in erreurs])
    classeur.save(chemin)


def main():
    analyseur = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    analyseur.add_argument('sortie', nargs='?', default='proxmox-vm-stockage.xlsx')
    args = analyseur.parse_args()

    ressources, invites, erreurs = collecter(ClientProxmox(connexion_proxmox()))
    chemin = Path(args.sortie)
    ecrire(chemin, ressources, invites, erreurs)
    print(f'{len(invites)} VM/conteneurs exportés ({len(erreurs)} config illisible(s)) dans {chemin.resolve()}')
    for s in supports(ressources):
        print(f"  {libelle(s['nom']):32}{' (socle, hors total)' if s['nom'] in SOCLES else ''} total {s['total'] / TIB:7.2f} To  utilisé {s['utilise'] / TIB:7.2f} To"
              f"  libre {(s['total'] - s['utilise']) / TIB:7.2f} To")
    return 0


if __name__ == '__main__':
    sys.exit(main())
