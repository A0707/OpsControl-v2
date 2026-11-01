"""Export Excel des serveurs actifs : nom, type et preuve de l'etat.

Lit directement l'inventaire et la base d'etat : aucun serveur InfraOps n'a
besoin de tourner, et rien n'est collecte — c'est une restitution de ce qui a
deja ete mesure.

Definition retenue de « actif », ecrite dans le fichier lui-meme :
un serveur dont le dernier audit SSH a abouti, quel que soit son etat de sante.
Un serveur injoignable n'est PAS actif ; un serveur en anomalie l'est. La date
de la preuve accompagne chaque ligne : sans elle, « actif » ne veut rien dire.

Usage :
    python export_serveurs.py [chemin/de/sortie.xlsx] [--tous]

    --tous  inclut aussi les serveurs injoignables, marques comme tels.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent

# Un serveur injoignable n'a pas d'etat mesurable : il n'est pas « actif ».
ETATS_ACTIFS = ('ok', 'critical', 'warning', 'unknown')
LIBELLES = {'ok': 'OK', 'critical': 'Critique', 'warning': 'À surveiller',
            'unknown': 'Incomplet', 'unreachable': 'Injoignable'}


def charger():
    """Inventaire, derniers audits et inventaire Proxmox, depuis le disque."""
    inventaire = json.loads((BASE / 'hosts.yaml').read_text(encoding='utf-8-sig'))['hosts']
    db = sqlite3.connect(f'file:{BASE / "data/state.sqlite3"}?mode=ro', uri=True)
    try:
        audits = {cle: json.loads(charge) for cle, charge in db.execute('SELECT key,payload FROM states')}
    finally:
        db.close()

    # Type de machine : une VM connue de Proxmox, sinon on ne conclut pas.
    guests = {}
    fichier = BASE / 'data/api-connections.json'
    if fichier.is_file():
        for connexion in json.loads(fichier.read_text(encoding='utf-8')):
            if connexion.get('provider') != 'Proxmox':
                continue
            inv = (connexion.get('last_result') or {}).get('inventory') or {}
            for noeud in inv.get('nodes', []):
                for invite in noeud.get('guests', []):
                    guests[(noeud['name'], invite['vmid'])] = invite
                    if invite.get('name'):
                        guests[invite['name'].lower()] = invite
    return inventaire, audits, guests


def type_machine(hote, guests):
    """Type de machine, ou « Non rapproché » — jamais une supposition."""
    invite = guests.get((hote.get('node'), hote.get('vmid'))) or guests.get((hote.get('name') or '').lower())
    if not invite:
        return 'Non rapproché', ''
    libelle = {'qemu': 'VM QEMU', 'lxc': 'Conteneur LXC'}.get(invite.get('type'), invite.get('type') or 'Inconnu')
    return libelle, invite.get('status') or ''


def lignes(tous=False):
    inventaire, audits, guests = charger()
    resultat = []
    for hote in inventaire:
        audit = audits.get(hote['key'], {})
        etat = audit.get('status') or 'unknown'
        actif = etat in ETATS_ACTIFS
        if not actif and not tous:
            continue
        machine, etat_pve = type_machine(hote, guests)
        mesure = audit.get('collected_at')
        resultat.append({
            'Nom': hote.get('name') or hote['key'],
            'Type de machine': machine,
            'Rôle': hote.get('role') or 'À renseigner',
            'Environnement': hote.get('environment') or 'À renseigner',
            'Adresse IP': hote.get('ip') or '',
            'Hyperviseur': hote.get('node') or '',
            'VMID': hote.get('vmid') or '',
            'État Proxmox': {'running': 'Démarrée', 'stopped': 'Arrêtée'}.get(etat_pve, etat_pve or 'Non mesuré'),
            'État audit SSH': LIBELLES.get(etat, etat),
            'Actif': 'Oui' if actif else 'Non',
            'Dernière preuve': (mesure or '').replace('T', ' ')[:19] or 'Jamais collecté',
        })
    resultat.sort(key=lambda r: (r['Rôle'], r['Nom']))
    return resultat


def ecrire(chemin, donnees, tous):
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.utils import get_column_letter

    classeur = Workbook()
    feuille = classeur.active
    feuille.title = 'Serveurs actifs'
    police = 'Arial'

    entetes = list(donnees[0].keys()) if donnees else ['Nom', 'Type de machine']
    titre = Font(name=police, bold=True, color='FFFFFF', size=10)
    fond = PatternFill('solid', fgColor='1F4E78')
    bord = Border(bottom=Side(style='thin', color='BFBFBF'))

    for colonne, entete in enumerate(entetes, 1):
        cellule = feuille.cell(row=1, column=colonne, value=entete)
        cellule.font, cellule.fill = titre, fond
        cellule.alignment = Alignment(horizontal='center', vertical='center')

    for ligne_num, ligne in enumerate(donnees, 2):
        for colonne, entete in enumerate(entetes, 1):
            cellule = feuille.cell(row=ligne_num, column=colonne, value=ligne[entete])
            cellule.font = Font(name=police, size=10)
            # Noms, rôles et environnements viennent de l'inventaire et de la découverte (noms de VM
            # Proxmox compris) : jamais évalués comme formule à l'ouverture (audit A6, 15/10).
            if cellule.data_type == 'f':
                cellule.data_type = 's'
            cellule.border = bord

    # Largeurs : lisible a l'ouverture, sans reglage manuel.
    for colonne, entete in enumerate(entetes, 1):
        largeur = max([len(str(entete))] + [len(str(l[entete])) for l in donnees] or [10])
        feuille.column_dimensions[get_column_letter(colonne)].width = min(max(largeur + 3, 11), 34)
    feuille.freeze_panes = 'A2'
    feuille.auto_filter.ref = f'A1:{get_column_letter(len(entetes))}{len(donnees) + 1}'

    # Ce que ce fichier affirme, et ce qu'il n'affirme pas. Sans cette note, un
    # tableau de serveurs « actifs » se lit comme un certificat de bonne sante.
    depart = len(donnees) + 3
    notes = [
        f"Export InfraOps — {datetime.now(timezone.utc).astimezone().strftime('%d/%m/%Y %H:%M')}",
        '',
        "« Actif » = le dernier audit SSH a abouti sur ce serveur, quel que soit son état de santé.",
        "Un serveur injoignable n'est pas listé comme actif ; un serveur en anomalie l'est.",
        "La colonne « Dernière preuve » date chaque ligne : une mesure ancienne reste une mesure ancienne.",
        "« Type de machine » vient de l'inventaire Proxmox. « Non rapproché » signifie que la VM n'a pas été",
        "retrouvée dans la collecte API — pas qu'il s'agit d'une machine physique.",
        "Ce tableau ne constitue ni une certification de sécurité, ni une preuve de disponibilité applicative.",
    ]
    if tous:
        notes.insert(2, "Export complet : les serveurs injoignables sont inclus, colonne « Actif » à Non.")
    for decalage, texte in enumerate(notes):
        cellule = feuille.cell(row=depart + decalage, column=1, value=texte)
        cellule.font = Font(name=police, size=9, italic=not decalage, bold=decalage == 0)

    classeur.save(chemin)


def main():
    analyseur = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    analyseur.add_argument('sortie', nargs='?', default='serveurs-actifs.xlsx')
    analyseur.add_argument('--tous', action='store_true', help='Inclure les serveurs injoignables')
    args = analyseur.parse_args()

    donnees = lignes(args.tous)
    if not donnees:
        print('Aucun serveur à exporter.')
        return 1
    chemin = Path(args.sortie)
    ecrire(chemin, donnees, args.tous)
    actifs = sum(r['Actif'] == 'Oui' for r in donnees)
    print(f'{len(donnees)} ligne(s) écrites ({actifs} actifs) dans {chemin.resolve()}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
