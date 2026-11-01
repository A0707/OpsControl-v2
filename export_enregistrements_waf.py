"""Classeur Excel des enregistrements publiés par le WAF, regroupés par serveur.

Méthode rapide : aucune connexion. Les noms DNS et les cibles de proxy sont déclarés sur
le WAF principal (prdlabwaf03, 10.77.0.131) ; son dernier relevé, fait pendant l'audit
SSH, est lu dans la base locale d'OpsControl, en lecture seule. Chaque cible
« serveur:port » est rapprochée de l'inventaire, et l'application qui écoute sur le port
vient du dernier relevé de ce serveur s'il existe (sinon, c'est dit).

Usage :
    python export_enregistrements_waf.py [sortie.xlsx] [--waf CLÉ_OU_IP]

Pour un relevé à jour : auditer le WAF dans OpsControl (« Auditer ce serveur »), puis
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
from pathlib import Path

import published_sites as ps
from audit_retention import measured

BASE = Path(__file__).resolve().parent
WAF_DEFAUT = 'prdlabwaf03'
DNS_LIBELLES = {'interne': 'DNS interne', 'en_ligne': 'En ligne (IP publique)', 'non_resolu': 'Non résolu'}
_CONTROLE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')


def base_donnees() -> Path:
    return Path(os.environ.get('COCKPIT_DB') or BASE / 'data' / 'state.sqlite3').resolve()


def observation(etat: dict) -> dict:
    """Dernier relevé réussi : après un audit en échec (serveur injoignable), l'état courant
    ne contient plus les mesures, conservées dans `last_observation`."""
    if measured(etat) or not isinstance(etat.get('last_observation'), dict):
        return etat
    return {**etat['last_observation'], 'etat_courant': etat.get('status')}


def charger(db_path: Path, inventaire: Path) -> tuple[list[dict], dict]:
    """Inventaire et derniers relevés réussis (lecture seule) : {clé: observation}."""
    hotes = json.loads(inventaire.read_text(encoding='utf-8-sig'))['hosts']
    db = sqlite3.connect(db_path.as_uri() + '?mode=ro', uri=True)
    try:
        etats = {cle: observation(json.loads(payload)) for cle, payload in db.execute('SELECT key, payload FROM states')}
    finally:
        db.close()
    return hotes, etats


def trouver_waf(hotes: list[dict], waf: str) -> dict:
    cible = waf.lower()
    for h in hotes:
        if cible in {str(h.get('key', '')).lower(), str(h.get('ip', '')).lower(), str(h.get('name', '')).lower()}:
            return h
    raise SystemExit(f'WAF « {waf} » absent de l’inventaire.')


def lignes(hotes: list[dict], etats: dict, waf: dict) -> tuple[list[dict], list[dict], list[dict], dict]:
    """(publiés par serveur, hors inventaire, sites sans cible, relevé du WAF)."""
    releve = (etats.get(waf['key']) or {}).get('applications') or {}
    if releve.get('status') != 'observed':
        raise SystemExit('Pas de relevé des applications pour le WAF : l’auditer dans OpsControl, puis relancer.')
    actifs = [{**h, 'applications': (etats.get(h['key']) or {}).get('applications')} for h in hotes]
    index = [(ps._identites(h), h) for h in actifs if h['key'] != waf['key']]
    publies, hors, sans_cible = [], [], []
    for site in releve.get('sites') or []:
        dns = site.get('dns') or {}
        commun = {'site': site.get('nom'), 'url': site.get('url'), 'https': 'Oui' if site.get('https') else 'Non',
                  'dns': DNS_LIBELLES.get(dns.get('statut'), 'Non mesuré'), 'adresses': ', '.join(dns.get('adresses') or []),
                  'fichiers': ', '.join(site.get('fichiers') or [])}
        if not site.get('cibles'):
            sans_cible.append({**commun, 'racines': ', '.join(site.get('racines') or [])})
            continue
        for entree in site['cibles']:
            hote, port, chemin = ps._cible(entree)
            ligne = {**commun, 'port': port, 'chemin': entree.get('chemin') or '/', 'chemin_cible': chemin,
                     'repartiteur': entree.get('repartiteur') or '', 'cible': f'{hote}:{port}'}
            serveur = next((h for noms, h in index if hote.rstrip('.') in noms), None)
            if hote in ps.LOCAUX:
                ligne['application'] = entree.get('application') or ''
                hors.append({**ligne, 'motif': 'Application locale au WAF'})
            elif serveur is None:
                hors.append({**ligne, 'motif': 'Cible absente de l’inventaire OpsControl'})
            else:
                apps = serveur.get('applications') or {}
                publies.append({**ligne, 'serveur': serveur.get('name') or serveur['key'], 'cle': serveur['key'],
                                'ip': serveur.get('ip'), 'role': serveur.get('role') or '',
                                'environnement': serveur.get('environment') or '',
                                'application': ps.application_locale(apps, port, chemin),
                                'releve_serveur': apps.get('collected_at') or 'Jamais'})
    publies.sort(key=lambda l: (str(l['serveur']).lower(), l['port'] or 0, str(l['site']).lower()))
    hors.sort(key=lambda l: (l['cible'], str(l['site']).lower()))
    return publies, hors, sans_cible, releve


def texte(valeur):
    return _CONTROLE.sub('', valeur) if isinstance(valeur, str) else valeur


def tableau(feuille, colonnes, donnees, largeur_max=50) -> None:
    """En-tête, lignes et filtres ; `colonnes` : [(en-tête, clé)]."""
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter
    titre = Font(name='Arial', bold=True, color='FFFFFF', size=10)
    fond = PatternFill('solid', fgColor='1F4E78')
    normal = Font(name='Arial', size=10)
    for n, (entete, _cle) in enumerate(colonnes, 1):
        c = feuille.cell(row=1, column=n, value=entete)
        c.font, c.fill = titre, fond
        c.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
    for r, ligne in enumerate(donnees, 2):
        for n, (_entete, cle) in enumerate(colonnes, 1):
            c = feuille.cell(row=r, column=n, value=texte(ligne.get(cle)))
            c.font = normal
            # Valeurs venues des configurations : jamais évaluées comme formule.
            if c.data_type == 'f':
                c.data_type = 's'
    for n, (entete, cle) in enumerate(colonnes, 1):
        largeur = max([len(entete)] + [len(str(l.get(cle) or '')) for l in donnees])
        feuille.column_dimensions[get_column_letter(n)].width = min(max(largeur + 2, 10), largeur_max)
    feuille.freeze_panes = 'A2'
    if donnees:
        feuille.auto_filter.ref = feuille.dimensions


def feuille_limites(classeur, lignes) -> None:
    from openpyxl.styles import Font
    limites = classeur.create_sheet('Source et limites')
    for r, ligne in enumerate(lignes, 1):
        for n, valeur in enumerate(ligne, 1):
            limites.cell(row=r, column=n, value=valeur).font = Font(name='Arial', size=10, bold=(n == 1))
    limites.column_dimensions['A'].width = 18
    limites.column_dimensions['B'].width = 110


def ecrire(chemin: Path, publies, hors, sans_cible, releve, waf) -> None:
    from openpyxl import Workbook
    classeur = Workbook()
    feuille = classeur.active
    feuille.title = 'Par serveur'
    tableau(feuille, [('Serveur', 'serveur'), ('IP', 'ip'), ('Rôle', 'role'), ('Environnement', 'environnement'),
                      ('Port', 'port'), ('Enregistrement DNS', 'site'), ('URL', 'url'), ('DNS', 'dns'),
                      ('Adresses DNS', 'adresses'), ('HTTPS', 'https'), ('Chemin public', 'chemin'),
                      ('Chemin cible', 'chemin_cible'), ('Répartiteur', 'repartiteur'),
                      ('Application sur le serveur', 'application'), ('Relevé du serveur', 'releve_serveur'),
                      ('Configuration WAF', 'fichiers')], publies)

    synthese = {}
    for l in publies:
        s = synthese.setdefault(l['cle'], {'serveur': l['serveur'], 'ip': l['ip'], 'role': l['role'],
                                           'sites': set(), 'ports': set(), 'applications': set()})
        s['sites'].add(l['site'])
        s['ports'].add(str(l['port']))
        s['applications'].add(l['application'])
    lignes_synthese = [{'serveur': s['serveur'], 'ip': s['ip'], 'role': s['role'], 'nb': len(s['sites']),
                        'ports': ', '.join(sorted(s['ports'], key=lambda p: int(p) if p.isdigit() else 0)),
                        'sites': ', '.join(sorted(s['sites'])), 'applications': ' | '.join(sorted(s['applications']))}
                       for s in sorted(synthese.values(), key=lambda s: str(s['serveur']).lower())]
    tableau(classeur.create_sheet('Synthèse par serveur'),
            [('Serveur', 'serveur'), ('IP', 'ip'), ('Rôle', 'role'), ('Nb enregistrements', 'nb'),
             ('Ports visés', 'ports'), ('Enregistrements DNS', 'sites'), ('Applications (relevé)', 'applications')],
            lignes_synthese)
    tableau(classeur.create_sheet('Hors inventaire'),
            [('Cible', 'cible'), ('Motif', 'motif'), ('Enregistrement DNS', 'site'), ('URL', 'url'), ('DNS', 'dns'),
             ('Chemin public', 'chemin'), ('Répartiteur', 'repartiteur'), ('Configuration WAF', 'fichiers')], hors)
    tableau(classeur.create_sheet('Sites sans cible'),
            [('Enregistrement DNS', 'site'), ('URL', 'url'), ('DNS', 'dns'), ('Racine de fichiers', 'racines'),
             ('Configuration WAF', 'fichiers')], sans_cible)
    feuille_limites(classeur, [
        ('Source', f"Relevé du WAF {waf.get('name') or waf['key']} ({waf.get('ip')}) du {releve.get('collected_at')}"),
        ('Généré le', datetime.now(timezone.utc).isoformat(timespec='seconds')),
        ('Méthode', 'Aucune connexion : relevés déjà collectés par OpsControl (base locale en lecture seule).'),
        ('Rapprochement', 'Cible du proxy (IP, clé, nom, FQDN ou nom court) comparée à l’inventaire.'),
        ('Application', 'Déduite du port visé d’après le relevé du serveur cible : conteneur Docker, contexte '
                        'Tomcat, port en écoute. « indisponible » si le serveur n’a pas de relevé récent.'),
        ('DNS', 'Résolu par OpsControl lors de l’audit du WAF : interne = adresses privées, en ligne = IP publique.'),
        ('Actualiser', 'Auditer le WAF (et les serveurs) dans OpsControl, puis relancer ce script.'),
    ])
    classeur.save(chemin)


def main(argv=None) -> int:
    a = argparse.ArgumentParser(description='Enregistrements publiés par le WAF, par serveur (Excel)')
    a.add_argument('sortie', nargs='?', default='enregistrements-waf.xlsx')
    a.add_argument('--waf', default=WAF_DEFAUT, help='clé, nom ou IP du WAF dans l’inventaire')
    args = a.parse_args(argv)
    from config import inventory_path
    hotes, etats = charger(base_donnees(), inventory_path(BASE / 'hosts.yaml'))
    waf = trouver_waf(hotes, args.waf)
    publies, hors, sans_cible, releve = lignes(hotes, etats, waf)
    sortie = Path(args.sortie).resolve()
    ecrire(sortie, publies, hors, sans_cible, releve, waf)
    serveurs = len({l['cle'] for l in publies})
    print(f'{sortie} : {len(publies)} enregistrement(s) vers {serveurs} serveur(s), '
          f'{len(hors)} hors inventaire, {len(sans_cible)} site(s) sans cible ; relevé du WAF du {releve.get("collected_at")}.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
