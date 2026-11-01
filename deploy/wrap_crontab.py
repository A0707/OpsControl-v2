"""Propose une crontab dont chaque batch passe par infraops-batch-report.

Ne touche à aucun serveur : lit un texte de crontab, écrit une proposition et
un rapport. L'installation reste un geste de votre équipe, après relecture.

Sur le serveur batch, en root :
    crontab -l > /root/crontab.avant-infraops            # sauvegarde
    python3 wrap_crontab.py /root/crontab.avant-infraops > /root/crontab.infraops
    diff /root/crontab.avant-infraops /root/crontab.infraops   # RELIRE
    crontab /root/crontab.infraops                       # installer
    # retour arrière : crontab /root/crontab.avant-infraops

Options : --systeme pour /etc/crontab ou /etc/cron.d/* (colonne utilisateur),
          --filtre /var/batch pour n'envelopper que les commandes qui citent ce chemin.

Règles de prudence — une ligne n'est JAMAIS modifiée si :
- elle contient un « % » non échappé : cron le transforme en saut de ligne AVANT
  le shell, l'envelopper changerait son sens ;
- sa planification n'est pas une syntaxe cron valide (ex. une expression Quartz
  « 0 0 1 ? 1/1 TUE#2 » collée par erreur : cron ne l'exécute pas) ;
- elle est déjà enveloppée, ou c'est une variable (MAILTO=, PATH=…) ou un commentaire.
Chaque cas est signalé dans le rapport (sortie d'erreur), jamais corrigé en silence.
"""
import re  # Python 3.6 minimum (CentOS 7) : pas de « from __future__ import annotations »
import sys

WRAPPER = '/usr/local/bin/infraops-batch-report'
CHAMP = r'(\*|\d+(-\d+)?(/\d+)?|\*/\d+)(,(\d+(-\d+)?(/\d+)?))*'
NOMS = r'(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec|sun|mon|tue|wed|thu|fri|sat)'
CHAMP_NOMME = r'(' + CHAMP + r'|' + NOMS + r'(-' + NOMS + r')?(,' + NOMS + r')*)'
SPECIAUX = {'@reboot', '@yearly', '@annually', '@monthly', '@weekly', '@daily', '@midnight', '@hourly'}


def planification_valide(champs):
    if len(champs) == 1:
        return champs[0].lower() in SPECIAUX
    return len(champs) == 5 and all(re.fullmatch(CHAMP_NOMME, c, re.I) for c in champs)


def nom_batch(commande, deja):
    """batch_demo-trade + script run_import.sh -> batch_demo-trade.run_import (unique)."""
    dossier = re.search(r'/var/batch/([A-Za-z0-9_.-]+)', commande)
    script = re.findall(r'([A-Za-z0-9_.-]+)\.(?:sh|py|pl|php|jar|ksh|bash)\b', commande)
    base = '.'.join(p for p in ((dossier.group(1) if dossier else ''), (script[-1] if script else '')) if p)
    if not base:
        mot = re.search(r'([A-Za-z0-9_.-]{3,})', commande.split()[-1] if commande.split() else '')
        base = mot.group(1) if mot else 'batch'
    base = re.sub(r'[^A-Za-z0-9_.-]', '_', base)[:60] or 'batch'
    nom, n = base, 2
    while nom in deja:
        nom, n = f'{base}.{n}', n + 1
    deja.add(nom)
    return nom


def envelopper(texte, systeme=False, filtre=None):
    sortie, rapport, deja = [], [], set()
    for numero, ligne in enumerate(texte.splitlines(), 1):
        brut = ligne.rstrip('\n')
        net = brut.strip()
        if not net or net.startswith('#') or re.match(r'^[A-Za-z_][A-Za-z0-9_]*\s*=', net):
            sortie.append(brut)
            continue
        nb = 1 if net.startswith('@') else 5
        morceaux = net.split(None, nb + (1 if systeme else 0))
        if len(morceaux) < nb + 1 + (1 if systeme else 0):
            sortie.append(brut)
            rapport.append(f'ligne {numero} : incomplète, laissée telle quelle')
            continue
        planif, reste = morceaux[:nb], morceaux[nb:]
        utilisateur = reste.pop(0) if systeme else None
        commande = reste[0]
        if not planification_valide(planif):
            sortie.append(brut)
            rapport.append(f'ligne {numero} : planification invalide « {" ".join(planif)} » — cron ne l’exécute PAS. À corriger.')
            continue
        if WRAPPER in commande:
            sortie.append(brut)
            rapport.append(f'ligne {numero} : déjà enveloppée')
            continue
        if filtre and filtre not in commande:
            sortie.append(brut)
            continue
        if re.search(r'(?<!\\)%', commande):
            sortie.append(brut)
            rapport.append(f'ligne {numero} : contient « % » (sens spécial pour cron) — à envelopper à la main')
            continue
        nom = nom_batch(commande, deja)
        cite = "'" + commande.replace("'", "'\\''") + "'"
        prefixe = ' '.join(planif) + ' ' + (utilisateur + ' ' if utilisateur else '')
        sortie.append(f'{prefixe}{WRAPPER} {nom} /bin/sh -c {cite}')
        rapport.append(f'ligne {numero} : enveloppée sous le nom {nom}')
    return '\n'.join(sortie) + '\n', rapport


def main(args):
    systeme = '--systeme' in args
    filtre = args[args.index('--filtre') + 1] if '--filtre' in args else None
    fichiers = [a for i, a in enumerate(args) if not a.startswith('--') and (i == 0 or args[i - 1] != '--filtre')]
    texte = open(fichiers[0], encoding='utf-8').read() if fichiers else sys.stdin.read()
    proposition, rapport = envelopper(texte, systeme, filtre)
    sys.stdout.write(proposition)
    sys.stderr.write('\n'.join(['# Rapport infraops-batch (à relire avant installation) :'] + ['#   ' + r for r in rapport]) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
