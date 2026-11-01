"""Saisie des secrets InfraOps sur la VM (remplace le coffre DPAPI de Windows).

    sudo python3 /opt/infraops/deploy/secrets_env.py            saisir les secrets manquants
    sudo python3 /opt/infraops/deploy/secrets_env.py --tous     tout ressaisir
    sudo python3 /opt/infraops/deploy/secrets_env.py --etat     afficher QUELLES variables sont renseignées

Les valeurs sont saisies sans écho et ne sont jamais affichées, y compris par
--etat (qui ne montre que les noms). Le fichier est en 0640 root:infraops :
lisible par le service, par personne d'autre. Chaque valeur est écrite entre
guillemets, au format EnvironmentFile de systemd : un jeton contenant des
espaces (« Basic … », « ApiKey … ») ou des « = » reste intact.
"""
from __future__ import annotations

import getpass
import grp
import json
import os
import secrets
import sys
from pathlib import Path

FICHIER = Path(os.environ.get('INFRAOPS_SECRETS', '/etc/infraops/secrets.env'))
CONNEXIONS = Path(__file__).resolve().parent.parent / 'data/api-connections.json'
FORMATS = {
    'Proxmox': 'clé API complète : PVEAPIToken=UTILISATEUR@REALM!ID=SECRET',
    'Wazuh': 'utilisateur:mot_de_passe',
    'Zabbix': 'jeton API seul, sans préfixe',
    'Elasticsearch': 'ApiKey CLE_ENCODEE',
    'Bacula': 'Basic BASE64(utilisateur:mot_de_passe)',
}
WEBHOOK = 'INFRAOPS_WEBHOOK_TOKEN'
# Veille sécurité (security_watch.py, security_alerts.py) : secrets FACULTATIFS, proposés une fois.
OPTIONNELS = {
    'NVD_API_KEY': 'clé API NVD, facultative (débit 50 requêtes / 30 s au lieu de 5)',  # pragma: allowlist secret -- nom de variable et description, aucune valeur
    'GITHUB_TOKEN': 'jeton GitHub en lecture seule, facultatif (avis PHP et WordPress)',
    'INFRAOPS_SMTP_PASSWORD': 'mot de passe du compte SMTP des alertes, si authentification',  # pragma: allowlist secret -- nom de variable et description, aucune valeur
}


def lire():
    valeurs = {}
    if FICHIER.is_file():
        for ligne in FICHIER.read_text(encoding='utf-8').splitlines():
            if '=' in ligne and not ligne.lstrip().startswith('#'):
                nom, _, brut = ligne.partition('=')
                brut = brut.strip()
                if len(brut) >= 2 and brut[0] == brut[-1] == '"':
                    brut = brut[1:-1].replace('\\"', '"').replace('\\\\', '\\')
                valeurs[nom.strip()] = brut
    return valeurs


def ecrire(valeurs):
    lignes = ['# Secrets InfraOps — 0640 root:infraops. Modifier avec deploy/secrets_env.py.']
    for nom, valeur in valeurs.items():
        if '\n' in valeur or '\r' in valeur:
            raise ValueError(nom + ' : retour à la ligne interdit dans une valeur')
        lignes.append(nom + '="' + valeur.replace('\\', '\\\\').replace('"', '\\"') + '"')
    FICHIER.parent.mkdir(parents=True, exist_ok=True)
    temporaire = FICHIER.with_suffix('.tmp')
    ancien = os.umask(0o027)
    try:
        temporaire.write_text('\n'.join(lignes) + '\n', encoding='utf-8')
    finally:
        os.umask(ancien)
    try:
        os.chown(temporaire, 0, grp.getgrnam('infraops').gr_gid)
    except KeyError:
        pass
    os.chmod(temporaire, 0o640)
    os.replace(temporaire, FICHIER)


def sources():
    try:
        items = json.loads(CONNEXIONS.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}
    return {c['token_env']: c.get('provider', '') for c in items if c.get('token_env')}


def main(args):
    if os.geteuid() != 0:
        print('À lancer en root (sudo) : le fichier appartient à root.')
        return 1
    valeurs = lire()
    attendus = sources()
    for nom in attendus:
        valeurs.setdefault(nom, '')
    if '--etat' in args:
        # Lecture seule : noms et présence, jamais les valeurs, rien n'est écrit.
        for nom in sorted(set(valeurs) | {WEBHOOK} | set(OPTIONNELS)):
            print(f"   {nom:28} {'renseigné' if valeurs.get(nom) else 'VIDE'}")
        return 0
    if not valeurs.get(WEBHOOK):
        valeurs[WEBHOOK] = secrets.token_hex(32)
        print(WEBHOOK, ': généré. Pour le recopier dans le type de média Zabbix :',
              'sudo grep', WEBHOOK, str(FICHIER))
    tous = '--tous' in args
    for nom, provider in attendus.items():
        if valeurs.get(nom) and not tous:
            continue
        saisie = getpass.getpass(f'{nom} ({provider} — {FORMATS.get(provider, "valeur")}), vide pour ignorer : ')
        if saisie.strip():
            valeurs[nom] = saisie.strip()
    for nom, description in OPTIONNELS.items():
        if nom in valeurs and not tous:
            continue
        saisie = getpass.getpass(f'{nom} ({description}), vide pour ignorer : ')
        # Une valeur vide est enregistrée : la question n'est plus reposée (--tous pour la changer).
        valeurs[nom] = saisie.strip()
    ecrire(valeurs)
    print('Écrit :', FICHIER, '(0640 root:infraops). Redémarrer : systemctl restart infraops')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
