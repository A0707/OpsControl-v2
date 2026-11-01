"""Prépare l'archive de migration vers la VM, sur le PC actuel.

    python deploy/package_vm.py            -> dist/infraops-vm-AAAAMMJJ-HHMM.tar.gz
    python deploy/package_vm.py --code-only -> dist/opscontrol-code-AAAAMMJJ-HHMM.tar.gz

Le mode --code-only fonctionne sans inventaire ni données, n’embarque aucune
empreinte personnelle et ne fait aucun test réseau local. Il est utilisé par la CI.

Ce que l'archive CONTIENT : le code, l'interface, les tests, l'inventaire, et
l'état déjà collecté (base SQLite copiée à chaud de façon cohérente, sources
API, empreintes SSH vérifiées). La VM repart donc avec tout l'historique : pas
de « premier audit » à refaire, pas d'empreinte à revérifier.

Ce qu'elle ne contient JAMAIS : aucun secret. Les jetons API vivent dans le
coffre DPAPI de ce compte Windows et ne sont pas lisibles ailleurs ; ils seront
saisis sur la VM (deploy/install-vm.sh les demande sans écho). Aucune clé
privée SSH non plus. Le script vérifie ces deux points avant d'écrire l'archive.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import socket
import sqlite3
import sys
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
DIST = BASE / 'dist'

# Code et interface : liste positive, rien d'autre n'entre.
CODE_GLOBS = ['*.py', 'routers/*.py', 'requirements.txt', 'hosts.yaml', 'web/*.js', 'web/*.css', 'web/*.html', 'web/*.json', 'web/next/*',
              'web/assets/*', 'deploy/*', 'deploy/remote/*', 'test_fixtures/tls/*.pem', 'docs/*.md', 'CHANGELOG.md',
              'hosts.example.yaml', 'requirements-dev.txt', '*.cjs', 'README.md', 'AGENTS.md',
              '.github/workflows/*.yml', '.secrets.baseline', 'pyproject.toml']
# Manifeste UNIQUE de l'état à conserver, partagé par la migration (ici), la sauvegarde
# (backup_state.py) et la restauration (restore_state.py). Chaque script avait sa liste :
# les CA placées dans data/ca/ (forme acceptée par management.ca_file_refused) n'étaient
# ni sauvegardées ni migrées, et les liaisons de jetons repartaient de zéro après reprise
# (audit A1, 15/10). Aucun de ces fichiers ne contient de secret ; SECRETS le vérifie.
DATA_FILES = ['data/api-connections.json', 'data/known_hosts', 'data/bacula-known_hosts', 'data/proxmox-ovh-root-ca.pem',
              'data/token-bindings.json']
CA_DIR = 'data/ca'
CA_SUFFIXES = ('.pem', '.crt', '.cer')
CA_MAX_BYTES = 1024 * 1024


def ca_files(base):
    """Certificats publics de data/ca/ : fichiers réguliers, extension attendue, sans lien
    sortant du dossier (un lien vers /etc/… embarquerait un fichier étranger à l'instance)."""
    racine = Path(base) / CA_DIR
    if not racine.is_dir() or racine.is_symlink():
        return []
    reel = racine.resolve()
    retenus = []
    for f in sorted(racine.rglob('*')):
        if f.is_symlink() or not f.is_file() or f.suffix.lower() not in CA_SUFFIXES:
            continue
        if reel not in f.resolve().parents or f.stat().st_size > CA_MAX_BYTES:
            continue
        retenus.append(f.relative_to(base).as_posix())
    return retenus


def state_files(base):
    """Fichiers d'état présents dans `base`, base SQLite exceptée (copiée à part, à chaud)."""
    return [f for f in DATA_FILES if (Path(base) / f).is_file()] + ca_files(base)


def restorable(rel):
    """Chemin relatif qu'une restauration peut écrire : la base et le manifeste, rien d'autre
    (ni code, ni configuration système). Une archive forgée ne remplace donc aucun .py."""
    if rel in ('data/state.sqlite3', 'hosts.yaml') or rel in DATA_FILES:
        return True
    parts = rel.split('/')
    return (rel.startswith(CA_DIR + '/') and '..' not in parts and '' not in parts
            and Path(rel).suffix.lower() in CA_SUFFIXES)
TEXTE = ('.py', '.sh', '.service', '.timer', '.conf', '.yaml', '.yml', '.json', '.js', '.cjs', '.css', '.html',
         '.md', '.txt', '.pem')
# regen_hostkeys.py écrit sur le parc (clés d'hôte, sshd) : outil d'administration du PC,
# jamais livré avec le service en lecture seule (audit SSH-04).
EXCLURE = re.compile(r'(^ssh\.before|\.avant-|\.bak$|^export_serveurs|\.xlsx$|/\.|^deploy/regen_hostkeys\.py$)')
# Motifs de secrets : si l'un apparaît dans un fichier embarqué, on refuse.
SECRETS = re.compile(r'PVEAPIToken=[^\s"\'<]*![^\s"\'<]*=[0-9a-f-]{20,}|Bearer [A-Za-z0-9._-]{30,}|'
                     r'ApiKey [A-Za-z0-9+/=]{30,}|Basic [A-Za-z0-9+/=]{24,}|-----BEGIN [A-Z ]*PRIVATE KEY-----')


def serveur_actif():
    try:
        with socket.create_connection(('127.0.0.1', 8000), timeout=0.5):
            return True
    except OSError:
        return False


def copie_base(dest):
    """Copie cohérente même serveur en marche (API de sauvegarde SQLite)."""
    source = sqlite3.connect(f'file:{BASE / "data/state.sqlite3"}?mode=ro', uri=True)
    cible = sqlite3.connect(dest)
    with cible:
        source.backup(cible)
    source.close()
    cible.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description='Archive VM de migration ou archive de code pour la CI')
    parser.add_argument('--code-only', action='store_true', help='Code et exemple synthétique uniquement, sans état ni empreintes')
    args = parser.parse_args(argv)
    fichiers = []
    for motif in CODE_GLOBS:
        for f in sorted(BASE.glob(motif)):
            rel = f.relative_to(BASE).as_posix()
            if args.code_only and rel == 'hosts.yaml':
                continue
            if f.is_file() and not EXCLURE.search(rel) and '__pycache__' not in rel:
                fichiers.append(rel)
    if not args.code_only:
        fichiers += state_files(BASE)

    refus = []
    for rel in fichiers:
        texte = (BASE / rel).read_text(encoding='utf-8', errors='replace')
        if SECRETS.search(texte) and not rel.startswith(('test_', 'deploy/package_vm.py')):
            refus.append(rel)
    connexions = [] if args.code_only else json.loads((BASE / 'data/api-connections.json').read_text(encoding='utf-8'))
    for c in connexions:
        for champ in ('token', 'password', 'secret', 'auth'):
            if c.get(champ):
                refus.append(f'data/api-connections.json ({c.get("name")} : champ « {champ} »)')
    if refus:
        print('REFUS : contenu ressemblant à un secret dans :', *refus, sep='\n  ')
        return 1

    DIST.mkdir(exist_ok=True)
    prefix = 'opscontrol-code' if args.code_only else 'infraops-vm'
    nom = DIST / f'{prefix}-{datetime.now():%Y%m%d-%H%M}.tar.gz'
    manifeste = []
    with tempfile.TemporaryDirectory() as tmp, tarfile.open(nom, 'w:gz') as archive:
        base_copie = Path(tmp) / 'state.sqlite3'
        entrees = [(BASE / rel, rel) for rel in sorted(set(fichiers))]
        if not args.code_only:
            copie_base(base_copie)
            entrees.append((base_copie, 'data/state.sqlite3'))
        # Empreintes SSH déjà acceptées sur ce poste : même confiance sur la VM,
        # ni plus ni moins. InfraOps les lit en second fichier known_hosts.
        if not args.code_only:
            perso = Path.home() / '.ssh/known_hosts'
            if perso.is_file():
                entrees.append((perso, 'ssh/known_hosts'))
        for chemin, rel in entrees:
            donnees = chemin.read_bytes()
            # Fins de ligne LF pour tout fichier texte : ce poste Windows en a en CRLF, et
            # un script bash ou une unité systemd en CRLF échoue ou se lit mal sur la VM.
            if rel.endswith(TEXTE) or rel.startswith('deploy/remote/'):
                donnees = donnees.replace(b'\r\n', b'\n')
            info = tarfile.TarInfo('infraops/' + rel)
            info.size, info.mode, info.mtime = len(donnees), 0o644, int(chemin.stat().st_mtime)
            archive.addfile(info, io.BytesIO(donnees))
            manifeste.append(f'{hashlib.sha256(donnees).hexdigest()}  {rel}')
        texte = ('\n'.join(manifeste) + '\n').encode()
        info = tarfile.TarInfo('infraops/MANIFEST.sha256')
        info.size = len(texte)
        archive.addfile(info, io.BytesIO(texte))

    taille = nom.stat().st_size / 1024 ** 2
    print(f'Archive : {nom} ({taille:.1f} Mo, {len(manifeste)} fichiers, aucun secret)')
    print(f'SHA-256 : {hashlib.sha256(nom.read_bytes()).hexdigest()}')
    if not args.code_only and serveur_actif():
        print('ATTENTION : InfraOps tourne encore sur ce PC. Au basculement, arrêtez-le AVANT de refaire '
              "l'archive : sinon les audits faits entre-temps sur le PC seront perdus, et deux collecteurs "
              'auditeraient le parc en double.')
    print('Copie vers la VM :  scp', nom.name, 'admin@<IP-VM>:/tmp/')
    return 0


if __name__ == '__main__':
    sys.exit(main())
