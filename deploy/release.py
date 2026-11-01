"""Releases versionnées d'OpsControl sur la VM : vérification, installation, bascule, rollback.

    python3 release.py verify   SRC [--archive F --sha256 H]   # refuse toute archive incorrecte
    python3 release.py stage    SRC DEST                       # copie le code dans DEST/releases/<id>
    python3 release.py activate DEST ID [--health-url URL]     # bascule current, redémarre, rollback si KO
    python3 release.py rollback DEST                           # revient à la release précédente
    python3 release.py status   DEST

Disposition sur la VM (données inchangées par rapport à l'installation historique) :

    /opt/infraops/
      data/  hosts.yaml  audit.log  .ssh/          <- données partagées, JAMAIS écrasées ici
      releases/<AAAAMMJJ-HHMMSS>-<empreinte>/      <- code + .venv propre à la release
          data -> ../../data     hosts.yaml -> ../../hosts.yaml
      current -> releases/<id>                     <- bascule atomique (rename d'un lien)
      releases/.previous                           <- release précédente, conservée

Ce module ne touche ni aux secrets (/etc/infraops), ni aux clés SSH, ni aux
empreintes, ni à la base : il ne copie que les fichiers de code du manifeste.
Les opérations sur les liens sont injectables (`Links`) pour être testées sous
Windows, où créer un lien symbolique demande un privilège.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import shutil
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

MANIFEST = 'MANIFEST.sha256'
# Jamais copiés dans une release : données partagées, gérées par install-vm.sh
# uniquement si absentes de la VM.
PERSISTENT = ('data/', 'ssh/', '.ssh/', 'hosts.yaml', 'audit.log', '.venv/')
SHARED_LINKS = ('data', 'hosts.yaml')
KEEP = 3


class ReleaseError(RuntimeError):
    pass


# --------------------------------------------------------------------------- manifeste
def read_manifest(src: Path) -> dict[str, str]:
    path = Path(src) / MANIFEST
    if not path.is_file():
        raise ReleaseError(f'{MANIFEST} absent : archive refusée')
    entries: dict[str, str] = {}
    for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        if not line.strip():
            continue
        digest, sep, rel = line.partition('  ')
        if not sep or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise ReleaseError(f'{MANIFEST} ligne {number} mal formée')
        normalized = posixpath.normpath(rel)
        if rel.startswith('/') or normalized.startswith('..') or '\\' in rel or normalized != rel:
            raise ReleaseError(f'{MANIFEST} ligne {number} : chemin refusé ({rel!r})')
        if rel in entries:
            raise ReleaseError(f'{MANIFEST} : chemin en double ({rel})')
        entries[rel] = digest
    if not entries:
        raise ReleaseError(f'{MANIFEST} vide')
    return entries


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def verify(src, archive=None, expected_sha256=None) -> dict:
    """Vérifie l'archive dépaquetée AVANT toute installation. Lève ReleaseError."""
    src = Path(src)
    if archive and expected_sha256:
        actual = sha256(Path(archive))
        if actual != expected_sha256.lower():
            raise ReleaseError(f'Empreinte de l’archive incorrecte : {actual} au lieu de {expected_sha256}')
    entries = read_manifest(src)
    errors = []
    for rel, digest in entries.items():
        path = src / rel
        if path.is_symlink():
            errors.append(f'lien symbolique refusé : {rel}')
        elif not path.is_file():
            errors.append(f'fichier manquant : {rel}')
        elif sha256(path) != digest:
            errors.append(f'empreinte différente : {rel}')
    listed = set(entries) | {MANIFEST}
    for path in sorted(src.rglob('*')):
        rel = path.relative_to(src).as_posix()
        if path.is_symlink():
            errors.append(f'lien symbolique refusé : {rel}')
        elif path.is_file() and rel not in listed and '__pycache__' not in rel:
            errors.append(f'fichier hors manifeste : {rel}')
    for required in ('app.py', 'requirements.txt', 'web/index.html'):
        if required not in entries:
            errors.append(f'fichier indispensable absent du manifeste : {required}')
    if errors:
        raise ReleaseError('Archive refusée :\n  ' + '\n  '.join(errors[:40]))
    manifest_digest = sha256(src / MANIFEST)
    return {'files': len(entries), 'manifest_sha256': manifest_digest, 'entries': entries}


def release_id(manifest_digest: str, now=None) -> str:
    return (now or datetime.now(timezone.utc)).strftime('%Y%m%d-%H%M%S') + '-' + manifest_digest[:12]


# --------------------------------------------------------------------------- liens
class Links:
    """Liens symboliques POSIX ; bascule atomique par rename d'un lien temporaire."""

    def point(self, link: Path, target: str):
        tmp = link.with_name('.' + link.name + '.tmp')
        if tmp.is_symlink() or tmp.exists():
            tmp.unlink()
        os.symlink(target, tmp)
        os.replace(tmp, link)  # rename(2) : atomique, jamais d'instant sans « current »

    def read(self, link: Path) -> str | None:
        return os.readlink(link) if link.is_symlink() else None

    def share(self, link: Path, target: Path):
        os.symlink(os.path.relpath(target, link.parent), link)


def _current_id(dest: Path, links: Links) -> str | None:
    value = links.read(dest / 'current')
    return Path(value).name if value else None


def _previous_id(dest: Path) -> str | None:
    path = dest / 'releases' / '.previous'
    return (path.read_text(encoding='utf-8').strip() or None) if path.is_file() else None


# --------------------------------------------------------------------------- installation
def stage(src, dest, links: Links | None = None, now=None) -> str:
    """Copie les fichiers de code du manifeste dans une nouvelle release. Rien d'autre."""
    links = links or Links()
    src, dest = Path(src), Path(dest)
    checked = verify(src)
    rid = release_id(checked['manifest_sha256'], now)
    releases = dest / 'releases'
    final = releases / rid
    if final.exists():
        raise ReleaseError(f'Release {rid} déjà présente')
    work = releases / ('.' + rid + '.partial')
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    copied = 0
    for rel in checked['entries']:
        if rel.startswith(PERSISTENT) or rel in PERSISTENT:
            continue
        target = work / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src / rel, target)
        copied += 1
    shutil.copy2(src / MANIFEST, work / MANIFEST)
    (work / 'RELEASE').write_text(json.dumps({'id': rid, 'manifest_sha256': checked['manifest_sha256'],
                                              'files': copied, 'staged_at': datetime.now(timezone.utc).isoformat()},
                                             indent=2), encoding='utf-8')
    for name in SHARED_LINKS:
        links.share(work / name, dest / name)
    os.replace(work, final)
    return rid


def activate(dest, rid, restart, healthy, links: Links | None = None) -> dict:
    """Bascule `current` vers rid, redémarre, et revient en arrière si le service ne répond pas.

    restart() et healthy() sont injectés : systemctl + /api/health sur la VM, simulés en test.
    """
    links = links or Links()
    dest = Path(dest)
    if not (dest / 'releases' / rid).is_dir():
        raise ReleaseError(f'Release inconnue : {rid}')
    previous = _current_id(dest, links)
    links.point(dest / 'current', 'releases/' + rid)
    try:
        restart()
        ok = healthy()
    except Exception:  # noqa: BLE001 — un échec de démarrage déclenche le retour arrière
        ok = False
    if ok:
        if previous and previous != rid:
            (dest / 'releases' / '.previous').write_text(previous, encoding='utf-8')
        return {'active': rid, 'previous': previous, 'rolled_back': False}
    if not previous:
        raise ReleaseError(f'La release {rid} ne démarre pas et aucune release précédente n’existe')
    links.point(dest / 'current', 'releases/' + previous)
    try:
        restart()
        restored = healthy()
    except Exception:  # noqa: BLE001
        restored = False
    return {'active': previous, 'previous': previous, 'rolled_back': True, 'failed': rid, 'restored_healthy': restored}


def rollback(dest, restart, healthy, links: Links | None = None) -> dict:
    dest = Path(dest)
    previous = _previous_id(dest)
    if not previous or not (dest / 'releases' / previous).is_dir():
        raise ReleaseError('Aucune release précédente conservée')
    return activate(dest, previous, restart, healthy, links)


def prune(dest, links: Links | None = None, keep=KEEP) -> list[str]:
    """Supprime les releases les plus anciennes ; jamais current ni la précédente."""
    links = links or Links()
    dest = Path(dest)
    protected = {_current_id(dest, links), _previous_id(dest)}
    items = sorted((p for p in (dest / 'releases').iterdir() if p.is_dir() and not p.name.startswith('.')),
                   key=lambda p: p.name, reverse=True)
    removed = []
    for path in items[keep:]:
        if path.name not in protected:
            shutil.rmtree(path)
            removed.append(path.name)
    return removed


# --------------------------------------------------------------------------- VM
def systemd_restart(service='infraops'):
    subprocess.run(['systemctl', 'restart', service], check=True, timeout=60)


def http_healthy(url='http://127.0.0.1:8000/api/health', wait=45):
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        try:
            # URL de santé locale fixée par l'installateur (http://127.0.0.1:8000), jamais saisie.
            with urllib.request.urlopen(url, timeout=3) as response:  # nosec B310
                if response.status == 200 and json.loads(response.read(4096)).get('status') == 'ok':
                    return True
        except Exception:  # noqa: BLE001 — service encore en démarrage
            pass
        time.sleep(1.5)
    return False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = parser.add_subparsers(dest='command', required=True)
    v = sub.add_parser('verify')
    v.add_argument('src')
    v.add_argument('--archive')
    v.add_argument('--sha256')
    s = sub.add_parser('stage')
    s.add_argument('src')
    s.add_argument('dest')
    a = sub.add_parser('activate')
    a.add_argument('dest')
    a.add_argument('id')
    a.add_argument('--health-url', default='http://127.0.0.1:8000/api/health')
    r = sub.add_parser('rollback')
    r.add_argument('dest')
    r.add_argument('--health-url', default='http://127.0.0.1:8000/api/health')
    st = sub.add_parser('status')
    st.add_argument('dest')
    args = parser.parse_args(argv)
    try:
        if args.command == 'verify':
            result = verify(args.src, args.archive, args.sha256)
            print(f'Manifeste vérifié : {result["files"]} fichiers, empreinte {result["manifest_sha256"][:12]}')
        elif args.command == 'stage':
            print(stage(args.src, args.dest))
        elif args.command in ('activate', 'rollback'):
            health = lambda: http_healthy(args.health_url)  # noqa: E731
            result = (activate(args.dest, args.id, systemd_restart, health) if args.command == 'activate'
                      else rollback(args.dest, systemd_restart, health))
            print(json.dumps(result))
            if result.get('rolled_back'):
                print(f'ÉCHEC : la release {result["failed"]} ne répond pas ; retour à {result["active"]}.', file=sys.stderr)
                return 3
        elif args.command == 'status':
            links = Links()
            print(json.dumps({'current': _current_id(Path(args.dest), links), 'previous': _previous_id(Path(args.dest)),
                              'releases': sorted(p.name for p in (Path(args.dest) / 'releases').iterdir()
                                                 if p.is_dir() and not p.name.startswith('.'))}))
    except ReleaseError as exc:
        print('REFUS : ' + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
