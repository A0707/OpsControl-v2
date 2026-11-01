"""Sauvegarde locale d'OpsControl : base SQLite et configuration, sans aucun secret.

    python deploy/backup_state.py                                  # PC : dossier du projet -> backups/
    python3 deploy/backup_state.py --base /opt/infraops --dest /opt/infraops/backups    # VM (timer systemd)
    python deploy/backup_state.py --base ..\\opscontrol-legacy --dest D:\\Sauvegardes\\infraops   # autre instance
    python3 deploy/backup_state.py ... --tag pre-<release>         # avant bascule (install-vm.sh)

Ce que l'archive CONTIENT : copie cohérente à chaud de la base (API de sauvegarde
SQLite, contrôlée par PRAGMA integrity_check), hosts.yaml et le manifeste d'état commun
(package_vm.DATA_FILES) : connexions API, empreintes SSH acceptées, liaisons des jetons,
certificat Proxmox et certificats publics de data/ca/.

Ce qu'elle ne contient JAMAIS : jetons API, secrets.env, coffre DPAPI, clés privées.
Les fichiers de configuration passent par le même filtre que package_vm.py : un
contenu ressemblant à un secret fait échouer la sauvegarde, rien n'est écrit.

Ce script ne copie RIEN hors de la machine et ne chiffre pas : la copie externe
(stockage de sauvegarde, partage distinct, immuable si possible) reste à brancher
sur le dossier --dest. Sans elle, la sauvegarde ne protège ni d'une perte du disque
ni d'un rançongiciel.

Rotation des sauvegardes ordinaires : la plus récente de chacun des 7 derniers jours,
de chacune des 4 dernières semaines et de chacun des 3 derniers mois. Les sauvegardes
étiquetées (--tag) sont gardées à part : les 5 plus récentes.

État : <dest>/last-backup.json, réécrit à chaque passage. `last_success_epoch` n'avance
qu'en cas de succès : c'est lui que surveille Zabbix (deploy/zabbix-template-opscontrol.yaml).
Le test de restauration qui suit (restore_state.py verify --record) y ajoute restore_test_*.
Code de sortie : 0 succès, 1 échec.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
# Même filtre de secrets et même manifeste d'état que l'archive de migration (audit A1).
from package_vm import DATA_FILES, SECRETS, state_files  # noqa: E402

BASE = Path(__file__).resolve().parent.parent
CONFIG_FILES = ['hosts.yaml', *DATA_FILES]
PREFIX = 'opscontrol-'
STATUS = 'last-backup.json'
TAG = re.compile(r'^[A-Za-z0-9._-]{1,40}$')
ARCHIVE = re.compile(r'^opscontrol-(\d{8})-(\d{6})(?:-([A-Za-z0-9._-]+))?\.tar\.gz$')
KEEP_DAILY, KEEP_WEEKLY, KEEP_MONTHLY, KEEP_TAGGED = 7, 4, 3, 5


class BackupError(RuntimeError):
    pass


def copy_database(source: Path, target: Path) -> None:
    """Copie cohérente même pendant une collecte, puis contrôle d'intégrité de la COPIE."""
    if not source.is_file():
        raise BackupError(f'Base absente : {source.name}')
    src = sqlite3.connect(f'file:{source.as_posix()}?mode=ro', uri=True, timeout=60)
    dst = sqlite3.connect(target)
    try:
        with dst:
            src.backup(dst)
        verdict = dst.execute('PRAGMA integrity_check').fetchone()[0]
    finally:
        src.close()
        dst.close()
    if verdict != 'ok':
        raise BackupError('Contrôle d’intégrité de la copie en échec : ' + str(verdict)[:200])


def check_no_secret(base: Path, files: list[str]) -> None:
    refus = [rel for rel in files if SECRETS.search((base / rel).read_text(encoding='utf-8', errors='replace'))]
    connexions = base / 'data/api-connections.json'
    if connexions.is_file():
        for c in json.loads(connexions.read_text(encoding='utf-8-sig')):
            for champ in ('token', 'password', 'secret', 'auth'):
                if isinstance(c, dict) and c.get(champ):
                    refus.append(f'data/api-connections.json (champ « {champ} »)')
    if refus:
        raise BackupError('Contenu ressemblant à un secret, sauvegarde refusée : ' + ', '.join(refus))


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for bloc in iter(lambda: f.read(1 << 20), b''):
            h.update(bloc)
    return h.hexdigest()


def keep_set(names: list[str]) -> set[str]:
    """Noms d'archives à conserver (voir la politique en tête de module)."""
    ordinary, tagged = [], []
    for name in names:
        m = ARCHIVE.match(name)
        if not m:
            continue
        stamp = datetime.strptime(m.group(1) + m.group(2), '%Y%m%d%H%M%S')
        (tagged if m.group(3) else ordinary).append((stamp, name))
    keep = {name for _, name in sorted(tagged, reverse=True)[:KEEP_TAGGED]}
    for period, limit in ((lambda d: d.date(), KEEP_DAILY),
                          (lambda d: d.isocalendar()[:2], KEEP_WEEKLY),
                          (lambda d: (d.year, d.month), KEEP_MONTHLY)):
        seen = []
        for stamp, name in sorted(ordinary, reverse=True):
            key = period(stamp)
            if key not in seen:
                seen.append(key)
                if len(seen) > limit:
                    break
                keep.add(name)
    return keep


def rotate(dest: Path) -> list[str]:
    names = [p.name for p in dest.glob(PREFIX + '*.tar.gz')]
    keep = keep_set(names)
    removed = []
    for name in names:
        if ARCHIVE.match(name) and name not in keep:
            for path in (dest / name, dest / (name + '.sha256')):
                path.unlink(missing_ok=True)
            removed.append(name)
    return sorted(removed)


def write_status(dest: Path, status: dict) -> None:
    previous = {}
    try:
        previous = json.loads((dest / STATUS).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        pass
    if not status['ok']:
        status['last_success_epoch'] = previous.get('last_success_epoch')
        status['last_success_archive'] = previous.get('last_success_archive')
    write_json(dest, status)


def write_json(dest: Path, status: dict) -> None:
    """Remplacement atomique de last-backup.json (aussi utilisé par restore_state verify --record)."""
    tmp = dest / (STATUS + '.tmp')
    tmp.write_text(json.dumps(status, indent=1, ensure_ascii=False), encoding='utf-8')
    # Lisible par l'agent Zabbix (droit de traversée seul sur le dossier) ; les archives,
    # elles, suivent l'UMask 0027 du service et restent réservées au compte infraops.
    os.chmod(tmp, 0o644)
    os.replace(tmp, dest / STATUS)


def backup(base: Path, dest: Path, db: Path, tag: str | None = None, now: datetime | None = None) -> dict:
    """Écrit une archive dans `dest` et renvoie son état. Lève BackupError sans rien laisser derrière."""
    if tag is not None and not TAG.match(tag):
        raise BackupError('Étiquette invalide : lettres, chiffres, . _ - (40 caractères au plus)')
    now = now or datetime.now()
    dest.mkdir(parents=True, exist_ok=True)
    files = (['hosts.yaml'] if (base / 'hosts.yaml').is_file() else []) + state_files(base)
    missing = [rel for rel in CONFIG_FILES if rel not in files]
    check_no_secret(base, files)
    name = f'{PREFIX}{now:%Y%m%d-%H%M%S}' + (f'-{tag}' if tag else '') + '.tar.gz'
    final = dest / name
    with tempfile.TemporaryDirectory(dir=dest) as tmp:
        copy = Path(tmp) / 'state.sqlite3'
        copy_database(db, copy)
        partial = Path(tmp) / name
        with tarfile.open(partial, 'w:gz') as archive:
            archive.add(copy, 'opscontrol/data/state.sqlite3')
            for rel in files:
                archive.add(base / rel, 'opscontrol/' + rel)
        digest = sha256(partial)
        os.replace(partial, final)  # même système de fichiers : bascule atomique
    (dest / (name + '.sha256')).write_text(f'{digest}  {name}\n', encoding='utf-8')
    return {'ok': True, 'at': datetime.now(timezone.utc).isoformat(), 'archive': name, 'bytes': final.stat().st_size,
            'sha256': digest, 'db_integrity': 'ok', 'files': ['data/state.sqlite3'] + files, 'missing': missing,
            'last_success_epoch': int(time.time()), 'last_success_archive': name}


def main(argv=None) -> int:
    a = argparse.ArgumentParser(description='Sauvegarde locale d’OpsControl (base + configuration, sans secret).')
    a.add_argument('--base', type=Path, help='Dossier contenant hosts.yaml et data/ (défaut : ce projet)')
    a.add_argument('--db', type=Path, help='Base SQLite (défaut : COCKPIT_DB sans --base, sinon <base>/data/state.sqlite3)')
    a.add_argument('--dest', type=Path, help='Dossier des archives (défaut : <base>/backups)')
    a.add_argument('--tag', help='Étiquette, ex. pre-20261005-120000 ; conservée hors rotation ordinaire')
    args = a.parse_args(argv)
    base = (args.base or BASE).resolve()
    db = args.db or (Path(os.environ['COCKPIT_DB']) if not args.base and os.environ.get('COCKPIT_DB')
                     else base / 'data/state.sqlite3')
    dest = (args.dest or base / 'backups').resolve()
    try:
        status = backup(base, dest, db, args.tag)
        status['removed'] = rotate(dest)
        write_status(dest, status)
    except (BackupError, OSError, sqlite3.Error, tarfile.TarError, ValueError) as exc:
        try:
            dest.mkdir(parents=True, exist_ok=True)
            write_status(dest, {'ok': False, 'at': datetime.now(timezone.utc).isoformat(),
                                'error': f'{type(exc).__name__}: {exc}'[:500]})
        except OSError:
            pass
        print(f'ÉCHEC de la sauvegarde : {type(exc).__name__}: {exc}', file=sys.stderr)
        return 1
    print(f'Sauvegarde : {dest / status["archive"]} ({status["bytes"] / 1024 ** 2:.1f} Mo, '
          f'intégrité ok, {len(status["files"])} fichiers)')
    if status['missing']:
        print('Absents (ignorés) :', ', '.join(status['missing']))
    if status['removed']:
        print('Rotation, supprimées :', ', '.join(status['removed']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
