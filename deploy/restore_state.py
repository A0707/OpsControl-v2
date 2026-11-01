"""Vérification et restauration des sauvegardes d'OpsControl (deploy/backup_state.py).

    python3 deploy/restore_state.py verify ARCHIVE            # test de restauration, sans aucun effet
    python3 deploy/restore_state.py verify --latest DOSSIER   # la plus récente du dossier
    python3 deploy/restore_state.py verify --latest DOSSIER --record   # + résultat dans last-backup.json
    python3 deploy/restore_state.py apply ARCHIVE --base DIR [--db BASE] [--only-db] --confirm

`verify` : empreinte SHA-256 (fichier .sha256 voisin), extraction dans un dossier
temporaire, PRAGMA integrity_check et nombre de lignes par table. Rien n'est écrit
ailleurs que dans ce dossier temporaire. C'est le test de restauration mensuel.

`apply` : SERVICE ARRÊTÉ uniquement. Le verrou d'instance de la base (<base>.lock, le même
que celui de l'application) est pris pendant toute l'opération : si OpsControl tourne,
la restauration est refusée, et OpsControl ne peut pas démarrer pendant qu'elle se fait.
Avant d'écraser quoi que ce soit, l'état actuel est lui-même sauvegardé (étiquette
« avant-restauration »). Les fichiers -wal/-shm de l'ancienne base sont supprimés : rejoués
sur la base restaurée, ils la corrompraient. Sans --confirm : simple liste de ce qui serait fait.

Sur la VM, lancer sous le compte du service pour garder les bons propriétaires :
    sudo systemctl stop infraops
    sudo -u infraops /opt/infraops/current/.venv/bin/python /opt/infraops/current/deploy/restore_state.py \\
        apply /opt/infraops/backups/opscontrol-….tar.gz --base /opt/infraops --confirm
    sudo systemctl start infraops
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import sys
import tarfile
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import backup_state  # noqa: E402
from package_vm import restorable  # noqa: E402 — manifeste d'état commun (audit A1)

PREFIX = 'opscontrol/'
DB_MEMBER = PREFIX + 'data/state.sqlite3'


class RestoreError(RuntimeError):
    pass


def latest(folder: Path) -> Path:
    archives = sorted(p for p in Path(folder).glob(backup_state.PREFIX + '*.tar.gz') if backup_state.ARCHIVE.match(p.name))
    if not archives:
        raise RestoreError(f'Aucune archive dans {folder}')
    return max(archives, key=lambda p: backup_state.ARCHIVE.match(p.name).group(1, 2))


def check_digest(archive: Path) -> str:
    sidecar = archive.with_name(archive.name + '.sha256')
    if not sidecar.is_file():
        raise RestoreError(f'Empreinte absente : {sidecar.name}')
    expected = sidecar.read_text(encoding='utf-8').split()[0]
    actual = backup_state.sha256(archive)
    if actual != expected:
        raise RestoreError('Empreinte SHA-256 différente : archive altérée ou incomplète')
    return actual


def extract(archive: Path, target: Path) -> list[str]:
    """Extrait les seuls membres attendus (fichiers réguliers sous opscontrol/, sans « .. »)."""
    names = []
    with tarfile.open(archive, 'r:gz') as tar:
        for member in tar.getmembers():
            rel = member.name
            if (not member.isfile() or not rel.startswith(PREFIX) or rel.startswith('/')
                    or '..' in Path(rel).parts or '\\' in rel):
                raise RestoreError(f'Membre inattendu dans l’archive : {rel!r}')
            if not restorable(rel[len(PREFIX):]):
                # Seul l'état du manifeste est restauré : jamais de code ni de fichier système.
                raise RestoreError(f'Fichier hors du manifeste d’état : {rel!r}')
            dest = target / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(member) as source, open(dest, 'wb') as out:
                shutil.copyfileobj(source, out)
            names.append(rel[len(PREFIX):])
    if 'data/state.sqlite3' not in names:
        raise RestoreError('Base absente de l’archive')
    return names


def inspect_db(path: Path) -> dict:
    db = sqlite3.connect(f'file:{path.as_posix()}?mode=ro', uri=True)
    try:
        verdict = db.execute('PRAGMA integrity_check').fetchone()[0]
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        counts = {t: db.execute(f'SELECT count(*) FROM "{t}"').fetchone()[0] for t in tables}
        recorded = ({r[0] for r in db.execute('SELECT name FROM schema_migrations')}
                    if 'schema_migrations' in tables else set())
    finally:
        db.close()
    if verdict != 'ok':
        raise RestoreError('Contrôle d’intégrité en échec : ' + str(verdict)[:200])
    newer = sorted(n for n in recorded if n.startswith('core_') and n not in known_core_migrations())
    if newer:
        # Sauvegarde d'une version plus récente : ce code ne connaît pas son schéma (audit DB-04).
        raise RestoreError('Sauvegarde issue d’une version plus récente d’OpsControl (' + ', '.join(newer) + ') : '
                           'déployer d’abord cette version, puis restaurer.')
    return counts


def known_core_migrations() -> set:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    import migrations
    return {name for name, _ in migrations.MIGRATIONS}


def record_test(folder: Path, archive: Path | None, error: Exception | None = None) -> None:
    """Ajoute le résultat du test à last-backup.json : Zabbix alerte sur restore_test_ok
    sans attendre que l'âge de la dernière sauvegarde réussie dépasse le seuil (OC-AUD-014).
    Les champs de la sauvegarde elle-même sont conservés tels quels."""
    try:
        status = json.loads((Path(folder) / backup_state.STATUS).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        status = {}
    status.update({'restore_test_ok': error is None, 'restore_test_epoch': int(time.time()),
                   'restore_test_archive': archive.name if archive else None,
                   'restore_test_error': f'{type(error).__name__}: {error}'[:500] if error else None})
    backup_state.write_json(Path(folder), status)


def verify(archive: Path) -> dict:
    archive = Path(archive)
    digest = check_digest(archive)
    with tempfile.TemporaryDirectory() as tmp:
        names = extract(archive, Path(tmp))
        counts = inspect_db(Path(tmp) / PREFIX / 'data/state.sqlite3')
    return {'archive': archive.name, 'sha256': digest, 'files': names, 'tables': counts}


class InstanceLock:
    """Même verrou que self_monitor.acquire_instance_lock (fichier <base>.lock)."""

    def __init__(self, db: Path):
        self.path, self.handle = str(db) + '.lock', None

    def __enter__(self):
        # Reprise sur machine vierge : data/ n'existe pas encore, le verrou ne pouvait pas
        # être créé et la restauration échouait avant d'avoir rien écrit (audit A1, 15/10).
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.handle = open(self.path, 'a+')
        try:
            if os.name == 'nt':
                import msvcrt
                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.handle.close()
            raise RestoreError('OpsControl utilise cette base : arrêter le service avant de restaurer') from None
        return self

    def __exit__(self, *exc):
        try:
            if os.name == 'nt':
                import msvcrt
                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        self.handle.close()


def replace_file(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name('.' + target.name + '.restauration')
    shutil.copyfile(source, tmp)
    os.replace(tmp, target)


def apply(archive: Path, base: Path, db: Path, only_db: bool = False, confirm: bool = False,
          dest: Path | None = None) -> dict:
    report = verify(archive)
    restored = ['data/state.sqlite3'] if only_db else report['files']
    plan = {'archive': report['archive'], 'restore': restored, 'tables': report['tables'], 'applied': False}
    if not confirm:
        return plan
    with InstanceLock(db):
        if db.is_file():
            safety = backup_state.backup(base, Path(dest or Path(archive).parent), db, tag='avant-restauration')
            plan['safety_backup'] = safety['archive']
        with tempfile.TemporaryDirectory() as tmp:
            extract(Path(archive), Path(tmp))
            root = Path(tmp) / PREFIX
            for suffix in ('-wal', '-shm'):
                Path(str(db) + suffix).unlink(missing_ok=True)
            replace_file(root / 'data/state.sqlite3', db)
            for rel in restored:
                if rel != 'data/state.sqlite3':
                    replace_file(root / rel, base / rel)
    plan['applied'] = True
    return plan


def main(argv=None) -> int:
    a = argparse.ArgumentParser(description='Vérification et restauration des sauvegardes OpsControl.')
    sub = a.add_subparsers(dest='action', required=True)
    v = sub.add_parser('verify', help='test de restauration, sans effet')
    v.add_argument('archive', nargs='?', type=Path)
    v.add_argument('--latest', type=Path, metavar='DOSSIER')
    v.add_argument('--record', action='store_true', help='écrire le résultat dans DOSSIER/last-backup.json (avec --latest)')
    p = sub.add_parser('apply', help='restauration, service arrêté')
    p.add_argument('archive', type=Path)
    p.add_argument('--base', type=Path, required=True, help='dossier contenant hosts.yaml et data/')
    p.add_argument('--db', type=Path, help='défaut : <base>/data/state.sqlite3')
    p.add_argument('--only-db', action='store_true', help='restaurer la base seule, pas la configuration')
    p.add_argument('--dest', type=Path, help='où écrire la sauvegarde « avant-restauration » (défaut : dossier de l’archive)')
    p.add_argument('--confirm', action='store_true', help='sans cette option : liste seulement ce qui serait fait')
    args = a.parse_args(argv)
    try:
        if args.action == 'verify':
            if args.record and not args.latest:
                a.error('--record exige --latest DOSSIER')
            archive = None
            try:
                archive = latest(args.latest) if args.latest else args.archive
                if archive is None:
                    a.error('indiquer une archive ou --latest DOSSIER')
                r = verify(archive)
            except (RestoreError, backup_state.BackupError, OSError, sqlite3.Error, tarfile.TarError) as exc:
                if args.record:
                    record_test(args.latest, archive, exc)
                raise
            if args.record:
                record_test(args.latest, archive)
            print(f'OK : {r["archive"]} — empreinte vérifiée, intégrité ok, {len(r["files"])} fichiers')
            for table, n in r['tables'].items():
                print(f'  {table:<22} {n:>8} lignes')
            return 0
        base = args.base.resolve()
        r = apply(args.archive, base, args.db or base / 'data/state.sqlite3', args.only_db, args.confirm, args.dest)
        verbe = 'Restauré' if r['applied'] else 'Serait restauré (ajouter --confirm)'
        print(f'{verbe} depuis {r["archive"]} : ' + ', '.join(r['restore']))
        if r.get('safety_backup'):
            print('État précédent sauvegardé :', r['safety_backup'])
        return 0
    except (RestoreError, backup_state.BackupError, OSError, sqlite3.Error, tarfile.TarError) as exc:
        print(f'ÉCHEC : {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
