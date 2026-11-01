"""Maintenance de la base d'OpsControl, SERVICE ARRÊTÉ.

    python3 deploy/maintenance.py vacuum --base /opt/infraops [--db BASE] [--dest SAUVEGARDES] [--confirm]

`vacuum` : en une fois, sur une base qui ne rétrécit jamais toute seule (auto_vacuum=0) :
1. prend le verrou d'instance (refus si OpsControl tourne ; OpsControl ne peut pas démarrer
   pendant l'opération) ;
2. sauvegarde l'état courant (étiquette « avant-vacuum ») ;
3. allège TOUS les anciens audits (la purge horaire le fait par lots de 5000) ;
4. active auto_vacuum=INCREMENTAL puis VACUUM : le fichier est réécrit compact ; ensuite,
   la purge horaire rend l'espace libéré au fil de l'eau (retention.reclaim) ;
5. contrôle d'intégrité.

Sans --confirm : mesure seulement (taille, audits à alléger, mode actuel).
Durée : quelques secondes à quelques dizaines de secondes pour ~100 Mo ; espace disque
temporaire nécessaire : environ deux fois la taille de la base.
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
import backup_state  # noqa: E402
import retention  # noqa: E402
from restore_state import InstanceLock, RestoreError  # noqa: E402


def size(db: Path) -> int:
    return sum(Path(str(db) + s).stat().st_size for s in ('', '-wal') if Path(str(db) + s).exists())


def measure(db: Path) -> dict:
    con = sqlite3.connect(f'file:{db.as_posix()}?mode=ro', uri=True)
    try:
        pending = con.execute(
            'SELECT count(*) FROM (SELECT payload, ROW_NUMBER() OVER (PARTITION BY key ORDER BY ts DESC) AS rang '
            "FROM audit_snapshots) WHERE rang > ? AND instr(payload, '\"_slim\"') = 0",
            (retention.FULL_SNAPSHOTS,)).fetchone()[0]
        mode = {0: 'NONE', 1: 'FULL', 2: 'INCREMENTAL'}.get(con.execute('PRAGMA auto_vacuum').fetchone()[0])
    finally:
        con.close()
    return {'bytes': size(db), 'snapshots_to_slim': pending, 'auto_vacuum': mode}


def vacuum(base: Path, db: Path, dest: Path | None = None, confirm: bool = False) -> dict:
    report = {'before': measure(db)}
    if not confirm:
        return report
    with InstanceLock(db):
        report['safety_backup'] = backup_state.backup(base, dest or base / 'backups', db, tag='avant-vacuum')['archive']
        con = sqlite3.connect(db, isolation_level=None, timeout=60)
        try:
            con.execute('BEGIN')
            report['slimmed'] = retention.slim_snapshots(con, limit=None)
            con.execute('COMMIT')
            con.execute('PRAGMA auto_vacuum=INCREMENTAL')
            con.execute('VACUUM')  # hors transaction ; réécrit le fichier et applique le mode
            con.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            verdict = con.execute('PRAGMA integrity_check').fetchone()[0]
        finally:
            con.close()
        if verdict != 'ok':
            raise RestoreError('Contrôle d’intégrité en échec après VACUUM : ' + str(verdict)[:200]
                               + ' — restaurer ' + report['safety_backup'])
    report['after'] = measure(db)
    return report


def main(argv=None) -> int:
    a = argparse.ArgumentParser(description='Maintenance de la base OpsControl (service arrêté).')
    sub = a.add_subparsers(dest='action', required=True)
    v = sub.add_parser('vacuum', help='alléger les anciens audits et compacter la base')
    v.add_argument('--base', type=Path, required=True)
    v.add_argument('--db', type=Path)
    v.add_argument('--dest', type=Path, help='dossier de la sauvegarde préalable (défaut : <base>/backups)')
    v.add_argument('--confirm', action='store_true', help='sans cette option : mesure seulement')
    args = a.parse_args(argv)
    base = args.base.resolve()
    db = args.db or base / 'data/state.sqlite3'
    try:
        r = vacuum(base, db, args.dest, args.confirm)
    except (RestoreError, backup_state.BackupError, OSError, sqlite3.Error) as exc:
        print(f'ÉCHEC : {exc}', file=sys.stderr)
        return 1
    b = r['before']
    print(f"Avant : {b['bytes'] / 1024 ** 2:.1f} Mo, {b['snapshots_to_slim']} audits à alléger, auto_vacuum={b['auto_vacuum']}")
    if 'after' not in r:
        print('Mesure seulement : ajouter --confirm, service arrêté.')
        return 0
    f = r['after']
    print(f"Après : {f['bytes'] / 1024 ** 2:.1f} Mo, {r['slimmed']} audits allégés, auto_vacuum={f['auto_vacuum']}")
    print('Sauvegarde préalable :', r['safety_backup'])
    return 0


if __name__ == '__main__':
    sys.exit(main())
