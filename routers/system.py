"""Réglages et diagnostic de l'instance : intervalle d'actualisation, rapport d'inventaire,
contexte SSH local (réservé à l'administrateur par access_policy, sans chemin complet)."""
import json
import os
import shutil
import stat
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict

from ssh import AUDIT_PATH

router = APIRouter()
context = None


class Monitoring(BaseModel):
    model_config = ConfigDict(extra='forbid')
    interval: int


@router.post('/api/monitoring')
def monitoring(settings: Monitoring):
    if settings.interval not in (0, 60, 300, 900):
        raise HTTPException(422, 'Intervalle autorisé : 0, 60, 300 ou 900 secondes')
    with context.lock:
        context.monitor.update(interval=settings.interval, next_at=time.time() + settings.interval if settings.interval else None)
    # Hors du verrou : le choix survit au redémarrage, quel que soit le mode de lancement.
    if context.write_setting('monitor_interval', settings.interval) is False:
        raise HTTPException(503, 'Intervalle appliqué mais non enregistré (base indisponible) : '
                                 'il sera perdu au redémarrage. Réessayer.')
    with context.lock:
        return dict(context.monitor)


@router.get('/api/inventory-report')
def inventory_report():
    try:
        return json.loads((context.BASE / 'inventory-report.json').read_text(encoding='utf-8'))
    except FileNotFoundError:
        # Un clone neuf n’a pas de rapprochement historique : ne pas inventer de compteurs.
        return {'available': False, 'policy': 'Rapport d’inventaire non généré sur cette installation.'}


def permissions(path, forbidden):
    """Droits d'un fichier local, lus sans rien modifier (audit UI du 31/10, fiche 16.2).

    `forbidden` : bits interdits (0o077 pour une clé privée, 0o022 pour une configuration).
    Sous Windows, les droits passent par des ACL que ce contrôle ne lit pas : il le dit.
    """
    try:
        target = Path(path).expanduser()
        if not target.is_file():
            return 'absent'
        if os.name == 'nt':
            return 'non vérifiés (ACL Windows)'
        return 'trop ouverts' if stat.S_IMODE(target.stat().st_mode) & forbidden else 'restreints'
    except OSError:
        return 'illisibles'


@router.get('/api/runtime')
def runtime():
    def present(path):
        try:
            return Path(path).expanduser().is_file()
        except OSError:
            return None
    cfg = context.cfg
    # Réservé au rôle admin (access_policy) et sans chemin complet ni compte local :
    # noms de fichiers et présence suffisent au diagnostic.
    return {'transport': cfg.transport, 'ssh_client_found': bool(shutil.which('ssh')), 'key_name': Path(cfg.key_path).name,
            'key_exists': present(cfg.key_path),
            'config_name': Path(cfg.config_path).name if cfg.config_path else 'config (par défaut)',
            'config_exists': present(cfg.config_path or str(Path.home() / '.ssh/config')),
            'known_hosts_exists': present(Path.home() / '.ssh/known_hosts'), 'audit_log_name': AUDIT_PATH.name,
            'key_permissions': permissions(cfg.key_path, 0o077),
            'config_permissions': permissions(cfg.config_path or str(Path.home() / '.ssh/config'), 0o022),
            'host_key_checking': 'StrictHostKeyChecking=yes (clé inconnue ou changée : refus, aucun contournement)',
            'workers': context.WORKERS,
            'hint': 'Configuration OpenSSH locale reprise, y compris ProxyJump. Les empreintes doivent être vérifiées manuellement.'}


def install(app, ctx):
    global context
    context = ctx
    app.include_router(router)
