"""Réaudit SSH périodique, en ROTATION, pour que les mesures restent à jour.

Jusqu'ici, la collecte automatique rafraîchissait le réseau, les API et Zabbix,
mais l'audit SSH (disques, services, partages, mémoire) restait manuel : une
fiche serveur affichait « Anciennes mesures » quelques minutes après un audit
et le restait indéfiniment. Constaté en exploitation (relevé du 25/09 encore
affiché le 26).

Pourquoi une rotation et pas « tout le parc toutes les N minutes » : un audit
complet ouvre une quinzaine de connexions SSH par serveur. Lancer 87 serveurs
d'un coup crée un pic sur le parc et sur le bastion ProxyJump, puis rien pendant
N minutes. Ici, chaque minute, on n'audite que les serveurs dont la mesure a
atteint l'intervalle choisi, les plus anciens d'abord, avec un quota qui étale
le parc entier sur l'intervalle : ~9 serveurs par minute pour 87 serveurs à
10 min.

Règles :
- Serveurs critiques (voie rapide) : au plus toutes les 5 min.
- Serveurs injoignables : au plus toutes les 30 min — chaque tentative coûte
  jusqu'à 34 s de délai, et 29 serveurs sans route ne doivent pas monopoliser
  les workers au détriment de ceux qui répondent.
- Jamais par-dessus un audit en cours (manuel ou non) : on attend le suivant.
- Désactivé par défaut (0) : c'est une charge sur l'infrastructure, qui se
  décide explicitement ; le choix est conservé entre deux démarrages.
"""
from __future__ import annotations

import math
import threading
import time
from datetime import datetime, timezone

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict

CHOICES = (0, 600, 1800, 3600)
TICK_SECONDS = 60
CRITICAL_MAX = 300
UNREACHABLE_MIN = 1800
SLACK = 30          # un audit « presque dû » part dans la même minute
SETTING = 'ssh_audit_interval'


def _instant(value):
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00')).timestamp()
    except (TypeError, ValueError):
        return None


def last_activity(row):
    """Dernière mesure OU dernière tentative : un échec récent compte aussi."""
    stamps = [_instant(row.get('collected_at')), _instant((row.get('last_attempt') or {}).get('collected_at'))]
    stamps = [s for s in stamps if s is not None]
    return max(stamps) if stamps else None


def due_hosts(rows, hosts, interval, now=None):
    """Serveurs à réauditer maintenant, dans l'ordre, quota appliqué. Pur."""
    if not interval:
        return []
    now = now or time.time()
    par_cle = {r['key']: r for r in rows}
    candidats = []
    for h in hosts:
        if not h.get('collect_enabled', True):
            continue
        row = par_cle.get(h['key'], {})
        cible = interval
        if h.get('criticality') == 'critical':
            cible = min(interval, CRITICAL_MAX)
        elif row.get('status') == 'unreachable':
            cible = max(interval, UNREACHABLE_MIN)
        vu = last_activity(row)
        age = math.inf if vu is None else now - vu
        if age >= cible - SLACK:
            candidats.append((h.get('criticality') != 'critical', -age, h['key'], h))
    candidats.sort(key=lambda c: c[:3])
    actifs = sum(1 for h in hosts if h.get('collect_enabled', True))
    quota = max(2, math.ceil(actifs * TICK_SECONDS / interval) + 1)
    return [c[3] for c in candidats[:quota]]


class Choice(BaseModel):
    model_config = ConfigDict(extra='forbid')
    interval: int


def install(app, context):
    from fastapi import APIRouter
    router = APIRouter()
    lock = threading.Lock()
    brut = context.read_setting(SETTING)
    try:
        initial = int(brut) if brut is not None else 0
    except ValueError:
        initial = 0
    state = {'interval': initial if initial in CHOICES else 0, 'next_at': 0.0, 'last_launch': None, 'last_count': 0}

    def tick(now=None):
        now = time.monotonic() if now is None else now
        with lock:
            if not state['interval'] or now < state['next_at']:
                return
            state['next_at'] = now + TICK_SECONDS
            interval = state['interval']
        with context.lock:
            if context.job['running']:
                return
        selection = due_hosts(context.rows(), context.HOSTS, interval)
        if not selection:
            return
        context.launch(selection, 'audit-periodique', 'rotation')
        with lock:
            state['last_launch'] = datetime.now(timezone.utc).isoformat()
            state['last_count'] = len(selection)

    def snapshot():
        with lock:
            return {k: state[k] for k in ('interval', 'last_launch', 'last_count')} | {'choices': list(CHOICES)}

    context.ssh_refresh_tick = tick
    context.ssh_refresh_state = snapshot

    @router.get('/api/ssh-refresh')
    def get_refresh():
        return snapshot()

    @router.post('/api/ssh-refresh')
    def set_refresh(choice: Choice):
        if choice.interval not in CHOICES:
            raise HTTPException(422, 'Intervalle autorisé : 0, 600, 1800 ou 3600 secondes')
        with lock:
            state['interval'] = choice.interval
            state['next_at'] = 0.0
        # Même contrat que /api/monitoring : un réglage non enregistré serait perdu au
        # redémarrage, la route ne doit pas répondre « OK » (OC-AUDIT-015).
        if context.write_setting(SETTING, choice.interval) is False:
            raise HTTPException(503, 'Intervalle appliqué mais non enregistré (base indisponible) : '
                                     'il sera perdu au redémarrage. Réessayer.')
        return snapshot()
    app.include_router(router)  # routes de ce module : APIRouter, inclus en fin d'installation
