"""Identité de l'opérateur : confiance au seul reverse proxy, jamais au navigateur.

Deux modes, toujours affichés tels quels :
- « proxy » : nginx a authentifié l'opérateur (oauth2-proxy) et transmet
  X-OpsControl-User ACCOMPAGNÉ du secret partagé X-OpsControl-Proxy, égal à
  INFRAOPS_TRUSTED_PROXY_SECRET. nginx remplace ces en-têtes : un navigateur ne
  peut ni les forger ni les ajouter.
- « local » : accès direct à uvicorn (poste Windows, tunnel SSH) ou secret absent
  ou incorrect. L'en-tête d'identité éventuel est IGNORÉ ; le nom saisi reste
  déclaratif et marqué « non authentifié ».

Le secret n'est jamais renvoyé, journalisé ni comparé autrement qu'en temps constant.
"""
from __future__ import annotations

import hmac
import os
import re

from fastapi import Request  # module : résolution des annotations différées par FastAPI

USER_HEADER = 'x-opscontrol-user'
PROXY_HEADER = 'x-opscontrol-proxy'
SECRET_ENV = 'INFRAOPS_TRUSTED_PROXY_SECRET'
# Nom par défaut du poste (mode local) : évite de ressaisir le même nom à chaque action.
# Il reste déclaratif : rien ne prouve qui est devant le poste.
LOCAL_NAME_ENV = 'INFRAOPS_LOCAL_OPERATOR'
VALID_LOCAL_NAME = re.compile(r'^[\w .@+-]{1,60}$')
MIN_SECRET_LENGTH = 32
# Adresse e-mail ou identifiant d'annuaire : lettres, chiffres, . _ @ + - (sans espace ni contrôle).
VALID_USER = re.compile(r'^[\w.@+-]{1,120}$')


def _secret() -> str | None:
    value = os.environ.get(SECRET_ENV, '')
    return value if len(value) >= MIN_SECRET_LENGTH else None


def local_default() -> str | None:
    """Nom déclaratif par défaut du poste, ou None s'il est absent ou invalide."""
    value = os.environ.get(LOCAL_NAME_ENV, '').strip()
    return value if VALID_LOCAL_NAME.match(value) else None


def resolve(headers) -> dict:
    """Identité effective d'une requête. `headers` : mapping insensible à la casse (Starlette)."""
    secret = _secret()
    presented = headers.get(PROXY_HEADER) or ''
    user = (headers.get(USER_HEADER) or '').strip()
    trusted = bool(secret) and bool(presented) and hmac.compare_digest(presented.encode(), secret.encode())
    if trusted and VALID_USER.match(user):
        return {'mode': 'proxy', 'authenticated': True, 'user': user,
                'label': user, 'detail': 'Identité transmise par le reverse proxy authentifié.'}
    reason = ('Accès direct au service : identité non vérifiée.' if not presented else
              'Secret du reverse proxy incorrect : en-tête d’identité ignoré.' if not trusted else
              'Identité transmise invalide ou vide.')
    return {'mode': 'local', 'authenticated': False, 'user': None, 'label': 'Session locale · non authentifiée',
            'detail': reason + ' Les noms saisis sont déclaratifs.',
            'ignored_identity_header': bool(user), 'proxy_trusted': trusted}


def actor(headers, declared: str | None) -> tuple[str, str]:
    """(auteur, mode) pour une action locale (prise en charge d'alerte…).

    En mode proxy, l'identité authentifiée remplace tout nom saisi. En mode local,
    le nom saisi est conservé tel quel et marqué comme déclaratif.
    """
    identity = resolve(headers)
    if identity['authenticated']:
        return identity['user'], 'proxy'
    name = (declared or '').strip() or local_default() or ''
    return name, 'local'


def install(app):
    from fastapi import APIRouter
    router = APIRouter()
    @router.get('/api/whoami')
    def whoami(request: Request):
        import access_policy  # rôle effectif et droits ; jamais le secret
        return access_policy.describe(request.headers)
    app.include_router(router)  # routes de ce module : APIRouter, inclus en fin d'installation
