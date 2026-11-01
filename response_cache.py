"""Cache des réponses lourdes (lot 7) : une construction partagée par les requêtes simultanées.

Mesuré sur un parc synthétique de 1 000 serveurs : /api/overview coûtait ~0,75 s de calcul
et ~0,6 s de sérialisation FastAPI (jsonable_encoder) ; huit clients simultanés attendaient
chacun leur propre calcul. Ici :

- clé = révision des données (lignes modifiées, révision des sources API, progression des
  collectes…) : toute écriture invalide immédiatement la réponse ;
- durée de vie courte (5 s par défaut) : les indicateurs « ancien / récent » calculés côté
  serveur ne peuvent pas dériver plus de 5 s (budget de fraîcheur : 900 s) ;
- une seule construction à la fois par route (les requêtes concurrentes attendent le résultat) ;
- sérialisation JSON directe, avec les mêmes conversions que FastAPI pour les dates.

Aucune donnée n'est servie au-delà de la durée de vie, et rien n'est persisté.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from datetime import date, datetime
from pathlib import PurePath

from starlette.requests import Request
from starlette.responses import Response

DEFAULT_TTL = 5.0


def _default(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, (set, frozenset, tuple)):
        return list(value)
    if isinstance(value, PurePath):
        return str(value)
    raise TypeError(f'Type non sérialisable : {type(value).__name__}')


def dumps(payload) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(',', ':'), allow_nan=False, default=_default).encode('utf-8')


class ResponseCache:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.entries = {}   # nom -> (clé, instant, octets)
        self.locks = {}
        self.guard = threading.Lock()
        self.stats = {}     # nom -> {'hits', 'builds', 'last_build_ms'}

    def _lock(self, name):
        with self.guard:
            return self.locks.setdefault(name, threading.Lock())

    def get_object(self, name, key, build, ttl=DEFAULT_TTL):
        """Comme get(), sans sérialisation : l'appelant ne doit pas modifier l'objet rendu."""
        return self._get(name, key, build, ttl, serialize=False)

    def get(self, name, key, build, ttl=DEFAULT_TTL) -> bytes:
        return self._get(name, key, build, ttl, serialize=True)

    def _get(self, name, key, build, ttl, serialize):
        stats = self.stats.setdefault(name, {'hits': 0, 'builds': 0, 'last_build_ms': None})
        entry = self.entries.get(name)
        if entry and entry[0] == key and self.clock() - entry[1] < ttl:
            stats['hits'] += 1
            return entry[2]
        with self._lock(name):
            entry = self.entries.get(name)   # une requête concurrente a pu construire entre-temps
            if entry and entry[0] == key and self.clock() - entry[1] < ttl:
                stats['hits'] += 1
                return entry[2]
            started = self.clock()
            body = dumps(build()) if serialize else build()
            self.entries[name] = (key, self.clock(), body)
            stats['builds'] += 1
            stats['last_build_ms'] = round((self.clock() - started) * 1000, 1)
            return body

    def invalidate(self, name=None):
        if name is None:
            self.entries.clear()
        else:
            self.entries.pop(name, None)


CACHE = ResponseCache()


# Horodatage de construction : seul champ qui change d'une construction à l'autre à données
# égales (relevé sur /api/alerts). Exclu de l'empreinte, renvoyé à part sur un 304.
GENERATED_AT = re.compile(rb'"generated_at":"([^"]{0,64})"')


def etag_of(body: bytes) -> str:
    return '"' + hashlib.blake2b(GENERATED_AT.sub(b'', body, count=1), digest_size=12).hexdigest() + '"'


def cached_json(name, revision, ttl=DEFAULT_TTL, cache=None):
    """Décorateur de route GET sans paramètre : réponse JSON mise en cache par révision.

    Réponse conditionnelle (audit UI du 31/10, performances) : l'ETag est l'empreinte du corps
    servi ; un client qui présente la même empreinte reçoit 304 sans corps. Les vues interrogées
    toutes les 5 à 10 s ne retéléchargent plus 75 à 140 Ko inchangés. `no-store` reste en place :
    le navigateur ne conserve rien, c'est la page qui garde sa dernière réponse.
    """
    def wrap(func):
        def route(request: Request = None):
            body = (cache or CACHE).get(name, revision(), func, ttl)
            etag = etag_of(body)
            if request is not None and etag in request.headers.get('if-none-match', ''):
                stamp = GENERATED_AT.search(body)
                extra = {'X-Generated-At': stamp.group(1).decode('ascii', 'replace')} if stamp else {}
                return Response(status_code=304, headers={'ETag': etag, **extra})
            return Response(body, media_type='application/json', headers={'ETag': etag})
        # Nom et documentation seulement : functools.wraps recopierait aussi les annotations
        # (vides) et __wrapped__, et FastAPI n'injecterait plus `request`.
        route.__name__, route.__qualname__, route.__doc__ = func.__name__, func.__qualname__, func.__doc__
        route.__module__ = func.__module__
        return route
    return wrap
