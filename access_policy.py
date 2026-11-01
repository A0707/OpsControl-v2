"""Politique d'accès centralisée : authentification, rôles, CSRF, quotas, audit des mutations.

Rôles (cumulatifs) :
    viewer    lecture seule ;
    operator  collectes et workflow incidents / alertes ;
    admin     inventaire, connexions API, réglages, suppressions.

Identité (operator_identity.py) :
- derrière le reverse proxy, l'identité n'est acceptée qu'avec le secret partagé
  INFRAOPS_TRUSTED_PROXY_SECRET. Rôle : INFRAOPS_ADMINS / INFRAOPS_OPERATORS
  (listes séparées par des virgules), sinon INFRAOPS_DEFAULT_ROLE (viewer par défaut) ;
- en accès direct à uvicorn (« local ») :
    * secret proxy CONFIGURÉ (VM) : toute requête /api/* est refusée (401), sauf
      INFRAOPS_LOCAL_ROLE explicitement défini (dépannage par tunnel SSH) ;
    * secret proxy ABSENT (poste Windows) : rôle INFRAOPS_LOCAL_ROLE, « admin » par
      défaut pour préserver l'usage local historique — toujours affiché comme
      « non authentifié » ; « off » interdit toute mutation locale.

Toute route POST non classée exige « admin » : un nouvel endpoint est fermé par défaut.
"""
from __future__ import annotations

import logging
import os
import re
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone

from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse

import http_metrics
import logging_setup
import operator_identity

ROLES = ('viewer', 'operator', 'admin')
RANK = {r: i for i, r in enumerate(ROLES)}
PUBLIC_API = ('/api/health', '/health/live', '/health/ready')
WEBHOOKS = ('/api/webhooks/zabbix',)  # authentifiés par leur propre jeton (tier0.py)
AUDIT_RETENTION_DAYS = 90
log = logging.getLogger('opscontrol.access')
http_log = logging.getLogger('opscontrol.http')

# (expression du chemin, rôle requis, groupe de quota). Évaluées dans l'ordre.
POST_RULES = [
    (r'/api/itsm/(take|preview|create|reconcile)', 'admin', 'mutation'),
    (r'/api/ai/chat', 'viewer', 'ai'),
    (r'/api/ai/history/clear', 'viewer', 'mutation'),
    (r'/api/(refresh|sync|daily/refresh|batches/refresh|network/refresh|availability/refresh)', 'operator', 'collect_all'),
    (r'/api/hosts/[^/]+/refresh|/api/network/hosts/[^/]+/refresh|/api/connections/[^/]+/collect', 'operator', 'collect_one'),
    (r'/api/incidents/sync', 'operator', 'collect_one'),
    (r'/api/alerts/(ack|unack)|/api/incidents/(ack|investigate|suppress|reactivate|maintenance(/delete)?)', 'operator', 'mutation'),
    (r'/api/waf/commands', 'operator', 'mutation'),  # plan de commandes texte, rien n'est exécuté
    (r'/api/connections/certificate', 'admin', 'probe'),
    # Accès SSH (host_access.py) : test en lecture (opérateur) ; empreintes et modification
    # groupée de l'inventaire (administrateur). La capture d'empreintes ouvre des connexions SSH.
    (r'/api/hosts/[^/]+/test', 'operator', 'collect_one'),
    (r'/api/hosts/test-params', 'operator', 'collect_one'),
    (r'/api/ssh/host-keys/scan', 'admin', 'probe'),
    # Découverte réseau : balayage actif d'une plage (une fois par minute au plus), puis ajout.
    (r'/api/discovery/scan', 'admin', 'collect_all'),
    (r'/api/discovery/add', 'admin', 'mutation'),
    (r'/api/ssh/host-keys/accept|/api/manage/hosts/bulk', 'admin', 'mutation'),
    (r'/api/manage/hosts(/[^/]+/delete)?|/api/connections(/[^/]+/delete)?|/api/inventory/apply', 'admin', 'mutation'),
    (r'/api/monitoring|/api/ssh-refresh', 'admin', 'mutation'),
    # Sécurité & CVE (security_cve.py) : relevés SSH en lecture et veille publique (collectes),
    # workflow des vulnérabilités (opérateur) ; réglages des automatismes (administrateur).
    (r'/api/security/(scan|sync)', 'operator', 'collect_all'),
    (r'/api/security/hosts/[^/]+/scan', 'operator', 'collect_one'),
    (r'/api/security/vulns/action|/api/security/notifications/read|/api/security/matches/decide', 'operator', 'mutation'),
    (r'/api/security/mail/test', 'admin', 'probe'),  # message de test aux destinataires configurés
    (r'/api/security/settings', 'admin', 'mutation'),
]
# Lectures sensibles : contexte local du poste (comptes, chemins).
GET_RULES = [(r'/api/runtime', 'admin'), (r'/api/admin/.*', 'admin'),
             (r'/api/manage/.*', 'admin')]  # paramètres d'accès et chemins réservés à la configuration
# Quotas : (nombre, fenêtre en secondes, portée). « global » = un seul compteur pour tous.
LIMITS = {'ai': (6, 60, 'actor'), 'collect_all': (1, 60, 'global'), 'collect_one': (10, 60, 'actor'), 'probe': (5, 60, 'actor'),
          'mutation': (60, 60, 'actor')}


def _list(name):
    return {x.strip().lower() for x in os.environ.get(name, '').split(',') if x.strip()}


def _role(value, default):
    value = (value or '').strip().lower()
    return value if value in ROLES or value == 'off' else default


def classify(method, path):
    """(rôle requis, groupe de quota) ; (None, None) pour une lecture publique ou libre."""
    if path in PUBLIC_API or path in WEBHOOKS:
        return None, None
    if method in ('GET', 'HEAD', 'OPTIONS'):
        for pattern, role in GET_RULES:
            if re.fullmatch(pattern, path):
                return role, None
        return 'viewer' if path.startswith('/api/') else None, None
    for pattern, role, group in POST_RULES:
        if re.fullmatch(pattern, path):
            return role, group
    return 'admin', 'mutation'  # fermé par défaut


def proxy_required() -> bool:
    """INFRAOPS_REQUIRE_PROXY=1 (unité systemd de la VM) : le reverse proxy authentifié est
    obligatoire. Sans cette déclaration, un secret effacé ou trop court faisait basculer
    silencieusement la VM en « local admin » pour tout utilisateur du proxy (audit SEC-01)."""
    return os.environ.get('INFRAOPS_REQUIRE_PROXY', '').strip().lower() in ('1', 'true', 'yes', 'oui')


def check_proxy_configuration():
    """Refus de démarrer plutôt qu'une ouverture silencieuse : l'erreur est lisible dans
    journalctl et la supervision d'OpsControl voit le service arrêté."""
    if proxy_required() and not operator_identity._secret():
        raise RuntimeError(f'INFRAOPS_REQUIRE_PROXY est actif mais {operator_identity.SECRET_ENV} est absent '
                           f'ou fait moins de {operator_identity.MIN_SECRET_LENGTH} caractères : démarrage refusé. '
                           'Corriger /etc/infraops/secrets.env (deploy/secrets_env.py).')


def principal(headers) -> dict:
    """Identité + rôle effectif de la requête. Ne contient jamais le secret."""
    identity = operator_identity.resolve(headers)
    proxy_configured = bool(operator_identity._secret())
    if identity['authenticated']:
        user = identity['user'].lower()
        role = 'admin' if user in _list('INFRAOPS_ADMINS') else 'operator' if user in _list('INFRAOPS_OPERATORS') \
            else _role(os.environ.get('INFRAOPS_DEFAULT_ROLE'), 'viewer')
        return {**identity, 'role': role, 'proxy_configured': proxy_configured, 'blocked': False}
    if identity.get('proxy_trusted'):
        # Le proxy authentifié a bien parlé, mais l'utilisateur transmis est invalide :
        # ne jamais retomber sur le rôle local de dépannage (audit SEC-10).
        return {**identity, 'role': 'off', 'proxy_configured': True, 'blocked': True,
                'detail': 'Identité transmise par le reverse proxy invalide : accès refusé.'}
    if proxy_required() and not proxy_configured:
        # Garde-fou si le contrôle de démarrage a été contourné (rechargement de l'environnement).
        return {**identity, 'role': 'off', 'proxy_configured': False, 'blocked': True,
                'detail': 'Secret du reverse proxy absent ou trop court : accès refusé.'}
    explicit = os.environ.get('INFRAOPS_LOCAL_ROLE')
    if proxy_configured and not explicit:
        return {**identity, 'role': 'off', 'proxy_configured': True, 'blocked': True,
                'detail': 'Accès direct refusé : OpsControl n’est accessible que par le reverse proxy authentifié.'}
    role = _role(explicit, 'admin')
    # « off » : lecture seule, toute mutation locale refusée (message dédié dans la garde).
    return {**identity, 'role': 'viewer' if role == 'off' else role, 'local_off': role == 'off',
            'proxy_configured': proxy_configured, 'blocked': False}


def allowed(role, required):
    return required is None or (role in RANK and RANK[role] >= RANK[required])


class RateLimiter:
    def __init__(self, limits=LIMITS, clock=time.monotonic):
        self.limits, self.clock, self.lock, self.hits = limits, clock, threading.Lock(), {}

    def check(self, group, actor):
        """None si autorisé, sinon nombre de secondes avant nouvel essai."""
        if group not in self.limits:
            return None
        count, window, scope = self.limits[group]
        key = (group, 'global' if scope == 'global' else actor)
        now = self.clock()
        with self.lock:
            q = self.hits.setdefault(key, deque())
            while q and now - q[0] >= window:
                q.popleft()
            if len(q) >= count:
                return max(1, int(window - (now - q[0])) + 1)
            q.append(now)
        return None


def migrate(db):
    db.execute('CREATE TABLE IF NOT EXISTS schema_migrations(name TEXT PRIMARY KEY, applied_at TEXT)')
    if db.execute("SELECT 1 FROM schema_migrations WHERE name='access_v1'").fetchone():
        return False
    db.execute('''CREATE TABLE IF NOT EXISTS mutation_audit(
        seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, request_id TEXT NOT NULL, actor TEXT,
        mode TEXT NOT NULL, role TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL, status INTEGER NOT NULL,
        outcome TEXT NOT NULL, duration_ms INTEGER, client TEXT)''')
    db.execute('CREATE INDEX IF NOT EXISTS mutation_audit_ts ON mutation_audit(ts)')
    db.execute("INSERT INTO schema_migrations(name, applied_at) VALUES('access_v1', ?)", (datetime.now(timezone.utc).isoformat(),))
    return True


# Requête d'un fichier versionné par deploy/assets_version.py : seul paramètre v=<8 hex>.
VERSIONED = re.compile(r'v=[0-9a-f]{8}')

SECURITY_HEADERS = {
    'Content-Security-Policy': "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
                               "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
}
REQUEST_ID = re.compile(r'^[A-Za-z0-9._-]{8,64}$')


def install(app, connect=None, limiter=None, migrate_schema=True):
    """Remplace l'ancienne garde d'app.py. `connect` : fabrique de connexion SQLite (audit)."""
    check_proxy_configuration()
    from fastapi import APIRouter
    router = APIRouter()
    from fastapi import Request
    limiter = limiter or RateLimiter()
    # migrate_schema=False : une autre instance tient le verrou, aucun DDL ici (OC-AUDIT-014).
    if connect is not None and migrate_schema:
        with connect() as db:
            migrate(db)
    purge = {'at': 0.0}

    def audit(entry):
        if connect is None:
            return
        try:
            with connect() as db:
                db.execute('INSERT INTO mutation_audit(ts, request_id, actor, mode, role, method, path, status, outcome, '
                           'duration_ms, client) VALUES(:ts,:request_id,:actor,:mode,:role,:method,:path,:status,:outcome,'
                           ':duration_ms,:client)', entry)
                if time.monotonic() - purge['at'] > 3600:
                    purge['at'] = time.monotonic()
                    cutoff = (datetime.now(timezone.utc) - timedelta(days=AUDIT_RETENTION_DAYS)).isoformat()
                    db.execute('DELETE FROM mutation_audit WHERE ts < ?', (cutoff,))
        except Exception:  # noqa: BLE001 — l'audit ne doit jamais faire échouer la requête
            log.exception('Audit de mutation non enregistré (request_id=%s)', entry.get('request_id'))

    @app.middleware('http')
    async def guard(request: Request, call_next):
        started = time.monotonic()
        incoming = request.headers.get('x-request-id', '')
        request_id = incoming if REQUEST_ID.match(incoming) else uuid.uuid4().hex
        request.state.request_id = request_id
        # Repris par chaque ligne de journal émise pendant la requête (logging_setup).
        logging_setup.REQUEST_ID.set(request_id)
        method, path = request.method, request.url.path
        who = principal(request.headers)
        request.state.principal = who
        required, group = classify(method, path)
        mutation = method not in ('GET', 'HEAD', 'OPTIONS')
        webhook = path in WEBHOOKS
        # Agent Zabbix local : /api/metrics sans rôle, seulement en boucle locale ET sans
        # passer par nginx (qui pose toujours X-Forwarded-For), et si les métriques sont activées.
        if local_metrics(request, method, path):
            required = None

        async def deny(status, detail, outcome, extra=None):
            response = JSONResponse({'detail': detail, 'request_id': request_id}, status_code=status, headers=extra or {})
            return await finish(response, outcome)

        async def finish(response, outcome=None):
            for k, v in SECURITY_HEADERS.items():
                response.headers.setdefault(k, v)
            response.headers['X-Request-ID'] = request_id
            # Réponses API jamais en cache ; fichiers statiques revalidés (ETag) au lieu d'être retéléchargés.
            # Fichier versionné par son empreinte (?v=, deploy/assets_version.py) : son URL change avec
            # son contenu, il est donc immuable. Évite ~40 revalidations à chaque ouverture (audit UI
            # du 31/10, performances). La page elle-même (index.html, sans ?v=) reste revalidée.
            if path.startswith('/api/') or path.startswith('/health'):
                response.headers['Cache-Control'] = 'no-store'
            elif response.status_code == 200 and VERSIONED.fullmatch(request.url.query or ''):
                response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
            else:
                response.headers['Cache-Control'] = 'no-cache'
            if mutation and not webhook:
                # Hors de la boucle asynchrone : l'INSERT peut attendre le verrou SQLite (30 s)
                # pendant une collecte, et gelait alors toutes les requêtes et le flux SSE.
                await run_in_threadpool(audit, {
                    'ts': datetime.now(timezone.utc).isoformat(), 'request_id': request_id,
                    'actor': who.get('user') or None, 'mode': who['mode'], 'role': who['role'], 'method': method,
                    'path': path[:300], 'status': response.status_code,
                    'outcome': outcome or ('ok' if response.status_code < 400 else 'error'),
                    'duration_ms': int((time.monotonic() - started) * 1000),
                    'client': request.client.host if request.client else None})
            # Ligne d'accès JSON (API, santé, erreurs) : corrélable avec nginx et mutation_audit.
            if logging_setup.access_log_enabled() and (path.startswith(('/api/', '/health'))
                                                       or response.status_code >= 400):
                http_log.info('requête', extra={
                    'request_id': request_id, 'method': method, 'path': path[:300],
                    'status': response.status_code, 'duration_ms': int((time.monotonic() - started) * 1000),
                    'role': who['role'], 'mode': who['mode'], 'outcome': outcome})
            # Métriques HTTP (SLO) : route = gabarit FastAPI, cardinalité bornée.
            route = getattr(request.scope.get('route'), 'path', None) or (
                'refusé' if outcome else 'hors route' if path.startswith(('/api/', '/health')) else 'statique')
            http_metrics.HTTP.record(route, response.status_code, time.monotonic() - started, path)
            return response

        public = path in PUBLIC_API or webhook or not path.startswith('/api/') or required is None and path == '/api/metrics'
        if not public and who['blocked']:
            return await deny(401, who['detail'], 'unauthenticated')
        if mutation and not webhook:
            # CSRF : en-tête applicatif (déclenche un preflight CORS), Origin et Sec-Fetch-Site cohérents.
            if request.headers.get('x-cockpit-request') != '1':
                return await deny(403, 'En-tête requis', 'csrf')
            origin = request.headers.get('origin')
            if origin and origin != str(request.base_url).rstrip('/'):
                return await deny(403, 'Origine refusée', 'csrf')
            if request.headers.get('sec-fetch-site') not in (None, 'same-origin', 'none'):
                return await deny(403, 'Requête inter-site refusée', 'csrf')
        if required and not allowed(who['role'], required):
            label = {'operator': 'opérateur', 'admin': 'administrateur', 'viewer': 'lecture'}[required]
            if who.get('local_off'):
                return await deny(403, 'Mutation refusée en session locale non authentifiée (INFRAOPS_LOCAL_ROLE=off).', 'forbidden')
            return await deny(403, f'Rôle « {label} » requis pour cette action.', 'forbidden')
        if group:
            retry = limiter.check(group, who.get('user') or who['mode'])
            if retry:
                what = 'Collecte complète déjà demandée' if group == 'collect_all' else 'Trop de requêtes'
                return await deny(429, f'{what} : réessayer dans {retry} s.', 'rate_limited', {'Retry-After': str(retry)})
        try:
            response = await call_next(request)
        except Exception:  # noqa: BLE001 — aucune trace, chemin ou secret dans la réponse
            log.exception('Erreur non gérée %s %s (request_id=%s)', method, path, request_id)
            response = JSONResponse({'detail': 'Erreur interne du service. Référence : ' + request_id,
                                     'request_id': request_id}, status_code=500)
        return await finish(response)

    @router.get('/api/admin/audit')
    def mutation_journal(limit: int = 200):
        if connect is None:
            return {'items': []}
        with connect() as db:
            rows = db.execute('SELECT ts, request_id, actor, mode, role, method, path, status, outcome, duration_ms '
                              'FROM mutation_audit ORDER BY seq DESC LIMIT ?', (max(1, min(limit, 1000)),)).fetchall()
        keys = ('ts', 'request_id', 'actor', 'mode', 'role', 'method', 'path', 'status', 'outcome', 'duration_ms')
        return {'items': [dict(zip(keys, r)) for r in rows], 'retention_days': AUDIT_RETENTION_DAYS}
    app.include_router(router)  # routes de ce module : APIRouter, inclus en fin d'installation


LOOPBACK = ('127.0.0.1', '::1')


def local_metrics(request, method, path) -> bool:
    """Lecture de /api/metrics par l'agent de supervision local (sans proxy ni identité)."""
    return (method == 'GET' and path == '/api/metrics' and os.environ.get('INFRAOPS_METRICS') == '1'
            and bool(request.client) and request.client.host in LOOPBACK
            and 'x-forwarded-for' not in request.headers)


def role_of(request) -> str:
    """Rôle effectif posé par le middleware ; « admin » hors middleware (appels internes, tests)."""
    who = getattr(getattr(request, 'state', None), 'principal', None)
    return who.get('role', 'viewer') if isinstance(who, dict) else 'admin'


def describe(headers) -> dict:
    """Pour /api/whoami : rôle et droits effectifs, sans secret."""
    who = principal(headers)
    role = who['role']
    return {'mode': who['mode'], 'authenticated': who['authenticated'], 'user': who.get('user'),
            'role': role, 'can_operate': allowed(role, 'operator'), 'can_admin': allowed(role, 'admin'),
            'proxy_configured': who['proxy_configured'],
            'label': who['label'] if who['authenticated'] else ('Session locale · non authentifiée' +
                                                                 ('' if role == 'off' else ' · lecture seule' if who.get('local_off')
                                                                  else f' · droits {role} locaux')),
            'detail': who.get('detail'),
            # Nom déclaratif par défaut du poste (INFRAOPS_LOCAL_OPERATOR), jamais en mode proxy.
            'default_name': None if who['authenticated'] else operator_identity.local_default()}

