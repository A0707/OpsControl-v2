"""Accès SSH aux serveurs depuis l'interface : empreintes, test de connexion, modification groupée.

1. Empreintes SSH (« clé absente » / « clé différente ») — l'équivalent de
   register_host_key.py, avec la MÊME garde : rien n'est enregistré sans relecture et
   confirmation explicite d'un administrateur.
     GET  /api/ssh/host-keys          serveurs dont la dernière tentative a échoué sur l'empreinte
     POST /api/ssh/host-keys/scan     capture les empreintes présentées (même chemin SSH que la
                                      plateforme, bastion compris) ; rien n'est écrit, la capture
                                      est gardée côté serveur 15 min sous un identifiant
     POST /api/ssh/host-keys/accept   écrit dans data/known_hosts les empreintes CAPTURÉES (jamais
                                      une clé envoyée par le navigateur), après confirmation « OUI »
   Une clé changée remplace l'ancienne (ssh-keygen -R) : sinon OpenSSH continuerait de refuser.

2. Test de connexion — POST /api/hosts/{clé}/test : dernière sonde réseau, empreinte connue,
   puis essai SSH réel en lecture (« uptime ») par compte/port, avec un diagnostic par cause.

3. Modification groupée — POST /api/manage/hosts/bulk : rôle, environnement, criticité, compte,
   port, collecte pour plusieurs serveurs en une fois ; mêmes validations et même refus pendant
   une collecte qu'une modification individuelle (si l'accès change).

Rien ici n'agit sur un serveur supervisé : seules des lectures SSH, comme la collecte.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Annotated, Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from management import Server, SSH_USER_PATTERN

SCAN_TTL = 900
# Clé d'inventaire bornée élément par élément, et pas seulement la liste (audit SEC-09).
HostKey = Annotated[str, Field(min_length=1, max_length=80)]
SCAN_MAX = 50
CONFIRMATION = 'OUI'
# Une clé déjà enregistrée qui change peut signaler une interception : confirmation distincte,
# impossible à donner par réflexe en tapant OUI (audit SSH-03).
REPLACEMENT_CONFIRMATION = 'REMPLACER'
ADVICE = {
    'host_key': 'Empreinte SSH absente ou différente : la vérifier puis l’enregistrer (Empreintes SSH à confirmer).',
    'auth': 'Compte ou clé refusés : autoriser la clé publique d’OpsControl pour ce compte, ou corriger le compte SSH du serveur.',
    'network': 'Serveur ou port injoignable : vérifier l’adresse IP, le port SSH, le pare-feu et le chemin par le bastion.',
    'ssh': 'Erreur SSH : consulter le détail ci-dessous.',
    '': 'Erreur non classée : consulter le détail ci-dessous.',
}


def known_hosts_path(base) -> Path:
    """Même fichier que la plateforme (ssh.persistent_config) et register_host_key.py."""
    return Path(os.environ.get('COCKPIT_SSH_DIR') or (Path(base) / 'data')) / 'known_hosts'


def _keygen(*args, timeout=10):
    try:
        return subprocess.run(['ssh-keygen', *args], capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None


def known_entry(ip, path, port=22) -> bool:
    """Entrée présente pour cet hôte (forme [ip]:port hors port 22, comme OpenSSH l'enregistre)."""
    if not Path(path).is_file():
        return False
    r = _keygen('-F', ip if int(port or 22) == 22 else f'[{ip}]:{port}', '-f', str(path))
    return bool(r and r.returncode == 0 and r.stdout.strip())


def fingerprints(lines) -> list[dict]:
    """[{bits, sha256, type}] des lignes known_hosts capturées (ssh-keygen -l)."""
    with tempfile.NamedTemporaryFile('w', suffix='.tmp', delete=False, encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
        path = f.name
    try:
        r = _keygen('-l', '-f', path)
        out = []
        for line in (r.stdout if r else '').splitlines():
            parts = line.split()
            if len(parts) >= 2:
                out.append({'bits': parts[0], 'sha256': parts[1], 'type': parts[-1].strip('()')})
        return out
    finally:
        Path(path).unlink(missing_ok=True)


def host_key_problems(rows) -> list[dict]:
    """Serveurs dont la dernière tentative a échoué sur l'empreinte (absente ou changée)."""
    out = []
    for h in rows:
        attempts = list(h.get('attempts') or []) + list((h.get('last_attempt') or {}).get('attempts') or [])
        failed = [a for a in attempts if a.get('error_kind') == 'host_key']
        if not failed or any(a.get('ok') for a in attempts):
            continue
        text = ' '.join(str(a.get('error') or '') for a in failed).lower()
        state = 'changed' if ('has changed' in text or 'différente' in text) else 'absent'
        out.append({'key': h['key'], 'name': h.get('name'), 'ip': h.get('ip'), 'state': state,
                    'error': str(failed[0].get('error') or '')[:300]})
    return sorted(out, key=lambda x: (x['state'] != 'changed', x['name'] or ''))


class Scan(BaseModel):
    model_config = ConfigDict(extra='forbid')
    keys: list[HostKey] = Field(min_length=1, max_length=SCAN_MAX)


class Accept(BaseModel):
    model_config = ConfigDict(extra='forbid')
    scan_id: str = Field(pattern=r'^[0-9a-f]{32}$')
    keys: list[HostKey] = Field(min_length=1, max_length=SCAN_MAX)
    confirm: str = Field(max_length=10)


class Bulk(BaseModel):
    """Champs absents = inchangés. Mêmes contraintes que management.Server."""
    model_config = ConfigDict(extra='forbid')
    keys: list[HostKey] = Field(min_length=1, max_length=500)
    role: str | None = Field(default=None, min_length=1, max_length=80)
    environment: str | None = Field(default=None, min_length=1, max_length=80)
    criticality: Literal['standard', 'critical'] | None = None
    user: str | None = Field(default=None, pattern=r'^(?:[A-Za-z_][A-Za-z0-9_.-]{0,63})?$')
    port: int | None = Field(default=None, ge=1, le=65535)
    collect_enabled: bool | None = None


PRIVATE_RFC1918 = tuple(ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))


def private_rfc1918(value) -> bool:
    """Liste blanche explicite : `is_private` accepte aussi 0.0.0.0/8, 198.18/15, 240/4…"""
    try:
        address = ip_address(value)
    except ValueError:
        return False
    return address.version == 4 and any(address in network for network in PRIVATE_RFC1918)


class TestParams(BaseModel):
    model_config = ConfigDict(extra='forbid')
    ip: str = Field(min_length=1, max_length=45)
    user: str = Field(default='', max_length=64, pattern=SSH_USER_PATTERN)
    port: int = Field(ge=1, le=65535)

    @field_validator('ip')
    @classmethod
    def valid_ip(cls, value):
        return Server.valid_ip(value)


def install(app, context):
    from fastapi import APIRouter
    import management
    import ssh
    from config import candidates
    router = APIRouter()
    scans, scans_lock, store_lock = {}, threading.Lock(), threading.Lock()

    def store():
        return known_hosts_path(context.BASE)

    def host(key):
        h = next((x for x in context.HOSTS if x['key'] == key), None)
        if h is None:
            raise HTTPException(404, 'Serveur inconnu : ' + key)
        return h

    # ---------------------------------------------------------------- empreintes
    # Lecture GET ouverte au rôle viewer : chaque appel lançait deux ssh-keygen par serveur
    # jamais audité. Résultat mémorisé tant que le magasin n'a pas changé (audit SEC-07).
    known_memo = {}

    def known_cached(ip, path, port):
        try:
            stamp = Path(path).stat().st_mtime_ns
        except OSError:
            return False
        key = (str(path), stamp, ip, int(port))
        if key not in known_memo:
            if len(known_memo) > 4096:
                known_memo.clear()
            known_memo[key] = known_entry(ip, path, port)
        return known_memo[key]

    @router.get('/api/ssh/host-keys')
    def pending_host_keys():
        rows = context.rows()
        found = host_key_problems(rows)
        listed = {h['key'] for h in found}
        # Serveurs jamais audités (ajout récent, découverte réseau) dont l'empreinte est inconnue :
        # sans cela ils n'apparaîtraient qu'après un premier audit en échec.
        personal = Path.home() / '.ssh' / 'known_hosts'
        for h in rows:
            if h['key'] in listed or h.get('collected_at') or h.get('attempts') or not h.get('ip') or h.get('collect_enabled') is False:
                continue
            port = h.get('port') or 22
            if not known_cached(h['ip'], store(), port) and not known_cached(h['ip'], personal, port):
                found.append({'key': h['key'], 'name': h.get('name'), 'ip': h['ip'], 'state': 'never', 'error': ''})
        return {'hosts': found, 'store': store().name}

    @router.post('/api/ssh/host-keys/scan')
    def scan_host_keys(request: Scan):
        from register_host_key import capture_key
        targets = [host(k) for k in dict.fromkeys(request.keys)]
        known = store()

        def capture(h):
            started = time.monotonic()
            for candidate in candidates(context.cfg, h):
                lines = [l for l in capture_key(h['ip'], candidate, context.cfg.timeout + 10).splitlines() if l.strip()]
                if lines:
                    ssh.audit(h['ip'], 'host_key_capture', 'ssh exit (capture d’empreinte, StrictHostKeyChecking=accept-new '
                              'dans un fichier jetable)', 0, int((time.monotonic() - started) * 1000), 'interface-empreintes',
                              True, '', candidate.user, candidate.port)
                    return h, lines, candidate.port
            return h, [], None

        with ThreadPoolExecutor(max_workers=min(8, len(targets))) as pool:
            captured = list(pool.map(capture, targets))
        scan_id, result = uuid.uuid4().hex, []
        with scans_lock:
            now = time.time()
            for sid in [s for s, v in scans.items() if now - v['at'] > SCAN_TTL]:
                scans.pop(sid)
            # Port RÉELLEMENT utilisé pour la capture : un serveur sans port propre peut répondre
            # sur 2222 ou 3300 (ssh.ports). Avec « port or 22 », une clé changée sur ces ports
            # passait pour nouvelle et « OUI » suffisait (audit SSH-03).
            scans[scan_id] = {'at': now, 'lines': {h['key']: lines for h, lines, _ in captured if lines},
                              'ports': {h['key']: port for h, lines, port in captured if lines}}
        for h, lines, port in captured:
            already = bool(lines) and Path(known).is_file() and all(l.strip() in known.read_text(encoding='utf-8') for l in lines)
            result.append({'key': h['key'], 'name': h.get('name'), 'ip': h['ip'],
                           'status': 'captured' if lines else 'unreachable',
                           'fingerprints': fingerprints(lines) if lines else [],
                           'already_known': already,
                           'replaces_existing': bool(lines) and not already and
                                                known_entry(h['ip'], known, port)})
        return {'scan_id': scan_id, 'expires_in': SCAN_TTL, 'hosts': result,
                'warning': 'Comparer chaque empreinte SHA256 à une source de confiance (console du serveur, '
                           '« ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub » sur le serveur) avant de confirmer.'}

    @router.post('/api/ssh/host-keys/accept')
    def accept_host_keys(request: Accept):
        confirm = request.confirm.strip().upper()
        if confirm not in (CONFIRMATION, REPLACEMENT_CONFIRMATION):
            raise HTTPException(422, 'Confirmation requise : taper OUI après avoir comparé les empreintes.')
        with scans_lock:
            scan = scans.get(request.scan_id)
            if not scan or time.time() - scan['at'] > SCAN_TTL:
                raise HTTPException(410, 'Lecture des empreintes expirée : relancer la lecture.')
            chosen = {k: scan['lines'][k] for k in dict.fromkeys(request.keys) if k in scan['lines']}
            ports = {k: scan.get('ports', {}).get(k) or host(k).get('port') or 22 for k in chosen}
        if not chosen:
            raise HTTPException(422, 'Aucune empreinte capturée pour ces serveurs.')
        path = store()
        written = []
        replacing = [k for k in chosen if known_entry(host(k)['ip'], path, ports[k])]
        if replacing and confirm != REPLACEMENT_CONFIRMATION:
            raise HTTPException(422, 'Remplacement d’une clé déjà enregistrée (' + ', '.join(replacing) + ') : '
                                     'vérifier l’empreinte à la console du serveur puis taper REMPLACER.')
        with store_lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            for key, lines in chosen.items():
                ip, port = host(key)['ip'], ports[key]
                replaced = known_entry(ip, path, port)
                if replaced:   # ancienne clé retirée (copie .old conservée)
                    _keygen('-R', ip if int(port) == 22 else f'[{ip}]:{port}', '-f', str(path))
                with path.open('a', encoding='utf-8') as f:
                    f.write('\n'.join(lines) + '\n')
                written.append({'key': key, 'ip': ip, 'port': port, 'replaced': replaced})
        with scans_lock:
            scans.pop(request.scan_id, None)
        personal = Path.home() / '.ssh' / 'known_hosts'
        conflicts = [w['ip'] for w in written if w['replaced'] and known_entry(w['ip'], personal, w['port'])]
        return {'written': written, 'store': path.name,
                'note': 'Relancer l’audit de ces serveurs.' + (
                    ' Attention : ' + ', '.join(conflicts) + ' figure aussi dans ~/.ssh/known_hosts (non modifié par '
                    'OpsControl) ; si la clé y est ancienne, la retirer avec « ssh-keygen -R <ip> ».' if conflicts else '')}

    # ---------------------------------------------------------------- test de connexion
    def diagnose(h):
        with context.connect() as db:
            row = db.execute('SELECT payload FROM network WHERE key=? AND ip=?', (h.get('key'), h['ip'])).fetchone()
        net = json.loads(row[0]) if row else {}
        steps = [{'step': 'Sonde réseau (dernière)', 'ok': None if not net else bool(net.get('ping') or any(p.get('ok') for p in net.get('ports') or [])),
                  'detail': ('ping ' + ('OK' if net.get('ping') else 'sans réponse') + ' · ports ' +
                             ', '.join(f"{p.get('port')} {'ouvert' if p.get('ok') else 'fermé'}" for p in net.get('ports') or []) +
                             ' · ' + str(net.get('collected_at'))) if net else 'Aucune sonde réseau : lancer « Réseau » ou une actualisation.'}]
        port = h.get('port') or context.cfg.port
        known = known_entry(h['ip'], store(), port) or known_entry(h['ip'], Path.home() / '.ssh' / 'known_hosts', port)
        steps.append({'step': 'Empreinte SSH connue', 'ok': known,
                      'detail': 'Présente dans les magasins OpsControl.' if known else ADVICE['host_key']})
        attempts, verdict = [], None
        for candidate in candidates(context.cfg, h):
            result = ssh.run_operation(h['ip'], 'uptime', candidate, 'test-connexion')
            hint = ssh.native_error(result.stderr)[1] if not result.ok and result.stderr else ''
            attempts.append({'user': candidate.user, 'port': candidate.port, 'ok': result.ok,
                             'kind': result.error_kind, 'duration_ms': result.duration_ms,
                             'detail': (result.stdout.strip()[:200] if result.ok else (hint or result.stderr.strip())[:400])})
            if result.ok:
                verdict = {'ok': True, 'summary': f'Connexion réussie ({candidate.user}@{h["ip"]}:{candidate.port}).'}
                break
        if verdict is None:
            kinds = [a['kind'] for a in attempts]
            main = next((k for k in ('host_key', 'auth', 'network', 'ssh') if k in kinds), '')
            verdict = {'ok': False, 'cause': main, 'summary': ADVICE[main]}
        return {'key': h.get('key'), 'name': h.get('name'), 'ip': h['ip'], 'steps': steps, 'attempts': attempts, **verdict}

    @router.post('/api/hosts/{key}/test')
    def test_connection(key: str):
        return diagnose(host(key))

    def allowed_test_target(ip, port):
        """Un opérateur ne doit pas pouvoir sonder n'importe quelle adresse ou n'importe quel
        port depuis le service (audit SEC-03 / GIT-01) : IP de l'inventaire ou IPv4 privée
        RFC 1918, et port SSH déjà en usage dans le parc (ssh.ports, ports des serveurs)."""
        inventory_ips = {str(h.get('ip')) for h in context.HOSTS}
        if ip not in inventory_ips and not private_rfc1918(ip):
            raise HTTPException(422, 'Adresse refusée : serveur de l’inventaire ou IPv4 privée '
                                     '(10/8, 172.16/12, 192.168/16) uniquement.')
        ports = {int(p) for p in (getattr(context.cfg, 'ports', None) or [context.cfg.port])}
        ports |= {int(h['port']) for h in context.HOSTS if h.get('port')}
        if port not in ports:
            raise HTTPException(422, 'Port refusé : seuls les ports SSH déjà utilisés dans le parc sont testables ('
                                     + ', '.join(str(p) for p in sorted(ports)) + ').')

    @router.post('/api/hosts/test-params')
    def test_params(request: TestParams):
        allowed_test_target(request.ip, request.port)
        # Ne reprendre aucun alias de l’ancien serveur : tester l’IP effectivement saisie.
        candidate = {'ip': request.ip, 'user': request.user or context.cfg.user,
                     'port': request.port, 'name': 'Paramètres non enregistrés'}
        return {**diagnose(candidate), 'saved': False}

    # ---------------------------------------------------------------- modification groupée
    @router.post('/api/manage/hosts/bulk')
    def bulk_update(request: Bulk):
        changes = {k: v for k, v in request.model_dump(exclude={'keys'}).items() if v is not None}
        if not changes:
            raise HTTPException(422, 'Aucune modification demandée.')
        keys = list(dict.fromkeys(request.keys))
        for k in keys:
            host(k)
        access = bool({'user', 'port', 'collect_enabled'} & set(changes))
        with context.lock, context.net_lock:
            # Accepté pendant une collecte : le lot en cours garde sa copie figée des serveurs
            # (jobs.launch) ; les nouveaux accès s'appliquent au lot suivant.
            updated = []
            for h in context.HOSTS:
                if h['key'] in keys:
                    merged = {**h, **changes}
                    management.Server(**{f: merged.get(f) for f in management.Server.model_fields if merged.get(f) is not None})
                    if merged.get('user') == '':
                        merged.pop('user')
                    updated.append(merged)
                else:
                    updated.append(h)
            management.save_inventory(context, updated)
            synced = True
            if access:
                purge = getattr(context, 'purge_network_cache', None)
                if purge:
                    synced = purge(keys)
                else:
                    with context.connect() as db:
                        db.executemany('DELETE FROM network WHERE key=?', [(k,) for k in keys])
        return {'updated': keys, 'changes': changes, 'sync_pending': not synced}

    app.include_router(router)
