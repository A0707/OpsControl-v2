"""Local inventory editing and explicit, bounded HTTPS JSON collection."""
import hashlib
import json
import logging
import math
import os
import re
import tempfile
import threading
import time
import socket
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from datetime import datetime, timezone
from ipaddress import ip_address
from urllib.parse import urlsplit
from typing import Annotated, Literal

from fastapi import HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from https_transport import (BACULA_TUNNEL_URL, BaculaHTTPHandler, CheckedHTTPSHandler,
                             DestinationRefused, connect_checked, forbidden_ip)

SSH_USER_PATTERN = r'^(?:[A-Za-z_][A-Za-z0-9_.-]{0,63})?$'


# Champs du formulaire qui ne sont pas des données d'inventaire : jamais écrits dans hosts.yaml.
REQUEST_ONLY = {'mode', 'revision'}


class Server(BaseModel):
    # Espaces retirés partout : une IP copiée avec un espace final était refusée à
    # l'enregistrement alors que le bouton de test l'acceptait (audit A6).
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    key: str = Field(pattern=r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$')
    name: str = Field(min_length=1, max_length=120)
    ip: str = Field(max_length=64)
    role: str = Field(default='À renseigner', max_length=80)
    environment: str = Field(default='PROD', max_length=80)
    criticality: Literal['standard', 'critical'] = 'standard'
    services: list[Annotated[str, Field(min_length=1, max_length=120)]] = Field(default_factory=list, max_length=100)
    user: str = Field(default='', pattern=SSH_USER_PATTERN)
    # Absent = hérité du profil SSH (ssh.ports). Un défaut à 22 remplaçait silencieusement
    # un port global (3300, par exemple) dès qu'on rouvrait le formulaire (audit A3).
    port: int | None = Field(default=None, ge=1, le=65535)
    collect_enabled: bool = True
    # create : un identifiant déjà utilisé est un conflit, jamais une modification
    # silencieuse d'un autre serveur (audit A2). update : la révision lue à l'ouverture du
    # formulaire détecte une modification concurrente. Absent : ancien comportement
    # (création ou mise à jour), conservé pour les scripts.
    mode: Literal['create', 'update'] | None = None
    revision: str | None = Field(default=None, pattern=r'^[0-9a-f]{16}$')

    @field_validator('ip')
    @classmethod
    def valid_ip(cls, value):
        try:
            return str(ip_address(value))
        except ValueError:
            raise ValueError('Adresse IP attendue (IPv4 ou IPv6) ; un nom DNS n’est pas accepté dans ce champ') from None

    @field_validator('services')
    @classmethod
    def valid_services(cls, values):
        if any(not re.fullmatch(r'[A-Za-z0-9_@.:-]{1,150}', v) for v in values):
            raise ValueError('Nom de service invalide')
        return list(dict.fromkeys(values))


# Variables de jeton autorisées : INFRAOPS_<PRODUIT>_AUTH[_SUFFIXE], cohérentes avec le
# produit de la connexion. Sans cette liste blanche, une connexion pouvait désigner
# N'IMPORTE QUELLE variable (secret du proxy, jeton d'un autre produit, variable
# système) et l'envoyer en en-tête Authorization vers une URL arbitraire.
TOKEN_ENV_PROVIDER = {'Proxmox': 'PROXMOX', 'Wazuh': 'WAZUH', 'Zabbix': 'ZABBIX', 'Elasticsearch': 'ELASTIC',
                      'Bacula': 'BACULA', 'JSON': 'JSON'}


def token_env_allowed(name, provider):
    """Lève ValueError si la variable n'est pas un jeton déclaré pour ce produit."""
    if not name:
        return
    code = TOKEN_ENV_PROVIDER.get(provider)
    if not code or not re.fullmatch(rf'INFRAOPS_{code}_AUTH(?:_[A-Z0-9]{{1,30}})?', name):
        raise ValueError(f'Variable de jeton refusée : attendue INFRAOPS_{code or "PRODUIT"}_AUTH '
                         '(suffixe facultatif _XXX), propre au produit de la connexion')


# Destinations interdites aux connexions API (hors tunnel Bacula prévu) : boucle locale,
# lien local (dont 169.254.169.254, métadonnées des clouds), multicast, adresse nulle.
# Sans ce garde-fou, une connexion pouvait viser un service local de la machine OpsControl.
# Liaisons jeton → hôte de l'instance en cours (posées par install) : relues par les voies
# d'appel secondaires (zabbix_live) qui n'ont pas accès au contexte d'installation.
ACTIVE_BINDINGS = None
# Racine d'installation (data/ca/), posée par install() : les voies secondaires résolvent
# et confinent la CA exactement comme la collecte principale (OC-AUDIT-010).
ACTIVE_BASE = None


def transport_for(connection, base):
    """Copie de la connexion prête pour le transport : CA relative résolue sous <base>/data/ca/.

    La configuration enregistrée n'est jamais modifiée : seule cette copie sert à TLS."""
    ca = (connection.get('ca_bundle') or '').strip()
    if ca and not ca.startswith('-----BEGIN CERTIFICATE-----') and not Path(ca).is_absolute():
        return {**connection, 'ca_bundle': str(Path(base) / 'data' / 'ca' / ca)}
    return connection


def connection_refusal(connection, base=None):
    """Mêmes contrôles que la collecte principale, sans lier de jeton : variable autorisée,
    HTTPS, destination non locale, CA confinée, liaison existante respectée (audit SEC-05)."""
    try:
        token_env_allowed(connection.get('token_env'), connection.get('provider'))
    except ValueError as exc:
        return str(exc)
    url = connection.get('url') or ''
    if urlsplit(url).scheme != 'https':
        return 'HTTPS requis'
    refus = destination_refused(url)
    if not refus and base is not None:
        refus = ca_file_refused(base, connection.get('ca_bundle'))
    if not refus and ACTIVE_BINDINGS is not None:
        refus = ACTIVE_BINDINGS.refusal(connection.get('token_env'), url)
    return refus


def endpoint_of(url):
    """« hôte:port » d'une URL, clé de liaison d'un jeton."""
    u = urlsplit(url)
    return f'{(u.hostname or "").lower()}:{u.port or (443 if u.scheme == "https" else 80)}'


def destination_refused(url, resolve=None):
    """Message de refus si l'URL vise (ou se résout vers) une destination interdite, sinon None."""
    resolve = resolve or socket.getaddrinfo
    if url == BACULA_TUNNEL_URL:
        return None
    host = urlsplit(url).hostname or ''
    if forbidden_ip(host):
        return 'Destination refusée : adresse locale ou de lien local'
    try:
        addresses = {info[4][0] for info in resolve(host, None)}
    except (OSError, UnicodeError):
        # Précontrôle sans socket : le transport résoudra et vérifiera les adresses
        # avant toute connexion, même si ce premier essai DNS a échoué.
        return None
    if any(forbidden_ip(a) for a in addresses):
        return 'Destination refusée : le nom se résout vers une adresse locale ou de lien local'
    return None


# Sonde de certificat : ports des API supervisées seulement. Sans cette liste, elle servait
# d'oracle de balayage (ouvert / refusé / délai) sur n'importe quel port interne.
PROBE_PORTS = {443, 8006, 8007, 8443, 9200, 9243, 10443, 55000}
SWEEP_MIN_INTERVAL = 60


def ca_file_refused(base, value):
    """Message si un ca_bundle donné comme CHEMIN sort de <base>/data/ca/, sinon None.

    Un PEM collé reste la forme recommandée. Un chemin libre permettait de tester
    l'existence de n'importe quel fichier lisible par le service (erreur ca_file ou TLS)."""
    value = (value or '').strip()
    if not value or value.startswith('-----BEGIN CERTIFICATE-----'):
        return None
    if value.startswith('~'):
        return 'Certificat CA : chemin relatif à data/ca/ attendu (pas de « ~ »)'
    root = (Path(base) / 'data' / 'ca').resolve()
    try:
        target = (root / value).resolve() if not Path(value).is_absolute() else Path(value).resolve()
    except (OSError, ValueError):
        return 'Chemin de certificat invalide'
    if target != root and root not in target.parents:
        return 'Certificat CA : coller le PEM, ou placer le fichier dans data/ca/ (chemin relatif à ce dossier)'
    return None


# « hôte:port » produit par endpoint_of (un hôte IPv6 n’a pas de crochets).
BINDING_ENDPOINT = re.compile(r'[^\s/]{1,253}:\d{1,5}')


class BindingsUnreadable(ValueError):
    """Registre des liaisons présent mais inexploitable : aucun jeton ne doit partir."""


class TokenBindings:
    """Liaison jeton -> hôte:port, établie au premier usage et immuable depuis l'interface.

    Un jeton (variable d'environnement) ne part jamais vers un autre hôte que celui pour
    lequel il a servi la première fois. Sans cela, modifier l'URL d'une connexion suffisait
    à envoyer le jeton Proxmox, Zabbix… ou le mot de passe Wazuh à un serveur arbitraire.
    Changer légitimement d'hôte : retirer l'entrée du fichier SUR LE SERVEUR (docs/RUNBOOK.md).
    """

    def __init__(self, path):
        self.path, self.lock = Path(path), threading.Lock()
        self._signale = None

    def _read(self):
        """Liaisons enregistrées. Seul un fichier ABSENT vaut « aucune liaison » (premier usage).

        Un registre illisible, corrompu ou mal structuré était lu comme vide : les restrictions
        d'envoi des jetons disparaissaient, et la collecte suivante réécrivait le fichier avec
        sa seule liaison, effaçant toutes les autres (audit A2, 15/10). Il lève désormais
        BindingsUnreadable et toute collecte authentifiée est refusée jusqu'à réparation."""
        try:
            texte = self.path.read_text(encoding='utf-8')
        except FileNotFoundError:
            return {}
        except (OSError, UnicodeError) as exc:
            raise self._invalide(f'illisible ({type(exc).__name__})') from None
        try:
            data = json.loads(texte)
        except ValueError:
            raise self._invalide('corrompu (JSON invalide)') from None
        if not isinstance(data, dict) or not all(
                isinstance(k, str) and isinstance(v, dict) and isinstance(v.get('endpoint'), str)
                and BINDING_ENDPOINT.fullmatch(v['endpoint']) for k, v in data.items()):
            raise self._invalide('invalide (structure inattendue)')
        self._signale = None
        return data

    def _invalide(self, cause):
        message = (f'Registre des liaisons de jetons {cause} : collectes authentifiées suspendues. '
                   'Restaurer data/token-bindings.json depuis la sauvegarde ou le corriger sur le serveur '
                   '(docs/RUNBOOK.md).')
        # Une seule trace par état : la voie rapide relit le registre toutes les 10 s.
        if self._signale != message:
            self._signale = message
            logging.getLogger('opscontrol.security').error(message)
        return BindingsUnreadable(message)

    def bound(self, token_env):
        entry = self._read().get(token_env)
        return entry.get('endpoint') if isinstance(entry, dict) else None

    def refusal(self, token_env, url):
        """Message si `url` sort de la liaison existante de `token_env`, sinon None (sans écrire)."""
        try:
            bound = self.bound(token_env) if token_env else None
        except BindingsUnreadable as exc:
            return str(exc)
        if bound and bound != endpoint_of(url):
            return (f'Jeton {token_env} lié à {bound} : envoi vers {endpoint_of(url)} refusé. '
                    'Changer d’hôte demande de retirer cette liaison sur le serveur (docs/RUNBOOK.md).')
        return None

    def check_and_bind(self, token_env, url):
        """Lève ValueError hors liaison ; enregistre la liaison au premier usage."""
        if not token_env:
            return
        with self.lock:
            refus = self.refusal(token_env, url)
            if refus:
                raise ValueError(refus)
            data = self._read()
            if token_env not in data:
                data[token_env] = {'endpoint': endpoint_of(url), 'bound_at': datetime.now(timezone.utc).isoformat()}
                atomic_json(self.path, data)


class Connection(BaseModel):
    model_config = ConfigDict(extra='forbid')
    key: str = Field(pattern=r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$')
    name: str = Field(min_length=1, max_length=120)
    url: str = Field(max_length=2048)
    token_env: str = Field(default='', pattern=r'^(?:[A-Z][A-Z0-9_]{0,100})?$')
    host_key: str = ''
    provider: Literal['Proxmox', 'Wazuh', 'Zabbix', 'Elasticsearch', 'Bacula', 'JSON'] = 'JSON'
    ca_bundle: str = Field(default='', max_length=8192)

    @field_validator('url')
    @classmethod
    def valid_url(cls, value):
        if value == BACULA_TUNNEL_URL:
            return value
        u = urlsplit(value)
        if u.scheme != 'https' or not u.hostname or u.username or u.password or u.fragment or u.query:
            raise ValueError('URL HTTPS sans identifiants, paramètres ni fragment requise')
        if forbidden_ip(u.hostname):
            raise ValueError('Destination refusée : adresse locale ou de lien local')
        return value

    @model_validator(mode='after')
    def local_transport(self):
        if self.url == BACULA_TUNNEL_URL and self.provider != 'Bacula':
            raise ValueError('Le tunnel local est réservé à Bacula')
        token_env_allowed(self.token_env, self.provider)
        return self

    @field_validator('ca_bundle')
    @classmethod
    def valid_ca_bundle(cls, value):
        if value.lstrip().startswith('-----BEGIN CERTIFICATE-----') and not value.rstrip().endswith('-----END CERTIFICATE-----'):
            raise ValueError('Certificat PEM incomplet')
        return value


class CertificateProbe(BaseModel):
    model_config = ConfigDict(extra='forbid')
    url: str = Field(max_length=2048)


class WafCommand(BaseModel):
    model_config = ConfigDict(extra='forbid')
    ip: str = Field(min_length=2, max_length=64)
    action: Literal['ban', 'whitelist', 'unban', 'remove_whitelist', 'inspect']
    host_key: str = Field(pattern=r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$')


def save_inventory(context, updated):
    """Réécrit hosts.yaml (remplacement atomique, champs documentaires conservés) puis
    l'inventaire en mémoire. À appeler sous context.lock et context.net_lock."""
    import yaml
    path = getattr(context, 'INVENTORY', context.BASE / 'hosts.yaml')
    original = yaml.safe_load(path.read_text(encoding='utf-8-sig'))
    original['hosts'] = updated
    atomic_json(path, original)
    context.HOSTS[:] = updated


def config_revision(entry):
    """Révision courte d'une entrée d'inventaire : change dès qu'un champ change."""
    return hashlib.sha256(json.dumps(entry, sort_keys=True, default=str).encode()).hexdigest()[:16]


def ssh_effective(cfg, entry):
    """Compte et ports réellement utilisés (config.candidates) et leur origine, pour
    l'affichage : la valeur d'un serveur sans surcharge vient du profil SSH global."""
    users = list(getattr(cfg, 'users', None) or ([cfg.user] if cfg else []))
    ports = [int(p) for p in (getattr(cfg, 'ports', None) or ([cfg.port] if cfg else []))]
    return {'profile': {'users': users, 'ports': ports},
            'users': [entry['user']] if entry.get('user') else users,
            'user_origin': 'serveur' if entry.get('user') else 'profil',
            'ports': [int(entry['port'])] if entry.get('port') else ports,
            'port_origin': 'serveur' if entry.get('port') else 'profil'}


def atomic_json(path, data):
    # Release versionnée : hosts.yaml et data/ sont des liens vers les données
    # partagées. On écrit à côté de la CIBLE, sinon os.replace remplacerait le
    # lien lui-même par un fichier propre à la release (perdu au déploiement suivant).
    path = Path(os.path.realpath(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.inventory-', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def api_opener(context, local_bacula=False):
    """API internes en direct : ni proxy d'environnement ni résolution non contrôlée."""
    return urllib.request.build_opener(NoRedirect, CheckedHTTPSHandler(context=context),
                                       BaculaHTTPHandler(enabled=local_bacula),
                                       urllib.request.ProxyHandler({}))


# --- Requêtes POST autorisées -------------------------------------------------
# La plateforme ne fait que des GET, sauf pour les API qui n'en proposent aucun.
# Zabbix est dans ce cas : son API est exclusivement du JSON-RPC en POST.
#
# Le principe de ssh.OPERATIONS est repris tel quel : le poste client ne choisit
# jamais la requête, seulement la source à interroger. Les corps ci-dessous sont
# figés dans le code, aucun champ n'est construit à partir d'une saisie, et
# seules des méthodes de LECTURE y figurent. Ajouter une méthode d'écriture ici
# reviendrait à casser la garantie « lecture seule » de la plateforme.
READ_ONLY_RPC = {
    'Zabbix': {
        'content_type': 'application/json-rpc',
        'calls': [
            ('hosts', {'jsonrpc': '2.0', 'id': 1, 'method': 'host.get', 'params': {
                'output': ['hostid', 'host', 'name', 'status'],
                'selectInterfaces': ['ip'],
                'limit': 2000,   # zabbix_inventory.HOST_LIMIT
            }}),
            ('problems', {'jsonrpc': '2.0', 'id': 2, 'method': 'trigger.get', 'params': {
                'output': ['triggerid', 'description', 'priority', 'lastchange'],
                'selectHosts': ['host', 'name'],
                'selectItems': ['itemid', 'lastclock'],
                'filter': {'value': 1, 'status': 0},
                'monitored': True,
                'skipDependent': True,
                'expandDescription': True,
                # Tri côté serveur par gravité : au-delà du plafond, ce sont les moins graves
                # qui manquent, jamais un problème critique (audit CON-01).
                'sortfield': 'priority', 'sortorder': 'DESC',
                'limit': 500,   # zabbix_inventory.TRIGGER_LIMIT
            }}),
        ],
    },
}


def rpc_request(url, body, headers, content_type, legacy_token=None):
    """Construit une requête JSON-RPC à partir d'un corps figé.

    `legacy_token` sert au repli pour Zabbix antérieur à 6.4, qui ignore
    l'en-tête Authorization et attend le jeton dans le champ `auth`.
    """
    payload = dict(body)
    if legacy_token:
        payload = {**payload, 'auth': legacy_token}
    data = json.dumps(payload).encode()
    return urllib.request.Request(url, data=data, method='POST',
                                  headers={**headers, 'Content-Type': content_type})


def ssl_context_for(item):
    """Certificat CA : soit un chemin de fichier .pem local, soit un certificat
    collé directement (récupéré et vérifié via 'Vérifier le certificat'). La
    vérification TLS standard reste active dans les deux cas ; vide = autorités
    du système."""
    ca = (item.get('ca_bundle') or '').strip()
    if not ca:
        return ssl.create_default_context()
    if ca.startswith('-----BEGIN CERTIFICATE-----'):
        # Un certificat collé sert d'ancre de confiance pour CE serveur : c'est
        # de l'épinglage, et toute la vérification standard reste active —
        # chaîne, nom d'hôte, période de validité, signature.
        #
        # On ne pré-refuse plus les certificats dont get_ca_certs() est vide.
        # Mesuré contre un service interne réel (Zabbix 6.4, certificat
        # auto-signé sans basicConstraints CA:TRUE) : get_ca_certs() renvoie
        # une liste vide, mais OpenSSL accepte parfaitement ce certificat comme
        # ancre et le handshake aboutit. L'ancien contrôle refusait donc une
        # configuration sûre. Un certificat inadapté échoue maintenant au
        # handshake, avec un diagnostic TLS explicite plutôt qu'une supposition.
        context = ssl.create_default_context(cadata=ca)
    else:
        context = ssl.create_default_context(cafile=str(Path(ca).expanduser()))
    # Older Proxmox cluster CAs omit keyUsage. Use standard chain validation
    # only for Proxmox with an explicitly supplied CA; retain CERT_REQUIRED,
    # hostname checking, validity checks and signature verification.
    if item.get('provider') == 'Proxmox':
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return context


def probe_certificate(hostname, port, timeout=6):
    """Récupère le certificat présenté par hostname:port pour inspection humaine
    uniquement : aucune confiance n'est accordée ici, rien n'est enregistré."""
    # Volontaire : on RÉCUPÈRE le certificat pour qu'un humain l'inspecte (aucune donnée
    # envoyée, aucune confiance accordée) ; la collecte, elle, vérifie toujours TLS.
    ctx = ssl._create_unverified_context()  # nosec B323
    with connect_checked((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            der = ssock.getpeercert(binary_form=True)
    if not der:
        raise ValueError('Aucun certificat présenté')
    pem = ssl.DER_cert_to_PEM_cert(der)
    digest = hashlib.sha256(der).hexdigest()
    details = {}
    is_ca = False
    try:
        verified = ssl.create_default_context(cadata=pem)
        is_ca = bool(verified.get_ca_certs())
        with connect_checked((hostname, port), timeout=timeout) as sock:
            with verified.wrap_socket(sock, server_hostname=hostname) as ssock:
                details = ssock.getpeercert() or {}
    except Exception:
        pass
    subject = dict(x[0] for x in details.get('subject', []))
    issuer = dict(x[0] for x in details.get('issuer', []))
    # Vérité de terrain plutôt que supposition : `details` n'est renseigné que
    # si la connexion VÉRIFIÉE avec ce certificat en ancre a abouti. C'est donc
    # la preuve directe qu'épingler ce certificat fera fonctionner la collecte,
    # qu'il porte ou non basicConstraints CA:TRUE.
    return {'hostname': hostname, 'port': port, 'pem': pem, 'is_ca': is_ca,
            'usable_anchor': bool(details),
            'self_signed': bool(subject) and subject == issuer,
            'sha256_fingerprint': ':'.join(digest[i:i + 2] for i in range(0, len(digest), 2)).upper(),
            'subject_cn': subject.get('commonName'), 'issuer_cn': issuer.get('commonName'),
            'not_before': details.get('notBefore'), 'not_after': details.get('notAfter')}


def wazuh_token(base_url, credentials, context, timeout):
    """Exchange 'username:password' for a fresh JWT via POST /security/user/authenticate.

    Wazuh JWTs are short-lived (a few minutes by default); calling this on every
    collection means the operator sets a password once and never has to fetch
    and paste a new token by hand again."""
    import base64
    user, sep, password = credentials.partition(':')
    if not sep:
        raise ValueError('Wazuh credentials must be user:password')
    parsed = urlsplit(base_url)
    auth_url = parsed._replace(path='/security/user/authenticate', query='').geturl()
    basic = base64.b64encode(f'{user}:{password}'.encode()).decode()
    opener = api_opener(context)
    req = urllib.request.Request(auth_url, method='POST', headers={'Authorization': 'Basic ' + basic, 'Accept': 'application/json'})
    with opener.open(req, timeout=timeout) as response:
        raw = response.read(65536)
    token = json.loads(raw).get('data', {}).get('token')
    if not token:
        raise ValueError('Wazuh authentication response missing token')
    return token


def credential_shape(provider, token):
    """Diagnostic de forme sur un identifiant, sans jamais révéler sa valeur.

    Un 401 ne dit pas *pourquoi* il est refusé. La cause la plus fréquente en
    exploitation n'est pas un droit manquant mais une valeur mal recopiée :
    préfixe oublié, mauvais format d'export, copie tronquée. On ne renvoie donc
    que ce qui cloche dans la forme — jamais un extrait du secret.
    """
    if not token:
        return None
    if provider == 'Proxmox' and not token.startswith('PVEAPIToken='):
        return 'La variable doit contenir l’en-tête complet : PVEAPIToken=USER@REALM!ID=SECRET.'
    if provider == 'Wazuh' and ':' not in token:
        return 'La variable doit contenir « utilisateur:mot_de_passe », pas un jeton.'
    if provider == 'Bacula' and not token.startswith('Basic '):
        return ('Baculum utilise l’authentification Basic : la variable doit contenir '
                '« Basic » suivi d’un espace et de base64(utilisateur:mot_de_passe).')
    if provider == 'Elasticsearch':
        if not token.startswith(('ApiKey ', 'Basic ')):
            return ('La variable doit commencer par « ApiKey » suivi d’un espace et de la clé encodée, '
                    'par exemple ApiKey VnVhQ2ZH… — coller la clé seule ne suffit pas.')
        encoded = token.split(' ', 1)[1].strip()
        if token.startswith('ApiKey '):
            import base64
            import binascii
            try:
                decoded = base64.b64decode(encoded, validate=True).decode('utf-8', 'replace')
            except (binascii.Error, ValueError):
                return ('La valeur après « ApiKey » n’est pas du base64 valide. Dans Kibana, choisir le format '
                        '« Encoded » à la création de la clé, pas « Beats » ni « Logstash ».')
            if ':' not in decoded:
                return ('La clé décodée ne contient pas le couple identifiant:secret attendu. '
                        'Reprendre le format « Encoded » proposé par Kibana.')
    return None


def collection_error(exc):
    """Actionable diagnostics without echoing tokens, server bodies or request headers."""
    if isinstance(exc, urllib.error.HTTPError):
        messages = {
            401: 'Authentification refusée (HTTP 401). Vérifier le format Authorization, l’identifiant et la valeur du jeton (ou, pour Wazuh, le mot de passe).',
            403: 'Accès refusé (HTTP 403). Vérifier les permissions de lecture du compte et du jeton.',
            404: 'Endpoint absent (HTTP 404). Vérifier le chemin de l’URL API.',
        }
        return {'error_kind': 'http', 'http_status': exc.code,
                'error': messages.get(exc.code, 'Réponse HTTP ' + str(exc.code) + '. Vérifier le service API et l’URL ; les redirections ne sont pas suivies.')}
    reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    if isinstance(reason, DestinationRefused):
        return {'error_kind': 'destination',
                'error': 'Destination réseau refusée. Vérifier le DNS et l’URL de l’API ; '
                         'les adresses locales ou de lien local et les proxies implicites sont interdits.'}
    if isinstance(reason, ssl.SSLCertVerificationError):
        code = reason.verify_code
        hint = ('Le nom ou l’IP de l’URL ne correspond pas au certificat. Utiliser un nom présent dans le certificat (champ Subject Alternative Name).' if code in (62, 64)
                else 'Le certificat ne porte pas l’extension Key Usage exigée en mode strict. Le régénérer avec keyCertSign, ou utiliser le certificat de son autorité.' if code == 92
                else 'Le certificat est expiré ou pas encore valide. Vérifier sa période de validité et l’horloge des deux machines.' if code in (9, 10)
                else 'Certificat auto-signé non épinglé. Cliquer « Vérifier le certificat du serveur », comparer l’empreinte SHA-256 à celle affichée par le produit, puis l’épingler.' if code in (18, 19)
                else 'L’autorité du certificat n’est pas reconnue. Épingler le certificat vérifié, renseigner le fichier PEM de son autorité dans « Certificat CA », ou installer cette autorité dans le magasin de confiance.')
        return {'error_kind': 'tls_certificate', 'tls_verify_code': code, 'error': 'Échec de vérification TLS. ' + hint}
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return {'error_kind': 'timeout', 'error': 'Délai de connexion dépassé. Vérifier la route, le VPN, le port et la disponibilité du service.'}
    if isinstance(reason, socket.gaierror):
        return {'error_kind': 'dns', 'error': 'Nom DNS introuvable depuis le poste InfraOps. Vérifier l’URL et le DNS.'}
    if isinstance(reason, ConnectionRefusedError):
        return {'error_kind': 'connection_refused', 'error': 'Connexion refusée. Vérifier que le port de l’URL est bien celui de l’API et que le service écoute.'}
    if isinstance(reason, (FileNotFoundError, PermissionError)):
        return {'error_kind': 'ca_file', 'error': 'Le fichier CA est absent ou inaccessible au processus InfraOps. Vérifier le chemin local du fichier PEM.'}
    if isinstance(reason, ssl.SSLError) and getattr(reason, 'reason', '') in ('WRONG_VERSION_NUMBER', 'UNKNOWN_PROTOCOL', 'HTTP_REQUEST', 'PACKET_LENGTH_TOO_LONG'):
        # Signature sans ambiguïté : le serveur a renvoyé du texte HTTP là où un
        # enregistrement TLS était attendu. Le certificat n'est pas en cause,
        # c'est le service qui n'écoute pas en HTTPS sur ce port.
        return {'error_kind': 'tls_absent',
                'error': 'Ce service répond en HTTP en clair sur ce port : TLS n’y est pas activé. '
                         'Activer HTTPS côté serveur (certificat + SSLEngine on sur le bon VirtualHost, '
                         'puis apache2ctl configtest avant de recharger). InfraOps refuse le HTTP en clair '
                         'car les identifiants y circuleraient lisibles sur le réseau.'}
    if isinstance(reason, ssl.SSLError):
        return {'error_kind': 'tls', 'error': 'Erreur TLS. Vérifier le certificat CA au format PEM et la configuration HTTPS du serveur.'}
    if isinstance(reason, (json.JSONDecodeError, UnicodeDecodeError)):
        return {'error_kind': 'json', 'error': 'La réponse reçue n’est pas un JSON valide. Vérifier que l’URL cible l’API et non l’interface web du produit.'}
    if isinstance(reason, ValueError) and str(reason) == 'Bacula PHP DOM unavailable':
        return {'error_kind': 'bacula_php_dom',
                'error': 'Baculum répond avec une erreur PHP/Prado : DOMDocument indisponible dans le moteur web. '
                         'Vérifier le PHP et l’extension DOM chargés par Apache ; le tunnel répond. '
                         'Aucun redémarrage n’est exécuté par OpsControl.'}
    if isinstance(reason, ValueError) and str(reason) == 'Bacula response too large':
        return {'error_kind': 'response_limit', 'error': 'Historique Bacula supérieur à 16 Mio. Une collecte paginée est nécessaire.'}
    if isinstance(reason, ValueError) and str(reason) == 'Response too large':
        return {'error_kind': 'response_limit', 'error': 'Réponse supérieure à la limite de 1 Mo.'}
    if isinstance(reason, ValueError) and str(reason) == 'API error response':
        return {'error_kind': 'api', 'error': 'L’API a retourné une erreur applicative. Vérifier son état et les droits du jeton.'}
    if isinstance(reason, ValueError) and str(reason) == 'Proxmox resources response invalid':
        return {'error_kind': 'proxmox_format', 'error': 'Réponse Proxmox inattendue : utiliser /api2/json/cluster/resources pour collecter les nœuds et leurs VM.'}
    if isinstance(reason, ValueError) and str(reason) == 'Bacula response invalid':
        return {'error_kind': 'bacula_format', 'error': 'Réponse Baculum inattendue : vérifier que l’URL cible /api/v2/jobs.'}
    if isinstance(reason, ValueError) and str(reason) == 'Zabbix response invalid':
        return {'error_kind': 'zabbix_format', 'error': 'Réponse Zabbix inattendue : vérifier que l’URL cible bien /api_jsonrpc.php.'}
    if isinstance(reason, ValueError) and str(reason).startswith('Zabbix API error'):
        return {'error_kind': 'zabbix_api', 'error': str(reason) + ' Vérifier le jeton, ses droits de lecture et la version de l’API (jeton Bearer à partir de Zabbix 6.4).'}
    if isinstance(reason, ValueError) and str(reason) == 'Wazuh response invalid':
        return {'error_kind': 'wazuh_format', 'error': 'Réponse Wazuh inattendue : vérifier que l’URL cible /manager/status.'}
    if isinstance(reason, ValueError) and str(reason) == 'Wazuh credentials must be user:password':
        return {'error_kind': 'wazuh_credentials', 'error': 'Pour Wazuh, la variable doit contenir « utilisateur:mot_de_passe », pas un jeton ou un en-tête Authorization.'}
    if isinstance(reason, ValueError) and str(reason) == 'Wazuh authentication response missing token':
        return {'error_kind': 'wazuh_auth', 'error': 'Authentification Wazuh acceptée mais réponse sans jeton : vérifier la version de l’API.'}
    return {'error_kind': 'network_or_local', 'error': 'Connexion impossible ou erreur locale. Vérifier le réseau et le format de l’en-tête Authorization (sans retour à la ligne).'}


def _count(value, maximum=None):
    """Nombre fini, positif, borné ; jamais un booléen (True est un int en Python).

    NaN accepté ici était enregistré puis rendait GET /api/connections non sérialisable
    pour TOUTES les sources (OC-AUDIT-020)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        return False
    return maximum is None or value <= maximum


def strict_json(body):
    """json.loads refusant NaN/Infinity : non conformes à JSON, ils cassaient la réponse HTTP."""
    def refuse(constant):
        raise ValueError(f'Valeur JSON non conforme : {constant}')
    return json.loads(body, parse_constant=refuse)


def indicators(provider, payload):
    """Extract only expected status enums and numbers, never arbitrary API content."""
    if not isinstance(payload, dict):
        return {}
    if provider == 'Elasticsearch':
        bounds = {'active_shards_percent_as_number': 100}
        result = {k: payload[k] for k in ('number_of_nodes', 'number_of_data_nodes', 'active_shards', 'unassigned_shards', 'active_shards_percent_as_number') if _count(payload.get(k), bounds.get(k))}
        if payload.get('status') in ('green', 'yellow', 'red'):
            result['cluster_status'] = payload['status']
        return result
    data = payload.get('data')
    if provider == 'Proxmox' and isinstance(data, list):
        return {'resources': len(data), 'running': sum(isinstance(x, dict) and x.get('status') == 'running' for x in data), 'stopped': sum(isinstance(x, dict) and x.get('status') == 'stopped' for x in data)}
    if provider == 'Wazuh' and isinstance(data, dict):
        items = data.get('affected_items', [])
        values = [v for x in items if isinstance(x, dict) for v in x.values()] if isinstance(items, list) else []
        return {'running_daemons': sum(v == 'running' for v in values), 'stopped_daemons': sum(v == 'stopped' for v in values)}
    if provider == 'Bacula' and isinstance(payload.get('output'), list):
        rows = [x for x in payload['output'] if isinstance(x, dict)]
        codes = [str(x.get('jobstatus') or '') for x in rows]
        return {'jobs_total': len(rows),
                'jobs_ok': sum(c == 'T' for c in codes),
                'jobs_warning': sum(c in ('W', 'A', 'I', 'B') for c in codes),
                'jobs_error': sum(c in ('E', 'f') for c in codes),
                'jobs_running': sum(c == 'R' for c in codes)}
    if provider == 'Zabbix' and isinstance(payload.get('result'), list):
        # Réponse de host.get : on ne compte que ce que le jeton a pu voir.
        rows = [x for x in payload['result'] if isinstance(x, dict)]
        return {'monitored_hosts': sum(str(x.get('status', '')) == '0' for x in rows),
                'unmonitored_hosts': sum(str(x.get('status', '')) == '1' for x in rows)}
    return {}


def install(app, context):
    from fastapi import APIRouter
    router = APIRouter()
    base, hosts = context.BASE, context.HOSTS
    api_file = base / 'data/api-connections.json'
    api_lock = threading.Lock()
    bindings = TokenBindings(base / 'data/token-bindings.json')
    global ACTIVE_BINDINGS, ACTIVE_BASE
    ACTIVE_BINDINGS, ACTIVE_BASE = bindings, base
    # Balayage réseau déclenché par une collecte Proxmox : au plus un par fenêtre de 60 s
    # (même fenêtre que le quota collect_all d'access_policy).
    sweep_state = {'at': float('-inf')}
    collecting = set()
    revision = 0
    last_change = {'revision': 0, 'source': None, 'provider': None}

    def api_revision():
        with api_lock:
            return revision

    context.api_revision = api_revision

    def api_change():
        """Dernière source modifiée, pour cibler les rafraîchissements SSE."""
        with api_lock:
            return dict(last_change)

    context.api_change = api_change

    def mark_change_locked(key=None, provider=None):
        """Incrémente la révision. L'appelant détient déjà ``api_lock``."""
        nonlocal revision
        revision += 1
        last_change.update(revision=revision, source=key, provider=provider)

    @router.get('/api/waf/{key}/bans')
    def waf_ban_analysis(key: str):
        """IP bannies analysées (waf_bans.py), depuis la dernière collecte enregistrée ; lecture seule."""
        import waf_bans
        from waf_audit import is_waf_host
        target = next((h for h in hosts if h['key'] == key), None)
        if not target or not is_waf_host(target):
            raise HTTPException(404, 'Serveur WAF inconnu')
        row = next((r for r in context.rows() if r['key'] == key), None) or {}
        inventory = {h['ip']: h['name'] for h in hosts if h.get('ip')}
        history = waf_bans.observed_history(context.connect, key, target['ip'])
        from ip_location import locator
        return {**waf_bans.analyze(row.get('waf') or {}, target['ip'], inventory, history, locator()), 'stale': bool(row.get('stale'))}

    @router.post('/api/waf/commands')
    def waf_commands(request: WafCommand):
        from waf_findings import command_plan
        from waf_audit import is_waf_host
        target = next((h for h in hosts if h['key'] == request.host_key), None)
        if not target or not is_waf_host(target):
            raise HTTPException(422, 'Serveur WAF inconnu ou rôle différent de « WAF ModSecurity »')
        try:
            return command_plan(request.ip, request.action, target['ip'])
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    # Lectures : fichier (~450 Ko, ~20 ms à analyser) relu seulement s'il a changé (date,
    # taille). Écritures : toujours une copie fraîche (fresh=True), modifiée puis réécrite ;
    # la réécriture change la date du fichier et invalide le cache.
    cache = {'stamp': None, 'items': []}

    def connections(fresh=False):
        try:
            info = api_file.stat()
        except FileNotFoundError:
            return []
        stamp = (info.st_mtime_ns, info.st_size)
        if fresh:
            return json.loads(api_file.read_text(encoding='utf-8'))
        if cache['stamp'] != stamp:
            cache['items'], cache['stamp'] = json.loads(api_file.read_text(encoding='utf-8')), stamp
        return cache['items']

    def save_hosts(updated):
        save_inventory(context, updated)

    def collecting_now():
        return bool(context.job['running'] or context.net_job['running'])

    # Purges du cache réseau en échec après un enregistrement déjà effectif : retentées
    # au prochain enregistrement ; la prochaine collecte réseau remplace aussi la ligne.
    purge_pending = set()

    def purge_network(keys):
        """Cache dérivé seulement : son échec n'annule pas l'enregistrement (audit A4)."""
        keys = set(keys) | purge_pending
        try:
            with context.connect() as db:
                db.executemany('DELETE FROM network WHERE key=?', [(k,) for k in sorted(keys)])
        except Exception as exc:
            purge_pending.update(keys)
            monitor = getattr(context, 'MONITOR', None)
            if monitor:
                monitor.error('Purge du cache réseau après enregistrement : ' + type(exc).__name__, source='inventaire')
            return False
        purge_pending.difference_update(keys)
        return True

    context.purge_network_cache = purge_network

    def outcome(item, synced):
        """Contrat de résultat : la configuration est enregistrée dans hosts.yaml ; le
        message dit quand elle s'applique et si une opération dérivée reste à faire."""
        running = collecting_now()
        if not synced:
            message = 'Configuration enregistrée. Synchronisation du cache réseau en attente : reprise automatique.'
        elif running:
            message = ('Configuration enregistrée. Collecte en cours avec les paramètres précédents : '
                       'les nouveaux s’appliquent au prochain lot.')
        else:
            message = 'Configuration enregistrée.'
        return {**item, 'revision': config_revision(item), 'saved': True, 'applies': 'next_batch' if running else 'now',
                'sync_pending': not synced, 'message': message}

    def add_discovered(additions):
        # Plus de refus pendant une collecte : chaque lot travaille sur une copie figée
        # des serveurs (jobs.launch), un ajout ne change donc pas le travail en cours.
        with context.lock, context.net_lock:
            added = []
            for item in additions:
                Server.model_validate({k: v for k, v in item.items() if k in Server.model_fields})
                if not any(h['key'] == item['key'] or h['ip'] == item['ip'] for h in hosts + added):
                    added.append({**item, 'admin_enrolled_at': datetime.now(timezone.utc).isoformat()})
            if added:
                save_hosts(hosts + added)
            return added

    context.add_discovered_hosts = add_discovered

    @router.get('/api/manage/hosts/{key}')
    def server_config(key: str):
        """Entrée d'inventaire telle qu'enregistrée (port absent = hérité), sa révision et
        les paramètres SSH effectifs avec leur origine. Aucun secret : chemins seulement."""
        entry = next((h for h in hosts if h['key'] == key), None)
        if entry is None:
            raise HTTPException(404, 'Serveur inconnu')
        return {'host': entry, 'revision': config_revision(entry),
                'effective': ssh_effective(getattr(context, 'cfg', None), entry), 'collecting': collecting_now()}

    @router.get('/api/manage/ssh-profile')
    def ssh_profile():
        """Profil SSH hérité par un nouveau serveur, pour le formulaire d'ajout."""
        return {'effective': ssh_effective(getattr(context, 'cfg', None), {}), 'collecting': collecting_now()}

    @router.post('/api/manage/hosts')
    def save_server(server: Server):
        with context.lock, context.net_lock:
            prior = next((h for h in hosts if h['key'] == server.key), {})
            item = {**prior, **server.model_dump(exclude=REQUEST_ONLY)}
            if not item['user']:
                item.pop('user')
            if item['port'] is None:
                item.pop('port')
            if server.mode == 'create' and prior:
                # Nouvelle tentative (double clic, réseau coupé après l'écriture) : même
                # contenu, même résultat. Sinon, conflit : l'autre serveur reste intact.
                if item == prior:
                    return outcome(prior, purge_network([server.key])) | {'unchanged': True}
                raise HTTPException(409, f'Identifiant « {server.key} » déjà utilisé par {prior.get("name")} '
                                         f'({prior.get("ip")}). Choisir un autre identifiant ou modifier ce serveur.')
            if server.mode == 'update':
                if not prior:
                    raise HTTPException(404, 'Serveur inconnu : supprimé entre-temps ? Rouvrir la liste.')
                if server.revision and server.revision != config_revision(prior):
                    if item == prior:
                        # Réponse perdue après écriture : reprendre le cache sans rejouer
                        # une modification et sans transformer le succès en conflit.
                        return outcome(prior, purge_network([server.key])) | {'unchanged': True}
                    raise HTTPException(409, 'Configuration modifiée entre-temps par une autre action. '
                                             'Rouvrir le formulaire pour partir de la version enregistrée.')
            if any(h['ip'] == server.ip and h['key'] != server.key for h in hosts):
                other = next(h for h in hosts if h['ip'] == server.ip and h['key'] != server.key)
                raise HTTPException(409, f'Adresse IP déjà présente : {other.get("name")} ({other["key"]}).')
            # Inscription administrative : le serveur apparaît dans le parc sans attendre une
            # preuve SSH ou Proxmox. Elle n'approuve aucune empreinte SSH (asset_registry.admitted).
            if not prior:
                item['admin_enrolled_at'] = datetime.now(timezone.utc).isoformat()
            # Plus de refus pendant une collecte (audit A1) : le lot en cours garde sa copie
            # figée de l'ancienne configuration (jobs.launch) et ses résultats portent
            # l'empreinte de cette configuration ; la nouvelle s'applique au lot suivant.
            updated = [item if h['key'] == server.key else h for h in hosts]
            if not prior:
                updated.append(item)
            save_hosts(updated)
            return outcome(item, purge_network([server.key]))

    @router.post('/api/manage/hosts/{key}/delete')
    def delete_server(key: str):
        with context.lock, context.net_lock:
            if context.job['running'] or context.net_job['running']:
                raise HTTPException(409, 'Attendre la fin des collectes')
            if not any(h['key'] == key for h in hosts):
                raise HTTPException(404, 'Serveur inconnu')
            save_hosts([h for h in hosts if h['key'] != key])
            try:
                with context.connect() as db:
                    # Échantillons Apache et états batch du serveur retiré aussi (audit DB-05) ;
                    # les audits complets suivent la règle des orphelins (retention.py).
                    for table in ('states', 'network', 'history', 'apache_samples', 'batch_states'):
                        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
                            db.execute(f'DELETE FROM {table} WHERE key=?', (key,))
            except Exception as exc:
                # Retrait déjà effectif dans hosts.yaml : ne pas l'annoncer comme un échec.
                monitor = getattr(context, 'MONITOR', None)
                if monitor:
                    monitor.error('Purge de l’historique local après retrait : ' + type(exc).__name__, source='inventaire')
                return {'deleted': key, 'sync_pending': True,
                        'message': 'Serveur retiré du suivi. Purge de son historique local en attente.'}
            return {'deleted': key, 'sync_pending': False, 'message': 'Serveur retiré du suivi.'}

    def list_connections(provider: str | None = None, compact: bool = False, admin: bool = True):
        """Connexions et dernier résultat. Appels internes (context.api_connections) : complet."""
        with api_lock:
            items = connections()
            if provider:
                items = [item for item in items if str(item.get('provider', '')).casefold() == provider.casefold()]
            result = [{**item, 'auth_configured': bool(os.getenv(item.get('token_env', ''), '')) if item.get('token_env') else None} for item in items]
            if compact:
                keep = ('status', 'collected_at', 'error', 'warning', 'summary', 'indicators')
                for item in result:
                    for field in ('last_result', 'last_success_result'):
                        value = item.get(field)
                        if isinstance(value, dict):
                            item[field] = {key: value[key] for key in keep if key in value}
            if not admin:
                # URL interne, chemin ou certificat d'ancrage, nom de variable : utiles à
                # l'administration des connexions seulement, pas à la lecture des résultats.
                for item in result:
                    for field in ('url', 'ca_bundle', 'token_env'):
                        item.pop(field, None)
            return result

    @router.get('/api/connections')
    def list_connections_route(request: Request, provider: str | None = None, compact: bool = False):
        import access_policy
        return list_connections(provider, compact, admin=access_policy.allowed(access_policy.role_of(request), 'admin'))

    @router.post('/api/connections')
    def save_connection(connection: Connection):
        if connection.host_key and not any(h['key'] == connection.host_key for h in hosts):
            raise HTTPException(422, 'Serveur associé inconnu')
        refus = bindings.refusal(connection.token_env, connection.url) or ca_file_refused(base, connection.ca_bundle)
        if refus:
            raise HTTPException(422, refus)
        with api_lock:
            items = connections(fresh=True)
            prior = next((x for x in items if x['key'] == connection.key), {})
            item = {**prior, **connection.model_dump()}
            # Observations belong to one endpoint/account scope, not to its label.
            if any(prior.get(k) != item.get(k) for k in ('provider', 'url', 'host_key', 'token_env')):
                item.pop('last_result', None)
                item.pop('last_success_result', None)
            items = [x for x in items if x['key'] != connection.key] + [item]
            atomic_json(api_file, items)
            mark_change_locked(item.get('key'), item.get('provider'))
            return item

    @router.post('/api/connections/{key}/delete')
    def delete_connection(key: str):
        with api_lock:
            items = connections(fresh=True)
            removed = next((x for x in items if x['key'] == key), None)
            atomic_json(api_file, [x for x in items if x['key'] != key])
            if removed:
                mark_change_locked(key, removed.get('provider'))
        return {'deleted': key}

    @router.post('/api/connections/certificate')
    def connection_certificate(probe: CertificateProbe):
        u = urlsplit(probe.url)
        if u.scheme != 'https' or not u.hostname:
            raise HTTPException(422, 'URL HTTPS requise')
        port = u.port or 443
        configured = {urlsplit(c.get('url', '')).port for c in connections()}
        if port not in PROBE_PORTS | configured:
            raise HTTPException(422, f'Port {port} non autorisé pour l’inspection de certificat '
                                     f'(ports d’API : {", ".join(str(p) for p in sorted(PROBE_PORTS))})')
        refus = destination_refused(probe.url)
        if refus:
            raise HTTPException(422, refus)
        try:
            return probe_certificate(u.hostname, u.port or 443)
        except Exception as exc:
            raise HTTPException(422, 'Certificat introuvable : ' + collection_error(exc)['error']) from exc

    context.api_connections = list_connections

    @router.post('/api/connections/{key}/collect')
    def collect_connection(key: str):
        # Manual, full and fast cycles share the same per-source exclusion.
        with api_lock:
            if key in collecting:
                return {'status': 'busy'}
            collecting.add(key)
        try:
            return collect_connection_once(key)
        finally:
            with api_lock:
                collecting.discard(key)

    def collect_connection_once(key: str):
        nonlocal revision
        with api_lock:
            item = next((x for x in connections() if x['key'] == key), None)
        if item is None:
            raise HTTPException(404, 'Connexion inconnue')
        # Configuration telle qu'enregistrée : `item` reçoit ensuite des paramètres de
        # transport (CA relative rendue absolue) qui ne doivent pas servir à la comparaison
        # finale, sinon le résultat d'une connexion à CA relative n'était jamais enregistré.
        configured = item
        headers = {'Accept': 'application/json'}
        # Revalidation à la collecte : un fichier de connexions modifié à la main ne
        # doit pas pouvoir désigner une autre variable que le jeton du produit.
        try:
            token_env_allowed(item.get('token_env'), item.get('provider'))
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        token = os.getenv(item['token_env'], '') if item['token_env'] else ''
        if item['token_env'] and not token:
            raise HTTPException(422, 'Variable du jeton absente sur le serveur InfraOps')
        # Le fichier de connexions peut avoir été modifié à la main : on revérifie ici.
        refus = destination_refused(item['url']) or ca_file_refused(base, item.get('ca_bundle'))
        if refus:
            raise HTTPException(422, refus)
        item = transport_for(item, base)  # chemin relatif à data/ca/
        if token:
            try:
                bindings.check_and_bind(item['token_env'], item['url'])
            except ValueError as exc:
                raise HTTPException(422, str(exc)) from None
        provider = item.get('provider')
        result = {'collected_at': datetime.now(timezone.utc).isoformat(), 'status': 'unknown'}
        try:
            # `tls_context`, pas `context` : ce nom est déjà celui du module
            # applicatif passé à install(), le masquer ici serait un piège.
            local_bacula = item['url'] == BACULA_TUNNEL_URL and provider == 'Bacula'
            if urlsplit(item['url']).scheme != 'https' and not local_bacula:
                raise ValueError('HTTPS required')
            tls_context = ssl_context_for(item) if not local_bacula else None
            if provider == 'Wazuh':
                # Wazuh's JWT expires in minutes; re-authenticate with user:password on
                # every collection instead of relying on a token pasted in once.
                if token:
                    headers['Authorization'] = 'Bearer ' + wazuh_token(item['url'], token, tls_context, 10)
            elif token:
                # Zabbix >= 6.4 attend un jeton Bearer ; Proxmox PVEAPIToken=...,
                # Elasticsearch ApiKey ... ; Bacula dépend de son édition.
                headers['Authorization'] = 'Bearer ' + token if provider == 'Zabbix' else token
            opener = api_opener(tls_context, local_bacula=local_bacula)
            if local_bacula:
                result['transport'] = 'Tunnel SSH local requis sur 127.0.0.1:19096'
            response_limit = 16 * 1048576 if provider == 'Bacula' else 1048576

            def fetch(request):
                """Lit une réponse JSON en appliquant la limite de taille commune."""
                with opener.open(request, timeout=10) as response:
                    body = response.read(response_limit + 1)
                if len(body) > response_limit:
                    raise ValueError('Bacula response too large' if provider == 'Bacula' else 'Response too large')
                if (provider == 'Bacula' and body.lstrip().startswith(b'<')
                        and b'DOMDocument' in body and b'TInvalidOperationException' in body):
                    raise ValueError('Bacula PHP DOM unavailable')
                return body, strict_json(body)

            def sibling(path):
                """Même hôte et même port que l'URL configurée, autre chemin."""
                return urlsplit(item['url'])._replace(path=path, query='').geturl()

            if provider == 'Zabbix':
                spec = READ_ONLY_RPC['Zabbix']
                legacy, payloads, raw = None, {}, b''
                def rpc_failure(answer):
                    failure = answer.get('error') if isinstance(answer, dict) else None
                    if not isinstance(failure, dict):
                        return None
                    return str(failure.get('data') or failure.get('message') or 'réponse en erreur')[:200]

                for index, (name, body) in enumerate(spec['calls']):
                    fetched, answer = fetch(rpc_request(item['url'], body, headers, spec['content_type'], legacy))
                    failure = rpc_failure(answer)
                    # Zabbix < 6.4 ignore l'en-tête Authorization et attend le jeton
                    # dans le champ `auth`. Un seul repli, sur la première requête.
                    if failure and legacy is None and token and index == 0:
                        bearer_failure, legacy = failure, token
                        fetched, answer = fetch(rpc_request(item['url'], body, headers, spec['content_type'], legacy))
                        failure = rpc_failure(answer)
                        if failure:
                            # Les deux modes ont échoué : rapporter les deux diagnostics.
                            # N'en montrer qu'un ferait chercher au mauvais endroit —
                            # le message du mode ancien parle de « session » là où le
                            # vrai sujet est la validité du jeton d'API.
                            failure = f'en-tête Bearer → « {bearer_failure} » ; champ auth → « {failure} »'
                        else:
                            legacy = token
                    if failure:
                        raise ValueError('Zabbix API error : ' + failure + '.')
                    payloads[name] = answer
                    if index == 0:
                        raw = fetched
                payload = payloads['hosts']
                from zabbix_inventory import inventory as zabbix_inventory
                result['inventory'] = zabbix_inventory(payload, payloads.get('problems'))
                if result['inventory']['empty']:
                    result['warning'] = 'Aucun hôte visible. Vérifier les droits du jeton sur les groupes d’hôtes ; cela ne prouve pas que Zabbix ne supervise rien.'
                if legacy:
                    result['warning'] = (result.get('warning', '') + ' Jeton transmis en mode compatibilité (Zabbix antérieur à 6.4).').strip()
            else:
                # Bacula : fenêtre des derniers passages si une lecture complète de moins de 24 h
                # sert de base (fiche 09.3). La requête est construite ici : l'URL configurée
                # reste sans paramètre (validation de la connexion inchangée).
                bacula_base = prior_inventory = None
                if provider == 'Bacula':
                    from bacula_inventory import WINDOW, window_base
                    # Dernier résultat réussi : last_result s'il est observé (last_success_result
                    # n'est conservé qu'après un échec).
                    last = item.get('last_result') or {}
                    prior_inventory = (last if last.get('status') == 'observed' else item.get('last_success_result') or {}).get('inventory')
                    bacula_base = window_base(prior_inventory, datetime.now(timezone.utc))
                url = urlsplit(item['url'])._replace(query=f'limit={WINDOW}').geturl() if bacula_base else item['url']
                raw, payload = fetch(urllib.request.Request(url, headers=headers))
                if isinstance(payload, dict) and payload.get('error'):
                    raise ValueError('API error response')
            if provider == 'Proxmox':
                from proxmox_inventory import inventory, cluster_info
                result['inventory'] = inventory(payload)
                if result['inventory']['empty']:
                    result['warning'] = 'Aucun nœud ni VM visible. Vérifier le périmètre des permissions du compte et du jeton ; cela ne prouve pas que le cluster est vide.'
                parsed = urlsplit(item['url'])
                if parsed.path.rstrip('/').endswith('/cluster/resources'):
                    status_url = parsed._replace(path=parsed.path.rstrip('/').rsplit('/', 1)[0] + '/status').geturl()
                    try:
                        result['inventory']['cluster'] = cluster_info(fetch(urllib.request.Request(status_url, headers=headers))[1])
                    except Exception as exc:
                        result['inventory']['cluster_error'] = collection_error(exc)['error']
            if provider == 'Bacula':
                from bacula_inventory import inventory as bacula_inventory, merge as bacula_merge
                client_names = {}
                try:
                    clients = fetch(urllib.request.Request(sibling('/api/v2/clients'), headers=headers))[1]
                    if clients.get('error') or not isinstance(clients.get('output'), list):
                        raise ValueError('Bacula response invalid')
                    client_names = {str(c.get('clientid')): c.get('name') for c in clients['output'] if isinstance(c, dict)}
                except Exception as exc:
                    result.setdefault('secondary_errors', {})['clients'] = collection_error(exc)['error']

                def named(answer):
                    return {**answer, 'output': [{**j, 'client': client_names.get(str(j.get('clientid'))) or j.get('client')}
                                                 if isinstance(j, dict) else j for j in answer.get('output', [])]}
                inventory_now, mode = bacula_merge(bacula_base, named(payload)) if bacula_base else (None, None)
                if bacula_base and inventory_now is None:
                    # Fenêtre non concluante : relecture complète, motif conservé dans le résultat.
                    result['collection_note'] = 'Fenêtre écartée (' + mode + ') : relecture complète.'
                    raw, payload = fetch(urllib.request.Request(item['url'], headers=headers))
                    if isinstance(payload, dict) and payload.get('error'):
                        raise ValueError('API error response')
                if inventory_now is None or mode == 'full':
                    inventory_now = inventory_now if mode == 'full' else bacula_inventory(named(payload))
                    inventory_now['full_at'] = result['collected_at']
                    from bacula_inventory import window_blocked
                    blocked = window_blocked(prior_inventory, datetime.now(timezone.utc))
                    if bacula_base and mode != 'full':
                        inventory_now.update(window_unsupported_at=result['collected_at'], window_unsupported=mode)
                    elif blocked:
                        inventory_now.update(window_unsupported_at=blocked,
                                             window_unsupported=prior_inventory.get('window_unsupported'))
                result['inventory'] = inventory_now
                if result['inventory']['empty']:
                    result['warning'] = ('Aucun job visible. Vérifier les droits de lecture du compte API Baculum ; '
                                         'cela ne prouve pas qu’aucune sauvegarde n’a tourné.')
            if provider == 'Wazuh':
                # Deux sources secondaires, en lecture seule comme la principale.
                # Leur échec n'invalide pas la collecte : l'interface signale
                # simplement que la donnée n'a pas été mesurée.
                from wazuh_inventory import inventory as wazuh_inventory
                extras = {}
                for name, path in (('agents', '/agents/summary/status'), ('manager', '/manager/info')):
                    try:
                        extras[name] = fetch(urllib.request.Request(sibling(path), headers=headers))[1]
                    except Exception as exc:
                        result.setdefault('secondary_errors', {})[name] = collection_error(exc)['error']
                        extras[name] = None
                result['inventory'] = wazuh_inventory(payload, extras['agents'], extras['manager'])
                try:
                    agents = fetch(urllib.request.Request(sibling('/agents') + '?limit=500&select=id,name,ip,status,version,lastKeepAlive', headers=headers))[1]
                    rows = agents.get('data', {}).get('affected_items', [])
                    if agents.get('error') or not isinstance(rows, list):
                        raise ValueError('Wazuh response invalid')
                    result['inventory']['agents_inventory'] = [{k: a.get(k) for k in ('id','name','ip','status','version','lastKeepAlive')} for a in rows if isinstance(a, dict)]
                    result['inventory']['agents_inventory_total'] = agents.get('data', {}).get('total_affected_items')
                    result['inventory']['agents_inventory_scope'] = 'Au maximum 500 agents visibles ; absence de correspondance ne prouve pas une absence de protection.'
                except Exception as exc:
                    result.setdefault('secondary_errors', {})['agents_inventory'] = collection_error(exc)['error']
            # Raw API bodies may contain secrets; expose structure and counts only.
            result.update(status='observed', summary={
                'type': type(payload).__name__,
                'entries': len(payload) if isinstance(payload, (list, dict)) else 1,
                'bytes': len(raw),
            })
            result['indicators'] = indicators(provider, payload)
        except Exception as exc:
            result.update(collection_error(exc))
            if result.get('http_status') in (401, 403):
                # Un refus d'authentification vient bien plus souvent d'une valeur
                # mal recopiée que d'un droit manquant : le dire évite de partir
                # chercher des permissions côté produit.
                hint = credential_shape(provider, token)
                if hint:
                    result['error'] += ' ' + hint
        with api_lock:
            items = connections(fresh=True)
            current = next((x for x in items if x['key'] == key), None)
            if current and all(current.get(k) == configured.get(k) for k in ('provider', 'url', 'token_env', 'host_key', 'ca_bundle')):
                if result.get('status') == 'observed':
                    current.pop('last_success_result', None)
                elif (current.get('last_result') or {}).get('status') == 'observed':
                    current['last_success_result'] = current['last_result']
                current['last_result'] = result
                atomic_json(api_file, items)
                mark_change_locked(key, provider)
        # A refreshed VM state also requires a current ping for the online view.
        # The existing network lock prevents concurrent duplicate network batches.
        # Au plus une fois par fenêtre du quota « collect_all » (60 s) : une collecte Proxmox
        # manuelle (quota collect_one, 10/min) relançait sinon un balayage réseau du parc entier
        # à chaque appel, hors du quota prévu pour les collectes complètes.
        if provider == 'Proxmox' and result.get('status') == 'observed' and hasattr(context, 'launch_network'):
            now = time.monotonic()
            if now - sweep_state['at'] >= SWEEP_MIN_INTERVAL:
                sweep_state['at'] = now
                context.launch_network(context.HOSTS, 'collecte-proxmox')
        return result

    context.collect_api_connection = collect_connection
    app.include_router(router)  # routes de ce module : APIRouter, inclus en fin d'installation
