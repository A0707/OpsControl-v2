"""Client REST V1 GLPI 11 : appels explicites, HTTPS et erreurs expurgées.

HTTP en clair seulement par dérogation explicite (GLPI_ALLOW_HTTP=true) et pour un hôte
listé dans GLPI_HTTP_HOSTS : les jetons traversent alors le réseau interne sans
chiffrement. La dérogation est signalée dans l'interface, jamais implicite."""

from __future__ import annotations

import json
import os
import ssl
from contextlib import contextmanager
from dataclasses import dataclass, field
from urllib import error, parse, request


class GlpiError(Exception):
    def __init__(self, message, uncertain=False):
        super().__init__(message)
        self.uncertain = uncertain


@dataclass(frozen=True)
class Settings:
    base: str
    app_token: str = field(repr=False)
    user_token: str = field(repr=False)
    entity: int = 0
    requester: int = 0
    observer: int = 0
    timeout: int = 15
    # Dérogation HTTP active : affichée dans l'interface comme transport non chiffré.
    insecure: bool = False

    @classmethod
    def load(cls):
        if os.getenv("GLPI_ENABLED", "false").lower() != "true":
            raise GlpiError("Connecteur GLPI désactivé")
        base = os.getenv("GLPI_BASE_URL", "").rstrip("/")
        url = parse.urlsplit(base)
        insecure = url.scheme == "http" and http_allowed(url.hostname)
        if (
            (url.scheme != "https" and not insecure)
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
        ):
            raise GlpiError(
                "GLPI_BASE_URL doit être une URL HTTPS sans credentials ni paramètres "
                "(HTTP : GLPI_ALLOW_HTTP=true et hôte listé dans GLPI_HTTP_HOSTS)"
            )
        if os.getenv("GLPI_VERIFY_TLS", "true").lower() != "true":
            raise GlpiError("La validation TLS GLPI est obligatoire")
        try:
            values = [
                int(os.getenv(k, d))
                for k, d in (
                    ("GLPI_ENTITY_ID", "0"),
                    ("GLPI_REQUESTER_ID", "0"),
                    ("GLPI_OBSERVER_GROUP_ID", "0"),
                    ("GLPI_TIMEOUT_SECONDS", "15"),
                )
            ]
            if values[0] < 0 or min(values[1:3]) < 1 or not 1 <= values[3] <= 60:
                raise ValueError
            tokens = [os.getenv(k, "") for k in ("GLPI_APP_TOKEN", "GLPI_USER_TOKEN")]
            if any(not t or len(t) > 512 or any(c.isspace() for c in t) for t in tokens):
                raise ValueError
        except ValueError:
            raise GlpiError("Configuration GLPI invalide : identifiants, jetons ou délai") from None
        return cls(base, *tokens, *values, insecure=insecure)


def http_allowed(hostname):
    """Vrai si HTTP est explicitement autorisé pour cet hôte précis (liste fermée)."""
    if os.getenv("GLPI_ALLOW_HTTP", "false").lower() != "true" or not hostname:
        return False
    hosts = {h.strip().lower() for h in os.getenv("GLPI_HTTP_HOSTS", "").split(",") if h.strip()}
    return hostname.lower() in hosts


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Un changement de destination ne doit jamais emporter les jetons.
        return None


class Client:
    def __init__(self, settings):
        self.settings = settings
        self.session = None
        self.opener = request.build_opener(
            NoRedirect(), request.HTTPSHandler(context=ssl.create_default_context())
        )

    def call(self, method, path, payload=None):
        headers = {"Content-Type": "application/json", "App-Token": self.settings.app_token}
        if self.session:
            headers["Session-Token"] = self.session
        else:
            headers["Authorization"] = "user_token " + self.settings.user_token
        req = request.Request(
            self.settings.base + "/apirest.php/" + path,
            data=json.dumps(payload).encode() if payload is not None else None,
            headers=headers,
            method=method,
        )
        try:
            with self.opener.open(req, timeout=self.settings.timeout) as response:
                raw = response.read(2_000_001)
                if len(raw) > 2_000_000:
                    raise ValueError
                return json.loads(raw)
        except error.HTTPError as exc:
            labels = {
                400: "requête refusée",
                401: "jeton invalide",
                403: "droits insuffisants",
                404: "ressource introuvable",
                409: "conflit",
                429: "quota dépassé",
            }
            raise GlpiError(
                f"GLPI HTTP {exc.code} : {labels.get(exc.code, 'service indisponible')}",
                uncertain=method == "POST" and exc.code not in (400, 401, 403, 404, 409, 429),
            ) from None
        except (OSError, error.URLError, ValueError):
            raise GlpiError(
                "GLPI : transport interrompu ou réponse inattendue", uncertain=method == "POST"
            ) from None

    @contextmanager
    def opened(self):
        try:
            result = self.call("GET", "initSession")
            token = result.get("session_token") if isinstance(result, dict) else None
            if (
                not isinstance(token, str)
                or not token
                or len(token) > 512
                or any(c.isspace() for c in token)
            ):
                raise GlpiError("GLPI : session invalide")
            self.session = token
            yield self
        finally:
            if self.session:
                try:
                    self.call("GET", "killSession")
                except GlpiError:
                    pass  # La fermeture ne doit pas masquer le résultat de création.
                self.session = None

    def create(self, kind, payload):
        result = self.call("POST", kind + "/", {"input": payload})
        ident = result.get("id") if isinstance(result, dict) else None
        if type(ident) is not int or ident <= 0:
            raise GlpiError("GLPI : création sans identifiant confirmé", uncertain=True)
        return ident

    def read(self, kind, ident):
        result = self.call("GET", f"{kind}/{ident}")
        if (
            not isinstance(result, dict)
            or str(result.get("id")) != str(ident)
            or not isinstance(result.get("name"), str)
        ):
            raise GlpiError("GLPI : objet retourné inattendu")
        return result

    def solve(self, kind, ident, content):
        """Solution ITIL : GLPI passe l'objet à « Résolu ». Seule écriture hors création."""
        return self.create(
            "ITILSolution", {"itemtype": kind, "items_id": ident, "content": content}
        )

    def observer(self, kind, ident, group):
        relation = "Group_" + kind
        rows = self.call("GET", f"{kind}/{ident}/{relation}?range=0-9999")
        if (
            not isinstance(rows, list)
            or len(rows) >= 10000
            or any(not isinstance(r, dict) for r in rows)
        ):
            raise GlpiError("GLPI : liste des observateurs incomplète")
        if any(str(r.get("groups_id")) == str(group) and str(r.get("type")) == "3" for r in rows):
            return
        self.create(relation, {kind.lower() + "s_id": ident, "groups_id": group, "type": 3})
        rows = self.call("GET", f"{kind}/{ident}/{relation}?range=0-9999")
        if (
            not isinstance(rows, list)
            or any(not isinstance(r, dict) for r in rows)
            or not any(
                str(r.get("groups_id")) == str(group) and str(r.get("type")) == "3" for r in rows
            )
        ):
            raise GlpiError("GLPI : observateur non confirmé")

    def find(self, kind, reference):
        options = self.call("GET", "listSearchOptions/" + kind)
        field_id = (
            next(
                (k for k, v in options.items() if isinstance(v, dict) and v.get("field") == "name"),
                None,
            )
            if isinstance(options, dict)
            else None
        )
        if field_id is None:
            raise GlpiError("GLPI : recherche par titre indisponible")
        query = parse.urlencode(
            {
                "criteria[0][field]": field_id,
                "criteria[0][searchtype]": "contains",
                "criteria[0][value]": reference,
                "forcedisplay[0]": 2,
                "range": "0-999",
            }
        )
        result = self.call("GET", f"search/{kind}?{query}")
        if not isinstance(result, dict) or not isinstance(result.get("data"), list):
            raise GlpiError("GLPI : recherche invalide")
        total = result.get("totalcount")
        if type(total) is not int or total != len(result["data"]):
            raise GlpiError("GLPI : recherche incomplète, rapprochement bloqué")
        matches = []
        for row in result["data"]:
            if not isinstance(row, dict):
                raise GlpiError("GLPI : résultat de recherche invalide")
            ident = row.get("2")
            if str(ident).isdigit():
                obj = self.read(kind, int(ident))
                if reference in obj.get("name", ""):
                    matches.append(int(ident))
        return matches
