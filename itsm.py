"""Workflow ITSM volontaire, persistant et indépendant des collecteurs."""

from __future__ import annotations

import hashlib
import html
import json
import logging
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

import access_policy
import incident_center
import operator_identity
from audit_engine import redact
from glpi_connector import Client, GlpiError, Settings


def now():
    return datetime.now(timezone.utc).isoformat()


# Libellés français des gravités OpsControl, pour le ticket GLPI.
SEVERITY_LABELS = {
    "critical": "Critique",
    "warning": "Majeur",
    "preventive": "Préventif",
    "info": "Information",
    "unknown": "Non classée",
}


def severity_label(value):
    return SEVERITY_LABELS.get(str(value or ""), str(value or "Non classée"))


def local_date(value):
    """Date ISO (ou epoch) en heure locale du serveur, avec son décalage UTC explicite :
    « 20/10/2026 17:31 (UTC+01:00) ». Le décalage évite toute ambiguïté si le fuseau du
    poste OpsControl et celui de GLPI diffèrent."""
    text = str(value or "")
    try:
        moment = (
            datetime.fromtimestamp(int(text), timezone.utc)
            if text.isdigit()
            else datetime.fromisoformat(text.replace("Z", "+00:00"))
        )
    except (ValueError, OverflowError, OSError):
        return value
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    local = moment.astimezone()
    offset = local.strftime("%z")
    return local.strftime("%d/%m/%Y %H:%M") + " (UTC" + offset[:3] + ":" + offset[3:] + ")"


# Statuts natifs GLPI (Ticket et Problem partagent 1 à 6), relus sans modification.
GLPI_STATUSES = {
    "1": "Nouveau",
    "2": "En cours (attribué)",
    "3": "En cours (planifié)",
    "4": "En attente",
    "5": "Résolu",
    "6": "Clos",
    # Statuts propres aux problèmes ITIL.
    "7": "Accepté",
    "8": "En observation",
}
GLPI_OPEN = {"1", "2", "3", "4", "7", "8"}
GLPI_DONE = {"5", "6"}


def status_label(value):
    if value is None or value == "":
        return None
    return GLPI_STATUSES.get(str(value), "Statut GLPI " + str(value)[:30])


def mismatch(origin_state, remote_status):
    """Incohérence entre l'anomalie OpsControl et le ticket GLPI, ou None.

    `origin_state` vaut active, resolved ou None (inconnu : source indisponible, constat
    d'audit) ; un état inconnu ne produit jamais d'alerte d'incohérence."""
    remote = str(remote_status or "")
    if origin_state == "resolved" and remote in GLPI_OPEN:
        return "Anomalie résolue dans OpsControl, ticket GLPI encore ouvert"
    if origin_state == "active" and remote in GLPI_DONE:
        return "Ticket GLPI " + status_label(remote).lower() + ", anomalie toujours active"
    return None


def host_for(context, name=None, host_key=None):
    """Serveur de l'inventaire : par clé, sinon par nom complet ou nom court (avant le 1er point).

    Zabbix nomme souvent l'hôte par son FQDN (reclabswr04.host.example.test) alors que
    l'inventaire le connaît sous son nom court (reclabswr04)."""
    rows = context.rows()
    if host_key:
        found = next((h for h in rows if h.get("key") == host_key), None)
        if found:
            return found
    if not name:
        return None
    full = str(name).strip().lower()
    short = full.split(".")[0]
    for candidates in ({full}, {short}):
        found = next(
            (
                h
                for h in rows
                if {str(h.get("key", "")).lower(), str(h.get("name", "")).lower()} & candidates
            ),
            None,
        )
        if found:
            return found
    return None


def hosts_facts(context, targets):
    """IP et environnement de chaque cible retrouvée dans l'inventaire.

    Une cible : valeurs simples. Plusieurs : « nom court : IP » par cible, environnements
    distincts. Une cible absente de l'inventaire reste « non inventorié », jamais devinée."""
    found = [(str(name), host_for(context, name, key)) for name, key in targets[:20] if name or key]
    if not found:
        return None, None
    if len(found) == 1:
        host = found[0][1] or {}
        return host.get("ip"), host.get("environment")
    ips = " · ".join(
        name.split(".")[0] + " : " + str((host or {}).get("ip") or "non inventorié") for name, host in found
    )
    envs = sorted({str(h["environment"]) for _, h in found if h and h.get("environment")})
    return ips, ", ".join(envs) or None


def safe(value):
    return html.escape(clean(value or "Non renseigné")[:4000], quote=True)


def clean(value):
    text = redact(str(value))
    text = re.sub(
        r'(?i)(["\']?(?:password|passwd|token|secret|app_token|user_token|session_token)["\']?\s*[:=]\s*)["\'][^"\']*["\']',
        r"\1[MASQUÉ]",
        text,
    )
    text = re.sub(r"(?i)(\buser_token\s+)\S+", r"\1[MASQUÉ]", text)
    for key in ("GLPI_APP_TOKEN", "GLPI_USER_TOKEN"):
        token = os.getenv(key)
        if token:
            text = text.replace(token, "[MASQUÉ]")
    return text


def migrate(db):
    db.execute("""CREATE TABLE IF NOT EXISTS itsm_cases(
        id TEXT PRIMARY KEY, origin TEXT NOT NULL, origin_id TEXT NOT NULL,
        kind TEXT NOT NULL CHECK(kind IN ('Ticket','Problem')), snapshot TEXT NOT NULL,
        owner TEXT NOT NULL, owner_auth TEXT NOT NULL, taken_at TEXT NOT NULL,
        reference TEXT NOT NULL UNIQUE, status TEXT NOT NULL DEFAULT 'pending',
        remote_id INTEGER, remote_base TEXT, remote_status TEXT, created_at TEXT,
        updated_at TEXT NOT NULL, last_error TEXT, preview TEXT, preview_hash TEXT,
        observer_id INTEGER, UNIQUE(origin,origin_id,kind), UNIQUE(kind,remote_base,remote_id))""")
    db.execute("""CREATE TABLE IF NOT EXISTS itsm_events(
        seq INTEGER PRIMARY KEY, case_id TEXT NOT NULL, at TEXT NOT NULL,
        actor TEXT NOT NULL, action TEXT NOT NULL, result TEXT NOT NULL)""")
    db.execute(
        "INSERT OR IGNORE INTO schema_migrations(name,applied_at) VALUES(?,?)", ("itsm_v1", now())
    )
    # itsm_v2 : relecture périodique du statut GLPI, état de l'anomalie d'origine et
    # résolution automatique (début de résolution observé, tentative de solution).
    columns = {row[1] for row in db.execute("PRAGMA table_info(itsm_cases)")}
    for name in (
        "remote_checked_at", "origin_state", "origin_checked_at", "origin_resolved_at", "auto_resolve_at"
    ):
        if name not in columns:
            db.execute("ALTER TABLE itsm_cases ADD COLUMN " + name + " TEXT")
    db.execute(
        "INSERT OR IGNORE INTO schema_migrations(name,applied_at) VALUES(?,?)", ("itsm_v2", now())
    )


class Take(BaseModel):
    model_config = ConfigDict(extra="forbid")
    origin: Literal["incident", "finding", "alert", "zabbix", "vulnerability", "security_alert"]
    origin_id: str = Field(min_length=1, max_length=400)
    host_key: str = Field(default="", max_length=200)
    kind: Literal["Ticket", "Problem"] = "Ticket"
    by: str = Field(default="", max_length=120)
    qualification: str = Field(default="", max_length=2000)
    # Incident encore ouvert : la demande de ticket vaut prise en charge (24 h) à ce nom.
    acknowledge: bool = False


class Action(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=36)
    by: str = Field(default="", max_length=120)
    confirmed: bool = False
    preview_hash: str = Field(default="", max_length=64)


def get(db, ident):
    cur = db.execute("SELECT * FROM itsm_cases WHERE id=?", (ident,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Dossier ITSM inconnu")
    return dict(zip((d[0] for d in cur.description), row))


def event(db, ident, actor, action, result):
    db.execute(
        "INSERT INTO itsm_events(case_id,at,actor,action,result) VALUES(?,?,?,?,?)",
        (ident, now(), actor, action, result),
    )


def view(case):
    out = {k: v for k, v in case.items() if k not in ("preview", "preview_hash")}
    out["snapshot"] = json.loads(case["snapshot"])
    out["url"] = (
        (
            case["remote_base"]
            + "/front/"
            + case["kind"].lower()
            + ".form.php?id="
            + str(case["remote_id"])
        )
        if case["remote_id"]
        else None
    )
    out["remote_status_label"] = status_label(case.get("remote_status"))
    return out


def ticket_name(case, data):
    """Titre GLPI lisible : gravité, anomalie, serveur, source, puis la référence.

    La référence reste dans le titre : le rapprochement la recherche (find)."""
    title = clean(data.get("title") or "Incident")
    target = clean(data.get("target") or "")
    short = target.split(".")[0] if target and "," not in target else target
    parts = "[" + severity_label(data.get("severity")) + "] " + title
    if short and short.lower() not in title.lower():
        parts += " — " + short
    if data.get("source"):
        parts += " (" + clean(data["source"]) + ")"
    suffix = " · " + case["reference"]
    return parts[: 250 - len(suffix)] + suffix


def summary(case, data):
    """Phrase d'en-tête : ce qui se passe, où, depuis quand et selon quelle source."""
    title = str(data.get("title") or "Anomalie")
    where = str(data.get("target") or "")
    extra = ", ".join(str(v) for v in (data.get("ip"), data.get("environment")) if v)
    since = data.get("opened_at") or data.get("observed_at")
    # Serveur déjà nommé dans le titre (cas Zabbix) : on ne le répète pas.
    named = where and where.split(".")[0].lower() in title.lower()
    return (
        severity_label(data.get("severity"))
        + " — "
        + title
        + ("" if named else " sur " + (where or "cible non renseignée"))
        + (" (" + extra + ")" if extra else "")
        + (", depuis le " + str(local_date(since)) if since else "")
        + (", détecté par " + str(data.get("source")) if data.get("source") else "")
        + "."
    )


def payload(case, settings):
    data = json.loads(case["snapshot"])
    sections = [
        (
            "<h2>EXAMPLE ITSM — "
            + ("Incident" if case["kind"] == "Ticket" else "Problème")
            + "</h2><p><b>"
            + safe(summary(case, data))
            + "</b></p>"
        )
    ]
    for title, pairs in (
        (
            "Détection",
            [
                ("Anomalie", data.get("title")),
                ("Gravité OpsControl", severity_label(data.get("severity"))),
                ("État à la prise en charge", data.get("state")),
                ("Source", data.get("source")),
                ("Début constaté", local_date(data.get("opened_at")) or "Non mesuré par la source"),
                ("Dernière observation", local_date(data.get("observed_at"))),
            ],
        ),
        (
            "Infrastructure",
            [
                ("Serveur", data.get("target")),
                ("IP", data.get("ip")),
                ("Environnement", data.get("environment")),
                ("Service / règle", data.get("rule")),
            ],
        ),
        (
            "Diagnostic et preuves",
            [
                ("Symptômes observés", data.get("evidence")),
                ("Qualification humaine", data.get("qualification")),
                ("Cause confirmée", "Non établie"),
                ("Impact potentiel", "À qualifier par le responsable"),
                ("Recommandations", data.get("recommendation")),
                ("Actions réalisées", "Prise en charge locale ; aucune correction exécutée"),
            ],
        ),
        (
            "Gestion ITSM",
            [
                ("Responsable OpsControl", case["owner"]),
                ("Prise en charge", local_date(case["taken_at"])),
                ("Référence OpsControl", case["reference"]),
                ("Identifiant technique de la source", case["origin_id"]),
                ("Groupe observateur GLPI (ID configuré)", settings.observer),
            ],
        ),
    ):
        sections.append(
            "<h3>"
            + title
            + "</h3><table>"
            + "".join("<tr><th>" + safe(k) + "</th><td>" + safe(v) + "</td></tr>" for k, v in pairs)
            + "</table>"
        )
    base = os.getenv("OPSCONTROL_PUBLIC_URL", "").rstrip("/")
    if base.startswith("https://"):
        sections.append(
            '<p><a href="'
            + html.escape(base + "/#/Dossiers%20ITSM", quote=True)
            + '">Ouvrir OpsControl — dossiers ITSM</a></p>'
        )
    result = {
        "name": ticket_name(case, data),
        "content": "".join(sections),
        "entities_id": settings.entity,
        "_users_id_requester": settings.requester,
        # Pris en charge dès la création : GLPI ne garde « En cours (attribué) » qu'avec un
        # assigné, d'où le groupe configuré (le même que l'observateur, choix d'exploitation).
        "status": 2,
        "_groups_id_assign": settings.observer,
        "urgency": {"critical": 5, "warning": 4, "preventive": 2}.get(data.get("severity"), 3),
    }
    if case["kind"] == "Ticket":
        result["type"] = 1
    return result


def _start(targets):
    """Début le plus ancien des cibles (ISO), ou None si la source ne le donne pas."""
    values = []
    for t in targets:
        v = str(t.get("started_at") or "")
        try:
            values.append(
                datetime.fromtimestamp(int(v), timezone.utc)
                if v.isdigit()
                else datetime.fromisoformat(v.replace("Z", "+00:00"))
            )
        except (ValueError, OverflowError, OSError):
            continue
    return min(values).isoformat() if values else None


def alert_snapshot(context, alert_id):
    """Alerte relue côté serveur : le navigateur ne fournit que son identifiant.

    La clé du dossier inclut le début de l'occurrence : une même cause qui revient
    plus tard ouvre un nouveau dossier au lieu de renvoyer l'ancien ticket."""
    import alert_center

    alert = next(
        (a for a in alert_center.build(context, for_incidents=True)["alerts"] if a["id"] == alert_id),
        None,
    )
    if alert is None:
        raise HTTPException(404, "Alerte inconnue ou déjà résolue")
    if alert.get("severity") == "info":
        raise HTTPException(409, "Une information n’ouvre pas de ticket")
    targets = alert.get("targets") or []
    start = _start(targets)
    names = [str(t.get("name")) for t in targets[:20] if t.get("name")]
    count = alert.get("count") or len(targets)
    ip, environment = hosts_facts(context, [(t.get("name"), t.get("host_key")) for t in targets])
    details = [str(t.get("name")) + " : " + str(t.get("detail")) for t in targets[:20] if t.get("detail")]
    ack = alert.get("ack") or {}
    return alert_id + "|" + (start or "début-inconnu"), {
        "title": alert.get("title"),
        "severity": alert.get("severity"),
        "state": ("Prise en charge par " + str(ack.get("by"))) if ack.get("by") else "Ouverte",
        "source": alert.get("source"),
        "target": ", ".join(names) + (f" … ({count} cibles)" if count > len(names) else ""),
        "ip": ip,
        "environment": environment,
        "evidence": "\n".join(filter(None, [alert.get("evidence"), *details])) or None,
        "observed_at": alert.get("observed_at"),
        "opened_at": start,
        "rule": alert.get("rule"),
    }


def security_alert_snapshot(context, ident, host_key):
    """Un signal de veille reste un signal à qualifier, jamais une CVE validée."""
    if not ident.isdigit() or len(ident) > 18 or not host_key:
        raise HTTPException(422, "Notification et serveur requis")
    with context.connect() as db:
        row = db.execute('SELECT title,level,detail,hosts,at,cve FROM sec_notifications WHERE id=?', (int(ident),)).fetchone()
    if not row or host_key not in json.loads(row[3] or '[]'):
        raise HTTPException(404, "Signal de sécurité absent de ce serveur")
    if row[1] not in ('critical', 'warning'):
        raise HTTPException(409, "Seul un signal majeur ou critique peut ouvrir un dossier")
    host = host_for(context, host_key=host_key)
    if not host:
        raise HTTPException(404, "Serveur inconnu")
    return ident + '|' + host_key, {
        'title': 'Vérification sécurité — ' + row[0], 'severity': row[1], 'state': 'Signal à qualifier',
        'source': 'Veille sécurité (applicabilité à vérifier)', 'target': host.get('name'), 'ip': host.get('ip'),
        'environment': host.get('environment'), 'evidence': row[2], 'observed_at': row[4], 'rule': row[5],
        'recommendation': "Vérifier l'applicabilité, les versions et les preuves. Une notification lue ne prouve pas la correction. "
                          "La clôture de ce ticket de vérification est manuelle dans GLPI.",
    }


def zabbix_snapshot(context, connection_key, triggerid):
    """Problème Zabbix relu dans la dernière collecte de la connexion désignée."""
    connection = next(
        (
            c
            for c in context.api_connections()
            if c.get("key") == connection_key and c.get("provider") == "Zabbix"
        ),
        None,
    )
    if connection is None:
        raise HTTPException(404, "Connexion Zabbix inconnue")
    last = connection.get("last_result") or {}
    if last.get("status") != "observed":
        last = connection.get("last_success_result") or last
    problems = (last.get("inventory") or {}).get("problems") or []
    problem = next((p for p in problems if str(p.get("triggerid")) == triggerid), None)
    if problem is None:
        raise HTTPException(404, "Problème Zabbix inconnu ou résolu")
    start = _start([{"started_at": problem.get("last_change")}])
    hosts = [str(h) for h in problem.get("hosts") or []]
    ip, environment = hosts_facts(context, [(h, None) for h in hosts])
    return connection_key + "|" + triggerid + "|" + (start or "début-inconnu"), {
        "title": problem.get("description"),
        "severity": problem.get("severity"),
        "state": "Problème actif",
        "source": "Zabbix (" + str(problem.get("severity_label")) + ")",
        "target": ", ".join(hosts) or None,
        "ip": ip,
        "environment": environment,
        "evidence": "Trigger Zabbix " + triggerid + " en anomalie",
        "observed_at": last.get("collected_at"),
        "opened_at": start,
        "rule": "Trigger Zabbix " + triggerid,
    }


SYNC_LIMIT = 200  # tickets relus au plus par passage : borne la charge imposée à GLPI
SYNC_ACTOR = "OpsControl (relecture GLPI)"


def sync_seconds():
    """Intervalle de relecture des statuts GLPI (GLPI_STATUS_SYNC_SECONDS, 0 = désactivé).

    Borné à 5 min – 24 h : un intervalle plus court n'apporte rien à un suivi de ticket et
    multiplierait les sessions ouvertes avec le compte de service GLPI."""
    try:
        value = int(os.getenv("GLPI_STATUS_SYNC_SECONDS", "900"))
    except ValueError:
        return 900
    return 0 if value <= 0 else min(max(value, 300), 86400)


def incident_states(db):
    """État courant des incidents liés à un dossier : active, resolved ou None (supprimé)."""
    rows = db.execute(
        "SELECT id,state FROM incidents WHERE id IN "
        "(SELECT origin_id FROM itsm_cases WHERE origin='incident')"
    ).fetchall()
    return {
        ident: "resolved" if state == "resolved" else "active" if state != "suppressed" else None
        for ident, state in rows
    }


def origin_states(context, cases):
    """État actuel des alertes et problèmes Zabbix d'origine (relu côté serveur).

    Une absence ne vaut « résolue » que si la source a réellement tout mesuré (même règle
    que le journal d'incidents) : une source en panne laisse l'état inconnu (None)."""
    states = {}
    alerts = [c for c in cases if c["origin"] == "alert"]
    if alerts:
        import alert_center

        at = datetime.now(timezone.utc)
        built = alert_center.build(context, at, for_incidents=True)
        active = {a["id"] for a in built["alerts"]}
        status = incident_center.source_status(
            built.get("sources"), context.rows(), built.get("probe"), at
        )
        for case in alerts:
            if case["origin_id"].rsplit("|", 1)[0] in active:
                states[case["id"]] = "active"
                continue
            data = json.loads(case["snapshot"])
            first = str(data.get("target") or "").split(",")[0].strip()
            host = host_for(context, first) if first else None
            source = str(data.get("source") or "")
            ok, _ = incident_center.can_confirm_absence(
                {
                    "source": source,
                    "target_key": (host or {}).get("key") or first,
                    # Type d'anomalie : la résolution SSH exige la mesure de ce contrôle.
                    "type": incident_center.incident_type(case["origin_id"].rsplit("|", 1)[0], source),
                },
                status,
            )
            states[case["id"]] = "resolved" if ok else None
    zabbix = [c for c in cases if c["origin"] == "zabbix"]
    if zabbix:
        from synchronization import fresh

        current = {}
        for connection in context.api_connections():
            last = connection.get("last_result") or {}
            inventory = last.get("inventory") or {}
            problems = inventory.get("problems")
            if connection.get("provider") == "Zabbix" and last.get("status") == "observed" and isinstance(problems, list):
                # Absence prouvée seulement par une liste complète ET récente : au-delà de
                # 500 triggers, ou sur une collecte ancienne, un problème toujours actif peut
                # manquer, et la résolution automatique fermait alors le ticket à tort.
                complete = not inventory.get("problems_truncated") and fresh(last.get("collected_at"))
                current[connection.get("key")] = ({str(p.get("triggerid")) for p in problems}, complete)
        for case in zabbix:
            key, trigger = (case["origin_id"].split("|") + [""])[:2]
            if key in current:
                listed, complete = current[key]
                states[case["id"]] = "active" if trigger in listed else "resolved" if complete else None
    # Vulnérabilités (security_cve) : « corrigée » seulement si l'analyse l'a constaté.
    vulnerabilities = [c for c in cases if c["origin"] == "vulnerability"]
    if vulnerabilities and hasattr(context, "security_vuln_states"):
        found = context.security_vuln_states([c["origin_id"] for c in vulnerabilities])
        for case in vulnerabilities:
            states[case["id"]] = found.get(case["origin_id"])
    return states


def auto_resolve_delay():
    """Délai de confirmation avant de résoudre le ticket GLPI, ou None si désactivé.

    GLPI_AUTO_RESOLVE=false désactive la résolution automatique. Le délai
    (GLPI_AUTO_RESOLVE_DELAY_SECONDS, 600 par défaut, 0 à 24 h) évite de résoudre un
    ticket sur une anomalie qui disparaît puis revient aussitôt."""
    if os.getenv("GLPI_AUTO_RESOLVE", "true").lower() != "true":
        return None
    try:
        value = int(os.getenv("GLPI_AUTO_RESOLVE_DELAY_SECONDS", "600"))
    except ValueError:
        return 600
    return min(max(value, 0), 86400)


def solution(case, since):
    """Texte de la solution GLPI ajoutée lors d'une résolution automatique."""
    data = json.loads(case["snapshot"])
    return (
        "<p><b>Résolu automatiquement par OpsControl</b> : l'anomalie « "
        + safe(data.get("title"))
        + " » n'est plus observée depuis le "
        + safe(local_date(since))
        + " (source : "
        + safe(data.get("source"))
        + ").</p><p>Aucune action corrective n'a été exécutée par OpsControl. "
        "Si le problème persiste, rouvrir ce ticket.</p><p>Référence OpsControl : "
        + safe(case["reference"])
        + "</p>"
    )


def refresh(context):
    """Relecture périodique des tickets liés et résolution automatique.

    Lecture : initSession, GET Ticket|Problem/<id>, killSession. Seule écriture : une
    solution (POST ITILSolution) quand l'anomalie d'origine est résolue dans OpsControl
    depuis le délai de confirmation ; GLPI passe alors le ticket à « Résolu ». Rien n'est
    jamais clos, rouvert ni supprimé ; une seule tentative par résolution."""
    result = {"at": now(), "checked": 0, "changed": 0, "resolved": 0, "errors": 0, "error": None}
    with context.connect() as db:
        cur = db.execute("SELECT id,origin FROM itsm_cases ORDER BY taken_at DESC LIMIT 500")
        cases = [dict(zip(("id", "origin"), row)) for row in cur.fetchall()]
        cases = [get(db, c["id"]) for c in cases]
    try:
        states = origin_states(context, cases)
        stamp = now()
        with context.connect() as db:
            incidents = incident_states(db)
            for case in cases:
                state = (
                    incidents.get(case["origin_id"])
                    if case["origin"] == "incident"
                    else states.get(case["id"])
                    if case["origin"] in ("alert", "zabbix", "vulnerability")
                    else None
                )
                # Date de première observation résolue (délai de confirmation) ; une anomalie
                # revenue efface la tentative, pour qu'une résolution suivante soit retentée.
                db.execute(
                    "UPDATE itsm_cases SET origin_state=CASE WHEN origin='incident' THEN origin_state ELSE ? END,"
                    "origin_checked_at=CASE WHEN origin='incident' THEN origin_checked_at ELSE ? END,"
                    "origin_resolved_at=CASE WHEN ?='resolved' THEN COALESCE(origin_resolved_at,?) ELSE NULL END,"
                    "auto_resolve_at=CASE WHEN ?='active' THEN NULL ELSE auto_resolve_at END WHERE id=?",
                    (state, stamp, state, stamp, state, case["id"]),
                )
            cases = [get(db, c["id"]) for c in cases]
            resolved_at = dict(
                db.execute(
                    "SELECT id,resolved_at FROM incidents WHERE state='resolved' AND id IN "
                    "(SELECT origin_id FROM itsm_cases WHERE origin='incident')"
                ).fetchall()
            )
    except Exception:  # noqa: BLE001 — l'état d'origine est un indicateur, jamais bloquant
        logging.getLogger("opscontrol.itsm").exception("État des anomalies d'origine non relu")
        resolved_at = {}
    try:
        settings = Settings.load()
    except GlpiError as exc:
        result["error"] = str(exc)
        return result
    delay = auto_resolve_delay()
    moment = datetime.now(timezone.utc)
    day_ago = moment.timestamp() - 86400

    def due(case):
        # Un ticket clos n'est relu qu'une fois par jour (une réouverture reste visible).
        if str(case["remote_status"]) != "6" or not case["remote_checked_at"]:
            return True
        return datetime.fromisoformat(case["remote_checked_at"]).timestamp() < day_ago

    def resolved_since(case):
        """Début de la résolution confirmée de l'anomalie d'origine, sinon None."""
        if delay is None or case["status"] != "linked" or case["auto_resolve_at"]:
            return None
        since = (
            resolved_at.get(case["origin_id"])
            if case["origin"] == "incident"
            else case["origin_resolved_at"]
            if case["origin"] in ("alert", "zabbix", "vulnerability")
            else None
        )
        if not since:
            return None
        start = datetime.fromisoformat(since.replace("Z", "+00:00"))
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        return since if (moment - start).total_seconds() >= delay else None

    targets = sorted(
        (
            c
            for c in cases
            if c["remote_id"]
            and c["status"] in ("linked", "partial")
            and c["remote_base"] == settings.base
            and due(c)
        ),
        key=lambda c: c["remote_checked_at"] or "",
    )[:SYNC_LIMIT]
    if not targets:
        return result
    try:
        with Client(settings).opened() as client:
            for case in targets:
                try:
                    obj = client.read(case["kind"], case["remote_id"])
                except GlpiError:
                    result["errors"] += 1
                    continue
                state = str(obj.get("status") or "")[:30] or None
                result["checked"] += 1
                since = resolved_since(case) if state in GLPI_OPEN else None
                if since:
                    with context.connect() as db:
                        # Réservation avant l'appel : jamais deux solutions pour une résolution.
                        reserved = db.execute(
                            "UPDATE itsm_cases SET auto_resolve_at=? WHERE id=? AND auto_resolve_at IS NULL",
                            (now(), case["id"]),
                        ).rowcount
                    if reserved:
                        try:
                            client.solve(case["kind"], case["remote_id"], solution(case, since))
                            state = str(client.read(case["kind"], case["remote_id"]).get("status") or "")[:30] or state
                            result["resolved"] += 1
                            message = "Solution ajoutée dans GLPI : anomalie résolue dans OpsControl depuis le " + str(local_date(since))
                        except GlpiError as exc:
                            result["errors"] += 1
                            message = "Résolution automatique non confirmée : " + str(exc) + " ; vérifier dans GLPI"
                        with context.connect() as db:
                            event(db, case["id"], SYNC_ACTOR, "auto_resolve", message)
                with context.connect() as db:
                    db.execute(
                        "UPDATE itsm_cases SET remote_status=COALESCE(?,remote_status),remote_checked_at=? WHERE id=?",
                        (state, now(), case["id"]),
                    )
                    if state and state != str(case["remote_status"] or ""):
                        result["changed"] += 1
                        event(
                            db,
                            case["id"],
                            SYNC_ACTOR,
                            "status",
                            "Statut GLPI : "
                            + (status_label(case["remote_status"]) or "non lu")
                            + " → "
                            + status_label(state),
                        )
    except GlpiError as exc:
        result["error"] = str(exc)
    return result


def links(db):
    """Correspondance origine → dossier, sans URL ni destination GLPI (lisible par un viewer)."""
    cur = db.execute(
        "SELECT id,origin,origin_id,kind,reference,status,remote_id,remote_status,"
        "remote_checked_at,origin_state,origin_checked_at FROM itsm_cases ORDER BY taken_at DESC LIMIT 2000"
    )
    names = [d[0] for d in cur.description]
    incidents = incident_states(db)
    items = []
    for row in cur.fetchall():
        item = dict(zip(names, row))
        if item["origin"] == "incident":
            # Journal local : l'état de l'incident est toujours lu en direct.
            item["origin_state"] = incidents.get(item["origin_id"])
            item["origin_checked_at"] = None
        item["remote_status_label"] = status_label(item["remote_status"])
        item["mismatch"] = mismatch(item["origin_state"], item["remote_status"])
        items.append(item)
    return items


def install(app, context):
    router = APIRouter()
    if not getattr(context, "SCHEMA_DEFERRED", False):  # autre instance active : aucun DDL (OC-AUDIT-014)
        with context.connect() as db:
            migrate(db)
    lock = threading.Lock()
    last = {"at": None, "checked": 0, "changed": 0, "errors": 0, "error": None}
    background = {"running": False, "seconds": 0}
    stop = threading.Event()

    def run():
        with lock:
            try:
                last.update(refresh(context))
            except Exception as exc:  # noqa: BLE001 — un passage en échec ne touche à aucun dossier
                logging.getLogger("opscontrol.itsm").exception("Relecture des statuts GLPI en échec")
                last.update(at=now(), error=type(exc).__name__ + " : détail dans le journal du service")
        return last

    def start_background():
        # Lancé par le lifespan, après le verrou d'instance (comme incident_center).
        seconds = sync_seconds()
        if not seconds or background["running"]:
            return False
        stop.clear()

        def loop():
            try:
                # Premier passage une minute après le démarrage, puis à intervalle fixe.
                while not stop.wait(seconds if last["at"] else 60):
                    run()
            finally:
                background["running"] = False

        background.update(running=True, seconds=seconds)
        from jobs import spawn  # producteur enregistré : attendu à l'arrêt (OC-AUDIT-013)

        spawn(loop, name="itsm-glpi-status")
        return True

    context.start_itsm_sync = start_background
    context.stop_itsm_sync = stop.set
    context.refresh_itsm = run

    @router.get("/api/itsm/links")
    def case_links():
        with context.connect() as db:
            items = links(db)
        return {
            "items": items,
            "sync": {
                **last,
                "interval_seconds": background["seconds"] if background["running"] else None,
            },
        }

    @router.get("/api/itsm/status")
    def status():
        # Ni URL ni jeton : seulement l'état utile à l'interface (bouton actif, transport).
        try:
            settings = Settings.load()
        except GlpiError as exc:
            return {"available": True, "protocol": 1, "configured": False, "reason": str(exc)}
        return {
            "available": True,
            "protocol": 1,
            "configured": True,
            "transport": "http" if settings.insecure else "https",
        }

    def actor(request, declared):
        if access_policy.principal(request.headers)["role"] != "admin":
            raise HTTPException(403, "Rôle administrateur requis")
        name, mode = operator_identity.actor(request.headers, declared)
        if not name:
            raise HTTPException(422, "Nom requis en mode local non authentifié")
        return name, mode

    @router.get("/api/itsm/cases")
    def cases():
        with context.connect() as db:
            ids = db.execute(
                "SELECT id FROM itsm_cases ORDER BY taken_at DESC LIMIT 500"
            ).fetchall()
            states = {item["id"]: item for item in links(db)}
            items = []
            for row in ids:
                case = view(get(db, row[0]))
                link = states.get(case["id"]) or {}
                case.update(origin_state=link.get("origin_state"), mismatch=link.get("mismatch"))
                items.append(case)
            return {"items": items}

    @router.get("/api/itsm/detail")
    def detail(id: str = Query(min_length=1, max_length=36)):
        with context.connect() as db:
            case = view(get(db, id))
            case["events"] = [
                dict(zip(("at", "actor", "action", "result"), r))
                for r in db.execute(
                    "SELECT at,actor,action,result FROM itsm_events WHERE case_id=? ORDER BY seq DESC LIMIT 100",
                    (id,),
                )
            ]
            return case

    @router.post("/api/itsm/take")
    def take(body: Take, request: Request):
        name, mode = actor(request, body.by)
        resolved = None
        if body.origin == "alert":
            resolved = alert_snapshot(context, body.origin_id)
        elif body.origin == "zabbix":
            resolved = zabbix_snapshot(context, body.host_key, body.origin_id)
        elif body.origin == "vulnerability":
            # Vulnérabilité relue et vérifiée côté serveur (validée, plan de correction joint).
            if not hasattr(context, "security_vuln_snapshot"):
                raise HTTPException(404, "Module sécurité absent")
            resolved = context.security_vuln_snapshot(body.origin_id)
        elif body.origin == "security_alert":
            resolved = security_alert_snapshot(context, body.origin_id, body.host_key)
        if resolved:
            origin_id, resolved = resolved
        elif body.origin == "incident":
            origin_id = body.origin_id
        else:
            origin_id = body.host_key + "|" + body.origin_id
        with context.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT id FROM itsm_cases WHERE origin=? AND origin_id=? AND kind=?",
                (body.origin, origin_id, body.kind),
            ).fetchone()
            if existing:
                return view(get(db, existing[0]))
            if body.origin == 'security_alert' and len(body.qualification.strip()) < 10:
                raise HTTPException(422, "Décrire les vérifications attendues (10 caractères minimum)")
            if body.kind == "Problem" and len(body.qualification.strip()) < 10:
                raise HTTPException(
                    422,
                    "Qualifier le caractère récurrent ou structurel du problème (10 caractères minimum)",
                )
            if resolved:
                data = resolved
            elif body.origin == "incident":
                data = incident_center.Repository(None).get(db, body.origin_id)
                if not data:
                    raise HTTPException(404, "Incident inconnu")
                if body.acknowledge and data["state"] in ("open", "reopened"):
                    # Même action que « Reconnaître », journalisée dans incident_events.
                    data = incident_center.act(
                        db, body.origin_id, "ack", name, mode, "Prise en charge pour ticket GLPI", "24h"
                    )
                if data["state"] not in ("acknowledged", "investigating"):
                    raise HTTPException(409, "Prendre en charge l’incident avant le dossier ITSM")
                if data.get("ack_until") and data["ack_until"] <= now():
                    raise HTTPException(409, "Prise en charge expirée")
                # Clé de la fiche serveur d'où vient la demande : seulement si l'incident n'en a
                # pas (incident Zabbix nommé par l'hôte Zabbix) ; sert à l'IP et à l'environnement.
                host = host_for(context, data.get("target"), data.get("target_key") or body.host_key)
                if host:
                    data.update(ip=host.get("ip"), environment=host.get("environment"))
            else:
                host = next((h for h in context.rows() if h["key"] == body.host_key), None)
                finding = next(
                    (
                        f
                        for f in (host or {}).get("findings", [])
                        if str(f.get("id") or f.get("title")) == body.origin_id
                    ),
                    None,
                )
                if not host or not finding:
                    raise HTTPException(404, "Constat d’audit inconnu")
                data = {
                    "title": finding.get("title"),
                    "severity": finding.get("severity"),
                    "state": "acknowledged",
                    "source": "Audit SSH",
                    "target": host.get("name"),
                    "ip": host.get("ip"),
                    "environment": host.get("environment"),
                    "evidence": finding.get("evidence"),
                    "observed_at": host.get("collected_at"),
                    "opened_at": host.get("collected_at"),
                    "recommendation": finding.get("precaution"),
                    "rule": finding.get("domain"),
                }
            ident, stamp = str(uuid.uuid4()), now()
            owner = data.get("owner") or name
            owner_auth = data.get("owner_auth") or mode
            taken_at = data.get("acknowledged_at") or stamp
            # Liste fermée : les champs non utiles et les détails internes ne sortent pas.
            data = {
                k: clean(data[k])[:4000]
                for k in (
                    "title",
                    "severity",
                    "state",
                    "source",
                    "target",
                    "ip",
                    "environment",
                    "evidence",
                    "observed_at",
                    "opened_at",
                    "recommendation",
                    "rule",
                )
                if data.get(k) is not None
            }
            data["qualification"] = clean(body.qualification)
            db.execute(
                "INSERT INTO itsm_cases(id,origin,origin_id,kind,snapshot,owner,owner_auth,taken_at,reference,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    ident,
                    body.origin,
                    origin_id,
                    body.kind,
                    json.dumps(data),
                    owner,
                    owner_auth,
                    taken_at,
                    "OC-" + ident.replace("-", "")[:8].upper(),
                    stamp,
                ),
            )
            event(db, ident, name, "take", "Prise en charge ITSM")
            return view(get(db, ident))

    @router.post("/api/itsm/preview")
    def preview(body: Action, request: Request):
        name, _ = actor(request, body.by)
        try:
            settings = Settings.load()
        except GlpiError as exc:
            raise HTTPException(503, str(exc)) from None
        with context.connect() as db:
            case = get(db, body.id)
            content = payload(case, settings)
            raw = json.dumps(content, sort_keys=True)
            digest = hashlib.sha256(
                (raw + str(settings.observer) + settings.base).encode()
            ).hexdigest()
            db.execute(
                "UPDATE itsm_cases SET preview=?,preview_hash=? WHERE id=?", (raw, digest, body.id)
            )
            event(db, body.id, name, "preview", "Prévisualisation locale sans appel GLPI")
        return {
            "payload": content,
            "preview_hash": digest,
            "kind": case["kind"],
            "observer_id": settings.observer,
        }

    def execute(body, request, reconcile=False):
        name, _ = actor(request, body.by)
        if not body.confirmed:
            raise HTTPException(422, "Confirmation explicite requise")
        try:
            settings = Settings.load()
        except GlpiError as exc:
            raise HTTPException(503, str(exc)) from None
        with context.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            case = get(db, body.id)
            if case["status"] == "linked" and not reconcile:
                return view(case)
            if case["status"] == "creating":
                # Une opération abandonnée devient rapprochable après cinq minutes.
                age = (
                    datetime.now(timezone.utc) - datetime.fromisoformat(case["updated_at"])
                ).total_seconds()
                if not reconcile or age < 300:
                    raise HTTPException(
                        409, "Création en cours ; rapprochement disponible après cinq minutes"
                    )
            if not reconcile and case["status"] in ("uncertain", "partial"):
                raise HTTPException(
                    409, "Rapprochement requis ; aucune nouvelle création autorisée"
                )
            if case["remote_base"] and case["remote_base"] != settings.base:
                raise HTTPException(
                    409, "La destination GLPI a changé : restaurer la configuration initiale"
                )
            if not reconcile:
                if case["origin"] == "incident":
                    incident = incident_center.Repository(None).get(db, case["origin_id"])
                    if (
                        not incident
                        or incident["state"] not in ("acknowledged", "investigating")
                        or (incident.get("ack_until") and incident["ack_until"] <= now())
                    ):
                        raise HTTPException(409, "Prise en charge active de l’incident requise")
                if (
                    not case["preview"]
                    or not body.preview_hash
                    or body.preview_hash != case["preview_hash"]
                ):
                    raise HTTPException(409, "Prévisualisation requise")
                current = json.dumps(payload(case, settings), sort_keys=True)
                digest = hashlib.sha256(
                    (current + str(settings.observer) + settings.base).encode()
                ).hexdigest()
                if digest != body.preview_hash:
                    raise HTTPException(409, "Configuration modifiée : refaire la prévisualisation")
            db.execute(
                "UPDATE itsm_cases SET status='creating',remote_base=?,observer_id=COALESCE(observer_id,?),updated_at=? WHERE id=?",
                (settings.base, settings.observer, now(), body.id),
            )
            event(db, body.id, name, "reconcile" if reconcile else "create", "Début")
        remote_id, phase = case["remote_id"], "session"
        try:
            with Client(settings).opened() as client:
                if reconcile and not remote_id:
                    matches = client.find(case["kind"], case["reference"])
                    if len(matches) != 1:
                        raise GlpiError(
                            "Rapprochement sans correspondance unique ; absence non établie",
                            uncertain=True,
                        )
                    remote_id = matches[0]
                if not remote_id:
                    phase = "post"
                    remote_id = client.create(case["kind"], json.loads(case["preview"]))
                # Sauvegarde immédiate de l’ID avant toute vérification ou association.
                with context.connect() as db:
                    db.execute(
                        "UPDATE itsm_cases SET remote_id=?,created_at=COALESCE(created_at,?) WHERE id=?",
                        (remote_id, now(), body.id),
                    )
                phase = "verify"
                obj = client.read(case["kind"], remote_id)
                if case["reference"] not in obj.get("name", ""):
                    raise GlpiError("La référence GLPI ne correspond pas au dossier")
                if case["status"] != "linked":
                    client.observer(
                        case["kind"], remote_id, case["observer_id"] or settings.observer
                    )
                state = str(obj.get("status", "Inconnu"))[:30]
            status = "linked"
            message = (
                "Statut GLPI relu sans modification"
                if case["status"] == "linked"
                else "Objet et groupe observateur vérifiés"
            )
        except GlpiError as exc:
            status = (
                "partial"
                if remote_id
                else "uncertain"
                if reconcile or exc.uncertain or phase == "verify"
                else "failed"
            )
            message, state = str(exc), None
        with context.connect() as db:
            db.execute(
                "UPDATE itsm_cases SET status=?,last_error=?,remote_status=COALESCE(?,remote_status),"
                "remote_checked_at=CASE WHEN ? IS NULL THEN remote_checked_at ELSE ? END,updated_at=? WHERE id=?",
                (status, None if status == "linked" else message, state, state, now(), now(), body.id),
            )
            event(
                db, body.id, name, status, message + (f" · GLPI {remote_id}" if remote_id else "")
            )
            return view(get(db, body.id))

    @router.post("/api/itsm/create")
    def create(body: Action, request: Request):
        return execute(body, request)

    @router.post("/api/itsm/reconcile")
    def reconcile(body: Action, request: Request):
        return execute(body, request, reconcile=True)

    app.include_router(router)
