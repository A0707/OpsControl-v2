"""Rapport de passation (fin de journée / début de shift), en lecture seule.

Le « Bilan à l'ouverture » (startup_check, web/briefing.js) montre l'état COURANT.
La passation montre ce qui a CHANGÉ sur une période et qui fait quoi :
nouveaux incidents, résolutions, prises en charge (par qui), incidents anciens
sans responsable, prises en charge qui expirent bientôt, tickets GLPI créés.

Sources : uniquement le journal persistant (tables incidents, incident_events,
itsm_cases). Rien n'est recalculé depuis les collecteurs et rien n'est écrit :
deux lectures successives d'une même période donnent le même rapport.

Données exposées : identités déjà visibles dans le journal d'incidents, notes
masquées (audit_engine.redact). Ni preuve brute, ni URL GLPI, ni jeton.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Query
from fastapi.responses import Response

from audit_engine import redact
from incident_center import SEVERITY_RANK, _parse

# Bornes fixes : « sans responsable » et « expire bientôt » ne dépendent pas de la
# période choisie (une passation de 8 h doit quand même signaler un incident orphelin
# depuis 30 h).
UNOWNED_AFTER = timedelta(hours=24)
EXPIRING_WITHIN = timedelta(hours=12)
MAX_HOURS = 168
# Plafond par section : la réponse reste lisible et rapide ; le total reste exact.
MAX_ITEMS = 200
NOTE_MAX = 200

SEVERITY_LABELS = {
    "critical": "Critique",
    "warning": "Majeur",
    "preventive": "Préventif",
    "info": "Information",
}
STATE_LABELS = {
    "open": "Ouvert",
    "reopened": "Réapparu",
    "acknowledged": "Pris en charge",
    "investigating": "En investigation",
    "suppressed": "Supprimé temporairement",
    "resolved": "Résolu",
}
TAKE_KINDS = {
    "ack": "Prise en charge",
    "investigation_started": "Investigation",
    "suppress": "Suppression temporaire",
}
DURATION_LABELS = {"24h": "24 h", "7d": "7 jours", "permanent": "sans échéance"}
ITSM_STATUS = {
    "pending": "En attente",
    "creating": "Création en cours",
    "linked": "Associé",
    "failed": "Échec sans création confirmée",
    "uncertain": "Résultat incertain",
    "partial": "Objet créé — association à vérifier",
}


def now_utc():
    return datetime.now(timezone.utc)


def _iso(value):
    return value.isoformat() if value else None


def _note(value):
    # Une note est saisie librement : on la masque comme une preuve avant de la diffuser.
    text = str(value or "").strip()
    return redact(text)[:NOTE_MAX] if text else None


def _rows(db, sql, args=()):
    cur = db.execute(sql, args)
    names = [d[0] for d in cur.description]
    return [dict(zip(names, row)) for row in cur.fetchall()]


def _incident(row):
    """Champs utiles à la passation ; jamais la preuve brute."""
    return {
        "id": row["id"],
        "title": row["title"],
        "source": row["source"],
        "target": row["target"],
        "host_key": row.get("target_key"),
        "severity": row["severity"],
        "state": row["state"],
        "chronic": bool(row.get("chronic")),
        "owner": row.get("owner"),
        "owner_authenticated": row.get("owner_auth") == "proxy",
    }


def _events(db, kinds, start, end):
    marks = ",".join("?" * len(kinds))
    rows = _rows(
        db,
        f"SELECT e.seq, e.at, e.kind, e.actor, e.actor_auth, e.detail, i.* "
        f"FROM incident_events e JOIN incidents i ON i.id = e.incident_id "
        f"WHERE e.kind IN ({marks}) AND e.at >= ? ORDER BY e.at DESC, e.seq DESC",
        (*kinds, _iso(start)),
    )
    # Filtre final sur la date lue (et non sur la chaîne) : bornes exactes de la période.
    return [r for r in rows if (moment := _parse(r["at"])) and start <= moment <= end]


def _unowned_since(row):
    """Début de la période sans responsable : réapparition, sinon ouverture du suivi."""
    return _parse(row.get("reopened_at")) or _parse(row["opened_at"])


def build(db, hours=24, at=None, sync=None) -> dict:
    at = at or now_utc()
    hours = max(1, min(int(hours), MAX_HOURS))
    start = at - timedelta(hours=hours)

    new = []
    for r in _events(db, ("opened", "reopened"), start, at):
        new.append({**_incident(r), "at": r["at"], "reopened": r["kind"] == "reopened"})

    resolved = []
    for r in _events(db, ("resolved",), start, at):
        resolved.append({**_incident(r), "at": r["at"], "reappeared": r["state"] != "resolved"})

    taken = []
    for r in _events(db, tuple(TAKE_KINDS), start, at):
        detail = json.loads(r["detail"]) if r.get("detail") else {}
        taken.append({
            **_incident(r),
            "at": r["at"],
            "action": r["kind"],
            "actor": r["actor"],
            "actor_authenticated": r["actor_auth"] == "proxy",
            "duration": detail.get("duration"),
            "until": detail.get("until"),
            "note": _note(detail.get("note")),
        })
    by_actor = {}
    for item in taken:
        if item["action"] != "suppress":
            by_actor[item["actor"]] = by_actor.get(item["actor"], 0) + 1

    # État courant du journal : un incident sans responsable, ou dont la prise en charge
    # a expiré sans que le rapprochement l'ait encore constaté.
    stamp = _iso(at)
    unowned, chronic_unowned = [], 0
    rows = _rows(
        db,
        "SELECT * FROM incidents WHERE state IN ('open','reopened') "
        "OR (state IN ('acknowledged','investigating') AND ack_until IS NOT NULL AND ack_until <= ?)",
        (stamp,),
    )
    for r in rows:
        since = _unowned_since(r)
        if not since or at - since < UNOWNED_AFTER:
            continue
        if r["chronic"]:
            # Déclencheurs ouverts depuis plus de 30 jours : comptés, pas listés (bruit).
            chronic_unowned += 1
            continue
        expired = r["state"] in ("acknowledged", "investigating")
        unowned.append({**_incident(r), "since": _iso(since), "age_seconds": int((at - since).total_seconds()),
                        "expired_owner": r["owner"] if expired else None})
    unowned.sort(key=lambda i: (SEVERITY_RANK.get(i["severity"], 9), -i["age_seconds"]))

    expiring = []
    rows = _rows(
        db,
        "SELECT * FROM incidents WHERE state IN ('acknowledged','investigating') "
        "AND ack_until IS NOT NULL AND ack_until > ? ORDER BY ack_until",
        (stamp,),
    )
    for r in rows:
        until = _parse(r["ack_until"])
        if until and at < until <= at + EXPIRING_WITHIN:
            expiring.append({**_incident(r), "until": r["ack_until"], "note": _note(r.get("note"))})

    tickets, pending = [], []
    for case in _rows(db, "SELECT * FROM itsm_cases WHERE created_at >= ? OR taken_at >= ? "
                          "ORDER BY COALESCE(created_at, taken_at) DESC", (_iso(start), _iso(start))):
        snap = json.loads(case["snapshot"] or "{}")
        item = {
            "reference": case["reference"],
            "kind": case["kind"],
            "glpi_id": case["remote_id"],
            "status": case["status"],
            "glpi_status": case["remote_status"],
            "title": snap.get("title"),
            "target": snap.get("target"),
            "source": snap.get("source"),
            "severity": snap.get("severity"),
            "owner": case["owner"],
            "owner_authenticated": case["owner_auth"] == "proxy",
            "origin": case["origin"],
            "taken_at": case["taken_at"],
            "created_at": case["created_at"],
        }
        created = _parse(case["created_at"])
        taken_at = _parse(case["taken_at"])
        if case["remote_id"] and created and start <= created <= at:
            tickets.append(item)
        elif not case["remote_id"] and taken_at and start <= taken_at <= at:
            # Dossier demandé sur la période mais sans numéro GLPI confirmé : à reprendre.
            pending.append(item)

    sections = {"new": new, "resolved": resolved, "taken": taken, "unowned": unowned,
                "expiring": expiring, "tickets": tickets, "tickets_pending": pending}
    report = {
        "generated_at": stamp,
        "period": {"start": _iso(start), "end": stamp, "hours": hours},
        "thresholds": {"unowned_hours": int(UNOWNED_AFTER.total_seconds() // 3600),
                       "expiring_hours": int(EXPIRING_WITHIN.total_seconds() // 3600)},
        "counts": {k: len(v) for k, v in sections.items()},
        "by_actor": dict(sorted(by_actor.items(), key=lambda kv: (-kv[1], str(kv[0])))),
        "chronic_unowned": chronic_unowned,
        "sync": sync,
        **{k: v[:MAX_ITEMS] for k, v in sections.items()},
        "scope": "Journal d’incidents et dossiers ITSM d’OpsControl uniquement ; aucune collecte relancée.",
    }
    report["text"] = text(report)
    return report


# --------------------------------------------------------------------------- texte
def _local(value, with_date=True):
    moment = _parse(value) if isinstance(value, str) else value
    if not moment:
        return "date inconnue"
    return moment.astimezone().strftime("%d/%m %H:%M" if with_date else "%H:%M")


def _offset():
    raw = now_utc().astimezone().strftime("%z")
    return "UTC" + raw[:3] + ":" + raw[3:]


def _age(seconds):
    hours = seconds // 3600
    return f"{hours // 24} j {hours % 24} h" if hours >= 24 else f"{hours} h"


def _who(name, authenticated):
    return (name or "inconnu") + ("" if authenticated else " (déclaratif)")


def _what(item):
    target = item.get("target")
    where = "" if not target or target == "global" else " — " + str(target)
    source = " (" + str(item["source"]) + ")" if item.get("source") else ""
    severity = SEVERITY_LABELS.get(item.get("severity"), item.get("severity") or "Non classée")
    return "[" + severity + "] " + str(item.get("title") or "Incident") + where + source


def _lines(title, items, total, render):
    out = [f"• {title} ({total})"]
    out += ["  - " + render(i) for i in items] or ["  - Rien"]
    if total > len(items):
        out.append(f"  - … et {total - len(items)} autre(s) dans OpsControl")
    return out


def text(report) -> str:
    """Texte brut prêt à coller dans Teams ou un mail (pas de Markdown ni de HTML)."""
    c, p = report["counts"], report["period"]
    th = report["thresholds"]
    out = [
        f"Passation OpsControl — du {_local(p['start'])} au {_local(p['end'])} "
        f"({p['hours']} h, heure locale {_offset()})",
    ]
    sync = report.get("sync") or {}
    if sync.get("error"):
        out.append("Attention : dernier rapprochement du journal en échec ; les chiffres datent du précédent.")
    elif sync.get("at"):
        out.append(f"Journal rapproché le {_local(sync['at'])}.")
    out.append(
        f"Résumé : {c['new']} nouveau(x) · {c['resolved']} résolu(s) · {c['taken']} prise(s) en charge · "
        f"{c['unowned']} sans responsable > {th['unowned_hours']} h · "
        f"{c['expiring']} échéance(s) < {th['expiring_hours']} h · {c['tickets']} ticket(s) GLPI"
    )
    if report["by_actor"]:
        out.append("Qui fait quoi : " + ", ".join(f"{a} {n}" for a, n in report["by_actor"].items()))
    out += ["", "À TRAITER"]
    out += _lines(f"Sans responsable depuis plus de {th['unowned_hours']} h", report["unowned"], c["unowned"],
                  lambda i: _what(i) + " · depuis " + _age(i["age_seconds"])
                  + (" · prise en charge de " + i["expired_owner"] + " expirée" if i.get("expired_owner") else ""))
    if report.get("chronic_unowned"):
        out.append(f"  ({report['chronic_unowned']} anomalie(s) chronique(s) > 30 j non listée(s))")
    out += _lines(f"Prises en charge qui expirent dans les {th['expiring_hours']} h", report["expiring"],
                  c["expiring"], lambda i: _what(i) + " · " + _who(i["owner"], i["owner_authenticated"])
                  + " · expire à " + _local(i["until"]))
    if c["tickets_pending"]:
        out += _lines("Dossiers ITSM sans ticket GLPI confirmé", report["tickets_pending"], c["tickets_pending"],
                      lambda i: i["reference"] + " · " + _what(i) + " · " + ITSM_STATUS.get(i["status"], i["status"]))
    out += ["", "CE QUI A CHANGÉ"]
    out += _lines("Nouveaux incidents", report["new"], c["new"],
                  lambda i: _local(i["at"]) + " " + _what(i) + (" · réapparu" if i["reopened"] else "")
                  + " · " + STATE_LABELS.get(i["state"], i["state"]).lower())
    out += _lines("Incidents résolus", report["resolved"], c["resolved"],
                  lambda i: _local(i["at"]) + " " + _what(i) + (" · réapparu depuis" if i["reappeared"] else ""))
    out += _lines("Prises en charge", report["taken"], c["taken"],
                  lambda i: _local(i["at"]) + " " + _who(i["actor"], i["actor_authenticated"]) + " : "
                  + TAKE_KINDS[i["action"]].lower()
                  + (" " + DURATION_LABELS[i["duration"]] if i.get("duration") in DURATION_LABELS else "")
                  + " — " + _what(i) + (" · « " + i["note"] + " »" if i.get("note") else ""))
    out += _lines("Tickets GLPI créés", report["tickets"], c["tickets"],
                  lambda i: i["reference"] + " · GLPI " + ("ticket" if i["kind"] == "Ticket" else "problème")
                  + " n° " + str(i["glpi_id"]) + " · " + _what(i) + " · " + _who(i["owner"], i["owner_authenticated"]))
    out += ["", "Source : journal d’incidents OpsControl (lecture seule, aucune collecte relancée)."]
    return "\n".join(out)


# --------------------------------------------------------------------------- CSV
CSV_COLUMNS = ("rubrique", "date", "gravite", "incident", "cible", "source", "etat", "qui", "detail")


def _cell(value):
    # Une cellule commençant par = + - @ serait interprétée comme formule par Excel.
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def csv_text(report) -> str:
    rows = []

    def add(section, at, item, who="", detail=""):
        rows.append((section, _local(at) if at else "", SEVERITY_LABELS.get(item.get("severity"), item.get("severity") or ""),
                     item.get("title") or "", item.get("target") or "", item.get("source") or "",
                     STATE_LABELS.get(item.get("state"), item.get("state") or ""), who, detail))

    for i in report["unowned"]:
        add("Sans responsable", i["since"], i, "", "depuis " + _age(i["age_seconds"]))
    for i in report["expiring"]:
        add("Échéance proche", i["until"], i, _who(i["owner"], i["owner_authenticated"]), "expire à " + _local(i["until"]))
    for i in report["new"]:
        add("Nouveau", i["at"], i, "", "réapparu" if i["reopened"] else "")
    for i in report["resolved"]:
        add("Résolu", i["at"], i, "", "réapparu depuis" if i["reappeared"] else "")
    for i in report["taken"]:
        add("Prise en charge", i["at"], i, _who(i["actor"], i["actor_authenticated"]),
            TAKE_KINDS[i["action"]] + (" " + DURATION_LABELS[i["duration"]] if i.get("duration") in DURATION_LABELS else "")
            + (" · " + i["note"] if i.get("note") else ""))
    for i in report["tickets"]:
        add("Ticket GLPI", i["created_at"], i, _who(i["owner"], i["owner_authenticated"]),
            i["reference"] + " · GLPI n° " + str(i["glpi_id"]))
    for i in report["tickets_pending"]:
        add("Dossier ITSM en attente", i["taken_at"], i, _who(i["owner"], i["owner_authenticated"]),
            i["reference"] + " · " + ITSM_STATUS.get(i["status"], i["status"]))
    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=";", lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    writer.writerows([[_cell(v) for v in row] for row in rows])
    # BOM : Excel (poste Windows en français) lit alors l'UTF-8 sans mojibake.
    return "﻿" + buffer.getvalue()


# --------------------------------------------------------------------------- API
def install(app, context):
    router = APIRouter()

    @router.get("/api/handover")
    def handover(hours: int = Query(24, ge=1, le=MAX_HOURS), format: str = Query("json", pattern="^(json|csv)$")):
        info = getattr(context, "incident_sync_info", None)
        sync = info() if callable(info) else None
        with context.connect() as db:
            report = build(db, hours, sync=sync and {"at": sync.get("at"), "error": sync.get("error")})
        if format == "csv":
            name = "passation-" + _parse(report["generated_at"]).astimezone().strftime("%Y-%m-%d-%Hh%M") + ".csv"
            return Response(csv_text(report), media_type="text/csv; charset=utf-8",
                            headers={"Content-Disposition": f'attachment; filename="{name}"'})
        return report

    app.include_router(router)
