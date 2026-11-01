"""Journaux applicatifs d'OpsControl en JSON lines, corrélés par request_id.

Avant : aucune configuration `logging` ; seuls les messages d'uvicorn sortaient, en texte,
et l'identifiant de requête n'apparaissait que dans la table mutation_audit. Un incident
ne pouvait donc pas être suivi d'un journal à l'autre.

Ici : le journal « opscontrol » (et ses enfants : opscontrol.access, opscontrol.http…)
écrit une ligne JSON par événement sur stderr — journald sur la VM, console du lanceur
sous Windows — avec horodatage UTC et request_id de la requête en cours. Les journaux
d'uvicorn ne sont pas modifiés. La propagation vers la racine est conservée : le tampon
d'erreurs de self_monitor continue de recevoir les WARNING et ERROR.

    INFRAOPS_LOG_LEVEL   niveau minimal (INFO par défaut)
    INFRAOPS_ACCESS_LOG  0 pour couper la ligne d'accès HTTP (opscontrol.http)
"""
from __future__ import annotations

import contextvars
import json
import logging
import os
import sys
from datetime import datetime, timezone

REQUEST_ID = contextvars.ContextVar('opscontrol_request_id', default=None)
ROOT = 'opscontrol'
# Champs passés par `extra=` recopiés dans la ligne JSON (liste fermée : rien d'imprévu).
FIELDS = ('method', 'path', 'status', 'duration_ms', 'role', 'mode', 'outcome', 'client')


def _redact(text):
    # Import tardif : audit_engine importe ssh, qui n'a pas à être chargé pour journaliser.
    try:
        from audit_engine import redact
    except Exception:  # noqa: BLE001 — journaliser ne doit jamais échouer
        return text
    return redact(text)


class JsonFormatter(logging.Formatter):
    def format(self, record):
        # Message et trace masqués : une exception peut citer une ligne de commande ou un en-tête.
        line = {'ts': datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec='milliseconds'),
                'level': record.levelname, 'logger': record.name, 'msg': _redact(record.getMessage())}
        request_id = getattr(record, 'request_id', None) or REQUEST_ID.get()
        if request_id:
            line['request_id'] = request_id
        for field in FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                line[field] = value
        if record.exc_info:
            line['exc'] = _redact(self.formatException(record.exc_info)[-4000:])
        # ASCII échappé : la console Windows (cp1252) abîmait les accents ; JSON reste exact partout.
        return json.dumps(line, ensure_ascii=True, default=str)


def access_log_enabled() -> bool:
    return os.getenv('INFRAOPS_ACCESS_LOG', '1') != '0'


def configure(stream=None) -> logging.Logger:
    """Idempotent : un seul gestionnaire JSON, même si l'application est importée deux fois."""
    logger = logging.getLogger(ROOT)
    level = os.getenv('INFRAOPS_LOG_LEVEL', 'INFO').upper()
    logger.setLevel(level if level in ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL') else 'INFO')
    if not any(getattr(h, '_opscontrol_json', False) for h in logger.handlers):
        handler = logging.StreamHandler(stream or sys.stderr)
        handler.setFormatter(JsonFormatter())
        handler._opscontrol_json = True
        logger.addHandler(handler)
    return logger
