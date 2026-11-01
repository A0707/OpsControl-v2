"""GLPI simulé : validation humaine, concurrence et reprise sans doublons."""

import contextlib
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock
from urllib.error import HTTPError

from fastapi import FastAPI, HTTPException
from starlette.datastructures import Headers

import incident_center as ic
import itsm
from glpi_connector import Client, GlpiError, Settings
from routers import all_routes


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = self.temp.name + "/test.sqlite3"
        self.context = SimpleNamespace(connect=self.connect, rows=lambda: [])
        with self.connect() as db:
            ic.migrate(db)
            ic.reconcile(
                db,
                ic.observations(
                    [
                        {
                            "id": "Zabbix:down:critical",
                            "source": "Zabbix",
                            "title": "Service indisponible",
                            "severity": "critical",
                            "targets": [{"name": "srv"}],
                        }
                    ]
                ),
                {"hosts": {}, "providers": {}, "probe": {}},
            )
            ic.act(db, "Zabbix|srv|down", "ack", "responsable", "local", "", "permanent")
        app = FastAPI()
        itsm.install(app, self.context)
        self.routes = {r.path: r.endpoint for r in all_routes(app)}
        self.request = SimpleNamespace(headers=Headers({}))
        self.env = mock.patch.dict(
            os.environ,
            {
                "INFRAOPS_LOCAL_ROLE": "admin",
                "INFRAOPS_REQUIRE_PROXY": "0",
                "INFRAOPS_TRUSTED_PROXY_SECRET": "",
            },
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.settings = Settings("https://glpi.example.test", "", "", 0, 61, 6, 15)
        patch = mock.patch("itsm.Settings.load", return_value=self.settings)
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch("itsm.Client")
        self.factory = patch.start()
        self.addCleanup(patch.stop)
        self.client = self.factory.return_value.opened.return_value.__enter__.return_value
        self.client.create.return_value = 123
        self.client.read.side_effect = lambda kind, ident: {
            "id": ident,
            "name": "[" + self.reference() + "]",
            "status": 1,
        }

    @contextlib.contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            with db:
                yield db
        finally:
            db.close()

    def call(self, path, body):
        return self.routes["/api/itsm/" + path](body, self.request)

    def reference(self):
        with self.connect() as db:
            return db.execute("SELECT reference FROM itsm_cases LIMIT 1").fetchone()[0]

    def take(self, kind="Ticket"):
        return self.call(
            "take",
            itsm.Take(
                origin="incident",
                origin_id="Zabbix|srv|down",
                kind=kind,
                by="admin",
                qualification="Incident récurrent à analyser",
            ),
        )

    def prepared(self, kind="Ticket"):
        case = self.take(kind)
        preview = self.call("preview", itsm.Action(id=case["id"], by="admin"))
        return case, itsm.Action(
            id=case["id"], by="admin", confirmed=True, preview_hash=preview["preview_hash"]
        )

    def test_requires_takeover(self):
        with self.connect() as db:
            db.execute("UPDATE incidents SET state='open'")
        with self.assertRaises(HTTPException) as exc:
            self.take()
        self.assertEqual(exc.exception.status_code, 409)

    def test_open_incident_acknowledged_with_ticket_request(self):
        with self.connect() as db:
            db.execute("UPDATE incidents SET state='open', owner=NULL")
        case = self.call(
            "take",
            itsm.Take(origin="incident", origin_id="Zabbix|srv|down", by="operator", acknowledge=True),
        )
        self.assertEqual(case["owner"], "operator")
        with self.connect() as db:
            state, owner = db.execute("SELECT state, owner FROM incidents").fetchone()
            kinds = [r[0] for r in db.execute("SELECT kind FROM incident_events")]
        self.assertEqual((state, owner), ("acknowledged", "operator"))
        self.assertIn("ack", kinds)

    def test_viewer_forbidden(self):
        with mock.patch.dict(os.environ, {"INFRAOPS_LOCAL_ROLE": "viewer"}):
            with self.assertRaises(HTTPException) as exc:
                self.take()
        self.assertEqual(exc.exception.status_code, 403)

    def test_preview_is_local_and_requires_confirmation(self):
        _, body = self.prepared()
        self.factory.assert_not_called()
        with self.assertRaises(HTTPException):
            self.call("create", body.model_copy(update={"confirmed": False}))
        self.factory.assert_not_called()

    def test_ticket_and_double_click(self):
        case, body = self.prepared()
        result = self.call("create", body)
        again = self.call("create", body)
        self.assertEqual(
            (result["status"], result["remote_id"], again["remote_id"]), ("linked", 123, 123)
        )
        self.client.create.assert_called_once()
        self.assertEqual(self.client.create.call_args.args[0], "Ticket")
        self.assertEqual(self.client.create.call_args.args[1]["type"], 1)
        self.client.observer.assert_called_once_with("Ticket", 123, 6)
        self.assertEqual(result["taken_at"], case["taken_at"])
        self.assertEqual(self.take()["id"], case["id"])

    def test_native_problem(self):
        _, body = self.prepared("Problem")
        self.assertEqual(self.call("create", body)["kind"], "Problem")
        self.assertEqual(self.client.create.call_args.args[0], "Problem")
        self.assertNotIn("type", self.client.create.call_args.args[1])
        self.client.observer.assert_called_once_with("Problem", 123, 6)

    def test_concurrent_creation(self):
        _, body = self.prepared()
        entered, release = threading.Event(), threading.Event()

        def delayed(*args):
            entered.set()
            release.wait(5)
            return 123

        self.client.create.side_effect = delayed
        with ThreadPoolExecutor(2) as pool:
            first = pool.submit(self.call, "create", body)
            self.assertTrue(entered.wait(5))
            try:
                with self.assertRaises(HTTPException) as exc:
                    self.call("create", body)
                self.assertEqual(exc.exception.status_code, 409)
            finally:
                release.set()
            self.assertEqual(first.result()["status"], "linked")
        self.client.create.assert_called_once()

    def test_timeout_then_reconcile_without_post(self):
        _, body = self.prepared()
        self.client.create.side_effect = GlpiError("Délai dépassé", uncertain=True)
        self.assertEqual(self.call("create", body)["status"], "uncertain")
        with self.assertRaises(HTTPException):
            self.call("create", body)
        self.client.find.return_value = [123]
        self.assertEqual(self.call("reconcile", body)["status"], "linked")
        self.client.create.assert_called_once()

    def test_no_match_is_not_proof_of_absence(self):
        _, body = self.prepared()
        self.client.create.side_effect = GlpiError("Délai", uncertain=True)
        self.call("create", body)
        self.client.find.return_value = []
        self.assertEqual(self.call("reconcile", body)["status"], "uncertain")
        self.client.create.assert_called_once()

    def test_observer_failure_preserves_id(self):
        _, body = self.prepared()
        self.client.observer.side_effect = GlpiError("Observateur refusé")
        result = self.call("create", body)
        self.assertEqual((result["status"], result["remote_id"]), ("partial", 123))
        self.client.observer.side_effect = None
        self.assertEqual(self.call("reconcile", body)["status"], "linked")
        self.client.create.assert_called_once()

    def test_invalid_token_before_post_can_retry(self):
        _, body = self.prepared()
        self.factory.return_value.opened.return_value.__enter__.side_effect = GlpiError(
            "GLPI HTTP 401 : jeton invalide"
        )
        self.assertEqual(self.call("create", body)["status"], "failed")
        self.client.create.assert_not_called()

    def test_unavailable_or_invalid_post_is_uncertain(self):
        _, body = self.prepared()
        self.client.create.side_effect = GlpiError("GLPI HTTP 503", uncertain=True)
        self.assertEqual(self.call("create", body)["status"], "uncertain")

    def test_html_and_secrets(self):
        with self.connect() as db:
            db.execute(
                "UPDATE incidents SET evidence=?,title=?",
                ("<script>alert(1)</script> password=hidden-value", "<img src=x onerror=bad()>"),
            )
        case = self.take()
        result = self.call("preview", itsm.Action(id=case["id"], by="admin"))
        raw = json.dumps(result)
        self.assertNotIn("hidden-value", raw)
        self.assertNotIn("<script>", raw)
        self.assertIn("&lt;script&gt;", raw)

    def test_collection_never_creates(self):
        with self.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM itsm_cases").fetchone()[0], 0)
        self.factory.assert_not_called()

    def test_finding_problem_is_explicitly_qualified(self):
        self.context.rows = lambda: [
            {
                "key": "srv",
                "name": "srv",
                "ip": "192.0.2.1",
                "environment": "Lab",
                "collected_at": "2026-10-20T10:00:00+00:00",
                "findings": [
                    {
                        "id": "disk",
                        "title": "Disque saturé",
                        "severity": "warning",
                        "evidence": "95 %",
                    }
                ],
            }
        ]
        body = itsm.Take(
            origin="finding", origin_id="disk", host_key="srv", kind="Problem", by="admin"
        )
        with self.assertRaises(HTTPException):
            self.call("take", body)
        result = self.call(
            "take", body.model_copy(update={"qualification": "Saturation structurelle récurrente"})
        )
        self.assertEqual(
            (result["snapshot"]["ip"], result["snapshot"]["environment"]), ("192.0.2.1", "Lab")
        )
        self.assertEqual(self.call("take", body)["id"], result["id"])
        self.factory.assert_not_called()

    def test_recovered_incident_keeps_existing_association(self):
        case, body = self.prepared()
        self.call("create", body)
        with self.connect() as db:
            db.execute("UPDATE incidents SET state='resolved'")
        self.assertEqual(self.take()["id"], case["id"])
        self.assertEqual(self.call("create", body)["remote_id"], 123)
        self.client.create.assert_called_once()

    def test_linked_status_refresh_does_not_write_glpi(self):
        _, body = self.prepared()
        self.call("create", body)
        self.client.reset_mock()
        self.assertEqual(self.call("reconcile", body)["status"], "linked")
        self.client.read.assert_called_once_with("Ticket", 123)
        self.client.create.assert_not_called()
        self.client.observer.assert_not_called()

    def test_current_takeover_required_when_creating(self):
        _, body = self.prepared()
        with self.connect() as db:
            db.execute("UPDATE incidents SET state='open'")
        with self.assertRaises(HTTPException):
            self.call("create", body)
        self.factory.assert_not_called()

    def test_json_secrets_are_removed(self):
        evidence = '{"password": "private test value", "user_token": "private test credential"}'  # pragma: allowlist secret — valeurs synthétiques du test de masquage
        self.assertNotIn("private test", itsm.clean(evidence))

    def test_preview_digest_and_history(self):
        case, body = self.prepared()
        with self.assertRaises(HTTPException):
            self.call("create", body.model_copy(update={"preview_hash": "bad"}))
        self.call("create", body)
        detail = self.routes["/api/itsm/detail"](case["id"])
        self.assertEqual(
            [e["action"] for e in detail["events"]][::-1], ["take", "preview", "create", "linked"]
        )


class AlertAndZabbixOriginTests(WorkflowTests):
    """Alertes et problèmes Zabbix : relus côté serveur, une occurrence = un dossier."""

    ALERT = {
        "id": "SSH:disk:critical",
        "source": "SSH",
        "severity": "critical",
        "title": "Disque plein",
        "evidence": "Occupation 97 %",
        "rule": "Disque ≥ 95 %",
        "observed_at": "2026-10-20T10:00:00+00:00",
        "count": 1,
        "targets": [{"name": "srv1", "detail": "/var 97 %", "started_at": "2026-10-19T08:00:00+00:00"}],
    }

    def setUp(self):
        super().setUp()
        self.alerts = [dict(self.ALERT), {**self.ALERT, "id": "SSH:uptime:info", "severity": "info"}]
        patch = mock.patch(
            "alert_center.build", side_effect=lambda *a, **k: {"alerts": self.alerts}
        )
        patch.start()
        self.addCleanup(patch.stop)
        self.context.api_connections = lambda: [
            {
                "key": "zbx",
                "provider": "Zabbix",
                "last_result": {
                    "status": "observed",
                    # Récente : une liste ancienne ne prouve plus l'absence d'un trigger.
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                    "inventory": {
                        "problems": [
                            {
                                "triggerid": "4242",
                                "description": "MS Nantissement DOWN",
                                "severity": "critical",
                                "severity_label": "Haute",
                                "hosts": ["prdlabsqu01"],
                                "last_change": "1792800000",
                            }
                        ]
                    },
                },
            }
        ]

    def take_origin(self, origin, origin_id, host_key=""):
        return self.call(
            "take", itsm.Take(origin=origin, origin_id=origin_id, host_key=host_key, by="admin")
        )

    def test_alert_snapshot_from_server_and_single_case(self):
        case = self.take_origin("alert", "SSH:disk:critical")
        self.assertEqual(case["origin_id"], "SSH:disk:critical|2026-10-19T08:00:00+00:00")
        self.assertEqual(case["snapshot"]["title"], "Disque plein")
        self.assertIn("/var 97 %", case["snapshot"]["evidence"])
        self.assertEqual(self.take_origin("alert", "SSH:disk:critical")["id"], case["id"])
        # Même cause revenue plus tard : nouvelle occurrence, nouveau dossier.
        self.alerts[0]["targets"] = [{"name": "srv1", "started_at": "2026-10-20T09:00:00+00:00"}]
        self.assertNotEqual(self.take_origin("alert", "SSH:disk:critical")["id"], case["id"])

    def test_alert_unknown_or_info_refused(self):
        for alert_id, code in (("absente", 404), ("SSH:uptime:info", 409)):
            with self.subTest(alert_id=alert_id):
                with self.assertRaises(HTTPException) as exc:
                    self.take_origin("alert", alert_id)
                self.assertEqual(exc.exception.status_code, code)

    def test_alert_creates_ticket_after_preview(self):
        case = self.take_origin("alert", "SSH:disk:critical")
        preview = self.call("preview", itsm.Action(id=case["id"], by="admin"))
        self.assertIn("Disque plein", preview["payload"]["name"])
        self.assertEqual(preview["payload"]["urgency"], 5)
        done = self.call(
            "create",
            itsm.Action(id=case["id"], by="admin", confirmed=True, preview_hash=preview["preview_hash"]),
        )
        self.assertEqual((done["status"], done["remote_id"]), ("linked", 123))

    def test_ticket_is_readable(self):
        self.context.rows = lambda: [
            {"key": "reclabswr04", "name": "reclabswr04", "ip": "10.77.0.142", "environment": "PREPROD"}
        ]
        self.alerts[0] = {
            **self.ALERT,
            "source": "Zabbix",
            "severity": "preventive",
            "title": "Too many processes on reclabswr04.host.example.test",
            "targets": [{"name": "reclabswr04.host.example.test", "host_key": None, "started_at": "1792510287"}],
        }
        case = self.take_origin("alert", "SSH:disk:critical")
        self.assertRegex(case["reference"], r"^OC-[0-9A-F]{8}$")
        # Serveur Zabbix en FQDN retrouvé par son nom court dans l'inventaire.
        self.assertEqual((case["snapshot"]["ip"], case["snapshot"]["environment"]), ("10.77.0.142", "PREPROD"))
        content = self.call("preview", itsm.Action(id=case["id"], by="admin"))["payload"]
        self.assertEqual(
            content["name"],
            "[Préventif] Too many processes on reclabswr04.host.example.test (Zabbix) · " + case["reference"],
        )
        self.assertIn("Préventif — Too many processes", content["content"])
        self.assertIn("10.77.0.142, PREPROD", content["content"])
        self.assertNotIn("preventive", content["content"])
        self.assertEqual(content["content"].count("reclabswr04.host.example.test sur"), 0)
        # Dates lisibles avec décalage explicite ; l'ISO ne reste que dans l'identifiant technique.
        lisible = content["content"].split("Identifiant technique")[0]
        self.assertNotIn("T15:31", lisible)
        self.assertRegex(lisible, r"\d{2}/\d{2}/\d{4} \d{2}:\d{2} \(UTC[+-]\d{2}:\d{2}\)")

    def test_several_servers_list_each_ip(self):
        self.context.rows = lambda: [
            {"key": "backup", "name": "backup", "ip": "10.77.0.10", "environment": "PROD"},
            {"key": "prdlabbak02", "name": "prdlabbak02", "ip": "10.77.0.20", "environment": "PROD"},
        ]
        self.alerts[0] = {
            **self.ALERT,
            "count": 3,
            "targets": [
                {"name": "backup.host.example.test"},
                {"name": "prdlabbak02.host.example.test"},
                {"name": "inconnu.host.example.test"},
            ],
        }
        snapshot = self.take_origin("alert", "SSH:disk:critical")["snapshot"]
        self.assertEqual(
            snapshot["ip"],
            "backup : 10.77.0.10 · prdlabbak02 : 10.77.0.20 · inconnu : non inventorié",
        )
        self.assertEqual(snapshot["environment"], "PROD")

    def test_ticket_name_adds_server_and_keeps_reference_when_long(self):
        case = {"reference": "OC-ABCDEF12"}
        name = itsm.ticket_name(case, {"title": "Disque plein", "severity": "critical", "target": "srv1.host.x", "source": "SSH"})
        self.assertEqual(name, "[Critique] Disque plein — srv1 (SSH) · OC-ABCDEF12")
        long = itsm.ticket_name(case, {"title": "x" * 400, "severity": "warning"})
        self.assertLessEqual(len(long), 250)
        self.assertTrue(long.endswith(" · OC-ABCDEF12"))

    def test_zabbix_problem_read_from_last_collection(self):
        case = self.take_origin("zabbix", "4242", "zbx")
        self.assertTrue(case["origin_id"].startswith("zbx|4242|"))
        self.assertEqual(case["snapshot"]["title"], "MS Nantissement DOWN")
        self.assertEqual(case["snapshot"]["target"], "prdlabsqu01")
        for trigger, connection in (("9999", "zbx"), ("4242", "autre")):
            with self.subTest(trigger=trigger, connection=connection):
                with self.assertRaises(HTTPException) as exc:
                    self.take_origin("zabbix", trigger, connection)
                self.assertEqual(exc.exception.status_code, 404)

    def test_status_reports_transport_without_secrets(self):
        insecure = Settings("http://glpi.example.test:9090", "app", "user", 0, 61, 6, 15, insecure=True)
        with mock.patch("itsm.Settings.load", return_value=insecure):
            status = self.routes["/api/itsm/status"]()
        self.assertEqual((status["configured"], status["transport"]), (True, "http"))
        self.assertNotIn("app", json.dumps(status).replace("available", ""))
        with mock.patch("itsm.Settings.load", side_effect=GlpiError("Connecteur GLPI désactivé")):
            self.assertFalse(self.routes["/api/itsm/status"]()["configured"])


class StatusSyncTests(AlertAndZabbixOriginTests):
    """Boucle de retour GLPI : badge, relecture périodique en lecture seule, incohérences."""

    def links(self):
        return {i["origin"]: i for i in self.routes["/api/itsm/links"]()["items"]}

    def linked(self):
        _, body = self.prepared()
        self.call("create", body)
        self.factory.reset_mock()
        self.client.reset_mock()
        return body

    def status(self, value):
        self.client.read.side_effect = lambda kind, ident: {
            "id": ident, "name": "[" + self.reference() + "]", "status": value
        }

    def test_links_expose_status_without_url(self):
        self.linked()
        response = self.routes["/api/itsm/links"]()
        item = response["items"][0]
        self.assertEqual(
            (item["origin_id"], item["remote_id"], item["remote_status"], item["remote_status_label"]),
            ("Zabbix|srv|down", 123, "1", "Nouveau"),
        )
        self.assertEqual((item["origin_state"], item["mismatch"]), ("active", None))
        self.assertIsNotNone(item["remote_checked_at"])
        self.assertNotIn("glpi.example.test", json.dumps(response))
        self.assertNotIn("url", item)
        self.assertNotIn("remote_base", item)

    def test_refresh_reads_only_and_records_change(self):
        self.linked()
        self.status(5)
        result = itsm.refresh(self.context)
        self.assertEqual((result["checked"], result["changed"], result["error"]), (1, 1, None))
        self.client.read.assert_called_once_with("Ticket", 123)
        self.assertEqual(
            [c[0] for c in self.client.mock_calls if not c[0].startswith("read")], []
        )
        item = self.links()["incident"]
        self.assertEqual(item["remote_status_label"], "Résolu")
        self.assertEqual(item["mismatch"], "Ticket GLPI résolu, anomalie toujours active")
        with self.connect() as db:
            history = db.execute(
                "SELECT actor,result FROM itsm_events WHERE action='status'"
            ).fetchall()
        self.assertEqual(history, [(itsm.SYNC_ACTOR, "Statut GLPI : Nouveau → Résolu")])
        # Statut inchangé : aucune nouvelle ligne d'historique.
        self.assertEqual(itsm.refresh(self.context)["changed"], 0)

    def test_resolved_incident_with_open_ticket(self):
        self.linked()
        with self.connect() as db:
            db.execute("UPDATE incidents SET state='resolved'")
        self.assertEqual(
            self.links()["incident"]["mismatch"],
            "Anomalie résolue dans OpsControl, ticket GLPI encore ouvert",
        )
        cases = self.routes["/api/itsm/cases"]()["items"]
        self.assertEqual(cases[0]["mismatch"], self.links()["incident"]["mismatch"])

    def test_alert_and_zabbix_origin_states(self):
        self.take_origin("alert", "SSH:disk:critical")
        self.take_origin("zabbix", "4242", "zbx")
        with self.connect() as db:
            db.execute(
                "UPDATE itsm_cases SET status='linked',remote_status='1',remote_base=?,"
                "remote_id=CASE origin WHEN 'alert' THEN 201 ELSE 202 END",
                (self.settings.base,),
            )
        itsm.refresh(self.context)
        states = {k: v["origin_state"] for k, v in self.links().items()}
        self.assertEqual(states, {"alert": "active", "zabbix": "active"})
        # Alerte disparue mais audit SSH incomplet : absence non prouvée, état inconnu.
        self.alerts = []
        zabbix = self.context.api_connections()
        zabbix[0]["last_result"]["inventory"]["problems"] = []
        self.context.api_connections = lambda: zabbix
        itsm.refresh(self.context)
        links = self.links()
        self.assertEqual((links["alert"]["origin_state"], links["alert"]["mismatch"]), (None, None))
        self.assertEqual(links["zabbix"]["origin_state"], "resolved")
        self.assertIn("ticket GLPI encore ouvert", links["zabbix"]["mismatch"])
        # Audit SSH récent mais disque non mesuré (CPU seul) : pas de preuve de résolution.
        audit = {"key": "srv1", "name": "srv1", "collected_at": "2026-10-20T10:00:00+00:00",
                 "coverage": {"measured": 4}, "cpu": 12}
        self.context.rows = lambda: [audit]
        itsm.refresh(self.context)
        self.assertIsNone(self.links()["alert"]["origin_state"])
        # Disque mesuré et sain : l'absence de l'alerte vaut résolution.
        audit["filesystems"] = [{"fs": "/dev/sda1", "mount": "/", "use_pct": 41}]
        # Collecte Zabbix en échec : l'état redevient inconnu, jamais « résolu ».
        zabbix[0]["last_result"] = {"status": "failed", "error": "délai"}
        itsm.refresh(self.context)
        links = self.links()
        self.assertEqual(links["alert"]["origin_state"], "resolved")
        self.assertEqual((links["zabbix"]["origin_state"], links["zabbix"]["mismatch"]), (None, None))

    def test_refresh_without_configuration_or_session(self):
        self.linked()
        with mock.patch("itsm.Settings.load", side_effect=GlpiError("Connecteur GLPI désactivé")):
            self.assertEqual(itsm.refresh(self.context)["error"], "Connecteur GLPI désactivé")
        self.factory.assert_not_called()
        self.factory.return_value.opened.side_effect = GlpiError("GLPI HTTP 401 : jeton invalide")
        result = itsm.refresh(self.context)
        self.assertEqual((result["error"], result["checked"]), ("GLPI HTTP 401 : jeton invalide", 0))
        self.assertEqual(self.links()["incident"]["remote_status"], "1")

    def test_closed_ticket_read_once_a_day(self):
        self.linked()
        with self.connect() as db:
            db.execute("UPDATE itsm_cases SET remote_status='6',remote_checked_at=?", (itsm.now(),))
        self.assertEqual(itsm.refresh(self.context)["checked"], 0)
        self.client.read.assert_not_called()

    def test_real_client_sends_only_get(self):
        self.linked()
        methods = []

        def opened(req, timeout):
            methods.append((req.get_method(), req.full_url.split("/apirest.php/")[1]))
            path = req.full_url.split("/apirest.php/")[1]
            body = {"session_token": "abc"} if path == "initSession" else {
                "id": 123, "name": "[" + self.reference() + "]", "status": 2
            }
            response = mock.MagicMock()
            response.__enter__.return_value.read.return_value = json.dumps(body).encode()
            return response

        opener = mock.Mock()
        opener.open.side_effect = opened
        with mock.patch("itsm.Client", Client), mock.patch(
            "glpi_connector.request.build_opener", return_value=opener
        ):
            self.assertEqual(itsm.refresh(self.context)["changed"], 1)
        self.assertEqual(
            methods, [("GET", "initSession"), ("GET", "Ticket/123"), ("GET", "killSession")]
        )
        self.assertEqual(self.links()["incident"]["remote_status_label"], "En cours (attribué)")

    def resolve_incident(self, minutes_ago):
        resolved = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()
        with self.connect() as db:
            db.execute("UPDATE incidents SET state='resolved', resolved_at=?", (resolved,))

    def glpi_status(self, start):
        """GLPI simulé : l'ajout d'une solution fait passer le ticket à Résolu."""
        current = {"status": start}
        self.client.read.side_effect = lambda kind, ident: {
            "id": ident, "name": "[" + self.reference() + "]", "status": current["status"]
        }
        self.client.solve.side_effect = lambda *a: current.update(status=5) or 77
        return current

    def test_creation_in_progress_assigned_to_group(self):
        _, body = self.prepared()
        self.call("create", body)
        sent = self.client.create.call_args.args[1]
        self.assertEqual((sent["status"], sent["_groups_id_assign"]), (2, 6))

    def test_auto_resolve_after_confirmation_delay(self):
        self.linked()
        self.glpi_status(2)
        self.resolve_incident(minutes_ago=3)
        itsm.refresh(self.context)
        self.client.solve.assert_not_called()  # délai de confirmation (10 min) non écoulé
        self.resolve_incident(minutes_ago=15)
        result = itsm.refresh(self.context)
        self.assertEqual(result["resolved"], 1)
        kind, ident, content = self.client.solve.call_args.args
        self.assertEqual((kind, ident), ("Ticket", 123))
        self.assertIn(self.reference(), content)
        self.assertIn("Résolu automatiquement par OpsControl", content)
        item = self.links()["incident"]
        self.assertEqual((item["remote_status_label"], item["mismatch"]), ("Résolu", None))
        with self.connect() as db:
            actions = [r[0] for r in db.execute("SELECT action FROM itsm_events WHERE actor=?", (itsm.SYNC_ACTOR,))]
        self.assertEqual(sorted(actions), ["auto_resolve", "status", "status"])  # 1 → 2, puis 2 → 5
        itsm.refresh(self.context)
        self.client.solve.assert_called_once()
        self.client.create.assert_not_called()

    def test_auto_resolve_failure_is_not_retried_until_reoccurrence(self):
        self.linked()
        self.glpi_status(1)
        self.client.solve.side_effect = GlpiError("GLPI HTTP 403 : droits insuffisants")
        self.resolve_incident(minutes_ago=30)
        itsm.refresh(self.context)
        itsm.refresh(self.context)
        self.client.solve.assert_called_once()
        with self.connect() as db:
            message = db.execute("SELECT result FROM itsm_events WHERE action='auto_resolve'").fetchone()[0]
        self.assertIn("droits insuffisants", message)
        self.assertEqual(self.links()["incident"]["mismatch"], "Anomalie résolue dans OpsControl, ticket GLPI encore ouvert")
        # L'incident revient puis se résout de nouveau : une nouvelle tentative est permise.
        with self.connect() as db:
            db.execute("UPDATE incidents SET state='acknowledged'")
        itsm.refresh(self.context)
        self.resolve_incident(minutes_ago=30)
        itsm.refresh(self.context)
        self.assertEqual(self.client.solve.call_count, 2)

    def test_auto_resolve_disabled_or_unknown_origin(self):
        self.linked()
        self.glpi_status(1)
        self.resolve_incident(minutes_ago=30)
        with mock.patch.dict(os.environ, {"GLPI_AUTO_RESOLVE": "false"}):
            itsm.refresh(self.context)
        self.client.solve.assert_not_called()

    def test_zabbix_problem_gone_resolves_ticket(self):
        self.take_origin("zabbix", "4242", "zbx")
        with self.connect() as db:
            db.execute("UPDATE itsm_cases SET status='linked',remote_status='2',remote_base=?,remote_id=202", (self.settings.base,))
        self.glpi_status(2)
        zabbix = self.context.api_connections()
        zabbix[0]["last_result"]["inventory"]["problems"] = []
        self.context.api_connections = lambda: zabbix
        with mock.patch.dict(os.environ, {"GLPI_AUTO_RESOLVE_DELAY_SECONDS": "0"}):
            self.assertEqual(itsm.refresh(self.context)["resolved"], 1)
        self.assertEqual(self.client.solve.call_args.args[:2], ("Ticket", 202))

    def test_truncated_or_old_zabbix_list_never_resolves_ticket(self):
        # OC-AUDIT-004 : un trigger sorti du top 500, ou une collecte ancienne, n'est pas une résolution.
        self.take_origin("zabbix", "4242", "zbx")
        with self.connect() as db:
            db.execute("UPDATE itsm_cases SET status='linked',remote_status='2',remote_base=?,remote_id=202", (self.settings.base,))
        self.glpi_status(2)
        zabbix = self.context.api_connections()
        last = zabbix[0]["last_result"]
        last["inventory"]["problems"] = []
        self.context.api_connections = lambda: zabbix
        old = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        for label, change in (("tronquée", {"truncated": True}), ("ancienne", {"collected_at": old})):
            with self.subTest(label):
                last["inventory"]["problems_truncated"] = change.get("truncated", False)
                last["collected_at"] = change.get("collected_at", datetime.now(timezone.utc).isoformat())
                with mock.patch.dict(os.environ, {"GLPI_AUTO_RESOLVE_DELAY_SECONDS": "0"}):
                    self.assertEqual(itsm.refresh(self.context)["resolved"], 0)
                self.assertIsNone(self.links()["zabbix"]["origin_state"])
        self.client.solve.assert_not_called()

    def test_sync_interval_bounds(self):
        for raw, expected in (("0", 0), ("-5", 0), ("60", 300), ("900", 900), ("abc", 900), ("999999", 86400)):
            with self.subTest(raw=raw), mock.patch.dict(os.environ, {"GLPI_STATUS_SYNC_SECONDS": raw}):
                self.assertEqual(itsm.sync_seconds(), expected)

    def test_labels_and_mismatch_rules(self):
        self.assertEqual([itsm.status_label(str(i)) for i in range(1, 9)], list(itsm.GLPI_STATUSES.values()))
        self.assertIsNone(itsm.status_label(None))
        self.assertIsNone(itsm.mismatch(None, "6"))
        self.assertIsNone(itsm.mismatch("active", "2"))
        self.assertIsNone(itsm.mismatch("resolved", "6"))
        self.assertEqual(itsm.mismatch("active", "6"), "Ticket GLPI clos, anomalie toujours active")


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.client = Client(Settings("https://glpi.example.test", "", ""))
        self.client.opener = mock.Mock()

    def test_http_statuses_are_sanitized(self):
        for code in (400, 401, 403, 404, 409, 429, 500, 503):
            with self.subTest(code=code):
                self.client.opener.open.side_effect = HTTPError(
                    "https://example.test", code, "credential", {}, None
                )
                with self.assertRaises(GlpiError) as exc:
                    self.client.call("POST", "Ticket/", {})
                self.assertNotIn("credential", str(exc.exception))
                self.assertEqual(exc.exception.uncertain, code >= 500)

    def test_unexpected_creation_response(self):
        with mock.patch.object(self.client, "call", return_value={"message": "unexpected"}):
            with self.assertRaises(GlpiError) as exc:
                self.client.create("Ticket", {})
            self.assertTrue(exc.exception.uncertain)

    def test_search_requires_complete_results(self):
        with mock.patch.object(
            self.client,
            "call",
            side_effect=[{"1": {"field": "name"}}, {"totalcount": 2, "data": [{"2": 123}]}],
        ):
            with self.assertRaises(GlpiError):
                self.client.find("Ticket", "OC-reference")

    def test_invalid_observer_response(self):
        with mock.patch.object(self.client, "call", return_value=[None]):
            with self.assertRaises(GlpiError):
                self.client.observer("Ticket", 123, 6)

    def test_https_and_tls_are_mandatory(self):
        for base, verify in (
            ("http://glpi.example.test", "true"),
            ("https://glpi.example.test", "false"),
        ):
            with mock.patch.dict(
                os.environ,
                {"GLPI_ENABLED": "true", "GLPI_BASE_URL": base, "GLPI_VERIFY_TLS": verify},
            ):
                with self.assertRaises(GlpiError):
                    Settings.load()

    def test_http_only_by_explicit_host_exception(self):
        env = {
            "GLPI_ENABLED": "true",
            "GLPI_BASE_URL": "http://glpi.example.test:9090",
            "GLPI_REQUESTER_ID": "61",
            "GLPI_OBSERVER_GROUP_ID": "6",
            "GLPI_APP_TOKEN": "app",
            "GLPI_USER_TOKEN": "user",
        }
        for allow, hosts in (("false", "glpi.example.test"), ("true", ""), ("true", "autre.example.test")):
            with self.subTest(allow=allow, hosts=hosts):
                with mock.patch.dict(
                    os.environ, {**env, "GLPI_ALLOW_HTTP": allow, "GLPI_HTTP_HOSTS": hosts}
                ):
                    with self.assertRaises(GlpiError):
                        Settings.load()
        with mock.patch.dict(
            os.environ,
            {**env, "GLPI_ALLOW_HTTP": "true", "GLPI_HTTP_HOSTS": "autre.test, GLPI.example.test"},
        ):
            settings = Settings.load()
        self.assertTrue(settings.insecure)
        self.assertEqual(settings.base, "http://glpi.example.test:9090")
        with mock.patch.dict(os.environ, {**env, "GLPI_BASE_URL": "https://glpi.example.test"}):
            self.assertFalse(Settings.load().insecure)

    def test_session_always_closed(self):
        with mock.patch.object(
            self.client, "call", side_effect=[{"session_token": "session"}, None]
        ) as call:
            with self.assertRaises(RuntimeError):
                with self.client.opened():
                    raise RuntimeError
            self.assertEqual(call.call_args.args, ("GET", "killSession"))

    def test_observer_relation_and_verification(self):
        with mock.patch.object(
            self.client, "call", side_effect=[[], {"id": 9}, [{"groups_id": 6, "type": 3}]]
        ) as call:
            self.client.observer("Problem", 123, 6)
            self.assertEqual(
                call.call_args_list[1].args,
                (
                    "POST",
                    "Group_Problem/",
                    {"input": {"problems_id": 123, "groups_id": 6, "type": 3}},
                ),
            )


if __name__ == "__main__":
    unittest.main()
