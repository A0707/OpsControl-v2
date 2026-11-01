"""Pagination, agrégats et plans de sécurité sur des preuves simulées."""

import testing_env  # noqa: F401

import json
import asyncio
from pathlib import Path
from contextlib import contextmanager
from types import SimpleNamespace
from urllib.parse import urlencode, urlsplit

from fastapi import FastAPI, HTTPException

import security_cve as sc
import itsm
from routers import all_routes
from test_security_cve import Base


class SecurityConsoleTests(Base):
    def test_cache_invalide_synthese_et_recommandations_apres_ecriture(self):
        self.context.DB = Path(self.path)
        try:
            summary = self.get['/api/security/summary']
            plans = self.get['/api/security/recommendations']
            first, before_plans = summary(), plans()
            self.assertIs(summary(), first)
            self.assertIs(plans(), before_plans)
            with self.connect() as db:
                db.execute("UPDATE sec_vulns SET status='resolved'")
            after = summary()
            self.assertEqual(after['counts']['open'], 0)
            self.assertNotEqual(first['counts']['open'], after['counts']['open'])
            self.assertIsNot(plans(), before_plans)
            self.hosts[0]['name'] = 'Nom modifié sans écriture'
            self.assertIsNot(summary(), after)
        finally:
            self.context.security_read_cache_close()

    def test_classement_optimise_identique_a_la_projection_detaillee(self):
        self.hosts[0]['name'] = 'Équipe A'
        self.hosts[1]['name'] = 'Équipe Z'
        with self.connect() as db:
            template = db.execute('SELECT * FROM sec_vulns LIMIT 1').fetchone()
            columns = [r[1] for r in db.execute('PRAGMA table_info(sec_vulns)')]
            for n in range(30):
                values = dict(zip(columns, template))
                values.update(id=f'{n:020d}', host_key=('web01', 'db01', 'hors-inventaire')[n % 3])
                db.execute('INSERT INTO sec_vulns VALUES(' + ','.join('?' for _ in columns) + ')',
                           tuple(values[k] for k in columns))
            expected = sc.vulns(db, self.hosts, "v.status IN ('open','validated','in_progress')")
            expected.sort(key=lambda v: (-v['priority'], v['host_name'], v['cve'], v['id']))
        result = self.get['/api/security/summary']()
        self.assertEqual([v['id'] for v in result['top_vulns']], [v['id'] for v in expected[:10]])
        self.assertEqual(result['counts']['open'], len(expected))

    def request(self, url, params=None):
        parts = urlsplit(url)
        sent = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            sent.append(message)

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": parts.path,
            "raw_path": parts.path.encode(),
            "query_string": (urlencode(params) if params else parts.query).encode(),
            "headers": [],
            "client": ("127.0.0.1", 50000),
            "server": ("127.0.0.1", 8001),
            "root_path": "",
        }
        asyncio.run(self.app(scope, receive, send))
        status = next(m["status"] for m in sent if m["type"] == "http.response.start")
        payload = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
        return SimpleNamespace(status_code=status, json=lambda: json.loads(payload))

    def setUp(self):
        super().setUp()
        self.app = FastAPI()
        sc.install(self.app, self.context)
        self.store_inventory()
        self.store_fixes()
        sc.analyze(self.context)
        self.get = {r.path: r.endpoint for r in all_routes(self.app) if "GET" in r.methods}

    def test_pages_exhaustives_stables_et_filtre_unicode(self):
        self.hosts[0]["name"] = "ÉQUIPE web"
        first = self.request("/api/security/vulns?limit=2&projection=list").json()
        second = self.request("/api/security/vulns?limit=2&offset=2&projection=list").json()
        ids = [v["id"] for v in first["items"] + second["items"]]
        self.assertEqual(first["total"], 3)
        self.assertEqual(len(set(ids)), 3)
        self.assertNotIn("description", first["items"][0])
        filtered = self.request("/api/security/vulns", params={"q": "équipe", "limit": 2}).json()
        self.assertEqual(filtered["total"], 3)
        self.assertEqual(self.request("/api/security/vulns?offset=20").json()["items"], [])
        self.assertEqual(self.request("/api/security/vulns?limit=0").status_code, 422)
        self.assertEqual(self.request("/api/security/vulns?projection=unsafe").status_code, 422)
        self.assertEqual(
            self.request("/api/security/vulns", params={"q": "' OR 1=1 --"}).json()["total"], 0
        )
        self.assertEqual(
            self.request("/api/security/vulns", params={"host": "' OR 1=1 --"}).json()["total"], 0
        )

    def test_synthese_conserve_les_compteurs_et_les_dix_priorites(self):
        with self.connect() as db:
            original = sc.vulns(db, self.hosts, "v.status IN ('open','validated','in_progress')")
        data = self.get["/api/security/summary"]()
        self.assertEqual(data["counts"]["open"], len(original))
        self.assertEqual(data["counts"]["kev"], sum(v["kev"] for v in original))
        self.assertEqual(
            data["counts"]["to_verify"], sum(v["confidence"] == "à vérifier" for v in original)
        )
        self.assertEqual({v["id"] for v in data["top_vulns"]}, {v["id"] for v in original})
        self.assertEqual(data["top_hosts"][0]["count"], 3)
        for severity in ("critical", "high", "medium", "low", "none", "unknown"):
            self.assertEqual(
                data["by_severity"].get(severity, 0),
                sum((v["severity"] or "unknown") == severity for v in original),
            )

    def test_synthese_et_filtre_partagent_la_gravite_wazuh(self):
        with self.connect() as db:
            ident = db.execute("SELECT id FROM sec_vulns LIMIT 1").fetchone()[0]
            db.execute(
                "UPDATE sec_vulns SET evidence=? WHERE id=?",
                (json.dumps({"wazuh": {"cvss": 9.8, "severity": "critical"}}), ident),
            )
            db.execute(
                "UPDATE sec_cve SET cvss=NULL WHERE cve=(SELECT cve FROM sec_vulns WHERE id=?)",
                (ident,),
            )
        rows = self.request("/api/security/vulns?severity=critical").json()
        summary = self.request("/api/security/summary").json()
        self.assertIn(ident, [v["id"] for v in rows["items"]])
        self.assertEqual(summary["counts"]["critical"], rows["total"])

    def test_recommandations_ignorent_historique_resolu_et_lisent_les_bulletins_une_fois(self):
        before = self.get["/api/security/recommendations"]()
        with self.connect() as db:
            row = db.execute("SELECT * FROM sec_vulns LIMIT 1").fetchone()
            columns = [r[1] for r in db.execute("PRAGMA table_info(sec_vulns)")]
            for n in range(50):
                values = dict(zip(columns, row))
                values.update(id=f"{n:020d}", status="resolved")
                db.execute(
                    "INSERT INTO sec_vulns VALUES(" + ",".join("?" for _ in columns) + ")",
                    tuple(values[k] for k in columns),
                )
        statements = []
        connect = self.context.connect

        @contextmanager
        def traced():
            with connect() as db:
                db.set_trace_callback(statements.append)
                yield db

        self.context.connect = traced
        after = self.get["/api/security/recommendations"]()
        self.assertEqual(before["items"], after["items"])
        self.assertEqual(
            sum("SELECT cves, severity FROM sec_advisories" in s for s in statements), 1
        )

    def test_signal_de_veille_filtre_qualifie_et_jamais_resolu_par_lecture(self):
        with self.connect() as db:
            for ref, host in (("signal-web", "web01"), ("signal-db", "db01")):
                db.execute(
                    "INSERT INTO sec_notifications(ref,at,level,title,detail,hosts,cve) VALUES(?,?,?,?,?,?,?)",
                    (
                        ref,
                        sc.iso(),
                        "critical",
                        "CVE potentielle",
                        "Applicabilité à vérifier",
                        json.dumps([host]),
                        "CVE-2026-9999",
                    ),
                )
            ident = str(
                db.execute("SELECT id FROM sec_notifications WHERE ref='signal-web'").fetchone()[0]
            )
        data = self.request("/api/security/notifications?host=web01&limit=5").json()
        self.assertTrue(all(all(h["key"] == "web01" for h in n["hosts"]) for n in data["items"]))
        with self.assertRaises(HTTPException):
            itsm.security_alert_snapshot(self.context, ident, "db01")
        itsm.install(self.app, self.context)
        take = next(r.endpoint for r in all_routes(self.app) if r.path == "/api/itsm/take")
        request = SimpleNamespace(headers={})
        body = itsm.Take(origin="security_alert", origin_id=ident, host_key="web01", by="Opérateur")
        with self.assertRaises(HTTPException) as exc:
            take(body, request)
        self.assertEqual(exc.exception.status_code, 422)
        body = body.model_copy(
            update={"qualification": "Vérifier la version installée et le rétroportage."}
        )
        case = take(body, request)
        self.assertEqual(take(body, request)["id"], case["id"])
        self.assertEqual(case["snapshot"]["state"], "Signal à qualifier")
        with self.connect() as db:
            db.execute("UPDATE sec_notifications SET read_at=? WHERE id=?", (sc.iso(), int(ident)))
        states = itsm.origin_states(
            self.context,
            [{"id": case["id"], "origin": "security_alert", "origin_id": ident + "|web01"}],
        )
        self.assertIsNone(states.get(case["id"]))
