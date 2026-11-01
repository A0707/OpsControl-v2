"""IA locale : transport simulé, RBAC, index, secrets et approbation de diff."""

import testing_env  # noqa: F401 — avant app, aucune base ou collecte d'exploitation
import asyncio
import io
import json
import os
import tempfile
import threading
import unittest
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from fastapi import FastAPI

import access_policy
import ai_developer
import ai_service
from ai_llm import LLMError, LocalLLM, NoRedirect
from ai_rag import Index, permitted
from ai_security import SYSTEM, clean, endpoint
from test_access_policy import MUTATE, SECRET, call, proxy


class Security(unittest.TestCase):
    def test_addresses(self):
        self.assertEqual(endpoint("http://127.0.0.1:5678/v1"), "http://127.0.0.1:5678/v1")
        for url in (
            "http://localhost:1234/v1",
            "http://192.168.1.1:1234/v1",
            "http://127.0.0.1:1234/foo",
            "http://a:b@127.0.0.1:1234/v1",
            "http://127.0.0.1:1234/v1?key=abc",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                endpoint(url)
        with mock.patch.dict(os.environ, {"OPSCONTROL_AI_ALLOWED_IPS": "192.168.1.1"}):
            self.assertEqual(endpoint("https://192.168.1.1:5678/v1"), "https://192.168.1.1:5678/v1")

    def test_redaction(self):
        secret = "".join(["fixture-", "sensitive-value"])
        with mock.patch.dict(os.environ, {"SERVICE_API_TOKEN": secret}):
            private_key = "-" * 5 + "BEGIN RSA " + "PRIVATE KEY" + "-" * 5 + "\nprivate-content"
            for text in (
                secret,
                "Bearer short",
                json.dumps({"pass" + "word": "one two"}),
                "api_" + "key=abc",
                private_key,
            ):
                result = clean(text)
                self.assertNotIn(secret, result)
                self.assertNotIn("one two", result)
                self.assertNotIn("private-content", result)
                self.assertNotIn("short", result)

    def test_connector_auth_values_are_masked(self):
        # OC-AUDIT-008 : jeton opaque d'un connecteur (INFRAOPS_<SOURCE>_AUTH), sans syntaxe reconnaissable.
        sentinel = "".join(["opaque", "-sentinel-", "4f2a9c"])
        for name in ("INFRAOPS_ZABBIX_AUTH", "INFRAOPS_GLPI_APP_AUTH", "BACULA_CREDENTIALS"):
            with self.subTest(name), mock.patch.dict(os.environ, {name: sentinel}):
                self.assertNotIn(sentinel, clean("observation : " + sentinel + " fin"))

    def test_prompt_and_allowlist(self):
        self.assertIn("DONNÉES NON FIABLES", SYSTEM)
        for name in (
            "hosts.yaml",
            "data/state.sqlite3",
            "../README.md",
            "audit.log",
            "release/app.py",
            ".git/config",
            "RAPPORT-ACCES-SSH.md",
        ):
            self.assertFalse(permitted(name), name)
        self.assertTrue(permitted("routers/hosts.py"))


class Transport(unittest.TestCase):
    def setUp(self):
        self.client = LocalLLM()
        self.opener = mock.Mock()
        self.client.opener = self.opener

    def response(self, value):
        return io.BytesIO(json.dumps(value).encode())

    def test_real_request_shape(self):
        self.opener.open.return_value = self.response({"data": [{"id": "test-model"}]})
        self.assertEqual(self.client.models(), ["test-model"])
        req = self.opener.open.call_args.args[0]
        self.assertEqual(req.full_url, self.client.url + "/models")

    def test_offline_timeout_invalid(self):
        for error, status in (
            (urllib.error.URLError("offline"), 503),
            (TimeoutError(), 504),
            (urllib.error.HTTPError("u", 404, "missing", {}, None), 404),
        ):
            self.opener.open.side_effect = error
            with self.assertRaises(LLMError) as ctx:
                self.client.models()
            self.assertEqual(ctx.exception.status, status)
        self.opener.open.side_effect = None
        for value in (b"not json", b"[]", b'{"data": false}'):
            self.opener.open.return_value = io.BytesIO(value)
            with self.assertRaises(LLMError):
                self.client.models()

    def test_chat_success_and_missing_model(self):
        with (
            mock.patch.object(self.client, "models", return_value=[self.client.model]),
            mock.patch.object(
                self.client,
                "request",
                return_value={"choices": [{"message": {"content": "Diagnostic français"}}]},
            ),
        ):
            self.assertEqual(
                self.client.chat([{"role": "user", "content": "Question"}]), "Diagnostic français"
            )
        with (
            mock.patch.object(self.client, "models", return_value=[]),
            self.assertRaises(LLMError) as ctx,
        ):
            self.client.chat([])
        self.assertEqual(ctx.exception.status, 404)

    def test_invalid_and_tool_responses(self):
        with mock.patch.object(self.client, "models", return_value=[self.client.model]):
            for value in (
                {},
                {"choices": []},
                {"choices": [{"message": {"content": None}}]},
                {
                    "choices": [
                        {
                            "message": {
                                "content": "x",
                                "tool_calls": [{"function": {"name": "shell"}}],
                            }
                        }
                    ]
                },
            ):
                with (
                    mock.patch.object(self.client, "request", return_value=value),
                    self.assertRaises(LLMError),
                ):
                    self.client.chat([])

    def test_concurrency_and_context_limits(self):
        self.client.gate.acquire()
        with self.assertRaises(LLMError) as ctx:
            self.client.chat([])
        self.assertEqual(ctx.exception.status, 429)
        self.client.gate.release()
        with (
            mock.patch.object(self.client, "models", return_value=[self.client.model]),
            self.assertRaises(LLMError) as ctx,
        ):
            self.client.chat([{"role": "user", "content": "é" * 4000}])
        self.assertEqual(ctx.exception.status, 413)

    def test_stream_redaction_and_truncation(self):
        chunks = [
            b'data: {"choices":[{"delta":{"content":"pass"}}]}\n',
            b'data: {"choices":[{"delta":{"content":"word=abc"}}]}\n',
            b"data: [DONE]\n",
        ]
        self.opener.open.return_value = io.BytesIO(b"".join(chunks))
        with mock.patch.object(self.client, "models", return_value=[self.client.model]):
            self.assertNotIn("abc", self.client.chat([], stream=True))
            self.opener.open.return_value = io.BytesIO(chunks[0])
            with self.assertRaises(LLMError):
                self.client.chat([], stream=True)

    def test_cancel_and_redirect(self):
        cancel = threading.Event()
        cancel.set()
        self.opener.open.return_value = io.BytesIO(b"data: {}\n")
        with self.assertRaises(LLMError) as ctx:
            self.client.request("/chat/completions", {"stream": True}, cancel)
        self.assertEqual(ctx.exception.status, 499)
        with self.assertRaises(LLMError):
            NoRedirect().redirect_request(None, None, 302, "", {}, "http://remote/")


class Rag(unittest.TestCase):
    def test_incremental_search_permissions_deletion(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "README.md").write_text("Architecture SQLite WAL supervision", encoding="utf-8")
            (root / "app.py").write_text("specialcode FastAPI", encoding="utf-8")
            index = Index(root, root / "rag.sqlite3")
            with mock.patch("ai_rag.tracked", return_value=["README.md", "app.py", "hosts.yaml"]):
                self.assertEqual(index.update(), 2)
                self.assertEqual(index.update(), 0)
                self.assertEqual(index.search("SQLite")[0]["path"], "README.md")
                self.assertFalse(index.search("specialcode"))
                self.assertTrue(index.search("specialcode", code=True))
                (root / "README.md").write_text("Zabbix incident confirmé", encoding="utf-8")
                self.assertEqual(index.update(), 1)
                self.assertFalse(index.search("SQLite"))
                (root / "README.md").unlink()
                index.update()
                self.assertFalse(index.search("Zabbix"))

    def test_release_without_git_indexes_from_manifest(self):
        # OC-AUDIT-017 : archive extraite, ni .git ni git → liste du manifeste, aucun sous-processus.
        import hashlib
        import ai_rag
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            files = {"README.md": "Supervision SQLite WAL", "app.py": "x = 1", "hosts.yaml": "hosts: []"}
            for name, text in files.items():
                (root / name).write_text(text, encoding="utf-8")
            (root / "MANIFEST.sha256").write_text("".join(
                f"{hashlib.sha256(t.encode()).hexdigest()}  {n}\n" for n, t in files.items()) + "malformée\n",
                encoding="utf-8")
            with mock.patch("ai_rag.subprocess.run", side_effect=FileNotFoundError("git")) as git:
                self.assertEqual(ai_rag.tracked(root), ["README.md", "app.py", "hosts.yaml"])
                index = Index(root, root / "rag.sqlite3")
                self.assertEqual(index.update(), 2, "hosts.yaml reste exclu par permitted()")
                self.assertEqual(index.search("SQLite")[0]["path"], "README.md")
            git.assert_not_called()

    def test_history_isolation_and_redaction(self):
        with tempfile.TemporaryDirectory() as folder:
            history = ai_service.History(Path(folder) / "history.sqlite3")
            history.save("alice", "a" * 32, "password=abc", "token=def", [], "supervision")
            self.assertEqual(history.list("bob"), [])
            self.assertNotIn("abc", history.list("alice")[0]["question"])
            history.clear("bob")
            self.assertEqual(len(history.list("alice")), 1)
            history.clear("alice")
            self.assertEqual(history.list("alice"), [])


class Endpoints(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        root = Path(self.folder.name)
        (root / "README.md").write_text("Supervision SQLite WAL", encoding="utf-8")
        self.context = SimpleNamespace(
            BASE=root,
            DB=root / "production.sqlite3",
            rows=mock.Mock(
                return_value=[
                    {"key": "fixture", "status": "unknown", "pass" + "word": "never-send"}
                ]
            ),
        )
        self.env = mock.patch.dict(
            os.environ,
            {
                "OPSCONTROL_AI_ENABLED": "1",
                "OPSCONTROL_AI_DATA": str(root / "ai"),
                "INFRAOPS_TRUSTED_PROXY_SECRET": SECRET,
                "INFRAOPS_ADMINS": "admin",
                "INFRAOPS_OPERATORS": "operator",
                "OPSCONTROL_AI_CODE_READ": "0",
            },
            clear=False,
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.app = FastAPI()
        access_policy.install(self.app, limiter=access_policy.RateLimiter(limits={}))
        ai_service.install(self.app, self.context)
        self.models = mock.patch.object(LocalLLM, "models", return_value=["opscontrol-local"])
        self.models.start()
        self.addCleanup(self.models.stop)
        self.tracked = mock.patch("ai_rag.tracked", return_value=["README.md"])
        self.tracked.start()
        self.addCleanup(self.tracked.stop)

    def request(self, method, path, user="viewer", payload=None):
        return call(
            self.app, method, path, {**MUTATE, **proxy(user)}, json.dumps(payload or {}).encode()
        )[0:3:2]

    def test_authentication_disabled_and_no_implicit_admin(self):
        self.assertEqual(call(self.app, "GET", "/api/ai/status")[0], 401)
        with mock.patch.dict(os.environ, {"OPSCONTROL_AI_ENABLED": "0"}):
            self.assertEqual(self.request("GET", "/api/ai/status")[0], 503)
        with mock.patch.dict(
            os.environ,
            {
                "INFRAOPS_TRUSTED_PROXY_SECRET": "",
                "INFRAOPS_LOCAL_ROLE": "admin",
                "OPSCONTROL_AI_LOCAL_TOKEN": "",
            },
        ):
            self.assertEqual(call(self.app, "GET", "/api/ai/status")[0], 401)

    def test_roles_and_no_shell(self):
        with mock.patch.object(LocalLLM, "chat", return_value="Faits inconnus"):
            for user in ("viewer", "operator", "admin"):
                self.assertEqual(
                    self.request("POST", "/api/ai/chat", user, {"message": "Supervision"})[0], 200
                )
            for user in ("viewer", "operator", "admin"):
                self.assertEqual(
                    self.request(
                        "POST", "/api/ai/chat", user, {"message": "code", "mode": "développement"}
                    )[0],
                    403,
                )
            self.assertEqual(
                self.request("POST", "/api/ai/chat", payload={"message": "q", "command": "sh"})[0],
                422,
            )
            self.assertEqual(self.request("POST", "/api/ai/apply", "admin")[0], 404)
        self.assertFalse(self.context.DB.exists())

    def test_early_ai_refusals_carry_central_headers(self):
        # OC-AUDIT-016 : 503 (désactivée), 413 (trop gros) et 401/403 passent par la garde centrale.
        def check(status, headers):
            self.assertTrue(headers.get("x-request-id"), (status, headers))
            self.assertEqual(headers.get("cache-control"), "no-store", status)
            self.assertIn("content-security-policy", headers, status)
        with mock.patch.dict(os.environ, {"OPSCONTROL_AI_ENABLED": "0"}):
            status, headers, _ = call(self.app, "GET", "/api/ai/status", proxy("viewer"))
        self.assertEqual(status, 503)
        check(status, headers)
        status, headers, _ = call(self.app, "POST", "/api/ai/chat", {**MUTATE, **proxy("viewer")},
                                  json.dumps({"message": "a" * 17000}).encode())
        self.assertEqual(status, 413)
        check(status, headers)
        with mock.patch.dict(os.environ, {"OPSCONTROL_AI_LOCAL_TOKEN": "", "INFRAOPS_TRUSTED_PROXY_SECRET": ""}):
            status, headers, _ = call(self.app, "GET", "/api/ai/status")
        self.assertIn(status, (401, 403))
        check(status, headers)

    def test_csrf_and_request_limits(self):
        self.assertEqual(
            call(self.app, "POST", "/api/ai/chat", proxy("viewer"), b'{"message":"x"}')[0], 403
        )
        self.assertEqual(
            self.request("POST", "/api/ai/chat", payload={"message": "a" * 1801})[0], 422
        )
        self.assertEqual(
            self.request("POST", "/api/ai/chat", payload={"message": "a" * 17000})[0], 413
        )

    def test_generation_sources_history_and_supervision_scope(self):
        with mock.patch.object(
            LocalLLM, "chat", return_value="Hypothèse : données manquantes"
        ) as chat:
            status, raw = self.request(
                "POST", "/api/ai/chat", payload={"message": "SQLite", "host_key": "fixture"}
            )
            self.assertEqual(status, 200)
            self.assertTrue(json.loads(raw)["sources"])
            self.assertNotIn("never-send", repr(chat.call_args))
            self.assertEqual(self.request("GET", "/api/ai/history", "operator")[1], '{"items":[]}')
            self.assertTrue(json.loads(self.request("GET", "/api/ai/history")[1])["items"])
            self.assertEqual(
                self.request(
                    "POST", "/api/ai/chat", payload={"message": "x", "host_key": "missing"}
                )[0],
                404,
            )

    def test_llm_unavailable(self):
        with mock.patch.object(LocalLLM, "models", side_effect=LLMError("Indisponible")):
            self.assertFalse(json.loads(self.request("GET", "/api/ai/status")[1])["connected"])
        with mock.patch.object(LocalLLM, "chat", side_effect=LLMError("Timeout", 504)):
            self.assertEqual(
                self.request("POST", "/api/ai/chat", payload={"message": "SQLite"})[0], 504
            )

    def test_source_projection_never_collects(self):
        self.context.api_connections = mock.Mock(
            return_value=[
                {
                    "key": "source",
                    "provider": "Zabbix",
                    "url": "private-url",
                    "token_env": "private-variable",
                    "last_result": {"status": "unknown", "summary": "Mesure absente"},
                }
            ]
        )
        with mock.patch.object(LocalLLM, "chat", return_value="Informations manquantes") as chat:
            self.assertEqual(
                self.request(
                    "POST", "/api/ai/chat", payload={"message": "Zabbix", "source_key": "source"}
                )[0],
                200,
            )
            self.context.api_connections.assert_called_once_with(compact=True, admin=False)
            self.assertNotIn("private-url", repr(chat.call_args))
            self.assertNotIn("private-variable", repr(chat.call_args))
            self.assertIn("Mesure absente", repr(chat.call_args))
            self.assertEqual(
                self.request(
                    "POST", "/api/ai/chat", payload={"message": "x", "source_key": "missing"}
                )[0],
                404,
            )

    def test_classification(self):
        self.assertEqual(access_policy.classify("POST", "/api/ai/chat"), ("viewer", "ai"))
        self.assertEqual(
            access_policy.classify("POST", "/api/ai/history/clear"), ("viewer", "mutation")
        )

    def test_local_token_is_distinct_and_loopback_only(self):
        token = "local-test-" + "a" * 40
        with mock.patch.dict(
            os.environ,
            {
                "INFRAOPS_TRUSTED_PROXY_SECRET": "",
                "OPSCONTROL_AI_LOCAL_TOKEN": token,
                "INFRAOPS_LOCAL_ROLE": "viewer",
            },
        ):
            headers = {"X-OpsControl-AI-Token": token}
            self.assertEqual(call(self.app, "GET", "/api/ai/status", headers)[0], 200)
            self.assertEqual(
                call(self.app, "GET", "/api/ai/status", {**headers, "X-Forwarded-For": "remote"})[
                    0
                ],
                401,
            )

    def test_document_and_code_permission(self):
        from starlette.requests import Request
        from routers import all_routes

        endpoint_function = next(
            route.endpoint
            for route in all_routes(self.app)
            if getattr(route, "path", None) == "/api/ai/document"
        )
        request = Request(
            {
                "type": "http",
                "headers": [(k.lower().encode(), v.encode()) for k, v in proxy("viewer").items()],
                "client": ("127.0.0.1", 1),
            }
        )
        for name in ("../README.md", "data/state.sqlite3", "hosts.yaml"):
            with self.subTest(name=name), self.assertRaises(Exception) as ctx:
                endpoint_function(request, name, 1)
            self.assertEqual(ctx.exception.status_code, 404)

    def test_stream_endpoint_and_errors(self):
        from starlette.requests import Request
        from routers import all_routes

        endpoint_function = next(
            route.endpoint
            for route in all_routes(self.app)
            if getattr(route, "path", None) == "/api/ai/chat"
        )
        request = Request(
            {
                "type": "http",
                "headers": [(k.lower().encode(), v.encode()) for k, v in proxy("viewer").items()],
                "client": ("127.0.0.1", 1),
            }
        )
        request.is_disconnected = mock.AsyncMock(return_value=False)

        async def collect():
            response = await endpoint_function(
                request, ai_service.Chat(message="SQLite", stream=True)
            )
            return "".join([chunk async for chunk in response.body_iterator])

        with mock.patch.object(LocalLLM, "chat", return_value="Diagnostic filtré"):
            self.assertIn("event: result", asyncio.run(collect()))
        with mock.patch.object(LocalLLM, "chat", side_effect=LLMError("Timeout", 504)):
            self.assertIn("event: error", asyncio.run(collect()))


class Developer(unittest.TestCase):
    def test_manifest_approval_and_stale_preimage(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            source = root / "app.py"
            source.write_text("old\n")
            patch = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+new\n"
            with mock.patch("ai_developer.run"):
                record = ai_developer.review(root, patch, root / "record.json")
            ai_developer.validate(root, record, record["approval"])
            with self.assertRaises(ValueError):
                ai_developer.validate(root, record, "")
            source.write_text("changed\n")
            with self.assertRaises(ValueError):
                ai_developer.validate(root, record, record["approval"])

    def test_forbidden_paths(self):
        root = Path(tempfile.gettempdir()).resolve()
        for name in (
            "../a.py",
            "data/a.py",
            ".git/a.py",
            "deploy/a.py",
            "C:/a.py",
            "a\\b.py",
            "AGENTS.md",
            "hosts.yaml",
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                ai_developer.allowed(root, name)

    def test_snapshot_includes_fixtures_and_excludes_operational_files(self):
        for name in (
            "data/state.sqlite3",
            "hosts.yaml",
            "private.yaml",
            "config.json",
            "credential.pem",
            ".env",
            "../app.py",
            "audit.log",
        ):
            self.assertFalse(ai_developer.snapshot_allowed(name), name)
        for name in (
            "deploy/ci.py",
            "deploy/opscontrol.service",
            "deploy/remote/probe.sh",
            "web/index.html",
            "test_fixtures/tls/leaf.pem",
            "hosts.example.yaml",
            ".github/workflows/ci.yml",
            ".secrets.baseline",
        ):
            self.assertTrue(ai_developer.snapshot_allowed(name), name)

    def test_docker_isolation_contract(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch("ai_developer.run") as runner:
            runner.return_value = SimpleNamespace(stdout=b"")
            ai_developer.isolated_tests(Path(folder), "tests:local")
            args = runner.call_args.args[0]
            for flag in (
                "--network=none",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--pull=never",
                "--user=65534:65534",
            ):
                self.assertIn(flag, args)
            self.assertNotIn("--privileged", args)


if __name__ == "__main__":
    unittest.main()
