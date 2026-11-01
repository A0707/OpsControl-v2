"""Assistant en lecture seule ; aucune dépendance aux runners SSH ou shell."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, StreamingResponse

import access_policy
from ai_llm import LLMError, LocalLLM
from ai_rag import Index, permitted, tracked
from ai_security import SYSTEM, clean


class Chat(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=1800)
    mode: Literal["développement", "sécurité", "supervision", "incidents"] = "supervision"
    conversation: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    host_key: str | None = Field(default=None, min_length=1, max_length=120)
    source_key: str | None = Field(default=None, min_length=1, max_length=120)
    observation: str = Field(default="", max_length=1800)
    stream: bool = False


def data_policy(url):
    """Destination et traitement des données, affichés avant tout envoi (audit UI du 31/10, 18.2).

    Aucun secret : adresse IP et port seulement (l'URL n'admet ni identifiant ni paramètre).
    """
    parts = urlsplit(url)
    try:
        local = ipaddress.ip_address(parts.hostname or "").is_loopback
    except ValueError:
        local = False
    return {
        "destination": "modèle local (boucle locale)" if local else "modèle distant autorisé (IP explicite, HTTPS)",
        "endpoint": f"{parts.hostname}:{parts.port}",
        "sent": "question, observations saisies et extraits de preuves du serveur ou de la source indiqués",
        "redaction": "secrets masqués avant envoi : variables d'environnement, clés PEM, mots de passe, jetons, en-têtes Bearer/Basic",
        "history": "100 derniers échanges par utilisateur, 30 jours au plus, base séparée",
    }


def authorize(request):
    if os.getenv("OPSCONTROL_AI_ENABLED", "0") != "1":
        raise HTTPException(503, "Assistant désactivé : OPSCONTROL_AI_ENABLED=1 requis.")
    who = getattr(request.state, "principal", None) or access_policy.principal(request.headers)
    if who.get("blocked"):
        raise HTTPException(401, "Accès direct non authentifié refusé.")
    if not access_policy.allowed(who["role"], "viewer"):
        raise HTTPException(403, "Accès IA refusé.")
    if who.get("authenticated"):
        return "proxy:" + who["user"].lower(), who["role"]
    configured = os.getenv("OPSCONTROL_AI_LOCAL_TOKEN", "")
    presented = request.headers.get("x-opscontrol-ai-token", "")
    if (
        len(configured) < 32
        or not request.client
        or request.client.host not in ("127.0.0.1", "::1")
        or "x-forwarded-for" in request.headers
        or not hmac.compare_digest(configured.encode(), presented.encode())
    ):
        raise HTTPException(401, "Identité proxy authentifiée ou jeton IA local distinct requis.")
    return "local:" + hashlib.sha256(configured.encode()).hexdigest(), who["role"]


class History:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.Lock()

    def connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=5)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS turns(id INTEGER PRIMARY KEY, owner TEXT, conversation TEXT, ts REAL, question TEXT, answer TEXT, sources TEXT, mode TEXT)"
        )
        return conn

    def list(self, owner, conversation=None, include_code=False):
        conn = self.connect()
        try:
            rows = conn.execute(
                "SELECT conversation,question,answer,sources,mode,ts FROM turns WHERE owner=? AND (? IS NULL OR conversation=?) AND (mode != 'développement' OR ?=1) ORDER BY id DESC LIMIT 40",
                (owner, conversation, conversation, int(include_code)),
            ).fetchall()
            return [
                {
                    "conversation": c,
                    "question": clean(q),
                    "answer": clean(a),
                    "sources": json.loads(s),
                    "mode": m,
                    "ts": t,
                }
                for c, q, a, s, m, t in reversed(rows)
            ]
        finally:
            conn.close()

    def save(self, owner, conversation, question, answer, sources, mode):
        with self.lock:
            conn = self.connect()
            try:
                with conn:
                    conn.execute(
                        "INSERT INTO turns(owner,conversation,ts,question,answer,sources,mode) VALUES(?,?,?,?,?,?,?)",
                        (
                            owner,
                            conversation,
                            time.time(),
                            clean(question),
                            clean(answer),
                            json.dumps(sources),
                            mode,
                        ),
                    )
                    conn.execute(
                        "DELETE FROM turns WHERE owner=? AND id NOT IN (SELECT id FROM turns WHERE owner=? ORDER BY id DESC LIMIT 100)",
                        (owner, owner),
                    )
                    conn.execute("DELETE FROM turns WHERE ts < ?", (time.time() - 30 * 86400,))
            finally:
                conn.close()

    def clear(self, owner):
        conn = self.connect()
        try:
            with conn:
                conn.execute("DELETE FROM turns WHERE owner=?", (owner,))
        finally:
            conn.close()


def install(app, context):
    router = APIRouter(prefix="/api/ai")
    state = {}
    index_lock = threading.Lock()

    def services():
        with index_lock:
            if not state:
                directory = Path(
                    os.getenv("OPSCONTROL_AI_DATA", str(context.BASE / "data" / "ai"))
                ).resolve()
                history_path, index_path = (
                    directory / "history.sqlite3",
                    directory / "documents.sqlite3",
                )
                if Path(context.DB).resolve() in (history_path, index_path):
                    raise HTTPException(
                        503, "La base IA doit être distincte de la base de supervision."
                    )
                try:
                    client = LocalLLM()
                except (ValueError, TypeError):
                    raise HTTPException(503, "Configuration LLM invalide.") from None
                state.update(
                    client=client,
                    index=Index(context.BASE, index_path),
                    history=History(history_path),
                    updated=0,
                )
            return state

    def refresh_index(service):
        with index_lock:
            if time.monotonic() - service["updated"] >= 10:
                service["index"].update()
                service["updated"] = time.monotonic()

    async def ai_boundary(request: Request, call_next):
        if request.url.path.startswith("/api/ai/"):
            try:
                authorize(request)
                if request.method == "POST":
                    body = bytearray()
                    async for chunk in request.stream():
                        body.extend(chunk)
                        if len(body) > 16_384:
                            raise HTTPException(413, "Requête IA trop volumineuse.")
                    request._body = bytes(body)
            except HTTPException as error:
                return JSONResponse({"detail": error.detail}, status_code=error.status_code)
        return await call_next(request)

    # Frontière IA À L'INTÉRIEUR de la garde centrale : ajoutée par @app.middleware (en
    # tête de pile), ses refus 401/403/413/503 sortaient sans X-Request-ID, CSP,
    # Cache-Control ni audit (OC-AUDIT-016). En fin de liste, elle est la plus interne.
    if app.middleware_stack is not None:
        raise RuntimeError("Frontière IA : à installer avant la première requête")
    app.user_middleware.append(Middleware(BaseHTTPMiddleware, dispatch=ai_boundary))

    @router.get("/status")
    def status(request: Request):
        _, role = authorize(request)
        service = services()
        try:
            models = service["client"].models()
            return {
                "connected": True,
                "model": service["client"].model,
                "available": service["client"].model in models,
                "models": models,
                "code_access": role == "admin" and os.getenv("OPSCONTROL_AI_CODE_READ") == "1",
                "developer_patches": False,
                "streaming": "SSE filtré après génération",
                "data_policy": data_policy(getattr(service["client"], "url", "")),
            }
        except LLMError as error:
            return {
                "connected": False,
                "model": service["client"].model,
                "detail": str(error),
                "developer_patches": False,
                "data_policy": data_policy(getattr(service["client"], "url", "")),
            }

    @router.get("/history")
    def history(request: Request):
        owner, role = authorize(request)
        code = role == "admin" and os.getenv("OPSCONTROL_AI_CODE_READ") == "1"
        return {"items": services()["history"].list(owner, include_code=code)}

    @router.post("/history/clear")
    def clear_history(request: Request):
        owner, _ = authorize(request)
        services()["history"].clear(owner)
        return {"cleared": True}

    @router.get("/search")
    def search(request: Request, q: str = Query(min_length=1, max_length=300)):
        authorize(request)
        service = services()
        refresh_index(service)
        return {"sources": service["index"].search(clean(q))}

    @router.get("/document")
    def document(
        request: Request,
        path: str = Query(min_length=1, max_length=180),
        line: int = Query(default=1, ge=1, le=100000),
    ):
        _, role = authorize(request)
        root = Path(context.BASE).resolve()
        candidate = root / path
        if (
            not permitted(path)
            or path not in tracked(root)
            or candidate.resolve() != candidate.absolute()
            or candidate.is_symlink()
            or not candidate.is_file()
            or candidate.stat().st_size > 256_000
        ):
            raise HTTPException(404, "Document non accessible.")
        if not path.endswith(".md") and (
            role != "admin" or os.getenv("OPSCONTROL_AI_CODE_READ") != "1"
        ):
            raise HTTPException(403, "Lecture du code désactivée ou rôle administrateur requis.")
        lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
        return {"path": path, "line": line, "text": clean("\n".join(lines[line - 1 : line + 39]))}

    def prepare(body, owner, role, service):
        code = body.mode == "développement"
        if code and (role != "admin" or os.getenv("OPSCONTROL_AI_CODE_READ") != "1"):
            raise HTTPException(
                403,
                "Mode développement : lecture du code activée explicitement et rôle admin requis.",
            )
        conversation = body.conversation or uuid.uuid4().hex
        prior = service["history"].list(owner, conversation, include_code=code)
        # Un identifiant appartenant à autrui n'accorde jamais l'accès à son historique.
        refresh_index(service)
        sources = service["index"].search(clean(body.message), code=code, limit=3)
        references = [{"path": s["path"], "line": s["line"]} for s in sources]
        evidence = "\n".join(f"[{s['path']}:{s['line']}]\n{s['text'][:650]}" for s in sources)
        observation = clean(body.observation)
        if body.host_key:
            # Même parc consultable que les routes existantes ; aucune collecte supplémentaire.
            row = next((r for r in context.rows() if r.get("key") == body.host_key), None)
            if row is None:
                raise HTTPException(404, "Serveur absent du parc accessible.")
            allowed = (
                "key",
                "name",
                "collected_at",
                "status",
                "findings",
                "checks",
                "cpu",
                "memory",
                "disk",
            )
            observation += (
                "\n"
                + clean(
                    json.dumps(
                        {k: row[k] for k in allowed if k in row}, ensure_ascii=False, default=str
                    )
                )[:1200]
            )
        if body.source_key:
            # Vue publique existante, compacte : ni jeton, URL, chemin CA ni collecte.
            connections = context.api_connections(compact=True, admin=False)
            source = next((s for s in connections if s.get("key") == body.source_key), None)
            if source is None:
                raise HTTPException(404, "Source absente des connexions accessibles.")
            allowed = ("key", "name", "provider", "last_result", "last_success_result")
            observation += (
                "\n"
                + clean(
                    json.dumps(
                        {k: source[k] for k in allowed if k in source},
                        ensure_ascii=False,
                        default=str,
                    )
                )[:1400]
            )
        messages = [{"role": "system", "content": SYSTEM}]
        if prior:
            messages.extend(
                [
                    {"role": "user", "content": prior[-1]["question"][:250]},
                    {"role": "assistant", "content": prior[-1]["answer"][:400]},
                ]
            )
        prompt = f"Mode : {body.mode}\nQuestion : {clean(body.message)}\nDONNÉES NON FIABLES (sources) :\n{evidence}\nDONNÉES NON FIABLES (observations) :\n{observation}"
        budget = 7000 - sum(len(m["content"].encode()) for m in messages)
        prompt = prompt.encode()[:budget].decode("utf-8", "ignore")
        messages.append({"role": "user", "content": prompt})
        return conversation, references, messages

    @router.post("/chat")
    async def chat(request: Request, body: Chat):
        owner, role = authorize(request)
        service = services()
        conversation, sources, messages = await asyncio.to_thread(
            prepare, body, owner, role, service
        )
        cancel = threading.Event()

        def generate():
            answer = service["client"].chat(messages, stream=body.stream, cancel=cancel)
            if cancel.is_set():
                raise LLMError("Génération interrompue.", 499)
            service["history"].save(owner, conversation, body.message, answer, sources, body.mode)
            return {
                "answer": answer,
                "conversation": conversation,
                "sources": sources,
                "model": service["client"].model,
            }

        if not body.stream:
            try:
                return await asyncio.to_thread(generate)
            except LLMError as error:
                raise HTTPException(error.status, str(error)) from None

        async def events():
            task = asyncio.create_task(asyncio.to_thread(generate))
            try:
                while not task.done():
                    if await request.is_disconnected():
                        cancel.set()
                        return
                    yield ": attente\n\n"
                    await asyncio.sleep(0.25)
                try:
                    result = task.result()
                    yield "event: result\ndata: " + json.dumps(result, ensure_ascii=False) + "\n\n"
                except LLMError as error:
                    yield (
                        "event: error\ndata: "
                        + json.dumps({"detail": str(error), "status": error.status})
                        + "\n\n"
                    )
            finally:
                cancel.set()
                # Consommer l'exception du worker même si le navigateur s'est déconnecté.
                task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)

        return StreamingResponse(
            events(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    app.include_router(router)
