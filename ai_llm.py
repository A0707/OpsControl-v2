"""Client LM Studio sans SDK cloud, proxy implicite ou redirection HTTP."""

from __future__ import annotations

import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request

from ai_security import clean, endpoint

MAX_RESPONSE = 256_000


class LLMError(Exception):
    def __init__(self, detail, status=503):
        super().__init__(detail)
        self.status = status


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise LLMError("Redirection du serveur LLM refusée.", 502)


class LocalLLM:
    def __init__(self):
        self.url = endpoint(os.getenv("OPSCONTROL_AI_URL", "http://127.0.0.1:1234/v1"))
        self.model = os.getenv("OPSCONTROL_AI_MODEL", "opscontrol-local")
        self.timeout = max(1, min(180, float(os.getenv("OPSCONTROL_AI_TIMEOUT", "180"))))
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.gate = threading.BoundedSemaphore(1)

    def request(self, path, body=None, cancel=None):
        headers = {"Content-Type": "application/json"}
        key = os.getenv("OPSCONTROL_AI_API_KEY")
        if key:
            headers["Authorization"] = "Bearer " + key
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, headers=headers)
        deadline = time.monotonic() + self.timeout
        try:
            with self.opener.open(req, timeout=self.timeout) as response:
                if body and body.get("stream"):
                    content, size = [], 0
                    while True:
                        raw = response.readline(MAX_RESPONSE + 1)
                        if not raw:
                            break
                        size += len(raw)
                        if size > MAX_RESPONSE:
                            raise LLMError("Réponse LLM trop volumineuse.", 502)
                        if time.monotonic() > deadline:
                            raise LLMError("Délai de génération dépassé.", 504)
                        if cancel and cancel.is_set():
                            raise LLMError("Génération interrompue.", 499)
                        if not raw.startswith(b"data:"):
                            continue
                        payload = raw[5:].strip()
                        if payload == b"[DONE]":
                            return {"text": "".join(content)}
                        chunk = json.loads(payload)
                        if "error" in chunk:
                            raise LLMError("Erreur du flux LLM.", 502)
                        choices = chunk.get("choices", [])
                        if choices:
                            delta = choices[0].get("delta", {})
                            if delta.get("tool_calls"):
                                raise LLMError("Appel d’outil refusé.", 502)
                            part = delta.get("content", "")
                            if not isinstance(part, str):
                                raise ValueError("delta")
                            content.append(part)
                    raise LLMError("Flux LLM incomplet.", 502)
                raw = response.read(MAX_RESPONSE + 1)
                if len(raw) > MAX_RESPONSE:
                    raise LLMError("Réponse LLM trop volumineuse.", 502)
                return json.loads(raw)
        except urllib.error.HTTPError as error:
            status = 404 if error.code == 404 else 503
            raise LLMError(
                "Modèle absent ou endpoint indisponible."
                if status == 404
                else "Requête refusée par LM Studio.",
                status,
            ) from None
        except (TimeoutError, socket.timeout):
            raise LLMError("LM Studio ne répond pas dans le délai prévu.", 504) from None
        except urllib.error.URLError as error:
            status = 504 if isinstance(error.reason, TimeoutError) else 503
            raise LLMError("LM Studio indisponible : vérifier le serveur local.", status) from None
        except (ValueError, KeyError, TypeError, IndexError, AttributeError):
            raise LLMError("Réponse LM Studio invalide.", 502) from None

    def models(self):
        data = self.request("/models")
        if not isinstance(data, dict) or not isinstance(data.get("data"), list):
            raise LLMError("Liste de modèles invalide.", 502)
        return [
            m["id"] for m in data["data"] if isinstance(m, dict) and isinstance(m.get("id"), str)
        ]

    def chat(self, messages, stream=False, cancel=None):
        if not self.gate.acquire(blocking=False):
            raise LLMError("Une génération est déjà en cours. Réessayez ensuite.", 429)
        try:
            if self.model not in self.models():
                raise LLMError("Modèle configuré absent : le charger dans LM Studio.", 404)
            # Budget conservateur en octets, indépendant d'une estimation optimiste des tokens.
            if sum(len(m["content"].encode("utf-8")) for m in messages) > 7000:
                raise LLMError("Contexte trop volumineux.", 413)
            result = self.request(
                "/chat/completions",
                {
                    "model": self.model,
                    "messages": messages,
                    "max_tokens": 512,
                    "temperature": 0.15,
                    "stream": stream,
                },
                cancel,
            )
            try:
                message = result["choices"][0]["message"] if not stream else None
                if message and message.get("tool_calls"):
                    raise LLMError("Appel d’outil refusé.", 502)
                answer = result["text"] if stream else message["content"]
                if not isinstance(answer, str) or not answer.strip():
                    raise ValueError("empty")
                return clean(answer)
            except (KeyError, IndexError, TypeError, ValueError):
                raise LLMError("Réponse du modèle vide ou invalide.", 502) from None
        finally:
            self.gate.release()
