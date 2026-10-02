"""LLM providers behind one small interface: ``complete_json(system, user) -> dict``.

Supported: Ollama, any OpenAI-compatible endpoint (vLLM, LM Studio…), Anthropic, Azure OpenAI.
Before anything is sent, the payload is checked for IP addresses: the model must only ever
see SGT names, ports and volumes.
"""

from __future__ import annotations

import ipaddress
import json
import re
import time

import httpx

from ..config import LLMConfig
from ..i18n import Message

_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?:/\d{1,2})?(?![\d.])")
_IPV6_CANDIDATE = re.compile(r"[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:[0-9A-Fa-f:]*")


class LLMError(Exception):
    pass


class PrivacyViolation(LLMError):
    pass


def assert_no_ip(text: str) -> None:
    for m in _IPV4.finditer(text):
        try:
            ipaddress.ip_address(m.group(1))
        except ValueError:
            continue
        raise PrivacyViolation(Message("llm_ipv4_refused"))
    for m in _IPV6_CANDIDATE.finditer(text):
        try:
            ipaddress.ip_address(m.group(0))
        except ValueError:
            continue
        raise PrivacyViolation(Message("llm_ipv6_refused"))


def _extract_json(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.DOTALL)
    try:
        return json.loads(text)
    except ValueError:
        m = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if m:
            return json.loads(m.group(0))
        raise LLMError(Message("llm_not_json", text=text[:200]))


class LLMClient:
    def __init__(self, cfg: LLMConfig):
        self.cfg = cfg
        self.http = httpx.AsyncClient(timeout=httpx.Timeout(cfg.timeout_s, connect=5.0))
        self.last_ok: float | None = None
        self.last_error: str | None = None

    async def close(self) -> None:
        await self.http.aclose()

    def _url(self, path: str) -> str:
        base = self.cfg.endpoint.rstrip("/")
        if self.cfg.provider == "openai" and base.endswith("/v1") and path.startswith("/v1"):
            path = path[3:]
        return base + path

    async def complete_json(self, system: str, user: str) -> dict:
        assert_no_ip(system + user)
        c = self.cfg
        try:
            if c.provider == "ollama":
                r = await self.http.post(self._url("/api/chat"), json={
                    "model": c.model, "stream": False, "format": "json",
                    "options": {"temperature": c.temperature},
                    "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                })
                r.raise_for_status()
                text = r.json()["message"]["content"]
            elif c.provider in ("openai", "azure"):
                if c.provider == "azure":
                    url = self._url(f"/openai/deployments/{c.model}/chat/completions?api-version={c.api_version}")
                    headers = {"api-key": c.api_key}
                else:
                    url = self._url("/v1/chat/completions")
                    headers = {"Authorization": f"Bearer {c.api_key}"} if c.api_key else {}
                r = await self.http.post(url, headers=headers, json={
                    "model": c.model, "temperature": c.temperature,
                    "response_format": {"type": "json_object"},
                    "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                })
                r.raise_for_status()
                text = r.json()["choices"][0]["message"]["content"]
            elif c.provider == "anthropic":
                base = c.endpoint.rstrip("/") or "https://api.anthropic.com"
                r = await self.http.post(base + "/v1/messages", headers={
                    "x-api-key": c.api_key, "anthropic-version": "2023-06-01",
                }, json={
                    "model": c.model, "max_tokens": 800, "temperature": c.temperature, "system": system,
                    "messages": [{"role": "user", "content": user}],
                })
                r.raise_for_status()
                text = "".join(b.get("text", "") for b in r.json().get("content", []))
            else:
                raise LLMError(f"fournisseur inconnu : {c.provider}")
        except httpx.HTTPStatusError as e:
            self.last_error = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
            raise LLMError(self.last_error) from e
        except httpx.HTTPError as e:
            self.last_error = f"{e.__class__.__name__}: {e}"
            raise LLMError(self.last_error) from e
        result = _extract_json(text)
        self.last_ok, self.last_error = time.time(), None
        return result

    async def ping(self) -> dict:
        """Cheap reachability check: lists models where the API allows it."""
        c = self.cfg
        t0 = time.perf_counter()
        try:
            if c.provider == "ollama":
                r = await self.http.get(self._url("/api/tags"))
                r.raise_for_status()
                names = [m.get("name", "") for m in r.json().get("models", [])]
                if not any(n == c.model or n.split(":")[0] == c.model for n in names):
                    raise LLMError(Message("llm_model_missing", model=c.model))
            elif c.provider == "openai":
                headers = {"Authorization": f"Bearer {c.api_key}"} if c.api_key else {}
                r = await self.http.get(self._url("/v1/models"), headers=headers)
                r.raise_for_status()
            elif c.provider == "anthropic":
                base = c.endpoint.rstrip("/") or "https://api.anthropic.com"
                r = await self.http.get(base + "/v1/models", headers={
                    "x-api-key": c.api_key, "anthropic-version": "2023-06-01"})
                r.raise_for_status()
            else:  # azure: no cheap listing for a deployment, do a tiny completion
                await self.complete_json("Reply with {\"ok\": true} only.", "ping")
        except httpx.HTTPStatusError as e:
            self.last_error = f"HTTP {e.response.status_code}"
            raise LLMError(self.last_error) from e
        except httpx.HTTPError as e:
            self.last_error = f"{e.__class__.__name__}: {e}"
            raise LLMError(self.last_error) from e
        self.last_ok, self.last_error = time.time(), None
        return {"latency_ms": round((time.perf_counter() - t0) * 1000)}
