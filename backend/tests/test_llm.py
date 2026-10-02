import asyncio
import json

import httpx

from matrix_advisor.agent.llm import LLMClient
from matrix_advisor.config import LLMConfig


def _client(provider: str, handler) -> LLMClient:
    c = LLMClient(LLMConfig(provider=provider, endpoint="http://llm.local", model="m", api_key="k"))
    c.http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return c


def test_ollama_json_answer():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"message": {"content": '{"risk": "high", "justification": "x"}'}})

    out = asyncio.run(_client("ollama", handler).complete_json("sys", "user"))
    assert out["risk"] == "high"
    assert seen["url"].endswith("/api/chat") and seen["body"]["format"] == "json"


def test_openai_compatible_and_fenced_json():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/chat/completions"
        assert request.headers["authorization"] == "Bearer k"
        return httpx.Response(200, json={"choices": [{"message": {"content": '```json\n{"risk": "low"}\n```'}}]})

    assert asyncio.run(_client("openai", handler).complete_json("s", "u")) == {"risk": "low"}


def test_anthropic_messages():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/messages" and request.headers["x-api-key"] == "k"
        return httpx.Response(200, json={"content": [{"type": "text", "text": '{"risk": "medium"}'}]})

    assert asyncio.run(_client("anthropic", handler).complete_json("s", "u"))["risk"] == "medium"
