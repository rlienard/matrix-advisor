"""pxGrid STOMP-over-websocket subscription against the ISE simulator's pubsub endpoint."""

import asyncio

import httpx
import yaml

from matrix_advisor.config import PxGridConfig
from matrix_advisor.ise.pxgrid import PxGridClient
from matrix_advisor.main import build_context

SESSION_TOPIC = "/topic/com.cisco.ise.session"
SGACL_TOPIC = "/topic/com.cisco.ise.config.trustsec.security.group.acl"


async def _until(predicate, timeout=5.0):
    for _ in range(int(timeout / 0.05)):
        if await predicate():
            return
        await asyncio.sleep(0.05)
    raise AssertionError("condition not met in time")


async def _subscribed(http: httpx.AsyncClient, sim_url: str) -> bool:
    # A no-op session event reports how many clients follow the session topic.
    r = await http.post(sim_url + "/sim/session", json={"ip": "192.0.2.1", "sgt": "Guests", "state": "DISCONNECTED"})
    return r.json()["subscribers"] > 0


def test_subscribe_receives_session_and_trustsec_messages(sim_url):
    httpx.post(sim_url + "/sim/reset")

    async def scenario():
        px = PxGridClient(PxGridConfig(base_url=sim_url, auth="password", password="x"), verify_tls=False)
        received: list[tuple[str, dict]] = []

        async def on_message(topic: str, body: dict) -> None:
            received.append((topic, body))

        task = asyncio.create_task(px.subscribe(on_message))
        async with httpx.AsyncClient() as http:
            try:
                await _until(lambda: _subscribed(http, sim_url))
                received.clear()
                await http.post(sim_url + "/sim/session", json={"ip": "10.10.9.9", "sgt": "Guests"})
                await http.post(sim_url + "/sim/conflict", json={"src": "Contractors", "dst": "Finance_DB"})

                async def got_both():
                    return {t for t, _ in received} >= {SESSION_TOPIC, SGACL_TOPIC}

                await _until(got_both)
            finally:
                task.cancel()
                await px.close()
        session = next(b for t, b in received if t == SESSION_TOPIC)
        assert session["sessions"][0]["ipAddresses"] == ["10.10.9.9"]
        assert session["sessions"][0]["ctsSecurityGroup"] == "Guests"
        sgacl = next(b for t, b in received if t == SGACL_TOPIC)
        assert sgacl["sgacl"]["name"] == "DBA_Maintenance"

    asyncio.run(scenario())


def test_subscribe_rejects_bad_secret(sim_url, monkeypatch):
    async def scenario():
        px = PxGridClient(PxGridConfig(base_url=sim_url, auth="password", password="x"), verify_tls=False)

        async def wrong_secret(peer: str) -> str:
            return "wrong"

        monkeypatch.setattr(px, "secret", wrong_secret)

        async def ignore(topic: str, body: dict) -> None:
            pass

        try:
            await asyncio.wait_for(px.subscribe(ignore), timeout=5)
        except Exception as e:  # noqa: BLE001 - any refusal is fine, hanging is not
            return type(e).__name__
        finally:
            await px.close()
        return None

    assert asyncio.run(scenario()) not in (None, "TimeoutError")


def test_service_uses_websocket_for_sessions_and_reconcile(sim_url, tmp_path):
    """ISEService picks websocket mode, applies session events to the resolver and reconciles on
    TrustSec notifications instead of waiting for the next poll."""
    cfg = {
        "ise": {
            "pan": "sim", "openapi": {"base_url": sim_url, "username": "matrix-advisor", "password": "demo-password"},
            "verify_tls": False, "pxgrid": {"base_url": sim_url, "auth": "password", "password": "x"},
        },
        "collector": {"input_file": str(tmp_path / "none.ndjson"), "parquet_dir": str(tmp_path / "pq")},
        "server": {"admin_password": "secret"},
    }
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(cfg))
    httpx.post(sim_url + "/sim/reset")

    async def scenario():
        ctx = build_context(str(tmp_path / "config.yaml"), ":memory:")
        ise = ctx.ise
        loop = asyncio.create_task(ise._pxgrid_loop())
        async with httpx.AsyncClient() as http:
            try:
                async def websocket_mode():
                    return ise.status["pxgrid"]["mode"] == "websocket" and await _subscribed(http, sim_url)

                await _until(websocket_mode)
                assert ctx.resolver.resolve("10.10.1.20") == "Employees"  # initial getSessions

                await http.post(sim_url + "/sim/session", json={"ip": "10.10.9.9", "sgt": "Guests"})

                async def resolved():
                    return ctx.resolver.resolve("10.10.9.9") == "Guests"

                await _until(resolved)

                ise._reconcile_now.clear()
                await http.post(sim_url + "/sim/conflict", json={"src": "Contractors", "dst": "Finance_DB"})

                async def reconcile_requested():
                    return ise._reconcile_now.is_set()

                await _until(reconcile_requested)
                assert ise.status["pxgrid"]["mode"] == "websocket"
            finally:
                loop.cancel()
                await ise.client.close()
                await ise.pxgrid.close()

    asyncio.run(scenario())
