"""pxGrid 2.0 client: account activation, service lookup, sessions, SXP bindings and
websocket (STOMP) subscriptions.

Flow:
  1. POST /pxgrid/control/AccountActivate          -> ENABLED once approved in ISE
  2. POST /pxgrid/control/ServiceLookup {name}      -> nodeName + properties (restBaseUrl, topics…)
  3. POST /pxgrid/control/AccessSecret {peerNodeName} -> secret for that provider
  4. POST {restBaseUrl}/getSessions | getBindings    (basic auth: client_name / secret)
  5. websocket wsPubsubService + STOMP SUBSCRIBE to sessionTopic / TrustSec topics
"""

from __future__ import annotations

import base64
import json
import logging
import ssl
from collections.abc import Awaitable, Callable

import httpx

from ..config import PxGridConfig
from ..i18n import Message

log = logging.getLogger(__name__)

SESSION_SERVICE = "com.cisco.ise.session"
SXP_SERVICE = "com.cisco.ise.sxp"
TRUSTSEC_CONFIG_SERVICE = "com.cisco.ise.config.trustsec"
PUBSUB_SERVICE = "com.cisco.ise.pubsub"


class PxGridError(Exception):
    pass


def _ssl(cfg: PxGridConfig) -> ssl.SSLContext | bool:
    if not cfg.verify_tls and cfg.auth != "certificate":
        return False
    ctx = ssl.create_default_context(cafile=cfg.ca_cert or None)
    if not cfg.verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if cfg.auth == "certificate" and cfg.client_cert:
        ctx.load_cert_chain(cfg.client_cert, cfg.client_key or None)
    return ctx


class PxGridClient:
    def __init__(self, cfg: PxGridConfig):
        self.cfg = cfg
        self.base = cfg.base_url.rstrip("/") if cfg.base_url else f"https://{cfg.node}:{cfg.port}"
        self._verify = _ssl(cfg)
        self.password = cfg.password if cfg.auth == "password" else ""
        self.http = httpx.AsyncClient(verify=self._verify, timeout=httpx.Timeout(20.0, connect=5.0),
                                      headers={"Accept": "application/json", "Content-Type": "application/json"})
        self.account_state = "UNKNOWN"
        self._secrets: dict[str, str] = {}

    async def close(self) -> None:
        await self.http.aclose()

    @property
    def _auth(self) -> tuple[str, str]:
        return (self.cfg.client_name, self.password)

    async def _control(self, op: str, body: dict, auth: bool = True) -> dict:
        try:
            r = await self.http.post(f"{self.base}/pxgrid/control/{op}", json=body, auth=self._auth if auth else None)
        except httpx.HTTPError as e:
            raise PxGridError(f"{op}: {e.__class__.__name__}: {e}") from e
        if r.status_code == 401:
            raise PxGridError(Message("pxgrid_unauthorized", op=op, client=self.cfg.client_name))
        if r.status_code >= 400:
            raise PxGridError(f"{op}: HTTP {r.status_code} {r.text[:200]}")
        return r.json() if r.content else {}

    async def ensure_account(self) -> str:
        """Create (password auth) and activate the client account. Returns ENABLED/PENDING/DISABLED."""
        if self.cfg.auth == "password" and not self.password:
            data = await self._control("AccountCreate", {"nodeName": self.cfg.client_name}, auth=False)
            self.password = data.get("password", "")
            log.warning("pxGrid account %s created; store its password in the configuration", self.cfg.client_name)
        data = await self._control("AccountActivate", {"description": "Matrix Advisor"})
        self.account_state = data.get("accountState", "UNKNOWN")
        return self.account_state

    async def lookup(self, service: str) -> dict | None:
        data = await self._control("ServiceLookup", {"name": service})
        services = data.get("services") or []
        return services[0] if services else None

    async def secret(self, peer: str) -> str:
        if peer not in self._secrets:
            data = await self._control("AccessSecret", {"peerNodeName": peer})
            self._secrets[peer] = data.get("secret", "")
        return self._secrets[peer]

    async def _service_call(self, service: str, op: str, body: dict | None = None) -> dict:
        svc = await self.lookup(service)
        if not svc:
            raise PxGridError(Message("pxgrid_service_missing", service=service))
        url = svc["properties"]["restBaseUrl"].rstrip("/") + "/" + op
        secret = await self.secret(svc["nodeName"])
        try:
            r = await self.http.post(url, json=body or {}, auth=(self.cfg.client_name, secret))
        except httpx.HTTPError as e:
            raise PxGridError(f"{op}: {e}") from e
        if r.status_code >= 400:
            raise PxGridError(f"{op}: HTTP {r.status_code} {r.text[:200]}")
        return r.json() if r.content else {}

    async def sessions(self) -> dict[str, str]:
        """IP -> SGT name for active sessions that carry a security group."""
        data = await self._service_call(SESSION_SERVICE, "getSessions")
        return sessions_to_mapping(data.get("sessions") or [])

    async def bindings(self) -> list[dict]:
        """IP-SGT bindings (SXP / static mappings): [{ipPrefix, tag}]."""
        try:
            data = await self._service_call(SXP_SERVICE, "getBindings")
        except PxGridError as e:
            log.info("SXP bindings unavailable: %s", e)
            return []
        return data.get("bindings") or []

    # ------------------------------------------------------------ websocket
    async def subscribe(self, on_message: Callable[[str, dict], Awaitable[None]]) -> None:
        """Subscribe to session and TrustSec configuration topics until cancelled or failure."""
        import websockets  # imported lazily: optional at runtime

        pubsub = await self.lookup(PUBSUB_SERVICE)
        session_svc = await self.lookup(SESSION_SERVICE)
        trustsec_svc = await self.lookup(TRUSTSEC_CONFIG_SERVICE)
        if not pubsub:
            raise PxGridError(Message("pxgrid_pubsub_missing"))
        topics: list[str] = []
        if session_svc and session_svc["properties"].get("sessionTopic"):
            topics.append(session_svc["properties"]["sessionTopic"])
        if trustsec_svc:
            topics += [v for k, v in trustsec_svc["properties"].items() if k.endswith("Topic")]
        ws_url = pubsub["properties"]["wsUrl"]
        secret = await self.secret(pubsub["nodeName"])
        token = base64.b64encode(f"{self.cfg.client_name}:{secret}".encode()).decode()
        ssl_ctx = self._verify if isinstance(self._verify, ssl.SSLContext) else None
        if ws_url.startswith("wss") and ssl_ctx is None:
            ssl_ctx = ssl.create_default_context()
            if not self.cfg.verify_tls:
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
        async with websockets.connect(
            ws_url, additional_headers={"Authorization": f"Basic {token}"}, ssl=ssl_ctx if ws_url.startswith("wss") else None
        ) as ws:
            await ws.send(stomp_frame("CONNECT", {"accept-version": "1.2", "host": pubsub["nodeName"]}))
            for i, topic in enumerate(topics):
                await ws.send(stomp_frame("SUBSCRIBE", {"destination": topic, "id": f"sub-{i}"}))
            log.info("pxGrid subscribed to %s", ", ".join(topics))
            async for raw in ws:
                frame = parse_stomp(raw if isinstance(raw, bytes) else raw.encode())
                if frame and frame["command"] == "MESSAGE":
                    try:
                        body = json.loads(frame["body"] or "{}")
                    except ValueError:
                        continue
                    await on_message(frame["headers"].get("destination", ""), body)


def sessions_to_mapping(sessions: list[dict]) -> dict[str, str]:
    out: dict[str, str] = {}
    for s in sessions:
        sgt = s.get("ctsSecurityGroup")
        if not sgt or s.get("state") in ("DISCONNECTED",):
            continue
        for ip in s.get("ipAddresses") or []:
            out[ip] = sgt
    return out


def stomp_frame(command: str, headers: dict[str, str], body: str = "") -> bytes:
    head = "".join(f"{k}:{v}\n" for k, v in headers.items())
    return f"{command}\n{head}\n{body}\0".encode()


def parse_stomp(data: bytes) -> dict | None:
    text = data.decode(errors="replace").rstrip("\0")
    if not text.strip():
        return None
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    headers = dict(line.split(":", 1) for line in lines[1:] if ":" in line)
    return {"command": lines[0].strip(), "headers": headers, "body": body}
