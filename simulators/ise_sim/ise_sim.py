"""ISE simulator for demos and tests.

Implements the subset of Cisco ISE used by Matrix Advisor:
  * ERS: /ers/config/sgt, /ers/config/sgacl, /ers/config/egressmatrixcell (list, get, create, update)
  * OpenAPI: /api/v1/deployment/node, /api/v1/certs/trusted-certificate[/import]
  * pxGrid 2.0 control (AccountActivate, ServiceLookup, AccessSecret) and REST
    (session/getSessions, sxp/getBindings)
  * pxGrid pubsub: STOMP over websocket at /pxgrid/ise/pubsub. SGT changes are published on
    securityGroupTopic; SGACL and egress cell changes on securityGroupAclTopic (a simplification:
    real ISE has no dedicated matrix topic); /sim/session publishes on sessionTopic.
Plus demo helpers under /sim: inject an administrator change (conflict), push a session event,
reset, dump state.

It is NOT a faithful ISE: just enough behaviour to exercise the workflow without a lab.
"""

from __future__ import annotations

import base64
import copy
import itertools
import json
import os
import uuid

from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

USER = os.environ.get("SIM_USER", "matrix-advisor")
PASSWORD = os.environ.get("SIM_PASSWORD", "demo-password")
DOMAIN = os.environ.get("SIM_DOMAIN", "lab.local")

SGTS = [
    ("Unknown", 0), ("Employees", 4), ("Contractors", 5), ("IT_Admins", 6), ("IoT_Cameras", 7), ("Guests", 8),
    ("Web_Servers", 10), ("HR_Servers", 11), ("Print_Servers", 12), ("Finance_DB", 13), ("Video_NVR", 14),
]
SGACLS = {
    "Web_Access": "permit tcp dst eq 443\npermit tcp dst eq 80\ndeny ip",
    "Printing": "permit tcp dst eq 9100\npermit tcp dst eq 631\ndeny ip",
    "Admin_SSH": "permit tcp dst eq 22\ndeny ip",
    "HR_Portal": "permit tcp dst eq 443\ndeny ip",
}
# Built-in contracts of ISE: read-only, names with a space.
BUILTIN_SGACLS = {"Permit IP": "permit ip", "Deny IP": "deny ip"}
CELLS = [
    ("Employees", "Web_Servers", ["Web_Access"]),
    ("Employees", "Print_Servers", ["Printing"]),
    ("IT_Admins", "HR_Servers", ["Admin_SSH"]),
    ("Employees", "HR_Servers", ["HR_Portal"]),
]
# Endpoint subnets (pxGrid sessions) and server subnets (SXP bindings).
CLIENT_NETS = {"Employees": (1, 10, 200), "Contractors": (2, 10, 60), "IT_Admins": (3, 10, 20),
               "IoT_Cameras": (4, 10, 100), "Guests": (5, 10, 200)}
SERVER_NETS = {"Web_Servers": "10.20.1.0/24", "HR_Servers": "10.20.2.0/24", "Print_Servers": "10.20.3.0/24",
               "Finance_DB": "10.20.4.0/24", "Video_NVR": "10.20.5.0/24"}

WRAP = {"sgt": "Sgt", "sgacl": "Sgacl", "egressmatrixcell": "EgressMatrixCell"}

PX_SECRET = "sim-secret"
SESSION_TOPIC = "/topic/com.cisco.ise.session"
SG_TOPIC = "/topic/com.cisco.ise.config.trustsec.security.group"
SGACL_TOPIC = "/topic/com.cisco.ise.config.trustsec.security.group.acl"
TOPIC_OF = {"sgt": SG_TOPIC, "sgacl": SGACL_TOPIC, "egressmatrixcell": SGACL_TOPIC}


def _id() -> str:
    return str(uuid.uuid4())


def seed() -> dict:
    st: dict = {"sgt": {}, "sgacl": {}, "egressmatrixcell": {}, "accounts": {}, "trusted_certs": {}}
    for name, value in SGTS:
        i = _id()
        st["sgt"][i] = {"id": i, "name": name, "value": value, "description": "", "generationId": "0"}
    for name, content in [*BUILTIN_SGACLS.items(), *SGACLS.items()]:
        i = _id()
        st["sgacl"][i] = {"id": i, "name": name, "description": "", "ipVersion": "IPV4",
                          "readOnly": name in BUILTIN_SGACLS, "aclcontent": content, "generationId": "0"}
    for src, dst, acls in CELLS:
        i = _id()
        st["egressmatrixcell"][i] = {
            "id": i, "name": f"{src}-{dst}", "description": "", "sourceSgtId": _by_name(st, "sgt", src),
            "destinationSgtId": _by_name(st, "sgt", dst), "matrixCellStatus": "ENABLED",
            "defaultRule": "NONE", "sgacls": [_by_name(st, "sgacl", a) for a in acls],
        }
    return st


def _by_name(st: dict, res: str, name: str) -> str | None:
    return next((k for k, v in st[res].items() if v["name"] == name), None)


STATE = seed()
app = FastAPI(title="ISE simulator")


def _check_auth(request: Request, user: str | None = None, password: str | None = None) -> str:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("basic "):
        raise HTTPException(401, "auth required")
    u, _, p = base64.b64decode(header[6:]).decode().partition(":")
    if user is not None and (u, p) != (user, password):
        raise HTTPException(401, "bad credentials")
    return u if user is not None else f"{u}:{p}"


def _ers(request: Request) -> None:
    _check_auth(request, USER, PASSWORD)


# ------------------------------------------------------------------ ERS
@app.get("/ers/config/{res}")
def ers_list(res: str, request: Request, size: int = 20, page: int = 1):
    _ers(request)
    if res not in WRAP:
        raise HTTPException(404)
    items = list(STATE[res].values())
    chunk = items[(page - 1) * size: page * size]
    out = {"total": len(items), "resources": [
        {"id": i["id"], "name": i.get("name", ""), "description": i.get("description", "")} for i in chunk]}
    if page * size < len(items):
        out["nextPage"] = {"rel": "next", "href": f"{request.url.path}?size={size}&page={page + 1}"}
    return {"SearchResult": out}


@app.get("/ers/config/{res}/{oid}")
def ers_get(res: str, oid: str, request: Request):
    _ers(request)
    item = STATE.get(res, {}).get(oid)
    if not item:
        raise HTTPException(404, "not found")
    return {WRAP[res]: item}


def _validate(res: str, body: dict, oid: str | None = None) -> None:
    if res in ("sgt", "sgacl"):
        other = _by_name(STATE, res, body.get("name", ""))
        if other and other != oid:
            raise HTTPException(400, f"{res} name already exists")
    if res == "egressmatrixcell":
        for k in ("sourceSgtId", "destinationSgtId"):
            if body.get(k) not in STATE["sgt"]:
                raise HTTPException(400, f"unknown {k}")
        for s in body.get("sgacls", []):
            if s not in STATE["sgacl"]:
                raise HTTPException(400, f"unknown sgacl {s}")
        dup = next((c for c in STATE[res].values() if c["sourceSgtId"] == body["sourceSgtId"]
                    and c["destinationSgtId"] == body["destinationSgtId"] and c["id"] != oid), None)
        if dup:
            raise HTTPException(400, "cell already exists")


@app.post("/ers/config/{res}", status_code=201)
async def ers_create(res: str, request: Request, response: Response):
    _ers(request)
    body = (await request.json()).get(WRAP.get(res, ""), {})
    _validate(res, body)
    oid = _id()
    item = {**body, "id": oid, "generationId": "0"}
    if res == "sgacl":
        item.setdefault("readOnly", False)
    STATE[res][oid] = item
    await _publish(TOPIC_OF.get(res), {"operation": "CREATE", res: item})
    response.headers["Location"] = f"{request.base_url}ers/config/{res}/{oid}"
    return Response(status_code=201, headers={"Location": response.headers["Location"]})


@app.put("/ers/config/{res}/{oid}")
async def ers_update(res: str, oid: str, request: Request):
    _ers(request)
    if oid not in STATE.get(res, {}):
        raise HTTPException(404)
    body = (await request.json()).get(WRAP.get(res, ""), {})
    current = STATE[res][oid]
    if current.get("readOnly"):
        raise HTTPException(400, "read-only object")
    if res == "sgacl" and body.get("generationId") not in (None, current["generationId"]):
        raise HTTPException(409, "generationId mismatch: object changed")
    merged = {**current, **body, "id": oid}
    _validate(res, merged, oid)
    merged["generationId"] = str(int(current.get("generationId", "0")) + 1)
    STATE[res][oid] = merged
    await _publish(TOPIC_OF.get(res), {"operation": "UPDATE", res: merged})
    return {"UpdatedFieldsList": {"updatedField": [{"field": k} for k in body]}}


# ------------------------------------------------------------------ OpenAPI
@app.get("/api/v1/deployment/node")
def nodes(request: Request):
    _ers(request)
    def n(host, ip, roles, services):
        return {"hostname": host, "fqdn": f"{host}.{DOMAIN}", "ipAddress": ip, "roles": roles,
                "services": services, "nodeStatus": "Connected"}
    return {"response": [
        n("ise-pan", "10.10.20.10", ["PrimaryAdmin", "PrimaryMonitoring"], []),
        n("ise-psn1", "10.10.20.11", [], ["Session", "Profiler"]),
        n("ise-px1", "10.10.20.21", [], ["Session", "Profiler", "pxGrid"]),
        n("ise-px2", "10.10.20.22", [], ["Session", "pxGrid"]),
    ], "version": "1.0.0"}


# Account allowed to import certificates (the API user by default; another name simulates a refusal).
CERT_ADMIN = os.environ.get("SIM_CERT_ADMIN", USER)


@app.post("/api/v1/certs/trusted-certificate/import")
async def trusted_import(request: Request):
    _ers(request)
    if USER != CERT_ADMIN:
        raise HTTPException(403, "insufficient rights on certificates")
    body = await request.json()
    pem = body.get("data", "")
    if "BEGIN CERTIFICATE" not in pem or not body.get("name"):
        raise HTTPException(400, "data must be a PEM certificate and name is required")
    if any(c["name"] == body["name"] for c in STATE["trusted_certs"].values()):
        raise HTTPException(400, "a trusted certificate with this name already exists")
    oid = _id()
    STATE["trusted_certs"][oid] = {"id": oid, **{k: v for k, v in body.items() if k != "data"}}
    return {"response": {"id": oid, "message": "Trusted certificate was successfully imported"}, "version": "1.0.0"}


@app.get("/api/v1/certs/trusted-certificate")
def trusted_list(request: Request):
    _ers(request)
    return {"response": list(STATE["trusted_certs"].values()), "version": "1.0.0"}


# ------------------------------------------------------------------ pxGrid
@app.post("/pxgrid/control/AccountCreate")
async def px_create(request: Request):
    body = await request.json()
    name = body.get("nodeName", "client")
    pw = uuid.uuid4().hex[:16]
    STATE["accounts"][name] = pw
    return {"nodeName": name, "password": pw, "userName": name}


def _px_user(request: Request) -> str:
    return _check_auth(request).split(":", 1)[0]


@app.post("/pxgrid/control/AccountActivate")
def px_activate(request: Request):
    _px_user(request)
    return {"accountState": "ENABLED", "version": "2.0"}


@app.post("/pxgrid/control/ServiceLookup")
async def px_lookup(request: Request):
    _px_user(request)
    name = (await request.json()).get("name")
    base = str(request.base_url).rstrip("/")
    services = {
        "com.cisco.ise.session": {"restBaseUrl": f"{base}/pxgrid/rest/session",
                                  "sessionTopic": SESSION_TOPIC},
        "com.cisco.ise.sxp": {"restBaseUrl": f"{base}/pxgrid/rest/sxp", "bindingTopic": "/topic/com.cisco.ise.sxp.binding"},
        "com.cisco.ise.config.trustsec": {"restBaseUrl": f"{base}/pxgrid/rest/trustsec",
                                          "securityGroupTopic": SG_TOPIC, "securityGroupAclTopic": SGACL_TOPIC},
        "com.cisco.ise.pubsub": {"wsUrl": base.replace("http", "ws", 1) + "/pxgrid/ise/pubsub"},
    }
    if name not in services:
        return {"services": []}
    return {"services": [{"name": name, "nodeName": f"ise-px1.{DOMAIN}", "properties": services[name]}]}


@app.post("/pxgrid/control/AccessSecret")
def px_secret(request: Request):
    _px_user(request)
    return {"secret": PX_SECRET}


@app.post("/pxgrid/rest/session/getSessions")
def px_sessions(request: Request):
    _px_user(request)
    sessions = []
    for sgt, (octet, lo, hi) in CLIENT_NETS.items():
        for host in range(lo, hi + 1):
            sessions.append({"ipAddresses": [f"10.10.{octet}.{host}"], "ctsSecurityGroup": sgt, "state": "STARTED",
                             "userName": f"{sgt.lower()}-{host}"})
    return {"sessions": sessions}


@app.post("/pxgrid/rest/sxp/getBindings")
def px_bindings(request: Request):
    _px_user(request)
    values = dict(SGTS)
    return {"bindings": [{"ipPrefix": net, "tag": values[sgt], "source": "static"} for sgt, net in SERVER_NETS.items()]}


# ------------------------------------------------------------------ pxGrid pubsub (STOMP over websocket)
SUBSCRIBERS: list[tuple[WebSocket, str, str]] = []  # (websocket, destination, subscription id)
_message_ids = itertools.count(1)


def stomp_frame(command: str, headers: dict[str, str], body: str = "") -> str:
    return command + "\n" + "".join(f"{k}:{v}\n" for k, v in headers.items()) + "\n" + body + "\0"


def parse_stomp(raw: str) -> tuple[str, dict[str, str]]:
    head = raw.rstrip("\0").partition("\n\n")[0].split("\n")
    return head[0].strip(), dict(line.split(":", 1) for line in head[1:] if ":" in line)


async def _publish(topic: str | None, body: dict) -> None:
    if not topic:
        return
    payload = json.dumps(body)
    gone = []
    for ws, dest, sub_id in SUBSCRIBERS:
        if dest != topic:
            continue
        frame = stomp_frame("MESSAGE", {"destination": topic, "subscription": sub_id,
                                        "message-id": str(next(_message_ids)), "content-type": "application/json"},
                            payload)
        try:
            await ws.send_bytes(frame.encode())
        except Exception:  # noqa: BLE001 - subscriber gone
            gone.append(ws)
    for ws in gone:
        _drop(ws)


def _drop(ws: WebSocket) -> None:
    SUBSCRIBERS[:] = [s for s in SUBSCRIBERS if s[0] is not ws]


@app.websocket("/pxgrid/ise/pubsub")
async def px_pubsub(ws: WebSocket):
    header = ws.headers.get("authorization", "")
    user, _, secret = base64.b64decode(header[6:]).decode(errors="replace").partition(":") \
        if header.lower().startswith("basic ") else ("", "", "")
    if not user or secret != PX_SECRET:
        await ws.close(code=1008)
        return
    await ws.accept()
    try:
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            raw = msg.get("text") or (msg.get("bytes") or b"").decode(errors="replace")
            command, headers = parse_stomp(raw)
            if command in ("CONNECT", "STOMP"):
                await ws.send_bytes(stomp_frame("CONNECTED", {"version": "1.2"}).encode())
            elif command == "SUBSCRIBE":
                SUBSCRIBERS.append((ws, headers.get("destination", ""), headers.get("id", "")))
            elif command == "UNSUBSCRIBE":
                SUBSCRIBERS[:] = [s for s in SUBSCRIBERS if not (s[0] is ws and s[2] == headers.get("id"))]
            elif command == "DISCONNECT":
                break
    except WebSocketDisconnect:
        pass
    finally:
        _drop(ws)


# ------------------------------------------------------------------ demo helpers
class Conflict(BaseModel):
    src: str
    dst: str
    sgacl: str = "DBA_Maintenance"
    content: str = "permit tcp dst eq 1433\ndeny ip"


@app.post("/sim/conflict")
async def sim_conflict(c: Conflict):
    """Simulate an administrator assigning a contract to a cell behind the advisor's back."""
    sid = _by_name(STATE, "sgacl", c.sgacl)
    if not sid:
        sid = _id()
        STATE["sgacl"][sid] = {"id": sid, "name": c.sgacl, "description": "manual", "ipVersion": "IPV4",
                               "readOnly": False, "aclcontent": c.content, "generationId": "0"}
    src, dst = _by_name(STATE, "sgt", c.src), _by_name(STATE, "sgt", c.dst)
    if not src or not dst:
        raise HTTPException(400, "unknown SGT")
    cell = next((x for x in STATE["egressmatrixcell"].values()
                 if x["sourceSgtId"] == src and x["destinationSgtId"] == dst), None)
    if cell:
        if sid not in cell["sgacls"]:
            cell["sgacls"].append(sid)
    else:
        cid = _id()
        STATE["egressmatrixcell"][cid] = {"id": cid, "name": f"{c.src}-{c.dst}", "description": "manual",
                                          "sourceSgtId": src, "destinationSgtId": dst, "matrixCellStatus": "ENABLED",
                                          "defaultRule": "NONE", "sgacls": [sid]}
    await _publish(SGACL_TOPIC, {"operation": "UPDATE", "sgacl": STATE["sgacl"][sid]})
    return {"ok": True}


class SessionEvent(BaseModel):
    ip: str
    sgt: str
    state: str = "STARTED"  # or DISCONNECTED


@app.post("/sim/session")
async def sim_session(e: SessionEvent):
    """Publish a session change (endpoint connected or disconnected) on the pxGrid session topic."""
    session = {"ipAddresses": [e.ip], "ctsSecurityGroup": e.sgt, "state": e.state, "userName": f"sim-{e.ip}"}
    await _publish(SESSION_TOPIC, {"sessions": [session]})
    return {"ok": True, "subscribers": sum(1 for s in SUBSCRIBERS if s[1] == SESSION_TOPIC)}


@app.post("/sim/reset")
def sim_reset():
    global STATE
    STATE = seed()
    return {"ok": True}


@app.get("/sim/state")
def sim_state():
    names = {k: v["name"] for k, v in itertools.chain(STATE["sgt"].items(), STATE["sgacl"].items())}
    cells = [{"src": names[c["sourceSgtId"]], "dst": names[c["destinationSgtId"]], "status": c["matrixCellStatus"],
              "sgacls": [names[s] for s in c["sgacls"]]} for c in STATE["egressmatrixcell"].values()]
    return {"sgacls": {v["name"]: v["aclcontent"] for v in STATE["sgacl"].values()}, "cells": cells}


def reset_for_tests() -> None:
    global STATE
    STATE = copy.deepcopy(seed())
