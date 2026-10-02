"""ISE simulator for demos and tests.

Implements the subset of Cisco ISE used by Matrix Advisor:
  * ERS: /ers/config/sgt, /ers/config/sgacl, /ers/config/egressmatrixcell (list, get, create, update)
  * OpenAPI: /api/v1/deployment/node
  * pxGrid 2.0 control (AccountActivate, ServiceLookup, AccessSecret) and REST
    (session/getSessions, sxp/getBindings). No websocket: clients fall back to polling.
Plus demo helpers under /sim: inject an administrator change (conflict), reset, dump state.

It is NOT a faithful ISE: just enough behaviour to exercise the workflow without a lab.
"""

from __future__ import annotations

import base64
import copy
import itertools
import os
import uuid

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel

USER = os.environ.get("SIM_USER", "matrix-advisor")
PASSWORD = os.environ.get("SIM_PASSWORD", "demo-password")
DOMAIN = os.environ.get("SIM_DOMAIN", "lab.local")

SGTS = [
    ("Employees", 4), ("Contractors", 5), ("IT_Admins", 6), ("IoT_Cameras", 7), ("Guests", 8),
    ("Web_Servers", 10), ("HR_Servers", 11), ("Print_Servers", 12), ("Finance_DB", 13), ("Video_NVR", 14),
]
SGACLS = {
    "Web_Access": "permit tcp dst eq 443\npermit tcp dst eq 80\ndeny ip",
    "Printing": "permit tcp dst eq 9100\npermit tcp dst eq 631\ndeny ip",
    "Admin_SSH": "permit tcp dst eq 22\ndeny ip",
    "HR_Portal": "permit tcp dst eq 443\ndeny ip",
}
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


def _id() -> str:
    return str(uuid.uuid4())


def seed() -> dict:
    st: dict = {"sgt": {}, "sgacl": {}, "egressmatrixcell": {}, "accounts": {}}
    for name, value in SGTS:
        i = _id()
        st["sgt"][i] = {"id": i, "name": name, "value": value, "description": "", "generationId": "0"}
    for name, content in SGACLS.items():
        i = _id()
        st["sgacl"][i] = {"id": i, "name": name, "description": "", "ipVersion": "IPV4", "readOnly": False,
                          "aclcontent": content, "generationId": "0"}
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
    response.headers["Location"] = f"{request.base_url}ers/config/{res}/{oid}"
    return Response(status_code=201, headers={"Location": response.headers["Location"]})


@app.put("/ers/config/{res}/{oid}")
async def ers_update(res: str, oid: str, request: Request):
    _ers(request)
    if oid not in STATE.get(res, {}):
        raise HTTPException(404)
    body = (await request.json()).get(WRAP.get(res, ""), {})
    current = STATE[res][oid]
    if res == "sgacl" and body.get("generationId") not in (None, current["generationId"]):
        raise HTTPException(409, "generationId mismatch: object changed")
    merged = {**current, **body, "id": oid}
    _validate(res, merged, oid)
    merged["generationId"] = str(int(current.get("generationId", "0")) + 1)
    STATE[res][oid] = merged
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
                                  "sessionTopic": "/topic/com.cisco.ise.session"},
        "com.cisco.ise.sxp": {"restBaseUrl": f"{base}/pxgrid/rest/sxp", "bindingTopic": "/topic/com.cisco.ise.sxp.binding"},
        "com.cisco.ise.config.trustsec": {"restBaseUrl": f"{base}/pxgrid/rest/trustsec",
                                          "securityGroupTopic": "/topic/com.cisco.ise.config.trustsec.security.group"},
    }
    if name not in services:
        return {"services": []}
    return {"services": [{"name": name, "nodeName": f"ise-px1.{DOMAIN}", "properties": services[name]}]}


@app.post("/pxgrid/control/AccessSecret")
def px_secret(request: Request):
    _px_user(request)
    return {"secret": "sim-secret"}


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


# ------------------------------------------------------------------ demo helpers
class Conflict(BaseModel):
    src: str
    dst: str
    sgacl: str = "DBA_Maintenance"
    content: str = "permit tcp dst eq 1433\ndeny ip"


@app.post("/sim/conflict")
def sim_conflict(c: Conflict):
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
    return {"ok": True}


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
