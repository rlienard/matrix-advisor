"""REST API consumed by the web UI."""

from __future__ import annotations

import ipaddress
import os
import time
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from ..agent.actions import ActionError
from ..agent.advisor import RANGES
from ..agent.llm import LLMClient, LLMError
from ..ise.client import ISEClient, ISEError
from ..ise.pxgrid import SESSION_SERVICE, PxGridClient, PxGridError
from ..store import utcnow
from . import auth

router = APIRouter(prefix="/api")
Range = Literal["24h", "7d", "30d"]


def ctx(request: Request):
    return request.app.state.ctx


def _error(e: ActionError) -> JSONResponse:
    return JSONResponse(status_code=e.status, content={"detail": str(e), **e.details})


# ---------------------------------------------------------------- auth
class LoginBody(BaseModel):
    password: str


@router.post("/auth/login")
def login(body: LoginBody, request: Request, response: Response):
    if not auth.check_password(request, body.password):
        time.sleep(1)
        raise HTTPException(401, "Mot de passe incorrect.")
    auth.login(request, response)
    return {"user": "admin"}


@router.post("/auth/logout")
def logout(response: Response):
    auth.logout(response)
    return {"ok": True}


@router.get("/auth/me")
def me(request: Request):
    return {"user": auth.current_user(request)}


# ---------------------------------------------------------------- status
@router.get("/status")
def status(request: Request, _: str = Depends(auth.require_user)):
    c = ctx(request)
    s = c.config.settings
    last = c.store.last_record_ts()
    fresh = last is not None and (utcnow() - last).total_seconds() <= s.collector.stale_after_seconds
    return {
        "netflow": {
            "online": fresh, "last_record": last, "flows_per_s": c.store.flow_rate(),
            "stats": c.pipeline.stats, "input_file": s.collector.input_file,
        },
        "ise": c.ise.summary(),
        "llm": {**c.llm.status, "provider": s.llm.provider, "model": s.llm.model,
                "cloud": s.llm.is_cloud},
        "learning": c.advisor.learning(),
        "observation": c.advisor.observation(),
        "write_mode": s.ise.write_mode,
        "prefix": s.ise.sgacl_prefix,
    }


# ---------------------------------------------------------------- dashboard
@router.get("/dashboard")
def dashboard(request: Request, range: Range = "7d", _: str = Depends(auth.require_user)):
    c = ctx(request)
    since = utcnow() - RANGES[range]
    views = c.advisor.pair_views(since)
    pending = {(p["src"], p["dst"]): p for p in c.store.proposals("pending")}
    links = []
    for v in views:
        cov = v["coverage"]
        key = (v["src"], v["dst"])
        status_ = cov["status"]
        prop = pending.get(key)
        decision = c.store.last_decision_for(*key)
        if status_ != "allowed" and not prop and decision and decision["status"] == "rejected":
            status_ = "rejected"
        covered = set(cov["covered"])
        links.append({
            "id": f"{v['src']}|{v['dst']}", "src": v["src"], "dst": v["dst"], "flows": v["flows"],
            "bytes": v["bytes"], "hosts": v["hosts"], "status": status_,
            "contracts": [{"name": a.name, "acl": a.content, "id": a.id,
                           "shared_with": [f"{s} → {d}" for s, d in c.ise.matrix.contract_users(a.id) if (s, d) != key]}
                          for a in c.ise.matrix.cell_sgacls(*key)],
            "monitor": cov["monitor"], "first_seen": v["first_seen"],
            "activity": v["activity"], "rare": v["rare"],
            "ports": [{"spec": p["spec"], "flows": p["flows"], "hosts": p["hosts"], "covered": p["spec"] in covered}
                      for p in v["ports"]],
            "blocked_flows": sum(p["flows"] for p in v["ports"] if p["spec"] not in covered),
            "proposal_id": prop["id"] if prop else None,
            "last_decision_id": decision["id"] if decision else None,
            "risk": prop["risk"] if prop else None,
            "kind": prop["kind"] if prop else None,
        })
    allowed = sum(1 for link in links if link["status"] == "allowed")
    partial = sum(1 for link in links if link["status"] == "partial")
    by_kind: dict[str, int] = {}
    for p in pending.values():
        by_kind[p["kind"]] = by_kind.get(p["kind"], 0) + 1
    return {
        "range": range,
        "links": links,
        "kpi": {
            "pairs": len(links), "allowed": allowed, "partial": partial,
            "coverage_pct": round(100 * allowed / len(links)) if links else 0,
            "pending": len(pending), "pending_by_kind": by_kind,
            "rejected": sum(1 for link in links if link["status"] == "rejected"),
            "blocked_flows": sum(link["blocked_flows"] for link in links),
            "total_flows": sum(link["flows"] for link in links),
        },
        "trend": c.store.coverage_trend(since),
        "learning": c.advisor.learning(),
        "observation": c.advisor.observation(),
    }


# ---------------------------------------------------------------- proposals
class AclBody(BaseModel):
    acl: str | None = None


class ModeBody(BaseModel):
    mode: Literal["clone", "inplace"]


class ApproveBody(BaseModel):
    acl: str | None = None
    mode: Literal["clone", "inplace"] | None = None
    merge: bool = False


@router.get("/proposals")
def proposals(request: Request, status: str | None = "pending", _: str = Depends(auth.require_user)):
    items = ctx(request).store.proposals(None if status == "all" else status)
    return sorted(items, key=lambda p: -(p.get("features") or {}).get("total_flows", 0))


@router.get("/proposals/{pid}")
def proposal(pid: str, request: Request, _: str = Depends(auth.require_user)):
    c = ctx(request)
    p = c.store.proposal(pid)
    if not p:
        raise HTTPException(404, "Proposition introuvable.")
    return {"proposal": p, "analysis": c.actions.analyse(p)}


@router.post("/proposals/{pid}/analyse")
def analyse(pid: str, body: AclBody, request: Request, _: str = Depends(auth.require_user)):
    c = ctx(request)
    p = c.store.proposal(pid)
    if not p:
        raise HTTPException(404, "Proposition introuvable.")
    return c.actions.analyse(p, body.acl)


@router.put("/proposals/{pid}/edit")
def edit(pid: str, body: AclBody, request: Request, _: str = Depends(auth.require_user)):
    try:
        return ctx(request).actions.save_edit(pid, body.acl)
    except ActionError as e:
        return _error(e)


@router.put("/proposals/{pid}/mode")
def mode(pid: str, body: ModeBody, request: Request, _: str = Depends(auth.require_user)):
    try:
        return ctx(request).actions.set_mode(pid, body.mode)
    except ActionError as e:
        return _error(e)


@router.post("/proposals/{pid}/approve")
async def approve(pid: str, body: ApproveBody, request: Request, user: str = Depends(auth.require_user)):
    try:
        return await ctx(request).actions.approve(pid, user, body.acl, body.mode, body.merge)
    except ActionError as e:
        return _error(e)


@router.post("/proposals/{pid}/reject")
def reject(pid: str, request: Request, user: str = Depends(auth.require_user)):
    try:
        return ctx(request).actions.reject(pid, user)
    except ActionError as e:
        return _error(e)


@router.post("/proposals/{pid}/reopen")
def reopen(pid: str, request: Request, user: str = Depends(auth.require_user)):
    try:
        return ctx(request).actions.reopen(pid, user)
    except ActionError as e:
        return _error(e)


@router.post("/agent/run")
async def run_agent(request: Request, _: str = Depends(auth.require_user)):
    created = await ctx(request).advisor.analyse()
    return {"created": created}


# ---------------------------------------------------------------- ISE
@router.post("/ise/sync")
async def ise_sync(request: Request, _: str = Depends(auth.require_user)):
    c = ctx(request)
    try:
        m = await c.ise.reconcile()
    except ISEError as e:
        return JSONResponse(status_code=502, content={"detail": str(e)})
    c.advisor.wake()
    return {"synced_at": m.synced_at, "sgacls": len(m.sgacls), "cells": len(m.cells)}


class ConfigBody(BaseModel):
    config: dict


def _preview(request: Request, body: ConfigBody):
    try:
        return ctx(request).config.preview(body.config)
    except ValidationError as e:
        raise HTTPException(422, e.errors(include_url=False)) from e


@router.post("/ise/pxgrid-nodes")
async def pxgrid_nodes(body: ConfigBody, request: Request, _: str = Depends(auth.require_user)):
    settings = _preview(request, body)
    client = ISEClient(settings.ise)
    try:
        nodes = await client.deployment_nodes()
    except ISEError as e:
        return JSONResponse(status_code=502, content={"detail": str(e)})
    finally:
        await client.close()
    return {"nodes": nodes, "pxgrid": [n for n in nodes if n["pxgrid"]]}


# ---------------------------------------------------------------- configuration
@router.get("/config")
def get_config(request: Request, _: str = Depends(auth.require_user)):
    return ctx(request).config.masked()


@router.put("/config")
def put_config(body: ConfigBody, request: Request, user: str = Depends(auth.require_user)):
    c = ctx(request)
    try:
        c.config.save(body.config)
    except ValidationError as e:
        raise HTTPException(422, e.errors(include_url=False)) from e
    c.store.audit(user, "config", {"sections": sorted(body.config.keys())})
    return c.config.masked()


@router.post("/config/test/{section}")
async def test_config(section: Literal["llm", "ise", "collector"], body: ConfigBody, request: Request,
                      _: str = Depends(auth.require_user)):
    settings = _preview(request, body)
    c = ctx(request)
    if section == "llm":
        client = LLMClient(settings.llm)
        try:
            res = await client.ping()
            where = "API joignable" if settings.llm.is_cloud else "Endpoint joignable"
            return {"ok": True, "message": f"{where} · modèle {settings.llm.model} disponible · "
                                           f"{res['latency_ms']} ms. Aucune donnée réseau envoyée pendant le test."}
        except LLMError as e:
            return {"ok": False, "message": str(e)}
        finally:
            await client.close()

    if section == "ise":
        client = ISEClient(settings.ise)
        parts = []
        try:
            info = await client.ping()
            parts.append(f"OpenAPI : authentifié sur {settings.ise.pan} · {info['sgt_total']} SGT.")
        except ISEError as e:
            await client.close()
            return {"ok": False, "message": f"OpenAPI : {e}"}
        await client.close()
        px_cfg = settings.ise.pxgrid
        if px_cfg.node or px_cfg.base_url:
            px = PxGridClient(px_cfg)
            try:
                state = await px.ensure_account()
                if state == "ENABLED":
                    await px.lookup(SESSION_SERVICE)
                    parts.append(f"pxGrid : client « {px_cfg.client_name} » approuvé.")
                else:
                    parts.append(f"pxGrid : compte {state}, à approuver dans ISE (Administration > pxGrid).")
            except PxGridError as e:
                return {"ok": False, "message": " ".join(parts) + f" pxGrid : {e}"}
            finally:
                await px.close()
        if not settings.ise.openapi.verify_tls:
            parts.append("Attention : certificat TLS non vérifié.")
        return {"ok": True, "message": " ".join(parts)}

    col = settings.collector
    try:
        for cidr in col.allowed_exporters:
            ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        return {"ok": False, "message": f"Exporteurs autorisés invalides : {e}"}
    if not os.path.exists(col.input_file):
        return {"ok": False, "message": f"Aucune sortie GoFlow2 trouvée ({col.input_file}). "
                                        "GoFlow2 est-il démarré avec -transport.file sur ce chemin ?"}
    age = time.time() - os.path.getmtime(col.input_file)
    last = c.store.last_record_ts()
    rate = c.store.flow_rate()
    if age > col.stale_after_seconds:
        return {"ok": False, "message": f"GoFlow2 n’a rien écrit depuis {int(age)} s : aucun flux reçu "
                                        f"sur les ports {col.ipfix_port}/{col.netflow_v9_port} ?"}
    return {"ok": True, "message": f"GoFlow2 actif · environ {rate} flux/s agrégés · dernier flux "
                                   f"{last:%H:%M:%S} UTC." if last else "GoFlow2 actif, en attente des premiers flux."}


@router.get("/audit")
def audit(request: Request, limit: int = 100, _: str = Depends(auth.require_user)):
    return ctx(request).store.audit_log(limit)


@router.get("/trend")
def trend(request: Request, range: Range = "7d", _: str = Depends(auth.require_user)):
    return ctx(request).store.coverage_trend(utcnow() - RANGES[range])

