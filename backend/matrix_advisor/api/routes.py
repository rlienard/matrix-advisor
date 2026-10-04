"""REST API consumed by the web UI."""

from __future__ import annotations

import ipaddress
import json
import os
import time
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from ..agent.actions import ActionError
from ..agent.advisor import RANGES
from ..agent.llm import LLMClient, LLMError
from ..i18n import Message, localize
from ..ise import certs
from ..ise.client import ISEClient, ISEError
from ..ise.pxgrid import SESSION_SERVICE, PxGridError, pxgrid_client
from ..store import utcnow
from . import auth

router = APIRouter(prefix="/api")
Range = Literal["24h", "7d", "30d"]


def ctx(request: Request):
    return request.app.state.ctx


def _error(e: ActionError, request: Request) -> JSONResponse:
    return JSONResponse(status_code=e.status, content={"detail": localize(e, auth.lang(request)), **e.details})


def _t(request: Request, key: str, **params) -> str:
    return Message(key, **params).render(auth.lang(request))


def _err(request: Request, e: Exception) -> str:
    return localize(e, auth.lang(request))


# ---------------------------------------------------------------- auth
class LoginBody(BaseModel):
    password: str


@router.post("/auth/login")
def login(body: LoginBody, request: Request, response: Response):
    if not auth.check_password(request, body.password):
        time.sleep(1)
        raise HTTPException(401, _t(request, "wrong_password"))
    auth.login(request, response)
    return {"user": "admin"}


@router.post("/auth/logout")
def logout(response: Response):
    auth.logout(response)
    return {"ok": True}


@router.get("/auth/me")
def me(request: Request):
    # The language is public: the login page needs it before authentication.
    return {"user": auth.current_user(request), "language": auth.lang(request)}


def _localized(value, lang: str):
    """Render the catalog messages held in a status structure (last errors) in ``lang``."""
    if isinstance(value, dict):
        return {k: _localized(v, lang) for k, v in value.items()}
    return localize(value, lang)


# ---------------------------------------------------------------- status
@router.get("/status")
def status(request: Request, _: str = Depends(auth.require_user)):
    c = ctx(request)
    s = c.config.settings
    lang = auth.lang(request)
    last = c.store.last_record_ts()
    fresh = last is not None and (utcnow() - last).total_seconds() <= s.collector.stale_after_seconds
    return {
        "netflow": {
            "online": fresh, "last_record": last, "flows_per_s": c.store.flow_rate(),
            "stats": c.pipeline.stats, "input_file": s.collector.input_file,
            "stale_after_seconds": s.collector.stale_after_seconds,
        },
        "ise": {**_localized(c.ise.summary(), lang), "pan": s.ise.pan,
                "reconcile_minutes": s.ise.reconcile_minutes},
        "llm": {**_localized(c.llm.status, lang), "provider": s.llm.provider, "model": s.llm.model,
                "cloud": s.llm.is_cloud, "location": s.llm.location, "endpoint": c.llm.client.endpoint,
                "timeout_s": s.llm.timeout_s},
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
        raise HTTPException(404, _t(request, "proposal_not_found"))
    return {"proposal": p, "analysis": c.actions.analyse(p, lang=auth.lang(request))}


@router.post("/proposals/{pid}/analyse")
def analyse(pid: str, body: AclBody, request: Request, _: str = Depends(auth.require_user)):
    c = ctx(request)
    p = c.store.proposal(pid)
    if not p:
        raise HTTPException(404, _t(request, "proposal_not_found"))
    return c.actions.analyse(p, body.acl, auth.lang(request))


@router.put("/proposals/{pid}/edit")
def edit(pid: str, body: AclBody, request: Request, _: str = Depends(auth.require_user)):
    try:
        return ctx(request).actions.save_edit(pid, body.acl, auth.lang(request))
    except ActionError as e:
        return _error(e, request)


@router.put("/proposals/{pid}/mode")
def mode(pid: str, body: ModeBody, request: Request, _: str = Depends(auth.require_user)):
    try:
        return ctx(request).actions.set_mode(pid, body.mode)
    except ActionError as e:
        return _error(e, request)


@router.post("/proposals/{pid}/approve")
async def approve(pid: str, body: ApproveBody, request: Request, user: str = Depends(auth.require_user)):
    try:
        return await ctx(request).actions.approve(pid, user, body.acl, body.mode, body.merge, auth.lang(request))
    except ActionError as e:
        return _error(e, request)


@router.post("/proposals/{pid}/reject")
def reject(pid: str, request: Request, user: str = Depends(auth.require_user)):
    try:
        return ctx(request).actions.reject(pid, user)
    except ActionError as e:
        return _error(e, request)


@router.post("/proposals/{pid}/reopen")
def reopen(pid: str, request: Request, user: str = Depends(auth.require_user)):
    try:
        return ctx(request).actions.reopen(pid, user)
    except ActionError as e:
        return _error(e, request)


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
        return JSONResponse(status_code=502, content={"detail": _err(request, e)})
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
        return JSONResponse(status_code=502, content={"detail": _err(request, e)})
    finally:
        await client.close()
    return {"nodes": nodes, "pxgrid": [n for n in nodes if n["pxgrid"]]}


# ---------------------------------------------------------------- certificates
class UploadBody(BaseModel):
    kind: Literal["ca", "client_cert", "client_key"]
    filename: str
    data: str  # base64 of the file
    password: str = ""


@router.post("/ise/certificates/upload")
def upload_certificate(body: UploadBody, request: Request, user: str = Depends(auth.require_user)):
    """Store an uploaded ISE chain, pxGrid client certificate or key under <data>/certs.

    Only local files are written; the configuration points to them once the operator saves.
    """
    c = ctx(request)
    try:
        path, details = certs.store_upload(certs.certs_dir(c.config.path), body.kind, body.filename,
                                           certs.decode_upload(body.data), body.password)
    except certs.CertError as e:
        return JSONResponse(status_code=422, content={"detail": _err(request, e)})
    c.store.audit(user, "certificate_upload", {"kind": body.kind, "path": path, **details})
    return {"path": path, "info": details}


@router.get("/ise/certificates")
def certificates(request: Request, _: str = Depends(auth.require_user)):
    s = ctx(request).config.settings.ise
    return {"ca": certs.info(s.ca_cert), "client": certs.info(s.pxgrid.client_cert),
            "trust_import": json.loads(ctx(request).store.get_meta("pxgrid_trust_import") or "null")}


@router.post("/ise/pxgrid/certificate")
async def generate_certificate(body: ConfigBody, request: Request, user: str = Depends(auth.require_user)):
    """Generate a self-signed pxGrid client certificate, and import it into the ISE trusted store
    when ``ise.pxgrid.import_to_ise_trust`` is set. Clicking the button is the explicit approval of
    that write; it is audited like every other write to ISE."""
    c = ctx(request)
    settings = _preview(request, body)
    px = settings.ise.pxgrid
    cn = (px.cert_cn or px.client_name).strip()
    cert_path, key_path, pem, details = certs.generate_self_signed(certs.certs_dir(c.config.path), cn, px.cert_days)
    c.store.audit(user, "pxgrid_cert_generate", {"cn": cn, "days": px.cert_days, "sha256": details["sha256"],
                                                 "path": cert_path})
    trust = {"status": "skipped"}
    if px.import_to_ise_trust:
        client = ISEClient(settings.ise)
        name = f"{settings.ise.sgacl_prefix}pxGrid_{cn}"[:64]
        try:
            res = await client.import_trusted_certificate(name, pem, f"Matrix Advisor pxGrid client {cn}")
            trust = {"status": "ok", "name": name, "pan": settings.ise.pan, "id": res.get("id")}
        except ISEError as e:
            trust = {"status": "failed", "error": _t(request, "trust_import_failed", error=_err(request, e))}
        finally:
            await client.close()
        c.store.audit(user, "ise_trust_import", {"sha256": details["sha256"], "pan": settings.ise.pan,
                                                 "status": trust["status"], "error": trust.get("error")})
    c.store.set_meta("pxgrid_trust_import", json.dumps({**trust, "sha256": details["sha256"],
                                                        "at": utcnow().isoformat()}))
    return {"client_cert": cert_path, "client_key": key_path, "info": details, "trust_import": trust}


# ---------------------------------------------------------------- AI model
@router.post("/llm/models")
async def llm_models(body: ConfigBody, request: Request, _: str = Depends(auth.require_user)):
    """Models of the Ollama / vLLM server described by the (unsaved) settings."""
    settings = _preview(request, body)
    client = LLMClient(settings.llm)
    try:
        return {"endpoint": client.endpoint, "models": await client.list_models()}
    except LLMError as e:
        return JSONResponse(status_code=502, content={"detail": _err(request, e), "endpoint": client.endpoint})
    finally:
        await client.close()


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
async def test_config(section: Literal["llm", "ise", "pxgrid", "collector"], body: ConfigBody, request: Request,
                      _: str = Depends(auth.require_user)):
    settings = _preview(request, body)
    c = ctx(request)
    if section == "llm":
        client = LLMClient(settings.llm)
        try:
            res = await client.ping()
            key = "test_llm_ok_cloud" if settings.llm.is_cloud else "test_llm_ok_local"
            return {"ok": True, "message": _t(request, key, model=settings.llm.model, ms=res["latency_ms"])}
        except LLMError as e:
            return {"ok": False, "message": _err(request, e)}
        finally:
            await client.close()

    tls_note = [] if settings.ise.verify_tls else [_t(request, "test_tls_unverified")]
    if section == "ise":
        client = ISEClient(settings.ise)
        try:
            info = await client.ping()
        except ISEError as e:
            return {"ok": False, "message": _t(request, "test_openapi_failed", error=_err(request, e))}
        finally:
            await client.close()
        msg = _t(request, "test_openapi_ok", pan=settings.ise.pan, sgts=info["sgt_total"])
        return {"ok": True, "message": " ".join([msg, *tls_note])}

    if section == "pxgrid":
        try:
            px = pxgrid_client(settings.ise)
        except (OSError, ValueError) as e:  # unreadable client certificate or key
            return {"ok": False, "message": _t(request, "test_pxgrid_failed", error=str(e))}
        if px is None:
            return {"ok": False, "message": _t(request, "test_pxgrid_not_configured")}
        try:
            state = await px.ensure_account()
            if state == "ENABLED":
                await px.lookup(SESSION_SERVICE)
                msg = _t(request, "test_pxgrid_ok", client=settings.ise.pxgrid.client_name)
            else:
                return {"ok": False, "message": _t(request, "test_pxgrid_pending", state=state)}
        except PxGridError as e:
            return {"ok": False, "message": _t(request, "test_pxgrid_failed", error=_err(request, e))}
        finally:
            await px.close()
        node = px.base.split("//", 1)[-1]
        return {"ok": True, "message": " ".join([f"{msg} ({_t(request, 'test_pxgrid_node', node=node)})", *tls_note])}

    col = settings.collector
    try:
        for cidr in col.allowed_exporters:
            ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        return {"ok": False, "message": _t(request, "test_exporters_invalid", error=str(e))}
    if not os.path.exists(col.input_file):
        return {"ok": False, "message": _t(request, "test_goflow_missing", path=col.input_file)}
    age = time.time() - os.path.getmtime(col.input_file)
    last = c.store.last_record_ts()
    rate = c.store.flow_rate()
    if age > col.stale_after_seconds:
        return {"ok": False, "message": _t(request, "test_goflow_stale", age=int(age), ipfix=col.ipfix_port,
                                           v9=col.netflow_v9_port)}
    if not last:
        return {"ok": True, "message": _t(request, "test_goflow_waiting")}
    return {"ok": True, "message": _t(request, "test_goflow_ok", rate=rate, last=f"{last:%H:%M:%S}")}


@router.get("/audit")
def audit(request: Request, limit: int = 100, _: str = Depends(auth.require_user)):
    return ctx(request).store.audit_log(limit)


@router.get("/trend")
def trend(request: Request, range: Range = "7d", _: str = Depends(auth.require_user)):
    return ctx(request).store.coverage_trend(utcnow() - RANGES[range])

