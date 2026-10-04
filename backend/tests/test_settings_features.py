"""Unknown (SGT 0) proposals, ISE TLS/certificate settings, pxGrid failover, model discovery and
the local model server host detection."""

import asyncio
import base64
import os
import stat
from datetime import timedelta

import httpx
import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from matrix_advisor.agent import llm as llm_mod
from matrix_advisor.agent.advisor import LLMHolder
from matrix_advisor.agent.llm import LLMClient, LLMError, effective_endpoint
from matrix_advisor.config import ConfigStore, LLMConfig, PxGridConfig
from matrix_advisor.ise.pxgrid import PxGridClient
from matrix_advisor.main import build_context, create_app
from matrix_advisor.store import utcnow


def _app(sim_url, tmp_path, firewall=True, extra_flows=None):
    httpx.post(sim_url + "/sim/reset")
    cfg = {
        "llm": {"provider": "ollama", "endpoint": "http://127.0.0.1:9", "learning_days": 0, "timeout_s": 2},
        "ise": {
            "pan": "sim", "openapi": {"base_url": sim_url, "username": "matrix-advisor", "password": "demo-password"},
            "egress_firewall": firewall,
            "static_bindings": {"10.10.1.0/24": "Employees", "10.20.1.0/24": "Web_Servers"},
        },
        "collector": {"input_file": str(tmp_path / "none.ndjson"), "parquet_dir": str(tmp_path / "pq")},
        "server": {"admin_password": "secret"},
    }
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(cfg))
    ctx = build_context(str(tmp_path / "config.yaml"), ":memory:")
    ctx.resolver.set_static(cfg["ise"]["static_bindings"])
    now = utcnow()
    rows = []
    for dst, port, n in [("198.51.100.7", 443, 30), ("203.0.113.9", 53, 10)] + (extra_flows or []):
        for i in range(n):
            ts = (now - timedelta(minutes=i)).strftime("%Y-%m-%d %H:%M:%S.%f")
            src = f"10.10.1.{10 + i % 5}"
            proto = "UDP" if port == 53 else "TCP"
            rows.append((ts, "10.0.0.1", src, 50000, dst, port, proto, 1000, 10,
                         ctx.resolver.resolve(src), ctx.resolver.resolve(dst)))
    ctx.store.ingest(rows)
    return ctx, create_app(ctx, start_workers=False)


@pytest.fixture()
def unknown_fw(sim_url, tmp_path):
    ctx, app = _app(sim_url, tmp_path, firewall=True)
    with TestClient(app) as c:
        assert c.post("/api/auth/login", json={"password": "secret"}).status_code == 200
        assert c.post("/api/ise/sync").status_code == 200
        assert c.post("/api/agent/run").json()["created"] == 1
        c.sim = sim_url
        yield c


def _proposal(c):
    (p,) = c.get("/api/proposals").json()
    return p


def _cell(c, src, dst):
    return next((x for x in httpx.get(c.sim + "/sim/state").json()["cells"] if x["src"] == src and x["dst"] == dst),
                None)


# ---------------------------------------------------------------- Unknown (SGT 0)
def test_unknown_behind_firewall_assigns_permit_ip(unknown_fw):
    p = _proposal(unknown_fw)
    assert (p["src"], p["dst"], p["kind"]) == ("Employees", "Unknown", "unknown")
    assert p["base_contract"] == "Permit IP" and p["proposed_acl"] == "permit ip"
    assert p["features"]["egress_firewall"] is True and "pare-feu" in p["justification"]
    r = unknown_fw.post(f"/api/proposals/{p['id']}/approve", json={})
    assert r.status_code == 200, r.text
    assert r.json()["result"]["action"] == "assign"
    cell = _cell(unknown_fw, "Employees", "Unknown")
    assert cell == {"src": "Employees", "dst": "Unknown", "status": "MONITOR", "sgacls": ["Permit IP"]}


def test_unknown_permit_ip_edit_is_always_cloned(unknown_fw):
    p = _proposal(unknown_fw)
    edit = "permit tcp dst eq 443\npermit udp dst eq 53\ndeny ip"
    a = unknown_fw.post(f"/api/proposals/{p['id']}/analyse", json={"acl": edit}).json()
    assert a["changes_base"] and not a["inplace_allowed"] and a["default_mode"] == "clone"
    assert a["clone_name"] == "MA_Permit_IP_Employees"  # ISE names: no space
    assert unknown_fw.post(f"/api/proposals/{p['id']}/approve", json={"acl": edit, "mode": "inplace"}).status_code == 409
    r = unknown_fw.post(f"/api/proposals/{p['id']}/approve", json={"acl": edit, "mode": "clone"})
    assert r.status_code == 200, r.text
    state = httpx.get(unknown_fw.sim + "/sim/state").json()
    assert state["sgacls"]["Permit IP"] == "permit ip"
    assert _cell(unknown_fw, "Employees", "Unknown")["sgacls"] == ["MA_Permit_IP_Employees"]


def test_unknown_without_firewall_is_least_privilege(sim_url, tmp_path):
    _, app = _app(sim_url, tmp_path, firewall=False)
    with TestClient(app) as c:
        c.sim = sim_url
        c.post("/api/auth/login", json={"password": "secret"})
        c.post("/api/ise/sync")
        c.post("/api/agent/run")
        p = _proposal(c)
        assert p["kind"] == "unknown" and p["base_contract"] is None
        assert p["proposed_acl"] == "permit tcp dst eq 443 log\npermit udp dst eq 53 log\ndeny ip log"
        assert "sans pare-feu" in p["justification"]
        r = c.post(f"/api/proposals/{p['id']}/approve", json={})
        assert r.status_code == 200 and r.json()["result"]["action"] == "create"
        assert _cell(c, "Employees", "Unknown")["sgacls"] == ["MA_Employees_to_Unknown"]


# ---------------------------------------------------------------- configuration
def test_tls_settings_are_migrated_to_ise_level(tmp_path):
    (tmp_path / "config.yaml").write_text(yaml.safe_dump({"ise": {
        "openapi": {"verify_tls": True, "ca_cert": "/certs/ise-ca.pem"},
        "pxgrid": {"verify_tls": False, "ca_cert": "/certs/other.pem"},
    }}))
    ise = ConfigStore(tmp_path / "config.yaml").settings.ise
    assert ise.verify_tls is False and ise.ca_cert == "/certs/ise-ca.pem"
    assert ise.egress_firewall is True and ise.pxgrid.import_to_ise_trust is True


def test_key_password_is_a_secret(tmp_path):
    store = ConfigStore(tmp_path / "config.yaml")
    store.save({"ise": {"pxgrid": {"client_key_password": "s3cret"}}})
    assert "s3cret" not in (tmp_path / "config.yaml").read_text()
    assert store.masked()["ise"]["pxgrid"]["client_key_password"] == "********"
    assert ConfigStore(tmp_path / "config.yaml").settings.ise.pxgrid.client_key_password == "s3cret"


# ---------------------------------------------------------------- AI model
def test_local_instance_endpoint(monkeypatch):
    llm_mod.local_host.cache_clear()
    monkeypatch.delenv("MA_LLM_LOCAL_HOST", raising=False)
    monkeypatch.setattr(llm_mod, "in_container", lambda: False)
    cfg = LLMConfig(provider="ollama", location="local", port=11500, endpoint="http://far:1")
    assert effective_endpoint(cfg) == "http://localhost:11500"
    # in a container, localhost is the container: use the name the runtime gives to the host
    llm_mod.local_host.cache_clear()
    monkeypatch.setattr(llm_mod, "in_container", lambda: True)
    monkeypatch.setattr(llm_mod, "_resolves", lambda name: name == "host.lima.internal")
    assert effective_endpoint(cfg) == "http://host.lima.internal:11500"
    llm_mod.local_host.cache_clear()
    monkeypatch.setenv("MA_LLM_LOCAL_HOST", "10.0.0.5")
    assert effective_endpoint(cfg) == "http://10.0.0.5:11500"
    # remote instances and cloud providers keep their URL
    assert effective_endpoint(LLMConfig(provider="ollama", location="remote", endpoint="http://gpu:11434/")) \
        == "http://gpu:11434"
    assert effective_endpoint(LLMConfig(provider="anthropic", location="local", endpoint="https://api.x")) \
        == "https://api.x"
    llm_mod.local_host.cache_clear()


def test_model_discovery_ollama_and_vllm():
    asyncio.run(_model_discovery())


async def _model_discovery():
    def ollama(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [
                {"name": "llama3.1:8b", "size": 4_900_000_000, "details": {"quantization_level": "Q4_K_M"}},
                {"name": "qwen2.5:14b", "size": 9_000_000_000, "details": {"quantization_level": "Q4_K_M",
                                                                            "parameter_size": "14.8B"}},
            ]})
        return httpx.Response(200, json={"models": [{"name": "qwen2.5:14b"}]})

    c = LLMClient(LLMConfig(provider="ollama", endpoint="http://ollama:11434"))
    c.http = httpx.AsyncClient(transport=httpx.MockTransport(ollama))
    models = await c.list_models()
    assert [(m["name"], m["loaded"]) for m in models] == [("qwen2.5:14b", True), ("llama3.1:8b", False)]
    assert models[0]["quantization"] == "Q4_K_M" and models[0]["size"] == 9_000_000_000

    def vllm(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/models"
        return httpx.Response(200, json={"data": [{"id": "Qwen/Qwen2.5-14B-Instruct"}]})

    c = LLMClient(LLMConfig(provider="openai", endpoint="http://vllm:8000/v1"))
    c.http = httpx.AsyncClient(transport=httpx.MockTransport(vllm))
    assert [m["name"] for m in await c.list_models()] == ["Qwen/Qwen2.5-14B-Instruct"]

    with pytest.raises(LLMError):
        await LLMClient(LLMConfig(provider="anthropic")).list_models()


def test_models_endpoint_reports_unreachable_server(unknown_fw):
    cfg = unknown_fw.get("/api/config").json()
    cfg["llm"].update(location="remote", endpoint="http://127.0.0.1:9")
    r = unknown_fw.post("/api/llm/models", json={"config": cfg})
    assert r.status_code == 502 and "127.0.0.1:9" in r.json()["detail"]


def test_llm_status_follows_real_calls(tmp_path):
    holder = LLMHolder(ConfigStore(tmp_path / "config.yaml"))
    woken = []
    holder.on_online = lambda: woken.append(1)
    holder.mark(LLMError("aucune réponse"))
    assert holder.status["online"] is False and holder.status["error"]
    holder.mark()
    assert holder.status["online"] is True and woken == [1]


# ---------------------------------------------------------------- connection tests
def test_ise_and_pxgrid_are_tested_separately(unknown_fw):
    cfg = unknown_fw.get("/api/config").json()
    r = unknown_fw.post("/api/config/test/ise", json={"config": cfg}).json()
    assert r["ok"] and r["message"].startswith("OpenAPI") and "pxGrid" not in r["message"]
    r = unknown_fw.post("/api/config/test/pxgrid", json={"config": cfg}).json()
    assert not r["ok"] and "aucun nœud" in r["message"]
    cfg["ise"]["pxgrid"].update(base_url=unknown_fw.sim, auth="password", password="x")
    r = unknown_fw.post("/api/config/test/pxgrid", json={"config": cfg}).json()
    assert r["ok"] and r["message"].startswith("pxGrid"), r


def test_pxgrid_falls_back_to_secondary_node():
    asyncio.run(_pxgrid_failover())


async def _pxgrid_failover():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        if request.url.host == "px1":
            raise httpx.ConnectError("down", request=request)
        return httpx.Response(200, json={"accountState": "ENABLED"})

    px = PxGridClient(PxGridConfig(node="px1", secondary_node="px2", auth="password", password="x"))
    px.http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    assert await px.ensure_account() == "ENABLED"
    assert seen == ["px1", "px2"] and px.base == "https://px2:8910"
    await px.ensure_account()
    assert seen[-1] == "px2"  # stays on the node that answers


# ---------------------------------------------------------------- certificates
def _audit(c, action):
    return [a for a in c.get("/api/audit").json() if a["action"] == action]


def test_generate_certificate_and_import_into_ise_trust(unknown_fw, tmp_path):
    cfg = unknown_fw.get("/api/config").json()
    cfg["ise"]["pxgrid"].update(client_name="matrix-advisor", cert_cn="ma-pxgrid", cert_days=365,
                                import_to_ise_trust=True)
    r = unknown_fw.post("/api/ise/pxgrid/certificate", json={"config": cfg})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["trust_import"]["status"] == "ok" and out["info"]["subject"] == "ma-pxgrid"
    assert 363 <= out["info"]["days_left"] <= 365 and len(out["info"]["sha256"].split(":")) == 32
    assert stat.S_IMODE(os.stat(out["client_key"]).st_mode) == 0o600
    cert = x509.load_pem_x509_certificate(open(out["client_cert"], "rb").read())
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    trusted = httpx.get(unknown_fw.sim + "/api/v1/certs/trusted-certificate",
                        auth=("matrix-advisor", "demo-password")).json()["response"]
    assert [t["name"] for t in trusted] == ["MA_pxGrid_ma-pxgrid"] and trusted[0]["trustForClientAuth"] is True
    assert _audit(unknown_fw, "ise_trust_import")[0]["detail"]["status"] == "ok"
    assert _audit(unknown_fw, "pxgrid_cert_generate")
    # nothing changes in the saved configuration until the operator saves the new paths
    assert unknown_fw.get("/api/config").json()["ise"]["pxgrid"]["client_cert"] == ""


def test_trust_import_refused_is_reported_and_audited(unknown_fw, monkeypatch):
    import ise_sim

    monkeypatch.setattr(ise_sim, "CERT_ADMIN", "someone-else")
    cfg = unknown_fw.get("/api/config").json()
    out = unknown_fw.post("/api/ise/pxgrid/certificate", json={"config": cfg}).json()
    assert out["trust_import"]["status"] == "failed" and "403" in out["trust_import"]["error"]
    assert _audit(unknown_fw, "ise_trust_import")[0]["detail"]["status"] == "failed"
    cfg["ise"]["pxgrid"]["import_to_ise_trust"] = False
    out = unknown_fw.post("/api/ise/pxgrid/certificate", json={"config": cfg}).json()
    assert out["trust_import"] == {"status": "skipped"}


def _self_signed(cn="ise-root"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = utcnow()
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + timedelta(days=30))
            .sign(key, hashes.SHA256()))
    return cert, key


def test_upload_certificates(unknown_fw):
    cert, key = _self_signed()
    b64 = lambda data: base64.b64encode(data).decode()  # noqa: E731
    pem = cert.public_bytes(serialization.Encoding.PEM)
    r = unknown_fw.post("/api/ise/certificates/upload", json={"kind": "ca", "filename": "ise root.pem", "data": b64(pem)})
    assert r.status_code == 200 and r.json()["info"]["subject"] == "ise-root"
    assert open(r.json()["path"], "rb").read() == pem
    der = cert.public_bytes(serialization.Encoding.DER)
    assert unknown_fw.post("/api/ise/certificates/upload",
                           json={"kind": "client_cert", "filename": "c.cer", "data": b64(der)}).status_code == 200
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.BestAvailableEncryption(b"pw"))
    r = unknown_fw.post("/api/ise/certificates/upload", json={"kind": "client_key", "filename": "c.key",
                                                              "data": b64(key_pem), "password": "bad"})
    assert r.status_code == 422 and "mot de passe" in r.json()["detail"]
    r = unknown_fw.post("/api/ise/certificates/upload", json={"kind": "client_key", "filename": "c.key",
                                                              "data": b64(key_pem), "password": "pw"})
    assert r.status_code == 200 and stat.S_IMODE(os.stat(r.json()["path"]).st_mode) == 0o600
    r = unknown_fw.post("/api/ise/certificates/upload", json={"kind": "ca", "filename": "x", "data": b64(b"garbage")})
    assert r.status_code == 422
