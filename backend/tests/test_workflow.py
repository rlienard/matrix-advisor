"""End-to-end workflow against the ISE simulator: flows -> proposals -> decisions -> ISE writes."""

from datetime import timedelta

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient

from matrix_advisor.main import build_context, create_app
from matrix_advisor.store import utcnow


@pytest.fixture()
def client(sim_url, tmp_path):
    httpx.post(sim_url + "/sim/reset")
    cfg = {
        "llm": {"provider": "ollama", "endpoint": "http://127.0.0.1:9", "learning_days": 0, "timeout_s": 2},
        "ise": {
            "pan": "sim", "openapi": {"base_url": sim_url, "username": "matrix-advisor", "password": "demo-password"},
            "static_bindings": {
                "10.10.1.0/24": "Employees", "10.10.2.0/24": "Contractors", "10.10.3.0/24": "IT_Admins",
                "10.20.1.0/24": "Web_Servers", "10.20.2.0/24": "HR_Servers", "10.20.4.0/24": "Finance_DB",
            },
        },
        "collector": {"input_file": str(tmp_path / "none.ndjson"), "parquet_dir": str(tmp_path / "pq")},
        "server": {"admin_password": "secret"},
    }
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(cfg))
    ctx = build_context(str(tmp_path / "config.yaml"), ":memory:")
    now = utcnow()

    def flows(src_net, dst, port, n, hosts, proto="TCP"):
        rows = []
        for i in range(n):
            ts = (now - timedelta(minutes=i)).strftime("%Y-%m-%d %H:%M:%S.%f")
            src = f"{src_net}.{10 + i % hosts}"
            rows.append((ts, "10.0.0.1", src, 50000, dst, port, proto, 1000, 10,
                         ctx.resolver.resolve(src), ctx.resolver.resolve(dst)))
        return rows

    ctx.resolver.set_static(cfg["ise"]["static_bindings"])
    ctx.store.ingest(
        flows("10.10.1", "10.20.1.20", 443, 40, 20) + flows("10.10.1", "10.20.1.20", 80, 10, 5)
        + flows("10.10.1", "10.20.2.20", 443, 20, 10) + flows("10.10.1", "10.20.2.20", 8443, 10, 10)
        + flows("10.10.2", "10.20.1.20", 443, 15, 8) + flows("10.10.2", "10.20.4.20", 1433, 6, 3)
        + flows("10.10.3", "10.20.4.20", 22, 6, 2) + flows("10.10.3", "10.20.4.20", 1433, 6, 2)
    )
    app = create_app(ctx, start_workers=False)
    with TestClient(app) as c:
        assert c.post("/api/auth/login", json={"password": "secret"}).status_code == 200
        assert c.post("/api/ise/sync").status_code == 200
        assert c.post("/api/agent/run").json()["created"] == 4
        c.sim = sim_url
        yield c


def _props(c):
    return {(p["src"], p["dst"]): p for p in c.get("/api/proposals").json()}


def _sim(c):
    return httpx.get(c.sim + "/sim/state").json()


def test_ise_sync_loads_sgt_values_for_flow_tags(client):
    resolver = client.app.state.ctx.resolver
    assert (resolver.tag_name(4), resolver.tag_name(13), resolver.tag_name(999)) == ("Employees", "Finance_DB", None)


def test_auth_required(client):
    client.post("/api/auth/logout")
    assert client.get("/api/dashboard").status_code == 401


def test_proposal_kinds(client):
    props = _props(client)
    assert props[("Employees", "HR_Servers")]["kind"] == "extend"
    assert props[("Contractors", "Web_Servers")]["kind"] == "reuse"
    assert props[("Contractors", "Web_Servers")]["base_contract"] == "Web_Access"
    assert props[("Contractors", "Finance_DB")]["risk"] == "high"
    assert props[("IT_Admins", "Finance_DB")]["kind"] == "new"
    kpi = client.get("/api/dashboard").json()["kpi"]
    assert kpi["allowed"] == 1 and kpi["partial"] == 1 and kpi["pending"] == 4


def test_reuse_edit_is_cloned_when_it_would_break_other_pairs(client):
    p = _props(client)[("Contractors", "Web_Servers")]
    edit = "permit tcp dst eq 443\ndeny ip"
    analysis = client.post(f"/api/proposals/{p['id']}/analyse", json={"acl": edit}).json()
    assert analysis["impacts"] and not analysis["inplace_allowed"]
    r = client.post(f"/api/proposals/{p['id']}/approve", json={"acl": edit, "mode": "inplace"})
    assert r.status_code == 409
    r = client.post(f"/api/proposals/{p['id']}/approve", json={"acl": edit, "mode": "clone"})
    assert r.status_code == 200, r.text
    state = _sim(client)
    assert state["sgacls"]["MA_Web_Access_Contractors"] == "permit tcp dst eq 443\ndeny ip"
    assert state["sgacls"]["Web_Access"].count("permit") == 2  # untouched


def test_extend_keeps_existing_cell_status(client):
    p = _props(client)[("Employees", "HR_Servers")]
    assert client.post(f"/api/proposals/{p['id']}/approve", json={}).status_code == 200
    cell = next(c for c in _sim(client)["cells"] if c["src"] == "Employees" and c["dst"] == "HR_Servers")
    assert cell["status"] == "ENABLED"
    assert "8443" in _sim(client)["sgacls"]["HR_Portal"]


def test_conflict_then_merge(client):
    p = _props(client)[("IT_Admins", "Finance_DB")]
    httpx.post(client.sim + "/sim/conflict", json={"src": "IT_Admins", "dst": "Finance_DB"})
    r = client.post(f"/api/proposals/{p['id']}/approve", json={})
    assert r.status_code == 409 and r.json()["current_contracts"] == ["DBA_Maintenance"]
    r = client.post(f"/api/proposals/{p['id']}/approve", json={"merge": True})
    assert r.status_code == 200
    cell = next(c for c in _sim(client)["cells"] if c["src"] == "IT_Admins" and c["dst"] == "Finance_DB")
    assert cell["sgacls"] == ["DBA_Maintenance", "MA_IT_Admins_to_Finance_DB"] and cell["status"] == "ENABLED"


def test_reject_and_reopen(client):
    p = _props(client)[("Contractors", "Finance_DB")]
    assert client.post(f"/api/proposals/{p['id']}/reject").json()["status"] == "rejected"
    links = {link["id"]: link for link in client.get("/api/dashboard").json()["links"]}
    assert links["Contractors|Finance_DB"]["status"] == "rejected"
    assert client.post(f"/api/proposals/{p['id']}/reopen").json()["status"] == "pending"


def test_invalid_edit_rejected(client):
    p = _props(client)[("Contractors", "Finance_DB")]
    r = client.put(f"/api/proposals/{p['id']}/edit", json={"acl": "permit everything"})
    assert r.status_code == 400 and r.json()["errors"]


def test_config_masks_secrets(client):
    cfg = client.get("/api/config").json()
    assert cfg["ise"]["openapi"]["password"] == "********"
    cfg["ise"]["sgacl_prefix"] = "AI_"
    assert client.put("/api/config", json={"config": cfg}).json()["ise"]["sgacl_prefix"] == "AI_"
    nodes = client.post("/api/ise/pxgrid-nodes", json={"config": cfg}).json()
    assert [n["hostname"] for n in nodes["pxgrid"]] == ["ise-px1", "ise-px2"]


def _ingest(c, src, dst, proto, port, days_ago, n=3):
    """Flows of one SGT pair ``days_ago`` days back, rolled up as the ingest loop would."""
    store = c.app.state.ctx.store
    day = utcnow() - timedelta(days=days_ago)
    store.ingest([((day - timedelta(minutes=i)).strftime("%Y-%m-%d %H:%M:%S.%f"), "10.0.0.1", f"10.99.0.{i}",
                   50000, "10.99.1.1", port, proto, 1000, 10, src, dst) for i in range(n)])
    if days_ago:
        store.rollup_daily(day)


def test_monthly_job_seen_weeks_ago_gets_a_rare_flow_proposal(client):
    _ingest(client, "Contractors", "HR_Servers", "TCP", 22, days_ago=20)
    assert client.post("/api/agent/run").json()["created"] == 1
    p = _props(client)[("Contractors", "HR_Servers")]
    assert p["features"]["activity"] == {"days_seen": 1, "observed_days": 21, "last_seen_days_ago": 20}
    assert p["risk"] != "low" and p["recommendation"] != "approve"
    assert any(r.startswith("trafic rare") for r in p["features"]["heuristics"])
    links = {link["id"]: link for link in client.get("/api/dashboard?range=30d").json()["links"]}
    assert links["Contractors|HR_Servers"]["rare"] is True
    obs = client.get("/api/status").json()["observation"]
    assert obs == {"days": 21, "recommended_days": 30, "retention_days": 30, "sufficient": False}


def test_rare_flow_of_another_pair_blocks_in_place_change(client):
    # Employees -> Print_Servers uses Printing (9100, 631); its 631 traffic is a job seen 20 days ago only.
    _ingest(client, "Employees", "Print_Servers", "TCP", 631, days_ago=20)
    _ingest(client, "Contractors", "Print_Servers", "TCP", 9100, days_ago=0)
    client.post("/api/agent/run")
    p = _props(client)[("Contractors", "Print_Servers")]
    assert (p["kind"], p["base_contract"]) == ("reuse", "Printing")
    analysis = client.post(f"/api/proposals/{p['id']}/analyse", json={"acl": "permit tcp dst eq 9100\ndeny ip"}).json()
    assert analysis["impacts"] == [{"src": "Employees", "dst": "Print_Servers", "spec": "TCP/631", "flows": 3}]
    assert not analysis["inplace_allowed"]


def test_api_messages_follow_accept_language(client):
    p = _props(client)[("Contractors", "Finance_DB")]
    en = {"Accept-Language": "en-GB,en;q=0.9,fr;q=0.5"}
    r = client.put(f"/api/proposals/{p['id']}/edit", json={"acl": "permit everything"}, headers=en)
    assert r.json() == {"detail": "The SGACL contains errors.",
                        "errors": ["Line 1: “permit everything” is not a recognised ACE."]}
    r = client.put(f"/api/proposals/{p['id']}/edit", json={"acl": "permit everything"})
    assert r.json()["detail"] == "La SGACL contient des erreurs."  # no header: French, as before
    assert client.get("/api/proposals/nope", headers=en).json()["detail"] == "Proposal not found."
    analysis = client.post(f"/api/proposals/{p['id']}/analyse", json={"acl": "permit tcp dst eq 1433"},
                           headers=en).json()
    assert analysis["validation"]["infos"] == ["No final “deny ip”: the default policy of the cell or the matrix applies."]
    client.post("/api/auth/logout")
    assert client.get("/api/status", headers=en).json()["detail"] == "Authentication required."
    assert client.post("/api/auth/login", json={"password": "x"}, headers={"Accept-Language": "en"}).json() == {
        "detail": "Incorrect password."}


def test_ise_error_status_is_localised(client, sim_url):
    cfg = client.get("/api/config").json()
    cfg["ise"]["openapi"]["password"] = "wrong"
    r = client.post("/api/config/test/ise", json={"config": cfg}, headers={"Accept-Language": "en"})
    assert r.json() == {"ok": False, "message": "OpenAPI: ISE refused the authentication (check the ERS user and its role)."}
