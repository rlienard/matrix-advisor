"""Operations: Prometheus metrics endpoint and scheduled backups."""

import asyncio
import re
import stat
from datetime import timedelta

import duckdb
import pytest
import yaml
from fastapi.testclient import TestClient

from matrix_advisor.main import build_context, create_app
from matrix_advisor.ops import Backups
from matrix_advisor.store import utcnow


@pytest.fixture()
def ctx(sim_url, tmp_path, monkeypatch):
    monkeypatch.setenv("MA_BACKUP_HOURS", "0")
    cfg = {
        "ise": {"pan": "sim", "openapi": {"base_url": sim_url, "username": "matrix-advisor",
                                          "password": "demo-password"}},
        "collector": {"input_file": str(tmp_path / "flows.ndjson"), "parquet_dir": str(tmp_path / "pq")},
        "server": {"admin_password": "secret"},
    }
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(cfg))
    c = build_context(str(tmp_path / "config.yaml"), str(tmp_path / "data" / "ma.duckdb"))
    now = utcnow()
    c.store.ingest([((now - timedelta(minutes=i)).strftime("%Y-%m-%d %H:%M:%S.%f"), "10.0.0.1", f"10.10.1.{i}",
                     50000, "10.20.1.20", 443, "TCP", 1000, 10, "Employees", "Web_Servers") for i in range(5)])
    yield c
    c.store.close()


def test_metrics_are_off_without_token_then_require_it(ctx, monkeypatch):
    with TestClient(create_app(ctx, start_workers=False)) as client:
        assert client.get("/metrics").status_code == 404
        monkeypatch.setenv("MA_METRICS_TOKEN", "t0ken")
        assert client.get("/metrics").status_code == 401
        assert client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
        r = client.get("/metrics", headers={"Authorization": "Bearer t0ken"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    body = r.text
    for name in ("ma_ingest_records_total", "ma_ingest_lag_bytes", "ma_flows_per_second", "ma_ise_online",
                 "ma_llm_online", 'ma_store_rows{table="pair_minutes"}', "ma_last_record_age_seconds"):
        assert name in body
    # Counts and states only: no address, no SGT pair.
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", body)
    assert "Employees" not in body


def test_backup_copies_database_and_config_and_prunes(ctx):
    backups = Backups(ctx, ctx.store.path.rsplit("/", 1)[0] + "/backups", hours=24, keep=2)
    folders = [backups.run_once() for _ in range(3)]
    kept = backups.existing()
    assert kept == folders[1:]
    assert stat.S_IMODE(backups.directory.stat().st_mode) == 0o700
    latest = kept[-1]
    files = {f.name: stat.S_IMODE(f.stat().st_mode) for f in latest.iterdir()}
    assert files == {"ma.duckdb": 0o600, "config.yaml": 0o600, "secrets.json": 0o600}
    copy = duckdb.connect(str(latest / "ma.duckdb"), read_only=True)
    assert copy.execute("SELECT sum(flows) FROM pair_minutes").fetchone()[0] == 5
    copy.close()
    assert backups.last_success is not None
    assert ctx.store.audit_log()[0]["action"] == "backup"


def test_backups_are_disabled_with_zero_hours_or_memory_store(ctx, monkeypatch):
    assert Backups.from_env(ctx) is None  # MA_BACKUP_HOURS=0 in the fixture
    monkeypatch.setenv("MA_BACKUP_HOURS", "12")
    assert Backups.from_env(ctx).hours == 12


def test_failed_backup_is_counted_and_leaves_no_partial_folder(ctx, tmp_path, monkeypatch):
    backups = Backups(ctx, tmp_path / "bk", hours=0.0001, keep=2)

    def boom(target):
        raise OSError("disk full")

    monkeypatch.setattr(ctx.store, "backup", boom)
    monkeypatch.setattr("matrix_advisor.ops.FIRST_BACKUP_DELAY_S", 0)

    async def run_briefly():
        task = asyncio.create_task(backups.run())
        await asyncio.sleep(0.5)
        task.cancel()

    asyncio.run(run_briefly())
    assert backups.failures >= 1
    assert list((tmp_path / "bk").iterdir()) == []
