"""Operations: Prometheus metrics and scheduled backups.

Both are configured with environment variables, like the other deployment settings (``MA_PORT``,
``MA_LOG_LEVEL``), not from the UI:
- ``MA_METRICS_TOKEN``: enables ``GET /metrics`` (Prometheus text format), which then requires
  ``Authorization: Bearer <token>``. Without it the endpoint does not exist.
- ``MA_BACKUP_HOURS`` (default 24, 0 disables), ``MA_BACKUP_KEEP`` (default 7), ``MA_BACKUP_DIR``
  (default ``backups`` next to the DuckDB file): a backup folder holds a copy of the database, the
  configuration and ``secrets.json``, readable by the owner only.

Metrics carry counts, durations and states only: no IP address, SGT pair or secret.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from .store import utcnow

if TYPE_CHECKING:
    from .main import Context

log = logging.getLogger(__name__)

BACKUP_PREFIX = "backup-"
FIRST_BACKUP_DELAY_S = 600


def _age(ts: datetime | None) -> float | None:
    return None if ts is None else round((utcnow() - ts).total_seconds(), 1)


class Metrics:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def add(self, name: str, kind: str, help_: str, value, labels: dict[str, str] | None = None) -> None:
        if not any(line.startswith(f"# TYPE {name} ") for line in self.lines):
            self.lines += [f"# HELP {name} {help_}", f"# TYPE {name} {kind}"]
        if value is None:
            return
        label = "{" + ",".join(f'{k}="{v}"' for k, v in labels.items()) + "}" if labels else ""
        self.lines.append(f"{name}{label} {float(value):g}")

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def metrics_text(ctx: Context, backups: Backups | None = None) -> str:
    m = Metrics()
    p = ctx.pipeline
    for key, help_ in (("records", "Flow records stored"), ("malformed", "Unparsable flow records"),
                       ("dropped_exporter", "Records from exporters outside allowed_exporters"),
                       ("concatenated_lines", "GoFlow2 lines holding several records"),
                       ("sgt_from_flow", "Flow sides attributed from the SGT exported in the record"),
                       ("unknown_tag", "Exported SGT values unknown to ISE")):
        m.add(f"ma_ingest_{key}_total", "counter", help_, p.stats.get(key, 0))
    m.add("ma_ingest_lag_bytes", "gauge", "GoFlow2 output not read yet", p.lag_bytes())
    m.add("ma_ingest_tick_seconds", "gauge", "Duration of the last ingest tick", p.last_tick_s)
    m.add("ma_flows_per_second", "gauge", "Flows stored per second over the last 5 minutes", ctx.store.flow_rate())
    m.add("ma_last_record_age_seconds", "gauge", "Age of the newest flow record", _age(ctx.store.last_record_ts()))

    a = ctx.advisor
    m.add("ma_advisor_run_seconds", "gauge", "Duration of the last advisor run", a.last_duration_s)
    m.add("ma_advisor_last_run_age_seconds", "gauge", "Time since the last advisor run", _age(a.last_run))
    for status, n in sorted(ctx.store.proposal_counts().items()):
        m.add("ma_proposals", "gauge", "Proposals by status", n, {"status": status})

    ise = ctx.ise.summary()
    m.add("ma_ise_online", "gauge", "ISE ERS/OpenAPI reachable at the last reconciliation", int(bool(ise["online"])))
    m.add("ma_ise_last_sync_age_seconds", "gauge", "Time since the last full matrix read", _age(ise["last_sync"]))
    m.add("ma_ise_reconcile_seconds", "gauge", "Duration of the last full matrix read", ise.get("last_duration_s"))
    for key in ("sgt", "sgacl", "cell"):
        m.add(f"ma_ise_{key}s", "gauge", f"{key.upper()} objects in the matrix cache", ise[f"{key}_count"])
    px = ise["pxgrid"]
    configured = px.get("state") != "not configured"
    m.add("ma_pxgrid_configured", "gauge", "pxGrid configured", int(configured))
    m.add("ma_pxgrid_online", "gauge", "pxGrid context loaded and no error since",
          int(configured and px.get("last_update") is not None and not px.get("error")))
    m.add("ma_pxgrid_websocket", "gauge", "1 when following the pxGrid websocket, 0 when polling",
          int(px.get("mode") == "websocket"))
    for key, n in ise["resolver"].items():
        m.add("ma_resolver_entries", "gauge", "IP to SGT resolver entries", n, {"source": key})

    llm = ctx.llm.status
    m.add("ma_llm_online", "gauge", "LLM answered the last call", int(bool(llm.get("online"))))
    latency = llm.get("latency_ms")
    m.add("ma_llm_latency_seconds", "gauge", "LLM latency at the last health check",
          None if latency is None else latency / 1000)

    for table, n in sorted(ctx.store.table_rows().items()):
        m.add("ma_store_rows", "gauge", "Rows per table (estimate)", n, {"table": table})
    if ctx.store.path != ":memory:" and os.path.exists(ctx.store.path):
        m.add("ma_store_file_bytes", "gauge", "Size of the DuckDB file", os.path.getsize(ctx.store.path))
    if backups is not None:
        m.add("ma_backup_last_success_timestamp_seconds", "gauge", "Unix time of the last successful backup",
              backups.last_success)
        m.add("ma_backup_failures_total", "counter", "Failed backups", backups.failures)
    return m.text()


class Backups:
    def __init__(self, ctx: Context, directory: str | Path, hours: float, keep: int):
        self.ctx = ctx
        self.directory = Path(directory)
        self.hours = hours
        self.keep = max(keep, 1)
        self.failures = 0
        self.last_success: float | None = None
        existing = self.existing()
        if existing:
            self.last_success = existing[-1].stat().st_mtime

    @classmethod
    def from_env(cls, ctx: Context) -> Backups | None:
        hours = float(os.environ.get("MA_BACKUP_HOURS", "24") or 0)
        if hours <= 0 or ctx.store.path == ":memory:":
            return None
        default = Path(ctx.store.path).parent / "backups"
        return cls(ctx, os.environ.get("MA_BACKUP_DIR") or default, hours,
                   int(os.environ.get("MA_BACKUP_KEEP", "7") or 7))

    def existing(self) -> list[Path]:
        if not self.directory.is_dir():
            return []
        return sorted(p for p in self.directory.iterdir() if p.is_dir() and p.name.startswith(BACKUP_PREFIX))

    def run_once(self) -> Path:
        """Write one backup folder (database, configuration, secrets) and prune the oldest ones."""
        self.directory.mkdir(parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        target = self.directory / f"{BACKUP_PREFIX}{utcnow():%Y%m%d-%H%M%S-%f}"
        partial = target.with_name(target.name + ".partial")
        shutil.rmtree(partial, ignore_errors=True)
        partial.mkdir(mode=0o700)
        try:
            self.ctx.store.backup(partial / Path(self.ctx.store.path).name)
            config = self.ctx.config
            for src in (config.path, config.secrets_path):
                if src.exists():
                    shutil.copy2(src, partial / src.name)
            for f in partial.iterdir():
                os.chmod(f, 0o600)
            partial.rename(target)
        except Exception:
            shutil.rmtree(partial, ignore_errors=True)
            raise
        for old in self.existing()[:-self.keep]:
            shutil.rmtree(old, ignore_errors=True)
        self.last_success = time.time()
        self.ctx.store.audit("system", "backup", {"folder": target.name})
        log.info("backup written to %s", target)
        return target

    async def run(self) -> None:
        interval = self.hours * 3600
        due = (self.last_success or 0) + interval - time.time()
        await asyncio.sleep(max(due, FIRST_BACKUP_DELAY_S if self.last_success is None else 0))
        while True:
            try:
                await asyncio.to_thread(self.run_once)
            except Exception:  # keep the loop alive, report via logs and metrics
                self.failures += 1
                log.exception("backup failed")
            await asyncio.sleep(interval)
