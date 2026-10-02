"""DuckDB storage: per-minute flow aggregates, daily rollups, proposals, audit.

Raw flow records are not kept in DuckDB. They are staged briefly, then archived to
Parquet files (``collector.parquet_dir``) every ``collector.rotate_minutes``. The
agent and the dashboard work on aggregates only.
"""

from __future__ import annotations

import csv
import json
import os
import statistics
import tempfile
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

import duckdb

SCHEMA = """
CREATE TABLE IF NOT EXISTS batch (
  ts TIMESTAMP, exporter VARCHAR, src_ip VARCHAR, src_port INTEGER, dst_ip VARCHAR, dst_port INTEGER,
  proto VARCHAR, bytes BIGINT, packets BIGINT, src_sgt VARCHAR, dst_sgt VARCHAR
);
CREATE TABLE IF NOT EXISTS raw_staging AS SELECT * FROM batch WHERE false;
CREATE TABLE IF NOT EXISTS flow_minutes (
  minute TIMESTAMP, src_sgt VARCHAR, dst_sgt VARCHAR, proto VARCHAR, port INTEGER,
  src_ip VARCHAR, dst_ip VARCHAR, flows BIGINT, bytes BIGINT, packets BIGINT
);
CREATE TABLE IF NOT EXISTS pair_daily (
  day DATE, src_sgt VARCHAR, dst_sgt VARCHAR, proto VARCHAR, port INTEGER,
  flows BIGINT, bytes BIGINT, hosts INTEGER
);
CREATE TABLE IF NOT EXISTS coverage_history (
  ts TIMESTAMP, total INTEGER, allowed INTEGER, partial INTEGER, pending INTEGER
);
CREATE TABLE IF NOT EXISTS proposals (
  id VARCHAR PRIMARY KEY, src VARCHAR, dst VARCHAR, kind VARCHAR, base_contract VARCHAR,
  base_sgacl_id VARCHAR, specs VARCHAR, proposed_acl VARCHAR, edited_acl VARCHAR,
  risk VARCHAR, recommendation VARCHAR, justification VARCHAR, features VARCHAR,
  status VARCHAR, mode VARCHAR, result VARCHAR, cell_fingerprint VARCHAR, llm_used BOOLEAN,
  created_at TIMESTAMP, updated_at TIMESTAMP, decided_at TIMESTAMP, decided_by VARCHAR
);
CREATE TABLE IF NOT EXISTS meta (k VARCHAR PRIMARY KEY, v VARCHAR);
CREATE TABLE IF NOT EXISTS audit (ts TIMESTAMP, actor VARCHAR, action VARCHAR, detail VARCHAR);
"""

DETAIL_RETENTION_DAYS = 7
PROPOSAL_JSON_FIELDS = ("specs", "features", "result")


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Store:
    def __init__(self, path: str, parquet_dir: str | None = None):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.parquet_dir = parquet_dir
        self.conn = duckdb.connect(path)
        self.lock = threading.RLock()
        with self.lock:
            self.conn.execute(SCHEMA)

    # ------------------------------------------------------------------ meta
    def get_meta(self, k: str, default: str | None = None) -> str | None:
        with self.lock:
            row = self.conn.execute("SELECT v FROM meta WHERE k = ?", [k]).fetchone()
        return row[0] if row else default

    def set_meta(self, k: str, v: str) -> None:
        with self.lock:
            self.conn.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", [k, v])

    def audit(self, actor: str, action: str, detail: dict) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT INTO audit VALUES (?, ?, ?, ?)", [utcnow(), actor, action, json.dumps(detail, default=str)]
            )

    def audit_log(self, limit: int = 100) -> list[dict]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT ts, actor, action, detail FROM audit ORDER BY ts DESC LIMIT ?", [limit]
            ).fetchall()
        return [{"ts": r[0], "actor": r[1], "action": r[2], "detail": json.loads(r[3])} for r in rows]

    # ------------------------------------------------------------------ ingest
    def ingest(self, rows: Iterable[tuple]) -> int:
        """Insert resolved flow records (columns of the ``batch`` table) and aggregate them."""
        fd, tmp = tempfile.mkstemp(suffix=".csv")
        n = 0
        with os.fdopen(fd, "w", newline="") as fh:
            w = csv.writer(fh)
            for row in rows:
                w.writerow(row)
                n += 1
        try:
            if not n:
                return 0
            with self.lock:
                self.conn.execute("DELETE FROM batch")
                self.conn.execute(
                    f"COPY batch FROM '{tmp}' (FORMAT CSV, HEADER false, TIMESTAMPFORMAT '%Y-%m-%d %H:%M:%S.%f')"
                )
                self.conn.execute(
                    """
                    INSERT INTO flow_minutes
                    SELECT date_trunc('minute', ts), src_sgt, dst_sgt, proto, dst_port, src_ip, dst_ip,
                           count(*), sum(bytes), sum(packets)
                    FROM batch GROUP BY ALL
                    """
                )
                if self.parquet_dir:
                    self.conn.execute("INSERT INTO raw_staging SELECT * FROM batch")
                last = self.conn.execute("SELECT max(ts) FROM batch").fetchone()[0]
                self.conn.execute("DELETE FROM batch")
            if last:
                self.set_meta("last_record_ts", last.isoformat())
            return n
        finally:
            os.unlink(tmp)

    def flush_parquet(self) -> str | None:
        """Archive staged raw records to a Parquet file and clear the staging table."""
        if not self.parquet_dir:
            return None
        with self.lock:
            count = self.conn.execute("SELECT count(*) FROM raw_staging").fetchone()[0]
            if not count:
                return None
            now = utcnow()
            folder = Path(self.parquet_dir) / f"date={now:%Y-%m-%d}"
            folder.mkdir(parents=True, exist_ok=True)
            target = folder / f"flows-{now:%H%M%S}-{uuid.uuid4().hex[:6]}.parquet"
            self.conn.execute(f"COPY raw_staging TO '{target}' (FORMAT PARQUET, COMPRESSION ZSTD)")
            self.conn.execute("DELETE FROM raw_staging")
        return str(target)

    def rollup_daily(self, day: datetime | None = None) -> None:
        day = (day or utcnow()).date()
        with self.lock:
            self.conn.execute("DELETE FROM pair_daily WHERE day = ?", [day])
            self.conn.execute(
                """
                INSERT INTO pair_daily
                SELECT CAST(minute AS DATE), src_sgt, dst_sgt, proto, port, sum(flows), sum(bytes),
                       count(DISTINCT src_ip)
                FROM flow_minutes WHERE CAST(minute AS DATE) = ? GROUP BY ALL
                """,
                [day],
            )

    def apply_retention(self, retention_days: int) -> None:
        now = utcnow()
        with self.lock:
            self.conn.execute(
                "DELETE FROM flow_minutes WHERE minute < ?", [now - timedelta(days=DETAIL_RETENTION_DAYS)]
            )
            self.conn.execute("DELETE FROM pair_daily WHERE day < ?", [(now - timedelta(days=retention_days)).date()])
            self.conn.execute("DELETE FROM coverage_history WHERE ts < ?", [now - timedelta(days=retention_days)])
        if self.parquet_dir and Path(self.parquet_dir).exists():
            limit = (now - timedelta(days=retention_days)).date().isoformat()
            for folder in Path(self.parquet_dir).glob("date=*"):
                if folder.name[5:] < limit:
                    for f in folder.glob("*.parquet"):
                        f.unlink()
                    folder.rmdir()

    # ------------------------------------------------------------------ queries
    def _split(self, since: datetime) -> tuple[datetime, datetime | None]:
        """Detailed minutes cover the last DETAIL_RETENTION_DAYS; older days come from pair_daily."""
        cutoff = utcnow() - timedelta(days=DETAIL_RETENTION_DAYS)
        if since >= cutoff:
            return since, None
        return cutoff, since

    def pair_ports(self, since: datetime) -> list[dict]:
        recent_from, daily_from = self._split(since)
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT src_sgt, dst_sgt, proto, port, sum(flows), sum(bytes), count(DISTINCT src_ip),
                       min(minute), max(minute)
                FROM flow_minutes WHERE minute >= ? GROUP BY ALL
                """,
                [recent_from],
            ).fetchall()
            if daily_from is not None:
                rows += self.conn.execute(
                    """
                    SELECT src_sgt, dst_sgt, proto, port, sum(flows), sum(bytes), max(hosts),
                           CAST(min(day) AS TIMESTAMP), CAST(max(day) AS TIMESTAMP)
                    FROM pair_daily WHERE day >= ? AND day < ? GROUP BY ALL
                    """,
                    [daily_from.date(), recent_from.date()],
                ).fetchall()
        merged: dict[tuple, dict] = {}
        for r in rows:
            key = (r[0], r[1], r[2], r[3])
            cur = merged.get(key)
            if cur is None:
                merged[key] = {"src": r[0], "dst": r[1], "proto": r[2], "port": r[3], "flows": int(r[4]),
                               "bytes": int(r[5]), "hosts": int(r[6]), "first_seen": r[7], "last_seen": r[8]}
            else:
                cur["flows"] += int(r[4])
                cur["bytes"] += int(r[5])
                cur["hosts"] = max(cur["hosts"], int(r[6]))
                cur["first_seen"] = min(cur["first_seen"], r[7])
                cur["last_seen"] = max(cur["last_seen"], r[8])
        return list(merged.values())

    def pair_hosts(self, since: datetime) -> dict[tuple[str, str], int]:
        recent_from, daily_from = self._split(since)
        with self.lock:
            rows = self.conn.execute(
                "SELECT src_sgt, dst_sgt, count(DISTINCT src_ip) FROM flow_minutes WHERE minute >= ? GROUP BY ALL",
                [recent_from],
            ).fetchall()
            if daily_from is not None:
                rows += self.conn.execute(
                    "SELECT src_sgt, dst_sgt, max(hosts) FROM pair_daily WHERE day >= ? AND day < ? GROUP BY ALL",
                    [daily_from.date(), recent_from.date()],
                ).fetchall()
        out: dict[tuple[str, str], int] = {}
        for src, dst, n in rows:
            out[(src, dst)] = max(out.get((src, dst), 0), int(n))
        return out

    def first_seen(self) -> dict[tuple[str, str], datetime]:
        with self.lock:
            minutes = self.conn.execute("SELECT src_sgt, dst_sgt, min(minute) FROM flow_minutes GROUP BY ALL").fetchall()
            days = self.conn.execute("SELECT src_sgt, dst_sgt, min(day) FROM pair_daily GROUP BY ALL").fetchall()
        out: dict[tuple[str, str], datetime] = {(r[0], r[1]): r[2] for r in minutes}
        for src, dst, day in days:
            cur = out.get((src, dst))
            if cur is None or day < cur.date():
                out[(src, dst)] = datetime(day.year, day.month, day.day)
        return out

    def pair_behaviour(self, src: str, dst: str, since: datetime) -> dict:
        """Deterministic features used for risk scoring. Contains no IP address."""
        with self.lock:
            hours = self.conn.execute(
                """
                SELECT hour(minute) AS h, isodow(minute) AS d, sum(flows)
                FROM flow_minutes WHERE src_sgt = ? AND dst_sgt = ? AND minute >= ? GROUP BY ALL
                """,
                [src, dst, since],
            ).fetchall()
            series = self.conn.execute(
                """
                SELECT src_ip, dst_ip, list(epoch(minute) ORDER BY minute)
                FROM (SELECT DISTINCT src_ip, dst_ip, minute FROM flow_minutes
                      WHERE src_sgt = ? AND dst_sgt = ? AND minute >= ?)
                GROUP BY ALL
                """,
                [src, dst, since],
            ).fetchall()
        total = sum(r[2] for r in hours) or 1
        off = sum(r[2] for r in hours if r[0] < 7 or r[0] >= 20 or r[1] >= 6)
        periodic = 0
        intervals_s: list[float] = []
        for _, _, minutes in series:
            if len(minutes) < 6:
                continue
            gaps = [b - a for a, b in zip(minutes, minutes[1:])]
            mean = statistics.mean(gaps)
            if mean >= 120 and statistics.pstdev(gaps) / mean < 0.15:
                periodic += 1
                intervals_s.append(mean)
        return {
            "off_hours_ratio": round(off / total, 2),
            "periodic_host_pairs": periodic,
            "host_pairs": len(series),
            "periodic_interval_s": round(statistics.median(intervals_s)) if intervals_s else None,
        }

    def last_record_ts(self) -> datetime | None:
        v = self.get_meta("last_record_ts")
        return datetime.fromisoformat(v) if v else None

    def flow_rate(self, minutes: int = 5) -> float:
        with self.lock:
            row = self.conn.execute(
                "SELECT sum(flows) FROM flow_minutes WHERE minute >= ?", [utcnow() - timedelta(minutes=minutes)]
            ).fetchone()
        return round((row[0] or 0) / (minutes * 60), 1)

    # ------------------------------------------------------------------ coverage history
    def record_coverage(self, total: int, allowed: int, partial: int, pending: int) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT INTO coverage_history VALUES (?, ?, ?, ?, ?)", [utcnow(), total, allowed, partial, pending]
            )

    def coverage_trend(self, since: datetime, buckets: int = 30) -> list[dict]:
        span = max((utcnow() - since).total_seconds() / buckets, 60)
        with self.lock:
            rows = self.conn.execute(
                f"""
                SELECT floor(epoch(ts) / {span}) * {span} AS b, arg_max(partial + pending, ts)
                FROM coverage_history WHERE ts >= ? GROUP BY b ORDER BY b
                """,
                [since],
            ).fetchall()
        return [
            {"ts": datetime.fromtimestamp(float(r[0]), tz=timezone.utc).replace(tzinfo=None).isoformat(),
             "uncovered": int(r[1])}
            for r in rows
        ]

    # ------------------------------------------------------------------ proposals
    def _row_to_proposal(self, cols: list[str], row: tuple) -> dict:
        d = dict(zip(cols, row))
        for f in PROPOSAL_JSON_FIELDS:
            d[f] = json.loads(d[f]) if d.get(f) else None
        return d

    def proposals(self, status: str | None = None) -> list[dict]:
        sql = "SELECT * FROM proposals"
        params: list[Any] = []
        if status:
            sql += " WHERE status = ?"
            params.append(status)
        with self.lock:
            cur = self.conn.execute(sql + " ORDER BY created_at", params)
            cols = [c[0] for c in cur.description]
            rows = cur.fetchall()
        return [self._row_to_proposal(cols, r) for r in rows]

    def proposal(self, pid: str) -> dict | None:
        with self.lock:
            cur = self.conn.execute("SELECT * FROM proposals WHERE id = ?", [pid])
            cols = [c[0] for c in cur.description]
            row = cur.fetchone()
        return self._row_to_proposal(cols, row) if row else None

    def open_proposal_for(self, src: str, dst: str) -> dict | None:
        with self.lock:
            cur = self.conn.execute(
                "SELECT * FROM proposals WHERE src = ? AND dst = ? AND status = 'pending'", [src, dst]
            )
            cols = [c[0] for c in cur.description]
            row = cur.fetchone()
        return self._row_to_proposal(cols, row) if row else None

    def last_decision_for(self, src: str, dst: str) -> dict | None:
        with self.lock:
            cur = self.conn.execute(
                "SELECT * FROM proposals WHERE src = ? AND dst = ? AND status IN ('approved', 'rejected') "
                "ORDER BY decided_at DESC LIMIT 1",
                [src, dst],
            )
            cols = [c[0] for c in cur.description]
            row = cur.fetchone()
        return self._row_to_proposal(cols, row) if row else None

    def save_proposal(self, p: dict) -> dict:
        p = dict(p)
        p.setdefault("id", uuid.uuid4().hex[:12])
        now = utcnow()
        p.setdefault("created_at", now)
        p["updated_at"] = now
        cols = [
            "id", "src", "dst", "kind", "base_contract", "base_sgacl_id", "specs", "proposed_acl", "edited_acl",
            "risk", "recommendation", "justification", "features", "status", "mode", "result",
            "cell_fingerprint", "llm_used", "created_at", "updated_at", "decided_at", "decided_by",
        ]
        values = [json.dumps(p.get(c), default=str) if c in PROPOSAL_JSON_FIELDS else p.get(c) for c in cols]
        with self.lock:
            self.conn.execute(
                f"INSERT OR REPLACE INTO proposals ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})", values
            )
        return self.proposal(p["id"])

    def close(self) -> None:
        with self.lock:
            self.conn.close()
