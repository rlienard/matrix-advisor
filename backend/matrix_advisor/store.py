"""DuckDB storage: per-minute flow aggregates, daily rollups, proposals, audit.

Raw flow records are not kept in DuckDB. They are staged briefly, then archived to
Parquet files (``collector.parquet_dir``) every ``collector.rotate_minutes``. The
agent and the dashboard work on aggregates only.

Aggregates are split by what reads them, so that the scans made on every advisor run and
dashboard load do not grow with the number of hosts:
- ``pair_minutes``: per minute and (SGT pair, protocol, port), no address. Flows, timing, activity.
- ``host_daily``: per day and (SGT pair, protocol, port), the source addresses seen. Host counts.
- ``host_minutes``: per minute and SGT pair, the (source, destination) address pairs seen, for the
  last half hour or so only: ``compact`` folds older minutes into ``host_pair_daily``.
- ``host_pair_daily``: per day and address pair, the statistics of the gaps between the minutes the
  pair was active (count, sum, sum of squares). Read for one SGT pair at a time to detect periodic
  (beaconing) behaviour, with the same result as from the minutes themselves, at one row per address
  pair and day instead of one per active minute.
Each ingest batch appends rows; ``compact`` merges the rows of the same key written by
successive batches.
"""

from __future__ import annotations

import csv
import itertools
import json
import math
import os
import statistics
import tempfile
import threading
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, time, timedelta
from pathlib import Path
from typing import Any

import duckdb

SCHEMA = """
CREATE TABLE IF NOT EXISTS batch (
  ts TIMESTAMP, exporter VARCHAR, src_ip VARCHAR, src_port INTEGER, dst_ip VARCHAR, dst_port INTEGER,
  proto VARCHAR, bytes BIGINT, packets BIGINT, src_sgt VARCHAR, dst_sgt VARCHAR
);
CREATE TABLE IF NOT EXISTS raw_staging AS SELECT * FROM batch WHERE false;
CREATE TABLE IF NOT EXISTS pair_minutes (
  minute TIMESTAMP, src_sgt VARCHAR, dst_sgt VARCHAR, proto VARCHAR, port INTEGER,
  flows BIGINT, bytes BIGINT, packets BIGINT
);
CREATE TABLE IF NOT EXISTS host_daily (
  day DATE, src_sgt VARCHAR, dst_sgt VARCHAR, proto VARCHAR, port INTEGER, src_ip VARCHAR, flows BIGINT
);
CREATE TABLE IF NOT EXISTS host_minutes (
  minute TIMESTAMP, src_sgt VARCHAR, dst_sgt VARCHAR, src_ip VARCHAR, dst_ip VARCHAR
);
CREATE TABLE IF NOT EXISTS host_pair_daily (
  day DATE, src_sgt VARCHAR, dst_sgt VARCHAR, src_ip VARCHAR, dst_ip VARCHAR,
  first_minute TIMESTAMP, last_minute TIMESTAMP, minutes BIGINT, gap_sum DOUBLE, gap_sq DOUBLE
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
COMPACT_WINDOW = timedelta(minutes=30)
# Minutes older than this are folded into host_pair_daily; flows arriving later than that for an
# address pair already folded past are left out of the periodicity statistics (not of the counts).
FOLD_LAG = timedelta(minutes=30)
HOST_PAIR_KEY = "day, src_sgt, dst_sgt, src_ip, dst_ip"

# Aggregates of one ingest batch (the ``batch`` table), and the same tables built from the
# per-minute table of earlier versions (``flow_minutes``, one row per address pair and minute).
_AGGREGATE = {
    "pair_minutes": "SELECT date_trunc('minute', ts), src_sgt, dst_sgt, proto, dst_port, count(*), sum(bytes), "
                    "sum(packets) FROM batch GROUP BY ALL",
    "host_daily": "SELECT CAST(ts AS DATE), src_sgt, dst_sgt, proto, dst_port, src_ip, count(*) FROM batch GROUP BY ALL",
    "host_minutes": "SELECT DISTINCT date_trunc('minute', ts), src_sgt, dst_sgt, src_ip, dst_ip FROM batch",
}
_MIGRATE = {
    "pair_minutes": "SELECT minute, src_sgt, dst_sgt, proto, port, sum(flows), sum(bytes), sum(packets) "
                    "FROM flow_minutes GROUP BY ALL",
    "host_daily": "SELECT CAST(minute AS DATE), src_sgt, dst_sgt, proto, port, src_ip, sum(flows) "
                  "FROM flow_minutes GROUP BY ALL",
    "host_minutes": "SELECT DISTINCT minute, src_sgt, dst_sgt, src_ip, dst_ip FROM flow_minutes",
}
# Merge rows of the same key written by successive batches, from ``since`` (a minute, or a day).
_COMPACT = {
    "pair_minutes": ("minute", ("SELECT minute, src_sgt, dst_sgt, proto, port, sum(flows), sum(bytes), sum(packets) "
                                "FROM pair_minutes WHERE minute >= ? GROUP BY ALL")),
    "host_daily": ("day", ("SELECT day, src_sgt, dst_sgt, proto, port, src_ip, sum(flows) "
                           "FROM host_daily WHERE day >= ? GROUP BY ALL")),
    "host_minutes": ("minute", "SELECT DISTINCT * FROM host_minutes WHERE minute >= ?"),
}
PROPOSAL_JSON_FIELDS = ("specs", "features", "result")


@dataclass(frozen=True)
class GapStats:
    """Active minutes of an address pair (epoch seconds) summarised by the gaps between them."""

    first: float
    last: float
    minutes: int
    gap_sum: float
    gap_sq: float

    @classmethod
    def of(cls, minutes: list[float]) -> GapStats:
        gaps = [b - a for a, b in itertools.pairwise(minutes)]
        return cls(minutes[0], minutes[-1], len(minutes), sum(gaps), sum(g * g for g in gaps))

    @staticmethod
    def join(a: GapStats | None, b: GapStats) -> GapStats:
        """``b`` follows ``a`` in time: one more gap between the two."""
        if a is None:
            return b
        cross = b.first - a.last
        return GapStats(a.first, b.last, a.minutes + b.minutes, a.gap_sum + b.gap_sum + cross,
                        a.gap_sq + b.gap_sq + cross * cross)

    def mean_pstdev(self) -> tuple[float, float]:
        n = self.minutes - 1
        mean = self.gap_sum / n
        return mean, math.sqrt(max(self.gap_sq / n - mean * mean, 0.0))


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


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
            self._migrate()

    def _migrate(self) -> None:
        """Rebuild the split aggregates from the single per-minute table of earlier versions."""
        legacy = self.conn.execute(
            "SELECT count(*) FROM information_schema.tables WHERE table_name = 'flow_minutes'"
        ).fetchone()[0]
        if not legacy:
            return
        self.conn.execute("BEGIN TRANSACTION")
        try:
            for table, sql in _MIGRATE.items():
                self.conn.execute(f"INSERT INTO {table} {sql}")
            self.conn.execute("DROP TABLE flow_minutes")
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

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
                for table, sql in _AGGREGATE.items():
                    self.conn.execute(f"INSERT INTO {table} {sql}")
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
                SELECT f.day, f.src_sgt, f.dst_sgt, f.proto, f.port, f.flows, f.bytes, coalesce(h.hosts, 0)
                FROM (SELECT CAST(minute AS DATE) AS day, src_sgt, dst_sgt, proto, port, sum(flows) AS flows,
                             sum(bytes) AS bytes
                      FROM pair_minutes WHERE minute >= ? AND minute < ? GROUP BY ALL) f
                LEFT JOIN (SELECT src_sgt, dst_sgt, proto, port, count(DISTINCT src_ip) AS hosts
                           FROM host_daily WHERE day = ? GROUP BY ALL) h
                USING (src_sgt, dst_sgt, proto, port)
                """,
                [datetime.combine(day, time()), datetime.combine(day + timedelta(days=1), time()), day],
            )

    def compact(self, now: datetime | None = None) -> None:
        """Merge the rows that successive ingest batches wrote for the same key (recent rows only)."""
        since = (now or utcnow()) - COMPACT_WINDOW
        with self.lock:
            self.conn.execute("BEGIN TRANSACTION")
            try:
                for table, (column, sql) in _COMPACT.items():
                    start = since.date() if column == "day" else since
                    self.conn.execute(f"CREATE OR REPLACE TEMP TABLE compacted AS {sql}", [start])
                    self.conn.execute(f"DELETE FROM {table} WHERE {column} >= ?", [start])
                    self.conn.execute(f"INSERT INTO {table} SELECT * FROM compacted")
                self.conn.execute("DROP TABLE compacted")
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise
        self.fold_host_minutes(now)

    def _folded_until(self) -> datetime:
        done = self.get_meta("host_minutes_folded_until")
        return datetime.fromisoformat(done) if done else datetime.fromtimestamp(0, UTC).replace(tzinfo=None)

    def fold_host_minutes(self, now: datetime | None = None) -> int:
        """Fold host_minutes older than FOLD_LAG into host_pair_daily. Returns the minutes folded."""
        upto = ((now or utcnow()) - FOLD_LAG).replace(second=0, microsecond=0)
        with self.lock:
            start = self._folded_until()
            if upto <= start:
                return 0
            self.conn.execute("BEGIN TRANSACTION")
            try:
                # Each address pair's active minutes of the chunk, by day: count, gaps and squared gaps.
                self.conn.execute(
                    f"""
                    CREATE OR REPLACE TEMP TABLE chunk AS
                    WITH m AS (SELECT DISTINCT CAST(minute AS DATE) AS day, src_sgt, dst_sgt, src_ip, dst_ip, minute
                               FROM host_minutes WHERE minute >= ? AND minute < ?),
                         g AS (SELECT *, epoch(minute) - epoch(lag(minute) OVER (
                                   PARTITION BY {HOST_PAIR_KEY} ORDER BY minute)) AS gap FROM m)
                    SELECT {HOST_PAIR_KEY}, min(minute) AS first_minute, max(minute) AS last_minute,
                           count(*) AS minutes, coalesce(sum(gap), 0) AS gap_sum, coalesce(sum(gap * gap), 0) AS gap_sq
                    FROM g GROUP BY ALL
                    """,
                    [start, upto],
                )
                # Appended to what the day already holds: the chunk starts after everything folded before,
                # so the only new gap is the one between the two.
                self.conn.execute(
                    f"""
                    CREATE OR REPLACE TEMP TABLE merged AS
                    SELECT {", ".join("c." + k for k in HOST_PAIR_KEY.split(", "))},
                           coalesce(o.first_minute, c.first_minute), c.last_minute,
                           coalesce(o.minutes, 0) + c.minutes,
                           coalesce(o.gap_sum, 0) + c.gap_sum + coalesce(epoch(c.first_minute) - epoch(o.last_minute), 0),
                           coalesce(o.gap_sq, 0) + c.gap_sq
                               + coalesce(pow(epoch(c.first_minute) - epoch(o.last_minute), 2), 0)
                    FROM chunk c LEFT JOIN host_pair_daily o USING ({HOST_PAIR_KEY})
                    """
                )
                self.conn.execute(
                    "DELETE FROM host_pair_daily h USING chunk c WHERE "
                    + " AND ".join(f"h.{k} = c.{k}" for k in HOST_PAIR_KEY.split(", "))
                )
                self.conn.execute("INSERT INTO host_pair_daily SELECT * FROM merged")
                folded = self.conn.execute("SELECT coalesce(sum(minutes), 0) FROM chunk").fetchone()[0]
                self.conn.execute("DELETE FROM host_minutes WHERE minute < ?", [upto])
                self.conn.execute("DROP TABLE chunk")
                self.conn.execute("DROP TABLE merged")
                self.set_meta("host_minutes_folded_until", upto.isoformat())
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise
        return int(folded)

    def apply_retention(self, retention_days: int) -> None:
        now = utcnow()
        with self.lock:
            detail = now - timedelta(days=DETAIL_RETENTION_DAYS)
            for table in ("pair_minutes", "host_minutes"):
                self.conn.execute(f"DELETE FROM {table} WHERE minute < ?", [detail])
            for table in ("host_daily", "host_pair_daily"):
                self.conn.execute(f"DELETE FROM {table} WHERE day < ?", [detail.date()])
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
                SELECT f.src_sgt, f.dst_sgt, f.proto, f.port, f.flows, f.bytes, coalesce(h.hosts, 0), f.first, f.last
                FROM (SELECT src_sgt, dst_sgt, proto, port, sum(flows) AS flows, sum(bytes) AS bytes,
                             min(minute) AS first, max(minute) AS last
                      FROM pair_minutes WHERE minute >= ? GROUP BY ALL) f
                LEFT JOIN (SELECT src_sgt, dst_sgt, proto, port, count(DISTINCT src_ip) AS hosts
                           FROM host_daily WHERE day >= ? GROUP BY ALL) h
                USING (src_sgt, dst_sgt, proto, port)
                """,
                [recent_from, recent_from.date()],
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
                "SELECT src_sgt, dst_sgt, count(DISTINCT src_ip) FROM host_daily WHERE day >= ? GROUP BY ALL",
                [recent_from.date()],
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
            minutes = self.conn.execute("SELECT src_sgt, dst_sgt, min(minute) FROM pair_minutes GROUP BY ALL").fetchall()
            days = self.conn.execute("SELECT src_sgt, dst_sgt, min(day) FROM pair_daily GROUP BY ALL").fetchall()
        out: dict[tuple[str, str], datetime] = {(r[0], r[1]): r[2] for r in minutes}
        for src, dst, day in days:
            cur = out.get((src, dst))
            if cur is None or day < cur.date():
                out[(src, dst)] = datetime.combine(day, time())
        return out

    def pair_activity(self, since: datetime) -> dict[tuple[str, str], dict]:
        """Per SGT pair: number of distinct days with traffic since ``since``, and the last one."""
        recent_from, daily_from = self._split(since)
        with self.lock:
            rows = self.conn.execute(
                "SELECT DISTINCT src_sgt, dst_sgt, CAST(minute AS DATE) FROM pair_minutes WHERE minute >= ?",
                [recent_from],
            ).fetchall()
            if daily_from is not None:
                rows += self.conn.execute(
                    "SELECT DISTINCT src_sgt, dst_sgt, day FROM pair_daily WHERE day >= ? AND day < ?",
                    [daily_from.date(), recent_from.date()],
                ).fetchall()
        days: dict[tuple[str, str], set] = {}
        for src, dst, day in rows:
            days.setdefault((src, dst), set()).add(day)
        return {k: {"days_seen": len(v), "last_day": max(v)} for k, v in days.items()}

    def observation_start(self) -> datetime | None:
        """Oldest traffic still held (detailed minutes or daily rollups)."""
        with self.lock:
            minute = self.conn.execute("SELECT min(minute) FROM pair_minutes").fetchone()[0]
            day = self.conn.execute("SELECT min(day) FROM pair_daily").fetchone()[0]
        candidates = [x for x in (minute, datetime.combine(day, time()) if day else None) if x is not None]
        return min(candidates) if candidates else None

    def pair_behaviour(self, src: str, dst: str, since: datetime) -> dict:
        """Deterministic features used for risk scoring. Contains no IP address."""
        with self.lock:
            hours = self.conn.execute(
                """
                SELECT hour(minute) AS h, isodow(minute) AS d, sum(flows)
                FROM pair_minutes WHERE src_sgt = ? AND dst_sgt = ? AND minute >= ? GROUP BY ALL
                """,
                [src, dst, since],
            ).fetchall()
            folded_until = self._folded_until()
            # Folded days (whole days since ``since``), then the minutes not folded yet, in time order.
            days = self.conn.execute(
                """
                SELECT src_ip, dst_ip, epoch(first_minute), epoch(last_minute), minutes, gap_sum, gap_sq
                FROM host_pair_daily WHERE src_sgt = ? AND dst_sgt = ? AND day >= ? ORDER BY day
                """,
                [src, dst, since.date()],
            ).fetchall()
            recent = self.conn.execute(
                """
                SELECT src_ip, dst_ip, list(epoch(minute) ORDER BY minute)
                FROM (SELECT DISTINCT src_ip, dst_ip, minute FROM host_minutes
                      WHERE src_sgt = ? AND dst_sgt = ? AND minute >= ?)
                GROUP BY ALL
                """,
                [src, dst, max(since, folded_until)],
            ).fetchall()
        series: dict[tuple[str, str], GapStats] = {}
        for s_ip, d_ip, *stats in days:
            series[(s_ip, d_ip)] = GapStats.join(series.get((s_ip, d_ip)), GapStats(*stats))
        for s_ip, d_ip, minutes in recent:
            series[(s_ip, d_ip)] = GapStats.join(series.get((s_ip, d_ip)), GapStats.of(minutes))
        total = sum(r[2] for r in hours) or 1
        off = sum(r[2] for r in hours if r[0] < 7 or r[0] >= 20 or r[1] >= 6)
        periodic = 0
        intervals_s: list[float] = []
        for g in series.values():
            if g.minutes < 6:
                continue
            mean, pstdev = g.mean_pstdev()
            if mean >= 120 and pstdev / mean < 0.15:
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
                "SELECT sum(flows) FROM pair_minutes WHERE minute >= ?", [utcnow() - timedelta(minutes=minutes)]
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
            {"ts": datetime.fromtimestamp(float(r[0]), tz=UTC).replace(tzinfo=None).isoformat(),
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

    def save_proposal_if_unchanged(self, p: dict, updated_at) -> dict | None:
        """Save ``p`` only if the stored proposal was not modified since ``updated_at`` (else None)."""
        with self.lock:
            current = self.proposal(p["id"])
            if current is None or current["updated_at"] != updated_at:
                return None
            return self.save_proposal(p)

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
