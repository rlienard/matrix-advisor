"""Ingestion loop: GoFlow2 NDJSON -> oriented flows -> SGT resolution -> DuckDB aggregates."""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import timedelta

from ..config import ConfigStore
from ..store import Store, utcnow
from .goflow import ExporterFilter, NDJSONTailer, decode_records, flow_from_record
from .resolver import SGTResolver

log = logging.getLogger(__name__)

INGEST_EVERY_S = 5
CONTEXT_WAIT_S = 180


class IngestPipeline:
    def __init__(self, config: ConfigStore, store: Store, resolver: SGTResolver, ready=None):
        self.config = config
        # Callable telling whether the ISE SGT table and endpoint context (pxGrid) are loaded. Until
        # then flows stay in the GoFlow2 file, so that they are not attributed to "Unknown" for good.
        self.ready = ready or (lambda: True)
        self._started = time.monotonic()
        self.store = store
        self.resolver = resolver
        self._tailer: NDJSONTailer | None = None
        self._filter: ExporterFilter | None = None
        self._last_flush = time.monotonic()
        self._last_rollup = 0.0
        self._last_retention = 0.0
        self.last_tick_s: float | None = None
        self.stats = {
            "records": 0, "dropped_exporter": 0, "malformed": 0, "concatenated_lines": 0,
            "sgt_from_flow": 0, "unknown_tag": 0,
        }
        config.on_change(lambda old, new: self._reset())
        self._reset()

    def _reset(self) -> None:
        c = self.config.settings.collector
        if self._tailer is None or self._tailer.path != c.input_file:
            self._tailer = NDJSONTailer(c.input_file)
        self._filter = ExporterFilter(c.allowed_exporters)
        self.resolver.set_static(self.config.settings.ise.static_bindings)

    def tick(self) -> int:
        if not self.ready() and time.monotonic() - self._started < CONTEXT_WAIT_S:
            return 0
        started = time.monotonic()
        lines = self._tailer.read()
        use_tags = self.config.settings.collector.sgt_source == "auto"
        rows = []
        for line in lines:
            records, bad = decode_records(line)
            self.stats["malformed"] += bad
            if len(records) > 1:
                self.stats["concatenated_lines"] += 1
            for rec in records:
                flow = flow_from_record(rec)
                if flow is None:
                    self.stats["malformed"] += 1
                    continue
                if not self._filter.allowed(flow.exporter):
                    self.stats["dropped_exporter"] += 1
                    continue
                src_sgt = self._sgt(flow.src_tag, flow.src_ip, use_tags)
                dst_sgt = self._sgt(flow.dst_tag, flow.dst_ip, use_tags)
                rows.append((
                    flow.ts.strftime("%Y-%m-%d %H:%M:%S.%f"), flow.exporter, flow.src_ip, flow.src_port,
                    flow.dst_ip, flow.dst_port, flow.proto, flow.bytes, flow.packets, src_sgt, dst_sgt,
                ))
        n = self.store.ingest(rows)
        self.stats["records"] += n
        self._housekeeping()
        self.last_tick_s = time.monotonic() - started
        return n

    def lag_bytes(self) -> int:
        return self._tailer.lag_bytes()

    def _sgt(self, tag: int | None, ip: str, use_tags: bool) -> str:
        """SGT name of one side of a flow: the exported tag when ISE knows it, else the IP resolver."""
        if use_tags and tag is not None:
            name = self.resolver.tag_name(tag)
            if name:
                self.stats["sgt_from_flow"] += 1
                return name
            self.stats["unknown_tag"] += 1
        return self.resolver.resolve(ip)

    def _housekeeping(self) -> None:
        c = self.config.settings.collector
        now = time.monotonic()
        if now - self._last_flush >= c.rotate_minutes * 60:
            path = self.store.flush_parquet()
            if path:
                log.info("archived raw flows to %s", path)
            self._last_flush = now
        if now - self._last_rollup >= 600:
            self.store.compact()
            today = utcnow()
            # Yesterday too: its last minutes arrived after the last rollup of the day.
            for day in (today - timedelta(days=1), today):
                self.store.rollup_daily(day)
            self._last_rollup = now
        if now - self._last_retention >= 3600:
            self.store.apply_retention(c.retention_days)
            self._last_retention = now

    async def run(self) -> None:
        while True:
            try:
                n = await asyncio.to_thread(self.tick)
                if n:
                    log.debug("ingested %d flows", n)
            except Exception:  # keep the loop alive, report via logs
                log.exception("ingest tick failed")
            await asyncio.sleep(INGEST_EVERY_S)
