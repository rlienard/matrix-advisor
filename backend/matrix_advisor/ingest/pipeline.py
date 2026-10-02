"""Ingestion loop: GoFlow2 NDJSON -> oriented flows -> SGT resolution -> DuckDB aggregates."""

from __future__ import annotations

import asyncio
import logging
import time

from ..config import ConfigStore
from ..store import Store
from .goflow import ExporterFilter, NDJSONTailer, parse_record
from .resolver import SGTResolver

log = logging.getLogger(__name__)

INGEST_EVERY_S = 5
CONTEXT_WAIT_S = 180


class IngestPipeline:
    def __init__(self, config: ConfigStore, store: Store, resolver: SGTResolver, ready=None):
        self.config = config
        # Callable telling whether endpoint context (pxGrid) is loaded. Until then flows stay in
        # the GoFlow2 file, so that they are not attributed to "Unknown" for good.
        self.ready = ready or (lambda: True)
        self._started = time.monotonic()
        self.store = store
        self.resolver = resolver
        self._tailer: NDJSONTailer | None = None
        self._filter: ExporterFilter | None = None
        self._last_flush = time.monotonic()
        self._last_rollup = 0.0
        self._last_retention = 0.0
        self.stats = {"records": 0, "dropped_exporter": 0, "malformed": 0}
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
        lines = self._tailer.read()
        rows = []
        for line in lines:
            flow = parse_record(line)
            if flow is None:
                self.stats["malformed"] += 1
                continue
            if not self._filter.allowed(flow.exporter):
                self.stats["dropped_exporter"] += 1
                continue
            rows.append((
                flow.ts.strftime("%Y-%m-%d %H:%M:%S.%f"), flow.exporter, flow.src_ip, flow.src_port,
                flow.dst_ip, flow.dst_port, flow.proto, flow.bytes, flow.packets,
                self.resolver.resolve(flow.src_ip), self.resolver.resolve(flow.dst_ip),
            ))
        n = self.store.ingest(rows)
        self.stats["records"] += n
        self._housekeeping()
        return n

    def _housekeeping(self) -> None:
        c = self.config.settings.collector
        now = time.monotonic()
        if now - self._last_flush >= c.rotate_minutes * 60:
            path = self.store.flush_parquet()
            if path:
                log.info("archived raw flows to %s", path)
            self._last_flush = now
        if now - self._last_rollup >= 600:
            self.store.rollup_daily()
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
