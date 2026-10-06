"""ISE integration service: matrix cache, reconciliation and pxGrid context.

ISE is the source of truth. The cache is rebuilt from scratch every
``ise.reconcile_minutes`` and whenever pxGrid notifies a TrustSec configuration change.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from datetime import UTC, datetime

from ..config import ConfigStore
from ..i18n import Message, message_of
from ..ingest.resolver import SGTResolver
from ..policy.matrix import Matrix
from .client import ISEClient, ISEError
from .pxgrid import PxGridError, pxgrid_client, sessions_to_mapping

log = logging.getLogger(__name__)


# A burst of change notifications (or of approvals) leads to one full read: wait until requests stop
# for DEBOUNCE_S, but never longer than MAX_DELAY_S after the first one.
DEBOUNCE_S = 5.0
MAX_DELAY_S = 30.0


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class ISEService:
    def __init__(self, config: ConfigStore, resolver: SGTResolver):
        self.config = config
        self.resolver = resolver
        self.matrix = Matrix(default=config.settings.ise.matrix_default)
        self.client = ISEClient(config.settings.ise)
        self.pxgrid = pxgrid_client(config.settings.ise)
        self.status = {
            "online": False, "last_sync": None, "last_error": None,
            "pxgrid": {"state": "not configured", "last_update": None, "error": None, "mode": None},
        }
        self._reconcile_now = asyncio.Event()
        self._restart = asyncio.Event()
        self.write_lock = asyncio.Lock()
        config.on_change(self._on_config)

    def _on_config(self, old, new) -> None:
        if old.ise != new.ise:
            self._restart.set()

    async def _rebuild_clients(self) -> None:
        await self.client.close()
        if self.pxgrid:
            await self.pxgrid.close()
        ise = self.config.settings.ise
        self.client = ISEClient(ise)
        self.pxgrid = pxgrid_client(ise)
        self.matrix.default = ise.matrix_default

    def request_reconcile(self) -> None:
        self._reconcile_now.set()

    async def reconcile(self) -> Matrix:
        ise = self.config.settings.ise
        try:
            m = await self.client.read_matrix(default=ise.matrix_default)
        except ISEError as e:
            self.status.update(online=False, last_error=message_of(e))
            raise
        self.matrix = m
        self.resolver.set_tags({s.value: s.name for s in m.sgts.values()})
        self.status.update(online=True, last_sync=m.synced_at, last_error=None)
        log.info("ISE matrix synced: %d SGT, %d SGACL, %d cells", len(m.sgts), len(m.sgacls), len(m.cells))
        return m

    async def refresh_written(self, src: str, dst: str, cell_id: str) -> Matrix:
        """Re-read from ISE the cell just written and the SGACLs it references.

        Done after every write so that the cache is exact at once for that pair, without waiting for
        the (debounced) full reconciliation, which still follows to pick up any other change.
        """
        client, m = self.client, self.matrix
        cell = await client.read_cell(cell_id)
        sgacls = await asyncio.gather(*(client.fresh_sgacl(i) for i in cell.sgacl_ids))
        self.matrix = Matrix(sgts=m.sgts, sgacls={**m.sgacls, **{a.id: a for a in sgacls}},
                             cells={**m.cells, (src, dst): cell}, default=m.default, synced_at=m.synced_at)
        return self.matrix

    # ------------------------------------------------------------ loops
    async def run(self) -> None:
        await asyncio.gather(self._reconcile_loop(), self._pxgrid_loop())

    async def _reconcile_loop(self) -> None:
        while True:
            if self._restart.is_set():
                self._restart.clear()
                await self._rebuild_clients()
            try:
                await self.reconcile()
            except Exception as e:  # noqa: BLE001 - surfaced in status
                log.warning("ISE reconcile failed: %s", e)
                self.status.update(online=False, last_error=message_of(e))
            wait = self.config.settings.ise.reconcile_minutes * 60
            try:
                await asyncio.wait_for(self._wait_any(), timeout=wait)
            except TimeoutError:
                pass
            if self._reconcile_now.is_set() and not self._restart.is_set():
                await self._debounce()
            self._reconcile_now.clear()

    async def _debounce(self) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + MAX_DELAY_S
        while (remaining := deadline - loop.time()) > 0:
            self._reconcile_now.clear()
            try:
                await asyncio.wait_for(self._reconcile_now.wait(), timeout=min(DEBOUNCE_S, remaining))
            except TimeoutError:
                return

    async def _wait_any(self) -> None:
        reconcile = asyncio.create_task(self._reconcile_now.wait())
        restart = asyncio.create_task(self._restart.wait())
        _, pending = await asyncio.wait({reconcile, restart}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()

    @property
    def context_ready(self) -> bool:
        """True once endpoint context is loaded (or when pxGrid is not configured)."""
        return self.pxgrid is None or self.status["pxgrid"]["last_update"] is not None

    async def _refresh_context(self) -> None:
        px = self.pxgrid
        if not self.matrix.sgts:  # SXP bindings carry tags: the SGT table is needed first
            try:
                await self.reconcile()
            except ISEError:
                pass
        state = await px.ensure_account()
        self.status["pxgrid"]["state"] = state
        if state != "ENABLED":
            raise PxGridError(Message("pxgrid_account_state", state=state, client=px.cfg.client_name))
        self.resolver.set_sessions(await px.sessions())
        prefixes: dict[str, str] = {}
        for b in await px.bindings():
            sgt = self.matrix.sgt_by_value(int(b.get("tag", -1)))
            prefix = b.get("ipPrefix")
            if sgt and prefix:
                try:
                    ipaddress.ip_network(prefix, strict=False)
                    prefixes[prefix] = sgt.name
                except ValueError:
                    continue
        self.resolver.set_bindings(prefixes)
        self.status["pxgrid"].update(last_update=_now(), error=None)

    async def _pxgrid_loop(self) -> None:
        while True:
            px = self.pxgrid
            if px is None:
                self.status["pxgrid"].update(state="not configured")
                await asyncio.sleep(30)
                continue
            try:
                await self._refresh_context()
                if px.cfg.subscribe:
                    self.status["pxgrid"]["mode"] = "websocket"
                    try:
                        await px.subscribe(self._on_pxgrid_message)
                    except Exception as e:  # noqa: BLE001
                        log.info("pxGrid websocket unavailable (%s), falling back to polling", e)
                self.status["pxgrid"]["mode"] = "polling"
                await asyncio.sleep(px.cfg.poll_seconds)
            except Exception as e:  # noqa: BLE001
                log.warning("pxGrid refresh failed: %s", e)
                self.status["pxgrid"].update(error=message_of(e))
                await asyncio.sleep(30)

    async def _on_pxgrid_message(self, topic: str, body: dict) -> None:
        if "session" in topic.lower() and "sessions" in body:
            removed = [ip for s in body["sessions"] if s.get("state") == "DISCONNECTED"
                       for ip in s.get("ipAddresses") or []]
            self.resolver.update_sessions(sessions_to_mapping(body["sessions"]), removed)
            self.status["pxgrid"]["last_update"] = _now()
        else:
            log.info("TrustSec change notified on %s, reconciling", topic)
            self.request_reconcile()

    # ------------------------------------------------------------ status
    def summary(self) -> dict:
        m = self.matrix
        return {
            **self.status,
            "sgt_count": len(m.sgts), "sgacl_count": len(m.sgacls), "cell_count": len(m.cells),
            "resolver": self.resolver.counts(),
        }
