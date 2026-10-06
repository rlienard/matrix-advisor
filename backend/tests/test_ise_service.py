"""Reconciliation scheduling: bursts of requests lead to one full read."""

import asyncio

from matrix_advisor.ise import service
from matrix_advisor.ise.service import ISEService


def _debounce_time(monkeypatch, request_every: float, requests: int) -> float:
    monkeypatch.setattr(service, "DEBOUNCE_S", 0.1)
    monkeypatch.setattr(service, "MAX_DELAY_S", 0.5)

    async def run() -> float:
        svc = ISEService.__new__(ISEService)
        svc._reconcile_now = asyncio.Event()
        svc._reconcile_now.set()

        async def burst():
            for _ in range(requests):
                await asyncio.sleep(request_every)
                svc.request_reconcile()

        loop = asyncio.get_running_loop()
        start = loop.time()
        task = asyncio.create_task(burst())
        await svc._debounce()
        elapsed = loop.time() - start
        task.cancel()
        return elapsed

    return asyncio.run(run())


def test_debounce_waits_for_the_burst_to_end(monkeypatch):
    # 4 requests 50 ms apart, then quiet: one read about 100 ms after the last request.
    assert 0.25 <= _debounce_time(monkeypatch, 0.05, 4) < 0.45


def test_debounce_never_waits_past_the_max_delay(monkeypatch):
    # Requests never stop: the read still happens after MAX_DELAY_S.
    assert 0.45 <= _debounce_time(monkeypatch, 0.05, 100) < 0.7
