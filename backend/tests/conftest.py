"""Shared fixtures: the ISE simulator served over real HTTP and websocket on a free port."""

import socket
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

SIM_DIR = Path(__file__).resolve().parents[2] / "simulators" / "ise_sim"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def sim_url():
    sys.path.insert(0, str(SIM_DIR))
    import ise_sim

    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(ise_sim.app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            httpx.get(url + "/sim/state")
            break
        except httpx.HTTPError:
            time.sleep(0.1)
    yield url
    server.should_exit = True
