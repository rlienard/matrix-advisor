"""IP -> SGT resolution.

A group tag exported in the flow record itself (Cisco CTS fields) wins when its value is
known in the ISE SGT table: it is what the switch enforced on, with no dependency on pxGrid.
Otherwise the address is resolved from these sources, by priority:
1. Active endpoint sessions from pxGrid (exact IP -> SGT, e.g. 802.1X / MAB users).
2. IP-SGT bindings (pxGrid SXP service, ISE static mappings) as prefixes.
3. Static bindings from the configuration.
Anything else is ``Internet`` (public address) or ``Unknown`` (private address).

Resolution happens here, in the deterministic layer: IP addresses never reach the LLM.
"""

from __future__ import annotations

import ipaddress
import threading

from ..policy.matrix import INTERNET, UNKNOWN

INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8",
    "fc00::/7", "fe80::/10", "::1/128",
)]


def is_internal(addr: ipaddress._BaseAddress) -> bool:
    return any(addr.version == n.version and addr in n for n in INTERNAL_NETS)


class SGTResolver:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._exact: dict[str, str] = {}
        self._prefixes: list[tuple[ipaddress._BaseNetwork, str]] = []
        self._static: list[tuple[ipaddress._BaseNetwork, str]] = []
        self._cache: dict[str, str] = {}
        self._tags: dict[int, str] = {}

    @staticmethod
    def _sorted(items: dict[str, str]) -> list[tuple[ipaddress._BaseNetwork, str]]:
        nets = []
        for cidr, sgt in items.items():
            try:
                nets.append((ipaddress.ip_network(cidr, strict=False), sgt))
            except ValueError:
                continue
        nets.sort(key=lambda x: x[0].prefixlen, reverse=True)
        return nets

    def set_sessions(self, mapping: dict[str, str]) -> None:
        with self._lock:
            self._exact = dict(mapping)
            self._cache.clear()

    def update_sessions(self, mapping: dict[str, str], removed: list[str] | None = None) -> None:
        with self._lock:
            self._exact.update(mapping)
            for ip in removed or []:
                self._exact.pop(ip, None)
            self._cache.clear()

    def set_bindings(self, prefixes: dict[str, str]) -> None:
        with self._lock:
            self._prefixes = self._sorted(prefixes)
            self._cache.clear()

    def set_static(self, prefixes: dict[str, str]) -> None:
        with self._lock:
            self._static = self._sorted(prefixes)
            self._cache.clear()

    def set_tags(self, values: dict[int, str]) -> None:
        """SGT value -> name, from the ISE SGT table."""
        with self._lock:
            self._tags = dict(values)

    def tag_name(self, tag: int | None) -> str | None:
        if tag is None:
            return None
        with self._lock:
            return self._tags.get(tag)

    def counts(self) -> dict:
        with self._lock:
            return {"sessions": len(self._exact), "bindings": len(self._prefixes), "static": len(self._static),
                    "tags": len(self._tags)}

    def resolve(self, ip: str) -> str:
        with self._lock:
            hit = self._cache.get(ip)
            if hit:
                return hit
            sgt = self._exact.get(ip)
            if sgt is None:
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    return UNKNOWN
                for table in (self._prefixes, self._static):
                    sgt = next((name for net, name in table if addr in net), None)
                    if sgt:
                        break
                if sgt is None:
                    sgt = UNKNOWN if is_internal(addr) else INTERNET
            if len(self._cache) > 500_000:
                self._cache.clear()
            self._cache[ip] = sgt
            return sgt
