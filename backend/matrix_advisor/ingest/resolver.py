"""IP -> SGT resolution.

A group tag exported in the flow record itself (Cisco CTS fields) wins when its value is
known in the ISE SGT table: it is what the switch enforced on, with no dependency on pxGrid.
Otherwise the address is resolved from these sources, by priority:
1. Active endpoint sessions from pxGrid (exact IP -> SGT, e.g. 802.1X / MAB users).
2. IP-SGT bindings (pxGrid SXP service, ISE static mappings) as prefixes.
3. Static bindings from the configuration.
Anything else is ``Unknown``: SGT 0, the tag the switches enforce for an unclassified address
(Internet destinations, unmapped hosts).

Resolution happens here, in the deterministic layer: IP addresses never reach the LLM.

Prefix tables are indexed by prefix length: a lookup costs one dictionary probe per distinct
length (at most 33 for IPv4), whatever the number of bindings. Resolved addresses are cached;
a pxGrid session event invalidates only the addresses it names, so the cache stays warm while
endpoints come and go.
"""

from __future__ import annotations

import ipaddress
import threading

from ..policy.matrix import UNKNOWN, UNKNOWN_VALUE

CACHE_MAX = 500_000


class PrefixTable:
    """Longest-prefix match over IPv4 and IPv6 prefixes."""

    def __init__(self, items: dict[str, str]):
        # (version, prefix length) -> {network address as int: SGT name}
        self._by_len: dict[tuple[int, int], dict[int, str]] = {}
        for cidr, sgt in items.items():
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            self._by_len.setdefault((net.version, net.prefixlen), {})[int(net.network_address)] = sgt
        # Longest prefixes first, per IP version.
        self._lengths = {v: sorted((n for ver, n in self._by_len if ver == v), reverse=True) for v in (4, 6)}
        self.size = sum(len(t) for t in self._by_len.values())

    def lookup(self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
        value, bits = int(addr), addr.max_prefixlen
        for length in self._lengths[addr.version]:
            mask = ((1 << length) - 1) << (bits - length)
            hit = self._by_len[(addr.version, length)].get(value & mask)
            if hit is not None:
                return hit
        return None


class SGTResolver:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._exact: dict[str, str] = {}
        self._prefixes = PrefixTable({})
        self._static = PrefixTable({})
        self._cache: dict[str, str] = {}
        self._tags: dict[int, str] = {}

    def set_sessions(self, mapping: dict[str, str]) -> None:
        with self._lock:
            self._exact = dict(mapping)
            self._cache.clear()

    def update_sessions(self, mapping: dict[str, str], removed: list[str] | None = None) -> None:
        """Apply a pxGrid session event: only the addresses it names leave the cache."""
        with self._lock:
            self._exact.update(mapping)
            for ip in removed or []:
                self._exact.pop(ip, None)
            for ip in [*mapping, *(removed or [])]:
                self._cache.pop(ip, None)

    def set_bindings(self, prefixes: dict[str, str]) -> None:
        table = PrefixTable(prefixes)
        with self._lock:
            self._prefixes = table
            self._cache.clear()

    def set_static(self, prefixes: dict[str, str]) -> None:
        table = PrefixTable(prefixes)
        with self._lock:
            self._static = table
            self._cache.clear()

    def set_tags(self, values: dict[int, str]) -> None:
        """SGT value -> name, from the ISE SGT table."""
        with self._lock:
            if values.get(UNKNOWN_VALUE) != self._tags.get(UNKNOWN_VALUE):
                self._cache.clear()  # cached unclassified addresses carry the old name of SGT 0
            self._tags = dict(values)

    def tag_name(self, tag: int | None) -> str | None:
        if tag is None:
            return None
        with self._lock:
            return self._tags.get(tag)

    def counts(self) -> dict:
        with self._lock:
            return {"sessions": len(self._exact), "bindings": self._prefixes.size, "static": self._static.size,
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
                    return self._tags.get(UNKNOWN_VALUE, UNKNOWN)
                sgt = self._prefixes.lookup(addr) or self._static.lookup(addr) \
                    or self._tags.get(UNKNOWN_VALUE, UNKNOWN)
            if len(self._cache) >= CACHE_MAX:
                self._cache.clear()
            self._cache[ip] = sgt
            return sgt
