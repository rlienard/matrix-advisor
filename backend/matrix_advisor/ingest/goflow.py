"""Reading GoFlow2 output.

GoFlow2 is started with ``-format json -transport file -transport.file <path>`` and
appends one JSON object per flow. This module tails that file, survives rotation and
truncation, and turns records into oriented flows (client -> service port).
"""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone

PROTO_NUM = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMP"}

# Service ports that are above 1024 but clearly server side.
KNOWN_SERVICE_PORTS = {
    1433, 1521, 1812, 1813, 2049, 3268, 3306, 3389, 4739, 5060, 5061, 5432, 5672, 5985, 5986, 6379,
    8080, 8443, 8000, 8008, 8888, 9000, 9042, 9092, 9100, 9200, 9443, 10443, 27017, 554, 631,
}


@dataclass
class Flow:
    ts: datetime
    exporter: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    bytes: int
    packets: int


class NDJSONTailer:
    """Incrementally read complete lines appended to a file.

    Handles rotation (inode change) and copy-truncate. When ``max_bytes`` is set and the
    file grew beyond it, the file is truncated after it has been fully read so that the
    shared volume does not fill up (GoFlow2 opens it in append mode).
    """

    def __init__(self, path: str, max_bytes: int = 256 * 1024 * 1024, start_at_end: bool = False):
        self.path = path
        self.max_bytes = max_bytes
        self.offset = 0
        self.inode: int | None = None
        self._partial = b""
        if start_at_end and os.path.exists(path):
            st = os.stat(path)
            self.inode, self.offset = st.st_ino, st.st_size

    def read(self, max_lines: int = 200_000) -> list[bytes]:
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return []
        if self.inode is not None and st.st_ino != self.inode:
            self.offset, self._partial = 0, b""
        if st.st_size < self.offset:
            self.offset, self._partial = 0, b""
        self.inode = st.st_ino
        lines: list[bytes] = []
        with open(self.path, "rb") as fh:
            fh.seek(self.offset)
            while len(lines) < max_lines:
                chunk = fh.read(4 * 1024 * 1024)
                if not chunk:
                    break
                data = self._partial + chunk
                parts = data.split(b"\n")
                self._partial = parts.pop()
                lines.extend(p for p in parts if p.strip())
            self.offset = fh.tell()
        if self.max_bytes and self.offset >= self.max_bytes and not self._partial:
            try:
                with open(self.path, "r+b") as fh:
                    if os.fstat(fh.fileno()).st_size == self.offset:
                        fh.truncate(0)
                        self.offset = 0
            except OSError:
                pass
        return lines


def _ts(rec: dict) -> datetime:
    for key in ("time_flow_end_ns", "time_received_ns", "time_flow_start_ns"):
        v = rec.get(key)
        if v:
            return datetime.fromtimestamp(int(v) / 1e9, tz=timezone.utc).replace(tzinfo=None)
    for key in ("time_flow_end", "time_received", "time_flow_start"):  # GoFlow2 v1 (seconds)
        v = rec.get(key)
        if v:
            return datetime.fromtimestamp(int(v), tz=timezone.utc).replace(tzinfo=None)
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _proto(v) -> str:
    if isinstance(v, int) or (isinstance(v, str) and v.isdigit()):
        return PROTO_NUM.get(int(v), str(v))
    return str(v or "").upper()


def _service_score(port: int) -> int:
    if 0 < port < 1024:
        return 3
    if port in KNOWN_SERVICE_PORTS:
        return 2
    if port < 32768:
        return 1
    return 0


def orient(proto: str, sip: str, sport: int, dip: str, dport: int) -> tuple[str, int, str, int]:
    """Return (client_ip, client_port, server_ip, service_port).

    NetFlow sees both directions of a conversation; the return direction must be folded
    onto the request so that a reply from a web server is not mistaken for traffic from
    the server group to the client group on an ephemeral port.
    """
    if proto not in ("TCP", "UDP"):
        return sip, 0, dip, 0
    s_src, s_dst = _service_score(sport), _service_score(dport)
    if s_src > s_dst or (s_src == s_dst and s_src > 0 and sport < dport):
        return dip, dport, sip, sport
    return sip, sport, dip, dport


def parse_record(line: bytes) -> Flow | None:
    try:
        rec = json.loads(line)
    except (ValueError, UnicodeDecodeError):
        return None
    src, dst = rec.get("src_addr") or rec.get("SrcAddr"), rec.get("dst_addr") or rec.get("DstAddr")
    if not src or not dst:
        return None
    proto = _proto(rec.get("proto", rec.get("Proto")))
    sport = int(rec.get("src_port", rec.get("SrcPort", 0)) or 0)
    dport = int(rec.get("dst_port", rec.get("DstPort", 0)) or 0)
    sampling = int(rec.get("sampling_rate") or 1) or 1
    c_ip, c_port, s_ip, s_port = orient(proto, src, sport, dst, dport)
    return Flow(
        ts=_ts(rec),
        exporter=str(rec.get("sampler_address") or rec.get("SamplerAddress") or ""),
        src_ip=c_ip, src_port=c_port, dst_ip=s_ip, dst_port=s_port, proto=proto,
        bytes=int(rec.get("bytes", rec.get("Bytes", 0)) or 0) * sampling,
        packets=int(rec.get("packets", rec.get("Packets", 0)) or 0) * sampling,
    )


class ExporterFilter:
    def __init__(self, cidrs: list[str]):
        self.nets = [ipaddress.ip_network(c.strip(), strict=False) for c in cidrs if c.strip()]

    def allowed(self, exporter: str) -> bool:
        if not self.nets:
            return True
        try:
            ip = ipaddress.ip_address(exporter)
        except ValueError:
            return False
        return any(ip in n for n in self.nets)
