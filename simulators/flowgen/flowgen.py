#!/usr/bin/env python3
"""IPFIX traffic generator for Matrix Advisor demos.

Sends IPFIX (RFC 7011) records to a collector (GoFlow2) describing a small campus:
users, contractors, admins, cameras and guests talking to server groups. The addresses
match the ISE simulator's pxGrid sessions and SXP bindings, so every flow resolves to an
SGT. Scenarios include the cases the demo talks about: a new port on an existing
contract, a reusable contract, SQL access from a handful of contractor laptops, and
cameras beaconing to the Internet every 5 minutes.

    python flowgen.py --collector 127.0.0.1:4739 [--speed 1] [--once]

No third-party dependency.
"""

from __future__ import annotations

import argparse
import ipaddress
import random
import socket
import struct
import time
from dataclasses import dataclass, field

TEMPLATE_ID = 256
# (IANA element id, length)
FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 8), (2, 8), (152, 8), (153, 8)]
RECORD = struct.Struct("!4s4sHHBQQQQ")
PROTO = {"TCP": 6, "UDP": 17}


@dataclass
class Profile:
    name: str
    src_net: tuple[int, int, int]          # (third octet, first host, last host) in 10.10.x.0/24
    dst: str                                # server CIDR or a public IP
    ports: list[tuple[str, int, float]]     # (proto, port, weight)
    per_minute: float                       # conversations per minute (whole profile)
    hosts: int | None = None                # restrict to N source hosts
    hours: tuple[int, int] = (0, 24)        # active hours (local time of the generator)
    beacon_s: int | None = None             # strictly periodic, one flow per host every N seconds
    reverse_ratio: float = 0.3              # share of conversations also exported server -> client
    _next_beacon: dict = field(default_factory=dict)


PROFILES = [
    Profile("employees-web", (1, 10, 200), "10.20.1.0/24", [("TCP", 443, 0.85), ("TCP", 80, 0.15)], 240),
    Profile("employees-hr", (1, 10, 200), "10.20.2.0/24", [("TCP", 443, 0.75), ("TCP", 8443, 0.25)], 60),
    Profile("employees-print", (1, 10, 200), "10.20.3.0/24", [("TCP", 9100, 0.7), ("TCP", 631, 0.3)], 25),
    Profile("contractors-web", (2, 10, 60), "10.20.1.0/24", [("TCP", 443, 1.0)], 40),
    Profile("contractors-finance", (2, 10, 60), "10.20.4.0/24", [("TCP", 1433, 1.0)], 6, hosts=3),
    Profile("cameras-nvr", (4, 10, 100), "10.20.5.0/24", [("TCP", 554, 0.4), ("UDP", 5004, 0.6)], 120),
    Profile("cameras-beacon", (4, 10, 100), "203.0.113.45", [("TCP", 443, 1.0)], 0, hosts=2, beacon_s=300),
    Profile("admins-finance", (3, 10, 20), "10.20.4.0/24", [("TCP", 22, 0.5), ("TCP", 1433, 0.5)], 12),
    Profile("admins-hr", (3, 10, 20), "10.20.2.0/24", [("TCP", 22, 1.0)], 8),
    Profile("guests-internet", (5, 10, 200), "198.51.100.0/24", [("TCP", 443, 0.8), ("UDP", 53, 0.2)], 90),
]


class Exporter:
    def __init__(self, collector: str, domain: int = 1):
        host, port = collector.rsplit(":", 1)
        self.addr = (host, int(port))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.domain = domain
        self.seq = 0
        self.messages = 0

    def _template_set(self) -> bytes:
        body = struct.pack("!HH", TEMPLATE_ID, len(FIELDS)) + b"".join(struct.pack("!HH", i, ln) for i, ln in FIELDS)
        return struct.pack("!HH", 2, 4 + len(body)) + body

    def send(self, records: list[bytes]) -> None:
        for i in range(0, len(records), 25):
            chunk = records[i:i + 25]
            # Template in every message: collectors decode in parallel workers and
            # would otherwise drop data sets that arrive before the template.
            sets = self._template_set()
            data = b"".join(chunk)
            sets += struct.pack("!HH", TEMPLATE_ID, 4 + len(data)) + data
            header = struct.pack("!HHIII", 10, 16 + len(sets), int(time.time()), self.seq, self.domain)
            self.sock.sendto(header + sets, self.addr)
            self.seq += len(chunk)
            self.messages += 1


def _host(p: Profile, rng: random.Random) -> str:
    octet, lo, hi = p.src_net
    if p.hosts:
        hi = min(hi, lo + p.hosts - 1)
    return f"10.10.{octet}.{rng.randint(lo, hi)}"


def _dst(p: Profile, rng: random.Random) -> str:
    net = ipaddress.ip_network(p.dst, strict=False)
    if net.num_addresses == 1:
        return str(net.network_address)
    return str(net.network_address + rng.randint(10, min(30, net.num_addresses - 2)))


def _record(src: str, dst: str, sport: int, dport: int, proto: str, now_ms: int, rng: random.Random) -> bytes:
    packets = rng.randint(4, 120)
    octets = packets * rng.randint(60, 1400)
    duration = rng.randint(50, 30_000)
    return RECORD.pack(socket.inet_aton(src), socket.inet_aton(dst), sport, dport, PROTO[proto],
                       octets, packets, now_ms - duration, now_ms)


def conversations(p: Profile, seconds: float, rng: random.Random) -> list[bytes]:
    now = time.time()
    hour = time.localtime(now).tm_hour
    now_ms = int(now * 1000)
    out: list[bytes] = []
    if p.beacon_s:
        octet, lo, _ = p.src_net
        for h in range(p.hosts or 1):
            src = f"10.10.{octet}.{lo + h}"
            due = p._next_beacon.setdefault(src, now + rng.uniform(0, p.beacon_s))
            if now >= due:
                proto, port, _ = p.ports[0]
                out.append(_record(src, _dst(p, rng), rng.randint(40000, 60000), port, proto, now_ms, rng))
                p._next_beacon[src] = due + p.beacon_s
        return out
    if not (p.hours[0] <= hour < p.hours[1]):
        return out
    expected = p.per_minute * seconds / 60
    count = int(expected) + (1 if rng.random() < expected - int(expected) else 0)
    for _ in range(count):
        proto, port, _ = rng.choices(p.ports, weights=[w for *_, w in p.ports])[0]
        src, dst, sport = _host(p, rng), _dst(p, rng), rng.randint(32768, 60999)
        out.append(_record(src, dst, sport, port, proto, now_ms, rng))
        if rng.random() < p.reverse_ratio:
            out.append(_record(dst, src, port, sport, proto, now_ms, rng))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--collector", default="127.0.0.1:4739", help="host:port of the IPFIX collector")
    ap.add_argument("--speed", type=float, default=1.0, help="traffic multiplier")
    ap.add_argument("--interval", type=float, default=5.0, help="seconds between export rounds")
    ap.add_argument("--only", default="", help="comma-separated profile names to run")
    ap.add_argument("--once", action="store_true", help="send one round and exit")
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    profiles = [p for p in PROFILES if not args.only or p.name in args.only.split(",")]
    exporter = Exporter(args.collector)
    print(f"flowgen -> {args.collector}: {', '.join(p.name for p in profiles)}", flush=True)
    while True:
        records: list[bytes] = []
        for p in profiles:
            scaled = Profile(**{**p.__dict__, "per_minute": p.per_minute * args.speed})
            scaled._next_beacon = p._next_beacon
            records += conversations(scaled, args.interval, rng)
        if records:
            exporter.send(records)
        if args.once:
            print(f"sent {len(records)} records", flush=True)
            return
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
