"""SGACL parsing, generation and evaluation.

Supported grammar (one ACE per line, the subset Matrix Advisor generates and checks):

    permit|deny tcp|udp|icmp|ip [dst eq N | dst range N M] [log]

A leading ``+`` (diff marker used in the UI) and surrounding spaces are ignored, as are
blank lines and lines starting with ``!`` or ``#``. Evaluation is first match, like an
SGACL on the switch.

Ports are written as *specs*: ``"TCP/443"`` or ``"UDP/5000-5100"``; ``"ICMP"`` has no port.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_ACE_RE = re.compile(
    r"^(permit|deny)\s+(tcp|udp|icmp|ip)"
    r"(?:\s+dst\s+(?:eq\s+(\d{1,5})|range\s+(\d{1,5})\s+(\d{1,5})))?"
    r"(?:\s+(log))?$",
    re.IGNORECASE,
)

DB_PORTS = {1433, 1521, 3306, 5432, 27017, 6379, 9042}
ADMIN_PORTS = {22, 23, 3389, 5985, 5986, 161, 830}


@dataclass(frozen=True)
class ACE:
    action: str          # permit | deny
    proto: str           # tcp | udp | icmp | ip
    lo: int | None = None
    hi: int | None = None
    log: bool = False

    def covers(self, proto: str, port: int | None) -> bool:
        if self.proto != "ip" and self.proto != proto:
            return False
        if self.lo is None:
            return True
        return port is not None and self.lo <= port <= self.hi

    def render(self) -> str:
        out = f"{self.action} {self.proto}"
        if self.lo is not None:
            out += f" dst eq {self.lo}" if self.lo == self.hi else f" dst range {self.lo} {self.hi}"
        if self.log:
            out += " log"
        return out

    @property
    def spec(self) -> str | None:
        if self.proto in ("tcp", "udp") and self.lo is not None:
            port = str(self.lo) if self.lo == self.hi else f"{self.lo}-{self.hi}"
            return f"{self.proto.upper()}/{port}"
        return None


@dataclass
class ParseResult:
    rules: list[ACE]
    errors: list[str]


def parse_spec(spec: str) -> tuple[str, int | None, int | None]:
    """'TCP/443' -> ('tcp', 443, 443); 'UDP/5000-5100' -> ('udp', 5000, 5100); 'ICMP' -> ('icmp', None, None)."""
    if "/" not in spec:
        return spec.lower(), None, None
    proto, port = spec.split("/", 1)
    if "-" in port:
        a, b = port.split("-", 1)
        return proto.lower(), int(a), int(b)
    return proto.lower(), int(port), int(port)


def make_spec(proto: str, port: int | None) -> str:
    proto = proto.upper()
    if proto in ("TCP", "UDP") and port:
        return f"{proto}/{port}"
    return proto


def parse(text: str) -> ParseResult:
    rules: list[ACE] = []
    errors: list[str] = []
    for i, raw in enumerate(text.splitlines(), start=1):
        line = re.sub(r"^\s*\+?\s*", "", raw).strip()
        if not line or line.startswith(("!", "#")):
            continue
        m = _ACE_RE.match(line)
        if not m:
            errors.append(f"Ligne {i} : « {line} » n’est pas une ACE reconnue.")
            continue
        action, proto = m.group(1).lower(), m.group(2).lower()
        lo = int(m.group(3)) if m.group(3) else (int(m.group(4)) if m.group(4) else None)
        hi = int(m.group(3)) if m.group(3) else (int(m.group(5)) if m.group(5) else None)
        if lo is not None and (lo < 1 or hi > 65535 or hi < lo):
            errors.append(f"Ligne {i} : port hors plage.")
            continue
        if lo is not None and proto not in ("tcp", "udp"):
            errors.append(f"Ligne {i} : un port n’a de sens qu’avec tcp ou udp.")
            continue
        rules.append(ACE(action, proto, lo, hi, bool(m.group(6))))
    if not rules and not errors:
        errors.append("Le contrat est vide.")
    return ParseResult(rules, errors)


def first_match(rules: list[ACE], proto: str, port: int | None) -> ACE | None:
    for r in rules:
        if r.covers(proto, port):
            return r
    return None


def allows(rules: list[ACE], spec: str) -> bool:
    """True when every port of ``spec`` is permitted (first match) by ``rules``."""
    proto, lo, hi = parse_spec(spec)
    for port in {lo, hi}:
        hit = first_match(rules, proto, port)
        if hit is None or hit.action != "permit":
            return False
    return True


def decision(rules: list[ACE], spec: str) -> str | None:
    """'permit', 'deny' or None when no ACE matches (falls through to the cell default)."""
    proto, lo, _ = parse_spec(spec)
    hit = first_match(rules, proto, lo)
    return hit.action if hit else None


def generate(specs: list[str], log: bool = True) -> str:
    """Least-privilege SGACL permitting exactly ``specs`` then denying the rest."""
    lines = []
    for spec in sorted(set(specs), key=_spec_sort_key):
        proto, lo, hi = parse_spec(spec)
        lines.append(ACE("permit", proto, lo, hi, log).render())
    lines.append(ACE("deny", "ip", log=log).render())
    return "\n".join(lines)


def extend(base_text: str, add_specs: list[str], log: bool = True) -> str:
    """Insert permits for ``add_specs`` before the first catch-all deny of ``base_text``.

    New lines are prefixed with ``+ `` so the UI can render the diff; ``parse`` ignores it.
    """
    base_lines = [ln for ln in base_text.splitlines() if ln.strip()]
    rules = parse(base_text).rules
    insert_at = len(base_lines)
    for idx, ln in enumerate(base_lines):
        clean = re.sub(r"^\s*\+?\s*", "", ln).strip().lower()
        if clean.startswith("deny ip"):
            insert_at = idx
            break
    added = [
        "+ " + ACE("permit", *parse_spec(s), log).render()
        for s in sorted(set(add_specs), key=_spec_sort_key)
        if not allows(rules, s)
    ]
    out = ["  " + ln.strip() for ln in base_lines[:insert_at]] + added + ["  " + ln.strip() for ln in base_lines[insert_at:]]
    return "\n".join(out)


def to_ise(text: str) -> str:
    """Canonical aclcontent for ISE (diff markers and comments stripped)."""
    return "\n".join(r.render() for r in parse(text).rules)


def permitted_specs(rules: list[ACE]) -> set[str]:
    return {r.spec for r in rules if r.action == "permit" and r.spec}


def has_permit_any(rules: list[ACE]) -> bool:
    return any(r.action == "permit" and r.proto == "ip" for r in rules)


def validate(text: str, observed: list[str]) -> dict:
    """Same checks as the UI: syntax, observed traffic still allowed, unused permits."""
    res = parse(text)
    warns: list[str] = []
    infos: list[str] = []
    if has_permit_any(res.rules):
        warns.append("« permit ip » ouvre tout le trafic entre ces deux groupes : contraire au deny par défaut.")
    if not res.errors:
        for spec in observed:
            if not allows(res.rules, spec):
                warns.append(f"{spec} est observé mais n’est plus autorisé : ce trafic sera bloqué.")
        for r in res.rules:
            if r.action == "permit" and r.spec and not any(_overlap(r, s) for s in observed):
                infos.append(f"{r.spec} autorisé mais jamais observé sur cette paire.")
        if res.rules and not (res.rules[-1].action == "deny" and res.rules[-1].proto == "ip"):
            infos.append("Pas de « deny ip » final : c’est la politique par défaut de la cellule ou de la matrice qui s’applique.")
    return {"errors": res.errors, "warns": warns, "infos": infos}


def _overlap(rule: ACE, spec: str) -> bool:
    proto, lo, hi = parse_spec(spec)
    if rule.proto != proto or rule.lo is None or lo is None:
        return False
    return lo <= rule.hi and hi >= rule.lo


def _spec_sort_key(spec: str):
    proto, lo, _ = parse_spec(spec)
    return (proto, lo or 0)
