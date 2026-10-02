"""In-memory view of the TrustSec matrix read from ISE, and coverage evaluation."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime

from . import acl

# Pseudo groups produced by the IP -> SGT resolver. They have no cell in the matrix.
UNKNOWN = "Unknown"
INTERNET = "Internet"
PSEUDO_GROUPS = {UNKNOWN, INTERNET}


@dataclass
class Sgt:
    id: str
    name: str
    value: int
    description: str = ""


@dataclass
class Sgacl:
    id: str
    name: str
    content: str
    description: str = ""
    generation_id: str = ""
    read_only: bool = False

    @property
    def rules(self) -> list[acl.ACE]:
        return acl.parse(self.content).rules


@dataclass
class Cell:
    id: str
    src_id: str
    dst_id: str
    status: str = "ENABLED"          # ENABLED | DISABLED | MONITOR
    default_rule: str = "NONE"       # NONE | PERMIT_IP | DENY_IP
    sgacl_ids: list[str] = field(default_factory=list)
    name: str = ""
    description: str = ""

    def fingerprint(self) -> str:
        raw = f"{self.status}|{self.default_rule}|{','.join(self.sgacl_ids)}"
        return hashlib.sha1(raw.encode()).hexdigest()[:12]


NO_CELL_FINGERPRINT = "none"


@dataclass
class Matrix:
    sgts: dict[str, Sgt] = field(default_factory=dict)          # id -> Sgt
    sgacls: dict[str, Sgacl] = field(default_factory=dict)      # id -> Sgacl
    cells: dict[tuple[str, str], Cell] = field(default_factory=dict)  # (src name, dst name) -> Cell
    default: str = "deny"
    synced_at: datetime | None = None

    # --- lookups
    def sgt_by_name(self, name: str) -> Sgt | None:
        return next((s for s in self.sgts.values() if s.name == name), None)

    def sgt_by_value(self, value: int) -> Sgt | None:
        return next((s for s in self.sgts.values() if s.value == value), None)

    def sgacl_by_name(self, name: str) -> Sgacl | None:
        return next((a for a in self.sgacls.values() if a.name == name), None)

    def cell(self, src: str, dst: str) -> Cell | None:
        c = self.cells.get((src, dst))
        if c is None or c.status == "DISABLED":
            return None
        return c

    def cell_fingerprint(self, src: str, dst: str) -> str:
        c = self.cells.get((src, dst))
        return c.fingerprint() if c else NO_CELL_FINGERPRINT

    def cell_sgacls(self, src: str, dst: str) -> list[Sgacl]:
        c = self.cell(src, dst)
        if not c:
            return []
        return [self.sgacls[i] for i in c.sgacl_ids if i in self.sgacls]

    def contract_users(self, sgacl_id: str) -> list[tuple[str, str]]:
        """Pairs (src, dst) whose cell references this SGACL."""
        return [k for k, c in self.cells.items() if sgacl_id in c.sgacl_ids and c.status != "DISABLED"]

    # --- evaluation
    def evaluate(self, src: str, dst: str, spec: str, override: dict[str, str] | None = None) -> bool:
        """Would traffic ``spec`` from src to dst be permitted?

        ``override`` maps an SGACL id to a replacement content (used for impact analysis).
        Monitor cells count as permitted (they log instead of dropping).
        """
        if src in PSEUDO_GROUPS or dst in PSEUDO_GROUPS:
            return self.default == "permit"
        c = self.cell(src, dst)
        if c is None:
            return self.default == "permit"
        for sid in c.sgacl_ids:
            sg = self.sgacls.get(sid)
            if not sg:
                continue
            content = override.get(sid, sg.content) if override else sg.content
            verdict = acl.decision(acl.parse(content).rules, spec)
            if verdict == "permit":
                return True
            if verdict == "deny":
                return c.status == "MONITOR"
        if c.default_rule == "PERMIT_IP":
            return True
        if c.default_rule == "DENY_IP":
            return c.status == "MONITOR"
        return self.default == "permit" or c.status == "MONITOR"

    def coverage(self, src: str, dst: str, specs: list[str]) -> dict:
        covered = [s for s in specs if self.evaluate(src, dst, s)]
        c = self.cell(src, dst)
        if specs and len(covered) == len(specs):
            status = "allowed"          # every observed port is permitted by the matrix
        elif c and c.sgacl_ids:
            status = "partial"          # a contract exists on the cell but misses some ports
        else:
            status = "pending"          # nothing permits this pair: would be dropped by default-deny
        return {
            "status": status,
            "covered": covered,
            "uncovered": [s for s in specs if s not in covered],
            "contracts": [a.name for a in self.cell_sgacls(src, dst)],
            "monitor": bool(c and c.status == "MONITOR"),
        }
