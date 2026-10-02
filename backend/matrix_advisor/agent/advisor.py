"""The advisor: turns uncovered SGT pairs into contract proposals.

Deterministic first: coverage against the ISE matrix, choice between extending the cell's
contract, reusing an existing contract or creating a least-privilege one. The LLM only adds a
risk opinion and a human-readable justification; heuristics remain the floor.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta

from ..config import ConfigStore
from ..ise.service import ISEService
from ..policy import acl
from ..policy.impact import new_contract_name
from ..policy.matrix import PSEUDO_GROUPS, Matrix
from ..store import Store, utcnow
from . import prompts, risk
from .llm import LLMClient, LLMError

log = logging.getLogger(__name__)

RISK_ORDER = ["low", "medium", "high"]
MAX_LLM_CALLS_PER_RUN = 10
RANGES = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}


class LLMHolder:
    """Keeps an LLM client in sync with the configuration."""

    def __init__(self, config: ConfigStore):
        self.config = config
        self.client = LLMClient(config.settings.llm)
        self.status = {"online": None, "last_check": None, "error": None, "latency_ms": None}
        config.on_change(self._on_change)

    def _on_change(self, old, new) -> None:
        if old.llm != new.llm:
            self.client = LLMClient(new.llm)
            self.status.update(online=None, error=None)

    async def check(self) -> None:
        try:
            res = await self.client.ping()
            self.status.update(online=True, error=None, latency_ms=res["latency_ms"])
        except LLMError as e:
            self.status.update(online=False, error=str(e))
        self.status["last_check"] = utcnow()

    async def run(self) -> None:
        while True:
            await self.check()
            await asyncio.sleep(120 if self.status["online"] else 30)


class Advisor:
    def __init__(self, config: ConfigStore, store: Store, ise: ISEService, llm: LLMHolder):
        self.config = config
        self.store = store
        self.ise = ise
        self.llm = llm
        self.last_run: datetime | None = None
        self._wake = asyncio.Event()

    # ------------------------------------------------------------ learning phase
    def learning(self) -> dict:
        started = self.store.get_meta("learning_started")
        if not started:
            if self.store.last_record_ts() is None:
                return {"active": True, "started": None, "ends_at": None}
            started = utcnow().isoformat()
            self.store.set_meta("learning_started", started)
        start = datetime.fromisoformat(started)
        ends = start + timedelta(days=self.config.settings.llm.learning_days)
        return {"active": utcnow() < ends, "started": start, "ends_at": ends}

    # ------------------------------------------------------------ observations
    def observed(self, since: datetime) -> dict[tuple[str, str], dict]:
        pairs: dict[tuple[str, str], dict] = {}
        for row in self.store.pair_ports(since):
            key = (row["src"], row["dst"])
            p = pairs.setdefault(key, {"src": key[0], "dst": key[1], "ports": [], "flows": 0, "bytes": 0})
            p["ports"].append({
                "spec": acl.make_spec(row["proto"], row["port"]), "flows": row["flows"], "hosts": row["hosts"],
                "first_seen": row["first_seen"], "last_seen": row["last_seen"],
            })
            p["flows"] += row["flows"]
            p["bytes"] += row["bytes"]
        hosts = self.store.pair_hosts(since)
        first = self.store.first_seen()
        for key, p in pairs.items():
            p["hosts"] = hosts.get(key, 0)
            p["first_seen"] = first.get(key)
            p["ports"].sort(key=lambda x: -x["flows"])
        return pairs

    def observed_ports(self, since: datetime) -> dict[tuple[str, str], list[dict]]:
        return {k: v["ports"] for k, v in self.observed(since).items()}

    # ------------------------------------------------------------ proposal building
    def _choose_base(self, m: Matrix, src: str, dst: str):
        prefix = self.config.settings.ise.sgacl_prefix
        candidates = [a for a in m.cell_sgacls(src, dst) if not a.read_only]
        owned = [a for a in candidates if a.name.startswith(prefix)]
        return (owned or candidates or [None])[0]

    def _reusable(self, m: Matrix, specs: list[str], dst: str):
        """Existing contract covering every observed port with at most 2 extra permits.

        Contracts already used towards the same destination group win (Web_Access for a new
        client of Web_Servers), then the one opening the fewest unobserved ports.
        """
        best, best_score = None, None
        for a in m.sgacls.values():
            rules = a.rules
            if not rules or acl.has_permit_any(rules):
                continue
            if not all(acl.allows(rules, s) for s in specs):
                continue
            extra = len(acl.permitted_specs(rules) - set(specs))
            if extra > 2:
                continue
            same_dst = any(d == dst for _, d in m.contract_users(a.id))
            score = (0 if same_dst else 1, extra)
            if best_score is None or score < best_score:
                best, best_score = a, score
        return best

    async def build(self, obs: dict, cov: dict) -> dict:
        m = self.ise.matrix
        settings = self.config.settings
        src, dst = obs["src"], obs["dst"]
        specs = [p["spec"] for p in obs["ports"]]
        base = None
        mode = None
        if src in PSEUDO_GROUPS or dst in PSEUDO_GROUPS:
            kind, proposed = "external", ""
        elif cov["status"] == "partial" and (base := self._choose_base(m, src, dst)):
            kind = "extend"
            proposed = acl.extend(base.content, cov["uncovered"])
            others = [p for p in m.contract_users(base.id) if p != (src, dst)]
            mode = "clone" if others else "inplace"
        elif base := self._reusable(m, specs, dst):
            kind, proposed = "reuse", base.content
        else:
            kind = "new"
            proposed = acl.generate(specs, log=True)

        features = {
            "src": src, "dst": dst,
            "ports": [{"spec": p["spec"], "flows": p["flows"], "hosts": p["hosts"]} for p in obs["ports"]],
            "total_flows": obs["flows"], "source_hosts": obs["hosts"],
            "first_seen": obs["first_seen"].date().isoformat() if obs.get("first_seen") else None,
            "behaviour": self.store.pair_behaviour(src, dst, utcnow() - timedelta(days=7)),
            "cell_contracts": cov["contracts"],
        }
        assessment = risk.assess(features)
        proposal = {
            "src": src, "dst": dst, "kind": kind, "base_contract": base.name if base else None,
            "base_sgacl_id": base.id if base else None, "specs": specs, "proposed_acl": proposed,
            "edited_acl": None, "status": "pending", "mode": mode,
            "cell_fingerprint": m.cell_fingerprint(src, dst),
            "risk": assessment["risk"], "recommendation": assessment["recommendation"],
            "justification": risk.fallback_justification(features, assessment, kind, base.name if base else None),
            "features": {**features, "heuristics": assessment["reasons"],
                         "new_name": new_contract_name(settings.ise.sgacl_prefix, src, dst,
                                                       {a.name for a in m.sgacls.values()})},
            "llm_used": False,
        }
        return proposal

    async def enrich_with_llm(self, proposal: dict) -> dict:
        features = proposal["features"]
        assessment = {"risk": proposal["risk"], "reasons": features["heuristics"]}
        try:
            out = await self.llm.client.complete_json(
                prompts.system_prompt(self.config.settings.llm.language),
                prompts.user_prompt(features, assessment, proposal),
            )
        except LLMError as e:
            log.info("LLM unavailable, heuristic proposal kept: %s", e)
            return proposal
        llm_risk = out.get("risk") if out.get("risk") in RISK_ORDER else proposal["risk"]
        # Heuristics are a floor: the model may raise the risk, never lower it.
        final = max(llm_risk, proposal["risk"], key=RISK_ORDER.index)
        proposal["risk"] = final
        rec = out.get("recommendation")
        if rec in ("approve", "review", "reject"):
            proposal["recommendation"] = rec if final == llm_risk else proposal["recommendation"]
        if isinstance(out.get("justification"), str) and out["justification"].strip():
            proposal["justification"] = out["justification"].strip()
        proposal["llm_used"] = True
        return proposal

    # ------------------------------------------------------------ main loop
    def pair_views(self, since: datetime) -> list[dict]:
        m = self.ise.matrix
        out = []
        for key, obs in self.observed(since).items():
            cov = m.coverage(*key, [p["spec"] for p in obs["ports"]])
            out.append({**obs, "coverage": cov})
        return out

    async def analyse(self) -> int:
        """Create or refresh proposals for uncovered pairs. Returns the number created."""
        if self.ise.matrix.synced_at is None:
            return 0
        views = self.pair_views(utcnow() - RANGES["7d"])
        allowed = sum(1 for v in views if v["coverage"]["status"] == "allowed")
        partial = sum(1 for v in views if v["coverage"]["status"] == "partial")
        self.store.record_coverage(len(views), allowed, partial, len(views) - allowed - partial)
        if self.learning()["active"]:
            return 0
        created = 0
        llm_calls = 0
        for v in sorted(views, key=lambda x: -x["flows"]):
            cov = v["coverage"]
            src, dst = v["src"], v["dst"]
            open_p = self.store.open_proposal_for(src, dst)
            if cov["status"] == "allowed":
                if open_p:  # covered meanwhile (e.g. fixed directly in ISE)
                    self.store.save_proposal({**open_p, "status": "superseded"})
                continue
            uncovered = set(cov["uncovered"])
            if open_p:
                if set(open_p["specs"]) >= {p["spec"] for p in v["ports"]} or open_p.get("edited_acl"):
                    continue
                self.store.save_proposal({**open_p, "status": "superseded"})
            else:
                last = self.store.last_decision_for(src, dst)
                if last and last["status"] == "rejected" and uncovered <= set(last["specs"] or []):
                    continue
            proposal = await self.build(v, cov)
            if llm_calls < MAX_LLM_CALLS_PER_RUN:
                proposal = await self.enrich_with_llm(proposal)
                llm_calls += 1
            self.store.save_proposal(proposal)
            created += 1
            log.info("proposal %s %s -> %s (%s, risk %s)", proposal["kind"], src, dst,
                     ",".join(proposal["specs"]), proposal["risk"])
        self.last_run = utcnow()
        return created

    def wake(self) -> None:
        self._wake.set()

    async def run(self) -> None:
        while True:
            try:
                await self.analyse()
            except Exception:  # noqa: BLE001
                log.exception("advisor run failed")
            llm = self.config.settings.llm
            delay = self.config.settings.collector.aggregation_seconds if llm.trigger == "event" \
                else llm.scheduled_minutes * 60
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass
            self._wake.clear()
