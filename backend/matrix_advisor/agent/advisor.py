"""The advisor: turns uncovered SGT pairs into contract proposals.

Deterministic first: coverage against the ISE matrix, choice between extending the cell's
contract, reusing an existing contract or creating a least-privilege one. The LLM only adds a
risk opinion and a human-readable justification; heuristics remain the floor.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta

from ..config import ConfigStore
from ..i18n import message_of
from ..ise.service import ISEService
from ..policy import acl
from ..policy.impact import new_contract_name
from ..policy.matrix import Matrix
from ..store import Store, utcnow
from . import prompts, risk
from .llm import LLMClient, LLMError, PrivacyViolation

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
        self.on_online = None  # called when the model answers again after being unreachable
        config.on_change(self._on_change)

    def _on_change(self, old, new) -> None:
        if old.llm != new.llm:
            self.client = LLMClient(new.llm)
            self.status.update(online=None, error=None)

    def mark(self, error: Exception | None = None, latency_ms: int | None = None) -> None:
        """Record the outcome of a call to the model (health check or real use).

        A call that gets no answer before the timeout turns the status red at once; the next
        answer turns it green again.
        """
        was_online = self.status["online"]
        if error is None:
            self.status.update(online=True, error=None)
            if latency_ms is not None:
                self.status["latency_ms"] = latency_ms
            if not was_online and self.on_online:
                self.on_online()
        else:
            self.status.update(online=False, error=message_of(error))
        self.status["last_check"] = utcnow()

    async def check(self) -> None:
        try:
            res = await self.client.ping()
        except LLMError as e:
            self.mark(e)
            return
        self.mark(latency_ms=res["latency_ms"])

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
        self.last_duration_s: float | None = None
        self._wake = asyncio.Event()
        llm.on_online = self.wake
        config.on_change(self._on_change)

    def _on_change(self, old, new) -> None:
        if old.ui.language != new.ui.language:
            self.wake()  # proposals are rewritten in the new language on the next run

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
        activity = self.store.pair_activity(since)
        observed_days = self.observed_days(since)
        today = utcnow().date()
        for key, p in pairs.items():
            p["hosts"] = hosts.get(key, 0)
            p["first_seen"] = first.get(key)
            p["ports"].sort(key=lambda x: -x["flows"])
            a = activity.get(key)
            p["activity"] = {
                "days_seen": a["days_seen"] if a else 0, "observed_days": observed_days,
                "last_seen_days_ago": (today - a["last_day"]).days if a else None,
            }
            p["rare"] = risk.is_rare(p["activity"])
        return pairs

    def observed_days(self, since: datetime) -> int:
        """Days of traffic history available since ``since`` (today included)."""
        start = self.store.observation_start()
        if start is None:
            return 0
        return (utcnow().date() - max(start, since).date()).days + 1

    def analysis_window(self) -> timedelta:
        """Proposals cover every pair still in the daily rollups, so that a monthly job seen weeks
        ago is not denied by default-deny just because it fell out of the last 7 days."""
        return timedelta(days=max(7, self.config.settings.collector.retention_days))

    def observation(self) -> dict:
        """Is the history long enough for monthly jobs to have been seen before default-deny?"""
        retention = self.config.settings.collector.retention_days
        days = self.observed_days(utcnow() - timedelta(days=retention))
        return {"days": days, "recommended_days": risk.MONTHLY_CYCLE_DAYS, "retention_days": retention,
                "sufficient": days >= risk.MONTHLY_CYCLE_DAYS}

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
        to_unknown = dst == m.unknown_name
        firewall = settings.ise.egress_firewall
        if not m.sgt_by_name(src) or not m.sgt_by_name(dst):
            kind, proposed = "external", ""  # no SGT in ISE on one side: no cell can carry it
        elif cov["status"] == "partial" and (base := self._choose_base(m, src, dst)):
            kind = "extend"
            proposed = acl.extend(base.content, cov["uncovered"])
            others = [p for p in m.contract_users(base.id) if p != (src, dst)]
            mode = "clone" if others else "inplace"
        elif to_unknown:
            # SGT 0 is mostly Internet-bound traffic. Behind an egress firewall, which does the fine
            # filtering, the cell stays permissive (the built-in Permit IP when ISE has it); without
            # one, the matrix is the only control: least privilege as for any other pair.
            kind = "unknown"
            if firewall:
                base = m.permit_ip()
                proposed = base.content if base else "permit ip"
            else:
                proposed = acl.generate(specs, log=True)
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
            "behaviour": await asyncio.to_thread(self.store.pair_behaviour, src, dst, utcnow() - timedelta(days=7)),
            "activity": obs.get("activity") or {},
            "cell_contracts": cov["contracts"],
            "src_unknown": src == m.unknown_name, "dst_unknown": to_unknown,
            "egress_firewall": firewall,
        }
        lang = settings.ui.language
        assessment = risk.assess(features, lang)
        proposal = {
            "src": src, "dst": dst, "kind": kind, "base_contract": base.name if base else None,
            "base_sgacl_id": base.id if base else None, "specs": specs, "proposed_acl": proposed,
            "edited_acl": None, "status": "pending", "mode": mode,
            "cell_fingerprint": m.cell_fingerprint(src, dst),
            "risk": assessment["risk"], "recommendation": assessment["recommendation"],
            "justification": risk.fallback_justification(features, assessment, kind, base.name if base else None, lang),
            "features": {**features, "heuristics": assessment["reasons"], "language": lang,
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
                prompts.system_prompt(self.config.settings.ui.language),
                prompts.user_prompt(features, assessment, proposal),
            )
        except LLMError as e:
            log.info("LLM unavailable, heuristic proposal kept: %s", e)
            if not isinstance(e, PrivacyViolation):
                self.llm.mark(e)
            return proposal
        self.llm.mark()
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
        started = utcnow()
        # Database scans run in a worker thread: the event loop keeps serving the API meanwhile.
        views = await asyncio.to_thread(self.pair_views, utcnow() - self.analysis_window())
        allowed = sum(1 for v in views if v["coverage"]["status"] == "allowed")
        partial = sum(1 for v in views if v["coverage"]["status"] == "partial")
        self.store.record_coverage(len(views), allowed, partial, len(views) - allowed - partial)
        if self.learning()["active"]:
            return 0
        created = 0
        llm_calls = 0
        pending = {(p["src"], p["dst"]): p for p in await asyncio.to_thread(self.store.proposals, "pending")}
        for v in sorted(views, key=lambda x: -x["flows"]):
            cov = v["coverage"]
            src, dst = v["src"], v["dst"]
            open_p = pending.get((src, dst))
            # ``pending`` was read before the loop: a proposal decided or edited since then is left alone.
            if cov["status"] == "allowed":
                if open_p:  # covered meanwhile (e.g. fixed directly in ISE)
                    self.store.save_proposal_if_unchanged({**open_p, "status": "superseded"}, open_p["updated_at"])
                continue
            uncovered = set(cov["uncovered"])
            if open_p:
                if set(open_p["specs"]) >= {p["spec"] for p in v["ports"]} or open_p.get("edited_acl"):
                    continue
                if self.store.save_proposal_if_unchanged({**open_p, "status": "superseded"},
                                                         open_p["updated_at"]) is None:
                    continue
            else:
                if self.store.open_proposal_for(src, dst):  # reopened meanwhile
                    continue
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
        await self.refresh_open(MAX_LLM_CALLS_PER_RUN - llm_calls)
        self.last_duration_s = round((utcnow() - started).total_seconds(), 3)
        self.last_run = utcnow()
        return created

    async def translate(self, text: str, language: str) -> str | None:
        """The model's translation of a justification, or None if it does not answer."""
        try:
            out = await self.llm.client.complete_json(prompts.translate_prompt(language),
                                                      json.dumps({"justification": text}, ensure_ascii=False))
        except LLMError as e:
            log.info("LLM unavailable, translation postponed: %s", e)
            if not isinstance(e, PrivacyViolation):
                self.llm.mark(e)
            return None
        self.llm.mark()
        text = out.get("justification")
        return text.strip() if isinstance(text, str) and text.strip() else None

    async def refresh_open(self, budget: int) -> int:
        """Bring stored analyses up to date. Returns the LLM calls made.

        - Pending proposals written in another language than ``ui.language``, or heuristic-only although
          the LLM now answers (it was down when they were created), are re-analysed: risk,
          recommendation, justification and reasons change; the SGACL, the edit, the mode and the id stay.
        - Decided proposals (approved, rejected) written in another language are translated: only the
          text changes, never the risk or recommendation the decision was taken on.
        A text written by the model is never replaced by bare heuristics: without an answer it waits.
        """
        language = self.config.settings.ui.language
        online = bool(self.llm.status["online"])
        calls = 0
        todo = [p for p in self.store.proposals() if p["status"] != "superseded"]
        todo.sort(key=lambda p: p["status"] != "pending")  # pending first: they still need a decision
        for p in todo:
            features = p["features"] or {}
            # Proposals created before the language was stamped were written in the default, French.
            stale_lang = features.get("language", "fr") != language
            pending = p["status"] == "pending"
            if not stale_lang and (not pending or p["llm_used"] or not online):
                continue
            if p["llm_used"] and not (online and calls < budget):
                continue  # rewriting only the heuristics would drop the model's text: wait for it
            assessment = risk.assess(features, language)
            new = {**p, "features": {**features, "heuristics": assessment["reasons"], "language": language}}
            if pending:
                new.update(risk=assessment["risk"], recommendation=assessment["recommendation"], llm_used=False,
                           justification=risk.fallback_justification(features, assessment, p["kind"],
                                                                     p["base_contract"], language))
                if online and calls < budget:
                    new = await self.enrich_with_llm(new)
                    calls += 1
                    online = new["llm_used"]  # no answer: do not insist during this run
                if p["llm_used"] and not new["llm_used"]:
                    continue
                if not new["llm_used"] and not stale_lang:
                    continue  # nothing new without the model
            elif p["llm_used"]:
                text = await self.translate(p["justification"], language)
                calls += 1
                if text is None:
                    online = False
                    continue
                new["justification"] = text
            else:
                new["justification"] = risk.fallback_justification(features, assessment, p["kind"],
                                                                   p["base_contract"], language)
            # The administrator may have decided or edited it while the model was answering.
            if self.store.save_proposal_if_unchanged(new, p["updated_at"]) is None:
                continue
            log.info("proposal %s -> %s (%s) rewritten in %s (%s)", p["src"], p["dst"], p["status"], language,
                     "llm" if new["llm_used"] else "heuristics")
        return calls

    def wake(self) -> None:
        self._wake.set()

    async def run(self) -> None:
        while True:
            try:
                await self.analyse()
            except Exception:
                log.exception("advisor run failed")
            llm = self.config.settings.llm
            delay = self.config.settings.collector.aggregation_seconds if llm.trigger == "event" \
                else llm.scheduled_minutes * 60
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=delay)
            except TimeoutError:
                pass
            self._wake.clear()
