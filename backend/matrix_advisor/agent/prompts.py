"""Prompts for the advisor. The model reasons on SGT names, ports and volumes only."""

from __future__ import annotations

import json

LANG = {"fr": "French", "en": "English", "de": "German", "es": "Spanish", "it": "Italian", "nl": "Dutch"}

SYSTEM = """You are a network security analyst helping an administrator move a Cisco TrustSec
(SD-Access) policy matrix to default-deny. For one source group -> destination group pair you
receive the traffic observed between them (ports, flow counts, number of source hosts, timing
behaviour) and the contract the deterministic engine proposes. You never see IP addresses.

Judge whether this traffic looks like a legitimate business flow that deserves an explicit permit,
or something to deny or investigate (lateral movement, beaconing, scanning, unusual access to data
stores, administrative access from the wrong group).

Answer with one JSON object and nothing else:
{"risk": "low" | "medium" | "high",
 "recommendation": "approve" | "review" | "reject",
 "justification": "<2 to 3 short sentences in LANGUAGE for the administrator, concrete, citing the signals>"}

"activity" tells on how many distinct days the pair was seen out of the days observed. Traffic seen
on very few days may be an infrequent but legitimate job (monthly batch, backups): say so, and warn
that ports it uses but that were not observed will be denied.

Rules: do not invent facts that are not in the input; if heuristic signals flag a risk, do not
rate the risk lower than they do; keep the justification under 60 words."""


def system_prompt(language: str) -> str:
    return SYSTEM.replace("LANGUAGE", LANG.get(language, language))


def user_prompt(features: dict, assessment: dict, proposal: dict) -> str:
    payload = {
        "pair": {"source_group": features["src"], "destination_group": features["dst"]},
        "observed": {
            "ports": features["ports"],
            "total_flows": features["total_flows"],
            "source_hosts": features["source_hosts"],
            "first_seen": features["first_seen"],
            "behaviour": features["behaviour"],
            "activity": features.get("activity") or {},
        },
        "existing_contract_on_cell": features.get("cell_contracts") or [],
        "proposal": {
            "kind": proposal["kind"],
            "base_contract": proposal.get("base_contract"),
            "sgacl": proposal.get("proposed_acl"),
        },
        "heuristic_signals": {"risk": assessment["risk"], "reasons": assessment["reasons"]},
    }
    return json.dumps(payload, ensure_ascii=False, indent=1, default=str)
