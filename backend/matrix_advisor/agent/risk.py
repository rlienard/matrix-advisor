"""Deterministic risk heuristics.

Used to give the LLM grounded signals, and as the full answer when the LLM is offline.
"""

from __future__ import annotations

from ..policy import acl
from ..policy.matrix import INTERNET, UNKNOWN

# A pair seen on at most RARE_MAX_DAYS distinct days, out of at least RARE_MIN_WINDOW days of
# observation, is "rare": possibly a periodic job (monthly batch) whose ports were not all observed.
RARE_MAX_DAYS = 2
RARE_MIN_WINDOW = 7
# Observation needed before default-deny so that monthly jobs have run at least once.
MONTHLY_CYCLE_DAYS = 30


def is_rare(activity: dict | None) -> bool:
    a = activity or {}
    return a.get("observed_days", 0) >= RARE_MIN_WINDOW and 0 < a.get("days_seen", 0) <= RARE_MAX_DAYS


def assess(features: dict) -> dict:
    """Return {risk, recommendation, reasons[]} from pair features (no IP addresses)."""
    reasons: list[str] = []
    risk = "low"
    ports = [acl.parse_spec(p["spec"]) for p in features["ports"]]
    port_numbers = {lo for _, lo, _ in ports if lo}
    hosts = features["source_hosts"]
    beh = features.get("behaviour", {})

    def bump(level: str) -> None:
        nonlocal risk
        order = ["low", "medium", "high"]
        if order.index(level) > order.index(risk):
            risk = level

    if features["dst"] == INTERNET and beh.get("periodic_host_pairs"):
        bump("high")
        reasons.append(
            f"connexions à intervalle régulier (~{beh.get('periodic_interval_s')} s) depuis "
            f"{beh['periodic_host_pairs']} hôte(s) vers une destination externe : ressemble à du beaconing"
        )
    elif beh.get("periodic_host_pairs") and beh["periodic_host_pairs"] == beh.get("host_pairs") and hosts <= 3:
        bump("medium")
        reasons.append("trafic strictement périodique depuis peu d’hôtes")

    if port_numbers & acl.DB_PORTS and hosts <= 3 and "admin" not in features["src"].lower():
        bump("high")
        reasons.append(f"accès direct à une base de données depuis seulement {hosts} poste(s)")
    if beh.get("off_hours_ratio", 0) >= 0.4:
        bump("medium")
        reasons.append(f"{int(beh['off_hours_ratio'] * 100)} % du trafic hors heures ouvrées")
    if port_numbers & acl.ADMIN_PORTS:
        bump("medium")
        reasons.append("ports d’administration (SSH, RDP, WinRM…) : contrat à restreindre au strict nécessaire")
    if len(ports) > 8:
        bump("medium")
        reasons.append(f"{len(ports)} ports distincts : vérifier qu’il ne s’agit pas d’un scan")
    act = features.get("activity") or {}
    if is_rare(act):
        bump("medium")
        last = act.get("last_seen_days_ago")
        since = f", dernier flux il y a {last} jour(s)" if last else ""
        reasons.append(
            f"trafic rare : vu {act['days_seen']} jour(s) sur {act['observed_days']} jours d’observation{since} ; "
            "vérifier qu’il s’agit d’un besoin récurrent (traitement mensuel ?) et que tous ses ports ont été vus"
        )
    if features["src"] == UNKNOWN or features["dst"] == UNKNOWN:
        bump("medium")
        reasons.append("adresses sans SGT : vérifier l’affectation des endpoints dans ISE")

    if not reasons:
        reasons.append(
            f"profil régulier réparti sur {hosts} hôte(s) source, ports cohérents avec un service applicatif"
        )
    recommendation = {"low": "approve", "medium": "review", "high": "reject"}[risk]
    return {"risk": risk, "recommendation": recommendation, "reasons": reasons}


def fallback_justification(features: dict, assessment: dict, kind: str, base: str | None) -> str:
    total = features["total_flows"]
    lead = {
        "extend": f"La cellule contient déjà {base} ; seuls les ports nouveaux sont ajoutés.",
        "reuse": f"Le contrat existant {base} couvre déjà ces ports : réutilisation plutôt qu’une nouvelle SGACL.",
        "new": "Aucun contrat existant ne couvre ces ports : nouvelle SGACL au plus juste.",
        "external": "Destination ou source sans SGT : à traiter par une politique de sortie (pare-feu), "
                    "pas par la matrice TrustSec.",
    }[kind]
    reasons = "; ".join(assessment["reasons"])
    return f"{total} flux observés. {reasons[0].upper() + reasons[1:]}. {lead}"
