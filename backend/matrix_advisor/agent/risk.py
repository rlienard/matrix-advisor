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


TEXTS = {
    "fr": {
        "beaconing": "connexions à intervalle régulier (~{interval} s) depuis {pairs} hôte(s) vers une destination "
                     "externe : ressemble à du beaconing",
        "periodic": "trafic strictement périodique depuis peu d’hôtes",
        "db": "accès direct à une base de données depuis seulement {hosts} poste(s)",
        "off_hours": "{pct} % du trafic hors heures ouvrées",
        "admin": "ports d’administration (SSH, RDP, WinRM…) : contrat à restreindre au strict nécessaire",
        "scan": "{n} ports distincts : vérifier qu’il ne s’agit pas d’un scan",
        "rare_since": ", dernier flux il y a {days} jour(s)",
        "rare": "trafic rare : vu {seen} jour(s) sur {observed} jours d’observation{since} ; vérifier qu’il s’agit "
                "d’un besoin récurrent (traitement mensuel ?) et que tous ses ports ont été vus",
        "unknown": "adresses sans SGT : vérifier l’affectation des endpoints dans ISE",
        "regular": "profil régulier réparti sur {hosts} hôte(s) source, ports cohérents avec un service applicatif",
        "extend": "La cellule contient déjà {base} ; seuls les ports nouveaux sont ajoutés.",
        "reuse": "Le contrat existant {base} couvre déjà ces ports : réutilisation plutôt qu’une nouvelle SGACL.",
        "new": "Aucun contrat existant ne couvre ces ports : nouvelle SGACL au plus juste.",
        "external": "Destination ou source sans SGT : à traiter par une politique de sortie (pare-feu), "
                    "pas par la matrice TrustSec.",
        "summary": "{total} flux observés. {reasons}. {lead}",
    },
    "en": {
        "beaconing": "connections at a regular interval (~{interval} s) from {pairs} host(s) to an external "
                     "destination: looks like beaconing",
        "periodic": "strictly periodic traffic from few hosts",
        "db": "direct database access from only {hosts} workstation(s)",
        "off_hours": "{pct} % of the traffic outside business hours",
        "admin": "administration ports (SSH, RDP, WinRM…): restrict the contract to what is strictly needed",
        "scan": "{n} distinct ports: check that this is not a scan",
        "rare_since": ", last flow {days} day(s) ago",
        "rare": "rare traffic: seen on {seen} day(s) out of {observed} days of observation{since}; check that it "
                "is a recurring need (monthly job?) and that all its ports have been seen",
        "unknown": "addresses without an SGT: check endpoint assignment in ISE",
        "regular": "regular profile spread over {hosts} source host(s), ports consistent with an application service",
        "extend": "The cell already holds {base}; only the new ports are added.",
        "reuse": "The existing contract {base} already covers these ports: reused rather than a new SGACL.",
        "new": "No existing contract covers these ports: new least-privilege SGACL.",
        "external": "Destination or source without an SGT: handle it with an egress (firewall) policy, "
                    "not with the TrustSec matrix.",
        "summary": "{total} flows observed. {reasons}. {lead}",
    },
}


def _t(lang: str, key: str, **params) -> str:
    return TEXTS.get(lang, TEXTS["en"])[key].format(**params)


def assess(features: dict, lang: str = "fr") -> dict:
    """Return {risk, recommendation, reasons[]} from pair features (no IP addresses).

    ``reasons`` are written in ``lang`` (fr or en): they are shown to the administrator.
    """
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
        reasons.append(_t(lang, "beaconing", interval=beh.get("periodic_interval_s"),
                          pairs=beh["periodic_host_pairs"]))
    elif beh.get("periodic_host_pairs") and beh["periodic_host_pairs"] == beh.get("host_pairs") and hosts <= 3:
        bump("medium")
        reasons.append(_t(lang, "periodic"))

    if port_numbers & acl.DB_PORTS and hosts <= 3 and "admin" not in features["src"].lower():
        bump("high")
        reasons.append(_t(lang, "db", hosts=hosts))
    if beh.get("off_hours_ratio", 0) >= 0.4:
        bump("medium")
        reasons.append(_t(lang, "off_hours", pct=int(beh["off_hours_ratio"] * 100)))
    if port_numbers & acl.ADMIN_PORTS:
        bump("medium")
        reasons.append(_t(lang, "admin"))
    if len(ports) > 8:
        bump("medium")
        reasons.append(_t(lang, "scan", n=len(ports)))
    act = features.get("activity") or {}
    if is_rare(act):
        bump("medium")
        last = act.get("last_seen_days_ago")
        since = _t(lang, "rare_since", days=last) if last else ""
        reasons.append(_t(lang, "rare", seen=act["days_seen"], observed=act["observed_days"], since=since))
    if features["src"] == UNKNOWN or features["dst"] == UNKNOWN:
        bump("medium")
        reasons.append(_t(lang, "unknown"))

    if not reasons:
        reasons.append(_t(lang, "regular", hosts=hosts))
    recommendation = {"low": "approve", "medium": "review", "high": "reject"}[risk]
    return {"risk": risk, "recommendation": recommendation, "reasons": reasons}


def fallback_justification(features: dict, assessment: dict, kind: str, base: str | None, lang: str = "fr") -> str:
    reasons = "; ".join(assessment["reasons"])
    return _t(lang, "summary", total=features["total_flows"], reasons=reasons[0].upper() + reasons[1:],
              lead=_t(lang, kind, base=base))
