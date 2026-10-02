"""User-facing messages in French and English.

API error messages and connection-test results are rendered in the global ``ui.language`` setting
(French by default). Errors raised deep in the code carry a :class:`Message`, a ``str`` holding the
French text (so logs and ``str(e)`` keep working) plus the key and parameters needed to render it
again in another language at the API boundary.
"""

from __future__ import annotations

from typing import Literal, Self

Lang = Literal["fr", "en"]
DEFAULT: Lang = "fr"

CATALOG: dict[str, dict[Lang, str]] = {
    # authentication
    "auth_required": {"fr": "Authentification requise.", "en": "Authentication required."},
    "wrong_password": {"fr": "Mot de passe incorrect.", "en": "Incorrect password."},
    # proposals
    "proposal_not_found": {"fr": "Proposition introuvable.", "en": "Proposal not found."},
    "proposal_decided": {"fr": "Proposition déjà traitée ({status}).", "en": "Proposal already decided ({status})."},
    "acl_has_errors": {"fr": "La SGACL contient des erreurs.", "en": "The SGACL contains errors."},
    "unknown_mode": {"fr": "Mode inconnu.", "en": "Unknown mode."},
    "reopen_rejected_only": {"fr": "Seule une proposition rejetée peut être rouverte.",
                             "en": "Only a rejected proposal can be reopened."},
    "external_no_cell": {
        "fr": "Source ou destination sans SGT : aucune cellule TrustSec ne peut porter ce contrat. "
              "Traitez ce flux sur le pare-feu de sortie, ou rejetez la proposition.",
        "en": "Source or destination without an SGT: no TrustSec cell can carry this contract. "
              "Handle this flow on the egress firewall, or reject the proposal.",
    },
    "inplace_refused": {"fr": "Modification sur place refusée : elle bloquerait du trafic d’autres paires.",
                        "en": "In-place change refused: it would block traffic of other pairs."},
    "unknown_sgt": {"fr": "SGT inconnu dans ISE : resynchronisez la matrice.",
                    "en": "SGT unknown to ISE: resynchronise the matrix."},
    "cell_read_failed": {"fr": "Lecture de la cellule impossible : {error}", "en": "Cannot read the cell: {error}"},
    "cell_changed": {"fr": "La cellule a été modifiée dans ISE depuis la proposition. Rien n’a été écrit.",
                     "en": "The cell was changed in ISE since the proposal. Nothing was written."},
    "sgacl_changed": {"fr": "{name} a été modifié dans ISE depuis la proposition.",
                      "en": "{name} was changed in ISE since the proposal."},
    "ise_write_refused": {"fr": "Écriture refusée par ISE : {error}", "en": "ISE refused the write: {error}"},
    # ISE / pxGrid
    "ise_auth_refused": {"fr": "Authentification refusée par ISE (vérifiez l’utilisateur ERS et son rôle).",
                         "en": "ISE refused the authentication (check the ERS user and its role)."},
    "pxgrid_unauthorized": {"fr": "{op}: non autorisé (compte pxGrid « {client} » inconnu ou refusé).",
                            "en": "{op}: unauthorised (pxGrid account “{client}” unknown or refused)."},
    "pxgrid_service_missing": {"fr": "service {service} introuvable (pxGrid activé ? compte approuvé ?)",
                               "en": "service {service} not found (pxGrid enabled? account approved?)"},
    "pxgrid_pubsub_missing": {"fr": "service pubsub introuvable", "en": "pubsub service not found"},
    "pxgrid_account_state": {"fr": "compte pxGrid {state} : approuvez « {client} » dans ISE",
                             "en": "pxGrid account {state}: approve “{client}” in ISE"},
    # LLM
    "llm_ipv4_refused": {"fr": "refus d’envoi : le message destiné au modèle contient une adresse IP",
                         "en": "not sent: the message for the model contains an IP address"},
    "llm_ipv6_refused": {"fr": "refus d’envoi : le message destiné au modèle contient une adresse IPv6",
                         "en": "not sent: the message for the model contains an IPv6 address"},
    "llm_not_json": {"fr": "réponse du modèle non JSON : {text}", "en": "model answer is not JSON: {text}"},
    "llm_model_missing": {"fr": "modèle {model} absent d’Ollama (ollama pull {model})",
                          "en": "model {model} not found in Ollama (ollama pull {model})"},
    # connection tests (Settings)
    "test_llm_ok_cloud": {
        "fr": "API joignable · modèle {model} disponible · {ms} ms. Aucune donnée réseau envoyée pendant le test.",
        "en": "API reachable · model {model} available · {ms} ms. No network data was sent during the test.",
    },
    "test_llm_ok_local": {
        "fr": "Endpoint joignable · modèle {model} disponible · {ms} ms. Aucune donnée réseau envoyée pendant le test.",
        "en": "Endpoint reachable · model {model} available · {ms} ms. No network data was sent during the test.",
    },
    "test_openapi_ok": {"fr": "OpenAPI : authentifié sur {pan} · {sgts} SGT.",
                        "en": "OpenAPI: authenticated on {pan} · {sgts} SGTs."},
    "test_openapi_failed": {"fr": "OpenAPI : {error}", "en": "OpenAPI: {error}"},
    "test_pxgrid_ok": {"fr": "pxGrid : client « {client} » approuvé.", "en": "pxGrid: client “{client}” approved."},
    "test_pxgrid_pending": {"fr": "pxGrid : compte {state}, à approuver dans ISE (Administration > pxGrid).",
                            "en": "pxGrid: account {state}, to approve in ISE (Administration > pxGrid)."},
    "test_pxgrid_failed": {"fr": "pxGrid : {error}", "en": "pxGrid: {error}"},
    "test_tls_unverified": {"fr": "Attention : certificat TLS non vérifié.",
                            "en": "Warning: TLS certificate not verified."},
    "test_exporters_invalid": {"fr": "Exporteurs autorisés invalides : {error}",
                               "en": "Invalid allowed exporters: {error}"},
    "test_goflow_missing": {
        "fr": "Aucune sortie GoFlow2 trouvée ({path}). GoFlow2 est-il démarré avec -transport.file sur ce chemin ?",
        "en": "No GoFlow2 output found ({path}). Is GoFlow2 running with -transport.file on this path?",
    },
    "test_goflow_stale": {
        "fr": "GoFlow2 n’a rien écrit depuis {age} s : aucun flux reçu sur les ports {ipfix}/{v9} ?",
        "en": "GoFlow2 has written nothing for {age} s: no flows received on ports {ipfix}/{v9}?",
    },
    "test_goflow_ok": {"fr": "GoFlow2 actif · environ {rate} flux/s agrégés · dernier flux {last} UTC.",
                       "en": "GoFlow2 running · about {rate} flows/s aggregated · last flow {last} UTC."},
    "test_goflow_waiting": {"fr": "GoFlow2 actif, en attente des premiers flux.",
                            "en": "GoFlow2 running, waiting for the first flows."},
}


def _render(key: str, lang: str, params: dict) -> str:
    texts = CATALOG[key]
    text = texts.get(lang) or texts[DEFAULT]
    return text.format(**{k: localize(v, lang) for k, v in params.items()}) if params else text


class Message(str):
    """A catalog message: the French text, re-renderable in another language with :meth:`render`."""

    key: str
    params: dict

    def __new__(cls, key: str, **params) -> Self:
        obj = super().__new__(cls, _render(key, DEFAULT, params))
        obj.key, obj.params = key, params
        return obj

    def render(self, lang: str) -> str:
        return _render(self.key, lang, self.params)


def localize(value, lang: str):
    """Render a Message (or an exception carrying one) in ``lang``; other values are returned unchanged."""
    if isinstance(value, BaseException):
        arg = value.args[0] if value.args else None
        return arg.render(lang) if isinstance(arg, Message) else str(value)
    if isinstance(value, Message):
        return value.render(lang)
    return value


def message_of(e: BaseException) -> str:
    """The exception's Message when it carries one (kept for later localisation), else ``str(e)``."""
    arg = e.args[0] if e.args else None
    return arg if isinstance(arg, Message) else str(e)
