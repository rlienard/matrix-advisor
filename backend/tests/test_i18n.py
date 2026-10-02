from matrix_advisor.agent import risk
from matrix_advisor.agent.llm import PrivacyViolation, assert_no_ip
from matrix_advisor.i18n import CATALOG, Message, localize, message_of


def test_catalog_is_complete():
    for key, texts in CATALOG.items():
        assert set(texts) == {"fr", "en"}, key


def test_message_keeps_french_text_and_renders_english():
    m = Message("cell_read_failed", error=Message("ise_auth_refused"))
    assert m == "Lecture de la cellule impossible : Authentification refusée par ISE (vérifiez l’utilisateur ERS et son rôle)."
    assert m.render("en") == "Cannot read the cell: ISE refused the authentication (check the ERS user and its role)."
    try:
        assert_no_ip('{"host": "10.10.1.7"}')
    except PrivacyViolation as e:
        assert str(e).startswith("refus d’envoi")
        assert localize(e, "en") == "not sent: the message for the model contains an IP address"
        assert message_of(e).key == "llm_ipv4_refused"
    assert localize(ValueError("raw"), "en") == "raw" and localize(3, "en") == 3


def test_heuristic_reasons_follow_the_language():
    features = {"src": "Contractors", "dst": "HR_Servers", "ports": [{"spec": "TCP/22", "flows": 3, "hosts": 1}],
                "source_hosts": 4, "behaviour": {}, "total_flows": 3}
    a = risk.assess(features, "en")
    assert a["reasons"] == ["administration ports (SSH, RDP, WinRM…): restrict the contract to what is strictly needed"]
    assert risk.fallback_justification(features, a, "new", None, "en").startswith("3 flows observed. Administration ports")
    fr = risk.assess(features)
    assert fr["risk"] == a["risk"] and fr["reasons"][0].startswith("ports d’administration")


def test_former_justification_language_becomes_the_global_language(tmp_path):
    from matrix_advisor.config import ConfigStore

    path = tmp_path / "config.yaml"
    path.write_text("llm:\n  language: en\n")
    assert ConfigStore(path).settings.ui.language == "en"
    path.write_text("ui:\n  language: fr\nllm:\n  language: en\n")
    assert ConfigStore(path).settings.ui.language == "fr"  # an explicit ui.language wins
