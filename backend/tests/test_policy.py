from matrix_advisor.policy import acl
from matrix_advisor.policy.impact import clone_name, impact_of_change
from matrix_advisor.policy.matrix import Cell, Matrix, Sgacl, Sgt


def test_parse_and_allows():
    res = acl.parse("permit tcp dst eq 443 log\n+ permit udp dst range 5000 5100\ndeny ip")
    assert not res.errors
    assert acl.allows(res.rules, "TCP/443")
    assert acl.allows(res.rules, "UDP/5004")
    assert not acl.allows(res.rules, "TCP/80")


def test_parse_errors():
    res = acl.parse("permit tcp dst eq 70000\nallow everything\npermit icmp dst eq 3")
    assert len(res.errors) == 3


def test_first_match_wins():
    rules = acl.parse("deny tcp dst eq 22\npermit tcp").rules
    assert not acl.allows(rules, "TCP/22")
    assert acl.allows(rules, "TCP/443")


def test_generate_and_extend():
    text = acl.generate(["TCP/443", "UDP/53"])
    assert text.splitlines() == ["permit tcp dst eq 443 log", "permit udp dst eq 53 log", "deny ip log"]
    ext = acl.extend("permit tcp dst eq 443\ndeny ip", ["TCP/8443", "TCP/443"])
    assert ext.splitlines() == ["  permit tcp dst eq 443", "+ permit tcp dst eq 8443 log", "  deny ip"]
    assert acl.to_ise(ext) == "permit tcp dst eq 443\npermit tcp dst eq 8443 log\ndeny ip"


def test_validate_messages():
    v = acl.validate("permit tcp dst eq 443\npermit tcp dst eq 80", ["TCP/443", "TCP/8443"])
    assert any("8443" in w for w in v["warns"])
    assert any("TCP/80" in i for i in v["infos"])
    assert any("deny ip" in i for i in v["infos"])
    assert any("permit ip" in w for w in acl.validate("permit ip", [])["warns"])


def _matrix() -> Matrix:
    m = Matrix()
    for i, (name, value) in enumerate([("Employees", 4), ("Contractors", 5), ("Web", 10)]):
        m.sgts[str(i)] = Sgt(str(i), name, value)
    m.sgacls["a"] = Sgacl("a", "Web_Access", "permit tcp dst eq 443\npermit tcp dst eq 80\ndeny ip")
    m.cells[("Employees", "Web")] = Cell("c1", "0", "2", sgacl_ids=["a"])
    return m


def test_coverage_states():
    m = _matrix()
    assert m.coverage("Employees", "Web", ["TCP/443"])["status"] == "allowed"
    assert m.coverage("Employees", "Web", ["TCP/443", "TCP/8443"])["status"] == "partial"
    assert m.coverage("Contractors", "Web", ["TCP/443"])["status"] == "pending"
    m.cells[("Contractors", "Web")] = Cell("c2", "1", "2", status="MONITOR", default_rule="DENY_IP")
    assert m.coverage("Contractors", "Web", ["TCP/443"])["status"] == "allowed"  # monitor logs, does not drop


def test_impact_and_clone_name():
    m = _matrix()
    observed = {("Employees", "Web"): [{"spec": "TCP/443", "flows": 10}, {"spec": "TCP/80", "flows": 5}]}
    impacts = impact_of_change(m, "a", "permit tcp dst eq 443\ndeny ip", observed, exclude=("Contractors", "Web"))
    assert impacts == [{"src": "Employees", "dst": "Web", "spec": "TCP/80", "flows": 5}]
    assert impact_of_change(m, "a", "permit tcp dst eq 443\npermit tcp dst eq 80\npermit tcp dst eq 22",
                            observed) == []
    assert clone_name("MA_", "Web_Access", "Contractors", set()) == "MA_Web_Access_Contractors"
    assert clone_name("MA_", "MA_X", "C", {"MA_X_C"}) == "MA_X_C_2"
