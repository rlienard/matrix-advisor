"""policy/acl.py against the cases shared with frontend/src/acl.ts (see frontend/tests/acl.parity.test.mjs).

Both implementations must produce exactly the results stored in tests/fixtures/acl_parity.json.
"""

import json
from pathlib import Path

import pytest

from matrix_advisor.policy import acl

CASES = json.loads((Path(__file__).parent / "fixtures" / "acl_parity.json").read_text(encoding="utf-8"))["cases"]


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_acl_parity(case):
    lang = case.get("lang", "fr")
    res = acl.parse(case["text"], lang)
    assert [{"action": r.action, "proto": r.proto, "lo": r.lo, "hi": r.hi} for r in res.rules] == case["rules"]
    assert res.errors == case["errors"]
    assert acl.validate(case["text"], case["observed"], lang) == case["validate"]
    assert {s: acl.allows(res.rules, s) for s in case["allows"]} == case["allows"]
