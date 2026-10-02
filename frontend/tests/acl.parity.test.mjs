// src/acl.ts against the cases shared with backend/matrix_advisor/policy/acl.py
// (see backend/tests/test_acl_parity.py). Run with `npm test` (Node >= 22.18 strips the TS types).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { allows, parse, validate } from "../src/acl.ts";

const fixture = new URL("../../backend/tests/fixtures/acl_parity.json", import.meta.url);
const { cases } = JSON.parse(readFileSync(fixture, "utf8"));

for (const c of cases) {
  test(c.name, () => {
    const { rules, errors } = parse(c.text, c.lang);
    assert.deepEqual(rules, c.rules);
    assert.deepEqual(errors, c.errors);
    assert.deepEqual(validate(c.text, c.observed, c.lang), c.validate);
    assert.deepEqual(Object.fromEntries(Object.keys(c.allows).map((s) => [s, allows(rules, s)])), c.allows);
  });
}
