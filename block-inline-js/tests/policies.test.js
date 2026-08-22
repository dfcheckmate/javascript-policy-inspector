import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CSP_POLICIES,
  DEFAULT_MODE,
  MODES,
  POLICY_SUMMARY,
  isMode,
} from "../lib/policies.js";
import {
  RULE_BANDS,
  buildRule,
  isPolicyRuleFor,
  ruleIdFor,
} from "../lib/rules.js";

const FIRST_PARTY_CSP =
  "script-src 'self'; script-src-attr 'none'; object-src 'none'; base-uri 'none'";
const NO_SCRIPTS_CSP =
  "script-src 'none'; script-src-attr 'none'; object-src 'none'; base-uri 'none'";

test("policy strings match the spec exactly", () => {
  assert.equal(CSP_POLICIES[MODES.OBSERVE], null);
  assert.equal(CSP_POLICIES[MODES.FIRST_PARTY_ONLY], FIRST_PARTY_CSP);
  assert.equal(CSP_POLICIES[MODES.NO_SCRIPTS], NO_SCRIPTS_CSP);
});

test("every mode has a summary and observe is the default", () => {
  for (const m of Object.values(MODES)) {
    assert.equal(typeof POLICY_SUMMARY[m], "string");
    assert.ok(POLICY_SUMMARY[m].length > 0);
  }
  assert.equal(DEFAULT_MODE, MODES.OBSERVE);
});

test("isMode accepts valid modes only", () => {
  for (const m of Object.values(MODES)) assert.ok(isMode(m));
  assert.equal(isMode("lockdown"), false);
  assert.equal(isMode(undefined), false);
});

const HOSTS = [
  "example.com",
  "localhost",
  "test.lumbago.ink",
  "a.io",
  "x".repeat(64),
];

test("ruleIdFor is deterministic, positive, inside site-policy band", () => {
  for (const h of HOSTS) {
    const id = ruleIdFor(h);
    assert.equal(id, ruleIdFor(h));
    assert.ok(Number.isInteger(id));
    assert.ok(id >= RULE_BANDS.SITE_POLICY && id < RULE_BANDS.TAB_OVERRIDE);
  }
});

test("ruleIdFor has no collisions across sample hosts", () => {
  const ids = new Set(HOSTS.map(ruleIdFor));
  assert.equal(ids.size, HOSTS.length);
});

test("buildRule produces the first-party rule shape", () => {
  const rule = buildRule("example.com", MODES.FIRST_PARTY_ONLY);
  assert.equal(rule.id, ruleIdFor("example.com"));
  assert.equal(rule.priority, 1);
  assert.equal(rule.action.type, "modifyHeaders");
  assert.deepEqual(rule.action.responseHeaders[0], {
    header: "Content-Security-Policy",
    operation: "append",
    value: FIRST_PARTY_CSP,
  });
  assert.deepEqual(rule.condition.requestDomains, ["example.com"]);
  assert.deepEqual(rule.condition.resourceTypes, ["main_frame", "sub_frame"]);
});

test("observe mode has no enforceable CSP", () => {
  assert.throws(() => buildRule("example.com", MODES.OBSERVE), /no enforceable/);
});

test("unknown modes are rejected", () => {
  assert.throws(() => buildRule("example.com", "lockdown"), /unknown mode/);
});

test("isPolicyRuleFor matches its own host only", () => {
  const ours = buildRule("example.com", MODES.NO_SCRIPTS);
  assert.ok(isPolicyRuleFor(ours, "example.com"));
  assert.equal(isPolicyRuleFor(ours, "other.com"), false);
  assert.equal(isPolicyRuleFor({ id: 123 }, "example.com"), false);
});
