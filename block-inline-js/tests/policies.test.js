import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CSP_POLICIES,
  DEFAULT_MODE,
  MODES,
  POLICY_SUMMARY,
  composeHeader,
  composePolicy,
  composePolicyFromFlags,
  isMode,
  normalizeOrigin,
} from "../lib/policies.js";
import { PRESETS, makeFlags } from "../lib/flags.js";
import {
  RULE_BANDS,
  buildRule,
  isPolicyRuleFor,
  ruleIdFor,
} from "../lib/rules.js";
import { normalizeHostForRule } from "../lib/host.js";

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
  const rule = buildRule("example.com", PRESETS[MODES.FIRST_PARTY_ONLY]);
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

test("observe and container-only bundles have no enforceable CSP rule", () => {
  assert.throws(
    () => buildRule("example.com", PRESETS[MODES.OBSERVE]),
    /no enforceable/,
  );
  assert.throws(
    () => buildRule("example.com", makeFlags({ blockJsonLd: true })),
    /no enforceable/,
  );
});

test("unknown flags are rejected", () => {
  assert.throws(() => buildRule("example.com", "lockdown"), /unknown policy flags/);
  assert.throws(() => buildRule("example.com", null), /unknown policy flags/);
});

test("isPolicyRuleFor matches its own host only", () => {
  const ours = buildRule("example.com", PRESETS[MODES.NO_SCRIPTS]);
  assert.ok(isPolicyRuleFor(ours, "example.com"));
  assert.equal(isPolicyRuleFor(ours, "other.com"), false);
  assert.equal(isPolicyRuleFor({ id: 123 }, "example.com"), false);
});

test("composePolicy: no exceptions returns the base policies", () => {
  assert.equal(composePolicy(MODES.OBSERVE, { origins: ["https://a.com"] }), null);
  assert.equal(composePolicy(MODES.FIRST_PARTY_ONLY), FIRST_PARTY_CSP);
  assert.equal(composePolicy(MODES.NO_SCRIPTS), NO_SCRIPTS_CSP);
});

test("composePolicy: first-party appends origins after 'self'", () => {
  const csp = composePolicy(MODES.FIRST_PARTY_ONLY, {
    origins: ["https://cdn.vendor.example", "https://events.vendor.example"],
  });
  assert.equal(
    csp,
    "script-src 'self' https://cdn.vendor.example https://events.vendor.example; script-src-attr 'none'; object-src 'none'; base-uri 'none'",
  );
});

test("composePolicy: no-scripts with exceptions replaces 'none'", () => {
  assert.equal(
    composePolicy(MODES.NO_SCRIPTS, { origins: ["https://cdn.vendor.example"] }),
    "script-src https://cdn.vendor.example; script-src-attr 'none'; object-src 'none'; base-uri 'none'",
  );
});

test("composePolicy: inline-script hashes join script-src", () => {
  const h = "sha256-QR0cIn9RcoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  assert.equal(
    composePolicy(MODES.NO_SCRIPTS, { scriptHashes: [h] }),
    `script-src ${h}; script-src-attr 'none'; object-src 'none'; base-uri 'none'`,
  );
});

test("composePolicy: attr hashes replace script-src-attr 'none'", () => {
  const h = "sha256-Q2V0M69lDdMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  assert.equal(
    composePolicy(MODES.FIRST_PARTY_ONLY, { attrHashes: [`attr-${h}`] }),
    `script-src 'self'; script-src-attr ${h}; object-src 'none'; base-uri 'none'`,
  );
});

test("composePolicy: mixed origins + both hash kinds, deduped", () => {
  const a = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  const b = "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
  const c = "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=";
  const csp = composePolicy(MODES.NO_SCRIPTS, {
    origins: ["https://a.com", "https://a.com"],
    scriptHashes: [a, b],
    attrHashes: [c],
  });
  assert.equal(
    csp,
    `script-src https://a.com ${a} ${b}; script-src-attr ${c}; object-src 'none'; base-uri 'none'`,
  );
});

test("composePolicy: truncated hash tokens are dropped (never emit a dead source)", () => {
  assert.equal(
    composePolicy(MODES.NO_SCRIPTS, {
      scriptHashes: ["sha256-too-short", "evil"],
    }),
    "script-src 'none'; script-src-attr 'none'; object-src 'none'; base-uri 'none'",
  );
});

test("composePolicy: dedupes and drops junk entries", () => {
  assert.equal(
    composePolicy(MODES.NO_SCRIPTS, {
      origins: ["https://x.com", "https://x.com", "", "  "],
    }),
    "script-src https://x.com; script-src-attr 'none'; object-src 'none'; base-uri 'none'",
  );
});

test("normalizeOrigin accepts only http(s) origins", () => {
  assert.equal(normalizeOrigin("https://cdn.example.com/path/x.js"), "https://cdn.example.com");
  assert.equal(normalizeOrigin("http://localhost:8001"), "http://localhost:8001");
  assert.equal(normalizeOrigin("javascript:alert(1)"), null);
  assert.equal(normalizeOrigin("not a url"), null);
});

test("ruleIdFor folds subdomains to the same id as their apex", () => {
  assert.equal(ruleIdFor("www.example.com"), ruleIdFor("example.com"));
  assert.equal(ruleIdFor("api.example.com"), ruleIdFor("example.com"));
});

test("normalizeHostForRule preserves localhost, IPs, and single labels", () => {
  assert.equal(normalizeHostForRule("localhost"), "localhost");
  assert.equal(normalizeHostForRule("127.0.0.1"), "127.0.0.1");
  assert.equal(normalizeHostForRule("LOCALHOST"), "localhost");
});

test("normalizeHostForRule folds common suffixes to 3 labels, else 2", () => {
  assert.equal(normalizeHostForRule("www.bbc.co.uk"), "bbc.co.uk");
  assert.equal(normalizeHostForRule("a.b.example.com"), "example.com");
  assert.equal(normalizeHostForRule("WWW.Example.COM"), "example.com");
});

test("composeHeader wraps composePolicy in a Content-Security-Policy header", () => {
  assert.equal(
    composeHeader(MODES.FIRST_PARTY_ONLY),
    `Content-Security-Policy: ${composePolicy(MODES.FIRST_PARTY_ONLY)}`,
  );
  const withAllow = composeHeader(MODES.FIRST_PARTY_ONLY, {
    origins: ["https://cdn.example.com"],
  });
  assert.ok(withAllow.startsWith("Content-Security-Policy: "));
  assert.ok(withAllow.includes("https://cdn.example.com"));
});

test("composeHeader returns null for observe mode", () => {
  assert.equal(composeHeader(MODES.OBSERVE), null);
});

test("composePolicyFromFlags: presets match the documented CSP exactly", () => {
  assert.equal(composePolicyFromFlags(PRESETS[MODES.OBSERVE]), null);
  assert.equal(composePolicyFromFlags(PRESETS[MODES.FIRST_PARTY_ONLY]), FIRST_PARTY_CSP);
  assert.equal(composePolicyFromFlags(PRESETS[MODES.NO_SCRIPTS]), NO_SCRIPTS_CSP);
});

test("composePolicyFromFlags: CSP_POLICIES cannot drift from presets", () => {
  for (const mode of Object.values(MODES)) {
    assert.equal(CSP_POLICIES[mode], composePolicyFromFlags(PRESETS[mode]));
  }
});

test("composePolicyFromFlags: container/report-only bundles need no CSP", () => {
  assert.equal(composePolicyFromFlags(makeFlags({ blockJsonLd: true })), null);
  assert.equal(
    composePolicyFromFlags(makeFlags({ blockJsonData: true, blockImportMaps: true })),
    null,
  );
  assert.equal(composePolicyFromFlags(makeFlags({ reportBlockedContent: false })), null);
});

test("composePolicyFromFlags: blockExternalScripts roots at 'none' (origins replace it)", () => {
  const allExternal = makeFlags({
    blockExternalScripts: true,
    blockClassicScripts: true,
    blockModuleScripts: true,
  });
  assert.equal(
    composePolicyFromFlags(allExternal),
    "script-src 'none'; script-src-attr 'none'; object-src 'none'; base-uri 'none'",
  );
  assert.equal(
    composePolicyFromFlags(allExternal, { origins: ["https://cdn.vendor.example"] }),
    "script-src https://cdn.vendor.example; script-src-attr 'none'; object-src 'none'; base-uri 'none'",
  );
});

test("composePolicyFromFlags: '*' posture blocks inline while allowing all external scripts", () => {
  assert.equal(
    composePolicyFromFlags(makeFlags({ blockClassicScripts: true, blockModuleScripts: true })),
    "script-src *; script-src-attr 'none'; object-src 'none'; base-uri 'none'",
  );
});

test("composePolicyFromFlags: attr hashes replace script-src-attr 'none' under any posture", () => {
  const h = "sha256-Q2V0M69lDdMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  assert.equal(
    composePolicyFromFlags(
      makeFlags({
        blockClassicScripts: true,
        blockModuleScripts: true,
        blockThirdPartyScripts: true,
      }),
      { attrHashes: [`attr-${h}`] },
    ),
    `script-src 'self'; script-src-attr ${h}; object-src 'none'; base-uri 'none'`,
  );
});

test("composePolicyFromFlags: inline-requiring combos are unexpressible and rejected", () => {
  // attr-only and partial-inline bundles would force 'unsafe-inline'
  assert.throws(
    () => composePolicyFromFlags(makeFlags({ blockInlineEventHandlers: true })),
    /unsafe-inline/,
  );
  assert.throws(
    () => composePolicyFromFlags(makeFlags({ blockJavascriptUrls: true })),
    /unsafe-inline/,
  );
  assert.throws(
    () => composePolicyFromFlags(makeFlags({ blockClassicScripts: true })),
    /unsafe-inline/,
  );
  assert.throws(
    () =>
      composePolicyFromFlags(
        makeFlags({ blockThirdPartyScripts: true, blockClassicScripts: false }),
      ),
    /unsafe-inline/,
  );
  assert.throws(
    () =>
      composePolicyFromFlags(
        makeFlags({ blockExternalScripts: true, blockModuleScripts: false }),
      ),
    /unsafe-inline/,
  );
  assert.throws(
    () => composePolicyFromFlags(makeFlags({ blockExternalScripts: true })),
    /unsafe-inline/,
  );
});

test("composePolicy ≡ composePolicyFromFlags(preset) for equal allowances", () => {
  const allows = {
    origins: ["https://cdn.a.com"],
    scriptHashes: ["sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],
    attrHashes: ["sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="],
  };
  for (const mode of Object.values(MODES)) {
    assert.equal(
      composePolicy(mode, allows),
      composePolicyFromFlags(PRESETS[mode], allows),
      mode,
    );
  }
});
