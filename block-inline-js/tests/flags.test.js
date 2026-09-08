import { test } from "node:test";
import assert from "node:assert/strict";

import {
  DEFAULT_FLAGS,
  DEFAULT_POLICY,
  FLAG_KEYS,
  MODES,
  PRESETS,
  REMOVAL_FLAG_BY_CATEGORY,
  isFlags,
  isPresetName,
  makeFlags,
  migrateLegacyModes,
  modeForFlags,
  presetFor,
} from "../lib/flags.js";

test("makeFlags builds a full bundle with defaults", () => {
  const f = makeFlags();
  for (const k of FLAG_KEYS) {
    assert.equal(typeof f[k], "boolean", k);
    assert.equal(f[k], DEFAULT_FLAGS[k], k);
  }
});

test("makeFlags applies overrides and rejects unknown keys", () => {
  const f = makeFlags({ blockExternalScripts: true });
  assert.equal(f.blockExternalScripts, true);
  assert.equal(f.blockClassicScripts, false);
  assert.throws(() => makeFlags({ bloqClassicScripts: true }), /unknown flag/);
});

test("isFlags validates bundles", () => {
  assert.equal(isFlags(makeFlags()), true);
  assert.equal(isFlags(makeFlags({ blockJsonLd: true })), true);
  assert.equal(isFlags({ ...makeFlags(), blockJsonLd: "yes" }), false);
  assert.equal(isFlags(null), false);
  assert.equal(isFlags("observe"), false);
  assert.equal(isFlags({}), false);
});

test("observe preset is the fully-default bundle and the default policy", () => {
  const f = PRESETS[MODES.OBSERVE];
  for (const k of FLAG_KEYS) assert.equal(f[k], DEFAULT_FLAGS[k], k);
  assert.equal(DEFAULT_POLICY, f);
});

test("firstPartyOnly preset blocks inline, third-party, handlers, urls and containers", () => {
  const f = PRESETS[MODES.FIRST_PARTY_ONLY];
  const on = [
    "blockClassicScripts",
    "blockModuleScripts",
    "blockThirdPartyScripts",
    "blockInlineEventHandlers",
    "blockJavascriptUrls",
    "blockImportMaps",
    "blockSpeculationRules",
    "blockJsonLd",
  ];
  const off = ["blockExternalScripts", "blockJsonData"];
  for (const k of on) assert.equal(f[k], true, k);
  for (const k of off) assert.equal(f[k], false, k);
  assert.equal(f.reportBlockedContent, true);
});

test("noScripts blocks everything except JSON data", () => {
  const f = PRESETS[MODES.NO_SCRIPTS];
  for (const k of FLAG_KEYS) {
    if (k === "blockJsonData" || k === "reportBlockedContent") continue;
    assert.equal(f[k], true, k);
  }
  assert.equal(f.blockJsonData, false);
  assert.equal(f.reportBlockedContent, true);
});

test("presets are immutable", () => {
  assert.throws(() => {
    PRESETS[MODES.NO_SCRIPTS].blockJsonData = true;
  }, TypeError);
});

test("modeForFlags recognizes presets and rejects custom bundles", () => {
  for (const [mode, bundle] of Object.entries(PRESETS)) {
    assert.equal(modeForFlags(bundle), mode);
  }
  assert.equal(modeForFlags(makeFlags()), MODES.OBSERVE);
  const custom = makeFlags({ blockJsonData: true });
  assert.equal(modeForFlags(custom), null);
  assert.equal(modeForFlags(undefined), null);
});

test("presetFor and isPresetName", () => {
  assert.ok(isPresetName(MODES.FIRST_PARTY_ONLY));
  assert.equal(isPresetName("lockdown"), false);
  assert.equal(presetFor(MODES.NO_SCRIPTS), PRESETS[MODES.NO_SCRIPTS]);
  assert.equal(presetFor("lockdown"), null);
  assert.equal(presetFor(undefined), null);
});

test("migrateLegacyModes materializes v1 modes as v2 preset bundles", () => {
  const { policies, changed } = migrateLegacyModes(
    {},
    { "example.com": MODES.FIRST_PARTY_ONLY, "cdn.other.io": MODES.NO_SCRIPTS },
  );
  assert.equal(changed, true);
  assert.deepEqual(policies["example.com"], PRESETS[MODES.FIRST_PARTY_ONLY]);
  assert.deepEqual(policies["cdn.other.io"], PRESETS[MODES.NO_SCRIPTS]);
  assert.equal(modeForFlags(policies["example.com"]), MODES.FIRST_PARTY_ONLY);
});

test("migrateLegacyModes is idempotent and preserves v2 bundles", () => {
  const custom = makeFlags({ blockJsonData: true });
  const first = migrateLegacyModes(
    { "example.com": custom },
    { "example.com": MODES.NO_SCRIPTS },
  );
  assert.equal(first.changed, false);
  assert.deepEqual(first.policies["example.com"], custom); // v2 wins

  const second = migrateLegacyModes(first.policies, {
    "example.com": MODES.NO_SCRIPTS,
  });
  assert.equal(second.changed, false);
});

test("migrateLegacyModes ignores unknown/observe-only legacy values", () => {
  const { policies, changed } = migrateLegacyModes({}, {
    "x.io": "lockdown",
    "y.io": MODES.OBSERVE,
  });
  assert.equal(changed, false);
  assert.equal("x.io" in policies, false);
  assert.equal("y.io" in policies, false);
});

test("migrateLegacyModes takes an empty store as a no-op", () => {
  const { policies, changed } = migrateLegacyModes(undefined, undefined);
  assert.deepEqual(policies, {});
  assert.equal(changed, false);
});

test("REMOVAL_FLAG_BY_CATEGORY maps non-executable containers to real flags", () => {
  assert.deepEqual(Object.keys(REMOVAL_FLAG_BY_CATEGORY).sort(), [
    "import-map",
    "json-data",
    "json-ld",
    "speculation-rules",
  ]);
  for (const flag of Object.values(REMOVAL_FLAG_BY_CATEGORY)) {
    assert.ok(FLAG_KEYS.includes(flag), `${flag} is a known flag`);
    assert.equal(typeof DEFAULT_FLAGS[flag], "boolean", flag);
  }
  assert.equal(
    "unknown-script-container" in REMOVAL_FLAG_BY_CATEGORY,
    false,
    "unknown containers are observation-only",
  );
});