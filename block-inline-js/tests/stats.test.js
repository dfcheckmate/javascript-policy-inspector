import { test } from "node:test";
import assert from "node:assert/strict";

import { INITIAL_STATS, computeStats } from "../lib/stats.js";

test("computeStats starts from all-zero counters", () => {
  assert.deepEqual(computeStats([]), INITIAL_STATS);
  assert.deepEqual(computeStats(undefined), INITIAL_STATS);
});

test("computeStats counts v1 legacy event kinds", () => {
  const events = [
    { kind: "script", party: "first" },
    { kind: "script", party: "third" },
    { kind: "script", party: "third" },
    { kind: "inline-script" },
    { kind: "inline-handler" },
    { kind: "csp-violation" },
  ];
  const stats = computeStats(events);
  assert.equal(stats.scriptsFirstParty, 1);
  assert.equal(stats.scriptsThirdParty, 2);
  assert.equal(stats.inlineScripts, 1);
  assert.equal(stats.inlineHandlers, 1);
  assert.equal(stats.blocked, 1);
  assert.equal(stats.removed, 0);
});

test("computeStats counts v2 category records without double-counting blocked", () => {
  const events = [
    { kind: "script-element", category: "inline-javascript", action: "observed" },
    { kind: "script-element", category: "external-javascript", party: "third", action: "blocked" },
    { kind: "handler-attr", action: "observed" },
    { kind: "javascript-url", action: "blocked" },
    { kind: "csp-violation", action: "blocked" },
  ];
  const stats = computeStats(events);
  assert.equal(stats.inlineScripts, 1);
  assert.equal(stats.scriptsThirdParty, 1);
  assert.equal(stats.inlineHandlers, 1);
  assert.equal(stats.javascriptUrls, 1);
  // each blocked event is counted exactly once (blocked != removed)
  assert.equal(stats.blocked, 3);
});

test("computeStats counts removed containers by category", () => {
  const events = [
    { kind: "script-element", category: "json-ld", action: "removed" },
    { kind: "script-element", category: "json-data", action: "removed" },
    { kind: "script-element", category: "import-map", action: "removed" },
    { kind: "script-element", category: "speculation-rules", action: "removed" },
  ];
  const stats = computeStats(events);
  assert.equal(stats.jsonLd, 1);
  assert.equal(stats.jsonData, 1);
  assert.equal(stats.importMaps, 1);
  assert.equal(stats.specRules, 1);
  assert.equal(stats.removed, 4);
  assert.equal(stats.blocked, 0);
  // containers are data blocks, never inline scripts
  assert.equal(stats.inlineScripts, 0);
  assert.equal(stats.scriptsFirstParty, 0);
  assert.equal(stats.scriptsThirdParty, 0);
});

test("computeStats keeps blocked and removed orthogonal", () => {
  // a DOM-removed container is NOT a CSP block
  const csp = computeStats([
    { kind: "csp-violation", action: "blocked" },
    { kind: "script-element", category: "json-ld", action: "removed" },
  ]);
  assert.equal(csp.blocked, 1);
  assert.equal(csp.removed, 1);
});

test("computeStats tolerates unknown kinds/categories", () => {
  const stats = computeStats([
    { kind: "mystery", category: "no-such-category", action: "strange" },
    null,
  ]);
  assert.deepEqual(stats, INITIAL_STATS);
});