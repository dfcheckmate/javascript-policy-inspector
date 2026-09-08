import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const fixtureUrl = new URL("./fixtures/layered-policy.html", import.meta.url);
const html = fs.readFileSync(fileURLToPath(fixtureUrl), "utf8");

// Every comment marker the verification fixture promises must stay present so
// manual testing exercises exactly the categories the classifier produces.
const MARKERS = [
  "category:inline-classic",
  "category:inline-module",
  "category:external-first-party",
  "category:external-third-party",
  "category:json-ld",
  "category:json-data",
  "category:import-map",
  "category:speculation-rules",
  "category:unknown-container",
  "category:inline-handler",
  "category:javascript-url",
];

test("layered-policy.html fixture contains every category marker", () => {
  for (const marker of MARKERS) {
    assert.ok(html.includes(marker), `missing ${marker}`);
  }
});

test("layered-policy.html fixture script types match the classifier input", () => {
  // The inline <script> carries no type (classic); modules, containers and
  // data blocks carry their exact type attribute values. Spot-check the
  // attribute values the classifier keys on.
  assert.match(html, /<script type="module">/); // INLINE_JAVASCRIPT (module)
  assert.match(html, /type="application\/ld\+json"/);
  assert.match(html, /type="application\/json"/);
  assert.match(html, /type="importmap"/);
  assert.match(html, /type="speculationrules"/);
  assert.match(html, /type="text\/x-custom-data"/);
  assert.match(html, /onclick="/);
  assert.match(html, /href="javascript:void\(0\)"/);
});