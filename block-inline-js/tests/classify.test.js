import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CATEGORIES,
  EXECUTABLE_TYPES,
  getScriptCategory,
  isExecutable,
  isInlineHandlerName,
  isJavaScriptType,
  isJavaScriptUrl,
} from "../lib/classify.js";

test("bare and legacy-JS scripts classify as inline javascript", () => {
  assert.equal(getScriptCategory({ src: null, type: null }), CATEGORIES.INLINE_JAVASCRIPT);
  assert.equal(getScriptCategory({ src: null, type: "" }), CATEGORIES.INLINE_JAVASCRIPT);
  assert.equal(getScriptCategory({ src: "", type: "" }), CATEGORIES.INLINE_JAVASCRIPT);
  const jsTypes = [
    "text/javascript",
    "application/javascript",
    "application/ecmascript",
    "application/x-ecmascript",
    "application/x-javascript",
    "text/ecmascript",
    "text/javascript1.3",
    "text/livescript",
    "text/x-javascript",
    "module",
  ];
  for (const t of jsTypes) {
    assert.equal(getScriptCategory({ src: null, type: t }), CATEGORIES.INLINE_JAVASCRIPT, t);
  }
});

test("JSON-LD, JSON data, import maps and speculation rules are data blocks, not scripts", () => {
  const cases = [
    ["application/ld+json", CATEGORIES.JSON_LD],
    ["application/json", CATEGORIES.JSON_DATA],
    ["importmap", CATEGORIES.IMPORT_MAP],
    ["speculationrules", CATEGORIES.SPECULATION_RULES],
  ];
  for (const [type, cat] of cases) {
    assert.equal(getScriptCategory({ src: null, type }), cat, type);
    assert.equal(isExecutable(cat), false, type);
    assert.ok(!EXECUTABLE_TYPES.includes(cat), type);
  }
  assert.equal(getScriptCategory({ src: null, type: " Application/ld+JSON " }), CATEGORIES.JSON_LD);
});

test("unknown MIME types are data blocks, never inline scripts", () => {
  assert.equal(
    getScriptCategory({ src: null, type: "text/plain" }),
    CATEGORIES.UNKNOWN_SCRIPT_CONTAINER,
  );
  assert.equal(
    getScriptCategory({ src: null, type: "application/x-typo" }),
    CATEGORIES.UNKNOWN_SCRIPT_CONTAINER,
  );
  assert.equal(isExecutable(CATEGORIES.UNKNOWN_SCRIPT_CONTAINER), false);
});

test("external src scripts classify by src presence", () => {
  assert.equal(getScriptCategory({ src: "app.js", type: null }), CATEGORIES.EXTERNAL_JAVASCRIPT);
  assert.equal(
    getScriptCategory({ src: "app.js", type: "module" }),
    CATEGORIES.EXTERNAL_JAVASCRIPT,
  );
  assert.equal(
    getScriptCategory({ src: "https://x/data", type: "application/ld+json" }),
    CATEGORIES.UNKNOWN_SCRIPT_CONTAINER,
  );
  // Import maps and speculation rules may be fetched via src; the container
  // category must survive even though the payload never executes.
  assert.equal(
    getScriptCategory({ src: "imports.json", type: "importmap" }),
    CATEGORIES.IMPORT_MAP,
  );
  assert.equal(
    getScriptCategory({ src: "rules.json", type: "speculationrules" }),
    CATEGORIES.SPECULATION_RULES,
  );
});

test("isJavaScriptType follows the spec's data-block rule", () => {
  assert.equal(isJavaScriptType(null), true);
  assert.equal(isJavaScriptType(""), true);
  assert.equal(isJavaScriptType("text/javascript"), true);
  assert.equal(isJavaScriptType("module"), true);
  // A MIME parameter makes the type a data block per the WHATWG definition.
  assert.equal(isJavaScriptType("text/javascript; charset=utf-8"), false);
  assert.equal(isJavaScriptType("application/ld+json"), false);
});

test("only inline/external javascript count as executable", () => {
  for (const cat of Object.values(CATEGORIES)) {
    assert.equal(isExecutable(cat), EXECUTABLE_TYPES.includes(cat), cat);
  }
  assert.deepEqual(
    [...EXECUTABLE_TYPES].sort(),
    [CATEGORIES.EXTERNAL_JAVASCRIPT, CATEGORIES.INLINE_JAVASCRIPT].sort(),
  );
});

test("isInlineHandlerName matches lowercase on<event> names only (lexical approximation)", () => {
  assert.ok(isInlineHandlerName("onclick"));
  assert.ok(isInlineHandlerName("onload"));
  assert.ok(isInlineHandlerName("oncontextmenu"));
  assert.equal(isInlineHandlerName("onClick"), false); // browsers ignore camelCase
  assert.equal(isInlineHandlerName("on1"), false); // unexpected event names are excluded
  assert.equal(isInlineHandlerName("on"), false); // no event name at all
  assert.equal(isInlineHandlerName("href"), false);
  assert.equal(isInlineHandlerName(null), false);
  assert.equal(isInlineHandlerName(undefined), false);
});

test("isJavaScriptUrl tolerates whitespace before the colon", () => {
  assert.ok(isJavaScriptUrl("javascript:alert(1)"));
  assert.ok(isJavaScriptUrl(" JAVAscript:void(0)"));
  assert.ok(isJavaScriptUrl("javascript\n:alert(1)"));
  assert.ok(isJavaScriptUrl(" javascript : 1"));
  assert.equal(isJavaScriptUrl("https://x/"), false);
  assert.equal(isJavaScriptUrl(null), false);
});