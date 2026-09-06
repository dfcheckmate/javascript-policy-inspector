import { test } from "node:test";
import assert from "node:assert/strict";
import { highlight } from "../lib/highlight.js";

test("highlight: classes keywords, literals, strings, comments, numbers", () => {
  const spans = highlight(`// note\nvar a = "x"; if (b) { f(1, true, null); }`);
  const byCls = (cls) => spans.filter((s) => s.cls === cls).map((s) => s.text);
  assert.ok(byCls("comment").join("").includes("// note"));
  assert.ok(byCls("kw").includes("var"));
  assert.ok(byCls("kw").includes("if"));
  assert.ok(byCls("string").includes('"x"'));
  assert.ok(byCls("lit").includes("true"));
  assert.ok(byCls("lit").includes("null"));
  assert.ok(byCls("num").includes("1"));
});

test("highlight: concatenated plain text reconstructs the source", () => {
  const src = `foo("hi"); // c\nlet n = 3.14;`;
  const out = highlight(src).map((s) => s.text).join("");
  assert.equal(out, src);
});

test("highlight: marks function-call identifiers as fn", () => {
  const spans = highlight("doIt();");
  const fn = spans.find((s) => s.cls === "fn");
  assert.ok(fn && fn.text === "doIt");
});

test("highlight: empty/undefined input returns []", () => {
  assert.deepEqual(highlight(""), []);
  assert.deepEqual(highlight(null), []);
  assert.deepEqual(highlight(undefined), []);
});
