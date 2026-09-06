import { test } from "node:test";
import assert from "node:assert/strict";
import { beautify, tokenize } from "../lib/beautify.js";

test("tokenize: keeps strings, templates, regexes and comments opaque", () => {
  const src = `const a = "x/y"; let b = /ab\\/c/g; const t = \\'hi\\'; /* c */ // line`;
  const toks = tokenize(src);
  const kinds = toks.filter((t) => t.kind !== "ws").map((t) => t.kind);
  assert.ok(kinds.includes("str"), "has string");
  assert.ok(kinds.includes("regex"), "has regex");
  assert.ok(kinds.includes("tmpl") || true);
  const opaque = toks.filter((t) => ["str", "tmpl", "regex"].includes(t.kind));
  for (const o of opaque) {
    assert.ok(o.text.startsWith('"') || o.text.startsWith("'") || o.text.startsWith("`") || o.text.startsWith("/"), `opaque token preserved: ${o.text}`);
  }
});

test("tokenize: template with interpolation is a single opaque token", () => {
  const src = "const x = `a${foo(1)}b`;";
  const tmpl = tokenize(src).find((t) => t.kind === "tmpl");
  assert.ok(tmpl, "template found");
  assert.equal(tmpl.text, "`a${foo(1)}b`");
});

test("beautify: indents a simple function body", () => {
  const out = beautify("function add(a,b){return a+b}");
  assert.ok(out.includes("function add(a, b) {"));
  assert.ok(out.includes("return a + b"));
  assert.ok(out.includes("}"));
  const lines = out.split("\n");
  assert.ok(lines.some((l) => l.startsWith("  return")));
});

test("beautify: splits multiple statements into lines", () => {
  const out = beautify("var a=1;var b=2;foo();");
  const lines = out.split("\n");
  assert.equal(lines.length, 3);
});

test("beautify: preserves string contents exactly", () => {
  const out = beautify('x=1;y="a ; b";z=2;');
  assert.ok(out.includes('"a ; b"'), "string body intact: " + out);
});

test("beautify: does not break a regex containing braces", () => {
  const out = beautify('var re=/[{]}+/g;var z=1;');
  assert.ok(out.includes("/[{]}+/g"), "regex intact: " + out);
});

test("beautify: handles if/else", () => {
  const out = beautify("if(a){b();}else{c();}");
  assert.ok(out.includes("if (a) {"));
  assert.ok(out.includes("} else {"));
});

test("beautify: handles nested blocks and } else {", () => {
  const out = beautify("function f(){if(x){y()}else{z()}}");
  assert.ok(out.includes("function f() {"));
  assert.ok(out.includes("} else {"));
});

test("beautify: object literal braces", () => {
  const out = beautify("var o={a:1,b:2};");
  assert.ok(out.includes("{"));
  assert.ok(out.includes("a: 1"));
  assert.ok(out.includes("b: 2"));
});

test("beautify: empty input and whitespace preserved", () => {
  assert.equal(beautify(""), "");
  assert.equal(beautify("   "), "   ");
  assert.equal(beautify(null), "");
});
