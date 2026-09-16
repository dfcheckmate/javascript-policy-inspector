// scripts/vendor-observer.mjs — regenerate the self-contained observer.js
//
// WHY: observer.js is an MV3 *content script*. Chrome/Edge/Firefox run
// content scripts as CLASSIC scripts and reject ES-module `import` (the
// "Cannot use import statement outside a module" error the user reported).
// So observer.js must be one self-contained file. The canonical logic stays
// in lib/*.js (source of truth, unit-tested under node --test); this script
// copies the exact brace-balanced `export` declarations observer imports,
// verbatim, stripping `export`, and splices them in place of the import
// lines — mechanically, so vendoring can never drift from lib/.
//
// USAGE:  node scripts/vendor-observer.mjs
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => readFileSync(join(ROOT, p), "utf8").replace(/\r\n/g, "\n");
const write = (p, t) => writeFileSync(join(ROOT, p), t);

const OBS = read("observer.js");

/**
 * Canonical lib imports observer.js depends on. Requiring this inline (rather
 * than relying on reading them back from observer.js) makes the script
 * idempotent: a vendored observer.js has no import lines left to discover.
 * When observer.js still HAS import lines they win (they are the live spec);
 * the constant only fills in for an already-vendored file.
 */
const OBSERVER_LIB_IMPORTS = `import { getScriptCategory, isExecutable, isInlineHandlerName, isJavaScriptUrl, CATEGORIES } from "./lib/classify.js";
import { normalizeHostForRule } from "./lib/host.js";
import { DEFAULT_POLICY, isFlags, migrateLegacyModes, REMOVAL_FLAG_BY_CATEGORY } from "./lib/flags.js";`;

/* 1. Which bindings does observer import, from which lib file? */
function importBindingsFrom(src) {
  const map = new Map(); // lib file -> Set(binding name)
  for (const line of src.split("\n")) {
    const m = line.match(
      /^import\s*\{([^}]*)\}\s*from\s*"\.\/lib\/([A-Za-z0-9_.-]+)\.js";$/
    );
    if (!m) continue;
    const names = m[1].split(",").map((s) => s.trim()).filter(Boolean);
    const mod = m[2] + ".js";
    if (!map.has(mod)) map.set(mod, new Set());
    names.forEach((n) => map.get(mod).add(n));
  }
  return map;
}
let bindings = importBindingsFrom(OBS);
if (bindings.size === 0) {
  bindings = importBindingsFrom(OBSERVER_LIB_IMPORTS);
  console.log("observer.js already vendored; using embedded canonical import spec.");
}
if (bindings.size === 0) {
  console.error("observer.js has no lib imports to vendor.");
  process.exit(1);
}

/* 2. Index every top-level declaration (exported or not) in a lib file,
 *    capturing its JSDoc block and a brace- / bracket-balanced extent.
 *    Private helpers (normalizeType, JS_LANGUAGE_TYPES, MULTI_LABEL_SUFFIXES,
 *    …) are indexed too so the closure in step 3 can vendor them. */
function indexDecls(file) {
  const lines = read("lib/" + file).split("\n");
  const decls = new Map();
  const DECL = /^(?:export\s+)?(?:async\s+)?(?:function|const|let|var|class)\s+([A-Za-z0-9_$]+)\b/;
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(DECL);
    if (!m || m[1] === "default" || decls.has(m[1])) continue;
    const name = m[1];

    // JSDoc immediately above (contiguous comment block).
    const doc = [];
    for (let j = i - 1; j >= 0; j--) {
      const t = lines[j].trim();
      if (t.startsWith("/**")) { doc.unshift(lines[j]); break; }
      if (t.startsWith("*") || t.startsWith("/*")) doc.unshift(lines[j]);
      else break;
    }

    let depth = 0;
    let opened = false;
    let k = i;
    const body = [];
    while (k < lines.length) {
      const line = lines[k];
      body.push(line);
      for (const ch of line) {
        if (ch === "{" || ch === "[") { depth++; opened = true; }
        else if (ch === "}" || ch === "]") depth--;
      }
      k++;
      if (opened && depth === 0) break;
      if (!opened && /;\s*$/.test(line)) break;
    }
    decls.set(name, { file, line: i + 1, doc, body });
  }
  return decls;
}

/* 3. Transitive closure over a file's declarations, starting from the
 *    imported roots. A declaration is kept when it — or anything it
 *    references — is needed. Over-inclusion is safe (extra standalone
 *    top-level const/function); under-inclusion would throw ReferenceError
 *    in the browser, exactly the PRESETS failure this replaced. */
function usedDecls(file, roots) {
  const decls = indexDecls(file);
  const seen = new Set();
  const visit = (name) => {
    if (seen.has(name)) return;
    const decl = decls.get(name);
    if (!decl) return;
    seen.add(name);
    const text = decl.body.join("\n");
    for (const other of decls.keys()) {
      if (seen.has(other)) continue;
      const re = new RegExp(`(?<![.\\w])${other}(?!\\w)`, "g");
      if (re.test(text)) visit(other);
    }
  };
  roots.forEach(visit);
  return [...seen]
    .map((n) => decls.get(n))
    .sort((a, b) => a.line - b.line)
    .map((decl) => {
      const body = [...decl.body];
      body[0] = body[0].replace(/^export\s+/, "");
      return { ...decl, body };
    });
}

/* 4. Assemble the vendored block and splice it into observer.js. */
const blocks = [];
for (const [file, names] of bindings) {
  const decls = usedDecls(file, [...names]);
  blocks.push(
    `/* ════════════════════════════════════════════════════════════════════
 * ══ vendored from lib/${file} (source of truth — DO NOT EDIT THIS BLOCK;
 * ══ edit lib/${file} and re-run scripts/vendor-observer.mjs) ══
 * ════════════════════════════════════════════════════════════════════ */
` + decls.map((d) => [...d.doc, ...d.body].join("\n")).join("\n\n")
  );
}
const vendored = blocks.join("\n\n");

const observer = read("observer.js");
const withoutImports = observer
  .split("\n")
  .filter((l) => !/^import\s*\{[^}]*\}\s*from\s*"\.\/lib\//.test(l))
  .join("\n")
  .replace(/\n{4,}/g, "\n\n\n");

// Find the IIFE start to insert the vendored block just before it.
const anchor = "(() => {";
const at = withoutImports.indexOf(anchor);
if (at === -1) { console.error("observer.js has no IIFE anchor:"); process.exit(1); }
// Drop a previously vendored block (first block-header through the anchor)
// so re-running never stacks duplicates.
const vh = withoutImports.indexOf("vendored from lib/");
const blockStart = vh !== -1 ? withoutImports.lastIndexOf("/* ═", vh) : -1;
const head0 = blockStart !== -1 ? withoutImports.slice(0, blockStart) : withoutImports.slice(0, at);
const head = head0.replace(/\n+$/, "\n");
const tail = withoutImports.slice(at);

const result = head + vendored + "\n\n" + tail;
write("observer.js", result);
const left = (result.match(/\n\s*import\s*\{[^}]*\}\s*from\s*"\.\/lib\//g) || []).length;
console.log("observer.js vendored OK. lib blocks:", blocks.length,
  "| remaining lib imports in observer.js:", left);


