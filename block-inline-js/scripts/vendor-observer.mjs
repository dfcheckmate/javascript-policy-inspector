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

/* 1. Which bindings does observer import, from which lib file? */
const bindings = new Map(); // lib file -> Set(binding name)
for (const line of OBS.split("\n")) {
  const m = line.match(
    /^import\s*\{([^}]*)\}\s*from\s*"\.\/lib\/([A-Za-z0-9_.-]+)\.js";$/
  );
  if (!m) continue;
  const names = m[1].split(",").map((s) => s.trim()).filter(Boolean);
  const mod = m[2] + ".js";
  if (!bindings.has(mod)) bindings.set(mod, new Set());
  names.forEach((n) => bindings.get(mod).add(n));
}
if (bindings.size === 0) {
  console.error("observer.js has no lib imports to vendor.");
  process.exit(1);
}

/* 2. Extract a top-level `export ...` declaration verbatim from a lib file,
 *    brace-balanced, and strip the leading `export` keyword. Also pulls the
 *    JSDoc block immediately above it. */
function extractDecl(file, name) {
  const lines = read("lib/" + file).split("\n");
  let start = -1;
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(
      /^export\s+(?:async\s+)?(?:function|const|let|var|class)\s+([A-Za-z0-9_$]+)\b/
    );
    if (m && m[1] === name) { start = i; break; }
  }
  if (start === -1) {
    console.error(`vendor: "${name}" not exported by lib/${file}`);
    process.exit(1);
  }

  // JSDoc immediately above (contiguous comment block).
  const doc = [];
  for (let j = start - 1; j >= 0; j--) {
    const t = lines[j].trim();
    if (t.startsWith("/**")) { doc.unshift(lines[j]); break; }
    if (t.startsWith("*") || t.startsWith("/*")) doc.unshift(lines[j]);
    else break;
  }

  let depth = 0;
  let opened = false;
  let k = start;
  const body = [];
  while (k < lines.length) {
    const line = lines[k];
    body.push(line);
    for (const ch of line) {
      if (ch === "{") { depth++; opened = true; }
      else if (ch === "}") depth--;
    }
    k++;
    if (opened && depth === 0) break;
    if (!opened && /;\s*$/.test(line)) break;
  }
  // Strip `export ` from the first line.
  body[0] = body[0].replace(/^export\s+/, "");
  return [...doc, ...body].join("\n");
}

/* 3. Assemble the vendored block and splice it into observer.js. */
const blocks = [];
for (const [file, names] of bindings) {
  blocks.push(
    `/* ════════════════════════════════════════════════════════════════════
 * ══ vendored from lib/${file} (source of truth — DO NOT EDIT THIS BLOCK;
 * ══ edit lib/${file} and re-run scripts/vendor-observer.mjs) ══
 * ════════════════════════════════════════════════════════════════════ */
` + [...names].map((n) => extractDecl(file, n)).join("\n\n")
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
const head = withoutImports.slice(0, at);
const tail = withoutImports.slice(at);

const result = head + vendored + "\n\n" + tail;
write("observer.js", result);
const left = (result.match(/\n\s*import\s*\{[^}]*\}\s*from\s*"\.\/lib\//g) || []).length;
console.log("observer.js vendored OK. lib blocks:", blocks.length,
  "| remaining lib imports in observer.js:", left);


