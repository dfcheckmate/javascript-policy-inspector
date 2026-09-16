import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const read = (p) => readFileSync(join(ROOT, p), "utf8");
const write = (p, t) => writeFileSync(join(ROOT, p), t);

/* -------------------------------------------------------------------------- *
 * 1. Parse observer.js: find its import block and the list of imported names
 * -------------------------------------------------------------------------- */
const observerSrc = read("observer.js");
const importRe =
  /^import\s*\{([\s\S]*?)\}\s*from\s*"\.\/lib\/([A-Za-z0-9_-]+\.js)";\s*$/gm;

const libNeeds = new Map(); // libfile -> Set(bindingName)
let m;
while ((m = importRe.exec(observerSrc))) {
  const [, names, mod] = m;
  for (const raw of names.split(",")) {
    const name = raw.trim().replace(/\s+as\s+\w+$/, "");
    if (!name) continue;
    if (!libNeeds.has(mod)) libNeeds.set(mod, new Set());
    libNeeds.get(mod).add(name);
  }
}

/* -------------------------------------------------------------------------- *
 * 2. Load each lib, index its pure declarations by name (brace-extracted),
 *    and walk the transitive closure of references within the same module.
 * -------------------------------------------------------------------------- */
function indexModule(text, moduleName) {
  const decls = new Map(); // name -> {docLines, bodyLines}
  const lines = text.split("\n");

  const isDeclStart = /^export\s+(?:async\s+|default\s+)?(?:const|let|var|function|class)\s+([A-Za-z0-9_$]+)/;

  for (let i = 0; i < lines.length; i++) {
    const dm = lines[i].match(isDeclStart);
    if (!dm) continue;
    const name = dm[1];
    const docLines = [];
    // collect preceding JSDoc lines
    let d = i - 1;
    while (d >= 0 && /^\s*(\/\*+|\*|\/\*|\*\/)/.test(lines[d])) docLines.unshift(lines[d--]);

    // brace-match the body
    const bodyLines = [];
    let depth = 0;
    let started = false;
    let j = i;
    for (; j < lines.length; j++) {
      const line = lines[j];
      bodyLines.push(line);
      for (const ch of line) {
        if (ch === "{") { depth++; started = true; }
        else if (ch === "}") depth--;
      }
      if (started && depth === 0) { j++; break; }
    }
    // if never braced (single-line object-less const), take until ';'
    if (!started) {
      bodyLines.length = 0;
      for (j = i; j < lines.length; j++) {
        bodyLines.push(lines[j]);
        if (/;\s*$/.test(lines[j])) { j++; break; }
      }
    }
    decls.set(name, { doc: docLines, body: bodyLines, mod: moduleName });
  }
  return decls;
}

// Bindings an observer-lib import actually needs may themselves reference
// sibling pure bindings (e.g. getScriptCategory -> CATEGORIES, isJavaScriptType,
// normalizeScriptType). Vendoring must pull that closure or the block won't run.
function vendorModule(moduleName, roots) {
  const text = read("lib/" + moduleName);
  const decls = indexModule(text, moduleName);

  const wanted = new Set(roots);
  // iterative closure: any identifier used inside a wanted body that resolves
  // to a sibling declaration in *this* file becomes wanted too.
  let grew = true;
  const refRe = /\b([A-Z][A-Z0-9_]*|[a-z][A-Za-z0-9_]*)\b/g;
  const bodies = {};
  while (grew) {
    grew = false;
    for (const name of [...wanted]) {
      const d = decls.get(name);
      if (!d || bodies[name]) continue;
      bodies[name] = d;
      const all = [...d.doc, ...d.body].join("\n");
      let rm;
      while ((rm = refRe.exec(all)) !== null) {
        const ref = rm[1];
        // skip JS keywords/docs-ish tokens already-bound in this file
        if (decls.has(ref) && !wanted.has(ref)) { wanted.add(ref); grew = true; }
      }
      refRe.lastIndex = 0;
    }
  }

  const out = [];
  for (const name of text.split("\n").length ? wanted : wanted) {
    const d = bodies[name];
    if (!d) throw new Error(`vendoring ${moduleName}: cannot find decl for ${name}`);
    const doc = d.doc.join("\n");
    // strip `export ` keyword
    const body = d.body.map((l) => l.replace(/^export\s+/, ""));
    out.push((doc ? doc + "\n" : "") + body.join("\n"));
  }
  return out.join("\n\n");
}

/* -------------------------------------------------------------------------- *
 * 3. Assemble the vendored prefix and splice it into observer.js
 * -------------------------------------------------------------------------- */
const parts = [...libNeeds].map(([mod, names]) =>
  "/* ── vendored verbatim from lib/" + mod + " ────────────────────────── */\n" +
  vendorModule(mod, [...names])
);

const banner =
  "/* ════════════════════════════════════════════════════════════════════════\n" +
  " * VENDORED PURE HELPERS\n" +
  " * observer.js is an MV3 *content script*: Chrome/Edge/Firefox run content\n" +
  " * scripts as classic (non-module) JS, so ES `import` is illegal there and\n" +
  " * would throw at load. These are byte-identical copies of the exact pure\n" +
  " * helpers the observer uses, spliced from lib/*.js by scripts/vendor-content-script.mjs.\n" +
  " * Canonical source + tests live in lib/; edit lib, re-run the script.\n" +
  " * Do not hand-edit below this marker.\n" +
  " * ════════════════════════════════════════════════════════════════════════ */\n";

const vendored = banner + "\n" + parts.join("\n\n") + "\n";

const iifeAnchor = "(() => {";
const iifeIdx = observerSrc.indexOf(iifeAnchor);
if (iifeIdx === -1) throw new Error("could not find observer IIFE anchor");

const afterIife = observerSrc.indexOf("\n", iifeIdx) + 1;

const strippedImports = observerSrc.replace(importRe, "");
let beforeIife = strippedImports.slice(0, iifeIdx);

const result = beforeIife + vendored + "\n" + strippedImports.slice(iifeIdx);
write("observer.js", result);
console.log("vendored observer.js:", result.length, "bytes");
console.log("remaining import lines:", (result.match(/^import\s/mg) || []).length);
