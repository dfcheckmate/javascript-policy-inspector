import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = "C:\\Users\\amigo\\Dev\\extension\\block-inline-js";
const read = (p) => readFileSync(join(ROOT, p), "utf8");
const write = (p, t) => writeFileSync(join(ROOT, p), t);

/* Extract the declarations observer.js imports, verbatim from lib/*.js.
 * Brace-balanced; strips the leading `export ` keyword only. */
function brace(body, tag, names) {
  const src = read(body);
  const lines = src.split("\n");
  const got = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^export\s+(async\s+)?(function|const|let|var|class)\s+([A-Za-z0-9_$]+)\b/);
    if (!m) continue;
    const name = m[3];
    if (!names.includes(name)) continue;
    let depth = 0;
    let started = false;
    const block = [];
    for (let j = i; j < lines.length; j++) {
      const line = lines[j];
      block.push(line);
      for (const c of line) {
        if (c === "{") { depth++; started = true; }
        else if (c === "}") depth--;
      }
      if (started && depth === 0 && /^\s*[{})]\s*(;?\s*)$/.test(line)) break;
      if (!started && /;\s*$/.test(line)) break;
    }
    block[0] = block[0].replace(/^export\s+/, "");
    got.push(block.join("\n"));
  }
  const missing = names.filter((n) => !got.some((g) => new RegExp(`\\b${n}\\b`).test(g)));
  if (missing.length) throw new Error(`${tag}: missing ${missing.join(", ")}`);
  return "/* ── vendored from lib/" + tag + " (canonical source; keep in sync) ── */\n" + got.join("\n\n");
}

const classify = ["CATEGORIES", "EXECUTABLE_TYPES", "JS_LANGUAGE_TYPES", "normalizeType", "isJavaScriptType", "getScriptCategory", "isExecutable", "isInlineHandlerName", "isJavaScriptUrl"];
const host = ["MULTI_LABEL_SUFFIXES", "normalizeHostForRule"];
const flags = ["FLAG_KEYS", "DEFAULT_FLAGS", "REMOVAL_FLAG_BY_CATEGORY", "isFlags"];

const vendored = [
  "/* ── vendored pure helpers (MV3 content scripts can't use ES imports in Chrome/Edge/Firefox) ── */",
  brace("lib/classify.js", "classify.js", classify),
  brace("lib/host.js", "host.js", host),
  brace("lib/flags.js", "flags.js", flags),
].join("\n\n");

const obs = read("observer.js");
// Strip import lines.
const clean = obs
  .split("\n")
  .filter((l) => !/^import\s*\{/.test(l))
  .join("\n")
  .replace(/\n{3,}/g, "\n\n");
// Insert vendored block right after the file's leading comment banner.
const marker = clean.indexOf("(function");
const head = clean.slice(0, marker).replace(/\n+$/, "");
const tail = clean.slice(marker);
write("observer.js", head + "\n\n" + vendored + "\n\n" + tail);
console.log("observer.js vendored; imports remaining:", /^import\s*\{/m.test(read("observer.js")) ? "PRESENT (bad)" : "none (ok)");
