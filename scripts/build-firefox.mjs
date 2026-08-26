/**
 * Bundles block-inline-js/service-worker.js + its local imports into a
 * single file (service-worker.bundled.js) for Firefox MV3, which does
 * not yet support ES modules in background scripts.
 *
 * Usage:  node scripts/build-firefox.mjs
 *   or:   yarn build:firefox
 */
import fs from "node:fs";
import path from "node:path";

const srcDir = path.resolve("block-inline-js");

function resolveLocal(fromFile, specifier) {
  if (!specifier.startsWith(".")) return null;
  const dir = path.dirname(fromFile);
  let p = path.resolve(dir, specifier);
  if (!fs.existsSync(p)) p += ".js";
  return fs.existsSync(p) ? p : null;
}

const seen = new Set();
const chunks = [];

function inline(filePath) {
  if (seen.has(filePath)) return;
  seen.add(filePath);
  let src = fs.readFileSync(filePath, "utf8");

  // Recursively inline nested local imports before stripping them.
  src = src.replace(
    /^import\s*\{[^}]+\}\s*from\s*"\.\/[^"]+"\s*;?\s*$/gm,
    (match) => {
      const m = match.match(/from\s*"([^"]+)"/);
      if (!m) return "";
      const dep = resolveLocal(filePath, m[1]);
      if (dep) {
        inline(dep);
        return "";
      }
      return match; // keep non-local imports (there shouldn't be any)
    },
  );

  // Strip export keywords so top-level declarations become script-scoped.
  src = src.replace(/^export\s+/gm, "");
  const label = path.relative(srcDir, filePath);
  chunks.push(`// --- ${label} ---\n${src}\n`);
}

inline(path.join(srcDir, "service-worker.js"));

const out = path.join(srcDir, "service-worker.bundled.js");
fs.writeFileSync(out, chunks.join("\n"));
console.log(`✓ ${out} (${chunks.length} modules, ${fs.statSync(out).size} bytes)`);
