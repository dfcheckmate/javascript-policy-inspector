/**
 * Produces a self-contained Firefox-ready build at dist-firefox/.
 *
 * The folder contains a single manifest.json (Firefox version) and no
 * Chrome-specific files, so "Load Temporary Add-on" works unambiguously.
 *
 * Usage:  node scripts/build-firefox.mjs
 *   or:   yarn build:firefox
 */
import fs from "node:fs";
import path from "node:path";

const srcDir = path.resolve("block-inline-js");
const distDir = path.resolve("dist-firefox");

// ---------------------------------------------------------------------------
// 1. Bundle service-worker.js + its local imports into a single flat file
// ---------------------------------------------------------------------------

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
      return match;
    },
  );

  src = src.replace(/^export\s+/gm, "");
  const label = path.relative(srcDir, filePath);
  chunks.push(`// --- ${label} ---\n${src}\n`);
}

inline(path.join(srcDir, "service-worker.js"));

// ---------------------------------------------------------------------------
// 2. Write dist-firefox/  (manifest.json = Firefox version)
// ---------------------------------------------------------------------------

fs.rmSync(distDir, { recursive: true, force: true });
fs.mkdirSync(distDir, { recursive: true });

fs.writeFileSync(
  path.join(distDir, "service-worker.bundled.js"),
  chunks.join("\n"),
);

// Copy all extension files except Chrome-only manifests and the build output
const skip = new Set([
  "manifest.json",
  "manifest.firefox.json",
  "service-worker.bundled.js",
]);

for (const entry of fs.readdirSync(srcDir)) {
  if (skip.has(entry)) continue;
  const src = path.join(srcDir, entry);
  const dst = path.join(distDir, entry);
  if (fs.statSync(src).isDirectory()) {
    fs.cpSync(src, dst, { recursive: true });
  } else {
    fs.copyFileSync(src, dst);
  }
}

// Write the Firefox manifest AS manifest.json (the only one Firefox will see)
const firefoxManifest = JSON.parse(
  fs.readFileSync(path.join(srcDir, "manifest.firefox.json"), "utf8"),
);
fs.writeFileSync(
  path.join(distDir, "manifest.json"),
  JSON.stringify(firefoxManifest, null, 2) + "\n",
);

const size = fs
  .readdirSync(distDir)
  .reduce((s, f) => s + fs.statSync(path.join(distDir, f)).size, 0);
console.log(
  `✓ dist-firefox/ ready  (${Object.keys(firefoxManifest).length} manifest keys, ${size} bytes total)`,
);
