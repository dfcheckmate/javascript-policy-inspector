/**
 * Produces two self-contained, clearly-labelled build outputs:
 *   - dist-edge/     Chrome / Edge (manifest uses "service_worker" + module SW)
 *   - dist-firefox/  Firefox (manifest uses "background.scripts", bundled SW)
 *
 * Each folder contains exactly ONE manifest.json suited to its browser and
 * none of the other's manifests, so you can copy the whole folder for the
 * matching browser without ever loading the wrong manifest file.
 *
 * Usage:  node scripts/build-firefox.mjs
 *   or:   yarn build:firefox
 */
import fs from "node:fs";
import path from "node:path";

const srcDir = path.resolve("block-inline-js");
const distDevDir = path.resolve("dist-edge");
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
// 2. Write the per-browser distributions
// ---------------------------------------------------------------------------

// Files never used by ANY browser dist. Per-browser SW files are handled
// explicitly below (the bundled SW is Firefox-only, the module SW Edge-only).
const sharedSkip = new Set([
  "manifest.json",
  "manifest.firefox.json",
  "service-worker.bundled.js",
]);

function emitDist(dir, extraSkip = []) {
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });

  const skip = new Set([...sharedSkip, ...extraSkip]);
  for (const entry of fs.readdirSync(srcDir)) {
    if (skip.has(entry)) continue;
    const src = path.join(srcDir, entry);
    const dst = path.join(dir, entry);
    if (fs.statSync(src).isDirectory()) {
      fs.cpSync(src, dst, { recursive: true });
    } else {
      fs.copyFileSync(src, dst);
    }
  }
}

// --- Firefox (background.scripts + bundled single-file SW) ---
// Drop the module SW (service-worker.js); write the bundled one explicitly.
emitDist(distDir, ["service-worker.js"]);
fs.writeFileSync(
  path.join(distDir, "service-worker.bundled.js"),
  chunks.join("\n"),
);

const firefoxManifest = JSON.parse(
  fs.readFileSync(path.join(srcDir, "manifest.firefox.json"), "utf8"),
);
fs.writeFileSync(
  path.join(distDir, "manifest.json"),
  JSON.stringify(firefoxManifest, null, 2) + "\n",
);

// --- Chrome / Edge (service_worker + ES-module SW + lib/ imports) ---
// Keep service-worker.js and lib/; drop the bundled SW + tests dir.
emitDist(distDevDir, ["service-worker.bundled.js", "tests"]);

const chromeManifest = JSON.parse(
  fs.readFileSync(path.join(srcDir, "manifest.json"), "utf8"),
);
fs.writeFileSync(
  path.join(distDevDir, "manifest.json"),
  JSON.stringify(chromeManifest, null, 2) + "\n",
);

const size = (dir) =>
  fs
    .readdirSync(dir)
    .reduce((s, f) => s + fs.statSync(path.join(dir, f)).size, 0);
console.log(
  `✓ dist-edge/ ready     (${Object.keys(chromeManifest).length} manifest keys, ${size(distDevDir)} bytes total)`,
);
console.log(
  `✓ dist-firefox/ ready  (${Object.keys(firefoxManifest).length} manifest keys, ${size(distDir)} bytes total)`,
);
