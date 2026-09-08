/**
 * stats.js — pure per-tab counter derivation.
 *
 * Extracted from the service worker so the event-shape evolution (v1 `kind`
 * fields → v2 `category`/`action`-based records) stays unit-testable under
 * plain Node. Counters added by the layered-policy engine: removed containers,
 * category breakdowns (JSON-LD, JSON data, import maps, speculation rules)
 * and javascript: URLs, with `blocked` now distinct from `removed`.
 */

/** All-zero starting counters; spreading guarantees no missing key. */
export const INITIAL_STATS = Object.freeze({
  scriptsFirstParty: 0,
  scriptsThirdParty: 0,
  inlineScripts: 0,
  inlineHandlers: 0,
  blocked: 0,
  removed: 0,
  javascriptUrls: 0,
  jsonLd: 0,
  jsonData: 0,
  importMaps: 0,
  specRules: 0,
});

const CONTAINER_STATS = Object.freeze({
  "json-ld": "jsonLd",
  "json-data": "jsonData",
  "import-map": "importMaps",
  "speculation-rules": "specRules",
});

/**
 * Counts the events (v1 legacy kinds and v2 category records) into a fresh
 * stats object. `blocked` counts CSP violations plus any record whose
 * action is "blocked" (excluding csp-violation so the same event never counts
 * twice); `removed` counts DOM-layer removals of non-executable containers.
 * @param {Array<object>} events
 */
export function computeStats(events) {
  const stats = { ...INITIAL_STATS };

  for (const e of events ?? []) {
    if (!e || typeof e !== "object") continue;

    switch (e.kind) {
      case "script":
        if (e.party === "third") stats.scriptsThirdParty++;
        else if (e.party === "first") stats.scriptsFirstParty++;
        break;
      case "inline-script":
        stats.inlineScripts++;
        break;
      case "inline-handler":
        stats.inlineHandlers++;
        break;
      case "csp-violation":
        stats.blocked++;
        break;
      // v2 records
      case "script-element":
        if (e.category === "external-javascript") {
          if (e.party === "third") stats.scriptsThirdParty++;
          else if (e.party === "first") stats.scriptsFirstParty++;
        } else if (!e.category || e.category === "inline-javascript") {
          // Container records (json-ld/json-data/import-map/…) carry other
          // categories and must never count as inline scripts.
          stats.inlineScripts++;
        }
        break;
      case "handler-attr":
        stats.inlineHandlers++;
        break;
      case "javascript-url":
        stats.javascriptUrls++;
        break;
    }

    const viaCategory = CONTAINER_STATS[e.category];
    if (viaCategory) stats[viaCategory]++;

    if (e.action === "blocked" && e.kind !== "csp-violation") stats.blocked++;
    if (e.action === "removed") stats.removed++;
  }

  return stats;
}