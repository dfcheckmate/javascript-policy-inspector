/**
 * JavaScript Policy Inspector — per-site enforcement modes.
 *
 * A mode maps to an appended Content-Security-Policy response header.
 * `observe` intentionally has no policy: scripts run untouched while the
 * observer content script records what loads.
 */

export const MODES = Object.freeze({
  OBSERVE: "observe",
  FIRST_PARTY_ONLY: "firstPartyOnly",
  NO_SCRIPTS: "noScripts",
});

const MODE_VALUES = new Set(Object.values(MODES));

/**
 * CSP per mode. Omitting 'unsafe-inline' blocks inline <script> blocks and
 * javascript: URIs; omitting 'unsafe-eval' additionally blocks eval() /
 * new Function(); script-src-attr 'none' kills inline event handlers.
 *
 * firstPartyOnly ('self') also refuses every cross-origin script, which is
 * what makes "first-party only" enforceable without source inspection.
 */
export const CSP_POLICIES = Object.freeze({
  [MODES.OBSERVE]: null,
  [MODES.FIRST_PARTY_ONLY]:
    "script-src 'self'; script-src-attr 'none'; object-src 'none'; base-uri 'none'",
  [MODES.NO_SCRIPTS]:
    "script-src 'none'; script-src-attr 'none'; object-src 'none'; base-uri 'none'",
});

/**
 * One-line human explanation per mode — surfaced in the popup so users can
 * see what a mode does without reading CSP syntax.
 */
export const POLICY_SUMMARY = Object.freeze({
  [MODES.OBSERVE]: "All scripts allowed. Activity is being observed.",
  [MODES.FIRST_PARTY_ONLY]:
    "Same-origin scripts only. Inline JS, eval(), inline handlers and third-party scripts are blocked.",
  [MODES.NO_SCRIPTS]: "All page JavaScript is blocked.",
});

/** @param {unknown} value @returns {boolean} true for valid mode strings */
export function isMode(value) {
  return typeof value === "string" && MODE_VALUES.has(value);
}

/** Default mode for hosts with no stored preference. */
export const DEFAULT_MODE = MODES.OBSERVE;

/**
 * Composes the CSP for a mode plus optional per-site allowed origins.
 * - firstPartyOnly: `'self'` plus the given origins
 * - noScripts: the origins only (`'none'` while the list is empty)
 *
 * @param {string} mode one of MODES
 * @param {string[]} exceptionOrigins full origins, e.g. "https://cdn.example.com"
 * @returns {string | null} policy value or null for observe
 */
export function composePolicy(mode, exceptionOrigins = []) {
  const base = CSP_POLICIES[mode];
  if (!base) return null;
  const origins = [
    ...new Set(exceptionOrigins.map((o) => String(o).trim()).filter(Boolean)),
  ];
  if (origins.length === 0) return base;
  if (mode === MODES.NO_SCRIPTS) {
    return `script-src ${origins.join(" ")}; script-src-attr 'none'; object-src 'none'; base-uri 'none'`;
  }
  return base.replace("'self'", `'self' ${origins.join(" ")}`);
}

/** Validates that a string is a usable http(s) origin for exceptions.
 * @param {unknown} input
 * @returns {string | null}
 */
export function normalizeOrigin(input) {
  let url;
  try {
    url = new URL(String(input));
  } catch {
    return null;
  }
  return /^https?:$/.test(url.protocol) ? url.origin : null;
}
