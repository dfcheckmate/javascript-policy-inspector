/**
 * JavaScript Policy Inspector — per-site enforcement modes.
 *
 * A mode maps to an appended Content-Security-Policy response header.
 * `observe` intentionally has no policy: scripts run untouched while the
 * observer content script records what loads.
 *
 * SCOPE (deliberate choices, not omissions):
 * - We gate script EXECUTION, not data flow. `connect-src` is unset, so
 *   XHR/fetch/WebSocket are unrestricted and a same-origin script can still
 *   exfiltrate cross-origin (subject to CORS). Tracking that is out of scope.
 * - `worker-src`/`child-src` are unset and fall back to `script-src`. In
 *   NO_SCRIPTS (`script-src 'none'`) Web Workers are therefore implicitly
 *   blocked; in FIRST_PARTY_ONLY same-origin workers are allowed. Intentional.
 * - `style-src` and `form-action` are unset: inline styles still work
 *   (fine for script-blocking) and forms may submit anywhere — the next
 *   directive to add if the extension grows beyond script control.
 * - `script-src-attr` is only honored by Chrome 111+ / Firefox 118+. Older
 *   engines ignore it and fall back to `script-src`, so (lacking
 *   'unsafe-inline') handlers are still blocked — a conservative failure.
 */

import { MODES, PRESETS } from "./flags.js";

// Modes now live in lib/flags.js (the flag bundle is the source of truth);
// re-exporting keeps existing importers working.
export { MODES } from "./flags.js";

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

// SHA-256 digest is 32 bytes → 44 base64 chars (plus up to 2 '=') when
// unpadded/padded. Requiring a near-full body rejects truncated tokens early
// (a short hash can never match any script) so composePolicy doesn't emit a
// dead source and the UI can report a clear error.
const SHA256_RE = /^sha256-[A-Za-z0-9+/]{40,}={0,2}$/;

/**
 * Composes a CSP from a flag bundle plus optional per-site allowances.
 * Allowance items (strings) are routed by shape:
 * - "https://origin"            → script-src source
 * - "sha256-BASE64"             → script-src hash (allows one inline script)
 * - "attr-sha256-BASE64"        → script-src-attr hash (allows one handler)
 *
 * The posture (what `script-src` is rooted at) is derived from flags:
 * - blockExternalScripts                       → `'none'` (origins replace it)
 * - blockThirdPartyScripts                     → `'self'` (+ origins)
 * - only blockClassicScripts + blockModuleScripts → `*` (block inline, allow all external)
 * - no executable/attr flag set               → null (container/report-only bundle;
 *   those flags are served by the DOM/reporting layer, not CSP)
 *
 * Combos that would require allowing inline execution while enforcing
 * handlers — any enforced posture with blockClassicScripts/blockModuleScripts
 * off, or attr-only bundles — are unexpressible because the extension never
 * emits 'unsafe-inline'; composePolicyFromFlags throws so the service worker
 * can never deploy a broken header.
 *
 * Attr hashes replace `script-src-attr 'none'`; without them handlers stay dead.
 *
 * @param {{[K in keyof typeof import("./flags.js").DEFAULT_FLAGS]: boolean}} flags
 * @param {{origins?: string[], scriptHashes?: string[], attrHashes?: string[]}} [allows]
 * @returns {string | null} policy value or null when the bundle needs no CSP
 */
export function composePolicyFromFlags(flags, allows = {}) {
  const posture = postureOf(flags);
  if (posture.head === null) return null;

  const origins = dedupe((allows.origins ?? []).map(normalizeOrigin).filter(Boolean));
  const scriptHashes = dedupe(
    (allows.scriptHashes ?? []).map(String).filter((h) => SHA256_RE.test(h)),
  );
  // tolerate the observer's "attr-" prefixed form
  const attrHashes = dedupe(
    (allows.attrHashes ?? [])
      .map((h) => String(h).replace(/^attr-/, ""))
      .filter((h) => SHA256_RE.test(h)),
  );

  const srcParts = [...origins, ...scriptHashes];
  const scriptSrc =
    posture.head === "'none'"
      ? srcParts.length > 0
        ? srcParts.join(" ")
        : "'none'"
      : [posture.head, ...srcParts].join(" ");
  const attrDirective =
    attrHashes.length > 0 ? `script-src-attr ${attrHashes.join(" ")}` : "script-src-attr 'none'";
  return `script-src ${scriptSrc}; ${attrDirective}; object-src 'none'; base-uri 'none'`;
}

/**
 * Composes the CSP for a mode (preset) plus optional per-site allowances —
 * a thin wrapper over composePolicyFromFlags so the presets and the flat flag
 * model can never drift.
 *
 * @param {string} mode one of MODES
 * @param {{origins?: string[], scriptHashes?: string[], attrHashes?: string[]}} [allows]
 * @returns {string | null} policy value or null for observe
 */
export function composePolicy(mode, allows = {}) {
  if (!isMode(mode)) return null;
  return composePolicyFromFlags(PRESETS[mode], allows);
}

const NON_EXPRESSIBLE_REASON =
  "flag combination is not expressible without emitting 'unsafe-inline'";

/**
 * Root `script-src` source for a flag bundle, or null when the bundle needs
 * no CSP at all. Throws for postures this extension refuses to deploy.
 */
function postureOf(flags) {
  const wantsCsp =
    flags.blockExternalScripts ||
    flags.blockThirdPartyScripts ||
    flags.blockClassicScripts ||
    flags.blockModuleScripts ||
    flags.blockInlineEventHandlers ||
    flags.blockJavascriptUrls;

  if (!wantsCsp) {
    // Container/report-only bundles are served by the DOM/reporting layer.
    return { head: null };
  }

  if (!flags.blockClassicScripts || !flags.blockModuleScripts) {
    throw new Error(NON_EXPRESSIBLE_REASON);
  }

  const head = flags.blockExternalScripts
    ? "'none'"
    : flags.blockThirdPartyScripts
      ? "'self'"
      : "*";
  return { head };
}

function dedupe(list) {
  return [...new Set(list)];
}

/**
 * Builds a deployable CSP header from the current functional state of a host.
 * Reuses composePolicy so the header always matches what the extension would
 * enforce. Returns null when the host is in Observe (no policy to deploy).
 *
 * @param {string} mode one of MODES
 * @param {{origins?: string[], scriptHashes?: string[], attrHashes?: string[]}} [allows]
 * @returns {string | null} e.g. "Content-Security-Policy: script-src 'self' …"
 */
export function composeHeader(mode, allows = {}) {
  const value = composePolicy(mode, allows);
  if (value === null) return null;
  return `Content-Security-Policy: ${value}`;
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
