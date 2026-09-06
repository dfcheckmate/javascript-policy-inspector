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

// SHA-256 digest is 32 bytes → 44 base64 chars (plus up to 2 '=') when
// unpadded/padded. Requiring a near-full body rejects truncated tokens early
// (a short hash can never match any script) so composePolicy doesn't emit a
// dead source and the UI can report a clear error.
const SHA256_RE = /^sha256-[A-Za-z0-9+/]{40,}={0,2}$/;

/**
 * Composes the CSP for a mode plus optional per-site allowances.
 * Allowance items (strings) are routed by shape:
 * - "https://origin"            → script-src source
 * - "sha256-BASE64"             → script-src hash (allows one inline script)
 * - "attr-sha256-BASE64"        → script-src-attr hash (allows one handler)
 *
 * firstPartyOnly: `'self'` + origins + script hashes.
 * noScripts: origins + script hashes only (`'none'` while all lists are empty).
 * Attr hashes replace `script-src-attr 'none'`; without them handlers stay dead.
 *
 * @param {string} mode one of MODES
 * @param {{origins?: string[], scriptHashes?: string[], attrHashes?: string[]}} [allows]
 * @returns {string | null} policy value or null for observe
 */
export function composePolicy(mode, allows = {}) {
  const base = CSP_POLICIES[mode];
  if (!base) return null;

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

  if (origins.length === 0 && scriptHashes.length === 0 && attrHashes.length === 0) {
    return base;
  }
  const srcParts = [...origins, ...scriptHashes];
  const scriptSrc =
    mode === MODES.FIRST_PARTY_ONLY
      ? ["'self'", ...srcParts].join(" ")
      : srcParts.length > 0
        ? srcParts.join(" ")
        : "'none'";
  const attrDirective =
    attrHashes.length > 0 ? `script-src-attr ${attrHashes.join(" ")}` : "script-src-attr 'none'";
  return `script-src ${scriptSrc}; ${attrDirective}; object-src 'none'; base-uri 'none'`;
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
