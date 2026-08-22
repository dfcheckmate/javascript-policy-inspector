/**
 * Shared rule-building logic for the Inline JS Blocker.
 * Imported by both the service worker and the popup (ESM).
 */

/**
 * CSP appended to matched documents.
 *
 * - `script-src * data: blob:`  → external scripts from anywhere keep running
 *   (`*` does NOT cover data:/blob:, so they are listed explicitly).
 * - Omitting `'unsafe-inline'`  → blocks inline <script> blocks and
 *   `javascript:` URIs.
 * - `'unsafe-eval'`             → keeps eval()/new Function() working, since
 *   the goal is inline code only. Remove this token to also kill eval.
 * - `script-src-attr 'none'`    → blocks inline event handler attributes
 *   (onclick="...", onerror="...", ...).
 */
export const CSP_VALUE = "script-src * data: blob: 'unsafe-eval'; script-src-attr 'none'";

/**
 * Deterministic rule ID for a hostname (FNV-1a, folded into int31 range).
 * Dynamic rules persist across browser restarts; deriving IDs from the
 * hostname means no extra bookkeeping storage is needed.
 * @param {string} host e.g. "example.com"
 * @returns {number} positive rule id
 */
export function ruleIdFor(host) {
  let h = 0x811c9dc5;
  for (let i = 0; i < host.length; i++) {
    h ^= host.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  const id = h >>> 1;
  return id === 0 ? 1 : id;
}

/**
 * Host-permission patterns that must be granted for the DNR rule to apply.
 * Covers the apex host and all of its subdomains, http and https.
 * @param {string} host
 * @returns {string[]}
 */
export function patternsFor(host) {
  return [`*://${host}/*`, `*://*.${host}/*`];
}

/**
 * Builds a declarativeNetRequest modifyHeaders rule that appends our CSP to
 * every document response served by `host`.
 *
 * `append` (not `set`) is intentional: if the site already sends a CSP, both
 * are enforced (intersection). Our policy can only add restrictions — inline
 * JS is blocked regardless of what the site's own CSP allows.
 * @param {string} host
 * @returns {chrome.declarativeNetRequest.Rule}
 */
export function buildRule(host) {
  return {
    id: ruleIdFor(host),
    priority: 1,
    action: {
      type: "modifyHeaders",
      responseHeaders: [
        { header: "Content-Security-Policy", operation: "append", value: CSP_VALUE },
      ],
    },
    condition: {
      requestDomains: [host],
      resourceTypes: ["main_frame", "sub_frame"],
    },
  };
}
