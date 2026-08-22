/**
 * declarativeNetRequest rule construction for per-site JavaScript policies.
 * Imported by both the service worker and the popup (ESM); must stay free of
 * chrome.* calls so it remains unit-testable under plain Node.
 */

import { composePolicy, isMode } from "./policies.js";

/**
 * Rule-ID bands (rule IDs are int32, max 2^31 - 1).
 * Reserving disjoint ranges up front prevents collisions once v0.3 adds
 * tab-scoped override rules alongside the per-site policy rules.
 */
export const RULE_BANDS = Object.freeze({
  /** Per-site CSP policy rules: 1 – 99,999,999 */
  SITE_POLICY: 1,
  /** Tab-scoped temporary overrides (v0.3): 100,000,000 – 199,999,999 */
  TAB_OVERRIDE: 100_000_000,
});

const SITE_POLICY_ID_SPAN = RULE_BANDS.TAB_OVERRIDE - RULE_BANDS.SITE_POLICY;

/**
 * Deterministic rule ID for a hostname (FNV-1a folded into the site-policy
 * band). Dynamic rules persist across browser restarts, so deriving IDs from
 * the hostname removes the need for bookkeeping storage.
 * @param {string} host e.g. "example.com"
 * @returns {number} stable positive rule id
 */
export function ruleIdFor(host) {
  let h = 0x811c9dc5;
  for (let i = 0; i < host.length; i++) {
    h ^= host.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  const slot = (h >>> 1) % SITE_POLICY_ID_SPAN;
  return RULE_BANDS.SITE_POLICY + slot;
}

/**
 * Builds a modifyHeaders rule that appends the mode's CSP to every document
 * response served by `host`.
 *
 * `append` (not `set`) is deliberate: when the site sends its own CSP, both
 * policies are enforced (they intersect), so ours can only ever add
 * restrictions — never weaken the site's own policy.
 *
 * @param {string} host
 * @param {string} mode one of MODES (observe has no CSP and yields no rule)
 * @param {{origins?: string[], scriptHashes?: string[], attrHashes?: string[]}} [allows]
 * @returns {chrome.declarativeNetRequest.Rule}
 * @throws {Error} unknown mode or a mode without an enforceable policy
 */
export function buildRule(host, mode, allows = {}) {
  if (!isMode(mode)) throw new Error(`unknown mode: ${mode}`);
  const value = composePolicy(mode, allows);
  if (!value) throw new Error(`mode "${mode}" has no enforceable CSP`);
  return {
    id: ruleIdFor(host),
    priority: 1,
    action: {
      type: "modifyHeaders",
      responseHeaders: [
        { header: "Content-Security-Policy", operation: "append", value },
      ],
    },
    condition: {
      requestDomains: [host],
      resourceTypes: ["main_frame", "sub_frame"],
    },
  };
}

/**
 * True when the given dynamic rule was produced by buildRule for `host`.
 * Used by the reconciler to identify which rules belong to us.
 * @param {chrome.declarativeNetRequest.Rule} rule
 * @param {string} host
 * @returns {boolean}
 */
export function isPolicyRuleFor(rule, host) {
  return (
    rule.id === ruleIdFor(host) &&
    rule.action?.type === "modifyHeaders" &&
    rule.condition?.requestDomains?.[0] === host
  );
}
