/**
 * declarativeNetRequest rule construction for per-site JavaScript policies.
 * Imported by both the service worker and the popup (ESM); must stay free of
 * chrome.* calls so it remains unit-testable under plain Node.
 */

import { composePolicyFromFlags } from "./policies.js";
import { isFlags } from "./flags.js";
import { normalizeHostForRule } from "./host.js";

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
 * band). The host is normalized to eTLD+1 first so subdomains share one
 * rule. Dynamic rules persist across browser restarts, so deriving IDs from
 * the hostname removes the need for a rule-ID registry.
 *
 * `>>> 0` keeps the full 32-bit unsigned entropy (FNV wraps on its own),
 * then folds modulo the band span for a non-negative id.
 * @param {string} host e.g. "example.com"
 * @returns {number} stable positive rule id
 */
export function ruleIdFor(host) {
  const h = normalizeHostForRule(host);
  let acc = 0x811c9dc5;
  for (let i = 0; i < h.length; i++) {
    acc ^= h.charCodeAt(i);
    acc = Math.imul(acc, 0x01000193);
  }
  const slot = (acc >>> 0) % SITE_POLICY_ID_SPAN;
  return RULE_BANDS.SITE_POLICY + slot;
}

/**
 * Builds a modifyHeaders rule that appends the policy's CSP to every document
 * response served by `host`.
 *
 * `append` (not `set`) is deliberate: when the site sends its own CSP, both
 * policies are enforced (they intersect), so ours can only ever add
 * restrictions — never weaken the site's own policy.
 *
 * `requestDomains` is always the eTLD+1 apex so one rule governs the whole
 * site (see normalizeHostForRule).
 *
 * All site-policy rules share priority 1; DNR breaks ties by higher rule id.
 * Since requestDomains is exact-registrable-domain, two rules never match the
 * same host — the tie-break is only a theoretical concern and is deterministic.
 *
 * @param {string} host
 * @param {{[K in keyof typeof import("./flags.js").DEFAULT_FLAGS]: boolean}} flags
 *   flag bundle; observe/container-only bundles have no CSP and yield no rule
 * @param {{origins?: string[], scriptHashes?: string[], attrHashes?: string[]}} [allows]
 * @param {number} [explicitId] caller-assigned rule id (collision-free allocation);
 *   defaults to ruleIdFor(host) for backward compatibility / standalone use
 * @param {number[]} [excludedTabIds] tabs to exempt from this rule (safe overrides
 *   that preserve the site's own CSP instead of removing headers)
 * @returns {chrome.declarativeNetRequest.Rule}
 * @throws {Error} invalid flags, an unexpressible bundle, or no enforceable CSP
 */
export function buildRule(
  host,
  flags,
  allows = {},
  explicitId = null,
  excludedTabIds = [],
) {
  if (!isFlags(flags)) throw new Error(`unknown policy flags: ${String(flags)}`);
  const value = composePolicyFromFlags(flags, allows);
  if (!value) throw new Error("policy has no enforceable CSP");
  const apex = normalizeHostForRule(host);
  const rule = {
    id: explicitId ?? ruleIdFor(apex),
    priority: 1,
    action: {
      type: "modifyHeaders",
      responseHeaders: [
        { header: "Content-Security-Policy", operation: "append", value },
      ],
    },
    condition: {
      requestDomains: [apex],
      resourceTypes: ["main_frame", "sub_frame"],
    },
  };
  if (excludedTabIds.length > 0) {
    rule.condition.excludedTabIds = excludedTabIds;
  }
  return rule;
}

/**
 * True when the given dynamic rule was produced by buildRule for `host`.
 * Used by the reconciler to identify which rules belong to us.
 * @param {chrome.declarativeNetRequest.Rule} rule
 * @param {string} host
 * @returns {boolean}
 */
export function isPolicyRuleFor(rule, host) {
  const apex = normalizeHostForRule(host);
  return (
    rule.id === ruleIdFor(apex) &&
    rule.action?.type === "modifyHeaders" &&
    rule.condition?.requestDomains?.[0] === apex
  );
}
