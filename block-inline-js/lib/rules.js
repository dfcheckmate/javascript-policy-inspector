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
 * Multi-label public suffixes needing a 3-label registrable dominance match.
 * This is a pragmatic, curated subset (no PSL dependency ships with the
 * extension). Unknown multi-label suffixes fall back to the last 2 labels;
 * `localhost` and IP addresses pass through untouched.
 */
const MULTI_LABEL_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "ne.jp", "ac.jp",
  "com.au", "net.au", "org.au", "co.nz", "net.nz", "org.nz",
  "co.in", "com.br", "com.mx", "co.za", "co.il", "com.tr", "co.kr",
  "com.cn", "net.cn", "org.cn", "com.hk", "com.sg", "com.my",
  "co.th", "com.tw", "com.vn", "com.pe", "com.co", "com.ar",
  "com.eg", "com.sa", "com.ua",
]);

/**
 * Reduces any hostname to its registrable (eTLD+1) form.
 *
 * This matters for DNR `requestDomains`: `["example.com"]` matches the apex
 * AND every subdomain, but `["www.example.com"]` matches only www + its
 * subdomains — MISSING the apex. Folding to the apex here means every
 * subdomain of a site collapses to one rule, so entering `www.example.com`
 * or `api.example.com` both govern the whole site instead of half-overlapping.
 *
 * @param {string|unknown} host e.g. "www.example.com" → "example.com"
 * @returns {string} normalized host; "" for empty input
 */
export function normalizeHostForRule(host) {
  const h = String(host ?? "").trim().toLowerCase().replace(/\.$/, "");
  if (!h) return "";
  const isIpv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(h);
  const isHostLike = /^[a-z0-9.-]+$/.test(h);
  // IPs, IPv6 (has ':'), and single labels can't be folded further.
  if (isIpv4 || !isHostLike || !h.includes(".")) return h;
  const labels = h.split(".");
  if (labels.length <= 2) return h;
  const lastTwo = labels.slice(-2).join(".");
  if (MULTI_LABEL_SUFFIXES.has(lastTwo)) return labels.slice(-3).join(".");
  return lastTwo;
}

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
 * Builds a modifyHeaders rule that appends the mode's CSP to every document
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
 * @param {string} mode one of MODES (observe has no CSP and yields no rule)
 * @param {{origins?: string[], scriptHashes?: string[], attrHashes?: string[]}} [allows]
 * @returns {chrome.declarativeNetRequest.Rule}
 * @throws {Error} unknown mode or a mode without an enforceable policy
 */
export function buildRule(host, mode, allows = {}) {
  if (!isMode(mode)) throw new Error(`unknown mode: ${mode}`);
  const value = composePolicy(mode, allows);
  if (!value) throw new Error(`mode "${mode}" has no enforceable CSP`);
  const apex = normalizeHostForRule(host);
  return {
    id: ruleIdFor(apex),
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
