/**
 * host.js — host normalization (eTLD+1 folding).
 *
 * Shared by the service worker (policy keys + DNR requestDomains), the popup,
 * and the observer (matching a frame's hostname against stored policies).
 * Pure module: no chrome.* calls, unit-testable under Node.
 */

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