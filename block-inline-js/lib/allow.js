/**
 * allow.js — shared validation/canonicalization for per-site allowances.
 *
 * Both the service worker (which stores hashes/digests) and the popup (which
 * renders allow state from those stores) must agree on one canonical form, or
 * rows drift apart: handler hashes are recorded by the observer with an
 * `attr-` prefix but persisted unprefixed in the store. Centralizing the
 * stripping/validation here keeps the UI's "already allowed" detection true
 * and guarantees every Allow button submits a token the store accepts.
 */

/** CSP sha256 token as produced by the observer's fingerprint(): "sha256-" + 44 base64 chars. */
export const ALLOWED_HASH_RE = /^sha256-[A-Za-z0-9+/]{40,}={0,2}$/;

/** Container fingerprints are recorded as 64 hex chars (lowercase). */
export const CONTAINER_DIGEST_RE = /^[0-9a-f]{64}$/;

/**
 * Validates + normalizes an inline hash token for storage. Tolerates the
 * observer's `attr-` prefix (handlers) so both kinds route through one path.
 * @param {string} hash
 * @returns {string} unprefixed "sha256-…" token
 * @throws {Error} when the token can never match a script/handler
 */
export function normalizeInlineHash(hash) {
  const clean = String(hash).replace(/^attr-/, "");
  if (!ALLOWED_HASH_RE.test(clean)) {
    throw new Error(
      "invalid sha256 token (expected sha256- followed by 44 base64 chars)",
    );
  }
  return clean;
}

/**
 * Canonical identity for set-membership checks: what a container digest or
 * inline hash "is" in the store. Strips the observer's `attr-` handler prefix;
 * origins and container digests pass through untouched.
 * @param {string | null | undefined} value
 * @returns {string}
 */
export function canonicalAllowKey(value) {
  return String(value ?? "").replace(/^attr-/, "");
}