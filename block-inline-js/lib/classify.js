/**
 * classify.js — pure script/container classification.
 *
 * Shared by the observer content script (DOM) and the node test-suite, so it
 * operates on a minimal descriptor instead of a live element:
 *   getScriptCategory({ src: string | null, type: string | null })
 *
 * Per the HTML spec a <script> element only executes when its `type` is empty
 * or a (legacy) JavaScript MIME type, or `module`. Every other type is a
 * *data block*: JSON-LD, JSON data, import maps, speculation rules, or an
 * unknown/typo'd MIME. Data blocks never execute and must never be reported
 * as inline JavaScript — this fixes the observer's blanket "no src ⇒
 * inline-script" misclassification.
 */

export const CATEGORIES = Object.freeze({
  JSON_LD: "json-ld",
  JSON_DATA: "json-data",
  IMPORT_MAP: "import-map",
  SPECULATION_RULES: "speculation-rules",
  INLINE_JAVASCRIPT: "inline-javascript",
  EXTERNAL_JAVASCRIPT: "external-javascript",
  JAVASCRIPT_URL: "javascript-url",
  UNKNOWN_SCRIPT_CONTAINER: "unknown-script-container",
});

/** Categories whose payload actually executes as JavaScript. */
export const EXECUTABLE_TYPES = Object.freeze([
  CATEGORIES.INLINE_JAVASCRIPT,
  CATEGORIES.EXTERNAL_JAVASCRIPT,
]);

// WHATWG "legacy-JavaScript MIME types" plus the "module" script language.
// Per spec, a MIME with parameters (e.g. "text/javascript; charset=utf-8") is
// NOT a JavaScript MIME type — it is a data block. Exact match after
// normalization, deliberately, to follow the spec.
const JS_LANGUAGE_TYPES = new Set([
  "application/ecmascript",
  "application/javascript",
  "application/x-ecmascript",
  "application/x-javascript",
  "text/ecmascript",
  "text/javascript",
  "text/javascript1.0",
  "text/javascript1.1",
  "text/javascript1.2",
  "text/javascript1.3",
  "text/javascript1.4",
  "text/javascript1.5",
  "text/jscript",
  "text/livescript",
  "text/x-ecmascript",
  "text/x-javascript",
  "module",
]);

/** Normalizes a `type` attribute for comparison: trimmed + lowercased. */
function normalizeType(type) {
  return (type ?? "").trim().toLowerCase();
}

/**
 * True when a <script> element with this `type` would execute (bare classic,
 * a legacy JS MIME, or a module).
 * @param {string | null | undefined} type
 * @returns {boolean}
 */
export function isJavaScriptType(type) {
  const t = normalizeType(type);
  return t === "" || JS_LANGUAGE_TYPES.has(t);
}

/**
 * Classifies a <script> element from its src/type attributes.
 * @param {{ src?: string | null, type?: string | null }} [descriptor]
 * @returns {string} one of CATEGORIES
 */
export function getScriptCategory({ src = null, type = null } = {}) {
  const hasSrc = typeof src === "string" && src.trim() !== "";
  const t = normalizeType(type);

  if (hasSrc) {
    // With a src, the element can still be a *fetched* container: import maps
    // and speculation rules may carry a src (JSON-LD/JSON-data never do).
    if (isJavaScriptType(t)) return CATEGORIES.EXTERNAL_JAVASCRIPT;
    switch (t) {
      case "importmap":
        return CATEGORIES.IMPORT_MAP;
      case "speculationrules":
        return CATEGORIES.SPECULATION_RULES;
      default:
        return CATEGORIES.UNKNOWN_SCRIPT_CONTAINER;
    }
  }

  if (isJavaScriptType(t)) return CATEGORIES.INLINE_JAVASCRIPT;

  switch (t) {
    case "application/ld+json":
      return CATEGORIES.JSON_LD;
    case "application/json":
      return CATEGORIES.JSON_DATA;
    case "importmap":
      return CATEGORIES.IMPORT_MAP;
    case "speculationrules":
      return CATEGORIES.SPECULATION_RULES;
    default:
      return CATEGORIES.UNKNOWN_SCRIPT_CONTAINER;
  }
}

/** @param {string | undefined} category @returns {boolean} true when executable */
export function isExecutable(category) {
  return EXECUTABLE_TYPES.includes(category);
}

/**
 * True for event-handler content attribute names (onclick, onload, …).
 * Browsers recognize lowercase `on<event>` names only, so "onClick"/"on1"
 * are not treated as handlers. Lexical approximation: only the *registered*
 * event names fire in browsers, but the registry is large and version-
 * dependent, so names like "once" are matched here rather than excluded.
 * @param {string | null | undefined} name
 * @returns {boolean}
 */
export function isInlineHandlerName(name) {
  return typeof name === "string" && /^on[a-z]+$/.test(name);
}

/**
 * True for `javascript:` URL strings. Whitespace between scheme and colon is
 * accepted, per the URL parser (e.g. "javascript\n:alert(1)").
 * @param {string | null | undefined} value
 * @returns {boolean}
 */
export function isJavaScriptUrl(value) {
  return typeof value === "string" && /^\s*javascript\s*:/i.test(value);
}