/**
 * JavaScript Policy Inspector — lightweight dependency-free syntax highlighter.
 *
 * Produces an array of {text, cls} spans from JS source using the same
 * opaque-lexing discipline as lib/beautify: strings, templates, regexes and
 * comments are classified at a whole-token level and their bytes preserved.
 * It intentionally does NOT tokenise every language construct; it covers the
 * four high-signal categories (keyword, string, comment, number) plus plain
 * text, which is enough to make short inline snippets scannable without
 * shipping (or depending on) a real highlighter.
 *
 * Returns plain structured data — the caller renders it with DOM
 * createElement/textContent (never innerHTML), so untrusted source can't
 * inject markup.
 */

const IDENT_CHAR = /[A-Za-z0-9_$]/;

const KEYWORDS = new Set([
  "await", "break", "case", "catch", "class", "const", "continue", "debugger",
  "default", "delete", "do", "else", "export", "extends", "finally", "for",
  "function", "if", "import", "in", "instanceof", "let", "new", "of", "return",
  "static", "super", "switch", "throw", "try", "typeof", "var", "void", "while",
  "with", "yield",
]);
const LITERALS = new Set(["true", "false", "null", "undefined", "this", "NaN", "Infinity"]);

/**
 * @param {string} src
 * @returns {{text: string, cls: string}[]} styled spans
 */
export function highlight(src) {
  if (typeof src !== "string" || src === "") return [];
  const spans = [];
  let i = 0;
  const n = src.length;

  const push = (text, cls = "") => {
    if (text === "") return;
    const last = spans[spans.length - 1];
    if (last && last.cls === cls) last.text += text;
    else spans.push({ text, cls });
  };

  while (i < n) {
    const ch = src[i];

    if (/\s/.test(ch)) {
      const j = skipWhile(src, i, /\s/);
      push(src.slice(i, j));
      i = j;
      continue;
    }
    if (ch === "/" && src[i + 1] === "/") {
      const j = idxOfNewline(src, i);
      push(src.slice(i, j), "comment");
      i = j;
      continue;
    }
    if (ch === "/" && src[i + 1] === "*") {
      const end = src.indexOf("*/", i + 2);
      const j = end === -1 ? n : end + 2;
      push(src.slice(i, j), "comment");
      i = j;
      continue;
    }
    if (ch === '"' || ch === "'") {
      const j = scanQuote(src, i, ch);
      push(src.slice(i, j), "string");
      i = j;
      continue;
    }
    if (ch === "`") {
      const j = scanTemplate(src, i);
      push(src.slice(i, j), "string");
      i = j;
      continue;
    }
    if (ch === "/" && isRegex(src, i)) {
      const j = scanRegex(src, i);
      push(src.slice(i, j), "regex");
      i = j;
      continue;
    }
    if (/[A-Za-z_$]/.test(ch)) {
      const j = skipWhile(src, i, IDENT_CHAR);
      const word = src.slice(i, j);
      let cls = "";
      if (KEYWORDS.has(word)) cls = "kw";
      else if (LITERALS.has(word)) cls = "lit";
      else if (startsCall(src, j)) cls = "fn";
      push(word, cls);
      i = j;
      continue;
    }
    if (/[0-9]/.test(ch) || (ch === "." && /[0-9]/.test(src[i + 1] ?? ""))) {
      const j = skipWhile(src, i, /[0-9a-fA-FxXoO_bBeE+\-.]/);
      push(src.slice(i, j), "num");
      i = j;
      continue;
    }
    push(ch);
    i++;
  }
  return spans;
}

function skipWhile(src, i, re) {
  let j = i;
  while (j < src.length && re.test(src[j])) j++;
  return j;
}

function idxOfNewline(src, i) {
  const j = src.indexOf("\n", i);
  return j === -1 ? src.length : j;
}

function scanQuote(src, start, quote) {
  let j = start + 1;
  while (j < src.length) {
    const c = src[j];
    if (c === "\\") { j += 2; continue; }
    if (c === quote) return j + 1;
    j++;
  }
  return src.length;
}

function scanTemplate(src, start) {
  let j = start + 1;
  while (j < src.length) {
    const c = src[j];
    if (c === "\\") { j += 2; continue; }
    if (c === "`") return j + 1;
    if (c === "$" && src[j + 1] === "{") {
      let depth = 1;
      j += 2;
      while (j < src.length && depth > 0) {
        const d = src[j];
        if (d === "\\") { j += 2; continue; }
        if (d === "`") { j++; continue; }
        if (d === "{") depth++;
        else if (d === "}") depth--;
        j++;
      }
      continue;
    }
    j++;
  }
  return src.length;
}

function scanRegex(src, start) {
  let j = start + 1;
  let inClass = false;
  while (j < src.length) {
    const c = src[j];
    if (c === "\\") { j += 2; continue; }
    if (c === "[") inClass = true;
    else if (c === "]") inClass = false;
    else if (c === "/" && !inClass) { j++; break; }
    else if (c === "\n") break;
    j++;
  }
  while (j < src.length && IDENT_CHAR.test(src[j])) j++;
  return j;
}

/** crude but safe: a '/' is a regex when not preceded by an operand end */
function isRegex(src, i) {
  let j = i - 1;
  while (j >= 0 && /\s/.test(src[j])) j--;
  if (j < 0) return true;
  const c = src[j];
  if (/[A-Za-z0-9_$)\]}"]/.test(c) || c === "`") return false;
  return true;
}

/** True when the identifier at position `end` is immediately followed by `(`. */
function startsCall(src, end) {
  let j = end;
  while (j < src.length && /\s/.test(src[j])) j++;
  return src[j] === "(";
}
