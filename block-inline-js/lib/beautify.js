/**
 * JavaScript Policy Inspector — minimal dependency-free JS formatter.
 *
 * Conservative pretty-printer. No AST, no third-party dependency. Safe for
 * arbitrary (possibly obfuscated) source: the lexer treats every string,
 * template literal, regex and comment as an opaque token, so their bytes are
 * never altered and formatting can never split or corrupt them. Re-joining
 * opaque tokens with normalised whitespace, per-statement lines and
 * brace-driven indentation cannot introduce a syntax error.
 *
 * Deliberately formats rather than deobfuscates: minified-but-plain scripts
 * become readable (the common case); packed/obfuscated payloads would require
 * an AST engine, which is a separate, heavier effort.
 *
 * NOTE: the lexer (tokenize, scan-string/template/regex, isRegexStart) is
 * shared in pattern with lib/highlight.js — keep edge-case fixes in sync
 * between the two files.
 */

const IDENT_CHAR = /[A-Za-z0-9_$]/;

// ---------------------------------------------------------------------------
// lexer — strings/templates/regexes/comments are opaque tokens
// ---------------------------------------------------------------------------

/**
 * @param {string} src
 * @returns {{kind:string,text:string}[]} token list
 */
export function tokenize(src) {
  const toks = [];
  let i = 0;
  const n = src.length;

  while (i < n) {
    const ch = src[i];

    if (/\s/.test(ch)) {
      const j = skipWhile(src, i, /\s/);
      toks.push({ kind: "ws", text: "" });
      i = j;
      continue;
    }
    if (ch === "/" && src[i + 1] === "/") {
      let j = src.indexOf("\n", i);
      if (j === -1) j = n;
      toks.push({ kind: "comment", text: src.slice(i, j) });
      i = j;
      continue;
    }
    if (ch === "/" && src[i + 1] === "*") {
      const end = src.indexOf("*/", i + 2);
      const j = end === -1 ? n : end + 2;
      toks.push({ kind: "comment", text: src.slice(i, j) });
      i = j;
      continue;
    }
    if (ch === '"' || ch === "'") {
      const j = scanString(src, i, ch);
      toks.push({ kind: "str", text: src.slice(i, j) });
      i = j;
      continue;
    }
    if (ch === "`") {
      const j = scanTemplate(src, i);
      toks.push({ kind: "tmpl", text: src.slice(i, j) });
      i = j;
      continue;
    }
    if (ch === "/" && isRegexStart(toks)) {
      const j = scanRegex(src, i);
      toks.push({ kind: "regex", text: src.slice(i, j) });
      i = j;
      continue;
    }
    if (/[A-Za-z_$]/.test(ch)) {
      const j = skipWhile(src, i, IDENT_CHAR);
      toks.push({ kind: "ident", text: src.slice(i, j) });
      i = j;
      continue;
    }
    if (/[0-9]/.test(ch) || (ch === "." && /[0-9]/.test(src[i + 1] ?? ""))) {
      const j = skipWhile(src, i, /[0-9a-fA-FxXoO_bBeE+\-.]/);
      toks.push({ kind: "num", text: src.slice(i, j) });
      i = j;
      continue;
    }
    toks.push({ kind: "punct", text: ch });
    i++;
  }
  return toks;
}

function skipWhile(src, i, re) {
  let j = i;
  while (j < src.length && re.test(src[j])) j++;
  return j;
}

function scanString(src, start, quote) {
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

function isRegexStart(toks) {
  const prev = lastNonWs(toks);
  if (!prev) return true;
  if (prev.kind === "ident" || prev.kind === "num" || prev.kind === "str" || prev.kind === "tmpl" || prev.kind === "regex") return false;
  if (/[)}\]"`]/.test(prev.text)) return false;
  return true;
}

function lastNonWs(toks) {
  for (let i = toks.length - 1; i >= 0; i--) {
    if (toks[i].kind !== "ws") return toks[i];
  }
  return null;
}

// ---------------------------------------------------------------------------
// emitter — rebuild formatted text from tokens
// ---------------------------------------------------------------------------

const PRE_GLUE = new Set([".", ";", ",", ")", "]", "}"]);
const POST_GLUE = new Set(["(", "[", "{"]);
const OPERATOR = /^[=+\-*/%<>&|^!?]+$/;
// no space before a word/operand after these characters
const NO_SPACE_BEFORE_WORD_AFTER = new Set([".", "(", "[", "{"]);
// bare control keywords get a space before "(" in normal style ("if (a)")
const CONTROL_KEYWORDS = new Set(["if", "for", "while", "switch", "catch", "with"]);

/**
 * Formats JS source.
 * @param {string} src
 * @returns {string}
 */
export function beautify(src) {
  if (typeof src !== "string" || src.trim() === "") return src ?? "";
  const toks = trimWs(tokenize(src));

  const out = [];
  let indent = 0;
  let line = ""; // pending text for the current line (no indentation prefix)
  const INDENT = "  ";

  const flushLine = () => {
    const trimmed = line.trim();
    if (trimmed !== "") out.push(INDENT.repeat(indent) + trimmed);
    line = "";
  };
  const indentStr = () => INDENT.repeat(indent);

  const nextSig = (i) => {
    for (let j = i + 1; j < toks.length; j++) if (toks[j].kind !== "ws") return toks[j];
    return null;
  };

  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];

    if (t.kind === "ws") {
      const nx = nextSig(i);
      if (nx && needsSpace(line, nx)) line += " ";
      continue;
    }

    if (t.kind === "comment") {
      if (t.text.startsWith("//")) {
        // end current line then emit comment on its own line
        const leading = line.trim();
        if (leading !== "") out.push(indentStr() + leading);
        line = "";
        // if the comment is the first thing after a `{`, indent by body depth
        out.push(indentStr() + t.text);
      } else {
        // block comment: keep on current line, space-separated
        line += (line && line[line.length - 1] !== " " ? " " : "") + t.text;
      }
      continue;
    }

    if (t.kind === "punct") {
      const p = t.text;

      if (p === ";") {
        line += ";";
        flushLine();
        continue;
      }
      if (p === "{") {
        if (line.trim() === "") {
          line = "{";
        } else {
          line = line.trimEnd() + " {";
        }
        if (nextSig(i)?.text === "}") {
          // empty block: "{}"
          line += "}";
          flushLine();
          continue;
        }
        flushLine();
        indent++;
        continue;
      }
      if (p === "}") {
        // flush any body content still pending on the line (e.g. object
        // literal entries) at the body's indent, then emit the closing brace
        if (line.trim() !== "") {
          const trimmed = line.trim();
          out.push(indentStr() + trimmed);
          line = "";
        } else {
          line = "";
        }
        indent = Math.max(0, indent - 1);
        out.push(indentStr() + "}");
        continue;
      }
      if (p === ",") {
        line += ",";
        continue;
      }
      if (p === ":") {
        line += ":";
        continue;
      }
      if (p === ".") {
        line = line.trimEnd();
        line += ".";
        continue;
      }
      if (p === "(") {
        // "if (a)", "for (;;)" — space after control keywords only
        if (endsWithKeyword(line)) line += " ";
        line += "(";
        continue;
      }
      if (OPERATOR.test(p)) {
        if (line !== "" && line[line.length - 1] !== " ") line += " ";
        line += p;
        continue;
      }
      // generic punctuation
      if (line === "") { line = p; }
      else if (PRE_GLUE.has(p)) { line += p; }
      else if (line[line.length - 1] === " ") { line += p; }
      else if (POST_GLUE.has(p)) { line += p; }
      else { line += " " + p; }
      continue;
    }

    // ident / num / str / tmpl / regex
    line += (needsSpace(line, t) ? " " : "") + t.text;
  }
  flushLine();

  // join trailing keywords onto their closing brace: "}else{" → "} else {"
  return out
    .join("\n")
    .replace(/\n(\s*)\}\s*else(\s*)\{/g, "\n$1} else {")
    .replace(/\n(\s*)\}\s*catch/g, "\n$1} catch")
    .replace(/\n(\s*)\}\s*while/g, "\n$1} while");
}

function needsSpace(line, tok) {
  if (line === "") return false;
  const last = line[line.length - 1];
  if (tok.kind === "punct") {
    if (PRE_GLUE.has(tok.text)) return false;
    return last !== " ";
  }
  // word/operand: keep spacing after "(", "[", "{", "." but add it after
  // spaces, operators, ":" and ",".
  if (last === " ") return false;
  if (NO_SPACE_BEFORE_WORD_AFTER.has(last)) return false;
  return true;
}

/** True when `line` ends with a bare control keyword (word boundary only). */
function endsWithKeyword(line) {
  const m = line.match(/([A-Za-z_$][A-Za-z0-9_$]*)$/);
  return m ? CONTROL_KEYWORDS.has(m[1]) : false;
}

function trimWs(toks) {
  while (toks.length && toks[0].kind === "ws") toks.shift();
  while (toks.length && toks[toks.length - 1].kind === "ws") toks.pop();
  return toks;
}
