/**
 * observer.js — page observation (isolated world), injected at
 * document_start into every http(s) frame.
 *
 * Reports, never enforces:
 * - <script> elements entering the DOM (first-party vs third-party vs inline)
 * - inline event handler attributes (on*)
 * - securitypolicyviolation events (ground truth for CSP blocks, incl. eval)
 *
 * Events are batched and forwarded to the service worker, which keeps the
 * bounded per-tab activity log. No chrome.storage access here.
 */

(() => {
  const FLUSH_INTERVAL_MS = 250;
  const MAX_QUEUE = 500;

  /** @type {object[]} */
  const queue = [];
  const FRAME = { url: location.href, isTop: window === window.top };
  // Tracks DOM nodes we've already cataloged. A WeakSet holds only weak
  // references, so observed nodes are garbage-collected as soon as the page
  // discards them (no leak in long-lived SPAs) while reparented nodes are
  // never re-hashed or double-counted.
  const processedNodes = new WeakSet();

  function push(event) {
    if (queue.length >= MAX_QUEUE) queue.shift();
    queue.push({ ts: Date.now(), frame: FRAME, ...event });
  }

  /**
   * SHA-256 of a payload, formatted as a CSP hash token. Returns null on
   * insecure contexts (crypto.subtle unavailable) or oversized payloads.
   * @param {string} text
   * @returns {Promise<string | null>} e.g. "sha256-AbCd…="
   */
  async function hashPayload(text) {
    try {
      if (!text || text.length > 100_000 || !crypto?.subtle) return null;
      const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(text),
      );
      let binary = "";
      for (const byte of new Uint8Array(digest)) {
        binary += String.fromCharCode(byte);
      }
      return `sha256-${btoa(binary)}`;
    } catch {
      return null;
    }
  }

  /** @returns {"first"|"third"|"unknown"} */
  function partyOf(url) {
    try {
      return new URL(url, location.href).origin === location.origin
        ? "first"
        : "third";
    } catch {
      return "unknown";
    }
  }

  async function recordScript(el) {
    if (processedNodes.has(el)) return;
    processedNodes.add(el);

    const src = el.getAttribute("src");
    if (src !== null && src !== "") {
      let abs;
      try {
        abs = new URL(src, location.href);
      } catch {
        push({ kind: "script", url: src, origin: null, party: "unknown", action: "observed", reason: null });
        return;
      }
      push({
        kind: "script",
        url: abs.href,
        origin: abs.origin,
        party: partyOf(abs.href),
        action: "observed",
        reason: null,
      });
    } else {
      // Hash the RAW textContent — browsers compute the CSP hash over the
      // exact text (including leading/trailing whitespace and indentation),
      // so trimming here would yield a token that never matches. Only the
      // displayed snippet is collapsed for readability.
      const raw = el.textContent ?? "";
      const hash = await hashPayload(raw);
      push({
        kind: "inline-script",
        url: null,
        origin: location.origin,
        party: "inline",
        action: "observed",
        reason: null,
        hash,
        raw: raw.slice(0, 8000),
        snippet: raw.replace(/\s+/g, " ").trim().slice(0, 200),
      });
    }
  }

  function recordHandlers(el) {
    if (processedNodes.has(el)) return;
    let found = false;
    for (const attr of el.attributes) {
      if (/^on/i.test(attr.name)) {
        found = true;
        // Hash is computed async; queue a placeholder then enrich it.
        enrichHandler(attr, el).catch(() => {});
      }
    }
    if (found) processedNodes.add(el);
  }

  async function enrichHandler(attr, el) {
    const value = attr.value ?? "";
    // Hash the RAW attribute value for the same reason as inline scripts.
    const hash = await hashPayload(value);
    push({
      kind: "inline-handler",
      url: null,
      origin: location.origin,
      party: "inline",
      action: "observed",
      reason: null,
      handler: attr.name.toLowerCase(),
      target: el.tagName.toLowerCase(),
      hash: hash ? `attr-${hash}` : null,
      raw: value.slice(0, 4000),
      snippet: `${attr.name.toLowerCase()}="${value.slice(0, 60)}"`,
    });
  }

  /** Walk an inserted subtree; parser chunks can carry many nodes at once. */
  function processNode(node) {
    if (node.nodeType !== Node.ELEMENT_NODE) return;
    if (node.tagName === "SCRIPT") recordScript(node);
    // Fast path: native getElementsByTagName collection (much faster than a
    // selector sweep in Gecko) without materializing a NodeList.
    for (const script of node.getElementsByTagName?.("script") ?? []) {
      recordScript(script);
    }
    // Handler sweep: visit only element nodes via a TreeWalker. Avoids the
    // quadratic attribute check over every descendant of a large subtree.
    if (node.childElementCount > 0 || node.attributes?.length) {
      recordHandlers(node);
      const walker = document.createTreeWalker(node, NodeFilter.SHOW_ELEMENT);
      let curr = walker.nextNode();
      while (curr) {
        recordHandlers(curr);
        curr = walker.nextNode();
      }
    }
  }

  const root =
    document.documentElement ?? document;
  new MutationObserver((muts) => {
    for (const m of muts) {
      for (const n of m.addedNodes) processNode(n);
    }
  }).observe(root, { childList: true, subtree: true });

  // One-time catch-up sweep when the document settles. A MutationObserver
  // attached at document_start can miss parser chunks flushed before it armed;
  // this final pass re-walks the whole tree. The WeakSet guarantees nothing is
  // re-hashed or double-counted.
  if (document.readyState === "loading") {
    window.addEventListener(
      "DOMContentLoaded",
      () => processNode(document.documentElement),
      { once: true },
    );
  } else {
    processNode(document.documentElement);
  }

  // Ground truth for anything the active policy blocks (inline scripts,
  // inline handlers, eval()/new Function(), third-party scripts).
  // Coverage caveat: eval() fires securitypolicyviolation only in
  // Chrome 111+ / Firefox 118+; older Chrome and Safari block eval()
  // silently without an event. The popup Activity therefore can't claim
  // complete eval() coverage on those engines — a browser limitation,
  // not fixable from a content script.
  window.addEventListener("securitypolicyviolation", (e) => {
    push({
      kind: "csp-violation",
      url: e.blockedURL || e.sourceFile || null,
      origin: (() => {
        try {
          return new URL(e.blockedURL ?? e.sourceFile ?? "about:blank").origin;
        } catch {
          return null;
        }
      })(),
      party: e.blockedURL ? partyOf(e.blockedURL) : "inline",
      action: "blocked",
      reason: `CSP ${e.violatedDirective}${e.sample ? ` sample="${e.sample.slice(0, 80)}"` : ""}`,
      directive: e.violatedDirective,
      sourceFile: e.sourceFile ?? null,
    });
  });

  function flush() {
    if (queue.length === 0) return;
    const events = queue.splice(0, queue.length);
    chrome.runtime.sendMessage({ type: "obs-events", events }).catch(() => {
      // Extension reloading or SW unreachable; drop the batch silently.
    });
  }

  setInterval(flush, FLUSH_INTERVAL_MS);
  window.addEventListener("pagehide", flush);
})();
