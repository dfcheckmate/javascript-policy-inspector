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

  function push(event) {
    if (queue.length >= MAX_QUEUE) queue.shift();
    queue.push({ ts: Date.now(), frame: FRAME, ...event });
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

  function recordScript(el) {
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
      push({
        kind: "inline-script",
        url: null,
        origin: location.origin,
        party: "inline",
        action: "observed",
        reason: null,
      });
    }
  }

  function recordHandlers(el) {
    for (const attr of el.attributes) {
      if (/^on/i.test(attr.name)) {
        push({
          kind: "inline-handler",
          url: null,
          origin: location.origin,
          party: "inline",
          action: "observed",
          reason: null,
          handler: attr.name.toLowerCase(),
          target: el.tagName.toLowerCase(),
        });
      }
    }
  }

  /** Walk an inserted subtree; parser chunks can carry many nodes at once. */
  function processNode(node) {
    if (node.nodeType !== Node.ELEMENT_NODE) return;
    if (node.tagName === "SCRIPT") recordScript(node);
    if (node.attributes?.length) recordHandlers(node);
    for (const script of node.querySelectorAll?.("script") ?? []) {
      recordScript(script);
    }
    for (const el of node.querySelectorAll?.("*") ?? []) {
      if (el.attributes?.length) recordHandlers(el);
    }
  }

  new MutationObserver((muts) => {
    for (const m of muts) {
      for (const n of m.addedNodes) processNode(n);
    }
  }).observe(document.documentElement, { childList: true, subtree: true });

  // Ground truth for anything the active policy blocks (inline scripts,
  // inline handlers, eval()/new Function(), third-party scripts).
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
