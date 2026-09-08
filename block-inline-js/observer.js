/**
 * observer.js — page observation (isolated world), injected at document_start
 * into every http(s) frame.
 *
 * Reports, never enforces CSP (the declarativeNetRequest layer is the sole
 * execution-policy authority):
 * - <script> elements entering the DOM, classified via lib/classify.js:
 *   external / inline JavaScript vs non-executing data blocks (JSON-LD,
 *   JSON data, import maps, speculation rules, unknown containers)
 * - inline event handler attributes (on*) and javascript: href/src URLs
 * - securitypolicyviolation events (ground truth for CSP blocks, incl. eval)
 *
 * The DOM layer additionally REMOVES non-executing containers when the
 * host's stored flag bundle asks for it (blockJsonLd / blockJsonData /
 * blockImportMaps / blockSpeculationRules) and the payload isn't user-
 * allowed. Parser-inserted executable scripts run before any observer can
 * act, so enforcement for those stays with CSP; container removal is safe
 * only because data blocks never execute. Removed containers are recorded
 * with hash + metadata + a short snippet only.
 *
 * README on flags: the effective bundle is resolved from chrome.storage
 * (sitePolicies + one-way legacy siteModes migration), mirroring the service
 * worker's resolver so a paused/overridden tab only differs at the DNR layer.
 * Until the bundle resolves, removals are deferred to the catch-up sweep —
 * the default profile (DEFAULT_POLICY = observe) removes nothing.
 */

import { getScriptCategory, isExecutable, isInlineHandlerName, isJavaScriptUrl, CATEGORIES } from "./lib/classify.js";
import { normalizeHostForRule } from "./lib/host.js";
import { DEFAULT_POLICY, isFlags, migrateLegacyModes, REMOVAL_FLAG_BY_CATEGORY } from "./lib/flags.js";

(() => {
  const FLUSH_INTERVAL_MS = 250;
  const MAX_QUEUE = 500;
  const MAX_CODE_RAW = 8000;
  const MAX_SNIPPET = 200;

  /** @type {object[]} */
  const queue = [];
  const FRAME = { url: location.href, isTop: window === window.top };
  // WeakSet holds weak references, so cataloged nodes are GC-able the moment
  // the page discards them (no leak in long-lived SPAs) while reparented
  // nodes are never re-hashed or double-counted.
  const processedNodes = new WeakSet();
  // Non-executing containers whose removal decision waits on the policy
  // bundle. Elements map onto their category via a WeakMap (no property
  // pollution on live DOM nodes).
  const pendingContainers = new Set();
  const containerCategory = new WeakMap();

  /** Effective flags once resolved; null until the storage read completes. */
  let activeFlags = null;
  /** Hex digests of containers explicitly exempted from removal on this site. */
  let allowedDigests = new Set();

  function push(event) {
    if (queue.length >= MAX_QUEUE) queue.shift();
    queue.push({ ts: Date.now(), frame: FRAME, ...event });
  }

  /**
   * SHA-256 of a payload as BOTH a CSP hash token (base64) and a lowercase
   * hex digest, computed from the same bytes — the hex form keys the
   * container allowlist, the token form matches CSP hash allowances.
   * Returns null on insecure contexts (crypto.subtle unavailable) or
   * oversized payloads.
   * @param {string} text
   * @returns {Promise<{hash: string, digest: string} | null>}
   */
  async function fingerprint(text) {
    try {
      if (!text || text.length > 100_000 || !crypto?.subtle) return null;
      const bytes = new Uint8Array(
        await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(text),
        ),
      );
      let binary = "";
      let hex = "";
      for (const byte of bytes) {
        binary += String.fromCharCode(byte);
        hex += byte.toString(16).padStart(2, "0");
      }
      return { hash: `sha256-${btoa(binary)}`, digest: hex };
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

  function originOf(src) {
    try {
      return new URL(src, location.href).origin;
    } catch {
      return null;
    }
  }

  /** Collapsed ≤200-char payload for a container: src if external, else text. */
  function snippetOf(el) {
    const src = el.getAttribute("src");
    if (src !== null && src !== "") return src.slice(0, MAX_SNIPPET);
    return (el.textContent ?? "").replace(/\s+/g, " ").trim().slice(0, MAX_SNIPPET);
  }

  function pushObservedContainer(el, category, fp, reason) {
    const src = el.getAttribute("src");
    push({
      kind: "script-element",
      category,
      executable: false,
      action: "observed",
      reason:
        reason ??
        (REMOVAL_FLAG_BY_CATEGORY[category]
          ? `kept (${REMOVAL_FLAG_BY_CATEGORY[category]} not set)`
          : "not a removable category"),
      url: src !== null && src !== "" ? src : null,
      origin: src !== null && src !== "" ? originOf(src) : location.origin,
      party: src !== null && src !== "" ? partyOf(src) : "inline",
      hash: fp?.hash ?? null,
      digest: fp?.digest ?? null,
      snippet: snippetOf(el),
    });
  }

  /**
   * Decides a container's fate: remove per the gated flag unless the digest
   * is user-allowed; otherwise record it as observed. Deferred until flags
   * resolve (the catch-up sweep then settles anything flushed before then).
   */
  async function decideContainer(el, category) {
    if (activeFlags === null) {
      pendingContainers.add(el);
      containerCategory.set(el, category);
      return;
    }
    const flag = REMOVAL_FLAG_BY_CATEGORY[category];
    if (!flag) {
      pushObservedContainer(el, category, null);
      return;
    }
    if (!activeFlags[flag]) {
      pushObservedContainer(el, category, null);
      return;
    }
    const src = el.getAttribute("src");
    const payload = src !== null && src !== "" ? src : (el.textContent ?? "");
    const fp = await fingerprint(payload);
    if (fp && allowedDigests.has(fp.digest)) {
      pushObservedContainer(el, category, fp, "kept (user-allowed container)");
      return;
    }
    push({
      kind: "script-element",
      category,
      executable: false,
      action: "removed",
      reason: `container removed (${flag}), non-executing data block`,
      url: src !== null && src !== "" ? src : null,
      origin: src !== null && src !== "" ? originOf(src) : location.origin,
      party: src !== null && src !== "" ? partyOf(src) : "inline",
      hash: fp?.hash ?? null,
      digest: fp?.digest ?? null,
      snippet: snippetOf(el),
    });
    el.remove();
  }

  /** Release removal decisions that were waiting on the policy bundle. */
  function flushPendingContainers() {
    if (activeFlags === null) return;
    for (const el of pendingContainers) {
      const category = containerCategory.get(el);
      if (category) decideContainer(el, category).catch(() => {});
    }
    pendingContainers.clear();
  }

  async function recordScript(el) {
    if (processedNodes.has(el)) return;
    processedNodes.add(el);

    const src = el.getAttribute("src");
    const category = getScriptCategory({
      src,
      type: el.getAttribute("type"),
    });

    if (isExecutable(category)) {
      if (src !== null && src !== "") {
        let abs;
        try {
          abs = new URL(src, location.href);
        } catch {
          push({
            kind: "script",
            category,
            executable: true,
            url: src,
            origin: null,
            party: "unknown",
            action: "observed",
            reason: null,
          });
          return;
        }
        push({
          kind: "script",
          category,
          executable: true,
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
        const fp = await fingerprint(raw);
        push({
          kind: "inline-script",
          category,
          executable: true,
          url: null,
          origin: location.origin,
          party: "inline",
          action: "observed",
          reason: null,
          hash: fp?.hash ?? null,
          digest: fp?.digest ?? null,
          raw: raw.slice(0, MAX_CODE_RAW),
          snippet: raw.replace(/\s+/g, " ").trim().slice(0, MAX_SNIPPET),
        });
      }
      return;
    }

    decideContainer(el, category).catch(() => {});
  }

  const ATTRIBUTE_SWEEP_KEYS = new Set(["href", "src"]);

  async function enrichHandler(attr, el) {
    const value = attr.value ?? "";
    // Hash the RAW attribute value for the same reason as inline scripts.
    const fp = await fingerprint(value);
    push({
      kind: "inline-handler",
      category: CATEGORIES.INLINE_JAVASCRIPT,
      executable: true,
      url: null,
      origin: location.origin,
      party: "inline",
      action: "observed",
      reason: null,
      handler: attr.name.toLowerCase(),
      target: el.tagName.toLowerCase(),
      hash: fp ? `attr-${fp.hash}` : null,
      digest: fp?.digest ?? null,
      raw: value.slice(0, MAX_CODE_RAW),
      snippet: `${attr.name.toLowerCase()}="${value.slice(0, 60)}"`,
    });
  }

  /** on* handler + javascript: href/src sweep over a single element's attrs. */
  function recordAttributes(el) {
    if (processedNodes.has(el)) return;
    let found = false;
    for (const attr of el.attributes) {
      const name = attr.name;
      if (isInlineHandlerName(name)) {
        found = true;
        // Hash is computed async; queue a placeholder then enrich it.
        enrichHandler(attr, el).catch(() => {});
      } else if (
        (name === "href" || name === "src") &&
        isJavaScriptUrl(attr.value)
      ) {
        found = true;
        const value = attr.value;
        push({
          kind: "javascript-url",
          category: CATEGORIES.JAVASCRIPT_URL,
          executable: true,
          url: value,
          origin: location.origin,
          party: "inline",
          action: "observed",
          reason: null,
          attr: name,
          target: el.tagName.toLowerCase(),
          snippet: value.replace(/\s+/g, " ").trim().slice(0, MAX_SNIPPET),
        });
      }
    }
    if (found) processedNodes.add(el);
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
    // Attribute sweep: visit only element nodes via a TreeWalker. Avoids the
    // quadratic attribute check over every descendant of a large subtree.
    if (node.childElementCount > 0 || node.attributes?.length) {
      recordAttributes(node);
      const walker = document.createTreeWalker(node, NodeFilter.SHOW_ELEMENT);
      let curr = walker.nextNode();
      while (curr) {
        recordAttributes(curr);
        curr = walker.nextNode();
      }
    }
  }

  // Resolve the effective flag bundle + container allowlist for this frame.
  // Mirrors the SW resolver (storage is the canonical store); the one-way
  // legacy-siteModes migration is idempotent in both writers.
  async function loadPolicy() {
    try {
      const store = await chrome.storage.local.get([
        "sitePolicies",
        "siteModes",
        "siteContainerAllows",
      ]);
      const { policies, changed } = migrateLegacyModes(
        store.sitePolicies ?? {},
        store.siteModes ?? {},
      );
      if (changed) {
        chrome.storage.local.set({ sitePolicies: policies }).catch(() => {});
      }
      try {
        const key = normalizeHostForRule(location.hostname);
        activeFlags = isFlags(policies[key]) ? policies[key] : DEFAULT_POLICY;
        const allows = store.siteContainerAllows?.[key];
        allowedDigests = new Set(Array.isArray(allows) ? allows : []);
      } catch {
        activeFlags = DEFAULT_POLICY;
      }
    } catch {
      activeFlags = DEFAULT_POLICY;
    }
    flushPendingContainers();
  }
  loadPolicy();

  const root = document.documentElement ?? document;
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