// --- lib/policies.js ---
/**
 * JavaScript Policy Inspector — per-site enforcement modes.
 *
 * A mode maps to an appended Content-Security-Policy response header.
 * `observe` intentionally has no policy: scripts run untouched while the
 * observer content script records what loads.
 */

const MODES = Object.freeze({
  OBSERVE: "observe",
  FIRST_PARTY_ONLY: "firstPartyOnly",
  NO_SCRIPTS: "noScripts",
});

const MODE_VALUES = new Set(Object.values(MODES));

/**
 * CSP per mode. Omitting 'unsafe-inline' blocks inline <script> blocks and
 * javascript: URIs; omitting 'unsafe-eval' additionally blocks eval() /
 * new Function(); script-src-attr 'none' kills inline event handlers.
 *
 * firstPartyOnly ('self') also refuses every cross-origin script, which is
 * what makes "first-party only" enforceable without source inspection.
 */
const CSP_POLICIES = Object.freeze({
  [MODES.OBSERVE]: null,
  [MODES.FIRST_PARTY_ONLY]:
    "script-src 'self'; script-src-attr 'none'; object-src 'none'; base-uri 'none'",
  [MODES.NO_SCRIPTS]:
    "script-src 'none'; script-src-attr 'none'; object-src 'none'; base-uri 'none'",
});

/**
 * One-line human explanation per mode — surfaced in the popup so users can
 * see what a mode does without reading CSP syntax.
 */
const POLICY_SUMMARY = Object.freeze({
  [MODES.OBSERVE]: "All scripts allowed. Activity is being observed.",
  [MODES.FIRST_PARTY_ONLY]:
    "Same-origin scripts only. Inline JS, eval(), inline handlers and third-party scripts are blocked.",
  [MODES.NO_SCRIPTS]: "All page JavaScript is blocked.",
});

/** @param {unknown} value @returns {boolean} true for valid mode strings */
function isMode(value) {
  return typeof value === "string" && MODE_VALUES.has(value);
}

/** Default mode for hosts with no stored preference. */
const DEFAULT_MODE = MODES.OBSERVE;

const SHA256_RE = /^sha256-[A-Za-z0-9+/]+={0,2}$/;

/**
 * Composes the CSP for a mode plus optional per-site allowances.
 * Allowance items (strings) are routed by shape:
 * - "https://origin"            → script-src source
 * - "sha256-BASE64"             → script-src hash (allows one inline script)
 * - "attr-sha256-BASE64"        → script-src-attr hash (allows one handler)
 *
 * firstPartyOnly: `'self'` + origins + script hashes.
 * noScripts: origins + script hashes only (`'none'` while all lists are empty).
 * Attr hashes replace `script-src-attr 'none'`; without them handlers stay dead.
 *
 * @param {string} mode one of MODES
 * @param {{origins?: string[], scriptHashes?: string[], attrHashes?: string[]}} [allows]
 * @returns {string | null} policy value or null for observe
 */
function composePolicy(mode, allows = {}) {
  const base = CSP_POLICIES[mode];
  if (!base) return null;

  const origins = dedupe((allows.origins ?? []).map(normalizeOrigin).filter(Boolean));
  const scriptHashes = dedupe(
    (allows.scriptHashes ?? []).map(String).filter((h) => SHA256_RE.test(h)),
  );
  // tolerate the observer's "attr-" prefixed form
  const attrHashes = dedupe(
    (allows.attrHashes ?? [])
      .map((h) => String(h).replace(/^attr-/, ""))
      .filter((h) => SHA256_RE.test(h)),
  );

  if (origins.length === 0 && scriptHashes.length === 0 && attrHashes.length === 0) {
    return base;
  }
  const srcParts = [...origins, ...scriptHashes];
  const scriptSrc =
    mode === MODES.FIRST_PARTY_ONLY
      ? ["'self'", ...srcParts].join(" ")
      : srcParts.length > 0
        ? srcParts.join(" ")
        : "'none'";
  const attrDirective =
    attrHashes.length > 0 ? `script-src-attr ${attrHashes.join(" ")}` : "script-src-attr 'none'";
  return `script-src ${scriptSrc}; ${attrDirective}; object-src 'none'; base-uri 'none'`;
}

function dedupe(list) {
  return [...new Set(list)];
}

/** Validates that a string is a usable http(s) origin for exceptions.
 * @param {unknown} input
 * @returns {string | null}
 */
function normalizeOrigin(input) {
  let url;
  try {
    url = new URL(String(input));
  } catch {
    return null;
  }
  return /^https?:$/.test(url.protocol) ? url.origin : null;
}


// --- lib/rules.js ---
/**
 * declarativeNetRequest rule construction for per-site JavaScript policies.
 * Imported by both the service worker and the popup (ESM); must stay free of
 * chrome.* calls so it remains unit-testable under plain Node.
 */


/**
 * Rule-ID bands (rule IDs are int32, max 2^31 - 1).
 * Reserving disjoint ranges up front prevents collisions once v0.3 adds
 * tab-scoped override rules alongside the per-site policy rules.
 */
const RULE_BANDS = Object.freeze({
  /** Per-site CSP policy rules: 1 – 99,999,999 */
  SITE_POLICY: 1,
  /** Tab-scoped temporary overrides (v0.3): 100,000,000 – 199,999,999 */
  TAB_OVERRIDE: 100_000_000,
});

const SITE_POLICY_ID_SPAN = RULE_BANDS.TAB_OVERRIDE - RULE_BANDS.SITE_POLICY;

/**
 * Deterministic rule ID for a hostname (FNV-1a folded into the site-policy
 * band). Dynamic rules persist across browser restarts, so deriving IDs from
 * the hostname removes the need for bookkeeping storage.
 * @param {string} host e.g. "example.com"
 * @returns {number} stable positive rule id
 */
function ruleIdFor(host) {
  let h = 0x811c9dc5;
  for (let i = 0; i < host.length; i++) {
    h ^= host.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  const slot = (h >>> 1) % SITE_POLICY_ID_SPAN;
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
 * @param {string} host
 * @param {string} mode one of MODES (observe has no CSP and yields no rule)
 * @param {{origins?: string[], scriptHashes?: string[], attrHashes?: string[]}} [allows]
 * @returns {chrome.declarativeNetRequest.Rule}
 * @throws {Error} unknown mode or a mode without an enforceable policy
 */
function buildRule(host, mode, allows = {}) {
  if (!isMode(mode)) throw new Error(`unknown mode: ${mode}`);
  const value = composePolicy(mode, allows);
  if (!value) throw new Error(`mode "${mode}" has no enforceable CSP`);
  return {
    id: ruleIdFor(host),
    priority: 1,
    action: {
      type: "modifyHeaders",
      responseHeaders: [
        { header: "Content-Security-Policy", operation: "append", value },
      ],
    },
    condition: {
      requestDomains: [host],
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
function isPolicyRuleFor(rule, host) {
  return (
    rule.id === ruleIdFor(host) &&
    rule.action?.type === "modifyHeaders" &&
    rule.condition?.requestDomains?.[0] === host
  );
}


// --- service-worker.js ---


const SITE_MODES_KEY = "siteModes";
const EXCEPTIONS_KEY = "siteExceptions";
const INLINE_ALLOWS_KEY = "siteInlineAllows";
const PAUSED_KEY = "pausedUntil";
const BADGE_COLOR = "#b45309";
const MAX_EVENTS_PER_TAB = 200;
const MAX_NET_PER_TAB = 300;
const NET_FLUSH_MS = 400;
const PAUSE_MS = 10 * 60 * 1000;
const OVERRIDE_PRIORITY = 1000;

/** @param {number} tabId */
const eventsKey = (tabId) => `tabEvents:${tabId}`;
/** @param {number} tabId */
const statsKey = (tabId) => `tabStats:${tabId}`;
/** @param {number} tabId */
const netKey = (tabId) => `tabNet:${tabId}`;
/** Tab-scoped CSP-removal overrides live in the reserved band. */
const tabOverrideId = (tabId) => RULE_BANDS.TAB_OVERRIDE + tabId;

/**
 * @typedef {object} ObsEvent
 * @property {number} ts
 * @property {{url: string, isTop: boolean}} frame
 * @property {string} kind "script" | "inline-script" | "inline-handler" | "csp-violation"
 * @property {string | null} url
 * @property {string | null} origin
 * @property {"first"|"third"|"inline"|"unknown"} party
 * @property {"observed"|"blocked"} action
 * @property {string | null} reason
 */

// ---------------------------------------------------------------------------
// storage accessors
// ---------------------------------------------------------------------------

async function getStore(key) {
  const data = await chrome.storage.local.get(key);
  return data[key] ?? {};
}

const getSiteModes = () => getStore(SITE_MODES_KEY);
const getExceptions = () => getStore(EXCEPTIONS_KEY);
const getInlineAllows = () => getStore(INLINE_ALLOWS_KEY);
const getPaused = () => getStore(PAUSED_KEY);

// ---------------------------------------------------------------------------
// observer event ingestion (bounded per-tab logs in storage.session)
// ---------------------------------------------------------------------------

/**
 * Derives the popup counters from a tab's event buffer.
 * @param {ObsEvent[]} events
 */
function computeStats(events) {
  const stats = {
    scriptsFirstParty: 0,
    scriptsThirdParty: 0,
    inlineScripts: 0,
    inlineHandlers: 0,
    blocked: 0,
  };
  for (const e of events) {
    switch (e.kind) {
      case "script":
        if (e.party === "third") stats.scriptsThirdParty++;
        else if (e.party === "first") stats.scriptsFirstParty++;
        break;
      case "inline-script":
        stats.inlineScripts++;
        break;
      case "inline-handler":
        stats.inlineHandlers++;
        break;
      case "csp-violation":
        stats.blocked++;
        break;
    }
  }
  return stats;
}

/**
 * Appends events to the tab's bounded ring buffer in storage.session and
 * refreshes its derived counters. storage.session survives service-worker
 * restarts but is wiped when the browser closes — no history DB.
 * @param {number} tabId
 * @param {ObsEvent[]} incoming
 */
async function ingestEvents(tabId, incoming) {
  const key = eventsKey(tabId);
  const stored = await chrome.storage.session.get(key);
  const merged = (stored[key] ?? []).concat(incoming).slice(-MAX_EVENTS_PER_TAB);
  await chrome.storage.session.set({
    [key]: merged,
    [statsKey(tabId)]: computeStats(merged),
  });
}

// ---------------------------------------------------------------------------
// webRequest observation (network view; strictly read-only)
// ---------------------------------------------------------------------------

/**
 * @typedef {object} NetEvent
 * @property {number} ts
 * @property {"net"} kind
 * @property {string} method
 * @property {string} url
 * @property {string} type resource type (script, xhr, image, main_frame, …)
 * @property {string} status "" until settled, then HTTP code or error token
 */

/** Per-tab buffers awaiting a debounced write. */
const netPending = new Map();
const netTimers = new Map();

function scheduleNetFlush(tabId) {
  if (netTimers.has(tabId)) return;
  netTimers.set(
    tabId,
    setTimeout(() => {
      netTimers.delete(tabId);
      flushNet(tabId).catch(() => {});
    }, NET_FLUSH_MS),
  );
}

async function flushNetNow(tabId) {
  const timer = netTimers.get(tabId);
  if (timer !== undefined) {
    clearTimeout(timer);
    netTimers.delete(tabId);
  }
  await flushNet(tabId);
}

async function flushNet(tabId) {
  const buf = netPending.get(tabId);
  if (!buf || buf.entries.length === 0) return;
  // Detach first: requests arriving during the awaits below open a fresh
  // buffer and re-arm their own timer.
  netPending.delete(tabId);
  const key = netKey(tabId);
  try {
    const stored = await chrome.storage.session.get([key, statsKey(tabId)]);
    const merged = (stored[key] ?? [])
      .concat(buf.entries)
      .slice(-MAX_NET_PER_TAB);
    const stats = stored[statsKey(tabId)] ?? {};
    stats.netRequests = merged.length;
    await chrome.storage.session.set({
      [key]: merged,
      [statsKey(tabId)]: stats,
    });
  } catch {
    // session store unavailable — drop this batch rather than wedge the SW
  }
}

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0) return; // non-tab traffic (SW fetches, prerender)
    let buf = netPending.get(details.tabId);
    if (!buf) {
      buf = { entries: [], byReqId: new Map() };
      netPending.set(details.tabId, buf);
    }
    const entry = /** @type {NetEvent} */ ({
      ts: details.timeStamp,
      kind: "net",
      method: details.method,
      url: details.url,
      type: details.type,
      status: "",
    });
    buf.entries.push(entry);
    // redirects reuse the requestId; last onBeforeRequest wins
    buf.byReqId.set(details.requestId, entry);
    if (buf.entries.length > 25) void flushNetNow(details.tabId);
    else scheduleNetFlush(details.tabId);
  },
  { urls: ["<all_urls>"] },
);

function patchNet(details, patch) {
  if (details.tabId < 0) return;
  const entry = netPending.get(details.tabId)?.byReqId.get(details.requestId);
  if (entry) Object.assign(entry, patch); // already-flushed entries stay ""
}

chrome.webRequest.onCompleted.addListener(
  (details) => patchNet(details, { status: String(details.statusCode) }),
  { urls: ["<all_urls>"] },
);

chrome.webRequest.onErrorOccurred.addListener(
  (details) => patchNet(details, { status: details.error ?? "ERR" }),
  { urls: ["<all_urls>"] },
);

// ---------------------------------------------------------------------------
// DNR helpers (normalized across Chromium builds, e.g. Edge)
// ---------------------------------------------------------------------------

/** Some builds resolve rule queries directly to an array. */
function normalizeRuleList(result) {
  return Array.isArray(result) ? result : (result?.rules ?? []);
}

const getSessionRulesSafe = async () =>
  normalizeRuleList(await chrome.declarativeNetRequest.getSessionRules());

// ---------------------------------------------------------------------------
// policy reconciliation
// ---------------------------------------------------------------------------

/**
 * Reconciles dynamic DNR rules with stored modes + exceptions + pauses.
 * Strategy: wipe every rule in the site-policy band, then rebuild from
 * stored state — mode SWITCHES must take effect, so no diffing.
 *
 * Paused hosts are skipped until their pause expires; expired pauses are
 * pruned lazily here so a lost alarm can never wedge a host forever.
 */
async function syncRules() {
  try {
    const [modes, exceptions, inlineAllows, paused] = await Promise.all([
      getSiteModes(),
      getExceptions(),
      getInlineAllows(),
      getPaused(),
    ]);
    const now = Date.now();
    for (const [host, entry] of Object.entries(paused)) {
      if (entry?.until <= now && modes[host] === MODES.OBSERVE) {
        modes[host] = entry.mode ?? DEFAULT_MODE;
        delete paused[host];
      }
    }
    if (Object.keys(paused).length !== Object.values(paused).length) {
      // prune happened above only when resuming; persist restored modes
      await chrome.storage.local.set({ [SITE_MODES_KEY]: modes, [PAUSED_KEY]: paused });
    }
    const hosts = Object.keys(modes).filter(
      (h) => modes[h] !== MODES.OBSERVE,
    );
    const rules = normalizeRuleList(
      await chrome.declarativeNetRequest.getDynamicRules(),
    );
    const removeRuleIds = rules
      .filter(
        (r) =>
          r.id >= RULE_BANDS.SITE_POLICY && r.id < RULE_BANDS.TAB_OVERRIDE,
      )
      .map((r) => r.id);
    const addRules = hosts.map((h) =>
      buildRule(h, modes[h], {
        origins: exceptions[h] ?? [],
        scriptHashes: inlineAllows[h]?.scripts ?? [],
        attrHashes: inlineAllows[h]?.attrs ?? [],
      }),
    );
    if (removeRuleIds.length > 0 || addRules.length > 0) {
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds,
        addRules,
      });
    }
    await refreshBadge(hosts.length);
  } catch (err) {
    console.error("[policy-inspector] syncRules failed:", err);
  }
}

async function refreshBadge(enforcedCount) {
  await chrome.action.setBadgeBackgroundColor({ color: BADGE_COLOR });
  await chrome.action.setBadgeTextColor({ color: "#ffffff" });
  await chrome.action.setBadgeText({
    text: enforcedCount > 0 ? String(enforcedCount) : "",
  });
}

/** @param {string} host @param {string} mode */
async function setSiteMode(host, mode) {
  if (!isMode(mode)) throw new Error(`invalid mode: ${mode}`);
  const siteModes = await getSiteModes();
  siteModes[host] = mode;
  await chrome.storage.local.set({ [SITE_MODES_KEY]: siteModes });
  if (mode === MODES.OBSERVE) await resumeHost(host).catch(() => {});
  else await syncRules();
}

// ---------------------------------------------------------------------------
// temporary controls
// ---------------------------------------------------------------------------

/** Pauses enforcement for `host` for PAUSE_MS; resumes automatically. */
async function pauseHost(host) {
  const paused = await getPaused();
  paused[host] = Date.now() + PAUSE_MS;
  await chrome.storage.local.set({ [PAUSED_KEY]: paused });
  await chrome.alarms.create(`resume:${host}`, { when: paused[host] });
  await syncRules();
  return { until: paused[host] };
}

async function resumeHost(host) {
  const paused = await getPaused();
  if (host in paused) {
    delete paused[host];
    await chrome.storage.local.set({ [PAUSED_KEY]: paused });
  }
  await chrome.alarms.clear(`resume:${host}`);
  await syncRules();
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name?.startsWith("resume:")) resumeHost(alarm.name.slice(7));
});

/** Toggles a per-tab session rule that strips ALL CSP response headers. */
async function toggleTabOverride(tabId) {
  const id = tabOverrideId(tabId);
  const active = (await getSessionRulesSafe()).some((r) => r.id === id);
  if (active) {
    await chrome.declarativeNetRequest.updateSessionRules({
      removeRuleIds: [id],
    });
    return false;
  }
  await chrome.declarativeNetRequest.updateSessionRules({
    addRules: [
      {
        id,
        priority: OVERRIDE_PRIORITY,
        action: {
          type: "modifyHeaders",
          responseHeaders: [
            { header: "Content-Security-Policy", operation: "remove" },
          ],
        },
        condition: {
          tabIds: [tabId],
          resourceTypes: ["main_frame", "sub_frame"],
        },
      },
    ],
  });
  return true;
}

// ---------------------------------------------------------------------------
// exceptions (per-host allowed script origins)
// ---------------------------------------------------------------------------

async function addException(host, origin) {
  const normalized = normalizeOrigin(origin);
  if (!normalized) throw new Error("origin must be http(s), e.g. https://cdn.example.com");
  const all = await getExceptions();
  const list = new Set(all[host] ?? []);
  list.add(normalized);
  all[host] = [...list];
  await chrome.storage.local.set({ [EXCEPTIONS_KEY]: all });
  await syncRules();
  return all[host];
}

async function removeException(host, origin) {
  const all = await getExceptions();
  all[host] = (all[host] ?? []).filter((o) => o !== origin);
  await chrome.storage.local.set({ [EXCEPTIONS_KEY]: all });
  await syncRules();
  return all[host];
}

const ALLOWED_HASH_RE = /^sha256-[A-Za-z0-9+/]+={0,2}$/;

/**
 * Allows one inline script or handler by adding its CSP hash for a host.
 * @param {string} host
 * @param {"script"|"attr"} kind
 * @param {string} hash "sha256-…" (attr- prefix tolerated)
 */
async function addInlineAllow(host, kind, hash) {
  const clean = String(hash).replace(/^attr-/, "");
  if (!ALLOWED_HASH_RE.test(clean)) throw new Error("invalid sha256 token");
  const all = await getInlineAllows();
  const entry = all[host] ?? { scripts: [], attrs: [] };
  const list = kind === "attr" ? entry.attrs : entry.scripts;
  if (!list.includes(clean)) list.push(clean);
  all[host] = entry;
  await chrome.storage.local.set({ [INLINE_ALLOWS_KEY]: all });
  await syncRules();
  return entry;
}

// ---------------------------------------------------------------------------
// lifecycle
// ---------------------------------------------------------------------------

chrome.runtime.onInstalled.addListener(() => syncRules());
chrome.runtime.onStartup.addListener(() => syncRules());

chrome.tabs.onRemoved.addListener(async (tabId) => {
  await chrome.storage.session.remove([
    eventsKey(tabId),
    statsKey(tabId),
    netKey(tabId),
  ]);
  netPending.delete(tabId);
  const timer = netTimers.get(tabId);
  if (timer !== undefined) {
    clearTimeout(timer);
    netTimers.delete(tabId);
  }
  try {
    await chrome.declarativeNetRequest.updateSessionRules({
      removeRuleIds: [tabOverrideId(tabId)],
    });
  } catch {
    // session store already gone; nothing to clean
  }
});

/**
 * Message hub for the popup and observer content scripts.
 * - {type:"get-state", host, tabId?}   -> {mode, pausedUntil, tabOverride, exceptions}
 * - {type:"set-mode", host, mode}      -> {ok:true}
 * - {type:"obs-events", events}        -> {ok:true}  (tab from sender)
 * - {type:"get-activity", tabId}       -> {events, stats, netEvents}
 * - {type:"pause-host", host}          -> {until}
 * - {type:"resume-host", host}         -> {ok:true}
 * - {type:"toggle-tab-override", tabId}-> {active}
 * - {type:"add-exception", host, origin}    -> {exceptions}
 * - {type:"remove-exception", host, origin}-> {exceptions}
 * - {type:"export-settings"}           -> {siteModes, siteExceptions}
 * - {type:"import-settings", data}     -> {ok:true}
 */
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    switch (msg?.type) {
      case "get-state": {
        const [siteModes, exceptions, inlineAllows, paused] =
          await Promise.all([
            getSiteModes(),
            getExceptions(),
            getInlineAllows(),
            getPaused(),
          ]);
        const state = {
          mode: siteModes[msg.host] ?? DEFAULT_MODE,
          pausedUntil: msg.host in paused ? paused[msg.host] : null,
          exceptions: exceptions[msg.host] ?? [],
          inlineAllows: inlineAllows[msg.host] ?? { scripts: [], attrs: [] },
        };
        state.tabOverride =
          typeof msg.tabId === "number"
            ? (await getSessionRulesSafe()).some(
                (r) => r.id === tabOverrideId(msg.tabId),
              )
            : false;
        sendResponse(state);
        break;
      }
      case "set-mode": {
        await setSiteMode(msg.host, msg.mode);
        sendResponse({ ok: true });
        break;
      }
      case "obs-events": {
        const tabId = sender.tab?.id;
        if (typeof tabId === "number" && Array.isArray(msg.events)) {
          await ingestEvents(tabId, msg.events);
          sendResponse({ ok: true });
        } else {
          sendResponse({ error: "obs-events without tab/events" });
        }
        break;
      }
      case "get-activity": {
        const keys = [
          eventsKey(msg.tabId),
          statsKey(msg.tabId),
          netKey(msg.tabId),
        ];
        const stored = await chrome.storage.session.get(keys);
        sendResponse({
          events: stored[keys[0]] ?? [],
          stats: stored[keys[1]] ?? null,
          netEvents: stored[keys[2]] ?? [],
        });
        break;
      }
      case "pause-host":
        sendResponse(await pauseHost(msg.host));
        break;
      case "resume-host":
        await resumeHost(msg.host);
        sendResponse({ ok: true });
        break;
      case "toggle-tab-override": {
        if (typeof msg.tabId !== "number") {
          sendResponse({ error: "toggle-tab-override needs tabId" });
          break;
        }
        sendResponse({ active: await toggleTabOverride(msg.tabId) });
        break;
      }
      case "add-exception":
        sendResponse({ exceptions: await addException(msg.host, msg.origin) });
        break;
      case "remove-exception":
        sendResponse({
          exceptions: await removeException(msg.host, msg.origin),
        });
        break;
      case "add-inline-allow":
        sendResponse({
          inlineAllows: await addInlineAllow(msg.host, msg.kind, msg.hash),
        });
        break;
      case "export-settings": {
        const [siteModes, siteExceptions, siteInlineAllows] =
          await Promise.all([getSiteModes(), getExceptions(), getInlineAllows()]);
        sendResponse({ siteModes, siteExceptions, siteInlineAllows });
        break;
      }
      case "import-settings": {
        const data = msg.data ?? {};
        const siteModes = data.siteModes ?? {};
        const siteExceptions = data.siteExceptions ?? {};
        const siteInlineAllows = data.siteInlineAllows ?? {};
        for (const m of Object.values(siteModes)) {
          if (!isMode(m)) throw new Error(`invalid mode in import: ${m}`);
        }
        await chrome.storage.local.set({
          [SITE_MODES_KEY]: siteModes,
          [EXCEPTIONS_KEY]: siteExceptions,
          [INLINE_ALLOWS_KEY]: siteInlineAllows,
          [PAUSED_KEY]: {},
        });
        await syncRules();
        sendResponse({ ok: true });
        break;
      }
      default:
        sendResponse({ error: `unknown message type: ${String(msg?.type)}` });
    }
  })().catch((err) => sendResponse({ error: String(err) }));
  return true;
});

