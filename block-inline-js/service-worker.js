import {
  DEFAULT_MODE,
  MODES,
  isMode,
  normalizeOrigin,
} from "./lib/policies.js";
import {
  RULE_BANDS,
  buildRule,
  normalizeHostForRule,
  ruleIdFor,
} from "./lib/rules.js";

const SITE_MODES_KEY = "siteModes";
const EXCEPTIONS_KEY = "siteExceptions";
const INLINE_ALLOWS_KEY = "siteInlineAllows";
const PAUSED_KEY = "pausedUntil";
const OVERRIDES_KEY = "tabOverrides";
const BADGE_COLOR = "#b45309";
const MAX_EVENTS_PER_TAB = 200;
const MAX_NET_PER_TAB = 300;
const NET_FLUSH_MS = 400;
const PAUSE_MS = 10 * 60 * 1000;

/** @param {number} tabId */
const eventsKey = (tabId) => `tabEvents:${tabId}`;
/** @param {number} tabId */
const statsKey = (tabId) => `tabStats:${tabId}`;
/** @param {number} tabId */
const netKey = (tabId) => `tabNet:${tabId}`;

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

/** Host storage keys are always stored in canonical (eTLD+1) form. */
const canon = (host) => normalizeHostForRule(host);

// ---------------------------------------------------------------------------
// rule-ID allocation (deterministic, collision-free)
// ---------------------------------------------------------------------------

/**
 * Computes the list of enforced hosts (stored mode != OBSERVE), normalised and
 * de-duplicated, then sorts them so linear-probe ID allocation is identical
 * across every restart and sync — no allocation table needs to be persisted.
 * @returns {{host: string, mode: string}[]} sorted, de-duplicated
 */
function computeEffectiveHosts(modes) {
  const byHost = new Map();
  for (const raw of Object.keys(modes)) {
    const h = normalizeHostForRule(raw);
    if (h && modes[normalizeHostForRule(h)] !== MODES.OBSERVE && !byHost.has(h)) {
      byHost.set(h, modes[h]);
    }
  }
  return [...byHost.entries()]
    .map(([host, mode]) => ({ host, mode }))
    .sort((a, b) => (a.host < b.host ? -1 : a.host > b.host ? 1 : 0));
}

/**
 * Assigns collision-free rule IDs to the given (already sorted) hosts by
 * linear probing inside the site-policy band.
 * @param {{host: string}[]} effectiveHosts sorted hosts
 * @returns {Map<string, number>} host → assigned rule id
 */
function allocatedRuleIds(effectiveHosts) {
  const used = new Set();
  const ids = new Map();
  for (const { host } of effectiveHosts) {
    let id = ruleIdFor(host);
    while (used.has(id)) {
      id++;
      if (id >= RULE_BANDS.TAB_OVERRIDE) id = RULE_BANDS.SITE_POLICY;
    }
    used.add(id);
    ids.set(host, id);
  }
  return ids;
}

// ---------------------------------------------------------------------------
// tab overrides (safe: exempt our rule for a tab, preserve the site's CSP)
// ---------------------------------------------------------------------------

/**
 * Overridden tab IDs are persisted in storage.session so they survive event-page
 * suspension, but are wiped when the browser session ends. Returns a Set.
 */
async function getOverrideTabs() {
  const data = await chrome.storage.session.get(OVERRIDES_KEY);
  return new Set(data[OVERRIDES_KEY] ?? []);
}

async function setOverrideTabs(ids) {
  await chrome.storage.session.set({ [OVERRIDES_KEY]: [...ids] });
}

/** True when `tabId` is currently excluded from our injected policies. */
async function isTabOverridden(tabId) {
  const ids = await getOverrideTabs();
  return ids.has(tabId);
}

/**
 * Resolves the enforcement context of `tabId`'s current page, if any.
 * Returns null when the tab has no URL, is not http(s), or its host is in
 * Observe mode (no policy rule to exclude). Otherwise returns the host, its
 * assigned rule id, and its stored allowances so a single rule can be patched.
 * @returns {Promise<{host: string, id: number, mode: string, allows: object} | null>}
 */
async function hostResolverForTab(tabId) {
  let tab;
  try {
    tab = await chrome.tabs.get(tabId);
  } catch {
    return null;
  }
  let host;
  try {
    host = normalizeHostForRule(new URL(tab.url ?? "").hostname);
  } catch {
    return null;
  }
  if (!host) return null;
  const [modes, exceptions, inlineAllows] = await Promise.all([
    getSiteModes(),
    getExceptions(),
    getInlineAllows(),
  ]);
  const hostKey = canon(host);
  if (!isMode(modes[hostKey]) || modes[hostKey] === MODES.OBSERVE) return null;
  const effective = computeEffectiveHosts({ ...modes, [hostKey]: modes[hostKey] });
  const id = allocatedRuleIds(effective).get(hostKey);
  if (id === undefined) return null;
  return {
    host: hostKey,
    id,
    mode: modes[hostKey],
    allows: {
      origins: exceptions[hostKey] ?? [],
      scriptHashes: inlineAllows[hostKey]?.scripts ?? [],
      attrHashes: inlineAllows[hostKey]?.attrs ?? [],
    },
  };
}

/**
 * Targeted patch: rebuild only the given host's dynamic rule with the current
 * override registry as excludedTabIds. Called on toggle and on tab close so a
 * single rule changes instead of a full-database reconciliation.
 */
async function patchHostOverrides(resolver, excludedTabIds) {
  const rule = buildRule(
    resolver.host,
    resolver.mode,
    resolver.allows,
    resolver.id,
    excludedTabIds,
  );
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [resolver.id],
    addRules: [rule],
  });
}

/**
 * Removes `tabId` from the override registry, then patches the tab's host rule
 * with the reduced (remaining) override set so its excludedTabIds is not stale.
 */
async function clearTabOverride(tabId) {
  const ids = await getOverrideTabs();
  if (!ids.has(tabId)) return;
  ids.delete(tabId);
  await setOverrideTabs(ids);
  const resolver = await hostResolverForTab(tabId);
  if (resolver) {
    await patchHostOverrides(resolver, [...ids]);
  }
}

/**
 * Toggles the per-tab override. Returns the new active state.
 *
 * Implementation: instead of stripping CSP headers with a high-priority
 * "remove" session rule (which also destroys the site's OWN anti-XSS policy),
 * we exempt the tab via condition.excludedTabIds on our dynamic policy rule.
 * The website's native CSP stays fully intact (least privilege), and only the
 * affected host's rule is patched.
 */
async function toggleTabOverride(tabId) {
  const ids = await getOverrideTabs();
  const isActive = ids.has(tabId);
  if (isActive) ids.delete(tabId);
  else ids.add(tabId);
  await setOverrideTabs(ids);

  const resolver = await hostResolverForTab(tabId);
  if (resolver) {
    await patchHostOverrides(resolver, [...ids]);
  }
  // Host in Observe/non-http → no policy rule to exempt; the registry entry
  // still records the user intent and will apply if the host is later enforced.
  return !isActive;
}

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
  await refreshBadge();
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
    const effectiveHosts = computeEffectiveHosts(modes);
    const excludedTabIds = [...(await getOverrideTabs())];
    const ids = allocatedRuleIds(effectiveHosts);
    const rules = normalizeRuleList(
      await chrome.declarativeNetRequest.getDynamicRules(),
    );
    const removeRuleIds = rules
      .filter(
        (r) =>
          r.id >= RULE_BANDS.SITE_POLICY && r.id < RULE_BANDS.TAB_OVERRIDE,
      )
      .map((r) => r.id);
    // Collision-free: hosts are sorted, then each gets a unique slot via
    // linear probing inside the site-policy band (see allocatedRuleIds). No
    // host is ever dropped, so enforcement never silently fails.
    const addRules = effectiveHosts.map(({ host }) =>
      buildRule(
        host,
        modes[host],
        {
          origins: exceptions[host] ?? [],
          scriptHashes: inlineAllows[host]?.scripts ?? [],
          attrHashes: inlineAllows[host]?.attrs ?? [],
        },
        ids.get(host),
        excludedTabIds,
      ),
    );
    if (removeRuleIds.length > 0 || addRules.length > 0) {
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds,
        addRules,
      });
    }
    await refreshBadge();
  } catch (err) {
    console.error("[policy-inspector] syncRules failed:", err);
  }
}

/** Set the toolbar badge text + colour; empty text clears the badge. */
async function setBadge(text, color) {
  await chrome.action.setBadgeBackgroundColor({ color });
  await chrome.action.setBadgeTextColor({ color: "#ffffff" });
  await chrome.action.setBadgeText({ text });
}

/**
 * Contextual toolbar badge for the ACTIVE tab:
 *  - override/paused host  → amber, so an unprotected site is never forgotten
 *  - enforced (firstParty/noScripts) → red with the blocked count when the
 *    policy actually stopped something, else empty
 *  - observe / non-http    → empty (neutral)
 * This replaces the old "global enforced host count"; the per-tab blocked count
 * (stats.blocked) is the signal the user actually needs at a glance.
 */
async function refreshBadge() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || typeof tab.id !== "number") return;
    const tabId = tab.id;

    const host = hostForUrl(tab.url);
    if (!host) {
      await setBadge("", BADGE_COLOR);
      return;
    }
    const [modes, paused, overrides] = await Promise.all([
      getSiteModes(),
      getPaused(),
      getOverrideTabs(),
    ]);
    const key = canon(host);
    const mode = modes[key] ?? DEFAULT_MODE;
    const isPaused = paused[key] != null;
    const isOverride = overrides.has(tabId);

    const data = await chrome.storage.session.get(statsKey(tabId));
    const blocked = computeStats(data[statsKey(tabId)] ?? []).blocked;

    if (isPaused || isOverride) {
      // Amber when the site is unprotected so the user isn't misled into
      // thinking hardening is on. "\u22C5" is a middle dot (non-emoji).
      await setBadge(blocked > 0 ? String(blocked) : "\u22C5", "#b45309");
      return;
    }
    if (mode === MODES.OBSERVE) {
      await setBadge("", BADGE_COLOR);
      return;
    }
    if (blocked > 0) {
      await setBadge(String(blocked), "#b91c1c");
    } else {
      await setBadge("", BADGE_COLOR);
    }
  } catch {
    // tab/store teardown races are harmless
  }
}

/** @param {string | undefined} url @returns {string | null} */
function hostForUrl(url) {
  if (!url) return null;
  let host;
  try {
    host = normalizeHostForRule(new URL(url).hostname);
  } catch {
    return null;
  }
  return host || null;
}

// Keep the contextual badge in sync with tab changes and policy state.
chrome.tabs.onActivated.addListener(() => refreshBadge());
chrome.tabs.onUpdated.addListener((_tabId, changeInfo) => {
  if (changeInfo.status === "loading" || changeInfo.url !== undefined) refreshBadge();
});

/** @param {string} host @param {string} mode */
async function setSiteMode(host, mode) {
  if (!isMode(mode)) throw new Error(`invalid mode: ${mode}`);
  const siteModes = await getSiteModes();
  const key = canon(host);
  siteModes[key] = mode;
  await chrome.storage.local.set({ [SITE_MODES_KEY]: siteModes });
  if (mode === MODES.OBSERVE) await resumeHost(host).catch(() => {});
  else await syncRules();
}

// ---------------------------------------------------------------------------
// temporary controls
// ---------------------------------------------------------------------------

/** Pauses enforcement for `host` for `ms`; resumes automatically. */
async function pauseHost(host, ms) {
  const paused = await getPaused();
  const key = canon(host);
  const until = Date.now() + ms;
  paused[key] = until;
  await chrome.storage.local.set({ [PAUSED_KEY]: paused });
  await chrome.alarms.create(`resume:${key}`, { when: until });
  await syncRules();
  return { until };
}

async function resumeHost(host) {
  const paused = await getPaused();
  const key = canon(host);
  if (key in paused) {
    delete paused[key];
    await chrome.storage.local.set({ [PAUSED_KEY]: paused });
  }
  await chrome.alarms.clear(`resume:${key}`);
  await syncRules();
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name?.startsWith("resume:")) resumeHost(alarm.name.slice(7));
});

// ---------------------------------------------------------------------------
// exceptions (per-host allowed script origins)
// ---------------------------------------------------------------------------

async function addException(host, origin) {
  const normalized = normalizeOrigin(origin);
  if (!normalized) throw new Error("origin must be http(s), e.g. https://cdn.example.com");
  const all = await getExceptions();
  const key = canon(host);
  const list = new Set(all[key] ?? []);
  list.add(normalized);
  all[key] = [...list];
  await chrome.storage.local.set({ [EXCEPTIONS_KEY]: all });
  await syncRules();
  return all[key];
}

async function removeException(host, origin) {
  const all = await getExceptions();
  const key = canon(host);
  all[key] = (all[key] ?? []).filter((o) => o !== origin);
  await chrome.storage.local.set({ [EXCEPTIONS_KEY]: all });
  await syncRules();
  return all[key];
}

const ALLOWED_HASH_RE = /^sha256-[A-Za-z0-9+/]{40,}={0,2}$/;

/**
 * Allows one inline script or handler by adding its CSP hash for a host.
 * @param {string} host
 * @param {"script"|"attr"} kind
 * @param {string} hash "sha256-…" (attr- prefix tolerated)
 */
async function addInlineAllow(host, kind, hash) {
  const clean = String(hash).replace(/^attr-/, "");
  if (!ALLOWED_HASH_RE.test(clean)) {
    // A truncated/absent hash token can never match a script; reject it
    // up front so the popup shows a real error instead of a dead Allow.
    throw new Error("invalid sha256 token (expected sha256- followed by 44 base64 chars)");
  }
  const all = await getInlineAllows();
  const key = canon(host);
  const entry = all[key] ?? { scripts: [], attrs: [] };
  const list = kind === "attr" ? entry.attrs : entry.scripts;
  if (!list.includes(clean)) list.push(clean);
  all[key] = entry;
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
  await clearTabOverride(tabId);
});

/**
 * Cross-site navigation reset. When a tab navigates to a new site (top-level
 * frameId 0), flush the old site's ledger and any temporary override so the
 * inspector never shows phantom scripts from a previously visited origin.
 */
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const { tabId } = details;
  netPending.delete(tabId);
  const timer = netTimers.get(tabId);
  if (timer !== undefined) {
    clearTimeout(timer);
    netTimers.delete(tabId);
  }
  await chrome.storage.session.remove([
    eventsKey(tabId),
    statsKey(tabId),
    netKey(tabId),
  ]);
  await clearTabOverride(tabId);
  await refreshBadge();
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
        const key = canon(msg.host);
        const state = {
          host: key,
          mode: siteModes[key] ?? DEFAULT_MODE,
          pausedUntil: key in paused ? paused[key] : null,
          exceptions: exceptions[key] ?? [],
          inlineAllows: inlineAllows[key] ?? { scripts: [], attrs: [] },
        };
        state.tabOverride =
          typeof msg.tabId === "number" && (await isTabOverridden(msg.tabId));
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
      case "pause-host": {
        const ms =
          typeof msg.ms === "number" && Number.isFinite(msg.ms) && msg.ms > 0
            ? msg.ms
            : PAUSE_MS;
        sendResponse(await pauseHost(msg.host, ms));
        break;
      }
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
        for (const v of Object.values(data.siteModes ?? {})) {
          if (!isMode(v)) throw new Error(`invalid mode in import: ${v}`);
        }
        const rekey = (obj) => {
          const out = {};
          for (const [k, v] of Object.entries(obj ?? {})) out[canon(k)] = v;
          return out;
        };
        await chrome.storage.local.set({
          [SITE_MODES_KEY]: rekey(data.siteModes),
          [EXCEPTIONS_KEY]: rekey(data.siteExceptions),
          [INLINE_ALLOWS_KEY]: rekey(data.siteInlineAllows),
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
