import {
  composePolicyFromFlags,
  normalizeOrigin,
} from "./lib/policies.js";
import {
  DEFAULT_POLICY,
  MODES,
  isFlags,
  makeFlags,
  migrateLegacyModes,
  modeForFlags,
  presetFor,
} from "./lib/flags.js";
import { computeStats } from "./lib/stats.js";
import {
  RULE_BANDS,
  buildRule,
  ruleIdFor,
} from "./lib/rules.js";
import { normalizeHostForRule } from "./lib/host.js";
import {
  CONTAINER_DIGEST_RE,
  ALLOWED_HASH_RE,
  normalizeInlineHash,
} from "./lib/allow.js";

const SITE_POLICIES_KEY = "sitePolicies";
const SITE_MODES_KEY = "siteModes"; // v1 store: read-only, migrated once
const EXCEPTIONS_KEY = "siteExceptions";
const INLINE_ALLOWS_KEY = "siteInlineAllows";
const CONTAINER_ALLOWS_KEY = "siteContainerAllows"; // { [host]: [hexDigest] }
const PAUSED_KEY = "pausedUntil";
const OVERRIDES_KEY = "tabOverrides";
const BADGE_COLOR = "#b45309";
const MAX_EVENTS_PER_TAB = 200;
const MAX_NET_PER_TAB = 300;
const NET_FLUSH_MS = 400;
const PAUSE_MS = 10 * 60 * 1000;
const MAX_PAUSE_MS = 24 * 60 * 60 * 1000;

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

/**
 * v2 policy store with one-way v1 migration. On first contact with a legacy
 * `siteModes` entry (host without a v2 bundle yet), the mode's preset is
 * materialized and persisted. Returns { [canonHost]: flagsBundle }.
 */
async function getSitePolicies() {
  const data = await chrome.storage.local.get([SITE_POLICIES_KEY, SITE_MODES_KEY]);
  const { policies, changed } = migrateLegacyModes(
    data[SITE_POLICIES_KEY],
    data[SITE_MODES_KEY],
  );
  if (changed) {
    await chrome.storage.local.set({ [SITE_POLICIES_KEY]: policies });
  }
  return policies;
}

/** Effective bundle for a host; hosts without a stored policy get observe. */
function flagsForHost(policies, hostKey) {
  return isFlags(policies[hostKey]) ? policies[hostKey] : DEFAULT_POLICY;
}

/** True when the bundle deploys a CSP rule (observational bundles don't). */
function hasCsp(flags) {
  try {
    return composePolicyFromFlags(flags) !== null;
  } catch {
    // stored bundle is unexpressible — never enforce, never crash
    return false;
  }
}

const getExceptions = () => getStore(EXCEPTIONS_KEY);
const getInlineAllows = () => getStore(INLINE_ALLOWS_KEY);
const getContainerAllows = () => getStore(CONTAINER_ALLOWS_KEY);
const getPaused = () => getStore(PAUSED_KEY);

/** Host storage keys are always stored in canonical (eTLD+1) form. */
const canon = (host) => normalizeHostForRule(host);

// ---------------------------------------------------------------------------
// rule-ID allocation (deterministic, collision-free)
// ---------------------------------------------------------------------------

/**
 * Computes the list of enforced hosts (policy bundles with a deployable CSP),
 * normalised and de-duplicated, then sorts them so linear-probe ID allocation
 * is identical across every restart and sync — no allocation table needs to
 * be persisted.
 * @returns {{host: string, flags: object}[]} sorted, de-duplicated
 */
function computeEffectiveHosts(policies) {
  const byHost = new Map();
  for (const raw of Object.keys(policies)) {
    const h = normalizeHostForRule(raw);
    if (!h || byHost.has(h)) continue;
    if (!isFlags(policies[raw])) continue;
    let enforced = false;
    try {
      enforced = composePolicyFromFlags(policies[raw]) !== null;
    } catch {
      // unexpressible stored bundle — skip so enforcement never half-applies
    }
    if (enforced) byHost.set(h, policies[raw]);
  }
  return [...byHost.entries()]
    .map(([host, flags]) => ({ host, flags }))
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
 * Returns null when the tab has no URL, is not http(s), or its host's policy
 * deploys no CSP (observe/container-only — no policy rule to exclude).
 * Otherwise returns the host, its assigned rule id, its flags bundle, and its
 * stored allowances so a single rule can be patched.
 * @returns {Promise<{host: string, id: number, flags: object, allows: object} | null>}
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
  const [policies, exceptions, inlineAllows] = await Promise.all([
    getSitePolicies(),
    getExceptions(),
    getInlineAllows(),
  ]);
  const hostKey = canon(host);
  const flags = flagsForHost(policies, hostKey);
  if (!hasCsp(flags)) return null;
  const effective = computeEffectiveHosts({ ...policies, [hostKey]: flags });
  const id = allocatedRuleIds(effective).get(hostKey);
  if (id === undefined) return null;
  return {
    host: hostKey,
    id,
    flags,
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
    resolver.flags,
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
  refreshBadgeDebounced();
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
    if (buf.byReqId.size < MAX_NET_PER_TAB) {
      buf.byReqId.set(details.requestId, entry);
    }
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
 * Reconciles dynamic DNR rules with stored policies + exceptions + pauses.
 * Strategy: wipe every rule in the site-policy band, then rebuild from
 * stored state — policy SWITCHES must take effect, so no diffing.
 *
 * Paused hosts are skipped until their pause expires; expired pauses are
 * pruned lazily here so a lost alarm can never wedge a host forever, and the
 * pre-pause flag bundle is restored (snapshotted at pause time).
 */
async function syncRules() {
  try {
    const [policies, exceptions, inlineAllows, paused] = await Promise.all([
      getSitePolicies(),
      getExceptions(),
      getInlineAllows(),
      getPaused(),
    ]);
    const now = Date.now();
    let changed = false;
    for (const [host, entry] of Object.entries(paused)) {
      // Legacy: pre-v0.3.6 entries stored a bare timestamp, and v1 pause
      // entries have no flags snapshot — default to observe on resume.
      const until = typeof entry === "number" ? entry : entry?.until;
      if (typeof until === "number" && until <= now) {
        policies[host] = entry?.flags ?? DEFAULT_POLICY;
        delete paused[host];
        changed = true;
      }
    }
    if (changed) {
      await chrome.storage.local.set({
        [SITE_POLICIES_KEY]: policies,
        [PAUSED_KEY]: paused,
      });
    }
    const effectiveHosts = computeEffectiveHosts(policies);
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
    const addRules = effectiveHosts.map(({ host, flags }) =>
      buildRule(
        host,
        flags,
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
    const [policies, paused, overrides] = await Promise.all([
      getSitePolicies(),
      getPaused(),
      getOverrideTabs(),
    ]);
    const key = canon(host);
    const flags = flagsForHost(policies, key);
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
    if (!hasCsp(flags)) {
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

/**
 * Trailing-debounced refreshBadge for high-frequency callers (observer event
 * ingestion ~every 250ms). The underlying refreshBadge does 5+ async storage
 * reads per call; coalescing bursts into one call per 500ms of quiet avoids
 * wedging the event-page with sustained work. State-change paths (syncRules,
 * tab listeners) still call refreshBadge() directly for immediate feedback.
 */
let scheduledBadge = null;
function refreshBadgeDebounced() {
  if (scheduledBadge !== null) return;
  scheduledBadge = setTimeout(() => {
    scheduledBadge = null;
    refreshBadge().catch(() => {});
  }, 500);
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

/**
 * Stores a flag bundle as the host's policy and reconciles rules. Bundles
 * without a deployable CSP (observe, container-only) also cancel any pause
 * so the host is never left "paused" with nothing to resume.
 * @param {string} host
 * @param {object} flags full bundle (see lib/flags.js)
 */
async function setSitePolicy(host, flags) {
  const key = canon(host);
  const policies = await getSitePolicies();
  if (modeForFlags(flags) === MODES.OBSERVE) {
    // observe is equivalent to "no policy stored" — keep the store canonical
    delete policies[key];
  } else {
    policies[key] = flags;
  }
  await chrome.storage.local.set({ [SITE_POLICIES_KEY]: policies });
  if (!hasCsp(flags)) await resumeHost(host).catch(() => {});
  else await syncRules();
}

// ---------------------------------------------------------------------------
// temporary controls
// ---------------------------------------------------------------------------

/** Pauses enforcement for `host` for `ms`; resumes automatically. */
async function pauseHost(host, ms) {
  const [paused, policies] = await Promise.all([getPaused(), getSitePolicies()]);
  const key = canon(host);
  const until = Date.now() + ms;
  // Snapshot the current bundle so an expired pause restores exactly what the
  // user had, not a globally-changed default.
  paused[key] = { until, flags: flagsForHost(policies, key) };
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

/**
 * Allows one inline script or handler by adding its CSP hash for a host.
 * @param {string} host
 * @param {"script"|"attr"} kind
 * @param {string} hash "sha256-…" (attr- prefix tolerated)
 */
async function addInlineAllow(host, kind, hash) {
  // A truncated/absent hash token can never match a script; reject it up
  // front so the popup shows a real error instead of a dead Allow.
  const clean = normalizeInlineHash(hash);
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

/**
 * Exempts one non-executing container from DOM removal on a host by adding
 * its SHA-256 hex digest to the allowlist (watched by the observer's removal
 * gate). Storage shape: { [canonHost]: string[] }.
 * @param {string} host
 * @param {string} digest 64-char lowercase hex
 */
async function addContainerAllow(host, digest) {
  const clean = String(digest).replace(/^attr-/, "");
  if (!CONTAINER_DIGEST_RE.test(clean) && !ALLOWED_HASH_RE.test(clean)) {
    throw new Error("invalid container digest (expected 64 hex chars)");
  }
  const all = await getContainerAllows();
  const key = canon(host);
  const list = all[key] ?? [];
  if (!list.includes(clean)) list.push(clean);
  all[key] = list;
  await chrome.storage.local.set({ [CONTAINER_ALLOWS_KEY]: all });
  return list;
}

/** Removes a container digest from a host's allowlist. */
async function removeContainerAllow(host, digest) {
  const all = await getContainerAllows();
  const key = canon(host);
  all[key] = (all[key] ?? []).filter((d) => d !== digest);
  await chrome.storage.local.set({ [CONTAINER_ALLOWS_KEY]: all });
  return all[key];
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

// ---------------------------------------------------------------------------
// per-site reset (revert a broken/custom policy without touching other hosts)
// ---------------------------------------------------------------------------

/**
 * Wipes every stored preference for one canonical host: flags bundle, legacy
 * mode, exceptions, inline allowances, container allowlists, and any pause.
 * After the wipe the host falls back to the observe default, so a policy that
 * broke a site can never wedge it. Rules are reconciled once at the end.
 * @param {string} host
 */
async function clearSite(host) {
  const key = canon(host);
  const [policies, legacyModes, exceptions, inlineAllows, containerAllows, paused] =
    await Promise.all([
      getSitePolicies(),
      getStore(SITE_MODES_KEY),
      getExceptions(),
      getInlineAllows(),
      getContainerAllows(),
      getPaused(),
    ]);
  let changed = false;
  for (const store of [
    policies,
    legacyModes,
    exceptions,
    inlineAllows,
    containerAllows,
    paused,
  ]) {
    if (key in store) {
      delete store[key];
      changed = true;
    }
  }
  if (changed) {
    await chrome.storage.local.set({
      [SITE_POLICIES_KEY]: policies,
      [SITE_MODES_KEY]: legacyModes,
      [EXCEPTIONS_KEY]: exceptions,
      [INLINE_ALLOWS_KEY]: inlineAllows,
      [CONTAINER_ALLOWS_KEY]: containerAllows,
      [PAUSED_KEY]: paused,
    });
  }
  // A stale alarm would re-deploy the old bundle on expiry; kill it.
  await chrome.alarms.clear(`resume:${key}`);
  await syncRules();
  return { ok: true };
}

/** Flushes one tab's transient ledger (events/stats/network) and override. */
async function clearTab(tabId) {
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
  await refreshBadge();
  return { ok: true };
}

/**
 * Fire-and-forget broadcast so an open popup can re-hydrate when policy,
 * pause or override state changes from outside its own action flow (alarm
 * auto-resume, another context, import). No payload — the popup re-fetches
 * get-state, keeping the contract single-source-of-truth.
 */
function notifyStateChanged() {
  try {
    void Promise.resolve(
      chrome.runtime.sendMessage({ type: "state-changed" }),
    ).catch(() => {});
  } catch {
    // no listeners (e.g. tests, popup closed) — nothing to notify
  }
}

/**
 * Message hub for the popup and observer content scripts.
 * - {type:"get-state", host, tabId?}   -> {flags, mode, activeCsp, pausedUntil, tabOverride, exceptions, inlineAllows}
 * - {type:"set-mode", host, mode}      -> {ok:true}   (mode = preset name)
 * - {type:"set-policy", host, flags}   -> {ok:true}   (arbitrary flag bundle)
 * - {type:"obs-events", events}        -> {ok:true}  (tab from sender)
 * - {type:"get-activity", tabId}       -> {events, stats, netEvents}
 * - {type:"pause-host", host}          -> {until}
 * - {type:"resume-host", host}         -> {ok:true}
 * - {type:"toggle-tab-override", tabId}-> {active}
 * - {type:"add-exception", host, origin}    -> {exceptions}
 * - {type:"remove-exception", host, origin}-> {exceptions}
 * - {type:"export-settings"}           -> {version:2, sitePolicies, siteExceptions, siteInlineAllows, siteContainerAllows}
 * - {type:"import-settings", data}     -> {ok:true} (accepts v1 siteModes + v2 sitePolicies)
 * - {type:"add-container-allow", host, digest}    -> {containerAllows}
 * - {type:"remove-container-allow", host, digest} -> {containerAllows}
 * - {type:"clear-site", host} -> {ok:true} (revert host to observe default)
 * - {type:"clear-tab", tabId} -> {ok:true} (flush the tab's transient ledger)
 * - broadcast {type:"state-changed"} — fire-and-forget; popup re-hydrates
 */
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    switch (msg?.type) {
      case "get-state": {
        const [policies, exceptions, inlineAllows, containerAllows, paused] =
          await Promise.all([
            getSitePolicies(),
            getExceptions(),
            getInlineAllows(),
            getContainerAllows(),
            getPaused(),
          ]);
        const key = canon(msg.host);
        const flags = flagsForHost(policies, key);
        const allows = {
          origins: exceptions[key] ?? [],
          scriptHashes: inlineAllows[key]?.scripts ?? [],
          attrHashes: inlineAllows[key]?.attrs ?? [],
        };
        let activeCsp = null;
        try {
          activeCsp = composePolicyFromFlags(flags, allows);
        } catch {
          // unexpressible stored bundle — surfaced in the popup as a profile
          // error rather than crashing the state fetch
        }
        const state = {
          host: key,
          flags: { ...flags },
          mode: modeForFlags(flags) ?? "custom",
          pausedUntil:
            key in paused
              ? typeof paused[key] === "number"
                ? paused[key]
                : paused[key]?.until ?? null
              : null,
          exceptions: allows.origins,
          inlineAllows: { scripts: allows.scriptHashes, attrs: allows.attrHashes },
          containerAllows: containerAllows[key] ?? [],
          activeCsp,
        };
        state.tabOverride =
          typeof msg.tabId === "number" && (await isTabOverridden(msg.tabId));
        sendResponse(state);
        break;
      }
      case "set-mode": {
        const flags = presetFor(msg.mode);
        if (!flags) throw new Error(`unknown preset mode: ${String(msg.mode)}`);
        await setSitePolicy(msg.host, flags);
        notifyStateChanged();
        sendResponse({ ok: true });
        break;
      }
      case "set-policy": {
        if (!isFlags(msg.flags)) {
          throw new Error("set-policy needs a full flags bundle");
        }
        await setSitePolicy(msg.host, makeFlags(msg.flags));
        notifyStateChanged();
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
        const ms = Math.min(
          typeof msg.ms === "number" && Number.isFinite(msg.ms) && msg.ms > 0
            ? msg.ms
            : PAUSE_MS,
          MAX_PAUSE_MS,
        );
        sendResponse(await pauseHost(msg.host, ms));
        notifyStateChanged();
        break;
      }
      case "resume-host":
        await resumeHost(msg.host);
        notifyStateChanged();
        sendResponse({ ok: true });
        break;
      case "toggle-tab-override": {
        if (typeof msg.tabId !== "number") {
          sendResponse({ error: "toggle-tab-override needs tabId" });
          break;
        }
        sendResponse({ active: await toggleTabOverride(msg.tabId) });
        notifyStateChanged();
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
      case "add-container-allow":
        sendResponse({
          containerAllows: await addContainerAllow(msg.host, msg.digest),
        });
        break;
      case "remove-container-allow":
        sendResponse({
          containerAllows: await removeContainerAllow(msg.host, msg.digest),
        });
        break;
      case "clear-site":
        sendResponse(await clearSite(msg.host));
        notifyStateChanged();
        break;
      case "clear-tab":
        if (typeof msg.tabId !== "number") {
          sendResponse({ error: "clear-tab needs tabId" });
          break;
        }
        sendResponse(await clearTab(msg.tabId));
        break;
      case "export-settings": {
        const [sitePolicies, siteExceptions, siteInlineAllows, siteContainerAllows] =
          await Promise.all([
            getSitePolicies(),
            getExceptions(),
            getInlineAllows(),
            getContainerAllows(),
          ]);
        sendResponse({
          version: 2,
          sitePolicies,
          siteExceptions,
          siteInlineAllows,
          siteContainerAllows,
        });
        break;
      }
      case "import-settings": {
        const data = msg.data ?? {};
        if (typeof data.version === "number" && data.version !== 2) {
          throw new Error(`unsupported settings version: ${data.version}`);
        }
        const policies = {};
        // v2 bundles first…
        for (const [k, v] of Object.entries(data.sitePolicies ?? {})) {
          policies[canon(k)] = makeFlags(v); // validates keys + booleans
        }
        // …then legacy v1 modes for hosts still missing a v2 bundle.
        for (const [k, v] of Object.entries(data.siteModes ?? {})) {
          const hostKey = canon(k);
          if (!isFlags(policies[hostKey])) {
            const preset = presetFor(v);
            if (!preset) throw new Error(`invalid mode in import: ${v}`);
            policies[hostKey] = preset;
          }
        }
        // Reject bundles the engine can never deploy (unexpressible combos)
        // outright, so a bad import can't wedge a host into broken rules.
        for (const flags of Object.values(policies)) {
          composePolicyFromFlags(flags);
        }
        const rekey = (obj) => {
          const out = {};
          for (const [k, v] of Object.entries(obj ?? {})) out[canon(k)] = v;
          return out;
        };
        // Container allowlists carry 64-char hex digests; validate on import
        // so a corrupted file can't poison the observer's removal gate.
        for (const digests of Object.values(data.siteContainerAllows ?? {})) {
          for (const d of digests ?? []) {
            if (!CONTAINER_DIGEST_RE.test(String(d))) {
              throw new Error(`invalid container digest in import: ${String(d)}`);
            }
          }
        }
        await chrome.storage.local.set({
          [SITE_POLICIES_KEY]: policies,
          [SITE_MODES_KEY]: {}, // legacy store fully superseded by the import
          [EXCEPTIONS_KEY]: rekey(data.siteExceptions),
          [INLINE_ALLOWS_KEY]: rekey(data.siteInlineAllows),
          [CONTAINER_ALLOWS_KEY]: rekey(data.siteContainerAllows),
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
