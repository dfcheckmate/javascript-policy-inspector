import { DEFAULT_MODE, MODES, isMode } from "./lib/policies.js";
import { RULE_BANDS, buildRule } from "./lib/rules.js";

const SITE_MODES_KEY = "siteModes";
const BADGE_COLOR = "#b45309";
const MAX_EVENTS_PER_TAB = 200;

/** @param {number} tabId */
const eventsKey = (tabId) => `tabEvents:${tabId}`;
/** @param {number} tabId */
const statsKey = (tabId) => `tabStats:${tabId}`;

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

chrome.tabs.onRemoved.addListener(async (tabId) => {
  await chrome.storage.session.remove([eventsKey(tabId), statsKey(tabId)]);
});

/**
 * @returns {Promise<Record<string, string>>} hostname -> mode
 */
async function getSiteModes() {
  const data = await chrome.storage.local.get(SITE_MODES_KEY);
  return data[SITE_MODES_KEY] ?? {};
}

/**
 * Stores the mode for a host and reconciles DNR rules.
 * @param {string} host
 * @param {string} mode
 */
async function setSiteMode(host, mode) {
  if (!isMode(mode)) throw new Error(`invalid mode: ${mode}`);
  const siteModes = await getSiteModes();
  siteModes[host] = mode;
  await chrome.storage.local.set({ [SITE_MODES_KEY]: siteModes });
  await syncRules(siteModes);
}

/**
 * Normalizes getDynamicRules() across Chromium builds: some older/forked
 * versions resolve directly to an array instead of `{rules: [...]}`.
 * @returns {Promise<chrome.declarativeNetRequest.Rule[]>}
 */
async function getDynamicRulesSafe() {
  const result = await chrome.declarativeNetRequest.getDynamicRules();
  return Array.isArray(result) ? result : (result?.rules ?? []);
}

/**
 * Reconciles dynamic DNR rules with stored modes.
 * Strategy: wipe every rule in the site-policy band, then rebuild from the
 * stored map. This makes mode SWITCHES (e.g. firstPartyOnly -> noScripts)
 * take effect — a diff-based update would keep the old policy because the
 * host still "has a rule". Idempotent and cheap (few rules at most).
 *
 * Tab-override rules (v0.3) live in a disjoint ID band and are left alone.
 */
async function syncRules(siteModes) {
  try {
    const modes = siteModes ?? (await getSiteModes());
    const hosts = Object.keys(modes).filter(
      (h) => modes[h] !== MODES.OBSERVE,
    );
    const rules = await getDynamicRulesSafe();
    const removeRuleIds = rules
      .filter(
        (r) =>
          r.id >= RULE_BANDS.SITE_POLICY && r.id < RULE_BANDS.TAB_OVERRIDE,
      )
      .map((r) => r.id);
    const addRules = hosts.map((h) => buildRule(h, modes[h]));
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

chrome.runtime.onInstalled.addListener(() => syncRules());
chrome.runtime.onStartup.addListener(() => syncRules());

/**
 * Message hub for the popup and observer content scripts.
 * - {type:"get-state", host}          -> {mode}
 * - {type:"set-mode", host, mode}     -> {ok:true}
 * - {type:"obs-events", events}       -> {ok:true}  (tab from sender)
 * - {type:"get-activity", tabId}      -> {events, stats}
 */
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    switch (msg?.type) {
      case "get-state": {
        const siteModes = await getSiteModes();
        sendResponse({ mode: siteModes[msg.host] ?? DEFAULT_MODE });
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
        const keys = [eventsKey(msg.tabId), statsKey(msg.tabId)];
        const stored = await chrome.storage.session.get(keys);
        sendResponse({
          events: stored[keys[0]] ?? [],
          stats: stored[keys[1]] ?? null,
        });
        break;
      }
      default:
        sendResponse({ error: `unknown message type: ${String(msg?.type)}` });
    }
  })().catch((err) => sendResponse({ error: String(err) }));
  return true;
});
