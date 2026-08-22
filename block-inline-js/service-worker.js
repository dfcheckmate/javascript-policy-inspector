import { DEFAULT_MODE, MODES, isMode } from "./lib/policies.js";
import { buildRule, isPolicyRuleFor } from "./lib/rules.js";

const SITE_MODES_KEY = "siteModes";
const BADGE_COLOR = "#b45309";

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
 * Reconciles dynamic DNR rules with stored modes: removes every rule we own
 * that no longer matches a stored non-observe mode, adds missing ones.
 * Idempotent — safe to run on every install/startup/mode change.
 *
 * Tab-override rules (v0.3) live in a disjoint ID band and are left alone.
 */
async function syncRules(siteModes) {
  const modes = siteModes ?? (await getSiteModes());
  const hosts = Object.keys(modes).filter(
    (h) => modes[h] !== MODES.OBSERVE,
  );
  const { rules } = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = rules
    .filter((r) => !hosts.some((h) => isPolicyRuleFor(r, h)))
    .filter((r) => r.action?.type === "modifyHeaders")
    .map((r) => r.id);
  const addRules = hosts
    .filter((h) => !rules.some((r) => isPolicyRuleFor(r, h)))
    .map((h) => buildRule(h, modes[h]));
  if (removeRuleIds.length > 0 || addRules.length > 0) {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds,
      addRules,
    });
  }
  await refreshBadge(hosts.length);
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
 * Message hub for the popup.
 * - {type:"get-state", host}          -> {mode}
 * - {type:"set-mode", host, mode}     -> {ok:true}
 */
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
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
      default:
        sendResponse({ error: `unknown message type: ${String(msg?.type)}` });
    }
  })().catch((err) => sendResponse({ error: String(err) }));
  return true;
});
