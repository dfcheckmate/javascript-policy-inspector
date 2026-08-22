import { ruleIdFor } from "./lib/rules.js";

/** Badge shows how many origins currently have inline JS disabled. */
async function refreshBadge() {
  const { rules } = await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.action.setBadgeBackgroundColor({ color: "#b91c1c" });
  await chrome.action.setBadgeTextColor({ color: "#ffffff" });
  await chrome.action.setBadgeText({
    text: rules.length > 0 ? String(rules.length) : "",
  });
}

chrome.runtime.onInstalled.addListener(refreshBadge);
chrome.runtime.onStartup.addListener(refreshBadge);

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === "rules-changed") refreshBadge();
});

/** Exposed so the popup can double-check state before toggling. */
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type !== "is-enabled") return;
  chrome.declarativeNetRequest.getDynamicRules().then(({ rules }) => {
    const enabled =
      typeof msg.host === "string" &&
      rules.some((r) => r.id === ruleIdFor(msg.host));
    sendResponse({ enabled });
  });
  return true;
});
