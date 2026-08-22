import { buildRule, patternsFor, ruleIdFor } from "./lib/rules.js";

const els = {
  origin: document.getElementById("origin"),
  state: document.getElementById("state"),
  toggle: document.getElementById("toggle"),
};

/** @type {string | null} */
let host = null;

/**
 * Resolves the hostname of the active tab, or null if unsupported
 * (chrome:// pages, file:// URLs, etc.).
 */
async function activeHost() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let url;
  try {
    url = new URL(tab?.url ?? "");
  } catch {
    return null;
  }
  return /^https?:$/.test(url.protocol) && url.hostname ? url.hostname : null;
}

async function isEnabled(target) {
  const { rules } = await chrome.declarativeNetRequest.getDynamicRules();
  return rules.some((rule) => rule.id === ruleIdFor(target));
}

function render(enabled) {
  if (!host) {
    els.origin.textContent = "no http(s) page";
    els.state.textContent = "Open an http(s) page to use the blocker.";
    els.state.className = "state unsupported";
    els.toggle.disabled = true;
    return;
  }
  els.origin.textContent = host;
  els.state.textContent = enabled ? "Inline JS: BLOCKED" : "Inline JS: allowed";
  els.state.className = enabled ? "state on" : "state off";
  els.toggle.textContent = enabled ? `Allow inline JS on ${host}` : `Block inline JS on ${host}`;
}

els.toggle.addEventListener("click", async () => {
  if (!host) return;
  if (await isEnabled(host)) {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: [ruleIdFor(host)],
    });
    try {
      await chrome.permissions.remove({ origins: patternsFor(host) });
    } catch {
      // patterns may already be gone; not fatal
    }
  } else {
    const granted = await chrome.permissions.request({
      origins: patternsFor(host),
    });
    if (!granted) return;
    await chrome.declarativeNetRequest.updateDynamicRules({
      addRules: [buildRule(host)],
      removeRuleIds: [ruleIdFor(host)],
    });
  }
  chrome.runtime.sendMessage({ type: "rules-changed" }).catch(() => {});
  render(await isEnabled(host));
});

host = await activeHost();
render(host ? await isEnabled(host) : false);
