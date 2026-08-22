import { DEFAULT_MODE, POLICY_SUMMARY } from "./lib/policies.js";

const els = {
  origin: document.getElementById("origin"),
  summary: document.getElementById("summary"),
  reload: document.getElementById("reload"),
  radios: () => document.querySelectorAll('input[name="mode"]'),
};

/** @type {string | null} */
let host = null;
/** @type {number | null} */
let tabId = null;

/** Resolves hostname + tab id of the active tab; null when unsupported. */
async function activeTabContext() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let url;
  try {
    url = new URL(tab?.url ?? "");
  } catch {
    return null;
  }
  if (!/^https?:$/.test(url.protocol) || !url.hostname) return null;
  return { host: url.hostname, tabId: tab.id };
}

function render(mode) {
  for (const radio of els.radios()) radio.checked = radio.value === mode;
  els.summary.textContent = POLICY_SUMMARY[mode] ?? "";
}

els.radios().forEach((radio) =>
  radio.addEventListener("change", async () => {
    if (!host || !radio.checked) return;
    const res = await chrome.runtime.sendMessage({
      type: "set-mode",
      host,
      mode: radio.value,
    });
    if (res?.error) {
      els.summary.textContent = `Error: ${res.error}`;
      return;
    }
    render(radio.value);
  }),
);

els.reload.addEventListener("click", async () => {
  if (tabId !== null) await chrome.tabs.reload(tabId);
  window.close();
});

const ctx = await activeTabContext();
if (!ctx) {
  host = null;
  els.origin.textContent = "no http(s) page";
  els.summary.textContent = "Open an http(s) page to inspect it.";
  els.reload.disabled = true;
} else {
  ({ host, tabId } = ctx);
  els.origin.textContent = host;
  const state = await chrome.runtime.sendMessage({
    type: "get-state",
    host,
  });
  render(state?.mode ?? DEFAULT_MODE);
}
