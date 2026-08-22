import { DEFAULT_MODE, POLICY_SUMMARY } from "./lib/policies.js";
import { ruleIdFor } from "./lib/rules.js";

const els = {
  origin: document.getElementById("origin"),
  summary: document.getElementById("summary"),
  rule: document.getElementById("rule"),
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

/** Shows whether a DNR rule actually exists for this host right now. */
async function renderRuleStatus(target) {
  let line;
  if (!target) {
    line = "";
  } else {
    const { rules } = await chrome.declarativeNetRequest.getDynamicRules();
    const rule = rules.find((r) => r.id === ruleIdFor(target));
    line = rule
      ? `CSP rule: ACTIVE → ${rule.action.responseHeaders[0].value}`
      : "CSP rule: none (Observe or not applied)";
  }
  els.rule.textContent = line;
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

const KIND_LABELS = {
  script: "script",
  "inline-script": "inline <script>",
  "inline-handler": "inline handler",
  "csp-violation": "CSP block",
};

function fmtTime(ts) {
  const d = new Date(ts);
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function renderInventory(stats) {
  const el = document.getElementById("inventory");
  if (!stats) {
    el.innerHTML = '<span class="muted">no activity recorded yet</span>';
    return;
  }
  const items = [
    ["1st-party", stats.scriptsFirstParty],
    ["3rd-party", stats.scriptsThirdParty],
    ["inline", stats.inlineScripts],
    ["handlers", stats.inlineHandlers],
    ["blocked", stats.blocked],
  ];
  el.innerHTML = items
    .map(
      ([label, n]) =>
        `<span class="count${label === "blocked" && n > 0 ? " hot" : ""}"><b>${n}</b>${label}</span>`,
    )
    .join("");
}

function renderActivity(events) {
  const list = document.getElementById("activity");
  if (!Array.isArray(events) || events.length === 0) {
    list.innerHTML = '<li class="muted">nothing recorded yet</li>';
    return;
  }
  const recent = events.slice(-8).reverse();
  list.innerHTML = recent
    .map((e) => {
      const what =
        e.kind === "csp-violation"
          ? e.reason ?? "violation"
          : `${KIND_LABELS[e.kind] ?? e.kind}${e.url ? `: ${e.url}` : ""}`;
      const cls = e.action === "blocked" ? "blocked" : "";
      return `<li class="${cls}"><time>${fmtTime(e.ts)}</time> ${what}</li>`;
    })
    .join("");
}

async function loadActivity() {
  if (tabId === null) return;
  const res = await chrome.runtime.sendMessage({
    type: "get-activity",
    tabId,
  });
  if (res?.error) return;
  renderInventory(res.stats);
  renderActivity(res.events);
}

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
  await renderRuleStatus(host);
  await loadActivity();
}
