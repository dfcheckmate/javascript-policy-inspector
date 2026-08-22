import { DEFAULT_MODE, POLICY_SUMMARY } from "./lib/policies.js";
import { ruleIdFor } from "./lib/rules.js";

const els = {
  origin: document.getElementById("origin"),
  summary: document.getElementById("summary"),
  rule: document.getElementById("rule"),
  reload: document.getElementById("reload"),
  radios: () => document.querySelectorAll('input[name="mode"]'),
  pause: document.getElementById("pause"),
  pauseState: document.getElementById("pause-state"),
  allowTab: document.getElementById("allow-tab"),
  excForm: document.getElementById("exc-form"),
  excInput: document.getElementById("exc-input"),
  excList: document.getElementById("exc-list"),
  exportBtn: document.getElementById("export-btn"),
  importBtn: document.getElementById("import-btn"),
  importFile: document.getElementById("import-file"),
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

/** Shows whether a DNR rule actually exists for this host right now.
 *  Normalizes getDynamicRules() across Chromium builds (see service-worker). */
async function renderRuleStatus(target) {
  if (!target) {
    els.rule.textContent = "";
    return;
  }
  try {
    const result = await chrome.declarativeNetRequest.getDynamicRules();
    const rules = Array.isArray(result) ? result : (result?.rules ?? []);
    const rule = rules.find((r) => r.id === ruleIdFor(target));
    els.rule.textContent = rule
      ? `CSP rule: ACTIVE → ${rule.action.responseHeaders[0].value}`
      : "CSP rule: none (Observe or not applied)";
  } catch (err) {
    els.rule.textContent = `CSP rule: error — ${err}`;
  }
}

function fmtClock(ts) {
  const d = new Date(ts);
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}`;
}

function renderPaused(pausedUntil) {
  const active = typeof pausedUntil === "number" && pausedUntil > Date.now();
  els.pause.classList.toggle("active", active);
  els.pause.textContent = active ? "Resume now" : "Pause 10 min";
  els.pauseState.textContent = active
    ? `Policy paused until ${fmtClock(pausedUntil)}`
    : "";
}

function renderTabOverride(active) {
  els.allowTab.classList.toggle("active", active);
  els.allowTab.textContent = active ? "Allow this tab ✓" : "Allow this tab";
}

function renderExceptions(list) {
  els.excList.innerHTML = (list ?? [])
    .map(
      (o) =>
        `<li>${o}<button type="button" data-origin="${o}" title="Remove">×</button></li>`,
    )
    .join("");
}

async function refreshUi() {
  if (!host) return;
  const state = await chrome.runtime.sendMessage({
    type: "get-state",
    host,
    tabId,
  });
  if (state?.error) return;
  render(state.mode ?? DEFAULT_MODE);
  renderPaused(state.pausedUntil);
  renderTabOverride(Boolean(state.tabOverride));
  renderExceptions(state.exceptions);
  await renderRuleStatus(host);
  await loadActivity();
}

// ---------------------------------------------------------------------------
// event wiring
// ---------------------------------------------------------------------------

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
    await refreshUi();
  }),
);

els.reload.addEventListener("click", async () => {
  if (tabId !== null) await chrome.tabs.reload(tabId);
  window.close();
});

els.pause.addEventListener("click", async () => {
  if (!host) return;
  const active =
    els.pause.classList.contains("active") ||
    (await chrome.runtime.sendMessage({ type: "get-state", host }))
      ?.pausedUntil != null;
  await chrome.runtime.sendMessage(
    active ? { type: "resume-host", host } : { type: "pause-host", host },
  );
  await refreshUi();
});

els.allowTab.addEventListener("click", async () => {
  if (tabId === null) return;
  const res = await chrome.runtime.sendMessage({
    type: "toggle-tab-override",
    tabId,
  });
  if (res?.active) await chrome.tabs.reload(tabId);
  await refreshUi();
});

els.excForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!host) return;
  const origin = els.excInput.value.trim();
  if (!origin) return;
  const res = await chrome.runtime.sendMessage({
    type: "add-exception",
    host,
    origin,
  });
  if (res?.error) {
    els.pauseState.textContent = `Error: ${res.error}`;
    return;
  }
  els.excInput.value = "";
  await refreshUi();
});

els.excList.addEventListener("click", async (event) => {
  const origin = event.target?.dataset?.origin;
  if (!origin || !host) return;
  await chrome.runtime.sendMessage({
    type: "remove-exception",
    host,
    origin,
  });
  await refreshUi();
});

els.exportBtn.addEventListener("click", async () => {
  const data = await chrome.runtime.sendMessage({ type: "export-settings" });
  if (data?.error) return;
  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "js-policy-inspector-settings.json";
  a.click();
  URL.revokeObjectURL(url);
});

els.importBtn.addEventListener("click", () => els.importFile.click());

els.importFile.addEventListener("change", async () => {
  const file = els.importFile.files?.[0];
  if (!file) return;
  try {
    const data = JSON.parse(await file.text());
    const res = await chrome.runtime.sendMessage({
      type: "import-settings",
      data,
    });
    if (res?.error) {
      els.pauseState.textContent = `Import failed: ${res.error}`;
      return;
    }
    await refreshUi();
  } catch (err) {
    els.pauseState.textContent = `Import failed: ${err}`;
  } finally {
    els.importFile.value = "";
  }
});

// ---------------------------------------------------------------------------
// inventory / activity rendering
// ---------------------------------------------------------------------------

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
  els.pause.disabled = true;
  els.allowTab.disabled = true;
} else {
  ({ host, tabId } = ctx);
  els.origin.textContent = host;
  await refreshUi();
}
