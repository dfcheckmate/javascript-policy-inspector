import { DEFAULT_MODE, POLICY_SUMMARY } from "./lib/policies.js";
import { normalizeHostForRule, ruleIdFor } from "./lib/rules.js";

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
  // Fold to eTLD+1 so subdomains resolve to the same stored policy/rule.
  return { host: normalizeHostForRule(url.hostname), tabId: tab.id };
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
        `<li>${escapeHtml(o)}<button type="button" data-origin="${escapeHtml(o)}" title="Remove">×</button></li>`,
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
  lastInlineAllows = state.inlineAllows ?? { scripts: [], attrs: [] };
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
    ["first", "1st-party", stats.scriptsFirstParty],
    ["third", "3rd-party", stats.scriptsThirdParty],
    ["inline-script", "inline", stats.inlineScripts],
    ["inline-handler", "handlers", stats.inlineHandlers],
    ["csp-violation", "blocked", stats.blocked],
    ["net", "network", stats.netRequests ?? 0],
  ];
  el.innerHTML = items
    .map(([view, label, n]) =>
      n === 0
        ? `<span class="count"><b>${n}</b>${label}</span>`
        : `<button type="button" class="count${label === "blocked" ? " hot" : ""}" data-view="${view}"><b>${n}</b>${label}</button>`,
    )
    .join("");
}

/** Dedupes events into rows keyed by their allow-identity. */
function detailRows(view, events) {
  const matchers = {
    first: (e) => e.kind === "script" && e.party === "first",
    third: (e) => e.kind === "script" && e.party === "third",
    "inline-script": (e) => e.kind === "inline-script",
    "inline-handler": (e) => e.kind === "inline-handler",
    "csp-violation": (e) => e.kind === "csp-violation",
    net: (e) => e.kind === "net",
  };
  const byKey = new Map();
  for (const e of events.filter(matchers[view] ?? (() => false))) {
    const key =
      view === "net"
        ? `${e.method}:${e.url}`
        : (e.hash ??
          e.url ??
          `${e.handler ?? ""}:${e.snippet ?? ""}:${e.reason ?? ""}`);
    const row = byKey.get(key) ?? { ...e, count: 0 };
    row.count++;
    if (!row.hash && e.hash) row.hash = e.hash;
    if (!row.status && e.status) row.status = e.status;
    byKey.set(key, row);
  }
  return [...byKey.values()].map((row) => {
    let action = null;
    if ((view === "first" || view === "third") && row.origin) {
      action = { kind: "origin", value: row.origin };
    } else if (view === "inline-script" && row.hash) {
      action = { kind: "script", value: row.hash };
    } else if (view === "inline-handler" && row.hash) {
      action = { kind: "attr", value: row.hash };
    }
    return { ...row, action };
  });
}

function renderDetail(view, events, inlineAllows) {
  const el = document.getElementById("detail");
  const allowedSet = new Set([
    ...(inlineAllows?.scripts ?? []),
    ...(inlineAllows?.attrs ?? []),
  ]);
  if (!view || !Array.isArray(events)) {
    el.innerHTML = "";
    return;
  }
  const rows = detailRows(view, events);
  if (rows.length === 0) {
    el.innerHTML = '<li class="muted">nothing in this category</li>';
    return;
  }
  if (view === "net") {
    // observation-only: no Allow actions, show method/target + type/status
    el.innerHTML = rows
      .map((row) => {
        const badge =
          `${row.type ?? ""}${row.status ? ` · ${row.status}` : " · …"}` +
          (row.count > 1 ? ` · ×${row.count}` : "");
        const cls = /ERR|FAILED/.test(row.status ?? "") ? ' class="bad"' : "";
        const title = escapeHtml(`${row.method} ${row.url}`);
        return `<li${cls}><span class="label" title="${title}">${title}</span><span class="badge">${escapeHtml(badge)}</span></li>`;
      })
      .join("");
    return;
  }
  el.innerHTML = rows
    .map((row) => {
      const full =
        row.url ?? row.snippet ?? row.reason ?? "(unknown)";
      const label = escapeHtml(full);
      const badge = row.count > 1 ? `×${row.count}` : "";
      let button = "";
      if (row.action) {
        const alreadyAllowed =
          row.action.kind === "origin"
            ? false
            : allowedSet.has(row.action.value);
        button = alreadyAllowed
          ? '<span class="badge">allowed</span>'
          : `<button type="button" data-kind="${row.action.kind}" data-value="${row.action.value}">Allow</button>`;
      }
      return `<li><span class="label" title="${label}">${escapeHtml(label)}</span><span class="badge">${badge}</span>${button}</li>`;
    })
    .join("");
}

function escapeHtml(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

let currentView = null;
let lastEvents = [];
let lastNetEvents = [];
let lastInlineAllows = { scripts: [], attrs: [] };

const allEvents = () => [...lastEvents, ...lastNetEvents];

document.getElementById("inventory").addEventListener("click", (event) => {
  const view = event.target?.dataset?.view;
  if (!view) return;
  currentView = currentView === view ? null : view;
  renderDetail(currentView, allEvents(), lastInlineAllows);
});

document.getElementById("detail").addEventListener("click", async (event) => {
  // Allow buttons take precedence; row clicks expand/collapse.
  const btn = event.target.closest("button[data-kind]");
  if (btn) {
    if (!host) return;
    const { kind, value } = btn.dataset;
    const message =
      kind === "origin"
        ? { type: "add-exception", host, origin: value }
        : { type: "add-inline-allow", host, kind, hash: value };
    const res = await chrome.runtime.sendMessage(message);
    if (res?.error) return;
    await refreshUi();
    return;
  }
  const li = event.target.closest("li");
  if (li) li.classList.toggle("expanded");
});

document.getElementById("activity").addEventListener("click", (event) => {
  if (event.target.closest("button")) return;
  const li = event.target.closest("li");
  if (li) li.classList.toggle("expanded");
});

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
      return `<li class="${cls}" title="${escapeHtml(what)}"><time>${fmtTime(e.ts)}</time> <span class="line">${escapeHtml(what)}</span></li>`;
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
  lastEvents = res.events ?? [];
  lastNetEvents = res.netEvents ?? [];
  renderInventory(res.stats);
  renderActivity(lastEvents);
  renderDetail(currentView, allEvents(), lastInlineAllows);
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
