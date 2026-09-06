import { DEFAULT_MODE, POLICY_SUMMARY, composeHeader } from "./lib/policies.js";
import { normalizeHostForRule, ruleIdFor } from "./lib/rules.js";
import { beautify } from "./lib/beautify.js";
import { highlight } from "./lib/highlight.js";

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
  copyCsp: document.getElementById("copy-csp"),
  sourceView: document.getElementById("source-view"),
  sourceCode: document.getElementById("source-code"),
  relax: () => document.querySelectorAll("[data-pause-min]"),
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
  els.pause.textContent = active ? "Resume now" : "Pause";
  els.pauseState.textContent = active
    ? `Policy paused until ${fmtClock(pausedUntil)}`
    : "";
}

function renderTabOverride(active) {
  els.allowTab.classList.toggle("active", active);
  els.allowTab.textContent = active ? "Allow this tab ✓" : "Allow this tab";
}

function renderExceptions(list) {
  els.excList.replaceChildren();
  for (const o of list ?? []) {
    const li = document.createElement("li");
    li.textContent = o;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.dataset.origin = o;
    btn.title = "Remove";
    btn.textContent = "×";
    li.append(btn);
    els.excList.append(li);
  }
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
  lastExceptions = state.exceptions ?? [];
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

// Relax presets: pause for N minutes (host-scoped, auto-resume).
for (const btn of els.relax()) {
  btn.addEventListener("click", async () => {
    if (!host) return;
    const ms = Number(btn.dataset.pauseMin) * 60 * 1000;
    await chrome.runtime.sendMessage({ type: "pause-host", host, ms });
    await refreshUi();
  });
}

// Copy a deployable CSP header for this host (built client-side, offline).
els.copyCsp.addEventListener("click", async () => {
  if (!host) return;
  const state = await chrome.runtime.sendMessage({
    type: "get-state",
    host,
    tabId,
  });
  if (state?.error) {
    els.pauseState.textContent = state.error;
    return;
  }
  const header = composeHeader(state.mode ?? DEFAULT_MODE, {
    origins: state.exceptions ?? [],
    scriptHashes: state.inlineAllows?.scripts ?? [],
    attrHashes: state.inlineAllows?.attrs ?? [],
  });
  if (header == null) {
    els.pauseState.textContent = "No CSP to copy (Observe mode)";
    return;
  }
  try {
    await navigator.clipboard.writeText(header);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = header;
    document.body.append(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
  els.pauseState.textContent = "CSP header copied to clipboard";
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
  el.replaceChildren();
  if (!stats) {
    const span = document.createElement("span");
    span.className = "muted";
    span.textContent = "no activity recorded yet";
    el.append(span);
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
  for (const [view, label, n] of items) {
    if (n === 0) {
      const span = document.createElement("span");
      span.className = "count";
      const b = document.createElement("b");
      b.textContent = n;
      span.append(b, label);
      el.append(span);
    } else {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.dataset.view = view;
      btn.className = `count${label === "blocked" ? " hot" : ""}`;
      const b = document.createElement("b");
      b.textContent = n;
      btn.append(b, label);
      el.append(btn);
    }
  }
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

function appendDetailRow(
  el,
  { cls, label, badgeValue, allowed, allowKind, allowValue, source, sourceUrl },
) {
  const li = document.createElement("li");
  if (cls) li.className = cls;
  const labelSpan = document.createElement("span");
  labelSpan.className = "label";
  labelSpan.title = label;
  labelSpan.textContent = label;
  li.append(labelSpan);
  if (badgeValue) {
    const badgeSpan = document.createElement("span");
    badgeSpan.className = "badge";
    badgeSpan.textContent = badgeValue;
    li.append(badgeSpan);
  }
  // Inline preview or "view external source" affordance.
  if (source != null) {
    const details = document.createElement("details");
    details.className = "preview";
    const sum = document.createElement("summary");
    sum.textContent = "preview";
    details.append(sum);
    const pre = document.createElement("pre");
    pre.className = "code";
    const fmt = beautify(source) || source;
    for (const span of renderCodeSpans(fmt)) pre.append(span);
    details.append(pre);
    li.append(details);
  } else if (sourceUrl) {
    const view = document.createElement("button");
    view.type = "button";
    view.dataset.viewSource = sourceUrl;
    view.textContent = "View";
    li.append(view);
  }
  if (allowed) {
    const allowedSpan = document.createElement("span");
    allowedSpan.className = "badge";
    allowedSpan.textContent = "allowed";
    li.append(allowedSpan);
  } else if (allowKind !== null) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.dataset.kind = allowKind;
    btn.dataset.value = allowValue;
    btn.textContent = "Allow";
    li.append(btn);
  }
  el.append(li);
}

/** Renders formatted code into safe highlighted DOM spans. */
function renderCodeSpans(src) {
  const spans = [];
  for (const tok of highlight(src)) {
    const span = document.createElement("span");
    if (tok.cls) span.className = `tok-${tok.cls}`;
    span.textContent = tok.text;
    spans.push(span);
  }
  return spans;
}

/** Populates the shared source panel; fetches external scripts (user-initiated). */
async function showSource(rawText, url) {
  let text = rawText;
  if (text == null && url) {
    els.sourceCode.textContent = "loading…";
    try {
      const resp = await fetch(url, { credentials: "omit" });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const buf = await resp.arrayBuffer();
      if (buf.byteLength > 1024 * 1024) throw new Error("Source exceeds 1MB limit");
      text = new TextDecoder().decode(buf);
    } catch (err) {
      els.sourceCode.textContent = `Failed to load source: ${err.message}`;
      els.sourceView.hidden = false;
      return;
    }
  }
  if (text == null) {
    els.sourceCode.textContent = "No source available.";
    els.sourceView.hidden = false;
    return;
  }
  const fmt = beautify(text) || text;
  els.sourceCode.replaceChildren();
  const pre = els.sourceCode;
  pre.append(...renderCodeSpans(fmt));
  els.sourceView.hidden = false;
  if (url) {
    const label = document.createElement("div");
    label.className = "src-url";
    label.textContent = url;
    pre.before(label);
  }
  els.sourceView.open = true;
}

function renderDetail(view, events, inlineAllows, exceptions) {
  const el = document.getElementById("detail");
  const allowedSet = new Set([
    ...(inlineAllows?.scripts ?? []),
    ...(inlineAllows?.attrs ?? []),
  ]);
  const excSet = new Set(exceptions ?? []);
  el.replaceChildren();
  if (!view || !Array.isArray(events)) {
    return;
  }
  const rows = detailRows(view, events);
  if (rows.length === 0) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "nothing in this category";
    el.append(li);
    return;
  }
  if (view === "net") {
    // Network request rows. Our CSP only gates *script* requests, so an
    // Allow action (adding the request's origin to the site exceptions) is
    // meaningful solely for script-type rows; every other type stays
    // observation-only.
    for (const row of rows) {
      const badge =
        `${row.type ?? ""}${row.status ? ` · ${row.status}` : " · …"}` +
        (row.count > 1 ? ` · ×${row.count}` : "");
      const isBad = /ERR|FAILED/.test(row.status ?? "");
      const title = `${row.method} ${row.url}`;
      let allowKind = null;
      let allowValue = null;
      if (row.type === "script") {
        const origin = originOf(row.url);
        if (origin) {
          if (excSet.has(origin)) {
            allowKind = "";
          } else {
            allowKind = "origin";
            allowValue = origin;
          }
        }
      }
      appendDetailRow(el, {
        cls: isBad ? "bad" : null,
        label: title,
        badgeValue: badge,
        allowed: allowKind === "",
        allowKind: allowKind === "" ? null : allowKind,
        allowValue,
        sourceUrl: row.type === "script" ? row.url : null,
      });
    }
    return;
  }
  for (const row of rows) {
    const full = row.url ?? row.snippet ?? row.reason ?? "(unknown)";
    const badge = row.count > 1 ? `×${row.count}` : "";
    let allowKind = null;
    let allowValue = null;
    if (row.action) {
      const alreadyAllowed =
        row.action.kind === "origin" ? false : allowedSet.has(row.action.value);
      if (alreadyAllowed) {
        allowKind = "";
      } else {
        allowKind = row.action.kind;
        allowValue = row.action.value;
      }
    }
    // Inline rows (script/handler) expose their raw body for preview; external
    // script rows (first/third) offer a "View" that fetches the source.
    const isInline = view === "inline-script" || view === "inline-handler";
    appendDetailRow(el, {
      cls: null,
      label: full,
      badgeValue: badge,
      allowed: allowKind === "",
      allowKind: allowKind === "" ? null : allowKind,
      allowValue,
      source: isInline ? row.raw ?? null : null,
      sourceUrl: row.url && !isInline ? row.url : null,
    });
  }
}

/** @param {string} url @returns {string | null} scheme://host[:port] */
function originOf(url) {
  try {
    const u = new URL(url);
    return /^https?:$/.test(u.protocol) ? u.origin : null;
  } catch {
    return null;
  }
}

let currentView = null;
let lastEvents = [];
let lastNetEvents = [];
let lastInlineAllows = { scripts: [], attrs: [] };
let lastExceptions = [];

const allEvents = () => [...lastEvents, ...lastNetEvents];

document.getElementById("inventory").addEventListener("click", (event) => {
  const view = event.target?.dataset?.view;
  if (!view) return;
  currentView = currentView === view ? null : view;
  renderDetail(currentView, allEvents(), lastInlineAllows, lastExceptions);
});

document.getElementById("detail").addEventListener("click", async (event) => {
  // View-source button: fetch + display an external script body.
  const viewBtn = event.target.closest("button[data-view-source]");
  if (viewBtn) {
    await showSource(null, viewBtn.dataset.viewSource);
    return;
  }
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
  list.replaceChildren();
  if (!Array.isArray(events) || events.length === 0) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "nothing recorded yet";
    list.append(li);
    return;
  }
  const recent = events.slice(-8).reverse();
  for (const e of recent) {
    const what =
      e.kind === "csp-violation"
        ? e.reason ?? "violation"
        : `${KIND_LABELS[e.kind] ?? e.kind}${e.url ? `: ${e.url}` : ""}`;
    const li = document.createElement("li");
    if (e.action === "blocked") li.className = "blocked";
    li.title = what;
    const time = document.createElement("time");
    time.textContent = fmtTime(e.ts);
    const rawText = document.createTextNode(" ");
    const line = document.createElement("span");
    line.className = "line";
    line.textContent = what;
    li.append(time, rawText, line);
    list.append(li);
  }
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
  requestAnimationFrame(() => {
    renderInventory(res.stats);
    renderActivity(lastEvents);
    renderDetail(currentView, allEvents(), lastInlineAllows, lastExceptions);
  });
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
