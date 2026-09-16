import {
  composePolicyFromFlags,
} from "./lib/policies.js";
import {
  FLAG_KEYS,
  makeFlags,
  nearestPreset,
  enforceInlineBase,
} from "./lib/flags.js";
import { normalizeHostForRule } from "./lib/host.js";
import { canonicalAllowKey, normalizeInlineHash } from "./lib/allow.js";
import { beautify } from "./lib/beautify.js";
import { highlight } from "./lib/highlight.js";

const els = {
  origin: document.getElementById("origin"),
  summary: document.getElementById("summary"),
  rule: document.getElementById("rule"),
  reload: document.getElementById("reload"),
  modeLabel: document.getElementById("mode-label"),
  modeDetail: document.getElementById("mode-detail"),
  pause: document.getElementById("pause"),
  pauseState: document.getElementById("pause-state"),
  allowTab: document.getElementById("allow-tab"),
  excForm: document.getElementById("exc-form"),
  excInput: document.getElementById("exc-input"),
  excList: document.getElementById("exc-list"),
  allowHashForm: document.getElementById("allow-hash-form"),
  allowHashInput: document.getElementById("allow-hash-input"),
  allowHashKind: document.getElementById("allow-hash-kind"),
  allowHashList: document.getElementById("allow-hash-list"),
  exportBtn: document.getElementById("export-btn"),
  importBtn: document.getElementById("import-btn"),
  importFile: document.getElementById("import-file"),
  copyCsp: document.getElementById("copy-csp"),
  sourceView: document.getElementById("source-view"),
  sourceCode: document.getElementById("source-code"),
  relax: () => document.querySelectorAll("[data-pause-min]"),
  profileBadge: document.getElementById("profile-badge"),
  botWarning: document.getElementById("bot-warning"),
  flagControls: document.getElementById("flag-controls"),
  removalHint: document.getElementById("removal-hint"),
  resetSite: document.getElementById("reset-site"),
  resetTab: document.getElementById("reset-tab"),
  inventory: document.getElementById("inventory"),
  detail: document.getElementById("detail"),
  activity: document.getElementById("activity"),
  allowNote: document.getElementById("allow-note"),
  allowNoteText: document.getElementById("allow-note-text"),
  allowNoteReload: document.getElementById("allow-note-reload"),
  allowNoteDismiss: document.getElementById("allow-note-dismiss"),
  debugBar: document.getElementById("debug-bar"),
  debugCopy: document.getElementById("debug-copy"),
};

/** @type {string | null} */
let host = null;
/** @type {number | null} */
let tabId = null;

// ---------------------------------------------------------------------------
// flag model (11 flags = source of truth; presets are named combinations)
// ---------------------------------------------------------------------------

const FLAG_LABELS = {
  blockClassicScripts: "Block classic <script>",
  blockModuleScripts: "Block module scripts",
  blockExternalScripts: "Block all external scripts",
  blockThirdPartyScripts: "Block third-party scripts",
  blockInlineEventHandlers: "Block inline event handlers (on*)",
  blockJavascriptUrls: "Block javascript: URLs",
  blockImportMaps: "Remove import maps",
  blockSpeculationRules: "Remove speculation rules",
  blockJsonLd: "Remove JSON-LD data",
  blockJsonData: "Remove JSON data blocks",
  reportBlockedContent: "Report blocked content to activity",
};

/** Short names for the condensed mode readout deltas. */
const SHORT_FLAG = {
  blockClassicScripts: "classic scripts",
  blockModuleScripts: "module scripts",
  blockExternalScripts: "external scripts",
  blockThirdPartyScripts: "3rd-party",
  blockInlineEventHandlers: "on* handlers",
  blockJavascriptUrls: "javascript: URLs",
  blockImportMaps: "import maps",
  blockSpeculationRules: "spec rules",
  blockJsonLd: "JSON-LD",
  blockJsonData: "JSON-data",
  reportBlockedContent: "report",
};

/** Human names for the derived preset readout. */
const MODE_LABELS = {
  observe: "Observe",
  firstPartyOnly: "First-party only",
  noScripts: "No scripts",
};

/** Flags that make the DOM layer remove non-executing containers. */
const DOM_REMOVAL_KEYS = [
  "blockImportMaps",
  "blockSpeculationRules",
  "blockJsonLd",
  "blockJsonData",
];

/**
 * Curated anti-bot / sensor-management hosts (heuristic, not exhaustive).
 * Used for the "hardening may read as automation" warning and the net-view
 * sensor badge — a hint, never policy.
 */
const BOT_DETECTOR_SUFFIXES = [
  "datadome.co",
  "datadome.com",
  "perimeterx.com",
  "px-cdn.net",
  "px-cloud.net",
  "incapsula.com",
  "imperva.com",
  "shape.security",
  "akamai.com",
];

/** @param {string} host @returns {boolean} canonical host or its subdomain matches */
function isBotDetectorHost(host) {
  const h = normalizeHostForRule(host);
  return BOT_DETECTOR_SUFFIXES.some((s) => h === s || h.endsWith(`.${s}`));
}

/**
 * Live count for a flag, mapped from the per-tab stats. Boundaries with no
 * direct counter (module vs classic scripts) render no badge.
 * @param {string} key
 * @param {object | null} stats
 * @returns {number | null}
 */
function flagCountFor(key, stats) {
  if (!stats) return null;
  switch (key) {
    case "blockClassicScripts":
      return stats.inlineScripts ?? 0;
    case "blockModuleScripts":
      return null;
    case "blockExternalScripts":
      return (stats.scriptsFirstParty ?? 0) + (stats.scriptsThirdParty ?? 0);
    case "blockThirdPartyScripts":
      return stats.scriptsThirdParty ?? 0;
    case "blockInlineEventHandlers":
      return stats.inlineHandlers ?? 0;
    case "blockJavascriptUrls":
      return stats.javascriptUrls ?? 0;
    case "blockImportMaps":
      return stats.importMaps ?? 0;
    case "blockSpeculationRules":
      return stats.specRules ?? 0;
    case "blockJsonLd":
      return stats.jsonLd ?? 0;
    case "blockJsonData":
      return stats.jsonData ?? 0;
    case "reportBlockedContent":
      return stats.blocked ?? 0;
    default:
      return null;
  }
}

function renderFlagControls(flags, stats) {
  els.flagControls.replaceChildren();
  for (const key of FLAG_KEYS) {
    const label = document.createElement("label");
    label.className = "flag-row";
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = Boolean(flags[key]);
    cb.dataset.flag = key;
    const name = document.createElement("span");
    name.className = "flag-name";
    name.textContent = FLAG_LABELS[key] ?? key;
    label.append(cb, name);
    const count = flagCountFor(key, stats);
    if (count != null) {
      const badge = document.createElement("span");
      badge.className = `flag-count${count > 0 ? " hot" : ""}`;
      badge.textContent = count;
      label.append(badge);
    }
    els.flagControls.append(label);
  }
}

function checkedFlags() {
  const out = {};
  for (const input of els.flagControls.querySelectorAll("input[data-flag]")) {
    out[input.dataset.flag] = input.checked;
  }
  return out;
}

function setFlagError(message, ref) {
  if (message) {
    let p = document.getElementById("flag-error");
    if (!p) {
      p = document.createElement("p");
      p.id = "flag-error";
      p.className = "hint warn";
      els.flagControls.before(p);
    }
    p.textContent = message;
  } else {
    document.getElementById("flag-error")?.remove();
  }
  ref?.scrollIntoView?.({ block: "nearest" });
}

function setFlagNote(message) {
  let p = document.getElementById("flag-note");
  if (!p) {
    p = document.createElement("p");
    p.id = "flag-note";
    p.className = "hint";
    els.flagControls.before(p);
  }
  p.textContent = message;
}

function showNote(message) {
  setFlagNote(message);
}

function clearNote() {
  document.getElementById("flag-note")?.remove();
}

function updateRemovalHint(flags) {
  const active = DOM_REMOVAL_KEYS.filter((key) => flags[key]);
  els.removalHint.textContent = active.length
    ? `Container removal active: ${active.map((k) => FLAG_LABELS[k]).join(", ")}. ` +
      "Removal is visible to page scripts (a MutationObserver sees nodes vanish) — " +
      "a site that screens for automation can detect it."
    : "No containers are being removed for this profile.";
}

function updateBotWarning(flags) {
  const hardening =
    flags.blockExternalScripts ||
    flags.blockThirdPartyScripts ||
    flags.blockClassicScripts;
  const bot = host !== null && isBotDetectorHost(host);
  els.botWarning.hidden = !(hardening && bot);
  if (hardening && bot) {
    els.botWarning.textContent =
      `${host} runs a bot-management / sensor suite. Enforcing here may be ` +
      "read as automation. Prefer a scoped profile (e.g. remove JSON-LD only) " +
      "or observe-only for this site.";
  }
}

/**
 * Truthful one-liner for the ACTUAL flag bundle — never the neighbor preset's
 * canned line. An exact preset shows its own summary; custom bundles describe
 * the enforced posture so the readout can't claim "all allowed" while the CSP
 * rule is active.
 */
function summaryForFlags(flags) {
  if (flags.blockExternalScripts) {
    return "External and inline scripts blocked; only allowed hashes/origins run.";
  }
  if (flags.blockThirdPartyScripts) {
    return "Same-origin scripts only; inline JS and third-party scripts are blocked.";
  }
  if (flags.blockClassicScripts && flags.blockModuleScripts) {
    return "Inline scripts blocked; external scripts are allowed.";
  }
  return "All scripts allowed. Activity is being observed.";
}

/**
 * Derived mode readout: flags are the source of truth; the mode label is just
 * a name for a combination. Exact preset → its name and "matches preset" —
 * custom → "Custom" plus the nearest-preset deltas, in ± notation.
 */
function renderModeReadout(flags) {
  const result = nearestPreset(flags);
  const presetMode = result?.mode;
  const exact = result && result.deltas.length === 0;
  els.modeLabel.textContent = exact
    ? MODE_LABELS[presetMode] ?? presetMode
    : "Custom";
  els.summary.textContent = summaryForFlags(flags);
  els.profileBadge.textContent = "";
  if (exact) {
    els.modeDetail.textContent = "matches preset";
  } else {
    const base = presetMode ? `${MODE_LABELS[presetMode] ?? presetMode} + ` : "";
    const parts = (result?.deltas ?? []).map(
      ({ key, on }) => `${on ? "+" : "\u2212"}${SHORT_FLAG[key] ?? key}`,
    );
    els.modeDetail.textContent =
      parts.length > 0
        ? parts.join(" · ")
        : "no presets apply";
    els.profileBadge.textContent =
      `Custom profile — closest to ${base.slice(0, -3)}; toggles below reflect this exact combination.`;
  }
}

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

/** Shows the CSP + DOM-filter arms the extension enforces. */
function renderRuleStatus({ csp, domFilters, autoEnabled } = {}) {
  const parts = [];
  parts.push(
    csp
      ? `CSP rule: ACTIVE \u2192 ${csp}`
      : "CSP rule: none (Observe or not applied)",
  );
  if (domFilters && domFilters.length > 0) {
    parts.push(`DOM strip: ${domFilters.join(", ")}`);
  }
  if (autoEnabled && autoEnabled.length > 0) {
    parts.push(`auto-enabled: ${autoEnabled.join(", ")}`);
  }
  els.rule.textContent = parts.join(" | ");
}

function fmtClock(ts) {
  const d = new Date(ts);
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}`;
}

function fmtTime(ts) {
  const d = new Date(ts);
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

// ---------------------------------------------------------------------------
// pause (host-scoped, alarm-driven in the SW; live countdown here)
// ---------------------------------------------------------------------------

let lastPausedUntil = null;
let pauseTicker = null;

function renderPaused(pausedUntil) {
  lastPausedUntil = pausedUntil;
  const active = typeof pausedUntil === "number" && pausedUntil > Date.now();
  els.pause.classList.toggle("active", active);
  els.pause.textContent = active ? "Resume now" : "Pause";
  for (const btn of els.relax()) btn.disabled = active;
  if (active) {
    const secs = Math.max(0, Math.ceil((pausedUntil - Date.now()) / 1000));
    els.pauseState.textContent = `Policy paused \u2014 ${Math.floor(secs / 60)}m ${String(
      secs % 60,
    ).padStart(2, "0")}s remaining`;
    if (pauseTicker === null) {
      pauseTicker = setInterval(() => {
        const until = lastPausedUntil;
        if (typeof until === "number" && until <= Date.now()) {
          clearInterval(pauseTicker);
          pauseTicker = null;
          refreshUi().catch(() => {});
          return;
        }
        renderPaused(until);
      }, 1000);
    }
  } else {
    if (pauseTicker !== null) {
      clearInterval(pauseTicker);
      pauseTicker = null;
    }
    els.pauseState.textContent = "";
  }
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

/**
 * Computes the CSP sha256 token for a script's source text: "sha256-" + the
 * base64 digest over the exact bytes provided, matching the token CSP would
 * use to allow an inline script whose source equals `text`.
 * @param {string} text
 * @returns {Promise<string>}
 */
async function sha256Token(text) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  const bin = String.fromCharCode(...new Uint8Array(digest));
  return `sha256-${btoa(bin)}`;
}

/** Lists per-host allowed inline script/handler hashes with a remove affordance. */
function renderInlineAllows(inlineAllows) {
  els.allowHashList.replaceChildren();
  const entries = [
    ...(inlineAllows?.scripts ?? []).map((hash) => ({ kind: "script", hash })),
    ...(inlineAllows?.attrs ?? []).map((hash) => ({ kind: "attr", hash })),
  ];
  if (entries.length === 0) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "no inline scripts allowed by hash yet";
    els.allowHashList.append(li);
    return;
  }
  for (const { kind, hash } of entries) {
    const li = document.createElement("li");
    const code = document.createElement("code");
    code.className = "hash";
    code.title = "sha256 token (click to copy)";
    code.textContent = hash;
    code.addEventListener("click", () => {
      navigator.clipboard?.writeText?.(hash);
    });
    li.append(code);
    const kindSpan = document.createElement("span");
    kindSpan.className = "hash-kind";
    kindSpan.textContent = kind;
    li.append(kindSpan);
    const btn = document.createElement("button");
    btn.type = "button";
    btn.dataset.removeHash = hash;
    btn.dataset.removeKind = kind;
    btn.title = "Remove this hash allowance";
    btn.textContent = "×";
    li.append(btn);
    els.allowHashList.append(li);
  }
}

// ---------------------------------------------------------------------------
// trace / diagnostics (gated off unless Alt is held / #debug hash; always
// records a short bounded tail for the "Copy diagnostics" dump)
// ---------------------------------------------------------------------------

const MAX_TRACE = 80;
const traceLog = [];
let debugOn = location.hash === "#debug";
let lastStateSnapshot = null;

/** sendMessage wrapper: records outcome + latency, surfaces errors loudly. */
async function traceSend(message) {
  const start = Date.now();
  const rec = {
    t: fmtTime(start),
    type: message?.type ?? "?",
    ms: 0,
    ok: false,
    detail: null,
  };
  traceLog.push(rec);
  if (traceLog.length > MAX_TRACE) traceLog.shift();
  try {
    const res = await chrome.runtime.sendMessage(message);
    rec.ms = Date.now() - start;
    rec.ok = !(res && res.error);
    rec.detail = res?.error ? String(res.error) : null;
    if (debugOn) {
      console.log(
        `[trace] ${rec.type} \u2192 ${rec.ok ? "ok" : "FAIL"} (${rec.ms}ms)` +
          (rec.detail ? ` ${rec.detail}` : ""),
      );
    }
    return res;
  } catch (err) {
    rec.ms = Date.now() - start;
    rec.ok = false;
    rec.detail = String(err?.message ?? err);
    if (debugOn) {
      console.error(`[trace] ${rec.type} \u2192 THREW (${rec.ms}ms) ${rec.detail}`);
    }
    throw err;
  }
}

function enableDebug() {
  debugOn = true;
  els.debugBar.hidden = false;
}

function copyDiagnostics() {
  const body = JSON.stringify(
    { host, tabId, state: lastStateSnapshot, trace: traceLog.slice(-60) },
    null,
    2,
  );
  navigator.clipboard
    ?.writeText?.(body)
    .then(() => showAllowNote("Diagnostics copied to clipboard.", false))
    .catch(() => showAllowNote("Clipboard unavailable.", false));
}

function showAllowNote(text, hasReload) {
  els.allowNote.hidden = false;
  els.allowNoteText.textContent = text;
  els.allowNoteReload.hidden = !hasReload;
}

function hideAllowNote() {
  els.allowNote.hidden = true;
}

window.addEventListener("error", (event) => {
  traceLog.push({
    t: fmtTime(Date.now()),
    type: "window.error",
    ok: false,
    detail: String(event?.message ?? event),
  });
  if (debugOn) showAllowNote(`JS error: ${event?.message ?? ""}`, false);
});

window.addEventListener("unhandledrejection", (event) => {
  traceLog.push({
    t: fmtTime(Date.now()),
    type: "unhandledrejection",
    ok: false,
    detail: String(event?.reason?.message ?? event?.reason),
  });
  if (debugOn) {
    showAllowNote(
      `Unhandled rejection: ${event?.reason?.message ?? ""}`,
      false,
    );
  }
});

// ---------------------------------------------------------------------------
// state hydration
// ---------------------------------------------------------------------------

let lastFlags = null;
let lastStats = null;

async function refreshUi() {
  if (!host) return;
  const state = await traceSend({ type: "get-state", host, tabId });
  if (state?.error) return;
  lastStateSnapshot = state;
  lastFlags = state.flags ?? null;
  const exceptions = state.exceptions ?? [];
  const containerAllows = state.containerAllows ?? [];
  lastInlineAllows = state.inlineAllows ?? { scripts: [], attrs: [] };
  lastExceptions = exceptions;
  lastContainerAllows = containerAllows;
  renderModeReadout(state.flags);
  renderRuleStatus({ csp: state.activeCsp, domFilters: state.domFilters, autoEnabled: state.autoEnabled });
  renderFlagControls(state.flags, lastStats);
  updateRemovalHint(state.flags);
  updateBotWarning(state.flags);
  renderPaused(state.pausedUntil);
  renderTabOverride(Boolean(state.tabOverride));
  renderExceptions(exceptions);
  renderInlineAllows(lastInlineAllows);
  await loadActivity();
}

// ---------------------------------------------------------------------------
// event wiring
// ---------------------------------------------------------------------------

// Per-category toggles. Some enforced postures — e.g. blocking external
// scripts while inline stays allowed — would need 'unsafe-inline', which the
// engine never emits (INLINE INVARIANT). Instead of rejecting those toggles,
// the popup auto-enables the inline-blocking pair (classic + module) that
// makes the bundle expressible and tells the user what it did.
els.flagControls.addEventListener("change", async (event) => {
  const cb = event.target.closest("input[data-flag]");
  if (!cb || !host) return;
  const raw = checkedFlags();
  const { flags: candidate, autoEnabled } = enforceInlineBase(makeFlags(raw));
  try {
    composePolicyFromFlags(candidate);
  } catch (err) {
    // Still unexpressible after the inline pair is forced on.
    cb.checked = !cb.checked;
    setFlagError(
      `Rejected: cannot express this combination without allowing inline ` +
        `scripts ('unsafe-inline'). Cause: ${String(err.message ?? err)}`,
      cb,
    );
    return;
  }
  setFlagError(null);
  if (autoEnabled.length > 0) {
    const names = autoEnabled.map((k) => FLAG_LABELS[k]).join(" + ");
    showNote(
      `To enforce this securely, inline scripts must also be blocked — ` +
        `${names} were ${autoEnabled.length === 1 ? "enabled" : "enabled"} for you ` +
        `(the CSP layer never emits 'unsafe-inline'). This may stop some site ` +
        `features from working; you can still Allow a specific script by sha256 hash.`,
    );
  } else {
    clearNote();
  }
  const res = await traceSend({ type: "set-policy", host, flags: candidate });
  if (res?.error) {
    setFlagError(`Error: ${res.error}`, cb);
    return;
  }
  await refreshUi();
});

els.reload.addEventListener("click", async () => {
  if (tabId !== null) await chrome.tabs.reload(tabId);
  window.close();
});

els.pause.addEventListener("click", async () => {
  if (!host) return;
  const active =
    els.pause.classList.contains("active") ||
    (await traceSend({ type: "get-state", host }))?.pausedUntil != null;
  await traceSend(
    active ? { type: "resume-host", host } : { type: "pause-host", host },
  );
  await refreshUi();
});

// Relax presets: pause for N minutes (host-scoped, auto-resume).
for (const btn of els.relax()) {
  btn.addEventListener("click", async () => {
    if (!host) return;
    const ms = Number(btn.dataset.pauseMin) * 60 * 1000;
    await traceSend({ type: "pause-host", host, ms });
    await refreshUi();
  });
}

// Copy a deployable CSP header for this host (SW-computed activeCsp).
els.copyCsp.addEventListener("click", async () => {
  if (!host) return;
  const state = await traceSend({ type: "get-state", host, tabId });
  if (state?.error) {
    els.pauseState.textContent = state.error;
    return;
  }
  if (state.activeCsp == null) {
    els.pauseState.textContent = "No CSP to copy (Observe mode)";
    return;
  }
  const header = `Content-Security-Policy: ${state.activeCsp}`;
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
  const res = await traceSend({ type: "toggle-tab-override", tabId });
  if (res?.active) await chrome.tabs.reload(tabId);
  await refreshUi();
});

els.excForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!host) return;
  const origin = els.excInput.value.trim();
  if (!origin) return;
  const res = await traceSend({ type: "add-exception", host, origin });
  if (res?.error) {
    showAllowNote(`Error: ${res.error}`, false);
    return;
  }
  els.excInput.value = "";
  await refreshUi();
});

els.excList.addEventListener("click", async (event) => {
  const origin = event.target?.dataset?.origin;
  if (!origin || !host) return;
  await traceSend({ type: "remove-exception", host, origin });
  await refreshUi();
});

// Allow an inline script/handler by hash: accepts an existing "sha256-…"
// token verbatim, or treats the pasted text as script source to hash (computed
// client-side with WebCrypto, so no source ever leaves the popup).
els.allowHashForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!host) return;
  const raw = els.allowHashInput.value.trim();
  if (!raw) return;
  const kind = els.allowHashKind.value === "attr" ? "attr" : "script";
  let hash;
  try {
    hash = normalizeInlineHash(raw);
  } catch {
    try {
      hash = await sha256Token(raw);
    } catch (err) {
      showAllowNote(`Could not hash input: ${err.message}`, false);
      return;
    }
  }
  const res = await traceSend({ type: "add-inline-allow", host, kind, hash });
  if (res?.error) {
    showAllowNote(`Allow failed: ${res.error}`, false);
    return;
  }
  els.allowHashInput.value = "";
  showAllowNote(`${kind} hash allowed \u2014 reload to apply?`, true);
  await refreshUi();
});

els.allowHashList.addEventListener("click", async (event) => {
  const btn = event.target.closest("button[data-remove-hash]");
  if (!btn || !host) return;
  const res = await traceSend({
    type: "remove-inline-allow",
    host,
    kind: btn.dataset.removeKind,
    hash: btn.dataset.removeHash,
  });
  if (res?.error) {
    showAllowNote(`Remove failed: ${res.error}`, false);
    return;
  }
  await refreshUi();
});

els.exportBtn.addEventListener("click", async () => {
  const data = await traceSend({ type: "export-settings" });
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
    const res = await traceSend({ type: "import-settings", data });
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
// allow note (inline feedback + optional reload-to-apply)
// ---------------------------------------------------------------------------

els.allowNoteReload.addEventListener("click", async () => {
  hideAllowNote();
  if (tabId !== null) await chrome.tabs.reload(tabId);
  await refreshUi();
});

els.allowNoteDismiss.addEventListener("click", hideAllowNote);

// ---------------------------------------------------------------------------
// reset controls (site reset is two-click armed; tab clear is one-shot)
// ---------------------------------------------------------------------------

let resetArmed = false;
let resetTimer = null;

function disarmReset() {
  resetArmed = false;
  if (resetTimer !== null) {
    clearTimeout(resetTimer);
    resetTimer = null;
  }
  els.resetSite.classList.remove("armed");
  els.resetSite.textContent = "Reset this site";
}

async function doResetSite() {
  const res = await traceSend({ type: "clear-site", host });
  if (res?.error) {
    showAllowNote(`Reset failed: ${res.error}`, false);
    return;
  }
  els.pauseState.textContent = "Site reset to default (Observe).";
  hideAllowNote();
  if (tabId !== null) await chrome.tabs.reload(tabId);
  await refreshUi();
}

els.resetSite.addEventListener("click", () => {
  if (!host) return;
  if (!resetArmed) {
    resetArmed = true;
    resetTimer = setTimeout(disarmReset, 3000);
    els.resetSite.classList.add("armed");
    els.resetSite.textContent = "Reset now?";
    return;
  }
  disarmReset();
  void doResetSite();
});

els.resetTab.addEventListener("click", async () => {
  if (tabId === null) return;
  const res = await traceSend({ type: "clear-tab", tabId });
  if (res?.error) {
    showAllowNote(`Clear failed: ${res.error}`, false);
    return;
  }
  await refreshUi();
});

// ---------------------------------------------------------------------------
// live updates: the SW broadcasts a fire-and-forget state-changed after any
// policy/pause/override transition outside this popup's own action flow.
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === "state-changed" && host) refreshUi().catch(() => {});
});

// Debug: press and hold Alt inside the popup (or open with #debug) to expose
// the trace bar + clipboard diagnostics for a hard-to-describe bug.
document.addEventListener("keydown", (event) => {
  if (event.key === "Alt" && !debugOn) enableDebug();
});

els.debugCopy.addEventListener("click", copyDiagnostics);

// ---------------------------------------------------------------------------
// inventory / activity rendering (ported from original; minor improvements)
// ---------------------------------------------------------------------------

const KIND_LABELS = {
  script: "script",
  "inline-script": "inline <script>",
  "inline-handler": "inline handler",
  "csp-violation": "CSP block",
  "script-element": "container",
  "javascript-url": "javascript: URL",
};

function renderInventory(stats) {
  const el = els.inventory;
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
    ["removed", "removed", stats.removed],
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
      btn.className = `count${label === "blocked" || label === "removed" ? " hot" : ""}`;
      const b = document.createElement("b");
      b.textContent = n;
      btn.append(b, label);
      el.append(btn);
    }
  }
}

function detailRows(view, events) {
  const matchers = {
    first: (e) => e.kind === "script" && e.party === "first",
    third: (e) => e.kind === "script" && e.party === "third",
    "inline-script": (e) => e.kind === "inline-script",
    "inline-handler": (e) => e.kind === "inline-handler",
    "csp-violation": (e) => e.kind === "csp-violation",
    removed: (e) => e.kind === "script-element" && e.action === "removed",
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
      action = { kind: "script", value: canonicalAllowKey(row.hash) };
    } else if (view === "inline-handler" && row.hash) {
      action = { kind: "attr", value: canonicalAllowKey(row.hash) };
    } else if (view === "removed" && row.digest) {
      action = { kind: "container", value: row.digest };
    }
    return { ...row, action };
  });
}

function appendDetailRow(
  el,
  { cls, label, badgeValue, allowed, allowKind, allowValue, source, sourceUrl, hashToken },
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
  if (hashToken) {
    const code = document.createElement("code");
    code.className = "hash";
    code.title = "sha256 token (click to copy)";
    code.textContent = hashToken;
    code.addEventListener("click", () => {
      navigator.clipboard?.writeText?.(hashToken);
    });
    li.append(code);
  }
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

const FETCH_TIMEOUT_MS = 10_000;
const FETCH_LIMIT_BYTES = 1024 * 1024;
const RENDER_LIMIT_BYTES = 200 * 1024;

async function showSource(rawText, url) {
  let text = rawText;
  if (text == null && url) {
    els.sourceCode.textContent = "loading\u2026";
    let foreign = false;
    try {
      const u = new URL(url);
      foreign = normalizeHostForRule(u.hostname) !== host;
    } catch {
      foreign = false;
    }
    if (foreign && !confirm(`Fetch script source from ${originOf(url)}?`)) {
      els.sourceCode.textContent = "Fetch cancelled by user.";
      els.sourceView.hidden = false;
      return;
    }
    try {
      const resp = await fetch(url, {
        credentials: "omit",
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const buf = await resp.arrayBuffer();
      const truncated = buf.byteLength > FETCH_LIMIT_BYTES;
      text = new TextDecoder().decode(
        truncated ? buf.slice(0, FETCH_LIMIT_BYTES) : buf,
      );
      if (truncated) {
        text += `\n\n[truncated at ${(FETCH_LIMIT_BYTES / 1024).toFixed(0)} KB — ` +
          `${((buf.byteLength - FETCH_LIMIT_BYTES) / 1024).toFixed(0)} KB omitted]`;
      }
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
  // When text is large, skip highlight/beautify (DOM flood + layout thrash)
  // and render plain textContent for reliable, fast display.
  if (text.length > RENDER_LIMIT_BYTES) {
    els.sourceCode.replaceChildren();
    els.sourceCode.textContent =
      text + "\n\n[plain view — syntax highlight skipped for large window]";
  } else {
    const fmt = beautify(text) || text;
    els.sourceCode.replaceChildren();
    els.sourceCode.append(...renderCodeSpans(fmt));
  }
  els.sourceView.hidden = false;
  if (url) {
    const label = document.createElement("div");
    label.className = "src-url";
    label.textContent = url;
    els.sourceCode.before(label);
  }
  els.sourceView.open = true;
}

function renderDetail(view, events, inlineAllows, exceptions) {
  const el = els.detail;
  const allowedSet = new Set([
    ...(inlineAllows?.scripts ?? []),
    ...(inlineAllows?.attrs ?? []),
    ...lastContainerAllows,
  ]);
  const excSet = new Set(exceptions ?? []);
  el.replaceChildren();
  if (!view || !Array.isArray(events)) return;
  const rows = detailRows(view, events);
  if (rows.length === 0) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "nothing in this category";
    el.append(li);
    return;
  }
  if (view === "net") {
    for (const row of rows) {
      const badge =
        `${row.type ?? ""}${row.status ? ` \u2192 ${row.status}` : " \u2192 \u2026"}` +
        (row.count > 1 ? ` \u00d7${row.count}` : "") +
        (isBotDetectorOrigin(row.url) ? " \u2192 sensor" : "");
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
    const badge = row.count > 1 ? `\u00d7${row.count}` : "";
    let allowKind = null;
    let allowValue = null;
    if (row.action) {
      const alreadyAllowed =
        row.action.kind === "origin"
          ? false
          : allowedSet.has(canonicalAllowKey(row.action.value));
      if (alreadyAllowed) {
        allowKind = "";
      } else {
        allowKind = row.action.kind;
        allowValue = row.action.value;
      }
    }
    const isInline = view === "inline-script" || view === "inline-handler";
    appendDetailRow(el, {
      cls: null,
      label: full,
      badgeValue: badge,
      allowed: allowKind === "",
      allowKind: allowKind === "" ? null : allowKind,
      allowValue,
      source:
        view === "removed"
          ? row.snippet ?? null
          : isInline
            ? row.raw ?? null
            : null,
      sourceUrl: row.url && !isInline ? row.url : null,
      hashToken: isInline && row.hash ? row.hash : null,
    });
  }
}

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
let lastContainerAllows = [];
let lastExceptions = [];

const allEvents = () => [...lastEvents, ...lastNetEvents];

function isBotDetectorOrigin(url) {
  try {
    return isBotDetectorHost(new URL(url).hostname);
  } catch {
    return false;
  }
}

els.inventory.addEventListener("click", (event) => {
  const view = event.target?.dataset?.view;
  if (!view) return;
  currentView = currentView === view ? null : view;
  renderDetail(currentView, allEvents(), lastInlineAllows, lastExceptions);
});

els.detail.addEventListener("click", async (event) => {
  const viewBtn = event.target.closest("button[data-view-source]");
  if (viewBtn) {
    await showSource(null, viewBtn.dataset.viewSource);
    return;
  }
  const btn = event.target.closest("button[data-kind]");
  if (btn) {
    if (!host) return;
    const { kind, value } = btn.dataset;
    const message =
      kind === "origin"
        ? { type: "add-exception", host, origin: value }
        : kind === "container"
          ? { type: "add-container-allow", host, digest: value }
          : { type: "add-inline-allow", host, kind, hash: value };
    const res = await traceSend(message);
    if (res?.error) {
      showAllowNote(`Allow failed: ${res.error}`, false);
      return;
    }
    // Allow was saved — prompt to reload.
    showAllowNote(`${kind} allowed — reload to apply?`, true);
    await refreshUi();
    return;
  }
  const li = event.target.closest("li");
  if (li) li.classList.toggle("expanded");
});

els.activity.addEventListener("click", (event) => {
  if (event.target.closest("button")) return;
  const li = event.target.closest("li");
  if (li) li.classList.toggle("expanded");
});

function renderActivity(events) {
  els.activity.replaceChildren();
  if (!Array.isArray(events) || events.length === 0) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "nothing recorded yet";
    els.activity.append(li);
    return;
  }
  const recent = events.slice(-8).reverse();
  for (const e of recent) {
    const what =
      e.kind === "csp-violation"
        ? e.reason ?? "violation"
        : e.kind === "script-element"
          ? `${KIND_LABELS[e.kind] ?? e.kind} (${e.category ?? "?"})${
              e.action === "removed" ? " \u2014 removed" : ""
            }: ${e.snippet ?? e.url ?? ""}`
          : e.kind === "inline-script" || e.kind === "inline-handler"
            ? `${KIND_LABELS[e.kind] ?? e.kind}${
                e.snippet ? `: ${e.snippet}` : ""
              }`
            : `${KIND_LABELS[e.kind] ?? e.kind}${e.url ? `: ${e.url}` : ""}`;
    const li = document.createElement("li");
    if (e.action === "blocked" || e.action === "removed") li.className = e.action;
    li.title = what;
    const time = document.createElement("time");
    time.textContent = fmtTime(e.ts);
    const rawText = document.createTextNode(" ");
    const line = document.createElement("span");
    line.className = "line";
    line.textContent = what;
    li.append(time, rawText, line);
    if (e.hash) {
      const code = document.createElement("code");
      code.className = "hash";
      code.title = "sha256 token (click to copy)";
      code.textContent = ` [${e.hash}]`;
      code.addEventListener("click", () => {
        navigator.clipboard?.writeText?.(e.hash);
      });
      li.append(code);
    }
    els.activity.append(li);
  }
}

async function loadActivity() {
  if (tabId === null) return;
  const res = await traceSend({ type: "get-activity", tabId });
  if (res?.error) return;
  lastEvents = res.events ?? [];
  lastNetEvents = res.netEvents ?? [];
  lastStats = res.stats ?? null;
  requestAnimationFrame(() => {
    renderInventory(res.stats);
    renderActivity(lastEvents);
    if (lastFlags) renderFlagControls(lastFlags, lastStats);
    renderDetail(currentView, allEvents(), lastInlineAllows, lastExceptions);
  });
}

// ---------------------------------------------------------------------------
// boot
// ---------------------------------------------------------------------------

if (debugOn) enableDebug();

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