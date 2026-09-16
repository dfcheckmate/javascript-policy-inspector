import { test } from "node:test";
import assert from "node:assert/strict";

// ---------------------------------------------------------------------------
// Minimal chrome mock — in-memory areas + capturable listener registration.
// ---------------------------------------------------------------------------

function memoryArea(initial = {}) {
  const store = { ...initial };
  return {
    get: async (keys) => {
      if (keys == null) return { ...store };
      const list = typeof keys === "string" ? [keys] : Array.isArray(keys) ? keys : [];
      const out = {};
      for (const k of list) if (k in store) out[k] = structuredClone(store[k]);
      return out;
    },
    set: async (obj) => {
      for (const [k, v] of Object.entries(obj ?? {})) store[k] = v;
    },
    remove: async (keys) => {
      const list = typeof keys === "string" ? [keys] : Array.isArray(keys) ? keys : [];
      for (const k of list) delete store[k];
    },
    _dump: () => ({ ...store }),
  };
}

function listenerStore() {
  const callbacks = [];
  return {
    addListener: (fn) => callbacks.push(fn),
    get callbacks() {
      return callbacks;
    },
  };
}

const calls = [];

function mockChrome() {
  const alarms = new Map();
  return {
    storage: {
      local: memoryArea(),
      session: memoryArea(),
    },
    alarms: {
      create: async (name, opts) => {
        alarms.set(name, opts);
        calls.push(["alarms.create", name, opts]);
      },
      clear: async (name) => {
        alarms.delete(name);
        calls.push(["alarms.clear", name]);
      },
      clearAll: async () => {
        alarms.clear();
        calls.push(["alarms.clearAll"]);
      },
      onAlarm: listenerStore(),
    },
    runtime: {
      id: "test-ext-id",
      sendMessage: async (msg) => {
        calls.push(["sendMessage", msg]);
        return undefined;
      },
      onMessage: listenerStore(),
      onInstalled: listenerStore(),
      onStartup: listenerStore(),
    },
    tabs: {
      query: async () => [{ id: 99, url: "https://test.example/page" }],
      get: async () => ({ id: 99, url: "https://test.example/page" }),
      reload: async (tabId) => {
        calls.push(["tabs.reload", tabId]);
      },
      onActivated: listenerStore(),
      onUpdated: listenerStore(),
      onRemoved: listenerStore(),
    },
    webNavigation: { onCommitted: listenerStore() },
    webRequest: {
      onBeforeRequest: { addListener: () => {} },
      onCompleted: { addListener: () => {} },
      onErrorOccurred: { addListener: () => {} },
    },
    action: {
      setBadgeText: async () => {},
      setBadgeBackgroundColor: async () => {},
    },
    declarativeNetRequest: {
      getDynamicRules: async () => [],
      updateDynamicRules: async () => {},
      setExtensionActionOptions: async () => {},
    },
    alarmsClear: alarms,
  };
}

const CHROME = mockChrome();

// expose globally before SW import (module side-effects)
globalThis.chrome = CHROME;

await import("../service-worker.js");

// Capture the message handler registered by the SW at import time.
assert.ok(
  CHROME.runtime.onMessage.callbacks.length > 0,
  "message handler registered",
);
const onMessage = CHROME.runtime.onMessage.callbacks[0];

/**
 * Drives the captured onMessage handler and returns the sendResponse value.
 * Handles the case where sendResponse is called async (the handler returns
 * `true` so we just await the callback).
 */
function drive(msg, sender = {}) {
  return new Promise((resolve) => {
    onMessage(msg, sender, resolve);
  });
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function deepEqualIgnoring(res, keys) {
  return Object.fromEntries(
    Object.entries(res).filter(([k]) => !keys.includes(k)),
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test("set-policy stores flags and get-state returns them", async () => {
  calls.length = 0;
  const setRes = await drive({
    type: "set-policy",
    host: "a.example",
    flags: {
      blockClassicScripts: true,
      blockModuleScripts: true,
      blockExternalScripts: false,
      blockThirdPartyScripts: true,
      blockInlineEventHandlers: true,
      blockJavascriptUrls: true,
      blockImportMaps: true,
      blockSpeculationRules: true,
      blockJsonLd: true,
      blockJsonData: false,
      reportBlockedContent: true,
    },
  });
  assert.equal(setRes.error, undefined);

  const state = await drive({ type: "get-state", host: "a.example" });
  assert.equal(state.mode, "firstPartyOnly");
  assert.equal(state.flags.blockClassicScripts, true);
  assert.ok(state.activeCsp !== null);
  assert.deepEqual(state.exceptions, []);
  assert.deepEqual(state.containerAllows, []);

  // state-changed broadcast was sent
  assert.ok(calls.some((c) => c[0] === "sendMessage" && c[1]?.type === "state-changed"));
});

test("clear-site wipes the host's policy and related storage", async () => {
  // Pre-seed: seed exceptions, inline-allows, container-allows and a legacy mode
  const { local } = CHROME.storage;
  const dump = local._dump();
  // set up as if two hosts exist; we'll only clear 'a.example'
  await drive({
    type: "set-policy",
    host: "b.other",
    flags: { blockClassicScripts: true, blockModuleScripts: true, blockExternalScripts: false, blockThirdPartyScripts: false, blockInlineEventHandlers: false, blockJavascriptUrls: false, blockImportMaps: false, blockSpeculationRules: false, blockJsonLd: false, blockJsonData: false, reportBlockedContent: true },
  });
  // add exception on a.example
  await drive({ type: "add-exception", host: "a.example", origin: "https://cdn.a.example" });
  // add container allow
  await drive({ type: "add-container-allow", host: "a.example", digest: "a".repeat(64) });
  // add inline allow
  await drive({ type: "add-inline-allow", host: "a.example", kind: "script", hash: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" });
  // seed legacy siteModes
  await local.set({ siteModes: { "a.example": "noScripts" } });
  // pre-seed a pause
  await local.set({ pausedUntil: { "a.example": { until: Date.now() + 90000, flags: null } } });
  calls.length = 0;

  const res = await drive({ type: "clear-site", host: "a.example" });
  assert.deepEqual(res, { ok: true });

  // verify all keys wiped for a.example
  const after = await CHROME.storage.local.get([
    "sitePolicies",
    "siteModes",
    "siteExceptions",
    "siteInlineAllows",
    "siteContainerAllows",
    "pausedUntil",
  ]);
  const key = "a.example";
  assert.equal(key in (after.sitePolicies ?? {}), false);
  assert.equal(key in (after.siteModes ?? {}), false);
  assert.equal(key in (after.siteExceptions ?? {}), false);
  assert.equal(key in (after.siteInlineAllows ?? {}), false);
  assert.equal(key in (after.siteContainerAllows ?? {}), false);
  assert.equal(key in (after.pausedUntil ?? {}), false);

  // b.other untouched
  assert.equal("b.other" in (after.sitePolicies ?? {}), true);

  // alarms.clear was called for resume:a.example
  assert.ok(calls.some((c) => c[0] === "alarms.clear" && c[1] === "resume:a.example"));

  // broadcast fired
  assert.ok(calls.some((c) => c[0] === "sendMessage" && c[1]?.type === "state-changed"));

  // clean up
  await local.set({ sitePolicies: {}, siteExceptions: {}, siteInlineAllows: {}, siteContainerAllows: {}, pausedUntil: {}, siteModes: {} });
});

test("add-inline-allow stores hashes; remove-inline-allow deletes one kind", async () => {
  const SCRIPT = `sha256-${"A".repeat(43)}=`;
  const ATTR = `sha256-${"B".repeat(43)}=`;

  // dedupe on re-add
  await drive({ type: "add-inline-allow", host: "hash.example", kind: "script", hash: SCRIPT });
  await drive({ type: "add-inline-allow", host: "hash.example", kind: "script", hash: SCRIPT });
  await drive({ type: "add-inline-allow", host: "hash.example", kind: "attr", hash: ATTR });

  let state = await drive({ type: "get-state", host: "hash.example" });
  assert.deepEqual(state.inlineAllows, { scripts: [SCRIPT], attrs: [ATTR] });

  const rem = await drive({
    type: "remove-inline-allow",
    host: "hash.example",
    kind: "script",
    hash: SCRIPT,
  });
  assert.deepEqual(rem.inlineAllows, { scripts: [], attrs: [ATTR] });

  state = await drive({ type: "get-state", host: "hash.example" });
  assert.deepEqual(state.inlineAllows, { scripts: [], attrs: [ATTR] });

  // unknown hashes are a no-op; the attr- prefix is tolerated on remove
  const UNKNOWN = `sha256-${"C".repeat(43)}=`;
  const unknown = await drive({
    type: "remove-inline-allow",
    host: "hash.example",
    kind: "script",
    hash: UNKNOWN,
  });
  assert.equal(unknown.error, undefined);
  state = await drive({ type: "get-state", host: "hash.example" });
  assert.deepEqual(state.inlineAllows, { scripts: [], attrs: [ATTR] });

  const prefixed = await drive({
    type: "remove-inline-allow",
    host: "hash.example",
    kind: "attr",
    hash: `attr-${ATTR}`,
  });
  assert.deepEqual(prefixed.inlineAllows, { scripts: [], attrs: [] });
  state = await drive({ type: "get-state", host: "hash.example" });
  assert.deepEqual(state.inlineAllows, { scripts: [], attrs: [] });

  // clean up the host's (now-empty) entry in the shared test store
  await CHROME.storage.local.set({ siteInlineAllows: {} });
});

test("clear-tab flushes session keys and override", async () => {
  const { session } = CHROME.storage;
  // pre-seed a session event and an override
  await session.set({
    "tabEvents:11": [{ kind: "inline-script" }],
    "tabStats:11": { inlineScripts: 1 },
    "tabNet:11": [{ method: "GET", url: "https://ext.example/x" }],
    tabOverrides: [11],
  });

  calls.length = 0;
  const res = await drive({ type: "clear-tab", tabId: 11 });
  assert.deepEqual(res, { ok: true });

  const after = await CHROME.storage.session.get([
    "tabEvents:11",
    "tabStats:11",
    "tabNet:11",
    "tabOverrides",
  ]);
  assert.equal(after["tabEvents:11"], undefined);
  assert.equal(after["tabStats:11"], undefined);
  assert.equal(after["tabNet:11"], undefined);
  assert.deepEqual(after.tabOverrides, []);
});