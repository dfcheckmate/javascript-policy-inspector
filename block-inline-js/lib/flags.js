/**
 * flags.js — flag-based per-site policy model.
 *
 * A policy is a flat bundle of boolean flags (FLAGS is the source of truth).
 * The legacy three modes are presets that map to fixed flag bundles. The
 * layers that consume a bundle:
 * - CSP layer (service worker): script EXECUTION posture, driven by
 *   blockExternalScripts / blockThirdPartyScripts (+ per-site allowances).
 * - DOM/reporting layer (observer): removes non-executable containers
 *   (json-ld, json-data, import maps, speculation rules) and refines what
 *   inline scripts get recorded.
 *
 * INLINE INVARIANT: no deployed policy ever emits 'unsafe-inline'. Any
 * enforced posture therefore blocks inline <script> execution unless the user
 * Allow-lists a specific sha256 hash. Categorical flags such as
 * blockClassicScripts / blockModuleScripts add meaning at the DOM/reporting
 * layer and are required (both true) for an enforceable CSP posture — a
 * bundle that claims to allow inline while enforcing handlers cannot be
 * expressed in CSP (see composePolicyFromFlags).
 */

export const MODES = Object.freeze({
  OBSERVE: "observe",
  FIRST_PARTY_ONLY: "firstPartyOnly",
  NO_SCRIPTS: "noScripts",
});

/** Canonical flag names, in UI order. */
export const FLAG_KEYS = Object.freeze([
  "blockClassicScripts",
  "blockModuleScripts",
  "blockExternalScripts",
  "blockThirdPartyScripts",
  "blockInlineEventHandlers",
  "blockJavascriptUrls",
  "blockImportMaps",
  "blockSpeculationRules",
  "blockJsonLd",
  "blockJsonData",
  "reportBlockedContent",
]);

export const DEFAULT_FLAGS = Object.freeze({
  blockClassicScripts: false,
  blockModuleScripts: false,
  blockExternalScripts: false,
  blockThirdPartyScripts: false,
  blockInlineEventHandlers: false,
  blockJavascriptUrls: false,
  blockImportMaps: false,
  blockSpeculationRules: false,
  blockJsonLd: false,
  blockJsonData: false,
  reportBlockedContent: true,
});

/**
 * Non-executable container categories the DOM layer may remove, keyed to the
 * flag that gates each removal. Categories absent here (e.g. unknown-script-
 * container) are observation-only: the observer never removes them.
 */
export const REMOVAL_FLAG_BY_CATEGORY = Object.freeze({
  "json-ld": "blockJsonLd",
  "json-data": "blockJsonData",
  "import-map": "blockImportMaps",
  "speculation-rules": "blockSpeculationRules",
});

/**
 * Builds a full flag bundle from partial overrides. Throws on unknown keys so
 * a typo can never silently disable a control.
 * @param {Partial<{[K in keyof typeof DEFAULT_FLAGS]: boolean}>} [overrides]
 * @returns {{[K in keyof typeof DEFAULT_FLAGS]: boolean}}
 */
export function makeFlags(overrides = {}) {
  /** @type {{[K in keyof typeof DEFAULT_FLAGS]: boolean}} */
  const flags = { ...DEFAULT_FLAGS };
  for (const [key, value] of Object.entries(overrides)) {
    if (!FLAG_KEYS.includes(key)) throw new Error(`unknown flag: ${key}`);
    flags[key] = Boolean(value);
  }
  return flags;
}

/** @param {unknown} value @returns {value is {[K in keyof typeof DEFAULT_FLAGS]: boolean}} */
export function isFlags(value) {
  if (!value || typeof value !== "object") return false;
  return FLAG_KEYS.every((k) => typeof value[k] === "boolean");
}

/**
 * Returns an expressible bundle for `flags`, auto-enabling the inline flag
 * pair (classic + module scripts) when an enforced posture demands it.
 *
 * Any enforced posture roots `script-src` at 'none'/'self'/'*' and never
 * emits 'unsafe-inline' (INLINE INVARIANT), so running scripts inline while
 * external sources are refused is unexpressible. Rather than rejecting single
 * toggles like "Block external scripts" alone, the popup completes the bundle
 * and reports what it enabled. Pure DOM/report bundles (no CSP posture) are
 * returned untouched.
 * @param {{[K in keyof typeof DEFAULT_FLAGS]: boolean}} flags
 * @returns {{flags: {[K in keyof typeof DEFAULT_FLAGS]: boolean}, autoEnabled: string[]}}
 */
export function enforceInlineBase(flags) {
  const wantsCsp =
    flags.blockExternalScripts ||
    flags.blockThirdPartyScripts ||
    flags.blockClassicScripts ||
    flags.blockModuleScripts ||
    flags.blockInlineEventHandlers ||
    flags.blockJavascriptUrls;
  const autoEnabled = [];
  if (wantsCsp && (!flags.blockClassicScripts || !flags.blockModuleScripts)) {
    if (!flags.blockClassicScripts) autoEnabled.push("blockClassicScripts");
    if (!flags.blockModuleScripts) autoEnabled.push("blockModuleScripts");
    flags = { ...flags, blockClassicScripts: true, blockModuleScripts: true };
  }
  return { flags, autoEnabled };
}

/**
 * Bottom-up enrichment for Tier-3 DOM removals: when a module-tied feature
 * (import maps, speculation rules) is removed while module scripts are
 * disabled, auto-enable both classic and module inline scripts so the
 * configuration is expressible. Pure data cleanup (JSON-LD, JSON data) is
 * served by the DOM arm alone and never forces the module-script base.
 *
 * @param {{[K in keyof typeof DEFAULT_FLAGS]: boolean}} flags
 * @returns {{flags: {[K in keyof typeof DEFAULT_FLAGS]: boolean}, autoEnabled: string[]}}
 */
export function enforceDomBase(flags) {
  const wantsModuleBase =
    flags.blockImportMaps ||
    flags.blockSpeculationRules;
  // Pure data cleanup (json-ld / json-data) is served by the DOM sanitizer arm
  // alone: removing those containers needs no module-script setup, so we never
  // auto-enable the classic+module pair for them.
  const autoEnabled = [];
  if (wantsModuleBase && (!flags.blockClassicScripts || !flags.blockModuleScripts)) {
    if (!flags.blockClassicScripts) autoEnabled.push("blockClassicScripts");
    if (!flags.blockModuleScripts) autoEnabled.push("blockModuleScripts");
    flags = { ...flags, blockClassicScripts: true, blockModuleScripts: true };
  }
  return { flags, autoEnabled };
}

/**
 * Built-in policy presets. A preset is a named, immutable flag bundle; the
 * popup radios map directly onto these.
 *
 * firstPartyOnly: blocks inline execution, handlers, javascript: URLs, third-
 * party scripts and (per the layered-policy decision) JSON-LD containers.
 * noScripts: everything except JSON *data* — inert `application/json` blocks
 * stay removable only by explicit opt-in.
 */
export const PRESETS = Object.freeze({
  [MODES.OBSERVE]: Object.freeze(makeFlags()),
  [MODES.FIRST_PARTY_ONLY]: Object.freeze(
    makeFlags({
      blockClassicScripts: true,
      blockModuleScripts: true,
      blockThirdPartyScripts: true,
      blockInlineEventHandlers: true,
      blockJavascriptUrls: true,
      blockImportMaps: true,
      blockSpeculationRules: true,
      blockJsonLd: true,
    }),
  ),
  [MODES.NO_SCRIPTS]: Object.freeze(
    makeFlags({
      blockClassicScripts: true,
      blockModuleScripts: true,
      blockExternalScripts: true,
      blockThirdPartyScripts: true,
      blockInlineEventHandlers: true,
      blockJavascriptUrls: true,
      blockImportMaps: true,
      blockSpeculationRules: true,
      blockJsonLd: true,
    }),
  ),
});

/**
 * Default policy for hosts with no stored preference — observe. Chosen for
 * bot-classification safety: a stable, sensor-loading posture is the profile
 * least likely to be flagged as automation; hardening is per-host opt-in.
 */
export const DEFAULT_POLICY = PRESETS[MODES.OBSERVE];

/** @param {unknown} value @returns {value is keyof typeof MODES} */
export function isPresetName(value) {
  return typeof value === "string" && Object.hasOwn(PRESETS, value);
}

/**
 * @param {string | undefined} name
 * @returns {{[K in keyof typeof DEFAULT_FLAGS]: boolean} | null}
 */
export function presetFor(name) {
  return isPresetName(name) ? PRESETS[name] : null;
}

/**
 * Returns the preset name whose bundle is exactly `flags`, or null when the
 * bundle is a custom profile. Drives the popup's "custom" indicator.
 * @param {unknown} flags
 * @returns {keyof typeof MODES | null}
 */
export function modeForFlags(flags) {
  if (!isFlags(flags)) return null;
  for (const [mode, bundle] of Object.entries(PRESETS)) {
    if (FLAG_KEYS.every((k) => flags[k] === bundle[k])) return mode;
  }
  return null;
}

/**
 * Nearest preset for a custom bundle, plus the deltas that set it apart.
 *
 * Exact bundles resolve to their own preset with an empty delta list. Custom
 * bundles resolve to the preset with the fewest differing flags (Hamming
 * distance over FLAG_KEYS), ties broken by preset declaration order. A delta
 * `on: true` means the custom profile turns the flag ON relative to the
 * preset; `on: false` means it turns it OFF. Drives the popup's condensed
 * mode readout ("No scripts  (+report)"), never policy.
 * @param {unknown} flags
 * @returns {{mode: keyof typeof MODES, deltas: Array<{key: string, on: boolean}>} | null}
 */
export function nearestPreset(flags) {
  if (!isFlags(flags)) return null;
  for (const [mode, bundle] of Object.entries(PRESETS)) {
    if (FLAG_KEYS.every((k) => flags[k] === bundle[k])) return { mode, deltas: [] };
  }
  let best = null;
  let bestDist = Infinity;
  for (const [mode, bundle] of Object.entries(PRESETS)) {
    let dist = 0;
    for (const k of FLAG_KEYS) if (flags[k] !== bundle[k]) dist++;
    if (dist < bestDist) {
      bestDist = dist;
      best = mode;
    }
  }
  const bundle = PRESETS[best];
  const deltas = FLAG_KEYS.filter((k) => flags[k] !== bundle[k]).map((key) => ({
    key,
    on: flags[key],
  }));
  return { mode: best, deltas };
}

/**
 * Caller is responsible for canonical keys (the storage layer already keeps
 * eTLD+1-normalized keys).
 * @param {unknown} policies existing v2 store object (plain map)
 * @param {unknown} legacyModes v1 store object ({[host]: mode})
 * @returns {{policies: object, changed: boolean}}
 */
export function migrateLegacyModes(policies, legacyModes) {
  const out = { ...(policies ?? {}) };
  let changed = false;
  for (const [raw, mode] of Object.entries(legacyModes ?? {})) {
    if (mode === MODES.OBSERVE) continue; // absence is already "observe"
    const preset = presetFor(mode);
    if (preset && !isFlags(out[raw])) {
      out[raw] = preset;
      changed = true;
    }
  }
  return { policies: out, changed };
}