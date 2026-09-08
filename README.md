# JavaScript Policy Inspector

Monitor and control JavaScript on a per-site basis. Enforce broad presets or a
fine-grained, per-category profile, then inspect exactly what each page loads
and why anything was blocked or removed.

The extension works by injecting a per-site `Content-Security-Policy` header
via `declarativeNetRequest` and observing the page from a content script. It
stores all policies and activity locally in the browser — nothing is sent
anywhere.

## Features

- **Three presets** — **Observe**, **First-party only**, **No scripts** — that
  map onto fixed flag bundles.
- **Custom profiles** — an Advanced panel exposes all 11 per-category flags for
  a tailored policy per site.
- **Layered enforcement** — script *execution* is enforced with CSP; non-
  executing data containers (JSON-LD, JSON data, import maps, speculation
  rules) are removed from the DOM when a profile asks for it.
- **Forensic activity log** — every `<script>` is classified as JavaScript or
  an inert data block; inline handlers and `javascript:` URLs are tracked;
  `securitypolicyviolation` events provide ground truth for CSP blocks.
- **Blocked vs removed** — CSP blocks and DOM container removals are tracked as
  separate counters.
- **Per-site allowances** — allow a specific script hash, handler, or origin;
  exempt a removed container from future removal.
- **Network view** — request-level view with a *sensor* marker for bot-
  management origins, plus a warning when hardening is applied to such sites.

## Install

### Chrome / Edge
1. Copy the `dist-edge/` folder onto your machine.
2. `edge://extensions` (or `chrome://extensions`) → enable **Developer mode**.
3. **Load unpacked** → select `dist-edge/`.

### Firefox
1. Load `dist-firefox/` via `about:debugging → This Firefox → Load Temporary
   Add-on` (pick `manifest.json`), or
2. install the signed `.xpi` from `dist-firefox/signed/`.

## Usage

Open the popup: the three presets sit at the top; the **Advanced** panel
exposes every flag for a custom profile. The **Inventory** section tallies
first-party/third-party/inline scripts, handlers, CSP blocks, removed
containers and network requests — click a count for details, where inline items
can be previewed and allowed. The **Activity** section is the live forensic
feed.

> **bot-safety note:** hardening changes a page's observable surface (blocked
> scripts, removed containers), which bot-management / sensor suites can
> detect. The extension warns about this and marks known sensor origins — it
> never fingerprints the browser or alters its own headers for automation
> detection.

## How it works

| Layer | What it controls | Mechanism |
|-------|------------------|-----------|
| **CSP layer** (service worker) | Script execution: classic/module scripts, third-party/external origins, inline handlers, `javascript:` URLs | DNR `modifyHeaders` appending a per-site `Content-Security-Policy` |
| **DOM layer** (observer) | Non-executing containers: JSON-LD, JSON data, import maps, speculation rules | Removes them from the DOM when the profile requests it |
| **Reporting layer** (observer + SW) | Forensic activity data | Content-script events → per-tab activity log |

The CSP layer is the sole execution authority: parser-inserted scripts run
before any content script can act, so the DOM layer only ever removes inert
data blocks — which a page's own scripts can observe, a deliberate and
documented opt-in trade-off. The engine never emits `unsafe-inline`, so any
enforced posture blocks inline scripts unless a specific `sha256-…` hash is
allow-listed.

### Flags

`blockClassicScripts`, `blockModuleScripts`, `blockExternalScripts`,
`blockThirdPartyScripts`, `blockInlineEventHandlers`, `blockJavascriptUrls`,
`blockImportMaps`, `blockSpeculationRules`, `blockJsonLd`, `blockJsonData`,
`reportBlockedContent`.

## Build

```sh
yarn build          # or: yarn build:firefox  (node scripts/build-firefox.mjs)
```

Produces two self-contained folders, each with exactly one browser-appropriate
manifest:

| Directory      | Browser          | Service worker              |
|----------------|------------------|-----------------------------|
| `dist-edge/`   | Chrome / Edge    | `service-worker.js` + `lib/` |
| `dist-firefox/`| Firefox          | `service-worker.bundled.js` |

## Test

```sh
node --test block-inline-js/tests/*.test.js
```

Covers CSP composition from the flag model, script/data-block classification,
activity statistics, the policy-store migration, and a fixture guard. A manual
verification page lives at `block-inline-js/tests/fixtures/layered-policy.html`
with expected popup tallies per profile.