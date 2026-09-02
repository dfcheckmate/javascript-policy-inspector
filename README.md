# JavaScript Policy Inspector

Per-site JavaScript policies: **Observe**, **First-party only**, **No scripts**.
Policies are injected via CSP headers (DNR `modifyHeaders`); scripts are
inventoried and block reasons explained, with per-item allow actions and a
network view.

## Build the browser-specific bundles

Run once to produce two self-contained, clearly-labelled directories:

```sh
yarn build          # or: yarn build:firefox  (node scripts/build-firefox.mjs)
```

| Directory      | Browser          | `manifest.json` background             | Service worker            |
|----------------|------------------|----------------------------------------|---------------------------|
| `dist-edge/`   | Chrome / Edge    | `service_worker` + `"type": "module"`   | `service-worker.js` + lib/ |
| `dist-firefox/`| Firefox          | `background.scripts`                    | `service-worker.bundled.js`|

Each folder contains exactly **one** `manifest.json` for its browser and none
of the other browser's files, so you can never load the wrong manifest.

## Load the extension

### Chrome / Edge
1. Copy the whole **`dist-edge/`** folder onto your machine.
2. `edge://extensions` (or `chrome://extensions`) → enable **Developer mode**.
3. **Load unpacked** → select `dist-edge/`.

### Firefox
1. Either load **`dist-firefox/`** via `about:debugging → This Firefox → Load
   Temporary Add-on` (pick `manifest.json`), or install the signed `.xpi` from
   `dist-firefox/signed/`.

## Tests

```sh
node --test block-inline-js/tests/policies.test.js
```
