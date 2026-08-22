// All harness code is external so it survives when inline JS is blocked.
// Only the payloads being tested are ever inline.

console.log("[test-page] tests.js executed");

// Third-party simulation: this folder served on a second port is a different
// origin, so vendor.js counts as third-party. Injected dynamically (async by
// default) so a dead :8001 can never block page load.
try {
  const VENDOR_URL = "http://localhost:8001/vendor.js";
  let cspBlockedVendor = false;
  window.addEventListener("securitypolicyviolation", (e) => {
    if (e.blockedURL?.includes("localhost:8001")) cspBlockedVendor = true;
  });

  const s = document.createElement("script");
  s.src = VENDOR_URL;
  s.onerror = () => {
    // The error event can fire BEFORE the violation event, so judge late.
    setTimeout(async () => {
      if (cspBlockedVendor) {
        console.info(
          "[test-page] vendor script blocked by active policy (expected under First-party only)",
        );
        return;
      }
      // Tiebreaker: our CSP restricts scripts only, so a plain fetch probes
      // true reachability.
      try {
        await fetch(VENDOR_URL, { mode: "no-cors", cache: "no-store" });
        console.info(
          "[test-page] vendor script blocked by active policy (server reachable)",
        );
      } catch {
        console.warn("[test-page] vendor server (:8001) not reachable");
      }
    }, 150);
  };
  document.head.appendChild(s);
} catch {
  console.warn("[test-page] vendor injection failed");
}

// eval / new Function — NOT in scope; should stay OK under the blocker
try {
  eval("window.__eval_flag = true;");
  const f = new Function("return '__fn_flag'")();
  mark(
    "status-eval",
    window.__eval_flag === true && f === "__fn_flag",
    window.__eval_flag && f === "__fn_flag" ? "Executed" : "Unexpected result",
  );
} catch {
  mark("status-eval", false);
}

// setTimeout — plain runtime API; must be unaffected
try {
  setTimeout(() => mark("status-timer", true, "timeout fired"), 20);
} catch {
  mark("status-timer", false);
}

// fetch + XHR against data: URLs — no network needed
try {
  const xhr = new XMLHttpRequest();
  xhr.open("GET", 'data:application/json,{"x":1}');
  xhr.onload = () => mark("status-fetch", true, "XHR OK");
  xhr.onerror = () => mark("status-fetch", false, "XHR error");
  xhr.send();
} catch {
  mark("status-fetch", false, "XHR blocked");
}

try {
  fetch('data:application/json,{"y":2}')
    .then((r) => r.text())
    .then((t) => mark("status-fetch", true, `fetch OK ${t}`))
    .catch(() => mark("status-fetch", false, "fetch error"));
} catch {
  mark("status-fetch", false, "fetch blocked");
}

// Blob-URL worker — script-src covers worker-src fallback; blob: is allowed
try {
  const url = URL.createObjectURL(
    new Blob(["postMessage('worker-ok');"], { type: "text/javascript" }),
  );
  const w = new Worker(url);
  w.onmessage = (e) => mark("status-worker", true, `Worker message: ${e.data}`);
  w.onerror = () => mark("status-worker", false);
} catch {
  mark("status-worker", false);
}

// Dynamic insertion of an INLINE script via blob URL — blob: stays allowed
try {
  const src =
    "window.__blob_external_ran = true; " +
    "mark('status-blob-external', true, 'Executed');";
  const url = URL.createObjectURL(new Blob([src], { type: "text/javascript" }));
  const s = document.createElement("script");
  s.src = url;
  document.head.appendChild(s);
} catch {
  mark("status-blob-external", false);
}

// Button: dynamic insertion of a genuinely INLINE script body.
// The mechanism (createElement/appendChild from external code) works, but the
// payload has no src → refused under the appended CSP.
document.getElementById("btn-dynamic").addEventListener("click", () => {
  const s = document.createElement("script");
  s.text = "mark('status-dynamic', true, 'Injected-run');";
  document.body.appendChild(s);
  setTimeout(() => {
    const st = document.querySelector("#status-dynamic .status")?.textContent;
    if (st !== "Injected-run") mark("status-dynamic", false, "Blocked");
  }, 50);
});

console.log("[test-page] tests.js finished setup");

// Deferred verdicts: payloads whose success marker only appears when they
// execute get flipped to Blocked once it's clear they never ran.
setTimeout(() => {
  if (!window.__blob_external_ran) mark("status-blob-external", false);
}, 300);
