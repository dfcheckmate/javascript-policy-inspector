// mark.js — shared result marker + post-parse verification.
// Loaded EXTERNALLY on purpose: it keeps working when inline JS is blocked.

window.mark = function mark(id, ok, msg) {
  const row = document.getElementById(id);
  if (!row) return;
  const span = row.querySelector(".status");
  if (!span) return;
  span.textContent = msg ?? (ok ? "OK" : "BLOCKED");
  span.className = ok ? "status ok" : "status blocked";
  const log = document.getElementById("console");
  if (log) log.textContent += `${id}: ${span.textContent}\n`;
};

document.addEventListener("DOMContentLoaded", () => {
  setTimeout(() => {
    const inlineRan = document.body.dataset.inlineRan === "true";
    mark("status-inline", inlineRan, inlineRan ? "Executed" : "Blocked");

    const extRan = window.__real_external_ran === true;
    mark("status-real-external", extRan, extRan ? "Executed" : "Blocked");

    console.log(
      `[test-page] verification: inline=${inlineRan} external=${extRan}`,
    );
  }, 0);
});

// Passive verdicts from live CSP violations — only meaningful while this
// file itself is allowed to run (i.e. not under No scripts).
window.addEventListener("securitypolicyviolation", (e) => {
  if (e.violatedDirective === "script-src-attr") mark("status-event", false);
});
