# AMO / Store Listing Copy

End-user facing text for the add-on listing. The **summary** lives in each
`manifest.json` (`"description"`); the **full description** and **release
notes** are pasted into the AMO Developer Hub (and, for Chrome, the Chrome Web
Store) when submitting a version.

---

## Summary (manifest "description")

> Per-site JavaScript control: monitor, allow first-party, or block entirely.
> See what loads, allow only what you trust.

(118 chars — within AMO's 132-char manifest limit.)

---

## Full description

> JavaScript is used by most websites, but sites do not necessarily need to run
> every script they include.
>
> JavaScript Policy Inspector provides three per-site options:
>
> - **Observe**: monitor what the page loads and does without changing its behavior.
> - **First-party only**: allow scripts from the site itself while blocking third-party scripts.
> - **No scripts**: block JavaScript on the page.
>
> The extension applies these settings by creating a Content Security Policy
> for each page. This also provides information about why a script was blocked,
> helping distinguish site behavior from extension-enforced restrictions.
>
> The popup displays scripts and inline event handlers detected on the current
> tab, categorized as first-party, third-party, inline, or blocked. It also
> lists the page's network requests and provides the reason when a script is
> blocked.
>
> Specific scripts, inline handlers, or origins can be allowed individually.
> These exceptions are saved per site and applied on subsequent visits.
>
> Policies and history are stored locally in the browser. No information is
> sent elsewhere, and the extension does not collect user data.

---

## Version notes

> **Version 0.3.2**
> - Cleaned up the popup's markup so AMO no longer reports any "unsafe
>   innerHTML" warnings — same behaviour, safer code.
> - Declared that the add-on collects no data, satisfying Firefox's built-in
>   consent check.
> - Added the icon set to both the Edge/Chrome and Firefox builds.
>
> **Version 0.3.1**
> - Added a rocket icon to the browser toolbar.
>
> **Version 0.3.0**
> - The network view now lets you allow a script's source origin straight from
>   the request list.
> - Separated the Edge/Chrome and Firefox builds so each browser always gets the
>   right manifest.
>
> **Version 0.2.0**
> - Firefox compatibility fixes.
> - Site names are now normalised consistently, and inline allowances match the
>   page content correctly.
>
> **Version 0.1.0**
> - First release: per-site Observe, First-party-only, and No-scripts policies,
>   with an activity log and per-item allowances.