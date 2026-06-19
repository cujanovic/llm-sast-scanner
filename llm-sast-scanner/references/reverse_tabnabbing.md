---
name: reverse_tabnabbing
description: Reverse tabnabbing — links/scripts that open a new tab with target="_blank" or window.open() without rel="noopener" (or the noopener feature), leaving window.opener exposed so the opened (possibly attacker/third-party) page can redirect the original tab to a phishing page (CWE-1022)
---

# Reverse Tabnabbing (CWE-1022)

When a page opens a new browsing context with `target="_blank"` (anchors/forms) or `window.open()` **without** `rel="noopener"` (or the `"noopener"` window feature), the newly opened page receives a live reference to the opener via `window.opener`. In legacy browser behavior, the opened page can then navigate the *original* tab — `window.opener.location = 'https://phishing.example'` — so a user who returns to the first tab lands on an attacker-controlled clone of the trusted site and re-enters credentials.

## What It Is / Is Not

- **Is**: outbound/new-tab navigation to a destination the origin does not fully control (external links, user-submitted URLs, third-party/partner links, ad/redirect links) that omits `noopener`, leaving `window.opener` writable by the destination.
- **Is not**: open redirect (`open_redirect.md` — server sends a redirect to an attacker URL), clickjacking/UI-redress (`clickjacking.md`), or XSS. Reverse tabnabbing is purely the missing `noopener`/`noreferrer` isolation on a new tab.
- **Highest signal** when the `href`/opened URL is external or attacker-influenced; same-origin `_blank` links are low/no risk but flagged when the destination is user-controlled.

## Source -> Sink Pattern

- **Sink**: `<a target="_blank">` / `<form target="_blank">` / `window.open(url)` / `window.open(url, '_blank')` with no `rel="noopener"` and no `"noopener"` in the feature string.
- **Aggravating source**: the destination URL is external, user-submitted, or comes from untrusted data (comments, profiles, link previews, redirectors) — the opened page is potentially attacker-controlled.

## Recon Indicators (Grep)

```bash
# HTML/template anchors & forms opening new tabs (then check for rel=noopener)
rg -ni 'target\s*=\s*["'"'"']_blank["'"'"']' --glob '*.{html,htm,php,erb,ejs,hbs,twig,vue,svelte,jsx,tsx,astro}'
# JSX/React new-tab links (rel often omitted)
rg -n 'target=\{?["'"'"']_blank["'"'"']\}?' --glob '*.{jsx,tsx}'
# window.open without a noopener feature
rg -n 'window\.open\s*\(' --glob '*.{js,jsx,ts,tsx,vue,svelte}'
# Dynamically created anchors set to _blank
rg -n "\.target\s*=\s*['\"]_blank['\"]|setAttribute\(\s*['\"]target['\"]\s*,\s*['\"]_blank['\"]" --glob '*.{js,ts,jsx,tsx}'
```
Then, for each `_blank` hit, confirm the **absence** of `rel="noopener"` / `rel="noopener noreferrer"` on the same element, and for `window.open` the absence of `"noopener"` in the feature argument.

## Vulnerable Conditions

- `<a href="https://external..." target="_blank">` with no `rel="noopener"` (or only `rel="noreferrer"` missing `noopener` on older engines that don't imply it).
- React/JSX `<a target="_blank">` without `rel="noopener noreferrer"` (JSX does not add it automatically).
- `window.open(userUrl)` / `window.open(userUrl, '_blank')` with no `"noopener"` feature, especially keeping the returned handle.
- User-controlled URLs rendered as `_blank` links (forum/comment/profile links, link unfurls).
- Forms with `target="_blank"` posting then exposing `window.opener`.

## Safe Patterns

- Anchors/forms: add `rel="noopener"` (use `rel="noopener noreferrer"` to also strip the `Referer`) to every `target="_blank"`.
- JS: `window.open(url, '_blank', 'noopener,noreferrer')`, or set `const w = window.open(); w.opener = null;` before navigating, or anchor-click with `rel`.
- Framework/lint: enforce `react/jsx-no-target-blank`; many modern bundlers/linters auto-flag this. Note modern browsers default `_blank` to `noopener`, but **do not rely on it** — older/embedded webviews and explicitly-overridden `rel` still expose `opener`; the static finding stands.
- Centralize external-link rendering through a component/helper that always injects `rel="noopener noreferrer"`.

## Severity / Triage

- External or user-controlled `_blank` destination without `noopener` → **Low–Medium** (phishing-assist; requires user to revisit the original tab).
- Same-origin `_blank` without `noopener` and no user-controlled URL → **Info** (defense-in-depth).
- `rel="noopener"` present, or `"noopener"` feature passed, or `opener` nulled → **FALSE POSITIVE**.

## Common False Alarms

- Links that already carry `rel="noopener"` / `rel="noopener noreferrer"`.
- `window.open` calls that pass a `"noopener"` feature or null the returned `opener`.
- Downloads / `mailto:` / same-tab navigations (no new browsing context, no `opener` exposure).

## Cross-References

- `open_redirect.md` — server-side redirect to attacker URLs (different mechanism, often chained for the phishing landing page).
- `clickjacking.md` — other UI-redress / phishing-assist client-side weaknesses.
- `content_security_policy.md` — broader client-side hardening headers.

## Core Principle

Every `target="_blank"` link and `window.open()` to a destination the page does not fully control must set `rel="noopener"` (prefer `noopener noreferrer`) so the opened page cannot reach back through `window.opener` to navigate the originating tab.
