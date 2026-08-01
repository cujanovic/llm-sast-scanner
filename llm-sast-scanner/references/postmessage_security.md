---
name: postmessage_security
version: "0.4"
description: postMessage origin validation failures — receivers that trust event.data without checking event.origin, wildcard targetOrigin ('*'), weak substring/regex origin checks, sender targetOrigin bypass via URL-parser host normalization (numeric IPv4 like 2130706433 → 127.0.0.1), and listeners that start OAuth / navigate to authorize URLs (escalating sibling XSS into code theft) that allow cross-origin message injection or secret leakage (CWE-345, CWE-346)
---

# postMessage Security (CWE-345 / CWE-346)

The `postMessage` API lets browsing contexts exchange data across origins (iframe ↔ parent, popup ↔ opener, WebView ↔ embedded page). The browser delivers every message to registered listeners; **origin is not validated automatically**. A receiver that processes `event.data` without a strict `event.origin` check accepts messages from any page that can obtain a reference to the target window — including attacker-controlled iframes, popups, or extensions. A sender that calls `postMessage(data, '*')` delivers data to whichever origin currently owns the target window, leaking secrets when the recipient navigates or is replaced. Weak origin checks (`indexOf`, unanchored regex, suffix `endsWith`) are bypassed as easily as permissive CORS reflection.

## What It Is / Is Not

- **Is**: missing or insufficient `event.origin` validation on `message` listeners; `postMessage(..., '*')` or dynamic target origins derived from untrusted input; treating `event.data` as trusted configuration, HTML, or script without sanitization; failing to verify `event.source` matches the expected child/opener reference; **replying with `location.href` / `window.location` / current-page URL** (or writing that URL into a cross-origin storage iframe) so an attacker tab can exfiltrate OAuth `?code=` / `#access_token=` without XSS.
- **Is not**: XSS when the sole issue is generic DOM sinks with no postMessage involvement — see `xss.md` for the full sink catalog and encoding rules. XS-Leak side channels from broadcasting session state via `postMessage(..., '*')` on auth pages — see `xs_leaks.md` (oracle/leak class, not origin-validation depth). CSRF (forged HTTP requests) or clickjacking (UI overlay). OAuth protocol gaps (state/PKCE/`response_type`) — see `oauth_oidc_misconfiguration.md`; this file owns the **URL-leak gadget** half of the chain.
- **Highest signal** when `event.data` flows to execution or markup sinks (`innerHTML`, `eval`, `location`, jQuery HTML helpers) **and** no strict origin allowlist guards the listener.

## Source -> Sink Pattern

**Sources (untrusted message input)**
- `event.data` from `window.addEventListener('message', …)` or `window.onmessage`
- jQuery / Node-style `.on('message', …)` on `MessagePort`, `Worker`, or wrapped event emitters
- `MessageChannel` / `BroadcastChannel` payloads when the channel is exposed cross-origin without pairing checks

**Origin-validation sinks (the security decision point)**
- Listener body uses `event.data` **before** or **without** `event.origin === '<exact expected>'` (or `ALLOWED_ORIGINS.has(event.origin)`)
- `postMessage(payload, '*')` — wildcard targetOrigin leaks `payload` to whatever origin owns `targetWindow` at delivery time
- `postMessage(payload, userSuppliedOrigin)` — attacker chooses the recipient origin, **including a value that passes a host regex on the raw string but normalizes to an attacker origin once parsed** (see the sender `targetOrigin` host-normalization case below)
- **`targetOrigin` from a `try { window.opener.location.href } catch { <request input> }` fallback** (common in OAuth popup flows): reading a *cross-origin* `opener`/parent `location.href` throws a SOP `DOMException`, so for any attacker-controlled opener the `catch` branch **always** runs and the send target becomes request-controlled input (`$('#source_url').val()`, a `source_url`/`redirect`/`origin` query param, `document.referrer`). Looks safe ("uses the opener's real URL") but the unsafe branch is the *guaranteed* path cross-origin → the token/`access_token` in `payload` is delivered to the attacker's origin. Do not treat a targetOrigin sourced from an opener/referrer read as safe when a user-influenced fallback exists; require an allowlist match on the final value.
- Weak guards: `event.origin.indexOf('legit.com')`, `event.origin.endsWith('.legit.com')`, `event.origin.startsWith('https://legit.com')`, unanchored `RegExp`, regex with unescaped dots in the host

**Data taint sinks (postMessage-specific path → impact)**
- `event.data` → DOM/HTML: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, jQuery `$()` / `.html()` / `.append()`
- `event.data` → JS execution: `eval`, `new Function`, `setTimeout(string)`, dynamic `<script>` / `.src` / `.setAttribute('src', …)`
- `event.data` → navigation: `location.href`, `location.assign`, `window.open(event.data)`
- Pair any sink above with missing/weak origin check → **CONFIRMED** cross-origin script or data injection. For sink-only analysis without origin context, cross-reference `xss.md`.

**Aggravating context**
- Listener registered on a top-level app page that holds session tokens, admin flags, or PII in replies
- `postMessage` handler on OAuth/login/callback pages or payment iframe integrations
- Child iframe `src` is user-controlled or third-party while parent trusts messages blindly
- **Listener starts OAuth / navigates to authorize** (`location = '/…OAuth…'`, `window.open(authorizeUrl)`, `action === 'startOAuth'`) with a missing/weak `event.origin` check — XSS on any origin that can obtain a window reference posts into the trusted app and kicks off the code flow; combined with XSS on the callback (or opener.location read) this steals `?code=` (cross-ref `oauth_oidc_misconfiguration.md`, `xss.md`)

## Recon Indicators (Grep)

```bash
# Message listeners — inspect each handler for event.origin check before event.data use
rg -n "addEventListener\s*\(\s*['\"]message['\"]" --glob '*.{js,jsx,ts,tsx,vue,svelte}'
rg -n "\.on\s*\(\s*['\"]message['\"]" --glob '*.{js,jsx,ts,tsx,vue,svelte}'
rg -n "onmessage\s*=" --glob '*.{js,jsx,ts,tsx,vue,svelte}'

# Wildcard or dynamic targetOrigin on send
rg -n "postMessage\s*\([^,]+,\s*['\"]\*['\"]" --glob '*.{js,jsx,ts,tsx,vue,svelte}'
rg -n "postMessage\s*\([^,]+,\s*\w+" --glob '*.{js,jsx,ts,tsx,vue,svelte}'

# Weak origin validation anti-patterns
rg -n "event\.origin\.(indexOf|search|match|includes)\s*\(" --glob '*.{js,jsx,ts,tsx,vue,svelte}'
rg -n "e\.origin\.(indexOf|search|match|includes)\s*\(" --glob '*.{js,jsx,ts,tsx,vue,svelte}'
rg -n "origin\.(startsWith|endsWith)\s*\(" --glob '*.{js,jsx,ts,tsx,vue,svelte}'
rg -n "new RegExp\s*\(.*origin" --glob '*.{js,jsx,ts,tsx,vue,svelte}'
rg -n "origin\.match\s*\(\s*/\^https\?" --glob '*.{js,jsx,ts,tsx,vue,svelte}'

# Sender targetOrigin: host-label regex matchers ([^.]+ / [^/]+) that a URL parser defeats —
# a numeric host normalizes to loopback (2130706433 / 0x7f000001 / 127.1 -> 127.0.0.1); an ^…$ anchor does NOT fix it
rg -n "\[\^\.\]\+|\[\^/\]\+" --glob '*.{js,jsx,ts,tsx,vue,svelte}'

# event.data flowing to high-risk sinks (trace identifier from listener param)
rg -n "event\.data|e\.data|msg\.data" --glob '*.{js,jsx,ts,tsx,vue,svelte}' | rg -i 'innerHTML|document\.write|eval\(|\.html\(|location\.(href|assign|replace)'
```

For each listener hit: confirm whether **every** code path that reads `event.data` is gated by strict origin equality (or Set membership) on the full origin string (`scheme + host + port`). Flag regex without `^`…`$` anchors or literal dots in host patterns. On the **send** path, also flag any `targetOrigin` that is regex-validated rather than parsed: a host regex — **even one anchored with `^…$`** — is defeated when the browser re-parses `targetOrigin` and normalizes a numeric host (`2130706433`/`0x7f000001`/`127.1` → `127.0.0.1`); require `new URL(candidate)` + exact origin/host allowlist (see `ssrf.md` for the full IPv4-encoding table).

## Vulnerable Conditions

- `window.addEventListener('message', (e) => { … e.data … })` with no `e.origin` check, or check occurs only in some branches.
- `postMessage(secret, '*')` from parent to iframe, popup, or WebView — any navigated origin receives the payload.
- Substring origin check: `e.origin.indexOf('https://legit.com') !== -1` accepts `https://legit.com.attacker.site`.
- `String.prototype.search` / unescaped regex: `"https://legit.com".search(e.origin)` treats `.` as wildcard; attacker origin `https://legitXcom` may match.
- Host regex without anchors: `/https:\/\/(mail|www)\.google\.com/` missing `$` accepts `https://www.google.com.evil.com`.
- Unescaped dots: `/^https?:\/\/(mail|www)\.google\.com/` written as `/^https?:\/\/(mail|www).google.com/` — trailing segment matches arbitrary suffix hosts.
- `startsWith('https://legit.com')` accepts `https://legit.com.evil`.
- `endsWith('.legit.com')` accepts `https://evil-legit.com`.
- **Sender `targetOrigin` validated by a host regex, then re-normalized by the browser's URL parser** (parser differential): the regex runs on the raw string, but `postMessage` parses `targetOrigin` through the WHATWG URL parser, which reads a **numeric host as IPv4 and re-serializes it in dotted form** — `2130706433`, `0x7f000001`, `0177.0.0.1`, and short form `127.1` all become `127.0.0.1`. A "subdomains of target.com" check like `/^https?:\/\/[^.]+\.target\.com/` **passes** `http://2130706433/.target.com` (the `[^.]+` label matcher eats `2130706433/` because a `/` is not a `.`), yet the parsed host is `127.0.0.1` and `/.target.com` is an ignored path → the payload (token/PII) is delivered to the attacker's origin. **An `^…$` anchor does not fix this** (the PoC regex is anchored); the defeaters are the `[^.]+`/`[^/]+` label matcher and any host check that does not re-parse + canonicalize the host. Full IPv4/IPv6 encoding table in `ssrf.md`.
- `event.data.url` or `event.data.html` passed to navigation or DOM sinks after weak origin validation.
- Reply messages echoing session/auth fields to `event.source.postMessage(response, '*')`.
- **`location.href` / `window.location` / `document.URL` in a postMessage reply (OAuth URL-leak gadget).** A listener with weak/no origin check that answers with the **current page URL** — `e.source.postMessage({ href: location.href }, '*')`, `postMessage(location.href, '*')`, `{ url: window.location.toString() }`, or syncing `last-url` into a storage iframe any parent can read — turns any page that still holds `?code=` / `#access_token=` / `#id_token=` into **one-click code/token theft** without an XSS sink. **Do not CLOSE** as "Informational URL disclosure" or "no XSS." Severity is **High–Critical** when the same origin hosts OAuth callback/error/login routes (or third-party widgets load on those routes). Cross-ref `oauth_oidc_misconfiguration.md` (non-happy-path retention). **SAFE**: never echo full `location` cross-origin; if a resize/ping reply is needed, return only typed non-sensitive fields after an exact origin allowlist.
- **Opener proxy**: `window.onmessage = (e) => opener.postMessage(e.data, '*')` (or parent forward without origin gate) on any path of a domain registered as `redirect_uri` / `web_message` target — OAuth `web_message` delivery to a legit origin is then forwarded to an attacker opener.

## Vulnerable vs Safe code examples

### Receiver — no origin check

```javascript
// VULN — any origin can send commands
window.addEventListener('message', (e) => {
  const { action, html } = e.data;
  if (action === 'render') document.getElementById('out').innerHTML = html;
});

// SAFE — strict allowlist before touching data
const ALLOWED = new Set(['https://app.example.com', 'https://widget.example.com']);
window.addEventListener('message', (e) => {
  if (!ALLOWED.has(e.origin)) return;
  const { action, html } = e.data;
  if (action === 'render') document.getElementById('out').textContent = html;
});
```

### Wildcard sender

```javascript
// VULN — payload delivered to whatever origin owns the iframe now
iframe.contentWindow.postMessage({ token: sessionToken }, '*');

// SAFE — explicit targetOrigin matching the iframe src origin
iframe.contentWindow.postMessage({ token: sessionToken }, 'https://widget.example.com');
```

### Sender targetOrigin — regex-validated but URL-parser-normalized

```javascript
// VULN — anchored subdomain regex on the RAW string, then postMessage re-parses it.
// ?origin=http://2130706433/.target.com PASSES ([^.]+ eats "2130706433/"), but the URL
// parser normalizes host 2130706433 -> 127.0.0.1 and "/.target.com" is just a path.
const dest = new URLSearchParams(location.search).get('origin');
if (/^https?:\/\/[^.]+\.target\.com/.test(dest)) {
  win.postMessage({ token: sessionToken }, dest);   // token delivered to http://127.0.0.1
}

// SAFE — parse the candidate, then exact-match its canonical origin against a Set.
// URL() canonicalizes 2130706433 -> http://127.0.0.1, so numeric/hex/octal spoofs fail.
const ALLOWED = new Set(['https://app.target.com', 'https://widget.target.com']);
try {
  const u = new URL(dest);
  if (ALLOWED.has(u.origin)) win.postMessage({ token: sessionToken }, u.origin);
} catch { /* invalid URL — reject */ }
```

### Weak origin validation

```javascript
// VULN — substring bypass: https://legit.com.attacker.site
window.addEventListener('message', (e) => {
  if (e.origin.indexOf('legit.com') === -1) return;
  eval(e.data.code);
});

// VULN — startsWith bypass: https://legit.com.evil
window.addEventListener('message', (e) => {
  if (!e.origin.startsWith('https://legit.com')) return;
  location.href = e.data.redirect;
});

// VULN — unanchored regex; www.google.com.evil.com matches
const ok = /^https?:\/\/(mail|www)\.google\.com/.test(e.origin);

// SAFE — exact equality (include port when non-default)
window.addEventListener('message', (e) => {
  if (e.origin !== 'https://legit.com') return;
  applyConfig(e.data);
});
```

### event.source validation

```javascript
// VULN — origin check present but wrong window accepted after opener swap
window.addEventListener('message', (e) => {
  if (e.origin !== 'https://child.example.com') return;
  childFrame.contentWindow.postMessage(e.data, '*');
});

// SAFE — verify source matches the known iframe element's contentWindow
window.addEventListener('message', (e) => {
  if (e.origin !== 'https://child.example.com') return;
  if (e.source !== childFrame.contentWindow) return;
  handleChildMessage(e.data);
});
```

### Python (PyWebView / embedded browser bridges)

```python
# VULN — bridge forwards web message payload to Python without origin gate
def on_message(message):
    run_action(message['cmd'], message['args'])

# SAFE — reject unless origin matches embedded app URL
ALLOWED_ORIGIN = 'https://app.example.com'
def on_message(message, origin):
    if origin != ALLOWED_ORIGIN:
        return
    run_action(message.get('cmd'), message.get('args'))
```

## Safe Patterns

- **Strict origin allowlist**: `e.origin === 'https://app.example.com'` or `ALLOWED_ORIGINS.has(e.origin)` on **every** path before reading `e.data`; include non-default ports explicitly.
- **Never `'*'` targetOrigin** when the message carries secrets, tokens, or PII — pass the exact expected recipient origin string.
- **Validate `e.source`**: compare to `iframe.contentWindow` / `window.opener` reference captured when the trusted child was created; reject unknown sources even if origin string matches (tab-nabbing / window reuse).
- **Treat `e.data` as untrusted input**: parse with schema validation; use `textContent` / structured data only; encode for sink context per `xss.md` if HTML is required.
- **Prefer MessageChannel** for dedicated parent↔child pairing when both sides are first-party — still validate origin on the initial handshake message.
- **Reply with explicit targetOrigin**: `event.source.postMessage(reply, event.origin)` only after origin and source checks pass — never `'*'` on the response.
- **Minimal message surface**: accept only typed commands (`{ type: 'resize', height: number }`); reject unexpected keys before merge/assign onto globals or config objects.

## Severity / Triage

- `event.data` → `eval` / `innerHTML` / `location.href` with **no** origin check → **High–Critical** (cross-origin script injection or open redirect).
- `postMessage(secrets, '*')` on pages handling auth/session → **High** (cross-origin secret leak to any recipient origin).
- **Reply includes `location.href` / full URL** (no/weak origin check), especially on OAuth callback, login, or shared site chrome → **High–Critical** (authorization-code / access-token theft gadget). **Do not** downgrade to Info because there is no XSS sink.
- Weak `indexOf` / `startsWith` / unanchored regex with sensitive actions → **Medium–High** (bypassable with crafted hostnames).
- Origin check present, `e.data` only drives non-executable UI state (validated enum), strict schema → **Low** or **FALSE POSITIVE**.
- Listener on static public widget with only `postMessage({ height: n })` and strict origin + no secrets/URLs in replies → **Info** (defense-in-depth still recommend exact match).

## Common False Alarms

- Listeners that return immediately unless `e.origin === '<constant>'` (or Set.has) on all paths — including early returns before any `e.data` access.
- `postMessage` with hardcoded non-wildcard targetOrigin matching the iframe's static `src`.
- Same-origin-only messaging (`window.postMessage(data, window.location.origin)`) on pages with no cross-origin embeds — low cross-origin exposure (still avoid wildcards).
- Workers / service workers using `MessagePort` between same-origin contexts only — different threat model unless port is transferred cross-origin.
- Test mocks that stub `event.origin` in unit tests — not production code paths.

## Cross-References

- `xss.md` — DOM/JS sink catalog and context encoding when `event.data` reaches markup or script execution (postMessage is listed as a DOM source; this file covers origin-validation gaps).
- `xs_leaks.md` — `postMessage(..., '*')` leaking session oracles; complementary leak-class guidance.
- `oauth_oidc_misconfiguration.md` — OAuth non-happy paths that keep `code`/token in the URL; chain with URL-echo gadgets here.
- `cors_misconfiguration.md` — similar weak origin/substring validation anti-patterns on HTTP responses.
- `ssrf.md` — full IPv4/IPv6 host-encoding normalization table (`2130706433`/`0x7f000001`/`127.1` → `127.0.0.1`); the same "parse and canonicalize the host, never regex the raw string" rule applies to `targetOrigin`.
- `clickjacking.md` — attacker iframe embedding may enable cross-origin messaging targets when combined with missing frame protections.

## Core Principle

Every `message` listener must reject messages whose `event.origin` is not an exact allowlisted origin (scheme + host + port) before reading `event.data`, and every `postMessage` send must use an explicit targetOrigin — never `'*'` — when the payload is sensitive; treat message bodies as untrusted input at downstream sinks.
