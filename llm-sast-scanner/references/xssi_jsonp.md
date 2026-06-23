---
name: xssi-jsonp
description: Cross-Site Script Inclusion (XSSI) and JSONP — server endpoints that wrap sensitive JSON in executable JavaScript (callback/jsonp parameters, application/javascript responses) enabling cross-origin data theft via script tags (CWE-345, CWE-200)
---

# Cross-Site Script Inclusion / JSONP (CWE-345 / CWE-200)

Browsers enforce the Same-Origin Policy on `fetch` and XHR, but **not** on classic `<script src="…">` inclusion: any page can load a cross-origin URL as script and execute the response body as JavaScript. When a server reflects user-specific data inside a JavaScript response — JSONP wrappers (`callback(JSON)`), dynamic `.js` files embedding session tokens, or JSON arrays served as executable script — an attacker page steals that data by including the URL in a script tag. This is Cross-Site Script Inclusion (XSSI); JSONP is the canonical callback-parameter variant. Static analysis should flag server routes that combine **authentication/session context**, **reflected callback names**, and **`Content-Type: application/javascript`** (or `text/javascript`).

## What It Is / Is Not

- **Is**: JSONP/callback endpoints reflecting `?callback=` / `?jsonp=` / `?showinfo=` into the response wrapper around sensitive or user-specific JSON; `res.jsonp(...)` and framework helpers emitting executable JS; dynamic `.js` routes embedding CSRF tokens, user IDs, or PII; global-variable assignment endpoints (`var userData = {…}`) includable cross-origin; authenticated GET returning JavaScript bodies with secrets.
- **Is not**: JSON API responses with `Content-Type: application/json` and no script execution path — not XSSI (may still be IDOR/CORS issues). CSRF token in a **JSON** body fetched with credentialed CORS — separate class. XSS from reflecting callback into **HTML** pages — see `xss.md`. CSP `script-src` whitelisting of JSONP hosts — see `content_security_policy.md` (defense bypass context).
- **Highest signal** when the response body interpolates **session-bound or user-specific data** and the route is reachable via GET without anti-hijack guards.

## Source -> Sink Pattern

**Sources**
- Query parameters: `callback`, `jsonp`, `jsoncallback`, `showinfo`, `cb`, `_callback`
- Request context: session cookie, authenticated user object, CSRF token, API keys embedded in server-rendered JS
- Route handlers explicitly setting JavaScript content types on personalized responses

**Sinks**
- Response body template: `res.send(callback + '(' + JSON.stringify(data) + ')')`
- Express / Connect: `res.jsonp(data)` — reflects `callback` query param into wrapper
- Spring / Java: `@RequestMapping(produces = "application/javascript")` with `@ResponseBody String` built from `callback` param + user JSON
- PHP: `header('Content-Type: application/javascript'); echo $_GET['callback'].'('.json_encode($user).');'`
- Global assignment: `res.send('var CONFIG = ' + JSON.stringify(userConfig) + ';')` served as `.js`
- Template literals in `.js` route files: `` `window.__INITIAL_STATE__ = ${JSON.stringify(state)}` ``

**Impact path (browser, not server-side)**
- Attacker page: `<script src="https://victim.example/api/user?callback=steal"></script>` — victim browser sends cookies; response executes in attacker origin context as JS, exfiltrating data via attacker-defined callback function name or side effects.

**Aggravating context**
- Session cookies without `SameSite=Strict` on GET JSONP endpoints
- Legacy API compatibility endpoints left enabled alongside modern JSON APIs
- Admin or billing data returned through JSONP for old jQuery clients

## Recon Indicators (Grep)

```bash
# JSONP / callback parameter handling
rg -ni 'callback|jsonp|jsoncallback|showinfo' --glob '*.{js,ts,jsx,tsx,py,rb,go,java,php,cs}'
rg -n 'res\.jsonp\s*\(' --glob '*.{js,ts}'
rg -n 'application/javascript|text/javascript' --glob '*.{js,ts,py,rb,go,java,php,cs}'

# Response wrapper patterns
rg -n "['\"]\\s*\\+\\s*JSON\\.stringify|JSON\\.stringify\\([^)]+\\)\\s*\\+\\s*['\"]" --glob '*.{js,ts,py,rb,php}'
rg -n 'function\s*\$\{?\s*callback|`\$\{callback\}\(' --glob '*.{js,ts,py,rb,php,java}'

# Dynamic JS embedding secrets / session data
rg -n 'var\s+\w+\s*=\s*.*(token|csrf|session|user|secret)' --glob '*.{js,ts,py,rb,php,ejs,hbs}'
rg -n '__INITIAL_STATE__|__PRELOADED_STATE__|window\.\w+\s*=' --glob '*.{js,ts,jsx,tsx,ejs,hbs}'

# Client templates pulling cross-origin script data
rg -n '<script\s+[^>]*src=\{?[^}]*\}?' --glob '*.{jsx,tsx,vue,svelte,ejs,hbs}'
rg -n '<script[^>]+src=["'"'"'][^"'"'"']*\?(callback|jsonp)=' --glob '*.{html,ejs,hbs,erb,vue}'

# Anti-hijack guard presence (negative signal when absent on sensitive JSON routes)
rg -n "\)\]\}'|while\s*\(\s*1\s*\)|&&&" --glob '*.{js,ts,py,rb,go,java,php}'
```

Trace each callback/jsonp hit to whether the wrapped payload includes user-specific fields and whether authentication is required.

## Vulnerable Conditions

- Route reflects `req.query.callback` (or alias) into response without strict identifier validation — allows `callback=alert` or attacker function names.
- `res.jsonp(userProfile)` on authenticated endpoints — any origin can `<script src=…>` include and read profile JSON.
- `Content-Type: application/javascript` (or `text/javascript`) on responses containing session tokens, CSRF secrets, email, or account IDs.
- `.js` asset endpoint dynamically generated per user/session and cacheable at a predictable URL.
- Sensitive JSON array/object served as executable JS without `)]}'` or similar non-executable prefix — classic Flash-era array XSSI still relevant for legacy parsers.
- GET endpoint returns JavaScript wrapper around data that should require CORS + explicit credentialed fetch.
- Template exposes `<script src="{{ apiUrl }}/data?callback=handleData">` where `apiUrl` is cross-origin and response is user-specific.

## Vulnerable vs Safe code examples

### Express JSONP

```javascript
// VULN — reflects callback; wraps authenticated user object as executable JS
app.get('/api/profile', (req, res) => {
  if (!req.session.userId) return res.status(401).end();
  res.jsonp(getProfile(req.session.userId));
});

// SAFE — JSON only; no script wrapper; CORS allowlist if cross-origin needed
app.get('/api/profile', (req, res) => {
  if (!req.session.userId) return res.status(401).end();
  res.type('application/json').send(JSON.stringify(getProfile(req.session.userId)));
});
```

### Manual callback reflection

```javascript
// VULN — callback name and body both attacker-influenced / includable
app.get('/api/data', (req, res) => {
  const cb = req.query.callback || 'cb';
  res.type('application/javascript');
  res.send(`${cb}(${JSON.stringify(getUserData(req))})`);
});

// SAFE — strict callback identifier + still prefer eliminating JSONP entirely
const CALLBACK_RE = /^[a-zA-Z_$][\w.$]*$/;
app.get('/api/public-feed', (req, res) => {
  const cb = req.query.callback;
  if (!cb || !CALLBACK_RE.test(cb)) return res.status(400).end();
  res.type('application/javascript');
  res.send(`${cb}(${JSON.stringify(getPublicFeed())})`); // no secrets in public feed only
});
```

### Dynamic JS with session secrets

```javascript
// VULN — any site can script-include this URL and read CSRF + user id
app.get('/config.js', (req, res) => {
  res.type('application/javascript');
  res.send(`window.APP_CONFIG = ${JSON.stringify({
    csrf: req.session.csrfToken,
    userId: req.session.userId,
  })};`);
});

// SAFE — serve non-secret bootstrap only; fetch secrets via same-origin JSON API
app.get('/config.js', (req, res) => {
  res.type('application/javascript');
  res.send('window.APP_CONFIG = { apiBase: "/api" };');
});
```

### Python (Flask / Django)

```python
# VULN — JSONP-style wrapper around private data
@app.route('/api/account')
def account_jsonp():
    cb = request.args.get('callback')
    data = get_account(session['user_id'])
    return Response(f'{cb}({json.dumps(data)})', mimetype='application/javascript')

# SAFE — JSON with nosniff; anti-hijack prefix on legacy JSON GET if needed
@app.route('/api/account')
def account_json():
    data = get_account(session['user_id'])
    body = ")]}'\n" + json.dumps(data)
    resp = Response(body, mimetype='application/json')
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    return resp
```

### Global variable XSSI (non-JSONP)

```javascript
// VULN — sensitive array served as JS; includable cross-origin
app.get('/api/friends.js', (req, res) => {
  res.type('application/javascript');
  res.send('var FRIENDS = ' + JSON.stringify(getFriends(req.session.userId)) + ';');
});

// SAFE — JSON endpoint with Content-Type application/json + nosniff
app.get('/api/friends', (req, res) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.json(getFriends(req.session.userId));
});
```

## Safe Patterns

- **Serve data as JSON** with `Content-Type: application/json` — never `application/javascript` for API payloads containing user or session data.
- **Eliminate JSONP** — replace with CORS-enabled JSON endpoints and explicit credentialed `fetch` from allowed origins.
- **Never embed secrets/PII** in script-includable responses (`.js` routes, JSONP wrappers, inline config blobs reachable via predictable GET URLs).
- **Anti-hijack prefix** on JSON GET responses when legacy clients require non-JSONP arrays: prefix body with `)]}'\n` or `while(1);` so script inclusion does not yield valid executable assignments (defense-in-depth — not a substitute for auth + JSON content type).
- **CSRF tokens** delivered via same-origin JSON POST responses or hidden form fields — not ambient JSONP GET callbacks.
- **`X-Content-Type-Options: nosniff`** on all JSON and dynamic JS responses — reduces content-sniffing escalation.
- **Callback allowlist** when JSONP cannot be removed immediately: validate `callback` matches `/^[a-zA-Z_$][\w.$]*$/` and wrap **public, non-user-specific** data only.
- **SameSite cookies** (`Strict` or `Lax`) on session cookies — limits cross-site script inclusion with cookies on some browsers; do not rely on this alone.
- **Require non-GET** or custom headers for sensitive reads — script tags cannot set arbitrary headers.

## Severity / Triage

- Authenticated JSONP / callback endpoint returning PII, tokens, or account data → **High–Critical** (one-click cross-origin data theft via `<script src>`).
- Public JSONP on non-sensitive feed with strict callback regex and no session fields → **Low** (legacy pattern; deprecate).
- Dynamic `.js` embedding CSRF token only (no PII) → **Medium** (CSRF token theft enables forged state-changing requests).
- `application/json` + `nosniff` + no callback reflection + CORS not misconfigured → **FALSE POSITIVE** for XSSI.
- Static public `.js` bundle with no interpolated user/session data → **Info** (not XSSI).

## Common False Alarms

- Public static JS files on CDN with fixed content and no server-side user interpolation.
- JSON API returning `application/json` without callback wrapping — not script-executable via inclusion semantics.
- JSONP endpoints returning **hardcoded public** data (weather, locale strings) with no auth and no secrets — low impact; still flag for deprecation.
- Callback parameter validated to safe identifier **and** response contains no user-specific fields — reduced risk but prefer removal.
- Server-side `jsonp` library used only in tests or disabled feature flags — confirm route not mounted in production.

## Cross-References

- `content_security_policy.md` — whitelisting JSONP hosts in `script-src` as CSP bypass gadget.
- `xss.md` — when callback names or JSON fragments reflect into HTML contexts instead of JS responses.
- `csrf.md` — stolen CSRF tokens from XSSI enable forged requests; JSONP GET mutations are related CSRF surface.
- `cors_misconfiguration.md` — preferred replacement pattern (CORS + JSON instead of JSONP).
- `information_disclosure.md` — broader sensitive data exposure taxonomy.
- `insecure_cookie.md` — `SameSite` and cookie scope affecting script-inclusion with credentials.

## Core Principle

Never serve user-specific or secret-bearing data inside executable JavaScript responses or JSONP callback wrappers reachable via cross-origin `<script src>`; use `application/json` with proper auth, CORS where needed, anti-hijack prefixes on legacy JSON, and `X-Content-Type-Options: nosniff` — eliminate JSONP rather than hardening it.
