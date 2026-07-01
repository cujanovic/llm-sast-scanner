---
name: xs_leaks
description: Cross-Site Leaks (XS-Leaks) — inferring cross-origin user state via side channels and missing browser isolation headers
---

# Cross-Site Leaks (XS-Leaks)

XS-Leaks let an attacker origin learn whether a victim is logged in, which account they use, or other cross-site state by observing subtle browser signals — not by reading response bodies directly. Side channels include timing, frame counts, navigation/error events, status-code oracles, cache hits, and browser API behavior. Static analysis targets endpoints whose responses differ by auth state without isolation, and missing mitigations (SameSite cookies, COOP/COEP/CORP, Fetch Metadata, cache/framing controls).

*The core pattern: a cross-origin page can probe a victim origin and distinguish authenticated vs unauthenticated (or user A vs user B) outcomes through an observable side channel — and the victim response lacks headers or cookie attributes that block the probe.*

## What It Is (and Is Not)

**What it IS**
- **Status-code / error oracles**: same URL returns `200` when logged in and `404`/`403`/`302` when not — attacker embeds resource and reads `onload` vs `onerror`
- **Navigation / frame oracles**: iframe `load`/`error`, `window.open` blocked vs allowed, popup `closed` timing — reveals whether a route exists or session is valid
- **Frame counting**: nested iframes or `window.length` changes when victim page loads child frames — infers login state or page type
- **Timing oracles**: `performance.now()` around cross-origin fetches, image loads, or `fetch()` with `no-cors` — duration differs by auth/cache/state
- **Cache probing**: attacker loads victim URL, then measures reload latency or `304` behavior to infer whether victim previously cached a personalized resource
- **Size / type oracles**: cross-origin `fetch`/`no-cors` or `<img>` error vs success correlates with response length or content-type differences across auth states
- **GraphQL response-size oracle (alias-padding + APQ delivery)**: a credentialed cross-origin request to a cookie-authed GraphQL endpoint becomes a per-character secret oracle — the attacker inflates a *matching* response with hundreds/thousands of **field aliases** (`h1:text h2:text …`, all selecting the same secret-bearing field, e.g. `searchNotes(query:"prefix"+candidate)`) so a match returns tens of KB while a non-match stays tiny, then reads the difference via the **Resource Timing API** (`performance.getEntriesByName(url)[0].duration`/`transferSize` — download time scales with size), one char per probe. Made practical by **Automatic Persisted Queries**: the attacker POST-seeds the giant aliased query server-side (cached by `sha256Hash`) from their own server, then the victim fires a tiny **GET** `?extensions={"persistedQuery":{"sha256Hash":…}}` that fits under URL-length limits, skips body parsing, and — with a CORS-safelisted `Content-Type` — skips preflight. **SAST signal**: a cookie-authenticated GraphQL endpoint reachable via GET or with APQ enabled and **no** per-alias/duplicate-field cap, `Origin`/Fetch-Metadata check, or response-size normalization. Cross-ref `graphql_dos.md` (alias amplification for DoS — the same primitive), `csrf.md` (GET/CSRF gating), `graphql_injection.md`.
- **Browser API leaks**: `window.name` persistence, `BroadcastChannel`, `localStorage` partition gaps, `SharedArrayBuffer` timing (when isolation headers absent) — cross-page state readable from attacker context
- **Missing isolation headers**: no `Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy`, `Cross-Origin-Resource-Policy`, or Fetch Metadata enforcement on state-bearing routes
- **Session cookies without SameSite**: credentialed cross-site subresource or navigation requests carry session — enables authenticated oracle probes

**What it is NOT**
- **Direct cross-origin response body read** — blocked by Same-Origin Policy; XS-Leaks infer state indirectly
- **Classic CSRF** — CSRF performs an action; XS-Leaks read state. Tag `csrf.md` when the primary issue is missing CSRF token on a state-changing POST
- **Clickjacking alone** — UI redress for clicks; tag `clickjacking.md` when framing is the sole gap with no state oracle. XS-Leaks often overlap framing but root cause is observable cross-site differentiation
- **CORS misconfiguration with body read** — `Access-Control-Allow-Origin` reflection enabling credentialed JSON read is `cors_misconfiguration.md`, not XS-Leaks
- **Web cache deception cross-user body replay** — shared cache serving victim HTML to attacker is `web_cache_deception.md`; XS-Leaks cache probing is attacker measuring their own cache interaction with victim URLs
- **Information disclosure in response body** — explicit secret/PII in JSON/HTML is `information_disclosure.md` unless the finding is specifically the cross-site *oracle* mechanism

## Recon Indicators

### State-bearing endpoints (grep / route review)

| Signal | Targets |
|--------|---------|
| Auth-gated routes | `/api/me`, `/account`, `/profile`, `/dashboard`, `/settings`, `/logout`, `/login/status`, `/user/`, `/session` |
| Conditional responses | handlers branching on `req.user`, `isAuthenticated`, `session`, `401`/`403`/`404`/`302` by login state |
| Personalized static paths | `/images/avatar`, `/users/{id}/photo`, `/export`, `/download` — same path shape, body varies by session |
| JSON error shape oracle | `{ "error": "Unauthorized" }` vs `{ "error": "Not found" }` for existence vs auth probes |
| Login-only redirects | `302` to login when anonymous, `200` when authenticated on same path |

### Missing cookie isolation (grep)

```javascript
// VULN — session cookie without SameSite
res.cookie('session', token, { httpOnly: true, secure: true }); // SameSite omitted

// VULN — SameSite=None without deliberate cross-site need
sameSite: 'none'
```

Grep: `Set-Cookie` without `SameSite`, `sameSite:\s*(true|false|null)`, `cookie:\s*\{[^}]*\}` blocks missing `sameSite`, `document\.cookie\s*=.*(?!SameSite)`.

### Missing framing / embedding isolation (grep)

Grep absence of: `X-Frame-Options`, `frame-ancestors`, `Content-Security-Policy.*frame-ancestors` on HTML or oracle routes.

```javascript
// VULN — sensitive route with no frame-ancestors / XFO
app.get('/account', (req, res) => { res.send(renderAccount(req.user)); });
```

Cross-ref `clickjacking.md` — framing enables iframe-based oracles.

### Missing cross-origin isolation headers (grep)

| Header | Grep for absence on app/middleware |
|--------|-------------------------------------|
| COOP | `Cross-Origin-Opener-Policy`, `crossOriginOpenerPolicy`, `cross-origin-opener-policy` |
| COEP | `Cross-Origin-Embedder-Policy`, `crossOriginEmbedderPolicy` |
| CORP | `Cross-Origin-Resource-Policy`, `crossOriginResourcePolicy` |

```javascript
// VULN — global middleware sets security headers but omits COOP/CORP on API routes
app.use(helmet()); // default may not set COOP/CORP/COEP on all responses
```

### Missing Fetch Metadata enforcement (grep)

```javascript
// VULN — sensitive endpoint with no Sec-Fetch-* gate
app.get('/api/me', auth, (req, res) => res.json(req.user));

// SAFE — reject cross-site subresource/navigation probes
const site = req.get('Sec-Fetch-Site');
const dest = req.get('Sec-Fetch-Dest');
if (site === 'cross-site' && dest !== 'document') return res.sendStatus(403);
```

Grep: `Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest`, `sec-fetch-site` — flag sensitive routes with **no** such checks in middleware or handler.

### Cache oracle enablement (grep)

```javascript
// VULN — personalized response publicly cacheable
res.setHeader('Cache-Control', 'public, max-age=3600');
res.json({ user: req.user });

// VULN — static URL for per-user resource (cache probing)
app.get('/avatar.png', (req, res) => sendUserAvatar(req.session.userId));
```

Grep: `Cache-Control.*public` on authenticated handlers, missing `no-store`/`private` on `/api/`, `/account`, `/me`, avatar/profile routes; `Vary` omitting `Cookie`/`Authorization` on personalized responses. Cross-ref `web_cache_deception.md`.

### Client-side cross-origin probes (grep — victim app enables oracles)

Not attacker code — review victim handlers that return **different status codes or timing** for anonymous vs authenticated callers on embeddable/cacheable routes:

```javascript
// VULN — existence oracle: 404 when logged out, 200 when logged in
if (!req.user) return res.status(404).end();
return res.sendFile('/private/resource');
```

### postMessage / window.name vectors (grep)

```javascript
// VULN — broadcasts sensitive state; readable cross-origin via name reuse
window.name = JSON.stringify({ loggedIn: true, userId });
window.postMessage(sessionData, '*');
```

Grep: `window\.name\s*=`, `postMessage\([^,]+,\s*['"]\*['"]\)` on pages that set auth/session state.

## Vulnerable Conditions

- Session or auth cookies set without explicit `SameSite=Strict` or `SameSite=Lax` on state-bearing apps
- Sensitive GET routes return distinguishable status codes, redirect targets, or error bodies for anonymous vs authenticated users
- HTML or API routes that reveal login state are embeddable cross-origin (no `frame-ancestors` / `X-Frame-Options`)
- No Fetch Metadata check (`Sec-Fetch-Site`, `Sec-Fetch-Dest`, `Sec-Fetch-Mode`) on endpoints probed via `<img>`, `<script>`, `fetch(no-cors)`, or iframe
- Personalized responses use `Cache-Control: public` or static URLs without per-user cache busting — enables cache probing
- `Cross-Origin-Resource-Policy` absent on resources probed cross-origin; `Cross-Origin-Opener-Policy` absent on pages using `window.open`/`opener` chains
- Per-user images, exports, or JSON at predictable paths return `200` vs `404`/`403` based on victim session — classic image/script oracle
- Application relies on "security through obscurity" URL patterns (`/api/internal/check-auth`) without isolation headers — still probeable
- `postMessage(..., '*')` or sensitive data in `window.name` on auth/account pages
- Global error handlers map auth failures to unique status codes (`401` vs `404`) on resources attackers can embed

## Safe Patterns

**Cookies**
- Set `SameSite=Strict` (or `Lax` when top-level navigation needs cookies) on all session cookies; use `SameSite=None; Secure` only for intentional third-party embeds
- `HttpOnly` + `Secure` on session cookies — limits script exfiltration (does not alone stop oracles)

```javascript
res.cookie('session', id, { httpOnly: true, secure: true, sameSite: 'strict' });
```

**Framing / subresource isolation**
- `Content-Security-Policy: frame-ancestors 'self'` and/or `X-Frame-Options: SAMEORIGIN` on pages that expose auth state
- `Cross-Origin-Resource-Policy: same-origin` (or `same-site`) on sensitive static and API responses

```javascript
res.setHeader('Content-Security-Policy', "frame-ancestors 'self'");
res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
```

**Browsing context isolation**
- `Cross-Origin-Opener-Policy: same-origin` — severs `window.opener` leaks
- `Cross-Origin-Embedder-Policy: require-corp` where cross-origin isolation is required (e.g. SharedArrayBuffer hardening)

```javascript
res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
```

**Fetch Metadata gates**
- Deny cross-site requests to sensitive endpoints unless explicitly required; block `Sec-Fetch-Dest: iframe` from cross-site on auth pages

```javascript
function xsLeakGuard(req, res, next) {
  if (req.get('Sec-Fetch-Site') === 'cross-site' && req.path.startsWith('/api/'))
    return res.sendStatus(403);
  next();
}
```

**Cache isolation**
- `Cache-Control: no-store` (or `private, no-store`) on personalized responses; per-user cache keys or URL nonces for user-specific static assets

```javascript
res.setHeader('Cache-Control', 'no-store');
const avatarUrl = `/avatar/${userId}?t=${sessionNonce}`;
```

**Oracle hardening**
- Return uniform status codes and error shapes for anonymous and wrong-user probes where possible (`404` for both unknown and unauthorized)
- Prefer POST + CSRF for existence checks; avoid auth-differentiated GET on embeddable content types

```javascript
// SAFE — indistinguishable denial
if (!authorized(req, resource)) return res.status(404).end();
```

**postMessage**
- Target fixed origin; verify `event.origin` on receive

```javascript
window.postMessage(data, 'https://app.example.com');
window.addEventListener('message', (e) => {
  if (e.origin !== 'https://app.example.com') return;
});
```

## Common False Alarms

- Public, intentionally anonymous endpoints (`/health`, `/public/status`) that differ by design but carry no user-specific state — not an oracle
- `SameSite=Lax` on apps that only need top-level navigation cookies — acceptable unless strict isolation is required for sensitive actions
- API-only JSON services never loaded as cross-origin subresources (`<img>`, iframe) — lower XS-Leak risk; confirm no embeddable HTML wrappers exist
- COOP/COEP/CORP set at CDN/reverse proxy but absent in application source — verify infra before reporting missing-header findings
- `404` vs `403` on non-session resources with no attacker-observable cross-origin probe path (CORP `same-origin` already set) — defense may be sufficient
- Endpoints already protected by Fetch Metadata middleware globally — grep may miss centralized guard; trace middleware chain
- Intentional third-party embed widgets with `SameSite=None` and documented cross-site need — not a cookie finding without evidence of oracle abuse
- Uniform error responses already implemented — absence of COOP alone is defense-in-depth, not always reportable without a demonstrated side channel
- CSRF tokens on mutating routes — irrelevant to read-only GET oracles; do not downgrade XS-Leak gaps because CSRF protection exists elsewhere
