---
name: csrf
description: CSRF testing covering token bypass, SameSite cookies, CORS misconfigurations, and state-changing request abuse
---

# CSRF

Cross-site request forgery exploits ambient authority — cookies and HTTP authentication — by issuing requests across origins on behalf of a victim. CORS alone is not a sufficient defense; every state-changing operation must require a non-replayable token and enforce strict origin validation.

## Where to Look

**Session Types**
- Web applications using cookie-based sessions and HTTP authentication
- JSON/REST endpoints, GraphQL (GET or persisted queries), and file upload surfaces

**Authentication Flows**
- Login, logout, password and email change, MFA enable/disable

**OAuth/OIDC**
- Authorize, token, logout, and connect/disconnect endpoints

## High-Value Targets

- Credential and profile updates (email/password/phone)
- Payment processing, money transfers, subscription and plan changes
- API key and secret generation, PAT rotation, SSH key management
- 2FA/TOTP enable and disable; backup codes; device trust
- OAuth connect/disconnect; logout; account deletion
- Admin and staff actions, impersonation workflows
- File uploads and deletions; access control modifications

## Reconnaissance

### Session and Cookies

- Examine cookies for HttpOnly, Secure, and SameSite attributes (Strict/Lax/None)
- Lax permits cookies on top-level cross-site GET navigation; None requires the Secure attribute
- Determine whether Authorization headers or bearer tokens are in use (generally not CSRF-prone) versus cookies (CSRF-prone)

### Token and Header Checks

- Find anti-CSRF tokens in hidden inputs, meta tags, or custom headers
- Test removal, indefinite reuse, cross-session reuse, and binding to specific methods or paths
- Verify the server validates Origin and/or Referer on all state-changing operations
- Try null, missing, and cross-origin header values

### Method and Content-Types

- Determine whether GET, HEAD, or OPTIONS trigger any state changes
- Attempt simple content-types that avoid CORS preflight: `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`
- Test parsers that automatically coerce `text/plain` or form-encoded bodies into JSON

### CORS Profile

- Identify `Access-Control-Allow-Origin` and `-Credentials` header values
- Permissive CORS configurations do not remediate CSRF and can escalate it into data exfiltration
- Test per-endpoint CORS behavior; preflight and simple request handling can diverge within the same application

## Vulnerability Patterns

### Configuration-Level CSRF Disable

Automated checks flag **framework CSRF protection disabled or weakened**, not per-endpoint missing tokens in all stacks:

| Pattern | Languages |
|---------|-----------|
| Spring `.csrf().disable()` / `csrf.disable()` in `SecurityFilterChain` | Java |
| Django `CSRF_*` verification disabled globally without local override | Python |
| Rails `protect_from_forgery` verification off or weak `:null_session` downgrade | Ruby |
| Express cookie session routes without `csurf`/`lusca`/`express.csrf` middleware | JavaScript |
| ASP.NET MVC/Core POST actions missing `[ValidateAntiForgeryToken]` when project uses tokens elsewhere | C# |
| OAuth2 `AuthCodeURL` with constant `state` parameter | Go |
| Spring/Stapler state change via safe HTTP method (GET/HEAD) | Java |
| JSONP callback parameter reflected in GET response without validation | Java |

### Navigation CSRF

- An auto-submitting form targeting the victim origin succeeds when cookies are automatically sent and no token or origin check is enforced
- Top-level GET navigation can cause state changes when the server misuses the GET method or wires actions to GET callbacks

### Simple Content-Type CSRF

- `application/x-www-form-urlencoded` and `multipart/form-data` POST requests never trigger a CORS preflight
- `text/plain` form bodies can slip past request validators and be parsed server-side as legitimate input

### JSON CSRF

- When a server parses JSON from `text/plain` or form-encoded bodies, craft parameters that reconstruct the expected JSON structure
- Some frameworks accept JSON keys expressed as form fields (e.g., `data[foo]=bar`) or handle duplicate keys permissively
- **Trailing-`=` form artifact + non-strict deserialization.** An auto-submitting HTML form with `enctype="text/plain"` forces a preflightless `text/plain` body, but the browser serializes inputs as `name=value`, so a single field appends a stray `=`: the body becomes `{"email":"x@a.test"}=` → **invalid JSON**, and a strict parser rejects it. The reliable bypass splits a valid JSON payload across the field **name and value** so the `=` lands *inside a throwaway string*: form `name={"x":"y` + value `","email":"x@a.test"}` serializes to `{"x":"y=","email":"x@a.test"}` — **valid JSON**. This works **only if the backend tolerates unknown/extra keys** (lenient deserialization). Therefore a JSON endpoint that (a) parses simple-content-type bodies and (b) **ignores unknown properties** is reliably CSRF-forgeable from a plain HTML form with no JS/CORS.
- **SAST signal**: lenient deserialization on a cookie-authed state-changing JSON handler is the enabler — Jackson default / `FAIL_ON_UNKNOWN_PROPERTIES=false` or `@JsonIgnoreProperties(ignoreUnknown=true)`; Go `json.Unmarshal` / `Decoder` without `DisallowUnknownFields()`; Python `pydantic` `extra="allow"`/`extra="ignore"`, plain `json.loads`, DRF serializers ignoring unexpected keys; .NET `System.Text.Json` default (unknown members ignored); Express/`body-parser` accepting any type. Strict schema validation (reject unknown keys) removes the *reliability* of the form-based PoC but is **not** a CSRF control on its own — still require a token/Origin check.

### Content-Type is not a CSRF defense (parse-as-JSON-regardless bypasses)

A `Content-Type: application/json` body normally triggers a CORS preflight, so many apps treat "we only parse JSON" as implicit CSRF protection. That collapses whenever the body parser produces JSON for a request the browser still classifies as **simple** (no preflight). Three source-detectable shapes:

- **Missing `Content-Type` ⇒ framework defaults to JSON.** Some frameworks parse the body as JSON when *no* `Content-Type` header is present. An attacker sends the JSON body inside a `new Blob([...])` with no type, so the browser attaches **no** `Content-Type` → simple request, no preflight, parsed as JSON. The *absence* of a header is more permissive than sending one.
  ```javascript
  // VULN (server): no content-type ⇒ treat as JSON
  if (!request.headers.get('content-type')) body = await request.json();
  // Attack (browser): Blob with no type ⇒ no Content-Type header ⇒ simple request
  fetch('https://target/profile/update', { method:'POST', credentials:'include',
    body: new Blob([JSON.stringify({ email:'attacker@evil.test' })]) });
  ```
- **Parse-everything-as-JSON.** Body-parser configured to ignore the declared type, e.g. Express `express.json({ type: () => true })` (or `type: '*/*'`). Every request body is JSON-parsed, so any simple-content-type request reaches the handler as a parsed object.
- **Browser safelist drift / blocklist incompleteness.** Content-type-based defenses that **blocklist** the three spec "simple" types (`application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`) are incomplete by construction: a blocklist can only reject types it knows. Browsers have shipped additional non-preflighted content types beyond the WHATWG-spec three (e.g. a Chromium ads-API type), so a request carrying an unlisted but browser-safelisted `Content-Type` slips past both the preflight and the blocklist while the server still parses it. This also enables **GET-only** cross-origin GraphQL/query execution → **XS-Leak** (timing/size oracle) even when mutations are POST-gated.
- **Malformed `Content-Type` nulls the header (blacklist + parse divergence).** A subtler defeat of a Content-Type *blacklist*: the attacker sends one of the *blacklisted* simple types but **corrupts its parameters** so a strict RFC-7230-compliant HTTP layer fails to parse the header and hands the framework a **`None`/absent** `Content-Type`. The classic trigger is an invalid multipart `boundary` — `Content-Type: multipart/form-data; boundary=------;---------------------139...` (an extra `;`/duplicate parameter makes the boundary unparseable). A blacklist keyed on the *parsed* value (`if contentType in blackList: requireToken`) never fires when the parsed value is null, yet a lenient body parser still consumes the form/multipart body → state change with no token. This is distinct from the "no header" case above (here the attacker *does* send a header; it is **discarded upstream**) and from the safelisted-type case (this reuses a *listed* type, nullified by malformed syntax). **SAST signal**: a CSRF filter whose check is a Content-Type **blacklist**/`bypassHeaders`/`contentType.blackList` gate, sitting in front of a request pipeline whose HTTP layer strictly validates the multipart `boundary`/media-type grammar — a rejected header becomes "no content type," which the blacklist reads as safe. **SAFE**: don't treat an unparseable/absent Content-Type as trusted — fail closed (require token/`Origin` when the type can't be positively confirmed as non-simple), or use an allowlist of exactly the JSON/non-simple types you accept rather than a blacklist of simple ones.

**SAFE**: never rely on content-type checks alone. Require an anti-CSRF token (or a custom header that *forces* a preflight, e.g. `X-Requested-With` validated server-side), validate `Origin`/`Referer` against an allowlist, and set `SameSite=Lax/Strict` cookies. Treat any "we only parse JSON" comment near a state-changing handler with a permissive/declared-type-ignoring parser as a **VULN**.

**Grep seeds**: `express\.json\(\{\s*type:` (`() => true`, `'\*/\*'`); `if not content_type`/`if (!content-?type)` followed by JSON parse; CSRF middleware built as an allow/deny list of content types (`text/plain`, `urlencoded`, `multipart`) with no token/Origin check; `request.json()` reached without a token gate. Lenient deserialization enabling the form-PoC: `FAIL_ON_UNKNOWN_PROPERTIES`, `@JsonIgnoreProperties\(ignoreUnknown\s*=\s*true`, `DisallowUnknownFields` (absence), `extra\s*=\s*[\"'](allow|ignore)`.

### Login/Logout CSRF

- Force a victim logout to invalidate existing CSRF tokens, then chain a login CSRF to bind the victim's browser to an attacker-controlled account
- Login CSRF: POST attacker credentials into the victim's browser so subsequent actions execute under the attacker's identity

### OAuth/OIDC Flows

- Abuse authorize and logout endpoints that are accessible via GET or unauthenticated form POST without origin enforcement
- Exploit permissive SameSite behavior on top-level navigations to send authenticated requests cross-site
- Open redirects or loose `redirect_uri` validation can be chained with CSRF to force unintended authorization grants

### File and Action Endpoints

- File upload and deletion endpoints frequently omit token checks; forge multipart requests to manipulate stored content
- Admin actions exposed as simple POST links are often vulnerable to CSRF without additional protection

### GraphQL CSRF

GraphQL on cookie sessions shares the same CSRF model as REST: ambient credentials on **simple**, **preflightless** requests can execute state-changing operations when the server accepts mutations outside a protected JSON POST path. See also `graphql_injection.md` (GET mutations / CSRF section).

**Vulnerable conditions**:
- Mutations or state-changing operations accepted over **GET** — `?query=mutation{...}` or **`variables` in the query string** (`?query=...&variables={"id":1}`)
- **Simple POST** bodies accepted: `application/x-www-form-urlencoded`, `multipart/form-data`, or **`text/plain`** parsed as GraphQL (no CORS preflight)
- Apollo Server / Gateway with **`csrfPrevention: false`** (or equivalent CSRF middleware disabled) on a cookie-authenticated endpoint. **Note: `csrfPrevention: true` — the default — is *not* fully sufficient by itself.** Apollo's built-in check is **blacklist-based** (it demands a preflight-forcing header *only* when the `Content-Type` is one of the three spec "simple" types `application/x-www-form-urlencoded`/`multipart/form-data`/`text/plain`, or absent); a request carrying a **browser-safelisted-but-unlisted** `Content-Type` (e.g. Chromium's `message/ad-auction-trusted-signals-request`) passes the check yet still fires without preflight — enabling GET/query execution against the victim session and an **XS-Leak** (see the blocklist-incompleteness rule above and `xs_leaks.md`). Treat `csrfPrevention: true` as necessary-not-sufficient: also require `Origin`/Fetch-Metadata validation and POST-only mutations.
- CSRF token validated on **POST** only while **GET** (or form-encoded POST) still executes mutations
- Batched JSON arrays where a mutation hides beside ostensibly read-only operations
- **Broken GET-mutation guards**: operation type checked by string match (`query.trim().startsWith("mutation")`) — bypassed by a leading comment `#`, leading `%0a`/whitespace, case-jumbling (`mUtaTiOn`), or a doc holding both a query and a mutation; or the op-type gate keys on `request.method === 'GET'` while a URL `?query=` param (which takes precedence over the POST body) lets a **POST** `…/graphql?query=mutation{...}` run the mutation. See `graphql_injection.md` (GET-mutation restriction bypasses).

**Grep seeds**:
```bash
rg -n "methods.*GET|app\.get\s*\(.*graphql|router\.get.*graphql" --glob '*.{js,ts,py,go,java}'
rg -n "req\.query\.(query|variables)|request\.args\.get\(['\"]query|URLSearchParams.*variables" --glob '*.{js,ts,py}'
rg -n "csrfPrevention:\s*false|csrf.*false|disableCsrf" --glob '*.{js,ts}'
rg -n "text/plain|application/x-www-form-urlencoded" --glob '*.{js,ts,py}' -B2 -A2 | rg -n "graphql|mutation"
```

**VULN**:
```html
<!-- GET mutation with variables — victim cookies sent on navigation -->
<img src="https://target/graphql?query=mutation{deleteUser(id:1)}">
<img src="https://target/graphql?query=mutation($id:ID!){deleteUser(id:$id)}&variables=%7B%22id%22%3A1%7D">
```
```js
// VULN — CSRF token on JSON POST only; GET still runs mutations
app.post('/graphql', csrfProtection, graphqlHandler);
app.get('/graphql', graphqlHandler);  // no token, no Content-Type gate
```

**SAFE**: disallow GET (and HEAD) for mutations and other state-changing operations; require **`Content-Type: application/json`** plus synchronizer token or non-simple custom header (`X-CSRF-Token`, `X-Requested-With`) on cookie-authenticated routes; enable framework CSRF prevention (e.g. Apollo `csrfPrevention: true`); enforce the same policy on batch and persisted-query paths. Cross-ref `graphql_injection.md`.

#### Subscription / WebSocket CSRF vector

State-changing GraphQL operations over the **WebSocket subscription transport** bypass HTTP CSRF protections — synchronizer tokens, `csrfPrevention`, SameSite POST semantics, and custom-header gates apply to HTTP requests, not to framed WS messages after upgrade. Cookie-authenticated WS without `Origin` validation in `onConnect` lets a cross-origin page open the socket and send mutation payloads on behalf of the victim. Cross-ref `websocket_security.md` (GraphQL Subscriptions / WebSocket as CSRF-bypassing state-change vector), `graphql_injection.md` (Cross-Site WebSocket Hijacking / Transport Parity).

**Grep seeds**:
```bash
rg -n "useServer|SubscriptionServer|graphql-ws|subscriptions-transport-ws" --glob '*.{js,ts}' -A8
rg -n "onConnect|connectionParams" --glob '*.{js,ts}' -A4
```

**SAFE**: validate `Origin` on upgrade; require non-cookie token in `connectionParams`; enforce authz on WS mutations same as HTTP POST.

#### Request smuggling / CRLF as CSRF or auth bypass

CRLF injection or HTTP request smuggling in a **forwarded or proxied** GraphQL request can desync front-end vs back-end parsing so edge CSRF or auth controls apply to one view of the request while the backend executes another — e.g. unsanitized `query`, `variables`, or custom headers concatenated into forwarded request lines without neutralizing `\r`/`\n`. Treat user-controlled data placed into outbound proxy headers or raw request assembly as a smuggling risk that can reach state-changing operations without the intended CSRF token check. Cross-ref `http_response_splitting.md`, `smuggling_desync.md`.

**Grep seeds**:
```bash
rg -n "proxy_pass|proxy_set_header|forward.*header" --glob '*.{js,ts,conf}' -B2 -A3 | rg -n "query|variables|GraphQL"
rg -n "%0d|%0a|\\\\r|\\\\n|\\r\\n" --glob '*.{js,ts,py,java}' -B2 -A2 | rg -n "graphql|forward|proxy"
```

**CSRF-or-session OR-gate**: mutation gate `if (hasSession || hasCsrfToken) allow` where **both** the session and the CSRF token are freely obtainable by an anonymous client — CSRF token minted without login (public `csrfToken` query/mutation), or anonymous session from a bootstrap operation — so satisfying **either** branch is not real authentication. Also: CSRF token **not bound** to an authenticated session (cross-session reuse accepted). Cross-ref `graphql_injection.md` (Request Forgery / CSRF section).

**Vulnerable conditions**:
- `||` OR-logic combining session and CSRF checks on mutation authorization
- Public resolver issues CSRF token without requiring verified login
- Bootstrap/init operation mints a session cookie usable for privileged mutations
- CSRF accepted as **sole** gate when token is public and unbound

**Grep seeds**:
```bash
rg -n '\|\|' --glob '*.{js,ts,py}' -C2 | rg -i 'csrf|session|token'
rg -n 'csrfToken|getCsrfToken|issueCsrf' --glob '*.{graphql,graphqls,js,ts,py}'
rg -n 'hasSession|hasCsrf|csrfValid|sessionValid' --glob '*.{js,ts,py}' -C3
```

**VULN**:
```js
// VULN — either anonymous session OR pre-login CSRF satisfies gate
function allowMutation(ctx, req) {
  const hasSession = !!req.cookies.session || !!ctx.session;
  const hasCsrf = req.headers['x-csrf-token'] || ctx.csrfToken;
  if (hasSession || hasCsrf) return true;
  return false;
}
// VULN — CSRF issued without authenticated session binding
csrfToken: async (_, __, ctx) => {
  const token = randomBytes(32).toString('hex');
  ctx.csrfToken = token;  // not tied to session id or user
  return { csrfToken: token };
},
```

**SAFE**: require **both** verified identity **and** CSRF for sensitive mutations; bind CSRF token to the authenticated session (store keyed by session id; rotate on login); bootstrap endpoints must not mint a session usable for privileged operations.

### JSONP / XSSI (CSRF-adjacent data theft)

JSONP callback endpoints and sensitive responses served as **executable JavaScript** (`application/javascript`, `text/javascript`) are CSRF/XSSI-adjacent: a victim's browser sends ambient cookies on `<script src="...">` or cross-origin GET, and the response runs in the victim's origin context. This is not classic CSRF (no state change required) but shares the same cookie-backed trust model. See `xssi_jsonp.md` for callback reflection, Flash-based XSSI, and Angular JSONP gadget patterns.

**VULN conditions**:
- GET endpoint reflects `callback`/`jsonp`/`_callback` into `callbackName({...sensitive...})` body
- Authenticated JSON API returns `Content-Type: application/javascript` or wraps JSON in a user-supplied function call
- `Access-Control-Allow-Origin: *` or reflected origin on cookie-authenticated JSON read endpoints (pairs with CORS misconfig)

```javascript
// VULN — JSONP wraps private data; any site can load with victim cookies
app.get('/api/user', (req, res) => {
  const cb = req.query.callback;
  res.type('application/javascript').send(`${cb}(${JSON.stringify(req.user)})`);
});

// SAFE — JSON only, no ambient-auth JSONP, CSRF token on state-changing routes
app.get('/api/user', (req, res) => {
  res.type('application/json').json(req.user);
});
res.setHeader('X-Content-Type-Options', 'nosniff');
```

**Defense checklist**: serve `application/json` (not JS), disable JSONP on authenticated routes, require synchronizer tokens on unsafe methods, set `X-Content-Type-Options: nosniff` on JSON responses.

### WebSocket CSRF

- Browsers automatically include cookies on WebSocket upgrade requests
- Without server-side Origin enforcement, cross-site pages can establish authenticated WebSocket connections and trigger server-side actions
- **GraphQL over WS**: subscription transports accept mutations that bypass HTTP CSRF tokens — see GraphQL CSRF section above and `websocket_security.md`

## Evasion Patterns

### SameSite Nuance

- Lax-by-default cookies are transmitted on top-level cross-site GET but withheld on cross-site POST
- Focus on GET-based state changes and GET-triggered confirmation steps
- Older or nonstandard browsers may not respect SameSite; validate findings across multiple clients and devices

### Origin/Referer Obfuscation

- Sandboxed iframes generate a null Origin value; some frameworks incorrectly permit null as a valid origin
- Navigating from `about:blank` or `data:` URLs alters or removes the Referer header
- Confirm the server requires an explicit, non-null Origin or Referer match

### Method Override

- Backends that honor `_method` or `X-HTTP-Method-Override` may allow destructive mutations to be triggered via a simple POST

### Token Weaknesses

- Accepting missing or empty token values
- Tokens that are not bound to the session, user identity, or specific path
- Tokens that can be reused indefinitely, or tokens transmitted via GET parameters
- Double-submit cookies lacking Secure/HttpOnly, or using predictable token generation

### Content-Type Switching

- Alternate between form-encoded, multipart, and `text/plain` to reach different parsing code paths
- Use duplicate keys and array-shaped values to confuse or misalign parsers

### Header Manipulation

- Remove the Referer header by navigating through a meta refresh or launching from `about:blank`
- Probe null Origin acceptance explicitly
- Leverage CORS misconfigurations to inject custom headers that the server incorrectly treats as CSRF tokens

## Special Contexts

### Mobile/SPA

- Deep links and embedded WebViews may silently forward cookies; trigger state changes via crafted intents or deep links
- SPAs relying exclusively on bearer tokens are less susceptible to CSRF, but hybrid applications that mix cookies and API calls may remain vulnerable

### Integrations

- Webhooks and back-office management tools occasionally expose state-changing GET endpoints intended only for internal staff use
- Verify CSRF protections are consistently applied to these surfaces as well

### Next.js Server Actions (`"use server"`)

Server Actions are server-side mutation functions (marked `"use server"`) invoked by POSTing to an internal Next.js endpoint with a `Next-Action: <hash>` header that selects which function runs — **the request path is ignored**, so the action token, not the route, is the real dispatch key. This shape has two SAST-relevant pitfalls:

- **CSRF**: because they are POST mutations reachable on cookie-authenticated origins, a Server Action relying on ambient cookie auth without an anti-CSRF control is forgeable. Modern Next.js adds an Origin/Host same-origin check by default, but it can be weakened by a permissive `allowedOrigins` / `serverActions.allowedOrigins` config, by trusting a forwarded `Host`/`X-Forwarded-Host`, or on older versions — verify a real origin check exists.
- **Missing per-action authorization (primary risk)**: since dispatch is by token and ignores the path, **every Server Action must enforce its own authentication and authorization inside the function** — middleware/route guards do not protect it. An action that mutates data with no in-function identity/role check is invocable by anyone who can craft the POST + `Next-Action` token. Tokens are discoverable from client bundles (and trivially when `productionBrowserSourceMaps` is on), including **unused/unreferenced actions** that no UI calls but remain dispatchable (zombie endpoints — cross-ref `privilege_escalation.md`).

```js
// VULN — "use server" mutation with no auth check; dispatched by Next-Action token, path ignored
"use server";
export async function deleteUser(formData) {
  await db.users.delete(formData.get("id"));   // anyone who replays the POST + Next-Action runs this
}

// SAFE — authenticate AND authorize inside the action itself; validate input
"use server";
export async function deleteUser(formData) {
  const session = await auth();                 // server-trusted identity
  if (!session) throw new Error("unauthenticated");
  const id = String(formData.get("id"));
  if (!canDelete(session.user, id)) throw new Error("forbidden");  // object-level authz
  await db.users.delete(id);
}
```

**Grep seeds**:
```bash
rg -n '"use server"|^\s*'\''use server'\''' --glob '*.{js,jsx,ts,tsx}'
rg -n "serverActions|allowedOrigins|X-Forwarded-Host" --glob 'next.config.*'
# "use server" functions whose body has no auth()/getSession()/authorize()/role check
rg -n "use server" -A15 --glob '*.{ts,tsx,js,jsx}' | rg -i "auth|session|getServerSession|authorize|can[A-Z]|role" -L
```

## Chaining Attacks

- CSRF + IDOR: once object references are known, force the victim to act on other users' resources
- CSRF + Clickjacking: steer user interactions to bypass confirmation dialogs in the UI
- CSRF + OAuth mix-up: bind victim sessions to unintended OAuth clients

## Secure Configuration (Defense Patterns)

Layer defenses; no single control (including SameSite) is sufficient on its own.

### Synchronizer Token Pattern

Server generates an unpredictable token bound to the session; client echoes it on every state-changing request; server validates before processing.

```python
# Django — middleware + template tag (default when CsrfViewMiddleware enabled)
# forms/template: {% csrf_token %}
# view receives POST only if token matches session
```

```java
// Spring MVC — hidden field wired to CsrfToken
<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
```

### Double-Submit Cookie (Signed)

Cookie holds token; request must carry matching value in header or body. Sign or HMAC the cookie value so attackers cannot forge it without the server secret.

```javascript
// Signed cookie + header echo — verify signature before compare
const cookieToken = req.signedCookies['csrf'];
const headerToken = req.headers['x-csrf-token'];
if (!cookieToken || cookieToken !== headerToken) return res.sendStatus(403);
```

Unsigned double-submit (predictable or client-writable cookies) is weak — see Token Weaknesses.

### Per-Session vs Per-Request Tokens

| Model | Trade-off |
|-------|-----------|
| Per-session | Lower overhead; token reuse window spans session lifetime |
| Per-request | Stronger replay resistance; higher storage/rotation cost |

Flag handlers that rotate tokens on GET but accept stale tokens on POST, or that issue per-request tokens but never invalidate after use.

### Framework CSRF Middleware

Prefer framework-native enforcement over ad-hoc checks in individual handlers.

```ruby
# Rails — default for ActionController::Base
protect_from_forgery with: :exception
```

```python
# Django — global middleware (do not disable without endpoint-level substitute)
MIDDLEWARE = ['django.middleware.csrf.CsrfViewMiddleware', ...]
```

```java
// Spring Security — enabled by default on SecurityFilterChain
http.csrf(Customizer.withDefaults())
```

### SameSite Cookies (Defense-in-Depth)

SameSite=Lax/Strict reduces cross-site cookie delivery but does not replace tokens — Lax still sends cookies on top-level GET; older clients ignore SameSite.

```http
Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax
```

Treat SameSite as supplemental only when synchronizer tokens or equivalent are also enforced.

### Custom Header + CORS for Cookieless APIs

SPAs and JSON APIs using bearer tokens: require a non-simple header (`X-Requested-With`, `X-CSRF-Token`) on unsafe methods so cross-origin form POST cannot satisfy the check. Pair with restrictive CORS (explicit allowlist, no wildcard with credentials).

```javascript
// API route — reject state-changing requests missing custom header
if (['POST','PUT','PATCH','DELETE'].includes(req.method) && !req.headers['x-requested-with']) {
  return res.sendStatus(403);
}
```

Cookie-backed endpoints still need synchronizer tokens — custom headers alone do not protect cookie sessions.

### Origin / Referer Validation

Validate `Origin` (preferred) or `Referer` against an allowlist on every unsafe method; reject missing, null, or mismatched values before handler logic.

```javascript
const origin = req.headers.origin || req.headers.referer;
if (!origin || !allowedOrigins.has(new URL(origin).origin)) return res.sendStatus(403);
```

Do not accept null Origin unless the endpoint is intentionally public and idempotent.

## SAST Detection Indicators

Static signals for missing or weakened CSRF controls on cookie/session-authenticated surfaces:

| Indicator | Pattern |
|-----------|---------|
| Unsafe method without token check | POST/PUT/PATCH/DELETE handler parses body or persists state with no CSRF middleware, `@ValidateAntiForgeryToken`, `csrf_protect`, or equivalent |
| GET with side effects | Route on GET/HEAD/OPTIONS performs create/update/delete, sends email, rotates keys, or toggles flags |
| Protection disabled or exempted | `@csrf_exempt`, `csrf_exempt()`, `.csrf().disable()`, `CSRF_COOKIE_SECURE = False` with verification off, `protect_from_forgery except:`, `@DisableCsrf`, route-level CSRF skip decorators |
| SameSite=None without compensating control | Session cookie set `SameSite=None; Secure` but handler lacks synchronizer token, origin check, or custom-header requirement |
| Token present but not validated | Hidden input or meta tag emitted; server-side compare missing, commented out, or gated behind `if (debug)` |
| Double-submit without signing | Plain cookie mirrored to header with no HMAC/signature verification |

Scope: only flag when authentication relies on ambient browser credentials (session cookies, HTTP auth). Bearer-only JSON APIs without cookies are out of scope.

## Triage: Correctly Protected Handlers

Use these patterns to downgrade false positives when middleware or annotations enforce CSRF globally.

**Spring (Java/Kotlin)** — CSRF enabled on `SecurityFilterChain`; forms include `_csrf` hidden field; `@PostMapping` methods inherit filter validation unless explicitly ignored.

```java
http.csrf(Customizer.withDefaults()); // default — do not pair with .disable() on cookie sessions
```

**Django (Python)** — `CsrfViewMiddleware` in `MIDDLEWARE`; templates use `{% csrf_token %}`; views lack `@csrf_exempt` unless replaced by token header validation.

```python
@csrf_protect  # explicit when middleware order is non-standard
def update_profile(request): ...
```

**Rails (Ruby)** — `protect_from_forgery with: :exception` (default); forms include `authenticity_token`; API-only `ActionController::API` skips CSRF by design (no cookies).

**Express / Node** — `csurf`, `lusca`, or `express.csrf` middleware applied before state-changing routers; token read from `(csrf|xsrf)` cookie/header pair.

```javascript
app.use(csrf({ cookie: { httpOnly: true, sameSite: 'lax', secure: true } }));
```

**ASP.NET** — `[ValidateAntiForgeryToken]` on POST actions or global auto-validation filter; Razor forms include `@Html.AntiForgeryToken()`.

**Angular / SPA frontends** — HttpClient XSRF config maps cookie `XSRF-TOKEN` to header `X-XSRF-TOKEN`; backend must validate the header on unsafe methods.

```typescript
provideHttpClient(withXsrfConfiguration({ cookieName: 'XSRF-TOKEN', headerName: 'X-XSRF-TOKEN' }))
```

**Stateless JWT APIs** — `SessionCreationPolicy.STATELESS`, no session cookies, Bearer-only auth: CSRF not applicable; `.csrf().disable()` is correct.

## Analysis Workflow

1. **Inventory endpoints** - Enumerate all state-changing operations, including admin and staff-facing routes
2. **Note request details** - Record method, content-type, and whether the endpoint is reachable via simple requests
3. **Assess session model** - Evaluate cookies with their SameSite attributes, custom headers, and anti-CSRF tokens
4. **Check defenses** - Examine anti-CSRF token presence and Origin/Referer validation logic
5. **Attempt preflightless delivery** - Try form POST, `text/plain`, and `multipart/form-data` vectors
6. **Test navigation** - Probe top-level GET navigation paths
7. **Cross-browser validation** - Compare behavior across browsers and navigation contexts; SameSite handling differs

## Confirming a Finding

1. Demonstrate that a cross-origin page triggers a state change without requiring any user interaction beyond a page visit
2. Show that removing the anti-CSRF control (token or custom header) is accepted by the server, or that Origin/Referer headers are not validated
3. Reproduce the behavior across at least two browsers or contexts (top-level navigation vs XHR/fetch)
4. Supply before-and-after state evidence from the same account
5. Where defenses exist, identify the precise bypass condition — content-type switch, method override, null Origin, etc.

## Common False Alarms

- Token verification is present, required, and enforced consistently; Origin/Referer checks pass every time
- No cookies are transmitted on cross-site requests (SameSite=Strict, no HTTP auth) and no state changes occur via simple requests
- Only idempotent, non-sensitive read operations are reachable cross-site
- Login/logout CSRF producing only generic session confusion without a concrete, demonstrable security consequence should generally not be reported
- Endpoints protected exclusively by bearer-token or header-based authentication rather than browser cookies are not CSRF-prone
- Missing token validation on JS routes: routes reading cookies only for CSRF/captcha checks (`csrf`, `xsrf`, `captcha` property names) are excluded
- Missing token validation on C#: projects with no anti-forgery token usage anywhere, or global anti-forgery filters, are excluded
- CSRF protection disabled on Python: test settings paths and projects with mixed vulnerable/non-vulnerable settings modules
- Constant OAuth2 state: out-of-band OAuth (`urn:ietf:wg:oauth:2.0:oob`, localhost listener redirects)

## Recognized Mitigations

**JavaScript**: `csurf`, `tiny-csrf`, `lusca` with `csrf`, `express.csrf`, Fastify `csrfProtection`; CSRF token property reads on `(csrf|xsrf)` fields.

## Java Source Detection Rules

### TRUE POSITIVE: Global CSRF protection disabled in Spring Security
- `.csrf().disable()` or `.csrf(AbstractHttpConfigurer::disable)` or `.csrf(csrf -> csrf.disable())` appearing inside a `WebSecurityConfigurerAdapter` or `SecurityFilterChain` disables CSRF protection for ALL endpoints — confirm CWE-352 for any state-changing POST/PUT/DELETE endpoint relying on session or cookie authentication.
- **Note**: `WebSecurityConfigurerAdapter` is deprecated since Spring Security 5.7 / Spring Boot 2.7. Modern applications use a `@Bean SecurityFilterChain` method instead. Both patterns should be checked: the deprecated `extends WebSecurityConfigurerAdapter` style and the modern `@Bean` component-based style.
- This is a high-confidence finding: global CSRF disable combined with session-based auth and at least one state-changing endpoint constitutes a confirmed vulnerability.
- A single POST endpoint that modifies state (registration, profile update, funds transfer) is sufficient to confirm the finding.

### TRUE POSITIVE: Missing CSRF token on specific form
- A Spring MVC form endpoint that lacks `<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>` in its template, and for which CSRF is not disabled globally, is individually vulnerable.

### FALSE POSITIVE: Stateless JWT-only API
- When all endpoints authenticate exclusively via `Authorization: Bearer` headers and the application issues no session cookies, CSRF is not applicable. Only exclude when the `SecurityConfig` confirms stateless mode via `SessionCreationPolicy.STATELESS`.

## Business Risk

- Account state modification (email/password/MFA changes) and session hijacking through login CSRF
- Financial operations and administrative actions performed without user intent
- Long-lasting authorization changes (role or permission flips, credential rotations) and irreversible data loss

## Analyst Notes

1. Prioritize preflightless delivery vectors — form-encoded, multipart, and `text/plain` — and top-level GET if state changes are reachable that way
2. Begin with login, logout, OAuth connect/disconnect, and account linking flows before moving to less sensitive endpoints
3. Verify Origin/Referer validation explicitly; do not assume frameworks enforce these checks
4. Toggle SameSite values and compare behavior between top-level navigation and XHR/fetch contexts
5. For GraphQL, test GET-based queries or persisted queries that include mutations
6. Always attempt method overrides and content-type parser differentials
7. When visual confirmation dialogs block CSRF, combine with clickjacking to guide victim interaction

## Core Principle

CSRF is only fully mitigated when state changes require a secret the attacker cannot obtain and the server independently verifies the request origin. Tokens and origin checks must hold consistently across all methods, content-types, and transport paths.
- State-changing routes without CSRF token validation should be tagged `csrf` even when the controller only binds form fields and directly persists them.
- Require a browser-driven, cookie-backed, state-changing flow before tagging `csrf`. Missing tokens on JSON helpers, setup endpoints, or samples that do not rely on ambient browser cookies are not enough by themselves.

## Additional FALSE POSITIVE Rules

- Do NOT emit `csrf` for REST APIs that exclusively use Bearer token authentication (Authorization header) with no cookie-based session — these are inherently CSRF-safe.
- Do NOT emit `csrf` when `.csrf().disable()` is configured alongside `SessionCreationPolicy.STATELESS` in a pure API context — this is correct Spring Security configuration for stateless APIs.
- Do NOT emit `csrf` for login/registration endpoints where the only consequence is session creation (no privilege change, no data modification).
