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

- If queries or mutations are accepted via GET or persisted queries, exploit top-level navigation with URL-encoded payloads
- Batched requests may obscure mutations inside an ostensibly safe combined operation

### WebSocket CSRF

- Browsers automatically include cookies on WebSocket upgrade requests
- Without server-side Origin enforcement, cross-site pages can establish authenticated WebSocket connections and trigger server-side actions

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
