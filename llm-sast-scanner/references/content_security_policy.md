---
name: content_security_policy
description: Content Security Policy weakness detection — missing headers, unsafe directives, broad allowlists, and bypass-prone configurations
---

# Content Security Policy Weaknesses

Content Security Policy (CSP) is a browser-enforced allowlist for scripts, styles, frames, and other resource loads. Static analysis targets **policy strings and header wiring in application code, middleware, and deployment config** — not individual XSS sinks (see `xss.md` for sink tracing).

*The core pattern: HTML responses leave the browser without an enforcing CSP, or the declared policy permits inline script, dynamic evaluation, overly broad origins, or known bypass gadgets.*

## What It Is (and Is Not)

**What it IS**
- **Missing CSP**: no `Content-Security-Policy` header and no equivalent `<meta http-equiv="Content-Security-Policy">` on HTML-serving routes
- **`unsafe-inline` / `unsafe-eval`**: `script-src` or `default-src` permits inline scripts or `eval`/`new Function` — negates XSS mitigation for script execution
- **Overly broad sources**: `*`, `https:`, `http:`, `data:`, `blob:`, or wildcard subdomains (`*.example.com`) in `script-src`/`default-src`
- **Missing hardening directives**: absent `object-src 'none'`, `base-uri 'none'` or `'self'`, `frame-ancestors 'none'`/`'self'` (clickjacking exposure; see `clickjacking.md`)
- **Nonce/hash misuse**: static or reused nonce across requests; nonce in policy but not on matching `<script>` tags; predictable nonce generation
- **Report-only in production**: only `Content-Security-Policy-Report-Only` set with no enforcing `Content-Security-Policy`
- **Bypass-prone allowlists**: whitelisted JSONP endpoints, legacy AngularJS on CDNs, `strict-dynamic` without nonce/hash, permissive `connect-src` enabling exfiltration

**What it is NOT**
- **XSS at the sink** — unescaped user input reaching `innerHTML`, templates, etc.; tag under `xss.md` unless the finding is the policy string itself
- **Clickjacking alone** — missing `X-Frame-Options` without CSP review; overlap only when `frame-ancestors` is absent or `*`
- **Trusted Types configuration** — complementary runtime control; separate from CSP header analysis
- **CSP set exclusively at CDN/WAF** — not visible in app source; note as coverage gap, do not assume absence from code alone

## Recon Indicators

### HTTP header wiring (grep)

| Signal | Grep / structural targets |
|--------|---------------------------|
| Header setters | `Content-Security-Policy`, `Content-Security-Policy-Report-Only`, `setHeader\(['"]Content-Security-Policy`, `add_header Content-Security-Policy`, `Header set Content-Security-Policy`, `append\(['"]Content-Security-Policy` |
| Middleware | `helmet\.contentSecurityPolicy`, `helmet\.csp`, `contentSecurityPolicy\(`, `django-csp`, `CSPMiddleware`, `Flask-Talisman`, `SecureHeadersMiddleware`, `UseCsp\(`, `AddContentSecurityPolicy` |
| Report-only only | `Content-Security-Policy-Report-Only` without paired enforcing header in same route/global config |
| Meta fallback | `<meta http-equiv="Content-Security-Policy"`, `<meta http-equiv="Content-Security-Policy-Report-Only"` |

### Weak directive tokens (policy string grep)

```text
'unsafe-inline'          # script-src or default-src — inline script allowed
'unsafe-eval'            # eval / Function / setTimeout(string) allowed
'unsafe-hashes'          # hash-only inline handlers; verify scope
script-src *             # any origin
script-src https:        # any HTTPS origin
script-src http:         # cleartext script loads
script-src data:         # data: URI scripts
script-src blob:         # blob: URI scripts
*.cdn.example.com        # wildcard subdomain allowlist
```

### Missing directive checks

Flag policies that set `default-src` or `script-src` but omit:

```text
object-src               # should be 'none' on modern apps
base-uri                 # should be 'none' or 'self'
frame-ancestors          # should be 'none' or 'self' for sensitive HTML
```

### Framework / platform config files

| Stack | Locations |
|-------|-----------|
| Node/Express | `helmet({ contentSecurityPolicy: { directives: ... } })`, `app.use(helmet())` with default or disabled CSP |
| Next.js | `next.config.js` `headers()` returning CSP, `middleware.ts` `response.headers.set('Content-Security-Policy'` |
| Nuxt | `nuxt.config` `routeRules` / `nitro.routeRules` headers, `@nuxt/security` module |
| Django | `CSP_*` settings in `settings.py`, `django-csp` middleware |
| Spring | `ContentSecurityPolicyHeaderWriter`, `SecurityFilterChain` `.headers().contentSecurityPolicy` |
| ASP.NET | `AddContentSecurityPolicy` in `Program.cs`, `web.config` customHeaders |
| nginx | `add_header Content-Security-Policy`, `more_set_headers` |
| Apache | `Header set Content-Security-Policy` in vhost / `.htaccess` |
| CloudFront / ALB | response header policy JSON/YAML with CSP key |

### Nonce / hash generation (grep)

```javascript
// VULN — constant nonce reused every response
const NONCE = 'abc123';
res.setHeader('Content-Security-Policy', `script-src 'nonce-${NONCE}'`);

// VULN — weak/predictable nonce
const nonce = Date.now().toString();
```

```javascript
// SAFE — per-request cryptographic nonce
const nonce = crypto.randomBytes(16).toString('base64');
res.locals.cspNonce = nonce;
res.setHeader('Content-Security-Policy', `script-src 'nonce-${nonce}' 'strict-dynamic'`);
```

Grep: `'nonce-` in static strings, `nonce\s*=\s*['"][^{$]`, template literals embedding fixed nonce, shared module exporting nonce constant.

### Bypass-prone allowlist entries

```http
# VULN — JSONP endpoint whitelisted in script-src
script-src 'self' https://apis.example.com/jsonp?callback=

# VULN — legacy AngularJS CDN (template injection / sandbox escape gadgets)
script-src 'self' https://ajax.googleapis.com/ajax/libs/angularjs/
```

Grep: `jsonp`, `callback=`, `angular\.js`, `angular.min.js` inside CSP directive strings; `strict-dynamic` without `'nonce-` or `'sha256-`.

### Dangling-markup injection sinks (grep)

CSP that blocks `script-src` does **not** stop **dangling markup**: user input reflected into HTML **without closing the opening tag** lets the browser treat the remainder of the page as attribute value or URL, enabling exfiltration or navigation without executable script.

**Vulnerable reflection patterns** (truncated attribute — no closing quote before next markup):

```html
<!-- VULN — reflected query in unclosed src -->
<img src='https://app.example/search?q=ATTACKER_INPUT
<!-- browser reads through page as URL; exfil via DNS/query to attacker host -->

<!-- VULN — meta refresh with unclosed content -->
<meta http-equiv="refresh" content="0;url=ATTACKER_INPUT

<!-- VULN — table background URL not terminated -->
<table background="//ATTACKER_INPUT

<!-- VULN — base href hijack (see base-uri below) -->
<base href='ATTACKER_INPUT
```

**Grep seeds** (application templates / handlers):
- User/template variable immediately after `'`, `"`, or `=` in tag openers: `<img[^>]*src=['"]\{\{`, `\+ req\.query`, `\+ user\.`
- Missing closing quote on same line before `>` or `%>` / `</`
- `echo.*<img`, `render.*background=`, `http-equiv.*refresh.*content=`

**SAFE**: encode for HTML attribute context; always terminate attributes; prefer CSP **plus** strict output encoding — CSP alone is insufficient when dangling markup is possible.

### Mandatory `base-uri 'none'` / `'self'`

Without `base-uri`, a dangling `<base href='//attacker.example/'` (or full `<base>` injection via XSS) retargets **all relative** `script`, `link`, `img`, and `a` URLs on the page — bypassing `'self'`-only `script-src` by loading `/app.js` from the attacker origin.

```http
# WEAK — script-src strict but base-uri absent; relative script URLs hijackable
Content-Security-Policy: default-src 'self'; script-src 'self';
```

```http
# STRONG — pair script policy with base-uri lockdown
Content-Security-Policy: default-src 'self'; script-src 'self'; base-uri 'none'; object-src 'none';
```

**Grep seeds**: policy strings missing `base-uri` entirely; HTML handlers emitting `<base` without server-side allowlist; reflected input adjacent to `<base href='` without closing quote (dangling-markup variant above).

## Weak vs Strong Policy

### Missing CSP

```javascript
// WEAK — HTML route, no CSP header
app.get('/dashboard', (req, res) => {
  res.send('<html><script src="/app.js"></script></html>');
});
```

```javascript
// STRONG — enforcing CSP on HTML responses
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    objectSrc: ["'none'"],
    baseUri: ["'none'"],
    frameAncestors: ["'none'"],
  },
}));
```

### `unsafe-inline` / `unsafe-eval`

```http
# WEAK
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval';
```

```http
# STRONG — nonce + strict-dynamic (no unsafe-inline)
Content-Security-Policy: default-src 'self'; script-src 'nonce-R4nd0mB64==' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none';
```

### Wildcard / broad sources

```http
# WEAK
Content-Security-Policy: script-src * 'unsafe-inline';
Content-Security-Policy: script-src https: data: blob:;
```

```http
# STRONG
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self';
```

### Missing `object-src` / `base-uri` / `frame-ancestors`

```http
# WEAK — falls back to default-src; plugins and base-tag injection possible
Content-Security-Policy: default-src 'self'; script-src 'self';
```

```http
# STRONG
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self';
```

### Nonce reuse

```python
# WEAK — module-level nonce, same value every request
CSP_NONCE = "fixed-value"
response["Content-Security-Policy"] = f"script-src 'nonce-{CSP_NONCE}'"
```

```python
# STRONG — fresh nonce per response, echoed on script tags
nonce = secrets.token_urlsafe(16)
response["Content-Security-Policy"] = f"script-src 'nonce-{nonce}' 'strict-dynamic'"
# template: <script nonce="{{ csp_nonce }}">...</script>
```

### Report-only left in production

```javascript
// WEAK — monitoring only; violations logged, not blocked
res.setHeader('Content-Security-Policy-Report-Only', policy);
// no Content-Security-Policy header
```

```javascript
// STRONG — enforce after report-only tuning phase
res.setHeader('Content-Security-Policy', policy);
// optional: keep Report-Only temporarily during rollout with BOTH present
```

### Allowlist bypass surfaces

```http
# WEAK — JSONP callback executes arbitrary JS from whitelisted host
Content-Security-Policy: script-src 'self' https://partner.example.com;
```

```http
# STRONG — remove JSONP; use CORS + JSON; no script-src entries for API hosts
Content-Security-Policy: script-src 'self' 'nonce-{random}'; connect-src 'self' https://partner.example.com;
```

## Safe Patterns

- **Enforcing header on all HTML routes**: `Content-Security-Policy` set globally via middleware or reverse proxy; not report-only alone
- **Strict script policy**: `'strict-dynamic'` with per-request cryptographic nonce (≥128 bits) on every inline `<script>`; or `'sha256-…'` hashes for static inline blocks — no `'unsafe-inline'` on `script-src`
- **Minimal allowlists**: `'self'` plus explicit hostnames only where required; no `*`, `https:`, `data:`, or `blob:` in `script-src`
- **Hardening trio**: `object-src 'none'; base-uri 'none'; frame-ancestors 'none'` (or `'self'` when intentional embedding)
- **Prefer HTTP header over meta tag**: meta CSP cannot set `frame-ancestors` or `report-uri` in all browsers; header delivery is stronger
- **Refactor for CSP**: external `.js` files, event listeners instead of inline handlers, classes instead of inline `style=""` — reduces `'unsafe-inline'` on `style-src` need
- **Report URI for tuning only**: `report-uri` / `report-to` during rollout; switch to enforcing policy before production hardening sign-off

## Common False Alarms

- **API/JSON-only routes** without HTML bodies — CSP not applicable; do not flag missing header on `application/json` handlers
- **Intentional `'unsafe-inline'` on `style-src` only** — common bootstrap pattern; flag `script-src 'unsafe-inline'`/`'unsafe-eval'`, not style-only inline CSS unless policy review scope includes style injection
- **CSP enforced at edge** (CDN, WAF, ingress) — absent from application repo; note as external control, not a false positive for infra-as-code repos that define the header
- **Hash-based CSP for fixed inline bootstraps** — `'sha256-…'` without nonce is valid when inline content is static and hash matches
- **Development report-only** — `Content-Security-Policy-Report-Only` in dev/test configs only; confirm production deploy artifacts before reporting
- **Third-party widget routes** — narrowly scoped permissive CSP on `/embed/*` while default site is strict; verify route isolation
- **Nonce present and unique per request** with `'strict-dynamic'` and no `unsafe-inline`/`unsafe-eval` — strong policy; do not duplicate as XSS finding without sink evidence (`xss.md`)

## Analyst Notes

- Pair CSP findings with `xss.md` only when demonstrating that a weak policy fails to block a confirmed sink — the CSP string is the primary artifact here
- `'unsafe-inline'` in `script-src` effectively disables XSS containment for script execution regardless of output encoding elsewhere
- Whitelisting entire CDNs (`cdn.jsdelivr.net`, `unpkg.com`) grants access to every library version hosted there — treat as overly broad
- `default-src` fallback: missing `script-src` inherits `default-src`; inspect the full directive set, not `script-src` alone
- Meta-tag CSP on pages that also lack `frame-ancestors` leaves clickjacking protection incomplete
