---
name: content_security_policy
version: "0.3"
description: Content Security Policy weakness detection — missing headers, unsafe directives, broad allowlists, attacker-publishable host gadgets (tag-manager/analytics/user-content origins), cookie-derived nonce reflection, and bypass-prone configurations
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
- **Bypass-prone allowlists**: whitelisted JSONP endpoints, legacy AngularJS on CDNs, **attacker-publishable host gadgets** (tag-manager/analytics/user-content/open-bucket origins where anyone can host JS — e.g. `googletagmanager.com`), a `script-src` host-source with **no** `'strict-dynamic'`, `strict-dynamic` without nonce/hash, permissive `connect-src` enabling exfiltration

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

Not every host in a `script-src` allowlist is equal: some **let any third party publish arbitrary JavaScript to them**, so listing one is functionally identical to `'unsafe-inline'` — an attacker with any injection foothold loads their own code *from the trusted origin*. Three distinct gadget shapes:

```http
# VULN — JSONP endpoint whitelisted: ?callback= reflects arbitrary JS
script-src 'self' https://apis.example.com/jsonp?callback=

# VULN — legacy AngularJS / library CDN (template-injection / sandbox-escape gadgets;
#        a whole-CDN allowlist also exposes every old vulnerable library version)
script-src 'self' https://ajax.googleapis.com/ajax/libs/angularjs/

# VULN — attacker-publishable host: ANYONE can host code there (nonce does NOT help)
script-src 'self' 'nonce-r4nd0m' https://www.googletagmanager.com https://www.google-analytics.com
```

**Attacker-publishable host gadget (the non-obvious, high-severity case).** Origins such as `www.googletagmanager.com`, `*.google-analytics.com`/`tagmanager.google.com`, and *any* platform where an outsider can **register a container / upload a script / host user content** — open object storage (`storage.googleapis.com`, `*.s3.amazonaws.com`, `*.blob.core.windows.net`), user-content CDNs, some CDN edges — are attacker-controllable. The attacker signs up for their **own** Google Tag Manager container, puts arbitrary JS in a Custom HTML/Custom JavaScript tag, and an XSS foothold injects `<script src="https://www.googletagmanager.com/gtm.js?id=GTM-ATTACKER">` — permitted by the host-source, executing attacker code. **No compromise of Google/GTM is required** — this is *not* the supply-chain "your own container got hacked" scenario, so do **not** downgrade it to a low-severity third-party-trust note. Treat it as equivalent to `'unsafe-inline'`: the policy no longer contains script execution (score it like `unsafe-inline`, not like an SRI/supply-chain hardening gap). It also **defeats WAFs** — the payload lives in the attacker's container on the trusted domain and never transits the protected app, so request-inspection rules (e.g. OWASP CRS 941180 blocking `document.cookie`) never see it.

**A nonce does not neutralize a dangerous host-source.** A host-source expression authorizes scripts from that origin **regardless of the nonce** — the nonce is an *additional* allow, not a restriction. Only `'strict-dynamic'` neutralizes host allowlists: it makes the browser **ignore** every host/scheme source and trust only nonce/hash-loaded scripts plus what they dynamically inject. So `script-src 'self' 'nonce-…' https://www.googletagmanager.com` (nonce present, **no** `'strict-dynamic'`) is still fully bypassable — flag it; the presence of a nonce is not a clearance. Fix: per-request nonce **+** `'strict-dynamic'` (and drop the host entries), or proxy analytics from first-party.

Grep: `jsonp`, `callback=`, `angular\.js`, `angular.min.js`, `googletagmanager\.com`, `google-analytics\.com`, `tagmanager\.google\.com`, `storage\.googleapis\.com`, `s3[.-].*amazonaws\.com`, `blob\.core\.windows\.net` inside `script-src`/`default-src` strings; any `script-src` host/scheme source present **without** an accompanying `'strict-dynamic'`; `strict-dynamic` without `'nonce-` or `'sha256-`.

### Nonce derived from a request cookie / header (cookie XSS + CSP self-defeat)

**VULN**: the CSP nonce is **read from a cookie, query, or request header** and interpolated into both `Content-Security-Policy: script-src 'nonce-…'` and `<script nonce="…">` (or style nonces). That is not a "nonce reuse" bug alone — it is an **XSS source**: an attacker who can plant the cookie (sibling-path XSS / cookie tossing / non-HttpOnly `Set-Cookie` on a broad `Domain`) injects into the attribute **and** into the CSP source list (e.g. splice `'unsafe-eval'` / extra hosts). The policy that should contain XSS becomes the injection vehicle. **Do NOT CLOSE** as "self-XSS / victim sets cookie" when the cookie is plantable into another user's jar. Cross-ref `xss.md` (Cookie XSS).

**SAFE**: generate a fresh cryptographic nonce per response (`secrets.token_urlsafe` / `crypto.randomBytes`); never echo Cookie/query/header bytes into the policy or nonce attributes.

### Policy built by string concatenation → directive injection & duplicate-directive bypass

When the CSP string is **assembled by concatenating/interpolating a user- or tenant-controlled value** — a "Trusted Sites"/allowed-origins settings field, a per-tenant `connect-src` list, a reflected origin — an attacker who controls that value can inject CSP syntax (a `;` starts a **new directive**; whitespace separates source expressions) rather than just adding one host. Two distinct outcomes:

- **Directive injection**: input like `https://ok.test; script-src 'unsafe-inline'` (or `... connect-src https://attacker.test`) splices an attacker-chosen directive into the policy — loosening `script-src`, adding an exfil origin to `connect-src`, or overwriting `default-src`.
- **Duplicate-directive "first-occurrence-wins" bypass**: browsers enforce **only the first** occurrence of a repeated directive and ignore later ones. So logic that *appends* or *relocates* a matched directive (leaving the page with two `connect-src`/`script-src` instances) is exploitable: if the attacker can make the **permissive** copy appear first, its version is the one enforced. Any policy-builder that can emit the same directive name twice is suspect.

**SAST signals**: a `Content-Security-Policy` value (header set OR `<meta http-equiv>` `content`) produced by `+`/template-literal/`join`/`sprintf` from a config field, DB row, or request value with no directive-token validation; code that de-dupes/reorders directives via string ops; user "allowed domains" written straight into a source-list. **SAFE**: build the policy from a **structured object** (one merged value per directive name), never string-concatenate untrusted input; validate injected origins against an exact host allowlist (reject `;`, whitespace, and directive keywords); prefer delivery via the **HTTP header** over a `<meta>` tag; emit each directive at most once.

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

# WEAK — attacker-publishable host (GTM/analytics); nonce present but no strict-dynamic,
#        so the host-source still authorizes an attacker's own GTM container → arbitrary JS
Content-Security-Policy: script-src 'self' 'nonce-{random}' https://www.googletagmanager.com https://www.google-analytics.com;
```

```http
# STRONG — remove JSONP; use CORS + JSON; no script-src entries for API hosts
Content-Security-Policy: script-src 'self' 'nonce-{random}'; connect-src 'self' https://partner.example.com;

# STRONG — nonce + strict-dynamic makes host allowlists inert; GTM loads via the nonced bootstrap only
Content-Security-Policy: script-src 'nonce-{random}' 'strict-dynamic'; object-src 'none'; base-uri 'none';
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
- **Attacker-publishable hosts in `script-src` (tag managers, analytics with Custom HTML/JS, open storage buckets, user-content CDNs) are equivalent to `'unsafe-inline'`, not a supply-chain "if it gets compromised" note** — any outsider can host code there with no compromise, so score script-execution containment as defeated. A per-request nonce does **not** clear this unless `'strict-dynamic'` is also present (which is what makes host-sources inert).
- `default-src` fallback: missing `script-src` inherits `default-src`; inspect the full directive set, not `script-src` alone
- Meta-tag CSP on pages that also lack `frame-ancestors` leaves clickjacking protection incomplete
