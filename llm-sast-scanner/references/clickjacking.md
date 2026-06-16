---
name: clickjacking
description: Clickjacking / missing frame protection detection (CWE-1021; related CWE-451)
---

# Clickjacking (CWE-1021; related: CWE-451)

Clickjacking (UI redress) loads a victim site in a transparent iframe so users click attacker-overlaid controls. Missing `X-Frame-Options` or equivalent frame-busting headers leaves pages embeddable cross-origin.

## Source -> Sink Pattern

This is a **configuration check**, not taint flow: verify whether HTTP server definitions emit the `X-Frame-Options` response header on any route.

**Scope checked**:
- JavaScript: `Http::ServerDefinition` — Express/Fastify/Node HTTP servers with no route setting `x-frame-options`
- C#: `Web.config` customHeaders, or `Response.AddHeader`/`AppendHeader("X-Frame-Options", ...)` in code

**Not modeled**: `Content-Security-Policy: frame-ancestors` (modern replacement); per-route exceptions; headers set only at reverse proxy. Use **Detection Indicators** below to grep CSP alongside XFO.

## Vulnerable Conditions

- Web application never sets `X-Frame-Options` on HTTP responses
- ASP.NET app without `Web.config` `<add name="X-Frame-Options" ...>` and no programmatic header
- Sensitive actions (transfer, delete, admin) on pages that allow framing

## Safe Patterns

- Global header: `X-Frame-Options: DENY` or `SAMEORIGIN`
- CSP: `Content-Security-Policy: frame-ancestors 'self'`
- Express: `helmet.frameguard({ action: 'deny' })`, `frameguard`, or `res.setHeader('X-Frame-Options', 'DENY')`
- HAProxy/nginx: `rspadd X-Frame-Options:\ DENY` at proxy layer (not visible in application source)

## Evasion Patterns

- Legacy browsers ignoring CSP `frame-ancestors` — defense in depth needs both where supported
- `ALLOW-FROM uri` (deprecated, inconsistent browser support)
- Double-framing or sandbox attribute tricks against weak client-side frame busters (not detected by configuration checks)

Commonly affected languages: JavaScript, C#. No standard automated clickjacking/frame-protection rules for Java, Python, Go, Ruby, or PHP.

## JavaScript / Express

- **VULN**: Express app with routes but no `X-Frame-Options` anywhere
- **SAFE**: `res.setHeader('X-Frame-Options', 'DENY')` on responses

## C#

- **VULN**: MVC app without Web.config header entry or `Response.AddHeader("X-Frame-Options", "SAMEORIGIN")`
- **SAFE**: `<add name="X-Frame-Options" value="SAMEORIGIN" />` under `system.webServer/httpProtocol/customHeaders`

## Java / Spring / Python / Go

- Review `SecurityFilterChain` headers, Django `XFrameOptionsMiddleware`, Flask-Talisman, Go middleware

## Common False Alarms

- API-only JSON services never rendered in browsers — framing risk lower but query may still fire (JS precision: low)
- Headers enforced exclusively at CDN/WAF — not visible in application source
- Intentional embeddable widgets on specific routes while rest of site protected — check is global per server definition

## Business Risk

- Forced clicks on "Confirm transfer", "Delete account", "Grant permission" buttons
- CSRF chain aid: trick users through UI that blocks simple form CSRF
- Credential harvesting via overlaid fake login forms

## Core Principle

Pages that perform sensitive actions must not be frameable by untrusted origins. Set `X-Frame-Options` or `Content-Security-Policy: frame-ancestors` on all HTML responses, preferably globally.

## Modern Alternatives

Standard configuration checks cover only `X-Frame-Options`, not:
- `Content-Security-Policy: frame-ancestors 'none'` or `'self'`
- Legacy JavaScript `if (top !== self) top.location = self.location` (unreliable)

When triaging missing X-Frame-Options findings, manually confirm CSP frame-ancestors is also absent before reporting. Full CSP hardening patterns: `content_security_policy.md`.

## Defense Hierarchy

1. **Primary — CSP `frame-ancestors` (header)**: preferred control; takes precedence over XFO when both are present.
2. **Legacy/compat — `X-Frame-Options`**: `DENY` or `SAMEORIGIN` fallback for browsers without CSP frame-ancestors.
3. **Supporting — `SameSite` cookies**: limits cross-site cookie inclusion; does not replace framing headers.
4. **Supplemental only — frame-busting JS**: bypassable; never sole control.

## frame-ancestors Directive Values

```http
Content-Security-Policy: frame-ancestors 'none';
Content-Security-Policy: frame-ancestors 'self';
Content-Security-Policy: frame-ancestors 'self' https://partner.example;
```

- `'none'` — no origin may embed; use on auth, admin, and payment HTML.
- `'self'` — same origin only; acceptable when no cross-origin embed is required.
- **Allowlist** — space-separated origin URLs (`https://host`); narrow to trusted partners only.
- **Weak/absent** — missing directive, `frame-ancestors *`, or permissive allowlist on sensitive routes.

Deliver via HTTP response header (not meta tag — meta CSP cannot enforce `frame-ancestors` in all browsers; see `content_security_policy.md`).

## X-Frame-Options Legacy Values

```http
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
```

- `DENY` — equivalent intent to `frame-ancestors 'none'`.
- `SAMEORIGIN` — equivalent intent to `frame-ancestors 'self'`.
- **`ALLOW-FROM uri` — deprecated**: dropped from the HTML Living Standard; never implemented consistently in Chrome/Firefox; superseded by CSP allowlist; grep hit = migrate to `frame-ancestors` allowlist, not a safe finding.

## SameSite Cookies (Supporting Control)

Framing headers block embed; SameSite reduces session impact when navigation or CSRF chains still occur:

```http
Set-Cookie: session=...; SameSite=Strict; Secure; HttpOnly
Set-Cookie: session=...; SameSite=Lax; Secure; HttpOnly
```

- `Strict` — cookie withheld on all cross-site requests (strongest).
- `Lax` — cookie on top-level GET navigations; common default; not a framing substitute.
- Elevated risk: sensitive HTML lacking frame-ancestors/XFO **and** session cookies without `SameSite` (chain with `csrf.md`).

## Frame-Busting JavaScript (Insufficient Alone)

Bypassable via sandboxed iframe (`sandbox` without `allow-top-navigation`), `onbeforeunload` traps, disabled JS, or nested frames. Supplement headers only:

```html
<script>if (top !== self) top.location = self.location;</script>
```

SAST signal: `top.location`, `self === top`, or anti-clickjack CSS hide without corresponding CSP/XFO in middleware, `Web.config`, or reverse-proxy config.

## Express Mitigations

Recommended npm modules: `helmet`, `frameguard`, `x-frame-options`. Prefer CSP plus XFO fallback:

```javascript
const helmet = require('helmet');
app.use(helmet({
  contentSecurityPolicy: { directives: { 'frame-ancestors': ["'none'"] } },
}));
app.use(helmet.frameguard({ action: 'deny' }));
// or: res.setHeader('X-Frame-Options', 'DENY');
```

## C# Web.config Pattern

```xml
<system.webServer>
  <httpProtocol>
    <customHeaders>
      <add name="X-Frame-Options" value="SAMEORIGIN" />
    </customHeaders>
  </httpProtocol>
</system.webServer>
```

## Analyst Notes

- JS missing-header query precision is **low** — expect broad server-level alerts; confirm sensitive HTML pages exist
- CSRF + clickjacking chain documented in `csrf.md` — frame hidden UI over confirmation dialogs
- API JSON endpoints flagged by JS query may be low business impact if never browser-rendered

## Java / Python / Go / Ruby

Equivalent manual checks:
- Spring Security: `headers().frameOptions().deny()`
- Django: `XFrameOptionsMiddleware` (DEFAULT `SAMEORIGIN`)
- Go: middleware setting `X-Frame-Options`
- Rails: `headers['X-Frame-Options'] = 'SAMEORIGIN'` in `ApplicationController`

### Framework Header Configuration

```python
# Django — settings.py
MIDDLEWARE = ['django.middleware.clickjacking.XFrameOptionsMiddleware', ...]
X_FRAME_OPTIONS = 'DENY'
```

```java
// Spring Security 6+
http.headers(h -> h
    .contentSecurityPolicy(csp -> csp.policyDirectives("frame-ancestors 'none'"))
    .frameOptions(FrameOptionsConfig::deny));
```

```csharp
// ASP.NET Core — Program.cs / middleware
ctx.Response.Headers.ContentSecurityPolicy = "frame-ancestors 'none'";
ctx.Response.Headers.XFrameOptions = "DENY";
```

## Detection Indicators (Grep)

Missing or weak framing controls in app source and server config:

```bash
# CSP present but no frame-ancestors
rg -i "Content-Security-Policy|contentSecurityPolicy" | rg -vi "frame-ancestors"

# Weak frame-ancestors
rg -i "frame-ancestors\s+'none'|frame-ancestors\s+'self'"  # invert: pages lacking these
rg -i "frame-ancestors\s+\*|frame-ancestors\s+https?://\*"

# Missing X-Frame-Options / framework middleware
rg -i "X-Frame-Options|XFrameOptions|frameguard|frameOptions|FrameOptionsMiddleware" \
  --glob '*.{js,ts,py,java,cs,go,rb,yml,yaml,conf,xml}'

# Deprecated ALLOW-FROM
rg -i "ALLOW-FROM|allowFrom"

# Frame-buster without header config (manual triage)
rg -i "top\.location|self\s*===?\s*top|antiClickjack|frame.?bust"

# Reverse-proxy / static server config
rg -i "add_header.*X-Frame-Options|Content-Security-Policy" --glob '*.{conf,nginx,haproxy,cnf}'
```

**Positive signals**: `helmet.frameguard`, `XFrameOptionsMiddleware`, `frameOptions().deny()`, `customHeaders` + `X-Frame-Options`, CSP string containing `frame-ancestors 'none'` or `'self'`.

**Report rule**: HTML-serving route with neither CSP `frame-ancestors` (`'none'`/`'self'`/narrow allowlist) nor `X-Frame-Options: DENY|SAMEORIGIN`. Cross-check CSP findings in `content_security_policy.md` before closing as false negative.

## CWE-829 Overlap

Both JS and C# missing-frame-header rules tag `external/cwe/cwe-829` (UI redress via framing) alongside CWE-451. Report as clickjacking/frame protection failure.
