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

**Not modeled**: `Content-Security-Policy: frame-ancestors` (modern replacement); per-route exceptions; headers set only at reverse proxy.

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

When triaging missing X-Frame-Options findings, manually confirm CSP frame-ancestors is also absent before reporting.

## Express Mitigations

Recommended npm modules: `helmet`, `frameguard`, `x-frame-options`. Example fix:
```javascript
res.setHeader('X-Frame-Options', 'DENY');
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

## CWE-829 Overlap

Both JS and C# missing-frame-header rules tag `external/cwe/cwe-829` (UI redress via framing) alongside CWE-451. Report as clickjacking/frame protection failure.
