---
name: aspnet-security-misconfig
description: ASP.NET security misconfiguration detection (CWE-011, CWE-016, related hardening)
---

# ASP.NET Security Misconfiguration (CWE-011 / CWE-016)

ASP.NET applications expose security posture through `Web.config`, `web.config` transforms, and programmatic `system.web` settings. Misconfigurations such as debug builds, weakened request validation, oversized uploads, disabled header checks, and overly broad cookie scope enable XSS, DoS, information disclosure, and session leakage.

## What to Look For

These are **configuration and flag queries**, not taint-flow analyses. The insecure XML attribute, assignment, or missing hardening is the finding.

### CWE-011 — Debug binary in production

- `<compilation debug="true" />` under `<system.web>` in a `Web.config` parsed as ASP.NET configuration
- Any value other than `false` (including omitted explicit false when true is set)
- **Exception modeled**: `Web.config` Release transform in the same directory tree that removes the `debug` attribute via `<compilation xdt:Transform="Remove" debug="..." />`

### CWE-016 — Request validation weakened

**Insecure request validation mode**
- `<httpRuntime requestValidationMode="..."/>` where numeric value **< 4.5** (e.g., `4.0` in BAD example config)
- Downgrades ASP.NET built-in dangerous-request filtering

**Request validation disabled**
- `<pages validateRequest="false" />` — disables page-level request validation (XSS-oriented guard)

### CWE-016 — DoS / resource limits

**Large max request length**
- `<httpRuntime maxRequestLength="N" />` where **N > 4096** (kilobytes)
- BAD example uses `255000` KB — enables large POST abuse

### Related hardening (not CWE-016 tags)

**Disabled header checking** (CWE-113)
- `enableHeaderChecking="false"` on `<httpRuntime>` in config, or `HttpRuntimeSection.EnableHeaderChecking = false` in code

**Broad cookie domain** (CWE-287)
- `HttpCookie.Domain` set to overly broad values (fewer than two dots after stripping non-dots, or leading `.` pattern)

**Broad cookie path** (CWE-287)
- `HttpCookie.Path = "/"` — only worth flagging when a narrower path scope is required; as a standalone signal `Path="/"` is the normal app-wide default and will cause false positives

### ViewState integrity and encryption (CWE-502 enabler)

- `<pages enableViewStateMac="false" />` — disables ViewState MAC; enables forgery when combined with `LosFormatter`/`ObjectStateFormatter` deserialization (see `insecure_deserialization.md`)
- `<pages ViewStateEncryptionMode="Never" />` — ViewState sent cleartext; weakens tamper resistance
- Default is MAC on and encryption `Auto`; any explicit weakening on production pages is a misconfiguration

**Grep seeds**: `enableViewStateMac="false"`, `enableViewStateMac='false'`, `ViewStateEncryptionMode="Never"`, `ViewStateEncryptionMode='Never'`

### Hardcoded machineKey (CWE-798 / deserialization enabler)

- `<machineKey validationKey="..." decryptionKey="..." />` in committed `Web.config`, transforms, or environment-specific configs checked into source
- Static keys let an attacker forge valid ViewState MACs and decrypt/encrypt ViewState blobs → enables `__VIEWSTATE` gadget chains (cross-ref `insecure_deserialization.md`, `weak_crypto_hash.md`)
- Production keys must be unique per deployment, rotated, and loaded from a secret store — not literals in repo

**Grep seeds**: `<machineKey`, `validationKey=`, `decryptionKey=`, `compatibilityMode=`

### Cookieless session URL rewriting (CWE-384 / session fixation)

- `<sessionState cookieless="UseUri" />` or `cookieless="AutoDetect"` — embeds session id in URL path segment `(S(...))` instead of HttpOnly cookie
- Example path shape: `/admin/(S(abc123...))/page.aspx` — session id leaks via Referer, logs, browser history, shared links
- Enables session fixation and hijacking when combined with open redirects or XSS

**Grep seeds**: `cookieless="UseUri"`, `cookieless='UseUri'`, `cookieless="AutoDetect"`, `cookieless='AutoDetect'`, `<sessionState`

### Auth cookie confusion anti-patterns

- Treating **presence** of `.ASPXAUTH` (Forms Authentication ticket cookie) as proof of authorization without validating ticket / role claims server-side
- Treating **absence** of `.ASPXAUTH` as "unauthenticated" while `ASP.NET_SessionId` alone grants access to `<deny users="?" />` protected resources — session id is not an auth ticket
- Relying on `Session["UserId"]` or similar session keys set before login completes — fixation-friendly when cookieless or session not regenerated on auth
- Code that branches on `Request.Cookies[".ASPXAUTH"] != null` or `Request.Cookies["ASP.NET_SessionId"]` instead of `User.Identity.IsAuthenticated` / role checks

**Grep seeds**: `.ASPXAUTH`, `ASP.NET_SessionId`, `Request\.Cookies\[`, `User\.Identity\.IsAuthenticated`, `<deny users="\?">`, `<authorization>`

### Output caching over authorized/personalized content (CWE-525 — cache serves auth response cross-user)

- **`[OutputCache]` on an `[Authorize]`-protected action** (MVC/Web API) — the cached response is served on subsequent requests **before the `[Authorize]` filter re-evaluates**, so a personalized/authorized page is handed to other users (or unauthenticated callers) until it expires. Same bug via `<%@ OutputCache %>` on a page, `[ResponseCache]` (ASP.NET Core) without `VaryByHeader`/`Location=None` on authenticated content, or IIS `<caching>`/`<outputCache>` enabled for paths that return per-user data.
- **Safe**: never cache authenticated/per-user responses — `[OutputCache(NoStore=true, Duration=0)]` / `[ResponseCache(Location=ResponseCacheLocation.None, NoStore=true)]` on authorized actions; if caching is required, `VaryByCustom`/`VaryByHeader` on the identity dimension (and confirm the proxy/IIS layer keys on it too). The general cache-vs-identity model is in `web_cache_deception.md`. **Grep seeds**: `\[OutputCache`, `OutputCache .*Duration`, `\[ResponseCache`, `<%@ *OutputCache`, `<outputCache .*enabled="true"` — then check whether the same action/controller carries `[Authorize]` or returns per-user data.

## Vulnerable Conditions

- Production deployment with `debug="true"` — stack traces, source hints, performance/memory impact (CWE-011 / CWE-532 in query tags)
- **ASP.NET Core** equivalent: `app.UseDeveloperExceptionPage()` reachable on a production path — called unconditionally (no `if (env.IsDevelopment())` guard), `ASPNETCORE_ENVIRONMENT`/`AddDeveloperExceptionPage` left on `Development` in a deployed config, or **no** `app.UseExceptionHandler("/Error")` for the non-dev branch. Leaks the full exception, stack trace, and source snippets to the client (the .NET Core analog of `debug="true"`).
- Global `validateRequest="false"` on Web Forms / legacy ASP.NET pages
- `requestValidationMode` below 4.5 while relying on platform XSS filtering
- Multi-megabyte `maxRequestLength` on public-facing upload endpoints
- Header checking disabled — CRLF/header injection risk increases
- Session cookies scoped to parent domain or `/` path unnecessarily
- ViewState MAC off or encryption `Never` on pages that accept posted `__VIEWSTATE`
- Committed `machineKey` literals enabling ViewState forgery
- Cookieless session state embedding `(S(...))` in URLs on authenticated areas
- Authorization logic keyed on cookie presence instead of validated identity

## Safe Patterns

- `<compilation debug="false" />` or remove debug flag; use Release transforms to strip debug in deployed configs
- Default or explicit strong validation:
  ```xml
  <httpRuntime requestValidationMode="4.5" />
  <pages validateRequest="true" />
  ```
- Size uploads intentionally: keep `maxRequestLength` aligned with business max (≤ 4096 KB unless justified)
- Leave `enableHeaderChecking` enabled (default); set `X-Frame-Options`, secure cookie flags per `insecure_cookie.md`
- Narrow cookie `Domain` and `Path` to the application scope
- ViewState: omit `enableViewStateMac="false"`; use default MAC or `ViewStateEncryptionMode="Auto"`/`Always`
- `machineKey` from deployment secret store; never hardcode keys in source-controlled config
- `<sessionState cookieless="UseCookies" />` (default) — session id in HttpOnly cookie only
- Authorization via `User.Identity.IsAuthenticated`, role/membership checks, and `[Authorize]` — not cookie name presence

## Sanitizers / Barriers

- Release `Web.config` transform removing `debug` in same container — excludes debug-binary findings when present
- `requestValidationMode` value ≥ 4.5
- `validateRequest="true"` or absent false
- `maxRequestLength` ≤ 4096
- `enableHeaderChecking` not false
- Specific subdomain domain strings (narrow cookie domain)
- Path narrower than `/` (narrow cookie path)

## Configuration Examples

**VULN — debug enabled**:
```xml
<compilation defaultLanguage="c#" debug="true" />
```

**VULN — validation disabled**:
```xml
<pages validateRequest="false" />
```

**VULN — old validation mode**:
```xml
<httpRuntime requestValidationMode="4.0"/>
```

**VULN — oversized requests**:
```xml
<httpRuntime maxRequestLength="255000" />
```

**SAFE — validation enabled**:
```xml
<pages validateRequest="true" />
```

## C# / ASP.NET Core Notes

- Checks target classic `Web.config` / `system.web` XML (`semmle.code.asp.WebConfig`) — ASP.NET Core uses `appsettings.json` and middleware; many checks do not apply verbatim
- Request validation disabled is most relevant to Web Forms / legacy MVC; Core apps should use explicit model validation and output encoding (`output_encoding.md`, `xss.md`)
- Pair `validateRequest="false"` findings with `[ValidateInput(false)]` / `AllowHtml` usage review in code

## Common False Alarms

- `debug="true"` only in local `Web.Debug.config` excluded from production publish profile — confirm deployed artifact
- `validateRequest="false"` on a single page with documented `[ValidateInput(false)]` and strict encoding elsewhere — still risky; verify compensating controls
- Large `maxRequestLength` on internal-only bulk-import endpoints behind auth — confirm network isolation
- Broad cookie path on intentionally host-wide SSO cookie — verify threat model
- Release transform removes debug but static analysis cannot see transform target — Release transform XML in the same tree is modeled when present

## Business Risk

- **Debug builds**: verbose errors, source file paths, performance degradation, easier exploitation (CWE-011)
- **Disabled validation**: reflected XSS via raw request fields on legacy ASP.NET (see Microsoft request validation documentation)
- **Large uploads**: denial-of-service via memory exhaustion
- **Header checking off**: response splitting / header injection (CWE-113)
- **Broad cookies**: session token exposure across sibling apps on same domain

## Core Principle

ASP.NET defaults exist for a reason. Production configs must disable debug output, keep request validation at modern levels, bound upload size, and scope cookies narrowly. Configuration review is as critical as code review for Web Forms and classic MVC deployments.

## Analyst Notes

- Debug-binary findings also tagged CWE-532 (information exposure) — align severity with error-detail leakage
- Request validation is **not** a substitute for output encoding — cross-check `xss.md` and `output_encoding.md`
- For cookie flag issues (Secure/HttpOnly), see `insecure_cookie.md` — separate from domain/path queries here
- Missing ASP.NET global error handler (CWE-248) complements debug/error exposure — optional adjacent finding
- Infrastructure headers (HSTS, CSP) set at IIS/reverse proxy are invisible to application config scans — verify deployment layer

## Cross-References

- `insecure_deserialization.md` — ViewState `LosFormatter`/`ObjectStateFormatter` RCE when MAC/keys weak
- `weak_crypto_hash.md` — hardcoded `machineKey` and weak validation/decryption key material
- `session_fixation.md` — cookieless session URLs and missing session regeneration on login
- `xss.md` — XSS when validation is off or bypassed
- `output_encoding.md` — wrong-context encoding on ASP.NET writers
- `insecure_cookie.md` — Secure/HttpOnly/SameSite flags
- `denial_of_service.md` — upload and request size abuse
