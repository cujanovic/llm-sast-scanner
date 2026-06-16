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

## Vulnerable Conditions

- Production deployment with `debug="true"` — stack traces, source hints, performance/memory impact (CWE-011 / CWE-532 in query tags)
- Global `validateRequest="false"` on Web Forms / legacy ASP.NET pages
- `requestValidationMode` below 4.5 while relying on platform XSS filtering
- Multi-megabyte `maxRequestLength` on public-facing upload endpoints
- Header checking disabled — CRLF/header injection risk increases
- Session cookies scoped to parent domain or `/` path unnecessarily

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

- `xss.md` — XSS when validation is off or bypassed
- `output_encoding.md` — wrong-context encoding on ASP.NET writers
- `insecure_cookie.md` — Secure/HttpOnly/SameSite flags
- `denial_of_service.md` — upload and request size abuse
