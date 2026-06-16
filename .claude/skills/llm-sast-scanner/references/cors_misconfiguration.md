---
name: cors-misconfiguration
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

## Safe Patterns

- Fixed allowlist of exact origin strings; reject unknown origins (no reflection)
- `Access-Control-Allow-Credentials: true` only with a single explicit origin, never `*` or `null`
- Parse origin URL and compare scheme + host + port exactly against whitelist
- Default-deny CORS; enable per-route only where cross-origin credentialed access is required

## Evasion Patterns

- Subdomain bypass: whitelist `https://example.com` but accept `https://example.com.attacker.com` via prefix checks
- Null origin from sandboxed iframe or `data:` documents
- Case/unicode normalization differences between validator and browser
- Pre-flight vs simple-request divergence on different routes

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
