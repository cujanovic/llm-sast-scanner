---
name: host-header-poisoning
description: Host header poisoning and email injection detection (CWE-640)
---

# Host Header Poisoning / Email Injection (CWE-640)

Using the HTTP `Host` header (or derived values like `req.host`, `X-Forwarded-Host`) to build absolute URLs — especially in password-reset emails — lets attackers poison links so victims leak reset tokens to attacker-controlled hosts. Related email-body injection covers untrusted input embedded in outbound mail content.

## Source -> Sink Pattern

**Sources**:
- HTTP `Host` header and derived request properties (`req.host`, `req.hostname`, `request.getHeader("Host")`)
- `X-Forwarded-Host`, `X-Forwarded-Proto`, `Forwarded` when used to reconstruct public base URLs without validation
- Remote user input reaching email subject/body/recipients (Go email injection)

**Sinks**:
- JavaScript: email generation functions that embed `req.host` into password-reset or notification links
- Go: mail composition APIs (`SendMail`, `text/template` on email body) with tainted content
- Any `https://${host}/reset?token=...` built from request context instead of configured canonical URL

## Vulnerable Conditions

- Password reset / verification / invite emails using `Host` header for link hostname
- Trusting `X-Forwarded-Host` from clients without reverse-proxy strip/validate
- Email templates interpolating unsanitized user fields into headers (`To`, `Subject`) or body (Go injection)

## Safe Patterns

- Canonical public base URL from environment/config (`PUBLIC_URL`, `APP_URL`) — never from request headers
- Validate `Host` against allowlist at edge; ignore client-supplied forwarded host unless set by trusted proxy
- For email: fixed domain in links; encode/sanitize user content in body; validate recipient addresses

## Evasion Patterns

- `Host: evil.com` on direct server access bypassing CDN host validation
- `X-Forwarded-Host: evil.com` when app trusts forwarded headers from any client
- Email header injection via `%0d%0aBcc: attacker@evil.com` in name fields (Go email injection class)

## JavaScript / Node

Taint from HTTP host header sources to email-generation sinks where links are built. Fix: read canonical hostname from config file, not `req.host`.

- **VULN**: `` const link = `https://${req.host}/reset?token=${token}`; sendMail(user, link); ``
- **SAFE**: `` const link = `${process.env.PUBLIC_URL}/reset?token=${token}`; ``

## Go

Path-problem from remote sources to email composition APIs. Distinct from host poisoning but same CWE-640 family — untrusted input in mail content enables Bcc injection and body spoofing.

- **VULN**: `` fmt.Fprintf(&buf, "Hello %s", userInput) `` then passed to `smtp.SendMail` — header/body injection
- **SAFE**: templated email with fixed headers; sanitize or struct-encode user fields

## Java / Spring / Python

Manual patterns: `ServletRequest.getServerName()`, Flask `request.host`, Django `request.get_host()` in reset emails

## Common False Alarms

- `Host` used only for logging, not for security-sensitive link generation
- Internal health-check routes that never send email
- Go email injection on HTML-escaped template output where newlines in headers are rejected by mail library

## Business Risk

- Password reset token theft and account takeover
- Phishing emails appearing to originate from trusted domain with attacker links
- OAuth/OIDC redirect URI poisoning when host-derived base URLs affect callback construction

## Core Principle

The authoritative site URL lives in server configuration, not in client-supplied host headers. Never embed request-derived hostnames in outbound security-sensitive links or emails.

## Related Attack Surfaces (manual review)

Automated detection covers email-link host poisoning (JavaScript) and email body injection (Go). Also review manually:
- Password reset tokens in query strings on poisoned host links
- Cache poisoning via poisoned `Host` affecting cached responses
- SSRF when internal fetches use `Host`/`X-Forwarded-Host` as URL authority (see `ssrf.md`)
- Webhook callback URL generation from request context

## Ruby / Python / Java / C#

High-value manual patterns:
- Rails: `default_url_options` using `request.host` in mailers
- Django: `request.get_host()` in password reset templates
- Spring: `ServletUriComponentsBuilder.fromCurrentContextPath()` with spoofed Host
- ASP.NET: `Request.Host` in `Url.Action` for email links

## Analyst Notes

- Validate at reverse proxy: reject unknown `Host` values before they reach application code
- `X-Forwarded-Host` should be stripped at edge and re-set only by trusted proxies
- Do not flag logging-only uses of `request.getServerName()` without email/link sinks

## CWE-640 Scope

Host-header email poisoning and Go email content injection map to CWE-640 (weak password recovery). Broader host-header attacks (cache poisoning, SSRF) overlap CWE-348 / CWE-918 — cross-reference other reference files when impact exceeds email.

## Detection Priority

1. Password reset / email verification / magic-link generation paths
2. OAuth redirect URI reconstruction from request host
3. Absolute URL builders using `req.protocol + '://' + req.get('host')`
4. Go mail templates with unsanitized user fields (path-problem from remote input)

## Business Risk Summary

Host poisoning turns trusted email into an attacker-controlled phishing channel. Reset-token leakage is one-click account takeover when victims follow poisoned links from legitimate senders.
