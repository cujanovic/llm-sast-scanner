---
name: cleartext-transmission
description: Cleartext transmission and missing TLS for sensitive web/API traffic (CWE-319, CWE-311)
---

# Cleartext Transmission (CWE-319, CWE-311)

Sensitive data sent over HTTP, unencrypted sockets, or non-TLS channels is readable on the network and in logs/proxies. Web focus: outbound API calls, redirect URLs, form actions, WebSocket schemes, and mobile/backend clients omitting TLS.

## Source -> Sink Pattern

**Sources** (sensitive data):
- Passwords, tokens, session IDs, PII, payment data marked sensitive in data-flow models
- Credentials in query strings (also see sensitive GET query patterns)

**Sinks** (cleartext transmission):
- `http://` URLs in fetch/XHR/axios, `HttpURLConnection` (non-SSL), plain `Socket`
- `URL.openConnection()` without HTTPS
- Rust `reqwest`/`hyper` to `http://` with sensitive body
- Swift `URLSession` / `URLRequest` without TLS
- Ruby gem downloads over HTTP
- C# SQL connection strings without encryption; missing `requireSSL` on cookies

## Vulnerable Conditions

- Hardcoded or constructed `http://` endpoint for auth, payment, or health APIs.
- TLS disabled via `verify=False`, `InsecureSkipVerify`, custom `TrustManager` that accepts all certs (related CWE-295, not cleartext but often co-located).
- Sensitive values appended to URL query (visible in access logs and Referer).
- WebSocket `ws://` carrying session tokens on untrusted networks.

## Safe Patterns

- Enforce HTTPS: `https://` URLs, `HttpsURLConnection`, TLS 1.2+ with certificate validation.
- HSTS on web properties; upgrade-insecure-requests in CSP.
- Send secrets in request body over TLS, never in query string.
- Pin or trust-store validate production endpoints; use SSL socket factory patterns (Java).

**Recognized mitigations**: explicit `https` scheme; `HttpsURLConnection`; modern TLS protocol constants; `requireSSL=true` (ASP.NET).

## Language Patterns

### Java / Spring
- **VULN**: `new URL("http://api.internal/auth").openConnection()` sending password bytes
- **VULN**: `RestTemplate` POST to `http://` payment gateway with card data
- **SAFE**: `HttpsURLConnection`, `https://` URI, TLS-enabled `RestTemplate` with verified trust store

### JavaScript / Node
- **VULN**: `fetch('http://api.example.com/login', { body: JSON.stringify({ password }) })`
- **SAFE**: `fetch('https://…')` with default TLS verification intact

Note: JavaScript/Node has no dedicated cleartext-transmission rule in standard packs; related findings use clear-text logging, sensitive GET query, and disabling certificate validation (CWE-295).

### Python
- **VULN**: `requests.post('http://…', data={'ssn': ssn})`
- **SAFE**: `https://` URLs; `requests` with cert verification enabled

### Rust
- **VULN**: sensitive struct serialized into query of `http://service/...`
- **SAFE**: `https://` only; `rustls` with valid roots

### C# / ASP.NET
- **VULN**: `new SqlConnection("Server=…;Encrypt=False;…")` with credentials
- **SAFE**: `Encrypt=True`; HTTPS site URLs; `requireSSL="true"`

### Ruby
- **VULN**: Gemfile/source or `open-uri` fetch over `http://` for signed release artifacts
- **SAFE**: `https://` gem source; TLS-verified downloads

## Related Web Misconfigurations

| Issue | Detection focus |
|-------|-----------------|
| Passwords/tokens in URL query | Logged in cleartext even over HTTPS |
| TLS MITM via disabled certificate validation | Effective cleartext despite HTTPS scheme |
| Secrets logged server-side after HTTPS transit | Cleartext storage/logging, not transport |
| Session cookie without Secure flag on HTTPS site | Cookie may leak on downgrade paths |

## HSTS and Mixed Content

Even with HTTPS APIs, pages that load active mixed content (`http://` scripts) weaken transport guarantees. Automated scans do not flag mixed content directly; pair non-HTTPS URL findings with front-end asset review.

## Common False Alarms

- `http://localhost` or `http://127.0.0.1` in dev-only branches (still flag for prod configs).
- Public, non-sensitive static assets over HTTP on CDN while API uses HTTPS — informational unless mixed content pulls cookies.
- Self-signed TLS misclassified as cleartext — separate CWE-295 finding.

## Business Risk

- Credential and session theft on public Wi‑Fi / compromised ISP.
- PCI-DSS and GDPR violations for card/PII in cleartext.
- Downgrade attacks combined with passive surveillance of API traffic.
- Compliance audit failure: cleartext transmission findings map directly to ASVS V9 transport requirements.

## Core Principle

Sensitive data belongs on TLS-protected channels only. Use HTTPS URLs, encrypted transports, and keep secrets out of query strings—even when the path is encrypted, logs and Referer headers are not.

## Analyst Notes

1. Distinguish **cleartext transport** (CWE-319/311) from **cleartext storage/logging** — same secret may need both tags.
2. Internal service mesh mTLS is out of scope for plain-socket checks; rules target `java.net` plain sockets and `http://` URL constructors.
3. Non-HTTPS URL rules flag URL literals; pair with dataflow review when scheme is built dynamically from user input.
4. WebSocket: `ws://` with auth cookie is equivalent finding — manual review when no dedicated automated rule exists.
5. Reverse proxies terminating TLS do not eliminate need for backend HTTPS on untrusted network segments.
