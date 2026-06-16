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
- Server/client allows TLS 1.0/1.1, SSLv3, or weak/export/null ciphers.
- HTTPS site serves session cookies without `Secure` flag or accepts HTTP without redirect.
- Active mixed content (`http://` scripts/XHR) on TLS pages; missing HSTS on production HTTPS hosts.

## Safe Patterns

- Enforce HTTPS: `https://` URLs, `HttpsURLConnection`, TLS 1.2+ with certificate validation.
- HSTS on web properties; upgrade-insecure-requests in CSP.
- Send secrets in request body over TLS, never in query string.
- Pin or trust-store validate production endpoints; use SSL socket factory patterns (Java).
- TLS 1.3 default with TLS 1.2 minimum; disable SSLv3/TLS 1.0/1.1; strong AEAD cipher suites only.
- HTTP 301/308 redirect to HTTPS; HSTS with `includeSubDomains` (and `preload` only when fully ready).
- `Secure` flag on all session/auth cookies; no active mixed content on HTTPS pages.

**Recognized mitigations**: explicit `https` scheme; `HttpsURLConnection`; modern TLS protocol constants; `requireSSL=true` (ASP.NET); `Strict-Transport-Security` header; `ssl_protocols TLSv1.2 TLSv1.3`.

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

## TLS Protocol & Cipher Hardening

Production endpoints must negotiate TLS 1.2 or 1.3 only. Legacy protocols and weak ciphers defeat confidentiality even when the URL uses `https://`.

**Protocol requirements**
- Default to TLS 1.3; allow TLS 1.2 only when legacy client compatibility is required.
- Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 in server and client configs.
- Enable TLS_FALLBACK_SCSV where fallback paths exist to block downgrade attempts.

**Cipher requirements**
- Prefer AEAD ciphers (AES-GCM, ChaCha20-Poly1305); disable null, anonymous, and EXPORT ciphers.
- Disable TLS compression (CRIME mitigation).
- Configure secure DH/ECDH groups (e.g., x25519, secp256r1, ffdhe3072).

**Detection indicators — weak TLS config**

| Signal | Example pattern |
|--------|-----------------|
| Legacy protocol enabled | `SSLProtocol all -SSLv2` (still allows TLS 1.0/1.1); `ssl_protocols TLSv1 TLSv1.1 TLSv1.2` |
| Explicit legacy allow | `MinProtocol = TLSv1`; `SecurityProtocol = Ssl3 \| Tls` |
| Weak/null cipher | `EXPORT`, `NULL`, `ADH`, `aNULL`, `RC4`, `DES`, `3DES` in cipher lists |
| Compression on | `SSLCompression on`; OpenSSL `COMP` methods enabled |
| Client downgrade | Node `secureProtocol: 'TLSv1_method'`; Java `SSLContext.getInstance("TLSv1")` |

```nginx
# VULN: legacy protocols and weak ciphers
ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
ssl_ciphers 'ECDHE-RSA-DES-CBC3-SHA:RC4-SHA';
```

```java
// SAFE: restrict to TLS 1.2+
SSLContext ctx = SSLContext.getInstance("TLSv1.2");
// or TLSv1.3 where supported
```

## HTTPS Enforcement, HSTS, and Mixed Content

**HTTP → HTTPS redirect**
- All HTTP requests must 301/308 redirect to HTTPS before sensitive data is exchanged.
- Flag listeners bound to port 80 without redirect rules; flag hardcoded `http://` canonical/base URLs in prod configs.

```nginx
# SAFE: force HTTPS
server { listen 80; return 301 https://$host$request_uri; }
```

**HSTS**
- Emit `Strict-Transport-Security` on all HTTPS responses; include `includeSubDomains` when all subdomains are TLS-ready.
- Add `preload` only after verifying full HTTPS coverage and subdomain readiness (misconfiguration causes long-lived browser lockout).

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Secure cookies over TLS**
- Session/auth cookies must set `Secure` on HTTPS sites; pair with `HttpOnly` and `SameSite`.
- Flag `Set-Cookie` without `Secure` on TLS-terminated routes; ASP.NET `requireSSL="false"`; Express `cookie({ secure: false })` in production.

```javascript
// VULN: session cookie may leak on HTTP downgrade paths
res.cookie('session', token, { httpOnly: true, secure: false });
```

**Mixed content**
- Active mixed content (`http://` scripts, XHR, WebSocket upgrade, iframes) bypasses page TLS and enables session theft or script injection.
- Flag hardcoded `http://` asset URLs in HTML/JS/CSS templates served over HTTPS; CSP missing `upgrade-insecure-requests` when legacy HTTP assets remain.

```html
<!-- VULN: active mixed content on HTTPS page -->
<script src="http://cdn.example.com/app.js"></script>
```

Even with HTTPS APIs, pages that load active mixed content weaken transport guarantees. Pair non-HTTPS URL findings with front-end asset review and CSP header inspection.

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
