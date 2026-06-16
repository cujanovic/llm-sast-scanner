---
name: certificate-validation
description: TLS certificate, hostname, pinning, and revocation validation failures (CWE-295/297/299/322)
---

# Certificate & Hostname Validation (CWE-295/297/299/322)

TLS clients must verify that server certificates are issued by a trusted authority, match the intended hostname, have not been revoked, and (where policy requires) match pinned keys. Disabling any of these checks exposes HTTPS connections to machine-in-the-middle attacks even when traffic appears encrypted.

## Source → Sink Pattern

Most certificate checks are **configuration/presence checks** — no remote taint flow. The dangerous API call or flag is the sink.

| Pattern | Sink | Risk |
|---------|------|------|
| Trust-all TrustManager | `checkServerTrusted` never throws | Accepts any certificate (CWE-295) |
| HostnameVerifier always true | `verify(hostname, session)` returns `true` | Accepts cert for wrong host (CWE-297) |
| Skip TLS verify | Go `InsecureSkipVerify: true`, Rust `danger_accept_invalid_certs` | No chain validation (CWE-295) |
| Skip hostname verify | Rust `danger_accept_invalid_hostnames` | Wrong-host cert accepted (CWE-297) |
| SSH host key policy | Paramiko `AutoAddPolicy` / `WarningPolicy` | Unknown host keys accepted (CWE-322) |
| Revocation disabled | `PKIXParameters.setRevocationEnabled(false)` without custom checker | Revoked certs trusted (CWE-299) |
| Missing Android pinning | HTTPS client with no `network-security-config` / `CertificatePinner` | Relies only on system CAs (CWE-295) |

## Vulnerable Conditions

- Custom `TrustManager`, `X509TrustManager`, or OkHttp interceptor that does not reject invalid chains.
- `HostnameVerifier` implementation returning `true` unconditionally or for all hostnames.
- TLS client config explicitly disabling certificate or hostname verification in production code.
- SSH client continuing after unknown host key instead of rejecting or requiring known key.
- Certificate path validation with revocation checking turned off and no replacement OCSP/CRL checker.
- Android/WebView or JavaMail connections without certificate validation enabled.

## Safe Patterns

- Default JVM / platform trust store with standard HTTPS APIs and no custom trust-all manager.
- `HostnameVerifier` delegating to `HttpsURLConnection.getDefaultHostnameVerifier()` or equivalent strict check.
- Go/Rust TLS clients with verification enabled; test-only skips isolated to `_test` files.
- Paramiko `RejectPolicy` (default) — throws on unknown host keys.
- `PKIXParameters.setRevocationEnabled(true)` (default) or custom `PKIXRevocationChecker`.
- Android `network-security-config` pin-set, OkHttp `CertificatePinner`, or TrustManager backed by a KeyStore containing only expected certs.

## Recognized Sanitizers / Safe APIs

- Default `TrustManagerFactory` / platform trust store initialization.
- `CertificatePinner` with explicit pins (Android/OkHttp).
- `RejectPolicy` for Paramiko SSH host keys.
- Custom revocation checker registered via `PKIXParameters.addCertPathChecker` when default revocation is disabled.

Commonly affected languages: Java, Go, Rust, Python (Paramiko, requests). No dedicated certificate-validation rules in standard JavaScript, Ruby, C#, or PHP web suites.

## Language Patterns

### Java / Spring / Android

**VULN**: `checkServerTrusted(X509Certificate[] chain, String authType) { }` — empty body, no `CertificateException`.
**SAFE**: Default SSL socket factory or TrustManager loaded from system KeyStore.

**VULN**: `new HostnameVerifier() { public boolean verify(String h, SSLSession s) { return true; } }`.
**SAFE**: Use default hostname verifier; fix certificate/ DNS mismatch instead of bypassing.

**VULN**: Android `OkHttpClient` with no `CertificatePinner` and no `network-security-config` pin-set.
**SAFE**: XML `network-security-config` with `<pin-set>` or OkHttp `CertificatePinner.Builder().add(...)`.

### Go

**VULN**: `tls.Config{InsecureSkipVerify: true}` in production HTTP client.
**SAFE**: Default `tls.Config` with system root CAs; pin custom CA via `RootCAs` pool.

### Python

**VULN**: `client.set_missing_host_key_policy(paramiko.AutoAddPolicy())`.
**SAFE**: `paramiko.RejectPolicy()` or explicit known-host key loading.

**VULN**: `requests.get(url, verify=False)` for HTTPS.
**SAFE**: `verify=True` (default) or path to trusted CA bundle.

### Rust

**VULN**: `ClientBuilder::danger_accept_invalid_certs(true)` or `danger_accept_invalid_hostnames(true)`.
**SAFE**: Default reqwest/native-tls client with verification enabled.

## Common False Alarms

- `InsecureSkipVerify` or trust-all code confined to `_test.go`, `*Test.java`, or mock servers in unit tests.
- Custom TrustManager that validates against a specific pinned certificate (not trust-all).
- Internal mTLS within a service mesh where verification is enforced at sidecar level — confirm in deployment, not visible in app code alone.
- Missing host key validation on dev-only SSH scripts not reachable from web attack surface.

## Business Risk

- Machine-in-the-middle interception of credentials, session tokens, and API secrets over "encrypted" channels.
- Acceptance of revoked or attacker-issued certificates when CAs or keys are compromised.
- Android apps vulnerable to rogue CA or corporate proxy abuse without pinning.
- SSH connections to backend infrastructure hijacked via host-key substitution.

## Analysis Workflow

1. Search for custom `TrustManager`, `HostnameVerifier`, `InsecureSkipVerify`, `verify=False`, and Paramiko policy setters.
2. Distinguish test-only skips from production HTTP/HTTPS client initialization.
3. For Android, check `AndroidManifest.xml` for `networkSecurityConfig` and OkHttp builder usage.
4. For Java mail/integration code, check JavaMail `mail.smtp.ssl.checkserveridentity` and WebView SSL handlers.
5. Confirm the client connects to external or user-influenced hosts — internal-only mTLS may be configured elsewhere.

## Core Principle

TLS provides confidentiality and authenticity only when certificate chain, hostname, revocation status, and optional pinning are all verified on every connection. Any bypass — even for debugging — must never ship in production code paths.
