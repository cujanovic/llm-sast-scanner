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
| SSH host key policy | Paramiko `AutoAddPolicy` / `WarningPolicy`, Go `ssh.InsecureIgnoreHostKey()` | Unknown host keys accepted (CWE-322) |
| Revocation disabled | `PKIXParameters.setRevocationEnabled(false)` without custom checker | Revoked certs trusted (CWE-299) |
| Missing Android pinning | HTTPS client with no `network-security-config` / `CertificatePinner` | Relies only on system CAs (CWE-295) |

## Vulnerable Conditions

- Custom `TrustManager`, `X509TrustManager`, or OkHttp interceptor that does not reject invalid chains.
- `HostnameVerifier` implementation returning `true` unconditionally or for all hostnames.
- TLS client config explicitly disabling certificate or hostname verification in production code.
- SSH client continuing after unknown host key instead of rejecting or requiring known key.
- Certificate path validation with revocation checking turned off and no replacement OCSP/CRL checker.
- Android/WebView or JavaMail connections without certificate validation enabled.
- Self-signed or expired embedded certs used as production trust anchors.
- Certificate pinning without backup pins or with user-bypass on pin failure.
- Hardcoded PEM certs with weak keys (RSA < 2048), SHA-1/MD5 signatures, or past `notAfter`.

## Certificate Chain & Hostname Verification

Every TLS client must validate the full chain against a trusted store **and** verify the server hostname matches the certificate SAN/CN. Never disable either check in production.

**Chain validation**
- Use platform default trust store or an explicit KeyStore of trusted CAs — not an empty or trust-all manager.
- Reject incomplete chains, expired/not-yet-valid certs, and signatures using MD5/SHA-1.

**Hostname verification**
- Delegate to platform default verifiers; do not return `true` unconditionally.
- Mismatch between requested host and cert SAN/CN must fail the connection — fix DNS/cert, do not bypass.

```java
// VULN: accepts any hostname
new HostnameVerifier() { public boolean verify(String h, SSLSession s) { return true; } }
```

```python
# VULN: chain validation disabled
requests.get("https://api.example.com", verify=False)
```

## Certificate Pinning — Patterns and Pitfalls

Pinning binds a host to expected certificate or public-key material. Use only when both endpoints are controlled and rotation is managed; most apps should rely on standard CA validation alone.

**When pinning may apply**
- Native mobile clients with controlled release/update channels.
- Threat model includes rogue or mis-issued CA certificates.
- Backup pins and rotation plan exist before deployment.

**When to avoid pinning**
- Web browsers (HPKP deprecated; no modern browser support).
- Endpoints where certificate lifecycle is not controlled.
- No secure pin-update path without full app redeployment.

**Pin types**
- Leaf certificate: highest certainty; breaks on every cert rotation unless backup pins exist.
- Subject public key (SPKI): survives cert renewal with same key pair — preferred balance.
- Intermediate CA: trusts all certs from that CA — use sparingly with backup.
- Root CA: not recommended — trusts entire CA subtree.

**Implementation patterns**

```xml
<!-- Android: network-security-config pin-set -->
<pin-set expiration="2027-01-01">
  <pin digest="SHA-256">base64+primary+pin==</pin>
  <pin digest="SHA-256">base64+backup+pin==</pin>
</pin-set>
```

```java
// OkHttp CertificatePinner — always include backup pin
new CertificatePinner.Builder()
    .add("api.example.com", "sha256/PRIMARY…")
    .add("api.example.com", "sha256/BACKUP…")
    .build();
```

**Common pitfalls (flag as risk)**
- Pinning without backup pins → outage on cert rotation.
- User-bypass UI on pin failure → defeats MITM protection.
- Custom TLS/pinning from scratch instead of platform or vetted library.
- TOFU (trust-on-first-use) pin preload — attacker can poison first connection.
- Root CA pinning without understanding expanded trust scope.
- Corporate interception proxy keys added to pinset without explicit risk acceptance.

## Self-Signed & Embedded Certificates

Self-signed or hardcoded certs (`Issuer == Subject`) must not ship in production client trust paths unless explicitly scoped to dev/test or internal mTLS with out-of-band trust distribution.

**Detection indicators**
- PEM literals: `-----BEGIN CERTIFICATE-----` embedded in source.
- File loads: `.pem`, `.crt`, `.cer`, `.der` read into custom `TrustManager` or `RootCAs`.
- `load_verify_locations` / `addCertPathChecker` with non-CA local cert as sole trust anchor in prod code.

**Mandatory sanity checks on embedded/loaded certs**
- `notAfter` not in the past; `notBefore` not in the future.
- RSA key ≥ 2048 bits; EC curve ≥ P-256 (reject secp192r1, P-192, P-224).
- Signature algorithm SHA-2 family — flag MD5/SHA-1 (`md5WithRSAEncryption`, `sha1WithRSAEncryption`).
- Self-signed (`Issuer == Subject`) in prod-facing code → LIKELY misconfiguration.

```go
// VULN: self-signed cert as sole trust anchor in production client
certPool := x509.NewCertPool()
certPool.AddCert(selfSignedCert)
tlsConfig := &tls.Config{RootCAs: certPool}
```

## OCSP, Revocation & Expiry Handling

**Revocation**
- Keep default PKIX revocation enabled; do not disable without registering a replacement checker.
- Flag `PKIXParameters.setRevocationEnabled(false)` with no custom `PKIXRevocationChecker`.
- Monitor OCSP stapling on servers; clients should fail closed when revocation status is required by policy.

**Expiry**
- Flag hardcoded certs or server configs with no rotation mechanism.
- Alert on cert load paths missing notAfter validation before use.
- Coordinate pin-set `expiration` attributes with backend cert rotation schedules.

```java
// VULN: revocation checking explicitly disabled
params.setRevocationEnabled(false); // no addCertPathChecker replacement
```

## Detection Indicators — Disabled Verification

| Signal | Pattern |
|--------|---------|
| Python skip verify | `verify=False`, `ssl._create_unverified_context()` |
| Node skip verify | `NODE_TLS_REJECT_UNAUTHORIZED=0`, `rejectUnauthorized: false` |
| Go skip verify | `InsecureSkipVerify: true` |
| Go SSH host key | `HostKeyCallback: ssh.InsecureIgnoreHostKey()` (golang.org/x/crypto/ssh) |
| Go gRPC insecure transport | client `grpc.WithInsecure()` / `grpc.WithTransportCredentials(insecure.NewCredentials())`; server `grpc.NewServer()` with no `grpc.Creds(...)` — cleartext gRPC with **no** transport security (cross-ref `cleartext_transmission.md`) |
| Rust skip verify | `danger_accept_invalid_certs(true)`, `danger_accept_invalid_hostnames(true)` |
| Java trust-all | empty `checkServerTrusted`, `TrustAllStrategy`, `ALLOW_ALL_HOSTNAME_VERIFIER` |
| OkHttp bypass | `hostnameVerifier((h,s) -> true)` |
| cURL/libcurl | `CURLOPT_SSL_VERIFYPEER 0`, `CURLOPT_SSL_VERIFYHOST 0` |
| OpenSSL client | `SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL)` |
| .NET | `ServerCertificateValidationCallback` always returns `true` |
| Paramiko SSH | `AutoAddPolicy()`, `WarningPolicy()` |
| Android WebView | `onReceivedSslError` → `handler.proceed()` |
| Erlang/Elixir | `ssl:connect(..., [{verify, verify_none}])` / `:ssl.connect(..., [verify: :verify_none])`; `{fail_if_no_peer_cert, false}` on a server (no `verify_peer`) |
| Swift Alamofire | `ServerTrustManager(evaluators: [host: DisabledTrustEvaluator()])` (disables evaluation per-host) |
| Obj-C AFNetworking | `AFSecurityPolicy.allowInvalidCertificates = YES`, `validatesDomainName = NO` |
| Obj-C WebKit/NSURLConnection | `[NSURLRequest setAllowsAnyHTTPSCertificate:YES forHost:]`; `didReceiveAuthenticationChallenge` → `continueWithoutCredentialForAuthenticationChallenge` |

Distinguish test-only usage (`_test.go`, `*Test.java`, mock servers) from production client initialization.

## Fail-Open / Silent No-Op Verification (verification present but skipped)

More dangerous than an explicit `verify=false` is a verification path that **silently degrades to no checking** for a non-obvious input — code review and the table above both miss it because the call *looks* enabled. Treat any of these as disabled verification:

- **Tri-state / falsy option that isn't a strict boolean**: Node treats `rejectUnauthorized: undefined` (and any non-`true` value produced when an options object is built dynamically, e.g. `{ rejectUnauthorized: opts.strict }` where `opts.strict` is missing) the same as `false`. Flag TLS option objects where the verify flag can be `undefined`/`null`/`""` at runtime rather than a literal `true`.
- **Length/empty-argument no-op across crypto libraries**: `X509_VERIFY_PARAM_set1_host(param, host, 0)` — passing `namelen = 0` means "use strlen" on OpenSSL but is a **no-op (hostname check disabled)** on LibreSSL/BoringSSL. Any verify-setup call where a name/length/option argument can be empty or zero needs an explicit non-empty assertion; do not assume cross-library parity.
- **Backend silently ignores an unsupported option**: setting issuer/CRL/curve/hostname options on a TLS backend that does not implement them returns success while the control is inert. Require the code to verify the option took effect (or fail closed) instead of trusting the setter's return.
- **Opportunistic-TLS / STARTTLS continues in cleartext on negotiation failure**: a mandatory-TLS flag (e.g. `--ssl-reqd`, "require TLS") that proceeds when the `STARTTLS`/upgrade command returns a non-OK status (or when the server omits the capability) downgrades to plaintext, and pipelined data sent before the handshake can be injected by a MITM. Opportunistic-upgrade paths must hard-fail on any non-OK negotiation response.
- **Unknown host key accepted (`accept-new`) before secret is sent**: SSH/SFTP clients configured with `accept-new` (or that auto-add when `known_hosts` lacks an entry) authenticate to an unverified host on first contact — if a password/key is sent before the trust prompt, a MITM on first connection captures it. Treat "missing known_hosts entry ⇒ trust" as fail-open (same category as Paramiko `AutoAddPolicy`).

```javascript
// VULN: dynamically-built options — rejectUnauthorized is undefined when cfg.strict is unset → cert check OFF
const agent = new https.Agent({ rejectUnauthorized: cfg.strict });

// SAFE: coerce to a strict boolean and default to secure
const agent = new https.Agent({ rejectUnauthorized: cfg.strict !== false });
```

## Safe Patterns

- Default JVM / platform trust store with standard HTTPS APIs and no custom trust-all manager.
- `HostnameVerifier` delegating to `HttpsURLConnection.getDefaultHostnameVerifier()` or equivalent strict check.
- Go/Rust TLS clients with verification enabled; test-only skips isolated to `_test` files.
- Paramiko `RejectPolicy` (default) — throws on unknown host keys.
- Go SSH clients using `ssh.FixedHostKey(pub)` or a `knownhosts` callback instead of `ssh.InsecureIgnoreHostKey()`.
- `PKIXParameters.setRevocationEnabled(true)` (default) or custom `PKIXRevocationChecker`.
- Android `network-security-config` pin-set with backup pins, OkHttp `CertificatePinner`, or TrustManager backed by a KeyStore containing only expected certs.

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

1. Search for custom `TrustManager`, `HostnameVerifier`, `InsecureSkipVerify`, `verify=False`, `NODE_TLS_REJECT_UNAUTHORIZED`, and Paramiko policy setters.
2. Distinguish test-only skips from production HTTP/HTTPS client initialization.
3. For Android, check `AndroidManifest.xml` for `networkSecurityConfig`, `<pin-set>` backup coverage, and OkHttp `CertificatePinner` usage.
4. For Java mail/integration code, check JavaMail `mail.smtp.ssl.checkserveridentity` and WebView SSL handlers (`handler.proceed()`).
5. Scan for embedded PEM blocks and cert file loads; verify key strength, signature algorithm, expiry, and self-signed status.
6. Confirm revocation checking is not disabled without a replacement checker; verify pin rotation/expiry attributes.
7. Confirm the client connects to external or user-influenced hosts — internal-only mTLS may be configured elsewhere.

## Core Principle

TLS provides confidentiality and authenticity only when certificate chain, hostname, revocation status, and optional pinning are all verified on every connection. Any bypass — even for debugging — must never ship in production code paths.
