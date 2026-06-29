---
name: authentication-jwt
description: JWT and OIDC security testing covering token forgery, algorithm confusion, kid/jku/x5u/jwk/x5c header injection and JKU allowlist bypass, JWE encryption-layer attacks (RSA1_5/CBC padding oracle, ECDH-ES invalid curve, PBES2 p2c DoS, GCM nonce reuse, zip decompression bomb, nested alg:none JWE→JWS confusion), ECDSA psychic signatures, OAuth/OIDC token-validation gaps (at+jwt typ confusion, ALBeast shared-signer binding, DPoP downgrade/ath), and claim manipulation
---

# Authentication / JWT / OIDC

Weaknesses in JWT and OIDC implementations frequently allow token forgery, cross-context token acceptance, service confusion, and durable account takeover. Headers, claims, and token opacity must never be trusted without strict validation that binds the token to the correct issuer, audience, key, and client context.

**Core pattern**: the server does not fully verify the JWT's authenticity and integrity before trusting its claims.

## Scope

### What It Is

- Algorithm confusion (`alg: none`, RS256→HS256) when verification does not pin allowed algorithms
- Missing or disabled signature verification (`verify_signature: False`, decode-only calls)
- Weak or hardcoded HMAC secrets brute-forceable offline
- Header-driven key selection under attacker control (`jwk`, `jku`, `x5u`, `kid` injection)
- Missing claim validation (`exp`, `iss`, `aud`, `nbf`) enabling replay or cross-service acceptance

### What It Is Not

- **IDOR via claim edit**: changing `user_id` to access another user's data — authorization flaw; flag only if the token itself can be forged
- **XSS in JWT payload**: unescaped claim rendered in HTML — XSS, not JWT integrity
- **CSRF**: JWT in cookies without `SameSite` — CSRF, not signature bypass
- **Correctly restricted verification**: `jwt.verify(token, secret, { algorithms: ['HS256'] })` with strong secret and full claim checks

## Where to Look

- Web, mobile, and API authentication built on JWT (JWS/JWE) and OIDC/OAuth2
- Access tokens, ID tokens, refresh tokens, device code flows, PKCE, and Backchannel flows
- First-party and microservice verification logic, API gateways, and JWKS distribution endpoints

## Reconnaissance

### Endpoints

- Well-known: `/.well-known/openid-configuration`, `/oauth2/.well-known/openid-configuration`
- Keys: `/jwks.json`, rotating key endpoints, tenant-specific JWKS URLs
- Auth: `/authorize`, `/token`, `/introspect`, `/revoke`, `/logout`, device code endpoints
- App: `/login`, `/callback`, `/refresh`, `/me`, `/session`, `/impersonate`

### Token Features

- Headers: `{"alg":"RS256","kid":"...","typ":"JWT","jku":"...","x5u":"...","jwk":{...}}`
- Claims: `{"iss":"...","aud":"...","azp":"...","sub":"user","scope":"...","exp":...,"nbf":...,"iat":...}`
- Formats: JWS (signed), JWE (encrypted). Note the unencoded payload option (`"b64":false`) and critical headers (`"crit"`)

### Code Indicators

Grep verification and issuance sites before assessing endpoints:

```bash
# Libraries
rg -n "import jwt|from jose|jsonwebtoken|@nestjs/jwt|io\.jsonwebtoken|com\.auth0\.jwt|golang-jwt|dgrijalva/jwt-go|lestrrat-go/jwx|firebase/php-jwt|lcobucci/jwt" .

# Signature bypass
rg -n "verify_signature.*False|verify_signature:\s*false|jwt\.decode\(|options=\{.*verify|complete\s*[:=]\s*[Ff]alse" .
# token pulled from a query string (logged in URLs/referrer, weaker than header/cookie):
rg -n "request\.args\.get\(['\"]token|req\.query\.(token|jwt|access_token)|query_params\[['\"]token" .

# Algorithm confusion / none acceptance
rg -n "algorithms.*none|get_unverified_header" .

# Missing claim validation
rg -n "verify_exp.*False|verify_iss.*False|verify_aud.*False|require.*exp" .

# Weak or hardcoded secrets (<32 chars or dictionary words)
rg -n "SECRET.*=.*[\"'](secret|password|changeme|jwt)" .

# Key lookup from attacker-controlled header fields
rg -n '"kid"|"jku"|"x5u"|"jwk"' .

# OAuth2 misconfiguration
rg -n "response_type.*token|implicit|password.*grant|grant_type.*password" .
rg -n "redirect_uri|startsWith|includes\(|indexOf|match\(" .
rg -n "code_challenge_method.*plain|code_verifier" .

# SAML processing gaps
rg -n "getElementsByTagName|InResponseTo|NotOnOrAfter|Recipient|OneTimeUse" .
rg -n "SAMLResponse|Assertion|XMLSignature|KeyInfo" .

# MFA bypass / weak OTP handling
rg -n "skipMfa|bypass.*mfa|mfa.*optional|verifyTotp|recovery.*code" .
rg -n "totp.*secret|TOTP_SECRET|otp.*window|rateLimit.*otp" .

# Auth hardening gaps
rg -n "user not found|invalid password|account.*lock|password.*reset" .
```

Red flags at verification sites: no `algorithms` allowlist on asymmetric endpoints (RS256→HS256), `jwt.decode()` (Node.js) used for auth decisions, manual base64 payload decode without signature check, `kid` interpolated into SQL or file paths.

## Vulnerability Patterns

### Signature Verification

- RS256→HS256 confusion: change alg to HS256 and use the RSA public key as the HMAC secret when algorithm pinning is absent
- "none" algorithm acceptance: set `"alg":"none"` and omit the signature if libraries process it without rejection
- ECDSA malleability/misuse: weak verification settings that accept non-canonical signatures
- **Psychic signatures (ECDSA `r=s=0`)**: a signature whose `r` and `s` are both zero (e.g. base64url `MAYCAQACAQA`) verifies for *any* message under *any* key on ECDSA implementations that skip the `r,s ∈ [1, n-1]` range check — canonically CVE-2022-21449 on Java 15–18 (`java.security`/Nimbus/`jjwt` on a vulnerable JDK), but the *pattern* (not just that JDK) is the finding. SAST signal: ES256/ES384/ES512 verification running on a JDK in the 15–18 range without the patch, or any custom ECDSA verifier that does not reject zero/`>= n` `r`/`s`. Grep: `rg -n "ES256|ES384|ES512|EC.*verify|Signature\.getInstance\(\"SHA256withECDSA\"" --glob '*.java'` and check the target JDK version.
- **Validation knobs explicitly disabled (config-level bypass)**: a token handler configured to skip a verification step is equivalent to accepting forged/expired tokens. **.NET** `TokenValidationParameters` with `RequireSignedTokens = false` (accepts unsigned JWTs — "a username with no password"), `ValidateIssuerSigningKey = false`, `ValidateLifetime = false` / `RequireExpirationTime = false` (replay of expired tokens), `ValidateIssuer = false` / `ValidateAudience = false` (cross-tenant/cross-app token reuse), or a custom `SignatureValidator`/`TokenReader` delegate that returns the token without verifying. Equivalents elsewhere: passing `{ algorithms: [...] }` that includes `"none"`, Go `jwt.ParseUnverified`, Python `jwt.decode(..., options={"verify_signature": False})`, Java `parseClaimsJwt` (unsigned) / disabled `requireExpiration`. Grep: `rg -n "RequireSignedTokens\s*=\s*false|ValidateIssuerSigningKey\s*=\s*false|ValidateLifetime\s*=\s*false|RequireExpirationTime\s*=\s*false|ValidateIssuer\s*=\s*false|ValidateAudience\s*=\s*false|SignatureValidator\s*=" --glob '*.cs'`. **SAFE**: leave the `Validate*`/`Require*` flags at their secure defaults (`true`) and pin signing keys/issuer/audience.
- **Extractor-as-authenticator (no decode at all)**: a bearer-token *extraction* dependency is treated as authentication, with the token string never passed to a signature-verifying decode. **FastAPI**: `oauth2_scheme = OAuth2PasswordBearer(tokenUrl=...)` (or `HTTPBearer()`), then `def route(token: str = Depends(oauth2_scheme))` where the handler uses `token` (or merely the fact the dependency returned) without calling `jwt.decode(token, key, algorithms=[...])` — `OAuth2PasswordBearer`/`HTTPBearer` only *pull the string from the header*; they do **not** validate it, so any non-empty `Authorization: Bearer x` authenticates. Signal: a route depending on `OAuth2PasswordBearer`/`HTTPBearer` with no signature-verifying decode of the extracted token in the dependency chain. **SAFE**: a dependency that decodes **and** verifies (`jwt.decode(..., algorithms=[...], audience=..., issuer=...)`) and raises `401` on failure before the handler runs.

### JWE (Encrypted Token) Attacks

JWE is the encrypted JWT form (5 dot-separated parts: protected header, encrypted key, IV, ciphertext, tag). Beyond the JWS attacks above, the **key-management (`alg`) and content-encryption (`enc`) choices are themselves an attack surface**, and most are detectable from configuration/library use:

- **`alg` not pinned on decryption**: the decryptor trusts the token's header `alg`/`enc` instead of an allowlist — the JWE analogue of alg confusion. Pin both `alg` and `enc` to the expected values before decrypting.
- **RSA1_5 (RSA PKCS#1 v1.5) key wrapping → Bleichenbacher / Million-Message oracle**: any use of `RSA1_5` (vs `RSA-OAEP`/`RSA-OAEP-256`) is a padding-oracle risk; flag it outright.
- **AES-CBC content encryption (`A128CBC-HS256`/`A256CBC-HS512`) padding oracle**: exploitable when decryption errors are distinguishable; prefer AEAD (`A256GCM`). Decrypt-then-MAC ordering or leaked padding errors are the signal.
- **ECDH-ES invalid-curve / untrusted `epk`**: the ephemeral public key (`epk`) from the header is used in ECDH without validating the point is on the expected curve — leaks the static private key over repeated requests. Signal: ECDH-ES decryption that does not validate/whitelist the `epk` curve and point.
- **PBES2 (`PBES2-HS256+A128KW`…) DoS via attacker-controlled `p2c`**: the iteration count `p2c` comes from the token header; an unbounded value (e.g. 10^9) makes one request burn CPU. Signal: PBES2 key-management with no upper bound enforced on `p2c`.
- **AES-GCM IV/nonce reuse ("forbidden attack")**: reusing a 96-bit IV across two messages under the same key recovers the GHASH authentication key → tag forgery. Signal: static/counter IVs or app-managed nonces for `A*GCM` instead of fresh CSPRNG per encryption.
- **`zip:"DEF"` decompression bomb**: JWE may DEFLATE-compress the payload before encryption; a token whose compressed body expands to gigabytes exhausts memory on decrypt (CVE-2024-33664, CVE-2024-21319 class). Signal: JWE decompression with no decompressed-size cap. Reject `zip` or bound the inflated size.
- **JWE→JWS confusion (nested `alg:none`)**: the decryptor unwraps the JWE, finds a *nested* JWT, and trusts its claims **without verifying the inner signature** — an inner `alg:none` (or attacker-signed) token then bypasses auth entirely (pac4j-jwt CVE-2026-29000 class, CVSS 10.0). Signal: decrypt step followed by claim use without an explicit inner-JWS verification with a pinned algorithm.

**Grep seeds**:
```bash
rg -n "RSA1_5|A128CBC-HS256|A256CBC-HS512|PBES2|ECDH-ES|p2c|epk|zip.*DEF|JsonWebEncryption|JWEObject|jwe\.decrypt|compactDecrypt" --glob '*.{java,kt,js,ts,py,go,rb,cs}'
rg -n "RSA-OAEP|A256GCM|A128GCM" --glob '*.{java,kt,js,ts,py,go}'   # presence of safer choices
```

**SAFE**: pin `alg`+`enc` to an allowlist before decrypt; use `RSA-OAEP-256` (not `RSA1_5`) and AEAD `A256GCM` (not CBC); validate `epk` curve/point for ECDH-ES; cap `p2c` (e.g. ≤ 10^6) for PBES2; generate a fresh random IV per GCM encryption — never reuse; reject/limit `zip`; **after decrypting, verify the nested JWS with a pinned algorithm** before trusting claims; return a **single uniform error for every crypto failure** (bad padding/MAC/OAEP indistinguishable) so no decryption oracle exists.

### Header Manipulation

- **kid injection**: path traversal `../../../../keys/prod.key`, SQL/command/template injection in key lookup, or references to world-readable files. Two extra primitives to flag: (a) **predictable-content file as the HMAC key** — pointing `kid` at a file whose bytes the attacker knows lets them sign with that value: `/dev/null` (empty key), `/proc/sys/kernel/randomize_va_space` (`"2"`), or a Docker-default `/etc/hostname`; (b) **command execution** when `kid` reaches a shell-capable API — e.g. Ruby `open("| whoami")` (leading pipe) → RCE; and **SSRF** when `kid`/key lookup fetches a URL (`http://169.254.169.254/…`, `http://127.0.0.1:6379/`)
- **jku/x5u abuse**: host attacker-controlled JWKS/X509 chain; if not pinned or whitelisted, the server fetches and trusts attacker keys. **Allowlist-bypass shapes** when the URL check is substring/`endsWith`/`startsWith` rather than a parsed-host equality: userinfo `https://trusted.com@attacker.com/jwks`, subdomain suffix `https://trusted.com.attacker.com/jwks`, open redirect on the trusted host, backslash `https://trusted.com%5c@attacker.com`, fragment `https://attacker.com#trusted.com` (see `ssrf.md` / `open_redirect.md` for the full parser-confusion set). Even a non-forgeable fetch is **SSRF** (reaches internal hosts/metadata)
- **jwk header injection**: embed attacker JWK directly in the token header; certain libraries prefer the inline JWK over server-configured keys (CVE-2018-0114 class — recurs in later libraries)
- **x5c injection (self-signed cert)**: attacker puts a self-signed X.509 cert chain in `x5c`; if the library extracts the leaf public key but never validates the chain to a trusted CA, the forged token verifies. Signal: `x5c` consumed for verification without trust-store/chain validation
- **SSRF via remote key fetch**: exploit the JWKS/`jku`/`x5u` URL retrieval mechanism to reach internal hosts

### Key and Cache Issues

- JWKS caching TTL and key rollover: accepting obsolete keys, racing key rotation windows, and missing kid pinning that causes any matching kty/alg to be accepted
- Mixed environments / regions: identical signing secret shared across dev/stage/prod **or across geographic regions/instances**; keys reused across tenants or unrelated services. Consequence — tokens are **portable between instances**: a token minted where the attacker *can* register (a different region, or a dev/staging instance) verifies and authorizes on the target instance, because nothing in the token is bound to the issuing deployment. Aggravated when a lower environment is weaker (e.g. dev returns the OTP/verification code in the response or skips email verification), letting the attacker mint a victim-scoped token there and replay it to prod. Signal: one shared `JWT_SECRET`/keyfile across environments **and** no per-deployment `iss`/`aud` (or region/env claim) enforced on verify — bind tokens to the deployment or use distinct per-environment/per-region keys
- Fallbacks: verification logic that succeeds when kid is not found by cycling through all keys or skipping verification entirely (implementation bugs)

### Claims Validation Gaps

- iss/aud/azp not enforced: cross-service token reuse; tokens from any issuer or the wrong audience are accepted
- scope/roles fully trusted from token: the server does not re-derive authorization; privilege inflation via claim manipulation when signature checks are weak
- exp/nbf/iat not enforced or excessively broad clock skew tolerance; long-expired or not-yet-valid tokens are accepted
- typ/cty not enforced: ID tokens accepted where access tokens are required (token confusion)
- **account status not re-checked after token/credential validation**: a token, API key, or personal access token validates by signature/lookup but the handler never verifies the backing account is still `active` (`deactivated`, `blocked`, `disabled`, `state != 'active'`) before authorizing the request — deactivated/blocked accounts keep executing privileged operations. Common when the password/session login path enforces status but the token/API-key path skips it (`User.find_by_token(t)` → `ctx.current_user = user` with no `user.active?` guard; API-key branch missing the `before_action :check_user_active` applied to web sessions). Re-derive and enforce account status server-side on every auth path, not just interactive login.

### Token Binding, Claim Trust, and Replay Controls

JWT verification that validates signature and `exp` but omits binding or replay checks still accepts cross-context tokens and stale replays. OAuth/OIDC **flow** misconfiguration (redirect URI, state, PKCE, code reuse) is covered in `references/oauth_oidc_misconfiguration.md` — this section covers **token-validation** gaps only.

- **Cross-service / cross-app token acceptance**: token passes signature and `exp` but `aud`, `azp`, or `client_id` is not compared to this app's registered client/API identifier — a token minted for another client, microservice, or tenant is accepted
- **Access-token type not pinned (`typ != at+jwt`)**: RFC 9068 requires access tokens to carry header `typ: "at+jwt"` (or `application/at+jwt`); a resource server that accepts an ID token (`typ: JWT`) where an access token is expected enables ID-as-access-token confusion (NGINX OIDC CVE-2024-10318 class). Signal: API token validation that checks signature/`aud` but never asserts `typ`
- **Shared-infrastructure signer not bound (ALBeast-style)**: when many tenants share one regional signing infrastructure (e.g. AWS ALB + Cognito), a token the attacker minted in their *own* pool verifies cryptographically against *your* service. The header carries an issuer/`signer` identifier (ALB ARN) that must be compared to your own — verifying only the signature is insufficient. Signal: federated token validation that trusts the shared key without pinning the `signer`/issuer to this deployment
- **DPoP / proof-of-possession not enforced**: `cnf.jkt`-bound (RFC 9449) access tokens are still accepted as plain Bearer (downgrade — drop the `DPoP` header / change `Authorization: DPoP` → `Bearer`), the proof's `ath` (access-token hash) is not checked (one proof reused with different tokens), or there is no server nonce (replay within the issuer's window). Signal: token acceptance path that ignores the `DPoP` header / `cnf` claim, or DPoP verification missing `ath`/`htm`/`htu`/nonce checks
- **Unverified identity claims (nOAuth-style)**: account lookup, creation, or linking keyed on `email`, `preferred_username`, or `upn` from the token without requiring `email_verified === true` (or equivalent) — attacker-controlled IdP issues a token with victim email and unverified flag
- **JTI replay window**: `jti` absent, predictable (numeric `0001`–`9999`), or not stored/checked in a replay cache — same token redeems multiple times within TTL
- **`nbf` not enforced alongside `exp`**: `exp` validated but `nbf` skipped or `verify_nbf: false` — not-yet-valid tokens accepted when clock skew or staged issuance is abused
- **Refresh-token identity swap**: refresh handler trusts `username`, `user_id`, or `sub` from the request body instead of deriving identity solely from the refresh token's validated subject

```bash
# Cross-app binding gaps
rg -n "verify_aud.*False|audience.*optional|skip.*aud|client_id|azp" .
rg -n "jwt\.decode|jwt\.verify|parseClaimsJws" . | rg -v "audience|requireAudience|aud|azp|client_id"

# Unverified email / username claim trust
rg -n "preferred_username|email_verified|emailVerified|findOrCreate.*email|link.*email" .

# JTI / nbf gaps
rg -n '"jti"|verify_nbf.*False|require.*nbf|jti.*store|replay.*cache' .

# Refresh identity from body
rg -n "refresh.*token|grant_type.*refresh" . -A5 | rg -n "req\.body\.(user|username|user_id|sub)"
```

```python
# VULN: signature + exp only — token for another API client accepted
payload = jwt.decode(token, key, algorithms=["RS256"], options={"verify_aud": False})

# SECURE: bind to this app's client/API identifier
payload = jwt.decode(
    token, key, algorithms=["RS256"],
    audience="myapp-api", issuer=IDP_ISSUER,
    options={"require": ["exp", "nbf", "jti", "aud"]},
)
assert payload.get("azp") == REGISTERED_CLIENT_ID or payload.get("aud") == REGISTERED_CLIENT_ID

# VULN: link account from unverified email claim
user = User.find_or_create(email=claims["email"])

# SECURE
if claims.get("email_verified") is not True:
    raise AuthError("email_not_verified")
user = User.find_or_create(email=claims["email"])

# VULN: refresh trusts body username over token subject
user = User.get(request.json["username"])
if valid_refresh(request.json["refresh_token"]):
    return issue_tokens(user)

# SECURE: identity from validated refresh token only
claims = validate_refresh_token(request.json["refresh_token"])
user = User.get(claims["sub"])
return issue_tokens(user)
```

### Token Confusion and OIDC

- Access vs ID token swap: use an ID token against APIs that verify the signature but not the audience or typ
- OIDC mix-up: redirect_uri and client mix-ups causing tokens minted for Client A to be redeemed at Client B
- PKCE downgrades: missing S256 enforcement; plain or absent code_verifier accepted
- State/nonce weaknesses: predictable or absent values leading to CSRF or logical interception of the login flow
- Device/Backchannel flows: codes and tokens accepted by unintended clients or services

### Refresh and Session

- Refresh token rotation not enforced: old refresh tokens reusable indefinitely with no reuse detection
- Long-lived JWTs with no revocation mechanism: access persists after logout
- Session fixation: new tokens bound to attacker-controlled session identifiers or cookies

### Transport and Storage

- Token in localStorage/sessionStorage: vulnerable to XSS-based exfiltration; cookie vs header trade-offs with SameSite and CSRF
- Insecure CORS: wildcard origins combined with credentialed requests expose tokens and protected responses
- TLS and cookie flags: missing Secure/HttpOnly; absence of mTLS or DPoP/"cnf" binding allows token replay from a different device

### Mitigation Patterns

- **Algorithm allowlist**: pass explicit `algorithms=["HS256"]` or `['RS256']` — never trust the token header's `alg`
- **Strong secret**: ≥256 bits entropy from env/secrets manager; not `"secret"` or `"password123"`
- **Full claim validation**: require and verify `exp`, `iss`, `aud` (and `nbf` when used)
- **Asymmetric isolation**: RS256 verify endpoints must reject HS256 on the same key material
- **JWKS/JKU allowlist**: fetch keys only from pinned URLs; never trust inline `jwk` from the token header

```python
# Secure verification — pinned alg, required claims, issuer/audience binding
payload = jwt.decode(
    token, os.environ["JWT_SECRET"], algorithms=["HS256"],
    options={"require": ["exp", "iss", "aud"]},
    issuer="https://myapp.example.com",
    audience="myapp-api",
)
```

## Federation & Protocol Secure Configuration

Detection targets missing enforcement at authorization servers, SAML consumers, and MFA gates — not JWT signature logic (covered above).

### OAuth 2.0 / OIDC Hardening

- **PKCE for public clients**: require `code_challenge` + S256 at `/authorize`; reject token exchange when `code_verifier` missing or when challenge used `plain`
- **State (CSRF)**: bind one-time, server-stored `state` to the user session; reject callback when absent, reused, or mismatched (OIDC: also validate `nonce` in ID token)
- **Redirect URI exact match**: compare full registered URI strings — no prefix, wildcard, or `startsWith` matching
- **No implicit flow**: reject `response_type=token` / `id_token token`; use authorization code (+ PKCE for public/native clients)
- **Short-lived access tokens**: cap access token TTL (minutes); rotate refresh tokens; detect reuse
- **Scope minimization**: issue and enforce least-privilege `scope`; resource servers re-check scope per endpoint — do not trust broad default scopes

```javascript
// VULN: prefix/wildcard redirect URI acceptance
if (requestedUri.startsWith(registeredBase)) { /* allow */ }

// SECURE: exact string equality against registered list
if (!client.redirectUris.includes(requestedUri)) throw new InvalidRedirectError();
```

```yaml
# VULN: implicit or ROPC enabled
response_types_supported: [token, id_token token]
grant_types_supported: [password, implicit]

# SECURE: code flow only for public clients
response_types_supported: [code]
grant_types_supported: [authorization_code, refresh_token]
code_challenge_methods_supported: [S256]
```

```python
# VULN: PKCE optional for public client
if client.is_public and not code_verifier:
    pass  # still issue tokens

# SECURE: require verifier when challenge was sent; reject plain
if auth_request.code_challenge and not verify_pkce(code_verifier, auth_request):
    raise OAuthError("invalid_grant")
```

**Detection indicators**: `response_type.*token`, `grant_type=password`, redirect validation via `startsWith`/`includes`/regex without exact set membership, `code_challenge_method: plain`, token endpoint accepting requests without prior `code_challenge`, scopes copied from client request without server-side filtering.

### SAML Consumer Hardening

- **Signature validation**: verify XML signature on the assertion, the outer response, or both per profile — signature must cover the element actually trusted; reject unsigned assertions when signing is required
- **Fail-open when no key/cert is configured**: the most common real-world SAML bypass is a `verifySignatures()` that **early-returns (no-ops) when the SP has no certificate set** — `if (!options.cert) return;` / `if not self.idp_cert: return True`. An attacker who can reach *any* code path that clears or omits the provider cert (or who registers a new provider whose cert defaults to falsy) then logs in with a **forged, unsigned** assertion. Make signing **mandatory**: treat a missing/empty trust anchor as a hard error, never as "skip validation." Also flag **framework auto-exposed methods** that mutate auth/security settings without an authz check — RPC-style endpoints that get published by default (e.g. `Meteor.call("addSamlService", name)`, exposed admin/setting mutators, magic-dispatched controller methods) let an unauthenticated caller add a provider or disable signature verification entirely
- **XML signature wrapping**: do not select security nodes via `getElementsByTagName`; use absolute XPath to the signed element; validate against hardened local schema before trust decisions; ignore attacker-supplied `KeyInfo` — pin IdP keys from config/JKS
- **NameID/attribute comment-truncation (canonicalization differential)**: when an XML comment is embedded inside a signed text node — `admin@company.com<!---->.evil.com` — the signature digest uses comment-stripped C14N (`admin@company.com.evil.com`, the attacker's *real* account) but the app's identity extraction reads only the **first text node**, yielding a *different* trusted value (`admin@company.com`, the victim). The discrepancy is the bug (CVE-2017-11428 ruby-saml/OneLogin, CVE-2016-5697). **SAST signal**: identity pulled from a signed node via a first-text-node API — `node.firstChild.nodeValue` / `childNodes[0]`, `el.text` (REXML/Nokogiri returns first child only), `getElementsByTagName(...).item(0).getFirstChild().getNodeValue()` — instead of concatenating the full normalized text (`textContent` / `el.content` / XPath `string(.)`), with no rejection of comment nodes. **SAFE**: extract identity with full-text-content APIs (or strip/reject comment nodes before extraction) so the value matches exactly what the signature canonicalized; upgrade the SAML library to a comment-hardened version.
- **Protocol binding checks**: validate `InResponseTo` against stored AuthnRequest ID; `Audience`/`Recipient` against SP entity ID and ACS URL; `NotBefore`/`NotOnOrAfter` with minimal clock skew; reject expired or not-yet-valid assertions
- **Canonicalization**: use library-default exclusive C14N for digest verification; do not re-serialize DOM before verify; disable external entity resolution in XML parsers

```java
// VULN: first Assertion element trusted without signature scope check
Element assertion = doc.getElementsByTagName("Assertion").item(0);

// SECURE: verify signature covers intended element; validate InResponseTo + conditions
SAMLObject signed = responseValidator.validate(response, pinnedIdpCredential);
assertConditions(signed, expectedAudience, storedRequestId, clockSkewSeconds);
```

```python
# VULN: timestamp check omitted
user = parse_saml_response(xml_body)

# SECURE: full condition validation
assert response.in_response_to == pending_request.id
assert sp_entity_id in assertion.audiences
assert assertion.not_on_or_after > now and assertion.not_before <= now
```

**Detection indicators**: DOM tag-name lookup for `Assertion`/`Signature`, missing `InResponseTo`/`NotOnOrAfter`/`Recipient` validation, `KeyInfo` from document used as trust anchor, no replay/OneTimeUse store, IdP-initiated SSO without RelayState allowlist, **signature-verification routine that returns/short-circuits when the cert/key is empty** (`if (!cert) return`, `if not idp_cert: return True`), and **publicly invokable framework methods that add SAML providers or change signature/security settings** without an authentication/authorization gate.

### Multi-Factor Authentication (MFA)

- **TOTP secret handling**: generate ≥160-bit secrets with CSPRNG; store encrypted or hashed at rest; never log or return secrets after enrollment; transmit setup QR/links only over TLS with step-up auth
- **OTP rate-limiting / replay**: cap verify attempts per user/IP; reject reused OTP within time step window; use standard TOTP window (±1 step max); invalidate code after successful use when using out-of-band codes
- **Recovery codes**: single-use, high-entropy, stored hashed; invalidate all recovery codes on MFA reset; require step-up auth before displaying or regenerating
- **No MFA bypass on alternate flows**: every authenticated path (API, mobile, password reset completion, OAuth callback, magic link) must re-check MFA state — flag `skipMfa`, alternate routes that mint sessions without MFA gate, or "remember device" on sensitive apps

```python
# VULN: MFA checked only on web login route
@app.post("/api/mobile/login")
def mobile_login(credentials):
    return issue_jwt(user)  # no mfa check

# SECURE: centralized MFA gate before session/token issuance
user = authenticate(credentials)
require_mfa_satisfied(user, context=request)
return issue_jwt(user)
```

```javascript
// VULN: TOTP secret in logs or API response
logger.info("Enrolled TOTP", { secret: totpSecret });
res.json({ secret: totpSecret });

// SECURE: hash recovery codes; constant-time OTP compare
const ok = crypto.timingSafeEqual(hash(input), storedHash);
await rateLimiter.consume(`otp:${userId}`);
```

**Detection indicators**: `skipMfa`/`bypassMfa` flags, OTP verify endpoints without rate limits, TOTP secrets in config/logs, recovery codes stored plaintext, session issued in `/callback` or `/reset-password/confirm` without MFA state check.

### Authentication Flow Hardening

- **Generic error messages**: same response for unknown user and bad password; normalize timing — flag distinct strings like "user not found" vs "wrong password"
- **Account lockout / backoff**: progressive throttling after failed attempts — see `references/brute_force.md` for lockout/rate-limit detection; avoid permanent lockout without admin recovery
- **Credential rotation**: force password change after breach indicator, admin reset, or privilege elevation; rotate refresh tokens and server sessions on password/MFA change
- **Secure password reset**: uniform response whether account exists; reset tokens ≥32-byte CSPRNG, single-use, stored hashed, short TTL; HTTPS link to pinned domain; require re-auth after reset — do not auto-login; rate-limit reset requests (see `references/brute_force.md`)
- **Bind email-action tokens to a purpose AND a target identity (token-type confusion)**: a single token store/secret reused for multiple email actions (verify-email, password-reset, magic-link, invite) lets a token minted for the low-privilege flow be replayed against the high-privilege one — e.g. an **email-verification link accepted as a password-reset link**. The bug is selecting the flow by a *client-removable* parameter (`?step=account`, `?action=verify`, path segment) instead of a purpose **bound into and checked from** the token record. SAST signals: one `tokens` table / one HMAC secret shared by reset+verify+invite with no `purpose`/`type` column asserted on consume; reset/verify handlers that branch on a query/path param rather than the stored token's action; a token whose payload encodes only `user_id` (not the action and not the exact target email). Fix: store `(token, purpose, user_id, target_email, expires)` and verify `purpose`+`target` match the *current* request before acting; rotate/expire sibling tokens on use.
- **Never perform credential changes from GET/query params; reject query-overrides-body**: setting a new password (or email/phone) from URL query parameters leaks the secret to history, `Referer`, and access logs and makes the action link-CSRF-able; additionally, frameworks that let a **query-string value override the POST/JSON body of the same key** allow an attacker to pin `newPassword`/`email` via a crafted link regardless of what the victim's form submits. SAST signals: reset/change handlers reading `request.args`/`req.query`/`$_GET` for `password`/`email`/`token` on a state-changing route; merged param bags (`request.values` in Flask, `req.query` merged into `req.body`) feeding identity/credential fields. Fix: accept credential mutations only via POST body, and resolve identity from the authenticated session or the server-side token record — never from request-supplied `userId`/`email`.

```python
# VULN: account enumeration via error text
if not user:
    return "User not found", 404
if not verify_password(user, password):
    return "Invalid password", 401

# SECURE: uniform failure
if not user or not verify_password(user, password):
    record_failed_attempt(identifier)
    return "Invalid username or password", 401
```

```java
// VULN: reset token stored plaintext; reusable
resetTokens.put(token, userId);

// SECURE: hashed, single-use, expiring
store.save(hash(token), userId, expiresAt);
// on use: delete row; rotate sessions; require login
```

**Detection indicators**: distinct login/reset error strings, missing `recordFailedAttempt`/`rateLimit` on auth routes, plaintext reset tokens, auto-login after reset without re-auth, no session/token revocation on password change.

## Advanced Techniques

- **Microservice audience mismatch**: internal services verify signature but ignore aud, accepting tokens destined for other services
- **Gateway header trust**: edge injects X-User-Id; backend trusts it over actual token claims
- **JWS edge cases**: unencoded payload (b64=false) mishandling; nested JWT verification order errors
- **Mobile**: deep-link/redirect bugs leak codes/tokens; insecure WebView bridges; plaintext token storage
- **SSO federation**: stale metadata or obsolete keys cause acceptance of foreign tokens

## Chaining Attacks

- XSS → token theft → replay across services with weak audience enforcement
- SSRF → fetch private JWKS → sign tokens accepted by internal services
- Host header poisoning → OIDC redirect_uri poisoning → authorization code capture
- JWT ↔ IDOR: a forgeable or unbound `sub`/`user_id` claim is an authorization-bypass primitive equivalent to IDOR on every object keyed by that identity — a successful claim swap yields the same cross-user access (and, with a `role`/scope claim, vertical escalation), so triage reachable object endpoints as IDOR once the claim is attacker-controllable (see `idor.md`)

## Analysis Workflow

1. **Inventory issuers/consumers** - Identity providers, API gateways, services, and mobile/web clients
2. **Capture tokens** - Obtain access and ID tokens for multiple roles; examine headers, claims, and signatures
3. **Map verification endpoints** - `/.well-known`, `/jwks.json`
4. **Build matrix** - Token Type × Audience × Service; attempt cross-context use
5. **Mutate components** - Headers (alg, kid, jku/x5u/jwk), claims (iss/aud/azp/sub/exp), and signatures
6. **Verify enforcement** - Determine what is actually validated versus assumed

## Confirming a Finding

1. Demonstrate acceptance of a forged or cross-context token (wrong algorithm, wrong audience/issuer, or attacker-signed JWKS)
2. Show access token vs ID token confusion at an API endpoint
3. Prove refresh token reuse succeeds without rotation detection or revocation
4. Confirm header abuse (kid/jku/x5u/jwk) that places key selection under attacker control
5. Provide evidence from both owner and non-owner contexts using requests that differ only in token content

### Dynamic Verification

Short runtime checks to confirm static findings (capture a valid token first):

| Test | Action | Expected signal if vulnerable |
|------|--------|-------------------------------|
| `alg: none` | Set header `"alg":"none"`, strip signature third segment, send to protected endpoint | `200`/authorized with forged claims |
| RS256→HS256 | On RS256 endpoints without alg pinning: re-sign with HS256 using the server's RSA public key as HMAC secret | Forged token accepted |
| Signature strip | Remove signature segment; send payload with elevated `role`/`sub` | Auth succeeds without valid signature |
| Weak secret | Offline brute-force captured token HMAC (wordlist against HS256) | Secret recovered → arbitrary forgery |

```bash
# alg:none probe (jwt_tool)
jwt_tool <TOKEN> -X a
curl -H "Authorization: Bearer <FORGED_TOKEN>" https://target/api/me

# RS256→HS256 confusion (requires public key + no alg pinning)
jwt_tool <TOKEN> -X s -pk public.pem
curl -H "Authorization: Bearer <CONFUSED_TOKEN>" https://target/api/me
```

**Claim tampering** (after signature bypass or weak key): elevate `role`/`is_admin`, swap `sub` to another user ID, then replay on a protected route.

**kid abuse** — if verification resolves keys from `kid`:
- Path traversal: `"kid":"../../../../dev/null"` with empty HMAC secret (sign HS256 with `""`)
- File reference: `"kid":"/proc/sys/kernel/hostname"` or `"kid":"../../../../keys/prod.key"`
- SQLi in lookup: `"kid":"' OR '1'='1"` when `kid` is interpolated into a query

**jku / inline jwk** — host attacker JWKS at `https://YOUR-COLLABORATOR.oast.fun/jwks.json`, set `"jku"` to that URL, or embed an attacker RSA key in the `"jwk"` header field; re-sign and send if the server fetches/trusts header-supplied keys.

**Weak HS256 secret** — offline crack captured token: `hashcat -m 16500 jwt.txt wordlist.txt`; re-sign with recovered secret and confirm server acceptance.

```python
# Minimal alg:none (base64url, no padding) — third segment empty or omitted
import base64, json
h = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b"=").decode()
p = base64.urlsafe_b64encode(json.dumps({"sub":"1","role":"admin"}).encode()).rstrip(b"=").decode()
forged = f"{h}.{p}."
# curl -H "Authorization: Bearer $forged" https://target/api/admin/users
```

Success = protected resource returns data for attacker-controlled claims. Rejection with `401`/`403` and no claim trust indicates effective mitigation.

## Common False Alarms

- Token rejected due to strict audience and issuer enforcement
- Key pinning with a JWKS whitelist and TLS validation in place
- Short-lived tokens with rotation and revocation triggered on logout
- ID tokens not accepted by APIs that require access tokens
- Missing-auth observations based solely on absent framework security configuration are insufficient without a concrete sensitive endpoint or action
- Hardcoded credentials in sample, tutorial, demo, or example applications must not be treated as production authentication flaws unless they are clearly deployed defaults

## Business Risk

- Account takeover and persistence of durable attacker sessions
- Privilege escalation through claim manipulation or cross-service token acceptance
- Cross-tenant or cross-application data access
- Token minting controlled by attacker-held keys or endpoints

## Analyst Notes

1. Test RS256→HS256 and "none" first only when algorithm pinning is unclear; otherwise focus on header-based key control (kid/jku/x5u/jwk)
2. Replay tokens across all services — many backends check signature only, skipping audience and typ
3. Validate every acceptance path: gateway, service, background worker, WebSocket, and gRPC
4. Treat the refresh token surface independently: verify rotation, reuse detection, and audience scoping
5. Exercise OIDC flows with PKCE, state, and nonce variations across mixed clients

## Core Principle

Verification must bind the token to the correct issuer, audience, key, and client context on every acceptance path. Any missing binding enables forgery or confusion.

## Source Detection Rules

### Python (PyJWT / python-jose)
- **VULN**: `jwt.decode(token, key, algorithms=["none"])` — accepts none algorithm
- **VULN**: `jwt.decode(token, options={"verify_signature": False})` — skips signature verification
- **VULN**: `jwt.decode(token, key, algorithms=jwt.get_unverified_header(token)['alg'])` — algorithm confusion
- **VULN**: `jwt.decode(token, key)` on **PyJWT < 2.0** with the `algorithms` arg omitted — older versions did not require it and would accept `alg:none`/attacker-chosen algs; always pass an explicit `algorithms=[...]` allowlist.
- **SAFE**: `jwt.decode(token, SECRET_KEY, algorithms=["HS256"])` — fixed algorithm
- **Pattern**: Any `verify=False` or `options={"verify_*": False}` = HIGH RISK

### JavaScript (jsonwebtoken)
- **VULN**: `jwt.verify(token, secret, { algorithms: ['none'] })`
- **VULN**: `jwt.decode(token)` used for authorization decisions (decodes without verification)
- **VULN**: Algorithm taken from token header and passed directly to verify
- **SAFE**: `jwt.verify(token, SECRET, { algorithms: ['HS256'] })`

### PHP
- **VULN**: `JWT::decode($token, null, ['none'])` — Firebase JWT with null key and none algorithm
- **VULN**: Base64-decoding claims and using them without signature verification
- **Pattern**: Any `alg: none` acceptance = CRITICAL

### Java (jjwt)
- **VULN**: deprecated `Jwts.parser().setSigningKey(key).parseClaimsJws(token)` — trusts header `alg`
- **VULN**: parse succeeds but `exp`/`iss`/`aud` never enforced via `require*` builders
- **SAFE**: `Jwts.parserBuilder().requireIssuer("myapp").requireAudience("myapp-api").setSigningKey(key).build().parseClaimsJws(token)`

### Go (golang-jwt / dgrijalva/jwt-go)
- **VULN**: key func returns secret without checking `token.Method` — accepts `alg: none` and unexpected algs
- **VULN**: `var jwtKey = []byte("secret")` — weak hardcoded secret
- **SAFE**: reject non-HMAC before returning key:

```go
token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
    }
    return []byte(os.Getenv("JWT_SECRET")), nil
})
```

### kid / JWK Header Injection

```python
# VULN: kid in SQL without parameterization
def get_signing_key(kid):
    return db.execute(f"SELECT key FROM jwt_keys WHERE id = '{kid}'").fetchone()[0]

# SECURE: parameterized lookup + unknown kid rejection
def get_signing_key(kid):
    row = db.execute("SELECT key FROM jwt_keys WHERE id = %s", (kid,)).fetchone()
    if not row:
        raise ValueError("Unknown key id")
    return row[0]
```

```javascript
// VULN: inline jwk from token header used as verify key
const { publicKey } = getPublicKeyFromHeader(decoded.header);
jwt.verify(token, publicKey);

// SECURE: only pre-configured trusted key
jwt.verify(token, loadKeyFromConfig(), { algorithms: ['RS256'] });
```

## FALSE POSITIVE Rules

- Do NOT emit `jwt` or `authentication_jwt` when the project already has an `authentication` tag for the same auth weakness — use the more precise tag. Emit `jwt` only when the vulnerability is specifically in JWT implementation (algorithm confusion, weak signing key, missing validation), not general authentication bypass.
- Do NOT emit for JWT libraries used correctly with proper algorithm pinning, key management, and claim validation — even if the signing key is hardcoded in a demo/test context.
- Cookie flag issues alone are not `authentication_jwt` unless a JWT validation or token-trust flaw is present.
- Emit `jwt` only when an attacker-supplied token from a header, cookie, or parameter is actually verified or accepted by a mapped vulnerable route. Helper classes, token-generation demos, and storage-only examples are insufficient alone.

## Source → Sink Patterns

### Java — Missing JWT Signature Check

- **Source**: `JwtParser.setSigningKey(...)` / `setSigningKeyResolver(...)` — a signing key is configured on the parser.
- **Sink**: Insecure parse on the same parser qualifier — `parse(token)`, `parseClaimsJwt(token)`, `parsePlaintextJwt(token)`, or `parse(token, handler)` where the handler overrides `onClaimsJwt`/`onPlaintextJwt` without extending `JwtHandlerAdapter`.
- **Sanitizer**: Use `parseClaimsJws(token)` / `parsePlaintextJws(token)`, or override `onClaimsJws` / `onPlaintextJws` on `JwtHandlerAdapter`.

**VULN**: `parser.setSigningKey(key).parse(untrustedToken)` — jjwt accepts empty-signature tokens via `parse`.
**SAFE**: `parser.setSigningKey(key).parseClaimsJws(untrustedToken)`.

### JavaScript — Decode Without Verification

- **Source**: Remote user input — e.g. `req.headers.authorization`.
- **Sink (unverified)**: `jwt.decode()`, `jwt-decode()`, `jwt-simple.decode(token, key, true)` (noVerify), `jose.decodeJwt()`.
- **Sanitizer**: Subsequent verified decode on the same token — `jwt.verify()`, `jose.jwtVerify()`, `jwt-simple.decode(token, key)` without noVerify.

**VULN**: `jwtJsonwebtoken.decode(UserToken)` used for auth decisions.
**SAFE**: `jwtJsonwebtoken.verify(UserToken, getSecret())`.

### Python — Missing Secret or Public Key Verification

- **Sink**: Any `JwtDecoding` where `verifiesSignature()` is false — PyJWT `decode(..., options={"verify_signature": False})`, python-jose without key, Authlib decode without verification.

**VULN**: `jwt.decode(token, options={"verify_signature": False})`.
**SAFE**: `jwt.decode(token, SECRET_KEY, algorithms=["HS256"])` with `verify=True` (default).

### Auth0 / Ruby Patterns

- **Auth0NoVerifier (Java)**: `JWT.decode(token)` or `JWT.require(...).build().verify(token)` missing — reading claims from unverified Auth0 tokens.
- **EmptyJWTSecret (Ruby)**: JWT encoded with empty secret or `alg: "none"`.

## Related References

- `references/oauth_oidc_misconfiguration.md` — OAuth/OIDC **flow** misconfiguration (redirect URI, state, PKCE, authorization-code reuse, cross-client token acceptance at callback, unverified email linking); use alongside this file for full OAuth/OIDC coverage
- `references/session_fixation.md` — CWE-384 session ID rotation on authentication state change
- `references/brute_force.md` — login/OTP/reset rate limiting and lockout

## Session Fixation Detection

See dedicated `references/session_fixation.md` for CWE-384 detection rules, Java Servlet patterns, and Spring Security configuration checks.
