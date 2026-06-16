---
name: authentication-jwt
description: JWT and OIDC security testing covering token forgery, algorithm confusion, and claim manipulation
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
rg -n "import jwt|from jose|jsonwebtoken|io\.jsonwebtoken|golang-jwt|dgrijalva/jwt-go|firebase/php-jwt" .

# Signature bypass
rg -n "verify_signature.*False|verify_signature:\s*false|jwt\.decode\(|options=\{.*verify" .

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

### Header Manipulation

- **kid injection**: path traversal `../../../../keys/prod.key`, SQL/command/template injection in key lookup, or references to world-readable files
- **jku/x5u abuse**: host attacker-controlled JWKS/X509 chain; if not pinned or whitelisted, the server fetches and trusts attacker keys
- **jwk header injection**: embed attacker JWK directly in the token header; certain libraries prefer the inline JWK over server-configured keys
- **SSRF via remote key fetch**: exploit the JWKS URL retrieval mechanism to reach internal hosts

### Key and Cache Issues

- JWKS caching TTL and key rollover: accepting obsolete keys, racing key rotation windows, and missing kid pinning that causes any matching kty/alg to be accepted
- Mixed environments: identical secrets shared across dev/stage/prod; keys reused across tenants or unrelated services
- Fallbacks: verification logic that succeeds when kid is not found by cycling through all keys or skipping verification entirely (implementation bugs)

### Claims Validation Gaps

- iss/aud/azp not enforced: cross-service token reuse; tokens from any issuer or the wrong audience are accepted
- scope/roles fully trusted from token: the server does not re-derive authorization; privilege inflation via claim manipulation when signature checks are weak
- exp/nbf/iat not enforced or excessively broad clock skew tolerance; long-expired or not-yet-valid tokens are accepted
- typ/cty not enforced: ID tokens accepted where access tokens are required (token confusion)

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
- **XML signature wrapping**: do not select security nodes via `getElementsByTagName`; use absolute XPath to the signed element; validate against hardened local schema before trust decisions; ignore attacker-supplied `KeyInfo` — pin IdP keys from config/JKS
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

**Detection indicators**: DOM tag-name lookup for `Assertion`/`Signature`, missing `InResponseTo`/`NotOnOrAfter`/`Recipient` validation, `KeyInfo` from document used as trust anchor, no replay/OneTimeUse store, IdP-initiated SSO without RelayState allowlist.

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

## Session Fixation Detection

See dedicated `references/session_fixation.md` for CWE-384 detection rules, Java Servlet patterns, and Spring Security configuration checks.
