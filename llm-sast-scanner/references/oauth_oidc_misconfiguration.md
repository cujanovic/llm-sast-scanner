---
name: oauth-oidc-misconfiguration
description: OAuth 2.0 / OpenID Connect flow misconfiguration — weak redirect_uri validation, missing state/PKCE, authorization-code reuse, cross-client token acceptance, unverified email linking, implicit/ROPC grants, dynamic registration SSRF, and client-secret exposure (CWE-287 / CWE-346 / CWE-601)
---

# OAuth 2.0 / OIDC Misconfiguration (CWE-287 / CWE-346 / CWE-601)

OAuth 2.0 and OpenID Connect delegate authentication and authorization to an identity provider (IdP) through redirect-based flows, authorization codes, and bearer tokens. **Flow misconfiguration** — not cryptographic JWT flaws — lets attackers steal codes/tokens, bind victims to attacker accounts, accept tokens minted for another client, or take over accounts via unverified email claims. Static analysis should trace authorize/callback/token handlers and client registration paths for missing binding checks between session, client, redirect URI, state, PKCE, and token audience.

## What It Is / Is Not

- **Is**: server-side OAuth/OIDC **protocol enforcement** gaps — redirect URI accepted by prefix/regex instead of exact match; `state` absent or not verified; PKCE missing or `plain` accepted; authorization codes reusable or not time-bound; access/ID tokens accepted without `aud`/`azp`/`client_id` binding; account create/link from IdP `email` without `email_verified`; implicit/`response_type=token` delivering tokens in URL; ROPC/password grant enabled; client secret in frontend bundle; dynamic registration fetching attacker `logo_uri`/`client_uri`; callback pages without `Referrer-Policy: no-referrer`.
- **Is not**: JWT signature bypass, algorithm confusion, `kid`/`jku` header abuse, or missing `exp`/`iss` claim crypto — see `authentication_jwt.md`. Generic open redirect without OAuth context — see `open_redirect.md`. Browser CSRF on non-OAuth forms — see `csrf.md`. Outbound fetch SSRF in non-OAuth features — see `ssrf.md`.
- **Highest signal** at `/authorize`, `/callback`, `/token`, `/oauth/token`, account-linking handlers, and OIDC dynamic client registration endpoints.

## Source -> Sink Pattern

- **Source**: HTTP query/body on authorize and callback — `redirect_uri`, `response_type`, `response_mode`, `state`, `code`, `client_id`, `code_challenge`, `code_challenge_method`; token endpoint — `grant_type`, `code`, `code_verifier`, `client_secret`; IdP profile/ID-token claims — `email`, `email_verified`, `sub`, `aud`, `azp`; dynamic registration JSON — `logo_uri`, `client_uri`, `redirect_uris`.
- **Sink (misconfiguration)**: redirect URI validator that uses `startsWith`/`includes`/regex/prefix instead of set equality; callback handler that exchanges `code` without verifying `state` against session; token endpoint that omits PKCE verification or accepts `plain`; code store that does not delete/mark-used on first redemption; resource/login handler that trusts token claims without `aud`/`azp`/`client_id` match; `findOrCreateUser({ email })` ignoring `email_verified`; signup route allowing unverified local email later merged on social login; metadata advertising `response_type=token` or `grant_type=password`; server-side HTTP fetch of registration `logo_uri`/`client_uri`; SPA callback rendering token from URL hash without referrer stripping.
- **Aggravating chain**: loose `redirect_uri` + missing `state` → authorization code interception; unverified email + pre-registration → account takeover; cross-client `aud` gap → token from attacker's registered app accepted by victim app.

## Recon Indicators (Grep)

```bash
# Redirect URI validation (weak match vs exact list)
rg -ni 'redirect_uri|redirectUri|redirect_uri_valid|validateRedirect' --glob '*.{js,ts,jsx,tsx,py,java,go,rb,php,cs}'
rg -ni 'startsWith|endsWith|includes\(|indexOf|match\(|RegExp|\.test\(' --glob '*.{js,ts,py,java}' -C2 | rg -i 'redirect'

# Flow parameters
rg -ni 'response_type|response_mode|grant_type|code_challenge|code_verifier|code_challenge_method' .
rg -ni "response_type.*token|response_type.*id_token\s+token|'token'|'id_token token'" .
rg -ni 'grant_type.*password|password.*grant|ResourceOwnerPassword|oauth2.*password' .

# State / CSRF binding on OAuth callback
rg -ni '\bstate\b' --glob '*.{js,ts,py,java,go,rb,php}' | rg -i 'oauth|callback|authorize|openid'
rg -ni 'session\[.state|req\.session\.state|state.*===|verifyState|validateState' .

# PKCE
rg -ni 'code_challenge|code_verifier|pkce|S256|plain' --glob '*.{js,ts,py,java,go,rb,php}'
rg -ni "code_challenge_method.*plain|'plain'" .

# Client secret exposure
rg -ni 'client_secret|clientSecret|OAUTH_CLIENT_SECRET' --glob '*.{js,ts,jsx,tsx,vue,svelte,html}'
rg -ni 'client_secret' --glob '*.{env.example,config.*,docker-compose*}'

# Dynamic client registration URIs (SSRF surface)
rg -ni 'logo_uri|client_uri|registration_client_uri' .

# Identity / account linking
rg -ni 'email_verified|emailVerified' .
rg -ni 'findOrCreate|find_or_create|linkAccount|link_account|mergeAccount' --glob '*.{js,ts,py,java,rb,php}'
rg -ni 'profile\.email|claims\.email|userinfo\.email|id_token.*email' .

# ID token acceptance (flow binding only — crypto in authentication_jwt.md)
rg -ni 'id_token|idToken|verify_id_token|decode_id_token' .
rg -ni 'verify_signature.*False|jwt\.decode\(|decode.*id_token' .

# OAuth libraries / middleware
rg -ni 'passport|authlib|spring-security-oauth|oauth2-server|oidc-provider|@okta/|openid-client|goth\.|oauth2\.Config' .

# Callback page referrer leakage
rg -ni 'Referrer-Policy|referrerPolicy|referrer-policy' --glob '*.{js,ts,html,tsx,jsx}'
rg -ni 'location\.hash|window\.hash|fragment.*access_token|query\.code' --glob '*.{js,ts,jsx,tsx,vue,svelte}'
```

Then trace each hit: does redirect validation compare **full strings** against a registered set? Is `state` generated server-side, stored in session, and rejected on mismatch? Is the authorization code deleted atomically on first `/token` call?

## Vulnerable Conditions

1. **Redirect URI**: `startsWith(registeredBase)`, substring/`includes`, regex without anchored full-URI match, or trailing-slash/path wildcard allowing `https://app.example.com.evil.com` or `https://app.example.com/attacker/callback`.
2. **State**: not generated, hardcoded, client-supplied only, not stored server-side, not compared on callback, or reusable across sessions.
3. **PKCE**: public/native clients allowed without `code_challenge`; token exchange skips `code_verifier`; `code_challenge_method=plain` accepted (verifier visible on authorize request).
4. **Authorization code**: no single-use flag; no TTL; concurrent double-redemption succeeds; no row lock/transaction on redeem.
5. **Cross-client tokens**: login/callback accepts access or ID token without verifying `aud`/`azp`/`client_id` equals the app's registered client (token from attacker's OAuth app works).
6. **Unverified email (nOAuth-style)**: account lookup/creation or linking keyed on `email` claim when `email_verified` is false, missing, or not checked.
7. **Pre-account takeover**: local registration with victim email (unverified) creates a stub account; victim's later IdP login links to attacker-controlled password account.
8. **Implicit / URL token delivery**: `response_type=token` or `response_mode=query`/`fragment` exposing access token or code in browser history/referrer; OAuth callback SPA without `Referrer-Policy: no-referrer` or equivalent.
9. **Dynamic registration SSRF**: authorization server fetches `logo_uri` or `client_uri` from registrant-controlled URL server-side without blocklist (internal metadata/metadata poisoning).
10. **Client secret / ROPC**: `client_secret` in frontend env/ bundle; password grant enabled for public or general users.
11. **ID token flow trust**: ID token used for session establishment without signature verification or without `iss`/`exp`/`nbf`/`aud` checks — brief; full JWT rules in `authentication_jwt.md`.

## Vulnerable vs Safe Code Examples

```javascript
// VULN: prefix redirect_uri — attacker registers https://app.example.com.evil.com
function validateRedirect(requested, registeredList) {
  const base = registeredList[0];
  return requested.startsWith(base);
}

// SAFE: exact match against full registered URI set (scheme, host, port, path)
function validateRedirect(requested, registeredList) {
  return registeredList.includes(requested);
}
```

```javascript
// VULN: callback without state verification — CSRF / forced login
app.get('/oauth/callback', async (req, res) => {
  const { code } = req.query;
  const tokens = await exchangeCode(code);
  req.session.user = tokens;
  res.redirect('/dashboard');
});

// SAFE: bind state to session; reject mismatch; one-time use
app.get('/oauth/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!state || state !== req.session.oauthState) {
    return res.status(400).send('Invalid state');
  }
  delete req.session.oauthState;
  const tokens = await exchangeCode(code, req.session.pkceVerifier);
  req.session.user = tokens;
  res.redirect('/dashboard');
});
```

```javascript
// VULN: PKCE optional; plain method accepted
if (body.code_challenge_method === 'plain') {
  expected = body.code_challenge;
}

// SAFE: require S256 for public clients; reject plain
if (client.isPublic && !body.code_verifier) throw invalidGrant();
if (body.code_challenge_method !== 'S256') throw invalidRequest();
verifyS256(body.code_verifier, storedChallenge);
```

```javascript
// VULN: authorization code reusable
async function redeemCode(code) {
  const row = await db.query('SELECT * FROM auth_codes WHERE code = ?', [code]);
  if (!row) throw new Error('invalid');
  return issueTokens(row);
}

// SAFE: atomic single-use + TTL
async function redeemCode(code) {
  const row = await db.transaction(async (tx) => {
    const r = await tx.query(
      'DELETE FROM auth_codes WHERE code = ? AND expires_at > NOW() RETURNING *',
      [code]
    );
    if (!r.length) throw new Error('invalid');
    return r[0];
  });
  return issueTokens(row);
}
```

```javascript
// VULN: accept any signed ID token — cross-app token
const payload = jwt.decode(idToken);
req.session.userId = payload.sub;

// SAFE: verify crypto + bind aud/azp to this client (see authentication_jwt.md for verify API)
const payload = await verifyIdToken(idToken, { issuer, audience: CLIENT_ID });
if (payload.azp && payload.azp !== CLIENT_ID) throw new Error('wrong client');
req.session.userId = payload.sub;
```

```javascript
// VULN: link by email without email_verified
async function onOAuthProfile(profile) {
  let user = await User.findOne({ email: profile.email });
  if (!user) user = await User.create({ email: profile.email });
  return user;
}

// SAFE: require verified email from IdP
async function onOAuthProfile(profile) {
  if (profile.email_verified !== true) {
    throw new Error('Email not verified by IdP');
  }
  let user = await User.findOne({ email: profile.email, emailVerified: true });
  if (!user) user = await User.create({ email: profile.email, emailVerified: true });
  return user;
}
```

```python
# VULN: ROPC / password grant enabled
OAUTH_GRANT_TYPES = ["authorization_code", "refresh_token", "password"]

# SAFE: code flow only for interactive clients
OAUTH_GRANT_TYPES = ["authorization_code", "refresh_token"]
OAUTH_RESPONSE_TYPES = ["code"]
OAUTH_PKCE_METHODS = ["S256"]
```

```python
# VULN: dynamic registration fetches attacker URL
def register_client(body):
    logo = requests.get(body["logo_uri"], timeout=5)  # SSRF
    save_client(body)

# SAFE: store URI as metadata only; do not server-fetch registrant URLs
def register_client(body):
    if not is_https_public_url(body.get("logo_uri")):
        raise ValidationError("logo_uri")
    save_client(body)  # no outbound fetch
```

## Safe Patterns

- **Redirect URI**: register exact URIs per client; compare with constant-time equality (or normalized canonical form with fixed rules); reject open redirects on callback landing pages.
- **State + nonce**: CSPRNG `state` stored server-side; single use; OIDC `nonce` echoed in ID token per spec.
- **PKCE**: require for public clients; only `S256`; bind challenge to authorization request record; verify at token endpoint.
- **Authorization code**: short TTL (minutes); cryptographically random; delete on successful exchange inside a transaction/lock.
- **Token binding**: enforce `aud`/`azp`/`client_id` match app registration on every token acceptance path; reject tokens from other OAuth clients even if signature valid.
- **Account linking**: require `email_verified === true`; block local signup with IdP-managed domains when SSO is offered; on link, require step-up auth and rotate sessions.
- **Flows**: authorization code only; no implicit; no ROPC for user authentication; confidential secrets only on server.
- **Callback UX**: `Referrer-Policy: no-referrer` on pages handling `?code=` or `#access_token=`; prefer POST callback or backend-only code exchange.
- **Dynamic registration**: disable or restrict; never fetch `logo_uri`/`client_uri`; validate HTTPS and same policy as SSRF allowlists — see `ssrf.md`.
- **ID tokens**: full signature and claim validation per `authentication_jwt.md`; never `jwt.decode` for session creation.

## Severity / Triage

| Condition | Typical severity |
|-----------|------------------|
| Prefix/wildcard `redirect_uri` on confidential or public client | **High** — code/token theft |
| Missing/weak `state` on login/linking callback | **High** — CSRF account binding |
| Missing PKCE on public client + predictable redirect | **High** |
| Authorization code reuse / no TTL | **High** |
| Cross-client token acceptance (`aud`/`azp` not checked) | **High** |
| Account create/link without `email_verified` | **High** — account takeover |
| Pre-registration stub + social link merge | **High** |
| Implicit flow / token in URL fragment | **Medium–High** |
| Client secret in frontend | **High** |
| ROPC/password grant enabled | **High** |
| Dynamic registration SSRF fetch | **High** (often internal) |
| Missing `Referrer-Policy` on callback only | **Low–Medium** (chain-dependent) |
| ID token decode-only at callback | **Critical** if exploitable — delegate severity to `authentication_jwt.md` |

Downgrade when: exact redirect list enforced, state/PKCE/nonce verified, codes single-use, tokens audience-bound, email_verified enforced, code-only flow, secrets server-only.

## Common False Alarms

- `redirect_uri` compared with `===` or set membership against a static registered list.
- `state` generated server-side, stored in session, cleared after use, mismatch returns error.
- PKCE enforced with `S256` only; `plain` rejected.
- Authorization code deleted or marked used in same transaction as token issuance.
- `aud`/`client_id` checked after proper JWT verification.
- `email_verified` explicitly required before link/create.
- `client_secret` referenced only in server-side config (not bundled).
- ID token verified via library with pinned algorithms and required claims — see `authentication_jwt.md`.
- OAuth library defaults (Spring Security OAuth2 Resource Server, Authlib with strict config) already enforce exact redirect and PKCE — confirm config, do not flag library presence alone.

## Cross-References

- `authentication_jwt.md` — JWT/OIDC **cryptographic** verification, algorithm confusion, `kid`/`jku`, claim validation (`exp`, `iss`, `aud`, `nbf`); not duplicated here.
- `csrf.md` — OAuth `state` as CSRF token; constant-state anti-patterns.
- `open_redirect.md` — attacker-controlled redirect destinations; often chained with loose `redirect_uri`.
- `ssrf.md` — server-side fetch of `logo_uri`/`client_uri` during dynamic client registration.
- `session_fixation.md` — session rotation after OAuth callback / account linking.
- `host_header_poisoning.md` — poisoned host affecting redirect URI construction.
- `insecure_cookie.md` — session cookie flags on OAuth-established sessions.
- `default_credentials.md` — hardcoded `client_secret` patterns in repo scans.

## Core Principle

Every OAuth/OIDC step must **cryptographically and logically bind** the authorization request, callback, and token to the same client, redirect URI, user session, and one-time artifacts (`state`, PKCE verifier, authorization code). Accept no token or identity claim — including email — until the registered client context and IdP verification flags are explicitly validated; delegate JWT integrity rules to `authentication_jwt.md`.
