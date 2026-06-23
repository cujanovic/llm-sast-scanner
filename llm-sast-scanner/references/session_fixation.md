---
name: session_fixation
description: Session fixation detection — session ID not regenerated on authentication state change
---

# Session Fixation

Session fixation occurs when a web application does not issue a new session identifier after a successful authentication event. An attacker who can set or predict the pre-authentication session ID retains access to the authenticated session, resulting in full account takeover (CWE-384).

## Overview

The attack works in three steps: (1) the attacker obtains or forces a known session ID onto the victim's browser (via URL parameter, cookie injection, or a subdomain cookie), (2) the victim authenticates using that session, and (3) because the server never rotates the session ID, the attacker's copy of the ID is now bound to the victim's authenticated context.

## Where to Look

- **Login handlers** — servlet `doPost` methods, Spring `@PostMapping("/login")`, custom authentication filters
- **Authentication success callbacks** — Spring Security `AuthenticationSuccessHandler`, custom post-login redirects
- **Session management configuration** — `SecurityFilterChain` or `WebSecurityConfigurerAdapter` beans, `<session-management>` XML
- **Password reset and identity change flows** — any endpoint that elevates privilege or switches the bound user identity
- **OAuth/OIDC callback handlers** — code-exchange endpoints that establish a server-side session after token validation
- **Multi-step authentication** — flows where the session survives across challenge steps without regeneration

## Vulnerability Patterns

### Java / Spring

- Login controller calls `request.getSession()` to read user data but never calls `session.invalidate()` or `request.changeSessionId()` before or after storing authenticated attributes
- Spring Security config omits `sessionManagement()` entirely **and** uses a custom authentication flow that bypasses the default filter chain
- Explicit `sessionFixation().none()` in the security config — disables all session ID rotation
- Manual session attribute copying (e.g., `Utils.setSessionUserName(session, user)`) without first invalidating the old session

### PHP

- `$_SESSION['user'] = $username;` after `session_start()` without calling `session_regenerate_id(true)` on successful login
- Custom login scripts that set session variables directly without regeneration

### Node.js / Express

- `req.session.user = authenticatedUser;` without calling `req.session.regenerate()` first
- Passport.js default `serializeUser` without session regeneration middleware

### Python / Django

- Django's built-in auth views call `login()` which rotates the session key by default — manual login flows that skip `django.contrib.auth.login()` and directly set `request.session['user']` are vulnerable
- Flask: `session['user'] = username` without rotating the session — Flask has no built-in `session.regenerate()`; on privilege change, clear and repopulate the session (e.g., `session.clear()` then set the authenticated identity), or use Flask-Login (`login_user(...)`) with `SESSION_PROTECTION` configured

## Java / Spring Detection Rules

### TRUE POSITIVE

- **No `session.invalidate()` on login**: a login handler sets session attributes (e.g., user identity, roles) after authentication succeeds but does not call `session.invalidate()` followed by `request.getSession(true)`, nor `request.changeSessionId()`, anywhere in the login path.
- **`sessionFixation().none()`**: Spring Security configuration explicitly disables session fixation protection.
- **Custom auth filter without regeneration**: a filter extending `UsernamePasswordAuthenticationFilter` or `OncePerRequestFilter` that authenticates the user and populates `SecurityContextHolder` without triggering session ID rotation.
- **Identity switch without session reset**: code that changes the session-bound user identity (e.g., via a helper like `setSessionUserName()`) without invalidating and re-creating the session — the old session ID remains valid under the new identity.

### FALSE POSITIVE

- **Spring Security default config**: since Spring Security 3.1, the default session fixation strategy is `migrateSession` (or `changeSessionId` since Servlet 3.1). If `sessionManagement()` is present without `.sessionFixation().none()`, session fixation is mitigated by default. Do not emit a finding.
- **Explicit `sessionFixation().newSession()` or `.migrateSession()` or `.changeSessionId()`**: these are safe configurations.
- **`session.invalidate()` followed by `request.getSession(true)`**: the old session is destroyed and a fresh session is created — safe.
- **Stateless JWT-only APIs**: when `SessionCreationPolicy.STATELESS` is set and no server-side session is created, session fixation is not applicable.
- **`request.changeSessionId()`** called in the login flow: this is the Servlet 3.1+ session fixation mitigation.

## TRUE POSITIVE Rules

Confirm session fixation when ALL of the following hold:

1. The application uses server-side sessions (cookies carry a session ID such as `JSESSIONID`)
2. A successful authentication event binds a user identity to the session
3. The session ID observable before authentication is identical to the session ID after authentication — no call to `invalidate()`, `changeSessionId()`, `regenerate()`, or framework-level session fixation protection
4. No compensating control (e.g., Spring Security default `migrateSession`) is in effect

## FALSE POSITIVE Rules

Do NOT emit a session fixation finding when:

- Spring Security's `SessionManagementConfigurer` is active with any strategy other than `none` — the default is `migrateSession`
- The application is purely stateless (JWT bearer tokens, no `JSESSIONID` cookie, `SessionCreationPolicy.STATELESS`)
- The login handler explicitly calls `session.invalidate()` and then `request.getSession(true)` before setting authenticated attributes
- The code calls `request.changeSessionId()` in the authentication success path
- A custom `SessionAuthenticationStrategy` that rotates session IDs is registered

## Remediation

### Java Servlet

```java
// SAFE: invalidate old session and create new one on login
HttpSession oldSession = request.getSession(false);
if (oldSession != null) {
    oldSession.invalidate();
}
HttpSession newSession = request.getSession(true);
newSession.setAttribute("user", authenticatedUser);
```

### Java Servlet 3.1+

```java
// SAFE: rotate session ID in place, preserving attributes
request.changeSessionId();
```

### Spring Security

```java
// SAFE: explicit session fixation protection
http.sessionManagement(session -> session
    .sessionFixation().newSession()
);
```

### PHP

```php
// SAFE: regenerate session ID on login, delete old session
session_regenerate_id(true);
$_SESSION['user'] = $username;
```

### Node.js / Express

```javascript
// SAFE: regenerate session before setting user
req.session.regenerate(function(err) {
    req.session.user = authenticatedUser;
});
```

## Business Risk

- Full account takeover when an attacker fixes the session ID before the victim logs in
- Privilege escalation when a low-privilege session is carried into a high-privilege context
- Compliance violations (OWASP A07:2021 — Identification and Authentication Failures)

## Core Principle

Every authentication state change — login, privilege elevation, identity switch — must issue a fresh session identifier. The pre-authentication session ID must never survive into the authenticated context.

## Session ID Generation and Entropy

Session IDs must be opaque, server-issued, and unpredictable. Weak generation enables guessing and fixation follow-on attacks.

**Requirements:**
- CSPRNG source (`SecureRandom`, `crypto.randomBytes`, `secrets.token_hex`, `random_bytes`)
- Minimum 64 bits entropy (128+ preferred); no sequential, timestamp, or user-derived components
- Generic cookie names instead of framework defaults (`JSESSIONID`, `PHPSESSID`) where configurable
- Reject client-supplied IDs not previously issued by the server

**Detection indicators:**
- Custom ID built from `Math.random()`, `rand()`, `time()`, user ID, or counter
- Session ID length below 16 hex chars (64 bits)
- `session.use_only_cookies = 0` (PHP) or URL rewriting enabled without compensating rotation
- No validation that incoming session ID exists in server store before binding identity

```javascript
// VULN: predictable session ID
const sessionId = Date.now().toString(36) + Math.random().toString(36);
req.sessionID = sessionId;
```

```java
// SAFE: framework default or explicit CSPRNG
String id = new BigInteger(130, new SecureRandom()).toString(32);
```

## Session IDs in URLs

Passing session IDs in query strings or path segments enables fixation via link sharing, Referer leakage, and log exposure.

**Detection indicators:**
- `response.encodeURL(...)` / `response.encodeRedirectURL(...)` (Servlet URL rewriting)
- `;jsessionid=` in generated links, redirects, or form actions
- PHP `session.use_trans_sid = 1` or `session.use_only_cookies = 0`
- Express/connect session with `cookie: { secure: false }` combined with `req.query.sessionId` binding
- Accepting `sessionid`, `sid`, or `JSESSIONID` from `request.getParameter(...)` / `req.query`

```java
// VULN: session ID appended to outbound URL
String url = response.encodeRedirectURL("/dashboard");
```

```php
// VULN: trans_sid embeds ID in links
ini_set('session.use_trans_sid', '1');
```

## Session Lifecycle: Idle and Absolute Timeouts

Timeouts must be enforced server-side. Client-side timers alone do not invalidate server sessions.

**Idle timeout** — expire after inactivity (typical: 2–5 min high-value, 15–30 min low-risk).
**Absolute timeout** — expire regardless of activity (typical: 4–8 hours).
**Renewal** — optionally rotate session ID on periodic renewal to limit fixation/hijack window.

**Detection indicators:**
- No `session.setMaxInactiveInterval(...)`, `SESSION_COOKIE_AGE`, or framework timeout config
- Only client-side `setTimeout` logout without server invalidation
- `maxInactiveInterval` set to `-1` (never expire) or unreasonably large with no absolute cap
- Missing server-side `createdAt` / `lastAccessedAt` tracking for absolute expiry
- Session store entries never purged (no TTL on Redis/DB session keys)

```java
// VULN: session never expires
session.setMaxInactiveInterval(-1);
```

```python
# VULN: PERMANENT_SESSION_LIFETIME unset or timedelta(days=365)
PERMANENT_SESSION_LIFETIME = timedelta(days=365)
```

```java
// SAFE: idle + absolute enforced
session.setMaxInactiveInterval(1800);
session.setAttribute("absoluteExpiry", Instant.now().plus(8, ChronoUnit.HOURS));
```

## Logout and Server-Side Invalidation

Logout must destroy server-side session state, not only clear the client cookie.

**Detection indicators:**
- Logout handler calls `response.addCookie(emptyCookie)` or `res.clearCookie(...)` without `session.invalidate()` / `Session.Abandon()` / `session_destroy()`
- Logout only redirects; no session store deletion
- Cookie cleared with `Max-Age=0` but session record remains in Redis/DB/memory
- Missing logout endpoint; only client-side `localStorage.removeItem(...)`

```javascript
// VULN: client cookie cleared, server session alive
res.clearCookie('connect.sid');
res.redirect('/');
```

```java
// SAFE: server-side teardown then cookie clear
HttpSession session = request.getSession(false);
if (session != null) {
    session.invalidate();
}
```

```php
// SAFE
session_destroy();
setcookie(session_name(), '', time() - 3600, '/');
```

## Privilege Change and Reauthentication

Regenerate session ID on password change, role elevation, account recovery completion, and identity switch — not only initial login.

**Detection indicators:**
- Role/permission update writes to existing session without `changeSessionId()` / `regenerate()` / `invalidate()`
- Admin impersonation or "switch user" retains pre-switch session ID
- Password-change handler updates credential store but not session
- OAuth account-linking binds new identity without session rotation

### Session survival after credential or MFA change

Fixation mitigation must invalidate **all** active sessions on credential rotation — not only rotate the current browser session ID.

- **Password reset / change without global invalidation**: password-reset completion or change-password handler updates the hash but does not call `session.invalidate()` on the current session **and** revoke other server-side sessions/tokens for that user — attacker-held pre-change session IDs remain authenticated
- **Parallel sessions survive 2FA enrollment**: enabling MFA/TOTP updates a flag or secret but leaves existing sessions (other browsers, stolen cookies) valid without re-authentication or forced logout
- **Remember-me / persistent token not rotated**: long-lived remember-me, device, or refresh cookie survives password reset, privilege elevation, or MFA enrollment — no token version bump, DB revocation list, or cookie re-issue on security state change

```bash
# Password change without session teardown
rg -n "change[_-]?password|reset[_-]?password|setPassword|updatePassword" . | rg -v "invalidate|revoke.*session|deleteAllSessions|session_version"
# MFA enrollment without session revocation
rg -n "enableMfa|enroll.*totp|two[_-]?factor.*enable|mfa.*enabled" . | rg -v "invalidate|revoke|logout.*all|session.*destroy"
# Remember-me rotation
rg -n "remember[_-]?me|persistent.*token|device[_-]?token|stay[_-]?logged" . | rg -v "rotate|invalidate|revoke|version"
```

```java
// VULN: password changed; other sessions still valid
user.setPassword(newHash);
userRepository.save(user);

// SECURE: bump credential epoch and destroy all sessions
user.setPassword(newHash);
user.incrementSessionVersion();
sessionRegistry.expireAllSessionsForUser(user.getId());
request.getSession(false).invalidate();
rememberMeServices.removeAllTokens(user.getUsername());
```

```javascript
// VULN: MFA enabled; stolen session cookie still works
user.mfaEnabled = true;
await user.save();

// SECURE
user.mfaEnabled = true;
await sessionStore.deleteByUserId(user.id);
await rememberMeTokens.revokeAll(user.id);
req.session.regenerate(() => { /* require MFA on next sensitive action */ });
```

```java
// VULN: privilege elevation without rotation
session.setAttribute("role", "admin");
```

```javascript
// SAFE
req.session.regenerate(() => {
  req.session.role = 'admin';
});
```

## Concurrent Session Controls

Limit simultaneous authenticated sessions per user when policy requires (financial, admin consoles).

**Detection indicators:**
- Login creates new session without invalidating or counting prior sessions for same user ID
- No server-side session registry keyed by user (only anonymous session store)
- Missing `maxSessions(n)` (Spring Security) or equivalent per-user cap
- Stolen session remains valid after victim logs in elsewhere with no notification or revocation

```java
// SAFE: Spring Security concurrent session control
http.sessionManagement(s -> s
    .maximumSessions(1)
    .maxSessionsPreventsLogin(true));
```

## Cache and Transport Hardening

Responses carrying session identifiers must not be cached.

**Detection indicators:**
- Authenticated pages missing `Cache-Control: no-store` (or `private, no-cache`)
- Session cookie set before HTTPS redirect completes
- Mixed HTTP/HTTPS within same session journey

Commonly affected languages: JavaScript, C#.

## Static Analysis Patterns

### What to Look For (JavaScript)

Config-only pattern (no taint flow). Flag Express route setups where:

1. Path matches `%login%` and a handler writes to `req.session` (login establishes session state).
2. No call to `req.session.regenerate` anywhere in that route setup.

Passport.js is explicitly excluded — modern Passport includes built-in session-fixation protection.

**VULN**: Login handler sets `req.session.user = authenticatedUser` without `req.session.regenerate(...)`.
**SAFE**: `req.session.regenerate(function(err) { req.session.user = authenticatedUser; })`.

### What to Look For (C#)

Config-only pattern. Flag ASP.NET login/logout handlers that mutate session state without calling `HttpSessionState.Abandon()`.

**VULN**: After authentication, session ID reused — no `Session.Abandon()` before binding authenticated user.
**SAFE**: `Session.Abandon()` called on login/logout so a new session is started.
