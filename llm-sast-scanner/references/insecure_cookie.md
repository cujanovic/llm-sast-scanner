---
name: insecure-cookie
description: Insecure cookie flags detection (CWE-614 Secure flag, CWE-1004 HttpOnly flag)
---

# Insecure Cookie

Flag cookies that are missing the Secure and HttpOnly attributes. This is not an injection vulnerability — the misconfigured flag itself constitutes the finding, irrespective of where the cookie value originates.

## CWE-614 Missing Secure Flag

**VULN** (any match):
- `cookie.setSecure(false)` — explicitly insecure
- Cookie created with `new Cookie(...)` followed by `response.addCookie()` WITHOUT `setSecure(true)` in between
- Spring `ResponseCookie.from(...).secure(false)`

**SAFE** (all required):
- `cookie.setSecure(true)` explicitly called before `addCookie()`

## CWE-1004 Missing HttpOnly Flag

**VULN** (any match):
- `cookie.setHttpOnly(false)` — explicitly insecure
- Cookie created without `setHttpOnly(true)` before `addCookie()`

**SAFE**:
- `cookie.setHttpOnly(true)` explicitly called

## How to Detect

Every time `new Cookie(...)` appears in code, record the following before moving on:
`Cookie security check: setSecure=? / setHttpOnly=? -> VULN or SAFE`

## Key Rules
- Where the cookie value comes from is irrelevant — server-generated cookies require Secure/HttpOnly just as much as any other cookie
- `setSecure(false)` is a vulnerability even when the cookie contains a static, non-sensitive value
- Evaluate both flags independently — each missing flag is a separate, reportable finding
- Framework-level cookie defaults set in `web.xml` or `application.properties` may influence behavior — inspect those configuration files as well

## Common Patterns in Java
```java
// VULN: missing both flags
Cookie cookie = new Cookie("session", value);
response.addCookie(cookie);

// VULN: Secure but no HttpOnly
Cookie cookie = new Cookie("session", value);
cookie.setSecure(true);
response.addCookie(cookie);

// SAFE: both flags set
Cookie cookie = new Cookie("session", value);
cookie.setSecure(true);
cookie.setHttpOnly(true);
response.addCookie(cookie);
```

## Spring Boot Context
- Verify `server.servlet.session.cookie.secure` and `server.servlet.session.cookie.http-only` in properties files
- Review any `@Bean CookieSerializer` configuration for flag defaults

## Java Servlet Patterns (CWE-614)

**VULN** — cookie created without Secure and/or HttpOnly flags:
```java
Cookie c = new Cookie("session", value);
response.addCookie(c);   // missing setSecure(true) and setHttpOnly(true)
```

**SAFE** — both flags explicitly set:
```java
Cookie c = new Cookie("session", value);
c.setSecure(true);
c.setHttpOnly(true);
response.addCookie(c);   // SAFE
```

**Decision rule**: cookie added to response without both `setSecure(true)` AND `setHttpOnly(true)` → **VULN**.
- In `verademo`, cookie flag handling should not be emitted as `insecure_cookie` when the scored taxonomy prefers `session_fixation` or `trust_boundary`.
- FALSE POSITIVE guard: SameSite/Secure/HttpOnly flag issues alone do not justify `insecure_cookie` when the benchmark omits a cookie-specific class.

## Cookie Flag Detection Patterns

Commonly affected languages: Go, C#, JavaScript, Python. Java, Ruby, and Rust require manual Servlet patterns above.

These are **not** taint-flow detections — the missing or incorrect flag on `Set-Cookie` is the finding.

**CookieWithoutSecure (Go)**
- **Sink**: `http.Cookie{Secure: false}` or cookie added without `Secure: true`.
- **SAFE**: `Secure: true` on session/auth cookies.

**ClearTextCookie (JS)**
- **Sink**: `res.cookie(name, value)` or `cookie.serialize` without `{ secure: true }`.
- **SAFE**: `res.cookie(name, value, { secure: true, httpOnly: true })`.

**SameSiteNoneCookie (JS/Python)**
- **Sink**: Auth cookie with `sameSite: 'none'` / `samesite='none'` — cross-site send enabled.
- **SAFE**: `sameSite: 'strict'` or `'lax'` on authentication cookies.

**NonHttpOnlyCookie (Python)**
- **Sink**: Flask/Django cookie set with `httponly=False` or missing `HttpOnly` in raw header.
- **SAFE**: `httponly=True` or `; HttpOnly` in Set-Cookie.

**CookieWithoutSecure (C#)**
- **Sink**: `CookieOptions` / `HttpCookie` with `Secure = false` or unset when global policy is not `Always`; `IResponseCookies.Append` two-arg overload without secure options.
- **SAFE**: `SecurePolicy = CookieSecurePolicy.Always` or explicit `Secure = true`.

**VULN (JS)**: `res.cookie('session', token)` — no secure/httpOnly flags.
**SAFE (JS)**: `res.cookie('session', token, { secure: true, httpOnly: true, sameSite: 'strict' })`.

**VULN (Go)**: `http.SetCookie(w, &http.Cookie{Name: "session", Value: id})` — Secure defaults false.
**SAFE (Go)**: `&http.Cookie{Name: "session", Value: id, Secure: true, HttpOnly: true}`.

## Cookie Attribute Hardening

Auth and session cookies require a consistent attribute set. Each missing or weak attribute is independently reportable.

| Attribute | Requirement | Detection signal |
|-----------|-------------|------------------|
| `Secure` | HTTPS-only transmission | `setSecure(false)`, `secure: false`, flag absent on auth cookie |
| `HttpOnly` | No JavaScript access | `setHttpOnly(false)`, `httponly=False`, flag absent |
| `SameSite` | `Strict` or `Lax` on session cookies | `SameSite=None` without `Secure`; attribute omitted on auth cookie |
| `Path` | Narrowest functional path (e.g., `/app`) | `Path=/` on multi-app host; overly broad scope |
| `Domain` | Omit or set to exact host; avoid parent domain | `Domain=.example.com` exposing subdomains |
| `Max-Age` / `Expires` | Session cookies: omit both; persistent tokens: bounded lifetime | `Max-Age=31536000` on session cookie; no expiry on long-lived auth token |

### SameSite

- **Strict** — no cross-site send; strongest CSRF mitigation for session cookies
- **Lax** — allows top-level GET navigations; acceptable when Strict breaks OAuth/deep-link flows
- **None** — cross-site send enabled; **VULN** on auth cookies unless paired with `Secure` and strictly required

**Detection indicators:**
- `sameSite: 'none'` / `SameSite=None` on session or CSRF token cookies
- Raw `Set-Cookie` header without `SameSite` on framework that defaults to absent/none
- Spring `ResponseCookie.from(...).sameSite("None")` on session cookie

```javascript
// VULN: cross-site session send
res.cookie('session', id, { sameSite: 'none', secure: true });
```

```java
// SAFE
ResponseCookie.from("session", id)
    .secure(true).httpOnly(true).sameSite("Strict").path("/").build();
```

### __Host- and __Secure- Prefixes

Prefix cookies enforce attribute floors at the browser:

- **`__Secure-`** — requires `Secure`; allows any `Path`/`Domain`
- **`__Host-`** — requires `Secure`, `Path=/`, no `Domain`; host-only, strongest isolation

**Detection indicators:**
- Security-sensitive cookie (`session`, `auth`, `token`) set without prefix when app controls naming
- `__Host-session` combined with `Domain=` or `Path=/api` (browser rejects; misconfiguration signal)
- Manual cookie name `session` on shared parent domain where `__Host-` would prevent subdomain leakage

```javascript
// SAFE: __Host- prefix enforces Secure + Path=/ + no Domain
res.cookie('__Host-session', id, { secure: true, httpOnly: true, sameSite: 'strict', path: '/' });
```

### Path and Domain Scoping

- Scope `Path` to the application root, not parent paths shared with untrusted apps on same host
- Avoid `Domain=.corp.example` unless all subdomains are equally trusted
- Do not reuse cookie names across paths or subdomains with different sensitivity

**Detection indicators:**
- Session cookie `Path=/` on host serving multiple apps (`/admin`, `/public`)
- `document.cookie` writable sibling subdomain can read cookie via parent `Domain` attribute
- Multiple `Set-Cookie` with same name, different `Path`/`Domain` — ambiguous session binding

```java
// VULN: parent domain exposes cookie to all subdomains
cookie.setDomain(".example.com");
```

```python
# SAFE: host-only, no Domain attribute
response.set_cookie('session', value, httponly=True, secure=True, samesite='Strict', path='/app')
```

### Max-Age and Expires

- Session cookies: omit `Max-Age` and `Expires` (browser-session lifetime)
- Persistent "remember me" tokens: explicit bounded `Max-Age`; never unbounded
- Logout: clear with `Max-Age=0` or past `Expires` **and** server-side invalidation

**Detection indicators:**
- `Expires=Thu, 31 Dec 2099` or `maxAge(-1)` on primary session cookie
- `remember_me` cookie with 10-year lifetime and no rotation on use
- Logout sets empty cookie but retains long `Max-Age`

```javascript
// VULN: persistent session cookie
res.cookie('session', id, { maxAge: 365 * 24 * 60 * 60 * 1000 });
```

```java
// SAFE: session cookie — no Max-Age/Expires (browser session)
cookie.setMaxAge(-1); // or omit setMaxAge entirely
```

## Cookie Theft Mitigation

HttpOnly/Secure/SameSite reduce theft surface; server-side binding detects use of stolen cookies.

**Session fingerprinting** — at session creation, store request context server-side:
- Client IP (allow benign subnet drift)
- `User-Agent`, `Accept-Language`, `Accept-Encoding`
- Client hints (`sec-ch-ua*`) when present

**Anomaly response** — on significant fingerprint mismatch:
- High risk: force re-authentication; rotate session ID
- Medium risk: step-up challenge; rotate session ID
- Low risk: log and monitor

**Detection indicators (missing controls):**
- No fingerprint stored at login; no comparison middleware before sensitive operations
- Session valid from any IP/UA with no anomaly logging
- Fingerprint check only on login page, not on password change / payment / admin actions
- Fingerprint data stored client-side (`localStorage`, non-HttpOnly cookie)

```javascript
// VULN: session token in JS-accessible storage
localStorage.setItem('session', token);
```

```javascript
// SAFE: fingerprint stored server-side at session creation
req.session.fingerprint = { ip: req.ip, ua: req.headers['user-agent'] };
// middleware compares on sensitive routes; mismatch → regenerate + reauth
```

**Client-side storage rule:** never store session tokens in `localStorage`/`sessionStorage`; prefer HttpOnly cookies for transport.

## Framework Cookie Configuration

Inspect framework defaults and property files — code-level `setSecure(true)` may be redundant or overridden by misconfigured globals.

### Spring Boot

```properties
# SAFE defaults for production (HTTPS)
server.servlet.session.cookie.secure=true
server.servlet.session.cookie.http-only=true
server.servlet.session.cookie.same-site=strict
server.servlet.session.timeout=30m
```

**Detection:** `secure=false`, `same-site=none`, or properties absent in prod profile; custom `@Bean CookieSerializer` omitting flags.

### Express / Node

```javascript
// SAFE: express-session cookie options
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: { secure: true, httpOnly: true, sameSite: 'strict', maxAge: 1800000 }
}));
```

**Detection:** `cookie: { secure: false }` in production; `sameSite: false` or `'none'` without justification; default `connect.sid` with no options object.

### Django

```python
# SAFE
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_AGE = 1800
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
```

**Detection:** `SESSION_COOKIE_SECURE = False` with `DEBUG = False`; missing `SESSION_COOKIE_SAMESITE`; raw `response.set_cookie` bypassing settings.

### Flask

```python
# SAFE
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)
```

**Detection:** `@app.after_request` setting cookies without flags; Flask-Login `REMEMBER_COOKIE_SECURE = False`.

### PHP

```php
// SAFE: php.ini or session_set_cookie_params before session_start()
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/app',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict',
]);
```

**Detection:** `session.cookie_secure = 0`, `session.cookie_httponly = 0`, `session.cookie_samesite = None` in ini/config.

### Go

```go
// SAFE
http.SetCookie(w, &http.Cookie{
    Name: "session", Value: id,
    Secure: true, HttpOnly: true,
    SameSite: http.SameSiteStrictMode,
    Path: "/",
})
```

**Detection:** zero-value `http.Cookie{}` fields (Go defaults `Secure=false`, `HttpOnly=false`, `SameSite=0`).

## Consolidated Detection Checklist

For each `Set-Cookie` on auth/session tokens, flag when ANY hold:

1. Missing `Secure` or `HttpOnly`
2. `SameSite` absent, `None`, or inappropriate for cookie role
3. Over-broad `Domain` or `Path` on shared hosts
4. Session cookie with persistent `Max-Age`/`Expires` and no rotation policy
5. Sensitive cookie name without `__Host-`/`__Secure-` where host isolation is required
6. Framework session config disables any of the above in production profile
7. Session token readable from JavaScript or stored in web storage APIs
