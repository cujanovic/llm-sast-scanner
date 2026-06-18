---
name: brute_force
description: Detect missing rate limiting and account lockout on authentication endpoints (login, OTP, password reset) that allow brute-force attacks.
---

# Brute Force / Missing Rate Limiting

When authentication endpoints impose no restrictions on the number of attempts, an attacker can run automated tools to guess passwords, OTP codes, or reset tokens at high speed. The absence of rate limiting, account lockout, or CAPTCHA converts an authentication endpoint into a wide-open enumeration target.

## Scope

- Login endpoints (username/password, PIN)
- OTP / 2FA verification endpoints
- Password reset token validation endpoints
- Account enumeration via response differences
- Security-question / knowledge-based recovery endpoints (legacy)

**Attack taxonomy** (same missing-control surface; differ by attacker input):
- **Brute force** — many passwords against one account.
- **Credential stuffing** — breached username/password pairs against many accounts.
- **Password spraying** — one weak password against many accounts (evades per-account lockout).

## Vulnerable Conditions

An authentication endpoint qualifies as vulnerable when it exhibits **all** of:
1. No rate limit (no `@limiter.limit(...)`, no IP-based throttle).
2. No account lockout mechanism that triggers after N consecutive failures.
3. No CAPTCHA or equivalent bot-detection control.

## Safe Patterns

- `@limiter.limit("5 per minute")` or an equivalent decorator applied directly to the route.
- A login failure counter stored in session or database that locks the account after a configurable threshold.
- CAPTCHA integration (`recaptcha`, `hcaptcha`) wired into the authentication flow.
- Note: `time.sleep()` introduces a delay but is not a genuine defense — flag it but do not classify the endpoint as safe.

## Defense Depth

Layer controls; absence of any single layer is a SAST signal when the handler accepts credentials, OTP, or reset tokens.

### Rate limiting / exponential backoff

- **Per-IP**, **per-account**, and **global** counters (distributed stuffing/spraying).
- **Exponential backoff** on consecutive failures — stronger than fixed `sleep()`:
  ```python
  delay = min(2 ** user.failed_attempts, 300)  # cap at 5 min
  time.sleep(delay)
  ```
- **VULN**: fixed delay only, no counter reset, or backoff applied before credential check (timing oracle).

### Account lockout (DoS trade-off)

- Lock after N failures (`failed_attempts`, `locked_until`, `is_locked`).
- **DoS risk**: attacker locks victim accounts — prefer IP throttling + soft lockout (`locked_until` TTL) + admin/unlock email over permanent lock.
- **VULN**: lockout with no unlock path and no out-of-band notification.

### CAPTCHA / proof-of-work

- Trigger after failed attempts, high velocity, or bot signals — not only on registration.
- **Proof-of-work** (client puzzle/token) raises automation cost when CAPTCHA is impractical:
  ```js
  if (failedAttempts >= 3 && !verifyPowToken(req.body.powNonce)) {
    return res.status(429).json({ error: 'Challenge required' });
  }
  ```
- **VULN**: CAPTCHA validated only client-side or on first page load, not on each auth attempt.

### MFA

- Blocks stuffing even with valid passwords — require MFA for admin/sensitive actions and on risk signals (new device, geo anomaly, recent failures).
- **VULN**: `skipMfa`, `bypassMfa`, or session issued at login without MFA step when policy requires it.
- OTP/TOTP verify specifics: see `references/authentication_jwt.md` (attempt caps, replay window, recovery codes).

### Breached-password checks

- Reject or force rotation when password appears in breach corpora (k-anonymity range lookup or local bloom filter).
  ```python
  prefix = hashlib.sha1(password.encode()).hexdigest()[:5].upper()
  if prefix in fetch_breach_suffixes(prefix):
      raise ValidationError('password_breached')
  ```
- **VULN**: registration/password-change handlers with no breach check alongside plaintext comparison.

### Device / IP reputation and anomaly detection

- Track device fingerprint, ASN, hosting-provider IP, impossible-travel velocity.
- **VULN**: auth handler with no `riskScore` / reputation gate and unlimited attempts from datacenter IPs.
  ```java
  // VULN: login succeeds/fails with no IP reputation or velocity check
  authenticationManager.authenticate(token);
  ```

### No username enumeration

- Uniform response body, status, and timing for valid vs invalid username on login, reset, and OTP request.
- **VULN**: distinct errors (`user_not_found` vs `wrong_password`) or reset endpoint returning 404 for unknown email.
- Reset/password-recovery rate limits must apply per IP **and** per submitted identifier — see `references/authentication_jwt.md`.

---

## Python Source Detection Rules

### Flask
- **VULN**: Login route with no Flask-Limiter decorator and no lockout logic:
  ```python
  @app.route('/login', methods=['POST'])
  def login():
      user = User.query.filter_by(username=request.form['username']).first()
      if user and user.check_password(request.form['password']):
          login_user(user)
  ```
- **VULN**: OTP check with no attempt counter:
  ```python
  @app.route('/verify-otp', methods=['POST'])
  def verify_otp():
      if request.form['otp'] == session['otp']:
          session['verified'] = True
  ```
- **SAFE**: `@limiter.limit("5 per minute")` from `flask_limiter`
- **SAFE**: Failed attempt counter: `user.failed_attempts += 1; if user.failed_attempts >= 5: user.locked = True`

### Django
- **VULN**: `authenticate(username=..., password=...)` in a view with no `django-axes` or `django-ratelimit`
- **SAFE**: `@ratelimit(key='ip', rate='5/m', block=True)` from `django_ratelimit`
- **SAFE**: `django-axes` installed and configured in `INSTALLED_APPS`

### Password reset
- **VULN**: Token validated with no expiry check AND no one-time-use enforcement:
  ```python
  user = User.query.filter_by(reset_token=token).first()
  if user:
      user.set_password(new_password)
  ```
- **SAFE**: `if user.reset_token_expires < datetime.utcnow(): abort(400)`

---

## JavaScript Source Detection Rules

### Express
- **VULN**: Login route with no rate-limiting middleware:
  ```js
  app.post('/login', async (req, res) => {
      const user = await User.findOne({username: req.body.username});
      if (user && await bcrypt.compare(req.body.password, user.password)) {
          req.session.userId = user._id;
      }
  });
  ```
- **SAFE**: `express-rate-limit` applied: `app.use('/login', loginLimiter)` where `loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 10 })`
- **SAFE**: `express-brute` or `rate-limiter-flexible` applied to auth routes

### OTP / 2FA
- **VULN**: `/verify-otp` route with no attempt counter in session or DB
- **SAFE**: `if (otpAttempts >= 5) return res.status(429).json({error: 'Too many attempts'})`

---

## PHP Source Detection Rules

### Login check
- **VULN**: Direct password comparison with no lockout:
  ```php
  if ($_POST['password'] == $row['password']) {
      $_SESSION['logged_in'] = true;
  }
  ```
- **VULN**: `password_verify($_POST['password'], $hash)` with no failed attempt tracking
- **SAFE**: Check `$_SESSION['login_attempts']` and enforce lockout threshold

### Rate limiting
- **VULN**: No call to rate-limit library (no `RateLimit`, no APCu/Redis counter check)
- **SAFE**: `if ($redis->incr('login_attempts:' . $ip) > 5) { http_response_code(429); exit; }`

### Password reset
- **VULN**: `SELECT * FROM users WHERE reset_token = '$token'` with no expiry column check
- **SAFE**: `WHERE reset_token = ? AND token_expires > NOW()` with token invalidated after use

### Brute Force Vulnerable Code Patterns (SAST Detection)

The vulnerability exists when an authentication, OTP, password-reset, or similar endpoint has NO rate limiting, lockout, or CAPTCHA protection.

```python
# VULNERABLE: login endpoint with no rate limiting
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        return jsonify({'token': generate_token(user)})
    return jsonify({'error': 'Invalid credentials'}), 401
# No: attempt counter, lockout, sleep/delay, CAPTCHA, rate limit decorator
# Attacker can submit thousands of requests/second

# VULNERABLE: OTP/verification code with no attempt limit
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    code = request.json.get('code')
    if code == session.get('otp'):
        return jsonify({'success': True})
    return jsonify({'error': 'Invalid code'}), 400
# 4-digit OTP = 10,000 possibilities, no lockout = always brute-forceable
```

```java
// VULNERABLE: no account lockout in Spring Security login
// Note: WebSecurityConfigurerAdapter is deprecated since Spring Security 5.7 / Spring Boot 2.7.
// Modern applications use @Bean SecurityFilterChain instead. Check both patterns.
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.formLogin()
        .loginProcessingUrl("/login")
        // No: lockout policy, no CAPTCHA
        // Note: .maximumSessions(1) limits concurrent sessions but does NOT prevent brute force;
        // it restricts how many sessions a user can have simultaneously, not login attempt rate.
        .permitAll();
}

// VULNERABLE: password reset without attempt tracking
@PostMapping("/reset-password")
public ResponseEntity<?> resetPassword(@RequestBody ResetRequest req) {
    User user = userRepo.findByEmail(req.getEmail());
    // No rate limiting on how many reset attempts per email/IP
    emailService.sendResetLink(user.getEmail(), generateToken());
    return ResponseEntity.ok().build();
}
```

```js
// VULNERABLE: Express login route without rate limiter
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
        res.json({ token: generateJWT(user) });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});
// No express-rate-limit, no lockout, no CAPTCHA

// SAFE: with rate limiting
const rateLimit = require('express-rate-limit');
const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 5 });
app.post('/login', loginLimiter, async (req, res) => { ... });
```

```php
// VULNERABLE: login with no rate limiting
if ($_POST['password'] === $user['password']) {
    $_SESSION['user_id'] = $user['id'];
}
// No attempt counter in session/DB, no lockout

// VULNERABLE: admin panel with no lockout
if (isset($_POST['admin_password']) && $_POST['admin_password'] === ADMIN_PASSWORD) {
    $_SESSION['is_admin'] = true;
}
```

### Brute Force Detection Signals

**VULN indicators** (any auth endpoint missing ALL of these):
1. Per-IP or per-account request rate limiting (e.g., `flask-limiter`, `express-rate-limit`, Spring `RateLimiter`)
2. Account lockout after N failed attempts (counter in DB/Redis)
3. CAPTCHA on login/registration
4. Progressive delay / exponential backoff on failures

**Special attention**:
- 4-6 digit numeric OTP/PIN with no attempt limit → always brute-forceable
- Password reset token with short/numeric format AND no attempt limit
- Admin panel (`/admin`, `/wp-admin`, `/manager`) with no lockout

### Brute Force TRUE POSITIVE Rules

- Login/auth endpoint with no visible rate limit, lockout, or CAPTCHA implementation → **CONFIRM** (`brute_force`)
- OTP/verification endpoint with no attempt counter → **CONFIRM** (`brute_force`)
- Password reset with no rate limiting on email submission → **CONFIRM** (`brute_force`)
- GraphQL mutation for login with no per-resolver rate limit → **CONFIRM** (`brute_force` + `graphql`)

### Brute Force FALSE POSITIVE Rules

- `flask-limiter`, `express-rate-limit`, Django `ratelimit`, Spring `Bucket4j` decorators present on the endpoint → **SAFE** (rate limited)
- Lockout logic: DB field `failed_attempts` checked and account disabled after threshold → **SAFE**
- CAPTCHA validated server-side on each attempt → mitigates brute force
- Do NOT emit `brute_force` merely because an authentication endpoint exists without visible rate limiting. The absence of rate limiting code in the scanned repository does NOT confirm brute force vulnerability — rate limiting may be implemented at the infrastructure level (WAF, reverse proxy, API gateway, load balancer) outside the application code.
- Do NOT emit `brute_force` when the project is a vulnerability demonstration or benchmark — focus on whether brute force is an explicit vulnerability category demonstrated by the project, not an incidental missing defense.
- Only emit when there is CONFIRMED: (a) a login/auth endpoint accepting credentials, AND (b) explicit evidence the endpoint processes unlimited attempts (e.g., a loop, no counter, no lockout after N attempts in the application code).
- Do NOT infer CWE-307 from generic missing-rate-limiting findings alone unless the handler is clearly an authentication endpoint and no lockout exists in code — that query class covers DoS on expensive handlers, not login-specific lockout.

## Security Questions (Legacy Recovery)

**Why weak**: answers are guessable (public records, social media), shared across sites, rarely rotated, and often stored with weaker hashing than passwords.

**Prefer alternatives**: MFA/TOTP, one-time recovery codes, verified email magic link — see `references/authentication_jwt.md` for recovery-token and re-auth requirements.

**If present in code** — same brute-force surface as login; flag when missing rate limit, lockout, or CAPTCHA on verify:
```python
# VULN: security question check with no attempt tracking
if normalize(request.form['answer']) == stored_answer_hash_compare(user, 'pet'):
    reset_session['recovery_passed'] = True
```

**Legacy hardening signals** (missing → LIKELY):
- Curated question list (not free-form user questions)
- Answers hashed (Argon2id/bcrypt + per-answer salt), normalized before compare
- Same question on failure (no rotation leaking other answers)
- Email verified before questions shown; re-auth before answer change

## SAST Grep Indicators

Find auth handlers first, then confirm absence of limiter/lockout symbols in same file or middleware chain.

**Auth route discovery**:
```bash
rg -n "(login|sign[_-]?in|authenticate|verify[_-]?otp|reset[_-]?password|forgot[_-]?password|security[_-]?question)" --glob "*.{py,js,ts,java,php,rb,go}"
```

**Missing rate limit / lockout** (handler file has route match above but none of below):
```bash
rg -n "limiter\.limit|rateLimit|ratelimit|RateLimiter|Bucket4j|django[_-]?ratelimit|django[_-]?axes|failed_attempts|lockout|locked_until|too many attempts|429" .
```

**Missing CAPTCHA / bot gate after failures**:
```bash
rg -n "recaptcha|hcaptcha|turnstile|verifyCaptcha|powNonce|proof[_-]?of[_-]?work" .
```

**Missing breach check on password set/change**:
```bash
rg -n "pwned|breach|compromised_password|password.*breach" .
```

**Username enumeration on auth/reset**:
```bash
rg -n "user_not_found|email_not_found|no such user|account does not exist" .
```

**Heuristic**: login/OTP/reset handler + zero grep hits for limiter/lockout/backoff in repo scope → **LIKELY** (`brute_force`); confirm handler processes unlimited attempts in application code (see FALSE POSITIVE rules for infra/WAF caveat).

## Dynamic Test / PoC

Establish baseline: send N+5 identical auth attempts from one IP — expect `429`/lockout/CAPTCHA after N. If all return `401`/`200` without throttle, retry with bypass variants below.

**Client-IP header rotation** (when limit is IP-based behind a proxy):

```bash
for i in $(seq 1 50); do
  IP="$((RANDOM%254+1)).$((RANDOM%254+1)).$((RANDOM%254+1)).$((RANDOM%254+1))"
  curl -s -o /dev/null -w "%{http_code} " -X POST https://app.example/api/login \
    -H "X-Forwarded-For: $IP" -H "X-Real-IP: $IP" -H "X-Client-IP: $IP" \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@example.com","password":"guess"}'
done
```

**URL / path normalization** — same body, alternate paths (new cache/routing keys):

```bash
curl -X POST https://app.example/API/LOGIN -d '{"email":"victim@example.com","password":"x"}'
curl -X POST https://app.example/api/login/ -d '...'
curl -X POST "https://app.example/api/login?_=1730000000" -d '...'
curl -X POST https://app.example//api//login -d '...'
```

**Header-based identity** — if the app trusts forwarded identity headers:

```bash
curl -X POST https://app.example/api/login \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Original-URL: /api/login" \
  -d '{"email":"victim@example.com","password":"x"}'
```

**Method / case variation** — `GET` vs `POST`, or mixed-case path segments, when middleware keys differ from the handler.

**HTTP/2 multiplexing** — many login attempts on one warmed connection (e.g. `curl --http2-prior-knowledge` in a loop) to evade per-connection counters.

**Confirm**: count attempts that reach credential verification beyond the advertised limit; OTP endpoints with 4–6 digit codes and no lockout after baseline N are especially high signal.

## Related References

- `references/authentication_jwt.md` — MFA/OTP rate limits, recovery tokens, uniform reset responses, session revocation on password change, `skipMfa`/`bypassMfa` detection; lockout/backoff and reset rate-limit patterns cross-link here.

## Analyst Notes

Brute-force resistance (CWE-307) is not modeled as a dedicated auth-endpoint property in standard SAST packs. Adjacent automated findings may surface related gaps — e.g., Express handlers doing expensive work without rate-limit middleware (DoS-oriented, not login-specific lockout), or hardcoded credential comparison at login (different vulnerability class). For brute-force findings, continue using the manual detection rules above.
