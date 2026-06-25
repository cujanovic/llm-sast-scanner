---
name: verification-code-abuse
description: Detect OTP, captcha, and verification-code flaws such as predictable generation, disclosure, brute force, weak TOTP config (short digits, wide acceptance/grace window), replay, and shared state.
---

# Verification Code / OTP / Captcha Abuse

Verification codes must be treated as security-critical tokens. Raise findings only when concrete code evidence supports the claim.

## High-signal patterns

- `java.util.Random`, `Math.random()`, or low-entropy generators used for OTP, captcha, SMS codes, password reset codes, or session verification: report as `CWE-330` when the code protects an account, login, or sensitive action.
- Generated verification code is echoed back to the client, added to the response model, returned in JSON, or printed in a way the attacker can trivially obtain it: report as information disclosure or logic weakness.
- Verification state stored in a shared field/static variable instead of per-user/per-session storage.
- Validation endpoint has no observable expiry, attempt counter, lockout, throttling, or one-time invalidation logic.
- GET endpoint triggers code generation or verification state change without protective controls.

## OTP / reset-token disclosure in responses

- OTP, 2FA code, SMS code, or password-reset token returned in the HTTP response body, debug payload, or serializer field — including post-enrollment "show your code" endpoints that leak the active secret.
- Response models / serializers expose `otp`, `code`, `token`, `reset_token`, `verificationCode`, or `twoFactorCode` to the client after generation.

```js
// VULN — OTP echoed in JSON response
const otp = generateOtp(userId);
await sendSms(user.phone, otp);
return res.json({ success: true, otp });   // disclosure

// SAFE — never return the secret; only a generic ack
await sendSms(user.phone, otp);
return res.json({ success: true, message: 'Code sent' });
```

```python
# VULN — reset token in serializer output
class ResetResponseSerializer(serializers.Serializer):
    reset_token = serializers.CharField()   # exposed to client

# SAFE — token only in out-of-band channel (email link); response is uniform
return Response({'message': 'If the account exists, instructions were sent.'})
```

## Single-use, invalidation, and resend semantics

- OTP or reset token **not invalidated after successful use** — same code works twice.
- **Resend without invalidating prior code** — old code remains valid alongside the new one; no `DELETE`/`used_at`/`consumed` flag on verify.
- Reset token **not invalidated on password change, email change, or account recovery completion**.
- No TTL / expiry check before compare (`expires_at`, `created_at + window`).

```js
// VULN — verify succeeds but code row never deleted/marked used
if (stored.code === submitted) {
  return res.json({ verified: true });
}

// SAFE — atomic consume on success
const row = await db.otp.findOne({ userId, code: submitted, used: false, expiresAt: { $gt: new Date() } });
if (!row) return res.status(401).json({ error: 'Invalid code' });
await db.otp.update({ id: row.id }, { used: true });
// on resend: invalidate all prior rows for userId before issuing new code
```

```js
// VULN — resend appends without invalidating
await db.otp.insert({ userId, code: newCode });   // old codes still valid

// SAFE
await db.otp.updateMany({ userId, used: false }, { used: true });
await db.otp.insert({ userId, code: newCode, expiresAt });
```

## Weak or missing code validation

- Comparison passes on **null, empty string, undefined, or whitespace** — `if (code == stored)`, `!code`, or missing guard before verify.
- **Default / trivial codes accepted**: `000000`, `123456`, hardcoded bypass, or config default used in production compare path.
- Non-constant-time compare on short numeric OTP (secondary to brute force — see `brute_force.md`).

```python
# VULN — empty submission matches empty/missing DB field
if request.json.get('code') == user.otp_code:
    grant_access()

# VULN — default bypass
if code == user.otp_code or code == '000000':
    grant_access()

# SAFE
submitted = (request.json.get('code') or '').strip()
if not submitted or not secrets.compare_digest(submitted, expected):
    return abort(401)
```

## Cross-account OTP / token reuse (missing binding)

- Verify step looks up code **without binding to requesting user, session, or account id** — attacker uses their own issued code against victim's session or replays a captured token across accounts.
- Reset/verify handler queries `WHERE code = ?` only, with no `userId`/`sessionId`/`email` correlation.
- **Code delivered to a request-supplied destination but bound to a victim-owned target (resource-claim / change-contact takeover)**: the send-OTP endpoint accepts *both* a delivery destination (`phone`/`email`) **and** a separate target identifier (`resId`, `accountId`, `listingId`, `merchantId`) from the request. The code is sent to the **attacker's** destination, then the verify step grants ownership/role over the **victim's** target object — because the server never checks that the destination is the contact **of record** for that target. Pattern recurs in business/listing "claim", phone/email change, and ownership-transfer flows. SAST signals: a `send*otp`/`request*verification` handler that reads the recipient channel from the request **and** a target object id from the request, with no assertion that the channel matches the target's stored owner contact (no `target.owner_phone == req.phone` / lookup of the destination from the target record); a `verify*otp` handler that maps the *current caller* onto the request-supplied target on success. Fix: derive the delivery destination **from the target's stored owner record**, never from the request; bind the code to `(target_id, owner_contact)` and confirm the caller controls that registered contact before granting access.

```js
// VULN — code valid for any account
const row = await db.otp.findOne({ code: req.body.code });

// SAFE — bind to authenticated session or explicit account context
const row = await db.otp.findOne({
  userId: req.session.pendingUserId,
  code: req.body.code,
  used: false,
});
```

## Weak reset-token generation (CWE-330)

- Predictable token sources: `Date.now()`, timestamp, incrementing id, sequential counter, `md5(email)`, raw `userId`, UUID v1 time component, or short numeric-only tokens (< 128 bits entropy).
- Missing CSPRNG: `Math.random()`, `java.util.Random`, `rand()`, `Random()` without `crypto.randomBytes` / `secrets.token_urlsafe` / `SecureRandom`.

```js
// VULN — predictable, low entropy
const resetToken = Date.now().toString();
const resetToken = crypto.createHash('md5').update(email).digest('hex');
const resetToken = String(user.id + 1);

// SAFE — CSPRNG, sufficient length, stored hashed
const resetToken = crypto.randomBytes(32).toString('base64url');
await db.resetTokens.save({ userId, hash: hashToken(resetToken), expiresAt });
```

```java
// VULN
String token = String.valueOf(System.currentTimeMillis());
String token = DigestUtils.md5Hex(user.getEmail());

// SAFE
byte[] bytes = new byte[32];
SecureRandom.getInstanceStrong().nextBytes(bytes);
String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
```

## TOTP replay and window abuse

- TOTP verify accepts **overly wide time window** (`window > 1` or custom skew with no replay cache) — same code reusable within validity period.
- No **replay cache** / `lastUsedStep` tracking — successful TOTP submission can be replayed until window expires.
- For rate limits and attempt caps on OTP endpoints, see `brute_force.md`; for recovery-token storage, session revocation on password change, and MFA flow binding, see `authentication_jwt.md`.

```python
# VULN — wide window, no replay tracking
if totp.verify(code, valid_window=10):
    login(user)

# SAFE — standard window + replay cache keyed by (user, time step)
if not totp.verify(code, valid_window=1):
    return deny()
if replay_cache.seen(user.id, totp.timecode):
    return deny()
replay_cache.mark(user.id, totp.timecode)
```

## TOTP brute-force exposure (weak config)

Distinct from replay: a TOTP verifier's resistance to **online guessing** is set by three code-visible knobs — digit count `D` (search space `10^D`), the acceptance/grace window `λ` (at any instant **`1 + λ` codes are valid**, so each extra accepted step *linearly* multiplies success odds), and whether the verify path has an attempt cap. Per-step success ≈ `attempts_per_step × (1+λ) / 10^D`; over many steps it compounds. A standard 6-digit code with **no rate limiting** reaches ~50% compromise in hours at only 20–30 req/s; shrinking to 4 digits (`10^4`) or widening the window makes it far faster.

Flag the *combination* (any single knob may be acceptable alone, but together they are exploitable):
- **Short codes** — `D < 6` (4-digit OTP/PIN) shrinks the space by 100×.
- **Wide acceptance window** — `valid_window`/`window`/`skew`/grace `> 1` (each step adds a fully-valid code). Prefer `0`; `1` only if clock-drift truly requires it.
- **No attempt cap on the verify endpoint** — no lockout/throttle/counter (the actual exploit enabler; see `brute_force.md`). Without it, the OTP is just a short number an attacker enumerates.

```python
# VULN — short code + wide window + no attempt cap = trivially brute-forceable
#   4 digits → 10^4 space; window=5 → 6 codes valid at once; no lockout on this path
totp = pyotp.TOTP(secret, digits=4)
if totp.verify(code, valid_window=5):          # ~6/10000 acceptance per attempt
    login(user)

# SAFE — 6 digits, minimal window, per-account attempt cap + replay cache
totp = pyotp.TOTP(secret, digits=6)
if attempts.exceeded(user.id):                 # lockout/throttle (brute_force.md)
    return deny()
if not totp.verify(code, valid_window=0):      # 1 valid code (or =1 only if drift requires)
    attempts.incr(user.id)
    return deny()
if replay_cache.seen(user.id, totp.timecode):  # block reuse within the step
    return deny()
replay_cache.mark(user.id, totp.timecode)
```

## SAST grep indicators

**Disclosure in responses / serializers:**
```bash
rg -n "res\.(json|send)\(.*\b(otp|code|token|reset_token|verificationCode|twoFactorCode)\b" --glob "*.{js,ts,py,rb,php,java}"
rg -n "(reset_token|verification_code|otp_code)\s*=" --glob "*serializer*"
rg -n "return.*\{[^}]*(otp|reset_token|verificationCode)" .
```

**Missing invalidation / single-use:**
```bash
rg -n "(verify|validate).*(otp|code|token)" --glob "*.{js,ts,py,java}" | rg -v "used|consumed|delete|invalidate|expires"
rg -n "resend|send.*otp|send.*code" . | rg -v "invalidate|deleteMany|used.*true"
```

**Weak compare / default codes:**
```bash
rg -n "==\s*['\"]000000['\"]|==\s*['\"]123456['\"]|or\s+code\s*==" .
rg -n "if\s*\(\s*!?\s*code\s*\)|\.get\(['\"]code['\"]\)\s*==|code\s*==\s*null" .
```

**Missing user/session binding on verify:**
```bash
rg -n "findOne.*code\s*:" --glob "*.{js,ts,py}" | rg -v "userId|user_id|session|email"
```

**Weak token generation:**
```bash
rg -n "Date\.now\(\)|System\.currentTimeMillis|Math\.random|java\.util\.Random|md5\(.*email|createHash\(['\"]md5" --glob "*reset*"
rg -n "resetToken|reset_token|verification_token" . | rg "randomBytes|secrets\.|SecureRandom|token_urlsafe"
```

**TOTP window / replay / weak config:**
```bash
rg -n "valid_window|window\s*[=:]\s*[2-9]|totp\.verify" .
rg -n "lastUsedStep|replay.*totp|totp.*cache" .
# short codes + wide grace/skew (brute-force amplifiers)
rg -n "digits\s*[=:]\s*[1-5]\b|TOTP\([^)]*digits\s*=\s*[1-5]" .
rg -n "valid_window|grace|skew|drift|window" --glob "*.{py,js,ts,go,java,rb,php}" | rg -iv "window\s*[=:]\s*[01]\b"
```

## Evidence expectations

- Show where the code is generated.
- Show where it is stored or exposed.
- Show where verification is checked without expiry or attempt controls.
- Prefer one finding per concrete issue; do not merge weak randomness and disclosure into one if they are separate locations.

## Common False Alarms

- Do not report a page that only renders a captcha/OTP template unless the backend code actually generates, stores, exposes, or verifies a code.
- FALSE POSITIVE guard: do not emit `verification_code` for demo message/code pages unless the benchmark taxonomy explicitly treats the flow as OTP/captcha abuse rather than weak random or generic logic.
- FALSE POSITIVE guard: demo code-echo flows outside `/captcha`, `/sms`, `/otp`, `/verify`, password-reset, or login-protection paths should not emit `verification_code` unless the benchmark explicitly scores that module as verification abuse.
- Missing rate limiting alone on OTP endpoints is primarily `brute_force` — pair with `verification_code` only when the code logic itself is flawed (disclosure, reuse, weak generation, missing binding).
- TOTP libraries with `valid_window=1` and documented replay protection are not findings unless replay cache is absent and demonstrably exploitable.
- A wide TOTP window (`> 1`), short digit count, or grace period is only a brute-force finding when the verify endpoint **also** lacks an attempt cap/lockout — a correct 6-digit code with `window<=1` behind rate limiting is not a finding. Pair the config weakness with the missing control (`brute_force.md`).

## Related references

- `brute_force.md` — attempt counters, lockout, throttling, CAPTCHA on OTP/login/reset endpoints.
- `authentication_jwt.md` — MFA/TOTP flow binding, recovery-token hashing, session revocation on password change, uniform reset responses.
