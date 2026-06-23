---
name: session_puzzling
description: Session puzzling (session variable overloading) — an unauthenticated or mid-flow session attribute is later read as proof of full authentication or authorization (CWE-841 / CWE-384)
---

# Session Puzzling / Session Variable Overloading (CWE-841 / CWE-384)

Session puzzling occurs when the application **reuses the same session key** for an unauthenticated or partial flow (password recovery, registration, email verification, checkout step 1, MFA challenge) and later treats the **mere presence** of that key as proof the user completed a full login. An attacker who triggers the pre-auth flow can populate `session['username']`, `session['user']`, or a mid-MFA flag, then navigate to a protected route whose guard only checks that the key exists — gaining access without valid credentials.

## What It Is / Is Not

- **Is**: writing session attributes during recovery/registration/verify/MFA-step handlers that share keys with post-login guards; auth checks of the form `if (session.user)` / `session.get('username')` without an explicit `authenticated` / `loginComplete` flag; MFA intermediate state (`mfaVerified`, `otpPassed`) reused to authorize unrelated privileged routes.
- **Is not**: session fixation — reusing the same session **ID** across login without rotation (`session_fixation.md`); storing the authenticated user object **after** verified login with proper session regeneration; CSRF on the recovery form (`csrf.md`); weak password-reset token validation (`verification_code_abuse.md` — token logic, not session key reuse).
- **Highest signal** when grep shows `session[...] =` / `req.session.X =` inside `reset`, `register`, `verify`, `forgot`, `mfa`, `step1` handlers and a **different** route reads the same key as an auth gate.

## Source -> Sink Pattern

- **Source**: unauthenticated or partial-auth handler writes a session attribute — `req.session.username = email`, `session['resetUser'] = user`, `HttpContext.Session.SetString("UserId", id)`, `$_SESSION['pending_user'] = $row`, MFA step sets `session.mfaOk = true`.
- **Sink**: protected route, admin action, or API whose guard checks **presence** of that attribute (`if session.get('username')`, `if req.session.user`, `User.Identity.IsAuthenticated` implied by custom session key) instead of a dedicated post-login authenticated flag tied to credential verification.
- **Aggravating chain**: recovery flow sets `session['user']` to the victim's identifier (account pre-binding); attacker completes puzzling before victim finishes reset; no session segregation or clear between flows.

## Recon Indicators (Grep)

```bash
# Session writes in unauthenticated / mid-flow handlers
rg -n 'session\[|req\.session\.|HttpContext\.Session\.(Set|SetString)|setAttribute\(|\.setAttribute\(' \
  --glob '*.{js,ts,py,php,java,cs,go}' \
  | rg -i 'reset|recover|forgot|register|signup|verify|confirm|activation|step.?1|mfa|otp|2fa|challenge|invite'
# Auth guards that read session keys (pair with writes above — same key name = puzzle candidate)
rg -n 'session\.(get|\[)|req\.session\.|HttpContext\.Session\.Get|getAttribute\(|\.getAttribute\(' \
  --glob '*.{js,ts,py,php,java,cs,go}' \
  | rg -i 'auth|login|protect|guard|require|middleware|@login|Authorize|isAuthenticated|currentUser'
# Presence-only checks (no explicit authenticated/loginComplete flag)
rg -n 'if\s*\(.*session\.(user|username|userId)|session\.get\(['"'"'"]user|!= null|!== undefined\)' --glob '*.{js,ts,py,php}'
# MFA / step flags read outside the MFA flow
rg -n 'mfaVerified|otpPassed|twoFactor|stepComplete|loginStep' --glob '*.{js,ts,py,php,java,cs}'
# Flask/Django/Express session config — shared cookie across flows
rg -n 'SESSION_|session\.|SessionMiddleware|express-session' --glob '*.{py,js,ts,env*}'
```

For each session **write** in a pre-auth handler, search for **reads** of the same key in protected routes. Flag when the read lacks verification that full login completed (password + MFA if required).

## Vulnerable Conditions

- Password-reset handler sets `session['username'] = submittedEmail` to "remember" the user; dashboard route allows access when `session.get('username')` is truthy.
- Registration step 1 stores `req.session.user = { email }`; step 3 profile route treats any `req.session.user` as logged-in.
- Email-verification link handler sets `session['userId'] = id` after token check; API routes use `userId` from session without `session['authenticated'] === true`.
- MFA handler sets `session.mfaPassed = true` after OTP; admin routes check `mfaPassed` but never confirm primary authentication completed in the same session.
- Guard: `if (session['user'] != null) { allow }` — no distinction between "user object from recovery" and "user object from login".
- Multiple flows share generic keys: `user`, `userId`, `username`, `email`, `role` — instead of flow-scoped keys cleared on transition.

## Vulnerable vs Safe code examples

### Flask — reset flow poisons auth session

```python
# VULN — forgot-password stores username; protected route treats it as login
@app.post('/forgot-password')
def forgot():
    email = request.form['email']
    session['username'] = email          # same key as login
    send_reset_email(email)
    return redirect('/check-email')

@app.get('/dashboard')
def dashboard():
    if session.get('username'):          # presence = "authenticated"
        return render_template('dashboard.html')
    return redirect('/login')

# SAFE — flow-scoped keys; explicit authenticated flag only after password verify
@app.post('/forgot-password')
def forgot():
    email = request.form['email']
    session['reset_pending_email'] = email
    send_reset_email(email)
    return redirect('/check-email')

@app.post('/login')
def login():
    user = verify_credentials(request.form)
    session.clear()
    session['authenticated'] = True
    session['user_id'] = user.id
    return redirect('/dashboard')

@app.get('/dashboard')
def dashboard():
    if not session.get('authenticated'):
        return redirect('/login')
    return render_template('dashboard.html', user=current_user())
```

### Express — registration step reuses `session.user`

```javascript
// VULN — step 1 sets session.user; later routes treat it as logged-in
app.post('/register/step1', (req, res) => {
  req.session.user = { email: req.body.email };
  res.redirect('/register/step2');
});
app.get('/account/settings', (req, res) => {
  if (req.session.user) return res.render('settings');   // no login
  res.redirect('/login');
});

// SAFE — segregated keys; regenerate + authenticated flag after full login
app.post('/register/step1', (req, res) => {
  req.session.registration = { email: req.body.email, step: 1 };
  res.redirect('/register/step2');
});
app.post('/login', (req, res) => {
  const user = verify(req.body);
  req.session.regenerate(() => {
    delete req.session.registration;
    req.session.authenticated = true;
    req.session.userId = user.id;
    res.redirect('/dashboard');
  });
});
app.get('/account/settings', (req, res) => {
  if (!req.session.authenticated) return res.redirect('/login');
  res.render('settings');
});
```

### Java / Spring — MFA flag reused for admin

```java
// VULN — OTP step sets generic flag; admin controller reads it as sufficient
@PostMapping("/mfa/verify")
public void verifyOtp(@RequestParam String code, HttpSession session) {
    if (checkOtp(code)) session.setAttribute("authComplete", true);
}
@GetMapping("/admin/users")
public List<User> listUsers(HttpSession session) {
    if (session.getAttribute("authComplete") != null) return userService.findAll();
    throw new AccessDeniedException();
}

// SAFE — Spring Security context after full authentication; MFA is a step, not the gate
// Use SecurityContextHolder.getContext().getAuthentication().isAuthenticated()
// and @PreAuthorize("hasRole('ADMIN')") — not a custom session flag from OTP alone
```

### PHP — verify handler binds user id

```php
// VULN
// verify.php after email token OK:
$_SESSION['user_id'] = $row['id'];
// dashboard.php:
if (isset($_SESSION['user_id'])) { /* full access */ }

// SAFE
$_SESSION['email_verified_user_id'] = $row['id'];  // scoped to verify flow only
// After password set + login:
session_regenerate_id(true);
unset($_SESSION['email_verified_user_id']);
$_SESSION['authenticated'] = true;
$_SESSION['user_id'] = $row['id'];
```

## Safe Patterns

- **Purpose-scoped session keys** — `reset_pending_email`, `registration`, `verify_token_ctx` — never reuse `user`, `username`, `userId` across flows.
- **Explicit authenticated flag** — set `authenticated = true` / bind server-side session to verified credentials **only** in the login success path (after password + MFA if required).
- **Clear or segregate on transition** — `session.clear()` or delete flow keys before setting authenticated state; complete registration must not leave half-auth keys readable by protected routes.
- **Regenerate session ID at privilege transition** — on login success, after reset completion, before elevating to admin (`session_fixation.md`).
- **Framework-native auth** — Flask-Login `login_user()`, Django `auth.login()`, Spring Security `SecurityContext`, Express Passport `req.login()` — guards check `isAuthenticated` / `@PreAuthorize`, not ad-hoc session keys from other flows.
- **MFA as sub-step** — MFA completion merges into the authenticated security context; do not expose `mfaPassed` to unrelated route guards.

## Severity / Triage

- **Critical**: puzzling grants access to victim account, admin panel, or account takeover primitive (reset flow binds victim username attacker can complete).
- **High**: access to authenticated-only data/API without credentials via registration or verify flow keys.
- **Medium**: partial state leak (profile draft) without full account control; requires specific flow ordering.
- **Low/Info**: flow key overlaps but protected routes also require valid server-side token/session store lookup tied to login event.
- **False positive path**: pre-auth write uses a distinct key never read by auth guards; login path clears all flow keys and sets `authenticated` only after verification.

## Common False Alarms

- `session['username']` stored **after** successful `verify_credentials()` / `login_user()` with session regeneration — that is post-login state, not puzzling.
- Pre-auth flow stores data in **server-side flash** or signed one-time cookie not consulted by auth middleware.
- Guard checks `request.user.is_authenticated` (Django) or `SecurityContextHolder` — framework flag, not a custom recovery key.
- MFA flag checked only inside the MFA completion endpoint, then discarded before issuing authenticated session.
- Readonly display of "reset email sent to X" from a flow-scoped key on a public page with no privileged action.

### GraphQL — token/session minting on public operations + chaining

GraphQL resolvers can mint session cookies, CSRF tokens, or access tokens during **unauthenticated** bootstrap operations (`initSession`, `csrfToken`, `register`/`signUp`, or token-issuing queries/mutations). Middleware or mutation guards then treat that token as proof of identity for "protected" mutations — session puzzling at the resolver/transport layer. Cross-ref `graphql_injection.md` (Authorization — session/token minting on public GraphQL operations).

**Vulnerable conditions**:
- (a) Session token returned in resolver payload or `Set-Cookie` from a signup/bootstrap resolver **before** credential verification completes
- (b) Same cookie/header name used for anonymous and authenticated phases with no explicit `authenticated` flag
- (c) Placeholder/sentinel tokens accepted — middleware treats header **presence** or values like `'na'`, `'null'`, `''` as authenticated

**Grep seeds**:
```bash
# Token/cookie set in unauthenticated resolvers
rg -n 'setCookie|res\.cookie|ctx\.session\s*=|context\.session' --glob '*.{js,ts,py}' \
  | rg -i 'register|signup|initSession|csrfToken|bootstrap|init'
# Public operations issuing tokens
rg -n 'csrfToken|initSession|register|signUp|createAnonymousSession' --glob '*.{graphql,graphqls,js,ts,py}'
# Auth gate — presence-only without crypto/server-side verification
rg -n 'if\s*\(\s*token|if\s*\(\s*!token|if\s*\(\s*ctx\.(user|session)|headers\[' --glob '*.{js,ts,py}'
rg -n "'na'|'null'|\"\"|placeholder|sentinel" --glob '*.{js,ts,py}' -C2 | rg -i 'auth|session|token'
```

**VULN**:
```js
// VULN — register resolver mints session before email/password verified
register: async (_, { email }, ctx) => {
  const sid = crypto.randomUUID();
  ctx.res.cookie('session', sid, { httpOnly: true });
  ctx.session = { email };  // same cookie name as post-login
  return { ok: true };
},
// VULN — protected mutation trusts cookie/header presence
updateProfile: async (_, args, ctx) => {
  if (ctx.session || ctx.req.headers.authorization) return doUpdate(args);
  throw new ForbiddenError('login required');
},
// VULN — sentinel values treated as authenticated
authMiddleware: (ctx, next) => {
  const t = ctx.req.headers['x-session-token'];
  if (t && t !== 'na' && t !== 'null') ctx.authenticated = true;
  return next();
},
```

**SAFE**: issue only **flow-scoped** tokens pre-auth; full session only after verified login + session-id regeneration; distinct anonymous vs authenticated token types/cookie names; reject placeholder/sentinel tokens; verify server-side session store lookup before authorizing privileged mutations.

## Cross-References

- `session_fixation.md` — session ID must rotate on login/privilege change; complementary control when fixing puzzling.
- `privilege_escalation.md` — missing role check after authentication; puzzling is an **authentication** bypass via session state confusion.
- `verification_code_abuse.md` — weak reset/verify **token** validation (orthogonal; often co-located in reset handlers).
- `authentication_jwt.md` — stateless token claims vs server session; puzzling applies to server-side session stores.
- `trust_boundary.md` — never treat client-supplied values as auth; here the server stored the value but in the wrong lifecycle phase.
- `business_logic.md` — multi-step workflow state machines that skip mandatory steps.
- `graphql_injection.md` — session/token minting on public GraphQL operations; bootstrap resolver chains.

## Core Principle

Every session attribute must have a **single, explicit lifecycle**. Unauthenticated and mid-flow handlers may store flow-scoped state; protected routes must require an **authenticated** flag set only after full credential verification (and MFA if required), never infer login from the mere presence of a key also written during recovery, registration, or verification.
