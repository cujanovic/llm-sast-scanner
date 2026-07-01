---
name: privilege_escalation
description: Detect broken access control issues including vertical privilege escalation, role bypass, missing authorization checks on privileged endpoints.
---

# Privilege Escalation / Broken Access Control

Broken access control arises when an application fails to enforce that users may only perform the actions and access the data they are explicitly authorized for. Three distinct failure modes are covered here:
- **Vertical escalation**: a regular user successfully executes operations reserved for administrators.
- **Horizontal escalation**: a user reaches another user's data by manipulating object identifiers.
- **Role bypass**: the role or permission level originates from client-supplied input and is accepted by the server without independent verification.

## Vulnerable Conditions

- A privileged operation (admin action, data modification, or sensitive read) executes without confirming the requesting user holds the necessary role or permission.
- Role or admin status is read directly from client-supplied input — such as a request body field, query parameter, or cookie — without a corresponding server-side lookup.
- **Access control enforced by a redirect that does not halt execution.** A guard redirects the unauthorized/unauthenticated user (`header('Location: /login')`, `res.redirect('/login')`, `return redirect()`/`RedirectResponse`) but the handler **keeps rendering and emitting the protected content**, so the sensitive body is fully present in the HTTP response and readable by any client that **ignores the redirect** (`curl`, Burp, `fetch(url,{redirect:'manual'})`, `curl --max-redirs 0`). The browser silently follows the 30x and hides it, masking the bug in normal use. **Highest-signal shape**: PHP `header('Location: …');` **not** immediately followed by `exit`/`die`; a filter/`before_action`/middleware that assigns a redirect response but doesn't `return`/short-circuit so the controller action still runs and streams its view; content rendered *before* the redirect is issued. **SAFE**: halt immediately after issuing the redirect (`exit`/`return`/`abort()`), and run the authz check **before** any sensitive data fetch or render — never rely on the client following a redirect to withhold already-emitted content. Cross-ref `information_disclosure.md`.

## Safe Patterns

- The endpoint is decorated with `@login_required`, `@admin_required`, or `@permission_required('...')`.
- The code calls `check_permission(user, action)`, `user.has_perm(...)`, or explicitly branches on `if not user.is_admin: abort(403)`.
- RBAC middleware is registered at the router or framework level and executes before the handler is reached.

---

## Missing Authentication & Broken Function-Level Authorization (BFLA)

Function-level access control failures at the **endpoint** layer — distinct from object-level IDOR (see `idor.md`).

### Class Boundaries

| Class | Condition | Example |
|-------|-----------|---------|
| **Missing authentication** | Sensitive action with no login/session/token required | `DELETE /api/admin/users/5` succeeds with no `Authorization` header |
| **Broken function-level authorization (BFLA)** | User is authenticated but endpoint lacks role/permission check | Regular user token deletes admin user |
| **IDOR (object-level)** | Authenticated user accesses another user's resource by changing an ID | `GET /api/orders/1002` returns another user's order → see `idor.md` |
| **JWT weaknesses** | Flawed token signing, verification, or algorithm handling | Forged `role=admin` claim → see `authentication_jwt.md` |
| **Business logic flaws** | Workflow or state manipulation (price, quantity, step skip) | Not BFLA — separate class |

**Vertical escalation** (user → admin function) and **missing authentication** are covered here. **Horizontal escalation** (user A → user B's object) is IDOR unless combined with a privileged operation.

### BFLA Vulnerability Classes

1. **Unauthenticated sensitive endpoint** — modifies data, returns private info, or performs admin actions with no auth gate.
2. **Authenticated, missing role check** — `@login_required` / `[Authorize]` present but no admin/permission verification on a privileged route.
3. **Incomplete or bypassable authorization** — role check on GET but not DELETE; check conditional on attacker-controlled header/param; route mounted before auth middleware applies; `except:` list excludes a sensitive action.
4. **Token/RPC-dispatched handlers that bypass route guards** — frameworks that dispatch by an identifier rather than the URL path, so path/middleware-based guards never apply and auth must live **inside** the handler. Notably **Next.js Server Actions** (`"use server"` functions dispatched via the `Next-Action` header; the request path is ignored): a Server Action with no in-function `auth()`/role/object-ownership check is invocable by anyone who replays the POST + action token — including **unused/unreferenced** actions still present in the bundle (zombie endpoints). Same pattern applies to other RPC/action-router styles. Cross-ref `csrf.md` (Server Actions) for the CSRF angle.
5. **Interface / transport parity gap — same action, two front doors, inconsistent authorization.** One privileged operation is reachable through **more than one interface** — native gRPC vs a REST/JSON transcoder, an admin CLI vs the web API, GraphQL vs REST, API `v1` vs `v2`, an internal service RPC vs its public gateway — and the authorization (or input validation, or audit logging) is enforced on only *some* of them. The attacker picks the weakest path. This is the transport generalization of the per-method gap in item 3 (and `http_method_tamper.md`'s method/`Accept`-differential authz). **SAST signal**: the same handler/service method wired to two entrypoints where one applies an auth interceptor/middleware/decorator and the other doesn't (e.g. a gRPC method with a server interceptor but its grpc-gateway/Connect transcoder route lacks it — cross-ref `grpc_security.md`; a CLI/admin path that calls the service function directly, skipping the web layer's guard). **SAFE**: enforce authorization in the **shared service/domain layer** every interface funnels through, not per-entrypoint; diff authz requirements across all interfaces exposing the same action.

### Recon Indicators

Grep for route/handler definitions, then verify each sensitive endpoint has **both** authentication and authorization:

**Route registration patterns**
- Express/Koa: `router.get|post|put|delete|patch|use`
- Django: `urlpatterns`, `path(`, `re_path(`
- Flask/FastAPI: `@app.route`, `@router.get|post|delete`
- Rails: `routes.rb` — `resources`, `namespace :admin`
- Spring: `@GetMapping`, `@PostMapping`, `@DeleteMapping`, `@RequestMapping`
- Go/Chi: `r.Get`, `r.Post`, `r.Delete`, `r.Group`
- Laravel: `Route::get|post|delete`
- ASP.NET: `[HttpGet]`, `[HttpPost]`, `[HttpDelete]`

**Non-REST entry points (often missed — inventory these too)**
- **GraphQL**: every `Query`/`Mutation`/`Subscription` resolver is an endpoint — a mutation with no `@auth`/guard in the resolver/field is BFLA even if the HTTP route is protected. Grep resolver maps, `@Resolver`, `buildSchema`, SDL `type Mutation`.
- **WebSocket**: message/event handlers (`socket.on(`, `@SubscribeMessage`, `@MessageMapping`, channel subscribe) — auth is frequently checked only on the HTTP upgrade, not per message/action.
- **RPC / gRPC**: service methods (`rpc `/`@GrpcService`/`ServerServiceDefinition`), tRPC `procedure`/`mutation`, JSON-RPC method dispatch tables — each method is a function-level authz boundary.
- **Background/queue/cron** handlers reachable from a user-triggered action.

**Missing or inconsistent guards**
- Handler under `/admin`, `/superadmin`, `/management`, `/ops`, `/internal`, `/api/admin`, `/system` with no auth decorator or middleware
- `authenticate_user!` / `@login_required` / `[Authorize]` without accompanying role check (`@admin_required`, `@PreAuthorize`, `requireRole`, `role:admin`)
- **Wrong-role guard**: an admin action gated only by `@Secured("ROLE_USER")` / `[Authorize]` (any authenticated user) / `middleware('auth')` without a role — authenticated ≠ authorized.
- Same resource: GET protected, POST/DELETE/PUT unguarded
- Route registered **before** auth middleware in the stack, or mounted outside a protected route group
- **FastAPI/Starlette mount & scope gaps**: a guarded `APIRouter(dependencies=[Depends(require_admin)])` does **not** protect routes added via `app.include_router(other)` *without* the same `dependencies=`, and routes inside an `app.mount("/x", sub_app)` ASGI sub-app (including `StaticFiles`) **do not inherit** the parent's route dependencies/guards. Separately, binding a security dependency with `Depends(get_user)` instead of `Security(get_user, scopes=[...])` **silently drops OAuth2 scope enforcement** — only `Security(...)` contributes to the `SecurityScopes` a downstream dependency checks, so the route accepts any valid token regardless of its scopes. Grep `app.mount(`, `include_router(` missing `dependencies=`, and `Security(`-vs-`Depends(` on privileged routes.
- **Secondary unauthenticated path** to the same handler: an internal API alias, a `/v1` vs `/v2` duplicate, or a second mount point where only one copy carries the guard.
- **Test/dev-mode auth skip**: middleware bypassed under an env/flag (`if (process.env.NODE_ENV !== 'production') return next()`, `if app.debug:`, `@Profile("!prod")` security config) that can ship or be toggled.
- Client-side-only gating: UI hides admin nav but server handler has no role check

**Role/permission system signals**
- Decorators: `@admin_required`, `@roles_required`, `@PreAuthorize`, `requireRole(`, `middleware('role:admin')`
- In-handler: `is_staff`, `is_superuser`, `user.role == 'admin'`, `Gate::authorize`, `User.IsInRole`
- Explicit exclusions: `except: [:index, :show]`, `skip_before_action :authenticate`

**Sensitive endpoints to prioritize**
- User management (create/delete users, change roles, reset others' passwords)
- Config/secrets (SMTP, feature flags, env vars)
- Aggregate reads (all users, all orders, audit logs)
- System actions (broadcast email, run jobs, clear cache)

### Preventing Patterns

- **Default-deny middleware** on route groups — auth + role check applied to entire prefix before any handler:
  ```javascript
  router.use('/admin', auth, requireRole('admin'));
  router.delete('/admin/users/:id', deleteUser);   // inherited protection
  ```
- **Declarative annotations** at method level — `@PreAuthorize("hasRole('ADMIN')")`, `[Authorize(Roles = "Admin")]`
- **In-handler check** before sensitive action when middleware is impractical:
  ```python
  if not request.user.is_staff:
      return HttpResponseForbidden()
  ```
- **Centralized authorization** — Policy/Gate/Ability objects (`Gate::define`, Pundit, CanCanCan) invoked from every privileged controller action
- **Server-side role lookup** — never trust client-supplied role/admin flags; derive permissions from DB record tied to authenticated session

Trace middleware order: middleware registered **after** the route does not protect it. Check **every HTTP method** on the same path.

### Build-strippable assertion as a security control (CWE-617)

A close sibling of fail-open: the guard is present in source but **compiled/optimized out of the production build**, so it never runs and the protected action proceeds unchecked. Distinct from the env-flag/test-mode skips above (those are runtime branches) — here the security check is implemented with an assertion that the *release/optimized* configuration silently elides.

- **PHP**: `assert($actor->isAdmin())` / `assert($sig_valid)` — a **no-op when `zend.assertions=-1`** (the recommended production setting), so the check disappears in prod. (Pre-8.0, `assert()` on a string also *evaluated* it — code injection.)
- **Python**: `assert user.can_read(doc)` (authz) or `assert verify(token)` — **stripped under `python -O` / `PYTHONOPTIMIZE=1`**, so optimized deployments lose the check.
- **Rust**: `debug_assert!(ctx.authorized)` — **compiles to nothing in `--release`**; use `assert!` only if a panic is the intended control, but prefer a real branch.

**SAST signal**: an `assert(...)` / `debug_assert!(...)` whose expression is a security decision (auth/role/permission, signature/token/HMAC verify, ownership, redaction, license/quota). Recon: `rg -n "assert\s*\(" --glob '*.{php,py}'` and `rg -n "debug_assert!" --glob '*.rs'` then check whether the asserted expression is a security check. **Safe**: enforce with an always-run branch that fails closed — `if (!$actor->isAdmin()) throw new ForbiddenException();` / `if not user.can_read(doc): raise PermissionError` / `if !ctx.authorized { return Err(Denied) }`.

### Fail-Open Security Checks (CWE-636 / CWE-755)

A security decision (authentication, authorization, signature/token verification, license/quota check) wrapped in error handling that **proceeds as allowed when the check throws** instead of denying. The exception path silently grants access — exactly the case attackers trigger by forcing the check to error (malformed token, unreachable auth service, null lookup).

**Recon indicators**
- A `try`/`catch` (or `except`) surrounding an auth/role/permission/verify call whose `catch` returns `true`, returns the resource, calls `next()`/`continue`, or logs-and-proceeds instead of returning 401/403.
- Empty catch blocks (`catch (e) {}`, `except: pass`) around a verification call — the failure is swallowed and execution falls through to the protected action.
- A boolean `isAuthorized`/`hasRole` initialized to `true` and only set to `false` inside a `try`, so an exception leaves it `true`.
- Unhandled promise rejection on an async guard (`await checkAuth()` with no `.catch`/surrounding try) where the framework continues the request on rejection.

**VULN** (exception → access granted):
```javascript
function isAdmin(req) {
  try {
    return verifyRole(req.user, 'admin');   // throws on malformed/expired token
  } catch (e) {
    return true;                            // fail-open: error treated as authorized
  }
}
```
```python
try:
    enforce_permission(user, "delete")
except Exception:
    pass            # swallowed — code falls through to the privileged action
delete_record(id)
```

**SAFE** (default-deny on error): the exception path must deny.
```javascript
function isAdmin(req) {
  try {
    return verifyRole(req.user, 'admin');
  } catch (e) {
    logger.warn('role check failed', { reason: e.name });
    return false;                           // fail-closed
  }
}
```

Distinguish from a non-security `try`/`catch`: only flag when the guarded call participates in a security decision and the error path widens access. The same fail-open shape in TLS/certificate verification is covered in `certificate_validation.md`; sensitive data leaked in the error response itself is `information_disclosure.md`.

### Loose Boolean Coercion & ACL Predicate Ordering (fail-open without an exception)

A guard can fail open even when nothing throws — through how the flag is *parsed* or the order predicates are *evaluated*:

- **Loose boolean coercion of an authz flag** — a restriction modeled as an "optional" boolean param that defaults to permissive when **absent, empty, or mistyped**. Examples: a check that only restricts when `restricted == 1` (so omitting the param, or sending `restricted=` / `restricted[]` / `restricted=anything`, yields unrestricted/privileged behavior); PHP/loose-typed comparisons where `"0"`, `""`, `"false"`, `[]`, or an array coerce to an unexpected truthiness; "enable protection" flags read from user-controlled form/body/query. **SAST signal**: an authorization/visibility decision keyed on a single optional request field with no strict type/value validation and a permissive default. **SAFE**: default-deny (`is_restricted = field === 'true'` and require the field), validate type, and derive privilege from server-side identity — never from an optional client flag.
- **ACL predicate ordering / short-circuit** — an access decision that ORs a **broad** predicate before a **narrow** one, so a feature flag / "public" path / early `return true` is evaluated first and the specific per-object permission check is never reached. Same family: `if (isFeatureEnabled() || hasPermission(obj))`, or a policy list whose first matching broad rule wins. **SAST signal**: authorization expressions where a coarse/global condition can satisfy the whole check ahead of the object-level check. **SAFE**: evaluate the narrowest required permission, combine with AND not OR, and put deny rules first.
- **Protective guard uses `&&` where `||` was intended (deny/redirect *under-fires*)** — the mirror of the allow-side bug: a redirect/return/`throw`/abort that *blocks* access is gated by `if (condA && condB) { block }`, so it only fires when **both** hold; an attacker who can falsify **either** operand slips past while the sensitive action still executes. Canonical shape: a lock that should engage when *initialization is complete* **OR** *no privileged action was requested* is written as `if (isEmpty(request.action) && SetupCompleted()) redirect("/home");` — sending any non-empty `action` makes the first operand false, the redirect is skipped, and the reachable setup/action handler (create-admin, config write) runs **post-install** → auth bypass → RCE (pairs with the setup-flow-reachable-after-install bug above). **SAST signal**: a security-relevant redirect/return/throw whose condition **ANDs** an attacker-influenceable predicate (request-param presence/emptiness, a client flag) with a server-state predicate — flipping the attacker-controlled operand disables the whole guard; the correct form usually **ORs** the sufficient conditions. **Recon**: `rg -n 'if\s*\(.*(isEmpty|IsNullOrEmpty|== *""|!= *null).*&&.*\)\s*\{?\s*(return|redirect|throw|abort|Redirect)'`. **SAFE**: gate protective actions so *any* sufficient condition triggers them, and never let a single request-controlled operand be able to switch a guard off.

```php
// VULN: restriction only applies when flag is exactly 1; omit/empty/array → unrestricted
if ($_POST['restricted'] == 1) { requireOwner(); }
doPrivilegedAction();

// SAFE: default-deny, strict parse, server-derived authority
if (($_POST['restricted'] ?? '1') !== '0' ) { requireOwner(); } // and validate input type
```

### Vulnerable vs. Secure — Additional Frameworks

Frameworks with dedicated detection rules below (Python, JavaScript, PHP, Java) are omitted here.

#### Ruby on Rails

```ruby
# VULNERABLE: No before_action
def destroy
  User.find(params[:id]).destroy
  head :no_content
end

# VULNERABLE: Authenticated but no admin check
before_action :authenticate_user!
def destroy
  User.find(params[:id]).destroy
  head :no_content
end

# SECURE
before_action :authenticate_user!, :require_admin
def destroy
  User.find(params[:id]).destroy
  head :no_content
end

private
def require_admin
  head :forbidden unless current_user.admin?
end
```

#### Go (Chi)

```go
// VULNERABLE: No auth middleware
r.Delete("/admin/users/{id}", deleteUser)

// VULNERABLE: Auth middleware but no role check
r.With(AuthMiddleware).Delete("/admin/users/{id}", deleteUser)

// SECURE: Group-level gates
r.Group(func(r chi.Router) {
    r.Use(AuthMiddleware)
    r.Use(AdminOnlyMiddleware)
    r.Delete("/admin/users/{id}", deleteUser)
})
```

#### C# — ASP.NET Core

```csharp
// VULNERABLE: No authorization attribute
[HttpDelete("api/admin/users/{id}")]
public async Task<IActionResult> DeleteUser(int id) {
    await _userService.DeleteAsync(id);
    return NoContent();
}

// VULNERABLE: [Authorize] but no role restriction
[Authorize]
[HttpDelete("api/admin/users/{id}")]
public async Task<IActionResult> DeleteUser(int id) { ... }

// SECURE
[Authorize(Roles = "Admin")]
[HttpDelete("api/admin/users/{id}")]
public async Task<IActionResult> DeleteUser(int id) { ... }
```

#### Java — Spring Security method-security annotations silently unenforced (CWE-862)

Spring's method-level authorization annotations are **no-ops unless method security is explicitly enabled** — the annotation is read as plain metadata and the advice that enforces it is never registered, so the method runs for everyone while the code *looks* guarded. This is a complete BFLA that passes code review. The enabling switch differs by annotation and Spring version, and each annotation has its own flag:

- `@PreAuthorize` / `@PostAuthorize` / `@PreFilter` / `@PostFilter` require `@EnableMethodSecurity` (Spring Security 6+, `prePostEnabled` defaults **true**) **or** the legacy `@EnableGlobalMethodSecurity(prePostEnabled = true)` (5.x, where it defaults **false** — annotating without the flag enforces nothing).
- `@Secured` requires `securedEnabled = true`.
- `@RolesAllowed` (JSR-250) requires `jsr250Enabled = true`.

**Detection signal** — methods/classes annotated with any of the above but **no** `@EnableMethodSecurity`/`@EnableGlobalMethodSecurity` anywhere in the config, **or** the annotation in use whose enabling flag is absent/false (e.g. `@Secured` used but only `prePostEnabled` set). Also flag annotations on **non-public** methods or on calls that bypass the Spring proxy (self-invocation within the same bean) — proxy-based advice does not apply there either.

```java
// VULN: @PreAuthorize present but method security never enabled → annotation ignored, anyone can call
@PreAuthorize("hasRole('ADMIN')")
public void deleteUser(long id) { ... }     // no @EnableMethodSecurity in any @Configuration

// VULN: @Secured used but only prePostEnabled — securedEnabled is false → @Secured ignored
@EnableGlobalMethodSecurity(prePostEnabled = true)
class SecCfg {}
@Secured("ROLE_ADMIN") public void purge() { ... }

// SECURE: enable the flags matching the annotations actually used
@Configuration @EnableMethodSecurity   // prePostEnabled true by default in Spring Security 6+
class SecCfg {}
@PreAuthorize("hasRole('ADMIN')") public void deleteUser(long id) { ... }
```

Cross-ref `expression_language_injection.md` for the **separate** risk of building the `@PreAuthorize`/`@PostAuthorize` SpEL string from user input (SpEL injection), and `authentication_jwt.md` for the auth layer the method check assumes.

### Dynamic Test / PoC

Confirm BFLA findings at runtime — static analysis alone cannot prove middleware ordering in all deployments.

**Missing authentication** — call sensitive endpoint with no credentials; success (200/204 + data/action) confirms:
```bash
curl -X DELETE https://<HOST>/api/admin/users/5
# Expected if vulnerable: 204 No Content (user deleted)
# Expected if secure: 401 Unauthorized
```

**Missing role check** — call admin endpoint with a regular (non-admin) user token; success confirms BFLA:
```bash
curl -X DELETE https://<HOST>/api/admin/users/5 \
  -H "Authorization: Bearer <REGULAR_USER_TOKEN>"
# Expected if vulnerable: 204 No Content
# Expected if secure: 403 Forbidden
```

Compare HTTP methods on the same path — a protected GET with unprotected DELETE is a common partial-fix signal.

---

## Authorization Bypass via Path, Header & Workflow Gaps

Function-level guards that key on one request representation while routing, proxying, or workflow state uses another. Path-normalization desync, rewrite-header routing, and proxy `location` mismatches are covered in `reverse_proxy_access_bypass.md` — use that reference for full proxy/normalization analysis; this section focuses on **handler-layer missing or alternate guards**.

### URL-Rewrite Header ACL Bypass

**VULN**: auth middleware checks `req.path` / `request.uri` while the router or upstream honors `X-Original-URL`, `X-Rewrite-URL`, or `X-Forwarded-Prefix` to select the handler — client sends a rewrite header pointing at a protected path while the guard evaluates an unprotected path.

```bash
rg -ni 'x-original-url|x-rewrite-url|x-forwarded-prefix' --glob '*.{js,ts,py,java,cs,go,php}'
# Verify auth gate reads a different path field than routing/upstream selection
```

```javascript
// VULN: auth on req.path; router uses x-original-url
if (req.path.startsWith('/admin')) return res.sendStatus(403);
const target = req.headers['x-original-url'] || req.path;
app.handle(target, req, res);   // attacker: X-Original-URL: /admin/users
```

**SAFE**: single canonical path computed before both auth and routing; rewrite headers stripped at the trust boundary or ignored for external routing. See `reverse_proxy_access_bypass.md`.

### Referer / Origin-Based Access Control

**VULN**: sensitive action gated on `Referer` or `Origin` matching an expected prefix — both headers are client-controlled and often omitted.

```bash
rg -ni 'referer|origin' --glob '*.{js,ts,py,java,cs,go,php}' | rg -i 'admin|allow|deny|guard|protect|internal'
```

```python
# VULN
if request.headers.get('Referer', '').startswith('https://app.example/admin'):
    return admin_action()
```

**SAFE**: server-side session/token role check independent of Referer/Origin.

### Case-Variant Route Bypass

**VULN**: guard checks literal `/admin` (case-sensitive) while the framework router matches `/Admin` case-insensitively, or a duplicate route is registered without `[Authorize]` / `requireRole`.

```bash
rg -n '["'"'"']/admin|startsWith\(["'"'"']/admin' --glob '*.{js,ts,py,java,cs,go,php}'
# Cross-check router caseSensitivity settings and duplicate route mounts
```

```csharp
// VULN: middleware checks lowercase only; ASP.NET routing is case-insensitive by default
if (!context.Request.Path.StartsWithSegments("/admin")) return;
// /Admin/users still reaches handler registered without [Authorize(Roles = "Admin")]
```

### Extension / Format Bypass

**VULN**: auth on `/user/1` but `/user/1.json`, `/user/1.html`, or a content-negotiation variant hits an unguarded static or API handler.

```javascript
// VULN: guard on exact path only
router.use('/user/:id', requireAuth);
app.get('/user/:id.json', exportUser);   // unguarded parallel mount
```

### Stale API Version Routes

**VULN**: `/api/v3/admin/*` has role guard; `/api/v1/admin/*` still mounted with identical handlers but no guard.

```bash
rg -n '(/v[0-9]+|api/v[0-9]+|router\.use|@(Get|Post|Request)Mapping)' --glob '*.{js,ts,py,java,cs,go,php}'
```

```java
// VULN: v3 protected, v1 legacy mount forgotten
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/api/v3/admin/users")
public List<User> listV3() { ... }

@GetMapping("/api/v1/admin/users")   // no @PreAuthorize
public List<User> listV1() { ... }
```

### Internal-IP Header Trust (Expanded)

Allow/deny or admin bypass keyed on client-spoofable IP headers beyond `X-Forwarded-For`.

**Headers**: `X-Real-IP`, `X-Client-IP`, `X-Custom-IP-Authorization`, `X-Originating-IP`, `Client-IP`, `True-Client-IP`, `Proxy-Client-IP`.

```bash
rg -ni 'x-real-ip|x-client-ip|x-custom-ip|x-originating-ip|client-ip|true-client-ip' --glob '*.{js,ts,py,java,cs,go,php}'
```

```python
# VULN: first matching header grants localhost admin
for hdr in ('True-Client-IP', 'X-Real-IP', 'X-Custom-IP-Authorization'):
    if request.headers.get(hdr) == '127.0.0.1':
        return admin_panel()
```

Cross-ref `trust_boundary.md` when spoofed IP crosses into session state; prefer `xff_spoofing` when the sole issue is IP derivation.

### Multi-Step Workflow State Skip

**VULN**: final execute/confirm endpoint performs the side effect without server-side proof that prior steps completed — no signed workflow token, server-side state machine, or nonce binding steps together. (Detailed step-up requirements: **Transaction Authorization (Step-Up)** above.)

```bash
rg -n '/execute|/confirm|finalize|complete' --glob '*.{py,js,java,php,cs}' | rg -v 'verify|step_up|workflow|pending|nonce'
```

```python
# VULN: direct POST to execute — no pending workflow record checked
@app.post('/transfer/execute')
def execute():
    transfer_repo.execute(request.json['amount'])
```

**SAFE**: server stores workflow state keyed to session/user; execute validates `workflow_id`, current step, and a server-signed nonce before side effect.

### Setup / installer / first-run flow reachable after install (leaked or non-expiring setup token)

**VULN**: a first-run setup/installer flow (create-admin, configure-database, seed-data) is gated only by a **setup token** that is (a) **not invalidated after setup completes** and/or (b) **exposed on an unauthenticated endpoint** — a `/api/session/properties`, `/settings`, `/status`, or HTML-embedded config blob that returns the live `setup-token`/`install_key`/`bootstrap_token`. An attacker reads the token from the public endpoint and replays the privileged setup endpoint (e.g. add a data source, create an admin, run an import) — often the highest-impact unauth path in the app because setup endpoints intentionally accept dangerous config (see the user-supplied JDBC-URL → RCE case in `sql_injection.md`). A refactor that deletes the "clear the token after setup" step silently re-opens this on all fresh installs.
- **SAST signals**: a `setup`/`install`/`onboarding` controller with **no auth filter** guarded by a token compared to a persisted value; that same token key emitted by a public properties/config/status handler; absence of a "setup complete → disable route / rotate token" transition. Grep: `rg -ni 'setup.?token|install.?(key|token)|bootstrap.?token|first.?run' ` and check whether the value is (1) returned by any unauthenticated endpoint and (2) ever invalidated.
- **SAFE**: make the setup token single-use and destroy it when setup finishes; permanently disable/route-404 setup endpoints once initialized (persisted "installed" flag checked server-side); never emit setup/bootstrap secrets from an unauthenticated properties/config endpoint.

---

## Secure Authorization Design

Architectural controls that reduce BFLA and escalation risk. Distinct from endpoint-level missing checks above — focus on policy shape and enforcement topology.

### Deny-by-Default & Single Enforcement Point

- Default posture: no allow rule matched → `403` (or generic `404` for existence hiding). Explicit allow only.
- **Single choke point**: every privileged action invokes one shared module (Policy engine, `Authorizer`, OPA/Cedar evaluator, Casbin enforcer) — not ad-hoc `if (user.isAdmin)` scattered per handler.
- **SAST signal**: same sensitive action guarded by copy-pasted role checks in multiple files instead of one imported policy call.
- **SAST signal**: handler performs sensitive work before any authorization call (check-after-use).

```python
# SECURE: explicit allows, deny fallback, centralized policy
def can_delete_user(actor, target_id):
    if policy.evaluate(actor, "user:delete", resource_id=target_id):
        return True
    raise PermissionDenied()  # no implicit allow
```

### ABAC / RBAC / ReBAC

| Model | Decision basis | Prefer when |
|-------|----------------|-------------|
| **RBAC** | Role membership (`hasRole('ADMIN')`) | Coarse, stable role sets |
| **ABAC** | Attributes (owner, tenant, clearance, resource tags) | Multi-tenant, context-dependent access |
| **ReBAC** | Relationships (owner-of, member-of, delegated-to) | Social/graph permissions (teams, sharing) |

- **Weak signal**: RBAC-only (`role == 'admin'`) on resources that need ownership/tenant scoping → horizontal + vertical escalation when roles are broad.
- **Strong signal**: policy predicate binds **actor + action + resource instance** (not action alone).
- **ReBAC signal**: access derived from `user.id == resource.owner_id` or graph lookup — not from client-supplied relationship flags.

```java
// SECURE (ABAC): attributes evaluated server-side
@PreAuthorize("@authz.can(actor, 'invoice:read', #invoiceId)")
public Invoice get(@PathVariable UUID invoiceId) { ... }
```

### Least Privilege & Separation of Duties

- Grant minimum scopes per role; flag default roles with write/admin permissions (`DEFAULT_ROLE = 'admin'`, seed data assigning `is_superuser=True`).
- **SoD signal**: one endpoint or user session can both **initiate** and **approve** the same sensitive workflow (wire transfer, role elevation, bulk export) with no second principal.
- **SAST signal**: permission constants like `'*'`, `'ALL'`, or overly broad resource wildcards in role definitions.

### Per-Request Re-Verification

- Authorization must run on **every** request (HTML, AJAX, API, WebSocket, background job triggered by user) — not once at login.
- **VULN**: session/cookie flag set at login (`session['authorized']=true`) skips subsequent checks.
- **VULN**: role cached in request context from stale token without DB/session revalidation after admin demotes user.
- **SAFE**: on role/permission change, invalidate sessions/tokens; middleware re-evaluates policy each call.

```javascript
// VULN: one-time gate — subsequent admin routes trust session bit
if (req.session.adminVerified) return next();
// SAFE: requireRole('admin') runs on every privileged route
```

### Client-Side Enforcement (UX Only)

- UI hiding admin nav/buttons is not authorization. **SAST signal**: frontend `if (user.role === 'admin')` with no corresponding server guard on the API the UI calls.
- **VULN**: API trusts client header mirroring UI state (`X-Admin-Mode: true`, `X-Requested-With` as auth substitute).
- **VULN — framework-internal / "internal" header trusted as a trust or identity marker**: a handler treats the presence of a header the *framework or gateway sets internally* — e.g. `x-middleware-subrequest`, `x-middleware-*`, `x-next-*`, or a custom `x-internal`/`x-trusted`/`x-from-gateway` — as proof the request is internal/authenticated. An external client can send the same header, so it is bypassable. **SAST signal**: a conditional reading such a header that then skips auth, returns privileged data, or marks the request "internal." **Safe**: strip framework-internal and `internal`/`trusted` headers at the trust boundary (edge/proxy/load balancer) on every inbound request, and re-verify authorization in the handler — never treat a client-settable header as proof of origin. (Same failure mode as the spoofable-IP-header trust above; it also defeats middleware-only auth — re-check authz in the handler, not only at the edge.)

---

## Transaction Authorization (Step-Up)

Sensitive operations require **separate** user confirmation beyond session login — privilege changes, large transfers, account recovery, bulk delete/export.

### When Required

Flag endpoints that mutate high-impact state without step-up: role/permission changes, password reset for others, financial transfers, API key creation, tenant-wide config.

### Design Requirements

- **WYSIWYS**: user confirms server-rendered canonical fields (amount, target account, action type) — not attacker-controlled display strings.
- **AuthN ≠ txn auth**: login password/SSO must not double as step-up credential; use distinct OTP, push approval, or hardware signature.
- **Unique per operation**: one-time challenge/nonce per transaction — replay of prior OTP rejected.
- **Time-limited**: challenge expires; delayed submission invalidates authorization.
- **Server-side canonical payload**: sign/hash transaction blob on server; client submits `confirmation_token` bound to that blob — not raw tamperable params.

```python
# VULN: sensitive action completes on session alone
def elevate_role(user_id, new_role):
    User.query.get(user_id).role = new_role

# SECURE: step-up + signed server payload
def elevate_role(user_id, new_role, confirmation_token):
    payload = step_up.verify(confirmation_token, expected_action="role:elevate", target=user_id)
    if payload["new_role"] != new_role:
        abort(400)  # tamper detected
    User.query.get(user_id).role = new_role
```

### State Machine & Anti-Tamper

- Enforce ordered steps: draft → review → confirm → execute. **VULN**: execute endpoint reachable without prior confirm step (direct POST to `/transfer/execute`).
- **VULN**: client can add/remove params (`skip_verification=true`, `auth_method=none`) that disable checks.
- **VULN**: transaction fields editable after challenge issued without invalidating authorization (TOCTOU).
- **SAFE**: modifying any signed field invalidates pending authorization and forces restart.
- **Method downgrade**: **VULN**: `auth_method` from client selects weakest verifier; **SAFE**: server policy fixes method by risk tier.

### Brute-Force & Execution Gate

- Failed step-up attempts throttle and reset entire flow (not just increment counter on same token).
- Final execute handler re-validates authorization record immediately before side effect — not only at flow start.

```java
// VULN: check once at start, execute later without re-verify
void executeTransfer(String txId) {
    transferRepo.execute(txId);  // no stepUpValid(txId) here
}
```

---

## Authorization Testing Signals

Static/recon indicators that authorization enforcement is untested or regressions will ship unnoticed.

### Matrix & Coverage Gaps

- **Signal**: no machine-readable authorization matrix (YAML/JSON/XML) mapping `{endpoint, role/attribute, allow|deny, expected_status}` alongside route definitions.
- **Signal**: integration tests exist for happy-path admin (`200`) but no paired negative case (regular user → `403`) for same route.
- **Signal**: test suite mints only admin tokens — no per-role token factory exercising deny paths.
- **Signal**: role-change or revocation scenarios untested (demoted user token still succeeds).

### Automated Test Patterns to Grep

```yaml
# SECURE: declarative matrix entry (fixture or test data)
- endpoint: DELETE /api/admin/users/{id}
  actor: user
  expect: 403
- endpoint: DELETE /api/admin/users/{id}
  actor: admin
  expect: 204
```

```python
# VULN (test gap): admin-only route tested only as admin
def test_delete_user():
    resp = client.delete("/admin/users/1", headers=admin_headers)
    assert resp.status_code == 204
# Missing: same call with user_headers → assert 403
```

### CI / Regression Indicators

- **Signal**: new privileged route merged without corresponding matrix row or negative test.
- **Signal**: authorization middleware excluded from test app bootstrap (tests hit handlers directly, bypassing production guard stack).
- **Signal**: `skip_before_action :verify_authorized`, `@Disabled` on security tests, or mock always returning `true` for policy checks.

---

## Python Source Detection Rules

### Flask missing decorators
- **VULN**: Admin route with no `@login_required` or role check:
  ```python
  @app.route('/admin/delete_user', methods=['POST'])
  def delete_user():
      user_id = request.form['user_id']
      User.query.filter_by(id=user_id).delete()
  ```
- **VULN**: `@app.route('/admin/...')` handler body has no `current_user.is_admin` check or `abort(403)`

### Client-supplied role
- **VULN**: `role = request.json.get('role')` then used to set permissions without server-side validation
- **VULN**: `user.role = request.form['role']` — role assigned directly from form input
- **VULN**: `is_admin = request.args.get('admin', False)` — admin flag from query string
- **SAFE**: Role fetched from database using authenticated user's ID: `user = db.query(User).get(current_user.id)`

### Django missing permission checks
- **VULN**: View missing `@permission_required` or `@staff_member_required` for admin operations
- **VULN**: `if request.user.is_authenticated:` only (no `is_staff` or `is_superuser` check) for admin action
- **SAFE**: `@permission_required('app.delete_user')`, `@staff_member_required`

### Horizontal → vertical escalation
- **VULN**: Only `user_id` validated, not ownership or role:
  ```python
  target_user = User.query.get(request.form['target_id'])
  target_user.is_admin = True
  ```

---

## JavaScript Source Detection Rules

### Express missing middleware
- **VULN**: Admin router/route without `isAdmin` or `requireRole` middleware:
  ```js
  app.delete('/admin/users/:id', (req, res) => { /* no auth check */ })
  ```
- **VULN**: Route handler reads role from request: `const role = req.body.role` then grants access
- **SAFE**: `router.use('/admin', requireAdmin)` — middleware applied to entire admin namespace

### JWT claims from client
- **VULN**: `const isAdmin = req.body.isAdmin` — client claims admin status
- **VULN**: `if (decoded.role === 'admin')` where `decoded` comes from untrusted token with unverified signature
- **SAFE**: Role read from verified JWT with fixed algorithm and server-side secret

### MongoDB / Mongoose
- **VULN**: `User.findByIdAndUpdate(req.body.userId, { role: req.body.role })` — role from client
- **SAFE**: Server looks up requesting user's role from DB before allowing the update

---

## PHP Source Detection Rules

### Session-based role bypass
- **VULN**: `$_SESSION['role'] = $_POST['role']` — session role set from POST without server validation
- **VULN**: `$_SESSION['is_admin'] = $_GET['admin']` — admin flag from query string
- **SAFE**: Role set only after DB lookup: `$_SESSION['role'] = $user['role']` from database query

### Missing authorization checks
- **VULN**: Admin function with no `checkAdmin()` or session role check:
  ```php
  function deleteUser($id) {
      $db->query("DELETE FROM users WHERE id = ?", [$id]);
  }
  ```
- **VULN**: `if ($_SESSION['logged_in'])` only — no role/admin check for privileged action

### Laravel / Symfony
- **VULN**: Route or controller method missing `middleware('admin')` or `$this->authorize(...)`
- **SAFE**: `$this->authorize('delete', $user)`, `Gate::allows('admin')`, `middleware('can:manage-users')`

---

## IDOR → Privilege Escalation Chain

Privilege escalation often occurs when an IDOR vulnerability allows accessing a higher-privileged user's resources or actions. Flag `privilege_escalation` in addition to `idor` when:

```python
# VULNERABLE: IDOR on user ID allows accessing admin account data
@app.route('/api/users/<int:user_id>/profile')
def get_profile(user_id):
    user = User.query.get(user_id)
    return jsonify(user.to_dict())   # no ownership check — accessing user_id=1 (admin) reveals admin data
# privilege_escalation: if admin profile contains credentials, tokens, or admin-only data
```

```java
// VULNERABLE: IDOR on account allows horizontal → vertical escalation
@GetMapping("/accounts/{accountId}/details")
public AccountDetails getDetails(@PathVariable Long accountId) {
    return accountService.findById(accountId);   // no principal ownership check
    // If accountId=1 is admin → returns admin details → privilege escalation
}
```

## Role/Permission Parameter Tampering

```python
# VULNERABLE: role passed in request body and trusted without server validation
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    user = User(
        username=data['username'],
        password=hash_password(data['password']),
        role=data.get('role', 'user')   # attacker supplies role='admin'
    )
    db.session.add(user)
```

```java
// VULNERABLE: user-controlled role assignment
@PostMapping("/api/users")
public User createUser(@RequestBody UserDTO dto) {
    User user = new User();
    user.setUsername(dto.getUsername());
    user.setRole(dto.getRole());   // role comes from request body — attacker supplies "ADMIN"
    return userRepository.save(user);
}
```

```js
// VULNERABLE: mass assignment allows role escalation in Node.js
app.put('/api/users/:id', authenticate, (req, res) => {
    User.findByIdAndUpdate(req.params.id, req.body, ...)   // req.body may include {role: 'admin'}
});
```

## JWT Claim Manipulation → Privilege Escalation

```python
# VULNERABLE: JWT payload trusted without server-side role validation
@app.route('/admin')
def admin_panel():
    token = request.headers.get('Authorization').split(' ')[1]
    payload = jwt.decode(token, SECRET, algorithms=['HS256'])
    if payload.get('role') == 'admin':    # role from JWT — if JWT forgeable, escalation possible
        return render_admin()

# VULNERABLE: alg=none bypass or weak secret → attacker forges JWT with role=admin
```

## Missing Function-Level Access Control

```python
# VULNERABLE: admin endpoints without role verification
@app.route('/admin/users')
@login_required    # only checks logged in, not admin role
def list_all_users():
    return jsonify([u.to_dict() for u in User.query.all()])

# SAFE:
@app.route('/admin/users')
@login_required
@requires_role('admin')
def list_all_users():
    ...
```

```java
// VULNERABLE: admin endpoint protected only by URL pattern, not method-level check
@GetMapping("/admin/deleteUser/{id}")
public ResponseEntity<?> deleteUser(@PathVariable Long id) {
    // No @PreAuthorize, no role check — any authenticated user can reach this
    userRepository.deleteById(id);
    return ResponseEntity.ok().build();
}

// SAFE: method-level security
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin/deleteUser/{id}")
public ResponseEntity<?> deleteUser(@PathVariable Long id) { ... }
```

## Insecure Direct Reference to Privileged Operations

```php
// VULNERABLE: action parameter determines privileged operation
$action = $_GET['action'];
if ($action === 'deleteUser') {
    // No admin check — any user can trigger admin actions by guessing action names
    delete_user($_GET['user_id']);
}

// VULNERABLE: hidden admin toggle via parameter
if ($_POST['is_admin'] == '1') {
    $user->setAdmin(true);   // client-side field controls server-side privilege
}
```

## Detection Rules

### TRUE POSITIVE: Privilege Escalation

- IDOR on user/account objects where accessing another user's record reveals elevated capabilities or admin account details → **CONFIRM** (`idor` + `privilege_escalation`)
- `role` or `is_admin` field accepted from request body/params without server-side authority validation → **CONFIRM**
- Admin endpoint reachable by any authenticated user (missing `@PreAuthorize`, `@Secured`, role decorator) → **CONFIRM**
- JWT with role claim where the role is trusted from the token payload without server-side cross-check → **CONFIRM** (especially if JWT secret is weak/default)
- Mass assignment (`req.body` or `request.json` passed directly to ORM update) where `role`/`admin` fields are not excluded → **CONFIRM**
- Sensitive mutation endpoint (role change, bulk delete, transfer) with no step-up/confirmation gate or server-bound authorization token → **CONFIRM**
- Client-supplied `skip_verification`, `auth_method`, or `confirmed` flag accepted to bypass step-up → **CONFIRM**
- Transaction execute handler with no re-validation of pending authorization at execution time (TOCTOU) → **CONFIRM**
- Authorization decision uses one-time session flag instead of per-request policy evaluation → **CONFIRM**
- Scattered inline role checks with no shared policy module for same resource type → **LIKELY** (maintainability/regression risk)
- RBAC-only guard on multi-tenant/owned resource with no owner/tenant attribute in predicate → **LIKELY** (pair with `idor`)
- Same principal can initiate and approve sensitive workflow with no SoD split → **CONFIRM**
- Integration tests cover privileged route success but omit deny case for lower-privilege actor → **LIKELY** (test gap — pair with BFLA finding on same route)
- Frontend role gate present; backing API handler lacks matching server authorization → **CONFIRM**
- Auth guard on `req.path` while routing honors `X-Original-URL` / `X-Rewrite-URL` / `X-Forwarded-Prefix` → **CONFIRM** (pair with `reverse_proxy_access_bypass.md`)
- Referer/Origin header used as access gate for privileged actions → **CONFIRM**
- Case-sensitive `/admin` guard with case-insensitive router or duplicate unguarded route → **CONFIRM**
- Format suffix (`.json`, `.html`) or stale `/v1` mount reaches privileged handler without guard on canonical path → **CONFIRM**
- Privileged access gated on spoofable IP headers (`X-Real-IP`, `True-Client-IP`, `X-Custom-IP-Authorization`, etc.) → **CONFIRM**
- Execute/confirm endpoint reachable without server-side proof prior workflow steps completed → **CONFIRM**

### FALSE POSITIVE: Not Privilege Escalation

- IDOR on non-sensitive data where all users have equal access (e.g., public posts, product listings) — **IDOR** only, not `privilege_escalation`
- Role check present but insufficiently strict (e.g., checks for any authenticated user) — flag as broken access control / `idor`, not `privilege_escalation` unless admin-level actions are reachable
- Admin role correctly enforced via `@PreAuthorize("hasRole('ADMIN')")` or equivalent — **SAFE**
- Reflection- or command-dispatch flaws such as dynamic `Class.forName(... + command + ...)` are not `privilege_escalation` by themselves; keep `unsafe_reflection` or `command_injection` unless the code also reaches an admin-only action or changes roles or permissions.
- `authentication`, `idor`, or generic broken-access-control findings should only be upgraded to `privilege_escalation` when a lower-privilege user can reach admin-only data, role changes, or privileged operations.
- In `vulhub`, representative Spring Security or auth-bypass CVE directories should preserve `privilege_escalation` when the exploit grants access to protected or admin routes by changing authentication state or bypassing route protection.

## Privilege Escalation as a Secondary / Companion Finding

Privilege escalation is frequently a **consequence** of another primary vulnerability. When analyzing code, always ask: "Does this vulnerability allow a lower-privileged user to gain higher-privileged access?" If yes, tag privilege escalation **in addition to** the primary vulnerability.

### Patterns That Almost Always Imply Privilege Escalation

1. **IDOR on user modification endpoints**: If an IDOR allows changing another user's password, role, or profile — and the target could be an admin — this is IDOR + privilege escalation.
   ```python
   # IDOR + privilege_escalation: change ANY user's password including admin
   @app.route('/change_password', methods=['POST'])
   def change_password():
       user_id = request.form['userId']  # attacker controls userId
       new_pass = request.form['password']
       User.query.get(user_id).password = hash(new_pass)
   ```

2. **JWT with weak/no verification**: If JWT signature is not verified (`verify=False`, `algorithms=['none']`, weak secret like `secret`), an attacker can forge tokens with `role=admin` → privilege escalation.
   ```python
   # jwt + privilege_escalation
   payload = jwt.decode(token, options={"verify_signature": False})
   ```

3. **X-Forwarded-For / X-Real-IP trust for access control**: If the application trusts client-supplied headers to determine admin access (e.g., "if IP == 127.0.0.1 then admin"), the header is spoofable → privilege escalation.
   ```python
   # privilege_escalation via header spoofing
   if request.headers.get('X-Forwarded-For') == '127.0.0.1':
       return admin_panel()
   ```

4. **Mass assignment allowing role/admin field**: When user-submitted form data or JSON directly sets `is_admin`, `role`, or permission fields without server-side filtering.
   ```python
   # privilege_escalation via mass assignment
   user.update(**request.json)  # request.json could include {"is_admin": true}
   ```

5. **Commented-out or missing authorization checks**: When a route handler has authorization logic commented out, deleted, or never implemented — especially on endpoints that modify user roles or access sensitive data.

6. **Session/cookie manipulation for role**: When role or admin status is stored in a client-side cookie (even if encoded/encrypted with weak crypto) and can be tampered with.

7. **Type juggling / loose comparison on auth**: PHP `==` comparisons or `strcmp()` returning NULL on type confusion, bypassing password checks to gain admin access.
   ```php
   // privilege_escalation via type juggling
   if (strcmp($_POST['password'], $admin_password) == 0) { // NULL == 0 is true
       $_SESSION['is_admin'] = true;
   }
   ```

8. **Hardcoded 2FA / verification codes**: When 2FA or verification codes are hardcoded (e.g., `if code == '1234'`), allowing bypass of multi-factor auth to reach admin functions.

### When NOT to Tag Privilege Escalation
- IDOR that only reads non-sensitive, equal-privilege data (e.g., viewing another regular user's public profile)
- Information disclosure that reveals data but does not grant elevated access
- XSS or CSRF alone (unless the XSS/CSRF specifically targets admin functionality)
- Default credentials alone — tag as `default_credentials`; only add `privilege_escalation` if the credentials grant admin-level access AND there is a separate mechanism (not just "login as admin with known password")

## Sources, Sinks & Sanitizers

Commonly affected languages: Java, JavaScript, C#, Go, Ruby. No dedicated vertical privilege-escalation rules in Python or Rust — use manual patterns below.

### Source → Sink Pattern (`ConditionalBypass`)

- **Source**: Remote/user-controlled input — cookies, request parameters, headers.
- **Sink**: Condition expression guarding a **sensitive method** (authentication, authorization, password change).
- **Sanitizer**: Validation against a fixed server-side allowlist; condition uses only server-derived data (DB lookup, verified session).

**VULN (Java)**: `if (cookie.get("loggedIn").equals("true")) { authenticate(); }` — auth gated on user-controlled cookie.
**SAFE (Java)**: `if (securityDb.isAuthenticated(sessionId)) { ... }`.

**VULN (JS)**: `if (req.cookies.skipAuth === '1') return next();` before protected handler.
**SAFE (JS)**: Auth decision based on verified server session only.

### Source → Sink Pattern (`TaintedPermissionsCheck`)

- **Source**: User-controlled string used to name the permission being checked.
- **Sink**: Shiro `subject.isPermitted(userSuppliedPermission)` or equivalent dynamic permission check.
- **Sanitizer**: Fixed permission string literal in the check — not derived from request input.

**VULN**: `subject.isPermitted(whatDoTheyWantToDo)` where `whatDoTheyWantToDo` comes from request.
**SAFE**: `subject.isPermitted("account:read:" + accountId)` with fixed action prefix and validated ID.

### What to Look For (`MissingAccessControl` — C#)

Flags WebForms/MVC action methods performing sensitive operations (edit, delete, admin pages) without `[Authorize]`, `User.IsInRole`, or `<authorization>` in Web.config.

**VULN**: Admin delete action with no authorization attribute.
**SAFE**: `[Authorize(Roles = "Admin")]` on the action method.

### What to Look For (`PamAuthBypass` — Go)

Flags login flows calling `pam.Authenticate` without a subsequent `pam.AcctMgmt` — expired/disabled accounts may still pass credential check.

**VULN**: Only `pam.Authenticate(t)` — no account-status verification.
**SAFE**: `pam.Authenticate(t)` followed by `pam.AcctMgmt(t, 0)`.
