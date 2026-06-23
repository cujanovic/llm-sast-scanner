---
name: reverse_proxy_access_bypass
description: Reverse-proxy access bypass — authorization applied to a different path representation than the one the router or upstream honors (rewrite/forward headers, normalization mismatch, stale API versions, proxy config gaps, Referer/Origin gates) (CWE-863 / CWE-289 / CWE-436)
---

# Reverse-Proxy Access Bypass (CWE-863 / CWE-289 / CWE-436)

Authorization fails when the **path the access-control layer evaluates** differs from the **path the router, framework, or upstream actually serves**. A reverse proxy, IIS rewrite module, or edge middleware may normalize, decode, strip a prefix, or route on rewrite headers (`X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Prefix`) while a separate auth guard matches the raw, undecoded, or differently-cased path. The attacker reaches a protected handler through an alternate representation the guard never saw.

## What It Is / Is Not

- **Is**: auth middleware, gateway policy, or proxy `location`/`allow` block keyed on one path form while routing/upstream selection uses another — including trust of client-supplied rewrite/forward headers for authz, normalization mismatches (`..;/`, `%2e%2e`, `%2f`, `;/`, trailing dot, case variants, format suffixes, double slashes), stale parallel API mounts (`/v1` without the guard present on `/v3`), and Referer/Origin-based gates.
- **Is not**: generic missing role check on the same canonical path (`privilege_escalation.md` — BFLA when path is agreed); object-level IDOR (`idor.md`); path traversal to read arbitrary files (`path_traversal_lfi_rfi.md` — filesystem escape, not ACL desync); HTTP request smuggling/desync (`http_request_smuggling.md` — byte-level framing); spoofing identity headers without a path split (`trust_boundary.md`).
- **Highest signal** when repo contains both (a) an auth guard on `req.path`/`request.uri`/`HttpContext.Request.Path` and (b) routing/proxy logic that reads `x-original-url`, `x-rewrite-url`, `x-forwarded-prefix`, or applies different normalization than the guard.

## Source -> Sink Pattern

- **Source**: raw request path/URI as seen by auth middleware (`req.path`, `req.url`, `request.getRequestURI()`, `HttpContext.Request.Path`, nginx `$request_uri` vs `$uri`), client-influenced rewrite headers, Referer/Origin, or a stale route mount.
- **Sink**: protected handler, admin API, static file under `alias`, or upstream selected by a **different** normalized/decoded/prefixed path — the request passes routing but skipped the guard's representation.
- **Aggravating chain**: auth enforced only at edge middleware (Next.js `middleware.ts`, nginx `location` with `auth_request`) with no handler-level re-check; proxy config where protected prefix does not cover encoded/normalized variants.

## Recon Indicators (Grep)

```bash
# Rewrite / forward headers used for routing or path reconstruction (then check if auth uses a different field)
rg -ni 'x-original-url|x-rewrite-url|x-forwarded-prefix|x-forwarded-uri|x-original-path' --glob '*.{js,ts,jsx,tsx,java,kt,cs,go,py,php,conf,xml}'
# Auth guard on path/URI (compare normalization with router)
rg -n 'req\.path|req\.url|request\.uri|getRequestURI|Request\.Path|request\.path' --glob '*.{js,ts,py,java,cs,go,php}'
# Path normalization before routing vs before auth (split pipelines)
rg -n 'normalizePath|path\.normalize|decodeURI|decodeURIComponent|\.replace\(.*/|\.toLowerCase\(\)' --glob '*.{js,ts,py,java,cs,go}'
# Referer / Origin used as access gate
rg -ni 'referer|origin' --glob '*.{js,ts,py,java,cs,go,php}' | rg -i 'admin|auth|allow|deny|guard|protect|internal'
# Parallel / versioned API mounts (stale handler without guard)
rg -n '(/v[0-9]+|api/v[0-9]+|router\.(use|get|post)|@(Get|Post|Request)Mapping)' --glob '*.{js,ts,py,java,cs,go,php}'
# Reverse-proxy config: separate auth location vs content location; alias/try_files
rg -n 'location\s|auth_request|allow\s|deny\s|alias\s|try_files|proxy_pass|RewriteRule|rewrite\s' --glob '*.{conf,nginx,xml,config}'
# Case-sensitive admin/privileged prefix checks
rg -n '["'"'"']/admin|["'"'"']/Admin|["'"'"']/internal|startsWith\(["'"'"']/admin' --glob '*.{js,ts,py,java,cs,go,php}'
```

For each hit, trace **two pipelines**: (1) what string the auth gate matches, and (2) what string the router/proxy/upstream uses. Flag when they diverge without an explicit shared canonicalization step applied **before** both.

## Vulnerable Conditions

- Auth middleware checks `req.path === '/admin'` but the framework router honors `req.headers['x-original-url']` or `x-forwarded-prefix` to select the handler.
- Guard matches literal path; router/proxy applies URL decoding, slash collapsing, semicolon stripping, trailing-dot removal, or case folding — attacker uses `%2f`, `%2e%2e`, `..;/`, `;/`, `/Admin`, `/user/1.json`, `//admin//`.
- `/api/v3/admin/*` has `@PreAuthorize` / `requireRole('admin')`; `/api/v1/admin/*` still mounted with identical handlers but no guard.
- nginx: `location /admin/ { auth_request ...; }` protects `/admin/` but `location ~ /admin` or `alias`/`try_files` serves `/static../admin/` or encoded variants without the auth subrequest (cross-ref `nginx_security.md`, `path_traversal_lfi_rfi.md`).
- Apache/IIS `web.config` rewrite sends external `/public/foo` to internal `/admin/foo` while app auth only covers `/public`.
- Access decision keyed on `Referer`/`Origin` containing `/admin` or `https://trusted.example` — attacker omits header or supplies arbitrary value; not a substitute for server-side authz.
- Next.js/edge: authorization **only** in `middleware.ts` matcher; internal subrequest or alternate path representation reaches the route handler unchecked (`trust_boundary.md`).

## Vulnerable vs Safe code examples

### Express — auth on `req.path`, routing trusts rewrite header

```javascript
// VULN — guard sees stripped path; custom router uses x-original-url for handler selection
function adminGuard(req, res, next) {
  if (!req.path.startsWith('/admin')) return next();
  if (!req.session.isAdmin) return res.sendStatus(403);
  next();
}
app.use(adminGuard);
app.use((req, res, next) => {
  const routed = req.headers['x-original-url'] || req.path;   // client can set header
  if (routed.startsWith('/admin')) return adminRouter(req, res, next);
  next();
});

// SAFE — one canonical path; ignore client rewrite headers for authz; re-check in handler
function canonicalPath(req) {
  const raw = req.path || '/';
  return decodeURIComponent(raw).replace(/\/+/g, '/').replace(/\/\.\//g, '/').toLowerCase();
}
function adminGuard(req, res, next) {
  const p = canonicalPath(req);
  if (!p.startsWith('/admin')) return next();
  if (!req.session?.authenticated || !req.session.isAdmin) return res.sendStatus(403);
  next();
}
app.use(adminGuard);
app.use('/admin', adminRouter);   // same prefix; handler also verifies role
```

### Next.js — middleware-only auth

```typescript
// VULN — only middleware checks path; matcher misses encoded/case variants; handler trusts edge
// middleware.ts
export function middleware(req: NextRequest) {
  if (req.nextUrl.pathname.startsWith('/admin') && !req.cookies.get('session')) {
    return NextResponse.redirect(new URL('/login', req.url));
  }
}
export const config = { matcher: ['/admin/:path*'] };   // misses /Admin, /admin%2f, /api/../admin

// SAFE — normalize in middleware; enforce again in route handler / server action
const norm = (p: string) => decodeURIComponent(p).replace(/\/+/g, '/').toLowerCase();
export function middleware(req: NextRequest) {
  if (!norm(req.nextUrl.pathname).startsWith('/admin')) return;
  const session = await verifySession(req.cookies);      // server-verified token
  if (!session?.roles?.includes('admin')) return NextResponse.json({}, { status: 403 });
}
// app/admin/page.tsx — duplicate check; never rely on middleware alone
```

### Spring — parallel API version without guard

```java
// VULN — v1 admin endpoint still live, v3 has @PreAuthorize
@RestController
@RequestMapping("/api/v1/admin")
public class AdminV1Controller {
    @DeleteMapping("/users/{id}")
    public void deleteUser(@PathVariable long id) { ... }   // no @PreAuthorize
}

// SAFE — remove stale mount or apply identical auth to every version prefix
@RestController
@RequestMapping("/api/v1/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminV1Controller { ... }
```

### Referer-based gate

```python
# VULN — Referer treated as proof of authorization
def admin_panel(request):
    ref = request.META.get('HTTP_REFERER', '')
    if '/admin' not in ref:
        return HttpResponseForbidden()
    return render(request, 'admin.html')

# SAFE — session/token role check regardless of Referer
def admin_panel(request):
    if not request.user.is_authenticated or not request.user.is_staff:
        return HttpResponseForbidden()
    return render(request, 'admin.html')
```

### nginx — auth location does not cover alias traversal variant

```nginx
# VULN — auth only on exact prefix; alias traversal reaches files without auth_request
location /private/ {
    auth_request /auth;
    alias /var/www/private/;
}
location /static/ {
    alias /var/www/;    # GET /static../private/secret → no auth_request
}

# SAFE — consistent prefix + trailing slash on alias; deny traversal; auth on all paths to sensitive root
location /private/ {
    auth_request /auth;
    alias /var/www/private/;
}
location /static/ {
    alias /var/www/static/;   # matching slashes; no escape to /private
}
```

## Safe Patterns

- **Canonicalize once, early** — URL-decode, collapse slashes, resolve `.`/`..` segments (or reject ambiguous forms), apply consistent case policy, strip matrix/semicolon params — then run auth **and** routing on the same result.
- **Never trust client rewrite/forward headers for authz** — if `X-Original-URL` / `X-Rewrite-URL` / `X-Forwarded-Prefix` are used for routing, strip them at the trust boundary from external requests; derive path from server-controlled variables only.
- **Defense in depth** — edge/middleware gate **plus** handler-level `@PreAuthorize` / `requireRole` / explicit role check on every sensitive action.
- **Deny-by-default route groups** — mount all `/admin` (and all API versions) under one protected router group; delete or lock down stale version prefixes.
- **Proxy config parity** — every `location`/`alias`/`try_files` path to sensitive content must pass the same auth subrequest; encoded and normalized forms must not reach upstream without the guard (see `nginx_security.md`).
- **No Referer/Origin as authz** — use server-verified session or token; optional Origin check is CSRF defense (`csrf.md`), not access control.

## Severity / Triage

- **Critical**: bypass reaches admin/privileged mutation or mass data read (user deletion, config, secrets) via path/header desync.
- **High**: bypass of authenticated-only API or internal route reachable from the public internet through normalization or stale version mount.
- **Medium**: partial bypass (read lower-sensitivity resource) requiring specific proxy stack or uncommon encoding.
- **Low/Info**: normalization gap exists but handler re-checks role on the canonical path; defense-in-depth gap only.
- **False positive path**: auth and router provably share one canonicalization function called before both; rewrite headers stripped at edge and unused in app routing.

## Common False Alarms

- Auth and routing both use the same framework-provided canonical path (`req.originalUrl` after framework normalization, Spring `request.getServletPath()` + consistent context path) with no alternate header-based router.
- `X-Forwarded-Prefix` set only by a trusted edge proxy, stripped from external clients, and used for link generation — not for authz decisions.
- Referer checked **in addition to** session auth for CSRF on a state-changing POST, not as the sole gate.
- Case-insensitive match intentionally applied in both middleware and router (`toLowerCase()` in shared helper).
- Stale `/v1` route returns `410 Gone` or redirects to guarded `/v3` with no handler logic.

## Cross-References

- `privilege_escalation.md` — missing role check when path representation is agreed; BFLA and middleware-order issues.
- `trust_boundary.md` — client-supplied headers trusted as identity or internal-origin markers; middleware-only auth.
- `nginx_security.md` — `location`/`alias`/`try_files`/`auth_request` misconfiguration, `merge_slashes`, path confusion at the edge.
- `path_traversal_lfi_rfi.md` — filesystem escape via alias/normalization (often chained with proxy ACL bypass).
- `http_request_smuggling.md` — byte-level front/back desync (distinct from path-string mismatch but similar impact).
- `web_cache_deception.md` — path-suffix/normalization at CDN diverging from origin auth.
- `client_side_path_traversal.md` — frontend path decoding desync (client-side cousin of server path/auth mismatch).

## Core Principle

Authorization must evaluate the **same canonical path** the router and upstream will act on. Normalize and decode before the access decision, never trust client rewrite or forward headers for authz, enforce privileges again at the handler, and configure the reverse proxy so every encoded, cased, and versioned variant of a protected prefix passes the identical gate — or is denied by default.
