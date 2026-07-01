---
name: reverse_proxy_access_bypass
description: Reverse-proxy access bypass — authorization applied to a different path representation than the one the router or upstream honors (rewrite/forward headers, normalization mismatch, stale API versions, proxy config gaps, Referer/Origin gates) (CWE-863 / CWE-289 / CWE-436)
---

# Reverse-Proxy Access Bypass (CWE-863 / CWE-289 / CWE-436)

Authorization fails when the **path the access-control layer evaluates** differs from the **path the router, framework, or upstream actually serves**. A reverse proxy, IIS rewrite module, or edge middleware may normalize, decode, strip a prefix, or route on rewrite headers (`X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Prefix`) while a separate auth guard matches the raw, undecoded, or differently-cased path. The attacker reaches a protected handler through an alternate representation the guard never saw.

## What It Is / Is Not

- **Is**: auth middleware, gateway policy, or proxy `location`/`allow` block keyed on one path form while routing/upstream selection uses another — including trust of client-supplied rewrite/forward headers for authz, normalization mismatches (`..;/`, `%2e%2e`, `%2f`, `;/`, `#`-fragment stripping, trailing dot, case variants, format suffixes, double slashes), stale parallel API mounts (`/v1` without the guard present on `/v3`), and Referer/Origin-based gates.
- **Is not**: generic missing role check on the same canonical path (`privilege_escalation.md` — BFLA when path is agreed); object-level IDOR (`idor.md`); path traversal to read arbitrary files (`path_traversal_lfi_rfi.md` — filesystem escape, not ACL desync); HTTP request smuggling/desync (`smuggling_desync.md` — byte-level framing); spoofing identity headers without a path split (`trust_boundary.md`).
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
# Non-nginx proxy/cache config: ACL matched on raw request URI (bypass via case/slash/encoding)
rg -n 'acl\s+\w+\s+(path_beg|path_dir|path_end|path|url_beg|url_dec)' --glob '*.{cfg,conf}'        # HAProxy/Nuster
rg -n 'req\.url\s*[~=]|req\.http\.host\s*==|return\s*\(synth' --glob '*.vcl'                        # Varnish VCL
rg -ni 'PathPrefix|ReplacePath(Regex)?|AddPrefix|forwardedHeaders|X-Forwarded-' --glob '*.{toml,yml,yaml}'  # Traefik
rg -n 'RewriteCond[^\n]*REQUEST_URI|AllowEncodedSlashes|ProxyPassMatch|ProxyPass\s' --glob '*.{conf,htaccess}'  # Apache httpd
rg -n 'respond\s+/|not\s*\{\s*path|@\w+\s*\{|strip_prefix|handle_path|header_up\s+Host' --glob 'Caddyfile*'    # Caddy matchers / strip_prefix / Host fwd
rg -n 'normalize_path|merge_slashes|path_with_escaped_slashes_action|headers_with_underscores_action' --glob '*.{yaml,yml}'  # Envoy path-normalization knobs (flag when absent/off)
# Case-sensitive admin/privileged prefix checks
rg -n '["'"'"']/admin|["'"'"']/Admin|["'"'"']/internal|startsWith\(["'"'"']/admin' --glob '*.{js,ts,py,java,cs,go,php}'
# Security/routing regex run against the FULL url (incl. query) instead of pathname
rg -n '\.(test|match|exec)\(\s*(req\.url|url|request\.url|fullUrl|originalUrl)\b' --glob '*.{js,ts,mjs}'
# Path equality/prefix guards that can desync from the parser-normalized route
rg -n '(pathname|path)\s*===|pathname\.(startsWith|includes)\(' --glob '*.{js,ts,mjs}'
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
- **Security/routing check matched against the full URL string (query/hash included) instead of the pathname**: a regex/`startsWith`/`.includes` evaluated on `req.url`/the whole URL rather than the parsed `pathname` lets an attacker satisfy (or evade) it via the query or fragment — e.g. a check `/_internal\.json(\?|$)/.test(url)` is passed by `/public?x=/_internal.json`, and `#/_internal.json` (the fragment is client-only and must never reach a server-side decision). Same class: an internal/data route gated by a pattern run on the URL rather than the route the router resolves.
- **Access check reads a `pathname` shaped by URL-parser edge cases the router later re-normalizes**: a `pathname === "/admin"` (or `startsWith("/admin")`) guard is bypassed when the value reaching the guard lacks the leading slash or differs by decoding, but the router/framework normalizes it back. Two concrete shapes: (a) WHATWG parsing of a **non-special scheme** (`x:admin?`) yields `pathname` `admin` (no `/`) → fails `=== "/admin"`, but a downstream `prependForwardSlash`/router matcher turns it into `/admin`; (b) the guard compares a **decoded** path while `url.pathname` is still encoded (or vice-versa: `/admin%2f..` , one URL-encoded character), so the two representations diverge. When the **scheme itself is attacker-influenced** (e.g. via `X-Forwarded-Proto` feeding `new URL(...)`, see `ssrf.md`), the whole parser state — and thus `pathname` — is controllable.
- **Proxy/cache ACL matched on the raw, un-decoded, un-normalized request URI** (HAProxy `acl … path_beg`, Varnish VCL `req.url ~`, Traefik prefix matchers, Apache `RewriteCond %{REQUEST_URI}`): because these stacks match before the origin decodes/normalizes, the same allow/deny prefix is evaded by **case** (`/Admin`), **extra or leading slashes** (`//admin`, `/asd/..///../admin`), or **percent-encoding** (`/%61dmin`). The mirror-image bug is a converter that *adds* tolerance — HAProxy `path_beg,url_dec /log` then matches any trailing-symbol variant (`/log/`, `/log%00`) the origin still routes to `/log`. Same root cause as the normalization-mismatch bullet above, but expressed in proxy config rather than app code.
- **Caddy named-matcher allow/deny keyed on a path prefix** (`@m { not { path /blocked* } }`, `respond /secret/* 403`, `handle /admin/*`): Caddy matches the decoded but **prefix-shaped** path, so a deny like `not path /blocked*` or `respond /secret/*` is evaded by a representation the upstream re-normalizes back (case, `..`, extra segments), and `uri strip_prefix` / `handle_path` rewrites the path *after* the matcher ran — the post-strip path can differ from what was authorized. Also flag `header_up Host {host}` / `header_up X-Forwarded-* {…}` that forward the **client** Host/forwarded values into the upstream.
- **Envoy/Istio route match without path normalization enabled**: when `normalize_path`, `merge_slashes`, and `path_with_escaped_slashes_action` are **absent or off** on the `HttpConnectionManager`, Envoy routes (and RBAC `path`/`prefix` matchers) act on the raw path while the upstream normalizes — `//admin`, `/a/../admin`, `/%2e%2e/admin`, `/admin%2f..` bypass the route/authz rule. The lab's safe baseline sets all three plus `headers_with_underscores_action: REJECT_REQUEST`; their absence is the SAST signal (cross-ref `nginx_security.md` `merge_slashes`).
- **Query-parameter smuggling via parser differential (Go `;` ParseThru class)**: an edge gate reads a parameter one way while the upstream re-parses the raw query differently, so `?role=user;role=admin` (or `&`-vs-`;` delimiter, duplicate keys) passes the edge as `user` but resolves to `admin` at the origin. In Go specifically, `url.Values` from `r.URL.Query()` **silently ignores** the error `ParseQuery` raises on `;`, and `httputil.ReverseProxy` forwards the original `RawQuery` untouched — so a gateway on a new Go validating `?role` and a backend on old Go (or a framework that still splits on `;`) desync. **Recon**: `rg -n 'httputil\.(NewSingleHostReverseProxy|ReverseProxy)|r\.Out\.URL\s*=\s*r\.In\.URL' --glob '*.go'`; `rg -n '\.Query\(\)|ParseQuery|RawQuery' --glob '*.go' | rg -i 'role|admin|auth|scope|tenant|allow'`. **SAFE**: canonicalize/re-encode the query once (drop `;` or treat it as a literal), validate the *same* parsed representation the upstream will use, and pin a single value per security-relevant key.
- **HTTP header-name normalization desync for auth identity (underscore ⇄ hyphen, duplicate concatenation)**: a proxy injects/strips an identity header on its **canonical** name while the origin's runtime maps a *different* spelling to the same value, so the client smuggles identity past the gate. Apache `mod_proxy` forwards `Client_Verified`/`X_User` (underscores) and WSGI/CGI/PHP fold `Foo-Bar`, `Foo_Bar`, and `HTTP_FOO_BAR` together; nginx `underscores_in_headers on` re-enables underscore headers; an `RequestHeader unset X-User` placed **only inside a `<Location>`** misses other paths. Duplicate same-named headers may be **concatenated** (proxy value + client value), so a suffix check like `value.endsWith('@corp.com')` is satisfied by `attacker@evil.com, real@corp.com`. **Recon**: `rg -n 'underscores_in_headers\s+on|RequestHeader\s+(set|unset)' --glob '*.{conf,xml}'`; `rg -n "headers?\.get\(['\"][^'\"]*[-_][^'\"]*['\"]\)|HTTP_[A-Z_]+|SSL_CLIENT|CLIENT.?VERIFIED|Remote-User" --glob '*.{py,php,js,ts,java}'`; suffix-only identity checks `rg -n '\.(endsWith|endswith)\(' | rg -i 'host|email|user|@'`. **SAFE**: strip *all* inbound spellings of identity headers at the trust boundary (VirtualHost root, not per-`Location`), forbid underscore headers, and compare identity by exact equality on a single normalized header, never a suffix on a possibly-concatenated value (cross-ref `trust_boundary.md`).
- **Server-side path-parameter (`;` matrix) stripping vs edge prefix ACL**: backends that honor matrix/path parameters strip everything after `;` from the routed path, so `/admin;x=1` (and `/path;/../admin`) routes to `/admin` at the origin while the edge prefix/regex ACL sees a different string. Tomcat/Jetty/WebLogic do this by default; Spring MVC does when `setUseSemicolonContent(true)` (or the property is left at a permissive default for the version). **Recon**: `rg -n 'setUseSemicolonContent\s*\(\s*true\s*\)|removeSemicolonContent|UrlPathHelper' --glob '*.{java,kt}'`; pair with any edge ACL matching a raw URI. **SAFE**: disable matrix-parameter content (`setRemoveSemicolonContent(true)` / framework default-deny), and authorize on the normalized resolved path, not a raw-URI prefix (cross-ref `path_traversal_lfi_rfi.md`).
- **CDN-enforced control the origin doesn't re-verify (direct-to-origin bypass) + load-balancer rule-order shadowing** (AWS-detectable in IaC): when access control (geo-restriction / WAF / auth) lives **only at the CDN** (CloudFront) but the origin (ALB/EC2) is **publicly reachable and does not verify a secret header the CDN injects**, an attacker hits the origin's DNS/IP directly and bypasses every edge control. Terraform signals: `aws_cloudfront_distribution` with `geo_restriction`/WAF but **no origin `custom_header`** (and no origin-side rule checking it), plus the origin security group open to `0.0.0.0/0`; also `routing.http.xff_header_processing.mode = "preserve"` (client `X-Forwarded-For` trusted downstream). Companion misconfig — **ALB listener-rule priority inversion**: `aws_lb_listener_rule`s are evaluated **lowest `priority` number first**, so a broad `path_pattern = ["/*"]` `forward` rule at priority 20 **shadows** an `authenticate-oidc` rule on `/admin/*` at priority 30 and the auth action never runs. Third pattern — **multi-front-door / shared-target-group bypass**: the same `aws_lb_target_group` (or the same backend instances) is registered behind **more than one** listener/load-balancer, but a restrictive `condition` — a `source_ip` allowlist, `authenticate-oidc`/`authenticate-cognito`, or a `host_header` gate — is present on only **one** of them, so the backend stays reachable through the weaker route where that condition is absent (the IaC analogue of the stale parallel-mount bug above). Flag a target group wired to multiple listeners/LBs whose `condition` blocks differ, and any `source_ip`/`host_header`/auth condition enforced on some paths but not every route to the same TG. **SAFE**: verify a CDN-injected secret header at the origin (or use VPC-origin / PrivateLink so the origin isn't public); order listener rules so specific auth rules out-prioritize catch-alls; apply the **same** `source_ip`/auth/`host_header` conditions on every listener that reaches a shared target group; lock the origin SG to the CDN's managed prefix list.

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

### HAProxy / Varnish / Traefik / Apache — config-level ACL & routing bypass

Non-nginx proxies match ACLs on the **raw** request URI (no decode/normalize before the rule), so the prefix guard is evaded by case, slash, or encoding variants the origin still routes to the protected path.

```haproxy
# VULN — path_beg on raw URI: bypassed by //admin, /Admin, /%61dmin
acl restricted path_beg /admin
http-request deny if restricted
# (and the converter pitfall) — url_dec widens the match to /log/, /log%00, …
acl logs path_beg,url_dec /log
http-request deny if logs

# SAFE — lowercase + collapse slashes + url-decode ONCE, anchor, deny-by-default
http-request set-var(txn.p) path,url_dec,lower
acl restricted var(txn.p) -m beg /admin/
http-request deny unless { var(txn.p) -m beg /public/ }   # allowlist, not blocklist
```

```vcl
# VULN — Varnish VCL blacklist on raw req.url: bypassed by POST //wp-login.php or /../admin/
sub vcl_recv {
  if (req.url ~ "^/wp-admin" || req.url ~ "^/wp-login.php$") { return (synth(403)); }
}

# SAFE — normalize (lowercase + std.querysort/clean) before matching; prefer positive routing
import std;
sub vcl_recv {
  set req.url = std.tolower(req.url);
  if (req.url ~ "^/+wp-(admin|login)") { return (synth(403)); }  # tolerate leading slashes
}
```

```yaml
# Traefik (VULN) — prefix matcher + client-overridable X-Forwarded-* (1.x forwards client values)
# A client sends X-Forwarded-Host/Proto/Port/X-Real-Ip and overrides the proxy's values;
# an IP/host allowlist or link-building that trusts them is bypassed.
# (dynamic config)
http:
  routers:
    admin:
      rule: "PathPrefix(`/admin`)"          # /Admin, //admin, /%61dmin reach the backend
# SAFE — forwardedHeaders is an ENTRYPOINT (static) setting, not a middleware: restrict who may
# set X-Forwarded-*, then re-check authz in the app on a canonical path.
# (static config)
entryPoints:
  websecure:
    address: ":443"
    forwardedHeaders:
      insecure: false
      trustedIPs: ["10.0.0.0/8"]            # only trusted proxies may set X-Forwarded-*
```

```apache
# VULN — RewriteCond on raw %{REQUEST_URI}: bypassed by multi-slash ..///..
RewriteCond %{REQUEST_URI} ^/neighborhood/[^/]+/feed$ [NC]
RewriteRule ^.*$ - [F,L]

# SAFE — authorize on the resolved resource, deny-by-default, and reject encoded slashes
AllowEncodedSlashes Off
<Location "/neighborhood/">
    Require valid-user            # enforce on the location, not a raw-URI regex
</Location>
```

```caddy
# Caddyfile (VULN) — blacklist matcher + post-match strip_prefix; Host forwarded from client
@notblocked {
    not { path /blocked* }       # /Blocked, /blocked%2f.., /x/../blocked evade the deny
}
reverse_proxy @notblocked backend:9999 {
    header_up Host {host}        # forwards the CLIENT Host to upstream
}
route /admin/* {
    uri strip_prefix /admin      # path the upstream sees is rewritten AFTER any matcher
    reverse_proxy backend:9999
}

# SAFE — allowlist exact protected handling, pin the upstream Host, authorize at the app too
handle /admin/* {
    forward_auth authsvc:9000 { uri /verify }   # auth runs on the matched, normalized path
    reverse_proxy backend:9999 {
        header_up Host backend                  # fixed upstream authority, not {host}
    }
}
```

```yaml
# Envoy (VULN) — route/RBAC prefix match with normalization OFF (raw path reaches matcher)
http_connection_manager:
  route_config: { virtual_hosts: [{ routes: [{ match: { prefix: "/admin" }, ... }] }] }
  # normalize_path / merge_slashes / path_with_escaped_slashes_action all unset → //admin, /a/../admin bypass

# SAFE — normalize before routing & RBAC so matcher and upstream agree
http_connection_manager:
  normalize_path: true
  merge_slashes: true
  path_with_escaped_slashes_action: UNESCAPE_AND_REDIRECT
  common_http_protocol_options: { headers_with_underscores_action: REJECT_REQUEST }
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
- `smuggling_desync.md` — byte-level front/back desync (distinct from path-string mismatch but similar impact).
- `web_cache_deception.md` — path-suffix/normalization at CDN diverging from origin auth.
- `client_side_path_traversal.md` — frontend path decoding desync (client-side cousin of server path/auth mismatch).
- `ssrf.md` — attacker-controlled `X-Forwarded-Proto`/`Host` feeding `new URL(...)` controls the parser state (and thus `pathname`) used by the access check; also Apache `ProxyPass` without a trailing slash → upstream-authority injection (`/@evil.com/`).

## Core Principle

Authorization must evaluate the **same canonical path** the router and upstream will act on. Normalize and decode before the access decision, never trust client rewrite or forward headers for authz, enforce privileges again at the handler, and configure the reverse proxy so every encoded, cased, and versioned variant of a protected prefix passes the identical gate — or is denied by default.
