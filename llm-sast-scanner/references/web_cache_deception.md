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
- Cache-key normalization differs from origin parsing (`//`, `/%2e/`, case, trailing chars) → "cache key confusion" lets an attacker poison the key that victims request.

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
