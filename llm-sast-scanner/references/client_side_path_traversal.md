---
name: client-side-path-traversal
description: Client Side Path Traversal (CSPT) and secondary-context path traversal across frontend frameworks (React Router, Next.js, Vue Router, Angular, SvelteKit, Nuxt, Ember, SolidStart)
---

# Client Side Path Traversal (CSPT)

Client Side Path Traversal occurs when a frontend router decodes a URL path/query/hash component and a developer interpolates that decoded value directly into a `fetch`-style request URL. The browser (or server-side enhanced fetch) then resolves the embedded `../` before issuing the request, redirecting the call to an unintended same-origin endpoint. CSPT bypasses frontend route guards and lets attackers control the destination of an authenticated API call. When chained with open redirect, file upload, or HTML-rendering sinks (`dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`, `{@html}`, `{{{ }}}`, Solid `innerHTML`), it commonly escalates to CSRF, stored XSS, or SSRF / secondary-context path traversal in hybrid frameworks (Next.js route handlers, SvelteKit `+page.server.ts`/`+server.ts`, Nuxt `server/api/`, SolidStart `"use server"` functions).

> Reference: "The Dot-Dot-Slash That Frameworks Hand You: CSPT Across Every Major Frontend Framework" — Jonathan Dunn (xssdoctor), April 2026 — `https://lab.ctbb.show/research/the-dot-dot-slash-that-frameworks-hand-you`

## Where to Look

**Frontend SPA Routers**
- React Router, Vue Router, Angular Router, Ember Router, `@solidjs/router`

**Hybrid Server/Client Frameworks**
- Next.js (App Router + Pages Router), Nuxt (Vue + H3/Nitro), SvelteKit, SolidStart

**Param/Query Sources**
- Dynamic path segments: `/users/:userId`, `/files/*`, `[...slug]`, `[id]`
- Query params: `useSearchParams`, `route.query`, `queryParamMap`, `url.searchParams`
- Hash fragment: `window.location.hash`
- Stored payloads (Nuxt island `__NUXT__` payload — CVE-2025-59414)

**Client Sinks**
- `fetch()`, `XMLHttpRequest`, `axios.*`, `useFetch`/`$fetch` (Nuxt), `useSWR`/`useQuery` URL templates, Angular `HttpClient.get/post/put`, Ember Data adapters (`urlForFindRecord`, `urlForQuery`), Solid `createResource`/`createAsync`, RTK Query, Apollo `link.uri` builders

**Server-Side / Secondary Sinks** (hybrid frameworks)
- Next.js Route Handlers (`app/api/.../route.ts`) — `await params` auto-decodes
- SvelteKit `+page.server.ts`, `+server.ts` — `params.*` decoded by `decode_params()`
- Nuxt `server/api/[...path].ts` — `getRouterParam(event, key, { decode: true })`
- SolidStart `"use server"` `query()`/`action()` args — passthrough of decoded client string

## Core Concept

The browser normalizes literal `../` in the **path** before the request leaves the address bar, but does NOT normalize `../` inside **query strings** or after framework decoding completes. CSPT exploits the gap where:

1. The attacker encodes traversal characters (`%2F`, `%2E%2E`, `%252F`, etc.) so the URL survives the browser's path normalization.
2. The frontend router's decoding pipeline turns those encoded characters back into a real `/` and `..` inside a param/query value.
3. The developer interpolates the decoded value into a `fetch` URL template.
4. `fetch()` is given a string like `/api/users/../../admin/profile`; the browser resolves the `../` immediately before issuing the request, hitting a different endpoint than the developer intended.

The "sink" is any HTTP request builder. The "source" is the framework decoding step. Whether a framework is exploitable depends on **whether it calls `decodeURIComponent` on the param before the developer's code sees it**.

## Source -> Sink Pattern

**Sources** (decoded — DANGEROUS unless explicitly noted)

| Framework | Param Source | Query Source | Hash Source | Decoded? |
|-----------|--------------|--------------|-------------|----------|
| React Router | `useParams()` | `useSearchParams()` | `useLocation().hash` | YES |
| Next.js (page / `useParams`) | `await params`, `useParams()` | `useSearchParams()`, `searchParams` | `useSearchParams` (hash via `window`) | Params: re-encoded; Query: YES |
| Next.js (route handler) | `await params` (route.ts) | `request.nextUrl.searchParams` | n/a | YES (auto-decoded — secondary PT risk) |
| Vue Router | `route.params.*` | `route.query.*` | `route.hash` | YES |
| Nuxt (client) | `useRoute().params.*` | `useRoute().query.*` | `route.hash` | YES (inherits Vue Router) |
| Nuxt (server) | `getRouterParam(event, k)` | `getQuery(event)` | n/a | Param: NO by default; Query: YES |
| Nuxt (server) | `getRouterParam(event, k, { decode: true })` | n/a | n/a | YES |
| Angular | `paramMap.get()`, `snapshot.paramMap.get()` | `queryParamMap.get()` | `Location.path()` | YES |
| SvelteKit | `params.*` (`+page.ts`, `+page.server.ts`, `+server.ts`) | `url.searchParams`, `$page.url.searchParams` | `$page.url.hash` | YES |
| Ember | `params.*` in `model()` hook (`:param`) | `params.*` in `model()` (declared `queryParams`) | `window.location.hash` | YES (`:param`); partial for `*wildcard` |
| SolidStart | `useParams()` | `useSearchParams()` | `useLocation().hash` | Param: NO; Query: YES |

**Sinks** (the request builders that consume the decoded value)

- `fetch(\`/api/users/${id}\`)`
- `axios.get(\`/api/...${userInput}\`)`
- Angular `this.http.get(url)`, `this.http.post(url, body)`
- Vue/Nuxt `useFetch(\`/api/...${id}\`)`, `$fetch(...)`
- SvelteKit load `fetch(\`/api/...${params.x}\`)` (client + enhanced server fetch)
- SolidStart `createResource(() => fetch(...))` and `query(... "use server")`
- Ember `fetch()` in `model()` hook; Ember Data `urlForFindRecord`, `urlForQuery`
- Next.js client component `fetch` to a same-origin route handler

## Vulnerability Patterns

### React Router

`useParams()` returns fully decoded values. `decodePath()` runs `decodeURIComponent` per-segment then re-encodes `/`, but `matchPath()` immediately undoes that with `value.replace(/%2F/g, "/")`. Net effect: `%2F` → `/`, `%2E%2E` → `..`, and even `%252F` round-trips to `/` via decode-then-replace.

```javascript
// VULN — path param interpolated into fetch
const { userId } = useParams();
useEffect(() => {
  fetch(`/api/users/${userId}/profile`).then(/* ... */);
}, [userId]);
// URL: /users/..%2F..%2Fadmin → userId = "../../admin"
// fetch issued: GET /api/admin/profile
```

```javascript
// VULN — splat / catch-all route is the most dangerous variant
// Route: <Route path="files/*" element={<Files />} />
const params = useParams();
const file = params["*"]; // captures across / boundaries
fetch(`/api/files/${file}`); // literal ../ works WITHOUT any encoding
```

```javascript
// VULN — query param into fetch then into dangerouslySetInnerHTML (CSPT -> XSS)
const [searchParams] = useSearchParams();
const widget = searchParams.get("widget");
fetch(`/api/widgets/${widget}`).then(r => r.text()).then(setHtml);
return <div dangerouslySetInnerHTML={{ __html: html }} />;
```

**SAFE source**: `useLocation().pathname` preserves `%2F` encoding.

### Next.js

Two encoding personas under the same `await params` API:

- **Page / layout / `useParams()`**: `getParamValue()` re-encodes `%2F` back to `%2F` after decoding. Values are SAFE for path params.
- **Route handlers** (`app/api/.../route.ts`): `await params` decodes via `getRouteMatcher()` → `match.split('/').map(decode)`. `%2F` becomes `/` and is split into separate array elements.

```typescript
// VULN — secondary context path traversal via route handler
// app/api/content/[...path]/route.ts
export async function GET(_req, { params }) {
  const { path } = await params;
  // path = ["docs", "..", "..", "internal", "credentials"]  (auto-decoded)
  const fullPath = path.join("/");  // "docs/../../internal/credentials"
  return fetch(`https://backend.internal/${fullPath}`);
}
```

```typescript
// VULN — query params on the client side (Next.js does NOT re-encode query)
"use client";
const sp = useSearchParams();
const widget = sp.get("widget"); // "../../attachments/malicious"
fetch(`/api/widgets/${widget}`);
```

**SAFE**: page-level `await params` and `useParams()` (re-encoded).
**DANGEROUS**: route handler `await params`, `useSearchParams()` on the client.

### Vue Router / Nuxt (client)

`route.params.*` runs through `decodeParams()` → `decodeURIComponent`. `%2F` → `/`. Same for `route.query.*` (via `parseQuery()`). `+` is preserved as a literal character (unlike standard `URLSearchParams`).

```javascript
// VULN — Vue Router param to useFetch / $fetch
const route = useRoute();
const { data } = useFetch(`/api/products/${route.params.productId}`);
// /product/..%2f..%2fadmin → productId = "../../admin"
// fetch URL: /api/products/../../admin → /api/admin
```

```javascript
// VULN — multi-param route doubles attack surface (Nuxt)
// /shop/..%2F..%2Fadmin/..%2Fusers
useFetch(`/api/shop/${route.params.category}/products/${route.params.productId}`);
// resolves to /api/admin/users
```

```html
<!-- CRITICAL — CSPT to XSS via v-html (Vue/Nuxt) -->
<script setup>
const widget = useRoute().query.widget;            // decoded
const { data: html } = await useFetch(`/api/widgets/${widget}`);
</script>
<template><div v-html="html" /></template>
```

**Nuxt server (H3)**: `getRouterParam(event, 'id')` does NOT decode by default. `getRouterParam(event, 'id', { decode: true })` and explicit `decodeURIComponent()` on the raw value DO decode → SSRF / secondary PT.

**Nuxt-specific stored CSPT** (CVE-2025-59414): the `revive-payload.client.js` plugin fetches `/__nuxt_island/${key}.json` using a key from the `window.__NUXT__` payload. If an attacker can poison the payload (cache poisoning, stored injection, MITM on initial HTML), the key can traverse to any same-origin endpoint:

```javascript
// nuxt/dist/app/plugins/revive-payload.client.js (excerpt)
nuxtApp.payload.data[key] ||= $fetch(`/__nuxt_island/${key}.json`, { ... });
// key = "../../api/proxy/attacker.com?x="
//   → $fetch("/__nuxt_island/../../api/proxy/attacker.com?x=.json")
//   → /api/proxy/attacker.com?x=.json  (the .json is absorbed by the query string)
```

**SAFE sources**: `route.path`, `route.fullPath` (preserve `%2F`); `getRouterParam(event, k)` without `{ decode: true }`.

### Angular

`paramMap.get()` and `queryParamMap.get()` both run `decodeURIComponent`. `SEGMENT_RE = /^[^\/()?;#]+/` allows `%2F` to stay inside one segment during matching, then `decode()` decodes after. Result: route matches AND param is decoded — Angular is more permissive for `%2F` than React/Vue.

```typescript
// VULN — paramMap into HttpClient (the canonical Angular CSPT)
ngOnInit() {
  this.route.paramMap.pipe(
    switchMap(p => {
      const userId = p.get('userId');           // "../../admin"
      return this.http.get(`/api/users/${userId}/profile`);
    })
  ).subscribe(d => this.user = d);
}
```

```typescript
// CRITICAL — CSPT -> XSS via [innerHTML] + bypassSecurityTrustHtml()
const html = this.sanitizer.bypassSecurityTrustHtml(apiResponse);  // disables sanitizer
// template: <div [innerHTML]="html"></div>
```

```typescript
// VULN — open redirect via router.navigate with decoded query value
const next = this.route.snapshot.queryParamMap.get('next'); // decoded
this.router.navigate([next]);
```

`router.navigate()` re-encodes its inputs (`%` → `%25`), so it is NOT a path-traversal sink, but it IS an open-redirect sink when fed an attacker-controlled decoded value.

**SAFE source**: `router.url` preserves `%2F`.

### SvelteKit

Two-stage pipeline: `decode_pathname()` (uses `decodeURI`, which preserves `/`) → route regex match → `decode_params()` (`decodeURIComponent`). Final params have real `/`. `decode_pathname()` splits on `%25` first, which makes `%252F` resolve to literal `%2F` (NOT `/`) — SvelteKit blocks double-encoding bypasses.

```typescript
// VULN — universal load function (runs on client nav AND SSR)
// src/routes/users/[userId]/+page.ts
export async function load({ params, fetch }) {
  const res = await fetch(`/api/users/${params.userId}/profile`);
  // /users/..%2Fadmin%2Fsecrets → params.userId = "../admin/secrets"
  // Resolved: GET /api/admin/secrets/profile
  return { user: await res.json() };
}
```

```typescript
// CRITICAL — server-only load with internal network access
// src/routes/data/[dataId]/+page.server.ts
export const load = async ({ params }) => {
  const dataId = params.dataId;  // decoded, traversal payload arrives here
  const doc = await fetch(`http://internal-service.local/data/${dataId}`);
  return { data: await doc.json() };
};
// The fetch does NOT pass through hooks.server.ts — auth middleware bypassed.
```

```svelte
<!-- CRITICAL — CSPT to XSS via {@html} -->
<script>
  import { page } from '$app/stores';
  const widget = $page.url.searchParams.get('widget'); // decoded
  let html = '';
  $: fetch(`/api/widgets/${widget}`).then(r => r.text()).then(t => html = t);
</script>
{@html html}
```

**SAFE** (best framework-level defense): param matchers reject the route entirely before `load()` runs.

```typescript
// src/params/id.ts
export function match(param: string): boolean {
  return /^[a-zA-Z0-9-_]+$/.test(param);
}
// Usage: src/routes/user/[id=id]/+page.svelte
// "../../admin" never matches → 404 before any load executes.
```

### Ember

`route-recognizer` runs `normalizePath()` (per-segment `decodeURIComponent` + re-encode `%` and `/`) then `findHandler()` which calls `decodeURIComponent` AGAIN for `:param` segments (skipped for `*wildcard`). Net: `:param` returns fully decoded value with real `/`. Double-encoding is blocked because `normalizePath` re-encodes `%`.

```javascript
// VULN — params in model hook
// app/routes/user.js
export default class UserRoute extends Route {
  model(params) {
    return fetch(`/api/users/${params.user_id}`).then(r => r.json());
    // /user/..%2f..%2fadmin → params.user_id = "../../admin"
  }
}
```

```javascript
// VULN — Ember Data adapter without encoding (indirect CSPT)
// app/adapters/user.js
export default class UserAdapter extends RESTAdapter {
  urlForFindRecord(id, modelName) {
    return `/api/${modelName}s/${id}`; // No encodeURIComponent on `id`
  }
}
// this.store.findRecord('user', params.user_id)
// where params.user_id = "../../admin" → fetches /api/admin
```

```handlebars
{{! CRITICAL — CSPT -> XSS via triple curlies / htmlSafe() }}
{{{this.model.content}}}
```

`*wildcard` segments capture `/` as part of the regex `(.+)` and skip the final `decodeURIComponent`. Literal `../` works without encoding; `%2F` stays encoded.

**SAFE source**: `window.location.pathname` (raw browser value, bypasses route-recognizer).

### SolidStart

`@solidjs/router`'s `createMatcher()` stores raw path segments WITHOUT calling `decodeURIComponent`. `useParams()` for single-segment dynamic params is the only framework-decoded source that is safe by default. `useSearchParams()` uses standard `URLSearchParams` and is fully decoded.

```tsx
// SAFE for path params
const params = useParams();
fetch(`/api/users/${params.userId}`); // %2F stays %2F → server receives literal %2F
```

```tsx
// VULN — search params are the primary CSPT vector in SolidStart
const [searchParams] = useSearchParams();
const [stats] = createResource(
  () => searchParams.source,
  async (source) => {
    const r = await fetch(`/api/stats?source=${source}`);
    return r.json();
  }
);
// /dashboard/stats?source=../../uploads/malicious → fetch fires with traversal
```

```tsx
// VULN — server function ("use server") passes client string through unchanged
const getData = query(async (dataId: string) => {
  "use server";
  const r = await fetch(`http://internal-service.local/data/${dataId}`);
  return r.json();
}, "getData");
// If dataId came from useSearchParams() (decoded) or a catch-all route,
// "../../admin" lands on the server unchanged → SSRF.
```

```tsx
// CRITICAL — Solid's first-class innerHTML JSX prop is an XSS sink
<div innerHTML={apiResponse()} />   // compiles to element.innerHTML = value
```

**SAFE sources**: `useParams()` (single segment) and `useLocation().pathname`. Both preserve percent-encoding.

### Remix

Remix is built on React Router, so the client-side decoding behaviour is **identical to React Router** — `useParams()` returns fully decoded values (`%2F` → `/`, `%2E%2E` → `..`, double-encoding via decode-plus-replace). The interesting wrinkles are server-side: `loader({ params })` and `action({ params })` receive params from the Remix router which also runs them through `decodeURIComponent`, so the same decoded values flow into server `fetch`/database/internal-API calls — a secondary-context PT path identical in shape to SvelteKit's `+page.server.ts`.

```typescript
// VULN — client-side CSPT
// app/routes/users.$userId.tsx
export default function UserPage() {
  const { userId } = useParams();                 // "../../admin"
  const { data } = useFetcher();
  useEffect(() => { fetcher.load(`/api/users/${userId}/profile`); }, [userId]);
}
```

```typescript
// CRITICAL — secondary-context PT in a server loader/action
// app/routes/users.$userId.tsx
export const loader = async ({ params }: LoaderFunctionArgs) => {
  const userId = params.userId;                   // decoded; e.g., "../../admin"
  const res = await fetch(`http://internal-service.local/users/${userId}`);
  return json(await res.json());
};

// app/routes/api.content.$.tsx  — splat route (`$` catch-all)
export const loader = async ({ params }: LoaderFunctionArgs) => {
  const path = params["*"];                       // decoded; literal `../` works
  return fetch(`http://backend/${path}`);          // SSRF / secondary PT
};
```

**Resource routes** (`app/routes/api.*.ts` that export `loader`/`action` without a default component) are the highest-risk Remix surface — they often proxy to internal APIs and inherit hooks/auth less consistently than page routes.

**SAFE sources**: like React Router, only `useLocation().pathname` preserves `%2F` encoding; server-side, treat `params.*` as decoded user input.

### Astro

Astro pages use file-based routing with `[param]` and `[...slug]` syntax. `Astro.params` is populated by Astro's router; values are URL-decoded once via `decodeURIComponent`, so behaviour is **similar to SvelteKit's `+page.ts`** — `%2F` decodes to `/` and lands in the param value.

```astro
---
// VULN — Astro page or endpoint reading decoded params
// src/pages/users/[userId].astro  (or src/pages/api/users/[userId].ts)
const { userId } = Astro.params;                  // decoded
const res = await fetch(`http://internal/users/${userId}`);
const data = await res.json();
---
```

Astro **API routes** (`src/pages/api/**/*.ts`) run on the server and execute with full network access, so any traversal in `Astro.params` reaching an internal `fetch` is a secondary-context PT, analogous to Next.js route handlers and SvelteKit `+server.ts`.

**SAFE sources**: there is no preserved-encoding alternative in Astro's official API; recommend validating param shape against a regex or matcher before interpolation, equivalent to SvelteKit's param matchers.

### TanStack Router / TanStack Start

TanStack Router supports both decoded params and validated search-params via `parseSearch`/`stringifySearch`. By default `useParams()` and `useSearch()` return decoded values; the safer pattern is to declare a Zod/Valibot schema in `validateSearch` / `parseParams`, which rejects values not matching the schema before the route renders.

```typescript
// VULN — default useParams without validation
const { userId } = Route.useParams();             // decoded
fetch(`/api/users/${userId}`);

// SAFE — typed param validation at route definition
export const Route = createFileRoute('/users/$userId')({
  parseParams: ({ userId }) => ({
    userId: z.string().regex(/^[\w-]+$/).parse(userId),
  }),
});
```

### Qwik City

`useLocation()` and route params expose decoded values; route `loader$()` / `action$()` run on the server. Conceptually identical to SvelteKit's load functions — pair decoded params with `fetch` for client-side CSPT or with server-side internal fetches for secondary PT.

### HTMX / Alpine.js (non-SPA frameworks)

Apps using HTMX (`hx-get="${url}"`) or Alpine.js (`x-data` / `:href="..."`) often interpolate values from the URL or DOM attributes into the request URL. The decoding is whatever the browser does to the attribute value (which mirrors the original URL), so encoded `%2F`/`%2E%2E` in attribute templates can be a CSPT primitive when the attribute interpolation runs on the client.

```html
<!-- VULN — HTMX hx-get built from a search param read by Alpine -->
<div x-data="{ id: new URL(location).searchParams.get('id') }">
  <button :hx-get="`/api/items/${id}`" hx-trigger="click">Load</button>
</div>
<!-- ?id=..%2F..%2Fadmin → hx-get hits /api/admin -->
```

## Decoding Cheat Sheet — Path Params

| Framework | Source | %2F → /? | %2E%2E → ..? | %252F → /? | Splat/catch-all literal `../`? |
|-----------|--------|:--------:|:------------:|:----------:|:-----------------------------:|
| React Router | `useParams()` | YES | YES | YES (decode + replace) | YES (browser normalizes path → traversal stays in param value) |
| Next.js page / `useParams` | re-encoded | NO | YES | NO | NO (re-encoded) |
| Next.js route handler | decoded | YES | YES | NO | YES |
| Vue Router | `route.params.*` | YES | YES | NO | depends on route shape |
| Nuxt client | `useRoute().params.*` | YES | YES | NO | as Vue Router |
| Nuxt server | `getRouterParam` | NO | NO | NO | NO |
| Nuxt server `{ decode: true }` | decoded | YES | YES | NO | YES |
| Angular | `paramMap.get()` | YES | YES | NO | n/a (`**` requires manual parse) |
| SvelteKit | `params.*` | YES | YES | NO (`%25`-split blocks) | catch-all returns string with real `/` |
| Ember (`:param`) | `params.*` | YES | YES | NO (`normalizePath` re-encodes `%`) | n/a |
| Ember (`*wildcard`) | `params.*` | NO (skips final decode) | partial | NO | YES (literal `../`) |
| SolidStart | `useParams()` | NO | NO | NO | NO (encoded), `[...path]` joins real `/` |

## Decoding Cheat Sheet — Query Params

**Every framework decodes query parameters.** Query strings have NO segment boundary, so the entire value (including literal `../`) lands in one decoded string with no encoding tricks needed.

| Framework | Source | Decoded | Notes |
|-----------|--------|:-------:|-------|
| React Router | `useSearchParams()` | YES | standard `URLSearchParams` |
| Next.js | `useSearchParams()` / `searchParams` | YES | standard `URLSearchParams` |
| Vue Router | `route.query.*` | YES | `parseQuery()`; `+` stays literal |
| Nuxt (client) | `useRoute().query.*` | YES | inherits Vue Router |
| Nuxt (server) | `getQuery(event)` | YES | `ufo` library decodes |
| Angular | `queryParamMap.get()` | YES | `decodeQuery()` → `decodeURIComponent` |
| SvelteKit | `url.searchParams`, `$page.url.searchParams` | YES | standard `URLSearchParams` |
| Ember | `params.*` (declared `queryParams`) | YES | browser-decoded |
| SolidStart | `useSearchParams()` | YES | standard `URLSearchParams` |

## XSS Sinks — The Escalation Function

When a CSPT-controlled `fetch` response is rendered as raw HTML, CSPT escalates to (often stored) XSS.

| Framework | Sink | Compiles To |
|-----------|------|-------------|
| React / Next.js | `dangerouslySetInnerHTML={{ __html: val }}` | `element.innerHTML = val` |
| Vue / Nuxt | `v-html="val"` | `element.innerHTML = val` |
| Angular | `[innerHTML]="val"` + `DomSanitizer.bypassSecurityTrustHtml(val)` | `element.innerHTML = val` (sanitizer bypassed) |
| SvelteKit | `{@html val}` | `element.innerHTML = val` |
| Ember | `{{{val}}}`, `htmlSafe(val)` | `insertAdjacentHTML('beforeend', val)` |
| SolidStart | `<div innerHTML={val} />` | `element.innerHTML = val` |

## Safe Sources — What Won't Betray You

| Framework | Safe Source | Why |
|-----------|-------------|-----|
| React Router | `useLocation().pathname` | preserves `%2F` |
| Next.js | `useParams()` / page `await params` | `getParamValue()` re-encodes `%2F` |
| Vue Router | `route.path`, `route.fullPath` | preserve `%2F` |
| Nuxt (client) | `route.path`, `route.fullPath` | inherits Vue Router |
| Nuxt (server) | `getRouterParam(event, k)` (no `{ decode: true }`) | radix3 returns raw |
| Angular | `router.url` | preserves `%2F` |
| SvelteKit | param matchers `[id=id]` | rejects non-matching values before `load()` runs |
| Ember | `window.location.pathname` | bypasses route-recognizer |
| SolidStart | `useParams()` (single segment), `useLocation().pathname` | router never calls `decodeURIComponent` |

## Server-Side / Secondary Context PT Sinks

When a decoded client value is forwarded to a server handler that interpolates it into an internal `fetch`, CSPT becomes SSRF / secondary-context path traversal — often more impactful because the server has access to internal networks the client does not.

| Framework | Server Sink | Decoded? | Risk |
|-----------|-------------|:--------:|------|
| Next.js | route handler `await params` → `fetch()` | YES (auto) | SSRF to internal services |
| Nuxt | `getRouterParam(event, k, { decode: true })` → `$fetch()` | YES (opt-in) | SSRF to internal services |
| SvelteKit | `+page.server.ts` / `+server.ts` `params.*` → `fetch()` | YES | SSRF, BYPASSES `hooks.server.ts` (auth middleware ineffective) |
| SolidStart | `query(... "use server")` args → `fetch()` | passthrough of client string | SSRF if client value already decoded |
| Remix | `loader({ params })` / `action({ params })` / resource routes → `fetch()` | YES | SSRF / secondary PT; resource routes (`api.*.ts`) most exposed |
| Astro | `Astro.params` in `src/pages/api/**/*.ts` → `fetch()` | YES | SSRF / secondary PT |
| Qwik City | `routeLoader$` / `routeAction$` params → `fetch()` | YES | SSRF / secondary PT |
| Nuxt | `revive-payload.client.js` island key → `$fetch` | stored | Stored CSPT (CVE-2025-59414) |

### Receiver-side decoding in server frameworks

Independent of which SPA framework the client uses, the *receiving* server framework also decodes path params. Treat any `req.params.*` / `request.params.*` / `ctx.params.*` interpolated into an internal `fetch` or filesystem path as a secondary-context PT sink.

| Server framework | Path-param API | Decoded? | Notes |
|------------------|----------------|:--------:|-------|
| Express (`/users/:id`) | `req.params.id` | YES — per-segment `decodeURIComponent` | `path-to-regexp` segment match prevents `%2F` from creating sub-segments but the final value is decoded |
| Fastify (`/users/:id`) | `request.params.id` | YES — `decodeURIComponent` per segment | Same shape as Express |
| Koa / `@koa/router` | `ctx.params.id` | YES | Same shape |
| Hapi (`/users/{id}`) | `request.params.id` | YES | `request.params['id*']` (multi-segment) also decoded; literal `../` works |
| NestJS (`@Param('id')`) | controller-method arg | YES (inherits Express/Fastify under the hood) | `@Param('id', new ParseIntPipe())`-style pipes are an effective allowlist defense |
| ASP.NET Core (`{id}`) | `[FromRoute] string id` | YES (`UrlDecoder`) | `[Route("api/files/{*path}")]` catch-all keeps literal `/` characters |
| Spring (`@PathVariable`) | method arg | YES | `@PathVariable("path") String path` decodes `%2F` post-routing |
| Flask (`<string:id>`) / FastAPI (`{id}`) | view-function arg | YES | Path converters (`<int:id>`, `<uuid:id>`) reject traversal at routing time |
| Rails (`params[:id]`) | controller method | YES | `constraints: { id: /\d+/ }` rejects traversal at routing time |

The strongest receiver-side defense in every framework is a **route-level constraint** (NestJS pipes, Spring `@PathVariable` + `@Pattern`, Express middleware regex, Rails `constraints`, Flask/FastAPI typed path converters, SvelteKit param matchers): the route fails to match and the handler never runs.

## Additional Client-Side Sinks

`fetch` is the canonical sink, but every HTTP/URL-aware client API resolves `../` the same way once it sees a path. Treat any of the following as a CSPT sink when fed a decoded param interpolated into a URL template:

```javascript
// All resolve `../` in the path portion before sending
fetch(`/api/x/${userId}`);
axios.get(`/api/x/${userId}`);
new XMLHttpRequest().open('GET', `/api/x/${userId}`);
new WebSocket(`/ws/${userId}`);                  // ws-relative URLs resolve `../` the same way
new EventSource(`/sse/${userId}`);
navigator.sendBeacon(`/beacon/${userId}`, body);
caches.match(`/api/x/${userId}`);                // service-worker cache key — pollutes the cache lookup
self.fetch(`/api/x/${userId}`);                  // inside a ServiceWorker
self.registration.showNotification('', { data: { url: `/api/x/${userId}` }});

// Library wrappers — same underlying primitive
useSWR(`/api/x/${userId}`, fetcher);
useQuery({ queryKey: ['x', userId], queryFn: () => fetch(`/api/x/${userId}`) });
apolloClient.query({ query: GET_X, variables: { id: userId }, uri: `/graphql/${userId}` });
```

### `new URL(path, base)` — sometimes a defense, sometimes a sink

`new URL` is a context-sensitive construct that often differs from string concatenation:

```javascript
// Effectively the same as string concat — resolves `../`
const u = new URL(`/api/x/${userId}`, location.origin);
fetch(u);

// SAFER — encodes path segment, but ONLY if the segment is used in pathname,
// not concatenated into the path string template
const u = new URL(location.origin);
u.pathname = `/api/x/${encodeURIComponent(userId)}`;
fetch(u);

// SAFE — URLSearchParams encodes query values
const u = new URL('/api/x', location.origin);
u.searchParams.set('id', userId);
fetch(u);                                        // ?id=..%2F..%2Fadmin (encoded, no traversal)
```

The pattern to look for: `URLSearchParams.set` / `URL.pathname = encodeURIComponent(...)` is generally safe; raw template-literal interpolation into `new URL(template, base)` is NOT.

### Open-redirect via CSPT (`location.href` / `location.assign` / `location.replace`)

A decoded param interpolated into a navigation sink is an open-redirect primitive:

```javascript
// VULN — decoded query param drives navigation
const next = useSearchParams()[0].get('next');   // "//evil.tld/phishing" or "../../auth/logout"
location.assign(next);
location.href = next;
window.open(next);
```

Combine with CSPT: a redirected fetch returning a URL string that flows into `location.assign` chains CSPT → open redirect → credential theft via spoofed login page on the attacker domain.

## CSPT → CSRF Chain (Doyensec / `cspt2csrf`)

Doyensec published a practical exploitation method that uses a CSPT primitive to *redirect a state-changing API call* to a different endpoint on the same origin. Because the browser still attaches the user's session cookies to the redirected request, CSPT becomes a fully-functional CSRF primitive even when the target API uses `SameSite=Lax`/`Strict` cookies — the request originates from the legitimate first-party page.

Typical chain:

1. Application has a Settings page that issues `fetch('/api/users/me/email', { method: 'POST', body: ... })`.
2. The endpoint URL is built using a decoded path param: `fetch(\`/api/users/\${userId}/email\`, …)`.
3. Attacker crafts a link `https://victim/settings/..%2F..%2Fadmin%2Fdelete-all` that, when the victim visits while logged in, causes the POST to land on `/api/admin/delete-all` instead of the user's own email endpoint.
4. Because the request shares the legitimate session, the chain succeeds when the endpoint does not require a CSRF token or the app's fetch wrapper auto-includes one — do not assume server-side CSRF tokens are always sent on redirected fetch calls.

Detection rule: flag any state-changing (`POST`/`PUT`/`PATCH`/`DELETE`) `fetch` whose URL template interpolates a decoded source as a high-priority CSPT-to-CSRF finding, NOT just a CSPT-to-data-disclosure finding.

## Tooling for Triage

These are dynamic-testing tools, useful when the user explicitly asks for runtime verification.

- **Burp Suite DOM Invader** (ships with Burp's built-in browser) — its CSPT panel automatically mutates dynamic path segments with `%2F` / `%5C` / `%252F` / `%255C` / literal `../` and observes whether subsequent `fetch`/XHR/WebSocket URLs traverse to a different endpoint. The fastest way to confirm a real target.
- **Caido `cspt2csrf` extension** — implements the Doyensec CSPT-to-CSRF chain; given a CSPT source, it enumerates reachable state-changing endpoints and generates a working CSRF PoC link.
- **Caido** generally is the preferred CSPT triage proxy today; its Match-and-Replace + Response Highlighter make it straightforward to trace decoded-param → fetch flows.
- Manual confirmation: open DevTools → Network, set a breakpoint on `fetch`/`XMLHttpRequest.open`, navigate to the crafted URL, and check the *resolved* request URL after the browser collapses `../`.

## Detection Rules

### Generic CSPT Pattern

A finding requires (1) a decoded source from the table above, (2) a fetch-style sink, and (3) string interpolation between them with no allowlist/encoding step in between.

```javascript
// VULN signature — decoded param flows into a fetch URL template
const x = <decoded-source>;             // e.g., useParams().id
fetch(`/api/.../${x}/...`);             // any axios/HttpClient/useFetch/$fetch
```

```javascript
// SAFE — value re-encoded at the sink
fetch(`/api/.../${encodeURIComponent(x)}/...`);
```

```javascript
// SAFE — value is constrained by an allowlist or regex BEFORE the sink
if (!/^[\w-]+$/.test(x)) throw new Error("invalid id");
fetch(`/api/.../${x}/...`);
```

### Framework-Specific Detection

```javascript
// React / Next.js (client) — VULN
const { id } = useParams(); fetch(`/api/x/${id}`);                // React Router only
const sp = useSearchParams(); fetch(`/api/x?w=${sp.get("w")}`);   // both

// Next.js route handler — VULN (secondary PT)
export async function GET(_, { params }) {
  const { path } = await params;                                  // decoded
  return fetch(`https://internal/${path.join("/")}`);
}
```

```javascript
// Vue / Nuxt — VULN
const r = useRoute(); useFetch(`/api/x/${r.params.id}`);
$fetch(`/api/x/${r.query.w}`);
```

```typescript
// Angular — VULN
this.route.paramMap.subscribe(p => this.http.get(`/api/x/${p.get("id")}`));
this.route.queryParamMap.subscribe(q => this.http.get(`/api/x?w=${q.get("w")}`));
```

```typescript
// SvelteKit — VULN (server-side is most dangerous)
// +page.server.ts
export const load = async ({ params, fetch }) =>
  ({ d: await (await fetch(`http://internal/${params.id}`)).json() });

// +server.ts
export const GET = async ({ params, fetch }) =>
  fetch(`http://internal/${params.id}`);
```

```javascript
// Ember — VULN
model(params) { return fetch(`/api/x/${params.user_id}`); }
// or via Ember Data adapter:
urlForFindRecord(id) { return `/api/users/${id}`; } // no encodeURIComponent
```

```tsx
// SolidStart — VULN (search params and server fns)
const [sp] = useSearchParams(); fetch(`/api/x?w=${sp.w}`);
const f = query(async (id) => { "use server"; return fetch(`http://internal/${id}`); }, "f");
```

### CSPT -> XSS Detection

Flag CRITICAL when ANY of the following are present in the same component/page where a CSPT primitive exists:

- React/Next: `dangerouslySetInnerHTML={{ __html: <fetch-response> }}`
- Vue/Nuxt: `<div v-html="<fetch-response>" />`
- Angular: `[innerHTML]="<bypass-trusted-html-of-fetch>"`
- SvelteKit: `{@html <fetch-response>}`
- Ember: `{{{<fetch-response>}}}` or `htmlSafe(<fetch-response>)`
- SolidStart: `<div innerHTML={<fetch-response>} />`

## Confirming a Finding

1. Identify the decoded source (`useParams`, `route.params`, `paramMap.get`, `params.*` in load, etc.) and confirm it bypasses the framework's safe sources (e.g., not `route.path`, `router.url`, `useLocation().pathname`).
2. Trace the value to a `fetch`-style sink and confirm there is NO `encodeURIComponent`, allowlist regex, or param matcher (`[id=id]` in SvelteKit) between source and sink.
3. Construct an encoding payload that survives both the browser and the framework decoder (see "Decoding Cheat Sheet"). Use literal `../` for query params and splat/catch-all routes; use `%2F`-style encoding for single-segment dynamic params; use `%252F` only for React Router and Next.js page query.
4. Verify the fetch URL after browser normalization. The browser resolves `../` in the path portion of the request just before sending; the resolved path is what the server sees.
5. For secondary-context PT, repeat with the server sink as the request target and confirm reachability of internal hosts/paths.
6. For XSS chaining, demonstrate that the redirected fetch endpoint returns attacker-controlled HTML (file upload, attachments, user-generated content) and that the response flows into the framework's HTML sink.

## Common False Alarms

- The decoded value is constrained by an allowlist regex (e.g., SvelteKit param matcher `[id=id]`, route guards that reject non-matching shapes) BEFORE reaching `fetch`.
- The value is `encodeURIComponent`'d at every interpolation point (full encoding, not just `encodeURI`).
- The value flows ONLY into framework-safe sources: `useLocation().pathname`, `route.path`, `route.fullPath`, `router.url`, `window.location.pathname`, `getRouterParam()` (Nuxt server, no `{ decode: true }`), or SolidStart `useParams()` for single segments.
- The fetch URL is constructed with `URL` / `URLSearchParams` and the value is set via `searchParams.set(...)`, which encodes; OR the value is the FULL URL passed to `fetch` (no traversal possible — no base path to escape).
- The response is rendered with framework auto-escaping only (no `dangerouslySetInnerHTML`/`v-html`/`{@html}`/triple curlies/`bypassSecurityTrustHtml`/Solid `innerHTML`) — CSPT to XSS is NOT exploitable, but the underlying CSPT may still be a CSRF/IDOR primitive.
- Static `fetch` URLs with no string interpolation of user-controlled values.

## Severity Heuristics

- **Critical**: CSPT chained to XSS via `innerHTML`-class sink AND the redirected endpoint can return attacker-controlled HTML (file upload / attachments / user content); OR secondary-context PT in a server route handler / `+page.server.ts` / Nuxt `server/api` / SolidStart `"use server"` that reaches internal services.
- **High**: CSPT primitive that lets an authenticated user redirect a privileged API call to a different same-origin endpoint (CSRF primitive, IDOR amplifier, ACL bypass), without an XSS chain.
- **Medium**: CSPT to a non-sensitive endpoint, or an open-redirect-only chain (e.g., Angular `router.navigate([decoded])`).
- **Informational**: Decoded source flows into a fetch URL but is gated by a strict allowlist or param matcher; document as defense-in-depth gap.

## Business Risk

- Bypassed frontend route guards: an attacker triggers privileged actions or reads data the app's UI never exposes.
- CSRF primitive: state-changing API calls (DELETE, PATCH, POST) issued under the victim's session, with the attacker controlling the destination via a crafted link.
- Stored XSS via attachment/upload chain when CSPT redirects fetches to user-uploaded HTML and that HTML flows into a raw-HTML render sink.
- SSRF / internal-service compromise via secondary-context path traversal (Next.js route handlers, SvelteKit `+page.server.ts`, Nuxt server, SolidStart server functions) — the server bypasses its own auth middleware (`hooks.server.ts` is not invoked for internal `fetch`).
- Information disclosure via traversal into admin/diagnostic endpoints exposed only to authenticated sessions.

## Core Principle

Treat every value returned by a frontend router's param/query API as URL-decoded user input until proven otherwise. Either re-encode it with `encodeURIComponent` at every fetch interpolation, constrain it with a strict allowlist (regex / param matcher) BEFORE it reaches the sink, or read raw URL state from the framework's safe source (`useLocation().pathname`, `route.path`, `router.url`, `window.location.pathname`, SolidStart `useParams`). Never interpolate a decoded path/query/hash value directly into a `fetch`/`HttpClient`/`useFetch`/`$fetch`/Ember Data URL template without one of those defenses. For hybrid frameworks, apply the same rule on the server side — `+page.server.ts`, route handlers, `server/api/*`, and `"use server"` functions all need the same allowlist or re-encoding before forwarding values into internal `fetch` calls.

## Analyst Notes

1. The browser normalizes literal `../` in the path BEFORE the request is sent. Encoded forms (`%2F`, `%2E%2E`, `%252F`) survive that normalization; choose the encoding the target framework actually decodes.
2. Query strings are NOT path-normalized by the browser. Use literal `../` first; reach for encoding only to bypass WAFs/filters.
3. The hash fragment is never URL-encoded or decoded by the browser — `window.location.hash.slice(1)` is exactly what the user typed.
4. SolidStart's path params and Next.js page-level params are the only framework-decoded sources that are safe by default; everywhere else, assume decoded.
5. SvelteKit param matchers (`[id=id]`) are the strongest framework-level defense; recommend them in remediation.
6. For Nuxt, also audit `revive-payload.client.js` consumers and any `__NUXT__` payload sources for stored CSPT (CVE-2025-59414 class).
7. When triaging, distinguish CSPT (client `fetch`) from secondary-context PT (server `fetch` with internal reachability) — the latter is materially higher impact.

## Sources, Sinks & Sanitizers

The closest automated models map CSPT primitives to **client-side request forgery** and **client-side open redirect** when untrusted data is concatenated into URL/fetch targets.

**Sources**: non-server-side remote sources (browser `useParams`, `useSearchParams`, `location`-derived values).

**Sinks**: `fetch`, `axios`, `XMLHttpRequest.open`, URL template concatenation before HTTP request.

**Sanitizers**: numeric coercion of IDs; allowlist regex before interpolation; `encodeURIComponent` at sink; `URLSearchParams.set` for query values; sanitizing prefix edges in URL builders.

**SAFE pattern**: restrict param to digits — parse `message_id` as number before fetch; matches manual `encodeURIComponent` / allowlist guidance in this reference.

**Related patterns** (not CSPT):
- Client-side URL redirect — open redirect via decoded param in `location` / router
- Server-side request forgery — secondary-context PT in route handlers / server fetch (not browser-normalized)
- Path injection — server-side path sinks (Next route handler internal paths)
- HTTP-to-file access — separate CWE-912 backdoor pattern, not CSPT

Framework-specific decoding tables (React Router vs SolidStart) require heuristic/manual review. Vue/Nuxt/Angular/SvelteKit CSPT requires taint from client source to fetch sink when URL is built in the browser bundle.
