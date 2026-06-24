---
name: shared-client-cache-leak
description: Cross-user / cross-tenant data leakage via shared client caches, request deduplication/coalescing, mutable-auth singletons, shared cookie jars, pooled-connection or thread-local reuse, and module-global request state — identity omitted from the cache/coalescing key or held in process-shared state. Covers JS/TS (urql, Apollo, DataLoader, TanStack/React Query, SWR, axios), Python (requests, aiohttp, httpx, SQLAlchemy, Django/Flask caches), Go (singleflight, gorm, go-redis, go-resty), Java/Kotlin (Caffeine, Spring @Cacheable/WebClient, OkHttp, Ktor, Hibernate L2, gRPC), Ruby (Rails.cache, Faraday), PHP (Guzzle, Octane/Swoole), C#/.NET (HttpClient, IHttpClientFactory, EF Core, IMemoryCache/FusionCache), Rust (moka, reqwest), Elixir/Phoenix (:persistent_term, ETS), Scala, Clojure, and reused headless-browser / SSR render workers (Puppeteer/Playwright "headless context bleed") (CWE-488 / CWE-524 / CWE-567 / CWE-362)
---

# Shared-Client Cache / Dedup Cross-User Leak

A process-shared object — an HTTP/GraphQL/SDK client, a cache, a request de-duplicator, a connection from a pool, a thread-local, or a plain module global — serves **one user's data to another** because the per-user identity (auth token, session, `userId`, `tenantId`) is **not part of the key** that the shared structure uses, or is stored as **shared mutable state** instead of being scoped to the request.

This is the in-process sibling of `web_cache_deception.md` (which covers HTTP/CDN/edge caches). Here the leak happens **inside the application process**, not at a proxy. It is framework- and language-agnostic and almost always **only reproduces under concurrency / load**, which makes it invisible to single-user testing and easy to ship.

The canonical trigger:

> A singleton client (`memoize`/`lazy`/`static`/global) runs the same operation for every user. The operation key is derived from the request shape (query+variables, URL, method args) but the identity travels in headers / options / mutable instance state. Two concurrent users collide on the same key, and the structure returns the first user's response to both.

## Root-Cause Sub-Classes

1. **In-flight request deduplication / coalescing** — concurrent identical operations are merged into one upstream call; the winner's auth is used, all callers get the winner's data.
2. **Response / object cache keyed without identity** — an authenticated response or per-user object is stored under a key that omits identity, then replayed to others. Includes server-side GraphQL/HTTP response caches whose `sessionId`/scope is missing or mis-set (e.g. a `PRIVATE` response cached without a per-user session key, so all logged-in callers share one entry).
3. **Shared client carrying per-request auth as mutable instance state** — `client.defaults.headers`/`setToken()`/an interceptor field is mutated per request on a singleton; under concurrency requests read each other's token (or the wrong response). Also a **shared cookie jar** (`Session.cookies`, a shared `CookieJar`/cookiejar) that persists one user's `Set-Cookie`/session cookie and replays it on another caller's request.
4. **Pooled connection / thread-local reuse** — a DB/HTTP connection or a `ThreadLocal`/`contextvar` retains identity/session state (role, `SET`/`SET ROLE`/`search_path`, RLS `SET app.current_tenant`, temp tables/creds, "current user") from a previous user of the pool/thread. Transaction-pooled proxies (e.g. PgBouncer `pool_mode=transaction`) silently leak session-level `SET`s to the next client unless `SET LOCAL` is used.
5. **Module-global / static request state** — a global/static variable is assigned the "current user/request" and read by concurrent requests. In **warm serverless** runtimes (Lambda/Cloud Functions/Azure Functions) module-scope state persists across invocations, so global per-user/per-tenant data leaks to later invocations on the same warm instance.
6. **Context propagation lost across `await`/goroutine/operator** — request identity stored in async-context (`AsyncLocalStorage`, `contextvars`, Reactor `Context`, Kotlin coroutine context, Spring `SecurityContext`) is read after it was overwritten by an interleaved request, or is not propagated onto a pooled worker thread (e.g. `SecurityContextHolder` `MODE_INHERITABLETHREADLOCAL` + a reused thread-pool thread → previous user's principal).
7. **Connection-bound credentials reused across identities** — schemes that bind identity to the *transport connection* rather than the request (NTLM/Kerberos/Negotiate, mutual-TLS client certs, a gRPC channel's channel-level credentials). Pooling/sharing that connection or channel lets a later, different user inherit the earlier user's authenticated identity — even when no header is mutated.
8. **Reused stateful headless browser / render worker ("headless context bleed")** — a pooled headless browser (Puppeteer/Playwright/`chromedp`) or a persistent `BrowserContext`/`userDataDir` profile is reused across tenants for SSR / PDF / screenshot / scrape jobs. Clearing cookies + `localStorage` between jobs does **not** clear a registered **Service Worker**, the HTTP/disk cache, the **DNS cache**, the keep-alive connection pool, IndexedDB / CacheStorage, or in-memory JS globals. So a page from job N (attacker) that registers a Service Worker or poisons a cache can **intercept or rewrite the render of job N+1 (victim)** — executing inside the backend network — turning a blind SSR/PDF bot into a persistent cross-tenant exfiltration / render-hijack channel. The renderer is also an SSRF sink (see `ssrf.md`) and the intercepted state enables backend-internal `xs_leaks.md`-style probing.

## Where to Look

- **Client construction at shared scope**: `memoize(() => new Client(...))`, `lazy`/`once_cell`/`lazy_static`, module-level `const client = ...`, `static`/`@Bean`(singleton) clients, DI singletons, and **module-scope state in serverless handlers** (anything declared outside the handler in Lambda/Cloud Functions persists across invocations).
- **Dedup / coalescing primitives**: urql v4/v5 `Client` (built-in dedup, always on), Apollo Client query dedup, `DataLoader` (must be per-request), `p-memoize`/`pMemoize`, Go `singleflight.Group`, Caffeine/Guava `LoadingCache.get(k, loader)`, `async_lru`, custom "in-flight promise" maps.
- **Caches**: `lru-cache`, **TanStack/React Query `QueryClient`** and **SWR** global cache (must be per server request), `IMemoryCache`/`FusionCache`/`LazyCache`, `cachetools`(`TTLCache`/`@cached`)/`requests-cache`/`aiocache`, **Django `cache.get_or_set`/`@cache_page`**, **Flask-Caching `@cache.cached`**, Caffeine/Guava, Spring `@Cacheable`, Rails `Rails.cache`/`||=` memoization, `Dalli`/Memcached, PHP `static`/APCu, `functools.lru_cache`/`@cache`, Rust `moka`/`DashMap`, Go `go-redis`/`groupcache`/`bigcache`, Elixir `:persistent_term`/`:ets`, Clojure `memoize`/`core.cache`, Next.js `unstable_cache` / `'use cache'` / `React.cache()`, **server-side GraphQL/HTTP response caches** (Apollo Server `responseCachePlugin` + its `sessionId`, Mercurius cache, `@cacheControl` `PRIVATE`/`PUBLIC` scope), and any Redis/Memcached namespace shared across tenants.
- **ORM session / identity map / L2 cache**: a long-lived or module-global ORM session (global SQLAlchemy `Session` instead of `scoped_session`, a Hibernate `Session`/JPA `EntityManager` outliving the request, **EF Core `DbContext` registered as Singleton**, a global `*gorm.DB`) whose identity map / change-tracker returns another user's loaded entities; Hibernate/Ehcache second-level/query caches keyed without `tenantId`; per-session DB state (`SET ROLE`/`search_path`/`SET app.current_tenant`) on a shared `*sql.DB` pool.
- **The KEY**: what goes into the cache/dedup key — query+vars, URL, method args — and whether the auth token / session / `userId` / `tenantId` is in it or only in headers/options.
- **Mutable auth / shared cookies on shared clients**: `instance.defaults.headers.common['Authorization'] = ...`, `session.headers['Authorization'] = ...`, `client.setToken(...)`, `HttpClient.DefaultRequestHeaders.Authorization = ...` (incl. **`IHttpClientFactory` typed clients**), Spring `RestTemplate`/`WebClient` mutated default headers, **OkHttp `CookieJar`/`Authenticator`**, Ruby **Faraday** shared connection, Python **`aiohttp.ClientSession`/`httpx` shared cookie jar + pool**, interceptors reading a mutable field, and a **shared cookie jar** (`requests.Session.cookies`, a process-wide `http.cookiejar`/`CookieJar`, `axios` + shared jar, `reqwest` `cookie_store`) that accumulates one user's session cookie.
- **Connection-bound credentials**: NTLM/Kerberos/Negotiate or mTLS on a pooled keep-alive connection, `UnsafeAuthenticatedConnectionSharing`, a gRPC **channel-level** credential / shared stub used for many users.
- **Pools / thread-locals**: connection-pool checkout without reset, transaction-pooled DB proxies (PgBouncer transaction mode) + session `SET`s, `ThreadLocal` without `remove()`, `contextvars`/`AsyncLocalStorage`/`Thread.current[...]` for "current user", `SecurityContextHolder` `MODE_INHERITABLETHREADLOCAL` with thread pools, and `@Async`/`Executor`/reactive pipelines that don't propagate the security context.
- **Headless render workers**: a long-lived `puppeteer.launch()`/`chromium.launch()` `Browser` reused across requests, a persistent `launchPersistentContext`/`userDataDir`, or a browser pool (`generic-pool`, `puppeteer-cluster`) where jobs only `page.deleteCookie()` / clear `localStorage` between tenants — leaving Service Workers (`navigator.serviceWorker.register`), CacheStorage/IndexedDB, the HTTP + DNS cache, and keep-alive sockets intact for the next tenant's job. Grep: `puppeteer|playwright|chromedp|launchPersistentContext|userDataDir|puppeteer-cluster|browser\.newPage`.

## Vulnerable vs Safe — by ecosystem

In every snippet below, the value returned depends on the caller's identity (the request carries an
auth token / session / tenant), yet the shared structure's key or scope omits that identity. Resource
names (`fetchResource`, `/api/resource`, `Record`) are generic placeholders for any identity-dependent
endpoint or object.

### JavaScript / TypeScript

**GraphQL client with built-in request dedup on a shared client (e.g. urql v4/v5)**
```ts
// VULN — singleton client; dedup key = hash(query + variables); the auth token is in headers (NOT in key).
// Two concurrent callers running the same query+vars get ONE upstream call → first caller's data to both.
export const getClient = memoize(() => new Client({ url, exchanges: [fetchExchange] }))
async function fetchResource(authToken: string) {
  return getClient()
    .query(ResourceDocument, {}, { fetchOptions: { headers: { Authorization: `Bearer ${authToken}` } } })
    .toPromise()
}
// SAFE — per-request client: dedup scope is a single caller.
async function fetchResource(authToken: string) {
  const client = new Client({ url, exchanges: [fetchExchange] })
  return client
    .query(ResourceDocument, {}, { fetchOptions: { headers: { Authorization: `Bearer ${authToken}` } } })
    .toPromise()
}
// Note: a "network-only"/no-cache request policy does NOT disable in-flight dedup; verify whether the
// client de-duplicates concurrent identical operations and whether identity is part of the operation key.
```

**Batching loader (e.g. DataLoader) — must be created per request**
```ts
// VULN — module-level loader shared across requests; batch cache keyed by id, not by caller.
export const recordLoader = new DataLoader(ids => batchLoad(ids))
// SAFE — new loader per request, scoped to the caller and stored on request context.
app.use((req, _res, next) => { req.loaders = { record: new DataLoader(ids => batchLoad(ids, req.auth)) }; next() })
```

**Shared HTTP instance (axios/got/ky) with mutated auth header**
```ts
// VULN — concurrent requests race on the shared default header.
const api = axios.create({ baseURL })
function call(token: string) { api.defaults.headers.common.Authorization = `Bearer ${token}`; return api.get('/api/resource') }
// SAFE — pass auth per-request; never mutate shared defaults.
const api = axios.create({ baseURL })
const call = (token: string) => api.get('/api/resource', { headers: { Authorization: `Bearer ${token}` } })
```

**Promise memoization / lru-cache keyed without identity**
```ts
// VULN — memoize/lru keyed by URL only; authenticated body cached and replayed across callers.
const fetchResource = pMemoize((path: string) => http.get(path, authHeader()))   // key = path
// SAFE — include identity in the key, or scope per request.
const fetchResource = pMemoize((path, userId) => http.get(path, authHeader()), { cacheKey: ([p, u]) => `${u}:${p}` })
```

**Framework in-process data cache (e.g. Next.js)**
```ts
// VULN — caches identity-dependent data without identity in the key / tag.
const getResource = unstable_cache(async () => fetchResource(), ['resource'])   // no identity in key
// SAFE — request-scoped memo (de-dupes within ONE request only), or identity-keyed cache.
import { cache } from 'react'
export const getResource = cache(async () => fetchResource())                   // per-request, not cross-request
```
(Cross-ref `web_cache_deception.md` for the route/CDN-level `Cache-Control`/cacheability variant.)

**Data-fetching cache built at module scope (TanStack Query / React Query, SWR)**
```ts
// VULN — one QueryClient created at module root; the server is long-lived, so its cache is shared
// across every SSR request and ALL users' fetched data collapses into one store (official docs: "NEVER DO THIS").
export const queryClient = new QueryClient()
// SAFE — new client per server request; reuse a singleton only in the browser tab.
import { isServer } from '@tanstack/react-query'
export function getQueryClient() {
  if (isServer) return new QueryClient()              // fresh per request
  return (globalThis.__qc ??= new QueryClient())      // browser singleton
}
// SWR: the same applies to a hoisted global `cache` / <SWRConfig provider> reused server-side — scope per request.
```

**Server-side GraphQL/HTTP response cache without a per-user session key**
```ts
// VULN — response cache enabled but no sessionId; a PRIVATE/per-user response is shared across callers
// (or all logged-in users collapse into one bucket). e.g. Apollo Server responseCachePlugin.
responseCachePlugin()                                   // no sessionId → identity not in the cache key
// SAFE — derive a per-user session key so PRIVATE entries are partitioned by identity.
responseCachePlugin({ sessionId: (ctx) => ctx.request.http?.headers.get('authorization') ?? null })
```

**Shared cookie jar on a singleton client persists a user's session cookie**
```ts
// VULN — one shared instance accumulates Set-Cookie from every response; user A's session cookie
// is then sent on user B's request. (Same risk with a process-wide CookieJar in any language.)
const api = wrapper(axios.create({ jar: sharedJar, withCredentials: true }))  // sharedJar is module-global
// SAFE — a fresh jar per request/user (or don't persist cookies on a shared client at all).
const api = wrapper(axios.create({ jar: new CookieJar(), withCredentials: true }))
```

**GraphQL/fetch clients with a mutated header or shared dispatcher (graphql-request, undici/global `fetch`)**
```ts
// VULN — graphql-request GraphQLClient singleton; setHeader/setHeaders mutate SHARED state → callers race.
const gql = new GraphQLClient(url); function call(token){ gql.setHeader('authorization', `Bearer ${token}`); return gql.request(Doc) }
// VULN — Node's global fetch uses one shared undici dispatcher (Agent) with keep-alive pooling; a shared
// cookie interceptor / CookieAgent on it (or setGlobalDispatcher) persists one user's cookies for the next.
// SAFE — pass auth per request; don't attach a shared cookie jar to the global dispatcher in a multi-user server.
const call = (token: string) => gql.request(Doc, {}, { authorization: `Bearer ${token}` })   // per-request headers
```

**Warm serverless: module-scope state survives across invocations/tenants**
```ts
// VULN — `current` lives in module scope; a warm Lambda/Function instance reuses it for the next
// invocation, which may be a different user/tenant. (Only stateless, identity-free resources belong here.)
let current: User                                  // module scope = shared across invocations
export const handler = async (event) => { current = await loadUser(event); return render(current) }
// SAFE — keep per-request data inside the handler; module scope only for stateless clients/pools.
export const handler = async (event) => { const user = await loadUser(event); return render(user) }
```

### Python

```python
# VULN — singleton Session with mutated auth header; ASGI/threaded concurrency races.
# Also: Session.cookies is shared, so one user's Set-Cookie/session cookie rides on another's request,
# and requests.Session is not thread-safe (one Session per thread/request).
session = requests.Session()
def fetch_resource(token):
    session.headers["Authorization"] = f"Bearer {token}"   # shared mutable state
    return session.get(f"{BASE}/api/resource")
# SAFE — per-call auth, no shared mutation.
session = requests.Session()
def fetch_resource(token):
    return session.get(f"{BASE}/api/resource", headers={"Authorization": f"Bearer {token}"})
```
```python
# VULN — shared aiohttp.ClientSession: one process-wide session holds a single cookie jar AND a
# connection pool, so one user's Set-Cookie/session cookie is replayed on another caller's request;
# it is also not safe to share across event loops/threads. (httpx.AsyncClient shares state the same way.)
SESSION = aiohttp.ClientSession()                         # module-global, shared cookie jar
async def fetch_resource(token):
    return await SESSION.get(f"{BASE}/api/resource", headers={"Authorization": f"Bearer {token}"})
# SAFE — a session per request/user, or disable cookie persistence on a shared client.
from aiohttp import ClientSession, DummyCookieJar
async def fetch_resource(token):
    async with ClientSession(cookie_jar=DummyCookieJar()) as s:   # no cross-request cookie carryover
        return await s.get(f"{BASE}/api/resource", headers={"Authorization": f"Bearer {token}"})
```
```python
# VULN — framework cache helpers keyed without the principal: Django cache.get_or_set / @cache_page,
# Flask-Caching @cache.cached(), cachetools TTLCache/@cached — one entry serves every user.
@cache.cached(timeout=60)                 # Flask-Caching: key = request path, identity omitted
def resource(): return api_get("/api/resource")
# SAFE — add the principal to the key (Flask-Caching: make_cache_key / key_prefix; cachetools: key=...).
@cache.cached(timeout=60, make_cache_key=lambda *a, **k: f"resource:{g.user.id}")
def resource(): return api_get("/api/resource")
```
```python
# VULN — module-global ORM session; the identity map can hand back another user's loaded entities.
Session = sessionmaker(bind=engine); db = Session()        # one shared session for the whole process
# SAFE — request-scoped session (scoped_session per request, closed in teardown).
SessionLocal = scoped_session(sessionmaker(bind=engine))   # one per request; .remove() on teardown
```
```python
# VULN — lru_cache / async_lru on a function returning identity-dependent data, key omits the caller.
@lru_cache(maxsize=1024)
def get_record():                    # no args → one cached value for everyone
    return api_get("/api/resource")
# VULN — httpx.AsyncClient/Client singleton with default auth mutated per request.
# SAFE — include the principal in the key, or don't cache per-caller data in a process-wide cache.
@lru_cache(maxsize=1024)
def get_record(user_id): ...
```
```python
# VULN — contextvar/threadlocal request identity not reset, leaks across pooled workers.
_current_principal = ContextVar("principal")   # set in middleware, read after an await that ran another request's code
```
```python
# VULN — requests-oauthlib OAuth2Session (or any SDK client) HOLDS the token on the instance; sharing one
# process-wide instance across users sends user A's bearer token on user B's call.
SESSION = OAuth2Session(client_id, token=user_token)      # token bound to a shared instance
# VULN — urllib3.PoolManager / a vendor SDK client (boto3, openai, stripe) constructed once with per-user
# creds and reused across users. SAFE — build the authed client/session per user, or pass creds per call.
```

### Go

```go
// VULN — singleflight coalesces by a key that omits the caller; first caller's auth/result returned to all.
var g singleflight.Group
func FetchResource(ctx context.Context, token string) (*Record, error) {
    v, _, _ := g.Do("resource", func() (any, error) { return fetchResource(ctx, token) })  // same key for everyone
    return v.(*Record), nil
}
// SAFE — include identity in the key.
v, _, _ := g.Do("resource:"+userID, func() (any, error) { return fetchResource(ctx, token) })
```
```go
// VULN — package-level var holds the current request's identity; concurrent requests overwrite it.
var requestPrincipal *Principal
// VULN — storing the token on a shared http.Transport/RoundTripper instead of a per-request header.
// SAFE — thread identity through ctx and per-request headers; reusing *http.Client itself is fine.
```
```go
// VULN — shared go-resty client mutated on the CLIENT: SetAuthToken/SetHeader/SetCookieJar are process-wide,
// so concurrent requests race and one user's token/cookies leak to another caller.
client.SetAuthToken(token)                              // shared mutation on the singleton client
// VULN — http.DefaultClient with a shared cookiejar.Jar persists a user's Set-Cookie for the next caller.
// SAFE — set auth/cookies PER REQUEST: resty's client.R().SetAuthToken(token); a per-request header on net/http.
resp, _ := client.R().SetAuthToken(token).Get("/api/resource")   // per-request, client reuse is fine
```
```go
// VULN — per-request session state (SET ROLE / search_path / SET app.current_tenant) issued on the
// shared *sql.DB or global *gorm.DB pool: the next request that checks out the SAME pooled connection
// inherits the previous user's role/tenant (silent RLS bypass). Same as the PgBouncer transaction-mode trap.
db.Exec("SET app.current_tenant = $1", tenantID)   // leaks to the next checkout of this conn
// VULN — go-redis/groupcache/bigcache key that omits the tenant for per-user data (shared namespace).
// SAFE — scope to one connection for the whole unit of work and use SET LOCAL inside a tx, or pass the
//        tenant as a query predicate; include tenantID in every cache key.
tx, _ := db.BeginTx(ctx, nil); tx.Exec("SET LOCAL app.current_tenant = $1", tenantID)  // reset on commit/rollback
```

### Java / Kotlin

```java
// VULN — Caffeine/Guava LoadingCache keyed without the principal; coalescing + caching leak across callers.
LoadingCache<String, Record> cache = Caffeine.newBuilder().build(k -> api.fetch());   // constant key
// SAFE — key by principal.
LoadingCache<String, Record> cache = Caffeine.newBuilder().build(userId -> api.fetch(userId));
```
```java
// VULN — Spring @Cacheable key omits the authenticated principal.
@Cacheable(value = "resource")                 // same entry for every caller
public Record getResource() { ... }
// SAFE — include principal in the key.
@Cacheable(value = "resource", key = "#root.target.currentPrincipalId()")
public Record getResource() { ... }
```
```java
// VULN — ThreadLocal request identity not cleared; the next request on the pooled thread inherits it.
static final ThreadLocal<Principal> CURRENT = new ThreadLocal<>();   // set, never remove() in finally
// VULN — static field / singleton bean holding per-request data; HTTP-client interceptor reading a mutable field.
// SAFE — try { CURRENT.set(p); ... } finally { CURRENT.remove(); }  and pass auth per-call.
```
```java
// VULN — MODE_INHERITABLETHREADLOCAL + a thread pool: a reused pooled thread keeps the PREVIOUS request's
// SecurityContext, so @Async/@PreAuthorize work runs as the wrong principal (authz bypass / wrong-user data).
SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
// SAFE — keep the default strategy and wrap the executor so the context is captured & cleared per task.
return new DelegatingSecurityContextAsyncTaskExecutor(delegate);
```
```java
// VULN — gRPC auth set at the CHANNEL level (or stored on a shared stub) → one identity for all callers.
ManagedChannel ch = ... ; var stub = Grpc.newStub(ch).withCallCredentials(userACreds);  // shared, reused
// SAFE — attach per-call credentials to each RPC (reusing the channel/stub itself is fine).
stub.withCallCredentials(perRequestCreds(token)).fetch(req);
```
```java
// VULN — OkHttp singleton with a shared CookieJar (or an Authenticator caching credentials):
// user A's session cookie is stored on the client and resent on user B's call.
OkHttpClient client = new OkHttpClient.Builder().cookieJar(new PersistentCookieJar()).build();  // shared jar
// VULN — Spring RestTemplate/WebClient singleton with a mutated default header (concurrent header race).
restTemplate.getInterceptors().add((req,b,ex) -> { req.getHeaders().setBearerAuth(currentToken); return ex.execute(req,b); });
// SAFE — no per-user state on the shared client: pass auth per request and don't persist cookies.
Request req = new Request.Builder().url(url).header("Authorization","Bearer "+token).build();   // per call
webClient.get().uri("/api/resource").headers(h -> h.setBearerAuth(token)).retrieve();           // per call
```
```java
// VULN — Apache HttpClient with a shared BasicCookieStore (or connection-bound NTLM/Kerberos on the pool):
// cookies/identity from one request are reused for the next caller on the shared client/connection.
CloseableHttpClient http = HttpClients.custom().setDefaultCookieStore(new BasicCookieStore()).build();  // shared
// VULN (Kotlin/Ktor) — singleton HttpClient with install(HttpCookies) (default in-memory AcceptAllCookiesStorage,
// shared by all calls) or install(Auth){ bearer{...} } (caches the token on the client) → cookie/token shared.
// VULN — OpenFeign/Retrofit client whose interceptor reads a mutable/ThreadLocal token field.
// SAFE — per-request HttpClientContext with its OWN cookie store (Apache); don't install client-wide
// HttpCookies/Auth on a multi-user Ktor client — pass bearerAuth(token) per call; Feign interceptor reads
// request-scoped identity (not a shared field).
HttpClientContext ctx = HttpClientContext.create(); ctx.setCookieStore(new BasicCookieStore());  // per request
```
```java
// VULN — Hibernate 2nd-level / query cache (or Ehcache region) keyed without tenant; a cached entity
// from tenant A is served to tenant B. Same for a JPA EntityManager that outlives the request.
// SAFE — enable Hibernate multi-tenancy (CurrentTenantIdentifierResolver) so caches are tenant-partitioned,
//        and use a request-scoped EntityManager (one persistence context per request).
```

### Ruby / Rails

```ruby
# VULN — class-level memoization on a singleton service caches the first caller's data.
def self.resource = @resource ||= API.get("/api/resource")   # @resource shared across requests
# VULN — Rails.cache key omits the principal; Thread.current[...] not cleared.
Rails.cache.fetch("resource") { API.get("/api/resource") }
# SAFE — per-principal key and request-scoped state.
Rails.cache.fetch("resource/#{current_user.id}") { API.get("/api/resource", token: current_user.token) }
```
```ruby
# VULN — shared Faraday connection whose Authorization header is mutated per request (concurrency race
# under Puma threads), or a shared cookie jar on the connection. Dalli/Memcached key omits the principal.
CONN = Faraday.new(URL)                       # process-wide
def call(token) = CONN.tap { |c| c.headers["Authorization"] = "Bearer #{token}" }.get("/api/resource")
# SAFE — pass auth per request; never mutate the shared connection's headers.
def call(token) = CONN.get("/api/resource") { |r| r.headers["Authorization"] = "Bearer #{token}" }
```
```ruby
# VULN — HTTParty class-level config is GLOBAL: headers / basic_auth / default_options set on the class
# (or `Api.default_options[:headers]=`) are shared by every caller — classic cross-user auth bleed.
class Api; include HTTParty; headers "Authorization" => "Bearer #{token}"; end   # class-level = shared
# VULN — a shared RestClient::Resource built with an Authorization header reused across users.
# SAFE — pass auth per call; never set it at class level on a multi-user client.
Api.get("/api/resource", headers: { "Authorization" => "Bearer #{token}" })
```

### PHP (long-running workers: Swoole / RoadRunner / Laravel Octane / FPM with persistent singletons)

```php
// VULN — static property / container singleton persists per-caller data across requests in a worker.
class Api { private static ?array $resource = null;
  public static function resource($t){ return self::$resource ??= self::get('/api/resource', $t); } }  // leaks across requests
// VULN — APCu/cache keyed without principal id for identity-dependent data.
// SAFE — request-scoped instance (not static), or cache key includes the principal id; reset persistent singletons between requests.
```
```php
// VULN — shared Guzzle client with cookies enabled and/or a default auth header: ['cookies' => true]
// creates ONE cookie jar for ALL requests by this client, and a default 'headers' Authorization is sent on
// every call — so user A's session cookie/token rides on user B's request. (Symfony HttpClient: a singleton
// with auth_bearer baked in via withOptions reused across users is the same bug.)
$client = new GuzzleHttp\Client(['cookies' => true, 'headers' => ['Authorization' => "Bearer $token"]]);
// SAFE — reuse the client for pooling, but pass a FRESH jar + auth per request (or 'cookies' => false).
$res = $client->get('/api/resource', ['cookies' => new GuzzleHttp\Cookie\CookieJar(),
                                      'headers' => ['Authorization' => "Bearer $token"]]);
```

### C# / .NET

```csharp
// VULN — singleton HttpClient with mutated DefaultRequestHeaders.Authorization (classic .NET race).
_http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
var res = await _http.GetAsync("/api/resource");
// SAFE — per-request HttpRequestMessage carries the header; reuse the HttpClient instance.
var req = new HttpRequestMessage(HttpMethod.Get, "/api/resource");
req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
var res = await _http.SendAsync(req);
```
```csharp
// VULN — connection-bound auth (NTLM/Kerberos/Negotiate, or mTLS) on a SHARED pooled connection.
// With UnsafeAuthenticatedConnectionSharing, a connection authenticated as user A is reused for user B,
// and B's request is served as A — no header is mutated. (Same class: any pooled keep-alive + connection-bound auth.)
handler.UnsafeAuthenticatedConnectionSharing = true;   // do NOT enable when one process serves multiple identities
// SAFE — isolate connections per identity (separate handler/connection group per user) or per-call credentials.
```
```csharp
// VULN — IMemoryCache keyed without principal; DI lifetime bug: Singleton service holding Scoped/per-request state; AsyncLocal misuse.
_cache.GetOrCreate("resource", e => api.GetResource());   // same entry for all callers
// SAFE — _cache.GetOrCreate($"resource:{userId}", ...);  register per-request state as Scoped, not Singleton.
```
```csharp
// VULN — typed HttpClient from IHttpClientFactory but auth set on the shared DefaultRequestHeaders
// (the underlying handler is pooled/shared) → same concurrency race as a raw singleton HttpClient.
_typed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
// VULN — EF Core DbContext registered as Singleton (or a static/captured context): DbContext is NOT
// thread-safe and its change-tracker/identity map serves one request's entities to another.
services.AddSingleton<AppDbContext>();                 // must be Scoped (per request)
// VULN — FusionCache/LazyCache/CacheManager GetOrAdd keyed without the principal for per-user data.
// SAFE — per-request HttpRequestMessage header; AddDbContext (Scoped); cache key includes the principal.
```
```csharp
// VULN — RestSharp RestClient reused with an Authenticator (or default header) set on the CLIENT, or a Flurl
// IFlurlClientCache client with .WithOAuthBearerToken on the CACHED client → one identity serves all callers.
var client = new RestClient(opts) { Authenticator = new JwtAuthenticator(token) };   // shared client auth
// SAFE — auth per request: RestSharp new RestRequest(...).AddHeader("Authorization", $"Bearer {token}");
//        Flurl flurlClient.Request(url).WithOAuthBearerToken(token) per call (the cached client carries no auth).
var req = new RestRequest("/api/resource").AddHeader("Authorization", $"Bearer {token}");
```

### Rust

```rust
// VULN — global cache (once_cell/lazy_static, or a moka::Cache / DashMap) of identity-dependent data
// keyed without the principal; or a shared reqwest::Client with a default auth header / enabled cookie_store.
static RESOURCE: Lazy<Mutex<Option<Record>>> = Lazy::new(|| Mutex::new(None));   // one value for everyone
static CACHE: Lazy<moka::sync::Cache<String, Record>> = Lazy::new(|| moka::sync::Cache::new(10_000));
// SAFE — key by principal (Cache<UserId, _> / DashMap<UserId, _>) or fetch per request; pass the token
//        per-request (.bearer_auth(token)) and do NOT enable a shared cookie_store on a multi-user client.
```

### Elixir / Erlang (Phoenix)

```elixir
# VULN — :persistent_term and (named/public) ETS are GLOBAL across all processes; storing per-user/per-tenant
# data there, or keying an ETS cache without the tenant, serves one user's value to every other process.
:persistent_term.put(:current_user, user)          # global — shared by all requests on the node
:ets.insert(:resource_cache, {:resource, value})   # key omits tenant → cross-tenant read
# VULN — tenant kept in the process dictionary but NOT re-propagated across a process boundary:
# Task.async / start_async / a GenServer.call run in a DIFFERENT process with no tenant set.
Task.async(fn -> Repo.all(Resource) end)           # no tenant in the spawned process
# SAFE — ETS/:persistent_term only for stateless/public data, or include tenant in the key; keep per-request
# identity in the request process (Process dictionary / conn assigns) and re-set it before crossing a boundary.
tenant = Tenant.current(); Task.async(fn -> Tenant.put(tenant); Repo.all(Resource) end)
```

### Scala (Cats Effect / Akka / Play)

```scala
// VULN — a shared cache (Caffeine, Play `cache`, a global `TrieMap`) or an sttp/STTP backend whose auth is
// held in shared mutable state, keyed/scoped without the principal — concurrent fibers/actors collide.
val cache = Caffeine.newBuilder().build[String, Record]() ; cache.get("resource", _ => api.fetch())
// SAFE — carry identity explicitly (Cats Effect `IOLocal`, a Reader/`Kleisli` env, an explicit param) and
// include the principal in any cache key; never stash "current user" in an actor field reused across messages.
```

### Clojure

```clojure
;; VULN — clojure.core/memoize or a global atom/core.cache holding identity-dependent data with no principal
;; in the key; or a dynamic var rebound per request but read after crossing a thread (future/pmap/core.async).
(def fetch-resource (memoize (fn [] (api-get "/api/resource"))))   ;; one cached value for everyone
;; SAFE — include the principal in the memo/cache key, or pass identity as an argument; use (binding ...)
;; with `bound-fn`/conveyed bindings so futures/agents keep the right principal.
(def fetch-resource (memoize (fn [user-id] (api-get "/api/resource" user-id))))
```

### Headless browser / SSR-render worker (Node — Puppeteer/Playwright)

```js
// VULN — one Browser reused for every tenant's PDF/SSR job; between jobs only cookies are cleared.
// A page from tenant A can register a Service Worker (or poison the HTTP/DNS cache); it survives the
// "cleanup" and intercepts tenant B's later render of a sensitive document — cross-tenant theft / render hijack.
const browser = await puppeteer.launch();                  // long-lived, shared across all jobs/tenants
async function render(url, authCookie) {
  const page = await browser.newPage();
  await page.setCookie(authCookie);
  await page.goto(url, { waitUntil: 'networkidle0' });
  const pdf = await page.pdf();
  await page.deleteCookie(authCookie);                     // clears cookies only — SW/cache/DNS/sockets persist
  await page.close();
  return pdf;
}

// SAFE — isolate each job in a fresh, throwaway context (own SW/cache/cookie partition); destroy it after.
async function render(url, authCookie) {
  const ctx = await browser.createBrowserContext();         // ephemeral, isolated storage partition
  try {
    const page = await ctx.newPage();
    await page.setCookie(authCookie);
    await page.goto(url, { waitUntil: 'networkidle0' });
    return await page.pdf();
  } finally {
    await ctx.close();                                      // disposes SW registrations, caches, sockets
  }
}
// Stronger: one browser process per tenant/job (or a pool that recycles the whole process); block Service
// Worker registration for untrusted content; disable the disk cache for the render profile.
```

## Popular clients — the shared-state knob to check

Quick lookup of widely-used HTTP/GraphQL/SDK clients and the **exact shared-state API** that leaks across users when the client is reused process-wide. The fix is always the same shape: **reuse the client for pooling, but carry auth/cookies per request** (or scope the client per user).

| Client (language) | Leaky shared-state API | Safe per-request form |
|---|---|---|
| axios / got / ky (JS) | `instance.defaults.headers`; shared cookie jar | per-call `headers`; fresh jar per request |
| graphql-request (JS) | `client.setHeader()`/`setHeaders()` | `request(doc, vars, headers)` |
| undici / global `fetch` (Node) | shared dispatcher / `setGlobalDispatcher`; cookie interceptor | per-request headers; no shared jar |
| Apollo / urql / DataLoader (JS) | module-level client/loader (built-in dedup) | per-request client/loader |
| TanStack/React Query, SWR (JS) | `QueryClient`/cache at module root (SSR) | new client per server request / `React.cache()` |
| requests (Python) | `Session.headers`, `Session.cookies` | per-call `headers=`; session per user |
| httpx / aiohttp (Python) | shared client/session cookie jar + pool | `DummyCookieJar` / session per user |
| requests-oauthlib (Python) | `OAuth2Session` holds the token | session per user |
| net/http + cookiejar, go-resty (Go) | `DefaultClient`+jar; `client.SetAuthToken/SetHeader/SetCookieJar` | per-request header; `client.R().SetAuthToken()` |
| OkHttp / Retrofit (JVM) | client `cookieJar` / `Authenticator` | per-request `.header()` |
| Apache HttpClient (JVM) | `setDefaultCookieStore`; connection-bound NTLM/Kerberos | per-request `HttpClientContext` cookie store |
| Ktor (Kotlin) | `install(HttpCookies)` (shared storage) / `install(Auth)` (cached token) | per-call `bearerAuth(token)` |
| Spring RestTemplate / WebClient (JVM) | mutated default headers / interceptor field | per-request headers |
| OpenFeign (JVM) | interceptor reading a mutable/ThreadLocal token | request-scoped identity |
| gRPC stub/channel (JVM/Go/…) | channel-level / shared-stub `CallCredentials` | per-call `CallCredentials` |
| Guzzle / Symfony HttpClient (PHP) | `['cookies' => true]`; default `headers`/`auth_bearer` | fresh jar + auth per request |
| Faraday / HTTParty / RestClient (Ruby) | shared conn headers; HTTParty **class-level** `headers`/`basic_auth` | per-call headers |
| HttpClient / IHttpClientFactory (.NET) | `DefaultRequestHeaders.Authorization` | per-request `HttpRequestMessage` |
| RestSharp / Flurl (.NET) | client `Authenticator` / `.WithOAuthBearerToken` on cached client | per-`RestRequest` / per-`Request()` header |
| reqwest / awc (Rust) | default auth header; `cookie_store(true)` | `.bearer_auth(token)` per request |
| Puppeteer / Playwright (Node) | reused `Browser`/persistent context — Service Worker, HTTP+DNS cache, sockets survive cookie/storage clears | fresh `createBrowserContext()`/incognito per job + `ctx.close()`; or process-per-tenant |

**Connection-bound auth caveat:** for NTLM/Kerberos/Negotiate and mTLS the identity rides the *connection*, so even per-request headers don't help — isolate the connection/handler pool per identity (see the rule below).

## Safe Patterns (general)

- **Scope to the request/user.** Create the client/loader/cache per request, or per (user|tenant). Reuse is fine only for stateless transports that carry no identity.
- **Put identity in the key.** Any shared cache or de-duplicator must include `userId`/`tenantId`/session (or a stable hash of the auth token) in its key when the value is identity-dependent.
- **Never mutate shared client state per request.** Pass auth per call (per-request message/headers/metadata), not via `defaults`/`setToken`/a mutable interceptor field on a singleton.
- **Reset pooled state.** On connection checkout reset role/`SET`/search_path/temp creds (use `SET LOCAL`, or `DISCARD ALL` on release); behind transaction-pooled proxies (PgBouncer) never rely on session-level `SET`; `ThreadLocal.remove()` in `finally`; clear worker singletons (Octane/Swoole) between requests.
- **Isolate connection-bound auth.** For NTLM/Kerberos/Negotiate or mTLS, keep a connection/handler (or connection group) per identity; never enable `UnsafeAuthenticatedConnectionSharing` in a multi-identity process. For gRPC use per-call `CallCredentials`, not channel-level creds, when callers differ.
- **Thread context explicitly.** Propagate identity via `ctx`/`contextvars`/`AsyncLocalStorage.run()`/Reactor `Context`/`DelegatingSecurityContext*` correctly; never use `SecurityContextHolder` `MODE_INHERITABLETHREADLOCAL` with thread pools; don't read async-context after an `await` that could run another request.
- **Keep serverless per-request state inside the handler.** In warm runtimes, module scope is shared across invocations/tenants — reserve it for stateless clients/pools only; use a tenant-isolation mode when caching per-tenant state is required.
- **Cache only non-identity/public data** in process-wide caches; per-user/per-tenant data → request-scoped or identity-keyed (include `tenantId` at *every* caching layer: app cache, ORM L2/query cache, Redis/Memcached namespace, response cache `sessionId`).
- **Isolate headless render jobs.** Don't reuse one `Browser`/persistent context across tenants while relying on cookie/storage clearing — render each job in a fresh ephemeral `BrowserContext` (or a fresh browser process) and destroy it afterward; block Service Worker registration for untrusted pages and disable the disk/DNS cache so job N cannot intercept job N+1's render.

## Business Risk

- Disclosure of another user's PII/credentials/balances/tokens to an unrelated user — typically **High/Critical**, mass-impact, and a reportable data breach.
- Cross-tenant leakage in multi-tenant SaaS (one customer reads another's data).
- Wrong-user **writes** when mutable-auth races mis-route a mutation (integrity, not just confidentiality).

## Triage / Severity

- **Critical**: shared structure returns another identity's sensitive data (PII, tokens, financial) to an unauthenticated-relative-to-that-data user; cross-tenant leak.
- **High**: cross-user leak of moderately sensitive per-user data, or wrong-user write, under realistic concurrency.
- **Medium**: identity-keyless cache of low-sensitivity per-user data, or a race that requires a narrow timing window and uncommon load.
- **Low/Info**: shared client/cache present and per-user-ish, but no demonstrated cross-identity value reaches an output (defense-in-depth gap), or the deployment is provably single-tenant/single-worker per user.

## FALSE POSITIVE Rules

- **Identity IS in the key** — if the cache/dedup key provably includes `userId`/`tenantId`/session (or an auth-token hash), it is safe; cite the key construction.
- **Per-request scope** — if the client/cache/loader is created per request (not memoized/singleton/static), there is no cross-user structure; cite the construction site.
- **Public / identity-independent data** — caching/coalescing non-personalized data (feature flags, public catalog, static config) on a shared client is correct, not a finding.
- **Stateless transport reuse** — reusing an `HttpClient`/`http.Client`/`reqwest::Client`/connection pool itself is fine and recommended **when** auth is passed per-call and no per-user state is stored on the instance. Only flag when identity is held as shared mutable state or in an identity-less key. **Exception (still a finding):** the auth is *connection-bound* (NTLM/Kerberos/Negotiate, mTLS) on a pooled/shared connection, or a shared cookie jar persists a user's session cookie — there identity rides the connection/jar, so reuse leaks even without a mutated header.
- **Mutations under urql/Apollo** — query dedup does not merge mutations (urql compares `_instance` for mutations); don't flag mutation paths for the dedup sub-class.
- **Single-worker-per-user / process isolation** — CLI tools, per-user sandboxes, or a worker model that provably serves one identity per process lifetime: not cross-user. Verify before dismissing (most web servers multiplex users per process). **Note:** warm serverless instances (Lambda/Cloud Functions/Azure Functions) are reused across *different* users/tenants unless an explicit tenant-isolation mode is configured, so "it's serverless, so it's fresh" is **not** a valid dismissal for module-scope per-user state.
- **Prefer the neighbor tag** when the cache is an HTTP/CDN/edge cache keyed at the proxy → use `web_cache_deception`. Use `shared_client_cache_leak` when the shared cache/dedup/state lives **inside the application process** (client library, in-memory cache, singleton, pool, thread-local, global).
- **`ThreadLocal`/`contextvar` that is reset** — if `remove()`/proper `contextvars` binding is shown, the reuse path is closed.
- **Headless browser fully isolated per job** — if each render uses a fresh ephemeral `BrowserContext`/incognito (or a fresh browser process) that is closed afterward, the Service-Worker/cache/socket bleed path is closed; reusing only the *process* with per-job isolated contexts is fine.

## Core Principle

A shared cache, de-duplicator, client, connection, or global is only safe when its key (or its scope) matches the response's true **authority boundary**. If a value depends on *who* is asking, then *who* must be in the key — or the structure must be scoped to that one asker. Identity carried in headers, options, or mutable instance state is **not** in the key, and will leak across users the moment two requests overlap.
