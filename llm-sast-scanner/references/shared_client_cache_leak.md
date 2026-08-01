---
name: shared_client_cache_leak
version: "0.7"
description: Cross-user / cross-tenant data leakage via shared client caches, request deduplication/coalescing, mutable-auth singletons, shared cookie jars, pooled-connection or thread-local reuse, reused pooled buffers/objects not reset (sync.Pool, Netty ByteBuf/Recycler, fasthttp/Fiber RequestCtx reuse — residual-data bleed), singleton request-handler instance fields (servlet / Spring @Controller / JSF @ApplicationScoped), process-global locale/timezone mutation, and module-global request state — identity omitted from the cache/coalescing key or held in process-shared state. Covers JS/TS (urql, Apollo, Apollo RESTDataSource, DataLoader, TanStack/React Query, SWR, axios, ofetch/$fetch, openapi-fetch, request, apisauce/wretch/Zodios shared-instance auth, typescript-memoize `@Memoize()`/`@MemoizeExpiring` (default key = first arg only, or `this` for a no-arg method → per-instance cache that is process-wide on a singleton), NestJS singleton providers, Buffer.allocUnsafe residual memory, AsyncLocalStorage enterWith/module-global, Express app.locals, Prisma/TypeORM/Sequelize/Mongoose, Next.js Full Route Cache / Data Cache / unstable_cache closure-captured identity / module-global in Server Components & Server Actions, RxJS module-level Subject/shareReplay on the server, Angular Universal SSR providedIn:'root' singleton state, InversifyJS/tsyringe/TypeDI singletons, Koa ctx.state/Hapi server.app), Python (requests, aiohttp, httpx, SQLAlchemy, Django/Flask caches, preforked-worker module globals (gunicorn/uWSGI), FastAPI app.state / sync-route threadpool threading.local, Django translation.activate/timezone.activate, django-tenants schema, Celery prefork task state), Go (singleflight, gorm method-chaining/`Session`, go-redis, go-resty, imroc/req, gin/echo pooled Context needing `c.Copy()`, ctx-in-struct, package-level sync.Map), Java/Kotlin (Caffeine, Spring @Cacheable/WebClient/RestClient, OkHttp, Ktor, Unirest, Vert.x WebClientSession, Hibernate L2, gRPC, SLF4J MDC not cleared on pooled threads, WebFlux/Reactor ThreadLocal vs Context, Jackson ObjectMapper per-request mutable config, static SimpleDateFormat), Ruby (Rails.cache, Faraday, HTTParty class-level config, Excon/Typhoeus shared-connection headers, ActiveSupport::CurrentAttributes leaking into Sidekiq jobs/threads, acts_as_tenant/Apartment tenant-bleed, class variables, Time.zone=/I18n.locale= vs use_zone/with_locale), PHP (Guzzle, Octane/Swoole), OpenAPI-generated clients, C#/.NET (HttpClient, IHttpClientFactory, EF Core, IMemoryCache/FusionCache), Rust (moka, reqwest, tokio thread_local vs task_local across .await, actix web::Data / axum State/Extension app-wide state, sqlx/SeaORM/Diesel pool SET), Elixir/Phoenix (:persistent_term, ETS, Tesla/Req shared-auth client), Scala, Clojure, and reused headless-browser / SSR render workers (Puppeteer/Playwright "headless context bleed"), and GraphQL federation-router / API-gateway request de-duplication (WunderGraph Cosmo Router single-flight / inbound dedup with identity set in an `OnOriginRequest`/`EnginePreOriginHandler` hook or coprocessor outside the dedup key, Apollo Router query dedup) (CWE-488 / CWE-524 / CWE-567 / CWE-362)
---

# Shared-Client Cache / Dedup Cross-User Leak

A process-shared object — an HTTP/GraphQL/SDK client, a cache, a request de-duplicator, a connection from a pool, a thread-local, or a plain module global — serves **one user's data to another** because the per-user identity (auth token, session, `userId`, `tenantId`) is **not part of the key** that the shared structure uses, or is stored as **shared mutable state** instead of being scoped to the request.

This is the in-process sibling of `web_cache_deception.md` (which covers HTTP/CDN/edge caches). Here the leak happens **inside the application process**, not at a proxy. It is framework- and language-agnostic and almost always **only reproduces under concurrency / load**, which makes it invisible to single-user testing and easy to ship.

The canonical trigger:

> A singleton client (`memoize`/`lazy`/`static`/global) runs the same operation for every user. The operation key is derived from the request shape (query+variables, URL, method args) but the identity travels in headers / options / mutable instance state. Two concurrent users collide on the same key, and the structure returns the first user's response to both.

## Root-Cause Sub-Classes

1. **In-flight request deduplication / coalescing** — concurrent identical operations are merged into one upstream call; the winner's auth is used, all callers get the winner's data. Also at the **GraphQL federation-router / API-gateway** layer (WunderGraph **Cosmo Router** `enable_single_flight` / `enable_inbound_request_deduplication`; **Apollo Router** query deduplication): the dedup key is `operation + variables + a hash of the DECLARATIVELY-FORWARDED headers`, computed **before** the origin/coprocessor hook runs — so any per-user/tenant identity injected *after* the key is built (a Cosmo `EnginePreOriginHandler.OnOriginRequest` header, an Apollo Router coprocessor/rhai header, or identity carried in a header that isn't in the forwarded set) is **not in the key**. Two concurrent callers with the same operation shape then collide and one caller's subgraph response (and PII) is served to the other. The router normally **auto-disables** dedup when such a hook is registered; `force_enable_single_flight` / `force_enable_inbound_request_deduplication` override that safety.
2. **Response / object cache keyed without identity** — an authenticated response or per-user object is stored under a key that omits identity, then replayed to others. Includes server-side GraphQL/HTTP response caches whose `sessionId`/scope is missing or mis-set (e.g. a `PRIVATE` response cached without a per-user session key, so all logged-in callers share one entry).
3. **Shared client carrying per-request auth as mutable instance state** — `client.defaults.headers`/`setToken()`/an interceptor field is mutated per request on a singleton; under concurrency requests read each other's token (or the wrong response). Also a **shared cookie jar** (`Session.cookies`, a shared `CookieJar`/cookiejar) that persists one user's `Set-Cookie`/session cookie and replays it on another caller's request.
4. **Pooled connection / thread-local reuse** — a DB/HTTP connection or a `ThreadLocal`/`contextvar` retains identity/session state (role, `SET`/`SET ROLE`/`search_path`, RLS `SET app.current_tenant`, temp tables/creds, "current user") from a previous user of the pool/thread. Transaction-pooled proxies (e.g. PgBouncer `pool_mode=transaction`) silently leak session-level `SET`s to the next client unless `SET LOCAL` is used.
5. **Module-global / static request state** — a global/static variable is assigned the "current user/request" and read by concurrent requests. In **warm serverless** runtimes (Lambda/Cloud Functions/Azure Functions) module-scope state persists across invocations, so global per-user/per-tenant data leaks to later invocations on the same warm instance.
6. **Context propagation lost across `await`/goroutine/operator** — request identity stored in async-context (`AsyncLocalStorage`, `contextvars`, Reactor `Context`, Kotlin coroutine context, Spring `SecurityContext`) is read after it was overwritten by an interleaved request, or is not propagated onto a pooled worker thread (e.g. `SecurityContextHolder` `MODE_INHERITABLETHREADLOCAL` + a reused thread-pool thread → previous user's principal).
7. **Connection-bound credentials reused across identities** — schemes that bind identity to the *transport connection* rather than the request (NTLM/Kerberos/Negotiate, mutual-TLS client certs, a gRPC channel's channel-level credentials). Pooling/sharing that connection or channel lets a later, different user inherit the earlier user's authenticated identity — even when no header is mutated.
8. **Reused stateful headless browser / render worker ("headless context bleed")** — a pooled headless browser (Puppeteer/Playwright/`chromedp`) or a persistent `BrowserContext`/`userDataDir` profile is reused across tenants for SSR / PDF / screenshot / scrape jobs. Clearing cookies + `localStorage` between jobs does **not** clear a registered **Service Worker**, the HTTP/disk cache, the **DNS cache**, the keep-alive connection pool, IndexedDB / CacheStorage, or in-memory JS globals. So a page from job N (attacker) that registers a Service Worker or poisons a cache can **intercept or rewrite the render of job N+1 (victim)** — executing inside the backend network — turning a blind SSR/PDF bot into a persistent cross-tenant exfiltration / render-hijack channel. The renderer is also an SSRF sink (see `ssrf.md`) and the intercepted state enables backend-internal `xs_leaks.md`-style probing.
9. **Shared / un-keyed LLM agent conversation memory** — a chat/agent memory object that holds one user's conversation but is **process-shared or keyed without the principal**, so a later request reads the previous user's history into its context (cross-user disclosure, and prompt-injection blast-radius). Signals: a **module-global / singleton** `ConversationBufferMemory()`/`ConversationSummaryMemory()`/`ConversationBufferWindowMemory()` (LangChain), `ChatMemoryBuffer.from_defaults()` (LlamaIndex), a `RunnableWithMessageHistory` / `get_session_history` whose `session_id` is constant/missing, a `Mem0`/`zep`/vector "memory" store queried without a `user_id`/`session_id` filter, or a server-side `messages = [...]` history list at app scope. The fix is the same identity-in-the-key rule: scope every memory read/write by the authenticated `user_id`+`session_id` (`memory_key`/`chat_store_key`/`session_id` bound to the principal), never a module-global or constant key. Distinct from *memory poisoning* (`prompt_injection.md`) — that is attacker content re-injected; this is one user's data leaking to another.
10. **Reused pooled *buffer / object* not reset (residual-data bleed)** — distinct from the *connection* pool (sub-class 4): an in-memory **buffer or object pool** hands back an item that still holds the **previous request's bytes/fields** because it wasn't zeroed on `Get`/`Put`. The next request reads the stale contents → another user's response body, token, or PII bleeds out (the app-layer Heartbleed/Cloudbleed shape). Signals: Go `sync.Pool` of `*bytes.Buffer`/`[]byte` used without `buf.Reset()` **before** use (reset-on-Get is safest — `Put` may be skipped on panic/early-return); a reused `bytes.Buffer`/`byte[]`/`StringBuilder`/`char[]` written with a *smaller* payload than the previous one and then read by `capacity`/length-of-prior instead of bytes-actually-written; Java Netty `io.netty.util.Recycler` / a pooled `ByteBuf` read past `writerIndex` (pooled memory is **not** zeroed on allocate); Apache **Commons Pool** `PooledObject` returned without a `passivateObject`/clear; and — the canonical framework case — a **request/response context object that the framework pools and reuses across keep-alive requests**: `fasthttp` `*RequestCtx`, `gofiber` `*fiber.Ctx`, and **`gin` `*gin.Context` / `echo` `Context` (pooled via `sync.Pool` and reset for the next request)** are **reused by the next request the moment the handler returns**, so retaining a reference to the ctx (or its `Args`/body/header members) in a goroutine, cache, or struct field leaks/overwrites across users (gin: call `c.Copy()` before a goroutine; fasthttp: `c.Context()` / copy out the bytes inside the handler). **Fix**: reset-on-Get *and* on-Put; never read a pooled buffer past bytes-written; never retain a pooled framework ctx/buffer past the handler.
11. **Singleton request-handler holding per-request state in an instance field** — the container instantiates the handler **once** and every concurrent request runs on that one object, so any *mutable instance field* assigned per request is shared and races/leaks across users. Classic shapes: a **servlet** instance field (servlets are container singletons), Struts 1 `Action`, a Spring `@Controller`/`@RestController`/`@Service`/`@Component` (**default singleton scope**) instance field, a JAX-RS root resource under a per-application lifecycle, a gRPC service-impl field, and a JSF/CDI **`@ApplicationScoped`/`@Singleton`** bean storing a per-user value. The field set by request A is read by request B → cross-user data disclosure or wrong-user write. **Fix**: keep handlers **stateless** — per-request data lives in locals / the request object / method params; if state is unavoidable use a request-scoped bean (`@RequestScope`/`@Dependent`) or a properly-cleared `ThreadLocal`, never a singleton field.
12. **Shared LLM KV / prefix cache with position-independent reuse (cross-tenant answer integrity)** — inference engines that cache **transformer past_key_values / KV blocks** for prompt prefixes or document chunks and **reuse those tensors across requests/tenants** — especially with **position-independent** chunk reuse (reuse a middle chunk's KV even when the preceding tokens differ) — let one caller poison the reusable block so later callers with the same shared context get **attacker-chosen answers**. Distinct from sub-class 9 (conversation *text* memory) and from classic prompt injection (`prompt_injection.md`): the sink is the **KV store / block manager**, not the prompt string. **VULN**: a process-/cluster-global map keyed only by `chunk_hash` / document id / token-block id with **no** tenant/trust-domain and **no** full-prefix binding; `enable_prefix_caching` / AutomaticPrefixCaching / radix-tree prefix cache / CacheBlend-style PI reuse across multi-tenant traffic; `past_key_values` returned from a shared store into another user's decode. Staff claim *"same document chunk ⇒ same KV is SAFE"* is **false** under PI reuse: KV for a chunk depends on the **prefix that produced it**; an adversarial prefix can leave a reusable middle chunk that steers later victims. **Do not CLOSE** as "performance feature" or "identity-independent public content." **SAFE**: isolate KV/prefix caches **per tenant / trust domain**; key by tenant + **full prefix hash** (not middle-chunk alone); disable PI/prefix caching across tenants; or force full recompute (`recomp_ratio = 1.0` / no cache) when untrusted prefixes can touch shared documents. Grep: `enable_prefix_caching|AutomaticPrefixCaching|prefix_caching|past_key_values|CHUNK_KV|radix.?cache|CacheBlend|position.?independent|block_manager|kv_cache`.

## Where to Look

- **Client construction at shared scope**: `memoize(() => new Client(...))`, `lazy`/`once_cell`/`lazy_static`, module-level `const client = ...`, `static`/`@Bean`(singleton) clients, DI singletons, and **module-scope state in serverless handlers** (anything declared outside the handler in Lambda/Cloud Functions persists across invocations).
- **Dedup / coalescing primitives**: urql v4/v5 `Client` (built-in dedup, always on), Apollo Client query dedup, `DataLoader` (must be per-request), `p-memoize`/`pMemoize`, **`typescript-memoize` `@Memoize()`/`@MemoizeExpiring()`** (JS/TS method/getter decorator; **default key = the FIRST ARGUMENT only** — every later arg, incl. an identity/token passed after the first, is dropped — or `this` for a no-arg method/getter; the cache Map is stored on the *instance*, so a module-level singleton makes it process-wide; `@MemoizeExpiring` only adds a TTL, not identity), Go `singleflight.Group`, Caffeine/Guava `LoadingCache.get(k, loader)`, `async_lru`, custom "in-flight promise" maps, and **federation-router / API-gateway request dedup** (Cosmo Router `enable_single_flight`/`enable_inbound_request_deduplication` and their `force_enable_*` overrides — grep `force_enable_single_flight|force_enable_inbound_request_deduplication|OnOriginRequest|EnginePreOriginHandler`; Apollo Router query dedup + a coprocessor/rhai step that sets per-user identity).
- **Caches**: `lru-cache`, **TanStack/React Query `QueryClient`** and **SWR** global cache (must be per server request), `IMemoryCache`/`FusionCache`/`LazyCache`, `cachetools`(`TTLCache`/`@cached`)/`requests-cache`/`aiocache`, **Django `cache.get_or_set`/`@cache_page`**, **Flask-Caching `@cache.cached`**, Caffeine/Guava, Spring `@Cacheable`, Rails `Rails.cache`/`||=` memoization, `Dalli`/Memcached, PHP `static`/APCu, `functools.lru_cache`/`@cache`, Rust `moka`/`DashMap`, Go `go-redis`/`groupcache`/`bigcache`, Elixir `:persistent_term`/`:ets`, Clojure `memoize`/`core.cache`, a **module-level RxJS `Subject`/`BehaviorSubject`/`ReplaySubject` or `shareReplay()`** on a server (buffers/replays one request's value to the next subscriber; `shareReplay` defaults to `refCount:false` so it outlives subscribers) and an **Angular Universal `providedIn:'root'` singleton** holding per-request state (SSR shares one long-lived Node process), Next.js `unstable_cache` / `'use cache'` (closure-captured identity → not in key) / `React.cache()`, **Next.js Full Route Cache** (a personalized page with no dynamic API is prerendered once and served to all — force dynamic via `cookies()`/`headers()`/`connection()`/`export const dynamic='force-dynamic'`) and **Data Cache** (`fetch(..., {cache:'force-cache'})` whose per-user identity isn't in the key; also `fetch(new Request(...), differentInit)` body/method/header override vs cache-key split on App Router — see Next.js section), **server-side GraphQL/HTTP response caches** (Apollo Server `responseCachePlugin` + its `sessionId`, Mercurius cache, `@cacheControl` `PRIVATE`/`PUBLIC` scope), and any Redis/Memcached namespace shared across tenants.
- **ORM session / identity map / L2 cache**: a long-lived or module-global ORM session (global SQLAlchemy `Session` instead of `scoped_session`, a Hibernate `Session`/JPA `EntityManager` outliving the request, **EF Core `DbContext` registered as Singleton**, a global `*gorm.DB`) whose identity map / change-tracker returns another user's loaded entities; Hibernate/Ehcache second-level/query caches keyed without `tenantId`; per-session DB state (`SET ROLE`/`search_path`/`SET app.current_tenant`) on a shared `*sql.DB` pool. **Node ORMs**: a single shared **Prisma** client with a tenant set via `$extends`/middleware (`$use`) or a per-request `SET app.current_tenant`/`search_path` issued on the shared pool (leaks to the next checkout — use `$transaction` + `SET LOCAL`); **TypeORM**/**Sequelize**/**Knex** running `SET search_path`/`SET ROLE` on a pooled connection without reset; **Mongoose** models registered on the process-wide default connection so a tenant/`$where` scoping set globally applies to concurrent requests — scope the tenant as a query predicate, or use a connection/client per tenant.
- **The KEY**: what goes into the cache/dedup key — query+vars, URL, method args — and whether the auth token / session / `userId` / `tenantId` is in it or only in headers/options.
- **Mutable auth / shared cookies on shared clients**: `instance.defaults.headers.common['Authorization'] = ...`, `session.headers['Authorization'] = ...`, `client.setToken(...)`, `HttpClient.DefaultRequestHeaders.Authorization = ...` (incl. **`IHttpClientFactory` typed clients**), Spring `RestTemplate`/`WebClient` mutated default headers, **OkHttp `CookieJar`/`Authenticator`**, Ruby **Faraday** shared connection, Python **`aiohttp.ClientSession`/`httpx` shared cookie jar + pool**, interceptors reading a mutable field, and a **shared cookie jar** (`requests.Session.cookies`, a process-wide `http.cookiejar`/`CookieJar`, `axios` + shared jar, `reqwest` `cookie_store`) that accumulates one user's session cookie.
- **Connection-bound credentials**: NTLM/Kerberos/Negotiate or mTLS on a pooled keep-alive connection, `UnsafeAuthenticatedConnectionSharing`, a gRPC **channel-level** credential / shared stub used for many users.
- **Pools / thread-locals**: connection-pool checkout without reset, transaction-pooled DB proxies (PgBouncer transaction mode) + session `SET`s, `ThreadLocal` without `remove()`, .NET **`[ThreadStatic]`** for "current user" (leaks on pooled threads **and** is wrong across `await` — use `AsyncLocal`), `contextvars`/`AsyncLocalStorage`/`Thread.current[...]` for "current user", Rust **`thread_local!`** for request identity under an async runtime (tokio's work-stealing scheduler moves the task across worker threads at `.await` — use `tokio::task_local!` + `.scope(...)`), `SecurityContextHolder` `MODE_INHERITABLETHREADLOCAL` with thread pools, and `@Async`/`Executor`/reactive pipelines that don't propagate the security context; **SLF4J/Logback `MDC.put` not `MDC.clear()`'d in a finally** (bleeds to the next request on the pooled Tomcat thread; also not propagated to `@Async`/executor threads); **Spring WebFlux/Reactor** where ThreadLocal state (`SecurityContextHolder`/`MDC`/`RequestContextHolder`) is read on a hopped Netty thread instead of the Reactor `Context` (`contextWrite`/`deferContextual`; Micrometer `context-propagation`).
- **Buffer / object pools (residual-data bleed)**: `sync\.Pool`, a reused `bytes.Buffer`/`byte[]`/`StringBuilder` read by capacity not bytes-written, Netty `Recycler`/pooled `ByteBuf`, Apache Commons Pool without a clear on passivate — grep `sync\.Pool|\.Reset\(\)|bytes\.Buffer|Recycler|PooledByteBuf|GenericObjectPool`. **Framework ctx reuse**: `fasthttp` `*RequestCtx` / `gofiber` `*fiber.Ctx` / **`gin` `*gin.Context` / `echo` `Context`** retained after the handler returns — grep `RequestCtx|fiber\.Ctx|\*gin\.Context|echo\.Context|c\.Copy\(\)` used in a `go func`/struct field/cache (gin needs `c.Copy()` before a goroutine). **GORM chained-handle reuse**: a shared/mid-chain `*gorm.DB` (`DB.Where(...)` stored/reused) carries conditions across queries — grep a package-level `*gorm.DB` reassigned from a chain method without `WithContext`/`Session`. **ctx in a struct**: `ctx context.Context` as a struct/package field (grep `ctx\s+context\.Context` inside a `struct {`).
- **Singleton request handlers with instance fields**: a servlet / Spring `@Controller`/`@RestController`/`@Service` / Struts `Action` / JSF `@ApplicationScoped` bean with a **mutable non-final field** assigned in a request method — grep `@Controller|@RestController|@Service|@Component|extends HttpServlet|@ApplicationScoped|@Singleton` then look for non-final instance fields written per request; also OpenResty **module-chunk `local`** used as per-request state (per-worker-shared) vs `ngx.ctx`.
- **Process-global locale/timezone/format mutated per request**: `Locale.setDefault`/`TimeZone.setDefault` (Java), `setlocale`/`date_default_timezone_set` (PHP), `moment.tz.setDefault` (JS), `time.Local =` (Go), Django `translation.activate`/`timezone.activate` (thread-local — use `override()`), Rails `Time.zone=`/`I18n.locale=` (leak on the pooled Puma thread — use `Time.use_zone`/`I18n.with_locale` blocks in an `around_action`) — a global set from one request's locale/tz is read by concurrent requests (wrong currency/format/timestamps → data-integrity and location-inference leak). Pass locale/tz per operation instead.
- **Python long-lived server/worker per-request state**: a **module-level global** assigned per request under a preforked/threaded WSGI/ASGI worker (gunicorn/uWSGI) — the worker outlives the request, so it bleeds to the next request on that worker (grep a `global ` write in a view, or a module-scope `= None` reassigned in a handler); FastAPI/Starlette **`app.state`** holding per-user data (use `request.state`); a `threading.local` set inside a **sync `def`** FastAPI route (runs on a shared anyio threadpool → sticks to the pooled thread; prefer `contextvars`); a **Celery/RQ/dramatiq** class-based task `self`/module global reused across tasks (`worker_max_tasks_per_child=1` to recycle); gevent/eventlet greenlets clobbering a module global across a blocking yield. Grep: `^\s*global |app\.state\.|threading\.local\(|class \w+\(.*Task\)|worker_max_tasks_per_child|translation\.activate|schema_name`.
- **Headless render workers**: a long-lived `puppeteer.launch()`/`chromium.launch()` `Browser` reused across requests, a persistent `launchPersistentContext`/`userDataDir`, or a browser pool (`generic-pool`, `puppeteer-cluster`) where jobs only `page.deleteCookie()` / clear `localStorage` between tenants — leaving Service Workers (`navigator.serviceWorker.register`), CacheStorage/IndexedDB, the HTTP + DNS cache, and keep-alive sockets intact for the next tenant's job. Grep: `puppeteer|playwright|chromedp|launchPersistentContext|userDataDir|puppeteer-cluster|browser\.newPage`.
- **LLM KV / prefix caches**: process-global or cluster-shared stores of `past_key_values` / KV blocks keyed by document or chunk hash; vLLM/SGLang/TGI **prefix caching** / AutomaticPrefixCaching / radix-tree caches; position-independent chunk reuse across multi-tenant gateways. Grep: `enable_prefix_caching|AutomaticPrefixCaching|past_key_values|prefix_caching|kv_cache|block_manager|CacheBlend`.
- **More clients to enumerate (recall list — *no new mechanism*; same knobs as above: shared cookie jar / baked default-auth header / cached token / pooled connection. Fix is always: reuse for pooling but carry auth & cookies per request, or scope per identity):**
  - *Python*: `urllib.request` `install_opener` (process-global opener+cookies), `httplib2` (`add_credentials`/`add_certificate`), `pycurl` (reused handle + share interface), `treq`, `tornado` `AsyncHTTPClient.configure(defaults=…)`, `grequests`/`requests-futures` (wrap a shared `Session`).
  - *Node/TS*: `needle.defaults`, `superagent` `request.agent()`, core `http.Agent`/`globalAgent` keep-alive, `@grpc/grpc-js` reused `Metadata`/channel `CallCredentials`, Elasticsearch/OpenSearch JS `new Client({auth,headers})`.
  - *JVM*: `java.net.http.HttpClient` (installed `CookieHandler`/`Authenticator`), `org.asynchttpclient` `setCookieStore`, `google-http-client` `Credential` (cached token), `reactor-netty` default headers, Elasticsearch Java `RestClient.setDefaultHeaders`, Android `Volley` `CookieHandler`, Kotlin `Fuel` `FuelManager.instance.baseHeaders`.
  - *Go*: `parnurzeal/gorequest` (`New()` reuse persists cookies — needs `ClearSuperAgent()`), `dghubble/sling` (reused base `.Set("Authorization")` without `.New()`), `hashicorp/go-retryablehttp`, `gojek/heimdall`, `h2non/gentleman`.
  - *Ruby*: `mechanize` (agent persists session cookies + NTLM), `http.rb` `HTTP.persistent`/`.auth`/`.cookies`, `httpclient` gem (`cookie_manager`/`set_auth`/client cert), `Net::HTTP::Persistent` `override_headers`, `curb` `Curl::Easy` `enable_cookies`.
  - *PHP*: native `curl_share_init()`+`CURLOPT_SHARE` (cookie/DNS/TLS-session share), `WpOrg/Requests` session jar, `Buzz`, `php-http/HTTPlug` `AuthenticationPlugin`, `Unirest-PHP` `Request::defaultHeader`, `nategood/httpful`, `laminas-http`/`zend-http` `addCookie`, `amphp/http-client` + `InMemoryCookieJar`, `react/http` `Browser->withHeader`.
  - *.NET*: `Refit` (`[Headers("Authorization")]` + cached-token `AuthorizationHeaderValueGetter`).
  - *Swift / Obj-C*: `URLSession` + `HTTPCookieStorage.shared` (default) / `httpAdditionalHeaders`, `Alamofire` `Session`, `AFNetworking` — per-user session with isolated or `.ephemeral` cookie storage.
  - *Dart / Flutter*: `dio` + `dio_cookie_manager`/`cookie_jar` (`PersistCookieJar`), `BaseOptions.headers['Authorization']` — fresh `CookieJar`/`Dio` per user.
  - *Perl*: `LWP::UserAgent` `cookie_jar`/`credentials`/`conn_cache`.
  - *C / C++*: `libcurl` `CURLOPT_COOKIEJAR` + the share interface (`CURLSHOPT_SHARE`) — per-identity easy handle; no shared cookie/connection share.
  - *R*: `httr` `handle_pool()`/`handle()` (reuses handles+cookies by host, **not** by user — `handle_reset()` between users), `crul`.
  - *Cloud/vendor & OAuth SDKs (cached-token-on-singleton, sub-class 3 — flag only **user-delegated / per-tenant** creds, never app/service-account/infra creds)*: AWS SDK JS v3 / `aws-sdk-go` / AWS SDK for Rust (per-tenant creds/identity cache), `azure-identity` **delegated** flows (`OnBehalfOfCredential`/`AuthorizationCodeCredential`), `google-auth`/`googleapis`/`google-api-python-client`, `Twilio` `Client(sid,token)`, Slack `WebClient(token=…)`, `authlib` `OAuth2Session`, `simple-oauth2`/`client-oauth2`, `golang.org/x/oauth2` (`ReuseTokenSource`/`oauth2.NewClient` built from one user's token), `oauth2` gem, `league/oauth2-client` `AccessToken`, `octokit` bound `access_token`, Spring `OAuth2AuthorizedClientManager` (leak only if not keyed by principal).
- **More framework request-scopes to enumerate (recall list — *no new mechanism*; the same knobs as sub-classes 11/8/12 above — a singleton bean/handler with a per-request mutable field, an app-wide namespace used as per-request state, or a captive/undisposed per-user dependency. Fix is always: keep the handler stateless, put per-request data in a request-scoped bean / the request object, never on a process-shared one. Generative test note: senior authors shipped the `@Singleton`+`setCurrentUser` mutable-field leak 3/5 times — so grep the annotation, don't assume sub-class 11 is Spring/servlet-only):**
  - *JVM (singleton-bean field, sub-class 11)*: **Micronaut** `@Singleton`, **Quarkus / Jakarta EE CDI** `@ApplicationScoped`/`@Singleton` (vs `@RequestScoped`), **Jersey / RESTEasy** JAX-RS root resources (per-application lifecycle), **Play** `@Inject` controllers (singleton by default) — grep the annotation, then a non-final instance field assigned per request (or a `ThreadLocal` never `remove()`'d in `finally`).
  - *.NET*: **Blazor Server** an `AddSingleton` service holding `User`/`Cart` is shared across **every circuit = every user** — use `AddScoped` (scope = the SignalR circuit); **`IHttpContextAccessor`** captured on a singleton or read from a background/`Task.Run` thread (`HttpContext` is null or another user's); `IOptionsSnapshot`/`IServiceScopeFactory` misuse from a singleton.
  - *Python (app-wide namespace vs per-request)*: **Tornado** `RequestHandler` instance attr kept via a cached handler / `self.application.settings`, **Pyramid** `config.registry` app-global, **Sanic** `app.ctx` (app-wide) vs `request.ctx` (per-request).
  - *Node/TS*: **Remix / React-Router** module-scope loader state (use the per-request `context`), **Fastify** `decorate` (app-wide) vs `decorateRequest` (per-request).
  - *Ruby*: **Sinatra** `settings`/class-var globals, **Grape** helper / class-var state.
  - *PHP*: **Slim** container singletons holding per-request state, **WordPress** `global $`/persistent object cache (Redis/W3TC) keyed without the user, **Symfony** shared services that retain per-request state without `ResetInterface`/`kernel.reset` under Octane/Swoole/RoadRunner.

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

**`typescript-memoize` `@Memoize()` — default key is the FIRST ARG only (or `this` for a no-arg method), cached on the instance**
```ts
// VULN — @Memoize() with no hashFunction keys ONLY on args[0] and DROPS every later argument, so an identity/
// token passed AFTER the first arg is not in the key. On a module-level singleton the Map is process-wide, so
// two users requesting the same programId collide and user B receives user A's authorized balance.
class StoreCredits { @Memoize() getBalance(programId: string, token: string) { return api.get(`/c/${programId}`, hdr(token)) } }
export default new StoreCredits()                 // singleton → memoized cache shared across all requests/users
// VULN — a NO-ARG @Memoize() (or @Memoize get accessor) keys on `this`: one value per instance, so on a
// singleton every caller gets the FIRST caller's per-user value. (@MemoizeExpiring only adds a TTL, not identity.)
// SAFE — args[0] IS the principal and the value depends only on it; or per-request instance; or a hashFunction
// that puts identity in the key: @Memoize((id, uid) => `${uid}:${id}`).
class Statements { @Memoize() getStmt(userId: string, token: string) { return api.get(`/s/${userId}`, hdr(token)) } } // key = userId
```

**Next.js App Router in-process caches (`unstable_cache` / `'use cache'` / Data Cache / Full Route Cache)**
```ts
// VULN — unstable_cache / "use cache" CANNOT read cookies()/headers() inside the cache scope, so devs
// capture the user in a CLOSURE — but identity is then NOT in the key → one entry shared across all users.
const getResource = unstable_cache(async () => fetchResource(currentUserId), ['resource'])  // closure id, no key part
// SAFE — pass identity as an ARGUMENT (it becomes part of the key) or add it to keyParts; read cookies OUTSIDE.
const getResource = (uid: string) => unstable_cache(async () => fetchResource(uid), ['resource', uid])()
// SAFE (per-request only) — React.cache de-dupes within ONE render pass, never across requests/users.
import { cache } from 'react'; export const getReq = cache(async () => fetchResource())
```
```ts
// VULN — cached fetch() whose per-user identity is NOT part of the fetch key: auth via a COOKIE the fetch
// doesn't include, or the header stripped "to make it cacheable" — the personalized response is shared.
const r = await fetch('https://api/me', { cache: 'force-cache' })   // key = URL+options; cookie auth not in key
// SAFE — per-user data must be uncached: cache: 'no-store' (or don't route it through the Data Cache).
const r = await fetch('https://api/me', { cache: 'no-store', headers: { authorization: `Bearer ${token}` } })
```
```ts
// VULN — fetch(Request, differentInit): second-arg init OVERRIDES the Request for the upstream call, but
// Next's Data Cache historically keyed from incomplete/split metadata → two POSTs to the same URL with
// DIFFERENT bodies can share one cached RESPONSE body (cross-request confidential leak). Pages Router N/A;
// App Router only. Vulnerable next: >=13 <15.5.21 and >=16 <16.2.11 (patch merges into one effective Request).
// Do NOT CLOSE as "framework bug / just upgrade" when the call shape is still in app code on a vulnerable
// range — report the call site; remediations are upgrade AND/OR stop splitting Request vs init / use no-store
// for body-bearing fetches. Safe same-init form alone does not prove cache correctness on unpatched next.
const base = new Request(url, { method: 'POST', body: JSON.stringify({ id }), headers: authHdrs })
await fetch(base, { cache: 'force-cache', next: { revalidate: 60 }, headers: { 'x-request-id': rid } }) // differentInit
// SAFE shapes:
await fetch(new Request(url, init), init)                          // same init object (no override split)
await fetch(url, { method: 'POST', body, headers: authHdrs, cache: 'no-store' })  // single init; no Data Cache
```
```ts
// VULN — Full Route Cache: a page that shows per-user data but calls NO dynamic API (cookies/headers/
// searchParams) is statically prerendered ONCE and the same HTML is served to EVERY user.
export default async function Page() { return <Profile data={await getMyData()} /> }  // no dynamic API → static
// SAFE — force dynamic rendering for personalized routes: read cookies()/headers()/connection(), call noStore(),
// or `export const dynamic = 'force-dynamic'` — so the page renders per request.
export const dynamic = 'force-dynamic'
```
```ts
// VULN — a module-level global/cache in a Server Component, Route Handler, or Server Action ("use server"):
// the server is long-lived and shared, so it persists/races across all users' renders (cross-user bleed).
let currentUser: User                                            // module scope = shared by every request
export async function action() { currentUser = await getUser(); return render(currentUser) }
// SAFE — keep per-request data in locals / function args; module scope only for stateless clients/pools.
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

**NestJS provider/controller is a SINGLETON by default — a mutable field is shared across all requests** (Node instance of sub-class 11)
```ts
// VULN — @Injectable() defaults to Scope.DEFAULT (singleton): one instance for the whole app.
// A per-request field set in one request is read by another → cross-user data leak.
@Injectable() // === Scope.DEFAULT (singleton)
class OrdersService {
  private userId: string;                                  // shared across every request!
  async list(userId: string) { this.userId = userId; return this.repo.findByOwner(this.userId); }
}
// SAFE — stateless method (pass userId), or request-scoped provider when per-request state is unavoidable.
@Injectable({ scope: Scope.REQUEST })                       // fresh instance per request (note: scope bubbles up)
class OrdersService { async list(userId: string) { return this.repo.findByOwner(userId); } }
```

**`Buffer.allocUnsafe` returns UNINITIALIZED memory — residual bytes of a prior request/heap leak** (Node instance of sub-class 10)
```ts
// VULN — allocUnsafe (and legacy new Buffer(size)) is not zeroed; if you don't FULLY overwrite it before
// sending, it emits leftover heap bytes — another request's body, a TLS key, a DB password.
const buf = Buffer.allocUnsafe(len);            // uninitialized; also `new Buffer(len)` (deprecated)
stream.read(buf); res.end(buf);                 // if fewer than `len` bytes written, the tail leaks old memory
// SAFE — Buffer.alloc() is zero-filled; or slice to exactly the bytes written; or run with --zero-fill-buffers.
const buf = Buffer.alloc(len); res.end(buf.subarray(0, bytesWritten));
```

**AsyncLocalStorage: `enterWith` + module-global "current user" leak the identity across concurrent requests** (Node instance of sub-class 6)
```ts
// VULN — a module-global holding the request principal (no ALS at all): concurrent requests overwrite it.
let currentUser: User;                                     // shared — request B clobbers A mid-flight
app.use((req,_res,next) => { currentUser = req.user; next() });
// VULN — als.enterWith(store): unlike run(), it has NO callback boundary, so the store bleeds into
// subsequent event-loop work / other handlers on the same tick → auth reads another user's session.
als.enterWith({ user: req.user });
// SAFE — wrap the whole request in als.run(store, next); read via als.getStore() (never a module global).
app.use((req,_res,next) => als.run({ user: req.user }, next));
```

**Express `app.locals` is application-wide (merged into every render); only `res.locals` is per-request**
```ts
// VULN — per-user data in app.locals is shared by ALL requests and merged into every view render → cross-user leak.
app.locals.user = req.user;                                // app-wide, not per-request
// SAFE — res.locals is scoped to this request/response cycle.
res.locals.user = req.user;                                // (Fastify analog: decorateRequest, NOT decorate())
// Koa: ctx.state is per-request (safe); a module global is not. Hapi: request.app is per-request, server.app is app-wide.
```

**RxJS on the server: a module-level Subject / `shareReplay()` holds one request's value and replays it to the next**
```ts
// VULN — a module-scope BehaviorSubject/ReplaySubject (or a shareReplay()-cached Observable) lives for the whole
// process, so on a long-lived Node/Nest/Angular-SSR server it emits/replays user A's value to user B's subscribe.
export const user$ = new BehaviorSubject<User | null>(null);          // shared across all requests
export const profile$ = this.http.get('/me').pipe(shareReplay(1));    // refCount:false → buffered value shared
// SAFE — create the stream per request (don't hoist to module scope); if you must share, key the cache by
// principal and use shareReplay({ bufferSize: 1, refCount: true }) so it doesn't outlive its subscribers.
function profileFor(uid: string) { return http.get(`/users/${uid}`).pipe(shareReplay({ bufferSize: 1, refCount: true })); }
```

**Angular Universal SSR: a `providedIn: 'root'` singleton (or a pending subscription) leaks across requests**
```ts
// VULN — SSR runs in ONE long-lived Node process; a root singleton that stores per-user state (or starts a
// subscription/timer not torn down) is shared/raced across concurrent server renders → another user's data or
// token ends up on the rendered page (a documented Angular SSR cross-request data-leak class).
@Injectable({ providedIn: 'root' }) class SessionService { user!: User; }   // state shared across SSR requests
// SAFE — keep request state out of root singletons (use request-scoped providers / REQUEST token / TransferState),
// and unsubscribe in ngOnDestroy (Angular calls it for services on SSR app teardown).
```

**TypeScript DI containers (InversifyJS `inSingletonScope`, tsyringe `@singleton`, TypeDI) — same singleton-field bug as NestJS/Spring** (sub-class 11): a container-managed singleton with a mutable per-request field is shared across requests; bind request-scoped (or pass identity per call), never store the caller on a singleton.

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
```python
# VULN — module-level global assigned per request. A preforked WSGI/ASGI worker (gunicorn/uWSGI) is a
# LONG-LIVED process serving many users in sequence, so a module global persists to the NEXT request on
# that worker (the non-serverless analog of warm-instance bleed). Threaded workers make it a live race.
CURRENT_USER = None                                  # module scope = shared by every request on this worker
def view(request):
    global CURRENT_USER; CURRENT_USER = request.user # request B overwrites; a concurrent read gets wrong user
    return render(CURRENT_USER)
# SAFE — keep per-request data on the request object / a contextvar set+reset per request; never a module global.
```
```python
# VULN (FastAPI/Starlette) — app.state is APP-WIDE (one object for the whole process); per-user data there
# leaks across requests. Only request.state is per-request. Also: a `def` (sync) path operation runs in a
# SHARED anyio threadpool, so a threading.local "current user" set there stays on the pooled thread for the
# next request that reuses it (classic pooled-thread bleed; thread-locals are not per-request under async).
app.state.user = request.user                        # WRONG: shared across all requests
_tls = threading.local()                             # set in a sync route, never reset → next req on the thread inherits
# SAFE — request.state.user = ...  (per request); prefer contextvars over threading.local; reset any thread-local.
```
```python
# VULN (Django) — translation.activate()/timezone.activate() write THREAD-LOCAL globals (`_active = Local()`);
# if not deactivated, the next request on that (pooled/reused) thread inherits the previous user's language/tz
# → wrong-locale render and location/format inference (the translation layer is thread-local; activating it by hand without restoring is not request-safe).
translation.activate(request.user.lang)              # leaks to the next request on this thread
# Also: django-tenants / a per-request `SET search_path`/`schema_name` on the SHARED connection leaks to the
# next checkout of that pooled connection (same as PgBouncer transaction-mode / sub-class 4).
# SAFE — use the `override(lang)` / `timezone.override(tz)` context managers (auto-restore on exit); scope tenant
#        per-connection within a transaction (SET LOCAL) or via LocaleMiddleware, never a bare activate().
with translation.override(request.user.lang): return render(request)
```
```python
# VULN (Celery / RQ / dramatiq prefork worker) — the worker process is reused across tasks, and a class-based
# task is instantiated ONCE, so `self`/a module global holding one task's tenant/user state leaks to the next
# task (different tenant) run by the same worker process.
class Report(celery.Task):
    rows = []                                        # shared across every task run on this worker!
    def run(self, tenant_id): self.rows.append(load(tenant_id)); return summarize(self.rows)  # cross-tenant bleed
# SAFE — no task/instance/module state between runs; pass everything as task args; if unavoidable set
#        worker_max_tasks_per_child=1 (recycle the process per task) or use local variables only.
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
```go
// VULN — sync.Pool buffer used without reset: it may still hold the PREVIOUS request's bytes
// (token/PII), which then bleed into this response. Reset-on-Get is safest (Put may be skipped on panic).
var bufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}
func handle(w http.ResponseWriter, r *http.Request) {
    b := bufPool.Get().(*bytes.Buffer)          // NOT empty — carries the last user's contents
    defer bufPool.Put(b)
    render(b, r); w.Write(b.Bytes())            // leaks residual bytes if payload is shorter than before
}
// SAFE — reset before use (and only trust bytes actually written this request).
b := bufPool.Get().(*bytes.Buffer); b.Reset(); defer func(){ b.Reset(); bufPool.Put(b) }()
// VULN — retaining a fasthttp *RequestCtx / gofiber *fiber.Ctx past the handler: it is reused by the
// NEXT request the instant the handler returns, so the goroutine reads/overwrites another user's data.
func h(ctx *fasthttp.RequestCtx) { go audit(ctx) }        // ctx reused after h returns → cross-user bleed
// SAFE — copy the bytes out inside the handler (or use c.Context()); never keep the pooled ctx.
func h(ctx *fasthttp.RequestCtx) { p := append([]byte(nil), ctx.Path()...); go audit(p) }
```
```go
// VULN — gin/echo pool *gin.Context (sync.Pool) and RESET it for the next request. Passing c into a
// goroutine that outlives the handler means the goroutine later reads/writes a Context now owned by a
// DIFFERENT user's request → data race + cross-user leak.
func handler(c *gin.Context) { go func() { audit(c.GetString("user")) }() }   // c is reused after handler returns
// SAFE — gin: use c.Copy() for anything that outlives the handler; echo: copy the values out first.
func handler(c *gin.Context) { cp := c.Copy(); go func() { audit(cp.GetString("user")) }() }
```
```go
// VULN — reusing a CHAINED *gorm.DB carries conditions across queries: a shared/mid-chain handle keeps the
// previous WHERE, so a tenant filter is duplicated or (worse) a stale tenant scope bleeds into another
// request's query → wrong-tenant rows. Method chaining clones per call, but a REUSED handle does not reset.
tenantDB := DB.Where("tenant_id = ?", tid)         // if shared across requests, conditions accumulate/leak
// SAFE — start a fresh session per request/query: WithContext / Session (New Session Methods reset conditions).
db := DB.WithContext(ctx).Session(&gorm.Session{}); db.Where("tenant_id = ?", tid).Find(&rows)
```
```go
// VULN — a context.Context (carrying per-user identity via ctx.Value) stored in a shared struct/package
// field: concurrent requests overwrite it, so a method/goroutine reads another user's ctx (Go's own guidance:
// do NOT store Context in a struct — pass it per call).
type Service struct { ctx context.Context }        // shared instance → ctx clobbered by concurrent requests
// SAFE — pass ctx as the first arg of each method; never stash the request ctx (or a package-global map) as state.
func (s *Service) Do(ctx context.Context) { ... }
// VULN — a package-level sync.Map / map[string]T used as an in-process cache keyed without the tenant/user.
// SAFE — include tenantID/userID in the key, or scope the map per request.
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
// VULN — Spring @Controller/@Service is a SINGLETON by default; a mutable instance field set per request
// is shared by every concurrent request → user B reads user A's value (same bug as a servlet instance field).
@RestController class OrderController {
  private User currentUser;                                  // shared across all requests!
  @GetMapping("/orders") List<Order> list(@AuthenticationPrincipal User u) {
    this.currentUser = u;                                    // request B overwrites while A still running
    return orderRepo.findByOwner(this.currentUser.id());     // A may now read B's user → cross-user leak
  }
}
// SAFE — keep the handler STATELESS: per-request data stays in locals/params (or a @RequestScope bean).
@GetMapping("/orders") List<Order> list(@AuthenticationPrincipal User u) { return orderRepo.findByOwner(u.id()); }
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
```java
// VULN — SLF4J/Logback MDC.put() in a filter but NOT cleared: Tomcat reuses the request thread, so the
// NEXT request inherits the previous user's MDC (wrong-user log correlation; leak if MDC is rendered/returned).
// Also MDC is thread-bound, so it is NOT propagated to @Async/executor/CompletableFuture worker threads.
MDC.put("userId", user.id());                                   // never removed → sticks on the pooled thread
// SAFE — set in the OUTERMOST filter and MDC.clear() in finally; for async, snapshot getCopyOfContextMap()
//        then setContextMap()+clear() inside the task (a TaskDecorator does this).
try { MDC.put("userId", user.id()); chain.doFilter(req,res); } finally { MDC.clear(); }
```
```java
// VULN (Spring WebFlux / Reactor) — ThreadLocal-based state (SecurityContextHolder, MDC, RequestContextHolder)
// does NOT work reactively: the pipeline hops Netty threads and one thread serves many requests, so a
// ThreadLocal read returns another request's value (or none). Identity must ride the Reactor Context.
String uid = SecurityContextHolder.getContext()...;             // wrong/empty on a hopped reactive thread
// SAFE — carry identity in the Reactor Context and read it in-chain; use Micrometer context-propagation
//        (ThreadLocalAccessor) to bridge to ThreadLocal-based libs at the right points.
Mono.deferContextual(ctx -> service.load(ctx.get("userId")));    // .contextWrite(c -> c.put("userId", uid)) upstream
```
```java
// VULN — mutating a SHARED Jackson ObjectMapper per request (setFilterProvider/setInjectableValues/setDateFormat):
// the mapper is only thread-safe once config is frozen; per-request config races → wrong filter/value in another
// user's serialized output. VULN — a `static SimpleDateFormat`/NumberFormat is NOT thread-safe (interleaved
// concurrent format() corrupts/mixes output across requests).
mapper.setFilterProvider(perUserFilters);                       // shared mapper mutated per request → race/leak
// SAFE — derive an IMMUTABLE ObjectWriter/ObjectReader per request; use java.time DateTimeFormatter (thread-safe).
byte[] out = mapper.writer(perUserFilters).writeValueAsBytes(dto);
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
```ruby
# VULN — ActiveSupport::CurrentAttributes (Current.user) is reset per WEB request by the Rails executor,
# but NOT inside Sidekiq jobs or manually-spawned threads — so a job reads the PREVIOUS job's Current.user
# on the reused worker thread (cross-user), and Thread.new/Concurrent work started from a request runs
# without the reset either.
class Current < ActiveSupport::CurrentAttributes; attribute :user; end
class ReportJob; def perform(id); mail(Current.user); end; end   # Current.user is stale from a prior job
# SAFE — Sidekiq::CurrentAttributes.persist(Current) in an initializer, or reset in an ensure at job end.
def perform(id); Current.user = User.find(uid); do_work; ensure; Current.reset; end
```
```ruby
# VULN — multi-tenant tenant is a THREAD-GLOBAL set once and not reset: acts_as_tenant
# ActsAsTenant.current_tenant=, Apartment::Tenant.switch!, or Rails `connected_to(role:)`/`default_scope`
# keyed on Current.tenant — the next request/job on the same Puma/Sidekiq thread inherits the prior tenant
# → cross-tenant reads (the DB-side sibling of sub-class 4 with `SET search_path`).
ActsAsTenant.current_tenant = tenant            # not reset → bleeds to the next request on this thread
# SAFE — block-scoped set (auto-restore), and a Sidekiq middleware that resets in ensure.
ActsAsTenant.with_tenant(tenant) { do_work }    # Apartment::Tenant.switch(name) { } ; reset current_tenant in ensure
```
```ruby
# VULN — a class variable / class-level accessor is PROCESS-GLOBAL (shared across every thread of the
# worker), so per-request data there is read by concurrent requests. Also Time.zone=/I18n.locale= set
# without a block leak on the pooled Puma thread to the next request (TLS isn't cleared between requests).
@@current_user = user                            # class var: shared by all threads/requests in the process
Time.zone = user.time_zone; I18n.locale = user.locale   # leak to the next request on this thread
# SAFE — no class-level per-request state; use block forms that auto-restore (around_action).
Time.use_zone(user.time_zone) { I18n.with_locale(user.locale) { render } }
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
```rust
// VULN — thread_local! for "current user" is WRONG under an async runtime: tokio's work-stealing scheduler
// moves a task to a DIFFERENT worker thread at each .await, so after an await the thread-local read returns
// another task's value (or the previous task's leftover on that worker). thread_local is per-thread, not per-task.
thread_local! { static CURRENT: RefCell<Option<User>> = RefCell::new(None); }   // wrong across .await
// SAFE — tokio::task_local! follows the task across threads; scope it around the whole request.
tokio::task_local! { static CURRENT: User; }
CURRENT.scope(user, async move { handle().await }).await;   // read via CURRENT.with(...) inside
```
```rust
// VULN — actix-web web::Data<T> / axum State<T> / Extension<T> is APP-WIDE (Arc-shared across every request
// and worker). Storing per-user data there (e.g. a Mutex<Option<User>> current-user) leaks across requests.
let data = web::Data::new(Mutex::new(CurrentUser::default()));  // shared by ALL requests
// SAFE — reserve Data/State for stateless shared resources (pools, config); put per-request identity in the
// REQUEST EXTENSIONS set by middleware (actix req.extensions_mut(); axum Request::extensions / a per-req extractor).
// VULN — sqlx PgPool / SeaORM / Diesel r2d2: `SET search_path`/`SET ROLE`/`SET app.current_tenant` on a pooled
// conn leaks to the next checkout (same as sub-class 4). SAFE — set it inside a transaction (SET LOCAL) or
// pass the tenant as a query predicate; never mutate session state on a pooled connection.
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

### GraphQL federation router / API gateway (Cosmo Router, Apollo Router) — request de-duplication

The router coalesces concurrent identical **queries** (mutations/subscriptions are never de-duplicated) so
one subgraph fetch serves many callers. The dedup key omits any identity injected *after* it is computed, so
a per-user/tenant header set in the origin/coprocessor hook leaks the winner's response to the losers.

```yaml
# VULN (Cosmo Router config.yaml) — dedup FORCED on while per-user identity is injected in a custom module's
# OnOriginRequest hook, which runs AFTER the dedup key is built. The router auto-disables dedup when an
# EnginePreOriginHandler is registered; the force_* flags override that safety. Two concurrent callers with the
# same operation+variables (and the same forwarded-header hash) coalesce → the winner's data goes to both.
engine:
  enable_single_flight: true
  force_enable_single_flight: true                     # overrides the safety auto-disable
  enable_inbound_request_deduplication: true
  force_enable_inbound_request_deduplication: true
headers:
  all:
    request:
      - op: propagate
        named: Authorization                           # X-Tenant-ID / X-User-ID are NOT forwarded → not in the key
```
```go
// The identity header is set at the WRONG hook (excluded from the dedup key) → cross-tenant bleed under load.
func (m *TenantModule) OnOriginRequest(r *http.Request, ctx core.RequestContext) (*http.Request, *http.Response) {
    r.Header.Set("X-Tenant-ID", ctx.Authentication().Claims()["tenant_id"].(string)) // post-key hook
    return r, nil
}
// SAFE — put identity IN the key: set it in RouterOnRequest/Middleware AND add a declarative header-forwarding
// rule so it is part of the pre-computed key; OR drop the force_* flags (dedup auto-disables when the hook is
// registered); OR scope identity into the operation. Apollo Router: keep per-user identity in a forwarded header
// the router hashes, not only in a coprocessor mutation.
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
| net/http + cookiejar, go-resty, req (Go) | `DefaultClient`+jar; go-resty `client.SetAuthToken/SetHeader/SetCookieJar`; imroc/req `client.SetCommonHeader/SetCommonBearerAuthToken/SetCommonCookies` (all mutate the shared client) | per-request header; go-resty `client.R().SetAuthToken()`; req `client.R().SetBearerAuthToken(token)` |
| OkHttp / Retrofit (JVM) | client `cookieJar` / `Authenticator` | per-request `.header()` |
| Apache HttpClient (JVM) | `setDefaultCookieStore`; connection-bound NTLM/Kerberos | per-request `HttpClientContext` cookie store |
| Ktor (Kotlin) | `install(HttpCookies)` (shared storage) / `install(Auth)` (cached token) | per-call `bearerAuth(token)` |
| Spring RestTemplate / WebClient / RestClient (JVM) | mutated default headers / interceptor field (`RestClient.builder().defaultHeader(...)` shares the same way) | per-request headers |
| OpenFeign (JVM) | interceptor reading a mutable/ThreadLocal token | request-scoped identity |
| gRPC stub/channel (JVM/Go/…) | channel-level / shared-stub `CallCredentials` | per-call `CallCredentials` |
| Guzzle / Symfony HttpClient (PHP) | `['cookies' => true]`; default `headers`/`auth_bearer` | fresh jar + auth per request |
| Faraday / HTTParty / RestClient (Ruby) | shared conn headers; HTTParty **class-level** `headers`/`basic_auth` | per-call headers |
| HttpClient / IHttpClientFactory (.NET) | `DefaultRequestHeaders.Authorization` | per-request `HttpRequestMessage` |
| RestSharp / Flurl (.NET) | client `Authenticator` / `.WithOAuthBearerToken` on cached client | per-`RestRequest` / per-`Request()` header |
| reqwest / awc (Rust) | default auth header; `cookie_store(true)` | `.bearer_auth(token)` per request |
| Puppeteer / Playwright (Node) | reused `Browser`/persistent context — Service Worker, HTTP+DNS cache, sockets survive cookie/storage clears | fresh `createBrowserContext()`/incognito per job + `ctx.close()`; or process-per-tenant |
| Apollo `RESTDataSource` (JS) | a **shared/singleton** data source: `willSendRequest` sets auth on `this.headers`, **and** built-in **GET request memoization/dedup** caches one caller's authenticated response for others | instantiate the data source **per request** (Apollo Server `context`), never as a module singleton |
| ofetch / `$fetch` (Nuxt/unjs) | `ofetch.create({ headers })` bakes default headers onto a shared instance; a Nuxt `onRequest` interceptor mutating shared options | per-call `headers`; don't bake auth into a shared `create()`/interceptor |
| openapi-fetch (JS) | `createClient({ headers })` default headers + shared middleware on one client | per-request `headers`/`params`; per-user client when auth differs |
| `request` / `request-promise` (Node, legacy) | `request.defaults({ headers, jar })` — a shared cookie `jar` persists one user's cookies and a baked-in `Authorization` rides every call | per-call `headers` + a fresh `request.jar()` per user |
| Unirest (Java/Kotlin) | `Unirest.config().setDefaultHeader(...)` / global cookie handling — the config is a **process-static singleton**, so a default `Authorization` is shared by every caller | per-request `Unirest.get(url).header("Authorization", ...)`; avoid global default auth |
| Vert.x WebClient / `WebClientSession` (Java) | `WebClientSession` keeps a **shared `CookieStore`** across requests; a default header on the shared `WebClient` | per-request `bearerTokenAuthentication`/headers; a `WebClientSession` per user, or a plain `WebClient` with no shared cookie store |
| OpenAPI-generated clients (all langs) | a global/shared `Configuration`/`ApiClient` with `accessToken`/`apiKey`/`setBearerToken` set once and reused across users | build the `Configuration`/client per user, or pass creds per call |
| apisauce (JS/React Native) | `api.setHeader()`/`setHeaders({Authorization})` persist on the shared axios-backed instance ("set and forget"), so one user's token rides every later call | per-call config; a fresh instance per user when auth differs |
| wretch (JS) | `.auth(token)`/`.headers({...})` bake onto a reused instance (each returns a configured client you keep) | derive a per-request child; don't persist the authed instance across users |
| Zodios (JS) | axios-backed `new Zodios(baseURL, api)` shares one axios instance; a baked `Authorization` header / interceptor is process-wide | per-call header params; per-user client when auth differs |
| Tesla / Req (Elixir) | a module-level client bakes auth in — Tesla `Tesla.client([{Tesla.Middleware.BearerAuth, token: …}])` / `{Tesla.Middleware.Headers, …}`, or `Req.new(auth: {:bearer, …})` reused across callers | build the client per request with the caller's token; keep auth out of a shared module-level client |
| Excon / Typhoeus (Ruby) | a shared `Excon.new(url, headers: {Authorization})` connection, or Typhoeus default headers / a reused `Typhoeus::Request`, carries one user's auth to the next | per-request headers; don't bake auth into a shared connection object |

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
- **Public / identity-independent data** — caching/coalescing non-personalized data (feature flags, public catalog, static config) on a shared client is correct, not a finding. **Exception — LLM KV/prefix tensors (sub-class 12):** do **not** treat "same document chunk" as identity-independent when position-independent / prefix caching reuses KV across tenants or across different prefixes — that is an integrity finding, not a false alarm.
- **Stateless transport reuse** — reusing an `HttpClient`/`http.Client`/`reqwest::Client`/connection pool itself is fine and recommended **when** auth is passed per-call and no per-user state is stored on the instance. Only flag when identity is held as shared mutable state or in an identity-less key. **Exception (still a finding):** the auth is *connection-bound* (NTLM/Kerberos/Negotiate, mTLS) on a pooled/shared connection, or a shared cookie jar persists a user's session cookie — there identity rides the connection/jar, so reuse leaks even without a mutated header.
- **Mutations under urql/Apollo** — query dedup does not merge mutations (urql compares `_instance` for mutations); don't flag mutation paths for the dedup sub-class.
- **Federation-router dedup that keeps identity in the key** — a Cosmo/Apollo Router is safe when it (a) leaves the `force_enable_*` flags **off** so dedup auto-disables once a pre-origin hook/coprocessor is registered, or (b) carries per-user/tenant identity in a **declaratively forwarded header that is part of the dedup key** (set in `RouterOnRequest`/middleware + a forwarding rule, not only in `OnOriginRequest`/coprocessor), or (c) de-duplicates **queries only** (mutations/subscriptions are never coalesced), or (d) serves anonymous / identity-independent / provably single-tenant traffic — cite the flag/rule/hook that puts identity in the key.
- **Single-worker-per-user / process isolation** — CLI tools, per-user sandboxes, or a worker model that provably serves one identity per process lifetime: not cross-user. Verify before dismissing (most web servers multiplex users per process). **Note:** warm serverless instances (Lambda/Cloud Functions/Azure Functions) are reused across *different* users/tenants unless an explicit tenant-isolation mode is configured, so "it's serverless, so it's fresh" is **not** a valid dismissal for module-scope per-user state.
- **Prefer the neighbor tag** when the cache is an HTTP/CDN/edge cache keyed at the proxy → use `web_cache_deception`. Use `shared_client_cache_leak` when the shared cache/dedup/state lives **inside the application process** (client library, in-memory cache, singleton, pool, thread-local, global).
- **Next.js `fetch(Request, differentInit)` Data Cache body confusion** — **CONFIRM / LIKELY** when App Router server code calls `fetch(new Request(...), init)` where the second `init` is a **different** object that overrides `body` / `method` / `headers` (or adds cacheability: `cache:'force-cache'`, `next.revalidate`) **and** `package.json` / lockfile shows vulnerable `next` (`>=13 <15.5.21` or `>=16 <16.2.11`). Do **not** CLOSE as "framework bug — just upgrade" while the vulnerable call site remains on that range; the app still ships the collision shape. **SAFE / not this finding**: Pages Router; `next >=15.5.21` or `>=16.2.11`; `fetch(new Request(init), init)` with the **same** init object and no body-bearing cache hit path; `cache:'no-store'` / uncached body-bearing fetches; identity-independent public GETs.
- **`ThreadLocal`/`contextvar` that is reset** — if `remove()`/proper `contextvars` binding is shown, the reuse path is closed.
- **Headless browser fully isolated per job** — if each render uses a fresh ephemeral `BrowserContext`/incognito (or a fresh browser process) that is closed afterward, the Service-Worker/cache/socket bleed path is closed; reusing only the *process* with per-job isolated contexts is fine.

### Evidence gate for cache-KEY leaks (defeats the key-scrubbing / `RESTDataSource` / `httpcache:` false positive)

Before you mark a **response/object cache** leak (sub-class 2) CONFIRMED, you MUST have READ and cited all three facts below. If any is only inferred, cap at **NEEDS CONTEXT / SUSPECTED**, never CONFIRMED — this is the class-specific form of the base skill's "every gate answered from code you actually read, never assumed" bar.

- **Key *redaction*/scrubbing ≠ the storage key.** A helper that strips query params or hashes a key (`stripQueryFromKey`, `scrubKey`, `sanitizeKey`, `maskKey`, `normalizeKeyForLog`) — *especially* one whose tests/examples carry PII shapes (`?email=…`, `?token=…`, a password-reset URL) — is almost always applied when the cache **logs** a hit/miss/error, to keep PII/secrets out of logs. That is **NOT** evidence that identity is omitted from the *storage/lookup* key. Confirm by reading the actual `get`/`set` path that the redacted value is what is used to store/read — not the full-URL key that Apollo `HTTPCache` computes via `cacheKeyFor` (default = method + URL **including** the query string, so an identity-bearing param like `?userId=…`/`?tenantId=…` normally **is** in the key). A **unit test of the pure transform proves only the transform** — never that it is the storage key, never that two identities collide. Citing such a test as "confirmed cross-user collision" is fabricated evidence.
- **A response that is never stored cannot leak.** For an HTTP response cache (Apollo `datasource-rest` `HTTPCache`, or any `KeyValueCache`-backed layer), an entry exists only when the response is **cacheable** — `Cache-Control: max-age>0`/`s-maxage`, and no `no-store`/`private`/`no-cache` — or an explicit `ttl`/`cacheOptions`/`cacheOptionsFor(...)` override you can cite. Establish storability from response headers or read code before confirming; otherwise NEEDS CONTEXT. (`datasource-rest` GET **request-memoization** is per-*instance*: if the data source is constructed per request, that path is already per-user — only the injected shared `KeyValueCache` `httpcache:` layer crosses requests, and only for storable responses.)
- **Cache / keying / dedup logic in an uninstalled or out-of-repo dependency ⇒ cannot CONFIRM from the caller.** When the cache class, its key construction, or the `HTTPCache`/dedup logic lives in a third-party or shared package whose source you did **not** read (deps not installed, vendored away, private registry), the collision is unprovable from the calling repo alone. Record **NEEDS CONTEXT**, name the exact package + symbol to inspect (e.g. the internal/shared cache-wrapper class's `get`/`set`, or the client library's cache layer such as `@apollo/datasource-rest` `HTTPCache`/`cacheKeyFor`), and assign no standing severity. **Exception — publicly-documented router/gateway dedup contracts.** The federation-router dedup case (sub-class 1) is **provable from the deploying repo's own config + module** even though the router binary isn't vendored, because the key-construction contract is documented: for **Cosmo Router**, `force_enable_single_flight`/`force_enable_inbound_request_deduplication: true` **with** a per-user/tenant header assigned in `OnOriginRequest`/`EnginePreOriginHandler` (or in `RouterOnRequest` but **not** in the declarative `headers` forwarding rules), and for **Apollo Router**, per-user identity applied only in a coprocessor/rhai step, are CONFIRM-able (or at least LIKELY) — do **not** down-rank to NEEDS CONTEXT merely because the router source isn't in-repo; cite the config flags plus the hook/rule that places identity outside the key.

## Core Principle

A shared cache, de-duplicator, client, connection, or global is only safe when its key (or its scope) matches the response's true **authority boundary**. If a value depends on *who* is asking, then *who* must be in the key — or the structure must be scoped to that one asker. Identity carried in headers, options, or mutable instance state is **not** in the key, and will leak across users the moment two requests overlap.
