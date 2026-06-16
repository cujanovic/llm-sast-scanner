---
name: api_security
description: API/REST/web-service layer detection — excessive data exposure, missing rate limits, endpoint inventory gaps, transport and content negotiation misconfig, and absent response schema filtering
---

# API / REST / Web-Service Security

API-layer weaknesses live in route registration, request/response handlers, serializers, and middleware — not in generic auth or injection sinks alone. Static analysis should trace from HTTP entrypoints through serialization and response construction to what leaves the wire.

*The core pattern: an API handler accepts or returns more than the contract requires — whole internal objects, unbounded payloads, debug routes, or mis-negotiated content — without transport hardening, throttling, or output filtering at the boundary.*

## What It Is (and Is Not)

**What it IS**
- **Excessive data exposure**: returning ORM entities, full `User`/`Account` objects, or nested relations when the client contract needs a DTO subset (password hashes, internal IDs, tokens, PII fields in JSON)
- **Missing output schema filtering**: no response DTO, serializer field list, or `@JsonIgnore`/`hidden`/`select`/`only()` before `res.json()` / `return entity`
- **Missing rate limiting / resource consumption**: state-changing or expensive read endpoints with no per-IP/user/client throttle, body-size cap, pagination default, or timeout
- **Improper endpoint inventory**: unversioned breaking routes, `/debug`, `/test`, `/internal`, deprecated handlers still mounted, management/actuator routes on the same host/port as public API
- **Verbose API errors**: stack traces, SQL fragments, validation internals, or framework hints returned in JSON/XML error bodies (API-specific; see also `information_disclosure.md`)
- **Missing TLS**: HTTP listeners, `http://` base URLs, TLS disabled in server config, or reverse-proxy forwarding cleartext for API traffic
- **Content-Type / Accept mishandling**: accepting any body without validating `Content-Type`; echoing `Accept` into `Content-Type`; no 415/406 on unsupported media types
- **JSON / AJAX response weaknesses**: top-level JSON arrays (legacy hijacking surface), string-concatenated JSON, missing `Content-Type: application/json`, sensitive fields in query strings on GET API routes
- **HTTP verb handling gaps**: routes registered without method allowlist; handlers that ignore `req.method`; method-override headers processed without guard (see `http_method_tamper.md` for CSRF overlap)
- **API security misconfiguration**: missing `Cache-Control: no-store` on sensitive JSON; absent HSTS on HTTPS API; debug/swagger/openapi UI enabled in production router

**What it is NOT**
- **Object-level authorization (BOLA/IDOR)** — see `idor.md`; flag here only when the handler returns extra fields *after* auth passes
- **Missing function-level auth or admin-only route without checks** — see `privilege_escalation.md`
- **Mass assignment via request binding** — see `mass_assignment.md`
- **SQL/command/template injection in handlers** — see `sql_injection.md`, `rce.md`
- **CORS origin misconfiguration** — see `cors_misconfiguration.md`; mention only when reviewing API middleware holistically
- **JWT/OAuth/API-key validation flaws** — see `authentication_jwt.md`
- **GraphQL depth/complexity limits** — see `graphql_injection.md`
- **SSRF in outbound webhook/callback helpers** — see `ssrf.md`

## Recon Indicators

### Route / handler registration

| Signal | Grep / structural targets |
|--------|----------------------------|
| Route tables | `@app.route`, `@GetMapping`, `@PostMapping`, `router.(get\|post\|put\|delete\|patch\|all)`, `app\.(get\|post\|use)`, `urlpatterns`, `Route::`, `gin\.(GET\|POST)` |
| Catch-all / any method | `methods=\['GET','POST'\]` on mutation paths, `router.all\(`, `@RequestMapping` without `method =`, `app.use('/api', handler)` with no verb check |
| Debug / internal | `/debug`, `/test`, `/dev`, `/internal`, `/admin`, `/actuator`, `/swagger`, `/openapi`, `/api-docs`, `/graphql-playground`, `/_`, `/health` with env dump |
| Versioning gaps | `/api/users` with no `/v1/` prefix; parallel unversioned and versioned mounts; `@Deprecated` handlers still registered |
| Management on public port | `management\.endpoints\.web\.exposure`, `spring\.boot\.admin`, `django-debug-toolbar` middleware in prod settings |

### Serializer / response construction

| Signal | Grep / structural targets |
|--------|----------------------------|
| Whole-object return | `return user`, `res.json(user)`, `Response(entity)`, `to_dict()` without field filter, `ModelSerializer` with `fields = '__all__'`, `serialize.*User` |
| Missing DTO layer | Direct ORM/document model in handler return; `jsonify(request.user.__dict__)`; `c.JSON(user)` in Go without struct tags |
| Sensitive field leaks | `password`, `password_hash`, `hashed_password`, `salt`, `secret`, `api_key`, `ssn`, `internal_notes` in response dict keys or serializer `fields` |
| String-built JSON | `'{"' +`, `"{\"name\":\"" +`, template literals assembling JSON from unescaped variables |
| Top-level array | `res.json([`, `return json.dumps(rows)` where root is `[` (not wrapped in object) |

### Transport, headers, content negotiation

| Signal | Grep / structural targets |
|--------|----------------------------|
| Cleartext | `app.run.*ssl_context=None`, `http://` in `BASE_URL`, `secure:\s*false`, `ssl\.?enabled\s*=\s*false`, `listen.*:80` without TLS redirect |
| Content-Type | Missing check of `Content-Type` / `request.is_json` before body parse; `res.setHeader('Content-Type', req.headers.accept)` |
| Accept handling | No branch on `Accept` header; always returns JSON regardless of `Accept: text/html` |
| Error verbosity | `res.status(500).json({ error: err.stack })`, `return str(e)`, `detail: exception`, `errors: err` in global exception handler |
| Rate / size limits | Absence of `rateLimit`, `throttle`, `Limiter`, `slowapi`, `@ratelimit`, `express-rate-limit`, `max_request_body_size`, `413` handling |

### Example grep one-liners

```bash
rg -n "res\.json\(|jsonify\(|return.*\.to_dict\(|fields\s*=\s*['\"]__all__['\"]" --glob '*.{py,js,ts,java,go,rb,php}'
rg -n "/debug|/swagger|/openapi|/actuator|graphql-playground|management\.endpoints" .
rg -n "rateLimit|Limiter|@ratelimit|slowapi|express-rate-limit" --glob '*.{py,js,ts,java}'  # absence on hot routes is manual follow-up
rg -n "Content-Type.*accept|req\.headers\.accept|http://|ssl_context=None|secure:\s*false" .
```

## Vulnerable Conditions

- Handler returns persistence model or ORM entity without serializer/DTO that excludes sensitive columns
- List/detail endpoints embed nested relations (`include`, `populate`, `select_related`) with no field allowlist on nested objects
- `ModelSerializer` / `@JsonAutoDetect` / `Gson` with default visibility exposes all fields including write-only secrets
- No default pagination or `limit` cap on collection endpoints; client controls `page_size`/`limit`/`per_page` without server maximum
- Expensive handler (aggregation, full-table scan, external call loop) reachable without rate limit or timeout middleware
- `/v1/` and unversioned route both active with different auth or response shapes
- Debug, swagger UI, actuator env/config, or test-only routes registered in production app factory or main router
- Global exception handler serializes `err.stack`, `err.message`, SQL state, or validation object keys to API clients
- Server listens on HTTP for externally reachable API or constructs callback URLs with `http://`
- POST/PUT/PATCH parses body without verifying `Content-Type` is in supported set (`application/json`, etc.)
- Response sets `Content-Type` from client `Accept` header instead of fixed intended type
- Unsupported `Accept` or `Content-Type` accepted silently or returns 200 with wrong representation
- JSON built via string concatenation/interpolation instead of `JSON.stringify` / `json.dumps` / marshaller
- GET API routes place tokens, passwords, or PII in query string (`?api_key=`, `?password=`)
- Route accepts all HTTP methods or handler omits method guard before mutation logic
- Sensitive JSON responses omit `Cache-Control: no-store` and are cacheable by shared proxies
- No request body size limit; large JSON/XML uploads parsed fully into memory

## Safe Patterns

**Response shaping**
- Return DTOs/view models with explicit field allowlists; never serialize password hashes, refresh tokens, or internal flags
- Use framework serializers with `fields = (...)` / `@JsonView` / `@JsonIgnore` / `hidden=True` on sensitive model attrs
- Paginate collections by default; cap `limit` server-side; return metadata `{ items, next_cursor, total_cap }`

**Throttling and limits**
- Apply rate limits at gateway and handler layer for auth, search, export, and write endpoints
- Enforce `max_content_length`, `413 Payload Too Large`, request timeouts, and circuit breakers on downstream calls

**Endpoint hygiene**
- Version all public routes (`/api/v1/...`); remove or gate deprecated handlers behind feature flags
- Mount management, swagger, and debug UIs on separate host/port or require strong auth; disable in prod config profiles
- Maintain machine-readable contract (OpenAPI/JSON Schema) and reject unknown request fields

**Transport and negotiation**
- HTTPS-only external API; HSTS on TLS responses; redirect HTTP→HTTPS at edge
- Validate `Content-Type` before parse; return `415 Unsupported Media Type` for wrong type
- Honor `Accept` with explicit supported set; return `406 Not Acceptable` when no match
- Set response `Content-Type` from server contract, never copied from request `Accept`

**Errors and caching**
- Generic error envelope to clients; log details server-side only
- `Cache-Control: no-store` on authenticated or sensitive JSON; correct status codes (`429` for throttle)

```python
# SAFE — DTO with explicit fields, pagination cap, generic errors
@router.get("/api/v1/users/{user_id}")
@limiter.limit("60/minute")
def get_user(user_id: int):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Not found")
    return UserPublic(id=user.id, name=user.name, email=user.email)

@app.exception_handler(Exception)
def handle_error(request, exc):
    logger.exception("api_error")
    return JSONResponse(status_code=500, content={"error": "Internal server error"})
```

```typescript
// SAFE — method allowlist, content-type check, shaped response
app.post('/api/v1/orders', rateLimit({ max: 30 }), async (req, res) => {
  if (req.headers['content-type']?.split(';')[0] !== 'application/json') {
    return res.status(415).json({ error: 'Unsupported media type' });
  }
  const order = await createOrder(req.body);
  res.setHeader('Cache-Control', 'no-store');
  res.json({ id: order.id, status: order.status, total: order.total });
});
```

```java
// SAFE — versioned controller, DTO mapping, no entity leak
@RestController
@RequestMapping("/api/v1/accounts")
public class AccountController {
    @GetMapping("/{id}")
    public AccountResponse get(@PathVariable UUID id) {
        Account a = service.find(id);
        return AccountResponse.from(a); // excludes passwordHash, internalFlags
    }
}
```

## Language / Framework Examples

### Python (Flask / FastAPI / Django REST)

```python
# VULN — whole SQLAlchemy model serialized
@app.get("/api/users/<id>")
def user_detail(id):
    return jsonify(User.query.get(id).__dict__)

# VULN — DRF serializer exposes all model fields
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

# VULN — no rate limit on expensive endpoint
@app.get("/api/search")
def search():
    return jsonify(run_full_table_scan(request.args.get('q')))
```

### JavaScript / Node (Express / Fastify)

```javascript
// VULN — string-built JSON
app.get('/api/profile', (req, res) => {
  res.send('{"name":"' + req.query.name + '"}');
});

// VULN — top-level JSON array response
app.get('/api/transactions', (req, res) => {
  res.json(transactions.map(t => t.toJSON()));
});

// VULN — verbose error to API client
app.use((err, req, res, next) => res.status(500).json({ stack: err.stack }));
```

### Java (Spring)

```java
// VULN — entity returned directly with lazy relations
@GetMapping("/api/v1/users/{id}")
public User getUser(@PathVariable Long id) {
    return userRepository.findById(id).orElseThrow();
}

// VULN — actuator exposed on same application
management.endpoints.web.exposure.include=*
```

### Go

```go
// VULN — struct tags expose secret fields
type User struct {
    ID       int    `json:"id"`
    Email    string `json:"email"`
    Password string `json:"password"`
}
c.JSON(http.StatusOK, user)

// VULN — no TLS on public listener
http.ListenAndServe(":8080", router)
```

### PHP (Laravel)

```php
// VULN — API resource returns entire model
return response()->json($user);

// VULN — route accepts any method
Route::any('/api/delete/{id}', [ItemController::class, 'destroy']);
```

## Common False Alarms

- Public read-only catalog endpoints intentionally returning full product records without auth — not excessive exposure unless hidden cost/wholesale fields leak
- Internal admin API behind VPN/mTLS returning rich objects to authenticated operators within scope — verify network boundary before downgrading
- `fields = '__all__'` on a model with no sensitive columns and explicit `@api_view` auth — still prefer explicit fields but may be low impact
- Rate limiting enforced at API gateway/WAF documented in infra but absent in app source — verify deployment; do not assume safe
- Swagger/OpenAPI UI disabled in prod via env flag though route exists in code — configuration finding depends on prod profile evidence
- HTTP listener on localhost-only bind (`127.0.0.1`) for dev tooling — transport finding does not apply externally
- Generic `{ "error": "Bad Request" }` without stack trace — not verbose error disclosure
- REST handler correctly using PUT/DELETE with auth — not HTTP verb tampering; see `http_method_tamper.md` only when GET mutates or override headers are trusted
- CORS `*` on anonymous public read API with no credentials — cross-ref `cors_misconfiguration.md`; not an API inventory issue
- Pagination optional on small fixed-size collections (enum lists, config keys) — DoS class requires unbounded user-driven growth
