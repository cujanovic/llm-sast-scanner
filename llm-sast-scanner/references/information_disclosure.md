---
name: information-disclosure
description: Information disclosure testing covering error messages, debug endpoints, metadata leakage, and source exposure
---

# Information Disclosure

Leaked information acts as a force multiplier for attackers — it maps the codebase, pinpoints component versions, surfaces credentials, and defines trust boundaries. Every byte returned by the server, every artifact published, and every header emitted is potential intelligence. The goal is to minimize, normalize, and tightly scope what gets exposed across every channel.

## Where to Look

- Errors and exception pages: stack traces, file paths, SQL, framework versions
- Debug/dev tooling reachable in prod: debuggers, profilers, feature flags
- DVCS/build artifacts and temp/backup files: .git, .svn, .hg, .bak, .swp, archives
- Configuration and secrets: .env, phpinfo, appsettings.json, Docker/K8s manifests
- API schemas and introspection: OpenAPI/Swagger, GraphQL introspection, gRPC reflection
- Client bundles and source maps: webpack/Vite maps, embedded env, `__NEXT_DATA__`, static JSON
- Headers and response metadata: Server/X-Powered-By, tracing, ETag, Accept-Ranges, Server-Timing
- Storage/export surfaces: public buckets, signed URLs, export/download endpoints
- Observability/admin: /metrics, /actuator, /health, tracing UIs (Jaeger, Zipkin), Kibana, Admin UIs
- Directory listings and indexing: autoindex, sitemap/robots revealing hidden routes

## High-Value Surfaces

### Errors and Exceptions

- SQL/ORM errors: reveal table/column names, DBMS, query fragments
- Stack traces: absolute paths, class/method names, framework versions, developer emails
- Template engine probes: `{{7*7}}`, `${7*7}` identify templating stack
- JSON/XML parsers: type mismatches leak internal model names

### Debug and Env Modes

- Debug pages: Django DEBUG, Laravel Telescope, Rails error pages, Flask/Werkzeug debugger, ASP.NET customErrors Off
- Profiler endpoints: `/debug/pprof`, `/actuator`, `/_profiler`, custom `/debug` APIs
- Feature/config toggles exposed in JS or headers

### DVCS and Backups

- DVCS: `/.git/` (HEAD, config, index, objects), `.svn/entries`, `.hg/store` → reconstruct source and secrets
- Backups/temp: `.bak`/`.old`/`~`/`.swp`/`.swo`/`.tmp`/`.orig`, db dumps, zipped deployments
- Build artifacts: dist artifacts containing `.map`, env prints, internal URLs

### Configs and Secrets

- Classic: web.config, appsettings.json, settings.py, config.php, phpinfo.php
- Containers/cloud: Dockerfile, docker-compose.yml, Kubernetes manifests, service account tokens
- Credentials and connection strings; internal hosts and ports; JWT secrets

### API Schemas and Introspection

- OpenAPI/Swagger: `/swagger`, `/api-docs`, `/openapi.json` — enumerate hidden/privileged operations
- GraphQL: introspection enabled; field suggestions; error disclosure via invalid fields
- gRPC: server reflection exposing services/messages

### Client Bundles and Maps

- Source maps (`.map`) reveal original sources, comments, and internal logic
- Client env leakage: `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_` variables; embedded secrets
- `__NEXT_DATA__` and pre-fetched JSON can include internal IDs, flags, or PII

### Headers and Response Metadata

- Fingerprinting: Server, X-Powered-By, X-AspNet-Version
- Tracing: X-Request-Id, traceparent, Server-Timing, debug headers
- Caching oracles: ETag/If-None-Match, Last-Modified/If-Modified-Since, Accept-Ranges/Range

### Storage and Exports

- Public object storage: S3/GCS/Azure blobs with world-readable ACLs or guessable keys
- Signed URLs: long-lived, weakly scoped, re-usable across tenants
- Export/report endpoints returning foreign data sets or unfiltered fields

### Observability and Admin

- Metrics: Prometheus `/metrics` exposing internal hostnames, process args
- Health/config: `/actuator/health`, `/actuator/env`, Spring Boot info endpoints
- Tracing UIs: Jaeger/Zipkin/Kibana/Grafana exposed without auth

### Cross-Origin Signals

- Referrer leakage: missing/weak referrer policy leading to path/query/token leaks to third parties
- CORS: overly permissive Access-Control-Allow-Origin/Expose-Headers revealing data cross-origin; preflight error shapes

### File Metadata

- EXIF, PDF/Office properties: authors, paths, software versions, timestamps, embedded objects

### Cloud Storage

- S3/GCS/Azure: anonymous listing disabled but object reads allowed; metadata headers leak owner/project identifiers
- Pre-signed URLs: audience not bound; observe key scope and lifetime in URL params

## Triage Rubric

- **Critical**: Credentials/keys; signed URL secrets; config dumps; unrestricted admin/observability panels
- **High**: Versions with reachable CVEs; cross-tenant data; caches serving cross-user content
- **Medium**: Internal paths/hosts enabling LFI/SSRF pivots; source maps revealing hidden endpoints
- **Low**: Generic headers, marketing versions, intended documentation without exploit path

## Analysis Workflow

1. **Build channel map** - Web, API, GraphQL, WebSocket, gRPC, mobile, background jobs, exports, CDN
2. **Establish diff harness** - Compare owner vs non-owner vs anonymous; normalize on status/body length/ETag/headers
3. **Trigger controlled failures** - Malformed types, boundary values, missing params, alternate content-types
4. **Enumerate artifacts** - DVCS folders, backups, config endpoints, source maps, client bundles, API docs
5. **Correlate to impact** - Versions→CVE, paths→LFI/RCE, keys→cloud access, schemas→auth bypass

## Confirming a Finding

1. Provide raw evidence (headers/body/artifact) and explain exact data revealed
2. Determine intent: cross-check docs/UX; classify per triage rubric
3. Attempt minimal, reversible exploitation or present a concrete step-by-step chain
4. Show reproducibility and minimal request set
5. Bound scope (user, tenant, environment) and data sensitivity classification

## Common False Alarms

- Intentional public docs or non-sensitive metadata with no exploit path
- Generic errors with no actionable details
- Redacted fields that do not change differential oracles
- Version banners with no exposed vulnerable surface and no chain
- Owner-visible-only details that do not cross identity/tenant boundaries
- Dev/debug mode flags by themselves are not enough unless they expose concrete sensitive data, a reachable debug console, or a specific exploitation path
- Dependency-version findings without a reachable vulnerable feature or chain should be treated as informational, not reportable disclosure

## FALSE POSITIVE Rules

- Do NOT emit `information_disclosure` for database credentials in config files (application.yml, application.properties, docker-compose.yml) — this is a deployment configuration issue, not an application-level info disclosure vulnerability. Tag as `default_credentials` or `weak_crypto` if appropriate.
- Do NOT emit for verbose error messages in development/debug mode unless there is evidence this mode is reachable in production.
- Do NOT emit for intentional vulnerability demo pages that display security-relevant information as part of their educational purpose.
- Do NOT emit when the "disclosed" information is only accessible to authenticated/authorized users within their normal access scope.
- Only emit when sensitive data (credentials, PII, internal paths, stack traces) is exposed to UNAUTHORIZED users through a reachable endpoint.

## Business Risk

- Accelerated exploitation of RCE/LFI/SSRF via precise versions and paths
- Credential/secret exposure leading to persistent external compromise
- Cross-tenant data disclosure through exports, caches, or mis-scoped signed URLs
- Privacy/regulatory violations and business intelligence leakage

## Analyst Notes

1. Start with artifacts (DVCS, backups, maps) before payloads; artifacts yield the fastest wins
2. Normalize responses and diff by digest to reduce noise when comparing roles
3. Hunt source maps and client data JSON; they often carry internal IDs and flags
4. Probe caches/CDNs for identity-unaware keys; verify Vary includes Authorization/tenant
5. Treat introspection and reflection as configuration findings across GraphQL/gRPC
6. Mine observability endpoints last; they are noisy but high-yield in misconfigured setups
7. Chain quickly to a concrete risk and stop—proof should be minimal and reversible

## Core Principle

Information disclosure is an amplifier. Convert leaks into precise, minimal exploits or clear architectural risks.

## Secure Error Handling Configuration

Separate **internal diagnostics** from **external responses**. Clients receive generic, stable messages; servers log full exception context for forensics.

### Client-Facing Response Policy

- Return generic messages (`"An error occurred, please retry"`) — never stack traces, file paths, framework versions, or SQL/ORM error text
- Use consistent error envelopes (JSON `message` field or Problem Details `application/problem+json`) with appropriate HTTP status (4xx client, 5xx server)
- Escape or encode error response bodies to block injection into HTML/JSON clients
- Strip `Server`, `X-Powered-By`, and technology fingerprint headers from error responses

### Production Debug & Error Pages

- Disable interactive debuggers and verbose exception pages in production (`DEBUG=False`, `display_errors=0`, `customErrors mode="RemoteOnly"`)
- Route unhandled exceptions through centralized handlers (`@RestControllerAdvice`, Express error middleware, Django `handler500`, ASP.NET Core `UseExceptionHandler`)
- Redirect to custom generic error pages — not framework default pages with source snippets

### Internal vs External Channel Split

```python
# VULN: same detail to client and logs
except Exception as e:
    return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500

# SAFE: generic client response; rich server-side log only
except Exception as e:
    logger.exception("order_create_failed", extra={"user_id": user_id, "order_id": order_id})
    return jsonify({"message": "Unable to process request"}), 500
```

```java
// VULN: exception message/stack sent to HTTP response
catch (Exception e) {
    e.printStackTrace(response.getWriter());
}

// SAFE: log internally; generic JSON to client
catch (Exception e) {
    logger.error("payment_failed", e);
    response.setStatus(500);
    response.getWriter().write("{\"message\":\"An error occurred, please retry\"}");
}
```

```xml
<!-- VULN: ASP.NET exposes detailed errors to remote clients -->
<customErrors mode="Off" />

<!-- SAFE: generic page for remote; detail only locally -->
<customErrors mode="RemoteOnly" defaultRedirect="~/ErrorPages/Generic.aspx" />
```

### Error-Logging Boundary (Cross-Reference)

Log exceptions with correlation IDs, user/session identifiers (non-PII where possible), source IP, and timestamps — but **never** passwords, tokens, recovery codes, full request bodies, or cleartext PII in error logs. Redact or hash sensitive fields before write (see `log_injection.md`).

## Python/JS/PHP Source Detection Rules

### Python (Flask / Django)
- **VULN**: `app.run(debug=True)` — Werkzeug interactive debugger exposes RCE in production
- **VULN**: `DEBUG = True` in production Django settings
- **VULN**: `app.config['PROPAGATE_EXCEPTIONS'] = True` + traceback returned in response
- **VULN**: `return str(e)` or `return traceback.format_exc()` inside an error handler
- **SAFE**: `DEBUG = os.environ.get('DEBUG', 'False') == 'True'` — only safe when production env does not set `DEBUG=True`; env-dependent, not inherently safe

### JavaScript (Node.js / Express)
- **VULN**: `res.json({ error: err.stack })` — stack trace leaked to client
- **VULN**: `res.send(err.message)` — raw error message returned
- **VULN**: `app.use((err, req, res, next) => res.json(err))` — entire error object serialized

### PHP
- **VULN**: `error_reporting(E_ALL); ini_set('display_errors', 1)` — all errors displayed
- **VULN**: `phpinfo()` endpoint accessible without authentication
- **VULN**: `die($e->getMessage())`, `echo $e->getTraceAsString()`
- **SAFE**: `ini_set('display_errors', 0); ini_set('log_errors', 1)`

### Java / Spring
- **VULN**: `e.printStackTrace()` or `printStackTrace(response.getWriter())` — stack sent to client
- **VULN**: `@ExceptionHandler` returning `exception.getMessage()` or full exception object in response body
- **VULN**: Spring Boot `server.error.include-stacktrace=always` or `include-message=always` in production config
- **SAFE**: `@RestControllerAdvice` returning generic `ProblemDetail`/`ResponseEntity` message; `include-stacktrace=never` in prod

### C# / ASP.NET
- **VULN**: `<customErrors mode="Off" />` or `app.UseDeveloperExceptionPage()` without environment guard in production
- **VULN**: `return Json(new { error = ex.ToString() })` or `ex.StackTrace` in API error responses
- **SAFE**: `customErrors mode="RemoteOnly"`; production `UseExceptionHandler("/error")` with generic JSON body

### Source Maps Shipped to Production (build-config class)
Production builds that emit and deploy `.map` files (or inline maps) hand attackers the original, un-minified source — comments, internal endpoints, function names, and sometimes secrets. Detect at the **build-config** level, framework-agnostic:
- **VULN**: `productionBrowserSourceMaps: true` in `next.config.js` — Next.js emits browser source maps in prod
- **VULN**: webpack `devtool: 'source-map'` (or `eval-source-map`) under a production config
- **VULN**: Vite `build: { sourcemap: true }`; Rollup `output.sourcemap: true`; esbuild `--sourcemap`
- **VULN**: `GENERATE_SOURCEMAP=true` (CRA) or any pipeline that copies `*.map` to the public/CDN dir
- **Note**: this is the static signature of the "reverse the bundle via the `.map`" technique; the `//# sourceMappingURL=` comment in shipped JS is the runtime tell.
- **SAFE**: source maps disabled for prod, or uploaded to an access-controlled error-tracking service (e.g. Sentry) and **not** served publicly.

## Automated Detection Patterns

### Stack trace / exception exposure (CWE-209)

Commonly affected languages: JavaScript, Java, Python, Go, Ruby, C#.

**Sources**: exceptions, stack traces flowing from catch blocks.

**Sinks**: HTTP response bodies (`res.send(err.stack)`), `sendError` with exception, error handlers returning raw exception objects.

**Sanitizers**: generic error messages to client; server-only logging; debug flags off in production.

**SAST indicators (error response sinks)**:
- `debug=True`, `DEBUG = True`, `app.run(debug=True)` without environment guard
- `printStackTrace`, `getTraceAsString`, `traceback.format_exc`, `err.stack`, `ex.ToString()`, `ex.StackTrace` flowing to HTTP response sinks
- Error handlers returning `str(e)`, `err.message`, raw exception objects, or SQL/ORM error strings to clients
- Production config: `include-stacktrace=always`, `customErrors mode="Off"`, `display_errors=1`, `PROPAGATE_EXCEPTIONS=True` combined with client-visible responses
- `res.json({ error: err })`, `sendError(500, exception)`, template rendering of `{{ exception }}` in user-facing pages

### Sensitive logging (CWE-312 / CWE-532)

Commonly affected languages: Java, JavaScript, Python, Go, Ruby, Rust, Swift.

**Sources**: credentials, tokens, PII fields marked sensitive in type/annotation models.

**Sinks**: log appenders (Log4j/SLF4J), clear-text logging of passwords/tokens.

**Sanitizers**: structured logging with redaction; avoid logging sensitive fields.

### Sensitive data in GET query (CWE-598)

Commonly affected languages: JavaScript, Ruby.

**Sinks**: passwords, tokens, or PII read from GET query parameters.

### Cross-window information leak (CWE-201)

**JavaScript**: `postMessage(data, '*')` with unrestricted target origin.

**Sanitizers**: fixed postMessage target origin.

### Build artifact / file exposure (CWE-200)

**JavaScript**: sensitive data in build artifacts; private file exposure; local file served over HTTP.

**C#**: exposure in transmitted data (CWE-201); exposure of private information (CWE-359).

**C++**: exposed system data (CWE-497).

### Debug mode exposure (CWE-215 / CWE-489)

**Python**: Flask app run in debug mode (`app.run(debug=True)`).

**C#**: ASP.NET debug binary in production.

**No automated query**: `.git`/source-map exposure (static artifact hunt). GraphQL introspection, Swagger UI exposure—not dedicated queries. Align with existing FALSE POSITIVE rules: config-file credentials → `default_credentials`, not info disclosure.

### LLM/AI sensitive-data disclosure (OWASP LLM02)

Generative-AI apps disclose sensitive data through model outputs: training-data memorization, secrets/PII placed in prompts or context, or over-permissive RAG retrieval that pulls documents the caller cannot read.

**Sources**: PII/secrets in fine-tuning data; secrets templated into system prompts; RAG context assembled from documents without an access filter; user messages echoed back with sensitive fields.

**Sinks**: the model response returned to the user; logs/telemetry capturing full prompts or completions.

**Sanitizers / safe patterns**:
- Sanitize/anonymize PII before training or fine-tuning; do not feed raw secrets into prompts (see `system_prompt_leakage.md`).
- Apply an output filter that scans completions for secret/PII patterns (API keys `sk-…`/`AKIA…`, private keys, SSNs, card numbers) and redacts before returning.
- Enforce permission- and tenant-scoped retrieval so context never includes unauthorized documents (see `rag_vector_security.md`).
- Avoid logging full prompts/responses that may contain credentials or PII (see "Sensitive logging" above).

**Triage**: secret/credential in model output or in a shared prompt → High; PII over-exposure via unfiltered RAG → High/Medium per data sensitivity. Cross-reference `system_prompt_leakage.md` (LLM07) for prompt-resident secrets and `rag_vector_security.md` (LLM08) for retrieval scoping.
