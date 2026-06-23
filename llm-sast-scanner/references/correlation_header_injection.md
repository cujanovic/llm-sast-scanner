---
name: correlation-header-injection
description: Correlation and request-tracing header injection — X-Request-ID, X-Correlation-ID, X-Trace-ID, or Request-Id taken from inbound requests and passed unsanitized into loggers, filesystem paths, shell commands, SQL, JSON bodies, downstream propagation, or HTTP responses (CWE-117 / CWE-93 / CWE-74)
---

# Correlation Header Injection (CWE-117 / CWE-93 / CWE-74)

Distributed systems propagate request identifiers through headers such as `X-Request-ID`, `X-Correlation-ID`, `X-Trace-ID`, and `Request-Id` for tracing and support. When the server **trusts client-supplied values** and passes them unsanitized into logs, file paths, shell commands, SQL, JSON construction, downstream HTTP headers, or reflected responses, attackers inject structure-breaking characters (CRLF, path segments, shell metacharacters, quote breaks) or oversized payloads. Unlike generic user input, correlation headers are often treated as "trusted infrastructure" and skip validation — making them a high-yield static-analysis gap.

## What It Is / Is Not

- **Is**: `req.headers['x-request-id']` / `getHeader("X-Correlation-ID")` flowing to `logger.info(...)`, `open(path + id)`, `exec`, SQL string concat, `JSON.stringify` body fields, outbound proxy headers, or echo in response body/headers without charset/length validation; middleware that auto-propagates inbound correlation ID to all downstream calls.
- **Is not**: server-generated UUID assigned at edge and never overwritten by client — safe pattern. Generic log injection from query/body parameters — see `log_injection.md` (correlation header is a distinct source with "trusted" false confidence). Path traversal from `filename` query param — see `path_traversal_lfi_rfi.md` when path param is the sole source.
- **Highest signal** when inbound header value reaches log, path, shell, SQL, or response sink with no `[A-Za-z0-9-]` allowlist and length cap.

## Source -> Sink Pattern

**Sources (client-influenced headers)**
- `X-Request-ID`, `X-Correlation-ID`, `X-Trace-ID`, `Request-Id`, `X-Amzn-Trace-Id` (when echoed/propagated from inbound)
- Framework accessors: `req.headers['x-request-id']`, `request.getHeader("X-Correlation-ID")`, `HttpContext.Request.Headers["X-Trace-Id"]`, `r.Header.Get("X-Request-Id")`

**Sinks**
- **Logging**: `logger.info(f"request {correlation_id}")`, `log.Printf("id=%s", id)` — CRLF log forging; see `log_injection.md`
- **Filesystem**: `open(f"/tmp/logs/{correlation_id}.json")`, `os.path.join(base, req_id)` — path traversal; see `path_traversal_lfi_rfi.md`
- **Shell/process**: `subprocess.run(f"grep {correlation_id} app.log", shell=True)`, `exec.Command("sh", "-c", "trace " + id)`
- **SQL**: `"SELECT * FROM events WHERE trace_id = '" + correlation_id + "'"`
- **JSON/body construction**: `'{"trace":"' + header + '"}'` — broken JSON or injection into downstream parsers
- **Downstream propagation**: outbound `headers['X-Correlation-ID'] = inbound_value` to internal services
- **Response reflection**: `res.setHeader('X-Request-ID', req.headers['x-request-id'])` with raw value — header injection / response splitting class

**Aggravating context**
- Correlation ID used as filename in shared temp or debug export directory
- Log aggregation that parses newline-delimited or key=value format
- Header value embedded in audit records displayed in admin HTML log viewers

## Recon Indicators (Grep)

```bash
# Header reads (trace each to sinks)
rg -ni 'x-request-id|x-correlation-id|x-trace-id|request-id|X-Request-Id|X-Correlation-Id|X-Trace-Id' .
rg -ni 'getHeader\s*\(\s*["'"'"']X-(Request|Correlation|Trace)-Id|headers\s*\[\s*["'"'"']x-(request|correlation|trace)-id' .

# Header → logger (log injection chain)
rg -ni 'x-request-id|x-correlation-id|x-trace-id' . | rg -i 'log\.|logger\.|console\.|Log\.|logging\.|printf.*%s'

# Header → path / file
rg -ni 'x-request-id|x-correlation-id|x-trace-id' . | rg -i 'open\s*\(|readFile|writeFile|path\.join|os\.path|File\.|sendFile|createWriteStream'

# Header → shell / process
rg -ni 'x-request-id|x-correlation-id|x-trace-id' . | rg -i 'exec|system\s*\(|subprocess|ProcessBuilder|spawn\s*\('

# Header → SQL
rg -ni 'x-request-id|x-correlation-id|x-trace-id' . | rg -i 'SELECT|INSERT|UPDATE|query\s*\(|execute\s*\(|\.raw\s*\('

# Downstream propagation middleware
rg -ni 'correlation|request.id|trace.id|requestId' --glob '*middleware*'
rg -ni 'headers\s*\[\s*["'"'"']X-Correlation|setHeader\s*\(\s*["'"'"']X-Request-Id' .
```

For each hit: is the value validated (charset + max length) or server-generated? Trace to sink before classifying.

## Vulnerable Conditions

1. **Log forging**: correlation header interpolated into log message without stripping `\r\n` — see `log_injection.md`.
2. **Path traversal**: header used as filename or path segment: `../etc/passwd` embedded in `X-Request-ID`.
3. **Shell injection**: header passed to shell string or unquoted command argument.
4. **SQL injection**: header concatenated into query instead of parameterized bind.
5. **JSON injection**: header embedded in manual JSON string without encoding.
6. **Blind propagation**: middleware copies all inbound tracing headers to internal microservices, amplifying injection.
7. **Response reflection**: raw header echoed to client enabling CRLF in legacy stacks — related to `http_response_splitting.md`.
8. **Oversized header**: no length cap → DoS in log pipelines or file creation — see `denial_of_service.md`.

## Vulnerable vs Safe Code Examples

```python
# VULN — client correlation ID logged verbatim (CRLF forge)
def handle(request):
    cid = request.headers.get("X-Request-ID", "")
    logger.info(f"start request correlation={cid}")

# SAFE — server generates ID; or validate client value before use
import re, uuid
CORR_RE = re.compile(r'^[A-Za-z0-9-]{1,64}$')
def get_correlation_id(request):
    raw = request.headers.get("X-Request-ID", "")
    if raw and CORR_RE.fullmatch(raw):
        return raw
    return str(uuid.uuid4())

def handle(request):
    cid = get_correlation_id(request)
    logger.info("start request correlation=%s", cid.replace("\r", "").replace("\n", ""))
```

```javascript
// VULN — correlation ID in file path
app.get('/debug/export', (req, res) => {
  const id = req.headers['x-correlation-id'] || 'unknown';
  const path = `/tmp/exports/${id}.json`;
  res.sendFile(path);
});

// SAFE — strict charset; basename; resolve under fixed root
const CORR = /^[A-Za-z0-9-]{1,64}$/;
app.get('/debug/export', (req, res) => {
  const raw = req.headers['x-correlation-id'];
  if (!raw || !CORR.test(raw)) return res.status(400).end();
  const safe = path.basename(raw);
  const full = path.resolve('/tmp/exports', `${safe}.json`);
  if (!full.startsWith('/tmp/exports/')) return res.status(400).end();
  res.sendFile(full);
});
```

```java
// VULN — SQL concat with X-Request-ID
String cid = request.getHeader("X-Correlation-ID");
jdbcTemplate.query("SELECT * FROM audit WHERE correlation_id = '" + cid + "'");

// SAFE — parameterized query + validated ID
String cid = request.getHeader("X-Correlation-ID");
if (cid == null || !cid.matches("^[A-Za-z0-9-]{1,64}$")) {
  cid = UUID.randomUUID().toString();
}
jdbcTemplate.query("SELECT * FROM audit WHERE correlation_id = ?", cid);
```

```go
// VULN — propagate raw inbound header to downstream service
func forward(w http.ResponseWriter, r *http.Request) {
  cid := r.Header.Get("X-Request-ID")
  req, _ := http.NewRequest("GET", downstreamURL, nil)
  req.Header.Set("X-Request-ID", cid)
  http.DefaultClient.Do(req)
}

// SAFE — generate or sanitize before propagation
var corrRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
func correlationID(r *http.Request) string {
  if v := r.Header.Get("X-Request-ID"); corrRe.MatchString(v) {
    return v
  }
  return uuid.NewString()
}
```

```python
# VULN — shell out with correlation id
def trace_logs(correlation_id):
    subprocess.run(f"grep {correlation_id} /var/log/app.log", shell=True)

# SAFE — no shell; list argv; validated id
def trace_logs(correlation_id):
    if not CORR_RE.fullmatch(correlation_id or ""):
        raise ValueError("invalid correlation id")
    subprocess.run(["grep", correlation_id, "/var/log/app.log"], check=False)
```

## Safe Patterns

- **Server-generated default**: assign UUID at API gateway or first middleware; ignore or treat client value as untrusted hint.
- **Strict validation when accepting client value**: allowlist charset `[A-Za-z0-9-]` (or `[A-Za-z0-9._-]` if required); max length 64–128; reject control characters and path separators.
- **Logging**: pass correlation ID as structured field; strip `\r\n` before write — details in `log_injection.md`.
- **Filesystem**: never use header as path; if required for debug, use validated token + `basename` + resolved path containment — see `path_traversal_lfi_rfi.md`.
- **Shell/SQL**: parameterized queries; `subprocess` with argument list, never `shell=True` with header value.
- **Downstream**: propagate only validated or server-issued ID; strip client-supplied trace headers at trust boundary.
- **Response echo**: if echoing for client debugging, emit validated value only.

## Severity / Triage

| Condition | Typical severity |
|-----------|------------------|
| Correlation ID → shell/command | **Critical** |
| Correlation ID → SQL concat on sensitive query | **High** |
| Correlation ID → log line (CRLF) on tamper-evident audit | **Medium–High** |
| Correlation ID → file path read/write | **High** |
| Reflection in response header (CRLF-capable stack) | **Medium** |
| Propagation to downstream internal only, structured logs | **Low–Medium** (depends on sink) |
| Server-generated UUID only; client header ignored | **FALSE POSITIVE** |
| Validated charset + length before all sinks | **FALSE POSITIVE** |

Downgrade when: edge generates ID; client header discarded or validated on every sink path.

## Common False Alarms

- Middleware sets `req.id = uuid.v4()` and never reads client `X-Request-ID`.
- Client header validated with `^[A-Za-z0-9-]{1,64}$` (or equivalent) on every use path including propagation.
- Header logged only via structured JSON field where newlines are encoded (still verify log viewer behavior).
- Correlation ID is integer from internal counter, not from HTTP header.
- Framework-provided request ID (Express `req.id` with genid) not sourced from client header.

## Cross-References

- `log_injection.md` — CRLF forging and structured logging when correlation ID reaches log sinks (do not duplicate full log sanitizer catalog).
- `path_traversal_lfi_rfi.md` — correlation ID used in filesystem paths or archive names.
- `http_response_splitting.md` — reflected header values with CRLF in legacy response paths.
- `sql_injection.md` — when correlation ID is one of many concatenated SQL fragments.
- `rce.md` — shell/process sinks driven by header values.
- `denial_of_service.md` — oversized correlation header without length cap.
- `trust_boundary.md` — client-supplied values crossing service boundaries.

## Core Principle

Correlation and trace identifiers from inbound requests are **untrusted input**: generate them server-side when possible; otherwise enforce strict charset and length limits before any log, path, shell, SQL, propagation, or response sink — never treat tracing headers as implicitly safe infrastructure data.
