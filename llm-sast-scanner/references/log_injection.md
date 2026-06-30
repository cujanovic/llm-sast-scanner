---
name: log-injection
description: Log injection and log forging detection (CWE-117)
---

# Log Injection / Log Forging (CWE-117)

If unsanitized user input is written to log files or log aggregation systems, attackers can forge extra log lines, hide malicious activity, inject fake audit entries, or break downstream parsers. HTML-bearing logs may also enable log-viewer XSS.

## Source -> Sink Pattern

**Sources**: remote HTTP parameters, headers, cookies, and other user-controlled strings (`ActiveThreatModelSource`).

**Sinks (`log-injection` kind)**:
- Java: SLF4J/Log4J/JUL `logger.warn/info/error(...)` with tainted message or format args
- Python: `logging.Logger` methods (`info`, `warning`, `error`, `warn`)
- JavaScript: `console.log`, Winston/Pino/Bunyan and modeled logging APIs
- Go: standard `log` package and structured loggers
- Ruby: Rails/logger calls
- C#: log-forging sinks — trace/write to `ILogger`, `Trace`, etc.

## Vulnerable Conditions

- User input concatenated or formatted directly into log messages
- Newlines (`\r`, `\n`, `%0a`) in usernames, search terms, or IDs logged verbatim
- Log viewers rendering HTML without encoding user-derived log content

## Safe Patterns

- Strip newlines: `input.replace("\n","").replace("\r","")` before logging
- Java: `matches("[a-zA-Z0-9]+")` guard — rejects malicious username entirely before logging
- Java: `String.replace`/`replaceAll` removing `\r`/`\n` recognized as sanitizer
- Python: `.replace("\n", "")` / `.replace("\r\n", "")` on string before logging
- Wrap user data in clearly delimited, encoded fields; use structured JSON logging with encoding
- HTML log UIs: HTML-encode user content before display
- **Recognized sanitizers**: Java `replace`/`replaceAll` removing line breaks; regexp `matches()` guards excluding `\r\n`; `SimpleTypeSanitizer`; models-as-data `log-injection` barriers; Python `ConstCompareBarrier`; `.replace("\r\n")` / `.replace("\n")`; models-as-data barriers; external `log-injection` barrier models from extensions

## Evasion Patterns

- Unicode line separators if only `\r`/`\n` stripped
- Log forging via `%` format specifiers when user input is format string (distinct class — verify logger API)
- CRLF in alternate encodings (`\u2028`, `%0d%0a` after URL decode)

Commonly affected languages: Java, Python, JavaScript, Go, Ruby, C#, Rust (web scope).

## Java / Spring

- **VULN**: `logger.warn("User:'" + username + "'");` with request parameter `Guest%0AUser:'Admin`
- **SAFE**: `if (!username.matches("[a-zA-Z0-9]+")) return;` before logging

## Python

- **VULN**: `logger.info(f"Login attempt: {request.args['user']}")`
- **SAFE**: `safe = user.replace("\n", "").replace("\r", ""); logger.info("Login: %s", safe)`

## JavaScript / Node

- **VULN**: `console.log('User:', req.query.name)` with embedded newlines
- **SAFE**: structured logger with encoded fields; strip `\r\n` before write

## Go

- **VULN**: `log.Printf("user=%s", r.FormValue("user"))`
- **SAFE**: sanitize or reject inputs containing `\n` before logging

## C#

- **VULN**: `_logger.LogInformation("User " + userInput);`
- **SAFE**: newline removal or strict allowlist validation before log write

## Ruby

- **VULN**: `Rails.logger.info "User #{params[:name]}"`
- **SAFE**: `params[:name].gsub(/[\r\n]/, '')` before interpolation

## Common False Alarms

- Logging fixed enum/status codes with no user-controlled substring
- Structured logs where user input is JSON-encoded as a field value (newlines contained in string — verify viewer behavior)
- Java `replaceAll` that accidentally replaces `\n` with `\r` — imperfect sanitizer detection may miss this
- Heuristic JS expanded-source rules on non-security log lines

## Business Risk

- Audit trail forgery hiding intrusion or fraud
- Compliance failure (PCI/SOC2) on tamper-evident logging
- SIEM alert injection or evasion
- XSS in admin log-viewer panels

## Core Principle

Log entries must treat user input as untrusted display data. Remove or reject line-break characters before writing, and encode when logs are rendered as HTML.

## Security Events to Log

Log security-relevant events with stable, machine-parseable event types and severity. Minimum high-value categories:

| Category | Event examples | Typical level |
|----------|----------------|---------------|
| Authentication | login success/fail, lockout, password change, token create/revoke/reuse | INFO–CRITICAL |
| Authorization | access denied, privilege/role change, admin actions | WARN–CRITICAL |
| Session | create, renew, expire, use-after-expire | INFO–CRITICAL |
| Input validation | server-side validation failure on sensitive fields | WARN |
| Sensitive data | create/read/update/delete of classified records | WARN |
| Abuse / attack | rate-limit exceeded, excess 404s, unexpected parameters, direct-object reference probes | WARN–CRITICAL |
| System | startup/shutdown, security monitor disabled | WARN |

Include on every security event where applicable: UTC timestamp (ISO 8601), correlation/request ID, app identifier, source IP, user agent, HTTP method/URI — use pseudonymous or hashed user identifiers when full IDs are PII.

**Absence is itself a finding (OWASP A09 / CWE-778 — Security Logging & Monitoring Failures).** The inverse of the injection bug above: not "bad data in the log" but "no log at all." When a security-critical handler — login/MFA, password reset, privilege/role change, payment/transfer, admin action, or an access-control **denial** — emits *nothing* on its success/failure path, the breach is undetectable (no trail for IR/SIEM, no alerting). Statically this is a sink-present / log-absent pattern (the sensitive handler exists; no logger call on the branch). **Keep it low-confidence and low-severity (Info/Low):** absence is noisy to prove and is an audit-checklist item, not a taint finding — only raise it when a specific security-critical path *demonstrably* logs nothing. A log an attacker can `DELETE`/`TRUNCATE`/overwrite fails A09 just as missing logging does (append-only / tamper-evident storage — cross-ref the mutable-audit-trail note in `excessive_agency.md`).

```json
{
  "datetime": "2026-06-16T12:00:00Z",
  "event": "authn_login_fail",
  "level": "WARN",
  "correlation_id": "req-abc123",
  "source_ip": "203.0.113.10",
  "user_id_hash": "sha256:…"
}
```

## Structured Logging Requirements

- Prefer JSON/structured fields over concatenated free-form strings for security signals
- Use stable field names (`event`, `level`, `correlation_id`, `user_id_hash`) — not ad-hoc sentence templates for alert-critical events
- Pass user-controlled values as **encoded field values**, not as the log format string (prevents `%` format injection and newline forging)
- Sanitize all external input before write: strip `\r`, `\n`, Unicode line separators (`\u2028`, `\u2029`) from string fields destined for plain-text or SIEM pipelines
- Never pass raw user input as the first argument to printf-style loggers when it may contain `%` specifiers

```python
# VULN: user controls format string and can inject newlines
logger.info(f"Login attempt: {username}")

# SAFE: structured field; newlines stripped; secrets excluded
safe_user = username.replace("\r", "").replace("\n", "")
logger.info("authn_login_fail", extra={"username": safe_user, "correlation_id": req_id})
```

## Sensitive Data Logging (Forbidden)

**Never log in cleartext**: passwords, API keys, access/refresh tokens, session IDs, recovery codes, private keys, database connection strings, payment card or bank data, government IDs, full request/response bodies, or other PII beyond what policy explicitly permits.

Required controls:
- Redact or tokenize sensitive fields at the logging layer (`[REDACTED]`, HMAC/hash of identifiers, truncated last-4 only where business requires)
- Block-list field names in serializers (`password`, `token`, `authorization`, `cookie`, `ssn`, `credit_card`)
- Audit log pipelines periodically for secret/PII leakage patterns

```javascript
// VULN: credentials and token in log line
logger.info(`Auth header: ${req.headers.authorization}, body: ${JSON.stringify(req.body)}`);

// SAFE: log event type and correlation only; no secrets or full body
logger.info({ event: 'authn_login_fail', correlation_id: req.id, source_ip: req.ip });
```

```java
// VULN: password and session token logged
logger.warn("Login failed for user=" + username + " password=" + password + " token=" + sessionToken);

// SAFE: redacted structured fields
logger.warn("authn_login_fail user={} correlationId={}", username.replaceAll("[\\r\\n]", ""), correlationId);
```

## Log-Analysis Sink Injection

Plain-text and regex-based SIEM parsers treat injected newlines as record boundaries. Forged lines can hide intrusion, trigger false alerts, or poison downstream aggregations.

- Neutralize CR/LF in all user-derived log fields before write
- JSON-encode user strings as field values so embedded newlines stay inside quoted strings
- HTML log viewers: encode user-derived content before render (log injection → log-viewer XSS chain)

## Sensitive-Data & Unsanitized-Input SAST Indicators

**Log injection / forging (CWE-117)**:
- User-controlled variables (`request.getParameter`, `req.query`, `params[]`, headers, cookies) concatenated into log message strings without newline sanitization
- Tainted data as first/format argument to `logger.info(userInput, …)`, `log.Printf(userInput, …)`, `console.log` template with raw user fields
- Missing `\r`/`\n`/`\u2028` stripping barrier between remote source and log sink

**Sensitive logging (CWE-312 / CWE-532)**:
- Log calls including variables named or typed as secrets: `password`, `token`, `apiKey`, `authorization`, `cookie`, `sessionId`, `creditCard`, `ssn`
- Logging full `req.body`, `req.headers`, `HttpServletRequest` dumps, or exception messages that echo SQL/credentials
- `JSON.stringify(req)` / `toString()` on request or auth objects passed to log sinks
- Missing redaction middleware on structured log serializers

## Example Payload (Java)

Malicious username: `Guest'%0AUser:'Admin`

BAD log line splits into:
```
User:'Guest'
User:'Admin'
```

GOOD endpoint rejects non-alphanumeric username via `matches("[a-zA-Z0-9]+")` before logging.

## Sink Coverage Notes

- Python excludes internal `logging/__init__.py` implementation noise when analyzing stdlib
- Java precision is **medium** — regexp sanitizer guards and partial replace detection
- C# log-forging class — same CWE-117 as other languages
- JavaScript expanded-source heuristics widen the source set beyond default remote inputs

## Analyst Notes

- Distinguish log injection from log **forgery via log level manipulation** — out of scope unless user controls severity
- SIEM pipelines parsing plain text are primary impact surface
- For compliance, pair newline stripping with immutable/append-only log storage
