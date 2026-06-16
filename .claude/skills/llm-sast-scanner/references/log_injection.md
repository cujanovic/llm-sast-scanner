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
