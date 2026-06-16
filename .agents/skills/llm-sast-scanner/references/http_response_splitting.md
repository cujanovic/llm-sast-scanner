---
name: http-response-splitting
description: HTTP response splitting and header injection detection (CWE-113)
---

# HTTP Response Splitting / Header Injection (CWE-113)

Writing user-controlled data into HTTP headers without neutralizing CR (`\r`) and LF (`\n`) lets attackers inject additional headers or split the response into two messages — enabling XSS, cache poisoning, session fixation, and request-smuggling-like SSRF in client sockets.

## Source -> Sink Pattern

**Sources**: request parameters, cookies, path segments, and other remote input reaching header construction.

**Sinks**:
- Java servlet: `response.setHeader(name, userValue)`, `addHeader`, `addCookie` with tainted cookie value; `HttpServletResponse.sendRedirect` Location (when combined with splitting chars — distinct from open redirect without CR/LF)
- Java Netty: HTTP encoder/decoder with `validateHeaders: false`
- Python: WSGI/Flask/Django `response.headers[...] = userValue`, `set_cookie`, `HttpResponse` header writes
- Any framework header write where name or value is tainted

## Vulnerable Conditions

- User input concatenated into header values without stripping `\r` or `\n`
- Cookie values, `Set-Cookie`, `Location`, custom headers built from request data
- Netty pipeline configured with header validation disabled
- Servlet containers that do not escape embedded blank lines in header values

## Safe Patterns

- Reject or strip CR/LF before any header write: `value.replace("\r","").replace("\n","")`
- Java: `String.replace('\n',' ').replace('\r',' ')` or `replaceAll` removing `[\r\n]`
- Use framework APIs that encode or reject illegal header characters
- Netty: `validateHeaders: true` (default in secure configurations)

## Evasion Patterns

- URL-encoded `%0d%0a` decoded before header write
- Unicode line separators (NEL, LS, PS) if not filtered
- Header **name** injection when attacker controls the header key (Python query covers name and value)

## Sanitizers / Barriers

Commonly affected languages: Java (servlet + Netty), Python. JavaScript, Go, C#, Ruby, and PHP require manual review.

**Recognized sanitizers**:
- Java: `String.replace`/`replaceAll` removing `\r`/`\n` (char 10/13); regexp guards rejecting line breaks; type barriers for non-string sinks
- Python: WSGI validators and framework barriers where modeled; line-break removal before write

## Java / Spring

- **VULN**: `response.addHeader("X-Custom", request.getParameter("name"))` — parameter contains `%0d%0aSet-Cookie: ...`
- **VULN**: Netty `DefaultHttpHeaders(true, false)` or explicit `validateHeaders(false)`
- **SAFE**: sanitize with `replaceAll("[\\r\\n]", "")` before `setHeader`

## Python

- **VULN**: `response.headers['X-User'] = request.args['name']`
- **SAFE**: escape line breaks before assigning header

## JavaScript / Node

Manual review: `res.setHeader('X-Custom', userInput)`, `res.cookie()` with tainted values

## Common False Alarms

- Header values from server-generated tokens/UUIDs with no remote input path
- Open redirect without CR/LF in the Location value — classify as `open_redirect`, not header splitting
- Frameworks that automatically reject header values containing `\r` or `\n` at runtime (verify version)

## Business Risk

- Reflected/stored XSS via injected `Content-Type` or body in split response
- Web cache poisoning forcing cached malicious pages
- Session hijacking via injected `Set-Cookie`
- Client-side request splitting when user input reaches outbound HTTP client headers

## Core Principle

Treat HTTP header values like output contexts: never embed raw remote input. Strip or reject CR and LF (and equivalent Unicode separators) before any header or cookie write.

## Distinguishing From Open Redirect

Java and Python header detection requires taint into **header write sinks**, not merely `Location` redirects. A user-controlled external URL in `Location` without `\r`/`\n` is `open_redirect` (CWE-601), not CWE-113. Escalate to header splitting only when line-break injection is possible or Netty validation is disabled.

## Netty-Specific (Java)

Netty HTTP request/response splitting detection covers:
- Response splitting when `validateHeaders: false` on encoders
- Request splitting in Netty client pipelines with validation disabled

## Python Header Example

```python
# BAD — user input in header name or value
response.headers[user_input] = value

# GOOD — escape line breaks before write
safe = user_input.replace("\r", "").replace("\n", "")
response.headers["X-Safe"] = safe
```

## Analyst Notes

- Modern servlet containers reject embedded newlines in many versions — verify runtime behavior for false-positive triage
- Cookie-based splitting often overlooked — `addCookie` with tainted value is in Java sink set
- Cache poisoning impact depends on CDN accepting injected `Cache-Control` or split body

## Ruby / C# / JavaScript

Manual sinks:
- Ruby: `response.headers['X'] = params[:v]`
- C#: `Response.Headers.Add("X-Custom", userInput)`
- Node: `res.setHeader`, `res.cookie` with unsanitized values

## Response vs Request Splitting

Java Netty detection covers both response splitting (poison downstream clients/cache) and request splitting (inject into client outbound socket — SSRF-like per CAPEC-105).
