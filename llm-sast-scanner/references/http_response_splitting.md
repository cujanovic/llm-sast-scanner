---
name: http-response-splitting
description: HTTP response splitting, CRLF injection, and header/cookie injection detection — including encoding-based sanitizer bypasses (double-encoding, %u, overlong UTF-8, %5c escapes, obs-fold) (CWE-113)
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

- **Validate after full canonicalization, not before**: recursively URL-decode and Unicode-normalize the value until it stops changing, then reject if *any* control char (`[\x00-\x1f\x7f]`) is present. Stripping once leaves double/`%u`/overlong/`%5c` encodings to collapse into CR/LF at a later stage (see Evasion Patterns).
- Reject (don't just strip) any value reaching a header sink that contains CR, LF, or a control char — strip-once `replace("\r","").replace("\n","")` is bypassable by the multi-layer encodings above.
- Java: `String.replace('\n',' ').replace('\r',' ')` or `replaceAll` removing `[\r\n]` — only safe when applied to the *fully decoded* value
- Use framework APIs that encode or reject illegal header characters (most modern stacks reject embedded CR/LF at the header API)
- Netty: `validateHeaders: true` (default in secure configurations)
- Don't reflect request-derived URL/host input into `Location`/`Set-Cookie` without the canonicalize-then-reject step (covers the open-redirect+CRLF chain)

## Evasion Patterns

- URL-encoded `%0d%0a` decoded before header write
- Unicode line separators (NEL, LS, PS) if not filtered
- **UTF-8 overlong / multibyte CRLF bypass**: sequences such as `%E5%98%8A` (overlong `\n`) and `%E5%98%8D` (overlong `\r`) — and other multibyte encodings some frameworks, reverse proxies, or legacy decoders normalize to CR/LF after a naive `%0d`/`%0a`/`[\r\n]` strip. Bypasses string filters that only reject literal `\r`/`\n` or single-byte percent-encoding.
- **Multi-layer / double URL-encoding**: `%250d%250a`, `%25250a`, `%25%30%61` (→`%0a`), or malformed `%%0a0a` — the value is decoded **more than once** (edge proxy decodes, then the app decodes again, or a framework double-decodes). A sanitizer that strips `\r\n`/`%0d%0a` exactly once runs *before* the final decode and misses it.
- **Legacy `%uXXXX` Unicode escaping**: `%u000a` / `%u000d` — decoded to CR/LF by IIS, classic ASP/.NET, and some legacy stacks even though it is not standard percent-encoding.
- **Backslash-escaped form**: `%5cr%5cn` decodes to the literal text `\r\n`, which a downstream JSON/JavaScript/template/log layer then interprets as real CR/LF (C-style escape processing after URL-decode). Relevant whenever the header value transits a second escape-processing stage.
- **C-style hex/unicode escapes decoded by a rule/transform engine**: `\x0d\x0a` (and `\u000d\u000a`, octal `\015\012`) carried as *literal text* through a CDN/proxy/WAF "transform rule," edge string function (`concat()`, `lower()`, header-rewrite), or templating layer that **un-escapes hex/unicode sequences** before emitting the header — the decoded CR/LF then injects a header or splits the request, enabling header smuggling / TE.CL desync that bypasses front-end auth (e.g. edge access controls). Flag any user-influenced value passed through an escape-decoding string transform on the way into a header; the request-rewrite/transform stage must reject or strip CR/LF *after* every decode pass, not before.
- **Delimiter-prefix and obs-fold bypass**: a CR/LF preceded by a junk delimiter — leading space `%20`, tab `%09`, `#` (`%23`), or `?` (`%3F`) — defeats filters anchored at the value start or "looks like a valid URL/token" checks. A **trailing** `%0d%0a%09` or `%0d%0a%20` opens an obs-fold *continuation line* (RFC 7230 line folding) that still injects a header on permissive parsers.
- **CRLF chained with open-redirect/path-traversal prefix**: payloads like `/%2F%2E%2E%0d%0a…` place traversal/redirect syntax before the break so one input both re-points `Location` and injects a header — cross-ref `open_redirect.md`.
- Header **name** injection when attacker controls the header key (Python query covers name and value)

```python
# VULN — strips literal CR/LF once; overlong UTF-8, double-encoding, %u, and %5c survive
#   and collapse to CR/LF at a later decode/escape stage
safe = user_input.replace("\r", "").replace("\n", "")
response.headers["X-User"] = safe
# Bypasses: %E5%98%8A%E5%98%8D... | %250d%250a... | %u000d%u000a... | %5cr%5cn...

# SAFE — fully canonicalize (recursive decode) THEN reject any control char
import re
from urllib.parse import unquote
def fully_decode(s, rounds=3):
    for _ in range(rounds):
        d = unquote(s)
        if d == s:
            break
        s = d
    return s
if re.search(r"[\x00-\x1f\x7f]", fully_decode(user_input)):
    abort(400)
response.headers["X-User"] = user_input   # prefer a framework header API that rejects CR/LF
```

## Header Mirroring & Client-Controlled Content-Type

Beyond a single tainted header write, two structural shapes reflect *whole* request headers back and are easy to miss:

- **Mirroring inbound request headers into the response** — a loop that copies request headers onto the response (`for (const k of Object.keys(req.headers)) res.setHeader(k, req.headers[k])`, or a proxy "passthrough headers" config). This hands the client control over response headers wholesale: it enables CR/LF splitting (if any value carries line breaks), leaks chatty internal headers, and — most importantly — lets the client set response headers the app assumes only it controls (`Content-Type`, `Location`, `Refresh`, `Set-Cookie`, cache directives). **SAST signal**: any code path that enumerates `req.headers`/inbound header map and writes them to the response; flag even when individual values look inert.
- **Honoring a request-supplied `Content-Type` on the response → content-type confusion → XSS.** When the response Content-Type is taken from (or overridable by) the request — common with the "set Content-Type only if not already present" idiom after headers were mirrored — an endpoint that returns a *non-HTML* type containing reflected input (a JSON/`pageProps` blob, a server-component/`text/x-component` payload, an API echo) can be flipped to `text/html`. The reflected input (often an unescaped URL parameter, because escaping was deemed unnecessary for the "safe" type) then executes as HTML. If the flipped response is also cacheable, this is a **stored XSS via cache poisoning** (cross-ref `web_cache_deception.md`, `xss.md`). **SAST signal**: response `Content-Type` derived from request input, or a `if (!res.getHeader('Content-Type')) ...` set *after* request headers were mirrored; combined with reflected request data in the body.
- **Request param reflected into `Set-Cookie`** (tracking/marketing/A-B params echoed into a cookie): an unvalidated value in the cookie enables cookie injection and, with a payload the WAF would normally block, a persistent self-DoS (the poisoned cookie is replayed on every request and rejected) or escalation when the cookie is later reflected into HTML. Treat `Set-Cookie` value built from request input as a header sink (canonicalize-then-reject CR/LF and constrain the value).

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
