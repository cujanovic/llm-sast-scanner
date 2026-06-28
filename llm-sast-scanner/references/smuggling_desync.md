---
name: smuggling_desync
description: Detect HTTP Request Smuggling and desync vulnerabilities arising from inconsistent Content-Length vs Transfer-Encoding handling between frontend proxy and backend server, custom HTTP parser/proxy implementation bugs (bare CR/LF delimiters, whitespace before colon, chunk-extension mishandling, obs-fold, dual framing headers), and client-side / pause-based desync.
---

# HTTP Request Smuggling / Desync

HTTP Request Smuggling (HRS) exploits ambiguity in how a chain of HTTP servers (typically a frontend proxy + backend application server) parse request boundaries. When they disagree on where one request ends and the next begins, an attacker can "smuggle" a prefix of their request into the next user's request stream.

## Attack Types

- **CL.TE**: Frontend uses Content-Length; backend uses Transfer-Encoding chunked.
- **TE.CL**: Frontend uses Transfer-Encoding; backend uses Content-Length.
- **TE.TE**: Both support TE but one can be confused with an obfuscated header (e.g., `Transfer-Encoding: xchunked`).

## Business Risk

- Bypass security controls (WAF, access control) on the frontend.
- Poison other users' requests (request hijacking).
- Cache poisoning, credential capture via redirect.

## Source -> Sink Pattern

Static analysis does not model CL.TE/TE.CL smuggling at the proxy layer. Manual review targets **Node.js HTTP parser configuration**:

**Sources**: `process.env.NODE_OPTIONS` containing `--insecure-http-parser`; HTTP/HTTPS server or client options object with `insecureHTTPParser: true`.

**Sinks**: `http.createServer(options)`, `https.createServer(options)`, `http.request(options)`, `https.request(options)` — any invocation whose options flow includes the insecure parser flag.

## Vulnerable Conditions

- `insecureHTTPParser: true` on Node HTTP server or client options
- `NODE_OPTIONS=--insecure-http-parser` in environment configuration checked into repo or deployment manifests
- Node.js before v14.5.0 historically rejected ambiguous CL+TE less strictly

## Safe Patterns

- Leave `insecureHTTPParser` at default (`false`) or omit it entirely
- Do not set `NODE_OPTIONS=--insecure-http-parser` in production
- Use patched Node.js (post-February 2020 security releases) and reject ambiguous requests at reverse proxies

Commonly affected languages: JavaScript/Node.js only for parser-configuration checks. Java servlets, Python WSGI/ASGI, Go net/http, C#, Ruby, and nginx/Apache proxy configuration require deployment-audit review — smuggling at the proxy/backend boundary is outside typical static web query packs.

## Dynamic Test / PoC

Send raw HTTP over TCP (replace `TARGET`) or use netcat. Ambiguous CL+TE requests probe front/back-end parser disagreement.

**CL.TE** (front honors Content-Length, back honors Transfer-Encoding):

```http
POST / HTTP/1.1
Host: TARGET
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404-proof HTTP/1.1
X: x

```

If the *next* request to `/` returns the `/404-proof` body or status, desync is confirmed.

**TE.CL** (front honors Transfer-Encoding, back honors Content-Length):

```http
POST / HTTP/1.1
Host: TARGET
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

**TE.TE obfuscation** — both layers accept TE but parse obfuscated values differently (e.g. `Transfer-Encoding: xchunked`, trailing whitespace, duplicate TE headers).

**CL.CL** — dual `Content-Length` headers with different values; front and back may pick different lengths.

**Timing probe** — back-end waiting for more chunked data often hangs:

```bash
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\nX' | timeout 10 nc TARGET 80
```

Response delay or timeout versus a normal request suggests CL.TE desync.

**HTTP/2 downgrade (H2.CL / H2.TE)** — HTTP/2 front translating to HTTP/1.1 back-end with conflicting length semantics:

```bash
curl --http2 https://TARGET/ \
  -H "Content-Length: 0" \
  -H "Transfer-Encoding: chunked" \
  -d "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: TARGET\r\n\r\n"
```

Confirm desync with a harmless smuggled probe path (e.g. `GET /404-proof`) before testing sensitive routes.

**HTTP/2 cleartext upgrade (h2c) smuggling** — distinct from HTTP/2 desync: a front-end proxy that blindly forwards an `Upgrade: h2c` handshake lets the client tunnel a raw HTTP/2 connection to the back-end, bypassing front-end routing/access controls:

```bash
# Probe whether the proxy forwards the h2c upgrade to an unguarded back-end
curl -v --http2-prior-knowledge http://TARGET/ \
  -H "Connection: Upgrade, HTTP2-Settings" \
  -H "Upgrade: h2c" \
  -H "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA"
# If the upgrade succeeds end-to-end, retry a front-end-blocked path (e.g. /admin) over the tunneled h2c stream.
```

**h2c — static (config/code) signal**, not just the runtime probe: flag an edge that **forwards the client upgrade** to the backend plus a backend that **speaks h2c**. The edge bug is forwarding `Upgrade`/`Connection`/`HTTP2-Settings` instead of consuming/stripping them; the backend bug is enabling cleartext HTTP/2.
```bash
# Edge forwards client Upgrade/Connection toward upstream (WebSocket-style config also enables h2c)
rg -n 'proxy_set_header\s+Upgrade\s+\$http_upgrade|proxy_set_header\s+Connection' --glob '*.{conf,nginx}'
rg -n 'set\s+bereq\.http\.(upgrade|connection)|header_up\s+(Upgrade|Connection)' --glob '*.{vcl}' --glob 'Caddyfile*'
# Backend enables cleartext HTTP/2
rg -n 'h2c\.NewHandler|AllowHTTP2WithoutTLS|h2c\.NewClientConn|ConfigureServer.*H2C' --glob '*.go'
# Mitigation to expect (flag absence): edge clears the upgrade toward the backend
rg -n 'del-header\s+Upgrade|proxy_set_header\s+Upgrade\s+""|more_clear_input_headers.*Upgrade' --glob '*.{cfg,conf,nginx,vcl}'
```

### HTTP/2 → HTTP/1.1 downgrade translation (when the repo translates h2→h1)

H2.CL/H2.TE (probe above) are the *deployment* symptom; the *code* bug is a translator that copies HTTP/2 pseudo-headers and header fields into an HTTP/1.1 request line/headers **without RFC 7540 §8.1.2 / §10.3 validation**. Each unvalidated character becomes request-line or header injection on the h1 hop:
- **CR/LF (or NUL) in a header value or pseudo-header** → injects a second header/request (H2.X). Reject `\r`, `\n`, `\0` in every copied value.
- **`:method`, `:path`, `:authority`, `:scheme` written verbatim into the request line** → a space/CRLF in `:method` (Apache class) or control chars in `:path` smuggle a request line. Reject whitespace/controls; validate `:scheme`; reconcile `:authority` vs a copied `Host`.
- **Duplicate pseudo-headers / pseudo-headers after regular headers** → must 400, not last-wins.
- **Forwarded `Content-Length`/`Transfer-Encoding` not reconciled with the DATA-frame length** on downgrade (length is lost across the boundary) → CL/TE smuggling. Derive length from the stream end, don't trust a client-sent CL.
- **RFC 8441 extended `CONNECT` / `:protocol`** copied through without hardening → tunnel/smuggling.
Recon: `rg -n ':method|:path|:authority|:scheme|pseudo.?header|downgrade|http2.*http1' --glob '*.{go,rs,java,py,c,cpp}'` then confirm each copied value is rejected for `\r\n\0`, whitespace, and duplicates before the h1 request is serialized.

Beyond opt-in lenient flags, the smuggling bug is often **in the request-parsing code itself**. When the codebase implements an HTTP/1.1 parser, a custom proxy, a WAF, or hand-rolled header/chunked handling, audit for these RFC-7230 deviations — each creates a parse discrepancy with the *other* hop:

- **Bare CR / bare LF as a line delimiter.** Header/request lines MUST be delimited by full `CRLF`. Code that splits on `\n` alone (or treats a lone `\r` as end-of-line) desyncs against a hop that requires `CRLF`. Recon: `split('\n')` / `indexOf('\n')` / `readLine` over raw header bytes without rejecting a `\r` not followed by `\n`.
- **Whitespace around the header name / before the colon.** Accepting `Content-Length : 5` (SP/HTAB before `:`) or trimming the name lets one hop see the header and another ignore it. RFC forbids whitespace between field-name and `:` (must reject with 400). Recon: header parsers that `trim()` the name or scan for `:` ignoring leading WS.
- **Chunk-extension mishandling.** A chunked decoder that skips bytes until `\r` but tolerates an embedded `\n` (or any byte outside `0x09,0x21-0x7E,0x80-0xFF`) in the `chunk-ext` region lets `\n`-based smuggling through. Recon: chunked decoders that "ignore until CR" without validating chunk-ext bytes or requiring `CRLF`.
- **Dual / obfuscated framing headers not rejected.** Forwarding *or* accepting both `Content-Length` and `Transfer-Encoding`, duplicate `Content-Length`, `Transfer-Encoding: chunked` plus a junk second TE, or TE values matched case-insensitively/substring (`xchunked`). A compliant server returns 400; lenient code picks one and forwards the other.
- **Obsolete line folding (`obs-fold`).** Honoring leading-space continuation lines in headers (multi-line header parsing) reintroduces classic smuggling; modern parsers must reject.
- **Trailing-header injection.** Promoting chunked trailer fields into the main header set lets a smuggled `Transfer-Encoding`/`Host` ride in trailers.

These are real source-code findings (Medium-High), not just deployment notes — flag the parsing function and name the specific deviation.

### Client-Side Desync (CSD) and pause-based desync

A distinct, modern variant that needs **no second server** — the discrepancy is between the browser and a single back-end:

- **CSD / CL.0 / H2.0**: the server mishandles `Content-Length` on certain requests — e.g. a route/handler that returns a response *without consuming the request body*, or treats some POSTs as bodyless (**CL.0**: the server effectively reads the request as `Content-Length: 0`; **H2.0**: the HTTP/2 equivalent where the backend ignores the body on an "unexpected" POST). The leftover body is parsed as the start of the next request on the reused connection. Because the victim's own browser can be scripted (via `fetch`/form) to send the poisoning request, this escalates to credential capture / account takeover with no proxy involved. Recon: handlers that early-`return`/redirect on POST without reading the body; endpoints that answer **before draining the body** on routes that don't expect one — static-file handlers, redirects, `404`/`405`/error responses, `GET`-only handlers that still receive a POST. Static signal: `rg -n 'static|sendFile|redirect|301|302|404|405' --glob '*.{js,ts,go,py,java,rb,php}'` paired with POST handlers lacking a body read/drain.
- **Pause-based desync**: the back-end forwards a partially-received request after a read pause, allowing the tail to be reinterpreted. Server/proxy-internals issue; flag custom code that streams un-terminated requests upstream, and configs that emit early responses on a kept-alive socket (Varnish `return(synth(...))`, Apache `Redirect`/`RewriteRule [R]` before body read).

### Response-queue desync / response smuggling

Distinct from request smuggling: instead of prefixing the *next request*, the attacker desynchronizes the **response queue** so one client receives another client's response (cross-user response leakage), or a smuggled body is concatenated onto a later response. Two statically-detectable gadgets feed this class:
- **`HEAD` response with a body.** A proxy/handler that emits an entity body (or doesn't suppress `Content-Length`/body) on a `HEAD` lets the declared length concatenate into the next response on the connection. Recon: code paths that write a body without checking `method == HEAD`; nginx/OpenResty body emission without `ngx_http_discard_request_body`; `rg -n 'HEAD' --glob '*.{c,go,js,ts,py,java,lua,conf}'` near response-body writes.
- **`TRACE` enabled.** `TRACE` reflects the request into a response body, a ready-made gadget for response splitting/smuggling chains. Flag `TraceEnable on` (Apache, default-on before 2.4) and any framework route handling `TRACE`. Recon: `rg -n 'TraceEnable|\bTRACE\b|AllowMethods.*TRACE' --glob '*.{conf,xml,nginx}'`. SAFE: `TraceEnable off`; never emit a body on `HEAD`; cross-ref `http_response_splitting.md` (request-line/path CRLF injection is the precursor that makes this critical).

## Common False Alarms

- Single-layer architecture: direct client-to-application with no proxy in between *and* no custom request parser in the repo.
- Modern, patched server stack configured to reject ambiguous requests.
- Using a vetted, spec-compliant parser library at default settings (the bugs above only apply to hand-rolled or lenient parsing).

---

## Python Source Detection Rules

### Werkzeug / Flask
- **RISK**: `app.run(host='0.0.0.0')` behind nginx/HAProxy without explicit CL/TE normalization
- **CONFIG RISK**: `gunicorn --worker-class gevent` or `--worker-class eventlet` behind nginx — async workers have historically had TE handling differences
- **PATTERN**: `proxy_pass` in nginx config pointing to Flask/Gunicorn — audit TE header normalization
- **MITIGATION**: `proxy_http_version 1.1` + `proxy_set_header Connection ""` in nginx (disables keep-alive ambiguity)

### WSGI servers (gunicorn, uWSGI)
- **RISK**: `gunicorn` < 20.x — known CL.TE handling differences
- **RISK**: `uWSGI` with `--http-keepalive` behind a proxy that doesn't normalize TE headers
- **CONFIG FLAG**: Look for both `Content-Length` and `Transfer-Encoding` allowed simultaneously in server config

### Django / Channels
- **RISK**: Django Channels with Daphne behind nginx — WebSocket upgrade paths may have desync surface
- **PATTERN**: Any deployment where nginx is configured with `proxy_pass` to a Python WSGI/ASGI server

---

## JavaScript Source Detection Rules

### Node.js HTTP server
- **RISK**: `http.createServer()` or Express behind nginx/Cloudflare/HAProxy
- **VULN CONFIG**: Node.js before v14.5.0 — `Content-Length` and `Transfer-Encoding: chunked` together not rejected
- **PATTERN**: Express behind nginx where `proxy_set_header` does not strip/normalize TE
- **MITIGATION**: `server.maxHeadersCount`, proper nginx `proxy_http_version 1.1`

### Fastify / Koa
- **RISK**: Same as Express — proxy-backend desync depends on nginx/HAProxy config, not framework
- **PATTERN**: `app.listen()` without TLS termination at app level — implies proxy in front

---

## PHP Source Detection Rules

### Apache + PHP-FPM / mod_php
- **RISK**: Apache `mod_proxy` + PHP-FPM — TE header handling depends on Apache version and ProxyPass config
- **RISK**: Apache < 2.4.48 — known HRS vulnerabilities in mod_proxy
- **CONFIG FLAG**: `ProxyPass / http://127.0.0.1:9000/` with default TE settings
- **MITIGATION**: `RequestHeader unset Transfer-Encoding` in Apache config

### nginx + PHP-FPM
- **RISK**: nginx `fastcgi_pass` to PHP-FPM — less common HRS surface but TE obfuscation possible
- **CONFIG FLAG**: `fastcgi_keep_conn on` with ambiguous CL/TE handling

### General indicators
- Any `nginx.conf`, `apache2.conf`, `haproxy.cfg` present in the repository alongside a backend application
- `keepalive` connections enabled between proxy and backend
- No explicit CL/TE conflict rejection in proxy config

## Core Principle

HTTP request smuggling requires inconsistent message-boundary parsing between chained parsers. Static analysis can flag only the Node.js opt-in to lenient parsing; broader desync risk still requires reviewing proxy + backend pairs for dual CL/TE acceptance.

## Deployment Audit Checklist

When proxy configs are present alongside application code, manually verify:
- nginx: `proxy_http_version 1.1`; `proxy_set_header Connection ""`; reject ambiguous TE on upstream
- Apache mod_proxy: version ≥ 2.4.48; `RequestHeader unset Transfer-Encoding early`
- HAProxy: `http-reuse safe` and strict HTTP parsing options
- Disable `insecureHTTPParser` in any Node tier behind the proxy

## Node.js Examples

```javascript
// BAD — insecure parser enabled
http.createServer({ insecureHTTPParser: true }, handler);

// BAD — environment flag
process.env.NODE_OPTIONS = '--insecure-http-parser';

// SAFE — default strict parser
http.createServer(handler);
```

## Analyst Notes

- Treat `insecureHTTPParser: true` or `NODE_OPTIONS=--insecure-http-parser` as a high-confidence misconfiguration when present
- Proxy/backend desync findings from nginx+Gunicorn patterns below remain valid manual heuristics
- Do not conflate with SSRF or open redirect — smuggling poisons connection reuse, not URL validation
