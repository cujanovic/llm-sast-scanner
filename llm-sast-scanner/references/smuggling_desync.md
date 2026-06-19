---
name: smuggling_desync
description: Detect HTTP Request Smuggling and desync vulnerabilities arising from inconsistent Content-Length vs Transfer-Encoding header handling between frontend proxy and backend server.
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

## Common False Alarms

- Single-layer architecture: direct client-to-application with no proxy in between
- Modern, patched server stack configured to reject ambiguous requests.

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
