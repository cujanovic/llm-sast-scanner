---
name: trust-boundary
description: Trust boundary violation detection (CWE-501)
---

# Trust Boundary Violation (CWE-501)

Identify untrusted external input crossing into trusted session storage without proper validation. This class of vulnerability demands cross-boundary data-flow analysis.

## Definition

A trust boundary violation arises when data originating from an untrusted source — HTTP request parameters, cookies, or headers — is written directly into a trusted store such as the HTTP session, bypassing any validation or sanitization step.

## Vulnerable Conditions (any match)

External input used as session key or value without validation:
- `session.setAttribute(request.getParameter(...), ...)` — param as key
- `session.setAttribute("key", request.getParameter(...))` — param as value
- `session.putValue("key", request.getCookies()[...].getValue())` — cookie value
- `session.setAttribute("key", request.getHeader(...))` — header value
- Indirect flow: `String x = request.getParameter("foo"); ... session.setAttribute("key", x);`

## Safe Patterns (all required)

- Value stored in session is a **constant** or **validated/transformed value**
- Ternary with always-true condition producing constant: `(7*18)+106 > 200 ? "constant" : param` -> 232 > 200 is true -> result is constant -> SAFE
- Input is validated against whitelist before session storage
- Input is type-converted (e.g., `Integer.parseInt()`) before storage

## Mandatory Check Pattern

When you see `session.setAttribute(...)` or `session.putValue(...)`:
`Trust Boundary check: value source=? / is constant=? / validated=? -> VULN or SAFE`

## Ternary Expression Rules

You MUST compute ternary conditions:
- `(7 * 42) - num > 200 ? "constant" : param` -> 294 - 106 = 188 > 200 is FALSE -> result is param -> **VULN**
- `(7 * 18) + num > 200 ? "constant" : param` -> 126 + 106 = 232 > 200 is TRUE -> result is constant -> **SAFE**

## Common Propagation Patterns
1. Direct: `session.setAttribute("user", req.getParameter("user"))`
2. Variable chain: `String u = req.getParameter("u"); session.setAttribute("user", u);`
3. Collection: `list.add(req.getParameter("x")); session.setAttribute("data", list);`
4. Method return: `String val = getInput(req); session.setAttribute("key", val);` — trace getInput()

## Java Servlet Patterns (CWE-501)

**VULN** — tainted HTTP input stored in server-side session without validation:
```java
HttpSession session = request.getSession();
session.setAttribute("role", request.getParameter("role"));   // VULN
session.setAttribute("userId", request.getParameter("id"));
```

**SAFE** — only server-generated values stored in session:
```java
String role = lookupRoleFromDatabase(authenticatedUser);
session.setAttribute("role", role);  // SAFE: not from request directly
```

**Decision rule**: `session.setAttribute(key, request.getParameter(...))` or any chain where tainted data flows directly into session → **VULN**.

**Edge cases**:
- `HttpSession.putValue(...)` is equivalent to `setAttribute(...)` and is **VULN** when either the key or the value is tainted.
- HTML encoding is NOT a trust-boundary defense — encoding a request value then storing it in session remains **VULN**.
- Only server-generated keys and server-generated values make this pattern **SAFE**.
- Reading `X-Forwarded-For`, `Host`, or similar headers is not `trust_boundary` by itself. Confirm only when that value crosses into session state, auth decisions, backend or proxy selection, or other privileged runtime configuration.
- When the issue is client-IP spoofing through `X-Forwarded-For`, prefer `xff_spoofing`; do not add a second `trust_boundary` tag unless a separate privileged boundary crossing exists.

## Header-Based Trust / Auth-Context Spoofing (class)

A related class worth detecting independently of session storage: an application treats a **client-controllable request header** as a trust signal for authentication, authorization, or "this request is internal." Because anyone can send the header, the gate is bypassable. Detect by the shape *"an auth / identity / internal-origin decision reads a request header"*, regardless of framework.

**Headers commonly over-trusted:**
- Identity injected by an edge/gateway but not stripped from external requests: `X-User-Id`, `X-Authenticated-User`, `X-Email`, `X-Roles`, `X-Auth-*`, `Remote-User`
- "Internal / subrequest" markers: `X-Internal`, generic `X-Forwarded-*`, and framework-specific internal markers such as Next.js `x-middleware-subrequest`
- Client-IP trust: `X-Forwarded-For`, `True-Client-IP`, `X-Real-IP` (for IP-only cases prefer the `xff_spoofing` tag)

**Concrete instance — middleware-only authorization (Next.js `x-middleware-subrequest`)**: when authn/authz is enforced *only* in edge `middleware.ts`, a request the framework treats as an internal subrequest skips the middleware entirely. Generic lesson: **never enforce authorization solely at a layer that a client-supplied header can cause the request to bypass.** Re-derive identity from a server-trusted source and re-check authorization in the handler/route itself (defense in depth).

```js
// VULN — trusts a client header as proof of identity / internal origin
if (req.headers['x-internal'] === '1') return next();   // any client can send this
const userId = req.headers['x-user-id'];                // spoofable identity used for authz
// VULN — authz ONLY in middleware; the route handler re-trusts it with no check of its own
```
**SAFE**: identity comes from a server-verified session/token re-derived per request; gateway-injected identity headers are explicitly stripped at the trust boundary before the app reads them; authorization is re-checked in the handler, not just in middleware/edge.

## FALSE POSITIVE Rules

- Do NOT emit `trust_boundary` for session attributes set from validated/sanitized user input. If the value is type-checked, range-validated, or comes from a controlled set (e.g., enum selection), the trust boundary is maintained.
- Do NOT emit `trust_boundary` when the stored value has no security-relevant impact (e.g., display preferences, pagination settings).
- Do NOT emit `trust_boundary` when the vulnerability is better described by a more specific tag (e.g., `xff_spoofing` for X-Forwarded-For abuse, `session_fixation` for session management issues).
- Prefer narrow tags: if the pattern is a role/privilege stored from user input, use `privilege_escalation`; if it is IP trust, use `xff_spoofing`.
