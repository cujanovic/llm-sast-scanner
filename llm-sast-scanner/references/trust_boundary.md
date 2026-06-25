---
name: trust-boundary
description: Trust boundary violation detection (CWE-501), header-based identity/origin spoofing, and network-origin / IP-range trust bypass via shared multi-tenant cloud, CI/CD, and serverless egress (CWE-290/291)
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

**Concrete instance — middleware-only authorization (Next.js `x-middleware-subrequest`, CVE-2025-29927)**: when authn/authz is enforced *only* in edge `middleware.ts`, a client-supplied `x-middleware-subrequest` header causes the framework to treat the request as an internal subrequest and **skip middleware entirely** — including auth gates. Affected Next.js **11.1.4 through 15.2.2**; fixed in **15.2.3** and **14.2.25**. Generic lesson: **never enforce authorization solely at a layer that a client-supplied header can cause the request to bypass.** Re-derive identity from a server-trusted source and re-check authorization in the handler, Server Action, or Route Handler (defense in depth). Function-level escalation from middleware-only auth: `privilege_escalation.md`; path/proxy representation splits: `reverse_proxy_access_bypass.md`.

**Package.json semver heuristic** — flag dependency when `next` satisfies vulnerable range and middleware is the sole auth layer:

```bash
rg -n '"next"\s*:\s*"' package.json package-lock.json pnpm-lock.yaml yarn.lock
# Vulnerable if semver in [11.1.4, 15.2.3) on 15.x track or [11.1.4, 14.2.25) on 14.x track
# Pair with: rg -l 'middleware' --glob 'middleware.{ts,js}'
```

```json
// package.json — heuristic TRUE POSITIVE when middleware.ts is sole auth gate
{ "dependencies": { "next": "15.1.0" } }
```

**Middleware-only auth anti-pattern (SAST)** — no `[Authorize]` / session re-check in the route handler, Server Action, or API route the middleware was meant to protect:

```bash
rg -n 'export\s+(async\s+)?function\s+middleware|NextResponse\.redirect|NextResponse\.next' middleware.ts
# Then verify protected app/**/route.ts and page.tsx lack independent auth guard
rg -L 'getServerSession|auth\(|verifySession|getSession' --glob 'app/**/{route,page,layout}.{ts,tsx}'
```

```js
// VULN — trusts a client header as proof of identity / internal origin
if (req.headers['x-internal'] === '1') return next();   // any client can send this
const userId = req.headers['x-user-id'];                // spoofable identity used for authz

// VULN — authz ONLY in middleware.ts; route handler performs sensitive work with no re-check
// Attacker: curl -H 'x-middleware-subrequest: middleware' https://app/admin
export async function GET() {
  return deleteAllUsers();   // no getServerSession() / role check here
}
```

**SAFE**: identity comes from a server-verified session/token re-derived per request; gateway-injected identity headers are explicitly stripped at the trust boundary before the app reads them; authorization is re-checked in every protected handler — not only in middleware/edge; upgrade `next` to a patched release.

## FALSE POSITIVE Rules

- Do NOT emit `trust_boundary` for session attributes set from validated/sanitized user input. If the value is type-checked, range-validated, or comes from a controlled set (e.g., enum selection), the trust boundary is maintained.
- Do NOT emit `trust_boundary` when the stored value has no security-relevant impact (e.g., display preferences, pagination settings).
- Do NOT emit `trust_boundary` when the vulnerability is better described by a more specific tag (e.g., `xff_spoofing` for X-Forwarded-For abuse, `session_fixation` for session management issues).
- Prefer narrow tags: if the pattern is a role/privilege stored from user input, use `privilege_escalation`; if it is IP trust, use `xff_spoofing`.

## Client-Supplied IP (CWE-348)

Commonly affected languages: Java, Python.

### Source → Sink Pattern

- **Source**: HTTP request headers — `X-Forwarded-For`, `X-Real-IP`, `Proxy-Client-IP`, and similar client-influenced IP headers.
- **Sink**: Security-sensitive use of the extracted IP — ban-list checks, rate limiting keyed on IP, admin-only access gated on `127.0.0.1`, audit allowlists.
- **Sanitizer**: Using the **last** (appended) entry in a comma-separated `X-Forwarded-For` chain when behind a trusted reverse proxy; validating IP against a server-side session; ignoring client-supplied headers entirely.

**VULN**: `String ip = request.getHeader("X-Forwarded-For").split(",")[0]; if (blocked.contains(ip)) deny();` — first XFF entry is attacker-controlled.
**SAFE**: Take the last XFF hop added by the trusted proxy, or derive client IP from the TCP connection at the edge. **Caveat**: a correctly-derived connection IP still is not an identity — see Network-Origin / IP-Range Trust Bypass below.

Relates to header-based trust patterns above — prefer `xff_spoofing` when the sole issue is IP spoofing; use `trust_boundary` when spoofed IP crosses into session state or privileged configuration.

## Network-Origin / IP-Range Trust Bypass (shared multi-tenant egress, CWE-290/291)

A separate class from header spoofing: the application determines the source IP **correctly** (from the TCP connection, not a client header) but grants trust because that IP falls in a **"trusted" network range** — and that range is actually **multi-tenant**, so any attacker can originate requests from inside it. Membership in the range proves *where* the packet came from, never *who* sent it. Taking the "real" connection IP (the usual fix for header spoofing) does **not** mitigate this.

**Over-trusted origins (all rentable/shared by anyone)**:
- **Cloud provider published CIDRs** — allowlisting AWS/GCP/Azure/Cloudflare IP ranges; an attacker simply runs from the same provider and lands in the same ranges.
- **CI/CD runner egress** — GitHub Actions, GitLab CI, Bitbucket Pipelines shared runners share an egress pool; anyone with a free account sends traffic from those IPs.
- **Serverless / managed-proxy egress** — Cloudflare Workers, AWS Lambda / API Gateway, other FaaS egress IPs are shared across all tenants; an attacker deploys their own function to borrow the origin.
- **"Same datacenter / region / VPC / internal"** — rules like `allow if src in same-region` or `allow if src in 10.0.0.0/8` trust co-tenants or anyone who gains a foothold in the shared network.

**Why it's weak**: these boundaries assume the trusted range is *yours alone*. On shared cloud/CI/serverless infrastructure it is not — the egress is pooled across every customer, so "from our datacenter / our cloud / our CI" is satisfiable by an external attacker at near-zero cost.

**SAST signals**:
```bash
# allowlists / firewall configs keyed on cloud-provider or shared ranges
rg -ni "aws.*ip.?ranges|ip-ranges\.json|cloudflare.*ips|googleusercontent|amazonaws|azure.*service.?tags" --glob '*.{tf,yaml,yml,json,py,js,ts,go,rb,java}'
# "internal/same region/same datacenter" origin trust, or provider CIDR allow rules
rg -ni "same.?region|same.?datacenter|internal traffic|trusted (range|cidr|subnet)|allow.*from (aws|gcp|azure|cloudflare|datacenter)" -C2
# code comparing source IP against a provider/internal CIDR set as an auth/authz gate
rg -ni "ip_address\(.*\) in |ipaddress\.ip_network|cidr.*contains|InRange.*ip|net\.ParseCIDR" -C2
```

**VULN** (Python — access gated on cloud/CI egress range; attacker rents the same origin):
```python
# rule trips an SSRF/ssrf-prevention rule too: trusting network origin as identity
TRUSTED = [ipaddress.ip_network(c) for c in load_aws_ranges() + CI_EGRESS_CIDRS]
def is_internal(req):
    ip = ipaddress.ip_address(req.transport_peer_ip)   # correctly derived, still not identity
    return any(ip in net for net in TRUSTED)            # VULN: range is multi-tenant
```

**SAFE**: authenticate the *caller*, not the network. Use mutual TLS, signed/short-lived service tokens, HMAC request signing, or cloud workload identity (OIDC) for service-to-service and "internal" calls. Never use cloud-provider/CI/serverless/datacenter/region membership as an authn or authz control. If IP allowlisting is genuinely required, restrict to **dedicated single-tenant egress you own** (e.g., a NAT gateway with a static IP under your control) **and** still layer real authentication on top. Cross-ref `ssrf.md` (server-side request origin), `privilege_escalation.md`, `reverse_proxy_access_bypass.md`.
