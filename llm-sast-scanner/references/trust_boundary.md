---
name: trust-boundary
description: Trust boundary violation detection (CWE-501), header-based identity/origin spoofing, network-origin / IP-range trust bypass via shared multi-tenant cloud, CI/CD, and serverless egress (CWE-290/291), and mutable internal-state exposure — returning/storing live references to mutable objects and mutable public-static fields (CWE-374/375/582/607)
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

## Mutable Internal-State Exposure (CWE-374 / CWE-375 / CWE-582 / CWE-607)

A second trust-boundary class, common in Java/JVM and applicable to any reference-semantics language: an object hands out, or absorbs, a **live reference to mutable internal state** instead of a copy. The caller (or untrusted code sharing the JVM — plugins, deserialization gadgets, same-process tenants) can then mutate that state *after* validation, defeating an invariant the object relies on. It matters specifically when the mutable value is **security-relevant** — a roles/permissions array, a `Date` used for token/cert expiry, key/IV bytes, an allow-list collection — or when instances are reachable by untrusted code.

**Two shapes:**

1. **Instance representation exposure** — a getter returns the internal field directly (CWE-374, return side), or a constructor/setter stores the caller's object directly (CWE-375, ingest side). Arrays, `Date`/`Calendar`, `Collection`/`Map`, and `byte[]` buffers are mutable; `String`/boxed primitives/`BigInteger` are not.
   ```java
   // VULN — caller can rewrite the role set after construction / after an auth check
   private String[] roles;
   public String[] getRoles() { return roles; }          // return side — hands out the live array (CWE-374)
   public void setRoles(String[] r) { this.roles = r; }   // ingest side — stores the caller's live array (CWE-375)
   // SAFE — defensive copy on both boundaries (or expose an unmodifiable view)
   public String[] getRoles() { return roles.clone(); }
   public void setRoles(String[] r) { this.roles = r.clone(); }
   // collections: return Collections.unmodifiableList(roles); store new ArrayList<>(r);
   // Date: return new Date(expiry.getTime());  // or use java.time.Instant (immutable)
   ```

2. **Mutable static state** (CWE-582/607/500) — a `public static` field that is non-`final` (reassignable) **or** `final` but references a mutable array/collection (the reference is fixed, the *contents* are not). Any code in the JVM can rewrite global security config.
   ```java
   public static final String[] ADMIN_IPS = {"10.0.0.1"};  // final ref, but contents writable by anyone (CWE-607)
   public static int MAX_LOGIN_ATTEMPTS = 3;                // non-final public static → reassignable (CWE-500/582)
   // SAFE — List.of(...) / Collections.unmodifiableList(...), and make scalars `static final`
   public static final List<String> ADMIN_IPS = List.of("10.0.0.1");
   ```

**TRUE POSITIVE**: getter `return`s a field, or constructor/setter assigns a parameter, where the field type is a mutable array/`Date`/`Calendar`/`Collection`/`Map`/`byte[]` **and** the value is security-relevant or the class is reachable by untrusted code; any `public/protected static` non-final field; `public static final` array/mutable-collection.

**FALSE POSITIVE**: the field is an immutable type (`String`, boxed primitive, `BigInteger`, `record` of immutables, `java.time.*`); the getter already returns a copy / `unmodifiable*` view; package-private/internal-only class with no untrusted reachability and no security-relevant content (encapsulation nit, not a finding). Severity is usually Low–Medium — escalate when the mutated object directly feeds an authn/authz/crypto/expiry decision.

**Grep seeds:**
```bash
rg -n 'public\s+static\s+(?!final)[A-Za-z<>\[\]]+\s+\w+\s*=' --glob '*.java'   # non-final public static
rg -n 'public\s+static\s+final\s+\w+\[\]|public\s+static\s+final\s+(List|Map|Set|Collection)' --glob '*.java'  # mutable static
rg -n 'return\s+(this\.)?\w+;\s*$' --glob '*.java'   # candidate getters — confirm field is a mutable type returned without .clone()/copy
```

## Cloud / Serverless Event Payloads as Untrusted Input (FaaS)

In a Lambda/Cloud-Function/Azure-Function handler, the **`event` object is attacker-influenced data, not a trusted internal call** — every field crossing into the function is a taint source, even when the trigger is "internal." Treat these as sources and trace them to the usual sinks (command/SQL/XXE/SSRF/cloud-API) in `rce.md`, `sql_injection.md`, `xxe.md`, `ssrf.md`:

- **S3 event** — `event['Records'][0]['s3']['object']['key']` (and `bucket.name`) are set by whoever can upload; URL-decode, then it commonly flows to `os.system`/`subprocess`/path joins. An uploaded object's **content** later parsed by the function (XML/CSV/YAML) is equally untrusted (XXE / `yaml.load`).
- **SNS / SQS / Kinesis / EventBridge** — `event['Records'][i]['Sns']['Message']` / `body` / `kinesis.data` (often base64) is publisher-controlled; JSON-parsed then spliced into SQL string-format, a shell, or a downstream API call.
- **API Gateway / Function URL** — `event['queryStringParameters']`, `['headers']`, `['pathParameters']`, `['body']`, `requestContext.authorizer.*` claims are raw request input (same as any web param).
- **DynamoDB Streams** — `event['Records'][i]['dynamodb']['NewImage']` reflects whatever a writer (possibly a lower-trust path) stored — second-order taint.
- **Cloud-API parameter injection** — an event field forwarded as an AWS-SDK argument (DynamoDB `ComparisonOperator`/`FilterExpression`, an S3 key, an IAM/STS parameter) without an allow-list lets the caller alter the API's semantics.

**SAFE**: schema-validate the event at the handler boundary (JSON Schema / `pydantic`); never pass event fields to a shell (`shlex.quote`, no `shell=True`); parameterize SQL; harden XML parsers; allow-list any event-derived value used as a cloud-API argument.

## FALSE POSITIVE Rules

- Do NOT emit `trust_boundary` for session attributes set from validated/sanitized user input. If the value is type-checked, range-validated, or comes from a controlled set (e.g., enum selection), the trust boundary is maintained.
- Do NOT emit `trust_boundary` when the stored value has no security-relevant impact (e.g., display preferences, pagination settings).
- Do NOT emit `trust_boundary` when the vulnerability is better described by a more specific tag (e.g., `xff_spoofing` for X-Forwarded-For abuse, `session_fixation` for session management issues).
- Prefer narrow tags: if the pattern is a role/privilege stored from user input, use `privilege_escalation`; if it is IP trust, use `xff_spoofing`.

## Client-IP & Network-Origin Trust → `xff_spoofing.md`

IP-trust failures have their own dedicated reference: **`xff_spoofing.md`** covers
client-supplied IP spoofing (CWE-348 — `X-Forwarded-For`/`X-Real-IP`/`True-Client-IP`/`Forwarded`
derivation failures: no trusted-proxy gate, single-instance reads on duplicate headers, spoofable
fallback chains, edge-append vs replace, RFC 7239 fail-open, unvalidated IP used as a rate-limit/cache
key) **and** network-origin trust (CWE-290/291 — granting trust by membership in a multi-tenant cloud/CI/
serverless/datacenter IP range).

Use `trust_boundary` here only when a spoofed IP additionally crosses into **session state or privileged
configuration**; for pure IP-trust bugs prefer the `xff_spoofing` tag and that reference.
