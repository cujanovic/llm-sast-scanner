---
name: idor
description: IDOR/BOLA testing for object-level authorization failures and cross-account data access
---

# IDOR

Object-level authorization failures (BOLA/IDOR) expose data and permit unauthorized modifications across APIs, web, mobile, and microservice architectures. Every object reference arriving from a client must be considered untrusted until the system confirms it belongs to the requesting principal.

IDOR occurs when an authenticated user changes a user-supplied identifier (path param, body field, query param) to access or modify another user's object without an ownership or permission check on that specific resource.

### What it IS

- `GET /api/orders/1002` returns another user's order after swapping the ID
- `DELETE /api/documents/555` removes a document the caller does not own
- Request body `{"account_id": 789}` references another user's account for a transfer
- `?file_id=42` downloads another user's private file

### What it is NOT

- **Missing authentication** — endpoint requires no login → unauthenticated access, not IDOR
- **Vertical privilege escalation** — regular user hits `/admin/dashboard` → function-level access control, not IDOR
- **Public-by-design resources** — intentionally public posts or catalog items
- **Mass assignment / business logic** — tampering `role=admin` or `price=0` on non-object fields
- **SQL injection** — `?id=1 OR 1=1` → SQLi, not IDOR

## Where to Look

**Scope**
- Horizontal access: one subject reaches another subject's objects of the same classification
- Vertical access: a lower-privilege actor reaches objects or actions reserved for admins or staff
- Cross-tenant access: isolation boundaries collapse in multi-tenant deployments
- Cross-service access: a token issued for one service is accepted by a different service

**Reference Locations**
- Paths, query params, JSON bodies, form-data, headers, cookies
- JWT claims, GraphQL arguments, WebSocket messages, gRPC messages

**Identifier Forms**
- Integers, UUID/ULID/CUID, Snowflake, slugs
- Composite keys (e.g., `{orgId}:{userId}`)
- Opaque tokens, base64/hex-encoded blobs

**Relationship References**
- parentId, ownerId, accountId, tenantId, organization, teamId, projectId, subscriptionId

**Expansion/Projection Knobs**
- `fields`, `include`, `expand`, `projection`, `with`, `select`, `populate`
- These parameters frequently bypass authorization inside resolvers or serializers

## High-Value Targets

- Exports/backups/reporting endpoints (CSV/PDF/ZIP)
- Messaging/mailbox/notifications, audit logs, activity feeds
- Billing: invoices, payment methods, transactions, credits
- Healthcare/education records, HR documents, PII/PHI/PCI
- Admin/staff tools, impersonation/session management
- File/object storage keys (S3/GCS signed URLs, share links)
- Background jobs: import/export job IDs, task results
- Multi-tenant resources: organizations, workspaces, projects

## Reconnaissance

### Parameter Analysis
- Pagination/cursors: `page[offset]`, `page[limit]`, `cursor`, `nextPageToken` — these often reveal or accept cross-tenant or cross-state identifiers
- Directory/list endpoints as seeders: search/list/suggest/export surfaces frequently leak object IDs that feed secondary exploitation
- **Object-reference param-name hints (prioritization only — never a standalone finding).** A param that *names* an object reference is high-priority to check for a missing ownership/tenant scope on the lookup it feeds — it is not itself the finding (the missing authz check is). Highest signal on **path and query** params (these address an object directly); a bare `id`/`key` in a JSON **body** is lower-signal. Identifier-suffix heuristic (case-insensitive): bare `id`, or names matching `[_-]id$` / `[a-z0-9]Id$` / `[a-z0-9]ID$` (`userId`, `account_id`, `orderId`, `docID`). Object-name tokens: `user`, `account`, `order`, `doc`, `document`, `group`, `profile`, `report`, `invoice`, `file`, `owner`, `tenant`, `org`, `customer`, `member`, `key`. A match means *verify the ownership check on that lookup*, nothing more.

### Enumeration Techniques
- Alternate types: `{"id":123}` vs `{"id":"123"}`, arrays vs scalars, objects vs scalars
- Edge values: null/empty/0/-1/MAX_INT, scientific notation, overflows
- Duplicate keys/parameter pollution: `id=1&id=2`, JSON duplicate keys `{"id":1,"id":2}` (parser precedence)
- Case/aliasing: userId vs userid vs USER_ID; alternate names like resourceId, targetId, account
- Path traversal-like in virtual file systems: `/files/user_123/../../user_456/report.csv`

### UUID/Opaque ID Sources
An "unpredictable" ID (UUID/ULID/opaque blob) is not secret — it leaks through many channels, so a missing ownership check is still exploitable. Sources:
- **In-app exposure**: list/search/export endpoints, notifications, emails, webhooks, analytics endpoints, JS bundles, GraphQL responses; any read-only user in the same org who can *view* the ID (an IDOR then becomes privilege escalation)
- **URL/referrer leakage**: IDs in paths or query strings leak via the `Referer` header to third-party hosts, browser history, and shared/streamed/screen-shared URLs; OAuth/SSO "sign in with" buttons often embed the org/tenant UUID in the generated URL
- **External archives & search**: web archives and crawl datasets (Wayback-style archives, Common Crawl), URL/sandbox scanners and threat-intel feeds, search-engine indexes/caches, and public code-search (repos/issues with pasted requests or hardcoded IDs)
- **Infrastructure logs**: HTTP access logs held by IT, reverse proxies, CDNs, VPNs, and ISPs capture IDs in paths/query strings
- **Insider / offline**: ex-employees who saved IDs from local storage/logs before access revocation
- **Weak randomness**: "random" IDs with a design flaw (sequential within a shard, embedded timestamp, low entropy) — time-based IDs (UUIDv1, ULID) may be predictable within a window
- **Lower-exposure case**: an ID that only ever travels in a POST/JSON **body** (never in a URL/path) leaks through fewer of the above — this lowers likelihood/severity but does **not** make the missing check safe

### Static Code Indicators

Grep for resource lookups by user-supplied ID **without** an ownership or tenant scope in the same query or on the reachable path:

- ORM: `.get(id=`, `.find(id)`, `.findById(`, `.findOne({ _id:`, `.findUnique({ where: { id`, `.objects.get(pk=`, `.query.get(`, `findByIdAndDelete(`
- Raw SQL: `WHERE id = ?` without a matching `user_id`, `owner_id`, or `tenant_id` predicate
- Body/query IDs: `req.body.userId`, `req.body.account_id`, `request.data['account_id']` passed straight into fetch or mutate calls
- GraphQL resolvers/mutations accepting `id` arguments with no per-object authorization at the resolver

**Where ownership checks should appear** (absence = candidate):

- Query scoped to caller: `filter(id=..., user=request.user)`, `current_user.orders.find(id)`, `findFirst({ where: { id, userId } })`
- Post-fetch guard: `if resource.owner_id != current_user.id: raise Forbidden`
- Policy/middleware: `authorize('view', obj)`, `can?(:read, @obj)`, `@PreAuthorize` with ownership expression
- Tenant scoping: all queries bound to `get_current_tenant(request)` or org context

**Not a fix**: UUIDs, ULIDs, or other non-guessable IDs — they only obscure identifiers; authorization must still bind the object to the caller. Indirect reference maps (session-stored ID → object) help only when paired with ownership validation on lookup.

**Triage guard — ID opacity is not grounds to dismiss the finding.** Do not WITHDRAW or downgrade a confirmed missing object-level authorization check to "not exploitable" solely because the identifier is a UUID/random/opaque value. Unpredictable IDs leak (see UUID/Opaque ID Sources), so the auth gap is real; opacity affects only *likelihood* (it raises attack complexity → may lower severity one band), not *validity*. The only genuine downgrades are: the resource is public/shared by design, or the value is a true secret-capability token (a session/bearer token or unguessable single-use share link that rotates and is never shown to other principals) rather than a stable object identifier. A stable object ID that other users/endpoints can see is **not** a capability token.

## Vulnerability Patterns

### Horizontal & Vertical Access

- Swap object IDs between principals while holding the same token to probe horizontal access
- Repeat the same requests with lower-privilege tokens to test vertical access
- Target partial updates (PATCH, JSON Patch/JSON Merge Patch) for silent unauthorized modifications

### Bulk & Batch Operations

- Batch endpoints (bulk update/delete) frequently validate only the first element; insert cross-tenant IDs mid-array to test per-item enforcement
- CSV/JSON imports that reference foreign object IDs (ownerId, orgId) may bypass checks applied at creation time

### Secondary IDOR

- Harvest valid IDs from list/search endpoints, notifications, emails, webhooks, and client-side logs
- Directly fetch or mutate those objects using a different principal's token
- Manipulate pagination cursors to skip tenant filters and retrieve another user's pages

### Job/Task Objects

- Access job/task IDs from one user and attempt to retrieve results belonging to another (`export/{jobId}/download`, `reports/{taskId}`)
- Try cancelling or approving another user's queued jobs by referencing their task IDs

### Authorization-Layer Mismatch (app checks authz, storage serves the object with none)

A very common real-world IDOR: the **application** enforces ownership correctly, but the object is then delivered by a **separate storage layer** (public S3/GCS/Azure Blob bucket, CDN, static file host) that has no concept of app users and performs **no** per-request authorization. The correct app-layer check is moot because the attacker fetches the object's storage URL directly. Switching the object key from a sequential integer to a **UUID does not add authorization** — it only obscures the key, which still leaks (see UUID/Opaque ID Sources) and remains enumerable/guessable in the integer case.

**SAST signal**: an ownership/authz check (or `@login_required`-style gate) followed by construction of a **direct, publicly reachable storage URL** built from the object id/key, returned to the client — instead of streaming the bytes through an app endpoint that re-checks authz, or minting a short-lived scoped pre-signed URL *after* the check.

```python
# VULN — app authz is correct, but the returned URL points at a public bucket with no authz.
#        Attacker hits bill-101 directly; UUID keys only obscure, they don't authorize.
@login_required
def view_latest_bill(request):
    bill = Bill.objects.filter(owner=request.user).latest("date")   # correct ownership check
    url = f"https://my-bucket.s3.amazonaws.com/bill-{bill.id}"        # public object, guessable/leakable key
    return render(request, "bill.html", {"url": url})

# SAFE (A) — stream through the app so authz is enforced on every fetch
@login_required
def download_bill(request, bill_id):
    bill = get_object_or_404(Bill, id=bill_id, owner=request.user)    # ownership re-checked on the fetch path
    return FileResponse(storage.open(bill.key))                       # bytes proxied; storage never public

# SAFE (B) — private bucket + short-lived, single-object pre-signed URL minted AFTER the check
    bill = get_object_or_404(Bill, id=bill_id, owner=request.user)
    url = s3.generate_presigned_url("get_object",
            Params={"Bucket": "private", "Key": bill.key}, ExpiresIn=60)  # expiring, scoped to one object
```

**Capability-URL hygiene** — if an unguessable URL is *deliberately* the access control (capability-URL / "secret link" pattern), it is a secret and must be treated like one: short expiry, **rotatable/revocable**, ideally single-use, and kept out of anything that records URLs — access logs, `Referer` to third parties, browser history, analytics, error trackers. A permanent public link keyed by a UUID is **not** a capability token (a leaked or logged URL is then a standing compromise with no rotation path). Cross-ref `information_disclosure.md` (secrets in logs) and `open_redirect.md` (`Referer` leakage).

### File/Object Storage

- Test direct object paths or weakly scoped signed URLs
- Attempt key prefix modifications, content-disposition tricks, or reuse of stale signatures across tenant boundaries
- Substitute share tokens with tokens originating from other tenants; try case and URL-encoding variants

### GraphQL

- Enforce checks at the resolver level; a top-level gate is insufficient on its own
- Confirm that field and edge resolvers re-bind the resource to the caller on every traversal hop
- Exploit batching and aliases to pull multiple users' nodes within a single request
- Global node patterns (Relay): decode base64 IDs and swap the raw underlying IDs
- Overfetch through fragments targeting privileged types

```graphql
query CrossAccountAccess {
  me { id }
  u1: user(id: "VXNlcjo0NTY=") { email billing { last4 } }
  u2: node(id: "VXNlcjo0NTc=") { ... on User { email } }
}
```

#### Nested Input-Object ID Traversal

The object identifier sits inside a nested input object; the resolver reads `args.input.<nested>.id` (or `args.parent.id`) and passes it to a DB call without verifying the nested entity belongs to `ctx.user`.

```graphql
# SDL
input UpdateOrderInput {
  order: OrderRefInput!
}
input OrderRefInput {
  id: ID!
}
```

```javascript
// VULN: nested id reaches ORM with no ownership bind
async updateOrder(_, { input }, ctx) {
  const row = await prisma.order.update({
    where: { id: input.order.id },
    data: input.payload,
  });
  return row;
}
```

```bash
rg -n 'args\.(\w+\.)+id|input\.\w+\.id|args\.input\.\w+\.id' --glob '*.{js,ts}'
# Flag resolver/DB path when nested id is not resolved then checked against ctx.user / principal
```

**SAFE**: resolve the nested entity first, then assert ownership (or use a scoped query: `where: { id, userId: ctx.user.id }`) before any read or write.

#### `*ById` Root Field Naming Heuristic

Root queries and mutations named `*ById` (`getById`, `updateById`, `deleteById`, `cancelById`) load or mutate solely from `args.id`. State-changing fields matching `/(update|delete|cancel|modify|patch|remove).*ById/i` are BOLA with higher severity.

```graphql
type Mutation {
  updateById(id: ID!, data: UpdateInput!): Order
  deleteById(id: ID!): Boolean
}
```

```javascript
// VULN: write keyed only on client-supplied id
async deleteById(_, { id }) {
  return prisma.order.delete({ where: { id } });
}
```

```bash
rg -n '(\w+ById)\([^)]*\bid:\s*(ID|String)!' --glob '*.{graphql,gql,ts,js}'
rg -n '(update|delete|cancel|modify|patch|remove).*ById' --glob '*.{graphql,gql,ts,js}' -i
```

**SAFE**: scoped write `WHERE id = ? AND user_id = ?`; reject cross-owner IDs before any side effect.

#### GraphQL List/Batch ID Arguments

Batch arguments (`ids: [ID!]!`) feed `findMany({ where: { id: { in: args.ids } } })` or per-id loops without per-element ownership or `userId IN (...)` scoping.

```graphql
type Mutation {
  archiveOrders(ids: [ID!]!): [Order]
}
```

```javascript
// VULN: batch fetch/update with no principal filter
async archiveOrders(_, { ids }) {
  return prisma.order.updateMany({
    where: { id: { in: ids } },
    data: { archived: true },
  });
}
```

```bash
rg -n 'ids:\s*\[ID|ids:\s*\[String' --glob '*.{graphql,gql}'
rg -n 'findMany\(\{[^}]*where:\s*\{\s*id:\s*\{\s*in:' --glob '*.{js,ts}'
rg -n 'args\.ids|input\.ids' --glob '*.{js,ts}' | rg -v 'userId|ownerId|tenantId'
```

**SAFE**: filter the batch to caller-owned IDs only; fail the whole batch if any foreign ID is present.

#### Service Credential with Client-Supplied Principal ID

Resolver uses a server-side privileged credential (service token, admin API key header, internal service client) to call a backend keyed by a **client-supplied** `userId` / `ownerId` / `accountId` with no `args.userId === ctx.user.id` check — any authenticated caller can read or modify another user's state.

```javascript
// VULN: privileged backend client + client-controlled principal id
async updatePreferences(_, { userId, settings }, ctx) {
  return serviceClient.patch(`/users/${userId}/preferences`, settings, {
    headers: { 'X-API-Key': process.env.SERVICE_KEY },
  });
}
```

```bash
rg -n 'X-API-Key|serviceClient|adminClient|SERVICE_KEY|internalClient' --glob '*.{js,ts}'
# Same resolver file must not pair privileged client with args\.(userId|ownerId|accountId) without ctx\.user bind
rg -n 'args\.(userId|ownerId|accountId)' --glob '*.{js,ts}' | rg -i 'service|admin|internal|apiKey'
```

**SAFE**: bind the backend call to the authenticated principal (`ctx.user.id`); never trust a client-supplied principal id for privileged operations.

#### Two-Hop ID-to-PII Operation Chain

Operation A returns an internal or mapped id (lookup/mapping field); operation B accepts that id and returns PII (email, phone) with no ownership check — chaining yields cross-user PII disclosure.

```graphql
type Query {
  resolveAccountRef(externalRef: String!): AccountMapping
  accountContact(accountId: ID!): ContactInfo
}
type AccountMapping { accountId: ID! }
type ContactInfo { email: String phone: String }
```

```javascript
// VULN: op B returns PII for any accountId with no principal bind
async accountContact(_, { accountId }) {
  return prisma.contact.findUnique({ where: { accountId } });
}
```

```bash
rg -n 'resolve.*Ref|map.*Id|lookup.*Id|internalId' --glob '*.{graphql,gql,js,ts}' -i
# Trace: id returned by mapping op → consumed by PII/email/phone resolver without ownership guard
rg -n 'email|phone|ssn|contact' --glob '*resolver*.{js,ts}' | rg 'args\.(id|accountId|userId)'
```

**SAFE**: authorize the resolve-to-PII step; do not expose internal-id ↔ external-id mapping operations without authentication and ownership binding.

#### GraphQL Response Oracle (`errors[]` vs `data`)

Foreign or unauthorized objects return a different response shape (thrown error vs `data.field: null`) or an error message naming the resource type (`"Order not found"`, `"Invalid appointmentId"`) — a blind IDOR/enumeration oracle.

```javascript
// VULN: distinct shapes leak existence vs authorization
async order(_, { id }, ctx) {
  const row = await prisma.order.findUnique({ where: { id } });
  if (!row) throw new UserInputError('Order not found');
  if (row.userId !== ctx.user.id) return null;  // foreign → null; missing → error
  return row;
}
```

```bash
rg -n 'UserInputError|ApolloError|GraphQLError' --glob '*.{js,ts}'
# Error messages naming resource types: not found|invalid.*Id|does not exist
rg -n 'not found|Invalid \w+Id|does not exist' --glob '*.{js,ts}' -i
```

**SAFE**: uniform forbidden responses for foreign and unauthorized objects; generic error messages that do not distinguish missing from forbidden.

#### Tenant/Org Argument vs Principal Claim

`args.tenantId`, `args.orgId`, or `args.organizationId` scopes data without verifying equality to the authenticated user's org claim (JWT/session).

```javascript
// VULN: client-supplied tenant scopes query
async listProjects(_, { tenantId }, ctx) {
  return prisma.project.findMany({ where: { tenantId } });
}
```

```bash
rg -n 'args\.(tenantId|orgId|organizationId)|input\.(tenantId|orgId)' --glob '*.{js,ts}'
# Absence of compare to ctx\.user\.(tenantId|orgId|organizationId) or verified JWT claim
```

**SAFE**: derive tenant from the verified principal, not from client args; if a tenant arg is accepted, assert it equals the principal's org claim before any query.

### Microservices & Gateways

- Token confusion: a token scoped for Service A is accepted by Service B due to shared JWT verification logic that omits audience or claims checks
- Header trust: reverse proxies or API gateways that inject or blindly trust headers like `X-User-Id`, `X-Organization-Id` — try overriding or removing them
- Context loss: async consumers (queues, workers) re-process requests without re-evaluating authorization

### Multi-Tenant

- Probe tenant scoping through headers, subdomains, and path params (`X-Tenant-ID`, org slug)
- Mix the org associated with a token with a resource belonging to a different org
- Test cross-tenant report rollups, analytics aggregations, and admin views that span multiple tenants

### Relational Filter / ORM Query Leakage (CWE-639 / CWE-200)

Request-controlled filter/query DSLs that the backend forwards into an ORM let a low-privileged user traverse relations and read fields they should never reach — distinct from classic single-ID IDOR (the ID is not the attack; the *filter operator/relation path* is).

- **Sinks**: `Model.objects.filter(**request.args)` / `filter_by(**request.GET)` (Django/SQLAlchemy); `prisma.x.findMany({ where: req.body })` (Prisma); `where(params[:filter])` (ActiveRecord); Query-by-Example from request body (Hibernate); PostgREST/Hasura-style `?filter[relation.field][op]=` traversal; GraphQL `where`/`filter` args without per-field auth.
- **Smell**: the *entire* filter/where object (not a fixed allow-list of columns) comes from the request, so an attacker can pivot to relations (`author.email`, `owner.org_id`) or sensitive columns (`password_hash`, `reset_token`).
- **Attacker input**: `GET /api/notes?filter[author.email][starts_with]=admin@` or `{"where":{"user":{"role":"admin"}}}` — leaks rows across the relation graph.
- **Blind char-by-char exfiltration (ORM leak)**: even when the sensitive column is **never returned**, attacker-controlled **lookup operators** turn the result set (or just result count / 200-vs-empty) into a boolean oracle to reconstruct it character by character — Django `?password__startswith=a` / `__contains` / `__gt`, Prisma `{password:{startsWith:"a"}}`, ActiveRecord/Ransack `q[reset_token_start]=a`, SQLAlchemy `like`. Iterating the prefix recovers password hashes, `reset_token`/`recoveries_key`, and secrets in neighboring tables. This is a read-only IDOR/info-leak, distinct from SQLi (the ORM still parameterizes — the *operator and column* are the attacker's control).
- **Safe**: per-endpoint allow-list of filterable fields **and operators** (block `startswith`/`contains`/comparison lookups on sensitive columns); resolve relations against the authenticated principal; apply row-level auth middleware; GraphQL field-level `@auth`.

### WebSocket

- Verify per-subscription authorization: channel and topic names must not be guessable (`user_{id}`, `org_{id}`)
- Subscribe/publish enforcement must occur server-side on every message, not only at handshake time
- After subscribing to your own channel, attempt to send messages referencing other users' IDs

### gRPC

- Direct protobuf fields (`owner_id`, `tenant_id`) often circumvent HTTP-layer middleware
- Validate cross-principal references using grpcurl with tokens from distinct principals

### Integrations

- Webhooks and callbacks that reference foreign objects (e.g., `invoice_id`) and process them without verifying the owning principal
- Third-party importers that sync data into the wrong tenant due to missing tenant binding at ingest time

## Evasion Patterns

**Parser & Transport**
- Content-type switching: `application/json` ↔ `application/x-www-form-urlencoded` ↔ `multipart/form-data`
- Method tunneling: `X-HTTP-Method-Override`, `_method=PATCH`; or issuing GET requests to endpoints that incorrectly accept state changes
- JSON duplicate keys or array injection to defeat naive validators

**Parameter Pollution**
- Duplicate parameters in query or body to influence server-side precedence (`id=123&id=456`); test both orderings
- Mix case and alias param names so the gateway and backend disagree on which value applies (userId vs userid)

**Cache & Gateway**
- CDN/proxy key confusion: responses cached without the Authorization or tenant header expose stored objects to different users
- Manipulate Vary and Accept headers to influence cache behavior
- Redirect chains and 304/206 partial-content behaviors can leak resources across tenants

**Race Windows**
- Time-of-check vs time-of-use: alter the referenced ID between validation and execution by sending parallel requests

**Blind Channels**
- Use differential responses (status code, body size, ETag, timing) to infer object existence
- Error shapes typically differ between owned and foreign objects
- HEAD/OPTIONS and conditional requests (`If-None-Match`/`If-Modified-Since`) can confirm existence without exposing full content

### Nested JSON ID Wrap

Flat auth check on a top-level identifier; nested duplicate key bypasses the guard while the inner value reaches the sink.

```python
# VULN: flat compare passes; nested object used in query
userid = request.json.get('userid')
if str(userid) != str(session['user_id']):
    abort(403)
target = request.json['userid']   # {"userid": {"userid": 123}} — outer != session, inner is victim
Order.query.filter_by(user_id=target['userid']).delete()
```

```bash
rg -n '\.get\(["'"'"']userid|\.get\(["'"'"']user_id|request\.json\[["'"'"']id' --glob '*.{py,js,java,php}'
# Flag when only top-level scalar compare precedes nested/body access
```

**SAFE**: normalize to scalar server-side (`userid = int(flatten_id(body['userid']))`) before auth compare and ORM use.

### Path-Embedded ID with Traversal

Auth compares a pre-normalized path segment; the router collapses `..` before the handler runs.

```python
# VULN: auth on raw segment before normalization
segments = request.path.split('/')
path_user = segments[3]   # /users/delete/123/../456 → compares "123"
if path_user != str(current_user.id):
    abort(403)
# Framework resolves path to victim 456 before delete executes
```

```bash
rg -n 'split\(["'"'"']/|path\.split|Request\.Path' --glob '*.{py,js,java,php,cs}' | rg -i 'user|owner|id'
```

**SAFE**: bind authorization to the **normalized** resource ID the handler will use (`resolve_path()` then compare).

### Alternate Parameter Names for Same Object

Only one parameter name is authorized; a sibling alias references the same object without a guard.

```javascript
// VULN: album_id checked; account_id (same underlying record) used for fetch
if (req.body.album_id !== req.user.albumId) return res.sendStatus(403);
const acct = await Account.findById(req.body.account_id);
```

```bash
rg -n '_id|Id' --glob '*.{js,py,java,php}' | rg -i 'album|account|resource|target'
# Pair param names on same handler — only one compared to session principal
```

**SAFE**: map all accepted aliases to one canonical ID, then run a single ownership check on that value.

#### GraphQL Parameter Alias Families

The same resource is referenced by multiple GraphQL argument names; when only one alias is ownership-checked, others bypass authorization.

```graphql
type Mutation {
  updateOrder(orderId: ID!, data: UpdateInput!): Order
  cancelOrder(order_id: ID!): Boolean
  refundOrder(orderNumber: String!): Boolean
}
```

```javascript
// VULN: orderId checked in sibling resolver; orderNumber (same record) unchecked here
async refundOrder(_, { orderNumber }, ctx) {
  return prisma.order.update({ where: { orderNumber }, data: { refunded: true } });
}
```

**Alias-family grep seeds** (pair names on the same resolver/schema; confirm all aliases reach one ownership check):

```bash
rg -n 'orderId|order_id|orderNumber' --glob '*.{graphql,gql,js,ts}'
rg -n 'userId|accountId|ownerId|\bid:\s*ID' --glob '*.{graphql,gql,js,ts}'
rg -n 'vehicleId|vin|assetId|resourceId' --glob '*.{graphql,gql,js,ts}'
rg -n 'appointmentId|bookingId|reservationId' --glob '*.{graphql,gql,js,ts}'
rg -n 'invoiceId|invoiceNumber|paymentId' --glob '*.{graphql,gql,js,ts}'
```

**SAFE**: canonicalize all accepted aliases to one internal id before the single ownership check; reject if any alias resolves to a record the caller does not own.

### Blind IDOR

HTTP 403/401 returned but the state-changing action still executed — mutation before or independent of the auth check, or async side effect after a failed guard.

```java
// VULN: delete before auth check
orderRepo.deleteById(orderId);
if (!authz.canDelete(orderId, principal)) {
    throw new AccessDeniedException();   // 403 returned; row already deleted
}
```

```javascript
// VULN: fire-and-forget side effect; response still 403
if (doc.ownerId !== req.user.id) {
    queue.publish('document.deleted', { id: doc.id });  // async mutation regardless
    return res.sendStatus(403);
}
```

```bash
rg -n 'delete|update|transfer|execute|destroy' --glob '*.{java,js,py,php,cs}' 
# Trace: side-effect call must follow — not precede — ownership/tenant guard on same path
```

### Sentinel / Backdoor UUIDs

Hardcoded nil or pattern UUIDs mapped to elevated privileges in application code or seed/migration data.

```bash
rg -n '00000000-0000-0000-0000-000000000000|11111111-1111-1111-1111-111111111111' --glob '*.{py,js,java,cs,go,php,sql}'
```

```python
# VULN
ADMIN_OVERRIDE = '00000000-0000-0000-0000-000000000000'
if str(user.uuid) == ADMIN_OVERRIDE:
    session['role'] = 'admin'
```

```sql
-- VULN: seed grants superuser to nil UUID
INSERT INTO users (id, role) VALUES ('00000000-0000-0000-0000-000000000000', 'admin');
```

**SAFE**: no magic identifiers; privilege derived only from authenticated principal lookup.

## Chaining Attacks

- IDOR + CSRF: compel victims to trigger unauthorized changes on objects you have already identified
- IDOR + Stored XSS: pivot into other sessions through data access obtained via IDOR
- IDOR + SSRF: exfiltrate internal IDs, then access the resources those IDs map to
- IDOR + Race: defeat spot checks by firing simultaneous requests
- IDOR ↔ JWT: a tamperable or over-trusted `sub`/`user_id`/`role` claim turns horizontal IDOR into full account takeover; conversely an IDOR that returns another principal's token/secret enables JWT replay or impersonation (see `authentication_jwt.md`)

## Analysis Workflow

1. **Build matrix** - Construct a Subject × Object × Action matrix defining who can perform what operation on which resource
2. **Obtain principals** - Acquire at least two: an owner and a non-owner (plus admin/staff if accessible)
3. **Collect IDs** - Capture at least one valid object ID per principal through list/search/export surfaces
4. **Cross-channel testing** - Exercise every action (R/W/D/Export) while alternating IDs, tokens, and tenants
5. **Transport variation** - Cover web, mobile, API, GraphQL, WebSocket, and gRPC
6. **Consistency check** - The same authorization rule must hold regardless of transport, content-type, serialization format, or gateway path

## Confirming a Finding

1. Demonstrate retrieval of an object not belonging to the requesting principal (content or metadata)
2. Show the identical request fails when authorization is correctly enforced
3. Establish cross-channel consistency: reproduce the unauthorized access through at least two transports (e.g., REST and GraphQL)
4. Document tenant boundary violations where applicable
5. Provide reproducible steps and evidence capturing both the owner and non-owner perspectives

### Dynamic PoC (two-account swap)

1. As **User A**, create or list a resource; record its ID (`<USER_A_RESOURCE_ID>`).
2. As **User B**, call the same endpoint with User A's ID using User B's token.
3. **Vulnerable signal**: HTTP 200 with User A's data, or successful delete/update on User A's object.
4. **Not vulnerable signal**: 403/404, empty body, or generic error — same shape for owned and foreign IDs.

```bash
# User B attempts to read User A's order
curl -s -H "Authorization: Bearer <USER_B_TOKEN>" \
  https://app.example/api/orders/<USER_A_RESOURCE_ID>
# Expect 403/404 if safe; 200 + foreign order data confirms IDOR
```

**Sequential / encoded ID enumeration** — when IDs are integers or leaked UUIDs:

```bash
for id in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code} " \
    -H "Authorization: Bearer <USER_B_TOKEN>" \
    "https://app.example/api/orders/$id"
done
# 200 on foreign IDs, or distinct 403 vs 404 shapes, confirms missing binding
```

Try base64/hex-decoded variants of opaque IDs when the API accepts alternate encodings.

**Vertical probe** — same low-privilege token against admin/internal routes (`/api/admin/users`, `/api/internal/reports`); `200` with privileged data is function-level IDOR/BOLA.

**HTTP method / param swap** — if `GET` is blocked, retry `DELETE`, `PATCH`, or `PUT` on the same path; auth middleware often differs by verb.

```bash
curl -X PATCH -H "Authorization: Bearer <USER_B_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@example.com"}' \
  https://app.example/api/users/<USER_A_RESOURCE_ID>
```

**Parameter pollution** — duplicate ID keys so gateway and backend disagree on precedence:

```bash
curl "https://app.example/api/profile?user_id=<USER_B_ID>&user_id=<USER_A_ID>" \
  -H "Authorization: Bearer <USER_B_TOKEN>"
```

### Multi-Principal Response-Equivalence Matrix

Generalizes the two-account swap to **N authenticated identities**: replay each captured request once per principal (each principal carries its own `Authorization` / `Cookie` / `X-User-Id` set), then compare responses pairwise. Two comparison modes:

- **All-vs-Baseline** — pick one principal as the owner/baseline; test every other principal against it. Cheapest; catches "everyone sees the baseline's data."
- **All-vs-All** — compare every principal pair (`i < j`). Catches asymmetric leaks (A sees B but B does not see A) and per-tenant gaps.

**Equivalence oracle.** For each pair, the resource is principal-specific yet authorization is missing when the two responses are *equivalent*: **same status code AND same body** after normalization. Interpret:

| Outcome | Meaning |
|---------|---------|
| **SAME** (all pairs equivalent) | Endpoint ignores identity entirely, or returns the owner's object to everyone → BAC/IDOR |
| **MIXED** (some pairs equivalent, some not) | Partial enforcement — a specific record, verb, tenant, or alias is unguarded while siblings are guarded |
| **DIFFERENT** (no pair equivalent) | Per-principal data — likely enforced (or naturally distinct) |

**Normalize before comparing — or you get false negatives.** Identical underlying data still differs byte-for-byte because of per-response dynamic fields. Strip them before hashing/diffing: CSRF/anti-forgery tokens, CSP/script nonces, `csrfToken`/`_token`/`authenticity_token`, request/trace IDs (`X-Request-Id`, `traceparent`), timestamps/`Date`, ETags, session/cart IDs, signed-URL signatures, pagination cursors. Skipping this is the #1 reason a real leak reads as "different."

```bash
# Replay one request under two principals, normalize dynamic fields, compare body hashes.
# Equal hash + equal status on an ID-bearing endpoint = candidate BAC/IDOR.
norm() {                       # strip volatile fields before hashing
  sed -E 's/"(csrf_?token|_token|authenticity_token|nonce|requestId|traceId|timestamp|createdAt|updatedAt|expiresAt|etag|cursor)":"[^"]*"/"\1":"X"/g'
}
A=$(curl -s -H "Authorization: Bearer <TOKEN_A>" "https://app.example/api/orders/<ID_A>" | norm | md5sum)
B=$(curl -s -H "Authorization: Bearer <TOKEN_B>" "https://app.example/api/orders/<ID_A>" | norm | md5sum)
[ "$A" = "$B" ] && echo "SAME -> B received A's order (IDOR)" || echo "different"
```

**Pre-filter to the requests worth replaying** (focus the matrix on likely object references): numeric or UUID segments in the path, query/body keys like `id|uid|user_id|account_id|order_id|invoice_id|ticket_id|customer_id|file_id|doc_id|record_id|item_id|resource_id`, self-reference endpoints (`/me`, `/self`, `/profile`, `/settings`), admin/internal paths, and any state-changing method (`POST|PUT|PATCH|DELETE`). Self-reference endpoints pair with an ID-taking sibling — swap `/api/me` → `/api/users/<other_id>`.

**Caveat (don't over-report):** equivalence is only a leak when the endpoint is *supposed* to be principal-specific. Identical responses for genuinely public/shared/empty/static resources are expected — gate on the pre-filter above and confirm the body actually contains another principal's data.

## Common False Alarms

- Resources that are public or anonymous by design
- Soft-private data whose content is already publicly accessible
- Idempotent metadata lookups that expose nothing sensitive
- Properly implemented row-level checks enforced uniformly across all channels
- Admin-only endpoints behind explicit role checks (`hasRole('ADMIN')`) — vertical access control, not horizontal IDOR

## Safe Patterns

**Query scoped to current user (preferred)**

```python
# Django
order = get_object_or_404(Order, id=order_id, user=request.user)
```

```javascript
// Express / Mongoose
const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });
```

```ruby
# Rails
@order = current_user.orders.find(params[:id])
```

**Explicit ownership check after fetch**

```java
Account acct = accountRepo.findById(id).orElseThrow();
if (!acct.getOwnerId().equals(auth.getName())) throw new AccessDeniedException();
```

**Policy / authorization middleware**

```php
$this->authorize('view', $invoice);  // Laravel Policy
```

**Tenant/org scoping**

```python
Order.objects.filter(id=order_id, tenant=get_current_tenant(request))
```

Trace route → middleware → controller → service → data access; `auth` middleware alone does not prove object-level authorization.

## Business Risk

- Cross-account exposure of PII/PHI/PCI data
- Unauthorized state changes including transfers, role assignments, and cancellations
- Cross-tenant data leakage violating contractual and regulatory obligations
- Regulatory liability (GDPR/HIPAA/PCI), fraud exposure, and reputational harm

## Analyst Notes

1. Start with list/search/export endpoints — they are the richest source of ID material
2. Build a reusable ID corpus from logs, notifications, email content, and compiled client bundles
3. Rotate content-types and transports; authorization middleware behavior often diverges across stack layers
4. In GraphQL, enforce checks at every resolver boundary; parent authorization does not automatically cover child resolvers
5. In multi-tenant applications, vary org headers, subdomains, and path params independently from one another
6. Scrutinize batch/bulk operations and background job endpoints — per-item authorization is routinely absent
7. Inspect gateway configurations for header trust relationships and cache key definitions
8. Treat UUIDs as untrusted; source them through OSINT or leakage and test ownership binding
9. Exploit timing, size, and ETag differentials for blind confirmation when response content is suppressed
10. Demonstrate impact with precise before/after diffs and role-separated request/response evidence

## Core Principle

Authorization must bind the subject, the action, and the specific object on every request, independent of identifier opacity or transport protocol. Any gap in that binding creates a vulnerability.

## Vulnerable vs Secure Examples

### Python — Django

```python
# VULNERABLE
def get_order(request, order_id):
    order = Order.objects.get(id=order_id)
    return JsonResponse(model_to_dict(order))

# SECURE
def get_order(request, order_id):
    order = get_object_or_404(Order, id=order_id, user=request.user)
    return JsonResponse(model_to_dict(order))
```

### Python — Flask / SQLAlchemy

```python
# VULNERABLE
doc = Document.query.get_or_404(doc_id)

# SECURE
doc = Document.query.filter_by(id=doc_id, owner_id=current_user.id).first_or_404()
```

### Node.js — Express / Prisma

```javascript
// VULNERABLE
const invoice = await prisma.invoice.findUnique({ where: { id: req.params.id } });

// SECURE
const invoice = await prisma.invoice.findFirst({
  where: { id: req.params.id, userId: req.user.id }
});
```

### Go

```go
// VULNERABLE
order, _ := db.GetOrder(id)

// SECURE
order, _ := db.GetOrderByUser(id, userID)
```

### PHP — Laravel

```php
// VULNERABLE
return Invoice::findOrFail($id);

// SECURE
return auth()->user()->invoices()->findOrFail($id);
```

## C# ASP.NET Detection Patterns

Config/heuristic detection on ASP.NET action methods. Flags methods that accept a user-controlled ID parameter to load or modify a resource when no authorization check binds that resource to the current user.

Checks WebForms and MVC patterns — methods that fetch entities by ID without `User.IsInRole`, `[Authorize]`, or resource-owner comparison (e.g. `comment.AuthorId == UserId`).

No IDOR/BOLA detection in Java, JavaScript, Python, Go, Ruby, or Rust — use manual source rules below.

**VULN (WebForms/MVC)**: `Comment GetComment(int id) => db.Comments.Find(id)` — no check that current user owns the comment.
**SAFE**: `if (comment.AuthorId != currentUserId) return Forbid();` or `[Authorize]` with resource-based policy for admin-only cross-user access.

## Java Source Detection Rules

### TRUE POSITIVE: object lookup without ownership binding
- An object identifier arriving from `@PathVariable`, `@RequestParam`, or a request body is passed directly to repository or service calls such as `findById(id)`, `getById(id)`, `deleteById(id)`, or update operations that select only by `id`.
- No ownership or tenant check tied to the current principal exists on the reachable code path — for example, no comparison of `ownerId`, `accountId`, or `tenantId`, and no filtering by both the object id and the authenticated user.
- The endpoint returns or mutates the object without any visible authorization guard beyond possession of the identifier itself.

### FALSE POSITIVE: admin-only endpoint with enforced role check
- `@PreAuthorize("hasRole('ADMIN')")`, `@Secured("ROLE_ADMIN")`, `@RolesAllowed("ADMIN")`, or equivalent Spring Security configuration explicitly restricts the endpoint or method to privileged roles.
- Repository queries such as `findByIdAndUserId(id, currentUserId)` or explicit guards like `if (!entity.getOwnerId().equals(currentUserId))` demonstrate that access is bound to the authenticated principal.
- Do not flag IDOR when the code shows both authentication-context usage and an authorization check preceding the object return or modification.
