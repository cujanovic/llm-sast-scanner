---
name: graphql_dos
description: Detect GraphQL denial-of-service — missing depth/complexity/cost limits, alias/batch/directive overloading, field duplication, circular fragments, unbounded pagination, unbounded list-typed input-argument cardinality (bulk-operation amplification), federation `_entities` entity-resolution amplification, missing execution timeouts, and resolver amplification on public GraphQL endpoints.
---

# GraphQL Denial of Service (CWE-770 / CWE-400 / CWE-834)

GraphQL endpoints accept a **declarative query document** that the server parses, validates, and executes. Unlike fixed REST routes, a single HTTP request can request arbitrarily nested fields, duplicate selections via aliases, spread many fragments, attach many directives, or batch many operations — multiplying resolver work, database round-trips, and memory use. SAST should flag **missing or ineffective limits** on depth, complexity/cost, aliases, directives, batch size, pagination, execution time, and request body size, plus **schema shapes** (cyclic types, circular fragments) and **resolver patterns** (N+1, unbounded list fetches) that amplify cost.

Cross-ref generic resource-exhaustion patterns in `denial_of_service.md` (ReDoS, HTTP slow-client, goroutine leaks). This file covers **GraphQL-specific** DoS only.

## What It Is / Is Not

- **Is**: attacker-controlled GraphQL documents or arguments causing unbounded parse/validate/execute cost — deep nesting on cyclic SDL, alias/directive/field duplication, unbounded HTTP array batching, uncapped pagination args, missing execution timeouts, introspection excluded from complexity rules, `@stream`/`@defer` abuse, N+1 resolver storms.
- **Is not**: SQL/NoSQL/command injection in resolvers (classify under resolver injection skills); authorization bypass via static documents (see `graphql_injection.md`); generic HTTP rate limiting without GraphQL-aware operation counting (defense-in-depth only unless combined with unbounded GraphQL cost).
- **ReDoS in search resolvers** — GraphQL arg → regex; primary class is `regex_injection_redos.md` / `denial_of_service.md`; note here when the trigger is a GraphQL `search`/`filter` arg on a public endpoint.

## Source → Sink / Amplification Model

| Source (client-controlled) | Amplifier (server gap) | Sink (resource exhaustion) |
|----------------------------|------------------------|----------------------------|
| Nested selections on cyclic types (`User.posts.author…`) | No `depthLimit` / `max_depth` | Exponential resolver + DB depth |
| Many aliases / duplicate fields | No alias/field-count rule | Linear CPU/memory per alias |
| Many directives on one field | No directive cap | Validation + execution overhead |
| JSON array body `[{query},…]` | No `maxBatchSize` | N × single-request cost |
| Large list-typed input arg (`ids:[ID!]`, `input:[T!]`) | No `maxItems`/array-length cap; static per-field cost | N resolver/DB units from one shallow op |
| Large `first`/`limit`/`pageSize`/`offset` args | Resolver `findAll()` / no server max | Memory + row fetch blow-up |
| Negative `limit` / `first` (-1) | ORM treats negative as "no limit" | Full-table fetch in one operation |
| Relay `Connection` `first`/`last` uncapped | No cap on connection page size | Unbounded edge fetch + cursor work |
| Circular fragment spreads | Engine lacks `NoFragmentCycles` | Parse/expand stack blow-up |
| `@stream` / `@defer` selections | No incremental-delivery limits | Long-lived connections, partial execution |
| Cyclic field resolvers | No DataLoader / no complexity on edges | N+1 query storm |

## Recon Indicators (Grep)

**GraphQL surface**:
```bash
rg -n "graphql|ApolloServer|graphqlHTTP|GraphQLView|mercurius|strawberry|graphene|gqlgen|graphql-ruby|HotChocolate|Ariadne" --glob '*.{js,ts,py,go,java,cs,rb,php}'
rg -n "path.*graphql|/graphql|MapGraphQL|UseGraphQL" --glob '*.{js,ts,py,go,java,cs,rb}'
```

**Depth limits (per stack)**:
```bash
# JavaScript / Apollo / graphql-js
rg -n "depthLimit|graphql-depth-limit|maxQueryDepth|queryDepth" --glob '*.{js,ts}'
# Python graphene
rg -n "depth_limit_validator|query_depth_limit|DepthLimitValidator" --glob '*.py'
# Ruby graphql-ruby
rg -n "max_depth|GraphQL::Analysis::QueryDepth" --glob '*.rb'
# Java graphql-java
rg -n "MaxQueryDepthInstrumentation|maxQueryDepth" --glob '*.{java,kt}'
# Go gqlgen
rg -n "FixedComplexityLimit|ComplexityLimit|extension\.FixedComplexity" --glob '*.go'
# .NET Hot Chocolate
rg -n "AddMaxExecutionDepthRule|MaxExecutionDepth" --glob '*.{cs,cshtml}'
# Python Ariadne
rg -n "query_cost_validator|validation_rules|depth" --glob '*.py'
# Node mercurius
rg -n "queryDepth|maxDepth|validationRules" --glob '*.{js,ts}'
# PHP graphql-php
rg -n "QueryDepth|maxQueryDepth|DocumentValidator" --glob '*.php'
```

**Complexity / cost**:
```bash
rg -n "createComplexityLimitRule|graphql-query-complexity|queryComplexity|max_complexity|AddCostAnalyzer|@cost|complexity" --glob '*.{js,ts,py,go,java,cs,rb,graphql,graphqls}'
rg -n "maxAliases|alias.*limit|AliasLimit|maxDirective|directive.*count" --glob '*.{js,ts,py,go,java}'
rg -n "complexity.*budget|cost.*budget|credit|rateLimit.*complexity|operationCount.*complexity|perIp|perToken|perClient" --glob '*.{js,ts,py,go,java,rb}' -i
```

**Batching**:
```bash
rg -n "allowBatchedHttpRequests|maxBatchSize|batch\s*=\s*True|batching|Array\.isArray\(req\.body\)|WPGraphQL.*batch" --glob '*.{js,ts,py,php,rb}'
```

**Timeouts / body size**:
```bash
rg -n "GraphQL::Schema::Timeout|executionTimeout|queryTimeout|ReadTimeout|bodyParser.*limit|maxRequestBody" --glob '*.{js,ts,py,rb,go,java}'
rg -n "introspection.*complexity|__schema.*exclude|disableIntrospection" --glob '*.{js,ts,py,java}'
rg -n "@stream|@defer|incremental" --glob '*.{graphql,graphqls,js,ts}'
```

**Pagination / unbounded lists**:
```bash
rg -n "resolve.*args\.(first|last|limit|take|max|total|offset|pageSize|per_page|count|page|skip)|args\.(limit|take|first|last|max|total|offset|pageSize|per_page|count)" --glob '*.{js,ts,py,java,rb,go}' -C2
rg -n "findAll\(\)|\.all\(\)|LIMIT\s*\$|\.limit\(args\.|\.take\(args\." --glob '*.{js,ts,py,java,rb,go}' -C2
rg -n "filter.*limit|batchSize|batch_size|args\.filter" --glob '*.{js,ts,py,java,rb,go}' -C2
```

**Relay-style Connection pagination**:
```bash
rg -n "Connection|pageInfo|edges\s*\{|cursor|after|before" --glob '*.{js,ts,py,java,rb,go,graphql,graphqls}' -C2
rg -n "resolveConnection|connectionFromArray|fromGlobalId|edgeCount|first.*last" --glob '*.{js,ts,py,java,rb,go}' -C2
```

**Negative pagination / "return all" semantics**:
```bash
rg -n "limit\s*[<>=!]+\s*0|first\s*[<>=!]+\s*0|limit\s*:\s*-1|first\s*==\s*-1|Math\.max\(.*limit" --glob '*.{js,ts,py,java,rb,go}' -C2
rg -n "limit\s*<\s*0|first\s*<\s*0|negative.*limit|unlimited.*limit" --glob '*.{js,ts,py,java,rb,go}' -i
```

**N+1 / DataLoader**:
```bash
rg -n "DataLoader|dataloader|batch_load|includes\(|preload|JOIN" --glob '*.{js,ts,py,java,rb,go}'
rg -n "resolve_.*posts|resolve_.*comments|resolve_.*author" --glob '*.{js,ts,py}' -A3
```

**Circular SDL / fragments**:
```bash
rg -n "type\s+\w+\s*\{[^}]*\w+:\s*\[\1" --glob '*.{graphql,graphqls}'
rg -n "fragment.*on\s+\w+.*\.\.\.\w+" --glob '*.{graphql,graphqls}'
rg -n "NoFragmentCycles|fragment.*cycle" --glob '*.{js,ts,py,go,java}'
```

## Vulnerable Conditions

### 1. Missing query DEPTH limit

**Vulnerable when**: public `/graphql` serves a schema with nested or cyclic types and no depth validation rule / instrumentation.

| Stack | Expected control | Grep absence signal |
|-------|------------------|---------------------|
| Apollo / graphql-js | `depthLimit(n)` from `graphql-depth-limit` in `validationRules` | No `depthLimit` import or rule |
| graphene | `depth_limit_validator(max_depth=…)` on schema | Schema without depth validator |
| graphql-ruby | `max_depth:` on schema class | No `max_depth` in schema definition |
| graphql-java | `MaxQueryDepthInstrumentation` | No max depth instrumentation bean |
| gqlgen | `extension.FixedComplexityLimit` or custom depth rule | Generated server with no depth extension |
| Hot Chocolate | `AddMaxExecutionDepthRule(n)` | Schema builder without max depth |
| Ariadne | custom validation rule or `query_cost_validator` with depth | No validation rules list |
| mercurius | `queryDepth` / validation rules | Default mercurius with no depth config |
| graphql-php | `QueryDepth` rule in `DocumentValidator` | StandardServer without depth rule |

**VULN**:
```js
new ApolloServer({ schema, introspection: false });
// no validationRules: [depthLimit(7)]
```

**SAFE**:
```js
import depthLimit from 'graphql-depth-limit';
new ApolloServer({
  schema,
  validationRules: [depthLimit(7)],
});
```

### 2. Missing COMPLEXITY / COST analysis

**Vulnerable when**: depth alone is capped but alias/field/list multipliers are unbounded, or cost limit is set too high with no per-client budget.

- Missing `createComplexityLimitRule` / `graphql-query-complexity` (JS)
- Missing `@cost` SDL directive + cost analyzer (Hot Chocolate `AddCostAnalyzer`, gqlgen complexity func)
- graphql-ruby `max_complexity` absent or `max_complexity: 999_999`
- Introspection fields assigned zero cost while still reachable (complexity bypass)

**VULN**:
```js
// depth only — attacker uses 1000 aliases at depth 6
validationRules: [depthLimit(10)]; // no createComplexityLimitRule
```

**SAFE**:
```js
import { createComplexityLimitRule } from 'graphql-query-complexity';
validationRules: [
  depthLimit(7),
  createComplexityLimitRule(500, { scalarCost: 1, objectCost: 2 }),
];
```

#### Stateless per-query complexity cap (no cumulative budget)

**Vulnerable when**: a per-query complexity/cost ceiling exists, but there is **no per-IP, per-token, or per-session cumulative budget** across parallel requests. An attacker opens many connections each submitting a max-cost query (at or just under the per-query cap); HTTP request-rate limits that count requests only still allow N × maxComplexity resolver/DB work.

Distinct from **"cost limit too high"** (misconfigured threshold) — here each individual query is within policy, but aggregate cost is unbounded.

**Grep**: per-query `createComplexityLimitRule` / `max_complexity` present; absence of `complexityBudget`, `costCredit`, `rateLimit` keyed on complexity score, or Redis/DB-backed operation-count × complexity debits.

**VULN**:
```js
// Per-query cap only — 50 parallel clients each send complexity-500 queries
validationRules: [createComplexityLimitRule(500)];
// express-rate-limit: max 100 req/min per IP — does not multiply by complexity
app.use('/graphql', rateLimit({ windowMs: 60000, max: 100 }));
```

**SAFE**:
```js
// Debit estimated complexity against a per-client credit store (Redis/DB), not HTTP count alone
async function complexityBudgetMiddleware(req, res, next) {
  const score = estimateQueryComplexity(req.body.query);
  const key = req.user?.sub ?? req.ip;
  const remaining = await redis.decrby(`gql:credits:${key}`, score);
  if (remaining < 0) return res.status(429).json({ error: 'complexity budget exhausted' });
  next();
}
```

### 3. Circular / recursive SDL types

Cyclic references (`User { posts: [Post!]! }` / `Post { author: User! }`) or self-referential `Node { children: [Node!]! }` make "one more hop" always valid when depth/complexity limits are missing or set too high.

**VULN** (SDL excerpt):
```graphql
type User { posts: [Post!]! }
type Post { author: User! }
```

**VULN query shape**:
```graphql
{ me { posts { author { posts { author { posts { author { id } } } } } } } } }
```

**SAFE**: cyclic types allowed only with enforced `depthLimit` + complexity; consider breaking cycles in public API (DTO graphs).

### 4. Alias overloading

No `maxAliases` / custom alias-count validation — attacker repeats `{ a1: __typename a2: __typename … aN: __typename }`.

**Grep**: absence of alias limit middleware; `rg -n "alias" --glob '*validation*'`.

**VULN**: server accepts queries with hundreds of aliases; rate limit counts HTTP requests only.

**SAFE**: alias-count validation rule; complexity rule that charges per alias.

### 5. Directive overloading

Many duplicate directives on one selection (`@include` / `@skip` / custom directives × N) without directive-count cap or request body size limit.

**VULN**: no max directive count; `bodyParser.json({ limit: '10mb' })` missing on `/graphql`.

**SAFE**: cap directives in validation; reject documents above size threshold before parse.

### 6. Field duplication (selection HEIGHT vs depth)

**Depth** limits nesting levels (`user { posts { author { … } } }`). **Height** is the count of **sibling field occurrences under one parent** — the same field repeated at the same level without nesting deeper. Height attacks stay within a low depth cap but still multiply resolver/DB work linearly.

**Vulnerable when**: complexity rules **dedupe** identical sibling fields (count each unique field name once) or charge only by unique selection names — attacker repeats `{ user { id id id id /* … × 500 */ } }` at depth 2.

**Grep**: custom complexity functions that use `Set`/`uniq` on field names; absence of per-occurrence counters or duplicate-field validators.

**VULN query** (height, not depth):
```graphql
{ user { name name name name name /* … repeated */ } }
```

**SAFE**: complexity analyzer charges **per field occurrence** (not deduped); validation rule caps duplicate sibling count (e.g. reject >10 identical fields under one selection set).

### 7. Circular FRAGMENT spreads

Non-spec-compliant or custom engines that expand fragments without cycle detection (`fragment A on Query { ...B } fragment B on Query { ...A }`).

**Grep**: custom fragment expansion; absence of `NoFragmentCycles` (graphql-js built-in) in forked parsers.

**CVE-shape signal**: circular-fragment DoS (e.g. Agoo, CVE-2022-30288) — the SAST-detectable shape is a custom/forked GraphQL server executing fragment spreads without a cycle guard (`NoFragmentCycles`).

**SAFE**: rely on spec-compliant `graphql-js` / `libgraphqlparser` validation; verify `NoFragmentCycles` active.

### 8. Unbounded HTTP array BATCHING

Handler executes every element of `[{ "query": "..." }, …]` with no upper bound — bypasses per-request rate limits.

| Stack | Control |
|-------|---------|
| Apollo Server | `maxBatchSize`, `allowBatchedHttpRequests` |
| Graphene / Flask | `batch=True` on view — verify cap |
| mercurius | batch plugin config / max operations |
| WPGraphQL | batch query settings — verify limit |

**VULN**:
```js
new ApolloServer({
  allowBatchedHttpRequests: true,
  // no maxBatchSize
});
```

```python
# Graphene Django
GraphQLView.as_view(..., graphiql=False, batch=True)  # no batch size cap
```

**SAFE**:
```js
new ApolloServer({
  allowBatchedHttpRequests: true,
  maxBatchSize: 10,
});
```

**CVE-shape**: array-batching DoS (e.g. WPGraphQL) — the SAST-detectable shape is an HTTP handler that executes a JSON-array request body element-by-element with no `maxBatchSize`/operation-count cap.

### 9. Client-controlled pagination without server max

Resolver honors client pagination arguments with no server-side ceiling, or calls ORM `findAll()` / `.all()` on list fields.

**Pagination arg families** — flag any resolver passing client args directly to ORM/SQL `LIMIT`/`OFFSET`/`SKIP`/`TAKE` without a server cap:

| Arg family | Common names |
|------------|--------------|
| Cursor/page size | `first`, `last`, `take`, `limit` |
| Offset/page index | `offset`, `skip`, `page`, `after` (numeric misuse) |
| Explicit size | `max`, `total`, `count`, `pageSize`, `per_page`, `perPage` |
| Filter-driven batch | `filter.limit`, `filter.batchSize`, nested `input.limit` on list queries |

**Grep**:
```bash
rg -n "args\.(first|last|limit|take|max|total|offset|pageSize|per_page|count|page|skip)" --glob '*.{js,ts,py,java,rb,go}' -C3
rg -n "\.limit\(args\.|\.take\(args\.|LIMIT\s*.*args\.|OFFSET\s*.*args\." --glob '*.{js,ts,py,java,rb,go}'
rg -n "filter\.(limit|batchSize|count)|args\.filter.*limit" --glob '*.{js,ts,py,java,rb,go}'
```

**VULN**:
```js
resolveUsers: (_, { first, pageSize, offset }) =>
  db.users.limit(first ?? pageSize ?? 1000).offset(offset ?? 0).fetch(),
// first=1000000 or pageSize=500000 accepted
```

```python
def resolve_items(_, info, max=None, per_page=None, count=None):
    return Item.objects.all()[: (max or per_page or count or 999999)]
```

**SAFE**:
```js
const cap = Math.min(args.first ?? args.pageSize ?? 20, 100);
const offset = Math.min(Math.max(args.offset ?? 0, 0), 10_000);
return db.users.limit(cap).offset(offset).fetch();
```

#### Negative integer pagination ("return all")

**Vulnerable when**: negative `limit`, `first`, or `last` values are accepted — some ORMs/drivers treat `limit: -1` or `first == -1` as **no limit** (return entire table).

**Grep**: `limit < 0`, `first == -1`, `limit: -1`, or missing validation before ORM `.limit()`.

**VULN**:
```js
resolveUsers: (_, { first }) => db.users.limit(first).fetch(),
// first=-1 → full table
```

```python
# Django-style slice: queryset[0:limit] with limit=-1 can return all rows
return queryset[: args.get("limit", 100)]
```

**SAFE**:
```js
const first = args.first ?? 20;
if (first < 1 || first > 100) throw new GraphQLError('first must be 1–100');
return db.users.limit(first).fetch();
```

```python
limit = max(1, min(int(args.get("limit", 20)), 100))
return queryset[:limit]
```

### 10. Relay-style Connection pagination unbounded

**Vulnerable when**: schema exposes `Connection` types with `edges` / `node` / `pageInfo` / `cursor` and resolvers honor client `first`, `last`, `after`, `before` with **no server cap on `first`/`last`**. Same blow-up as flat pagination but often missed because limits are applied only to non-Connection list fields.

**Grep**:
```bash
rg -n "Connection|pageInfo|edges|cursor|after|before" --glob '*.{js,ts,py,java,rb,go,graphql,graphqls}' -C2
rg -n "resolveConnection|connectionFromArray|applyPagination|edgeCount" --glob '*.{js,ts,py,java,rb,go}'
# Absence of Math.min(first, MAX) or validateFirst() near connection resolvers
```

**VULN**:
```js
async function resolveUsersConnection(_, { first, after }) {
  const take = first ?? 50; // no Math.min — first=100000 accepted
  return connectionFromArraySlice(allUsers, { sliceStart, sliceEnd: sliceStart + take });
}
```

**SAFE**:
```js
const MAX_PAGE = 100;
const take = Math.min(Math.max(first ?? 20, 1), MAX_PAGE);
if (last != null) throw new GraphQLError('backward pagination not supported');
return connectionFromArraySlice(users, { sliceStart, sliceEnd: sliceStart + take });
```

### 11. Missing execution TIMEOUT and HTTP limits

No GraphQL-level timeout (`GraphQL::Schema::Timeout`, Apollo `plugins` / custom deadline, Java `AbortExecutionInstrumentation`) and no HTTP server/proxy read/write timeouts or body size limit on `/graphql`.

**VULN**:
```ruby
class MySchema < GraphQL::Schema
  # no use GraphQL::Schema::Timeout
end
```

```js
app.use('/graphql', bodyParser.json()); // default unlimited body
graphqlHTTP({ schema }); // no execution timeout
```

**SAFE**: schema timeout + reverse-proxy timeouts + `bodyParser.json({ limit: '100kb' })`.

### 12. Introspection-amplified DoS / large arguments

Complexity rules that **exclude** introspection meta-fields (`__schema`, `__type`) from cost — attacker runs expensive introspection while complexity stays low. Large string arguments with no max length on args/scalars.

**VULN**: custom complexity function returns 0 for fields starting with `__`; no `maxStringLength` validation.

**SAFE**: disable introspection in production **or** include introspection in complexity; cap argument string lengths in validation rules.

**Circular introspection (meta-schema recursion)**: the introspection meta-types are self-referential — `__Type.ofType → __Type`, `__Type.fields → __Field.type → __Type`, `__Type.interfaces/possibleTypes → __Type` — so a single introspection document can nest these meta-fields arbitrarily deep and force exponential resolution **regardless of the domain schema**. Bites when introspection is enabled and the depth/complexity rule is applied only to user types or exempts `__`-prefixed fields (the same exclusion above), so domain-schema depth limits never trip.

```graphql
query { __schema { types { fields { type { ofType { ofType {
  fields { type { ofType { name } } } } } } } } }
```

**Grep seeds**:
```bash
rg -n "depthLimit|maxDepth|costAnalysis|complexity" --glob '*.{js,ts,py,go,java,cs,rb}' -C2
# exemptions/ignores that skip introspection from limits
rg -n "ignoreIntrospection|skip.*__|startsWith\\(\"__\"\\)|ignore.*introspection" --glob '*.{js,ts,py,go,java,cs}' -i
```

**SAFE**: disable introspection in production; if it must stay on, apply depth/complexity limits to introspection meta-fields too (do not exempt `__`), or serve introspection only from a static pre-validated document.

### 13. `@stream` / `@defer` incremental-delivery abuse

Incremental delivery enabled without limits on concurrent streams, stream batch size, or total deferred fields — long-lived connections and unbounded partial execution.

**Grep**: `@stream`, `@defer`, `incrementalDelivery`, `@defer` plugin config without caps.

**SAFE**: disable on public endpoints or cap stream count / duration in server config.

### 14. N+1 resolver amplification (DoS amplifier)

Cyclic or list fields resolved with per-row fetches (`posts` → `author` → `posts`) and no DataLoader / JOIN / batch loader — single query triggers O(n²) database round-trips.

**VULN**:
```js
Post: {
  author: (post) => db.users.findById(post.authorId), // N+1 on nested lists
},
```

**SAFE**: DataLoader per request; eager `includes` / JOIN in list resolvers; complexity limits as backstop.

### 15. Multipart `Upload` orphan/excess-part exhaustion

Stacks implementing the GraphQL multipart request spec (`Upload` scalar, `operations` + `map` form fields) where the parser **buffers every received file part to disk/RAM before checking whether it is referenced in `map`**. Unreferenced ("orphan") or oversized extra parts — plus reusing one `Upload` variable across many arguments to force repeated stream reads — drive memory/disk exhaustion from a single request.

**VULN**:
```js
// graphql-upload with no caps: every part is processed/buffered before map validation
app.use(graphqlUploadExpress()); // no maxFiles / maxFileSize
```

**SAFE**: set `maxFiles` and per-file `maxFileSize`; reject parts not referenced in `map`; treat each `Upload` variable as single-use; stream to bounded temp storage with cleanup. Cross-ref `graphql_injection.md` (Multipart `Upload` scalar abuse) and `arbitrary_file_upload.md`.

### 16. Unbounded list/array INPUT argument (bulk-operation amplification)

A **list-typed input argument** (`ids: [ID!]!`, `input: [CreateOrderInput!]!`) — or a **list field inside an input object** — whose element count is unbounded, where the resolver performs **per-element work** (DB write/read, HTTP call, crypto, file op). A single shallow operation (depth 1–2, one alias, one HTTP request) carrying a 50k-element array in `variables` forces 50k units of work. This **bypasses** depth limits, alias/field caps, HTTP-batch disabling, and any complexity/cost rule that scores **statically per selection/field** without multiplying by `variables[arg].length`.

**Distinct from**: HTTP array batching (#8 — array of *operations*, not an argument), alias overloading (#4), large *string* args (#12 — scalar character length, not element count), and pagination (#9 — output page size, not input cardinality). The amplifier here is the **cardinality of one list-typed input value**.

**Vulnerable when**: a resolver iterates a client-supplied list argument (`Promise.all(input.map(…))`, `for (const x of args.ids)`, `ids.map(id => db…)`, bulk `insertMany`/`deleteMany(args.ids)`, `WHERE id IN (:ids)`) with no element-count check; **and** no `maxItems` / array-length validation rule is installed; **and** complexity/cost is static-per-field (never reads the variable array length) or absent.

**Grep**:
```bash
rg -n "Promise\.all\(\s*\w+\.map|\.map\(\s*\w*\s*=>.*(db|repo|fetch|axios|prisma|knex|query|insert|delete|update)|insertMany|deleteMany|bulkCreate|createMany|updateMany|findByIds|IN\s*\(" --glob '*.{js,ts,py,go,java,rb}' -C2
# list-typed input args / input-object list fields in SDL (then check for a length cap)
rg -n "\w+\s*:\s*\[\w+!?\]!?" --glob '*.{graphql,graphqls}'
rg -n "maxItems|array.*length.*limit|input.*length|len\(.*\)\s*>|\.length\s*>" --glob '*.{js,ts,py,go,java,rb}' -i
```

**VULN**:
```graphql
type Mutation { createOrders(input: [CreateOrderInput!]!): [Order!]! }   # no max list length
type Query    { productsByIds(ids: [ID!]!): [Product!]! }
```
```js
// one DB unit per element — depth/alias/complexity-per-field/batch-disable do not bound it
createOrders: (_, { input }) => Promise.all(input.map(o => db.orders.insert(o))),
productsByIds: (_, { ids }) => Promise.all(ids.map(id => db.products.findById(id))),
```

**SAFE**: validate input-list length before execution (reject `input.length > N`); a validation rule that caps total list-input elements per document; charge complexity **proportional to** array length (`cost = perItem × variables[arg].length`); or route bulk operations through a paginated/queued batch API with a hard ceiling.

### 17. Federation `_entities` representation-storm amplification

Apollo Federation's auto-generated `Query._entities(representations: [_Any!]!): [_Entity]!` (added by `buildSubgraphSchema` / `buildFederatedSchema` for every `@key` type) is a **list-typed input argument** (special case of #16) whose per-element work is a `__resolveReference` call — typically a DB/HTTP lookup per representation. A single shallow operation carrying tens of thousands of representations forces one resolver round-trip each, **bypassing** depth/alias/field caps and HTTP-batch limits, and is usually invisible to complexity rules that score the public SDL (the `_entities` field is not in it). Aliasing `_entities` (`a:_entities(...) b:_entities(...)`) multiplies further.

**Vulnerable when**: a directly reachable subgraph (`buildSubgraphSchema`) has no `representations` length cap and no complexity rule that multiplies by `variables.representations.length`; `__resolveReference` does per-id DB/HTTP work (often without DataLoader → also #14).

**Grep**:
```bash
rg -n "buildSubgraphSchema|buildFederatedSchema|_entities|representations|__resolveReference" --glob '*.{js,ts,go,py,java,rb}'
```

**VULN**: `_entities(representations:[{__typename:"User",id:"1"}, … × 50000])` → 50k `User.__resolveReference` DB reads in one request.

**SAFE**: cap `representations` length in a validation rule; batch `__resolveReference` via DataLoader; restrict subgraph network reachability to the gateway. Cross-ref the access/disclosure side of `_entities` in `graphql_injection.md` (federation entity-resolution access).

## Vulnerable vs Safe Examples

```graphql
# VULN: alias storm (no alias/complexity cap)
{ a1:__typename a2:__typename a3:__typename /* … × 500 */ }

# VULN: field height duplication (same parent, many siblings)
{ users { id id id id /* … */ } }

# VULN: unbounded Relay connection
{ users(first: 999999) { edges { node { id } } } }

# VULN: directive pile
{ user { name @include(if:true) @include(if:true) /* custom directives × N */ } }

# SAFE: rejected by complexity/alias rules or depth limit
```

```bash
# VULN: batch amplification
curl -X POST https://target/graphql -H 'Content-Type: application/json' \
  -d '[{"query":"{ __typename }"},{"query":"{ __typename }"}]'  # × thousands if no maxBatchSize
```

## Safe Patterns

- Enforce **depth + complexity/cost** on every public endpoint; include introspection in cost or disable it.
- Cap **aliases**, **directives**, **field duplicates (height)**, and **document size** in validation rules.
- Set **`maxBatchSize`** (or disable batching) when `allowBatchedHttpRequests` / `batch=True`.
- **Server-side pagination caps** — never trust client `first`/`limit`/`pageSize`/`offset`/`max`/`count` alone; reject negative values; cap Relay `Connection` `first`/`last`.
- **Execution timeouts** at schema and resolver level; HTTP **body size** and **proxy timeouts**.
- **DataLoader** / batch fetching for list+cyclic fields; monitor p95 resolver count per operation.
- Rate-limit by **operation count × complexity score** with a **cumulative per-IP/per-token budget** (Redis/DB credit store), not HTTP request count alone.
- For `@stream`/`@defer`: disable or strictly limit on production public APIs.

### Recommended baseline limits (misconfiguration benchmark)

Use as SAST triage defaults when reviewing public/anonymous GraphQL endpoints — configs **far above** these without documented justification warrant **Low–Medium** misconfiguration findings:

| Control | Public / authenticated baseline | Anonymous / untrusted (tighter) |
|---------|--------------------------------|----------------------------------|
| Query **depth** | ~7–20 (typical API: 7–10; rich graphs: up to ~20) | Lower third of range (e.g. 7–8) |
| Query **complexity/cost** | ~300–500 per operation | ~200–300 |
| Pagination `first`/`limit` | Server cap ~50–100 regardless of client arg | Same or lower |
| HTTP batch size | ≤10 operations | ≤5 or disabled |

**Grep for outliers**:
```bash
rg -n "depthLimit\(\s*[2-9][0-9]{2,}|maxQueryDepth\s*[:=]\s*[2-9][0-9]{2,}|max_complexity:\s*[5-9][0-9]{3,}" --glob '*.{js,ts,py,rb,go,java}'
rg -n "createComplexityLimitRule\(\s*[5-9][0-9]{3,}|max_complexity:\s*[5-9][0-9]{3,}" --glob '*.{js,ts,py,rb}'
```

## Severity / Triage

| Finding | Typical severity |
|---------|------------------|
| Public endpoint, cyclic SDL, no depth **and** no complexity | **High** |
| Depth limit only, no complexity (alias/field height/batch amplification) | **Medium–High** |
| Per-query complexity cap but no cumulative per-client budget | **Medium** |
| Unbounded Relay `Connection` `first`/`last` on public API | **Medium–High** |
| Negative `limit`/`first` accepted (ORM "return all") | **Medium–High** |
| Client `pageSize`/`offset`/`max`/`count` passed to ORM without cap | **Medium** |
| Unbounded HTTP batching on authenticated internal API | **Medium** |
| Missing timeout with otherwise strong limits | **Medium** |
| N+1 on high-cardinality list field (no DataLoader) | **Medium** (availability) |
| Depth/complexity present but limits far above baseline (depth >20, complexity >500 public / >1000 any) | **Low–Medium** (misconfiguration) |
| Depth + complexity + batch cap + timeouts all configured | **FALSE POSITIVE** |

## Common False Alarms

- Depth/complexity rules present in **test** config but also wired in production server bootstrap (verify prod entrypoint, not only dev `ApolloServer` in tests).
- Internal-only GraphQL with mTLS / network ACL — lower severity; limits still recommended.
- `findAll()` in admin-only resolver behind strong role check — triage as Low unless BFLA path exists (cross-ref `graphql_injection.md`).
- ReDoS in search resolver — report under `regex_injection_redos.md`; mention GraphQL transport only as context.

## Cross-References

- `denial_of_service.md` — generic ReDoS, HTTP slow-client, zip/XML bombs, LLM token exhaustion (not GraphQL-specific).
- `graphql_injection.md` — document injection, authz, CSRF, introspection disclosure (not structural DoS).
- `regex_injection_redos.md` — search/filter args passed to regex in resolvers.
- `cve_patterns.md` — known-CVE methodology (sink+source pattern, fix-pattern variant sweep) for generalizing a confirmed DoS shape to its unfixed siblings.
- `websocket_security.md` — subscription transport DoS / missing Origin (complements HTTP GraphQL limits).

## Core Principle

Treat every public GraphQL operation as a **program** the client submits: bound its parse/validate/execute cost with depth, complexity, alias/directive/field caps, batch limits, pagination ceilings, timeouts, and request size limits — and design resolvers so list/cyclic fields cannot multiply work beyond those bounds.
