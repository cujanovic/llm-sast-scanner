---
name: graphql_injection
description: Detect GraphQL security issues including document injection, resolver-layer taint to SQL/NoSQL/RCE/SSRF/XSS sinks, introspection and information disclosure, authorization gaps, CSRF/request forgery, WebSocket transport parity, and operation-name injection — structural DoS covered in graphql_dos.md.
---

# GraphQL Security Issues

GraphQL APIs present a distinct attack surface that differs significantly from REST. The primary risk categories are:

1. **GraphQL document injection** — user input embedded into the operation string (query/mutation text), not only the `variables` map.
2. **Resolver taint** — every argument surface (field args, directives, variables map, input objects, JSON scalars, Upload) reaching injection sinks without sanitization.
3. **Introspection / information disclosure** — schema leakage, field suggestions, partial introspection disable, tracing/cost extensions, GraphiQL in prod (incl. client-only IDE gates), static SDL/docs routes, collection/list filter-operator exfiltration, sensitive SDL/PII field heuristics, engine-fingerprint errors, ORM errors in responses, GET variable logging.
4. **Authorization gaps** — gateway-only auth (incl. federation/stitching, Mutation-only resolver wrapping), BFLA on privileged mutations, miswired `@auth` directives (incl. interface vs implementing types), graphql-shield allow-by-default, enum sort/order exposure, JWT-as-argument, IP allowlist as sole gate, optional-arg auth bypass, deprecated/stub operations unauthenticated, auth-exempt operation Sets, soft-fail auth returns, header-derived identity in context.
5. **Request forgery** — GET mutations (incl. Sangria), form-urlencoded/`text/plain` POST, CSRF on cookie-auth endpoints, side effects / state-changing operations on Query type.
6. **WebSocket transport parity** — subscriptions without Origin check; queries/mutations/subscriptions over WS must share HTTP validationRules/auth/introspection config.
7. **Operation-name injection** — client-controlled `operationName` persisted to logs/SQL unsanitized (distinct from allowlist bypass).
8. **Operation-name allowlist bypass / APQ not enforced** — enforcement keyed on `operationName` without document hashing; or `persistedQueries`/`AutomaticPersistedQueries` enabled but ad-hoc `query` bodies still execute.
9. **Unauthenticated GraphQL endpoint / alternate mount paths** — no auth middleware on `/graphql`; hardening applied only to primary route while `/gql`, `/v1/graphql`, `/playground`, etc. remain exposed.
10. **Custom scalar / directive handler gaps** — pass-through scalar coercion; directive handlers executing string templates with user-controlled args.
11. **ReDoS in resolvers** — GraphQL arguments passed into server-side regex without bounds (cross-ref `graphql_dos.md` for search-arg amplification).
12. **Structural DoS** — depth/complexity/alias/batch/pagination/timeouts — see `graphql_dos.md`.

## GraphQL Document Injection (Operation String Injection)

Occurs when user-controlled data alters the **GraphQL document** (query/mutation/subscription source string) rather than being bound only through **variables**. The parser then interprets attacker-controlled syntax — new fields, aliases, directives, or fragments — which can bypass intent, reach unauthorized resolvers, or change server-side behavior when the document is executed or forwarded.

**Core pattern**: unvalidated user input changes the operation string passed to `execute`, `graphql`, a gateway client, or an HTTP body `query` field built from string operations.

### What GraphQL Injection IS

- Concatenating or interpolating user input into operation text: `` `query { user(id: "${id}") { name } }` ``, `"query { user(id: \"" + id + "\") { name } }"`
- Building the JSON `query` field for a downstream GraphQL HTTP request with string concat from request body or params
- Forwarding `req.body.query` into another interpolated template that wraps or extends the operation
- Dynamic `gql` / `graphql-tag` template literals where a non-static expression changes document structure (not just a bound variable value inside a static document)
- Server-side code that selects or assembles operation text from user input (including persisted-query ID → document maps without allowlisting)
- Wrappers around `graphql.execute()`, `graphqlHTTP`, Yoga/Apollo request pipeline where the document/source argument is built from user-influenced variables
- Client-controlled **`operationName`** written to logs, audit tables, or SQL without encoding (operation-name injection sink)

### What GraphQL Injection is NOT

- **SQL injection in resolvers** — resolver builds SQL from `args`; classify as SQL injection at resolver layer (still report under GraphQL context)
- **NoSQL / command injection in resolvers** — same; use the appropriate resolver-layer skill
- **IDOR via GraphQL arguments** — static document with another user's ID in `variables` JSON is authorization, not document injection
- **Normal variable binding** — static document with `{"query": "query($id: ID!) { user(id: $id) { name } }", "variables": {"id": userInput}}`; structure is fixed (still verify authorization in resolvers)
- **Introspection / field suggestion enabled** — information disclosure; only document injection if user input alters the operation **string**
- **Query depth / complexity / alias / batch DoS** — `graphql_dos.md` (not document injection)

### Recon Indicators

**GraphQL surface** (dependencies, schema, routes):
- Libraries: `graphql`, `@apollo/server`, `apollo-server-express`, `@nestjs/graphql`, `graphql-yoga`, `mercurius`, `strawberry-graphql`, `graphene`, `gqlgen`, `graphql-ruby`, Hot Chocolate, Ariadne
- Artifacts: `*.graphql`, `*.graphqls`, GraphQL Code Generator config
- Entry points: routes or plugins mounting `/graphql`

**Unsafe document construction** (grep):
- `` `query { ...${x}...}` ``, `"mutation { " + userFragment + " }"`, `sprintf` / `.format()` / f-strings building `query` or `source`
- `graphql(schema, dynamicString)`, `execute({ document: parsedDynamic })` where the string feeding `parse`/`execute` is non-constant
- `graphqlHTTP` or similar patterns that **mutate** or **wrap** `req.body.query` with user data
- `JSON.stringify({ query: \`...${userPart}...\` })`, `axios.post(url, { query: builtFromInput })`
- Persisted/stored query lookup by user-supplied key without allowlist → file path or DB value becomes document source

**Not document-injection candidates**:
- Fully static `source` / `query`; only `variableValues` / `variables` come from the request
- SDL / `buildSchema` with no user interpolation
- Resolvers using parameterized DB APIs (note for SQLi skill unless the **document** is built unsafely)

### Safe / Preventing Patterns

- **Static operation documents with variables** — compile-time constant document; dynamic values only in `variableValues`
- **Server parses client document once** — mere `req.body.query` on a standard handler is client-supplied operation text; flag **server-side** construction of a **new** document incorporating user strings before `execute` or forwarding
- **Persisted queries / allowlisted operation IDs** — document looked up by ID from a server-side registry; client cannot inject arbitrary document text
- **graphql-js static `source`** — `graphql({ schema, source: staticQueryString, variableValues: { id: userId } })`

### Dynamic Test / PoC

Proxy or BFF that interpolates user input into operation text:

```bash
curl -X POST https://target/proxy -H 'Content-Type: application/json' \
  -d '{"fragment": "id email __typename } admin: user(id: 1) { role"}'
```

**Expected signal**: response includes fields/aliases not in the intended operation (e.g., `admin`, `role`) or downstream GraphQL parse/validation errors referencing injected selections.

If server builds `query { me { ${userFields} } }`, payload in `userFields`:

```graphql
id } secretField { token
```

**Expected signal**: unauthorized fields in JSON response or errors referencing unexpected field nodes.

**Introspection enabled**
```bash
curl -s -X POST https://target/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { types { name fields { name type { name } } } mutationType { fields { name args { name type { name } } } } queryType { fields { name } } } }"}'
```
**Expected signal**: full schema dump (`types`, `mutationType`, hidden admin fields).

**Auth bypass probes (static document — test resolver authorization)**
```graphql
{ adminUsers { id email role } }
mutation { deleteUser(id: "123") { success } }
{ user(id: "OTHER_USER_ID") { email ssn } }
```

**Structural DoS probes** — depth/alias/batch patterns; see `graphql_dos.md` for expected signals and limits.

**Directive / error oracle**
```graphql
{ user(id: "1") { name email @skip(if: false) secretField @include(if: true) } }
{ user { nonExistentField } }
```
**Expected signal**: leaked fields via directives, or validation errors suggesting hidden field names.

## Resolver Taint Sources (GraphQL-Specific)

In GraphQL, **every argument surface is a taint source** at the resolver layer. Variables protect the **document** from injection but do **not** sanitize values passed to resolvers.

| Source | Examples |
|--------|----------|
| Top-level operation args | `query($id: ID!)`, mutation input args |
| **Field args** (nested resolvers) | `username(capitalize: Boolean)`, `search(q: String)` on nested fields |
| **Directive handler args** | Custom `@auth(role: String)`, `@computed(value: String)`, `@deprecated(reason:)` — handler may eval/format/template with user-controlled directive args |
| **`variables` map** | `info.variableValues`, `context.variables` — taint at resolver, not document-safe |
| **Input object fields** | `CreateUserInput { email, profile { bio } }` |
| **Custom scalars** | `JSON`, `JSONObject`, `AWSJSON` — opaque structured taint; `Email`, `IPAddress`, `UUID`, `DateTime` via `graphql-scalars` or `GraphQLScalarType` with weak `parse_value`/`parse_literal`/`serialize` |
| **`Upload` scalar** | Filename and file content in multipart requests |

**Resolver grep bundle**:
```bash
rg -n "resolve_|@QueryMapping|@MutationMapping|@SubscriptionMapping|@Argument|@SchemaMapping" --glob '*.{js,ts,py,java,go,rb,php,cs}'
rg -n "args\.|args\[|getArgument|info\.variableValues|variableValues" --glob '*.{js,ts,py,java,go,rb,php,cs}'
rg -n "SchemaDirectiveVisitor|visitDirective|mapSchema|@directive|Directives\." --glob '*.{js,ts}'
rg -n "GraphQLUpload|UploadScalar|upload\.|multipart" --glob '*.{js,ts,py,java}'
```

**FALSE-POSITIVE guidance**: GraphQL schema types (`String`, `Int`, `Boolean`, enums) are **not** sufficient barriers for sinks — a `String` arg still reaches SQL, shell, HTTP client, and HTML sinks.

## Injection Sink Bridges (Resolver Layer)

Track taint from resolver sources above into sinks. Emit GraphQL tag **plus** the sink-specific skill tag.

| Sink | Pattern | Cross-ref |
|------|---------|-----------|
| **SQLi** | `args.filter` → `LIKE '%' + args.q + '%'`, f-string SQL in `resolve_*` | `sql_injection.md` |
| **OS command** | `systemDebug(cmd: String)` → `os.system(args.cmd)`, `subprocess`, `exec` | `rce.md` |
| **NoSQL** | `args` / JSON scalar → `collection.find(args)`, Mongo query doc built from input | `nosql_injection.md` |
| **SSRF** | `importUrl`, `fetchUrl`, `download`, decomposed `scheme`/`host`/`port`/`path` args → outbound HTTP client | `ssrf.md` |
| **Reflected XSS** | Resolver returns HTML string built from args without encoding | `xss.md` |
| **Stored XSS** | Mutation persists arg → later server render of user content | `xss.md` |
| **File upload** | `Upload` scalar — filename path traversal, dangerous MIME, write outside intended dir | `arbitrary_file_upload.md` |

**VULN (SQLi)**:
```js
resolveUsers: (_, args) => db.query(`SELECT * FROM users WHERE name LIKE '%${args.filter}%'`);
```

**VULN (SSRF)**:
```python
def resolve_fetch_url(root, info, url):
    return requests.get(url).text  # args.url attacker-controlled
```

**VULN (Upload)**:
```js
Upload: GraphQLUpload,
// resolver: fs.writeFileSync(args.filename, stream) — no basename/sandbox
```

**SAFE**: parameterized queries; allowlisted outbound hosts; encode HTML output; validate upload path and content type.

## Custom Scalar Coercion Without Validation

Custom scalars whose `parse_value`, `parse_literal`, or `serialize` is pass-through, identity, or regex-only (without canonicalization) let attacker-controlled literals bypass intended validation and reach downstream sinks (SQL, SSRF host checks, auth gates).

**Vulnerable conditions**:
- `GraphQLScalarType` / `graphql-scalars` `Email`, `IPAddress`, `UUID`, `DateTime` with `parseValue: (v) => v` or trivial `.test()` without library validators
- IPAddress accepting ambiguous forms (e.g. dotted-quad with leading zeros, mixed encodings) — CVE-2021-29921 class; canonicalize before allowlist/compare
- Custom scalar serializes internal object to client without redaction

**Grep seeds**:
```bash
rg -n "GraphQLScalarType|graphql-scalars|parseValue|parse_value|parseLiteral|parse_literal|serialize" --glob '*.{js,ts,py,java,go,rb,cs}'
rg -n "Email|IPAddress|UUID|DateTime|PositiveInt" --glob '*.{graphql,graphqls,js,ts,py}'
rg -n "parseValue:\s*\(|parse_value.*=>|def parse_value" --glob '*.{js,ts,py,java,go,rb}'
```

**VULN**:
```js
const IPAddress = new GraphQLScalarType({
  name: 'IPAddress',
  parseValue: (v) => String(v),  // no canonicalization; ambiguous forms reach SSRF sink
});
```

**SAFE**: use `graphql-scalars` with default validators; canonicalize IP/UUID/datetime before compare; reject non-canonical literals at parse time.

## Custom Directive Handlers Executing String Templates

Custom directive handlers that interpolate user-controlled directive arguments into templates, format strings, or dynamic expressions behave like resolvers — taint from directive args can reach SQL, shell, or eval sinks.

**Vulnerable conditions**:
- `@computed(value: "$firstName $lastName")` or similar where handler substitutes field/directive args into a template without sanitization
- Directive visitor / `mapSchema` handler calling `eval`, `Function`, `format`, or string concat with `args` from SDL or client-supplied directive values
- `@auth(role: String)` where `role` flows to SQL or shell without allowlist

**Grep seeds**:
```bash
rg -n "@computed|visitDirective|DirectiveVisitor|getDirective|schema\.getDirective" --glob '*.{js,ts,graphql,graphqls}'
rg -n "directive.*resolve|Directives\.|mapSchema.*directive" --glob '*.{js,ts}'
rg -n '\$\{|\.format\(|sprintf|f".*\{.*args' --glob '*.{js,ts,py}' -C2
```

**VULN**:
```js
ComputedDirective: {
  visitFieldDefinition(field, { value }) {
    field.resolve = (obj) => eval(`\`${value}\``);  // directive arg → template → eval
  },
},
```

**SAFE**: treat directive handlers like resolvers — parameterized sinks, role allowlists, no eval; static directive args only in SDL.

## Operation-Name as Injection Sink

Distinct from **allowlist bypass**: client-controlled `info.operation.name` / `req.body.operationName` used as **data** in logs, audit events, metrics labels, or SQL without sanitization.

**VULN**:
```js
auditLog.insert({ op: req.body.operationName }); // SQL/log injection if name contains quotes/newlines
db.query(`INSERT INTO audit (name) VALUES ('${info.operation.name}')`);
```

**SAFE**: bind operation name as parameterized value; allowlist alphanumeric names; never concatenate into SQL or shell.

## Information Disclosure

Beyond verbose stack traces — GraphQL-specific disclosure channels.

### Field suggestions / "Did you mean"

graphql-js and graphene enable **field suggestion** on validation errors (`Did you mean "secretField"?`), leaking hidden field names when introspection is disabled.

**Grep**:
```bash
rg -n "did_you_mean|DidYouMean|suggestionList|MAX_LENGTH" --glob '*.{js,ts,py}'
```

**VULN**: introspection off but suggestions on in production.

**SAFE**: disable suggestions when introspection disabled (`graphene` `did_you_mean.MAX_LENGTH = 0` or equivalent).

### Partial introspection disable

Middleware/WAF blocking only `__schema` while `__type(name: "User")` / `__typename` still work — incomplete hide. Rely on **engine-native** `introspection: false` or validation rules, not substring denylists on query text.

**Grep**:
```bash
rg -n "__schema|__type|introspection.*false|disableIntrospection|NoSchemaIntrospection" --glob '*.{js,ts,py,go,java,cs,rb}'
# gqlgen
rg -n "extension\.Introspection|AroundOperations|AroundResponses" --glob '*.go'
# Hot Chocolate
rg -n "DisableIntrospection|IntrospectionOptions|AddMaxExecutionDepthRule" --glob '*.cs'
# Ariadne
rg -n "introspection|validation_rules" --glob '*.py'
# mercurius
rg -n "graphiql|introspection|validationRules" --glob '*.{js,ts}'
# NestJS
rg -n "GraphQLModule\.forRoot|introspection|playground" --glob '*.{ts,js}'
# graphql-ruby
rg -n "disable_introspection_entry_points|introspection" --glob '*.rb'
```

### Apollo / tracing extensions

Tracing plugin emitting client-visible `extensions.tracing` in production — timing and resolver path disclosure.

**Grep**: `ApolloServerPluginUsageReporting`, `tracing`, `includeStacktraceInErrorResponses`.

### Cost / credit metadata in extensions

Query-cost or billing plugins attaching `extensions.cost`, `queryCost`, `credits_remaining`, or similar to client responses in production — distinct from tracing; aids quota probing and business-logic mapping.

**Vulnerable conditions**:
- Cost-analysis plugin or custom formatter appends `extensions.cost` / `queryCost` to every response in prod
- `credits_remaining` or rate-limit counters exposed in GraphQL JSON extensions

**Grep seeds**:
```bash
rg -n "extensions\.cost|queryCost|credits_remaining|estimatedCost|complexityCost" --glob '*.{js,ts,py,java}'
rg -n "formatResponse|willSendResponse|extensions:" --glob '*.{js,ts}' -C2
```

**VULN**:
```js
willSendResponse({ response }) {
  response.extensions = { ...response.extensions, cost: computeCost(response), credits_remaining: ctx.credits };
}
```

**SAFE**: strip cost/credit metadata in production formatters; log server-side only.

### GraphiQL / Playground in production

GraphiQL/Playground enabled alongside hardened `/graphql` — dual endpoints with divergent error/security config (e.g. `/graphiql` leaks stacks).

**Client-side-only IDE gate**: IDE disabled via client-readable cookie, `localStorage`, or query flag (e.g. `env=graphiql:disable`) while the `/graphiql` or `/playground` route still serves the full API or schema explorer without server-side auth or environment guard — trivially bypassed in DevTools.

**Vulnerable conditions**:
- `graphiql: true`, `playground: true` in production config
- Route `/graphiql` or `/playground` registered without server-side `NODE_ENV` / auth middleware
- Frontend hides GraphiQL link via cookie/localStorage; backend route unchanged

**Grep seeds**:
```bash
rg -n "graphiql:\s*true|playground:\s*true|GraphiQL|GraphQLPlayground" --glob '*.{js,ts,py,java,cs}'
rg -n "/graphiql|/playground|graphiql.*route|playground.*route" --glob '*.{js,ts,py,java}'
rg -n "localStorage.*graphiql|cookie.*graphiql|graphiql.*disable|playground.*disable" --glob '*.{js,ts,jsx,tsx,vue}'
```

**VULN**:
```js
// Client-only gate — server still serves IDE
if (localStorage.getItem('graphiql') !== 'disable') mountGraphiQL();
app.use('/graphiql', graphiqlMiddleware({ endpointUrl: '/graphql' })); // no auth, all envs
```

**SAFE**: disable GraphiQL/Playground routes in production at server config; require auth on IDE routes; never rely on client storage/cookies alone.

### Static schema documentation / exported SDL in production

Generated HTML schema docs, committed `*.graphql` / `*.graphqls` files, or codegen output served via static middleware or routes (`/docs`, `/schema`, `/api-docs`, `/sdl`) without authentication — introspection-equivalent disclosure of types, fields, and mutations.

**Vulnerable conditions**:
- `express.static('schema')`, `app.use('/docs', serveSchemaDocs)`, or `/schema` route returns full SDL in production
- Committed `schema.graphql` deployed and web-accessible
- GraphQL Code Generator `schema.graphql` or generated static HTML schema docs in public static dir

**Grep seeds**:
```bash
rg -n "express\.static|serveStatic|StaticFiles|app\.use\s*\(\s*['\"]/(docs|schema|api-docs|sdl)" --glob '*.{js,ts,py,go,java}'
rg -n "\.graphql['\"]|\.graphqls['\"]|schema\.graphql|introspection\.json" --glob '*.{js,ts,py,go,yml,yaml,json}'
rg -n "renderSchema|printSchema|buildSchema.*write|schema\.sdl" --glob '*.{js,ts,py,go}'
```

**VULN**:
```js
app.use('/schema', express.static(path.join(__dirname, 'generated/schema.graphql')));
```

**SAFE**: serve SDL/docs only in dev or behind auth; generate at build time for internal tooling, not public HTTP.

### Engine-fingerprinting error shapes

Custom `formatError` / `format_error` handlers that emit non-spec top-level keys or extension fields (`syntaxError`, `validationErrorType`, engine-specific error codes) leak server implementation identity — aids targeted exploitation.

**Vulnerable conditions**:
- Response shape not normalized to spec `{ errors: [{ message, locations?, path?, extensions? }] }` in production
- Custom keys at error root or in extensions identifying graphql-js vs Apollo vs graphene vs Hot Chocolate
- Validation errors include internal rule names or parser token details

**Grep seeds**:
```bash
rg -n "formatError|format_error|GraphQLError|serializeError" --glob '*.{js,ts,py,java,go,rb,cs}'
rg -n "syntaxError|validationErrorType|errorType|extensions\.code" --glob '*.{js,ts,py,java}'
```

**VULN**:
```js
formatError: (err) => ({
  message: err.message,
  syntaxError: err.source?.body,
  validationErrorType: err.extensions?.validationErrorType,
});
```

**SAFE**: normalize to spec error shape in production; map internal codes server-side; generic client messages. Cross-ref `information_disclosure.md`.

### Collection/list filter operator data exfiltration

Public list/collection Query fields expose rich filter input types (`*Filter`, `where`, `filter`) with operator suffix fields (`*_contains`, `*_in`, `*_gt`, `*_lt`, `*_starts_with`, `key_contains`) — unauthenticated clients can target specific records (key-value/config string collections leaking secrets, internal URLs, tokens). Resolver forwards `args.where` / `args.filter` to ORM/search/CMS backend with no field/operator allowlist or auth.

**Vulnerable conditions**:
- Root or public Query exposes `items(where: ItemFilter)` / `configs(filter: ConfigFilter)` without auth
- Filter input defines `key_contains`, `value_contains`, `name_in`, or similar operator fields on sensitive collections
- Resolver passes client filter object directly to DB/CMS query builder (`prisma.*.findMany({ where: args.where })`, search index, headless CMS filter API)

**Grep seeds**:
```bash
rg -n "input\s+\w*Filter|_contains:|_in:|_gt:|_lt:|_starts_with:|key_contains" --glob '*.{graphql,graphqls}'
rg -n "args\.where|args\.filter|where:\s*args|filter:\s*args" --glob '*.{js,ts,py,java,go,rb,php,cs}'
rg -n "findMany\(\s*\{\s*where|\.filter\(|where\(args" --glob '*.{js,ts,py,java,go,rb,php,cs}' -C2
```

**VULN**:
```graphql
input ConfigFilter { key_contains: String, value_contains: String }
type Query { configs(where: ConfigFilter): [ConfigItem] }
```
```js
resolveConfigs: (_, args) => cms.find({ filter: args.where }),  // no auth; arbitrary operators
```

**SAFE**: auth on collection queries; allowlist filterable fields and operators server-side; separate public vs admin schema; block sensitive keys (e.g. `api_key`, `secret`) from filterable fields. Cross-ref `idor.md`, `information_disclosure.md`.

### Sensitive SDL fields (PII heuristic bundle)

Sensitive scalar field names on public-queryable types (`User`, `Account`, `Customer*`, `Profile`) where the resolver returns an ORM entity mapped 1:1 without field-level auth or public DTO redaction.

**Vulnerable conditions**:
- SDL exposes PII-named fields on types reachable from unauthenticated or under-scoped Query fields
- Resolver returns full DB row / ORM model without `@auth`, shield rule, or projection layer
- Admin-only fields (`role`, `internalNotes`) co-located on same type as public fields

**Grep SDL** (field-name substrings on queryable object types):
```bash
rg -n "email|phone|ssn|dob|vin|routingNumber|accountNumber|deviceId|password|token|apiKey|address|postalCode|secret" --glob '*.{graphql,graphqls}'
rg -n "type\s+(User|Account|Customer|Profile)\b" --glob '*.{graphql,graphqls}'
rg -n "resolve.*return\s+(user|account|customer|profile)|findUnique|findOne|getById" --glob '*.{js,ts,py,java,go,rb,php,cs}' -C2
```

**VULN**:
```graphql
type User { id: ID!, email: String!, phone: String!, ssn: String, apiKey: String }
type Query { user(id: ID!): User }  # no @auth; full ORM map
```

**SAFE**: public DTOs without PII; field-level auth/redaction; separate `PublicUser` vs `AdminUser` types. Cross-ref `information_disclosure.md`, `trust_boundary.md`.

### ORM / DB errors in GraphQL responses

SQLAlchemy, Prisma, TypeORM, JDBC exceptions passed through `formatError` / `format_error` into `errors[].message`.

**VULN**:
```js
formatError: (err) => ({ message: err.originalError?.detail || err.message });
```

**SAFE**: generic production messages; log details server-side. Cross-ref `information_disclosure.md`.

### GET queries logging sensitive variables

GET `/graphql?query=...&variables={"password":"..."}` — variables in URL, referrers, access logs.

**VULN**: GET handler accepts `variables` query param for authenticated operations.

## Authorization

Session/token minting on public GraphQL operations (anonymous session creation, pre-auth token issuance) — see `session_puzzling.md`.

### Gateway-only auth / federation hardening

Authorization enforced only at API gateway or route middleware — subgraphs/resolvers unprotected; `context.user` set once and never re-checked per field.

**Federation / schema-stitching**: `ApolloGateway`, `ApolloRouter`, `stitchSchemas`, or similar gateway must enforce authN/authZ **and** depth/complexity/batch limits at the **gateway engine** — not only on the public HTTP route. Audit federated SDL for sensitive fields exposed via `@key`, `@external`, `@requires`. Assume subgraphs are **directly reachable** without the gateway; each subgraph needs its own auth and introspection guards.

**Vulnerable conditions**:
- Federation subgraph with no `@auth` / shield rules; resolver assumes prior gateway check
- Gateway forwards to subgraph URLs without mTLS or subgraph-side auth
- Depth/complexity limits configured on `/graphql` HTTP handler but not on gateway `ApolloGateway` / router config
- Sensitive entity fields only `@external` on one subgraph but subgraph endpoint is public

**Grep seeds**:
```bash
rg -n "ApolloGateway|ApolloRouter|@apollo/gateway|stitchSchemas|RemoteGraphQLDataSource|subgraph" --glob '*.{js,ts,go}'
rg -n "@key|@external|@requires|@provides|@shareable|federation" --glob '*.{graphql,graphqls,js,ts}'
rg -n "subgraph.*url|serviceList|supergraphSdl|buildSubgraphSchema" --glob '*.{js,ts,go,yml,yaml}'
```

**VULN**: federation subgraph with no `@auth` / shield rules; resolver assumes prior gateway check.

**Mutation-only auth wrapper; queries exported unwrapped**: auth applied via `wrapResolvers`, `applyMiddleware`, `graphql-shield`, custom handler, or `new Proxy` on the **Mutation** resolver map only while **Query** resolvers are registered/exported directly — read paths bypass the auth pipeline.

**Vulnerable conditions**:
- `Mutation: shield(mutationResolvers, rules)` but `Query: queryResolvers` without equivalent wrapping
- Schema builder applies middleware to `rootMutationConfig` only; `rootQueryConfig` omitted
- Federation/subgraph registers auth plugin for mutations path only

**Grep seeds**:
```bash
rg -n "wrapResolvers|applyMiddleware|shield\(|new Proxy" --glob '*.{js,ts}' -C3
rg -n "Mutation:\s*\{|Query:\s*\{|rootMutation|rootQuery" --glob '*.{js,ts,py,java,go,rb}' -C2
rg -n "Mutation.*middleware|Query.*resolvers" --glob '*.{js,ts}' -i
```

**VULN**:
```js
const resolvers = {
  Query: queryResolvers,                    // no auth wrapper
  Mutation: shield(mutationResolvers, rules),
};
```

**SAFE**: single auth pipeline for **all** root types (Query, Mutation, Subscription); per-field rules on sensitive Query fields; never assume gateway-only checks cover reads.

### BFLA on privileged mutations

`deleteAllUsers`, `setRole`, `withdrawal`, `impersonate` mutations without role checks or graphql-shield rule.

**Grep**:
```bash
rg -n "deleteAll|setRole|impersonate|withdraw|admin" --glob '*.{graphql,graphqls,js,ts,py,rb}'
rg -n "graphql-shield|shield\(|fallbackRule|allowExternalErrors" --glob '*.{js,ts}'
```

### Schema directive miswiring

`@auth` / `@hasRole` on some fields but missing on sibling sensitive fields; or directive declared in SDL but transformer not registered (`visitSchemaDirectives`, `mapSchema`, `Directives` config absent).

**Interface-level authorization gap**: sensitive field declared on an `interface` where `@auth` / `@hasRole` is applied on only **some** implementing types (`implements`) — callers resolve via interface and hit unguarded concrete types.

**Vulnerable conditions**:
- `interface Node { secret: String }` with `@auth` on `User implements Node` but not on `Admin implements Node`
- Directive visitor skips interface field definitions; only concrete type fields wrapped

**Grep seeds**:
```bash
rg -n "@auth|@hasRole|@permission" --glob '*.{graphql,graphqls}'
rg -n "visitSchemaDirectives|mapSchema|SchemaDirectiveVisitor|directives:" --glob '*.{js,ts}'
rg -n "interface\s+\w+|implements\s+\w+" --glob '*.{graphql,graphqls}'
rg -n "GraphQLInterfaceType|visitInterfaceType|InterfaceType" --glob '*.{js,ts,py,java,go,rb,cs}'
```

**VULN**:
```graphql
interface Account { balance: Float }
type User implements Account { balance: Float @auth(requires: USER) }
type ServiceAccount implements Account { balance: Float }  # no @auth — reachable via Account
```

**SAFE**: enforce auth on interface field via shared schema transformer; or require directive on every implementing type; test resolution through interface type name.

### Enum sort / order args exposing privileged ordering

GraphQL `order`, `sort`, or `orderBy` enum arguments (e.g. `UserSortEnum` with `ID`, `DATE_JOINED`, `CREATED_AT`) flowing to SQL `ORDER BY` or ORM `.order()` let unprivileged callers sort by privileged columns — surfacing admin/first-created records at list head.

**Vulnerable conditions**:
- Public list query accepts `sort: UserSortEnum` with values mapping to sensitive DB columns
- No role-based restriction on allowed sort enum members
- Default sort is `ID ASC` or `DATE_JOINED ASC` exposing oldest/admin accounts first

**Grep seeds**:
```bash
rg -n "enum\s+\w*(Sort|Order)|orderBy|sortBy|order:" --glob '*.{graphql,graphqls}'
rg -n "ORDER BY|\.order\(|order_by|sort_by" --glob '*.{js,ts,py,java,go,rb,php,cs}' -C2
rg -n "UserSortEnum|SortOrder|OrderDirection" --glob '*.{graphql,graphqls,js,ts,py}'
```

**VULN**:
```python
def resolve_users(root, info, sort=UserSortEnum.ID):
    return User.query.order_by(getattr(User, sort.value)).all()  # ID/DATE_JOINED unscoped
```

**SAFE**: restrict sort fields by role; safe default (e.g. `NAME`); allowlist enum→column mapping server-side.

### graphql-shield fallback

`fallbackRule: allow` or new Query/Mutation fields not in shield map → deny-by-default (`fallbackRule: deny` + explicit rules per field).

### Multi-path authorization inconsistency

Multiple Query fields return the same type with unequal auth — one path guarded (`me { orders }`), sibling not (`user(id) { orders }`).

### JWT handled GraphQL-specifically

Token accepted as GraphQL **argument** (`me(token: String)`) or `context.user = jwt.decode(token)` without signature verification — JWT must come from `Authorization` header and be verified. Cross-ref `authentication_jwt.md`.

### IP allowlist as sole auth

GraphQL route gated only on `X-Forwarded-For` / `X-Real-IP` — spoofable at trust boundary. Cross-ref `privilege_escalation.md`, `trust_boundary.md`.

### Required-arguments-only auth bypass

Authorization depends on **optional** arguments (token, scope, tenant ID passed as optional GraphQL args) or optional-header-derived values — calling the operation with only required (`NonNull`) args reaches the resolver unauthenticated or unscoped.

**Vulnerable conditions**:
- `me(token: String): User` where auth runs only when `args.token` is present
- `orders(tenantId: ID): [Order]` — tenant scoping skipped when `tenantId` omitted
- Context sets `user` from optional arg; resolver proceeds when arg absent

**Grep seeds**:
```bash
rg -n "if\s*\(\s*args\.(token|scope|tenant|auth)|args\.token\s*\?" --glob '*.{js,ts,py,java,go,rb,php,cs}'
rg -n "resolve.*info.*args.*\)\s*\{|@Argument.*required\s*=\s*false" --glob '*.{js,ts,java,kt}' -C3
rg -n "token:\s*String[^!]|tenantId:\s*ID[^!]|scope:\s*String[^!]" --glob '*.{graphql,graphqls}'
```

**VULN**:
```js
resolveMe: (_, args, ctx) => {
  if (args.token) ctx.user = verify(args.token);
  return db.user.find(ctx.user?.id);  // runs with undefined user when token omitted
},
```

**SAFE**: auth must never depend on optional args; default-deny when principal missing; required auth context from validated session/header only.

### Deprecated / stubbed operations still live and unauthenticated

`@deprecated` Query/Mutation fields remain resolvable; stub resolvers (`return { success: false }`, empty arrays) still mounted with no auth guard; "to be removed" operations still in the public schema.

**Vulnerable conditions**:
- SDL marks field `@deprecated` but schema still exposes it on public endpoint
- Stub resolver returns placeholder success/failure without auth check — side channels or partial data may leak
- Router composition includes deprecated ops in production schema bundle

**Grep seeds**:
```bash
rg -n "@deprecated" --glob '*.{graphql,graphqls}'
rg -n "success:\s*false|return\s*\{\s*\}|return\s*\[\s*\]" --glob '*.{js,ts,py,java,go,rb}' -C3
rg -n "deprecated|toBeRemoved|stub.*resolver" --glob '*.{js,ts,py,java}' -i
```

**VULN**:
```graphql
type Mutation {
  legacyExport: ExportResult @deprecated(reason: "use exportV2")
}
```
```js
legacyExport: () => ({ success: false }),  // no auth; still callable, may leak via errors/metadata
```

**SAFE**: remove from public schema; `@inaccessible` (federation) or router composition omit; auth-deny even for stubs; block at gateway validationRules.

### Auth-exempt operation allowlist Sets

Distinct from **Operation-Name Allowlist Bypass** (APQ/persisted-query document enforcement): server-side hardcoded `new Set([...])` / arrays (`csrfExempt`, `skipAuth`, `publicOperations`, `exempt`, `allowlist`) keyed on operation or field name bypass **all** session/CSRF checks — especially dangerous when paired with side-effecting or PII mutations.

**Vulnerable conditions**:
- Middleware checks `PUBLIC_OPS.has(operationName)` or `skipAuth.includes(fieldName)` before resolver
- Exempt set includes mutations (`updateProfile`, `submitForm`) or data-export queries
- Gateway skips auth when operation name matches static allowlist

**Grep seeds**:
```bash
rg -n "new Set\(\[|skipAuth|csrfExempt|publicOperations|exempt|allowlist" --glob '*.{js,ts,py,java,go,rb,php,cs}' -C2
rg -n "operationName.*includes|ALLOWED.*operations|PUBLIC.*mutations" --glob '*.{js,ts,py}' -i
```

**VULN**:
```js
const skipAuth = new Set(['GetPublicConfig', 'UpdateEmail', 'ExportData']);
if (skipAuth.has(req.body.operationName)) return next();  // bypasses session + CSRF
```

**SAFE**: minimize and review exempt set; enforce auth at resolver layer even when gateway skips; never exempt side-effecting or PII operations.

### Soft-fail authorization

Resolver returns `{}`, `null`, or partial empty success when auth fails instead of throwing a forbidden error — masks missing auth, may leak partial data, and creates a `data: null` vs `errors[]` oracle.

**Vulnerable conditions**:
- `if (!ctx.user) return {}` or `return null` on sensitive Query/Mutation
- Partial object returned (some fields populated) when caller lacks scope
- Inconsistent error shape: some fields error, sibling fields return empty object

**Grep seeds**:
```bash
rg -n "if\s*\(\s*!ctx\.(user|auth)|!context\.(user|auth)" --glob '*.{js,ts,py,java,go,rb,php,cs}' -C2
rg -n "return\s*\{\s*\}|return\s+null|return\s+\[\s*\]" --glob '*.{js,ts,py}' -C2
```

**VULN**:
```js
resolveAccount: (_, __, ctx) => {
  if (!ctx.user) return {};  // soft fail — client may probe field presence
  return db.account.find(ctx.user.id);
},
```

**SAFE**: fail closed with explicit auth errors (`GraphQLError`, `ForbiddenError`); consistent error shape; no partial success on auth failure.

### Untrusted header-derived identity in GraphQL context

Context builder trusts client-supplied headers (`X-User-Id`, `X-Forwarded-User`, custom session headers) without cryptographic verification — attacker sets header and impersonates any user ID.

**Vulnerable conditions**:
- `context.user = { id: req.headers['x-user-id'] }` without JWT/session validation
- BFF forwards identity headers from client to subgraph context unchecked
- Reverse proxy user header accepted at application trust boundary

**Grep seeds**:
```bash
rg -n "X-User-Id|X-Forwarded-User|x-user-id|forwarded-user|headers\['x-" --glob '*.{js,ts,py,java,go,rb,php,cs}' -i
rg -n "context\.user\s*=|ctx\.user\s*=.*headers|req\.headers" --glob '*.{js,ts,py}' -C2
```

**VULN**:
```js
context: ({ req }) => ({ user: { id: req.headers['x-user-id'] } }),
```

**SAFE**: derive identity only from validated tokens/sessions; verify signatures; cross-ref `trust_boundary.md`, `authentication_jwt.md`.

## Request Forgery (GET / CSRF)

GraphQL endpoints that accept **mutations over GET** (`?query=mutation{deleteUser...}`) or via **simple** bodies enable cross-site state change. Extend beyond basic GET:

**Vulnerable conditions**:
- GET accepts **`variables`** (not just `query`) — sensitive data and mutations via `<img src>`
- **State-changing operations on Query type** (mutation semantics on `Query` fields) — see Side effects in Query resolvers below
- **`text/plain` POST** accepted (preflightless) in addition to `application/x-www-form-urlencoded`
- Apollo `csrfPrevention: false` on cookie-authenticated endpoint
- CSRF enforced on POST but **not GET** when GET still executes operations
- Missing requirement for `Content-Type: application/json` + CSRF token / custom header

**Grep seeds**:
```bash
rg -n "methods.*GET|app\.get\s*\(\s*['\"].*graphql|router\.get.*graphql" --glob '*.{js,ts,py,go,java,scala}'
rg -n "req\.query\.(query|variables)|request\.args\.get\(['\"]variables" --glob '*.{js,ts,py}'
rg -n "csrfPrevention|csrf|text/plain|urlencoded" --glob '*.{js,ts}'
rg -n "mutation.*GET|GET.*mutation|graphqlHTTP.*GET" --glob '*.{js,ts,py}'
# Sangria (Scala)
rg -n "Sangria|sangria\.|GraphQLRoute|getOnly|supportedQueryMethods|allowGet" --glob '*.{scala,sbt}'
```

**VULN**:
```js
app.get('/graphql', (req, res) => {
  graphql({ schema, source: req.query.query, variableValues: JSON.parse(req.query.variables) });
});
```

**SAFE**: mutations on `POST` only with `Content-Type: application/json`; CSRF token or custom header for cookie sessions. Cross-ref `csrf.md`.

### Sangria (Scala) GET mutations

Sangria-backed routes may accept mutations over **GET** when GET is enabled for queries — PII and tokens in URL query strings, proxy/access logs, and Referer leakage.

**Vulnerable conditions**:
- `supportedQueryMethods` / route config allows GET for all operations including mutations
- No explicit POST+JSON-only policy for state-changing operations

**VULN**:
```scala
// GET enabled for GraphQL route — mutations reachable via ?query=mutation{...}
GET / graphql ? query = mutation { updateEmail(email: "x") { ok } }
```

**SAFE**: disable GET for mutations; POST + `Content-Type: application/json` only; reject mutation operations on GET at route layer.

### Side effects in read (Query) resolvers

Root **Query** resolver performs writes, external API calls with side effects, or state changes — executed even on minimal `{ __typename }` selection; bypasses mutation CSRF/POST-only policies.

**Vulnerable conditions**:
- Query field calls `db.update`, `sendEmail`, `chargePayment`, cache invalidation, audit log write
- Read resolver triggers outbound webhook or increments counter
- Auth check runs after side effect or only when sensitive subfields requested

**Grep seeds**:
```bash
rg -n "Query:\s*\{|resolveQuery|@QueryMapping" --glob '*.{js,ts,py,java,go,rb,php,cs}' -C5
rg -n "\.update\(|\.create\(|\.delete\(|sendEmail|fetch\(.*method.*POST" --glob '*.{js,ts,py,java,go,rb,php,cs}' -C3
```

**VULN**:
```js
resolveTrackView: (_, args) => {
  db.views.increment(args.id);  // write on Query
  return db.item.find(args.id);
},
```

**SAFE**: no side effects in read resolvers; auth before any state change; put state changes in Mutation type; idempotent reads only.

## Alternate GraphQL Mount Paths

Hardening (introspection disable, auth middleware, CSRF, depth/complexity limits, IDE guards) applied to primary `/graphql` but **not** to alternate registrations — `/gql`, `/query`, `/console`, `/v1/graphql`, `/v2/graphql`, `/playground`, BFF proxy paths, or framework default secondary mounts.

**Vulnerable conditions**:
- `app.use('/graphql', hardenedHandler)` and `app.use('/gql', bareGraphqlHTTP({ schema }))` on same schema
- Versioned routes `/v1/graphql` vs `/v2/graphql` with inconsistent `validationRules` or auth
- Playground/console route shares schema but skips middleware stack

**Grep seeds**:
```bash
rg -n "['\"]/(graphql|gql|query|console|v1/graphql|v2/graphql|playground)['\"]" --glob '*.{js,ts,py,go,java,rb,php,cs,scala}'
rg -n "GraphQLModule\.forRoot|mercurius|graphqlHTTP|ApolloServer|createYoga" --glob '*.{js,ts,py,java}' -C3
rg -n "path:\s*['\"]/(gql|graphql)" --glob '*.{js,ts,yml,yaml}'
```

**VULN**:
```js
app.use('/graphql', auth, depthLimit, graphqlHTTP({ schema }));
app.use('/gql', graphqlHTTP({ schema }));  // same schema, no auth/limits
```

**SAFE**: single middleware stack for all GraphQL HTTP mounts; register one canonical path in prod; audit route table for duplicate handlers.

## Cross-Site WebSocket Hijacking / Transport Parity

**Subscriptions over WebSocket** without Origin validation (or naive substring Origin check) — cross-ref `websocket_security.md`.

**Queries and mutations over WebSocket**: `graphql-ws` and similar transports may accept **non-subscription** operations (queries, mutations) over the same WebSocket connection — not only subscriptions. These operations must receive the **same** `validationRules` (introspection disable, depth/complexity), auth/context, and CSRF-equivalent connection checks as HTTP POST.

**Introspection / auth parity**: introspection disabled on HTTP but still reachable via WS:
```json
{"type":"start","payload":{"query":"{ __schema { types { name } } }"}}
```

Mutations over WS when HTTP restricts mutations to POST:
```json
{"type":"start","payload":{"query":"mutation { deleteUser(id: \"1\") { ok } }"}}
```

Enforce introspection disable, depth/complexity limits, and authorization at the **engine** level across **all transports** (HTTP GET/POST, WS queries/mutations/subscriptions, multipart) — not per-route middleware on HTTP only.

**Grep**:
```bash
rg -n "subscription|graphql-ws|subscriptions-transport-ws|onConnect|origin|useServer" --glob '*.{js,ts}'
rg -n "disableIntrospection|introspection:\s*false|validationRules" --glob '*.{js,ts}'  # verify WS path uses same config
rg -n "onSubscribe|onOperation|message\.type.*subscribe|executeOperation" --glob '*.{js,ts}'
```

## Operation-Name Allowlist Bypass

Persisted-query or operation allowlists that gate execution on `req.body.operationName` (or a similar label) **without hashing or canonicalizing the full document** let attackers supply a permitted name while the `query` string contains a different or additional operation.

**Vulnerable conditions**:
- Server checks `operationName === 'GetUser'` then executes `req.body.query` verbatim with no document hash / registry lookup
- Allowlist keyed on client-supplied `operationName` while document text is unconstrained
- Multi-operation documents: first operation allowed by name, second malicious operation still parsed and run

### APQ / persisted queries enabled but not enforced

Automatic Persisted Queries (`persistedQueries`, `AutomaticPersistedQueries`, `documentId` / `extensions.persistedQuery.sha256Hash`) may be **enabled** for cache efficiency while the server still executes arbitrary ad-hoc `query` bodies when no registered hash is supplied — APQ is optional, not enforced.

**Vulnerable conditions**:
- `persistedQueries: { cache: new Map() }` or APQ plugin registered but full `req.body.query` still parsed and executed when hash missing or unknown
- Production accepts both persisted hash **and** raw document text with no persisted-queries-only mode
- Hash lookup miss falls through to `parse(req.body.query)` instead of reject

**Grep seeds** (extends operation-name seeds):
```bash
rg -n "operationName|operation_name" --glob '*.{js,ts,py,go,java}' -C3
rg -n "allowedOperations|persistedQuery|APQ|documentId|persistedQueries|AutomaticPersistedQueries|sha256Hash" --glob '*.{js,ts,py}'
rg -n "persistedQueriesOnly|requirePersistedQueries|allowOnlyPersisted|reject.*ad.?hoc" --glob '*.{js,ts,py}'
```

**VULN**:
```js
// APQ enabled but ad-hoc queries still accepted
plugins: [ApolloServerPluginCacheControl(), persistedQueriesPlugin],
// handler: if (!hashMatch) still execute(parse(req.body.query))
if (ALLOWED.includes(req.body.operationName)) {
  return execute({ schema, document: parse(req.body.query) });  // query body not verified against name/hash
}
```

**SAFE**: persisted-queries-only or strict allowlist in production; reject unregistered documents and unknown hashes; map operation ID → server-side stored document hash; disallow multi-operation documents unless every operation is allowlisted. Cross-ref operation-name allowlist bypass above.

## GraphQL Structural DoS (Cross-Reference)

GraphQL structural DoS — missing depth/complexity/cost limits, alias/batch/directive/field-duplication overloading, circular SDL types and fragments, unbounded pagination, execution timeouts, N+1 amplification — is covered in **`graphql_dos.md`**. Do not duplicate those checks here; cross-ref when resolver or schema review touches cyclic types or batch config.

## ReDoS via Resolver Regex

GraphQL arguments (`args['q']`, `args.filter`, `args.pattern`) passed into server-side regex (`re.search`, `RegExp`, `Pattern.compile`, `.match()`) without length caps or safe-regex validation enable ReDoS — a single query can stall the event loop or worker thread. On public GraphQL search fields this also acts as a **DoS amplifier** — cross-ref `graphql_dos.md` and `regex_injection_redos.md`.

**Vulnerable conditions**:
- Resolver: `re.search(args['q'], row.title)` where `q` is attacker-controlled and pattern is nested-quantifier prone
- User-supplied pattern string compiled server-side: `new RegExp(args.pattern)`
- Filter/search resolvers building dynamic regex from GraphQL variables

**Grep seeds**:
```bash
rg -n "resolve.*args|args\['|args\." --glob '*.{js,ts,py}' -A2 | rg -n "re\.(search|match|compile)|RegExp|Pattern\.compile|\.matches\("
rg -n "new RegExp\(args|Pattern\.compile\(.*args" --glob '*.{js,ts,java,py}'
```

**VULN**:
```js
resolveSearch: (_, args) => db.rows.filter(r => new RegExp(args.q).test(r.name));
```

**SAFE**: literal/substring match, precompiled static patterns, RE2-style engines, input length limits, timeout guards.

## Verbose Error Disclosure

GraphQL error formatters that serialize **exception stacks** into the response (`extensions.exception.stacktrace`, `extensions.stack`, full Java/Python tracebacks) or honor client **`debug=1` / `?debug=true`** flags leak internal paths, library versions, and resolver logic — aiding further attacks.

**Vulnerable conditions**:
- Custom `formatError` / `GraphQLError` handler appends `err.stack` or `originalError.stack` to JSON extensions
- `debug: true`, `includeStacktraceInErrorResponses: true`, or env-un guarded stack traces in production Apollo/Yoga/Graphene config
- `GRAPHQL_DEBUG=1` or query param enabling traceback in HTTP 200 error payloads

**Grep seeds**:
```bash
rg -n "formatError|format_error|includeStacktrace|stacktrace|\.stack" --glob '*.{js,ts,py,java}'
rg -n "debug:\s*true|DEBUG.*graphql|extensions\.exception" --glob '*.{js,ts,py}'
```

**VULN**:
```js
formatError: (err) => ({
  message: err.message,
  extensions: { exception: { stacktrace: err.stack.split('\n') } },
});
```

**SAFE**: production `debug: false`; generic client messages; log stacks server-side only; strip `extensions.exception` in production formatters. Cross-ref `information_disclosure.md`.

## TRUE POSITIVE Criteria

- User-controlled data reaches string assembly of a GraphQL operation document (concat, template literal, format) before `execute` or downstream HTTP forward.
- A resolver concatenates GraphQL arguments directly into a raw database query string (or NoSQL/RCE/SSRF/XSS/upload sink).
- Introspection, field suggestions, tracing/cost extensions, static SDL/docs routes, engine-fingerprint errors, or GraphiQL active in production without server-side environment guard (client-only IDE gates insufficient).
- Partial introspection disable (WAF substring) while `__type`/`__typename` still disclose schema.
- Sensitive fields (`password`, `apiKey`, PII heuristic names) exposed on queryable types without field auth; collection/list filter operators allow targeted exfiltration without auth.
- The `/graphql` endpoint is reachable without authentication **or** authorization is gateway-only with unprotected resolvers/subgraphs; federation gateway lacks depth/complexity/auth parity; Mutation-only auth wrapper leaves Query unwrapped.
- Optional-arg-only auth (`token`/`tenantId` optional) lets required-args-only calls reach resolver unscoped; deprecated/stub operations callable without auth; auth-exempt `Set`/`skipAuth` bypasses session checks; soft-fail `return {}`/`null` on auth miss.
- Context built from unverified headers (`X-User-Id`, `X-Forwarded-User`) without token validation.
- Alternate GraphQL mount paths (`/gql`, `/v1/graphql`, `/playground`) lack same hardening as primary route.
- Mutations executable via GET (incl. Sangria), GET+variables, form-urlencoded, `text/plain`, or WebSocket without CSRF/auth parity; Query resolvers perform writes/side effects.
- Operation allowlist checks `operationName` only; APQ enabled but ad-hoc `query` bodies still execute; document not hash-verified against registry.
- Client `operationName` concatenated into SQL/logs unsanitized.
- `@auth` in SDL but directive visitor not registered; auth on some `implements` types but not all for same interface field; graphql-shield `fallbackRule: allow`.
- Enum `sort`/`order` args map to privileged DB columns without role restriction.
- Custom scalar pass-through coercion or directive handler template/eval with user-controlled args reaches sink.
- JWT accepted as GraphQL arg or decoded without verification.
- WS subscriptions without Origin check; queries/mutations over WS lack same validationRules/auth/introspection as HTTP.
- Resolver passes GraphQL args into `RegExp` / `re.compile` / `Pattern.compile` on attacker-controlled input.
- Error formatter exposes stack traces, ORM details, or engine-fingerprint keys in `errors[]` / extensions.
- Missing depth/complexity/batch limits → cross-ref **`graphql_dos.md`** (tag `graphql_dos` when reporting DoS class).

## FALSE POSITIVE Criteria

- Static operation document with user data only in `variables` / `variableValues` — not document injection (still check resolver authz and sinks).
- The resolver uses parameterized queries: `db.execute("SELECT * FROM users WHERE id = ?", [args['id']])`.
- Introspection disabled via engine config; suggestions disabled; depth/complexity limits enforced — see `graphql_dos.md`.
- Authentication middleware applied before GraphQL handler **and** per-resolver/per-field authorization verified.
- Persisted-query or operation-ID allowlist with enforced hash/registry; ad-hoc documents rejected in production; document text never assembled from user strings.
- GraphQL `String` type alone does not justify closing a finding when taint reaches a sink — verify sink handling.

---

## Python Source Detection Rules

### graphene / strawberry
- **VULN (document injection)**:
  ```python
  def run_custom_query(user_gql: str):
      document = f"query {{ user {{ {user_gql} }} }}"
      return graphql_sync(schema, document)
  ```
- **SAFE (document)**: static document string; user data only in `variable_values` dict passed to `execute`
- **VULN (SQL in resolver)**:
  ```python
  def resolve_user(root, info, id):
      return db.execute(f"SELECT * FROM users WHERE id = {id}").fetchone()
  ```
- **VULN**: `db.execute("SELECT * FROM users WHERE name = '" + args['name'] + "'")` in any resolver
- **SAFE**: `db.execute("SELECT * FROM users WHERE id = %s", (id,))` — parameterized
- **SAFE**: SQLAlchemy ORM: `User.query.filter_by(id=id).first()`

### Flask-GraphQL introspection
- **VULN**: `GraphQLView.as_view('graphql', schema=schema)` with no introspection guard
- **VULN**: `graphene.Schema(query=Query)` served at `/graphql` with no auth decorator
- **NOT sufficient for introspection**: `GraphQLView.as_view('graphql', schema=schema, graphiql=False)` hides the GraphiQL IDE only; introspection remains enabled unless explicitly disabled via `introspection=False` or validation rules blocking `__schema`/`__type`

### Depth / complexity / batch DoS
- See **`graphql_dos.md`** — `depth_limit_validator`, `query_complexity_limit`, `batch=True` caps.

---

## JavaScript Source Detection Rules

### graphql-js / Apollo Server
- **VULN (document injection — downstream proxy)**:
  ```js
  app.post('/proxy', async (req, res) => {
    const query = `query { me { ${req.body.fragment} } }`;
    await fetch('https://api.internal/graphql', {
      method: 'POST',
      body: JSON.stringify({ query }),
    });
  });
  ```
- **SAFE (document)**: static operation string; user data only in `variables` when forwarding
- **VULN (SQL in resolver)**:
  ```js
  resolve: (parent, args) => db.query(`SELECT * FROM users WHERE id = ${args.id}`)
  ```
- **VULN**: Template literal or string concatenation in any resolver's database call
- **SAFE**: `db.query('SELECT * FROM users WHERE id = $1', [args.id])` — pg parameterized

### Introspection in production
- **VULN**: `new ApolloServer({ schema })` with no `introspection: false` for production
- **VULN**: Apollo Server v2: no `playground: false` for production
- **SAFE**: `introspection: process.env.NODE_ENV === 'development'`

### Depth / complexity / batching DoS
- See **`graphql_dos.md`** — `depthLimit`, `createComplexityLimitRule`, `maxBatchSize`.

### GET mutations / CSRF / errors
- **VULN**: `app.get('/graphql', …)` or router accepting mutations/variables from query string
- **VULN**: `csrfPrevention: false` with cookie auth
- **VULN**: `includeStacktraceInErrorResponses: true` or custom `formatError` emitting `err.stack`
- **VULN**: Allowlist on `operationName` only — `parse(req.body.query)` not matched to registry hash
- **SAFE**: POST-only mutations; `csrfPrevention: true`; production `debug: false`; document hash verification

### Unauthenticated endpoint
- **VULN**: `app.use('/graphql', graphqlHTTP({ schema }))` — no auth middleware before graphqlHTTP
- **SAFE**: `app.use('/graphql', authenticate, graphqlHTTP({ schema }))`

---

## PHP Source Detection Rules

### Webonyx / graphql-php
- **VULN (document injection)**:
  ```php
  $fields = $_POST['fields'];
  $query = "query { user { {$fields} } }";
  GraphQL::executeQuery($schema, $query);
  ```
- **SAFE (document)**: fixed query string; `$variableValues` array for dynamic args
- **VULN (SQL in resolver)**:
  ```php
  'resolve' => function($root, $args) use ($db) {
      return $db->query("SELECT * FROM users WHERE id = " . $args['id']);
  }
  ```
- **VULN**: String concatenation or interpolation of GraphQL args into raw SQL queries
- **SAFE**: PDO prepared statements: `$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$args['id']])`

### Introspection
- **VULN**: `$server = new StandardServer(['schema' => $schema])` with introspection not disabled in production
- **SAFE**: Check for environment-based introspection toggle

### Unauthenticated endpoint
- **VULN**: `/graphql` route handler with no session or token authentication check before processing the query

---

## Go Source Detection Rules

### gqlgen
- **VULN (document injection — BFF/client)**:
  ```go
  query := fmt.Sprintf("query { user { %s } }", r.FormValue("fields"))
  resp, _ := http.Post(apiURL, "application/json",
      bytes.NewBuffer([]byte(`{"query":"`+query+`"}`)))
  ```
- **SAFE (document)**: compile-time constant query string; `variables` map for user input
- **Introspection / depth**: see grep seeds in Information Disclosure and `graphql_dos.md` (`extension.Introspection`, `FixedComplexityLimit`).

---

## GraphQL Vulnerable Code Patterns (SAST Detection)

```python
# VULNERABLE: GraphQL query string built from user input (injection)
@app.route('/graphql', methods=['POST'])
def graphql_endpoint():
    query = request.json.get('query')
    result = schema.execute(query)   # user-controlled query executed directly — introspection + injection
    return jsonify(result.data)

# VULNERABLE: no depth/complexity limiting — see graphql_dos.md
schema = graphene.Schema(query=Query)
```

```js
// VULNERABLE: GraphQL with introspection enabled in production
const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: true,
    playground: true
});

// VULNERABLE: no query complexity/depth limit — graphql_dos.md
const server = new ApolloServer({ typeDefs, resolvers });
```

```java
// VULNERABLE: GraphQL resolver with unsanitized variable used in SQL
@QueryMapping
public List<User> users(@Argument String filter) {
    return em.createQuery("SELECT u FROM User u WHERE u.name = '" + filter + "'").getResultList();
}
```

### GraphQL-Specific Vulnerability Classes

1. **GraphQL document injection** — user input alters operation string text
2. **Resolver sink injection** — args/variables/directives/Upload → SQL/NoSQL/RCE/SSRF/XSS/file upload
3. **Operation-name injection** — unsanitized `operationName` in logs/SQL
4. **Introspection / information disclosure** — schema, suggestions, tracing/cost extensions, GraphiQL, static SDL/docs, filter-operator exfiltration, sensitive SDL/PII heuristics, engine-fingerprint errors, ORM errors, GET variable logging
5. **Authorization gaps** — gateway/federation (incl. Mutation-only wrapping), BFLA, miswired directives (incl. interface), shield fallback, enum sort exposure, JWT-as-arg, IP allowlist, optional-arg auth bypass, deprecated/stub ops, auth-exempt Sets, soft-fail returns, header-derived context, alternate mount paths
6. **Request forgery** — GET/variables (incl. Sangria), Query-type side effects/mutations, text/plain POST, CSRF gaps
7. **WebSocket transport parity** — CSWSH; queries/mutations/subscriptions over WS share HTTP validationRules/auth
8. **Operation-name allowlist bypass / APQ not enforced** — label or hash optional; ad-hoc documents still run
9. **Custom scalar / directive handler gaps** — pass-through coercion; template/eval directive handlers
10. **ReDoS in resolver** — GraphQL arg → server-side regex
11. **Structural DoS** — `graphql_dos.md` (depth, complexity, alias, batch, pagination, timeouts, N+1)

### GraphQL TRUE POSITIVE Rules

- User-controlled data concatenated into GraphQL operation document before `execute` → **CONFIRM** (`graphql_injection`)
- Resolver string concatenation with GraphQL arg in SQL/NoSQL/shell/HTTP → **CONFIRM** (`graphql_injection` + sink skill)
- `introspection: true` / field suggestions / tracing / cost extensions in production → **CONFIRM** (`graphql_injection` + `information_disclosure`)
- Static SDL or schema docs route without auth in production → **CONFIRM** (`graphql_injection` + `information_disclosure`)
- APQ/persistedQueries enabled but ad-hoc query bodies still execute → **CONFIRM** (`graphql_injection`)
- Alternate mount path (`/gql`, `/v1/graphql`) missing auth/limits → **CONFIRM** (`graphql_injection`)
- Interface field `@auth` missing on some implementing types → **CONFIRM** (`graphql_injection` + `idor` / `privilege_escalation.md`)
- Enum sort/order exposing privileged ORDER BY → **CONFIRM** (`graphql_injection` + `information_disclosure`)
- Public collection Query with rich filter operators (`key_contains`, `_in`) forwarded to backend without auth/allowlist → **CONFIRM** (`graphql_injection` + `information_disclosure` / `idor`)
- PII-named SDL fields on public types with 1:1 ORM mapping → **CONFIRM** (`graphql_injection` + `information_disclosure`)
- Optional-arg auth bypass; deprecated/stub ops unauthenticated; auth-exempt operation Set; soft-fail `return {}` → **CONFIRM** (`graphql_injection` + `idor` / `privilege_escalation.md`)
- Mutation-only auth wrapper; Query resolvers unwrapped → **CONFIRM** (`graphql_injection` + `privilege_escalation.md`)
- Header-derived context identity without verification → **CONFIRM** (`graphql_injection` + `trust_boundary.md`)
- Query resolver side effects (writes, external state change) → **CONFIRM** (`graphql_injection` + `csrf.md` as applicable)
- Custom scalar pass-through or directive template handler → **CONFIRM** (`graphql_injection` + sink skill as applicable)
- Sangria or other GET mutations → **CONFIRM** (`graphql_injection` + `csrf.md`)
- Queries/mutations over WS without HTTP parity → **CONFIRM** (`graphql_injection` + `websocket_security.md`)
- No depth limit + no complexity limit on public endpoint → **CONFIRM** (`graphql_dos` — see `graphql_dos.md`)
- GraphQL resolver accessing object by ID without ownership check → **CONFIRM** (`graphql_injection` + `idor`)
- Mutations over GET/GET+variables or form/text/plain without CSRF → **CONFIRM** (`graphql_injection` + `csrf.md`)
- `operationName` allowlist without document hash → **CONFIRM** (`graphql_injection`)
- `operationName` in SQL/logs unsanitized → **CONFIRM** (`graphql_injection`)
- Resolver regex on GraphQL args → **CONFIRM** (`graphql_injection` + `regex_injection_redos.md`; DoS note in `graphql_dos.md`)
- Stack traces / ORM text in GraphQL errors → **CONFIRM** (`graphql_injection` + `information_disclosure.md`)
- Unbounded batch / alias / cyclic schema DoS → **CONFIRM** (`graphql_dos`)

### GraphQL FALSE POSITIVE Rules

- Static operation document; user input only in `variables` — **NOT document injection** (still audit resolver sinks)
- Persisted-query allowlist with enforced hash/registry; ad-hoc documents rejected — **NOT document injection**
- Introspection disabled AND depth/complexity limits enforced — lower disclosure/DoS risk
- Parameterized resolver with verified field-level auth — **NOT injection**

### Tag Convention

- **Default tag**: `graphql_injection` — document injection, resolver sinks, authz, CSRF, disclosure
- **DoS tag**: `graphql_dos` — depth/complexity/alias/batch/pagination/timeout/N+1 (see `graphql_dos.md`)
- **Short form**: `graphql` — use only when benchmark ground truth (`xben/`) expects short form
- Emit both tags when a finding spans classes (e.g. `graphql_injection` + `sql_injection`)

## Cross-References

- `graphql_dos.md` — structural denial of service (depth, complexity, batching, pagination, timeouts)
- `sql_injection.md`, `nosql_injection.md`, `rce.md`, `ssrf.md`, `xss.md`, `arbitrary_file_upload.md` — resolver sink classes
- `csrf.md` — GET/form/text/plain request forgery
- `websocket_security.md` — subscription Origin, queries/mutations over WS transport parity
- `authentication_jwt.md` — JWT verification (not GraphQL args)
- `privilege_escalation.md`, `trust_boundary.md`, `idor.md` — authorization
- `session_puzzling.md` — session/token minting on public GraphQL operations
- `information_disclosure.md`, `regex_injection_redos.md`, `denial_of_service.md` — related generic classes
