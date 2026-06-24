---
name: graphql_injection
description: Detect GraphQL security issues including document injection, resolver-layer taint to SQL/NoSQL/RCE/SSRF/XSS sinks, schema-level input validation (weak/over-permissive argument typing, custom-scalar coercion, missing semantic validation), introspection and information disclosure, authorization gaps, CSRF/request forgery, WebSocket transport parity, and operation-name injection — structural DoS covered in graphql_dos.md.
---

# GraphQL Security Issues

GraphQL APIs present a distinct attack surface that differs significantly from REST. The primary risk categories are:

1. **GraphQL document injection** — user input embedded into the operation string (query/mutation text), not only the `variables` map.
2. **Resolver taint** — every argument surface (field args, directives, variables map, input objects, JSON scalars, Upload) reaching injection sinks without sanitization.
3. **Introspection / information disclosure** — schema leakage, field suggestions / error-oracle schema reconstruction (field/type stuffing), union/interface `__typename` + inline-fragment enumeration, input-object field-name guessing, partial introspection disable, tracing/cost extensions, GraphiQL in prod (incl. client-only IDE gates), static SDL/docs routes, collection/list filter-operator exfiltration, sensitive SDL/PII field heuristics, engine-fingerprint errors, ORM errors in responses, GET variable logging.
4. **Authorization gaps** — gateway-only auth (incl. federation/stitching, Mutation-only resolver wrapping), BFLA on privileged mutations, mutation return-type field over-exposure (read vs mutation-return auth divergence), miswired `@auth` directives (incl. interface vs implementing types), graphql-shield allow-by-default (incl. contextual rule-cache warming), multi-path inconsistency (incl. Relay `node(id:)` alternate path), nested/relationship-traversal auth (root-only checks, unchecked nested resolvers pivoting to other users' data), null-coercion auth bypass, enum sort/order exposure, JWT-as-argument, IP allowlist as sole gate, optional-arg auth bypass, deprecated/stub operations unauthenticated, auth-exempt operation Sets, soft-fail auth returns, header-derived identity in context.
5. **Request forgery** — GET mutations (incl. Sangria), form-urlencoded/`text/plain` POST, CSRF on cookie-auth endpoints, side effects / state-changing operations on Query type.
6. **WebSocket transport parity** — subscriptions without Origin check; queries/mutations/subscriptions over WS must share HTTP validationRules/auth/introspection config.
7. **Operation-name injection** — client-controlled `operationName` persisted to logs/SQL unsanitized (distinct from allowlist bypass).
8. **Operation-name allowlist bypass / APQ not enforced** — enforcement keyed on `operationName` without document hashing; operation-name enumeration/fuzzing when execution or error responses differ for known vs unknown names; or `persistedQueries`/`AutomaticPersistedQueries` enabled but ad-hoc `query` bodies still execute; or sensitive operations/fields gated by a deny-list/WAF string-match on query text, bypassable via alias, operation rename, or whitespace.
9. **Unauthenticated GraphQL endpoint / alternate mount paths** — no auth middleware on `/graphql`; hardening applied only to primary route while `/gql`, `/v1/graphql`, `/playground`, etc. remain exposed; dev/staging/test mounts with weaker config than production.
10. **Custom scalar / directive handler gaps & weak input typing** — pass-through scalar coercion; directive handlers executing string templates with user-controlled args; over-permissive argument typing (`String`/`ID`/`JSON` where enum/validated-scalar/input-type fits) and missing semantic validation that push input validation downstream.
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
| **Built-in directive args** | User-controlled `@include(if: $flag)` / `@skip(if: $flag)` boolean variables and custom directive arguments — attacker-influenced inputs at validation/execution (see Custom Directive Handlers; do not duplicate that section). Client-supplied `@include`/`@skip` let the caller toggle which fields resolve at will: dangerous when **authorization or side-effects are wrongly assumed to follow the static/expected query shape** (e.g. a field guarded only by "it's not in our official client's query"), and they create **response-differential oracles** (flip `if:` true/false to confirm a field/branch exists). Real injection lives in *custom* directive argument handlers; built-ins are an authz/exfiltration-shaping surface |
| **`variables` map** | `info.variableValues`, `context.variables` — taint at resolver, not document-safe |
| **Input object fields** | `CreateUserInput { email, profile { bio } }` — **deeply nested** input-object subfields are taint sources reaching injection sinks (IDOR variant when nested IDs select other users' records — cross-ref `idor.md`). **Nested-input injection bypass**: validation/sanitization or key-allowlists that only inspect **top-level** input keys miss payloads buried in nested objects, lists of inputs, and list-of-list inputs (`filter: { OR: [{ name_contains: "<inj>" }] }`, `items: [{ meta: { q: "<inj>" } }]`). Resolvers that spread/merge the whole nested input into an ORM/NoSQL filter (`Object.assign`, `**input`, `prisma.findMany({ where: input })`) let deep keys reach the sink unchecked — validate recursively and allowlist keys at every level |
| **Custom scalars** | `JSON`, `JSONObject`, `AWSJSON` — opaque structured taint; `Email`, `IPAddress`, `UUID`, `DateTime` via `graphql-scalars` or `GraphQLScalarType` with weak `parse_value`/`parse_literal`/`serialize` |
| **`Upload` scalar** | Filename and file content in multipart requests |
| **Non-standard transport params** | Custom query-string/form params read by middleware or transport glue **outside** the standard `query`/`variables`/`operationName` (e.g. a connection/session pragma the handler concatenates into SQL such as `SET SESSION ...`) — same detection as resolver SQLi (`sql_injection.md`), but the taint enters at the transport layer, not a typed arg |

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

## Schema-Level Input Validation (weak typing pushes validation downstream)

The **schema is the first input-validation boundary**: a strict type rejects malformed input before any resolver runs (syntactic validation, for free). Over-permissive typing defeats this and forces validation into resolvers, where it is frequently forgotten — so loosely typed args are a high-signal place to look for injection/IDOR/DoS.

**Vulnerable conditions (weak typing / missing validation)**:
- Arguments typed as `String`, `ID`, or catch-all `JSON`/`JSONObject`/`AWSJSON` where a **narrow type fits** — an `enum` for a fixed set (status, role, sort key), a validated custom scalar (`EmailAddress`, `URL`, `UUID`, `PositiveInt`), or a defined **input object type** for a mutation instead of many loose scalar args. Loose typing means the only validation is whatever the resolver remembers to do.
- Numeric/string/list args with **no bounds**: `Int`/`Float` without min/max range, `String` without max length, list args without size cap (list size also crosses into DoS — see `graphql_dos.md`).
- **Syntactic-only validation**: relying on schema types alone and skipping **semantic** validation in the resolver (business-context rules: `startDate < endDate`, quantity within stock, value in allowed range, cross-field consistency). Schema typing cannot express these.
- Mutation accepts a free-form `JSON`/map input that the resolver spreads into an ORM/CMS/filter (`where: input`, `Object.assign`, `**input`) without a per-field allowlist (see also Input object fields / nested-input injection above).

**SAST signals**:
```bash
# loose argument/scalar typing in the SDL
rg -n ":\s*(String|ID|JSON|JSONObject|AWSJSON)\b" --glob '*.{graphql,graphqls}'
# mutations taking many scalar args instead of a defined Input type
rg -n "type Mutation|input \w+Input" --glob '*.{graphql,graphqls}' -C1
# resolver consuming args with no validate/parse/check between arg and sink
rg -n "args\.(input|filter|where|data)\b" --glob '*.{js,ts,py,go,rb}' -C2
```

**VULN**:
```graphql
# status/role should be enums; amount has no range; free-form JSON bypasses typing
type Mutation { updateOrder(id: ID!, status: String!, meta: JSON): Order }
```
```js
// resolver does no semantic validation; status & meta reach the DB unchecked
updateOrder: (_, { id, status, meta }) =>
  db.orders.update(id, { status, ...meta })   // status not allowlisted; meta spreads arbitrary keys
```

**SAFE**:
```graphql
enum OrderStatus { PENDING PAID SHIPPED CANCELLED }
input UpdateOrderInput { status: OrderStatus!, note: String }   # narrow types = syntactic validation
type Mutation { updateOrder(id: ID!, input: UpdateOrderInput!): Order }
```
```js
// schema already rejected bad status/extra keys; resolver adds SEMANTIC validation + authz
updateOrder: (_, { id, input }, ctx) => {
  if (input.note && input.note.length > 500) throw new GraphQLError('note too long');
  assertCanEdit(ctx.user, id);                       // semantic/business rule, not expressible in schema
  return db.orders.update(id, { status: input.status, note: input.note });
}
```

General input-validation principles apply (allowlist over denylist; anchored, length-bounded, ReDoS-safe regex; canonicalize *before* validating; server-side is authoritative; validation is defense-in-depth, **not** the primary control for injection/XSS — see `regex_injection_redos.md`, `sql_injection.md`, `xss.md`, `arbitrary_file_upload.md`, and reject invalid input without leaking internals per `information_disclosure.md`).

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

**Edit-distance mechanics (why a wordlist works)**: the suggestion engine (graphql-js `suggestionList`, graphene's `did_you_mean`) compares the invalid name to every real name using **Damerau-Levenshtein lexical distance** and emits a suggestion only when distance ≤ a threshold of roughly `floor(len(input)/2) + 1` (case-insensitive, capped at ~5 suggestions). Consequences an attacker exploits: (a) a near-miss guess (`secretFiel`, `Secre7Field`) reveals the real name; (b) names **≤2-3 chars** (`id`, `me`, `pk`) are below the threshold and never suggested, so they require **exact-match brute force** rather than fuzzy probing; (c) feeding a long candidate widens the threshold, surfacing more matches per request. The same algorithm leaks type, argument, and input-field names (see below).

**Field/type stuffing — schema reconstruction via error oracle (introspection OFF)**: even with `introspection: false`, suggestion text on invalid fields/types leaks schema structure. An attacker seeds a **wordlist** of common field/type names, parses `Cannot query field 'X' on type 'Y'. Did you mean 'Z'?`, probes subfields recursively, and **brute-forces short names** (`id`, `pk`, `me`, `key`) too short for suggestions — reconstructing full SDL with zero introspection queries. **Type stuffing**: guess type names (e.g. `Admin`, `Config`, `Internal`, `Debug`, `Service`, `System`) via `Cannot query ... on type` / `Unknown type` oracles.

**Wordlist sourcing (target-specific beats generic)**: high-hit-rate candidates come from (1) **client-side artifacts** — extract every GraphQL name with the spec regex `[_A-Za-z][_0-9A-Za-z]*` from JS/TS bundles, source maps, mobile app static files, and persisted-query manifests; (2) **observed traffic** — names seen in any legitimate query/response, plus `operationName` values; (3) **prior schemas / public dictionaries** for the same framework (Relay adds `node`/`nodes`/`edges`/`pageInfo`/`__typename`; common admin/debug names). Recursion: each recovered object field's type becomes the next probe root, so a small seed expands into the full graph. Detection note for SAST: the *server-side* enabler is suggestions/oracle errors being reachable in prod — the wordlist is the attacker's input, not a code signal.

**Argument stuffing**: the validation error `Unknown argument "X" on field "Y" of type "Z". Did you mean "W"?` enumerates resolver **argument names** (e.g. discovering a hidden `asAdmin`, `internal`, `includeDeleted`, `debug`, or `tenantId` arg on an otherwise-known field) even with introspection disabled — a discovered argument is then a new auth/IDOR/injection probe surface. **Non-null structure oracle**: `Cannot return null for non-nullable field A.B` confirms a field exists, its parent type, and that it is `NonNull` — leaking schema shape from ordinary execution responses without any suggestion text. **Type-kind oracle**: the execution errors `Field "x" must not have a selection since type "String" has no subfields` (field is a leaf — scalar/enum) vs `Field "x" of type "Foo" must have a selection of subfields. Did you mean "x { ... }"?` (field is an object/abstract type, and the error even names the return type `Foo`) let an attacker classify every recovered field as leaf-vs-object and read its return type — reconstructing the full **type graph** (output usable by schema-visualizer/exporter tooling), not just field names, with introspection fully disabled.

**Vulnerable conditions**:
- Introspection disabled but validation errors still include `Did you mean` suggestions
- No `hideSchemaDetailsFromClientErrors` / custom `formatError` / `customFormatErrorFn` stripping suggestion text
- Short common field names reachable only via direct probe (no suggestion hint)

**Grep seeds**:
```bash
rg -n "did_you_mean|DidYouMean|suggestionList|MAX_LENGTH|hideSchemaDetailsFromClientErrors|customFormatErrorFn" --glob '*.{js,ts,py}'
rg -n "Did you mean|Cannot query field|Unknown type|Unknown argument|Cannot return null for non-nullable|must have a selection of subfields|must not have a selection" --glob '*.{js,ts,py}' -C1
```

**VULN**: introspection off but suggestions on in production; disabling introspection alone is insufficient.

**SAFE**: disable field suggestions in production — Apollo `hideSchemaDetailsFromClientErrors: true`, or custom `formatError` / `customFormatErrorFn` stripping `Did you mean`; `graphene` `did_you_mean.MAX_LENGTH = 0` or equivalent.

### Union / Interface `__typename` introspection bypass

When `__schema` / `__type` introspection is blocked, **abstract types** still leak via selection and inline fragments — selecting `__typename` and using **inline fragments** (`... on TypeName { field }`) enumerates union members, interface implementing types, and their fields without introspection queries.

**Vulnerable conditions**:
- Production relies on introspection-disable as the sole schema-secrecy control
- Union/interface types expose member fields reachable without field-level auth
- Error oracles on invalid inline fragment type names reveal implementing type names

**Grep seeds**:
```bash
rg -n "__typename|\.\.\.\s*on\s+\w+" --glob '*.{graphql,graphqls,js,ts}'
rg -n "GraphQLUnionType|GraphQLInterfaceType|resolveType|__resolveType" --glob '*.{js,ts,py,java,go,rb,cs}'
rg -n "introspection.*false|disableIntrospection" --glob '*.{js,ts,py}' -C2
```

**VULN**:
```graphql
{ searchResult { __typename ... on AdminUser { role secretKey } ... on User { email } } }
```

**SAFE**: do not rely on introspection-disable as a control; field-level authz on every member type; consider limiting abstract-type exposure. Cross-ref `information_disclosure.md`.

### Input object polymorphism / unknown input field enumeration

Validation errors on input objects name valid fields — `Field "x" is not defined by type "YInput". Did you mean "z"?` — enabling input field-name guessing and schema mapping. Unexpected/extra input fields may also be used as injection probes when resolvers merge unknown keys into backend queries.

**Vulnerable conditions**:
- Input validation errors echo valid-field hints or `Did you mean` for unknown input keys
- Resolver spreads `args.input` / mutation input object into ORM/CMS filter without key allowlist
- Custom input types expose operator suffix fields discoverable via typo/oracle probing

**Grep seeds**:
```bash
rg -n "is not defined by type|Did you mean|Unknown field|input.*Did you mean" --glob '*.{js,ts,py,java}'
rg -n "input\s+\w+Input|Create\w+Input|Update\w+Input" --glob '*.{graphql,graphqls}'
rg -n "\.\.\.args\.|Object\.assign\(.*args\.input|spread.*input" --glob '*.{js,ts,py}' -C2
```

**VULN**:
```graphql
mutation { updateProfile(input: { emial: "x" }) { ok } }
# error: Field "emial" is not defined by type "UpdateProfileInput". Did you mean "email"?
```

**SAFE**: strip suggestion text from input validation errors; strict input validation with generic messages; do not echo valid-field hints; allowlist input keys server-side.

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

**ORM error signatures to grep for in responses/tests** (their presence in `errors[].message` or `extensions` confirms leakage and often fingerprints the DB + reveals table/column names → aids SQLi/IDOR mapping): Prisma `PrismaClientKnownRequestError` / `Invalid \`prisma.user.findUnique()\`` / codes `P2002`,`P2025`; Sequelize `SequelizeDatabaseError` / `SequelizeUniqueConstraintError`; TypeORM `QueryFailedError`; SQLAlchemy `sqlalchemy.exc.*` / `psycopg2.errors.*`; Django `ProgrammingError` / `IntegrityError` with `column "x" does not exist`; Hibernate `org.hibernate.exception.*` / `SQLGrammarException`; raw driver text `ER_DUP_ENTRY`, `ORA-`, `SQLSTATE[`, `duplicate key value violates unique constraint`. Treat any of these reaching the client as both information disclosure and a strong SQLi-surface signal (cross-ref `sql_injection.md`).

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

### Mutation return-type field over-exposure (read vs mutation-return auth divergence)

A mutation's **return payload** is a read channel. When field-level authorization is enforced on the **Query** path but not re-checked on the objects/fields returned by a **Mutation** resolver, the response to a permitted write leaks data the caller could not read directly. Two shapes: (a) the mutation return type exposes nested/related objects and sensitive scalars (`updateProfile` returns `User { ssn apiKey orders { ... } }`) that query-side `@auth`/shield/projection would have stripped; (b) a data path/object is **reachable only via a mutation return** and is exposed for a role that no Query field exposes it to — an unguarded read surface that read-path review misses entirely.

**Vulnerable conditions**:
- Mutation resolver returns the full ORM entity / nested graph while the equivalent Query field applies field-level auth, projection, or a public DTO
- `@auth` / `graphql-shield` / projection wired on `Query` (and root `Mutation` fields) but **not** on the **return object types' fields**, so post-write field resolution is unguarded
- Mutation return type includes related collections (`{ ...; allUsers { email } }`, `{ ...; auditLog { ... } }`) not gated for the caller's role
- A field/object appears in a mutation payload for a role but is absent from every query that role can run (read surface exclusive to the mutation path)

**Grep seeds**:
```bash
# mutation resolvers returning entities/nested graphs; compare auth wiring to the read path
rg -n "Mutation:\s*\{|@MutationMapping|type Mutation" --glob '*.{js,ts,py,java,go,rb,graphql,graphqls}' -C2
rg -n "return\s+(user|account|order|customer|entity)\b|return\s+await\s+\w+\.(save|update|create)\(" --glob '*.{js,ts,py,java,go,rb}' -C2
# mutation return types exposing sensitive/related fields in SDL
rg -n "type\s+\w*Payload|): \w+(Payload|Result)\b" --glob '*.{graphql,graphqls}' -C2
```

**VULN**:
```js
// Query path strips sensitive fields; mutation returns the raw entity unfiltered
Query: { me: (_, __, ctx) => projectPublic(db.user.find(ctx.user.id)) },     // safe DTO
Mutation: {
  updateProfile: async (_, { input }, ctx) =>
    db.user.update(ctx.user.id, input),   // returns User { ssn apiKey role ... } — no projection/field auth on return type
},
```

**SAFE**: apply the **same** field-level authorization/projection to mutation return types as to query reads — enforce auth on the return object's field resolvers (not just the root mutation), return narrow `*Payload` types instead of raw ORM entities, and verify no field/object is reachable via a mutation payload that the caller could not read via a query. Cross-ref `idor.md`, `information_disclosure.md`, `privilege_escalation.md`.

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

Same data reachable via **multiple GraphQL paths** with unequal auth — guarded path vs unguarded sibling.

**Vulnerable conditions**:
- `me { orders }` scoped to session user but `user(id: ID!) { orders }` omits ownership check
- **Relay global object identification** — `node(id:)` / `nodes(ids:)` reaches objects without checks placed only on typed queries (e.g. auth on `user(id:)` but not on generic `node` resolver — CVE-2025-31481 class)
- **Alias / fragment / inline-fragment** paths defeat naive field-name path checks (`admin: user(id: 1) { role }`, `... on Admin { secret }`)
- **graphql-shield rule cache warming** — `cache: 'contextual'` shared across a batched document lets an early self-owned fetch warm the cache so sibling fields for other objects pass; use `cache: 'strict'` to re-eval per `(parent, args, context)`

**Grep seeds**:
```bash
rg -n "me\s*\{|user\s*\(\s*id:|node\s*\(\s*id:|nodes\s*\(\s*ids:" --glob '*.{graphql,graphqls,js,ts,py,java}'
rg -n "globalId|fromGlobalId|toGlobalId|Relay|Node\s*interface|resolveNode|nodeResolver" --glob '*.{js,ts,graphql,graphqls}'
rg -n "cache:\s*['\"]contextual['\"]|shield\(|graphql-shield" --glob '*.{js,ts}' -C2
rg -n "parent\.id\s*===|ctx\.user\.id|context\.user\.id" --glob '*.{js,ts,py,java,go,rb}' -C2
```

**VULN**:
```js
// Typed query guarded; node resolver unchecked
Query: { user: (_, { id }, ctx) => requireOwner(id, ctx) },
Node: { __resolveType: () => 'User' },
node: (_, { id }) => db.findByGlobalId(id),  // no auth — same object as user(id:)
```
```js
shield({ Query: { orders: rule() } }, { cache: 'contextual' }); // batch warms cache across users
```

**SAFE**: enforce authz in **every** resolver including `node` / `nodes` / interface field resolvers; ownership via `parent.id === ctx.user.id`; graphql-shield `cache: 'strict'`; test alias and fragment paths. Cross-ref `idor.md` (Relay `node(id:)` alternate-path bypass, e.g. CVE-2025-31481).

### Nested / relationship-traversal authorization (root-only auth, unchecked nested resolvers)

The defining GraphQL BOLA: authorization is enforced (or implicitly satisfied) **only at the root field**, and the nested resolvers reached by **walking object relationships** run unchecked — on the false assumption that "you had to go through an authorized object to get here." Every resolver is independent and executes with the **graph position**, not the caller's permissions; a relation that resolves for display (e.g. `Post.author` for a byline) becomes a pivot into that author's private fields. Because the entry point is **public or low-privilege**, this is easy to miss in review that only checks top-level queries.

**Vulnerable conditions**:
- A **public / low-priv root** (e.g. `publicPost(id:)`, `search`, `feed`) exposes a relation to a **sensitive type**, and that type's field/object resolvers don't re-authorize: `publicPost(id:123){ author { email draftPosts{body} linkedPaymentMethod{ last4 } } }` returns another user's private data even though `me{ email }` is locked down.
- **Bidirectional relationship pivoting**: `Post → author → posts → author …` (or `User → orders → user`) lets you loop back into *arbitrary* other users' objects from one public node — the relationship edges form an unbounded BOLA traversal graph (also a DoS shape — see `graphql_dos.md`).
- **Field-level sensitivity ignored**: object-level access to the parent is treated as access to *all* its scalars (`email`, `phone`, `ssn`, `apiKey`, tokens) and child collections (`draftPosts`, `messages`, `paymentMethods`) with no per-field/per-object owner-or-role check.
- Sensitive types reachable through **union/interface fragments** that the normal typed path would not surface (see Union / Interface `__typename` introspection bypass).

**Recon**: use introspection (or field-suggestion/error-oracle recovery when it is disabled — see Field suggestions) to map which **sensitive types are reachable from public entry points**, then probe each relation hop for missing authz.

**Grep seeds**:
```bash
# nested resolvers on related/sensitive types returning private fields with no ctx/owner check
rg -n "(author|owner|user|account|customer|profile)\s*:\s*(async\s*)?\(.*parent" --glob '*.{js,ts}' -C2
rg -n "(email|phone|ssn|apiKey|token|secret|paymentMethod|draft|message)s?\s*:\s*(async\s*)?\(.*parent" --glob '*.{js,ts}' -C2
# resolver maps where only Query.* has guards but type resolvers (User/Post/...) do not
rg -n "type Query|Query:\s*\{|User:\s*\{|Post:\s*\{" --glob '*.{js,ts}' -C1
rg -n "parent\.userId|parent\.ownerId|ctx\.user\.id|context\.user" --glob '*.{js,ts,py,java,go,rb}' -C1
```

**VULN**:
```js
// Root is public; nested resolvers trust the parent and never check the caller
Query: { publicPost: (_, { id }) => db.posts.find(id) },           // public on purpose
Post:  { author: (post) => db.users.find(post.authorId) },         // resolves for the byline
User:  {
  email:             (u) => u.email,                               // no owner/role check
  draftPosts:        (u) => db.posts.where({ authorId: u.id, published: false }),
  linkedPaymentMethod:(u) => db.payments.forUser(u.id),            // cross-user private data
}
```

**SAFE**:
```js
// Authorize at EVERY resolver against the caller, not the graph position
User: {
  email: (u, _a, ctx) => (ctx.user?.id === u.id || isAdmin(ctx)) ? u.email : null,
  draftPosts: (u, _a, ctx) => {
    if (ctx.user?.id !== u.id) throw new GraphQLError('forbidden');   // owner-only
    return db.posts.where({ authorId: u.id, published: false });
  },
  linkedPaymentMethod: (u, _a, ctx) => {
    if (ctx.user?.id !== u.id) throw new GraphQLError('forbidden');
    return db.payments.forUser(u.id);
  },
}
// Prefer field-level @auth directives / shield rules / projection that apply on the
// NESTED type regardless of entry path; mark sensitive fields owner/role-scoped centrally.
```

Detection rule: a relation from a public/low-priv root to a type carrying private scalars or child collections, where the **nested type's resolvers contain no `ctx.user`/owner/role check**, is a CONFIRMED nested-authz BOLA — not informational. Cross-ref `idor.md` and `information_disclosure.md`.

### Null coercion authorization bypass

A resolver branches on an argument being **`null`/absent vs present** and takes a **different code path** that skips scoping/auth — e.g. `if (!args.filter) return allRecords`; `if (args.userId == null) useSessionUser() else trustArg`. Explicit **`null` vs default-value** divergence (graphql-spec argument coercion ambiguity, CWE-863): client sends `"userId": null` vs omitting the key may hit different resolver branches.

**Vulnerable conditions**:
- Optional filter/scope args — null/absent widens result set to all records
- `userId` / `tenantId` optional — `null` falls back to session but non-null trusts client-supplied ID without ownership check
- Default argument in SDL differs from explicit `null` in variables map

**Grep seeds**:
```bash
rg -n "args\.\w+\s*==\s*null|args\.\w+\s*===\s*null|!\s*args\.(filter|userId|tenant)" --glob '*.{js,ts,py,java,go,rb,php,cs}' -C2
rg -n "if\s*\(\s*!args\.|userId:\s*ID[^!]|filter:\s*\w+[^!]" --glob '*.{graphql,graphqls,js,ts,py}'
rg -n "return\s+.*\.findAll|return\s+.*\.all\(\)|findMany\(\s*\{\s*\}\)" --glob '*.{js,ts,py,java}' -C3
```

**VULN**:
```js
resolveOrders: (_, args, ctx) => {
  if (!args.filter) return db.orders.findAll();  // null/absent → all records
  return db.orders.find({ userId: args.filter.userId });
},
```

**SAFE**: default-deny regardless of null/absent args; derive scope from verified principal only; never widen results when an arg is null; treat explicit `null` and omission consistently. Cross-ref `idor.md`, `business_logic.md`.

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

#### Zombie / orphaned types & fields (unmarked legacy still resolvable)

Distinct from `@deprecated` (explicitly marked): a **zombie object** is a type/field whose resolver is still mounted and reachable but is no longer referenced by any active operation/client — orphaned schema left behind by refactors. Because it is unmarked, depth/field allowlists and review skip it, yet it is fully callable and frequently unmaintained/unpatched (old validation, old auth assumptions, legacy column names). Reachable via introspection or field-suggestion recovery even when "current" docs omit it.

**Vulnerable conditions**:
- Schema `type`/`field` defined and wired to a resolver but unreferenced anywhere in client queries/fragments or gateway allowlist
- Old module/feature flag still imported into schema build (`makeExecutableSchema`/`buildSubgraphSchema` merges a stale typeDefs file)
- Resolver delegates to a deprecated internal service path or pre-refactor DB accessor with weaker checks
- Federation subgraph still publishes a removed type that the supergraph re-exposes

**Grep seeds**:
```bash
# types/fields wired to resolvers; cross-check against operations/allowlist for unreferenced ones
rg -n "type\s+\w+|extend type" --glob '*.{graphql,graphqls}'
rg -n "typeDefs|makeExecutableSchema|buildSubgraphSchema|mergeTypeDefs" --glob '*.{js,ts}' -C3
rg -n "legacy|_old|V1\b|deprecatedSchema|orphan" --glob '*.{js,ts,py,java,go,rb}' -i
```

**SAFE**: delete unused types/fields and their resolvers (don't just hide); diff schema against client operation/allowlist coverage in CI and fail on unreferenced reachable fields; `@inaccessible`/router exclusion for federation; treat orphaned resolvers as live attack surface requiring the same auth/validation as current code.

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

### Multipart `Upload` scalar abuse (GraphQL multipart request spec)

Stacks that implement the GraphQL **multipart request specification** to support file uploads expose a `multipart/form-data` transport with `operations` + `map` form fields and an `Upload` scalar. This transport is a **simple request** (no CORS preflight), so it reintroduces CSRF on endpoints that otherwise accept only JSON, and the multipart parser adds upload-specific abuse beyond ordinary file-type validation.

**Vulnerable conditions**:
- **CSRF via multipart**: upload mutations (`uploadAvatar`, `createMediaItem`, `import*`) accept `multipart/form-data` from cookie-authenticated browsers with no CSRF token / custom-header / `application/json` requirement — state change cross-origin without preflight, even when the rest of the API claims JSON-only
- **Upload variable reuse → double read**: the same `Upload` variable referenced from multiple resolver arguments in one operation (`map` points one file part at several variable paths) while the backend assumes single-use — re-reading an exhausted stream causes double reads, premature stream exhaustion, partial writes, or unbounded server-side buffering
- **Orphan / excess parts**: parser buffers every received file part to disk/RAM **before** checking whether it is referenced in `map` — unreferenced or oversized extra parts drive disk/memory exhaustion (DoS)
- No `Upload` size/count cap, content-type/magic-byte validation, or single-use enforcement per variable

**Grep seeds**:
```bash
rg -n "scalar Upload|GraphQLUpload|graphql-upload|graphqlUploadExpress|ProcessRequestOptions|FileUpload" --glob '*.{js,ts,py,go,java,graphql,graphqls}'
rg -n "createReadStream|\.promise\b|processRequest|maxFiles|maxFileSize|map\b" --glob '*.{js,ts}' -C2
# upload mutations that may accept multipart cross-origin
rg -n "upload[A-Z]\w*|createMediaItem|import[A-Z]\w*|attachment|avatar" --glob '*.{js,ts,py,go,java,graphql,graphqls}' -i
```

**VULN**:
```graphql
# one file part mapped to two args; backend reads the stream twice
mutation($f: Upload!){ a: uploadAvatar(file:$f){id} b: uploadAvatar(file:$f){id} }
```

**SAFE**: require `application/json` + CSRF token / custom header (or a dedicated authenticated upload route) — never let multipart bypass CSRF on cookie auth; enforce `maxFiles`, per-file `maxFileSize`, and reject parts not referenced in `map`; treat each `Upload` variable as single-use; validate content type/magic bytes and store outside executable paths. Cross-ref `csrf.md`, `arbitrary_file_upload.md`, and `graphql_dos.md` (orphan-part memory/disk exhaustion).

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

### Non-production environment exploitation

Dev/staging/test GraphQL endpoints (`/graphql-dev`, `/staging/graphql`, `/test`, `/beta`, versioned `/v1/graphql` on non-prod hosts) often ship with **weaker config** than production — introspection/IDE/debug enabled, no depth/cost limits, relaxed auth/CORS — while exposing the same schema and data.

**Vulnerable conditions**:
- Staging mount registered without auth middleware or with `introspection: true` / `playground: true`
- Non-prod routes reachable from public internet (no VPN/IP allowlist)
- Prod hardening checklist not applied to `/graphql-dev`, `/api/test/graphql`, or env-specific subdomains

**Grep seeds**:
```bash
rg -n "graphql-dev|staging.*graphql|/test.*graphql|/beta|NODE_ENV.*development" --glob '*.{js,ts,py,go,java,yml,yaml,env*}'
rg -n "playground:\s*true|introspection:\s*true|graphiql:\s*true" --glob '*.{js,ts,py}' -C3
rg -n "['\"]/(v1|v2|dev|staging|test)/graphql['\"]" --glob '*.{js,ts,py,go,java}'
```

**VULN**:
```js
if (process.env.NODE_ENV !== 'production') {
  app.use('/graphql-dev', graphqlHTTP({ schema, graphiql: true })); // public, no auth
}
```

**SAFE**: same hardening baseline across all environments; never expose non-prod endpoints publicly; disable or firewall dev/staging GraphQL mounts. Cross-ref `trust_boundary.md`.

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

### Operation name enumeration

Fuzzing `operationName` to discover registered/allowlisted operations when **execution or error responses differ** for known vs unknown names — bypassing an operation allowlist by guessing valid names before pairing with a malicious document body.

**Vulnerable conditions**:
- Distinct HTTP status, error message, or partial `data` when `operationName` matches a registered op vs unknown string
- Allowlist checked before parse — oracle leaks valid operation names from validation/error text
- Metrics or logs expose registered operation name list

**Grep seeds**:
```bash
rg -n "operationName|operation_name|registeredOperations|knownOperations" --glob '*.{js,ts,py,go,java}' -C3
rg -n "unknown operation|OperationNotFound|invalid operationName|ALLOWED.*includes" --glob '*.{js,ts,py}' -i
```

**VULN**:
```js
if (!REGISTERED.has(req.body.operationName)) {
  throw new Error(`Unknown operation: ${req.body.operationName}`); // 404 vs 200 oracle
}
```

**SAFE**: persisted-queries by **document hash** (not name alone); uniform errors for unknown operations; no distinguishable response shape for invalid names.

Persisted-query or operation allowlists that gate execution on `req.body.operationName` (or a similar label) **without hashing or canonicalizing the full document** let attackers supply a permitted name while the `query` string contains a different or additional operation.

**Vulnerable conditions**:
- Server checks `operationName === 'GetUser'` then executes `req.body.query` verbatim with no document hash / registry lookup
- Allowlist keyed on client-supplied `operationName` while document text is unconstrained
- Multi-operation documents: first operation allowed by name, second malicious operation still parsed and run

### Operation/field deny-list bypass via alias, rename, or whitespace

Sensitive operations/fields gated by a **deny-list or WAF rule that string-matches the raw query text or operation name** (rather than enforcing per-resolver auth) are bypassable because GraphQL treats aliases, operation names, and insignificant whitespace/commas as cosmetic. Generalizes the `__schema` substring case (see Partial introspection disable) to any blocked operation/field.

**Bypass variants** (all reach the same resolver):
- **Operation rename** — denylist matches a specific operation name; resubmit under a different name (`query random { restrictedOp }`)
- **Alias** — denylist matches a field name; alias it (`query { ok: restrictedOp }`)
- **Whitespace/comma/newline** — denylist regex anchored to `field(` or `field {`; insert ignored tokens (`restrictedOp ,{`, newline before brace)
- **Allowed-name reuse** — naive *allowlist* keyed on operation name; supply a permitted name with a different body (`query getPublicData { restrictedOp }`)

**Vulnerable conditions**:
- Middleware/gateway/WAF blocks operations by `req.body.query.includes("restrictedOp")` / regex on raw document, or by `DENY.has(operationName)`
- Authorization/feature-gating decided from operation or field **name strings** instead of the resolved field + caller identity
- Field-level block list compares against selection name but resolver runs regardless of alias

**Grep seeds**:
```bash
rg -n "DENY|denylist|blocklist|blacklist|forbidden(Ops|Operations|Fields)" --glob '*.{js,ts,py,go,java,cs,rb}' -i
rg -n "query\.(includes|match|indexOf|test)\(|req\.body\.query.*(includes|regex|match)" --glob '*.{js,ts}' -i
rg -n "operationName.*(===|==|includes|in )\s*['\"]" --glob '*.{js,ts,py}'
```

**VULN**:
```js
// denylist on raw text — bypassed by alias `ok: restrictedOp` or operation rename
if (/\brestrictedOp\b/.test(req.body.query)) return res.status(403).end();
```

**SAFE**: enforce authorization in the resolver against the resolved field + caller identity (not on query text or operation name); use persisted-queries by document hash; never rely on substring/regex denylists or name allowlists as the access-control boundary.

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
- **Engine debug-mode flags left on in prod**: GraphQL Yoga `maskedErrors: false`; Hot Chocolate (.NET) `IncludeExceptionDetails = true`; Sangria `exceptionHandler` exposing messages; Strawberry/Ariadne `debug=True`; `graphql-go` returning raw resolver errors
- **graphene-django `DjangoDebugMiddleware`**: registering it exposes a special `_debug` field — `{ _debug { sql { rawSql duration } exceptions { message stack } } }` returns **executed SQL and exception stacks** to the client. It is gated by Django `DEBUG=True`, so a prod deploy with `DEBUG` accidentally on (or the middleware always registered) leaks the full query log and schema relationships

**Debug-mode detection (probe shapes)**: a `_debug`/`__debug` field resolving rather than erroring; `extensions.tracing`/`extensions.exception` present on a deliberately malformed query; verbose errors that flip to generic when a `?debug`/`X-Debug` toggle is removed.

**Grep seeds**:
```bash
rg -n "formatError|format_error|includeStacktrace|stacktrace|\.stack" --glob '*.{js,ts,py,java}'
rg -n "debug:\s*true|DEBUG.*graphql|extensions\.exception|maskedErrors:\s*false|IncludeExceptionDetails" --glob '*.{js,ts,py,cs}'
rg -n "DjangoDebugMiddleware|graphene_django\.debug|_debug\s*\{|rawSql" --glob '*.{py,graphql,gql}'
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
- Introspection, field suggestions / error-oracle schema reconstruction (field/type stuffing), union/interface `__typename` enumeration, input-object field-name guessing, tracing/cost extensions, static SDL/docs routes, engine-fingerprint errors, or GraphiQL active in production without server-side environment guard (client-only IDE gates insufficient).
- Partial introspection disable (WAF substring) while `__type`/`__typename` or inline fragments on unions/interfaces still disclose schema.
- Sensitive fields (`password`, `apiKey`, PII heuristic names) exposed on queryable types without field auth; collection/list filter operators allow targeted exfiltration without auth.
- The `/graphql` endpoint is reachable without authentication **or** authorization is gateway-only with unprotected resolvers/subgraphs; federation gateway lacks depth/complexity/auth parity; Mutation-only auth wrapper leaves Query unwrapped; multi-path inconsistency (`me` vs `user(id:)`, Relay `node(id:)` unchecked, graphql-shield contextual cache warming); null-coercion widens scope when args null/absent.
- Optional-arg-only auth (`token`/`tenantId` optional) lets required-args-only calls reach resolver unscoped; deprecated/stub operations callable without auth; auth-exempt `Set`/`skipAuth` bypasses session checks; soft-fail `return {}`/`null` on auth miss.
- Context built from unverified headers (`X-User-Id`, `X-Forwarded-User`) without token validation.
- Alternate GraphQL mount paths (`/gql`, `/v1/graphql`, `/playground`, `/graphql-dev`, staging/test) lack same hardening as primary route.
- Mutations executable via GET (incl. Sangria), GET+variables, form-urlencoded, `text/plain`, or WebSocket without CSRF/auth parity; Query resolvers perform writes/side effects.
- Operation allowlist checks `operationName` only; operation-name enumeration oracle; APQ enabled but ad-hoc `query` bodies still execute; document not hash-verified against registry.
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
- Introspection disabled via engine config; suggestions disabled (`hideSchemaDetailsFromClientErrors` or equivalent); depth/complexity limits enforced — see `graphql_dos.md`.
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
4. **Introspection / information disclosure** — schema, suggestions/error-oracle reconstruction, union/interface `__typename` enumeration, input-object field guessing, tracing/cost extensions, GraphiQL, static SDL/docs, filter-operator exfiltration, sensitive SDL/PII heuristics, engine-fingerprint errors, ORM errors, GET variable logging
5. **Authorization gaps** — gateway/federation (incl. Mutation-only wrapping), BFLA, mutation return-type over-exposure, miswired directives (incl. interface), shield fallback (incl. contextual cache), multi-path (`node(id:)`), null-coercion bypass, enum sort exposure, JWT-as-arg, IP allowlist, optional-arg auth bypass, deprecated/stub ops, auth-exempt Sets, soft-fail returns, header-derived context, alternate/non-prod mount paths
6. **Request forgery** — GET/variables (incl. Sangria), Query-type side effects/mutations, text/plain POST, CSRF gaps
7. **WebSocket transport parity** — CSWSH; queries/mutations/subscriptions over WS share HTTP validationRules/auth
8. **Operation-name allowlist bypass / APQ not enforced / operation-name enumeration** — label or hash optional; ad-hoc documents still run; response oracle leaks registered names
9. **Custom scalar / directive handler gaps** — pass-through coercion; template/eval directive handlers
10. **ReDoS in resolver** — GraphQL arg → server-side regex
11. **Structural DoS** — `graphql_dos.md` (depth, complexity, alias, batch, pagination, timeouts, N+1)

### GraphQL TRUE POSITIVE Rules

- User-controlled data concatenated into GraphQL operation document before `execute` → **CONFIRM** (`graphql_injection`)
- Resolver string concatenation with GraphQL arg in SQL/NoSQL/shell/HTTP → **CONFIRM** (`graphql_injection` + sink skill)
- `introspection: true` / field suggestions / error-oracle schema reconstruction / input-object field hints / tracing / cost extensions in production → **CONFIRM** (`graphql_injection` + `information_disclosure`)
- Union/interface inline-fragment enumeration with introspection disabled → **CONFIRM** (`graphql_injection` + `information_disclosure`)
- Static SDL or schema docs route without auth in production → **CONFIRM** (`graphql_injection` + `information_disclosure`)
- APQ/persistedQueries enabled but ad-hoc query bodies still execute → **CONFIRM** (`graphql_injection`)
- Alternate mount path (`/gql`, `/v1/graphql`, `/graphql-dev`, staging) missing auth/limits → **CONFIRM** (`graphql_injection`)
- Relay `node(id:)` / `nodes(ids:)` reaches objects without auth on typed-query path → **CONFIRM** (`graphql_injection` + `idor`; e.g. CVE-2025-31481)
- Null-coercion auth bypass (`null`/absent args widen scope) → **CONFIRM** (`graphql_injection` + `idor` / `business_logic.md`)
- graphql-shield `cache: 'contextual'` batch cache warming across objects → **CONFIRM** (`graphql_injection` + `idor`)
- Interface field `@auth` missing on some implementing types → **CONFIRM** (`graphql_injection` + `idor` / `privilege_escalation.md`)
- Enum sort/order exposing privileged ORDER BY → **CONFIRM** (`graphql_injection` + `information_disclosure`)
- Public collection Query with rich filter operators (`key_contains`, `_in`) forwarded to backend without auth/allowlist → **CONFIRM** (`graphql_injection` + `information_disclosure` / `idor`)
- PII-named SDL fields on public types with 1:1 ORM mapping → **CONFIRM** (`graphql_injection` + `information_disclosure`)
- Optional-arg auth bypass; deprecated/stub ops unauthenticated; auth-exempt operation Set; soft-fail `return {}` → **CONFIRM** (`graphql_injection` + `idor` / `privilege_escalation.md`)
- Mutation-only auth wrapper; Query resolvers unwrapped → **CONFIRM** (`graphql_injection` + `privilege_escalation.md`)
- Mutation return type exposes sensitive/nested fields not re-authorized on the read path, or a field/object reachable only via a mutation payload → **CONFIRM** (`graphql_injection` + `idor` / `information_disclosure.md`)
- `Unknown argument` error oracle enumerates hidden resolver argument names (introspection off) → **CONFIRM** (`graphql_injection` + `information_disclosure`)
- Header-derived context identity without verification → **CONFIRM** (`graphql_injection` + `trust_boundary.md`)
- Query resolver side effects (writes, external state change) → **CONFIRM** (`graphql_injection` + `csrf.md` as applicable)
- Custom scalar pass-through or directive template handler → **CONFIRM** (`graphql_injection` + sink skill as applicable)
- Sangria or other GET mutations → **CONFIRM** (`graphql_injection` + `csrf.md`)
- Queries/mutations over WS without HTTP parity → **CONFIRM** (`graphql_injection` + `websocket_security.md`)
- No depth limit + no complexity limit on public endpoint → **CONFIRM** (`graphql_dos` — see `graphql_dos.md`)
- GraphQL resolver accessing object by ID without ownership check → **CONFIRM** (`graphql_injection` + `idor`)
- Mutations over GET/GET+variables or form/text/plain without CSRF → **CONFIRM** (`graphql_injection` + `csrf.md`)
- `operationName` allowlist without document hash → **CONFIRM** (`graphql_injection`)
- Operation-name enumeration oracle (distinct response for unknown vs registered name) → **CONFIRM** (`graphql_injection`)
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
- `information_disclosure.md`, `regex_injection_redos.md`, `denial_of_service.md`, `business_logic.md`, `cve_patterns.md` — related generic classes
