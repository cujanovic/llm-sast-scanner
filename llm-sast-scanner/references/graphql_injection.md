---
name: graphql_injection
description: Detect GraphQL security issues including document injection, introspection exposure, SQL injection in resolvers, missing depth/complexity limits, and unauthenticated endpoints.
---

# GraphQL Security Issues

GraphQL APIs present a distinct attack surface that differs significantly from REST. The primary risk categories are:

1. **GraphQL document injection** — user input embedded into the operation string (query/mutation text), not only the `variables` map.
2. **Introspection enabled in production** — exposes the complete schema to any caller.
3. **Injection in resolvers** — GraphQL arguments passed into SQL/NoSQL queries without parameterization.
4. **No query complexity/depth limits** — opens the door to DoS through deeply nested or batched queries.
5. **Unauthenticated GraphQL endpoint** — no auth middleware guarding the `/graphql` route.

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

### What GraphQL Injection is NOT

- **SQL injection in resolvers** — resolver builds SQL from `args`; classify as SQL injection, not document injection
- **NoSQL / command injection in resolvers** — same; use the appropriate resolver-layer skill
- **IDOR via GraphQL arguments** — static document with another user's ID in `variables` JSON is authorization, not document injection
- **Normal variable binding** — static document with `{"query": "query($id: ID!) { user(id: $id) { name } }", "variables": {"id": userInput}}`; structure is fixed (still verify authorization in resolvers)
- **Introspection / field suggestion enabled** — information disclosure; only document injection if user input alters the operation **string**
- **Query depth / complexity DoS** — separate class (rate limiting / cost analysis)

### Recon Indicators

**GraphQL surface** (dependencies, schema, routes):
- Libraries: `graphql`, `@apollo/server`, `apollo-server-express`, `@nestjs/graphql`, `graphql-yoga`, `mercurius`, `strawberry-graphql`, `graphene`, `gqlgen`, `graphql-ruby`, Hot Chocolate
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

**Depth / alias / batch DoS (when no complexity limits)**
```graphql
{ users { posts { comments { author { posts { comments { author { id } } } } } } } } }
{ a1: __typename a2: __typename a3: __typename }
```
```bash
# Batch array body — rate-limit bypass probe
curl -X POST https://target/graphql -H 'Content-Type: application/json' \
  -d '[{"query":"{ __typename }"},{"query":"{ __typename }"}]'
```
**Expected signal**: timeout, 500, or linear cost growth vs. alias/batch count.

**Directive / error oracle**
```graphql
{ user(id: "1") { name email @skip(if: false) secretField @include(if: true) } }
{ user { nonExistentField } }
```
**Expected signal**: leaked fields via directives, or validation errors suggesting hidden field names.

## TRUE POSITIVE Criteria

- User-controlled data reaches string assembly of a GraphQL operation document (concat, template literal, format) before `execute` or downstream HTTP forward.
- A resolver concatenates GraphQL arguments directly into a raw database query string.
- Introspection is active with no environment guard (`if DEBUG` / `if NODE_ENV !== 'production'`).
- The `/graphql` endpoint is reachable without any authentication or authorization middleware.

## FALSE POSITIVE Criteria

- Static operation document with user data only in `variables` / `variableValues` — not document injection (still check resolver authz).
- The resolver uses parameterized queries: `db.execute("SELECT * FROM users WHERE id = ?", [args['id']])`.
- Introspection is disabled outside development environments.
- Authentication middleware is applied before the GraphQL handler.
- Persisted-query or operation-ID allowlist; document text never assembled from user strings.

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

### No depth limit
- **VULN**: Schema served without `query_depth_limit` or `query_complexity_limit` middleware
- **Pattern**: `from graphql_server` or `from graphene_django` with no depth limit import

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

### No depth/complexity limits
- **VULN**: Apollo Server without `validationRules: [depthLimit(5)]` or similar
- **Pattern**: Missing `graphql-depth-limit` or `graphql-query-complexity` imports

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

### GraphQL Vulnerable Code Patterns (SAST Detection)

```python
# VULNERABLE: GraphQL query string built from user input (injection)
@app.route('/graphql', methods=['POST'])
def graphql_endpoint():
    query = request.json.get('query')
    result = schema.execute(query)   # user-controlled query executed directly — introspection + injection
    return jsonify(result.data)

# VULNERABLE: no depth/complexity limiting
schema = graphene.Schema(query=Query)
# Without query depth limit: attacker sends deeply nested query → DoS/resource exhaustion
```

```js
// VULNERABLE: GraphQL with introspection enabled in production
const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: true,   // exposes full schema — should be false in production
    playground: true       // developer UI enabled in production
});

// VULNERABLE: no query complexity/depth limit
const server = new ApolloServer({
    typeDefs,
    resolvers,
    // No validationRules: [depthLimit(5), createComplexityLimitRule(1000)]
});
```

```java
// VULNERABLE: GraphQL resolver with unsanitized variable used in SQL/LDAP
@QueryMapping
public List<User> users(@Argument String filter) {
    return em.createQuery("SELECT u FROM User u WHERE u.name = '" + filter + "'").getResultList();
    // GraphQL variable → SQL injection
}

// VULNERABLE: batch query / alias attack (no rate limiting on aliases)
// query { a: user(id:1){...} b: user(id:2){...} ... z: user(id:26){...} }
// Allows bulk data extraction through a single GraphQL request
```

### GraphQL-Specific Vulnerability Classes

1. **GraphQL document injection** — user input alters operation string text (fields, aliases, directives) before parse/execute
2. **Introspection exposure** — schema structure leaked via `__schema`/`__type` queries
3. **SQL/NoSQL injection via resolver** — GraphQL variable reaches DB query without parameterization
4. **Batch query / alias enumeration** — multiple aliased queries in one request bypass rate limits
5. **Broken object-level authorization** — resolver doesn't check if requesting user owns the object
6. **No query depth/complexity limit** — deeply nested queries cause DoS

### GraphQL TRUE POSITIVE Rules

- User-controlled data concatenated/interpolated into GraphQL operation document before `execute` or HTTP forward → **CONFIRM** (`graphql_injection`)
- GraphQL endpoint accepting user-controlled query string without schema validation → **CONFIRM** (`graphql`)
- Resolver using string concatenation with GraphQL argument in SQL/NoSQL query → **CONFIRM** (`graphql_injection` + `sql_injection`)
- `introspection: true` in production Apollo/Graphene config → **CONFIRM** (`graphql` + `information_disclosure`)
- No depth limit + no complexity limit on public GraphQL endpoint → **CONFIRM** (`graphql`)
- GraphQL resolver accessing object by ID without ownership check → **CONFIRM** (`graphql` + `idor`)

### GraphQL FALSE POSITIVE Rules

- Static operation document; user input only in `variables` / `variableValues` — **NOT document injection**
- Persisted-query allowlist or operation-ID registry with no user-controlled document text — **NOT document injection**
- Introspection disabled (`introspection: false`) AND depth/complexity limits enforced — lower risk
- Parameterized resolver: `WHERE id = $1` with bound variable, no string concatenation — **NOT injection**

### Tag Convention

- **Default tag**: `graphql_injection` — use this in all general scans and most benchmark projects
- **Short form**: `graphql` — use only when the benchmark ground truth (`xben/`) explicitly expects the short-form tag
- When a GraphQL vulnerability involves a secondary class (e.g., SQL injection in a resolver), emit both tags: `graphql_injection` + `sql_injection`
