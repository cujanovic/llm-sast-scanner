---
name: nosql_injection
version: "0.4"
description: Detect NoSQL injection vulnerabilities where user-controlled data is passed directly into MongoDB or other NoSQL query operators without type validation, or concatenated into a NoSQL query/command string (Redis, Neo4j Cypher, Cassandra CQL, CouchDB, DynamoDB PartiQL, Amazon SimpleDB SelectRequest, ArangoDB AQL) instead of bound as a parameter.
---

# NoSQL Injection

NoSQL injection arises when user-supplied data is incorporated directly into a NoSQL query document. Unlike SQL injection, the payload exploits the database's native query operators (e.g., MongoDB `$gt`, `$where`, `$regex`) to alter query logic rather than breaking out of a SQL statement.

## Canonical Example

```python
# VULN — if username is {"$gt": ""} instead of a string, matches all users
collection.find({"username": request.json['username']})
```

The attacker sends: `{"username": {"$gt": ""}, "password": {"$gt": ""}}` to bypass authentication.

## TRUE POSITIVE Criteria

- User input is inserted directly as a MongoDB query value without any type validation.
- The input could be a dict/object (rather than a plain string) that MongoDB would treat as an operator expression.

## FALSE POSITIVE Criteria

- Type validation is performed before the query: `if isinstance(username, str):` or `typeof username === 'string'`.
- ORM-level type enforcement automatically rejects non-string values.
- MongoDB `$where` is not used with any user-controlled input.

---

## Python Source Detection Rules

### pymongo
- **VULN**: `collection.find({"username": request.json['username']})` — no isinstance check
- **VULN**: `collection.find({"email": request.form.get('email')})` — form value unvalidated
- **VULN**: `collection.find_one({"$where": f"this.username == '{username}'"})` — JS injection
- **VULN**: `collection.find(request.json)` — entire JSON body used as query document
- **SAFE**:
  ```python
  username = request.json.get('username')
  if not isinstance(username, str):
      abort(400)
  collection.find({"username": username})
  ```

### MongoEngine
- **VULN**: `User.objects(**request.json)` — arbitrary query kwargs sourced from user input
- **VULN**: `User.objects(raw_query=request.json)` — raw query document supplied by user

### Source identifiers
`request.json`, `request.json.get`, `request.form.get`, `request.args.get`, `request.data`

---

## JavaScript Source Detection Rules

### mongoose
- **VULN**: `User.find({username: req.body.username})` — if `req.body.username` is an object `{$gt: ""}`, injection succeeds
- **VULN**: `User.findOne({email: req.body.email, password: req.body.password})` — both fields are injectable
- **VULN**: `db.collection('users').find(req.body.query)` — entire query sourced from request body
- **VULN**: `Model.find().populate({ path: 'author', match: req.query.filter })` — attacker JSON in the populate **`match`** clause reaches Mongo operators (incl. `$where` server-side JS / `$regex`) against the joined collection. The sink is **not** the top-level `find()` argument, so rules that only watch `find`/`findOne` filters miss it; `sanitizeFilter`/`strictQuery` historically did **not** cover `populate.match`. Treat **any** chained position that accepts a filter sub-document as a sink: `populate({match})`, `$elemMatch`, aggregate `$match` stages, `.where(...).equals(tainted)`.
- **SAFE**:
  ```js
  if (typeof req.body.username !== 'string') return res.status(400).json({error: 'Invalid input'});
  User.find({username: req.body.username})
  ```
- **SAFE**: Use mongoose-sanitize or express-mongo-sanitize middleware

### $where operator
- **VULN**: `User.find({$where: `this.username == '${req.body.username}'`})` — JS code injection
- All `$where` usage with any user input is HIGH RISK (allows arbitrary JS execution inside MongoDB)

### Source identifiers
`req.body`, `req.query`, `req.params`

---

## PHP Source Detection Rules

### MongoDB PHP driver
- **VULN**: `$collection->find(['username' => $_POST['username']])` — POST value could be an array
- **VULN**: `$collection->find(['email' => $_GET['email']])` — GET value unvalidated
- **VULN**: `$collection->find(json_decode($_POST['filter'], true))` — JSON body used as query document
- **SAFE**:
  ```php
  $username = (string)$_POST['username']; // cast to string
  $collection->find(['username' => $username]);
  ```

### Type validation patterns
- **VULN**: No `(string)` cast or `is_string()` check before using input in a MongoDB query
- **SAFE**: `if (!is_string($_POST['username'])) { http_response_code(400); exit; }`

### Laravel MongoDB (jenssegers/laravel-mongodb)
- **VULN**: `User::where('username', request('username'))->first()` — no type validation in middleware
- **VULN**: `User::where(request()->all())->first()` — entire request object used as query

## Source -> Sink Pattern

**Sources**
- `ActiveThreatModelSource` — `request.json`, `req.body`, `req.query`, form/URL params
- Python: remote flow into string state; dict state after `json.loads` or NoSQL decode (tracks `String` vs `Dict` flow states)
- JavaScript: tainted objects tracked via `TaintedObject` flow state (deep object taint)

**Sinks**
- **Python**: `NoSqlExecution.getQuery()` where execution `vulnerableToStrings()` or `interpretsDict()` — PyMongo `find`/`find_one`, MongoEngine queries
- **JavaScript**: `NoSql::Query` — MongoDB driver/mongoose query documents; code operators flagged under code-injection sinks (`$where`)
- **Java**: `BasicDBObject.parse(userInput)`; cast to `com.mongodb.DBObject`; `JSON.parse` → Mongo object
- **Go**: `NoSql::Query` — MongoDB Go driver query construction

**Sanitizers / barriers**
- MongoDB `$eq` operator wrapping user value
- `typeof input === 'string'` / `isinstance(input, str)` validation before query
- Go/Java: `SimpleTypeSanitizer` (numeric/boolean)
- Model barriers: `nosql-injection` (Go, JS)
- Python: string-only sinks vs dict sinks — type validation on string path acts as guard via flow state

Commonly affected languages: Python, JavaScript, Go, Java.

**Examples**
- **VULN**: `collection.deleteOne({ _id: req.body.id })` when `req.body.id` can be `{"$gt": ""}`
- **SAFE**: `collection.deleteOne({ _id: { $eq: req.body.id } })` or reject non-string types

## Vulnerable Conditions

- User input reaches query document without type validation
- JSON body parsed into object used directly as filter (`find(req.body)`)
- `$where` clause contains interpolated user string (also code-injection class in JavaScript)

### Query-string / form bracket-notation operator injection

Operator injection does **not** require a JSON body. Body parsers that build nested objects from keys — Express `qs` (default), `body-parser` extended mode, and PHP's native `param[$ne]=` array parsing — let an attacker smuggle operators through ordinary URL/form parameters. This is a high-signal source pattern: a route reading `req.query`/`req.body`/`$_GET` and passing it straight into a filter is injectable even with no visible JSON.

- **VULN (Express + qs)**: `GET /login?user=admin&pass[$ne]=` → `req.query.pass` becomes `{ $ne: "" }`
- **VULN (PHP)**: `POST user=admin&pass[$ne]=` → `$_POST['pass']` becomes `['$ne' => '']`
- **Confirmation forms** to test against a candidate parameter (URL-encode `[`/`]` as needed):
  - `param[$ne]=` and `param[$ne]=null` — matches any value (auth bypass)
  - `param[$gt]=` — greater-than empty, matches most values
  - `param[$regex]=.*` — regex match
  - `$where=1` / `$where=sleep(100)` — server-side JS execution / time-based blind signal (Mongo `$where`)
- **SAFE**: cast the field to a primitive before use (`String(req.query.pass)`), reject non-string types, or disable nested parsing (`qs` with `{ depth: 0 }` / `parameterLimit`).

## Beyond MongoDB — other NoSQL store injection sinks

The operator-injection model above is MongoDB-specific, but every NoSQL store has its own injection sink when user input is **concatenated into a query/command string** rather than bound as a parameter. These are distinct, statically-detectable sinks across different stores — flag the concatenation; prefer the parameterized form:

- **Redis — RESP command injection / CRLF smuggling**: a raw command built from user input — `r.execute_command(f"SET {key} {val}")`, `send_command(...)`, or a hand-built RESP string — lets a `\r\n` in `key`/`val` smuggle a **second** command (`…\r\nCONFIG SET dir /var/www\r\n…` → file write/RCE, `FLUSHALL`, `CONFIG SET`). User input as the body of `EVAL "<lua>"` is Lua injection. **SAFE**: the client's typed methods (`r.set(key, val)`) frame RESP arguments safely; never `execute_command`/`send_command` with an interpolated command; pass Lua `KEYS`/`ARGV`, never concatenate into the script.
- **Neo4j — Cypher injection**: `session.run(f"MATCH (u {{name:'{name}'}}) RETURN u")` instead of `session.run("MATCH (u {name:$name}) RETURN u", name=name)`. Escalators: `apoc.*` procedures reachable from injectable Cypher (`apoc.load.json`/`apoc.load.jdbc` → SSRF/file read, `apoc.cypher.runMany`), and a server configured with `dbms.security.procedures.unrestricted=apoc.*`. **SAFE**: `$param` bind parameters; allowlist labels/relationship types (which **cannot** be parameterized) instead of interpolating them.
- **Cassandra / ScyllaDB — CQL injection**: user input concatenated into `session.execute("… WHERE x = '" + v + "'")` instead of a prepared statement (`session.prepare(…)` + bound values); `' OR '1'='1' ALLOW FILTERING` exposes rows. **SAFE**: prepared statements with bound parameters; never concatenate, especially around `ALLOW FILTERING`.
- **CouchDB — `_design` view & Mango selector injection**: user input written into a design-document view **map function** (`views.<name>.map = "function(doc){…}"`) is stored server-side JS injection; a Mango `_find` `selector` built from raw request JSON permits operator injection (`$regex`, `$or`, `$gt`) like Mongo. **SAFE**: never build view map functions from user input; validate/allowlist Mango selector keys and force scalar types.
- **DynamoDB — PartiQL injection**: `ExecuteStatement(Statement=f"SELECT * FROM users WHERE name='{name}'")` is injectable (`x' OR '1'='1`); the typed `get_item`/`query` with `KeyConditionExpression` + `ExpressionAttributeValues` is not. **SAFE**: PartiQL with `Parameters=[…]` placeholders (`?`), or the typed key/condition-expression API.
- **Amazon SimpleDB — SelectRequest query injection (CWE-943)**: `new SelectRequest("select * from items where name = '" + name + "'")` (or any string-built SimpleDB select passed to `AmazonSimpleDB`/`AmazonSimpleDBClient.select`) is **query-language injection**, not a “structured SDK object.” `SelectRequest` only wraps the query **string**; the AWS client does not parameterize interpolated values. An attacker breaks out of the quoted literal (`' OR '1'='1`) and reads unauthorized domains/items. **Do not CLOSE** because the call uses the official SDK type. **SAFE**: allowlist/escape values for SimpleDB select syntax, or migrate off SimpleDB to an API with bound parameters (DynamoDB typed API / PartiQL `Parameters`).
- **ArangoDB — AQL injection**: user input concatenated into an AQL query string instead of bound — arangojs `db.query(\`FOR d IN products FILTER d.name == "${q}" RETURN d\`)` / the raw-string `db.query({ query, bindVars })` form, python-arango `db.aql.execute(f"…")`, or the Go/Java drivers. AQL binds **both values (`@var`) and identifiers (`@@collection`, `@attribute`)**, so binding the value `@id` does **not** make the query safe when the collection (`FOR x IN ${col}`) or a `SORT x.${attr}` position is still interpolated — flag interpolation into the `FOR … IN`, `SORT`, or `FILTER` positions even when other params are bound. **Escalators (drive severity to Critical, not just data read):** AQL allows data-modification operations inside a read-only outer query like stacked SQL (`INSERT`/`UPDATE`/`REMOVE`/`UPSERT`/`REPLACE … IN <col>`); and an injection able to write can add a server-side JavaScript **user-defined function to the `_aqlfunctions` collection** (`INSERT { name, code } INTO _aqlfunctions`) then invoke it, reaching `require('fs')` (arbitrary file **read/write**) and `require('internal').download(url, …, dest)` (SSRF/OOB) — running **as `root` in the stock Docker image** (e.g. read `/proc/self/environ` → `ARANGO_ROOT_PASSWORD`). Extraction primitives mirror SQLi: `FAIL("…")` (error-based), `SUBSTRING`+`SORT`+`LIMIT` (blind), `SLEEP()`/`FAIL(SLEEP())` (time-based). Do **not** downgrade AQL injection to "read-only" because "modern ArangoDB has no server-side JS" — UDFs are exploitable in 3.x (removed only in 4.0) unless explicitly disabled. **SAFE**: `@var`/`@@collection`/`@attribute` bind parameters (arangojs `` aql`…` `` tagged template or `{ query, bindVars }` with no interpolation) + allowlist identifier names; least-privilege DB user; disable UDFs (`--javascript.user-defined-functions false`) and Foxx (`--foxx.enable false`) when unused.

- **ServiceNow — GlideRecord `javascript:` filter evaluation**: the Glide query API evaluates a filter **value** that begins with `javascript:` as a server-side JavaScript expression *before* using the result as the operand — so `addQuery(field, value)`, `addQuery(field, op, value)`, `addOrCondition(...)`, `get(field, value)`, and `addEncodedQuery(str)` with an untrusted value are **code-evaluation sinks, not safe scalar binds** (CVE-2026-6875). The two-argument "structured" form is the trap: `gr.addQuery('sys_id', input)` with `input = "javascript:<expr>"` runs `<expr>` server-side. Reachable **pre-auth** through public Scripted REST resources (`request.queryParams.*`, `request.body.data.*`) and `.do` UI-page processors (`jelly.sysparm_*`). Evaluation runs in the restricted Glide *script sandbox*, but documented escapes (`gs.include()` loads a script-include in an unsandboxed context, then clobbering a global it calls — `Object.defineProperty(Object,'clone',{value: Class.create.constructor})` with the payload in `AbstractAjaxProcessor.prototype` — forces `Function(code)()`) escalate to full **unauthenticated RCE** plus command execution on connected MID/proxy servers. **SAFE**: validate/allowlist the value before it reaches the query (e.g. a 32-hex `sys_id` regex, an enum of field names) and reject a leading `javascript:`; build encoded queries server-side from typed inputs — never forward a client-supplied `addEncodedQuery` string; `GlideRecordSecure`+ACLs and the patched **Guarded Script** mode are defense-in-depth, not a reason to pass tainted input. See `expression_language_injection.md`.

(Elasticsearch/OpenSearch Painless & Lucene `script_score`/`sort` injection is its own class — see `expression_language_injection.md`.)

## Safe Patterns

- Explicit string type check before query field assignment
- `$eq` (or equivalent) to force literal interpretation
- Never pass raw `request.json` / `req.body` as entire query object

## Common False Alarms

- Query fields set only from validated `typeof x === 'string'` / `isinstance(x, str)` branches
- Numeric ObjectId lookups where simple-type sanitizer applies (Go/Java)
- ORM methods with framework-enforced scalar types (verify — not all ORMs are modeled, and not every two-argument "bind" is a scalar: ServiceNow GlideRecord `addQuery(field, value)` evaluates a `javascript:`-prefixed value as server-side JS — see the ServiceNow bullet above)

## Business Risk

- Authentication bypass via operator injection (`$gt`, `$ne`, `$regex`)
- Unauthorized data read/write when filter logic is attacker-controlled
- Server-side JS execution via MongoDB `$where` (JavaScript code-injection class)

## Core Principle

NoSQL injection exploits schema-less query documents, not SQL quoting. Treat every request field as potentially an operator object until proven a scalar literal.
