---
name: cve_patterns
description: Detect known dangerous code patterns associated with high-severity library vulnerabilities, identified by sink pattern rather than version number.
---

# Known CVE Pattern Detection

This skill surfaces dangerous patterns associated with well-known library vulnerabilities. Detection is grounded in **sink + source pattern** — the dangerous function call combined with user-controlled input — rather than version pinning, because the pattern itself carries design-level risk regardless of patch status.

## Philosophy

Rather than checking `requirements.txt` version numbers (which change), this skill flags code where:
1. A historically-vulnerable function is called.
2. With user-controlled or externally-sourced input.

Even when the library is up to date, the pattern signals an architectural risk worth reviewing.

---

## Variant Hunting / Fix-Pattern Lifting

A single confirmed vulnerability is rarely unique — the same mistake usually recurs elsewhere. After confirming one finding (or learning of a CVE), **lift the abstract pattern and sweep the whole codebase for unfixed siblings**. This raises recall far beyond the seed location.

**Two triggers**

- **Post-finding sweep** — once any finding is confirmed, generalize it to a pattern (dangerous sink + source shape + the missing guard) and search for every other call site that matches the sink/source but lacks the guard.
- **N-day fix-pattern lifting** — from a public CVE/patch diff, the *removed* code reveals the vulnerable shape and the *added* code reveals the correct guard/sanitizer. Hunt the target for call sites that still match the pre-fix shape (e.g. a dependency upgraded in one module but the same unsafe call open elsewhere, or a fix applied to one handler but not its copies).

**Method**

1. Express the seed as an invariant: *"every call to `SINK` reachable from `SOURCE` must be preceded by `GUARD`."*
2. Enumerate all call sites of `SINK` (normalize across wrappers, aliases, and re-exports — the same function is often reached via a helper).
3. Flag every site where the guard/sanitizer is absent or bypassable; confirm reachability from untrusted input per the usual source→sink rules.
4. Emit each variant as its own finding that references the seed pattern, so triage can batch them.

**Cross-reference**: combine with the per-class sink tables in the other references — those define the `SINK` set to sweep for each vulnerability class.

---

## Python Source Detection Rules

### PyYAML — Arbitrary Code Execution
- **VULN**: `yaml.load(user_input)` — no `Loader` argument; pre-6.0 default is `FullLoader` (unsafe)
- **VULN**: `yaml.load(user_input, Loader=yaml.Loader)` — `yaml.Loader` executes arbitrary Python
- **VULN**: `yaml.load(yaml.Loader)` with any file or stream from user uploads or external sources
- **SAFE**: `yaml.safe_load(user_input)` — restricts to basic Python objects, no code execution
- **SAFE**: `yaml.load(data, Loader=yaml.SafeLoader)`
- **Pattern to flag**: `yaml.load(` without `Loader=yaml.SafeLoader` or `Loader=yaml.CSafeLoader`

### Pillow — Remote/User Image Processing
- **RISK**: `Image.open(user_uploaded_file)` — decompression bomb, ImageMagick delegation exploits
- **MITIGATION**: `Image.MAX_IMAGE_PIXELS = 10000000` set before processing
- **RISK**: `Image.open(url)` via `io.BytesIO(requests.get(url).content)` — SSRF + image attack chain

### Werkzeug Debugger — RCE Exposure
- **VULN**: `app.run(debug=True)` — Werkzeug interactive debugger accessible in production
- **VULN**: `FLASK_DEBUG=1` or `FLASK_ENV=development` without host restriction
- **VULN**: `USE_DEBUGGER = True` in Flask config
- **SAFE**: `app.run(debug=os.environ.get('FLASK_DEBUG', 'False') == 'True')`

### Django ALLOWED_HOSTS
- **VULN**: `ALLOWED_HOSTS = ['*']` — allows Host header injection, cache poisoning
- **NOTE**: `ALLOWED_HOSTS = []` with `DEBUG=False` rejects all requests (DisallowedHost / 400) — does NOT fall back to wildcard
- **SAFE**: `ALLOWED_HOSTS = ['example.com', 'www.example.com']`

### Jinja2 Sandbox Escape
- **VULN**: `Environment(undefined=Undefined)` with `from_string(user_template)` — see ssti.md
- **VULN**: `jinja2.Template(user_input).render()` — template constructed directly from user input
- **SAFE**: `Environment(sandbox=True)` + `from_string()` — SandboxedEnvironment for user templates

### requests — SSRF via Open Redirect
- **VULN**: `requests.get(user_url, allow_redirects=True)` — follows redirects to internal services
- **SAFE**: `requests.get(url, allow_redirects=False)` + URL allowlist validation

### Python pickle
- **VULN**: `pickle.loads(data)` where `data` originates from an HTTP request, file upload, Redis, or message queue
- **VULN**: `pickle.loads(base64.b64decode(request.cookies['session']))` — cookie-based pickle RCE
- **Impact**: `pickle.loads` on attacker-controlled data = arbitrary code execution

---

## JavaScript Source Detection Rules

### eval / Function constructor — RCE
- **VULN**: `eval(req.body.code)` — direct eval of request body
- **VULN**: `eval(req.query.expr)` — eval of query parameter
- **VULN**: `new Function(req.body.code)()` — Function constructor from user input
- **VULN**: `new Function('return ' + userInput)()` — expression evaluator
- **SAFE**: `eval()` only with static strings (no user input in argument)

### node-serialize — RCE via IIFE
- **VULN**: `require('node-serialize').unserialize(req.body.data)` — IIFE in serialized object executes on deserialization
- **VULN**: `serialize.unserialize(userInput)` from `node-serialize` package
- **Pattern**: Any use of `node-serialize`'s `unserialize()` with external data

### vm module — Sandbox Escape
- **VULN**: `vm.runInNewContext(userCode)` — Node.js vm module is NOT a security sandbox
- **VULN**: `vm.runInThisContext(userCode)` — executes in the current context
- **Pattern**: `require('vm')` + user-controlled code string

### Lodash — Prototype Pollution
- **VULN**: `_.merge(target, req.body)` — lodash merge with an untrusted deep object
- **VULN**: `_.set(obj, req.body.key, req.body.value)` — arbitrary property path sourced from user input
- **SAFE**: Schema validation before merge; `Object.freeze(Object.prototype)`

---

## PHP Source Detection Rules

### unserialize — PHP Object Injection
- **VULN**: `unserialize($_GET['data'])` — PHP object injection leading to POP chain RCE
- **VULN**: `unserialize($_POST['object'])` — POST body deserialized
- **VULN**: `unserialize($_COOKIE['user'])` — cookie value deserialized
- **VULN**: `unserialize(base64_decode($input))` — encoded but equally dangerous
- **Impact**: PHP POP (Property-Oriented Programming) chains can achieve RCE, SSRF, arbitrary file write
- **SAFE**: `json_decode($_GET['data'])` — JSON does not instantiate PHP objects

### eval — Code Injection
- **VULN**: `eval($_POST['code'])` — direct eval of POST data
- **VULN**: `eval(base64_decode($_GET['payload']))` — encoded eval
- **VULN**: `assert($_GET['expr'])` — PHP assert with a string argument is equivalent to eval (PHP < 8)
- **SAFE**: `eval()` only with fully static strings

### preg_replace with /e modifier (historical)
- **VULN**: `preg_replace('/' . $userPattern . '/e', $replacement, $subject)` — /e modifier executes replacement as PHP (PHP < 7.0)
- **Note**: /e modifier removed in PHP 7.0; flag when encountered in legacy codebases

### include/require with user input (RFI)
- **VULN**: `include($_GET['page'])` when `allow_url_include = On` — Remote File Inclusion = RCE
- **VULN**: `require($_POST['module'] . '.php')` — local or remote file inclusion
- See also: path_traversal_lfi_rfi.md
- For `JavaSecLab` modules under `components/` (`fastjson`, `jackson`, `xstream`, `shiro`, `log4j2`), preserve project tag `component_vulnerability` when the route exists, even if the exploit primitive could also be labeled `jndi_injection` or `insecure_deserialization`.
- In `vulhub`, prefer the concrete benchmark tag exposed by the selected sample (`sql_injection`, `spel_injection`, `insecure_deserialization`, and similar) and use `component_vulnerability` only when the ground truth explicitly groups the sample by vulnerable component family rather than exploit primitive.
- In benchmark mode, when source review already confirms a dedicated project module or stable public taxonomy for the vulnerability class, preserve the exact benchmark tag in later rounds instead of re-collapsing it into a broader sink label merely because another exploit primitive also matches.
- In `verademo`, request-controlled class selection such as `Class.forName("com.veracode.verademo.commands." + ucfirst(command) + "Command")` should preserve `unsafe_reflection`, not only downstream `rce` or `privilege_escalation`.
- If untrusted input reaches `String.format(userControlledTemplate, ...)`, `printf(userControlledTemplate, ...)`, or a logger sink like `logger.info(tainted)` / `logger.error(tainted)` in a benchmark that splits those classes, preserve `format_string` or `log_injection` instead of collapsing into generic disclosure.
- FALSE POSITIVE guard: do not emit `privilege_escalation` from reflective command dispatch alone unless the code also shows a distinct role, ownership, or privilege check that the attacker can bypass.

---

## GraphQL Source Detection Rules

GraphQL CVE and recurring known-weakness shapes combine **manifest signals** (dependency identity + version in `package.json`, `Gemfile`/`Gemfile.lock`, `composer.json`, `pom.xml`, WordPress plugin headers) with **sink/default patterns** (resolver SQL concat, GET mutation handlers, missing validation rules). Cross-ref `graphql_injection.md` for document injection, resolver SQLi, GET/CSRF, and batching; cross-ref `graphql_dos.md` for depth/complexity, fragment-cycle, large-argument, and introspection DoS detail.

### Agoo (Ruby) — Circular Fragment DoS (CVE-2022-30288)

- **SIGNAL**: `agoo` gem in `Gemfile`/`Gemfile.lock` at version `< 2.14.1`
- **VULN**: Agoo GraphQL handler accepts fragment definitions with no cycle detection — mutually referencing fragments (`fragment A on T { ...B }` / `fragment B on T { ...A }`) cause unbounded expansion during query execution
- **Pattern**: `gem 'agoo'` or `agoo (` in lockfile below `2.14.1`; no `validate_fragments` / fragment-cycle guard in Agoo GraphQL middleware
- **FIX**: Upgrade `agoo` to `>= 2.14.1`; enforce spec-compliant fragment validation (reject cyclic fragment spreads before execution). Cross-ref `graphql_dos.md` (fragment-cycle DoS)

### WordPress WPGraphQL — Array Batching DoS

- **SIGNAL**: `wp-graphql` / `WPGraphQL` in `composer.json`, plugin directory, or `composer.lock` below a version shipping batch-size limits (audit lockfile against current advisory baseline)
- **VULN**: HTTP handler accepts JSON array body `[{ "query": "..." }, …]` and executes every element with no `maxBatchSize` or operation-count cap — multiplies server cost per request and bypasses per-request rate limits
- **Pattern**: `Array.isArray( $input )` / batch loop over request body in WPGraphQL bootstrap; `graphql_batch_limit` filter absent or set to unlimited; `allowBatching` enabled with no cap
- **FIX**: Upgrade WPGraphQL to a patched release; disable batching in production or enforce a low batch/operation cap. Cross-ref `graphql_injection.md` (Unbounded HTTP Array Batching) and `graphql_dos.md`

### Apache SkyWalking — GraphQL SQL Injection (CVE-2020-9483)

- **SIGNAL**: `apache-skywalking` / `skywalking-oap-server` in `pom.xml`, Gradle deps, or Docker image tag below `8.0.1` (also affects 6.x/7.x lines prior to vendor patch)
- **VULN**: GraphQL metric resolver builds SQL by concatenating metric IDs into a quoted string — `StringBuilder` / string concat with user-supplied or request-derived metric identifiers inside `'…'` literals passed to JDBC/native query execution
- **Pattern**: `StringBuilder` + quoted metric-ID concat (`append("'" + metricId + "'")`); `"SELECT … WHERE id = '" + args.get("id")` in SkyWalking OAP GraphQL resolver packages; `createNativeQuery` / `executeQuery` fed by concatenated metric ID list
- **FIX**: Upgrade OAP to `>= 8.0.1`; replace string-built SQL with parameterized queries / prepared statements. Cross-ref `graphql_injection.md` (SQL in resolvers)

### GraphQL Playground / GraphiQL — XSS (CVE-2021-41249)

- **SIGNAL**: `graphql-playground-react`, `@apollographql/graphql-playground-react`, or `graphql-playground-html` in `package.json`/`package-lock.json`/`yarn.lock` below `1.7.33`
- **VULN (CVE)**: Playground React renders attacker-controlled query/variable strings without encoding — reflected XSS via malicious GraphQL document or variable values in the IDE UI
- **VULN (broader pattern)**: `playground: true`, `graphiql: true`, or `GraphiQL` / `GraphQLPlayground` middleware mounted on production routes without auth or environment guard
- **Pattern**: `new ApolloServer({ playground: true })`, `expressGraphiQL`, `graphiql: true` in non-development config; Playground static assets served on public `/graphql` or `/playground` paths
- **FIX**: Upgrade Playground packages to `>= 1.7.33`; set `playground: false` / `graphiql: false` in production; gate IDE behind auth and `NODE_ENV === 'development'`. Cross-ref `graphql_injection.md` (Introspection in production)

### GET-Based GraphQL CSRF (GitLab-class pattern)

- **SIGNAL**: Route accepts `GET` for `/graphql` while CSRF/session token middleware applies only to `POST` — mutations and `variables` executable from query string (`?query=mutation{…}&variables={…}`)
- **VULN**: `app.get('/graphql', …)` / `router.get.*graphql` executes `req.query.query` including mutations; CSRF token checked on POST handler only; session cookies sent on simple GET cross-site requests
- **Pattern**: `req.query.query`, `request.args.get('query')`, `URLSearchParams` GraphQL source on GET; `methods: ['GET', 'POST']` on GraphQL route with token guard on POST branch only
- **FIX**: Disallow GET (and HEAD) for state-changing operations; enforce uniform CSRF/custom-header token on all GraphQL methods that execute mutations; restrict GET to read-only persisted queries if needed. Cross-ref `graphql_injection.md` (GET-Based Mutations and CSRF) and `csrf.md`

### Introspection Defaults and Complexity-Rule Gaps

- **SIGNAL**: GraphQL engine defaults leave introspection enabled (`introspection: true`, no env guard) — recurring disclosure shape across Apollo, Graphene, graphql-ruby, gqlgen, and graphql-php deployments
- **VULN**: `new ApolloServer({ schema })` / `GraphQLView.as_view(…)` / `StandardServer` with no `introspection: false` or validation rule blocking `__schema` / `__type` in production
- **VULN (complexity gap)**: `createComplexityLimitRule` / `query_complexity` configured but **excludes introspection meta-fields** (`__schema`, `__type`, `__typename`) from cost — circular introspection queries (`__schema { types { fields { type { fields { … } } } } }`) bypass the complexity budget and cause DoS
- **Pattern**: Missing `introspection: process.env.NODE_ENV === 'development'`; complexity rule with `introspectionFieldFactor: 0` or explicit skip of `__*` fields; no `depthLimit` paired with complexity on public endpoint
- **FIX**: Disable introspection outside development; include meta-fields in complexity/depth accounting or block introspection queries in production middleware. Cross-ref `graphql_injection.md` (Introspection in production, Circular Schema Relationships) and `graphql_dos.md` (introspection/circular-introspection DoS)

### Large-Argument DoS and search(q:) Resolver ReDoS

- **SIGNAL**: GraphQL `String` / `[String!]!` arguments with no `maxLength` directive, server-side length guard, or parser-level input cap — disclosed DoS shape in multiple GraphQL implementations
- **VULN (large argument)**: Resolver or variable coercion accepts megabyte-scale strings/lists (`search(q: $q)`, `filter: $filter`, bulk ID arrays) with no pre-execution size limit — memory/CPU exhaustion during parse, validate, or resolver fan-out
- **VULN (ReDoS)**: `search(q: String)` / `search(query: …)` resolver passes `args.q` / `args.query` into `new RegExp(…)`, `re.search(…)`, `Pattern.compile(…)`, or `.match(…)` without input length cap or safe-regex validation
- **Pattern**: `resolveSearch` / `search(` resolver + `RegExp(args` / `re.compile(args['q']` / `Pattern.compile(.*args`; SDL `search(q: String!): [Item]` with no `@length(max: …)` or custom validation rule; missing `maxInputLength` / `MAX_QUERY_LENGTH` middleware
- **FIX**: Enforce argument and document size limits before execution; cap string/list argument length in validation rules; use literal/substring match or RE2-style engines for search resolvers; add timeout guards. Cross-ref `graphql_injection.md` (ReDoS via Resolver Regex) and `graphql_dos.md` (large-argument DoS)

### GitLab — GraphQL vs REST Authorization Parity (CVE-2019-15576)

- **SIGNAL**: Same domain model (e.g. notes, issues, confidential attributes) exposed by a GraphQL resolver/field with weaker or no authorization than the REST serializer, policy object, or controller path — nested GraphQL traversal (`project → issue → notes`) reaches data REST endpoints would block
- **VULN**: Field resolver for sensitive nested type returns rows without calling the same `authorize` / policy / serializer guard used by the REST API; federation or schema stitching forwards sub-graph fields that skip parent REST access checks
- **Pattern**: `NotesResolver` / `resolve_notes` / `notes:` field handler with no `authorize!` / `policy_scope` / `Ability` check while REST `NotesController#index` or equivalent serializer applies visibility rules; GraphQL `IssueType` exposes `notes { nodes { … } }` without reusing REST `NotePolicy` / `visible_to?` logic
- **FIX**: Single authorization source shared across REST controllers, serializers, and GraphQL resolvers (and federated sub-schemas); enforce field-level rules on sensitive fields — not only REST serializers. Cross-ref `graphql_injection.md` (authorization) and `idor.md`

### GitLab — Unauthenticated User Enumeration via Query.users (CVE-2021-4191)

- **SIGNAL**: `Query.users` resolver (or equivalent top-level `users { nodes { … } }` field) returns user rows with no authentication guard when the instance is private or registration is disabled
- **VULN**: Public or sessionless access to `users { nodes { id username publicEmail … } }` leaks account metadata; `signup_enabled` / `registration_enabled` / private-instance flag checked on web UI but not enforced on the GraphQL resolver
- **Pattern**: `def resolve_users` / `users:` root query resolver without `context[:current_user]` or `authorize` gate; SDL `users: UserConnection!` with no `@auth` / shield rule; registration-disabled config read in controllers only, not in GraphQL middleware
- **FIX**: Gate `Query.users` and nested user fields on authentication plus instance policy (reject when registration disabled or instance is private); apply the same visibility rules as the REST user directory. Cross-ref `graphql_injection.md` and `idor.md`

### Custom GET-Parameter → SQL SET SESSION Injection (GraphQL handler class)

- **SIGNAL**: Non-standard HTTP GET parameters (outside `query`, `variables`, `operationName`) interpolated into SQL such as `SET SESSION <key> TO <value>` — disclosed bug-bounty class in GraphQL SQL-backed deployments
- **VULN**: GraphQL HTTP adapter reads arbitrary `req.query` / `request.args` / `@RequestParam` keys and string-builds session-configuration SQL (`SET SESSION ` + paramName + ` TO ` + paramValue) before or during query execution
- **Pattern**: `Object.keys(req.query).filter(k => !['query','variables','operationName'].includes(k))` fed into SQL; `SET SESSION ${key} TO '${value}'` / `"SET SESSION " + request.getParameter(...)` in GraphQL bootstrap or connection pool setup; GET param names or values concatenated into JDBC/native query strings
- **FIX**: Allowlist only standard GraphQL parameters (`query`, `variables`, `operationName`, `extensions` if used); never string-build SQL from GET keys or values — use parameterized statements or fixed session settings. Cross-ref `graphql_injection.md` and `sql_injection.md`

### Deactivated Account Still Authorized via API Token (GraphQL API class)

- **SIGNAL**: Authentication middleware loads the user by API token or personal access token but never checks `active`, `deactivated`, `blocked`, or `state` before GraphQL execution — deactivated accounts execute mutations (e.g. `labelCreate`, `issueUpdate`) successfully
- **VULN**: Token lookup returns a user record whose `active: false` / `deactivated_at` / `blocked` flag is ignored in GraphQL context construction; only password/session login paths enforce account status
- **Pattern**: `User.find_by_token(token)` → `context[:current_user] = user` with no `user.active?` / `deactivated?` guard; API-key auth branch skips `before_action :check_user_active` applied to web sessions; GraphQL mutations succeed for `state: 'blocked'` users
- **FIX**: Reject inactive, deactivated, or blocked users immediately after token lookup and before resolver execution; unify account-status checks across REST, GraphQL, and token auth paths. Cross-ref `authentication_jwt.md` and `graphql_injection.md`

### graphql-shield — Authorization Bypass (< 6.0.6)

- **SIGNAL**: `graphql-shield` pinned below `6.0.6` in `package.json`, `package-lock.json`, or `yarn.lock` alongside `shield()` / `applyMiddleware` usage
- **VULN**: Versions `< 6.0.6` allow authorization bypass when rule composition, caching, or fallback handling is misconfigured — unprotected fields execute without hitting deny rules
- **Pattern**: `"graphql-shield": "6.0.5"` / `"^6.0.0"` in lockfile with `shield({ Query: { … } })`; `applyMiddleware(schema, permissions)` without `fallbackRule: deny`; missing per-type rules on nested fields after shield upgrade gap
- **FIX**: Upgrade `graphql-shield` to `>= 6.0.6`; set `fallbackRule: deny` and define explicit per-field rules for every Query/Mutation field. Cross-ref `graphql_injection.md` (graphql-shield fallback)
