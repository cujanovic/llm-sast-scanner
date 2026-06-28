---
name: insecure_deserialization
description: Insecure deserialization detection covering Java native serialization, JSON libraries (Fastjson, Jackson, Gson), YAML, and XML deserialization
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

### JSON Deserialization Libraries

**Fastjson (com.alibaba.fastjson)**
- `JSON.parseObject(input)` / `JSON.parse(input)` — auto-type can instantiate arbitrary classes
- `@type` field in JSON enables polymorphic deserialization leading to RCE
- AutoType enabled by default in older versions; bypass gadgets exist in many versions < 1.2.83
- Key CVEs: CVE-2017-18349 (autoType RCE in < 1.2.25), CVE-2022-25845 (autoType bypass in < 1.2.83)
- Detection: Look for `JSON.parseObject()`, `JSON.parse()`, `JSONObject.parseObject()` receiving user-controlled strings

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

Use a harmless callback (`curl http://YOUR-COLLABORATOR.oast.fun/deser`) as the gadget action first; only escalate to command execution with authorization.

## Severity Assessment

| Scenario | Severity | CVSS Range |
|----------|----------|------------|
| Native Java deserialization (`ObjectInputStream`) with known gadgets on classpath | Critical | 9.0-10.0 |
| Fastjson `parseObject` with AutoType enabled on user input | Critical | 9.0-9.8 |
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
- Upgrade to Fastjson 2.x or >= 1.2.83
- Disable AutoType: `ParserConfig.getGlobalInstance().setAutoTypeSupport(false)`
- Better: migrate to Jackson or Gson with safe defaults

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
- A method contains `new ObjectInputStream(...).readObject()` and accepts data derived from user input (HTTP request body, Base64-decoded parameter, cookie value, or network stream). CONFIRM even if the complete call chain is in another file.
- A helper/utility class such as `SerializationHelper.fromString(String s)` that calls `ObjectInputStream.readObject()` IS a TP sink. Any controller or endpoint that passes a user-controlled string into this helper is vulnerable.
- Base64 decode followed by `ObjectInputStream.readObject()` on the result is the classic Java deserialization pattern — CONFIRM with high confidence when user-controlled bytes flow into this.
- Fastjson `JSON.parseObject(input)` or `JSON.parse(input)` without a type whitelist/SafeMode — CONFIRM as CWE-502.
- Jackson `readValue(input, Object.class)` or `readValue(input, HashMap.class)` with `enableDefaultTyping()` active — CONFIRM.
- Helper flows that read a cookie or parameter, Base64-decode it, then call `ObjectInputStream.readObject()` still count as `insecure_deserialization` even when the controller only invokes the helper.
- JDBC or demo flows that first persist attacker-controlled serialized bytes and later call `readObject()` on the retrieved blob are still `insecure_deserialization`; do not discard them just because the immediate source is a database row.

### FALSE POSITIVE: Internal or signed data only
- `ObjectInputStream` used exclusively to deserialize data that was serialized in the same JVM, never crossing a trust boundary.
- Fastjson/Jackson used only to serialize (write) data, never to parse untrusted external input.
- Serialization filters (`ObjectInputFilter`) that restrict allowed classes to a known-safe allowlist.
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

**.NET safe alternatives**:
- `DataContractSerializer` with known type list
- `XmlSerializer` with explicit known types
- `JsonSerializer` / `System.Text.Json` without TypeNameHandling

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

## .NET FALSE POSITIVE Rules

- `XmlSerializer` with explicit, fully-qualified known types and no `[XmlInclude]` wildcard on user input — generally safe
- `DataContractSerializer` with explicit `[KnownType]` list and no dynamic type resolution
- `JsonConvert.DeserializeObject<ExplicitType>(input)` with no `TypeNameHandling` setting (default = None) — safe for simple DTOs

## Python Deserialization Vulnerable Patterns

```python
# VULNERABLE: RCE via pickle gadgets
obj = pickle.loads(base64.b64decode(request.args['data']))

# VULNERABLE: YAML !!python/object tags
config = yaml.load(uploaded_yaml)

# SAFE: data-only binding
data = yaml.safe_load(uploaded_yaml)
dto = json.loads(body, object_hook=lambda d: UserDto(**d))
```

**Python unsafe deserializers** (user/network/file input → CONFIRM):
- `pickle.load` / `pickle.loads` / `cPickle`, `dill.load`, `marshal.loads`
- `yaml.load` / `yaml.unsafe_load` / `yaml.full_load` without `Loader=SafeLoader`
- `jsonpickle.decode`, `torch.load` without `weights_only=True` (PyTorch ≥2.0)

**Python secure-config indicators** (downgrade or FP):
- `yaml.safe_load` or `yaml.load(..., Loader=yaml.SafeLoader|BaseLoader)`
- `json.loads` / `orjson.loads` into dict or typed model only — no pickle/jsonpickle on path
- Explicit const/string guard before decode on same branch

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
| Java | `setObjectInputFilter`, `ObjectInputFilter.Config.createFilter`, `ValidatingObjectInputStream`, `SafeConstructor`, `ParserConfig.setSafeMode(true)`, `PolymorphicTypeValidator`, `readValue(..., ConcreteDto.class)` | Filter/validator/DTO type visible on path to sink |
| Python | `safe_load`, `Loader=SafeLoader`, `json.loads`, `model_validate` | No pickle/yaml.load on untrusted branch |
| PHP | `allowed_classes => false`, `json_decode` + validator | No bare `unserialize` on request data |
| .NET | `TypeNameHandling.None`, `DeserializeObject<T>`, `DataContractSerializer(typeof(T))` | No BinaryFormatter/Auto/All on user stream |
| Node | `JSON.parse`, js-yaml default schema | No `node-serialize` / eval on request path |

**Missing safe config on untrusted path → maintain CONFIRM/LIKELY.**

## Analyst Notes

1. Check `pom.xml` / `build.gradle` for Fastjson version — any version < 2.0 with user input parsing is likely vulnerable
2. Even "internal" APIs may receive attacker-controlled input via SSRF or upstream injection
3. The `@type` field in Fastjson is the key indicator — if the application parses JSON containing `@type`, it's exploitable
4. For Jackson, grep for `enableDefaultTyping` and `@JsonTypeInfo` — these are the danger signals
5. SnakeYAML is commonly used in Spring Boot for config parsing — check if it also parses user-provided YAML
6. Chain deserialization with classpath analysis: having CommonsCollections/C3P0/Spring on classpath makes native Java deserialization instantly critical

## Unsafe Deserialization Detection

Commonly affected languages: Java, Python, JavaScript, Ruby, C#, Go.

**Java sinks modeled**: `ObjectInputStream.readObject`/`readUnshared`; Kryo, XStream, SnakeYAML, JYaml, JsonIO, YAMLBeans, Hessian/Burlap, Castor, Jackson (`enableDefaultTyping`), Fastjson, Gson gadgets, JMS `ObjectMessage`, `XMLDecoder.readObject`, `SerializationUtils.deserialize`, Jabsorb, Jodd, Flexjson; RMI deserialization; Spring HTTP invoker exporter in XML/configuration.

**Python sinks**: `pickle.load(s)`/`pickle.loads`, `cPickle`, `dill`, `marshal.loads`, `jsonpickle.decode`; `yaml.load`/`unsafe_load`/`full_load` without `SafeLoader`; `torch.load` (without `weights_only=True`); decoders where input may execute code.

**PHP sinks**: `unserialize()` on superglobals, cookies, sessions, uploads, network bodies; Phar metadata deserialization via `phar://` stream wrappers.

**JavaScript sinks**: `node-serialize`/`serialize-javascript` `.unserialize()`; `js-yaml` `load`/`loadAll` with unsafe schema (`DEFAULT_FULL_SCHEMA`, js-yaml-js-types); `eval`/`Function`/`vm.*` on serialized user strings.

**Ruby sinks**: `Marshal.load`, `YAML.load` (Psych), Oj global options; YAML unsafe tags.

**C# sinks**: `BinaryFormatter`, `LosFormatter`, `NetDataContractSerializer`, `JavaScriptSerializer` + type resolver; untrusted stream → unsafe deserializer.

**Go sinks**: `encoding/gob` `gob.NewDecoder(...).Decode(...)` on attacker-controlled streams; third-party decoders that resolve concrete types from input (e.g. registered `gob` interface types, `mapstructure`/YAML into `interface{}`). Risk is generally lower than Java native deserialization (no broad gadget chains in the stdlib) — primary impact is DoS/panic and type confusion — but untrusted `gob` input should still be treated as a sink. Safe: decoding into a fixed concrete struct from a trusted source; `json.Unmarshal` into typed structs.

**OCaml sinks**: `Marshal.from_string` / `Marshal.from_bytes` / `Marshal.from_channel`, and `input_value` (the `Stdlib` wrapper over the same format) on attacker-controlled bytes. The OCaml marshal format is unauthenticated and unverified — unmarshalling violates type safety (a forged blob produces a value of an arbitrary claimed type), so a crafted payload causes memory corruption / crashes and can be leveraged for code execution. Safe: never unmarshal untrusted input; use a typed, validating parser (e.g. a `ppx`-derived JSON/`Sexp` decoder into a fixed type).

**Clojure sinks**: `(read-string s)` and `clojure.core/read` with the default `*read-eval*` true — reader macro `#=(...)` evaluates arbitrary Clojure/Java at read time → RCE. Safe: `(clojure.edn/read-string s)` / `clojure.edn/read` (no eval, no arbitrary tagged-literal execution), or bind `*read-eval*` to `false` (still prefer `edn`).

**Sources**: remote/network input on all platforms.

**Sanitizers / barriers**:
- Java: `ObjectInputFilter` / `setObjectInputFilter`; `ValidatingObjectInputStream`, `SerialKiller`; XStream/Kryo whitelist configuration flows to read call; Jackson `PolymorphicTypeValidator` / `activateDefaultTyping` with validator; SnakeYAML `SafeConstructor`; Fastjson `ParserConfig.setSafeMode(true)`; HMAC/signature verify before `readObject`.
- Python: const-compare barriers; `yaml.safe_load` / `yaml.load(..., Loader=SafeLoader|BaseLoader)`; typed `json.loads` / pydantic `model_validate`; no pickle on untrusted path.
- PHP: `unserialize(..., ['allowed_classes' => false])`; `json_decode` with schema validation; HMAC on blob before decode.
- JS: `JSON.parse` only; default `js-yaml` v4+ without unsafe schema; no `node-serialize` on cookies/body.
- C#: no `TypeNameHandling` / no type resolver on `JavaScriptSerializer`; HMAC verify before `BinaryFormatter` (still prefer removal).

Remote input → deserialization API argument (unsafe-deserialization sink or decoder input where execution is possible).

Java additional config: tracks user-controlled `Class`/`type` passed to polymorphic deserializers (Jackson, etc.).

## Core Principle

Flag any path from remote input to a deserializer that can instantiate arbitrary types; prefer typed DTO binding and explicit allowlists over blocklists.
