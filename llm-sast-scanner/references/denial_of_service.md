---
name: denial_of_service
description: Denial of Service detection — vulnerable code patterns for ReDoS, XML bomb, Zip bomb, resource exhaustion, unbounded operations, and missing rate/size limits
---

# Denial of Service (DoS)

DoS vulnerabilities occur when user-controlled input can trigger unbounded computation, memory allocation, or I/O operations. This includes algorithmic complexity attacks (ReDoS), decompression bombs, XML entity expansion, unbounded uploads, catastrophic regex backtracking, and missing pagination/rate limits.

## CWE Classification

- **CWE-400**: Uncontrolled Resource Consumption
- **CWE-770**: Allocation of Resources Without Limits or Throttling
- **CWE-1333**: Inefficient Regular Expression Complexity (ReDoS)
- **CWE-776**: Improper Restriction of Recursive Entity References in DTDs (Billion Laughs)

## Vulnerable Patterns

### ReDoS (Regular Expression Denial of Service)

**Dangerous regex patterns** — catastrophic backtracking when applied to attacker-controlled input:

```java
// VULNERABLE: Polynomial/exponential backtracking regex on user input
String input = request.getParameter("email");
if (input.matches("^(a+)+$")) { ... }          // exponential backtracking
if (input.matches("([a-z]+)*@[a-z]+\\.com")) { ... }  // nested quantifiers
if (input.matches("(a|aa)*b")) { ... }         // alternation with overlap

// VULNERABLE: Java Pattern.compile on user-provided pattern string
String userPattern = request.getParameter("pattern");
Pattern p = Pattern.compile(userPattern);        // attacker controls the regex
Matcher m = p.matcher(subject);
m.matches();  // attacker can supply catastrophic pattern
```

**ReDoS-prone structures** (flag any of these applied to unbounded user input):
- Nested quantifiers: `(a+)+`, `(a*)*`, `(a|a?)+`
- Alternation with overlap: `(x|xx)*`, `(a|ab)+`
- Backtracking-heavy lookahead: `(?=.*a)(?=.*b).*`
- User-supplied regex patterns evaluated server-side

```python
# VULNERABLE Python: user-controlled regex
import re
pattern = request.args.get('filter')
re.search(pattern, subject)    # attacker can supply catastrophic regex

# VULNERABLE: complex regex on user-controlled long string
if re.match(r'^(\w+\s?)*$', user_input):   # exponential on " " at end
```

```js
// VULNERABLE Node.js: user input as regex pattern
const pattern = new RegExp(req.query.pattern);
pattern.test(subject);

// VULNERABLE: built-in dangerous regex on user string
/^(a+)+$/.test(req.body.input);
```

### XML Bomb / Entity Expansion

```java
// VULNERABLE: DocumentBuilderFactory with entity expansion (billion laughs)
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
// No setExpandEntityReferences(false) or setFeature(...)
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(userXmlStream);
// Attacker sends billion-laughs payload → memory exhaustion

// VULN indicator: DocumentBuilderFactory created WITHOUT:
//   dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
//   OR dbf.setExpandEntityReferences(false)
```

```python
# VULNERABLE: lxml without entity limits
from lxml import etree
tree = etree.parse(user_xml_source)   # no XMLParser with resolve_entities=False
# billion laughs can exhaust memory
```

### Zip Bomb / Decompression Bomb

```java
// VULNERABLE: unzip without size limit
ZipInputStream zis = new ZipInputStream(request.getInputStream());
ZipEntry entry;
while ((entry = zis.getNextEntry()) != null) {
    byte[] buffer = new byte[1024];
    // No check on entry.getSize() or total extracted bytes
    while (zis.read(buffer) != -1) { /* write to disk */ }
}
// Attacker sends 42.zip (42KB zip → 4.5PB decompressed) → disk/memory exhaustion

// SAFE: enforce uncompressed size limit
long totalSize = 0;
while ((entry = zis.getNextEntry()) != null) {
    totalSize += entry.getSize();  // often -1 for stored/unknown entries — do not rely on getSize() alone
    if (totalSize > MAX_DECOMPRESSED_BYTES) throw new IOException("Zip bomb detected");
    // Also cap actual bytes read during decompression (count zis.read() output), not just entry metadata
}
```

```python
# VULNERABLE: tarfile extraction without size check
import tarfile
with tarfile.open(user_file) as tar:
    tar.extractall(path=extract_dir)    # no size limit → decompression bomb

# SAFE: limit member sizes
for member in tar.getmembers():
    if member.size > MAX_FILE_SIZE:
        raise ValueError("File too large")
```

### Unbounded File Upload

```java
// VULNERABLE: no content-length or size limit on upload
@PostMapping("/upload")
public ResponseEntity<?> upload(@RequestParam MultipartFile file) {
    // No file size check — attacker uploads multi-GB file
    file.transferTo(new File(UPLOAD_DIR + file.getOriginalFilename()));
}

// VULNERABLE: Spring missing max-file-size config
// application.properties has no: spring.servlet.multipart.max-file-size=10MB

// SAFE:
if (file.getSize() > MAX_UPLOAD_BYTES) {
    throw new FileSizeLimitExceededException(...);
}
```

```python
# VULNERABLE: Flask without file size enforcement
@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    f.save(os.path.join(UPLOAD_FOLDER, f.filename))
    # No check on f.content_length or file.tell()

# SAFE: enforce MAX_CONTENT_LENGTH
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB
```

### Missing Pagination / Unbounded DB Query

```java
// VULNERABLE: returns entire table without limit
@GetMapping("/users")
public List<User> getAllUsers() {
    return userRepository.findAll();    // no page/limit — 10M rows crashes JVM heap
}

// VULNERABLE: user-controlled page size with no upper bound
int pageSize = Integer.parseInt(request.getParameter("size"));
return userRepository.findAll(PageRequest.of(page, pageSize));  // size=2147483647

// SAFE:
int pageSize = Math.min(Integer.parseInt(request.getParameter("size", "20")), 100);
```

### Missing Rate Limiting

```java
// VULNERABLE: no rate limiting on expensive endpoint
@PostMapping("/search")
public List<Result> search(@RequestBody SearchQuery query) {
    return searchService.fullTextSearch(query);  // unbounded, no throttle
}

// VULNERABLE: no brute-force protection on auth endpoint
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest req) {
    // No attempt counter, no lockout, no CAPTCHA
    return authService.authenticate(req.getUsername(), req.getPassword());
}
```

### Hash Collision DoS (HashDoS)

```java
// VULNERABLE: Java HashMap with user-controlled keys (pre-Java 8)
// Attacker crafts keys with same hashCode() → O(n²) insertion
Map<String, String> params = new HashMap<>();
for (String key : request.getParameterNames()) {
    params.put(key, request.getParameter(key));  // vulnerable in Java < 8 without RANDOMHASHSEED
}

// VULNERABLE: PHP hash tables (CVE-2011-4885 style)
// parse_str() or $_POST with many colliding parameter names
```

### CPU-Intensive Operations Without Limits

```python
# VULNERABLE: user-controlled iteration count in crypto/hash
rounds = int(request.args.get('rounds', 12))
# Attacker sends rounds=31 → bcrypt.gensalt(rounds=31) takes minutes per hash
# bcrypt rounds is a log2 factor (2^rounds iterations); values above 20 cause severe CPU exhaustion
bcrypt.hashpw(password, bcrypt.gensalt(rounds=rounds))

# VULNERABLE: user controls sleep/wait duration
time.sleep(float(request.args.get('delay', 0)))
```

```java
// VULNERABLE: user-controlled thread pool or recursion depth
int depth = Integer.parseInt(request.getParameter("depth"));
recursiveCompute(data, depth);   // no max depth → StackOverflowError or OOM
```

## Detection Rules

### TRUE POSITIVE

- `Pattern.compile(userInput)` — user-controlled regex applied server-side → **CONFIRM** (ReDoS risk, unconstrained pattern complexity)
- `ZipInputStream` extraction with no total-size limit on user-uploaded files → **CONFIRM**
- `DocumentBuilderFactory` without `disallow-doctype-decl` feature processing user XML → **CONFIRM** (billion laughs possible)
- DB query / `findAll()` with user-controlled unbounded page size (no upper bound enforcement) → **CONFIRM**
- Missing rate limiting on auth endpoints → classify under `brute_force`, NOT `denial_of_service` (requires an actual unbounded/amplifiable resource sink)
- `tarfile.extractall()` / `ZipFile.extractall()` without member size validation → **CONFIRM**

### FALSE POSITIVE

- Regex patterns that are fully hardcoded (not user-supplied) — only flag if the *pattern itself* is catastrophic AND the *subject* is unbounded user input
- File extraction with documented size limits enforced before write
- Pagination enforced server-side with a hardcoded maximum page size
- Do NOT emit `denial_of_service` merely because an endpoint lacks rate limiting or size limits — this is a defense-in-depth gap, not a confirmed DoS vulnerability. Require EXPLICIT evidence of unbounded resource consumption (e.g., user-controlled allocation size, recursive processing, entity expansion).
- Do NOT emit `denial_of_service` for file upload size limits handled by the framework default (e.g., Spring Boot's default 1MB multipart max) unless explicitly overridden to unlimited.
- Prefer more specific tags when applicable: `xxe` for XML bomb, `brute_force` for auth endpoint flooding, `race_conditions` for thread exhaustion.

## Severity

| Pattern | Severity |
|---------|----------|
| XML entity bomb (billion laughs) without entity limit | High |
| ReDoS: user-controlled regex pattern server-side | High |
| Zip/Tar decompression bomb without size limit | High |
| Unbounded file upload (no size limit) | Medium |
| Missing pagination on bulk data endpoints | Medium |
| Missing rate limiting on auth endpoints | N/A — use `brute_force` tag |
| User-controlled hash iterations (bcrypt rounds) | Medium |

## Sources, Sinks & Sanitizers

**Sources**: remote user input controlling regex pattern, allocation size, loop bound, XML payload, archive stream, JSON validation depth.

**Sinks**: `RegExp`/`Pattern.compile`, `Buffer.alloc(n)`, large array loops, `setTimeout(ms)`, XML parsers with entity expansion, unzip without size cap, Express handlers without rate limit middleware.

**Sanitizers**: constant regex patterns; capped `Math.min(size, MAX)`; `disallow-doctype-decl` / secure XML features; rate-limit middleware (`express-rate-limit`); `ajv` without `allErrors: true`.

Commonly affected languages: JavaScript, Java, Python, Ruby, C#, Go, Rust, Swift.

**Not modeled**: database calls in loops; Java hash-collision DoS (HashDoS). Generic "missing pagination" without tainted page size requires explicit unbounded tainted allocation for HIGH severity per existing analyst rules.

## LLM/AI unbounded consumption (OWASP LLM10)

LLM inference is expensive, so resource and *cost* exhaustion ("denial of wallet") is a real DoS vector for AI endpoints. The amplifier is attacker-controlled token volume, not just request count.

**Sources**: user prompt length/complexity; uncapped `max_tokens`; recursive/agentic loops; high-volume or systematic querying (also a model-extraction signal).

**Sinks**: `*.create`/`generate`/`invoke` calls with no input-size cap and no output `max_tokens`; chat endpoints with no per-user rate limit or token/cost budget; agent loops with no step/iteration cap.

**Sanitizers / safe patterns**:
- Enforce input size limits (chars/estimated tokens) and reject token-amplifying repetitive input before calling the model.
- Always set an output `max_tokens` cap.
- Apply multi-tier rate limits (per minute/day) and per-user **token/cost budgets**; return `429`/`503` rather than processing unbounded load.
- Bound agent loops (max steps) and monitor for systematic high-volume querying (model-extraction pattern).

**Triage**: uncapped input *and* output on a public, attacker-reachable LLM endpoint with no rate limit/budget → Medium/High (denial of wallet / service). A missing rate limit alone is a defense-in-depth gap (Info/Low) unless unbounded token amplification is demonstrable. Prefer `brute_force` for auth-endpoint flooding; use this section for inference cost/volume exhaustion.

## Goroutine / async-task resource leaks (Go)

Long-lived servers leak memory and scheduler capacity when goroutines (or other async tasks) are spawned per request but can never terminate. Under attacker-driven request volume each leaked goroutine pins its stack and any captured resources, degrading the service until OOM — an unbounded-consumption DoS reachable from any handler that spawns work.

**Recon — leak-prone patterns**:
- **Blocked send on an unbuffered/full channel** — `go func(){ ch <- v }()` with no guaranteed receiver; the sender parks forever.
- **Blocked receive that never arrives** — `go func(){ <-done }()` where `done` is never closed/signalled on all paths.
- **Forgotten sender in fan-out** — early `return` after reading the first result leaves remaining workers blocked on `results <-`.
- **Context never cancelled** — `ctx, _ := context.WithCancel(...)` (cancel func discarded) so a `<-ctx.Done()` goroutine waits forever. Always keep and `defer cancel()`.
- **`time.After` in a loop** — each iteration spawns a timer goroutine that lives until it fires; use a single reset `time.NewTimer`/`time.Ticker`.
- **`time.NewTicker`/`NewTimer` never stopped** — missing `defer t.Stop()` leaks the timer goroutine.
- **Missing `wg.Done()`** — a path that skips `wg.Done()` makes `wg.Wait()` (and its goroutines) hang.
- **Infinite work loop with no exit/`ctx` check** — `for { ... }` goroutine with no cancellation path.

**Sanitizers / safe patterns**: buffered channels sized to senders, or `select { case ch<-v: case <-ctx.Done(): }`; always `defer cancel()` / `defer t.Stop()` / `defer wg.Done()`; bound spawned goroutines with a worker pool or semaphore; give every goroutine a `ctx` exit path.

**Triage**: per-request goroutine spawn reachable from a remote handler with no termination guarantee → Medium (resource exhaustion). Bounded/one-shot background goroutines with a clear exit are not findings.

## Missing HTTP server timeouts — slow-client / Slowloris (Go)

A Go HTTP server with no read/write/idle timeouts lets a single client hold a connection open indefinitely (dribbling headers or a slow body), so a small number of slow connections exhausts the accept queue and starves legitimate traffic — an availability DoS reachable on any public listener.

**Recon — unhardened server patterns**:
- **`http.ListenAndServe(addr, handler)`** / `http.ListenAndServeTLS(...)` — the package-level helpers use a default server with **no** `ReadTimeout`, `ReadHeaderTimeout`, `WriteTimeout`, or `IdleTimeout`.
- **`&http.Server{Addr: ...}`** constructed without `ReadTimeout`/`ReadHeaderTimeout` and `WriteTimeout`/`IdleTimeout` set.
- No `MaxHeaderBytes` cap (defaults to 1MB, but unbounded header *time* is the Slowloris vector — the timeout is what matters).

```go
// VULNERABLE: no timeouts → slow-client / Slowloris exhaustion
http.ListenAndServe(":8080", handler)
srv := &http.Server{Addr: ":8080", Handler: handler} // missing all timeouts

// SAFE: bound how long any one connection can occupy a server slot
srv := &http.Server{
    Addr:              ":8080",
    Handler:           handler,
    ReadHeaderTimeout: 5 * time.Second,  // critical for Slowloris (slow header dribble)
    ReadTimeout:       10 * time.Second,
    WriteTimeout:      10 * time.Second,
    IdleTimeout:       120 * time.Second,
    MaxHeaderBytes:    1 << 20,
}
```

**Sanitizers / safe patterns**: set `ReadHeaderTimeout` (and ideally `ReadTimeout`/`WriteTimeout`/`IdleTimeout`) on the `http.Server`; for long-lived/streaming handlers use per-request `http.ResponseController` deadlines instead of leaving the server-wide timeouts at zero; front the service with a timeout-enforcing reverse proxy.

**Triage**: a public/attacker-reachable Go listener with no `ReadHeaderTimeout`/`ReadTimeout` → Medium (slow-client connection exhaustion). Internal-only listeners, or servers behind a proxy that enforces timeouts, are Low/Info. A server with read/idle timeouts configured is not a finding.

## Unreleased resource leaks (CWE-404 / CWE-772)

Handles acquired per request but not released on **every** path (especially exception paths) accumulate until the process exhausts file descriptors, connection-pool slots, threads, or native memory — an availability DoS reachable from any handler that opens a resource under attacker-driven volume. This is the managed-language analogue of the Go leak above (Java/Kotlin, C#, Python, JS/Node, Go `io.Closer`).

**Recon — leak-prone patterns**:
- **`Closeable`/`AutoCloseable` opened without try-with-resources** — Java `new FileInputStream(...)`, `Socket`, `Connection`/`Statement`/`ResultSet` (JDBC), `InputStream`/`Reader` assigned to a local and closed only on the happy path (a throw before `close()` leaks).
- **`close()` inside `try` instead of `finally`** — any exception between open and `close()` skips release; pre-Java-7 idiom without `finally`, or `finally` that closes only the outer resource and leaks inner ones.
- **JDBC chains partially closed** — closing `Connection` but not `Statement`/`ResultSet`, or returning a pooled `Connection` only on success so errors drain the pool.
- **C# `IDisposable` without `using`** — `new SqlConnection(...)`/`FileStream` not wrapped in `using`/`await using` and not disposed in `finally`.
- **Python file/socket/cursor without `with`** — `open(...)`, `socket.socket()`, DB `cursor()` held in a variable and closed only on success; generators that `yield` an open handle never finalized.
- **Node.js streams/handles** — `fs.open`/`createReadStream`/DB clients without `finally`-close or pipeline error handling; listeners added per request via `.on(...)` never removed.
- **Native / pooled handles** — thread pools, `ExecutorService` never `shutdown()`, memory-mapped buffers, temp files opened but never deleted (cross-ref `insecure_temp_file.md`).

**Sanitizers / safe patterns**: language-native scoped release — Java try-with-resources `try (var in = ...) { }`, C# `using`, Python `with`, Go `defer x.Close()`; close inner-then-outer resources in `finally`; return pooled connections in `finally`; bound pool sizes and set acquisition timeouts so a leak fails fast rather than hanging.

**Triage**: a resource opened on a remote-reachable path with a release that is missing or skippable on exception → Low/Medium (resource exhaustion; raises to Medium when attacker-controlled request volume can drive exhaustion of a bounded pool/FD limit). A resource closed on all paths (try-with-resources/`using`/`with`/`defer`) is not a finding. Pure single-run scripts/CLIs where leak has no availability impact are Info at most.
