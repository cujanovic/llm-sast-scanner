---
name: denial_of_service
description: Denial of Service detection — vulnerable code patterns for ReDoS, XML bomb, Zip bomb, resource exhaustion, unbounded operations, and missing rate/size limits
---

# Denial of Service (DoS)

DoS vulnerabilities occur when user-controlled input can trigger unbounded computation, memory allocation, or I/O operations. This includes algorithmic complexity attacks (ReDoS), decompression bombs, XML entity expansion, unbounded uploads, catastrophic regex backtracking, and missing pagination/rate limits.

## GraphQL Structural DoS

GraphQL endpoints accept declarative query documents that can amplify server work in ways REST routes typically cannot — deep nesting on cyclic types, alias/field/directive duplication, HTTP array batching, unbounded pagination arguments, circular fragments, and missing execution timeouts. **GraphQL-specific** depth/complexity/cost limits, batch caps, pagination bounds, and resolver amplification patterns are covered in **`graphql_dos.md`**. This file retains generic DoS (ReDoS, zip/XML bombs, slow-client, goroutine leaks, unbounded uploads); do not duplicate GraphQL query-cost detail here.

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

**Writing a backtracking-safe regex** — a *hardcoded* pattern can still be catastrophic (e.g. `(\w+\s*)+please`), so "the regex is a constant" is not sufficient. When you must match untrusted text:
- Quantify only a single character class or a fixed alternation — never a *group* that itself contains a quantifier (`(\w+\s*)+` → `[\w\s]+`).
- No nested or overlapping quantifiers (`(a+)+`, `(a|ab)+`).
- Bound open-ended quantifiers with an explicit upper limit (`{0,N}`) and cap how far a single run is scanned.
- Bound the number of matches collected (stop after N).
- For tokenizing/searching long untrusted text, prefer an allocation-free linear scan over a backtracking regex.

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

### Cache-poisoning DoS

Attacker poisons a **shared HTTP/CDN cache** with an empty, broken, or error response that is stored under a key normal users request — denying service to everyone who hits that URL until the entry expires or is purged. Typical poison bodies: `{}`, blank HTML, or cacheable **4xx/5xx** with `Cache-Control: public` / `s-maxage`.

**Common vectors**: framework data routes and middleware short-circuits (Next.js `x-middleware-prefetch` / `__nextDataReq`, Nuxt `/_payload.json`) where an attacker-controlled header or query produces a minimal cacheable response. Full framework patterns, version checks, and grep seeds live in `web_cache_deception.md`.

**SAST signal**: `Cache-Control: public` or `s-maxage` on handlers that return `{}`, empty bodies, or error statuses without `private`/`no-store`.

**Triage**: demonstrated or structurally obvious cacheable empty/error response on a high-traffic route → Medium/High availability impact. Prefer tag `web_cache_deception` when the caching/keying misconfiguration is primary; use `denial_of_service` when reporting pure availability denial without cross-user data leakage or XSS.

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

**Sources**: user prompt length/complexity; uncapped `max_tokens`; recursive/agentic loops; high-volume or systematic querying (also a model-extraction signal). **Context-window flooding** is a concrete amplifier: a long run of repeated/identical characters or a near-duplicate filler block padded into the prompt inflates token count and crowds out instructions — e.g. a single character repeated hundreds of times.

**Sinks**: `*.create`/`generate`/`invoke` calls with no input-size cap and no output `max_tokens`; chat endpoints with no per-user rate limit or token/cost budget; agent loops with no step/iteration cap.

**Sanitizers / safe patterns**:
- Cap input by **bytes/chars** and **truncate with an explicit flag** (never silently drop) before the model call; reject token-amplifying repetitive input.
- Flag a **repeated-character run above a threshold** (e.g. a run of >200 identical chars within an input over a few hundred chars) as a context-flooding signal.
- Always set an output `max_tokens` cap.
- Apply multi-tier rate limits (per minute/day) and per-user **token/cost budgets**; return `429`/`503` rather than processing unbounded load.
- Bound agent loops (max steps) and monitor for systematic high-volume querying (model-extraction pattern).

**Framework cap-parameter specifics** (the absence of these is the finding):
- **Output cap by SDK**: OpenAI `max_tokens` / `max_completion_tokens` (the latter is required for o-series/reasoning models — `max_tokens` is ignored there); Anthropic `max_tokens` (SDK-required, so the risk is an *effectively unbounded* value like `100_000` on a user-facing path); Vercel AI `maxTokens`.
- **Agent-loop cap by framework**: LangChain `AgentExecutor(max_iterations=, max_execution_time=)` — `max_iterations` **defaults to 15** (bounded by default, but routinely raised, or explicitly set to `None` = unlimited), while **`max_execution_time` defaults to `None` = no wall-clock cap**; flag an explicit `max_iterations=None`/very-high value, or a loop whose only bound is time with no cap set; LangGraph `recursion_limit` in `.compile`/config; LlamaIndex `ReActAgent.from_tools(max_function_calls=)`; Vercel AI `maxSteps`.
- **Global-client-default false-negative trap**: a bare `openai.chat.completions.create(...)` with no `max_tokens` may be capped by an `OpenAI(default_query={"max_tokens": ...})` / default on the client constructor — **check the client constructor before flagging a bare call site.**
- **Model-refusable base case**: a depth/step counter is sound, but a loop whose only exit is the model emitting "Final Answer" is *not* bounded — adversarial tool output can prevent that string indefinitely. The guard must be one the model output cannot bypass.
- **Recursive / fan-out spawn** over a user-controlled task list (`asyncio.gather(*[...])`, `Promise.all(tasks.map(...))`, subagent fan-out) with no element-count or depth cap is the **critical** tier (exponential cost).
- **Input axis is separate from output axis**: a correct `max_tokens` does nothing about an unbounded user-supplied document concatenated into the prompt — that exhausts the context window and inflates token-count cost independently. Cap input bytes/chars even when the output cap is set.

**Triage**: uncapped input *and* output on a public, attacker-reachable LLM endpoint with no rate limit/budget → Medium/High (denial of wallet / service). A missing rate limit alone is a defense-in-depth gap (Info/Low) unless unbounded token amplification is demonstrable. Prefer `brute_force` for auth-endpoint flooding; use this section for inference cost/volume exhaustion.

## Denial of wallet — metered third-party calls (non-LLM)

"Denial of wallet" is not only an LLM-token problem. A low-friction endpoint that triggers a **metered, billable third-party call per request** is an amplifiable resource even when each call is cheap and bounded: the attacker loops it to run up *your* bill, drain a provider quota, or abuse a paid channel. The amplifier here is **inter-request** (many cheap calls → large cost), not the intra-request allocation/recursion/token-expansion the rest of this file models — so the "don't flag a mere missing rate limit" rule does **not** dismiss it: the per-request billable cost *is* the unbounded resource.

**Sinks** (a request-reachable call to a paid provider with no abuse gate):
- **Email**: `resend.emails.send`, `sgMail.send` (SendGrid), `ses.sendEmail`, Postmark/Mailgun send → mail bombing + send-cost / sender-reputation burn.
- **SMS / voice**: `twilio…messages.create`, `sns.publish` (SMS), Vonage/MessageBird send → **SMS pumping / toll fraud** (attacker controls premium-rate destination numbers).
- **Payments / ledger**: Stripe/PayPal `…create` (charges, payment intents, transfers, payouts) reachable without authorization.
- **Push / fan-out**: FCM/APNs/webhook fan-out that sends N messages per request with no cap.

**Detection**: a route handler / server action / public endpoint that reaches one of the above with **no abuse gate** — *none of* authentication, rate limit / throttle, CAPTCHA / bot check, or a per-recipient/per-user cap. A public endpoint is acceptable **iff** it has at least one such gate.

**Safe patterns**: require auth or a per-IP/per-user rate limit before the metered call; CAPTCHA on unauthenticated send paths; per-recipient and per-window caps; for SMS, a destination-country/number allowlist (anti-pumping).

**Triage**: unauthenticated (or trivially reachable) endpoint that fires a metered email/SMS/payment call with no gate → Medium (denial of wallet); High when the channel is high-cost (SMS/voice/payments) or the cap is entirely absent. Distinguish from `verification_code_abuse`/`brute_force` (flooding a *victim* with codes) — this class is the attacker draining *your* budget/quota.

## Atom-table exhaustion (BEAM / Erlang / Elixir)

On the BEAM VM the **atom table is a fixed-size, non-garbage-collected global** (default cap ~1,048,576). Converting unbounded **user input** to atoms grows it permanently; once full, the node **crashes** — a single attacker can take down the whole VM (availability DoS, CWE-400/CWE-770). This is BEAM-specific and absent from generic resource-exhaustion checks.

**Sinks** (flag when the argument is request-derived): Erlang `list_to_atom(UserInput)`, `binary_to_atom(UserBin, utf8)`; Elixir `String.to_atom(input)`, `:erlang.binary_to_atom(bin, :utf8)`. Also indirect: routing/JSON libraries configured to decode keys *as atoms* (e.g. `Jason.decode(body, keys: :atoms)`, `Poison` atom keys) on attacker JSON.

**Safe**: use the `*_to_existing_atom` family — `String.to_existing_atom/1`, `binary_to_existing_atom/2`, `list_to_existing_atom/1` — which only resolve already-defined atoms (attacker input can't grow the table); or keep identifiers as binaries/strings and decode JSON with **string** keys (`keys: :strings`). **Triage**: request-reachable `to_atom` on unbounded input → Medium/High (node crash).

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

## Slow-body / slow-JSON-stream (low-bandwidth body-read DoS)

A distinct, framework-agnostic evolution of slow-client: the attacker sends a **valid request body prefix** (e.g. `{"items":[{"a":1},`) via `Transfer-Encoding: chunked` (no `Content-Length`), then drips ~1 byte/sec and **never sends the closing `}`/`]`**. The server's **body reader / JSON parser blocks waiting for a body that never completes**, pinning a worker thread / goroutine / event-loop slot per connection — a few dozen connections exhaust the pool. It hits PHP/Laravel, .NET/Kestrel, Flask, Rails, Node, Go, Rust alike.

This is **not** header-Slowloris and **not** R.U.D.Y./Slow-POST: the headers complete normally (so `ReadHeaderTimeout` does **not** help), and there is no declared `Content-Length` (so body-size caps and Content-Length checks never trigger, and valid JSON sails past WAFs).

- **Smell:** a handler/middleware that reads or parses the **whole request body** (`express.json()`, `await req.json()`, `json.NewDecoder(r.Body).Decode`, `request.get_json()`, `JSON.parse(await readBody())`, model/DTO binding) with **no body-read timeout and no minimum body-data-rate** on the server. A request body **size** limit does **not** mitigate this — the attack is bounded by *time*, not *size*.
- **`ReadHeaderTimeout` is insufficient — it covers headers, not the body.** A Go server with `ReadHeaderTimeout` set but no whole-request `ReadTimeout` (or per-request `http.ResponseController` read deadline) is still vulnerable; treat header-timeout-only as a finding for body-reading endpoints.
- **Safe / framework knobs:** nginx `client_body_timeout` (+ `client_max_body_size`); Apache `RequestReadTimeout body=10,MinRate=500`; Kestrel `MinRequestBodyDataRate` (**disabled by default** — must be set non-null); Node `server.requestTimeout` (≥18, default now non-zero but verify it isn't disabled); Go whole-request `ReadTimeout` or a per-request body deadline; or front the app with a proxy that buffers the full body before forwarding. Prefer a streaming parser with a read-buffer/time cap over buffering the whole body.

**Triage**: a public/attacker-reachable endpoint that parses a request body with no body-read timeout / minimum data rate → Medium (worker-pool exhaustion; **High** in per-connection-worker models like PHP-FPM or thread-per-request, or in autoscaled microservices where it cascades). A body-size limit alone does not downgrade it; a configured body-read timeout / min-data-rate does.

## Missing client-side timeout on outbound calls (CWE-400 / CWE-1088)

The mirror image of slow-client: when **your** code makes an outbound network call with **no timeout**, a slow or unresponsive *peer* (a hung upstream API, a wedged DB, an attacker-controlled URL via SSRF) blocks the calling thread/worker **forever**. Under load — or with an attacker who can choose/influence the target — every worker ends up parked on a dead socket and the service stops serving (thread/connection-pool exhaustion), without any large payload. The default for most clients is **no timeout** (block indefinitely), so *absence* of an explicit timeout is the finding.

**Sinks (flag a network/IO call with no timeout argument set):**
- **Python stdlib**: `socket.create_connection(...)` / `sock.connect(...)` without `settimeout`/`timeout=`; `urllib.request.urlopen(url)` (no `timeout=`); `http.client.HTTPConnection(...)`; `ftplib.FTP`/`smtplib.SMTP`/`poplib.POP3`/`imaplib.IMAP4`/`nntplib.NNTP`/`telnetlib.Telnet` constructed without `timeout=`; `ssl.SSLContext.wrap_socket` over a timeout-less socket.
- **requests/httpx**: `requests.get/post/request(...)` with **no `timeout=`** (requests defaults to *wait forever*); `httpx` client without `timeout=`.
- **Other langs**: Go `http.Client{}` with no `Timeout` (and no per-request `context` deadline) / `net.Dial` without `DialTimeout`; Java `HttpClient`/`URLConnection` without `connectTimeout`/`readTimeout`; Node `http.request` with no `timeout` + no abort.

**SAFE**: set an explicit, finite `timeout=` (connect **and** read) on every outbound call; in Go use `http.Client{Timeout:…}` or a `context.WithTimeout`; bound the connection pool so a stall fails fast rather than queueing. **Triage**: outbound call on a request-serving path with no timeout → Medium (worker-pool exhaustion); **High** when the target host/URL is attacker-influenced (pairs with `ssrf.md` — a `169.254.169.254`/internal target that *tarpits* the connection). Internal one-shot scripts → Low/Info.

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
