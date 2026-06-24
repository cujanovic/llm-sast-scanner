---
name: open-redirect
description: Open redirect and unvalidated forward detection (CWE-601), including allowlist/parser-confusion bypasses — protocol-relative, multiple slashes, backslash, userinfo @, encoded host, IDN/Unicode homoglyph, and bidi code-point evasions
---

# Open Redirect (CWE-601)

Identify cases where user-controlled input reaches a redirect or forward target without adequate validation or restriction.

## Source -> Sink Pattern

**Sources**: Query parameters (`url`, `redirect`, `next`, `return`, `returnTo`), POST body fields, path variables, and headers such as `Referer` that reach redirect/forward targets.

**Sinks (`url-redirection` kind)**:
- `response.sendRedirect(userInput)`
- `response.setHeader("Location", userInput)`
- `response.setStatus(302); response.setHeader("Location", userInput)`
- Spring: `return "redirect:" + userInput`
- `RequestDispatcher.forward(userInput)`
- `ModelAndView("redirect:" + userInput)`
- JavaScript server-side: `res.redirect(userUrl)`, `Location` response header writes
- JavaScript client-side: `window.location`, `location.href`, `location.assign` (browser redirect)
- Python: Flask `redirect()`, Django `HttpResponseRedirect`
- Go: `http.Redirect`, `Header().Set("Location", ...)`
- Ruby: Rails redirect helpers with user-controlled target
- C#: MVC `Redirect()`, `RedirectToAction` with tainted URL
- Java forward (CWE-552): `RequestDispatcher.forward(userInput)` — server-side forward, not browser redirect

**Sanitizers**: Hostname-sanitizing prefix, `contains` allowlist guard, `URI.getHost().equals(...)`, regexp check; Go additionally flags **insufficient** checks when validation is prefix-only `/` without rejecting `//` or `/\`. Same redirect guards as SSRF analysis; host comparison and allowlist membership where modeled.

Commonly affected languages: Java, JavaScript, Python, Go, Ruby, C#.

## Vulnerable Conditions
- User-supplied input flows directly into the redirect destination without transformation
- Validation only examines the prefix (e.g., `url.startsWith("/")`) — can be bypassed using `//evil.com` or `/\evil.com`
- Blocking-based (denylist) validation that attackers can route around

## Safe Patterns
- The redirect target is a hardcoded constant with no user input involved
- An allowlist explicitly enumerates every permitted redirect destination
- Relative paths are validated server-side and then prepended with a known base URL
- The URL is fully parsed and both scheme and host are verified against an approved list
- Java: validate against known fixed string before redirect
- Java: parse URL and verify host is same as current page or on allowlist
- Go: extend prefix check to reject second character `/` or `\` after leading slash
- **Indirection mapping**: user supplies opaque id/token/name; server resolves to a fixed URL from a static map — raw URL strings never accepted

```java
String dest = ALLOWED_REDIRECTS.get(request.getParameter("pageId"));
if (dest != null) response.sendRedirect(dest);
```

- **Reject absolute/external targets**: after parse, reject any value with scheme, authority/host, or protocol-relative prefix before issuing redirect

```python
parsed = urlparse(url)
if parsed.scheme or parsed.netloc or url.startswith("//"):
    abort(400)
return redirect(url)
```

- **Exact host match**: allowlist compares parsed host to full hostname — never suffix/substring/`endsWith`/`contains` on the raw string
- **Normalize before comparing**: decode percent-encoding, IDNA/punycode-normalize the host, and reject backslashes, multiple leading slashes, and control/non-ASCII bytes **before** the host check — so `///`, `\`, `%2e`, `。`/`｡`, and bidi/RTL code points cannot move the effective host past the allowlist
- **Authorization gate**: verify the authenticated subject may reach the mapped or allowlisted destination (forward/redirect)
- **External interstitial**: off-domain targets pass through a confirmation page; `Location` only set after explicit user consent
- **PHP**: always `exit`/`die` immediately after `header("Location: ...")` to prevent post-redirect logic execution

## Evasion Patterns
- `//evil.com` — protocol-relative URL that satisfies a `startsWith("/")` check
- `/\evil.com` — backslash parsed as a path separator by certain browsers
- `/%09/evil.com` — tab character inserted to break naive pattern matching
- `https://trusted.com@evil.com` — attacker host hidden in the authority/userinfo section
- URL encoding: `%2F%2Fevil.com`
- Go partial check bypass: `strings.HasPrefix(redir, "/")` passes for `//evil.com` and `/\evil.com` — weak prefix-only validation
- **Scheme-relative variants**: `//evil.com/path`, `/%2f%2fevil.com`, `\evil.com` (leading backslash)
- **Allowlist substring tricks**: `contains("trusted.com")` passes `https://evil.com/?x=trusted.com`; `endsWith(".trusted.com")` passes `evil-trusted.com`; `startsWith("https://trusted.com")` passes `https://trusted.com.evil.com`
- **Userinfo @ variants**: `https://trusted.com@evil.com`, `//trusted.com@evil.com`, `/trusted.com@evil.com`
- **CRLF in redirect value**: `%0d%0a` or literal `\r\n` embedded in param — flag taint reaching `Location`; classify as `http_response_splitting` only when CR/LF breaks header structure
- **Multi-layer encoding**: `%252f%252fevil.com` (double-encoded `//`), `\u002f\u002fevil.com`, `%5c%65vil.com` (encoded `\e`)
- **Mixed separators**: `/\/evil.com`, `//evil.com%2f@trusted.com` — parser/normalizer divergence vs naive prefix checks
- **Multiple leading slashes**: `///evil.com`, `////evil.com`, `/////evil.com` — browsers collapse the extra slashes and treat the value as protocol-relative, while a guard that inspects only the first one or two characters (`startsWith("/")` and `!startsWith("//")`) passes it
- **Backslash as authority separator**: browsers normalize `\` to `/`, so `\\evil.com`, `\/\/evil.com`, `/\/evil.com`, `//\/evil.com` all resolve to an off-site protocol-relative target that slash-only checks miss
- **Parser-confusion via userinfo delimiters**: the validator and the browser disagree on where the host ends. `https://trusted.com#@evil.com`, `https://trusted.com?@evil.com`, `https://trusted.com:80#@evil.com`, `https://trusted.com;@evil.com`, a bare leading `@evil.com`, multiple `@` (`a@trusted.com@evil.com`), and encoded forms (`%40`, `%23`, `%3F`, Unicode small semicolon `﹔`) move the real host past a prefix/`contains` allowlist
- **Encoded host metacharacters**: `%2e` / double-encoded `%252e` for the dot (`trusted.com%2eevil.com`), `%2f`/`%5c` inside the host, and `%40` for `@` — decode server-side to push the effective host outside an allowlisted prefix
- **Scheme obfuscation**: colon-only scheme with no slashes (`https:evil.com`, `http:evil.com`), encoded scheme colon (`https%3A/evil.com`), and `javascript:`/`data:` schemes hidden via HTML entities (`javascript&#58;`, `&colon;`, `&Tab;`/`&NewLine;`), `\xNN`/`\uNNNN`/octal `\NNN` escapes, or embedded newlines/tabs (`java%0ascript:`, `java%09script:`) — bypass denylists matching the literal scheme string
- **IDN / Unicode host homoglyphs**: full-width or alternative code points that a parser maps back to ASCII — e.g. ideographic full stop `。` (`%E3%80%82`) or half-width `｡` used as the dot, full-width letters, and homoglyph domains — defeat an exact-string host compare unless the host is IDNA/punycode-normalized first
- **Bidi / line-separator code points**: right-to-left override `%E2%80%AE`, line/paragraph separators `%E2%80%A8` / `%E2%80%A9`, plus `%a0` / `%19` / `%01` control bytes inserted into the scheme or userinfo to spoof the visible host or break a `javascript:` filter
- **Control / invalid bytes in host**: `%00`, `%FF`, raw tab/newline (`%09`/`%0a`/`%0d`), and unpaired surrogates around the `@` — exploited where the validator stops at the byte but the browser's parser does not
- **IP-address host encodings** (when the allowlist is IP-based): decimal (`http://3627734734`), hex (`http://0xd8.0x3a.0xd6.0xce`), octal (`http://0330.072.0326.0316`), and IPv6-mapped (`http://[::ffff:127.0.0.1]`) forms — see `ssrf.md` for the full IP-encoding matrix

**SAST principle for all of the above**: any allowlist/denylist applied to the **raw string** (prefix, suffix, `contains`, regex) is bypassable because the validator and the browser's URL parser disagree on scheme/host boundaries. Safe validation parses the value with a spec-compliant parser (WHATWG URL / `java.net.URI` / `urlparse`), **IDNA/punycode-normalizes the host**, then compares the parsed host against an exact allowlist and rejects any non-`http(s)` scheme, backslash, or control character.

## Detection Indicators (grep)

Token-aware sink hunts — trace matched identifiers back to request/query/body/header sources.

### Redirect sinks
```text
sendRedirect\s*\(
\.redirect\s*\(
redirect:\s*["']?\s*\+
ModelAndView\s*\(\s*["']redirect:
setHeader\s*\(\s*["']Location["']
headers\.setLocation\s*\(
HttpResponseRedirect\s*\(
redirect\s*\(
http\.Redirect\s*\(
header\s*\(\s*["']Location:
Response\.Redirect\s*\(
RedirectToAction\s*\(
redirect_to\s
location\.(href|assign|replace)\s*=
window\.location\s*=
res\.writeHead\s*\([^)]*Location
```

### Forward sinks (CWE-552)
```text
getRequestDispatcher\s*\(
RequestDispatcher\.forward\s*\(
\.forward\s*\(
dispatch\s*\(
include\s*\(
```

### Common source parameter names
```text
(url|redirect|next|return|returnTo|returnUrl|goto|destination|target|continue|redir|forward|fwd|callback|RelayState)
```

### Weak-validation signals (pair with sinks)
```text
startsWith\s*\(\s*["']/["']
HasPrefix\s*\([^,]+,\s*["']/["']
indexOf\s*\(\s*["']trusted
endsWith\s*\(\s*["']\.trusted
\.contains\s*\(\s*["']trusted
match\s*\(\s*["']\^/
```

### High-confidence taint chains
- Sink argument is `request.getParameter`, `req.query`, `req.body`, `request.GET`, `$_GET`, `params[`, `QueryString[`, `c.Query(`, `Referer` header — no parse/allowlist between source and sink
- `redirect:` / `Location` value built via string concat (`+`, `fmt.Sprintf`, template literal) with user-controlled fragment

## Java / Spring Detection Rules

- `return "redirect:" + target`, `new ModelAndView("redirect:" + target)`, `response.sendRedirect(target)`, `headers.setLocation(URI.create(target))`, and `response.setHeader("Location", target)` are all open-redirect sinks when `target` is user-controlled.
- Do not relabel a plain attacker-chosen redirect destination as `http_response_splitting` unless the evidence shows CR/LF injection into the header value; without header-breaking characters it remains `open_redirect`.
- On repeat benchmark runs, keep `open_redirect` for a reachable user-controlled redirect target even when the same flow also writes a `Location` header or participates in a login redirect chain; only add or replace it with `http_response_splitting` when the evidence contains actual CR/LF header breaking.

## Python/JS/PHP Source Detection Rules

### Python (Flask / Django)
- **VULN**: `return redirect(request.args.get('next'))` — user-controlled redirect target
- **VULN**: `return redirect(request.args.get('url'))` without URL validation
- **VULN (Django)**: `return HttpResponseRedirect(request.GET.get('redirect'))` — no validation
- **SAFE**: `if url_has_allowed_host_and_scheme(url, allowed_hosts={'example.com'}): return redirect(url)`
- **SAFE**: `return redirect(url_for('dashboard'))` — framework-generated internal URL

### JavaScript (Express / Node.js)
- **VULN**: `res.redirect(req.query.url)` — user-controlled redirect
- **VULN**: `res.redirect(req.body.returnTo)` — POST body controls destination
- **VULN**: `res.set('Location', req.query.next); res.status(302).end()`
- **SAFE**: URL parsed and host validated against allowlist before redirect
- **SAFE**: `res.redirect('/dashboard')` — hardcoded path

### PHP
- **VULN**: `header("Location: " . $_GET['url'])` — user-controlled redirect
- **VULN**: `header("Location: " . $_POST['redirect'])` — POST parameter controls destination
- **SAFE**: `if (in_array($_GET['url'], $allowedUrls)) header("Location: " . $_GET['url'])`
- **SAFE**: `header("Location: /dashboard")` — hardcoded

## Dynamic Test / PoC

Replace `PARAM` with the discovered redirect parameter (`url`, `redirect`, `next`, `returnTo`, `redirect_uri`, …). Inspect `Location` in response headers (`curl -s -D-`).

```bash
curl -s -D- 'https://TARGET/redirect?PARAM=https://evil.com'
curl -s -D- 'https://TARGET/redirect?PARAM=//evil.com'
curl -s -D- 'https://TARGET/redirect?PARAM=https%3A%2F%2Fevil.com'
curl -s -D- 'https://TARGET/redirect?PARAM=https://evil.com%40TARGET'
curl -s -D- 'https://TARGET/redirect?PARAM=https://TARGET%40evil.com'
curl -s -D- 'https://TARGET/redirect?PARAM=https://TARGET.evil.com'
curl -s -D- 'https://TARGET/redirect?PARAM=https://evil.com%23.TARGET'
curl -s -D- 'https://TARGET/redirect?PARAM=https://%65%76%69%6c.com'
curl -s -D- 'https://TARGET/redirect?PARAM=https://evil.com%00.TARGET'
curl -s -D- 'https://TARGET/redirect?PARAM=%0d%0aLocation:%20https://evil.com'
curl -s -D- 'https://TARGET/redirect?PARAM=javascript:alert(document.domain)'
curl -s -D- 'https://TARGET/redirect?PARAM=data:text/html,<script>alert(1)</script>'
```

**Scheme/parser bypasses** when host allowlist blocks bare `https://evil.com`:

```bash
curl -s -D- 'https://TARGET/redirect?PARAM=https:evil.com'
curl -s -D- 'https://TARGET/redirect?PARAM=/\evil.com'
curl -s -D- 'https://TARGET/redirect?PARAM=///evil.com'
curl -s -D- 'https://TARGET/redirect?PARAM=https://TARGET#@evil.com'
curl -s -D- 'https://TARGET/redirect?PARAM=https://TARGET%2eevil.com'
curl -s -D- 'https://TARGET/redirect?PARAM=//evil%E3%80%82com'
curl -s -D- 'https://TARGET/redirect?PARAM=//trusted.example/path/../@evil.com'
```

Confirmed when `Location` (or meta-refresh / client `location.assign`) resolves off-origin to an attacker-controlled host.

## Common False Alarms

- Redirect target is a hardcoded constant or framework-generated route (e.g., `url_for()`, `redirect('/')')
- URL is fully parsed and both scheme and host are verified against an explicit allowlist before the redirect
- Redirect is to a relative path that is prepended with a known base URL server-side
- Login redirect that only accepts relative paths starting with `/` AND rejects protocol-relative URLs (`//evil.com`)
- Internal forward/dispatch that does not result in an HTTP redirect response to the client
- Go weak-prefix validation on intentionally permissive relative-only redirects that also block `//` and `/\` elsewhere
- Client-side redirect sinks when the finding scope is server-side open redirect testing only

## Business Risk
- Phishing attacks that exploit a trusted domain's reputation
- OAuth token theft through manipulation of the `redirect_uri` parameter
- Session fixation when the redirect is embedded within login or authentication flows

## Core Principle

Never pass remote input directly into a redirect or forward destination. Maintain a server-side allowlist of permitted targets, or parse the URL and verify scheme and host against approved values before issuing `Location` or framework redirect responses.

## Analyst Notes

- Distinguish `open_redirect` from `http_response_splitting`: only escalate to header splitting when CR/LF characters are present in the tainted redirect value
- Spring `redirect:` view prefix patterns beyond servlet APIs are in scope for open-redirect analysis
- Client-side redirect sinks apply when tainted data reaches browser navigation APIs — relevant for SPA phishing, not server `Location` headers
- CWE-552 forward is information-disclosure class (server-side forward), not browser redirect — still tag when user input selects internal resources
