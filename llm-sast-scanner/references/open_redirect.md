---
name: open-redirect
description: Open redirect and unvalidated forward detection (CWE-601)
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

## Evasion Patterns
- `//evil.com` — protocol-relative URL that satisfies a `startsWith("/")` check
- `/\evil.com` — backslash parsed as a path separator by certain browsers
- `/%09/evil.com` — tab character inserted to break naive pattern matching
- `https://trusted.com@evil.com` — attacker host hidden in the authority/userinfo section
- URL encoding: `%2F%2Fevil.com`
- Go partial check bypass: `strings.HasPrefix(redir, "/")` passes for `//evil.com` and `/\evil.com` — weak prefix-only validation

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

## Common False Alarms

- Redirect target is a hardcoded constant or framework-generated route (e.g., `url_for()`, `redirect('/')`)
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
