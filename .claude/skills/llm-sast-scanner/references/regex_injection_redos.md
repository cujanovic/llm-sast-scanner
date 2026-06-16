---
name: regex-injection-redos
description: Regular expression injection, ReDoS, incomplete regex validation, and incomplete sanitization patterns
---

# Regular Expression Injection / ReDoS / Incomplete Validation (CWE-1333, CWE-730, CWE-020, CWE-625, CWE-116)

User-controlled data fed into regular expressions can change regex semantics (injection) or trigger catastrophic backtracking (ReDoS). Separately, regex-based *validation* and *sanitization* that is incomplete—missing anchors, permissive dot ranges, single-pass replace—creates authorization bypass, SSRF, and injection chains in web apps.

## Source -> Sink Pattern

**Sources** (remote / active threat-model sources):
- HTTP query/body/path params, cookies, headers
- WebSocket / postMessage payloads
- URL components used in redirect/SSRF allowlists

**Sinks — regex injection / ReDoS (CWE-730, CWE-1333)**:
- `new RegExp(userInput)` / `RegExp(userInput)` (JS)
- `Pattern.compile(userInput)` / `String.matches(userPattern)` (Java)
- `re.compile(userInput)` / `re.search(userPattern, …)` (Python)
- `Regexp.new(userInput)` / `Regexp.compile(userInput)` (Ruby)
- `Regex::new(userInput)` (Rust)
- `Regex(userInput)` (C#, Go via `regexp.MustCompile` with tainted input)
- Any tainted regex applied to unbounded user-controlled *subject* strings (ReDoS)

**Sinks — incomplete validation (CWE-020, CWE-625)**:
- Hostname / URL allowlist checks via `.includes()`, substring match, or unanchored regex
- Redirect / SSRF guards using `url.includes(allowedHost)` instead of parsed host comparison
- Auth path checks where `.` in regex matches `/` (CWE-625 permissive-dot pattern)

**Sinks — incomplete sanitization (CWE-116)**:
- `str.replace("'", "''")` without global flag (single replacement)
- `str.replace(/pattern/g, "")` where pattern matches multi-char sequences once (unsafe text reappears)
- HTML tag filters using overly broad or backtracking-heavy regex (`BadTagFilter`)

## Vulnerable Conditions

- Attacker controls the regex *pattern* (injection + unbounded complexity).
- Attacker controls the regex *subject* and the pattern has nested quantifiers / overlapping alternation (ReDoS).
- Allowlist uses substring search: `url.indexOf("example.com") !== -1` bypassed by `evil-example.com` or `example.com.evil.net`.
- Hostname regex lacks `$` anchor: `/^([a-z]+\\.)*example\\.com/` matches `example.com.attacker.tld`.
- `.` in URL-matching regex without escaping: matches path separators → auth bypass (CWE-625).
- Sanitizer removes `../` once: `".../...//"` → `"../"` after one pass.

## Safe Patterns

- **Injection**: escape meta-characters before embedding (`_.escapeRegExp`, `Pattern.quote`, `re.escape`).
- **ReDoS**: use linear-time validators (email libraries, `validator.js`), RE2-style engines where available, or timeout guards; never compile user-supplied patterns.
- **Hostname / URL**: parse with `URL` / `urllib.parse` / `java.net.URI`, compare `hostname` to an explicit allowlist; anchor regex with `^…$`.
- **Sanitization**: use vetted libraries (`sqlstring`, `DOMPurify`, `sanitize-html`); if replacing, use global regex or loop until stable; prefer character-class deletion over multi-char pattern replace.

Commonly affected languages: JavaScript, Java, Python, Ruby, C#, Go, Rust, Swift.

## Sanitizers / Barriers

- **Incomplete sanitization (JS)**: global-regex replace (`/g` flag); well-known library calls (`sqlstring`, `sanitize-html`); repeated replace until fixed point (multi-char sanitization).
- **ReDoS**: pattern is fully compile-time constant; subject length bounded; `Pattern.quote` / `_.escapeRegExp` on injected portion only (does not fix bad static pattern on unbounded input).

## Language Patterns

### JavaScript / Node
- **VULN**: `new RegExp(req.query.filter).test(input)` — user pattern
- **VULN**: `/^(a+)+$/.test(req.body.email)` — catastrophic static pattern on user string
- **VULN**: `if (redirectUrl.includes('example.com'))` — substring allowlist
- **SAFE**: `_.escapeRegExp(user) ` embedded in fixed template; `new URL(u).hostname === 'example.com'`

### Java / Spring
- **VULN**: `Pattern.compile(request.getParameter("regex")).matcher(data).find()`
- **VULN**: URL guard regex with unescaped `.` matching path separators
- **SAFE**: `Pattern.quote(userFragment)`; hostname check after `URI.create(url).normalize()`

### Python
- **VULN**: `re.search(request.args['pat'], text)` with user `pat`
- **VULN**: `if 'trusted.com' in url:` before redirect
- **SAFE**: `re.escape(user)`; `urllib.parse.urlparse(url).hostname in ALLOWED`

### Go
- **VULN**: `regexp.MustCompile(r.FormValue("pattern")).MatchString(s)` — regex injection (logic bypass; large patterns / huge repetition counts), not classic ReDoS (Go `regexp` uses RE2 finite automata)
- **SAFE**: anchored host regex `^([a-z0-9-]+\\.)*example\\.com$` plus parsed URL check

### Ruby
- **VULN**: `Regexp.new(params[:re]).match(str)`
- **SAFE**: `Regexp.escape(params[:re])` in fixed pattern; `URI.parse(url).host`

### C#
- **VULN**: `new Regex(userInput).IsMatch(data)` on attacker-controlled pattern
- **SAFE**: `Regex.Escape(userInput)`; strict host whitelist on `Uri.Host`

### Rust
- **VULN**: `Regex::new(&user_pattern)?` then match on request body — regex injection (logic bypass; large compiled programs / huge repetition counts), not classic catastrophic-backtracking ReDoS (Rust `regex` crate uses finite automata)
- **SAFE**: fixed regex only; use `regex::escape` for literal portions

## Common False Alarms

- Regex fully hardcoded and applied to bounded input (short max length enforced in code).
- Incomplete-substring query on non-security redirect (still worth fixing, not always exploitable).
- ReDoS on patterns proven linear-time; verify subject is actually user-controlled and unbounded before CRITICAL rating.
- Sanitizer library call (`sqlstring`, `DOMPurify`) — downgrade to false positive.

## Business Risk

- ReDoS on login/search endpoints → single-request CPU hang, outage of shared Node/Java workers.
- Regex injection in WAF bypass or filter evasion → secondary XSS/SQLi/SSRF.
- Incomplete hostname check → open redirect and SSRF allowlist bypass.
- Incomplete HTML/path sanitization → stored XSS and path traversal.

## Core Principle

Never compile user-supplied regex. For validation, parse URLs and compare structured fields—not substrings. For sanitization, use library primitives with global replacement or repeat-until-stable; treat every regex-based strip of `../`, HTML tags, or metacharacters as guilty until proven repeated or character-safe.
