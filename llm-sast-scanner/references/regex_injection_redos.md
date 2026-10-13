---
name: regex_injection_redos
version: "0.2"
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
- A fixed regex with a shape under Vulnerable Conditions run on an attacker-supplied *subject* that no short cap bounds (ReDoS; **Bounded Subjects** below); a tainted pattern is a sink on any subject (the sinks above)

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
- **Polynomial (quadratic/cubic) ReDoS — *sequential* overlapping quantifiers, not just nested.** The textbook `(a+)+` (exponential) is only the loudest case; far more common — and routinely missed by "look for nested quantifiers" reviews — is **two or more unbounded quantifiers in sequence whose character classes overlap**, giving quadratic/cubic (still DoS-grade) backtracking. Signatures: adjacent overlapping repeats where one class subsumes another (`\d+[^;]+`, `.*[a-z]+.*`, `\w+\w+`); **an optional/`*` section separating two unbounded quantifiers that share characters** — the classic **whitespace-ambiguity** shape `\s*(.+?)\s*` or `X\s*Y\s*Z` where each `\s*` can also match what its neighbor matches (real cases: `ssri` SRI parsing, CairoSVG `rgba\([ \n\r\t]*(.+?)[ \n\r\t]*\)`, cpython `http.cookiejar` Set-Cookie date parsing — all fed attacker-controlled headers/markup). **SAST signal**: `+`/`*`/`{n,}` quantifiers *adjacent* (directly or across an optional group) over classes that intersect (`\s`+`.`, `\d`+`\w`, `.`+anything), on a pattern matched against user-controlled input (headers, URLs, uploaded markup/CSS/SVG). These need **no nesting** to hang a backtracking engine. Same fix: RE2/linear engine, atomic groups/possessive quantifiers, a short input-length cap (**Bounded Subjects**), or match-then-strip instead of embedding `\s*` around a capture.
- **Search-retry (quadratic) ReDoS — one unbounded quantifier, an unanchored scan.** Every unanchored search retries the pattern at each start position: Python `re.search` / `findall` / `finditer` / `sub` / `split`, every JS regex method (`test`, `exec`, `match`, `matchAll`, `search`, `replace`, `split`, with or without `/g`), Java `Matcher.find()` / `String.replaceAll` / `split`, .NET `Regex.IsMatch` / `Match` / `Replace`, Ruby `=~` / `match` / `scan` / `gsub` (before 3.2 — see the Ruby barrier below), PHP `preg_*`. When the pattern's unbounded quantifier can also match its first token, and the match then needs a character the subject may lack, every start scans to the end: `<[^>]*>` over `<<<<…` with no `>`, `\s+$` over a run of spaces followed by a non-space — about n²/2 steps with no nesting and no adjacent overlap. Anchoring at the string start (`\A`, or `^` outside multiline mode — Ruby's `^` is always a line anchor) or an API that tries one position (Python `re.match` / `fullmatch`, Java `matches()` / `lookingAt()`, a JS sticky `/y` regex except in `split`, which tries every position whatever its flags) removes it; an end anchor (`$`) does not.
- **Degree under search.** A search API runs a shape from every start, so where the run that makes one start polynomial also opens a match at each of its own positions the degree rises by one: `\d+\d+;` over a run of digits is quadratic under `re.match` and cubic under `re.search` (1,000 digits: about 0.002 s and 0.6 s on CPython). Count the degree for the call the code makes.
- Allowlist uses substring search: `url.indexOf("example.com") !== -1` bypassed by `evil-example.com` or `example.com.evil.net`.
- Hostname regex lacks `$` anchor: `/^([a-z]+\\.)*example\\.com/` matches `example.com.attacker.tld`.
- `.` in URL-matching regex without escaping: matches path separators → auth bypass (CWE-625).
- Sanitizer removes `../` once: `".../...//"` → `"../"` after one pass.

## Safe Patterns

- **Injection**: escape meta-characters before embedding (`_.escapeRegExp`, `Pattern.quote`, `re.escape`).
- **ReDoS**: use linear-time validators (email libraries, `validator.js`), RE2-style engines where available, or a per-match timeout the engine enforces; never compile user-supplied patterns.
- **Hostname / URL**: parse with `URL` / `urllib.parse` / `java.net.URI`, compare `hostname` to an explicit allowlist; anchor regex with `^…$`.
- **Sanitization**: use vetted libraries (`sqlstring`, `DOMPurify`, `sanitize-html`); if replacing, use global regex or loop until stable; prefer character-class deletion over multi-char pattern replace.

Commonly affected languages: JavaScript, Java, Python, Ruby, C#, Go, Rust, Swift.

## Sanitizers / Barriers

- **Incomplete sanitization (JS)**: global-regex replace (`/g` flag); well-known library calls (`sqlstring`, `sanitize-html`); repeated replace until fixed point (multi-char sanitization).
- **ReDoS**: a linear-time engine the pattern compiles in with no backtracking fallback (RE2 and its bindings, Go `regexp`, Rust `regex`, .NET `RegexOptions.NonBacktracking`) — linear for one search; iterating every match (`FindAll`, `find_iter`, `ReplaceAll`, `split`) can be quadratic where an earlier alternative scans far before a later one matches short (`[a-z]*X|[a-z]`); `regexp2`, Python's `regex` module and `fancy-regex` (for look-around or backreferences) backtrack, as does a binding that falls back to a backtracking engine on syntax it does not support.
- **ReDoS**: a pattern shown linear for the scan the code runs (anchored at the string start or run at one position, as Vulnerable Conditions gives, with no shape listed there); a per-match timeout the engine enforces (.NET `matchTimeout`, `regexp2`'s `MatchTimeout`, Ruby 3.2+ `Regexp.timeout`, the Python `regex` module's `timeout=`), about a second or less as the C# SAFE example sets it — a timeout of many seconds is a limit too large to count; Ruby 3.2+'s match cache at the repository's pinned runtime, which runs a pattern with no backreference, negative look-around, atomic group, possessive quantifier or large or nested bounded repeat in linear time — PHP's `pcre.backtrack_limit` stops each `preg_*` call with `false`/`null`, so rate what the code does with that result; a short length cap enforced before the match (**Bounded Subjects**). A compile-time constant pattern is no barrier by itself; `Pattern.quote` / `_.escapeRegExp` on the injected portion stops injection only (does not fix a bad static pattern on an uncapped subject).

## Bounded Subjects

A bound clears a super-linear match only when the work at the bound is small. The work grows faster than the subject — about n² backtracking steps for a quadratic shape, n³ for a cubic one, about cⁿ for an exponential one (2ⁿ for `(a+)+`) — so a limit on the length n is not a limit on the work. This section bounds a fixed pattern's subject: no subject cap clears an attacker-supplied pattern, which sets its own base and degree (`((a+)+)+$` takes seconds on 17 characters in CPython); only never compiling it, a linear-time engine or a per-match timeout the engine enforces does.
- A cap counts when the code, a schema it validates, a limit the repository's deployment config sets (a queue's `MaximumMessageSize`, a body parser's `limit`) or a pinned framework's default shown at its code enforces it on the text the match reads, before the match, and the worst case at the cap is small: about 10⁷ steps or fewer for one match (a backtracking engine runs some 10⁸–10⁹ simple steps a second on a full core, fewer where groups backtrack). That allows a quadratic shape up to about 3,000 characters, a cubic one up to about 200, an exponential one up to about log_c 10⁷ characters (about 20 for `(a+)+`, 14 for `((a+)+)+`); a quadratic shape at 256 KiB is about 7×10¹⁰ steps (tens of seconds to minutes).
- A limit on a compressed or pointer form (a message body naming an object in storage) bounds nothing decompressed or fetched from it; a limit on base64, hex or percent-encoded text bounds the decoded text, which decoding only shrinks. A length the data's own format fixes — a UUID, an enum, a DNS label — is a structural bound (Verification Standard, gate 3), weighed by the same test.
- Once each match is capped at L characters, the work left grows only linearly with the input — about L steps per character for a quadratic shape, L² for a cubic one — and is rated as the base **Bounded DoS** guardrail rates iteration over the input (its natural bounds, a provider's size limit among them), not as this class: the cap clears the ReDoS, unless the code matches the same text over and over (once per pattern of a long list, or in a loop over the text's own length).
- A limit the repository does not set — a provider's maximum message size or invoke payload, the request-body limit of a platform it does not configure — is a provider limit (the note after Step 6's verdict table): it clears no super-linear match, grounds no `WITHDRAWN` or `DISPUTED`, and its documented value only sizes the attack. A cap too large to count narrows the attack without stopping it: no clearance, and no `WITHDRAWN` or `DISPUTED` on that ground.
- The base skill's **Bounded DoS** guardrail skips `denial_of_service` on a bound of the iterated or allocated data. A super-linear match costs more than that data's size, so a body or message size limit answers it only by the test above. The guardrail answers iterated or allocated data only: it clears no super-linear match and grounds no `WITHDRAWN` or `DISPUTED` of one.
- The handler's time budget is its function or request timeout as the repository's deployment config gives it, and what waits while the match runs: an event-loop thread, a shared consumer, the other records of a batch. A function timeout ends the invocation, not the attack: the record fails, and a queue or batch consumer retries it; a request timeout a gateway or an in-process server enforces ends neither — the match runs to its end. A time measured on a development machine understates a function holding a fraction of a CPU (an AWS Lambda below 1,769 MB holds part of one vCPU); state it as a lower bound.
- A producer's queue-write or invoke authority is a privileged position only where the Flow's attacker must hold it (Severity Downgrade Rule, Downgrade validity check): one level below, never a clearance. A relay of what another party supplied, or a write a repository workload makes of what a request, message or user supplied with no position its caller holds, lowers nothing. Input the repository shows only the operator writing is operator self-harm (False Positive Guardrails).
- A Clearance Record that clears on a cap names it as `safe-because <cap>@file:line` with the work at the cap (`quadratic, 512 chars ≈ 2.6×10⁵ steps`). A finding whose subject passes a limit too large to count names that limit's `file:line`, or that the repository sets none, and the work at it on its `Impact:` line.

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
- **VULN**: static backtracking-prone `Regex` (e.g. `new Regex(@"(?<x>[^\?]*)(?<q>\?.*)?")`, nested quantifiers, overlapping alternation) run on user input with **no `matchTimeout`** — `.NET` regex has no timeout by default, so a single request can pin a CPU core
- **SAFE**: pass a timeout — `new Regex(pattern, RegexOptions.None, TimeSpan.FromSeconds(1))` or `Regex.IsMatch(input, pattern, options, TimeSpan.FromSeconds(1))` (or set `AppDomain` `REGEX_DEFAULT_MATCH_TIMEOUT`); `Regex.Escape(userInput)`; strict host whitelist on `Uri.Host`

### Rust
- **VULN**: `Regex::new(&user_pattern)?` then match on request body — regex injection (logic bypass; large compiled programs / huge repetition counts), not classic catastrophic-backtracking ReDoS (Rust `regex` crate uses finite automata)
- **SAFE**: fixed regex only; use `regex::escape` for literal portions

## Common False Alarms

- Regex fully hardcoded and applied to bounded input (a short cap enforced before the match, as **Bounded Subjects** defines — a body or message size limit counts only by that test).
- Incomplete-substring query on non-security redirect (still worth fixing, not always exploitable).
- ReDoS on patterns proven linear-time for the scan the code runs; for a fixed pattern, verify the subject is attacker-supplied and no short cap bounds it (**Bounded Subjects**) before rating it.
- Sanitizer library call (`sqlstring`, `DOMPurify`) — downgrade to false positive.

## Severity (regex injection / ReDoS)

| Case | Severity |
|------|----------|
| Attacker-supplied pattern run server-side in a backtracking engine | High |
| Fixed super-linear pattern run on an attacker-supplied subject no short cap bounds | High |

In a linear-time engine a tainted pattern is rated by what the regex decides (a filter or allowlist it bypasses), not as ReDoS. Incomplete validation and sanitization are rated by the class they enable (`open_redirect`, `ssrf`, `xss`, `path_traversal_lfi_rfi`). Lowered only by a Severity Downgrade Rule trigger, an `UNCERTAIN cap:` or a Step 6 `DISPUTED` the note under its verdict table admits; a size limit is never a trigger — a path that needs a cap raised past every shipped config's value takes the non-default-configuration trigger (Scope), not a clearance — and a limit too large to count is no doubt.

## Business Risk

- ReDoS on login/search endpoints → single-request CPU hang, outage of shared Node/Java workers.
- Regex injection in WAF bypass or filter evasion → secondary XSS/SQLi/SSRF.
- Incomplete hostname check → open redirect and SSRF allowlist bypass.
- Incomplete HTML/path sanitization → stored XSS and path traversal.

## Core Principle

Never compile user-supplied regex. For validation, parse URLs and compare structured fields—not substrings. For sanitization, use library primitives with global replacement or repeat-until-stable; treat every regex-based strip of `../`, HTML tags, or metacharacters as guilty until proven repeated or character-safe.
