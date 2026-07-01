---
name: input_validation
description: Detect missing or weak input validation as a standalone defense-in-depth finding (CWE-20) — a parameter, field, DTO property, or GraphQL argument whose name/semantics imply a constrained domain (email, zip/postal, phone, url, uuid, date, country, currency, locale, ip, numeric id, enum-like state) is typed as free-form String/JSON/text and reaches a store/use with no format, allowlist, schema, or scalar validation. Also covers validation-order bypasses where a value is normalized/case-mapped/decoded/stripped *after* it is validated (CWE-179/180 — Unicode NFKC, toUpperCase, URL-decode re-creating a payload the filter rejected) numeric NaN/inf parse-coercion bypasses, and Python security checks written as `assert` (silently stripped under `python -O`). Applies across all languages and GraphQL even when NO injection sink is present. Excludes legitimately free-text fields and already-validated inputs.
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

### Python NaN / numeric type-confusion (parse-coercion bypass)

A numeric field validated *after* coercion can be bypassed with the special float tokens `NaN`, `inf`, `-inf`: tainted request data passed to `float(...)`, `complex(...)`, or `bool(...)` (and `json.loads`, which parses bare `NaN`/`Infinity`) yields a value for which **every comparison is false** (`NaN < limit`, `NaN > limit`, `NaN == NaN` are all `False`). A range/threshold check (`if amount > MAX: reject`) therefore lets `NaN` through, and it can poison aggregates, balances, or auth scoring downstream. Flag tainted input reaching `float()`/`complex()`/`json.loads()` whose result feeds a comparison-based gate without an explicit `math.isnan()`/`math.isfinite()` (or NumPy `np.isnan`) check. **SAFE**: reject non-finite values (`if not math.isfinite(x): abort(400)`) or validate with a schema that disallows `NaN`/`inf` (pydantic `allow_inf_nan=False`).

### Canonicalize / normalize *after* validation (validation-order bypass, CWE-179 / CWE-180)

A general ordering defect: the code validates (or denylist-filters) the **raw** value, then a *later* step **transforms** the same value — Unicode normalization, case mapping, decoding, or character stripping — into something that would have failed the check, or that reconstitutes a payload. The validator inspected one string; the sink receives a different one. Distinct from the semantic-type gap above: validation may be *present and correct*, just in the wrong order.

Concrete transform-after-validation bypasses:
- **Unicode normalization (NFC/NFKC) after an HTML/keyword filter**: a `<script>`/tag filter passes because the input is `"﹤script﹥"` (small-form `<`/`>`), then a later `Normalizer.normalize(s, NFKC)` (or DB/template normalization) folds it to literal `<script>` → stored/reflected XSS. Same for fullwidth/compatibility forms folding to ASCII metacharacters.
- **Character deletion/replacement after validation**: stripping non-character or control code points *after* the filter rejoins a split token — input `"<scr﷯ipt>"` passes the `<script>` check, then removal of the non-character `﷯` yields `<script>`.
- **Case mapping after/within a check**: `toUpperCase()`/`toLowerCase()` is locale- and Unicode-lossy — `"ADMıN"` (dotless ı) uppercases toward `ADMIN`, `"ſcript"` (ſ) and `"ﬀ"` (ﬀ) case/normalize toward ASCII. A reserved-name or role gate that compares a *transformed* copy while trusting the original (or vice-versa) is bypassable.

**SAST signal**: a validation / denylist / `equals`/`matches`/`contains` check on a value, followed — *before the sink* — by `Normalizer.normalize` / `.normalize('NFKC'|'NFC')` / `unicodedata.normalize` / `toUpperCase` / `toLowerCase` / `casefold` / `URLDecoder.decode` / `replaceAll`/`replace` removing characters, applied to the **same** value. The transform downstream of the gate is the bug.

**SAFE**: canonicalize first, validate second — decode/normalize (to a **fixpoint**: repeat until the string stops changing), case-fold, and strip/reject disallowed code points **before** the allowlist/format check, then carry the *canonical* form to the sink unchanged; reject (don't silently strip) non-character/control code points. Domain-specific instances of this same principle: host allowlists `ssrf.md` (normalize/IDNA before compare), path filters `client_side_path_traversal.md` / `path_traversal_lfi_rfi.md` (decode-to-fixpoint before check), identity/reserved-name fields `business_logic.md` (NFKC + confusables skeleton before uniqueness/blocklist).

### Query-string parser differential (validate with one parser, consume with another)

A sibling of the ordering defect: the request's query string is **validated by one parser but consumed by a different one**, so the two disagree on the same bytes and a payload that passed validation reaches the sink. Common in Node — `qs` (Express `req.query`, bracket-aware) vs the browser/`URLSearchParams` (or vice-versa) — and PHP/Rack bracket parsing vs a flat reader. Divergences that smuggle a value past a validator: **bracket notation** (`a[b]=x` — `qs` builds a nested object while `URLSearchParams` sees the literal key `a[b]`, so a validator keyed on `redirect`/`q` never sees the value the sink reads), **`]=`/delimiter precedence**, **duplicate keys** (first-vs-last-wins mismatch), and **`qs` `parameterLimit` (default 1000)** — parameters past the cap are silently dropped by the server-side validator but still read by a downstream or client parser, so an XSS/`redirect`/SSRF payload hidden in overflow params or a bracketed key validates as *absent* yet is consumed as *present*. **SAST signal**: a security check that reads a param through one API (`qs.parse`, `req.query`, a framework validator) while the sink reads the **same** query through a different API (`URLSearchParams`, manual `location.search`/`split('&')`, or a second service). **SAFE**: validate and consume the query with the **same** parser; coerce each security-relevant key to a single scalar (reject arrays/bracket/duplicate shapes); re-validate the exact value handed to the sink.

The same **cross-parser differential** hits other structured formats parsed twice. **YAML tags**: a tag honored by one parser and dropped by another — Ruby Psych decodes a `!binary`/custom tag while Go `gopkg.in/yaml.v3` drops it — lets a field slip past a validator that never sees it yet reach the consumer that does, bypassing an allowlist/`parent`/type check across a Ruby↔Go (or any two-runtime) boundary. **General rule**: whenever the *same* request or document is parsed by two different parsers (edge vs origin, validator vs consumer, one language/library vs another), any value they decode differently defeats a check performed on only one of them — validate the exact representation the sink will use, or parse once and pass the parsed object.

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

## Cross-References

- GraphQL weak typing as an injection/IDOR/DoS **precursor**: `graphql_injection.md` (Schema-Level Input Validation, Custom Scalar Coercion).
- When the unvalidated value reaches a sink: `sql_injection.md`, `nosql_injection.md`, `ssrf.md`, `path_traversal_lfi_rfi.md`, `open_redirect.md`, `rce.md`, `xss.md`, `log_injection.md`, `regex_injection_redos.md`.
- Privileged-field binding: `mass_assignment.md`, `privilege_escalation.md`, `idor.md`.
- Size/cardinality (not format): `denial_of_service.md`, `graphql_dos.md`.

## Core Principle

Constrain at the boundary: prefer a precise type (`enum`, validated custom scalar, schema/DTO with anchored format) over a free-form string the resolver "remembers" to check. A semantically-constrained input accepted without validation is a Low finding even with no exploit today — it is missing data-integrity assurance and a standing injection precursor.
