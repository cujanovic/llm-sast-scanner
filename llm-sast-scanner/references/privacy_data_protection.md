---
name: privacy_data_protection
description: Privacy and data-protection weaknesses — over-collection, retention, consent, PII in URLs/analytics/third parties, and missing erasure support
---

# Privacy / Data Protection

Privacy flaws arise when personal data is collected, stored, transmitted, or shared beyond what the product purpose requires, without user consent, or without lifecycle controls (retention, encryption, deletion). Static analysis traces PII fields from forms/APIs through persistence, logging, analytics, URL construction, and third-party SDK calls.

*The core pattern: personal data crosses a privacy boundary — into storage, logs, URLs, analytics, or third parties — without minimization, consent gating, retention limits, encryption, or erasure support.*

## What It Is (and Is Not)

**What it IS**
- **Over-collection / missing minimization**: forms, APIs, or schemas request or persist fields not required for the stated purpose (full DOB when age band suffices, government ID when email suffices)
- **Indefinite retention**: PII stored with no TTL, expiry job, or retention policy; soft-delete flags without purge; backup/archive copies never scrubbed
- **PII in URLs/query strings**: email, name, phone, SSN, token, or health data appended to redirect URLs, GET endpoints, or client-side routing params (visible in browser history, Referer, proxy logs)
- **PII to analytics/telemetry**: user identifiers, email, IP, location, or health/financial attributes sent to product analytics, crash reporters, or APM without redaction or consent
- **Missing consent gating**: tracking, profiling, marketing, or third-party data sharing runs before consent check, ignores opt-out, or defaults to opt-in without explicit action
- **Third-party / tracker sharing**: PII forwarded to ad networks, social pixels, CDNs, or SaaS widgets without data-processing controls or purpose limitation
- **Unencrypted sensitive personal data at rest**: plaintext columns/files for health, biometric, financial, or government-ID fields (algorithm choice → `weak_crypto_hash.md`)
- **Missing right-to-erasure**: no delete-account flow, no cascade delete/anonymize for user-owned rows, exports, caches, search indexes, or third-party processors

**What it is NOT**
- **Log forging / newline injection in log messages** — see `log_injection.md`
- **Generic sensitive logging or stack-trace disclosure** — see `information_disclosure.md` (flag here only when the privacy issue is *personal-data handling policy*, not log format)
- **Weak algorithm selection for encryption/hashing** — see `weak_crypto_hash.md` (tag both when plaintext storage is the root issue)
- **Cleartext HTTP transport** — see `cleartext_transmission.md`
- **Cross-user cache leak** — see `shared_client_cache_leak.md`
- **IDOR exposing another user's PII** — see `idor.md` (access control, not collection/retention policy)

## Recon Indicators

### PII field-name patterns

| Category | Grep / schema targets |
|----------|----------------------|
| Identity | `email`, `e_mail`, `phone`, `mobile`, `msisdn`, `ssn`, `social_security`, `national_id`, `passport`, `driver_license`, `tax_id`, `date_of_birth`, `dob`, `birth_date` |
| Health / biometric | `diagnosis`, `medical_record`, `mrn`, `health`, `prescription`, `fingerprint`, `face_id`, `biometric` |
| Financial | `iban`, `account_number`, `routing`, `credit_card`, `card_number`, `cvv`, `salary`, `income` |
| Location / device | `latitude`, `longitude`, `geo`, `gps`, `ip_address`, `device_id`, `advertising_id`, `idfa`, `gaid`, `mac_address`, `browser_fingerprint`, `canvas_fingerprint`, `device_fingerprint` |
| Sensitive attributes (GDPR Art. 9/10) | `gender`, `ethnicity`, `race`/`racial`, `national_origin`, `religion`, `philosophical_beliefs`, `political`/`political_affiliation`, `union`/`trade_union`, `sexual_orientation`, `genetic`/`dna`, `biometric`/`voiceprint`, plus **criminal/judicial (Art. 10)**: `convictions`, `criminal_record`, `charges`, `pardons`, `disciplinary_action` |
| Behavioral / profiling | `browsing_history`, `clickstream`, `links_clicked`, `viewing_history`, `search_history`, `purchase_history`, `spending_habits` (profiling / ePrivacy data — taint as a PII *source*, distinct from the analytics *sinks* below) |
| Audit / actor identity | `created_by`, `createdBy`, `updated_by`, `updatedBy`, `last_updated_by`, `approver`, `assigned_to`, `assignedTo`, `owner`, `reviewer` (reveal *which person* acted on a record — relationship/identity metadata, often over-exposed on shared objects) |
| Ownership / financial stake | `ownership_percentage`, `ownershipPercentage`, `ownership_status`, `ownershipStatus`, `stake`, `beneficial_owner`, `shareholding` |
| Child data | `child`, `minor`, `parent_consent`, `coppa`, `under_13`, `age_gate` |

Also scan: OpenAPI/GraphQL/Proto field names, ORM models, DB migrations, form `name=` attributes, mobile `UserDefaults`/SharedPreferences keys, analytics event property maps.

**Confidence tiering (strong vs. weak) to control false positives.** When deciding whether a struct/DTO/endpoint *handles PII* (so the sink rules below apply), tier the field names — a single common field is benign on its own; one unambiguous field is enough:

- **Strong (1 hit flags it)** — names that rarely appear outside a PII/financial context: `ssn`, `social_security`, `cvv`, `cvc`, `cvv2`, `iban`, `passport`, `national_id`, `aadhaar`/`aadhar`, `tax_id`, `drivers_license`/`license_number`, `routing_number`, `sort_code`, `credit_card`/`card_number`, `dob`/`date_of_birth`, plus any Health/biometric or Sensitive-attribute row above. Also match these as a **token inside a compound** name so `userSsn`, `customer_cvv`, `applicantPassport` are caught.
- **Weak (require ≥2 distinct)** — common individually but PII in aggregate: `email`, `phone`/`mobile`, `first_name`/`last_name`/`full_name`, `address`/`street_address`/`postal_code`/`zip`, `gender`, `nationality`, `birthday`. Two or more distinct weak fields on the same object ⇒ treat as PII handling.
- **Normalize before matching:** fold camelCase→snake (`firstName`→`first_name`), unify `-`/`_`/`.` separators, lowercase, but keep digit runs (`cvv2` must survive). This makes `First-Name`, `firstName`, and `first_name` all match one list.
- **Container context (precision axis):** a *weak* field (`name`, `gender`, `location`, `image`, `dob`) is PII when its enclosing object/table/DTO is a **person-role** — `User`/`Customer`/`Patient`/`Employee`/`Applicant`/`Member`/`Subscriber`/`Cardholder`/`Passenger`/`Guardian`/`Insuree`/`Shareholder`/`Beneficiary` — and is **not** PII on a non-person object (`Server.location`, `Product.name`, an order-line `quantity`). Promote weak fields when the container names a data subject; demote otherwise. This cuts the dominant false-positive (bare `name`/`location`/`status` columns on non-person tables).

This tiering decides *PII presence*; severity still comes from the **sink** (logging, third-party/LLM egress, cross-tenant exposure) per the rules below — a single highly-sensitive strong field (SSN/card/health) reaching a logging or off-tenant sink is high severity regardless of the count.

### PII value-shape signatures (scanning *content*, not field names)

The field-name table decides whether a struct/endpoint *handles* PII. To detect PII **values** leaving through a content sink — model output/completions, logs, telemetry payloads, URLs — match value shapes:

| PII | Regex | Note |
|-----|-------|------|
| Email | `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b` | |
| Phone | `\+?\d[\d\s().-]{6,}\d` | noisy — require PII context or ≥2 signals |
| US SSN | `\b\d{3}-\d{2}-\d{4}\b` | |
| Credit card | `\b(?:\d[ -]?){13,16}\b` | **Luhn-validate** before flagging |

False-positive controls (essential — these regexes are otherwise noisy): **Luhn-validate** (mod-10) every card candidate before reporting — most random 13–16-digit runs fail Luhn; **exclude a card-shaped span from the phone match** so one number isn't double-counted; treat value-shape scanning as **locale-sensitive** (enable per region). Use these to power an egress/output filter and to confirm a field-name hit actually carries PII. For secret value shapes (API-key/token regexes + high-entropy fallback) see `information_disclosure.md`.

**Health & financial identifiers** — higher-impact (PHI/PCI/GDPR), but the bare digit shapes are *extremely* noisy, so report only on a **passing checksum** or an **adjacent identifier keyword**:

| Identifier | Regex | Required validation |
|-----------|-------|---------------------|
| Medical record no. | `\b(?:MRN\|MR#\|MED)\s*[-:#]?\s*\d{6,10}\b` (case-insensitive) | keyword-anchored by the prefix itself |
| NPI (US provider) | `\b\d{10}\b` | **Luhn over `80840` + the 10 digits** (CMS checksum) — mandatory; a bare 10-digit run is noise |
| DEA registration | `\b[A-Z][A-Z9]\d{7}\b` | **check digit**: over the 7 digits, `(d1+d3+d5) + 2·(d2+d4+d6) ≡ d7 (mod 10)` |
| IBAN | `\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}\b` | **mod-97 (ISO 7064)**: move first 4 chars to the end, map `A`→10…`Z`→35, value `% 97 == 1` |
| UK NHS number | `\b\d{3}[-\s]?\d{3}[-\s]?\d{4}\b` | **mod-11** over first 9 digits (weights 10…2); check = `11 − (sum % 11)`, `11`→`0`, `10`→invalid |
| US driver's license | state-specific, e.g. CA `\b[A-Z]\d{7}\b`, FL `\b[A-Z]\d{12}\b`, IL `\b[A-Z]\d{11}\b` | context-anchor (a "license" keyword nearby) — low specificity alone |
| US passport | `\b[A-Z]{1,2}\d{6,7}\b` | context-anchor — low specificity alone |

The checksum (NPI/DEA/IBAN/NHS) or keyword context (MRN/DL/passport) is **mandatory**, not optional: `\b\d{10}\b` and `\b\d{3} \d{3} \d{4}\b` match vast amounts of benign numeric data. These matter most when health/billing values reach a **log, off-tenant HTTP/analytics, or an LLM prompt** — a PHI/financial disclosure (cross-ref `information_disclosure.md` LLM02).

### Logging / analytics / telemetry sinks

| Sink type | Grep / structural targets |
|-----------|----------------------------|
| Logging | `logger\.(info\|debug\|warn\|error)`, `console\.log`, `Log\.`, `print\(`, `Rails\.logger`, `Sentry\.`, `Bugsnag\.`, `Rollbar\.`, `Datadog\.`, `NewRelic\.`, `OpenTelemetry`, `analytics\.track`, `gtag\(`, `fbq\(`, `mixpanel`, `segment\.track`, `amplitude`, `heap\.track`, `posthog`, `FullStory`, `LogRocket`, `Hotjar` |
| Crash / session replay | `Sentry\.setUser`, `setUserContext`, `identify\(`, `setUserId`, `recordSession`, `captureMessage` with user object |
| Mobile SDKs | `FirebaseAnalytics`, `AppsFlyer`, `Adjust`, `Branch`, `FacebookSDK`, `Crashlytics\.setUserIdentifier` |

Trace PII variables into these sinks. For log *content* exposure mechanics, cross-check `information_disclosure.md`; for log *injection*, cross-check `log_injection.md`.

### Sensitive data to AI/LLM providers, data warehouses & managed third parties

A privacy-relevant data flow also exists when personal data reaches an external **component** — not just an analytics SDK. The risk is off-tenant disclosure of PII/PHI to a processor outside the data-controller boundary. Trace PII into these sinks even when the call looks like ordinary business logic. Include **object storage** (S3/GCS/Azure Blob) and **data lakes** as raw-PII/image/voice persistence sinks (minimization/retention surfaces). Classify each sink as **internal-service (same controller)** vs **off-tenant third-party**: the controller-boundary crossing is the severity driver — PII to a same-controller internal service is a minimization/retention question, while the same data to a third-party processor is a *sharing* disclosure.

| Component class | Grep / structural targets |
|-----------------|----------------------------|
| AI / LLM provider APIs | `openai`, `OpenAI(`, `chat\.completions\.create`, `embeddings\.create`, `anthropic`, `messages\.create`, `cohere`, `replicate`, `huggingface`, `bedrock`, `vertexai`, `generativelanguage`, `azure.*openai` — PII placed in prompts, embeddings, or fine-tune/training payloads sent off-tenant |
| Data warehouses / pipelines | `bigquery`, `snowflake`, `redshift`, `clickhouse`, `databricks`, `dataflow` — raw PII columns streamed/exported without minimization or tenant scoping |
| Search / index clusters | `elasticsearch`, `opensearch`, `algolia`, `meilisearch`, `typesense` — personal fields indexed in plaintext, often with broad read access |
| Managed DB / KV / queue / stream | `dynamodb`, `firestore`, `cosmosdb`, `mongodb.*atlas`, `redis`, `kafka`, `sqs`, `pubsub` — PII persisted/forwarded to a third-party-operated store |

For each: confirm the personal data is necessary, minimized/pseudonymized, covered by a data-processing agreement, and scoped to the correct tenant. Placing raw PII in an LLM prompt or embedding is an off-tenant disclosure — cross-check `information_disclosure.md` (LLM02) and `rag_vector_security.md`.

### URL / query / redirect param patterns

| Signal | Examples |
|--------|----------|
| PII in query builder | `URLSearchParams`, `encodeURIComponent(email)`, `?email=`, `?name=`, `?phone=`, `?token=`, `?ssn=` |
| Redirect with user data | `res.redirect(\`/welcome?email=${`, `window.location = ... + user.email`, OAuth `state` carrying profile fields |
| GET handlers returning PII | `@GetMapping` / `router.get` with sensitive params in path or query |
| Client routing | React Router `searchParams.set('email'`, Next.js `router.push({ query: { name` |

### Consent / preference / erasure signals

| Missing control | Grep when absent near collection/tracking |
|-----------------|-------------------------------------------|
| Consent gate | `consent`, `gdpr`, `opt_in`, `opt_out`, `privacy_preferences`, `cmp`, `OneTrust`, `Cookiebot`, `didAccept`, `trackingAllowed` |
| Erasure | `deleteUser`, `delete_account`, `erase`, `anonymize`, `right_to_be_forgotten`, `purge`, `hard_delete`, `GDPR_DELETE`, `accountDeletion` |
| Retention | `retention`, `ttl`, `expires_at`, `purge_after`, `data_lifecycle`, `scheduled.*delete`, `cron.*cleanup` |

## Vulnerable Conditions

- Registration/profile/API schema marks sensitive fields `required` when optional for core function
- Full PII snapshot persisted to `users`, `events`, `audit_log`, or analytics tables with no field-level necessity review
- No `expires_at`, retention job, or documented TTL on rows containing personal data
- Email, name, phone, token, health, or financial value interpolated into URL, redirect, or GET query
- `analytics.identify(user.id, { email, phone, ... })` or equivalent without consent check or field filtering
- Third-party script/SDK initialized on every page load before consent; PII passed in init config
- Ad/tracking pixel receives hashed or raw email/phone (`sha256(email)`, `user_data`, `_fbc`, `external_id`)
- Sensitive personal columns stored as plaintext strings/files/blobs (defer algorithm details to `weak_crypto_hash.md`)
- Account "delete" sets `deleted=true` only; related tables, S3 objects, caches, search indexes, and vendor profiles untouched
- Export/backup jobs copy full user records indefinitely with no redaction or rotation
- Webhook or batch job forwards full user profile to marketing/CRM without purpose limitation or consent flag
- Raw personal data placed in an LLM prompt/embedding/fine-tune payload, or streamed into a third-party data warehouse, search index, or managed datastore, without minimization, pseudonymization, or a data-processing agreement (off-tenant disclosure)
- Child-directed or health/finance flows collect data without age/consent branch in code
- Sensitive HTML input fields (password, SSN, card number, OTP) rendered without `autocomplete="off"` (or `new-password`/`one-time-code`), letting browsers cache the value in form history on shared devices (CWE-525)

## Safe Patterns

**Data minimization**
- Collect only fields required for the feature; derive aggregates server-side (age band, postal prefix) instead of raw values
- Separate optional marketing/profile fields from mandatory auth fields; reject unknown PII keys on input

**Retention & lifecycle**
- Store `retention_until` or TTL on PII-bearing records; scheduled job purges or anonymizes past deadline
- Backups and exports inherit retention policy; document cascade on delete

**URLs & transport**
- Never place PII in query strings; use POST body, server-side session, or opaque server-issued token in path
- Redirect with one-time server nonce, not email/name

**Analytics & third parties**
- Initialize tracking SDKs only after consent=true; no-op or stub before consent
- Send pseudonymous ID only; strip email/phone/name from event payloads; hash only after consent and with documented purpose
- Data-processing agreements enforced in code: allowlist vendor endpoints; block PII fields in outbound webhook mappers

**Encryption & erasure**
- Encrypt sensitive personal columns at rest with current algorithms (see `weak_crypto_hash.md` for cipher/hash rules)
- Delete flow cascades: DB rows, object storage, cache keys, search index docs, queue dead-letter, vendor delete API
- Anonymize irreplaceable audit rows (replace PII with irreversible token) when hard delete is impossible

```python
# VULN — full DOB collected when only age verification needed
class SignupForm(forms.Form):
    email = forms.EmailField()
    date_of_birth = forms.DateField(required=True)

# SAFE — collect minimum; derive age server-side
class SignupForm(forms.Form):
    email = forms.EmailField()
    birth_year = forms.IntegerField(min_value=1900, max_value=2020)
```

```javascript
// VULN — PII in redirect URL
res.redirect(`/dashboard?email=${encodeURIComponent(user.email)}`);

// SAFE — session-only context
req.session.userId = user.id;
res.redirect('/dashboard');
```

```typescript
// VULN — analytics identify before consent
analytics.identify(user.id, { email: user.email, phone: user.phone });

// SAFE — gate on consent; minimal traits
if (user.consents.analytics) {
  analytics.identify(user.pseudonymId, { plan: user.plan });
}
```

```java
// VULN — soft delete only; PII remains
user.setDeleted(true);
userRepository.save(user);

// SAFE — cascade erasure
userErasureService.erase(userId); // deletes/anonymizes rows, files, cache, vendor profiles
```

```sql
-- VULN — indefinite PII retention
CREATE TABLE user_events (
  id BIGINT PRIMARY KEY,
  user_id BIGINT,
  email VARCHAR(255),
  payload JSONB
);

-- SAFE — TTL column + purge job
CREATE TABLE user_events (
  id BIGINT PRIMARY KEY,
  user_id BIGINT,
  payload JSONB,
  retention_until TIMESTAMPTZ NOT NULL
);
```

## Language / Stack Examples

### Python (Django / Flask)

```python
# VULN — PII logged on signup failure
logger.info(f"Signup failed for {request.json['email']} / {request.json['ssn']}")

# VULN — Send full profile to third-party CRM unconditionally
requests.post(CRM_URL, json=user.__dict__)

# VULN — raw PII/PHI placed in an LLM prompt (off-tenant disclosure; see information_disclosure.md LLM02)
openai.chat.completions.create(model="gpt-4", messages=[
    {"role": "user", "content": f"Summarize patient {p.name}, SSN {p.ssn}, dx {p.diagnosis}"}
])
```

### JavaScript / TypeScript (web & Node)

```javascript
// VULN — Meta/ad pixel with raw email
fbq('init', PIXEL_ID, { em: user.email });

// VULN — session replay with identifiable user
LogRocket.identify(user.id, { name: user.name, email: user.email });
```

### Java / Kotlin (Android / Spring)

```java
// VULN — plaintext health note column
@Column(name = "diagnosis_text")
private String diagnosisText;

// VULN — Firebase Analytics user properties with PII
mFirebaseAnalytics.setUserProperty("email", user.getEmail());
```

### Go

```go
// VULN — query param carries phone
http.Redirect(w, r, "/verify?phone="+url.QueryEscape(phone), http.StatusFound)
```

### Swift / iOS

```swift
// VULN — IDFA/tracking before ATT consent
Analytics.setUserProperty(user.email, forName: "email")
```

## Source → Sink Pattern (privacy lens)

**Sources**: form fields, API body/query, mobile sensors, imported contacts, OAuth profile claims, DB columns marked personal.

**Sinks (privacy-specific)**:
- Persistent stores (SQL/NoSQL/files) without minimization or retention
- Log/analytics/APM/crash/session-replay SDK calls
- URL builders, redirects, deep links, email templates with query params
- Third-party HTTP calls, webhooks, ad/tracking pixels
- Missing delete/anonymize handlers when user requests erasure

**Sanitizers**: field allowlists; consent checks before track/share; pseudonymization; TTL jobs; encrypted columns; erasure cascade.

## Common False Alarms

- Email/username in server-side audit log for security investigations with documented retention — may be intentional; verify policy, not just presence (log injection/disclosure classes may still apply separately)
- Pseudonymous analytics ID (`user.uuid`) with no direct identifiers and consent gate present
- PII in POST body over HTTPS with no URL/logging/analytics sink — transport alone is not a privacy minimization finding
- Optional profile fields clearly marked optional in schema and unused by downstream code
- Encrypted PII at rest using modern algorithms — no plaintext-storage finding (still verify key management separately)
- Delete flow that soft-deletes then async hard-purges within documented SLA — not missing erasure if purge job exists in code
- Internal admin-only export of PII with authZ — not third-party sharing; still check minimization/retention
- Pseudonymized or aggregated data exported to a warehouse/search index/LLM under a documented data-processing agreement with tenant scoping — verify minimization, not mere presence of the sink
- Age field required for legal compliance ( alcohol, gambling, COPPA gate) — not over-collection when code enforces jurisdictional rules
- Hashing email for analytics *after* consent solely for attribution within same controller — lower risk than raw PII to ad networks; confirm consent branch exists
