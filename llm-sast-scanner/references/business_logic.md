---
name: business_logic
version: "0.6"
description: Business logic testing for workflow bypass, state manipulation, and domain invariant violations
---

# Business Logic Flaws

Business logic flaws exploit intended functionality to violate domain invariants: move money without paying, exceed limits, retain privileges, or bypass reviews. They require a model of the business, not just payloads.

**Core pattern:** input is syntactically valid and passes auth, but violates a business rule never enforced in code.

### What It Is

- Negative quantity purchase → credit instead of charge
- Same one-time coupon redeemed in parallel requests
- Skip payment/verification in multi-step checkout via direct API call
- Out-of-range ratings, scores, or percentages (e.g., 9999 when max is 5)
- Negative transfer reversing money flow; self-referral for bonus
- Single-use token/voucher reuse; out-of-stock purchase via inventory race
- Premium access after downgrade; auction bid retraction after competitors eliminated

### What It Is NOT

- **Injection classes** (SQLi, XSS, RCE, XXE, SSRF, SSTI) — technical input-handling flaws
- **Missing authentication** — endpoint requires no login at all
- **IDOR** — accessing another user's resource by changing an ID
- **Generic brute-force / rate-limit bypass** — unless it clearly circumvents a specific business rule

## Where to Look

- Financial logic: pricing, discounts, payments, refunds, credits, chargebacks
- Account lifecycle: signup, upgrade/downgrade, trial, suspension, deletion
- Authorization-by-logic: feature gates, role transitions, approval workflows
- Quotas/limits: rate/usage limits, inventory, entitlements, seat licensing
- Multi-tenant isolation: cross-organization data or action bleed
- Event-driven flows: jobs, webhooks, sagas, compensations, idempotency

## High-Value Targets

- Pricing/cart: price locks, quote to order, tax/shipping computation
- Discount engines: stacking, mutual exclusivity, scope (cart vs item), once-per-user enforcement
- Payments: auth/capture/void/refund sequences, partials, split tenders, chargebacks, idempotency keys
- Credits/gift cards/vouchers: issuance, redemption, reversal, expiry, transferability
- Subscriptions: proration, upgrade/downgrade, trial extension, seat counts, meter reporting
- Refunds/returns/RMAs: multi-item partials, restocking fees, return window edges
- Admin/staff operations: impersonation, manual adjustments, credit/refund issuance, account flags
- Quotas/limits: daily/monthly usage, inventory reservations, feature usage counters

## Attack Category Checklist

Use as a domain-scoping checklist; not all categories apply to every application.

| # | Category | Key abuse signals |
|---|----------|-------------------|
| 1 | Price & payment | Negative/zero price; client-supplied price; cents vs dollars; float precision; discount below zero; **JSON duplicate-key amount drift** across policy/gateway vs execution (`{"amount":10,"amount":1000}` — see `input_validation.md`) |
| 2 | Quantity & limits | Negative qty; exceed per-user/order caps; overflow/underflow; out-of-range bounded fields; **client-supplied quota counters** (`remaining_downloads`, `usage_count`, `remaining_limit`, `bypass_limit`) trusted as the gate |
| 3 | Workflow bypass | Skip mandatory steps; replay completion token; direct terminal endpoint; state machine violations |
| 4 | Coupon/voucher | Reuse single-use coupon; stack incompatible discounts; expired coupon; guess/generate codes; **GraphQL aliased `createCoupon`/`issueVoucher` minting N codes in one HTTP request** when limits count requests not resolver executions (see `graphql_dos.md` § Alias overloading) |
| 5 | Race/concurrency | Double-spend; concurrent coupon drain; TOCTOU inventory; parallel withdrawal exceeding balance |
| 6 | Refund/chargeback | Refund after digital consumption; partial refund stacking; refund without return |
| 7 | Reward/referral | Self-referral; repeat signup bonus; loyalty farming; transfer non-transferable rewards |
| 8 | Subscription/entitlement | Premium after downgrade; trial abuse via new accounts; plan check only at signup, not access; **client-supplied tier flags** (`is_premium`, `unlimited`, `plan_tier`) from the request body used as the entitlement gate (distinct from ORM mass-assignment — see pattern below) |
| 9 | Auction/bidding | Retract winning bid; shill bidding; reserve price bypass; concurrent bid manipulation |
| 10 | Inventory/stock | Buy out-of-stock; over-reserve via concurrency; negative inventory; phantom availability |
| 11 | Time/date | Expired offers (client-side expiry); backdated transactions; grace-period abuse; client timestamps |
| 12 | Transfer/balance | Negative amount; signed/unsigned integer **overflow/underflow wrapping a balance from debit to credit** (withdraw/transfer an amount that wraps a fixed-width signed counter positive — `balance - (-N)` or a value past `SHRT_MAX`/`INT_MAX` → funds created from nothing); self-transfer fee/bonus abuse; overdraft; rounding across micro-transactions |

## Reconnaissance

### Workflow Mapping

- Derive endpoints from the UI and proxy/network logs; map hidden/undocumented API calls, especially finalize/confirm endpoints
- Identify tokens/flags: stepToken, paymentIntentId, orderStatus, reviewState, approvalId; test reuse across users/sessions
- Document invariants: conservation of value (ledger balance), uniqueness (idempotency), monotonicity (non-decreasing counters), exclusivity (one active subscription)

### Input Surface

- Hidden fields and client-computed totals; server must recompute on trusted sources
- Alternate encodings and shapes: arrays instead of scalars, objects with unexpected keys, null/empty/0/negative, scientific notation
- Business selectors: currency, locale, timezone, tax region; vary to trigger rounding and ruleset changes

### State and Time Axes

- Replays: resubmit stale finalize/confirm requests
- Out-of-order: call finalize before verify; refund before capture; cancel after ship
- Time windows: end-of-day/month cutovers, daylight saving, grace periods, trial expiry edges

## Vulnerability Patterns

### Client-Supplied Quota / Entitlement Gate (usage-limit bypass)

Auth + rate-limit middleware do **not** make this SAFE. The bug is trusting **request-body (or query) fields that assert remaining capacity or tier** instead of a server-side ledger keyed by user/account.

**SAST signal:** a free-trial / download / vote / API-quota / coupon-redeem handler reads any of `remaining_downloads`, `remaining_limit`, `usage_count`, `bypass_limit`, `unlimited`, `is_premium`, `plan_tier` (or synonyms) from `request.get_json()` / `req.body` / query params and branches on that value to allow the action — with **no** lookup of a persisted counter or subscription row for `current_user` / account id.

```python
# VULN — authenticated, rate-limited, but quota is client-asserted
@app.post("/api/download/free")
@login_required
def free_download():
    body = request.get_json() or {}
    if body.get("is_premium") or body.get("remaining_downloads", 0) > 0:
        return send_file(pick_asset())
    return jsonify(error="limit exceeded"), 429
```

**Related shapes (same class):**
- Resetting limits via profile update: `PUT /api/user/profile` with `{"usage_count": 0}` when the handler writes the body field into the counter store without server authority.
- **Per-session counters** (`session["free_downloads"] += 1`) with no `user_id` key in Redis/DB — a new session resets the quota (limit is not per-user).

**Not this class:** ORM mass-assignment of `is_premium` onto a User model (`mass_assignment.md`) — that is a bind/allowlist bug. This class is the **gate reading the client field as truth** without persisting it as a model attribute.

**CONFIRM when:** attacker-set body fields alone raise remaining capacity / flip tier and the action succeeds beyond the intended limit for that principal.

### State Machine Abuse

- Skip or reorder steps via direct API calls; verify server enforces preconditions on each transition
- Replay prior steps with altered parameters (e.g., swap price after approval but before capture)
- Split a single constrained action into many sub-actions under the threshold (limit slicing)

### Ownership / Resource-Claim Verification via Attacker-Controlled Proof

Applies to any "claim / connect / import / add-show" flow that establishes ownership of a resource — a podcast/show, domain, app-store or business listing, package/namespace, social profile — or binds an account identity.

**Decision rule:** if the flow proves ownership by sending a code to — or checking a value read from — **content the claimant themselves supplied** (a manifest/feed fetched from a *user-submitted URL*, an uploaded file, or a request-body field), the verification is **circular / self-asserted** and the claim is forgeable, *regardless of how sound the code/token mechanics are*. Report it unless the proof is bound to a reference the platform **already holds independently of this request**. Do **not** mark such a flow safe merely because it checks `claim.user_id == current_user` and a single-use code — those guard *who* completes the claim and *replay*, not *whether the proof means anything*.

- **Mechanism**: the claimant authors the proof document, so they also author the "owner" attribute inside it (contact email, `owner`/`author` id, embedded verification token, domain). Receiving the emailed code / clicking the link proves only that they control a value **they chose** — not that they own the real resource.
- **Exploit (podcast/RSS example from the wild)**: download a famous show's RSS feed → change `<itunes:email>` to the attacker's address → re-host at an attacker URL (e.g. a public cloud bucket) → submit that URL → the code is delivered to the **attacker's own inbox** → claim succeeds, minting an impersonating **duplicate** of the victim's show. Same shape for re-hosted `package.json` / `.well-known` / sitemap / metadata XML.
- **Distinct from** OTP mechanics (`verification_code_abuse.md`): the code can be unguessable, single-use, and rate-limited and the claim is **still** forgeable — the attacker never needs to guess it because it is mailed to *their own* address. **Distinct from** email parameter pollution (the address is not a duplicate key; the *entire proof document* is attacker-authored). The defect is the **provenance of the verified datum**, not the delivery channel or the code.
- **SAST signal**: a `claim` / `verify` / `submit-feed` / `connect` / `import` / `add-show` handler that extracts an email/owner/token from `requests.get(<request-supplied url>)`, an uploaded blob, or `request.json[...]`, then sends a verification to it or writes `owner_id` / `verified = true` — with **no comparison to a pre-existing trusted reference** already bound to the resource (a canonical URL on record from the platform's own crawler/registry, a DNS TXT / WHOIS record on the resource's *own* domain, or a contact stored against the resource out-of-band) and **no content-fingerprint duplicate check**.
- **Fix**: derive the challenge target from a reference the **true owner already controls and the platform already knows** — a token placed at the *canonical* resource location on record (never a freshly-submitted URL), DNS/WHOIS on the resource's own domain, or an out-of-band contact on file — and fingerprint/deduplicate submitted content so a re-hosted copy cannot create a parallel owned duplicate.

```bash
# Ownership proof read from attacker-fetched/uploaded content (circular verification)
rg -n "claim|verify|submit.*(feed|rss)|import.*url|connect|add[_-]?show" --glob '*.{py,js,ts,go,rb,php,java}' \
  | rg -n "requests\.get|urlopen|fetch\(|http\.get|files\[|request\.(json|body|form)"
# then confirm the extracted email/owner/token gates ownership with NO canonical/DNS/on-file cross-check
```

```python
# VULN: ownership proof read from attacker-controlled feed content (circular verification)
feed = requests.get(request.json["rss_url"]).text        # claimant supplies the URL...
owner_email = parse(feed).findtext("itunes:email")       # ...and therefore this value
send_verification_code(owner_email)                      # code goes to the attacker's own inbox
# on confirm: Podcast(owner_id=current_user.id, feed_url=request.json["rss_url"])  # ANY feed claimable -> impersonating duplicate

# SECURE: bind the proof to a reference the true owner already controls / the platform already knows
show = Podcast.query.get(podcast_id)                      # existing catalog entry (canonical URL on record)
token = issue_challenge(current_user.id, show.id)
feed = requests.get(show.canonical_feed_url).text        # fetch the CANONICAL feed, not a user-submitted URL
if token not in feed:                                    # true owner must place our token in the real feed
    abort(400)
if content_fingerprint(feed) in existing_show_fingerprints:  # reject re-hosted duplicates of another show
    abort(409)
show.owner_id = current_user.id
```

### Rollback / Restore / Undo Re-authorization

The forward path is guarded; the **undo direction** often is not. Operations that *reconstruct persisted state* from a historical snapshot — undelete, restore-from-backup, revert-to-revision, undo, un-cancel, un-ban — frequently re-write privileged or access-control fields (`role`, `permissions`, `acl`, `sharedWith`, `visibility`, `status`, `ownerId`, `tenantId`, membership) straight from the snapshot **without re-validating them against *current* policy**. The result is *privilege/access resurrection*:

- **Undelete restores a revoked privilege** — a soft-deleted account is restored from a snapshot carrying its old `role: "admin"` even though an admin demoted the user before deletion; the restore re-persists admin rights the DB had already revoked.
- **Revert-to-revision restores stale authorization** — reverting a document to an old revision copies that revision's `visibility`/`sharedWith`, silently re-publishing a now-private resource and re-granting collaborators who were since removed.
- **Restore/undo resurrects banned or expired state** — un-ban, restore a cancelled subscription at its old tier, re-activate a membership in an org the user was removed from.

This is distinct from two patterns covered elsewhere: it is **not** forward state-machine abuse (skip/reorder/replay *forward* steps, above), and **not** stale-role-via-cached-token (`privilege_escalation.md` — a role never re-checked at use); here an undo operation *actively re-writes* revoked state back into storage. An ownership check on the tombstone/revision is **necessary but insufficient** — it authorizes *who* restores, not *what* privileged state gets resurrected.

- **SAST signal**: an undelete/restore/revert/undo handler that writes authority/visibility fields from a stored snapshot, revision, or tombstone with no re-check that those values are still valid under current policy. Recon: `rg -ni "restore|undelete|undo|revert|recover|rollback|reinstate|unarchive" --glob '*.{js,ts,py,go,rb,java,cs}'` then check whether the write copies `role`/`acl`/`visibility`/`status`/`owner`/`tenant` from the historical record.
- **Safe**: on restore, re-derive privileged and ACL/visibility fields from *current* policy (never trust the snapshot's copy); re-run the same authorization and validation the create/forward path enforces; restore only non-authority content fields and recompute role/visibility/membership from current state; refuse to restore a resource into a state that would violate current rules.
- Bulk **import / restore-from-backup** planting cross-tenant or foreign-owner records is the data-injection sibling — see `idor.md` (Bulk & Batch: imports referencing foreign `ownerId`/`tenantId` bypass creation-time checks).

### Concurrency and Idempotency

- Parallelize identical operations to bypass atomic checks (create, apply, redeem, transfer)
- Abuse idempotency: key scoped to path but not principal → reuse other users' keys; or idempotency stored only in cache
- Message reprocessing: queue workers re-run tasks on retry without idempotent guards; cause duplicate fulfillment/refund

### Numeric and Currency

- Floating point vs decimal rounding; rounding/truncation favoring attacker at boundaries
- Cross-currency arbitrage: buy in currency A, refund in B at stale rates; tax rounding per-item vs per-order
- Negative amounts, zero-price, free shipping thresholds, minimum/maximum guardrails

### Quotas, Limits, and Inventory

- Off-by-one and time-bound resets (UTC vs local); pre-warm at T-1s and post-fire at T+1s
- Reservation/hold leaks: reserve multiple, complete one, release not enforced; backorder logic inconsistencies
- Distributed counters without strong consistency enabling double-consumption

### Refunds and Chargebacks

- Double-refund: refund via UI and support tool; refund partials summing above captured amount
- Refund after benefits consumed (downloaded digital goods, shipped items) due to missing post-consumption checks

### Feature Gates and Roles

- Feature flags enforced client-side or at edge but not in core services; toggle names guessed or fallback to default-enabled
- Role transitions leaving stale capabilities (retain premium after downgrade; retain admin endpoints after demotion)
- **Delegated / on-behalf mutations**: handlers accepting `subject_id`, `booked_for`, `on_behalf`, `delegate`, or impersonation context let one actor perform a consequential action for another principal (sign/accept an agreement, book a resource, approve/reject, change identity data). A generic manager/admin check is not enough: verify an explicit delegation capability for this **action and target**, bind the target server-side, require consent/step-up where the action is legally or financially meaningful, and audit both actor and subject. Flag `role == admin` followed by a mutation of an arbitrary request-supplied subject with no target-scoped policy check; do not dismiss it as “admin functionality” merely because the actor is privileged.

### Account Lifecycle and Identity

Registration, email change, and username uniqueness are business invariants — parser/precedence bugs and missing normalization create duplicate identities or pre-account-takeover paths. Email parsing/canonicalization differentials are detailed in `references/email_parser_differential.md`; OTP/resend abuse chains in `references/verification_code_abuse.md`.

- **Registration / password-reset email parameter pollution (incl. 0-click ATO)**: duplicate keys or array shapes where one value drives verification and another drives delivery/identity — `email=victim@x&email=attacker@x`, `{"email":["victim","attacker"]}`, case-variant keys (`Email=` vs `email=`), or CRLF/header injection in the email field (`%0a%0dcc:`) causing verification email to one address while account is bound to another. The **highest-impact variant targets password reset / account recovery**: when the recovery handler reads the address as a collection instead of a single scalar (e.g. JSON `{"user":{"email":["victim@x","attacker@x"]}}`, repeated `user[email]` params, or any field a body-parser/ORM coerces to an array), the **reset link is mailed to *every* recipient**, so the attacker receives the victim's token and takes over the account with **no victim interaction** (0-click ATO). SAST signals: reset/recovery (and registration) handlers that pass `params[:email]`/`request.json["email"]`/`body.user.email` straight into the mailer/lookup without asserting it is a single `str` (no `isinstance(..., str)` / `Array.isArray` rejection, no length-1 coercion); deep mass-assignment of a nested `user`/`account` object into the recovery flow; mailers invoked with a list-typed `to:` built from request input. Fix: coerce the recovery address to one server-resolved scalar (look it up by the *stored* account, never echo client-supplied recipients), and reject array/object/duplicate shapes for identity fields
- **Duplicate / twin accounts**: same logical username with different case (`AdMIn` vs `admin`), whitespace/trailing-space collisions (`"admin "` vs `"admin"`), SQL column truncation collisions, or missing `UNIQUE` + trim/lowercase normalize at insert — two accounts map to one identity or bypass uniqueness checks
- **Unicode confusables / homoglyph normalization bypass (impersonation + denylist evasion)**: identity fields (username, display name, email local-part) compared or filtered **without Unicode normalization** let an attacker register a name that is *visually identical* to a reserved/existing one using confusable code points — e.g. the Cherokee letter `Ꮇ` (U+13B7) for Latin `M` to pass a blocked-keyword check for a reserved brand/role like `acme`/`admin`/`support`, full-width/escaped forms, combining marks, or zero-width joiners. Same root cause defeats uniqueness checks (two "distinct" strings render the same) and **denylist/keyword filters** (the blocklist matches only the ASCII spelling). SAST signals: uniqueness/reserved-name/blocklist checks that compare raw input (`name in BLOCKED`, `== "admin"`, `LIKE '%acme%'`) with no `unicodedata.normalize('NFKC', …)` / ICU `Normalizer2`, no confusables-skeleton fold, and no single-script (mixed-script) restriction before the check. Fix: normalize (NFKC) + apply a confusables **skeleton** (Unicode TR39) and/or restrict identity fields to a single script/allowed code-point set *before* uniqueness, reserved-word, and impersonation checks; store and compare the normalized form
- **Composite key/filename/namespace collision from ambiguous concatenation (cross-tenant overwrite / auth bypass)**: when a security-relevant resource name — an auth/`.htpasswd` file, cache key, lock name, S3 prefix, config path, permission record — is built by **concatenating two or more user/tenant-controlled identifiers with a non-injective separator** (`f"{namespace}-{ingress}"`, `tenant + ":" + key`, `org + "_" + name`), different identifier pairs can produce the **same final key**: `(ns="a", name="b-c")` and `(ns="a-b", name="c")` both yield `a-b-c`. An attacker picks the pair that collides with a victim's resource and **overwrites it** — e.g. replacing another namespace's generated auth file to strip its authentication, or poisoning a shared cache/lock entry. Aggravated when a path separator or `..` is permitted inside one component (path traversal into another tenant's directory). SAST signals: composite keys/filenames/paths assembled by string concatenation/`-`/`_`/`:`-join of multiple request- or tenant-derived fields, with no length-prefix/escaping/encoding of each part and no per-tenant directory isolation. Fix: build composite keys with an **injective, escaped encoding** (length-prefixed, or per-segment percent-encoding/hashing) and isolate each tenant under its own namespace/directory; reject separator and `..`/path characters inside identifier components
- **Namespace scope omitted entirely (cross-tenant overwrite / disclosure)**: even an unambiguous key collides when an identifier is unique only *inside* a parent scope but that scope is dropped. Example: the route and authorization use `(tenant_id, event_id)`, while the object key/path/cache key is only `events/{event_id}/{filename}`; tenant A and tenant B can both own event `7` and write the same storage slot. Compare every route/auth scope dimension with the persisted key: tenant/org/account plus local resource ID must be bound in the namespace (or the resource ID must be proven globally unique). A fixed storage root and sanitized filename do not repair the missing tenant segment.
- **Change-email without verification → pre-account-takeover**: authenticated user sets email to victim address without confirming inbox; attacker triggers password reset or OTP to victim email and completes takeover before victim registers — durable binding to unverified address
- **Verification token bound to the user, not the target email (email-bind confusion)**: the email-change/confirmation link encodes only a user id or an opaque token tied to the account, not the *specific* address being confirmed, and is **not invalidated when the pending email changes**. Exploit: (1) request change to `attacker@x` → receive a confirmation link but don't click; (2) change the pending email again to `victim@x`; (3) click the original `attacker@x` link — the server marks the *current* pending email (`victim@x`) as verified because the token only proves "this user", granting a verified address the attacker never controlled. Indicators: confirm handler reads `userId`/`token` and sets `user.email = user.pendingEmail` / `emailVerified = true` without comparing the token's bound address to the address being confirmed; pending-email writes don't rotate/expire prior tokens. Fix: bind the token to the exact email string (and rotate/expire all prior tokens on any pending-email change); on confirm, verify the token's email equals the stored pending email before marking verified
- **Client-supplied workflow `state` + request-supplied identity → credential overwrite (signup/onboarding ATO)**: a single multi-step endpoint (signup, passwordless onboarding, account-claim, SSO-link) accepts a **client-chosen state/step field** (`state=CREATE_NEW_PASSWORD`, `userWorkflow=PASSWORDLESS_SIGNUP`, `step`, `phase`, `flow`) that drives a server state machine, while the **target identity is read from the request** (`phoneNumberE164`, `email`, `userId`) rather than an authenticated session. An attacker submits the credential-setting state directly with a *victim's* identifier — skipping the proof-of-ownership steps the machine assumed had run — and the server **sets/overwrites the password (or links a credential) on the existing victim account**, an unauthenticated full ATO that only needs a known phone/email. Distinct from registration twin-accounts: the flow meant for *new* identities is reused against an *existing* one. Indicators: an endpoint that branches on `request.json["state"]`/`step` to reach a `setPassword`/`createCredential`/`linkAccount` path; identity loaded via `findByPhone(req.body.phone)` / `findByEmail(req.body.email)` instead of `session.user`; no check that the account is unclaimed (no existing password / not yet verified) and no possession proof (OTP/token) tied to *this* request before the credential write; the same handler used for both "new signup" and "set password". Fix: never let the client select a credential-mutating state — derive the allowed next transition server-side from persisted flow state bound to a possession proof; resolve identity from session or a server-issued token; refuse credential creation when the account already exists/owns a password.
- **Resource-claim / ownership verification via attacker-authored proof** (claim a podcast/domain/package/listing/profile, or bind an account identity, by re-hosting the resource's manifest with your *own* contact email): the verifying datum is self-supplied, so the check is circular — see **Ownership / Resource-Claim Verification via Attacker-Controlled Proof** under Vulnerability Patterns.

```bash
# Email pollution / duplicate-key handling
rg -n "request\.(form|json|query|body).*email|getlist\(['\"]email|email.*\[\]" .
rg -n "normalizeEmail|trim.*email|lower.*email|UNIQUE.*email|citext" .

# Twin-account / case sensitivity
rg -n "username.*unique|createUser|register|sign[_-]?up" . | rg -v "lower|trim|normalize|citext"
rg -n "VARCHAR\(|CHAR\(|username" --glob "*.{sql,py,java,rb,php}"

# Change-email without step-up verification
rg -n "change[_-]?email|update.*email|setEmail|email.*=" . | rg -v "verify|confirm|otp|token|pending"
```

```python
# VULN: first email wins for verify, last for storage (parameter pollution)
emails = request.form.getlist("email") or [request.json.get("email")]
send_verification(emails[0])
user.email = emails[-1] if isinstance(emails, list) else emails
user.save()

# VULN: case-sensitive username uniqueness
User.create(username=request.json["username"])  # "Admin" and "admin" both succeed

# SECURE: canonical identity + single verified email
email = normalize_email(single_email_value(request))  # reject arrays/duplicates
if User.exists(username=canonical_username(request.json["username"])):
    raise ConflictError()
user.pending_email = email
send_verification(email)  # account email updates only after token verify

# VULN: email change without verification — pre-account-takeover
user.email = request.json["new_email"]
user.save()
send_password_reset(user.email)
```

## Advanced Techniques

### Event-Driven Sagas

- Saga/compensation gaps: trigger compensation without original success; or execute success twice without compensation
- Outbox/Inbox patterns missing idempotency → duplicate downstream side effects
- Cron/backfill jobs operating outside request-time authorization; mutate state broadly

### Microservices Boundaries

- Cross-service assumption mismatch: one service validates total, another trusts line items; alter between calls
- Header trust: internal services trusting X-Role or X-User-Id from untrusted edges
- Partial failure windows: two-phase actions where phase 1 commits without phase 2, leaving exploitable intermediate state

### Off-chain EVM settlement and indexing

- A transaction receipt with `Status == 1` proves only that the **top-level transaction did not revert**. A contract can catch a failed external call, or ignore a `call`/`delegatecall`/`staticcall` return value, and still finish successfully. A bridge, exchange, or deposit indexer must verify the expected canonical event/state transition — emitting contract, asset, sender/recipient, and actual amount — instead of crediting a caller-supplied amount from receipt status alone.
- `debug_trace*`, `trace_transaction`, and related call traces describe attempted execution, including frames whose effects were reverted. When deriving transfers, propagate failure from every frame carrying `error`/revert to **all descendants** and exclude that whole subtree; then reconcile the remaining effects with canonical logs/state. Summing every frame's `value` double-counts calls and credits reverted transfers.
- Receipt and trace data is provisional until the containing block is canonical and sufficiently finalized for the chain's threat model. Bind processing to `(blockHash, txHash)`, require confirmations/finality before irreversible credit, and handle reorgs by reversing or replaying prior credits.

### Multi-Tenant Isolation

- Tenant-scoped counters and credits updated without tenant key in the where-clause; leak across orgs
- Admin aggregate views allowing actions that impact other tenants due to missing per-tenant enforcement

## Evasion Patterns

- Content-type switching (JSON/form/multipart) to hit different code paths
- Method alternation (GET performing state change; overrides via X-HTTP-Method-Override)
- Client recomputation: totals, taxes, discounts computed on client and accepted by server
- Cache/gateway differentials: stale decisions from CDN/APIM that are not identity-aware

## Special Contexts

### E-commerce

- Stack incompatible discounts via parallel apply; remove qualifying item after discount applied; retain free shipping after cart changes
- Modify shipping tier post-quote; abuse returns to keep product and refund

### Banking/Fintech

- Split transfers to bypass per-transaction threshold; schedule vs instant path inconsistencies
- Exploit grace periods on holds/authorizations to withdraw again before settlement

### SaaS/B2B

- Seat licensing: race seat assignment to exceed purchased seats; stale license checks in background tasks
- Usage metering: report late or duplicate usage to avoid billing or to over-consume

## Chaining Attacks

- Business logic + race: duplicate benefits before state updates
- Business logic + IDOR: operate on others' resources once a workflow leak reveals IDs
- Business logic + CSRF: force a victim to complete a sensitive step sequence

## Analysis Workflow

1. **Enumerate state machine** - Per critical workflow (states, transitions, pre/post-conditions); note invariants
2. **Build Actor × Action × Resource matrix** - Unauth, basic user, premium, staff/admin; identify actions per role
3. **Test transitions** - Step skipping, repetition, reordering, late mutation
4. **Introduce variance** - Time, concurrency, channel (mobile/web/API/GraphQL), content-types
5. **Validate persistence boundaries** - All services, queues, and jobs re-enforce invariants

### Verification Checks (per scenario)

Apply to every candidate finding; category-specific checks below.

**Universal:**

- [ ] Rule enforced server-side (handler, service, ORM/DB) — not client-side only
- [ ] Validation complete: negatives, upper bounds, edge cases, null/zero
- [ ] Check-then-act is atomic — no TOCTOU window on shared resources
- [ ] Re-validated at point of use, not only at an earlier step

**By category:**

- **Workflow:** each step verifies prior steps completed server-side; terminal endpoints unreachable without intermediates
- **Coupon/voucher:** marked used atomically in same DB transaction; concurrent redemption locked (SELECT FOR UPDATE, optimistic lock, CAS); expiry checked at redemption
- **Race/concurrency:** stock/balance check and decrement in one transaction or with row lock; idempotency key or dedup on concurrent duplicates
- **Entitlement/subscription:** current plan/tier checked at feature access — not cached at login without re-evaluation; **never** gate on client-supplied `is_premium` / `remaining_*` / `usage_count` / `bypass_limit`
- **Transfer/balance:** amount positive; sender balance sufficient; both checks inside a DB transaction
- **Usage limits:** remaining capacity loaded from a server ledger keyed by user/account (not session-only, not request body)

## Safe Patterns

- **Server-side validation only** — client constraints and API docs are not security controls
- **Atomic transactions with locking** — check-and-decrement, coupon mark-used, inventory reserve in one transaction
- **Idempotency keys** — scoped to principal + operation; persisted beyond cache TTL
- **Re-evaluate entitlement at access time** — plan/tier/feature gate on every mutation and read of protected resource
- **Quota from server ledger** — `remaining` / `usage_count` / tier derived from DB/Redis keyed by authenticated principal; request body may carry the *action*, never the *remaining allowance*
- **DB-level constraints** — CHECK constraints, unique indexes, and row locks can enforce rules invisible in app code alone

## Confirming a Finding

1. Show an invariant violation (e.g., two refunds for one charge, negative inventory, exceeding quotas)
2. Provide side-by-side evidence for intended vs abused flows with the same principal
3. Demonstrate durability: the undesired state persists and is observable in authoritative sources (ledger, emails, admin views)
4. Quantify impact per action and at scale (unit loss × feasible repetitions)

### Dynamic Test / PoC

Short runtime checks to confirm static findings:

| Scenario | Test | Expected signal if vulnerable |
|----------|------|--------------------------------|
| Negative quantity | `POST /orders` with `"quantity": -1` | Credit/refund issued; negative line total accepted |
| Concurrent coupon | Two parallel `POST /checkout` with same single-use code | Both succeed; coupon used twice |
| Workflow skip | Call finalize/confirm endpoint without prior verify/payment step | Order completes; status jumps to terminal state |
| Entitlement bypass | Downgrade plan, then access premium endpoint in same session | Premium feature returns success |
| Double-spend | Two concurrent transfers/purchases equal to full balance | Both succeed; balance goes negative |
| Out-of-range value | Submit rating/score above declared maximum | Value persisted above cap |

Include exact method, endpoint, body, and the durable side effect (ledger entry, email, admin view) that proves invariant violation.

## Common False Alarms

- Promotional behavior explicitly allowed by policy (documented free trials, goodwill credits)
- Visual-only inconsistencies with no durable or exploitable state change
- Admin-only operations with proper audit and approvals
- Display-only echoes of `remaining_downloads` in a response when the **next** gate recomputes from a server ledger (not when the same request body field authorizes the action)
- Presence of `@login_required` / rate-limit middleware alone — does **not** make a body-trusted quota gate SAFE

## Business Risk

- Direct financial loss (fraud, arbitrage, over-refunds, unpaid consumption)
- Regulatory/contractual violations (billing accuracy, consumer protection)
- Denial of inventory/services to legitimate users through resource exhaustion
- Privilege retention or unauthorized access to premium features

## Analyst Notes

1. Start from invariants and ledgers, not UI—prove conservation of value breaks
2. Test with time and concurrency; many bugs only appear under pressure
3. Recompute totals server-side; never accept client math—flag when you observe otherwise
4. Treat idempotency and retries as first-class: verify key scope and persistence
5. Probe background workers and webhooks separately; they often skip auth and rule checks
6. Validate role/feature gates at the service that mutates state, not only at the edge
7. Explore end-of-period edges (month-end, trial end, DST) for rounding and window issues
8. Use minimal, auditable PoCs that demonstrate durable state change and exact loss
9. Chain with authorization tests (IDOR/Function-level access) to magnify impact
10. When in doubt, map the state machine; gaps appear where transitions lack server-side guards

## Core Principle

Business logic security is the enforcement of domain invariants under adversarial sequencing, timing, and inputs. If any step trusts the client or prior steps, expect abuse.

## Static Analysis Heuristics for Business Logic Flaws

Business logic flaws are notoriously hard to detect statically, but the following code patterns are strong indicators:

### 1. Client-Side-Only Enforcement
When security-critical decisions are enforced only in JavaScript/HTML but not validated server-side:
```python
# VULN: hidden form field controls admin access — no server-side check
# HTML: <input type="hidden" name="isAdmin" value="0">
if request.form.get('isAdmin') == '1':
    grant_admin_access()
```
```php
// VULN: client-side role check, server trusts whatever arrives
if ($_POST['role'] === 'admin') {
    $_SESSION['role'] = 'admin';  // no verification against DB
}
```

### 2. Type Juggling / Loose Comparison Auth Bypass
When authentication or authorization uses loose comparison that can be tricked:
```php
// VULN: strcmp returns NULL on type juggling (array input), NULL == 0 is true
if (strcmp($_POST['password'], $stored_password) == 0) { login(); }

// VULN: MD5 magic hash — '0e...' == '0e...' is true in loose comparison
if (md5($_POST['password']) == $stored_hash) { login(); }
```

### 3. Hardcoded Verification / 2FA Codes
```python
# VULN: 2FA code is hardcoded, not generated per-session
if request.form['2fa_code'] == '1234':
    session['2fa_verified'] = True
```

### 4. Missing Server-Side Price/Amount Validation
When the server accepts client-computed values for financial transactions:
```python
# VULN: total comes from client, not recomputed from item prices
total = request.form['total']
charge_payment(total)
```

**JSON duplicate-key policy↔execution drift (not the same as trusting a single client total):** when a gateway/policy sidecar and the transfer handler each parse the **same raw JSON body**, duplicate keys can make policy authorize one `amount` while execution debits another (`{"amount":10,"amount":1000}`). Auth + “policy checked amount” is **not** SAFE if the two layers use different first/last-wins JSON parsers. Full SAST signals and SAFE parse-once / reject-duplicates patterns: `input_validation.md` (*JSON body duplicate-key drift*). Tag `business_logic` when the durable impact is a ledger/price invariant; the root cause is the dual parse.

### 5. State Machine Violations
When critical workflow steps can be skipped or reordered:
```python
# VULN: no check that step 1 (verification) was completed before step 2 (action)
@app.route('/transfer', methods=['POST'])
def transfer():
    # missing: if not session.get('verified'): abort(403)
    do_transfer(request.form['amount'], request.form['to'])
```

### 6. HTTP Method Tampering
When access control checks apply only to certain HTTP methods:
```python
# VULN: POST is protected but GET/PUT/DELETE bypass the check
@app.route('/admin/action', methods=['GET', 'POST', 'PUT', 'DELETE'])
def admin_action():
    if request.method == 'POST':
        if not current_user.is_admin:
            abort(403)
    # GET/PUT/DELETE reach here without admin check
    perform_action()
```

```apache
# .htaccess — VULN: only protects GET and POST
<Limit GET POST>
    Require valid-user
</Limit>
# PUT, DELETE, PATCH bypass authentication entirely
```

### 7. Insufficient Rate Limiting on Sensitive Operations
When brute-forceable operations lack rate limiting:
```python
# VULN: no rate limit on password reset / OTP verification
@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    if request.form['otp'] == session['otp']:  # 4-digit = 10000 attempts
        reset_password()
```

### 8. Inverted / Mismatched Event Handler
When a dispatch table routes an event to a handler whose action contradicts the event name (copy-paste bug), the intended state change silently inverts. A deprovision/revoke event that runs the provision/grant path leaves access in place — a real access-control failure that no input-validation rule catches.
```javascript
// VULN: handler action is the inverse of the event it serves
switch (event.type) {
  case "membership.removed":
    return addMembership(event.payload);   // never revokes → stale access
  case "user.deactivated":
    return activateUser(event.payload);    // account stays live
}
```
Recon: enumerate `switch`/dispatch maps over event/webhook/message types and verify each handler's verb matches its case (add↔remove, grant↔revoke, enable↔disable, create↔delete). High-value on auth/membership/billing/lifecycle events.

### When to Tag Business Logic
- The vulnerability **cannot be described by a more specific injection or access control class**
- The flaw is in the **application's domain rules**, not in generic input handling
- The exploit involves **abusing intended functionality** rather than injecting payloads
- Client-side-only enforcement of critical business rules
- HTTP method tampering that bypasses access controls
- Type juggling or loose comparison that breaks authentication logic

### Relationship to Concurrency

| Signal | Tag | Rationale |
|--------|-----|-----------|
| Race condition on shared resource (double-spend, TOCTOU) | `race_conditions` | Primary exploit is timing/concurrency |
| Business rule bypass that uses parallel requests as the mechanism | `business_logic` | Primary exploit is domain invariant violation; concurrency is only the vehicle |
| Idempotency key reuse across users | `business_logic` | Domain-level key scoping flaw, not a raw concurrency bug |
| Thread-pool exhaustion via unbounded parallel requests | `denial_of_service` | Resource exhaustion, not a business rule |

When both concurrency AND business logic are present, prefer the tag that describes the **primary exploit primitive**. If the attacker must violate a domain invariant (price, quota, state machine) to achieve impact, tag `business_logic` even if concurrency is the delivery mechanism.

### Tag Precision in Benchmark Mode

To reduce false positives, apply the following guardrails when tagging `business_logic`:

- Do NOT emit `business_logic` when a more specific tag fully describes the vulnerability (e.g., `csrf`, `idor`, `race_conditions`, `brute_force`)
- Do NOT emit `business_logic` for missing input validation that is better described as an injection class (SQLi, XSS, etc.)
- Do NOT emit `business_logic` for generic missing authorization -- prefer `privilege_escalation` or `idor`
- Emit `business_logic` only when the flaw is in the **application's domain rules** and cannot be reduced to a standard vulnerability class
