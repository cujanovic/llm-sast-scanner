---
name: webhook_integration_security
version: "0.6"
description: Webhook and third-party integration security — outbound SSRF via test/ping/verify URL features, webhook CRUD IDOR/BFLA, unallowlisted delivery with redirect follow, OAuth redirect_uri from query without allowlist, inbound webhook receivers missing HMAC signature verification or replay protection, signing-secret disclosure, and third-party support/feedback/chat widget identity that trusts client-controlled userId/email without a server-signed JWT or HMAC proof (CWE-918 / CWE-639 / CWE-352 / CWE-287); cloud event channels (SES via SNS, S3 notifications) whose grant admits every customer of the provider
---

# Webhook & Integration Security (CWE-918 / CWE-639 / CWE-352)

Webhook integrations combine **outbound** server-side HTTP (delivery, health checks, URL verification) with **inbound** event receivers and OAuth-style callback configuration. Static analysis should trace user-supplied callback URLs through outbound clients, webhook CRUD handlers for owner/tenant authorization, inbound signature verification, and secret handling. The highest-impact failures are server-initiated requests to attacker-controlled destinations (SSRF to internal/metadata endpoints), cross-tenant webhook manipulation, and accepting forged inbound events without cryptographic verification.

## What It Is / Is Not

- **Is**: server makes an outbound HTTP request to a user-supplied webhook/callback URL (`testWebhook`, `pingWebhook`, `verifyUrl`, `sendTest`); webhook create/update/delete without owner or tenant scope check; outbound delivery to arbitrary hosts with redirect following enabled; integration OAuth `redirect_uri` taken from query/body without registered allowlist; inbound webhook handler that processes JSON/events with no HMAC/signature check, no timestamp window, or no nonce/idempotency; signing secret logged or returned in API responses; **third-party support/feedback/chat/portal SDKs** booted or identified with client-controlled `userId`/`email`/`name` and no server-signed JWT/HMAC identity proof; host backends that proxy client identity fields to a vendor identify API without binding to the authenticated session.
- **Is not**: generic SSRF in non-webhook features (image proxy, import-from-URL) — see `ssrf.md` for IP/metadata defenses and client hardening. OAuth authorize/callback flow misconfiguration without webhook context — see `oauth_oidc_misconfiguration.md`. IDOR on non-webhook resources — see `idor.md`. CSRF on browser forms unrelated to webhook endpoints — see `csrf.md`. Generic spoofable `X-User-Id` middleware alone — see `trust_boundary.md` (widget identity is the same class applied to SaaS SDKs).
- **Highest signal** on handlers named `*webhook*`, `*callback*`, `*integration*`, outbound job workers that POST to stored URLs, inbound routes under `/webhooks/`, `/hooks/`, `/integrations/events`, and client/SDK calls named `identify`/`boot`/`Featurebase(`/`Intercom(`/`Crisp(`/`zendesk` with plaintext identity fields.

## Source -> Sink Pattern

**Sources (outbound)**
- Request body/query: `webhook_url`, `callback_url`, `url`, `endpoint`, `target`, `ping_url`, `verify_url`
- Stored webhook record: URL persisted at create/update time, later used by delivery worker or test action
- OAuth integration setup: `redirect_uri` from client query during connect/test flow

**Sinks (outbound — SSRF archetype)**
- `requests.post(user_url)`, `fetch(callbackUrl)`, `axios.post(webhookUrl)`, `HttpClient.PostAsync(url)`, `RestTemplate.postForObject(url, …)`
- Handlers: `testWebhook`, `pingWebhook`, `verifyUrl`, `sendTest`, `validateWebhook`, `checkEndpoint`
- Redirect-following enabled on delivery client (`allow_redirects=True`, `maxRedirects > 0`, default fetch follow)
- **Cloud-managed push/subscription destinations** — the delivery request is made by the *cloud service or an SDK call*, not a visible `fetch`, so a grep for HTTP clients misses it: AWS **SNS** HTTP/S subscription `sns.subscribe(Protocol='https', Endpoint=…)`, **EventBridge API destination** `createApiDestination(InvocationEndpoint=…)`, **GCP Pub/Sub** push subscription `pushConfig.pushEndpoint`, **Azure Event Grid** `webhook_endpoint.url`, or a **webhook-as-a-service** (Svix/Hookdeck) endpoint. A user/attacker-influenced destination is still an SSRF sink; SNS additionally POSTs a `SubscriptionConfirmation` to the endpoint **immediately on subscribe**

**Sources (inbound receiver)**
- Raw HTTP body, headers (`X-Hub-Signature`, `X-Signature`, provider-specific signature headers)
- Query params on webhook ingress route

**Sinks (inbound — trust failure)**
- Event parsed and applied without signature verification: `processWebhook(req.body)`, `handleStripeEvent(payload)` with no HMAC compare
- Missing replay controls: no `timestamp`/`t` tolerance check, no nonce/event-id deduplication store

**Sources (authorization)**
- Path/body IDs: `webhook_id`, `integration_id`, `hookId`, `subscription_id`
- Tenant context missing on CRUD: `DELETE /webhooks/:id` without `owner_id` / `tenant_id` filter

**Sinks (IDOR/BFLA)**
- `Webhook.findById(id)` then update/delete without `where user_id = currentUser`
- Admin-only integration settings exposed on user-scoped routes

**Sources (secrets)**
- `signing_secret`, `webhook_secret`, `shared_secret` from DB or env

**Sinks (disclosure)**
- `logger.info("webhook secret: %s", secret)`, API response `{ signingSecret: row.secret }`, debug endpoint returning full webhook config

## Recon Indicators (Grep)

```bash
# Outbound test/ping/verify webhook features
rg -ni 'testWebhook|pingWebhook|verifyUrl|sendTest|validateWebhook|checkEndpoint|test_webhook|ping_webhook' .
rg -ni 'webhook_url|callback_url|callbackUrl|webhookUrl|ping_url|verify_url' .

# Outbound HTTP to variable URL (trace taint from user input)
rg -n 'requests\.(get|post|put|request)\(|fetch\(|axios\.(get|post|request)|HttpClient\.|RestTemplate\.|httpx\.|aiohttp\.' .

# Redirect following on delivery clients
rg -ni 'allow_redirects\s*=\s*True|follow_redirects\s*=\s*True|maxRedirects|redirect:\s*["'"'"']follow["'"'"']' .

# Cloud-managed push/subscription destinations (delivery made by the cloud service / SDK, not a fetch)
rg -ni 'sns\.subscribe|SubscribeCommand|create_?api_?destination|createApiDestination|InvocationEndpoint|pushEndpoint|push_endpoint|webhook_endpoint|aws_sns_topic_subscription|aws_cloudwatch_event_api_destination|google_pubsub_subscription|azurerm_eventgrid_event_subscription|svix|hookdeck' .

# Webhook CRUD without obvious owner scope
rg -ni 'webhook|WebHook|WebhookSubscription' --glob '*.{py,js,ts,java,go,rb,php,cs}' | rg -i 'create|update|delete|destroy|remove'
rg -ni 'findById|find_by_id|getWebhook|Webhook\.find|webhooks\.get' .

# Inbound receivers — signature verification presence
rg -ni '/webhooks|/hooks/|handleWebhook|processWebhook|onWebhook|webhookHandler' .
rg -ni 'X-Hub-Signature|X-Signature|sha256=|hmac|verifySignature|verify_signature|timingSafeEqual|compare_digest' .

# OAuth redirect_uri in integration connect flows
rg -ni 'redirect_uri|redirectUri' --glob '*.{js,ts,py,java,go,rb,php}' | rg -i 'integration|connect|webhook|oauth'

# Secret logging / API exposure
rg -ni 'signing_secret|webhook_secret|shared_secret|WH_SECRET' .
rg -ni 'logger\.(info|debug|warn).*secret|console\.log.*secret' .
```

For each outbound hit: confirm allowlist validation and internal-IP/metadata blocking before the HTTP call — see `ssrf.md`. For CRUD hits: confirm query includes authenticated principal's `user_id`/`tenant_id`. For inbound hits: confirm HMAC verified with constant-time compare before side effects.

## Vulnerable Conditions

1. **Test/ping URL feature**: admin or user triggers server-side GET/POST to arbitrary URL from form field with no destination allowlist.
2. **Stored webhook URL**: URL saved at registration; background worker delivers events without re-validating host against allowlist at send time.
3. **Redirect chains**: HTTP client follows 301/302 from public URL to `http://169.254.169.254/` or internal RFC1918 address.
4. **Webhook IDOR**: `PUT /api/webhooks/{id}` or `DELETE /api/webhooks/{id}` loads by primary key only; attacker swaps ID across accounts.
5. **Integration OAuth redirect**: connect flow accepts `redirect_uri` query parameter not present in registered client list (prefix/substring match counts as vulnerable — see `oauth_oidc_misconfiguration.md`).
6. **Unauthenticated inbound**: POST to `/webhooks/stripe` (or generic provider route) parses body and updates account state with no signature header check.
7. **Replay**: same signed payload accepted indefinitely; no `timestamp` skew window (e.g. ±5 minutes) or event-id idempotency store.
8. **Secret disclosure**: create-webhook response includes `signing_secret`; secret written to application logs on delivery failure.
9. **Signature verified over the wrong bytes**: HMAC computed over a *re-serialized* parsed body (`createHmac(...).update(JSON.stringify(await req.json()))`, `hmac(json.dumps(parsed))`) instead of the **exact raw request bytes** the sender signed. `JSON.stringify`/`json.dumps` of the parsed object differs from the original payload in key order, whitespace, and number/unicode escaping, so the digest can never match a legitimate signature — and frameworks that auto-parse the body (Next.js `req.json()`, Express default `json()` middleware, FastAPI model binding) make this the *default* mistake, pushing developers to weaken or skip the check to make it "work." **Capture and HMAC the raw bytes before any parse.** SAST signal: an HMAC `update(...)` whose argument is a parsed/stringified body rather than a raw buffer/`req.rawBody`/`await req.text()`.
10. **Cloud eventing push destination set from user input**: an HTTP(S) delivery endpoint registered through a cloud eventing **SDK or IaC** — SNS subscription `Endpoint` (`sns.subscribe`/`SubscribeCommand`), EventBridge API-destination `InvocationEndpoint` (`createApiDestination`), GCP Pub/Sub `push_endpoint`, Azure Event Grid `webhook_endpoint.url` (Terraform `aws_sns_topic_subscription` / `aws_cloudwatch_event_api_destination` / `google_pubsub_subscription` / `azurerm_eventgrid_event_subscription`) — is user/attacker-influenced and not constrained to an **HTTPS host allowlist**. The request to the endpoint is issued by the cloud service (or the SDK call), so a `fetch`/`requests` grep misses it, yet an internal/RFC1918/metadata endpoint is still reached — and SNS confirms a subscription by POSTing to the endpoint at subscribe time. Enforce the same allowlist + internal-IP/metadata block + HTTPS-only **at registration**, and prefer provider signature/`ConnectionArn`-scoped auth on delivery. Cross-ref `iac_security.md`, `ssrf.md`.
11. **Cloud event channel open to every provider customer**: the inbound channel is a cloud service's own delivery — SES feedback or event publishing through an SNS topic, an S3 event notification — whose grant names the provider's service principal with no condition pinning a source account, organization or resource, at a service that delivers for other accounts (the shared block under **Downgrade when** names them), and the consumer acts on each event without checking its origin by a value the provider sets (the identity ARN, the bucket and its owner): anyone with an account at the provider can point their own configuration at the channel and feed the consumer genuine provider-generated events.

## Vulnerable vs Safe Code Examples

```python
# VULN — test webhook: SSRF to internal/metadata
@app.post("/webhooks/test")
def test_webhook(body):
    url = body["webhook_url"]
    return requests.post(url, json={"ping": True}, timeout=5).text

# SAFE — allowlist + block internal IPs + no redirects (see ssrf.md for IP pinning)
ALLOWED_HOSTS = {"hooks.example.com", "api.partner.example"}
def test_webhook(body):
    parsed = urlparse(body["webhook_url"])
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("destination not allowed")
    if resolves_to_private_ip(parsed.hostname):
        raise ValueError("internal destination blocked")
    return requests.post(body["webhook_url"], json={"ping": True}, allow_redirects=False, timeout=5)
```

```javascript
// VULN — delete webhook by ID only (IDOR)
app.delete('/api/webhooks/:id', auth, async (req, res) => {
  await Webhook.destroy({ where: { id: req.params.id } });
  res.sendStatus(204);
});

// SAFE — scope to authenticated owner/tenant
app.delete('/api/webhooks/:id', auth, async (req, res) => {
  const n = await Webhook.destroy({
    where: { id: req.params.id, userId: req.user.id, tenantId: req.user.tenantId },
  });
  if (!n) return res.sendStatus(404);
  res.sendStatus(204);
});
```

```javascript
// VULN — inbound webhook: no signature verification
app.post('/webhooks/events', (req, res) => {
  processOrderUpdate(req.body);
  res.sendStatus(200);
});

// VULN — HMAC over a RE-SERIALIZED parsed body: digest can never match the sender's raw-byte signature
app.post('/webhooks/events', express.json(), (req, res) => {        // auto-parses & discards raw bytes
  const expected = crypto.createHmac('sha256', WEBHOOK_SECRET)
    .update(JSON.stringify(req.body)).digest('hex');                // wrong input: re-serialized, not raw
  if (req.headers['x-signature'] !== expected) return res.sendStatus(401); // also non-constant-time
  processOrderUpdate(req.body);
  res.sendStatus(200);
});

// SAFE — HMAC verify + timestamp window + constant-time compare (note: HMAC over the RAW body bytes)
import crypto from 'crypto';
app.post('/webhooks/events', express.raw({ type: '*/*' }), (req, res) => {
  const sig = req.headers['x-signature'];
  const ts = req.headers['x-timestamp'];
  if (!sig || !ts || Math.abs(Date.now() / 1000 - Number(ts)) > 300) {
    return res.sendStatus(401);
  }
  const expected = crypto.createHmac('sha256', WEBHOOK_SECRET).update(req.body).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
    return res.sendStatus(401);
  }
  processOrderUpdate(JSON.parse(req.body));
  res.sendStatus(200);
});
```

```python
# VULN — signing secret in list/get responses and logs
def get_webhook(webhook_id):
    row = Webhook.get(webhook_id)
    logger.info("loaded webhook secret=%s", row.signing_secret)
    return {"id": row.id, "url": row.url, "signing_secret": row.signing_secret}

# SAFE — secret never logged; omitted from read APIs (one-time display at create if required)
def get_webhook(webhook_id):
    row = Webhook.get(webhook_id)
    return {"id": row.id, "url": row.url}
```

```javascript
// VULN — integration OAuth redirect_uri from query without allowlist
app.get('/integrations/oauth/start', (req, res) => {
  const redirectUri = req.query.redirect_uri;
  res.redirect(buildAuthorizeUrl({ redirect_uri: redirectUri }));
});

// SAFE — redirect_uri must match registered client set (exact match)
app.get('/integrations/oauth/start', (req, res) => {
  const redirectUri = req.query.redirect_uri;
  if (!CLIENT.redirectUris.includes(redirectUri)) {
    return res.status(400).send('invalid redirect_uri');
  }
  res.redirect(buildAuthorizeUrl({ redirect_uri: redirectUri }));
});
```

## Third-party widget / portal identity (client-trusted userId/email)

Support, feedback, changelog, survey, and chat widgets (and their public portals) commonly accept an **identify/boot** payload that maps a visitor to a vendor-side user. In production, identity fields must be **cryptographically bound by the host backend** (server-signed JWT or HMAC of `user_id`). When the browser (or an authenticated host proxy) can supply arbitrary `userId`/`email`/`name`, an attacker impersonates any customer → private conversations, author-only posts, and often **email change → password-reset account takeover** on the vendor portal.

**This is a finding in the host application code/config**, not a "vendor-only" issue. Vendor docs that call secure installation "optional" or "disable for local testing" do **not** make production plaintext identity SAFE. **"They should enable JWT in the dashboard"** is not a mitigator when the shipped SDK boot still passes client-editable fields.

### SAST signals (host app)

| Shape | VULN | SAFE |
|-------|------|------|
| Feedback/support SDK `identify` / `boot` / provider props | Plain `userId`/`email`/`name`/`companies` from client state | Only `featurebaseJwt` / `user_hash` / equivalent minted on the **server** with a secret never shipped to the browser |
| Intercom / Crisp / Zendesk / similar Messenger boot | `user_id`+`email` without `user_hash` (HMAC-SHA256 of user id with app secret) | Server computes `user_hash` (or JWT) and injects it; secret stays server-side |
| Host API proxy to vendor `/identify` / SSO | Forwards `req.body.userId`/`email` under a service key despite `requireAuth` | Bind to `req.session.userId` / verified JWT `sub`; sign vendor JWT server-side; never trust body identity fields |
| Dashboard/config | Secure installation / identity verification **disabled** in prod config checked into repo | Secure mode required; plaintext identify rejected |

**Recon**: `rg -n "Featurebase\(|featurebaseJwt|Intercom\(|user_hash|Crisp\.|zendesk|identify.*userId|boot.*user_id" --glob '*.{js,jsx,ts,tsx,vue,html}'` then confirm whether a server-minted proof is present. Also flag `Settings → Security` / `secureInstallation: false` / `identityVerification: false` style config in production.

```javascript
// VULN — plaintext identity in production widget boot
Featurebase('identify', {
  organization: 'acme',
  email: window.__USER__.email,
  userId: window.__USER__.id,
  name: window.__USER__.name,
});

// VULN — Intercom without user_hash
Intercom('boot', {
  app_id: 'abc',
  user_id: user.id,
  email: user.email,
});

// SAFE — server-signed proof only
Featurebase('identify', {
  organization: 'acme',
  featurebaseJwt: user.featurebaseJwt, // minted with FEATUREBASE_JWT_SECRET on backend
});

Intercom('boot', {
  app_id: 'abc',
  user_id: user.id,
  email: user.email,
  user_hash: user.intercomUserHash, // hmac_sha256(secret, user.id) on backend
});
```

```javascript
// VULN — authenticated proxy still trusts client identity fields (confused deputy)
app.post('/integrations/vendor/identify', requireAuth, async (req, res) => {
  await fetch('https://vendor.example/api/v1/user/identify', {
    method: 'POST',
    headers: { Authorization: `Bearer ${process.env.VENDOR_KEY}` },
    body: JSON.stringify({
      userId: req.body.userId, // attacker-chosen
      email: req.body.email,
    }),
  });
});

// SAFE — bind to session; mint signed vendor JWT server-side
app.post('/integrations/vendor/identify', requireAuth, async (req, res) => {
  const token = jwt.sign(
    { userId: req.session.userId, email: req.session.email },
    process.env.VENDOR_JWT_SECRET,
    { algorithm: 'HS256' },
  );
  await fetch('https://vendor.example/api/v1/user/identify', {
    method: 'POST',
    body: JSON.stringify({ featurebaseJwt: token }),
  });
});
```

**Impact chain (report as High/Critical when reachable):** impersonate victim on vendor portal → change email / steal session or access token from profile APIs → password reset or direct session use → ATO. Cross-ref `idor.md` when the vendor identify endpoint itself is the object under test; cross-ref `trust_boundary.md` for the outbound confused-deputy framing.

## Safe Patterns

- **Outbound destinations**: strict HTTPS host allowlist per integration type; resolve DNS and reject private/link-local/metadata ranges; disable redirect following or re-validate each hop — full SSRF checklist in `ssrf.md`. **Do not treat** framework syntax-only URL rules (`'url'`, `FILTER_VALIDATE_URL`, `isURL`/`HttpUrl`) as destination allowlists — see `ssrf.md` *False-SAFE barriers — syntax-only URL validation*.
- **Dedicated egress**: webhook delivery from isolated network segment or proxy that cannot reach internal services.
- **Webhook CRUD**: every read/update/delete filters by authenticated `user_id`/`tenant_id`; admin routes require explicit role check — see `idor.md`.
- **Inbound verification**: verify provider HMAC (`sha256=…`, `v1=…`) with `crypto.timingSafeEqual` / `hmac.compare_digest`; reject missing or stale `timestamp`; store processed event IDs for idempotency.
- **OAuth integration**: `redirect_uri` exact-match against registered list — see `oauth_oidc_misconfiguration.md`.
- **Secrets**: generate with CSPRNG; store hashed if comparison-only; never log; omit from list/get API responses; rotate on compromise.
- **Delivery resilience**: retry with backoff; sign outbound payloads so receivers can verify authenticity.

## Severity / Triage

| Condition | Typical severity |
|-----------|------------------|
| Test/ping/verify URL to arbitrary host (no allowlist) | **High** — SSRF to metadata/internal |
| Outbound delivery + redirect follow to internal | **High** |
| Webhook delete/update IDOR across tenants | **High** |
| Inbound webhook without signature on state-changing handler | **High** — forged events |
| Cloud event channel (SES via SNS, S3 notifications) whose grant admits the provider's service principal | Rated by the shared block under **Downgrade when** — unbound: **High** when the consumer changes state keyed by the event, **Medium** otherwise; account-bound: one level lower; resource-bound: no finding. The attacker's own provider account is no privileged position (base Severity Downgrade Rule) |
| Integration `redirect_uri` prefix/substring acceptance | **High** — code/token theft chain |
| Signing secret in logs or list API | **Medium–High** |
| Missing replay window on signed inbound | **Medium** (depends on event impact) |
| Production widget identify/boot with plaintext userId/email (no JWT/HMAC) | **High–Critical** — impersonation / ATO via vendor portal |
| Host identify proxy forwards client userId under service key | **High–Critical** — confused-deputy ATO |
| Read-only webhook metadata IDOR (URL leak, no mutation) | **Medium** |
| Test feature restricted to admin + strict allowlist | **Info / FALSE POSITIVE** |
| Widget identify with server-minted JWT/user_hash only | **FALSE POSITIVE** |

Downgrade when: outbound path uses allowlist + IP block + no redirects; CRUD scoped to owner; inbound HMAC + timestamp + idempotency enforced; secrets not exposed after create. A cloud event channel is rated by the shared block below, which `iac_security.md` holds word for word:

<!-- BEGIN shared block: service-principal grants — identical in iac_security.md and webhook_integration_security.md -->
**Service-principal grants** — a resource policy or Lambda permission that admits a cloud provider's service principal
(`ses.amazonaws.com`, `s3.amazonaws.com`, …). CWE-441; the record's `File:` is the grant's principal line — the line
naming the service principal (`- ses.amazonaws.com`, `Service: sns.amazonaws.com`, `principal = "s3.amazonaws.com"`,
`identifiers = ["ses.amazonaws.com"]`), as the base skill's Deduplication & Sink Location rule has it — whichever class
reports it, so the records of whom one grant admits name one line and merge as one finding for each consumer the grant
feeds (one when none is in scope): a grant finding's entry point is that consumer, named as the scan's entry-point list
names it, else by its handler's `file:line` — `none in scope` when there is none.
- **Which services deliver for other accounts.** SES (an event destination or a feedback notification that another
  account's configuration set or identity names), S3 event notifications (to a topic, queue or function), API Gateway (a
  Lambda permission for `apigateway.amazonaws.com` lets another account's API integrate the function, and that API
  writes the whole event — a non-proxy integration's template sets every field, `requestContext` included — so no event
  field is a provider-set origin or sending account; AWS's own setup binds the grant by an `aws:SourceArn` naming the
  API), and CloudTrail, AWS Config and log delivery (`delivery.logs.amazonaws.com`) writing to a bucket do. These do not
  through the service principal alone, so a grant to them is account-bound at most: SNS — until the endpoint's owner
  confirms a subscription made by another account's topic, that topic can place only `SubscriptionConfirmation` messages
  in the queue or function (unbound only when the consumer itself confirms a `SubscribeURL`); EventBridge — another
  account's rules reach a target only through an execution role the target's policy admits by account ID, and a grant to
  `events.amazonaws.com` serves rules of the same account; S3 server access logging (`logging.s3.amazonaws.com`) —
  buckets of the same account only. A service not named here delivers for other accounts unless the provider's
  documentation, read in this run, says otherwise; one you cannot check is unbound at LIKELY.
- **Unbound** — no condition pins an account: none of `aws:SourceArn`, `aws:SourceAccount`, `aws:SourceOwner`,
  `aws:SourceOrgID`, `aws:SourceOrgPaths` (a Lambda permission: `SourceArn`, `SourceAccount`), or every value leaves the
  account open (`*`, `arn:aws:ses:*`, `arn:aws:ses:*:*:configuration-set/x`, a topic or function name any account can
  create) — at a service that delivers for other accounts. An S3 bucket name is global: `arn:aws:s3:::<bucket>` and
  `arn:aws:s3:*:*:<bucket>` pin that bucket (the S3 bullet below); an API Gateway id is a label AWS assigns (the
  `<api-id>.execute-api.<region>.amazonaws.com` host) that no account can choose, so an `arn:aws:execute-api:…` value
  whose id segment is written out in full — no `*` or `?` in it — pins that API even with the account or region left
  open (resource-bound below). The rating is the class default: **High** when an event the attacker's configuration
  produces makes the consumer change data or behaviour beyond that event's own record — a recipient blocked or
  suppressed, a record updated or deleted, privileged code invoked — keyed by a value the event chooses (a recipient
  address, an object key); **Medium** otherwise (each event only appended to a log or archive, or a fixed action no
  event value steers); with no consumer in scope, Medium at LIKELY.
- **Account-bound** — a condition pins an account or organization (this one, or a sending account or organization the
  grant names: `aws:SourceAccount`, the legacy `aws:SourceOwner`, `aws:SourceOrgID`, `aws:SourceOrgPaths`; a Lambda
  permission's `SourceAccount`) but not the resource meant to deliver; or the consumer checks only the sending account
  (`mail.sendingAccountId`); or the service delivers only within its own account (above). What remains needs a principal
  inside that account: the Severity Downgrade Rule's privileged position, applied once — one level below the unbound
  rating of the same consumer. The record names it
  `privileged position: an IAM principal inside the account the grant at <file:line> pins (a role held, not a hop)`,
  `<file:line>` being the record's own `File:` line (a verdict cell names an identifier from its record), at the end of
  its `Judge:` line, after `; `, and, when Step 6 runs on it, on its `Adversarial:` line as well — as a `DOWNGRADED`
  verdict's trigger and named thing while the account pin holds, or in the rationale of a `DISPUTED` one — and no later
  step demotes it again for that position.
- **Resource-bound** — no finding: a condition pins the one resource meant to deliver (its ARN; an S3 bucket ARN together
  with `aws:SourceAccount`), or the consumer rejects, before acting, every event whose provider-set origin is not that
  resource — the identity ARN (`mail.sourceArn`; an event without it rejected too), the bucket with its owner. A
  configuration-set name, a message tag or anything else the sender chooses is no origin check; an SES identity binds
  whoever can verify its domain or address. When only the consumer's check binds and the grant itself pins nothing, the
  unpinned grant is a Hardening Note.
- **S3 bucket ARN without `aws:SourceAccount`** — a Hardening Note, no severity, when this repository creates that bucket:
  the pin holds while the bucket exists, and a deleted bucket's name can be recreated by any account. When the
  repository does not create it, nothing shows who owns the name: unbound, at LIKELY.
- **Never grounds to lower these ratings** — no downgrade, NEEDS CONTEXT, DISPUTED or UNCERTAIN mark: holding an account
  at the provider; knowing the resource's ARN, account ID or bucket name (AWS treats them as non-secret); the provider's
  gate on the attacker's own account (SES production access, a sending quota), which is part of opening that account —
  the record may mention it in Impact.
<!-- END shared block -->

## Common False Alarms

- Outbound URL is hardcoded provider endpoint with user input only in signed payload body (not authority).
- Test-webhook feature disabled in production or gated behind admin role with fixed partner allowlist.
- `findById` followed by explicit `row.userId === req.user.id` guard on every mutating path.
- Inbound route uses library middleware that verifies signature before handler (confirm default is not `verify: false`).
- Signing secret returned only once on `201 Created` and documented as intentional; absent on subsequent GET — still flag if logged.
- Webhook URL validated at write time **and** re-validated at delivery time with same allowlist.

## Cross-References

- `ssrf.md` — outbound fetch SSRF: IP/metadata defenses, redirect chains, DNS rebinding, allowlist patterns (webhook test/ping is a common SSRF archetype; do not duplicate full SSRF sink catalog here).
- `idor.md` — webhook/integration CRUD without owner or tenant authorization.
- `oauth_oidc_misconfiguration.md` — integration OAuth `redirect_uri` validation, state/PKCE (when connect flow uses OAuth).
- `csrf.md` — browser-initiated webhook configuration changes without anti-CSRF token.
- `information_disclosure.md` — signing secrets and integration tokens in responses/logs.
- `business_logic.md` — webhook event handlers with inverted or missing verb checks (grant vs revoke).
- `api_security.md` — REST webhook management API surface.
- `iac_security.md` — the resource-policy grant itself when a cloud event channel admits a service principal with no condition pinning its source, and which services let another customer deliver.

## Core Principle

Treat webhook URLs as **server-side network destinations** subject to SSRF controls, webhook records as **tenant-scoped objects** requiring authorization on every access, and inbound events as **unauthenticated until HMAC-verified** with replay protection — never trust payload content or client-supplied redirect URIs without allowlist binding.
