---
name: webhook_integration_security
description: Webhook and third-party integration security — outbound SSRF via test/ping/verify URL features, webhook CRUD IDOR/BFLA, unallowlisted delivery with redirect follow, OAuth redirect_uri from query without allowlist, inbound webhook receivers missing HMAC signature verification or replay protection, and signing-secret disclosure (CWE-918 / CWE-639 / CWE-352)
---

# Webhook & Integration Security (CWE-918 / CWE-639 / CWE-352)

Webhook integrations combine **outbound** server-side HTTP (delivery, health checks, URL verification) with **inbound** event receivers and OAuth-style callback configuration. Static analysis should trace user-supplied callback URLs through outbound clients, webhook CRUD handlers for owner/tenant authorization, inbound signature verification, and secret handling. The highest-impact failures are server-initiated requests to attacker-controlled destinations (SSRF to internal/metadata endpoints), cross-tenant webhook manipulation, and accepting forged inbound events without cryptographic verification.

## What It Is / Is Not

- **Is**: server makes an outbound HTTP request to a user-supplied webhook/callback URL (`testWebhook`, `pingWebhook`, `verifyUrl`, `sendTest`); webhook create/update/delete without owner or tenant scope check; outbound delivery to arbitrary hosts with redirect following enabled; integration OAuth `redirect_uri` taken from query/body without registered allowlist; inbound webhook handler that processes JSON/events with no HMAC/signature check, no timestamp window, or no nonce/idempotency; signing secret logged or returned in API responses.
- **Is not**: generic SSRF in non-webhook features (image proxy, import-from-URL) — see `ssrf.md` for IP/metadata defenses and client hardening. OAuth authorize/callback flow misconfiguration without webhook context — see `oauth_oidc_misconfiguration.md`. IDOR on non-webhook resources — see `idor.md`. CSRF on browser forms unrelated to webhook endpoints — see `csrf.md`.
- **Highest signal** on handlers named `*webhook*`, `*callback*`, `*integration*`, outbound job workers that POST to stored URLs, and inbound routes under `/webhooks/`, `/hooks/`, `/integrations/events`.

## Source -> Sink Pattern

**Sources (outbound)**
- Request body/query: `webhook_url`, `callback_url`, `url`, `endpoint`, `target`, `ping_url`, `verify_url`
- Stored webhook record: URL persisted at create/update time, later used by delivery worker or test action
- OAuth integration setup: `redirect_uri` from client query during connect/test flow

**Sinks (outbound — SSRF archetype)**
- `requests.post(user_url)`, `fetch(callbackUrl)`, `axios.post(webhookUrl)`, `HttpClient.PostAsync(url)`, `RestTemplate.postForObject(url, …)`
- Handlers: `testWebhook`, `pingWebhook`, `verifyUrl`, `sendTest`, `validateWebhook`, `checkEndpoint`
- Redirect-following enabled on delivery client (`allow_redirects=True`, `maxRedirects > 0`, default fetch follow)

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

## Safe Patterns

- **Outbound destinations**: strict HTTPS host allowlist per integration type; resolve DNS and reject private/link-local/metadata ranges; disable redirect following or re-validate each hop — full SSRF checklist in `ssrf.md`.
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
| Integration `redirect_uri` prefix/substring acceptance | **High** — code/token theft chain |
| Signing secret in logs or list API | **Medium–High** |
| Missing replay window on signed inbound | **Medium** (depends on event impact) |
| Read-only webhook metadata IDOR (URL leak, no mutation) | **Medium** |
| Test feature restricted to admin + strict allowlist | **Info / FALSE POSITIVE** |

Downgrade when: outbound path uses allowlist + IP block + no redirects; CRUD scoped to owner; inbound HMAC + timestamp + idempotency enforced; secrets not exposed after create.

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

## Core Principle

Treat webhook URLs as **server-side network destinations** subject to SSRF controls, webhook records as **tenant-scoped objects** requiring authorization on every access, and inbound events as **unauthenticated until HMAC-verified** with replay protection — never trust payload content or client-supplied redirect URIs without allowlist binding.
