---
name: hardcoded_secrets
description: Detect hardcoded secrets at rest in source/config/build artifacts (CWE-798/259/321) — API keys, access tokens, signing/JWT secrets, private keys, OAuth client secrets, and connection strings carrying embedded passwords, assigned as string literals. Severity is driven by the public-exposure question — can an external attacker extract this secret from the deployed artifact (client bundle, mobile binary, public asset) without server access? Distinct from default_credentials (reachable login PAIRS), weak_crypto (algorithm strength), and information_disclosure (runtime leakage).
---

# Hardcoded Secrets (CWE-798 / CWE-259 / CWE-321)

A hardcoded secret is a credential — an API key, access/refresh token, signing or JWT secret, private key, OAuth client secret, or a connection string carrying an embedded password — written **directly as a string literal** in source, config, or a build artifact. It is committed to version control, visible to everyone with repo (or artifact) access, survives in git history after "removal", and cannot be rotated without a code change and redeploy.

This is the home for **secret literals at rest**. It is distinct from its neighbors — pick the narrowest:

- **`default_credentials`** — a hardcoded *username/password login PAIR* (e.g. `admin`/`admin`) reachable through an auth endpoint. That is an access-control bug; this class is about secret *material* leaking from the artifact. See `default_credentials.md`.
- **`weak_crypto_hash`** — the *algorithm/key strength* is the defect (MD5, DES, 16-byte AES key). When the problem is that the key is *hardcoded and extractable* (not that it's weak), report **here**. See `weak_crypto_hash.md`.
- **`information_disclosure`** — a secret leaked at *runtime* via logs, error bodies, debug endpoints, or HTTP responses. This class is about secrets sitting in code/artifacts at rest. See `information_disclosure.md`.

## Core question: can an external attacker extract it?

Severity is governed by **reachability of the artifact**, not just the presence of a literal:

> **Can an external attacker obtain this secret from the deployed application without server access?**

- **YES — client-exposed** (bundled into frontend JS, mobile binary, source map, or a public static asset): an attacker extracts it with browser DevTools or by decompiling the app. → **High / Critical** (Critical if it's a live, high-privilege secret: cloud key, server-side API key, signing key).
- **NO — backend-only** (server source never shipped to clients): still a real finding — VCS exposure, no rotation, blast radius on repo compromise, lateral movement. → **Medium** (Low only for low-value/scoped secrets). **Do not silently drop backend secrets** — "bad practice but not externally reachable" is a *Medium*, not a non-finding.

This is the key addition over naive secret-grepping: a publishable client key (Stripe `pk_live_`) is **not** a finding, while the *same shape* server secret (`sk_live_`) shipped into a client bundle is **Critical**.

## Client vs backend routing (where does this file ship?)

Decide whether the file reaches a client. Treat as **publicly accessible** when in doubt — if it *could* be bundled for the client, it is exposed.

| Stack | Public (shipped to client) | Backend-only |
|-------|----------------------------|--------------|
| **Next.js** | `NEXT_PUBLIC_*` env (inlined into bundle), files imported from a `"use client"` component, `pages/` client code | `app/api/`, `"use server"` actions, server components not importing the secret |
| **Nuxt** | `pages/`, `components/`, anything under client runtime | `server/`, `nitro` handlers |
| **CRA / Vite / Angular / Vue** | **all of `src/`** is bundled; `REACT_APP_*`, `VITE_*`, `NG_*`, `VUE_APP_*` are inlined | server code in a separate backend project |
| **Mobile (iOS/Android/RN/Flutter)** | **ALL source is public** — APK/IPA decompile, RN/Hermes JS bundles, `strings` on binaries | none — there is no "backend-only" inside the app |
| **Electron** | renderer code, `app.asar` (just an archive — `npx asar extract`) | main-process code is still on disk, treat as low-trust |
| **Static / SSG** | `public/`, `static/`, `assets/`, `www/`, `dist/`, source maps (`.map`), `__NEXT_DATA__` | — |

**Import-chain method:** (1) is the literal in a path that bundles to the client? (2) is the defining module transitively imported from a client entry point? (3) is there a `"use server"` / `app/api/` boundary that keeps it server-side? (4) cross-check `architecture.md`. If a client import path exists, classify **client-exposed**.

## What it IS / IS NOT

**IS:** an API key / token / signing or JWT secret / private key / OAuth client secret / connection string with an embedded password, present as a **real, high-entropy literal** (matches a provider format or ≥20 random chars) in source, config, or a build artifact.

**IS NOT (do not flag):**
- **Env-var reads** — `process.env.X`, `os.environ[...]`, `System.getenv(...)`, `ENV[...]`, `Deno.env.get(...)`, secrets-manager/Key-Vault fetches (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault).
- **Placeholders** — `"your-api-key-here"`, `"INSERT_KEY"`, `"changeme"`, `"REPLACE_ME"`, `"<api_key>"`, `"xxxxxxxx"`, `"sample"`, `"dummy"`, `"test"`, empty string.
- **Publishable-by-design keys** — Stripe `pk_live_*`/`pk_test_*`, Firebase **client** `apiKey` (it's an identifier; admin/service keys are NOT this), Google Maps browser keys, Sentry public DSN, Algolia search-only key, Mapbox `pk.*`, PostHog/Mixpanel project tokens. These are meant to be public.
- **Test/sandbox keys** — `sk_test_*`, keys in `tests/`, `__mocks__/`, `*_test.go`, fixtures (note as Info only if they could ship to clients).
- **Public keys / certs** — RSA/EC **public** keys, `authorized_keys`, `.crt`/`.pub` — designed to be shared.
- **Type defs / docs / examples** — `interface Config { apiKey: string }`, doc comments, `.env.example` (template; only a finding if a matching real `.env` is committed or the value is real), hash checksums, build IDs, commit SHAs.
- **`process.env` references with no literal** — a `NEXT_PUBLIC_*` *name* is only a finding when a real value is hardcoded in source, not when read from a gitignored env.

## Recon Indicators

Grep for provider formats and secret-named assignments, then resolve the client/backend routing above.

**High-confidence provider regexes** (canonical catalog — `default_credentials.md` defers here):

| Secret Type | Pattern |
|---|---|
| AWS Access Key ID | `AKIA[0-9A-Z]{16}` (40-char base64 secret nearby), `ASIA[0-9A-Z]{16}` (temp) |
| Google API Key | `AIza[0-9A-Za-z\-_]{35}` |
| Google OAuth Client Secret | `GOCSPX-[0-9A-Za-z\-_]{28}` |
| GCP Service Account JSON | `"type"\s*:\s*"service_account"` with `"private_key"` / `"private_key_id"` |
| GitHub PAT / tokens | `ghp_[0-9A-Za-z]{36}`, `github_pat_[0-9A-Za-z_]{82}`, `gho_`/`ghs_`/`ghr_` + `[0-9A-Za-z]{36}` |
| GitLab PAT | `glpat-[0-9A-Za-z\-_]{20}` |
| Slack | token `xox[bpars]-...`; webhook `hooks.slack.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+` |
| Stripe **secret** | `sk_live_`, `sk_test_`, `rk_live_` (restricted). `pk_*` are **publishable — not a finding** |
| Twilio | `AC[0-9a-f]{32}` (SID, auth token nearby), `SK[0-9a-fA-F]{32}` (API key) |
| SendGrid | `SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}` |
| Mailgun | `key-[0-9a-zA-Z]{32}` |
| OpenAI | `sk-[A-Za-z0-9]{48}`, `sk-proj-[A-Za-z0-9\-_]{100,}` |
| Anthropic | `sk-ant-[A-Za-z0-9\-_]{90,}` |
| xAI (Grok) | `xai-[A-Za-z0-9]{80,}` |
| Azure Storage | `AccountKey=` + ~88-char base64; `DefaultEndpointsProtocol=...;AccountName=...;AccountKey=` |
| HashiCorp Vault | `hvs\.`, `hvb\.`, `hvr\.` + `[A-Za-z0-9_\-]{24,}` |
| DigitalOcean | `dop_v1_`, `doo_v1_`, `dor_v1_` + `[a-f0-9]{64}` |
| Shopify | `shpat_`, `shpss_`, `shppa_`, `shpca_` + `[a-fA-F0-9]{32}` |
| npm | `npm_[A-Za-z0-9]{36}` |
| Telegram Bot | `[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}` |
| Discord webhook | `discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_\-]{60,68}` |
| Firebase (admin/server) | `firebase-adminsdk` service-account JSON, `FIREBASE_*` private key (client `apiKey` is NOT this) |
| JWT (already-issued) | `eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+` (a baked-in long-lived token) |
| Private Key | `-----BEGIN (RSA \|EC \|OPENSSH \|DSA \|PGP )?PRIVATE KEY-----` |
| DB connection string | `(postgresql\|mysql\|mongodb(\+srv)?\|redis\|amqp)://[^:/@]+:[^@]+@` (user:pass@host) |

**Generic / entropy heuristics** (no provider prefix):
- Long random literals — **≥32 alphanumeric chars**, or **≥64 hex chars**, or base64 blobs assigned in an auth/crypto context.
- UUID used *as an API key* (in an auth header / SDK init).
- Secret-named assignments: `*api_key*`, `*apikey*`, `*secret*`, `*token*`, `*password*`, `*passwd*`, `*private_key*`, `*signing_key*`, `*client_secret*`, `*access_key*`, `*connection_string*`, `DATABASE_URL` = string literal.
- Sinks that consume it: SDK init (`new Stripe("...")`, `new S3Client({credentials:{...}})`), `Authorization: Bearer <literal>`, `jwt.sign(payload, "<literal>")`, ORM/DB connect with inline `user:pass@`.

```bash
# provider-prefixed literals (highest confidence)
rg -n "AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|gh[posr]_[0-9A-Za-z]{36}|sk_live_|sk-ant-|xox[bpars]-|glpat-|-----BEGIN [A-Z ]*PRIVATE KEY-----"
# embedded creds in connection strings
rg -n "(postgresql|mysql|mongodb(\+srv)?|redis|amqp)://[^:/@\"' ]+:[^@\"' ]+@"
# secret-named assignment to a literal (then check client/backend routing + entropy)
rg -ni "(api[_-]?key|secret|token|client[_-]?secret|signing[_-]?key|private[_-]?key|access[_-]?key)['\"]?\s*[:=]\s*['\"][^'\"]{16,}" --glob '!**/*.example' --glob '!**/test*'
# client-exposure amplifiers
rg -n "NEXT_PUBLIC_|REACT_APP_|VITE_|VUE_APP_|NG_APP_"
```

**Skip during recon:** `node_modules/`, `dist/`/`build/` *vendor* output (but DO inspect first-party bundles for client exposure), `.git/` blobs, `process.env.*` / `os.environ` / `System.getenv`, obvious placeholders, public keys, `*.lock` hashes.

## Verify (two questions)

1. **Is it a real secret?** Entropy + provider-format check; reject placeholders, test/sandbox keys, publishable-by-design keys, type defs.
2. **Is it publicly accessible?** Walk the import chain / file routing above. Client-exposed → High/Critical; backend-only → Medium.

## Finding fields (this class)

- **Exposure path** — *how* an attacker reaches it. e.g. "inlined into client bundle via Vite, visible in DevTools → Sources"; "`npx asar extract app.asar`"; "`apktool d app.apk` then `grep AKIA`"; or "backend source only — VCS / repo-compromise exposure" for Medium cases.
- **Verification steps** — concrete extraction (DevTools search for `AKIA`/`sk_live_`; ASAR extract; APK decompile). Optional authorized validity probe against the provider's identity endpoint (200 = live).
- **Redaction (mandatory)** — never write the full secret in results. Mask: `AKIA****WXYZ`, `sk_live_****6789`. Record **class + `file:line` + masked value + type**.

## Examples

**VULN (Critical) — server secret shipped to the client bundle:**
```javascript
// src/lib/stripe.ts — imported by a "use client" component (Next.js)
export const stripe = new Stripe("sk_live_EXAMPLEFAKE0123456789abcdef"); // extractable from bundle
```

**VULN (Medium) — backend-only, still a finding (VCS exposure, no rotation):**
```python
# app/server/config.py — never shipped to clients
JWT_SECRET = "EXAMPLEFAKE-signing-key-9f8a7b6c5d4e"
DB_URL = "postgresql://app:EXAMPLEFAKEpw@db.internal:5432/prod"
```

**SAFE — env/secret-manager; client calls a backend proxy:**
```javascript
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY); // server-only route; client → /api/charge
```

**NOT A FINDING — publishable-by-design client key:**
```javascript
const stripePub = "pk_live_EXAMPLEpublishable"; // publishable key, meant to be public
const firebase = { apiKey: "AIzaSyEXAMPLEclientApiKey" }; // Firebase client apiKey is an identifier
```

## Cross-References

- Reachable hardcoded login *pairs* (`admin`/`admin`): `default_credentials.md`.
- Weak/short key *material* (algorithm strength, IV reuse): `weak_crypto_hash.md`.
- Runtime secret leakage (logs/errors/responses/source maps served live): `information_disclosure.md`.
- Client-shipped admin/service keys for BaaS: `baas_security.md`.
- Secrets in IaC/CI/containers: `iac_security.md`, `cicd_container_security.md`.
- Mobile artifact secrets: `mobile_security.md`.

## Core Principle

Secrets belong in environment variables or a secrets manager, never in source. The severity is set by **who can reach the artifact**: a client-exposed live secret is Critical; a backend-only literal is still Medium because it lives in version control forever and cannot be rotated cleanly. Never report the raw value — mask it.
