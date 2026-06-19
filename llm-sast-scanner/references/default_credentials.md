---
name: default_credentials
description: Detect hardcoded or default credentials used for authentication, database connections, or secret keys in source code and configuration files.
---

# Default / Hardcoded Credentials

Hardcoded credentials are secrets — passwords, API keys, signing keys — embedded directly in source code, configuration files, or connection strings. They represent a critical risk: they are committed to version control, visible to every person with repository access, and cannot be rotated without a code change and a new deployment.

Secrets leaked at runtime via logs, error messages, HTTP responses, or debug endpoints belong to **information_disclosure** — see `information_disclosure.md`. This class covers credentials embedded in source, config, or build artifacts at rest.

## What It Is and Is Not

### What it IS

- Passwords, API keys, access tokens, private keys, JWT/signing secrets, or connection strings assigned as string literals
- Default or factory credentials (`admin`/`password`, `root`/`root`) used on reachable auth or DB paths
- Fallback literals when env vars are unset: `process.env.ADMIN_PASSWORD || 'default_password'`
- Secrets in client-shipped code (frontend bundles, mobile binaries, `public/`/`static/` assets) — extractable without server access
- High-entropy literals assigned to `*password*`, `*secret*`, `*token*`, `*api_key*`, `*private_key*` variables

### What it is NOT

- **Placeholders**: `"your-api-key-here"`, `"changeme"`, `"REPLACE_ME"`, `"<api_key>"`, `"dummy"`, `"TODO"`, empty strings
- **Env-var reads**: `process.env.API_KEY`, `os.environ["SECRET"]`, `System.getenv("KEY")` — runtime lookup, not hardcoded
- **Public keys**: RSA/EC public keys, SSH `authorized_keys` entries — designed to be shared
- **Publishable-by-design keys**: Stripe `pk_test_*`/`pk_live_*`, Firebase client `apiKey`, Google Maps browser keys (restrict by referrer)
- **Test fixtures**: keys in `tests/`, `__mocks__/`, `*_test.go` — lower risk unless shipped to clients
- **Type definitions / docs**: `interface Config { apiKey: string }`, comments describing key format
- **Runtime disclosure**: credentials in stack traces, API error bodies, or log output — tag `information_disclosure`

## Vulnerable Conditions

A true positive requires **both** of the following:
1. A hardcoded value that is a recognizable credential — a password, secret key, token, or connection string carrying an embedded password.
2. The value is used within an **authentication-relevant execution path** — a database connection, session signing operation, login comparison, or API call.

## Safe Patterns

- Placeholder strings: `<YOUR_PASSWORD_HERE>`, `${DB_PASSWORD}`, `%(password)s`, `{password}` — template slots awaiting substitution, not real secrets.
- Empty strings: `password = ""` — no credential is present.
- Test/mock files: code inside `tests/`, `test_*.py`, `*_test.go`, `__mocks__/` — carries lower risk but should still be noted.
- Code comments that describe what a credential should look like without supplying one.
- Environment variables: `os.environ.get('SECRET_KEY')`, `process.env.API_KEY`, `ENV["DB_PASSWORD"]`.
- Secrets managers / key vaults: AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault — fetched at runtime, not stored as literals.
- Distinguishing real vs placeholder: real credentials have high entropy (20+ random chars) and match provider formats; placeholders use dictionary words, repeated chars, or explicit marker strings.

## Common Vulnerable Values

`admin`, `password`, `123456`, `root`, `changeme`, `secret`, `test`, `demo`, `letmein`, `qwerty`

## Where to Look

- Application source: config modules, init/seed scripts, shared `utils/`/`lib/` imported by client entry points
- Config files: `.env`, `config.ini`, `application.yml`, `appsettings.json`, `wp-config.php`
- Infrastructure: `docker-compose.yml`, Kubernetes manifests, Dockerfiles, Makefiles
- CI/CD: `.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`
- Client-shipped paths: `public/`, `static/`, `assets/`, frontend bundles, mobile app source (APK/IPA decompilation)
- Version history: `git log -p`, deleted commits — secrets persist after removal

## Recon Indicators

Grep for distinctive formats and secret-named assignments; trace whether the file reaches a client bundle or auth path.

**High-confidence regex patterns**

| Secret Type | Pattern |
|---|---|
| AWS Access Key ID | `AKIA[0-9A-Z]{16}` (40-char base64 secret nearby) |
| Google API Key | `AIza[0-9A-Za-z\-_]{35}` |
| Google OAuth Client Secret | `GOCSPX-[0-9A-Za-z\-_]{28}` |
| GitHub PAT | `ghp_[0-9A-Za-z]{36}`, `github_pat_[0-9A-Za-z_]{82}` |
| GitHub OAuth/app/server token | `gho_`, `ghs_`, `ghr_` + `[0-9A-Za-z]{36}` |
| GitLab PAT | `glpat-[0-9A-Za-z\-_]{20}` |
| Slack Token | `xoxb-`, `xoxp-`, `xoxa-`, `xoxr-` |
| Slack Webhook URL | `hooks.slack.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+` |
| Stripe Secret Key | `sk_live_`, `sk_test_`, `rk_live_` (restricted) (note: `pk_*` are publishable, not secret) |
| Twilio Account SID / API Key | `AC[0-9a-f]{32}` (SID, 32-hex auth token nearby), `SK[0-9a-fA-F]{32}` (API key) |
| SendGrid API Key | `SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}` |
| Mailgun API Key | `key-[0-9a-zA-Z]{32}` |
| OpenAI API Key | `sk-[A-Za-z0-9]{48}`, `sk-proj-[A-Za-z0-9\-_]{100,}` |
| Anthropic API Key | `sk-ant-[A-Za-z0-9\-_]{90,}` |
| xAI (Grok) API Key | `xai-[A-Za-z0-9]{80,}` |
| Azure Storage Key | `AccountKey=` + ~88-char base64; `DefaultEndpointsProtocol=https?;AccountName=...;AccountKey=` |
| GCP Service Account JSON | `"type"\s*:\s*"service_account"` with `"private_key"`/`"private_key_id"` fields |
| HashiCorp Vault Token | `hvs\.`, `hvb\.`, `hvr\.` + `[A-Za-z0-9_\-]{24,}` |
| DigitalOcean Token | `dop_v1_`, `doo_v1_`, `dor_v1_` + `[a-f0-9]{64}` |
| Shopify Token | `shpat_`, `shpss_`, `shppa_`, `shpca_` + `[a-fA-F0-9]{32}` |
| npm Access Token | `npm_[A-Za-z0-9]{36}` |
| Telegram Bot Token | `[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}` |
| Discord Webhook URL | `discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_\-]{60,68}` |
| Private Key | `-----BEGIN (RSA \|EC \|OPENSSH \|DSA \|PGP )?PRIVATE KEY-----` |
| DB Connection String | `postgresql://[^:]+:[^@]+@`, `mysql://[^:]+:[^@]+@`, `mongodb(?:\+srv)?://[^:]+:[^@]+@`, `redis://:[^@]+@` |

**Variable assignment patterns**

- `api_key = "..."`, `apiKey: "..."`, `SECRET_KEY = '...'`, `password = "..."`, `client_secret = "..."`
- Long alphanumeric strings (32+ chars) or base64 blobs assigned to auth-related variable names
- `*api_key*`, `*secret*`, `*token*`, `*password*`, `*private_key*`, `*connection_string*`, `DATABASE_URL`

**Skip during recon**

- `process.env.*`, `os.environ[*]`, `System.getenv(*)`, `ENV[*]`
- Obvious placeholders, public keys, type-only definitions, hash checksums, build IDs

---

## Python Source Detection Rules

These patterns detect hardcoded secrets generally, but the `default_credentials` tag is reserved for reachable username/password login pairs — hardcoded signing keys, API keys, and DB credentials should be tagged `weak_crypto` or `information_disclosure` per the FALSE POSITIVE rules below.

### Direct assignment
- **VULN**: `password = "admin"` — literal credential assigned to password variable
- **VULN**: `SECRET_KEY = "changeme"` — Flask/Django secret key hardcoded
- **VULN**: `app.secret_key = 'hardcoded_secret'` — Flask session signing key
- **VULN**: `DJANGO_SECRET_KEY = "my-secret-key-12345"` — Django settings
- **VULN**: `API_KEY = "sk-abc123..."` — hardcoded API key

### Database connection strings
- **VULN**: `mysql+pymysql://root:password@localhost/db` — SQLAlchemy URI with credentials
- **VULN**: `postgresql://admin:1234@db.internal/mydb` — PostgreSQL URI
- **VULN**: `mongodb://admin:password@host:27017/db` — MongoDB URI
- **VULN**: `redis://:password@localhost:6379` — Redis with password

### Config / environment patterns
- **VULN**: `DB_PASSWORD = "root"` in Python config file (not read from env)
- **VULN**: `ADMIN_PASSWORD = "admin123"` assigned as constant
- **SAFE**: `SECRET_KEY = os.environ.get('SECRET_KEY')` — read from environment
- **SAFE**: `password = os.getenv('DB_PASSWORD')` — from environment

### .env / config files (text patterns)
- **VULN**: `DB_PASSWORD=root` in `.env` or `config.ini`
- **VULN**: `ADMIN_PASSWORD=admin` in `.env`
- **SAFE**: `DB_PASSWORD=` (empty) — no value set

---

## JavaScript Source Detection Rules

### Direct object / variable assignment
- **VULN**: `password: 'admin'` in config object
- **VULN**: `const SECRET = 'hardcoded_value'` used in JWT signing or session
- **VULN**: `const dbUrl = 'mongodb://admin:password@localhost/db'`
- **VULN**: `mongoose.connect('mongodb://root:pass@host/db')` — inline credentials

### Environment variable bypass
- **VULN**: `const apiKey = 'sk-abc123'` — no `process.env` lookup
- **SAFE**: `const apiKey = process.env.API_KEY` — from environment

### JWT / session secrets
- **VULN**: `jwt.sign(payload, 'my_jwt_secret')` — hardcoded signing secret
- **VULN**: `app.use(session({ secret: 'keyboard cat' }))` — Express session secret

---

## PHP Source Detection Rules

### Variable assignment
- **VULN**: `$password = "admin123"` — hardcoded password variable
- **VULN**: `$db_pass = "root"` — DB password hardcoded
- **VULN**: `define('DB_PASSWORD', 'root')` — constant with credential
- **VULN**: `define('SECRET_KEY', 'mysecret')` — hardcoded secret constant

### Connection functions
- **VULN**: `mysqli_connect('localhost', 'root', 'password', 'db')` — inline credentials
- **VULN**: `new PDO('mysql:host=localhost;dbname=app', 'root', '1234')` — PDO with password
- **SAFE**: `new PDO($dsn, $_ENV['DB_USER'], $_ENV['DB_PASS'])` — from environment

### WordPress / CMS patterns
- **VULN**: `define('DB_PASSWORD', 'hardcoded_pass')` in `wp-config.php`
- **VULN**: `define('AUTH_KEY', 'put your unique phrase here')` — default placeholder (low risk) vs actual value (high risk)

## C/C++ Source Detection Rules

### Hardcoded credential comparison
- **VULN**: `const char *pw = "secret123";` then `if (strcmp(input, pw) == 0)` — literal password gating an auth/access decision
- **VULN**: `if (strcmp(user, "admin") == 0 && strcmp(pass, "admin") == 0)` — inline hardcoded login pair
- **VULN**: `#define PASSWORD "root"` used in a comparison on a reachable input path
- **SAFE**: comparison against a value loaded from `getenv()`, a config file, or a verified hash (e.g., `crypt`/`bcrypt`) rather than a string literal

## Additional Source Patterns

### Application Init / Seed Scripts (any language)
- **VULN**: `CommandLineRunner` / `@PostConstruct` / `before_first_request` creating admin user with hardcoded password
- **VULN**: `INSERT INTO users` with plaintext password or predictable hash in seed/fixture SQL
- **VULN**: Fallback to hardcoded default when env var is not set: `process.env.ADMIN_PASSWORD || 'default_password'`

### Infrastructure Files
- **VULN**: Hardcoded credentials in `docker-compose.yml` `environment:` section that are used by the application login path
- **VULN**: Credentials in `.env` files (`ADMIN_PASSWORD=admin`, `MYSQL_ROOT_PASSWORD=root`)
- **VULN**: Credentials in Makefile targets used for application setup

## TRUE POSITIVE Rules for Default Credentials

- Hardcoded username/password pair used by a REACHABLE login endpoint → **CONFIRM**
- `INSERT INTO users` with plaintext password in seed SQL where those accounts are accessible via a login endpoint → **CONFIRM**
- `CommandLineRunner` / `@PostConstruct` / `before_first_request` creating admin user with hardcoded password reachable via login → **CONFIRM**
- Application falls back to hardcoded default when env var is not set and the credential gates a login path → **CONFIRM**

## FALSE POSITIVE Rules

- Credentials in `.env.example` only (template file, not `.env`) AND no corresponding `.env` file exists AND no fallback in code — **NOT a finding** if the app requires the operator to set real credentials
- Credentials used only for local dev that are clearly not reachable (e.g., CI-only fixture with `if os.getenv('CI'):`) — lower confidence
- Password hashing with bcrypt/argon2/scrypt of a seed password — the hash itself is not a default credential vulnerability UNLESS the seed password is trivially guessable (admin/admin, test/test)
- Do NOT emit `default_credentials` for database connection credentials in application config files (application.yml, application.properties, docker-compose.yml) — these are infrastructure credentials, not application login defaults. Tag as `information_disclosure` or `weak_crypto` if appropriate.
- Do NOT emit for test data, seed data, or demo account setup in database initialization scripts UNLESS those accounts are accessible through a reachable production login endpoint.
- Do NOT emit for hardcoded secrets used in JWT signing, encryption keys, or API keys — these should be tagged as `weak_crypto` or `information_disclosure` instead.
- Only emit when there is a REACHABLE authentication endpoint that accepts a hardcoded username/password pair defined in the application code.

### Source → Sink Patterns

**HardcodedCredentials (JS/Python/Go/Ruby/C#)**
- **Source**: String literals, config constants — passwords, API keys, tokens in source.
- **Sink**: Authentication or connection APIs — DB connect strings, HTTP Authorization headers, AWS SDK calls, ORM credentials.

**HardcodedCredentialsComparison (Java)**
- **Source**: Hardcoded string literal (password/secret).
- **Sink**: `String.equals`, `MessageDigest.isEqual`, or similar comparison used in an auth check.

**InsecureBasicAuth (Java)**
- **Sink**: HTTP URL connection or request using `Authorization: Basic ...` over non-HTTPS scheme.

**ImproperLdapAuth (Go/Python/Ruby)**
- **Sink**: LDAP bind or search using cleartext/simple bind without TLS — credentials or queries sent unencrypted.

### Sanitizers / Safe Patterns

- Credentials read from environment variables (`process.env`, `os.environ`, `System.getenv`).
- Placeholder literals flagged as non-sensitive by heuristics (`"SampleToken"`, `"MyPassword"`).
- Basic auth over `https://` URLs (InsecureBasicAuth).

**VULN (Java)**: `if (password.equals("admin123"))` — hardcoded comparison at login.
**SAFE (Java)**: `if (password.equals(System.getenv("ADMIN_PASSWORD")))`.

**VULN (JS)**: `mongoose.connect('mongodb://admin:password@host/db')`.
**SAFE (JS)**: `mongoose.connect(process.env.MONGODB_URI)`.

**VULN (Java)**: `new URL("http://api.example.com").openConnection()` with Basic auth header.
**SAFE (Java)**: Same pattern over `https://`.

## Examples

**VULN (Python)** — hardcoded API key and DB password:

```python
API_KEY = "sk-EXAMPLEFAKEKEY1234567890ABCDEF"
db_url = "postgresql://admin:SuperSecret123@db.internal/app"
```

**SAFE (Python)** — env lookup and secrets manager:

```python
API_KEY = os.environ["API_KEY"]
db_url = os.environ["DATABASE_URL"]
# or: client.get_secret_value(SecretId="prod/db")
```

**VULN (JavaScript)** — secret embedded in client bundle:

```javascript
const stripeKey = "sk_live_EXAMPLEFAKEKEY1234567890";
fetch("https://api.stripe.com/v1/charges", {
  headers: { Authorization: `Bearer ${stripeKey}` }
});
```

**SAFE (JavaScript)** — server-side env read; client calls backend proxy:

```javascript
const stripeKey = process.env.STRIPE_SECRET_KEY; // server-only route
// client: fetch("/api/charge", { method: "POST", body })
```

## Dynamic Test / Validation

Confirm a candidate is a live credential (conceptually — never paste real values):

1. **Real vs placeholder**: check entropy and provider format; reject dictionary words and marker strings (`changeme`, `your-key-here`).
2. **Reachability**: trace import chain — does the file ship in a client bundle, mobile binary, or public static asset?
3. **Client exposure (web)**: search bundled JS in browser DevTools Sources for the key prefix (e.g., `AKIA`, `sk_live_`).
4. **Mobile**: decompile APK/IPA and grep for the pattern; React Native JS bundles are plaintext.
5. **API validity (controlled)**: if authorized, send a minimal read-only request to the provider's identity/account endpoint using the extracted key; a `401`/`403` suggests invalid/revoked; a `200` with account metadata confirms live exposure.
6. **Rotation check**: compare against the secrets manager or env var the deployment actually uses — a literal in source that matches production confirms the finding.

Commonly affected languages: Python, JavaScript, Go, Ruby, C#, Java, Swift.
