---
name: default_credentials
description: Detect reachable hardcoded or default login credential PAIRS (admin/admin, root/root, seeded admin accounts, env-var||fallback login defaults) that gate an authentication path. Standalone secret literals (API keys, tokens, signing/JWT secrets, private keys, connection strings) belong to hardcoded_secrets (CWE-798); runtime credential leakage belongs to information_disclosure.
---

# Default / Hardcoded Credentials

This class covers **reachable login credential pairs** — a hardcoded or default *username/password pair* (`admin`/`admin`, `root`/`root`, a seeded admin account, an `env-var || 'fallback'` login default) that gates a reachable authentication path. The defect is an attacker logging in with credentials baked into the application.

**Scope split — pick the narrowest class:**
- **Secret literals at rest** (API keys, access/refresh tokens, signing/JWT secrets, private keys, OAuth client secrets, connection strings carrying an embedded password) → **`hardcoded_secrets.md`** (CWE-798). That class owns the provider-format catalog, entropy heuristics, and the client-vs-backend public-exposure model. Do **not** suppress those — route them there.
- **Secrets leaked at runtime** via logs, error messages, HTTP responses, or debug endpoints → **`information_disclosure.md`**.
- **Reachable hardcoded login PAIRS / default creds** → **this class.**

## What It Is and Is Not

### What it IS

- Default or factory **login credential pairs** (`admin`/`password`, `root`/`root`) used on reachable auth paths
- A hardcoded `username` + `password` compared/checked at a reachable login endpoint
- Seed/init scripts creating an admin user with a trivially-guessable hardcoded password reachable via login
- Fallback **login** literals when env vars are unset: `process.env.ADMIN_PASSWORD || 'default_password'`
- A hardcoded DB/service password used as the *login* on a reachable path (the connection *string* as an extractable secret → `hardcoded_secrets.md`)

> Standalone secret literals (API keys, tokens, signing/JWT secrets, private keys, connection strings) are **`hardcoded_secrets.md`**, not this class.

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

- Login/auth handlers and middleware: hardcoded `user==... && pass==...` comparisons, admin-login routes
- Application source: config modules, init/seed scripts creating admin accounts, shared `utils/`/`lib/` auth helpers
- Config files used by the login/DB-connect path: `.env`, `config.ini`, `application.yml`, `appsettings.json`, `wp-config.php`
- Infrastructure that seeds login creds: `docker-compose.yml` `environment:`, Kubernetes manifests, Makefile setup targets

> Client-shipped artifacts (`public/`/`static/`, frontend bundles, mobile APK/IPA) and git history as *secret-extraction* surfaces are covered by `hardcoded_secrets.md`.

## Recon Indicators

This class targets **login pairs / default creds**. Grep for hardcoded password literals that gate an auth path, then confirm a reachable login endpoint accepts them.

> Provider secret-format regexes (AWS/Stripe/GitHub/etc.), entropy heuristics, and the client-vs-backend public-exposure model now live in the canonical **`hardcoded_secrets.md`** catalog. For a bare API key / token / signing secret / private key / connection string, report there.

**Login-pair / default-cred patterns**

- Hardcoded comparison: `if (user == "admin" && pass == "admin")`, `password.equals("admin123")`, `strcmp(input, "secret123")` on a reachable input path
- Constant credential: `define('DB_PASSWORD', 'root')`, `$password = "admin123"`, `ADMIN_PASSWORD = "admin123"` used by a login/connect path
- Inline-credential connect that doubles as the login: `mysqli_connect('localhost','root','password','db')`, `mongoose.connect('mongodb://admin:password@host/db')`
- Fallback login default: `process.env.ADMIN_PASSWORD || 'default_password'`
- Seed/init: `INSERT INTO users (...) VALUES ('admin', '<plaintext-or-trivial-hash>')`; `CommandLineRunner`/`@PostConstruct`/`before_first_request` creating an admin with a hardcoded password

(Common weak login values are listed under *Common Vulnerable Values* above.)

**Skip during recon**

- `process.env.*`, `os.environ[*]`, `System.getenv(*)`, `ENV[*]`
- Obvious placeholders, public keys, type-only definitions, hash checksums, build IDs

---

## Python Source Detection Rules

The `default_credentials` tag is reserved for reachable username/password login pairs. The patterns below that assign bare secret literals (`SECRET_KEY`, `API_KEY`, signing keys, connection strings) are detected here for convenience but belong to **`hardcoded_secrets`** (`hardcoded_secrets.md`) — emit them there, not as `default_credentials`.

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
- Do NOT emit `default_credentials` for database connection credentials in application config files (application.yml, application.properties, docker-compose.yml) — these are not application login defaults. Tag the connection string as `hardcoded_secrets` (extractable secret at rest) per `hardcoded_secrets.md`.
- Do NOT emit for test data, seed data, or demo account setup in database initialization scripts UNLESS those accounts are accessible through a reachable production login endpoint.
- Do NOT emit `default_credentials` for hardcoded secrets used in JWT signing, encryption keys, API keys, tokens, or private keys — these are **`hardcoded_secrets`** (CWE-798), report them there (not suppressed, not `weak_crypto`/`information_disclosure`). `weak_crypto` is only when the algorithm/key strength is the defect.
- Only emit `default_credentials` when there is a REACHABLE authentication endpoint that accepts a hardcoded username/password pair defined in the application code.

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
