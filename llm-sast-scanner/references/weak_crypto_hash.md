---
name: weak_crypto_hash
description: Weak cryptography, weak hashing, and insecure randomness detection (CWE-327/328/330)
---

# Weak Cryptography, Hash & Randomness

Identify deprecated cryptographic algorithms, broken hash functions, and predictable random number generators in Java code. Unlike injection vulnerabilities, these do not require tracing a Source-to-Sink data flow — the mere presence of a prohibited API call is sufficient evidence of the weakness.

## CWE-328 Weak Hash

**VULN** (any match):
- `MessageDigest.getInstance("MD5")` — MD5 is broken
- `MessageDigest.getInstance("SHA1")` or `"SHA-1"` — SHA-1 is broken
- `MessageDigest.getInstance("MD2")` or `"MD4"` — obsolete
- Other-runtime spellings of the same weak digests: Python `hashlib.md5`/`hashlib.sha1`; Node `crypto.createHash('md5'|'sha1')`; PHP `md5()`/`sha1()`; Go `crypto/md5`/`crypto/sha1`; **Apple CommonCrypto `CC_MD5`/`CC_SHA1` (and streaming `CC_MD5_Init`/`CC_SHA1_Init`), `SecDigestGetData(kSecDigestMD5/kSecDigestSHA1, …)`; Apple CryptoKit `Insecure.MD5.hash(...)` / `Insecure.SHA1.hash(...)`** (the type is literally namespaced `Insecure`); Rust RustCrypto `Md5::new()` / `Sha1::new()` (the `md5`/`md-5` & `sha1` crates), or `openssl`/`ring` MD5/SHA-1; Dart/Flutter `crypto` package `md5`/`sha1` convenience objects (`md5.convert(bytes)` / `sha1.convert(bytes)`, return type `Hash`).

**SAFE** (any match):
- `MessageDigest.getInstance("SHA-256")`, `"SHA-384"`, `"SHA-512"`; Apple `CC_SHA256` / CryptoKit `SHA256`/`SHA512`. For passwords use bcrypt/scrypt/Argon2/PBKDF2, never a bare hash.

**Mandatory**: When you see `MessageDigest.getInstance(...)`, write:
`Hash check: algorithm=? -> weak(MD5/SHA1/MD2/MD4) or strong(SHA-256+) -> VULN or SAFE`

## CWE-327 Weak Cryptography

**VULN** (any match):
- `Cipher.getInstance("DES/...")` or `"DESede/..."` — weak block cipher
- `Cipher.getInstance("AES/ECB/...")` — ECB mode is insecure
- `Cipher.getInstance("RC2/...")` or `"RC4/..."` or `"Blowfish/..."` — weak
- `javax.crypto.NullCipher` (or a custom `CipherSpi`/`Cipher` whose transform returns the plaintext unchanged) — **no-op "encryption"**: the data is not encrypted at all, so anything relying on it for confidentiality is in cleartext. Flag any `new NullCipher()` / `Cipher.getInstance("...")` resolving to an identity transform on a confidentiality path.

**SAFE** (any match):
- `Cipher.getInstance("AES/GCM/...")` or other AEAD modes — prefer authenticated encryption; AES/CBC alone (even with random IV) lacks integrity and is vulnerable to padding-oracle attacks unless combined with encrypt-then-MAC
- `Cipher.getInstance("ChaCha20/...")`

## CWE-330 Weak Random

**VULN** (any match):
- `new java.util.Random()` — predictable PRNG
- `Math.random()` — predictable PRNG
- Using `java.util.Random` for tokens, passwords, session IDs, OTP, or any security context
- **Other languages — same CWE-330 (a non-crypto PRNG seeding a security value)**: .NET `System.Random` / `new Random()` / `Random.Shared` / `Random.Next()` (→ `RandomNumberGenerator.GetBytes`/`GetInt32`); Python `random.*` — `random()`, `randint`, `randrange`, `choice`, `getrandbits`, `seed` (→ `secrets` / `os.urandom`); Go `math/rand` (→ `crypto/rand`); Node/JS `Math.random()` (→ `crypto.randomBytes`/`randomInt`/`webcrypto.getRandomValues`); PHP `rand`/`mt_rand`/`uniqid`/`lcg_value` (→ `random_int`/`random_bytes`); Ruby bare `rand`/`Random.rand` (→ `SecureRandom`); Dart/Flutter `dart:math` `Random()` — the default constructor is explicitly *not* cryptographically secure (→ `Random.secure()`). Flag only when the output is security-relevant — token, password, session ID, OTP, nonce, salt, API key, password-reset/CSRF token.

**SAFE** (any match):
- `new java.security.SecureRandom()` — cryptographically secure
- `SecureRandom.getInstance(...)` — cryptographically secure
- IMPORTANT: `SecureRandom` is NOT weak. Never flag SecureRandom as CWE-330.

## Common False Alarms

- `SecureRandom` flagged as weak random — WRONG, it is secure
- MD5 used only for non-security checksums (e.g., cache key) — still flag but note context
- `java.util.Random` used for non-security purposes (e.g., UI shuffle) — lower severity

## Analysis Workflow

1. Search for all crypto/hash/random API calls
2. Check algorithm parameter (string literal or variable)
3. Classify as VULN or SAFE per the rules above
4. No data flow analysis needed — the API call itself is the evidence

## Java Source Detection Rules

### TRUE POSITIVE: Weak PRNG in security context (CWE-330)
- `new java.util.Random()` used to generate captcha codes, OTP, verification tokens, session IDs, or passwords = CONFIRM.
- `Math.random()` in any security context = CONFIRM.

### FALSE POSITIVE
- `SecureRandom` is NOT weak — never flag it.
- `java.util.Random` used for non-security shuffling, UI randomness, or test data generation without security use = lower risk, consider context.

## Python/JS/PHP Source Detection Rules

### Python
- **VULN (hash)**: `hashlib.md5(password.encode()).hexdigest()` — MD5 used for passwords
- **VULN (hash)**: `hashlib.sha1(data).hexdigest()` — SHA1 is broken for collision resistance
- **VULN (random)**: `random.random()`, `random.randint()` used for token, OTP, or session ID
- **VULN (crypto)**: `DES.new(key)`, `AES.new(key, AES.MODE_ECB)` — pycryptodome weak modes
- **SAFE**: `hashlib.sha256()`, `hashlib.sha512()` for non-password integrity use
- **SAFE**: `secrets.token_hex(32)`, `secrets.token_urlsafe()` for security tokens
- **SAFE**: `bcrypt.hashpw(password, bcrypt.gensalt())` for password storage
- **Pattern**: `random` module in any security context = HIGH RISK

### JavaScript (Node.js)
- **VULN**: `crypto.createHash('md5').update(password).digest('hex')`
- **VULN**: `crypto.createHash('sha1').update(data).digest('hex')`
- **VULN**: `Math.random()` used for token, OTP, or session ID generation
- **SAFE**: `crypto.createHash('sha256')`, `crypto.createHash('sha512')`
- **SAFE**: `crypto.randomBytes(32)`, `crypto.randomUUID()`

### PHP
- **VULN**: `md5($password)`, `sha1($password)` — used for password storage
- **VULN**: `rand()`, `mt_rand()` used for token generation
- **SAFE**: `password_hash($password, PASSWORD_BCRYPT)`, `password_verify()`
- **SAFE**: `random_bytes(32)`, `bin2hex(random_bytes(16))`

### Go
- **VULN (random)**: `math/rand` (`rand.Int`, `rand.Read`, `rand.Intn`, including the global `math/rand/v2`) used for tokens, OTP, session IDs, nonces, salts, or password reset values — predictable PRNG
- **VULN (hash)**: `crypto/md5` (`md5.Sum`), `crypto/sha1` (`sha1.Sum`) for security; `crypto/des`, `crypto/rc4`; `crypto/sha256` directly on a password (fast hash)
- **SAFE (random)**: `crypto/rand` (`rand.Read`, `rand.Int`) for all security-sensitive values — never flag `crypto/rand`
- **SAFE (password)**: `golang.org/x/crypto/argon2` (`argon2.IDKey`), `golang.org/x/crypto/bcrypt`, `golang.org/x/crypto/scrypt`, or stdlib `crypto/pbkdf2` (Go 1.24+) with ≥600k iterations
- **Decision rule**: `math/rand*` in any security context → **VULN**; `crypto/rand` → **SAFE**. Import-path resolves the ambiguity (both expose `rand.Read`/`rand.Int`).

## Java Servlet Patterns

### Weak Random (CWE-330)

**Presence check — no taint tracing needed.**

**VULN**:
```java
new java.util.Random()
Math.random()
```

**SAFE**:
```java
new java.security.SecureRandom()
SecureRandom.getInstance("SHA1PRNG")
```

**Decision rule**: `new Random()` or `Math.random()` → **VULN**. `new SecureRandom()` → **SAFE**. Never flag `SecureRandom` as weak.

---

### Weak Cryptography (CWE-327)

**Presence check — no taint tracing needed.**

**VULN**:
```java
Cipher.getInstance("DES/...")
Cipher.getInstance("DESede/...")
Cipher.getInstance("AES/ECB/...")
Cipher.getInstance("RC2/...") / Cipher.getInstance("RC4/...") / Cipher.getInstance("Blowfish/...")
KeyGenerator.getInstance("DES")
```

**SAFE**:
```java
Cipher.getInstance("AES/GCM/NoPadding")
Cipher.getInstance("AES/CBC/PKCS5Padding")   // only acceptable with encrypt-then-MAC; prefer AES/GCM
Cipher.getInstance("ChaCha20-Poly1305")
```

**Decision rule**: weak algorithm string in `Cipher.getInstance()` → **VULN**. AES/GCM (or other AEAD) → **SAFE**. AES/CBC without integrity protection → **VULN** unless encrypt-then-MAC is present.

**Edge cases**:
- `benchmarkprops.getProperty("cryptoAlg1", "...")` resolves to a weak crypto setting → treat as **VULN** even when the fallback literal is not the actual runtime value.

---

### Weak Hash (CWE-328)

**Presence check — no taint tracing needed.**

**VULN**:
```java
MessageDigest.getInstance("MD5")
MessageDigest.getInstance("SHA1") / MessageDigest.getInstance("SHA-1")
MessageDigest.getInstance("MD2")
```

**SAFE**:
```java
MessageDigest.getInstance("SHA-256")
MessageDigest.getInstance("SHA-384")
MessageDigest.getInstance("SHA-512")
```

**Decision rule**: weak algorithm string → **VULN**. SHA-256 or stronger → **SAFE**.

**Edge cases**:
- `benchmarkprops.getProperty("hashAlg1", "...")` resolves to a weak hash setting → treat as **VULN** even when the fallback literal looks strong.
- In benchmark mode for `VulnerableApp` and `verademo`, map confirmed MD5/SHA1, insecure crypto storage, or Base64-as-encryption evidence to project tag `weak_crypto`.
- Keep `weak_crypto_hash` only when the benchmark explicitly scores hash weaknesses as a separate class.
- FALSE POSITIVE guard: do not emit `weak_crypto_hash` for `VulnerableApp/CryptographicFailures*` or verademo MD5 password storage if the project taxonomy exposes only `weak_crypto`.
- Do not up-map `java.util.Random` in captcha or demo flows, standalone MD5 helpers, or representative directories without a crypto taxonomy to benchmark tag `weak_crypto`; keep `weakrand`/`weak_random`, `verification_code`, or the exact primitive tag unless the project ground truth explicitly groups them under `weak_crypto`.
- FALSE POSITIVE guard: `java.util.Random()` used only in a demo echo/code page should not emit project-level `weakrand` or `weak_crypto` unless the route is an actual OTP/captcha/authentication flow scored by the benchmark.

## Static Analysis Patterns

Commonly affected languages: Java, JavaScript, Python, Go, Ruby, Rust, C#.

CWE-326 (insufficient key size), CWE-780 (RSA without OAEP), CWE-1204 (static IV), CWE-1240 (predictable seed), and CWE-335 (custom crypto primitive) are not covered by default web language static analysis suites.

### What to Look For (presence / config patterns)

**BrokenCryptoAlgorithm** — flags weak algorithm strings in crypto API calls:
- Java: `Cipher.getInstance("DES/...")`, `AES/ECB`, `RC4`; `KeyGenerator.getInstance("DES")`.
- JS: `crypto.createCipher('des')`, `createHash('md5')` in crypto (not hashing-sensitive-data query).
- Python/Go/Ruby/Rust: analogous weak algorithm constants.

**WeakSensitiveDataHashing** — weak hash on **sensitive** data (passwords, certificates, usernames):
- MD5, SHA-1, SHA-256 for passwords (SHA-256 flagged as too fast for passwords).
- **Sanitizer**: Argon2, scrypt, bcrypt, PBKDF2; SHA-256+ only for non-password integrity.

**InsecureRandomness** — predictable PRNG in security context:
- Java: `new Random()`, `Math.random()` for tokens/OTP/session IDs.
- JS: `Math.random()` for security values; **SAFE**: `crypto.randomBytes()`.
- **Sanitizer**: `SecureRandom`, `crypto.randomBytes`, `secrets` module (Python).

**HashWithoutSalt** — password hashing without salt mixed in.

**WeakPasswordKDFParams** — modern KDF name but unsafe work factor:
- bcrypt PHC cost digit `< 10` (e.g. `$2a$08$`); `gensalt(rounds=4)` / `cost=4`
- `PBEKeySpec(..., iterations)` with PBKDF2-HMAC-SHA256 iterations `< 600000`
- Argon2 `memory_cost` `< 19456` or `time_cost` `< 2`; scrypt `N` `< 131072`

**StaticIVOrNonce** — AEAD/cipher with fixed initialization vector:
- `IvParameterSpec(new byte[16])`, `GCMParameterSpec(128, new byte[12])`, `Buffer.alloc(n, 0)` passed to `createCipheriv`
- Class-level `static final byte[] IV` reused across encrypt calls

**HardcodedOrMisplacedKey** — key material in code or co-located with ciphertext:
- Literal `byte[] key = {...}`, `SecretKeySpec(...getBytes())`, Base64 key strings in source/config
- Same env var or file holds DEK and encrypted payload without KEK wrap
- Password/passphrase bytes used directly as symmetric key

### Timing Attacks (CWE-208)

**UnsafeHmacComparison (Ruby)**
- **Source**: `OpenSSL::HMAC.hexdigest` / `digest` / `base64digest` output.
- **Sink**: `==` or `!=` comparison — non-constant-time.
- **Sanitizer**: `ActiveSupport::SecurityUtils.secure_compare`, `OpenSSL.fixed_length_secure_compare`.

**TimingAttackAgainstSignature (Java)**
- **Sink**: Signature or MAC compared with `String.equals` instead of constant-time API.

**VULN (Ruby)**: `if computed_hmac == params[:signature]`.
**SAFE (Ruby)**: `ActiveSupport::SecurityUtils.secure_compare(computed_hmac, params[:signature])`.

**VULN (Java)**: `signature.equals(expectedSig)` on HMAC/signature bytes.
**SAFE (Java)**: `MessageDigest.isEqual` or `Arrays.compareUnsigned` on fixed-length MAC bytes.

**Non-constant-time comparison of secrets — per-language sinks → sanitizers**

| Language | VULN sink (secret/MAC/token compared with) | SAFE constant-time API |
|----------|--------------------------------------------|------------------------|
| Python | `==`, `!=`, `hmac.compare(...)` via `digest()==` | `hmac.compare_digest(a, b)`, `secrets.compare_digest` |
| PHP | `==`, `===`, `strcmp()` on MAC/token | `hash_equals(known, user)` |
| Go | `==`, `bytes.Equal` on MAC/token | `crypto/subtle.ConstantTimeCompare(a, b) == 1` |
| C# / .NET | `==`, `SequenceEqual`, `String.Equals` on MAC | `CryptographicOperations.FixedTimeEquals(a, b)` |
| Node.js | `===`, `Buffer.compare`, `==` on digests | `crypto.timingSafeEqual(a, b)` (equal-length buffers) |
| Ruby | `==` / `!=` on HMAC | `ActiveSupport::SecurityUtils.secure_compare`, `OpenSSL.fixed_length_secure_compare` |
| Java | `String.equals` / `Arrays.equals` on MAC | `MessageDigest.isEqual`, `Arrays.compareUnsigned` |

**Other timing leaks on secret-derived values (not just equality)** — flag when the operand is a key, nonce, or other secret:
- **Division / modulo** (`/`, `%`) on secret-derived values — variable-time on many CPUs (KyberSlash-class leaks in crypto/KEM code). Prefer constant-time arithmetic or masking.
- **Secret-dependent branches** — `if (secretByte == x)`, early-return on first mismatch in a compare loop, or differing work per secret bit.
- **Secret-indexed table/array lookups** — `sbox[secretIndex]` leaks via cache timing; use constant-time selection.
- **Early-terminating string operations** on a secret/MAC/token — `startswith`/`endsWith`/`find`/`index`/`indexOf`/`in`/substring search return as soon as they diverge, leaking a prefix-match length oracle. Treat these the same as `==` on a secret; use the per-language constant-time API above.

---

## Signature/Key-Operation Result Misuse (fail-open crypto)

A correct algorithm is worthless if the *result* of a verify/generate call is interpreted wrong. These are silent fail-opens: the verify call is present, so reviews and the algorithm-focused checks above pass it.

- **Tri-state verify return treated as boolean** — `openssl_verify()` (PHP) and several C/OpenSSL wrappers return **1 = valid, 0 = invalid, -1 = error**. A truthy test (`if (openssl_verify(...))`), `!= 0`, or a cast-to-bool accepts the **-1 error path as a valid signature**, so any input that makes verification *error* (malformed key, wrong algo) authenticates. Require an explicit `=== 1` (or `== 1`) comparison; flag any signature/MAC verify whose return is consumed by a loose/boolean test rather than compared to the exact success constant. Same shape: functions that return a status code where only one value means "verified."

```php
// VULN: -1 (error) is truthy → forged/malformed signature passes
if (openssl_verify($data, $sig, $pubKey)) { grantAccess(); }

// SAFE: only the exact success value authorizes
if (openssl_verify($data, $sig, $pubKey) === 1) { grantAccess(); }
```

- **Key-generation/rotation that silently no-ops when material already exists** — `DiffieHellman.generateKeys()` (Node `crypto`) and similar APIs **do not regenerate** when a private key was already set via `setPrivateKey()`; the call returns normally but reuses attacker-influenced/static material, so the "fresh" ephemeral key never rotates. Flag any `generateKeys()`/`generateKeyPair`/key-rotation call that can run *after* a `setPrivateKey()`/preset on the same object, and any rotate routine whose success is assumed rather than verified to have produced new material.

- **Signature/MAC over ambiguously concatenated fields (canonicalization / field-splitting forgery)** — when a request signature is computed by **concatenating field names and values with no unambiguous delimiter or length prefix** (`hash(secret + name1 + value1 + name2 + value2 …)`), an attacker who controls *any one* field can shift the `=`/`&`/separator characters between adjacent fields so the **concatenated byte string is unchanged while the parsed key/value pairs differ** — forging a valid signature for a different logical message. Classic payment-tampering shape: `Amount=2000` rewritten to `Amount2=000`, with the freed `2000` re-introduced through an attacker-controlled `CustomerEmail`/`Description` field that injects `&amount=100`; the digest input is byte-identical so the signature still verifies, but the upstream parser now reads a different (lower) amount. The same flaw lets an attacker append/override authorization-relevant fields (currency, recipient, role). SAST signal: a signing/verifying routine that builds its message by string concatenation or naive sort-and-join of params (`"".join(f"{k}{v}" …)`, `query.replace("&","")`, `implode('', $fields)`) instead of a **canonical, injective encoding** — length-prefixed/TLV, JSON/CBOR of a fixed schema, or percent-encoded `k=v` pairs with reserved-char escaping — *and* where at least one signed field is free-form user input. Fix: sign a canonical serialization with unambiguous, escaped delimiters (or per-field length prefixes), pin the exact field set, and reject unknown/duplicate keys before verifying.

```python
# VULN: signature input is just concatenated names+values — no delimiters.
# Moving '=' across fields (Amount=2000 -> Amount2=000) keeps this string
# identical, so a forged amount still verifies.
sig_input = "".join(f"{k}{v}" for k, v in sorted(params.items()))
if hmac.compare_digest(sign(secret, sig_input), provided_sig):
    process_payment(params["Amount"])

# SAFE: canonical, injective encoding (escaped k=v) + fixed allowed field set
allowed = ("MerchantID", "Amount", "Currency", "MerchantTransactionID")
if params.keys() - set(allowed):
    raise ValueError("unexpected signed field")
canonical = "&".join(f"{quote(k, safe='')}={quote(str(params[k]), safe='')}" for k in allowed)
if hmac.compare_digest(sign(secret, canonical), provided_sig):
    process_payment(params["Amount"])
```

---

## Password Storage (Slow Hashing)

Presence/config check — flag weak or misconfigured password hashing; no Source→Sink taint required when algorithm or parameters are evident.

### Safe Parameter Reference

| Algorithm | Minimum safe config | SAST triage cue |
|-----------|---------------------|-----------------|
| Argon2id | m≥19456 (19 MiB), t≥2, p=1 | `$argon2id$` PHC string; explicit `memory_cost`/`time_cost` |
| scrypt | N≥2^17 (131072), r=8, p=1 | `$scrypt$` or `scrypt(N=131072,...)` |
| bcrypt | cost≥10; input≤72 bytes | `$2[aby]$10$`+ or `gensalt(rounds=10+)` |
| PBKDF2-HMAC-SHA256 | iterations≥600,000 | `PBKDF2WithHmacSHA256` + iteration literal |
| PBKDF2-HMAC-SHA512 | iterations≥210,000 | inner SHA-512 |
| PBKDF2-HMAC-SHA1 | iterations≥1,300,000 | legacy/FIPS only; prefer SHA-256 inner hash |

Target hash time `< 1s` on production hardware; increase work factors over time.

### VULN (any match)

- Fast digest on passwords: `hashlib.sha256(password)`, `createHash('sha256').update(password)`, any `MessageDigest` on raw password bytes
- `Cipher.encrypt(password)` or reversible encryption of credentials — passwords must be hashed, not encrypted
- bcrypt / `PASSWORD_BCRYPT` with cost `< 10`
- PBKDF2 / `PBEKeySpec` below minimum iterations in table above
- Argon2/scrypt parameters below table minimums
- Fixed/global salt: string literal salt, `getBytes("staticSalt")`, salt derived from username/email only
- Pepper hardcoded in source or stored in same DB row/table as hash
- Terminal layered legacy hash without upgrade path: `bcrypt(md5($password))` with no re-hash-on-login

### SAFE (any match)

- Argon2id, scrypt, bcrypt, or PBKDF2 at/above parameter minimums
- Per-user random salt embedded in PHC output (`$argon2id$…`, `$2b$12$…`) via library `gensalt()`
- Pepper loaded from vault/HSM/secrets store segregated from DB (static analysis may only note presence)
- Re-hash on successful login when stored parameters are upgraded

```python
# VULN — fast hash on password
hashlib.sha256(password.encode()).hexdigest()

# SAFE — Argon2id with approved parameters
PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1).hash(password)
```

```java
// VULN
MessageDigest.getInstance("SHA-256").digest(password.getBytes());

// SAFE
new PBEKeySpec(password, salt, 600_000, 256);  // PBKDF2WithHmacSHA256
```

### Salting & Peppering

| Control | Requirement | VULN indicator | SAFE indicator |
|---------|-------------|----------------|----------------|
| Salt | Unique per password; CSPRNG-generated | Shared constant salt; manual prepend without KDF | Salt inside PHC/`gensalt()` output |
| Pepper | Optional; stored outside password DB | Pepper string in source/config next to hash | Vault/HSM/env segregated from DB |

Do not hand-roll salting when using Argon2/bcrypt/scrypt/PBKDF2 — libraries handle salt generation.

### Detection Patterns (grep / config)

```
argon2|scrypt|bcrypt|pbkdf2|PASSWORD_BCRYPT|password_hash|hashpw|Argon2
PBKDF2WithHmac|PBEKeySpec|SecretKeyFactory|time_cost|memory_cost|rounds|iterations
(md5|sha1|sha256).*password|password.*(md5|sha1|sha256)
\$2[aby]\$0[0-9]\$|\$2[aby]\$08\$
```

Parse numeric literals for cost/iterations/memory; flag when below minimums. Flag fast-hash APIs within 3 lines of `password|passwd|credential`.

---

## Post-Quantum Readiness / Crypto-Agility (harvest-now-decrypt-later)

A **forward-looking** class, distinct from CWE-327 weak crypto: the asymmetric primitives that are *classically strong today* — **RSA, ECDSA, ECDH, DSA, finite-field DH, Ed25519/EdDSA, X25519, ECC curves (P-256/384/521)** — are all breakable by a future cryptographically-relevant quantum computer (Shor's algorithm). Symmetric/hash primitives (AES-256, SHA-384/512) only lose half their strength to Grover and stay safe at large sizes (the key-size guidance below already covers them). So the post-quantum finding is the **inverse** of the classical one: code using RSA-2048 / P-256 / Ed25519 is *not* a CWE-327 weakness, but **is** a migration target.

**Harvest-now-decrypt-later (HNDL)** sets priority: an attacker can record TLS/VPN traffic or stored ciphertext encrypted under a classical key exchange *today* and decrypt it once a quantum computer exists. So **key establishment** (ECDH / RSA-KEM / DH) and **long-lived signatures** (firmware, CA roots, code/document signing) are the urgent sites; ephemeral auth-only signatures are lower priority.

**Detection (recon):**
- **Key-gen / KEM / signature call sites** by language: Go `rsa.`/`ecdsa.`/`ecdh.`/`dsa.`/`ed25519.`/`elliptic.P*`; Java `KeyPairGenerator.getInstance("RSA"|"EC"|"DSA"|"DH"|"EdDSA")`, `Signature.getInstance("*ECDSA"|"*withRSA")`; Python `cryptography` `rsa.generate_private_key`/`ec.generate_private_key`/`dh.`, PyNaCl Ed25519; Node `crypto.generateKeyPair('rsa'|'ec'|'ed25519'|'x25519'|'dh')`, `crypto.createSign`; OpenSSL `EVP_PKEY_RSA`/`EC`/`X25519`.
- **TLS configs** lacking a PQ-hybrid key-exchange group — e.g. nginx/Apache `ssl_protocols` without TLSv1.3 **and** a hybrid group such as `X25519MLKEM768`.
- Emit a **crypto inventory / CBOM** (CycloneDX Cryptographic Bill-of-Materials) of every primitive and its call sites so migration can be tracked.

**Migration targets (NIST PQC, finalized 2024):** key establishment → **ML-KEM** (FIPS 203) or a **hybrid** classical+PQ suite (`X25519MLKEM768`) for defense-in-depth; signatures → **ML-DSA** (FIPS 204) or **SLH-DSA** (FIPS 205, hash-based/conservative); **FN-DSA** (FIPS 206) is draft. National-security systems follow **CNSA 2.0** timelines (software/firmware signing earliest, general TLS/data-in-transit later in the decade).

**Triage (keep severity proportionate):** this is **agility/readiness, not a currently-exploitable bug** — default **Low/Info** unless the path protects **long-lived** secrets or sits under a near-term compliance deadline (then raise). Classical primitives remain fine for ephemeral, non-security, or already-trusted-release-verification paths — **don't churn working crypto without context** (ask about the path's role first). A site can be *both* classically weak and quantum-vulnerable (e.g. RSA-1024) — see the classical key-size table below.

## Cryptographic Storage — IV, Nonce & Key Size

Extends CWE-327 beyond weak algorithm strings.

### Approved Algorithms & Modes

| Use | Approved | Prohibited |
|-----|----------|------------|
| Symmetric at rest | AES-GCM, ChaCha20-Poly1305 (AEAD) | ECB; CBC/CTR without separate MAC |
| Symmetric key size | AES ≥128-bit (256 preferred) | DES, 3DES, RC4, Blowfish |
| Asymmetric | RSA ≥2048 with OAEP; Curve25519/Ed25519 | RSA `<2048`; RSA PKCS#1 v1.5 for encryption |
<!-- "Approved" here is *classical* strength only; RSA/ECC/Ed25519/X25519 are all quantum-vulnerable migration targets — see Post-Quantum Readiness above. -->
| Integrity | AEAD tag or encrypt-then-MAC | AES-CBC + PKCS padding only |

### VULN (any match)

- Static/reused IV or nonce: zero-filled arrays, string-literal IV, field never reassigned per encrypt
- GCM nonce reuse under same key (singleton cipher, counter not incremented)
- `Cipher.getInstance("RSA/ECB/PKCS1Padding")` or equivalent PKCS#1 v1.5 encryption padding
- `KeyGenerator.init(64)` or AES key `<128` bits; RSA `<2048` bits
- `SecretKeySpec` / key derived from password passphrase via `getBytes()` only

### SAFE (any match)

- Fresh random IV/nonce per operation: `SecureRandom` + `GCMParameterSpec`; Node `crypto.randomBytes(12)` for GCM
- `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` (or platform OAEP default)
- AEAD auth tag verified on decrypt

```javascript
// VULN — static IV
const iv = Buffer.alloc(16, 0);
crypto.createCipheriv('aes-256-gcm', key, iv);

// SAFE
const iv = crypto.randomBytes(12);
crypto.createCipheriv('aes-256-gcm', key, iv);
```

### Detection Patterns

```
IvParameterSpec\s*\(\s*new byte|GCMParameterSpec\s*\([^)]*new byte\[
Buffer\.alloc\([^,]+,\s*0\)|static final byte\[\].*IV
RSA/ECB/PKCS1Padding|PKCS1Padding
KeyGenerator.*\.init\s*\(\s*(56|64|128)\s*\)
SecretKeySpec\s*\([^)]*\.getBytes\(\)
```

---

## Key Management (CWE-321 / CWE-326)

**VULN** (any match) — these are the *crypto-management* defects this class owns:

- Same key object used for encryption and signing/MAC
- DEK stored with ciphertext without KEK wrap (JSON `{key, data}`, key file beside `.enc`)
- Password/phrase as raw symmetric key (no KDF), or key shorter than the minimum size below
- Static/reused IV/nonce; long-lived key with no version/alias/rotation metadata when KMS is absent

> **De-confliction (avoid double-reporting):** a key that is merely *hardcoded and extractable* — `SECRET_KEY = "…"`, `byte[] key = {0x…}`, Base64 key literal in source/committed config — whose size and algorithm are otherwise adequate is **`hardcoded_secrets`** (CWE-798, see `hardcoded_secrets.md`), **not** this class. Report `weak_crypto_hash` only when the *cryptographic* property is wrong (too short, reused for encrypt+sign, DEK-with-ciphertext, password-as-key, static IV). When both are true (e.g. a hardcoded **and** undersized key), prefer `weak_crypto_hash` and note the exposure; do not emit both for the same literal.

**SAFE** (any match):

- Runtime fetch from KMS/HSM/vault: `KMSClient`, `KeyVaultClient`, `generateDataKey`, envelope encryption
- DEK per item/session; KEK in separate vault/HSM; purpose-separated keys (encrypt vs sign vs wrap)
- Key version or rotation alias in config (`key-version`, `kms:Alias/app-v2`)

```java
// VULN
private static final byte[] AES_KEY = "hardcoded16bytes".getBytes();

// SAFE
GenerateDataKeyResult r = kmsClient.generateDataKey(request);
```

| Key type | Minimum size |
|----------|--------------|
| AES DEK | 128-bit (256 preferred) |
| RSA | 2048-bit |
| KEK | ≥ strength of wrapped DEK |

Rotate on compromise, cryptoperiod expiry, or algorithm deprecation; document rotation before compromise occurs.

### Detection Patterns

```
(hardcoded|secret[_-]?key|encryption[_-]?key)\s*=\s*["'{]
SecretKeySpec\s*\(|BEGIN (RSA |EC )?PRIVATE KEY
KMS|KeyVault|CloudKMS|generateDataKey|Envelope|wrapKey|vault\.read
process\.env\.(SECRET|KEY).*createCipher
```

Cross-ref: a plain hardcoded/extractable key literal (adequate size & algorithm) is `hardcoded_secrets` (CWE-798); reserve this class for the crypto-management defects above. See `hardcoded_secrets.md`.

---

## Triage Cues — What Is NOT Vulnerable

Use after presence match to avoid false positives:

| Signal | Likely SAFE | Still VULN |
|--------|-------------|------------|
| Password hash | Argon2id/scrypt/bcrypt/PBKDF2 params ≥ minimums | MD5/SHA-1/SHA-256 on password; `Cipher` on password |
| Salt | Random per-user via KDF library output | Fixed/global salt string |
| Symmetric mode | AES-GCM / ChaCha20-Poly1305 + random nonce | AES/ECB; CBC without MAC |
| IV/nonce | New CSPRNG bytes each encrypt | Zero/constant IV reused |
| RNG | `SecureRandom`, `crypto.randomBytes`, `secrets.*`, Go `crypto/rand` | `Random`, `Math.random`, `rand()`, Go `math/rand` for tokens |
| Keys | KMS/HSM/vault reference; versioned alias | Literal key in repo; env-only DEK without wrap |
| Storage | One-way slow hash | Reversible password encryption |

**Mandatory disambiguation:**

- `MessageDigest` + password variable → **VULN** even if SHA-256
- `Cipher` + password plaintext → **VULN** (reversible storage)
- bcrypt PHC: `$2b$12$…` → SAFE; `$2a$08$…` → VULN (cost 8)
- SHA-256/512 for file integrity, cache keys, non-credential checksums → context-dependent; note non-password use
