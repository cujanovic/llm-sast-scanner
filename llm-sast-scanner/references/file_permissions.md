---
name: file_permissions
description: Incorrect permission assignment for critical resources — world-writable files, missing mode args, weak DACLs (CWE-732)
---

# File Permissions (CWE-732)

Critical files created or modified with overly permissive access controls let other local users (or, on shared hosts, other tenants) read secrets, tamper with configuration, or replace content the application trusts. Web backends that write session stores, upload staging files, or default config templates on disk are especially exposed when those paths are world-writable or world-readable.

## Source → Sink Pattern

**Sources** (permission value / flag):
- Literal `mode` arguments to `open`, `creat`, `chmod`, `os.chmod`, `FileUtils.chmod`
- Missing `mode` on `open(..., O_CREAT)` — stack garbage becomes the mode (C/C++)
- `File.setWritable(true, false)` or `Files.setPosixFilePermissions` including `OTHERS_WRITE` (Java)
- Rails cookie-security config overrides (`cookies_same_site_protection=`, weak cipher settings)
- `SetSecurityDescriptorDacl(..., TRUE, NULL, ...)` — NULL DACL on Windows (C/C++)

**Sinks** (insecure assignment):
- File creation: `creat`, `open`/`openat` with `O_CREAT`, `fopen`/`fopen_s` write modes
- Permission change: `chmod`, `fchmod`, `_chmod`, `os.chmod`, `FileUtils.chmod` / `File.chmod`
- Post-creation trust: reading a file variable that was also set world-writable (Java)
- Cookie policy weakening via Rails `config.action_dispatch.*` settings (Ruby)

## Vulnerable Conditions

- Mode `0666`, `0777`, or any bitmask with **other write** (`S_IWOTH` / world `2`) after umask
- `open(path, O_CREAT)` without third `mode` argument — undefined stack bits used as permissions
- `fopen(path, "w")` / `"a"` — treated as world-writable (`0666`-class) when mode is implicit
- `configFile.setWritable(true, false)` — writable by all users, then loaded as trusted config
- `FileUtils.chmod 0755`, `0222`, `"a+rw"`, `"u=rwx,o+r"` — group/other read or write (Ruby/Python)
- NULL DACL with `bDaclPresent=TRUE` — grants full access, bypasses normal ACL checks (Windows)
- Rails: `cookies_same_site_protection = :none`, weak `encrypted_cookie_cipher`, `use_authenticated_cookie_encryption = false`

## Safe Patterns

- Owner-only: `S_IRUSR | S_IWUSR` (`0600`), `0700`, `open(..., O_CREAT, S_IRUSR | S_IWUSR)`
- Always pass explicit `mode` when `O_CREAT` or `O_TMPFILE` is set
- Java: `setWritable(true, true)` (owner only) or avoid world-writable POSIX permissions; use groups/ACLs instead of `OTHERS_WRITE`
- Python/Ruby: `0700` or symbolic `"u=rwx,go-r"` — no group/other read or write bits
- Windows: pass a real `ACL` pointer to `SetSecurityDescriptorDacl`, never `NULL` with present flag
- Rails: keep defaults (`SameSite: :lax`, `aes-256-gcm`, authenticated encryption enabled)

## Sanitizers / Barriers

Commonly affected languages: C/C++, Java, Python, Ruby. Go, C#, JavaScript, and Rust require manual review.

**C/C++ (world-writable file creation)**
- Modes after local `umask()` masking that clear `S_IWOTH`
- `fopen_s` without `"u"` in mode string — restrictive default (`0600`-class)
- Excludes `ConfigurationTestFile` paths (build-time generated files)

**C/C++ (open with O_CREAT)**
- **SAFE**: third argument present on `open`/`openat` when `O_CREAT`/`O_TMPFILE` set

**Java (world-writable file read)**
- **Sink pairing**: same `File` variable both set world-writable and read; parameters reported at caller
- World-writable via `setWritable(_, false)` on second arg or `Files.setPosixFilePermissions` with `OTHERS_WRITE`

**Python / Ruby (overly permissive file)**
- Literal modes only (Ruby TODO: non-literal flows partially tracked)
- Flags modes where world or group nibble grants read (`4`) or write (`2`)
- Ruby: `0700`, `0711`, `"u=rwx,go-r"` — no group/other read or write

**Ruby (weak cookie configuration)**
- Flags weak cipher, disabled authenticated encryption, `SameSite=None`, or unset SameSite

## Language Patterns

### C/C++

**VULN**: `creat(OUTFILE, 0666);` — world-writable default config.
**VULN**: `open(FILE, O_CREAT)` — missing mode leaks stack bits.
**VULN**: `SetSecurityDescriptorDacl(&pSD, TRUE, NULL, FALSE)` — NULL DACL.
**SAFE**: `open(OUTFILE, O_WRONLY | O_CREAT, S_IWUSR | S_IRUSR);`

### Java

**VULN**: `configFile.createNewFile(); configFile.setWritable(true, false); loadConfig(configFile);`
**SAFE**: owner-only write or restrictive POSIX permissions before reading trusted content.

### Python

**VULN**: `os.open(path, os.O_CREAT, 0o666)` or `os.chmod(path, 0o777)`.
**SAFE**: `os.open(path, os.O_CREAT, 0o600)`.

### Ruby

**VULN**: `FileUtils.chmod 0777, filename` / `FileUtils.chmod "a+rw", filename`.
**VULN**: `config.action_dispatch.cookies_same_site_protection = :none`.
**SAFE**: `FileUtils.chmod 0700, filename`.

## Common False Alarms

- `0755` / world-execute-only modes flagged by Ruby/Python queries when only execute bits are set for group/other (Ruby treats `0711` as safe)
- C/C++ files in generated configuration test paths excluded by `ConfigurationTestFile`
- Intentionally shared spool directories on dedicated multi-user systems (still risky for secrets)
- Rails cookie settings left at framework defaults (`:lax`, strong cipher) — not reported

## Business Risk

- Local privilege abuse: attackers on shared hosts overwrite session files, API keys, or upload temp paths
- Config tampering: world-writable `.env`, YAML, or property files alter application behavior
- Compliance: secrets readable by other OS users violates least-privilege and data-protection requirements
- Windows NULL DACL: any user can seize control of the security descriptor and object ACL

## Core Principle

Create and retain critical files with the minimum permissions required — typically owner read/write only (`0600`/`0700`). Never rely on the process umask or platform defaults; always specify an explicit mode for `O_CREAT`, and never assign NULL DACLs on Windows when `bDaclPresent` is true.
