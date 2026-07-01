---
name: insecure_temp_file
description: Insecure temporary file creation — predictable names, race windows, world-readable paths (CWE-377)
---

# Insecure Temporary File (CWE-377)

Temporary files created with predictable names, split create/open steps, or permissive modes in shared directories (`/tmp`, `os.tmpdir()`) let attackers pre-create or swap files between name generation and use. On web servers this can expose uploaded content, poison config snippets written to temp paths, or — in worst cases — enable local code execution when another process executes a replaced file.

## Source → Sink Pattern

**Sources**:
- Python: calls to `tempfile.mktemp`, `os.tmpnam`, `os.tempnam` (name-only APIs)
- JavaScript: `os.tmpdir()` return value; string literals matching `/tmp/%`
- C/C++: `tmpnam`, `tmpnam_s`, `tmpnam_r` without nearby `mkstemp`/`mktemp`/`mkdtemp`

**Sinks**:
- Python: any use site of deprecated name-only temp functions (the call itself is the finding)
- JavaScript: `fs.open`/`openSync`/`writeFile`/`writeFileSync`/`outputFile*` paths under the OS temp dir **without** a secure `mode` (no mode or mode with low six bits set — not `0o600`-class)
- C/C++: `fopen("/tmp/name.tmp", "w")` after predictable name; `tmpnam` then separate `fopen`

## Vulnerable Conditions

- **Name-then-open race**: `filename = mktemp(); open(filename, "w")` — attacker creates symlink/file between calls
- **Predictable paths**: `path.join(os.tmpdir(), "test-" + Date.now() + ".txt")` — guessable, no exclusive create
- **World-accessible temp dir defaults**: files in `/tmp` readable/writable by other users unless mode restricted
- **Missing secure mode on Node `fs` calls**: no `mode: 0o600` (or equivalent) when writing under tmpdir
- **C `tmpnam` without atomic create**: name returned but file not opened exclusively (`mkstemp`/`mkdtemp` not paired)

## Safe Patterns

- Python: `tempfile.NamedTemporaryFile`, `TemporaryFile`, or `mkstemp` — open atomically with restrictive permissions
- JavaScript: `tmp.fileSync()` from the `tmp` npm package — private file, exclusive creation
- Node `fs`: if writing under tmpdir manually, pass `mode: 0o600` (secure mode — lowest six bits all zero)
- C/C++: `mkstemp` on `"/tmp/name.XXXXXX"` template, then `fdopen`; avoid `tmpnam` + separate `fopen`
- Prefer private app-specific directories with strict ownership over world-writable `/tmp` for secrets

## Sanitizers / Barriers

Commonly affected languages: Python, JavaScript, C/C++. Java, Go, C#, Ruby, and Rust require manual review for `File.createTempFile`, `Files.createTempFile`, and similar APIs.

**JavaScript (insecure temporary file)**
- **Source**: `os.tmpdir()`; `/tmp/...` string literals
- **Sink**: file-open calls (`open`, `writeFile`, `outputJson`, etc.) on paths tainted from tmpdir without secure mode
- **Sanitizer**: non-first leaf in string concatenation (`NonFirstStringConcatLeaf`); `path.join` arguments after index 0
- **Secure mode**: integer mode where lowest six bits are all zero (e.g. `0o600`)

**Python (insecure temporary file)**
- Direct detection of deprecated APIs — no taint flow; replacement with `NamedTemporaryFile`/`TemporaryFile` is the fix

**C/C++ (insecure filename generation)**
- **SAFE pairing**: `tmpnam` in same control-flow region as `mktemp`, `mkstemp`, `mkstemps`, or `mkdtemp`

## Language Patterns

### Python

**VULN**:
```python
filename = mktemp()
with open(filename, "w+") as f:
    f.write(results)
```

**SAFE**:
```python
with NamedTemporaryFile(mode="w+", delete=False) as f:
    f.write(results)
```

### JavaScript / Node

**VULN**:
```javascript
const file = path.join(os.tmpdir(), "test-" + Date.now() + ".txt");
fs.writeFileSync(file, "content");
```

**SAFE**:
```javascript
const file = tmp.fileSync().name;
fs.writeFileSync(file, "content");
```

### C/C++ (insecure filename generation)

**VULN**: `fp = fopen("/tmp/name.tmp", "w");` — fixed name in shared dir.
**VULN**: `char *name = tmpnam(NULL); fp = fopen(name, "w");` — TOCTOU window.
**SAFE**: `strcat(filename, "/tmp/name.XXXXXX"); fd = mkstemp(filename); fp = fdopen(fd, "w");`

### Java (manual review)

**NOTE**: `File.createTempFile(...)` atomically creates a private, randomly named file — generally acceptable; not the primary insecure pattern. Flag legacy/insecure variants instead: predictable names, `tmpnam`/`mktemp`, world-readable umask, or name-then-open TOCTOU races.
**VULN**: `File.createTempFile("prefix", ".suffix")` with delayed open and no restrictive `PosixFilePermissions` on multi-user hosts — lower severity; prefer flagging predictable-name or name-then-open patterns.
**SAFE**: `Files.createTempFile(...)` with `PosixFilePermissions.asFileAttribute(OWNER_READ, OWNER_WRITE)` and immediate use inside try-with-resources.

## Common False Alarms

- JavaScript paths under tmpdir where `mode: 0o600` (or `384`) is explicitly passed to `open`/`writeFile`
- String concat where user/content segment is not the first leaf (sanitizer applies)
- C/C++ `tmpnam` immediately followed by `mkstemp` on same path in analyzed control flow
- Temp files holding only ephemeral, non-sensitive, recomputable data (lower risk but pattern still discouraged)

## Business Risk

- **Information disclosure**: world-readable temp files leak PII, tokens, or report output to other OS users
- **Integrity / TOCTOU**: attacker replaces temp config or payload before the application reads it
- **RCE escalation**: when another service executes or includes attacker-controlled temp content
- **Compliance**: processing user data in insecure temp paths fails least-privilege expectations on shared infrastructure

## Core Principle

Never use name-only temporary file APIs (`mktemp`, `tmpnam`, predictable `tmpdir` paths). Create temp files atomically in one step with exclusive access and owner-only permissions (`0600`), using library helpers (`NamedTemporaryFile`, `tmp.fileSync`, `mkstemp`) rather than hand-rolled names in shared directories.
