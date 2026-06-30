---
name: hardcoded-code-backdoor
description: Embedded malicious code and supply-chain backdoor patterns (CWE-506)
---

# Hardcoded Code / Backdoor (CWE-506)

Malicious or suspicious logic is often hidden in otherwise trusted code: hex/base64 blobs decoded at runtime, time-gated execution, process-name fingerprinting, and dangerous native API calls. Static analysis models the event-stream–style obfuscation pattern and Solorigate-inspired heuristics for C#.

## Source -> Sink Pattern

### Hard-coded data interpreted as code (JS / Ruby)

**Sources**
- String literals matching `[0-9a-fA-F]{8,}` with at least one digit (hex-encoded payload)
- Ruby additionally: string literals composed entirely of `\x` escape sequences

**Transform steps (taint)**
- Hex decode: `Buffer.from(s, "hex").toString()`, Ruby `[r].pack 'H*'`, and default taint steps between decode and sink
- Flow state transitions from `unmodified`/`Data` to `modified`/`Taint` after transformation

**Sinks**
- **Code injection** — `eval`, `Function`, `module._compile`, and other `CodeInjection` sinks (`getKind(): "Code"`)
- **Import path** — first argument to `require(...)` (JS) or `require e(...)` (Ruby) (`getKind(): "An import path" / "an import path"`)

### C# backdoor heuristics

| Pattern | Source | Sink / trigger |
|---------|--------|----------------|
| Hardcoded → code | *(no dedicated C# CWE-506 detection)* | — |
| Time bomb | `File.GetLastWriteTime` / creation/access time calls | DateTime arithmetic → comparison → `if`/selection condition |
| Process fingerprint | `Process.ProcessName` property read | Argument to hash function (`Hash*`, MD/SHA names, non-cryptographic hash callables) |
| Native backdoor APIs | — | Extern/DllImport calls to token/process/privilege APIs (see list below) |

## Vulnerable Conditions

- Hex constant decoded then passed to `require()` — classic supply-chain hiding (event-stream incident)
- Hex constant decoded then passed to `eval()` — hidden payload execution
- `File.GetLastWriteTime(path)` plus offset compared in conditional branch (planted-file time bomb)
- `Process.ProcessName` hashed and compared against obfuscated AV/process blocklists
- P/Invoke to `OpenProcessToken`, `DuplicateTokenEx`, `CreateProcess*`, `LoadLibrary*`, `GetProcAddress`, `ImpersonateLoggedOnUser`, etc.
- **Obfuscation beyond hex/base64** — the decode-then-execute pattern also hides behind **XOR-decrypt** (`bytes([b ^ k for b in data])`, `c.charCodeAt(0) ^ key`, C `buf[i] ^= key[i%len]`) and **character-code-array reconstruction** (`String.fromCharCode(104,101,…)`, `''.join(chr(c) for c in [...])`, `bytes([...]).decode()`) feeding `eval`/`exec`/`Function`/`compile`/`require`. Same class as the hex/base64 case — a long encoded blob that is **decoded and then executed** is the signature, regardless of codec. (The decode family also appears in `prompt_injection.md`, but there the payload is *attacker input*; here it is **hard-coded in the repo** — an implant, not an injection.)
- **Cryptominer / resource-hijacking implant** — a planted miner (T1496): mining-pool URLs (`stratum+tcp://`, `stratum+ssl://`, `pool.`/`*.minexmr.com`/`*.nanopool.org` hosts), known miner names/libs (`xmrig`, `cpuminer`, `minerd`, `cryptonight`, `coinhive`, `coinimp`, `cryptoloot`, in-browser WASM miners), a hard-coded wallet address, or miner flags (`--donate-level`, `--cpu-priority`, `--max-cpu-usage`). **High-signal, low-FP** (these strings almost never appear in legitimate app code); common in compromised npm/PyPI packages, trojanized Docker images, and lifecycle (`postinstall`) scripts — cross-ref `supply_chain_security.md`.

## Safe Patterns

- Plain string module paths: `require('./utils')`, `require "json"` — no decode indirection
- Configuration and secrets from environment, vault, or signed artifacts — not hex literals interpreted at runtime
- Time checks based on documented business rules with clear constants, not file mtime of the deployed assembly
- Legitimate native interop isolated, documented, and absent hash/compare obfuscation around `ProcessName`

## Detection Coverage

**JavaScript / Ruby — hard-coded data interpreted as code**
- Hex string literals (≥8 hex chars with at least one digit) decoded then passed to `eval`, `Function`, `module._compile`, or `require(...)` first argument
- **Barriers**: sanitizer nodes in customization (extension point; default pack relies on flow-state — direct hex to eval without decode may not alert)
- Ruby requires taint after decode — raw hex to `require` without decode is OK (syntax error)

**C# backdoor heuristics** (low precision — triage signals, not verdicts)
- Time bomb: `File.GetLastWriteTime` / creation/access time → DateTime arithmetic → comparison → conditional branch
- Process fingerprint: `Process.ProcessName` → hash function (`Hash*`, MD/SHA names)
- Native backdoor APIs: extern/DllImport calls to token/process/privilege APIs (see list below)

**No automated CWE-506 detection for Python** — manually hunt `base64.b64decode`, `codecs.decode`, `exec`, `importlib` on literals.

### Dangerous native methods flagged (C#)

`OpenProcessToken`, `OpenThreadToken`, `DuplicateToken`, `DuplicateTokenEx`, `LogonUser*`, `WNetAddConnection*`, `DeviceIoControl`, `LoadLibrary*`, `GetProcAddress`, `CreateProcess*`, `InitiateSystemShutdown*`, `GetCurrentProcess`, `GetCurrentProcessToken`, `GetCurrentThreadToken`, `GetCurrentThreadEffectiveToken`, `SetTokenInformation`, `LookupPrivilegeValue*`, `AdjustTokenPrivileges`, `SetProcessPrivilege`, `ImpersonateLoggedOnUser`, `Add*Ace*` — on extern or `[DllImport]` methods.

## JavaScript

**VULN** — event-stream pattern:
```javascript
function e(r) { return Buffer.from(r, "hex").toString(); }
var n = require(e("2e2f746573742f64617461")); // hex → import path
```

**VULN** — hex literal to eval (test fixture):
```javascript
var s = '636f6e736f6c652e6c6f672827636f646520696e6a656374696f6e2729';
eval(Buffer.from(s, 'hex').toString());
```

**SAFE** — literal path without decode indirection:
```javascript
require('./helpers');
```

## Ruby

**VULN** — hex decoded into `require`:
```ruby
def e(r); [r].pack 'H*'; end
require e("2e2f746573742f64617461")
```

**SAFE** — direct require:
```ruby
require 'json'
```

## C# (backdoor heuristics)

- **VULN**: `if (File.GetLastWriteTime(AssemblyPath).AddDays(90) < DateTime.Now) { /* hidden payload */ }`
- **VULN**: `hasher.ComputeHash(Encoding.UTF8.GetBytes(Process.GetCurrentProcess().ProcessName))`
- **VULN**: `[DllImport("advapi32")] static extern bool OpenProcessToken(...)` used alongside obfuscated control flow
- **Note**: Solorigate-inspired heuristics indicate similarity only, not confirmed malice

## Common False Alarms

- Short hex strings (< 8 hex chars) — below source regex threshold
- Hex constants used for legitimate binary protocols, UUIDs, or test vectors with no code/import sink
- `eval(test+"n")` on short digit strings — known spurious alert in JS tests (bigint feature probe)
- Legitimate admin tools using native APIs without obfuscation — `dangerous-native-functions` precision is **low**
- Time-bomb query: any file-mtime-driven feature flag — verify intent before escalation

## Business Risk

- Supply-chain compromise (hidden dependency loader, credential exfiltration)
- Delayed activation evades code review and CI scanning windows
- AV/process evasion prolongs dwell time
- Token/process manipulation enables privilege escalation and lateral movement

## Core Principle

Trust boundaries apply to **dependencies and dormant code paths**, not only request handlers. Any pattern that decodes opaque constants into imports or executable code demands human provenance review. Treat C# backdoor heuristics as triage signals, not verdicts.

## Analyst Notes

- JS/Ruby patterns mirror the npm **event-stream** incident — prioritize dependency and minified bundle review
- Python lacks automated CWE-506 coverage; manually hunt `base64.b64decode`, `codecs.decode`, `exec`, `importlib` on literals
- Distinguish from `rce.md` (user-controlled code injection) — here the payload is **hard-coded** and intentionally obscured

## Cross-References

- `dependency_confusion.md` — typosquatting and package substitution
- `rce.md` — runtime code execution from user input
- `information_disclosure.md` — debug/backdoor adjacent data leaks
