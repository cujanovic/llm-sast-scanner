---
name: environment_variable_injection
description: Detect user-controlled data flowing into process environment-variable assignment (name and/or value) — os.environ/os.putenv, process.env, setenv/putenv, ENV[]=, Environment.SetEnvironmentVariable, ProcessBuilder.environment().put — where attacker control of a variable name or a security-relevant variable's value enables loader/runtime hijack (LD_PRELOAD, NODE_OPTIONS, PYTHONPATH, PATH) or override of app secrets/flags (JWT_SECRET, DEBUG, DATABASE_URL). Covers CWE-99 / CWE-454 across all languages.
---

# Environment Variable Injection (CWE-99 / CWE-454)

When untrusted input controls **which** environment variable is set (the *name*) and/or the *value* of a **security-relevant** variable, the attacker can change how the current process or its child processes load code and behave. Environment is inherited by children, so a single tainted assignment can become code execution in a later `spawn`/`exec`, or can silently override an application's own configuration (secrets, auth flags, connection strings).

This is distinct from command injection (no shell metacharacters needed — the variable *is* the vector) and from mass assignment (that binds object properties, not the process environment).

## Source → Sink Pattern

**Sources** (`RemoteFlowSource` / `ActiveThreatModelSource`):
- HTTP parameters, headers, cookies, JSON/form body fields, path segments
- Filenames/metadata from uploads, message-queue payloads, webhook bodies
- Any externally controlled string that reaches the variable name or value below

**Sinks** (environment-setting APIs — flag when the *name* is tainted, or the *value* of a security-relevant name is tainted):
- **Node.js**: `process.env.X = v`, `process.env[userKey] = v`, `Object.assign(process.env, userObj)`, and `env:` maps built from user input passed to `child_process.spawn/exec/execFile/fork`
- **Python**: `os.environ[k] = v`, `os.environ.setdefault(k, v)`, `os.environ.update(mapping)`, `os.putenv(k, v)`, and `env=` passed to `subprocess.run/Popen/call`
- **Java**: `ProcessBuilder.environment().put(k, v)` / `.putAll(map)` (affects spawned children; the JDK has no portable setenv for the current process)
- **Go**: `os.Setenv(k, v)`, and `cmd.Env = append(os.Environ(), userKV)` for `exec.Command`
- **C/C++**: `setenv(k, v, 1)`, `putenv("K=V")`, `_putenv_s`
- **Ruby**: `ENV[k] = v`, `ENV.store(k, v)`, `ENV.update(h)`
- **PHP**: `putenv("K=V")`, `apache_setenv`
- **C# / .NET**: `Environment.SetEnvironmentVariable(k, v[, target])`, `ProcessStartInfo.Environment[k] = v` / `.EnvironmentVariables[k] = v`

## Why it is dangerous — three impact tiers

1. **Loader hijack → RCE** (highest). Setting a dynamic-linker variable makes the next child process load an attacker library:
   - Linux: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`
   - macOS: `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, `DYLD_FRAMEWORK_PATH`
   - Windows: search-order via `PATH` (DLL planting)
2. **Runtime / interpreter option injection → RCE**. Many runtimes execute code named by an env var:
   - `NODE_OPTIONS` (e.g. `--require /tmp/x.js`, `--experimental-loader`), `BASH_ENV` / `ENV`, `IFS`, `PATH`
   - `PYTHONPATH`, `PYTHONSTARTUP`, `PYTHONINSPECT`; `RUBYOPT` (e.g. `-r`); `PERL5LIB`, `PERL5OPT`
   - `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `CLASSPATH`; `GIT_SSH`, `GIT_EXTERNAL_DIFF`, `GIT_PAGER`, `GIT_CONFIG_*` hook commands
3. **Application-config / secret override → auth bypass, account takeover, SSRF, data exfiltration**. If the app reads its own config from the environment, overriding it at runtime is a direct compromise even with no loader/runtime trick:
   - `JWT_SECRET`, `SESSION_SECRET`, `SECRET_KEY` → forge tokens / sessions
   - `ADMIN_*`, `DISABLE_AUTH`, `AUTH_ENABLED`, feature flags → privilege escalation
   - `DATABASE_URL`, `REDIS_URL`, `SMTP_HOST` → redirect to attacker infrastructure (SSRF / credential capture)
   - `DEBUG`, `NODE_ENV` → enable verbose errors / stack traces (information disclosure)

**Tainted variable name = High by default** (attacker can choose any of the above). **Tainted value of a fixed, non-security variable = Medium/Low** depending on what reads it.

## Adjacent smell: insecure env-flag parsing (a config bug, not injection)

Distinct from the injection sink above (no attacker-controlled write) — this is the developer-side bug of **gating a security control on a raw env-flag read used as a boolean**. In JS a non-empty string is truthy (`Boolean("false") === true`), and the same trap exists in other languages (Python `os.environ.get("X")` truthiness, Go non-empty string, shell `[ -n "$X" ]`):

- `if (process.env.DISABLE_AUTH) { …skip auth… }` — setting `DISABLE_AUTH=false` is a non-empty string → still truthy → **auth stays disabled**.
- `if (process.env.ENABLE_RATE_LIMIT) { app.use(rateLimit()) }` — unset → `undefined` → falsy → the control is **never installed** (fail-open by default).

**Safe**: parse the flag explicitly and fail closed — `process.env.DISABLE_AUTH === "true"` (default security ON; an unset or unrecognized value must keep the control enabled), and require an explicit opt-out rather than relying on truthiness. A security control whose *enabled* state depends on an env-flag's truthiness, with no fail-closed default, is the smell.

## Vulnerable vs Safe

**VULN (Node.js — attacker controls both name and value → can set `LD_PRELOAD`/`JWT_SECRET`):**
```js
// req.body = { key: "LD_PRELOAD", value: "/tmp/evil.so" }  — or { key: "JWT_SECRET", value: "attacker" }
app.post("/config", (req, res) => {
  process.env[req.body.key] = req.body.value;   // CWE-99: arbitrary env var assignment from user input
  res.sendStatus(204);
});
```

**SAFE (allowlist the name; validate the value; restrict to admins):**
```js
const SETTABLE = new Set(["APP_THEME", "APP_LOCALE"]);          // never security-relevant vars
app.post("/config", requireAdmin, (req, res) => {
  const { key, value } = req.body;
  if (!SETTABLE.has(key) || typeof value !== "string" || !/^[\w.-]{1,64}$/.test(value)) {
    return res.sendStatus(400);
  }
  process.env[key] = value;
  res.sendStatus(204);
});
```

**VULN (Python — user-controlled name into the environment):**
```python
os.environ[request.form["name"]] = request.form["value"]   # attacker sets PYTHONSTARTUP / LD_PRELOAD / SECRET_KEY
subprocess.run(["python", "worker.py"])                     # child inherits the tainted environment
```

**SAFE (explicit minimal env for the child; no user-controlled names):**
```python
child_env = {"PATH": "/usr/bin", "LANG": "C.UTF-8"}         # build a clean env, don't merge user data
subprocess.run(["python", "worker.py"], env=child_env)
```

## Sanitizers / Barriers

- **Allowlist variable names.** Never let user input choose the variable name; compare against a fixed set of non-security names.
- **Denylist is a fallback, not primary.** If you must, reject `LD_*`, `DYLD_*`, `*_OPTIONS`, `PATH`, `IFS`, `BASH_ENV`, `ENV`, `GIT_*`, `PYTHON*`, `NODE_*`, `JAVA_*`, `PERL5*`, `RUBYOPT`, `CLASSPATH`, and your app's own secret/flag names — but allowlisting is safer because this list is incomplete by nature.
- **Validate the value** against the expected format for that specific known variable.
- **Give children an explicit, minimal environment** instead of inheriting the (now-tainted) parent environment or merging user-provided maps.
- **Restrict to privileged users / build-time config**, never an unauthenticated request path.

## Recon Indicators (Grep)

```bash
# env-write sinks taking a variable derived from request data (triage: is the NAME or a security var's VALUE tainted?)
rg -n "process\.env\[[^\]]*\]\s*=|process\.env\.\w+\s*=|os\.environ\[|os\.putenv|os\.environ\.(update|setdefault)|setenv\(|putenv\(|_putenv_s|ENV\[[^\]]*\]\s*=|ENV\.(store|update)|Environment\.SetEnvironmentVariable|\.environment\(\)\.put|os\.Setenv\(" \
  --glob '*.{js,ts,py,go,java,cs,rb,php,c,cc,cpp,h}'
# child processes whose env map is assembled from user data
rg -n "spawn|exec|execFile|fork|Popen|ProcessBuilder|exec\.Command|ProcessStartInfo" --glob '*.{js,ts,py,go,java,cs,rb,php}' -C2 | rg -i "env"
```

## Common False Alarms

- Setting a **fixed, non-security** variable to a constant or already-validated value (e.g. `process.env.TZ = "UTC"`).
- Reading the environment (`os.getenv`, `process.env.X`) — that is a *source*, not this sink (though attacker-controlled env reaching a dangerous sink is its own taint path).
- Build/CI scripts setting env from trusted pipeline config rather than runtime request data.
- A child given an **explicit allowlisted** env map with no user-controlled keys.

## Cross-References

- When the override leads to library/code loading: `rce.md` (dynamic library/assembly load, unsafe reflection).
- When `PATH`/`IFS`/shell vars feed a shell: `rce.md` (command injection).
- When a redirected `DATABASE_URL`/`*_URL` becomes an outbound request: `ssrf.md`.
- When overriding `JWT_SECRET`/`SESSION_SECRET` enables forgery: `authentication_jwt.md`.
- When `DEBUG`/`NODE_ENV` flips on verbose errors: `information_disclosure.md`.
- Untrusted input controlling other resource identifiers (ports, connection strings, file descriptors) is the broader CWE-99 family.

## Core Principle

The process environment is trusted configuration that children inherit. Never let untrusted input pick an environment variable's **name**, and never let it set the **value** of a security-relevant variable. Allowlist the few names a request may set, validate their values, and hand child processes a clean, explicit environment.
