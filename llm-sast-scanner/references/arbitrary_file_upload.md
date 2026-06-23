---
name: arbitrary_file_upload
description: Detect unrestricted file upload vulnerabilities where attackers can upload executable files leading to Remote Code Execution or path traversal.
---

# Unrestricted File Upload

When an application allows users to upload files without restricting executable types, an attacker can deposit a server-side script (e.g., `.php`, `.py`, `.sh`) into a web-accessible directory and trigger it via an HTTP request to achieve Remote Code Execution. A secondary risk is path traversal through attacker-controlled filenames.

The core pattern: *a user-supplied file reaches a storage location without adequate extension validation, and the stored file is accessible or executable.*

## Class Boundaries

### What it IS

- No extension or content check: `file.save(upload_path)` with no validation
- Content-Type-only validation — trivially bypassed by setting the header manually
- Extension blocklist with gaps: `.php` blocked but `.php3`, `.phtml`, `.phar`, `.shtml` not
- Case-insensitive bypass: blocking `.php` but allowing `.PHP`, `.Php`
- Double extension: `shell.php.jpg` — last-segment extraction may pass allowlist while Apache executes as PHP
- Path traversal in filenames: `../../webroot/shell.php` via unsanitized `file.filename` (also overlaps `path_traversal`)
- Incomplete sanitization: stripping `../` but not `%2e%2e%2f`
- Uploads stored in a web-executable directory (`static/uploads/`, `public/`, `wwwroot/`)

### What it is NOT (commonly confused with)

- **Stored XSS via SVG/HTML** — embedded `<script>` in an uploaded SVG reflected back; sink is output encoding, not server-side execution
- **SSRF/XXE via file content** — uploaded XML/SVG triggering outbound requests; separate class
- **DoS via large files** — missing size limits; availability issue, not execution
- **IDOR on download** — accessing another user's file without authorization
- **Path traversal alone** — reading/writing files outside intended dirs without an upload execution chain; tag `path_traversal` when no web-shell deposit is possible
- **Secure uploads** — outside webroot, UUID rename, allowlist, served via `Content-Disposition: attachment` download endpoint

## Vulnerable Conditions

Both conditions must hold:
1. **No extension whitelist** (or only MIME/Content-Type check, which is bypassable).
2. **Upload directory is web-accessible** (or code executes the uploaded file).

## Safe Patterns

When these appear together, the site is likely **not vulnerable**:

- **Extension allowlist** (most important): `ext = filename.rsplit('.', 1)[-1].lower()` then check against `{'png','jpg','jpeg','gif','pdf'}`
- **Magic-byte / content validation** (defense in depth): read first 2 KB and verify MIME via `magic.from_buffer()` or equivalent — does not replace allowlist
- **Image re-encoding**: decode and re-encode through Pillow/ImageMagick to strip embedded script/polyglot payloads
- **Filename sanitization**: `secure_filename()`, `basename()`, `Path.GetFileName()`, `filepath.Base()` — strips path separators
- **Server-generated name**: `stored = f"{uuid4()}.jpg"` — extension server-controlled, not user-controlled
- **Storage outside webroot**: `/var/uploads/` not served by the web server; never `static/`, `public/`, `wwwroot/`
- **Controlled download endpoint**: `send_from_directory(..., as_attachment=True)` or `Content-Disposition: attachment` — prevents in-browser execution

## Recon Indicators

Grep for receive-and-store chains; trace whether validation exists and where the file lands.

**Upload receive patterns (find all sites first)**

| Stack | Grep targets |
|-------|-------------|
| Python/Flask | `request\.files`, `file\.save\(`, `FileStorage` |
| Python/Django | `request\.FILES`, `InMemoryUploadedFile`, `default_storage\.save`, `FileField`, `ImageField` |
| Node.js | `multer\(`, `upload\.(single\|array\|fields)`, `formidable`, `busboy`, `multiparty`, `req\.files`, `express-fileupload` |
| PHP | `\$_FILES`, `move_uploaded_file\(`, `copy\(\$_FILES` |
| Java/Spring | `MultipartFile`, `file\.transferTo\(`, `Part\.write\(`, `Files\.write\(.*getBytes` |
| Go | `FormFile\(`, `MultipartForm\.File`, `io\.Copy\(.*header\.Filename` |
| Ruby/Rails | `params\[:file\]`, `has_one_attached`, `mount_uploader`, `CarrierWave` |
| C#/ASP.NET | `IFormFile`, `CopyToAsync\(`, `HttpPostedFileBase`, `Request\.Files` |

**Dangerous sink chain (flag when present)**

1. User-controlled filename or extension reaches a path join: `os.path.join(UPLOAD, file.filename)`, `Paths.get("uploads/" + file.getOriginalFilename())`, `move_uploaded_file(..., 'uploads/' . $_FILES['file']['name'])`
2. Storage under web-served or executable dirs: `static/uploads/`, `public/uploads/`, `wwwroot/`, `getServletContext().getRealPath("/")`, `Rails.root.join('public', 'uploads')`
3. No allowlist visible before save — or only `content_type` / `mimetype` / `$_FILES['type']` checked

**Safe chain (lower priority)**

- Allowlist + `.lower()` on extension + UUID rename + path outside webroot

---

## Python Source Detection Rules

### Flask
- **VULN**: `file.save(os.path.join(UPLOAD_FOLDER, file.filename))` — no extension check, uses original filename
- **VULN**: Only MIME check (bypassable): `if 'image' in file.content_type: file.save(...)`
- **VULN**: `file.filename` used directly without `secure_filename()` — path traversal risk
- **VULN**: `os.path.join(UPLOAD_FOLDER, request.form['filename'])` — filename from form field
- **SAFE**: Extension whitelist enforced:
  ```python
  ALLOWED_EXTENSIONS = {'png', 'jpg', 'gif'}
  def allowed_file(filename):
      return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
  ```
- **SAFE**: `werkzeug.utils.secure_filename(file.filename)` + extension whitelist check

### Django
- **VULN**: `InMemoryUploadedFile` saved with original name and no extension validation
- **VULN**: `FileField` with no `validate_image` or custom validator

### Path traversal in filename
- **VULN**: `../../../etc/cron.d/evil` as filename accepted without sanitization
- **Pattern**: `file.filename` used directly in `os.path.join` without `secure_filename`

---

## JavaScript Source Detection Rules

### Multer (Node.js)
- **VULN**: `multer({ dest: 'uploads/' })` with no `fileFilter` — accepts any file type
- **VULN**: `fileFilter` only checks `mimetype` (client-supplied, bypassable):
  ```js
  fileFilter: (req, file, cb) => {
      cb(null, file.mimetype.startsWith('image/'));
  }
  ```
- **VULN**: `multer({ storage: diskStorage({ filename: (req, file, cb) => cb(null, file.originalname) }) })` — original name used, path traversal possible
- **SAFE**: Extension whitelist in fileFilter:
  ```js
  const ALLOWED = ['.jpg', '.png', '.gif'];
  const ext = path.extname(file.originalname).toLowerCase();
  cb(null, ALLOWED.includes(ext));
  ```

### Formidable / busboy
- **VULN**: File saved with original name without extension validation
- **VULN**: Upload path constructed from user-controlled filename segment

---

## Go Source Detection Rules

```go
// VULNERABLE: no extension check, stored in static directory
func uploadHandler(w http.ResponseWriter, r *http.Request) {
    file, header, _ := r.FormFile("file")
    defer file.Close()
    dst, _ := os.Create("static/uploads/" + header.Filename)
    io.Copy(dst, file)
}

// SECURE: allowlist + UUID rename + outside web root
var allowed = map[string]bool{"jpg": true, "jpeg": true, "png": true, "gif": true}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
    file, header, _ := r.FormFile("file")
    defer file.Close()
    ext := strings.ToLower(filepath.Ext(header.Filename))
    if ext == "" || !allowed[ext[1:]] {
        http.Error(w, "invalid extension", http.StatusBadRequest)
        return
    }
    stored := "/var/uploads/" + uuid.New().String() + ext
    dst, _ := os.Create(stored)
    io.Copy(dst, file)
}
```

---

## Ruby / Rails Source Detection Rules

```ruby
# VULNERABLE: no validation, stored in public/
def upload
  file = params[:file]
  File.open(Rails.root.join('public', 'uploads', file.original_filename), 'wb') do |f|
    f.write(file.read)
  end
end

# SECURE: CarrierWave with extension allowlist
class AvatarUploader < CarrierWave::Uploader::Base
  def extension_allowlist
    %w[jpg jpeg png gif]
  end
end
# Note: ActiveStorage content_type is user-supplied in some configs — validate extension too
```

---

## PHP Source Detection Rules

### Basic upload
- **VULN**: `move_uploaded_file($_FILES['file']['tmp_name'], $uploadDir . $_FILES['file']['name'])` — original name, no validation
- **VULN**: Only MIME type check: `if ($_FILES['file']['type'] == 'image/jpeg')` — easily spoofed
- **VULN**: Extension check via `$_FILES['file']['type']` (client-supplied Content-Type)

### Extension-based checks
- **VULN**: Blacklist approach — blocks `.php` but misses `.php5`, `.phtml`, `.phar`:
  ```php
  if (pathinfo($filename, PATHINFO_EXTENSION) != 'php') { /* allow */ }
  ```
- **SAFE**: Whitelist approach:
  ```php
  $allowed = ['jpg', 'jpeg', 'png', 'gif'];
  $ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
  if (!in_array($ext, $allowed)) { die('Invalid file type'); }
  ```

### Path traversal
- **VULN**: `$uploadDir . $_FILES['file']['name']` — filename could contain `../`
- **SAFE**: `basename($_FILES['file']['name'])` — strips directory components

### Dangerous extensions to flag

**Server-side scripts**: `.php`, `.php3`, `.php4`, `.php5`, `.phtml`, `.phar`, `.py`, `.rb`, `.pl`, `.sh`, `.cgi`, `.asp`, `.aspx`, `.jsp`, `.jspx`, `.jspf`

**Apache config override**: `.htaccess` (AddHandler/AddType), `.user.ini` (`auto_prepend_file` / `auto_append_file` on PHP-FPM/CGI)

**IIS handler/config**: `.asa`, `.asax`, `.cer`, `.cdx`, `.config` (`web.config`), `.ashx`, `.asmx`

## Java / Spring Source Detection Rules

```java
// VULNERABLE: Spring MultipartFile with no extension validation
@PostMapping("/upload")
public ResponseEntity<?> upload(@RequestParam("file") MultipartFile file) {
    String filename = file.getOriginalFilename();
    Path dest = Paths.get(UPLOAD_DIR).resolve(filename);  // no extension check, path traversal possible
    file.transferTo(dest.toFile());
}
// Risk: upload .jsp → deploy to webroot → RCE if directory is served by Tomcat

// VULNERABLE: only MIME/Content-Type check (client-controlled)
if (file.getContentType().startsWith("image/")) {
    file.transferTo(new File(UPLOAD_DIR + filename));  // MIME easily spoofed
}

// VULNERABLE: no content-type validation at all
@PostMapping("/avatar")
public String uploadAvatar(@RequestParam MultipartFile avatar, Principal principal) {
    String path = AVATAR_DIR + principal.getName() + "_" + avatar.getOriginalFilename();
    avatar.transferTo(new File(path));  // .jsp / .jspx → RCE if within webroot
}

// SAFE: extension whitelist + randomized filename
private static final Set<String> ALLOWED = Set.of("jpg","jpeg","png","gif","pdf");
String ext = StringUtils.getFilenameExtension(file.getOriginalFilename()).toLowerCase();
if (!ALLOWED.contains(ext)) throw new IllegalArgumentException("Invalid file type");
String safeFilename = UUID.randomUUID() + "." + ext;
file.transferTo(Paths.get(UPLOAD_DIR, safeFilename).toFile());
```

### JSP/JSPX Upload → RCE Chain

**VULN condition**:
1. Application accepts `.jsp`, `.jspx`, or no extension filter
2. Upload directory is within Tomcat/Jetty webroot OR accessible via URL
3. Uploaded file served/executed by the servlet container

```java
// HIGH RISK: upload dir inside webroot
String UPLOAD_DIR = request.getServletContext().getRealPath("/uploads/");
// Any .jsp uploaded here is executable via HTTP request
```

### WAR/JAR Auto-Deploy

```java
// VULNERABLE: user can upload to Tomcat autodeploy directory
String deployPath = System.getProperty("catalina.home") + "/webapps/" + file.getOriginalFilename();
file.transferTo(new File(deployPath));
// .war file uploaded → Tomcat auto-deploys it → RCE

// VULNERABLE: ZIP extraction to webroot (Zip Slip → JSP drop)
ZipInputStream zis = new ZipInputStream(file.getInputStream());
ZipEntry entry;
while ((entry = zis.getNextEntry()) != null) {
    String entryPath = WEBROOT + entry.getName();  // no canonicalization → ../webapps/ROOT/shell.jsp
    // write to entryPath
}
```

## PHP Extension Bypass Patterns

### Double Extension and Alternative PHP Extensions

```php
// VULNERABLE: blacklist missing alternative PHP extensions
$blacklist = ['php'];
$ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
if (!in_array($ext, $blacklist)) {
    move_uploaded_file($_FILES['file']['tmp_name'], UPLOAD_DIR . $_FILES['file']['name']);
}
// Bypasses: .php5, .php7, .phtml, .phar, .PHP (case bypass if no strtolower), .php.jpg (Apache AddHandler)

// Executable extensions in Apache/Nginx context:
// .php, .php3, .php4, .php5, .php7, .phtml, .phar
// .asp, .aspx, .asa, .ashx (IIS)
// .jsp, .jspx, .jspf (Java EE)
// .pl, .cgi (Perl/CGI)

// SAFE: whitelist approach
$allowed = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'docx'];
$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, $allowed, true)) { die('Rejected'); }
```

### .htaccess / .user.ini Upload → RCE

```php
// VULNERABLE: allows .htaccess file upload in Apache environments
// Attacker uploads .htaccess containing:
//   AddType application/x-httpd-php .jpg
// Then any .jpg file in that directory is executed as PHP

// VULNERABLE: .user.ini upload on PHP-FPM/CGI (per-directory INI override)
// Attacker uploads .user.ini containing:
//   auto_prepend_file=evil.jpg
// Then any request in that directory prepends/executes evil.jpg as PHP

// VULN indicator: .htaccess / .user.ini not in the blocked extensions list
$blocked = ['php', 'exe', 'sh'];  // Missing .htaccess, .user.ini → bypass
```

## ASP.NET / IIS Source Detection Rules

```csharp
// VULNERABLE: no extension validation in ASP.NET upload
[HttpPost]
public IActionResult Upload(IFormFile file) {
    var path = Path.Combine(uploadDir, file.FileName);  // .aspx, .ashx, .config upload possible
    using var stream = System.IO.File.Create(path);
    file.CopyTo(stream);
    return Ok();
}

// VULNERABLE: only MIME type check
if (file.ContentType.StartsWith("image/")) { /* save file */ }
// ContentType is client-controlled header — easily spoofed

// DANGEROUS: .aspx upload → IIS executes as ASP.NET handler
// DANGEROUS: web.config upload → overrides application config (potential auth bypass / RCE)

// SAFE: extension whitelist + randomized name + store outside webroot
var allowedExt = new HashSet<string> { ".jpg", ".jpeg", ".png", ".gif", ".pdf" };
var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
if (!allowedExt.Contains(ext)) return BadRequest("Invalid file type");
var safeName = Guid.NewGuid() + ext;
var uploadPath = Path.Combine(storageDir, safeName);  // storageDir outside wwwroot
```

### ASP.NET Dangerous Extensions

`.aspx`, `.ascx`, `.ashx`, `.asmx`, `.asax`, `.cer`, `.cdx`, `.config` (`web.config`), `.cs`, `.vb`

A blacklist missing any of these allows IIS handler execution.

## Java TRUE POSITIVE Rules

- `MultipartFile.transferTo(new File(UPLOAD_DIR + file.getOriginalFilename()))` with no extension check → **CONFIRM** (arbitrary file write, potential RCE if JSP)
- Upload directory within `getServletContext().getRealPath("/")` or webroot subdirectory + no extension filter → **CONFIRM** (JSP execution risk)
- `ZipInputStream` extraction with entry path not canonicalized → **CONFIRM** (Zip Slip)
- WAR/JAR extraction to Tomcat `webapps/` directory → **CONFIRM** (auto-deploy RCE)
- If code derives `suffix` from `file.getOriginalFilename()`, saves with `transferTo(...)`, and the same project exposes that directory through `/file/**`, `ResourceHandlerRegistry`, a `file:` static mapping, or a returned public URL, CONFIRM `arbitrary_file_upload` even when the stored filename is timestamp-randomized.

## Java FALSE POSITIVE Rules

- Extension whitelist enforced + filename randomized + stored outside webroot → **SAFE**
- Files stored in object storage (S3, GCS) never served directly by the app server → lower risk (no server-side execution, but content-type sniffing risk remains)
- Content served through a download endpoint that sets `Content-Disposition: attachment` → reduces XSS risk but not server-side execution risk
- FALSE POSITIVE guard: profile-image upload is not `arbitrary_file_upload` unless attacker-controlled file type, path, or execution context can escape image-only constraints or reach a web-executable location.

## Additional FALSE POSITIVE Rules

- Do NOT emit `arbitrary_file_upload` for profile image/avatar upload endpoints that restrict to image types (jpg/png/gif) AND store files outside the webroot or in object storage — the risk is minimal and better categorized as a defense-in-depth gap.
- Do NOT emit when file type validation (extension whitelist + content-type check + magic byte validation) is present, even if not perfect — flag as LIKELY only if a specific bypass is demonstrable.
- Do NOT emit for file write operations that are not uploads (e.g., logging, temp files, cache writes) — these should be tagged as `path_traversal` if applicable.

## Polyglot / Magic-Byte-Only Validation

**VULN condition**: extension allowlist passes, but validation stops at Content-Type header or magic-byte sniff (`magic.from_buffer`, `filetype.guess`, `getimagesize`) with no decode-and-re-encode step. Attacker embeds executable payload in metadata/comments/polyglot structure while preserving valid leading bytes (e.g., JPEG SOI + PHP in EXIF comment, GIF header + script in trailer).

```python
# VULN: magic-byte check only — embedded script survives
header = file.read(2048)
if header.startswith(b'\xff\xd8\xff'):  # looks like JPEG
    file.save(path)  # PHP in EXIF/comment still present

# SAFE: re-encode strips non-image payload (defense in depth — still require allowlist)
from PIL import Image
img = Image.open(file)
img.save(path, format='JPEG')  # drops foreign bytes/comments
```

**Grep seeds**: `magic\.from_buffer`, `getimagesize`, `filetype\.guess`, `mimetype`/`content_type` check with no `Image\.open.*save` / `sharp\(` / `convert` re-encode downstream.

## Null-Byte and Extension Parsing Weaknesses

**VULN patterns** — naive extension extraction from the original filename:

```python
# VULN: last segment only — shell.php.jpg passes allowlist {'jpg'}
ext = filename.split('.')[-1].lower()

# VULN: first segment only — shell.jpg.php passes allowlist {'jpg'}
ext = filename.split('.')[1].lower()

# VULN: null-byte truncation (legacy stacks) — shell.php%00.jpg stored/executed as .php
name = filename.replace('\x00', '')  # too late if path already built
```

```php
// VULN: pathinfo on unsanitized name — file.jpg.php vs file.php.jpg order matters
$ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
// Bypass: shell.php.jpg (Apache may execute leftmost .php); shell.jpg.php (allowlist sees jpg)
```

**SAFE**: `rsplit('.', 1)` on basename only; reject filenames containing `%00`, `\x00`, or multiple `.` when policy is single-extension; server-generated stored name; `secure_filename()` / `basename()` before any extension logic.

## Post-Upload Media Processing Chain (SSRF / RCE)

After save, many apps pass the stored path or a signed URL into image/PDF/video pipelines. The **uploaded file path** becomes input to subprocesses or libraries that fetch, transcode, or render — a second-stage sink beyond web execution.

**VULN condition**: user-controlled upload reaches `convert`, `ffmpeg`, ImageMagick, `sharp`, `libvips`, headless screenshot/PDF renderers, or thumbnail workers without sandboxing the path and without blocking remote schemes in nested fetches.

| Stack | Grep seeds (trace from `file.save` / `transferTo` / `move_uploaded_file`) |
|-------|---------------------------------------------------------------------------|
| Shell | `convert\s`, `ffmpeg\s`, `magick\s`, `gm convert`, `exiftool\s`, `wkhtmltopdf`, `puppeteer`, `playwright` |
| Node.js | `sharp\(`, `ffmpeg-static`, `fluent-ffmpeg`, `gm\(`, `jimp\.`, `pdf-lib`, `puppeteer\.launch` |
| Python | `subprocess.*convert`, `Wand\(`, `ffmpeg\.`, `pdf2image`, `imgkit`, `weasyprint` |
| Java | `ProcessBuilder.*ffmpeg`, `ImageIO\.read`, `Thumbnailator`, `PDFBox`, `GraphicsMagick` |

```javascript
// VULN: transcode attacker-controlled path — ImageMagick/FFmpeg CVE-class gadget chains
sharp(uploadedFile.path).resize(200).toFile(thumbPath);
exec(`ffmpeg -i ${uploadedFile.path} -f mp4 ${outPath}`);

// VULN: URL passed to renderer after upload — nested SSRF (see ssrf.md)
await page.goto(signedUrlFor(uploadedFile.path));
```

Tag secondary impact as `ssrf` or RCE when the processing chain invokes network/file handlers on attacker content; cross-ref `ssrf.md` for URL-fetch variants of the same pipeline.

## SVG Upload — Server-Side Processing (XSS / SSRF / XXE)

SVG is XML. When uploads are stored and **rendered, thumbnailed, sanitized server-side, or inlined** in responses, the file content — not just the extension — matters.

**VULN surfaces**:
- Inline `<script>`, event handlers (`onload`), `foreignObject` → stored/reflected XSS when SVG served as `image/svg+xml` without CSP; see `xss.md`
- `xlink:href="http://169.254.169.254/..."` or external `<image href="...">` → SSRF when server-side renderer fetches resources; see `ssrf.md`
- `<!DOCTYPE>` / external entities / XInclude in SVG → XXE when parsed by XML-aware pipelines; see `xxe.md`

```xml
<!-- VULN payload shapes in uploaded SVG -->
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <script>alert(document.domain)</script>
  <image xlink:href="http://127.0.0.1:6379/"/>
</svg>
```

**Grep seeds**: `image/svg`, `\.svg`, `dangerouslyAllowSVG`, SVG sanitizer bypass, `lxml.*svg`, `Batik`, `rsvg-convert`, `ImageMagick.*svg`.

**SAFE**: reject SVG uploads; or rasterize server-side to PNG/JPEG with no script/XML retention; serve downloads as `Content-Disposition: attachment`; never inline user SVG in HTML.

## Dynamic Test / PoC

Confirm with a minimal runtime probe; pair with static analysis of validation and storage path.

**Direct webshell upload (no validation)**

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
curl -X POST "https://app.example.com/upload" -F "file=@shell.php"
curl -s "https://app.example.com/static/uploads/shell.php?cmd=id"
# Signal: command output in response body (200 + uid/gid text)
```

**Content-Type / MIME bypass**

```bash
curl -X POST "https://app.example.com/upload" \
  -F "file=@shell.php;type=image/png"
# Signal: file saved despite non-image content; then request stored URL for execution
```

**Blocklist / alternate extension bypass**

```bash
curl -X POST "https://app.example.com/upload" -F "file=@shell.phtml"
# Signal: 200 on upload + executable response when accessing stored path (try .phtml, .phar, .php5, .PHP)
```

**Path traversal in filename**

```bash
curl -X POST "https://app.example.com/upload" \
  -F "file=@shell.php;filename=../../webroot/shell.php"
# Signal: file appears outside intended upload dir and is web-accessible
```
