---
name: email_parser_differential
description: Email validation-vs-parsing differential — app validates with regex or split('@') but the mail-sending library parses encoded-words, comments, quoted strings, multiple @, Punycode/IDN, or UUCP paths differently, so stored domain differs from delivery target; plus identity-key collisions from missing canonicalization (CWE-20 / CWE-697)
---

# Email Parser Differential (CWE-20 / CWE-697)

Applications often validate email addresses with a simple regex, a lone `@` check, or `split('@')`, then pass the **same string** to an SMTP client, transactional mailer, or cloud mail API. Mail libraries and MTAs parse RFC 5322/5321 syntax more permissively: encoded-words (`=?utf-8?...?=`), parenthetical comments, quoted local parts, multiple `@` signs, Punycode/IDN domains, UUCP/bang paths, and embedded control characters (`NUL`, `CRLF`). The application may record `user@victim.com` while the mailer delivers to `attacker.com` — enabling verification-email hijack, password-reset takeover, or invite redirection. A related failure uses email as a unique identity key without canonicalization (case, `+` tags, dot semantics, Unicode confusables), producing duplicate or colliding accounts.

## What It Is / Is Not

- **Is**: validate with `EMAIL_REGEX` / `indexOf('@')` / `split('@')` then send via `mailer.send`, `sendmail`, SMTP client, SES, SendGrid, etc.; stored email used as login/verification key without normalize/canonicalize step; comparison against "verified email" uses raw string equality after different parsing paths.
- **Is not**: generic input validation on non-email fields — standard injection classes. SMTP header injection via unsanitized display names in headers — overlaps `log_injection.md` / CRLF in headers (tag separately if CRLF in subject/from is the sole issue). OAuth `email_verified` claim trust — see `oauth_oidc_misconfiguration.md`.
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

## Severity / Triage

| Condition | Typical severity |
|-----------|------------------|
| Parser differential on verification/reset/invite send | **Critical** — account takeover |
| Parser differential on marketing/low-risk mail | **Medium** |
| Missing canonicalization on unique email constraint | **High** — duplicate accounts, auth bypass |
| Unicode homograph in domain without IDNA normalize | **High** (context-dependent) |
| Regex stricter than sender ( rejects attacker input ) | **Info** — verify sender path not alternate |
| Same library parse + canonicalize + verified-only send | **FALSE POSITIVE** |

Downgrade when: one canonicalization function feeds validation, persistence, and delivery; verified-email gate on sensitive sends.

## Common False Alarms

- Validation and send both use strict `InternetAddress` / `parseaddr` with `validate()` and no raw string bypass.
- Email field rejected unless exactly one `@`, no quotes/comments, and domain is IDNA-normalized before insert.
- Marketing alias accepts `+tag` but auth uniqueness uses provider-canonicalized form consistently.
- Framework validator (Django `EmailValidator`) immediately followed by same normalized value to `send_mail` without re-reading raw request — confirm no intermediate concatenation.
- Disposable-domain blocklist only — not a differential fix; still flag if parser differential exists on verification path.

## Cross-References

- `business_logic.md` — account lifecycle, invite/verification workflow bypass, duplicate account creation.
- `oauth_oidc_misconfiguration.md` — trusting IdP `email` without `email_verified` on link/create.
- `authentication_jwt.md` — email claim in tokens used for authorization.
- `log_injection.md` — CRLF in logged email strings (orthogonal to parser differential).
- `privacy_data_protection.md` — PII handling for email in logs and exports.

## Core Principle

Email validation must use the **same canonical parser** as the mail-sending path: normalize once, store the canonical form, enforce uniqueness on that form, and perform verification, reset, and invite delivery only to **verified** canonical addresses — never assume regex or `split('@')` matches MTA behavior.
