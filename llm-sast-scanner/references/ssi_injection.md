---
name: ssi_injection
description: Server-Side Include (SSI) injection — user input reflected into pages processed by an SSI-enabled web server, allowing #exec command execution and #include/#printenv file & environment disclosure (CWE-97)
---

# Server-Side Include (SSI) Injection (CWE-97)

Server-Side Includes are directives an SSI-enabled web server (Apache `mod_include`, nginx SSI module, IIS) evaluates **before** sending a `.shtml`/`.stm`/`.shtm` (or SSI-configured) page. When attacker-controlled input is reflected into a page that the server parses for SSI, the attacker injects directives that run on the server:

- `<!--#exec cmd="id"-->` / `<!--#exec cgi="..."-->` — arbitrary command execution (→ RCE)
- `<!--#include file="/etc/passwd"-->` / `<!--#include virtual="..."-->` — arbitrary file read
- `<!--#printenv-->` — environment dump (often leaks secrets/tokens)
- `<!--#echo var="DOCUMENT_ROOT"-->` — server variable disclosure

## What It Is / Is Not

- **Is**: untrusted input written into a response (or a file later served) that the web server SSI-parses, where the SSI directive syntax is not neutralized.
- **Is not**: template-engine injection (`ssti.md`), HTML/XSS where the browser — not the server — interprets the payload (`xss.md`), or path traversal where the include target is a server-side language `include()` (`path_traversal_lfi_rfi.md`). SSI directives are interpreted by the **web server**, not the application runtime or browser.
- **Reachability precondition**: SSI must be enabled for the served file (e.g., Apache `Options +Includes`, `AddType text/html .shtml` + `AddOutputFilter INCLUDES .shtml`, `XBitHack`, or content served with SSI parsing). Without SSI enabled, the directives are inert text — downgrade accordingly.

## Source -> Sink Pattern

Taint flows from a request source to a response/file that is SSI-parsed.

- **Sources**: query/body/header/cookie params, uploaded filenames/content, stored values later rendered.
- **Sinks**: writing tainted data into an SSI-parsed response or into a `.shtml`/SSI-enabled file on disk, comment/guestbook/profile fields rendered on `.shtml` pages, error pages parsed for SSI.

## Recon Indicators (Grep)

```bash
# Pages/files that the server may SSI-parse
rg -i --glob '*.{shtml,stm,shtm,html,conf}' '<!--#\s*(exec|include|printenv|echo|config|fsize|flastmod|set)'
# Server config enabling SSI
rg -i 'Options\s+[^#\n]*\+?Includes|AddOutputFilter\s+INCLUDES|XBitHack|ssi\s+on|SSIEnable'
# User input written into .shtml or SSI-served pages (PHP example)
rg -i 'echo\s+\$_(GET|POST|REQUEST|COOKIE).*\.shtml|file_put_contents\([^)]*\.shtml[^)]*\$_(GET|POST|REQUEST)'
# Reflected input on responses that may be SSI-parsed
rg -i 'getParameter|request\.(args|form|values|GET|POST)|req\.(query|body|params)' --glob '*.{shtml,stm,jsp,php}'
```

High-signal: any path where request data lands in a `.shtml` (or SSI-`AddOutputFilter`'d) file **and** the SSI directive delimiters `<!--#` are not stripped/encoded.

## Vulnerable Conditions

- Guestbook/comment/profile/search field echoed onto an SSI-parsed page without encoding.
- User-supplied filename or content saved as/into a `.shtml` file that is later served.
- Error/404 pages that reflect the requested path and are SSI-parsed.
- Legacy CMS or static-site setups with `Options +Includes` plus user-writable served content.

## Safe Patterns

- **Disable SSI** for any directory containing user-controlled content (`Options -Includes`, no `INCLUDES` output filter); serve user content as non-parsed `.html`/`.txt` with a fixed `Content-Type`.
- **Encode the directive delimiters** before reflecting input: HTML-encode `<`, `>`, `&`, and specifically neutralize `<!--#`, `-->`. Allowlist-validate where the value has a known format.
- Never let users control the name/extension of files written under an SSI-enabled docroot; store uploads outside the web root.
- `<!--#exec-->` should be globally disabled (`Options +IncludesNOEXEC`) even where SSI is otherwise needed.

## Multi-language Notes

- **PHP / classic CGI / Perl**: most common host of legacy SSI; watch `echo`/`print` of request data onto `.shtml`.
- **Java**: servlet/JSP output written to SSI-parsed `.shtml` fronted by Apache; `request.getParameter` → `.shtml`.
- **Static generators / nginx**: nginx `ssi on;` reflecting `$arg_*`/`$http_*` into parsed responses.

## Severity / Triage

- `<!--#exec-->` reachable with SSI enabled → **Critical** (server RCE).
- `<!--#include file=...-->` / `<!--#printenv-->` reachable → **High** (file/secret disclosure).
- Reflected input on a parsed page but SSI/exec not confirmed enabled → **NEEDS CONTEXT** (cap Low until SSI config verified).

## Dynamic Test / PoC

```bash
# Probe reflection of SSI syntax (look for evaluated output, not literal echo)
curl -s "https://target/page.shtml?q=<!--%23echo%20var=%22DATE_LOCAL%22-->" | grep -i 'GMT\|UTC\|20'   # date rendered => SSI active
curl -s "https://target/search.shtml?q=<!--%23printenv-->"                 # env dump
curl -s --data 'comment=<!--%23exec%20cmd=%22id%22-->' https://target/guestbook  # then load the .shtml page
```
Confirmed when the directive is **evaluated** (date/`uid=`/env output appears) rather than echoed verbatim.

## Common False Alarms

- `<!--#...-->` strings in pages that are served as static `.html` with SSI disabled — inert text.
- Reflected input that is HTML-encoded before output (`&lt;!--#` in the response) — delimiters neutralized.
- Directives in documentation/examples, not in a live served path.

## Cross-References

- `rce.md` — SSI `#exec` is a command-execution sink; report the RCE impact.
- `path_traversal_lfi_rfi.md` — runtime `include()`/`require()` of user paths (distinct mechanism).
- `ssti.md` / `xss.md` — server template engines vs. browser-interpreted injection.
- `information_disclosure.md` — `#printenv`/`#echo var` secret and path leakage.

## Core Principle

Never reflect untrusted input into content a web server parses for Server-Side Includes, and disable SSI (especially `#exec`) for any directory holding user-controlled data.
