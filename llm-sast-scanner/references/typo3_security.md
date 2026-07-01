---
name: typo3_security
description: TYPO3 CMS security — Fluid template-engine escape-bypass XSS and template injection (f:format.raw/html/htmlentitiesDecode, $escapeOutput=false, f:render partial/section, f:cObject typoscriptObjectPath), TypoScript config-as-code RCE and injection (userFunc/preUserFunc/postUserFunc, stdWrap.insertData, data = GP:, typolink), TYPO3 superglobal taint sources (GeneralUtility::_GP/_GET/_POST), Doctrine-DBAL QueryBuilder->quote() SQLi, Extbase property-mapping mass assignment (allowAllProperties / __trustedProperties bypass / #[IgnoreValidation]), and FAL/FILE_DENY_PATTERN upload bypass (CWE-79/89/94/434/915). Load when a TYPO3 project is present (composer typo3/cms-core, ext_emconf.php, *.typoscript / setup.typoscript / constants.typoscript, Configuration/TCA/, Resources/Private/Templates/*.html with `xmlns:f`).
---

# TYPO3 Security (Fluid / TypoScript / Extbase)

TYPO3 is a PHP CMS whose attack surface is **not** visible to generic PHP/XSS/SSTI/SQLi rules: it routes output through the **Fluid** template engine (auto-escaping, with named opt-outs) and is configured by **TypoScript**, a configuration-as-code language that can execute PHP. Taint engines keyed on `$_GET`/`$_POST` literals miss TYPO3's wrapper accessors entirely. Treat Fluid `.html` templates, `*.typoscript`/`setup.txt`, `Configuration/TCA/`, and Extbase controllers as in-scope source files.

This file is the TYPO3-specific layer; the underlying classes live in `xss.md`, `ssti.md`, `rce.md`, `sql_injection.md`, `mass_assignment.md`, `arbitrary_file_upload.md`, `open_redirect.md`, and `ssrf.md` — cross-reference them for the generic analysis and severity model.

## Taint Sources (TYPO3 superglobal wrappers)

A scanner that only recognizes `$_GET`/`$_POST`/`$_REQUEST` will treat these as clean and lose the entire TYPO3 source set:

- `\TYPO3\CMS\Core\Utility\GeneralUtility::_GP('x')` — merged GET+POST (the most common source)
- `GeneralUtility::_GET(...)`, `GeneralUtility::_POST(...)`, `GeneralUtility::getIndpEnv('...')` (e.g. `HTTP_HOST`, `TYPO3_SITE_URL`)
- PSR-7 `$request->getQueryParams()`, `->getParsedBody()`, `->getUploadedFiles()` in middlewares/controllers
- In **TypoScript**: `GP:`, `TSFE:fe_user|...`, `getenv:`, `page:`, `field:` data accessors (see below)

## Fluid XSS — escape-bypass family

Fluid **auto-escapes `{variable}` output by default**, so the vulnerability is a *named opt-out* of that escaping on a value that traces to a source. Flag (cross-ref `xss.md`):

- `{var -> f:format.raw()}` / `<f:format.raw>{var}</f:format.raw>` — emits raw, no escaping. The canonical Fluid XSS sink.
- `{var -> f:format.htmlentitiesDecode()}` — *removes* escaping (often chained before `f:format.raw`).
- `<f:format.html>{var}</f:format.html>` — safe **only** when routed through TYPO3's `htmlSanitizer` (`lib.parseFunc_RTE`); on older cores / misconfig it is an XSS sink. Version-gated (the `htmlSanitizer` hardening landed in a recent core release). Treat as VULN unless a trusted `parseFunc` config is in scope.
- Custom ViewHelper class with `protected $escapeOutput = false;` and/or `protected $escapeChildren = false;` — silently disables auto-escape for that ViewHelper at the class level.
- `{var}` placed inside a JS/attribute context (`onclick="...{var}..."`, inside `<script>`) — HTML auto-escape ≠ JS/attribute escape (generic XSS, but Fluid's auto-escape lulls reviewers).

**Safe**: rely on default `{var}` HTML escaping; never `f:format.raw`/`htmlentitiesDecode` on user-influenced data; `f:format.html` only with a vetted `parseFunc`/`htmlSanitizer` config.

## Fluid SSTI / template injection

The template *name* or a TypoScript path resolved from a variable lets an attacker pick which template/TypoScript runs (cross-ref `ssti.md`):

- `<f:render partial="{var}" />` / `<f:render section="{var}" />` — partial/section name from a variable resolves against `partialRootPaths`; attacker-controlled name = template injection.
- `<f:render ... arguments="{_all}" />` — passes the entire variable scope to the partial (info over-share).
- `<f:cObject typoscriptObjectPath="{var}" />` — **Fluid→TypoScript bridge**: an attacker-controlled path can reach a `USER`/`userFunc` object → PHP execution.

## TypoScript — config-as-code RCE and injection

TypoScript is parsed and executed server-side; generic SAST does not scan it. Sources are `*.typoscript` / `setup.typoscript` / `constants.typoscript` / `Configuration/TypoScript/`, and `Configuration/TCA/*.php`.

- **RCE — `userFunc` family**: `userFunc = Vendor\Ext\Class->method`, `stdWrap.preUserFunc = ...`, `postUserFunc = ...`, `USER`/`USER_INT` objects, and `'userFunc' => ...` keys in **TCA**/Services config — execute arbitrary PHP. If any part of the callable string (or its resolution) is influenced by config an attacker can edit, it is RCE (cross-ref `rce.md`).
- **Second-order marker injection — `stdWrap.insertData = 1`**: re-parses the rendered string and expands `{GP:x}`, `{TSFE:...}`, `{getenv:...}`, `{page:...}` markers. A value containing user input that is later re-parsed with `insertData` leaks server data / injects content. Uniquely TYPO3.
- **XSS via raw `data = GP:`**: `lib.x.data = GP:q` (or `field:`, `TSFE:fe_user|...`) emitted **without** `stdWrap.htmlSpecialChars = 1` is reflected XSS straight from config.
- **Open redirect / SSRF — `typolink`**: `typolink { parameter.data = GP:to; forceAbsoluteUrl = 1 }` / `additionalParams.data = GP:` — the `LinkService` `ExternalLinkHandler` does no host allowlist (cross-ref `open_redirect.md`, `ssrf.md`). `ATagParams.data = GP:` injects attributes (`onclick=...`) → stored XSS.
- **Footgun config committed to the repo**: `config.no_cache = 1` (DoS — disables caching) and `config.debug = 1` (verbose error/info disclosure).

## SQL Injection — Doctrine-DBAL QueryBuilder

TYPO3's `QueryBuilder` (Doctrine DBAL) has a **counterintuitive** sink:

- **VULN**: `$qb->where('uid = ' . $qb->quote($userId))` — `quote()` *looks* safe but is the flagged sink (it is escaping, not a bound parameter; and is wrong/insufficient when the value lands outside a quoted literal, e.g. an identifier or `IN()` position).
- **SAFE**: `$qb->where($qb->expr()->eq('uid', $qb->createNamedParameter($userId, \PDO::PARAM_INT)))` / `createPositionalParameter()`. Also flag raw `$connection->executeQuery($sql . $input)` and legacy `$GLOBALS['TYPO3_DB']->exec_SELECTquery(... . $input)`.

## Mass assignment / validation bypass — Extbase

- `->getPropertyMappingConfiguration()->allowAllProperties()` (or `setTypeConverterOption(..., PersistentObjectConverter::CONFIGURATION_CREATION_ALLOWED, true)`) — defeats Extbase's HMAC-signed `__trustedProperties`, letting a request bind arbitrary domain-object properties (cross-ref `mass_assignment.md`).
- `#[IgnoreValidation(['value' => 'newUser'])]` / `@TYPO3\CMS\Extbase\Annotation\IgnoreValidation` on a `create`/`update`/`delete` action — skips all validators for that argument.

## File upload — FAL / FILE_DENY_PATTERN bypass

- Direct `move_uploaded_file($_FILES['f']['tmp_name'], 'fileadmin/' . $name)` (or writing into `fileadmin/`/`uploads/` outside FAL) bypasses the **File Abstraction Layer** and `FileNameValidator`. TYPO3's `FILE_DENY_PATTERN_DEFAULT` blocks `.php`/`.phar`/`.phtml`/`.pht`/`.htaccess` **but not** `.pl`/`.asp`/`.aspx`/`.cer`/`.svg`/`.html` — flag uploads whose validation relies on the deny pattern alone (cross-ref `arbitrary_file_upload.md`).
- Unauthenticated **`eID`** / AJAX entry points (`Configuration/...`/`ext_localconf.php` `$GLOBALS['TYPO3_CONF_VARS']['FE']['eID_include']`) that read `_GP` and reach a sink without a BE/FE user check — a classic TYPO3 unauth surface.

## Recon Indicators (grep)

```bash
rg -n "GeneralUtility::_(GP|GET|POST)\(" --glob '*.php'
rg -n "f:format\.(raw|html|htmlentitiesDecode)|escapeOutput\s*=\s*false|escapeChildren\s*=\s*false" --glob '*.html'
rg -n "f:render\s+(partial|section)=\"\{|f:cObject\s+typoscriptObjectPath=\"\{" --glob '*.html'
rg -n "userFunc\s*=|preUserFunc\s*=|postUserFunc\s*=|insertData\s*=\s*1|data\s*=\s*GP:|typolink|ATagParams\.data\s*=\s*GP:|config\.(no_cache|debug)\s*=\s*1" --glob '*.{typoscript,txt,ts}'
rg -n "->quote\(|exec_SELECTquery|executeQuery\(" --glob '*.php'
rg -n "allowAllProperties\(|IgnoreValidation|CONFIGURATION_CREATION_ALLOWED" --glob '*.php'
rg -n "eID_include|move_uploaded_file\(.*(fileadmin|uploads)" --glob '*.php'
```

## Common False Alarms

- `{var}` with default Fluid escaping (no `f:format.raw`/`htmlentitiesDecode`) — auto-escaped, not XSS.
- `f:format.html` **with** a trusted `lib.parseFunc_RTE` / `htmlSanitizer` config on a current core — sanitized.
- `userFunc`/`typolink`/`insertData` whose data is a fixed literal or non-user constant — not attacker-controlled.
- `QueryBuilder` using `createNamedParameter()`/`createPositionalParameter()` or restricted Extbase repository query methods (`findBy*`) — parameterized.
- `_GP`/`_GET` value passed through `(int)`/`MathUtility::canBeInterpretedAsInteger()`/an allowlist before the sink.

## Core Principle

In TYPO3 the dangerous surface is the **template engine and the config language**, not just PHP. Fluid is safe by default — so every `f:format.raw`/`htmlentitiesDecode`/`$escapeOutput=false` is a deliberate escape opt-out to scrutinize; TypoScript can run PHP (`userFunc`) and re-parse markers (`insertData`), so attacker-influenced TypoScript or `GP:` data is code/markup execution; and `GeneralUtility::_GP` is the real taint source a `$_GET`-only engine never sees.
