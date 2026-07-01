---
name: output_encoding
description: Inappropriate encoding for output context detection (CWE-838)
---

# Inappropriate Encoding for Output Context (CWE-838)

Using the wrong encoder for a sink context produces output that looks sanitized but is not safe for that context. Static analysis flags values that pass through one encoding API yet reach a sink requiring a different encoding — a distinct failure mode from missing encoding covered in `xss.md`.

## Source -> Sink Pattern

**Sources (mis-encoded values)**
- Return values of encoding/sanitization calls treated as `EncodedValue`: `HttpUtility.HtmlEncode`, `HtmlAttributeEncode`, `UrlEncode`, `JavaScriptStringEncode`, `WebUtility` equivalents, and user-defined methods whose names match `*(encode|saniti(s|z)e|cleanse|escape)*`
- SQL “encoding” via `String.Replace` on quote characters (e.g., escaping `"` to `""`) — modeled as an additional source because it is not valid SQL protection

**Sinks (required encoding kind)**
- **HTML expression** — `HtmlSink` nodes (response writes, `HtmlHelper.Raw`, attribute setters, literal writers, model sink `html-injection`)
- **URL expression** — `UrlRedirect` sinks (open redirects, URL construction for redirects)
- **SQL expression** — `SqlInjection` sinks (dynamic SQL concatenation)

**Flow logic**: taint from an `EncodedValue` that is **not** a valid encoder for the sink’s required context into that sink. Barriers are context-matched sanitizers only (`HtmlSanitizedExpr` for HTML, `UrlSanitizedExpr` for URL).

**Recognized barriers (C#)**: `HtmlSanitizedExpr` (HtmlEncode/HtmlAttributeEncode calls); `UrlSanitizedExpr` (UrlEncode calls); SQL sinks accept only parameters, not string encoders.

Commonly affected languages: C# (primary automated coverage); Java, JavaScript, Python, Go, and Ruby require manual review.

## Vulnerable Conditions

- `WebUtility.UrlEncode(user)` written to HTML via `Response.Write` — URL encoding does not escape `<`, `>`, `"` for HTML text nodes
- `WebUtility.HtmlEncode(user)` embedded in `Response.Redirect("?param=" + ...)` — HTML entities are not valid URL encoding; enables open-redirect / phishing chains
- `user.Replace("\"", "\"\"")` concatenated into SQL instead of parameterized queries — quote doubling is not a substitute for parameters
- Custom `SanitizeInput()` applied before an HTML sink when the method is not recognized as HTML encoding
- Remote user controls the value being encoded; wrong-context encoding combined with attacker input amplifies impact (HTML-encoded URL in redirect facilitates phishing)

## Safe Patterns

- Match encoder to sink context: `HtmlEncode` / `HtmlAttributeEncode` for HTML; `UrlEncode` for URL/query components; `SqlParameter` (not string escaping) for SQL
- Prefer framework auto-escaping (Razor `@Model.Value`, encoded template output) over manual encoding at each sink
- For redirects, validate destination against an allowlist in addition to URL encoding
- Avoid custom encode helpers; use `System.Web.HttpUtility`, `HttpServerUtility`, or `System.Net.WebUtility` APIs explicitly

## Detection behavior (C#)

Path-problem analysis merging three sub-configurations:
1. **HtmlExpr** — encoded value → HTML sink without `HtmlSanitizedExpr` barrier
2. **UrlExpr** — encoded value → URL redirect sink without `UrlSanitizedExpr` barrier
3. **SqlExpr** — quote-replacement or wrong encoder → SQL injection sink (barrier: none for string encoding; use parameters)

Alert text distinguishes kind: `"This HTML expression may include data from a possibly inappropriately encoded value"`.

## Relationship to XSS

`xss.md` covers missing or bypassed encoding across HTML/JS/CSS/URL/DOM contexts. CWE-838 is the **encoder/context mismatch** case: encoding exists but is the wrong type, so defenses appear present while the sink remains exploitable. A URL-encoded string in HTML can still break out of markup; HTML-encoded data in a redirect URL can still manipulate navigation. Report both when manual encoding is used instead of context-aware output controls.

## C# Patterns

**VULN — URL encoding for HTML output**:
```csharp
ctx.Response.Write("Hello, " + WebUtility.UrlEncode(user));
```

**SAFE — HTML encoding for HTML output**:
```csharp
ctx.Response.Write("Hello, " + WebUtility.HtmlEncode(user));
```

**VULN — HTML encoding in redirect URL**:
```csharp
ctx.Response.Redirect("?param=" + WebUtility.HtmlEncode(user));
```

**SAFE — URL encoding in redirect URL**:
```csharp
ctx.Response.Redirect("?param=" + WebUtility.UrlEncode(user));
```

**VULN — quote replacement for SQL**:
```csharp
var query = "select * from Users where Name='" + user.Replace("\"", "\"\"") + "'";
```

**SAFE — parameterized SQL**:
```csharp
var query = "select * from Users where Name=@name";
adapter.SelectCommand.Parameters.Add(new SqlParameter("name", user));
```

## Common False Alarms

- Value encoded with the **correct** API for the sink context (HtmlEncode → HTML sink; UrlEncode → redirect URL)
- SQL queries using bound parameters with no string concatenation of user data
- Numeric/boolean/guid types flowing to sinks (simple types treated as sanitized in related XSS rules, not primary CWE-838 targets)
- Low precision on user-defined `Encode*` methods — verify actual implementation before dismissing

## Business Risk

- Reflected/stored XSS when HTML metacharacters survive URL encoding in page output
- Open redirect and phishing when HTML entities appear in redirect targets
- SQL injection when quote-escaping is mistaken for parameterization
- False sense of security from “we encode everything” policies that use one encoder globally

## Core Principle

Encoding is context-specific. The encoder must match the sink’s grammar (HTML, URL, SQL, JavaScript). Wrong-context encoding is not a partial fix — it is a distinct vulnerability. See `xss.md` for sink inventory and CSP defenses; use this reference when encoding is present but misapplied.

## Analyst Notes

- Automated CWE-838 coverage is C#-only today — Java, JavaScript, Python, Go, and Ruby need manual review
- Triage alongside XSS rules for C#: XSS finds unencoded taint; this class finds **wrongly** encoded taint
- `JavaScriptStringEncode` is tracked as an encoded value — confirm target sink expects JS string encoding, not HTML
- Custom sanitizer methods matching the name heuristic become sources when reaching mismatched sinks — read the method body

## Java / JavaScript / Python

Manual equivalents:
- **VULN**: `URLEncoder.encode(input)` written to JSP/HTML without `StringEscapeUtils.escapeHtml4`
- **VULN**: `encodeURIComponent(x)` assigned to `innerHTML`
- **SAFE**: OWASP Encoder `encodeForHTML` / `encodeForJavaScript` / `encodeForURL` matched to sink
