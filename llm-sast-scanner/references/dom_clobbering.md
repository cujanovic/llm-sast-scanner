---
name: dom_clobbering
description: DOM clobbering — attacker HTML with id/name attributes shadowing JS globals and built-in APIs, enabling logic bypass and XSS gadget chains
---

# DOM Clobbering

DOM clobbering occurs when attacker-controlled HTML injects elements whose `id` or `name` attributes become named properties on `window`, `document`, or form objects. JavaScript that reads those names expecting plain objects, booleans, or functions may receive DOM nodes or primitive coercions instead — bypassing authorization checks or feeding XSS gadgets.

*The core pattern: security-sensitive code reads an unqualified global or nested property (or a built-in DOM API) that attacker HTML can shadow via `id`/`name`, without type validation — often paired with an HTML sink that preserves those attributes.*

## What It Is (and Is Not)

**What it IS**
- **Global shadowing**: `<img id="config">` makes `window.config` (and often `document.config`) an `HTMLImageElement`; `if (config.isAdmin)` may follow prototype-chain lookups on the element instead of a real config object
- **Nested clobbering**: `<form id="config"><input name="isAdmin" value="1"></form>` exposes `window.config.isAdmin` as the input element (truthy in boolean context)
- **Multi-node clobbering**: duplicate `id` values yield an `HTMLCollection`; chained property access behaves differently than a plain object
- **Primitive coercion via `href`**: `<a id="config"><a id="config" name="isAdmin" href="true">` can make `config.isAdmin` resolve to the string `"true"` or a URL-bearing anchor — flipping expected booleans or redirect targets
- **Built-in API clobbering**: injected `name`/`id` on elements inside `document` or forms can shadow `document.getElementById`, `document.createElement`, or similar when code reads them without verifying `typeof … === 'function'`
- **Sanitizer gaps**: HTML sanitizers that strip scripts but retain `id`/`name` leave clobbering primitives in stored/reflected markup
- **Gadget chains**: clobbering alone rarely executes script; impact requires downstream code that trusts the clobbered value (auth flag, URL, callback name, sanitizer config key)

**What it is NOT**
- **Direct script injection** — no `<script>` execution required; tag `xss.md` when a clobber bypass leads to an executable sink
- **Prototype pollution** — clobbering uses named DOM property accessors, not `Object.prototype` writes; see `client_side_prototype_pollution.md`
- **Server-side HTML injection** — finding is client-side property resolution unless server emits attacker `id`/`name` into responses
- **Safe `getElementById` usage** — calling `document.getElementById('literal')` on a literal id is not clobbering; risk is *reading* `document.getElementById` (or `window.config`) as a value without validation
- **Framework auto-escaped text nodes** — escaped text cannot introduce clobbering attributes; risk starts at HTML sinks (`innerHTML`, `dangerouslySetInnerHTML`, `v-html`)

## Recon Indicators

### Clobberable JavaScript reads (grep)

| Signal | Grep / structural targets |
|--------|---------------------------|
| Implicit globals | Assignment without `var`/`let`/`const`/`function` at top level or in non-strict slopp mode: `^\s*(config\|api\|user\|admin\|settings)\s*=` |
| Window/document property reads | `window\.(config\|api\|user\|admin\|settings)\b`, `document\.(config\|getElementById\|createElement)\b` used as values (not only call targets with validation) |
| Truthy guard on clobberable name | `if\s*\(\s*(window\.)?(config\|api\|user\|admin)\.` , `if\s*\(\s*!\s*(config\|api)\.` |
| Fallback to clobberable global | `(window\.)?(config\|api\|user)\s*\|\|`, `\?\?\s*(window\.)?(config\|api)` — DOM nodes are truthy |
| Unvalidated nested access | `(config\|api\|user\|settings)\.[a-zA-Z_$]+\s*(\|\||&&|\?)` without prior `typeof` / `instanceof` guard |
| Dynamic property from DOM | `\[['"]?(isAdmin\|role\|token\|callback\|url\|src)['"]?\]` on objects that may be globals |
| Missing strict mode | files without `"use strict"` that assign/read bare identifiers |
| Sensitive data on window | `window\.(userRole\|isAdmin\|token\|apiKey)\s*=` |

### Unvalidated built-in API use

```javascript
// VULN — getElementById may be shadowed by named element
const el = document.getElementById('target');

// VULN — checks presence, not type
if (document.getElementById) { ... }
```

Grep: `document\.getElementById\s*[^(]` (property access, not invocation), `typeof\s+document\.getElementById\s*!==\s*['"]function['"]` absent near call sites.

### HTML sinks that can introduce id/name (grep)

Pair any sink below with a user-influenced source; trace whether sanitization strips `id`/`name`.

| Sink | Grep |
|------|------|
| Direct HTML assignment | `\.innerHTML\s*=`, `\.outerHTML\s*=`, `insertAdjacentHTML(`, `document\.write(` |
| Framework HTML render | `dangerouslySetInnerHTML`, `v-html`, `v-html=`, `\[innerHTML\]`, `{@html}`, `bypassSecurityTrustHtml` |
| jQuery / DOM libs | `\.html\(`, `\.append\(`, `\.prepend\(`, `\$\('<` |
| Template / partial injection | `\| safe`, `mark_safe(`, `{!!`, `<%-`, `\| raw`, `@Html\.Raw(` |
| DOM insertion | `appendChild\(`, `insertBefore\(`, `replaceChild\(` with parsed HTML fragments |
| setHTML / sanitizer API | `setHTML\(`, `createHTML\(`, `DOMPurify\.sanitize\(` |

### Sanitizer misconfiguration (grep)

```javascript
// VULN — allows clobbering attributes
DOMPurify.sanitize(input, { ALLOWED_ATTR: ['id', 'name', ...] });
DOMPurify.sanitize(input); // default may retain id/name unless configured

// VULN — named-prop protection disabled
DOMPurify.sanitize(input, { SANITIZE_NAMED_PROPS: false });
```

Grep: `FORBID_ATTR.*id`, `SANITIZE_NAMED_PROPS:\s*true`, `blockAttributes.*id`, `blockAttributes.*name` — absence of these near user HTML sanitization is a flag.

### Dynamic attribute assignment

```javascript
// VULN — user-controlled attribute name or value on id/name
element.setAttribute(userAttr, userVal);
el.id = userInput;
el.name = userInput;
```

Grep: `setAttribute\(\s*(req\.|params\.|user|input|payload)`, `\.(id|name)\s*=\s*(req\.|params\.|user|input)`.

### Test payload (static review)

Markup that should be stripped or neutralized before reaching the DOM:

```html
<a id="config"><a id="config" name="isAdmin" href="true">
<form id="api"><input name="token" value="attacker"></form>
<img name="getElementById">
```

## Vulnerable vs Secure Examples

### Implicit global read

```javascript
// VULN — bare identifier resolves via global object; clobberable
if (config.isAdmin) { showAdminPanel(); }

// SAFE — block-scoped binding; not shadowed by DOM named props
const config = { isAdmin: false };
if (config.isAdmin) { showAdminPanel(); }
```

### Window property guard

```javascript
// VULN — DOM element is truthy; nested name resolves on element
const api = window.api || { baseUrl: '/api/v1' };

// SAFE — reject DOM nodes before use
const raw = window.api;
const api = (raw && typeof raw === 'object' && !(raw instanceof Element))
  ? raw
  : { baseUrl: '/api/v1' };
```

### Built-in API shadowing

```javascript
// VULN — may invoke clobbered non-function
document.getElementById('panel');

// SAFE — verify API before call
if (typeof document.getElementById === 'function') {
  document.getElementById('panel');
}
```

### innerHTML without clobbering-safe sanitization

```javascript
// VULN — preserves id/name from user HTML
container.innerHTML = userHtml;

// SAFE — strip clobbering attributes and named props
container.innerHTML = DOMPurify.sanitize(userHtml, {
  SANITIZE_DOM: true,
  SANITIZE_NAMED_PROPS: true,
  FORBID_ATTR: ['id', 'name']
});
```

### Dynamic id/name assignment

```javascript
// VULN — attacker sets clobbering attribute
el.setAttribute(attrName, value);

// SAFE — block high-risk attribute names
const blocked = new Set(['id', 'name', 'onclick', 'onload', 'onerror']);
if (blocked.has(attrName.toLowerCase())) throw new Error('attribute not allowed');
el.setAttribute(attrName, value);
```

## Safe Patterns

**Variable discipline**
- `"use strict"` in every script module; declare config/state with `const`/`let` — never assign bare identifiers
- Avoid storing security state on `window`/`document`; keep secrets and flags in closure/module scope

**Type validation before use**
- Reject DOM nodes: `typeof x === 'object' && x !== null && !(x instanceof Element)`
- Validate functions: `typeof document.getElementById === 'function'` immediately before invocation
- Prefer `Object.prototype.hasOwnProperty.call(obj, key)` on plain config objects deserialized from JSON (not globals)

**Sanitizer configuration**
- Forbid `id` and `name` on all tags in user HTML; enable named-property sanitization when using DOMPurify
- Sanitizer API: block `id`/`name` via `blockAttributes` for every element kind
- Pair with Trusted Types for DOM sinks so only policy-produced HTML reaches `innerHTML`

**HTML handling**
- Prefer `textContent` for user strings; when HTML is required, run through a clobbering-aware sanitizer config
- Never reflect user input into static markup templates as attribute names or `id`/`name` values

```javascript
// SAFE — sanitizer policy + forbidden clobber attrs
const policy = trustedTypes.createPolicy('default', {
  createHTML: (s) => DOMPurify.sanitize(s, {
    SANITIZE_NAMED_PROPS: true,
    FORBID_ATTR: ['id', 'name']
  })
});
element.innerHTML = policy.createHTML(userHtml);
```

**Runtime detection (defense-in-depth)**
- Periodically assert critical globals are not `Element` instances: `if (window.config instanceof Element) { /* alert */ }`

## Common False Alarms

- **`const config = …` / module-scoped binding** — local bindings are not clobbered by DOM named properties; only unqualified global lookups and `window.*` reads are in scope
- **`document.getElementById('literalId')` with literal string** — standard lookup by id; not vulnerable unless the *method itself* is shadowed and invoked without `typeof` check
- **DOMPurify with `FORBID_ATTR: ['id','name']` and `SANITIZE_NAMED_PROPS: true`** — clobbering primitives removed; downgrade unless another HTML path bypasses the same policy
- **Server-rendered static ids** — hardcoded template ids (`id="nav"`) on trusted markup; not attacker-controlled unless user input reaches attribute values
- **Content Security Policy / Trusted Types alone** — mitigates some exploitation chains but does not fix clobberable logic; do not close finding on CSP presence alone when auth bypass reads remain
- **JSON API config loaded at runtime** — fetch/XHR JSON into a local variable is not clobberable unless later assigned to `window` or read via unqualified global name
