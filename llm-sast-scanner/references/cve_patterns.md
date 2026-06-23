---
name: cve_patterns
description: Methodology for catching known-CVE classes by sink+source pattern (not version) and lifting fix-patterns to sweep for variants; generic sinks are delegated to their class references.
---

# Known CVE Pattern Detection

This reference is deliberately **not** a CVE/version list (that is SCA, not SAST — it goes stale and duplicates the class references). As a SAST aid it does two things:

1. **Methodology** — detect known-vulnerability *classes* by **sink + source pattern**, not version number, and **lift fix-patterns to sweep for variants** across the whole codebase (the general, language/library-agnostic engine).
2. **Routing** — for generic dangerous sinks, point to the class reference that already catches the pattern in every language (avoid duplicating detail here).

Detection is grounded in **sink + source pattern** — the dangerous call combined with user-controlled input — rather than version pinning, because the pattern itself carries design-level risk regardless of patch status. When a vulnerability has **no source-visible pattern** (the bug lives entirely inside a dependency and the calling code looks correct), it is an SCA concern, not a SAST one — out of scope for this skill.

## Philosophy

Rather than checking `requirements.txt` version numbers (which change), this skill flags code where:
1. A historically-vulnerable function is called.
2. With user-controlled or externally-sourced input.

Even when the library is up to date, the pattern signals an architectural risk worth reviewing.

---

## Variant Hunting / Fix-Pattern Lifting

A single confirmed vulnerability is rarely unique — the same mistake usually recurs elsewhere. After confirming one finding (or learning of a CVE), **lift the abstract pattern and sweep the whole codebase for unfixed siblings**. This raises recall far beyond the seed location.

**Two triggers**

- **Post-finding sweep** — once any finding is confirmed, generalize it to a pattern (dangerous sink + source shape + the missing guard) and search for every other call site that matches the sink/source but lacks the guard.
- **N-day fix-pattern lifting** — from a public CVE/patch diff, the *removed* code reveals the vulnerable shape and the *added* code reveals the correct guard/sanitizer. Hunt the target for call sites that still match the pre-fix shape (e.g. a dependency upgraded in one module but the same unsafe call open elsewhere, or a fix applied to one handler but not its copies).

**Method**

1. Express the seed as an invariant: *"every call to `SINK` reachable from `SOURCE` must be preceded by `GUARD`."*
2. Enumerate all call sites of `SINK` (normalize across wrappers, aliases, and re-exports — the same function is often reached via a helper).
3. Flag every site where the guard/sanitizer is absent or bypassable; confirm reachability from untrusted input per the usual source→sink rules.
4. Emit each variant as its own finding that references the seed pattern, so triage can batch them.

**Cross-reference**: combine with the per-class sink tables in the other references — those define the `SINK` set to sweep for each vulnerability class.

---

## Generic dangerous sinks → detected by class references

The sinks below are **not version-specific CVEs** — they are generic dangerous calls whose full source→sink detection (per-language sources, `SAFE` forms, bypasses) already lives in the class references. They are kept here only as a **routing breadcrumb**; do not duplicate per-call detail in this file. Apply the **Variant Hunting / Fix-Pattern Lifting** method above against the authoritative reference for each — the reference catches the pattern across every language and library, not just the example call.

| Sink / pattern (with caller-controlled input) | Authoritative reference |
|---|---|
| `yaml.load` (no `SafeLoader`), `pickle.loads`, `node-serialize` `unserialize()`, PHP `unserialize($_GET/$_POST/$_COOKIE)` | `insecure_deserialization.md`, `rce.md` |
| `eval()` / `new Function()` / PHP `eval`/`assert($…)`, Node `vm.runInNewContext`/`runInThisContext`, PHP `preg_replace('/…/e')` | `rce.md` (expression form → `expression_language_injection.md`) |
| Jinja2 `from_string(user_template)` / `Template(user_input).render()` | `ssti.md` |
| Lodash `_.merge` / `_.set` with an untrusted object | `server_side_prototype_pollution.md`, `client_side_prototype_pollution.md` |
| `requests.get(user_url, allow_redirects=True)` (redirect-follow to internal) | `ssrf.md` |
| PHP `include`/`require` of user input (RFI/LFI) | `path_traversal_lfi_rfi.md`, `php_security.md` |
| `Image.open(user_file/url)` (decompression bomb / delegate / SSRF chain) | `arbitrary_file_upload.md`, `denial_of_service.md` |

### Config/version-specific misconfig shapes (recall items)

These are framework/config shapes (not a single class sink) worth flagging in passing; each cross-refs its class home:

- **Werkzeug/Flask debugger RCE** — `app.run(debug=True)`, `FLASK_DEBUG=1`/`FLASK_ENV=development`, or `USE_DEBUGGER=True` reachable in production (the interactive console executes arbitrary code). Cross-ref `information_disclosure.md`.
- **Django `ALLOWED_HOSTS = ['*']`** — Host-header injection / cache poisoning (note: `[]` with `DEBUG=False` rejects all requests, it does NOT fall back to wildcard). Cross-ref `host_header_poisoning.md`.
- **Pillow `Image.MAX_IMAGE_PIXELS` unset** before processing remote/user images — decompression-bomb DoS. Cross-ref `denial_of_service.md`.

---

## Benchmark / tag-preservation rules

Tagging/triage rules for labeled benchmark suites — they govern which tag to preserve when several sink labels match the same sample, independent of any specific CVE:

- For `JavaSecLab` modules under `components/` (`fastjson`, `jackson`, `xstream`, `shiro`, `log4j2`), preserve project tag `component_vulnerability` when the route exists, even if the exploit primitive could also be labeled `jndi_injection` or `insecure_deserialization`.
- In `vulhub`, prefer the concrete benchmark tag exposed by the selected sample (`sql_injection`, `spel_injection`, `insecure_deserialization`, and similar) and use `component_vulnerability` only when the ground truth explicitly groups the sample by vulnerable component family rather than exploit primitive.
- In benchmark mode, when source review already confirms a dedicated project module or stable public taxonomy for the vulnerability class, preserve the exact benchmark tag in later rounds instead of re-collapsing it into a broader sink label merely because another exploit primitive also matches.
- In `verademo`, request-controlled class selection such as `Class.forName("com.veracode.verademo.commands." + ucfirst(command) + "Command")` should preserve `unsafe_reflection`, not only downstream `rce` or `privilege_escalation`.
- If untrusted input reaches `String.format(userControlledTemplate, ...)`, `printf(userControlledTemplate, ...)`, or a logger sink like `logger.info(tainted)` / `logger.error(tainted)` in a benchmark that splits those classes, preserve `format_string` or `log_injection` instead of collapsing into generic disclosure.
- FALSE POSITIVE guard: do not emit `privilege_escalation` from reflective command dispatch alone unless the code also shows a distinct role, ownership, or privilege check that the attacker can bypass.
