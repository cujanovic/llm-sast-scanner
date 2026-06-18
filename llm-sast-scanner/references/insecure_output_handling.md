---
name: insecure_output_handling
description: Insecure handling of LLM/model output — treating model-generated text as trusted and passing it to HTML, SQL, shell, file, or HTTP sinks (OWASP LLM05, CWE-79/89/78/918)
---

# Insecure Output Handling (LLM05)

LLM output is attacker-influenceable: a user prompt (or injected/retrieved content) can steer the model into producing markup, SQL, shell commands, URLs, or file paths. When application code consumes that output as if it were trusted, the model becomes a *second-order source* feeding a classic injection sink. Static analysis traces **model response → downstream sink** the same way it traces user input → sink.

The core pattern: *text returned from an LLM/agent call reaches an HTML, SQL, OS-command, file-system, HTTP-client, `eval`, or deserialization sink without context-aware encoding, parameterization, or an allowlist.*

## What It Is (and Is Not)

**What it IS**
- Rendering a model response into the DOM/HTML via `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, template `| safe`, `render_template_string`, etc.
- Executing model-generated SQL directly, or interpolating model output into a query string
- Passing model output to `subprocess`/`exec`/`system` (especially with `shell=True`) or to `eval`/`Function`/`vm.runInContext`
- Using a model-provided URL in a server-side HTTP client (SSRF) or redirect
- Writing to a file path or executing a tool argument derived from model output without canonicalization/allowlist
- Deserializing model output (`pickle`, `yaml.load`, `JSON.parse`→`eval`) into live objects

**What it is NOT**
- The *prompt-side* injection that influences the model — that is `prompt_injection.md` (this file is the *output/egress* side; they often chain)
- Plain user-input-to-sink with no LLM in the path — use the specific class (`xss.md`, `sql_injection.md`, `rce.md`, `ssrf.md`)
- Model output displayed as inert plain text (`textContent`, auto-escaped template variable) with no downstream parsing
- Tool-call routing where the framework enforces a typed schema and the value never reaches a raw sink

## Source -> Sink Pattern

**Sources (model output / egress)**
- Chat/completion responses: `openai.*.create(...).choices[].message.content`, `client.messages.create(...).content`, `model.generate_content(...)`, `llm.invoke(...)`, `chain.run(...)`, `agent.run(...)`, `.predict(...)`, `ChatCompletion`, `generate(...)`
- LangChain / LlamaIndex / Semantic Kernel outputs, streaming deltas, tool/function-call `arguments`
- Any variable assigned from the above, or fields parsed out of it

**Sinks** — same as the underlying class: HTML render, SQL/NoSQL exec, OS command, `eval`/code-exec, HTTP client, redirect, file path, deserializer, template engine.

**Sanitizers / barriers**
- Context-aware output encoding (HTML entity encode, `textContent`, framework auto-escape, DOMPurify with a strict allowlist)
- Parameterized queries / prepared statements — never model-built SQL strings
- Structured extraction: have the model emit JSON fields validated against an allowlist, then build the action in code (never execute raw model text)
- `shell=False` + fixed argv; command/tool allowlists keyed by name, not free text
- URL allowlist + private-range/redirect blocking before any fetch (see `ssrf.md`)

## Recon Indicators

| Signal | Grep / structural targets |
|--------|----------------------------|
| Model call assigned to a var | `\.choices\[0\]\.message\.content`, `\.messages\.create`, `generate_content`, `llm\.invoke`, `chain\.run`, `agent\.run`, `\.predict\(`, `ChatCompletion`, `completion\.create` |
| Output → HTML | model-output var flowing to `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `render_template_string`, `\|\s*safe`, `Markup\(` |
| Output → SQL | model var concatenated/interpolated into `execute(`, `query(`, `.raw(`, f-string SQL |
| Output → shell/code | model var into `subprocess`, `os\.system`, `exec\(`, `eval\(`, `Function\(`, `child_process`, `vm\.` |
| Output → HTTP/redirect | model var into `requests\.get`, `fetch(`, `axios`, `httpx`, `redirect(`, `Location` header |
| "LLM writes SQL/cmd" prompts | prompts containing `Generate SQL`, `write a shell command`, `return the URL`, then executing the result |

## Vulnerable Conditions

- Model response injected into a page without encoding (stored/reflected XSS via AI output).
- Application asks the model to "generate SQL" / "generate a command" and runs it verbatim.
- Model output used as an HTTP target, redirect destination, or file path with no allowlist.
- Function/tool-calling handler trusts `arguments` JSON and forwards fields to a raw sink without schema validation.
- Markdown/HTML from the model rendered with an `img`/`a`/`script` allowlist that permits `javascript:`/`onerror`/data-URIs.

## Safe Patterns

```javascript
// SAFE — render model output as inert text, or sanitize with a strict allowlist
output.textContent = response;                       // no HTML parsing
// or:
import DOMPurify from 'dompurify';
output.innerHTML = DOMPurify.sanitize(response, {
  ALLOWED_TAGS: ['p','br','strong','em','ul','ol','li'], ALLOWED_ATTR: []
});
```

```python
# SAFE — model emits structured fields; code builds the query with an allowlist + params
ALLOWED = {"products": ["id", "name", "price"]}
spec = json.loads(llm.generate(STRUCTURED_PROMPT))   # {"table","columns","filters"}
if spec["table"] not in ALLOWED or any(c not in ALLOWED[spec["table"]] for c in spec["columns"]):
    raise ValueError("disallowed query shape")
cols = ", ".join(spec["columns"])
cur.execute(f"SELECT {cols} FROM {spec['table']} WHERE id = %s", [spec["filters"]["id"]])
```

```python
# SAFE — model selects a command by name; code maps name -> fixed argv, shell=False
ALLOWED_CMDS = {"list_files": ["ls", "-la"], "disk_usage": ["df", "-h"]}
name = llm.generate(SELECT_PROMPT).strip()
if name not in ALLOWED_CMDS:
    raise ValueError("command not allowed")
subprocess.run(ALLOWED_CMDS[name], capture_output=True, text=True, shell=False, timeout=30)
```

Additional barriers: parameterized DB access; URL allowlist + private-IP/redirect blocking before fetch (see `ssrf.md`); a strict Content-Security-Policy (`script-src 'self'`, no `unsafe-inline`) to limit damage from any XSS that slips through (see `content_security_policy.md`).

## Severity & Triage

- Model output → `eval`/shell/SQL with attacker-influenceable prompt: **Critical/High** (RCE/SQLi).
- Model output → DOM HTML without sanitization: **High** (stored) / **Medium** (reflected) XSS.
- Model output → server-side fetch/redirect: **High/Medium** (SSRF/open redirect) per `ssrf.md` / `open_redirect.md`.
- Tag the downstream class as the primary impact (`xss`, `sql_injection`, `rce`, `ssrf`) and note `insecure_output_handling` as the mechanism. Chains with `prompt_injection` raise confidence that the output is attacker-controllable.

## Common False Alarms

- Output rendered with `textContent`/auto-escaped templates and never re-parsed as HTML.
- Model output logged or stored only (no executable sink) — unless later read into a sink (trace it).
- Tool-calling where the SDK enforces a typed schema and the value is used as data, not code.
- Internal batch jobs where the prompt and model are fully trusted and no external input reaches the prompt (verify there is truly no user/retrieved content upstream).

## Related: Insecure Inference-Parameter Configuration (CWE-1434)

Output trustworthiness also depends on *how the model is invoked*. Insecurely set generative inference parameters make responses less predictable and easier to steer, raising jailbreak/prompt-injection success and the chance that unsafe text reaches a sink.

**Recon / signals**
- High or unbounded sampling for security-sensitive flows (auth/eligibility decisions, content moderation, code/command generation): `temperature` near or above `1.0`, wide-open `top_p`/`top_k`, where deterministic output is required.
- Disabled or downgraded safety/guardrails: `safety_settings=...BLOCK_NONE`, `moderation` off, content filters turned off.
- Missing output caps that become unbounded consumption: no `max_tokens` / `max_output_tokens` (cost/DoS — see `denial_of_service.md`).
- Non-reproducible security checks: no fixed `seed` where a deterministic verdict is expected.

**Safe pattern** — for security-relevant decisions use low/zero `temperature`, constrained `top_p`/`top_k`, an explicit `max_tokens`, and keep provider safety filters enabled; still treat the result as data and validate it against an allowlist before any sink.

Tag impact by the sink the unsafe output reaches; this chains with `prompt_injection.md` (weaker sampling → higher injection success) and `denial_of_service.md` (missing token caps).

## References

- OWASP LLM05:2025 Improper Output Handling
- CWE-79 (XSS), CWE-89 (SQLi), CWE-78 (Command Injection), CWE-918 (SSRF), CWE-94 (Code Injection)
- CWE-1434 (Insecure Setting of Generative AI/ML Model Inference Parameters)
- Related: `prompt_injection.md`, `xss.md`, `sql_injection.md`, `rce.md`, `ssrf.md`, `content_security_policy.md`, `denial_of_service.md`
