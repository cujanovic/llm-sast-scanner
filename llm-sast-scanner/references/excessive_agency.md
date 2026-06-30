---
name: excessive_agency
description: Excessive agency in LLM/agent systems — too much tool functionality, over-broad permissions, or autonomous high-impact actions without human approval, including self-generated/self-improving skill (code) execution loops, unattended scheduled actions, subagent privilege propagation, and messaging-gateway commands without per-sender authorization (OWASP LLM06, CWE-250/269/862)
---

# Excessive Agency (LLM06)

Excessive agency is the damage an LLM-driven system can do when it is granted more **functionality**, **permissions**, or **autonomy** than the task requires. A hallucination, a prompt injection, or a malicious input then turns into real side effects: deleting data, sending money, calling internal APIs, running shell commands. Static analysis looks at how tools/extensions are defined and wired, what credentials they run under, and whether high-impact actions execute without a human gate.

The core pattern: *a model is wired to a tool/credential/action whose blast radius exceeds the task — free-form command execution, write/delete on an admin connection, or irreversible operations performed autonomously with no confirmation, rate limit, or audit.*

## What It Is (and Is Not)

**What it IS**
- **Excessive functionality**: tools that accept free-form commands, raw SQL, arbitrary paths/URLs, or expose write/delete/exec when only read is needed
- **Excessive permissions**: the agent runs under an admin/root DB user, a wildcard cloud role, or a broadly-scoped token shared across tenants/users
- **Excessive autonomy**: irreversible/sensitive actions (send email, transfer funds, delete account, deploy, post publicly) run directly from model intent with no human-in-the-loop, no rate limit, and no audit log
- Tool surfaces that let the model pivot (a "run code" / "http request" / "file write" tool) regardless of the stated use case
- **Autonomous loops**: self-generated/self-improving skills (model-written code) executed without review, unattended scheduled/cron actions, subagents inheriting full privileges, and messaging-gateway commands run without per-sender authorization (see Autonomous Agent Loops below)

**What it is NOT**
- The injection that triggers the action — see `prompt_injection.md` (excessive agency is what makes that injection *consequential*)
- The output→sink mechanics of a single tool body — see `insecure_output_handling.md`, `rce.md`, `ssrf.md` for the concrete sink
- MCP-specific transport/metadata risks — see `mcp_security.md` (this file is broader agent-permission/autonomy design)
- Ordinary missing authZ on a human-facing endpoint — see `privilege_escalation.md`

## Source -> Sink Pattern

**Sources** — model intent / tool-call selection: `agent.run`, `tool_calls`, function-calling `arguments`, planner output, autonomous loop steps.

**Sinks (impact)** — privileged operations reachable from a tool: DB writes/deletes, money movement, email/SMS send, account/role changes, cloud API calls, file write/delete, process exec, deploy/CI triggers.

**Barriers**
- Least-functionality tools (read-only, single-purpose, typed params)
- Least-privilege credentials per tool (scoped DB user, narrow token/role, `default_transaction_read_only=on`)
- Human-in-the-loop approval gate for HIGH-risk actions; default-deny on unknown actions
- Per-user/per-action rate limits and quotas; comprehensive audit logging

## Recon Indicators

| Signal | Grep / structural targets |
|--------|----------------------------|
| Tool/agent wiring | `Tool\(`, `@tool`, `tools\s*=\s*\[`, `function_call`, `tool_calls`, `bind_tools`, `AgentExecutor`, `initialize_agent`, `create_react_agent` |
| Over-broad tool body | tool method calling `subprocess`, `os\.system`, `exec\(`, `eval\(`, `open(.*'w'`, `os\.remove`, raw `execute(`, `requests\.(get\|post)` on free-form arg |
| Admin/broad creds in agent path | `user=["']?admin`, `DB_ADMIN`, `root`, wildcard IAM (`"Action":"*"`), broadly-scoped `scope=`/`Authorization` reused for tool calls |
| Autonomous high-impact action | `send_email(`, `transfer`, `delete_account`, `refund`, `deploy`, `charge`, `payout` invoked directly from `action = llm...` with no approval/confirm branch |
| Missing gate | absence of `requires_approval`, `confirm`, `human_in_the_loop`, rate-limit, or audit-log around the above |
| Unscreened command at execution boundary | a model-chosen command reaching `subprocess.run(cmd, shell=True)` / `os.system` / `exec` with no decode + denylist + normalization step before it runs (esp. in autonomous recon/pentest agents) |

## Vulnerable Conditions

- A single tool exposes read **and** write/delete/exec; the model can choose the dangerous method.
- The agent's DB connection or cloud credential is admin/wildcard rather than scoped to the tool's job.
- High-risk actions execute the moment the model decides, with no confirmation step and no cap on frequency.
- A "general" tool (run shell / fetch URL / write file / eval) is registered "just in case," widening blast radius.
- Tool parameters are free-form strings forwarded to a sink instead of validated typed fields.
- **Data-exfiltration tool combo (the "lethal trifecta")** — a single agent scope holds **both** (a) a private/internal-data read capability *and* (b) an outbound/send channel, so any injected or hallucinated intent can read-then-send with no separate exploit. The combo is the finding even when each tool alone is "read-only" or "just HTTP". Read side: SQL/DB toolkit (`SQLDatabaseToolkit`, `create_sql_agent`, `SQLDatabase.from_uri`), vector-store retriever, file/`ReadFileTool`, internal-API/secrets tool. Send side: HTTP/browse/search (`RequestsTool`, `requests.*`/`httpx.*`/`fetch` on a free arg, web-browser, `SerpAPI`/`Tavily`/`DuckDuckGo` search) or messaging (`Gmail`/`Slack`/`Discord`/`Twilio`/`SendGrid` toolkit). **Worst when the same agent also ingests untrusted content** (RAG docs, web fetch, inbox, tool output) — that completes the trifecta (private data + untrusted input + egress) and makes prompt-injection exfil unavoidable. **Safe**: split responsibilities — one agent (or step) reads, a *separate* human-approved step sends; never combine internal-data access with an unrestricted outbound tool in one scope; egress-allowlist outbound destinations; log/alert every external send. Cross-ref `prompt_injection.md` (the injection that drives it), `rag_vector_security.md` (untrusted-content side), `ssrf.md` (the outbound side).

## Autonomous Agent Loops (self-generated skills, schedulers, subagents, gateways)

Self-improving / always-on agent architectures add autonomy surfaces beyond a single tool call. Each turns model intent (or injected intent) into durable, unattended, or cross-principal side effects.

- **Self-generated / self-improving skill (code) execution**: the agent **writes new skills/scripts from its own output — or rewrites existing ones — and executes them in later turns without human review or a sandbox**. Model output becomes persistent executable code; one injection or hallucination yields durable RCE that re-runs automatically. This is the highest-blast-radius agentic pattern. Three compounding mechanisms make it worse than a normal "run code" tool:
  - **Untrusted authoring source**: a "learn a skill" / self-improve flow authors the skill body from whatever the agent just read — a web page (`web_extract`), pasted text, or prior conversation — so indirect prompt injection in that source writes the skill. The malicious instructions are now *persisted to disk*, surviving context resets.
  - **Load-time execution via templating**: skill/prompt formats that support **inline command substitution** (e.g. a `` !`cmd` `` snippet whose stdout is spliced into the body) or **template-variable expansion** (`${VAR}`) **execute when the skill is loaded/preprocessed**, not when the agent consciously calls a tool. A persisted skill containing `` !`...` `` is therefore RCE on every load. Treat any doc/markdown/prompt template that shells out or interpolates during rendering as a code sink (cross-ref `ssti.md` and `rce.md`).
  - **Body-as-instructions + memory capture**: invoking a skill splices its **full body into the agent's instruction context** (and frequently into long-term memory/embedding stores), so a poisoned skill is a durable instruction channel, not inert data (cross-ref memory write-back in `prompt_injection.md`).
  - *Safe*: treat generated/modified skills as untrusted code — require human approval before a new/edited skill becomes executable or loadable, run in a least-privilege sandbox, disable inline-shell/template expansion in skill bodies (or render with execution disabled), pin/verify provenance, and diff-review self-edits; never `exec`/`import`/load-with-expansion a freshly model-written file in the same autonomous loop.
- **Unattended scheduled (cron) actions**: scheduled/automation runs are autonomous *by design* — no human in the loop at trigger time. A poisoned memory, feed, or inbox read during the run drives high-impact actions, and "deliver results to <messaging channel>" is an **exfiltration sink**. *Safe*: apply the same risk gating to scheduled actions as interactive ones; restrict unattended runs to a low-risk allowlist; alert + audit every scheduled high-impact action.
- **Subagent privilege propagation**: spawned subagents inherit the parent's tools/credentials, so untrusted input handed to a subagent reaches the same privileged sinks, and injection propagates across the fan-out. *Safe*: scope each subagent's tools/creds to its subtask (don't pass the full toolset); treat subagent inputs as untrusted.
- **Gateway command authz (confused deputy)**: when the agent is driven from shared messaging platforms (group chats, multiple senders, multiple connected apps), privileged actions execute for **whoever sends a message** unless each command is authorized against a verified sender identity. *Safe*: authenticate/authorize the commanding principal per gateway; default-deny unknown senders; bind high-risk actions to a verified owner identity, not "any message on the channel."

| Signal | Grep / structural targets |
|--------|----------------------------|
| Self-generated skill exec | model output written to a file then `exec(`/`eval(`/`import`/`runpy`/`child_process`/`subprocess` on it; `create_skill`, `write_skill`, `save_tool`, self-edit of skill/prompt files in an autonomous loop; skill authored from `web_extract`/pasted/conversation content |
| Load-time skill execution | skill/prompt renderer that runs embedded commands or interpolates at load — inline command-substitution markers (`` !`cmd` ``, `$(...)`, `{{ ... }}`), `subprocess`/`os.popen`/`check_output` inside a skill/template loader, `Template(...).render`/f-string expansion over a file the agent can write |
| Unattended scheduler | `cron`, `crontab`, `APScheduler`, `schedule.every`, `BackgroundScheduler`, `celery beat`, timer-triggered `agent.run` with no approval branch |
| Subagent fan-out | `spawn`, `subagent`, `delegate`, `Task(`, `create_agent` passing the parent's full tool/cred set |
| Gateway → tool with no sender authz | Telegram/Discord/Slack/WhatsApp/Signal/webhook handler invoking tools/`agent.run` without mapping the sender to an authorization check |

## Safe Patterns

```python
# SAFE — minimal, read-only, single-purpose tool with typed, validated params
class SecureFileReader:
    ALLOWED_DIRS = ("/app/data/",)
    ALLOWED_EXT = (".txt", ".md", ".json")
    def read_file(self, path: str) -> str:           # no write/delete/exec method exists
        p = Path(path).resolve()
        if not str(p).startswith(self.ALLOWED_DIRS) or p.suffix not in self.ALLOWED_EXT:
            raise PermissionError("denied")
        return p.read_text()
```

```python
# SAFE — least privilege: agent uses a read-only DB role, not admin
conn = psycopg2.connect(user="llm_readonly", options="-c default_transaction_read_only=on", ...)
```

```python
# SAFE — human-in-the-loop gate for high-impact actions; default deny
RISK = {"search": "low", "update_profile": "medium", "transfer_funds": "high", "delete_account": "high"}
action = llm.determine_action(request)
level = RISK.get(action["type"], "high")            # unknown -> treated as high
if level == "high":
    return queue_for_approval(action)               # executes only after explicit user approval
return execute_action(action) if level == "low" else execute_with_audit(action)
```

Additional barriers: per-user/per-action rate limiting and quotas; audit logging of every tool invocation (user, action, params, result) with anomaly alerts; separate agents/contexts for different privilege tiers.

### Framework HITL-gate APIs and their bypasses

The generic rule "gate high-impact actions behind human approval" maps to concrete framework primitives. Two failure shapes: an explicit **bypass flag**, and a **gate that doesn't actually block**.

- **Danger-bypass flag literals (grep, treat as high-confidence)**: `allow_dangerous_requests=True`, `allow_dangerous_code=True`, `auto_approve=True`, `bypass_confirmation=True`, `skip_human_review`, `skip_approval`, `no_confirm`, `force_execute`, `dangerously_allow`, and AutoGen `human_input_mode="NEVER"` (`"ALWAYS"`/`"TERMINATE"` = human-in-loop). LangChain documents `allow_dangerous_requests=True` as explicitly disabling the safety warning.
- **Real gate APIs whose *presence* is the FP-killer**: LangChain `HumanApprovalCallbackHandler` (on the executor or per-tool `callbacks=[...]`); LangGraph `interrupt_before=[...]` / `interrupt_after=[...]` in `.compile(checkpointer=..., interrupt_before=[...])`; LlamaIndex `before_action=fn`; Vercel AI `onStepFinish` guard.
- **"Logging is not a gate."** A callback (e.g. `on_tool_start`) that only logs and returns — without raising, blocking, or prompting a human — does **not** stop the tool. Audit logging is a separate barrier; a log-only hook fails to constitute the approval gate. Require the gate to *raise/throw/return-to-block*.
- **Partial gate (node-membership)**: LangGraph `interrupt_before=["plan"]` gates a benign node while the **destructive** node (`execute_payment`) is absent from the interrupt list → still ungated. Verify the destructive node is actually in the interrupt set, not merely that an interrupt exists.

### Tool dispatch — the model chooses which function runs

Distinct from *authority* (above): here the **model's output selects which function/route executes**. The dispatch code only ever sees clean tool-call JSON — never the injected instruction that produced it — so **the model is an untrusted dispatcher**, and a fully trusted user's session is still dangerous. Severity is gated on whether **any attacker-influenceable text** (a RAG doc, a prior tool result, an email/PDF body, an agent-to-agent message) can reach the context window — *not* on who is prompting.

- **Reflection / dict dispatch keyed on model output**: `TOOL_MAP[name](**args)`, `getattr(obj, name)(args)`, `globals()[name]`, `handlers.get(name)(args)` (and Ruby `send`/`public_send`, Java `getMethod(name).invoke`, Go `MethodByName(name).Call`). The sink mechanics are the dynamic-dispatch RCE in `rce.md`; the addition here is that the **model** supplies `name`/`args`, so an allowlist must run **before** the lookup. (See `rce.md` for the reflection sink list.)
- **LangGraph edge-routing on verbatim model output**: `add_conditional_edges(node, lambda s: s["next"], {... "admin_cleanup": "admin_cleanup"})` where `s["next"]` is the model's chosen route and a destructive node is in the edge map. There is no callable lookup at all — reaching the node *is* the action — so a function-name allowlist won't catch it; the route value itself must be constrained.
- **Registry-narrow ≠ safe — check the argument schema**: a one-tool registry can still ship an unconstrained arg (`{"path": {"type": "string"}}` with no `enum`/`pattern`/`maxLength`, or `additionalProperties` absent while the impl does `**input`). The argument schema is a separate attack surface from the tool list.
- **`JSON.parse` alone is not validation.** A typed-schema validation (`pydantic .model_validate`, Zod `.parse`, `jsonschema.validate`/Ajv) must run **after** the parse and **before** dispatch — and an `enum` over safe values still needs `realpath`/`startswith(base)` to defeat symlink escape. Cross-ref `mcp_security.md` (tool arg-schema) and `prompt_injection.md` (the upstream injection that steers the dispatch).

### Command-execution guardrail (screen the agent's chosen command)

When an agent legitimately needs a command/shell tool, add a guardrail at the **execution boundary** that screens the command the model actually chose — defense-in-depth *behind* least-functionality and typed params, for the case where injection (often indirect — see `prompt_injection.md`) hijacked the model's intent.

```python
# SAFE — decode, normalize, then denylist the chosen command BEFORE running it
import base64, re, unicodedata
DANGEROUS = [r"rm\s+-rf\s+/", r":\(\)\s*\{\s*:\|:&\s*\};:",      # wipe, fork bomb
    r"\bnc\b.*\d+\.\d+\.\d+\.\d+", r"\b(curl|wget)\b.*\|\s*(sh|bash)",  # reverse shell / curl|sh
    r"/dev/tcp/", r"bash\s+-i\s*>&", r"socat\s+TCP:.*EXEC",      # bash/socat reverse shell
    r"\$\((env|id|whoami)\)", r"`(env|id|whoami)`"]              # recon/exfil substitution

def screen(cmd: str) -> None:
    norm = unicodedata.normalize("NFKD", cmd).replace("${IFS}", " ")   # defeat homograph + ${IFS} evasion
    candidates = [norm]
    for enc in re.findall(r"[A-Za-z0-9+/=]{16,}", norm):               # decode-before-execute
        try: candidates.append(base64.b64decode(enc).decode("utf-8", "ignore"))
        except Exception: pass
        try: candidates.append(base64.b32decode(enc).decode("utf-8", "ignore"))
        except Exception: pass
    for c in candidates:
        if any(re.search(p, c, re.I) for p in DANGEROUS):
            raise PermissionError("blocked dangerous command")
```

Key points a scanner should require: **decode base64/base32 inside the command** (`echo <enc> | base64 -d`, `… | base32 -d`) and re-check the *decoded* payload, not just the literal string; **normalize evasion** (`${IFS}`→space, leetspeak/homoglyphs, commands reassembled from shell variables) before matching; and treat the denylist as a **secondary** control — a denylist is bypassable, so the primary defense remains an allowlist of fixed commands run with `shell=False`/argv (and a human gate for anything outside it).

**A denylist/`argv[0]` guardrail is incomplete unless it also handles these evasions** (flag the guard as bypassable if it doesn't):

- **Transparent-wrapper / env-assignment stripping** — `sudo rm -rf /`, `env X=1 rm -rf /`, `nohup`/`nice`/`ionice`/`time`/`exec <danger>` defeat an `argv[0]`-based denylist because the dangerous program isn't `argv[0]`. Strip leading wrappers and `FOO=bar` env-assignments before matching.
- **Recurse into command-substitution and `bash -c` bodies** — split on `; && || |` and inspect the bodies of `$(...)`, backticks, and `bash -c '<payload>'` (and `sh -c`/`zsh -c`); a guard that only reads the outer argv misses `bash -c '<danger>'` and `eval "$(…)"`.
- **Interpreter-payload bypass** — `python -c "import shutil; shutil.rmtree('/')"`, `node -e …`, `perl -e …`, `ruby -e …` route destructive operations through an interpreter, so there is no shell verb to denylist. Treat `<interpreter> -c/-e <code>` as an opaque code sink (require approval / inspect the code), not an allowed command.
- **Fail closed on unparseable/opaque input** — if the guard can't statically parse the command (`shlex` error on unbalanced quotes) or the payload is opaque (`bash -c <blob>`), it must **escalate/deny**, never default-allow or crash open. A guard that returns "allow" on a parse exception is the bug.

### Code-interpreter / sandbox isolation (config, not just the bypass flag)

The danger-bypass flag (`allow_dangerous_code=True`) is in the grep list above; the sandbox's **isolation config** is a separate sink. A code-exec sandbox SDK (`Sandbox()` / E2B / Riza / Daytona / `CodeInterpreter()` / `create_pandas_dataframe_agent`) stood up with **no network/egress isolation** (`network_disabled` unset, `network_mode != "none"`, no egress allowlist) lets model-generated code reach the internet (exfil, SSRF, C2); a container launched in the agent's exec path with `privileged=True`, `network_mode="host"`, or host-root `volumes` is a sandbox in name only. **Safe**: disable network by default (`network_disabled=True`/`network_mode="none"`), egress-allowlist when network is needed, drop privileges, no host mounts, set CPU/mem/time caps. Also flag a tool/MCP server the agent **auto-installs unpinned** (`pip install <tool>` / `mcp install <server>` with no `==`/`--require-hashes`, `version: latest`) — a downgrade-to-vulnerable axis distinct from rug-pull.

### Agentic commerce — signed-mandate integrity & replay

When an agent transacts (payments, purchases, transfers) under a **signed mandate / authorization token**, the integrity of that mandate *is* the control — a class the HITL-gate coverage above doesn't reach:

- **Mandate constraint mutability** — authorization fields (`budget`/`limit`/`max_amount`/`allowed_merchants`/`spending_cap`) reassigned after issuance, or set to sentinels (`"unlimited"`/`None`/`-1`) → privilege escalation by widening the mandate.
- **Replay / missing idempotency on a signed envelope** — a signed mandate/tool-call/transfer accepted with no `nonce`/`jti`/`idempotency_key`/timestamp dedup, so a *validly signed* request double-executes (cross-ref the adjacent-protocols replay note in `mcp_security.md`).
- **Signature alg-downgrade on the mandate** — `alg` accepted as `none`/`HS256` where EdDSA/ES256 is required; a permissive `jwt.decode(..., algorithms=[...])` (cross-ref `authentication_jwt.md`).
- **Settlement / escrow finality bypass** — charge/settle with no proof-of-execution; credit accepted on `pending`/`unconfirmed`; single-party `escrow.release` with no quorum; `bypass_escrow`/`skip_escrow` flags.
- **Mutable audit trail** — `DELETE`/`TRUNCATE`/`.delete()` on `mandate_log`/`audit_trail`/`payment_history` destroys non-repudiation (append-only violation).

**Safe**: treat the mandate as immutable once signed (re-verify signature **and** constraints server-side at spend time), bind a nonce/idempotency key and reject replays, pin the signature algorithm, require settlement proof / multi-party escrow release, and keep the mandate/audit log append-only.

## Severity & Triage

- Autonomous irreversible action (funds/data deletion/deploy) with attacker-influenceable prompt and no gate: **Critical/High**.
- Over-broad tool/credential that enables RCE/SSRF/data exfil: severity of the reachable sink (`rce`, `ssrf`, `idor`).
- Missing audit/rate-limit alone (action otherwise gated): **Low/Info** (defense-in-depth gap).
- Downgrade when a human approval step, scoped credential, or framework-enforced typed tool boundary is present and effective.

## Common False Alarms

- Read-only/informational tools with no state-changing capability.
- High-impact actions that already require explicit user confirmation or a signed/idempotent request.
- Internal automation where the entire prompt chain is trusted and no external input can reach the planner (verify no user/retrieved content upstream).
- Tools whose parameters are strictly typed and validated by the framework before reaching any sink.

## References

- OWASP LLM06:2025 Excessive Agency
- CWE-250 (Execution with Unnecessary Privileges), CWE-269 (Improper Privilege Management), CWE-862 (Missing Authorization)
- Related: `prompt_injection.md`, `mcp_security.md`, `insecure_output_handling.md`, `privilege_escalation.md`
