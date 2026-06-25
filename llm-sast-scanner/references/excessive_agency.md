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

## Vulnerable Conditions

- A single tool exposes read **and** write/delete/exec; the model can choose the dangerous method.
- The agent's DB connection or cloud credential is admin/wildcard rather than scoped to the tool's job.
- High-risk actions execute the moment the model decides, with no confirmation step and no cap on frequency.
- A "general" tool (run shell / fetch URL / write file / eval) is registered "just in case," widening blast radius.
- Tool parameters are free-form strings forwarded to a sink instead of validated typed fields.

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
