---
name: excessive_agency
description: Excessive agency in LLM/agent systems — too much tool functionality, over-broad permissions, or autonomous high-impact actions without human approval (OWASP LLM06, CWE-250/269/862)
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
