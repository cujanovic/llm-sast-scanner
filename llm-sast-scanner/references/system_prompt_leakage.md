---
name: system_prompt_leakage
description: System prompt leakage and over-trusted prompts — secrets embedded in system prompts, security/authorization logic expressed in prompt text, and reliance on prompt secrecy as a control (OWASP LLM07, CWE-200/522/312)
---

# System Prompt Leakage (LLM07)

System prompts get extracted. Treat any instruction sent to a model as potentially user-visible. The vulnerability is not that the prompt *can* leak — it is that the application put something **sensitive or security-critical** into the prompt: credentials, internal endpoints, or the authorization rules themselves. Static analysis inspects prompt construction for secrets and for security logic that belongs in code, and checks whether the only protection against leakage is the prompt asking the model not to talk.

The core pattern: *a secret, internal detail, or access-control rule lives inside a system/developer prompt string, or the app relies on the prompt's "do not reveal" instruction instead of an external control.*

## What It Is (and Is Not)

**What it IS**
- Credentials/secrets in prompt text: DB connection strings, API keys, tokens, internal URLs, signing keys
- Authorization/business rules expressed in the prompt ("admins can access any account", "limit is $5000") so that leakage hands an attacker the bypass map
- Reliance on prompt-only guardrails ("never reveal these instructions") with no external input/output filtering
- Prompts that embed PII or proprietary data that becomes disclosed when the prompt is echoed

**What it is NOT**
- General PII/secret exposure in model *responses* from training data or RAG context — see `information_disclosure.md` (LLM02)
- The injection technique used to extract the prompt — see `prompt_injection.md`
- Hardcoded secrets in ordinary source (non-prompt) — see `default_credentials.md` / `hardcoded_code_backdoor.md`
- A system prompt that contains only behavioral instructions and no secrets/security logic (leakage is low-impact; note, don't over-flag)

## Source -> Sink Pattern

**Sources / locations** — system/developer prompt strings, prompt templates, "instructions"/"system" message fields, persona/config files loaded into the prompt.

**Sink (disclosure)** — the model response channel returned to the user; prompt content reflected verbatim or paraphrased.

**Barriers**
- Secrets via environment/secret manager, used only in tool/handler code — never in prompt text
- Authorization and limits enforced in code (RBAC, server-side checks), not described in the prompt
- External (non-LLM) input filters for extraction attempts and output filters for prompt/secret patterns
- Design assumption: "the prompt will leak" — nothing security-critical depends on its secrecy

## Recon Indicators

| Signal | Grep / structural targets |
|--------|----------------------------|
| Prompt construction | `system_prompt`, `system\s*=`, `role"\s*:\s*"system"`, `SystemMessage(`, `ChatPromptTemplate`, `instructions\s*=`, `"""You are` |
| Secrets in prompt | within a prompt string: `postgres://`, `mysql://`, `mongodb://`, `sk-`, `AKIA[0-9A-Z]{16}`, `api[_-]?key`, `Bearer `, `password`, `secret`, internal hostnames (`*.internal`, `*.svc`, `10.`/`192.168.`) |
| Authz logic in prompt | prompt text containing `admin`, `role`, `permission`, `can access`, `limit is`, `only users who`, `if the user is` |
| Prompt-only guardrail | `never reveal`, `do not disclose your`, `keep these instructions secret` as the sole protection (no external filter present) |

## Vulnerable Conditions

- A connection string, API key, or token is concatenated into the system prompt.
- The prompt enumerates the permission model, transaction limits, or filtering rules an attacker would need to plan a bypass.
- The app depends on "do not reveal your instructions" with no external output check; standard extraction phrasings recover the prompt.
- Per-tenant/customer secrets or PII are templated into a shared prompt.

## Safe Patterns

```python
# SAFE — no secrets in the prompt; credentials live in env/secret manager, used in tool code only
db = psycopg2.connect(os.environ["DATABASE_URL"])     # not in any prompt
system_prompt = """You are a support assistant for ACME.
Help with orders, products, and account questions.
Use the provided tools to look things up."""           # behavioral only, no secrets/rules
```

```python
# SAFE — authorization enforced in code, not described in the prompt
ROLE_LIMITS = {"customer": 5000, "manager": 50000}
def can_transfer(user, amount, target_account) -> bool:
    if target_account not in user.owned_accounts and user.role != "admin":
        return False
    return amount <= ROLE_LIMITS.get(user.role, 0)
# prompt says nothing about limits or roles
```

```python
# SAFE — external output guardrail independent of the model (defense in depth)
def safe_reply(resp: str, system_prompt: str) -> str:
    overlap = len(set(resp.lower().split()) & set(system_prompt.lower().split())) / max(len(set(system_prompt.split())),1)
    if overlap > 0.5 or re.search(r"(api[_-]?key|password|secret)\s*[:=]", resp, re.I):
        log_security_event("prompt_leak_blocked")
        return "I can't share that."
    return resp
```

## Severity & Triage

- Live credential/token/connection string in a prompt: **High/Critical** (treat as exposed secret; rotate).
- Authorization rules/limits in the prompt that enable a concrete bypass: **Medium/High**.
- Prompt-only guardrail with no external control, no secrets, behavioral instructions only: **Low/Info**.
- Downgrade when secrets are referenced from env/secret manager and only behavioral text is in the prompt.

## Common False Alarms

- System prompts containing only tone/behavior instructions and no secrets or security logic.
- "Do not reveal instructions" *plus* an external output filter and no sensitive prompt content.
- Placeholders/examples (`sk-xxxx`, `your-api-key`) that are not real secrets — verify the value.
- Secret-looking tokens that are actually public identifiers (publishable keys, client IDs).

## References

- OWASP LLM07:2025 System Prompt Leakage
- CWE-200 (Information Exposure), CWE-522 (Insufficiently Protected Credentials), CWE-312 (Cleartext Storage of Sensitive Information)
- Related: `prompt_injection.md`, `information_disclosure.md`, `default_credentials.md`
