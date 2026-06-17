---
name: prompt-injection
description: LLM prompt injection detection — untrusted user content in AI model prompts (CWE-1427)
---

# Prompt Injection (CWE-1427)

Prompt injection occurs when attacker-controlled text is concatenated into an LLM system prompt, tool prompt, or agent instruction. The model may follow embedded instructions instead of developer intent—leaking secrets, calling tools, or exfiltrating context. Automated static analysis coverage is strongest for Python; other languages require manual review.

## Source -> Sink Pattern

**Sources**:
- `ActiveThreatModelSource` — remote HTTP inputs, framework request objects
- Model-as-data sink nodes tagged `prompt-injection`
- User content flowing into OpenAI / Agent SDK APIs

**Sinks**:
- `AIPrompt.getAPrompt()` — any AI prompt construction node
- OpenAI `content` argument nodes (`OpenAI::getContentNode()`)
- Agent SDK content nodes (`AgentSDK::getContentNode()`)
- External model sink nodes from MaD (`ModelOutput::getASinkNode("prompt-injection")`)

**Sanitizers**:
- `ConstCompareBarrier` — comparison guards that confine input to expected literals (partial; not semantic prompt firewall)

Commonly affected languages: Python (primary automated coverage); JavaScript/TypeScript, Java, Go, C#, Ruby, and Rust require manual review for `openai.chat.completions.create`, LangChain `PromptTemplate`, Semantic Kernel planners, etc.

## Vulnerable Conditions

- User message, document chunk, ticket body, or search result interpolated into system/developer prompt without isolation.
- RAG pipeline embeds retrieved web/tenant content directly into prompt template.
- Agent loop passes tool output (HTTP response, email body) into next-turn prompt unchecked.
- No structural separation between *instructions* and *data* (single string template).

## Safe Patterns

- Keep system instructions static; pass user content as structured `user` role messages only (API-native separation).
- Treat retrieved/third-party text as untrusted data—summarize in a sandboxed step or apply output filtering before re-prompting.
- Use guardrail frameworks (OpenAI Guardrails, NeMo, Llama Guard) on inputs *and* outputs; deny tool calls triggered by user text alone.
- Allowlist expected input shape (JSON schema, max length, language) before prompt assembly.
- Never embed user input in developer/system prompt strings; use parameterized chat APIs.

## Language Patterns

### Python
- **VULN**: `prompt = f"Answer using: {request.json['context']}"` passed to OpenAI chat `messages` system content
- **VULN**: RAG: `llm.invoke(SYSTEM + retrieved_page_text)`
- **SAFE**: `messages=[{"role":"system","content":STATIC},{"role":"user","content":user_text}]` with static system string

### JavaScript / TypeScript
- **VULN**: `` client.chat.completions.create({ messages: [{ role: 'system', content: `Rules: ${userBio}` }] }) ``
- **SAFE**: system prompt constant; user content only in `role: 'user'`

### Java / Spring AI
- **VULN**: `PromptTemplate.render(Map.of("doc", userInput))` where template mixes instructions + `{doc}`
- **SAFE**: Spring AI `UserMessage` / `SystemMessage` separation with fixed system text

## Example

```python
# BAD — user input in agent instructions (system-level prompt)
badAgent = Agent(
    name="Assistant",
    instructions="This prompt is customized for " + input  # tainted
)

# GOOD — static instructions; user input only in user-role message
goodAgent = Agent(
    name="Assistant",
    instructions=STATIC_SYSTEM_PROMPT,
)
messages = [{"role": "user", "content": input}]
```

Taint into `instructions=` and OpenAI `content` nodes is the primary detection signal; guardrail wrappers are not automatic sanitizers unless input is validated before prompt assembly.

## Triage Workflow

1. Identify prompt sink: `AIPrompt`, OpenAI chat `messages`, LangChain `PromptTemplate`, Agent SDK `content`.
2. Trace remote source → string concat / f-string / template render into **system** or **developer** role text.
3. Check for `ConstCompareBarrier` only — does not replace semantic isolation.
4. Assess tool access: agents with shell/HTTP/DB tools escalate injection to RCE/SSRF.
5. Downgrade if user text is confined to `user` role with static system prompt and no tools.

## Related CWEs

- **CWE-94** / **CWE-78**: if injection leads to tool command execution — tag downstream impact.
- **CWE-200**: context exfil via prompt leaking — manual review of model output handlers.

## Common False Alarms

- User text in `user` role only with fixed system prompt and no tool side-effects — lower risk (jailbreak still possible, not classic prompt-injection sink).
- Const-compare sanitizer on unrelated field while different user field reaches prompt.
- Test fixtures with hardcoded prompts — not remote-exploitable.

## Business Risk

- Exfiltration of system prompt, API keys in context, or other tenants' RAG documents.
- Unauthorized tool/API invocation (send email, delete records, SSRF via agent tools).
- Policy bypass in customer-support or admin copilots → fraud and data breach.
- Supply-chain: compromised document in RAG corpus acts as stored prompt injection for all users querying that index.

## Core Principle

Instructions and untrusted data must never share a prompt string. Use API-level role separation, treat all external text as hostile, and assume the model will obey the last plausible instruction in context. On Python repos using OpenAI Agents SDK, Guardrails, or MaD-tagged AI sinks, review any route where remote input reaches prompt assembly.

## Related AI/LLM Classes (OWASP LLM Top 10)

Prompt injection (LLM01) usually chains with one of these — load them when reviewing an LLM/agent app:

- `insecure_output_handling.md` (LLM05) — the model's output reaching an HTML/SQL/shell/HTTP sink (the egress side of an injection chain)
- `excessive_agency.md` (LLM06) — what makes a successful injection consequential (over-broad tools/permissions/autonomy)
- `system_prompt_leakage.md` (LLM07) — secrets / authz logic in prompts, prompt-extraction attacks
- `rag_vector_security.md` (LLM08) — indirect injection via poisoned/over-retrieved documents; cross-tenant context leakage
- `ml_supply_chain_poisoning.md` (LLM03/04) — model/dataset supply-chain and training-data poisoning
- `information_disclosure.md` (LLM02) and `denial_of_service.md` (LLM10) — sensitive-data egress and unbounded token/cost consumption
- `mcp_security.md` — tool poisoning and injection via MCP tool metadata/output

## Analyst Notes

1. RAG retrieval is a first-class source: web pages, tickets, and uploads become prompt content without hitting HTTP param sources directly.
2. Multi-modal inputs (image alt-text, PDF extract) are not yet modeled in most static rules — extend review manually.
3. Indirect injection: attacker poisons data another user's agent reads later (stored prompt injection).
4. Guardrail SDK wrappers reduce risk but tainted `instructions=` still warrants review unless input is sanitized before concat — verify guardrail config does not re-embed raw user text.
