# SAST Security Assessment

Your goal is to identify security vulnerabilities in the codebase located in the current working directory by orchestrating the `llm-sast-scanner` skill across parallel subagents — one per vulnerability lens — so each lens runs in its own isolated context.

All output is written to a `.llm-sast-scanner-cache/` folder in the project root. Steps whose output file already exists are skipped, so this is safe to re-run after fixing issues.

> **Skill resolution:** subagents invoke skills by name (`llm-sast-scanner`, `llm-sast-scanner-full-scan-loop`). Each tool loads them from its own skills directory — Claude Code from `.claude/skills/`, Cursor/Codex/agents from `.agents/skills/`. Both directories are symlinks to the single canonical skill source at the repo root, so the two runtimes always run identical skill content.

---

## Arguments

This orchestrator forwards optional tagged arguments to the underlying skill.

- `adv=critical,high,medium` (case-insensitive, comma-separated) — controls which severities go through the scanner's **Step 6: Adversarial Impact Validation**. When omitted, Step 6 is skipped. Pass the same `adv=` value to every Step 2 subagent and to the Step 3 report agent.

---

## Step 1: Codebase Analysis & Threat Modeling

Check if `.llm-sast-scanner-cache/architecture.md` already exists. If it does, skip the analysis below (but still run the project-memory step at the end of this section).

Otherwise, **in-session** (not as a subagent, since later steps read its output), run the `llm-sast-scanner` skill's **Step 1 (Understand Scope)** over the whole repo and write a short architecture/threat-model brief to `.llm-sast-scanner-cache/architecture.md` covering: languages & frameworks, entry points (routes/handlers/CLI/jobs), trust boundaries, authN/authZ model, data stores, outbound calls, and the **detected stack** so later lenses can skip inapplicable reference files. Also record the **per-lens stack-gated reference allowlist** derived from the files actually present (gateable platform/language/infra references whose signals appear, plus the always-loaded language-agnostic classes), so lenses share one definition of applicable classes and drop only provably-absent stacks.

**Project memory (always, even when `architecture.md` already existed):** ensure `.llm-sast-scanner-cache/project-memory.md` exists; if absent, initialize it from the template in the base skill's **Project Memory Protocol**. This file carries cross-scan hints (confirmed findings, confirmed false-positive patterns, project security primitives, hotspots) and is consumed by every detection subagent as *hints, never authority*. Also add `.llm-sast-scanner-cache/` to the repo's `.gitignore` if not already ignored.

**Wait for this step to finish before proceeding.**

---

## Step 2: Vulnerability Detection (Parallel)

Start **one subagent per lens**, all **in parallel**. Skip any lens whose results file already exists.

Give each subagent the same instruction pattern, substituting the lens name, class list, and results path from the table below:

> Read `.llm-sast-scanner-cache/architecture.md` for context and `.llm-sast-scanner-cache/project-memory.md` as **hints, never authority** (follow the base skill's **Project Memory Protocol**: memory may prioritize or explain known-safe patterns but must never make you skip a line or auto-dismiss a class; a false-positive entry may suppress a re-report only after you re-confirm its safe rationale in the current code). Then run the `llm-sast-scanner` skill focused on the **\<lens\>** vulnerability classes. From the skill's `references/` directory, load only your lens's reference files that are on the stack-gated allowlist in `architecture.md` (always-load the language-agnostic classes; skip only stacks whose files are absent; when unsure, load). Follow the skill's full workflow — Source→Sink taint tracking (Step 3), business-logic/auth analysis (Step 4), Judge re-verification (Step 5), and (only if `adv=` was provided) Adversarial Impact Validation (Step 6). Report only CONFIRMED / LIKELY findings using the skill's finding format. Write all findings to the results file below. Do **not** write to `project-memory.md` (the report step is the single writer). Clean up any intermediate recon/threat/batch files for this lens when done.

| Lens | Results file | Vulnerability classes (reference lenses) |
|------|--------------|------------------------------------------|
| injection | `.llm-sast-scanner-cache/injection-results.md` | SQLi, XSS, client-side prototype pollution, SSTI, SSI injection, NoSQLi, GraphQL injection, XXE, RCE/command injection, expression-language injection, LDAP injection, XPath/XQuery injection, CSV/formula injection, log injection, prompt injection (LLM01), insecure output handling (LLM05), DOM clobbering |
| access-auth | `.llm-sast-scanner-cache/access-auth-results.md` | IDOR, privilege escalation / missing auth (BFLA), authentication & JWT, default credentials, hardcoded secrets (CWE-798 secret literals at rest / client-exposure model), brute force, business logic, HTTP method tampering, verification code abuse, session fixation, mass assignment, excessive agency (LLM06), RAG / vector & embedding security (LLM08), API / REST / web-service security, MCP (Model Context Protocol) security |
| crypto-data | `.llm-sast-scanner-cache/crypto-data-results.md` | weak crypto/hash, information disclosure (incl. LLM02 sensitive disclosure), insecure cookie, trust boundary, shared-client cache/dedup cross-user leak, cleartext transmission, certificate/TLS validation, system prompt leakage (LLM07), privacy / data protection (PII) |
| server-side | `.llm-sast-scanner-cache/server-side-results.md` | SSRF, path traversal/LFI/RFI, client-side path traversal, server-side prototype pollution, insecure deserialization, arbitrary file upload, JNDI injection, race conditions, insecure temp file, file permissions, batch/ETL/mainframe data-pipeline security |
| protocol-infra | `.llm-sast-scanner-cache/protocol-infra-results.md` | CSRF, open redirect, reverse tabnabbing, HTTP request smuggling/desync, HTTP response splitting, host header poisoning, CORS misconfiguration, WebSocket security (CSWSH), clickjacking, web cache deception/poisoning, denial of service (incl. LLM10 unbounded consumption), regex injection/ReDoS, CVE patterns, Content Security Policy (CSP) weaknesses, XS-Leaks |
| hardening-platform | `.llm-sast-scanner-cache/hardening-platform-results.md` | output encoding, format string injection, ASP.NET security misconfiguration, hardcoded code/backdoor, dependency confusion, ML supply chain & data/model poisoning (LLM03/04), AI editor / agent config poisoning (repo poisoning), PHP security (incl. TYPO3 CMS — Fluid / TypoScript / Extbase), mobile security, C/C++ memory safety, smart contract security (Solidity/EVM), IaC security (Terraform/CloudFormation/ARM/Bicep/Pulumi), Kubernetes / cloud orchestration, CI/CD & container security, nginx / web-server configuration, supply chain security (SRI / provenance / lifecycle scripts) |

**Wait for all subagents to finish before proceeding.**

---

## Step 3: Report Generation

After all Step 2 subagents finish, skip this step if `.llm-sast-scanner-cache/final-report.md` already exists.

Otherwise launch a single subagent:

> Read all available `.llm-sast-scanner-cache/*-results.md` files and `.llm-sast-scanner-cache/architecture.md` for context, then apply the `llm-sast-scanner` skill's **Step 7 (Report Findings)** — severity model, severity-downgrade rule, finding format, and report structure — to consolidate every finding into `.llm-sast-scanner-cache/final-report.md`, ranked by severity (Critical → Info) with exact file paths, line numbers, and concrete remediations. De-duplicate findings reported by more than one lens. Finally, as the **single writer**, update `.llm-sast-scanner-cache/project-memory.md` per the base skill's **Project Memory Protocol**: append newly CONFIRMED findings (with current `git rev-parse HEAD`), record any downgraded/disputed findings as false-positive patterns with the rationale that defeated them, refresh project security primitives and hotspots, and bump `last-scanned-sha` / `last-updated`.

---

## Alternative: Exhaustive Convergence Audit

For a deeper, line-by-line audit instead of the lens fan-out in Step 2, use the `llm-sast-scanner-full-scan-loop` skill. It comes in two modes.

### Single-agent (default)

Run the `llm-sast-scanner-full-scan-loop` skill against the target directory in one session. It loops Steps 1–5 to convergence, verifies 100% line coverage, runs one final adversarial pass, and writes a timestamped `sast_report-<timestamp>.md`. Use this when you want the strongest convergence/coverage guarantee (a single context owns the ledger and coverage map).

### Deep Mode (Parallel) — one loop subagent per lens

Use when asked for a *"deep parallel scan"*, *"full scan loop with all agents"*, or to run the convergence loop across subagents. This trades the single-context guarantee for parallelism: each lens gets its own convergence loop, and coverage/ledger state is reconciled at merge time. Note each lens subagent independently reads every in-scope line, so total read cost scales with the number of lenses.

> **Shortcut:** the `llm-sast-scanner-full-scan-loop` skill now performs this exact fan-out natively in its default `mode=parallel`. You can simply run `llm-sast-scanner-full-scan-loop <dir>` and it will execute Steps D1–D3 below itself. The steps are spelled out here so the orchestrator can drive them directly when preferred.

**Step D1 — Analysis.** Reuse `.llm-sast-scanner-cache/architecture.md` from Step 1 (run that step first if it does not exist). Ensure `.llm-sast-scanner-cache/project-memory.md` exists too (Step 1 initializes it; create it from the base skill's **Project Memory Protocol** template if missing).

**Step D2 — Parallel convergence loops.** Start **one subagent per lens** (same six lenses and class lists as the Step 2 table), all **in parallel**. Skip any lens whose deep results file already exists. Give each subagent this instruction:

> Read `.llm-sast-scanner-cache/architecture.md` for context and `.llm-sast-scanner-cache/project-memory.md` as **hints, never authority** (base skill's **Project Memory Protocol** — never skip a line or auto-dismiss a class; a false-positive entry suppresses a re-report only after you re-confirm its rationale in current code). Then run the `llm-sast-scanner-full-scan-loop` skill in **`mode=single lens=<lens>`** over this repository (single-context so it does NOT fan out again), **constrained to the \<lens\> vulnerability classes** (load only the matching references from the base skill). Perform the loop's convergence phase: multi-pass Steps 1–5 (taint tracking, business-logic/auth, Judge) until convergence, with the loop's ledger + 100% line-coverage discipline applied to your lens. **Do NOT run the final Adversarial Impact Validation pass and do NOT write a timestamped report** — those are deferred to consolidation. Do **not** write to `project-memory.md` (consolidation is the single writer). Write only Judge-passed CONFIRMED / LIKELY findings, plus your final coverage result and pass log, to `.llm-sast-scanner-cache/deep-<lens>-results.md`.

| Lens | Deep results file |
|------|-------------------|
| injection | `.llm-sast-scanner-cache/deep-injection-results.md` |
| access-auth | `.llm-sast-scanner-cache/deep-access-auth-results.md` |
| crypto-data | `.llm-sast-scanner-cache/deep-crypto-data-results.md` |
| server-side | `.llm-sast-scanner-cache/deep-server-side-results.md` |
| protocol-infra | `.llm-sast-scanner-cache/deep-protocol-infra-results.md` |
| hardening-platform | `.llm-sast-scanner-cache/deep-hardening-platform-results.md` |

**Wait for all subagents to finish before proceeding.**

**Step D3 — Consolidation + single adversarial pass.** Launch one subagent:

> Read all `.llm-sast-scanner-cache/deep-*-results.md` files and `.llm-sast-scanner-cache/architecture.md`. Merge and de-duplicate findings across lenses (same `file:line` + class = one finding). Run the `llm-sast-scanner` skill's **Step 6 (Adversarial Impact Validation)** ONCE over the full consolidated set with `adv=critical,high,medium`, apply the STANDING / DOWNGRADED / DISPUTED / WITHDRAWN verdicts, then write a timestamped consolidated report `sast_report-<timestamp>.md` (timestamp from `date +%Y-%m-%d_%H-%M-%S`) using the skill's report structure. Also print a combined coverage summary and per-lens pass log. Finally, as the **single writer**, update `.llm-sast-scanner-cache/project-memory.md` per the base skill's **Project Memory Protocol** (append newly CONFIRMED findings with current `git rev-parse HEAD`; record DOWNGRADED/DISPUTED/WITHDRAWN as false-positive patterns with their defeating rationale; refresh primitives/hotspots; bump `last-scanned-sha`/`last-updated`).

---

When the chosen flow is complete, tell the user where the report is (`.llm-sast-scanner-cache/final-report.md` for Step 3, or `sast_report-<timestamp>.md` for the convergence audit) and give a short summary of the highest-severity findings.
