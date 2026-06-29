# llm-sast-scanner

A general-purpose **Static Application Security Testing (SAST) skill** for LLM-based code vulnerability analysis. It is loaded by AI coding agents (Claude Code, OpenAI Codex, Cursor, and other agent runtimes) to perform structured **source → sink taint analysis** across **102 vulnerability classes** — covering web, API, authentication, cloud/IaC, nginx config, mobile, smart-contract, BaaS (Supabase/Firebase) authorization, and the OWASP LLM Top 10 for AI/agent apps.

Instead of pattern-matching with hardcoded rules, it gives an agent a disciplined, evidence-based methodology: identify untrusted input, trace it through the code, and confirm whether it reaches a dangerous sink without a sanitizer in between — then verify every candidate through an adversarial "Judge" stage to cut false positives.

---

## Why it exists

Traditional SAST tools rely on fixed rule sets and tend to drown teams in false positives. LLMs can reason about code semantically — understanding intent, data flow, and context — but left unguided they hallucinate, miss reachability, and report noise. This project supplies the missing structure: a repeatable workflow, curated per-class knowledge bases, and verification gates that keep an LLM's reasoning grounded in actual code evidence.

---

## What's in this repo

| Component | What it is |
|-----------|-----------|
| **`llm-sast-scanner/`** | The core skill — a 7-step detection workflow plus Judge verification and an optional adversarial pass, backed by 102 vulnerability reference knowledge bases. |
| **`llm-sast-scanner-full-scan-loop/`** | A wrapper skill for an exhaustive, convergence-driven, line-by-line audit of an entire repository, guaranteeing 100% line coverage. |
| **`AGENTS.md` / `CLAUDE.md`** | The repo-level orchestrator playbook that drives parallel multi-agent scanning and report consolidation. `CLAUDE.md` is a symlink to `AGENTS.md`. |
| **`.claude/skills/`, `.agents/skills/`** | Per-runtime skill discovery directories — both symlink to the single canonical skill source, so the two runtimes can never drift apart. |

---

## How it works

The core skill gives an agent a structured, evidence-based workflow:

1. **Understand scope** — target, languages/frameworks, and goal (quick scan, deep audit, single class, full report).
2. **Load references** — pull in only the vulnerability knowledge bases that match the stack in use.
3. **Trace taint** — read each file once and evaluate every loaded lens: sources → data flow → sinks → sanitizers.
4. **Business logic & auth analysis** — missing authorization, IDOR, broken state machines, race conditions, cross-user leaks.
5. **Judge** — an adversarial second opinion re-verifies each candidate (reachability / sanitization / exploitability) to eliminate false positives.
6. **Adversarial impact validation** *(optional)* — stress-test surviving findings for real-world exploitability.
7. **Report** — actionable findings with severity, exact file path + line number, evidence, and concrete remediation.

A few principles keep results trustworthy:

- **Read-once discipline** — each file is read once and checked against every in-scope class, so total cost stays ~1× the codebase regardless of how many classes are active.
- **Sources / sinks / sanitizers** — every reference documents per-language entry points, dangerous sinks, and the barriers that neutralize them; a recognized barrier is required before ruling a finding safe.
- **Verification gates** — the Judge issues `CONFIRMED` / `LIKELY` / `NEEDS CONTEXT` / `FALSE POSITIVE` verdicts; only confirmed/likely findings are reported, and dismissing one requires citing the exact protecting line.

---

## Cross-scan memory

Each scan writes its working artifacts to a `.llm-sast-scanner-cache/` folder in the target repo. Alongside the architecture/threat-model brief, the orchestrator maintains a **`project-memory.md`** — a per-repository knowledge file that persists and grows across scans, recording confirmed findings, confirmed false-positive patterns (with rationale), project-specific security primitives (sanitizers/validators/auth wrappers), and hotspots. Repeat scans reuse it to prioritize effort and avoid re-deriving the same context.

It is deliberately treated as **hints, never authority**, with guardrails that keep it from degrading detection:

- Memory may prioritize or explain a known-safe pattern, but it can **never** make an agent skip a line or auto-dismiss a vulnerability class — 100% coverage discipline is unchanged.
- A "false positive" entry only suppresses a re-report after the agent **re-confirms the safe rationale in the current code**; stale entries (the file changed since the recorded git SHA) are re-verified.
- The file's content is consumed as untrusted **data, not instructions**, so a poisoned cache can't redirect a scan.
- Secrets and PII are never persisted — entries record class + `file:line` + a neutral description, with sensitive values redacted.
- A **single writer** (the consolidation/report step) updates it; detection agents are read-only, so parallel lenses never corrupt it.

---

## Languages & ecosystems

- **Application languages:** Java, Python, JavaScript / TypeScript, PHP, C# / .NET, Go, Ruby, C / C++, Kotlin, Swift, Objective-C, Rust
- **Smart contracts:** Solidity / EVM
- **Infrastructure, config & markup:** Terraform / HCL, Kubernetes & CI/CD YAML, Dockerfile, nginx config, XML, SQL, HTML

Java, Python, JavaScript/TypeScript, PHP, and C#/.NET have the deepest dedicated rule sets; the rest are covered with vulnerable-vs-secure detection patterns across the relevant classes.

---

## Vulnerability coverage

102 reference knowledge bases, organized into categories:

| Category | Focus |
|----------|-------|
| **Injection** | SQLi, XSS, RCE/command injection, environment variable injection, SSTI, SSI/ESI injection, NoSQL, GraphQL, XXE, XSLT, LDAP, XPath, prototype pollution, prompt injection, and more |
| **Access Control & Auth** | IDOR/BOLA, privilege escalation & missing auth, JWT/OAuth/OIDC/SAML/MFA, default credentials, hardcoded secrets (CWE-798, secret literals at rest / client-exposure model), brute force, verification-code abuse, business logic, mass assignment, session fixation & puzzling, reverse-proxy access bypass, email-parser differential, BaaS client-side authorization (Supabase RLS / Firebase Security Rules) |
| **Data Exposure & Crypto** | weak crypto/hashing, information disclosure, insecure cookies, TLS/certificate validation, cleartext transmission, shared-client cache/dedup cross-user leak, trust-boundary, client-IP/network-origin trust (XFF spoofing), privacy/PII handling |
| **Server-Side Attacks** | SSRF, path traversal/LFI/RFI, client-side path traversal, prototype pollution (client & server), insecure deserialization, file upload, JNDI, race conditions, temp-file & permission issues |
| **Protocol & Infrastructure** | CSRF, open redirect, reverse tabnabbing, request smuggling, response splitting, host-header poisoning, correlation/tracing header injection, CORS, WebSockets, postMessage, XSSI/JSONP, clickjacking, CSP, XS-Leaks, cache deception, DoS/ReDoS, GraphQL DoS |
| **Cloud & IaC** | Terraform/CloudFormation/ARM/Bicep/Pulumi, subdomain takeover (dangling-DNS candidate flagging), Kubernetes/cloud orchestration, CI/CD & container/Docker security, nginx/web-server configuration |
| **API & AI/Agent Services** | REST/web-service security, gRPC/gRPC-Web/Connect server-side security, webhook/integration security, MCP (Model Context Protocol) security |
| **AI / LLM Application Security** | OWASP LLM Top 10 — prompt injection, insecure output handling, excessive agency, system-prompt leakage, RAG/vector weaknesses, ML supply-chain poisoning, agent config poisoning |
| **Output & Hardening** | output encoding, format strings, ASP.NET misconfiguration, embedded malicious code, improper input validation (semantic-type mismatch) |
| **Supply Chain** | dependency confusion, unpinned/unverified dependencies, malicious lifecycle scripts |
| **Language / Platform** | PHP, Android security, iOS security, Electron/desktop app security, C/C++ memory safety, Solidity smart contracts, batch/ETL/mainframe pipelines |

The full per-class list (with files and CWE mappings) lives in `llm-sast-scanner/references/`.

---

## Severity model

| Severity | Criteria |
|----------|----------|
| **Critical** | Direct RCE, authentication bypass, unauthenticated data exposure |
| **High** | SQLi, SSRF, IDOR with sensitive data, stored XSS, privilege escalation |
| **Medium** | Reflected XSS, CSRF, path traversal, insecure deserialization |
| **Low** | Information disclosure, open redirect, weak crypto, insecure cookie |
| **Info** | Missing security headers, verbose errors, defense-in-depth gaps |

Exploitation that requires authentication, non-default config, chaining, or admin/internal-only access is downgraded one level from the class default.

---

## Installation

From the repository directory, **symlink** both skill directories into the skills folder for your agent runtime — a single `git pull` then updates every runtime at once, with no stale copies to re-sync. Link the real top-level directories (not the `.claude`/`.agents` symlinks), using absolute paths so the links resolve from anywhere:

```bash
cd /path/to/llm-sast-scanner

# Claude Code
mkdir -p ~/.claude/skills
ln -s "$(pwd)/llm-sast-scanner" "$(pwd)/llm-sast-scanner-full-scan-loop" ~/.claude/skills/

# OpenAI Codex / Cursor / other agent runtimes
mkdir -p ~/.agents/skills
ln -s "$(pwd)/llm-sast-scanner" "$(pwd)/llm-sast-scanner-full-scan-loop" ~/.agents/skills/
```

To update later, just `git pull` in the repo — the symlinks always point at the latest version.

To use the parallel orchestrator, also place `AGENTS.md` (and/or `CLAUDE.md`) at the root of the project you want to scan.

---

## Usage

**Targeted or scoped scan** — run the core skill on a file, directory, or whole repo:

```
llm-sast-scanner [adv=critical,high,medium]
```

Without arguments it runs the detection + Judge workflow. The optional `adv=` flag selects which severities also go through the adversarial impact pass.

**Exhaustive whole-repository audit** — run the convergence loop until no new bugs are found, with guaranteed 100% line coverage:

```
llm-sast-scanner-full-scan-loop <dir> [mode=parallel|single] [adv=critical,high,medium]
```

`mode=parallel` (default) dispatches one subagent per vulnerability lens and consolidates the results; `mode=single` runs everything in one context for the strongest convergence guarantee. Output is a timestamped `sast_report-<timestamp>.md`.

**Parallel multi-agent orchestration** — point your agent at `AGENTS.md` / `CLAUDE.md` to run a full assessment (codebase analysis → parallel detection across six vulnerability lenses → consolidated report) written to a `.llm-sast-scanner-cache/` folder. It is re-runnable: steps whose output already exists are skipped, and the run updates `project-memory.md` (see [Cross-scan memory](#cross-scan-memory)) so later scans build on earlier ones. Add `.llm-sast-scanner-cache/` to the scanned repo's `.gitignore`.

---

## Repository structure

```
llm-sast-scanner/                      ← repo root
├── README.md
├── AGENTS.md                          # parallel orchestrator playbook
├── CLAUDE.md                          # → symlink to AGENTS.md
├── llm-sast-scanner/                  # core skill (canonical source)
│   ├── SKILL.md                       # 7-step workflow + Judge + adversarial + project-memory protocol
│   └── references/                    # 102 vulnerability knowledge bases
├── llm-sast-scanner-full-scan-loop/   # exhaustive convergence-audit skill
│   └── SKILL.md
├── .claude/skills/                    # → symlinks to the two skill dirs above
└── .agents/skills/                    # → symlinks to the two skill dirs above
```

---

## License

MIT License — free to use, modify, and distribute with attribution.

## Contributing

Contributions are welcome to help improve detection rates and coverage.
