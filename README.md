# llm-sast-scanner

A general-purpose **Static Application Security Testing (SAST) skill** for LLM-based code vulnerability analysis. It is loaded by AI coding agents (Claude Code, OpenAI Codex, Cursor, and other agent runtimes) to perform structured **source → sink taint analysis** across **81 vulnerability classes** (including the OWASP LLM Top 10 for AI/agent apps), with a Judge verification stage, an optional adversarial impact pass, and a parallel multi-agent orchestration mode for whole-repo audits.

---

## What's in this repo

| Component | What it is |
|-----------|-----------|
| **`llm-sast-scanner/`** | The core skill — a 7-step detection workflow + Judge verification + adversarial validation, backed by 81 vulnerability reference knowledge bases. |
| **`llm-sast-scanner-full-scan-loop/`** | A wrapper skill for an exhaustive, convergence-driven, line-by-line audit of an entire repository. Runs one subagent per vulnerability lens in parallel (or single-context), guarantees 100% line coverage, and writes a timestamped report. |
| **`AGENTS.md` / `CLAUDE.md`** | The repo-level orchestrator playbook. Drives the parallel lens fan-out and report consolidation. `CLAUDE.md` is a symlink to `AGENTS.md`. |
| **`.claude/skills/`, `.agents/skills/`** | Per-runtime skill discovery directories. Both are **symlinks to the single canonical skill source** at the repo root, so there is exactly one copy of every skill file and the two runtimes can never drift apart. |

---

## What it does

The core skill gives an agent a structured, evidence-based workflow for finding security vulnerabilities in source code:

1. **Understand scope** — target, languages/frameworks, and goal (quick scan, deep audit, single class, full report)
2. **Load references** — pull in only the vulnerability knowledge bases that match the stack in use
3. **Trace taint** — read each file once and evaluate every loaded lens: sources → data flow → sinks → sanitizers
4. **Business logic & auth analysis** — missing authZ, IDOR, broken state machines, race conditions, shared-state cross-user leaks
5. **Judge** — an adversarial second opinion re-verifies every candidate (reachability / sanitization / exploitability) to eliminate false positives
6. **Adversarial impact validation** *(optional, via `adv=`)* — stress-test surviving findings for real-world exploitability
7. **Report** — actionable findings with severity, exact file path + line number, evidence, and concrete remediation

### Languages & ecosystems

- **Application languages:** Java, Python, JavaScript / TypeScript, PHP, C# / .NET, Go, Ruby, C / C++, Kotlin, Swift, Objective-C, Rust
- **Smart contracts:** Solidity / EVM
- **Infrastructure, config & markup:** Terraform / HCL, Kubernetes & CI/CD YAML, Dockerfile, XML, SQL, HTML

Java, Python, JavaScript/TypeScript, PHP, and C#/.NET have the deepest, dedicated source-detection rule sets; the remaining languages are covered with vulnerable-vs-secure detection patterns across the relevant vulnerability classes.

---

## Installation

Clone the repo, then copy **both** skill directories into the skills folder for your agent runtime. Copy the real top-level directories (not the `.claude`/`.agents` symlinks).

```bash
git clone https://github.com/anthropic-lab/llm-sast-scanner.git
cd llm-sast-scanner

# Claude Code
cp -R llm-sast-scanner llm-sast-scanner-full-scan-loop ~/.claude/skills/

# OpenAI Codex / Cursor / other agent runtimes
cp -R llm-sast-scanner llm-sast-scanner-full-scan-loop ~/.agents/skills/
```

To use the parallel orchestrator, also place `AGENTS.md` (and/or `CLAUDE.md`) at the root of the project you want to scan, or point your agent at it.

---

## Usage

### Single skill — targeted or scoped scan

Invoke the core skill on a file, directory, or whole repo:

```
llm-sast-scanner [adv=critical,high,medium]
```

- Without arguments it runs Steps 1–5 and 7 (no adversarial pass).
- `adv=` selects which severities go through **Step 6: Adversarial Impact Validation** (case-insensitive, comma-separated; valid values: `critical`, `high`, `medium`, `low`, `info`).

| Invocation | Adversarial validation applied to |
|------------|-----------------------------------|
| `llm-sast-scanner` | none — Step 6 skipped |
| `llm-sast-scanner adv=critical` | Critical only |
| `llm-sast-scanner adv=critical,high` | Critical + High |
| `llm-sast-scanner adv=critical,high,medium` | Critical + High + Medium |

### Exhaustive convergence audit — whole repository

```
llm-sast-scanner-full-scan-loop <dir> [mode=parallel|single] [adv=critical,high,medium]
```

- `<dir>` — repository/directory to audit (defaults to the current directory).
- `mode=parallel` *(default)* — dispatches **one subagent per vulnerability lens**; each runs the convergence loop (Steps 1–5) in its own context until it stops finding new bugs, with a deterministic **scope manifest** ensuring 100% line coverage. A consolidation subagent then merges + de-duplicates findings, runs the adversarial pass once, and writes the report.
- `mode=single` — runs the whole convergence loop in one context (strongest convergence/coverage guarantee; one context owns the ledger + coverage map).
- Output: a timestamped `sast_report-<timestamp>.md`.

### Parallel multi-agent orchestration (`AGENTS.md` / `CLAUDE.md`)

The orchestrator playbook coordinates a full assessment and writes everything to a `sast/` folder (re-runnable — steps whose output already exists are skipped):

1. **Codebase analysis & threat modeling** → `sast/architecture.md`
2. **Vulnerability detection (parallel)** — one subagent per lens, each writing `sast/<lens>-results.md`
3. **Report generation** — consolidates and de-duplicates into `sast/final-report.md`

The work is split across six vulnerability lenses, each running in an isolated context:

| Lens | Vulnerability classes |
|------|-----------------------|
| **injection** | SQLi, XSS, client-side prototype pollution, SSTI, SSI injection, NoSQLi, GraphQL, XXE, RCE/command injection, expression-language, LDAP, XPath/XQuery, CSV/formula, log injection, prompt injection |
| **access-auth** | IDOR, privilege escalation / missing auth (BFLA), authentication & JWT, default credentials, brute force, business logic, HTTP method tampering, verification code abuse, session fixation, mass assignment |
| **crypto-data** | weak crypto/hash, information disclosure, insecure cookie, trust boundary, shared-client cache/dedup cross-user leak, cleartext transmission, certificate/TLS validation |
| **server-side** | SSRF, path traversal/LFI/RFI, client-side path traversal, server-side prototype pollution, insecure deserialization, arbitrary file upload, JNDI injection, race conditions, insecure temp file, file permissions |
| **protocol-infra** | CSRF, open redirect, reverse tabnabbing, request smuggling/desync, response splitting, host header poisoning, CORS misconfiguration, WebSocket security (CSWSH), clickjacking, web cache deception, DoS, regex injection/ReDoS, CVE patterns |
| **hardening-platform** | output encoding, format string, ASP.NET misconfiguration, hardcoded/backdoor code, dependency confusion, PHP security, mobile security |

> **Skill resolution:** subagents invoke skills by name. Each runtime loads them from its own directory — Claude Code from `.claude/skills/`, Codex/Cursor/other agents from `.agents/skills/`. Both directories symlink to the same canonical source, so the two runtimes always run identical skill content.

---

## Workflow detail

The core skill (`llm-sast-scanner/SKILL.md`) defines the full protocol:

- **Read-once discipline** — each source file is read once and evaluated against every loaded lens, keeping total read cost ~1× the codebase regardless of how many classes are in scope.
- **Sources / sinks / sanitizers** — every reference documents per-language entry points, dangerous sinks, and the barriers that neutralize them; recognized barriers are required before ruling a finding SAFE.
- **Judge verdicts** — `CONFIRMED`, `LIKELY`, `NEEDS CONTEXT`, or `FALSE POSITIVE`. Only `CONFIRMED`/`LIKELY` are reported; declaring a false positive requires citing the exact protecting line.
- **False-positive guardrails** — explicit rules for demo/example code, non-default config, internal-only services, protocol-required SSRF, bounded DoS, trusted admin roles, and more.
- **Adversarial verdicts** — `STANDING`, `DOWNGRADED`, `DISPUTED`, or `WITHDRAWN`, applied to finalize severity.

### Severity model

| Severity | Criteria |
|----------|----------|
| **Critical** | Direct RCE, authentication bypass, unauthenticated data exposure |
| **High** | SQLi, SSRF, IDOR with sensitive data, stored XSS, privilege escalation |
| **Medium** | Reflected XSS, CSRF, path traversal, insecure deserialization |
| **Low** | Information disclosure, open redirect, weak crypto, insecure cookie |
| **Info** | Missing security headers, verbose errors, defense-in-depth gaps |

Exploitation that requires authentication, non-default config, chaining, or admin/internal-only access is downgraded one level from the class default.

---

## Repository structure

```
llm-sast-scanner/                      ← repo root
├── README.md
├── AGENTS.md                          # parallel orchestrator playbook
├── CLAUDE.md                          # → symlink to AGENTS.md
├── llm-sast-scanner/                  # core skill (canonical source)
│   ├── SKILL.md                       # 7-step workflow + Judge + adversarial
│   └── references/                    # 81 vulnerability knowledge bases
├── llm-sast-scanner-full-scan-loop/   # exhaustive convergence-audit skill
│   └── SKILL.md
├── .claude/skills/                    # → symlinks to the two skill dirs above
│   ├── llm-sast-scanner
│   └── llm-sast-scanner-full-scan-loop
└── .agents/skills/                    # → symlinks to the two skill dirs above
    ├── llm-sast-scanner
    └── llm-sast-scanner-full-scan-loop
```

---

## Vulnerability coverage

81 reference files across the following categories.

### Injection
| File | Vulnerability |
|------|--------------|
| `sql_injection.md` | SQL Injection (CWE-89) |
| `xss.md` | Cross-Site Scripting (CWE-79) |
| `client_side_prototype_pollution.md` | Client-Side Prototype Pollution (CSPP) — gadget catalog, browser-API gadgets, sanitizer bypasses (CWE-1321 / 79 / 94 / 400 / 471) |
| `ssti.md` | Server-Side Template Injection |
| `ssi_injection.md` | Server-Side Include (SSI) Injection — #exec RCE, #include/#printenv disclosure (CWE-97) |
| `nosql_injection.md` | NoSQL Injection |
| `graphql_injection.md` | GraphQL Injection / Introspection Abuse |
| `xxe.md` | XML External Entity (CWE-611) |
| `rce.md` | Remote Code Execution / Command Injection |
| `expression_language_injection.md` | Expression Language Injection (SpEL, OGNL) |
| `ldap_injection.md` | LDAP Injection — RFC 4515 filter / RFC 4514 DN escaping (CWE-90) |
| `xpath_injection.md` | XPath / XQuery / XML Injection (CWE-643 / 652 / 91) |
| `csv_injection.md` | CSV / Formula Injection (CWE-1236) |
| `log_injection.md` | Log Injection / Log Forging (CWE-117) |
| `prompt_injection.md` | LLM Prompt Injection (CWE-1427) |
| `dom_clobbering.md` | DOM Clobbering — attacker id/name HTML shadowing JS globals/DOM APIs |

### Access Control & Auth
| File | Vulnerability |
|------|--------------|
| `idor.md` | Insecure Direct Object Reference / BOLA |
| `privilege_escalation.md` | Privilege Escalation + Missing Auth / Broken Function-Level Authorization (BFLA) |
| `authentication_jwt.md` | Authentication / JWT / OAuth2 / SAML / MFA weaknesses |
| `default_credentials.md` | Hardcoded / Default Credentials |
| `brute_force.md` | Brute Force / Credential Stuffing / Missing Rate Limiting |
| `business_logic.md` | Business Logic Flaws |
| `http_method_tamper.md` | HTTP Method Tampering |
| `verification_code_abuse.md` | Verification Code Abuse |
| `session_fixation.md` | Session Fixation & Lifecycle (CWE-384) |
| `mass_assignment.md` | Mass Assignment / Autobinding of Privileged Fields (CWE-915) |

### Data Exposure & Crypto
| File | Vulnerability |
|------|--------------|
| `weak_crypto_hash.md` | Weak Crypto / Hash / Random + password & key storage (CWE-327 / 328 / 330) |
| `information_disclosure.md` | Sensitive Information Disclosure / verbose errors |
| `insecure_cookie.md` | Insecure Cookie Attributes (CWE-614 / 1004) |
| `trust_boundary.md` | Trust Boundary Violation (CWE-501) |
| `shared_client_cache_leak.md` | Shared-Client Cache/Dedup Cross-User Leak (CWE-488 / 524 / 567 / 362) |
| `cleartext_transmission.md` | Cleartext Transmission / Missing or Weak TLS (CWE-319 / 311) |
| `certificate_validation.md` | TLS Certificate / Hostname / Pinning / Revocation Failures (CWE-295 / 297 / 299 / 322) |
| `privacy_data_protection.md` | Privacy / Data Protection — PII over-collection, retention, PII in logs/URLs/third parties (CWE-359 / 200) |

### Server-Side Attacks
| File | Vulnerability |
|------|--------------|
| `ssrf.md` | Server-Side Request Forgery |
| `path_traversal_lfi_rfi.md` | Path Traversal, LFI, RFI (CWE-22) |
| `client_side_path_traversal.md` | Client-Side Path Traversal (CSPT) across React/Next/Vue/Angular/SvelteKit/Nuxt/Ember/SolidStart |
| `server_side_prototype_pollution.md` | Server-Side Prototype Pollution (SSPP) — sinks + Node.js / Deno gadget catalog (CWE-1321) |
| `insecure_deserialization.md` | Insecure Deserialization |
| `arbitrary_file_upload.md` | Arbitrary File Upload |
| `jndi_injection.md` | JNDI Injection (Log4Shell class) |
| `race_conditions.md` | Race Conditions / TOCTOU |
| `insecure_temp_file.md` | Insecure Temporary File Creation / Predictable Names (CWE-377) |
| `file_permissions.md` | Incorrect Permission Assignment / World-Writable Files / Weak DACLs (CWE-732) |

### Protocol & Infrastructure
| File | Vulnerability |
|------|--------------|
| `csrf.md` | Cross-Site Request Forgery |
| `open_redirect.md` | Open Redirect / Unvalidated Forwards |
| `reverse_tabnabbing.md` | Reverse Tabnabbing — target="_blank"/window.open without rel="noopener" (CWE-1022) |
| `smuggling_desync.md` | HTTP Request Smuggling / Desync |
| `http_response_splitting.md` | HTTP Response Splitting / Header Injection (CWE-113) |
| `host_header_poisoning.md` | Host Header Poisoning / Email-Link Injection (CWE-640) |
| `cors_misconfiguration.md` | CORS Misconfiguration / Permissive Origin Reflection (CWE-346 / 942) |
| `websocket_security.md` | WebSocket Security — CSWSH (missing Origin check), missing connection/per-message auth, unsanitized broadcast (CWE-345 / 284 / 346) |
| `clickjacking.md` | Clickjacking / Missing X-Frame-Options / CSP frame-ancestors (CWE-451) |
| `content_security_policy.md` | CSP Weaknesses — missing/weak policy, unsafe-inline/eval, wildcard sources, allowlist bypass (CWE-693 / 1021) |
| `xs_leaks.md` | Cross-Site Leaks — timing/frame/status/cache oracles, missing COOP/COEP/CORP/Fetch-Metadata (CWE-200) |
| `web_cache_deception.md` | Web Cache Deception / Cache Poisoning (CWE-525) |
| `denial_of_service.md` | Denial of Service / Resource Exhaustion |
| `regex_injection_redos.md` | Regex Injection / ReDoS / Incomplete Regex Validation (CWE-730 / 1333 / 20 / 625 / 116) |
| `cve_patterns.md` | Known CVE Patterns |

### Cloud & Infrastructure-as-Code
| File | Vulnerability |
|------|--------------|
| `iac_security.md` | IaC Misconfiguration — Terraform/CloudFormation/ARM/Bicep/Pulumi (public storage, open security groups, wildcard IAM, missing encryption) |
| `kubernetes_cloud_security.md` | Kubernetes / Cloud Orchestration — privileged pods, hostPath/hostNetwork, RBAC over-permission, missing securityContext/NetworkPolicy, secrets in manifests |
| `cicd_container_security.md` | CI/CD Pipeline + Container/Docker Security — poisoned pipeline execution, untrusted workflow inputs, root images, unpinned tags, build-time secrets |

### API & AI/Agent Services
| File | Vulnerability |
|------|--------------|
| `api_security.md` | API / REST / Web-Service Security — excessive data exposure, missing rate limiting, endpoint inventory, security misconfig |
| `mcp_security.md` | MCP (Model Context Protocol) Security — tool poisoning, injection via tool output, over-broad/unauthenticated servers, token passthrough |

### AI / LLM Application Security (OWASP LLM Top 10)
| File | Vulnerability |
|------|--------------|
| `prompt_injection.md` | LLM01 Prompt Injection — direct & indirect (also listed under Injection) |
| `insecure_output_handling.md` | LLM05 Insecure Output Handling — model output reaching HTML/SQL/shell/HTTP/eval sinks (CWE-79/89/78/918) |
| `excessive_agency.md` | LLM06 Excessive Agency — over-broad tool functionality/permissions/autonomy without human approval (CWE-250/269/862) |
| `system_prompt_leakage.md` | LLM07 System Prompt Leakage — secrets/authorization logic in prompts, reliance on prompt secrecy (CWE-200/522/312) |
| `rag_vector_security.md` | LLM08 Vector & Embedding Weaknesses — permission-blind retrieval, cross-tenant leak, indirect injection via documents (CWE-285/863/200) |
| `ml_supply_chain_poisoning.md` | LLM03/04 ML Supply Chain & Data/Model Poisoning — unsafe model deserialization, `trust_remote_code`, unverified artifacts, training-data poisoning (CWE-502/494/829) |
| `ai_editor_config_poisoning.md` | AI Editor / Agent Config Poisoning (repo poisoning) — weaponized agent instruction & editor config files (`.cursorrules`, `CLAUDE.md`, `AGENTS.md`, `SKILL.md`, `.mcp.json`), hidden-unicode/HTML payloads, approval/YOLO-mode bypass (CWE-94/116/829/506) |

> LLM02 (sensitive disclosure) and LLM10 (unbounded consumption) are covered as dedicated sections within `information_disclosure.md` and `denial_of_service.md`; `mcp_security.md` covers agent tool-protocol risks.

### Output & Hardening
| File | Vulnerability |
|------|--------------|
| `output_encoding.md` | Inappropriate Encoding for Output Context / Encoder-Context Mismatch (CWE-838) |
| `format_string_injection.md` | Externally-Controlled Format String (CWE-134) |
| `aspnet_security_misconfig.md` | ASP.NET Security Misconfiguration — debug binary, disabled request validation (CWE-11 / 16) |
| `hardcoded_code_backdoor.md` | Embedded Malicious Code / Supply-Chain Backdoor Patterns (CWE-506) |

### Supply Chain
| File | Vulnerability |
|------|--------------|
| `dependency_confusion.md` | Dependency Confusion / substitution across npm, PyPI, RubyGems, Maven/Gradle, NuGet, Go, Composer, Cargo (CWE-1357) |
| `supply_chain_security.md` | Supply Chain Security — unpinned/unlocked deps, missing integrity hashes/SRI, malicious lifecycle scripts, untrusted registries, provenance gaps (CWE-1104 / 829) |

### Language / Platform
| File | Vulnerability |
|------|--------------|
| `php_security.md` | PHP-specific security issues |
| `mobile_security.md` | Mobile security (Android / iOS) — insecure storage, IPC/exported components, WebView, transport |
| `memory_safety_c_cpp.md` | C/C++ Memory Safety — buffer overflow, use-after-free, double-free, unsafe string functions, integer overflow, null deref, toolchain hardening (CWE-119 / 120 / 416 / 190 / 787) |
| `smart_contract_security.md` | Smart Contract Security (Solidity / EVM) — reentrancy, access control, unsafe `delegatecall`/low-level calls, integer over/underflow, DoS, front-running/MEV, insecure randomness, oracle manipulation, proxy/upgrade hazards, ERC-20/721/1155 pitfalls (CWE-841 / 284 / 682) |
| `batch_etl_pipeline_security.md` | Batch / ETL / Mainframe Data-Pipeline Security — job-param & record-field path traversal, landing-dir TOCTOU, fixed-width/COMP-3/EBCDIC parse bounds, trailer integrity, restart double-post (CWE-22 / 78 / 367 / 125 / 707) |

---

## Advanced usage tips

- **Precompute the call graph before scanning** — improves cross-function reasoning and reduces missed paths
- **Run 2+ scanning rounds** — increases recall and stabilizes findings via iterative refinement
- **Enforce per-finding validation** — the Judge + adversarial passes significantly cut false positives
- **Use the full-scan-loop for whole-repo audits** — it guarantees 100% line coverage against a deterministic scope manifest

---

## License

MIT License — free to use, modify, and distribute with attribution.

---

## Contributing

Contributions are welcome to help improve detection rates and coverage.
