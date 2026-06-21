---
name: llm-sast-scanner
description: >
  General-purpose Static Application Security Testing (SAST) skill for code vulnerability analysis.
  Trigger when the user asks to: "analyze code for vulnerabilities", "review code security", "find security bugs",
  "do a SAST scan", "check for [vulnerability type] in code", "audit source code", or requests a security
  code review of any language or framework.   Covers 81 vulnerability classes across web, API, auth, mobile, cloud/infrastructure, AI/LLM, and logic layers.
  Accepts optional tagged arguments, e.g. "llm-sast-scanner adv=critical,high" for adversarial validation.
metadata:
  version: "1.30.0"
  domain: application-security
  references: 81 vulnerability knowledge bases
---

# SAST Vulnerability Analysis

## Purpose

Systematically analyze source code for security vulnerabilities using structured Source→Sink taint tracking,
pattern matching, and vulnerability-class-specific detection heuristics. Produce actionable findings with
severity ratings, affected code locations (file + line number), and remediation guidance.

## Scope

This skill covers the following 81 vulnerability classes. Each has a dedicated reference file loaded on demand,
documenting the sources, sinks, and sanitizers/barriers used to detect and triage that class:

| Category | Vulnerabilities |
|----------|----------------|
| **Injection** | SQL Injection, XSS, Client-Side Prototype Pollution (CSPP), SSTI, Server-Side Include (SSI) Injection, NoSQL Injection, GraphQL Injection, XXE, RCE / Command Injection, Expression Language Injection, LDAP Injection, XPath/XQuery Injection, CSV/Formula Injection, Log Injection, Prompt Injection (LLM), DOM Clobbering |
| **Access Control & Auth** | IDOR, Privilege Escalation, Authentication/JWT, Default Credentials, Brute Force, Business Logic, HTTP Method Tampering, Verification Code Abuse, Session Fixation, Mass Assignment |
| **Data Exposure & Crypto** | Weak Crypto/Hash, Information Disclosure, Insecure Cookie, Trust Boundary, Shared-Client Cache/Dedup Cross-User Leak, Cleartext Transmission, Certificate/TLS Validation, Privacy / Data Protection |
| **Server-Side** | SSRF, Path Traversal/LFI/RFI, Client Side Path Traversal (CSPT), Server-Side Prototype Pollution (SSPP), Insecure Deserialization, Arbitrary File Upload, JNDI Injection, Race Conditions, Insecure Temp File, File Permissions |
| **Protocol & Infrastructure** | CSRF, Open Redirect, Reverse Tabnabbing, HTTP Request Smuggling/Desync, HTTP Response Splitting, Host Header Poisoning, CORS Misconfiguration, WebSocket Security (CSWSH), Clickjacking, Content Security Policy (CSP) Weaknesses, XS-Leaks, Web Cache Deception/Poisoning, Denial of Service, Regex Injection/ReDoS, CVE Patterns |
| **Cloud & Infrastructure-as-Code** | IaC Security (Terraform/CloudFormation/ARM/Bicep/Pulumi), Kubernetes / Cloud Orchestration, CI/CD & Container Security |
| **API & AI/Agent Services** | API / REST / Web-Service Security, MCP (Model Context Protocol) Security |
| **AI / LLM Application Security** | Prompt Injection (LLM01, see Injection), Insecure Output Handling (LLM05), Excessive Agency (LLM06), System Prompt Leakage (LLM07), RAG / Vector & Embedding Security (LLM08), ML Supply Chain & Data/Model Poisoning (LLM03/04), AI Editor / Agent Config Poisoning (repo poisoning) |
| **Output & Hardening** | Output Encoding (context mismatch), Format String Injection, ASP.NET Security Misconfiguration, Hardcoded Code / Backdoor |
| **Supply Chain** | Dependency Confusion (candidate flagging across npm/PyPI/RubyGems/Maven/Gradle/NuGet/Go/Composer/Cargo), Supply Chain Security (dependency integrity, SRI, lifecycle scripts, provenance) |
| **Language/Platform** | PHP Security, Mobile Security (Android/iOS), C/C++ Memory Safety, Smart Contract Security (Solidity/EVM), Batch / ETL / Mainframe Data-Pipeline Security |

---

## Arguments

This skill accepts optional tagged arguments using `key=value` syntax.

**Syntax:** `llm-sast-scanner [arg=value ...]`

### `adv` — Adversarial Impact Validation severities

Controls which severity levels go through **Step 6: Adversarial Impact Validation**.

| Invocation | Adversarial Validation Applied To |
|------------|-----------------------------------|
| `llm-sast-scanner adv=critical,high,medium` | Critical, High, and Medium findings |
| `llm-sast-scanner adv=critical,high` | Critical and High findings |
| `llm-sast-scanner adv=critical` | Critical findings only |
| `llm-sast-scanner adv=high` | High findings only |
| `llm-sast-scanner` | **None** — Step 6 is skipped entirely; all Judge-passed findings go straight to the report |

- Severity values are **case-insensitive**: `Critical`, `CRITICAL`, and `critical` are all equivalent.
- Multiple values are **comma-separated** with no spaces: `adv=critical,high,medium`.
- Only `critical`, `high`, `medium`, `low`, and `info` are valid values. Invalid values are ignored with a warning.
- When `adv` is omitted, the scan runs Steps 1–5 and 7 (report) without adversarial validation.

---

## Workflow

### Step 1: Understand Scope

Determine:
- Target: single file, directory, API endpoint, module, or full repo
- Language(s) and framework(s) in use
- User's goal: quick scan, deep audit, specific vuln class, or full report

### Step 2: Load Relevant References

Based on the code being reviewed, load the appropriate reference files from `references/`:

```
references/sql_injection.md          — SQL / ORM injection
references/xss.md                    — Cross-site scripting
references/ssrf.md                   — Server-side request forgery
references/rce.md                    — Remote code execution
references/idor.md                   — Insecure direct object reference
references/authentication_jwt.md     — Auth flaws, JWT weaknesses
references/csrf.md                   — Cross-site request forgery
references/path_traversal_lfi_rfi.md — Path traversal, LFI/RFI
references/client_side_path_traversal.md — Client Side Path Traversal (CSPT) across React/Next/Vue/Angular/SvelteKit/Nuxt/Ember/SolidStart
references/server_side_prototype_pollution.md — Server-Side Prototype Pollution (Node.js / Deno / NPM gadget catalog)
references/client_side_prototype_pollution.md — Client-Side Prototype Pollution (BlackFan PP/gadget catalog, browser-API gadgets, sanitizer bypasses)
references/ssti.md                   — Server-side template injection
references/ssi_injection.md          — Server-Side Include (SSI) injection: #exec RCE, #include/#printenv disclosure on SSI-parsed pages (CWE-97)
references/xxe.md                    — XML external entity
references/insecure_deserialization.md    — Insecure deserialization
references/arbitrary_file_upload.md      — Arbitrary file upload
references/privilege_escalation.md       — Privilege escalation
references/nosql_injection.md            — NoSQL injection
references/graphql_injection.md          — GraphQL injection
references/weak_crypto_hash.md           — Weak cryptography / hash
references/information_disclosure.md     — Information disclosure
references/insecure_cookie.md            — Insecure cookie attributes
references/open_redirect.md              — Open redirect
references/reverse_tabnabbing.md         — Reverse tabnabbing: target="_blank"/window.open without rel="noopener" exposing window.opener (CWE-1022)
references/websocket_security.md         — WebSocket security: CSWSH (missing Origin check), missing connection/per-message auth, unsanitized broadcast (CWE-345/284/346)
references/trust_boundary.md             — Trust boundary violations
references/race_conditions.md            — Race conditions / TOCTOU
references/brute_force.md                — Brute force / credential stuffing
references/default_credentials.md        — Default / hardcoded credentials
references/verification_code_abuse.md    — Verification code abuse
references/business_logic.md             — Business logic flaws
references/http_method_tamper.md         — HTTP method tampering
references/smuggling_desync.md           — HTTP request smuggling / desync
references/web_cache_deception.md        — Web cache deception / cache poisoning (cached personalized data, unkeyed-input poisoning)
references/shared_client_cache_leak.md   — Cross-user leak via shared client caches / request dedup-coalescing / mutable-auth singletons / pooled-connection & thread-local reuse / module-global request state (in-process, all client libs & languages)
references/dependency_confusion.md       — Dependency confusion candidate flagging (npm/PyPI/RubyGems/Maven/Gradle/NuGet/Go/Composer/Cargo)
references/cve_patterns.md               — Known CVE patterns
references/expression_language_injection.md — Expression language injection (SpEL / OGNL)
references/jndi_injection.md             — JNDI injection (Log4Shell class)
references/denial_of_service.md          — Denial of service / resource exhaustion
references/php_security.md               — PHP-specific security issues
references/mobile_security.md            — Mobile security (Android / iOS)
references/session_fixation.md           — Session fixation
references/ldap_injection.md             — LDAP injection (CWE-090, RFC 4515 filter/DN escaping)
references/xpath_injection.md            — XPath (CWE-643), XQuery (CWE-652), XML injection (CWE-091)
references/cors_misconfiguration.md      — CORS misconfiguration / permissive origin reflection (CWE-346/942)
references/http_response_splitting.md    — HTTP response splitting / header injection (CWE-113)
references/host_header_poisoning.md      — Host header poisoning / email-link injection (CWE-640)
references/clickjacking.md               — Clickjacking / missing X-Frame-Options / CSP frame-ancestors (CWE-451)
references/log_injection.md              — Log injection / log forging (CWE-117)
references/certificate_validation.md     — TLS certificate / hostname / pinning / revocation failures (CWE-295/297/299/322)
references/cleartext_transmission.md     — Cleartext transmission, missing TLS (CWE-319/311)
references/mass_assignment.md            — Mass assignment / autobinding of privileged fields (CWE-915)
references/regex_injection_redos.md      — Regex injection, ReDoS, incomplete regex/URL validation (CWE-730/1333/020/625/116)
references/csv_injection.md              — CSV / formula injection on spreadsheet export (CWE-1236)
references/prompt_injection.md           — LLM prompt injection (CWE-1427)
references/file_permissions.md           — Incorrect permission assignment / world-writable files / weak DACLs (CWE-732)
references/insecure_temp_file.md         — Insecure temporary file creation / predictable names / race window (CWE-377)
references/format_string_injection.md    — Externally-controlled format strings in printf-style APIs (CWE-134)
references/output_encoding.md            — Inappropriate encoding for output context, encoder/context mismatch (CWE-838)
references/hardcoded_code_backdoor.md    — Embedded malicious code / supply-chain backdoor patterns (CWE-506)
references/aspnet_security_misconfig.md  — ASP.NET misconfiguration: debug binary, disabled request validation (CWE-011/016)
references/dom_clobbering.md             — DOM clobbering: attacker id/name HTML shadowing JS globals/DOM APIs
references/content_security_policy.md    — CSP weaknesses: missing/weak policy, unsafe-inline/eval, wildcard sources, allowlist bypass
references/xs_leaks.md                    — Cross-site leaks (timing/frame/status/cache oracles), missing COOP/COEP/CORP/Fetch-Metadata
references/privacy_data_protection.md    — Privacy / PII handling: over-collection, retention, PII in logs/URLs/third parties
references/supply_chain_security.md      — Supply chain: unpinned deps, missing integrity/SRI, lifecycle scripts, untrusted registries
references/api_security.md               — API / REST / web-service layer: excessive data exposure, rate limits, endpoint inventory, misconfig
references/mcp_security.md               — MCP (Model Context Protocol): tool poisoning, injection via tool output, over-broad/unauth servers
references/iac_security.md               — Infrastructure-as-Code misconfig (Terraform/CloudFormation/ARM/Bicep/Pulumi)
references/kubernetes_cloud_security.md  — Kubernetes / cloud orchestration: privileged pods, RBAC, securityContext, secrets, NetworkPolicy
references/cicd_container_security.md     — CI/CD pipeline + container/Docker security (PPE, untrusted inputs, root images, unpinned tags)
references/memory_safety_c_cpp.md        — C/C++ memory safety: buffer overflow, UAF, unsafe string funcs, integer overflow, toolchain hardening
references/smart_contract_security.md    — Solidity/EVM smart contracts: reentrancy, access control, unsafe delegatecall/low-level calls, integer over/underflow, oracle/MEV, proxy-upgrade, ERC-20/721/1155
references/insecure_output_handling.md   — Insecure handling of LLM/model output reaching HTML/SQL/shell/HTTP/eval sinks (OWASP LLM05)
references/excessive_agency.md           — Excessive LLM/agent functionality, permissions, or autonomy without human approval (OWASP LLM06)
references/system_prompt_leakage.md      — Secrets / authorization logic in system prompts; reliance on prompt secrecy (OWASP LLM07)
references/rag_vector_security.md        — RAG / vector & embedding weaknesses: permission-blind retrieval, cross-tenant leak, indirect injection (OWASP LLM08)
references/ml_supply_chain_poisoning.md  — AI/ML model & dataset supply chain and data/model poisoning: unsafe model load, trust_remote_code, unverified artifacts (OWASP LLM03/04)
references/ai_editor_config_poisoning.md — Repo poisoning of AI coding agents: weaponized editor/agent config & instruction files (.cursorrules/CLAUDE.md/AGENTS.md/SKILL.md/.mcp.json), hidden-unicode/HTML payloads, approval/YOLO-mode bypass
references/batch_etl_pipeline_security.md — Batch / ETL / mainframe data-pipeline flaws: job-param & record-field path traversal, landing-dir TOCTOU, fixed-width/COMP-3/EBCDIC parse bounds, trailer integrity, restart double-post (CWE-22/78/367/125/707)
```

**Sources / sinks / sanitizers:** Each reference documents the per-language sources and sinks for the class and the
sanitizers/barriers that neutralize it. Prefer those recognized barriers when ruling a finding SAFE.

**Loading strategy:**
- For a targeted review (e.g., "check for SQL injection"), load only the relevant reference(s).
- For a full audit, load the references that match the stack actually present and skip classes that cannot
  apply (e.g., do not load `php_security.md` or `mobile_security.md` for a pure Go service). Across the
  detected languages/frameworks this still covers every applicable class — it just avoids spending context
  on inapplicable ones.
- Keep the applicable references loaded together so each source file can be scanned against every lens in a
  single read (see Step 3 "Read-once discipline"). Only if the codebase plus its references exceed the
  context window, fall back to lens-grouped batches (injection → auth/access → crypto & data-exposure →
  server-side → protocol/infra → supply-chain), running one batch at a time.
- For any code using a **shared/singleton client, cache, request de-duplicator, connection pool, thread-local, or module global** that returns per-user/per-tenant data, load `shared_client_cache_leak.md`.
- Always load references for the top OWASP risks even if not explicitly requested.

---

### Step 3: Analyze Code — Source→Sink Taint Tracking

**Read-once discipline:** read each source file's full text ONCE and evaluate ALL loaded vulnerability
lenses against it in that single read — do not re-open the same file once per vuln class. Re-read a file
only to follow a cross-file data-flow chain into it. This keeps total read cost ~1x the codebase regardless
of how many classes are in scope.

For each loaded vulnerability class, perform taint analysis:

1. **Identify Sources** — User-controlled input entry points:
   - HTTP params, headers, cookies, request body
   - File uploads
   - WebSocket messages
   - Environment variables
   - Database reads of user-supplied data, deserialized objects
   - **Event-driven / serverless / RPC entry points** — handlers invoked outside the HTTP request path still receive attacker-influenced data: serverless/cloud-function handlers (`event`/payload args), message-queue and stream consumers (Kafka, RabbitMQ, SQS/SNS, Pub/Sub, Kinesis), gRPC/RPC and GraphQL resolver methods, scheduled/cron jobs that read external state, and CLI argument/stdin parsers. Enumerate the full attack surface — including undocumented, deprecated, and debug handlers still registered — not just documented routes.
   - **Library/SDK mode** — when the target is a library, framework, or SDK with no HTTP layer, treat the parameters of public/exported API methods (those a downstream consumer can call with attacker-influenced input, e.g. parsers, deserializers, path/URL/command builders) as taint sources. Internal/private helpers and config-only setters are not sources.

2. **Trace Data Flow** — Follow the data through:
   - Variable assignments, function arguments, return values
   - Framework helpers, ORM calls, template rendering
   - Cross-module/service boundaries

3. **Check Sinks** — Dangerous operations receiving tainted data:
   - Query execution (SQL, NoSQL, LDAP, XPath)
   - Shell/OS command execution
   - File system operations
   - HTTP client calls
   - Template rendering / eval / expression parsing
   - Serialization/deserialization

4. **Evaluate Sanitization** — Between source and sink, look for:
   - Input validation (allowlist vs denylist)
   - Context-appropriate encoding/escaping
   - Parameterization (prepared statements)
   - Framework-native protections

   Do **not** treat the mere presence of a sanitizer as proof of safety — confirm it is effective for this exact sink and context. Common *broken-sanitizer* failure modes that remain VULN:
   - **Wrong-context escaping** — HTML-escaping a value used in a JS/URL/SQL/shell/attribute context (or vice versa)
   - **Flawed regex** — unanchored (`^…$` missing), `.` matching too much, alternation gaps, or validating format but not dangerous characters
   - **Insufficient transform** — truncation/length caps, single-pass replace that can be re-introduced (e.g. stripping `../` once), case-only or trim-only normalization
   - **Order bug** — sanitize then mutate/decode/concatenate, so tainted data is reintroduced after the check
   - **Encoding/normalization bypass** — value is URL/Unicode/base64-decoded or Unicode-normalized (NFKC) *after* validation; homoglyph or double-encoded input slips a denylist
   - **Partial coverage** — only some paths/parameters validated, or the guard runs on a sibling branch the taint does not pass through

5. **Determine Preliminary Verdict**:
   - **VULN**: Taint reaches sink with no effective sanitization
   - **LIKELY VULN**: Sanitization present but bypassable per reference heuristics
   - **SAFE**: Effective sanitization or no taint path

---

### Step 4: Business Logic & Auth Analysis

Beyond taint tracking, check for:
- Missing authentication/authorization on sensitive endpoints
- **Differential / consistency analysis** — compare peer code paths that should enforce the same control: sibling endpoints in the same controller/router, the verbs of one resource (GET/POST/PUT/DELETE), or handlers in the same directory. When most peers apply a control (authorization/ownership check, input validation/sanitization, rate limit, output encoding) and one omits it, flag the outlier. High-impact bugs like missing authorization on 1-of-N endpoints, IDOR, and inconsistent validation are the *absence* of a check rather than a matchable bad pattern — they surface only by comparing a code path against its peers, so load the related handlers together before judging.
- Insecure state machine transitions
- Race conditions in concurrent operations
- Improper trust boundaries between components
- JWT algorithm confusion, token fixation, session issues
- Default/hardcoded credentials
- Enumeration via timing or response differences
- **Shared-state identity-key analysis** (`shared_client_cache_leak.md`): for every shared/singleton/memoized client, cache, request de-duplicator/coalescer (urql/Apollo dedup, `DataLoader`, `singleflight`, `LoadingCache`, `@Cacheable`, `lru_cache`/`@cache`, `IMemoryCache`, `p-memoize`, `unstable_cache`/`'use cache'`), connection pool, `ThreadLocal`/`contextvar`/`AsyncLocalStorage`, or module/static global, ask: (a) is it shared across requests/users? (b) does the value depend on identity (auth token, session, `userId`, `tenantId`)? (c) is that identity part of the cache/coalescing **key** (not just headers/options/mutable instance state)? If shared + identity-dependent + identity NOT in the key (or held as shared mutable state), it leaks across users under concurrency.

---

### Step 5: Judge — Validity Re-Verification

Before reporting, every preliminary finding (VULN or LIKELY VULN) **must pass a Judge review**. The Judge acts as an adversarial second opinion to eliminate false positives.

For each candidate finding, answer all of the following:

#### Reachability Check
- [ ] Is the source actually user-controlled, or is it internal/trusted data?
- [ ] Is the vulnerable code path reachable from an HTTP endpoint / entry point — or, for a library/SDK, from a public/exported API a downstream caller can reach — or is it dead code / private-internal-only?
- [ ] Are there upstream guards (auth middleware, input filters) that block the path before it reaches the sink?

**Map the sink to its entry point (route + parameter).** To confirm web reachability and record the concrete attack surface for each finding:
- If the sink is in a request handler, derive the route by combining class-level and method-level route declarations, and note the HTTP method and the tainted parameter (e.g. Spring `@RequestMapping`/`@GetMapping`/`@PostMapping` + `@RequestParam`/`@PathVariable`/`@RequestBody`; Flask/Express/Rails/Gin equivalents — see route tables in `api_security.md`).
- If the sink is in a service/repository/helper (no route annotations), trace callers up the call graph until you reach a handler; the finding is reachable only if such a path exists. Report the resolved `METHOD /route` + parameter (e.g. `POST /search` ← `search` param) so the finding is verifiable and maps cleanly to a dynamic test.

#### Sanitization Re-Evaluation
- [ ] Is there sanitization that was missed in Step 3? (Check parent functions, middleware, framework internals)
- [ ] Is the sanitization method sufficient for this specific sink and context?
- [ ] Does the framework provide implicit protection for this pattern?

#### Exploitability Check
- [ ] Can the tainted value actually reach the sink in a form that triggers the vulnerability?
- [ ] Is exploitation conditional on a specific environment, config, or privilege level?
- [ ] For logic bugs: is the business impact real, or hypothetical?
- [ ] Is the chosen tag the most precise valid label for this finding?
- [ ] **Victim other than the attacker**: does exploitation harm a *different* user, the system, or other tenants — not only the attacker themselves? A flow where the attacker can only affect their own account/session/data/cache entry (e.g. self-XSS pasted into one's own browser, poisoning only one's own row, DoSing only one's own request) is **not** a finding unless it can be delivered to or triggered against a victim (stored/reflected to others, CSRF-delivered, cache-key-shared). When uncertain whether a victim exists, try multiple delivery paths before concluding it is self-harm only.

**Confidence signals** (use to set verdict and severity, not to silently drop):
- *Raises confidence*: reachable from the Internet (vs local console/CLI only); exploitable by an anonymous vs an authenticated user; the input (source) and output (sink) nodes match what the class actually requires.
- *Lowers confidence — cap at LIKELY / prefer NEEDS CONTEXT*:
  - **Source/sink type mismatch**: the actual source or sink does not match the class (e.g., a "reflected XSS" whose sink is a log file rather than an HTTP response, or an "SQLi" sink that is not a query API) — usually a false positive.
  - **Second-order / stored input**: the flow starts from stored data (file/DB/cache/config) rather than a direct request — exploitability depends on how that store was populated.
  - **Non-production sink**: output goes only to a debug/trace log or dev-only path typically disabled in production.
  - **Sanitizer present in the path** (even if imperfect), or the data-flow is very long/complex/hard to reproduce, or evidence is insufficient — do not report as CONFIRMED on weak evidence.

#### Judge Verdict

| Verdict | Meaning | Action |
|---------|---------|--------|
| **CONFIRMED** | All reachability/sanitization/exploitability checks pass | Include in report |
| **LIKELY** | Most checks pass; one uncertainty remains | Include in report, flag uncertainty |
| **NEEDS CONTEXT** | Cannot determine without runtime behavior / config / additional files | Note as "unverifiable without X" |
| **FALSE POSITIVE** | Positive evidence of protection found — cite the exact file+line of the sanitization, allowlist check, guard, or framework-level auto-protection that makes the sink safe | Drop silently |

**Only CONFIRMED and LIKELY findings are reported.**

**FP burden of proof**: `UNCERTAIN` on any check is NOT sufficient to declare FALSE POSITIVE. If a check result is UNCERTAIN after inspecting the sink, its callers, and the framework internals, use `NEEDS CONTEXT` instead. Only use FALSE POSITIVE when you have found and can cite positive evidence that the path is protected.

#### Judge Output Format (internal, before reporting)

```
Finding: VULN-NNN — <class>
Reachability:   PASS / FAIL / UNCERTAIN — <reason>
Sanitization:   PASS / FAIL / UNCERTAIN — <reason>
Exploitability: PASS / FAIL / UNCERTAIN — <reason>
Judge Verdict:  CONFIRMED / LIKELY / NEEDS CONTEXT / FALSE POSITIVE
```

#### False Positive Guardrails

**Tags**
- `default_credentials`: require a reachable auth path that accepts the hardcoded credential.
- `weak_crypto_hash`: require direct use of weak hash/algo — not just an import or third-party component. Covers both weak algorithms (DES, RC4, ECB) and weak hashes (MD5, SHA-1 for passwords); do not use `weak_crypto` as a separate tag.
- `rce` → prefer `command_injection` for direct shell/process execution. Do not replace `spel_injection` with `rce`/`command_injection`.
- `jndi_injection` in demos: only if the JNDI sink is the primary exploit path.
- Broad tags (`trust_boundary`, `authentication`, `privilege_escalation`): prefer the narrowest valid tag (`xff_spoofing`, `session_fixation`, `verification_code`).
- `open_redirect`: only if the attacker-controlled redirect is the primary exploit (not infra/parser misconfiguration).
- `csrf`: skip for stateless Bearer-token-only APIs (`SessionCreationPolicy.STATELESS`).
- `insecure_deserialization`: skip if `component_vulnerability` covers the same sink.
- `arbitrary_file_upload`: skip for avatar/profile upload with type restrictions and non-webroot storage.
- `session_fixation`: skip when Spring Security default session management is active.
- `information_disclosure`: skip for DB credentials in config files — deployment issue, not app-level.
- `shared_client_cache_leak`: require a structure that is BOTH shared across requests/users AND keyed/scoped without the identity the value depends on. Safe (drop) when the key provably includes `userId`/`tenantId`/session/auth-token-hash, when the client/cache/loader is created per-request, when the cached data is identity-independent (public/config), or when only a stateless transport is reused with auth passed per-call. Prefer `web_cache_deception` when the cache is an HTTP/CDN/edge/proxy cache; use `shared_client_cache_leak` only for in-process caches/dedup/singletons/pools/thread-locals/globals. Do not flag mutation paths for the dedup sub-class (query dedup does not merge mutations).

**Scope**
- Demo/example code: skip any finding whose ONLY vulnerable path is in `examples/`, `demo/`, `sample/` (or similar). Report only if the bug is in the library/SDK itself.
- Non-default config: verify the DEFAULT value before reporting. Requires non-default/deprecated → cap `Low`. Explicitly labeled `legacy` or deprecated in code/docs → cap `Informational`.

**Trust Boundary**
- Operator self-harm: skip findings where the "attacker" input comes from operator-written config files (YAML/JSON/TOML), CLI flags the operator supplies themselves (`--file`, `--url`, `--chain-id`), or commands the operator must explicitly run.
- Trusted admin role: skip `privilege_escalation`/`business_logic` for actions behind `onlyAdmin`/`onlyOwner`/`onlyPoolAdmin` when that role is trusted by design. Only report if an unprivileged user can reach the same path.
- Internal-only service: skip `authentication` and `information_disclosure` when the entire codebase has zero auth AND references internal infra (VPC vars, `EC2_INSTANCE_ID`, Eureka, Consul). Auth is at the network layer.
- Code generators: skip `injection`/`path_traversal`/`rce` for codegen tools (`protoc`, `swagger-codegen`, etc.) whose input comes from developer-controlled source comments, annotations, or local config.

**Protocol & Architecture**
- Protocol-designed SSRF: skip `ssrf` when fetching a peer-supplied URL is required by spec (LNURL, UMA, OAuth discovery, WebFinger, OIDC discovery). Only report if the impl allows schemes the protocol does not require (e.g., `file://`) or skips required domain validation.
- Blind SSRF: downgrade to `Informational` when all three hold: (a) response never reaches the attacker, (b) no meaningful side effect on the target, (c) no error oracle.
- Bounded DoS: skip `denial_of_service` unless the upper bound of the iterated/allocated data is attacker-controllable and unbounded. Naturally bounded data (blockchain validator set, gas limits, etcd/request-body size caps) → not a finding.
- Brute force: skip `brute_force` only if rate limiting is visible in code, framework config, or referenced middleware in the repo. Do not assume infrastructure-level rate limiting.
- Idempotent replay: skip replay/`business_logic` when the operation is idempotent AND parameters are cryptographically signed (no tampering possible).
- Library dead path: if no real caller in the codebase triggers the vulnerable parameter combination AND the code has a warning log for that path → `NEEDS CONTEXT`, not a finding.

**Platform**
- Android app-private storage: skip `insecure_storage`/`information_disclosure` for `SharedPreferences`/`DataStore` in app-private storage without `android:allowBackup="true"` in a production manifest.
- Terraform state: skip `information_disclosure` for providers writing secrets to state when attributes are marked `Sensitive: true`.
- Intra-org CI/CD: skip `supply_chain` for mutable action tags (e.g., `@v3`) when the action org matches the repo org. Only report third-party org actions.
- Local dev tools: skip `authentication` for README-described local dev tools with no production docs. Exception: report (reduced severity) if the tool does not bind to `localhost`, exposes tokens in API responses, or allows destructive ops.

---

#### Pre-Report Checklist

- [ ] Public-facing service, or internal-by-design (zero auth everywhere + internal infra refs)?
- [ ] Production code, or demo/example/sample directory?
- [ ] Attacker is genuinely untrusted, not an admin/operator within their own trust boundary?
- [ ] Verify DEFAULT config value — does the attack work with defaults?
- [ ] SSRF required by protocol spec?
- [ ] SSRF response reachable by attacker (readable / side effect / error oracle)?
- [ ] Sensitive storage protected by OS sandbox (Android app-private)?
- [ ] Replay: is the operation idempotent with signature-bound parameters?
- [ ] Library: does any real caller trigger the vulnerable path?
- [ ] Terraform state with `Sensitive: true` — by design?
- [ ] DoS: is the upper bound attacker-controllable and unbounded?
- [ ] CI/CD mutable tags: same org or third-party?
- [ ] Admin action within the admin's designed trust boundary?
- [ ] Shared client/cache/dedup/pool/global: is identity in the key (or is it per-request scoped), and is the data actually identity-dependent?

#### Variant Sweep (after each confirmation)

A bug almost never exists in isolation: the same unsafe sink, helper, or pattern is usually copy-pasted elsewhere. Whenever the Judge CONFIRMS a finding, before moving on, sweep the rest of the codebase for siblings of that exact pattern:

- **Same sink, other call sites** — grep the confirmed sink/API (e.g. the raw-query call, `exec`, the unsafe deserializer, the missing-auth decorator's absence) across all in-scope files; each unguarded call site is a candidate finding, not a duplicate.
- **Same helper / wrapper** — if the bug is in a shared helper, every caller inherits it; if a caller re-implements the same logic inline, it shares the flaw.
- **Same root cause, different shape** — the missing control (no ownership check, no sanitizer, wrong comparison) often recurs in other handlers; look for the *absence* of the fix, not just the literal string.

Evaluate each variant through the full Source→Sink + Judge process (it may be a true positive, or guarded and safe). Report confirmed variants as their own findings at their own `file:line`. A confirmed systemic pattern (same root cause in 3+ places) is itself a signal — note it so remediation fixes the class, not just one instance.

---

### Step 6: Adversarial Impact Validation

**This step is controlled by the `adv` argument.** If `adv` was not provided, skip this step entirely and proceed to Step 7.

**Scope:** This step applies only to findings whose severity matches the `adv=` value provided at invocation. All other findings that passed the Judge proceed directly to Step 7.

For example:
- `llm-sast-scanner adv=critical,high` → validate Critical and High findings; Medium/Low/Info skip to Step 7
- `llm-sast-scanner adv=critical` → validate Critical findings only; everything else skips to Step 7
- `llm-sast-scanner` → no `adv` argument, skip this step entirely

Every matching finding that passed the Judge (CONFIRMED or LIKELY) must survive an adversarial stress test focused on real-world impact before it can be reported. The goal is to actively try to **disprove** each finding — only those that withstand scrutiny are worth reporting at that severity.

For each matching finding, work through ALL of the following:

#### 1. Why You Might Be Wrong
- What assumptions are you making about the data flow, environment, or attacker capability?
- Is there a reasonable interpretation of the code where this is actually safe?
- Could the surrounding architecture (WAF, API gateway, service mesh, network segmentation) neutralize this in practice?
- Are you pattern-matching on a known vuln class without sufficient evidence for THIS specific codebase?
- Did you confuse a defense-in-depth gap with an exploitable weakness?

#### 2. Real Impact Assessment
- What specifically can an attacker gain — data, access, availability, integrity?
- Is the impact theoretical or demonstrable with a concrete payload/sequence?
- What is the blast radius — single user, all users, entire system, adjacent systems?
- Does exploitation require chaining with other vulnerabilities that may not exist?
- Quantify: how many users/records/systems are affected in the worst realistic case?

#### 3. Practical Attack Scenarios
- Write out a concrete, step-by-step attack scenario from the attacker's perspective.
- What preconditions must hold (network position, auth level, timing, user interaction)?
- How likely are those preconditions in a real deployment?
- Would a competent attacker actually pursue this, or are there far easier paths to the same goal?
- Can the attack be performed reliably, or does it depend on race conditions / timing windows that make it impractical?

#### 4. Real-World Viability
- Does this bug survive contact with production reality (load balancers, CDNs, containerization, monitoring, rate limiting, WAFs)?
- Is the vulnerable code path exercised in normal operation, or is it an edge case requiring unusual input or deprecated functionality?
- Has this class of bug been exploited and confirmed in similar real-world systems, or is it purely academic?
- Would standard deployment hardening (HTTPS, CSP, network policies) prevent or significantly limit exploitation?

#### 5. Production Impact
- If exploited, what is the operational impact — downtime, data breach, compliance violation, reputational damage?
- Is the affected component internet-facing, internal-only, or behind multiple trust boundaries?
- What detection and response mechanisms exist that would limit damage (logging, alerting, auto-scaling, circuit breakers)?
- How quickly would exploitation be noticed, and how easily can it be remediated once detected?

#### Adversarial Verdict

| Verdict | Meaning | Action |
|---------|---------|--------|
| **STANDING** | Finding survived all challenges — real-world impact is credible and demonstrable | Report at original severity |
| **DOWNGRADED** | Finding is real but impact is lower than initially assessed | Demote by one or more severity levels, proceed to report |
| **DISPUTED** | Reasonable doubt exists on practical exploitability or real-world impact | Demote by one severity level, add explicit caveat to finding |
| **WITHDRAWN** | Cannot construct a credible real-world attack scenario despite the technical truth of the bug | Drop from report; log internally as "withdrawn after adversarial review" with rationale |

**Only STANDING, DOWNGRADED, and DISPUTED findings proceed to the report.** A finding that is DOWNGRADED or DISPUTED loses its original severity (e.g., Critical → High or below, High → Medium or below). DISPUTED findings must include the specific doubt rationale so the reader can make their own judgment.

#### Adversarial Output Format (internal, before reporting)

```
Finding: VULN-NNN — <class>
Why wrong:       <strongest counter-argument against the finding>
Real impact:     <concrete impact statement, or "theoretical only">
Attack scenario: <1-2 sentence practical scenario, or "no credible scenario">
Real-world:      VIABLE / MARGINAL / IMPRACTICAL — <reason>
Production:      <impact on live systems>
Adversarial Verdict: STANDING / DOWNGRADED / DISPUTED / WITHDRAWN — <rationale>
```

---

### Step 7: Report Findings

#### Severity Classification

| Severity | Criteria |
|----------|----------|
| **Critical** | Direct RCE, authentication bypass, unauthenticated data exposure |
| **High** | SQLi, SSRF, IDOR with sensitive data, stored XSS, privilege escalation |
| **Medium** | Reflected XSS, CSRF, path traversal, insecure deserialization |
| **Low** | Information disclosure, open redirect, weak crypto, insecure cookie |
| **Info** | Missing security headers, verbose errors, defense-in-depth gaps |

**Severity Downgrade Rule:** When exploitation requires authentication, specific non-default configuration, chained prerequisites, or is only reachable through an internal/admin-only path, downgrade severity by one level from the class default; LIKELY-verdict findings whose exploitability is marked UNCERTAIN must be capped at one level below the class default regardless of vulnerability type.

#### Finding Format

```
[SEVERITY] VULN-NNN — <Vulnerability Class>  [CONFIRMED | LIKELY]
CWE: <CWE-ID(s) for the class, taken from the matching reference file — e.g. CWE-89>
File: <path>:<line_number>
Description: <one sentence — what the vulnerability is>
Impact: <what an attacker can achieve>
Evidence:
  <relevant code snippet>
Judge: <one sentence — why this passed re-verification>
Adversarial: <one sentence — why this survived the stress test> [STANDING | DOWNGRADED | DISPUTED]
Remediation: <specific fix — not generic advice>
Reference: references/<vuln>.md
```

For NEEDS CONTEXT findings:

```
[UNVERIFIABLE] VULN-NNN — <Vulnerability Class>
File: <path>:<line_number>
Blocked by: <what additional context is needed>
```

#### Deduplication & Sink Location

- **Point to the sink, not the source.** `File: <path>:<line_number>` must reference the line of the dangerous operation (query execution, command exec, render/output, deserialize) — not where the tainted value originates.
- **One finding per distinct sink.** Same sink line + same tainted value + same dangerous operation = one finding; never emit identical duplicates.
- **Collapse equivalent sink chains.** When one tainted value flows through several equivalent sinks (e.g. a value rendered by multiple wrappers, or re-passed to the same API), report only the final externally-visible sink — unless an intermediate stage is independently reachable or exploitable.
- Distinct sink lines remain separate findings only when independently reachable/exploitable.

#### Chained / Compound Risk

After individual findings are confirmed, check whether two or more **CONFIRMED** findings form an attack path where one enables or amplifies the next, reachable in sequence by the same actor. Report these together as a compound risk and escalate the combined severity one level above the highest individual link (cap at Critical).

- This is the inverse of the Severity Downgrade Rule, not a contradiction: **downgrade** applies to a single finding that *depends on* an unconfirmed/hypothetical vulnerability; **escalation** applies only when every link is independently CONFIRMED and reachable in order by one actor. Never escalate using a speculative link.
- Common attack chains to look for:
  - SQLi / broken authentication → sensitive-data exposure → broken access control
  - Path traversal → file inclusion → remote code execution
  - Insecure deserialization → remote code execution → OS command / code injection
  - XSS → CSRF / session theft → authentication compromise
  - IDOR / broken authentication → privilege escalation → account or data takeover
  - SSRF → cloud-metadata credential theft → lateral movement
- Report each chain with the ordered links (their `VULN-NNN` ids), the combined severity, and a one- to two-sentence end-to-end attack path. Do not duplicate the individual findings — reference them.

#### Report Structure

When producing a full report, write to `sast_report.md` (or user-specified path):

```markdown
# SAST Security Report — <target>
Date: <date>
Analyzer: llm-sast-scanner v1.30.0

## Executive Summary
<2-3 sentences: total findings by severity, most critical issue>

## Critical Findings
## High Findings
## Medium Findings
## Low Findings
## Informational
## Chained / Compound Risks
<confirmed multi-finding attack paths with escalated combined severity; omit if none>
## Unverifiable Findings

## Remediation Priority
<ordered fix list>
```

- **Evidence over assertion**: always show the vulnerable code path, not just the pattern name
- **Context matters**: a finding is only valid if the sink is reachable with user-controlled data
- **Avoid false positives**: if sanitization exists, verify it is bypassable before marking VULN
- **Be precise**: include exact file paths and line numbers — never approximate
- **No fabricated evidence**: every cited file path, line number, and code snippet must appear verbatim in the scanned source; never invent paths, lines, call chains, or snippets to support a finding. If you cannot locate the exact evidence, mark the finding NEEDS CONTEXT instead of approximating. Remediation prose must not contradict or exceed the verified data-flow.
- **Fix > flag**: always provide a concrete remediation, not just a problem statement
- **Language-aware**: adapt sink/source patterns to the specific language and framework in use
- **Token discipline**: read each source file once and evaluate all loaded lenses in that pass; load only references that match the stack in use
