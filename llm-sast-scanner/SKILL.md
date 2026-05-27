---
name: llm-sast-scanner
description: >
  General-purpose Static Application Security Testing (SAST) skill for code vulnerability analysis.
  Trigger when the user asks to: "analyze code for vulnerabilities", "review code security", "find security bugs",
  "do a SAST scan", "check for [vulnerability type] in code", "audit source code", or requests a security
  code review of any language or framework. Covers 37 vulnerability classes across web, API, auth, mobile, and logic layers.
  Accepts optional tagged arguments, e.g. "llm-sast-scanner adv=critical,high" for adversarial validation.
metadata:
  version: "1.7.1"
  domain: application-security
  references: 37 vulnerability knowledge bases
---

# SAST Vulnerability Analysis

## Purpose

Systematically analyze source code for security vulnerabilities using structured Source→Sink taint tracking,
pattern matching, and vulnerability-class-specific detection heuristics. Produce actionable findings with
severity ratings, affected code locations (file + line number), and remediation guidance.

## Scope

This skill covers the following 37 vulnerability classes. Each has a dedicated reference file loaded on demand:

| Category | Vulnerabilities |
|----------|----------------|
| **Injection** | SQL Injection, XSS, Client-Side Prototype Pollution (CSPP), SSTI, NoSQL Injection, GraphQL Injection, XXE, RCE / Command Injection, Expression Language Injection |
| **Access Control & Auth** | IDOR, Privilege Escalation, Authentication/JWT, Default Credentials, Brute Force, Business Logic, HTTP Method Tampering, Verification Code Abuse, Session Fixation |
| **Data Exposure & Crypto** | Weak Crypto/Hash, Information Disclosure, Insecure Cookie, Trust Boundary |
| **Server-Side** | SSRF, Path Traversal/LFI/RFI, Client Side Path Traversal (CSPT), Server-Side Prototype Pollution (SSPP), Insecure Deserialization, Arbitrary File Upload, JNDI Injection, Race Conditions |
| **Protocol & Infrastructure** | CSRF, Open Redirect, HTTP Request Smuggling/Desync, Denial of Service, CVE Patterns |
| **Language/Platform** | PHP Security, Mobile Security (Android/iOS) |

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
references/trust_boundary.md             — Trust boundary violations
references/race_conditions.md            — Race conditions / TOCTOU
references/brute_force.md                — Brute force / credential stuffing
references/default_credentials.md        — Default / hardcoded credentials
references/verification_code_abuse.md    — Verification code abuse
references/business_logic.md             — Business logic flaws
references/http_method_tamper.md         — HTTP method tampering
references/smuggling_desync.md           — HTTP request smuggling / desync
references/cve_patterns.md               — Known CVE patterns
references/expression_language_injection.md — Expression language injection (SpEL / OGNL)
references/jndi_injection.md             — JNDI injection (Log4Shell class)
references/denial_of_service.md          — Denial of service / resource exhaustion
references/php_security.md               — PHP-specific security issues
references/mobile_security.md            — Mobile security (Android / iOS)
references/session_fixation.md           — Session fixation
```

**Loading strategy:**
- For a targeted review (e.g., "check for SQL injection"), load only the relevant reference(s).
- For a full audit, load all 37 references and scan systematically.
- Always load references for the top OWASP risks even if not explicitly requested.

---

### Step 3: Analyze Code — Source→Sink Taint Tracking

For each loaded vulnerability class, perform taint analysis:

1. **Identify Sources** — User-controlled input entry points:
   - HTTP params, headers, cookies, request body
   - File uploads
   - WebSocket messages
   - Environment variables
   - Database reads of user-supplied data, deserialized objects

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

5. **Determine Preliminary Verdict**:
   - **VULN**: Taint reaches sink with no effective sanitization
   - **LIKELY VULN**: Sanitization present but bypassable per reference heuristics
   - **SAFE**: Effective sanitization or no taint path

---

### Step 4: Business Logic & Auth Analysis

Beyond taint tracking, check for:
- Missing authentication/authorization on sensitive endpoints
- Insecure state machine transitions
- Race conditions in concurrent operations
- Improper trust boundaries between components
- JWT algorithm confusion, token fixation, session issues
- Default/hardcoded credentials
- Enumeration via timing or response differences

---

### Step 5: Judge — Validity Re-Verification

Before reporting, every preliminary finding (VULN or LIKELY VULN) **must pass a Judge review**. The Judge acts as an adversarial second opinion to eliminate false positives.

For each candidate finding, answer all of the following:

#### Reachability Check
- [ ] Is the source actually user-controlled, or is it internal/trusted data?
- [ ] Is the vulnerable code path reachable from an HTTP endpoint / entry point, or is it dead code / internal-only?
- [ ] Are there upstream guards (auth middleware, input filters) that block the path before it reaches the sink?

#### Sanitization Re-Evaluation
- [ ] Is there sanitization that was missed in Step 3? (Check parent functions, middleware, framework internals)
- [ ] Is the sanitization method sufficient for this specific sink and context?
- [ ] Does the framework provide implicit protection for this pattern?

#### Exploitability Check
- [ ] Can the tainted value actually reach the sink in a form that triggers the vulnerability?
- [ ] Is exploitation conditional on a specific environment, config, or privilege level?
- [ ] For logic bugs: is the business impact real, or hypothetical?
- [ ] Is the chosen tag the most precise valid label for this finding?

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

#### Report Structure

When producing a full report, write to `sast_report.md` (or user-specified path):

```markdown
# SAST Security Report — <target>
Date: <date>
Analyzer: llm-sast-scanner v1.7.1

## Executive Summary
<2-3 sentences: total findings by severity, most critical issue>

## Critical Findings
## High Findings
## Medium Findings
## Low Findings
## Informational
## Unverifiable Findings

## Remediation Priority
<ordered fix list>
```

---

## Key Principles

- **Evidence over assertion**: always show the vulnerable code path, not just the pattern name
- **Context matters**: a finding is only valid if the sink is reachable with user-controlled data
- **Avoid false positives**: if sanitization exists, verify it is bypassable before marking VULN
- **Be precise**: include exact file paths and line numbers — never approximate
- **Fix > flag**: always provide a concrete remediation, not just a problem statement
- **Language-aware**: adapt sink/source patterns to the specific language and framework in use
