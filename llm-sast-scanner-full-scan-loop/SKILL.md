---
name: llm-sast-scanner-full-scan-loop
description: >
  Convergence-driven, exhaustive line-by-line security audit wrapper around the llm-sast-scanner skill.
  Invoke explicitly as "llm-sast-scanner-full-scan-loop <dir> [mode=parallel|single]" where <dir> is the target
  repository/directory path; if <dir> is omitted it defaults to the current working directory.
  By DEFAULT (mode=parallel) it dispatches one subagent per vulnerability lens — each runs the convergence loop
  (Steps 1-5) constrained to its lens until convergence with 100% line coverage — then a consolidation subagent
  merges results, runs Adversarial Impact Validation (Step 6) once, and writes a timestamped consolidated report.
  With mode=single it runs the entire convergence loop in one context (strongest convergence/coverage guarantee).
disable-model-invocation: true
metadata:
  version: "1.2.0"
  domain: application-security
  wraps: llm-sast-scanner
---

# SAST Full Scan Loop

## Purpose

A driver command around the [`llm-sast-scanner`](../llm-sast-scanner/SKILL.md) skill. It performs an
exhaustive, convergence-driven, line-by-line security audit of an entire repository passed as an argument.
**By default it parallelizes the audit across subagents — one per vulnerability lens** — and consolidates
their results with a single final adversarial pass. A single-context mode is available for the strongest
convergence guarantee.

## Arguments

```
llm-sast-scanner-full-scan-loop <dir> [mode=parallel|single] [adv=critical,high,medium] [lens=<lens>]
```

- `<dir>` — the path to the repository/directory to audit. Use this value wherever the prompt below
  references the target directory. If no `<dir>` is provided, default to the current working directory
  (`.`) and audit it.
- `mode` — `parallel` (default) dispatches one subagent per lens; `single` runs the whole loop in one context.
- `adv` — severities for the final Adversarial Impact Validation pass (default `critical,high,medium`).
- `lens` — **internal**: restrict the Convergence Loop Procedure to a single lens. Set automatically by
  parallel-mode subagents; you normally do not pass this by hand.

## Execution Modes

| Mode | Behavior | When |
|------|----------|------|
| **parallel** (default) | Run **Parallel Orchestration** below: D1 analysis → one subagent per lens runs the **Convergence Loop Procedure** constrained to its lens → consolidation subagent merges, runs the single adversarial pass, writes the report. | Default. Faster wall-clock; each lens converges in its own isolated context. |
| **single** | Skip the orchestration; run the **Convergence Loop Procedure** once in this session across ALL lenses (rotating the lens each pass), then the final adversarial pass + report inline. | `mode=single`, or when subagents are unavailable, or when you want one context to own the ledger + coverage map end-to-end. |

> **No recursion:** parallel-mode subagents run the **Convergence Loop Procedure** directly (as if `mode=single
> lens=<their lens>`). They MUST NOT re-invoke this `llm-sast-scanner-full-scan-loop` wrapper, or it would
> fan out again.

## Prerequisite

Load the base skill first: read [`../llm-sast-scanner/SKILL.md`](../llm-sast-scanner/SKILL.md). Load
reference files from its `references/` directory ON DEMAND, per pass — only the subset relevant to the
current pass's analysis lens (see LOOP CONTROL), rather than all 75 at once. As the lens rotates across
passes, every vulnerability class gets covered, without holding all references in context simultaneously.
Following the base skill's read-once discipline, keep the current pass's lens references loaded while you read
each file so all of that pass's classes are evaluated in a single read. All step numbers (Step 1-6), the Judge
protocol, the false-positive guardrails, the severity model, and the report structure are defined there and
MUST be used.

## Parallel Orchestration (default — `mode=parallel`)

Skip this whole section if `mode=single` was requested; go straight to the **Convergence Loop Procedure**.

### Step D1 — Analysis

If `sast/architecture.md` already exists, reuse it. Otherwise run the base skill's **Step 1 (Understand
Scope)** over `<dir>` **in this session** and write a short architecture/threat-model brief to
`sast/architecture.md` (languages & frameworks, entry points, trust boundaries, authN/authZ, data stores,
outbound calls, detected stack). Wait for this to finish.

### Step D2 — Parallel convergence loops (one subagent per lens)

Start **one subagent per lens**, all **in parallel**. Skip any lens whose deep results file already exists.
Give each subagent this instruction (substitute the lens, class list, and results file from the table):

> Read `sast/architecture.md` for context, then run the base `llm-sast-scanner` skill following the
> **Convergence Loop Procedure** (below) with `lens=<lens>` — i.e. restrict analysis to the **\<lens\>**
> vulnerability classes and load only the matching references that fit the detected stack. Execute the loop's
> convergence phase: multi-pass Steps 1–5 (taint tracking, business-logic/auth, Judge) until convergence,
> applying the ledger + 100% line-coverage discipline to your lens. **Do NOT run the final Adversarial Impact
> Validation pass, do NOT write a timestamped report, and do NOT re-invoke the full-scan-loop wrapper.** Write
> only Judge-passed CONFIRMED / LIKELY findings, plus your final coverage result and pass log, to the results
> file below.

| Lens | Deep results file | Vulnerability classes (reference lenses) |
|------|-------------------|------------------------------------------|
| injection | `sast/deep-injection-results.md` | SQLi, XSS, client-side prototype pollution, SSTI, NoSQLi, GraphQL injection, XXE, RCE/command injection, expression-language injection, LDAP injection, XPath/XQuery injection, CSV/formula injection, log injection, prompt injection (LLM01), insecure output handling (LLM05) |
| access-auth | `sast/deep-access-auth-results.md` | IDOR, privilege escalation / missing auth (BFLA), authentication & JWT, default credentials, brute force, business logic, HTTP method tampering, verification code abuse, session fixation, mass assignment, excessive agency (LLM06), RAG / vector & embedding security (LLM08) |
| crypto-data | `sast/deep-crypto-data-results.md` | weak crypto/hash, information disclosure (incl. LLM02 sensitive disclosure), insecure cookie, trust boundary, shared-client cache/dedup cross-user leak, cleartext transmission, certificate/TLS validation, system prompt leakage (LLM07) |
| server-side | `sast/deep-server-side-results.md` | SSRF, path traversal/LFI/RFI, client-side path traversal, server-side prototype pollution, insecure deserialization, arbitrary file upload, JNDI injection, race conditions, insecure temp file, file permissions |
| protocol-infra | `sast/deep-protocol-infra-results.md` | CSRF, open redirect, HTTP request smuggling/desync, HTTP response splitting, host header poisoning, CORS misconfiguration, clickjacking, web cache deception/poisoning, denial of service (incl. LLM10 unbounded consumption), regex injection/ReDoS, CVE patterns |
| hardening-platform | `sast/deep-hardening-platform-results.md` | output encoding, format string injection, ASP.NET security misconfiguration, hardcoded code/backdoor, dependency confusion, ML supply chain & data/model poisoning (LLM03/04), PHP security, mobile security |

Each lens subagent independently reads every in-scope line for its own coverage proof, so total read cost
scales with the number of lenses — this is the cost of per-lens parallelism. **Wait for all subagents to
finish before proceeding.**

### Step D3 — Consolidation + single adversarial pass

Launch one subagent:

> Read all `sast/deep-*-results.md` files and `sast/architecture.md`. Merge and de-duplicate findings across
> lenses (same `file:line` + vuln class = one finding). Run the base `llm-sast-scanner` skill's **Step 6
> (Adversarial Impact Validation)** ONCE over the full consolidated set with the `adv` value (default
> `adv=critical,high,medium`), apply the STANDING / DOWNGRADED / DISPUTED / WITHDRAWN verdicts, then write a
> single timestamped report `sast_report-<timestamp>.md` (timestamp from `date +%Y-%m-%d_%H-%M-%S`) using the
> base skill's report structure (Executive Summary; Critical/High/Medium/Low/Informational; Unverifiable;
> Remediation Priority). Also print a combined coverage summary and a per-lens pass log.

When D3 finishes, tell the user the report path and summarize the highest-severity findings. **In parallel
mode you are done here — do NOT also run the single-context procedure below.**

---

## Convergence Loop Procedure (single context)

This is the loop body. It runs in ONE context — either the whole `mode=single` run (all lenses, rotating per
pass), or a single parallel-mode lens subagent (when invoked with `lens=<lens>`, restrict every pass to that
lens's classes and treat "convergence" as "a pass surfaced no new bug **in that lens**"). When run as a
parallel-mode lens subagent, STOP after COVERAGE VERIFICATION, write findings to the lens's
`sast/deep-<lens>-results.md`, and SKIP the FINAL ADVERSARIAL PASS + OUTPUT (Step D3 owns those).

Execute the following prompt against the target `<dir>`. Treat `"dir as argument"` as the `<dir>` value
provided to this command.

---

Use the /llm-sast-scanner to perform an exhaustive, line-by-line security audit of the repository at:
"dir as argument"
GROUND RULES
- Scope = EVERY text/source file in the repo, REGARDLESS OF LANGUAGE OR EXTENSION. The paths/extensions
  below are EXAMPLES, NOT an allowlist — do not narrow scope to them: server/, src/, scripts/, public/,
  docs/, config, CI, Dockerfile, and source of any language (*.py, *.java, *.go, *.rb, *.php, *.cs, *.js,
  *.jsx, *.ts, *.tsx, *.json, *.yml/*.yaml, *.toml, *.sh, *.env, *.html, templates, etc.). Do NOT sample
  or skim — read each in-scope file fully, line by line.
- EXCLUDE from scope (do NOT read, do NOT count against coverage): binary assets; vendored/third-party
  dependency trees (node_modules/, vendor/, third_party/); build/generated output (dist/, build/, out/,
  *.min.js, *.bundle.js, source maps); and lock files (package-lock.json, yarn.lock, pnpm-lock.yaml,
  poetry.lock, Gemfile.lock, etc.). If a specific dependency must be reviewed, do it deliberately — not as
  part of the line-by-line repo sweep.
- SCOPE MANIFEST (build ONCE, before pass 1): enumerate the in-scope files + line counts deterministically with
  the shell, so coverage has an objective denominator and you never re-discover files on later passes:
  ```bash
  cd "dir as argument"
  { git ls-files --cached --others --exclude-standard 2>/dev/null || find . -type f; } \
    | grep -ivE '(^|/)(node_modules|vendor|third_party|dist|build|out|\.git|coverage)/' \
    | grep -ivE '\.(min\.js|bundle\.js|map|png|jpe?g|gif|webp|ico|pdf|zip|gz|jar|woff2?|ttf|mp4|so|dylib|dll|exe|wasm)$' \
    | grep -ivE '(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Gemfile\.lock|go\.sum|Cargo\.lock)$' \
    | tr '\n' '\0' | xargs -0 grep -Il '' 2>/dev/null \
    | tr '\n' '\0' | xargs -0 wc -l 2>/dev/null | sort -n
  ```
  This file list is the coverage denominator; seed the LOOP CONTROL coverage map from it and tick each file off
  as its lines are read. (Enumerating once also avoids re-listing the tree on every pass.)
- During the loop, run Steps 1–5 ONLY: Source→Sink taint tracking (Step 3), business-logic/auth analysis
  (Step 4), and Judge re-verification (Step 5). DO NOT run Adversarial Impact Validation (Step 6) inside the
  loop — no adv during passes.
- Only carry forward CONFIRMED / LIKELY findings that survive the Judge. Apply all false-positive guardrails
  (trusted-VPN/internal-only, bounded-DoS, operator self-harm, etc.).
LOOP CONTROL (convergence-driven; pass 5 is the CEILING for the converge phase, extendable to an absolute
cap of 10; NO adv inside the loop)
- Maintain (a) a running ledger of every finding already reported (by file:line + vuln class) so you never
  re-report the same issue, and (b) a coverage map of which files / line-ranges have already been READ.
- READ vs. ANALYZE (token discipline): read each in-scope file's full text ONCE — during pass 1, or the
  first pass that reaches it — and keep notes sufficient to reason about it later. A subsequent "pass" is a
  re-ANALYSIS of already-read code under a different lens, NOT a fresh full re-read. Re-read a file's bytes
  only when (a) it still has unread lines, or (b) you are tracing a cross-file data-flow chain into it. This
  keeps total read cost ~1x the repo while still getting multi-lens depth. (Optional accelerator: `rg` for
  high-risk sink keywords to decide where to look first — but you MUST still read every in-scope line for
  coverage, not just `rg` hits.)
- Iteration = one analysis pass that covers the entire in-scope repo under the current lens (reading any
  not-yet-read files in full as it goes).
- After each pass, compare against the ledger:
    * If the pass surfaced at least one NEW, previously-unreported bug → record it, then run ANOTHER pass.
    * If a pass finds NO new bug → STOP the loop (converged).
- Stop conditions (in priority order):
    1. CONVERGENCE (primary rule): the moment ANY pass surfaces NO new bug, STOP immediately — whether that
       is pass 2 or pass 9. Convergence always wins; do not keep running just to reach pass 5.
    2. CEILING = pass 5: if passes are STILL finding new bugs at pass 5, you MAY extend past it; if they are
       not, you will already have converged at or before pass 5.
    3. EXTENSION: while each pass at or beyond 5 keeps surfacing at least one NEW bug, continue one pass at a
       time.
    4. ABSOLUTE HARD CAP = pass 10: STOP after pass 10 regardless, even if new bugs are still appearing.
- On each pass, vary your analysis lens to find what earlier passes missed (e.g., pass 1: injection/SSRF/
  path-traversal; pass 2: auth/IDOR/business-logic; pass 3: deserialization/DoS/race conditions; pass 4:
  crypto/secrets/info-disclosure/supply-chain; pass 5: cross-file data-flow chains and prompt-injection;
  passes 6–10: rotate/deepen these lenses, e.g. concurrency/TOCTOU, trust-boundary, header/transport,
supply-chain, and full cross-file taint chains). Load only the reference files relevant to the current
pass's lens (not all 75 at once) to keep context cost bounded.
COVERAGE VERIFICATION (run whenever the loop stops — at convergence, the pass-5 ceiling, or the pass-10 cap)
- Before finalizing, reconcile the coverage map against the SCOPE MANIFEST built before pass 1 and confirm
  that EVERY line of EVERY in-scope file (per the GROUND RULES scope + exclusions) was actually read (not
  sampled) — every manifest file marked fully read `1..total_lines`. Produce a coverage checklist: each file
  with its total line count and the line ranges read. List excluded paths (vendored deps, build output, lock
  files, binaries) separately as "excluded" — they are not coverage gaps.
- If any in-scope file or line range was NOT fully read, run one more targeted pass over only the
  unread lines until coverage is 100%. (This coverage-completion pass does not count toward the
  10-pass cap, but any NEW bug it surfaces is added to the ledger.)
- State the final coverage result explicitly (e.g., "100% of N in-scope files / M lines read; K paths excluded").
FINAL ADVERSARIAL PASS (run ONCE, after the loop is fully done)
- SINGLE-AGENT MODE ONLY. If you are a parallel-mode lens subagent (`lens=<lens>` set), SKIP this section and
  the OUTPUT section — write your Judge-passed findings + coverage result to `sast/deep-<lens>-results.md` and
  stop; Step D3 runs the adversarial pass once over the merged set.
- After the loop terminates (converged, reached the pass-5 ceiling, or hit the 10-pass cap) AND coverage is verified at
  100%, take the FULL consolidated set of Judge-passed findings and run Adversarial Impact Validation (Step 6)
  ONE TIME over all of them with the `adv` value (default adv=critical,high,medium).
- Apply the adversarial verdicts (STANDING / DOWNGRADED / DISPUTED / WITHDRAWN) to finalize severities.
OUTPUT (single-agent mode)
- After the final adversarial pass, write a single consolidated report to the current dir named
  `sast_report-<timestamp>.md`, where `<timestamp>` is the output of `date +%Y-%m-%d_%H-%M-%S`
  (e.g., `sast_report-2026-06-11_14-30-05.md`). Use the skill's report structure (Executive Summary;
  Critical/High/Medium/Low/Informational; Unverifiable; Remediation Priority), with exact file paths +
  line numbers and concrete remediations.
- Also print a short loop log: how many passes ran, what NEW finding (if any) each pass added, the reason the
  loop stopped (converged with no new bug, reached the pass-5 ceiling, or hit the 10-pass cap), the final
  line-coverage result (100% of N in-scope files / M lines, with the per-file checklist), and the adversarial
  verdict applied to each finding.

---

## Notes

- The report filename uses a real timestamp: compute it with `date +%Y-%m-%d_%H-%M-%S` and write
  `sast_report-<timestamp>.md` to the current working directory.
- "Step 6 / Adversarial Impact Validation" refers to the base skill's reporting + severity model; run it once
  over the consolidated, Judge-passed findings only.
