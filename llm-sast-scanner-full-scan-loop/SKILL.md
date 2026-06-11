---
name: llm-sast-scanner-full-scan-loop
description: >
  Convergence-driven, exhaustive line-by-line security audit wrapper around the llm-sast-scanner skill.
  Invoke explicitly as "llm-sast-scanner-full-scan-loop <dir>" where <dir> is the target repository/directory path;
  if <dir> is omitted it defaults to the current working directory.
  Runs the SAST detection workflow (Steps 1-5) in a multi-pass loop until convergence (hard stop at pass 5,
  extendable to a max of 10), verifies 100% line coverage, then runs Adversarial Impact Validation (Step 6) once
  over the consolidated findings and writes a timestamped consolidated report.
disable-model-invocation: true
metadata:
  version: "1.0.0"
  domain: application-security
  wraps: llm-sast-scanner
---

# SAST Full Scan Loop

## Purpose

A driver command around the [`llm-sast-scanner`](../llm-sast-scanner/SKILL.md) skill. It performs an
exhaustive, convergence-driven, line-by-line security audit of an entire repository passed as an argument.

## Argument

```
llm-sast-scanner-full-scan-loop <dir>
```

- `<dir>` — the path to the repository/directory to audit. Use this value wherever the prompt below
  references the target directory. If no `<dir>` is provided, default to the current working directory
  (`.`) and audit it.

## Prerequisite

Load the base skill first: read [`../llm-sast-scanner/SKILL.md`](../llm-sast-scanner/SKILL.md). Load
reference files from its `references/` directory ON DEMAND, per pass — only the subset relevant to the
current pass's analysis lens (see LOOP CONTROL), rather than all 40 at once. As the lens rotates across
passes, every vulnerability class gets covered, without holding all references in context simultaneously.
All step numbers (Step 1-6), the Judge protocol, the false-positive guardrails, the severity model, and the
report structure are defined there and MUST be used.

## Procedure

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
  keeps total read cost ~1x the repo while still getting multi-lens depth.
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
  pass's lens (not all 40 at once) to keep context cost bounded.
COVERAGE VERIFICATION (run whenever the loop stops — at convergence, the pass-5 ceiling, or the pass-10 cap)
- Before finalizing, confirm via the coverage map that EVERY line of EVERY in-scope file (per the GROUND
  RULES scope + exclusions) was actually read (not sampled). Produce a coverage checklist: each file with
  its total line count and the line ranges read. List excluded paths (vendored deps, build output, lock
  files, binaries) separately as "excluded" — they are not coverage gaps.
- If any in-scope file or line range was NOT fully read, run one more targeted pass over only the
  unread lines until coverage is 100%. (This coverage-completion pass does not count toward the
  10-pass cap, but any NEW bug it surfaces is added to the ledger.)
- State the final coverage result explicitly (e.g., "100% of N in-scope files / M lines read; K paths excluded").
FINAL ADVERSARIAL PASS (run ONCE, after the loop is fully done)
- After the loop terminates (converged, reached the pass-5 ceiling, or hit the 10-pass cap) AND coverage is verified at
  100%, take the FULL consolidated set of Judge-passed findings and run Adversarial Impact Validation (Step 6)
  ONE TIME over all of them with adv=critical,high,medium.
- Apply the adversarial verdicts (STANDING / DOWNGRADED / DISPUTED / WITHDRAWN) to finalize severities.
OUTPUT
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
