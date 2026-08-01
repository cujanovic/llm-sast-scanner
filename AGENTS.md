# SAST Security Assessment

Your goal is to identify security vulnerabilities in the codebase located in the current working directory by orchestrating the `llm-sast-scanner` skill across parallel subagents — one per vulnerability lens — so each lens runs in its own isolated context.

All output is written to a `.llm-sast-scanner-cache/` folder in the project root. Steps may be skipped only when strict shell artifact validation succeeds for the expected lens (where applicable), the artifact's `source-fingerprint=` matches the current v2 snapshot fingerprint (`CURRENT_FP`), and snapshot verification/report rules in each step are satisfied — a completion marker alone never authorizes skip. A file that exists **but lacks the terminal sentinel, fails validation, or carries a mismatched fingerprint** is from a crashed/partial/stale run — re-run that step and overwrite it.

**Concurrency:** run at most **one active orchestration per target directory and `.llm-sast-scanner-cache/`** at a time. Concurrent whole scans against the same target/cache are unsupported — serialize them externally. This implementation does not provide safe shared cleanup under concurrency.

> **Skill resolution:** subagents invoke skills by name (`llm-sast-scanner`, `llm-sast-scanner-full-scan-loop`). Each tool loads them from its own skills directory — Claude Code from `.claude/skills/`, Cursor/Codex/agents from `.agents/skills/`. Both directories are symlinks to the single canonical skill source at the repo root, so the two runtimes always run identical skill content.

---

## Arguments

This orchestrator forwards optional tagged arguments to the underlying skill.

- `adv=critical,high,medium` (case-insensitive, comma-separated) — controls which severities go through the scanner's **Step 6: Adversarial Impact Validation**. Pass the same `adv=` value to every Step 2 subagent and to the Step 3 report agent (the report agent does not run Step 6, but it needs to know whether findings carry an `Adversarial:` line).

  **Default when `adv` is omitted differs by flow, on purpose:** the Step 2 + Step 3 fan-out **skips Step 6 entirely**, while the Exhaustive Convergence Audit (D1–D3 / `llm-sast-scanner-full-scan-loop`) **runs it at `adv=critical,high,medium`** at consolidation. Do not carry one default into the other.

---

## Snapshot prepare (before Step 1)

Resolve `<scanner-repo>` as the parent directory of the installed `llm-sast-scanner-full-scan-loop` wrapper skill (the repository root that contains `scripts/scan-cache-contract.sh`, not the target being scanned).

Ensure `.llm-sast-scanner-cache/` is added to the target repo's `.gitignore` if not already ignored — **before** snapshot prepare (a post-prepare gitignore mutation would change the live tree and invalidate the snapshot).

```bash
bash "<scanner-repo>/scripts/scan-cache-contract.sh" snapshot prepare \
  --target "<dir>" --cache "<dir>/.llm-sast-scanner-cache"
CURRENT_SNAPSHOT="$(cat "<dir>/.llm-sast-scanner-cache/snapshot-current")"
SNAPSHOT_ROOT="${CURRENT_SNAPSHOT}/tree"
CURRENT_FP="$(cat "${CURRENT_SNAPSHOT}/source-fingerprint.txt")"
```

All ordinary and deep agents read source only from `SNAPSHOT_ROOT`, write findings and artifacts to the original target cache, and cite **original target-relative paths** (never the snapshot prefix). The shared coverage denominator is `${CURRENT_SNAPSHOT}/scope-manifest.b64.tsv`.

---

## Step 1: Codebase Analysis & Threat Modeling

Check if `.llm-sast-scanner-cache/architecture-threat-model.md` already exists **and is current** — reuse it only when its recorded `source-fingerprint:` line exactly matches `CURRENT_FP`. Pre-fingerprint or mismatched threat models are stale — **regenerate** it — the code changed, so entry points / detected stack / the stack-gated allowlist may have too, and a stale `architecture-threat-model.md` silently drops newly-applicable lenses.

Otherwise, **in-session** (not as a subagent, since later steps read its output), run the `llm-sast-scanner` skill's **Step 1 (Understand Scope)** over `SNAPSHOT_ROOT` and write a short architecture/threat-model brief to `.llm-sast-scanner-cache/architecture-threat-model.md` covering: languages & frameworks, entry points (routes/handlers/CLI/jobs), trust boundaries, authN/authZ model, data stores, outbound calls, and the **detected stack** so later lenses can skip inapplicable reference files. Also record the **per-lens stack-gated reference allowlist** derived from the files actually present (gateable platform/language/infra references whose signals appear, plus the always-loaded language-agnostic classes), so lenses share one definition of applicable classes and drop only provably-absent stacks. Record both `git rev-parse HEAD` (history only — not the freshness authority) and the current `source-fingerprint:` (`CURRENT_FP`) in the threat model.

**Project memory (always, even when `architecture-threat-model.md` already existed):** ensure `.llm-sast-scanner-cache/project-memory.md` exists; if absent, initialize it from the template in the base skill's **Project Memory Protocol**. This file carries cross-scan hints (confirmed findings, confirmed false-positive patterns, project security primitives, hotspots) and is consumed by every detection subagent as *hints, never authority*.

**Wait for this step to finish before proceeding.**

---

## Step 2: Vulnerability Detection (Parallel)

Initialize `ORDINARY_LENS_RERAN=0` before launching lenses. **`new-scan` sets `ORDINARY_LENS_RERAN=1` and re-runs every lens** (ignore skip short-circuit).

Start **one subagent per lens**, all **in parallel**. For each lens, first attempt strict shell skip validation:

```bash
bash "<scanner-repo>/scripts/scan-cache-contract.sh" artifact shallow \
  --file "<dir>/.llm-sast-scanner-cache/<lens>-results.md" \
  --expected-lens "<lens>" \
  --expected-fingerprint "$CURRENT_FP"
```

When validation succeeds (exit 0), **reuse** that lens artifact and leave `ORDINARY_LENS_RERAN` unchanged. When validation fails or the file is absent, set `ORDINARY_LENS_RERAN=1` and launch that lens's subagent (overwrite on completion).

A present-but-unmarked or validation-failing file is a crashed/partial/stale run — re-run that lens and overwrite it.

Give each subagent the same instruction pattern, substituting the lens name, class list, and results path from the table below:

> Read `.llm-sast-scanner-cache/architecture-threat-model.md` for context and `.llm-sast-scanner-cache/project-memory.md` as **hints, never authority** (follow the base skill's **Project Memory Protocol**: memory may prioritize or explain known-safe patterns but must never make you skip a line or auto-dismiss a class; a false-positive entry may suppress a re-report only after you re-confirm its safe rationale in the current code). Scan source only from `SNAPSHOT_ROOT` (`<dir>` snapshot tree) and cite **original target-relative paths** in every finding. Then run the `llm-sast-scanner` skill focused on the **\<lens\>** vulnerability classes. From the skill's `references/` directory, load only your lens's reference files that are on the stack-gated allowlist in `architecture-threat-model.md` (always-load the language-agnostic classes; skip only stacks whose files are absent; when unsure, load). Also read every `*.md` in the skill's `context/` directory — ungated, never stack-gated (base skill Step 2 → **External Context**); cite any file that changed a verdict in the finding's `Context:` line. Follow the skill's full workflow — Source→Sink taint tracking (Step 3), business-logic/auth analysis (Step 4), Judge re-verification (Step 5), and (only if `adv=` was provided) Adversarial Impact Validation (Step 6). Report only CONFIRMED / LIKELY findings using the skill's finding format. Write all findings to the results file below. Do **not** write to `project-memory.md` (the report step is the single writer). Clean up any intermediate recon/threat/batch files for this lens when done. **As the FINAL line of the results file — only once your analysis is complete — append the completion sentinel `<!-- LLM-SAST-COMPLETE lens=<lens> source-fingerprint=<hex> -->`** where `<hex>` is `CURRENT_FP`; it is what the resume/consolidation steps use to tell a finished lens from a crashed one, so write it ONLY when done and omit it if you stop early.

| Lens | Results file | Vulnerability classes (reference lenses) |
|------|--------------|------------------------------------------|
| injection | `.llm-sast-scanner-cache/injection-results.md` | SQLi, XSS, client-side prototype pollution, SSTI, SSI injection, ESI injection, NoSQLi, GraphQL injection, XXE, RCE/command injection, environment variable injection (CWE-99/454), expression-language injection, LDAP injection, XPath/XQuery injection, CSV/formula injection, log injection, prompt injection (LLM01), insecure output handling (LLM05), DOM clobbering |
| access-auth | `.llm-sast-scanner-cache/access-auth-results.md` | IDOR, privilege escalation / missing auth (BFLA), authentication & JWT, OAuth 2.0 / OIDC misconfiguration, default credentials, hardcoded secrets (CWE-798 secret literals at rest / client-exposure model), brute force, business logic, HTTP method tampering, verification code abuse, session fixation, session puzzling, reverse-proxy access bypass, email parser differential, mass assignment, BaaS client-side authorization (Supabase RLS / Firebase Security Rules), excessive agency (LLM06), RAG / vector & embedding security (LLM08), API / REST / web-service security, webhook / integration security, MCP (Model Context Protocol) security, gRPC / gRPC-Web server-side security |
| crypto-data | `.llm-sast-scanner-cache/crypto-data-results.md` | weak crypto/hash, information disclosure (incl. LLM02 sensitive disclosure), insecure cookie, trust boundary, client-IP / network-origin trust (XFF spoofing), shared-client cache/dedup cross-user leak, cleartext transmission, certificate/TLS validation, system prompt leakage (LLM07), privacy / data protection (PII) |
| server-side | `.llm-sast-scanner-cache/server-side-results.md` | SSRF, path traversal/LFI/RFI, client-side path traversal, server-side prototype pollution, insecure deserialization, arbitrary file upload, JNDI injection, race conditions, insecure temp file, file permissions, batch/ETL/mainframe data-pipeline security |
| protocol-infra | `.llm-sast-scanner-cache/protocol-infra-results.md` | CSRF, open redirect, reverse tabnabbing, HTTP request smuggling/desync, HTTP response splitting, host header poisoning, correlation/tracing header injection, CORS misconfiguration, WebSocket security (CSWSH), postMessage security, XSSI / JSONP / Reflected File Download (RFD), clickjacking, web cache deception/poisoning, denial of service (incl. LLM10 unbounded consumption), GraphQL denial of service, regex injection/ReDoS, CVE patterns, Content Security Policy (CSP) weaknesses, XS-Leaks |
| hardening-platform | `.llm-sast-scanner-cache/hardening-platform-results.md` | output encoding, format string injection, improper input validation (semantic-type mismatch / missing format validation), ASP.NET security misconfiguration, hardcoded code/backdoor, dependency confusion, ML supply chain & data/model poisoning (LLM03/04), AI editor / agent config poisoning (repo poisoning), PHP security (incl. TYPO3 CMS — Fluid / TypoScript / Extbase; loads **both** `php_security.md` and the separate `typo3_security.md`), Android security, iOS security, Electron / desktop app security, C/C++ memory safety, smart contract security (Solidity/EVM + Solana/Anchor + Move/Aptos/Sui + TRON + Substrate/XCM; loads `smart_contract_security.md`, `solana_smart_contract_security.md`, `move_aptos_security.md`, `tron_smart_contract_security.md`, and/or `substrate_pallet_security.md` when their stack signals appear), IaC security (Terraform/CloudFormation/ARM/Bicep/Pulumi), subdomain takeover (dangling-DNS candidate flagging in IaC/zone files), Kubernetes / cloud orchestration, CI/CD & container security, nginx / web-server configuration, supply chain security (SRI / provenance / lifecycle scripts) |

**Wait for all subagents to finish before proceeding.**

---

## Step 3: Report Generation

After all Step 2 subagents finish, **regenerate** the consolidated report whenever `ORDINARY_LENS_RERAN=1`, any lens artifact is missing/invalid, or run state is unknown/interrupted. Skip Step 3 **only when all four gates pass**:

1. **`ORDINARY_LENS_RERAN=0`** — every lens was reused via successful `artifact shallow` skip (no lens subagent ran in this invocation; `new-scan` always fails this gate).
2. **All six lens artifacts validate** — each expected shallow result passes `artifact shallow` for its exact lens and `$CURRENT_FP`.
3. **`final-report.md` validates** — `artifact report` succeeds for `$CURRENT_FP`.
4. **Live tree unchanged** — `snapshot verify` succeeds.

When all four gates pass (exit 0 throughout), skip Step 3. Otherwise launch the generate subagent below.

```bash
if [ "$ORDINARY_LENS_RERAN" -ne 0 ]; then exit 1; fi
for lens in injection access-auth crypto-data server-side protocol-infra hardening-platform; do
  bash "<scanner-repo>/scripts/scan-cache-contract.sh" artifact shallow \
    --file "<dir>/.llm-sast-scanner-cache/${lens}-results.md" \
    --expected-lens "$lens" \
    --expected-fingerprint "$CURRENT_FP" || exit 1
done
bash "<scanner-repo>/scripts/scan-cache-contract.sh" artifact report \
  --file "<dir>/.llm-sast-scanner-cache/final-report.md" \
  --expected-fingerprint "$CURRENT_FP"
bash "<scanner-repo>/scripts/scan-cache-contract.sh" snapshot verify \
  --target "<dir>" --cache "<dir>/.llm-sast-scanner-cache"
```

If any check fails, treat the report as stale and **regenerate** from all six current lens artifacts (do not skip).

Otherwise launch a single subagent:

> First confirm all six lens results files exist and each passes `artifact shallow` for its lens and `$CURRENT_FP`. Read all available `.llm-sast-scanner-cache/*-results.md` files and `.llm-sast-scanner-cache/architecture-threat-model.md` for context, then apply the `llm-sast-scanner` skill's **Step 7 (Report Findings)** — severity model, severity-downgrade rule, finding format, and report structure — to consolidate every finding into `.llm-sast-scanner-cache/final-report.md`, ranked by severity (Critical → Info) with exact **original target-relative** file paths, line numbers, and concrete remediations (findings were produced from `SNAPSHOT_ROOT`; paths in the report remain target-relative). De-duplicate findings reported by more than one lens (preserve Platform Auth Gap rollups from the base skill — do not expand an all-NONE-auth surface back into N duplicate missing-auth rows). Write the full report body first. **Immediately before the completion sentinel**, verify the live tree still matches the snapshot:
>
> ```bash
> bash "<scanner-repo>/scripts/scan-cache-contract.sh" snapshot verify \
>   --target "<dir>" --cache "<dir>/.llm-sast-scanner-cache"
> ```
>
> On verify mismatch, **discard the current run's report and artifacts** and restart from snapshot prepare. When verify succeeds, append `<!-- LLM-SAST-COMPLETE source-fingerprint=<hex> -->` as the final nonblank line of `final-report.md` (where `<hex>` is `CURRENT_FP`), then confirm the report passes:
>
> ```bash
> bash "<scanner-repo>/scripts/scan-cache-contract.sh" artifact report \
>   --file "<dir>/.llm-sast-scanner-cache/final-report.md" \
>   --expected-fingerprint "$CURRENT_FP"
> ```
>
> Only after successful verification and sentinel validation, as the **single writer**, update `.llm-sast-scanner-cache/project-memory.md` per the base skill's **Project Memory Protocol**: append newly CONFIRMED findings (with current `git rev-parse HEAD`), record any downgraded/disputed findings as false-positive patterns with the rationale that defeated them, refresh project security primitives and hotspots, and bump `last-scanned-sha` / `last-updated`. Finally run snapshot cleanup:
>
> ```bash
> bash "<scanner-repo>/scripts/scan-cache-contract.sh" snapshot cleanup \
>   --cache "<dir>/.llm-sast-scanner-cache"
> ```
>
> Never update project memory or run cleanup before successful snapshot verify and report sentinel validation.

---

## Alternative: Exhaustive Convergence Audit

<!-- FIVE-PASS-CONTRACT:START -->
**MANDATORY FIVE-PASS CONTRACT (`contract=five-pass-v1`)**
- Passes 1–5 are mandatory for every deep-scan lens. A zero-new pass before pass 5 does not satisfy convergence.
- Pass 1 — Surface inventory: entry points, input inventory, behavioral sink families, candidate ledger.
- Pass 2 — Class sweep: every on-allowlist class, intra-file source→sink traces, preliminary dispositions.
- Pass 3 — Differential analysis: peer controls, state machines, trust boundaries, inconsistent guards.
- Pass 4 — Cross-file analysis: callers/callees through helpers, services, clients, middleware, and downstream transitions.
- Pass 5 — Negative-verdict challenge: rerun structural sweeps, challenge every clearance, close inventory gaps, and run variants.
- At pass 5 or later, +0 new means converged; +N new requires another pass, up to pass 10.
<!-- FIVE-PASS-CONTRACT:END -->

<!-- SOURCE-SNAPSHOT-CONTRACT:START -->
**IMMUTABLE SOURCE SNAPSHOT CONTRACT (`source-fingerprint-v2`)**
- Prepare or verify one stable, owner-only immutable snapshot before threat modeling or any skip decision.
- Ordinary and deep agents read source only from that snapshot and report original target-relative paths.
- Every lens artifact and final report records the snapshot's 64-hex source fingerprint.
- Reuse requires strict shell artifact validation for the expected lens and current fingerprint.
- Immediately before a completion sentinel, verify the live tree against the snapshot; mismatch invalidates and restarts the run.
- Cleanup occurs only after a successful final report; interrupted runs retain the snapshot for safe resume.
<!-- SOURCE-SNAPSHOT-CONTRACT:END -->

For a deeper, line-by-line audit instead of the lens fan-out in Step 2, use the `llm-sast-scanner-full-scan-loop` skill. It comes in two modes.

### Single-agent (mode=single)

Run the `llm-sast-scanner-full-scan-loop` skill against the target directory in one session. It runs snapshot prepare before pass 1, reads only `SNAPSHOT_ROOT`, runs the mandatory five-pass floor (passes 1–5 unconditional; convergence eligible only at pass 5+ with +0 new) — each role pass spans all on-allowlist lens groups, batching references one lens group at a time within the role when context requires it — verifies 100% line coverage against `${CURRENT_SNAPSHOT}/scope-manifest.b64.tsv`, runs `snapshot verify` immediately before Step 6/report completion, runs one final adversarial pass, and writes a timestamped `sast_report-<timestamp>.md` whose completion sentinel records `source-fingerprint=<hex>`. It cleans up the snapshot only after the report sentinel is safely written and validated. Use this when you want the strongest convergence/coverage guarantee (a single context owns the ledger and coverage map).

**Single-mode verify barrier (immediately before Step 6/report):**

```bash
bash "<scanner-repo>/scripts/scan-cache-contract.sh" snapshot verify \
  --target "<dir>" --cache "<dir>/.llm-sast-scanner-cache"
```

On verify mismatch, invalidate the run and restart from snapshot prepare + pass 1. Proceed to Step 6 and report generation only when verify succeeds. After writing the report body and appending `<!-- LLM-SAST-COMPLETE source-fingerprint=<hex> -->`, validate with:

```bash
bash "<scanner-repo>/scripts/scan-cache-contract.sh" artifact report \
  --file "<dir>/sast_report-<timestamp>.md" \
  --expected-fingerprint "$CURRENT_FP"
```

Then update project memory and run `snapshot cleanup`. Never update project memory or run cleanup before successful snapshot verify and report sentinel validation.

### Deep Mode (Parallel, default) — one loop subagent per lens

Use when asked for a *"deep parallel scan"*, *"full scan loop with all agents"*, or to run the convergence loop across subagents. Each lens subagent stays fixed to its assigned lens and executes all five mandatory role passes before convergence is eligible. This trades the single-context guarantee for parallelism: each lens gets its own convergence loop, and coverage/ledger state is reconciled at merge time. Note each lens subagent independently reads every in-scope line, so total read cost scales with the number of lenses.

> **Shortcut:** the `llm-sast-scanner-full-scan-loop` skill now performs this exact fan-out natively in its default `mode=parallel`. You can simply run `llm-sast-scanner-full-scan-loop <dir>` and it will execute Steps D1–D3 below itself. The steps are spelled out here so the orchestrator can drive them directly when preferred.

**Step D1 — Analysis.** When entering deep mode **directly** (without running ordinary Steps 1–3 above), ensure `.llm-sast-scanner-cache/` is in the target `.gitignore` **before** snapshot prepare, then call snapshot prepare:

```bash
bash "<scanner-repo>/scripts/scan-cache-contract.sh" snapshot prepare \
  --target "<dir>" --cache "<dir>/.llm-sast-scanner-cache"
CURRENT_SNAPSHOT="$(cat "<dir>/.llm-sast-scanner-cache/snapshot-current")"
SNAPSHOT_ROOT="${CURRENT_SNAPSHOT}/tree"
CURRENT_FP="$(cat "${CURRENT_SNAPSHOT}/source-fingerprint.txt")"
```

When deep mode **follows** ordinary Steps 1–3, **reuse** `CURRENT_SNAPSHOT`, `SNAPSHOT_ROOT`, and `CURRENT_FP` from the global prepare above — **do not** call snapshot prepare again.

The shared coverage denominator is `${CURRENT_SNAPSHOT}/scope-manifest.b64.tsv`.

1. **Reuse** `.llm-sast-scanner-cache/architecture-threat-model.md` only when its recorded `source-fingerprint:` line exactly matches `CURRENT_FP`. Pre-fingerprint or mismatched threat models are stale — **regenerate** by running the base skill's **Step 1 (Understand Scope)** over `SNAPSHOT_ROOT` and writing a brief covering languages & frameworks, entry points, trust boundaries, authN/authZ, data stores, outbound calls, detected stack, and the per-lens stack-gated reference allowlist. Record both `git rev-parse HEAD` (history only — not the freshness authority) and the current `source-fingerprint:` in the threat model.

2. Ensure `.llm-sast-scanner-cache/project-memory.md` exists (initialize from the base skill's **Project Memory Protocol** template if missing).

3. **Write/refresh** `.llm-sast-scanner-cache/scan-plan.md` (see the loop skill's **Iterative Improvement Across Runs**): record `base-sha`, `source-fingerprint:` (copy `CURRENT_FP`), in-scope vs dropped lenses, the deep-dive file list, prior findings to re-verify, and an "improve this run" list.

**Wait for D1 to finish before proceeding.**

**Step D2 — Parallel convergence loops.** Start **one subagent per lens** (same six lenses and class lists as the Step 2 table), all **in parallel**. Skip a lens only when its deep results file already exists **and passes full five-pass artifact validation against `CURRENT_FP`** (see below) — **`new-scan` reruns every lens regardless of a matching fingerprint.** A file failing any check, lacking `source-fingerprint=`, or carrying a mismatched fingerprint is a crashed/partial/pre-contract/stale lens — re-run it and overwrite. Give each subagent the instruction below, **preceded by the `llm-sast-scanner-full-scan-loop` skill's Convergence Loop Procedure — its GROUND RULES, REFERENCE LOADING, LOOP CONTROL and COVERAGE VERIFICATION sections — pasted verbatim and byte-identically for every lens** (same text for all six, per-lens variables appended as a short tail block, so the shared prefix stays cacheable). The procedure must be pasted rather than referenced: that skill sets `disable-model-invocation: true`, so it is **not** in a subagent's invocable skill list and a subagent cannot load it by name.

Before skipping a lens, validate its artifact:

```bash
bash "<scanner-repo>/scripts/scan-cache-contract.sh" artifact deep \
  --file "<dir>/.llm-sast-scanner-cache/deep-<lens>-results.md" \
  --expected-lens "<lens>" \
  --expected-fingerprint "$CURRENT_FP"
```

**Five-pass artifact validation** (reject and re-run the lens if ANY check fails — D3 applies the same rules):
- Terminal sentinel present: `<!-- LLM-SAST-COMPLETE lens=<lens> contract=five-pass-v1 source-fingerprint=<hex> passes=<N> coverage=100% convergence=<status> -->`
- Pass log has at least five entries; pass numbers are consecutive, ascending, with no gaps or duplicates
- Passes 1–5 use the required roles in contract order: 1 Surface inventory, 2 Class sweep, 3 Differential analysis, 4 Cross-file analysis, 5 Negative-verdict challenge
- Sentinel `passes=<N>` equals the pass-log entry count (and equals the highest pass number)
- Final pass +0 at pass 5 or later → sentinel and body `## CONVERGENCE STATUS` (when present) must both claim `converged`
- Final pass +N new at pass 5–9 → artifact is **incomplete** (another pass was mandatory; re-run the lens)
- Final pass +N new at pass 10 → sentinel and body must both claim `NOT CONVERGED (hit pass-10 hard cap; last pass +N new)`
- Final pass +N new must not claim `converged`
- Body `## CONVERGENCE STATUS` and sentinel `convergence=` must agree when both are present
- **Peer-generalization clearance gate (all lenses):** `artifact deep` rejects any class Clearance Record whose
  `SAFE-because` disposition generalizes a peer control across "sensitive flows", "similar endpoints", or
  equivalent plural middleware language without per-hit `file:line` dispositions or an explicit cited finding for
  each outlier (see **PEER-DIFFERENTIAL CLEARANCE GATE** in the loop skill LOOP CONTROL)

> Read `.llm-sast-scanner-cache/architecture-threat-model.md` for context, `${CURRENT_SNAPSHOT}/scope-manifest.b64.tsv` as your shared coverage denominator (use this manifest as-is; do NOT rebuild your own, so every lens reconciles against ONE identical denominator), `CURRENT_FP` as the run's authoritative fingerprint (record its value in your terminal sentinel), and `.llm-sast-scanner-cache/project-memory.md` as **hints, never authority** (base skill's **Project Memory Protocol** — never skip a line or auto-dismiss a class; a false-positive entry suppresses a re-report only after you re-confirm its rationale in current code). Scan source only from `SNAPSHOT_ROOT` and cite **original target-relative paths** in every finding. Then run the base `llm-sast-scanner` skill following the **Convergence Loop Procedure pasted above** with `lens=<lens>` — i.e. stay fixed to the **\<lens\> vulnerability classes** for all five mandatory role passes (load only the matching references from the base skill). Do **not** try to invoke the `llm-sast-scanner-full-scan-loop` skill by name: it is not model-invocable, and re-entering the wrapper would fan out again. Also read every `*.md` in the base skill's `context/` directory — ungated, never stack-gated (base skill Step 2 → **External Context**); cite any file that changed a verdict in the finding's `Context:` line. Perform the loop's convergence phase: multi-pass Steps 1–5 (taint tracking, business-logic/auth, Judge) with the mandatory five-pass floor (passes 1–5 unconditional; convergence eligible only at pass 5+ with +0 new), with the loop's ledger + 100% line-coverage discipline applied to your lens. **Do NOT run the final Adversarial Impact Validation pass and do NOT write a timestamped report** — those are deferred to consolidation. Do **not** write to `project-memory.md` (consolidation is the single writer). Write only Judge-passed CONFIRMED / LIKELY findings, plus your final coverage result, **Pass log** (one entry per pass, all five mandatory roles for passes 1–5), and **CONVERGENCE STATUS** section (`converged` when pass 5+ ends +0 new, or `NOT CONVERGED` only when the pass-10 hard cap stops with +new on the final pass), to `.llm-sast-scanner-cache/deep-<lens>-results.md`. **As the FINAL line of that file, only after COVERAGE VERIFICATION passes, append the completion sentinel `<!-- LLM-SAST-COMPLETE lens=<lens> contract=five-pass-v1 source-fingerprint=<hex> passes=<N> coverage=100% convergence=<status> -->`** where `<hex>` is `CURRENT_FP` — it is what D3 uses to tell a finished lens from a crashed/pre-contract/stale one; omit it if you stop early so the lens is re-run.

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

> First confirm all six `.llm-sast-scanner-cache/deep-*-results.md` files exist **and that each passes full five-pass artifact validation against `CURRENT_FP`** (same rules as D2 — reject if ANY check fails; **refuse mixed-fingerprint result sets** — every lens sentinel must carry the same `source-fingerprint=` as `CURRENT_FP`):
> ```bash
> bash "<scanner-repo>/scripts/scan-cache-contract.sh" artifact deep \
>   --file "<dir>/.llm-sast-scanner-cache/deep-<lens>-results.md" \
>   --expected-lens "<lens>" \
>   --expected-fingerprint "$CURRENT_FP"
> ```
> - Terminal sentinel: `contract=five-pass-v1`, `source-fingerprint=<hex>`, `coverage=100%`, `passes=<N>`, `convergence=<status>`
> - Pass log: ≥5 entries; consecutive ascending pass numbers; passes 1–5 bound in order to Surface inventory, Class sweep, Differential analysis, Cross-file analysis, Negative-verdict challenge
> - Sentinel `passes=<N>` equals pass-log entry count
> - Final pass +0 at pass 5+ → `converged` (body `## CONVERGENCE STATUS` must agree when present)
> - Final pass +N at pass 5–9 → **incomplete** (re-run the lens)
> - Final pass +N at pass 10 → `NOT CONVERGED (hit pass-10 hard cap; last pass +N new)` (body must agree)
> - Final pass +N must not claim `converged`
> Any lens that is **missing OR fails validation** is incomplete (crashed/partial/pre-contract) — re-run it and overwrite the file before consolidating, otherwise partial findings would merge as if the lens were exhaustive. Then **reconcile every lens against the shared denominator**: confirm each lens's coverage checklist covers the SAME file set + line counts as `${CURRENT_SNAPSHOT}/scope-manifest.b64.tsv`; re-run any lens whose file set or line counts diverge. Then read all `.llm-sast-scanner-cache/deep-*-results.md` files and `.llm-sast-scanner-cache/architecture-threat-model.md`. Merge and de-duplicate findings across lenses (same **entry point** + `file:line` + class = one finding; **independent entry points that share a sink line stay separate** — per the base skill's *(entry point → sink)* finding-identity rule, so many routes funneling through one shared helper/DAO/render sink yield one finding **per route**, not one collapsed finding). **Exception (Platform Auth Gap):** when lenses report one all-NONE-auth surface rollup that lists every affected `METHOD /route`, keep that single rollup — do not expand it back into N duplicate missing-auth rows; still keep separate findings for distinct secondary bugs on those routes. Run the `llm-sast-scanner` skill's **Step 6 (Adversarial Impact Validation)** ONCE over the full consolidated set (against `SNAPSHOT_ROOT` source) with the `adv=` value forwarded to this run (default `adv=critical,high,medium`), apply the STANDING / DOWNGRADED / DISPUTED / WITHDRAWN verdicts, then write a timestamped consolidated report `sast_report-<timestamp>.md` (timestamp from `date +%Y-%m-%d_%H-%M-%S`) using the skill's report structure with **original target-relative paths**. **Immediately before the report completion sentinel**, verify the live tree still matches the snapshot:
> ```bash
> bash "<scanner-repo>/scripts/scan-cache-contract.sh" snapshot verify \
>   --target "<dir>" --cache "<dir>/.llm-sast-scanner-cache"
> ```
> On verify mismatch, **discard the current run's artifacts and report**, refresh D1 (snapshot prepare + threat model as needed), and **re-run all six lenses** — do not merge partial results from a mutated tree. When verify succeeds, append `<!-- LLM-SAST-COMPLETE source-fingerprint=<hex> -->` as the final nonblank line (where `<hex>` is `CURRENT_FP`), then confirm the report passes:
> ```bash
> bash "<scanner-repo>/scripts/scan-cache-contract.sh" artifact report \
>   --file "<dir>/sast_report-<timestamp>.md" \
>   --expected-fingerprint "$CURRENT_FP"
> ```
> Only after successful verify and report sentinel validation, update project memory and run `snapshot cleanup`. Never update memory or cleanup before successful verify and sentinel validation. **Non-convergence escalation:** read each lens's convergence status from its `deep-<lens>-results.md`; if ANY lens is `NOT CONVERGED` (hit the pass-10 hard cap while the final pass was still surfacing new bugs), the report's **Executive Summary MUST open with a prominent warning** that the audit did not saturate and is likely INCOMPLETE for those lens(es) — name them and their last-pass new-bug counts, note that 100% coverage is not convergence, and recommend manual deep review or a re-scan; do not present a partially non-converged scan as exhaustive. Also print a combined coverage summary and per-lens pass log (including each lens's convergence status). Finally, as the **single writer**, update `.llm-sast-scanner-cache/project-memory.md` per the base skill's **Project Memory Protocol** (append newly CONFIRMED findings with current `git rev-parse HEAD`; record DOWNGRADED/DISPUTED/WITHDRAWN as false-positive patterns with their defeating rationale; refresh primitives/hotspots; bump `last-scanned-sha`/`last-updated`).

---

When the chosen flow is complete, tell the user where the report is (`.llm-sast-scanner-cache/final-report.md` for Step 3, or `sast_report-<timestamp>.md` for the convergence audit) and give a short summary of the highest-severity findings.
