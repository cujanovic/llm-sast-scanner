# SAST Security Assessment

Your goal is to identify security vulnerabilities in the codebase located in the current working directory by
orchestrating the `llm-sast-scanner` skill across parallel subagents, each owning an enumerated slice of work.

All output is written to a `.llm-sast-scanner-cache/` folder in the project root.

**The rule that makes this work: enumerate before you examine, and give every enumerated item a verdict.**
Coverage is `rows dispositioned / rows enumerated` — two integers a reader can subtract. It is never a claim
an agent asserts about itself.

**Concurrency:** run at most **one active orchestration per target directory and `.llm-sast-scanner-cache/`**
at a time. Serialize concurrent scans externally.

**Reuse / skip rule.** A results file may be reused only when it ends with its completion sentinel **and**
records a `base-sha` equal to the current `git rev-parse HEAD` **and** `git status --porcelain` is empty.
Missing sentinel, different SHA, dirty worktree, or non-git target ⇒ re-run and overwrite. A file that exists
but lacks its sentinel is from a crashed run.

> **Skill resolution:** subagents invoke skills by name (`llm-sast-scanner`, `llm-sast-scanner-full-scan-loop`).
> Each tool loads them from its own skills directory — Claude Code from `.claude/skills/`, Cursor/Codex/agents
> from `.agents/skills/`. Both directories are symlinks to the single canonical skill source at the repo root,
> so the two runtimes always run identical skill content.

---

## Arguments

- `adv=critical,high,medium` (case-insensitive, comma-separated) — controls which severities go through the
  scanner's **Step 6: Adversarial Impact Validation**. Pass the same `adv=` value to every Step 2 subagent and
  to the Step 3 report agent (the report agent does not run Step 6, but it needs to know whether findings carry
  an `Adversarial:` line).

  **Default when `adv` is omitted differs by flow, on purpose:** the Step 2 + Step 3 fan-out **skips Step 6
  entirely**, while the Exhaustive Audit (D1–D3 / `llm-sast-scanner-full-scan-loop`) **runs it at
  `adv=critical,high,medium`** at consolidation. Do not carry one default into the other.

- `new-scan` — re-run every agent regardless of the reuse rule, and consume `project-memory.md` as an active
  plan (see the loop skill's **Iterative Improvement Across Runs**).

---

## Step 1: Scope, Threat Model, and Worklists

Ensure `.llm-sast-scanner-cache/` is in the target repo's `.gitignore`.

Run **in-session** (not as a subagent, since later steps read its output) the `llm-sast-scanner` skill's
**Step 1 (Understand Scope — Build the Denominators)**. Produce:

1. **`base-sha`** — `git rev-parse HEAD` plus `git status --porcelain` (or `unknown` on a non-git target).
   Every artifact this run writes records it.
2. **The file list** — `git ls-files`, minus binaries, vendored trees, build output, lock files, and the
   scanner's own artifacts. On a non-git target, a find over the tree with the same exclusions.
3. **`.llm-sast-scanner-cache/surface.tsv` (W1)** — one row per externally-reachable operation:
   `kind <TAB> file:line <TAB> operation <TAB> guards-verbatim <TAB> input-type`. Write an enumeration command
   for the target's framework and paste its raw output; do not hand-curate. Record the command in
   `scan-plan.md` with its row count.

   **Verify the enumeration before trusting it.** Compare W1's row count against a raw `grep -c` of the
   framework's operation marker, then **account for every row of the difference by name**. Two things produce
   it: markers inside comments or docstrings, which are not operations and are correctly absent; and
   declaration shapes the command mishandles — multi-line decorators, a comment or blank line between the
   decorator and the signature, wrapped registrations, inherited routes — which are operations and must be
   recovered. Fix the command and re-run until every row of the difference is explained.

   **Validate the columns too.** The guard cell holds a declaration chain and nothing else. Reject the
   enumeration when any cell carries function-body tokens (braces, semicolons, `return`, assignment keywords)
   or runs past a couple of hundred characters — the extractor ran past the declaration. Then open three rows
   at random and confirm each cell against the source at its cited `file:line`. A bled guard column makes an
   unguarded operation read as guarded, defeating the sort. Record paths **target-relative** — absolute paths
   embed the operator's username and machine layout.

   An under-built W1
   silently shrinks every surface-bound class's denominator, which is the failure this whole design exists to
   prevent.
4. **`.llm-sast-scanner-cache/assets.tsv` (W3)** — per asset-bound class, the glob and its matching files.
5. **`.llm-sast-scanner-cache/architecture-threat-model.md`** — languages & frameworks, entry points, trust
   boundaries, authN/authZ model, data stores, outbound calls, detected stack, the applicable-class set derived
   from the dependency manifests and extensions actually present, and `base-sha`.
6. **`.llm-sast-scanner-cache/project-memory.md`** — ensure it exists; initialize from the template in the base
   skill's **Project Memory Protocol** if absent. Consumed by every detection subagent as *hints, never
   authority*.

Reuse an existing `architecture-threat-model.md` only when its recorded `base-sha` matches the current HEAD and
the worktree is clean. **Always rebuild the worklists** — they are cheap and they are the run's ground truth.

**Wait for this step to finish before proceeding.**

---

## Step 2: Detection (Parallel)

Initialize `LENS_RERAN=0`. **`new-scan` sets `LENS_RERAN=1` and re-runs everything.**

Two agent families, all dispatched **in parallel**. For each, reuse its results file only if it passes the
reuse rule above; otherwise set `LENS_RERAN=1` and launch the agent.

### 2a. Surface shards — surface-bound classes

Split `W1` into contiguous slices of **20–30 operations** (fewer if handlers are large), sized so one agent can
read each operation's handler and its transitive callees. One subagent per slice, writing to
`.llm-sast-scanner-cache/surface-shard-<id>-results.md`.

Each shard evaluates **every surface-bound class against every row in its slice**: missing auth (BFLA), IDOR,
privilege escalation, CSRF, brute force, verification code abuse, mass assignment, HTTP method tampering,
business logic, improper input validation, session fixation/puzzling, reverse-proxy access bypass, email parser
differential, excessive agency, API/REST/web-service security, webhook/integration security.

These classes are sharded by *operation* rather than by *class* because they fail by comparison: an operation
is vulnerable relative to its siblings. An agent can only see that if the siblings are in front of it as rows.

### 2b. Class groups — sink-bound and asset-bound classes

Six subagents, one per lens, writing to `.llm-sast-scanner-cache/<lens>-results.md`.

| Lens | Classes |
|------|---------|
| injection | SQLi, XSS, client-side prototype pollution, SSTI, SSI injection, ESI injection, NoSQLi, GraphQL injection, XXE/XSLT, RCE/command injection, environment variable injection (CWE-99/454), expression-language injection, LDAP injection, XPath/XQuery injection, CSV/formula injection, log injection, prompt injection (LLM01), insecure output handling (LLM05), DOM clobbering |
| access-auth | hardcoded secrets (CWE-798), default credentials, JWT construction/validation sinks, OAuth 2.0 / OIDC configuration, session primitives, BaaS rules files (Supabase RLS / Firebase Security Rules), RAG / vector & embedding security (LLM08), MCP configuration, gRPC service definitions |
| crypto-data | weak crypto/hash, information disclosure (incl. LLM02), insecure cookie, trust boundary, client-IP / network-origin trust (XFF spoofing), shared-client cache/dedup cross-user leak, cleartext transmission, certificate/TLS validation, system prompt leakage (LLM07), privacy / data protection (PII) |
| server-side | SSRF, path traversal/LFI/RFI, client-side path traversal, server-side prototype pollution, insecure deserialization, arbitrary file upload, JNDI injection, race conditions, insecure temp file, file permissions, batch/ETL/mainframe data-pipeline security |
| protocol-infra | open redirect, reverse tabnabbing, HTTP request smuggling/desync, HTTP response splitting, host header poisoning, correlation/tracing header injection, CORS misconfiguration, WebSocket security (CSWSH), postMessage security, XSSI / JSONP / RFD, clickjacking, web cache deception/poisoning, denial of service (incl. LLM10), GraphQL DoS, regex injection/ReDoS, CVE patterns, Content Security Policy, XS-Leaks |
| hardening-platform | output encoding, format string injection, ASP.NET security misconfiguration, hardcoded code/backdoor, dependency confusion, ML supply chain & data/model poisoning (LLM03/04), AI editor / agent config poisoning, PHP security (incl. TYPO3), Android security, iOS security, Electron / desktop app security, C/C++ memory safety, smart contract security (Solidity/EVM, Solana/Anchor, Move/Aptos/Sui, TRON, Substrate/XCM), IaC security, subdomain takeover, Kubernetes / cloud orchestration, CI/CD & container security, nginx / web-server configuration, supply chain security |

### Instruction pattern (both families)

Give each subagent the same text, substituting only the tail block (agent id, assigned rows or class list,
results path):

> Read `.llm-sast-scanner-cache/architecture-threat-model.md` for context and
> `.llm-sast-scanner-cache/project-memory.md` as **hints, never authority** (base skill's **Project Memory
> Protocol**: memory may prioritize or explain known-safe patterns but must never make you skip a row or
> auto-dismiss a class; a false-positive entry suppresses a re-report only after you re-confirm its safe
> rationale in the current code).
>
> Then run the `llm-sast-scanner` skill over your assigned denominator. From the skill's `references/`
> directory, load the reference files for your classes, gated on the stack actually present — derive the gate
> from the repo's dependency manifests and the extensions in the file list, gate on the behavioral **surface**
> rather than a library keyword, and **load when unsure**. Also read every `*.md` in the skill's `context/`
> directory — ungated, never stack-gated (base skill Step 2 → **External Context**); cite any file that changed
> a verdict in the finding's `Context:` line.
>
> Follow the skill's workflow — Source→Sink taint tracking (Step 3), business-logic/auth analysis (Step 4),
> Judge re-verification (Step 5), and (only if `adv=` was provided) Adversarial Impact Validation (Step 6).
>
> **Produce a Disposition Ledger per class** in the base skill's format: binding, denominator, pasted
> enumeration output, one row per item with evidence transcribed verbatim, a `read` range, a cited
> disposition, and `Dispositioned: N/N`. Sort your rows by the evidence column before dispositioning —
> operations that share a purpose but not a guard chain land next to each other, and that adjacency is what
> surfaces the outlier.
>
> **Read to the decision point and record every range you opened.** The declaration chain says what was
> declared; the handler says what was routed; only the code at the end of the call chain says what the
> operation does. When the range you read contains a call into project code, open the callee, append its range
> to the `read` cell, and continue until you reach the code that implements or refuses the behavior. Never
> clear a row from a callee's name — `verify*`/`check*`/`validate*` are hypotheses, and the vulnerable path is
> often the one whose name promises safety. Name any literal argument at a call site and say which branch it
> selects.
>
> Every disposition cites — `SAFE-because <guard>@file:line`, `NOT-REACHABLE — <what is absent>, per
> file.ext:START-END`, or `FINDING VULN-nnn`. No two rows may share a disposition string.
>
> **Write your ledger to the exact results path you were given** — full Disposition Ledger tables, in that
> file. Do not emit an area-level or focus-area summary in place of rows, do not move the ledger into a side
> file and leave a pointer, and do not write to a filename outside the set you were given.
>
> Report CONFIRMED / LIKELY findings using the skill's finding format. Do **not** write to
> `project-memory.md` (the report step is the single writer). **As the FINAL line of the results file — only
> once every assigned row is dispositioned — append `<!-- LLM-SAST-COMPLETE agent=<id> contract=worklist-v1
> base-sha=<sha> dispositioned=<D>/<T> -->`.** It is what Step 3 uses to tell a finished agent from a crashed
> one; omit it if you stop early.

**Wait for all subagents to finish before proceeding.**

---

## Step 3: Report Generation

Regenerate the report whenever `LENS_RERAN=1`, any results file is missing or unsentinelled, or run state is
unknown. Skip Step 3 only when every agent was reused, every results file carries the current `base-sha`, and
`final-report.md` itself carries it.

Launch a single subagent:

> First confirm every expected results file exists, ends with its sentinel, and records the current `base-sha`.
> **Refuse mixed-SHA result sets.** Any missing, unsentinelled, or divergent file is incomplete — re-run that
> agent and overwrite before consolidating.
>
> **Reconcile coverage.** Sum the `dispositioned=<D>/<T>` pairs. Confirm the surface shards collectively cover
> every row of `surface.tsv` exactly once — no gaps, no overlaps. Re-run any shard whose range diverges.
> **Any class with D < T is INCOMPLETE**: re-run it, or name it as incomplete in the report. Never present a
> partial class as cleared.
>
> Also count, across all results files, (a) dispositions carrying no `file:line`, (b) rows with an empty or
> single-line `read` cell, and (c) duplicate disposition strings. Each is a row that was filled rather than
> worked — one judgement copied across many rows. Re-run any agent whose ledger contains them, and state all
> three counts in the report's Coverage Ledger.
>
> Also count rows whose `read` cell holds a single range containing a call into project code — rows that
> stopped at the routing layer rather than following the call to the logic. Re-run any agent with a high count,
> and state it in the Coverage Ledger.
>
> Read all `.llm-sast-scanner-cache/*-results.md` files and `architecture-threat-model.md`, then apply the
> `llm-sast-scanner` skill's **Step 7 (Report Findings)** — severity model, severity-downgrade rule, finding
> format, and report structure — to consolidate every finding into `.llm-sast-scanner-cache/final-report.md`,
> ranked by severity (Critical → Info) with exact file paths, line numbers, and concrete remediations. Include
> the skill's **Coverage Ledger** section with the per-class arithmetic.
>
> De-duplicate findings reported by more than one agent (same **entry point** + `file:line` + class = one
> finding; **independent entry points that share a sink line stay separate** — per the base skill's *(entry
> point → sink)* rule). Preserve Platform Auth Gap rollups — do not expand an all-NONE-auth surface back into N
> duplicate missing-auth rows.
>
> If any class ended incomplete, the **Executive Summary must open with a prominent warning** naming those
> classes and their shortfall.
>
> Append `<!-- LLM-SAST-COMPLETE base-sha=<sha> -->` as the final nonblank line. Then, as the **single
> writer**, update `.llm-sast-scanner-cache/project-memory.md` per the base skill's **Project Memory
> Protocol**: append newly CONFIRMED findings with the current SHA, record downgraded/disputed findings as
> false-positive patterns with the rationale that defeated them, refresh project security primitives and
> hotspots, and bump `last-scanned-sha` / `last-updated`.

---

## Alternative: Exhaustive Audit

For a deeper audit than the Step 2 fan-out, use the `llm-sast-scanner-full-scan-loop` skill. It comes in two
modes and performs the D1–D3 orchestration natively:

- **`mode=single`** — one context owns every ledger end to end. Strongest consistency guarantee.
- **`mode=parallel`** (default) — the same surface-shard + class-group fan-out as Step 2, plus a challenge pass
  over every `SAFE` row on mixed-guard surfaces, and a single consolidated adversarial pass at merge time.

Run it as `llm-sast-scanner-full-scan-loop <dir>` and it executes the whole flow itself.

---

When the chosen flow is complete, tell the user where the report is
(`.llm-sast-scanner-cache/final-report.md` for Step 3, or `sast_report-<timestamp>.md` for the exhaustive
audit), give a short summary of the highest-severity findings, and state the coverage arithmetic.
