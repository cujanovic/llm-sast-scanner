---
name: llm-sast-scanner-full-scan-loop
description: >
  Exhaustive partitioned security audit of a repository. Invoke explicitly as
  "llm-sast-scanner-full-scan-loop <dir> [adv=critical,high,medium] [new-scan]" where <dir> is the target
  repository/directory path; if <dir> is omitted it defaults to the current working directory.
disable-model-invocation: true
metadata:
  version: "2.0.0"
  domain: application-security
  wraps: llm-sast-scanner-convergence-loop
---

# SAST Full Scan Loop

Runs the convergence loop **partitioned**: the codebase is split into three line-balanced slices and each of the
six vulnerability lenses gets one subagent per slice — 18 subagents, each covering a third of the code under a
single lens, so it can follow call chains instead of skimming.

This is a thin wrapper. All audit mechanics live in
[`llm-sast-scanner-convergence-loop`](../llm-sast-scanner-convergence-loop/SKILL.md); this file only fixes the
partitioned invocation as the default so it does not have to be supplied by hand each time.

## How to run it

**Step A — load the procedure.** Read
[`../llm-sast-scanner-convergence-loop/SKILL.md`](../llm-sast-scanner-convergence-loop/SKILL.md) in full. It
defines D1/D2/D3, the Convergence Loop Procedure, GROUND RULES, REFERENCE LOADING, LOOP CONTROL, COVERAGE
VERIFICATION, and the report structure. Everything below is applied **on top of** that procedure, never in place
of it.

**Step B — apply the run configuration below**, forwarding whatever arguments this skill was invoked with
(`<dir>` defaults to `.`; `adv` defaults to `critical,high,medium`; `new-scan` passes through unchanged).

---

## Run configuration

```
llm-sast-scanner-convergence-loop <dir> mode=parallel adv=<adv>
```

Run this PARTITIONED, not as one agent per lens.

**STEP 1** — Build the scope manifest per the skill's D1. Then split the in-scope files into 3 partitions
balanced by LINE COUNT (~1/3 each) and cohesive by module. Write the file lists + line totals to
`.llm-sast-scanner-cache/` before dispatching anything.

**STEP 2** — Dispatch 6 lenses x 3 partitions = 18 subagents in parallel. Each gets exactly ONE lens and ONE
partition and runs its own full convergence loop over only that partition's files. Write results to
`.llm-sast-scanner-cache/deep-<lens>-<partition>-results.md`.

**STEP 3** — Consolidate by executing the skill's D3 consolidation procedure IN ITS ENTIRETY AND IN ORDER. Do
not substitute a shortened list of steps for it. D3 includes, among others: negative-verdict re-derivation, the
cross-lens shared-primitive rule, the BURIED-SINK AUDIT, Adversarial Impact Validation, and citation
verification. Run all of them.

The BURIED-SINK AUDIT is where false negatives hide, so treat it as mandatory rather than optional. Scan EVERY
lens file's notes, observations, tables, hardening-notes, "defense-in-depth", "not-reachable", and
dropped-not-FP items for any attacker-reachable sink that was demoted rather than reported. Promote each one
into the findings body at its class floor.

A demotion is INVALID — and the item must be promoted — when its stated reason:
- defers to a downstream condition, flag, or config the lens did not verify ("safe when X is off", "depends on
  Y being set"),
- cites a precondition as a mitigation ("requires an existing record", "only for provisional accounts"),
- rests on an unproven absence of a gadget, chain, or weaponization, or
- reasons object-locally about a process-global primitive.

A demotion is valid ONLY when the lens proved the negative from code it read, or the gap sits behind a layer
that is already effective on that exact path.

**REQUIRED APPENDIX FIELDS** — the report must state all of these explicitly:
- Buried-sink promotions: `<count>`, and one line per promoted item naming the lens/partition it came from and
  the demotion reason that was rejected. State 0 only if you audited every lens file and found none.
- Per-lens-per-partition pass log: passes run, what the last pass added, stop reason, converged yes/no.
- Line-count reconciliation of each partition against the manifest.
- Severity histogram.

Every finding keeps its Flow (source -> sink hops as `file:line` steps), Evidence code block, Judge verdict,
CWE, severity with a one-line rationale, and entry point.

---

## Notes

- **Do not modify the inner skill to "integrate" this configuration.** That was tried and measured: editing the
  convergence loop to make partitioning its default produced 39, 43 and 40 findings with **zero** Criticals
  across four runs, against 53 and 41 findings **with** a Critical when the inner skill was left untouched and
  the configuration supplied from outside. The separation is the thing that works; keep the audit mechanics and
  the run configuration in different files.
- Subagents dispatched by STEP 2 run the Convergence Loop Procedure directly. They must not invoke this wrapper
  or the inner skill by name, or the fan-out repeats.
- For a single-context audit with no partitioning, invoke `llm-sast-scanner-convergence-loop` directly with
  `mode=single`.
