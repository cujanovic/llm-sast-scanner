---
name: llm-sast-scanner-full-scan-loop
description: >
  Exhaustive partitioned security audit of a repository. Invoke explicitly as
  "llm-sast-scanner-full-scan-loop <dir> [adv=critical,high,medium] [new-scan]" where <dir> is the target
  repository/directory path; if <dir> is omitted it defaults to the current working directory.
disable-model-invocation: true
metadata:
  version: "2.4.0"
  domain: application-security
  wraps: llm-sast-scanner-convergence-loop
---

# SAST Full Scan Loop

Runs the convergence loop **partitioned**: the codebase is split into three line-balanced slices and every
vulnerability lens gets one subagent per slice, so each subagent covers a third of the code under a single lens
and can follow call chains instead of skimming.

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

**STEP 2** — Dispatch every lens x 3 partitions in parallel. Each subagent gets exactly ONE lens and ONE
partition and runs its own full convergence loop over only that partition's files. Write results to
`.llm-sast-scanner-cache/deep-<lens>-<partition>-results.md`.

The lens set is the six in the base skill's class table, **plus any additional lens the detected stack
warrants** — split one out when a stack puts a meaningful body of code under classes the six would otherwise
sweep past. Name each added lens in the report's appendix alongside the classes it owns, so coverage stays
attributable and runs stay comparable.

**STEP 2a — LEDGER SINK CALLER ENUMERATION.** If `project-memory.md`'s confirmed-findings ledger is
non-empty, a subagent OWNS a ledger sink when that sink's file is in the subagent's partition. Each subagent
traces every sink it owns BACKWARD to all of that sink's entry points, repository-wide — reaching outside its
own partition and following intermediate helpers, services, and resolvers through however many hops it takes
to arrive at an entry point. Your READ SCOPE IS UNRESTRICTED; the partition bounds what you must COVER, not
how far you may trace.

A known sink's other callers are the routes a re-scan otherwise never revisits: memory prioritizes *files*, so
a sink gets re-confirmed through the entry point already on record while its remaining entry points stay
unexamined. Each entry point that is not already reported for that sink is a NEW CANDIDATE: run it through the
full Source→Sink + Judge process and report it as its own finding, per the *(entry point → sink)* identity
rule. Evaluate every hop along the way for defects of its own — an authorization gate, a validation branch, or
a state check sitting mid-chain is in scope for its own class, not merely a step on the path.

Each subagent states in its results file, for every sink it owns: the entry points it traced to, the hop chain
for each, which were already reported, and which are new. Write `new entry points: <count>` — `0` is a valid
answer only after tracing.

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
- rests on an unproven absence of a gadget, chain, or weaponization,
- defers across a partition or lens boundary ("the consumer is outside this partition", "no p3 caller taints
  it", "callers live in p1/p2", "the other lens owns it"), or
- reasons object-locally about a process-global primitive.

A demotion is valid ONLY when the lens proved the negative from code it read, or the gap sits behind a layer
that is already effective on that exact path.

**STEP X — CROSS-PARTITION CLEARANCE RECONCILIATION.** Partitioning splits sinks from their callers, so a
sink can be cleared by every agent that saw it and examined by none in full. Build an index keyed by sink
`file:line` covering every sink that appears in a Clearance Record, a Hardening Note, a Positive Pattern, or
any other non-finding disposition in ANY lens file. For each sink appearing in two or more lens files, compare
the rationales. When each clearing agent scoped its rationale to its own partition or lens, that is a COVERAGE
GAP, not a clearance — no agent evaluated the union of entry points. Promote it into the findings body at its
class floor.

A multi-agent clearance stands ONLY when one agent's rationale enumerates that sink's callers repo-wide from
code that agent actually read.

**STEP Y — HAND-OFF HARVEST.** Scan every lens file for items it assigned to a different lens or partition
("belongs to crypto-data", "needs the p1/p2 server-side lens", "callers outside p3 should...", "if X becomes
client-controlled in future partitions"). Every such item is a required report item: either promoted as a
finding with a severity, or listed with a stated disposition and the evidence that closed it.

**REQUIRED APPENDIX FIELDS** — the report must state all of these explicitly:
- Buried-sink promotions: `<count>`, and one line per promoted item naming the lens/partition it came from and
  the demotion reason that was rejected. State 0 only if you audited every lens file and found none.
- Cross-partition clearance reconciliation (STEP X): one row per sink cleared by two or more agents — sink
  `file:line`, the lenses/partitions that cleared it, the scope each one claimed, and the verdict (GAP promoted
  / clearance stands). Then `promoted: <count>`.
- Routed hand-offs (STEP Y): one line per hand-off — source lens/partition, target, the item, and its
  disposition. Then `routed: <count>`.
- Ledger sink caller enumeration (STEP 2a): one row per ledger sink — sink `file:line`, the partition that
  owned it, each entry point traced to with its hop chain, which were already reported, and which are new.
  Then `new entry points: <count>`. State `ledger empty` if there was no ledger to trace against.
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
- **STEP X and STEP Y exist because consolidation was measured to be the largest single source of variance.**
  Three consolidations of one identical set of 18 lens files produced 55, 95 and 96 findings. The 55-finding
  run dropped exactly three Mediums (a hardcoded AES key + static IV, and two S3 object-key sinks); every one
  of them was present in the lens artifacts, demoted with a partition-boundary rationale, and recovered by a
  consolidation that actually ran the buried-sink audit. Adding STEP X/Y on top raised buried-sink promotions
  from 2 to 7 and routed 25 hand-offs that otherwise evaporate. Note the ceiling: the same three consolidations
  all missed a client-supplied boolean used as an authorization gate, because no lens file recorded it —
  consolidation cannot recover what detection never wrote down.
- **STEP 2a exists because `new-scan` was measured not to recover known misses.** A re-scan with a populated
  ledger (11 confirmed findings, 7 hotspots) advanced the ratchet and added findings, but missed a verified
  authorization defect: a client-supplied boolean in an OR with a server-derived admin check, opening a second
  route to a sink already in the ledger. The re-scan re-confirmed that sink through its recorded entry point
  and never enumerated the others. Memory's priority set is file-scoped — hotspots, churn, prior-finding files
  — so no term in it says "find this sink's other callers." The enumeration is cheap because the ledger is
  small; keep it keyed to the ledger rather than to all sinks.
- **STEP 2a traces from the SINK's owner outward, not from each partition inward — this direction was
  measured.** The first version made every subagent enumerate call sites *within its own partition*, which
  requires a caller-side agent to infer that a local chain eventually lands on a sink it cannot see. It
  produced 7 new entry points, all of them shallow two-hop resolver→datasource→sink routes, and still missed a
  four-hop route that left the caller's partition mid-chain. The one agent that ever found that route was
  assigned the sink's partition and traced backward out of it. Sink-owner tracing works because the owning
  agent has already read and understood the sink; caller-side enumeration asks for a forward inference across
  a boundary. Do not flip this back.
- Subagents dispatched by STEP 2 run the Convergence Loop Procedure directly. They must not invoke this wrapper
  or the inner skill by name, or the fan-out repeats.
- For a single-context audit with no partitioning, invoke `llm-sast-scanner-convergence-loop` directly with
  `mode=single`.
