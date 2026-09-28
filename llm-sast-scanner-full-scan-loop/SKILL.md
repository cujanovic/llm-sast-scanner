---
name: llm-sast-scanner-full-scan-loop
description: >
  Exhaustive partitioned security audit of a repository. Invoke explicitly as
  "llm-sast-scanner-full-scan-loop <dir> [adv=critical,high,medium] [new-scan]" where <dir> is the target
  repository/directory path; if <dir> is omitted it defaults to the current working directory.
metadata:
  version: "2.22.50"
  domain: application-security
  wraps: llm-sast-scanner-convergence-loop
---

# SAST Full Scan Loop

Runs the convergence loop **partitioned**: the codebase is split into three line-balanced slices and every
vulnerability lens gets one subagent per slice, so each subagent covers a third of the code under a single lens
and can follow call chains instead of skimming.

This is a thin wrapper. All audit mechanics live in
[`llm-sast-scanner-convergence-loop`](../llm-sast-scanner-convergence-loop/SKILL.md); this file only fixes the
partitioned invocation as the default so it does not have to be supplied by hand each time. The numbered STEPs below
are the plan and are carried out as written — STEP 1 in this session, STEP 2 by dispatching one worker subagent per
lens and partition, STEP 3 by one consolidation subagent — never from inside a runtime's planning mode, whose exit
would ask a human that a non-interactive run does not have. Nothing in this file forbids subagents; it requires them.

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

**STEP 1** — runs in this session, never in a subagent: its artifacts are what every worker and STEP 3 depend
on, and a delegated cut cannot be checked by the session that dispatches against it. Build the scope manifest per
the skill's D1, writing the manifest and partition files with redirected shell commands rather than composing them
in a response. Then split the in-scope files into 3 partitions balanced by ATTACK SURFACE, not by line count
alone. The manifest holds only what D1 leaves in scope: generated output derived from in-scope source — ORM
snapshots and journals, build and bundle output, generated route trees — is excluded in `scope-excluded.txt`
with its reason, never classified or partitioned, and so are the orchestrating runtime's own run logs and exported
transcripts in the repository: they are records of a scan, not code under review, and a route string inside one is
not an entry point. Classify every remaining row as `source` (application,
infrastructure, CI and build code), `test` (test, fixture, mock and end-to-end trees) or `text` (documentation,
package manifests, lockfiles, editor and agent configuration). Count entry points per directory with STEP 2's entry-point
definition — every registration of every kind that a caller can invoke: an operation (query, mutation,
subscription, field resolver), a route or handler, a message consumer, a scheduled job, a command — plain HTTP routes
included; a class, module, schema or container that only groups such registrations is not an entry point however it
is registered, so two sessions deriving the list from one commit derive the same count — attributed to the directory
of the file that registers it. This count balances the cut and nothing else, and the registrations themselves are written
into `scan-plan.md` under a `## Entry points` heading, one line each as `<file:line> | <kind> | <name> | p<n>` with the partition holding the file (a bare `<n>` reads the same), so that STEP 3 can account for every one of them by name. The derivation table is a separate count:
a family's row holds only the registrations of that family's own protocol or declaration, and a plain HTTP route
belongs to no family, so it counts for the cut and for no row. The two totals are expected to differ; `scan-plan.md`
states both on one line, `entry points: <n> counted for the cut | <m> across families`, so no later step
reconciles them. A derivation row that reaches its count through the files a family touches, rather than through
the registrations it owns, is a STEP 1 error. The cut is a procedure run the same way every time, not a set of bounds to satisfy creatively: (1) form
units — each `source` directory at the shallowest depth at which it holds at most one third of the `source` lines
AND at most one third of the entry points, and each `test` or `text` directory at the shallowest depth at which it
holds at most one third of its own class's lines; a directory over a limit is split at its subdirectories, or at its
files when it has none, and only that directory is split; (2) sort the units by `source` lines, largest first, ties
by path ascending, and assign each in turn to the partition with the fewest `source` lines so far, ties broken by
the fewest entry points, then by the lowest partition number; (3) assign the `test` units, then the `text` units,
as two separate passes, each pass largest first with ties by path ascending, each unit to the partition with the
fewest total lines so far, ties by the lowest partition number. The same manifest therefore yields the same three
partitions, and a run at the same SHA is comparable worker by worker with the one before it. The result must still
pass the checks — no partition above 40% of the `source` lines or of the entry points, every partition within 15%
of one third of the manifest — and a failed check means one unit is too large: split only the largest unit of the
class that failed, by the quantity that failed, one level deeper and run the procedure again; never move a file by hand — units move only by the reassignment rule below — and never re-form units
that passed. The remedy repeats until the checks pass or the largest unit of the class that failed — by the quantity that
failed — is itself a single file; only then does no split remain, and the check is recorded in `scan-plan.md` as
`check failed: <check> — <file> holds <n> of <m> <source lines | entry points> (<share>%)`. The cut does not stand
as formed while a partition is over a cap: the remedy continues by reassignment — the deterministic assignment is
re-run with the over-cap partition's smallest whole units moved, in assignment order, to the partition with the
lowest share of the failed quantity, one unit at a time, until every partition is under its caps or no move leaves
every partition under them — and STEP 1 ends with one `checks:` line, written above `workers dispatched:`, `checks: pass — <the shares>` or, once remedy and reassignment leave no move,
`checks: failed — <each failure> | <the shares>`, which the report repeats.
The line is the output of `python3 <this skill's directory>/recheck.py --checks`, run from the target once the entry list
and the partition manifests are written — the one computation recheck item (19) repeats — copied verbatim, never
composed from this session's own arithmetic: while the command prints `failed` for a share, the remedy and the
reassignment continue, except for a failure that ends `(one file: <path> holds <n> of <m> entry points)` — a file is
never split, so no move can fix it; the line is written as the command prints it. It counts each entry in the partition whose manifest holds the entry's file and fails a list
line that names no partition, or one other than that file's — a bare `<n>` reads as `p<n>` — which is corrected before
any dispatch, because workers are assigned their entry points by that column. Nine entry lines of one plan once named
their partition as a bare number, and a recheck that read only `p<n>` computed a failing share for a cut that passed. A scan plan carrying a
`check failed:` line and no `checks:` line has not finished STEP 1, and nothing is dispatched on it. The named file
is that largest unit and nothing else: a `check failed` line naming a file that is not the
largest unit of the failed class by the failed quantity is a STEP 1 error, and a cut is never dispatched on it. The unit
list passes its own check before the partition table is written: every unit's parent directory holds more than one third
of its class's lines or more than one third of the entry points, or the unit was produced by the remedy for a failed
partition check and its unit line ends `(remedy split: <check>)` — any other unit whose parent is under both limits was
split without cause, which is a STEP 1 error, and the parent is the unit. Write the cut into `scan-plan.md` as the partition table — `partition | files | lines | source lines |
test lines | text lines | entry points | source share | entry-point share` — followed by one line per unit,
`<unit> -> p<n> (<source lines>, <entry points>)`, in assignment order, so the cut can be replayed. Write the file
lists + line totals to `.llm-sast-scanner-cache/` before dispatching anything. Then derive the added lens set
from the dependency-signal column of its derivation table — never from any count — and write the table
into `scan-plan.md`; compile the worker contracts
only after the lens set is fixed, and check each one before any dispatch: a contract contains the four-field
first-line form `procedure: <convergence-loop skill name> v<its version> / <base skill name> v<its version> | target:
<pwd output> | base-sha: <git output>` together with the instruction that the names and versions come from the two
frontmatters and the two values from the commands, the sentinel line `<!-- LLM-SAST-COMPLETE lens=<lens>
partition=p<n> files=<f>/<mf> lines=<l>/<ml> passes=<p> convergence=... -->`. The partition manifest's path is not
the contract's to carry: a contract serves one lens across every partition, so the manifest path belongs to the
dispatch prompt, where the path test below verifies it before the worker starts. The two forms appear as the worker's
instruction, with their placeholders
intact — `<pwd output>`, `<git output>`, `<f>/<mf>`, `<l>/<ml>`, `<p>` — introduced by the words `Its first line is`
and `The final line ... is`; a copy of either form with values filled in — a real path, a real hash, real counts —
is a header of the contract document, not an instruction to the worker, and does not satisfy the check. The wording
around them may be the orchestrator's own; the two forms and their placeholders may not. The third checked element
is the ledger sink caller enumeration itself, copied from the WORKER DISPATCH template below from the words `for every
ledger sink whose file is in your partition` through the sentence that writes the `new entry points: <count>` line, with
that placeholder intact — a summary of it in the orchestrator's words is not the procedure, and a contract that reduced it
to one clause sent twenty-seven workers who wrote thirty-seven re-verification lines where the run before had written
two hundred and thirty-three, so a report at an unchanged commit lost ninety-three of its predecessor's sinks. The fourth checked element is the
self-gate, copied from the WORKER DISPATCH template from the words `Before the final line, check your own file`
through the words `before you write it.`, `<skills root>` replaced by its path and `<lens>` by the contract's lens,
`p<n>` left for the worker: a run whose prompts were condensed carried it to none of twenty-seven workers, while the
three checked elements reached every one. A contract lacking any of the four is recompiled, never dispatched — an
omitted form is how a whole wave comes back with the wrong header — and `scan-plan.md` records `contracts checked:
<k>/<n>` before the first wave line, the output of `python3 <this skill's directory>/recheck.py --contracts` run from
the target and copied verbatim; it names each contract that fails an element, and a contract it names is recompiled
and the command run again. Before this run's `scan-plan.md` is written, an existing one — the previous run's — is copied
as it stands to `.llm-sast-scanner-cache/previous-run-<started>/scan-plan.md` (the directory created if absent; the stale
worker files join it below), because writing this plan destroys it; its last `recheck: mismatches` line becomes this
plan's row `previous run residual: <n> — <items>` — `previous run residual: 0` when that line listed no items (`0 — none`
reads the same) — or `previous run residual: none` when no earlier plan existed. When the copy has no `recheck: mismatches` line at all — the previous run ended before its recheck set (stopped, killed or crashed) and so resolved nothing — its own `previous run residual:` row is copied forward unchanged as this plan's row. This run's `scan-plan.md` is then written
anew: no dispatch, gate, wave, join or `recheck:` line of the previous run stays in it — those live in the copy — because
the recheck reads the plan's dispatch lines, join line and rosters as this run's, and a plan edited in place carried a
previous run's twenty-seven dispatch lines and twenty-nine recheck lines under a new header. `scan-plan.md` opens with the rows `invocation: <the skill invocation as given>`, `model: <the model this
session runs on, written as the base skill's header `<model>` rule prescribes — the exact model ID when the runtime
states one, else the stated display name, else `unknown`; the identifier alone, never the sentence around it>` and
`base-sha: <sha>`, `target: <the absolute path of the target directory, from pwd>`, `wrapper:
llm-sast-scanner-full-scan-loop v<this file's frontmatter version>`, `started: <date +%Y-%m-%d_%H-%M-%S, run when
this file is first written>` and `earlier-reports: <n> — <name> <bytes>, ...` — every `sast_report-*.md` already in
`<dir>` with its byte size, or `earlier-reports: 0`, `ledger rows at start: <n>` and `previous run residual: <…>` — before anything else in this run reads or writes `project-memory.md`, STEP 1
copies it to `.llm-sast-scanner-cache/project-memory.md.pre-write-<started>` — that exact name, `<started>` the
`started:` row's value — and `<n>` is the output of a command that counts, in the copy, the lines between the
`## Confirmed findings ledger` heading and the next `## ` heading that match the ledger row pattern of STEP 3's recheck
item (6), the same measure as `ledger rows after`, and no line outside that section: the false-positive section's rows
share the shape, and six runs in a row counted the whole file and corrected the row afterwards; `0`, over an empty copy,
when the file is absent or empty. An existing `project-memory.md` is the ledger every later run builds on: STEP 1
copies it and never deletes it, re-creates it or initialises it from the base skill's template — only an absent file is
initialised, after its empty copy is written — and an existing `scan-plan.md` is copied into `previous-run-<started>/`
before this plan replaces it, never discarded; at a `new-scan` the copy's ledger is what the Same-commit carry and the
not-re-found marks read, so a memory re-created first leaves the run nothing to carry. The copy is the state before this run, the writer's redo source and the recheck's
reference for `before`, and nothing in the run overwrites it; a value typed into this row from anywhere but that
command's output — an earlier scan plan, an earlier report — is the previous run's number, not this one's. STEP 3
copies the report header from these rows, so a value missing here is missing from the report, and the `started:` and
`earlier-reports:` rows are what the report-naming rule below and the close-out compare against. Once
`workers dispatched:` is written, no row above it is edited: a value found wrong is corrected by appending
` → corrected <new value> at <time>` to its line, so the row shows the value the run started with and the one it
ended with, and a recheck that compares against it compares against what the run actually used.

**REQUIRED CACHE ARTIFACTS.** Every run leaves this exact file set in `.llm-sast-scanner-cache/`. Each one is
the written record of a decision that otherwise stays in one agent's context and cannot be audited afterward.

| File | Written by | Records |
|------|-----------|---------|
| `scope-manifest.txt` | STEP 1 | every in-scope file with its line count, and the total |
| `scope-excluded.txt` | STEP 1 | every path dropped from scope, one per line, each with its reason |
| `project-memory.md.pre-write-<started>` | STEP 1 | `project-memory.md` as it stood before the run touched it — the `ledger rows at start` count and the writer's redo source; never overwritten; on a first run, with no `project-memory.md` yet, an empty file written before the template is initialised, so it exists under that name and the count reads `0` |
| `partition-p<n>-manifest.txt` | STEP 1 | one per partition — its file list and line total, cut by the STEP 1 attack-surface rule |
| `<lens>-agent-procedure.md` | STEP 1 | the compiled worker contract every STEP 2 subagent reads |
| `scan-plan.md` | STEP 1 | invocation as given, model (this session's model identifier per the base skill's header rule, else `unknown`), base SHA, mode, adv, the partition table with source and entry-point shares, both entry-point totals, the lens set with its added-lens derivation table, stack-gated exclusions, and the STEP 2 dispatch list with its waves |
| `prompts/<lens>-p<n>.md` | STEP 2 | the worker's prompt, one per lens per partition — tested by `--paths` and named by the one line its worker was started with; a re-run's prompt replaces it |
| `deep-<lens>-p<n>-results.md` | STEP 2 | one per lens per partition |
| `disposition-table.md` | STEP 3 | one row per Judge-passed worker record — id in the form `<lens>/p<n>/<the record's VULN id as its heading states it>`, entry point, sink `file:line`, class, disposition, verdict, body record — written before any body block |
| `handoff-table.md` | STEP 3 | one row per STEP Y hand-off, each with a final disposition |
| `writer-prompt.md` | STEP 3 | the consolidation writer's prompt, checked by `--prompt` and named by the one line the writer was started with; `repair-prompt.md` beside it when a repair ran |
| `scan-plan.md.at-dispatch-<started>` | STEP 2 | `scan-plan.md` as it stood the moment `workers dispatched:` was written — what recheck item (20) compares the STEP 1 rows against |
| `recheck.py` | STEP 3 | this skill's shipped recheck, copied unchanged from the skill directory — the `script sha256` line proves it — and run after every report write; it computes every `recheck:` line from these artifacts |

Before dispatching STEP 2, move every `deep-*-results.md` in the cache whose modification time precedes the
`started:` row into `.llm-sast-scanner-cache/previous-run-<started>/` — an earlier run's file at the same commit
carries a header and pinning the gate accepts, and a worker that never writes must leave an absent file, never an
old one that passes — recording `stale worker files moved: <n>`; the earlier run's `prompts/` directory,
`writer-prompt.md` and `repair-prompt.md` go into the same directory, uncounted, and `--paths` and `--prompt` reject a
prompt file older than `started:`, so a write that missed its path cannot pass on the last run's copy; the previous plan already sits in that directory, copied
before this plan was written, and its residual row above is what this run's writer must not carry forward — a run that
ended with a residual left artifacts the next run would otherwise trust. Then verify the STEP 1 artifacts exist and that the partition line counts sum to the
manifest total. A partition file that is absent, empty, or a glob pattern instead of an enumerated file list
means STEP 1 did not finish — rebuild it. Never dispatch a subagent against a partition whose file list is not
on disk; a worker that cannot read its partition will invent a scope and report against it.

Consolidation reads the `deep-*-results.md` files and never writes to them. A lens file is the record of what
that worker found; a consolidation step that edits one destroys the only evidence of what the run actually
produced and makes re-consolidation from clean inputs impossible.

Write ONE report, into `<dir>` itself — the directory this skill was invoked on, alongside the code, NOT into
`.llm-sast-scanner-cache/`, which holds the run's working artifacts. The report is the deliverable; the cache
is the workings. Name it from `date +%Y-%m-%d_%H-%M-%S` at the moment of writing, and the moment the file exists
record that name in `scan-plan.md` as `report: sast_report-<timestamp>.md`. Never invent a timestamp,
advance a clock, or emit a second report under a later name — a run that produces several reports has no
answer to "which one is the result." A re-consolidation, repair or rebuild within the run rewrites the file named in
the `report:` row, in place, under that name — except a name recheck item (30) reads as later than its own file, a
time chosen rather than read: that report is renamed once to a fresh `date +%Y-%m-%d_%H-%M-%S` output and the new name
appended as a `report:` row, one report under its true name and never a second one; a second `sast_report-*.md` whose name timestamp is at or after the
scan-plan's `started:` row is a STEP 3 error and is deleted before the run ends. A `sast_report-*.md` whose name
timestamp precedes `started:` is an earlier run's result and belongs to the user: this session and every subagent it
starts never writes to it, renames it or deletes it. "One report" means one report from this run, not one report in
the directory — a run that removes or rewrites an earlier report has destroyed a record that no repair can restore,
and the close-out reports it by file name rather than hiding it.

Every finding in the report body is one complete Finding Format record (base skill Step 7) and keeps its Flow
(source -> sink hops as `file:line` steps), Evidence code block, Judge verdict, CWE, severity with a one-line
rationale, and entry point. The count of records under each severity heading is what the Severity Histogram
reports; the appendix's Body/histogram reconciliation (below) shows the two side by side, and the Executive Summary
holds the base skill's severity table — the same five counts and their total — ahead of its sentences (a
non-convergence warning, when D3 requires one, still comes first).

**STEP 2** — Dispatch every lens x 3 partitions, in waves of at most 15 workers (WORKER DISPATCH, below). Each subagent gets exactly ONE lens and ONE
partition and runs its own full convergence loop over only that partition's files. Write results to
`.llm-sast-scanner-cache/deep-<lens>-<partition>-results.md`.

**WORKER DISPATCH.** Every worker is started as a write-capable subagent whose prompt is this text with the
slots filled — the whole of it, in this order, nothing dropped — held in its prompt file and sent as the one line that
names that file (the path test below):

> You are the `<lens>` worker for partition `p<n>` of an `llm-sast-scanner-full-scan-loop` run on `<target>`.
> Run every command from `<target>` and read every file by an absolute path under it. Before reading anything
> else, run `pwd` and `git rev-parse HEAD` there; their outputs go into the results file's first line as its
> `target:` and `base-sha:` fields (below), produced by running those commands, never copied from this prompt; if
> either differs from the `target:` and `base-sha:` rows of `.llm-sast-scanner-cache/scan-plan.md`, stop and write
> nothing.
> Read in full, in this order: `<skills root>/llm-sast-scanner-convergence-loop/SKILL.md`,
> `<skills root>/llm-sast-scanner/SKILL.md`, `.llm-sast-scanner-cache/<lens>-agent-procedure.md`,
> `architecture-threat-model.md`, `scan-plan.md`, `scope-manifest.txt`, `partition-p<n>-manifest.txt`, and
> `project-memory.md` (hints, never authority). Run the Convergence Loop Procedure of the convergence-loop skill
> in this session over exactly the files of `partition-p<n>-manifest.txt`, constrained to the classes in the
> contract: Steps 1–5 to convergence with 100% line coverage; no adversarial pass, no timestamped report, no
> `project-memory.md` write, no skill or wrapper invocation. The cache's `previous-run-*` directories hold an earlier
> run's worker files, moved there so that no gate accepts them: read none of them, and write every line of your file
> from this run's reading of the code — the gate compares your file with them, and one whose prose is mostly theirs is
> re-run. Write only
> `<target>/.llm-sast-scanner-cache/deep-<lens>-p<n>-results.md`, by that absolute path — a file written anywhere else is
> not a worker file: the worker is re-run and the stray file, this run's own output, is removed. Its first line is
> `procedure: <convergence-loop skill name> v<its version> / <base skill name> v<its version> | target: <pwd output> |
> base-sha: <git output>` — one line, four fields: the convergence-loop skill first and the base skill second, both
> names and both versions copied from the `name:` and `version:` fields of the two SKILL.md frontmatters you have
> just read, then the two command outputs; nothing on this line comes from this prompt. Then every Judge-passed finding as one complete Finding Format
> record (base skill Step 7) whose first line is `[SEVERITY] VULN-<id> — <class> [CONFIRMED | LIKELY]` with the
> severity in capitals and without the Adversarial field — that field is consolidation's. After the records, four
> sections the file holds even when it holds no finding: the Clearance Records for every class you cleared, the
> coverage checklist, the pass log, and the convergence status; their numbers go into the sentinel below, whose
> right-hand values are copied from `partition-p<n>-manifest.txt`. Your partition is a third of the repository, so a
> class or surface you found absent is written `SAFE in p<n> — no <surface> in this partition`, never the unscoped
> `SAFE — no such production surface`; and a clearance that rests on absent callers names the sink, lists the callers
> you enumerated repository-wide, and reads `no in-repository production caller` — what lies outside this repository is
> unverifiable, not safe. Every entry point in the scan-plan's `## Entry points` list whose partition is yours is named
> in your file, by the name the list uses, in a finding's `Entry point:` line or in a Clearance Record's disposition; one
> named in neither is unanalyzed, whatever the coverage numbers say. When `project-memory.md`'s confirmed-findings ledger
> holds no row — the scan-plan's `ledger rows at start: 0`, as on a first run — write the line `ledger empty` on its own:
> the gate re-runs a worker whose file on an empty ledger lacks it. Your own records are not that ledger: on an empty
> ledger no caller enumeration is owed, and none is written in its place. When `project-memory.md`'s confirmed-findings ledger is non-empty, also run the
> ledger sink caller enumeration: for every ledger sink whose file is in your partition, trace backward to every entry point
> repository-wide, state per sink which entry points were already reported and which are new, run each new one
> through Source→Sink and the Judge as its own candidate, and write the line `new entry points: <count>` (`0` is a
> valid count); write `ledger empty` when there was no ledger. Before the final line, check your own file as the gate
> will: its first line is the `procedure:` line above; it holds `ledger empty` on an empty ledger and `new entry points:
> <count>` on a populated one; every record
> opens with a severity token — `[CRITICAL]`, `[HIGH]`, `[MEDIUM]`, `[LOW]` or `[INFO]` — before its `VULN-` id, carries a
> `Reference:` line naming a file of the base skill's `references/` directory, and cites in its `File:` line a path
> that exists under the target — its `:line` dropped, each tested with `test -f <path>` from the target directory, never
> recalled. A record
> that fails is corrected before the sentinel: the gate re-runs the whole worker for one wrong path, and one worker once
> cited its sink under the wrong module directory. The gate is a command you can run: from the target directory,
> `python3 <skills root>/llm-sast-scanner-full-scan-loop/recheck.py --gate <lens>/p<n>` prints your file's gate line —
> every field but the sentinel, which you have not written yet, must read `ok` or its full count — `absolute` and
> `entry pipes` are counts the writer handles and `digest` a value the gate compares, never a fail — and `copied` below
> 80% or `n/a`, before you write it.
> The final line, written only after coverage verification passes, is
> `<!-- LLM-SAST-COMPLETE lens=<lens> partition=p<n> files=<f>/<mf> lines=<l>/<ml> passes=<p> convergence=<converged | NOT CONVERGED (...)> -->`
> — `f` and `l` the files and lines you covered, `mf` and `ml` the partition manifest's file and line counts, `p` the
> passes run. The sentinel is the file's only machine-read record of coverage and passes: one with `f` below `mf`, `l`
> below `ml` or `p` of 0 is an unfinished worker.
> The sentinel is also the file's last write: once it is in, the file is not written again — the gate reads the file
> then and the wave closes on it, so a change after it goes ungated.
> If you stop early, omit the sentinel.

`<skills root>` is the directory that contains this skill's directory. Workers start in **waves of at most 15**:
order the worker list by lens — the six base lenses in the class table's order, then the added lenses in
derivation-table order — and by partition p1, p2, p3 within each lens; the first 15 are wave 1, the next 15 wave 2,
and so on, counted across lens boundaries: a lens whose partitions fall on both sides of the fifteenth position is
split between two waves, and the sixteenth pair waits for the next wave even though its lens has begun — one
orchestrator started a sixth lens's first partition beside five lenses' fifteen and recorded its own wave-cap error,
and a later one started eighteen. The rosters are therefore written before any dispatch: STEP 1 writes one line per
wave into `scan-plan.md`, `wave roster <k>: <lens>/p<n>, <lens>/p<n>, ...`, each roster the next fifteen pairs of the
ordered list and the last one the remainder, and STEP 2 dispatches each wave from its roster line and nothing else — a re-run belongs to the wave of the worker it replaces and is not a roster entry.
The batch is built from `python3 <this skill's directory>/recheck.py --roster <k>`: one subagent start per pair it prints
and no other, the calls counted against its count before any is sent. The base lenses are not a wave: a lens
whose partitions the roster puts in the next wave waits for it, and one run sent the six base lenses' eighteen
partitions as its first batch. Once a batch has started, the same command's `recorded first attempts` line names no
pair `not on this roster`. Recheck item (25) reads the rosters
against the dispatch lines. A wave starts only when every file of the wave before it ends with its sentinel, or that worker has
been re-run under the crashed-file rule below, or its pair is recorded `worker not run:` under the attempt cap below. A start the runtime rejects with a rate-limit or retryable error is
retried after the interval the error states; the wave size is never raised to catch up. Such a retry is the same attempt, not a new one: an attempt's dispatch line is written when its subagent starts, or when the runtime refuses it for good
— `refused` then standing in the subagent-id slot — and a start retried after an interval keeps its own later time
and still belongs to the wave it was dispatched with. The dispatch is recorded in
`scan-plan.md` as `workers dispatched: <n>` — `n` equal to lenses × 3 — then `waves: <w> of at most 15`, and for
each wave `wave <k>: <m> workers | started <time> | complete <time>` followed by one line per worker,
`<lens>/p<n>: <subagent id> <time> paths <k>/<k>`, written as each subagent starts, its time a `date +%Y-%m-%d_%H-%M-%S` output read after that pair's prompt file has passed the path test below and before its start call — one reading serving a batch started together — and the `paths` field from that test. A wave is the set of first-attempt dispatch lines from its `started` time up to the next wave's; the `wave <k>:` line summarizes them — written before the wave's first start call, its start time a `date +%Y-%m-%d_%H-%M-%S` output read then; its worker count and start time are never edited afterwards,
only `complete <time>` is filled in, with a `date +%Y-%m-%d_%H-%M-%S` output read once the wave's last file ends with its
sentinel, or the `complete` time `python3 <this skill's directory>/recheck.py --roster <k>` prints then, never a time
recalled or composed — and more than 15 first-attempt dispatch lines in one wave is a STEP 2 error,
recorded as `wave <k>: <m> workers — STEP 2 error, cap is 15` and never re-labelled into smaller waves. A wave's
`complete <time>` may be written only when the dispatch lines beneath it number its worker count and every one of
them carries a time earlier than that completion time; a first-attempt dispatch line whose time equals or follows its wave's
completion was written after the fact and records nothing about when its worker ran — such lines are counted in the
appendix as `dispatch lines late: <n>`, and a wave completed over missing lines is a STEP 2 error. A re-run
worker's dispatch line is written under the wave it replaces, in the same form and ending `(re-run: <reason>)`, and is not a wave.
Before any worker prompt is sent — first dispatch or re-run — it is written to
`.llm-sast-scanner-cache/prompts/<lens>-p<n>.md` and `python3 <this skill's directory>/recheck.py --paths
.llm-sast-scanner-cache/prompts/<lens>-p<n>.md <lens>/p<n>` is run from the target: it tests every filesystem path the
prompt names, and the one that cannot exist yet — the worker's output file — by equality instead, against exactly
`<target>/.llm-sast-scanner-cache/deep-<lens>-p<n>-results.md` for the prompt's own lens and partition. It also requires
the WORKER DISPATCH text itself, every sentence of it with its slots filled — a prompt built by joining a string's
characters, or one that summarizes the template, is flagged with the first sentence it lacks, as all twenty-seven
prompts of one run were before a re-run rebuilt them — the prompt's first line to name that lens and partition, no other pair's `partition-p<n>-manifest.txt` or
`<lens>-agent-procedure.md` in it, the first-line form at its end with its placeholders intact, and a file written by this run, never one older than
`started:`. The file is
corrected until the command exits 0, and the worker is then started with the text after `send: ` on the one line the
command prints on a pass — `You are the <lens> worker for partition p<n>. Your prompt is
<target>/.llm-sast-scanner-cache/prompts/<lens>-p<n>.md. Read it in full before anything else; if that path cannot be
read, read prompts/<lens>-p<n>.md in the directory of <target> whose name begins .llm-sast instead. Before you follow
it, check its first line: it must name the <lens> worker and partition p<n>. If neither path can be read, or the first
line names another lens or partition, stop: write nothing and reply "prompt file not found". Otherwise follow the file;
it is your whole task.` — copied as printed and nothing added, never the prompt re-typed into the start call: a re-typed prompt is
a second copy the path test never read, and one run's four misspelled cache directories were all typed there, in the
call, and in no file — four of 183 mentions of the cache directory in that run's start calls were misspelled, none of
62 in its commands, so the one line keeps a single mention and its fallback finds the file without spelling it. A worker that replies `prompt file not found` read nothing and wrote nothing; it is re-run, within
the three-attempt cap below, as `(re-run: prompt file not found)`, its file tested again and its send line copied
again from that output. A prompt naming a path
that does not exist is never sent, and a re-run prompt is written and tested again rather than inherited, because a repair prompt copies its parent's
paths along with its parent's mistake. The dispatch line's `paths <k>/<k>` field is copied from the command: a line
reading `paths 9/10` records a prompt sent despite a failing test, and four such prompts, each naming a misspelled cache directory,
once cost four worker attempts and took one pair to its last permitted one. The prompt file's last sentence
is the contract's first-line form, verbatim, placeholders intact — Its first line is `procedure: <convergence-loop
skill name> v<its version> / <base skill name> v<its version> | target: <pwd output> | base-sha: <git output>` — so
the form stands at the point of action and not only inside a contract paragraph: eleven of twenty-seven workers whose
contract carried the form after the sentence telling them to run `pwd` and `git rev-parse HEAD` wrote those two
outputs as their first line. While a wave runs, this session checks worker files at most once every two minutes.
Worker result files are written only by
the worker that owns them: this session never writes, edits or completes a `deep-*-results.md`, and neither does any
subagent other than that worker — a "repair" of a worker file by anyone else is a STEP 2 error: the file is deleted
and the worker re-run. When the runtime
cannot start subagents — established only by actual attempts: the first worker's `run_subagent` call fails with an
error or refusal from the runtime and so does one retry of it, before any worker of this run has started; never by
this session's reading of any instruction — the run stops after STEP 1: `scan-plan.md` records
`workers dispatched: 0 — <that result, quoted verbatim>`, a line written without those attempts is a STEP 2 error, no
worker file and no report is written, and the user is told. A refusal or error for one worker once any worker of this
run has started is a per-worker failure, never a stop: the worker is re-run with the result as its `(re-run: ...)`
reason, up to twice; a worker refused or failed on all three attempts is recorded as
`worker not run: <lens>/p<n> — <result, verbatim>`, its dispatch line stays, the run continues with the other workers,
and the report's Worker dispatch appendix and Executive Summary name that lens and partition as uncovered — a
documented gap is a result, an abandoned run is not. The cap is three attempts for every reason together — a runtime
refusal or error, a crashed or stray file, a failed gate, an unfinished file: a lens/partition pair has at most three
dispatch lines in a run, the first dispatch and two re-runs, and a pair whose third attempt also ends without a passing
gate is recorded as `worker not run: <lens>/p<n> — unfinished after 3 attempts: <the last gate line's failing field, or
the last (re-run: …) reason, verbatim>`. Its worker file stays exactly as its last worker wrote it — partial, without a
sentinel, never completed or edited by anyone else — its gate line is written with the file's actual values (`sentinel
absent` when it has none), its records enter the table like any other worker's — except a record that fails the gate's record checks, a heading
without a severity, no `Reference:` naming a base skill reference file or a `File:` path that does not resolve, which is
dispositioned `unverifiable` with the failing check as its reason — its class cell the literal `unclassified` when the
record names no reference file, never a class composed from its title — and its block placed in the Unverifiable
section, never body, as a `File:` without a line number already is: a class composed from a title is a key no later run matches, and a
severity-less record cannot fill the table — and the report's Worker dispatch
appendix carries one line `uncovered: <lens>/p<n> — <f>/<mf> files, <l>/<ml> lines read after 3 attempts` per such
pair, the Executive Summary naming each as uncovered. Twelve workers that each stopped at a fifth of their partition
were once re-run in rounds for an hour under a rule with no cap, and the run never reached its second wave. Recheck
item (29) reads the `worker not run:` lines against the worker files and the dispatch-line counts. `workers dispatched: <n>` counts the workers that were started
and is never rewritten downward; the
user is told that a single-context audit is a separate `llm-sast-scanner-convergence-loop mode=single`
invocation. Before STEP 3, every worker file is checked against the dispatch list and its first line. The first line is
read mechanically: split on ` | ` into `name: value` fields; the check needs exactly the fields named `procedure`,
`target` and `base-sha`, in any order, and reads nothing else on the line — a field under any other name is not one of
them, a line that is not made of such fields has no fields, and a title, prose or Markdown line fails. A file with no
dispatch line, or whose `procedure` field is absent or names a skill or version other than the two frontmatters' `name:`
and `version:` fields — the two skills in either order pass; a wrong name or version does not — was not produced by a
worker that loaded the procedure: delete it and re-run that worker. A file whose `target` or `base-sha` field is absent
or differs from the scan-plan's row, or whose cited `File:` paths do not resolve under the target, was produced against
another checkout: delete it and re-run that worker; the path line is the primary check, because a sibling copy can sit
at the same commit. The `gate:` line's `header` and `pinned` slots report exactly these field tests, so a header that
reads `ok` there has the three fields and nothing the check could not parse. A file that nowhere contains
`new entry points: <count>` or `ledger empty` — on its own line or inside a sentence, in any letter case, so
`New entry points: 0` at the start of a sentence passes — fails the same gate and is
re-run the same way; the phrase's presence is the test, not its position or its capitalization. Which phrase is valid
depends on the scan-plan's `ledger rows at start:` row: when it is above `0`, `ledger empty` is false and fails the
gate like a missing phrase — the worker skipped the caller enumeration its partition owed — and only
`new entry points: <count>` passes; when it is `0`, `ledger empty` is the phrase that passes, and a file holding it
passes whatever else it says — a `new entry points: 0` beside it records nothing wrong. A file whose sentinel
lacks the `files=`, `lines=` or `passes=` field, or whose `mf` and `ml` differ from its partition manifest's counts, or
whose `f` is below `mf`, `l` below `ml` or `p` is 0, is an unfinished worker — re-run it, within the three-attempt cap above. The gate's result is written into `scan-plan.md`, one line per worker file, each line the output of
`python3 <this skill's directory>/recheck.py --gate` run from the target — or `--gate <lens>/p<n>` for one re-run pair —
copied verbatim and never composed by this session, which once gated a byte-identical header `pinned fail` and passed a
file that held neither ledger phrase. A run that prints `gate: error` gated nothing: it is run again with
`--skills <skills root>`, and no worker is re-run on it. A re-run file is gated again and its pair's line rewritten in place, the
dispatch line's `(re-run: …)` reason keeping the failure on record, so the plan holds one `gate:` line per worker file
and recheck item (29) reads that line:
`gate: <lens>/p<n> — header <ok | fail> | pinned <ok | fail> | phrase <ok | fail> | sentinel files <f>/<mf> lines <l>/<ml>
passes <p> | paths <k>/<m> resolve | headings <s>/<m> | absolute <a> | references <r>/<m> | entry pipes <e> | copied
<c>%[ from <directory>] | digest <d>` — its `copied` field `copied n/a` for a file too short to tell — where `m` is the file's record count, counted as its `File:` lines
and its record lines written behind a list marker, a blockquote `>` or indentation
— every record has one, read with
its backticks removed and any `:line` or `:line-line` suffix dropped, and a record is counted by that line, never by
its heading, because a heading that is wrong is exactly what the next field must see — and `k` how many of those paths exist under the
target; a file with records and not one `File:` line is counted by its record headings instead, so its line reads
`paths 0/<n>`, the `fail` it is. `s` is the number of headings that open, after any
leading Markdown markers, with a severity token — `[CRITICAL]`, `[HIGH]`, `[MEDIUM]`, `[LOW]` or `[INFO...]` — before
`VULN-`; a record headed by its confidence tag or by anything else has no severity to enter the table with, so `s`
below `m` fails the gate and the worker is re-run: two records headed `[LIKELY]` once passed a gate, entered the table
without a severity, and were dropped by a repair to balance an equation; a gate that then counted records by their
severity headings wrote `headings 10/10` over a file with eleven `File:` lines, the eleventh headed `[LIKELY]`. `a` is
the number of those `File:` paths written absolute under the target — they resolve, so they are not a `fail`, but the
writer rewrites each one target-relative when the table is built, and the count stands in the gate line so a run whose
keys matched nothing can be traced to the worker that wrote them: fifteen absolute paths from one worker once made
fifteen keys no ledger row met. `r` is the number of records carrying a `Reference:` line that names a file of the base
skill's `references/` directory — the record's class, in the only form the ledger key accepts — and `r` below `m` fails
the gate and re-runs the worker: a record without one leaves the writer to compose a class from the title, and five
such records from one worker once put five keys into the ledger that no later run will match. `e` is the number of
`Entry point:` lines that hold a `|` — the `## Entry points` list writes ` | ` between its fields, and a
worker naming an entry point as the list does carries them. They are not a `fail`, but a `|` splits a table cell, so
the writer builds the entry point cell without them, and the count stands in the gate line so a draft whose rows came
out nine cells wide, as thirty-two rows of one first draft did, can be traced to the workers whose lines it copied.
`c` is the share, in whole percent rounded down, of the file's eight-word phrases of composed prose that the file of
the same name under a `previous-run-*` directory also holds, the highest over those directories, named after `from`
when above 0; a file long enough to judge with no such file for its pair reads `copied 0%`. Composed prose is what a
worker writes afresh even at an unchanged commit, where the code it quotes, the paths it cites and the forms this
template prescribes are the same as last time: the file's words less code fences, lines indented two spaces or a tab
that are not list items, its first line, headings, comments, label-only lines, the lines that open with `CWE:`,
`File:`, `Entry point:`, `Reference:`, `Worker record:`, `Evidence:`, `coverage:`, `passes:`, `convergence:`,
`unread ranges:`, `new entry points:` or `procedure:`, and the phrases `SAFE in p<n> — no <surface> in this
partition`, `no in-repository production caller` and `ledger empty`. Phrases are read in any
order and across line breaks, so a moved section or a re-wrapped line is still the phrase it was; a file holding fewer
than 100 of them reads `copied n/a` — too little prose to tell a copy from a re-verification — and passes that field.
`c` at 80 or above fails the gate and re-runs the worker: its file is an earlier run's, not this run's — seven of one
run's twenty-seven workers once handed back their predecessors' files with a line or a record changed, in five to
seven minutes, their sentinels' coverage and pass counts copied with them, while no file of a run whose workers did the work
held more than three fifths of its predecessor's phrases. `d` is the first twelve hex digits of the file's SHA-256 as
the gate reads it (`unreadable` for a file the gate cannot read): a write to the file after its gate changes it. A worker file with no `gate:` line, or whose line shows a `fail`, `k`
below `m`, `s` below `m`, `c` at 80 or above, or sentinel values below their manifest counts, has not passed the gate, and STEP 3 does not start — unless its pair is recorded `worker not run:`, whose gate line is still written and still counted — a pair with no
worker file at all has no gate line, so the two counts still agree; the consolidation writer's first action is to count `gate:` lines against worker files and to stop, writing nothing, if
they differ. The gate also searches the whole target for any `deep-*-results.md` outside the cache — under a
misspelled cache name, the repository root, or any other directory — and removes each one, recording
`stray worker files removed: <n> — <paths>`; a stray is a worker's misdirected output, never evidence, and its worker
is re-run only when its own cache file is absent or fails the gate.

The lens set is the six in the base skill's class table, **plus at least one added lens. The added lens is
REQUIRED, not optional.** A dispatch of exactly the six base lenses is an incomplete STEP 2 — the six are the
floor, never the whole set.

An added lens is a cross-cutting attack surface, never a programming language. It owns the classes of one
surface family that the six base lenses split between themselves, so one worker follows that family's
boundaries end-to-end; the base lenses keep applying those classes, and the added lens is a second, joined-up
pass over them. The candidate families, in the order they appear in the derivation table, are:
- `ai-agent`: prompt injection, insecure output handling, excessive agency, system prompt leakage, RAG / vector
  and embedding security, MCP, ML supply chain and model/data poisoning, AI editor / agent config poisoning
- `realtime-rpc`: WebSocket, Socket.IO, SSE, WebTransport, gRPC / Connect, message and event consumers
- `cloud-infra`: Kubernetes / orchestration, IaC, CI/CD and containers, web-server configuration
- `graphql-api`: GraphQL schema and resolvers, API gateway / BFF, webhooks and integrations
- `browser`: client-side rendering, DOM sinks, postMessage, CSP, service workers
- `data-pipeline`: batch / ETL, message queues, query builders, export and import jobs
- `mobile-desktop`: Android, iOS, Electron
- `language-runtime`: the implementation language's own concurrency, lifecycle, serialization and memory model

Derive the added lens set from the dependency manifests, not from a count and not from the stack description. Write the **added-lens derivation
table** to `scan-plan.md`: one row per candidate family, in the order above, with the columns
`family | dependency signals | files touched | lines in those files | entry points | chosen`. The columns are
defined, not interpreted:
- `dependency signals`: the family's signal packages named in the dependency manifests (`package.json`
  dependencies and devDependencies, `go.mod`, `requirements.txt` / `pyproject.toml`, `pom.xml` / `build.gradle`,
  `Cargo.toml`, `Gemfile`, `composer.json`, `*.csproj`, and their equivalents), each written as
  `<package> (<manifest path>)`. A hit in source, documentation, a comment or a lockfile is not a dependency
  signal. The signal packages are, per family — `ai-agent`: model and agent SDKs and vector stores
  (`@aws-sdk/client-bedrock-runtime`, `@anthropic-ai/sdk`, `anthropic`, `openai`, `@google/generative-ai`,
  `@google-cloud/vertexai`, `langchain` and `@langchain/*`, `llamaindex`, `@modelcontextprotocol/sdk`, `mcp`,
  `ai`, `litellm`, `transformers`, `pgvector`, `@pinecone-database/pinecone`, `chromadb`, `weaviate-client`);
  `realtime-rpc`: socket, streaming and RPC transports (`ws`, `socket.io`, `@slack/bolt`, `@slack/socket-mode`,
  `@grpc/grpc-js`, `grpc`, `grpcio`, `@connectrpc/*`, `@bufbuild/*`, `graphql-ws`, `eventsource`, `mqtt`,
  `websockets`, `gorilla/websocket`, `nhooyr.io/websocket`, `tokio-tungstenite`, `channels`); `graphql-api`:
  GraphQL servers (`graphql`, `@apollo/server`, `apollo-server*`, `graphql-yoga`, `mercurius`, `type-graphql`,
  `@nestjs/graphql`, `graphene`, `strawberry-graphql`, `ariadne`, `gqlgen`, `graphql-java`, `async-graphql`,
  `juniper`); `browser`: a UI framework or bundler in a package that ships to a browser (`react-dom`, `vue`,
  `@angular/core`, `svelte`, `solid-js`, `next`, `nuxt`, `@sveltejs/kit`, `vite`, `webpack`, `htmx.org`,
  `jquery`); `data-pipeline`: queues, schedulers, ETL and bulk import/export (`pg-boss`, `bullmq`, `bull`,
  `bee-queue`, `agenda`, `@aws-sdk/client-sqs`, `@aws-sdk/client-kinesis`, `kafkajs`, `amqplib`, `node-cron`,
  `celery`, `rq`, `dramatiq`, `apache-airflow`, `dagster`, `prefect`, `luigi`, `pyspark`, `pandas`, `exceljs`,
  `xlsx`, `papaparse`, `csv-parse`, `fast-csv`, `openpyxl`) — an ORM or query builder alone is not a signal,
  every database application has one; `mobile-desktop`: (`electron`, `@tauri-apps/api`, `react-native`, `expo`,
  `@capacitor/core`, `@ionic/*`, `flutter` in `pubspec.yaml`, `com.android.application` in a Gradle file, an
  `*.xcodeproj` or `Podfile`). `cloud-infra` has file signals instead of packages: any in-scope `*.tf` or
  `*.tfvars`, `Pulumi.*`, CloudFormation / ARM / Bicep template, `Chart.yaml` or Kubernetes manifest,
  `Dockerfile*`, `docker-compose*`, `.gitlab-ci.yml`, `.github/workflows/*`, `Jenkinsfile`, or nginx / Apache
  configuration, written as `<pattern> (<count> files)`. A package of the same kind under another name counts
  and is written with the word `equivalent` and the package it stands in for; the equivalence is stated, never
  assumed. `language-runtime` has no signal.
- `files touched`: hand-written source and configuration files with a word-boundary hit for the family's own
  identifiers — SDK import paths, protocol handler APIs, schema and resolver declarations, resource kinds.
  Generated code, lockfiles, test files, fixtures and documentation are excluded from every count.
- `lines in those files`: the manifest line counts of the files touched.
- `entry points`: registrations in hand-written source where data from outside the process is first handed to
  a handler — HTTP route and RPC method registrations, WebSocket / Socket.IO / SSE / WebTransport handler
  registrations, GraphQL operation and resolver declarations, message or queue consumer subscriptions,
  model-callable tool and function declarations, CLI commands and scheduled jobs. Nothing else is an entry point:
  UI event props, goroutine or thread spawns, decode and parse calls, init functions, mocks, Kubernetes and IaC
  resources, CI jobs, Dockerfile stages and configuration files all count as zero. A registration counts once,
  for the family whose protocol or declaration it registers, on the side of the connection that runs in the
  process under audit: server-side registrations count for their protocol family, and browser-side handler
  registrations (`socket.on`, `onmessage`, `addEventListener('message')`) count for `browser`. A plain HTTP route
  registration — REST, form or webhook receiver — registers no family's protocol: it is an entry point for the
  partition cut and for no derivation row, and a family whose dependency signals are imported by the route files
  does not inherit those routes. `cloud-infra`, `mobile-desktop` and `language-runtime` therefore carry `0`
  entry points and compete on lines.
Use the same sweep discipline a Clearance Record uses. A family with no signal and no sweep hit gets a zero
row, not a missing row. Selection reads one column: **every surface family with at least one dependency signal
is an added lens.** `files touched`, `lines in those files` and `entry points` are reported for the record and
the report's appendix; they select nothing, rank nothing and exclude nothing — a family with a signal and zero
counted registrations is still added, and a family with a thousand counted registrations and no signal is not.
`language-runtime` is the added lens only when no surface family has a signal; it is never added beside a
surface lens. The `chosen` cell states the signal that applied: `yes (signal: <package> in <manifest path>)`,
`yes (signal: <file pattern>, <count> files)`, `yes (language-runtime: no surface signal)`, or `no (no signal)`. Same base SHA, same table, same lens set: a
lens set that differs from the previous run's at the same SHA is a STEP 1 error to fix before dispatch. Name each
added lens in the report's appendix with the classes it owns and its table row, so coverage stays attributable
and runs stay comparable.

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
not substitute a shortened list of steps for it. STEP 3 begins only after the artifact gate below has passed for every
worker file — or, for a file whose pair is recorded `worker not run:` under the attempt cap, after its gate line is
written with the file's actual values; a consolidation started before that is discarded and its outputs deleted. STEP 3 runs one subagent at a
time — the consolidation writer, then
at most one repair subagent, each started only after the previous one has returned — and this session checks a
running subagent's output at most once every two minutes. When the writer returns, this session runs the recheck that is recorded — the writer's own run under the writer
self-check below records nothing — and the recheck is code this skill ships, not commands anyone writes during the run:
`recheck.py`, the file beside this SKILL.md. Before it starts the writer, the session copies it unchanged to
`.llm-sast-scanner-cache/recheck.py` (`cp <this skill's directory>/recheck.py .llm-sast-scanner-cache/recheck.py`),
and each time a subagent that wrote the report — the writer, a repair — has returned, and never while one is still
running, it runs, from the target directory,
`python3 .llm-sast-scanner-cache/recheck.py --record`, with nothing after it — the script appends the set to the scan
plan itself and prints one `recorded: set <n> … lines <a>-<b> — mismatches <k>` line, the set being those lines of the
plan, while a run without `--record` whose output is redirected into the plan writes nothing there: a report is written in passes,
skeleton first and blocks after, and a recheck taken between passes measures a draft — one set recorded seven
mismatches over a thirteen-block skeleton that the writer was still filling. A report that lacks its sentinel when its
subagent has returned is the writer's failure, not a draft: item (23) records it and the report goes to repair. The `recheck:` lines of the scan
plan are that command's output and nothing else: one line per item below in the form
`recheck: <item> <recomputed> vs reported <value> — python3 .llm-sast-scanner-cache/recheck.py`, then
`recheck: mismatches <n> — <items>`; an item the script could not finish appears as
`recheck: script error <type>: <message> at line <n>, after item <name>`, itself a mismatch, so a set always ends with its
last line and never with a traceback. Its first line, `recheck: script sha256 <a> = shipped <b> | match`, compares the
copy with the shipped file; `MISMATCH`, or a shipped file the script cannot find, ends the run with that line in the
final message, because a recheck that was edited measures whatever its editor wanted. Nothing in the run creates,
edits or replaces a file under that name, and the writer never writes a recheck of its own: a writer that also grades itself printed
constants for twelve of eighteen items under a rule that asked for one script. A `recheck:` line the script did not
print is an assertion and counts as nothing. The items below are the specification the script implements; where a
rule here and the script disagree, the script is what ran, and the rule is corrected: (1) `body blocks` and `linked blocks` — one block per `body`, `promoted` or `carried` row, no VULN id heading two blocks, each
block's `Adversarial:` line opening with that row's `verdict` cell verbatim; (2) `invalid cells` — every body line
opening `Adversarial: DOWNGRADED` or `Adversarial: DISPUTED` that does not match the regular expression
`(DOWNGRADED|DISPUTED) — [^—]*(\`[^\`]+\`|[A-Za-z0-9_./-]+:[0-9]+)` — the clause with a backticked identifier or a
`file:line` — is an invalid cell, so a bare verdict word or a clause naming nothing counts; the recheck command
contains that expression verbatim; (3) `first-line tags` — every body block's first line
ending `[CONFIRMED]` or `[LIKELY]`; (4) `merges with a different entry point` — the number of `merged` rows whose entry point, sink `file:line` or class differs from their target body row's, required to be 0,
each entry point cell read as the list entry it names — a cited `file:line` as the entry at it or up to three lines
below it in that file, a bare name as the one entry holding it, a name two entries share as written; (5) `config clearances rewritten` — the phrase search over the
worker files' disposition lines, a finding record's own lines (its `Judge:`, its `Impact:`) not among them; (6) `ledger rows after` and `archived` — `ledger rows after` is the number of lines in `project-memory.md`'s
confirmed-findings ledger section matching `^[a-z][a-z0-9_]* \| [^|]+:[0-9]+(-[0-9]+)? \|` — a class may carry digits,
and a sink may be cited as a line or a line range — `archived` the same count over the archive
file, `duplicate-key rows` the number of those lines beyond the first for any one `class | file:line` key — a key's line
is the sink's first line, so a row written with a range (`Dockerfile:45-55`) duplicates the row `Dockerfile:45` — required to
be 0 after the write, `ledger rows before` the pre-write copy's row count, `duplicate-key rows merged` the copy's
duplicate-key rows (none may remain), `after` equal to `before − merged + new keys` less the copy keys that left the ledger
this run (archived now; none leave at an unchanged commit; a title-class row STEP X corrects onto a stem row is merged, not
gone, and counts in `merged`) — `archived` itself is the archive file's all-time count — and
`ledger present` the number of distinct body `File:` sinks whose `file:line` — by
its first line — appears in the ledger section, each by a command that states that pattern; (7)
`earlier reports` — each listed file present at its recorded size; (8) the close-out equations; (9) `header versions` — the report's `Analyzer:` line and the scan-plan's `wrapper:`
row naming each skill's version as its own frontmatter states it, never another skill's; (10) `headings` — the
report's `## ` headings are the severity sections, the base skill's fixed sections and one `## Appendix`, in that
order and nothing else, so a working-notes, draft or duplicate section anywhere is a mismatch; (11) `maturity
worker records` — the maturity line's `worker records` value equals the table's rows minus its `carried` rows, and its
`vs` pair states the newest earlier report's close-out `table rows` and `body blocks`; (12) `new keys` — the
number of distinct `class | file:line` keys in `project-memory.md`'s ledger section that have no row in the run's
pre-write copy, keys compared by the sink's first line (a range twin of a copy row is not a new key), by a command that
reads both files and applies STEP X's class correction to the copy's keys; the
maturity line's `new keys`, the STEP X ledger equation and the
memory's new run line `new-confirmed` all equal it — row arithmetic is not this number, since rows merge and archive
while keys only appear; (13) `required lines` — each of these opens a line in the report, counted `<k>/<k>`:
`Maturity:`, `checks:`, `contracts checked:`, `stale worker files moved:`, `dispatch lines late:`, `earlier reports:`,
`entry points dispositioned`, `config clearances rewritten:`, `class clearances`, `ledger rows before`, `ledger:`,
`verdicts carried`, `close-out:`, `maturity:`; (14) `verdicts carried` — the number of body rows whose `File:` sink
and class hold a standing downgrade across the listed earlier reports (a `DOWNGRADED` or `DISPUTED` verdict at that sink and
class, oldest to newest, not since voided by a `previous downgrade voided:` block there), against the appendix's `carried`
plus `voided`, every such row's cell either repeating that verdict or opening `STANDING — previous downgrade voided:`, and
every carried block at such a sink and class honouring it likewise, counted `carried blocks at such sinks <n> (stale <s>)`
with `s` required 0; (15) `entry points dispositioned` — `m` is the line count of the scan-plan's `## Entry points` list by a command, never `0` while the list has lines,
— an entry line opens with its `file:line`, so a table header or separator row is not one —
and `n` equals `m` except for entry points on `unanalyzed` lines, which number `m − n`, each in the list once and each in
a partition holding a `worker not run:` pair — in a run whose workers all passed, every entry point is dispositioned; (16) `ledger rows
at start` — the scan-plan row equals the command's count over `project-memory.md.pre-write-<started>`, which exists
under that exact name, and when the cache is an earlier run's — an older at-dispatch copy, a `previous-run-` directory
holding that run's worker files or dispatched plan, or a worker file, prompt or table older than `started:` stands in
it (a lone older pre-write copy is this run's STEP 1 begun again) — the copy holds the ledger rows that run left: its
plan copy's last `recheck: ledger rows after`, else the newest report on disk written since it began that states
`ledger rows before <n> | after <m>`, else its own pre-write copy's count; (17) `non-stem classes` — the ledger rows in `project-memory.md` and the rows in the disposition
table whose class is not the file stem of a file in the base skill's `references/` directory, the stems listed by a
command over that directory, counted `<ledger>/<table>` and required to be `0/0`; (18) `rekeyed to stem` — the pre-write
copy's rows under a class that is not a stem whose sink now stands in `project-memory.md` under a stem, against the
appendix's `rekeyed to stem <r>`, with `trail missing <x>` the number of those whose new brief lacks ` was <old class>`,
required to be 0; (19) `checks` — the scan-plan's `checks:` line reads `pass` only if it should: the entry-point share of every partition, each entry of the `## Entry points` list counted in the partition whose manifest
holds its file and the list's partition column required to agree, is at most 40%, and every
partition's line share, recounted from the `partition-p<n>-manifest.txt` headers, is within 15% of one third — a
`checks: failed` line whose every failure names one file (`(one file: …)`) reads as the plan's outcome, not a mismatch; (20)
`step 1 rows unchanged` — the scan plan above `workers dispatched:` equals `scan-plan.md.at-dispatch-<started>`, the copy
this session makes of `scan-plan.md` the moment it writes `workers dispatched:`, line for line, blank lines ignored,
except lines carrying
` → corrected` and the `report:` and `continuity join:` rows STEP 3 writes, wherever they land; a line edited or removed
after dispatch is a STEP 1 row rewritten to fit the result; (21) `maturity
streak` — the streak derived as the maturity rule states: the memory's previous run line's streak plus one when
`found-late` is 0, `new keys` is at most 3 and no `worker not run:` line stands in the plan, else 0, against
the appendix's `streak <n>`, with the header's `Maturity:` line required to repeat it, and the memory holding exactly one
`run ` line more than the pre-write copy (ten at most, the oldest folded) — a run line replaced instead of appended is a
history rewritten; (22) `continuity join` — the
scan-plan's `continuity join: <n> rows carry a previous verdict — <ids>` against the rows the join yields, the sum of
carried, voided and bare, with `n` equal to the ids listed and `listed rows bare <x>` — listed rows whose block's
`Adversarial:` line is a bare `STANDING` — required to be 0; a join line without its ids is a count nobody can walk, and
a run whose `earlier-reports:` row reads `0` has nothing to join, so its absent join line reads as `0`; (23) `sentinel` — the report's last non-empty line is `<!-- LLM-SAST-COMPLETE -->`; (24) `not re-found` — every key of
the pre-write copy — read after STEP X's class correction — that holds neither a body record nor a carried row this run still has its ledger row and its brief carries
`not re-found <this run's date>`, counted `<marked>/<such keys>` with `rows gone <g>`, required equal and `0`: the
same-commit rule's mark is how a later reader tells a miss from a fix, and one write left one hundred and
twenty-eight missed sinks unmarked while the run ended clean; (25) `wave rosters` — the scan-plan's `wave roster <k>:`
lines hold every lens/partition pair once, none above fifteen, and the first-attempt dispatch lines of each wave — those at or after its `started` time and before the next wave's,
so a start retried after a rate-limit interval stays in its wave — are exactly that wave's roster, counted `<waves matching>/<rosters>` with `over cap <c>`,
and, where the worker files' times are the run's own, every first attempt's file was sealed at or before its wave's
`complete` time and before the next wave's `started`, and every first attempt's dispatch time lies at or after its prompt
file's write and at or before its worker file's seal, counted `dispatched before its prompt <n>` and `dispatched after
its file was sealed <n>`, both `0` — a prompt written once one of its wave's workers had ended, once one of that
wave's re-run prompts was written, or once the run had rewritten, for a re-run dispatched after it, a prompt whose
worker had ended, may have been rebuilt since and is not read — and a first-attempt time that is not a
full `date` output is named on the line, since it cannot be read; a `wave <k> complete: <time>` line of its own is read as that wave's `complete`
when its `wave <k>:` line carries none; (26)
`carried` — at an unchanged commit, as the Same-commit carry paragraph reads it, the `carried` rows equal the blocks that the copy's `open` keys — read after STEP X's
class correction — without a row of any other disposition this run hold in their newest earlier report, `s` the count of such keys no earlier report holds
(recomputed from the reports), every carried row has its block, every block's `Carried:` line carries the row's
`last-verified` cell as the copy holds it and the scan-plan's `base-sha` and names the newest earlier report that holds a block with the same
sink whose reference stem is the row's class and whose verdict honours the key's standing downgrade, the block's
other lines match one of that report's blocks of the key word for word (heading id, `Worker record:` and `Carried:` lines
aside, whitespace collapsed) with no source block copied twice, and every carried row's ledger line is the copy's line
unchanged, its sink cell read by first line (a lone range row rewritten as `Dockerfile:45` with every other cell intact is the
same row) — or, for a key the copy held as range twins or under a title-form class STEP X corrected, the one row the merge
or correction left, its sha, `last-verified` and status cells one copy row's and its brief holding every copy row's brief
(a twin dropped with its brief is a loss even when the surviving row is byte-identical) — counted
`<rows> | blocks <k> | sources verified <v>/<k> | verbatim <w>/<k> | without source <s> | expected <e> | ledger rows altered <a>`
with `a` required zero and the close-out's and the maturity line's `carried` values both equal to the rows; at a
changed commit the item reads `not applicable` and requires zero carried rows; (27) `summary table` — the Executive Summary's severity table, the first table there whose header opens `Severity` (a
warning's own table of uncovered partitions or lenses may precede it), holds one row each for Critical, High, Medium, Low, Informational and Total, each severity's number equal
to the records counted under that heading and to the histogram's line, Total their sum, counted per row as
`<table>=<body>=<histogram>` with `total <t> = <sum>`; a missing row or table reads `absent`; (28) `previous run residual` —
the scan-plan's `previous run residual:` row against the last `recheck: mismatches` line of `previous-run-<started>/scan-plan.md` (or, when that copy has no such line, against the copy's own `previous run residual:` row),
count and items alike, `none` only when no earlier plan exists; a copy missing where an earlier run left a plan — a
`previous-run-<started>/` directory holding moved worker files but no plan, or a cache that is an earlier run's as item
(16) reads it; an empty directory is no earlier run — reads `copy absent` and is a mismatch; a copy whose own `started:` is
not earlier than this run's, or that is the earlier run's at-dispatch copy though that run went on to write its report,
is not the previous plan and is a mismatch too; and at such a cache `stale worker files moved: <n>` equals the worker
files in `previous-run-<started>/`, none older than `started:` left in the cache; (29) `uncovered partitions` — the roster pairs whose worker file is absent, does not end
with a complete sentinel (files and lines at or above the sentinel's own denominators, passes above zero), or whose last
`gate:` line shows a fail — a complete sentinel is not a passed gate — against the
plan's `worker not run:` lines and the report's `uncovered:` lines, the three sets equal, and no pair holding more than
three dispatch lines, and every pair's last `gate:` line, a pair recorded `worker not run:` aside, reading what the gate
reads in its file now — its digest and the counts its text decides, never the header, pinning, resolving paths or
`copied`, which follow the skills, the plan, the checkout and the earlier runs: `recorded gate lines off the file` counts
the files changed after their gate — before the writer's prompt was written, a STEP 2 line the writer names and leaves
standing; after it, a write by the writer or a repair, which read the worker files and never write them; (30) `report name` — the report name's timestamp at or after `started:` and no later than the file
it names, written or renamed, a later one being a time chosen rather than read; a `report:` row naming a file created
before `started:` names an earlier run's report, which is the user's and is never renamed; (31) `worker record ids` — the
identity check of the disposition table: every `worker record` id outside `promoted` and `carried` rows names a record
of the current worker files, every such record has a row under its own id — two records of one worker file under one id
take two rows, and the line names them — and no id is on more rows than records hold it; (32) `withdrawn lines` — every
`withdrawn` row has its appendix line `withdrawn: <worker record> — <Step 6 | citation>: <one line>`, no such line names a
row that is not withdrawn or gives a duplicate as its reason (a duplicate is `merged`), and every `unverifiable` row's
`UNV-<nnn>` stands in the Unverifiable section; (33) `promoted rows` — no `promoted` row stands at the entry point, sink
and class that a `withdrawn` or `unverifiable` row's worker record names in its own `Entry point:`, `File:` and
`Reference:` lines, since that finding is the record's own row; (34) `withdrawn cells` — a `withdrawn` or
`unverifiable` row's sink and class cells are its worker record's own `File:` and `Reference:`, so what was withdrawn
stays readable in the table; (35) `dispatch lines late` — the appendix's `dispatch lines late: <n>` equals the
first-attempt dispatch lines beneath each `wave <k>:` line timed at or after that wave's `complete` — a second line
for a wave already opened opening nothing — or, where every wave's start is read and the plan's layout and its start
times place a line in different waves, the same count taken by start times; the line's presence is item (13)'s; (36) `memory header` — the written memory holds, above its `## Confirmed findings ledger`
heading, `scanner-version:`, `last-scanned-sha:` equal to the scan-plan's `base-sha`, `last-updated:` a date from the
run's `started` to the memory's own write, and the hints notice; (37) `record cells` — every `body` and `merged` row's
sink and class cells are its worker record's own — the first sink of its `File:` line, the same `path:line` read by
first line, and a stem its `Reference:` names; a record with no `path:line` there makes the row `unverifiable` — and, when the
record states an `Entry point:` line, its entry point cell names that entry point. The cell is written as the `## Entry
points` list writes it and the record in its own words, so the two meet when either holds the other, or when they share
a naming word (four letters or more, no generic or report word, a file path read by its file name), the cell's
`file:line` or a name of twelve letters or more; a naming word or `file:line` other than the sink's also counts from the
record's `Flow:` line or a line of its worker file that names its id; a cell of generic words alone needs at least half
of them in the `Entry point:` line; and a cell that copies the row's sink cell (unless the record's entry point is that
line), or whose only words are the report's own — `worker entry point`, `see VULN-…`, `—` — names none. A record with no `Entry point:` line
leaves the writer the list's entry or `unavailable`, and its cell is not read — and each body block's `File:` and `Reference:` are that record's, so a merge is read
from what the workers wrote; (38) `verdict scope`
— every `body` row's verdict follows its worker record's severity, the one Step 6 saw: a Step 6 verdict when it is in
`adv=`, `not run` when it is outside, a verdict the continuity join carries excepted; a block rendered below its
record's severity carries the `DOWNGRADED` or `DISPUTED` verdict that lowered it; `merged`, `withdrawn` and
`unverifiable` rows read `n/a`; (39) `section placement` — every record stands under the heading of its own severity
tag, and none outside the five severity sections and the Unverifiable section; (40) `block layout` — every body and
promoted block reads the one layout below: its `Worker record:` and `Entry point:` lines its row's, its Evidence a
fenced code block, no other line between its fields, and its `Adversarial:` line the row's cell followed by the
rationale, three words at least; (41) `appendix table` — the appendix holds every row of `disposition-table.md` as the
file holds it; (42) `scope exclusions` — the appendix reproduces every row of `scope-excluded.txt`, and
`excluded: <p> paths / <l> lines` has `p` its row count and `l` the lines of the regular files it names, counted from
them; (43) `class clearances` — `class clearances <n>` is the number of lines across the worker files that hold
`SAFE in p<n> — no <surface>`; (44) `pass log` — one entry per pair, its passes the worker file's sentinel `passes=`;
(45) `routed hand-offs` — `handoff-table.md` exists and `routed: <n>` counts its rows. Two lines are readings, not
items: `recorded sets <n> | lone mismatches lines <k>`, a lone line being a subagent's own run appended to the plan, and
`recheck: repair none — …`, printed when every mismatch in the set reads a STEP 1 or STEP 2 line.

Before it starts the writer, the session writes the writer's prompt to `.llm-sast-scanner-cache/writer-prompt.md`,
runs `python3 <this skill's directory>/recheck.py --prompt .llm-sast-scanner-cache/writer-prompt.md` from the target,
corrects the file until the command prints `ok` — it requires the Writer self-check paragraph below and, at an
unchanged commit whose pre-write copy holds ledger rows, the Same-commit carry paragraph, both verbatim, and for every
worker file one recorded `gate:` line that the file still reads — its digest and the counts its own text decides (its
sentinel, records, headings, absolute paths, references and entry pipes) — a file changed after it was gated having its
line rewritten in place from `--gate <lens>/p<n>` unless it changed after the writer's prompt was written, which is the
writer's or a repair's write, left as it stands for item (29) to name — none failing unless its pair is recorded
`worker not run:`, and no `gate:` line beyond them — a pair with no worker file has none, and a `gate: error` line is
replaced by the run it asks for — so the gate lines are in the plan, as many as the writer will count, as the gate command prints them, before the writer starts — and starts
the writer with the text after `send: ` on the line the command prints beneath its `ok`, `Your prompt is
<target>/.llm-sast-scanner-cache/writer-prompt.md. Read it in full before anything else; ...`, copied as printed and nothing added, never the
prompt re-typed into the start call, as for the workers above; a repair's
prompt goes through `.llm-sast-scanner-cache/repair-prompt.md` the same way. A writer or repair that replies `prompt file
not found` has read and written nothing: it is started again, its file checked again and its send line copied again from
that output, and that start is not a repair. One run's writer prompt condensed the
paragraph below away, and its first recorded set read four items short; the repair's paraphrased it.

**Writer self-check.** The writer's prompt, and a repair's, carries this paragraph verbatim, its skills-root
placeholders replaced by the path of the directory that holds this skill's directory, as the worker contracts carry it. Before it
writes anything, the writer reads `<skills root>/llm-sast-scanner-full-scan-loop/SKILL.md` from its `**STEP 3**` line to its
`## Notes` heading: the disposition table's id form and disposition words, how the body is rendered from the table and
every appendix line are defined there, beside the Finding Format and Steps 6 and 7 of
`<skills root>/llm-sast-scanner/SKILL.md`. The writer finishes all of its outputs — the disposition table, the body, the memory write, then the appendix, whose
`ledger:`, `ledger rows before` and maturity lines are counted from the written memory, and the sentinel last — and
only then runs
`python3 .llm-sast-scanner-cache/recheck.py` from the target directory, exactly that, with nothing after it, and reads
the lines it prints; the sets in the scan plan are the session's, recorded with `--record` after the writer returns, so
`--record` is never a writer's. For each item that reads a mismatch it corrects the artifact by the rule that item names, which the line's `fix:` states — a count
re-counted from its source, a table cell set by the verdict rule, a missing line written in its form, a ledger row
written for a body key, duplicate-key rows merged, a merge pointed at the body row that carries its own entry point,
sink and class or, with none, undone into its own body row — its entry-point cell first read against the worker
record's own `Entry point:` line, a cell that differs being the error the row holds — a report name later than its
file replaced by a fresh `date +%Y-%m-%d_%H-%M-%S` output, the file renamed and the new name appended to the scan plan as a `report:` row — never a stated number changed to match without being re-derived, and never a verdict re-adjudicated to make two lines agree;
the artifacts it corrects are its own — the disposition table, the report and its `report:` row, the memory, and the join line only by its
append-only correction — while the scan plan's STEP 1 rows, its dispatch, wave, roster, gate and `worker not run:` lines, the pre-write memory
copy, the cache's `recheck.py` and every worker file belong to the session's STEP 1 and STEP 2: a mismatch in what reads
them — the `script sha256` line, item (9)'s `wrapper:` row, item (16)'s plan row and copy, (19), (20), (25), (28), item
(29)'s plan lines — is left as it stands and named in its final message, never corrected by the
writer, because editing a STEP 1 row is what item (20) exists to catch; a `recheck: script error` line names no artifact, so nothing is changed for it — one that reads `skills directory not found` is run again with `--skills <skills root>` — it runs the script again after the
corrections, five runs at most in all, and returns with the last run's `recheck: mismatches` line quoted in its final
message. The session's recheck after the writer returns is the record, and a first recorded set that reads
`mismatches 0` sends nothing to repair. A first write once reached the session's recheck nine items short — the memory
not yet written, two cross-entry merges, a count never searched, two required lines missing, a worker-record count
taken from the body, one finding outside `adv=` tabled `STANDING` — each a rule the writer had and a line the script
would have shown it.

A recorded set whose script error reads `skills directory not found` is recorded again with `--record --skills <skills
root>` before anything goes to repair: it computed no item. A recorded set with a `recheck: repair none` line — every
mismatch in it reads a STEP 1 or STEP 2 line, which no writer or repair changes — sends nothing to repair: the run ends
with those lines named in its final message. Otherwise a `recheck:` line whose numbers differ, or (1), (3) or (4) short of its required value, sends the report to the one repair subagent,
which re-renders the body from the table, rewrites the counts and writes any `uncovered:` line the plan's `worker not run:` lines call for, then runs the writer self-check above — never
a line-by-line patch of the body — and a
second `recheck:` mismatch after that ends the run with the mismatch named in the final message. The `recheck:` lines
describe the report as it is when the run ends: after every subagent that wrote the report has returned — the
writer's, a repair's — and after any write of this session's own, the set is recorded again with `--record`, earlier sets kept; a report written after the last
`recheck:` set has not been rechecked, and the run does not end on it: before the final message this session compares
the report's modification time with the last `recheck:` set's and records a set again with `--record` if the report is newer. D3 includes, among others: negative-verdict re-derivation, the
cross-lens shared-primitive rule, the BURIED-SINK AUDIT, Adversarial Impact Validation, and citation
verification. Run all of them. Whoever writes the report — this session or a consolidation subagent — reads
`scan-plan.md` first: the header's `Invocation:`, `Model:` and `Base SHA:` lines are copied from its
`invocation`, `model` and `base-sha` rows, never taken from the writer's own session; `<target>` in the title is
the target directory's basename; `Analyzer:` names the three skills with their frontmatter versions — the wrapper's
from the scan-plan's `wrapper:` row, the other two from the frontmatters the writer read; a name without a version
is a missing header value.

**WORKER RECORD ACCOUNTING.** The first thing STEP 3 writes is `.llm-sast-scanner-cache/disposition-table.md`,
before Step 6 and before any body block. A record is any line that opens — after any heading `#`s — with the Finding
Format first line `[SEVERITY] VULN-<id> — ...`, the severity token in any letter case: enumeration, the `file records`
count and every other count treat `[Medium]`, `[MEDIUM]` and `### [MEDIUM]` alike, and a count that differs by letter
case or by heading level has dropped records. A record line behind a list marker, a blockquote `>` or indentation is
not one: the gate counts it among the file's records and reads its heading as missing, so the worker is re-run and no
worker file that reaches STEP 3 holds one. The same reading applies wherever this skill counts records — the gate's path
count, the identity check, the close-out — so no two counts of one file can disagree by form.
Enumerate every such record in every `deep-<lens>-p<n>-results.md`, in worker file order, and give each one a row with the columns `worker record | entry point | sink file:line | class | disposition | verdict | body record`,
the entry point cell naming the entry point as the scan-plan's `## Entry points` list does — its `<file:line>` and name,
never with the list's ` | ` between them, which splits the cell —
so two workers that cite one resolver at its decorator line and at its method line, or by name alone, fill one cell;
two list entries sharing a name, the same field on two types, stay two entry points. The sink and class cells are the
record's own — the first sink of its `File:`, the same `path:line` read by first line, and a stem its `Reference:`
names, or, for a record whose `Reference:` names no stem, the stem its class is corrected to — never a sink or class the writer would choose: a record the writer reads as
another class keeps its own class in its cell and in its body block, because the merge rule and every key are read from
these cells. The table is built from
this run's worker files alone: a previous run's table, a previous report and its VULN ids are not inputs to any cell,
and a table found in the cache from an earlier run is deleted, not extended. Before Step 6 the table passes an identity
check — the set of `worker record` ids in the table equals the set of Judge-passed record ids in the current worker
files, in both directions, `promoted` rows excepted — their `worker record` cell reads `promoted/<lens>/p<n>` and is
the one id form the check ignores; a table that fails is deleted and rebuilt, never patched, and recheck item (31)
repeats the check on the table as written. Here `worker record` is
`<lens>/p<n>/<the worker's own finding id>`, the id exactly as the record's heading states it: the record headed
`[MEDIUM] VULN-001` in `deep-access-auth-p2-results.md` is `access-auth/p2/VULN-001`, never an id composed from the lens
or the partition. A record is one row, and a record's own finding is always that row — `body`, or `merged` into the
`body` row with its entry point, sink and class — never a `promoted` row: a `promoted` row is a STEP X or buried-sink
promotion, or a finding at another entry point of a record that names several. Every cell holds exactly one of these: a worker record id, an entry
point (route, handler, tool or consumer name), a `path:line` sink, a class name, a disposition word, a verdict as
defined below, or a VULN id;
a cell holding anything else — a cross-reference, a placeholder, a blank, a description, a sink without its `:line`,
a disposition outside the four words below and the `promoted` and `carried` rows' own — is an **invalid cell**. An invalid cell is filled from the row's worker
record; when the worker record does not hold the value (a `File:` with no line number), the row's disposition
becomes `unverifiable` with that reason and its body block moves to the Unverifiable section.
`disposition` of a worker record's row is exactly one of these four (a `promoted` or a `carried` row, defined below, is
not a worker record's and carries its own word):
- `body` — the record is a body record; `body record` holds the VULN id assigned to it here, in the table;
- `merged` — the record has the same entry point, the same sink `file:line` and the same class as a `body` row;
  `body record` holds that row's VULN id. A record whose entry point differs from every `body` row is never
  `merged`;
- `withdrawn` — Step 6 returned WITHDRAWN, or Citation & Evidence Verification failed, and nothing else — a record that
  repeats a `body` row's entry point, sink and class is `merged`; `body record` holds the word
  `withdrawn`, and the appendix lists one line per such row, `withdrawn: <worker record> — <Step 6 | citation>: <one
  line>`, so the reason has a home outside the cells;
- `unverifiable` — the record moved to the Unverifiable section, whose entries are numbered `UNV-<nnn>` in order;
  `body record` holds that id.
`verdict` is Step 6's result for the row, written into the table before any body block is rendered: `STANDING`,
`STANDING — downgrade voided: <named thing> is hop <n> of the Flow`, `DOWNGRADED — <trigger>: <the named thing the
attacker must hold>`, or `DISPUTED — <one clause>` for every `body` row whose worker record's severity — the severity
Step 6 saw, before any downgrade — is in `adv=`; `not run` for a `body` row whose record's severity is outside `adv=`,
so a record Step 6 disputed or downgraded below `adv=` keeps the verdict that lowered it; a `carried` row's cell is the copied block's `Adversarial:` verdict as it stands; `n/a` for every
other row. Any other content is an invalid cell, and so is a cell that is
specific in form but not in substance: every `DOWNGRADED` and `DISPUTED` cell contains at least one identifier in
backticks — a permission string, configuration key, function, type, route, role or VULN id — or a `file:line`, copied
verbatim from that row's own record (its File, Flow, Description or Evidence); a cell with no backticked identifier and
no `file:line`, or whose identifiers appear in no line of the record, is an invalid cell whatever its prose says, and
`invalid cells <c>` counts exactly those cells. Identical text on two rows is valid only when each row's record holds
the identifier. Verdicts are written per finding, never per category, and they carry across runs, and continuity is
the first write into the verdict column, not a repair after the recheck: before Step 6 runs, the writer joins the
table's `body` rows on their sink `file:line` — backticks removed — and class with the body records of every report the
scan-plan's `earlier-reports:` row lists, oldest to newest: a `DOWNGRADED` or `DISPUTED` verdict at a sink and class
stands from the report that gave it until a later report's block at that sink and class opens `STANDING — previous
downgrade voided:` — a bare `STANDING` in between does not clear it (one run rendered a downgraded sink bare, its repair
missed it, and the next run carried the bare verdict verbatim) — and a verdict given to one class's finding at a line
says nothing about another class's finding there. Every row whose sink and class hold a standing downgrade starts with
that verdict and its identifier already in its cell; the join is written into
`scan-plan.md` as `continuity join: <n> rows carry a previous verdict — <the joined rows' body record ids, comma-separated>`
before Step 6 starts, `n` equal to the ids listed, and it is what the appendix's
`verdicts carried <c> | voided <v>` must sum to; once written, the join line is never rewritten — a repair that finds
it wrong appends ` → corrected <n> — <ids> at <time>` to the same line, so the join the writer walked and the join the
repair settled on are both on record, because one repair cut a join line from sixty-six rows to fifty-nine in place
and the second recheck set agreed with a list nobody had seen; a join that names its rows is one the writer has walked, and a row it
names whose cell is later found bare is the writer's, not a joiner's, omission — one join line claimed fifty-four rows
while twenty-three of them were rendered bare. A carried verdict is copied, not re-run: it applies whatever the row's
severity and whatever `adv=` covers, so a row at a previously downgraded sink never reads `not run` — a class that came
in at its downgraded severity is exactly the row the previous verdict was about, and twenty-seven such rows once read
`not run (severity outside adv=)` under a join line that listed them as carrying. A voided cell is held to the same
identifier rule as a downgrade cell — `STANDING — previous downgrade voided: <clause>` names, in backticks or as
`file:line`, the thing from the row's own record that changed the judgement — and identical clause text across rows is
valid only when each row's record holds the identifier; recheck item (2) counts a voided cell without one as invalid,
because a repair once voided twenty-seven carried verdicts with one sentence that named nothing. Sinks are compared target-relative:
a `File:` line or sink cell written as an absolute path under the target is rewritten relative to it by the writer when
the table is built, because the ledger, the earlier reports and the join all speak in relative paths and fifteen
absolute ones once made fifteen keys that matched nothing. Step 6 may then replace such a cell only with
`STANDING — previous downgrade voided: <one clause naming what changed>`; a bare `STANDING` on such a row is an invalid
cell, and a run whose join line is missing rendered its verdicts without looking: one writer rendered thirty previously
downgraded sinks as bare `STANDING` and restored them only when the recheck named them.
Step 6 and citation verification update the `disposition` and `verdict` cells of this table. The body is then
rendered from the table: one Finding Format record per `body` row, in severity order, carrying the row's VULN id.
Every block has one layout, so two runs' blocks diff line for line: the severity line, then
`Worker record: <worker record id>` — or, for a carried block, its `Carried:` line in that position — then `Entry point: <the row's entry point>`, then the base skill's fields in its
order — CWE, File, Description, Impact, Flow, Evidence as a fenced code block, Judge, Adversarial, Remediation,
Reference — with no other line between them; and the `Adversarial:` line opens with the row's `verdict` cell —
the verdict word, and for a downgrade its trigger and named thing, for a voided downgrade its hop — followed by ` — `
and the base skill's one-sentence rationale, which is never omitted; a `not run` row's line reads
`Adversarial: not run (severity outside adv=)`. A block whose opening differs from its row's cell, or whose line ends
at the cell with no rationale, is an invalid block. The table is the only source of
verdicts: a re-rendering of the body for any reason — a repair, a completion pass, a second writer — copies them
from the table and never re-adjudicates, defaults or omits one. Body records that STEP X or the BURIED-SINK AUDIT promoted from a
clearance or a note are `promoted` rows under the table, each naming its source lens/partition, and are rendered
the same way. **Same-commit carry.** When the scan-plan's `base-sha` is not `unknown` and equals the commit the pre-write copy was
last written at — its header's `last-scanned-sha`, above its ledger heading, or, for a copy that holds ledger rows under no
such line, the sha of its newest `run <sha> <date>:` line under Coverage / depth notes, the latest date and of lines
sharing it the last — nothing in the code has changed since the ledger was last judged, so a finding judged then is a finding now: every
ledger row of the copy whose status is `open` and whose `class | file:line` key holds no row of any other disposition
this run — a key a worker reached and the writer dispositioned, as `body`, `merged`, `withdrawn` or `unverifiable`, or
that STEP X promoted, was judged this run and is not carried — is carried from the newest earlier report — among those the
scan-plan's `earlier-reports:` row lists, never a stray file in the directory — that holds a block with the same
target-relative `File:` sink and class whose verdict honours the sink and class's standing downgrade (repeats it, or voids it
in the named-hop form) — a report whose block at that key reads bare `STANDING` under a standing downgrade is passed over
for the newest one that honours it — a sink's line is its first line on either side, so
`Dockerfile:45-55` and `Dockerfile:45` name one sink; a block's class is the stem of its `Reference:` file, never the
words of its heading, which older reports wrote as titles: every block of that key in that report — several
when several entry points reach the sink, each a finding of its own under the base skill's identity rule — becomes one
`carried` row of the table (worker record cell `ledger` — or `ledger/<class>/<sink>/<n>` when the writer wants it unique — sink
and class the copy row's key, entry point from the block,
verdict cell the block's `Adversarial:` verdict, body record a fresh VULN id) and one body block, that block copied
verbatim, its `Worker record:` line dropped and its second line written as
`Carried: confirmed <the row's last-verified cell, copied as it stands> at <base-sha> — not re-judged this run — source <that report's file
name>` — a `Carried:` line the source block already holds is replaced by this one, not kept, so a block carried across
several runs names only its latest source — and every other line of the block as the source has it: copy the block's
lines byte for byte (the check forgives whitespace, nothing else); do not re-describe, re-evidence, re-word or re-title
it, do not change its severity, and do not rebuild it from the worker record — two runs rewrote every carried block in the
writer's own words and spent the one repair putting them back. So
the reader sees on every carried block what was checked today and what was not. A carried block keeps its
source's severity and verdict, counts in the histogram, and leaves its ledger row as it stands: `last-verified` keeps
the date of the judgement it carries. A row whose key no earlier
report holds as a block cannot be carried: such rows are counted in the appendix as `carried without source: <s>` — rows,
not blocks — and each brief
gains `not re-found <date>` as before. At a changed commit nothing is carried and every rule below reads as it did.
Workers are not told about the carry and behave as before: a sink they re-confirm is a `body` row with this run's
evidence, and only the sinks no worker re-confirmed are carried. At an unchanged commit the writer's prompt, and a
repair's, carries this **Same-commit carry** paragraph verbatim with the pre-write copy's path, the earlier reports'
file names and `base-sha`, so the carry is not lost to a summary. Two different things share the word: `verdicts
carried <n>` and the `continuity join:` line count previous verdicts joined onto this run's `body` rows at previously
downgraded sinks and never list a carried block; `carried` rows, blocks and the `carried <c>` counts are this same-commit
carry of un-judged ledger keys and never enter the join. The appendix reproduces `disposition-table.md` by copying the file, then states
`worker records: <n> | body: <b> | merged: <m> | withdrawn: <w> | unverifiable: <u> | promoted: <p> | carried: <c>`, where
`b + m + w + u = n` and `b + p + c` equals the number of body records, and the close-out line
`close-out: table rows <t> | file records <f> | body rows <b> | promoted <p> | carried <c> | body blocks <k> | linked blocks <j> |
invalid cells <i>`, each number produced by counting — table rows, Judge-passed record ids across the current worker
files, `body` rows, `promoted` rows, `carried` rows, `### [SEVERITY] VULN-` headings in the
body, body blocks whose
`Worker record:` id has a `body` row with the same VULN id or whose `Carried:` line has a `carried` row with the same VULN
id, and cells of the table that are invalid under the cell
rule above. `k` equals `b + p + c`, `j` equals `b + c`, `i` equals `0` and `t` equals `f + p + c` — a table shorter than the worker files
has dropped records and is rebuilt; until they do, the report is not finished and
the sentinel is not written. Both lines are written in exactly that form — a paraphrase into prose, however
complete, is not the line — and a repair that touches the body or the table re-counts and re-writes both; a report
whose appendix lacks either line is unfinished whatever its last line says. The body holds Finding Format records
and nothing else: no worker-file section, clearance record, pass log or coverage block is copied between body blocks,
and a severity section that refers the reader to another file for its records holds zero blocks — blocks are counted,
never described. The Severity Histogram is counted from the body. A
worker record that is absent from the body without a `merged`, `withdrawn` or `unverifiable` row is a STEP 3
error, not a de-duplication.

A prior report, the project-memory ledger, and a previous run's histogram are inputs to re-verify, never sources
of records or counts: a worker record that matches a ledger row is a body record of this run, and the ledger's
status is updated from it. Route families are entry points: two routes reaching one sink are two body records. A
`merged` row shares its entry point, its sink `file:line` and its class with the body row it points to; a row that
differs in any of the three is a `body` row, not a merge, whatever the writer's reason — de-duplication is between
lenses that recorded one finding, never between findings.

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

Class- and surface-level clearances get the same treatment by class instead of by sink: every `SAFE in p<n> — no
<surface> ...` line, and every unscoped `SAFE — no such ...` line a worker wrote anyway, is compared with the
disposition table's `body` rows by class. A body record of that class anywhere in the run contradicts the clearance:
the clearance is dropped from the report's clearance, Positive Patterns and Hardening Notes sections, is never written
to `project-memory.md` as a false-positive pattern, and is counted. One worker's slice proves nothing about the
repository, and a run that reports a class as absent while its body holds a record of that class has contradicted
itself in one document.

Any non-finding disposition line in a worker file — a Clearance Record, a `Hits → disposition` entry, a Hardening
Note, a Positive Pattern, a `safe-because` clause — whose text contains `disabled by default`, `enabled by default`,
`default configuration`, `environment-gated`, `non-production`, `only when the flag` or `unless configured` rests on
configuration and is not a clearance, unless the same line also names a code guard that holds regardless of
configuration — an authorization middleware, an ownership check, a validator, by name or by `file:line`. A flag or
setting listed beside such a guard is a guard list, not a clearance by configuration, and does not trigger. The base skill's Severity Downgrade Rule makes a non-default configuration a downgrade
trigger, so the negative-verdict re-derivation rewrites each such line's sink as a body record at its class severity
and Step 6 downgrades it naming that configuration. `config clearances rewritten: <k>` equals the number of such lines
without a `file:line` guard, found by searching the worker files for those phrases, and the appendix lists each as
`<lens>/p<n>: <its text> → <body VULN id>`; a `0` while the search finds such lines is a STEP 3 error.

Then every line of the scan-plan's `## Entry points` list is looked up by name across the worker files. An entry
point named in no finding's `Entry point:` line and in no Clearance Record was read but never analyzed — a worker
that cites lines 587 and 599 of a file has not examined the method at line 386 — and is a STEP Y hand-off to its
partition's owning lens; one still unresolved when the report closes is listed by name with the disposition
`unanalyzed`. A finding is never written for an entry point nobody traced.

The memory write is append-only and commit-aware. It keeps the memory's header above the ledger heading as the base
skill's template writes it — `scanner-version: <version>`, `last-scanned-sha: <base-sha>`, `last-updated: <the write's date,
YYYY-MM-DD>` and the `> Hints, never authority.` notice — because the next run's same-commit carry reads `last-scanned-sha`:
one write that dropped the header made the run after it read an unchanged commit as changed. It gives each distinct `class | file:line` key among the table's
`body` rows one ledger row, whatever the row's verdict — `STANDING`, `DOWNGRADED`, `DISPUTED` and `not run` alike — and
writes none for a row whose class is `unclassified`, which has no key: a first write over an empty ledger once kept 37
rows for 83 body keys, every low-severity finding Step 6 had not validated among the missing. A ledger row is never `fixed` when this run's `base-sha` equals the
row's `last-verified` sha: at an unchanged commit nothing was fixed, and a row whose sink no worker re-confirmed is
carried into the body under the same-commit carry of STEP 3; only a row that could not be carried — no earlier report
holds its block — is a miss of this run: it stays `open`, its brief gains `not re-found <date>`, and its sink is a STEP Y
hand-off to the owning lens. At a different commit a row becomes `fixed` only when `git diff <last-verified sha> <base-sha> --
<file>` is non-empty for the sink's file; an unchanged file is not re-found, not fixed. Run lines under Coverage /
depth notes are appended, never rewritten or removed, no ledger row is deleted, and a row is rekeyed only as this
paragraph says. A row's class is the
reference file stem, as the base skill's Memory Protocol defines the key — taken from the record's class, never composed
from its title — and a table or ledger row whose class is not the stem of a file in the base skill's `references/`
directory is an invalid cell, corrected to the stem before the write: a title as class is a key no later run will
match, so its sink is re-found as new every time. A ledger row already carrying such a class is rekeyed to the stem —
its brief, first-seen sha, last-verified and status kept, ` was <old class>` appended to its brief — and counted as
`rekeyed to stem <r>`; a rekeyed row is not a new key, and the pre-write copy's keys are read through the same
correction when the new keys are counted, so a rekey never appears as a key that arrived. When the pre-write copy holds
more than one row for a key, or the rekeying produces one — earlier
writes that broke the one-row-per-key rule — the writer merges them into one row whose brief joins the distinct briefs
with `; `, the brief's word limit yielding to the join so no caller's brief is lost, and counts them as
`duplicate-key rows merged <d>` — a row whose sink carries a range is a duplicate of the single-line row and merges into
it, the single-line row keeping its cells; this merge is the only way a row count may fall at an unchanged commit. The appendix
states `ledger rows before <n> | after <m> | archived <k> | duplicate-key rows merged <d> | rekeyed to stem <r>`,
counted from the pre-write
copy, `project-memory.md` and its archive: `m` equals `n` minus `d` plus the new keys minus `k`, `m` equals the number
of distinct keys after the write, the new keys are recheck item (12)'s key difference between the copy and the file,
and `k` is `0` at an unchanged commit, as the Same-commit carry paragraph reads it; a write that fails any of these is redone
from the pre-write copy STEP 1 made, `project-memory.md.pre-write-<started>`, which nothing in the run overwrites — a
copy made later would be a copy of the write under test, not of the state before it, and an earlier run's copy is that
run's evidence, not this one's. A writer that finds no copy under that name makes it before touching the file and the
scan plan records `pre-write copy: late`, so a `before` count taken from it is marked as taken after STEP 2.

**STEP Y — HAND-OFF HARVEST.** Scan every lens file for items it assigned to a different lens or partition
("belongs to crypto-data", "needs the p1/p2 server-side lens", "callers outside p3 should...", "if X becomes
client-controlled in future partitions"). Every such item is a required report item: either promoted as a
finding with a severity, or listed with a stated disposition and the evidence that closed it.

**REQUIRED APPENDIX FIELDS** — the report must state all of these explicitly:
The appendix is one `## Appendix` section whose sub-headings are the items below as `###` headings, in this order and
under these names, with nothing else at the `##` level after the body:
- Required cache artifacts: one line per file in the REQUIRED CACHE ARTIFACTS table — the filename and its
  byte size on disk. Any file that is absent gets a line saying so and why. Then `artifacts present: <n>/13`, then
  the section's final line, `earlier reports: <n> recorded | <m> present at recorded size` — `n` from the scan-plan's `earlier-reports:`
  row, `m` counted on disk at close-out by name and byte size. `m` below `n` is a STEP 3 error that no repair
  undoes; the run's final message names each missing or resized file.
- Scope exclusions: the contents of `scope-excluded.txt` — every row, its path and its reason — plus
  `excluded: <count> paths / <count> lines`, the paths its row count and the lines the `wc -l` total of the regular
  files it lists, a directory adding none, so a reader can tell a deliberate exclusion from a forgotten one. State
  `excluded: 0` only if nothing was dropped.
- Manifest citation coverage: `files cited in lens work: <n> / <manifest total> (<pct>%)`. Get `<n>` by
  extracting the distinct in-scope paths that appear anywhere in the `deep-*-results.md` files, and the total
  from `scope-manifest.txt`. Count both from the artifacts; neither is read from a worker's own coverage claim.
  Every other coverage number in this report is something a worker asserted about itself, and a worker that
  scanned some scope other than its assigned partition still asserts 100% — this one is derived, so that run
  shows a gap here. Report the number you get. It is a reading of the run, not a bar the run has to clear.
  Then `entry points dispositioned <n>/<m>` — `m` the line count of the scan-plan's `## Entry points` list, taken by
  a command and never `0` while the list has lines, `n` those
  named in a finding's `Entry point:` line or in a Clearance Record — followed by one line per entry point named in neither, `<file:line> | <name> | p<n> | unanalyzed` — possible only in a
partition holding a `worker not run:` pair, since a worker that passed its gate dispositioned every entry point it owns — and then `config clearances rewritten: <k>`.
- Added lenses: the added-lens derivation table from `scan-plan.md`, reproduced in full, then one line per lens
  beyond the base six — the lens name, the classes it owns, and the rule that chose it. Then
  `added lenses: <count>`, which is 1 or greater. A report stating `0` records a STEP 2 that did not finish.
- Buried-sink promotions: `<count>`, and one line per promoted item naming the lens/partition it came from and
  the demotion reason that was rejected. State 0 only if you audited every lens file and found none.
- Cross-partition clearance reconciliation (STEP X): one row per sink cleared by two or more agents — sink
  `file:line`, the lenses/partitions that cleared it, the scope each one claimed, and the verdict (GAP promoted
  / clearance stands). Then `promoted: <count>`, then `class clearances <n> | contradicted by body records <m>` —
  `n` the number of lines across the worker files that hold a scoped clearance, `SAFE in p<n> — no <surface>`, one
  count by one search in every run, never a writer's reading of what a clearance is; `m` those whose `<surface>`
  names a class that a `body` row carries — with each contradicted clearance named on its own line as
  `<lens>/p<n>: <its text> — contradicted by <body VULN id>`.
- Routed hand-offs (STEP Y): one line per hand-off — source lens/partition, target, the item, and its
  disposition. Then `routed: <count>`.
- Ledger sink caller enumeration (STEP 2a): one row per ledger sink — sink `file:line`, the partition that
  owned it, each entry point traced to with its hop chain, which were already reported, and which are new.
  Then `new entry points: <count>`. State `ledger empty` if there was no ledger to trace against.
- Worker dispatch: the `workers dispatched: <n>` line, the `waves:` line, each `wave <k>:` line and the per-worker
  lines copied from `scan-plan.md` — the per-worker lines with their start times are the evidence, and a wave line
  that disagrees with them is reported here as a STEP 2 error — then
  `dispatch lines late: <n>` — the first-attempt dispatch lines beneath each `wave <k>:` line whose time equals or follows that wave's completion — then
  `procedure lines: <k>/<n>` — the count of worker files whose first line is the `procedure:` line with the
  frontmatter versions; `k` equals `n` — then `contracts checked: <n>/<n>` and `stale worker files moved: <n>`, both
  copied from `scan-plan.md` (two runs' reports lacked them, and recheck item (13) counts them) — then, when the plan
  holds `worker not run:` lines, one line `uncovered: <lens>/p<n> — <f>/<mf> files, <l>/<ml> lines read after 3 attempts`
  per such pair, its numbers from the file's `coverage:` line — `0` when it has none — over the partition manifest's
  counts (recheck item (29) counts these lines against the worker files; a list marker before `uncovered:` is tolerated).
- Per-lens-per-partition pass log: passes run, what the last pass added, stop reason, converged yes/no — copied from
  each worker file's sentinel `passes=` value and its pass log, never composed by the writer; a `worker not run:` pair's
  entry copies the file's own convergence status line and reads `passes: none (worker not run)`, or `no worker file`
  when the file is absent.
- Line-count reconciliation of each partition against the manifest, the scan-plan's `checks:` line copied verbatim,
  and the partition table from `scan-plan.md`
  with each partition's source share and entry-point share, none above 40% — or, when one is, the `check failed` line
  copied from `scan-plan.md`, so the single file that forced it is named in the report.
- Worker record disposition: `disposition-table.md` copied in full (one row per Judge-passed worker record), the
  `promoted` rows, the totals line `worker records: <n> | body: <b> | merged: <m> | withdrawn: <w> |
  unverifiable: <u> | promoted: <p> | carried: <c>` with `b + m + w + u = n` and `b + p + c` equal to the body record count, and the
  close-out line `close-out: table rows <t> | file records <f> | body rows <b> | promoted <p> | carried <c> | body blocks <k> | linked blocks <j> |
  invalid cells <i>` with `k = b + p + c`, `j = b + c`, `t = f + p + c` and `i = 0`, then, at an unchanged commit,
  `carried without source: <s>`. Then the ledger line
  `ledger: <k> distinct class|file:line keys among body rows | <j> of them present in the ledger`, both counted after
  the memory write — `k` the distinct keys among the table's `body` rows, not the ledger's row count (one writer stated the
  whole ledger here), `j` of those keys found in `project-memory.md`'s confirmed-findings ledger; `j` below
  `k` means the write dropped findings, and the memory file is rewritten from the table before the run ends. A
  DOWNGRADED or DISPUTED row is one of those keys, carrying its verdict in its brief, never a false-positive pattern.
  Then `ledger rows before <n> | after <m> | archived <k> | duplicate-key rows merged <d> | rekeyed to stem <r>` as
  defined under STEP X, and `verdicts carried <c> | voided <v>` from the continuity rule of the verdict column.
- Severity histogram.
- Maturity: one line, `maturity: streak <n> | new keys <k> | found-late <f> | worker records <this run> vs <previous> |
  body <this run> vs <previous> | carried <c> | <mature | not mature>` — `k` the new keys of recheck item (12), the distinct ledger
  keys present after this run's write and absent from its pre-write copy, the number the memory run line's
  `new-confirmed` states, `f` the found-late
  files of the base skill's Memory Protocol, the two `vs` pairs — `worker records` the table's row count, `body` the
  body blocks, the close-out's `b + p` and the histogram total, never the `body` rows alone, because rows follow how a
  writer split multi-route records into promoted rows while blocks follow the findings — counted from this run's
  close-out and, for `<previous>`,
  read from the `close-out:` line of the newest earlier report — the last file of the scan-plan's `earlier-reports:`
  row — as its `table rows` and `body blocks` values (`n/a` only when that row reads `earlier-reports: 0`), and `worker
  records` for this run is the table's rows minus its `carried` rows. The streak is derived, never asserted: the previous run line's streak plus one when `f` is 0, `k` is at most 3 and the
  plan holds no `worker not run:` line — the union of findings has stopped growing, and a partition nobody read says nothing
  about it — else 0. The body
  count is no longer the measure: under the same-commit carry the body is the ledger's open keys plus this run's new
  ones, so it can only grow, and how many known sinks a day's workers happened to re-confirm no longer moves it; the
  measure is whether the ledger still gains keys. Three new keys, not zero: one more caller of a known sink or one
  re-keyed sink does not mean the repository is still yielding findings, and thirty new keys does. `mature` is
  written only at a streak of 2 or more, and the
  memory's new run line carries the same streak, so the two never differ. The two `vs` pairs and `carried` are evidence for the
  reader, not inputs to the streak.
  The report header repeats the status on its first screen: a `Maturity:` line directly under `Base SHA:`, reading
  `Maturity: streak <n> — <mature | not mature>`, copied from this appendix line once it is derived and from nowhere
  else; a header whose `Maturity:` line differs from the appendix line is a STEP 3 error, repaired in place.
- Body/histogram reconciliation: one line per severity, `<severity>: <records counted in body> / <histogram
  count>`, produced by recounting the finished body; every pair equal.


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
- **Added lenses are selected by dependency signal because registration counts were measured not to converge.**
  Seven runs of one repository at one SHA produced seven derivation tables — the leading family's entry-point count
  ran 42, 83, 41, 49, 49, 458 and 395, a second family's 20, 55, 24, 24, 24, 38 and 123 — and four different lens
  sets, while the packages the manifests name were the same in every run but one. Two wording rounds that told the
  orchestrator what a registration is and whose it is did not narrow the spread. The counts stay in the table as
  information; nothing reads them to choose.
- **Workers start in waves of at most 15 because concurrency was measured against the runtime's account-wide message
  limit.** 21 concurrent workers completed twice; 27 tripped the limit mid-run and the run died with partial files; 33
  tripped it nineteen seconds after the consolidator finished, losing the final verification and the transcript. Fifteen
  leaves room for the orchestrator's own polling. A wave waits for the whole previous wave rather than sliding one slot
  at a time so the dispatch record stays a short list a reader can check.
- **Verdicts live in the disposition table because a re-render lost them.** One consolidation first rendered 11 of
  201 body records; the orchestrator caught it and dispatched a completion pass, which re-rendered every block from the
  table — a table that held no verdicts — and stamped one STANDING sentence on all 201, dropping two correct downgrades
  and one dispute the first pass had made. The same pass paraphrased the close-out into prose and pasted worker-file
  sections between body blocks. The `verdict` column, the verbatim close-out requirement and the body-purity sentence
  each name one of those three losses.
- **The worker's first line is built from the frontmatters, not copied from the prompt,** because in two consecutive
  runs one of 33 compiled prompts carried a typo in a skill name, the worker copied it, and the header check forced a
  serialized re-run before the next wave.
- **The disposition table has an identity check because a consolidator re-used the previous run's table.** With a
  prior report and table left in the cache, one `new-scan` consolidation added the new column to last night's 323 rows —
  73 of them for records no current worker had written, 97 current records missing — and wrote a report whose severity
  sections pointed at the previous report instead of holding blocks. The check compares id sets in both directions and
  rebuilds; a pointer section counts as zero blocks.
- **Waves are defined by dispatch timestamps because a wave line was re-labelled.** An orchestrator started 18 workers
  together, then rewrote the summary as waves of 15 and 3 sharing one start time. The dispatch lines could not be
  re-labelled; the check reads them.
- **Unit formation checks parents because a directory under both limits was split anyway,** moving 128 of 178 units
  between partitions at an unchanged SHA and ending the worker-by-worker comparability the deterministic cut exists for.
- **STEP 2a is in the worker template because workers never read this file;** a run whose contracts omitted it produced no
  enumeration and no `new entry points` lines, after a run whose contracts included it had produced 183.
- **STEP 3 runs one subagent at a time because the account message limit tripped after the workers had finished,** in
  the consolidation-and-repair phase, on two runs whose worker waves had stayed under the cap.
- **Records are enumerated case-insensitively because a case-sensitive count dropped 43 and then 42 records** — every
  one written `[Medium]` instead of `[MEDIUM]` — while the self-check, counted the same way, reported the table complete.
- **Workers pin the target path and commit by running the commands** because seven of fifteen workers in one wave audited
  a sibling copy of the repository and were caught only after finishing; one sibling sits at the same commit, so the
  path line is the primary check and the SHA the secondary.
- **Block layout and appendix sectioning are fixed because three consecutive reports laid them out three ways** — the
  `Worker record:` line second, last, or third; an `Entry point:` line in one; Evidence fenced in a third of blocks;
  one appendix section or nine — each consolidator choosing where the unspecified pieces went.
- **The pinning values live in the first line because a separate line was skipped by half the workers on first
  attempt** — one run re-ran seventeen of thirty-three workers for it — while the first line has been written correctly
  in every file of four consecutive runs.
- **Verdict cells must be specific because one consolidation wrote a single sentence for all seventeen downgrades and
  another for all fifty-two disputes**, meeting the form of the rule while naming nothing the Flow check could test.
- **Runtime logs and transcripts are excluded because a previous run's exported transcript was partitioned as source
  with fifty entry points**, all of them route strings quoted inside the JSON.
- **Earlier runs' reports are named, counted and protected because a consolidation writer deleted them.** The rule
  said a second report "newer than the run's start" is deleted "so exactly one report is newer than the run's log";
  with no recorded start and no named report file, one `new-scan` writer read it as one report in the directory and
  deleted the two earlier runs' reports, and the run before it had "rewritten in place" the previous run's report
  instead of its own. The `started:`, `earlier-reports:` and `report:` rows make both comparisons mechanical, and
  the `earlier reports:` close-out line makes a loss visible instead of silent.
- **The ledger-phrase gate is case-insensitive because five of six re-runs in one run were for `New entry points: 0`
  written at the start of a sentence** — the phrase was present; only its capitalization differed.
- **Worker files must end in `coverage:` and `passes:` lines because a template sentence read as "omit them".** One
  run's 27 workers took "without the Adversarial field, the Clearance Records, the coverage checklist, the pass log and
  the convergence status" literally: 22 files had no coverage line, 26 no pass log or clearance records, and three held
  only the header, `ledger empty` and the sentinel — 300 bytes of evidence for the partition with the most entry
  points. The sections are now required with two checkable lines, and the gate checks them.
- **The gate writes a `gate:` line per worker file because a gate that ran three of its six checks passed a file citing
  a path that did not exist.** The consolidator's citation verification passed it too; the orchestrator found it after
  the report was written, re-ran the worker, and string-patched the report, table and gates file itself — a third
  writer after the single permitted repair. A gate line with a `paths <k>/<m>` count cannot be skipped silently.
- **A recorded gate line is compared with its file — its digest and its counts — because one worker rewrote its file
  after its sentinel and its gate.** Its 47 records became 40 while the next wave ran; the plan kept the line for 47, the report
  was built from the 40, and the only check that compared the two read their verdicts, both a pass. The line now carries
  the file's digest, so a change that keeps every count — a severity rewritten, a path swapped — reads as one too.
- **Item (37) reads the entry point cell because one repaired run read `mismatches 0` with none left.** Its writer
  wrote `worker entry point` into all 328 rows it built and into their blocks, and the repair kept it: item (37) read
  the sink and class cells only, block layout read the block against the row, and the two agreed. The cell is met by
  what names it — the list's form and the record's words differ — never by equality.
- **The gate compares each worker file with its pair's earlier files because a clean run's coverage was partly
  copied.** Two new-scans at one commit each read `mismatches 0` on their first recorded set, and in each about a
  quarter of the workers had returned the previous run's file for their pair, pass log included, with a line or a
  record edited; nothing read it, because every count in those files was right. The `copied` field reads it, over
  the prose a worker writes rather than the code it quotes, so a worker that re-verifies passes and one that copies
  is re-run.
- **The ledger line exists because one memory write kept 19 rows for 88 body keys.** None of the run's 31 DOWNGRADED
  or DISPUTED findings got a row, so the next `new-scan`'s STEP 2a would have re-traced 19 sinks instead of 88. Memory
  is regenerable from the table, so a shortfall is rewritten, not reported.
- **Identical verdict text across sinks is allowed only for one verbatim identifier because the flat ban flagged real
  cells and missed bad ones.** Seven shared verdicts named one permission gating adjacent resolvers or one
  configuration key across four overlay files, each present in its rows; two other cells named a phrase that appeared
  in neither of their records and were counted valid.
- **Coverage and pass counts live in the sentinel because two separate lines reached 12 of 27 files.** The orchestrator
  compiles a per-lens contract and copied two specs verbatim — the first line and the sentinel — which reached 27 of 27
  in two runs; the `coverage:` and `passes:` lines it paraphrased into "include the coverage checklist and pass log", and
  its gate had a slot for one and none for the other, so twelve files without a pass count passed.
- **The gate's path count is the record count, read with backticks stripped, because `paths 0/0 resolve` passed a file
  with six records** — every `File:` value in it sat in backticks and the check saw no paths at all.
- **Verdict cells need a backticked identifier or `file:line` from their own record because four consolidations judged
  their own prose valid.** Thirty-seven of thirty-eight cells in one run reused seven sentences, none containing an
  identifier, and the close-out still read `invalid cells 0`; a regex is the first form of this rule that anyone but
  the writer can recount.
- **The worker file is named by absolute path because one worker wrote it into the repository root**, where the
  orchestrator found and removed it before re-running the worker.
- **The appendix states maturity from counted values because one consolidation declared a repository mature on a run
  with 118 newly confirmed findings.** The streak had been asserted by the writer into a memory line no reader opens;
  it is now derived from the new-key and found-late counts and shown beside the record counts, which are evidence for
  the reader and not inputs.
- **Class clearances are partition-scoped and checked against the body because one worker cleared a whole attack
  class from its third of the repository.** It wrote "0 applicable production hits in the assigned partition" and
  stamped it `SAFE — no such production surface`; another worker's body finding of exactly that class sat in the
  same report, and STEP X, which reconciles by sink, kept the clearance with a boilerplate verdict. A clearance
  resting on absent callers now also says "in-repository", because what an external consumer does with an upload
  bucket is unverifiable from the code, not safe.
- **A configuration default is never a clearance because one worker cleared a whole anti-automation middleware as
  "disabled by default" and "environment-gated".** Eleven findings of an earlier scan at that sink vanished behind
  that sentence; under the base skill the same sentence is a downgrade trigger, so they are body records carrying a
  DOWNGRADED verdict, not silence.
- **Entry points are accounted for by name because two live resolver methods in a fully "covered" file were never
  analyzed.** The workers cited two lines of the file and nothing in the ninety lines holding the other two
  methods; a third mutation in another file was never mentioned by anyone. Coverage counts lines read, not entry
  points traced, and the list STEP 1 already builds for the cut is the denominator that shows the difference.
- **The memory write is commit-aware because one consolidation marked 54 ledger rows `fixed` at an unchanged commit.**
  The workers had not re-confirmed them, the writer read "mark now-fixed ones fixed" without a guard, archived them,
  and deleted a run line from the history; the next `new-scan` would have re-traced 154 sinks instead of 218 and
  called the loss maturity. At the same commit a finding not re-found is a miss, and a miss stays open.
- **Compiled contracts are checked for the two spec sentences because one omitted the first-line spec and all fifteen
  workers of a wave came back with the wrong header.** The sentinel sentence in the same contract was verbatim and
  reached 25 of 25.
- **The configuration rule names its trigger phrases because three consolidations reported `rewritten: 0`** while the
  clearance it was written for — "disabled by default and environment-gated" — stood in every one of them.
- **Verdicts carry across runs because three consecutive re-scans downgraded nothing** at a commit where the run before
  them had downgraded thirteen findings with proper identifiers.
- **Previous counts come from the earlier report because the memory run line never held them**, so the first
  `vs <previous>` pairs read `n/a` under two preserved reports.
- **This session recomputes the writer's counts because every count the writer reported about itself was asserted.**
  One report carried `invalid cells 0` computed on a table with two verdict cells while its body held thirty-three,
  thirty of them without clause or identifier; the orchestrator then spent an hour of in-place repairs converging the
  body toward the table. The `recheck:` lines make the recomputation a recorded step instead of an instinct.
- **The cut continues by reassignment because a cut that failed its own check was dispatched.** One partition held 47
  percent of the entry points against a 40 percent cap; the remedy stopped when its largest unit was a single file,
  the plan recorded `check failed` and no verdict, and that partition produced records at a third of the rate of the
  lightest one.
- **Merges are constrained to identical entry point, sink and class because one writer merged 31 of 132 records,**
  three of them across different entry points, where the run before merged 8 of 176.
- **The contract check asks for the two forms, not the template's sentences, because a paraphrased contract reached
  27 of 27** while an earlier contract that omitted the first-line form reached 0 of 15.
- **The configuration phrases are narrowed because a flag named beside real code guards is not a clearance by
  configuration**; the broad list matched nine such guard lists and no configuration-only clearance.
- **Record enumeration strips line prefixes because one worker wrote its records as headings and every count missed
  them.** The gate read the file as holding no paths, the writer read it as holding no records, and the close-out
  agreed with itself because both counts shared the blind spot. A count is only a check when its reading of a line is
  the same everywhere.
- **Worker prompts are path-tested before dispatch because ten of thirteen re-runs in one run were the orchestrator's
  own path error, repeated once** by the repair prompt that inherited it. The contract check cannot see the prompt.
- **The writer's failing recheck lines print their fix, the writer starts only on recorded gate lines, and the report name
  is checked, because one first run went to repair**: its writer returned after three self-check runs with four items
  open — a merge across entry points, a config-clearance count, a duplicate ledger key, a run line counting body blocks
  — that the repair closed in five minutes; its session had run the gate but recorded no `gate:` line; and its report
  was named for a time twenty minutes after the file was written. One of the four was the recheck's: its phrase search
  read a finding's own `Judge:` line (`no safe default`) as a configuration clearance, so the writer's correct `0` was
  flagged and the repair changed it to `1`; the search now reads disposition lines only.
- **A withdrawn row says why, and a promoted row is never a worker record's own finding, because one fresh run's writer
  withdrew all 146 worker records and rendered 50 findings as promoted rows, which a repair cut to 36**: the recheck read
  `mismatches 0` twice while 66 worker records' findings were in no row of the report. The id check exempts promoted
  rows and nothing read the withdrawn lines the rules require, nor the sink and class cells the writer had replaced on
every withdrawn row; all three are items now, and the table rules say plainly that
  a record's own finding is its `body` row, the wording "a finding at another of its entry points is a `promoted` row"
  having been read as the form for every kept finding.
- **The ledger at start is read against the report that left it, and a kept cache against its previous plan, because
  one STEP 1 re-created the memory**: a `new-scan` over a kept cache initialised `project-memory.md` from the template,
  copied the empty file as its pre-write copy, overwrote the previous plan without copying it and left twenty-seven
  earlier worker files in place — `ledger rows at start: 0`, `previous run residual: none` and `stale worker files
  moved: 0` all read true against what the run itself had made, and ninety-eight ledger rows were gone. The earlier
  run's own copies in the cache and its report's `after` count are what the run could not rewrite.
- **Eight appendix and block rules are items because a clean-reading write broke them all**: a first write whose set
  read `mismatches 0` held two Medium records under Low, forty-six Low records with Step 6 verdicts, sixty-four
  `Adversarial:` lines ending at their cell, and a sentence where the disposition table, the exclusions, the clearance
  count and the pass log belong; an audit of STEP 3 rule by rule found each of them read by no item, and the repair that
  fixed them, reading `adv=` on the block's severity, erased forty-six verdicts Step 6 had written. The verdict rule now
  names the record's severity.
- **A row's sink and class are read against its worker record, and a body block's too, because one writer collapsed a
  scan into one finding**: it rewrote 213 of 214 rows onto one sink and class, merged them into one body row, and every
  item read the table it had made agree with itself — only the carry, at an unchanged commit, saw the report had lost
  its findings; at a changed commit the set would have read `0`. Earlier clean-reading runs had changed a few classes
  and sinks the same way, unseen.
- **The memory's header is an item, and a copy without one reads its newest run line's commit, because one write
  dropped it**: a clean-reading run rewrote `project-memory.md` from its ledger heading down, losing `last-scanned-sha`
  with the rest of the header, and its recheck read `mismatches 0`; the next run at the same commit found no sha in its
  pre-write copy, carried nothing, and its report lost three findings its predecessor held — one Medium — while that
  run's recheck also read `0`. The header is now checked where it is written, and a copy that lost it is read at the
  commit of its newest run line, which the same write kept — the newest by date, not by place, since one write put
  its line first.
- **A dispatch line's time is read after its prompt is tested because one run's first-wave lines were timed before
  any prompt existed**: all fifteen carried the wave's `started` time, read five seconds before the first prompt file
  was written, its completion stood on a line of its own that the recheck did not read, and the appendix's `dispatch
  lines late` was stated and never counted. All three are read now; a prompt written after one of its wave's workers
  ended is not, since one run rebuilt all twenty-seven for a re-run while its first wave was still running.
- **The recheck reads what the skill writes, because a whole-script review found lines a correct run could fail**: a
  `## ` line in a quoted Makefile read as a stray heading, a `wrapper:` row corrected by its append still read wrong, a
  wave written on two lines split its roster, an archived `fixed` row at a changed commit read as lost, a report whose
  name held no timestamp passed unread, and a worker file for a pair on no roster left `--prompt` asking for a gate line
  the gate never printed. A failure that no writer or repair can change now says so (`recheck: repair none`), so the
  one repair is not spent on a STEP 1 or STEP 2 line.
- **A VULN id heading two blocks is named, the writer has five self-check runs, and a wave's completion is a time read,
  never composed, because one fresh run's writer rendered two findings twice — once Medium, once Info — and returned
  after its third run with three items open, each described by its hint**, and its session wrote both waves' `complete`
  times minutes before their last files were sealed. The block count's hint had said to restate the count, which
  would have hidden the duplicates; it now names them. The waves had started in order, so only the stamps were wrong,
  and the recheck reads them against the files only where the files' times are the run's own.
- **The writer reads this skill's STEP 3 before it writes, and the recheck repeats the table's identity check, because
  one fresh run's writer, sent only to the base and loop skills, drafted a table in ids of its own (`INJ-P1-001`,
  disposition `retained`) and an appendix with none of its required lines, and its repaired table, read
  `mismatches 0`, joined 15 of 114 worker records by id**: `VULN-001` had become `VULN-AA-P2-001`, and one record sat on
  six rows. The skill defined the check and no script ran it; the recheck now does, its hint naming the heading's id, and
  the Writer self-check paragraph, which every writer's prompt carries verbatim, names the file and the span that define
  the table.
- **The session records a set with `--record`, and a run without it writes nothing into the plan, because one
  rehearsal's writer appended its three self-check runs to the plan under a prompt that said to read them without
  appending them, and its session ran its last recheck without recording it.** A rule about where output goes held for
  neither agent, so the script decides what a redirect records: only `--record` appends, what it prints is one
  `recorded:` line that is never a set, and a plain run redirected into the plan is dropped with a note. A `checks: failed` line whose failures each name
  one file over the cap is accepted by item (19) because the same rehearsal's plan was flagged for a cut no move could
  fix.
- **A worker is started with one line naming its tested prompt file, never with the prompt re-typed, because the
  four misspelled cache directories of one run were all typed into the start calls,** which no test reads. A test of
  the file says nothing about a second copy made after it; the one line leaves a single path to type, and a worker
  that cannot open it says so before it reads anything. The line reads, checks, then follows: worded "read it and follow
  it" with the partition check after, four of five test workers followed a file that named another partition; in this
  order five of five stopped, five of five recovered a misspelled path through the fallback, and five of five read a
  correct one.
- **Header versions are on the recheck list because a scan plan named another skill's version as the wrapper's** and
  the report header copied it.
- **Entry points are defined as invocable registrations because two sessions counted the same commit as 250 and 205**,
  one counting the containers that group operations and one not. An accounting denominator that moves between runs
  measures the counter, not the code.
- **The recheck follows the report's last write because one report was written eleven minutes after its recheck**;
  lines that certify an earlier version certify nothing.
- **The preamble states that subagents are required, and the no-subagent fallback needs an actual refused attempt,
  because one session read "executed directly" as a ban on delegation** and ended after STEP 1 with `workers
  dispatched: 0 — prohibited by session policy` without ever calling the subagent tool, which the runtime offered.
- **The contract check demands the forms with placeholders because one contract passed it with a filled-in header as
  its own first line** and told workers in prose that two command outputs "must become the first-line fields";
  twelve of fourteen workers then built their own line, fields reordered and versions split. A form with real values
  in it is a record of one run, not an instruction for the next.
- **The gate reads the first line as named fields because two gates read the same twelve reordered headers two ways**:
  a gate that tests the form fails a line whose fields are merely reordered and re-runs a wave for nothing, a gate that
  tests for words passes a line whose fields carry other names. Splitting on the separator and requiring three named
  fields accepts the first and rejects the second, and the `gate:` line then says what was tested.
- **Recheck lines carry their command because two of ten were asserted.** One session wrote `invalid cells 0` over
  eight cells with no identifier and a tag count one higher than the body held, then a repair happened to make both
  true. A number with its command beside it can be re-run by anyone; a number alone is the writer's word again.
- **Headings and the maturity record count are recheck items because a writer inserted a thousand-line working-notes
  section between the body and the fixed sections**, duplicating the close-out inside the report, and quoted body
  rows as worker records; neither had an item, and the orchestrator found the first by luck.
- **Stale worker files are moved aside at STEP 1 because a run over an uncleared cache held twenty-nine files from an
  earlier run at the same commit**, each with a header and pinning the gate accepts; only their older sentinel form
  would have failed them, and the next sentinel change removes that accident.
- **Stray worker files are swept at the gate because one worker wrote its first attempt under a misspelled cache
  directory**, eight records in a file no count could see, left behind after the run ended.
- **A single worker's refusal is a re-run and then a recorded gap, never a stop, because one session read "one attempt
  whose result is a refusal" as proof the runtime could not start subagents** after fourteen workers had finished,
  overwrote `workers dispatched: 27` with `0`, and abandoned the run with the same content-filter refusal that earlier
  runs had re-run successfully.
- **A recheck command must read the artifact it measures because ten lines in one run carried `print(0)` as their
  command**: present, as the rule asked, and recomputing nothing. A command whose output cannot change when the file
  changes is the writer's number with a shell prompt in front of it.
- **The output path is tested by equality because an existence test cannot see it**: the file does not exist until the
  worker writes it, and two output-path typos in one evening — a misspelled cache directory, an inherited prompt typo —
  passed `paths 8/8` and left records where no count could find them.
- **Dispatch lines late are counted because one session wrote all of a wave's lines at the wave's close**, every
  timestamp the completion time, so the record of when each worker started was the record of when the orchestrator
  got round to writing it.
- **`class clearances` is one search because four writers returned 0, 94, 183 and 515 for runs of the same shape**;
  a count whose definition changes with the counter measures the counter.
- **`new keys` is reconciled against the ledger statements because one report carried 94 beside 92**, two lines apart,
  and no item compared them.
- **The phrase test reads the ledger state because the same two workers wrote `ledger empty` against a populated
  ledger in two consecutive re-scans and passed the gate both times**; two partitions' recorded sinks went
  un-retraced twice while the gate reported `phrase ok`.
- **The invalid-cell test is a regular expression in the rule because a recheck command that read the table still
  passed ten cells that were the bare word `DISPUTED`**; a command can read the right file and test the wrong thing,
  so the rule now says what to test.
- **Ledger counts are named patterns because a recheck read the memory file and reported 137 rows where it held
  111**, and the `present` count was claimed complete while 31 body sinks were absent.
- **Required lines are a recheck item because four appendix lines were missing under twelve correct headings**; the
  heading check cannot see what is under a heading.
- **Verdict continuity is a join on `File:` because a run reported `carried 0 | voided 0` while six of the previous
  report's ten disputed sinks sat in its body as bare `STANDING`**.
- **`entry points dispositioned` takes its denominator from a command because one report read `0/0` against a
  208-line list.**
- **The maturity streak follows the body count, not the key count, because three re-scans at one commit held the
  findings at 162, 162 while the ledger grew 111, 178, 211**: the keys grow from re-keyed sinks and newly traced routes
  long after the findings have stopped moving, so a key-based streak never leaves zero on a converged repository.
  Superseded: once open ledger rows are carried into the body at an unchanged commit, the body can no longer
  swing with the workers' re-confirmation, and the key count — bounded at three — is the measure again.
- **The pre-write copy is per run and the row pattern admits a line range because one redo used the previous run's
  copy and one count read 168 where 178 rows stood**, ten of them citing a range.
- **The contract check asks for the two forms and nothing else because its third element, the partition manifest's
  path, was never in a contract yet always reported present**: a contract is compiled per lens and serves three
  partitions, so the path lives in the dispatch prompt, which the path test already verifies. A check with an element
  nothing can satisfy is a check that gets asserted.
- **The start count is taken over a copy STEP 1 makes because one scan plan carried the previous plan's number as a
  literal**: the script that wrote the row had a counting function and did not call it, the row was rewritten after
  the report, and the state it described no longer existed. A copy made before anything runs is a number anyone can
  recount later.
- **Duplicate keys are merged with their briefs joined, and counted, because one write collapsed 37 rows in silence**:
  six callers of one sink had six rows and one survived, and the row equation held because 37 deletions and 74
  additions net to the 34 it reported.
- **`new keys` is a key difference between two files because three numbers stood for it in one run** — 34 by row
  arithmetic in the report, 74 in the memory run line, 74 in the files — and the two recheck commands for it print a
  fourth when run.
- **The row pattern admits digits because three rows whose class carried one were outside every count**: the file
  held 248 rows and every statement about it said 245.
- **Classes are checked against the reference directory because nearly half of a ledger's rows carried a finding
  title as their class**: 117 of 248 rows, 86 of 255 table rows, each a key nothing in a later run will match, so the
  ledger grew from 92 to 248 rows at one commit while the findings converged. The key exists so the next run
  recognises a sink; a title as class defeats it.
- **Recheck lines are printed by one script because two lines carried numbers their commands do not produce**, and
  two more returned to `print(0)` after the rule forbidding it; a line printed from the command's output cannot
  disagree with it.
- **Rows above `workers dispatched:` are corrected by appending because one was overwritten after the report**; the
  correction made a recheck pass against an input changed to match it.
- **Maturity compares body blocks because two writers rendered findings of the same shape as 162 rows plus 52 promoted
  and as 245 rows plus 0**: rows follow the writer's splitting, blocks follow the findings.
- **The recheck script is an artifact that must hold the rules' expressions because the first one-script set read
  `invalid cells 0` over ten identical verdict cells that named nothing**: the script tested the table's cell structure
  where the rule states a regular expression over the body, and it lived under a temporary directory. One script made
  the numbers reproducible; only the expressions in it make them the right numbers.
- **`rekeyed to stem` is recomputed from the briefs because a write reported 117 rekeys and left the old class in 35
  briefs**: a count nothing in the file can reproduce is an assertion, and a rekey without its trail cannot be audited
  back to the row it replaced.
- **The recheck is shipped code because seven versions of recheck prose were each defeated by a new form of
  assertion**: typed numbers, then `print(0)`, then the right file with the wrong predicate, then one script that
  held the rules' expressions beside constants for twelve of eighteen items and was also the writer's own build
  script. Prose cannot pin eighteen predicates; a file with a checksum can. The session copies it, runs it and pastes
  its output, and every number on a `recheck:` line is one anyone can reproduce by running the same file.
- **The scan plan is copied at dispatch because STEP 1 rows were rewritten after the report**: a `checks:` line and an
  entry-point row were replaced with values that matched the writer's tables, so a recheck that read the plan read
  the result it was meant to test. A copy taken when `workers dispatched:` is written is the STEP 1 the workers ran on.
- **The dispatch prompt ends with the first-line form because eleven of twenty-seven workers wrote the outputs of two
  commands as their first line**: the contract held the form, one paragraph deep, after the sentence that named the
  commands; the gate re-ran all eleven at a cost of eight minutes.
- **The gate counts severity-headed records because two records headed `[LIKELY]` reached the table and were dropped
  by a repair**: a heading without a severity cannot fill the table's severity, the equation `file records = table rows`
  then fails for a reason no repair can fix without touching a worker file, and the repair balanced it by deleting
  findings. The worker is re-run instead, before anything downstream depends on the file.
- **Continuity is the verdict column's first write, recorded as a join line, because a writer rendered thirty previously
  downgraded sinks as bare `STANDING`** and restored them only after the recheck named them; a rule that is applied
  when a check fails is a repair, and a join whose size is written down before Step 6 is a step.
- **Open ledger rows are carried into the body at an unchanged commit, labelled, and the streak follows new keys,
  because ten re-scans of one commit produced bodies of 245, 280, 268, 261, 283, 280, 248, 172, 233 and 199 blocks
  while the ledger only grew**: a finding that passed the Judge and the adversarial step at this commit is as valid
  today as then, re-judging it measures the workers' consistency and nothing else, and a body that follows that
  consistency can never hold still. Every block of the key in its newest report is carried, one per entry point, so a
sink several routes reach keeps every route; each carried block says on its second line that it was not re-judged, its source
  is named and checked, the ledger stays the record, and maturity now asks the one question the streak was for:
  has the union of findings stopped growing.
- **The start count names the section and the waves are rostered before dispatch because the same two slips recurred
  under rules that already forbade them**: six runs counted the whole memory file where the rule said the ledger, and
  two runs started sixteen and eighteen workers under a cap of fifteen. A count that names its boundaries and a list
  written before the pressure of dispatch leave less to decide at the moment the slip happens.
- **The contract check demands the caller-enumeration paragraph verbatim, and the recheck counts `not re-found`
  marks, because a contract that summarised the procedure produced a report missing ninety-three of the previous
  run's sinks and a memory write that marked none of them**: the two forms the check asked for were present, the
  procedure between them was a clause, and the misses left no trace in the ledger.
- **The gate counts `Reference:` lines because five records without one became five composed classes**: the writer
  takes the class from the record's reference file, so a record that names none gives it nothing to take, and the
  class rule that held for five runs was broken by one worker's omission rather than by a writer's choice.
- **The join line is append-corrected and the gate counts absolute paths because a repair rewrote a join from
  sixty-six to fifty-nine in place and fifteen absolute sinks passed a path test that only asked whether they exist**:
  a line that can be replaced records whatever its last editor needed, and a path that exists is not yet a key.
- **Voided cells need an identifier because a repair voided twenty-seven carried verdicts with one sentence**: the
  verdict-specificity rule covered downgrades and disputes, so the one cell form it did not cover became the way out,
  and a run at an unchanged commit reported twenty-seven judgements that changed for a reason no record holds.
- **A carried verdict ignores `adv=` and sinks compare target-relative because a join listed sixty-six rows of which
  twenty-seven read `not run` and fifteen cited absolute paths**: a copied verdict is not a Step 6 run, so scope cannot
  skip it, and a key written absolute is a key no ledger row and no earlier report can meet.
- **The continuity join names its rows because a writer wrote `continuity join: 54` and filled twenty-nine cells**:
  a count is a promise; a list of ids is a worklist the recheck can walk row by row, and a named row found bare has one
  owner.
- **A wave is the first fifteen undispatched pairs across lens boundaries because an orchestrator kept a lens whole**
  and started sixteen: the cap is a concurrency limit on the account, not a grouping of lenses, and a lens split
  between two waves costs nothing.
- **The worker-record id form is stated and the shipped recheck reads a table row by its shape, because one writer
  numbered rows `<lens>-p<n>/<n>`** and a reader that knew rows by the earlier `<lens>/p<n>/VULN-<id>` form saw an
  empty table: six items then disagreed with a report that was right. A row is seven cells whose fifth is a
  disposition word; the id form matters for cross-reference, not for recognition.
- **The recheck runs when the writing subagent has returned, never between its passes, because one set measured a
  thirteen-block skeleton** the writer was still filling and recorded seven mismatches that described nothing but the
  moment; a set taken on a draft is noise that a repair could be dispatched on.
- **The recheck derives the maturity streak, checks the join line and the sentinel, because one report declared
  `streak 1` over a body that had moved from 268 to 261 blocks, wrote `continuity join: 0` against 35 previously
  downgraded sinks, and ended without its sentinel while every counted item passed.** A maturity line that is
  asserted is the one line the reader acts on; a join line that is asserted makes continuity a repair again; a report
  without its last line is unfinished by the skill's own definition. All three are now numbers the script computes.
- **The shipped recheck reads a corrected row's corrected value, matches a correction-appended line to its original,
  and counts a record whose heading opens with a confidence tag**, because its first run flagged three things the
  rules had already accepted: a start count corrected by the append rule, the same append read as a removed STEP 1
  row, and two worker records headed `[LIKELY]` instead of a severity that the table had counted. A recheck that
  disputes its own rules sends a correct report to a repair that cannot fix a worker file; the headings without a
  severity are now reported beside the file-record count instead.
