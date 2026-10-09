---
name: llm-sast-scanner-full-scan-loop
description: >
  Exhaustive partitioned security audit of a repository. Invoke explicitly as
  "llm-sast-scanner-full-scan-loop <dir> [adv=critical,high,medium] [new-scan]" where <dir> is the target
  repository/directory path; if <dir> is omitted it defaults to the current working directory.
metadata:
  version: "2.26.12"
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
in a response. D1's `architecture-threat-model.md` is written anew whenever the previous plan's `wrapper:` row differs
from this run's, or the previous plan holds none, whatever D1's SHA gate allows: its entry points, stack and
allowlist were read under rules this version changed. Then split the in-scope files into 3 partitions balanced by ATTACK SURFACE, not by line count
alone. The manifest holds only what D1 leaves in scope: generated output derived from in-scope source — ORM
snapshots and journals, build and bundle output, generated route trees — is excluded in `scope-excluded.txt`
with its reason, never classified or partitioned, and so are the orchestrating runtime's own run logs and exported
transcripts in the repository: they are records of a scan, not code under review, and a route string inside one is
not an entry point. Classify every remaining row as `source` (application,
infrastructure, CI and build code), `test` (test, fixture, mock and end-to-end trees) or `text` (documentation,
package manifests, lockfiles, editor and agent configuration). Count entry points per directory with STEP 2's entry-point
definition — every registration of every kind that a caller can invoke: an operation (query, mutation,
subscription, field resolver), a route or handler, a message consumer, a scheduled job, a command — plain HTTP routes
included; a direct call of a triggered function through its platform's invoke API is none (base skill, finding
identity), and each triggered handler is read for a branch that, when the trigger's records are absent, goes on to
process the event, that branch listed at its line, kind `direct-invocation branch`; a class, module, schema or
container that only groups such registrations is not an entry point however it
is registered, so two sessions deriving the list from one commit derive the same count — attributed to the directory
of the file that registers it. This count balances the cut and nothing else; the list is derived from the code at this
run's commit, never copied from an earlier plan, threat model or helper script, each made under the rules its skill version held. The
registrations themselves are written
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
class that failed, by the quantity that failed, one level deeper and run the procedure again; never move a file by hand — units move only by the reassignment and move rules below — and never re-form units
that passed. The remedy repeats until the checks pass or the largest unit of the class that failed — by the quantity that
failed — is itself a single file; only then does no split remain, and the check is recorded in `scan-plan.md` as
`check failed: <check> — <file> holds <n> of <m> <source lines | entry points> (<share>%)`. The cut does not stand
as formed while a partition is over a cap: the remedy continues by reassignment — the deterministic assignment is
re-run with the over-cap partition's smallest whole units moved, in assignment order, to the partition with the
lowest share of the failed quantity, one unit at a time, until every partition is under its caps or no move leaves
every partition under them — and STEP 1 ends with one `checks:` line, written above `workers dispatched:`, `checks: pass — <the shares>` or, once remedy and reassignment leave no move,
`checks: failed — <each failure> | <the shares>`, which the report repeats. A line share outside the band is remedied the
same way — the largest unit by lines, of any class, split one level deeper while it is not a single file — and then by
moves, one at a time: the partition with the most lines that has a movable unit gives the partition with the fewest
the smallest movable unit whose move puts both inside the band, else its smallest movable unit, a unit being movable
when it has more than zero lines, is smaller than the difference between the two partitions' lines and puts the
receiving partition above neither 40% cap, of the source lines or of the entry points — ties to the lowest partition
number, then to the unit first in assignment order; each such move narrows the spread, so
the moves end — a moved unit's entry points moving with it, their list lines' partition column rewritten, until every
partition that no single file holds above the band is within it or no unit is movable; the manifests and unit lines are
rewritten to the cut that results. A line share writes no `check failed:` line of its own, and `--checks` prints a
`remedy:` line under its `checks:` line whenever a line share has no `(one file: …)` and no file by itself holds more
than about 43% of the lines (100% less twice the band's floor, which leaves the other two no room) — it never reads
units, so the split and the moves decide whether the cut can still be balanced — and that line is never copied into the
plan. One
first run's cut left a partition at 41% of the lines, a lockfile a fifth of the manifest, and recorded its own
`check failed:` over it instead of moving the small units that would have passed.
The line is the output of `python3 <this skill's directory>/recheck.py --checks`, run from the target once the entry list
and the partition manifests are written — the one computation recheck item (19) repeats — copied verbatim, never
composed from this session's own arithmetic: while the command prints `failed` for a share, the remedy and the
reassignment continue, except for a failure that ends `(one file: <path> holds <n> of <m> entry points)` or
`(one file: <path> holds <n> of <m> lines)` — a file is never split, so no move can fix it; a line share without it is
written, once no split and no move remains, as the command prints it, and item (19) reads it as a mismatch even then — the
run's record that its cut could not be balanced; the line is written as the command prints it. It counts each entry in the partition whose manifest holds the entry's file and fails a list
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
reads the same) — or `previous run residual: none` when no earlier plan existed. When the copy has no `recheck: mismatches` line at all — the previous run ended before its recheck set (stopped, killed or crashed) and so resolved nothing — its own `previous run residual:` row is copied forward unchanged as this plan's row; a copy with neither that line nor that row — a plan an earlier version of this skill wrote, no `started:` or `workers dispatched:` row in it either — gives `previous run residual: none`. This run's `scan-plan.md` is then written
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
`started:` row's value — and the `ledger rows at start:` row, left out of the plan's first write and added among these
rows before `workers dispatched:` is written, is the whole line
`python3 <this skill's directory>/recheck.py --ledger-start` prints, run from the target once this run's `scan-plan.md`
holds its `started:` row and the copy is made, copied verbatim and never composed — the command refuses a plan that
holds a `workers dispatched:` line (the previous run's plan still in place, whose copy is that run's ledger, or this
run's past STEP 1, whose row is corrected by appending the count recheck item (16) names), and it refuses a copy holding
a different number of ledger rows from `project-memory.md`, since nothing before the dispatch adds a ledger row to the
memory (a first run's template holds none): the command counts, in the copy the `started:` row names and no other, the lines between the `## Confirmed findings ledger` heading and the next `## `
heading that match the ledger row pattern of STEP 3's recheck item (6), the same measure as `ledger rows after`, and no
line outside that section — the false-positive section's rows share the shape, six runs in a row counted the whole file
and corrected the row afterwards, and one session counted the previous run's copy and wrote its 363 over a ledger of
448; `0`, over an empty copy, when the file is absent or empty. An existing `project-memory.md` is the ledger every later run builds on: STEP 1
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
holds the base skill's severity table — the same five counts and their total — and, after its Total row,
`| Unverifiable | <u> | n/a | n/a |`, `u` the entries of the Unverifiable section, which Total does not count — each
entry's line opens with its id, after any `#` marks and its `[UNVERIFIABLE]` tag, then ` — ` and its title
(`### [UNVERIFIABLE] UNV-001 — <title>`), and its `needs context:` lines are no entries. The sentences after the table
name each Unverifiable entry by its id and title (`UNV-001 — <title>`; a range such as `UNV-001–UNV-010` names only its
two ends), so the start of the report shows what could not be decided beside what was found (a non-convergence
warning, when D3 requires one, still comes first).

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
> through Source→Sink and the Judge as its own candidate — and where your trace shows a sink's recorded finding does
> not hold, because a named guard, type fact or deployment fact defeats it, write for that sink one line
> `ledger refuted: <class> | <sink file:line> — <that guard, function or file:line>`
> with the ledger row's own class and sink, never a finding or a clearance in its place — and write the line
> `new entry points: <count>` (`0` is a valid count); write `ledger empty` when there was no ledger. Before the final line, check your own file as the gate
> will: its first line is the `procedure:` line above; it holds `ledger empty` on an empty ledger and `new entry points:
> <count>` on a populated one; each `ledger refuted:` line reads
> `ledger refuted: <class> | <sink file:line> — <the guard>`
> with a ledger row's class and sink as the ledger holds them — STEP 3 reads no other form; every record
> opens with a severity token — `[CRITICAL]`, `[HIGH]`, `[MEDIUM]`, `[LOW]` or `[INFO]` — before its `VULN-` id, carries a
> `Reference:` line naming a file of the base skill's `references/` directory, and cites in its `File:` line a path
> that exists under the target — its `:line` dropped, each tested with `test -f <path>` from the target directory, never
> recalled. A record
> that fails is corrected before the sentinel: the gate re-runs the whole worker for one wrong path, and one worker once
> cited its sink under the wrong module directory. No line of your file outside a fenced code block is longer than
> 2000 bytes (UTF-8 — an em dash counts three): a file reader keeps only a longer line's first 2,000 bytes and the
> writer reads your file with one, so a record's field stays one line and is shortened — an `Also at:` list that would
> run longer continues on a further `Also at:` line right after it, no sink dropped — and any other text — an
> entry-point coverage or disposition list, a clearance, a pass log — is broken across lines between its items; the
> gate names each such line. The gate is a command you can run: from the target directory,
> `python3 <skills root>/llm-sast-scanner-full-scan-loop/recheck.py --gate <lens>/p<n>` prints your file's gate line —
> every field but the sentinel, which you have not written yet, must read `ok` or its full count — `absolute` and
> `entry pipes` are counts the writer handles and `digest` a value the gate compares, never a fail — `copied` below
> 80% or `n/a`, and `long lines` 0, before you write it.
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
`started:` — and no line of it longer than 2000 bytes (UTF-8, an em dash three): a file reader keeps a longer line's first
2,000 bytes and the worker reads only its start, so the prompt keeps the template's line breaks (one fresh run wrote every
prompt as a single line of 6,800 characters and re-ran thirteen workers). The file is
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
refusal or error, a crashed or stray file, a failed gate, an unfinished file, an `Also at:` overlap: a lens/partition pair has at most three
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
<c>%[ from <directory>] | digest <d> | long lines <n> | groups <q>/<g>` — its `copied` field `copied n/a` for a file too short to tell — where `m` is the file's record count, counted as its `File:` lines
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
the gate reads it (`unreadable` for a file the gate cannot read): a write to the file after its gate changes it. `n` is
the number of the file's lines longer than 2000 bytes (UTF-8) outside a fenced code block: a file reader keeps a longer
line's first 2,000 bytes, so the writer reads only its start, and `n` above 0 fails the gate and re-runs the worker —
worker files of 116 of 173 earlier runs held such lines, most of them entry-point coverage lists written as one
paragraph; `--gate <lens>/p<n>` names each such line on its error output, never in the gate line. `g` is the number
of the file's records whose `Also at:` line names a sink, a `path:line`, and `q` how many of them name on it no sink
that another record of the same file holds as its own `File:` sink at their class — the first base-skill reference
each `Reference:` names — and entry point, each `Entry point:` read as the list entry it names, as item (4) reads a
cell, a name several entries share read as the one of them whose whole name the line holds; a record naming no class
or no entry point — `unavailable` — is read on neither side. Such a line is
one finding filed twice, or a line that needs a fix of its own on a group's line, and the base skill's Deduplication &
Sink Location rule allows neither, so `q` below `g` fails the gate and re-runs the worker, `--gate <lens>/p<n>` naming
each such record and sink on its error output; a file with no group reads `groups 0/0`, which passes. The worker
keeps a record of its own and takes its line off the group's `Also at:` line; a record is deleted only when the
group's one check closes its line — every such line earlier runs held needed a fix of its own. A recorded line
written before a field existed has none and is read by the fields it has. A worker file with no `gate:` line, or whose line shows a `fail`, `k`
below `m`, `s` below `m`, `c` at 80 or above, `n` above 0, `q` below `g`, or sentinel values below their manifest counts, has not passed the gate, and STEP 3 does not start — unless its pair is recorded `worker not run:`, whose gate line is still written and still counted — a pair with no
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
  model-callable tool and function declarations, CLI commands and scheduled jobs. A triggered handler's
  `direct-invocation branch` (base skill, finding identity) is the one entry point that is no registration, counted
  for the partition cut and for no derivation row; a function's trigger, a function URL, an HTTP or API integration
  and an invoke grant to a principal outside the function's account or project count as registrations even where an
  infrastructure file declares them, the URL, integration and grant each for the cut and for no derivation row; a
  grant to a cloud service's own principal is part of the trigger that service is, and no entry point when no trigger
  of the function uses it. Nothing else is an entry point:
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

Once every worker file has passed the gate or its pair is recorded `worker not run:`, and before STEP 3,
`python3 <this skill's directory>/recheck.py --overlaps` is run from the target — a run that prints
`overlaps: error` is run again with `--skills <skills root>`. It reads the worker files against each other as the
gate's `groups` field reads one: one `overlap:` line for each sink of a record's `Also at:` line that another worker
file's record holds as its own `File:` sink at one class and entry point — two groups that each name the other's
sink print twice, and are read once — then `overlaps: <n>` and the grouping workers; it exits 1 when it lists any,
which is a list to read, not a failure. This session reads each listed pair's two records. Where the record holding
the sink needs a fix the group's one check at its one place does not supply — the base skill's Deduplication & Sink
Location rule: a decoder's depth or size limit, a wrong value passed, a decoder or serializer option, a missing
default or normalization two reads share, an escaping switch or a library upgrade, a guard at another place — even
where a broader remediation would also close it, the line does not belong on the group's `Also at:` line, and the
grouping record's worker is re-run, `(re-run: Also at names <lens>/p<n>/<VULN id>'s own sink <path>:<line>[, …])`.
Its prompt carries, on a line of its own after its first line, each such line and the record that holds it as
`<lens>/p<n>/<VULN id>` — never by its file, which the path test reads as an output path — and asks the worker to take
each line off its group's `Also at:` line, keeping a record of its own at that line where its own lens reaches it.
Where the group's one check closes that line too, nothing is re-run, and the writer merges the pair as a group
overlap. An overlap re-run is sent only while its pair has two attempts left, so a re-run that leaves a file short of
its gate still has one: the file the gate passed stands until the re-run writes its own, which is gated and capped as
any re-run's is — a pair whose last attempt ends short of its gate is recorded `worker not run:` as any is — and a refused overlap re-run is not tried again for this reason — the passed file stands and its
overlap goes to the writer. Once the re-runs are gated the command is run once more, with no second round of re-runs
for this reason, and its last line is copied into `scan-plan.md` verbatim, on a line of its own, rewritten in place
when a worker file changes before the writer's prompt is written — a change after it is the writer's or a repair's,
item (29)'s to name, and the line is left as it stands; `--prompt` reads it against the files before the writer
starts. A pair it still lists goes to the writer. Across files the overlap is most often two lenses grouping one
check, a merge; one run's access-auth worker put two decoder-depth sinks of the protocol-infra worker's records on its
schema group's line, the report could not render both, and that run re-ran the worker only after its first STEP 3
set, which this reading moves before the writer.

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
answer only after tracing. A sink whose recorded finding the trace shows does not hold — a named guard, type fact or
deployment fact defeats it — gets one line `ledger refuted: <class> | <sink file:line> — <that guard, function or
file:line>`, the ledger row's class and sink as the ledger holds them, on a line or list item of its own — a mention
inside a sentence (`considered … but rejected`, `e.g. …`) is read as prose. The line is a claim for STEP 3 to test, never a
verdict of its own: a confirmed finding outranks one worker's reading until Step 6 withdraws every block of it, as it
outranks a clearance.

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
a duplicate the writer judged under the **Duplicates** rule aside — its `duplicate candidate:` line `merged into` the kept row,
the lower worker severity merged and, across keys, the kept block's `Also:` line and the merged key no ledger row of the copy —
and a group overlap aside — one class and entry point, as each record's own `Entry point:` names it too, the merged
record's sink on the kept block's group line (the kept record's `Also at:` line and those of the records of its class
merged into it) — two groups that each name the other's sink either way — two workers' records of one missing check,
never merged the other way round —
each entry point cell read as the list entry it names — a cited `file:line` as the entry at it or up to three lines
below it in that file, a bare name as the one entry holding it, a name two entries share as written; (5) `config clearances rewritten` — the phrase search over the
worker files' disposition lines that hold a clearance word, cite no `file:line` and are no `ledger refuted:` line, a finding record's own lines (its `Judge:`, its `Impact:`) not among them, nor a phrase
inside an absence claim (`no … non-production endpoint surface`), shown as `(absence claims <a>)`; a report that counted
those too reads either count; (6) `ledger rows after` and `archived` — `ledger rows after` is the number of lines in `project-memory.md`'s
confirmed-findings ledger section matching `^[a-z][a-z0-9_]* \| [^|]+:[0-9]+(-[0-9]+)? \|` — a class may carry digits,
and a sink may be cited as a line or a line range — `archived` the same count over the archive
file, `duplicate-key rows` the number of those lines beyond the first for any one `class | file:line` key — a key's line
is the sink's first line, so a row written with a range (`Dockerfile:45-55`) duplicates the row `Dockerfile:45` — required to
be 0 after the write, `ledger rows before` the pre-write copy's row count, `duplicate-key rows merged` the copy's
duplicate-key rows (none may remain), `after` equal to `before − merged + new keys` less the copy keys that left the ledger
this run (archived now; at an unchanged commit only a key whose every block Step 6 withdrew leaves; a title-class row STEP X corrects onto a stem row is merged, not
gone, and counts in `merged`) — `archived` itself is the archive file's all-time count — and
`ledger present` the number of distinct body `File:` sinks whose `file:line` — by
its first line — appears in the ledger section, each by a command that states that pattern; (7)
`earlier reports` — each listed file present at its recorded size; (8) the close-out equations; (9) `header versions` — the report's `Analyzer:` line and the scan-plan's `wrapper:`
row naming each skill's version as its own frontmatter states it, never another skill's, and the report's `Base SHA:`
line, the first before its first `## ` heading, the scan-plan's `base-sha`, the sha alone; (10) `headings` — the
report's `## ` headings are the severity sections, the base skill's fixed sections and one `## Appendix`, in that
order and nothing else, so a working-notes, draft or duplicate section anywhere is a mismatch; (11) `maturity
worker records` — the maturity line's `worker records` value equals the table's rows minus its `carried` and `refuted` rows, and its
`vs` pair states the newest earlier report's close-out `table rows` and `body blocks`; (12) `new keys` — the
number of distinct `class | file:line` keys in `project-memory.md`'s ledger section that have no row in the run's
pre-write copy, keys compared by the sink's first line (a range twin of a copy row is not a new key), by a command that
reads both files and applies STEP X's class correction to the copy's keys; the
maturity line's `new keys`, the STEP X ledger equation and the
memory's new run line `new-confirmed` all equal it — row arithmetic is not this number, since rows merge and archive
while keys only appear — and no new key is a line only a finding's `Also at:` line names, `| rows written for `Also at:`
lines <n>` shown when not 0; (13) `required lines` — each of these opens a line in the report, counted `<k>/<k>`:
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
copy's rows under a class that is not a stem whose sink now stands in `project-memory.md` under a stem — or, for a key
Step 6 withdrew in every block, in the archive's `superseded` row — against the
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
the pre-write copy — read after STEP X's class correction — that holds neither a body record — at its `File:` sink, or, at its class, a line its record's `Also at:` line names — a carried row (or a line a carried block's `Also at:` line names) nor a `refuted` row this run still has its ledger row and its brief carries
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
class correction — without a row of any other disposition this run (a key a record's `Also at:` line names, at its class,
held by that record's row; a key the newest report names only on an `Also at:` line goes with that block, as the
One missing check's other lines paragraph reads it), a `refuted` row aside, hold in the newest earlier report holding a block of the key that is a source, less the key's `refuted` rows — a block citing a line past the end of a file of the target, or held by a report whose `Base SHA:` does not name the scan-plan's `base-sha`, being no source, and `sources citing past the end <p>` counting the past-end blocks of those keys passed over, from the newest report of this commit holding a key down to and including its source, or in all of them at this commit when it has none — `s` the count of such keys no earlier report holds in a block that is a source (recomputed from the reports), every carried row has its block, every block's `Carried:` line carries the row's
`last-verified` cell as the copy holds it and the scan-plan's `base-sha` and names the newest earlier report that holds a block with the same sink whose reference stem is the row's class, whose verdict honours the key's standing downgrade and that is a source, the block's
other lines match one of that report's blocks of the key word for word (heading id, `Worker record:` and `Carried:` lines
aside, whitespace collapsed) with no source block copied twice, and every carried row's ledger line is the copy's line
unchanged, its sink cell read by first line (a lone range row rewritten as `Dockerfile:45` with every other cell intact is the
same row) — or, for a key the copy held as range twins or under a title-form class STEP X corrected, the one row the merge
or correction left, its sha, `last-verified` and status cells one copy row's and its brief holding every copy row's brief
(a twin dropped with its brief is a loss even when the surviving row is byte-identical) — counted
`<rows> | blocks <k> | sources verified <v>/<k> | verbatim <w>/<k> | without source <s> | sources citing past the end <p> | expected <e> | ledger rows altered <a> |
rows without source altered <x>` with `a` and `x` required zero — a key without source keeping its row as the copy holds it, or the one row a range-twin merge or STEP X's class
correction left, `open`, every earlier mark kept and its brief gaining only this run's `not re-found <date>` — and the close-out's and the maturity line's `carried` values both equal to the rows; at a
changed commit the item reads `not applicable` and requires zero carried rows; (27) `summary table` — the Executive Summary's severity table, the first table there whose header opens `Severity` (a
warning's own table of uncovered partitions or lenses may precede it), holds one row each for Critical, High, Medium, Low, Informational and Total, each severity's number equal
to the records counted under that heading and to the histogram's line, Total their sum, counted per row as
`<table>=<body>=<histogram>` with `total <t> = <sum>`; a missing row or table reads `absent`; and its `Confirmed` and
`Likely` columns, found by their header names, split each row by the tag closing its records' headings — `[CONFIRMED]`
or `[LIKELY]` — Total's their sums, counted `confirmed/likely <row> <c>/<l>=<c>/<l>`, a table without the two columns
reading `columns absent` and a record whose heading carries neither tag failing the item; (28) `previous run residual` —
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
reads in its file now — its digest and the counts its text decides, never the header, pinning, resolving paths,
`copied` or `groups`, which follow the skills, the plan, the checkout and the earlier runs: `recorded gate lines off the file` counts
the files changed after their gate — before the writer's prompt was written, a STEP 2 line the writer names and leaves
standing; after it, a write by the writer or a repair, which read the worker files and never write them; (30) `report name` — the report name's timestamp at or after `started:` and no later than the file
it names, written or renamed, a later one being a time chosen rather than read; a `report:` row naming a file created
before `started:` names an earlier run's report, which is the user's and is never renamed; (31) `worker record ids` — the
identity check of the disposition table: every `worker record` id outside `promoted`, `carried` and `refuted` rows names a record
of the current worker files, every such record has a row under its own id — two records of one worker file under one id
take two rows, and the line names them — and no id is on more rows than records hold it; (32) `withdrawn lines` — every
`withdrawn` row has its appendix line `withdrawn: <worker record> — <Step 6 | citation>: <one line>`, no such line names a
row that is not withdrawn or gives a duplicate as its reason (a duplicate is `merged`), and every `unverifiable` row's
`UNV-<nnn>` stands in the Unverifiable section; (33) `promoted rows` — no `promoted` row stands at the entry point, sink
and class that a `withdrawn` or `unverifiable` row's worker record names in its own `Entry point:`, `File:` and
`Reference:` lines, since that finding is the record's own row, and none stands at the entry point, sink and class
of a `body` row — each entry point cell read as the `## Entry points` entry it names, an `unavailable` cell not
read — since that is the body row's finding counted twice; (34) `withdrawn cells` — a `withdrawn` or
`unverifiable` row's sink and class cells are its worker record's own `File:` and `Reference:`, so what was withdrawn
stays readable in the table; (35) `dispatch lines late` — the appendix's `dispatch lines late: <n>` equals the
first-attempt dispatch lines beneath each `wave <k>:` line timed at or after that wave's `complete` — a second line
for a wave already opened opening nothing — or, where every wave's start is read and the plan's layout and its start
times place a line in different waves, the same count taken by start times; the line's presence is item (13)'s; (36) `memory header` — the written memory holds, above its `## Confirmed findings ledger`
heading, `scanner-version:`, `last-scanned-sha:` equal to the scan-plan's `base-sha`, `last-updated:` a date from the
run's `started` to the memory's own write, and the hints notice; (37) `record cells` — every `body` and `merged` row's sink and class cells are its worker record's own — the first sink of its `File:` line, the same `path:line` read by
first line, and a stem its `Reference:` names; a record with no `path:line` there makes the row `unverifiable` — and, when the
record states an `Entry point:` line, its entry point cell names that entry point. The cell is written as the `## Entry
points` list writes it and the record in its own words, so the two meet when either holds the other, or when they share
a naming word (four letters or more, no generic or report word, a file path read by its file name), the cell's
`file:line` or a name of twelve letters or more; a naming word or `file:line` other than the sink's also counts from the
record's `Flow:` line or a line of its worker file that names its id; a cell of generic words alone needs at least half
of them in the `Entry point:` line; and a cell that copies the row's sink cell (unless the record's entry point is that
line), or whose only words are the report's own — `worker entry point`, `see VULN-…`, `—` — names none. A record with no `Entry point:` line
leaves the writer the list's entry or `unavailable`, and its cell is not read — and each body block's `File:` and `Reference:` are that record's, so a merge is read
from what the workers wrote; a record whose own sink lies past the end of its file makes its row `withdrawn` as (46)
reads it, never copied into the row; (38) `verdict scope`
— every `body` row's verdict follows its worker record's severity, the one Step 6 saw — for a block holding group
overlaps, the highest among its record and the records merged into it as group overlaps: a Step 6 verdict when it is in
`adv=`, `not run` when it is outside, a verdict the continuity join carries excepted; a block rendered below its
record's severity — a group block's, its highest line — carries the `DOWNGRADED` or `DISPUTED` verdict that lowered it; `merged`, `withdrawn` and
`unverifiable` rows read `n/a`; (39) `section placement` — every record stands under the heading of its own severity
tag, and none outside the five severity sections and the Unverifiable section; (40) `block layout` — every body and
promoted block reads the one layout below: its `Worker record:` and `Entry point:` lines its row's, its Evidence a
fenced code block, no other line between its fields, and its `Adversarial:` line the row's cell followed by the
rationale, three words at least — and a body block's `Also at:` line naming the sinks its record's names, `| Also at not
the record's <n>` shown when not 0; (41) `appendix table` — the appendix holds every row of `disposition-table.md` as the
file holds it; (42) `scope exclusions` — the appendix reproduces every row of `scope-excluded.txt`, and
`excluded: <p> paths / <l> lines` has `p` its row count and `l` the lines of the regular files it names, counted from
them; (43) `class clearances` — `class clearances <n>` is the number of lines across the worker files that hold
`SAFE in p<n> — no <surface>`; (44) `pass log` — one entry per pair, its passes the worker file's sentinel `passes=`;
(45) `routed hand-offs` — `handoff-table.md` exists and `routed: <n>` counts its rows; (46) `citations` — every `file:line`
a body, promoted or carried block cites on its `File:`, `Flow:` or `Also at:` line in a file of the target lies within that file,
`checked <c> in <b> blocks | past the end of their file <k>`, `k` required `0`, each block read to its next `#`, `##` or `###` heading and outside fenced code, a file's lines counted as `grep -c ''` counts them: a worker's record whose `File:` sink lies past
the end fails the base skill's Citation & Evidence Verification and is `withdrawn` with a `citation:` line, never
re-cited, since (37) reads the sink against the record, and every `merged` row whose own sink is that sink and whose
body record is that VULN id is withdrawn the same way, while one merged into it from another sink becomes a `body` row
of its own, and a `duplicate candidate:` line naming a withdrawn row goes — a body block whose sink is not its record's is rendered from the record instead, unless the
record's sink lies past the end too, and a promoted row's block, rendered from the record the same way, goes with its
row when the record is withdrawn or has none, one `withdrawn` row per record; a `Flow:` hop, another citation on a `File:` line or a sink's range end past the end is corrected from the source, as that verification
requires, or the record withdrawn the same way; and a carried block citing past the end is (26)'s — its key carried
from its source, or counted without one; (47) `refutations` — at an unchanged commit, the worker files' `ledger refuted:`
lines, outside fenced code, whose class and sink name an `open` key of the copy that no row of another disposition
holds — at its `File:` sink or on its record's `Also at:` line — each such key accounted for once, every source block of it either a `refuted` row or a carried row: all
`refuted`, the key gone from the ledger, its row in the archive with status `superseded` and a false-positive pattern
row at its class and sink; some, its ledger row kept; none, carried as (26) reads it; or, with no source block, neither
— and the appendix's one `refuted:` line for it naming that outcome, no `refuted` row or `refuted:` line at any other
key, and `refutations: <n>` counting the keys, `<n> | withdrawn <w> | partly withdrawn <q> | stands <s> | no source <x> |
refuted rows <r> | unaccounted <u>`, `u` required `0`, the line's `n of m` and `carried as` ids those of the key's rows;
a worker's line the checker cannot read, or one naming no row of the copy, is shown on the item's line — `worker lines
unread <n> | naming no ledger row <o>` — and is no mismatch, its key read as one no line names; at a changed commit the
item reads `not applicable` and requires zero `refuted` rows; (48) `duplicates` — every pair `--duplicates` lists, computed
from the table's `body` and `merged` rows and the plan's `## Entry points` list, has one `duplicate candidate:` line whose
answer the table bears out — `merged into` the kept block's VULN id with each row of the pair that row or merged into it,
`distinct: <clause>` with neither merged into the other nor both held by kept blocks whose own pair reads `linked`, `linked` for two `body` rows at two keys whose record to merge
away holds a ledger key of the copy and whose blocks name each other on `Also:` lines, a row merged into such a block
read as that block and the kept blocks' own pair, when listed, answered `linked` too — a line on a pair the table
answers agreeing with it, and `duplicate candidates: <n>` counting the lines, `pairs <p> (entry <e> | same <s> | near
<x>) | answered merged <m> | distinct <d> | linked <l> | unanswered <u> | lines at no pair <z> | pairs the table answers
<t> | repeated clauses <r>`, `u`, `z` and `r` required `0` — `r` counting the `distinct` clauses that each answer three or
more pairs of two or more class pairs over two or more groups of the records those pairs join; nothing is merged by the
item, so a pair answered with its own `distinct` clause stands; (49) `needs context` — every line `--needs-context` lists, a line of a worker file
outside its finding records that names a NEEDS CONTEXT judgement — the words NEEDS CONTEXT, `Unverifiable candidate`
or UNVERIFIABLE in capitals — or heads one of the worker's own `[UNVERIFIABLE]` records, has one `needs context:` line in the Unverifiable section answering it in one of its three forms, `lines <n> |
answered observation <o> | carried <c> | mention <m> | unanswered <u> | lines at no marker <z> | answers in no form <f> |
repeated mentions <r>`, `u`, `z`, `f` and `r` required `0` — an observation's cite first, a file of the target outside the
scanner's own cache and reports and a line within it, two words or more after it; a `carried by` id one the report
gives a candidate — a body block's or record heading's id, a `body record` cell, the id opening an Unverifiable entry
line — and every id after a `carried by` anywhere in the answer the same, an id read by its prefix, one the report's ids
use, so a weakness or hash name beside it is the text's; a cite before `carried by` or `mention:`, when one is written,
held as an observation's is, whatever separates them; on a line of several answers, each later one's file cite — a bare
`:<line>` read in the file cited before it — held so too; a `mention:` two words or more; and
`r` counting the `mention:`
texts naming no line key or id that each answer three or more lines of two or more worker files; (50) `unverifiable summary` —
the Executive Summary's severity table holds, after Total, an `Unverifiable` row counting the Unverifiable section's
entries, and the summary's sentences name each entry by its id and title (the id is what is read), `entries <n> | table
row <m> | named in the summary <k>/<n>[ | ids no entry line opens <j>]`, `m` and `k` required equal to `n` — with no entry
the row reads 0 or stands absent. `j`, shown when not 0, counts the `UNV-` ids that open no entry line — on the section's
lines that are neither entries nor `needs context:` answers, and in `unverifiable` rows' `body record` cells; with `j`
above 0 the item fails while the row stands absent or counts more than `n`; (51) `merge severity` — every `merged`
row whose kept `body` block stands: the block's severity is at least its merged record's, less the one level a
`DOWNGRADED` or `DISPUTED` verdict on the block names, `merged records above their kept block <n> | unreadable <u> |
merged rows read <m>`, `n` required 0 — a merged record or block whose severity cannot be read is counted in `u`, not
judged; (52) `long lines` — no line of the report outside a fenced code block is longer than 2000 bytes (UTF-8), which a
file reader would cut: `<n> over 2000 bytes outside code blocks`, `n` required 0 — a block's field stays one line and
is shortened, an `Also at:` list continues on a further `Also at:` line with no sink dropped, a table row is shortened
cell by cell (a disposition-table row in `disposition-table.md`, then copied again and its block re-rendered), any other
line is broken between its sentences or items, and a carried block's lines, an earlier report's words, are not counted;
a fence left open counts as none; (53) `dispute clauses` — a block's `DISPUTED` clause that cites nothing but its own
sink (its `File:` path, with or without its line) or nothing at all and is, identifiers set aside, word for word the
clause of such blocks at two other sinks: `<n> boilerplate in <k> shapes (of <d> disputed)`, `n` required 0, a same-commit
carried block, an earlier report's words, not read; (54) `withdrawn guards` — every `withdrawn:` line whose reason is
Step 6's cites the `file:line` of the code it rests on — a line of a file the target holds, never the row's own sink: a
guard's for a guard that stops the attack, a dependency's at the line of its code that shows it, never a version
alone, and for another ground, such as operator self-harm, the line that shows it, the entry point the operator runs —
`<n> Step 6 withdrawals citing no file:line (of <s>)`, `n` required 0. Two lines are readings, not items: `recorded sets <n> | lone mismatches lines <k>`, a lone line being a subagent's own run appended to the plan, and
`recheck: repair none — …`, printed when every mismatch in the set reads a STEP 1 or STEP 2 line.

Before it starts the writer, the session writes the writer's prompt to `.llm-sast-scanner-cache/writer-prompt.md`,
runs `python3 <this skill's directory>/recheck.py --prompt .llm-sast-scanner-cache/writer-prompt.md` from the target,
corrects the file until the command prints `ok` — it requires no line longer than 2000 bytes (UTF-8), which a file
reader would cut, the Writer self-check paragraph below and, at an
unchanged commit whose pre-write copy holds ledger rows, the Same-commit carry paragraph, both verbatim, and for every
worker file one recorded `gate:` line that the file still reads — its digest and the counts its own text decides (its
sentinel, records, headings, absolute paths, references, entry pipes and long lines) — a file changed after it was gated having its
line rewritten in place from `--gate <lens>/p<n>` unless it changed after the writer's prompt was written, which is the
writer's or a repair's write, left as it stands for item (29) to name — none failing unless its pair is recorded
`worker not run:`, and no `gate:` line beyond them — a pair with no worker file has none, and a `gate: error` line is
replaced by the run it asks for — and the one `overlaps:` line STEP 2's `--overlaps` reading copied, its count what
the command counts in the worker files now, for a plan whose `wrapper:` row is this version or later — so the gate lines are in the plan, as many as the writer will count, as the gate command prints them, before the writer starts — and starts
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
cross-lens shared-primitive rule, the BURIED-SINK AUDIT, Adversarial Impact Validation, and citation verification — never of a carried block, which the
Same-commit carry reads. Run all of them. Whoever writes the report — this session or a consolidation subagent — reads
`scan-plan.md` first: the header's `Invocation:`, `Model:` and `Base SHA:` lines are copied from its
`invocation`, `model` and `base-sha` rows, never taken from the writer's own session — the next run's same-commit
carry reads `Base SHA:` to tell a report of its commit; `<target>` in the title is
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
files, in both directions, `promoted`, `carried` and `refuted` rows excepted — a promoted row's `worker record` cell
reads `promoted/<lens>/p<n>`, a carried or refuted row's `ledger`, and those are the id forms the check ignores; a table that fails is deleted and rebuilt, never patched, and recheck item (31)
repeats the check on the table as written. Here `worker record` is
`<lens>/p<n>/<the worker's own finding id>`, the id exactly as the record's heading states it: the record headed
`[MEDIUM] VULN-001` in `deep-access-auth-p2-results.md` is `access-auth/p2/VULN-001`, never an id composed from the lens
or the partition. A record is one row, and a record's own finding is always that row — `body`, or `merged` into the
`body` row with its entry point, sink and class — never a `promoted` row: a `promoted` row is a STEP X or buried-sink
promotion, or a finding at another entry point of a record that names several — a read trigger of a store a route or handler
writes, named beside that writer, is a hop of its Flow (base skill, finding identity), never a promoted row, the
grant-only writers' finding at that trigger excepted, and a direct call of a triggered function through its
platform's invoke API is no entry point (base skill, finding identity), never a promoted row: its caller is named in
the `Description:` of each finding the function's triggers open or hold as a hop. In this flow the `## Entry points` list fixes the entry points at
dispatch: a handler's `direct-invocation branch` the list holds is an entry point of its own — when no worker filed
its finding there, a promoted row of the record whose `Entry point:` is the direct call — and one STEP 1 did not list
is named in the `Description:` of each finding the function's triggers open or hold as a hop this run, for the next
run's STEP 1 to list. Every cell holds
exactly one of these: a worker record id, an entry
point (route, handler, tool or consumer name), a `path:line` sink, a class name, a disposition word, a verdict as
defined below, or a VULN id;
a cell holding anything else — a cross-reference, a placeholder, a blank, a description, a sink without its `:line`,
a disposition outside the four words below and the `promoted`, `carried` and `refuted` rows' own — is an **invalid cell**. An invalid cell is filled from the row's worker
record; when the worker record does not hold the value (a `File:` with no line number), the row's disposition
becomes `unverifiable` with that reason and its body block moves to the Unverifiable section.
`disposition` of a worker record's row is exactly one of these four (a `promoted`, a `carried` or a `refuted` row,
defined below, is not a worker record's and carries its own word):
- `body` — the record is a body record; `body record` holds the VULN id assigned to it here, in the table;
- `merged` — the record has the same entry point, the same sink `file:line` and the same class as a `body` row — each
  entry point read as the `## Entry points` entry it names, never by its wording, so `POST /x (a.ts:20)` and
  `a.ts:20 — HTTP route — POST /x` are one — or it is the same defect as a `body` row by the **Duplicates** rule below;
  `body record` holds that row's VULN id. A record whose entry point differs from every `body` row is never
  `merged`. A record whose `Entry point:` is a direct call of a triggered function, or a `direct-invocation branch`
  the list does not hold, names in its cell the entry point of the finding whose Flow holds the trigger it reads —
  else the first of the function's trigger entries, in list order, with a `body` row at its sink and class, else the
  first of them — and is one finding with that row, the next sentence choosing which record is the `body` row, or is
  the `body` row when there is none. Of two records that are one finding, the one of the higher worker severity is the `body` row and the other
  is `merged` into it — a group overlap aside (One missing check's other lines), merged into the block that holds the
  group's line, which then reads at its highest line — so a block never reads below a record merged into it, except by the one level a `DOWNGRADED` or
  `DISPUTED` verdict on the block names — recheck item (51);
- `withdrawn` — Step 6 returned WITHDRAWN, or Citation & Evidence Verification failed, and nothing else — a record that
  repeats a `body` row's entry point, sink and class is `merged`; `body record` holds the word
  `withdrawn`, and the appendix lists one line per such row, `withdrawn: <worker record> — <Step 6 | citation>: <one
  line>`, so the reason has a home outside the cells — a Step 6 one reads `withdrawn: <worker record> — Step 6:
  <guard file:line> <one line>`, the guard the one that stops the attack on every path and target of the attack (base
  skill, the note after Step 6's verdict table), never a guard named in prose alone;
- `unverifiable` — the record moved to the Unverifiable section, whose entries are numbered `UNV-<nnn>` in order;
  `body record` holds that id.

**Duplicates.** Two workers often report one finding: an added lens re-applies classes a base lens owns, and a worker
traces past its partition. `python3 .llm-sast-scanner-cache/recheck.py --duplicates`, run from the target once the
table is written, lists every pair of `body` and `merged` rows that may be one finding, each read from its worker
record's own `Entry point:` line — `entry`: one class and sink,
both records' entry points naming one list entry by `file:line` and by name, one finding by the identity rule; `same`: one
class and sink, entry points shown one — the same wording, list entry or unique route — or one of them `unavailable`,
a record that states no `Entry point:` line being `unavailable` unless its `Flow:` line or the lines naming its id hold
every route its cell names or meet the cell as item (37) reads a cell, and an `unavailable` entry point told apart
from none — and, at a line of a configuration or infrastructure file (a Dockerfile, Makefile or Jenkinsfile, any YAML
— CI, a deployment manifest, a Helm template —, Terraform or Bicep, build, server or environment config (INI, TOML,
`.conf`, `.properties`, `.env`, `.htaccess`, a Caddyfile or Procfile) or a template of one, a site's `index.html` shell
— no other page, since a filename cannot tell a static page from a template rendered once per route, and no
`index.html` under a template, view, layout, partial, include or `jinja2` directory — and no code file whatever its name),
any two unless the list resolves their entry points — by list entry or unique route — to entries with none in common, or
both cells name routes with none in common;
`near`: another class or sink line within five lines of one file, at
one entry point — or another class at one line of such a configuration or infrastructure file, unless the list resolves
their entry points to entries with none in common or both cells name routes with none in common — with each record's
worker severity and whether its own `class | file:line` key is a ledger row of the
pre-write copy. The writer judges every listed pair from its two records, and nothing is merged by rule. An `entry` pair
is one finding by the identity rule and is merged, unless its records show two entry points the list resolved to one —
then `distinct: <the two entry points>`. A `same` or `near` pair is one finding when both records name the same absent
check on the same data path from one entry point; two entry points, or one topic with two different checks, parameters
or guards, are two findings. A class difference is what makes a pair `near`, never what tells it apart, and a
`distinct` clause names what differs — the two entry points, or the two checks, parameters or guards — in its own pair:
one clause written for pairs of different classes names it in none — a group of records that pair with each other may
share one clause naming every difference — and recheck item (48) counts it. In a merge — a group overlap aside,
which is merged into the block that holds the group's line (One missing check's other lines) — the
record of the lower worker severity is `merged` into the other — on a tie the one holding a ledger key of the pre-write
copy is kept, then a `[CONFIRMED]` record over a `[LIKELY]` one, else the one `--duplicates` lists first — and the kept
block gains a last line after `Reference:`, `Also: <class> — <worker record> at <sink file:line>`, when the merged
record's class or sink differs, so neither class leaves the report, or when it names a fix the kept block lacks, with
` — <that fix>` after it. A record whose own key is a ledger row of the pre-write copy is never merged into another key —
merged, that row would read as not re-found; a group overlap's, which the kept block's `Also at:` line holds, aside — so when the record to be merged away holds one, both stay `body` and the
pair is `linked`: two findings in the counts, the price of keeping the ledger row, each block's last line after
`Reference:` naming the other on an `Also:` line. A pair one or both of whose records are merged into blocks `linked`
to each other — three or four records of one defect over two keys — reads `linked` too: the link its two kept blocks
hold, read between those kept records — the lower worker severity, the ledger key, the `Also:` lines naming each other —
with the kept records' own pair, when listed, answered `linked` as well; `merged into` and `distinct` are wrong there. The appendix answers every listed pair on one line,
`duplicate candidate: <worker record> / <worker record> — merged into <the kept block's VULN id>`,
`— distinct: <what differs>` or `— linked`, then `duplicate candidates: <n>`, the number of those lines; a pair the table already
answers — one key whose two rows name one entry point, one merged into the other, or two rows merged into one body row —
is not listed, and a line on it that agrees is no stray; a merge whose two records name two list entries is two findings
whatever their cells read. A wrong `merged into` folds a distinct finding into the kept one — its record and row stay,
its block and count do not — so a pair is merged only on the records' own evidence. A merge is made before the body, the histogram and the counts are taken, like every
merge. One run carried twenty-nine `entry` pairs as separate findings, the same defect at two severities.
`--duplicates` also prints a `merge severity:` line for every `merged` row whose worker record outranks its kept row's
— a same-key merge the table answers included, a group overlap not — and the writer turns each round before the body
is rendered: the higher record becomes the `body` row and the other is `merged` into it.

**Needs context.** A worker that cannot decide a candidate for want of a fact outside the repository writes NEEDS
CONTEXT in its clearances, or calls the candidate an `Unverifiable candidate` or UNVERIFIABLE, or writes its own
`[UNVERIFIABLE]` record, its tag before or after the heading's title,
where no table row carries it, and the base skill reports such a judgement under Unverifiable.
`python3 .llm-sast-scanner-cache/recheck.py --needs-context`, run from the target once the table is written and again
after the Unverifiable section is, lists every line of a worker file outside its finding records that names one —
`<lens>/p<n>:<line>`, the line as `grep -n` numbers it, a worker's `[UNVERIFIABLE]` record by its heading line alone, the
record running over the field lines under it (`File:`, `Blocked by:`, `Judge:` and the like) — its text, and the answer
the report holds. The writer reads each line where it stands and answers it on one line of the
Unverifiable section, after the section's entries and any prose, writing the section when the report has none:
`needs context: <lens>/p<n>:<line> — <path:line> — <what is missing>`, the cite first — the sink of the candidate the
line leaves undecided, as a record's `File:` would name it, its path from the target directory; a path the line omits,
as in `:217`, is read from the worker file's nearest full cite above it; a line that cites no sink is answered at the
sink the worker file or the code shows it judging, never the cite nearest its words, which was the sink in ten of
nineteen; a judgement about something the repository lacks cites the file and line whose content it judges — then two
words or more naming the fact outside the repository that would decide it; `— carried by <id>` in place of the missing
fact, the sink's cite before it or none, the id after `carried by` or a word or three later, when the report already
reports that candidate, the id the report gives it — the `body record` cell of its row, or the `UNV-<nnn>` that heads its
Unverifiable entry — never a worker record's own `VULN-` id, which names another finding of the report; or `— mention:
<what the line restates>`, likewise after the cite or without it, for a line that judges nothing itself — a pass-log, class-table or coverage line restating a
judgement — two words or more, naming the line key or id that answers the judgement it restates where one exists. Lines that judge one
candidate, of one worker or several, are answered alike, each on its own line; a line leaving two candidates undecided
answers both on its one line, `; ` between them, each in its form, every cite and id of it checked. An answer line is the report's note of that
judgement and takes no `UNV-` id and no table row. The answers are this run's: an earlier report's `needs context:` lines
are never copied, their keys naming lines of the earlier run's worker files. The Executive Summary counts the section's
entries in an `| Unverifiable | <u> | n/a | n/a |` row after its severity table's Total, and its sentences name each entry
by its id and title — recheck item (50). A judgement a reader of the report could act on is never a `mention:`:
one `mention:` text naming no line key or id that answers three or more lines of two or more worker files says what none
of them is, and recheck item (49) counts it; one missing fact may decide several sinks, each its own observation.

`verdict` is Step 6's result for the row, written into the table before any body block is rendered: `STANDING`,
`STANDING — downgrade voided: <named thing> is hop <n> of the Flow`, `DOWNGRADED — <trigger>: <the named thing the
attacker must hold>`, or
`DISPUTED — <the concrete thing the doubt is about, as the record cites it>: <the property in doubt>` (what in the code
leaves it unsettled is the block's rationale) for every `body` row whose worker record's severity — the severity
Step 6 saw, before any downgrade; for a block holding group overlaps the highest among its record and the records
merged into it as group overlaps, so Step 6 judges the block at its highest line — is in `adv=`, and every `promoted` row whose severity as promoted, before Step 6, is;
`not run` for a `body` row whose record's severity, read so, or a `promoted` row whose severity as promoted, is outside `adv=`,
so a record Step 6 disputed or downgraded below `adv=` keeps the verdict that lowered it; a `carried` row's cell is the copied block's `Adversarial:` verdict as it stands; a `refuted` row's is
`WITHDRAWN — <the guard its worker's line names>`; `n/a` for every other row. Any other content is an invalid cell, and so is a cell that is
specific in form but not in substance: every `DOWNGRADED` and `DISPUTED` cell contains at least one identifier in
backticks — a permission string, configuration key, function, type, route, role or VULN id — or a `file:line`, copied
verbatim from that row's own record (its File, Flow, Description or Evidence), or from a record merged into its block
as a group overlap; a cell with no backticked identifier and
no `file:line`, or whose identifiers appear in no line of the record, is an invalid cell whatever its prose says, and
`invalid cells <c>` counts exactly those cells. Identical text on two rows is valid only when each row's record holds
the identifier, and a `DISPUTED` clause that cites nothing but its own row's sink and is, identifiers set aside, word for
word the clause of rows at two other sinks is boilerplate, not a doubt — nor an invalid cell; recheck item (53) counts
it — and Step 6 re-judges a fresh one to the verdict the rest of Step 6 gives (`STANDING` with the open question in its
rationale where nothing else applies, `DOWNGRADED` for a trigger that holds, `DISPUTED` naming the property in doubt),
while a verdict the continuity join carried is voided as the continuity rule below gives — a `carried` row's block,
an earlier report's words, is not read; one doubt about the code at one
sink that several routes reach is one doubt, however many rows repeat it. Verdicts are written per finding, never per category, and they carry across runs, and continuity is
the first write into the verdict column, not a repair after the recheck: before Step 6 runs, the writer joins the
table's `body` and `promoted` rows on their sink `file:line` — backticks removed — and class with the body records of every report the
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
`not run (severity outside adv=)` under a join line that listed them as carrying. A copied downgrade still meets the
base skill's Downgrade validity check: Step 6 tests a carried `DOWNGRADED` cell's named thing against this run's
record, whatever `adv=` covers, and voids one that is a hop of the Flow, never a trigger, or one this run's record
shows does not hold; it voids a carried `DISPUTED` cell, whatever `adv=` covers, only on a ground the base skill bars (the grounds its note after
Step 6's verdict table lists: the non-default-configuration trigger's setting or a deprecated or `legacy` label, the
population of a store the repository does not show, that writers of content the code executes are trusted or their
authority not shown, a fact the repository does not show, or a doubt that names no property of what it cites but the
finding's exploitability or impact in general — and a question that reading the code or the shipped configs settles is
no doubt: Step 6 settles it and the answer decides), or as the restated-cell rule below voids one specific in form but not in substance. The void reads
`STANDING — previous downgrade voided: <clause>`, an identifier in the clause before any em dash within it (recheck
item (2)) — for a barred ground, the clause naming the store, grant or default `file:line` the record's `Description:` line names,
or, where it names none, the store's read `file:line` or the setting or label in backticks, and for a fact the
repository does not show, a doubt that names no property or a question the code settles, the record's sink
`file:line` or the `file:line` of the code that settles it — the row then rated as the base
skill's Downgrade validity check rates a voided record and counted under `voided`; where
the row's `Judge:` line names a trigger that holds, the cell reads `DOWNGRADED — <that trigger>: <named thing>`
instead, its block's rationale naming the voided ground, one level below and counted under `verdicts carried`. A voided cell is held to the same
identifier rule as a downgrade cell — `STANDING — previous downgrade voided: <clause>` names, in backticks or as
`file:line`, the thing from the row's own record that changed the judgement — and identical clause text across rows is
valid only when each row's record holds the identifier; recheck item (2) counts a voided cell without one as invalid,
because a repair once voided twenty-seven carried verdicts with one sentence that named nothing. Sinks are compared target-relative:
a `File:` line or sink cell written as an absolute path under the target is rewritten relative to it by the writer when
the table is built, because the ledger, the earlier reports and the join all speak in relative paths and fifteen
absolute ones once made fifteen keys that matched nothing. Step 6 may then replace such a cell only with
`STANDING — previous downgrade voided: <one clause naming what changed>`, or with a `DOWNGRADED` or `DISPUTED` cell as
the base skill's Downgrade validity check gives, its block's rationale naming the voided ground and, for `DISPUTED`,
its doubt besides, counted under `verdicts carried`, or with a cell the two rules below give; and where reading the
code or a shipped config settles a carried `DISPUTED` cell's question against the attack — a guard cited at its
`file:line` stopping it on every path and target of the attack — Step 6 withdraws the record in place of the void
above, as it withdraws any record: the row `withdrawn`, its verdict cell `n/a`, the guard's `file:line` on its
appendix line, and the join line corrected in its ` → corrected <n> — <ids>` form with that row's id dropped; a bare `STANDING` on such a row is an invalid
cell, and a run whose join line is missing rendered its verdicts without looking: one writer rendered thirty previously
downgraded sinks as bare `STANDING` and restored them only when the recheck named them. A carried `DOWNGRADED` or
`DISPUTED` cell that neither the Downgrade validity check nor the barred-ground test above voids, both tested first,
but whose clause fails the identifier rule — no backticked identifier or `file:line` this row's record holds ahead of
any em dash, an earlier report's clause written without one or citing a line the code has since moved — is restated,
never on a new ground: a `DOWNGRADED` cell keeps its trigger and named thing, cited as this record cites that same
thing — its moved `file:line`, or in backticks as the record words it; a `DISPUTED` cell keeps its doubt, citing ahead of it the
identifier this record holds for what the doubt concerns — the route, consumer, role, setting, store or line of the
Flow it is about (`DISPUTED — <file:line>: <the same doubt>`), the sink `file:line` only for a doubt about the code at
that line, as its `Evidence:` shows it. A restated cell is still a carried verdict, its row on the join line and counted under `verdicts
carried`. Where this record names the `DOWNGRADED` cell's named thing nowhere, or holds nothing the `DISPUTED` cell's
doubt concerns, the cell is specific in form but not in substance and is voided, never restated at a line it does not
concern: `STANDING — previous downgrade voided: <sink file:line>: <the named thing or doubt> is named nowhere in this
run's record`, the sink standing for the record that changed the judgement, counted under `voided` — or, where the
row's `Judge:` line names a trigger that holds, `DOWNGRADED — <that trigger>: <named thing>` as above, counted under
`verdicts carried`. A carried `DOWNGRADED` cell naming the non-default configuration that the rules above leave
standing, on a record already at `Low` or below without it once Step 6's voids are made, lowers it no level — the
base skill's Severity Downgrade Rule counts the configuration last — so it reads `DOWNGRADED` for a trigger other than
the configuration that holds and that the row's `Judge:` line or Step 6 names, counted under `verdicts carried`, and
otherwise `STANDING — previous downgrade voided: <the default's file:line its Description: names>: the configuration
lowers this record no further`, counted under `voided`: the configuration still holds, but its level is gone.
Step 6 and citation verification update the `disposition` and `verdict` cells of this table — never a carried row's,
whose cells are its block's. The body is then
rendered from the table: one Finding Format record per `body` row, in severity order, carrying the row's VULN id.
Every block has one layout, so two runs' blocks diff line for line: the severity line, then
`Worker record: <worker record id>` — or, for a carried block, its `Carried:` line in that position — then `Entry point: <the row's entry point>`, then the base skill's fields in its
order — CWE, File, Description, Impact, Flow, Evidence as a fenced code block, Judge, Adversarial, Remediation,
Reference — with no other line between them; and the `Adversarial:` line opens with the row's `verdict` cell —
the verdict word, and for a downgrade its trigger and named thing, for a voided downgrade its hop — followed by ` — `
and the base skill's one-sentence rationale, which is never omitted; a `not run` row's line reads
`Adversarial: not run (severity outside adv=)`. A block whose opening differs from its row's cell, or whose line ends
at the cell with no rationale, is an invalid block. Every field line outside a carried block (copied as its source holds
it), like every other line of the report outside a fenced code block, stays within 2000 bytes (UTF-8), which a file
reader keeps whole: a field that would run longer is
shortened, never wrapped, and an `Also at:` list that would run longer continues on a further `Also at:` line right
after it, no sink dropped — recheck item (52). The table is the only source of
verdicts: a re-rendering of the body for any reason — a repair, a completion pass, a second writer — copies them
from the table and never re-adjudicates, defaults or omits one. Body records that STEP X or the BURIED-SINK AUDIT promoted from a
clearance or a note are `promoted` rows under the table, each naming its source lens/partition, and are rendered
the same way. **Same-commit carry.** When the scan-plan's `base-sha` is not `unknown` and equals the commit the pre-write copy was
last written at — its header's `last-scanned-sha`, above its ledger heading, or, for a copy that holds ledger rows under no
such line, the sha of its newest `run <sha> <date>:` line under Coverage / depth notes, the latest date and of lines
sharing it the last — nothing in the code has changed since the ledger was last judged, so a finding judged then is a finding now: every
ledger row of the copy whose status is `open` and whose `class | file:line` key holds no row of any other disposition
this run — a key a worker reached and the writer dispositioned, as `body`, `merged`, `withdrawn` or `unverifiable`,
or that STEP X promoted, was judged this run and is not carried — a key whose blocks Step 6 withdrew on a worker's
`ledger refuted:` line is read below — is carried from the newest earlier report — among those the
scan-plan's `earlier-reports:` row lists, never a stray file in the directory, and only a report written at this commit,
its header's `Base SHA:` naming the scan-plan's `base-sha` in full or by seven or more leading digits (a report of
another commit judged other code, so its blocks are no source) — that holds a block with the same
target-relative `File:` sink and class whose verdict honours the sink and class's standing downgrade (repeats it, or voids it
in the named-hop form) — a block at that key reading bare `STANDING` under a standing downgrade is passed over for the newest report whose block
honours it,
and a block whose `File:` or `Flow:` line cites a line past the end of a file of the target — its lines counted as
`grep -c ''` counts them, a last line without a newline counting, never `wc -l` — is no source: that line does not
exist at this commit, so the block cannot have been verified where it points, and it is left out — neither
carried nor re-cited, nor its key re-keyed to a sink a worker reached, since correcting it would judge the finding anew,
which only a worker does. The downgrade and line-count tests are block by block: the key's source is the newest listed report holding a block
of the key that is a source, its blocks that are sources are carried and its others left out, and the base skill's Citation & Evidence Verification,
by its exception for a `carried` record, does not re-open a carried block — it was verified when judged, its label says it is not re-judged, its source's
commit and the line count are the checks it meets, and it is never re-cited. A sink's line is its first line on either side, so
`Dockerfile:45-55` and `Dockerfile:45` name one sink; a block's class is the stem of its `Reference:` file, never the
words of its heading, which older reports wrote as titles: every block of that key in the key's source report that is a source — several when several entry points reach the sink, each a finding of its own under the base skill's identity rule — becomes one
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
the date of the judgement it carries. A row whose key no earlier report holds as a block — or holds only in blocks that are no source — cannot be carried: such
rows are counted in the appendix as `carried without source: <s>` — rows, not blocks — and each brief gains `not re-found <date>` as before, the row otherwise as the copy holds it — or the one row a
range-twin merge or STEP X's class correction left, as for a carried key — every earlier mark kept and its status `open`.
A key that a worker's `ledger refuted:` line names — an `open` key of the copy that no row of another disposition holds
this run, the line's class and sink read as the copy's keys are — is tested before it is carried, within the run's one
Step 6 pass and whatever the block's severity or `adv=`: Step 6 is run on each of its source blocks with one question,
whether the guard the line names defeats it — the guards of several workers' lines joined with `; ` — and each block it
withdraws is not carried but gives one `refuted` row (worker record cell as a carried row's, entry point from the block,
sink and class the key, verdict `WITHDRAWN — <the guard>`, body record `refuted`) and no body block, since each block is
a finding of its own entry point; the blocks it does not withdraw are carried as above, each as its source has it. Any
result but WITHDRAWN leaves a block not withdrawn, and a carried block keeps its `Carried:` label: the Judge did not
re-judge it. When every block is withdrawn the key's ledger row — as STEP X's class correction left it, a ` was <old
class>` trail kept and counted in `rekeyed to stem` — takes the status `superseded` and moves to the archive, and the
false-positive patterns gain the row `<class> | <sink> | <the guard> | <base-sha>`; when only some are, the ledger row
stands as the copy holds it and no false-positive pattern row is written, since an entry point still reaches the sink. A refuted key with no source block cannot be
tested and stays a row without source. The appendix states one line per such key,
`refuted: <class> | <sink> — <lens>/p<n>[, <lens>/p<n>…]: <the guard> — withdrawn`, or
`— partly withdrawn: <n> of <m> blocks, carried as <VULN ids>`, or `— stands, carried as <VULN ids>`, or
`— no source, not tested`, then `refutations: <count>` counting those keys. A `ledger refuted:` line at a key a row of
another disposition holds is moot — that row is this run's judgement — and has no line; at a changed commit no line is
tested: nothing is carried, and its key reads as any key no worker re-found. At a changed commit nothing is carried and every rule below reads as it did.
Workers are not told about the carry and behave as before: a sink they re-confirm is a `body` row with this run's
evidence, and only the sinks no worker re-confirmed are carried. At an unchanged commit the writer's prompt, and a
repair's, carries this **Same-commit carry** paragraph verbatim with the pre-write copy's path, the earlier reports'
file names and `base-sha`, so the carry is not lost to a summary. Two different things share the word: `verdicts
carried <n>` and the `continuity join:` line count previous verdicts joined onto this run's `body` rows at previously
downgraded sinks and never list a carried block; `carried` rows, blocks and the `carried <c>` counts are this same-commit
carry of un-judged ledger keys and never enter the join. The appendix reproduces `disposition-table.md` by copying the file, then states
`worker records: <n> | body: <b> | merged: <m> | withdrawn: <w> | unverifiable: <u> | promoted: <p> | carried: <c>`, with
`| refuted: <r>` after it when the table holds `refuted` rows — a `refuted` row is none of the four, whatever its verdict
cell reads — where
`b + m + w + u = n` and `b + p + c` equals the number of body records, and the close-out line
`close-out: table rows <t> | file records <f> | body rows <b> | promoted <p> | carried <c> | body blocks <k> | linked blocks <j> |
invalid cells <i>`, each number produced by counting — table rows, Judge-passed record ids across the current worker
files, `body` rows, `promoted` rows, `carried` rows, `### [SEVERITY] VULN-` headings in the
body, body blocks whose
`Worker record:` id has a `body` row with the same VULN id or whose `Carried:` line has a `carried` row with the same VULN
id, and cells of the table that are invalid under the cell
rule above. `k` equals `b + p + c`, `j` equals `b + c`, `i` equals `0` and `t` equals `f + p + c + r`, `r` the `refuted` rows — a table shorter than the worker files
has dropped records and is rebuilt; until they do, the report is not finished and
the sentinel is not written. Both lines are written in exactly that form — a paraphrase into prose, however
complete, is not the line — and a repair that touches the body or the table re-counts and re-writes both; a report
whose appendix lacks either line is unfinished whatever its last line says. The body holds Finding Format records
and nothing else: no worker-file section, clearance record, pass log or coverage block is copied between body blocks,
and a severity section that refers the reader to another file for its records holds zero blocks — blocks are counted,
never described. The Severity Histogram is counted from the body. A
worker record that is absent from the body without a `merged`, `withdrawn` or `unverifiable` row is a STEP 3
error, not a de-duplication.

**One missing check's other lines.** A worker record that collapses one missing check of one entry point — the base
skill's Deduplication & Sink Location rule — carries, right after `Reference:`, an `Also at: <path>:<line>, …` line naming
its other sink lines, one `<path>:<line>` each, never a range. Its body or promoted block keeps that line after
`Reference:` with the same sinks, and with the lines of each record of its class merged into it — a merged group's lines
travel on the kept block, or the next run would read them as missed — each line one the checker can read, a file of the
target: recheck item (40). Two records of one class and entry point whose groups overlap — one's `File:` sink on the
other's `Also at:` line — are one finding: `--duplicates` prints a `group overlap:` line for each, and the writer merges
one into the other before the body is rendered, a merge item (4) reads as one finding's; a block cannot leave its
record's `Also at:` line, so keeping both counts one defect twice (item (48)), and one run whose two lenses grouped one
schema check under two lead lines stopped on that mismatch. A line that needs a fix of its own comes off a group's
line before the writer starts — within one worker file the gate's `groups` field re-runs the worker, across files
STEP 2's `--overlaps` reading re-runs the grouping worker — and the writer merges each group overlap it meets into
the block that holds the group's line — the grouping record's own block, or the one it already stands in, never the
sink-holder's by merging the grouping record into it; two groups that each name the other's sink merge either way — whatever the two worker severities or the **Duplicates** rule's
order: the block reads at the highest severity among its lines, a downgrade standing only where its trigger holds
for every line it names, and a merged record whose own key is a ledger row of the pre-write copy stays held by the
block's `Also at:` line, so it is merged, never linked. The block's `File:` stays its own record's line, as item
(37) reads it, where the base skill's rule would name the most severe: the merged line keeps its severity on the
block and its key on the block's `Also at:` line. A group is read as its block holds it, its record's `Also at:`
line and those of the records of its class merged into it, as item (40) reads it. Where a merged record needs a fix
of its own — a line STEP 2 could not re-run off the group — the kept block names it on that record's own `Also:`
line, `Also: <class> — <worker record> at <sink file:line> — <that fix>`, as a merged duplicate's does. Its key is its `File:` sink alone: no ledger row is written for a line only an `Also at:`
line names — item (12). At its class, each such line is a key the record holds when the record is a finding this run (a
`body`, `merged` or `promoted` row's): a row of the pre-write copy at one of them is re-found by it — not carried, not
marked `not re-found`, its `last-verified` this run's — items (24), (26) and (47), whose `ledger refuted:` reading counts
it as that record's. A withdrawn or unverifiable record's lines are read as its `File:` key is. A carried block keeps its
`Also at:` line as its source holds it, and the lines it names are held by that carried row; a key the newest earlier
report at this commit names only on `Also at:` lines goes with the block that names it — carried with it when any such
block's own key is carried this run, whatever their order; else, or when that block's key is refuted, a key without
source — and no older per-line block is carried for it beside the group. A source block's `Also at:` cites count as its
`File:` cites do: one past the end of a file makes it no source, and item (46) reads them as it reads `File:`'s.

A prior report, the project-memory ledger, and a previous run's histogram are inputs to re-verify, never sources
of records or counts: a worker record that matches a ledger row is a body record of this run, and the ledger's
status is updated from it. Route families are entry points: two routes reaching one sink are two body records. A
`merged` row shares its entry point, its sink `file:line` and its class with the body row it points to; a row that
differs in any of the three is a `body` row, not a merge, whatever the writer's reason, save a duplicate the
**Duplicates** rule's judgement merges — one finding two lenses recorded under two classes or sink lines, its `Also:`
line naming the merged class — or a group overlap (One missing check's other lines), a fix of its own STEP 2 left on a
group's line named on an `Also:` line — de-duplication is between workers that recorded one finding, never between
findings.

The BURIED-SINK AUDIT is where false negatives hide, so treat it as mandatory rather than optional. Scan EVERY
lens file's notes, observations, tables, hardening-notes, "defense-in-depth", "not-reachable", and
dropped-not-FP items for any attacker-reachable sink that was demoted rather than reported. Promote each one
into the findings body at its class floor. A `ledger refuted:` line is not such a demotion: it names a finding the
ledger already holds, and the Same-commit carry tests it with Step 6 — the audit never promotes it.

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
Note, a Positive Pattern, a `safe-because` clause, never a `ledger refuted:` line, which Step 6 tests — whose text contains `disabled by default`, `enabled by default`,
`default configuration`, `environment-gated`, `non-production`, `only when the flag` or `unless configured` rests on
configuration and is not a clearance, unless the same line also names, at its `file:line`, a code guard that holds
regardless of configuration — an authorization middleware, an ownership check, a validator: a guard named by name
alone, and the `file:line` of the setting the line rests on or of its default, exempt nothing. A flag or
setting listed beside such a cited guard is a guard list, not a clearance by configuration, and does not trigger; nor does a
phrase inside an absence claim — its clause opens `no`, `none of`, `neither` or `nor` and lists what the partition lacks
(`SAFE in p3 — no IaC resource-attribute … or vendor non-production endpoint surface in this partition`) — which names a
class found absent, not a configuration a clearance rests on; nor does a line citing a `file:line`, every one under a
path the base skill's Scope skips — tests, fixtures, mocks, `__tests__`, examples, demos, samples, seeds — which names
code no deployment runs.
The base skill's Severity Downgrade Rule makes a non-default configuration a downgrade
trigger, so the negative-verdict re-derivation rewrites each such line's sink as a body record at its class severity,
its `Description:` line naming the setting and each `file:line` that sets its default — in the code and in every
deployment config the repository ships that sets it — and Step 6 tests that trigger as on any record in `adv=`: where
the finding needs a configuration the code and every deployment config the repository ships show is not the default,
and the trigger lowers the record — one level, after its other triggers, never below `Low`, as the base skill's
Severity Downgrade Rule counts it — Step 6 downgrades it naming that configuration on its `Adversarial:` line, and
otherwise rates it as Step 6 rates any record, the phrase its clearance used being no trigger; a record whose class
severity is outside `adv=` is `not run`, a verdict the continuity join carries excepted, and otherwise stays at it,
which under the default `adv=` is only a `Low` or `Informational` record, one the trigger never lowers. `config clearances rewritten: <k>` counts those of such lines that recheck
item (5)'s search finds — a clearance word on the line (`SAFE`, `clearance`, `cleared`, `not exploitable`, `not a
finding`, `no finding`, `dismiss`) and no `file:line`, a path with a file extension and a line; that search cannot tell
a guard's line from any other, so a line whose only `file:line` is no guard's — its setting's, its default's, its
sink's — is rewritten and listed all the same, outside `k` — and the appendix lists each rewritten line as
`<lens>/p<n>: <its text> → <body VULN id>`, one outside `k` marked `(cites <file:line>, outside k)`; a `0` while the search finds such lines is a STEP 3 error.

Then every line of the scan-plan's `## Entry points` list is looked up by name or `file:line` across the worker files. An entry
point named in no finding's `Entry point:` line, as no stored-content finding's read trigger (a finding whose Flow
reads the attacker's content back from a store — on its `Flow:` line or named in its `Description:`), and in no
Clearance Record was read but never analyzed — a worker
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
carried into the body under the same-commit carry of STEP 3, or withdrawn there on a worker's `ledger refuted:` line; only a row that could not be carried — no earlier report holds its block, or holds it only in blocks that are no source —
is a miss of this run: it stays `open`, its brief gains `not re-found <date>`, and its sink, when that line exists, is a
STEP Y hand-off to the owning lens. At a different commit a row becomes `fixed` only when `git diff <last-verified sha> <base-sha> --
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
it, the single-line row keeping its cells; this merge and the row of a key Step 6 withdrew in every block moving to the archive are the only ways a row count may fall at an unchanged commit. The appendix
states `ledger rows before <n> | after <m> | archived <k> | duplicate-key rows merged <d> | rekeyed to stem <r>`,
counted from the pre-write
copy, `project-memory.md` and its archive: `m` equals `n` minus `d` plus the new keys minus the rows this write moved
to the archive, `k` is the archive's row count after the write, `m` equals the number
of distinct keys after the write, the new keys are recheck item (12)'s key difference between the copy and the file,
and at an unchanged commit the only rows this write moves are those of keys whose every block Step 6 withdrew, as the
Same-commit carry paragraph reads it; a write that fails any of these is redone
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
  named in a finding's `Entry point:` line, as a stored-content finding's read trigger (on its `Flow:` line or named in its `Description:`), or in a Clearance Record — followed by one line per entry point named in none of them, `<file:line> | <name> | p<n> | unanalyzed` — possible only in a
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
  Then `new entry points: <count>`. State `ledger empty` if there was no ledger to trace against. At an unchanged
  commit whose workers wrote `ledger refuted:` lines at open keys no row of another disposition holds, the Same-commit carry's
  `refuted:` lines and `refutations: <count>` follow.
- Duplicate candidates (the **Duplicates** rule): one `duplicate candidate:` line per pair recheck item (48) lists, then
  `duplicate candidates: <count>`.
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
  unverifiable: <u> | promoted: <p> | carried: <c>` (then `| refuted: <r>` when the table holds `refuted` rows) with `b + m + w + u = n` and `b + p + c` equal to the body record count, and the
  close-out line `close-out: table rows <t> | file records <f> | body rows <b> | promoted <p> | carried <c> | body blocks <k> | linked blocks <j> |
  invalid cells <i>` with `k = b + p + c`, `j = b + c`, `t = f + p + c + r` — `r` the `refuted` rows, `0` in a run without
  them — and `i = 0`, then, at an unchanged commit,
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
  files of the base skill's Memory Protocol, the two `vs` pairs — `worker records` counted from the table's rows, `body` the
  body blocks, the close-out's `b + p` and the histogram total, never the `body` rows alone, because rows follow how a
  writer split multi-route records into promoted rows while blocks follow the findings — counted from this run's
  close-out and, for `<previous>`,
  read from the `close-out:` line of the newest earlier report — the last file of the scan-plan's `earlier-reports:`
  row — as its `table rows` and `body blocks` values (`n/a` only when that row reads `earlier-reports: 0`), and `worker
  records` for this run is the table's rows minus its `carried` and `refuted` rows. The streak is derived, never asserted: the previous run line's streak plus one when `f` is 0, `k` is at most 3 and the
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
  three of them across different entry points, where the run before merged 8 of 176. The **Duplicates** rule's merges
  across classes or sink lines keep that constraint's point — one entry point, the merged class named on the kept
  block — and each is judged on a line of its own.
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
  consistency can never hold still. Every source block of the newest report holding the key is carried, one per entry point, so a
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
- **A copied downgrade still meets the validity check because one run's Step 6 kept a downgrade that read the attacker's
  own provider account as a privileged position**: copied verbatim, that verdict would outlive every later worker that
  rates the finding at its class default; a copy keeps a judgement, not its errors.
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
- **A carried block citing a line past the end of its file is no source, and every citation is read against its file,
  because one carried finding cited line 533 of a 496-line file across six reports**: the sink was in a file of the same
  name one directory up, and at an unchanged commit the copy-byte-for-byte rule carried the error forward each run. The
  first run to notice rewrote the blocks and re-keyed the ledger row, which the carry rule forbids, and then patched and
  rechecked eight times with no rule that let it finish. A line that does not exist at the commit was never verified
  there, so the block is passed over like one that fails a standing downgrade, and item (46) finds such a citation in
  any block. A carried block citing a line that exists in the wrong file is beyond any count of lines: it is carried as
  it stands, labelled not re-judged, and never re-cited — Citation & Evidence Verification does not re-open a carried
  block, which is what let the writer and the carry rule disagree. A source is also a report of this commit: a
  changed-commit run leaves `open` a row whose sink's file did not change, and the next run at the new commit would
  otherwise carry it from a report of the old one, whose hops into files that did change were never checked at this one.
- **A worker's refutation of a ledger finding is a fixed `ledger refuted:` line that STEP 3 tests, because one run
  carried two findings labelled not re-judged while its worker had written that they no longer stood**: the note sat in
  a free-text caller-enumeration row, which nothing read. A confirmed finding outranks one worker's reading, as it
  outranks a clearance, so the line is a claim, and Step 6 — the step that already returns WITHDRAWN — decides it against
  the guard it names, block by block since each block is its own entry point's finding: a withdrawn block is a
  `refuted` row instead of a carried one, a key withdrawn in every block has its ledger row superseded, the rest are
  carried as before; the appendix says which, and item (47) holds every such key to one outcome. A line the checker cannot read is shown
  on item (47)'s line and its key carried as before: failing the worker's gate on it would cost a re-run and, past
  three attempts, an uncovered partition — more than the carry costs.
- **A block never reads below a record merged into it because 126 of 1,978 same-key merges in past reports kept the
  lower record**: a pair the table answers is listed to no one, so the record kept was whichever the writer took first —
  a HIGH injection record folded into a MEDIUM block read `STANDING`, others into LOW blocks outside `adv=` — and the
  report carried a severity no verdict had lowered while Step 6 never saw the higher one. Kept, the higher record meets
  Step 6, which may still lower it one level by a named trigger — a group overlap's block meets it at its highest line; item (51) reads every merge, and `--duplicates` names
  one before the body exists.
- **Duplicates are listed by the entry point a cell names, not its wording, and every pair is judged, because one run
  carried twenty-nine pairs of one finding as two**: an added lens re-applies a base lens's classes, so the same defect
  at one sink and entry point came from two workers worded `POST /items (items.ts:20)` and
  `items.ts:20 — HTTP route — POST /items`, and the writer compared the words. Nothing is merged by rule: a test by
  `file:line` merged `POST /import/commit (routes.ts:369)` into `preview` at `:353`, a nearby handler line, a GraphQL
  operation or a cell naming two routes each named the wrong registration, and three of one report's near-line pairs
  across classes were distinct defects. The writer reads the two records, keeps the higher severity, names the other
  class on the kept block, and never merges away a key the ledger holds — a group overlap, whose key the kept block's
  `Also at:` line holds, aside. A pair is read from each worker record's own
  `Entry point:` line, never a merged row's cell, which no item reads and a writer could make agree. A record with no
  `Entry point:` line is `unavailable` beside a record of its class and sink unless its own lines name the cell the
  writer filled: one first run's checker listed none of four such pairs — an unpinned base image and three supply-chain
  sinks, each reported by a base lens naming no entry point and an added lens naming one — two because one side was
  `unavailable` and two because the writer had filled the entry-less record's cell from the list with a command the
  record never named; the writer merged three of the pairs on its own reading and left the base image at two findings. A
  cited `file:line` is the list entry on that line before any within three lines of it: the same run's `manage.py:344`
  read as the registration at `:346`, two commands down. Listing every pair of one class and sink the list does not
  place apart was tried and withdrawn: over one target's six runs it multiplied the writers' pairs by as much as twelve
  and a half — 98 to 1,235 on one — and of a judged sample of the pairs it added about two in five were one finding, the
  rest two routes, operations or handlers reaching one shared sink; a `same` pair needs its entry points shown one, or
  one of them `unavailable`. The wider pairing stands at configuration and infrastructure lines alone: a config line is
  one statement and its entry point a deployment surface in prose, and there it listed, on one target's latest run,
  forty-three pairs of two lenses at one Dockerfile, CI job, manifest or server-config line and no pair at a code sink;
  on another it paired the unpinned test image two lenses reported at one Helm template line, which the rule above left
  two findings. Of sixty-four of its pairs judged from their records, over four targets, sixty-two were one finding and
  two were two checks at one Dockerfile `FROM` line, an unpinned tag and no `USER`, so each pair is still judged. Every
  page pair it listed on the runs judged was at a site's `index.html` shell, and no other page counts; an `index.html`
  under a template directory stays out: one run held one disclosure at such a served template twice, once for each of
  two servers' `GET /` routes that render it — one route to the list, so the routes rule could not keep them apart — and
  the pairing would have listed the two as one pair. A route a cell names ends at the sentence around it: on one run a
  cell ending `… that calls POST /x.` read as the route `/x.`, the two lenses' cells for one mutable job image named two
  routes with none in common, and the pair was never listed; a trailing `.`, `:`, `!` or quote is the sentence's,
  while a `?` stands as written — a route's own optional marker (`GET /:id?`) looks the same as a question's — and so
  does an ellipsis. Two lenses file one configuration defect under two classes as well: an unpinned base image reported
  as a container finding and as a supply-chain one at one `FROM` line was never listed, `near` needing one entry point.
  Listing another class at one configuration line unless the list places the entry points apart added ninety pairs over
  the saved runs of every target, and judged from their records, eighty-two were one defect under two names, five two
  checks at one line — a consent gate and a missing integrity check on one `<script>`, a missing policy and a missing
  frame guard — and three could not be read, so each such pair is still judged.
  A `distinct` clause is judged in its own pair: one writer answered all hundred and sixteen pairs the checker listed
  with one clause, `separate entry points, sink operations, classes, or guards`, merged none — a build secret two lenses
  reported at one Dockerfile line among them — and the recheck read 0; over the earlier runs' answers a clause repeated
  at most five times, always over one class pair, and one fresh run's clause answered eleven of its thirteen pairs over
  eight.
- **A NEEDS CONTEXT judgement in a worker's clearances is listed by the checker and answered by the writer, because
  one run's report left two such candidates out**: a worker that cannot decide a candidate without a fact outside the
  repository writes NEEDS CONTEXT in prose, and the writer's hand-off harvest brought five bullets of such judgements into
  the Unverifiable section and left out a message-chosen sender address one worker called an `Unverifiable candidate` and
  a secret carried in a URL query another judged NEEDS CONTEXT. Reading the sink out of the prose was measured and
  rejected: over sixty-four such passages of the earlier runs, thirty cite no `path:line`, and of nineteen whose cited
  line no report section held, the `path:line` nearest the words was the judgement's sink in ten, so the checker lists
  the lines — telling a line that names such a judgement is reliable where finding its sink is not — and the writer, who
  reads them, names the sink. The `mention:` answer is the escape, and is guarded like a `distinct` clause: one text
  naming no line or id over three or more lines of two or more workers. An observation names its sink, so it stands even
  when one missing fact — an edge's header policy, a sending identity's policy — decides several. Three simulated writers
  answering sixty-one such lines on three runs wrote no answer the checker refused, and each wrote `carried by` after the
  sink's cite, which 2.25.9 read as an observation and never tested: 2.25.10 reads the cite and then the id, any id the
  report gives a candidate — a body record, a heading's, an Unverifiable entry's — as older reports number them too. A
  fourth review found what 2.25.10 still let pass or lose: a colon or a bracket between the cite and `carried by` read
  as an observation, so a made-up id passed; a line of several answers was read only to its first; a worker record whose
  heading ended with its `[UNVERIFIABLE]` tag, or a clearance calling a candidate UNVERIFIABLE, was not listed — one
  run held such a record — and a missing fact opening with the words "carried by" was refused. 2.25.11 reads past the
  separator, every answer of a line, every id after a `carried by` that bears a prefix the report's ids use — so a
  weakness number or a hash name beside it is text, as a fifth review asked — and lists those lines; the eight
  simulated writers' answers read as before. Two simulated repairs, given only the checker's `fix:` text, cleared six
  kinds of wrong answer in one round each; 2.25.12 tells a line with no answer from one answered twice and says what to
  do with an answer at no listed line, and the paragraph says an earlier report's answers are not copied — a run whose
  worker lines moved by two read thirteen of fourteen copied answers as at no listed line, the fourteenth on a line it
  did not judge. Ten simulated writers and repairs on the scan's own model answered 143 lines with one refusal the
  rules did not make: a `mention:` that listed, after a `; `, the line keys it restates, each read as a file's cite —
  2.25.13 reads a line key as the line it names.
- **The Executive Summary counts the Unverifiable entries and names them, because one run's report held ten of them
  two thousand lines down while its summary table showed only the five severities**: a reader of the start of the
  report saw what was found and not what could not be decided — a sender identity's policy, a template's HTML context,
  a deployment's approvals — though each entry names the fact that would decide it. The row stands after Total, which
  counts findings and not these, and the sentences name each entry by its id; its Confirmed and Likely cells read
  `n/a`, as an entry has neither tag. An UNV id on a line no entry opens fails the item when the row is absent or counts
  more than the entries read, as a review's entry headings `UNV-001. <title>` were read as no entry and the hint asked
  for `| Unverifiable | 0 |` over nine of them.
- **A phrase inside an absence claim does not make a configuration clearance, and a dotfile's cite after `; ` keeps its
  dot, because one run's writer was told to rewrite as a finding the clearance `no … or vendor non-production endpoint
  surface in this partition` — a class found absent, with no sink to rewrite — and to re-form five honest answers citing
  `.gitlab-ci.yml:37` after a `; `, read as `gitlab-ci.yml:37`**: across 1587 worker files three lines are such absence
  claims, all of that class, and every clearance resting on `disabled by default` or a test-only `non-production` caller
  still counts. A report written before reads either count.
- **A pair one of whose records is merged into the block linked to the other reads `linked`, because one run held three
  records of one defect over two keys** — a webhook record holding the ledger key, linked to a HIGH IaC record, and a
  second IaC record merged into that one — and its third pair had no answer the table bore out: not `merged into` (the
  webhook record stays `body`), not `linked` (one row merged), and `distinct` untrue. The writer and the repair left the
  mismatch standing rather than answer falsely; the link is now read between the two kept blocks. A review then found the
  link passing while the kept records' own pair read `distinct`: the kept pair's own answer is read now.
- **One missing check of one entry point is one finding, its other sink lines on an `Also at:` line, because one handler
  was filed as thirty-one findings, one per field it read, then sixty-seven across its two consumers** — every one closed
  by one shape check at its top — and the ledger kept each line as a key the next run had to re-find or carry, so the
  split held and spread. The base skill's identity rule now collapses one missing check (a catch-all — per-record error
  isolation — groups nothing, as a test worker that folded a wrong-value bug under it showed); at its class each
  `Also at:` line is a key its record holds — re-found, never a row of its own — a grouped block in a newer report keeps
  the older per-line blocks from being carried back, and items (12), (40) and (46) read the line as (24) and (26) do.
- **A direct call of a triggered function is no entry point of its own because one run filed sixty-eight findings that
  way**: its writer gave every finding at a queue handler a second, promoted row at the handler's direct invocation —
  four handlers, three of which read only the queue's records — and each promoted row stood at a body row's sink, class
  and severity, so the report held a copy of each such finding with nothing added. The invoke API's caller holds only
  the permission to invoke, as the queue's producer holds the permission to send, so it is named on the queue's
  finding; a handler's own branch for an event without the queue's records stays an entry point, which STEP 1
  lists, and item (33) reads each promoted row's entry point as
  the list entry it names, so a promoted row at a body row's entry, sink and class reads as one finding counted twice.
  Compared as written, the cells caught only the copy whose wording matched; the list is the authority.
- **A group's `Also at:` line is read against the other records before STEP 3, because workers put a line that needs
  a fix of its own on a schema group's line** — a decoder's depth limit, a helper passed a string where it reads a
  mapping — nine such lines in five worker files of earlier runs and test runs, under two models, each the error of
  the one worker whose file held both records. The writer, told to merge a group overlap and by the base skill to keep
  such a line off a group's, could do neither: two runs stopped on item (48), one re-running the grouping workers in a
  repair and the other refused its re-run, and a third run merged the decoder-depth finding into the group and read
  clean. Within one file the gate's `groups` field re-runs the worker. Across files the same reading found thirty-nine
  overlap lines — some thirty pairs, nine read from both sides — and none a false match: twenty-eight lines two lenses
  grouping one check, which the writer merges, and eleven a line with a fix of its own, five of them close calls — so
  `--overlaps` lists them and the session judges each, re-running the grouping worker only where the other record
  needs a fix of its own; simulated sessions judging twenty-seven of those lines three times agreed with that
  reading on seventy-five of eighty-one judgements, twenty-four of twenty-seven under this text, each miss a re-run
  more.
