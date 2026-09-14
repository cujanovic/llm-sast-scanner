---
name: llm-sast-scanner-full-scan-loop
description: >
  Exhaustive partitioned security audit of a repository. Invoke explicitly as
  "llm-sast-scanner-full-scan-loop <dir> [adv=critical,high,medium] [new-scan]" where <dir> is the target
  repository/directory path; if <dir> is omitted it defaults to the current working directory.
metadata:
  version: "2.16.6"
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

**STEP 1** — runs in this session, never in a subagent: its artifacts are what every worker and STEP 3 depend
on, and a delegated cut cannot be checked by the session that dispatches against it. Build the scope manifest per
the skill's D1, writing the manifest and partition files with redirected shell commands rather than composing them
in a response. Then split the in-scope files into 3 partitions balanced by ATTACK SURFACE, not by line count
alone. The manifest holds only what D1 leaves in scope: generated output derived from in-scope source — ORM
snapshots and journals, build and bundle output, generated route trees — is excluded in `scope-excluded.txt`
with its reason, never classified or partitioned. Classify every remaining row as `source` (application,
infrastructure, CI and build code), `test` (test, fixture, mock and end-to-end trees) or `text` (documentation,
package manifests, lockfiles, editor and agent configuration). Count entry points per directory with STEP 2's entry-point
definition — every registration of every kind, plain HTTP routes included, attributed to the directory of the
file that registers it. This count balances the cut and nothing else. The derivation table is a separate count:
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
class that failed, by the quantity that failed, one level deeper and run the procedure again; never move a file by hand and never re-form units
that passed. The remedy repeats until the checks pass or the largest unit of the class that failed — by the quantity that
failed — is itself a single file; only then does no split remain, and the check is recorded in `scan-plan.md` as
`check failed: <check> — <file> holds <n> of <m> <source lines | entry points> (<share>%)` and the cut stands as
formed. The named file is that largest unit and nothing else: a `check failed` line naming a file that is not the
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
only after the lens set is fixed. `scan-plan.md` opens with the rows `invocation: <the skill invocation as given>`, `model: <the model this
session runs on, written as the base skill's header `<model>` rule prescribes — the exact model ID when the runtime
states one, else the stated display name, else `unknown`; the identifier alone, never the sentence around it>` and
`base-sha: <sha>`, `target: <the absolute path of the target directory, from pwd>`, and `wrapper:
llm-sast-scanner-full-scan-loop v<this file's frontmatter version>`; STEP 3 copies the
report header from these rows, so a value missing here is missing from the report.

**REQUIRED CACHE ARTIFACTS.** Every run leaves this exact file set in `.llm-sast-scanner-cache/`. Each one is
the written record of a decision that otherwise stays in one agent's context and cannot be audited afterward.

| File | Written by | Records |
|------|-----------|---------|
| `scope-manifest.txt` | STEP 1 | every in-scope file with its line count, and the total |
| `scope-excluded.txt` | STEP 1 | every path dropped from scope, one per line, each with its reason |
| `partition-p<n>-manifest.txt` | STEP 1 | one per partition — its file list and line total, cut by the STEP 1 attack-surface rule |
| `<lens>-agent-procedure.md` | STEP 1 | the compiled worker contract every STEP 2 subagent reads |
| `scan-plan.md` | STEP 1 | invocation as given, model (this session's model identifier per the base skill's header rule, else `unknown`), base SHA, mode, adv, the partition table with source and entry-point shares, both entry-point totals, the lens set with its added-lens derivation table, stack-gated exclusions, and the STEP 2 dispatch list with its waves |
| `deep-<lens>-p<n>-results.md` | STEP 2 | one per lens per partition |
| `disposition-table.md` | STEP 3 | one row per Judge-passed worker record — id, entry point, sink `file:line`, class, disposition, verdict, body record — written before any body block |
| `handoff-table.md` | STEP 3 | one row per STEP Y hand-off, each with a final disposition |

Before dispatching STEP 2, verify the STEP 1 artifacts exist and that the partition line counts sum to the
manifest total. A partition file that is absent, empty, or a glob pattern instead of an enumerated file list
means STEP 1 did not finish — rebuild it. Never dispatch a subagent against a partition whose file list is not
on disk; a worker that cannot read its partition will invent a scope and report against it.

Consolidation reads the `deep-*-results.md` files and never writes to them. A lens file is the record of what
that worker found; a consolidation step that edits one destroys the only evidence of what the run actually
produced and makes re-consolidation from clean inputs impossible.

Write ONE report, into `<dir>` itself — the directory this skill was invoked on, alongside the code, NOT into
`.llm-sast-scanner-cache/`, which holds the run's working artifacts. The report is the deliverable; the cache
is the workings. Name it from `date +%Y-%m-%d_%H-%M-%S` at the moment of writing. Never invent a timestamp,
advance a clock, or emit a second report under a later name — a run that produces several reports has no
answer to "which one is the result." A re-consolidation, repair or rebuild within the run rewrites that same file in
place under its original name; a second `sast_report-*.md` newer than the run's start is a STEP 3 error and is deleted
before the run ends, so exactly one report is newer than the run's log.

Every finding in the report body is one complete Finding Format record (base skill Step 7) and keeps its Flow
(source -> sink hops as `file:line` steps), Evidence code block, Judge verdict, CWE, severity with a one-line
rationale, and entry point. The count of records under each severity heading is what the Severity Histogram
reports; the appendix's Body/histogram reconciliation (below) shows the two side by side.

**STEP 2** — Dispatch every lens x 3 partitions, in waves of at most 15 workers (WORKER DISPATCH, below). Each subagent gets exactly ONE lens and ONE
partition and runs its own full convergence loop over only that partition's files. Write results to
`.llm-sast-scanner-cache/deep-<lens>-<partition>-results.md`.

**WORKER DISPATCH.** Every worker is started as a write-capable subagent whose prompt is this text with the
slots filled — the whole of it, in this order, nothing dropped:

> You are the `<lens>` worker for partition `p<n>` of an `llm-sast-scanner-full-scan-loop` run on `<target>`.
> Run every command from `<target>` and read every file by an absolute path under it. Before reading anything
> else, run `pwd` and `git rev-parse HEAD` there: the results file's second and third lines are
> `target: <pwd output>` and `base-sha: <git output>`, produced by running those commands, never copied from this
> prompt; if either differs from the `target:` and `base-sha:` rows of `.llm-sast-scanner-cache/scan-plan.md`,
> stop and write nothing.
> Read in full, in this order: `<skills root>/llm-sast-scanner-convergence-loop/SKILL.md`,
> `<skills root>/llm-sast-scanner/SKILL.md`, `.llm-sast-scanner-cache/<lens>-agent-procedure.md`,
> `architecture-threat-model.md`, `scan-plan.md`, `scope-manifest.txt`, `partition-p<n>-manifest.txt`, and
> `project-memory.md` (hints, never authority). Run the Convergence Loop Procedure of the convergence-loop skill
> in this session over exactly the files of `partition-p<n>-manifest.txt`, constrained to the classes in the
> contract: Steps 1–5 to convergence with 100% line coverage; no adversarial pass, no timestamped report, no
> `project-memory.md` write, no skill or wrapper invocation. Write only
> `.llm-sast-scanner-cache/deep-<lens>-p<n>-results.md`. Its first line is
> `procedure: <convergence-loop skill name> v<its version> / <base skill name> v<its version>` — the convergence-loop
> skill first and the base skill second, both names and both versions copied from the `name:` and `version:` fields
> of the two SKILL.md frontmatters you have just read, never from this prompt. Then every Judge-passed finding as one complete Finding Format
> record (base skill Step 7) whose first line is `[SEVERITY] VULN-<id> — <class> [CONFIRMED | LIKELY]` with the
> severity in capitals, without the Adversarial field, the Clearance Records, the coverage checklist, the
> pass log and the convergence status. When `project-memory.md`'s confirmed-findings ledger is non-empty, also run the
> ledger sink caller enumeration: for every ledger sink whose file is in your partition, trace backward to every entry point
> repository-wide, state per sink which entry points were already reported and which are new, run each new one
> through Source→Sink and the Judge as its own candidate, and write the line `new entry points: <count>` (`0` is a
> valid count); write `ledger empty` when there was no ledger. The final line, written only after coverage verification passes, is
> `<!-- LLM-SAST-COMPLETE lens=<lens> partition=p<n> coverage=100% convergence=<converged | NOT CONVERGED (...)> -->`.
> If you stop early, omit the sentinel.

`<skills root>` is the directory that contains this skill's directory. Workers start in **waves of at most 15**:
order the worker list by lens — the six base lenses in the class table's order, then the added lenses in
derivation-table order — and by partition p1, p2, p3 within each lens; the first 15 are wave 1, the next 15 wave 2,
and so on. A wave starts only when every file of the wave before it ends with its sentinel, or that worker has
been re-run under the crashed-file rule below. A start the runtime rejects with a rate-limit or retryable error is
retried after the interval the error states; the wave size is never raised to catch up. The dispatch is recorded in
`scan-plan.md` as `workers dispatched: <n>` — `n` equal to lenses × 3 — then `waves: <w> of at most 15`, and for
each wave `wave <k>: <m> workers | started <time> | complete <time>` followed by one line per worker,
`<lens>/p<n>: <subagent id> <time>`, written as each subagent starts. A wave is the set of dispatch lines that share
a start time; the `wave <k>:` line summarizes them — its worker count and start time are never edited afterwards,
only `complete <time>` is filled in — and more than 15 dispatch lines sharing one start time is a STEP 2 error,
recorded as `wave <k>: <m> workers — STEP 2 error, cap is 15` and never re-labelled into smaller waves. A re-run
worker's dispatch line is written under the wave it replaces, ending `(re-run: <reason>)`, and is not a wave. While a wave runs, this session checks worker files at most once every two minutes.
Worker result files are written only by
the worker that owns them: this session never writes, edits or completes a `deep-*-results.md`, and neither does any
subagent other than that worker — a "repair" of a worker file by anyone else is a STEP 2 error: the file is deleted
and the worker re-run. When the runtime
cannot start subagents, the run stops after STEP 1: `scan-plan.md` records
`workers dispatched: 0 — <the runtime's refusal, verbatim>`, no worker file and no report is written, and the
user is told that a single-context audit is a separate `llm-sast-scanner-convergence-loop mode=single`
invocation. Before STEP 3, every worker file is checked against the dispatch list and its first line: a file with
no dispatch line, or whose `procedure:` line is missing or names a skill or version other than the two frontmatters' `name:` and `version:`
fields — the two skills in either order pass; a wrong name or version does not —,
was not produced by a worker that loaded the procedure — delete it and re-run that worker. A file whose `target:` or
`base-sha:` line is missing or differs from the scan-plan's rows, or whose cited `File:` paths do not resolve under the
target, was produced against another checkout — delete it and re-run that worker; the path line is the primary check,
because a sibling copy can sit at the same commit. A file that nowhere contains
`new entry points: <count>` or `ledger empty` — on its own line or inside a sentence — fails the same gate and is
re-run the same way; the phrase's presence is the test, not its position.

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
worker file; a consolidation started before that is discarded and its outputs deleted. STEP 3 runs one subagent at a
time — the consolidation writer, then
at most one repair subagent, each started only after the previous one has returned — and this session checks a
running subagent's output at most once every two minutes. D3 includes, among others: negative-verdict re-derivation, the
cross-lens shared-primitive rule, the BURIED-SINK AUDIT, Adversarial Impact Validation, and citation
verification. Run all of them. Whoever writes the report — this session or a consolidation subagent — reads
`scan-plan.md` first: the header's `Invocation:`, `Model:` and `Base SHA:` lines are copied from its
`invocation`, `model` and `base-sha` rows, never taken from the writer's own session; `<target>` in the title is
the target directory's basename; `Analyzer:` names the three skills with their frontmatter versions — the wrapper's
from the scan-plan's `wrapper:` row, the other two from the frontmatters the writer read; a name without a version
is a missing header value.

**WORKER RECORD ACCOUNTING.** The first thing STEP 3 writes is `.llm-sast-scanner-cache/disposition-table.md`,
before Step 6 and before any body block. A record is any line matching the Finding Format first line
`[SEVERITY] VULN-<id> — ...` with the severity token in any letter case: enumeration, the `file records` count and every
other count treat `[Medium]` and `[MEDIUM]` alike, and a count that differs by letter case has dropped records.
Enumerate every such record in every `deep-<lens>-p<n>-results.md`, in worker file order, and give each one a row
with the columns
`worker record | entry point | sink file:line | class | disposition | verdict | body record`. The table is built from
this run's worker files alone: a previous run's table, a previous report and its VULN ids are not inputs to any cell,
and a table found in the cache from an earlier run is deleted, not extended. Before Step 6 the table passes an identity
check — the set of `worker record` ids in the table equals the set of Judge-passed record ids in the current worker
files, in both directions, `promoted` rows excepted — their `worker record` cell reads `promoted/<lens>/p<n>` and is
the one id form the check ignores; a table that fails is deleted and rebuilt, never patched. Here `worker record` is
`<lens>/p<n>/<the worker's own finding id>`. Every cell holds exactly one of these: a worker record id, an entry
point (route, handler, tool or consumer name), a `path:line` sink, a class name, a disposition word, a verdict as
defined below, or a VULN id;
a cell holding anything else — a cross-reference, a placeholder, a blank, a description, a sink without its `:line`,
a disposition outside the four words below — is an **invalid cell**. An invalid cell is filled from the row's worker
record; when the worker record does not hold the value (a `File:` with no line number), the row's disposition
becomes `unverifiable` with that reason and its body block moves to the Unverifiable section.
`disposition` is exactly one of:
- `body` — the record is a body record; `body record` holds the VULN id assigned to it here, in the table;
- `merged` — the record has the same entry point, the same sink `file:line` and the same class as a `body` row;
  `body record` holds that row's VULN id. A record whose entry point differs from every `body` row is never
  `merged`;
- `withdrawn` — Step 6 returned WITHDRAWN, or Citation & Evidence Verification failed; `body record` holds the word
  `withdrawn`, and the appendix lists one line per such row, `withdrawn: <worker record> — <Step 6 | citation>: <one
  line>`, so the reason has a home outside the cells;
- `unverifiable` — the record moved to the Unverifiable section, whose entries are numbered `UNV-<nnn>` in order;
  `body record` holds that id.
`verdict` is Step 6's result for the row, written into the table before any body block is rendered: `STANDING`,
`STANDING — downgrade voided: <named thing> is hop <n> of the Flow`, `DOWNGRADED — <trigger>: <the named thing the
attacker must hold>`, or `DISPUTED — <one clause>` for every `body` row whose severity is in `adv=`; `not run` for a
`body` row outside `adv=`; `n/a` for every other row. Any other content is an invalid cell.
Step 6 and citation verification update the `disposition` and `verdict` cells of this table. The body is then
rendered from the table: one Finding Format record per `body` row, in severity order, carrying the row's VULN id.
Every block has one layout, so two runs' blocks diff line for line: the severity line, then
`Worker record: <worker record id>`, then `Entry point: <the row's entry point>`, then the base skill's fields in its
order — CWE, File, Description, Impact, Flow, Evidence as a fenced code block, Judge, Adversarial, Remediation,
Reference — with no other line between them; and the `Adversarial:` line opens with the row's `verdict` cell —
the verdict word, and for a downgrade its trigger and named thing, for a voided downgrade its hop — followed by ` — `
and the base skill's one-sentence rationale, which is never omitted; a `not run` row's line reads
`Adversarial: not run (severity outside adv=)`. A block whose opening differs from its row's cell, or whose line ends
at the cell with no rationale, is an invalid block. The table is the only source of
verdicts: a re-rendering of the body for any reason — a repair, a completion pass, a second writer — copies them
from the table and never re-adjudicates, defaults or omits one. Body records that STEP X or the BURIED-SINK AUDIT promoted from a
clearance or a note are `promoted` rows under the table, each naming its source lens/partition, and are rendered
the same way. The appendix reproduces `disposition-table.md` by copying the file, then states
`worker records: <n> | body: <b> | merged: <m> | withdrawn: <w> | unverifiable: <u> | promoted: <p>`, where
`b + m + w + u = n` and `b + p` equals the number of body records, and the close-out line
`close-out: table rows <n> | file records <f> | body rows <b> | promoted <p> | body blocks <k> | linked blocks <j> |
invalid cells <c>`, each number produced by counting — table rows, Judge-passed record ids across the current worker
files, `body` rows, `promoted` rows, `### [SEVERITY] VULN-` headings in the
body, body blocks whose
`Worker record:` id has a `body` row with the same VULN id, and cells of the table that are invalid under the cell
rule above. `k` equals `b + p`, `j` equals `b`, `c` equals `0` and `n` equals `f + p` — a table shorter than the worker files
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
status is updated from it. Route families are entry points: two routes reaching one sink are two body records.

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
The appendix is one `## Appendix` section whose sub-headings are the items below as `###` headings, in this order and
under these names, with nothing else at the `##` level after the body:
- Required cache artifacts: one line per file in the REQUIRED CACHE ARTIFACTS table — the filename and its
  byte size on disk. Any file that is absent gets a line saying so and why. Then `artifacts present: <n>/8`.
- Scope exclusions: the contents of `scope-excluded.txt`, plus `excluded: <count> paths / <count> lines`, so a
  reader can tell a deliberate exclusion from a forgotten one. State `excluded: 0` only if nothing was dropped.
- Manifest citation coverage: `files cited in lens work: <n> / <manifest total> (<pct>%)`. Get `<n>` by
  extracting the distinct in-scope paths that appear anywhere in the `deep-*-results.md` files, and the total
  from `scope-manifest.txt`. Count both from the artifacts; neither is read from a worker's own coverage claim.
  Every other coverage number in this report is something a worker asserted about itself, and a worker that
  scanned some scope other than its assigned partition still asserts 100% — this one is derived, so that run
  shows a gap here. Report the number you get. It is a reading of the run, not a bar the run has to clear.
- Added lenses: the added-lens derivation table from `scan-plan.md`, reproduced in full, then one line per lens
  beyond the base six — the lens name, the classes it owns, and the rule that chose it. Then
  `added lenses: <count>`, which is 1 or greater. A report stating `0` records a STEP 2 that did not finish.
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
- Worker dispatch: the `workers dispatched: <n>` line, the `waves:` line, each `wave <k>:` line and the per-worker
  lines copied from `scan-plan.md` — the per-worker lines with their start times are the evidence, and a wave line
  that disagrees with them is reported here as a STEP 2 error — then
  `procedure lines: <k>/<n>` — the count of worker files whose first line is the `procedure:` line with the
  frontmatter versions; `k` equals `n`.
- Per-lens-per-partition pass log: passes run, what the last pass added, stop reason, converged yes/no.
- Line-count reconciliation of each partition against the manifest, and the partition table from `scan-plan.md`
  with each partition's source share and entry-point share, none above 40% — or, when one is, the `check failed` line
  copied from `scan-plan.md`, so the single file that forced it is named in the report.
- Worker record disposition: `disposition-table.md` copied in full (one row per Judge-passed worker record), the
  `promoted` rows, the totals line `worker records: <n> | body: <b> | merged: <m> | withdrawn: <w> |
  unverifiable: <u> | promoted: <p>` with `b + m + w + u = n` and `b + p` equal to the body record count, and the
  close-out line `close-out: table rows <n> | file records <f> | body rows <b> | promoted <p> | body blocks <k> | linked blocks <j> |
  invalid cells <c>` with `k = b + p`, `j = b` and `c = 0`.
- Severity histogram.
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
