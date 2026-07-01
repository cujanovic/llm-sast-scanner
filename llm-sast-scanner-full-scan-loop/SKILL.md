---
name: llm-sast-scanner-full-scan-loop
description: >
  Convergence-driven, exhaustive line-by-line security audit wrapper around the llm-sast-scanner skill.
  Invoke explicitly as "llm-sast-scanner-full-scan-loop <dir> [mode=parallel|single]" where <dir> is the target
  repository/directory path; if <dir> is omitted it defaults to the current working directory.
  By DEFAULT (mode=parallel) it dispatches one subagent per vulnerability lens — each runs the convergence loop
  (Steps 1-5) constrained to its lens until convergence with 100% line coverage — then a consolidation subagent
  merges results, runs Adversarial Impact Validation (Step 6) once, independently verifies every finding's
  citations against the source, and writes a timestamped consolidated report.
  With mode=single it runs the entire convergence loop in one context (strongest convergence/coverage guarantee).
disable-model-invocation: true
metadata:
  version: "1.8.0"
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
current pass's analysis lens (see LOOP CONTROL), rather than all 102 at once. As the lens rotates across
passes, every vulnerability class gets covered, without holding all references in context simultaneously.
Following the base skill's read-once discipline, keep the current pass's lens references loaded while you read
each file so all of that pass's classes are evaluated in a single read. All step numbers (Step 1-6), the Judge
protocol, the false-positive guardrails, the severity model, and the report structure are defined there and
MUST be used.

## Context & cache efficiency

The agent runtime (not this skill) performs LLM prompt caching, but a cache only hits when the prompt **prefix is stable and byte-identical across calls**. Long multi-pass, multi-subagent runs are exactly the high-cost / high-cacheability case, so structure every prompt *static-first, dynamic-last*:

- **Identical static preamble across all lens subagents.** The **Convergence Loop Procedure**, GROUND RULES, REFERENCE LOADING, and LOOP CONTROL text MUST be byte-identical for every lens (and across re-runs). Pass the per-lens variables (lens name, class list, results-file path) as a short **tail block appended after** that shared text — never interleaved into it. Six lenses sharing one large identical prefix lets the runtime serve it from cache instead of reprocessing it six times.
- **Keep volatile tokens out of the prefix.** Do not bake values that change every call (wall-clock timestamps, `git rev-parse HEAD`, run IDs, counters) into the analysis prompt. Compute the report timestamp and SHA only at OUTPUT / Project-Memory time (the end), not in the loop body. Date-only is stable for a day; clock time would invalidate the cache continuously.
- **Deliver dynamic context as tool results at the tail, not inline.** Read `architecture.md`, `project-memory.md`, and source files **by path** (their changing contents then arrive as tool output at the end of context) rather than pasting their text into the static instruction prefix.
- **Append, don't rewrite, working state.** Extend the ledger, coverage map, and results files by appending; editing earlier context invalidates every cached block after the edit point.

This "stable prefix, dynamic at the tail" discipline complements the base skill's read-once / load-references-once rules: it lowers token cost on long runs **without changing what gets analyzed or the coverage guarantees**.

## Parallel Orchestration (default — `mode=parallel`)

Skip this whole section if `mode=single` was requested; go straight to the **Convergence Loop Procedure**.

### Step D1 — Analysis

If `.llm-sast-scanner-cache/architecture.md` already exists, reuse it. Otherwise run the base skill's **Step 1 (Understand
Scope)** over `<dir>` **in this session** and write a short architecture/threat-model brief to
`.llm-sast-scanner-cache/architecture.md` (languages & frameworks, entry points, trust boundaries, authN/authZ, data stores,
outbound calls, detected stack). Also run the SCOPE MANIFEST enumeration here and record in
`.llm-sast-scanner-cache/architecture.md` the **per-lens stack-gated reference allowlist** derived from it (see REFERENCE
LOADING) — the gateable platform/language/infra references whose signals are present, plus the always-loaded
language-agnostic classes — so each lens subagent loads its minimal set and all lenses share ONE definition
of "applicable classes". Also ensure `.llm-sast-scanner-cache/project-memory.md` exists — if absent, initialize it from
the base skill's **Project Memory Protocol** template (cross-scan hints consumed by every lens as *hints,
never authority*); add `.llm-sast-scanner-cache/` to the target repo's `.gitignore` if not already ignored. Wait for
this to finish.

### Step D2 — Parallel convergence loops (one subagent per lens)

Start **one subagent per lens**, all **in parallel**. Skip any lens whose deep results file already exists.
Give each subagent the instruction below as a **byte-identical static preamble**, then append the three
per-lens variables (lens, class list, results file from the table) as a short **tail block** — do not splice
those variables into the middle of the shared text (see **Context & cache efficiency**), so all lens
subagents share one cacheable prefix:

> Read `.llm-sast-scanner-cache/architecture.md` for context and `.llm-sast-scanner-cache/project-memory.md` as **hints,
> never authority** (base skill's **Project Memory Protocol**: never skip a line or auto-dismiss a class; a
> false-positive entry suppresses a re-report only after you re-confirm its rationale in the current code).
> Do **not** write to `project-memory.md` — Step D3 is the single writer. Then run the base `llm-sast-scanner`
> skill following the **Convergence Loop Procedure** (below) with `lens=<lens>` — i.e. restrict analysis to the **\<lens\>**
> vulnerability classes and load only your lens's references that are on the stack-gated allowlist in
> `.llm-sast-scanner-cache/architecture.md` — or derive it from the SCOPE MANIFEST per REFERENCE LOADING if a reused
> architecture.md lacks it (always-load the language-agnostic classes, skip only stacks whose files are
> absent, and load when unsure). Execute the loop's
> convergence phase: multi-pass Steps 1–5 (taint tracking, business-logic/auth, Judge) until convergence,
> applying the ledger + 100% line-coverage discipline to your lens. **Do NOT run the final Adversarial Impact
> Validation pass, do NOT write a timestamped report, and do NOT re-invoke the full-scan-loop wrapper.** Write
> only Judge-passed CONFIRMED / LIKELY findings, plus your final coverage result and pass log, to the results
> file below.

| Lens | Deep results file | Vulnerability classes (reference lenses) |
|------|-------------------|------------------------------------------|
| injection | `.llm-sast-scanner-cache/deep-injection-results.md` | SQLi, XSS, client-side prototype pollution, SSTI, SSI injection, ESI injection, NoSQLi, GraphQL injection, XXE, RCE/command injection, environment variable injection (CWE-99/454), expression-language injection, LDAP injection, XPath/XQuery injection, CSV/formula injection, log injection, prompt injection (LLM01), insecure output handling (LLM05), DOM clobbering |
| access-auth | `.llm-sast-scanner-cache/deep-access-auth-results.md` | IDOR, privilege escalation / missing auth (BFLA), authentication & JWT, OAuth 2.0 / OIDC misconfiguration, default credentials, hardcoded secrets (CWE-798 secret literals at rest / client-exposure model), brute force, business logic, HTTP method tampering, verification code abuse, session fixation, session puzzling, reverse-proxy access bypass, email parser differential, mass assignment, BaaS client-side authorization (Supabase RLS / Firebase Security Rules), excessive agency (LLM06), RAG / vector & embedding security (LLM08), API / REST / web-service security, webhook / integration security, MCP (Model Context Protocol) security, gRPC / gRPC-Web server-side security |
| crypto-data | `.llm-sast-scanner-cache/deep-crypto-data-results.md` | weak crypto/hash, information disclosure (incl. LLM02 sensitive disclosure), insecure cookie, trust boundary, client-IP / network-origin trust (XFF spoofing), shared-client cache/dedup cross-user leak, cleartext transmission, certificate/TLS validation, system prompt leakage (LLM07), privacy / data protection (PII) |
| server-side | `.llm-sast-scanner-cache/deep-server-side-results.md` | SSRF, path traversal/LFI/RFI, client-side path traversal, server-side prototype pollution, insecure deserialization, arbitrary file upload, JNDI injection, race conditions, insecure temp file, file permissions, batch/ETL/mainframe data-pipeline security |
| protocol-infra | `.llm-sast-scanner-cache/deep-protocol-infra-results.md` | CSRF, open redirect, reverse tabnabbing, HTTP request smuggling/desync, HTTP response splitting, host header poisoning, correlation/tracing header injection, CORS misconfiguration, WebSocket security (CSWSH), postMessage security, XSSI / JSONP / Reflected File Download (RFD), clickjacking, web cache deception/poisoning, denial of service (incl. LLM10 unbounded consumption), GraphQL denial of service, regex injection/ReDoS, CVE patterns, Content Security Policy (CSP) weaknesses, XS-Leaks |
| hardening-platform | `.llm-sast-scanner-cache/deep-hardening-platform-results.md` | output encoding, format string injection, improper input validation (semantic-type mismatch / missing format validation), ASP.NET security misconfiguration, hardcoded code/backdoor, dependency confusion, ML supply chain & data/model poisoning (LLM03/04), AI editor / agent config poisoning (repo poisoning), PHP security (incl. TYPO3 CMS — Fluid / TypoScript / Extbase; loads **both** `php_security.md` and the separate `typo3_security.md`), Android security, iOS security, Electron / desktop app security, C/C++ memory safety, smart contract security (Solidity/EVM + Solana/Anchor; loads **both** `smart_contract_security.md` and the separate `solana_smart_contract_security.md`), IaC security (Terraform/CloudFormation/ARM/Bicep/Pulumi), subdomain takeover (dangling-DNS candidate flagging in IaC/zone files), Kubernetes / cloud orchestration, CI/CD & container security, nginx / web-server configuration, supply chain security (SRI / provenance / lifecycle scripts) |

Each lens subagent independently reads every in-scope line for its own coverage proof, so total read cost
scales with the number of lenses — this is the cost of per-lens parallelism. **Wait for all subagents to
finish before proceeding.**

### Step D3 — Consolidation + single adversarial pass

Launch one subagent:

> First confirm all SIX `.llm-sast-scanner-cache/deep-*-results.md` files exist (injection, access-auth, crypto-data,
> server-side, protocol-infra, hardening-platform). If any is missing, that lens's whole class group was
> skipped — re-run that lens before consolidating, otherwise class coverage is <100%. Then read all
> `.llm-sast-scanner-cache/deep-*-results.md` files and `.llm-sast-scanner-cache/architecture.md`. Merge and de-duplicate findings across
> lenses (same `file:line` + vuln class = one finding). Run the base `llm-sast-scanner` skill's **Step 6
> (Adversarial Impact Validation)** ONCE over the full consolidated set with the `adv` value (default
> `adv=critical,high,medium`), apply the STANDING / DOWNGRADED / DISPUTED / WITHDRAWN verdicts. Then, as an
> **independent gate** (you did NOT author these per-lens findings), run the base skill's **Citation & Evidence
> Verification** over every surviving finding: re-open each cited `file:line` and confirm the path exists, the
> line/snippet and function scope match, and the route/method + payload + preconditions are accurate — correct
> mismatches, or downgrade to NEEDS CONTEXT / drop any finding whose evidence does not verify. Then write a
> single timestamped report `sast_report-<timestamp>.md` (timestamp from `date +%Y-%m-%d_%H-%M-%S`) using the
> base skill's report structure (Executive Summary; Critical/High/Medium/Low/Informational; Unverifiable;
> Hardening Notes; Positive Patterns; Remediation Priority). Also print a combined coverage summary and a per-lens pass log. Finally, as the
> **single writer**, update `.llm-sast-scanner-cache/project-memory.md` per the base skill's **Project Memory Protocol**
> (append newly CONFIRMED findings with current `git rev-parse HEAD`; record DOWNGRADED/DISPUTED/WITHDRAWN as
> false-positive patterns with the rationale that defeated them; refresh primitives/hotspots; bump
> `last-scanned-sha`/`last-updated`).

When D3 finishes, tell the user the report path and summarize the highest-severity findings. **In parallel
mode you are done here — do NOT also run the single-context procedure below.**

---

## Convergence Loop Procedure (single context)

This is the loop body. It runs in ONE context — either the whole `mode=single` run (all lenses, rotating per
pass), or a single parallel-mode lens subagent (when invoked with `lens=<lens>`, restrict every pass to that
lens's classes and treat "convergence" as "a pass surfaced no new bug **in that lens**"). When run as a
parallel-mode lens subagent, STOP after COVERAGE VERIFICATION, write findings to the lens's
`.llm-sast-scanner-cache/deep-<lens>-results.md`, and SKIP the FINAL ADVERSARIAL PASS + OUTPUT (Step D3 owns those).

Execute the following prompt against the target `<dir>`. Treat `"dir as argument"` as the `<dir>` value
provided to this command.

---

Use the /llm-sast-scanner to perform an exhaustive, line-by-line security audit of the repository at:
"dir as argument"
GROUND RULES
- PROJECT MEMORY: if `.llm-sast-scanner-cache/project-memory.md` exists, read it as **hints, never authority** (base
  skill's **Project Memory Protocol**) — it may prioritize files/classes or explain known-safe patterns, but
  must never make you skip a line or auto-dismiss a class, and a false-positive entry suppresses a re-report
  only after you re-confirm its safe rationale in the current code. In single-agent mode the OUTPUT step updates
  this file; parallel-mode lens subagents never write it.
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
- REFERENCE LOADING (stack-gated by the SCOPE MANIFEST — coverage-safe; DEFAULTS TO LOAD):
  - Gate on the files actually present (NOT a coarse "detected stack" label), detected two cheap and
    deterministic ways: (1) filename/extension over the SCOPE MANIFEST; and (2) a one-shot `rg -l` CONTENT
    probe over the manifest files for signals that live INSIDE files rather than in their names — e.g. k8s
    `kind:`/`apiVersion:`, CloudFormation `AWSTemplateFormatVersion`, Pulumi, and AI-SDK deps/imports
    (`openai`/`anthropic`/`langchain`/`transformers`). The manifest alone is filenames + line counts, so the
    content probe is REQUIRED for those. This gated set is the lens's APPLICABLE-CLASS set, and COVERAGE
    VERIFICATION must use the SAME set (an excluded class is "not in stack", never a coverage gap).
  - Only the PLATFORM/LANGUAGE/STACK-SPECIFIC references below are gateable — load each ONLY when its signal
    is detected (filename match OR `rg` content probe, per above); otherwise SKIP it and record its class as
    "excluded — not in stack":
      * php_security ← *.php / composer.json
      * memory_safety_c_cpp ← *.c / *.cc / *.cpp / *.h / *.hpp
      * android_security ← AndroidManifest.xml / *.kt / *.java (+ build.gradle / *.gradle / settings.gradle) / Android markers `com.android.application`·`androidx`·`android {` in Gradle
      * ios_security ← *.swift / *.m / *.mm / Info.plist / *.xcodeproj / *.xcworkspace / Podfile / Package.swift
      * electron_desktop_security ← "electron"/"electron-builder"/"@electron/remote"/"nw" in package.json / BrowserWindow|BrowserView|webPreferences|contextBridge|nodeIntegration in *.js|*.mjs|*.cjs|*.ts|*.jsx|*.tsx / *preload* / electron-builder.{yml,yaml,json} / nwjs config
      * smart_contract_security ← *.sol / *.vy
      * aspnet_security_misconfig ← *.cs / *.aspx / *.cshtml / *.csproj / web.config
      * jndi_injection, expression_language_injection ← JVM sources *.java / *.kt / *.scala (+ pom.xml / build.gradle)
      * server_side_prototype_pollution ← Node backend (*.js / *.ts + package.json)
      * client_side_prototype_pollution, dom_clobbering, xs_leaks, client_side_path_traversal,
        content_security_policy, clickjacking, postmessage_security, reverse_tabnabbing ← browser frontend /
        server-rendered HTML (*.html / *.js / *.ts / *.jsx / *.tsx / *.vue / *.svelte). NOTE: postMessage
        handlers (`addEventListener('message'`) and `target="_blank"` links also appear in plain *.js / *.ts,
        not only JSX/HTML — include those extensions so frontend logic in vanilla JS isn't skipped.
      * iac_security ← *.tf / *.bicep / CloudFormation / ARM / Pulumi
      * subdomain_takeover ← DNS records in IaC/zone files (`aws_route53_record` / `azurerm_dns_*record` / `google_dns_record_set` / `cloudflare_record` / `AWS::Route53::RecordSet` / `Microsoft.Network/dnsZones` / BIND `*.zone` / CNAME/ALIAS lines)
      * kubernetes_cloud_security ← k8s manifests (kind: …) / Helm Chart.yaml
      * cicd_container_security ← Dockerfile / .github/workflows/* / .gitlab-ci.yml / Jenkinsfile / *compose*.y*ml
      * nginx_security ← nginx.conf / conf.d/*.conf / *.nginx / sites-available/* / sites-enabled/* / snippets/* (these last three are usually **extensionless** — match by path, not extension) / files containing `server {` / `location ` / `proxy_pass` / `worker_processes` / `ssl_protocols` / `ssl_certificate`
      * baas_security ← Backend-as-a-Service markers: `@supabase/*` / `firebase` / `firebase-admin` deps, `createClient(`, `*.rules` / `firestore.rules` / `storage.rules` / `database.rules.json`, SQL containing `ENABLE ROW LEVEL SECURITY` / `CREATE POLICY` / `auth.uid()`, `service_role`, `x-hasura-admin-secret`, `aws_appsync_*` / `amplify`
      * prompt_injection, insecure_output_handling, excessive_agency, system_prompt_leakage,
        rag_vector_security, ml_supply_chain_poisoning, mcp_security, ai_editor_config_poisoning ←
        AI/LLM/agent markers (openai / anthropic / langchain / llama / transformers deps, *.ipynb,
        .cursorrules, CLAUDE.md / AGENTS.md, *.mcp.json)
      * grpc_security ← gRPC/gRPC-Web/Connect: *.proto / deps·imports `io.grpc`·`grpc-java`·`grpcio`·`grpc`·`@grpc/`·`grpc-web`·`Grpc.Net`·`connectrpc`·`google.golang.org/grpc` / `ServerInterceptor`·`ManagedChannel`·`StreamObserver`·`grpc.server(`·`mustEmbedUnimplemented` / grpc-gateway / grpc transcoding. (A custom/in-house binary RPC that is NOT gRPC does NOT count — require a gRPC signal.)
      * graphql_injection, graphql_dos ← GraphQL: *.graphql / *.gql / deps `graphql`·`apollo-server`·`graphql-java`·`graphene`·`gqlgen`·`hotchocolate`·`strawberry` / `type Query`·`buildSchema(`·`makeExecutableSchema`·`@Resolver`·`/graphql` endpoint
      * nosql_injection ← NoSQL drivers/usage: `mongodb`·`mongoose`·`pymongo`·`spring-data-mongodb`·DynamoDB/Couchbase/Cassandra/CosmosDB SDKs / Mongo query operators from input (`$where`·`$ne`·`$gt`·`$regex`)
      * ldap_injection ← LDAP: `javax.naming.directory`·`LdapContext`·`InitialDirContext`·`DirContext.search` / `ldapjs`·`python-ldap`·`ldap3`·`spring-ldap` deps / `ldap://`·`ldaps://`
      * xpath_injection ← XPath/XQuery: `XPath`·`XPathFactory`·`XPathExpression`·`selectNodes`·`selectSingleNode`·`compile(` over XML / `lxml ... .xpath(`
      * xxe ← an XML parser is instantiated on attacker-reachable input: (JVM) `DocumentBuilderFactory`·`SAXParser`·`XMLReader`·`XMLInputFactory`·`Unmarshaller`·`SAXReader`·`SAXBuilder` / (Python) `lxml`·`xml.etree`·`xml.dom`·`xml.sax`·`libxml` / (PHP) `DOMParser`·`simplexml_load`·`libxml_*`·`DOMDocument` / (.NET) `XmlDocument`·`XmlReader`·`XmlTextReader`·`XmlReaderSettings`·`XDocument`·`XPathDocument` / (Go) `encoding/xml`·`xml.Unmarshal`·`xml.NewDecoder` / (Ruby) `Nokogiri`·`REXML`·`Ox` / (Node) `libxmljs`·`xml2js`·`fast-xml-parser`·`@xmldom/xmldom` — **also XSLT injection** when a user-influenced **stylesheet** reaches a transform sink: (PHP) `XSLTProcessor::importStylesheet`+`registerPHPFunctions` / (.NET) `XslCompiledTransform.Load`+`XsltSettings.TrustedXslt`/`EnableScript`/`msxsl:script` / (JVM) `TransformerFactory.newTransformer`·Saxon `XsltCompiler` / (Python) `lxml.etree.XSLT` / `xsltproc` — file read/write, SSRF, RCE
      * websocket_security ← WebSockets: `javax.websocket`·`@ServerEndpoint`·`WebSocketHandler`·`TextWebSocketHandler` / `ws`·`socket.io`·`SignalR`·`STOMP`·`@stomp` / server-side `new WebSocketServer(`·`websockets.serve`
      * batch_etl_pipeline_security ← batch/ETL/mainframe: Spring Batch (`ItemReader`·`ItemWriter`·`@StepScope`·`JobLauncher`) / *.jcl·*.cbl·copybooks / fixed-width·EBCDIC·COMP-3 parsing / landing-dir watchers
      * format_string_injection ← a format/template function can receive a NON-literal (user-influenced) format argument: (C/C++) *.c·*.cc·*.cpp·*.h·*.hpp with `printf`·`fprintf`·`sprintf`·`snprintf`·`vprintf`·`vsnprintf`·`syslog(`·`err(`/`warn(` / (Python) `%`-formatting or `.format(` / `logging`·`logger` calls whose format string is a variable / `f"{...}"` built from input / (Java) `String.format`·`Formatter`·`MessageFormat`·`printf`·`String.formatted` / (C#) `String.Format`·`$"..."`·`Console.Write*` with a non-literal format / (Go) `fmt.Printf`/`fmt.Sprintf`/`fmt.Errorf` with a non-constant format verb. (A constant/literal format string is NOT a finding — require the format arg to be variable/attacker-influenced.)
      * ssi_injection ← Server-Side Includes enabled or SSI-parsed templates: *.shtml·*.shtm·*.stm files / Apache `Options +Includes`·`Options +IncludesNOEXEC`·`mod_include`·`AddType text/html .shtml`·`AddOutputFilter INCLUDES`·`XBitHack on` / nginx `ssi on;` / SSI directives in templates (`<!--#include`·`<!--#exec`·`<!--#echo`·`<!--#config`·`<!--#set`). (Plain HTML with no SSI-enabled server/filter does NOT count.)
      * esi_injection ← Edge Side Includes processed by a surrogate/CDN in front of reflected output: response emits `Surrogate-Control`/`content="ESI` / cache config enabling ESI (`esi on`·`do_esi`·`esi_parse`·`EnableEsi`·`x-esi` in *.vcl·*.conf·*.toml·*.yaml·*.yml) / `<esi:include`·`<esi:vars` in templates·*.vcl / a Varnish·Squid·Apache-Traffic-Server·Fastly·Akamai surrogate fronting the app. (Plain responses with no ESI-enabled surrogate do NOT count — default to load when a surrogate/CDN cache is present and the app reflects input.)
  - ALL OTHER classes are language-agnostic — ALWAYS load them (never gated). The always-load set is genuinely
    cross-stack: sqli, xss, ssrf, rce/command_injection, environment_variable_injection, ssti, path_traversal_lfi_rfi, insecure_deserialization,
    arbitrary_file_upload, idor, privilege_escalation, authentication_jwt/oauth/session/brute_force/default_credentials,
    hardcoded_secrets, business_logic, mass_assignment, weak_crypto_hash, information_disclosure, insecure_cookie, csrf, open_redirect,
    smuggling_desync, http_response_splitting, host_header_poisoning, cors_misconfiguration, web_cache_deception,
    denial_of_service, regex_injection_redos, log_injection, file_permissions, output_encoding, api_security,
    trust_boundary, xff_spoofing (client-IP/network-origin trust — derived from request handling, not a stack), etc.
  - MAINTENANCE INVARIANT (keep this gate in sync with references/): EVERY platform/language/stack/protocol-bound
    reference MUST have a gate entry above. When a new ecosystem-specific reference is added to references/, add
    its detection signal here in the SAME change — otherwise it silently falls into "ALL OTHER / ALWAYS load" and
    gets scanned against stacks where it cannot apply (e.g. hunting gRPC flaws in a repo with no gRPC). Gating a
    provably-absent stack is coverage-safe; the COVERAGE VERIFICATION step records each skipped class as
    "excluded — not in stack", which is NOT a coverage gap.
  - DEFAULT TO LOAD: if a signal is ambiguous or you are unsure a class applies, LOAD the reference. Gating
    may drop a reference ONLY when its ecosystem is provably absent — coverage wins over tokens.
  - LOAD ONCE PER RUN: load each needed reference at most once; keep its key sources/sinks/sanitizers in
    working notes and do NOT re-load full reference files on later passes when a lens recurs.
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
pass's lens (not all 102 at once) to keep context cost bounded. Across all passes you MUST apply EVERY
applicable class — every class on the stack-gated allowlist (see REFERENCE LOADING) — in all six lens groups
from the Step D2 table, including the cloud/infrastructure and web-platform classes (IaC, Kubernetes/cloud,
CI/CD & container, API, MCP, CSP, XS-Leaks, DOM clobbering, privacy/PII, supply-chain) whenever their files
are present — not only the example lenses named above. The D2 table, gated by the allowlist, is the
authoritative class set for class coverage.
COVERAGE VERIFICATION (run whenever the loop stops — at convergence, the pass-5 ceiling, or the pass-10 cap)
- Before finalizing, reconcile the coverage map against the SCOPE MANIFEST built before pass 1 and confirm
  that EVERY line of EVERY in-scope file (per the GROUND RULES scope + exclusions) was actually read (not
  sampled) — every manifest file marked fully read `1..total_lines`. Produce a coverage checklist: each file
  with its total line count and the line ranges read. List excluded paths (vendored deps, build output, lock
  files, binaries) separately as "excluded" — they are not coverage gaps.
- If any in-scope file or line range was NOT fully read, run one more targeted pass over only the
  unread lines until coverage is 100%. (This coverage-completion pass does not count toward the
  10-pass cap, but any NEW bug it surfaces is added to the ledger.)
- CLASS coverage (not just lines): confirm every applicable vulnerability class was actually APPLIED — not
  merely that every line was read. A parallel-mode lens subagent must evaluate every class in its D2 lens row
  that is on the stack-gated allowlist; single mode must cover every on-allowlist class across all six lens
  groups. Classes excluded as not-in-stack are recorded as "excluded — not in stack", which is NOT a gap.
  100% coverage = every in-scope line read AND every applicable (on-allowlist) class evaluated. Reading 100%
  of lines under only some lenses is NOT 100% coverage.
- State the final coverage result explicitly (e.g., "100% of N in-scope files / M lines read; K paths
  excluded; all C applicable classes applied").
FINAL ADVERSARIAL PASS (run ONCE, after the loop is fully done)
- SINGLE-AGENT MODE ONLY. If you are a parallel-mode lens subagent (`lens=<lens>` set), SKIP this section and
  the OUTPUT section — write your Judge-passed findings + coverage result to `.llm-sast-scanner-cache/deep-<lens>-results.md` and
  stop; Step D3 runs the adversarial pass once over the merged set.
- After the loop terminates (converged, reached the pass-5 ceiling, or hit the 10-pass cap) AND coverage is verified at
  100%, take the FULL consolidated set of Judge-passed findings and run Adversarial Impact Validation (Step 6)
  ONE TIME over all of them with the `adv` value (default adv=critical,high,medium).
- Apply the adversarial verdicts (STANDING / DOWNGRADED / DISPUTED / WITHDRAWN) to finalize severities.
- Then run the base skill's **Citation & Evidence Verification** over every surviving finding: re-open each
  cited `file:line` and confirm path/line/scope/route/payload/preconditions match the source; correct
  mismatches, or downgrade to NEEDS CONTEXT / drop any finding whose evidence does not verify. (Single-agent
  mode is self-review — be deliberately adversarial toward your own citations here.)
OUTPUT (single-agent mode)
- After the final adversarial pass, write a single consolidated report to the current dir named
  `sast_report-<timestamp>.md`, where `<timestamp>` is the output of `date +%Y-%m-%d_%H-%M-%S`
  (e.g., `sast_report-2026-06-11_14-30-05.md`). Use the skill's report structure (Executive Summary;
  Critical/High/Medium/Low/Informational; Unverifiable; Hardening Notes; Positive Patterns; Remediation
  Priority), with exact file paths + line numbers and concrete remediations.
- Also print a short loop log: how many passes ran, what NEW finding (if any) each pass added, the reason the
  loop stopped (converged with no new bug, reached the pass-5 ceiling, or hit the 10-pass cap), the final
  line-coverage result (100% of N in-scope files / M lines, with the per-file checklist), and the adversarial
  verdict applied to each finding.
- Finally, as the single writer, update `.llm-sast-scanner-cache/project-memory.md` per the base skill's **Project
  Memory Protocol**: append newly CONFIRMED findings (with current `git rev-parse HEAD`), record
  DOWNGRADED/DISPUTED/WITHDRAWN findings as false-positive patterns with the rationale that defeated them,
  refresh project security primitives and hotspots, and bump `last-scanned-sha` / `last-updated`.

---

## Notes

- The report filename uses a real timestamp: compute it with `date +%Y-%m-%d_%H-%M-%S` and write
  `sast_report-<timestamp>.md` to the current working directory.
- "Step 6 / Adversarial Impact Validation" refers to the base skill's reporting + severity model; run it once
  over the consolidated, Judge-passed findings only.
