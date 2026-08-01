---
name: cicd_container_security
version: "0.2"
description: CI/CD pipeline, security-control workflow, and container/Docker misconfiguration — PPE, untrusted workflow inputs, mutable action tags, overprivileged tokens, secret leakage, incomplete-run cache markers, attacker-forgeable scan exemptions, and insecure image build patterns
---

# CI/CD Pipeline & Container Security

Build pipelines and container images are high-value supply-chain targets. Attackers abuse workflow triggers, third-party actions, token scope, and Dockerfile layers to execute code in CI, exfiltrate secrets, or ship compromised images.

*The core pattern: untrusted input or mutable upstream artifact crosses a CI/container trust boundary — into a privileged runner, image layer, or deploy path — without pinning, isolation, or least privilege.*

## What It Is (and Is Not)

**What it IS**
- **Poisoned Pipeline Execution (PPE)**: attacker-controlled repo content (PR branch, fork workflow, malicious `pull_request_target`) runs steps with secrets or write tokens meant for protected branches
- **Untrusted workflow input injection**: event fields (`github.head_ref`, `github.event.pull_request.title`, `github.event.issue.body`, `gitlab` `CI_COMMIT_MESSAGE`) interpolated into `run:` shell without sanitization → command injection on the runner
- **Mutable third-party action tags**: `uses: org/action@v1` or `@main` — tag can be retargeted to malicious commit after review
- **Overprivileged pipeline tokens**: default `GITHUB_TOKEN`/`CI_JOB_TOKEN` with `contents: write`, `packages: write`, or broad cloud OIDC roles when job only builds/tests
- **Secrets in CI logs/env**: `echo`, `printenv`, `set -x`, debug flags, or `env:` blocks that dump `${{ secrets.* }}` / `$CI_*` to stdout or artifacts
- **Incomplete-run cache suppression**: a scan/test/deploy reserves or writes a cache marker before work starts, then later runs treat marker **existence** as proof of successful completion. A crash, timeout, cancellation, or invalid result leaves a durable “already ran” signal that suppresses every retry.
- **Attacker-forgeable scan exemptions**: a security control drops a whole file/diff/artifact when untrusted content merely contains a marker such as `@generated`, `do not scan`, `test`, or `vendor`. The subject being inspected can forge the predicate that exempts itself.
- **Container runs as root**: Dockerfile missing `USER`, explicit `USER root`, or K8s/`docker run` without `runAsUser` / `-u`
- **Unpinned images**: `FROM node:latest`, `image: nginx:latest`, action `@latest` — non-deterministic, silently updatable base
- **Build-time secrets in layers**: `ARG`/`ENV`/`RUN echo` with tokens; `COPY .npmrc`; secrets not using BuildKit `--mount=type=secret`
- **Remote URL fetch in Dockerfile**: `ADD https://...` — fetches mutable remote content at build time without checksum
- **Missing digest pinning**: image reference uses tag only, no `@sha256:` digest in Dockerfile, compose, Helm, or workflow `container:`
- **Unverified base images**: no image signature/cosign verification, no internal mirror allowlist, pulling from public registries without provenance gate

**What it is NOT**
- **Application-layer injection** in app source — see `sql_injection.md`, `rce.md`, etc., unless taint originates in workflow YAML/Dockerfile
- **Dependency confusion** from package manifests — see `dependency_confusion.md`
- **Runtime container escape** in application code — flag Dockerfile/K8s hardening here; runtime bugs elsewhere
- **Hardcoded secrets in app config** — see `default_credentials.md` unless the literal is in `.github/workflows/`, `.gitlab-ci.yml`, or Dockerfile
- **Local-only `docker build` on developer laptop** with no CI path — lower pipeline risk; still review Dockerfile patterns

## Recon Indicators

### CI/CD workflow files

| Signal | Grep / structural targets |
|--------|----------------------------|
| Workflow paths | `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`, `azure-pipelines.yml`, `.circleci/config.yml`, `bitbucket-pipelines.yml` |
| Dangerous triggers | `pull_request_target`, `workflow_run`, `issue_comment` with `if: github.event.comment.body`, fork PR workflows with `secrets.` access |
| Untrusted interpolation | `\${{ github\.(head_ref\|event\.pull_request\.(title\|head\.ref\|body))`, `\${{ github\.event\.(issue\|comment)\.`, `\$CI_COMMIT_(MESSAGE\|BRANCH\|TAG)` inside `run:` |
| Mutable actions | `uses:\s*[^@\s]+/[^@\s]+@(v[0-9]+|main\|master\|latest)` without full commit SHA |
| Mutable CircleCI orbs | `orbs:` value containing `@dev:` (development orb) or `@volatile` / a bare major like `@1` — mutable third-party code pulled at build time (the CircleCI analogue of a mutable action ref); pin to an immutable `@x.y.z` |
| Deprecated GHA command injection | `env:` containing `ACTIONS_ALLOW_UNSECURE_COMMANDS:\s*(true\|'true'\|"true")` — re-enables the deprecated `::set-env::`/`::add-path::` workflow commands, so any step whose stdout an attacker can influence can inject env vars or hijack `PATH` → code execution on the runner |
| Token scope | `permissions:\s*\n\s*contents:\s*write`, `id-token:\s*write` on lint/test jobs; `GITHUB_TOKEN` with default write on `pull_request` from fork |
| Secret exposure | `echo.*secrets\.`, `printenv`, `env \|`, `set -x`, `--debug`, `ACTIONS_STEP_DEBUG`, `CI_DEBUG_TRACE:\s*true`, `run:.*\${{ secrets\.` |
| Unpinned containers in CI | `container:\s*[^\s@]+:[^\s@]+` without `@sha256:` |
| Cache poisoning | `actions/cache`, `actions/setup-*` (implicit cache), or any `restore`-keys in a workflow whose trigger is `workflow_run` / `pull_request_target` — the privileged job restores a cache an unprivileged fork build can write |
| Completion-marker confusion | cache/marker/artifact is written in a reservation or pre-run step, while a later run checks only `-f`, directory existence, `cache-hit`, or a broad `restore-keys` prefix; a stored `status: reserved/running` field is never parsed; scan exit/result validity is not required before publishing `complete` |
| Content-controlled scan exemption | diff/file/artifact filtering uses substring/regex over the content itself (`'@generated' in section`, `contains("do not scan")`) and `continue`/`return []` skips the whole security operation; especially dangerous when the marker can appear in any added hunk rather than trusted metadata or a canonical generated-file header |
| Artifact poisoning | `actions/download-artifact` / `dawidd6/action-download-artifact` in a `workflow_run`-triggered job — it pulls the *triggering* (fork) run's artifacts, then extracts/executes/deploys their content |
| Self-hosted runner | `runs-on:\s*\[?\s*self-hosted` (or a custom label) on a repo whose workflows are fork-PR-reachable — non-ephemeral runners give persistence + secret reuse across jobs |
| Mutable-ref checkout (TOCTOU) | `actions/checkout` with `ref:` = `github.event.pull_request.head.ref`, `refs/pull/`, `inputs.ref`/`inputs.branch` (mutable) rather than `*.head.sha`/`github.sha`/`*.merge_commit_sha` (immutable) — esp. after a label/approval/`workflow_dispatch` gate |

### Dockerfile / compose / K8s

| Signal | Grep / structural targets |
|--------|----------------------------|
| Root execution | missing `USER` after last `RUN`; `USER root`; no `runAsUser` / `runAsNonRoot` in deployment YAML |
| Latest tags | `FROM\s+\S+:latest`, `FROM\s+\S+\s*$` (implicit latest), `image:\s*\S+:latest` |
| Secrets in layers | `ARG\s+(TOKEN\|PASSWORD\|SECRET\|KEY)`, `ENV\s+.*(_TOKEN\|_KEY\|PASSWORD\|SECRET)=`, `RUN\s+.*(curl\|wget).*(-H|--header).*`, `COPY\s+\.npmrc` |
| Remote ADD | `ADD\s+https?://` |
| Fetch-and-exec in RUN | `RUN` containing `(curl\|wget)\b.*\|\s*(sh\|bash)` — remote script piped straight into a shell at build time, no checksum (distinct from `ADD https://`) |
| Disabled sandbox profile | `security_opt:` with `seccomp:unconfined` / `apparmor:unconfined` / `label:disable` (compose), or `--security-opt\s+(seccomp\|apparmor)=unconfined` / `--security-opt\s+label[:=]disable` (docker run) — turns off the kernel-level confinement (seccomp, AppArmor, **or SELinux**) |
| No digest | `FROM\s+\S+:\S+` without `@sha256:`; `image:\s*\S+:\S+` without digest in compose/Helm |
| Daemon socket | `/var/run/docker\.sock`, `docker\.sock` volume mount in compose or CI service config |
| Sensitive host bind-mount | compose `volumes:` / `docker run -v` mounting a host path (`/`, `/etc`, `/root`, `/home`, `/var/run`, `/proc`, `/sys`, `/var/lib/docker`) into the container — **read-write is the default**, letting the container tamper with host files or read host secrets → escape. K8s `hostPath` analogue: `kubernetes_cloud_security.md` |
| Privileged runtime | `privileged:\s*true`, `--privileged`, `cap_add:\s*\[?\s*ALL` |
| Host namespace shared | compose `network_mode:\s*host`, `pid:\s*host`, `ipc:\s*host`, `uts:\s*host`, `userns_mode:\s*host`; `docker run --network[= ]host` / `--pid[= ]host` / `--ipc[= ]host` / `--uts[= ]host` / `--userns[= ]host` — container joins the host's net/PID/IPC/UTS/user namespace, so it can see & signal host processes, sniff host traffic, or abuse host IPC → isolation break / escape. K8s analogue (`hostNetwork`/`hostPID`/`hostIPC`): `kubernetes_cloud_security.md` |
| Privilege-acquisition not blocked | **absence** of `security_opt:` containing `no-new-privileges:true` (compose) / `--security-opt no-new-privileges` (run) on a container that has any setuid binary — without it a setuid/`CAP_SETUID` binary inside the container can still gain privileges. K8s analogue: `allowPrivilegeEscalation: false` |
| Writable root FS | **absence** of `read_only:\s*true` (compose) / `--read-only` (run) — a writable container root lets an attacker drop a binary, rewrite app code, or persist. K8s analogue: `readOnlyRootFilesystem: true` |
| No resource limits | **absence** of `mem_limit`/`pids_limit`/`cpus` (compose) or `--memory`/`--pids-limit`/`--cpus` (run) — an unbounded container can exhaust host RAM or fork-bomb the host PID table → node-wide DoS. Cross-ref `denial_of_service.md` |
| Insecure registry | `insecure-registries` in `daemon.json` / `--insecure-registry` dockerd flag — pulls images over plaintext HTTP and skips TLS verification → image-pull MITM / poisoned image. Cross-ref `cleartext_transmission.md`, `supply_chain_security.md` |

### Example grep one-liners

```bash
rg -n 'pull_request_target|uses:.*@(main|master|latest|v[0-9]+)' .github/workflows/
rg -n '\$\{\{.*(head_ref|pull_request\.(title|body))' .github/workflows/
rg -n 'FROM .*(:latest|@sha256:)|ADD https?://|USER root' **/Dockerfile*
rg -n 'echo.*secrets\.|printenv|CI_DEBUG_TRACE:\s*true' .github/workflows/ .gitlab-ci.yml
rg -n '>> ?"?\$GITHUB_(ENV|OUTPUT)|eval .*steps\..*outputs|\$\(.*steps\..*outputs' .github/workflows/
# cross-trigger supply-chain: cache/artifact restore in a privileged-trigger workflow, self-hosted, or mutable-ref checkout
rg -n 'actions/(cache|download-artifact)|dawidd6/action-download-artifact|runs-on:.*self-hosted|ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.ref' .github/workflows/
# docker-side container hardening: host-namespace sharing / insecure registry (then audit for *missing* no-new-privileges / read_only / limits)
rg -n 'network_mode:\s*host|pid:\s*host|ipc:\s*host|uts:\s*host|userns_mode:\s*host|--(network|pid|ipc|uts|userns)[= ]host|insecure-registr' . --glob '*compose*.y*ml' --glob 'daemon.json' --glob '*.sh'
# non-GitHub CI: CircleCI mutable orbs, deprecated-GHA-command injection, unpinned CircleCI/Azure executor images
rg -n '@dev:|@volatile|ACTIONS_ALLOW_UNSECURE_COMMANDS' .circleci/config.yml .github/workflows/ azure-pipelines.yml
```

**Other CI platforms (same classes, different syntax):** the supply-chain / secret-exposure / privilege classes above are GitHub-Actions-centric but apply across CI. On **CircleCI**, mutable **orbs** (`@dev:`/`@volatile`/unpinned) are the action-ref analogue, and `executors`/`docker` images should be pinned by `@sha256:` not `:latest`. On **Azure Pipelines**, `container:`/`resources.containers` follow the same digest-pinning rule, and avoid passing secrets through `##vso[task.setvariable …]` logging commands. On **Argo Workflows**, a `Workflow`/`WorkflowTemplate` `spec` with no `serviceAccountName` (or `default`) gives pods the namespace default SA token, and templates should set `securityContext.runAsNonRoot: true` — the Kubernetes securityContext rules in `kubernetes_cloud_security.md` apply to Argo template pods.

## Vulnerable Conditions

- Workflow uses `pull_request_target` (or equivalent) and checks out/ref/builds untrusted fork code while `secrets.*` or write-scoped token is available
- Shell step embeds attacker-controlled event field directly: `run: echo "${{ github.event.pull_request.title }}"` or unquoted `${{ github.head_ref }}`
- Third-party action referenced by mutable tag (`@v3`, `@main`) on a job with secret access or deployment permissions
- CircleCI config references a development (`@dev:...`) or volatile/unpinned orb — equivalent supply-chain exposure to a mutable action ref, on a platform whose orbs run with the job's context/secrets
- GitHub Actions workflow sets `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` — reopens the `set-env`/`add-path` injection sink that GitHub disabled by default
- Job `permissions:` grants write/deploy scopes not required for the step (e.g., `contents: write` on PR lint)
- Secret passed to subprocess/logging: debug scripts, `curl -v`, test fixtures printing env, artifact upload of `.env` generated from secrets
- Final Dockerfile stage has no non-root `USER`; runtime compose/K8s omits `user:` / `securityContext.runAsNonRoot: true`
- Production image uses `:latest` or unpinned tag for base or runtime `container:` image
- `ARG NPM_TOKEN` + `RUN npm ci` without BuildKit secret mount — token persists in layer history
- `ADD http(s)://example.com/script.sh` fetches remote content without hash verification
- `RUN curl … | sh` / `RUN wget … | bash` fetches and executes a remote script at build time with no checksum (same supply-chain risk as `ADD https://`, but inside `RUN`) — pin + verify: `RUN curl -fsSL <url> -o f && echo "<sha256>  f" | sha256sum -c && sh f`
- `security_opt: [seccomp:unconfined, apparmor:unconfined]` (compose) or `--security-opt seccomp=unconfined` (run) disables the seccomp/AppArmor syscall sandbox — a distinct weakening from `privileged`/`cap_add` — keep the default profiles or supply a custom one, never `unconfined`. The **SELinux** equivalent is `security_opt: [label:disable]` / `--security-opt label=disable` (or a `label:type:`/`label:user:` override that loosens the domain) — it strips the container's SELinux confinement on SELinux-enforcing hosts (RHEL/Fedora/CentOS); flag it the same way as the other two LSMs.
- compose `volumes:` / `docker run -v` bind-mounts a sensitive host path (`/`, `/etc`, `/root`, `/var/run`, `/proc`, `/sys`, `/var/lib/docker`) into the container **read-write** (the default when no `:ro` suffix) — the container can rewrite host `/etc/passwd`, drop a host crontab/SSH key, or read host credentials → host tampering and escape. Mount read-only (`:ro`) and scope to the narrowest path actually needed, never the host root or `/etc` (the `hostPath` analogue and `docker.sock` case are covered separately).
- Container joins a host namespace: compose `network_mode: host` / `pid: host` / `ipc: host` / `uts: host` / `userns_mode: host`, or `docker run --network=host` / `--pid=host` / `--ipc=host` / `--uts=host` / `--userns=host` — defeats the namespace isolation that confines the container, exposing host processes, host network sniffing, and host IPC. Keep the default per-container namespaces; only the network case (`host`) is occasionally justified and should then drop all caps + run read-only. (The K8s `hostNetwork`/`hostPID`/`hostIPC` analogue lives in `kubernetes_cloud_security.md`.)
- Container can still acquire new privileges — no `security_opt: ["no-new-privileges:true"]` (compose) / `--security-opt=no-new-privileges` (run) — so a setuid binary or file capability inside the image can escalate even after caps are dropped. Set `no-new-privileges` (the compose/run analogue of K8s `allowPrivilegeEscalation: false`); flag its **absence** on any service, especially one also running as root.
- Container root filesystem is writable — no `read_only: true` (compose) / `--read-only` (run) — letting an attacker overwrite app binaries/config or persist a payload. Mount the root FS read-only and grant only specific writable `tmpfs:`/`volumes:` for runtime scratch (analogue of K8s `readOnlyRootFilesystem: true`).
- Container has no resource caps — no `mem_limit` + `pids_limit` (compose) / `--memory` + `--pids-limit` (run): an unbounded container can exhaust host memory (OOM-kill neighbors) or fork-bomb the shared host PID table, taking down every container on the node → DoS. Always bound at least memory and PIDs; see `denial_of_service.md`.
- `daemon.json` lists the target in `insecure-registries` (or dockerd runs with `--insecure-registry`) — image pulls fall back to plaintext HTTP and skip registry-certificate verification, so a network attacker can MITM the pull and inject a poisoned image. Use only TLS registries with a trusted CA; cross-ref `cleartext_transmission.md` and `supply_chain_security.md`.
- Deploy manifests reference `registry/app:1.2.3` without `@sha256:` digest
- CI pulls and deploys public base images with no signature/provenance verification step
- A workflow saves `reserved`/`started` state to a reusable cache before the security job, then any restored marker disables future runs without requiring `status == complete`, a successful exit code, and a validated result bound to the same immutable input/config
- A scanner, redactor, policy check, or artifact validator skips an entire unit because attacker-controlled bytes anywhere in that unit contain a magic marker (`@generated`, `generated by`, `ignore`, `test`, `vendor`); adding the marker and the vulnerable change in one diff suppresses inspection

## Safe Patterns

**Pipeline hardening**
- Use `pull_request` (not `pull_request_target`) for untrusted code; restrict secrets to protected-branch `push`/`workflow_dispatch` with environment approval
- Pass untrusted strings only as structured env vars to vetted actions — never interpolate into `run:` shell; use `env:` + fixed script with no eval
- Pin actions to immutable commit SHA: `uses: org/action@abc1234deadbeef...`

**Expression-injection precision (FP/FN nuances)**:
- **Why env-var passthrough is the fix — parse-time vs shell-time**: `${{ … }}` is expanded by the Actions **template engine before the shell ever runs**, splicing the attacker value straight into the script *source* (a `"; rm -rf / #` in a PR title becomes script text). Moving the value into an `env:` block and referencing it as `$VAR` in `run:` is safe because the shell receives it as **data**, not script source. This is the #1 false positive: a value that "appears in `run:`" via `$VAR` from `env:` is **safe**; only inline `${{ }}` *inside the `run:` text* is the sink. (Caveat: writing untrusted input to `$GITHUB_ENV` and then using it re-opens the hole.)
- **`actions/github-script` is JavaScript injection, not shell**: `${{ github.event.* }}` inside the `script:` body is interpolated into the **JS source** — fix is to read `context.payload.*` (already a JS object), not `${{ }}`, and not env-var passthrough.
- **`github.head_ref` vs `github.ref`**: `github.head_ref` (PR source branch), `github.event.pull_request.head.ref`, `*.head.label` are attacker-controlled; but on a `pull_request`/`pull_request_target` event **`github.ref` is the server-controlled merge ref `refs/pull/N/merge`** — don't flag `github.ref` the way you flag `head_ref`.
- **Jenkins pipelines — Groovy string interpolation is the parse-time sink (the same class, different syntax)**: inside a `sh "..."` / `bat`/`powershell` step, a **double-quoted** Groovy string interpolates `${env.BRANCH_NAME}`, `${env.CHANGE_TITLE}`, `${env.CHANGE_BRANCH}`, `${params.X}` into the script *source* before the shell runs — so an attacker-controlled SCM field (branch name, PR/tag title, commit message arriving via webhook) becomes script text, exactly like Actions `${{ }}`. A **single-quoted** `sh '...$BRANCH_NAME...'` is safe: Groovy does not interpolate it, so the shell receives the value as a data env var. Sink = `${…}` of a tainted variable inside a **double-quoted** `sh`/`bat`/`powershell`; fix = single-quote the script and pass the value via `environment {}` / `withEnv`. (Same re-opening caveat: a value written to a later shell stage's env is still data, but echoing it back into a double-quoted `sh` re-creates the hole.)
- Set explicit minimal `permissions:` per job; use OIDC with scoped cloud role per environment
- Mask secrets platform-side; never echo secret env vars; disable debug trace in production pipelines
- Model resumable security work as explicit states: `reserved/running` prevents concurrent ownership only; **only** `complete` may satisfy a skip check. Write `complete` atomically after exit success **and** result-schema/integrity validation, bind it to the immutable input SHA/range + policy/config/tool version, and give stale reservations a timeout/retry path. Cancellation/failure must leave no completion sentinel. Prefer CI-native concurrency locks for race prevention rather than caching an in-progress marker as a permanent result.
- Derive scan exemptions from trusted provenance, not arbitrary inspected content: an explicit repository-owned generated-file manifest, generator attestation, deterministic regeneration check, or at minimum a canonical whole-file header at a fixed location plus an expected path. A marker appearing only in an added diff hunk is never sufficient. On ambiguity, **scan**; emit the exact skipped-file list and reason so coverage loss is visible.

**Container / image hardening**
- Pin base with digest: `FROM node:20-alpine@sha256:...`
- Multi-stage build: build stage may use tools; final stage is minimal, non-root, no package manager
- BuildKit secrets: `RUN --mount=type=secret,id=npmrc npm ci` — no secret in layer
- Prefer `COPY` over `ADD`; never `ADD` remote URLs
- Set `USER` to dedicated low-privilege UID in final stage; align K8s `runAsUser` / `readOnlyRootFilesystem`
- Verify image signatures or internal mirror allowlist before deploy; record digest in lockfile/manifest

```yaml
# SAFE — narrow permissions, pinned action SHA, no untrusted shell interpolation
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Run tests
        run: ./scripts/test.sh
        env:
          TITLE: ${{ github.event.pull_request.title }}
```

```dockerfile
# SAFE — digest-pinned base, BuildKit secret, non-root final stage
FROM node:20-alpine@sha256:abc123... AS build
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci --omit=dev

FROM node:20-alpine@sha256:abc123...
USER node
COPY --from=build --chown=node:node /app/node_modules /app/node_modules
COPY --chown=node:node . /app
CMD ["node", "server.js"]
```

## Examples

### Poisoned Pipeline Execution (PPE)

```yaml
# VULN — untrusted fork code runs with elevated context + secrets
on: pull_request_target
jobs:
  deploy-preview:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install && npm run build
        env:
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
```

### Cross-trigger supply-chain attacks (cache / artifact / runner / TOCTOU)

A privileged trigger (`workflow_run`, `pull_request_target`) runs trusted-context jobs *in response to* an untrusted fork's activity. Beyond direct PPE, four well-known GitHub Actions classes let the fork smuggle code/content across that privilege boundary (equivalents exist in GitLab CI `needs:`/`artifacts:` and Azure Pipelines). Each is a distinct finding:

- **Cache poisoning** — a `pull_request` build from a fork populates an `actions/cache` (or implicit `setup-node`/`setup-go`/`setup-python` dependency cache) key; a later **privileged** workflow (`workflow_run`/`pull_request_target` / default-branch job) restores that **same key** and runs the cached content (built binaries, `node_modules`, compiler outputs) → RCE in the trusted context. GitHub cache scoping lets a base-branch job read caches created from PRs. **Safe**: don't restore caches in privileged jobs that handle secrets; namespace cache keys by trust level; treat restored cache as untrusted input.
- **Artifact poisoning** — a `workflow_run`-triggered job calls `actions/download-artifact` (or `dawidd6/action-download-artifact`) to fetch the **triggering** run's artifacts — which a fork PR produced — then unzips and *uses* them (executes a script, reads a "PR number" file unsanitized, deploys the bundle). The artifact is fully attacker-controlled. **Safe**: validate artifact provenance, never execute downloaded content, treat every field as untrusted (the classic "read PR number from artifact" → injection bug).
- **Self-hosted runner exposure** — `runs-on: self-hosted` on a public/fork-reachable repo: a fork PR's job runs on your infrastructure. **Non-ephemeral** runners are worse — tools, env vars, and credentials persist between jobs, enabling lateral movement and persistence. **Safe**: ephemeral (just-in-time) runners only; never run untrusted PRs on self-hosted; isolate per-job.
- **TOCTOU on an approved/mutable ref** — a gated workflow (label-triggered, `workflow_dispatch`, or environment-approval) checks out a **mutable ref** — `github.event.pull_request.head.ref`, `refs/pull/N/head`, `inputs.ref`/`inputs.branch` — so the attacker pushes a new commit *after* the human approves but *before* checkout: approved code ≠ executed code. **Safe**: pin the checkout to an **immutable** commit — `*.head.sha`, `github.sha`, `*.merge_commit_sha`, or an `inputs.sha` resolved at approval time — never a branch/PR ref.

### Security-control completion and exemption integrity

```yaml
# VULN — "reserved" is cached before the scan; later runs use existence as completion.
- run: echo '{"status":"reserved"}' > .scan-marker/state.json
- uses: actions/cache/save@<sha>
  with: { path: .scan-marker, key: scan-${{ github.event.pull_request.number }}-${{ github.sha }} }
# A crash now leaves a restorable marker.
- run: |
    if [ -f .scan-marker/state.json ]; then exit 0; fi
    ./security-scan
```

```python
# VULN — the reviewed diff can forge its own whole-file exemption.
for section in split_diff(diff):
    if "@generated" in section:
        continue
    scan(section)
```

**Review invariant:** a skip verdict needs positive evidence that the *same work item* completed successfully, not evidence that it merely started; a scan exemption needs provenance outside the attacker-controlled bytes being exempted. Validate both predicates at the exact `continue` / `if:` / early-return where coverage is lost.

### Untrusted workflow input injection

```yaml
# VULN — PR title reaches shell unquoted
- run: echo Processing ${{ github.event.pull_request.title }}
```

```yaml
# VULN — branch name in script
- run: git checkout ${{ github.head_ref }} && ./deploy.sh
```

### Env-var intermediary injection (`$GITHUB_ENV` / `$GITHUB_OUTPUT`)

Attacker-controlled `github.event.*` reaching `$GITHUB_ENV`/`$GITHUB_OUTPUT`, or an `env:` value, that a later step (or an AI agent prompt) consumes by name — bypasses scanners that only flag `${{ }}` inside `run:`.

```yaml
# VULN — untrusted body written into the workflow environment, then used later
- run: echo "TITLE=${{ github.event.issue.title }}" >> "$GITHUB_ENV"   # injection into env file
- run: deploy --label "$TITLE"                                          # consumed unquoted later
```

```yaml
# VULN — attacker text placed in env:, AI prompt reads it by name (no ${{ }} in prompt)
- uses: some-org/ai-agent-action@v1
  env:
    ISSUE_BODY: '${{ github.event.issue.body }}'   # attacker-controlled
  with:
    prompt: 'Review the issue in "$ISSUE_BODY" and run the needed fixes.'
```

### Eval of AI / tool output in a later step

LLM or tool output (`steps.<id>.outputs.*`) is attacker-influenced when prompt injection succeeds; a consuming step that runs it through `eval`/`$()`/unquoted expansion gets RCE in the token's security context. See also `insecure_output_handling.md`.

```yaml
# VULN — AI response flows into a shell execution sink
- id: ai
  uses: org/ai-inference@v1
  with: { prompt: 'Summarize ${{ github.event.comment.body }}' }
- run: eval "${{ steps.ai.outputs.response }}"        # arbitrary command execution
```

**SAFE**: pass untrusted values via quoted env vars consumed by argv (not shell), pin to least privilege, and never `eval`/interpolate AI or event data into a shell; validate/parse outputs before use.

### Mutable third-party action tag

```yaml
# VULN — @v2 tag can be moved to malicious commit
- uses: popular-org/setup-node@v2
```

### Overprivileged pipeline token

```yaml
# VULN — write token on every PR job
permissions:
  contents: write
  packages: write
```

### Secrets exposed in CI logs/env

```yaml
# VULN — secret echoed to log
- run: echo "token=${{ secrets.API_KEY }}"
```

```yaml
# VULN — debug dumps environment
env:
  CI_DEBUG_TRACE: true
```

### Dockerfile runs as root

```dockerfile
# VULN — no USER directive; container runs as root
FROM ubuntu:22.04
COPY app /app
CMD ["/app/server"]
```

### Use of :latest

```dockerfile
# VULN — non-deterministic base
FROM python:latest
```

```yaml
# VULN — unpinned CI service container
container: postgres:latest
```

### Build-time secrets in layers

```dockerfile
# VULN — ARG persists in image history
ARG GITHUB_TOKEN
RUN git clone https://${GITHUB_TOKEN}@github.com/org/private.git
```

```dockerfile
# VULN — credential file copied into layer
COPY .npmrc /root/.npmrc
RUN npm ci
```

### ADD of remote URLs

```dockerfile
# VULN — mutable remote content at build time
ADD https://example.com/install.sh /tmp/install.sh
RUN chmod +x /tmp/install.sh && /tmp/install.sh
```

### Missing image digest pinning

```yaml
# VULN — tag only, no digest
services:
  api:
    image: myregistry.io/app:1.4.0
```

```dockerfile
# VULN — tag without sha256
FROM nginx:1.25
```

### Unverified base images

```yaml
# VULN — pull and deploy with no signature/provenance gate
- run: docker pull public.ecr.aws/vendor/base:stable && docker push internal/app:latest
```

## Common False Alarms

- `pull_request_target` job that only posts a comment/bot label and never checks out PR head or runs PR-supplied scripts — review for indirect PPE via artifact download before clearing
- Action pinned to `@v4` on a read-only lint job with no secrets — downgrade severity; still recommend SHA pin for supply-chain hygiene
- `echo` of non-secret context (`github.repository`, `github.sha`) — not secret exposure
- `USER root` in an intermediate build stage followed by `USER app` in final stage — flag only if final stage lacks non-root `USER`
- `FROM alpine:3.19` with digest in a comment but not inline — verify deploy manifest actually pins digest
- BuildKit `--mount=type=secret` usage — secrets not retained in layers; do not flag as layer leakage
- `ADD archive.tar.gz /app/` extracting local context — prefer `COPY` stylistically but not remote-fetch risk
- Internal registry images tagged `:latest` on dev-only compose files explicitly excluded from production deploy path — confirm deploy pipeline separately
- OIDC `id-token: write` on deploy job to cloud with scoped role — expected; flag only when same scope appears on untrusted-trigger jobs
- Test workflows in `tests/fixtures/` with intentional vulnerable YAML for scanner unit tests — exclude by path if documented
