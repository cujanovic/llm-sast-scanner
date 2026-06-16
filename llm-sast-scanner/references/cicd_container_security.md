---
name: cicd_container_security
description: CI/CD pipeline and container/Docker misconfiguration — PPE, untrusted workflow inputs, mutable action tags, overprivileged tokens, secret leakage, and insecure image build patterns
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
| Token scope | `permissions:\s*\n\s*contents:\s*write`, `id-token:\s*write` on lint/test jobs; `GITHUB_TOKEN` with default write on `pull_request` from fork |
| Secret exposure | `echo.*secrets\.`, `printenv`, `env \|`, `set -x`, `--debug`, `ACTIONS_STEP_DEBUG`, `CI_DEBUG_TRACE:\s*true`, `run:.*\${{ secrets\.` |
| Unpinned containers in CI | `container:\s*[^\s@]+:[^\s@]+` without `@sha256:` |

### Dockerfile / compose / K8s

| Signal | Grep / structural targets |
|--------|----------------------------|
| Root execution | missing `USER` after last `RUN`; `USER root`; no `runAsUser` / `runAsNonRoot` in deployment YAML |
| Latest tags | `FROM\s+\S+:latest`, `FROM\s+\S+\s*$` (implicit latest), `image:\s*\S+:latest` |
| Secrets in layers | `ARG\s+(TOKEN\|PASSWORD\|SECRET\|KEY)`, `ENV\s+.*(_TOKEN\|_KEY\|PASSWORD\|SECRET)=`, `RUN\s+.*(curl\|wget).*(-H|--header).*`, `COPY\s+\.npmrc` |
| Remote ADD | `ADD\s+https?://` |
| No digest | `FROM\s+\S+:\S+` without `@sha256:`; `image:\s*\S+:\S+` without digest in compose/Helm |
| Daemon socket | `/var/run/docker\.sock`, `docker\.sock` volume mount in compose or CI service config |
| Privileged runtime | `privileged:\s*true`, `--privileged`, `cap_add:\s*\[?\s*ALL` |

### Example grep one-liners

```bash
rg -n 'pull_request_target|uses:.*@(main|master|latest|v[0-9]+)' .github/workflows/
rg -n '\$\{\{.*(head_ref|pull_request\.(title|body))' .github/workflows/
rg -n 'FROM .*(:latest|@sha256:)|ADD https?://|USER root' **/Dockerfile*
rg -n 'echo.*secrets\.|printenv|CI_DEBUG_TRACE:\s*true' .github/workflows/ .gitlab-ci.yml
```

## Vulnerable Conditions

- Workflow uses `pull_request_target` (or equivalent) and checks out/ref/builds untrusted fork code while `secrets.*` or write-scoped token is available
- Shell step embeds attacker-controlled event field directly: `run: echo "${{ github.event.pull_request.title }}"` or unquoted `${{ github.head_ref }}`
- Third-party action referenced by mutable tag (`@v3`, `@main`) on a job with secret access or deployment permissions
- Job `permissions:` grants write/deploy scopes not required for the step (e.g., `contents: write` on PR lint)
- Secret passed to subprocess/logging: debug scripts, `curl -v`, test fixtures printing env, artifact upload of `.env` generated from secrets
- Final Dockerfile stage has no non-root `USER`; runtime compose/K8s omits `user:` / `securityContext.runAsNonRoot: true`
- Production image uses `:latest` or unpinned tag for base or runtime `container:` image
- `ARG NPM_TOKEN` + `RUN npm ci` without BuildKit secret mount — token persists in layer history
- `ADD http(s)://example.com/script.sh` fetches remote content without hash verification
- Deploy manifests reference `registry/app:1.2.3` without `@sha256:` digest
- CI pulls and deploys public base images with no signature/provenance verification step

## Safe Patterns

**Pipeline hardening**
- Use `pull_request` (not `pull_request_target`) for untrusted code; restrict secrets to protected-branch `push`/`workflow_dispatch` with environment approval
- Pass untrusted strings only as structured env vars to vetted actions — never interpolate into `run:` shell; use `env:` + fixed script with no eval
- Pin actions to immutable commit SHA: `uses: org/action@abc1234deadbeef...`
- Set explicit minimal `permissions:` per job; use OIDC with scoped cloud role per environment
- Mask secrets platform-side; never echo secret env vars; disable debug trace in production pipelines

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

### Untrusted workflow input injection

```yaml
# VULN — PR title reaches shell unquoted
- run: echo Processing ${{ github.event.pull_request.title }}
```

```yaml
# VULN — branch name in script
- run: git checkout ${{ github.head_ref }} && ./deploy.sh
```

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
