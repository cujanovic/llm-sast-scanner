---
name: dependency-confusion
description: Dependency confusion / substitution attack — flag CANDIDATE internal packages that a public registry could shadow, across npm, PyPI, RubyGems, Maven/Gradle, NuGet, Go, Composer, and Cargo (CWE-1357 / supply chain)
---

# Dependency Confusion (candidate flagging)

Dependency confusion (a.k.a. substitution / namespace-confusion attack) occurs when a build resolves an **internal/private** package name from a **public** registry because an attacker published a same-named (often higher-version) package there. The malicious package's install/build hooks then run arbitrary code in the developer or CI environment → supply-chain RCE.

## Scope of this skill: CANDIDATES ONLY

This reference flags **candidates** from source alone. It does **not** confirm exploitability, because confirmation requires an out-of-band registry-ownership lookup (does the name exist / who owns it on the public registry?) which is a network action outside static analysis.

- **CANDIDATE** = an internal-looking dependency that is resolvable from a public-capable registry with **no private-source pin**.
- Report candidates as **Informational / Low** with the note: *"confirm by checking public-registry ownership of the name (404 = claimable = exploitable)."*
- Do not upgrade severity or assert exploitability without that confirmation step.

## The candidate condition (all ecosystems)

Flag a dependency when ALL hold:

1. **Internal-looking name** — a private scope/namespace (`@company/*`, `com.acme.internal`, company prefix) or a name you would not expect on the public registry.
2. **No private-source pin** — the ecosystem's registry config does NOT bind that name/namespace to a private registry (so the resolver can fall back to the public one).
3. **Lockfile does not pin it privately** — no `resolved`/repository URL pointing at the internal registry with an integrity/checksum.
4. **Not a local/workspace member** — the name is not provided by an in-repo workspace/path/sibling module.

## Detection inputs to parse

- **Manifests** (declared dependencies) and **lockfiles** (resolved source + integrity)
- **Registry/source configuration** files — the presence/absence of a private-scope pin is the deciding signal
- **Workspace/monorepo** declarations — to exclude locally-provided names

---

## Per-Ecosystem Rules

### npm / yarn / pnpm (Node.js)
- Manifests: `package.json` (`dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`). Lockfiles: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`. Config: `.npmrc`, `.yarnrc.yml`. Workspaces: `workspaces` field, `pnpm-workspace.yaml`.
- **CANDIDATE**: a `@scope/*` (or internal unscoped) dependency with **no** `@scope:registry=https://npm.internal/` line in `.npmrc`, and a lockfile `resolved` that is empty or points at `registry.npmjs.org`.
- **SAFE**: `.npmrc` pins the scope to a private registry (`@acme:registry=...`); lockfile `resolved` is the private URL with a matching `integrity`; the name is a local `workspaces` package.
- Next.js note: a Next.js app's exposed `package.json`/`package-lock.json`/`.npmrc` (served publicly or committed in a public webroot) hands an attacker the exact internal names to claim — treat exposed manifests as a candidate amplifier, not a separate class.

### Python — pip / Poetry / PDM (PyPI)
- Manifests: `requirements*.txt`, `pyproject.toml`, `setup.py`, `setup.cfg`, `Pipfile`. Lockfiles: `poetry.lock`, `Pipfile.lock`, `pdm.lock`. Config: `pip.conf`/`pip.ini`, `.pypirc`, per-project `--index-url`/`--extra-index-url`.
- **CANDIDATE**: an internal distribution installed while `--extra-index-url <internal>` is used **alongside** public PyPI — pip merges both indexes and may prefer the public copy (classic confusion vector). Also: internal package with no index pinning at all.
- **SAFE**: `--index-url` set to the private index **only** (not `--extra-index-url`); `[tool.pip] index-strategy = "unsafe-first-match"` avoided; Poetry `[[tool.poetry.source]]` with `priority = "explicit"`/`"primary"` binding the package to the private source; hashes pinned (`--require-hashes`).

### Ruby — Bundler (RubyGems)
- Manifests: `Gemfile`. Lockfiles: `Gemfile.lock` (`GEM remote:` / `source` blocks).
- **CANDIDATE**: an internal gem declared under the global `source "https://rubygems.org"` with no scoped `source` block.
- **SAFE**: gem declared inside a scoped `source "https://gems.internal" do ... end` block; `Gemfile.lock` records the private remote for that gem.

### Java — Maven & Gradle (Maven Central / internal repos)
- Maven: `pom.xml` (`<dependencies>`, `<repositories>`), `~/.m2/settings.xml` (`<mirrors>`, `<repositories>`). Gradle: `build.gradle(.kts)`, `settings.gradle(.kts)` (`repositories { mavenCentral(); maven { url ... } }`), `gradle.lockfile`.
- **CANDIDATE**: an internal `groupId` (e.g. `com.acme.internal:*`) while both a public repo (`mavenCentral()`/`jcenter()`) and an internal repo are configured with no routing rule — resolution can pick whichever serves a higher version.
- **SAFE**: a `<mirror>` of `*` to the internal repo (all traffic proxied), or Gradle `exclusiveContent`/`repositories` content-filtering (`includeGroup "com.acme"`) binding the internal group to the internal repo only; dependency verification (`gradle/verification-metadata.xml`) with checksums.

### .NET — NuGet
- Manifests: `*.csproj`/`*.fsproj` (`<PackageReference>`), `packages.config`, `Directory.Packages.props`. Config: `nuget.config` (`<packageSources>`, `<packageSourceMapping>`).
- **CANDIDATE**: an internal package referenced while `nuget.config` lists both nuget.org and an internal feed **without** `<packageSourceMapping>` — NuGet may restore the internal name from nuget.org.
- **SAFE**: `<packageSourceMapping>` routes the internal pattern (e.g. `Acme.*`) exclusively to the internal feed; the only configured source is the private feed.

### Go modules
- Manifests: `go.mod`. Config/env: `GOPRIVATE`, `GONOSUMCHECK`/`GONOSUMDB`, `GOPROXY`, `GOINSECURE`, `.netrc`.
- **CANDIDATE**: a private module path (e.g. `git.acme.internal/...` or a vanity import) **not** covered by `GOPRIVATE`/`GONOSUMDB`, so it routes through the public `proxy.golang.org`/sum DB and can be shadowed.
- **SAFE**: the module's prefix is listed in `GOPRIVATE` (bypasses public proxy + checksum DB); `GOPROXY` set to the internal proxy with `direct`/`off` fallback.

### PHP — Composer (Packagist)
- Manifests: `composer.json` (`require`, `repositories`). Lockfiles: `composer.lock`.
- **CANDIDATE**: an internal `vendor/package` required while Packagist remains enabled and no private `repositories` entry (VCS/Composer repo) provides that exact name — Packagist can serve a same-named package.
- **SAFE**: a private `repositories` entry provides the package and `"packagist.org": false` (or canonical/exclude filters) restricts public resolution; `composer.lock` records the private dist URL.

### Rust — Cargo (crates.io)
- Manifests: `Cargo.toml` (`[dependencies]`, `[registries]`). Lockfiles: `Cargo.lock`. Config: `.cargo/config.toml`.
- **CANDIDATE**: an internal crate referenced from the default registry (crates.io) without a `registry = "internal"` qualifier, or an alternate registry configured without the dependency pinned to it.
- **SAFE**: dependency declared with `{ version = "...", registry = "internal-registry" }` and the registry defined in `.cargo/config.toml`; or a `[source]` replacement redirecting crates.io to the internal mirror.

---

## Cross-Ecosystem Candidate Signals

- **Typosquat candidate**: a dependency name within edit-distance 1 of a popular package (`reactt`, `lodahs`, `crossenv` vs `cross-env`, `python-dateutil` vs `python-dateutils`). Flag for manual confirm.
- **Exposed manifest**: any manifest/lockfile/registry-config (`package.json`, `requirements.txt`, `pom.xml`, `composer.json`, `.npmrc`, `pip.conf`, `nuget.config`, etc.) checked into a public webroot or served by the app — leaks the internal names an attacker would claim. Amplifier signal that strengthens a candidate; cross-ref `information_disclosure.md`.

## FALSE POSITIVE Rules

- Namespace/scope is **pinned to a private registry** (npm scope registry, NuGet `packageSourceMapping`, Gradle content filtering / Maven `*` mirror, Go `GOPRIVATE`, Composer Packagist-disabled, Cargo `registry=`, pip `--index-url`-only) → SAFE, drop.
- Lockfile **pins** the dependency to a private source URL with an integrity/checksum → SAFE.
- The name is a **local workspace / path / sibling module** (npm `workspaces`, pnpm/yarn workspaces, Go local `replace`, Composer path repo, Maven reactor module) → not a finding.
- The package is a well-known **public** dependency (not internal) → not in scope for confusion.
- You have **defensively published** a placeholder of the internal name on the public registry under your own ownership → SAFE (this is the recommended mitigation).
- Do NOT assert exploitability or assign Medium+ severity without the out-of-band public-registry ownership check — keep candidates at Informational/Low and flag the verification step.

## Business Risk

- Arbitrary code execution in developer machines and CI/CD via install/build hooks of a substituted public package.
- Supply-chain compromise: poisoned artifacts propagate to every downstream build and deployment.

## Core Principle

A private dependency is safe only when its name/namespace is **bound to a trusted private source** at resolution time. Any internal package that a public registry could serve, with no private pin, is a **dependency-confusion candidate** worth confirming.

---

## Insecure Resolution Channels (Adjacent CWE-829 / CWE-300)

Namespace-confusion / dependency-substitution (CWE-1357) is covered by the candidate heuristics in this reference. **Adjacent supply-chain transport and repository-trust issues** — insecure resolution channels — are detectable separately:

- **Java Maven**: `<repository><url>` using `http://` or `ftp://` (excluding `localhost`) and not disabled (CWE-300, CWE-829)
- **Java Maven**: repository URL containing `.bintray.com` — deprecated host, supply-chain sunset risk (CWE-1104)
- **Ruby Bundler**: gem `source` or `remote` URL using unencrypted protocol (CWE-300, CWE-829)
- **JavaScript**: taint from HTTP URL to download of sensitive file types — executables, archives (CWE-829)
- **JavaScript**: script/import from URL without integrity check (CWE-830)
- **JavaScript**: script/content from domain not on trusted allowlist, no SRI (CWE-830)

**Not covered by automated queries**: npm `@scope` confusion, NuGet `packageSourceMapping` gaps, Go `GOPRIVATE` omissions, pip `--extra-index-url` merging, Composer Packagist shadowing, or Cargo alternate-registry misconfiguration — those are covered only by the candidate heuristics in this reference.

### CWE-829 / CWE-300 — Insecure dependency resolution

**Java Maven sources:** `DeclaredRepository` XML elements in `pom.xml` (and parent POMs via Maven model).

**Java pattern (non-HTTPS repository URL):**
```xml
<repository>
  <url>http://internal.repo/artifacts</url>  <!-- BAD: http:// or ftp:// -->
</repository>
```

**SAFE:** `https://` repository URLs; `localhost` HTTP allowed by regex exception.

**Java Bintray:** any active repository URL matching `%.bintray.com%` — deprecated host, supply-chain sunset risk.

**Ruby pattern:** gem `source` or `remote` URL using non-HTTPS protocol — flags unencrypted gem hosts.

### CWE-829 — Insecure download (JavaScript)

**Sources:** HTTP (non-TLS) URLs from remote/network input.

**Sinks:** download APIs for sensitive file types (executables, archives).

**Sanitizers:** HTTPS URLs; modeled barriers in the download dataflow config.

### CWE-830 — Untrusted source / domain (JavaScript)

**Sinks:** dynamic `<script src=...>`, `import()`, `require()` of remote URLs, and similar inclusion APIs.

**Pattern split:**
- Untrusted source — any remote inclusion without integrity/subresource integrity
- Untrusted domain — URL host not on the trusted-domain allowlist

**Sanitizers:** Subresource Integrity (`integrity=` attribute); trusted domain allowlist.

**BAD (conceptual):**
```html
<script src="http://cdn.example.com/lib.js"></script>  <!-- no integrity, HTTP -->
```

**SAFE:**
```html
<script src="https://cdn.example.com/lib.js"
        integrity="sha384-..." crossorigin="anonymous"></script>
```

### Candidate vs transport-issue triage

| This reference (candidate) | Confirmed transport/repo issue |
|---|---|
| `@acme/pkg` with no scope registry pin | not detected — manual registry lookup required |
| Internal gem via `source "http://rubygems.org"` only | not detected — unless gem *host* URL is HTTP |
| Maven resolves from HTTP internal repo | non-HTTPS Maven repository URL |
| Build still points at Bintray | Bintray repository URL present |
| Runtime `fetch('http://.../tool.bin')` in CI script | insecure download of sensitive file |

### Common False Alarms

- **Maven non-HTTPS URL:** `localhost` HTTP repos excluded — CI mirror on `127.0.0.1` not flagged; production HTTP repos are.
- **Bintray dependency:** flags URL presence, not whether artifacts are actually resolved from Bintray today.
- **Untrusted source vs domain:** intentionally split — same script may trigger one but not the other depending on allowlist.
- **No substitution detection:** a perfectly HTTPS-configured project remains vulnerable to public-registry shadowing of internal names — keep candidate severity at Informational until registry ownership check.
- **Insecure download:** requires sensitive-file download sink — generic `npm install` / `mvn dependency:get` not covered.
