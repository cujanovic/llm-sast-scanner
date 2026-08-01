---
name: supply_chain_security
version: "0.2"
description: Software supply-chain weaknesses — unpinned dependencies, missing integrity, lifecycle scripts, typosquatting, outdated packages, missing SRI, untrusted registries, lockfile drift, provenance gaps, and build-time asset-pipeline code execution (CSS preprocessor loaders — Less `@plugin`/`javascriptEnabled` — that evaluate package-controlled stylesheets as code at compile time, bypassing install-time `--ignore-scripts`/lifecycle-off hardening and `.js`-only SCA)
---

# Software Supply Chain Security

Third-party packages, lockfiles, install hooks, and externally loaded scripts are primary trust boundaries. Attackers abuse mutable versions, missing checksums, install-time scripts, and unverified CDN assets to run code in developer, CI, and client environments.

*The core pattern: a dependency or external script is resolved, installed, or executed without deterministic pinning, integrity verification, registry trust controls, or provenance attestation — allowing substitution, tampering, or silent upgrades.*

## What It Is (and Is Not)

**What it IS**
- **Unpinned / unlocked dependencies**: semver ranges (`^`, `~`, `>=`), floating tags (`latest`, `*`), or manifests without a committed lockfile — resolver picks different artifacts per install
- **Missing integrity hashes**: lockfile entries without `integrity`/`checksum`/`sha256`/`hash` fields; pip requirements without `--require-hashes`; Docker/npm installs without digest pinning
- **Typosquatting exposure**: dependency names within edit distance of popular packages (`lodahs`, `crossenv`, `python-dateutils`) or copy-pasted install commands from untrusted sources
- **Malicious lifecycle scripts**: `preinstall`/`postinstall`/`prepare`/`prepublish` in third-party or first-party `package.json` that execute shell/node at install time
- **Install-time code execution enabled**: CI/Docker uses `npm install` (not `npm ci`), no `--ignore-scripts`, no `.npmrc` `ignore-scripts=true`
- **Build-time asset/preprocessor code execution**: a build tool's loader *evaluates* package-controlled non-`.js` content as code at **compile** time — most notably CSS preprocessors. Less honors `@plugin "./mod.js"` (loads and executes a JS module, **even with `javascriptEnabled: false`**) and `javascriptEnabled: true` (inline backtick JavaScript). Reached transitively through a stylesheet `@import` of a `node_modules`/dependency `.less`, so a single compromised Less-shipping dependency = arbitrary code on the dev/CI host at `npm run build`/`ng build`. Runs at build, not install, so `--ignore-scripts`, pnpm/yarn lifecycle-off, and `.js`-extension-only SCA scanners **all miss it**; no ecosystem guidance treats `@import` as a trust boundary. (Sass/dart-sass is **not** affected — see False Alarms.)
- **Outdated / known-vulnerable dependencies**: pinned versions with published CVEs; no SCA step in CI; audit disabled or ignored on high/critical
- **Missing Subresource Integrity (SRI)**: third-party `<script src="https://...">` or `<link rel="stylesheet">` without `integrity=` and `crossorigin`
- **Untrusted registries**: `.npmrc`/`pip.conf`/`nuget.config` pointing at HTTP mirrors, wildcard `registry=`, or public registry as default for all scopes without allowlist
- **Lockfile tampering / drift**: `package.json`/`pyproject.toml`/`Cargo.toml` changed without matching lockfile update; CI does not verify lockfile consistency; lockfile excluded from review gates
- **Provenance / signing gaps**: no SBOM generation, no artifact signature verification at deploy, no digest-pinned container/base images in build manifests

**What it is NOT**
- **Dependency confusion / namespace shadowing** — internal names resolvable from public registries; see `dependency_confusion.md`
- **CI workflow PPE, mutable action tags, Dockerfile root** — see `cicd_container_security.md` unless the finding is manifest/lockfile/install-hook specific
- **Hardcoded malicious payloads in app source** — see `hardcoded_code_backdoor.md`
- **Runtime fetching of packages from user input** — see `rce.md` / `ssrf.md`; here focus on build-time resolution and static HTML includes
- **Confirmed CVE exploitability in application code paths** — flag outdated dep as supply-chain hygiene; triage reachability separately (see *Dependency CVE Exploitability Triage* below)

## Recon Indicators

### Manifests and lockfiles

| Signal | Grep / structural targets |
|--------|----------------------------|
| Node manifests | `package.json` (`dependencies`, `devDependencies`, `scripts`), `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `.npmrc`, `.yarnrc.yml` |
| Python | `requirements*.txt`, `pyproject.toml`, `Pipfile`, `poetry.lock`, `Pipfile.lock`, `pip.conf`, `pip.ini` |
| Java / .NET / Go / Rust / Ruby / PHP | `pom.xml`, `build.gradle*`, `*.csproj`, `go.mod`, `go.sum`, `Cargo.toml`, `Cargo.lock`, `Gemfile`, `Gemfile.lock`, `composer.json`, `composer.lock` |
| Floating versions | `"[^"]+":\s*"\^`, `"[^"]+":\s*"~`, `"[^"]+":\s*"\*"`, `"[^"]+":\s*">="`, `latest`, `master`, `main` in dependency fields |
| Missing lockfile | `package.json` present, no `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml`; `requirements.txt` with unpinned lines and no hash block |
| Missing integrity | npm lock entry without `"integrity":`; yarn lock without checksum block; pip file without `--hash=sha256:` |
| Lifecycle scripts | `"preinstall"`, `"postinstall"`, `"prepare"`, `"prepublish"`, `"install"` under `"scripts"` in any `package.json` (app or `node_modules` vendor review) |
| Registry config | `registry=http://`, `registry=*`, missing scope pins for private-looking `@scope/` packages |
| Typosquat candidates | dependency names 1–2 edits from top packages in same manifest |

### CI / install commands

| Signal | Grep / structural targets |
|--------|----------------------------|
| Non-deterministic install | `npm install\b` (not `npm ci`), `yarn install` without `--frozen-lockfile`, `pnpm install` without `--frozen-lockfile` |
| Scripts allowed | absent `--ignore-scripts`; no `ignore-scripts=true` in `.npmrc` |
| Lockfile not enforced | no step comparing manifest to lockfile; `package-lock.json` in `.gitignore` |
| No SCA gate | no `npm audit`, `pip-audit`, `cargo audit`, `govulncheck`, Dependabot/Renovate config, or audit failures ignored |
| Lockfile-only drift | staged `package.json` without corresponding lockfile in same commit/PR |
| Build-time preprocessor code-exec | `javascriptEnabled\s*:\s*true` in `less-loader`/`less.render`/`lessOptions`; `@plugin\b` in any `*.less` (esp. under `node_modules`/vendored deps); Less compile config lacking `disablePluginRule: true`; `.less` `@import` reaching a dependency stylesheet |

### HTML / frontend static assets

| Signal | Grep / structural targets |
|--------|----------------------------|
| External scripts | `<script\s+[^>]*src=["']https?://` without `integrity=` |
| External styles | `<link[^>]+href=["']https?://[^"']+\.css` without `integrity=` |
| CDN without SRI | `cdn.`, `unpkg.com`, `jsdelivr`, `googleapis.com` script/link tags missing `crossorigin` + `integrity` |

### Example grep one-liners

```bash
rg -n '"\^|"~|": "\*"|": "latest"' package.json pyproject.toml requirements*.txt
rg -n 'preinstall|postinstall|prepare|prepublish' **/package.json
rg -n 'npm install[^-]|yarn install(?!.*frozen)' .github/workflows/ Dockerfile* **/*.sh
rg -n '<script[^>]+src=.*https?://' --glob '*.html' --glob '*.tsx' --glob '*.jsx' | rg -v integrity=
rg -n 'registry=http://|ignore-scripts\s*=\s*false' .npmrc **/.npmrc
rg -n 'javascriptEnabled\s*:\s*true|less-loader|less\.render|disablePluginRule' --glob '*.{js,ts,mjs,cjs,json}'
rg -n '@plugin\b|`.*`' --glob '*.less'   # @plugin loads JS at compile time; backticks = inline JS
```

## Vulnerable Conditions

- Production or CI install uses semver ranges with no committed lockfile — builds are non-reproducible
- Lockfile exists but entries lack integrity/checksum fields for tarball artifacts
- `package.json` declares `postinstall`/`prepare` running shell commands; third-party deps not vetted; `--ignore-scripts` not used in CI
- CI pipeline runs `npm install` instead of `npm ci` / frozen lockfile equivalent after checkout
- Manifest lists dependency within typosquat distance of a widely used package and no lockfile pins exact resolved name/version
- `requirements.txt` or `pip install -r` without pinned versions and without `--require-hashes`
- HTML templates load analytics/JS libraries from third-party hosts with no `integrity` attribute
- `.npmrc` sets global `registry` to HTTP or to public registry with no scope allowlist for internal-looking packages
- `package.json` version bumps without lockfile update in same changeset; CI does not fail on lockfile mismatch
- Deploy/build pulls `:latest` images or unpinned base tags with no digest or signature verification step
- Known CVE affects pinned dependency version and no compensating control or upgrade path documented in repo
- **Auto-update / firmware / package installer verifies the signature but not the *version* (no anti-rollback)** — an update client that checks only a signature/hash over the artifact, with no monotonic-version enforcement, lets an attacker serve or replay an **older, still-validly-signed** release to force a **downgrade** to a known-vulnerable version. Signals: an updater that records/compares no minimum-or-monotonic version before applying (signature/`SHA-256` check on the file while the version field is unsigned or unchecked); a signature that covers the payload but not the version/metadata; shared signing keys across release channels (a dev/beta-signed build accepted by prod). Fix: sign the version **together with** the artifact and reject any version ≤ the installed one (monotonic/anti-rollback counter); use separate per-channel signing keys
- **Build-time CSS-preprocessor code execution (compile-time supply-chain RCE that install-time hardening does not cover)** — a build tool compiles Less at bundle time, including stylesheets reached transitively via `@import` from `node_modules`, using a configuration that leaves Less's JavaScript primitives on. Two sinks, either sufficient: **(a)** `@plugin "./mod.js";` inside any compiled `.less` — Less `require()`s and runs the module's top-level code at compile time, and this fires **regardless of `javascriptEnabled`**; **(b)** `javascriptEnabled: true` (e.g. hardcoded in `@angular-devkit/build-angular`'s `less-loader` options, or set for antd-style theme math) — inline backtick JS in a `.less` expression executes. A compromised or typosquatted dependency that ships a crafted `.less` (or a malicious first-party `.less`) therefore gets arbitrary code on every developer and CI machine during `npm run build`/`ng build`, with impact = whatever the build identity holds: `GITHUB_TOKEN`/`NPM_TOKEN`/cloud creds in CI env, `~/.npmrc`/`~/.aws/credentials` on disk, and **artifact poisoning** — a library built with `ng-packagr` re-emits the payload into its published stylesheet surface, reaching every downstream consumer. **Why the usual defenses miss it:** execution is at *build*, so `--ignore-scripts`, pnpm `onlyBuiltDependencies`, and Yarn Berry `enableScripts:false` never fire (there is no lifecycle event), and SCA/secret scanners that content-inspect only `.js`/`package.json` never parse `.less`. **Mitigation and its trap:** set `disablePluginRule: true` **and** `javascriptEnabled: false` (recover theme math with `math: 'always'`) on **every** Less invocation (`less-loader`, `less.render`, `ng-packagr`). But `disablePluginRule` has a **propagation gap** — Less installs the guard only on the entry stylesheet and does **not** re-apply it to `@import`-ed files — so the realistic transitive-dependency shape (the `@plugin` sits in `node_modules/**/*.less`) still fires; pair the flag with a content scrub in the loader's file resolver (`loadFile`) that strips comments+strings then rejects `@plugin` on **every** file it loads. **Severity: High–Critical** (build/CI RCE, CVSS Scope: Changed). Signals: `javascriptEnabled: true` anywhere in a Less build; any `@plugin` in a `.less` (especially vendored/`node_modules`); a Less compile of dependency stylesheets with no `disablePluginRule` + no content scrub. Do **not** flag Sass/`.scss` this way (Sass runs JS only via consumer-registered functions — see False Alarms).

## Safe Patterns

**Deterministic resolution**
- Commit lockfiles for all deployable apps; pin exact versions or digests in manifests where lockfiles are unsupported
- CI uses frozen installs: `npm ci`, `yarn install --frozen-lockfile`, `pnpm install --frozen-lockfile`, `poetry install --sync`, `cargo fetch` + locked `Cargo.lock`
- Fail build when manifest and lockfile diverge

**Integrity and registry trust**
- Lock entries include package integrity hashes; pip uses `--require-hashes` or hash-pinned lock formats
- Scope private namespaces to trusted registries in `.npmrc` / ecosystem equivalent; disallow HTTP registry URLs
- Pin container and vendored assets by digest (`@sha256:...`) where applicable

**Install script hygiene**
- Default `ignore-scripts=true` in CI `.npmrc`; enable scripts only for vetted internal packages
- Review any first-party `scripts` hooks; prefer build-time steps over install-time execution

**Third-party script loading**
- Add SRI + `crossorigin="anonymous"` on every external script/stylesheet; monitor vendor updates for hash rotation

**Vulnerability and provenance**
- Run SCA on every build; block or gate on critical/high per policy
- Generate and store SBOM with artifacts; verify signatures/provenance before deploy when platform supports it

```json
{
  "dependencies": {
    "lodash": "4.17.21"
  },
  "scripts": {}
}
```

```json
{
  "name": "lodash",
  "version": "4.17.21",
  "resolved": "https://registry.example/lodash/-/lodash-4.17.21.tgz",
  "integrity": "sha512-..."
}
```

```ini
ignore-scripts=true
@myorg:registry=https://npm.internal/
```

```yaml
- run: npm ci --ignore-scripts
  working-directory: app
```

```html
<script src="https://cdn.example.com/lib.js"
        integrity="sha384-MBO5IDfYaE6c6Aao94oZrIOiC7CGiSNE64QUbHNPhzk8Xhm0djE6QqTpL0HzTUxk"
        crossorigin="anonymous"></script>
```

## Examples

### Unpinned semver range

```json
{
  "dependencies": {
    "express": "^4.18.0"
  }
}
```

### Missing lockfile integrity

```json
{
  "packages": {
    "node_modules/foo": {
      "version": "1.2.3"
    }
  }
}
```

### Lifecycle script at install

```json
{
  "scripts": {
    "postinstall": "node scripts/setup.js && curl -fsSL https://vendor.example/install.sh | sh"
  }
}
```

### Non-deterministic CI install

```yaml
- run: npm install && npm run build
```

### Build-time preprocessor code execution (Less `@plugin` / inline JS)

```js
// VULN: less-loader compiles node_modules .less with JS primitives left on.
//       A compromised dep shipping `@plugin`/backtick-JS in a .less → build-time RCE,
//       and --ignore-scripts / lifecycle-off do NOT stop it (runs at build, not install).
{
  loader: 'less-loader',
  options: { lessOptions: { javascriptEnabled: true, paths: ['node_modules'] } },
}
```

```less
/* VULN: either line runs code when this .less is compiled */
@plugin "./palette.js";                 /* loads + executes JS — fires even if javascriptEnabled:false */
.brand { width: `process.mainModule.require('child_process').execSync('id')`; }
```

```js
// SAFE: disable both primitives; recover theme math via `math`. Because disablePluginRule
//       only guards the ENTRY stylesheet, also scrub every loaded file for @plugin.
{
  loader: 'less-loader',
  options: { lessOptions: { javascriptEnabled: false, math: 'always', disablePluginRule: true } },
  // + resolver.loadFile scrub: strip comments/strings, reject /@plugin\b/ on EVERY imported file
}
```

### Typosquat candidate

```json
{
  "dependencies": {
    "crossenv": "7.0.3"
  }
}
```

### Missing SRI on third-party script

```html
<script src="https://cdn.example.com/analytics.js"></script>
```

### SRI/integrity present but unenforced (fail-open verification)

Worse than a *missing* `integrity=` is one that is **present but never actually enforced** — reviewers see the attribute and assume the control works. Treat the verifier itself as suspect:
- **Malformed/unparseable hash → load proceeds**: a custom integrity check (or a fetch wrapper) that, on a hash it cannot parse (wrong prefix, truncated, unknown algorithm), logs and continues instead of rejecting. The defender ships a valid-looking `sha384-…`; an attacker who can influence the hash string makes it unparseable to *disable* the check rather than fail the load.
- **Empty/absent algorithm treated as "no check required"**: `if (expected) verify(...)` where `expected` is empty/`null` for the very entry an attacker controls.
- **SRI without `crossorigin`**: the resource loads opaque and the integrity check is silently skipped by the browser.

```javascript
// VULN: unknown/empty hash format → verification skipped, content trusted
const ok = expectedHash ? sriMatches(expectedHash, body) : true; // fail-open
if (ok) execute(body);

// SAFE: require a well-formed hash and a successful match; otherwise reject
if (!isWellFormedSri(expectedHash) || !sriMatches(expectedHash, body)) throw new Error('integrity check failed');
execute(body);
```

### Untrusted HTTP registry

```ini
registry=http://mirror.local/npm/
```

### Lockfile drift

```diff
# package.json bumped, package-lock.json unchanged in same PR
-    "axios": "1.6.0"
+    "axios": "1.7.0"
```

### Outdated vulnerable pin (hygiene signal)

```json
{
  "dependencies": {
    "minimist": "0.0.8"
  }
}
```

## Dependency CVE Exploitability Triage (reachability)

A dependency appearing in the tree with a known CVE/GHSA is **not** proof the project is exploitable. "The lib is present, therefore we are vulnerable" is the most common false positive in software-composition findings. Before raising a dependency CVE to a real bug, triage whether the *vulnerable code path* is actually reached in this project, with attacker-influenced input, under a configuration that enables it.

**Triage questions (answer in order; stop at the first that resolves the verdict):**

1. **Is the vulnerable symbol reachable?** Identify the specific vulnerable function/class/endpoint named in the advisory (not just the package). Grep the codebase for calls to it — directly and through wrappers, re-exports, framework auto-wiring, or reflection/DI. If nothing in the app (or its reachable transitive deps) ever calls it, the finding trends toward *not affected*.
2. **Is it transitively pulled but pruned?** A vulnerable package can be a declared dep yet excluded from the shipped artifact (dev/test-only scope, tree-shaken, optional feature flag off, platform-specific dependency not built). Confirm it is in the production runtime, not just the lockfile.
3. **Can attacker input reach it?** Apply the normal source→sink rules: is there a path from an untrusted source to the vulnerable API, or is it only ever called with constant/internal data?
4. **Is the vulnerable configuration enabled?** Many CVEs require a non-default setting (e.g. a parser feature, a deserialization mode, a specific protocol). If the project disables it, the advisory may not apply to this build.

**Record a verdict** for each triaged advisory so it is not re-investigated every scan:

- `affected` — vulnerable path reachable from attacker-controlled input under the project's config. Treat as a real finding and remediate (upgrade/patch/mitigate).
- `not_affected` — with a concrete justification class: *vulnerable code not present / not reachable*, *not in runtime artifact (dev-only or pruned)*, *requires config that is disabled*, or *input is never attacker-controlled*.
- `under_investigation` — reachability could not be determined. In a read-only or sandboxed context without package-manager/grep execution you can usually only read the lockfile/SBOM, so most reachability questions default here — state that limitation explicitly rather than guessing `not_affected`.

This triage reduces dependency-scan noise without ignoring it: a `not_affected` verdict still leaves the outdated pin as a hygiene signal (upgrade opportunistically), it just is not an exploitable-bug finding. Keep the SCA reachability verdict separate from first-party taint findings.

## Common False Alarms

- Semver range in `package.json` **with** committed lockfile pinning exact resolved version and CI uses frozen install — manifest range alone is not a finding
- `postinstall` in **root** monorepo workspace that only runs vetted internal bootstrap — review script body; do not flag solely on key name
- `npm install` in **local dev** docs or one-off contributor setup scripts not used in CI/deploy path — lower severity; note hygiene recommendation
- External script from **same-origin** first-party static host — SRI still recommended but not third-party supply-chain equivalent
- SRI hash stale after vendor CDN update — operational maintenance, not absence of SRI control
- `ignore-scripts=true` breaks native addon build — team may selectively re-enable for known packages; flag only when scripts run globally on untrusted deps in CI
- Typosquat candidate that is a **legitimate differently named package** with established registry metadata — confirm name intent manually
- Lockfile in `.gitignore` for **published library** packages (consumers lock transitively) — flag for apps/services, not always for pure libraries
- Renovate/Dependabot PR with intentional version bump — not tampering; verify paired lockfile update instead
- CVE in devDependency not in production bundle — downgrade unless dev tool runs in CI with secrets or ships to users
- Internal registry URL using private CA HTTPS — not the same as cleartext HTTP registry
- **Sass/SCSS (dart-sass) compilation** — Sass exposes JavaScript only through *consumer-registered* custom functions; imported `.scss`/`.sass` cannot load or execute JS from stylesheet syntax (`@use`/`@import`/`@forward` are inert as code-loaders). Do **not** flag `.scss`/`sass-loader` builds as build-time-preprocessor RCE — Less is the outlier, not "all preprocessors."
- **Less compiling only first-party, reviewed `.less` with no `@import` of `node_modules`/dependency stylesheets** — with the entire import graph first-party and trusted, `@plugin`/`javascriptEnabled` are a build-hardening recommendation, not an exploitable supply-chain path; downgrade severity (still note them as unnecessary build-time code authority). The finding becomes exploitable the moment the compiled graph includes any dependency-shipped `.less`.

## Cross-References

- `dependency_confusion.md` — public-registry shadowing of internal package names (namespace/substitution attacks)
- `cicd_container_security.md` — pipeline tokens, mutable CI actions, Dockerfile image pinning
- `hardcoded_code_backdoor.md` — obfuscated payloads inside dependencies after compromise
- `rce.md` — the code-execution sinks the build-time preprocessor path reaches (JS run by Less `@plugin`/inline backtick JS at compile time); build-time vs runtime execution boundary
- `information_disclosure.md` — manifests/lockfiles exposed via public webroot leak dependency intelligence
- `ml_supply_chain_poisoning.md` — AI/ML model & dataset supply chain: unsafe model deserialization (pickle/`torch.load`), `trust_remote_code=True`, unverified models/adapters, unpinned ML deps, training-data poisoning
