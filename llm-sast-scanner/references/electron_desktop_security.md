---
name: electron_desktop_security
description: Electron / desktop web-runtime hardening detection — BrowserWindow/BrowserView webPreferences misconfiguration (nodeIntegration / contextIsolation / sandbox / webSecurity / enableBlinkFeatures), unsafe preload contextBridge & ipcMain handlers, unrestricted navigation / window-open / will-attach-webview, shell.openExternal with untrusted input, missing/permissive permission handler (Electron auto-approves camera/mic/clipboard/geolocation by default with no setPermissionRequestHandler/setPermissionCheckHandler/setDevicePermissionHandler), certificate-error / setCertificateVerifyProc TLS opt-out, dangerous Chromium/Node command-line switches, custom protocol handlers, and insecure auto-update (cleartext/attacker feed URL, missing publisher-signature verification, downgrade/rollback, verify-vs-install TOCTOU) (CWE-1188/CWE-829/CWE-94/CWE-79/CWE-295/CWE-494)
---

# Electron / Desktop App Security

Desktop apps built on a web runtime (Electron, and the same shapes in NW.js / CEF embeddings) run attacker-reachable web content next to full OS-level Node/native APIs. The security model depends entirely on keeping the renderer (untrusted web content) isolated from the main process (trusted Node). The dangerous pattern is *a renderer that can load or be influenced by untrusted content while the process/window configuration removes the isolation that would contain it* — turning an XSS or a malicious page into local code execution, file read/write, or SSRF.

This is a static-config + sink class: the decisive evidence is in the `BrowserWindow`/`webPreferences` options, the preload bridge surface, the IPC handlers, and the navigation/`shell` sinks — all readable from source.

## Source -> Sink Pattern

**Sources (untrusted content reaching the renderer)**
- `loadURL(...)` / `<webview src>` / `<iframe>` pointing at a remote origin, or any origin that can be navigated away from a bundled page
- Reflected/stored web content rendered in the window (in-app XSS becomes process-level once isolation is off)
- IPC messages from the renderer: `ipcMain.handle(channel, (e, arg) => ...)` / `ipcMain.on(...)` where `arg` is renderer-controlled
- Deep-link / protocol-handler payloads: `app.setAsDefaultProtocolClient(...)` + the `open-url` (macOS) / `second-instance` (Win/Linux) argv URL

**Sinks**
- `new BrowserWindow({ webPreferences: { ... } })` with isolation-disabling flags (see below)
- `webContents.loadURL(userControlledUrl)` / `webContents.executeJavaScript(untrusted)`
- `contextBridge.exposeInMainWorld(name, api)` exposing raw `ipcRenderer`/`require`/`fs`/`child_process` or an unfiltered `invoke`
- IPC handler bodies that pass renderer args into `fs.*`, `child_process.exec/spawn`, `shell.openPath`, dynamic `require`, or SQL
- `shell.openExternal(userInput)` / `shell.openPath(userInput)`
- Missing `will-navigate` / `setWindowOpenHandler` guards on `webContents`

**Sanitizers / barriers**
- `contextIsolation: true` (default since Electron 12) **and** `nodeIntegration: false` (default since 5) **and** `sandbox: true`
- Preload exposes only narrow, parameter-validated functions over a fixed channel allowlist — never raw `ipcRenderer`/modules
- Navigation locked to an allowlist of trusted origins; `setWindowOpenHandler` returns `{ action: 'deny' }` for anything else
- `shell.openExternal` called only after scheme allowlist (`https:` / `mailto:`) validation
- Content rendered is **bundled local content only** (`file://` / `app://`) with no remote navigation possible

---

## Vulnerable Conditions (any match)

### 1. BrowserWindow / webPreferences misconfiguration
The renderer's isolation is removed, so any web content (or in-app XSS) reaches Node / OS APIs.

```js
// VULN — Node exposed to a window that loads remote content -> XSS == RCE
const win = new BrowserWindow({
  webPreferences: {
    nodeIntegration: true,        // renderer gets require()/process/Buffer
    contextIsolation: false,      // preload + page share one JS world (prototype-pollution into Node)
    sandbox: false,               // no OS sandbox on the renderer
  },
});
win.loadURL('https://content.example.com/app');   // remote/untrusted origin
```

```js
// VULN — disables same-origin policy and TLS/cert enforcement in the renderer
new BrowserWindow({ webPreferences: { webSecurity: false, allowRunningInsecureContent: true } });
// webSecurity:false defeats SOP and certificate checks -> SSRF / local file read / MITM
// cross-ref certificate_validation.md, ssrf.md
```

Flag any of these in `webPreferences`: `nodeIntegration: true`, `nodeIntegrationInWorker: true`, `nodeIntegrationInSubFrames: true`, `contextIsolation: false`, `sandbox: false`, `webSecurity: false`, `allowRunningInsecureContent: true`, `experimentalFeatures: true`, `enableBlinkFeatures`/`blinkFeatures` (turns on off-by-default Blink features that widen attack surface), or `enableRemoteModule: true` (legacy `@electron/remote`). The same options apply to `BrowserView` and (deprecated) `webview`. Severity escalates to RCE when the same window can load or navigate to non-bundled content.

**`affinity` — shared renderer process across windows (isolation collapse).** `new BrowserWindow({ webPreferences: { affinity: 'x' } })` (and `BrowserView`) makes every window/view with the **same `affinity` string share one renderer process**. Two consequences: (1) a **higher-privileged** window's `webPreferences` (e.g. `nodeIntegration`/`sandbox`) can be inherited by the shared process, so a **lower-trust** page sharing that affinity is effectively upgraded; (2) a compromise (XSS) in *any* window on that affinity gains the same-process context of the others (shared JS realm/globals). It's **version-dependent** — the process-model semantics differ pre- vs post-Electron-v14 (`affinity` was deprecated/removed as the process model changed), so the same code is safe or unsafe by version (determine the `electron` version before judging). **Flag**: an `affinity` shared by windows that load content of *differing trust levels*, or any `affinity` combined with a permissive `webPreferences`.
- **`ELECTRON_DISABLE_SECURITY_WARNINGS` set (`= true`/`"1"` in `process.env`, `.env`, or a `Dockerfile`/CI env)** suppresses Electron's built-in DevTools console warnings (insecure CSP, `nodeIntegration` with remote content, insecure resources, etc.) — low severity itself, but it **hides the very misconfigurations above** from developers; treat its presence as a signal to scrutinize the webPreferences/CSP more closely.

### 2. Unsafe preload bridge (contextBridge / exposeInMainWorld)
Even with `contextIsolation: true`, a preload that hands the page a powerful primitive re-opens the boundary.

```js
// VULN — raw ipcRenderer / modules exposed to the page; any XSS can call anything
contextBridge.exposeInMainWorld('api', {
  ipc: ipcRenderer,                         // full send/invoke surface
  readFile: (p) => require('fs').readFileSync(p),   // arbitrary file read from web content
  run: (cmd) => require('child_process').exec(cmd), // arbitrary command exec
});
```

```js
// SAFE — narrow, validated functions over a fixed channel allowlist
const ALLOWED = new Set(['settings:get', 'doc:save']);
contextBridge.exposeInMainWorld('api', {
  getSettings: () => ipcRenderer.invoke('settings:get'),
  saveDoc: (id, text) => {
    if (typeof id !== 'string' || typeof text !== 'string') throw new Error('bad args');
    return ipcRenderer.invoke('doc:save', { id, text });
  },
});
```

### 3. IPC handlers trusting renderer input
The main process is trusted, but its IPC handlers receive untrusted renderer data. Treat the renderer arg as tainted (cross-ref `trust_boundary.md`, `rce.md`, `path_traversal_lfi_rfi.md`).

```js
// VULN — renderer-controlled path/command reaches OS sinks with no validation
ipcMain.handle('file:read', (_e, p) => fs.readFileSync(p, 'utf8'));        // path traversal
ipcMain.handle('tool:run', (_e, name) => child_process.exec(name));         // command injection
ipcMain.handle('open', (_e, target) => shell.openPath(target));             // arbitrary open
```

```js
// SAFE — validate/allowlist and resolve within a base dir before the sink
ipcMain.handle('file:read', (_e, name) => {
  if (!/^[\w.-]+$/.test(name)) throw new Error('invalid name');
  const base = app.getPath('userData');
  const full = path.resolve(base, name);
  if (!full.startsWith(base + path.sep)) throw new Error('traversal');
  return fs.readFileSync(full, 'utf8');
});
```

### 4. Unrestricted navigation / window-open / webview
Without guards, attacker content can navigate the trusted window or spawn child windows with inherited privileges.

```js
// VULN — no navigation allowlist; page can move to attacker origin (then abuse exposed APIs)
win.webContents.loadURL(userControlledUrl);
// VULN — <webview allowpopups> and missing will-navigate / setWindowOpenHandler guards
```

```js
// SAFE — deny untrusted navigation and external windows
const ALLOW = new Set(['https://app.example.com']);
win.webContents.on('will-navigate', (e, url) => {
  if (!ALLOW.has(new URL(url).origin)) e.preventDefault();
});
win.webContents.setWindowOpenHandler(({ url }) => {
  if (ALLOW.has(new URL(url).origin)) return { action: 'allow' };
  return { action: 'deny' };   // open externals via shell.openExternal after scheme check
});
```

Also flag a `will-attach-webview` handler that **re-enables** Node in attached `<webview>` frames (or fails to strip a renderer-supplied `preload`):

```js
// VULN — forces nodeIntegration back on for every embedded <webview>
app.on('web-contents-created', (_e, contents) => {
  contents.on('will-attach-webview', (_evt, webPreferences) => {
    webPreferences.nodeIntegration = true;        // re-opens the boundary for guest content
  });
});
// SAFE — strip privileges/preload from guests: delete webPreferences.preload;
//        webPreferences.nodeIntegration = false; and verify params.src is allowlisted
```

### 5. shell.openExternal / openPath / showItemInFolder + other main-process APIs exposed to the renderer
`shell.openExternal` hands the string to the OS, so non-`http(s)` schemes (e.g. `file:`, custom protocol handlers, on Windows `.url`/`.lnk`/SMB paths) can launch programs or fetch internal resources.

Other main-process APIs are just as dangerous when reachable from renderer input (directly, via `contextBridge`, or via an IPC handler that forwards the arg):
- **`shell.showItemInFolder(path)`** — reveals a file in the OS file manager, but the underlying handler can *execute*: on Linux it shells out via `xdg-open <dir>` (TOCTOU — swap the dir for an executable between check and launch), and on Windows the `SHOpenFolderAndSelectItems` fallback is `ShellExecute(..., "open", dir, ...)` which launches the associated app/executable. Treat a user-controlled `showItemInFolder` path like `openPath`.
- **`remote.app.*` (or IPC that reaches `app`) → RCE / persistence** — `app.relaunch({ execPath, args })` + `app.exit()` runs an **arbitrary executable**; `app.setLoginItemSettings({ path, args })` and `app.setAsDefaultProtocolClient(scheme, execPath, args)` and (Windows) `app.setJumpList`/`setUserTasks`, (macOS) `app.moveToApplicationsFolder` establish **persistence/hijack**. If the deprecated `remote` module (or a preload that re-exposes `app`) is reachable from a compromised renderer, these are direct RCE/persistence sinks — not just "info leak."
- **`systemPreferences.getUserDefault(key,type)` / `subscribeNotification()` (macOS)** exposed to the renderer leaks host data — `getUserDefault("NSNavRecentPlaces",...)` (recent file paths), geographic/timezone keys; `subscribeNotification`/`subscribeWorkspaceNotification` (esp. with a `nil`/broad name) sniffs system-wide events (screen lock, device attach, app launches). Cross-ref `information_disclosure.md`. **SAFE**: never bridge these to the renderer; expose only a fixed, argument-validated IPC verb for the exact narrow action needed.

```js
// VULN — untrusted URL/scheme passed straight to the OS handler
ipcMain.handle('open-link', (_e, url) => shell.openExternal(url));
```

```js
// SAFE — allowlist the scheme before opening
function openSafe(raw) {
  const u = new URL(raw);                       // throws on garbage
  if (u.protocol !== 'https:' && u.protocol !== 'mailto:') throw new Error('blocked scheme');
  return shell.openExternal(u.toString());
}
```

### 6. Permissive / missing permission handler (Electron auto-approves by default)
**Unlike a browser, Electron's *default* is to auto-approve every Chromium permission request** — with **no handler registered at all**, any loaded page silently gets `media` (camera/microphone), `geolocation`, `notifications`, `clipboard-read`, `idle-detection`, `local-fonts`, `midi`, `display-capture`, etc. So the **absence** of `setPermissionRequestHandler` is not merely "missing defense in depth" — it is the affirmative vulnerable state: a compromised/hijacked renderer (XSS, unsafe navigation, remote/`<webview>` content, a sub-frame) obtains those capabilities with no prompt. A `setPermissionRequestHandler` that calls back `true` unconditionally (or lacks an origin+permission check) is the same bug written explicitly. Two sibling handlers are also off by default: **`setPermissionCheckHandler`** governs synchronous checks (`navigator.permissions.query`, `getUserMedia` capability probes), and **`setDevicePermissionHandler`** governs device selection for **WebUSB / Web Serial / WebHID / Web Bluetooth** — a window loading untrusted content without all three that it needs is exposed.

```js
// VULN — NO handler at all: Electron auto-approves every permission request by default
const win = new BrowserWindow(); win.loadURL(remoteOrUntrustedUrl);   // camera/mic/clipboard/geo all grantable
// VULN — explicit form: every permission auto-granted regardless of origin or type
session.defaultSession.setPermissionRequestHandler((wc, permission, cb) => cb(true));
```

```js
// SAFE — allowlist by origin + permission
session.defaultSession.setPermissionRequestHandler((wc, permission, cb) => {
  const ok = new URL(wc.getURL()).origin === 'https://app.example.com'
    && ['notifications'].includes(permission);
  cb(ok);
});
```

### 7. Dangerous Chromium / Node command-line switches
Security-disabling switches passed via `app.commandLine.appendSwitch`/`appendArgument` (main process) or baked into `package.json` `scripts`/`config` (the launch command) silently turn off protections process-wide. Treat the presence of any of these as a finding regardless of taint.

```js
// VULN — disables web security / TLS validation / sandbox / opens a debug port
app.commandLine.appendSwitch('disable-web-security');
app.commandLine.appendSwitch('ignore-certificate-errors');
app.commandLine.appendSwitch('no-sandbox');
app.commandLine.appendSwitch('remote-debugging-port', '9222');   // arbitrary local code exec via DevTools protocol
```

Dangerous switch substrings (also as `--flag` in `package.json` `scripts`/`config`, or in `additionalArguments`): `disable-web-security`, `ignore-certificate-errors`(`-spki-list`), `ignore-urlfetcher-cert-requests`, `allow-running-insecure-content`, `allow-file-access-from-files`, `enable-local-file-accesses`, `no-sandbox`, `allow-no-sandbox-job`, `host-rules`, `host-resolver-rules`, `js-flags`, `disable-xss-auditor`, `disable-webrtc-encryption`, `remote-debugging-port`/`remote-debugging-address`, `inspect`/`inspect-brk`, `unsafely-treat-insecure-origin-as-secure`, `reduce-security-for-testing`, `auth-server-whitelist`, `auth-negotiate-delegate-whitelist`. Cross-ref `certificate_validation.md` (cert-error switches), `cleartext_transmission.md`.

### 8. Electron-specific TLS validation opt-out
Two Electron APIs bypass certificate validation outside the `webSecurity` flag (cross-ref `certificate_validation.md`):

```js
// VULN — accepts every certificate, including invalid/attacker ones
app.on('certificate-error', (event, webContents, url, error, cert, callback) => {
  event.preventDefault();
  callback(true);                  // trust regardless of error -> MITM
});
// VULN — custom verify proc that always succeeds
session.defaultSession.setCertificateVerifyProc((req, cb) => cb(0)); // 0 = success
```

```js
// SAFE — do not preventDefault / callback(true); let Electron reject, or pin explicitly
// session.setCertificateVerifyProc((req, cb) => cb(-2 /* use Chromium verification */));
```

### 9. Custom protocol / scheme handlers
Registering a custom scheme that maps a URL to a filesystem path or buffer can become arbitrary local file read (path traversal) or a privileged-origin bypass when the resolved path/content is influenced by the URL. `setAsDefaultProtocolClient` also makes deep-link argv a remote attacker source (see Sources).

```js
// VULN — URL path segment used to build the served file path (traversal -> arbitrary read)
protocol.registerFileProtocol('app', (request, cb) => {
  const p = new URL(request.url).pathname;       // attacker: app://x/../../etc/passwd
  cb({ path: path.join(APP_ROOT, p) });          // no normalize/allowlist
});
// SAFE — resolve, then confirm path.resolve(...) stays within APP_ROOT before serving
// cross-ref path_traversal_lfi_rfi.md
```

### 10. Auto-update: insecure feed, unverified signature, downgrade

The updater downloads and executes a new binary with the app's privileges, so a compromised update = RCE on every client. Distinct failure modes to flag on `autoUpdater`/`electron-updater`/Squirrel:

- **Update feed over cleartext / attacker-influenced URL** — `autoUpdater.setFeedURL({url})` (or electron-updater `provider`/generic `url`, `publishConfig`) using `http://`, or a feed URL built from config/env/user input. Cleartext lets a MITM swap `latest.yml`/the package (cross-ref `cleartext_transmission.md`).
- **Signature verification absent or platform-partial** — `autoUpdater` code-signature validation is **macOS-only**; on **Windows there is no OS-level check**, so a Windows updater that trusts only the `sha512` in `latest.yml` (an *integrity* checksum an attacker who controls the feed can recompute) without verifying a **publisher signature** installs an attacker package. electron-updater before the 2020 fix accepted a crafted `latest.yml` → RCE. Require a real cryptographic **signature over `hash + version`** with a pinned publisher public key, not just a hash.
- **Downgrade / rollback** — nothing binds the served version to be **newer** than installed, so an attacker serving an old (vulnerable) signed release forces a downgrade; and dev/beta builds signed with the **same key** as prod can be pushed to prod users. Bind the signature to the version (`sign(sha(file) + version)`) and reject non-monotonic versions; separate dev/prod signing keys.
- **Verify-then-install not atomic (TOCTOU)** — the package is verified, then read again for install from a world-writable temp dir, so a local attacker swaps the file between check and use. Verify and install from the **same** owner-only file/descriptor.

**Grep**: `autoUpdater`, `setFeedURL`, `electron-updater`, `autoInstallOnAppQuit`, `latest\.yml`, `provider:\s*['\"]generic`, `http://` in an update/feed URL, a `sha512`/hash check with **no** signature verify, `allowDowngrade`. **SAFE**: HTTPS + pinned CA, publisher-signature verify over `hash+version` before install, monotonic-version enforcement, install from the verified descriptor.

---

## Recon greps

```bash
# Window/runtime misconfig
rg -n "nodeIntegration\s*:\s*true|contextIsolation\s*:\s*false|sandbox\s*:\s*false|webSecurity\s*:\s*false|allowRunningInsecureContent\s*:\s*true|nodeIntegrationInSubFrames|enableBlinkFeatures|experimentalFeatures\s*:\s*true|enableRemoteModule\s*:\s*true|@electron/remote|affinity\s*:|ELECTRON_DISABLE_SECURITY_WARNINGS" --glob '*.{js,mjs,cjs,ts,jsx,tsx}'
# Preload bridge surface
rg -n "exposeInMainWorld|contextBridge|ipcRenderer" --glob '*preload*'
# IPC handlers (inspect each body for fs/child_process/shell sinks on the renderer arg)
rg -n "ipcMain\.(handle|on)\(" --glob '*.{js,mjs,cjs,ts,jsx,tsx}'
# Dangerous OS sinks & navigation
rg -n "shell\.openExternal|shell\.openPath|shell\.showItemInFolder|webContents\.executeJavaScript|insertCSS|loadURL\(|<webview|setWindowOpenHandler|will-navigate|will-attach-webview|app\.relaunch|setLoginItemSettings|systemPreferences\.(getUserDefault|subscribeNotification)" --glob '*.{js,mjs,cjs,ts,jsx,tsx,html}'
# Permission handler, TLS opt-out, custom schemes
rg -n "setPermissionRequestHandler|certificate-error|setCertificateVerifyProc|registerFileProtocol|registerStringProtocol|registerBufferProtocol|registerStreamProtocol|setAsDefaultProtocolClient" --glob '*.{js,mjs,cjs,ts,jsx,tsx}'
# Dangerous Chromium/Node switches (main process + package.json launch command)
rg -n "appendSwitch|appendArgument|disable-web-security|ignore-certificate-errors|no-sandbox|remote-debugging-port|allow-running-insecure-content|unsafely-treat-insecure-origin-as-secure" --glob '*.{js,mjs,cjs,ts,jsx,tsx,json}'
# Is this even an Electron/desktop project?
rg -n '"electron"|"electron-builder"|"@electron/remote"|"nw"\s*:' package.json
```

---

## TRUE / FALSE POSITIVE Rules

- **TRUE POSITIVE**: an isolation-disabling `webPreferences` flag on a window that can load or navigate to non-bundled content; a preload exposing raw `ipcRenderer`/modules/`require`; an IPC handler passing the renderer arg into an `fs`/`child_process`/`shell`/dynamic-`require` sink without validation; `shell.openExternal`/`openPath` on an unvalidated string; `loadURL`/`webview` with no navigation allowlist.
- **FALSE POSITIVE**: a window that renders **only bundled local content** (`file://`/`app://`) with **no** remote navigation and `contextIsolation` on — `nodeIntegration: true` there is lower risk (still prefer disabling, but not RCE-by-design). Preload functions that take no parameters and call a fixed channel. IPC handlers whose arg is allowlisted/coerced before the sink. `shell.openExternal` guarded by a scheme allowlist. Test/dev-only `webSecurity: false` behind an explicit dev guard (note it, but lower severity).
- Prefer the narrower tag when a finding is purely another class surfaced through Electron: a traversal in an IPC handler is `path_traversal_lfi_rfi`; a command sink is `rce`/command injection; a renderer XSS itself is `xss`. Use `electron_desktop_security` for the configuration/boundary weakness that makes those reachable or process-level.

## Severity

- **Critical / RCE**: isolation removed (`nodeIntegration: true` or `contextIsolation: false` or `sandbox: false`) on a window reachable by untrusted content, or a preload/IPC path that hands `child_process`/dynamic `require` to the renderer.
- **High**: `webSecurity: false` / `allowRunningInsecureContent` (SOP + TLS bypass -> SSRF / local file read / MITM), TLS opt-out (`certificate-error` + `callback(true)`, `setCertificateVerifyProc` accepting all, cert/TLS-disabling CLI switches), security-disabling switches (`disable-web-security`, `no-sandbox`, `remote-debugging-port`), unvalidated `shell.openExternal`, traversal in custom protocol handlers, arbitrary-file-read IPC handlers, `will-attach-webview` re-enabling Node, unrestricted navigation enabling origin takeover of a privileged window.
- **Medium / Low**: permissive/missing `setPermissionRequestHandler`, `enableBlinkFeatures`, isolation flags on a strictly-bundled-content window, dev-only relaxations behind guards, missing-defense-in-depth where no untrusted content path is demonstrable.

Cross-ref `rce.md` (command/eval sinks), `trust_boundary.md` (renderer↔main boundary), `certificate_validation.md` (`webSecurity:false` disables cert checks), `ssrf.md` / `open_redirect.md` (navigation & external-open), `path_traversal_lfi_rfi.md` (file IPC handlers), `xss.md` (the web-content trigger).
