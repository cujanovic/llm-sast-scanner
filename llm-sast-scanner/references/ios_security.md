---
name: ios_security
description: iOS/macOS application security (Swift / Objective-C) — insecure storage (UserDefaults/plist/Core Data/file-protection), Keychain misuse (weak kSecAttrAccessible class), local-authentication/biometric bypass (boolean LAContext.evaluatePolicy, weak SecAccessControl ACL), deep-link/URL-scheme handling to WKWebView/open, App Transport Security bypass (NSAllowsArbitraryLoads, low TLSMinimumSupportedProtocolVersion), crypto misuse (DES/3DES/RC4, hardcoded keys, arc4random), TLS trust bypass (missing SecTrustEvaluateWithError), clipboard/keyboard-cache/screen-capture leakage, client-only jailbreak detection (CWE-287/295/305/312/319/327/524/798/939). Load when an iOS/Swift/Objective-C project is present (*.swift/*.m + Info.plist/*.xcodeproj/Podfile).
---

# iOS Security (Swift / Objective-C)

Identify cases where iOS application code stores sensitive data insecurely, handles URL schemes/deep links unsafely, disables transport security, applies weak or static cryptographic material, or bypasses TLS certificate validation. (Android patterns: see `android_security.md`.)

## Source -> Sink Pattern

**iOS Sources**
- URL scheme parameters: `url.host`, `url.path`, `URLComponents(url:).queryItems`
- Universal Link / deep-link payload in `application(_:open:options:)`
- Push notification payload: `userInfo["url"]` or arbitrary `userInfo` keys
- Clipboard: `UIPasteboard.general.string`
- `WKScriptMessage.body` from JavaScript message handlers

**iOS Sinks**
- `UserDefaults.standard.set(sensitiveValue, forKey: key)`
- `FileManager.default.createFile(atPath: docPath, contents: sensitiveData, attributes: nil)` without `NSFileProtectionComplete`
- `print(sensitiveValue)` / `NSLog(@"%@", sensitiveValue)`
- `WKWebView.load(URLRequest(url: unvalidatedURL))`
- `UIApplication.shared.open(unvalidatedURL)`
- `CCCrypt` with `kCCAlgorithmDES` or key length < 16
- `SecItemAdd` / `SecItemUpdate` storing cleartext passwords outside the keychain

---

## iOS Vulnerable Patterns (Swift / Objective-C)

### Insecure Keychain / Storage

#### UserDefaults Storing Sensitive Data

**VULN**:
```swift
UserDefaults.standard.set(password, forKey: "userPassword")
UserDefaults.standard.set(authToken, forKey: "authToken")
```

**VULN (Objective-C)**:
```objc
[[NSUserDefaults standardUserDefaults] setObject:token forKey:@"auth_token"];
```

**SAFE** — store in the Keychain:
```swift
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "userPassword",
    kSecValueData as String: password.data(using: .utf8)!
]
SecItemAdd(query as CFDictionary, nil)
```

**TRUE POSITIVE**: `UserDefaults.standard.set(value, forKey: key)` where the value originates from a variable named `password`, `token`, `secret`, `key`, `credential`, `pin`, or `ssn`.

**FALSE POSITIVE**: `UserDefaults.standard.set(true, forKey: "hasCompletedOnboarding")` — non-sensitive flag. Evaluate the semantics of both the key name and the value origin.

---

#### File Written Without Data Protection

**VULN**:
```swift
let path = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    .appendingPathComponent("credentials.json")
try sensitiveData.write(to: path)  // no file protection attributes
```

**SAFE**:
```swift
try sensitiveData.write(to: path, options: .completeFileProtection)
// equivalent to NSFileProtectionComplete — file inaccessible when device is locked
```

**TRUE POSITIVE**: `.write(to: path)` or `FileManager.createFile(atPath:contents:attributes:)` with `attributes: nil` (or absent `NSFileProtectionKey`) when the written content is sensitive.

**FALSE POSITIVE**: Writing cached images, non-sensitive JSON configuration, or temporary files to `.cachesDirectory` without file protection is low risk; flag only when the written data contains credentials or PII.

---

#### Plist / Core Data Cleartext Storage

**VULN** — secrets written to plist on disk:
```swift
let creds = ["authToken": token, "refreshToken": refresh]
(creds as NSDictionary).write(toFile: plistPath, atomically: true)
```

**VULN (Objective-C)**:
```objc
[@{@"password": password} writeToFile:path atomically:YES];
```

**VULN** — sensitive fields in Core Data without encryption transform:
```swift
entity.setValue(ssn, forKey: "socialSecurityNumber")
try context.save()
```

**SAFE** — Keychain for secrets; Core Data with `NSPersistentStoreFileProtectionKey`:
```swift
let options = [NSPersistentStoreFileProtectionKey: FileProtectionType.complete]
```

**TRUE POSITIVE**: `write(toFile:atomically:)` / `write(to:atomically:)` / Core Data `setValue` where the value traces to `token`, `password`, `secret`, `pin`, `ssn`, or `credential` without Keychain or file-protection attributes.

**FALSE POSITIVE**: Plist storing non-sensitive feature flags or cached public configuration.

**Grep (Swift/Objective-C):**
```bash
rg -n 'writeToFile:|write\(toFile:|NSUserDefaults|UserDefaults\.standard\.set|setValue\(.*forKey:' --glob '*.{swift,m,mm}'
rg -n 'kSecClass|SecItemAdd|SecItemCopyMatching' --glob '*.{swift,m,mm}'
```

---

#### Weak Keychain Accessibility Class

A Keychain item's `kSecAttrAccessible` value controls *when* the secret is readable. The two non-`ThisDeviceOnly` "always available" classes leave the secret extractable from an unlocked-but-backed-up or off-device image.

**VULN**:
```swift
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "authToken",
    kSecAttrAccessible as String: kSecAttrAccessibleAlways,            // readable even when locked; also syncs to backups
    kSecValueData as String: token.data(using: .utf8)!
]
SecItemAdd(query as CFDictionary, nil)
```

**SAFE** — bind to this device and (ideally) to passcode being set:
```swift
kSecAttrAccessible as String: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
// or kSecAttrAccessibleWhenUnlockedThisDeviceOnly / kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
```

**TRUE POSITIVE**: a Keychain add/update using `kSecAttrAccessibleAlways`, `kSecAttrAccessibleAlwaysThisDeviceOnly` (deprecated), or `kSecAttrAccessibleAfterFirstUnlock` for credential/token/key material. `*Always*` is the strongest finding (survives backup + readable while locked).

**FALSE POSITIVE**: `kSecAttrAccessibleAfterFirstUnlock` on a background-task secret that legitimately must be read while the device is locked — downgrade, but prefer the `ThisDeviceOnly` variant to block backup extraction.

---

#### Local-Authentication (Biometric) Bypass & Weak Access-Control Flags

Two distinct iOS-specific failures, both CWE-287/CWE-305:

**VULN — boolean-only biometric gate** (the result is just a `Bool`, patchable by Frida/objection at runtime; nothing cryptographically depends on it):
```swift
let ctx = LAContext()
ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: r) { ok, _ in
    if ok { self.unlockSecret() }     // gate is a bool — bypassable by hooking the callback
}
```

**VULN — weak biometric ACL** (`.biometryAny` / `.userPresence` / `.touchIDAny` let an attacker who can *enroll a new fingerprint/face* on the device authenticate as the user):
```swift
let acl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                          .biometryAny, nil)   // or .userPresence / .touchIDAny
```

**SAFE** — protect the secret *in the Keychain* with `.biometryCurrentSet` so the OS (not app code) enforces auth, and the secret is invalidated if the enrolled biometric set changes:
```swift
let acl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                          .biometryCurrentSet, &error)
// store under kSecAttrAccessControl: acl — decryption now requires the current biometric, not a swappable bool
```

**TRUE POSITIVE**: `LAContext().evaluatePolicy(...)` whose only consequence is an `if ok { ... }` branch unlocking data, with no Keychain-backed `SecAccessControlCreateWithFlags`; or any `SecAccessControlCreateWithFlags` using `.biometryAny`, `.userPresence`, `.touchIDAny`, or `.devicePasscode`.

**FALSE POSITIVE**: `evaluatePolicy` used purely for a low-value UX gate (e.g., re-revealing already-displayed non-secret data) where no protected asset hangs off the boolean.

**Grep:**
```bash
rg -n 'kSecAttrAccessibleAlways|kSecAttrAccessibleAfterFirstUnlock\b' --glob '*.{swift,m,mm}'
rg -n 'evaluatePolicy|deviceOwnerAuthentication|\.biometryAny|\.userPresence|\.touchIDAny|SecAccessControlCreateWithFlags' --glob '*.{swift,m,mm}'
```

---

#### Sensitive Field Without Keyboard-Cache Disabled

iOS caches typed text for autocorrection; secret values typed into a field that allows autocorrection persist in the keyboard dictionary on disk (CWE-524).

**VULN**: a `UITextField`/`UITextView` collecting a password, PIN, card number, or seed phrase without `isSecureTextEntry = true` **and** without `autocorrectionType = .no` (Obj-C `UITextAutocorrectionTypeNo`).

**SAFE**: `field.isSecureTextEntry = true; field.autocorrectionType = .no` (secure entry implies no cache; set both explicitly for non-password sensitive fields like card/seed where masking is undesirable).

**FALSE POSITIVE**: search boxes, usernames, and other non-secret fields — autocorrection is expected there.

---

#### Logging Sensitive Data

**VULN**:
```swift
print("Auth token: \(authToken)")
print("Password entered: \(password)")
NSLog("User credentials: %@ / %@", username, password)
```

**SAFE**:
```swift
print("Login attempt for user ID: \(userId)")  // no credential value emitted
```

**TRUE POSITIVE**: `print(...)` or `NSLog(...)` interpolating or formatting a variable whose name contains `password`, `token`, `secret`, `key`, `credential`, `pin`, or `ssn`.

**FALSE POSITIVE**: `print("Response status: \(statusCode)")` — no sensitive value present.

**PII log indicators — extend variable-name heuristics with:**
```bash
# Android
rg -n 'Log\.[divwe]\s*\(.*(email|phone|ssn|dob|address|iban|pan|cvv|accountNumber)' --glob '*.{java,kt}'
# iOS
rg -n 'print\s*\(|NSLog\s*\(.*(email|phone|ssn|dob|address|iban|pan|cvv|accountNumber)' --glob '*.{swift,m,mm}'
```

---

### Clipboard and Screenshot Leakage

#### Sensitive Data on Clipboard

**VULN (Android)**:
```java
ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
cm.setPrimaryClip(ClipData.newPlainText("token", authToken));
```

**VULN (iOS)**:
```swift
UIPasteboard.general.string = password
UIPasteboard.general.setValue(token, forPasteboardType: "token")
```

**SAFE** — avoid copying secrets; clear after one-time use:
```swift
UIPasteboard.general.items = []
```

**TRUE POSITIVE**: Clipboard write where the payload variable matches sensitive heuristics (`password`, `token`, `pin`, `ssn`, `otp`, `secret`).

**FALSE POSITIVE**: Copying non-sensitive user-selected text (e.g., shareable promo code) to clipboard.

**Grep:**
```bash
rg -n 'ClipData\.newPlainText|setPrimaryClip|UIPasteboard\.general' --glob '*.{java,kt,swift,m,mm}'
```

---

#### Screenshot / Screen-Capture Exposure

**VULN** — sensitive screen without capture protection:
```swift
// No UIApplication.shared.isProtectedDataAvailable check
// Missing: window.makeSecure() / UITextField.isSecureTextEntry for PIN entry
```

**VULN (Android)** — `FLAG_SECURE` not set on credential Activity:
```java
// onCreate missing:
getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                     WindowManager.LayoutParams.FLAG_SECURE);
```

**TRUE POSITIVE**: Activity/ViewController presenting `password`, `pin`, `cvv`, or `ssn` input without `FLAG_SECURE` (Android) or without `isSecureTextEntry` / secure-field equivalent (iOS).

**FALSE POSITIVE**: Public marketing screens with no sensitive data.

**Grep:**
```bash
rg -n 'FLAG_SECURE|isSecureTextEntry|secureTextEntry' --glob '*.{java,kt,swift,m,mm,xml}'
```

---

### Insecure URL Scheme / Deep Link Handling

#### Unvalidated Deep-Link URL Handling

**VULN**:
```swift
func application(_ app: UIApplication, open url: URL,
                 options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    let target = url.host  // e.g. myapp://redirect?to=https://evil.com
    webView.load(URLRequest(url: URL(string: target!)!))
    return true
}
```

**SAFE**:
```swift
func application(_ app: UIApplication, open url: URL,
                 options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    guard let host = url.host, allowedHosts.contains(host) else { return false }
    webView.load(URLRequest(url: URL(string: "https://\(host)/safe-path")!))
    return true
}
```

**TRUE POSITIVE**: URL components extracted from `application(_:open:options:)` or `scene(_:openURLContexts:)` flow directly into `WKWebView.load(URLRequest(...))`, `UIApplication.shared.open(...)`, or file operations without scheme/host validation.

**FALSE POSITIVE**: URL host extracted from the deep link and used only as a lookup key against a local dictionary or route map where actual navigation targets are hardcoded.

---

#### Deep Link → Internal Action → API Request Path (second-order CSPT)

Beyond WebView/navigation sinks, a deep-link handler that **fetches remote/stored JSON and dispatches an internal action which builds an authenticated API request** is a second-order Client-Side Path Traversal source: if the action concatenates a field from that JSON into the request **URL path**, `#`/`%23` truncation and `../`/`%2e%2e%2f` traversal in the field rewrite the call into an **arbitrary authenticated request to any API endpoint, as the victim**. A common enabler is a **hardcoded third-party service API key** (e.g. a link shortener) extracted from the app, letting the attacker store the JSON blob the app later trusts.

**TRUE POSITIVE**: a value parsed from `application(_:open:options:)` / `ACTION_VIEW` / `onNewIntent` / RN `Linking` (directly, or fetched back from a service keyed by the link) flows into an internal action that interpolates it into an authenticated `URLRequest`/`fetch`/HTTP-client **path** without an allowlist.

**FALSE POSITIVE**: the deep-link/JSON field selects an action by exact match against a fixed route map and the request path is hardcoded per action (the field never concatenates into the URL).

See `client_side_path_traversal.md` (Second-Order CSPT) for the full chain, the query-only impact gadgets, and SAFE patterns.

---

#### WKWebView Loading Unvalidated External URL

**VULN**:
```swift
let urlString = deepLinkURL.queryParameters["redirect"] ?? ""
webView.load(URLRequest(url: URL(string: urlString)!))
```

**SAFE**:
```swift
guard let urlString = deepLinkURL.queryParameters["redirect"],
      urlString.hasPrefix("https://trusted.example.com/") else { return }
webView.load(URLRequest(url: URL(string: urlString)!))
```

**TRUE POSITIVE**: `WKWebView.load(URLRequest(url: externalURL))` where `externalURL` is derived from external input (URL scheme, push notification, user text field) without strict prefix or allowlist validation.

**FALSE POSITIVE**: `webView.load(URLRequest(url: URL(string: "https://static.example.com/help")!))` — hardcoded URL, no user control.

---

### ATS Bypass (App Transport Security)

#### NSAllowsArbitraryLoads

**VULN** — Info.plist:
```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>
```

**TRUE POSITIVE**: `NSAllowsArbitraryLoads` set to `true` at the top-level ATS dictionary — this disables TLS enforcement globally for all network connections.

**FALSE POSITIVE**: `NSAllowsArbitraryLoads` set to `true` only within `NSExceptionDomains` for a specific domain (e.g., a legacy internal server during a migration window) with `NSTemporaryExceptionAllowsInsecureHTTPLoads` is lower severity than the global flag; still report as a finding but at MEDIUM rather than HIGH.

---

#### NSExceptionDomains Insecure Exception

**VULN**:
```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSExceptionDomains</key>
    <dict>
        <key>api.example.com</key>
        <dict>
            <key>NSTemporaryExceptionAllowsInsecureHTTPLoads</key>
            <true/>
            <key>NSIncludesSubdomains</key>
            <true/>
        </dict>
    </dict>
</dict>
```

**TRUE POSITIVE**: `NSTemporaryExceptionAllowsInsecureHTTPLoads: true` for a domain used as a production API endpoint, especially combined with `NSIncludesSubdomains: true`.

**FALSE POSITIVE**: Exceptions restricted to `localhost` or `127.0.0.1` for local development tooling — valid test configuration; do not flag in CI/CD SAST unless the build target is a release variant.

**Also flag (programmatic minimum-TLS, CWE-326/CWE-757):** a `URLSessionConfiguration` setting `TLSMinimumSupportedProtocolVersion` to `.TLSv10`/`.TLSv11`/`.TLSv12` (TLS 1.3 should be the floor), or any use of the deprecated `tlsMinimumSupportedProtocol` / `kTLSProtocol1` API — these silently negotiate down to a weak protocol regardless of ATS plist settings.
```bash
rg -n 'TLSMinimumSupportedProtocol|tlsMinimumSupportedProtocol|TLSv1[01]\b|kTLSProtocol1\b' --glob '*.{swift,m,mm}'
```

---

### Insecure Crypto (iOS)

#### DES or Small Key Size

**VULN**:
```swift
let status = CCCrypt(
    CCOperation(kCCEncrypt),
    CCAlgorithm(kCCAlgorithmDES),  // 56-bit key — broken
    CCOptions(kCCOptionPKCS7Padding),
    keyBytes, kCCKeySizeDES, iv,
    plaintext, plaintextLength,
    ciphertext, ciphertextLength, &moved)
```

**SAFE**:
```swift
CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
        keyBytes, kCCKeySizeAES256, iv, ...)
```

**TRUE POSITIVE**: `kCCAlgorithmDES`, `kCCAlgorithm3DES`, or `kCCAlgorithmRC4` in any `CCCrypt` call. Also flag `kCCAlgorithmAES` with key size constant `kCCKeySizeAES128` only when the key material is derived from a weak source (see below).

**FALSE POSITIVE**: `kCCAlgorithmAES` with `kCCKeySizeAES256` and a key derived from `SecRandomCopyBytes` — acceptable configuration.

---

#### Hardcoded Encryption Key

**VULN**:
```swift
let key = "MySecretKey12345"
let keyData = key.data(using: .utf8)!
CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
        (keyData as NSData).bytes, keyData.count, iv, ...)
```

**VULN (Objective-C)**:
```objc
const char *key = "HardcodedKeyValue";
CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
        key, strlen(key), iv, ...);
```

**TRUE POSITIVE**: String literal or byte array literal used directly as the key argument to `CCCrypt`, `SecKeyCreateWithData`, or any third-party symmetric encryption API, when the literal has length >= 8 and mixed entropy suggesting it is a real key rather than a placeholder.

**FALSE POSITIVE**: Test-only key literals in files under `*Tests*`, `*Spec*`, or `*Mock*` directories — report as INFORMATIONAL in test code, not HIGH in production code.

---

#### arc4random for Key / Token Generation

**VULN**:
```swift
let token = String(arc4random_uniform(1_000_000))
UserDefaults.standard.set(token, forKey: "sessionToken")
```

**VULN (Objective-C)**:
```objc
NSString *otp = [NSString stringWithFormat:@"%d", arc4random_uniform(999999)];
```

**SAFE**:
```swift
var tokenBytes = [UInt8](repeating: 0, count: 32)
let result = SecRandomCopyBytes(kSecRandomDefault, tokenBytes.count, &tokenBytes)
guard result == errSecSuccess else { fatalError("SecRandomCopyBytes failed") }
let token = Data(tokenBytes).base64EncodedString()
```

**TRUE POSITIVE**: `arc4random`, `arc4random_uniform`, or `rand()` / `random()` used to generate values assigned to variables named `token`, `otp`, `nonce`, `sessionId`, `key`, `secret`, or `password`.

**FALSE POSITIVE**: `arc4random_uniform` used to shuffle UI elements, randomize quiz question order, or produce non-security-critical random numbers.

---

### Weak Certificate Validation

#### Accepting All TLS Certificates in URLSession Delegate

**VULN**:
```swift
func urlSession(_ session: URLSession,
                didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition,
                                              URLCredential?) -> Void) {
    // Accepts ANY certificate — including expired, self-signed, or attacker-controlled
    let serverTrust = challenge.protectionSpace.serverTrust!
    completionHandler(.useCredential, URLCredential(trust: serverTrust))
}
```

**SAFE** — evaluate trust before accepting:
```swift
func urlSession(_ session: URLSession,
                didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition,
                                              URLCredential?) -> Void) {
    guard challenge.protectionSpace.authenticationMethod ==
              NSURLAuthenticationMethodServerTrust,
          let serverTrust = challenge.protectionSpace.serverTrust else {
        completionHandler(.cancelAuthenticationChallenge, nil)
        return
    }
    var error: CFError?
    if SecTrustEvaluateWithError(serverTrust, &error) {
        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    } else {
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}
```

**TRUE POSITIVE**: `completionHandler(.useCredential, URLCredential(trust: serverTrust))` called without a preceding `SecTrustEvaluateWithError` check that gates on a `true` return value.

**FALSE POSITIVE**: Custom certificate pinning implementations that verify the server's leaf or intermediate certificate against a bundled public key or certificate hash before calling `.useCredential` — not a vulnerability even though `SecTrustEvaluateWithError` may not be used.

---

#### Objective-C NSURLConnection / NSURLSession Trust Bypass

**VULN**:
```objc
- (void)connection:(NSURLConnection *)connection
    willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    [challenge.sender useCredential:
        [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust]
             forAuthenticationChallenge:challenge];
}
```

**TRUE POSITIVE**: `useCredential:forAuthenticationChallenge:` called with a trust credential for a server trust challenge without validating the trust object first.

**FALSE POSITIVE**: Implementation that calls `SecTrustEvaluate` (or `SecTrustEvaluateWithError`) and only proceeds with `useCredential` when the return value indicates success.

**Cross-ref:** Certificate pinning absence, custom trust managers, and TLS protocol downgrade patterns are covered in `certificate_validation.md` and `cleartext_transmission.md`. Flag missing pins as MEDIUM (absence-based); flag trust bypass as CRITICAL.

---

### Root / Jailbreak / Tamper Detection Weaknesses

#### Client-Only Integrity Gate

**VULN** — sensitive operation gated solely by bypassable client check:
```java
if (RootBeer.with(context).isRooted()) {
    showError(); return;
}
processPayment(cardData);  // no server-side device-trust signal
```

**VULN (iOS)**:
```swift
if FileManager.default.fileExists(atPath: "/Applications/Cydia.app") {
    exit(0)
}
unlockPremiumFeatures()  // local-only enforcement
```

**SAFE** — combine local signal with server attestation; fail closed on high-risk ops:
```kotlin
val verdict = integrityManager.requestIntegrityToken(request).await()
if (!server.verifyIntegrityToken(verdict.token)) abortSensitiveFlow()
```

**TRUE POSITIVE**: `isRooted`, `isJailbroken`, `su`, `/system/xbin/su`, `frida`, `substrate`, or Play Integrity / App Attest result used as the **only** guard before accessing Keystore secrets, decrypting local data, or enabling premium/sensitive features — especially when the check is a single `if` with no server validation.

**FALSE POSITIVE**: Root/jailbreak detection used for analytics or warning banners only, with no security decision tied to the result.

**Grep:**
```bash
rg -n 'isRooted|isJailbroken|/system/xbin/su|Magisk|frida|substrate|PlayIntegrity|AppAttest|DeviceCheck' --glob '*.{java,kt,swift,m,mm}'
```

---

## Severity Reference

| Vulnerability | Platform | CWE | Severity |
|---|---|---|---|
| Logging sensitive data | Android / iOS | CWE-312 | MEDIUM |
| Hardcoded credentials / keys in source | Android / iOS | CWE-798 | HIGH |
| UserDefaults storing sensitive data | iOS | CWE-312 | HIGH |
| File written without NSFileProtectionComplete | iOS | CWE-312 | MEDIUM |
| Unvalidated deep-link URL to WKWebView | iOS | CWE-939 | HIGH |
| NSAllowsArbitraryLoads: true (global) | iOS | CWE-319 | HIGH |
| NSTemporaryExceptionAllowsInsecureHTTPLoads per domain | iOS | CWE-319 | MEDIUM |
| kCCAlgorithmDES / 3DES usage | iOS | CWE-327 | HIGH |
| Hardcoded encryption key literal | iOS | CWE-798 | HIGH |
| arc4random for security token generation | iOS | CWE-338 | HIGH |
| TLS certificate accepted without SecTrustEvaluateWithError | iOS | CWE-295 | CRITICAL |
| Secrets in plist / unprotected Core Data | iOS | CWE-312 | HIGH |
| Keychain item with `kSecAttrAccessibleAlways` / `AfterFirstUnlock` (non-`ThisDeviceOnly`) | iOS | CWE-312 | MEDIUM |
| Boolean-only `LAContext.evaluatePolicy` biometric gate (no Keychain binding) | iOS | CWE-287 | HIGH |
| Weak biometric ACL (`.biometryAny` / `.userPresence` / `.touchIDAny`) | iOS | CWE-305 | MEDIUM |
| Sensitive field without secure entry / keyboard cache disabled | iOS | CWE-524 | LOW |
| Programmatic `TLSMinimumSupportedProtocolVersion` < TLS 1.3 | iOS | CWE-326 | MEDIUM |
| Deep link parameter to navigation sink | Android / iOS | CWE-939 | HIGH |
| Sensitive data copied to clipboard | Android / iOS | CWE-200 | MEDIUM |
| Credential screen without FLAG_SECURE / secure field | Android / iOS | CWE-200 | MEDIUM |
| Client-only root/jailbreak gate for sensitive ops | Android / iOS | CWE-693 | LOW |

---

## Sources, Sinks & Sanitizers
### CWE-079 — WebView XSS / script injection

**Detection patterns (Android):**
- Any `WebView.addJavascriptInterface(...)` call
- `WebSettings.setJavaScriptEnabled(true)`
- Taint: `ActiveThreatModelSource` → `WebView.loadUrl`/`postUrl` when JS enabled and/or cross-origin file access enabled
- `setAllowFileAccess` / `setAllowUniversalAccessFromFileURLs` / `setAllowFileAccessFromFileURLs` set `true`
- `setAllowContentAccess(true)` or WebView never calling `setAllowContentAccess(false)`

**Detection patterns (Swift/iOS):**
- Taint into `loadHTMLString`/`load(_:)` where `baseURL` is absent, `nil`, or tainted

**Sources (Android taint):** `ActiveThreatModelSource` — remote/user/Intent/deep-link inputs.

**Sinks (Android):**
- `UrlResourceSink` via `WebView.loadUrl` / `postUrl` first argument
- Subtypes: `JavaScriptEnabledUrlResourceSink` (JS on WebView), `CrossOriginUrlResourceSink` (also `setAllowFileAccess(true)`)

**Sanitizers (Android):** `RequestForgerySanitizer` (URL allowlist/host validation).

**Sinks (Swift):** WebView HTML load with unrestricted/tainted `baseURL`.

**Sanitizers (Swift):** Non-tainted `baseURL` set to a fixed trusted URL or `about:blank` (not `nil`).

**Good / bad:**
- **BAD (Android):** `webView.addJavascriptInterface(new MyBridge(), "bridge")` on a WebView that loads untrusted content.
- **BAD (Swift):** `webView.loadHTMLString(html, baseURL: nil)` — `nil` does not restrict `file://` or attacker URLs.
- **SAFE (Swift):** `webView.loadHTMLString(html, baseURL: URL(string: "about:blank")!)`.

### CWE-200 / CWE-312 — Cleartext storage and sensitive UI leak

**Detection patterns:**
- **Android:** `SensitiveSource` → `SharedPreferences$Editor.put*` → `commit()`/`apply()`; sensitive data → `FileOutputStream` / local file write; sensitive data → SQLite local DB store; `AndroidManifest.xml` `android:allowBackup="true"` (or default-allowed); Intent from `onActivityResult` → file path sink without `startsWith` guard; sensitive data → `NotificationManager.notify`; sensitive data → `TextView.setText` / password fields without masking
- **Swift/iOS:** Sensitive data → `UserDefaults` / preference store; local database write; log output
- **JavaScript (web):** `express.static` / `serve-static` exposing `node_modules`, project root, home, or cwd

**Sources:** `SensitiveSource` (password/token/PII heuristics) for Android cleartext rules; Swift uses dedicated cleartext taint configs.

**Sanitizers (Android SharedPreferences):** `EncryptedSharedPreferences.create(...)` — editors from encrypted prefs are excluded.

**Sanitizers (sensitive file leak):** `path.startsWith(...)` guard on the taint path.

### CWE-295 — Certificate pinning / WebView TLS

**Detection patterns:**
- Network call with no certificate pin for the target domain (Android)
- `WebViewClient.onReceivedSslError` handler that accepts all certs (`trustsAllCerts`) (Android)
- TLS configuration allowing weak/insecure protocols (Swift/iOS)

### CWE-489 — Debug exposure

**Detection patterns:**
- Taint/enabled path to `WebView.setWebContentsDebuggingEnabled(true)` (Android)
- Manifest `android:debuggable="true"` outside build dirs (Android)

### CWE-749 — Unsafe Android WebView resource access

Primary taint pattern linking user input to `loadUrl` with dangerous WebSettings — see CWE-079 WebView section above.

### CWE-925 / 926 / 927 / 940 — Intent and component exposure

**Detection patterns:**
- Exported receiver registered for system action without intent verification
- Manifest component has `<intent-filter>` but no explicit `android:exported`
- Exported provider missing read or write permission attribute
- Implicit mutable `PendingIntent` sent via `startActivity`/`startActivities`
- Sensitive data in implicit `Intent` broadcast/start
- Sensitive data sent to untrusted `ResultReceiver`
- User input → `startActivity`/`startService`/`sendBroadcast` with attacker-controlled component

**Sources:** `ActiveThreatModelSource`, `ImplicitPendingIntentSource`.

**Sinks:** `IntentRedirectionSink`, `ImplicitPendingIntentSink`, `SensitiveCommunication` broadcast/start sinks.

**Sanitizers:**
- `IntentRedirectionSanitizer` / `OriginalIntentSanitizer` — relaunching the same incoming Intent (component not attacker-set)
- `ExplicitIntentSanitizer` — fully explicit Intent (`setComponent`/`setClass`/`setClassName` with non-tainted class)
- `RequestForgerySanitizer` (URL context)

**Good / bad (intent verification):** receivers registered for `BOOT_COMPLETED` must verify sender; permission/explicit component check vs no verification.

### CWE-470 — Fragment injection

**Detection patterns:**
- User input → `Fragment.instantiate` / reflective fragment creation
- Exported `PreferenceActivity` with `isValidFragment` always returning `true`

**Sanitizers:** `FragmentInjectionSanitizer` from external flow model (`barrierNode(..., "fragment-injection")`).

### CWE-287 — Local authentication / key generation

**Detection patterns:**
- `KeyGenParameterSpec` / biometric key with insecure parameters when local auth is used
- `BiometricPrompt` callback without `CryptoObject` result use

### CWE-441 / CWE-266 — Content URI and permission manipulation

**Detection patterns:**
- User input → `ContentResolver` query/open/getType on URI
- User-controlled Intent → `setResult` with URI permission flags

### Swift security patterns (non-WebView)

Commonly tracked classes: SQL injection (CWE-089), predicate injection (CWE-943), path injection (CWE-022), cleartext transmission (CWE-311), unsafe JS eval (CWE-094).

iOS cookie storage and ATS plist keys (`NSAllowsArbitraryLoads`) remain heuristic-only for this scanner.

## Manifest & WebView Config
**Android manifest (XML models):**
- `android:exported` implicit when `<intent-filter>` present
- `android:allowBackup`, `android:debuggable` on `<application>`
- Provider `android:readPermission` / `android:writePermission` completeness

**Android WebView config chain:**
- `getSettings()` → `setJavaScriptEnabled`, cross-origin file access methods, `setAllowContentAccess`
- `loadUrl` / `postUrl`, `addJavascriptInterface`, `setWebViewClient` → `shouldOverrideUrlLoading`

**iOS WebView config:**
- `baseURL` parameter on HTML load APIs — must not be `nil` or user-controlled

## Common False Alarms
- **`setJavaScriptEnabled(true)`** flags every call — not limited to user-controlled URLs; pair with unsafe WebView fetch taint for exploitable XSS paths.
- **`addJavascriptInterface`** is syntactic — any bridge registration alerts regardless of loaded origin; downgrade when WebView loads only bundled `file:///android_asset/` assets.
- **Missing certificate pinning** is absence-based — apps using system trust store without pins alert on all network calls; not equivalent to MITM-vulnerable custom trust managers.
- **Cleartext SharedPreferences** excludes `EncryptedSharedPreferences` but not other custom crypto wrappers unless modeled.
- **`allowBackup` manifest flag** is manifest-only — no data-flow proof that backups contain secrets.
- **Sensitive file leak** narrowly tracks `onActivityResult` Intent paths with `startsWith` as the only modeled sanitizer.
- **Implicit PendingIntents** sanitizes explicit Intents — `FLAG_IMMUTABLE` alone is insufficient if the base Intent is implicit.
- **Fragment injection in PreferenceActivity** only covers exported activities whose `isValidFragment` unconditionally returns `true`.
- **Swift unsafe WebView fetch** requires taint flow — hardcoded safe `baseURL` with static HTML is not flagged.


---

## Platform Detection Indicators (grep)

Consolidated SAST grep anchors — pair with taint heuristics above; hits alone are not findings.

**iOS (Swift/Objective-C/plist):**
```bash
# Storage
rg -n 'UserDefaults|NSUserDefaults|writeToFile|SecItemAdd|kSecClass|NSPersistentStore' --glob '*.{swift,m,mm}'
# Keychain accessibility / local auth
rg -n 'kSecAttrAccessibleAlways|kSecAttrAccessibleAfterFirstUnlock\b|evaluatePolicy|SecAccessControlCreateWithFlags|\.biometryAny|\.userPresence|\.touchIDAny' --glob '*.{swift,m,mm}'
# Deep links / WebView
rg -n 'open url:|openURLContexts|WKWebView|loadHTMLString|load\s*\(\s*URLRequest' --glob '*.{swift,m,mm}'
# Transport / ATS
rg -n 'NSAllowsArbitraryLoads|NSExceptionDomains|didReceive.*challenge|SecTrustEvaluate' --glob '*.{swift,m,mm,plist}'
# Logging / clipboard / capture
rg -n 'print\s*\(|NSLog\s*\(|UIPasteboard|isSecureTextEntry|secureTextEntry' --glob '*.{swift,m,mm}'
# Integrity
rg -n 'jailbreak|Cydia|frida|AppAttest|DeviceCheck|fileExists.*MobileSubstrate' --glob '*.{swift,m,mm}'
```

**Cross-lens refs:**
- Hardcoded secrets → `hardcoded_secrets` (CWE-798)
- TLS trust bypass / missing pinning → `certificate_validation`, `cleartext_transmission` (CWE-295, CWE-319)
