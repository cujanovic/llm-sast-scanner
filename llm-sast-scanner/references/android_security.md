---
name: android_security
description: Android application security — insecure data storage (SharedPreferences/SQLite/external storage/Keystore), exported component & intent injection, deep-link/WebView RCE (addJavascriptInterface, file-URL access), insecure IPC (ContentProvider/PendingIntent), crypto misuse (ECB/static IV/weak key/java.util.Random), allowBackup, clipboard/FLAG_SECURE leakage, client-only root detection, cert-trust bypass (CWE-312/89/22/749/927/327/295). Load when an Android project is present (*.kt/*.java + AndroidManifest.xml/build.gradle).
---

# Android Security

Identify cases where Android application code stores sensitive data insecurely, exposes components to untrusted callers, passes user-controlled input to dangerous APIs without validation, or applies weak or static cryptographic material. (iOS/Swift patterns: see `ios_security.md`.)

## Source -> Sink Pattern

**Android Sources**
- `getIntent().getStringExtra(...)` / `getIntent().getData()`
- `ContentResolver` query parameters passed through `Uri` or cursor data
- `Bundle` values from `getArguments()` in Fragment
- Deep-link parameters extracted from `Intent.ACTION_VIEW` data
- IPC data received via `Messenger`, `AIDL`, or `BroadcastReceiver.onReceive(context, intent)`

**Android Sinks**
- `SharedPreferences.Editor.putString(key, sensitiveValue)` with `MODE_WORLD_READABLE`
- `SQLiteDatabase.execSQL(rawQuery)` / `rawQuery(query, null)` where query contains untrusted data
- `Log.d/i/v/w/e(TAG, sensitiveValue)`
- `new FileOutputStream(new File(Environment.getExternalStorageDirectory(), filename))`
- `WebView.loadUrl(userControlledUrl)`
- `WebView.addJavascriptInterface(object, name)`
- `startActivity(intentFromIPC)` / `startService(intentFromIPC)`
- `Cipher.getInstance("AES/ECB/...")` / `Cipher.getInstance("DES/...")`

---

## Android Vulnerable Patterns

### Insecure Data Storage

#### SharedPreferences with Sensitive Data

**VULN** — world-readable preference file exposing credentials:
```java
SharedPreferences prefs = getSharedPreferences("creds", MODE_WORLD_READABLE);
prefs.edit().putString("password", userPassword).apply();
```

**VULN** — storing auth token in default (unencrypted) SharedPreferences:
```java
getSharedPreferences("app_prefs", MODE_PRIVATE)
    .edit().putString("auth_token", token).apply();
// MODE_PRIVATE is filesystem-private but still plaintext on the device
```

**SAFE** — using `EncryptedSharedPreferences` from Jetpack Security:
```java
SharedPreferences encPrefs = EncryptedSharedPreferences.create(
    "secret_prefs", masterKeyAlias, context,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM);
encPrefs.edit().putString("auth_token", token).apply();
```

**TRUE POSITIVE**: `putString` / `putInt` / `putLong` writing a value whose variable name or assignment origin contains tokens such as `password`, `token`, `secret`, `key`, `credential`, `ssn`, `pin`, or `cvv`.

**FALSE POSITIVE**: `putString("theme", userSelectedTheme)` — non-sensitive UI preference. Do not flag when the stored value demonstrably carries no authentication or personal-data semantics.

---

#### Logging Sensitive Data

**VULN**:
```java
Log.d(TAG, "User password: " + password);
Log.i(TAG, "Auth token=" + authToken);
Log.e(TAG, "Login failed for user: " + email + " pwd=" + pwd);
```

**SAFE** — sanitized log message:
```java
Log.d(TAG, "Login attempt for user: " + userId);  // no credential value
```

**TRUE POSITIVE**: `Log.d/i/v/w/e` where the concatenated or formatted string contains a variable whose name matches `password`, `passwd`, `token`, `secret`, `key`, `credential`, `pin`, `cvv`, `ssn`, or `dob`.

**FALSE POSITIVE**: `Log.d(TAG, "Request URL: " + url)` where `url` is a non-sensitive endpoint. Evaluate the variable name and assignment chain, not the presence of `Log` alone.

**Grep (Android Java/Kotlin):**
```bash
rg -n 'Log\.[divwe]\s*\(.*(password|token|secret|pin|ssn|cvv|email|phone|dob|iban)' --glob '*.{java,kt}'
```

---

#### External Storage Writes with Sensitive Data

**VULN**:
```java
File file = new File(Environment.getExternalStorageDirectory(), "user_data.json");
FileOutputStream fos = new FileOutputStream(file);
fos.write(sensitiveJson.getBytes());
```

**SAFE** — internal storage:
```java
FileOutputStream fos = openFileOutput("user_data.json", Context.MODE_PRIVATE);
fos.write(encryptedData);
```

**TRUE POSITIVE**: `getExternalStorageDirectory()` or `getExternalFilesDir()` combined with a write operation whose data originates from a sensitive variable or network response containing credentials/PII.

**FALSE POSITIVE**: Writing a cached image, log file, or media file to external storage where the content carries no sensitive semantics.

---

#### SQLite Cleartext Sensitive Data

**VULN** — token/password inserted without encryption or parameterization:
```java
ContentValues cv = new ContentValues();
cv.put("auth_token", token);
db.insert("sessions", null, cv);
db.execSQL("UPDATE users SET password='" + password + "' WHERE id=" + userId);
```

**VULN (Kotlin)**:
```kotlin
database.execSQL("INSERT INTO creds (pin) VALUES ('$pin')")
```

**SAFE** — store only opaque references; encrypt value column with Keystore-wrapped key:
```java
SecretKey key = (SecretKey) keyStore.getKey("db_key", null);
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
// encrypt token bytes before cv.put("auth_token", encryptedBlob)
```

**TRUE POSITIVE**: `insert` / `execSQL` / `rawQuery` writing or updating columns whose names or bound values trace to `token`, `password`, `secret`, `pin`, `ssn`, `credential`, or PII variables without an intervening encrypt call or Keystore key use.

**FALSE POSITIVE**: SQLite storing non-sensitive app state (UI prefs, cache keys, analytics event IDs).

**Grep (Android Java/Kotlin):**
```bash
rg -n 'execSQL\s*\(|\.insert\s*\(|ContentValues\(\)|rawQuery\s*\(' --glob '*.{java,kt}'
rg -n 'put\s*\(\s*"(auth_token|password|secret|pin|token|credential|ssn)"' --glob '*.{java,kt}'
```

---

#### Android Keystore for Key Material

**VULN** — symmetric key generated/stored outside hardware-backed Keystore:
```java
byte[] keyBytes = "static_aes_key_16b".getBytes(StandardCharsets.UTF_8);
SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
```

**SAFE** — hardware-backed key, non-exportable:
```java
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
    "auth_key", KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setUserAuthenticationRequired(true)
    .build();
KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
kg.init(spec);
SecretKey key = kg.generateKey();
```

**TRUE POSITIVE**: `SecretKeySpec` / `KeySpec` constructed from a hardcoded byte array or `SharedPreferences` string when protecting credentials or tokens; absence of `"AndroidKeyStore"` in the key-generation path for sensitive crypto.

**FALSE POSITIVE**: Keystore keys used only for TLS client auth or signing where the private key never encrypts local PII.

**Grep (Android Java/Kotlin):**
```bash
rg -n 'SecretKeySpec|KeyStore\.getInstance\s*\(\s*"AndroidKeyStore"' --glob '*.{java,kt}'
rg -n 'KeyGenParameterSpec|EncryptedSharedPreferences\.create' --glob '*.{java,kt}'
```

---

#### Hardcoded Credentials / Keys

**VULN**:
```java
private static final String API_KEY = "AIzaSyD-EXAMPLE-KEY-12345";
private static final String DB_PASSWORD = "Sup3rS3cr3t!";
String jwt = signJWT(payload, "hardcoded_secret_key");
```

**TRUE POSITIVE**: String literal assigned to a variable named `key`, `secret`, `password`, `token`, `apiKey`, `privateKey`, or `credential` — particularly when the literal length and entropy are consistent with a real credential (e.g., > 16 characters with mixed case and digits).

**FALSE POSITIVE**: Placeholder strings such as `"YOUR_KEY_HERE"`, `"TODO"`, or `"REPLACE_ME"` in configuration templates. Also do not flag localization strings, error message literals, or display labels even when they appear in a field named `key`.

**Cross-ref:** Full hardcoded-secret detection (provider-format catalog, entropy heuristics, public-exposure model — and on mobile **all** app source/binary is client-exposed) lives in the `hardcoded_secrets` reference (CWE-798). `hardcoded_code_backdoor` is CWE-506 (malicious embedded code), a different class.

---

### Intent Injection / Exported Components

#### Exported Activity / Service / Receiver Without Permission Check

**VULN** — exported with no `android:permission`:
```xml
<activity android:name=".DeepLinkActivity" android:exported="true" />
<service android:name=".SyncService" android:exported="true" />
<receiver android:name=".TokenReceiver" android:exported="true" />
```

```java
// Inside DeepLinkActivity.onCreate — no caller identity check
String target = getIntent().getStringExtra("redirect");
startActivity(new Intent(this, InternalActivity.class).putExtra("url", target));
```

**SAFE** — permission-gated export:
```xml
<activity android:name=".AdminActivity"
          android:exported="true"
          android:permission="com.example.permission.ADMIN" />
```

**TRUE POSITIVE**: `android:exported="true"` on a component that reads intent extras and uses them in a sensitive operation (file access, SQL query, `startActivity`, `loadUrl`) without validating the caller via `checkCallingPermission` or an explicit allowlist.

**FALSE POSITIVE**: Launcher Activity with `<intent-filter><action android:name="android.intent.action.MAIN"/>` — this must be exported; flag only when it also passes intent extras to dangerous sinks without validation.

---

#### Intent Data Used in SQL / File Path Without Validation

**VULN**:
```java
String id = getIntent().getStringExtra("user_id");
Cursor c = db.rawQuery("SELECT * FROM users WHERE id='" + id + "'", null);
```

```java
String filename = getIntent().getStringExtra("file");
File f = new File(getFilesDir(), filename);  // path traversal if filename contains ../
FileInputStream fis = new FileInputStream(f);
```

**SAFE**:
```java
String id = getIntent().getStringExtra("user_id");
Cursor c = db.rawQuery("SELECT * FROM users WHERE id=?", new String[]{id});
```

**TRUE POSITIVE**: `getIntent().getStringExtra(...)` / `getIntent().getData()` value flows without sanitization into `rawQuery`, `execSQL`, `new File(base, userValue)`, `loadUrl`, or `Runtime.exec`.

**FALSE POSITIVE**: Intent extra used only as a display label rendered in a `TextView` with no HTML rendering enabled.

---

#### Deep Link / Intent-Filter Exposure

**VULN** — exported handler accepts arbitrary scheme/host without validation:
```xml
<activity android:name=".DeepLinkActivity" android:exported="true">
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="myapp" android:host="*"/>
    </intent-filter>
</activity>
```

```kotlin
val redirect = intent.data?.getQueryParameter("url")
startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(redirect)))
```

**SAFE** — path-prefix allowlist before navigation:
```kotlin
val path = intent.data?.path ?: return
if (!path.startsWith("/safe/")) return
```

**TRUE POSITIVE**: `<intent-filter>` with `VIEW`/`BROWSABLE` on an exported component where `intent.data`, `getQueryParameter`, or `getStringExtra` flows to `startActivity`, `loadUrl`, or file I/O without host/path/scheme validation.

**FALSE POSITIVE**: App Links with `autoVerify="true"` where handler only maps known path segments to internal routes with hardcoded targets.

**Grep (Android Java/Kotlin/XML):**
```bash
rg -n 'android:scheme|android:host|intent-filter|ACTION_VIEW|getQueryParameter|intent\.data' --glob '*.{java,kt,xml}'
rg -n 'android:exported\s*=\s*"true"' --glob 'AndroidManifest.xml'
```

---

#### WebView Loading Intent-Supplied URL

**VULN**:
```java
String url = getIntent().getStringExtra("url");
webView.loadUrl(url);  // arbitrary URL including javascript: or file://
```

**SAFE**:
```java
String url = getIntent().getStringExtra("url");
if (url != null && url.startsWith("https://trusted.example.com/")) {
    webView.loadUrl(url);
}
```

**TRUE POSITIVE**: `webView.loadUrl(...)` or `webView.loadData(...)` where the argument is directly derived from `getIntent()`, `getStringExtra`, `uri.getQueryParameter`, or another IPC channel without a strict prefix or allowlist check.

**FALSE POSITIVE**: `webView.loadUrl(BuildConfig.BASE_URL + "/help")` where `BuildConfig.BASE_URL` is a compile-time constant.

---

### WebView RCE

#### addJavascriptInterface Exposure

**VULN**:
```java
webView.getSettings().setJavaScriptEnabled(true);
webView.addJavascriptInterface(new FileAccessBridge(this), "NativeBridge");
// FileAccessBridge methods are now callable from any page loaded in the WebView
```

**SAFE** — restrict to trusted origins only and remove the interface when not needed:
```java
// On API < 17, addJavascriptInterface is exploitable regardless.
// On API >= 17, only @JavascriptInterface-annotated methods are exposed,
// but loading untrusted URLs still allows arbitrary method invocation.
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
    webView.addJavascriptInterface(bridge, "NativeBridge");
    webView.loadUrl("https://internal.example.com/ui");
} // ensure the loaded URL is never user-controlled
```

**TRUE POSITIVE**: `addJavascriptInterface` present AND `setJavaScriptEnabled(true)` AND `loadUrl` / `loadData` where the loaded URL or content is user-controlled or loaded from an untrusted origin.

**FALSE POSITIVE**: `addJavascriptInterface` where the WebView exclusively loads a bundled `file:///android_asset/` resource that contains no user-generated content and JavaScript is enabled only for that asset.

---

#### JavaScript Enabled with User-Controlled URL

**VULN**:
```java
WebSettings settings = webView.getSettings();
settings.setJavaScriptEnabled(true);
settings.setAllowFileAccessFromFileURLs(true);
webView.loadUrl(urlFromIntent);
```

**TRUE POSITIVE**: `setJavaScriptEnabled(true)` combined with `loadUrl` / `loadDataWithBaseURL` where the URL argument traces to external input (intent extra, deep link, push notification payload).

**FALSE POSITIVE**: `setJavaScriptEnabled(true)` with a hardcoded `loadUrl("https://app.example.com/home")` — no user control over the loaded origin.

---

#### WebView File-Access Misconfiguration

**VULN** — JS + cross-origin file access with untrusted content:
```java
WebSettings s = webView.getSettings();
s.setJavaScriptEnabled(true);
s.setAllowFileAccess(true);
s.setAllowFileAccessFromFileURLs(true);
s.setAllowUniversalAccessFromFileURLs(true);
webView.loadUrl(userSuppliedUrl);
```

**SAFE** — disable file URL access when loading remote or user-controlled pages:
```java
s.setAllowFileAccess(false);
s.setAllowFileAccessFromFileURLs(false);
s.setAllowUniversalAccessFromFileURLs(false);
```

**TRUE POSITIVE**: Any of `setAllowFileAccess(true)`, `setAllowFileAccessFromFileURLs(true)`, `setAllowUniversalAccessFromFileURLs(true)`, or `setAllowContentAccess(true)` on a WebView that also has `setJavaScriptEnabled(true)` and loads non-bundled URLs.

**FALSE POSITIVE**: WebView loading only `file:///android_asset/` with file access enabled and JavaScript disabled.

**Grep (Android Java/Kotlin):**
```bash
rg -n 'setAllowFileAccess|setAllowUniversalAccessFromFileURLs|setAllowFileAccessFromFileURLs|setAllowContentAccess|addJavascriptInterface|setJavaScriptEnabled' --glob '*.{java,kt}'
```

---

#### shouldOverrideUrlLoading Returning False Unconditionally

**VULN**:
```java
webView.setWebViewClient(new WebViewClient() {
    @Override
    public boolean shouldOverrideUrlLoading(WebView view, String url) {
        return false;  // allows all navigations including javascript: and file://
    }
});
```

**TRUE POSITIVE**: `shouldOverrideUrlLoading` returns `false` (or is absent) and no URL scheme validation is applied elsewhere before loading user-controlled navigations.

**FALSE POSITIVE**: Returns `false` only after an explicit scheme/host allowlist check has already confirmed the URL is safe.

---

### Insecure IPC

#### ContentProvider Without Permission Check

**VULN** — exported with no `android:permission`:
```xml
<provider
    android:name=".UserDataProvider"
    android:authorities="com.example.provider"
    android:exported="true" />
```

```java
@Override
public Cursor query(Uri uri, String[] projection, String selection,
                    String[] selectionArgs, String sortOrder) {
    return db.rawQuery("SELECT * FROM users WHERE " + selection, null);
    // 'selection' comes directly from untrusted caller
}
```

**SAFE**:
```xml
<provider
    android:name=".UserDataProvider"
    android:authorities="com.example.provider"
    android:exported="true"
    android:readPermission="com.example.permission.READ_DATA"
    android:writePermission="com.example.permission.WRITE_DATA" />
```

**TRUE POSITIVE**: `android:exported="true"` ContentProvider with no `android:permission` / `android:readPermission` attribute AND a `query` / `insert` / `update` / `delete` override that uses `selection` or `selectionArgs` in a raw SQL call without parameterization.

**FALSE POSITIVE**: ContentProvider exported solely for use by a companion app that shares the same `android:sharedUserId` and is declared as a system component. Still recommend adding permission protection as defense-in-depth.

---

#### SQL Injection in ContentProvider query()

**VULN**:
```java
public Cursor query(Uri uri, String[] proj, String selection, String[] args, String sort) {
    String query = "SELECT * FROM messages WHERE sender='" + selection + "'";
    return db.rawQuery(query, null);
}
```

**SAFE**:
```java
public Cursor query(Uri uri, String[] proj, String selection, String[] args, String sort) {
    return db.query("messages", proj, "sender=?", new String[]{ args[0] }, null, null, sort);
}
```

**TRUE POSITIVE**: `selection` parameter concatenated into the SQL string passed to `rawQuery` or `execSQL` inside a ContentProvider method.

**FALSE POSITIVE**: `selection` passed as the `whereClause` argument of `db.query(table, proj, whereClause, whereArgs, ...)` where it is used as a parameterized clause with `whereArgs` — only flag if the literal SQL string is assembled by concatenation.

---

#### PendingIntent with Empty Base Intent

**VULN**:
```java
Intent base = new Intent();  // empty — action and component unset
PendingIntent pi = PendingIntent.getActivity(context, 0, base, PendingIntent.FLAG_MUTABLE);
// A malicious app receiving this PendingIntent can fill in any target
```

**SAFE**:
```java
Intent base = new Intent(context, TargetActivity.class);
PendingIntent pi = PendingIntent.getActivity(context, 0, base,
    PendingIntent.FLAG_IMMUTABLE);
```

**TRUE POSITIVE**: `PendingIntent` constructed from an `Intent` with no `setComponent`, `setClass`, or explicit action set, especially when `FLAG_MUTABLE` is used on API 31+.

**FALSE POSITIVE**: `FLAG_IMMUTABLE` PendingIntents with fully specified explicit intents — immutable PendingIntents cannot be modified by the recipient.

---

### Insecure Crypto (Android)

#### ECB Mode

**VULN**:
```java
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, secretKey);
```

**SAFE**:
```java
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
```

**TRUE POSITIVE**: `Cipher.getInstance` argument contains `"ECB"` for any algorithm.

**FALSE POSITIVE**: None — ECB mode is never safe for encrypting data longer than one block.

---

#### Static / Zero IV

**VULN**:
```java
IvParameterSpec iv = new IvParameterSpec(new byte[16]);  // all-zero IV
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, key, iv);
```

**SAFE**:
```java
byte[] ivBytes = new byte[16];
new SecureRandom().nextBytes(ivBytes);
IvParameterSpec iv = new IvParameterSpec(ivBytes);
```

**TRUE POSITIVE**: `new IvParameterSpec(new byte[N])` — zero-initialized byte array used as IV, or any IV literal such as `"0000000000000000".getBytes()`.

**FALSE POSITIVE**: IV array that is subsequently filled by `SecureRandom.nextBytes(iv)` before use — evaluate the data flow, not just the allocation site.

---

#### Weak Key Size

**VULN**:
```java
KeyGenerator kg = KeyGenerator.getInstance("AES");
kg.init(64);  // 64-bit key — far below the 128-bit minimum
SecretKey key = kg.generateKey();
```

**SAFE**:
```java
KeyGenerator kg = KeyGenerator.getInstance("AES");
kg.init(256);
```

**TRUE POSITIVE**: `KeyGenerator.init(n)` where `n < 128` for AES, or `n < 2048` for RSA, or `n < 256` for EC.

**FALSE POSITIVE**: Key size argument is a variable whose value is determined at runtime from a validated configuration — flag only when the literal value is demonstrably weak.

---

#### java.util.Random for Security Tokens

**VULN**:
```java
Random rng = new Random();
String token = Long.toHexString(rng.nextLong());
session.setToken(token);
```

**SAFE**:
```java
SecureRandom rng = new SecureRandom();
byte[] tokenBytes = new byte[32];
rng.nextBytes(tokenBytes);
String token = Base64.encodeToString(tokenBytes, Base64.URL_SAFE | Base64.NO_WRAP);
```

**TRUE POSITIVE**: `new Random()` or `Math.random()` used to generate values assigned to variables named `token`, `nonce`, `otp`, `salt`, `sessionId`, `key`, or `secret`.

**FALSE POSITIVE**: `new Random()` used for UI randomness (shuffle, animation, A/B bucket assignment) where the value has no security meaning.

---

### Backup Exposure (allowBackup)

**VULN** — full backup enabled; SharedPreferences/SQLite included in backup blob:
```xml
<application
    android:allowBackup="true"
    android:fullBackupContent="@xml/backup_rules"
    ...>
```

**VULN** — `allowBackup` omitted on API < 31 (defaults to `true`):
```xml
<application android:label="@string/app_name" ...>
```

**SAFE**:
```xml
<application android:allowBackup="false" android:fullBackupContent="false" ...>
```

**TRUE POSITIVE**: `android:allowBackup="true"` or attribute absent on `<application>` when the app stores credentials in SharedPreferences, SQLite, or internal files without `EncryptedSharedPreferences` / Keystore protection.

**FALSE POSITIVE**: `allowBackup="false"` explicitly set; or backup rules XML excludes all sensitive domains via `tools:node="remove"`.

**Grep (Android XML):**
```bash
rg -n 'allowBackup|fullBackupContent|data-extraction-rules' --glob '**/AndroidManifest.xml'
rg -n 'domain path=' --glob '**/backup_rules.xml'
```

---

## Clipboard, Screenshot & Integrity (shared with iOS)

**PII log indicators — extend variable-name heuristics with:**
```bash
# Android
rg -n 'Log\.[divwe]\s*\(.*(email|phone|ssn|dob|address|iban|pan|cvv|accountNumber)' --glob '*.{java,kt}'
# iOS
rg -n 'print\s*\(|NSLog\s*\(.*(email|phone|ssn|dob|address|iban|pan|cvv|accountNumber)' --glob '*.{swift,m,mm}'
```

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
| SharedPreferences storing credentials | Android | CWE-312 | HIGH |
| Logging sensitive data | Android / iOS | CWE-312 | MEDIUM |
| External storage write of sensitive data | Android | CWE-312 | HIGH |
| Hardcoded credentials / keys in source | Android / iOS | CWE-798 | HIGH |
| Exported Activity/Service/Receiver without permission | Android | CWE-927 | HIGH |
| Intent extra used in raw SQL (injection) | Android | CWE-89 | HIGH |
| Intent extra used in file path (traversal) | Android | CWE-22 | HIGH |
| WebView loading intent URL (arbitrary) | Android | CWE-939 | HIGH |
| addJavascriptInterface with user-controlled URL | Android | CWE-749 | HIGH |
| setJavaScriptEnabled with user-controlled URL | Android | CWE-749 | MEDIUM |
| shouldOverrideUrlLoading returning false unconditionally | Android | CWE-939 | MEDIUM |
| ContentProvider exported without permission | Android | CWE-927 | HIGH |
| SQL injection in ContentProvider query() | Android | CWE-89 | HIGH |
| PendingIntent with empty base intent | Android | CWE-927 | MEDIUM |
| AES/ECB mode | Android | CWE-327 | HIGH |
| Static / zero IV | Android | CWE-329 | HIGH |
| AES key size < 128 bits | Android | CWE-326 | HIGH |
| java.util.Random for security tokens | Android | CWE-338 | HIGH |
| SQLite storing credentials/tokens in cleartext | Android | CWE-312 | HIGH |
| Symmetric key outside Android Keystore | Android | CWE-522 | HIGH |
| allowBackup enabled with local secrets | Android | CWE-530 | MEDIUM |
| Deep link parameter to navigation sink | Android / iOS | CWE-939 | HIGH |
| WebView file-URL access + JavaScript enabled | Android | CWE-749 | HIGH |
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

**Android (Java/Kotlin/XML):**
```bash
# Storage
rg -n 'SharedPreferences|EncryptedSharedPreferences|MODE_WORLD_READABLE|openFileOutput|getExternalStorage' --glob '*.{java,kt}'
rg -n 'ContentValues|execSQL|rawQuery|\.insert\s*\(' --glob '*.{java,kt}'
rg -n 'AndroidKeyStore|KeyGenParameterSpec|SecretKeySpec' --glob '*.{java,kt}'
# IPC / components
rg -n 'android:exported|getIntent\(\)|getStringExtra|sendBroadcast|startActivity|startService' --glob '*.{java,kt,xml}'
# WebView
rg -n 'WebView|loadUrl|addJavascriptInterface|setJavaScriptEnabled|setAllowFileAccess' --glob '*.{java,kt}'
# Logging / clipboard / backup
rg -n 'Log\.[divwe]\s*\(|ClipData|setPrimaryClip|allowBackup' --glob '*.{java,kt,xml}'
# Integrity
rg -n 'RootBeer|isRooted|PlayIntegrity|FLAG_SECURE' --glob '*.{java,kt}'
```

**Cross-lens refs:**
- Hardcoded secrets → `hardcoded_secrets` (CWE-798)
- TLS trust bypass / missing pinning → `certificate_validation`, `cleartext_transmission` (CWE-295, CWE-319)
