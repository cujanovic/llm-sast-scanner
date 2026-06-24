---
name: php_security
description: PHP-specific vulnerability detection — dangerous functions, type juggling, file inclusion, object injection, framework sinks, configuration weaknesses, variable injection (extract/parse_str/variable variables), dynamic function and method calls, stream-wrapper and Phar deserialization, php://filter chains, and second-order/stored taint via $_SESSION and database reads
---

# PHP Security

PHP has numerous language-specific vulnerability patterns beyond the common OWASP categories. This reference covers PHP-specific sinks, type juggling exploits, object injection via `unserialize()`, dynamic code execution, dangerous configuration settings, and framework-specific patterns (Laravel, Symfony, CodeIgniter, WordPress).

## CWE Classification

- **CWE-78**: OS Command Injection
- **CWE-94**: Code Injection
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-22**: Path Traversal
- **CWE-843**: Type Confusion (via type juggling)

## PHP Dangerous Function Sinks

### Code/Command Execution Sinks

```php
// CRITICAL: any user input reaching these functions
eval($_GET['code']);
eval('$var = ' . $_POST['value'] . ';');
assert($_GET['assertion']);                    // PHP < 8: assert() can execute code strings
preg_replace('/' . $_GET['pattern'] . '/e', $_GET['replacement'], $subject);  // /e modifier (PHP < 7)

exec($_GET['cmd'], $output);
system($_GET['cmd']);
passthru($_GET['cmd']);
shell_exec($_GET['cmd']);
`{$_GET['cmd']}`;                             // backtick operator
popen($_GET['cmd'], 'r');
proc_open($_GET['cmd'], $desc, $pipes);

// VULN indicator: user-controlled variable reaching any of the above
```

### Dynamic Include / Require

```php
// VULNERABLE: LFI / RFI via dynamic include
include($_GET['page']);
require($_GET['page']);
include_once($_GET['template']);
require_once($_GET['module']);

// VULNERABLE: with partial control (may still be LFI)
include('templates/' . $_GET['theme'] . '.php');
include($_GET['lang'] . '/messages.php');
// Bypasses: null byte (%00 in PHP < 5.3.4), wrappers (php://filter, zip://)

// VULN indicator: any $_GET/$_POST/$_COOKIE/$_REQUEST in include/require argument
```

### File Operations

```php
// VULNERABLE: path traversal in file ops
file_get_contents($_GET['file']);
file_put_contents($_GET['file'], $data);
readfile($_GET['path']);
fopen($_GET['filename'], 'r');
copy($_FILES['upload']['tmp_name'], $_GET['destination']);

// VULNERABLE: SSRF via file_get_contents with URL
$data = file_get_contents($_GET['url']);    // supports http://, ftp://
```

### Stream-wrapper & Phar sinks (filesystem ops are deserialization/LFI sinks)

Any filesystem function that accepts an attacker-controlled path is more than path traversal — PHP **stream wrappers** turn it into an LFI/RCE/deserialization sink:

```php
// VULNERABLE: php://filter CHAIN RCE — chaining convert.iconv.* filters generates
//   arbitrary bytes from no file, turning any file-read sink into RCE-capable output
//   (no allow_url_include needed). Treat php://filter reaching include/eval-class sinks as RCE.
include($_GET['page']);   // attacker: php://filter/convert.iconv.<...long chain...>/resource=/etc/passwd

// VULNERABLE: data:// / expect:// wrappers
include("data://text/plain;base64," . $b64);     // RCE if allow_url_include=On
$x = file_get_contents($_GET['p']);              // expect://id, http://… (SSRF)

// VULNERABLE: Phar deserialization — ANY filesystem op on a phar:// path (or attacker-controlled
//   path that can be set to phar://) deserializes Phar metadata → triggers POP gadget chain,
//   even without a literal unserialize() call. file_exists / is_file / fopen / include / getimagesize…
file_exists($_GET['path']);                      // attacker: phar://uploaded.jpg/test
```

See `path_traversal_lfi_rfi.md` (wrapper/LFI detail) and `insecure_deserialization.md` (Phar/POP gadget chains).

### Variable Injection (user keys become local variables)

Functions that materialize variables from a user-controlled array/string let an attacker **set or overwrite arbitrary local variables** — a notorious source of auth bypass and uninitialized-variable abuse:

```php
// VULNERABLE: every key in $_POST becomes a local variable (e.g. $isAdmin, $authenticated)
extract($_POST);                                 // attacker: ?isAdmin=1 → $isAdmin = 1
extract($_GET, EXTR_OVERWRITE);                  // can overwrite already-set trusted vars

// VULNERABLE: parse_str into local scope (no second arg) — same effect as extract
parse_str($_SERVER['QUERY_STRING']);             // creates locals from the query string
mb_parse_str($input);                            // same footgun
import_request_variables('gpc');                 // PHP < 5.4 — register_globals on demand

// VULNERABLE: variable variables driven by user keys
foreach ($_GET as $k => $v) { $$k = $v; }        // $$k sets arbitrary variable names

// SAFE: parse into an explicit array, never the local scope
parse_str($qs, $out);                            // values land in $out['...'], no locals created
// SAFE: extract only allowlisted keys with a prefix, EXTR_SKIP to not overwrite
extract($data, EXTR_PREFIX_ALL | EXTR_SKIP, 'u');
```

### Dynamic / Variable Function & Method Calls (code-exec sinks)

When the **callable name** (not just its arguments) is user-controlled, the attacker picks which function/method runs — reachable RCE or auth-logic bypass:

```php
// VULNERABLE: variable function / method / static call with user-controlled name
$fn = $_GET['action']; $fn($arg);                // $fn = 'system' → system($arg)
$obj->{$_GET['method']}($arg);                   // attacker selects the method
call_user_func($_GET['cb'], $arg);               // cb = 'system' / 'exec' / 'assert'
call_user_func_array($_POST['fn'], $_POST['args']);  // name AND args attacker-controlled
$class::{$_GET['m']}();                           // dynamic static method
new $_GET['class']($arg);                         // dynamic instantiation → __construct gadget

// SAFE: allowlist the callable; never derive the function/method name from input
$allowed = ['list' => 'listItems', 'view' => 'viewItem'];
$method = $allowed[$_GET['action']] ?? abort(400);
$this->$method($arg);
```

## PHP Type Juggling Vulnerabilities

### Loose Comparison (`==`) Exploits

```php
// VULNERABLE: loose comparison with magic hash values
$token = md5($user_input);
if ($token == "0") { ... }         // any MD5 starting with "0e" + digits == 0 in PHP
if ($token == 0) { ... }           // "0e..." == 0 is TRUE

// VULNERABLE: authentication bypass via type juggling
$hash = hash('md5', $_POST['password']);
if ($hash == $_SESSION['stored_hash']) {  // "0e..." == "0e..." even if different
    // authenticated
}

// VULNERABLE: JSON type confusion
$data = json_decode($_POST['data']);
if ($data->token == $expected_token) {    // if $data->token is integer 0 and $expected_token is "0e..."
    // bypass
}

// SAFE: use strict === comparison
if ($hash === $expected_hash) { ... }
```

**Magic hash values** (MD5 hashes starting with `0e` + digits):
- `240610708` → MD5 = `0e462097431906509019562988736854`
- `QNKCDZO` → MD5 = `0e830400451993494058024219903391`
- `s878926199a` → SHA1 = `0e545993274517709034328855841020`

### Type Juggling in Switch/in_array

```php
// VULNERABLE: in_array without strict mode
$roles = ['admin', 'user', 'guest'];
if (in_array($_POST['role'], $roles)) { ... }
// Attacker sends role=0 → in_array(0, ['admin','user','guest']) === TRUE (0 == 'admin' in loose mode)

// SAFE:
if (in_array($_POST['role'], $roles, true)) { ... }  // third param true = strict

// VULNERABLE: switch uses loose comparison
switch ($_GET['status']) {
    case 1: grantAdmin(); break;    // status=true or status="1abc" may match
}
```

## PHP Object Injection (Deserialization)

```php
// VULNERABLE: unserialize() on user-controlled input
$data = unserialize($_COOKIE['user']);
$obj = unserialize(base64_decode($_GET['data']));
$obj = unserialize(file_get_contents($_POST['serialized_file']));

// IMPACT: If the application has classes with __wakeup(), __destruct(),
//         __toString() magic methods that perform dangerous operations:
class FileLogger {
    public $logFile;
    public function __destruct() {
        file_put_contents($this->logFile, "destroyed");  // arbitrary file write
    }
}
// Attacker crafts: O:10:"FileLogger":1:{s:7:"logFile";s:15:"/var/www/evil.php";}

// VULN indicator: unserialize() accepting any $_GET/$_POST/$_COOKIE/$_REQUEST/$_SERVER data
// ALSO check: __wakeup, __destruct, __toString magic methods doing file/exec/eval operations
```

## PHP Framework-Specific Patterns

### Laravel

```php
// VULNERABLE: raw query with user input (SQL injection)
DB::select("SELECT * FROM users WHERE name = '" . $request->name . "'");
DB::statement("DELETE FROM logs WHERE id = " . $request->id);

// VULNERABLE: Mass assignment without $guarded/$fillable protection
User::create($request->all());             // if $fillable not defined, all fields assignable
// Attacker can set is_admin=1 if no $guarded = ['is_admin']

// VULNERABLE: Blade template with raw output (XSS)
{!! $user_input !!}                        // unescaped output
// SAFE:
{{ $user_input }}                          // escaped by default

// VULNERABLE: deserialization in cookie/session (HMAC bypass not considered)
// Laravel signed cookies use app key — if app key is leaked, cookie forgery enables deserialization

// VULNERABLE: eval in Blade custom directives
Blade::directive('inject', function ($expression) {
    return "<?php eval({$expression}); ?>";   // dangerous custom directive
});
```

### Symfony

```php
// VULNERABLE: createQuery with user-controlled DQL
$query = $em->createQuery("SELECT u FROM User u WHERE u.name = '" . $_GET['name'] . "'");
// SAFE: use setParameter()
$query = $em->createQuery('SELECT u FROM User u WHERE u.name = :name')
            ->setParameter('name', $_GET['name']);

// VULNERABLE: Symfony YAML unsafe parsing
$data = Yaml::parse($userInput, Yaml::PARSE_OBJECT);
// SAFE: Yaml::parse($userInput) — no PARSE_OBJECT flag
```

### WordPress

```php
// VULNERABLE: direct DB query without $wpdb->prepare()
$results = $wpdb->get_results("SELECT * FROM {$wpdb->posts} WHERE post_title = '" . $_GET['title'] . "'");
// SAFE:
$results = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$wpdb->posts} WHERE post_title = %s", $_GET['title']));

// VULNERABLE: add_action with eval (plugin code injection)
add_action('wp_ajax_run_code', function() {
    eval($_POST['code']);   // arbitrary PHP execution
});

// VULNERABLE: update_option with unvalidated user data
update_option('admin_email', $_POST['email']);  // may allow option injection

// VULNERABLE: file path construction from request
$template = get_template_directory() . '/' . $_GET['template'] . '.php';
include($template);   // path traversal in template param
```

### CodeIgniter

```php
// VULNERABLE: direct query without query builder
$this->db->query("SELECT * FROM users WHERE id = " . $this->input->get('id'));
// SAFE: use query bindings
$this->db->query("SELECT * FROM users WHERE id = ?", [$this->input->get('id')]);
```

## PHP Configuration Weaknesses (php.ini)

| Setting | Dangerous Value | Risk |
|---------|----------------|------|
| `allow_url_include` | `On` | RFI via include/require with http:// URLs |
| `allow_url_fopen` | `On` | SSRF via file_get_contents on URLs |
| `display_errors` | `On` in production | Information disclosure (paths, DB errors) |
| `register_globals` | `On` (PHP < 5.4) | Variable injection — `$_GET` populates globals |
| `magic_quotes_gpc` | off + no escaping | SQL injection facilitated |
| `session.use_strict_mode` | `0` | Session fixation attacks |
| `disable_functions` | missing exec/system | OS command execution enabled |

## PHP Superglobal Sources

All of the following are attacker-controlled sources:
- `$_GET['x']`, `$_POST['x']`, `$_COOKIE['x']`, `$_REQUEST['x']`
- `$_FILES['x']['name']`, `$_FILES['x']['type']` (MIME type — client-controlled)
- `$_SERVER['HTTP_HOST']`, `$_SERVER['HTTP_REFERER']`, `$_SERVER['HTTP_USER_AGENT']`
- `$_SERVER['QUERY_STRING']`, `$_SERVER['REQUEST_URI']`, `$_SERVER['PHP_SELF']`
- `getallheaders()`, `apache_request_headers()`
- `file_get_contents('php://input')`, `fopen('php://input', 'r')`

**Note**: `$_SERVER['PHP_SELF']` is often used in HTML forms and is XSS-injectable.

## Second-Order & Stored Taint (PHP)

The dangerous flow often does not start at a superglobal on *this* request. When tracing PHP, treat these as **tainted roots** too:

- **`$_SESSION` values are second-order tainted.** If any request anywhere writes user input into the session (`$_SESSION['x'] = $_POST['x'];`), then `$_SESSION['x']` is attacker-influenced on every later request. Grep the whole project for `$_SESSION['x'] =` to find the writer before clearing a finding as safe.
- **Database reads echo prior writes.** A value read back from the DB (`$row['name']`) is tainted if that column was ever populated from user input without sanitization at write time → stored XSS (`echo $row['name']`) or second-order SQLi (the read value re-concatenated into another raw query). Grep for `INSERT`/`UPDATE` touching the column.
- **Scope-merging propagates taint.** `include`/`require` merge the caller's and includee's variable scope; a tainted variable set before the include is visible inside it (and vice-versa). Follow includes when tracing.
- **`extract()` / `parse_str()` rename taint.** After `extract($_POST)`, every resulting local (`$username`, …) carries the taint of the corresponding key — trace those new variable names, not just `$_POST`.
- **Framework route/request binding are entry points.** Laravel/Symfony controller method parameters bound from `/user/{id}` or `Request` injection are tainted sources even though no superglobal appears.
- **Composer autoload widens the gadget pool.** For deserialization/Phar findings, every class under `vendor/` with `__wakeup`/`__destruct`/`__toString` is a candidate POP gadget — autoload makes them all reachable.

## PHP-Specific Detection Rules

### TRUE POSITIVE

- `eval(` + any superglobal or user-derived variable → **CONFIRM** (RCE)
- `include/require` + `$_GET/$_POST/$_COOKIE` → **CONFIRM** (LFI / RFI)
- `unserialize(` + superglobal or decoded cookie → **CONFIRM** + check for magic method gadgets
- `==` (loose) comparison in authentication/token validation → **CONFIRM** (type juggling bypass)
- `in_array($input, $list)` without `true` third argument in access control → **CONFIRM** (type juggling)
- `exec/system/passthru/shell_exec/popen/proc_open/pcntl_exec(` + user input → **CONFIRM** (OS command injection)
- `file_get_contents($_GET['url'])` or similar → **CONFIRM** (SSRF or LFI)
- `DB::select("...'" . $request->x . "'...")` in Laravel → **CONFIRM** (SQL injection)
- `extract(`/`parse_str($x)` (no 2nd arg)/`mb_parse_str(`/`import_request_variables(` on user data → **CONFIRM** (variable injection)
- `$$var`, `$fn(`, `$obj->$method(`, `call_user_func(`/`call_user_func_array(`, `new $class(` with user-controlled name → **CONFIRM** (dynamic call → RCE / logic bypass)
- `php://filter` reaching `include`/`require`/eval-class sink → **CONFIRM** (filter-chain RCE); `data://`/`expect://` with `allow_url_include=On` → **CONFIRM**
- filesystem op (`file_exists`/`is_file`/`fopen`/`include`/`getimagesize`) on a path that can be `phar://` → **CONFIRM** + trace POP gadget chain
- `echo $row['col']` / raw query using a DB value whose column is populated from user input → **CONFIRM** (stored XSS / second-order SQLi)

### FALSE POSITIVE

- `unserialize()` used exclusively on server-generated, HMAC-signed data where the signature is validated *before* unserialize
- `include` with `basename()` applied to user input AND only static extension appended AND `allow_url_include=Off`
- `eval()` inside a template engine's own codebase (e.g., Smarty's compiled templates) — not a direct user-input path
