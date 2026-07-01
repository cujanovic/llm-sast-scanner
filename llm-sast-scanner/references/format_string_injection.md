---
name: format_string_injection
description: Externally-controlled format strings in printf-style APIs (CWE-134)
---

# Format String Injection (CWE-134)

When user input is used as the format string (not merely as a data argument) in printf-style functions, attackers can inject extra specifiers. In C/C++ this can cause memory corruption or information leaks; in managed languages (`String.format`, `console.log`, `string.Format`) it more often causes exceptions, garbled logs, or unintended access to positional arguments (information disclosure).

## Source → Sink Pattern

**Sources** (`ActiveThreatModelSource` / `RemoteFlowSource` / C++ `FlowSource`):
- HTTP parameters, headers, cookies, request body fields
- Environment variables, argv (C/C++)
- Any remote user-controlled string reaching the format argument

**Sinks** (format-string parameter position):
- **Java**: `String.format`, `formatted`, `PrintStream.printf`, `Formatter.format`, `Console.readLine`/`readPassword` format args
- **C/C++**: any `PrintfLikeFunction` argument — `printf`, `fprintf`, `sprintf`, `snprintf`, wrappers
- **JavaScript**: `console.log/debug/info/warn/error`, `console.assert` (2nd arg), `util.format`, `util.formatWithOptions`, `sprintf-js`, `printf`, `format-util`, `string-template`
- **C#**: `string.Format`, `String.Format`, `CompositeFormat.Parse`, and modeled format methods
- **Ruby**: `Kernel.printf`/`sprintf`, `IO#printf`, `String#%` receiver
- **Swift**: modeled uncontrolled format-string sinks
- **Objective-C / Cocoa**: `NSLog(userInput)`, `[NSString stringWithFormat:userInput]` / `+localizedStringWithFormat:`, `[NSString initWithFormat:]`, `[NSException raise:format:]`, `[label setText:[NSString stringWithFormat:userControlled]]`, and the C bridge `printf([userInput UTF8String])` — user input as the **format** string. The `%@` object specifier and `%n` make this a read/leak/crash primitive. **SAFE**: always a literal format with data as an argument — `NSLog(@"%@", userInput)`.
- **Python**: attacker-controlled template passed to `str.format`, `str.format_map`, `string.Formatter().format`/`vformat`, or `"...%s..." % user` where the *template* (not the data) is tainted. Unlike printf-style bugs, Python's `{}` field-access syntax lets the template **traverse object attributes and globals** — see the Python section below.

## Vulnerable Conditions

- User string concatenated into format position: `System.out.format(cardSecurityCode + " hint %1$ty.", date)`
- User string passed directly: `string.Format(format, surname, forenames)` where `format` is from `QueryString`
- Logging with tainted prefix: `console.log("Unauthorized access by " + user, ip)` — `%d` in `user` corrupts output
- Ruby interpolation in format position: `printf("attempt by #{params[:user]}: %s", ip)`
- C/C++: tainted data as first argument to `printf`-family (classic format-string vulnerability)

## Safe Patterns

- **Constant format string + data as arguments**:
  - Java: `System.out.format("%s is not the right value. Hint: %2$ty.", userValue, expirationDate)`
  - JS: `console.log("Unauthorized access attempt by %s", user, ip)`
  - Ruby: `printf("attempt by %s: %s", params[:user], request.ip)`
  - C#: `string.Format("Hello {0} {1}", surname, forenames)` with literal format only
- If displaying untrusted text as plain text: use `"%s"` as format and pass user value as sole trailing argument
- Never pass remote input as the format/template parameter; sanitize is secondary to structural separation

## Sanitizers / Barriers

Commonly affected languages: Java, C/C++, JavaScript, C#, Ruby, Swift, **Python**. Go lacks a dedicated CWE-134 security class (its `fmt` verbs do not expose attribute/global traversal). Python is **not** safe here despite lacking printf memory semantics: `str.format`/`format_map` on an attacker-controlled template is a real information-disclosure (sometimes secret-leak / RCE-adjacent) sink because the `{}` mini-language supports attribute and index access (`{0.__class__}`, `{x.__init__.__globals__[...]}`). Do not dismiss Python format calls as correctness-only.

**Java (`ExternallyControlledFormatString`)**
- **Barrier**: values typed as `NumericType` or `BooleanType` (not format-string carriers)
- **Sink**: first/format argument of `StringFormat` calls (`String.format`, `printf`, etc.)

**C/C++ (`UncontrolledFormatString`)**
- **Barrier**: arithmetic non-char types at sink; arithmetic non-char definitions
- **Exclusion**: sinks inside functions that *implement* printf-like parsing (inner `"%d"` locals not flagged)
- Tracks through `PrintfLikeFunction` wrappers to outermost call

**JavaScript / Ruby (`TaintedFormatString`)**
- **Sink**: format-string argument of `PrintfStyleCall` when at least one format argument exists
- **Source**: `RemoteFlowSource` by default

**C# (`UncontrolledFormatString`)**
- **Source**: `ActiveThreatModelSource`
- **Sink**: `FormatStringParseCall.getFormatExpr()` — `string.Format`, `CompositeFormat.Parse`, etc.

## Language Patterns

### Java

**VULN**: `System.out.format(cardSecurityCode + " is not the right value. Hint: the card expires in %1$ty.", expirationDate);`
**SAFE**: `System.out.format("%s is not the right value. Hint: the card expires in %2$ty.", cardSecurityCode, expirationDate);`

### JavaScript

**VULN**: `console.log("Unauthorized access attempt by " + user, ip);`
**SAFE**: `console.log("Unauthorized access attempt by %s", user, ip);`

### C/C++

**VULN**: `printf(userControlled);` — tainted format string to printf-like function.
**SAFE**: `printf("%s", userControlled);` — constant format, data as argument.

### C#

**VULN**: `FormattedName = string.Format(format, Surname, Forenames);` where `format = ctx.Request.QueryString["nameformat"]`.
**SAFE**: `FormattedName = string.Format("{0} {1}", Surname, Forenames);`

### Ruby

**VULN**: `printf("Unauthorised access attempt by #{params[:user]}: %s", request.ip)`
**SAFE**: `printf("Unauthorised access attempt by %s: %s", params[:user], request.ip)`

### Python (attribute/global traversal via `str.format`)

Python's `{}` format mini-language allows attribute access (`{0.attr}`), index access (`{0[key]}`), and chaining. If an attacker controls the **template** passed to `.format()`/`.format_map()`/`Formatter().vformat()`, they can walk from any passed object to module globals and read secrets — no printf-style memory bug required.

**VULN (full template control):**
```python
# user_template comes from request; objects are passed as data
template = request.args["greeting"]          # e.g. "{user.__class__.__init__.__globals__[CONFIG][SECRET_KEY]}"
return template.format(user=current_user)    # leaks app secret_key / DB DSN / config
```

**VULN (partial template control — real-world pattern):** even when only *part* of the literal is attacker-influenced, the whole string is still parsed as a template:
```python
# an id/name the attacker sets becomes part of the path, then the whole literal is .format()'d
url = ("http://{host}:{port}/log/" + log_relative_path).format(host=h, port=p)
# attacker sets the run_id inside log_relative_path to "{config.__class__...}" → field access fires
```
This is the mechanism behind externally-controlled-format-string findings in Python web apps: attacker-set identifiers flow into a literal that is later `.format()`'d with live objects, exposing `__globals__`, config dicts, `secret_key`, and connection strings (CWE-134 / information disclosure, can rise to **High/Critical** when secrets that enable auth forgery or DB access leak).

**SAFE:**
```python
# 1) Only ever .format() a TRUSTED literal template; pass user data as values:
"Hello {}".format(user_name)
# 2) For user-supplied templates, use string.Template ($-substitution) which cannot do attribute/index access:
from string import Template
Template(user_template).safe_substitute(name=user_name)
# 3) Never build the template string from any request-controlled fragment before calling .format()/.format_map().
```

**Barriers:** template is a string literal/constant; user input only appears in the *arguments* to `.format(...)`; f-strings (`f"{x}"`) are evaluated at definition with local scope and are **not** a remote-template sink (but never `eval`/`.format()` a runtime f-string-like user string). `.format_map(user_dict)` with a trusted literal template is safe; the risk is a tainted *template*.

## Common False Alarms

- User input passed as `%s` data argument with a string-literal format (not the format parameter)
- Numeric/boolean remote values blocked by Java/C++ type barriers
- C/C++ custom printf implementations where inner format strings are bounded local literals
- `logger.info("{}", userInput)` SLF4J-style — `{}` placeholders are a different class (see log injection); Java `LoggerFormatMethod` uses distinct `{}` syntax

## Business Risk

- **C/C++**: memory corruption, arbitrary read/write, potential RCE (critical severity)
- **Python**: `str.format`/`format_map` on a tainted template traverses `__globals__`/config → leaks `secret_key`, DB connection strings, tokens (High/Critical when the leaked secret enables auth forgery or DB access)
- **Java/C#/JS**: `FormatException`/crash → DoS; positional specifiers (`%1$tm`) leak unintended object fields
- **Logging integrity**: `%d`/`%s` injection in usernames corrupts audit trails ( overlaps with CWE-117)
- **Compliance**: unintended PII exposure via format positional access in error messages

## Core Principle

Treat format strings as trusted, constant templates. Pass all external data exclusively as trailing format *arguments* — use `"%s"` (or `{}` for SLF4J-style loggers) as the format and never concatenate or interpolate user input into the format position.
