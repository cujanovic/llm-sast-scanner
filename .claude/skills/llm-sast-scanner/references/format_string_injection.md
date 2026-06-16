---
name: format-string-injection
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

Commonly affected languages: Java, C/C++, JavaScript, C#, Ruby, Swift. Python and Go lack dedicated CWE-134 security detection (Python has formatting *correctness* checks only, e.g. wrong argument counts).

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

## Common False Alarms

- User input passed as `%s` data argument with a string-literal format (not the format parameter)
- Numeric/boolean remote values blocked by Java/C++ type barriers
- C/C++ custom printf implementations where inner format strings are bounded local literals
- `logger.info("{}", userInput)` SLF4J-style — `{}` placeholders are a different class (see log injection); Java `LoggerFormatMethod` uses distinct `{}` syntax

## Business Risk

- **C/C++**: memory corruption, arbitrary read/write, potential RCE (critical severity)
- **Java/C#/JS**: `FormatException`/crash → DoS; positional specifiers (`%1$tm`) leak unintended object fields
- **Logging integrity**: `%d`/`%s` injection in usernames corrupts audit trails ( overlaps with CWE-117)
- **Compliance**: unintended PII exposure via format positional access in error messages

## Core Principle

Treat format strings as trusted, constant templates. Pass all external data exclusively as trailing format *arguments* — use `"%s"` (or `{}` for SLF4J-style loggers) as the format and never concatenate or interpolate user input into the format position.
