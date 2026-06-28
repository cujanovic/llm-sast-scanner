---
name: expression_language_injection
description: Expression Language injection detection for OGNL, SpEL, MVEL, EL, Groovy — vulnerable code patterns where user input reaches EL evaluation sinks
---

# Expression Language Injection

> **Precedence note**: This file is the primary reference for all expression language injection vulnerabilities (SpEL, OGNL, MVEL, Jakarta EL, Groovy). When an EL injection finding overlaps with content in `rce.md` (which also covers EL/SpEL/OGNL sinks), the detection rules and tag guidance in THIS file take precedence. Use `rce.md` only for EL-related content that is not covered here (e.g., EL-to-command-chain classification).

EL injection occurs when user-controlled input is passed into an expression language evaluator without sanitization, allowing arbitrary code execution. This covers OGNL (Struts2), SpEL (Spring), MVEL, Jakarta EL, Groovy `GroovyShell`, and similar dynamic evaluation APIs.

## CWE Classification

- **CWE-94**: Improper Control of Generation of Code (Code Injection)
- **CWE-917**: Improper Neutralization of Special Elements Used in an Expression Language Statement

## Source → Sink Pattern

**Sources**: `request.getParameter()`, `@RequestParam`, `@PathVariable`, `@RequestBody`, HTTP headers, cookies

**Sinks**:
- OGNL: `Ognl.getValue(userInput, context, root)`
- SpEL: `parser.parseExpression(userInput).getValue(...)`
- MVEL: `MVEL.eval(userInput, vars)`
- EL: `ELProcessor.eval(userInput)`, `ExpressionFactory.createValueExpression(ctx, userInput, ...)`
- Groovy: `new GroovyShell().evaluate(userInput)`, `Eval.me(userInput)`
- Scripting: `ScriptEngine.eval(userInput)`, `new ScriptEngineManager().getEngineByName("groovy").eval(userInput)`

**Additional sinks by engine** (Java):
- SpEL: `ExpressionParser.parseExpression` / `parseRaw`; `Expression.getValue(...)` unless arg0 is `SimpleEvaluationContext`
- OGNL: `Ognl.getValue`, `parseExpression`, `compileExpression`; Struts2 `OgnlValueStack`, `TextParseUtil.translateVariables`; MyBatis OGNL sinks
- JEXL: `JexlEngine.createScript` / `createExpression` / `createTemplate` (JEXL 2/3) unless engine built with `JexlBuilder.sandbox()` / custom `JexlUberspect`
- MVEL: `MVEL.eval`, `compileExpression`, `ExpressionCompiler`, `MvelScriptEngine.compile`, `TemplateCompiler`
- Groovy: `GroovyShell.evaluate`, `GroovyClassLoader.parseClass`, `Eval.me`, `CompilationUnit.addSource`
- Jakarta EL: `ExpressionFactory.createValueExpression`, EL evaluation APIs
- BeanShell: `Interpreter.eval` / `source`
- JShell: `JShell.eval`
- Jython: Jython script execution

**Sanitizers / barriers**:
- SpEL: `SimpleEvaluationContext` constructor or `.forReadWriteDataBinding().build()` passed to `getValue`.
- JEXL: `JexlBuilder.uberspect(...)` / `.sandbox(...)` before `createScript`/`createExpression`.
- MVEL: numeric/boolean typed data.
- Groovy: extension barriers on dynamic evaluation paths.
- OGNL: sandbox via `-Dognl.security.manager` (not auto-detected unless modeled).

## Vulnerable Code Patterns

### OGNL (Struts2 / Apache Commons OGNL)

```java
// VULNERABLE: user input evaluated as OGNL expression
String expr = request.getParameter("expression");
Object result = Ognl.getValue(expr, context, root);

// VULNERABLE: Struts2 tag with user-controlled value attribute
// In JSP: <s:property value="%{request.getParameter('name')}"/>
// OGNL evaluation of request params via ValueStack
```

**VULN indicator**: `Ognl.getValue(...)` or `Ognl.parseExpression(...)` where the expression string is derived from HTTP input.

**Struts2 OGNL RCE condition**:
- `struts2-core` present in `pom.xml` at vulnerable version
- AND `struts.xml` contains `<action>` mapping that reaches the vulnerable code path
- Without both conditions, do NOT flag as high-confidence TP

### SpEL (Spring Expression Language)

```java
// VULNERABLE: user input as SpEL expression
String input = request.getParameter("query");
ExpressionParser parser = new SpelExpressionParser();
Expression expr = parser.parseExpression(input);  // RCE if input = "T(Runtime).getRuntime().exec('id')"
Object result = expr.getValue();

// VULNERABLE: controller passes request param directly to parseExpression
String userInput = request.getParameter("expr");
ExpressionParser parser = new SpelExpressionParser();
parser.parseExpression(userInput).getValue();

// VULNERABLE: SpEL template with user input
TemplateParserContext ctx = new TemplateParserContext();
Expression expr = parser.parseExpression(userInput, ctx);

// SAFE: SpEL with SimpleEvaluationContext (no method invocations)
EvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
parser.parseExpression(input).getValue(ctx);
```

**VULN indicator**: `SpelExpressionParser` + `parseExpression(userInput)` with `StandardEvaluationContext` (default) or no context restriction.

**FALSE POSITIVE**: `SimpleEvaluationContext` blocks method invocations and type access — NOT exploitable for RCE.

### MVEL

```java
// VULNERABLE: MVEL evaluates user input directly
String userExpr = request.getParameter("filter");
Object result = MVEL.eval(userExpr, vars);          // arbitrary Java execution

// VULNERABLE: MVEL.executeExpression(compiledExpr, vars) where compiledExpr built from user input
Serializable compiled = MVEL.compileExpression(request.getParameter("expr"));
MVEL.executeExpression(compiled, context);
```

### Jakarta EE / JSF EL

```java
// VULNERABLE: user input embedded in EL expression string
String name = request.getParameter("name");
FacesContext fc = FacesContext.getCurrentInstance();
ELContext elCtx = fc.getELContext();
ExpressionFactory ef = fc.getApplication().getExpressionFactory();
ValueExpression ve = ef.createValueExpression(elCtx, "${" + name + "}", Object.class);
// If name = "facesContext.externalContext.request" etc — information disclosure
// If name = "''['class'].forName('java.lang.Runtime')" — RCE in some EL implementations

// VULNERABLE: JSP EL with unescaped user input in template
// <%-- JSP: user data rendered as: ${param.name} in EL context --%>
```

### Groovy Script Execution

```java
// VULNERABLE: user input executed as Groovy script
String script = request.getParameter("script");
GroovyShell shell = new GroovyShell();
Object result = shell.evaluate(script);             // full RCE

// VULNERABLE: ScriptEngine with Groovy
ScriptEngine engine = new ScriptEngineManager().getEngineByName("groovy");
engine.eval(request.getParameter("code"));

// VULNERABLE: Groovy's Eval.me()
Object val = Eval.me(request.getParameter("expr"));
```

### Thymeleaf SSTI / SpEL context

```java
// VULNERABLE: Thymeleaf template with user-controlled fragment selector
// URL: /__/fragments/section :: (${T(java.lang.Runtime).getRuntime().exec('id')})
// When controller passes user input directly as fragment expression:
String template = "fragments/" + request.getParameter("page");
return template;  // if Thymeleaf processes the path as a fragment expression, SSTI possible
```

### Search-engine script injection (Elasticsearch / OpenSearch Painless, Lucene)

Search backends embed a scripting language (Painless, Lucene expressions, the legacy `mvel`/Groovy script engines) reachable through `sort`, `script_fields`, `script_score`, `runtime_mappings`, `min_score`, and scripted aggregations. If any part of a query body — especially a **raw `sort`/`script` string forwarded from a client argument** — is taken from user input without an allowlist, the attacker controls a per-document expression. Even sandboxed Painless yields field/metadata exfiltration (`doc['_seq_no']`, ordering oracles), tenant-boundary probing, and CPU-DoS; older/unsandboxed engines are full RCE.

```jsonc
// VULNERABLE: client-supplied sort_query forwarded verbatim into the ES sort clause
// GraphQL/REST arg:  sort_query = "_script:{...,\"script\":{\"source\":\"doc['_seq_no'].value\"}}"
{ "query": {...}, "sort": <RAW_USER_SORT> }          // per-document Painless executes

// VULNERABLE: user value concatenated into a script source
{ "script_score": { "script": { "source": "Math.log(2 + doc['" + userField + "'].value)" } } }
```

**SAFE / barriers:** never forward a raw `sort`/`script`/aggregation string from the client — accept a typed enum of allowed sort fields and map server-side; use **parameterized** scripts (`"params"` with a fixed `source`, never string concatenation); disable dynamic scripting where unused (`script.allowed_types: none`/`stored`), restrict contexts; allowlist queryable fields. Treat any user input reaching `sort`, `script.source`, `runtime_mappings`, or `aggs...script` as an injection sink. Cross-ref `nosql_injection.md` (query-shape injection) and `rce.md`.

## Java Source Detection Rules

### TRUE POSITIVE

- `SpelExpressionParser().parseExpression(userInput)` with default `StandardEvaluationContext` or no context → **CONFIRM** (RCE possible via `T(java.lang.Runtime)`)
- `Ognl.getValue(userInput, ...)` where `userInput` is HTTP request data → **CONFIRM**
- `MVEL.eval(userInput, ...)` where `userInput` is HTTP request data → **CONFIRM**
- `GroovyShell().evaluate(userInput)` or `ScriptEngine.eval(userInput)` → **CONFIRM** (full RCE)
- `ELProcessor.eval(userInput)` where EL implementation supports method invocations → **CONFIRM**

### FALSE POSITIVE

- `SimpleEvaluationContext` used with SpEL — blocks `T(...)` type references and method invocations
- SpEL used only with property paths on trusted bean objects with no user-controlled expression string
- OGNL in Struts2 with sandbox/version mitigations (Struts >= 2.5.31, `struts.ognl.excludedClasses`) reduces but does not eliminate risk — still flag `Ognl.getValue(userInput, ...)` when `userInput` is HTTP-driven
- EL in JSP rendering where user data is passed as a value binding argument (the *value*, not the *expression itself*)

## PHP/Python/Node.js EL-Equivalent Patterns

### PHP

```php
// VULNERABLE: eval() with user input
eval($_GET['code']);
eval('$result = ' . $_POST['expr'] . ';');

// VULNERABLE: create_function() (deprecated but still present)
$fn = create_function('', $_GET['body']);
$fn();

// VULNERABLE: preg_replace with /e modifier (PHP < 7.0)
preg_replace('/' . $_GET['pattern'] . '/e', $_GET['replacement'], $subject);
```

### Python

```python
# VULNERABLE: eval/exec with user input
result = eval(request.args['expr'])
exec(request.form['code'])

# VULNERABLE: Jinja2 render with user-controlled template string
from jinja2 import Template
Template(user_input).render()   # SSTI — should use Environment.from_string on sandboxed env
```

### Node.js

```js
// VULNERABLE: vm.runInThisContext with user input
const vm = require('vm');
vm.runInThisContext(req.body.code);     // full access to Node globals

// VULNERABLE: eval() in request handler
app.get('/calc', (req, res) => { res.send(eval(req.query.expr)); });

// VULNERABLE: Function constructor
const fn = new Function(req.body.code);
fn();
```

## Severity

| Pattern | Severity |
|---------|----------|
| GroovyShell/ScriptEngine eval with user input | Critical |
| SpEL with StandardEvaluationContext | Critical |
| OGNL eval with user input | Critical |
| MVEL eval with user input | Critical |
| EL eval in JEE with method support | High |
| PHP eval() with user input | Critical |
| Python eval()/exec() with user input | Critical |
| Thymeleaf fragment expression injection | High |

## Language one-liners

**Java/Spring**
- **VULN**: `new SpelExpressionParser().parseExpression(request.getParameter("q")).getValue()` — no `SimpleEvaluationContext`.
- **SAFE**: `parser.parseExpression(input).getValue(SimpleEvaluationContext.forReadOnlyDataBinding().build())`.
- **VULN**: `Ognl.getValue(userExpr, ctx, root)` with HTTP-derived `userExpr`.
- **VULN**: `new GroovyShell().evaluate(userScript)` / `MVEL.eval(userExpr)`.

**JS/Node**
- **VULN**: `eval(req.body.code)` / `vm.runInThisContext(userInput)`.
- **VULN**: `obj[userKey]()` when `userKey` is remote.

**Python**
- **VULN**: `eval(request.args['expr'])` (not template injection unless building a Jinja template string).

**Go / C#**
- No dedicated SpEL/OGNL/MVEL detection; flag dynamic evaluation (`ScriptEngine`, Roslyn scripting) manually.

## Common False Alarms

- SpEL with `SimpleEvaluationContext` on the `getValue` call — not flagged.
- JEXL engine from sandboxed `JexlBuilder` — not flagged for createScript/createExpression.
- MVEL sink receiving only numeric/boolean — sanitized.
- Property-path SpEL on a trusted bean where the *expression string* is constant — no remote-to-parse flow.
- Struts OGNL without vulnerable version/path — downgrade per project rules; still flag sink if taint reaches `Ognl.getValue`.

## Business Risk

EL evaluators run with JVM method access; one attacker-controlled expression string typically equals RCE (SpEL `T(Runtime)`, OGNL chains, GroovyShell, MVEL, JEXL without sandbox).

## Core Principle

Treat the expression *string* as code, not data. Restrict evaluation context (SpEL `SimpleEvaluationContext`, JEXL sandbox) or eliminate user influence on the expression entirely.
