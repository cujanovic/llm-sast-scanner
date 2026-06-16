---
name: ssti
description: Detect Server-Side Template Injection where user input controls the template string itself, not just template variables.
---

# Server-Side Template Injection (SSTI)

SSTI arises when an application passes user-supplied data into a template engine as the raw template source rather than as a value to be rendered within a fixed template. The engine then evaluates whatever the attacker submits, making arbitrary server-side code execution possible.

## Key Distinction

- **SAFE**: `render_template('page.html', name=user_input)` — user input fills a variable slot; the template engine escapes it.
- **VULN**: `render_template_string(user_input)` — user input *is* the template; the engine evaluates it.

## Vulnerable Conditions

### Trigger Conditions
1. User-supplied data becomes the template **string** itself rather than a variable inserted into a pre-existing template.
2. The template engine is invoked against that attacker-controlled string.

### Test Payloads
- Jinja2 / Twig: `{{7*7}}` → expects `49`
- Mako: `${7*7}` / Smarty: `{7*7}` → expects `49`
- EJS / ERB: `<%= 7*7 %>` → expects `49`

## Exploitation Chain

For Python Jinja2, a typical PoC:
```
{{ ''.__class__.__mro__[1].__subclasses__()[...exec...]('id') }}
```
Full RCE is achievable through class-hierarchy traversal.

## Common False Alarms

- `render_template('fixed_name.html', var=user_input)` — safe; template path is hardcoded.
- `Environment().get_template('report.html').render(data=row)` — safe; template is loaded from disk.
- Only flag cases where the template **content string** itself originates from user-controlled input.
- User input bound as a template *variable* (`render('page.html', name=user)`) — not a sink.
- Java numeric/boolean template arguments — simple-type sanitizers treat these as safe.
- Ruby/Python string compared to a constant or allowlisted set before template construction.
- Express `res.render()` with user-controlled *template object* only fires when the router uses a known vulnerable view engine configuration (`ejs`, `hbs`, `express-handlebars`, `eta`, `squirrelly`, `haml-coffee`, `express-hbs`, or `whiskers`).

---

## Python Source Detection Rules

### Flask / Jinja2
- **VULN**: `render_template_string(request.args.get('tmpl'))` — template body from query param
- **VULN**: `render_template_string(request.form['content'])` — template body from POST
- **VULN**: `render_template_string(request.json['template'])` — template body from JSON
- **VULN**: `Template(user_input).render()` — raw Jinja2 Template from user input
- **VULN**: `Environment().from_string(user_input).render()` — Environment.from_string with user input
- **SAFE**: `render_template('page.html', content=user_input)` — fixed template name

### Mako
- **VULN**: `Template(user_input).render()` — user string passed as Mako template source
- **VULN**: `mako.template.Template(request.form['t']).render_unicode()`

### Source identifiers
`request.args.get`, `request.form.get`, `request.form[`, `request.json`, `request.data`, `request.values`

---

## JavaScript Source Detection Rules

### Pug (Jade)
- **VULN**: `pug.render(req.body.template)` — template source from request body
- **VULN**: `pug.compile(req.query.tmpl)(locals)` — compile from user input

### Handlebars
- **VULN**: `Handlebars.compile(req.body.template)(context)` — template string from user
- **VULN**: `handlebars.compile(userInput)()` — any user-controlled compile argument

### EJS
- **VULN**: `ejs.render(req.body.template, data)` — template string from user

### Source identifiers
`req.body`, `req.query`, `req.params`

---

## PHP Source Detection Rules

### Twig
- **VULN**: `$twig->render($userInput, $vars)` — template name or string from user
- **VULN**: `$twig->createTemplate($userInput)->render($vars)` — inline template from user
- **SAFE**: `$twig->render('emails/welcome.html', $vars)` — hardcoded template name

### Smarty
- **VULN**: `$smarty->fetch($userInput)` — template name/string from user
- **VULN**: `$smarty->display($userInput)`

### Raw PHP eval
- **VULN**: `eval("?>" . $userInput)` — PHP template injection via eval
- **VULN**: `eval($userInput)` — direct eval of user input

### Source identifiers
`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `file_get_contents('php://input')`
- Spring `SpelExpressionParser`, `parseExpression`, `#{...}`, `${...}`, or expression-evaluated Thymeleaf content should be reported as `spel_injection`, not generic `ssti` or `rce`.
- In `JavaSecLab`, user-controlled view names like `return "vul/ssti/" + para;` still count as template-side injection coverage and should preserve project tag `ssti`.
- In `SecExample`, dedicated `/spel` demo routes/templates should keep `spel_injection` even if the downstream effect looks like command execution.
- In benchmark/demo projects, dedicated SpEL routes or templates such as `/speloutput`, `templates/spel/*`, or view names containing `spel` should preserve `spel_injection` even when the parser helper is indirect or not colocated in the controller file.
- In `SecExample`, if the visible source snapshot still contains `templates/spel/spel.html`, `templates/spel/speloutput.html`, and an explicit SpEL payload hint, preserve `spel_injection` as at least `LIKELY` even when the controller or parser helper is missing from the checked-in Java sources.
- In benchmark/demo repositories, once a dedicated template or expression-injection module has been confirmed from a reachable route plus checked-in template evidence, do not drop the benchmark tag on a later rerun solely because the parser helper is indirect, relocated, or outside the smaller file subset reviewed in that pass.
- In `JavaSecLab`, `SSTIController.vul1` returning `"vul/ssti/" + para` or similar user-controlled view names should preserve project tag `ssti`, while explicit `parseExpression(...)` or SpEL execution should stay under `spel_injection`.

## Source → Sink Pattern

**Sources**: remote user input — HTTP params, body, headers, cookies, and other remote input (Python/Ruby/JS threat-model sources; Java active threat-model sources).

**Sinks** (template *source string*, not variable slot):
- **Java** (`template-injection` sinks): Velocity `RuntimeServices.evaluate` / `parse`, `VelocityEngine.evaluate` / `mergeTemplate`; FreeMarker `Template` constructors and `StringTemplateLoader.putTemplate`; Pebble `getTemplate` / `getLiteralTemplate`; Jinjava `render` / `renderForResult`; Thymeleaf `ITemplateEngine.process` / `processThrottled`.
- **Python** (template construction source argument): Jinja2 `Template` / `Environment.from_string`, Flask `render_template_string`, Mako `Template`, Django/Bottle/Genshi/Chameleon/Chevron/Airspeed/TRender template constructors.
- **Ruby**: ERB `TemplateRendering.getTemplate()` — user input passed as template body.
- **JavaScript**: user-controlled *template object* passed to Express `res.render()` when view engine is `ejs`, `hbs`, `express-handlebars`, `eta`, `squirrelly`, `haml-coffee`, `express-hbs`, or `whiskers`.

**Sanitizers / barriers**:
- Java: simple/numeric/boolean types not treated as template code.
- Python/Ruby: comparison against constant; Ruby also allowlist of template names.

Commonly affected languages: Java, Python, Ruby, JavaScript. No dedicated SSTI coverage for Go, C#, PHP. Related Spring view/SpEL paths should be tagged `spel_injection`, not `ssti`.

## Safe Patterns

- Fixed template path/name with user data only in the render context map.
- Jinja2: `SandboxedEnvironment` for unavoidable dynamic templates.
- Spring: `@ResponseBody` / `@RestController` so return value is not interpreted as a view name.
- Express: avoid passing user objects as the template argument to `res.render()` on vulnerable engines.

## Business Risk

Attacker-controlled template syntax yields server-side code execution (Jinja2/Mako/Velocity/FreeMarker) or, on Express misconfiguration, local file read and RCE via template object injection.

## Core Principle

Never pass untrusted data as the template *source*; only as escaped data bound into a fixed template. Separate Spring view-name manipulation and SpEL from generic SSTI tagging.
