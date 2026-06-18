---
name: ssti
description: Detect Server-Side Template Injection where user input controls the template string itself, not just template variables.
---

# Server-Side Template Injection (SSTI)

SSTI arises when an application passes user-supplied data into a template engine as the raw template source rather than as a value to be rendered within a fixed template. The engine then evaluates whatever the attacker submits, making arbitrary server-side code execution possible.

The core pattern: *unvalidated user input is used as the template string passed to a template engine's render/compile/evaluate function.*

## Key Distinction

- **SAFE**: `render_template('page.html', name=user_input)` — user input fills a variable slot; the template engine escapes it.
- **VULN**: `render_template_string(user_input)` — user input *is* the template; the engine evaluates it.
- **VULN (template name)**: `render_template(user_input)` or `res.render(req.query.template)` where the template *name/path* is user-controlled and not allowlisted — path traversal or arbitrary file resolution.

## Vulnerable Conditions

### Trigger Conditions
1. User-supplied data becomes the template **string** itself rather than a variable inserted into a pre-existing template.
2. The template engine is invoked against that attacker-controlled string.
3. User input constructs a dynamic view/template name without strict allowlist validation (Thymeleaf view names, Flask template paths).

### Test Payloads
Confirm execution with a math probe before escalating to RCE:

| Engine | Probe | Expected signal |
|--------|-------|-----------------|
| Jinja2 / Twig / Nunjucks | `{{7*7}}` | `49` in response body |
| Mako | `${7*7}` | `49` |
| Smarty | `{7*7}` | `49` |
| EJS / ERB | `<%= 7*7 %>` | `49` |
| FreeMarker | `${7*7}` | `49` |
| Velocity | `#set($x=7*7)${x}` | `49` |
| Go text/template | `{{printf "%d" (mul 7 7)}}` or `{{7}}` variants | depends on func map |
| Handlebars | `{{#with "s"}}{{/with}}` then gadget chains | engine-specific |
| Jinja2 (string mult) | `{{7*'7'}}` | `7777777` (distinguishes Jinja2 from Twig) |
| Thymeleaf | `#{7*7}` | `49` |

### Dynamic Verification
1. Inject math probe into the suspected template-string parameter.
2. If output contains computed result (not literal `{{7*7}}`), SSTI is confirmed.
3. Fingerprint engine before RCE — e.g. `{{config.items()}}` (Jinja2/Flask), `${T(java.lang.Runtime)}` (Spring EL), `<#assign x=1>${x}` (FreeMarker), `{{_self.env.getFilter('id')}}` (Twig).
4. Escalate with engine-specific RCE only after confirmation.

## Exploitation Chain

Always confirm evaluation with `{{7*7}}` → `49` (or engine-equivalent) before RCE.

**Jinja2 (Python/Flask)**
```
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{ ''.__class__.__mro__[1].__subclasses__()[XXX]('id',shell=True,stdout=-1).communicate() }}
```

**FreeMarker (Java)**
```
${"freemarker.template.utility.Execute"?new()("id")}
```

**Twig (PHP)**
```
{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}
```

**ERB (Ruby)**
```
<%= `id` %>
<%= system('id') %>
```

## Common False Alarms

- `render_template('fixed_name.html', var=user_input)` — safe; template path is hardcoded.
- `Environment().get_template('report.html').render(data=row)` — safe; template is loaded from disk.
- Only flag cases where the template **content string** itself originates from user-controlled input.
- User input bound as a template *variable* (`render('page.html', name=user)`) — not a sink.
- **XSS via template output**: unsanitized user data rendered in a browser is XSS, not SSTI.
- **Allowlisted template names**: user picks a name but it is validated against a hardcoded set — not SSTI.
- **Logic-less engines** (Mustache, Liquid with safe config): arbitrary code execution is typically impossible even if the template string is user-supplied — lower risk; flag for manual review unless engine config is confirmed logic-less.
- Java numeric/boolean template arguments — simple-type sanitizers treat these as safe.
- Ruby/Python string compared to a constant or allowlisted set before template construction.
- Express `res.render()` with user-controlled *template object* only fires when the router uses a known vulnerable view engine configuration (`ejs`, `hbs`, `express-handlebars`, `eta`, `squirrelly`, `haml-coffee`, `express-hbs`, or `whiskers`).
- **Second-order SSTI**: user-submitted template stored in DB/config and later rendered server-side — trace write path, still flag if unsandboxed.

---

## Python Source Detection Rules

### Flask / Jinja2
- **SINK grep**: `render_template_string(`, `from_string(`, `jinja2.Template(`, `Template(` (jinja2 import) — flag when first arg is non-literal
- **VULN**: `render_template_string(request.args.get('tmpl'))` — template body from query param
- **VULN**: `render_template_string(request.form['content'])` — template body from POST
- **VULN**: `render_template_string(request.json['template'])` — template body from JSON
- **VULN**: `Template(user_input).render()` — raw Jinja2 Template from user input
- **VULN**: `Environment().from_string(user_input).render()` — Environment.from_string with user input
- **VULN**: `render_template(request.args.get('tmpl'))` — dynamic template name without allowlist
- **SAFE**: `render_template('page.html', content=user_input)` — fixed template name

```python
# VULN: user input is the template string
return render_template_string(f"<h1>Hello {request.args.get('name')}!</h1>")  # ?name={{7*7}}

# SECURE: static template, user input in context only
return render_template("greet.html", name=request.args.get("name"))
```

### Mako
- **SINK grep**: `mako.template.Template(`, `Template(` (mako import) — non-literal first arg
- **VULN**: `Template(user_input).render()` — user string passed as Mako template source
- **VULN**: `mako.template.Template(request.form['t']).render_unicode()`

### Source identifiers
`request.args.get`, `request.form.get`, `request.form[`, `request.json`, `request.data`, `request.values`

---

## JavaScript Source Detection Rules

### Pug (Jade)
- **SINK grep**: `pug.render(`, `pug.compile(` — non-literal first arg
- **VULN**: `pug.render(req.body.template)` — template source from request body
- **VULN**: `pug.compile(req.query.tmpl)(locals)` — compile from user input

### Handlebars
- **SINK grep**: `Handlebars.compile(`, `handlebars.compile(` — non-literal argument
- **VULN**: `Handlebars.compile(req.body.template)(context)` — template string from user
- **VULN**: `handlebars.compile(userInput)()` — any user-controlled compile argument

```javascript
// VULN
const template = Handlebars.compile(req.query.tmpl);
res.send(template({ user: req.user }));

// SECURE: compile static file once; user data in context
const template = Handlebars.compile(fs.readFileSync('email.hbs', 'utf8'));
res.send(template({ name: req.query.name }));
```

### EJS
- **SINK grep**: `ejs.render(`, `ejs.renderFile(` — non-literal first arg
- **VULN**: `ejs.render(req.body.template, data)` — template string from user

```javascript
// VULN — payload: ?template=<%- global.process.mainModule.require('child_process').execSync('id') %>
res.send(ejs.render(req.query.template, { user: req.user }));

// SECURE
res.render('report', { content: req.query.content });
```

### Nunjucks
- **SINK grep**: `nunjucks.renderString(`, `env.renderString(` — non-literal first arg
- **VULN**: `nunjucks.renderString(req.body.tmpl, ctx)` — user-controlled template string

### Lodash / Underscore
- **SINK grep**: `_.template(` — non-literal argument
- **VULN**: `_.template(req.body.tmpl)(ctx)` — user string compiled as template

### Source identifiers
`req.body`, `req.query`, `req.params`

---

## PHP Source Detection Rules

### Twig
- **SINK grep**: `createTemplate(`, `$twig->render(` — non-literal first arg when inline template
- **VULN**: `$twig->render($userInput, $vars)` — template name or string from user
- **VULN**: `$twig->createTemplate($userInput)->render($vars)` — inline template from user
- **SAFE**: `$twig->render('emails/welcome.html', $vars)` — hardcoded template name

```php
// VULN — payload: {{7*7}} or Twig RCE gadget chains
return $twig->createTemplate($request->query->get('template'))->render([]);

// SECURE
return $twig->render('profile.html.twig', ['name' => $request->query->get('name')]);
```

### Smarty
- **SINK grep**: `fetch("string:"`, `display("string:"`, `fetch($var)` with dynamic arg
- **VULN**: `$smarty->fetch($userInput)` — template name/string from user
- **VULN**: `$smarty->display($userInput)`
- **VULN**: `$smarty->fetch("string:" . $_GET['tmpl'])` — inline template from user

```php
// SECURE
$smarty->assign('name', $_GET['name']);
$smarty->display('profile.tpl');
```

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

---

## Ruby Source Detection Rules

### ERB
- **SINK grep**: `ERB.new(` — non-literal first arg
- **VULN**: `ERB.new(params[:template]).result(binding)` — user string evaluated as ERB
- **SAFE**: `@name = params[:name]; erb :profile` — static template file, user data in binding

```ruby
# VULN — payload: <%= `id` %>
ERB.new(params[:template]).result(binding)

# SECURE
@name = params[:name]
erb :profile
```

### Liquid
- **SINK grep**: `Liquid::Template.parse(` — non-literal argument
- **VULN**: `Liquid::Template.parse(user_input).render(ctx)` — logic-less but flag for data leakage; manual review unless tags restricted

---

## Java Source Detection Rules

### FreeMarker
- **SINK grep**: `new Template(`, `StringReader(` as template source — non-literal body
- **VULN**: `new Template("x", new StringReader(tmplStr), cfg).process(...)` — user string as template
- **SAFE**: `cfg.getTemplate("report.ftl")` — load from trusted path; user data in model only

```java
// VULN — payload: <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
Template t = new Template("preview", new StringReader(tmplStr), cfg);

// SECURE
return "report";  // resolves to templates/report.ftl; model holds user data
```

### Velocity
- **SINK grep**: `Velocity.evaluate(`, `ve.evaluate(` — non-literal template string arg
- **VULN**: `Velocity.evaluate(ctx, sw, "tag", userTemplate)` — user input evaluated as template
- **SAFE**: `Velocity.getTemplate("report.vm").merge(ctx, sw)`

### Thymeleaf
- **SINK grep**: controller `return "prefix/" + var + "/suffix"`, `templateEngine.process(` with non-literal name
- **VULN**: `return "user/" + lang + "/welcome"` — user-controlled view name may embed Spring EL
- **SAFE**: validate `lang` against `Set.of("en", "fr", "de")` before building view name

### StringTemplate (ST4)
- **SINK grep**: `new ST(` — non-literal argument
- **VULN**: `new ST(userInput).render()`

### Pebble
- **SINK grep**: `getLiteralTemplate(`, `Template.fromString(`
- **VULN**: `Template.fromString(userInput).render(ctx)`

---

## Go Source Detection Rules

### text/template / html/template
- **SINK grep**: `.Parse(`, `.ParseFiles(` — non-literal argument to Parse
- **VULN**: `template.New("x").Parse(r.URL.Query().Get("tmpl"))` — user string parsed as template
- **SAFE**: `template.ParseFiles("tmpl/page.html")` with user input only in Execute data map
- Note: `html/template` auto-escapes output but is still vulnerable to SSTI when user input reaches `.Parse()`.

```go
// VULN
t, _ := template.New("x").Parse(r.URL.Query().Get("tmpl"))
t.Execute(w, data)

// SECURE
t := template.Must(template.ParseFiles("tmpl/page.html"))
t.Execute(w, map[string]string{"Name": r.URL.Query().Get("name")})
```

---

## Source → Sink Pattern

**Sources**: remote user input — HTTP params, body, headers, cookies, uploaded file content, and stored values originally from user input (second-order).

**Sinks** (template *source string*, not variable slot):
- **Java**: Velocity `RuntimeServices.evaluate` / `parse`, `VelocityEngine.evaluate` / `mergeTemplate`; FreeMarker `Template` constructors and `StringTemplateLoader.putTemplate`; Pebble `getTemplate` / `getLiteralTemplate` / `Template.fromString`; Jinjava `render` / `renderForResult`; Thymeleaf `ITemplateEngine.process` / `processThrottled`; StringTemplate `new ST(var)`.
- **Python**: Jinja2 `Template` / `Environment.from_string`, Flask `render_template_string`, Mako `Template`, Django/Bottle/Genshi/Chameleon/Chevron/Airspeed/TRender template constructors.
- **Ruby**: ERB `ERB.new(var).result`, Liquid `Template.parse(var)`.
- **JavaScript**: `ejs.render`, `nunjucks.renderString`, `Handlebars.compile`, `pug.render` / `pug.compile`, `_.template`; user-controlled *template object* passed to Express `res.render()` on vulnerable engines (`ejs`, `hbs`, `express-handlebars`, `eta`, `squirrelly`, `haml-coffee`, `express-hbs`, `whiskers`).
- **PHP**: Twig `createTemplate`, Smarty `fetch("string:" . $var)`.
- **Go**: `template.New(name).Parse(var)`.

**Sanitizers / barriers**:
- Java: simple/numeric/boolean types not treated as template code.
- Python/Ruby: comparison against constant; Ruby also allowlist of template names.
- Blocklist filtering of `{{`, `}}`, `<%` is **not** reliable — do not downgrade findings based on filters alone.

Commonly affected languages: Java, Python, Ruby, JavaScript, PHP, Go. Limited coverage for C# (Scriban `Template.Parse`, Handlebars.Net `Compile`, DotLiquid, Fluid). Related Spring view/SpEL paths should be tagged `spel_injection`, not `ssti`.

## Safe Patterns

- Fixed template path/name with user data only in the render context map.
- **Allowlist validation** for dynamic template names:

```python
ALLOWED = {"invoice.html", "receipt.html"}
tmpl = request.args.get("tmpl", "invoice.html")
if tmpl not in ALLOWED:
    abort(400)
return render_template(tmpl)
```

- Jinja2: `SandboxedEnvironment` for unavoidable dynamic templates.
- Spring: `@ResponseBody` / `@RestController` so return value is not interpreted as a view name.
- Express: avoid passing user objects as the template argument to `res.render()` on vulnerable engines.
- Logic-less engines (Mustache): lower RCE risk but still review for sensitive data exposure.

## Business Risk

Attacker-controlled template syntax yields server-side code execution (Jinja2/Mako/Velocity/FreeMarker/Twig/ERB) or, on Express misconfiguration, local file read and RCE via template object injection.

## Core Principle

Never pass untrusted data as the template *source*; only as escaped data bound into a fixed template. Separate Spring view-name manipulation and SpEL from generic SSTI tagging.
