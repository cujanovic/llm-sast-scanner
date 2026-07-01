---
name: http_method_tamper
description: Detect HTTP method tampering vulnerabilities where GET requests trigger state-changing operations or method override headers/fields are accepted without restriction.
---

# HTTP Method Tampering

HTTP method tampering arises in three distinct scenarios:
1. **GET requests perform state-changing operations** (write, delete, update) — violates HTTP semantics and bypasses CSRF protections.
2. **Method override is accepted without restriction** — `_method` form field or `X-HTTP-Method-Override` header allows an attacker to turn a GET/POST into DELETE/PUT.
3. **Authorization is enforced per-method / per-content-type, not per-resource** — the same resource is reachable through more than one verb (or content-negotiation branch) but the authz filter guards only some of them, so switching method (`GET`→`PATCH`/`PUT`/`HEAD`/`OPTIONS`) or `Accept` (`text/html`→`application/json`) routes to an **unguarded handler** and returns the protected data/action. E.g. `GET /users/{id}` → 403 but `PATCH /users/{id}` + `Accept: application/json` → 200 with the PII. Root cause: a route/filter/annotation that scopes the access check to a specific verb or media type (Spring `@PreAuthorize` only on the `@GetMapping`, an `[Authorize]`/middleware bound to one action, an API gateway rule keyed on method) while another handler for the same path skips it.

## How to Detect

- CSRF: GET-triggered mutations bypass SameSite cookie protection and CSRF tokens.
- Method override abuse: An attacker crafts a form/request that performs DELETE or PATCH through a POST channel.

## TRUE POSITIVE Criteria

- GET route performs a database write, delete, or other state-changing action.
- `X-HTTP-Method-Override` or `_method` field is accepted and overrides the HTTP method without restriction.

## FALSE POSITIVE Criteria

- REST APIs correctly using DELETE, PUT, PATCH via proper HTTP methods with CSRF protection.
- Method override only enabled in a controlled, authenticated context with CSRF token validation.

---

## Python Source Detection Rules

### Flask — GET triggers mutation
- **VULN**: `@app.route('/delete/<int:id>', methods=['GET', 'POST'])` where DELETE logic runs on GET
- **VULN**: `@app.route('/delete', methods=['GET'])` with `db.session.delete(obj)` in the handler
- **VULN**: `@app.route('/activate-user')` with no method restriction executing a DB update
- **SAFE**: `@app.route('/delete/<id>', methods=['POST', 'DELETE'])` with CSRF token validation

### Method override in Flask
- **VULN**: Custom middleware that reads `request.form.get('_method')` and overrides `request.method` without CSRF check
- **VULN**: `X-HTTP-Method-Override` header processed by a middleware and trusted unconditionally

### Django — unsafe methods
- **VULN**: `def delete_view(request):` without `if request.method == 'POST':` guard, accessible via GET
- **SAFE**: `@require_POST` or `@require_http_methods(["POST", "DELETE"])` decorator

---

## JavaScript Source Detection Rules

### Express — GET triggers mutation
- **VULN**: `app.get('/delete/:id', async (req, res) => { await Item.findByIdAndDelete(req.params.id) })`
- **VULN**: `router.get('/users/:id/ban', ...)` with DB mutation in handler
- **SAFE**: `app.delete('/users/:id', ...)` using correct HTTP verb

### Method override (method-override package)
- **VULN**: `app.use(methodOverride('_method'))` with no CSRF protection or restriction
- **VULN**: `app.use(methodOverride('X-HTTP-Method-Override'))` without authentication guard
- **SAFE**: method-override applied only after authentication middleware and with CSRF token validation

### Next.js / Express API routes
- **VULN**: API handler does not check `req.method` before executing mutation:
  ```js
  export default async function handler(req, res) {
      // runs delete regardless of method
      await prisma.user.delete({ where: { id: req.query.id } });
  }
  ```

---

## PHP Source Detection Rules

### GET-triggered mutations
- **VULN**: `if (isset($_GET['delete_id'])) { $db->query("DELETE FROM items WHERE id = " . $_GET['delete_id']); }`
- **VULN**: Script performs INSERT/UPDATE/DELETE based on `$_GET` parameters without POST method check
- **SAFE**: `if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); exit; }`

### Laravel method spoofing
- **VULN**: `method_field('DELETE')` form submitted without CSRF token verification
- **VULN**: Route accessible via both GET and POST where the POST route performs deletion without CSRF check
- **SAFE**: Laravel's built-in CSRF middleware (`VerifyCsrfToken`) active for all state-changing routes

### Method override header
- **VULN**: `$method = $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'] ?? $_SERVER['REQUEST_METHOD']` — override header trusted
- **SAFE**: Only trust override header after authentication and CSRF validation

---

## Spring & Rails Method-Semantics Detection

Static analysis addresses **safe HTTP methods used for state-changing actions** (CSRF / method-semantics class). It does **not** model `_method` form spoofing or `X-HTTP-Method-Override` header processing directly.

**Not covered by automated queries**: Express `method-override` middleware, Flask `_method` / `X-HTTP-Method-Override`, Laravel method spoofing, or generic "handler ignores `req.method`" outside the frameworks below.

### Spring CSRF-unprotected request type — Java (Spring + Stapler)

**Unprotected methods (sources on call graph):**

| Framework | Treated as CSRF-unprotected |
|---|---|
| Spring | `@GetMapping`; `@RequestMapping` with `method = GET/HEAD` or **no method specified** (all verbs allowed) |
| Stapler (Jenkins) | Web methods lacking `@RequirePOST` and lacking `@POST`/`@PUT`/`@DELETE` verb annotations |

**State-change sinks (callees):** methods reachable on call graph that either:
- Match name heuristics: `post`, `put`, `patch`, `delete`, `remove`, `create`, `add`, `update`, `edit`, `publish`, `transfer`, `logout`, `login`, `register`, `submit`, … (excludes `get`, `show`, `view`, `list`, `query`, `find`)
- Are MyBatis insert/update/delete mappers, JDBC `executeUpdate`, or SQL-injection-sink `execute` with INSERT/UPDATE/DELETE string

**Sanitizers:** none — `@PostMapping` / `@RequirePOST` / Stapler `@POST` on the entry method prevents the unprotected classification.

**BAD (Spring):**
```java
@GetMapping("/deleteUser")
public String deleteUser(@RequestParam int id) {
    userService.delete(id);  // state change via safe HTTP method
    return "redirect:/";
}
```

**SAFE (Spring):**
```java
@PostMapping("/deleteUser")
public String deleteUser(@RequestParam int id) {
    userService.delete(id);
    return "redirect:/";
}
```

**BAD (Stapler):** web method performing filesystem/config mutation without `@RequirePOST` or `@POST`.

**SAFE (Stapler):** `@RequirePOST` on methods that mutate Jenkins configuration.

### Manual HTTP verb check — Ruby on Rails

**Sources:** `request.method`, `request.request_method`, `request.raw_request_method`, `request.request_method_symbol`, `request.get?`, `request.env` in `ActionController` action methods.

**Sinks:** conditional expressions (`if` / `case`) branching on HTTP verb — indicates multiple verbs routed to one action.

**Rationale:** manual verb checks often mean GET and POST share an action, bypassing Rails routing protections and CSRF filters.

**Sanitizer:** none — prefer separate actions per verb with Rails routing.

**BAD:**
```ruby
def update
  if request.get?
    @user = User.find(params[:id])
  else
    @user.update!(user_params)  # mutation reachable via GET path
  end
end
```

**SAFE:** separate `show` (GET) and `update` (PATCH/PUT) actions with `before_action` auth and CSRF.

### Automated vs manual method-tamper patterns

| Manual pattern (this reference) | Automated equivalent |
|---|---|
| Flask `@app.route(..., methods=['GET'])` + DB delete | not covered — Python has no CSRF-unprotected-request detection |
| Express `app.get('/delete/:id', ...)` | not covered |
| Spring `@GetMapping` + service delete | Spring CSRF-unprotected request type |
| `methodOverride('_method')` without CSRF | not covered |
| Rails `if request.post?` in shared action | partial — manual verb-in-condition detection flags verb-in-condition smell |

### Common False Alarms

- **Spring CSRF-unprotected request:** name-based state-change heuristic — `getConnection()`-style names may false-positive; read-only `@GetMapping` handlers that call unrelated `update*` utilities may alert.
- **`@RequestMapping` without method:** treated as unsafe for all verbs even if only GET is used in practice — intentional conservative modeling.
- **Stapler:** PUT/DELETE excluded from default-safe set due to CORS interaction — may differ from deployment CSRF policy.
- **Call-graph reachability:** may miss state changes via reflection or Spring `@Transactional` indirect effects.
- **Manual verb check (Rails):** low precision — legitimate verb branching (content negotiation) alerts.
- **Method override headers:** no automated model — rely on framework-specific manual rules in sections above.
