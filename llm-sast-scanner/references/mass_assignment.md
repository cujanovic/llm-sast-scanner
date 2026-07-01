---
name: mass_assignment
description: Mass assignment / object injection allowing privilege fields to be set from user input (CWE-915)
---

# Mass Assignment (CWE-915)

Mass assignment (also called bulk assignment or object injection in frameworks) binds HTTP request parameters directly to model attributes. When sensitive fields — `is_admin`, `role`, `account_id`, `verified` — are not excluded, attackers can escalate privileges or reassign ownership by adding extra parameters to a create/update request.

## Source → Sink Pattern

| Layer | Source | Sink | Example |
|-------|--------|------|---------|
| Rails ActiveRecord | Remote user input (`params`) | `Model.new(params)`, `update(params)`, `create(params)` after `permit!` | `User.create(params.permit!)` sets `is_admin` |
| ORM bulk update | Request body / query params | Hash passed to ORM update without field whitelist | `User.update_all(request.params)` |

Stateful taint tracking applies in Ruby: user params start in an **unpermitted** state; calling `permit!` or `permit` with an empty hash transitions to **permitted** and enables the sink.

## Vulnerable Conditions

- User-controlled parameter hash passed to model constructor or update without a strict attribute whitelist.
- Rails `params.permit!` — permits all keys for mass assignment.
- Rails `params.permit()` with empty hash `{}` — equivalent to permitting arbitrary keys.
- Node/Mongoose `User.findByIdAndUpdate(id, req.body)` where `req.body` may contain `role`, `isAdmin`, etc.
- Spring `@ModelAttribute User user` binding all request fields without `@InitBinder` field blocklist

## Safe Patterns

- Rails **Strong Parameters**: `params.require(:user).permit(:name, :email)` — only listed keys reach the model.
- Explicit field assignment: `user.name = params[:name]` — no bulk hash binding.
- ORM `update` with fixed column map: `user.update(name: params[:name])`.
- DTO/ViewModel layer that exposes only safe fields before persistence.
- Mongoose `schema.pick` or explicit destructuring excluding privileged paths.

## Allowlist vs Blocklist

Prefer **allowlist** binding: only named fields reach the model. **Blocklist** (`exclude`, `$guarded`, `setDisallowedFields`) omits known-sensitive keys but fails when new privileged columns are added without updating the list.

| Strategy | Mechanism | SAST risk |
|----------|-----------|-----------|
| Allowlist | Rails `permit`, Spring `setAllowedFields`, Laravel `$fillable`, Django `fields=` | Low when list is explicit and non-empty |
| Blocklist | `$guarded`, `exclude=`, `setDisallowedFields`, `@JsonIgnore` on entity | High — new `role`/`balance` columns bind until blocklist updated |

**VULN (blocklist gap)**: Model gains `is_premium`; `$guarded = ['is_admin']` still permits `is_premium=1`.
**SAFE (allowlist)**: `permit(:name, :email)` — unknown keys dropped regardless of schema changes.

## DTO / View-Model Binding

Bind HTTP input to a **narrow input type**, then map to the persistence entity server-side. The entity must not appear as a direct binding target for user params.

**VULN**: `@PostMapping create(@ModelAttribute User user)` — entity includes `role`.
**SAFE**: `@PostMapping create(@ModelAttribute UserRegistrationDto dto)` → `user.setName(dto.getName())`; entity never receives raw request hash.

Same pattern: Rails form object / `ActiveModel::Model`, ASP.NET view model, DRF `Serializer` with explicit `fields`, GraphQL input types separate from DB models.

## Sensitive Fields to Protect

Flag model columns and request keys that must never be client-writable:

| Category | Examples |
|----------|----------|
| Privilege / role | `is_admin`, `isAdmin`, `role`, `permissions`, `verified`, `approved` |
| Ownership / identity | `id`, `user_id`, `owner_id`, `account_id`, `organization_id`, `tenant_id` |
| Financial / quota | `balance`, `credit`, `price`, `discount`, `plan_tier` |
| Auth / lifecycle | `password_digest`, `reset_token`, `email_verified_at`, `locked_at` |
| One-time verification secret | `key`, `otp`, `otp_key`, `code`, `verification_key`/`token`, `magic_link_key`, `signin_key`, `nonce`, `activation_token` |

Any create/update path that bulk-binds request data while the model defines these columns is a candidate sink.

**Binding the server-generated verification secret at generation time → pre-auth account takeover.** The usual mass-assignment finding is an *authenticated* user escalating on an update (`role`/`owner_id`). A higher-impact variant binds the **one-time secret the server is supposed to generate itself** — the OTP/magic-link/verification `key` — on the **sign-in / code-request** endpoint: the struct/model bound from the request body includes the verification-key field, so an **unauthenticated** attacker submits `{email: victim, key: "attacker-known"}`, the server stores *their* value as the expected secret, and they then "verify" with the value they chose → account takeover with no code to brute-force. **SAST signal**: a sign-in/OTP-request/passwordless handler that binds the whole request body (`c.Bind(&signInModel)`, `json.NewDecoder(r.Body).Decode(&m)`, `req.body`→ORM create) into a struct/model that *also* carries the verification key/token/OTP field, with no allowlist excluding it — the key must be set **server-side only** (CSPRNG), never accepted from input.

## Detection Indicators (Grep)

Bulk-binding sinks — trace backward for allowlist/permit before the call:

```text
\.create\s*\(\s*params
\.update\s*\(\s*params
assign_attributes\s*\(
update_attributes\s*\(
permit!
findByIdAndUpdate\s*\([^,]+,\s*req\.(body|query)
findOneAndUpdate\s*\([^,]+,\s*req\.body
\.update\s*\(\s*req\.body
Model\.create\s*\(\s*req\.body
\*\*request\.(POST|GET|data)
objects\.create\s*\(\s*\*\*
@ModelAttribute\s+\w+
ModelForm\s*\([^)]*\)(?!.*fields\s*=)
Serializer\s*\([^)]*\)(?!.*fields\s*=)
\$fillable\s*=\s*\[\s*\]
\$guarded\s*=\s*\[\s*\]
setDisallowedFields\s*\(
Bind\s*\(\s*"Include"
```

Missing allowlist signals (manual review):

```text
ModelForm\s*\(\s*\)
ModelForm\s*\([^)]*exclude\s*=
params\.permit\s*\(\s*\{\s*\}\s*\)
params\.permit\s*\(\s*\)
WebDataBinder(?!.*setAllowedFields)
```

## Sources, Sinks & Sanitizers (Ruby)

Commonly affected languages: Ruby (automated mass-assignment tracking); JavaScript/Node, Java/Spring, and Python/Django require manual review for Mongoose, Sequelize, `@ModelAttribute`, and `**request.POST` patterns.

### Ruby / Rails (`MassAssignment`)

- **Source**: `RemoteFlowSource` — HTTP params, cookies, request body reaching controller.
- **Sink**: ActiveRecord mass-assignment calls (`new`, `create`, `update`, `assign_attributes`) receiving **permitted** params.
- **MassPermit (unsafe transition)**: `params.permit!`; `params.permit({})` or `permit` with empty/nested-empty hash.
- **Sanitizer**: `params.permit(:field1, :field2, ...)` with explicit non-empty key list.

Flow tracks whether `permit!` (or empty `permit`) was applied before the ORM sink.

## Language Patterns

### Ruby / Rails

**VULN**: `User.create(params.permit!)` — attacker sends `is_admin=1`.
**VULN**: `User.new(params.require(:user).permit(profile: {}))` — nested empty permit allows an arbitrary hash for `profile` (e.g. `profile[is_admin]=1`).
**SAFE**: `User.create(params.require(:user).permit(:name, :email))`.

The contrast between `permit!` vs `permit(:name, :email)` is the canonical safe vs unsafe pattern.

### JavaScript / Node

**VULN**: `User.findByIdAndUpdate(req.params.id, req.body)` — `req.body.role = 'admin'`.
**SAFE**: `User.findByIdAndUpdate(id, { name: req.body.name, email: req.body.email })`.

### Java / Spring

**VULN**: `@PostMapping("/users") create(@ModelAttribute User u)` — `User` entity includes `role` field bound from form.
**SAFE**: Separate DTO with only safe fields; map explicitly to entity.

### Python / Django

**VULN**: `User.objects.create(**request.POST.dict())` including privilege fields on model.
**VULN**: `UserForm(request.POST)` with no `fields`/`exclude` — all model fields bind.
**SAFE**: `class UserForm(ModelForm): class Meta: model = User; fields = ['username', 'email']`.
**SAFE**: DRF `Serializer` with `fields = ['username', 'email']` (not `exclude = ['is_staff']` alone).

### PHP / Laravel

**VULN**: `User::create($request->all())` with `$guarded = []` or missing `$fillable`.
**VULN**: `$guarded = ['is_admin']` — new `role` column remains assignable.
**SAFE**: `protected $fillable = ['name', 'email'];` then `User::create($request->only('name', 'email'))`.

### ASP.NET MVC / Core

**VULN**: `public IActionResult Edit(User model)` — model binder maps all posted properties including `IsAdmin`.
**SAFE**: `[Bind("Name,Email")] public IActionResult Edit(User model)` or bind a view model with only safe properties.
**SAFE**: `[BindNever]` on entity properties that must not bind from request.

### Java / Spring (extended)

**VULN**: `@RequestBody User user` on entity with Jackson default — all JSON properties deserialize.
**SAFE**: `@InitBinder` → `binder.setAllowedFields("name", "email")`.
**SAFE**: `@JsonIgnore` on privileged entity fields **plus** separate request DTO for writes (ignore alone is blocklist-style).

### JavaScript / Express (extended)

**VULN**: `User.update(req.body)` or spread `{ ...req.body }` into ORM update.
**SAFE**: `const { name, email } = req.body; User.update({ name, email })`.
**SAFE**: `_.pick(req.body, ['name', 'email'])` or `lodash/omit(req.body, ['role', 'isAdmin'])` — prefer pick (allowlist).

### TypeScript validation-library passthrough (Zod / Yup) → ORM write

A schema validator is a mass-assignment **allowlist only when it strips keys it didn't declare**. Zod's default `.parse()`/`.safeParse()` *does* strip unknown keys — but `.passthrough()`, `.catchall(z.any())`, and `.merge(z.record(...))` / `.and(z.record(...))` opt out and **retain attacker-chosen keys** on the parsed output. The validated object is then **still tainted**: spreading or passing it into a column-scoped ORM write assigns whatever extra columns the request carried. The validator looked like a guard but admitted `role`/`isAdmin`/`credits`.

**VULN**: `const P = z.object({ name: z.string() }).passthrough(); const parsed = P.parse(req.body); await db.update(users).set({ ...parsed })` — `parsed` still carries undeclared columns.
**VULN**: `.catchall(z.any())` on the schema, or `await db.insert(orders).values(parsed)` — same hole via insert.
**VULN (Yup)**: `schema.validate(body, { stripUnknown: false })`, or a schema with no `.noUnknown()` — unknown keys survive validation.
**SAFE**: rely on Zod's default strip (do **not** call `.passthrough()`/`.catchall()`), or `.strict()` (throws on any unknown key); Yup `.noUnknown()` / `validate(..., { stripUnknown: true })`. Then still bind only declared columns into the ORM call.

**Key rule for SAST**: treat any spread/pass of a *parsed/validated* object into an ORM write as a sink — **post-validation data is not an allowlist unless the schema strips unknown keys**. Column-scoped writes that are sinks here: Drizzle `.values(obj)` / `.set(obj)`, Prisma `create({ data: obj })` / `update({ data: obj })`, Mongoose `create`/`updateOne`. Recon: `rg -n "\.passthrough\s*\(|\.catchall\s*\(|stripUnknown\s*:\s*false"` then check whether the parsed result feeds an ORM `values`/`set`/`data`.

## Common False Alarms

- `permit` with explicit safe field list even when params originate from remote input.
- Mass assignment on models with no sensitive attributes (e.g., read-only `Comment` with only `body` and `post_id`).
- Admin-only endpoints where `[Authorize(Roles = "Admin")]` legitimately sets privileged fields server-side without user params.
- Benchmark/demo apps where mass assignment is the intentional vulnerability category.

## Business Risk

- Vertical privilege escalation via `is_admin`, `role`, or permission flags set from request parameters.
- Account takeover by overwriting `user_id`, `owner_id`, or email verification fields.
- Cross-tenant data corruption when `organization_id` or `tenant_id` is mass-assignable.
- Regulatory impact when role or consent fields can be tampered without audit trail.

## Analysis Workflow

1. Identify ORM create/update paths that accept a params hash or request body object.
2. Trace whether a framework permit/whitelist runs before the ORM call.
3. Enumerate model columns — flag any privileged field (`role`, `admin`, `verified`, foreign keys to other tenants).
4. For Node/Java/Python stacks without automated mass-assignment rules, grep for `req.body`, `@ModelAttribute`, `**request.POST` passed directly to ORM (see Detection Indicators).
5. Classify binding as allowlist vs blocklist; downgrade confidence if only `$guarded`, `exclude=`, or `setDisallowedFields` protects privileged columns.
6. Confirm exploitability: can a non-admin HTTP request set a privileged column?

## Core Principle

Never bind a client-supplied parameter hash directly to a persistence model. Every create/update path must use an explicit allowlist of assignable fields; privileged attributes must be set only by server-side logic after authorization checks.
