---
name: mass-assignment
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
**SAFE**: Serializer with explicit `fields = ['username', 'email']` (DRF) or form with limited fields.

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
4. For Node/Java/Python stacks without automated mass-assignment rules, grep for `req.body`, `@ModelAttribute`, `**request.POST` passed directly to ORM.
5. Confirm exploitability: can a non-admin HTTP request set a privileged column?

## Core Principle

Never bind a client-supplied parameter hash directly to a persistence model. Every create/update path must use an explicit allowlist of assignable fields; privileged attributes must be set only by server-side logic after authorization checks.
