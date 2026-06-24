---
name: baas-security
description: Backend-as-a-Service (BaaS) client-side authorization misconfig — Supabase/Postgres RLS disabled or permissive policies, Firebase/Firestore/RTDB/Storage Security Rules allowing public read/write, admin/RLS-bypassing keys (service_role, Hasura admin secret, Amplify/AppSync API keys) shipped in client/browser/mobile code, anon-key writes to sensitive tables, over-broad realtime subscriptions (CWE-862/863/732/798/200)
---

# BaaS Client-Side Authorization (Supabase RLS / Firebase Security Rules)

In Backend-as-a-Service architectures (Supabase, Firebase Firestore/Realtime Database, AWS Amplify/AppSync, Hasura, Appwrite, Nhost, PocketBase, Parse) the **browser or mobile client talks directly to the data layer**. There is often no server-side controller in the request path, so authorization lives entirely in **declarative database policies** (Postgres Row-Level Security) or **Security Rules**. When those rules are missing, disabled, or written as `true`, any holder of the public client key can read or write other users' data directly — bypassing whatever checks exist in the UI code.

## What to Look For

These are mostly **configuration / flag / policy queries**, not taint-flow analyses. The missing or permissive rule, or the admin key in client code, **is** the finding. The threat model: the `anon`/publishable client key is *meant* to be public — security must come from the rules, not from the key being secret.

### 1. RLS-bypassing / admin key in client-reachable code (CWE-798 / CWE-200)

The privileged key bypasses ALL row-level rules. It must live only in trusted server/edge environments, never in a bundle shipped to users.

- **Supabase** `service_role` key (a JWT with `"role":"service_role"`) used in browser/mobile/`NEXT_PUBLIC_*`/`VITE_*`/`EXPO_PUBLIC_*` code, committed `.env` exposed to the client, or `createClient(url, SERVICE_ROLE_KEY)` in frontend
- **Hasura** `x-hasura-admin-secret` sent from the client / embedded in app config
- **Firebase Admin SDK** (`firebase-admin`, service-account JSON) bundled into client or a non-server context
- **AWS Amplify / AppSync** `API_KEY` auth mode for anything non-public, or IAM/admin creds in the app
- service_role used inside an edge/serverless function that then acts on a **client-supplied user id** without re-checking the caller's identity (confused-deputy — the function becomes an authorization bypass)

**Grep seeds**: `service_role`, `SERVICE_ROLE`, `createClient(`, `NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `x-hasura-admin-secret`, `firebase-admin`, `serviceAccountKey`, `admin.initializeApp`, `aws_appsync_authenticationType`, `API_KEY`

### 2. RLS disabled / tables not protected (CWE-862)

In Supabase/Postgres, a table reachable by the `anon` or `authenticated` role with RLS **off** (or **on but with no policies + permissive grants**) is fully readable/writable by any client.

- Migration/SQL that `CREATE TABLE` without a following `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`
- `ALTER TABLE ... DISABLE ROW LEVEL SECURITY`
- `GRANT ALL ON ... TO anon` / `TO authenticated` without scoped policies
- RLS enabled but `FORCE ROW LEVEL SECURITY` missing on tables a table-owner role reaches
- Dashboard-created tables left with the "no RLS" warning unaddressed

**Grep seeds**: `ENABLE ROW LEVEL SECURITY`, `DISABLE ROW LEVEL SECURITY`, `CREATE POLICY`, `GRANT .* TO anon`, `GRANT .* TO authenticated`, `auth.uid()`, `auth.role()`

### 3. Permissive policies / Security Rules — the `true` trap (CWE-863)

A rule that evaluates to a constant `true`, or checks only that the user is *logged in* (not that they *own the row*), provides no object-level authorization.

- **Supabase / Postgres RLS**: `CREATE POLICY ... USING (true)` / `WITH CHECK (true)`, or `USING (auth.role() = 'authenticated')` on per-user data (any logged-in user reads everyone's rows — BOLA/IDOR at the DB layer)
- **Firestore / RTDB rules**: `allow read, write: if true;`, `allow read, write;` (rules v1), `".read": true` / `".write": true`, or `if request.auth != null` guarding per-user documents without comparing `request.auth.uid` to the owner field / `{userId}` path segment
- **Time-bomb test rules**: `allow read, write: if request.time < timestamp.date(...)` left from `firebase init` — world-open until the date, often shipped
- Write policy with `USING` but no `WITH CHECK` (Postgres) → row passes the read predicate but the inserted/updated row is unconstrained (privilege fields, foreign tenant id can be set)

**Grep seeds**: `USING (true)`, `WITH CHECK (true)`, `if true`, `allow read, write`, `".read": true`, `".write": true`, `request.auth != null`, `request.auth.uid`, `allow .*: if request.time`

### 4. Anon writes / over-broad mutations to sensitive tables (CWE-862)

- `anon`-role `INSERT`/`UPDATE`/`DELETE` policies on tables like `profiles`, `orders`, `roles`, `balances`, `subscriptions`
- Client `.insert()/.update()/.delete()` against privileged columns (`role`, `is_admin`, `tenant_id`, `price`) with no `WITH CHECK` constraining them → mass-assignment at the data layer (cross-ref `mass_assignment.md`)
- RPC / Postgres functions marked `SECURITY DEFINER` and `GRANT EXECUTE ... TO anon` that mutate data without internal authorization checks

**Grep seeds**: `.insert(`, `.update(`, `.upsert(`, `.delete(`, `SECURITY DEFINER`, `GRANT EXECUTE`, `for insert`, `for update`, `for delete`, `to anon`

### 5. Public storage buckets / open file rules (CWE-732)

- Supabase Storage bucket created `public = true` for user-private files, or storage RLS policies `USING (true)`
- Firebase Storage rules `allow read, write: if true;` / `if request.auth != null` on per-user paths
- Listable buckets exposing other tenants' object keys

**Grep seeds**: `createBucket`, `public: true`, `storage.objects`, `allow read, write` (in `storage.rules`)

### 6. Over-broad realtime / subscriptions (CWE-200)

- Supabase Realtime subscription to a whole table (`.channel(...).on('postgres_changes', { table: 'messages' })`) where RLS does not constrain the stream → other users' inserts pushed to every subscriber
- Firestore `onSnapshot` on a collection root rather than an owner-scoped query, paired with permissive rules

## Vulnerable Conditions

- A table the public/`anon` role can reach with RLS disabled, or enabled but policy-less
- Any policy / Security Rule that reduces to `true` or "is authenticated" on per-user/per-tenant data
- `service_role` / admin secret / Admin SDK present in any client-shipped bundle, public env var, or committed client config
- Write policy lacking `WITH CHECK`, allowing privileged-column or cross-tenant values
- `SECURITY DEFINER` RPC executable by `anon`/`authenticated` with no internal authorization
- Public storage bucket or `if true` storage rule on private files
- Edge/serverless function using the admin key to act on a client-supplied `userId` without verifying the caller owns it

## Safe Patterns

- **Enable RLS on every client-reachable table and write owner-scoped policies**:
  ```sql
  -- SAFE — Supabase: RLS on + per-user policy with both USING and WITH CHECK
  alter table profiles enable row level security;
  create policy "owner can read"   on profiles for select using  (auth.uid() = user_id);
  create policy "owner can modify" on profiles for update using  (auth.uid() = user_id)
                                                          with check (auth.uid() = user_id);
  -- privileged columns are NOT writable by clients (handle role changes server-side)
  ```
  ```js
  // VULN — service_role key in a browser-shipped client: bypasses ALL RLS
  // (any visitor who reads the bundle gets full DB read/write)
  const db = createClient(URL, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY);

  // SAFE — client uses the anon/publishable key; RLS enforces authorization.
  // The service_role key is used ONLY in trusted server code, never NEXT_PUBLIC_*.
  const db = createClient(URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY);
  ```
- **Firestore/RTDB**: compare the authenticated uid to the resource owner, never a bare `if true` or `if request.auth != null`:
  ```
  // VULN — any authenticated user can read/write any document
  match /users/{uid}/private/{doc} { allow read, write: if request.auth != null; }

  // SAFE — only the owner; writes additionally validated
  match /users/{uid}/private/{doc} {
    allow read, write: if request.auth != null && request.auth.uid == uid;
  }
  ```
- Keep admin keys / Admin SDK / `x-hasura-admin-secret` only in server/edge runtimes loaded from a secret store; never in `NEXT_PUBLIC_*`/`VITE_*`/`EXPO_PUBLIC_*` or committed client config.
- Edge/serverless functions that use the admin key must derive the user from the verified session/JWT, not from a client-supplied id, and re-check ownership before acting.
- Scope realtime subscriptions to the authenticated principal and rely on RLS to filter the stream.
- Storage buckets default to private; grant per-object access through scoped policies.

## Sanitizers / Barriers

- RLS enabled **and** at least one policy whose predicate references the caller identity (`auth.uid()`, `request.auth.uid`, `tenant_id = current_setting(...)`) for the role the client uses
- Write paths constrained by `WITH CHECK` covering privileged/tenant columns
- Client uses only the `anon`/publishable key; admin key provably absent from client-reachable code
- `SECURITY DEFINER` RPC contains an explicit caller-identity authorization check before any mutation

## Common False Alarms

- **Intentionally public data** — a `posts`/`public_content` table with a read-only `USING (true)` SELECT policy and no client write policy is by design; flag only writes or sensitive reads.
- **Publishable-by-design keys** — Supabase `anon` key, Firebase client `apiKey`, Amplify public config are meant to ship; they are not secrets (cross-ref `default_credentials.md`). Flag the **service_role/admin** key, not these.
- **Admin key in a server-only file** — `service_role` inside an API route / edge function that verifies the session first is correct usage; confirm it is not bundled to the client and that it re-checks identity.
- **RLS off on an internal-only Postgres role** never exposed through PostgREST/the `anon`/`authenticated` roles — confirm the role is unreachable from the client before clearing.

## Business Risk

- **Full data breach**: with RLS off or `true` policies, any visitor reads every user's/tenant's rows directly with the public key — no auth bypass chain needed.
- **Data tampering / privilege escalation**: anon/authenticated writes with no `WITH CHECK` let attackers modify other rows, set `is_admin`/`role`, or change prices/balances.
- **Account takeover scale**: a leaked `service_role` key is equivalent to a full database admin credential reachable by anyone who opens DevTools.

## Core Principle

In BaaS, **the database policy IS the access-control layer** — the client is untrusted by construction. Every client-reachable table needs RLS enabled with owner/tenant-scoped `USING` and `WITH CHECK` predicates; every Security Rule must compare the authenticated identity to the resource owner; and RLS-bypassing keys (service_role, admin secret, Admin SDK) must never reach a client bundle or public env var. A rule that evaluates to `true`, or that only checks "is logged in" on per-user data, is the same bug as a missing server-side authorization check.

## Cross-References

- `idor.md` — object-level authorization failures (BOLA/IDOR); BaaS permissive policies are IDOR enforced (or not) at the DB layer
- `privilege_escalation.md` — missing/over-broad authorization, BFLA
- `mass_assignment.md` — client writes to privileged columns when `WITH CHECK` is absent
- `default_credentials.md` — distinguishing publishable-by-design keys (anon/apiKey) from secret admin keys
- `information_disclosure.md` — secrets / keys committed or exposed to the client
- `api_security.md` — GraphQL (Hasura/AppSync) authorization, excessive data exposure
- `authentication_jwt.md` — Supabase/Firebase JWT verification in edge/server functions
- `shared_client_cache_leak.md` — connection-pool RLS `SET`/`SET ROLE` leakage across pooled sessions
