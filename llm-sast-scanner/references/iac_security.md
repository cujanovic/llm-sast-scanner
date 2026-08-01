---
name: iac_security
version: "0.4"
description: Infrastructure-as-Code misconfiguration detection for cloud resource definitions (Terraform, CloudFormation, ARM/Bicep, Pulumi) and Ansible playbooks/roles (become privilege escalation, no_log secret leakage, validate_certs/http, file mode, unpinned packages, allow_unsafe_lookups, Vault); AWS Cognito identity/user pool misconfig (guest/unauthenticated identity pools, identity-pool role escalation, self-service sign-up, Cognito admin-action privesc); non-production cloud API endpoint URLs that keep IAM auth but bypass customer audit trails
---

# Infrastructure-as-Code Security

Cloud resources declared in IaC inherit their security posture from attribute values in `.tf`, `.yaml`, `.json`, and Pulumi programs. Static analysis targets dangerous defaults and explicit misconfigurations before deployment.

The core pattern: *a resource attribute grants public access, excessive privilege, missing encryption, or embeds a secret in source — without compensating controls visible in the same definition.*

## What It Is (and Is Not)

**What it IS**
- Public object storage, file shares, or container registries reachable from the Internet
- Security group / NSG / firewall rules allowing `0.0.0.0/0` or `::/0` to admin, database, or Kubernetes API ports
- IAM / RBAC policies with `"Action": "*"` or `"Resource": "*"` (or equivalent wildcards)
- Hardcoded passwords, API keys, tokens, or certificates in IaC source
- Storage, database, disk, or backup resources with encryption disabled or unset
- Public EBS/RDS/Azure disk snapshots or backup copies without access restrictions
- Audit, flow, or access logging explicitly disabled or never configured
- **Non-production / undocumented cloud API endpoint URLs** in deployable IaC or app SDK config that still accept normal cloud credentials (IAM) while skipping or distorting the customer audit trail (e.g. CloudTrail) — silent permission enumeration / defense-evasion class
- Terraform/Pulumi state stored in unencrypted or world-readable backends
- Drift-prone patterns: inline policies duplicating broad grants, `ignore_changes` on security attributes, lifecycle blocks suppressing encryption updates

**What it is NOT**
- **Runtime application secrets** in app code — see `hardcoded_code_backdoor.md` / secret patterns in application languages
- **Cleartext HTTP in app code** — see `cleartext_transmission.md`
- **Missing auth on HTTP routes** — see `privilege_escalation.md`
- **Container image CVEs** — dependency/image scanning, not IaC attribute review
- **Intentionally public static assets** behind CDN with documented public classification and no sensitive data
- **Variables marked `sensitive = true`** referencing external secret stores — the reference itself is not a hardcoded secret
- **Local emulators** — `endpoint_url` / `AWS_ENDPOINT_URL` aimed at `localhost` / `127.0.0.1` / `localstack` / MinIO-on-loopback for tests (not publicly routable vendor non-prod API DNS)

## Recon Indicators

Grep IaC trees for structural misconfig patterns. Recon is attribute/value presence; confirm resource type and context in a later pass.

| Area | Grep / pattern targets |
|------|------------------------|
| Public storage | `acl\s*=\s*"public"`, `public_access_block\s*{[^}]*block_public_acls\s*=\s*false`, `allow_blob_public_access\s*=\s*true`, `uniform_bucket_level_access\s*=\s*false`, `"Effect"\s*:\s*"Allow".*"Principal"\s*:\s*"\*"`, `allUsers`, `allAuthenticatedUsers`, `anonymous_access_enabled\s*=\s*true` |
| Open ingress | `cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]`, `source_address_prefix\s*=\s*"\*"`, `0\.0\.0\.0/0`, `::/0`, `source_ranges\s*=\s*\["0\.0\.0\.0/0"\]`, `"CidrIp"\s*:\s*"0\.0\.0\.0/0"` combined with ports `22`, `3389`, `3306`, `5432`, `1433`, `1521`, `27017`, `6443`, `10250` |
| Wildcard IAM | `"Action"\s*:\s*"\*"`, `"Resource"\s*:\s*"\*"`, `"actions"\s*:\s*\["\*"\]`, `effect\s*=\s*"Allow".*actions\s*=\s*\["\*"\]`, `"Microsoft\.\*/\*"`, `"Effect": "Allow".*"NotAction"` with broad resources |
| Hardcoded secrets | `(password\|secret\|api_key\|apikey\|token\|private_key)\s*=\s*"[^$"{]+"`, `default\s*=\s*"[A-Za-z0-9+/=]{20,}"`, `sk-[A-Za-z0-9]{20,}`, `AKIA[0-9A-Z]{16}`, `-----BEGIN (RSA\|EC\|OPENSSH) PRIVATE KEY-----` |
| Encryption off | `encrypt\s*=\s*false`, `encrypted\s*=\s*false`, `storage_encrypted\s*=\s*false`, `server_side_encryption`, `sse_algorithm\s*=\s*"none"`, `enable_https_traffic_only\s*=\s*false`, `minimum_tls_version\s*=\s*"TLS1_0"`, `require_ssl\s*=\s*false` |
| Public snapshots | `snapshot_access\s*=\s*"public"`, `create_volume_permission.*Group.*all`, `"Group"\s*:\s*"all"`, `public_snapshot\s*=\s*true` |
| Logging disabled | `enable_flow_log\s*=\s*false`, `enabled\s*=\s*false` near `aws_flow_log`, `logging\s*{[^}]*enable\s*=\s*false`, `enable_logging\s*=\s*false`, `audit_logs\s*=\s*"Off"`, `retention_in_days\s*=\s*0` |
| Non-prod cloud API endpoints | `endpoint_url\s*=`, `endpoint-url`, `AWS_ENDPOINT_URL`, Terraform `endpoints\s*{`, provider `endpoints`, boto3/AWS SDK `endpoint_url=` / `endpointUrl` / `--endpoint-url` combined with host markers: `\.gamma\.`, `\.alpha\.`, `\.beta\.`, `\.aws\.a2z\.com`, `starport\.`, `\.alameda\.aws`, `redacted-mds`, non-standard `*.amazonaws.com` service prefixes not in the regional production pattern `{service}.{region}.amazonaws.com` |
| State exposure | `backend\s+"s3"`, `encrypt\s*=\s*false`, missing `server_side_encryption_configuration`, `acl\s*=\s*"public-read"`, `pulumi\.StackReference` with secrets in plain outputs |
| Drift / suppress | `lifecycle\s*{[^}]*ignore_changes\s*=\s*\[[^\]]*(encrypt\|acl\|public\|cidr\|policy)`, `prevent_destroy\s*=\s*true` on security resources without review, duplicate inline + managed policy with `"*"` |
| IMDSv1 / user-data secrets | `http_tokens\s*=\s*"optional"`, `aws_instance`/`aws_launch_template` blocks with **no** `metadata_options`, `user_data` / `user_data_base64` containing `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`password`/`BEGIN .* PRIVATE KEY` |
| Ansible intrinsic | `validate_certs:\s*(no\|false)`, `become:\s*true` / `become_user:\s*root`, `state:\s*latest`, `mode:\s*["']?07[0-7]7`, `allow_unsafe_lookups\s*=\s*True`, `url:\s*["']?http://`, `(shell\|command):\s*.*\{\{`, plaintext `password:`/`api_key:` in `vars:`/`group_vars`/`host_vars` (no `no_log:\s*true`) |

**File extensions**: `*.tf`, `*.tfvars`, `*.hcl`, `*.yaml`, `*.yml`, `*.json`, `*.bicep`, `*.bicepparam`, `Pulumi.*`, `__main__.py` (Pulumi), `index.ts`/`index.js` (CDK/Pulumi).

**Sensitive ports** (flag when paired with `0.0.0.0/0` or `*`): 22 SSH, 3389 RDP, 3306 MySQL, 5432 PostgreSQL, 1433 MSSQL, 1521 Oracle, 27017 MongoDB, 6379 Redis, 6443/10250 Kubernetes API/kubelet.

## Vulnerable Conditions

- S3/GCS/Azure Blob bucket or container allows anonymous or public read/write/list
- Security group, NSG, or firewall rule permits `0.0.0.0/0` ingress to admin, database, cache, or K8s API ports
- Kubernetes cluster API server authorized IP ranges include `0.0.0.0/0` or are unset on a public endpoint
- RDS/Azure SQL/Cloud SQL instance has `publicly_accessible = true` or equivalent with open network path
- IAM/RBAC policy grants `*` actions on `*` resources (or admin/Owner role attached where a scoped role suffices)
- Literal secret, password, or private key embedded in IaC instead of secret manager / variable from CI
- EBS/RDS/disk snapshot or backup shared with `all` or marked public
- Storage account, database, or volume lacks encryption at rest (`encrypted = false` or attribute absent where default is off)
- HTTPS-only, TLS minimum version, or SSL enforcement disabled on storage/API endpoints
- VPC/VNET flow logs, S3 access logs, CloudTrail/equivalent audit logging disabled or retention zero
- Terraform/Pulumi remote state bucket lacks encryption and public-access block
- `lifecycle { ignore_changes = [...] }` hides drift on ACL, encryption, CIDR, or policy attributes
- EC2 instance / launch template allows IMDSv1 (no `metadata_options` block, or `http_tokens = "optional"`) — an app-layer SSRF can then steal the instance-role credentials from `169.254.169.254`
- Long-lived credentials, passwords, or private keys embedded in EC2 `user_data` / `user_data_base64` — retrievable at runtime via the metadata service (`/latest/user-data`)

## Safe Patterns

- **Private-by-default storage**: block public access, disable anonymous ACLs, require IAM/service identity for access
- **Least-privilege network**: ingress restricted to known CIDRs or security-group references; admin/DB ports never open to Internet
- **Scoped IAM**: explicit action list and resource ARNs; separate roles per workload; no inline `*` unless break-glass with documented exception
- **Secrets externalized**: reference secret manager, SSM Parameter Store, Key Vault, or CI-injected variables; mark `sensitive = true`
- **Encryption on**: server-side encryption with KMS/customer-managed keys; `storage_encrypted = true`; TLS 1.2+ minimum
- **Logging enabled**: flow logs, access logs, audit trails with non-zero retention and central aggregation
- **Encrypted state**: S3/GCS backend with SSE-KMS, versioning, public-access block, and least-privilege state IAM
- **No drift suppression on security**: avoid `ignore_changes` on security-critical attributes; use policy-as-code checks in CI

### Public storage — VULN vs SAFE

**VULN** — world-readable bucket:
```hcl
resource "aws_s3_bucket" "data" {
  bucket = "my-data"
  acl    = "public-read"
}
```

**SAFE** — block all public access:
```hcl
resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

### Open security group — VULN vs SAFE

**VULN** — SSH open to Internet:
```hcl
resource "aws_security_group_rule" "ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.app.id
}
```

**SAFE** — restrict to admin CIDR:
```hcl
resource "aws_security_group_rule" "ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.admin_cidr]
  security_group_id = aws_security_group.app.id
}
```

### Wildcard IAM — VULN vs SAFE

**VULN**:
```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}
```

**SAFE** — scoped actions and resources:
```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:PutObject"],
  "Resource": "arn:aws:s3:::my-bucket/app/*"
}
```

### Hardcoded secrets — VULN vs SAFE

**VULN**:
```hcl
resource "azurerm_key_vault_secret" "db" {
  name  = "db-password"
  value = "SuperSecret123!"
}
```

**SAFE** — external secret, sensitive flag:
```hcl
variable "db_password" {
  type      = string
  sensitive = true
}

resource "azurerm_key_vault_secret" "db" {
  name  = "db-password"
  value = var.db_password
}
```

**Plaintext secret in an env-var / parameter block instead of a secret-manager reference (structural signal, cross-cloud):** a literal credential placed in a compute resource's environment or parameter store — rather than referenced from a secrets manager — is a hardcoded secret *and* a missed-encryption finding. Flag: AWS `aws_lambda_function` `environment { variables = { DB_PASSWORD = "…" } }` or `aws_codebuild_project` env var with `type = "PLAINTEXT"` holding a secret (vs `type = "PARAMETER_STORE"`/`"SECRETS_MANAGER"`), `aws_ssm_parameter` `type = "String"` for a secret (vs `"SecureString"` with a KMS key), ECS `container_definitions` `environment` literal (vs `secrets` `valueFrom`); GCP `google_cloudfunctions*_function` `environment_variables` / Cloud Run `env { value = "…" }` holding a secret (vs `secret_environment_variables` / `value_source.secret_key_ref`); Azure `app_settings` / `azurerm_*function_app` literal connection string (vs `@Microsoft.KeyVault(...)` reference); K8s `env.value` literal (vs `valueFrom.secretKeyRef`). **SAFE**: reference the secret manager / use `SecureString`+KMS / `secret_environment_variables` / `secretKeyRef`; never the inline literal. Cross-ref `hardcoded_secrets.md`.

### Missing encryption — VULN vs SAFE

**VULN**:
```hcl
resource "aws_db_instance" "main" {
  storage_encrypted = false
  publicly_accessible = true
}
```

**SAFE**:
```hcl
resource "aws_db_instance" "main" {
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.db.arn
  publicly_accessible   = false
}
```

### Disabled logging — VULN vs SAFE

**VULN** (CloudFormation):
```yaml
Properties:
  EnableLogFileValidation: false
  IsLogging: false
```

**SAFE**:
```yaml
Properties:
  IsLogging: true
  EnableLogFileValidation: true
  EventSelectors:
    - IncludeManagementEvents: true
      ReadWriteType: All
```

### Non-production cloud API endpoints (audit-trail bypass) — VULN vs SAFE

Some cloud providers expose **non-production / undocumented API hostnames** that still accept **normal account credentials** (e.g. AWS IAM) and evaluate permissions, but **do not emit** (or emit malformed) customer-visible audit events (CloudTrail and equivalents). Callers can then **silently enumerate permissions** or act with reduced detection — the same class as disabled audit logging, reached via endpoint selection rather than a logging flag. This is **insufficient security logging** (CWE-778) at the cloud-API edge.

**VULN condition** (all of):
1. Deployable code or IaC sets a custom cloud API endpoint (`endpoint_url` / `AWS_ENDPOINT_URL` / provider `endpoints { ... }` / CLI `--endpoint-url`).
2. The host is a **publicly routable vendor non-prod / undocumented API** (markers above: `gamma`/`alpha`/`beta`, `aws.a2z.com`, `starport.`, etc.) — not loopback/LocalStack.
3. The same credentials used for production APIs are used (default SDK credential chain).

```python
# VULN: production path talks to a non-prod AWS API host with normal IAM creds
boto3.client("cloudwatch", endpoint_url="https://monitoring.gamma.us-east-1.amazonaws.com")
```

```hcl
# VULN: provider-level custom endpoints to non-prod hosts
provider "aws" {
  endpoints {
    cloudwatch = "https://monitoring.gamma.us-east-1.amazonaws.com"
  }
}
```

**SAFE**:
- Omit custom endpoints (SDK default regional production hosts).
- Emulators only: `http://localhost:4566`, `http://127.0.0.1:4566`, `*.localstack.cloud` — and keep them out of production deploy configs.
- Do **not** apply the skill's **operator self-harm** skip here: the issue is the **configured host** creating an audit gap after credential theft, not an operator pasting attacker-controlled input into a sink.

**Severity**: typically **Low** / Hardening Note unless the endpoint is also shown to read or mutate production account data without audit events — then raise toward **Medium** (same floor thinking as disabled CloudTrail). Cross-ref `log_injection.md` (CWE-778 absence) for app-handler logging gaps; this section is the **cloud-endpoint** face of the same control failure.

### Unencrypted state — VULN vs SAFE

**VULN**:
```hcl
terraform {
  backend "s3" {
    bucket = "tf-state"
    key    = "prod/terraform.tfstate"
    region = "us-east-1"
  }
}
```

**SAFE**:
```hcl
terraform {
  backend "s3" {
    bucket         = "tf-state"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/abc"
  }
}
```

### Instance Metadata Service (IMDSv2) & user-data secrets — VULN vs SAFE

An EC2 instance that allows **IMDSv1** (token-less metadata access) turns any in-instance request forgery into full cloud-credential theft: a single app-layer SSRF can `GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` and exfiltrate the instance role's keys. IMDSv2 requires a `PUT`-issued session token, which a basic SSRF cannot mint. The Terraform default leaves `http_tokens = "optional"` (IMDSv1 **allowed**) — absence of `metadata_options` is the finding. Same gap on `aws_launch_template` / `aws_launch_configuration`.

**Container task-role → EC2 instance-role escalation (ECS/AWS Batch on EC2 launch type).** A container's *task/job role* (reached at `169.254.170.2` via `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`) is usually scoped tightly — but on the **EC2 launch type** (not Fargate) the task shares the host's network, so the container can also reach the **host IMDS** at `169.254.169.254` and assume the EC2 **instance role**, which is typically far broader (ECR pull, SSM, the whole node's permissions). The task-role sandbox is therefore escapable to the instance role unless IMDS is blocked from containers. **VULN signals**: an ECS `aws_ecs_capacity_provider`/Batch `compute_environment` on EC2 (not `FARGATE`) whose instances allow IMDSv1 or set `http_put_response_hop_limit` **> 1** (the default `1` blocks the extra container→IMDS hop; raising it re-opens the pivot), and no egress rule blocking `169.254.169.254` from task security groups. **SAFE**: prefer Fargate; keep `http_tokens = "required"` + `http_put_response_hop_limit = 1`; block `169.254.169.254` from containers; give the instance role only what the ECS/Batch agent needs.

**Recursive compute-submit self-escalation (batch/ECS IAM policy).** A role that can **both define and run** a compute job can execute arbitrary code as *any role it can pass* — `batch:RegisterJobDefinition` + `batch:SubmitJob`, or ECS `RegisterTaskDefinition` + `RunTask` — where the attacker sets `image`/`command`/`ContainerOverrides` and a `jobRoleArn`/`taskRoleArn`. Combined with an over-broad **`iam:PassRole`** (`Resource: "*"` or a wildcard role ARN), the caller passes a *more-privileged* role to its own job → privilege escalation with no code vuln (cross-ref `rce.md` compute-job-as-role). **VULN signal**: an IAM policy granting `batch:SubmitJob`/`batch:RegisterJobDefinition` or `ecs:RunTask`/`ecs:RegisterTaskDefinition` alongside `iam:PassRole` without a tight `Condition`/`iam:PassedToService` + exact-role `Resource`. **SAFE**: scope `iam:PassRole` to the exact minimal role ARNs and the specific service; separate "define" from "run"; deny job roles the ability to submit/register further jobs.

**VULN** — IMDSv1 reachable + long-lived secrets baked into user-data (which is itself retrievable at `/latest/user-data`, so the SSRF that steals role creds also reads these):
```hcl
resource "aws_instance" "web" {
  ami           = "ami-005e54dee72cc1d00"
  instance_type = "t2.micro"
  # no metadata_options block → IMDSv1 allowed (http_tokens defaults to "optional")
  user_data = <<EOF
export AWS_ACCESS_KEY_ID=AKIA...EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalr...EXAMPLEKEY
EOF
}
```

**SAFE** — force IMDSv2, cap the hop limit so containers can't reach IMDS through an extra network hop, and pull secrets at boot from a secret manager:
```hcl
resource "aws_instance" "web" {
  ami           = "ami-005e54dee72cc1d00"
  instance_type = "t2.micro"
  metadata_options {
    http_tokens                 = "required"  # IMDSv2 only
    http_put_response_hop_limit = 1           # blocks container-escape pivots to IMDS
    http_endpoint               = "enabled"
  }
  iam_instance_profile = aws_iam_instance_profile.web.name  # role, not static keys
  # user_data fetches secrets from SSM Parameter Store / Secrets Manager at runtime
}
```

**TRUE POSITIVE**: `aws_instance` / `aws_launch_template` / `aws_launch_configuration` with no `metadata_options` block, or `http_tokens = "optional"`; or `user_data` / `user_data_base64` containing literal `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, passwords, or private keys. Cross-ref `ssrf.md` (the metadata-service target and its IP-encoding bypasses).

**FALSE POSITIVE**: `http_tokens` set on a launch template that the instance/ASG actually references (don't double-flag the instance that inherits it); `user_data` that only fetches secrets at runtime (`aws ssm get-parameter`, `secretsmanager`) rather than embedding them. GCP/Azure differ — the GCP metadata server already requires a `Metadata-Flavor: Google` header (harder to hit via naive SSRF); flag the AWS pattern specifically.

### AWS Cognito — identity pools, user pools & privesc

Cognito is managed auth, but its **Terraform/CloudFormation config is where the exploitable decisions live**, and none of it is caught by the wildcard-IAM rule above because the dangerous policies are *scoped*, not `*`. The identity pool ID, user pool ID, and app client ID are **public** (shipped in the frontend bundle), so any weakness reachable from those IDs is internet-reachable.

- **Unauthenticated ("guest") identity pool** — `aws_cognito_identity_pool` with `allow_unauthenticated_identities = true` (CloudFormation `AllowUnauthenticatedIdentities: true`) lets **anyone** call `GetId` + `GetCredentialsForIdentity` with only the public pool ID and receive **real AWS STS credentials** for the unauthenticated role — no login, no account. This is the headline Cognito misconfig; treat guest access as **anonymous internet access** to everything the unauth role can do.
- **Over-privileged identity-pool roles — the wildcard rule does NOT apply here.** The roles mapped by `aws_cognito_identity_pool_roles_attachment` are assumed by anonymous callers (unauth) and by *any* user-pool member (auth), so **any real data-plane permission counts even when scoped to specific ARNs** — `dynamodb:GetItem`/`s3:GetObject`/`s3:PutObject` on one table/bucket is a critical anonymous read/write when it sits on the *unauthenticated* role. Do not wait for `Action:"*"`/`Resource:"*"`. Also check the role **trust policy**: `sts:AssumeRoleWithWebIdentity` for `cognito-identity.amazonaws.com` should pin `Condition` `cognito-identity.amazonaws.com:aud = <this pool id>` and gate `amr` (`unauthenticated`/`authenticated`); a missing/loose condition lets other pools' identities assume the role.
- **Identity-pool escalation (user-pool -> AWS).** Even with guest access off, a user-pool JWT is exchangeable through the identity pool for the *authenticated* role's STS creds; if that role is broad, ordinary signup/login becomes broad AWS access. With self-service sign-up (below) an external attacker mints their own JWT first, then escalates.
- **User-pool self-service sign-up left open** — `aws_cognito_user_pool` `admin_create_user_config { allow_admin_create_user_only = false }` (the AWS default) allows public `SignUp`. For an app that assumes "only admins create users" this is an **auth bypass / unwanted account creation**, and it also exposes a **username-enumeration oracle** (`SignUp` returns `UsernameExistsException` for existing users — a self-service pool cannot uniformly hide account existence).
- **Identity-pool provider-trust weakeners** — `allow_classic_flow = true` (enables the basic/classic `GetOpenIdToken` -> STS flow), `server_side_token_check = false` on a `cognito_identity_providers` entry (revoked/changed tokens keep working), and `ambiguous_role_resolution = "AuthenticatedRole"` with no explicit `mapping_rule`s (any authenticated token falls through to the authenticated role) each broaden who gets which role.
- **Cognito admin actions as IAM privesc primitives** (scoped resources still count — the wildcard rule misses them): `cognito-identity:SetIdentityPoolRoles` (+`iam:PassRole`) reassigns the role handed to auth/unauth users; `cognito-idp:AdminSetUserPassword`/`AdminResetUserPassword` = arbitrary account takeover; `AdminUpdateUserAttributes` = set `custom:role=admin` / flip `email_verified` (see `oauth_oidc_misconfiguration.md` cond. 22); `AdminAddUserToGroup` or `CreateGroup`+`iam:PassRole` = join a higher-privileged group/role; `Create`/`UpdateUserPoolClient` = spawn a client with relaxed auth flows or long token TTLs; `CreateIdentityProvider`/`UpdateIdentityPool` = add an attacker IdP or turn on guest access.

**SAFE**: disable guest access (`allow_unauthenticated_identities = false`) unless a concrete anonymous use-case exists; scope the unauth role to the bare minimum (ideally nothing sensitive) and pin its trust-policy `aud`/`amr` conditions; keep the authenticated role least-privilege; set `allow_admin_create_user_only = true` for closed registration; leave `server_side_token_check = true` and omit `allow_classic_flow`; grant the Cognito admin actions above only to dedicated admin roles.

**Grep seeds**:
```bash
rg -n "allow_unauthenticated_identities\s*=\s*true|AllowUnauthenticatedIdentities.{0,8}true" --glob '*.{tf,json,yaml,yml,template}'
rg -n "allow_admin_create_user_only\s*=\s*false" --glob '*.tf'   # also flag a closed-reg pool with NO admin_create_user_config block (default is open)
rg -n "allow_classic_flow\s*=\s*true|server_side_token_check\s*=\s*false|ambiguous_role_resolution\s*=\s*\"AuthenticatedRole\"" --glob '*.tf'
rg -n "cognito-identity:SetIdentityPoolRoles|cognito-idp:Admin(SetUserPassword|ResetUserPassword|AddUserToGroup|UpdateUserAttributes|CreateUser)|cognito-idp:(Create|Update)UserPoolClient|cognito-idp:CreateIdentityProvider|cognito-identity:UpdateIdentityPool" --glob '*.{tf,json,yaml,yml}'
```

## Provider-Specific Misconfigurations

Quick VULN→SAFE attribute references per cloud. Flag the VULN attribute; confirm the resource type and that no compensating control exists elsewhere in the stack.

### AWS

| Resource | VULN | SAFE |
|----------|------|------|
| `aws_ebs_volume` | `encrypted = false` | `encrypted = true` |
| `aws_db_instance` | `backup_retention_period = 0` | `backup_retention_period = 35` |
| `aws_dynamodb_table` | no `server_side_encryption` block | `server_side_encryption { enabled = true; kms_key_arn = ... }` |
| `aws_sqs_queue` / `aws_sns_topic` | no SSE | `sqs_managed_sse_enabled = true` / `kms_master_key_id = ...` |
| `aws_kms_key` | `enable_key_rotation = false` | `enable_key_rotation = true` |
| `aws_cloudtrail` | no `kms_key_id` | `kms_key_id = aws_kms_key.key.arn` |
| `aws_instance` | `associate_public_ip_address = true` | `associate_public_ip_address = false` |
| `aws_instance` / `aws_launch_template` | no `metadata_options`, or `http_tokens = "optional"` (IMDSv1 → SSRF steals role creds) | `metadata_options { http_tokens = "required"; http_put_response_hop_limit = 1 }` |
| `provider "aws"` | `access_key`/`secret_key` inline | `shared_credentials_file` / `profile` / env |
| `aws_iam_role` | `Principal = {AWS = "*"}` on `sts:AssumeRole` | restricted account/role ARN principal |
| `aws_cognito_identity_pool` | `allow_unauthenticated_identities = true` (guest → anonymous STS creds via GetId/GetCredentialsForIdentity), `allow_classic_flow = true` | `= false`; if guest access is required, scope + `aud`/`amr`-condition the unauth role |
| `aws_cognito_identity_pool_roles_attachment` | unauth/auth role with real data-plane perms **even scoped to ARNs**; `ambiguous_role_resolution = "AuthenticatedRole"` without `mapping_rule` | least-privilege roles; explicit `mapping_rule`s; pin role trust-policy `cognito-identity.amazonaws.com:aud`/`amr` |
| `aws_cognito_user_pool` | `admin_create_user_config { allow_admin_create_user_only = false }` (self-service sign-up → account creation + username oracle) | `= true` when registration should be closed |

### Azure

| Resource | VULN | SAFE |
|----------|------|------|
| `azurerm_storage_account` | `min_tls_version = "TLS1_0"`, `allow_nested_items_to_be_public = true` | `min_tls_version = "TLS1_2"`, `= false`, `network_rules { default_action = "Deny" }` |
| `azurerm_storage_container` | `container_access_type = "blob"` | `container_access_type = "private"` |
| `azurerm_linux_web_app` | `https_only = false`, `minimum_tls_version = "1.0"`, `cors { allowed_origins = ["*"] }` | `https_only = true`, `"1.2"`, explicit origins |
| `azurerm_key_vault` | `purge_protection_enabled = false`, `network_acls { default_action = "Allow" }` | `purge_protection_enabled = true`, `default_action = "Deny"` |
| `azurerm_mssql_server` | `minimum_tls_version = "1.0"`, `public_network_access_enabled = true` | `"1.2"`, `public_network_access_enabled = false` |
| `azurerm_mysql_firewall_rule` | `0.0.0.0`–`255.255.255.255` | narrow start/end IP range |
| `azurerm_kubernetes_cluster` | `private_cluster_enabled = false`, empty `api_server_authorized_ip_ranges` | `private_cluster_enabled = true`, `disk_encryption_set_id` set |
| `azurerm_*_virtual_machine_scale_set` | `admin_password = "..."`, `encryption_at_host_enabled = false` | `admin_ssh_key`, `disable_password_authentication = true`, `encryption_at_host_enabled = true` |
| `azurerm_role_definition` | `actions = ["*"]` | explicit scoped `actions` list |
| `azurerm_function_app` / `azurerm_linux_function_app` / `function.json` | HTTP trigger `authLevel = "anonymous"` (unauthenticated function endpoint — function/admin keys bypassed) | `authLevel = "function"`/`"admin"`, or front with APIM/Easy Auth (`auth_settings_v2`) |
| `azurerm_*_web_app` / App Service SCM | basic-auth publishing on — `auth_settings_v2` absent **and** `basicPublishingCredentialsPolicy`/`scm_*`/ARM `allowBasicAuthFtp = true` / `ftpsState = "AllAllowed"` | `auth_settings_v2` enabled; `ftps_state = "FtpsOnly"`/`"Disabled"`; disable basic publishing creds |

### GCP

| Resource | VULN | SAFE |
|----------|------|------|
| `google_storage_bucket` | `uniform_bucket_level_access = false` | `= true`, `versioning { enabled = true }`, `logging {}` |
| `google_storage_bucket_iam_member` | `member = "allUsers"` / `allAuthenticatedUsers` | specific `user:`/`serviceAccount:` member |
| `google_compute_firewall` | `source_ranges = ["0.0.0.0/0"]` to `22`/`3389` | narrow `source_ranges` + `target_tags` |
| `google_compute_instance` | `can_ip_forward = true`, `enable-oslogin = false`, public `access_config {}` | `can_ip_forward = false`, `enable-oslogin = true`, `shielded_instance_config`, KMS boot disk |
| `google_container_cluster` | `enable_legacy_abac = true`, `master_auth { username/password }`, `logging_service = "none"` | `enable_legacy_abac = false`, `enable_shielded_nodes`, `private_cluster_config`, `network_policy { enabled = true }` |
| `google_sql_database_instance` | `ipv4_enabled = true`, `authorized_networks { value = "0.0.0.0/0" }` | `ipv4_enabled = false`, `require_ssl = true`, `private_network` |
| `google_redis_instance` | `auth_enabled = false` | `auth_enabled = true`, `transit_encryption_mode = "SERVER_AUTHENTICATION"` |
| `google_bigquery_dataset` / `google_pubsub_topic` | no `kms_key_name` / `default_encryption_configuration` | CMEK encryption configured |
| `google_*_iam_member` (Cloud Run, etc.) | `member = "allUsers"` | specific principal |
| `google_compute_ssl_policy` | `min_tls_version = "TLS_1_0"` | `"TLS_1_2"`, `profile = "MODERN"` |
| `google_project_iam_member` | `roles/iam.serviceAccountTokenCreator` to broad SA | least-privilege role to specific user |

### Ansible

Config-management IaC (playbooks/roles are YAML; `ansible.cfg` is INI). Beyond the cloud-resource modules (which mirror the AWS/Azure/GCP rows above), these are the **Ansible-intrinsic** misconfigurations — flag the VULN attribute on a task/play/role/`ansible.cfg`.

| Location | VULN | SAFE |
|----------|------|------|
| `ansible.cfg` `[defaults]` | `allow_unsafe_lookups = True` — lookup plugins may return unsafe (un-escaped) data that templates then evaluate → template/code injection (CWE-94) | omit (default `False`); never mark lookup output safe |
| any task | `become: true` / `become_user: root` applied play-wide or where the action doesn't need root (CWE-250) | scope `become` to the single task that needs it; least-privilege `become_user` |
| task handling a secret | no `no_log: true` on a task that passes a password/token/key (loops over secrets, `debug:` of a secret var) → value printed to stdout/Ansible logs (CWE-532) | `no_log: true` on every task that touches sensitive values |
| `uri` / `get_url` / `apt_key` / `yum` / `pip` | `url:`/`repo:`/`key:` using `http://` → cleartext fetch / MITM of fetched payload (CWE-319) | `https://`; verify checksums for downloaded artifacts |
| `uri` / `get_url` / `*_module` over TLS | `validate_certs: no` (or `false`) → skips certificate verification, MITM (CWE-295; the Ansible analogue of `rejectUnauthorized:false` — see `certificate_validation.md`) | omit (default validates) / `validate_certs: yes` |
| `file` / `copy` / `template` / `get_url` | `mode: "0777"` / `mode: "0666"` / world-writable, or **missing** `mode` on a sensitive file → unpredictable/over-broad perms (CWE-732) | explicit least-privilege octal `mode` (e.g. `"0600"`/`"0644"`) |
| `apt` / `yum` / `package` / `pip` / `gem` | `state: latest` or no version pin → non-reproducible build, silent supply-chain drift | pin `version:`/`name: pkg=1.2.3`; `state: present` |
| vars / playbook | hardcoded `password:`/`api_key:`/private key literal in `vars:`/`group_vars`/`host_vars` (CWE-798) | Ansible Vault (`ansible-vault encrypt`) or an external secret lookup; never commit plaintext |
| `shell` / `command` / `raw` | unquoted/templated user-or-inventory var interpolated into the command string — `shell: "rm {{ user_path }}"` → command injection (cross-ref `rce.md`) | use the purpose-built module (`file`, `copy`), `command:` with an argument list, or `{{ var | quote }}` |
| `ansible.builtin.copy`/`unarchive` `src` | relative/`..`-containing path resolved outside the role files dir → path traversal | restrict to role-relative paths; validate/normalize before use |
| Jinja2 **lookup plugin** (template render time, on the **controller**) | `lookup('pipe', cmd)` / `q('pipe', …)` runs a subprocess → controller RCE; `lookup('url', x)` → SSRF / malicious-payload fetch; `lookup('env', 'AWS_SECRET…')` → pulls controller env secrets into play scope (exfil); `lookup('file', "{{ user_var }}")` → controller path traversal (`~/.ssh/id_rsa`). The arg being a var/inventory/extra-var is the taint — distinct from (and not gated by) `allow_unsafe_lookups`. (Same risk inside a `{% %}` block, a `when:`, or a `set_fact` that stores a value re-rendered next task = second-order SSTI.) | never build a `lookup()` arg from untrusted input; for `pipe`/`url` use a vetted module with validation; treat extra-vars/inventory as untrusted |
| `ansible.cfg` `[defaults]` / env | `host_key_checking = False` (or `ANSIBLE_HOST_KEY_CHECKING=False`) → SSH host-key verification off, controller→target MITM (CWE-322) | omit (default `True`); pre-populate `known_hosts` |
| dynamic `include_tasks`/`import_tasks`/`include_role`/`vars_files` | path built from a var/extra-var — `include_tasks: "{{ play }}.yml"` — lets attacker-staged YAML be executed (arbitrary task execution) | allow-list includable files; never template the include path from untrusted input |
| Ansible Tower / AWX | management host/`inbound` exposed to `0.0.0.0/0` → control-plane exposure | restrict to admin CIDR / private network |

### Nomad agent TLS

Nomad's `tls` block can enable encrypted HTTP/RPC while still omitting server identity checks: `verify_server_hostname` defaults to `false`. Treat `tls { http = true; rpc = true; ... }` with no explicit `verify_server_hostname = true` (or with it false) as hostname-verification disabled on outgoing agent connections, not as a safe TLS configuration merely because CA/cert/key files are present. Require `verify_server_hostname = true` and certificates whose DNS names match Nomad's expected server naming; assess `verify_https_client` separately because it controls inbound HTTP client certificates.

## Common False Alarms

- `0.0.0.0/0` on port 443/80 for a documented public load balancer or CDN origin — confirm target is LB tier, not admin/DB tier
- `"Principal": "*"` inside a bucket policy **deny** statement or conditioned with `aws:SourceVpc`, `aws:SourceIp`, or MFA — read full policy JSON
- `public_access_block` absent in a module that always invokes the block resource in a parent stack — trace module outputs/wiring
- Encryption attribute omitted where provider default is encrypt-on (verify provider/version docs; flag as Info if default is secure)
- `sensitive = true` on variables populated from CI secrets — not a hardcoded secret finding
- Test/dev stacks with `environment = "dev"` and narrow CIDR comments — still flag if CIDR is literally `0.0.0.0/0` to sensitive ports unless policy exempts dev
- Pulumi/CDK constructs that wrap secure defaults — read generated plan or underlying resource args, not wrapper name alone
- `ignore_changes` on tags or naming only — not a security suppress unless encryption/ACL/CIDR/policy are included
