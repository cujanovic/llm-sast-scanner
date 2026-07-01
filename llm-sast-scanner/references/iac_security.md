---
name: iac_security
description: Infrastructure-as-Code misconfiguration detection for cloud resource definitions (Terraform, CloudFormation, ARM/Bicep, Pulumi) and Ansible playbooks/roles (become privilege escalation, no_log secret leakage, validate_certs/http, file mode, unpinned packages, allow_unsafe_lookups, Vault)
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
- Terraform/Pulumi state stored in unencrypted or world-readable backends
- Drift-prone patterns: inline policies duplicating broad grants, `ignore_changes` on security attributes, lifecycle blocks suppressing encryption updates

**What it is NOT**
- **Runtime application secrets** in app code — see `hardcoded_code_backdoor.md` / secret patterns in application languages
- **Cleartext HTTP in app code** — see `cleartext_transmission.md`
- **Missing auth on HTTP routes** — see `privilege_escalation.md`
- **Container image CVEs** — dependency/image scanning, not IaC attribute review
- **Intentionally public static assets** behind CDN with documented public classification and no sensitive data
- **Variables marked `sensitive = true`** referencing external secret stores — the reference itself is not a hardcoded secret

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

## Common False Alarms

- `0.0.0.0/0` on port 443/80 for a documented public load balancer or CDN origin — confirm target is LB tier, not admin/DB tier
- `"Principal": "*"` inside a bucket policy **deny** statement or conditioned with `aws:SourceVpc`, `aws:SourceIp`, or MFA — read full policy JSON
- `public_access_block` absent in a module that always invokes the block resource in a parent stack — trace module outputs/wiring
- Encryption attribute omitted where provider default is encrypt-on (verify provider/version docs; flag as Info if default is secure)
- `sensitive = true` on variables populated from CI secrets — not a hardcoded secret finding
- Test/dev stacks with `environment = "dev"` and narrow CIDR comments — still flag if CIDR is literally `0.0.0.0/0` to sensitive ports unless policy exempts dev
- Pulumi/CDK constructs that wrap secure defaults — read generated plan or underlying resource args, not wrapper name alone
- `ignore_changes` on tags or naming only — not a security suppress unless encryption/ACL/CIDR/policy are included
