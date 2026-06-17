---
name: iac_security
description: Infrastructure-as-Code misconfiguration detection for cloud resource definitions (Terraform, CloudFormation, ARM/Bicep, Pulumi)
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

## Common False Alarms

- `0.0.0.0/0` on port 443/80 for a documented public load balancer or CDN origin — confirm target is LB tier, not admin/DB tier
- `"Principal": "*"` inside a bucket policy **deny** statement or conditioned with `aws:SourceVpc`, `aws:SourceIp`, or MFA — read full policy JSON
- `public_access_block` absent in a module that always invokes the block resource in a parent stack — trace module outputs/wiring
- Encryption attribute omitted where provider default is encrypt-on (verify provider/version docs; flag as Info if default is secure)
- `sensitive = true` on variables populated from CI secrets — not a hardcoded secret finding
- Test/dev stacks with `environment = "dev"` and narrow CIDR comments — still flag if CIDR is literally `0.0.0.0/0` to sensitive ports unless policy exempts dev
- Pulumi/CDK constructs that wrap secure defaults — read generated plan or underlying resource args, not wrapper name alone
- `ignore_changes` on tags or naming only — not a security suppress unless encryption/ACL/CIDR/policy are included
