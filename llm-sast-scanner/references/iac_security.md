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

## Common False Alarms

- `0.0.0.0/0` on port 443/80 for a documented public load balancer or CDN origin — confirm target is LB tier, not admin/DB tier
- `"Principal": "*"` inside a bucket policy **deny** statement or conditioned with `aws:SourceVpc`, `aws:SourceIp`, or MFA — read full policy JSON
- `public_access_block` absent in a module that always invokes the block resource in a parent stack — trace module outputs/wiring
- Encryption attribute omitted where provider default is encrypt-on (verify provider/version docs; flag as Info if default is secure)
- `sensitive = true` on variables populated from CI secrets — not a hardcoded secret finding
- Test/dev stacks with `environment = "dev"` and narrow CIDR comments — still flag if CIDR is literally `0.0.0.0/0` to sensitive ports unless policy exempts dev
- Pulumi/CDK constructs that wrap secure defaults — read generated plan or underlying resource args, not wrapper name alone
- `ignore_changes` on tags or naming only — not a security suppress unless encryption/ACL/CIDR/policy are included
