---
name: subdomain-takeover
description: Subdomain takeover — flag CANDIDATE dangling DNS records in Infrastructure-as-Code (Route53/Azure DNS/Cloud DNS/CNAME to SaaS) that point at takeover-prone external services with no co-declared backing resource (CWE-350 / dangling DNS). Use when reviewing *.tf, CloudFormation/ARM/Bicep/Pulumi, zone files, or DNS config for dangling CNAME/ALIAS to deprovisionable cloud/SaaS endpoints.
---

# Subdomain Takeover (IaC candidate flagging)

Subdomain takeover happens when a DNS record (usually a `CNAME`, `ALIAS`, or provider alias) points at an **external service endpoint that is no longer claimed** by the owning org. An attacker registers/claims that endpoint on the third-party provider (an unclaimed S3 bucket, a free Heroku/Netlify/GitHub Pages app, an expired SaaS tenant, a deleted CloudFront distribution) and then serves content from the victim's hostname — enabling phishing, cookie theft, OAuth `redirect_uri`/CORS allowlist abuse, CSP bypass, and full session/authentication bypass on the parent domain.

## Scope of this skill: CANDIDATES ONLY

Subdomain takeover is fundamentally a **DNS-state + provider-ownership** condition: whether a target is *actually* claimable can only be confirmed by resolving the record live and probing the provider (a fingerprint response, an `NXDOMAIN`/`NoSuchBucket`/404 "no such app" page, or an unclaimed-tenant signal). That is an **out-of-band/runtime action outside static analysis** — the same boundary as `dependency_confusion.md` (which flags claimable package names but cannot prove ownership statically).

This reference therefore flags **candidates from IaC/config source alone**:

- **CANDIDATE** = a declared DNS record pointing at a takeover-prone external service whose backing resource is **not co-declared/managed** in the same IaC.
- Report candidates as **Informational / Low** with the note: *"confirm by resolving the record and probing the target endpoint (unclaimed fingerprint / NXDOMAIN behind a live CNAME = claimable = exploitable)."*
- Do **not** assert exploitability or raise severity without that out-of-band confirmation.

## The candidate condition

Flag a DNS record when ALL hold:

1. **Points at an external/third-party endpoint** — a `CNAME`/`ALIAS`/alias-target hostname owned by a cloud or SaaS provider (see fingerprint table), not an in-account resource referenced by attribute.
2. **Backing resource not co-declared** — the target bucket/app/distribution/zone is **not** created or referenced (by resource reference/output/`depends_on`) in the same IaC tree, so it can drift out of existence while the record survives.
3. **Service is takeover-prone** — the provider returns a claimable state when the backing resource is absent (no domain-ownership binding, no required verification token).

## Detection inputs to parse

- **Terraform**: `aws_route53_record`, `azurerm_dns_cname_record` / `azurerm_dns_a_record`, `google_dns_record_set`, `cloudflare_record`, `ns1_record`, `dnsimple_record`.
- **CloudFormation / SAM**: `AWS::Route53::RecordSet`(`Group`).
- **Azure ARM / Bicep**: `Microsoft.Network/dnsZones/CNAME` (and `A`).
- **Pulumi**: `aws.route53.Record`, `azure-native.network.RecordSet`, `gcp.dns.RecordSet`.
- **Zone files / config**: BIND zone files, `*.zone`, exported DNS JSON/YAML.

The deciding signal is the **relationship between the record's target and a managed resource** — a hardcoded external hostname (string literal) is a candidate; an attribute reference to a managed resource (`aws_s3_bucket.site.website_endpoint`, `aws_cloudfront_distribution.cdn.domain_name`) is generally safe because the record and its backing resource are created/destroyed together.

---

## Takeover-prone target fingerprints

Treat a record as a candidate when its target host matches a deprovisionable provider endpoint and the backing resource is not co-managed:

| Provider / service | Target-host shape | Why takeover-prone |
|---|---|---|
| Object storage (S3-style website) | `*.s3-website[.-]<region>.<cloud-tld>`, `*.<storage>.web.core.windows.net`, `storage.googleapis.com/<bucket>` | Bucket/container name is globally claimable once deleted; no domain binding |
| CDN distribution | `*.cloudfront.<cloud-tld>`, `*.azureedge.net`, generic CDN edge host | Deleted distribution frees the CNAME alias; re-creatable by anyone in some setups |
| PaaS app hosting | `*.herokuapp.com`, `*.<paas>.app`, `*.azurewebsites.net`, `*.elasticbeanstalk.<cloud-tld>` | App/space name reclaimable when app is deleted |
| Static site hosting | `*.github.io`, `*.netlify.app`, `*.pages.dev`, `*.gitlab.io`, `*.surge.sh` | Repo/site/custom-domain claim is first-come once released |
| SaaS custom domains | helpdesk/status/forms/commerce/email-marketing vendor hosts | Tenant/custom-domain slot reclaimable; many lack ownership verification |
| Regional traffic/alias | `*.trafficmanager.net`, regional load-balancer alias hosts | Profile/endpoint deletion leaves a dangling alias |

**Cross-cutting amplifier**: a `CNAME` to an endpoint behind a **deleted/unmanaged** zone or a **wildcard** record (`*.example.com`) delegating to an external host widens the blast radius — flag with a note.

## Per-platform candidate rules

### Terraform
- **CANDIDATE**: `aws_route53_record` with `type = "CNAME"` (or `alias { name = ... }`) whose value is a **string literal** matching a fingerprint host, with no `aws_s3_bucket`/`aws_cloudfront_distribution`/`aws_elastic_beanstalk_environment` reference in scope binding it.
- **SAFE**: record value is an **attribute reference** to a resource managed in the same configuration (`alias { name = aws_cloudfront_distribution.cdn.domain_name, zone_id = ... }`), or the record and target share a `depends_on` lifecycle.

### CloudFormation / ARM / Bicep / Pulumi
- **CANDIDATE**: `RecordSet`/`dnsZones/CNAME` whose target is a literal external host not produced by a `Ref`/`Fn::GetAtt`/resource-output in the same template/stack.
- **SAFE**: target is `!GetAtt Distribution.DomainName` / a Bicep `resource.properties.hostName` reference / a Pulumi resource output — created and destroyed atomically with the record.

### Zone files / DNS-as-data
- **CANDIDATE**: a `CNAME`/`ALIAS` line whose right-hand side is a fingerprint host. Zone files carry **no resource binding at all**, so every external CNAME is a candidate to reconcile against live provider ownership.

---

## FALSE POSITIVE Rules

- Record target is an **attribute reference to a resource managed in the same IaC** (bucket/distribution/app created alongside the record) → SAFE, drop. The record cannot dangle independently of its backing resource.
- Provider **requires domain-ownership verification** for that service (a TXT/verification token co-declared, or apex-binding that blocks third-party claims) → SAFE.
- Target points at an **in-account IP / internal load balancer / first-party origin** you control (not a globally-claimable shared endpoint) → not in scope.
- Record is a **TXT/MX/NS/SOA/DS** or an `A`/`AAAA` to a stable owned address — takeover applies to records aliasing **reclaimable external service slots**, not arbitrary record types.
- Do NOT assign Medium+ severity or assert exploitability without the out-of-band check: resolve the record and confirm the target returns an unclaimed/claimable fingerprint. A live, claimed endpoint = not vulnerable.

## Business Risk

- Attacker-served content on a trusted subdomain → credential phishing, malware delivery, and brand abuse with a valid TLS cert (issued via the claimed endpoint).
- **Auth/session impact**: cookies scoped to the parent domain (`Domain=.example.com`) leak to the hostile subdomain; OAuth `redirect_uri` allowlists, CORS `Access-Control-Allow-Origin` reflections, CSP `*.example.com` sources, and postMessage origin checks that trust subdomains are all bypassed → authentication bypass / account takeover (see `oauth_oidc_misconfiguration.md`, `cors_misconfiguration.md`).

## Core Principle

A DNS record is safe only when its target is **bound to a resource whose lifecycle it shares**. Any record aliasing a globally-reclaimable external service slot, with no co-managed backing resource, is a **subdomain-takeover candidate** worth confirming out-of-band.

Cross-ref: `iac_security.md` (broader IaC misconfiguration), `information_disclosure.md` (exposed zone exports leaking the internal hostnames an attacker would target).
