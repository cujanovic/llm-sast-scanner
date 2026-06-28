---
name: xff_spoofing
description: Client-IP spoofing and network-origin trust failures — security decisions (authz, rate-limit, IP allowlist/ban-list, admin-on-localhost, audit) made from client-controllable IP headers (X-Forwarded-For, X-Real-IP, True-Client-IP, CF-Connecting-IP, Forwarded) or from a correctly-derived-but-multi-tenant network range (CWE-348/290/291). Load for any web/API code that derives or trusts a client IP.
---

# Client-IP Spoofing & Network-Origin Trust (CWE-348/290/291)

Two related failures that both treat the *source IP* — or a header claiming it — as **identity**:

1. **Client-supplied IP spoofing (CWE-348)** — the IP comes from a client-controllable header and is forgeable.
2. **Network-origin trust (CWE-290/291)** — the IP is derived correctly (from the TCP connection) but the "trusted" range is multi-tenant, so anyone can originate from inside it.

A correctly-derived connection IP still is **not** an identity; prefer the `xff_spoofing` tag when the sole issue is IP trust (use `trust_boundary` only when a spoofed IP additionally crosses into session state or privileged configuration).

Commonly affected languages: all web stacks (Java, Python, Go, Node/TS, PHP, Ruby, C#).

## Client-Supplied IP (CWE-348)

### Source → Sink Pattern

- **Source**: HTTP request headers — `X-Forwarded-For`, `X-Real-IP`, `Proxy-Client-IP`, and similar client-influenced IP headers.
- **Sink**: Security-sensitive use of the extracted IP — ban-list checks, rate limiting keyed on IP, admin-only access gated on `127.0.0.1`, audit allowlists.
- **Sanitizer**: Using the **last** (appended) entry in a comma-separated `X-Forwarded-For` chain when behind a trusted reverse proxy; validating IP against a server-side session; ignoring client-supplied headers entirely.

**VULN**: `String ip = request.getHeader("X-Forwarded-For").split(",")[0]; if (blocked.contains(ip)) deny();` — first XFF entry is attacker-controlled.
**SAFE**: Take the last XFF hop added by the trusted proxy, or derive client IP from the TCP connection at the edge. **Caveat**: a correctly-derived connection IP still is not an identity — see Network-Origin / IP-Range Trust Bypass below.

### Beyond leftmost: the full client-IP derivation failure catalog

The leftmost-`split(",")[0]` bug is only the most common shape. Each of the following is independently exploitable and statically detectable; treat any client-IP used for authz/rate-limit/allowlist/audit as suspect until the derivation is proven sound.

- **No trusted-proxy gate at all.** The app reads `X-Forwarded-For` (or any forwarded header) without first checking that the **connection** (`RemoteAddr`/`req.socket.remoteAddress`/`REMOTE_ADDR`) is one of *your* proxies. If the service is reachable directly (cloud LB passthrough, SSRF, misrouting), the attacker sets the whole header. SAFE requires: trust forwarded IPs **only** when the peer is a known proxy, and count exactly the hops you control (e.g. Express `trust proxy` set to a number/CIDR, not `true`).
- **Only first/last header *instance* read on duplicate headers.** With two `X-Forwarded-For:` headers, Go `r.Header.Get("X-Forwarded-For")` / Java `getHeader(...)` / PHP `$_SERVER['HTTP_X_FORWARDED_FOR']` return only **one** instance; an attacker-supplied first header hides behind (or in front of) the proxy-appended one. SAFE: read **all** instances (`r.Header.Values(...)`, `getHeaders(...)`), join, then take the correct trusted hop.
- **Spoofable fallback header chain.** Trusting `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP`, `Fastly-Client-IP`, `X-Client-IP`, `X-Cluster-Client-IP`, or `Forwarded: for=` **without verifying the request actually arrived through that CDN/proxy** — these are plain request headers off-path. Recon: `rg -ni 'true-client-ip|x-real-ip|cf-connecting-ip|fastly-client-ip|x-client-ip|forwarded[^-]' --glob '*.{go,js,ts,py,java,rb,php,cs}'`.
- **Edge *appends* instead of *replacing*.** `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` (nginx) and equivalents **prepend the client value** to the chain, so the client controls every entry to the left of your proxy's hop. Any "take the first/Nth" logic is then attacker-controlled; only the proxy-written rightmost hop is trustworthy.
- **`Forwarded` (RFC 7239) fail-open/sabotage.** A strict parser that discards the whole header on a malformed *client-supplied* prefix lets the attacker erase the proxy-added `for=`; a naive `split(",")` that keeps going trusts a forged entry. Normalize at the edge (strip inbound `Forwarded`/`X-Forwarded-*` from untrusted peers) before parsing.
- **Unvalidated IP string → resource exhaustion / key injection.** Using the raw header value (non-IP garbage, huge token, or the *entire* comma list) as a rate-limit key, cache key, or map key lets an attacker mint unbounded distinct keys (memory DoS) or evade per-IP limits. Parse to a canonical `net.IP`/`InetAddress` and reject non-IPs before use.

```go
// VULN — no trusted-proxy gate, first instance only, leftmost entry
ip := strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]
allow(ip) // attacker sends X-Forwarded-For: 127.0.0.1

// SAFE — only trust forwarded headers from a known proxy; take the hop you wrote; parse to IP
host, _, _ := net.SplitHostPort(r.RemoteAddr)
peer := net.ParseIP(host)
clientIP := peer // default: the real connection peer
if isTrustedProxy(peer) {
    xff := r.Header.Values("X-Forwarded-For") // ALL instances
    all := strings.Split(strings.Join(xff, ","), ",")
    // walk right-to-left, skipping your own trusted hops, to the first untrusted = real client
    clientIP = rightmostUntrusted(all)
}
if clientIP == nil { deny() }
```

Hop-by-hop stripping of the edge-added `X-Forwarded-For` (via a client `Connection: X-Forwarded-For` token on proxies that honor it) is a related desync — cross-ref `smuggling_desync.md`.

## Network-Origin / IP-Range Trust Bypass (shared multi-tenant egress, CWE-290/291)

A separate class from header spoofing: the application determines the source IP **correctly** (from the TCP connection, not a client header) but grants trust because that IP falls in a **"trusted" network range** — and that range is actually **multi-tenant**, so any attacker can originate requests from inside it. Membership in the range proves *where* the packet came from, never *who* sent it. Taking the "real" connection IP (the usual fix for header spoofing) does **not** mitigate this.

**Over-trusted origins (all rentable/shared by anyone)**:
- **Cloud provider published CIDRs** — allowlisting AWS/GCP/Azure/Cloudflare IP ranges; an attacker simply runs from the same provider and lands in the same ranges.
- **CI/CD runner egress** — GitHub Actions, GitLab CI, Bitbucket Pipelines shared runners share an egress pool; anyone with a free account sends traffic from those IPs.
- **Serverless / managed-proxy egress** — Cloudflare Workers, AWS Lambda / API Gateway, other FaaS egress IPs are shared across all tenants; an attacker deploys their own function to borrow the origin.
- **"Same datacenter / region / VPC / internal"** — rules like `allow if src in same-region` or `allow if src in 10.0.0.0/8` trust co-tenants or anyone who gains a foothold in the shared network.

**Why it's weak**: these boundaries assume the trusted range is *yours alone*. On shared cloud/CI/serverless infrastructure it is not — the egress is pooled across every customer, so "from our datacenter / our cloud / our CI" is satisfiable by an external attacker at near-zero cost.

**SAST signals**:
```bash
# allowlists / firewall configs keyed on cloud-provider or shared ranges
rg -ni "aws.*ip.?ranges|ip-ranges\.json|cloudflare.*ips|googleusercontent|amazonaws|azure.*service.?tags" --glob '*.{tf,yaml,yml,json,py,js,ts,go,rb,java}'
# "internal/same region/same datacenter" origin trust, or provider CIDR allow rules
rg -ni "same.?region|same.?datacenter|internal traffic|trusted (range|cidr|subnet)|allow.*from (aws|gcp|azure|cloudflare|datacenter)" -C2
# code comparing source IP against a provider/internal CIDR set as an auth/authz gate
rg -ni "ip_address\(.*\) in |ipaddress\.ip_network|cidr.*contains|InRange.*ip|net\.ParseCIDR" -C2
```

**VULN** (Python — access gated on cloud/CI egress range; attacker rents the same origin):
```python
# rule trips an SSRF/ssrf-prevention rule too: trusting network origin as identity
TRUSTED = [ipaddress.ip_network(c) for c in load_aws_ranges() + CI_EGRESS_CIDRS]
def is_internal(req):
    ip = ipaddress.ip_address(req.transport_peer_ip)   # correctly derived, still not identity
    return any(ip in net for net in TRUSTED)            # VULN: range is multi-tenant
```

**SAFE**: authenticate the *caller*, not the network. Use mutual TLS, signed/short-lived service tokens, HMAC request signing, or cloud workload identity (OIDC) for service-to-service and "internal" calls. Never use cloud-provider/CI/serverless/datacenter/region membership as an authn or authz control. If IP allowlisting is genuinely required, restrict to **dedicated single-tenant egress you own** (e.g., a NAT gateway with a static IP under your control) **and** still layer real authentication on top.

## Cross-References

- `trust_boundary.md` — general CWE-501 trust-boundary violations; use it when a spoofed IP crosses into session state / privileged configuration rather than being a pure IP-trust bug.
- `smuggling_desync.md` — hop-by-hop `Connection: X-Forwarded-For` stripping of the edge-added header.
- `ssrf.md` — server-side request origin; SSRF can reach IP-gated internal services.
- `privilege_escalation.md`, `reverse_proxy_access_bypass.md` — privileged access reached via spoofed IP / origin trust.

## Core Principle

The source IP — whether claimed in a header or derived from the connection — is never an identity. Authenticate the caller (mTLS / signed tokens / workload identity); only trust forwarded IP headers from your own proxies, reading the hop you control, and never grant trust based on membership in a shared/multi-tenant network range.
