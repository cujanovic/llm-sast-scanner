---
name: nginx_security
description: nginx / OpenResty configuration misconfiguration detection — alias traversal, CRLF/response splitting, SSRF via proxy_pass, header redefinition, access-control bypass, regex ReDoS, and information disclosure in nginx.conf and server/location blocks
---

# nginx Configuration Security

nginx behaviour is driven entirely by directive values in `nginx.conf`, `sites-available/*`, `conf.d/*.conf`, and included snippets. Static analysis targets directive-level misconfigurations that expose traversal, request/response manipulation, SSRF, broken access control, or information disclosure — independent of the application behind the proxy.

**CWE**: CWE-22 (alias traversal), CWE-113 (CRLF/response splitting), CWE-918 (SSRF), CWE-284 (access-control bypass), CWE-644 (host spoofing), CWE-693 (dropped security headers), CWE-200 (information disclosure), CWE-1333 (regex ReDoS).

The core pattern: *a directive embeds a decoded or client-controlled variable into a security-sensitive position (filesystem path, upstream target, redirect/Location, header), or a block-scoped directive silently overrides an inherited control.*

## What It Is (and Is Not)

**What it IS**
- `location` / `alias` prefix mismatch enabling path traversal outside the served root
- `$uri` / `$document_uri` (URL-decoded) used in `rewrite`, `return`, `add_header`, or `proxy_set_header` — CRLF injection / response splitting
- `proxy_pass` whose target host/scheme is built from a client-controlled variable (`$arg_*`, `$http_*`, `$uri`) — SSRF / internal pivot
- `proxy_pass` to a name resolved by an external/attacker-influenced `resolver`, or relying on a stale DNS cache — SSRF / rebinding
- block-scoped `add_header` that drops security headers inherited from the parent (nginx replaces, never merges, the `add_header` set per block)
- `server_tokens on`, exposed `stub_status` / status pages, `autoindex on` — information disclosure
- `allow` without a matching `deny`, or a `return`/`rewrite` placed so it bypasses `allow`/`deny`, or `satisfy any` weakening auth — access-control bypass
- `$host` / `$http_host` trusted for security decisions or forwarded as `X-Forwarded-Host` to a backend that trusts it — host-header poisoning
- unsafe `valid_referers` (e.g. `none blocked`) used as an access-control gate
- unanchored / overlapping / catastrophically-backtracking regex `location` or `map` keys — bypass or ReDoS
- `if` used inside `location` for non-trivial logic ("if is evil"), `try_files`+`if` interactions, `merge_slashes off` enabling path confusion
- `proxy_pass` with a normalized URI (trailing-slash/rewrite forms) that desyncs path between nginx and the upstream — request smuggling / ACL bypass

**What it is NOT**
- **Application-code** SSRF/traversal/XSS — see `ssrf.md`, `path_traversal_lfi_rfi.md`, `xss.md`
- **TLS/cert validation in app clients** — see `certificate_validation.md` (nginx `ssl_*` cipher/protocol hygiene is in scope here only as config)
- **Cloud firewall / LB rules** — see `iac_security.md`, `kubernetes_cloud_security.md`
- **WAF rule tuning** — not a config-static finding
- **Intentional public endpoints** (health checks, public CDN paths) with no sensitive data

## Recon Indicators

Grep nginx config trees. Recon is directive/variable presence; confirm block scope and context in a later pass.

| Area | Grep / pattern targets |
|------|------------------------|
| Alias traversal | `location\s+[^/{]*[^/]\s*\{` immediately followed by `alias\s` (location lacks trailing `/` while `alias` ends in `/`); any `alias` whose `location` is a prefix without matching trailing slash |
| CRLF / splitting | `(rewrite\|return\|add_header\|proxy_set_header\|set)\s+[^;]*\$(uri\|document_uri)\b` (decoded vars); `return\s+30[0-9][^;]*\$arg_`; `add_header[^;]*\$arg_` |
| SSRF (proxy) | `proxy_pass\s+https?://\$(arg_\|http_\|cookie_\|uri)`, `fastcgi_pass\s+\$`, `proxy_pass\s+\$\w+;`, `proxy_pass[^;]*\$host` |
| Resolver / DNS | `resolver\s+(?!127\.)\d`, `resolver\s+\d+\.\d+\.\d+\.\d+` (public DNS), `proxy_pass` to a variable name with `resolver` set; missing `resolver` with `ssl_stapling on` |
| Header redefinition | multiple `add_header` blocks across `server` vs `location`; any `location` with `add_header` while parent sets security headers (`X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`) |
| Host spoofing | `\$host\b`, `\$http_host\b` in `return`/`rewrite`/`proxy_set_header X-Forwarded-Host`/security `if` |
| Access control | `allow\s` without nearby `deny`, `satisfy\s+any`, `return\s` / `rewrite\s` before `allow`/`deny` in same block, `valid_referers\s+none\s+blocked` |
| Info disclosure | `server_tokens\s+on`, `stub_status`, `autoindex\s+on`, `location[^{]*\b(status\|nginx_status\|server-status\|metrics\|\.git\|\.env)\b` without `allow`/`deny`/auth |
| Regex hazards | unanchored `location\s*~\s*[^^]`, `location\s*~\s*.*(\.\*\|\.\+).*(\.\*\|\.\+)` (overlapping), `(a+)+`/nested quantifiers in `location ~`/`map`/`if` |
| `if` is evil | `if\s*\([^)]*\)\s*\{` inside `location` containing `proxy_pass`/`rewrite`/`return`/`set` |
| Path confusion | `merge_slashes\s+off`, `proxy_pass[^;]*/;` with `rewrite`, `proxy_pass http://up/$1` from a captured URI |
| TLS hygiene | `ssl_protocols[^;]*(SSLv2\|SSLv3\|TLSv1[ ;]\|TLSv1\.0\|TLSv1\.1)` (matches bare `TLSv1`/`.0`/`.1` only — must NOT match modern `TLSv1.2`/`TLSv1.3`), `ssl_ciphers[^;]*(RC4\|MD5\|DES\|3DES\|NULL\|EXPORT\|LOW)`, `ssl_stapling on` without `resolver` |
| Logging | `error_log\s+off`, `access_log\s+off` on security-relevant vhosts (note: `error_log off` writes to a file literally named `off`) |

**File targets**: `nginx.conf`, `*.conf` under `conf.d/`, `sites-available/*`, `sites-enabled/*`, `snippets/*`, `*.nginx`, and Helm/ConfigMap embedded nginx blocks. nginx config files are frequently **extensionless** (e.g. Debian/Ubuntu `sites-available/default`, `include`d snippets) — match `sites-available/`, `sites-enabled/`, and `snippets/` by **path, not extension**. Detect by these paths or by content containing `server {` / `location ` / `proxy_pass` / `worker_processes` / `ssl_protocols` / `ssl_certificate`.

## Vulnerable Conditions

- A `location` prefix without a trailing slash maps via `alias` to a directory with a trailing slash (e.g. `location /static` + `alias /var/www/static/;`) → `GET /static../etc/passwd`.
- `$uri`/`$document_uri` (already URL-decoded by nginx) flows into a `Location`, header, or rewrite target → injected `%0d%0a` splits the response or forges headers.
- `proxy_pass` host or scheme derives from `$arg_*`, `$http_*`, `$cookie_*`, or `$uri` → attacker selects the upstream (internal services, `169.254.169.254`, `localhost`).
- A `location` defines any `add_header`, so the security headers set in the parent `server`/`http` block are not emitted for that path.
- `stub_status`, a metrics endpoint, `server_tokens on`, or `autoindex on` is reachable without `allow`/`deny`/auth.
- `allow` appears with no `deny all;`, or a `return`/`rewrite` short-circuits before the `allow`/`deny` check, or `satisfy any;` lets either auth OR IP pass.
- `X-Forwarded-Host`/`Host` is forwarded from `$http_host` to a backend that builds links or makes auth decisions on it.
- `valid_referers none blocked;` used as the only gate on a sensitive route.
- An unanchored or overlapping regex `location`/`map`, or a nested-quantifier regex, allows route bypass or ReDoS-driven worker exhaustion.
- `proxy_pass` with URI normalization or `merge_slashes off` causes nginx and the upstream to disagree on the path, bypassing ACLs or enabling smuggling.

## Safe Patterns

- **Alias with matching slashes** — `location /static/ { alias /var/www/static/; }`, or prefer `root` over `alias`; use `^~` to avoid regex-location surprises.
- **No decoded vars in security positions** — build redirects/headers from `$request_uri` (raw) only when necessary, validate against an allowlist, and never place `$uri`/`$arg_*` in a `Location` or header without sanitization.
- **Fixed upstreams** — `proxy_pass http://named_upstream;` with a static `upstream {}` block, or a `map` from a closed allowlist of names to fixed targets; never a client variable.
- **Repeat security headers** — re-declare all security headers (with `always`) in every block that uses `add_header`, or centralize via an `include snippets/security-headers.conf;` in each block.
- **Lock down ops endpoints** — `stub_status`/metrics/status behind `allow 127.0.0.1; deny all;` or auth; `server_tokens off;`; `autoindex off;`.
- **Deny-by-default ACLs** — pair `allow` with `deny all;`, order checks before any `return`/`rewrite`, avoid `satisfy any` unless intended.
- **Trusted host** — use `$host` only from a trusted front proxy; pin `server_name` and add a default catch-all `server` returning `444` for unknown hosts.
- **Anchored, simple regex** — anchor `location ~ ^/path$`, avoid overlapping/nested quantifiers; prefer prefix locations.
- **Internal resolver** — set `resolver` to a trusted internal DNS with a sane `valid` TTL; provide `resolver` when `ssl_stapling on`.

### Alias traversal — VULN vs SAFE

**VULN**:
```nginx
location /static {
    alias /var/www/static/;
}
```

**SAFE**:
```nginx
location /static/ {
    alias /var/www/static/;
}
```

### CRLF / response splitting via decoded `$uri` — VULN vs SAFE

**VULN**:
```nginx
location /redir {
    return 302 https://app.example.com$uri;
}
```

**SAFE**:
```nginx
location = /redir {
    return 302 https://app.example.com/landing;
}
```

### SSRF via client-controlled proxy_pass — VULN vs SAFE

**VULN**:
```nginx
location /api/ {
    proxy_pass http://$arg_backend;
}
```

**SAFE**:
```nginx
upstream api { server 127.0.0.1:8080; }
location /api/ { proxy_pass http://api; }
```

### Security-header redefinition — VULN vs SAFE

**VULN** — `/images/` drops the parent CSP/XFO:
```nginx
server {
    add_header Content-Security-Policy "default-src 'self'" always;
    location /images/ {
        add_header Cache-Control "max-age=3600";   # parent security headers now NOT sent here
    }
}
```

**SAFE**:
```nginx
location /images/ {
    add_header Content-Security-Policy "default-src 'self'" always;
    add_header Cache-Control "max-age=3600" always;
}
```

### Access-control bypass — VULN vs SAFE

**VULN** — `return` runs before allow/deny, and `allow` has no `deny`:
```nginx
location /admin/ {
    allow 10.0.0.0/8;
    return 200 "ok";    # served regardless of source IP
}
```

**SAFE**:
```nginx
location /admin/ {
    allow 10.0.0.0/8;
    deny all;
}
```

### Trusting `X-Accel-Redirect` / `X-Sendfile` from an untrusted upstream — VULN vs SAFE

`X-Accel-Redirect` lets a backend tell nginx to internally serve an arbitrary `internal` location (the X-Sendfile pattern). If the upstream behind `proxy_pass` is **not fully trusted** — a third-party app, a multi-tenant backend, or anything that reflects user input into response headers — the backend (or an attacker who can set that response header) can make nginx return **any internal file/location**, bypassing auth on `internal` routes. The same applies to `X-Accel-*` family headers.

**VULN** — external/untrusted upstream, response `X-Accel-Redirect` honored:
```nginx
location / { proxy_pass http://untrusted_app; }   # app can emit X-Accel-Redirect: /internal/secret
location /internal/ { internal; alias /var/secrets/; }
```

**SAFE** — strip the headers from untrusted upstreams so only trusted backends can use the feature:
```nginx
location / {
    proxy_pass http://untrusted_app;
    proxy_hide_header X-Accel-Redirect;     # and X-Accel-Buffering, X-Accel-Charset, etc.
    proxy_ignore_headers X-Accel-Redirect X-Accel-Buffering X-Accel-Charset X-Accel-Expires X-Accel-Limit-Rate;
}
```

**Recon**: `proxy_pass` to a non-local/third-party upstream **without** a matching `proxy_hide_header`/`proxy_ignore_headers X-Accel-Redirect`; an `internal` location holding sensitive files reachable via `X-Accel-Redirect`.

## Cross-References (enrich these classes with the nginx signal)

- **Path traversal** → `path_traversal_lfi_rfi.md` (alias/`location` mismatch)
- **HTTP response splitting / CRLF** → `http_response_splitting.md` (`$uri`/`$arg_*` in `return`/`add_header`)
- **SSRF** → `ssrf.md` (`proxy_pass` to a variable; external `resolver`; stale DNS cache)
- **Host header poisoning** → `host_header_poisoning.md` (`$http_host`/`$host` trust)
- **CORS** → `cors_misconfiguration.md` (regex `origins`/`valid_referers` reflection)
- **Security headers / CSP** → `content_security_policy.md` (block-scoped `add_header` dropping CSP/XFO)
- **Information disclosure** → `information_disclosure.md` (`server_tokens on`, `stub_status`, `autoindex on`)
- **ReDoS** → `regex_injection_redos.md` (catastrophic regex in `location`/`map`)
- **Request smuggling / desync** → `smuggling_desync.md` (`proxy_pass` normalization, `merge_slashes off`)
- **Access control** → `privilege_escalation.md` (`allow` without `deny`, `return` bypass, `satisfy any`)

## Common False Alarms

- `alias` whose `location` already ends in `/` and matches the alias slash — safe; only the prefix-without-slash form traverses.
- `$request_uri` (raw, not decoded) reflected in a redirect — lower risk than `$uri`; still validate, but it is not the classic decoded-CRLF sink.
- `proxy_pass http://$upstream;` where `$upstream` is set by `set $upstream <literal>;` or a closed `map` — not client-controlled; trace the variable's source.
- A `location` with only non-security `add_header` (e.g. `Cache-Control`) where the parent sets no security headers — header-redefinition is informational, not a dropped-control finding.
- `stub_status`/metrics already guarded by `allow`/`deny`/auth, or bound to a localhost-only `listen` — not exposed.
- `server_tokens on` on an internal-only vhost behind authenticated network — downgrade to Info.
- `valid_referers` used only for hotlink protection (not auth) — not an access-control finding.
