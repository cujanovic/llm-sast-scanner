---
name: grpc_security
description: gRPC / gRPC-Web / Connect server-side security — server reflection enabled in production, insecure/plaintext (h2c) transport credentials, missing authentication/authorization interceptors (per-method authz), trusting proxy-injected identity metadata, binary -bin metadata auth bypass, and grpc-gateway/gRPC-Web/JSON-transcoder routes re-exposing internal RPCs without auth (CWE-306/287/319/863/200).
---

# gRPC Server-Side Security

gRPC services are built from a `.proto` contract and served over HTTP/2. The dominant risk is the architectural assumption that a service is **"internal"** — authentication is enforced at an edge proxy (Envoy/grpc-gateway) and the backend trusts any caller that reaches it. When that trust is encoded in source (no per-method authz interceptor, plaintext transport, identity read from spoofable metadata), it is statically detectable.

*The core pattern: a gRPC server exposes callable methods (or a reflection catalog) without enforcing authentication/authorization in code, or derives identity from caller-controlled metadata, so reaching the server is sufficient to invoke privileged RPCs.*

## What It Is (and Is Not)

**What it IS**
- **Reflection enabled in production**: the server registers `ServerReflection`, exposing the full service/method/message catalog to any caller (enumeration enabler, info disclosure)
- **Insecure / plaintext transport (h2c)**: server bound with insecure credentials or no TLS — metadata (bearer tokens, identity headers) travels in cleartext
- **Missing auth interceptor**: server constructed without a unary/stream interceptor (or per-method check) performing authentication and authorization → methods are callable anonymously; relies on network reachability or edge-only auth
- **Trusting proxy-injected identity metadata**: backend reads `x-user-id` / `x-tenant-id` / `x-authenticated-user` / `x-forwarded-*` from incoming metadata and treats it as proof of identity, without verifying a signed token — spoofable if the caller reaches the backend or the edge forwards client-supplied values unstripped
- **Binary `-bin` metadata auth bypass**: auth middleware inspects only text metadata keys while sensitive values arrive under base64 `-bin` keys (or vice versa), so the check is skipped
- **Transcoder re-exposing internal RPCs**: grpc-gateway, gRPC-Web, Envoy `grpc_json_transcoder`, or Connect maps gRPC methods to browser-reachable REST/JSON without re-applying the auth the native gRPC path assumed — internal/admin services become externally callable
- **Per-method authz gaps**: a global interceptor authenticates (proves *who*) but does not authorize *which* methods/resources — admin RPCs callable by any authenticated principal (BFLA), or IDOR via enumerable id fields in request messages

**What it is NOT**
- **Generic SSRF/RCE/SQLi inside an RPC handler** — tag the downstream sink class (`ssrf.md`, `rce.md`, `sql_injection.md`); gRPC is the transport, not the sink
- **IDOR logic itself** — see `idor.md`; this file covers the gRPC-specific surfaces (request-message id fields, reflection-aided enumeration)
- **HTTP/2 Rapid Reset (CVE-2023-44487)** — a dependency-version/DoS issue (SCA + `denial_of_service.md`), not a source-code taint pattern; flag only the *config* mitigations below
- **mTLS/TLS termination handled entirely in infrastructure** (service mesh) not visible in source — verify deployment separately before downgrading

## Recon Indicators

### Reflection registered (enumeration enabler)

| Stack | Grep / structural targets |
|-------|----------------------------|
| Go | `reflection\.Register\(`, `google\.golang\.org/grpc/reflection` |
| Java | `ProtoReflectionService`, `ProtoReflectionServiceV1`, `.addService(ProtoReflection` |
| Python | `grpc_reflection`, `enable_server_reflection`, `reflection\.enable_server_reflection` |
| .NET | `AddGrpcReflection\(`, `MapGrpcReflectionService\(` |
| Node | `@grpc/reflection`, `ReflectionService`, `addReflection` |

Reflection on by itself is **info disclosure (Low/Medium)** — the finding is the *sensitive* service it reveals that is then callable without auth. Many vendors ship reflection on by design; flag highest when combined with a missing-auth signal below.

### Insecure / plaintext transport

| Stack | VULN signal | Safe alternative |
|-------|-------------|------------------|
| Go | `grpc.NewServer()` with no `grpc.Creds(...)`; serving listener without TLS | `grpc.Creds(credentials.NewTLS(cfg))` / mTLS |
| Python | `server.add_insecure_port(` | `server.add_secure_port(addr, server_credentials)` |
| .NET / Kestrel | `HttpProtocols.Http2` endpoint without `UseHttps()` (h2c) | TLS on the HTTP/2 endpoint |
| Node | `ServerCredentials.createInsecure()` | `ServerCredentials.createSsl(...)` |
| Java | `ServerBuilder.forPort(p)` (plaintext Netty) | `TlsServerCredentials` / `.useTransportSecurity(...)` |

Cross-ref `cleartext_transmission.md`. Plaintext is highest-severity when bearer tokens / identity metadata cross that channel.

### Missing authentication/authorization interceptor

| Stack | Where auth SHOULD be (absence = finding) |
|-------|------------------------------------------|
| Go | `grpc.UnaryInterceptor` / `grpc.ChainUnaryInterceptor` / `grpc.StreamInterceptor` performing token validation + per-method authz |
| Java | a `ServerInterceptor` (e.g. `interceptCall`) validating credentials; `Contexts.interceptCall` |
| Python | `grpc.ServerInterceptor` subclass passed to `grpc.server(interceptors=[...])`, or per-method checks of `context.invocation_metadata()` |
| .NET | `[Authorize]` on gRPC service/methods + `AddAuthentication`/`AddAuthorization`; gRPC interceptors |
| Node | server interceptor or in-handler `call.metadata` validation |

```bash
# server constructed with no interceptor wiring (review each hit for an auth check)
rg -n "grpc\.NewServer\(\)|grpc\.server\(|new Server\(|ServerBuilder\.forPort|GrpcServiceEndpoint" --glob '*.{go,py,js,ts,java,cs}'
rg -n "UnaryInterceptor|StreamInterceptor|ServerInterceptor|invocation_metadata|\[Authorize\]" --glob '*.{go,py,js,ts,java,cs}'
```
A server with reflection on, insecure port, and **no interceptor** is the classic anonymous-callable backend.

### Trusting proxy-injected identity metadata

```bash
# identity read directly from caller-controlled metadata (not a verified token)
rg -n "x-user-id|x-tenant-id|x-authenticated-user|x-forwarded-(user|for)|x-internal" --glob '*.{go,py,js,ts,java,cs}'
rg -n "FromIncomingContext|invocation_metadata|RequestHeaders|call\.metadata\.get" --glob '*.{go,py,js,ts,java,cs}' -C2
```
Identity must come from a verified credential (mTLS peer, validated JWT/`authorization` token), not from a plaintext header a peer can set. Cross-ref `trust_boundary.md`, `authentication_jwt.md`. The proxy must **strip** client-supplied identity headers at ingress; if it forwards them unchanged, the spoof is reachable by real external users.

### Binary `-bin` metadata bypass

gRPC base64-decodes metadata keys ending in `-bin`. Auth checks that inspect only text keys (or only `-bin` keys) miss the other channel.

```bash
rg -n "[a-z0-9-]+-bin\b|WithKeyBinary|Metadata\.Key\.of\(.*BINARY|metadata\.BinaryKey" --glob '*.{go,py,js,ts,java,cs}'
```

### Transcoder / gRPC-Web re-exposure

| Signal | Grep targets |
|--------|--------------|
| grpc-gateway | `runtime\.NewServeMux`, `Register.*HandlerFromEndpoint`, `google.api.http` annotations in `.proto` |
| gRPC-Web | `grpcweb`, `grpc-web`, `improbable-eng/grpc-web`, `Access-Control-Allow-Origin` on a gRPC mux |
| Envoy transcoder | `grpc_json_transcoder`, `envoy.filters.http.grpc_web` |
| Connect | `connectrpc`, `connect-go`, `connect-web` |

Flag when an admin/internal service is added to a transcoder mux without the auth filter the native path relied on, or with permissive CORS.

### DoS mitigation config (HTTP/2 stream limits)

Not the CVE itself (that is version/SCA) but a hardening signal: server with **no `MaxConcurrentStreams` cap** and unbounded concurrent-stream/keepalive handling is more exposed to stream-flood/Rapid-Reset abuse. Cross-ref `denial_of_service.md`.
```bash
rg -n "MaxConcurrentStreams|max_concurrent_streams|MaxConcurrentRpcs|keepalive" --glob '*.{go,py,js,ts,java,cs}'
```

## Vulnerable Conditions

- gRPC server registers reflection and is reachable outside the mesh, exposing a non-public service catalog
- Server bound with insecure/plaintext credentials (h2c) where metadata carries tokens or identity
- No unary/stream interceptor (or per-method check) authenticates AND authorizes calls — methods callable anonymously
- A global interceptor authenticates but does not enforce per-method/per-resource authorization (privileged RPC callable by any principal — BFLA; or IDOR via request-message id field)
- Identity derived from `x-user-id`/`x-tenant-id`/`x-forwarded-*` metadata rather than a verified credential, and the edge does not strip client-supplied copies
- Auth middleware inspects only text or only `-bin` metadata, leaving the other channel unchecked
- grpc-gateway/gRPC-Web/Connect/Envoy transcoder maps internal or admin RPCs to browser-reachable REST/JSON without re-applying auth, or with wildcard CORS
- Request messages expose mutating/admin methods (`DeleteUser`, `GetConfig`, `Impersonate`) without authorization on the resolver

## Safe Patterns

**Transport**
- TLS (preferably mTLS) on every server; never `add_insecure_port` / `createInsecure` / h2c in production
- Service-mesh mTLS is acceptable but verify it is actually enforced (not permissive mode)

**AuthN/AuthZ**
- A single chained interceptor that (1) authenticates via mTLS peer identity or a validated, audience-bound token, then (2) enforces per-method authorization from a server-side policy — default-deny for unlisted methods
- Authorize on the resolved server-side identity and the specific resource id in the request message (prevent BFLA/IDOR), not on caller-supplied identity fields

**Identity from metadata**
- Derive identity only from a verified credential; treat all `x-*` identity metadata as untrusted unless it arrives over mTLS from a trusted peer AND the ingress strips external copies

**Reflection / surface**
- Disable reflection in production builds (or gate behind auth); ship descriptors to trusted clients out-of-band
- Apply the same interceptors/auth to transcoder and gRPC-Web routes as to the native gRPC plane; restrict CORS

```go
// SAFE (Go) — TLS + chained auth interceptor, reflection gated to non-prod
s := grpc.NewServer(
    grpc.Creds(credentials.NewTLS(tlsCfg)),                 // no h2c
    grpc.ChainUnaryInterceptor(authnUnary, authzUnary),     // authn THEN per-method authz
    grpc.MaxConcurrentStreams(250),                          // stream-flood hardening
)
pb.RegisterAdminServiceServer(s, &adminSrv{})
if env != "prod" {                                          // reflection off in prod
    reflection.Register(s)
}

func authzUnary(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
    id := identityFromVerifiedToken(ctx)                     // NOT md.Get("x-user-id")
    if !policy.Allow(id, info.FullMethod) {                  // default-deny per method
        return nil, status.Error(codes.PermissionDenied, "denied")
    }
    return h(ctx, req)
}
```

## Language Examples

### Go (grpc-go)

```go
// VULN — plaintext server, reflection on, no interceptor: any caller invokes any method
s := grpc.NewServer()
pb.RegisterAdminServiceServer(s, &adminSrv{})
reflection.Register(s)
lis, _ := net.Listen("tcp", ":50051")                       // no TLS (h2c)
s.Serve(lis)

// VULN — identity trusted from caller-supplied metadata
md, _ := metadata.FromIncomingContext(ctx)
userID := md.Get("x-user-id")[0]                            // spoofable; not a verified token
```

### Python (grpcio)

```python
# VULN — insecure port, reflection on, no interceptor
server = grpc.server(futures.ThreadPoolExecutor())
admin_pb2_grpc.add_AdminServiceServicer_to_server(AdminService(), server)
reflection.enable_server_reflection(SERVICE_NAMES, server)
server.add_insecure_port('[::]:50051')                      # cleartext h2c

# VULN — identity from metadata
md = dict(context.invocation_metadata())
tenant = md.get('x-tenant-id')                              # trusted without verification
```

### .NET (Grpc.AspNetCore)

```csharp
// VULN — gRPC service with no [Authorize]; reflection mapped; h2c endpoint
builder.Services.AddGrpc();
builder.Services.AddGrpcReflection();
app.MapGrpcService<AdminService>();          // anonymous
app.MapGrpcReflectionService();
// Kestrel endpoint set to HttpProtocols.Http2 without UseHttps() → cleartext
```

### Node (@grpc/grpc-js)

```js
// VULN — insecure credentials, no auth check in handler
const server = new grpc.Server();
server.addService(AdminService.service, { deleteUser: deleteUserHandler });
server.bindAsync('0.0.0.0:50051', grpc.ServerCredentials.createInsecure(), () => {});
// deleteUserHandler never inspects call.metadata for a verified token
```

## Dynamic Test / PoC

Use only on systems you are authorized to test. PoC confirms reachability; mesh-only reachability downgrades severity but not the source-code finding.

| Check | Probe | Confirms |
|-------|-------|----------|
| Reflection on | `grpcurl -plaintext HOST:50051 list` returns a non-public catalog | Catalog disclosure |
| Anonymous call | `grpcurl -plaintext HOST:50051 -d '{}' admin.AdminService/ListUsers` returns `OK` + data | Missing auth (status `0`, not `Unauthenticated 16` / `PermissionDenied 7`) |
| Metadata spoof | add `-H 'x-user-id: 1'` and observe another principal's data; verify the **public proxy** forwards it unstripped | Proxy-injected-identity trust |
| `-bin` bypass | send the auth value under an `auth-token-bin` key | Text-only auth middleware skipped |
| Transcoder re-exposure | `curl -X POST https://HOST/admin.AdminService/ListUsers -H 'content-type: application/json' -d '{}'` | Internal RPC externally reachable |

Discriminate on the gRPC **status code/trailer**, not whether bytes returned: `OK(0)` = executed; `Unauthenticated(16)`/`PermissionDenied(7)` = auth works (not a finding); `Unimplemented(12)` = wrong method.

## Common False Alarms

- Reflection / `grpc.health.v1.Health` reachable on a service intentionally public — info disclosure at most unless it unlocks a sensitive callable method
- `add_insecure_port`/`createInsecure` on a **localhost-only** bind or behind enforced mesh mTLS — verify the bind address and mesh policy before flagging cleartext
- A method legitimately anonymous (health, public catalog read) — prove a finding with an authenticated-vs-unauthenticated state delta, not just a non-empty response
- Identity read from metadata that is itself a **verified** token (`authorization` validated by the interceptor) — not the proxy-trust pattern
- Interceptor present and chained but located in a separate module — trace wiring before reporting "missing auth"
- Test/example servers under `examples/`, `testdata/`, integration tests — not production entrypoints
