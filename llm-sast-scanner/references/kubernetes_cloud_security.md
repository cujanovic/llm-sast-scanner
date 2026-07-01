---
name: kubernetes_cloud_security
description: Kubernetes and cloud orchestration misconfiguration detection — privileged workloads, host namespace mounts, weak securityContext, RBAC, secrets, network policy, and resource limits
---

# Kubernetes / Cloud Orchestration Security

Static detection of insecure Kubernetes manifests, Helm charts, Kustomize overlays, and RBAC bindings. Applies to YAML/JSON cluster configuration checked into repos or rendered in CI — not runtime cluster state unless manifests are the artifact under review.

The core pattern: *a workload or binding grants excessive privilege, exposes sensitive data, or omits baseline hardening that admission policy or Pod Security Standards would enforce.*

## What It Is (and Is Not)

**What it IS**
- Pod/Deployment/StatefulSet/DaemonSet specs with `privileged: true`, dangerous host integrations, or absent `securityContext`
- ClusterRole/Role/RoleBinding/ClusterRoleBinding granting `cluster-admin`, wildcard verbs/resources, or secrets access beyond need
- Secrets, tokens, or credentials embedded in env vars, ConfigMaps, or committed manifest literals
- Namespaces or workloads with no `NetworkPolicy` while running multi-tenant or internet-facing services
- ServiceAccount defaults (`automountServiceAccountToken: true`) on workloads that do not call the API
- Containers without CPU/memory `resources.limits` (and often missing `requests`)
- Manifests exposing Kubernetes Dashboard, kubelet read-only port, or API/etcd without network/auth hardening signals

**What it is NOT**
- Application-layer injection, SSRF, or auth bugs inside container code — analyze application source separately
- Image CVEs or unsigned images — supply-chain class unless manifest pins `:latest` with no digest policy context
- Cloud IAM misconfiguration outside Kubernetes RBAC (AWS/GCP/Azure console policies)
- Runtime-only drift (live cluster differs from Git) — flag only when committed manifests encode the weakness
- Legitimate system components (CNI, CSI, node agents) that require host access — verify role and namespace before reporting

## Recon Indicators

Grep manifests, Helm templates, and Kustomize patches for structural signals. Trace values through `{{ }}` / `$()` only when templating is in scope.

| Signal | Grep / pattern targets |
|--------|------------------------|
| Privileged container | `privileged:\s*true`, `securityContext:` blocks omitting `privileged: false` on sensitive tiers |
| Host integrations | `hostPath:`, `hostNetwork:\s*true`, `hostPID:\s*true`, `hostIPC:\s*true` |
| Missing pod security | `kind:\s*(Pod\|Deployment\|StatefulSet\|DaemonSet\|Job\|CronJob)` without nearby `securityContext:` |
| Privilege escalation | `allowPrivilegeEscalation:\s*true`, `capabilities:` with `add:` containing `SYS_ADMIN`, `NET_ADMIN`, `ALL` |
| Capabilities not dropped | no `capabilities:\s*\n\s*drop:\s*\n\s*-\s*ALL`, or `add:` without prior drop-all |
| Non-root / RO root FS | absent `runAsNonRoot:\s*true`, absent `readOnlyRootFilesystem:\s*true` on app workloads |
| Restricted-PSS escape surface | `procMount:\s*Unmasked` (unmasks `/proc/kcore`, `/proc/sys`, … → escape/info-leak), `appArmorProfile:\s*\n\s*type:\s*Unconfined` or legacy annotation `container\.apparmor\.security\.beta\.kubernetes\.io/.*:\s*unconfined` (no MAC confinement), `seccompProfile:\s*\n\s*type:\s*Unconfined`, and `securityContext:\s*\n\s*sysctls:` setting any sysctl outside the kubelet **safe** set (`kernel.shm_rmid_forced`, `net.ipv4.ip_local_port_range`, `net.ipv4.ip_unprivileged_port_start`, `net.ipv4.tcp_syncookies`, `net.ipv4.ping_group_range`) |
| Over-permissive RBAC | `name:\s*cluster-admin`, `verbs:\s*\[\s*"\*"\s*\]`, `resources:\s*\[\s*"\*"\s*\]`, `apiGroups:\s*\[\s*"\*"\s*\]` |
| Wildcard rules | `- apiGroups:.*\*`, `- verbs:.*\*`, `- resources:.*\*` in Role/ClusterRole |
| RBAC bound to anonymous / all-authenticated | `RoleBinding`/`ClusterRoleBinding` whose `subjects:` include `name:\s*system:anonymous`, `name:\s*system:unauthenticated`, or the group `name:\s*system:authenticated` — the subject side, not the verbs |
| Secrets in env | `env:` entries with `value:` matching secret material, or `secretKeyRef` paired with `env:` on broad workloads |
| Plaintext secrets | `kind:\s*Secret` with `data:` or `stringData:` in repo (base64 is not encryption) |
| SA token automount | `automountServiceAccountToken:\s*true` (default) on Pods/ServiceAccounts for non-API workloads |
| Missing network policy | namespace manifests without `kind:\s*NetworkPolicy`; Deployments with `hostNetwork: true` and no policy |
| Dashboard exposure | `kubernetes-dashboard`, `kind:\s*Service` + `type:\s*LoadBalancer` on dashboard labels |
| Kubelet / API exposure | `10250`, `10255`, `6443`, `2379` in `hostPort:` or `containerPort:` without TLS/auth context |
| Missing limits | `containers:` blocks lacking `resources:` or lacking `limits:` under `resources:` |
| Pod Security labels | namespaces without `pod-security.kubernetes.io/enforce:` |

**File paths to prioritize**: `**/deploy/**`, `**/manifests/**`, `**/k8s/**`, `**/charts/**/templates/**`, `**/*-rbac*.yaml`, `**/clusterrole*.yaml`, `**/networkpolicy*.yaml`.

## Vulnerable Conditions

- **Privileged container** — `securityContext.privileged: true` on application workloads (not documented node-level agents).
- **Host path mount** — `hostPath` mounting `/`, `/var/run/docker.sock`, `/proc`, `/sys`, or host credential paths without read-only + strict path.
- **Host namespace sharing** — `hostNetwork: true`, `hostPID: true`, or `hostIPC: true` breaking network/PID isolation.
- **Missing securityContext** — pod or container spec lacks hardening: no `runAsNonRoot`, no `readOnlyRootFilesystem`, no `capabilities.drop: ["ALL"]`.
- **allowPrivilegeEscalation** — explicitly `true` or omitted while `capabilities.add` is non-empty or container runs as root (`runAsUser: 0`).
- **Restricted Pod Security Standards controls weakened** — beyond the common ones above, the PSS *Restricted* profile also forbids: `procMount: Unmasked` (re-exposes the masked `/proc` paths the runtime hides — a container-escape/info-leak surface; require `Default`); `appArmorProfile.type: Unconfined` (or the legacy `container.apparmor.security.beta.kubernetes.io/<container>: unconfined` annotation) and `seccompProfile.type: Unconfined` — both strip the syscall/MAC sandbox (require `RuntimeDefault`/`Localhost`); and **unsafe sysctls** — a `securityContext.sysctls` entry outside the kubelet's namespaced *safe* set (`kernel.shm_rmid_forced`, `net.ipv4.ip_local_port_range`, `net.ipv4.ip_unprivileged_port_start`, `net.ipv4.tcp_syncookies`, `net.ipv4.ping_group_range`) requires the node's kubelet to run with `--allowed-unsafe-sysctls` and can affect the node or neighbouring pods. These complement the `privileged`/host-namespace/`runAsNonRoot`/`capabilities` controls — flag them on workloads that claim Restricted compliance (or carry the `pod-security.kubernetes.io/enforce: restricted` namespace label).
- **Over-permissive RBAC** — `ClusterRoleBinding`/`RoleBinding` to `cluster-admin`; wildcard verbs; `secrets`/`*` resource for SA used by front-end pods.
- **RBAC bound to anonymous / all-authenticated subjects** — a `RoleBinding`/`ClusterRoleBinding` whose `subjects:` name `system:anonymous` or `system:unauthenticated` grants its role to **unauthenticated** API callers (critical even for a modest role — anyone who can reach the API server gets it); a binding to the `system:authenticated` group grants it to **every** authenticated identity (any valid token, including other namespaces'/tenants' service accounts). This is the *subject* axis of RBAC risk — distinct from the over-permissive-role axis above; a tightly-scoped role bound to an anonymous/all-authenticated subject is still a finding.
- **Secrets in env/manifests** — credentials in `env.value`, `envFrom.secretRef` logged by probes, or committed `Secret`/`ConfigMap` with production keys.
- **Missing NetworkPolicy** — namespace runs multiple tiers (frontend/backend/db) with no default-deny or scoped ingress/egress policies.
- **Exposed dashboard/kubelet** — Dashboard `Service` type `LoadBalancer`/`NodePort` without auth annotations; kubelet port `10250`/`10255` published broadly.
- **automountServiceAccountToken** — default or explicit `true` on workloads with no in-cluster API need (increases token theft blast radius).
- **Missing resource limits** — container omits `resources.limits` for CPU/memory; enables noisy-neighbor and node exhaustion DoS.
- **Ingress annotation / snippet injection** — ingress-nginx `nginx.ingress.kubernetes.io/configuration-snippet`, `server-snippet`, `stream-snippet`, `auth-url`, `permanent-redirect`, `mirror-*`, and `*-by-lua*` annotation values are interpolated into the generated `nginx.conf`. If users (or low-privileged tenants) can create/edit `Ingress` objects, unsanitized annotation values inject nginx directives / Lua → read any in-cluster Secret (via the controller's ServiceAccount), SSRF, or RCE on the controller. Treat `allow-snippet-annotations: true` (historically the default), `annotation-value-word-blocklist` unset, and multi-tenant `Ingress` create rights as the vulnerable condition. Note: certain newline/`permanent-redirect`/`auth-url` value injections bypass `allow-snippet-annotations: false`. Cross-ref `ssrf.md`, `rce.md`, `nginx_security.md`.
- **Scheduling-field abuse — landing a pod on a sensitive node or beside a victim.** When a tenant/user can submit or influence a pod spec (directly, or via a templating/CI/GitOps path that echoes user values into the spec), the *scheduling* fields are an attack surface distinct from the container-hardening fields above:
  - **`nodeName` (hard-assign) bypasses the scheduler entirely** — the scheduling decision is pre-made, so `nodeSelector`/affinity/taints **and** any admission/quota/policy that runs at *schedule* time are skipped. `nodeName: <control-plane or high-value node>` places the pod there directly (reach kubelet/etcd/other tenants' secrets). Flag any user-influenceable pod spec with a non-empty `nodeName`.
  - **`tolerations` for a restricted taint** — a pod that tolerates `node-role.kubernetes.io/control-plane`/`master` (or a dedicated-node taint) schedules onto the isolated node the taint was meant to protect. Flag tolerations of control-plane/dedicated taints (esp. `operator: Exists` with empty `key`, which tolerates **all** taints).
  - **`podAffinity` co-location with a victim** — `requiredDuringSchedulingIgnoredDuringExecution` matching a high-value workload's labels (`app: database`) forces the attacker pod onto the same node → node-local side channels, shared-volume/token theft, IMDS.
  - **Anti-affinity / topology-spread as DoS** — over-constrained `requiredDuringScheduling` anti-affinity leaves legitimate pods `Pending` (resource denial).
  - **Enabling RBAC** — `pods: create`/`patch` lets a subject inject `nodeName`/`tolerations`/`affinity`; `nodes: patch`/`update` (or a compromised kubelet via `nodes/proxy`) lets an attacker **relabel a node** to satisfy a victim's `nodeSelector`/affinity and attract its pods. **SAFE**: enforce the **NodeRestriction** admission plugin (blocks kubelet self-labeling of `node-restriction.kubernetes.io/*`) plus a ValidatingAdmissionPolicy/OPA/Kyverno rule that forbids user workloads from setting `nodeName` or control-plane `tolerations`; reserve sensitive nodes with taints **and** admission-enforced isolation (taints alone are bypassable by tolerations).

## Safe Patterns

**Restricted pod securityContext** — non-root, read-only root FS, drop all caps, no privilege escalation:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  seccompProfile:
    type: RuntimeDefault
containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
```

**Avoid host integrations** — prefer PVCs and standard pod networking; if `hostPath` is required, read-only and minimal path:

```yaml
volumes:
  - name: data
    persistentVolumeClaim:
      claimName: app-data
# If hostPath unavoidable:
volumeMounts:
  - name: sock
    mountPath: /var/run/sock
    readOnly: true
```

**Least-privilege RBAC** — namespace-scoped Role, explicit verbs, no wildcards:

```yaml
kind: Role
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["app-config"]
    verbs: ["get"]
```

**Secrets as mounted volumes** — not env vars; external secret operator or sealed secrets in Git:

```yaml
volumes:
  - name: db-creds
    secret:
      secretName: db-credentials
      defaultMode: 0400
volumeMounts:
  - name: db-creds
    mountPath: /etc/secrets
    readOnly: true
```

**Default-deny NetworkPolicy** with explicit allow rules:

```yaml
kind: NetworkPolicy
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        - podSelector:
            matchLabels:
              role: frontend
      ports:
        - protocol: TCP
          port: 8080
```

**Disable SA token automount** when API access is not needed:

```yaml
automountServiceAccountToken: false
```

**Resource requests and limits** on every container:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 512Mi
```

**Pod Security Admission** — enforce restricted profile at namespace level:

```yaml
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

**Dashboard / kubelet** — ClusterIP or ingress with SSO; kubelet `--authentication-token-webhook=true` and `--read-only-port=0`; never expose 10255.

## Vulnerable vs Secure Examples

**VULN — privileged + hostPath**:

```yaml
containers:
  - name: app
    securityContext:
      privileged: true
    volumeMounts:
      - name: docker
        mountPath: /var/run/docker.sock
volumes:
  - name: docker
    hostPath:
      path: /var/run/docker.sock
```

**VULN — cluster-admin binding**:

```yaml
kind: ClusterRoleBinding
subjects:
  - kind: ServiceAccount
    name: web-app
    namespace: production
roleRef:
  kind: ClusterRole
  name: cluster-admin
```

**VULN — secret in env**:

```yaml
env:
  - name: DB_PASSWORD
    value: "prod-super-secret-password"
```

**VULN — no limits**:

```yaml
containers:
  - name: api
    image: api:1.2.3
    # resources: absent
```

**SAFE — hardened deployment snippet** (combined):

```yaml
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: api
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      resources:
        requests:
          cpu: 100m
          memory: 128Mi
        limits:
          cpu: 500m
          memory: 512Mi
```

## Common False Alarms

- **kube-system / platform namespaces** — CNI, DNS, metrics-server, and node exporters legitimately use host mounts or elevated caps; confirm namespace and upstream chart intent.
- **Init containers** — short-lived `runAsUser: 0` init that chowns a volume before main container runs as non-root may be acceptable with documented pattern.
- **Helm subcharts** — templated `securityContext` defaults in parent values; follow `$`-reference to values.yaml before flagging absent fields in template stub.
- **NetworkPolicy in separate repo** — cluster-level policy repo not visible in app manifest tree; note coverage gap, not confirmed missing policy.
- **SealedSecrets / ExternalSecrets** — encrypted or referenced secrets in Git are not plaintext commits.
- **Resource limits on Jobs** — batch Jobs sometimes omit limits when cluster ResourceQuota enforces caps namespace-wide.
- **Read-only kubelet 10255** — deprecated and bad practice, but lower severity than authenticated 10250 exposed with weak auth; avoid duplicate findings for same Service.
- **Pod Security `privileged` profile** — explicitly labeled system namespaces using `enforce: privileged` by design for infrastructure agents.
