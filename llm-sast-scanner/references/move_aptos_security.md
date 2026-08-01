---
name: move_aptos_security
version: "0.2"
description: Move / Aptos / Sui module security — capability ability misuse (copy/store/drop on admin caps), by-value capability consumption, unconstrained phantom type parameters, Sui public(package)+entry visibility bypass, single-attester / CCTP quorum SPOF, and missing signer gates on privileged entry functions. Load when Move modules are present (*.move, Move.toml, aptos / sui Move frameworks).
---

# Move / Aptos / Sui Smart-Contract Security

Move's safety model is **resource/capability abilities**, not Solidity modifiers. Privileged authority is often an owned struct (`AdminCap`, `TreasuryCap`, mint ticket). Whether that capability can be **copied**, **stored**, **dropped**, or accepted **by value** without a signer check decides whether authority stays unique.

Core pattern: *a capability type that should be unique/non-transferable is declared with `copy` (and often `store`/`drop`), or a public entry accepts that capability by value / forges a phantom-typed ticket without verifying attestations — so authority is duplicated or forged.*

Distinct from EVM (`smart_contract_security.md`) and Solana (`solana_smart_contract_security.md`).

## What It Is (and Is Not)

### What it IS
- Move modules on Aptos, Sui, or other Move VMs (`module addr::name`, `Move.toml`, `has key|store|copy|drop`)
- Capability ability misuse, by-value cap parameters, unconstrained `phantom` type params on mint/ticket types, Sui `public(package) entry` exposing package-only helpers, bridge/CCTP attestation threshold = 1, public entry functions that mint/burn/configure without `&signer` + role proof

### What it is NOT
- Solidity/EVM reentrancy/delegatecall → `smart_contract_security.md`
- Solana account-cosplay / CPI → `solana_smart_contract_security.md`
- Off-chain indexer/API bugs → web/API classes

## Where to Look

- Capability structs: `struct AdminCap has …`, `TreasuryCap`, `MintCap`, `OwnerCap`, witness types
- Entry / public functions taking `Cap` **by value** (`cap: AdminCap`) vs `&AdminCap` / `&signer`
- `phantom` type parameters on tickets/receipts without tying `CoinType` to an allowlist
- Bridge / CCTP / attester config: `num_required_attestations`, `threshold`, `attesters` vector length
- `borrow_global` / `borrow_global_mut` gated only by "exists at address" without unique capability

## Recon Indicators

| Signal | Grep / structural targets |
|--------|----------------------------|
| Move present | `*.move`, `Move.toml`, `module `, `aptos_framework`, `sui::`, `move_to(` |
| Dangerous abilities on authority | `struct .*Cap has` containing `copy` (often with `store`/`drop`) |
| By-value cap | `fun .*\(.*Cap[,)]` taking owned cap, not reference |
| Unconstrained phantom | `struct .*Ticket<phantom` / `fun forge_.*<CoinType>` public with no type constraint |
| Attestation SPOF | `num_required_attestations:\s*1`, `threshold:\s*1` with single attester |
| Sui package+entry leak | `public(package) entry fun` on privileged helpers |
| Global mut borrow | `borrow_global_mut<` without capability witness |

```bash
rg -n "struct \w+Cap has|has key, store, copy|has key, copy" --glob '*.move'
rg -n "phantom |num_required_attestations|threshold:\s*1" --glob '*.move'
rg -n "public fun .*\(.*Cap|public\(package\)\s+entry" --glob '*.move'
```

## Vulnerability Patterns

### Capability `copy` (authority duplication)

- **VULN**: `struct AdminCap has key, store, copy` (or `copy, drop`) — any holder can duplicate the capability and satisfy later by-value checks; uniqueness of admin authority is broken even if `init` publishes only one.
- **SAFE**: admin/treasury caps use `key` only (or `key, store` without `copy`); transfer via explicit controlled functions; prefer hot-potato / one-time witness patterns that cannot be copied.

### By-value capability parameter looks like a gate (but isn't unique)

- **VULN**: `public fun authorize_payout(cap: AdminCap, …)` — appears capability-gated, but with `copy` on `AdminCap` an attacker who obtained one copy (or any path that yields a duplicate) passes the check; consuming `cap` by destructure does not restore uniqueness.
- **SAFE**: take `&AdminCap` or `&signer` + prove unique cap at a fixed address; never `copy` on authority types; audit every `public`/`public(friend)` that accepts caps by value.

### Unconstrained phantom / forgeable ticket

- **VULN**: `public fun forge_ticket<CoinType>(…): MintTicket<CoinType>` with no signer/attester check and no constraint binding `CoinType` — attacker forges tickets for arbitrary assets; `execute_mint` trusts the ticket.
- **SAFE**: ticket mint restricted to attested paths; type constraints / witness types; verify signatures against `threshold` before mint.

### Single-attester / CCTP quorum SPOF

- **VULN**: `num_required_attestations: 1` or `threshold: 1` with one attester address — compromise/coercion of that key mints/burns cross-chain.
- **SAFE**: threshold ≥ 2 (or policy minimum); rotate attesters; never hardcode 1 in production init.

### Sui `public(package)` + `entry` (visibility bypass)

- **VULN**: `public(package) entry fun …` on a privileged helper (fee/admin/config). `public(package)` alone restricts callers to the same package, but adding **`entry`** makes the function invocable as a **transaction entry point** by anyone who can build a PTB/tx — package visibility does not block entry dispatch. Distinct from Cap `copy` / by-value Cap (those are ability bugs); here the Cap check may be correct yet the function was never meant to be externally callable.
- **Do not CLOSE** because staff say “it still requires AdminCap” if the Cap is obtainable by more parties than the intended package-internal call graph, or if the finding is specifically unintended external entry exposure of a package-scoped API.
- **SAFE**: drop `entry` from package-only helpers (`public(package) fun` without `entry`); keep `entry` only on intentionally public entrypoints; gate privileged entries with unique Cap + signer proofs as required.

## Severity

| Pattern | Typical severity |
|---------|------------------|
| `copy` on Admin/Treasury/Mint cap + by-value privileged entry | **Critical** / **High** |
| Public forge ticket / unconstrained phantom mint | **Critical** / **High** |
| Attestation threshold = 1 on bridge mint | **High** |
| Sui `public(package) entry` on privileged helper | **High** / **Medium** (scope to who can satisfy Cap) |

## Common False Alarms

- `copy` on **non-authority** data (events, pure config snapshots) — not a finding
- Test-only modules under `#[test_only]` — skip unless shipped
- Cap taken by value in a **private** function after an on-chain unique borrow that cannot be copied — still flag the type ability if `copy` is present on the struct

## Remediation

1. Remove `copy` (and usually `drop`) from privilege capabilities; keep `key` (± controlled `store`).
2. Prefer `&Cap` / signer+address proofs over by-value `Cap` for privileged ops.
3. Bind phantom types; require multi-attester quorum ≥ policy minimum for bridges.
