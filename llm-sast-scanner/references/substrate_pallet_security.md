---
name: substrate_pallet_security
version: "0.1"
description: Substrate / Polkadot FRAME pallet and XCM security — CallFilter=Everything, unsigned extrinsics, permissive XCM Transact origins, origin/role checks that only ensure_signed. Load when Substrate/FRAME signals appear (frame_support, construct_runtime!, pallet_*, xcm_executor, Cumulus, polkadot-sdk).
---

# Substrate / Polkadot FRAME & XCM Security

Substrate runtimes are **FRAME pallets** (Rust), not EVM contracts. Cross-consensus messaging (**XCM**) and **unsigned extrinsics** create fund/authority paths that Solidity/Solana/Move refs do not cover. Mobile “Substrate” (jailbreak) in Android/iOS refs is unrelated.

Core pattern: *an XCM or extrinsic path executes privileged pallet calls, or accepts free/unauthenticated dispatch, because filters/origins are too broad.*

## What It Is (and Is Not)

### What it IS
- Runtime/pallet Rust: `frame_support`, `construct_runtime!`, `pallet_*`, `Config` types, `#[pallet::call]`
- XCM executor config: `CallFilter`, `Transact`, barrier/origin converters, `SafeCallFilter`
- `ValidateUnsigned` / `ensure_none` unsigned extrinsic paths

### What it is NOT
- Solidity/EVM → `smart_contract_security.md`
- Solana programs → `solana_smart_contract_security.md`
- Move → `move_aptos_security.md`
- Generic Rust `unsafe` → `memory_safety_c_cpp.md`
- Mobile jailbreak “substrate” strings → `android_security.md` / `ios_security.md`

## Gate / When to Load

Load when any of:
- `Cargo.toml` deps: `frame-support`, `frame-system`, `xcm-executor`, `polkadot-sdk`, `cumulus-*`
- Sources with `construct_runtime!`, `#[frame_support::pallet]`, `type CallFilter`, `XcmConfig`
- Runtime/node repos under `runtime/`, `pallets/`

## Recon Indicators

| Signal | Grep targets |
|--------|----------------|
| Permissive XCM filter | `CallFilter = Everything`, `type CallFilter` |
| XCM Transact | `Transact {`, `SafeCallFilter` |
| Unsigned path | `ensure_none(`, `ValidateUnsigned`, `#[pallet::validate_unsigned]` |
| Origin-only-signed | `ensure_signed(origin)` without role/membership check on privileged calls |

```bash
rg -n "CallFilter\s*=\s*Everything|SafeCallFilter|ensure_none|ValidateUnsigned|construct_runtime!" --glob '*.rs'
```

## Vulnerability Patterns

### XCM `CallFilter = Everything`

- **VULN**: XCM executor config sets `type CallFilter = Everything` (or an equivalently broad filter) so `Transact` from a reachable origin can dispatch **any** runtime call — governance, balances, staking, bridges. **SAFE**: restrictive `SafeCallFilter` / allowlisted call enums; only expose the specific pallet calls required; validate XCM origin (sovereign/sibling) before Transact.
- **Do not CLOSE** because staff say “XCM is infrastructure.” Over-broad filters are a Critical/High confused-deputy class on chain runtimes.

### Unsigned extrinsic without strong `ValidateUnsigned`

- **VULN**: dispatchables using `ensure_none(origin)?` (or unsigned submit paths) with missing/weak `ValidateUnsigned` — no fee, floodable, or forgeable under weak validation. **SAFE**: implement `ValidateUnsigned` with cryptographic/proof checks and rate limits; prefer signed+fee paths for user actions.

### Origin checks that only `ensure_signed`

- **VULN**: privileged pallet calls that `ensure_signed(origin)?` (or match on CircuitRole but accept any signed account) without verifying role membership / `EnsureOrigin` for the required privilege. **SAFE**: `EnsureOrigin` / role storage / `T::AdminOrigin::ensure_origin(origin)`.

## Severity

| Pattern | Typical severity |
|---------|------------------|
| `CallFilter = Everything` with reachable Transact | **Critical** / **High** |
| Unsigned extrinsic weakly validated | **High** / **Medium** (DoS → Critical if consensus halt) |
| Privileged call with only `ensure_signed` | **High** |

## Common False Alarms

- `CallFilter` already a narrow `SafeCallFilter` listing only intended calls
- Unsigned validation used solely for inherent/system digests with tight `ValidateUnsigned`
- Test runtimes under `mock.rs` / `#[cfg(test)]` not shipped

## Cross-References

- `smart_contract_security.md` — EVM only
- `memory_safety_c_cpp.md` — Rust unsafe / integer
- `solana_smart_contract_security.md` — different account model
