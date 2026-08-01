---
name: tron_smart_contract_security
version: "0.1"
description: TRON TVM / Solidity-on-TRON security — block.number used as wall-clock or vesting time, TRON transfer/Stake-2.0 silent-failure vs Ethereum revert semantics, and TRON-specific timing assumptions. Load when TRON deployment signals appear (TRON addresses T…, tronbox.js, tronweb, "*.tron", network mainnet/shasta/nile) or when reviewing Solidity intended for TRON.
---

# TRON Smart-Contract Security

TRON runs a TVM that accepts Solidity-like contracts, but **runtime semantics diverge from Ethereum**. Rules that assume EVM `.transfer` reverts, or that `block.number` is only a weak-randomness signal, **miss TRON-specific fund-loss and unlock bugs**.

Use together with `smart_contract_security.md` (shared Solidity patterns). This reference covers **TRON deltas** only.

## What It Is (and Is Not)

### What it IS
- Contracts deployed to TRON mainnet / Shasta / Nile (TronBox, TronWeb, `T…` addresses)
- Vesting/timelock/unlock logic keyed off `block.number` (or treating TRON block cadence as wall clock)
- `.transfer` / low-level value send assuming Ethereum revert-on-failure

### What it is NOT
- Generic EVM reentrancy/oracle on Ethereum-only code → `smart_contract_security.md` alone
- Move/Aptos → `move_aptos_security.md`
- Off-chain TronWeb key leakage → `hardcoded_secrets.md`

## Gate / When to Load

Load when any of:
- `tronbox.js`, `tronweb`, `@tronprotocol`, network names `shasta`/`nile`/`mainnet` TRON
- Comments/docs saying TRON / TVM / Stake 2.0
- Address literals matching TRON base58 (`T` + 33 chars) in deploy scripts
- Fixtures/modules under explicit TRON paths

When the same `.sol` is multi-chain, apply TRON rules to TRON deployment paths and shared rules from `smart_contract_security.md` always.

## Vulnerability Patterns

### `block.number` as vesting / unlock clock

- **VULN**: `unlockBlock[user] = block.number + N` then `require(block.number >= unlockBlock[user])` — treats block height as elapsed wall time. TRON block production rate and finality assumptions differ from Ethereum; unlock duration is manipulable/mis-estimated vs intended calendar time. Same class on any chain when `block.number` (not timestamp + documented duration model) gates value release — see also `smart_contract_security.md` **Block height as wall-clock**.
- **SAFE**: use `block.timestamp` with explicit duration in seconds **and** document TRON timestamp trust assumptions; or off-chain attested time; avoid encoding "days locked" as raw block deltas without a chain-specific rate model.

### `.transfer` / value send silent failure (TRON / Stake 2.0)

- **VULN**: `payable(msg.sender).transfer(amt)` (or equivalent) after zeroing balances, assuming failure reverts like Ethereum. On TRON, certain energy/Stake-2.0 / transfer paths can **fail without reverting the outer transaction** the way auditors expect on ETH — funds marked spent in storage while the recipient never received them (or opposite accounting drift).
- **SAFE**: check return values; prefer patterns that revert on failure explicitly; test value transfer on TRON testnet; do not assume EVM `.transfer` 2300-gas/revert folklore holds on TVM.

```solidity
// VULN on TRON if failure is non-reverting / energy-related
balance[msg.sender] = 0;
payable(msg.sender).transfer(amt);

// Prefer explicit success check / pull payment
(bool ok, ) = payable(msg.sender).call{value: amt}("");
require(ok, "pay failed");
```

## Recon

```bash
rg -n "block\.number\s*[+\-]|unlockBlock|vesting|cliff" --glob '*.sol'
rg -n "\.transfer\(|Stake 2\.0|tronweb|tronbox" --glob '*.{sol,js,ts}'
rg -n "shasta|nile|tronprotocol" --glob '*.{js,ts,json,md}'
```

## Severity

| Pattern | Typical severity |
|---------|------------------|
| Vesting/unlock via `block.number` controlling withdrawable value | **High** / **Medium** |
| Balance zeroed + `.transfer` under TRON silent-fail risk | **High** / **Medium** |

## Common False Alarms

- `block.number` used only as a unique non-secret counter / event id — not a time lock
- Ethereum-only deployment with no TRON signals — do not apply Stake 2.0 silent-fail; still apply shared `smart_contract_security.md` for ignored `.call` returns

## Remediation

1. Replace block-delta locks with timestamp-based durations (or chain-aware converters).
2. On TRON, assert payment success; prefer pull-over-push; test energy/ Stake edge cases on Shasta/Nile.
