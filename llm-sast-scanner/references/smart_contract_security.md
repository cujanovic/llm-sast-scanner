---
name: smart_contract_security
description: Solidity/EVM smart-contract vulnerability detection — reentrancy, access control, unsafe low-level calls, integer over/underflow, oracle/MEV, proxy-upgrade hazards, and ERC-20/721/1155 pitfalls
---

# Smart Contract Security (Solidity / EVM)

Smart contracts execute on-chain with publicly readable bytecode, immutable deployed logic, and direct custody of value. A single reachable flaw is often irreversibly exploitable for direct financial loss. Static analysis targets value transfers, external calls, privileged state changes, and arithmetic on token amounts.

The core pattern: *attacker-influenced input or an untrusted external contract reaches a state mutation, value transfer, or privileged operation without the ordering, access control, validation, or arithmetic safety that EVM execution requires.*

## What It Is (and Is Not)

### What it IS
- Solidity/Vyper/Yul contracts (`.sol`, `.vy`) holding value or authority on an EVM chain.
- Logic where the **checks-effects-interactions** ordering, access modifiers, low-level call handling, or arithmetic safety is missing or incorrect.
- Protocol-level economic flaws (oracle manipulation, MEV/front-running, slippage) expressed in contract code.

### What it is NOT
- Off-chain web/backend code that merely *calls* a contract — that is ordinary web/API analysis (`ssrf.md`, `api_security.md`).
- Frontend wallet integration bugs (use `xss.md`, `default_credentials.md` for leaked keys/RPC secrets).
- Gas *optimization* or style issues with no security impact.

## Where to Look
- Contract sources: `*.sol`, `*.vy`, `contracts/`, `src/`, Foundry/Hardhat/Truffle projects
- Functions marked `payable`, `external`, `public`; anything calling `.call{value:}`, `.transfer`, `.send`, `delegatecall`, `selfdestruct`
- Upgradeable patterns: proxy/implementation pairs, `initializer`, `__gap`, UUPS/Transparent proxies
- Token standards: `transfer`/`transferFrom`/`approve`, `_mint`, `safeTransferFrom`, ERC-20/721/1155 hooks
- Price-dependent logic: AMM swaps, lending/liquidation, anything reading a price/balance from another contract

## Recon Indicators

Flag where an external call, value transfer, or privileged write occurs without the matching guard. Phase-2 reasoning confirms exploitability.

| Concern | Grep targets |
|---|---|
| External call before state update | `.call{value:`, `.call(`, `.delegatecall(`, `.transfer(`, `.send(` preceding `balances[...] =`, `-=`, state writes |
| `tx.origin` auth | `tx.origin ==`, `require(tx.origin` |
| Unchecked low-level return | `.call(`/`.send(` whose `bool` return is not checked or `require`d |
| Dangerous delegatecall | `delegatecall(`, especially with non-constant target or in constructor |
| Self-destruct / ownership loss | `selfdestruct(`, `suicide(`, `renounceOwnership(` |
| Unsafe arithmetic | `unchecked {`, `+`/`-`/`*` on token amounts in `pragma <0.8.0` without SafeMath |
| Weak randomness | `block.timestamp`, `block.number`, `blockhash(`, `block.prevrandao`/`difficulty` used for entropy/selection |
| Price/oracle trust | `getReserves(`, `balanceOf(` used as price, single-source `latestAnswer(` without staleness/round checks |
| Proxy/upgrade | `delegatecall` in proxy, missing `initializer`/`_disableInitializers()`, storage layout edits |
| Missing access control | `external`/`public` state-changing fns with no `onlyOwner`/role modifier |

**Skip (lower risk)** — `view`/`pure` functions with no state change or value flow; constant-target `delegatecall` to a trusted library; arithmetic under Solidity ≥0.8 default checked math (unless inside `unchecked {}`).

## Vulnerability Patterns

### Reentrancy
- **VULN**: external call before state update — `(_bool,) = msg.sender.call{value: amount}(""); balances[msg.sender] -= amount;`
- **SAFE**: checks-effects-interactions — update state first, then call; or a `nonReentrant` guard; or pull-payment pattern.

### Access control
- **VULN**: `function setOwner(address o) external { owner = o; }` — no modifier; anyone takes ownership.
- **VULN**: `require(tx.origin == owner)` — phishable; use `msg.sender`.
- **SAFE**: `function setOwner(address o) external onlyOwner { ... }`; two-step ownership transfer; role checks via `AccessControl`.

### Unsafe low-level calls
- **VULN**: `recipient.call{value: amt}("");` with the returned `bool` ignored — silent failure.
- **VULN**: `target.delegatecall(data)` where `target`/`data` is attacker-influenced — arbitrary code in caller's storage context.
- **SAFE**: `(bool ok,) = recipient.call{value: amt}(""); require(ok, "transfer failed");`; delegatecall only to a fixed, audited library.

### Integer overflow / underflow / precision
- **VULN**: `pragma solidity ^0.7.0;` with `balances[to] += amt;` and no SafeMath; or `unchecked { totalSupply -= burn; }` enabling underflow.
- **VULN**: division before multiplication causing precision loss in fee/interest math.
- **SAFE**: Solidity ≥0.8 checked arithmetic; SafeMath on older compilers; multiply-before-divide.

### Denial of service
- **VULN**: unbounded `for` loop over a user-growable array in a state-changing function; single failed `transfer` in a loop blocking all payouts.
- **SAFE**: pull-payment withdrawals; bounded iteration; isolate external-call failures.

### Front-running / MEV
- **VULN**: AMM swap or auction bid with no `minAmountOut`/slippage bound or `deadline`; sensitive action whose ordering is profitable to manipulate.
- **SAFE**: slippage/`minOut` parameters, deadlines, commit-reveal schemes.

### Insecure randomness
- **VULN**: `uint winner = uint(keccak256(abi.encodePacked(block.timestamp, block.prevrandao))) % players;` — miner/validator-influenceable.
- **SAFE**: VRF/commit-reveal off-chain-seeded randomness.

### Oracle manipulation
- **VULN**: spot price from a single DEX pool (`getReserves`) used directly for valuation/liquidation.
- **VULN**: oracle read without staleness/round/min-answer checks.
- **SAFE**: TWAP or multi-source oracle; validate `updatedAt`, `answeredInRound`, and bounds.

### Proxy / upgrade hazards
- **VULN**: implementation missing `_disableInitializers()`; reinitialization possible; storage layout reordered between versions; `delegatecall` to implementation from constructor.
- **SAFE**: `initializer`/`reinitializer` guards, append-only storage with `__gap`, upgrade authorization.

### Token-standard pitfalls
- **VULN**: ERC-20 `approve` race; missing return-value check on non-standard tokens; ERC-721/1155 `safeTransfer` reentrancy via `onERC*Received`; missing events.
- **SAFE**: `SafeERC20` wrappers, increase/decrease-allowance, reentrancy-aware hooks.

### Self-destruct / privileged teardown
- **VULN**: reachable `selfdestruct(attacker)`; `renounceOwnership()` leaving no admin; force-fed ether assumptions.
- **SAFE**: remove/guard `selfdestruct`; deliberate, access-controlled lifecycle.

## Source → Sink

- **Sources**: `msg.sender`, `msg.value`, function parameters, external contract return values, `block.*` (for randomness misuse), cross-contract `balanceOf`/price reads.
- **Sinks**: value transfers (`call{value}`, `transfer`, `send`), `delegatecall`, state-variable writes governing balances/ownership/accounting, `selfdestruct`, mint/burn.
- **Sanitizers/barriers**: `nonReentrant`, access modifiers (`onlyOwner`/role), checks-effects-interactions ordering, checked arithmetic/SafeMath, slippage/deadline bounds, oracle staleness checks, `SafeERC20`.

## Severity & Triage
- **Critical**: direct theft/loss of funds (reentrancy drain, arbitrary `delegatecall`, missing access control on value/ownership, mint authority).
- **High**: oracle manipulation, proxy reinit/storage collision, integer under/overflow affecting balances.
- **Medium**: front-running without bounds, DoS via unbounded loops, weak randomness in value-bearing selection.
- Confirm the vulnerable function is externally reachable and the contract custodies value or authority before rating Critical.

## Common False Alarms
- Reentrancy flagged on a function that already follows checks-effects-interactions or carries `nonReentrant`.
- Arithmetic "overflow" under Solidity ≥0.8 outside any `unchecked {}` block (compiler reverts).
- `delegatecall` to a hardcoded, audited library address (e.g., a known math lib) — not attacker-controlled.
- `block.timestamp` used only for coarse time windows (e.g., deadlines), not as randomness or for fund selection.
- `view`/`pure` helpers with no state or value effect.
- Test/mock contracts under `test/`, `mocks/`, `script/` not deployed to production.

## Dynamic Test / PoC

Confirm on a fork or local chain (Foundry/Hardhat) — never on mainnet.

**Reentrancy (Foundry attacker contract):**
```solidity
// Attacker fallback re-enters withdraw() before balance is zeroed
receive() external payable { if (address(target).balance >= amt) target.withdraw(); }
// Expect: drained balance > attacker's deposit
```

**Access control:**
```bash
# Call a privileged setter from a non-owner account on a fork
cast send $CONTRACT "setOwner(address)" $ATTACKER --private-key $NON_OWNER_KEY
# Expect: tx succeeds and ownership changes => missing access control
```

**Oracle/price manipulation:** simulate a large swap to move a single-pool spot price, then call the dependent function in the same transaction; expect mispriced valuation/liquidation. Restrict to a TWAP/multi-source oracle in remediation — PoC confirms manipulability, not safe design.
