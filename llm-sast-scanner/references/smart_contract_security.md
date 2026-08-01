---
name: smart_contract_security
version: "0.10"
description: Solidity/EVM smart-contract vulnerability detection — reentrancy (incl. EIP-1153 sticky transient locks), access control (incl. hollow modifiers / EIP-7702 EOA-gate failure), unsafe low-level calls, .transfer/.send 2300-gas stipend pitfalls, emit-after-external-call, confused-deputy custody calls, integer/oracle/MEV (incl. L2 sequencer uptime), cross-chain message auth (lzCompose / Wormhole / Across), block-height vesting, return-bomb DoS, proxy/ERC pitfalls, fee-on-transfer/decimal mismatch, native/ERC20 branch asymmetry (msg.value vs amount), vault deposit/withdraw rounding direction, ZK verifier soundness
---

# Smart Contract Security (Solidity / EVM)

Smart contracts execute on-chain with publicly readable bytecode, immutable deployed logic, and direct custody of value. A single reachable flaw is often irreversibly exploitable for direct financial loss. Static analysis targets value transfers, external calls, privileged state changes, and arithmetic on token amounts.

The core pattern: *attacker-influenced input or an untrusted external contract reaches a state mutation, value transfer, or privileged operation without the ordering, access control, validation, or arithmetic safety that EVM execution requires.*

## What It Is (and Is Not)

### What it IS
- Solidity/Vyper/Yul contracts (`.sol`, `.vy`) holding value or authority on an EVM chain.
- Logic where the **checks-effects-interactions** ordering, access modifiers, low-level call handling, or arithmetic safety is missing or incorrect.
- Protocol-level economic flaws (oracle manipulation, MEV/front-running, slippage) expressed in contract code.
- **On-chain ZK proof verifiers** (Groth16/PLONK/Halo2/STARK verifier contracts, rollup processors) and — when circuit source is in scope — the **circuits** they verify (`.circom`, Halo2/`.rs`, Noir `.nr`, gnark/Go, Cairo). ZK soundness bugs are *not* EVM-execution bugs: a false statement verifies, or a value that drives asset effects is never bound to the proven statement.

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
- ZK verifier / rollup contracts: `verifyProof`/`verify(`, `*Verifier.sol`, `publicInputs`/`publicInputsHash`, pairing checks (`ecPairing`, precompile `0x08`), G1/G2 limb decoding; and (when in scope) circuit sources — `*.circom`, Noir `*.nr`, Halo2 `assign_advice`/`copy_advice`, gnark `frontend.Circuit`/`api.AssertIsEqual`

## Recon Indicators

Flag where an external call, value transfer, or privileged write occurs without the matching guard. Phase-2 reasoning confirms exploitability.

| Concern | Grep targets |
|---|---|
| External call before state update | `.call{value:`, `.call(`, `.delegatecall(`, `.transfer(`, `.send(` preceding `balances[...] =`, `-=`, state writes |
| EIP-1153 transient lock | `tstore(`, `tload(`, `TSTORE`/`TLOAD` without matching clear; `transient` storage libs |
| `.transfer`/`.send` stipend DoS | `payable(...).transfer(`, `.send(` as ETH payout (prefer checked `.call{value:}`) |
| L2 sequencer oracle | `latestRoundData` on L2 without `SEQUENCER_UPTIME` / sequencer feed / grace period |
| Hollow access modifier | `modifier onlyOwner` / role modifiers whose body lacks `require`/`revert` |
| Emit state after external call | `emit ` after `.call(`/external call with mutable state args |
| `tx.origin` auth | `tx.origin ==`, `require(tx.origin` |
| EIP-7702 / fake-EOA gate | `msg.sender.code.length == 0`, `extcodesize(`, `tx.origin == msg.sender` used as anti-contract / "EOA only" security boundary |
| Cross-chain compose/receive auth | `lzCompose(`, `lzReceive(`, `wormholeRelayer`, `handleV3AcrossMessage`, `messageFee(` without endpoint/relayer/`from` binding |
| Unchecked low-level return | `.call(`/`.send(`/`.staticcall(` whose `bool` return is not checked or `require`d |
| Return-bomb / unbounded returndata (griefing DoS) | low-level `.call(`/`.delegatecall(`/`.staticcall(` to an untrusted/user-supplied target that copies the whole returndata (`(bool, bytes memory …)` capture, or `returndatacopy(_, 0, returndatasize())`), esp. inside a liquidation/settlement/payout loop, with no `ExcessivelySafeCall`/bounded returndata/gas cap |
| Dangerous delegatecall | `delegatecall(`, especially with non-constant target or in constructor |
| Self-destruct / ownership loss | `selfdestruct(`, `suicide(`, `renounceOwnership(` |
| Unsafe arithmetic | `unchecked {`, `+`/`-`/`*` on token amounts in `pragma <0.8.0` without SafeMath |
| Weak randomness | `block.timestamp`, `block.number`, `blockhash(`, `block.prevrandao`/`difficulty` used for entropy/selection |
| Price/oracle trust | `getReserves(`, `balanceOf(` used as price, single-source `latestAnswer(` without staleness/round checks |
| Proxy/upgrade | `delegatecall` in proxy, missing `initializer`/`_disableInitializers()`, storage layout edits |
| Uninitialized storage pointer / data location | local `struct`/array declared without explicit `memory`/`storage` (esp. `pragma <0.5.0`); data-location mismatch aliasing low storage slots |
| Incorrect visibility / mutability | state-changing fn left `public`/unspecified where `external`/`internal` intended; missing `view`/`pure`; unnecessary `payable` |
| Missing access control | `external`/`public` state-changing fns with no `onlyOwner`/role modifier |
| Read-only reentrancy | external consumers reading `view` getters (`getRate(`, `getPoolTokens(`, `get_virtual_price(`, LP `getReserves(`) for valuation without a reentrancy lock |
| Transfer-hook reentrancy | `tokensReceived`/`tokensToSend` (ERC-777), `onERC721Received`/`onERC1155Received`, `onTokenTransfer`/`transferAndCall` (ERC-677/1363) reachable before state settles |
| Hash collision | `abi.encodePacked(` with ≥2 dynamic (`string`/`bytes`/array) args feeding `keccak256`/a signature or commitment check |
| Signature malleability / digest domain | raw `ecrecover(` without canonical-`s`/`v`/`address(0)` guard; signature bytes as replay key; signed digest / EIP-712 `DOMAIN_SEPARATOR` omitting `address(this)` / `block.chainid` (cross-deploy / cross-fork replay) |
| ERC-4626 / vault share inflation | share math `assets * totalSupply / totalAssets()` where the rate/`totalAssets()` reads `balanceOf(address(this))`; no virtual-shares offset, locked dead shares, or zero-shares-minted revert |
| Vault mint/burn rounding direction | `deposit`/`mint` and `withdraw`/`redeem` share the same round-down `assets * supply / totalAssets` (or same floor-only `_convertToShares`); burn/asset-out path must round **up** |
| Native / ERC20 dual-path asymmetry | `payable` fn with `_ETH`/`0xEeee…`/`address(0)` sentinel: ERC20 path `transferFrom(amount)` (+ fee) but native path credits `amount` **without** `require(msg.value == amount)` (often skips ERC20 fee too) |
| Fee-on-transfer / rebasing accounting drift | `transferFrom(...)`/`safeTransferFrom(...)` into the contract immediately followed by crediting the **requested `amount`** to accounting (`staked[x] += amount`, `deposits += amount`, `shares = amount * …`, `totalX += amount`) with no `balanceOf(address(this))` before/after **delta** — code trusts the amount asked for, not the amount actually received |
| Confused-deputy arbitrary call | `target.call(data)` / `target.functionCall(data)` / `Address.functionCall(` where **both** `target` and `data` are caller-supplied, inside a contract that holds token/ETH balances or is the spender of users' ERC-20 approvals (routers, aggregators, `multicall`/`execute`, batch relayers, reward-claim helpers) |
| Cross-token decimal mismatch | amounts of two tokens with different `decimals()` (USDC 6, WBTC 8, DAI 18) compared/summed/exchanged as **raw integers** — e.g. `require(collateral[u] >= debt[u])` across an 18-dec and a 6-dec token, a 1:1 swap/wrapper between mismatched-decimal tokens — or value math hardcoding `1e18`/`1e8` scaling (`amount * price / 1e18`) applied to a token whose `decimals()` differs, with no per-token `10**(18-decimals())` normalization |
| ZK: unbound public input | a value that drives transfers/mint/settlement (a loop bound, index, amount, recipient, count) read from calldata/`abi.decode`/`assembly calldataload` **outside** the region folded into `publicInputsHash`/the verified statement |
| ZK: verifier-boundary field/limb decode | G1/G2 coordinate reduced by the **scalar** modulus where the **base** modulus is required (or vice-versa); limb OR-packing (`<< 68`, `<< 136`, `<< 204`) without a per-limb range check; `mulmod`/`addmod` with a mismatched modulus constant |
| ZK: nullifier / spent-marker reuse | a note/proof/voucher consumed without first checking **and** setting a nullifier/`spent[...]` marker |
| ZK: circuit constraint completeness | Circom `<--` (assign, no constraint) where `<==`/`===` is required; Halo2 `assign_advice`/`witness` with no matching `copy_advice`/`constrain_equal` to the trusted source cell; gnark witness never `AssertIsEqual`'d |

**Skip (lower risk)** — `view`/`pure` functions with no state change or value flow; constant-target `delegatecall` to a trusted library; arithmetic under Solidity ≥0.8 default checked math (unless inside `unchecked {}`).

## Vulnerability Patterns

### Reentrancy
- **VULN**: external call before state update — `(_bool,) = msg.sender.call{value: amount}(""); balances[msg.sender] -= amount;`
- **VULN (read-only / view reentrancy)**: a `view` function (e.g. an LP price getter — `getRate()`, `getPoolTokens()`, Curve `get_virtual_price()`) is called by a consumer *during* a reentrant callback, while the pool's internal accounting is mid-update — it returns a stale/inconsistent price even though no state is written in the view. The vulnerable shape is a protocol that trusts another contract's `view` getter for valuation without that getter being reentrancy-protected. **SAFE**: pools expose a reentrancy-locked read (or revert during reentrancy); consumers check the lock / use a manipulation-resistant source.
- **VULN (transfer-hook reentrancy)**: callbacks invoked *before* state settles — ERC-777 `tokensReceived`/`tokensToSend`, ERC-721/1155 `onERC721Received`/`onERC1155Received`, ERC-677/1363 `onTokenTransfer`/`transferAndCall` — let a malicious recipient re-enter mint/transfer/accounting.
- **SAFE**: checks-effects-interactions — update state first, then call; or a `nonReentrant` guard (covering view getters too); or pull-payment pattern.
- **VULN (EIP-1153 sticky transient lock)**: a reentrancy/mutex lock implemented with `tstore`/`tload` (inline assembly or a transient-storage library) that is **set on entry and never cleared** on all exit paths. Transient storage persists for the **entire transaction**, so a second call in the same tx (multicall, flash-loan callback, `this.fn()` batch) always sees the lock and reverts — composability DoS, not a style nit. **Do not CLOSE** because staff say “missing unlock is style” or “TSTORE is just cheaper SSTORE.” Also: do **not** treat `.transfer`/`.send`’s 2300-gas stipend as preventing callback state writes — `TSTORE` costs ~100 gas and fits inside the stipend (Cancun+). **SAFE**: clear the lock on every path (`tstore(LOCK, 0)` in success and revert/cleanup); prefer a storage `nonReentrant` (or OZ) when same-tx re-entry must be allowed after unlock; never rely on the 2300 stipend as a security boundary.
- **VULN (emit mutable state after external call)**: `emit Transfer(amountToTransfer)` (or any event argument sourced from a **mutable state variable**) *after* an external call. A reentrant/malicious callee can mutate that state before the emit, so off-chain indexers/bridges that trust the event log see a **false post-condition** (wrong amount/recipient/status). Distinct from classic fund-drain reentrancy: state may later be "correct" for the contract, but the **event lied**. **SAFE**: snapshot locals before the call (`uint256 amt = amountToTransfer; … call; emit Transfer(amt);`) or emit before the external interaction; never emit post-call values that an untrusted callee can still change.

### Access control
- **VULN**: `function setOwner(address o) external { owner = o; }` — no modifier; anyone takes ownership.
- **VULN**: `require(tx.origin == owner)` — phishable; use `msg.sender`.
- **VULN (hollow modifier)**: a modifier that only **evaluates** an access condition as a discarded expression — `modifier onlyOwner() { owner == msg.sender; _; }` — with **no** `require`/`revert`/`if (!…) revert`. The comparison is a no-op; every caller passes. Looks protected in review, is not. **SAFE**: `require(msg.sender == owner, "…"); _;` (or OpenZeppelin `Ownable` / `AccessControl`).
- **Do not CLOSE** because staff say “harmless style / no-op.” A named `onlyOwner` that does not enforce is **High** missing access control on every gated function.
- **VULN (EIP-7702 / code-size EOA gate)**: treating “no code at `msg.sender`” as proof the caller is an EOA — `require(msg.sender.code.length == 0)`, `extcodesize(msg.sender) == 0`, or `require(tx.origin == msg.sender)` as an anti-contract / bot / callback boundary before claims, mints, or payouts. **EIP-7702** lets an EOA attach temporary delegated code for a transaction, so these checks no longer mean “cannot be a contract / cannot reenter.” **Do not CLOSE** because staff say “standard anti-bot EOA check.” Distinct from classic `tx.origin == owner` phishing: here the bug is **false belief that emptiness of code proves non-delegated EOA**. **SAFE**: do not use code-size / `tx.origin == msg.sender` as a security boundary; use explicit allowlists, signed intents, or protocol-level auth that tolerates smart wallets and 7702 delegation.
- **SAFE**: `function setOwner(address o) external onlyOwner { ... }` with an enforcing modifier; two-step ownership transfer; role checks via `AccessControl`.

### Cross-chain messaging / compose auth
- **VULN (LayerZero compose/receive)**: `lzCompose` / `lzReceive` (or custom compose handlers) that credit, mint, or release value **without** binding `msg.sender` to the expected Endpoint **and** binding `from` (or peer) to the expected OApp/OFT. Anyone can call the handler and forge delivery. **SAFE**: `require(msg.sender == endpoint)`; `require(from == peers[srcEid]` / expected OFT); verify GUID/nonce uniqueness; do not trust calldata alone.
- **VULN (Wormhole / Across-class receive)**: receivers that process `publishMessage` / `handleV3AcrossMessage` / relayer callbacks without `msg.sender == wormholeRelayer` (or Core/SpokePool) and without binding token/amount/message params to the attested payload. **SAFE**: only accept calls from the documented relayer/SpokePool; decode and check payload fields against the verified VAA / Across fill params; replay-protect message IDs.
- Grep: `rg -n "lzCompose|lzReceive|setPeer|wormholeRelayer|handleV3AcrossMessage|messageFee\\(" --glob '*.sol'`

### Unsafe low-level calls
- **VULN**: `recipient.call{value: amt}("");` with the returned `bool` ignored — silent failure.
- **VULN**: `target.delegatecall(data)` where `target`/`data` is attacker-influenced — arbitrary code in caller's storage context.
- **VULN (`.transfer` / `.send` 2300-gas stipend)**: `payable(to).transfer(amt)` / `.send(amt)` forward only **2300 gas**. Recipients that need more gas in `receive`/`fallback` (proxy wallets, multisigs, contracts with logging) cause the transfer to **revert** (or `.send` returns false) — brittle DoS / broken payouts. Solidity ≥0.8 docs recommend **checked `.call{value:}("")`** instead. **Do not CLOSE** because staff say “classic safe APIs.” The stipend is a liability, not a security feature, for modern recipients.
- **SAFE**: `(bool ok,) = recipient.call{value: amt}(""); require(ok, "transfer failed");`; delegatecall only to a fixed, audited library; never recommend `.transfer` as the “safe” alternative to unchecked `.call`.

### Confused deputy — arbitrary external call from a custody/approval contract
- **VULN**: a function forwards a **caller-chosen `(target, data)`** into a low-level `target.call(data)` (or OpenZeppelin `Address.functionCall`) from a contract that either **holds token/ETH balances** or is the **spender of users' ERC-20 approvals**. The call executes with *this contract's* identity as `msg.sender`, so an attacker sets `target = someToken` and `data = transfer(attacker, thisBalance)` (drains custodied funds) or `data = transferFrom(victim, attacker, allowance)` (drains every user who ever approved the contract — the BadgerDAO/Multichain-class approval drain). Common in swap aggregators, routers, `multicall`/`execute`, batch relayers, and reward-claim helpers. Distinct from `delegatecall` (which runs the callee's code in *this* storage) and from the return-bomb DoS. `nonReentrant` and an unchecked-return fix do **not** help — the call "succeeds" exactly as the attacker intends.
- **SAFE**: never forward an arbitrary `(target, data)` from a contract with custody or approvals — **allowlist** the callable `target`s (and ideally the 4-byte selectors); forbid `target` == any token the contract holds or is approved to spend; pull exact funds per call and grant **zero-then-exact** approvals scoped to a specific, vetted router; or route arbitrary calls through an isolated, asset-less executor that holds no balances and no approvals.
- Grep: `rg -n "\.call\(|\.call\{|functionCall\(" --glob '*.sol'` — then check whether `target`/`data` derive from function params and whether the contract ever holds balances or is an approval spender.

### Integer overflow / underflow / precision
- **VULN**: `pragma solidity ^0.7.0;` with `balances[to] += amt;` and no SafeMath; or `unchecked { totalSupply -= burn; }` enabling underflow.
- **VULN**: division before multiplication causing precision loss in fee/interest math.
- **SAFE**: Solidity ≥0.8 checked arithmetic; SafeMath on older compilers; multiply-before-divide.

### Denial of service
- **VULN**: unbounded `for` loop over a user-growable array in a state-changing function; single failed `transfer` in a loop blocking all payouts.
- **VULN (return-bomb / returndata bombing)**: a low-level `.call`/`.delegatecall`/`.staticcall` to an untrusted or user-supplied target that copies the **full returndata** into memory — `(bool ok, bytes memory ret) = target.call(...)` or `returndatacopy(dst, 0, returndatasize())`. The callee controls `returndatasize()`, so a malicious target returns a giant blob → quadratic memory-expansion gas cost → the caller runs out of gas and reverts, *even when the return value is discarded* (`try/catch` still copies it). In a liquidation/settlement/payout loop over user-registered contracts, one crafted position permanently bricks the operation for everyone (griefing DoS → protocol insolvency; escalate above Medium when it blocks liquidations/withdrawals). Invisible to the loop-length / failed-`transfer` seeds above: the loop can be bounded and every call can "succeed".
- **SAFE**: pull-payment withdrawals; bounded iteration; isolate external-call failures; for calls to untrusted targets, cap the returndata copied (LayerZero `ExcessivelySafeCall.excessivelySafeCall` or a bounded `returndatacopy`) and/or forward a fixed gas stipend instead of ABI-decoding attacker-sized returndata.

### Front-running / MEV
- **VULN**: AMM swap or auction bid with no `minAmountOut`/slippage bound or `deadline`; sensitive action whose ordering is profitable to manipulate.
- **SAFE**: slippage/`minOut` parameters, deadlines, commit-reveal schemes.

### Insecure randomness
- **VULN**: `uint winner = uint(keccak256(abi.encodePacked(block.timestamp, block.prevrandao))) % players;` — miner/validator-influenceable.
- **SAFE**: VRF/commit-reveal off-chain-seeded randomness.

### Block height as wall-clock / vesting (not weak randomness)
- **VULN**: unlock/vesting/timelock uses `block.number + N` (or compares `block.number` to a stored unlock height) to mean *elapsed calendar time* before releasing value — e.g. `unlockBlock[u] = block.number + blocks; require(block.number >= unlockBlock[u]);` then withdraw. Distinct from the weak-randomness row (`block.number` as entropy): here the bug is **duration semantics**. Block time varies by chain and can be skewed; encoding "30 days" as a raw block delta silently mis-times unlocks. On TRON/TVM also load `tron_smart_contract_security.md` (cadence + transfer semantics).
- **SAFE**: `block.timestamp` + explicit second durations with documented trust assumptions; or oracle/attested time; do not treat block deltas as portable wall-clock across chains.
- Grep: `rg -n "block\.number\s*[+\-]|unlockBlock|vesting|cliff" --glob '*.sol'`

### Oracle manipulation
- **VULN**: spot price from a single DEX pool (`getReserves`) used directly for valuation/liquidation.
- **VULN**: oracle read without staleness/round/min-answer checks.
- **VULN (L2 sequencer uptime)**: on sequencer-based L2s (Arbitrum, Optimism, Base, …), Chainlink **price** feeds can still look “fresh” (`updatedAt` within heartbeat) during / right after **sequencer downtime**, while L1 markets moved. Liquidation/valuation that only checks price feed staleness — with **no** Chainlink **L2 Sequencer Uptime Feed** (`answer == 0` = up) and **no** post-restart grace (`block.timestamp - startedAt >= GRACE_PERIOD`) — misprices under outage. **Do not CLOSE** because “heartbeat alone is enough on L2.” **SAFE**: query the network’s Sequencer Uptime Feed before consuming prices; require sequencer up + grace period; or use pull oracles (Pyth/Redstone) with embedded freshness proofs. L1-only deployments without a sequencer are out of scope for this row.
- **SAFE**: TWAP or multi-source oracle; validate `updatedAt`, `answeredInRound`, and bounds; on L2 also enforce sequencer uptime + grace as above.

### Proxy / upgrade hazards
- **VULN**: implementation missing `_disableInitializers()`; reinitialization possible; storage layout reordered between versions; `delegatecall` to implementation from constructor.
- **SAFE**: `initializer`/`reinitializer` guards, append-only storage with `__gap`, upgrade authorization.

### Token-standard pitfalls
- **VULN**: ERC-20 `approve` race; missing return-value check on non-standard tokens; ERC-721/1155 `safeTransfer` reentrancy via `onERC*Received`; missing events.
- **VULN (reversed allowance axes)**: delegated operations must read/write `_allowances[owner][spender]`. In `burnFrom(from, amount)` / `transferFrom(from, ...)`, the owner is `from` and the spender is `msg.sender`; checking `_allowances[msg.sender][from]` lets an attacker call standard ERC-20 `approve(spender = victim, amount)` **as the attacker** (so `approve` writes `_allowances[msg.sender][spender]` = `_allowances[attacker][victim]`), then burn/transfer the victim's balance without the victim ever approving the attacker. Both the authorization check and allowance decrement must use the correct `_allowances[from][msg.sender]` slot.
- **VULN (ERC-721 `_mint` vs `_safeMint`)**: public/privileged mint paths that call OpenZeppelin `_mint(to, id)` when `to` **may be a contract**. `_mint` skips `onERC721Received`; tokens can be **permanently locked** in contracts that cannot handle ERC-721. **SAFE**: `_safeMint(to, id)` whenever the recipient is not proven to be an EOA; keep `_mint` only when `to` is known non-contract (and document why).
- **Do not CLOSE** because staff say “`_mint` is cheaper.” Gas savings do not justify locked NFTs when recipient type is unconstrained.
- **SAFE**: `SafeERC20` wrappers, increase/decrease-allowance, reentrancy-aware hooks; `_safeMint` for unconstrained recipients.

### ERC-4626 vault share inflation (first-depositor / donation)
- **VULN**: shares minted as `shares = assets * totalSupply / totalAssets()` where `totalAssets()` reflects the vault's **live token balance** (`asset.balanceOf(address(this))`). The first depositor mints a tiny supply (1 wei → 1 share), then **donates** tokens by transferring them directly to the vault (bypassing `deposit`), inflating the share price. A later victim depositing less than one share's worth mints `0` shares (rounded down) while their tokens stay in the vault — the attacker redeems the victim's deposit. Same shape in any "mint proportional to `balanceOf`" LP/lending accounting. Solidity ≥0.8 checked math does **not** stop this (it is rounding, not overflow), and the multiply-before-divide is correct — so arithmetic rules never fire.
- **SAFE**: OpenZeppelin ERC4626 **virtual shares/assets offset** (decimals offset), permanently locking initial "dead" shares at deployment, tracking assets in an **internal accumulator** rather than `balanceOf`, and/or reverting when `0` shares would be minted or below a minimum first deposit.
- Grep: `rg -n "balanceOf\(address\(this\)\)|totalAssets|convertToShares|previewDeposit|totalSupply\s*==\s*0" --glob '*.sol'`

### Vault deposit/withdraw conversion rounding direction (paired ops)
Distinct from first-depositor inflation: even with a healthy virtual-offset vault, **mint and burn must use opposite rounding**. Deposit/mint that converts assets→shares should **round down** (favor the vault); withdraw/redeem that converts assets→shares-to-burn (or shares→assets-out) must **round up** so the user cannot extract more assets than their shares entitle.

- **VULN**: `withdraw`/`redeem` reuses the same round-down formula (or the same `_convertToShares` / `mulDiv` with default floor) that `deposit`/`mint` uses. Attacker repeatedly withdraws dust amounts, burns too few shares, and drifts `totalAssets` vs `totalSupply` — free assets / insolvency for remaining depositors. Solidity ≥0.8 and multiply-before-divide do **not** fix this (direction is wrong, not overflow). **Do not CLOSE** because “ERC-4626 inflation mitigated” or “checked math.”
- **SAFE**: OpenZeppelin-style `mulDiv` with `Math.Rounding.Up` on burn/asset-out paths; separate `_convertToShares(assets, Rounding.Floor)` vs `_convertToShares(assets, Rounding.Ceil)` (or assets-out round-down / shares-in round-up per ERC-4626); never call the deposit converter unchanged from withdraw.
- Grep: `rg -n "function (deposit|mint|withdraw|redeem)|_convertToShares|convertToShares|mulDiv" --glob '*.sol'` — then confirm withdraw/redeem does **not** share deposit's floor-only path.

### Native / ERC20 dual-path asymmetry (`msg.value` vs `amount`)
Routers/pools that accept either an ERC-20 or native ETH via a sentinel (`0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE`, `address(0)`, `_ETH_ADDRESS_`) often validate the ERC-20 rail and leave the native rail unbound.

- **VULN**: `payable` function branches `if (token != _ETH) { transferFrom(..., amount); … fee … credit(amount - fee); } else { credit(amount); }` with **no** `require(msg.value == amount)` (and often **no** fee deduction from `msg.value`). Attacker sets `amount` high, sends `msg.value = 0` (or underpays), and is credited the full `amount`. Validating the ERC-20 branch alone does **not** make the function SAFE. Distinct from fee-on-transfer drift (which is about delivered ERC-20 shortfall).
- **SAFE**: on the native branch `require(msg.value == amount)` (or credit exactly `msg.value`); apply the same fee/penalty math to both rails; refund dust `msg.value` only when intentional and documented; prefer separate `depositETH()` / `depositToken()` entry points.
- Grep: `rg -n "0x[Ee]{4,}|_ETH|ETH_ADDRESS|address\(0\).*payable|msg\.value" --glob '*.sol'` — then confirm every native credit path binds `msg.value` to the credited amount and mirrors ERC-20 fees.

### Fee-on-transfer / rebasing token accounting drift
- **VULN**: a pool/vault credits the **requested** `amount` after pulling tokens — `token.safeTransferFrom(msg.sender, address(this), amount); staked[msg.sender] += amount; totalStaked += amount;` — but the token is **fee-on-transfer/deflationary** (delivers less than `amount`) or **rebasing** (balance drifts up/down). Internal accounting then exceeds the contract's real balance: the last withdrawers' `transfer`/`safeTransfer` reverts (funds permanently stuck) or an early actor withdraws more than they truly contributed → protocol insolvency. `SafeERC20` does **not** help (the transfer *succeeds*; the shortfall is in the delivered amount), and Solidity ≥0.8 checked math never fires (nothing overflows — the credited number is simply wrong). Same shape whenever a cached principal/`amount` is trusted instead of the measured balance change.
- **SAFE**: credit the **measured delta** — `uint256 pre = token.balanceOf(address(this)); token.safeTransferFrom(msg.sender, address(this), amount); uint256 received = token.balanceOf(address(this)) - pre;` — and account/mint with `received`, not `amount`; or restrict deposits to a vetted allowlist of standard (non-fee, non-rebasing) tokens; for rebasing assets track shares against live `balanceOf`, never a fixed principal.
- Grep: `rg -n "safeTransferFrom|transferFrom" --glob '*.sol' -A3` then confirm the credited value comes from a `balanceOf(address(this))` delta and not directly from the `amount` parameter.

### Cross-token decimal-scale mismatch
- **VULN**: amounts of two **different** tokens are compared, summed, or exchanged as **raw integers** without normalizing to a common precision — or a valuation hardcodes `1e18`/`1e8` scaling and applies it to a token whose `decimals()` differs. Because one whole unit of an 18-dec token = `1e12` raw units of a 6-dec token, a health check / price / 1:1 conversion that treats raw amounts as equal lets an attacker post negligible high-decimal value to pull far more low-decimal value: e.g. `require(collateral[u] >= debt[u])` where `collateral` is 18-dec DAI and `debt` is 6-dec USDC → 1 DAI (`1e18`) "covers" `1e18` USDC base units ≈ **$1,000,000,000,000** of borrow for ~$1 of collateral → under-collateralized borrow / pool drain. Same shape in a vault/oracle that assumes every token is 18-decimals, a 1:1 stable-swap/wrapper between a 6-dec and 18-dec token, or reward math mixing an 18-dec reward token with a 6-dec stake token. This is **not** overflow/precision loss (nothing overflows; multiply-before-divide can be correct — the operands are simply on different scales) and **not** an oracle/depeg bug (it holds when every token is worth exactly $1, so tools that reach for "add a price feed" mis-severity it as a small depeg arb and miss the ~1e6–1e12× drain).
- **SAFE**: normalize every token amount to one internal precision **before** comparing/aggregating/pricing — scale by `10**(18 - IERC20Metadata(token).decimals())`, reading `decimals()` per token (never hardcode `1e18`); for conversions use `amountOut = amountIn * 10**outDec / 10**inDec` (times price); or constrain a market/pair to tokens of identical, known decimals.
- Grep: `rg -n "decimals\(\)|1e18|1e8|1e6|>= *debt|collateral\b|\* *price" --glob '*.sol'` — then confirm amounts of *different* tokens are combined only after per-token `10**(18-decimals())` scaling.

### Hash collision via `abi.encodePacked`
- **VULN**: `keccak256(abi.encodePacked(a, b))` where **two or more** arguments are dynamic types (`string`/`bytes`/dynamic arrays) — packed encoding is ambiguous, so `("ab","c")` and `("a","bc")` hash identically. When the hash gates auth, signatures, or a Merkle/commitment check, an attacker crafts a colliding input to bypass it.
- **SAFE**: use `abi.encode` (each field length-prefixed) for hashing multiple dynamic values, or place fixed-width fields between them / hash each separately.

### Signature malleability & signature-as-key
- **VULN**: verifying with low-level `ecrecover` without rejecting non-canonical `s` (high-`s` half-order) or `v ∉ {27,28}` → a second valid signature exists for the same message; replay/double-spend when a raw signature (or its hash) is used as a uniqueness key / mapping key (`usedSig[sig] = true`). Also treat `ecrecover` returning `address(0)` (invalid sig) as a failure, not a match.
- **SAFE**: OpenZeppelin `ECDSA.recover`/`tryRecover` (enforces canonical `s`, rejects `address(0)`); key replay protection on the **message digest + nonce**, never on the malleable signature bytes.
- **VULN (digest / domain not bound to contract or chain)**: off-chain ECDSA / EIP-712 / permit digest hashes only business fields (`to`, amounts, ids) — **omits `address(this)` and/or `block.chainid`** (or EIP-712 domain typehash lacks `address verifyingContract` / `uint256 chainId`). Same signature validates on every clone, factory deploy, or fork even when `used[digest]` / per-owner nonces fire on *this* instance. Canonical-`s` recovery and local nullifiers do **not** discharge this — they only stop malleability and same-contract digest reuse.
- **SAFE**: fold `address(this)` and `block.chainid` (or EIP-712 domain with both `verifyingContract` and `chainId`) into every signed digest; for EIP-2612/`DOMAIN_SEPARATOR`, include `chainId` in the domain typehash and rebuild on chain-id change (or compute per-call). Do **not** CLOSE because OZ `ECDSA.recover` or `used[digest]`/`nonces[owner]` alone look solid.

### Self-destruct / privileged teardown
- **VULN**: reachable `selfdestruct(attacker)`; `renounceOwnership()` leaving no admin; force-fed ether assumptions.
- **SAFE**: remove/guard `selfdestruct`; deliberate, access-controlled lifecycle.

### Uninitialized storage pointer / data location
- **VULN**: `pragma solidity ^0.4.24;` with a local `struct`/array declared without an explicit data location, defaulting to `storage` and aliasing low slots (e.g. `owner`); a write through it silently corrupts critical state.
- **SAFE**: explicit `memory`/`storage` locations; Solidity ≥0.5 (mandatory data location); never write through an unvalidated storage reference.

### Incorrect visibility / mutability
- **VULN**: a sensitive setter left `public`/unspecified with no access modifier, or a helper that should be `internal`/`external` exposed broadly; missing `view`/`pure` masking unintended state writes; unnecessary `payable` trapping ether.
- **SAFE**: least-permissive visibility; `external` for external-only callers, `internal`/`private` for helpers; `view`/`pure` where no state changes; drop unneeded `payable`.

### ZK proof-system & verifier soundness

A verified proof only guarantees the *statement the verifier actually checked*. Soundness bugs let a false statement verify, or let attacker-chosen data bypass the proof entirely. These are invisible to reentrancy/oracle/arithmetic reasoning — the mental model is **"trace every value that drives an asset effect back to the verified statement, and every witnessed value back to the constraint that binds it."**

- **VULN (unbound public input / statement binding)**: a value that decides *how much* or *how many* asset effects happen is read from calldata that is **not** part of the proof's committed statement. E.g. `publicInputsHash = sha256(header)` is verified, but a `batchSize`/`count`/`amount`/`recipient` is read from bytes *after* the hashed region and then drives a settlement loop or transfer. The prover can inflate/shrink/redirect the effect while the proof still verifies → double-processed deposits, skipped withdrawals, minted value. **SAFE**: every value consumed by an effect is inside the hashed/committed public inputs (or derived from a committed field); reject trailing/uncommitted calldata.
- **VULN (verifier-boundary field-domain & limb decoding)**: in a recursive/aggregate or hand-rolled pairing verifier — (a) a **base-field** curve coordinate reduced with the **scalar-field** modulus (or vice-versa), silently normalizing distinct points into a collision; (b) public-input **limbs** OR-packed (`x = pi[0] | pi[1]<<68 | pi[2]<<136 | ...`) with no per-limb range check, so an over-wide limb encodes a value the honest prover could not, i.e. **non-canonical decoding**; (c) accumulator/pairing points combined on the **wrong side or sign** versus the documented relation. **SAFE**: use the correct field modulus per coordinate; range-check every limb to its bit-width and reject non-canonical encodings; pin accumulator composition to the spec relation.
- **VULN (underconstrained / wrong-referent witness)** — *circuit source*: a witnessed/advice cell whose meaning depends on a trusted value is **assigned but never constrained** to it. Circom `computed <-- amount * secret;` (assignment hint only) with no `<==`/`===`; Halo2 `region.assign_advice(...)` for an input with no matching `copy_advice`/`constrain_equal` back to the trusted source cell; gnark values never `api.AssertIsEqual`'d. Also **wrong-referent**: a constraint exists but binds a *different* value than the design requires. **SAFE**: every security-relevant signal is `<==`/`===`-constrained (Circom), `copy_advice`/`constrain_equal`-bound (Halo2), or `AssertIsEqual`'d (gnark) to the exact value the statement relies on.
- **VULN (nullifier / value uniqueness)**: a spend/note/voucher consumed without atomically checking **and** recording a nullifier → replay/double-spend. **SAFE**: `require(!spent[n]); spent[n] = true;` before value moves.
- **VULN (proof-to-context replay)**: a valid proof accepted without binding it to the intended task/block/chain-id/verification-key/nonce, so a proof valid in one context is replayed in another. **SAFE**: fold the context (task id, block, `chainid`, VK hash, nonce) into the public inputs.

Grep seeds:
```bash
rg -n "verifyProof|publicInputsHash|abi\.decode|calldataload" --glob '*.sol'      # trace settlement values vs. the verified statement
rg -n "mulmod\(|addmod\(|<< *(68|136|204)|% *[A-Z_]*MOD" --glob '*.sol'           # verifier field-domain & limb decoding
rg -n "<--|assign_advice|copy_advice|constrain_equal|AssertIsEqual" --glob '*.{circom,rs,nr,go}'  # circuit constraint completeness
rg -n "nullifier|spent\[|isSpent|doubleSpend" --glob '*.{sol,circom,rs,nr}'       # nullifier uniqueness
```

## Source → Sink

- **Sources**: `msg.sender`, `msg.value`, function parameters, external contract return values, `block.*` (for randomness misuse), cross-contract `balanceOf`/price reads; **prover-supplied proof bytes, public inputs, and circuit witnesses**.
- **Sinks**: value transfers (`call{value}`, `transfer`, `send`), `delegatecall`, state-variable writes governing balances/ownership/accounting, `selfdestruct`, mint/burn; **proof-gated settlement/mint loops driven by a decoded count/amount**.
- **Sanitizers/barriers**: `nonReentrant`, access modifiers (`onlyOwner`/role), checks-effects-interactions ordering, checked arithmetic/SafeMath, slippage/deadline bounds, oracle staleness checks, `SafeERC20`, **`balanceOf` before/after delta measurement (fee-on-transfer/rebasing)**, **per-token decimal normalization to a common precision — `10**(18-decimals())` — before comparing/pricing (cross-token decimal mismatch)**, **target/selector allowlists for forwarded external calls (confused deputy)**; **public-input/statement binding (every effect value folded into the verified commitment), per-limb range checks & correct field modulus, circuit constraint completeness (`<==`/`copy_advice`/`AssertIsEqual`), nullifier uniqueness**.

## Severity & Triage
- **Critical**: direct theft/loss of funds (reentrancy drain, arbitrary `delegatecall`, confused-deputy arbitrary `call`/`transferFrom` draining custodied funds or user approvals, cross-token decimal-scale mismatch enabling under-collateralized borrow or a mispriced drain, missing access control on value/ownership, mint authority); **ZK soundness break — a false statement verifies, an effect value is unbound from the proof, or an underconstrained witness lets a prover forge a valid proof.**
- **High**: oracle manipulation, proxy reinit/storage collision, integer under/overflow affecting balances; ERC-4626/vault share-inflation (first-depositor/donation) causing depositor loss; vault mint/burn **rounding-direction** drift; fee-on-transfer/rebasing accounting drift causing insolvency or permanently stuck withdrawals; native/ERC20 dual-path underpay (`msg.value` unbound from `amount`).
- **Medium**: front-running without bounds, DoS via unbounded loops, weak randomness in value-bearing selection.
- Confirm the vulnerable function is externally reachable and the contract custodies value or authority before rating Critical.

## Common False Alarms
- Reentrancy flagged on a function that already follows checks-effects-interactions or carries `nonReentrant`.
- Arithmetic "overflow" under Solidity ≥0.8 outside any `unchecked {}` block (compiler reverts).
- `delegatecall` to a hardcoded, audited library address (e.g., a known math lib) — not attacker-controlled.
- `block.timestamp` used only for coarse time windows (e.g., deadlines), not as randomness or for fund selection.
- `view`/`pure` helpers with no state or value effect.
- Test/mock contracts under `test/`, `mocks/`, `script/` not deployed to production.
- ZK: an effect value (count/amount/recipient) that **is** folded into the verified public inputs, a witnessed cell with an immediate `copy_advice`/`constrain_equal`/`<==` to its trusted source, or a limb that **is** range-checked and canonically decoded — discharge, do not report. A verifier stub returning `true` in a fixture/test is not itself the finding; the finding is the missing binding around it.
- ERC-4626/vault: a vault using OpenZeppelin's virtual-shares/decimals offset, locked dead shares, an internal asset accumulator (not `balanceOf`), or a zero-shares-minted revert — discharge; the inflation vector is already mitigated. **Do not** discharge mint/burn **rounding-direction** bugs merely because inflation mitigations exist — those are separate classes.
- Fee-on-transfer/rebasing accounting flagged where the contract credits a `balanceOf(address(this))` before/after **delta** (not the raw `amount`), or restricts deposits to a vetted allowlist of standard non-fee/non-rebasing tokens — discharge.
- Native/ERC20 dual-path: discharge only when the native branch has `require(msg.value == amount)` (or credits exactly `msg.value`) **and** fee/penalty math mirrors the ERC-20 rail — presence of a correct ERC-20 `transferFrom` alone is **not** SAFE for the whole function.
- Confused-deputy arbitrary call flagged where `target` (and ideally the selector) is allowlisted or immutable, or where the calling contract holds **no** balances and is **never** an approval spender (e.g. a stateless `Multicall3`-style aggregator operating only on the caller's own behalf) — discharge.
- Cross-token decimal mismatch flagged where amounts are normalized to a common precision (e.g. scaled by `10**(18-decimals())`) before comparison/pricing, where the contract handles a single token or tokens of identical known decimals, or where a raw comparison is between amounts of the **same** token — discharge.

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
