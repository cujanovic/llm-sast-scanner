---
name: solana_smart_contract_security
description: Solana / Anchor program (Rust) security — missing signer/owner/account-data checks, account-type confusion, arbitrary CPI, PDA bump canonicalization, PDA sharing, unsafe account closing, duplicate mutable accounts, reinitialization, and lamport/precision arithmetic. Distinct from EVM (see smart_contract_security.md). Load when a Solana program is present (Rust + solana_program/anchor_lang, declare_id!, entrypoint!, #[program], Anchor.toml, Cargo.toml with solana-program/anchor-lang).
---

# Solana / Anchor Smart-Contract Security

Solana programs are **Rust**, not Solidity, and the threat model is **completely different from EVM** (see `smart_contract_security.md` for Solidity/EVM). A Solana program is stateless code; all state lives in **accounts** passed in by the *caller*, who fully controls which accounts (and which account contents) the instruction receives. The runtime does **not** automatically verify that a passed-in account is the one the program intended, is owned by this program, was signed for, or is even the right *type*. Almost every Solana vulnerability is a **missing validation of attacker-supplied accounts** before the program reads/trusts them or moves lamports/tokens.

Core pattern: *the program acts on an account (reads its data, mutates it, transfers its lamports/tokens, or treats it as an authority) without verifying signer, owner, type, key, or PDA derivation — so the caller substitutes an account they control.*

## What It Is (and Is Not)

### What it IS
- Native (`solana_program`) or **Anchor** (`anchor_lang`) on-chain programs in Rust
- Missing account-validation checks (signer / owner / data-matching / type / PDA), cross-program-invocation (CPI) target confusion, PDA-derivation flaws, unsafe account closing, lamport/token arithmetic

### What it is NOT
- Solidity/EVM contracts → `smart_contract_security.md` (reentrancy, delegatecall, `tx.origin`, etc. do **not** map to Solana's account model)
- Generic Rust memory-safety (`unsafe`, `transmute`, `MaybeUninit`) → `memory_safety_c_cpp.md` (Rust section)
- Off-chain client/SDK bugs, RPC key leakage → `hardcoded_secrets.md` / `information_disclosure.md`

## Where to Look

- Native instruction handlers: `process_instruction`, manual `next_account_info(&mut iter)` loops reading `AccountInfo`
- Anchor: `#[derive(Accounts)]` structs and their **constraint attributes** (`#[account(...)]`), `#[program]` handler bodies, `Context<T>`
- Any `invoke` / `invoke_signed` (CPI), `create_program_address` / `find_program_address` (PDA), `**account.lamports.borrow_mut()` (manual lamport math), SPL-token transfers

## Recon Indicators

| Signal | Grep / structural targets |
|--------|----------------------------|
| Solana program present | `solana_program`, `anchor_lang`, `declare_id!`, `entrypoint!`, `#[program]`, `Anchor.toml` |
| Account reads w/o checks | `next_account_info(`, `AccountInfo`, `.try_borrow_data(`, `.data.borrow(` without nearby `is_signer`/`owner`/key assertions |
| Signer check | presence/absence of `.is_signer`, Anchor `Signer<'info>` / `#[account(signer)]` / `has_one` |
| Owner check | `.owner == program_id`, `#[account(owner = ...)]`; native handler trusting `AccountInfo` with no owner compare |
| PDA derivation | `Pubkey::create_program_address(`, `find_program_address(`, Anchor `seeds = [...]`, `bump` |
| CPI | `invoke(`, `invoke_signed(`, `CpiContext::new(`, target program account passed in by caller |
| Account close | `**acc.lamports.borrow_mut() = 0`, `Anchor #[account(close = ...)]`, manual data zeroing/discriminator |
| Token ops | `spl_token`, `TokenAccount`, `Mint`, `transfer(`, `mint_to(`, `set_authority(` |

## Vulnerability Patterns

### Missing signer check (authorization)
The instruction performs a privileged action (move funds, change authority, update config) but never asserts the relevant account **signed** the transaction — so anyone can pass that account as a non-signer and execute it.
- **VULN (native)**: handler uses `authority.key` for an authority decision without `if !authority.is_signer { return Err(...) }`.
- **VULN (Anchor)**: the authority is typed `AccountInfo`/`UncheckedAccount` instead of `Signer<'info>`, or no `has_one = authority` / `constraint = ... .key() == authority.key()`.
- **SAFE**: require `account.is_signer` (native) or type the field `Signer<'info>` and bind it with `has_one`/`address`/`constraint` (Anchor).

### Missing owner / program-ID check (account substitution)
The program reads an account's data and trusts it, but never checks the account is **owned by the expected program** — so the attacker passes a look-alike account they populated under a program they control.
- **VULN**: deserialize `account.data` into the program's state struct without `account.owner == program_id` (native) / without `#[account(owner = ...)]` or a typed `Account<'info, T>` (Anchor auto-checks owner+discriminator).
- **SAFE**: assert `account.owner == &expected_program_id`; in Anchor use `Account<'info, T>` (not bare `AccountInfo`) so owner + discriminator are enforced.

### Account-data matching (relationship not verified)
Two related accounts (e.g. a vault and its authority, a token account and its mint/owner) are both attacker-supplied; the program acts on one without confirming it **belongs to** the other.
- **VULN**: transfer from a `TokenAccount` without verifying its `owner`/`mint`/`authority` matches the expected PDA/signer; using a config account without `has_one` linking it to the caller.
- **SAFE**: Anchor `has_one = mint` / `has_one = authority` / `constraint = token.owner == expected.key()`; native: explicit field comparisons.

### Account-type confusion ("type cosplay")
Two account structs share the same byte layout, so an account of type A is accepted where type B is expected, bypassing logic.
- **VULN**: native programs that deserialize by layout with **no type discriminant**; trusting `AccountInfo` data without a tag.
- **SAFE**: include a unique discriminant/enum tag as the first field and check it; Anchor's 8-byte account discriminator does this automatically when you use `Account<'info, T>`.

### Arbitrary CPI (unverified target program)
The program invokes another program whose **program id is passed in by the caller** and never validated, so the attacker points it at a malicious program.
- **VULN**: `invoke`/`invoke_signed` (or `CpiContext::new(attacker_supplied_program, ...)`) where the program account is an untrusted input not compared to the expected id (e.g. not asserting the token program is `spl_token::ID`).
- **SAFE**: assert the CPI target program key equals the expected program id; in Anchor, type it as `Program<'info, Token>` (or the specific program) so the address is enforced.

### PDA bump-seed canonicalization
A Program-Derived Address is validated/created with a **caller-supplied bump** via `create_program_address` instead of the canonical bump from `find_program_address`, letting an attacker pick a non-canonical bump for the same logical seeds and bypass uniqueness/authority assumptions.
- **VULN**: `Pubkey::create_program_address(&[seeds, &[user_bump]], program_id)` where `user_bump` is from instruction data and is not checked to be the canonical bump.
- **SAFE**: derive with `find_program_address` (or store and reuse the canonical bump); Anchor `seeds = [...] , bump` enforces the canonical bump.

### PDA sharing across authority domains
One PDA (same seeds) is reused as the signing authority for multiple users/pools/roles, so a signature/authority valid for one context is replayable into another.
- **VULN**: a global PDA used to sign withdrawals for *every* user/vault.
- **SAFE**: include the user/pool/role identity in the PDA seeds so each domain gets a distinct PDA and authority.

### Unsafe account closing (revival / reinit)
Closing an account by only zeroing its lamports leaves its data intact; an attacker can re-fund it (or exploit the same-transaction refund) so it survives and is reused with stale data.
- **VULN**: `**acc.lamports.borrow_mut() = 0` without also clearing data / setting a closed discriminator; closing without transferring to a destination and zeroing.
- **SAFE**: zero/overwrite the data, set a `CLOSED_ACCOUNT_DISCRIMINATOR`, and send lamports to a destination; in Anchor use `#[account(close = destination)]`.

### Duplicate mutable accounts
The handler expects two distinct mutable accounts but the caller passes the **same** account for both, so writes to "A" clobber "B" (or double-credit).
- **VULN**: two `#[account(mut)]` of the same type with no `constraint = a.key() != b.key()`; native handlers that don't compare keys before mutating.
- **SAFE**: assert the two keys differ before mutating.

### Reinitialization
An "init" path can run twice on an already-initialized account, resetting authority/balance state.
- **VULN**: `init_if_needed` without guarding already-initialized state; native handlers with no `is_initialized` flag check.
- **SAFE**: prefer `#[account(init, ...)]` (fails if already initialized) over `init_if_needed`; check/set an `is_initialized` flag.

### Missing writable check
A native handler mutates an account the caller did not mark writable (or relies on it being writable) without asserting `is_writable`.
- **SAFE**: assert `account.is_writable` for accounts the instruction modifies (Anchor `#[account(mut)]` enforces this).

### Lamport / token / precision arithmetic
Unchecked arithmetic on lamports/token amounts overflows or loses precision.
- **VULN**: `+`/`-`/`*` on `u64` balances without `checked_*`; `saturating_*` masking an error; rounding up (`try_round`) where down (`try_floor`) is required, letting an attacker drain dust/precision.
- **SAFE**: `checked_add/sub/mul/div` with explicit error on `None`; floor (not round) on value-out calculations; cross-ref `weak_crypto_hash.md` only for RNG, and `memory_safety_c_cpp.md` for Rust integer semantics generally.

## Source → Sink

- **Sources** (attacker-controlled): every account in the instruction's account list (`ctx.accounts.*`, `next_account_info`), instruction data bytes, caller-chosen program ids and bumps.
- **Sinks**: lamport/token transfers, `set_authority`, config/state writes, `invoke`/`invoke_signed`, account close, deserialization of account data into trusted structs.
- **Sanitizers / barriers**: `is_signer`, `owner == program_id`, key/`has_one`/`address` comparisons, canonical-bump PDA derivation, account discriminator/type tag, distinct-key checks, `checked_*` arithmetic. Anchor encodes most of these as `#[account(...)]` constraints — **their absence on an attacker-supplied account is the finding.**

## Severity & Triage

- **High/Critical**: missing signer/owner/data-matching, arbitrary CPI, PDA bump/sharing, unsafe close — all give direct fund/authority theft.
- **Medium**: reinitialization, duplicate-mutable, precision loss — exploitable under conditions.
- Anchor's typed accounts (`Account<'info, T>`, `Signer`, `Program<'info, _>`) auto-enforce owner/discriminator/signer — confirm a finding is on a **bare `AccountInfo`/`UncheckedAccount`** or a missing constraint, not on an already-typed field.

## Common False Alarms

- A bare `AccountInfo`/`UncheckedAccount` that is only read for its key (never deserialized or trusted) and is independently constrained elsewhere.
- `init_if_needed` that is genuinely idempotent with a state guard.
- `find_program_address` already used (canonical bump) — not a finding.
- Read-only accounts not asserted writable — only flag accounts the instruction actually mutates.

## Cross-References

- `smart_contract_security.md` — Solidity/EVM (entirely separate model; do not conflate)
- `memory_safety_c_cpp.md` — Rust `unsafe`/`transmute`/integer semantics
- `weak_crypto_hash.md` — insecure RNG in Rust
- `access_control` / `privilege_escalation.md` — the authorization concepts, here expressed via signer/owner/PDA
