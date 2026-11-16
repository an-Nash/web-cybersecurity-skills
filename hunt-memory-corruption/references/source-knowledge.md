# MERGED SOURCE KNOWLEDGE: memory-corruption

7 unique sections from 3 source files. Each section appears in exactly one target.


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-1-arithmetic-operations/fv-anc-1-cl1-overflow-underflow-in-arithmetic-operations.md

## TLDR

Integer overflow and underflow in Rust Anchor programs occur when arithmetic on u64/u128/i64 values wraps or panics, leading to corrupted balances, bypassed caps, or exploitable logic. In release builds, Rust integers wrap silently unless checked variants are used.

## Detection Heuristics

**Unchecked Arithmetic on Account Fields**
- Direct use of `+`, `-`, `*` operators on account field values such as `ctx.accounts.user.balance + amount`
- Arithmetic result assigned directly without `.checked_add()`, `.checked_sub()`, `.checked_mul()`, or `.checked_div()`
- Use of `as` casts (e.g., `u128 as u64`) that silently truncate

**Saturating or Wrapping Instead of Checked**
- Use of `.saturating_add()` or `.wrapping_add()` in financial or security-sensitive contexts where saturation masks real overflow
- Intermediate values computed in u64 that could exceed u64::MAX before being cast

**Absence of Error Propagation on Arithmetic**
- `.unwrap()` on checked arithmetic instead of `.ok_or(ErrorCode::...)` or `?`
- Arithmetic inside a loop over account balances without per-iteration overflow checks

## False Positives

- Arithmetic on values bounded by protocol invariants already enforced earlier in the instruction, making overflow mathematically impossible
- Use of `.saturating_add()` on non-financial counters such as event sequence numbers where saturation is the intended behavior
- Arithmetic inside `#[cfg(test)]` blocks that only appear in test code


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-1-arithmetic-operations/readme.md

## Classifications

Run `cat $SKILL_DIR/reference/anchor/fv-anc-1-arithmetic-operations/<filename>` to read any case file listed below.


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/move/fv-mov-8-advanced-patterns/fv-mov-8-cl1-generic-type-confusion.md

## TLDR

Unvalidated generic type parameters are the number-one critical vulnerability across real Move audits. An attacker creates a worthless `Coin<FakeUSDC>` and passes it to any function accepting `Coin<T>` without type validation, borrowing real assets against fake collateral. Phantom types on generic capabilities (`RoleCap<T>`) with no concrete type check enable role confusion.

## Detection Heuristics

- Find every function with a generic type parameter `<T>` that handles `Coin<T>`, `Balance<T>`, or any value-bearing type - verify `T` is validated against a stored type identifier or a whitelist
- Safe pattern: pool or vault struct uses `Pool<T>` - the phantom type on the container forces the function to only accept `Coin<T>` for the same `T`; verify this pattern is used consistently
- Search for `type_info::type_of::<T>()` comparisons - verify they compare against a stored expected type, not a hardcoded string that could be bypassed
- For role capabilities `RoleCap<T>` used in access control: verify the function asserts `T` is the expected concrete type, not just any type satisfying the constraint
- Navi Protocol and Econia are named examples - any lending or AMM function accepting generic coins without pool-level phantom type binding is high risk

## False Positives

- Pool/vault struct uses phantom type binding: `Pool<T>` forces all operations to use matching `Coin<T>`
- Explicit type registry: `assert!(type_info::type_of<T>() == stored_type)`
- Function is `public(package)` and only called by trusted internal code with statically verified types
