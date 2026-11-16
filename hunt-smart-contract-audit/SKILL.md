---
name: hunt-smart-contract-audit
description: Hunting skill for smart-contract / Web3 vulnerabilities across EVM (Solidity/Vyper), Solana (Rust/Anchor), TON (FunC/Tact), Sui/Aptos (Move), and TRON. Built from 221 curated source skill files (1,924 distilled sections) covering invariant breaks, reentrancy, proxy/upgrade flaws, oracle and price manipulation, signature replay, first-depositor inflation, access control, arithmetic/precision gaps, cross-chain bridge bugs, and meme-coin rug vectors. Use when auditing on-chain protocols — map invariants before touching a function, every lead must carry a concrete payload/proof, and every finding must pass the four validation gates before reporting.
sources:
  - smart-contract-audit
  - web3-audit
  - web3-bug-hunting
  - meme-coin-audit
  - rust-smart-contract-hack
  - sui-bug-hunting
report_count: 0
full_reports_read: 0
source_skills: 221
---

## Crown Jewel Targets

Smart-contract bugs are highest-value when a broken invariant maps directly to **fund loss, insolvency, or unauthorized asset movement**. Priority targets:

- **High-TVL DeFi protocols** — lending/borrowing, AMM/DEX, perpetuals/derivatives, ERC-4626 yield vaults. Every solvency/supply/price invariant here is a critical candidate.
- **Cross-chain bridges & message passers** — attester/relayer single points of failure, missing destination-domain validation, replay across domains, replace-before-revoke windows.
- **Upgradeable proxy systems** — uninitialized implementations, EIP-1967 storage collisions, UUPS `_authorizeUpgrade` gaps, timelock-free upgrades, retained admin keys.
- **Oracle consumers & price-dependent logic** — spot-price reads, short TWAPs, stale Chainlink feeds, single-block manipulation of `getRate()`-style views.
- **Signature/permit flows** — EIP-2612 permits, meta-transactions, cross-chain messages missing `chainId`/`nonce`/`deadline`, malleable `ecrecover`.
- **Token contracts with retained authorities** — hidden mint, unlimited supply, blacklist/honeypot, unbounded fee setters, LP migration, fake renounce (the meme-coin rug surface).
- **Cross-program / capability / actor-model boundaries** — Solana CPI + account validation, Move `acquires`/capability/object ownership, TON async message routing.
- **First-depositor / inflation-vulnerable vaults** — share-exchange-rate math that can be donated into and rounded against later depositors.

Payouts are highest when the finding is an **unprivileged, reachable, materially impactful invariant break** — not an admin-only action, not a named pattern with no concrete path.

| Target class | Crown-jewel asset | Canonical invariant to break |
| --- | --- | --- |
| Lending / vault | Deposited user funds | `totalAssets() == Σ(getRate()·balance)` |
| AMM / DEX | Pool reserves | `k` invariant, `Σ userShares == totalSupply` |
| Bridge | Locked collateral | message uniqueness `(nonce, sourceDomain, destDomain)` |
| Token | Holder balances / LP | `MAX_SUPPLY`, transfer symmetry, authority revocation |
| Solana program | Token accounts | owner + signer + `has_one` constraints |
| Move/Sui object | Owned resources | capability cannot be copied/dropped; `coin::extract` not `coin::value` |

---

## Attack Surface Signals

### Multi-Chain Reading Order (detect chain + protocol type first)

| Platform | Language | Toolchain | Key Attack Surface |
| --- | --- | --- | --- |
| Ethereum/EVM | Solidity, Vyper | Foundry, Hardhat, Slither | Storage, reentrancy, flash loans, proxy upgrades |
| Solana/SVM | Rust (Anchor) | Anchor CLI, cargo-test-sbf | Program owner, PDA seeds, account privilege escalation |
| TON | FunC, Tact | blueprint, toncli | Fundament, context, async message routing |
| Sui/Move | Move | sui-cli, move-prover | Object ownership, hot potato, transfer rules |
| Aptos/Move | Move | aptos-cli, move-prover | Capabilities, `borrow_global_mut`, generic `T` confusion |
| Cosmos | CosmWasm | cargo-test, wasmd | Message ordering, IBC relayer, staking |
| TRON | Solidity (TRC20) | TronIDE, foundry-tron | `transferFrom` allowance, `mulDiv` overflow, `block.number` |

### Protocol-Type-Specific Signals

- **Oracle consumers** — price feed freshness, TWAP window, single-block manipulation, `roundId`/`updatedAt`/heartbeat.
- **Lending** — interest-rate model bounds, utilization cap, bad-debt handling, `<= cap` on every mutation path.
- **Staking/Delegation** — validator-set changes, slashing conditions, reward distribution, cooldown timers.
- **AMM/DEX** — fee-on-transfer handling, `k` invariant, price-impact bounds, `MINIMUM_LIQUIDITY`.
- **Governance** — timelock bypass, proposal threshold, vote manipulation, flash-loan voting.
- **Meme coin / token** — mint authority, freeze authority, transfer hooks, permanent delegate, LP lock state, fee setters, renounce overrides.

### Code Signals by Family

```
# EVM
external/payable functions, .call{value:}, .transfer(), .send(), delegatecall
onlyOwner / onlyRole / require(msg.sender==...), tx.origin
upgradeTo / upgradeToAndCall / initialize() on implementation
ecrecover / ECDSA / DOMAIN_SEPARATOR / nonce / signature
getRate / getPrice / latestAnswer / spotPrice / twap
totalSupply / totalAssets / convertToShares / balanceOf
unchecked{ } / SafeMath / assembly / bytes20() casts

# Solana / Anchor
#[account(mut)], has_one, constraint, seeds/bump, CPI invoke_signed
mint_authority / freeze_authority / update_authority (Some(pubkey)?)
transfer_hook / permanent_delegate / Token-2022 extensions

# Move / Sui / Aptos
borrow_global_mut, acquires, upgrade_policy, UpgradeCap/AdminCap
coin::value vs coin::extract, generic T unconstrained, hot potato

# TON
receive()/external(), message parsing, send(), context fundamentals
```

### On-Chain / Off-Chain State Signals

- Contract **not verified** on Etherscan/Solscan → cannot audit source = cannot trust.
- Deployer wallet with rug history; token age < 1 hour with unknown team.
- LP not burned/locked; top holder > 20%; < $5K liquidity.
- Proxy/admin retained with no timelock; ownership "renounced" but second admin role present.

### Feature → Bug Class Map

| Observed feature | First bug classes to probe | Source family |
| --- | --- | --- |
| `external` function with state write after `.call` | Reentrancy (single, cross-function, read-only) | EVM |
| `initialize()` + proxy admin slot | Uninitialized impl, storage collision, UUPS guard | EVM |
| `ecrecover` / `ECDSA` on a digest | Replay (chainId/nonce/deadline), malleability | EVM |
| `getRate` / `getPrice` / `latestAnswer` | Spot/TWAP manipulation, stale feed, read-only reentrancy | All |
| `deposit` / `mint` / `redeem` on a vault | First-depositor inflation, share rounding, view/write divergence | EVM |
| `transferFrom` / `allowance` | Residual approval, missing allowance check, false-return | EVM/TRON |
| `delegatecall` to a user-supplied address | Arbitrary storage write, selfdestruct of impl | EVM |
| `#[account(...)]` without owner/signer/constraint | Account substitution, privilege escalation | Solana |
| `invoke` / `invoke_signed` with caller-supplied program | Unchecked CPI target, signer escalation | Solana |
| `mint_authority` / `freeze_authority` = `Some(...)` | Infinite mint, honeypot (rug) | Solana/Token-2022 |
| `borrow_global_mut` / capability by value | Ownership break, capability copy/drop | Move |
| Generic `T` unconstrained / `coin::value` | Type confusion, double-spend | Move |
| `receive()` / async `send()` between contracts | Message ordering, stale context, replay | TON |

### Detection Heuristics by Protocol Type

- **Oracle consumer**: is the price read in the same block/transaction as the value-moving operation? Is the feed heartbeat checked against `block.timestamp - updatedAt`?
- **Lending**: does the interest accrual round in the protocol's favor *without* compounding against users? Is the utilization cap enforced on settlement and fee-accrual paths too?
- **AMM/DEX**: is `MINIMUM_LIQUIDITY` burned? Is the K invariant checked after fee-on-transfer? Can a single-block price move exceed the price-impact bound?
- **Governance**: can flash-loaned votes reach the proposal threshold in one transaction? Is there a timelock between pass and execution?
- **Bridge**: is `(nonce, sourceDomain, destDomain)` validated as a tuple? Is there a replace-before-revoke gap where two attesters are simultaneously valid?

---

## Discovery Patterns From Curated Source Skills

### Where Researchers Start

1. **Map the protocol (P1) before any function.** Enumerate every contract *and* every external dependency — oracles, rate providers, LPs, bridges, shared accountants. The bug is usually at a **dependency boundary**, not in the one file you were scoped. (`references/hacking-agents/smart-contract-agent.md`)
2. **Write the invariants file first.** Create `state/sessions/{target}/maps/invariants.md` with one row per solvency/supply/permission/price invariant: `totalAssets() == Σ(getRate()·balance)`, `Σ userShares == totalSupply`, mint == burn, only listed actors touch withdraw/transfer, price not manipulable in one block. (`references/hacking-agents/smart-contract-agent.md`)
3. **Detect chain + protocol type, then load the matching context file and quick-tricks file.** The three-layer reading order: protocol context → bug-class reference → quick tricks, repeated per chain. (`skills/smart-contract-audit/SKILL.md`, `references/web3-quickstart.md`)
4. **Pre-dive kill signals on tokens.** Check hard kills before reading a line of code — unverified contract, rug-history deployer, mint/freeze authority retained, mutable transfer hook, permanent delegate. (`skills/meme-coin-audit/SKILL.md`)
5. **Scan hot contracts, not the whole repo.** Point the auditor at the 2–5 contracts actively changing; run it 2–3 times since LLM output is non-deterministic. (`skills/pashov/solidity-auditor/README.md`)
6. **Initialize a straight-line debug log.** `audit-debug.md` records every search, scan, protocol-type decision, and "pursued/skipped" choice. (`skills/smart-contract-audit/SKILL.md`)
7. **Trust map the authority boundary.** Who is allowed, who profits/pays, who is treated differently — the gap between lenses is where reports come from. (`.../hacking-agents/trust-gap-agent.md`)

8. **Build a debug log as straight lines.** Log every search, scan, and decision: detected chain, detected protocol type, each grep command and its result, each protocol-specific trick pursued or skipped (`✓`/`✗`), and KB pattern matches. This creates technical breadcrumbs for reviewers and prevents forgotten leads. (`skills/smart-contract-audit/SKILL.md`)

9. **Establish the economic context before scoring.** Estimate TVL, identify user funds at stake, calculate a realistic security budget (~10% of TVL, $2K–$60K), and record who is affected by a failure. `value_at_risk` fields must be quantified later, and they start here. (`skills/smart-contract-audit/SKILL.md`)

### Feature-Based Discovery Signals

- **External call sites** — `call`, `transfer`, `send`, `staticcall`, `delegatecall`, ERC20 transfers, ERC721 hooks. Is state updated before or after? Is `nonReentrant` present? (`smart-contract-agent.md`, `.../boundary-agent.md`)
- **Paired operations** — deposit↔withdraw, mint↔burn, modify↔settle, user `X()`↔admin `forceX()`. Diff storage writes/reads between both sides. (`.../asymmetry-agent.md`)
- **Payable functions** — `msg.value > 0`, `== 0`, `!= amount` branches; native-path fee deduction vs ERC20-path. (`.../boundary-agent.md`)
- **Sentinel branches** — `if (token == _ETH_ADDRESS_)`, `address(0)`, `0xEeEe...`, `type(uint256).max`. Walk both sides forward into any `IERC20` op. (`.../boundary-agent.md`)
- **`bytes` inputs / `abi.decode`** — empty input, attacker-supplied length, `bytes20(longerBytes)` truncation, `abi.encodePacked` ambiguity, field-order mismatch. (`.../boundary-agent.md`)
- **Admin variants of user functions** — `setPositionWidth`/`unpause` mirroring a guarded rebalance; can a user sandwich the admin transaction? (`.../asymmetry-agent.md`, Beefy pattern)
- **Capped values** — enumerate *every* path that increments a `<= cap` value: settlement, fee accrual, emergency mode, admin ops. (`.../invariant-agent.md`)
- **Cache-then-mutate-then-use chains** — a function caches `state.x`, calls a mutator writing `state.x`, then uses the stale cached value. (`.../invariant-agent.md`)
- **Capability / account substitution** — Move capability copied/dropped, `borrow_global_mut` on unowned resource, Solana missing signer/owner/`has_one`, unconstrained generic `T`. (`smart-contract-agent.md`)
- **Async message ordering (TON)** — message delivery order, stale context, cross-message field corruption. (`skills/smart-contract-audit/SKILL.md` → `ton-checks.md`)

### Verbatim Hunter Clues

> "You hunt **invariant breaks**, not 'dangerous code.' Before probing any function..." — `references/hacking-agents/smart-contract-agent.md`

> "The bug is usually at a **dependency boundary, not in the one file you were scoped**." — `references/hacking-agents/smart-contract-agent.md`

> "**Every lead = a payload NOW.** Never write a lead without a `payload:` (calldata sketch, Foundry test, or fork script) and `probe_results:`. Never skip a function because 'onlyOwner' gates it — find the caller of the caller. Gates decide reports, never probes." — `references/hacking-agents/smart-contract-agent.md`

> "**Cheat the Engine (WILD MODE — do this before and during everything below)** ... Every contract is a machine you are trying to make do something it wasn't designed to do." — `references/hacking-agents/smart-contract-agent.md`

> "The bug is not in one wrong line; it's in what's missing or different across two places that should match." — `.../hacking-agents/asymmetry-agent.md`

> "One bug in a 20-line library compromises every caller." — `.../hacking-agents/periphery-agent.md`

> "**Do not pattern-match.** Forget 'reentrancy' and 'oracle manipulation.' For every line, ask: 'this assumes X — break X.'" — `.../hacking-agents/first-principles-agent.md`

> "A finding is not real until you've traced the attack with concrete values. You are an attacker, not a defender — when you find a bug, deepen the attack; never argue yourself out of one." — `.../references/senior-auditor-sop.md`

> "Trust your discomfort. Reach for the tool. Don't stop until the discomfort has a name." — `.../references/senior-auditor-sop.md`

> "**Check ALL authorities and owner functions. The retained authority IS the rug vector.**" — `skills/meme-coin-audit/SKILL.md`

> "Every rug pull requires a privileged operation: mint, blacklist, fee change, LP removal, or authority abuse. If you find the privilege, you found the bug." — `skills/meme-coin-audit/SKILL.md`

> "Without concrete proof of the seam, it's a LEAD, not a finding." — `.../hacking-agents/flow-gap-agent.md`

> "Static-check the ERC4626 surface: call the operation at the reported `max*` value — make it revert to prove the guarantee is broken." — `.../hacking-agents/economic-security-agent.md`

> "Libraries, helpers, encoders/decoders, provider wrappers, and abstract bases are your primary attack surface." — `.../hacking-agents/periphery-agent.md`

### Probe Checklist

- [ ] Chain + language + protocol type detected before reading code
- [ ] `invariants.md` written with one row per solvency/supply/permission/price invariant
- [ ] External dependencies mapped (oracles, LPs, bridges, rate providers, shared accountants)
- [ ] Every external call site checked for state-before-call and guard presence
- [ ] Every paired function set storage-write-diffed
- [ ] Every payable function walked for `msg.value` branch cases
- [ ] Every sentinel branch walked forward into downstream token ops
- [ ] Every `bytes`/`abi.decode` input exercised with empty/max/truncated cases
- [ ] Admin functions diffed against user variants; unprivileged amplifier named
- [ ] All paths incrementing a capped value enumerated
- [ ] Signature checks verified for `chainId`, `nonce`, `deadline`, malleability
- [ ] Token-behavior assumptions tested (fee-on-transfer, rebasing, void return, blacklist)
- [ ] Every lead carries a `payload:` and `probe_results:`; no proof = LEAD
- [ ] Kill signals checked (token authority retention, LP lock, deployer history)
- [ ] Capped/enumerated values checked on secondary mutation paths (settlement, fee accrual, emergency)
- [ ] `queryX` vs `doX` view/write math compared modulo state mutation
- [ ] Timer/cooldown resets via secondary call paths enumerated
- [ ] Capability / UpgradeCap / AdminCap public accessibility checked (Move)
- [ ] TON async message ordering and cross-message field corruption considered
- [ ] Confidence score computed (100 − deductions); ≥80 gets description + fix
- [ ] Safe patterns exclusion list applied before finalizing

> **Note:** This digest covers 22 representative source files. The full **1,924-section corpus** distilled from all 221 source files is archived at `references/source-knowledge.md` — consult it for the complete per-language bug-class reference (`fv-sol-X`, `fv-anc-X`, `fv-vyp-X`, `fv-ton-X`, `fv-mov-X`) and protocol-context files.

---

## Step-by-Step Hunting Methodology

1. **Detect the platform and protocol type (mandatory first step).** Identify blockchain (Ethereum/EVM, Solana, TON, Sui/Move, Aptos, Cosmos, Near, Cardano, TRON) and protocol type (AMM/DEX, lending, derivatives, staking, bridge, NFT, governance, insurance). Load the matching protocol context + quick-tricks reference. (`skills/smart-contract-audit/SKILL.md`)

2. **Define scope and output structure.** Core vs periphery vs governance; which networks, which deployment phases. Ignore the project's `.context/` directory. Initialize `audit-debug.md` and log the protocol-type decision as a straight line. (`skills/smart-contract-audit/SKILL.md`)

3. **Map invariants before touching a function.** Write `invariants.md`. Map every contract and dependency boundary. Run the economic loop on each invariant: IDENTIFY ASSUMPTION → FIND CONTROLLED VARIABLE → MUTATE → OBSERVE → CHECK INVARIANT → CHAIN → CALCULATE VALUE AT RISK.
   - Solvency: `totalAssets() == Σ(getRate()·balance)`, deposited − withdrawn == contract balance.
   - Supply: `Σ userShares == totalSupply`, mint == burn, first/last deposit boundaries.
   - Permission: only listed actors touch withdraw/transfer/upgrade.
   - Price: price not manipulable in one block; view returns same value write would use.
   - For each invariant, list every function that modifies any of its terms — that list is the attack surface. (`references/hacking-agents/smart-contract-agent.md`, `.../invariant-agent.md`)

4. **Run the 30-minute grep arsenal.** Fire all copy-paste grep blocks for access control, reentrancy, price/oracle, flash loans, proxy, accounting, signatures, ERC4626, roles, unsafe math. (`references/web3-quickstart.md`, section 6 below)

5. **Apply the pre-dive kill screen for tokens.** Hard kills (unverified contract, rug deployer, mint/freeze authority, mutable hook, permanent delegate) → skip. Soft kills (top holder >20%, unlocked LP, upgradeable admin) → extreme caution. (`skills/meme-coin-audit/SKILL.md`)

6. **Name the Web3 intersection in every finding:** `IDENTITY × ASSET × STATE × PRICE × AUTHORITY × TRUST BOUNDARY × CALL GRAPH × TIME`. Accounting comes before implementation — a first-depositor attack on sound accounting beats a reentrancy on broken accounting. (`smart-contract-agent.md`)

7. **Cheat the engine — WILD MODE on every function.** Lie about identity (swap callers, reuse approvals, masquerade via delegatecall). Lie about authority (find every caller of the caller, every proxy path, uninitialized `initialize()`). Lie about state (skip steps, reenter with stale state, race transitions). Lie about time (replay signatures, reuse permits, front-run transitions). Lie about inputs (fee-on-transfer, rebasing, decimals, malicious hooks). Give MORE/LESS than expected. Weaponize the platform (fallback, selfdestruct, proxies, pause, fee setters). (`smart-contract-agent.md`)
   - **Give MORE**: overflow, favorable rounding, compounding dust, flash-loan amplification, array-length abuse.
   - **Give LESS**: underflow, zero amounts, empty arrays/messages, zero addresses, dust, minimum-liquidity bypass.
   - **Weaponize**: `fallback`/`receive()` as entry, `selfdestruct` paths, upgrade proxies, pause toggles, fee setters, emergency functions treated as attacker inputs.

8. **Sweep with the specialist lenses.** Run independent passes: math-precision, access-control, economic-security, execution-trace, invariant, periphery, first-principles, asymmetry, boundary, trust-gap, sequential-flow, numerical-gap. For gap-hunters, only emit bugs that *require* two or three lenses at once. (`skills/pashov/solidity-auditor/SKILL.md`, `.../hacking-agents/*-agent.md`)

9. **Use the mental-tool protocol continuously.** On opening any function emit `[Feynman: <name>]` (plain-English explanation — fuzziness marks the hidden assumption); on an unclear line `[Socratic: <file:line> — why?]`; on any clean-looking path `[Inversion: <function>]` with three concrete attacker moves. (`.../references/shared-rules.md`, `senior-auditor-sop.md`)

10. **Escalate and cross-pollinate.** Escalate every finding to its worst exploitable variant (DoS may hide fund theft). Weaponize a confirmed pattern across every other contract/deployment by function name and code pattern. Revisit every function where you found something and attack the other branches. (`shared-rules.md`)

11. **Build a concrete PoC only if the repo is configured with a test framework.** Complete test cases with realistic parameters, economic analysis showing profitability, and the exact transaction sequence. (`skills/smart-contract-audit/SKILL.md`, meme-coin Foundry template below)

12. **Validate every candidate through the four gates (section 9), then report.** No numbers = LEAD; no proof = LEAD. Promote leads on cross-contract echo or multi-agent convergence. (`.../references/judging.md`)

---

## Payload & Detection Patterns

### WEB3 GREP ARSENAL — first 30 minutes (copy-paste ready)

```bash
# Access Control (19% of all Criticals)
rg -n "onlyOwner|onlyRole|require\(.*msg\.sender" --include="*.sol" | grep -v "test\|mock\|lib/"
# Reentrancy
rg -n "external.*\{|\.call\{value|\.transfer\(|\.send\(" --include="*.sol" | grep -v "test\|mock"
# Price/Oracle Manipulation
rg -n "getRate|getPrice|latestAnswer|spotPrice|twap" --include="*.sol" | grep -v "test\|mock"
# Flash Loan Entry Points
rg -n "flashLoan|flash loan|onFlashLoan|IPool" --include="*.sol" | grep -v "test\|mock"
# Proxy/Upgrade Patterns
rg -n "upgradeTo|upgradeToAndCall|delegatecall|implementation" --include="*.sol" | grep -v "test\|mock"

# Accounting Desync (28% of all Criticals)
rg -n "totalSupply|totalAssets|balanceOf|sharesOf|convertToShares" --include="*.sol" | grep -v "test\|mock"
# Signature Replay
rg -n "ecrecover|ECDSA|signature|nonce|DOMAIN_SEPARATOR" --include="*.sol" | grep -v "test\|mock"
# ERC4626 Vault
rg -n "deposit|withdraw|mint|redeem|totalAssets|convertToShares|convertToAssets" --include="*.sol" | grep -v "test\|mock"
# Access Control State
rg -n "grantRole|revokeRole|_grantRole|DEFAULT_ADMIN_ROLE" --include="*.sol" | grep -v "test\|mock"
# Unsafe Math
rg -n "unchecked\{|\.add\(|\.sub\(|\.mul\(|SafeMath" --include="*.sol" | grep -v "test\|mock\|lib/"

# Oracle Staleness
rg -n "block\.timestamp.*stale|heartbeat|roundId|updatedAt" --include="*.sol"
# LP/Share Price
rg -n "getReserves|token0|token1|totalSupply.*pool|MINIMUM_LIQUIDITY" --include="*.sol"
# Admin/Privileged Roles
rg -n "OWNER_ROLE|MANAGER_ROLE|PAUSER_ROLE|MINTER_ROLE|STRATEGIST" --include="*.sol"
```

### EVM / Solidity Patterns

```solidity
// 1. Reentrancy — state AFTER external call, no nonReentrant
function withdraw(uint256 amt) external {
    (bool ok,) = msg.sender.call{value: amt}("");   // external call first
    require(ok);
    balances[msg.sender] -= amt;                     // state after -> reenter
}

// 2. Uninitialized implementation — free admin claim
// Probe initializer on BOTH implementation and proxy addresses:
// cast send <impl> "initialize(address)" <attacker>  -> succeeds? = bug

// 3. Signature replay — missing chainId/nonce/deadline
bytes32 digest = keccak256(abi.encodePacked(amount, recipient)); // no chainId/nonce
address signer = ecrecover(digest, v, r, s);                    // check s <= n/2

// 4. First-depositor inflation / ERC-4626 rounding
// donate -> inflate convertToAssets(); later depositor rounds to 0 shares

// 5. tx.origin auth
require(tx.origin == owner);   // phishable via intermediary contract

// 6. Unchecked low-level return
token.call(abi.encodeWithSelector(...));  // bool ignored -> silent failure

// 7. Read-only reentrancy — stale view consumed by an oracle
function getRate() public view returns (uint256) {
    return totalAssets * 1e18 / totalSupply;  // stale mid-reentrancy
}

// 8. tx.origin / block.timestamp entropy
uint256 winner = uint256(keccak256(abi.encode(block.timestamp, blockhash(block.number-1))));

// 9. Storage collision — proxy admin slot vs implementation slot 0
// EIP-1967: keccak256("eip1967.proxy.implementation") - 1

// 10. approve out+fee but consume out-fee -> 2*fee residual allowance per call
```

#### Solidity Anti-Pattern Quick Reference

| Anti-pattern | Detection | Concrete trigger |
| --- | --- | --- |
| Reentrancy | call before state write | reenter via `receive()` before balance decrement |
| Uninitialized impl | `initialize` lacks `initializer` on impl | call `initialize(attacker)` on implementation |
| Signature replay | digest omits chainId/nonce | replay on second chain / second call |
| Oracle spot read | `slot0` / single-source in same tx | manipulate price in prior block, deposit |
| First-depositor | donate inflates exchange rate | 1 wei deposit + large donation |
| Precision loss | division before multiplication | 1 wei fee truncates to zero |
| Downcast wrap | `uint64((x<<64)/y)` near saturation | ratio → 1 wraps to ~0 |
| Residual approval | approve `out+fee`, consume `out-fee` | N calls accumulate `N·2·fee` |
| Cache-then-mutate | `state.x` cached, mutator rewrites it | use stale cached value after call |
| Emergency strand | pause without paired cleanup | generate rewards during emergency |

### Vyper Patterns

- Establish **compiler version and built-in guard behavior first** — they determine which patterns apply.
- Reentrancy locks are compiler-version dependent; fixed-point division has version-specific edge cases.
- Walk: external calls, integer overflow (pre-0.8 equivalent), access control, timestamps, randomness, front-running, precision, DoS, upgradeability. (`skills/smart-contract-audit/SKILL.md` → `vyper-checks.md`)

```bash
rg -n "raw_call|self\.balance|@external|@internal|nonreentrant|as wei_value" --include="*.vy"
```

### TON / FunC / Tact Patterns

- **Actor-model + async delivery**: message ordering, context fundamental, `receive()`/`external()`, fund backbone, TEP standard compliance.
- Async-specific protocol contexts: oracle (async delivery), AMM/DEX (async slippage), lending (async liquidation), staking (accumulator ordering, cooldown griefing), bridge/governance. (`skills/smart-contract-audit/SKILL.md` → `ton-checks.md`)

```bash
rg -n "receive\(|external\(|send\(|message|context\(\)|throw_unless|require\(" --include="*.fc" --include="*.tact"
```

### Solana / Rust / Anchor Patterns

```rust
// Missing account validation — attacker substitutes arbitrary accounts
#[derive(Accounts)]
pub struct Withdraw<'info> {
    // #[account(mut)] missing
    pub vault: Account<'info, Vault>,          // no owner / has_one / seeds check
    pub authority: Signer<'info>,              // is signer actually enforced?
}

// CPI target unchecked — program passed as account argument
invoke_signed(&ix, &[&program_from_caller], &[seeds]); // verify program ID!

// Authority retention (no source needed)
// solana account <MINT> --output json -> mint_authority / freeze_authority
//   Some(pubkey) = CRITICAL; should be null
// Token-2022: transfer_hook, permanent_delegate extensions
```

### Sui / Aptos Move Patterns

```move
// Capability copied/dropped; ownership not checked
public fun withdraw<T>(cap: &mut AdminCap, obj: &mut Object<Vault>) {
    // borrow_global_mut on resource not owned by caller?
    // generic T not constrained to expected coin type?
    // coin::value used instead of coin::extract -> double-spend
}

// upgrade_policy too permissive; UpgradeCap / AdminCap publicly accessible
// CCTP: num_required_attestations == 1 -> single key drains bridge
// replace_attester race; orphaned minter allowance after remove_minter
```

### TRON Patterns

```bash
rg -n "transferFrom|mulDiv|block\.number|Stake2\.0|pending" --include="*.sol"
# TRC20 transferFrom without allowance; int overflow in mulDiv (pre-0.8)
# block.number used as timestamp; eth_call 'pending' fallthrough to 'latest'
```

### Static / Dynamic Analysis Tooling

```bash
# Slither — static detectors + printers
slither . --detect reentrancy-eth,unprotected-upgrade,arbitrary-send-eth \
  --print contract-summary,function-summary,call-graph

# Foundry — fork tests, fuzzing, invariant campaigns
forge test -vvv
forge test --match-test test_exploit --fork-url $RPC
forge fuzz --fuzz-runs 10000
forge inspect Contract storageLayout       # proxy storage collision check

# Echidna / Medusa — property-based invariant fuzzing
echidna . --contract InvariantTest --test-mode property --config echidna.yaml
# Define invariants as property_* functions; seed with realistic actors

# Solhint / semgrep quick sweep
semgrep --config p/solidity .
```

### Token / Rug Greps (meme-coin-audit family)

```bash
# Hidden mint / unlimited supply (EVM)
grep -rn "function mint\|_mint(\|_balances\[.*\] +=" src/ --include="*.sol" | grep -v "test\|lib\|node_modules"
# Honeypot / transfer restriction
grep -rn "blacklist\|isBlacklisted\|_bots\|maxTxAmount\|approve.*override\|tradingEnabled" src/ --include="*.sol"
# Fee manipulation
grep -rn "setFee\|setSellFee\|_taxFee\|_sellFee" src/ --include="*.sol"
grep -rn "function set.*Fee" -A5 src/ --include="*.sol" | grep -v "require\|MAX\|<="
# LP drain / migration
grep -rn "migrateLP\|emergencyWithdraw\|\.sync()\|setPair\|setRouter" src/ --include="*.sol"
# Bonding curve manipulation
grep -rn "virtualReserve\|setCurve\|graduate\|bonding_curve" src/ --include="*.sol" --include="*.rs"
# Fake renounce
grep -rn "renounceOwnership.*override\|_shadowAdmin\|_backupOwner\|selfdestruct" src/ --include="*.sol"
# Solana authorities / Token-2022
grep -rn "MintTo\|mint_to\|mint_authority\|freeze_authority\|update_authority\|transfer_hook\|permanent_delegate" src/ --include="*.rs"
grep -rn "set_authority.*None" src/ --include="*.rs"   # good sign: revocation
```

### Multi-Chain Token Scanner

```bash
python3 tools/token_scanner.py programs/token/ --chain solana --recursive
python3 tools/token_scanner.py src/ --recursive --output findings/token-report.md
# Checks 8 bug classes via regex: mint/balance manipulation, blacklist, unbounded
# fee setters, LP migration, fake renounce, zero-slippage swaps, Solana authorities,
# Token-2022 extensions. Does NOT check on-chain state, holder distribution, LP lock,
# or deployer history — verify those manually (Etherscan/Solscan/Birdeye).
```

### Foundry PoC Template (token exploit pattern)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Test.sol";
import "../src/Token.sol";

contract TokenExploitTest is Test {
    Token token;
    address owner    = makeAddr("owner");
    address victim   = makeAddr("victim");
    address attacker = makeAddr("attacker");

    function setUp() public {
        vm.createSelectFork("mainnet");
        vm.startPrank(owner);
        token = new Token();
        vm.stopPrank();
    }

    function test_hiddenMint_rug() public {
        vm.startPrank(owner);
        uint256 supplyBefore = token.totalSupply();
        token.mint(owner, 1_000_000_000e18);
        assertGt(token.totalSupply(), supplyBefore, "Supply should increase");
        vm.stopPrank();
    }

    function test_honeypot_blacklist() public {
        vm.startPrank(owner);
        token.blacklist(victim);
        vm.stopPrank();
        vm.startPrank(victim);
        vm.expectRevert("Blacklisted");
        token.transfer(address(1), 100e18);
        vm.stopPrank();
    }
}
```

### Output Fields for Findings

```
FINDING | contract: Name | function: func | bug_class: kebab-tag | group_key: Contract | function | bug-class
path: caller -> function -> state change -> impact
proof: concrete values/trace demonstrating the bug
description: one sentence
fix: one-sentence suggestion

LEAD | contract: Name | function: func | bug_class: kebab-tag
code_smells: what you found
description: one sentence with what remains unverified

# chain-specific additions (smart-contract-agent.md):
chain: evm | aptos | solana | tron
language: solidity | move | rust | solidity-tron
invariant_broken: <invariants.md row>
value_at_risk: <TVL / funds quantified>
```

---

## Common Root Causes

1. **Accounting before implementation was never proven** — the protocol's invariant is broken at a dependency boundary, so any reentrancy/overflow work is moot.
2. **State updated after external call** — classic reentrancy plus cross-function and read-only (stale view used by oracle) variants.
3. **Uninitialized or misconfigured proxy** — implementation `initialize()` callable, storage collision, UUPS `_authorizeUpgrade` unguarded, no timelock.
4. **Incomplete signature domain** — missing `chainId` (cross-chain replay), `nonce` (same-chain replay), `deadline`, or malleable `ecrecover`.
5. **Oracle/price trust** — spot price or short TWAP read in the same block as a deposit/liquidation, stale feed, `getRate()`-style view returning stale state mid-reentrancy.
6. **Rounding/precision in the wrong direction** — deposits round shares up, withdrawals round assets up, debt/fees round down; truncation amplified across function boundaries; hardcoded `1e18` on 6-decimal tokens.
7. **Asymmetric paired functions** — developer copied structure but forgot to mirror one storage update, or an admin variant omits guards present on the user version.
8. **Broken external-boundary assumptions** — void return, fee-on-transfer, rebasing, blacklist/pausable tokens, sentinel placeholders, ERC165 fallback, `abi.encodePacked` ambiguity.
9. **Missing platform-level validation** — Solana owner/signer/`has_one`, Move capability/ownership, PDA seed collision, unconstrained generic `T`, TON async ordering.
10. **Retained authority as rug vector** — hidden mint, freeze/honeypot, unbounded fee setter, LP migration, fake renounce (meme-coin family).
11. **Cross-chain replay / single point of failure** — attester/relayer key, missing destination-domain validation, replace-before-revoke gap, orphaned roles.
12. **Unbounded loops and forced reverts** — gas-limit DoS, emergency transitions that strand value, caps enforced on one path but not secondary mutation paths.
13. **View/write divergence** — `queryX` omits a penalty/fee/accrual that `doX` applies; off-chain integrators trust the wrong number while on-chain comparisons drift.
14. **Cross-message field corruption** — packed fields in bridges/callbacks/queues manipulated across legs; user-controlled identifiers key state maps without occupancy checks (overwrites).
15. **Truncated cross-encoded recipients** — a `bytes32` non-EVM address or `address + extra` packed into `bytes20` silently truncates; refunds route to the truncated value.
16. **Mid-operation config mutation** — setters callable while a draw/settle/multistep operation is ACTIVE; settlement reads current values instead of values captured at start.

---

## Bypass Techniques

### Access-Control Bypasses
- **Caller-of-caller**: never stop at `onlyOwner` — find every caller of the guarded function, every proxy path, every ungated role-grant.
- **Uninitialized initializer**: call `initialize()` on the implementation directly (free admin claim).
- **Upgrade path**: timelock-free `upgradeToAndCall` to a malicious implementation; UUPS `_authorizeUpgrade` reachable.
- **Fake renounce**: `renounceOwnership` overridden, `_shadowAdmin`/`_backupOwner`, `selfdestruct` backdoor.

### Invariant & Cap Bypasses
- Enumerate **all** paths modifying a capped value — settlement, fee accrual, emergency mode, admin ops — and take the one that skips `<= cap`.
- **Cache-then-mutate**: use stale cached `state.x` after a mutator rewrote it.
- **Partial mint / peg break**: partial failures leave supply un-collateralized until the next full cycle.
- **Emergency transitions**: pause normal flows but skip cleanup → value generated in emergency is stranded.

### Precision & Rounding Bypasses
- Feed 1 wei / 1 share to truncate fees to zero; compound the difference.
- Overflow intermediates in `a*b/c` before the division saves it (flash-loan-scale operands).
- Downcast `uint256 → uint128/96/64` with realistic values; cast-wrap at saturation.
- Sign loss on `uint24`/`int24` round-trips; mask the wrong bits in pack/unpack.

### Token-Behavior Bypasses
- Fee-on-transfer: `received != amount` — drain the cached difference.
- Rebasing / blacklist / pausable: cached balance goes stale or transfers revert unexpectedly.
- Void return (USDT style) breaks `require(token.transferFrom())`; false-returning tokens silently corrupt state.
- Sentinel placeholder flows into `IERC20(SENTINEL).approve(...)` → silent no-op or revert.

### Signature / Replay Bypasses
- Strip `chainId` → replay across chains; strip `nonce` → replay same-chain.
- Accept `s > secp256k1n/2` → signature malleability; front-run a pending signature and submit first.
- Reuse expired EIP-2612 permits against non-standard tokens (DAI class).

### Oracle / MEV Bypasses
- Manipulate spot price / single-source feed in the prior block, then deposit/liquidate against it.
- Sandwich every price-dependent operation missing a deadline / `amountOutMin`.
- Push fee formulas to zero (free extraction) and max (overflow).

### Cross-Chain Bypasses
- Replay `(nonce, sourceDomain, destDomain)` messages on the wrong destination chain.
- Single-attester threshold; front-run `replace_attester`; orphaned minter allowance after removal.
- `burn_with_caller_address` caller not validated against stored message sender.

### Platform-Specific Bypasses
- **Solana**: substitute accounts when owner/signer/`has_one` missing; unchecked CPI target; non-canonical bump; PDA seed collision.
- **Move/Sui**: pass arbitrary type into unconstrained generic `T`; copy/drop capability; `borrow_global_mut` on unowned resource; `coin::value` instead of `coin::extract`.
- **TON**: exploit async message delivery order and stale context across messages.

### Structural Bypasses (gap-hunter seams)

- **Access × economics**: an `onlyKeeper` rebalance calls a swap with `amountOutMin = 0` — the guard is "correct" and the swap is "correct," but a keeper can sandwich themselves.
- **Economics × asymmetry**: deposit uses spot price, withdraw uses TWAP — deposit cheap, withdraw expensive.
- **Access × asymmetry**: `setFeeRecipient` redirects pending fees instead of crediting the old recipient first — admin rugs in-flight value.
- **Execution × periphery**: a vault deposit computes `balance_before`, calls a fee-on-transfer token, then uses the pre-transfer value downstream.
- **Periphery × first principles**: a technically-correct `safeTransferFrom` to a rebasing/blacklist token violates the promise "users always receive at least X."
- **Precision × invariant**: per-deposit rounding loss accumulates so `Σ userShares == totalSupply` silently drifts after N deposits.
- **Boundary × invariant**: a zero-amount `repay()` bypasses the invariant update, leaving a stale `lastUpdate` future calls trust.

### Compounding & Amplification Bypasses
- Turn a bounded DoS into fund theft by escalating to its worst exploitable variant before reporting (e.g., forced revert on refund → poisoned refund record → permanent fund lock).
- Use flash-loan-scale capital to push user-influenced operands past overflow/intermediate limits.
- Poison a refund/state map with a user-controlled identifier lacking an occupancy check, then overwrite a prior entry.
- Pump a tracked value (liquidity, ticket count, share supply) past a threshold that gates parameter updates, bricking legitimate updates until decay.

---

## Gate 0 Validation

> Adapted from `.../references/judging.md` — every finding passes four sequential gates. Fail any gate → rejected or demoted. Later gates are not evaluated for failed findings. We are not defending the code; we verify the attacker's claimed exploit actually fires end-to-end.

### The Four Gates

| Gate | Question | Reject / Demote | Clear |
| --- | --- | --- | --- |
| **1 — Attack execution** | Trace the claimed path; does any guard interrupt it before harm? | A specific guard/check/modifier on the path interrupts it → REJECT (or DEMOTE if a smell remains) | Interruption speculative → continue |
| **2 — Reachability** | Does the vulnerable state exist in a live deployment? | Structurally impossible → REJECT; needs privileged action → DEMOTE | Reachable via normal usage / common token behavior |
| **3 — Trigger** | Can an unprivileged actor execute it? | Only trusted roles → DEMOTE | Unprivileged actor triggers profitably |
| **4 — Impact** | Material harm to an identifiable victim? | Self-harm only → REJECT; dust, no compounding → DEMOTE | Material loss to identifiable victim → CONFIRMED |

### Admin-Action Rule
Reject admin/owner findings unless an **unprivileged amplifier** is named: **race** (admin sets X mid-flow; user exploits the window), **retroactive sweep** (update rewrites an already-credited pending value), **asymmetric formula** (admin output chains into a formula an unprivileged actor profits from), or **access gap** (missing/tautological guard, missing init guard — the access mechanism itself is the bug). No amplifier → REJECTED, not even a LEAD.

### Confidence Score
Start at **100**; deduct partial attack path **-20**, bounded non-compounding impact **-15**, specific-but-achievable state **-10**. **≥ 80** → description + fix; **< 80** → description only.

### Safe Patterns (do not flag)
- `unchecked` in 0.8+ (but verify the reasoning), explicit narrowing casts in 0.8+ (revert on overflow).
- `MINIMUM_LIQUIDITY` burn on first deposit; SafeERC20; `nonReentrant` (only flag cross-contract); two-step admin transfer.
- Consistent protocol-favoring rounding unless compounding or zero-rounding.
- Linter/compiler issues, gas micro-opts, naming, NatSpec, missing events, centralization without an exploit path.

### Lead Promotion
- **Cross-contract echo**: same root cause as a FINDING in one contract → promote in every contract with the identical pattern.
- **Multi-agent convergence**: 2+ agents flagged the same area, lead demoted (not rejected) → promote at confidence 75.
- **Partial-path completion**: only a partial trace, but reachable and unguarded → promote at confidence 75, description only.

### Every finding must state
1. **What can the attacker do right now?** (concrete trace with values)
2. **What does the victim lose?** (quantified value at risk / TVL)
3. **Can it be reproduced in 10 minutes from a clean state?** (deterministic PoC, no luck/timing dependence)

---

## Real Impact Examples

*Grounded in the curated source knowledge — no report IDs or external URLs are asserted.*

### Scenario A: First-Depositor Inflation Drains Later Depositors (Vault / ERC-4626)
Attacker deposits 1 wei as first depositor, then donates a large amount directly to the vault to inflate `convertToAssets()`. Later depositors' share calculations round to zero shares (`amount * totalSupply / totalAssets < 1`), so their deposits become claimable by the attacker. Fixes require `MINIMUM_LIQUIDITY` / dead-share seeding. Root cause: share-exchange-rate accounting that can be inflated with an unrestricted donation (`smart-contract-agent.md`, `math-precision-agent.md`).

### Scenario B: Cross-Function Reentrancy via Stale Price View (Lending)
A lending contract updates collateral state after an external call; a read-only `getRate()` view returns stale state during the reentrant call, and liquidation reads price and balance at different points in one transaction. Attacker reenters with stale price, liquidates a healthy position at a favorable rate, and extracts the collateral difference. Both functions need `nonReentrant`; price must be read atomically (`smart-contract-agent.md`, `invariant-agent.md`).

### Scenario C: Uninitialized Implementation = Free Admin Claim (Proxy)
The implementation contract's `initialize()` is callable directly (not just through the proxy). Attacker calls it on the implementation, sets themselves as owner, then upgrades to a malicious implementation or drains proxy-held funds. Probe: call `initialize(attacker)` on both implementation and proxy addresses (`smart-contract-agent.md`).

### Scenario D: Signature Cross-Chain Replay (Permit / Meta-transaction)
Signed message omits `chainId` and `nonce`. Attacker copies a valid permit from chain A and replays it on chain B where the same user holds funds, draining the B balance. Fix binds `domainSeparator` with `chainId` and enforces a per-user nonce (`smart-contract-agent.md`).

### Scenario E: Bridge Drain via Single Attester (Cross-chain / Aptos CCTP)
`num_required_attestations == 1` means a single compromised attester key can authorize arbitrary burns/mints; `replace_attester` can be front-run to insert the attacker's key; `remove_minter` leaves orphaned allowance spendable. Fix requires threshold attestation, a rotation delay, and allowance reset (`smart-contract-agent.md`, `attack-vectors/smart-contract-vectors.md`).

### Scenario F: Hidden Mint / Honeypot Rug (Meme Coin)
Deployer retains mint authority and mints post-launch, dumping on the LP; or freeze authority / mutable transfer hook blocks sells while buys work. On Solana, `solana account <MINT>` showing `mint_authority: Some(pubkey)` or `freeze_authority: Some(pubkey)` is a critical kill signal. Fix revokes all authorities (`None`), burns/locks LP, caps supply (`skills/meme-coin-audit/SKILL.md`).

### Scenario G: Solana Account Substitution via Missing Constraints
An instruction accepts a vault account without `#[account(mut)]`, owner check, `has_one`, or `seeds/bump` validation. Attacker substitutes an arbitrary account they own and withdraws funds. Fix adds all Anchor constraints and verifies CPI program IDs (`smart-contract-agent.md`, `attack-vectors/smart-contract-vectors.md`).

### Scenario H: Move Capability Misuse / Double-Spend (Sui)
Generic `T` unconstrained lets a caller pass an arbitrary coin type; `coin::value()` reads a balance without `coin::extract()`, allowing a double-spend; `borrow_global_mut` on a resource not owned by the caller mutates another account's state. Real-world references in the source include Cetus, Thala, and KriyaDEX exploit patterns (`skills/smart-contract-audit/SKILL.md` → `move-checks.md`, `attack-vectors/smart-contract-vectors.md`).

### Scenario I: Admin Rebalance Sandwiched (Asymmetry / Trust-Gap)
An admin-only `setPositionWidth`/`unpause` mirrors the same liquidity-rebalancing flow as a guarded `deposit` but omits the `onlyCompPeriods` guard and slippage limit. An unprivileged user watches the mempool, sandwiches the admin transaction, and drains TVL on the parameter change. The admin action alone is not reportable — the **unprivileged amplifier** (the sandwich) is what clears Gate 3 (`.../asymmetry-agent.md`, `.../trust-gap-agent.md`).

### Scenario J: Residual Approval Drift (Numerical Gap)
A bridge helper approves `out + fee` but consumes `out − fee`, leaving `2·fee` residual allowance per call. After N calls, cumulative drift is `N · 2 · fee`; an attacker with residual approval drains the accumulated difference from a shared allowance bucket. The symptom only emerges when precision (two different fee directions) and invariants (allowance should equal consumed amount) are reasoned together (`.../numerical-gap-agent.md`).

### Scenario K: Void-Return Token Silently Corrupts State (Boundary)
A vault wraps `require(token.transferFrom(user, address(this), amount))` around an arbitrary user-supplied token. A USDT-style void-return token makes the call revert on `require(bool)` — or a false-returning token (Tether Gold class) returns `false` and silently corrupts accounting because the return value is ignored. Deposit proceeds with no funds received; later withdrawals are backed by nothing (`.../boundary-agent.md`, `.../economic-security-agent.md`).

---

## Source Skill Lineage

All paths below are taken verbatim from the `## SOURCE:` headers of the condensed digest. Each entry notes the unique knowledge it contributes. The full 221-file / 1,924-section corpus is in `references/source-knowledge.md`.

### smart-contract-audit family
- **`hunt-skills/bountyforge/skills/smart-contract-audit/SKILL.md`** — Master framework: scope/detection workflow, chain+protocol-type detection, three/four-layer reading orders per language, knowledge-base layout (`fv-sol-X`, `fv-anc-X`, `fv-vyp-X`, `fv-ton-X`, `fv-mov-X`), debug-log format, threat-model and PoC approach.

### web3-audit family
- **`hunt-skills/bountyforge/references/web3-quickstart.md`** — 7-platform support matrix and the copy-paste "first 30 minutes" grep arsenal (access control, reentrancy, price, flash loans, proxy, accounting, signatures, ERC4626, roles, unsafe math).
- **`hunt-skills/bountyforge/skills/pashov/solidity-auditor/README.md`** — Fast-audit operating advice: target the 2–5 hot contracts, run 2–3 non-deterministic passes.
- **`hunt-skills/bountyforge/skills/pashov/solidity-auditor/SKILL.md`** — 12-agent parallel orchestration: exclude patterns, mode selection, bundle construction, gap-hunter prompts, dedup workflow.

### web3-bug-hunting family
- **`hunt-skills/bountyforge/references/attack-vectors/smart-contract-vectors.md`** — Cross-chain taxonomy by language: EVM, Move/Aptos, Solana/Anchor, TRON, and bridge attack vectors in one condensed checklist.
- **`hunt-skills/bountyforge/references/hacking-agents/smart-contract-agent.md`** — "Invariants first" doctrine, WILD MODE cheat-the-engine heuristics, and per-chain (EVM/Move/Solana/TRON/CCTP) concrete probes plus output fields.

### meme-coin-audit family
- **`hunt-skills/bountyforge/skills/meme-coin-audit/SKILL.md`** — Pre-dive hard/soft kill signals, the "retained authority IS the rug vector" rule, 8 bug classes with greps, on-chain Solana checks, scanner and Foundry PoC template.

### pashov solidity-auditor — specialist lens files (web3-audit / web3-bug-hunting)
- **`hunt-skills/bountyforge/skills/pashov/solidity-auditor/references/hacking-agents/asymmetry-agent.md`** — Paired-surface and branch-symmetry diffing; storage-write symmetry; admin-variant omissions (Beefy pattern).
- **`hunt-skills/bountyforge/skills/pashov/solidity-auditor/references/hacking-agents/boundary-agent.md`** — Disciplined boundary enumeration: no-code/non-standard token/zero-max/return-handling corner cases, sentinel walks, `bytes`/`abi.decode` corruption.
- **`hunt-skills/bountyforge/skills/pashov/solidity-auditor/references/hacking-agents/economic-security-agent.md`** — Dependency-breaking, token misbehavior, atomic value extraction, ERC-compliance and sentinel-abuse economics; "no numbers = LEAD."
- **`hunt-skills/bountyforge/skills/pashov/solidity-auditor/references/hacking-agents/execution-trace-agent.md`** — Within/across-transaction flow: parameter divergence, value leaks, encoding mismatches, stale reads, partial state updates, interleaving.
- **`hunt-skills/bountyforge/skills/pashov/solidity-auditor/references/hacking-agents/first-principles-agent.md`** — Assumption extraction and violation; "do not pattern-match," catch bugs with no name.
- **`hunt-skills/bountyforge/skills/pashov/solidity-auditor/references/hacking-agents/flow-gap-agent.md`** — Bugs requiring execution × periphery × first-principles seams; three-way control/periphery/purpose chains.
- **`hunt-skills/bountyforge/skills/pashov/solidity-auditor/references/hacking-agents/invariant-agent.md`** — Conservation-law and state-coupling mapping; cap bypasses, cache-then-mutate, timer resets, emergency-transition breaks.
- **`hunt-skills/bountyforge/skills/pashov/solidity-auditor/references/hacking-agents/math-precision-agent.md`** — Rounding direction, zero-round theft, truncation amplification, overflow intermediates, decimals, downcasts, sign/bitmask bugs.
- **`hunt-skills/bountyforge/skills/pashov/solidity-auditor/references/hacking-agents/numerical-gap-agent.md`** — Seams between precision × invariant × boundary; N-segment scaling, rate drift, residual-allowance drift.
- **`hunt-skills/bountyforge/skills/pashov/solidity-auditor/references/hacking-agents/periphery-agent.md`** — Libraries/helpers/encoders: unvalidated inputs, corrupt returns, assembly byte-width, truncated recipients, ERC165 fallback, single-block oracles.
- **`hunt-skills/bountyforge/skills/pashov/solidity-auditor/references/hacking-agents/trust-gap-agent.md`** — Seams between access control × economics × asymmetry; admin setters redirecting in-flight value, spot-vs-TWAP asymmetry.
- **`hunt-skills/bountyforge/skills/pashov/solidity-auditor/references/hacking-agents/shared-rules.md`** — Bundle protocol, mandatory Feynman/Socratic/Inversion markers, cross-contract pattern weaponization, FINDING/LEAD output format.

### rust-smart-contract-hack / audit-process support (pashov references)
- **`hunt-skills/bountyforge/skills/pashov/solidity-auditor/references/judging.md`** — Four sequential validation gates, admin-action amplifier rule, confidence scoring, safe patterns, lead promotion, do-not-report list.
- **`hunt-skills/bountyforge/skills/pashov/solidity-auditor/references/report-formatting.md`** — Report path, scope table, confidence-sorted findings, diff fixes, leads section, AI disclaimer.
- **`hunt-skills/bountyforge/skills/pashov/solidity-auditor/references/senior-auditor-sop.md`** — Senior mindset: Feynman test, Socratic questioning, Inversion; when to reach for each tool; "trust your discomfort."

> These 22 files are the representative sample surfaced in the condensed digest. The rust-smart-contract-hack and sui-bug-hunting families (Solana/Anchor and Sui/Move deep-dives) are fully represented in `references/source-knowledge.md` alongside the other 199 source files.

---

## Related Skills & Chains

- **`hunt-ssrf`-style OOB discipline → on-chain equivalent**: just as blind SSRF needs an OOB callback, a smart-contract finding needs a concrete on-chain trace/proof — "OOB-or-it-didn't-happen" becomes "proof-or-it's-a-LEAD."
- **`hunt-rce` / exploit chains**: oracle manipulation → liquidation cascade → protocol insolvency; flash loan → price manipulation → under-collateralized borrow.
- **`web3-audit` / `web3-bug-hunting`**: reuse the grep arsenal and invariant-map workflow as the first-pass scanner before deep specialist lenses.
- **`meme-coin-audit`**: token-specific kill screen and authority-retention checks; chain primitive retained mint/freeze authority → rug → LP drain.
- **`rust-smart-contract-hack`**: Solana/Anchor account-validation and CPI probes; chain primitive missing `has_one`/signer → account substitution → fund drain.
- **`sui-bug-hunting`**: Move capability/object-ownership and `coin::extract` probes; chain primitive unconstrained generic `T` → arbitrary token → double-spend.
- **`triage-validation`**: the four gates + confidence score are the Web3 analog of report triage — no proof, no finding.

---

**Summary:** This skill turns 221 curated Web3/smart-contract source files into a disciplined hunting workflow: detect chain and protocol type, map invariants before code, cheat the engine across identity/state/price/authority/time, sweep with specialist lenses, and promote only findings that survive the four validation gates with concrete proof. Grounded in the condensed digest; the full 1,924-section corpus is in `references/source-knowledge.md`.
