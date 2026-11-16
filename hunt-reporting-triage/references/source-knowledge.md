# MERGED SOURCE KNOWLEDGE: reporting-triage

335 unique sections from 39 source files. Each section appears in exactly one target.


## SOURCE: hunt-skills/bountyforge/references/reporting.md

# Reporting — Defensive-Proof Format & Submission Rules

> Split from SKILL.md v4.1.0. Load when writing the report. Platform templates: `skills/report-writing/SKILL.md` + `references/report-formatting.md`.

---

## Canonical Defensive-Proof Report Format

Every report MUST follow this exact structure to preempt triager rejection. See also `references/report-formatting.md`.

```

## Scope & Engagement Gate
- **Engagement Context:** <BBP | VDP | Direct Vendor Disclosure | Internal Red Team / Pentest>
- **Target Asset:** <Exact domain, IP, repo, contract, or binary>
- **In Scope:** <Yes / N/A (Independent Research)>
- **Explicit Exclusions:** <Check program/vendor policy for excluded assets or classes; None if self-hosted/pentest>
- **Governing Rule / Policy:** <Quote program policy clause, security advisory terms, or Audit Rules of Engagement>
- **Impact & Boundary Threshold:** <Demonstrated security boundary crossed or business risk proven>
- **Evidence Supporting Eligibility:** <Concrete demonstrated observations proving impact>

**Severity:** <Critical | High | Medium | Low>
**Vulnerability Type:** <Primary CWE / Class>
**Affected Component:** <Component / Endpoint / Daemon Listener> (`<path/port/URL>`)
---

## Summary
<3–5 sentences. Covers: what the vulnerability is, where it lives, how it is triggered, and what an attacker gains. Explicitly state what is NOT claimed if scope/severity is sensitive. No hedging. Present tense.>

---

## Control Plane vs Unauthenticated Listener Architecture (Path A vs Path B)
- **Path A (Legitimate Intended Flow):** Requires valid authentication credentials (e.g. Bearer token, API key, OAuth state).
- **Path B (Unauthorized Flow Demonstrated):** Accepts equivalent operations directly without presenting any credential or authorization token.
- **Security Boundary Crossed:** <Explicit description of the authorization barrier bypassed>

---

## Absent Credential Evidence Grid
| Credential / Artifact | Present in Attack Request? | Verification Evidence |
|-----------------------|---------------------------|-----------------------|
| Authorization Header  | ❌ No | HEADERS frame contains only standard HTTP pseudo-headers |
| Bearer / API Token    | ❌ No | `/proc/self/environ` contains no TOKEN/KEY/SECRET variables |
| Session Cookie        | ❌ No | No Cookie header; cookie jar empty |
| Session File          | ❌ No | No token files in local filesystem or shared run directories |
| mTLS Certificate      | ❌ No | Connection opened over standard unauthenticated cleartext TCP / TLS |
| Capability Token      | ❌ No | No capability payload or signed request headers |

---

## Demonstrated vs. Inferred Audit Matrix
| Claim | Verification Status | Evidence / Reasoning |
|-------|--------------------|----------------------|
| <Target accepts unauthenticated request> | Demonstrated | <Executed request succeeded with zero headers> |
| <Execution context equals SDK capability> | Demonstrated | <Executed `id` returning same UID/GID as SDK> |
| <Guest isolation boundary crossed> | Demonstrated / Inferred | <Exact boundary verification> |
| <Host escape / system takeover> | Unproven | <Explicitly NOT claimed unless directly executed> |

---

### 1. <Root cause label>
- <Tight bullet — one clause each, referencing exact code file / line / port>
- <No prose paragraphs>

---

## Steps to Reproduce
1. <Step 1: Context / setup>
2. <Step 2: Copy-pasteable curl or script>
3. <Step 3: Execute and observe response>

**Expected (if secure):** <What secure behavior / auth check should happen>
**Actual:** <What the vulnerable endpoint does>

---

### Step 1: <Short action label>
<sentence describing what this step demonstrates.>
[Screenshot or code block]

---

## Security Impact
- **Demonstrated Capability:** An attacker with <access level> can <exact action> without credentials.
- **Program Policy Threshold:** Meets program policy requirement by demonstrating <policy eligibility evidence>.

---

## Recommended Fix
1. <Actionable fix step 1 — e.g., enforce authentication on listener or bind to isolated interface>
2. <Actionable fix step 2>
```

### Format Rules (non-negotiable)
- **Zero fluff.** Every sentence must carry technical weight.
- **No hedging.** Never write "may", "could potentially", "it is possible that". If the code allows it, state it as fact.
- **Present tense throughout.**
- **H1** for the report title. **H2** for all top-level sections.
- **`---`** as divider after metadata strip and between major sections.
- No tables. No collapsible sections. No emoji.
- PoC steps: numbered, one-line action header (H3), one sentence of context, then screenshot or code block.

### Platform Adaptations

| Platform | Additional requirement |
|----------|----------------------|
| `h1` | Append CVSS 3.1 vector string as code block if `--cvss` |
| `immunefi` | Add **Asset Type**, **Blockchain/Tech Stack**, **Vulnerability Category** |
| `bugcrowd` | Use Bugcrowd severity labels (P1/P2/P3/P4) alongside plain label |
| `intigriti` | Add **Impact** tag field to metadata strip |

## Report Title Formula
```
[Bug Class] in [Exact Endpoint/Feature] allows [attacker role] to [impact] [victim scope]
```
**Good:** `IDOR in /api/v2/invoices/{id} allows authenticated user to read any customer's invoice data`
**Bad:** `IDOR vulnerability found`

## Impact Statement Formula
```
An [attacker with X access level] can [exact action] by [method], resulting in [business harm].
This requires [prerequisites] and leaves [detection/reversibility].
```

## Severity Escalation Language
| Program Says | You Counter With |
|---|---|
| "Requires authentication" | "Attacker needs only a free account (no special role)" |
| "Limited impact" | "Affects [N] users / [PII type] / [$ amount]" |
| "Already known" | "Show me the report number — I searched and found none" |
| "By design" | "Show me the documentation that states this is intended" |
| "Low CVSS score" | "CVSS doesn't account for business impact — attacker can steal [X]" |

---

## Confidence Scoring

Start at **100**, deduct:
- Partial attack path: **-20**
- Bounded, non-compounding impact: **-15**
- Requires specific (but achievable) state: **-10**
- Requires user interaction: **-10**
- Fix already partially mitigates: **-10**

Confidence ≥ 80 → full description + PoC + fix.
Confidence 60–79 → description + partial PoC.
Below 60 → LEAD only (no fix, no PoC).

---

## ALWAYS REJECTED — Never Submit These

> **Wild-mode note:** this list kills standalone SUBMISSIONS, not hunting avenues. Every entry below has a chain partner (see "Conditionally Valid With Chain" below) — if you found one, find the partner before dropping it. Open redirect alone → N/A. Open redirect → OAuth code theft → ATO. The list is the chain menu, not a stop sign.

Missing CSP/HSTS/security headers, missing SPF/DKIM/DMARC, GraphQL introspection alone, banner/version disclosure without working CVE exploit, clickjacking on non-sensitive pages, tabnabbing, CSV injection, CORS wildcard without credential exfil PoC, logout CSRF, self-XSS, open redirect alone, OAuth client_secret in mobile app, SSRF DNS-ping only, host header injection alone, no rate limit on non-critical forms, session not invalidated on logout, concurrent sessions, internal IP disclosure, mixed content, SSL weak ciphers, missing HttpOnly/Secure cookie flags alone, broken external links, pre-account takeover, autocomplete on password fields.

---

## HIGH-VALUE TARGET PROFILES (From H100 Analysis)

Patterns extracted from 100 highest-upvoted HackerOne reports. Use for target selection and prioritization.

### Tier 1: Highest ROI Targets

**GitLab (12 reports, $134K total bounty)**
- Biggest attack surface of any program — code hosting, CI/CD, wiki, imports
- Top bug classes: RCE (4), File Read/Write (3), SSRF, Data Leak, SSTI
- Key attack surfaces:
  - **Project import** — SSRF, path traversal, file read via UploadsRewriter
  - **Markdown/Wiki rendering** — Kramdown RCE, stored XSS, template injection
  - **File uploads** — path traversal, webshell, ExifTool RCE
  - **CI/CD pipelines** — runner token exposure, pipeline job execution
  - **Merge requests** — code review features bypass file restrictions
- Hunting strategy: Focus on import/export features, check for path traversal in any file copy/move operation

**Shopify (8 reports, $50K total bounty)**
- Top bug classes: Privilege Escalation (4), SSRF, OAuth, Credential Leak, SSTI
- Key attack surfaces:
  - **Email confirmation flow** — bypass leads to full store takeover via SSO
  - **Electron apps** — .env files in packaged apps leak GitHub tokens
  - **Third-party apps** — OAuth misconfigurations in app integrations
  - **Stocky app** — OAuth token theft via redirect_uri manipulation
- Hunting strategy: Download all Shopify apps, extract .env from asar files, check OAuth flows

**PayPal (6 reports, $93.9K total bounty — highest $/report)**
- Top bug classes: XSS (2), RCE, Token Leak, DoS, IDOR
- Key attack surfaces:
  - **Login page** — cache poisoning → stored XSS on paypal.com/signin
  - **Security challenge flow** — token leaks email + plaintext password
  - **npm packages** — internal packages published to public registry
  - **Business management API** — IDOR on user management endpoints
- Hunting strategy: Focus on auth flows, cache poisoning, supply chain

**Snapchat (7 reports, $65K total bounty)**
- Top bug classes: Infrastructure Misconfig (3), RCE, Auth Bypass, SSRF
- Key attack surfaces:
  - **Internal tools** — Jenkins, Grafana, CI dashboards exposed
  - **Kubernetes** — API server exposed to internet, no auth
  - **Content management** — delete any user's spotlight content
  - **GraphQL** — information disclosure via introspection
- Hunting strategy: Scan for exposed admin panels, K8s APIs, internal dashboards

### Tier 2: Consistent Payouts

**Valve (5 reports, $40K)**
- Game client RCE (buffer overflow, XSS in chat), SQLi, payment tampering
- Attack surface: Steam client, game servers, report generation API
- Key: Client-side parsing of untrusted data (server info, chat messages)

**X / xAI (4 reports, $20.16K)**
- Pre-auth RCE via VPN (Pulse Secure 1-day), auth bypass, CRLF injection
- Attack surface: VPN infrastructure, Digits API, web properties
- Key: Monitor VPN vendor patches, test immediately after disclosure

**Uber (3 reports, $40.4K)**
- Info disclosure (bonjour.uber.com RPC), OAuth chain, leaked certificates
- Attack surface: Internal microservices, mobile APIs, OAuth flows
- Key: Check old/mobile API versions, leaked certs in git history

### Tier 3: Quick Wins

**Snapchat infrastructure** — Jenkins, Grafana, K8s API = instant $10-25K
**Starbucks** — SQLi on web apps + leaked credentials in repos = consistent findings
**Razer** — SQLi + command injection on gaming web portals
**Mail.ru** — SQLi, file upload, memory disclosure
**LY Corp (LINE)** — HTTP smuggling, OAuth misconfig, privilege escalation

### Cross-Target Patterns

| Attack Vector | Programs Hit | Avg Bounty |
|---------------|-------------|------------|
| Leaked tokens in code/apps | Shopify, Starbucks, Snapchat, Superhuman | $10-50K |
| HTTP smuggling → session hijack | Slack, LY Corp, Zomato, New Relic | $0-6.5K |
| Infrastructure misconfig (Jenkins/K8s) | Snapchat | $10-25K |
| GraphQL missing auth | HackerOne | $0-12.5K |
| Email confirmation bypass | Shopify | $0-15K |
| Cache poisoning → XSS | PayPal | $18-20K |
| File upload → RCE | Semrush, Starbucks, GitLab | $0-20K |
| npm/supply chain | PayPal, LY Corp | $11-30K |
| SQLi (classic) | Starbucks, Razer, Valve, Mail.ru, GSA | $0-25K |

## Conditionally Valid With Chain

| Low Finding | + Chain | = Valid Bug |
|------------|---------|-------------|
| Open redirect | + OAuth code theft | ATO |
| Clickjacking | + sensitive action + PoC | Account action |
| CORS wildcard | + credentialed exfil | Data theft |
| CSRF | + sensitive state change | Account takeover |
| No rate limit | + OTP brute force | ATO |
| SSRF (DNS only) | + internal access proof | Internal network access |
| Host header injection | + password reset poisoning | ATO |
| Self-XSS | + login CSRF | Stored XSS on victim |

---

## Safe Patterns (Do Not Flag)

**Smart contracts:** `unchecked` in Solidity 0.8+ with correct reasoning, explicit narrowing casts in 0.8+, MINIMUM_LIQUIDITY burn on first deposit, `SafeERC20`, `nonReentrant` (flag only cross-contract), two-step admin transfer, consistent protocol-favoring rounding without compounding.

**Web/API:** Rate limiting that genuinely prevents exploitation, CSRF tokens that are properly validated, self-XSS without escalation path, logout CSRF without session fixation, non-sensitive information disclosure (stack traces in dev mode only).

**Infrastructure/Nodes:** Unauthenticated operator RPC (ecosystem standard), plaintext local signer/CL↔EL communication, default bind to 0.0.0.0 (dev convenience), JWT without `exp` when `iat` freshness enforced, version/health endpoints without auth, no CORS headers on non-browser APIs.

**General:** Operator configuration parameters treated as attacker input, "add rate limiting" without amplification attack, "use checked_X instead of saturating_X" when upstream check exists, error messages containing HTTP status codes or generic library errors (not credentials/PII).

---


## SOURCE: hunt-skills/bountyforge/references/validation.md

# Validation — Smart-Contract Reasoning, 7-Question Gate, Triage

> Split from SKILL.md v4.1.0. Load before writing ANY report. Compact gate: `skills/triage-validation/SKILL.md`. Supervisor detail: `references/supervisor.md`.

---

## SMART CONTRACT REASONING — 5-LAYER PRIORITY (applies to ALL contract hunting, before any gate)

**First: map the protocol and write `invariants.md` (Rule 1).** Before any layer below, list the protocol's solvency/supply/permission/price invariants and run the economic loop — `MAP → INVARIANT → IDENTIFY ASSUMPTION → FIND CONTROLLED VARIABLE → MUTATE → OBSERVE → CHECK INVARIANT → CHAIN → CALCULATE VALUE AT RISK` (full track: `references/methodology.md` — Smart-Contract Track). Every finding names the invariant it breaks and the value it puts at risk.

The criticals on audited code are rarely in the code. Rank effort by where bugs actually live:

**Layer 1 — Deployment config, not contract code (biggest source of criticals on audited code).** The invariant is enforced in Solidity but violated at deploy time:
- Rate provider / oracle pointed at a manipulatable spot price (Curve pool, short-window Uniswap TWAP, Balancer pool) instead of Chainlink → exchange rate manipulation → share-price theft
- Decimal mismatch: rate provider returns 6 decimals where the accountant assumes 18 (10^12 error). Scaling helpers (e.g., `GenericRateProviderWithDecimalScaling`) only scale if `inputDecimals`/`outputDecimals` are set correctly at deploy
- Ownership not actually renounced (`transferOwnership(address(0))` skipped), or `STRATEGIST_ROLE` held by a hot EOA
- Two vaults sharing one accountant; a `manageRoot` computed against a stale decoder
- **You CANNOT see this from source. It needs the live addresses + mainnet RPC.** When the code reads clean, request the deploy addresses and fork the chain — that IS the attack surface.

**Layer 2 — Fork mainnet and run invariant fuzzers.** Criticals are found by simulating the state machine against live state (Foundry fork tests + `invariant_` fuzzing), not by more reading. Core invariants:
- `totalAssets() == Σ(balances valued via getRate())` — break this → mint/drain
- Share price monotonicity across deposit/withdraw/vest/postLoss sequences
- First-depositor / donation inflation: `mulDivDown(ONE_SHARE, getRate())`; a donation or `claimFees` timing that shifts `getRate()` between enter and exit = classic repeatable-loss critical

**Layer 3 — The integration layer, not the target.** The vault holds real tokens with real quirks; a decoder correct for the "canonical" ABI is wrong for the deployed variant:
- stETH / rebasing / fee-on-transfer / 18-vs-6 tokens where a balance read or transfer assumption breaks
- A token that's a proxy with different `decimals()`, or a token with a `beforeTokenTransfer` hook that re-enters
- Read-only reentrancy via `getRate()` reading an external contract whose state can be manipulated in the same tx

**Layer 4 — Chase new deployments and upgrades.** Protocols add tellers/decoders/adapters continuously; the newly added, unaudited contract is where the critical lives. A hardened adapter (fee/extension bounds added post-finding) means the NEXT one won't be. Watch the deployer address for fresh contracts and audit them before the program updates scope.

**Layer 5 — Chain a medium into a critical.** A single small bug is a Medium; the same bug made repeatable is a Critical. A 1-wei accounting drift in `payoutSplits` (balance - 1) or a rounding direction in `mulDivDown` compounded over N deposits becomes an extractable loss.

**The uncomfortable truth:** if the audited code is sound, the critical is at Layer 1 (config/oracle targets) or Layer 2 (fork-fuzzing `getRate()` against a manipulatable feed) — both need live chain access, not more file reads. When file reads run dry: request deployment addresses + RPC, fork, and fuzz. That's not a limitation; that's the attack surface.

---

## The 7-Question Gate & Red Team Triage Engine (Run BEFORE Writing ANY Report)

> **HUNT vs REPORT (wild mode):** These gates are the LAST step of the pipeline — they filter what gets SUBMITTED. They are never run during the hunt, never kill a probe, and never delete a lead. A finding that fails a gate is demoted to a LEAD with its payload and its chain partners, and retested on the next pass. **Firing a payload is always allowed; the gates only decide what a human triager reads.**
>
> **5-STEP METHODOLOGY SPINE:** `Program policy → Scope → Security boundary → Demonstrated impact → Severity`
>
> **RED TEAM TRIAGE ENGINE:** Before drafting a report, apply `references/supervisor.md` — BountyForge attacks its own finding across **10 Red Team Attack Questions**:
> 1. *Scope:* Is the exact asset/function in scope?
> 2. *Policy:* Is this vulnerability class explicitly excluded?
> 3. *Precondition:* What does the attacker actually need?
> 4. *Authentication:* What credential/authorization is supposed to exist?
> 5. *Path A:* What is the legitimate intended flow?
> 6. *Path B:* What unauthorized flow was demonstrated?
> 7. *Boundary:* What security boundary is crossed?
> 8. *Impact:* What concrete capability does the attacker gain?
> 9. *Alternative explanation:* What is the strongest reasonable triager rebuttal?
> 10. *Evidence:* What observation defeats that rebuttal?
>
> **THE RED TEAM RULE:** If the finding cannot survive the strongest plausible triager objection, DO NOT promote it to a report.
>
> **DEMONSTRATED VS INFERRED RULE:** Explicitly categorize every claim as **Demonstrated** (verified via executed PoC), **Inferred** (suggested by code/arch but unexecuted), or **Unproven** (speculative). Never allow report drift from a demonstrated primitive to an unproven claim (e.g. guest execution primitive drifting into unproven host escape).

All 7 must be YES. Any NO → STOP. See also `references/supervisor.md` for detailed triage flow and `references/al-mizaan-gates.md` for deep validation methodology.

### Q1: Can I exploit this RIGHT NOW with a real PoC?
Write the exact HTTP request or test case. If you cannot produce a working trigger → KILL IT.

### Q3: Is the impact concrete (money, PII, ATO, RCE)?
"Technically possible" is not impact. "I read victim's SSN" is impact. Quantify the harm.

### ⛓️ 7-Question Gate — Smart Contract Track (USE FOR ALL CONTRACT FINDINGS)

The web2 gate kills good contract bugs — "real user", "PII/ATO/RCE" don't translate to a DeFi protocol. For `--solidity` / `--move` / `--solana` findings, run THIS gate instead. All 7 must be YES. If a finding passes, the Al-Mizaan deep gates below are optional, not required.

### Q1 (SC): Can I exploit this RIGHT NOW with a working PoC?
Write a running Foundry/Hardhat test (or fork script) that triggers the path and asserts the damage. Static code observation, "this line looks wrong", or unexecuted speculation → KILL IT. PoC must execute against a fork of the deployed chain or a local EVM node.

**Counter-pattern (Gate 1):** "It's documented" / "it matches upstream design" is NOT an automatic refutation. Rejecting on that requires actually having read the upstream source — citing another protocol's behavior without seeing its code (e.g., "Camelot does the same with xGRAIL") is a miss, not a defense. Docs describe intent; deployed bytecode is reality. If you reject on documentation, show the upstream code doing the same thing.

### Q2 (SC): Is the triggerer someone the protocol does NOT intend to be the actor?
Ask: "Who does the protocol DESIGN to call this?" If only `onlyOwner`/governance/`onlyRole` can trigger it and it's working as designed → intended, KILL. If ANY other party (user, third-party contract, griefer, LP depositor) can reach the vulnerable path — even with clever conditions — it's valid. Trusted-actor trigger WITH a governance bypass still passes.

**Counter-pattern (Gate 2):** "Requires an oracle misreport" is NOT an auto-kill. Before rejecting, check for an honest-path route to the same vulnerable state (e.g., the Lido `onchainTotalValueOnRefSlot` case — the state was reachable with HONEST oracle data, making the "oracle manipulation" precondition unnecessary). If an honest path exists, the finding stands without the oracle caveat.

**Counter-pattern (Gate 3):** "Requires the exiting holder's cooperation" is NOT an auto-kill when the state transition is public and observable on-chain (e.g., an xSilo `totalSupply → 0` after exit). The attacker can front-run the public transition — that makes it attacker-triggerable, not victim-cooperative. Precondition = a transaction the victim will unavoidably submit, not a deliberate action on their part.

### Q3 (SC): Is impact concrete in protocol-native terms?
"Technically possible" is not impact. Quantify: exact funds stolen/locked (wei, token amounts, USD), accounting desync amount, invariant breach (name the invariant verbatim from the code/docs), permanent DoS of someone's funds, oracle manipulation with real profit margin. No number = no finding.

**Counter-pattern (Gate 4):** Split self-harm into actor-scoped legs. An attack that looks like "self-harm" often has SEPARATE victims per leg: the exiter's penalty loss is evaluated as its own leg, and the front-runner's captured residual is another leg — one leg being self-inflicted does NOT kill the other leg's valid impact. Name the victim for every leg before rejecting as "self-harm."

### Q4 (SC): Is this in scope per the program policy?
Deployed contract on the listed chain, and the exact version verified on-chain (etherscan/solscan match the audited source). Testnets, old unpinned versions, `interfaces/`, `lib/`, `mocks/`, `*.t.sol`, `*Mock*` → KILL.

### Q5 (SC): Did I check known-issue history for duplicates?
Search: Immunefi/Sherlock/Code4rena contest history for this protocol, ALL prior audit reports (in the repo's `audits/` or docs), `CHANGELOG.md`, README "known issues" sections, and previous bounty submissions. Duplicate → KILL.

### Q6 (SC): Is this NOT on the contract always-rejected list?
- Theoretical / no working PoC → KILL
- Trusted-actor-only with no bypass → KILL
- View/read-only fn returning wrong value with no downstream effect → KILL
- Admin backdoor behaving as documented → KILL
- MEV-dependence the protocol explicitly accepts (e.g., sandwichable AMMs) → KILL unless the profit exceeds documented slippage bounds
- Sub-$1 dust profit that breaks no invariant → KILL (unless part of a bigger chain)

### Q7 (SC): Would a DeFi-literate judge say "yes, that's a real bug"?
Read it as an Immunefi/Sherlock judge: quote the invariant, trace the exact exploitable call path, show the PoC result. If the judge could argue "edge case, working as intended" and you can't pre-kill that argument → KILL.

**Smart contract quick-kill rules (before you even write the report):**
- No `forge test` PoC against a fork → DEMOTE to lead, not a finding
- Trigger only via `onlyOwner`/governance → KILL unless you have a governance bypass
- Code in `lib/`, `interfaces/`, `mocks/`, `test/` → KILL (scanner noise)
- "Docs say X but code does Y" → code is authoritative, report the code behavior
- Compiler version is old but function unreachable → KILL (reachability before severity)
- **Trigger proven but impact untraced → OPEN LEAD, not KILL.** "No attacker profit" refutes nothing — an accounting desync that strands or misdirects account value is account-owner loss, a Medium floor on Immunefi on its own. Trace the harm before any severity call (Two-Question Rule).

**Severity rule — "transient DoS" is only valid if it self-resolves:**
Never call something a "transient DoS" without confirming the recovery path actually exists and executes on its own (a timelock that expires, a keeper that is guaranteed to run, a function any user can call to restore). If recovery depends on an action a specific party may never take, or on conditions you have not verified, score it as permanent DoS (or drop it if no DoS is provable). Assumed recovery = inflated severity.

---

### Deep Validation: Al-Mizaan v3 Gates (for borderline or complex findings) ⚡ On-Demand

The 7 gates below are self-contained. **Do NOT load `references/al-mizaan-gates.md` unless you need the full methodology with web/API translations and Sherlock contest evidence.** Use this inline version for 95% of cases.

When a finding passes the 7-Question Gate but feels borderline, involves complex protocol logic, multi-step attack chains, or smart contract context:

1. **Code Reading** — Does the code actually execute the vulnerable path? (Not docs, not comments)
2. **Reachability Chain** — Map the exact call path from external entry point to vulnerable operation
3. **Threat Model** — Who can trigger it? Trusted actor only with no bypass? → ELIMINATE. **Counter-patterns:** "requires oracle misreport" ≠ auto-kill — check for an honest-path route to the same state (Lido `onchainTotalValueOnRefSlot`). "Requires victim cooperation" ≠ auto-kill — a public on-chain state transition (e.g., xSilo `totalSupply → 0`) is front-runnable and therefore attacker-triggerable.
4. **Invariant Breach** — What protocol security property is violated?
5. **Protocol Intent** — Would the designers call this a bug or a feature? **Counter-pattern:** "documented" / "matches upstream design" refutations require actually reading the upstream source — citing another protocol (e.g., "Camelot does the same with xGRAIL") without seeing its code is a miss, not a defense. Verify upstream bytecode before rejecting.
6. **Impact** — Quantify concrete harm in native terms (exact amount, not "could be significant"). **Counter-pattern:** split self-harm into actor-scoped legs — the exiter's penalty loss and a front-runner's captured residual are SEPARATE victims; one self-inflicted leg does not kill the other leg's impact. **Severity:** "transient DoS" requires a confirmed self-resolving recovery path, else score as permanent DoS.
7. **Formal Proof** — Working PoC that executes against a realistic environment

**Quick kill rules (from Al-Mizaan + Slither benchmark lesson):**
- Trusted-actor-only trigger with no governance bypass → ELIMINATE
- Finding in `lib/`, `interfaces/`, `mocks/`, `test/` → ELIMINATE (89% of automated scanner "Highs" are out-of-scope dependency noise)
- No working PoC against realistic environment → DEMOTE to LEAD
- "Documentation says X but code does Y" → code is authoritative, report the code behavior

**Load the full `references/al-mizaan-gates.md` only when:**
- The finding involves complex DeFi protocol economics
- You need the Sherlock contest acceptance-rate data to defend severity
- A triager is pushing back and you need the formal methodology citation

## HackenProof Triage Workflow

When `--hackenproof` flag is set, apply HackenProof-specific triage pipeline:

### Mandatory Tool Sequence
1. `get_program_info` — Program scope, rules, severity definitions
2. `get_report_details` — Full report content, attachments
3. `get_attachments` — List all attachments
4. `fetch_attachment` — Download specific attachment content
5. `list_reports` — Search for similar/duplicate reports
6. `search_comments` — Check for prior triage discussion
7. `get_comments` — Read existing decision history

### 4 Pre-Validation Gates
1. **Commit/Version Match:** Does the report reference a specific commit/version? Verify it against deployed code.
2. **Scope Match:** Is the exact asset/function in the program's scope?
3. **Duplicate Check:** Search all reports for same vulnerability class + same endpoint
4. **PoC Presence:** Does the report include a working proof of concept?

### Decision States
| State | When |
|-------|------|
| **Out of Scope** | Asset/class not in program scope |
| **Duplicate** | Same vuln already reported |
| **Informative** | Valid finding but low/no security impact |
| **Not Applicable** | Claim cannot be reproduced |
| **Triaged** | Valid finding, passed all gates, ready for fix |

---

## Immunefi Web3 Triage (Smart Contract Track)

When reporting to Immunefi, apply these additional Web3-specific gates:

### 20 Real Paid Bounty Patterns (Dissected)

| # | Protocol | Bug Class | Payout | Key Lesson |
|---|----------|-----------|--------|------------|
| 1 | Beanstalk | Governance | $182M | Flash loan + governance = total drain |
| 2 | Cream Finance | Reentrancy | $130M | Cross-contract reentrancy via ERC777 |
| 3 | Pancake Bunny | Flash Loan | $45M | Price manipulation in same tx |
| 4 | Bondly Finance | Access Control | $1.6M | `setDefaultAdmin` callable by anyone |
| 5 | SushiSwap | Access Control | $3M | Migrator contract had unchecked owner |
| 6 | ValueDeFi | Flash Loan | $6M | Vault share price manipulation |
| 7 | Harvest Finance | Flash Loan | $34M | Price oracle manipulation via deposit |
| 8 | Curve Finance | Reentrancy | $62M | Vyper reentrancy via struct storage |
| 9 | Euler Finance | Access Control | $197M | Donate + liquidate = protocol insolvency |
| 10 | Platypus Finance | Access Control | $8.5M | Single-sided LP lock bypass |
| 11 | Decurra Protocol | Reentrancy | $1.6M | Staking contract reentrancy |
| 12 | Sentiment | Access Control | $1M | Arbitrary call via account abstraction |
| 13 | dYdX | Accounting | $2M | Margin trading accounting desync |
| 14 | Perp Protocol | Accounting | $5.5M | Funding rate calculation error |
| 15 | Moonwell | Access Control | $11.5M | Governance proposal exploit |
| 16 | Exactly Protocol | Access Control | $12M | Oracle manipulation + borrow |
| 17 |oki dEX | Access Control | $3M | Admin key compromise |
| 18 | CoinEx | Access Control | $70M | Hot wallet key leak |
| 19 | StakeWise | Flash Loan | $75M | MEV-Boost relay manipulation |
| 20 | Polycat Finance | Flash Loan | $1.2M | Mint + dump via price oracle lag |

### Immunefi Report Format Requirements
- **Asset Type:** Token, Chain, Smart Contract, etc.
- **Blockchain/Tech Stack:** Ethereum, BSC, Polygon, etc.
- **Vulnerability Category:** Access Control, Reentrancy, etc.
- **Root Cause:** Exact function and line number
- **Impact:** Exact funds at risk, not "could be exploited"
- **PoC:** Runnable Foundry test, not pseudocode
- **Recommended Fix:** One concrete fix, not "add access control"

## CVSS 3.1 Quick Guide

| Score | Severity | Typical Bug |
|-------|----------|-------------|
| 0-3.9 | Low | Info disclosure (non-sensitive) |
| 4-6.9 | Medium | IDOR (read PII), Stored XSS (low impact) |
| 7-8.9 | High | IDOR (write/delete), SQLi, Race (double spend) |
| 9-10 | Critical | Auth bypass → admin, SSRF (cloud metadata), RCE |

---


## SOURCE: hunt-skills/bountyforge/skills/hackenproof-triage-marketplace/SKILL.md

# HackenProof Triage Marketplace

Execute consistent, evidence-based triage for HackenProof bug bounty reports.

See also: [[Triage]], [[Report Writing]], [[Lead Ledger]], [[Vuln Classes]]

## Workflow

1. Apply global HackenProof classification baseline from `references/hackenproof-global-policy.md`.
2. Run pre-validation gates in strict order:
   a. Verify the reported commit/version is the intended in-scope commit.
   b. Verify the submission target and impact are in scope.
   c. Verify PoC evidence is provided and readable.
   d. Verify whether an equivalent duplicate already exists.
3. Start technical validation only after all pre-validation gates pass.
4. Classify severity, choose state transition, and apply labels.
5. Post a concise decision comment with explicit rationale and next action.

## Mandatory Tool Sequence

1. Run `get_program_info` for scope and reward context.
2. Detect program type from `get_program_info` (for example: `web`, `mobile`, `smart-contract`, `blockchain`).
3. Map detected type to the equivalent vulnerability classification section in `references/hackenproof-global-policy.md`.
4. Run `get_report_details` to extract target, asset, and reported commit/version.
5. Run `get_attachments`; if no PoC evidence exists, set `Need more info` immediately.
6. Run `fetch_attachment` to confirm commit/version evidence in PoC files.
7. Compare commit/version against in-scope assets and versions from program rules.
8. Verify in-scope status for both target and claimed impact using program scope/rules, then global baseline if no override exists.
9. Run `list_reports`/`search_comments` to check duplicate candidates before validation.
10. Start validation: confirm reproducibility, impact, exploit preconditions, and proof quality.
11. Run `get_comments` before posting to avoid contradictory messaging.
12. Only then change `severity`, `state`, `labels`, and add comments.

### Gate 1: Commit or Version Match

- Confirm the submission references a concrete commit hash, tag, or release version.
- Confirm that commit/version maps to an in-scope repository, branch, deployment, or audit target.
- If commit/version is missing or mismatched, set `Need more info` and request exact commit evidence.

### Gate 2: Scope Match

- Confirm target asset is in scope.
- Confirm reported impact category is in scope for bounty eligibility.
- Confirm the finding matches the equivalent classification track for the detected program type.
- If either target or impact is excluded, mark `Out of scope` with explicit rule reference.

### Gate 3: Duplicate Check

- Search for same root cause and same impacted component before deep validation.
- Treat as duplicate only when both root cause and impact match an existing report.
- Add `dup-{report_id}` label when marking `Duplicate`.

### Gate 4: PoC Presence Check

- Confirm at least one usable PoC artifact exists (steps, payload, tx hash, video, logs, or attachment).
- If no PoC is provided, set `Need more info` and request concrete PoC evidence.

## Decision Rules

- Reject or mark `Need more info` when PoC is missing, commit/version evidence is missing, or reproduction steps are incomplete with no verifiable PoC.
- Mark `Out of scope` when target or impact is excluded by program scope/rules.
- Mark `Duplicate` only when matching root cause and impact are confirmed; add `dup-{report_id}` label.
- Use `Informative`/`Not applicable` for weak-impact findings that do not meet bounty criteria.
- Move valid reports to `Triaged` with severity aligned to program policy and demonstrated impact.

Use `references/severity-mapping.md` for impact-to-severity normalization.
Use `references/hackenproof-global-policy.md` for HackenProof-wide scope and severity baseline.
Use `references/triage-comment-templates.md` for consistent responder tone and structure.

## Quality Bar

- Ground every decision in concrete evidence from report fields, attachments, or program rules.
- Keep comments short, specific, and actionable; state exactly what is missing when requesting more info.
- Never guess exploitability when evidence is weak; request clarification instead.
- Prefer reversible actions (`Need more info`) over premature invalidation when uncertainty is material.


## SOURCE: hunt-skills/bountyforge/skills/hackenproof-triage-marketplace/references/hackenproof-global-policy.md

# HackenProof Global Vulnerability Policy

Use this as baseline triage guidance before applying program-specific scope/rules.

Source docs:

- Web & Mobile classification: https://docs.hackenproof.com/bug-bounty/vulnerability-classification/web-and-mobile
- Web & Mobile out-of-scope: https://docs.hackenproof.com/bug-bounty/vulnerability-classification/web-and-mobile/out-of-scope-bugs
- Smart contract classification: https://docs.hackenproof.com/bug-bounty/vulnerability-classification/smart-contracts
- Blockchain protocol classification: https://docs.hackenproof.com/bug-bounty/vulnerability-classification/blockchain-protocols

## Rule Priority

1. Program-specific scope and rules (`get_program_info`) always override global baseline.
2. If no program-specific override exists, use this global policy.
3. If classification is still ambiguous, use CVSS-based reasoning and request more evidence.

## Program Type to Classification Mapping

Derive the program type from `get_program_info` labels/scope metadata, then use:

- `web` or `mobile` -> Web & Mobile classification + Web & Mobile out-of-scope list
- `smart-contract`, `sc`, `solidity`, `evm`, `move` -> Smart Contract classification
- `blockchain`, `protocol`, `node`, `consensus`, `l1`, `l2` -> Blockchain Protocol classification

If labels indicate mixed scope, classify by impacted component first (application, contract, or protocol layer), then use the matching track.

## Web & Mobile Severity Baseline

- `Critical`: payments manipulation, SQLi, RCE, command injection, business logic causing user fund/asset loss.
- `High`: stored XSS, SSRF, wallet-linked subdomain takeover, major sensitive data leakage, auth bypass, impactful IDOR/privilege escalation.
- `Medium`: reflected XSS, non-wallet subdomain takeover, 2FA bypass, moderate sensitive data leakage, CSRF with meaningful impact.
- `Low`: HTML injection, low-impact subdomain takeover, no-rate-limit issues on low-sensitivity endpoints, content spoofing, broken link hijacking.

## Web & Mobile Out-of-Scope Baseline

General out-of-scope conditions:

- no meaningful security impact
- no practical exploitability
- non-production or third-party systems

Common web out-of-scope examples:

- best-practice/informational only findings without exploit impact
- clickjacking/tapjacking on non-sensitive pages
- open redirects without demonstrated abuse impact
- version disclosure, verbose errors, harmless mixed content
- scanner-only or theoretical reports
- DoS/resource abuse without security impact
- outdated software claims without working exploit
- CORS/session-fixation findings without demonstrable impact
- recently disclosed 0day/1day (policy indicates short cooling-off windows)

Common mobile out-of-scope examples:

- root/jailbreak-only attack paths without business impact
- obfuscation/repackaging/decompilation-only findings
- low-risk insecure storage without sensitive data exposure
- debug logs without secrets/tokens
- local/MitM assumptions without proof of exploit impact

## Smart Contract Severity Baseline

- `Critical`: direct theft, permanent freezing of funds/NFTs, governance manipulation, protocol insolvency, unauthorized mint/burn.
- `High`: temporary freezing of funds/NFTs, theft/permanent freeze of unclaimed funds, high-impact oracle manipulation.
- `Medium`: gas-theft patterns, out-of-gas flaws causing disruption/loss, DoS via state or gas abuse, griefing/no-profit attacks with protocol harm.
- `Low`: under-delivery of promised returns due to logic flaws, low-risk uninitialized storage.

Notes:

- privileged/admin-only attack paths may justify severity downgrade or disqualification

## Blockchain Protocol Severity Baseline

- `Critical`: protocol-level theft, permanent fund freeze, total network shutdown, consensus manipulation/chain split risk, hard-fork-required resolution.
- `High`: node-crash DoS, temporary network transaction freeze, temporary fund freeze.
- `Medium`: subset-node DoS, protocol edge-case behavior affecting dApps, timestamp/time manipulation, minor reorg abuse.
- `Low`: non-critical shutdown of minority node set, low-impact fee miscalculation, low-impact gossip-layer issues.

## Triage Application

Before deep validation:

1. map report domain to one baseline (`web-mobile`, `smart-contract`, `blockchain-protocol`)
2. compare claimed impact against baseline severity bucket
3. check out-of-scope indicators early; if matched, mark `Out of scope` with explicit reason
4. if in scope, continue with duplicate checks and technical validation


## SOURCE: hunt-skills/bountyforge/skills/hackenproof-triage-marketplace/references/severity-mapping.md

# Severity Mapping

Use this baseline when program-specific rules do not override it.

- `Critical`: Direct, realistic loss of funds or full protocol compromise with clear attacker path.
- `High`: Major security impact (privilege escalation, substantial theft, permanent denial of service) with practical exploitability.
- `Medium`: Meaningful security weakness with constrained impact or stronger preconditions.
- `Low`: Limited impact, narrow edge case, or low-likelihood abuse.
- `None`: Best-practice issue without material security impact.

## Adjustments

- Raise severity when exploit path is simple, repeatable, and low-cost.
- Lower severity when exploit needs privileged access, unrealistic assumptions, or excessive coordination.
- Anchor final severity to demonstrated impact, not hypothetical worst case.


## SOURCE: hunt-skills/bountyforge/skills/hackenproof-triage-marketplace/references/triage-comment-templates.md

# Triage Comment Templates

Use short markdown comments and keep them evidence-based.

## Valid and Triaged

```md
Thanks for the report.

We validated the issue and confirmed the following:
- **Impact**: <clear impact>
- **Reproducibility**: <reproduced/noted from PoC>
- **Scope**: In scope

We are marking this report as **Triaged** with severity **<severity>**.
```

## Need More Info

```md
Thanks for the submission.

We could not fully validate the issue yet. Please provide:
- <missing step or environment details>
- <expected vs actual behavior evidence>
- <PoC artifact, logs, or transaction links>

We are setting this to **Need more info** until the additional details are shared.
```

## Out of Scope

```md
Thanks for your report.

After review, this issue is currently **Out of scope** for this program because:
- <specific scope/rule reference>

If you believe this maps to a different in-scope target, share that target and evidence and we will re-check.
```

## Duplicate

```md
Thanks for the submission.

This issue matches an existing report with the same root cause and impact: **<report-id>**.

We are marking this report as **Duplicate**.
```


## SOURCE: hunt-skills/bountyforge/skills/report-writing/SKILL.md

# REPORT WRITING

Impact-first. Human tone. No theoretical language. Triagers are people.

See also: [[Report Writing]], [[Triage]], [[A→B Chains]], [[Lead Ledger]]

---

## THE MOST IMPORTANT RULE

> **Never use "could potentially" or "could be used to" or "may allow".**
> Either it does the thing or it doesn't. If you haven't proved it, don't claim it.

```
BAD:  "This vulnerability could potentially allow an attacker to access user data."
GOOD: "An attacker can access any user's order history by changing the user_id
       parameter to the target user's ID. I confirmed this using two test accounts:
       attacker@test.com (ID 123) successfully retrieved victim@test.com (ID 456)
       orders, including their shipping address and payment method last 4 digits."
```

---

## TITLE FORMULA

```
[Bug Class] in [Exact Endpoint/Feature] allows [attacker role] to [impact] [victim scope]
```

**Good titles (specific, impact-first):**
```
IDOR in /api/v2/invoices/{id} allows authenticated user to read any customer's invoice data
Missing auth on POST /api/admin/users allows unauthenticated attacker to create admin accounts
Stored XSS in profile bio field executes in admin panel — allows privilege escalation
SSRF via image import URL parameter reaches AWS EC2 metadata service
Race condition in coupon redemption allows same code to be used unlimited times
```

**Bad titles (vague, useless to triager):**
```
IDOR vulnerability found
Broken access control
XSS in user input
Security issue in API
Unauthorized access to user data
```

---

## Summary

[One paragraph: what the bug is, where it is, what an attacker can do. Be specific.
Include: endpoint, method, parameter, data exposed, required access level.]

Example: "The `/api/users/{user_id}/orders` endpoint does not verify that the
authenticated user owns the requested user_id. An attacker can enumerate any
user's order history, including PII (email, address, phone) and purchase history,
by incrementing the user_id parameter. No privileges beyond a standard free
account are required."

## Vulnerability Details

**Vulnerability Type:** IDOR / Broken Object Level Authorization
**CVSS 3.1 Score:** 6.5 (Medium) — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
**Affected Endpoint:** GET /api/users/{user_id}/orders

## Steps to Reproduce

**Environment:**
- Attacker account: attacker@test.com, user_id = 123
- Victim account: victim@test.com, user_id = 456
- Target: https://target.com

**Steps:**

1. Log in as attacker@test.com, obtain Bearer token

2. Send the following request:

```
GET /api/users/456/orders HTTP/1.1
Host: target.com
Authorization: Bearer ATTACKER_TOKEN_HERE
```

3. Observe response:

```json
{
  "orders": [
    {"id": 789, "items": [...], "email": "victim@test.com", "address": "123 Main St..."}
  ]
}
```

The response contains victim's full order history and PII despite being requested
by a different user.

## Impact

An authenticated attacker can enumerate all user orders by iterating user_id values.
This exposes: full name, email, shipping address, purchase history, and payment
method (last 4). With ~100K users, this represents a mass PII breach affecting
all registered users. Exploitation requires only a free account and takes minutes
with a simple loop.

## Recommended Fix

Add server-side ownership verification:
```python
if order.user_id != current_user.id:
    raise Forbidden()
```

## Supporting Materials

[Screenshot showing attacker's session returning victim's order data]
[Video walkthrough if available]
```

---

# [IDOR] User order history accessible without authorization via /api/users/{id}/orders

**VRT Category:** Broken Access Control > IDOR > P2

## Steps to Reproduce

[Same structured steps — exact HTTP requests, exact responses]

## Expected vs Actual Behavior

**Expected:** 403 Forbidden when user_id does not match authenticated user
**Actual:** 200 OK with victim's full order data

## Severity Justification

P2 (High) — Direct read access to other users' PII. Affects all user accounts.
No user interaction required. Exploitable by any authenticated user.
Automated enumeration could exfil all [N] user records in minutes.

## Remediation

Add ownership verification: `if order.user_id != current_user.id: raise 403`
```

---

## Description

[Impact-first paragraph. Start with what an attacker can do, not with how you found it.
Include: endpoint, method, parameter, data exposed, required privileges.]

## Steps to Reproduce

**Environment:**
- Attacker: email=attacker@test.com (standard account, no special role)
- Victim: email=victim@test.com
- Tested: [date]

**Reproduction steps:**

1. [Login as attacker / visit URL / send request]

2. Send the following HTTP request:

\```http
METHOD /endpoint HTTP/1.1
Host: target.com
Authorization: Bearer ATTACKER_TOKEN
Content-Type: application/json

{"param": "victim_id_here"}
\```

3. Observe response contains victim's private data:

\```json
{"email": "victim@test.com", "address": "123 Main St", ...}
\```

## Impact

[Specific, quantified impact. What data, how many users, what can attacker do.]

CVSS 3.1 Score: X.X ([Severity]) — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N

## Attachments

[Screenshot or Loom video showing the impact — Intigriti triagers prefer video for complex bugs]
```

**Intigriti-specific notes:**
- Title format: `[Bug Class]: [One-line impact]` (no formula required, but keep it specific)
- Severity is set by you: Critical/High/Medium/Low/Exceptional
- CVSS 3.1 is standard (CVSS 4.0 also accepted on newer programs)
- PoC video is valued much more than screenshot alone — record with Loom
- Safe harbor: Intigriti enforces it, be comfortable going slightly aggressive with testing

---

## Summary

[One paragraph with: root cause, affected function, economic impact, attack cost.
Include numbers where possible: "attacker can drain $X in Y transactions."]

## Vulnerability Details

**Contract:** `VulnerableContract.sol`
**Function:** `claimRedemption()`
**Bug Class:** Accounting State Desynchronization
**Severity:** Critical

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// Foundry PoC — run: forge test --match-test test_exploit -vvvv

contract ExploitTest is Test {
    // ... full working exploit
}
```

## Impact

[Quantified: "Attacker can drain X% of TVL = $Y at current rates.
Requires $Z gas. Attack is repeatable."]

### Metric Quick Picks

| Metric | Value | Weight | When |
|---|---|---|---|
| **Attack Vector (AV)** | Network | +0.85 | Via internet |
| | Local | +0.55 | Local access needed |
| **Attack Complexity (AC)** | Low | +0.77 | Repeatable |
| | High | +0.44 | Race/timing needed |
| **Privileges Required (PR)** | None | +0.85 | No login |
| | Low | +0.62 | Regular user account |
| | High | +0.27 | Admin account |
| **User Interaction (UI)** | None | +0.85 | No victim action |
| | Required | +0.62 | Victim must click |
| **Scope (S)** | Changed | higher | Affects browser/OS/other |
| | Unchanged | lower | Stays in app |
| **Confidentiality (C)** | High | +0.56 | All data exposed |
| | Low | +0.22 | Limited data |
| **Integrity (I)** | High | +0.56 | Can modify any data |
| **Availability (A)** | High | +0.56 | Crashes service |

### Typical Scores by Bug Class

| Bug | Typical CVSS | Severity |
|---|---|---|
| IDOR (read PII) | 6.5 | Medium |
| IDOR (write/delete) | 7.5 | High |
| Auth bypass → admin | 9.8 | Critical |
| Stored XSS (any user) | 5.4–8.8 | Med–High |
| SQLi (data exfil) | 8.6 | High |
| SSRF (cloud metadata) | 9.1 | Critical |
| Race condition (double spend) | 7.5 | High |
| GraphQL auth bypass | 8.7 | High |
| JWT none algorithm | 9.1 | Critical |

---

### Critical (P1)
- Full account takeover of any user without interaction
- Remote code execution
- SQLi with ability to dump/modify entire DB
- Auth bypass to admin panel
- SSRF to cloud metadata → IAM credentials exfil

### High (P2)
- Mass PII exposure (email, phone, SSN, payment data)
- Privilege escalation from user to admin
- SSRF reaching internal services (data returned)
- Stored XSS executing for all users of sensitive feature
- Payment bypass / financial loss without limit

### Medium (P3)
- IDOR on specific user's non-critical data
- XSS on low-sensitivity page requiring victim interaction
- CSRF on important but non-critical action
- Rate limit bypass on OTP (with effort demonstrated)

### Low (P4)
- Information disclosure (non-sensitive, no PII)
- Clickjacking on sensitive action WITH working PoC
- CORS on limited data

---

## SEVERITY SELF-ASSESSMENT

Each YES raises severity:
```
1. Exposes PII / health / financial data of other users?        → +1 severity
2. Allows account takeover or privilege escalation?             → +2 severity
3. Requires ZERO user interaction from victim?                  → +1 severity
4. Affects ALL users (not specific condition)?                  → +1 severity
5. Remotely exploitable with no internal network access?        → baseline for High+
```

---

## DOWNGRADE COUNTERS

| Program Says | Counter With |
|---|---|
| "Requires authentication" | "Attacker needs only a free account — no special role or permission" |
| "Limited impact" | "Affects [N] users / exposes [PII type] / $[amount] at risk" |
| "Already known" | "Show me the report number — I searched hacktivity and found none" |
| "By design" | "Show me the documentation stating this is intended behavior" |
| "Low CVSS" | "CVSS doesn't capture business impact — attacker can extract [X] in [Y] minutes" |
| "Not exploitable" | "Here is the exact response showing victim's data returned to attacker session" |

---

## THE 60-SECOND PRE-SUBMIT CHECKLIST

```
[ ] Title follows formula: [Class] in [endpoint] allows [actor] to [impact]
[ ] First sentence states exact impact in plain English
[ ] Steps to Reproduce has exact HTTP request (copy-paste ready)
[ ] Response showing the bug is included (screenshot or JSON body)
[ ] Two test accounts used — not just one account testing itself
[ ] CVSS score calculated and included
[ ] Recommended fix is 1-2 sentences (not a lecture)
[ ] No typos in endpoint paths or parameter names
[ ] Report is < 600 words — triagers skim long reports
[ ] Severity claimed matches impact described — don't overclaim
[ ] Never used "could potentially" or "may allow"
[ ] PoC is reproducible by triager from a fresh state
```

---

## CVSS 4.0 QUICK REFERENCE (newer programs)

CVSS 4.0 replaced CVSS 3.1 in November 2023. Some newer programs require it.

### Key Differences from CVSS 3.1

| Metric | CVSS 3.1 | CVSS 4.0 |
|---|---|---|
| Attack Vector | Network/Adjacent/Local/Physical | Same |
| Attack Complexity | Low/High | Low/High |
| **NEW**: Attack Requirements | (didn't exist) | None/Present (replaces some PR/UI) |
| Privileges Required | None/Low/High | Same |
| User Interaction | None/Required | None/Passive/Active |
| Scope | Unchanged/Changed | REMOVED |
| **NEW**: Sub-Impact metrics | (didn't exist) | Vulnerable/Subsequent system impact |

### CVSS 4.0 Score Examples

| Finding | CVSS 4.0 Score | Vector |
|---|---|---|
| Unauthenticated RCE | 10.0 | CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H |
| IDOR read PII, auth required | 6.9 | CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N |
| Stored XSS, admin views it | 8.2 | CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N |
| SSRF → cloud metadata | 8.7 | CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:N |

### Quick CVSS 4.0 Calculator
```
Use: https://www.first.org/cvss/calculator/4.0
Key fields:
  VC/VI/VA = Vulnerable System Confidentiality/Integrity/Availability
  SC/SI/SA = Subsequent System (downstream impact)
  AT = None (no special condition) | Present (race/specific config needed)
  UI = None | Passive (victim visits URL) | Active (victim takes explicit action)
```

**Practical rule**: If program uses CVSS 4.0 and you don't know the vector, use the calculator and include the full string starting with `CVSS:4.0/AV:...`. Programs cannot dispute a valid vector string.

---

## HUMAN TONE GUIDELINES

**Write to a person, not a system:**
- Triagers are tired. Get to the impact in sentence 1.
- Use "I" not "the researcher" — you found it, own it
- Short paragraphs, bullet points for steps
- Hyperlink relevant docs if needed

**Escalation language (when payout is being downgraded):**
```
"This vulnerability does not require any special privileges — only a free account."
"The exposed data includes [PII type], which is subject to GDPR requirements."
"An attacker can automate this with a simple loop — all [N] records in minutes."
"This is exploitable externally without network access to any internal system."
"The impact is equivalent to a full data breach of [feature/data type]."
```

**Avoid:**
- Jargon the triager might not know
- 5-paragraph explanations of what IDOR is (they know)
- Theoretical chains ("could be combined with X to...")
- Passive voice ("it was observed that...")
- Qualifying language ("seems to," "appears to")

---

## STEPS TO REPRODUCE FORMAT (triager-optimized)

```markdown
**Setup:**
- Account A (attacker): email=attacker@test.com, ID=111
- Account B (victim): email=victim@test.com, ID=222
- Both created via normal registration — no special access

**Steps:**

1. Log in as Account A
2. Send this request (replace `111` with victim ID `222`):

\```
GET /api/v2/resource/222 HTTP/1.1
Host: target.com
Authorization: Bearer ACCOUNT_A_TOKEN
\```

3. Response contains Account B's private data:

\```json
{"id": 222, "email": "victim@test.com", "name": "Victim User", "address": "..."}
\```

**Expected:** 403 Forbidden
**Actual:** 200 OK with victim's private data
```


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-11-state-management/fv-anc-11-cl5-time-unit-mismatch-in-deadline-validation.md

## TLDR

Solana's `Clock` sysvar provides both `unix_timestamp` (seconds since Unix epoch) and `slot` (current slot number). Mixing these two units in deadline or expiry comparisons produces incorrect results: a value stored in seconds interpreted as a slot number, or vice versa, can make a deadline that should expire in one hour appear to expire in days, or vice versa.

## Detection Heuristics

**Mixed Unit Comparison**
- Protocol stores a deadline or expiry as `Clock.slot` but compares it against `Clock.unix_timestamp` in a later instruction, or vice versa
- Expiry field not labeled with its unit in the account struct comment or field name; auditor must trace all write sites to determine whether seconds or slots were intended
- Cooldown or lock duration specified in seconds in the protocol documentation but stored by assigning `Clock.slot + duration_seconds`, producing a value in slots not seconds

**Slot Duration Assumptions**
- Protocol assumes a fixed slot duration (e.g., 400ms per slot) to convert between seconds and slots; actual slot duration varies and the assumption causes drift over time
- Lock duration computation: `current_slot + (lock_seconds / 0.4)` uses hardcoded slot duration that may be inaccurate, making locks shorter or longer than intended

**Cross-Instruction Unit Inconsistency**
- One instruction writes `last_updated_slot = Clock.unix_timestamp` (wrong unit) while another instruction reads `elapsed = Clock.slot - last_updated_slot`, producing nonsensical elapsed time
- Config parameter for timelock duration accepted from user input without validation of whether it is denominated in slots or seconds

## False Positives

- Protocol uses only one time source consistently throughout all instructions; either always `unix_timestamp` or always `slot`, never mixed
- Field names and struct comments explicitly document the unit (`expiry_slot`, `expiry_unix_ts`), and all comparison sites use the matching Clock field


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl1-trying-to-modify-an-account-without-checking-if-its-writeable.md

## TLDR

Solana requires accounts to be marked writable in the transaction's account list before the runtime permits lamport or data changes. Writing to an account not flagged as writable will either panic or silently fail depending on the Solana version, and opens logic errors when the writability check is absent at the program level.

## Detection Heuristics

**Mutation Without Writable Guard**
- `ctx.accounts.config.data.borrow_mut()` or similar data mutation on an `AccountInfo` without a prior `require!(ctx.accounts.config.is_writable, ...)` check
- Lamport arithmetic on an account (e.g., `**account.lamports.borrow_mut() += ...`) without verifying `is_writable`

**Missing mut Constraint in Anchor Context**
- Account field in `#[derive(Accounts)]` struct lacks `#[account(mut)]` yet the instruction body writes to it
- Anchor `Account<'info, T>` used without `mut` constraint on a data-mutating instruction

**Unconditional Write on User-Supplied Accounts**
- `AccountInfo` received from `ctx.remaining_accounts` or a raw account list is written without checking `is_writable`

## False Positives

- Account is written only via CPI and the callee program enforces writable constraints on its own accounts
- Read-only deserialization of account data into a local variable without any mutation of the account itself


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl10-using-ctx.remaining_accounts-without-non-zero-data-check.md

## TLDR

An uninitialized account on Solana has all-zero data. Accepting such an account from `ctx.remaining_accounts` without checking that it contains non-zero data allows an attacker to pass an empty system account that will be deserialized as a zero-value struct, potentially bypassing balance or state checks.

## Detection Heuristics

**No Liveness Check Before Deserialization**
- `remaining_accounts` entry deserialized or read without verifying that `data.iter().any(|&b| b != 0)` or that the lamport balance is non-zero
- Code assumes a non-zero discriminator check serves as a liveness check, but all-zero data passes byte-equality checks against a zero discriminator

**Zero-Balance Account Accepted as Valid State**
- Account with zero lamports taken from `remaining_accounts` and used as if it represents initialized state
- Missing check for `account.lamports() > 0` before trusting the account as representing a real on-chain entity

**System-Owned Zero Account**
- Account owned by the System Program with zero data accepted and treated as a valid program account of a specific type

## False Positives

- Account is expected to start at zero as part of its initialized state (e.g., a counter initialized to zero); zero data is valid and expected
- Program immediately initializes the account after accepting it and does not read any fields from it prior to initialization


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl11-no-reload-after-account-mutation.md

## TLDR

In Anchor, after mutating an account via a `load_mut()` or direct field write, subsequent reads of the same account may use a stale in-memory copy. Without explicitly reloading, the program may act on outdated state, leading to logic errors when the mutation affects values read later in the same instruction.

## Detection Heuristics

**load_mut Scope Not Dropped Before Subsequent load**
- `let mut data = ctx.accounts.account.load_mut()?` followed by logic that reads `ctx.accounts.account` without dropping the mutable borrow and calling `.reload()` or `.load()`
- Borrow of mutable account data not scoped tightly, causing stale in-memory values to persist beyond the mutation

**Mutation Followed by Computation Using Pre-Mutation Values**
- Account field updated (e.g., `account.balance = new_balance`) and then used in a subsequent calculation that should reflect the updated value, but the local variable still holds the old value
- CPI invoked after mutation that passes the account, but the caller reads the account's fields again after the CPI without reloading

**Missing .reload() After CPI**
- After a CPI that mutates an account owned by the current program, the instruction reads the account's fields without calling `.reload()` to pull the updated data from the account's storage

## False Positives

- Mutation and subsequent reads are in separate instructions; Anchor re-deserializes on each instruction entry
- Account is written exactly once at the end of the instruction and no further reads occur after the write


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl12-not-validating-a-set-address.md

## TLDR

When an instruction stores a new address into an account field (e.g., updating a treasury, fee recipient, or authority), failing to validate that address allows arbitrary pubkeys to be set. This can redirect funds, grant privileges to attacker-controlled accounts, or break protocol invariants.

## Detection Heuristics

**Unconstrained Address Update**
- `ctx.accounts.config.treasury = new_address` or similar field assignment without preceding validation of `new_address`
- Address stored from instruction data without checking it is not the System Program, a PDA of the current program, or a known-invalid address

**No Existence or Receivability Check**
- New address not verified to be an initialized account that can receive tokens or lamports
- Fee recipient or authority address updated to a PDA that has no associated token account for the relevant mint

**No Access Control on the Update Instruction**
- Instruction that sets an address does not enforce that only a privileged authority (admin, DAO, multisig) can call it
- Missing `has_one = admin` or equivalent signer constraint on the update instruction context

## False Positives

- New address is derived on-chain from a PDA computation and validated by seeds rather than passed as user input
- Address is constrained to a fixed set of known values enforced by a `constraint` expression


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl13-init-if-needed-without-reinit-guard.md

## TLDR

Anchor's `init_if_needed` skips account creation if the account already exists, but it does not prevent an attacker from pre-creating the PDA with malicious initial state. Without a reinitialization guard in the instruction body, a subsequent call that skips init will silently operate on attacker-controlled data.

## Detection Heuristics

**init_if_needed Without State Validation on Existing Account**
- `#[account(init_if_needed, ...)]` used without any check in the instruction body that verifies the account's existing fields when the account was already initialized
- No `is_initialized` flag or equivalent sentinel checked before writing fields, allowing re-entry to overwrite state

**Pre-Created PDA Attack Surface**
- PDA seeds include only user-controlled inputs (e.g., user pubkey, a name string) allowing an attacker to derive the PDA and create it with arbitrary data before the legitimate user

**Authority Field Not Verified on Existing Account**
- Instruction uses `init_if_needed` for an account that stores an `authority: Pubkey` but does not verify that the stored authority matches `ctx.accounts.user.key()` when the account already exists

**Missing Idempotency Check**
- Instruction is intended to be idempotent but lacks protection against an attacker calling it a second time to reset critical state

## False Positives

- Account is a token account (ATA) where `init_if_needed` is safe because the token program enforces ownership on initialization
- Instruction only writes to the account on first initialization and subsequent calls are no-ops due to explicit guards in the instruction body


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl14-realloc-without-zero-init.md

## TLDR

Anchor's `realloc` constraint expands an account's data allocation. When `realloc::zero_init = false`, newly exposed bytes from the previous allocation are not zeroed and may contain stale data from prior account usage. Reading those bytes as structured fields yields unpredictable values.

## Detection Heuristics

**realloc::zero_init = false on Expanding Reallocations**
- `#[account(mut, realloc = new_size, realloc::payer = payer, realloc::zero_init = false)]` where `new_size` is larger than the account's current size
- Instruction body reads fields in the newly allocated region without manually zeroing them first

**Stale Byte Exposure After Size Increase**
- Account previously used for a different data structure, closed, and then reallocated to a new type without zeroing; residual bytes from the old structure appear in new fields
- Reallocation performed in a loop where each iteration may expose previously used memory from a prior account lifecycle

**Missing Manual Zero in Instruction Body**
- `realloc::zero_init = false` used and no `data[old_size..new_size].fill(0)` or equivalent in the instruction body before reading new fields

## False Positives

- `realloc::zero_init = false` used only for shrinking allocations, where no new bytes are exposed
- Instruction immediately overwrites all newly allocated bytes with explicit values before any read, making the initial content irrelevant


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl2-trying-to-access-account-data-without-ownership-checks.md

## TLDR

On Solana, any account can be passed to a program. Without verifying that an account is owned by the expected program, an attacker can substitute a look-alike account controlled by a different program, causing the instruction to operate on attacker-crafted data.

## Detection Heuristics

**Raw Data Borrow Without Owner Verification**
- `ctx.accounts.config.data.borrow()` on an `AccountInfo` or `UncheckedAccount` without checking `ctx.accounts.config.owner`
- `try_from_slice` or manual deserialization of account data without a preceding owner check

**Missing owner Constraint in Anchor Context**
- `UncheckedAccount<'info>` used to read structured data without `#[account(owner = expected_program_id)]` constraint
- `AccountInfo` interpreted as a known struct type without verifying `account.owner == &expected_program::ID`

**Ownership Checked Against Wrong Program**
- `account.owner == ctx.program_id` check missing, or checked against system program when the data account should be owned by the current program

## False Positives

- Anchor `Account<'info, T>` type used, which automatically enforces program ownership during deserialization
- Account is the System Program, Token Program, or another well-known program account where ownership of the program itself is not meaningful to check


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl3-usage-of-uncheckedaccount-without-manual-ownership-check.md

## TLDR

`UncheckedAccount<'info>` explicitly bypasses Anchor's automatic ownership and discriminator verification. Any instruction using this type must manually perform the ownership checks that `Account<'info, T>` would otherwise enforce, or an attacker can supply an account owned by any program.

## Detection Heuristics

**UncheckedAccount Without owner Constraint or Manual Check**
- `pub some_account: UncheckedAccount<'info>` in a context struct without `#[account(owner = expected_program_id)]` constraint
- `UncheckedAccount` used in an instruction body that reads or writes structured data without a preceding `require!(account.owner == &expected_program::ID, ...)`

**`/// CHECK:` Comment Absent or Inadequate**
- Anchor requires a `/// CHECK:` doc comment above every `UncheckedAccount` field; absence suggests the safety rationale was not considered
- `/// CHECK:` comment present but only states "safe" without explaining why owner verification is unnecessary

**UncheckedAccount Passed to CPI Without Validation**
- `UncheckedAccount` forwarded to a CPI without verifying its owner, allowing an attacker-controlled account to be interpreted as a legitimate target by the callee

## False Positives

- `UncheckedAccount` used for accounts whose key is fully constrained by `#[account(address = known_constant)]`, making ownership implied
- Account is a program account (executable) where owner is always the BPF loader and ownership of the program itself is not relevant


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl4-usage-of-uncheckedaccount-without-manual-signer-check.md

## TLDR

When `UncheckedAccount<'info>` is used for an account that is expected to authorize an action, the `is_signer` field must be explicitly checked in the instruction body. Anchor does not perform this check automatically for unchecked account types.

## Detection Heuristics

**UncheckedAccount Used as Authority Without Signer Verification**
- `pub authority: UncheckedAccount<'info>` in a context struct where the instruction performs privileged operations gated on this account
- No `require!(ctx.accounts.authority.is_signer, ...)` in the instruction body when `UncheckedAccount` is the authorizing party

**Key Equality Check Without Signer Check**
- Code verifies `authority.key() == expected_key` but omits `authority.is_signer`, allowing signature replay or impersonation
- `has_one` constraint on a related account pointing to an `UncheckedAccount` without enforcing that it signed

**`/// CHECK:` Justification Omits Signer Rationale**
- `/// CHECK:` comment explains ownership but does not address how signer status is enforced

## False Positives

- `UncheckedAccount` used for a PDA that authorizes via seeds rather than a signature
- Account is used purely for reading data and no privileged action is gated on it being a signer


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl5-no-is_initialized-check-when-operating-on-an-account.md

## TLDR

Operating on an uninitialized account allows instructions to read garbage data or overwrite state during initialization with attacker-controlled values. Anchor's `#[account(init)]` guards against double-initialization, but manually managed accounts or legacy patterns that track initialization via a boolean flag must be explicitly checked.

## Detection Heuristics

**Missing Initialization Guard on Manual Account Structs**
- Account struct contains `is_initialized: bool` field but no instruction reads this field and rejects the account if already initialized
- Instruction that should only run once does not check `is_initialized` before writing state

**init_if_needed Without Subsequent State Validation**
- `#[account(init_if_needed)]` used without checking whether the account was already initialized before writing fields, allowing re-initialization with new values

**Operating on Zero-Discriminator Account**
- Instruction accepts an `Account<'info, T>` that should be freshly initialized but does not use `init` constraint, allowing an all-zero account to pass deserialization

## False Positives

- Anchor `#[account(init)]` constraint is used, which enforces that the account is uninitialized (all-zero discriminator) at the time of the instruction
- Instruction is explicitly designed to re-initialize an account and documents this behavior


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl6-missing-account-constraints.md

## TLDR

Anchor constraints such as `has_one`, `constraint`, and `address` enforce relational correctness between accounts at the framework level. Omitting these constraints forces the instruction body to perform manual checks, and if those checks are also absent, an attacker can pass unrelated accounts.

## Detection Heuristics

**Missing has_one on Relational Fields**
- `Account<'info, Vault>` struct contains an `admin: Pubkey` field but the context does not include `#[account(has_one = admin)]`, allowing any signer to be passed as admin
- Loan, position, or order accounts that reference a user or mint pubkey without a `has_one` constraint linking them to the corresponding account in the context

**Missing address Constraint for Known Fixed Accounts**
- Sysvar, program, or well-known singleton account accepted without `#[account(address = known_id)]`
- Token program, System Program, or Rent sysvar passed as `AccountInfo` without address verification

**Missing constraint for Business Logic Invariants**
- Two accounts that must differ (e.g., source and destination token accounts) lack `constraint = a.key() != b.key()`
- Numerical invariants (e.g., `amount > 0`, `deadline > clock.unix_timestamp`) not enforced at the account constraint level or in the instruction entry

## False Positives

- Constraint enforced equivalently inside the instruction body with a `require!` macro, providing the same security guarantee
- Relationship is structurally impossible to violate due to how the PDA seeds are constructed


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl7-duplicate-mutable-accounts.md

## TLDR

When two mutable account fields in an Anchor context can be satisfied by the same public key, an attacker can pass the same account for both. Instructions that assume the accounts are distinct (e.g., transferring between them) will produce incorrect results or allow double-mutation exploits.

## Detection Heuristics

**Two mut Accounts of the Same Type Without Uniqueness Constraint**
- Context struct has `pub user_a: Account<'info, User>` and `pub user_b: Account<'info, User>`, both with `#[account(mut)]`, and no `constraint = user_a.key() != user_b.key()`
- Source and destination token accounts, or two vaults, declared as mutable without a key-inequality constraint

**Transfer Logic Assuming Distinct Accounts**
- Instruction performs `from.amount -= value` and `to.amount += value` where `from` and `to` could be the same account, resulting in net zero effect or data corruption
- Self-transfer path not considered in tests or constraints

**Accounts With Overlapping Seeds**
- Two PDA accounts derived with different logical roles but whose seeds can be made equal by an attacker choosing inputs

## False Positives

- Instruction explicitly handles the case where both accounts are the same (e.g., a no-op self-transfer path with a guard)
- Accounts are derived from distinct constant seeds that cannot collide


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl8-using-ctx.remaining_accounts-without-manual-ownership-check.md

## TLDR

`ctx.remaining_accounts` provides raw `AccountInfo` references with no Anchor-enforced constraints. Every account taken from this slice must be manually validated for ownership before its data is read or it is passed to a CPI, otherwise an attacker can substitute an account owned by any program.

## Detection Heuristics

**Direct Data Access From remaining_accounts Without Owner Check**
- `let account = &ctx.remaining_accounts[i]` followed by `account.try_borrow_data()` or deserialization without `require!(account.owner == &expected_program::ID, ...)`
- Loop over `ctx.remaining_accounts` that deserializes each entry without per-entry owner validation

**Accounts From remaining_accounts Forwarded to CPI**
- `AccountInfo` taken from `remaining_accounts` passed directly into a `CpiContext` or `invoke` call without owner verification
- `remaining_accounts` entry used as an authority or signer account in a CPI without checking ownership and key

**Missing Length and Bounds Checks**
- Access to `ctx.remaining_accounts[i]` without verifying the slice has sufficient length, allowing index-out-of-bounds panics

## False Positives

- Account key is fully constrained by a PDA derivation check performed immediately after extracting it from `remaining_accounts`
- Accounts are only used for lamport balance reads, and the program logic is not affected by which program owns the account


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl9-using-ctx.remaining_accounts-without-manual-discriminator-check.md

## TLDR

Accounts from `ctx.remaining_accounts` bypass Anchor's automatic discriminator verification. Without checking the first 8 bytes against the expected Anchor discriminator, an attacker can pass an account of a different struct type that shares the same owner program, leading to type confusion.

## Detection Heuristics

**Deserialization Without Discriminator Verification**
- `MyAccountType::try_from_slice(&account.data.borrow())` or `MyAccountType::try_deserialize(&mut ...)` called on a `remaining_accounts` entry without first verifying `&data[..8] == MyAccountType::DISCRIMINATOR`
- Account data interpreted as a specific struct type using only owner check, not discriminator check

**Type Cosplay via remaining_accounts**
- Program has multiple account types with the same owner (the program itself); code picks an account from `remaining_accounts` and reads it as type A without discriminating it from type B

**Generic Data Reads Skipping Discriminator**
- Code reads specific byte offsets from `remaining_accounts` entries as if the account structure is known, without validating the discriminator that would confirm the structure

## False Positives

- Account is a token account or system account whose structure is fixed by an external program and does not use Anchor discriminators; the owner check alone is sufficient
- Account type is confirmed by an address constraint that uniquely identifies the account


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/readme.md

## Classifications

Run `cat $SKILL_DIR/reference/anchor/fv-anc-3-account-ownership-validations/<filename>` to read any case file listed below.

#### fv-anc-3-cl1-trying-to-modify-an-account-without-checking-if-its-writeable.md

#### fv-anc-3-cl8-using-ctx.remaining_accounts-without-manual-ownership-check.md

#### fv-anc-3-cl9-using-ctx.remaining_accounts-without-manual-discriminator-check.md


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-5-cross-program-invocation-cpi/fv-anc-5-cl1-lack-of-validation-of-external-program-before-cpi.md

## TLDR

When the program ID for a CPI target is passed as an account in the transaction rather than hardcoded, an attacker can substitute a malicious program. Without validating the program ID before calling, the CPI executes arbitrary attacker-controlled code with the caller's account context.

## Detection Heuristics

**Program Account Used Without Key Comparison**
- `ctx.accounts.external_program.to_account_info()` passed to `CpiContext::new` or `invoke` without first comparing `ctx.accounts.external_program.key()` against a known program ID constant
- `AccountInfo` for a program accepted in the context struct as `external_program: AccountInfo<'info>` without an `#[account(address = expected_program_id)]` constraint

**Dynamic Program Selection Without Allowlist**
- Program ID derived from user input or an account field without an allowlist check
- CPI target varies by instruction parameter and no exhaustive match or set-membership check is performed

**Missing Program Executable Check**
- Program account not verified to be executable (`account.executable == true`) before use as a CPI target

## False Positives

- Program ID is fully constrained by `#[account(address = spl_token::ID)]` or equivalent Anchor address constraint
- CPI uses Anchor's typed CPI helpers (e.g., `token::transfer`, `system_program::transfer`) which hardcode the target program ID internally


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-8-system-account-validation/fv-anc-8-cl1-unvalidated-sysvar-address.md

## TLDR

Solana sysvars (Clock, Rent, SlotHashes, etc.) have fixed public addresses. If a sysvar is accepted as an `AccountInfo` without verifying its address, an attacker can substitute a different account, causing the program to read attacker-controlled data as if it were the sysvar.

## Detection Heuristics

**Sysvar Accepted as AccountInfo Without Address Constraint**
- `pub rent: AccountInfo<'info>` or `pub clock: AccountInfo<'info>` in a context struct without `#[account(address = sysvar::rent::ID)]` or equivalent
- Sysvar account deserialized using `Rent::from_account_info(&ctx.accounts.rent)` without a prior address check

**Missing address Constraint on Sysvar Accounts**
- Sysvar fields in Anchor context structs declared as `AccountInfo` instead of the typed `Sysvar<'info, Rent>` or `Sysvar<'info, Clock>` wrappers
- No `require!(ctx.accounts.rent.key() == sysvar::rent::ID, ...)` in the instruction body when `AccountInfo` is used

**Sysvar Data Read Without Identity Verification**
- `Rent::try_from_slice(&account.data.borrow())` called on an account not verified to be the Rent sysvar
- Clock fields (e.g., `unix_timestamp`, `slot`) read from an account without confirming it is the Clock sysvar

## False Positives

- Anchor typed sysvar wrappers `Sysvar<'info, Clock>` or `Sysvar<'info, Rent>` used, which enforce address validation automatically
- Sysvar accessed via `Clock::get()` or `Rent::get()` syscalls, which retrieve the canonical sysvar data without account passing


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-8-system-account-validation/fv-anc-8-cl2-instruction-introspection-using-absolute-index.md

## TLDR

Programs that call `load_instruction_at_checked(index, ...)` with a hardcoded or fixed index assume a specific transaction layout. An attacker can prepend additional instructions, shifting the intended instruction to a different position and causing the verification to either fail or point at an unrelated instruction, bypassing the security check or triggering a denial of service.

## Detection Heuristics

**Hardcoded Index in Instruction Sysvar Read**
- `load_instruction_at_checked` or equivalent called with a literal index (e.g., `0`, `1`, `ix_index - 1`) rather than a dynamically discovered index
- Program uses `current_index - 1` to find a preceding instruction without verifying that instruction matches the expected program ID and data
- Index value treated as authoritative without checking the located instruction's program ID

**No Program ID Validation on Located Instruction**
- Instruction loaded by index but program ID of that instruction not compared against an expected constant before trusting its data
- Instruction data parsed from the introspected instruction without verifying it originated from the expected program (e.g., Ed25519 or Secp256k1 native program)
- Error condition when the expected instruction is not at the given index is a generic failure rather than a specific invalid-instruction error

**Attacker Can Prepend Instructions**
- Transaction allows arbitrary number of pre-instructions before the main instruction; no constraint on total instruction count
- Nonce or fee-payment instruction prepended by attacker shifts all subsequent instruction indices by one

## False Positives

- Program iterates all instructions and searches for one from the expected program with the expected discriminator, regardless of position; absolute index is never trusted
- Index is provided as an instruction parameter and the program validates that the instruction at that index has the expected program ID and data prefix


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-8-system-account-validation/fv-anc-8-cl3-address-lookup-table-signer-forgery.md

## TLDR

Address Lookup Tables (ALTs) expand transaction account lists from compressed indices. A malicious transaction can use an ALT to inject accounts that appear at indices the program expects to belong to specific signers or programs. Programs that identify accounts by position rather than by explicit key comparison are vulnerable to position-based spoofing via ALT-injected accounts.

## Detection Heuristics

**Positional Account Access Without Key Comparison**
- Program accesses `ctx.remaining_accounts[n]` or instruction accounts by a positional index and trusts the account at that position without comparing its `key()` against an expected constant or stored address
- Signer status of an ALT-resolved account trusted without re-verifying the account key matches the expected signer

**ALT Injection Path**
- Transaction account list extended via an ALT that the attacker controls; attacker can populate the ALT with accounts that mimic expected positions
- Program does not check whether an account at a given position originated from a static account reference or from an ALT resolution
- Expected program ID account (e.g., Token program, System program) verified only by position without comparing the key at runtime

**No Address Constraint on Critical Accounts**
- Critical authority or program accounts accepted without Anchor's `#[account(address = expected_key)]` constraint
- Accounts in `ctx.remaining_accounts` parsed and acted upon without building a validated allowlist before the first operation

## False Positives

- Every account is validated by comparing its key against a hardcoded constant or a stored expected address, making position irrelevant
- Anchor `#[account(address = known_constant)]` constraint applied to all critical accounts, ensuring key equality before any account data is accessed


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-8-system-account-validation/fv-anc-8-cl4-durable-nonce-transaction-ordering-attack.md

## TLDR

Durable nonce transactions replace the `recent_blockhash` field with a nonce value that does not expire with slots, allowing a signed transaction to be submitted at any future time. Protocols that rely on transaction recency for security (signed price updates, authority transfers, time-bounded operations) are vulnerable when those operations can be submitted via a durable nonce transaction long after the signing context has changed.

## Detection Heuristics

**No Expiry Check Independent of Blockhash**
- Protocol accepts signed instructions or price updates without checking a timestamp from the `Clock` sysvar that must fall within a validity window
- Authority-modifying instructions carry no expiry field in their instruction data, relying only on the implicit blockhash expiry that durable nonces bypass
- Signed operations (e.g., signed delegate approvals, signed configurations) do not include a slot or Unix timestamp that the on-chain program validates against the current clock

**Durable Nonce Account Present Without Single-Use Enforcement**
- Transaction includes a nonce account and a `AdvanceNonce` instruction but the nonce authority is not invalidated or rotated after use
- Protocol does not treat transactions with a recognized nonce account as requiring additional expiry validation
- Signed off-chain messages that authorize on-chain state changes do not embed an expiry timestamp verified at execution time

**Retroactively Favorable Execution**
- Attacker holds a signed transaction that was unfavorable at signing time; conditions change (price movement, governance vote, authority change) and the transaction becomes profitable; submits it after the change
- Liquidation or settlement operations signed with durable nonces can be withheld and executed when market conditions are most advantageous to the submitter

## False Positives

- Protocol validates instruction timestamps independently of transaction blockhash using the `Clock` sysvar with an explicit validity window (e.g., `require!(clock.unix_timestamp - signed_at < MAX_VALIDITY_SECONDS)`)
- Nonce authority is a single-use keypair that is destroyed or transferred after the single authorized transaction


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-8-system-account-validation/readme.md

## Classifications

Run `cat $SKILL_DIR/reference/anchor/fv-anc-8-system-account-validation/<filename>` to read any case file listed below.


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/triager.md

### Security Expert 3: Customer Validation Expert
**ROLE:** Customer Validation Expert

**ENHANCED TRIAGER MANDATE:**
```markdown
You represent the PROTOCOL TEAM who controls the bounty budget and CANNOT AFFORD to pay for invalid findings.
Your job is to PROTECT THE BUDGET by challenging every finding from Security Experts 1 and 2.
You are FINANCIALLY INCENTIVIZED to reject findings - every dollar saved on false positives is money well spent.
You must be absolutely certain a finding is genuinely exploitable before recommending any bounty payment.

MANDATORY CROSS-REFERENCE VALIDATION:
□ Finding Consistency Check: Compare all findings for logical contradictions or overlapping issues
□ Evidence Chain Validation: Verify each finding's evidence chain (Code Pattern → Vulnerability → Impact → Risk)
□ Contract Location Verification: Confirm all referenced contracts, functions, and line numbers exist and are accurate
□ Attack Path Cross-Check: Ensure attack scenarios don't contradict protocol protections found in other areas
□ Severity Calibration Review: Check if severity levels are consistent across similar finding types
□ Economic Impact Validation: Verify economic attack scenarios are realistic and profitable

BUDGET-PROTECTION VALIDATION:
□ Technical Disproof: Actively test the finding to prove it's NOT exploitable in practice
□ Economic Disproof: Calculate realistic attack costs vs profits to show it's unprofitable
□ Evidence Challenges: Identify flawed assumptions and test alternative scenarios
□ Exploitability Testing: Try to reproduce the attack and document where it fails
□ False Positive Detection: Find protocol protections or mitigations that prevent exploitation
□ Production Reality Check: Test how actual deployment conditions invalidate the finding

Your default stance is BUDGET PROTECTION - only pay bounties for undeniably valid, exploitable vulnerabilities.
```

**ENHANCED TRIAGER VALIDATION FOR EACH FINDING:**

```markdown

### Triager Validation Notes

**Cross-Reference Analysis:**
- Checked finding against all other discoveries for consistency
- Verified no contradictory evidence exists in other analyzed contracts
- Confirmed attack path doesn't conflict with protocol protections found elsewhere
- Validated severity level matches similar findings in this audit

**Economic Feasibility Check:**
- Calculated realistic attack costs (gas fees, capital requirements, time investment)
- Analyzed profit potential vs. risk and complexity
- Evaluated if attack is economically rational for attackers

**Technical Verification:**
- Actively tested the vulnerability by attempting reproduction with provided steps
- Performed technical disproof attempts: [specific tests run to invalidate the finding]
- Verified contract locations and challenged technical feasibility through direct testing
- Calculated realistic economic scenarios to disprove profitability claims

**Evidence Chain Validation:**
[Document the complete evidence chain and validate each link:
- Code Pattern Observed: [Specific smart contract code pattern]
- Vulnerability Type: [How pattern leads to security weakness]
- Attack Vector: [How an attacker would exploit this]
- Business Impact: [Real-world consequences for protocol and users]
- Risk Assessment: [Why this matters to the protocol team]]

**Protocol Context Validation:**
[Specific technical challenges raised against this finding:
- Contract function calls tested and results
- Economic scenarios simulated and actual outcomes
- Integration tests performed and discrepancies found
- External dependency checks and potential mitigating factors]

**Dismissal Assessment:**
- **DISMISSED:** Finding is invalid because [specific technical reasons proving it's not exploitable]
- **QUESTIONABLE:** Technical issue may exist but [specific concerns about practical exploitability/economic viability]
- **RELUCTANTLY VALID:** Finding is technically sound despite [attempts to dismiss - specific validation evidence]

**Economic Recommendation:**
[Harsh economic critique: Why this finding should be deprioritized or dismissed, focusing on unrealistic economic assumptions, impractical attack scenarios, or misunderstanding of protocol economics]
```
- **QUESTIONABLE:** Technical issue may exist but [specific concerns about practical exploitability/impact]
- **RELUCTANTLY VALID:** Finding is technically sound despite [attempts to dismiss - specific validation evidence]

**Technical Recommendation:**
[Harsh technical critique: Why this finding should be deprioritized or dismissed, focusing on technical inaccuracies, impractical scenarios, or misunderstanding of protocol mechanics]


## SOURCE: hunt-skills/bountyforge/skills/triage-validation/SKILL.md

# TRIAGE & VALIDATION

One wrong answer = STOP. Kill it. Move on.

> "N/A hurts your validity ratio. Informative is neutral. Only submit what passes all 7 questions."

See also: [[Triage]], [[Lead Ledger]], [[Report Writing]], [[Vuln Classes]]

---

### Q1: Can an attacker use this RIGHT NOW, step by step?

Complete this template:
```
1. Setup:   I need [own account / another user's ID / no account]
2. Request: [exact HTTP method, URL, headers, body — copy-paste ready]
3. Result:  I can [read / modify / delete] [exact data shown in response]
4. Impact:  The real-world consequence is [account takeover / PII read / money stolen]
5. Cost:    Time: [X minutes], Capital: [$0 / $X subscription required]
```

**If you CANNOT write step 2 as a real HTTP request → KILL IT.**

---

### Q2: Is the impact on the program's accepted impact list?

Go to the program page. Find "Vulnerability Types" or "Out of Scope."

Common tiers:
- **Critical**: Any-user ATO without interaction, RCE, SQLi with data exfil, admin auth bypass
- **High**: Mass PII exfil, privilege escalation, internal SSRF with data, stored XSS all users
- **Medium**: IDOR on specific user non-critical data, XSS on sensitive page requiring click
- **Low**: Non-sensitive info disclosure, clickjacking with PoC

**If your bug maps to a listed exclusion → KILL IT.**

---

### Q3: Is the root cause in an in-scope asset?

Confirm:
- Vulnerable domain is on the in-scope list (not `*.internal.target.com`)
- It's a production asset (not staging/dev unless explicitly in scope)
- It's not a third-party service the company just uses (not Stripe, Salesforce, Google Auth)

**If out-of-scope → KILL IT.**

---

### Q4: Does it require privileged access that an attacker can't realistically get?

- "Admin can do X" = centralization risk = **KILL IT** (on 99% of programs)
- "Non-admin can do X that only admin should do" = valid
- "Requires physical access / MFA device" = usually invalid
- "Requires compromised victim account to work" = questionable, low severity at best

---

### Q5: Is this already known or accepted behavior?

Search:
1. Program's HackerOne/Bugcrowd disclosed reports: Ctrl+F endpoint name + bug class
2. GitHub issues on target repo: `is:issue label:security ENDPOINT_NAME`
3. Changelog/CHANGELOG.md — does it mention this behavior?
4. API docs / design docs — is it documented as intended?

**If acknowledged/design decision → KILL IT.**

---

### Q6: Can you prove impact beyond "technically possible"?

- XSS → show actual cookie theft or session hijack, not just `alert(1)` or `alert(document.domain)`
- SSRF → hit an internal endpoint that returns data, not just DNS ping
- SQLi → show actual data exfil from a real table, not just error message
- IDOR → show actual other-user's data in response, not just a 200 status code

**If you can only show "technically possible" → DOWNGRADE severity, not kill.**

---

### Q7: Is this a known-invalid bug class?

Check the NEVER SUBMIT list below. If it's on this list without a chain → **KILL IT.**

---

### Q8: Identity check — which session found this, and does it survive?

For any finding made under an authenticated hunt, record the answer to each:

```
1. Session ID:        [12-char BBHUNT_SESSION_ID hash from audit.jsonl]
2. Identity:          [low-priv user A / high-priv user B / API key / etc.]
3. Anonymous repro:   Does the same request work with NO auth header?
4. Cross-identity:    Does it work under session B with the same data scope?
5. Stale-cred repro:  Does a logged-out / expired session still get the data?
```

Why this matters:
- **IDOR / BOLA**: must work with session A reading session B's data — if it
  only works with no auth, that's "missing auth" not IDOR (different bug,
  different severity).
- **Priv-esc**: must work with low-priv session reading high-priv data — if
  both sessions can already see it, no bug.
- **Auth bypass**: must work *without* a valid session — if it stops working
  when you log out, you've found a permissions issue, not a bypass.
- **Always check both directions**: a finding that only reproduces under
  one identity is often a real, scoped permission boundary, not a vuln.

`audit.jsonl` entries are tagged with `session_id`. Re-run the request
under each identity and confirm the bug holds before writing the report.
This is the most common reason "confirmed IDOR" findings come back as N/A.

---

---

## ⛓️ 7-QUESTION GATE — SMART CONTRACT TRACK

For smart contract findings (EVM/Move/Solana), replace the web/general questions with these. All 7 must be YES.

### Q1 (SC): Can I exploit this RIGHT NOW with a working PoC?

Complete this template:
```
1. Setup:   [fork of deployed chain / local Anvil node / foundry test]
2. Trigger: [exact function calls, calldata, account — copy-paste ready forge test]
3. Result:  I can [steal / lock / desync / brick] [exact amount or invariant affected]
4. Impact:  The protocol consequence is [funds lost / invariant broken / permanent DoS]
5. Cost:    Time: [X minutes], Capital: [$0 / capital required for the attack]
```

**If you CANNOT write a passing `forge test` → KILL IT.**

---

### Q2 (SC): Is the triggerer someone the protocol does NOT intend to be the actor?

- "onlyOwner/governance can do X" = centralization risk = **KILL IT**
- "Any other party can do X that only the owner should do" = valid
- Trusted-actor trigger WITH a governance bypass = still valid
- Requires the attacker to already hold protocol admin keys = usually invalid

---

### Q3 (SC): Is impact concrete in protocol-native terms?

- Funds stolen or locked: state exact wei/token amounts + USD
- Accounting desync: name the exact invariant from code/docs it violates
- Oracle manipulation: show the real profit margin vs. manipulation cost
- Permanent DoS of someone's funds (locked forever, not just griefing)

**If you can only say "could lose funds" → KILL or DOWNGRADE to lead.**

---

### Q4 (SC): Is the contract version in scope and verified on-chain?

Confirm:
- Deployed on the listed chain (not testnet, not an old unpinned version)
- Source matches the verified Etherscan/Solscan bytecode
- Not `lib/`, `interfaces/`, `mocks/`, `*.t.sol`, `*Mock*`

**If out-of-scope file path or version → KILL IT.**

---

### Q5 (SC): Is this already known or accepted behavior?

Search:
1. Immunefi/Sherlock/Code4rena contest history for this protocol
2. ALL prior audit reports (`audits/` in repo, docs site)
3. CHANGELOG.md / README "known issues" / design docs
4. Prior bounty submissions (immunefi.com/vulnerabilities, program page)

**If acknowledged/known issue → KILL IT.**

---

### Q6 (SC): Is this on the contract always-rejected list?

- Theoretical / no working PoC → KILL
- Trusted-actor-only with no bypass → KILL
- View/read-only fn with wrong value, no downstream effect → KILL
- Admin backdoor behaving as documented → KILL
- MEV-dependence the protocol explicitly accepts → KILL unless profit clears documented slippage bounds
- Sub-$1 dust profit, no invariant broken → KILL (unless part of a chain)

---

### Q7 (SC): Would a DeFi-literate judge say "yes, that's a real bug"?

Read it as an Immunefi/Sherlock judge: quote the invariant, trace the exact
exploitable call path, show the PoC output. If the judge could argue "edge
case, working as intended" and you can't pre-kill that argument → **KILL.**

**Quick-kill rules:**
- No `forge test` PoC against a fork → DEMOTE to lead, not a finding
- `onlyOwner`/governance only trigger → KILL unless governance bypass shown
- Code in `lib/`/`interfaces/`/`mocks/`/`test/` → KILL
- "Docs say X but code does Y" → code is authoritative
- Old compiler, unreachable function → KILL (reachability before severity)

---

## COUNTER-PATTERNS — ANTI-REFUTATION RULES (from real misses)

These override the auto-kill reflexes above. Sourced from actual gate mistakes — do not repeat them.

**Gate 1 — "documented" / "matches upstream design" is NOT an automatic refutation:**
Rejecting on documentation requires actually having read the upstream source. Citing another protocol's behavior without seeing its code (e.g., "Camelot does the same with xGRAIL" while never opening Camelot's source) is a miss, not a defense. Docs describe intent; deployed bytecode is reality. To refute with "upstream," show the upstream code doing the same thing.

**Gate 2 — "requires oracle misreport" forces an honest-path check:**
Before rejecting a finding for relying on a misreporting oracle, check for an honest-path route to the same vulnerable state (e.g., the Lido `onchainTotalValueOnRefSlot` case — reachable with HONEST oracle data, making the "oracle manipulation" precondition unnecessary). Honest path exists → the finding stands WITHOUT the oracle caveat.

**Gate 3 — front-running a public state transition is attacker-triggerable, not "victim cooperation":**
"Requires the exiting holder's cooperation" is NOT an auto-kill when the state transition is public and observable on-chain (e.g., an xSilo `totalSupply → 0` after exit). The attacker front-runs the transition → attacker-triggerable. Precondition = a transaction the victim will unavoidably submit, not a deliberate action on their part.

**Gate 4 — split self-harm into actor-scoped legs:**
"Self-harm" often has SEPARATE victims per leg: the exiter's penalty loss is its own leg, the front-runner's captured residual is another leg. One self-inflicted leg does NOT kill the other leg's valid impact. Name the victim for EVERY leg before rejecting as "self-harm."

**Severity — "transient DoS" requires a confirmed self-resolving recovery path:**
Never call something "transient DoS" without confirming the recovery path exists and executes on its own (timelock expiry, guaranteed keeper, function any user can call to restore). Recovery dependent on a party that may never act, or unverified conditions → score as permanent DoS (or drop if no DoS is provable). Assumed recovery = inflated severity.

---

---

### Gate 0: Reality Check (30 seconds)
```
[ ] Bug is REAL — confirmed with actual HTTP requests, not code reading alone
[ ] Bug is IN SCOPE — checked program scope page explicitly
[ ] Reproducible from scratch — can reproduce starting from fresh session
[ ] Evidence ready — screenshot, response body, or video
```

### Gate 1: Impact Validation (2 minutes)
```
[ ] Can answer: "What can attacker DO that they couldn't before?"
[ ] Answer is more than "see non-sensitive data" (unless program pays for info disclosure)
[ ] Real victim: another user's data, company's data, financial loss
[ ] Not relying on victim doing something unlikely
```

### Gate 2: Deduplication Check (5 minutes)
```
[ ] Searched HackerOne Hacktivity for this program + similar bug title/endpoint
[ ] Searched GitHub issues for target repo
[ ] Read most recent 5 disclosed reports for this program
[ ] Not a "known issue" in their changelog or public docs
[ ] Google: "TARGET_NAME ENDPOINT_NAME bug bounty"
```

### Gate 3: Report Quality (10 minutes)
```
[ ] Title: [Bug Class] in [Endpoint] allows [actor] to [impact]
[ ] Steps to Reproduce: copy-pasteable HTTP request
[ ] Evidence: screenshot/video of actual impact (not just 200 status)
[ ] Severity: matches CVSS 3.1 score AND program's severity definitions
[ ] Remediation: 1-2 sentences of concrete fix
[ ] NEVER used "could potentially" or "may allow"
```

---

## NEVER SUBMIT LIST

Submitting these destroys your validity ratio.

```
Missing CSP / HSTS / security headers
Missing SPF / DKIM / DMARC
GraphQL introspection alone (no auth bypass, no IDOR demonstrated)
Banner / version disclosure without working CVE exploit
Clickjacking on non-sensitive pages (no sensitive action PoC)
Tabnabbing
CSV injection (no actual code execution shown)
CORS wildcard (*) without credential exfil proof of concept
Logout CSRF
Self-XSS (only exploits own account)
Open redirect alone (no ATO or OAuth theft chain)
OAuth client_secret in mobile app (known, expected)
SSRF DNS callback only (no internal service access or data)
Host header injection alone (no password reset poisoning PoC)
Rate limit on non-critical forms (search, contact, login with Cloudflare)
Session not invalidated on logout
Concurrent sessions
Internal IP in error message
Mixed content
SSL weak ciphers
Missing HttpOnly / Secure cookie flags alone
Broken external links
Autocomplete on password fields
Pre-account takeover (usually — very specific conditions required)
```

---

## CONDITIONALLY VALID — CHAIN REQUIRED

Build the chain first, prove it works end to end, THEN report.

| Standalone Finding | Chain Required | Valid Result |
|---|---|---|
| Open redirect | + OAuth redirect_uri → auth code theft | ATO (Critical) |
| Clickjacking | + sensitive action + working PoC | Medium |
| CORS wildcard | + credentialed request exfils user PII | High |
| CSRF | + sensitive action (transfer funds, change email, delete account) | High |
| Rate limit bypass | + OTP/reset token brute force succeeds | Medium/High |
| SSRF DNS-only | + internal service access + data returned | Medium |
| Host header injection | + password reset email uses injected host | High |
| Prompt injection | + reads other user's data (IDOR) | High |
| S3 bucket listing | + JS bundles contain API keys or OAuth secrets | Medium/High |
| Self-XSS | + CSRF to trigger it on victim without their knowledge | Medium |
| Subdomain takeover | + OAuth redirect_uri registered at that subdomain | Critical |
| GraphQL introspection | + auth bypass mutation or IDOR on node() | High |

---

### Common Score Examples

| Finding | Score | Severity | Vector |
|---|---|---|---|
| IDOR read PII, any user, auth required | 6.5 | Medium | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |
| IDOR write/delete, any user | 7.5 | High | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| Auth bypass → admin panel | 9.8 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Stored XSS → cookie theft, stored | 8.8 | High | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N |
| SQLi → full DB dump | 8.6 | High | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| SSRF → cloud metadata | 9.1 | Critical | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N |
| Race → double spend | 7.5 | High | AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N |
| GraphQL auth bypass | 8.7 | High | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| JWT none algorithm | 9.1 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |

### Metric Quick Guide

| What you have | Metric | Value |
|---|---|---|
| Exploitable over internet | AV | Network (N) |
| No special timing or race | AC | Low (L) |
| Free account needed | PR | Low (L) |
| No login needed | PR | None (N) |
| Admin needed | PR | High (H) |
| No victim action | UI | None (N) |
| Victim must click | UI | Required (R) |
| Reads all data | C | High (H) |
| Reads some data | C | Low (L) |
| Modifies all data | I | High (H) |
| Crashes service | A | High (H) |
| Affects only app | S | Unchanged (U) |
| Affects browser/OS/cloud | S | Changed (C) |

---

## KILL FAST RULES

The goal is to QUICKLY disqualify bad leads so you hunt real bugs:

1. **5-minute rule**: If you can't fill in Q1's template in 5 minutes → move on
2. **Precondition count**: More than 2 preconditions simultaneously required → kill it
3. **Impact test**: "What does attacker walk away with?" — if nothing tangible → kill it
4. **Admin bypass**: "Admin can do X" is NEVER a bug → kill it immediately
5. **Design doc test**: If it's documented behavior → kill it immediately
6. **Rabbit hole signal**: 30+ min on Q6 with no reproducible PoC → kill it

---

## ANTI-PATTERNS THAT LOSE MONEY

```
Writing a report before confirming the bug exists (most common)
Submitting theoretical impact without proof
"The API returns more fields than necessary" (sensitivity matters — is it actually sensitive?)
Chaining A+B into one report when they're separate bugs (two separate payouts)
Reporting B saying "similar to A in my other report" — fresh Gate 0 for every bug
Overclaiming severity — triagers trust you less next time
Under-describing impact — triager doesn't understand why it matters
```


## SOURCE: hunt-skills/bountyforge/wiki/Lead Ledger.md

# Lead Ledger

Open leads are persistent research objects, not notes to self.

See also: [[BountyForge]], [[Triage]], [[A→B Chains]], [[Methodology]], [[Trust Map]]

---

## Lead Lifecycle

```
OPEN → MUTATING → FINDING   (both halves proven → promoted)
  │         │
  │         └──→ PARKED (impact not provable → chain pool)
  └────────────→ PARKED (kill refused: only one half refuted)
  └──→ KILLED (BOTH halves refuted with evidence)
```

---

## The Two-Question Rule

Every lead has TWO independent questions:

| Question | What to answer |
|----------|----------------|
| **TRIGGER** — "Can this path fire?" | Reachable? Attacker-invokable? |
| **IMPACT** — "If it fires, what's the harm?" | Victim loses what? How much? |

**Rules:**
1. Both halves get a written trace.
2. Impact is victim-harm, not attacker-profit.
3. Three verdicts: FINDING / OPEN LEAD / KILL.
4. "Below the bar" is not a kill.

---

## One-Variable Mutation

Change exactly ONE thing per attempt:
- `user_id` (IDOR)
- `role` (privesc)
- `state` (TOCTOU)
- `amount` (business logic)
- `token` (auth bypass)
- `method` (GET vs POST)
- `version` (v1 vs v2)

**Never two at once.** You need to attribute the result.

---

## Missing Preconditions

Track them by name:
- "need second account for cross-account proof"
- "need race window (10ms sleep)"
- "need admin role"
- "need sibling endpoint /v2/users/{id}"
- "need chain partner for ATO"

Each resolves to: `missing → present | refuted | irrelevant` **with evidence**.

---

## Kill Guard

`kill_lead()` refuses unless BOTH halves are refuted with evidence.

One-half refutation = auto-park with counted dismissal attempt.

A parked lead stays in the chain pool. It becomes the missing half of a future A→B chain.

---

## Re-Trigger Conditions

Every KILLED or PARKED lead records what would reopen it:

| Dead End | Observable that Reopens |
|----------|------------------------|
| RAM escape | New shared-memory region appears |
| vsock channel | vsock device enumerated |
| MMDS metadata | 169.254.169.254 responds |
| Per-sandbox CA | CA cert differs between instances |

Next: [[Triage]] → [[Report Writing]]


## SOURCE: hunt-skills/bountyforge/wiki/Report Writing.md

# Report Writing

Platform-specific templates, human tone, impact-first.

See also: [[BountyForge]], [[Triage]], [[Lead Ledger]], [[A→B Chains]], [[Methodology]]

---

### Title
`[Bug Class] in [Endpoint] allows [role] to [impact]`

**Examples:**
- `IDOR in /api/v2/users/{id} allows any user to read other users' PII`
- `SSRF in webhook handler allows attacker to access cloud metadata`
- `Race condition in withdrawal allows double-spend of $5,000`

### Summary (1 sentence)
What the attacker CAN DO. Not "could potentially" — what they ACTUALLY DO.

**Good:** "An attacker can read any user's profile data including email, phone, and password hash by changing the user_id parameter in GET /api/v2/users/{id}."

**Bad:** "An attacker could potentially access other users' data if certain conditions are met."

### Steps to Reproduce
Exact HTTP requests. Copy-pasteable. Include:
- Full URL
- All headers (especially auth)
- Request body
- Expected response

### Impact
Quantified business impact:
- "All 50K users affected"
- "$150K in fraudulent withdrawals possible"
- "Password hashes exposed for 10K accounts"

## Human Tone Rules

- **Be direct.** "An attacker can..." not "It might be possible to..."
- **Be specific.** "Reads email, phone, password hash" not "accesses user data"
- **Be quantified.** "50K users affected" not "many users"
- **Be reproducible.** Exact HTTP requests, not vague descriptions
- **Be honest.** If impact is Medium, say Medium. Don't inflate.

---

## Severity Escalation Language

| Severity | Language |
|----------|----------|
| Critical | "allows full account takeover", "enables theft of $X", "results in RCE" |
| High | "exposes sensitive PII for N users", "bypasses authentication" |
| Medium | "allows unauthorized access to", "could be chained with" |
| Low | "reveals internal information", "missing security header" |

---

## Pre-Submit Checklist

- [ ] Title follows format
- [ ] First sentence is impact-first
- [ ] HTTP requests are exact
- [ ] Under 600 words
- [ ] CVSS matches impact
- [ ] No "theoretical" language
- [ ] Checked for duplicates
- [ ] In scope for program

See [[Triage]] for the 7-Question Gate.


## SOURCE: hunt-skills/bountyforge/wiki/Triage.md

# Triage

Validate before submitting. The 7-Question Gate.

See also: [[BountyForge]], [[Lead Ledger]], [[Report Writing]], [[Vuln Classes]], [[Methodology]]

---

## The 7-Question Gate

Run on EVERY finding before writing a report:

| # | Question | Pass Criteria |
|---|----------|---------------|
| 1 | **Is the trigger proven?** | Path fires with a real request, not "could theoretically" |
| 2 | **Is the impact traced?** | Victim loses specific thing (amount, data, account) |
| 3 | **Is it reproducible?** | Others can follow your steps and get same result |
| 4 | **Is it not already known?** | Checked disclosed reports, CVE databases, duplicate reports |
| 5 | **Is it in scope?** | Program accepts this bug class |
| 6 | **Is there a real victim?** | Not self-XSS, not admin-only, not require unusual actions |
| 7 | **Is there business impact?** | Quantified: "N users", "$X at risk" |

**One wrong answer = KILL the finding.** Don't waste time.

---

## Always Rejected (Don't B submitting)

| Pattern | Kill Reason |
|---------|-------------|
| "Could theoretically allow..." | Trigger not proven |
| "An attacker with X, Y, Z conditions could..." | Too many preconditions |
| "Wrong implementation but no practical impact" | Wrong but harmless |
| Dead code with a bug in it | Not reachable |
| SSRF with DNS-only callback | Need data exfil or internal access |
| Open redirect alone | Need ATO or OAuth chain |
| "Could be used in a chain if..." | Build the chain first, THEN report |
| Self-XSS | No victim affected |
| Clickjacking on non-sensitive action | No meaningful impact |

---

## Severity Decision Guide

| Severity | Criteria |
|----------|----------|
| **Critical** | RCE, ATO, full financial control, chain that drains funds |
| **High** | IDOR on PII + write, SSRF to cloud metadata, SQLi with data exfil |
| **Medium** | IDOR on PII (read only), XSS with cookie theft, business logic flaw |
| **Low** | Self-XSS, info disclosure, version disclosure, missing headers |
| **Informational** | Best practice violations, defense-in-depth suggestions |

---

## CVSS 3.1 Quick Reference

```
AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 (Critical)
AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8 (High)
AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N = 8.1 (High)
AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:N = 6.3 (Medium)
AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N = 6.1 (Medium)
AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N = 3.7 (Low)
```

---

## Pre-Submit Checklist

- [ ] All 7 questions answered YES
- [ ] Title follows format: `[Bug Class] in [Endpoint] allows [role] to [impact]`
- [ ] First sentence says what attacker CAN DO (not "could potentially")
- [ ] HTTP requests are exact and reproducible
- [ ] Report is under 600 words
- [ ] CVSS score matches actual impact
- [ ] No "theoretical" language
- [ ] Checked for duplicates on program

Next: [[Report Writing]]


## SOURCE: hunt-skills/bountyforge/wiki/Trust Map.md

# Trust Map

Who trusts whom. The attack surface.

See also: [[BountyForge]], [[Methodology]], [[Web2 Recon]], [[Vuln Classes]], [[A→B Chains]]

---

## What Is a Trust Boundary?

Every bug is a trust violation. The system trusted something it shouldn't have:
- **Identity** it shouldn't have → IDOR, privilege escalation, auth bypass
- **State** it shouldn't have → race conditions, TOCTOU, state machine bypass
- **Input** it shouldn't have → injection, deserialization, SSTI
- **Intent** it shouldn't have → business logic abuse, economic manipulation

**Map trust first. Hunt violations second.**

---

## Trust Endpoint Categories

| Category | Examples | Bug Classes |
|----------|----------|-------------|
| **Identity trust** | Auth tokens, session cookies, API keys, JWT claims, OAuth flows | IDOR, auth bypass, session hijack |
| **Input trust** | User params, headers, body, file uploads | XSS, SQLi, SSRF, SSTI, XXE |
| **State trust** | Database records, cache, file system | Race conditions, TOCTOU, replay |
| **Service trust** | Webhooks, APIs, oracles, payment processors | SSRF, signature bypass, replay |
| **User trust** | Fingerprints, User-Agent, IPs, referrer | Spoofing, header injection |

---

## The Trust Graph

```
                    ┌─────────────┐
                    │   CLIENT    │
                    │  (browser)  │
                    └──────┬──────┘
                           │
                    trust: token/cookie
                           │
                           ▼
                    ┌─────────────┐
                    │     CDN     │
                    │  (Cloudflare)│
                    └──────┬──────┘
                           │
                    trust: X-Forwarded-For
                           │
                           ▼
                    ┌─────────────┐
                    │ LOAD BALANCER│
                    └──────┬──────┘
                           │
                    trust: internal network
                           │
                           ▼
                    ┌─────────────┐
                    │  APP SERVER  │
                    └──────┬──────┘
                           │
                    trust: SQL query
                           │
                           ▼
                    ┌─────────────┐
                    │  DATABASE    │
                    └─────────────┘
```

**Every arrow is a trust boundary. Every boundary is an attack surface.**

---

## Building the Trust Map

1. **Identify all trust endpoints** from recon. See [[Web2 Recon]].
2. **Draw edges** between entities (client, CDN, LB, app, DB, third-party).
3. **Label each edge** with trust type: `token_based`, `header_based`, `ip_based`, `no_auth`, `signature`.
4. **Find crossings** — where does trust cross from outside to inside?
5. **Attack crossings** — the highest-value bugs live at trust boundary crossings.

---

## Trust Map Schema

```markdown
| trustor | trustee | trust_type | strength | boundary_crossed |
|---------|---------|------------|----------|------------------|
| client | api | token_based | 0.7 | public→private |
| user | admin | header_based (X-Forwarded-For) | 0.9 | user→admin |
| app | webhook | signature_based | 0.5 | external→internal |
```

**High-impact bugs:** crossings over `no_auth`/`header_based`/`ip_based`/`internal_skip` edges.

---

## Finding Trust Violations

| Signal | What to Test |
|--------|--------------|
| ID parameter in URL | IDOR — can you access other users' data? |
| Auth header checked | Does the check actually exist? Or just assumed? |
| Webhook endpoint | Is the signature validated? Or just present? |
| Admin path | Is auth enforced? Or just hidden? |
| API versioning | Does v1 still work with weaker auth? |
| Error messages | Do they reveal trust assumptions? |

Next: [[Methodology]] → [[A→B Chains]]


## SOURCE: hunt-skills/bugcrowd-reporting/SKILL.md

# BUGCROWD REPORTING — Program-Specific Tactics

> Companion to the generic `report-writing` skill. Use when working specifically on Bugcrowd submissions where VRT mapping, OOS-clause rebuttals, or per-program target selection matter.

This skill encodes patterns that apply specifically to Bugcrowd's submission flow. For the generic per-platform templates (HackerOne / Bugcrowd / Intigriti / Immunefi report bodies), use the `report-writing` skill. For the 7-Question Gate before deciding to report at all, use `triage-validation`.

---

## 1. VRT Category Selection — Search & Fallback Strategy

Bugcrowd's submission form requires a single VRT (Vulnerability Rating Taxonomy) selection. The dropdown's default severity is bound to the chosen node — pick wrong and the form auto-suggests a lower priority (often P4) when the actual impact is P3 or P2.

> Note: VRT default severities are not fixed constants. Bugcrowd revises the VRT schema across versions, and individual programs can remap defaults via their own priority configuration. The P-values shown in the examples below (e.g., "No Rate Limiting on Form → Login" defaulting to P4) are the typical baseline at time of writing — always read the severity the *current* form actually auto-suggests for *this* program rather than assuming the value here.

### 1.1 Search hierarchy (try in order, pick the highest-severity match that still describes the bug)

For any finding, search the VRT dropdown with these terms in this order:

1. **The bug's primary class** — e.g., `IDOR`, `XSS`, `SSRF`, `auth bypass`, `2FA bypass`
2. **The data category exposed** — e.g., `PII`, `sensitive data exposure`, `disclosure of secrets`
3. **The control bypassed** — e.g., `broken access control`, `authentication bypass`
4. **The endpoint type** — e.g., `no rate limiting on form > login`, `no rate limiting on form > change password`
5. **The generic parent node** — e.g., `Server Security Misconfiguration > Other`, `Broken Access Control > Other`

### 1.2 Pick the highest-severity match that still accurately describes the bug

Never select a VRT that misrepresents the bug just to get a higher default severity. Triagers will reassign and may flag the misrepresentation. The discipline is: pick the most specific *accurate* VRT, then use §2 (Manual Severity Override) if the default is wrong.

### 1.3 Common mappings worth knowing

| Finding type | First-choice VRT | Fallback |
|---|---|---|
| ATO via missing 2FA on password change | Broken Authentication & Session Management → Second Factor Authentication (2FA/MFA) → Bypass | Broken Auth → Authentication Bypass → Other |
| Password oracle without rate limit | Broken Authentication & Session Management → Authentication Bypass → Other | Server Security Misconfiguration → No Rate Limiting on Form → Login |
| GraphQL introspection / APQ allowlist bypass | Server Security Misconfiguration → Other (justify in body) | Broken Access Control → Other |
| Username → real name PII enumeration | Sensitive Data Exposure → PII Leakage / Disclosure of Secrets → Non-Corporate User | Broken Access Control → Other |
| State desync on security-sensitive action | Application-Level DoS → Other (with state-desync framing) | Server Security Misconfiguration → Other |
| Email/SMS pumping on auth-flow endpoint | Server Security Misconfiguration → No Rate Limiting on Form → Email-Triggering / SMS-Triggering | Server Security Misconfiguration → No Rate Limiting on Action |
| Token brute-force (email-change OTP, password reset) | Broken Authentication → Authentication Bypass → Other | Server Security Misconfiguration → No Rate Limiting on Action |

### 1.4 If no good VRT exists

Pick `Server Security Misconfiguration → Other` or `Broken Access Control → Other` and **lead the description body with a "VRT mapping note"** explaining why the chosen node is the closest available match and what the bug actually is.

---

## 2. Manual Severity Override

Bugcrowd's form lets you manually set Technical Severity *separate from the VRT default*. The form text itself states: *"A severity rating suggested by the VRT is not guaranteed to be the severity rating applied to your submission."*

### 2.1 When to override

Override the VRT default when:
- The chained outcome is a higher severity than the standalone bug class (chain → ATO)
- The VRT category is approximate and its default doesn't reflect the actual impact class
- The program's own Focus Areas explicitly list this outcome at a higher severity than VRT's default
- The data class exposed is more sensitive than the VRT's example uses (e.g., real-name PII vs. handle enumeration)

### 2.2 How to override (form mechanics)

1. Select the VRT that most accurately describes the bug (per §1)
2. Note the auto-suggested severity (P4, P3, etc.)
3. In the **Technical Severity** field, manually pick the severity you're requesting
4. Add a **Severity Request** paragraph as the FIRST section of the description body (per §3)

### 2.3 Don't over-claim

P1 inflation is the fastest way to lose triager trust. Reserve P1 for ATO without interaction, RCE, mass PII exfiltration, fund theft, and similar Critical-bucket impacts. If the chain to P1 requires a separate stolen-cookie premise, file the standalone primitive at P3 and discuss the chain explicitly with cross-references (per §4).

---

## 3. Severity-Request Paragraph — Always First in the Body

When the VRT default underrates impact, the FIRST section of the description body should be a severity-request paragraph. This is the first thing the triager reads and it pre-empts the auto-close that often happens when triagers see "P4" in the form.

## Severity request — please review carefully before applying VRT default

The closest VRT category for this finding is "[chosen VRT]," which Bugcrowd defaults to **P[N] ($X-$Y in [program]'s rubric)**. **I am requesting evaluation at P[M] [standalone | in chain with submission XXXX]** for the following reasons:

1. **[Impact axis 1]** — [specific reason this finding exceeds the VRT default's example]
2. **[Impact axis 2]** — [specific reason, often citing the program's own Focus Areas]
3. **[Impact axis 3]** — [specific reason, often comparing to historical bounty payouts for the same data class]

[Optional: one paragraph contrasting the VRT default's typical example with this finding's actual impact, e.g., "P4 = No Rate Limiting on Login Form" applies to ordinary login pages where brute force is bounded by lockout policies; this endpoint has neither lockout nor throttle.]
```

## Severity request — please review carefully before applying VRT default

The closest VRT category for this finding is "No Rate Limiting on Form → Login," which Bugcrowd defaults to **P4 ($XX–$YY in this program's rubric)**. **I am requesting evaluation at P3 standalone, P2 in chain with submission XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX** for the following reasons:

1. **[Endpoint] is a password-disclosure oracle, not a generic rate-limit gap.** The endpoint returns true/false for a supplied password — combined with cookie theft, it is the exact primitive an attacker uses to learn the victim's *durable* credential from a stolen *transient* session.
2. **The chained outcome is "Account Takeover,"** explicitly listed under the program → Focus Areas → Critical (P1) examples. This finding is one of two independent links that make that chain work; the other is submission XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX.
3. **The two findings have independent fix surfaces.** Per the program's "one fix = one bounty" rule they should be evaluated as two separate findings whose chain raises the joint severity.

The "P4 = No Rate Limiting on Login Form" default applies to ordinary login pages where brute-force is bounded by lockout policies. This endpoint has neither lockout nor throttle, and the result of brute force is the *user's actual password* (not a session) — making the impact significantly higher than the default VRT severity assumes.
```

### 3.3 Tone guidelines

- Open with *"Severity request — please review carefully before applying VRT default"* (literal phrase). Triagers recognize this and don't auto-close.
- Use **bold** sparingly; one or two phrases per reason at most.
- Never use "could potentially" or "may allow" — these are downgrade-bait.
- Cite the program's own Focus Areas / accepted-impact list by exact name.
- Cross-reference linked submissions by full submission ID (UUID format).

---

## 4. OOS-Clause Rebuttals — Templates

Bugcrowd triagers sometimes auto-close findings by mapping them to an OOS clause without reading the report. Pre-empt this by including an **In-scope justification** section that quotes the OOS clause and explains why your finding doesn't fit it.

### 4.1 "Rate limiting on non-authentication endpoints" rebuttal

When the finding is on an authentication endpoint (login, password change, password verify, OTP verify, token validate):

```markdown

## In-scope justification

The program OOS list excludes "Rate limiting or brute-force issues on **non-authentication** endpoints." `[endpoint name]` is the canonical authentication endpoint — it accepts a password/token/OTP and returns whether it matches the user's stored credential. By definition this is an authentication primitive. The OOS clause's "non-authentication" qualifier therefore does NOT apply.
```

### 4.2 "Debug information disclosure" rebuttal (for schema/introspection findings)

When the finding involves schema disclosure that's actually a control bypass (e.g., GraphQL allowlist bypass exposing the mutation surface):

```markdown

## In-scope justification

This is not a "debug information" finding. The [persisted-query allowlist | introspection gate | etc.] is acting as an authorization control on the [GraphQL surface | API tree | etc.]. The bypass converts that gate into a no-op — multiple [mutations | endpoints] become reachable that the official clients cannot invoke. The schema disclosure is incidental; the impact is **mutation-surface unlock**, not information leakage.
```

### 4.3 "User enumeration with low-risk information" rebuttal

When the finding leaks more than just "this handle/email exists":

```markdown

## In-scope justification

The program OOS list excludes "User Enumeration issues with **low-risk and insignificant** information being enumerated." The data leaked here is **neither low-risk nor insignificant**: it includes the matched user's [full real first name, last name, profile photo / SSN last 4 / phone number / etc.]. Real-[name | identity | etc.] knowledge is the same data class that gates the program's own [account-recovery flows / fraud-investigation interviews / support-call verification], which means this lookup directly defeats one of the program's own anti-fraud controls. This is PII disclosure, not handle enumeration.
```

### 4.4 "Theoretical issues / not exploitable" rebuttal

When the finding's exploitability has been demonstrated end-to-end:

```markdown

## In-scope justification

This finding is exploitable end-to-end as demonstrated in the PoC: [one-sentence summary of the proven exploitation path]. The PoC includes [N HTTP requests with redacted cookies | N screenshots | a sanitized HAR file | etc.] showing the attacker's session [reading victim data | changing victim credentials | etc.]. The OOS clause for "theoretical issues that are not exploitable, or can not be demonstrated as exploitable" does not apply.
```

### 4.5 If you don't have end-to-end proof

If you only have an "API behavior" observation without a fully demonstrated exploitation path, the finding is theoretical. Don't file it. Capture the missing evidence (delivery confirmation, token-format inspection, cross-account victim data in response, etc.) and re-evaluate. Filing theoretical findings damages researcher reputation on the platform.

---

## 5. Chained Findings — Cross-Reference Strategy

Many high-impact findings are chains of two or more standalone primitives (oracle + missing step-up = ATO). Bugcrowd's program rule: *"Submit one vulnerability per report. If multiple vulnerabilities must be chained to demonstrate impact, you may include them together, but please clearly explain the chain."*

### 5.1 Filing strategy for chains

1. **Identify the highest-severity chained outcome** (typically the one that maps to a P1/P2 example in the program's Focus Areas).
2. **File the chain primitives FIRST** as separate reports — each at its standalone severity (typically P3/P4). A submission's UUID only exists *after* it is filed, so the primitives must exist before anything can reference them. Leave the cross-reference line in each primitive's body as a placeholder for now.
3. **File the chain consumer** — the report whose body describes the full ATO/RCE/etc. impact at the chained severity (e.g., P1). Because the primitives already exist, fill in their real UUIDs in the consumer's "Chain partners" block (per §5.2).
4. **Edit each primitive after filing the consumer** to backfill the consumer's UUID: *"Chain partner: submission [UUID] for the full impact narrative."* (The reference is bidirectional, so one report must be edited after the other is filed — Bugcrowd allows post-submission edits to the description body.)

### 5.2 Cross-reference template

In the chain consumer's body, near the top:

```markdown

## Chain partners (filed as separate reports)

- **submission [UUID-1]** — [primitive 1: e.g., `me.verify_password` no rate limit]
- **submission [UUID-2]** — [primitive 2: e.g., GraphQL APQ allowlist bypass]

These primitives have independent fix surfaces and are filed separately per the program's "one fix = one bounty" rule. The chained impact described here requires both primitives to be exploited end-to-end.
```

In each primitive's body:

```markdown

## Chain context

This finding is the [N]th of [M] independent primitives that together produce [impact, e.g., "permanent account takeover from a stolen session cookie"]. The full chain narrative and the chained severity (P1) are documented in submission [UUID]. This standalone report is at P3 reflecting the primitive's individual impact.
```

### 5.3 What NOT to do

- Don't paste the entire chain narrative into every primitive's body. Cross-reference instead.
- Don't claim each primitive is independently P1 — overclaiming damages credibility for all linked reports.
- Don't ask for a single combined bounty for the chain. The program's "one fix = one bounty" rule means each independent fix surface is a separate bounty. Frame the chain as a severity-amplifier, not a merge request.

---

## 6. Target Selection — QA vs. Production

Programs that scope both production and QA assets (e.g., `app.target.com` vs. `app-qa.target.com`) require careful target selection.

### 6.1 Picking the right target dropdown entry

| If you tested... | Pick this target | Why |
|---|---|---|
| Production app/API | The production target | Most accurate; signals the impact landed on real users |
| QA app/API (per program rules for non-US researchers) | The QA target (e.g., `Sign In - (QA)`, `Enrollment - (QA)`) | Accurate per program rules; signals friendly tester |
| QA but no specific QA target exists | Closest matching production target with a clear QA disclaimer in the body | Triager will reassign correctly if needed |
| Cross-asset finding (multiple targets affected) | The asset where the bug originates / has the highest impact | Add list of other affected targets in the body |

## Notes for triagers

- Tested in the QA environment ([qa-host]) per the program's instruction for non-US researchers / per the program's QA-testing scope.
- Production may enforce additional controls that QA does not — please confirm whether the same resolver code path runs on production.
- All testing limited to my own QA test account; no other accounts were interacted with.
- Selected target: `[chosen-target]`. Selected VRT: `[chosen-VRT]`. Both selected as closest available matches; please reassign if more appropriate options exist.
```

---

## 7. Researcher-Side Hygiene (Bugcrowd-specific)

These are program-rule items that affect submission quality even though they're not part of the report body itself.

### 7.1 Account email — Bugcrowdninja alias

Most Bugcrowd-managed programs ask researchers to use their `@bugcrowdninja.com` alias as the account email on the target. This flags traffic as friendly-tester to the target's fraud team. Steps:

1. Sign up for the target using your Bugcrowd alias (looks like `username@bugcrowdninja.com`)
2. If you already have an account, update the email to the alias before testing
3. If the program offers a contact path for multi-account testing, use that to coordinate additional aliased accounts (`alias+test1@bugcrowdninja.com`, etc.)
4. Document the alias in the report's "Notes for triagers" section so the triager can correlate test traffic in their logs

### 7.2 Account-state restoration after PoC

After demonstrating any state-changing action (password change, email change, device removal, money transfer):

1. Restore the account to its pre-PoC state immediately (e.g., revert the password to what it was)
2. Document the restoration in the report — *"Account state was restored immediately after the PoC."*
3. If restoration is impossible (e.g., a sent email cannot be unsent), document the residual state honestly

### 7.3 Cookie / session rotation after submission

After submitting any report that includes session-cookie-derived evidence:

1. Log out and log back in to rotate the session cookie
2. Any cookie value visible in screenshots / HARs you submitted is now dead
3. Optionally, rotate the test-account password to a fresh value not used elsewhere — that way passwords visible in PoC screenshots are also dead

### 7.4 If the test account gets locked

1. Don't create a second account to bypass the lock — that looks like fraud
2. Email the program-specific contact (if provided) with your Bugcrowd username and the report ID
3. Wait for the program team to unblock you; testing during the lock period damages credibility

---

## 8. Submission-Order Strategy for Multi-Finding Engagements

When you have multiple findings from a single engagement, the order matters.

### 8.1 Recommended order

1. **Chain primitives before their consumer.** A consumer references the primitives' report UUIDs, which only exist once the primitives are filed (see §5.1). File the best-evidenced primitive first to lock your timestamp, then the rest of the chain's primitives.
2. **The chain consumer next** — fill in the real primitive UUIDs, then edit each primitive to backfill the consumer's UUID (Bugcrowd allows post-submission body edits).
3. **Standalone P3 findings next.** Order by quality of evidence: best-evidenced first, riskier (OOS-adjacent) findings later.
4. **OOS-risky findings last.** By the time these land, you've established a credible track record on this engagement.

### 8.2 Tracking submission IDs

Maintain a simple text file with each submission's UUID, severity, and one-line description. You'll reference these IDs across reports and during any subsequent triager dialogue.

### 8.3 What to avoid

- Don't file all findings in a single batch within minutes. Triagers see this as low-effort spam.
- Don't file an OOS-risky finding before a clean P3 from the same engagement. The clean one establishes credibility; the risky one benefits from being read in that context.
- Don't disclose any findings publicly until the program explicitly says it's OK. Bugcrowd's confidentiality applies to both unresolved AND resolved issues.

---

## 9. Pairing with Other Skills

| For this question / task | Use this skill |
|---|---|
| "Should I report this finding at all?" | `triage-validation` (7-Question Gate) |
| "What's the report body template for Bugcrowd?" | `report-writing` |
| "What VRT do I pick?" | This skill (`bugcrowd-reporting`) §1 |
| "How do I argue for higher severity?" | This skill §2-3 |
| "How do I rebut an OOS objection?" | This skill §4 |
| "How do I redact cookies / PII in screenshots?" | `evidence-hygiene` |
| "Where do I find the payload for this exploitation step?" | `security-arsenal` |
| "Where do I find recon probes for this asset class?" | `offensive-osint` |

---

## Notes on usage

This skill is small and focused. It does NOT duplicate content from `report-writing` (per-platform templates, CVSS scoring, downgrade counters, 60-second pre-submit checklist) — load both skills together when filing a Bugcrowd report. The two skills' content composes naturally because their boundaries are clean: `report-writing` is the body templates, `bugcrowd-reporting` is the program-specific tactics layered on top.

---

## Related Skills & Chains

- **`report-writing`** — Always load this skill alongside `bugcrowd-reporting`. Workflow primitive: `report-writing` provides the body skeleton; this skill layers VRT selection + severity-request paragraph + OOS-clause rebuttals on top of that skeleton.
- **`triage-validation`** — When deciding if a Bugcrowd-bound finding will pass triage. Workflow primitive: 7Q gate runs first; only validated findings reach this skill for VRT mapping.
- **`evidence-hygiene`** — When attaching screenshots / HARs to a Bugcrowd submission. Workflow primitive: Bugcrowd's private attachment system requires redacted evidence; route everything through `evidence-hygiene` before clicking attach.
- **`security-arsenal`** — When the PoC step needs payloads cited verbatim. Workflow primitive: the "Steps to Reproduce" section in this skill's report bodies pulls exact payloads from `security-arsenal` so the triager can paste-and-run.
- **`bb-methodology`** — When confirming engagement mode is bug-bounty (not red-team). Workflow primitive: PART 0 of `bb-methodology` answers "bug bounty?"; if yes AND the target is Bugcrowd, this skill becomes the reporting overlay.


## SOURCE: hunt-skills/evidence-hygiene/SKILL.md

# EVIDENCE HYGIENE — PoC Capture & Redaction Discipline

> Use this skill BEFORE capturing any screenshot, exporting any HAR, or attaching any evidence to a bug-bounty submission. It catches the most common evidence-hygiene mistakes that cause cookies to leak, PII to be shared without consent, or screenshots to be unsuitable for triage.

The core principle: **Bug-bounty evidence is meant to convince a triager. Anything beyond that — live cookies, real-user PII, internal trace IDs that aren't useful — should not be in the evidence.**

---

## 1. Two Categories of Sensitive Data

Every PoC artifact (screenshot, HAR, raw HTTP request, terminal transcript) potentially contains data that needs different treatment.

| Category | Examples | Treatment |
|---|---|---|
| **Your-account secrets** | Session cookies, OAuth tokens, refresh tokens, API keys | Always redact. Even in private bug-bounty platform attachments. Your account, your session — protect it. |
| **Other users' PII** | Real names, emails, phone numbers, addresses, profile photos, account IDs | Redact unless explicitly demonstrating cross-account impact. Even then, mask faces and minimize the data you display. |
| **Triager-useful metadata** | Trace IDs (`x-datadog-trace-id`), request IDs, server timestamps, your test account UID/email, GraphQL operation names, response shapes | **Leave visible** — these help the triager correlate to logs and reproduce. |
| **Test-account passwords (limited use)** | Throwaway passwords on a test account (e.g., `Testing@5678`) | Acceptable in screenshots if you rotate immediately after submission so the value shown is dead. Don't leave real-use passwords in evidence. |

---

### 2.1 What must be masked

The session cookie value is the highest-value secret in any PoC. Mask:

- The session cookie (`authn`, `session`, `sid`, `__Secure-id`, etc. — name varies per target)
- `csrf-token` if it's bound to your session
- `Authorization` headers (Bearer tokens, JWT)
- `Cookie` request header values for any session-bearing cookie
- `Set-Cookie` response header values for any session-bearing cookie

### 2.2 What's safe to leave visible

- Cloudflare cookies (`__cf_bm`, `_cfuvid`) — these are bot-management, not session-bearing
- Analytics cookies (`ajs_anonymous_id`, `_ga`)
- Trace correlation IDs (`x-datadog-trace-id`, `x-request-id`)
- Server / framework headers (`Server: cloudflare`, `X-Frame-Options`)
- Your test account email/UID (per Bugcrowdninja alias section in `bugcrowd-reporting`)

### 2.3 Redaction methods (ranked by practicality)

**Method A — Don't capture the cookies in the first place** (preferred when possible)
- For DevTools Console PoCs: use `credentials: 'include'` so the browser sends cookies automatically. Console output won't echo the cookie. Screenshot the Console output, never the Network tab Headers panel.
- For Burp Repeater PoCs: drag the bottom request/response panel divider DOWN to hide the request body before screenshotting. Capture only the Results table for Intruder runs.

**Method B — Black-bar in image editor** (when capture inevitably includes cookies)
- macOS: Open screenshot in Preview → Tools → Annotate → Rectangle → set fill color to black → drag rectangle over the cookie value → save
- Windows: Use Snip & Sketch's annotation tools or any image editor (Paint.NET, etc.)
- Burp itself: in Burp's Proxy → Match and Replace, you can pre-emptively redact cookie values to placeholder strings before screenshotting

**Method C — Find/replace in raw text** (for HAR files, terminal transcripts)
- See §4 for the jq commands

### 2.4 Pre-screenshot checklist

Before clicking Capture:

```
[ ] Network tab Headers panel is collapsed or out of frame
[ ] Burp's Request panel is hidden behind the divider drag
[ ] No "Copy as cURL" output is visible on screen
[ ] DevTools Application → Storage → Cookies tab is closed
[ ] Browser URL bar doesn't show a session token in query string (rare but possible)
```

After capturing:

```
[ ] Open the screenshot at full resolution before saving
[ ] Search for the session cookie name substring in any visible text — if present, redact
[ ] Search for the literal first 6 chars of your cookie value — if present, redact
[ ] Compare to the previous PoC screenshot in the same engagement — same redaction discipline
```

---

## 3. PII Black-Bar Protocol

When a PoC necessarily exposes another user's data (e.g., demonstrating IDOR by showing the victim's email in an attacker-session response), redact the actual PII even in private attachments.

### 3.1 What to mask (other-user data)

- First name, last name (full or partial)
- Email address (mask the local part; can leave domain if non-identifying)
- Phone number (mask the last 7 digits, optionally leave country code)
- Physical address (mask everything below city)
- Date of birth (mask the year, optionally the month)
- Government IDs (SSN, passport — mask everything)
- Profile photos / face images (black-bar the face entirely)
- Account IDs that the user could correlate to public profiles

### 3.2 What to leave visible (proves the bug, not the user)

- The fact that the field was returned (the JSON key name)
- The shape / type of the field (`"first_name": "<REDACTED>"`)
- Your own (attacker session's) UID / email — this proves cross-account
- The endpoint URL and request method
- The trace ID

### 3.3 Worked example — IDOR PoC body

**Bad (leaks victim's full PII):**
```json
{"data":{"contact":{"first_name":"Nadene","last_name":"Afton","email":"nadene.afton@example.com","phone":"+1-555-867-5309"}}}
```

**Good (proves the bug, masks the PII):**
```json
{"data":{"contact":{"first_name":"<REDACTED — real first name>","last_name":"<REDACTED — real last name>","email":"<REDACTED>@example.com","phone":"<REDACTED>"}}}
```

In screenshot form, black-bar each value with a rectangle annotation labeled "REAL PII REDACTED" if there's space.

## Proof of Concept

The screenshot below demonstrates the IDOR. The attacker session (uid 12345678) successfully retrieves the victim's profile data (uid 99887766). **Real PII fields in the response are masked with black rectangles to limit unauthorized exposure of victim data, per responsible-disclosure hygiene.** The unredacted response is available privately on request.
```

This signals the triager that you're disciplined and gives them a clear path to the unredacted version if they need it for verification.

---

## 4. HAR File Sanitization

HAR (HTTP Archive) files are JSON dumps of network traffic with full request/response bodies and headers. They include cookies, auth tokens, and any PII that was in transit.

### 4.1 Generate the HAR

Chrome DevTools → Network tab → right-click anywhere in the request list → "Save all as HAR with content"

### 4.2 Sanitize before attaching

Use `jq` to strip sensitive headers. Save this as a shell function or one-liner you can re-use:

```bash
sanitize_har() {
  local input="$1"
  local output="${1%.har}.sanitized.har"

  jq '
    .log.entries |= map(
      (.request.headers |= map(
        if .name | ascii_downcase | IN("cookie", "authorization", "x-csrf-token") then .value = "<REDACTED>" else . end
      )) |
      (.response.headers |= map(
        if .name | ascii_downcase | IN("set-cookie") then .value = "<REDACTED>" else . end
      )) |
      (.request.cookies |= map(.value = "<REDACTED>")) |
      (.response.cookies |= map(.value = "<REDACTED>"))
    )
  ' "$input" > "$output"

  echo "Sanitized: $output"
}
```

Usage:

```bash
sanitize_har /path/to/exported.har

# Check that no Cookie or Authorization values are leaking
grep -i 'authn\|"cookie"\|authorization' /path/to/exported.sanitized.har | head -20
```

If you see your real cookie value in the output, the sanitization missed something — fix the jq filter for that specific field name.

### 4.4 Remove other-user PII (if applicable)

If the HAR captured cross-account data (e.g., during an IDOR demo), additionally strip the response body fields that contain victim PII. Add to the jq filter:

```jq
(.response.content.text |= (
  if . then 
    (fromjson? // .) | tostring | gsub("real.first.name.example"; "<REDACTED>")
  else . end
))
```

Customize the gsub patterns to your specific captured data.

---

### 5.1 Repeater (single request demo)

1. In the Repeater request panel, the Cookie header is on its own line — drag the panel divider DOWN to hide everything below the request line / target line
2. Or: temporarily delete the Cookie header text from the Repeater pane (it doesn't affect the original captured request) before screenshotting, then restore
3. Capture only the response panel (right side) showing the JSON / HTML response that demonstrates the bug

### 5.2 Intruder Results table (rate-limit / brute-force demos)

The Results window is the strongest evidence for rate-limit findings. To capture cleanly:

1. After the attack finishes, drag the horizontal divider between the Results table and the Request/Response panels DOWN, until only the Results table is visible
2. Screenshot only the columns: `Request#`, `Payload`, `Status code`, `Response received`, `Length`
3. Don't include the Request / Response sub-panels — they contain the cookie

### 5.3 Proxy HTTP history (capture demo)

Almost never the right screenshot — it shows entire request/response pairs with cookies. Use Repeater for demos instead.

### 5.4 Scanner findings (if applicable)

The Scanner tab's Issues panel is generally safe to screenshot — it shows finding summaries without the underlying request bodies. Click into a specific finding before screenshotting only if you've redacted its evidence first.

---

### 6.1 The clean-PoC pattern

```js
fetch('/api/endpoint', {
  method: 'POST',
  headers: {'content-type': 'application/json'},
  credentials: 'include',  // sends cookies automatically — they won't appear in your code
  body: JSON.stringify({ /* your payload */ })
}).then(r => r.json()).then(j => console.log("LABEL:", JSON.stringify(j)))
```

Why this is clean:
- `credentials: 'include'` means the browser sends cookies. Your code never references them. They never appear in screenshots.
- `console.log("LABEL:", ...)` produces a labeled output line you can search for in the screenshot
- `JSON.stringify(j)` formats the response on a single line — easier to crop tightly

### 6.2 Multi-step PoCs (clear console between calls)

For a 4-step PoC (verify before / change / verify after / revert), clear the console between calls so each screenshot only shows ONE call and ONE response:

- Mac: `Cmd+K`
- Windows / Linux: `Ctrl+L`

Take the screenshot immediately after the response prints — don't wait for unrelated framework warnings to appear.

### 6.3 Long responses (truncate for screenshot)

If the response body is too long for a clean screenshot, log a summary instead:

```js
fetch('/api/endpoint', { /* ... */ })
  .then(r => r.json())
  .then(j => {
    console.log("RESPONSE SHAPE:", Object.keys(j.data || {}));
    console.log("CRITICAL FIELD:", j.data?.victim_id, j.data?.email);
    // (Don't dump the full j — your screenshot becomes unreadable)
  })
```

### 6.4 Allow-pasting reminder

Chrome blocks paste into DevTools Console as anti-self-XSS protection. Type `allow pasting` (literal phrase) once at the start of each session. Do this BEFORE you take any "running PoC" screenshot — otherwise the warning text appears in the screenshot.

---

### 7.1 The 5-step PoC pattern (for state-change findings)

For findings like "password change without step-up," the canonical 5-screenshot pattern is:

1. **Pre-state verification** — `verify_password("current") → true`. Proves you knew the starting state.
2. **The bug itself** — `update_password(...)` succeeds without step-up. THE most important screenshot.
3. **Post-state verification (negative)** — `verify_password("old") → false`. Proves the change took effect.
4. **Post-state verification (positive)** — `verify_password("new") → true`. Proves the new credential is active.
5. **Out-of-band side effects** — inbox screenshot showing whether a notification email arrived. Proves whether passive defense exists.

### 7.2 Filename conventions

Numbered, descriptive, hyphen-separated:

```
{finding-#}-step{step-#}-{description}.png

Examples:
04-step1-verify-true-before.png
04-step2-update-password-no-stepup.png
04-step3-verify-false-after.png
04-step4-verify-true-new-pw.png
04-step5-inbox-notification-check.png
```

In the report body, reference each by filename:

```markdown
- **Screenshot 1 (`04-step1-verify-true-before.png`)** — verify_password returns true with the current password.
- **Screenshot 2 (`04-step2-update-password-no-stepup.png`)** — update_password returns User with no StepUpRequiredError. THIS IS THE BUG.
- **Screenshot 3 (`04-step3-verify-false-after.png`)** — verify_password with old password returns false.
- **Screenshot 4 (`04-step4-verify-true-new-pw.png`)** — verify_password with new password returns true.
- **Screenshot 5 (`04-step5-inbox-notification-check.png`)** — inbox showing whether out-of-band notification was sent.
```

### 7.3 Capture timing

- Take all screenshots in one sitting, not across multiple sessions. Mid-session inconsistencies (different browser sizes, different cookie values) are confusing for the triager.
- Don't reload pages between screenshots if avoidable. Reloads regenerate cookies and may invalidate prior captures.

---

## 8. Post-Submission Hygiene

After clicking Submit on the bug-bounty platform:

### 8.1 Rotate the test account credentials

```
1. Log out of the target
2. Log back in (this rotates the session cookie — any cookie shown in your screenshots is now dead)
3. Change the password to a fresh value not used elsewhere (any password shown in your screenshots is now dead)
```

### 8.2 Save the unredacted artifacts privately

Keep your unredacted HARs / screenshots in a local folder accessible only to you. The triager may ask for the unredacted version during verification. **Never share unredacted artifacts via email — use the platform's private attachment system on the existing submission thread.**

### 8.3 Don't post about the finding publicly

Most platforms' confidentiality applies to BOTH unresolved and resolved issues. Don't tweet, blog, or discuss the finding in any forum until the program explicitly says you can.

### 8.4 Audit your local artifacts

Quarterly, sweep your `~/security-research/` and `~/Downloads/` for stale HARs / screenshots from old engagements. Either move them to a properly-encrypted archive or delete them. Bug-bounty engagement artifacts are sensitive — they accumulate fast and become a liability.

---

## 9. Pairing with Other Skills

| For this question / task | Use this skill |
|---|---|
| "Should I report this finding at all?" | `triage-validation` |
| "What's the report body template?" | `report-writing` |
| "What VRT / severity / OOS rebuttal for Bugcrowd?" | `bugcrowd-reporting` |
| "How do I redact / sanitize this evidence?" | This skill (`evidence-hygiene`) |
| "How do I demonstrate the bug actually fires?" | `security-arsenal` |
| "Where are the recon probes for this asset class?" | `offensive-osint` |

---

## Notes on usage

This skill is meant to be loaded together with `report-writing` and (for Bugcrowd) `bugcrowd-reporting` when preparing a submission. It does NOT cover:

- **What** to capture (that's `triage-validation` and `report-writing`'s job — they tell you what evidence is required for the report to be accepted)
- **How** to demonstrate exploitation (that's `security-arsenal`'s job — payloads to send)
- **Where** to find the assets (that's `offensive-osint`'s job — recon)

This skill covers ONLY the redaction / sanitization / hygiene layer that sits between "I have evidence" and "I'm attaching it to the platform."

---

## Related Skills & Chains

- **`report-writing`** — When evidence is redacted and ready for the report body. Workflow primitive: after redaction passes the pre-screenshot checklist, hand off to `report-writing` for the platform-specific report template (H1 / Bugcrowd / Intigriti / Immunefi).
- **`bugcrowd-reporting`** — When the redacted evidence is destined for Bugcrowd specifically. Workflow primitive: redacted screenshots + sanitized HARs become attachments referenced in `bugcrowd-reporting`'s VRT-mapped submission body.
- **`triage-validation`** — When deciding which evidence is required at all. Workflow primitive: `triage-validation` says "you need a 5-screenshot PoC for password-change-without-step-up"; this skill says "here's how to capture and redact those 5 screenshots cleanly."
- **`security-arsenal`** — When the payload that produced the evidence is being documented. Workflow primitive: the payload (from `security-arsenal`) goes in the report verbatim; its output / response (handled by this skill) gets cookie / PII redacted before screenshotting.
- **`bb-methodology`** — When Phase 5 (Validate & Report) needs evidence captured. Workflow primitive: Phase 5's evidence-capture step routes through this skill before the report is drafted.


## SOURCE: hunt-skills/report-writing/SKILL.md

# REPORT WRITING

Impact-first. Human tone. No theoretical language. Triagers are people.

---

## Related Skills & Chains

- **`triage-validation`** — When deciding whether to write a report at all. Workflow primitive: NEVER open this skill before `triage-validation`'s 7-Question Gate passes; a finding that fails the gate should be killed, not written up.
- **`bugcrowd-reporting`** — When the target is a Bugcrowd program. Workflow primitive: this skill's body template is the foundation; `bugcrowd-reporting` overlays VRT selection, severity-request paragraph, OOS-clause rebuttals on top.
- **`evidence-hygiene`** — When PoC screenshots / HARs are being attached to the report. Workflow primitive: every artifact referenced in the "Supporting Materials" / "Proof of Concept" section gets routed through `evidence-hygiene` for cookie + PII redaction before attachment.
- **`redteam-report-template`** — When the engagement is an external red team (NOT bug bounty). Workflow primitive: confirm engagement mode via `bb-methodology` PART 0; if red-team, swap this skill out for `redteam-report-template` (different audience, different structure: Subject / Observations / Description / Impact / Recommendation / PoC).

---

### Title formula in practice

`<asset> | <bug class> | <impact>` — three components, no fluff. Triagers read titles in roughly three seconds and use them to order the queue.

- BAD: "Interesting finding on /api/users"
- BAD: "IDOR vulnerability in API"
- GOOD: "Authenticated IDOR on /api/users/{uid} -> admin email + role disclosure"
- GOOD: "Unauthenticated SSRF on /preview?url= -> AWS metadata 169.254.169.254 reachable"

The bad titles get opened last. The good titles get opened first. Same finding, different queue position, different triage day, different payout speed.

### What triagers actually read

Their reading sequence on a fresh report:

1. **Title** (3 seconds)
2. **First paragraph of impact / summary** (15 seconds)
3. **The curl command or HTTP request block** (30 seconds)
4. **Reproduction steps** (only if the first three were convincing)
5. **Everything else** (only on follow-up review)

Optimize the top of the report ruthlessly. Save narrative for the middle. Triagers who are convinced by step 3 will rubber-stamp the rest; triagers who aren't convinced by step 3 won't read step 5.

### CVSS 3.1 vs Bugcrowd VRT vs H1 default severity

These three systems disagree about 30% of the time. The most common gap: a finding that scores CVSS 7.x (High) maps to Bugcrowd P4 (Low) or H1 Medium-default. When the platform default rates lower than CVSS:

1. **File the severity-request paragraph as the first body section.** Bugcrowd respects this. (See `bugcrowd-reporting` for the canonical template.)
2. **Anchor the request in CVSS vector string + business impact, not feelings.** "CVSS 3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5 High because Confidentiality:High applies to cross-tenant data exposure."
3. **Cite the platform's own VRT entry** that matches your finding. Don't argue against the platform; route within it.

An authorized bug-bounty engagement saw P4-default findings escalated to P3 via the severity-request paragraph. The escalation isn't automatic — you have to ask, with grounded reasoning, in the first body section.

### Evidence rotation

Everything in the submission body is logged forever by the platform. Operate accordingly:

- Use throwaway test accounts created specifically for the engagement.
- Rotate cookies / tokens after each submission (don't reuse the cookie that's pasted in the report).
- Never paste production cookies, real user emails, or real PII into the report body — redact in the PoC step.
- Screenshots of admin panels: blur the user list, blur the URL bar if it contains tokens.

Cross-link `evidence-hygiene` for the full capture-and-redact protocol.

### Templates by platform — when they differ

| Platform | Tone | Required Structure | Severity Mechanism |
|---|---|---|---|
| HackerOne | Narrative | Summary -> Steps -> Impact -> Suggested fix | Triager-set, contestable |
| Bugcrowd | Structured | Severity request -> VRT category -> Title -> Body -> Remediation | VRT-default + manual override paragraph |
| Intigriti | Between | Summary -> PoC -> Impact -> Recommendation | Researcher-proposed, triager-confirmed |
| Immunefi | PoC-first | Working PoC code -> Walkthrough -> Impact -> Severity | Foundry/Hardhat code is the primary deliverable |

Picking the wrong template style costs validity. A narrative-heavy Bugcrowd report misses the VRT mapping the triager needs; a structured H1 report reads as terse and gets follow-up questions that delay payout.

### The single biggest report-writing mistake

Claiming an attack works "in theory" or "could be chained to [bigger impact]" without demonstrating it. Triage-validation Q6 (impact beyond technically possible) kills these on the validation side; report-writing has to mirror it on the writing side.

Two valid paths:

1. **Show concrete impact end-to-end.** Capture the chain on a test account. Paste the full request/response sequence. Done.
2. **Downgrade the severity claim to match what you actually demonstrated.** "IDOR on /api/users/{uid} reading email + role" is real and reportable; "IDOR chained to potential admin takeover" is not until you demonstrate the takeover.

Pick one. Never split the difference with "could potentially" or "may allow" — those phrases are the triager's signal that the report is theoretical, and theoretical reports get N/A.
- **`bb-methodology`** — When Phase 5's report-writing step starts. Workflow primitive: Phase 5 calls `/report` which loads this skill for the platform-specific template (H1 / Bugcrowd / Intigriti / Immunefi).


## SOURCE: hunt-skills/triage-validation/SKILL.md

# TRIAGE & VALIDATION

One wrong answer = STOP **this finding**. Kill **the finding**. Move on **to the next test class**.

> **Scope of "STOP" in this skill:** This skill's gates kill INDIVIDUAL FINDINGS that fail validation. They do NOT authorize stopping the engagement. Killing a finding via the 7-Question Gate just means *that finding* doesn't get submitted — every other test class in the engagement is still pending. See `redteam-mindset` "DO NOT STOP primary directive" for the coverage-axis rule.

> "N/A hurts your validity ratio. Informative is neutral. Only submit what passes all 7 questions."

---

## THE LAYER-ORDERING TRAP — read before claiming any auth bypass

**A validation error does NOT prove you passed authentication.**

This is the highest-confidence false positive in the auth-bypass class, because the
evidence looks concrete. The reasoning that fails:

> "I sent an unauthenticated request and got back `400 — field X is required`.
> A validation error means the request cleared auth and reached business logic.
> Therefore auth is missing."

That inference is only valid if auth runs *before* input handling. Many stacks put a
**global input sanitiser, body parser, or schema filter in front of the auth
middleware.** A malformed body is then rejected before auth is ever consulted, and
the response is indistinguishable from "auth passed, validation failed."

**The test: re-send with a minimal WELL-FORMED body.**

```bash

# malformed body — trips the sanitiser, which runs FIRST
curl -s -X POST https://target/api/v1/resource -d '{'

# same endpoint, well-formed empty object — now auth is reached
curl -s -X POST https://target/api/v1/resource -H 'Content-Type: application/json' -d '{}'

# 401 {"code":"ERR-AUTH-0001","message":"Not authenticated. Please log in."}
```

**Only the second response tells you where the auth layer sits.**

**Lesson from an authorized engagement.** On a production API, a malformed body
returned a validation-shaped `400` on the large majority of endpoints tested. Read
as an auth bypass, that is a Critical filed against production infrastructure
covering financial and administrative operations. It was a sanitiser reacting to
the `{` character before auth ran — every one of those endpoints returned `401` to
a well-formed `{}`. The false Critical was avoided only because someone re-tested.

**Rules:**
- Layer ordering is not observable from a single response. Never infer it.
- Probe auth with the *simplest valid* body the parser will accept, not a malformed one.
- If the error text is about **input shape or character class**, you are talking to a
  parser or sanitiser, not to business logic.
- If the error text names a **domain field** (`accountId is required`) AND a
  well-formed body still returns it, that is a real signal — proceed to Q6.
- Applies equally to WAF and CDN layers: an edge block is not an origin response.

---

### Common Score Examples

| Finding | Score | Severity | Vector |
|---|---|---|---|
| IDOR read PII, any user, auth required | 6.5 | Medium | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |
| IDOR write/delete, any user | 7.5 | High | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| Auth bypass → admin panel | 9.8 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Stored XSS → cookie theft, stored | 8.5 | High | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N |
| SQLi → full DB dump | 9.1 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| SSRF → cloud metadata | 9.1 | Critical | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N |
| Race → double spend | 7.5 | High | AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N |
| GraphQL auth bypass | 8.1 | High | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| JWT none algorithm | 9.1 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |

> **UI for stored XSS is a judgment call.** Stored XSS that fires on page view is a long-standing CVSS gray area — NVD/FIRST frequently score it UI:R (which drops the stored-XSS row above to ~7.6). The UI:N above models "no extra action beyond normal page use"; if your triager expects UI:R, defend the choice or re-score before copying the number into a report.

## PRE-SEVERITY GATE

Before labelling any finding **Critical** or **High** anywhere in your notes or report — write out the answer to each of these as a one-liner. If you can't answer concretely, **the severity is wrong**.

1. **Have I validated the FULL chain to attacker-attainable impact, or only one primitive in the middle?**
   — "Primitive confirmed at layer N" ≠ exploitable. Multi-stage chains require ALL stages validated before the severity matches the chain's top end.
2. **What does the attacker walk away with, in one concrete sentence?**
   — "RCE on the SP front-end web server" is concrete. "Could lead to RCE" is not — that's High at best, often Medium.
3. **Have I personally reproduced the full chain end-to-end at least twice?**
   — Twice = once during discovery, once for the report screenshot/PoC. Not "I'm sure it would work."
4. **Is there an inheritance gate, signature check, audience check, or other validation step still gating the chain?**
   — If yes, the chain is not Critical. Document it as "primitive present" at lower severity until the gate is bypassed.
5. **Has the program rejected this severity class before?**
   — Many programs cap "info disclosure with no concrete impact" at Low/Info regardless of the data type. Read the program scope.

**Lesson from an authorized engagement:** JWT `alg:none` was initially labelled **Critical** based on the signature-bypass primitive being confirmed at the audience-validation layer. Subsequent testing showed the issuer-trust check still rejected unsigned tokens — the full ATO chain did not complete. Finding had to be retracted. If the Pre-Severity Gate had been run on the original draft, Q1 would have killed the Critical label before submission.

---

## RETRACTION DISCIPLINE

When a previously-claimed finding fails reproduction — **never silently drop it.** Document the retraction in the report's appendix. This proves to the triager that you validate your own work, and it saves them from chasing a phantom you've already disproved.

**Retraction entry template:**

```markdown

### Retracted: <finding name>

- **Original signal:** <one-line description of what looked like a bug>
- **Disproving evidence:** <concrete reproduction-step + observation that disproves it>
- **Why it looked like a bug:** <root cause of the false positive — e.g., natural marker collision, network jitter, status-code-only confidence>
- **Retraction date:** <YYYY-MM-DD>
```

**Concrete retractions from an authorized engagement — pattern reference:**

- **X-Forwarded-Proto reflection** — looked like header reflection across 4 pages; was the literal word `javascript` in SP help-link hrefs. Cause: non-unique marker.
- **Host header `:80@evil` bypass** — 200 OK on a path that normally 403s; body byte-identical to baseline (8341 bytes). Cause: status-code-only confidence; ELB Host normalisation dropped the `@evil` portion.
- **`download.aspx` file-existence oracle** — looked like a file-existence differentiator across path types; was SP's file-extension blocklist (`.ashx`/`.asmx`/`.svc`/`.config` always blocked regardless of existence). Cause: confusing server-side policy with file state.
- **`Administrator` timing leak** — single-shot 1527 ms vs ~700 ms control on Authentication.asmx Login; n=80 interleaved reproduction collapsed every group to 685-716 ms. Cause: single-sample statistical claim.

**Why this matters:** retracted findings put in an appendix demonstrate methodological honesty. Silently dropping them looks like you cherry-picked. A clean 11-finding report with a retraction appendix is more trustworthy than a 13-finding report where 2 fall apart at triage.

---

## Related Skills & Chains

- **`report-writing`** — When all 7 questions pass and the Pre-Severity Gate is clean. Workflow primitive: this skill is the gate that runs BEFORE `report-writing`; only findings that clear all 7Q + 4 pre-submission gates get the report-template handoff.
- **`bugcrowd-reporting`** — When a Bugcrowd VRT mapping is needed for an accepted finding. Workflow primitive: after this skill validates the finding, `bugcrowd-reporting` decides the VRT category and severity-request paragraph.
- **`evidence-hygiene`** — When the validated finding needs PoC evidence captured. Workflow primitive: this skill says "Q6 requires proof of impact"; `evidence-hygiene` provides the capture-and-redact protocol for that proof.
- **`security-arsenal`** — When checking the always-rejected / conditionally-valid tables. Workflow primitive: this skill's "Never Submit List" and `security-arsenal`'s "Always Rejected" table are aligned; either entry-point lookup decides whether a primitive is reportable alone or only with a chain.
- **`bb-methodology`** — When Phase 5 (Validate & Report) starts. Workflow primitive: Phase 5's pre-report gate explicitly invokes `/validate` (this skill's 7Q gate) before any report is drafted.

---

### 7-Question Gate at scale

The 7Q gate is the single highest-ROI artifact in this skill. Phase 2D's hardened-lab campaign verified it kills four distinct false-positive shapes:

1. **URL echo dressed as reflection** — payload appears in the response body because the response IS the URL. Q1 (is this a real HTTP request that does something on the server) kills it.
2. **Word collision dressed as marker hit** — the canary string `XSS-test` matched a CSS class name, not your injection. Marker Discipline + Q1 kill it.
3. **Server policy mistaken for state oracle** — `download.aspx?file=foo.config` always returns "blocked" regardless of whether the file exists. Q6 (impact beyond technically possible) kills it: there's no oracle, just a deny-list.
4. **200 OK without leak** — status code differs from baseline 403; body is byte-identical. Body-Diff Rule + Q6 kill it.

Without the 7Q gate, expect 10-20% submission validity loss across an engagement. With it, retraction rates trend to single digits.

### Pre-Severity Gate before reporting Critical

A authorized SharePoint engagement nearly submitted a Critical when the chain didn't actually complete end-to-end — a primitive that read auth state was conflated with a primitive that mutated it. The Pre-Severity Gate (run all 7 questions specifically against the **Critical claim**, not the generic "is this a bug" claim) would have caught it.

Process: write your draft Critical title. Take each of the 7 questions and answer them with the Critical claim substituted for "the bug." If Q6 (impact beyond technically possible) returns "I have a primitive that should let me do X, but I haven't demonstrated X end-to-end on a test account," downgrade. Critical means impact-demonstrated, not impact-inferable.

### Retraction discipline

If a finding stops reproducing 24h after submission — retract preemptively. Two reasons:

1. **Triagers retract for you with downgraded scoring.** A self-retraction reads "the researcher validates their own work." A triager-retraction reads "the researcher submitted noise."
2. **Validation rate is platform-tracked.** Self-retractions don't hit the same metric as triager-closed-as-N/A. Your reputation signal stays cleaner.

The retraction template in the RETRACTION DISCIPLINE section above is the canonical format. Don't silently delete — append a retraction appendix to the engagement report instead.

### When the 7Q feels obstructive

The friction is the gate working. The half of findings that get killed by the 7Q are the half that would have come back as Informative or N/A. Take the friction. Your average payout per submission goes up when low-confidence findings stop diluting the funnel.

The exception: if the 7Q kills a finding but you still believe it, the answer is **gather more evidence**, not **bypass the gate**. The gate is a "do you have proof" check. Get proof, then re-run the gate.

### Validation discipline rules cross-link

The 7 questions are the umbrella; the discipline rules from `bb-methodology` are the implementation:

| 7Q Question | Discipline Rule (bb-methodology) |
|---|---|
| Q1 (real HTTP request that does something) | Reproducibility Gate |
| Q2 (impact beyond informational) | Pre-Severity Gate |
| Q3 (server-side state change or data leak) | Server-Policy-vs-State |
| Q4 (cross-tenant / cross-user demonstrated) | OOB Gate (for blind class), Marker Discipline (for reflective class) |
| Q5 (not already known / dup) | disclosed-reports/ index + HackerOne hacktivity check |
| Q6 (impact beyond technically possible) | OOB Gate + Body-Diff Rule + Statistical-Sample Rule |
| Q7 (in scope per program rules) | scope.md lookup (engagement scaffold) |

When a question is hard to answer "yes" to, the cross-linked rule tells you which artifact to produce to make the answer yes. Q6 is the one most engagements stumble on; that's why three discipline rules back it.
