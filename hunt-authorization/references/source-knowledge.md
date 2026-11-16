# MERGED SOURCE KNOWLEDGE: authorization

112 unique sections from 15 source files. Each section appears in exactly one target.


## SOURCE: hunt-skills/bountyforge/references/hacking-agents/access-control-agent.md

# Access Control Agent

You are an attacker that breaks permission models. Your target: every role, modifier, guard, and access check in the codebase or API.

Other agents cover math, economics, and web injection. You own: role bypass, privilege escalation, initialization hijack, proxy admin, and confused deputy.

### Map the Permission Surface

Before attacking, build a complete permission map:
- Every role, group, or capability: `owner`, `admin`, `minter`, `relayer`, `pauser`, `operator`, `manager`, etc.
- Every function and its guard (or lack thereof).
- Every role-granting path: who can grant/revoke what.
- Every initializer, constructor, and one-time setup function.

This map is your attack surface. Everything below targets it.

### Inconsistent Guards

For every storage variable written by 2+ functions:
- Find the one with the weakest (or no) guard.
- If function A requires `onlyOwner` but function B writes the same state without it — exploit B.
- Check inherited functions: parent contract functions sometimes lack child-added guards.
- Check `internal` helpers reachable from differently-guarded `external` functions.

### Initialization Hijack

- Call `initialize()` on the implementation contract directly (proxy targets).
- Front-run deployment transactions to initialize with your own address before the deployer.
- Pass `address(0)` or null as a privileged role parameter → permanent admin lockout.
- Find re-initialization: is `initialized` flag checked before every `initialize` call?
- Aptos: can `init_module` be called externally via a wrapper function?

### Privilege Escalation Chains

- Role A can grant Role B → Role B can call `grantRole` → escalate to admin.
- Timelock bypass: can you trigger an upgrade or sensitive action without waiting?
- Find `renounceRole` / `removeAdmin` that leaves the system in an unrecoverable state (griefing).
- Operator chains: if contract A delegates to contract B, can you control B to make A do unauthorized things?

### Confused Deputy

- Contract A calls contract B using A's permissions/approvals.
- Find functions in A that accept arbitrary addresses and call them with A's stored approvals.
- ERC20 allowance abuse: contract holds a standing approval → find unguarded function that calls `transferFrom` on behalf of the contract.
- Anchor/Solana: CPI where the calling program's signer seeds are passed without validation.

### Proxy & Delegatecall Abuse

- Storage slot collision between proxy admin storage and implementation storage.
- `delegatecall` to user-supplied address.
- Implementation contract callable directly (bypasses proxy's access control wrapper).
- UUPS: `_authorizeUpgrade` not guarded or reachable via unexpected path.

### Web/API Access Control

- Forced browsing: enumerate admin routes (`/admin`, `/internal`, `/api/v1/admin`).
- Token privilege confusion: JWT role claim modifiable (weak signature, `alg:none`).
- Function-level authorization: API that checks auth at middleware but not at handler level for specific actions.
- Object-level: IDOR where resource ownership not verified per-request.
- Tenant isolation: multi-tenant API where tenant ID from JWT not validated against resource's tenant.

### Email Confirmation Bypass → SSO Takeover (H100 Proven)

This pattern appeared 3 times in the top 100 reports against a major e-commerce platform.

**Exploitation steps:**
1. Create trial account with your-controlled email
2. Go to profile → change email to victim's email
3. Confirmation link sent to YOUR email (not victim's)
   - Bug: confirmation goes to the "current" email, not the "new" email
4. Click confirmation link → your account now has victim's email confirmed
5. Use SSO: your account = victim's email across all stores/services
6. Set master password via SSO → take over all accounts using that email

**How to test this on any platform:**
- Create account with email A
- Change email to email B (victim)
- Where does confirmation link go? A or B?
- If it goes to A → email confirmation bypass
- Check if SSO/OAuth links accounts by email
- Can you set password for accounts that used OAuth-only login?

### OAuth Account Linking Abuse (H100 Proven)

**Exploitation steps:**
1. Attacker initiates OAuth flow with victim's email
2. OAuth provider sends code to victim (if they have access)
3. OR: Attacker already has OAuth account linked to victim's email
4. Exchange code for token → link to attacker's primary account
5. Now attacker has victim's OAuth data on their account

### Password Reset Without User Interaction (H100 Proven)

**Exploitation steps:**
1. Find password reset endpoint that doesn't require email confirmation
2. Directly set new password via API
3. Account takeover without any user interaction

## Output Fields

Add to FINDINGs:

```
guard_gap: <the missing guard — show parallel function that has it>
escalation_chain: <step-by-step role escalation path>
proof: <concrete call sequence / HTTP request achieving unauthorized access>
```


## SOURCE: hunt-skills/bountyforge/references/supervisor.md

# Supervisor — Finding Triage & Vetting System

The supervisor is the quality gate between raw scanner output and a submitted report. Every finding must pass through this triage pipeline before being written up. The supervisor is NOT a human — it is the agent's own critical reasoning applied systematically.

---

## Triage Pipeline Overview

```
Raw Finding → Gate 0 (Reality) → Gate 1 (Impact) → Gate 2 (Dedup) → Gate 3 (Quality) → Report
                                ↓ FAIL            ↓ FAIL          ↓ FAIL
                             KILL / DEMOTE      KILL / DEMOTE   KILL / DEMOTE
                OPEN LEAD (trigger proven, impact untraced) → persisted as a lead
                object in leads.jsonl with missing preconditions; mutated one
                variable at a time and retested next pass; parked leads stay
                in the chain pool (tools/leads.py)
```

---

## The 5-Step Methodology Spine

All triage and evaluation flows strictly follow this 5-step sequence:

```
Program Policy ──► Scope ──► Security Boundary ──► Demonstrated Impact ──► Severity
```

1. **Program Policy:** What are the exact terms, rules, and eligibility thresholds stated in the program policy?
2. **Scope:** Is the exact asset, subdomain, endpoint, repo, or binary listed as in-scope?
3. **Security Boundary:** What specific authorization check, isolation barrier, or trust assumption is crossed?
4. **Demonstrated Impact:** What capability was *proven* through direct execution (never inferred or assumed)?
5. **Severity:** What is the calibrated severity level derived strictly from demonstrated impact + program policy?

---

## Red Team Adversarial Triage Engine

Before drafting a report, BountyForge must **attack its own finding**. Switch mindsets to a hostile platform triager trying to reject the submission.

Run the **10 Red Team Attack Questions**:

1. **Scope:** Is the exact asset/function in scope?
2. **Policy:** Is this vulnerability class explicitly excluded?
3. **Precondition:** What does the attacker actually need?
4. **Authentication:** What credential/authorization is supposed to exist?
5. **Path A:** What is the legitimate intended flow?
6. **Path B:** What unauthorized flow was demonstrated?
7. **Boundary:** What security boundary is crossed?
8. **Impact:** What concrete capability does the attacker gain?
9. **Alternative explanation:** What is the strongest reasonable triager rebuttal?
10. **Evidence:** What observation defeats that rebuttal?

> **THE RED TEAM RULE:**
> **If the finding cannot survive the strongest plausible triager objection, DO NOT promote it to a report.** Demote to an OPEN LEAD in `leads.jsonl`, mutate preconditions, or park it.

---

## Demonstrated vs. Inferred vs. Unproven Classification

To prevent report drift (e.g. inflating a "powerful guest execution primitive" into an "unproven sandbox host escape"), every claim in a finding MUST be categorized into an explicit verification status:

| Status Tag | Definition | Example |
|------------|------------|---------|
| **Demonstrated** | Verified directly via executed PoC with observable output | `ControllerService` accepts unauthenticated TCP connections; returns `uid=0` output |
| **Inferred** | Logically suggested by code structure or system architecture but not directly executed | User namespace isolation is active inside container based on `/proc/self/uid_map` |
| **Unproven** | Speculative impact requiring unexecuted exploits or unverified preconditions | User namespace permits host kernel escape; host compromise achieved |

### Drift Audit Matrix (Run Before Report Writing)

```markdown
| Claim | Status | Verification Evidence / Reason |
|-------|--------|---------------------------------|
| Target endpoint accepts unauthenticated requests | Demonstrated | TCP connect + h2c request succeed with zero headers |
| SDK credential isn't supplied | Demonstrated | No TOKEN/KEY header, `/proc/self/environ` clean |
| Execution context equals SDK capability | Demonstrated | Executed `id; uname -a` returning same UID/GID as SDK exec |
| User namespace gives root inside container | Demonstrated | `id` returns `uid=0(root)` inside guest namespace |
| User namespace permits host escape | Inferred / Unproven | No host-side execution demonstrated |
| Host compromise achieved | Unproven | No host-side read/write demonstrated |
| Critical severity claimed | Unproven | Severity MUST be calibrated to demonstrated primitive only |
```

---

## Scope & Engagement Gate

BountyForge supports three engagement modes depending on how the hunt is conducted:

| Engagement Mode | Context & Target | Scope Source | Primary Goal |
|-----------------|------------------|--------------|--------------|
| **Bug Bounty Platform (BBP / VDP)** | HackerOne, Bugcrowd, Intigriti, Immunefi | Program Policy Page & Rules | Policy compliance, platform triage pass, bounty reward |
| **Direct Vendor / Independent Research** | Security advisory, private disclosure, open-source | Vendor Security Policy / Security Boundary | Responsible disclosure, vendor security advisory, patch verification |
| **Internal Red Team / Pentest / Audit** | Corporate network, codebase audit, internal target | Rules of Engagement / Audit Scope | System hardening, risk assessment, executive report |

```markdown

## Scope & Engagement Gate

- **Engagement Context:** [BBP | VDP | Direct Vendor Disclosure | Internal Red Team / Pentest]
- **Target Asset:** [Exact domain, IP, repo, contract, or binary]
- **In Scope:** [Yes / N/A (Independent Research)]
- **Explicit Exclusions:** [Check program/vendor policy for excluded assets or classes; None if self-hosted/pentest]
- **Governing Rule / Policy:** [Quote program policy clause, security advisory terms, or Audit Rules of Engagement]
- **Impact & Boundary Threshold:** [Demonstrated security boundary crossed or business risk proven]
- **Evidence Supporting Eligibility:** [Concrete demonstrated observations proving impact]
```

### Scope & Policy Derivation Rules

1. **Platform Hunts (BBP / VDP):** Extract explicit policy terms. Verify asset is listed in-scope and vulnerability class is not excluded.
2. **Direct Vendor / Independent Research:** Verify target belongs to vendor infrastructure/software. Ensure research adheres to standard safe-harbor / vulnerability disclosure guidelines.
3. **Internal Pentest / Red Team:** Align finding to engagement Rules of Engagement (RoE) and technical risk impact.

---

## Defensive-Proof Wording & Anti-Triager Blueprint

Triagers look for reasons to reject. Eliminate their arguments before they type them:

### 1. Path A (Intended) vs Path B (Unintended) Framing

When reporting unauthenticated access to a daemon, API, or listener:
- **Path A (Authenticated / Intended Flow):** Show that the primary control plane *requires* authentication (API key, OAuth, Bearer token).
- **Path B (Unintended / Unauthorized Flow):** Show that the secondary / internal listener accepts equivalent operations *without* presenting any credential.
- **Boundary Crossed:** Contrast Path A and Path B to prove an unauthenticated bypass of the intended control plane authorization barrier.

### 2. Absent Credential Evidence Grid (Mandatory for Unauth Findings)

Every unauthenticated vulnerability report MUST include an explicit evidence table:

```markdown
| Credential / Artifact | Present in Attack Request? | Verification Evidence |
|-----------------------|---------------------------|-----------------------|
| Authorization Header  | ❌ No | HEADERS frame contains only standard HTTP pseudo-headers |
| Bearer / API Token    | ❌ No | `/proc/self/environ` contains no TOKEN/KEY/SECRET variables |
| Session Cookie        | ❌ No | No Cookie header; cookie jar empty |
| Session File          | ❌ No | No token files in local filesystem or shared run directories |
| mTLS Certificate      | ❌ No | Connection opened over standard unauthenticated cleartext TCP / TLS |
| Capability Token      | ❌ No | No capability payload or signed request headers |
```

### 3. Overclaim Prevention Table

| Overclaimed Title (Triggers Triager Rejection) | Bulletproof Defensive Title (Triager Accepts) |
|-----------------------------------------------|-----------------------------------------------|
| "Host Escape / Container Breakout in Sandbox" | "Unauthenticated `ControllerService` Listener Exposes Command Execution to Guest Workload Processes" |
| "Full Account Takeover via API" | "IDOR in `/api/v2/users/{id}/email` Allows Authenticated User to Modify Secondary Account Email" |
| "Remote Code Execution via File Upload" | "Arbitrary File Upload to Web-Accessible Directory Enables Script Execution in Web Server Context" |
| "Authentication Bypass in OAuth Flow" | "Missing `state` Validation in `/oauth2callback` Enables Cross-Site Request Forgery (Login CSRF)" |

---

## Gate 0: Reality Check (30 seconds)

The finding must be REAL — confirmed with actual HTTP requests or code execution, not speculation from reading code.

### Required Evidence (at least ONE must be present)

| Evidence Type | What Counts | What Doesn't |
|--------------|-------------|--------------|
| HTTP response | Full request + response with status code and body | "The server would probably..." |
| Screenshot | Shows actual impact (changed data, exposed PII) | Screenshot of a form field existing |
| Code trace | Exact line numbers showing unguarded path | "This pattern is dangerous in general" |
| Reproduction | Same result from 2+ different starting states | "It worked once but I can't reproduce" |

### Fail Conditions (KILL immediately)
- "I read the code and it looks like..." — no live confirmation
- "This type of endpoint is often vulnerable to..." — pattern matching without testing
- "The response was different so there might be..." — ambiguous signal
- Only tested with your own data (IDOR needs cross-account proof)
- Tested on a dev/staging environment not in scope

### Demote Conditions
- Finding is real but only on a non-production environment explicitly out of scope → DEMOTE to note, do not report
- Finding requires a specific browser/OS version → note the constraint

---

### The Impact Litmus Test

Answer this question with a single concrete sentence:

> "An attacker can __________, resulting in __________."

The first blank must be a specific action. The second must be a specific harm.

**PASSES:**
- "An attacker can read any user's booking confirmation emails, resulting in exposure of full traveler PII including passport numbers."
- "An attacker can redeem the same gift card 50 times concurrently, resulting in $5,000 theft from a $100 card."
- "An attacker can write arbitrary telemetry to the production Azure App Insights instance, resulting in false SOC alerts and masked real attacks."

**FAILS (kill immediately):**
- "An attacker can potentially access data" — what data? whose?
- "An attacker could theoretically..." — theoretically is not a finding
- "This could be used in a chain" — build the chain first, then report
- "This is a security misconfiguration" — describe the actual harm, not the category
- "This violates best practice" — best practice violations without exploit impact are not bugs

### Trigger vs Impact — the two-halves rule (read before ANY kill)

The Impact Litmus Test answers ONE half of every lead. A kill is legal only
after BOTH halves are resolved:

- **Q-TRIGGER** — "Can the path fire?" If refuted (unreachable, trusted-actor-only with no bypass) → KILL.
- **Q-IMPACT** — "If it fires, what does the VICTIM lose?" If untraced → **DEMOTE to OPEN LEAD**, not KILL. The lead becomes a persistent research object (`tools/leads.py`): decompose the block into named missing preconditions, mutate one variable at a time until impact is provable, and keep the payload. If it still cannot prove impact, PARK it into the chain pool — never drop it. A kill without BOTH refutations is refused by the ledger and auto-parks instead.

**Conflation is the failure mode.** Answering "can it fire?" and moving on
because the impact "seems below the bar" is the mistake this gate exists to
prevent. And impact is victim-harm, not attacker-profit: "this doesn't make an
attacker money" refutes nothing — an accounting desync that strands or
misdirects account value is account-owner loss, a Medium floor on Immunefi on
its own. Whether it chains into attacker profit is a separate trace, never a
precondition for keeping the lead alive. Severity estimation never precedes
the impact trace.

### Impact Tiers

| Tier | Impact | Examples | Severity Floor |
|------|--------|----------|----------------|
| T0 | Critical | RCE, auth bypass → admin, cloud credential theft, fund drain | Critical (9.0+) |
| T1 | High | PII/PHI exposure, ATO, financial manipulation, data destruction | High (7.0+) |
| T2 | Medium | Non-sensitive data exposure, limited IDOR (read-only, non-PII), stored XSS on low-value page | Medium (4.0+) |
| T3 | Low | Info disclosure (non-sensitive), missing security headers, clickjacking on static page | Low (0.1+) |
| T4 | None | CSP report-only, banner version without exploit, self-XSS, logout CSRF | Informational (0.0) — DO NOT REPORT |

### Common Impact Inflation (reject these)

| Claim | Reality |
|-------|---------|
| "Session hijacking" via XSS | Is HttpOnly set? If yes, you can't steal the session cookie. |
| "Account takeover" via open redirect | Do you have a full OAuth chain? If not, it's just an open redirect. |
| "Data breach" via API exposing counts | A count is not a breach. You need actual PII/credentials. |
| "RCE" via file upload | Did you actually execute code on the server? Or just upload a .php file to a static CDN? |
| "Denial of service" via one slow request | Can you actually take the service offline? If the request just times out, that's not DoS. |

---

# HackerOne Hacktivity
curl -s "https://hackerone.com/hacktivity?querystring=PROGRAM_NAME+BUG_CLASS"

# GitHub issues for the target
gh search issues "security" --repo OWNER/REPO --limit 20

### Step 2: Check These Sources

- [ ] HackerOne Hacktivity for this program (last 90 days)
- [ ] Bugcrowd Crowdstream for this program
- [ ] Program's public changelog / release notes
- [ ] GitHub Issues for the target repo (search: "security", "vuln", bug class name)
- [ ] The program's "known issues" or "out of scope" page
- [ ] Google: `site:target.com "security" "fixed"`

### Step 3: Duplicate Decision

| Situation | Action |
|-----------|--------|
| Same endpoint, same bug class, same impact → exact duplicate | KILL |
| Same endpoint, different bug class → not a duplicate | CONTINUE |
| Different endpoint, same bug class and root cause | Group into ONE report mentioning all affected endpoints |
| Same bug but your impact is significantly higher | REPORT with escalation language |

---

### Title Quality

The title must contain: **vuln class + location + attacker role + impact + victim scope**.

```
FORMAT: [Bug Class] in [Exact Endpoint] allows [attacker] to [action] [victim]
GOOD:   IDOR in /api/v2/bookings/{id} allows any authenticated user to read any traveler's passport data
BAD:    IDOR vulnerability found
BAD:    Possible authorization issue in booking API
```

### PoC Quality

The PoC must be:
1. **Copy-pasteable** — the triager can run your curl command and see the same result
2. **Self-contained** — no "set up a VPS first" or "install this toolchain"
3. **Minimal** — the shortest sequence that demonstrates the impact
4. **Reproducible** — works every time, not just once

### Evidence Quality

- Screenshots must show the impact, not just the request
- For IDOR: show victim's data accessed from attacker's session
- For XSS: show the alert popup OR DOM manipulation result
- For SSRF: show the callback received OR metadata response
- For race conditions: show both successful responses

### Impact Statement Quality

Must answer ALL of:
1. What can the attacker do? (specific action)
2. To whom? (identifiable victim — user, company, system)
3. What's the worst case? (quantify: $ amount, number of users, type of data)
4. What does the attacker need? (nothing, free account, paid account, admin approval)
5. Is it detectable? (audit log? alert? or silent?)

---

### Pattern 1: Missing Auth Header Returns Different Status
```
GET /api/admin/users → 401 (expected: auth required)
GET /api/admin/users -H "Authorization: Bearer USER_TOKEN" → 200 (expected: user list)
```
If 401 without token, auth IS working. The lack of 403 for user token might be a finding, but 401 without token is correct behavior.

### Pattern 2: Parameter Reflection Without Execution
```
GET /search?q=<script>alert(1)</script> → Response contains: <script>alert(1)</script>
```
Reflection alone is not XSS. Is it reflected in HTML context without encoding? In a JSON string? In a header? Context matters.

### Pattern 3: CORS Reflects Origin Without Credentials
```
Origin: https://evil.com → Access-Control-Allow-Origin: https://evil.com
```
If `Access-Control-Allow-Credentials: true` is NOT present, this is not exploitable for credentialed data theft.

### Pattern 4: CSP Report-Only
A `content-security-policy-report-only` header DOES NOT block anything. It only reports violations. This is not a finding unless the report-uri is attacker-controllable.

### Pattern 5: Rate Limiting "Bypass" That Doesn't Scale
If you need 100 different IP addresses to bypass rate limiting, and the harm requires 10,000 requests... that's not a practical attack.

---

## Severity Escalation Pattern

When a triager pushes back with a lower severity, use these counter-arguments:

| Triager Says | You Respond |
|-------------|-------------|
| "This requires authentication" | "Authentication requires only a free account — no special role, no approval, no payment. The program's threat model includes malicious authenticated users." |
| "The impact is limited to one user" | "The attack is repeatable against ALL users. An attacker can enumerate every user ID and exfiltrate all PII. This is not one victim — it's the entire user base." |
| "This is by design" | "Please point me to the documentation that states users should be able to access other users' private data. If this is intended, it's not documented." |
| "The CVSS score is lower" | "CVSS doesn't capture business context. This endpoint exposes passport numbers — regulatory fines for PII exposure exceed $X. The business impact is higher than the technical score." |
| "We already know about this" | "Can you share the internal ticket ID or previous report number? I searched disclosed reports and found nothing." |
| "This is informational" | "I can demonstrate actual data exposure (see PoC). Informational findings don't have demonstrable impact — this does." |

---

## Triage Decision Tree (Quick Reference)

```
Finding received:
│
├─ Is it confirmed with a real HTTP request?
│  └─ NO → KILL
│
├─ Does it affect a real victim with real harm?
│  └─ NO → KILL
│
├─ Is the harm one of: money stolen, PII leaked, ATO, RCE, data destruction?
│  └─ NO → DEMOTE to informational or KILL
│
├─ Is the endpoint in scope?
│  └─ NO → KILL (or note as out-of-scope lead)
│
├─ Has this exact bug been reported before?
│  └─ YES → KILL (duplicate)
│
├─ Is this on the "always rejected" list?
│  └─ YES and no chain → KILL
│
├─ Can a triager reproduce this from my PoC in under 5 minutes?
│  └─ NO → Improve PoC before submitting
│
└─ All checks pass → WRITE REPORT
```

---

## Batch Triage Mode

When given a list of findings (from a scan, another tool, or manual testing), triage in this order:

1. **Group** — cluster by endpoint/feature. Same endpoint bugs go together.
2. **Sort** — highest impact first. T0 before T1 before T2.
3. **Dedup within batch** — if findings #3 and #7 are the same root cause, merge them.
4. **Gate each** — run each unique finding through all 4 gates.
5. **Output** — three lists: CONFIRMED (ready for report), LEADS (needs more testing), KILLED (dead ends).

### CONFIRMED (Ready for Report)
| # | Title | Severity | CVSS | Confidence |
|---|-------|----------|------|------------|
| 1 | IDOR in /api/bookings/{id} — read traveler PII | High | 7.5 | 90 |
| 2 | Race condition in /redeem — double-spend gift cards | Critical | 9.0 | 85 |

### LEADS (Needs More Testing)
| # | Description | What's Missing |
|---|-------------|----------------|
| 1 | /api/export returns 200 without auth cookie — possible unauth data export | Need to confirm what data is returned |
| 2 | GraphQL introspection enabled — field-level auth may be missing | Need to test node() queries across types |

### KILLED (Do Not Revisit)
| # | Description | Kill Reason |
|---|-------------|-------------|
| 1 | Missing CSP header | Always rejected — no exploit impact |
| 2 | Cloudflare blocks POST without cookie | Working as intended — WAF doing its job |
```

---

## Integration with SKILL.md

The main SKILL.md Phase 4 (Validate) references this supervisor. The 7-Question Gate is the quick version. This document is the detailed version. Use the 7-Question Gate for fast triage during hunting; use this full supervisor for findings you intend to report.


## SOURCE: hunt-skills/bountyforge/skills/pashov/solidity-auditor/references/hacking-agents/access-control-agent.md

# Access Control Agent

You are an attacker that exploits permission models. Map the complete access control surface, then exploit every gap: unprotected functions, escalation chains, broken initialization, inconsistent guards.

Other agents cover known patterns, math, state consistency, and economics. You break the permission model.

## Attack plan

**Map the permission model.** Every role, modifier, and inline access check. Who grants what to whom. This map is your weapon — every attack below references it.

**Exploit inconsistent guards.** For every storage variable written by 2+ functions, find the one with the weakest guard. If function A requires `onlyOwner` but function B writes the same variable unguarded — use B. Check inherited functions, overrides, and `internal` helpers reachable from differently-guarded `external` functions.

**Hijack initialization.** Call `initialize()` on the implementation contract directly. Front-run deployment to initialize with your own roles. Pass `address(0)` as a role parameter to permanently lock out admins.

**Escalate privileges.** Find routes where role A grants role B to itself. Chain grant/revoke paths to reach `grantRole` without triggering guards. Find upgrade paths that bypass timelock. Trigger `renounceRole` to leave the system unrecoverable.

**Exploit confused deputies.** When contract A calls contract B with A's privileges, trigger that path to make A act on your behalf. Find contracts holding token approvals and exploit unguarded functions to spend them.

**Abuse delegatecall/proxy.** Collide storage layouts. Self-destruct implementation contracts. Collide admin slots with business logic storage.

## Output fields

Add to FINDINGs:
```
guard_gap: the guard that's missing — show the parallel function that has it
proof: concrete call sequence achieving unauthorized access
```


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/multi-expert.md

**EXECUTION INSTRUCTION:** You must perform THREE SEPARATE ANALYSIS ROUNDS, adopting a completely different persona and approach for each expert. Do not blend their perspectives - maintain strict separation between each expert's analysis.

### ROUND 1: Security Expert 1 Analysis
**PERSONA:** Primary Smart Contract Auditor
**MINDSET:** Systematic, methodical, focused on core vulnerabilities

**ANALYSIS APPROACH:**
```markdown
1. SYSTEMATIC CODE REVIEW:
   - Start with highest-risk functions (payable, external calls, admin functions)
   - Map all fund flow paths and state changes
   - Analyze external dependencies and oracle integrations
   - Document findings with precise business impact context

2. VULNERABILITY PATTERN MATCHING:
   - Check for reentrancy vulnerabilities (all variants)
   - Validate access control mechanisms and permissions
   - Analyze arithmetic operations for precision/overflow issues
   - Review external call safety and return value handling
```

**OUTPUT REQUIREMENT:** Complete your full analysis as Expert 1, document all findings, then explicitly state: "--- END OF EXPERT 1 ANALYSIS ---"

### ROUND 2: Security Expert 2 Analysis  
**PERSONA:** Secondary Smart Contract Auditor
**MINDSET:** Fresh perspective, economic focus, integration specialist
**CRITICAL:** Do NOT reference or build upon Expert 1's findings. Approach as if you've never seen their analysis.

**ANALYSIS APPROACH:**
```markdown
1. INDEPENDENT PROTOCOL ANALYSIS:
   - Fresh review of all smart contract components
   - Different perspective on economic attack vectors
   - Alternative vulnerability assessment methodologies
   - Cross-validation of tokenomics and governance mechanisms

2. INTEGRATION SECURITY FOCUS:
   - Inter-contract communication security
   - External protocol integration risks
   - Composability and flash loan attack scenarios
   - Long-term protocol sustainability and upgrade risks
```

**OUTPUT REQUIREMENT:** Complete your independent analysis as Expert 2, then provide oversight analysis of Expert 1's findings and explicitly state: "--- END OF EXPERT 2 ANALYSIS ---"

**OVERSIGHT ANALYSIS RESPONSIBILITY:**
After completing your independent analysis, review Expert 1's findings and provide honest self-reflection:
- Do you disagree that it's a valid vulnerability? Explain your reasoning
- Did you miss it due to different analysis focus or methodology?
- Was it an oversight in your systematic review process?
- Would you have caught it with more time or different approach?

### ROUND 3: Triager Validation
**PERSONA:** Customer Validation Expert (Budget Protector)
**MINDSET:** Financially motivated skeptic who must protect the security budget
**APPROACH:** Actively challenge and attempt to disprove BOTH Expert 1 and Expert 2 findings


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-2-signer-checks/fv-anc-2-cl1-unvalidated-signers.md

## TLDR

Declaring an account as `AccountInfo<'info>` rather than `Signer<'info>` in an Anchor context struct means the framework does not enforce that the account signed the transaction. Any public key can be passed as the authority without authorization.

## Detection Heuristics

**AccountInfo Used Where a Signer Is Required**
- Account declared as `pub authority: AccountInfo<'info>` in a context struct for an instruction that performs privileged operations
- Account used to authorize transfers, mutations, or admin actions but typed as `AccountInfo` instead of `Signer`

**No Supplemental is_signer Check**
- `AccountInfo` account used in a privileged path without a subsequent `require!(ctx.accounts.authority.is_signer, ...)` check in the instruction body
- `has_one` constraint on a vault pointing to an `AccountInfo` authority without signer enforcement

**Signer Constraint Missing on PDA-Signed Paths**
- Instruction accepts a user-provided authority for a PDA operation but does not enforce signing from that authority before deriving or using the PDA

## False Positives

- `AccountInfo` is used for read-only informational accounts (e.g., sysvars, program IDs) where signing is not required
- Account is a PDA that cannot sign transactions; signer seeds are instead validated via `invoke_signed` or Anchor seeds constraint


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-2-signer-checks/fv-anc-2-cl2-no-is_signer-check.md

## TLDR

When using raw `AccountInfo` or native Solana program patterns, the `is_signer` field on the account info must be explicitly checked. Omitting this check means an instruction accepts any account as an authority without verifying it signed the transaction.

## Detection Heuristics

**Key Comparison Without Signer Verification**
- Code that checks `authority.key != expected_key` or `authority.key() == expected_key` but never checks `authority.is_signer`
- Authorization based solely on account key equality, allowing a known-public-key account to be passed without a signature

**Missing is_signer Guard in Instruction Body**
- Instruction using raw `AccountInfo` for an authority account without `if !account.is_signer { return Err(...) }`
- `require!(account.is_signer, ...)` absent from all code paths that perform privileged operations

**AccountInfo in Context Struct Without Signer Wrapper**
- Multiple `AccountInfo` accounts in a context struct where at least one is treated as an authorizing party in the instruction body, but none have `is_signer` verified

## False Positives

- Account is a PDA controlled by the program; PDAs cannot be signers and authorization is instead proven through seed derivation
- Account is a read-only system account or sysvar where signing is not meaningful


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-4-pda-security/fv-anc-4-cl1-using-create_program_address.md

## TLDR

`Pubkey::create_program_address` requires a caller-supplied bump seed and does not find the canonical bump. An attacker can supply a non-canonical bump that produces a valid but unintended PDA, bypassing seed-based access controls or creating collisions with legitimate PDAs.

## Detection Heuristics

**create_program_address Without Canonical Bump Verification**
- `Pubkey::create_program_address(&[seed, &[bump]], program_id)` where `bump` comes from instruction data or an account field without verifying it is the canonical bump returned by `find_program_address`
- No comparison of the derived PDA against `Pubkey::find_program_address` output to confirm canonicity

**Bump Stored Without Derivation Check**
- Bump value stored in an account during initialization without verifying it was obtained from `find_program_address`
- Instruction accepts a `bump: u8` parameter and uses it directly in `create_program_address` without on-chain verification

**Missing seeds Constraint in Anchor**
- PDA account declared in a context struct without `#[account(seeds = [...], bump)]`, which would have Anchor enforce canonical bump derivation

## False Positives

- Bump is stored in the PDA account itself during `init` using Anchor's `bump` constraint, and subsequent instructions read it with `#[account(seeds = [...], bump = account.bump)]`, which enforces the canonical value
- `find_program_address` is called in the same instruction and the result is immediately compared, making the use of `create_program_address` equivalent


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-5-cross-program-invocation-cpi/fv-anc-5-cl2-cpi-without-signer-seeds.md

## TLDR

When a CPI requires a PDA to sign on behalf of the program, `invoke_signed` must be called with the correct signer seeds. Using `invoke` or passing empty seeds to `invoke_signed` causes the CPI to fail or to execute without the PDA's authority, breaking the intended access control.

## Detection Heuristics

**invoke Used Where PDA Signature Is Required**
- `invoke(&instruction, &accounts)?` called when one of the accounts listed is a PDA that needs to sign; the PDA will not be recognized as a signer by the callee
- CPI to the Token Program for a PDA-owned token account using `invoke` instead of `invoke_signed`

**invoke_signed With Empty Seeds**
- `invoke_signed(&instruction, &accounts, &[])` where one of the accounts is a PDA, providing no signing authority
- Seeds array passed to `invoke_signed` does not include the seeds for all PDAs that must sign

**Incorrect or Incomplete Seeds**
- Signer seeds passed to `invoke_signed` do not match the seeds used to derive the PDA, causing signature verification to fail at the callee
- Bump seed omitted from the signer seeds array

## False Positives

- CPI is initiated on behalf of a user who signed the transaction; the user's `AccountInfo` carries `is_signer = true` and no PDA signature is needed
- `invoke` is correct when none of the accounts in the CPI need to be PDAs signing on behalf of the program


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-5-cross-program-invocation-cpi/fv-anc-5-cl7-invoke-signed-with-wrong-or-partial-seeds.md

## TLDR

If the seeds array passed to `invoke_signed` does not exactly match the seeds used to derive the PDA that is expected to sign, the call will fail or sign under the wrong identity. More critically, when multiple seed combinations can resolve to valid program addresses, using an incorrect subset can authorize operations under an unintended signer identity, bypassing intended access controls.

## Detection Heuristics

**Seeds Mismatch Between Derivation and Signing**
- Seeds list in `invoke_signed` call differs from seeds used in the corresponding `Pubkey::find_program_address` or `Pubkey::create_program_address` call
- `bump` seed omitted from the `invoke_signed` seeds while the PDA derivation included it, or vice versa
- Seed values sourced from user-supplied accounts without validation used in the signing call

**Incomplete Seed Validation**
- Program dynamically constructs the seeds array at runtime from account fields without asserting the resulting address matches the expected PDA key
- Seeds array passed as a slice reference where individual seed byte arrays come from attacker-controlled instruction data
- No `Pubkey::create_program_address(seeds, program_id) == expected_pda` assertion before the invoke_signed call

**Shared Seed Prefix Ambiguity**
- Multiple PDA types share a seed prefix, and the wrong type can be used as a signer because the seeds are checked by inclusion not exact match
- Bump stored in an account field can be manipulated to produce a different valid PDA address

## False Positives

- Seeds are compile-time constant byte slices that are identical in both derivation and signing call sites; compiler ensures they cannot diverge
- Program verifies the derived address from seeds matches the account key before using it in invoke_signed


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-5-cross-program-invocation-cpi/fv-anc-5-cl9-cpi-privilege-escalation-via-account-authority.md

## TLDR

When accounts passed into a CPI carry `is_writable` or `is_signer` flags that originated from the outer transaction context, an attacker can escalate privileges inside the CPI by crafting the outer transaction's account flags. Anchor's `CpiContext` does not automatically strip or re-derive account privilege flags; the program must construct them from protocol logic rather than forwarding them from the incoming accounts.

## Detection Heuristics

**Raw AccountInfo Forwarded to CPI**
- `account.to_account_info()` called directly on an incoming account and the result passed to a CPI without explicitly setting `is_signer: false` or `is_writable: false` where those privileges should not be forwarded
- `CpiContext::new` constructed from accounts list built by iterating `ctx.remaining_accounts` and passing each entry through without flag validation
- Program does not verify that an account's `is_signer` flag in the incoming transaction context corresponds to an expected signer key before relying on it inside a CPI

**Authority Account Not Key-Validated**
- Account is accepted as an authority in the CPI accounts list without comparing its key against a stored expected authority address
- Writable flag forwarded to an account that should only be read during the inner CPI, allowing the CPI target to modify it

**Elevated CPI Privilege Without Explicit Grant**
- Inner CPI receives signer authority over accounts not owned by the calling program, derived from outer transaction signer flags the calling program did not explicitly grant
- `invoke` (not `invoke_signed`) called with accounts carrying signer flags set to true from the outer transaction, propagating caller-level authority into the CPI

## False Positives

- Anchor typed CPI helpers (e.g., `token::transfer`, `system_program::create_account`) construct the account list with explicit flag values and do not forward raw AccountInfo flags from the context
- Program explicitly reconstructs each account's `AccountMeta` with hardcoded `is_signer` and `is_writable` values appropriate to the inner CPI's expected interface


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/move/fv-mov-2-access-control/readme.md

# FV-MOV-2: Access Control and Capabilities

Sui Move uses the capability object pattern as its primary access control mechanism. This category covers missing capability checks, incorrect visibility modifiers, phantom type bypass, and sender address spoofing.

## Cases

- [fv-mov-2-cl1-missing-capability-check.md](fv-mov-2-cl1-missing-capability-check.md) - Privileged function callable without a capability object
- [fv-mov-2-cl2-capability-lifecycle.md](fv-mov-2-cl2-capability-lifecycle.md) - Capability created outside `init` or OTW pattern missing
- [fv-mov-2-cl3-entry-visibility-bypass.md](fv-mov-2-cl3-entry-visibility-bypass.md) - `public(package) entry` overrides package-only restriction
- [fv-mov-2-cl4-sender-spoofing.md](fv-mov-2-cl4-sender-spoofing.md) - Caller address accepted as parameter instead of from TxContext


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/solidity/fv-sol-4-bad-access-control/fv-sol-4-c1-using-tx.origin-for-authorization.md

## TLDR

`tx.origin` always resolves to the original EOA that initiated the transaction, regardless of how many contracts the call passed through. A malicious contract invoked by a privileged user can exploit this to impersonate that user in any contract that relies on `tx.origin` for access control.

## Detection Heuristics

**tx.origin Used as Access Guard**
- `require(tx.origin == admin)` or `require(tx.origin == owner)` as the sole authorization check
- `if (tx.origin != trustedAddress) revert` pattern in state-changing functions
- `tx.origin` compared against any stored address to gate privileged operations

**Combination Patterns That Still Fail**
- `tx.origin` used as a fallback when `msg.sender` check fails - still exploitable via phishing
- `tx.origin` used to set an owner or beneficiary address during initialization, then later compared for authorization

## False Positives

- `msg.sender` is used instead of `tx.origin` for the authorization check
- `tx.origin` appears only in event emissions or logging, not in require/revert guards
- `tx.origin == msg.sender` used to assert caller is an EOA with no downstream privileged action gated solely on that check


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/solidity/fv-sol-4-bad-access-control/fv-sol-4-c5-callback-authorization-bypass.md

## TLDR

External callback functions (`onFlashLoan`, `onERC721Received`, `onERC1155Received`) are invoked by third-party contracts. If the callback does not verify `msg.sender` is the expected caller, anyone can invoke it directly with fabricated parameters, bypassing intended access control. ERC4626 `withdraw`/`redeem` has a related variant: when `msg.sender != owner`, allowance must be checked and decremented or any address can burn an arbitrary owner's shares.

## Detection Heuristics

**Flash Loan Callback**
- `onFlashLoan` does not verify `msg.sender == address(lendingPool)`
- Initiator, token, or amount parameters unchecked - callable directly without a real flash loan
- State changes or fund transfers triggered solely by caller-supplied parameters

**ERC721 onERC721Received Spoofing**
- `onERC721Received` uses `from` or `tokenId` to update state without checking `msg.sender == address(expectedNFT)`
- Any caller can invoke directly with fabricated parameters to trigger unintended state changes

**ERC1155 Burn Without Authorization**
- Public `burn(address from, ...)` callable by anyone without `msg.sender == from` or operator approval check
- Any caller can burn another user's tokens

**ERC4626 Missing Allowance Check**
- `withdraw(assets, receiver, owner)` or `redeem(shares, receiver, owner)` where `msg.sender != owner` but no `_spendAllowance` call present

**ERC1155 setApprovalForAll Over-Permission**
- Protocol requires `setApprovalForAll(protocol, true)` for deposits - operator can transfer any token ID at full balance, not just the deposited amount

## False Positives

- `require(msg.sender == address(lendingPool))` and `initiator == address(this)` both validated in flash loan callback
- `require(msg.sender == address(nft))` present before state update in `onERC721Received`
- `require(from == msg.sender || isApprovedForAll(from, msg.sender))` in custom burn
- OZ `ERC4626` used without custom overrides (allowance check is built in)
- Protocol uses direct `safeTransferFrom` with user as `msg.sender` (no `setApprovalForAll` needed)


## SOURCE: hunt-skills/bountyforge/skills/smart-contract-audit/reference/ton/fv-ton-2-access-control/fv-ton-2-cl3-admin-authorization.md

## TLDR

Administrative operations (parameter updates, fund withdrawals, pausing, upgrading) that lack a sender address check against the stored admin/owner address allow any contract or wallet to invoke privileged functions.

## Detection Heuristics

**Missing sender validation on privileged opcodes**
- Handler for ops like `op::change_admin`, `op::withdraw`, `op::upgrade`, `op::set_params` has no `throw_unless(error::not_owner, equal_slices(sender_address, admin_address))`
- `admin_address` loaded from storage but the comparison is skipped or commented out
- Authorization check present only on some admin ops but not all - inconsistent coverage

**No admin transfer mechanism or insecure one**
- No `op::change_admin` or `op::transfer_ownership` handler - admin key loss permanently locks privileged functions
- Admin address change in a single step with no pending/confirm pattern - sending to a wrong address is irreversible
- Admin address stored in code cell (c3) instead of data cell (c4), requiring a full code upgrade to change it

**Tact contracts**
- Tact contract uses `Ownable` trait but one or more `receive()` handlers for administrative messages do not call `self.requireOwner()` before executing

## False Positives

- Contract is intentionally permissionless for the audited operation; confirm this is by design and there is no way to escalate to fund extraction
- Admin check implemented via a helper function - verify the helper performs `equal_slices(sender_address, admin_address)` and throws on mismatch


## SOURCE: hunt-skills/bountyforge/skills/web3/web3-case-study-role-misconfig/SKILL.md

# CASE STUDY: ROLE MISCONFIGURATION IN A YIELD AGGREGATOR

Bug Class: Access Control | Severity: Critical/Medium | Payout Range: $10K–$50K

See also: [[Web3 Audit]], [[Web3 Bug Classes]], [[Methodology]], [[Trust Map]], [[A→B Chains]]

---

## TARGET PROFILE (Anonymized)

| Field | Value |
|-------|-------|
| Protocol Type | Yield aggregator — stablecoin → lending protocol → harvest → DEX → reward token |
| Max Bounty | $50K (Critical) |
| TVL | Low (fresh program, under $100K) |
| Core Contracts | Vault.sol, RewardsDistributor.sol |
| Program Age | ~5 days when hunted (fresh = low competition) |
| Prior Audits | Firm A (16 findings, all Risk Accepted) + Firm B (18 findings, all Risk Accepted) |

**Scorecard:** Max bounty (+2) + custom math (+1) + recent code (+1) + known prior audits (+1) + public source (+1) + program new (+2) = **8/10 → HUNT**

**Why this scores high:** Fresh program on a live bounty platform + prior audits that accepted all risk = team is aware of issues but hasn't patched them. Hunt for what auditors missed or flagged but accepted.

---

## ARCHITECTURE + FUND FLOW

```
User deposits Stablecoin
    ↓ deposit(uint256 amount)
Vault.sol stores:
  - deposits[user] += amount
  - totalDeposited += amount
  - depositTimestamp[user] = block.timestamp
    ↓ safeTransferFrom(user, address(this), amount)
    ↓ lendingProtocol.supply(stablecoin, amount, address(this), 0)
  Interest-bearing token accrues in Vault.sol balance
    ↓ (periodic) _performHarvest()
  aToken balance > totalDeposited + DUST_THRESHOLD
    ↓ lendingProtocol.withdraw(stablecoin, harvestAmount - 1, address(this))
    ↓ dex.exactInputSingle(stablecoin → rewardToken)
    ↓ RewardsDistributor.distribute(rewardToken, amount)
  RewardsDistributor tracks:
  - cumulativeRewardPerShare updates
  - users can call claimFor(user) to collect rewardToken

User withdraws:
    ↓ withdraw(uint256 amount)
  if block.timestamp < depositTimestamp[user] + LOCK_PERIOD:
    withdrawFee applies (e.g. 0.5%)
  lendingProtocol.withdraw(stablecoin, amount, user)
```

**Key state variables:**
- `deposits[user]` — user principal (stablecoin)
- `totalDeposited` — sum of all principals
- `depositTimestamp[user]` — last deposit time (affects withdrawal fee)
- `cumulativeRewardPerShare` — reward index in RewardsDistributor
- `lastClaimedReward[user]` — user's last reward index

---

### Firm A Findings (16 total, all Risk Accepted)
All standard: missing events, gas optimizations, reentrancy guards present (CEI followed), centralization risks (owner can pause), single oracle (DEX swap is operational, not security-critical).

### Firm B Findings (18 total, all Risk Accepted)
Including:
- HAL-01: withdrawFee can be changed by owner (centralization)
- HAL-05: deposit() resets depositTimestamp even on partial top-ups → **extends lock period for existing deposits**
- HAL-08: Missing check for DISTRIBUTOR_ROLE being set *(flagged but did NOT verify it was never granted)*
- Various gas and event issues

**Pattern:** Firm B flagged "missing check" but didn't verify the role was actually ungranted. This is the gap to exploit.

---

### 1. Accounting Desync — 2 FINDINGS

**Finding 1: The `-1` Stranding Pattern**
```solidity
// In _performHarvest():
harvestAmount = aToken.balanceOf(address(this)) - totalDeposited - 1; // strands 1 wei
```
The hardcoded `-1` strands 1 wei of stablecoin per harvest permanently. Over thousands of harvests, this accumulates. Severity: LOW/INFORMATIONAL (no user loss, just protocol dust accumulation).

**Finding 2: Dust Harvest DoS** ← VALID MEDIUM
```
Scenario: Accumulated harvest amount is very tiny (< DEX minimum swap)
1. harvest() calls dex.exactInputSingle(stablecoin → rewardToken)
2. DEX returns 0 (amount too small to produce any output)
3. RewardsDistributor.distribute(0) is called
4. If distribute() reverts on 0 amount → harvest is permanently frozen
5. Users can still withdraw principal but all future yield is lost

Verification: Check if distribute(0) reverts. Check DEX minimum swap threshold.
```

### 2. Access Control — 1 FINDING (CRITICAL/HIGH)
**Finding: DISTRIBUTOR_ROLE Never Granted** ← MAIN FINDING

```solidity
// RewardsDistributor.sol
bytes32 public constant DISTRIBUTOR_ROLE = keccak256("DISTRIBUTOR_ROLE");

function claimFor(address user) external {
    require(hasRole(DISTRIBUTOR_ROLE, msg.sender), "Not distributor");
    // ... distribute rewardToken to user
}
```

**Problem:** `DISTRIBUTOR_ROLE` is defined but NEVER granted in the constructor or any initialization function. No address holds this role. `claimFor()` can never succeed — all reward tokens are permanently locked.

**How Firm B missed it:** They flagged "missing check for whether role is set" — but their fix recommendation was "add a require that checks the role exists." They didn't verify that `getRoleMemberCount(DISTRIBUTOR_ROLE) == 0` on the live deployment.

**Severity Assessment:**
- If harvest HAS already happened: CRITICAL (funds locked forever)
- If harvest never happened yet: HIGH (permanent lock when it does happen)
- Impact × Likelihood × Exploitability: 3 × 3 × 3 = 27 → CRITICAL

**Verification commands:**
```bash

# Check if any address has DISTRIBUTOR_ROLE (replace with actual address)
cast call <REWARDS_DISTRIBUTOR_ADDR> \
  "getRoleMemberCount(bytes32)(uint256)" \
  "$(cast keccak 'DISTRIBUTOR_ROLE')"

### 3. Incomplete Path — Known (Risk Accepted)
Firm B HAL-05: `deposit()` resets `depositTimestamp[user]` even on partial top-ups, extending the lock period for all existing deposits. Risk Accepted by team.

### 4. Off-by-One — CLEAN
All boundary operators (`>=`, `<`) in Vault.sol and RewardsDistributor.sol are correct.

### 5. Oracle Price — CLEAN
Protocol does NOT use price oracles for security decisions (no lending, no liquidation, no collateral). The DEX swap is operational (converting yield), not security-critical. MEV/sandwich risk exists but is a griefing/efficiency issue, not a theft vulnerability.

### 6. ERC4626 Vaults — NOT APPLICABLE
Uses a custom 1:1 share model, NOT ERC4626:
- `deposits[user]` tracks exact principal
- No share price, no share-based rounding
- Transfers between users are blocked
- First depositor inflation attack does NOT apply

### 7. Reentrancy — CLEAN
Follows CEI (Checks-Effects-Interactions) correctly:
- `deposits[user] += amount` BEFORE `lendingProtocol.supply()`
- `deposits[user] -= amount` BEFORE `lendingProtocol.withdraw()`
- Missing `nonReentrant` guard, but CEI makes it safe. Not submittable without PoC.

### 8. Flash Loan — CLEAN (Economically)
Flash loan attack would attempt: deposit → dilute harvest → withdraw to steal yield.
The `withdrawFee` makes this unprofitable:
- Attacker deposits $1M → harvest dilutes → attacker gains $0 extra yield
- But: attacker pays withdrawal fee to exit
- Net: negative expected value → NOT PROFITABLE

### 9. Signature Replay — NOT APPLICABLE
No signature-based functions, no EIP-2612 permit, no meta-transactions.

### 10. Proxy/Upgrade — NOT APPLICABLE
Not upgradeable proxies. No proxy pattern.

---

### SUBMIT (2 findings):

**Finding 1 — CRITICAL/HIGH:**
```
Title: DISTRIBUTOR_ROLE never granted in RewardsDistributor.sol,
       permanently locking all reward tokens

Root Cause: DISTRIBUTOR_ROLE is defined but grantRole() is never called
            in constructor or initialization. No address holds this role.

Impact: All rewards distributed by harvest() are permanently locked —
        claimFor() always reverts.
        Users receive zero yield despite depositing and paying withdrawFee.

Attack Path: Not an attack — passive failure. Any harvest → rewards locked forever.

Severity: Critical (if harvest has occurred) / High (if not yet)
```

**Finding 2 — MEDIUM:**
```
Title: _performHarvest() dust harvest causes permanent DoS on yield distribution

Root Cause: When accumulated yield rounds to < DEX minimum swap amount,
            exactInputSingle() returns 0 output. distribute(0) may revert or
            permanently advance the reward index with no rewards.

Impact: After a dust harvest, all subsequent harvests may fail permanently.

Severity: Medium (requires specific conditions but permanently impacts yield)
```

### DO NOT SUBMIT:
- The `-1` stranding (informational, design choice)
- depositTimestamp reset (Risk Accepted by team)
- Missing nonReentrant (CEI is followed; no PoC = no submission)
- Owner centralization (excluded by design in Immunefi SC programs)
- Any of the already-acknowledged findings from prior audits

---

## COMPLETE POC TEMPLATE: ROLE NEVER GRANTED

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import "forge-std/Test.sol";
import "forge-std/console.sol";

interface IRewardsDistributor {
    function DISTRIBUTOR_ROLE() external view returns (bytes32);
    function hasRole(bytes32 role, address account) external view returns (bool);
    function getRoleMemberCount(bytes32 role) external view returns (uint256);
    function claimFor(address user) external;
}

contract RoleNeverGrantedTest is Test {
    // Replace with actual deployed address from target
    address constant REWARDS_DISTRIBUTOR = address(0xYOUR_TARGET_ADDRESS);

    IRewardsDistributor distributor;

    function setUp() public {
        // Fork at current block
        vm.createSelectFork(vm.envString("MAINNET_RPC_URL"));
        distributor = IRewardsDistributor(REWARDS_DISTRIBUTOR);
    }

    function testDistributorRoleNeverGranted() public {
        bytes32 DISTRIBUTOR_ROLE = distributor.DISTRIBUTOR_ROLE();

        uint256 memberCount = distributor.getRoleMemberCount(DISTRIBUTOR_ROLE);
        console.log("Addresses with DISTRIBUTOR_ROLE:", memberCount);

        // Should be 0 — proving no one can call claimFor()
        assertEq(memberCount, 0, "DISTRIBUTOR_ROLE has 0 members (confirmed bug)");

        // Verify claimFor() reverts for any user
        address testUser = address(0x1234);
        vm.expectRevert(); // "AccessControl: account does not have role"
        distributor.claimFor(testUser);

        console.log("CONFIRMED: claimFor() reverts for all users.");
        console.log("All rewards permanently locked.");
    }
}
```

**Run:**
```bash
forge test --match-test testDistributorRoleNeverGranted -vvvv \
  --fork-url $MAINNET_RPC_URL
```

**Expected output:**
```
Addresses with DISTRIBUTOR_ROLE: 0
CONFIRMED: claimFor() reverts for all users.
All rewards permanently locked.

[PASS] testDistributorRoleNeverGranted()
```

---

## REPORT TEMPLATE

**Title:** Missing DISTRIBUTOR_ROLE grant permanently locks all rewards for all users

**Bug Description:**
`RewardsDistributor.sol` defines `DISTRIBUTOR_ROLE` and requires it to call `claimFor()`. However, `grantRole(DISTRIBUTOR_ROLE, ...)` is never called in the constructor, any initialization function, or any privileged setter. No address holds this role. `claimFor()` always reverts.

The Vault contract calls `RewardsDistributor.distribute()` after each harvest, successfully depositing reward tokens into the distributor. However, these tokens can never be claimed — permanently locked.

**Root Cause:** Constructor is missing `grantRole(DISTRIBUTOR_ROLE, vaultContract)`.

**Impact:** All yield earned by all depositors is permanently locked in RewardsDistributor.sol. Users cannot receive any return from their deposits.

*Impact category:* **Permanent freezing of funds**

**Proof of Concept:** [Run PoC above against deployed contract]

**Remediation:** Add `grantRole(DISTRIBUTOR_ROLE, address(vault))` in RewardsDistributor constructor, OR add a `setDistributor(address)` function callable only by admin.

---

## VALIDATION CHECKLIST (7-Question Gate)

| Question | DISTRIBUTOR_ROLE | Dust Harvest DoS |
|----------|-----------------|-----------------|
| Can attacker use it NOW? | Yes (passive — already locked) | Yes (needs small harvest) |
| Impact in program's list? | Permanent freezing of funds ✓ | Temporary/permanent DoS ✓ |
| In-scope contract? | RewardsDistributor.sol ✓ | Vault.sol ✓ |
| Requires admin access? | No — passive ✓ | No — anyone can trigger ✓ |
| Already known/acknowledged? | No ✓ | No ✓ |
| Economically viable? | Yes — passive lock ✓ | Yes — dust accumulates ✓ |
| Already public? | No ✓ | No ✓ |
| **VERDICT** | **SUBMIT** | **SUBMIT** |

---

## LESSONS: WHAT TO LOOK FOR ON SIMILAR TARGETS

This pattern (role defined, never granted) appears frequently in:

1. **Any contract using OpenZeppelin AccessControl** — check every `bytes32 public constant *_ROLE` — verify each one has a corresponding `grantRole()` call in constructor
2. **Distributor/reward contracts** — these are often deployed separately and the grant is "supposed to happen" during deployment setup
3. **Contracts with multiple initialization steps** — if setup requires calling multiple functions in sequence, the grant is often missed

**Grep to find candidates:**
```bash

# If roles > grantRole calls → investigate each missing grant
```

**Protocols to check for this pattern:** Any protocol where `RewardsDistributor`, `FeeDistributor`, `YieldDistributor`, or `Distributor` is a separate contract from the main vault.

---

→ NEXT: [08-ai-tools.md](08-ai-tools.md)
