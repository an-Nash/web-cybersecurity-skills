---
name: hunt-reporting-triage
description: Definitive "from finding to paid report" skill for report writing, evidence hygiene, severity calibration, false-positive discipline, and triage rebuttals. Built from 39 curated source files covering BountyForge reporting/validation gates, HackerOne/Bugcrowd/Intigriti/Immunefi/HackenProof submission craft, 100-high-upvoted-report target profiles, A→B chain writeups, lead/trust ledgers, the Customer-Validation triager mandate, and 20+ smart-contract false-positive case files. Use when turning a confirmed primitive into a report a triager will pay for — or when a triager pushes back and you must counter with evidence. Never fabricate HackerOne IDs or URLs; cite source skill paths.
sources: bountyforge, hackerone_public, bugcrowd, intigriti, immunefi, hackenproof, portswigger_research
report_count: 0
full_reports_read: 0
source_skills: 39
---

## Crown Jewel Targets

This skill is not about *finding* bugs — it is about which findings deserve a report and how to get them paid. The crown jewels are report shapes that survive a hostile triage read on the first pass.

Priority report archetypes, in descending order of triage ROI:

- **Path B — unauthenticated flow demonstrated against a Path A control plane.** "Path A requires valid credentials; Path B accepts equivalent operations with zero credential." This is the single strongest structure in the corpus — it crosses an explicit authorization barrier and is provable with an absent-credential evidence grid.
- **Demonstrated impact, not inferred impact.** "I read victim@test.com's orders from attacker@test.com's session" beats "the endpoint appears to lack ownership checks." Every claim is tagged **Demonstrated / Inferred / Unproven** and report drift from a demonstrated primitive into an unproven claim is forbidden.
- **Accepted-impact-category bugs** — ATO, RCE, SQLi with data exfil, mass PII exposure, cloud-metadata SSRF returning data, privilege escalation. These map cleanly onto program severity tables; no argument about whether they "count."
- **Two-account proofs** — attacker session + victim session, both obtained through normal registration. This converts an "IDOR" claim from a permissions misunderstanding into an undeniable cross-identity breach.
- **AB-chains that revive a rejected class** — open redirect → OAuth code theft → ATO; SSRF DNS-only → internal access + returned data; self-XSS → login CSRF → stored XSS on victim. The chain is the report; the low finding alone is a chain menu entry, not a submission.
- **In-scope production asset with an explicit policy clause** — the report's Scope & Engagement Gate quotes the clause and points to concrete evidence of eligibility.

Highest-value *programs* from the H100 analysis (100 highest-upvoted HackerOne reports) — prioritize hunting here because the surface is broad and the payouts are proven:

| Program | Reports / Total | Top classes | Key surfaces |
|---|---|---|---|
| GitLab | 12 / $134K | RCE, File Read/Write, SSRF, Data Leak, SSTI | Project import, Markdown/Wiki rendering, file uploads, CI/CD, merge requests |
| Shopify | 8 / $50K | Priv-Esc, SSRF, OAuth, Credential Leak, SSTI | Email confirmation flow, Electron apps (.env in asar), third-party apps, Stocky OAuth |
| PayPal | 6 / $93.9K (highest $/report) | XSS, RCE, Token Leak, DoS, IDOR | Login cache poisoning, security challenge flow, npm packages, business mgmt API |
| Snapchat | 7 / $65K | Infra Misconfig, RCE, Auth Bypass, SSRF | Jenkins/Grafana/CI dashboards, exposed K8s API, content deletion, GraphQL introspection |
| Valve | 5 / $40K | Client RCE, SQLi, payment tampering | Steam client parsing of untrusted server info/chat, report generation API |
| X / xAI | 4 / $20.16K | Pre-auth RCE (1-day VPN), auth bypass, CRLF | VPN infra, Digits API, web properties |
| Uber | 3 / $40.4K | Info disclosure, OAuth chain, leaked certs | Internal microservices, mobile APIs, OAuth flows, git-history certs |

Quick-win profiles: Snapchat infrastructure (Jenkins/Grafana/K8s API = instant $10–25K); Starbucks SQLi + repo creds; Razer SQLi + command injection; Mail.ru SQLi/upload/memory disclosure; LY Corp (LINE) HTTP smuggling + OAuth misconfig. Cross-target patterns that repeatedly pay: leaked tokens in code/apps ($10–50K), HTTP smuggling → session hijack ($0–6.5K), infra misconfig ($10–25K), GraphQL missing auth ($0–12.5K), email confirmation bypass ($0–15K), cache poisoning → XSS ($18–20K), file upload → RCE ($0–20K), npm/supply chain ($11–30K), classic SQLi ($0–25K).

Payouts are highest when the demonstrated capability crosses into another user's data, into money, or into a control plane — not when it is "a technically interesting request."

---

## Attack Surface Signals

These are the signals that a finding is *triage-ready*. Check them before you spend an hour writing.

### In-Surface / Eligibility Signals

- Target asset appears verbatim on the program's in-scope list (not `*.internal.target.com`, not staging/dev unless explicitly in scope).
- Target is a production asset, not a third-party service the company merely uses (Stripe, Salesforce, Google Auth are out).
- Impact category appears on the program's accepted "Vulnerability Types" list — or at minimum is not on its "Out of Scope" list.
- The exact commit/version is referenced and matches the in-scope deployment (HackenProof Gate 1; smart contract Q4 — verified on-chain bytecode matches audited source).
- A program policy clause can be quoted in the Scope & Engagement Gate; no exclusions apply to the demonstrated class.
- Safe-harbor / disclosure terms are known (Intigriti enforces safe harbor — be comfortable going slightly aggressive).

### Evidence-Readiness Signals

- A working PoC exists: a real HTTP request, a running `forge test` against a fork, a video, a transaction hash, or logs.
- The response body / screenshot actually shows the bug (victim data returned, token exfiltrated, 200 where 403 expected) — not just a status code or error string.
- Two identities are available and the finding holds cross-identity (session A reading session B's scope).
- The chain, if any, is proven end to end — not "could be combined with X."
- Confidence score ≥ 80 (start at 100; -20 partial path, -15 bounded impact, -10 specific state, -10 user interaction, -10 partial mitigation).

### Red-Flag / Triage-Kill Signals

- Only "technically possible" demonstrated; no data, no money, no boundary crossed.
- Requires admin/owner/governance authority with no bypass — centralization risk, kill on 99% of programs.
- More than two simultaneous preconditions, or a 30+ minute dig with no reproducible PoC.
- Class appears on the never-submit list without a chain partner (see Common Root Causes and Bypass Techniques).
- Finding lives in `lib/`, `interfaces/`, `mocks/`, `test/`, `*.t.sol`, `*Mock*` — 89% of automated scanner "Highs" are out-of-scope dependency noise.
- A duplicate exists with the same root cause *and* same impact.
- Conflicting evidence: reports in the same batch contradict each other, or the attack path conflicts with a protection found elsewhere in the code.

### Platform Signal Map

| Platform | Signals to include |
|---|---|
| HackerOne | VRT category (Broken Access Control > IDOR > P2), CVSS 3.1 string, disclosed-report dedup via Hacktivity |
| Bugcrowd | P1/P2/P3/P4 label alongside the plain severity; VRT category |
| Intigriti | Impact tag field, self-assigned severity, CVSS 3.1/4.0, Loom video over screenshot |
| Immunefi | Asset Type, Blockchain/Tech Stack, Vulnerability Category, exact funds at risk, runnable Foundry PoC, one concrete fix |
| HackenProof | Commit/version evidence, detected program type → matching classification track, PoC artifact present |
| `h1` CLI | Append CVSS 3.1 vector as a code block when `--cvss` is set |

---

## Discovery Patterns From Curated Source Skills

### Where Researchers Start

1. **The program page, before the bug.** Find "Vulnerability Types" and "Out of Scope," quote the clause, and record the accepted impact tiers. A bug that maps to an exclusion dies at Q2 no matter how clever.
2. **High-upvoted report analysis (H100).** The corpus extracted target-and-surface profiles from the 100 highest-upvoted HackerOne reports (see Crown Jewel Targets). Start where big bugs actually live: imports, renderers, auth flows, CI/CD, internal dashboards.
3. **The audit `invariants.md` for smart contracts.** Before any gate, map the protocol's solvency/supply/permission/price invariants and run `MAP → INVARIANT → IDENTIFY ASSUMPTION → FIND CONTROLLED VARIABLE → MUTATE → OBSERVE → CHECK INVARIANT → CHAIN → CALCULATE VALUE AT RISK`. Every finding names the invariant it breaks and the value it puts at risk.
4. **Live deployment addresses, not just source.** On audited code, the criticals live at Layer 1 (deployment config: oracle/rate provider/decimals/ownership) and Layer 2 (fork-fuzzing `getRate()`). When file reads run dry, request addresses + RPC, fork, and fuzz — that is the attack surface.
5. **The lead ledger.** Open leads are persistent research objects with two independent questions (TRIGGER / IMPACT) and named missing preconditions. Start each pass from parked leads, not from a blank page.
6. **Prior disclosures.** Search contest history, prior audits, `CHANGELOG.md`, README "known issues," GitHub issues (`is:issue label:security ENDPOINT_NAME`), and prior submissions before investing.

**The 5-layer smart-contract priority (rank effort by where criticals actually live):**
- **Layer 1 — Deployment config, not contract code.** Biggest source of criticals on audited code: rate provider/oracle pointed at a manipulatable spot price instead of Chainlink; decimal mismatch (6 vs 18 → 10^12 error); ownership not actually renounced; two vaults sharing one stale accountant. Invisible from source — needs live addresses + mainnet RPC.
- **Layer 2 — Fork mainnet and run invariant fuzzers.** Core invariants: `totalAssets() == Σ(balances valued via getRate())`; share-price monotonicity across deposit/withdraw/vest/postLoss; first-depositor/donation inflation via `mulDivDown(ONE_SHARE, getRate())`.
- **Layer 3 — The integration layer, not the target.** stETH/rebasing/fee-on-transfer/18-vs-6 tokens; proxy tokens with different `decimals()`; `beforeTokenTransfer` hooks that re-enter; read-only reentrancy via `getRate()` reading a manipulable external contract.
- **Layer 4 — New deployments and upgrades.** Freshly added, unaudited tellers/decoders/adapters; watch the deployer address for new contracts.
- **Layer 5 — Chain a medium into a critical.** A 1-wei accounting drift or a rounding direction compounded over N deposits becomes an extractable loss. A single small bug is a Medium; the same bug made repeatable is a Critical.

### Feature-Based Discovery Signals

- **Import/export features** — SSRF, path traversal, arbitrary file read via rewriters; check every file copy/move.
- **Markdown/wiki/renderers** — RCE, stored XSS, template injection in the rendering library.
- **Auth/email-confirmation flows** — bypass leads to full store takeover via SSO; token leaks in the security challenge flow.
- **Image/link preview, screenshot, PDF generation** — headless-browser SSRF with network-privileged JS execution.
- **Webhooks and URL-accepting fields** — validation-then-fetch with separate DNS lookups.
- **OAuth `redirect_uri`, client_secret in mobile apps, subdomain registrations** — chain primitives for ATO.
- **Unauthenticated network listeners / daemon ports** — the Path A vs Path B split: intended control plane vs raw unauthenticated listener.
- **Business logic with amounts, roles, states, tokens** — one-variable mutation targets (`user_id`, `role`, `state`, `amount`, `token`, `method`, `version`).
- **Newly deployed/upgraded contracts** — the freshly added, unaudited teller/decoder/adapter is where the critical lives.
- **Rate limits on OTP/reset/token endpoints** — only interesting when a brute-force succeeds (chain).

### Verbatim Hunter Clues

Direct quotes from the curated sources — internalize these:

> "Never use 'could potentially' or 'could be used to' or 'may allow'. Either it does the thing or it doesn't. If you haven't proved it, don't claim it." — `report-writing/SKILL.md`

> "One wrong answer = STOP. Kill it. Move on. N/A hurts your validity ratio. Informative is neutral. Only submit what passes all 7 questions." — `triage-validation/SKILL.md`

> "The RED TEAM RULE: If the finding cannot survive the strongest plausible triager objection, DO NOT promote it to a report." — `references/validation.md`

> "DEMONSTRATED VS INFERRED RULE: Explicitly categorize every claim as Demonstrated, Inferred, or Unproven. Never allow report drift from a demonstrated primitive to an unproven claim." — `references/validation.md`

> "Impact is victim-harm, not attacker-profit." — `wiki/Lead Ledger.md`

> "HUNT vs REPORT (wild mode): These gates are the LAST step of the pipeline — they filter what gets SUBMITTED. They are never run during the hunt, never kill a probe, and never delete a lead." — `references/validation.md`

> "Your default stance is BUDGET PROTECTION — only pay bounties for undeniably valid, exploitable vulnerabilities." — `smart-contract-audit/triager.md`

> "Write to a person, not a system. Triagers are tired. Get to the impact in sentence 1. Use 'I' not 'the researcher'." — `report-writing/SKILL.md`

> "If you CANNOT write step 2 as a real HTTP request → KILL IT." — `triage-validation/SKILL.md`

> "kill_lead() refuses unless BOTH halves are refuted with evidence. One-half refutation = auto-park." — `wiki/Lead Ledger.md`

> "Zero fluff. Every sentence must carry technical weight. No hedging. Never write 'may', 'could potentially', 'it is possible that'. If the code allows it, state it as fact." — `references/reporting.md`

> "Technically possible is not impact. 'I read victim's SSN' is impact. Quantify the harm." — `references/validation.md`

> "Below the bar is not a kill." — `wiki/Lead Ledger.md`

> "Never allow report drift from a demonstrated primitive to an unproven claim." — `references/validation.md`

> "Anchor final severity to demonstrated impact, not hypothetical worst case." — `hackenproof-triage-marketplace/references/severity-mapping.md`

### Probe Checklist

Run this against every candidate before drafting:

```
[ ] Can an attacker use this RIGHT NOW, step by step? (Q1 template filled in 5 min)
[ ] Is impact on the program's accepted impact list? (Q2)
[ ] Is the root cause in an in-scope, production asset? (Q3)
[ ] Does it require privileged access an attacker can't realistically get? (Q4)
[ ] Already known / accepted / documented behavior? (Q5 — four searches done)
[ ] Can I prove impact beyond "technically possible"? (Q6 — real data/money/boundary)
[ ] Is it a known-invalid bug class without a chain? (Q7 — NEVER SUBMIT list)
[ ] Identity check: which session found it, does it survive anonymous/cross-identity/stale-cred repro? (Q8)
[ ] Two-account proof captured with attacker + victim IDs?
[ ] Evidence artifact ready: HTTP request + response body / screenshot / video / tx hash?
[ ] Chain proven end to end if the standalone class is rejected?
[ ] Dedup searched: Hacktivity + GitHub issues + last 5 disclosed reports + Google?
[ ] Confidence ≥ 80? Else demote to LEAD, no fix, no PoC.
[ ] Both halves of the Two-Question Rule traced (TRIGGER + IMPACT)?
[ ] Only one variable mutated per attempt so results are attributable?
```

---

## Step-by-Step Hunting Methodology

This is the submission pipeline, applied in order. Gates are the last step — they filter what a human reads.

1. **Capture program context.** Record engagement type (BBP / VDP / Direct Vendor Disclosure / Internal Red Team), exact target asset, scope, exclusions, governing policy clause, and the security boundary at stake. Map program type → classification track (web / mobile / smart-contract / blockchain-protocol).

2. **Promote a lead, don't assume a finding.** Log each candidate in the lead ledger with both questions written: TRIGGER ("can this path fire?") and IMPACT ("if it fires, what does the victim lose?"). Track named missing preconditions (`missing → present | refuted | irrelevant`). KILL only when both halves are refuted; otherwise PARK.

3. **Mutate one variable.** Change exactly one of `user_id`, `role`, `state`, `amount`, `token`, `method`, `version` per attempt. Never two at once — you need attribution.

4. **Build the two-identity proof.** For IDOR/BOLA: session A reads session B's data. For priv-esc: low-priv reads high-priv data (if both already see it, no bug). For auth bypass: it works with no session (if it stops when logged out, it's a permissions issue). Always check both directions. Record the 12-char `BBHUNT_SESSION_ID`, identity, anonymous repro, cross-identity repro, and stale-cred repro. This is the most common reason "confirmed IDOR" comes back N/A.

5. **Run the 7-Question Gate (web2) or the SC track (contracts).** All seven must be YES; any NO → STOP, demote to lead with payload + chain partners. Complete Q1's template literally: Setup / Request / Result / Impact / Cost.

6. **Run the Red Team Triage Engine on your own finding.** Answer all 10 questions: Scope, Policy, Precondition, Authentication, Path A, Path B, Boundary, Impact, Alternative explanation, Evidence. Then find the strongest plausible triager rebuttal and the observation that defeats it. If you cannot defeat it, do not promote.

7. **Apply the Demonstrated / Inferred audit.** Build the absent-credential evidence grid (Authorization header, Bearer/API token, session cookie, session file, mTLS cert, capability token — each "Present in attack request? ❌ No" with verification evidence) and the demonstrated-vs-inferred matrix. Mark host escape/system takeover **Unproven** unless directly executed.

8. **Check known-issue history and dedup.** Program disclosures, GitHub issues, changelog, design docs, prior submissions; Hacktivity + last 5 disclosed reports + Google for web.

9. **Assemble the chain if the class is rejected.** Use the CONDITIONALLY VALID table. Build it, prove it end to end, then report the chain — not the low finding and not a separate "similar to A" submission.

10. **Calibrate severity.** Anchor to demonstrated impact, never hypothetical worst case. Compute CVSS 3.1 (or 4.0 for newer programs) with the full vector string; cross-check the program's severity definitions and the global baseline; apply the self-assessment and downgrade counters; score confidence.

11. **Write the report in the canonical format** (see Payload & Detection Patterns). H1 title by formula, H2 sections, `---` dividers, no hedging, present tense, numbered copy-pasteable PoC steps, one-line action headers, screenshot/code block per step.

12. **Run the 60-second pre-submit check, then submit.** If a triager responds, switch to the rebuttal playbook in Bypass Techniques and answer with evidence, not adjectives.

---

## Payload & Detection Patterns

### Canonical Defensive-Proof Report Template

Every report follows this exact structure to preempt triager rejection:

```
## Scope & Engagement Gate
- Engagement Context: <BBP | VDP | Direct Vendor Disclosure | Internal Red Team / Pentest>
- Target Asset: <Exact domain, IP, repo, contract, or binary>
- In Scope: <Yes / N/A (Independent Research)>
- Explicit Exclusions: <Check program policy; None if self-hosted/pentest>
- Governing Rule / Policy: <Quote program policy clause / advisory terms / ROE>
- Impact & Boundary Threshold: <Boundary crossed or business risk proven>
- Evidence Supporting Eligibility: <Concrete demonstrated observations>
**Severity:** <Critical | High | Medium | Low>
**Vulnerability Type:** <Primary CWE / Class>
**Affected Component:** <Component / Endpoint / Daemon Listener> (`<path/port/URL>`)
---
## Summary
<3–5 sentences: what it is, where it lives, how it triggers, what an attacker gains.
State explicitly what is NOT claimed if scope/severity is sensitive. No hedging. Present tense.>
---
## Control Plane vs Unauthenticated Listener (Path A vs Path B)
- Path A (Legitimate Intended Flow): requires valid authentication credentials
- Path B (Unauthorized Flow Demonstrated): accepts equivalent operations with no credential
- Security Boundary Crossed: <explicit authorization barrier bypassed>
---
## Absent Credential Evidence Grid
| Credential / Artifact | Present? | Verification Evidence |
| Authorization Header | No | Frame contains only standard pseudo-headers |
| Bearer / API Token | No | /proc/self/environ has no TOKEN/KEY/SECRET |
| Session Cookie | No | No Cookie header; jar empty |
| mTLS Certificate | No | Standard unauthenticated TCP/TLS |
---
## Demonstrated vs. Inferred Audit Matrix
| Claim | Status | Evidence / Reasoning |
| Target accepts unauthenticated request | Demonstrated | Executed request succeeded with zero headers |
| Host escape / system takeover | Unproven | NOT claimed unless directly executed |
---
### 1. <Root cause label> — one tight bullet per line, reference exact file/line/port
---
## Steps to Reproduce
1. Context / setup
2. Copy-pasteable curl or script
3. Execute and observe response
**Expected (if secure):** <auth check should happen>
**Actual:** <what the endpoint does>
---
## Security Impact
- Demonstrated Capability: attacker with <access> can <exact action> without credentials
- Program Policy Threshold: meets requirement by demonstrating <eligibility evidence>
---
## Recommended Fix
1. Actionable fix step 1
2. Actionable fix step 2
```

### Format Rules (non-negotiable for the report itself)

- Zero fluff. Every sentence carries technical weight. No hedging: never "may," "could potentially," "it is possible that." Present tense throughout.
- H1 for title, H2 for top-level sections, `---` divider after metadata and between major sections.
- No tables, no collapsible sections, no emoji *inside the submitted report* (the grids above are an internal evidence aid; render their conclusions as prose).
- PoC steps numbered; one-line H3 action header, one sentence of context, then screenshot or code block.

### Platform-Specific Report Templates

**Bugcrowd / VRT:**
```markdown
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

**Intigriti (severity self-assigned; video valued over screenshot):**
```markdown
## Description
[Impact-first paragraph. Start with what an attacker can do, not how you found it.
Include: endpoint, method, parameter, data exposed, required privileges.]
## Steps to Reproduce
**Environment:**
- Attacker: email=attacker@test.com (standard account, no special role)
- Victim: email=victim@test.com
- Tested: [date]
**Reproduction steps:**
1. [Login as attacker / visit URL / send request]
2. Send the following HTTP request:
   METHOD /endpoint HTTP/1.1
   Host: target.com
   Authorization: Bearer ATTACKER_TOKEN
   Content-Type: application/json
   {"param": "victim_id_here"}
3. Observe response contains victim's private data:
   {"email": "victim@test.com", "address": "123 Main St", ...}
## Impact
[Specific, quantified impact. What data, how many users, what can attacker do.]
CVSS 3.1 Score: X.X ([Severity]) — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
## Attachments
[Screenshot or Loom video showing the impact — Intigriti prefers video for complex bugs]
```
Intigriti specifics: title format `[Bug Class]: [One-line impact]`; severity set by you (Critical/High/Medium/Low/Exceptional); CVSS 3.1 standard (4.0 accepted on newer programs); Loom video worth more than a screenshot; safe harbor enforced.

**Immunefi (Web3):**
```markdown
## Summary
[Root cause, affected function, economic impact, attack cost. Include numbers:
"attacker can drain $X in Y transactions."]
## Vulnerability Details
**Contract:** `VulnerableContract.sol`
**Function:** `claimRedemption()`
**Bug Class:** Accounting State Desynchronization
**Severity:** Critical
## Proof of Concept
// Foundry PoC — run: forge test --match-test test_exploit -vvvv
[full working exploit]
## Impact
[Quantified: "Attacker can drain X% of TVL = $Y at current rates.
Requires $Z gas. Attack is repeatable."]
```
Immunefi must include Asset Type, Blockchain/Tech Stack, Vulnerability Category, exact root-cause function and line, exact funds at risk (not "could be exploited"), a runnable Foundry PoC (not pseudocode), and one concrete fix (not "add access control").

### Report Title & Impact Formulas

```
TITLE:  [Bug Class] in [Exact Endpoint/Feature] allows [attacker role] to [impact] [victim scope]
IMPACT: An [attacker with X access] can [exact action] by [method], resulting in [business harm].
        This requires [prerequisites] and leaves [detection/reversibility].
```

Good: `IDOR in /api/v2/invoices/{id} allows authenticated user to read any customer's invoice data`
Bad: `IDOR vulnerability found`, `Broken access control`, `Security issue in API`

### Triager-Optimized Steps to Reproduce

```markdown
**Setup:**
- Account A (attacker): email=attacker@test.com, ID=111
- Account B (victim): email=victim@test.com, ID=222
- Both created via normal registration — no special access
**Steps:**
1. Log in as Account A
2. Send this request (replace `111` with victim ID `222`):
   GET /api/v2/resource/222 HTTP/1.1
   Host: target.com
   Authorization: Bearer ACCOUNT_A_TOKEN
3. Response contains Account B's private data:
   {"id": 222, "email": "victim@test.com", "name": "Victim User", "address": "..."}
**Expected:** 403 Forbidden   **Actual:** 200 OK with victim's private data
```

### Evidence Checklist

```
[ ] Exact HTTP request (copy-paste ready) with method, URL, headers, body
[ ] Response showing the bug: JSON body / screenshot / video
[ ] Two test accounts with their IDs — not one account testing itself
[ ] Expected vs Actual stated explicitly
[ ] Absent-credential grid conclusions rendered as prose (Path B)
[ ] Cross-identity / anonymous / stale-credential repro outcomes recorded
[ ] Fix is 1–2 sentences, not a lecture; no typos in paths or parameter names
[ ] Report < 600 words — triagers skim
[ ] CVSS string present and severity claimed matches impact described
[ ] Supporting materials: screenshot + Loom video for complex bugs (Intigriti prefers video)
```

### Severity Calculators

**CVSS 3.1 quick guide:** 0–3.9 Low (non-sensitive info disclosure) · 4–6.9 Medium (IDOR read PII, low-impact stored XSS) · 7–8.9 High (IDOR write/delete, SQLi, race/double-spend) · 9–10 Critical (auth bypass → admin, cloud-metadata SSRF, RCE).

Common vectors:

| Finding | Score | Severity | Vector |
|---|---|---|---|
| IDOR read PII, auth required | 6.5 | Medium | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |
| IDOR write/delete | 7.5 | High | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| Stored XSS → cookie theft | 8.8 | High | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N |
| SQLi → full DB dump | 8.6 | High | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| SSRF → cloud metadata | 9.1 | Critical | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N |
| Auth bypass → admin | 9.8 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| JWT none algorithm | 9.1 | Critical | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| GraphQL auth bypass | 8.7 | High | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| Race → double spend | 7.5 | High | AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N |

Metric picks: AV Network +0.85 (internet) / Local +0.55; AC Low +0.77 (repeatable) / High +0.44 (race); PR None +0.85 / Low +0.62 / High +0.27; UI None +0.85 / Required +0.62; S Changed (browser/OS/cloud) / Unchanged; C/I/A High +0.56 (all data / any modify / crash) / Low +0.22 (limited).

**CVSS 4.0** (replaced 3.1 in Nov 2023; some newer programs require it): adds Attack Requirements (None/Present) and Sub-Impact metrics (VC/VI/VA vulnerable system, SC/SI/SA subsequent system); removes Scope; UI becomes None/Passive/Active. Examples: unauthenticated RCE 10.0 `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H`; authenticated IDOR read PII 6.9 `.../PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`; SSRF → cloud metadata 8.7 `.../VC:H/VI:N/VA:N/SC:H/SI:H/SA:N`. Use the FIRST calculator and include the full `CVSS:4.0/...` string — programs cannot dispute a valid vector.

**Severity self-assessment** (each YES raises one level): exposes PII/health/financial data of others +1 · ATO or priv-esc +2 · zero victim interaction +1 · affects ALL users +1 · remotely exploitable with no internal access = baseline for High+.

**Severity tiers (Bugcrowd-style):** Critical/P1 — any-user ATO without interaction, RCE, SQLi dump/modify, admin auth bypass, SSRF → IAM credential exfil · High/P2 — mass PII, user→admin priv-esc, SSRF to internal services with data returned, stored XSS for all users of a sensitive feature, unbounded payment bypass · Medium/P3 — IDOR on non-critical data, XSS on low-sensitivity page requiring interaction, CSRF on important action, OTP rate-limit bypass with effort shown · Low/P4 — non-sensitive info disclosure, clickjacking on sensitive action WITH PoC, CORS on limited data.

**HackenProof baseline** (when program rules don't override): Critical — payments manipulation, SQLi, RCE, command injection, fund/asset loss · High — stored XSS, SSRF, wallet-linked subdomain takeover, major sensitive data leak, auth bypass, impactful IDOR/priv-esc · Medium — reflected XSS, non-wallet takeover, 2FA bypass, moderate data leak, meaningful CSRF · Low — HTML injection, low-impact takeover, no-rate-limit on low-sensitivity endpoints, content spoofing, broken link hijack. Adjustments: raise for simple/repeatable/low-cost paths; lower for privileged access, unrealistic assumptions, excessive coordination.

**Confidence scoring:** start 100; −20 partial attack path, −15 bounded non-compounding impact, −10 specific-but-achievable state, −10 user interaction, −10 partial mitigation. ≥80 → full description + PoC + fix; 60–79 → description + partial PoC; <60 → LEAD only (no fix, no PoC).

**20 real paid bounty patterns (dissected) — Web3 severity anchors:**

| # | Protocol | Bug class | Payout | Key lesson |
|---|---|---|---|---|
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
| 17 | 0ki dEX | Access Control | $3M | Admin key compromise |
| 18 | CoinEx | Access Control | $70M | Hot wallet key leak |
| 19 | StakeWise | Flash Loan | $75M | MEV-Boost relay manipulation |
| 20 | Polycat Finance | Flash Loan | $1.2M | Mint + dump via price oracle lag |

Use these as severity anchors: the dominant Web3 critical patterns are access control, flash-loan-driven price manipulation, and reentrancy — each with an exact measurable drain. A "critical" that cannot name the amount and path is not one.

### Repro Harnesses

**Web — Q1 template (must be fillable in 5 minutes):**
```
1. Setup:   I need [own account / another user's ID / no account]
2. Request: [exact HTTP method, URL, headers, body — copy-paste ready]
3. Result:  I can [read / modify / delete] [exact data in response]
4. Impact:  [ATO / PII read / money stolen]
5. Cost:    Time: [X min], Capital: [$0 / $X subscription]
```

**Smart contract — Foundry PoC (must be a passing `forge test` against a fork):**
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// run: forge test --match-test test_exploit -vvvv
contract ExploitTest is Test {
    // fork deployed chain, trace exact call path, assert the broken invariant
    // report: exact wei/token amounts + USD, gas cost, repeatability
}
```

**HackenProof validation tool sequence (strict order):** `get_program_info` → detect program type → map to classification track → `get_report_details` → `get_attachments` (no PoC → Need more info) → `fetch_attachment` → compare commit/version to scope → verify target + impact in scope → `list_reports`/`search_comments` for duplicates → validate reproducibility/impact/preconditions/proof → `get_comments` before posting → only then change severity/state/labels and comment.

**Decision states:** Out of scope · Duplicate (add `dup-{report_id}` label) · Informative (valid, low/no impact) · Not applicable (not reproducible) · Triaged (passed all gates). Prefer reversible `Need more info` over premature invalidation when uncertainty is material.

**HackenProof comment templates (short, evidence-based):**
```md
<!-- Triaged -->
Thanks for the report. We validated: Impact: <clear impact>; Reproducibility: <reproduced>; Scope: In scope.
Marking as Triaged with severity <severity>.
<!-- Need more info -->
We could not fully validate. Please provide: <missing step>, <expected vs actual evidence>, <PoC/logs>.
Setting to Need more info.
<!-- Out of scope -->
Currently Out of scope because: <specific scope/rule reference>. If you believe this maps to an
in-scope target, share that target and evidence and we will re-check.
<!-- Duplicate -->
Matches existing report with same root cause and impact: <report-id>. Marking as Duplicate.
```

---

## Common Root Causes

Why good findings fail — and the false-positive patterns that must be recognized before reporting:

1. **Report drift.** A demonstrated primitive quietly becomes an unproven claim (guest execution primitive → "host escape"). Fix: tag every claim Demonstrated / Inferred / Unproven; never claim host escape without directly executing it.
2. **Hedging.** "Could potentially allow access" instead of "I changed user_id to 456 and retrieved victim orders." Fix: the Most Important Rule.
3. **Identity confusion.** Calling a missing-auth issue "IDOR" or a permissions issue "auth bypass." Fix: Q8 identity check in both directions.
4. **Impact theater.** Showing `alert(1)`, a DNS ping, an error message, or a 200 status and calling it impact. Fix: Q6 — show data, money, or a crossed boundary.
5. **Theoretical chains.** "Could be combined with X." Fix: build the chain, prove it end to end, then report the chain.
6. **Merging separate bugs.** Chaining A+B into one report when they are two separate bugs (two payouts) — or reporting B as "similar to A in my other report" without a fresh Gate 0.
7. **Admin/owner-only triggers.** Centralization risk, not a vuln, on most programs. Fix: find a non-intended actor who can reach the path, or a governance bypass.
8. **Out-of-scope files/versions.** `lib/`, `interfaces/`, `mocks/`, `test/`, testnet, stale unpinned version. Fix: verifiable on-chain/in-scope asset.
9. **Assuming recovery for "transient DoS."** Without a confirmed self-resolving path (timelock expiry, guaranteed keeper, any-user restore function), score as permanent DoS or drop it.
10. **Auto-kill reflexes that are actually misses (counter-patterns):**
    - "Documented / matches upstream design" ≠ refutation unless you actually read the upstream source. Docs describe intent; deployed bytecode is reality.
    - "Requires oracle misreport" ≠ auto-kill — check for an honest-path route to the same state first.
    - "Requires victim cooperation" ≠ auto-kill when the state transition is public and front-runnable.
    - "Self-harm" ≠ no impact — split into actor-scoped legs; each leg's victim is separate.
11. **Anchor smart-contract false positives** (from the curated case files — a finding that matches a False-Positives section is NOT a bug):
    - Single consistent time source (always `unix_timestamp` or always `slot`), documented units → not a time-unit mismatch.
    - Account written only through a CPI where the callee enforces writability; read-only deserialization → not a missing-writable bug.
    - All-zero data is the intended initialized state; program initializes immediately before any read → not an uninitialized-account bug.
    - Mutation and reads in separate instructions (Anchor re-deserializes on entry), single write at end → not a stale-read bug.
    - Address derived on-chain from validated PDA seeds or constrained to a fixed set → not an unvalidated-address bug.
    - Token ATA with `init_if_needed` (token program enforces ownership), explicit no-op guards → not a reinit bug.
    - `realloc::zero_init = false` on a shrinking allocation, or all new bytes overwritten before read → not a stale-byte bug.
    - Anchor `Account<'info, T>` type (ownership auto-enforced), address-constrained `UncheckedAccount`, executable program accounts → not an ownership-check bug.
    - Signer status enforced via PDA seeds or key is address-constrained → not a missing-signer bug.
    - Constraint enforced equivalently with `require!`, or structurally impossible to violate → not a missing-constraint bug.
    - Self-transfer handled with a no-op guard, accounts from distinct constant seeds → not a duplicate-mutable-account bug.
    - Typed sysvar wrappers / `Clock::get()` syscalls → not an unvalidated-sysvar bug; index validated against expected program ID → not an absolute-index bug; key comparison rather than position → not an ALT spoofing bug; timestamp validated via Clock window or single-use nonce → not a durable-nonce ordering bug.
    - Typed CPI helpers hardcode program IDs, or `#[account(address = ...)]` constrains the CPI target → not an unvalidated-CPI bug.
12. **Safe patterns that are not bugs:** real rate limiting, properly validated CSRF tokens, self-XSS without escalation, stack traces in dev mode only, unauthenticated operator RPC (ecosystem standard), plaintext local signer comms, default `0.0.0.0` bind (dev convenience), version/health endpoints without auth, generic library error messages.

**ALWAYS REJECTED — never submit standalone:** missing CSP/HSTS/security headers · missing SPF/DKIM/DMARC · GraphQL introspection alone · banner/version disclosure without working CVE · clickjacking on non-sensitive pages · tabnabbing · CSV injection without code execution · CORS wildcard without credential exfil PoC · logout CSRF · self-XSS · open redirect alone · OAuth client_secret in mobile app (expected) · SSRF DNS-ping only · host header injection alone · rate limits on non-critical forms · session not invalidated on logout · concurrent sessions · internal IP in error message · mixed content · SSL weak ciphers · missing HttpOnly/Secure flags alone · broken external links · autocomplete on password fields · pre-account takeover. **This is a chain menu, not a stop sign** — find the chain partner before dropping the lead.

---

## Bypass Techniques

This section is about bypassing triage pushback with evidence — not about exploit filter evasions.

### The Downgrade Counter Playbook

| Triager says | Counter with |
|---|---|
| "Requires authentication" | "Attacker needs only a free account — no special role or permission" |
| "Limited impact" | "Affects [N] users / exposes [PII type] / $[amount] at risk" |
| "Already known" | "Show me the report number — I searched hacktivity and found none" |
| "By design" | "Show me the documentation stating this is intended behavior" |
| "Low CVSS" | "CVSS doesn't capture business impact — attacker can extract [X] in [Y] minutes" |
| "Not exploitable" | "Here is the exact response showing victim's data returned to attacker session" |

### Anti-Refutation Rules (from real misses)

- **Documented behavior:** to refute with "it matches upstream design," show the upstream *source*, not another protocol's docs. Docs describe intent; deployed bytecode is reality.
- **Oracle precondition:** before accepting "requires oracle misreport," check whether an honest data path reaches the same state. If yes, the finding stands without the caveat.
- **Victim cooperation:** a public, observable on-chain transition is front-runnable and therefore attacker-triggerable. Name the unavoidable victim transaction.
- **Self-harm:** split into actor-scoped legs; name a victim for every leg. One self-inflicted leg does not nullify another leg's impact.
- **Transient DoS:** name the exact self-resolving recovery path and confirm it executes on its own. No confirmed recovery → permanent DoS or drop.

### Reviving a Rejected Class with a Chain

Build the chain first, prove it end to end, THEN report. The standalone low finding is a chain menu entry.

| Standalone finding | Chain partner | Valid result |
|---|---|---|
| Open redirect | OAuth `redirect_uri` → auth code theft | ATO (Critical) |
| Clickjacking | sensitive action + working PoC | Medium |
| CORS wildcard | credentialed request exfils user PII | High |
| CSRF | sensitive state change (transfer, change email, delete) | High |
| Rate-limit bypass | OTP/reset-token brute force succeeds | Medium/High |
| SSRF DNS-only | internal service access + data returned | Medium |
| Host header injection | password reset email uses injected host | High |
| Prompt injection | reads another user's data (IDOR) | High |
| S3 bucket listing | JS bundles contain API keys/OAuth secrets | Medium/High |
| Self-XSS | CSRF triggers it on victim | Medium |
| Subdomain takeover | OAuth `redirect_uri` registered at that subdomain | Critical |
| GraphQL introspection | auth-bypass mutation or IDOR on `node()` | High |

### Writing the AB-Chain Writeup

- One H1 title naming the *end* impact (ATO), not the first primitive (open redirect).
- Each hop gets its own numbered PoC step with the exact request/response and a screenshot.
- State the security boundary crossed by the chain as a whole; show that the chain is attacker-triggerable from start to finish.
- Never submit B as "similar to A in my other report" — every bug gets a fresh Gate 0.
- If two primitives are genuinely separate bugs with separate victims, write two reports for two payouts.

### Evidence Weapons Against Specific Objections

- **"Not reproducible":** provide a fresh-state video and a second-person reproduction; resolve flakiness before submission.
- **"No real victim":** show session B's actual data in session A's response, with both IDs.
- **"Impact overclaimed":** restate at the demonstrated level; a correctly-scored Medium paid is worth more than a disputed Critical N/A'd.
- **"Duplicate":** show the other report's root cause *or* impact differs; duplicates require both to match.
- **"Missing PoC":** attach a runnable request harness / `forge test` / tx hash / logs immediately — this is the single most common "Need more info" trigger.

### Human-Tone Rebuttal Language

Use "I" and short paragraphs. Avoid jargon, passive voice, qualifying language ("seems to," "appears to"), and five-paragraph explanations of what IDOR is. Escalation lines that work: "This is exploitable externally without network access to any internal system." "The impact is equivalent to a full data breach of [feature]." "An attacker can automate this with a simple loop — all [N] records in minutes."

### Lead & Trust Ledger Discipline

A lead is not a note to self — it is a persistent research object. This keeps rebuttals honest across sessions and prevents the "I thought this was confirmed" failure.

**Lead lifecycle:**
```
OPEN → MUTATING → FINDING   (both halves proven → promoted)
  │         │
  │         └──→ PARKED (impact not provable → chain pool)
  └────────────→ PARKED (kill refused: only one half refuted)
  └──→ KILLED (BOTH halves refuted with evidence)
```

**Two-Question Rule:** every lead carries TRIGGER ("can this path fire?") and IMPACT ("if it fires, what does the victim lose?"). Both get a written trace. Impact is victim-harm, not attacker-profit. Three verdicts only: FINDING / OPEN LEAD / KILL. "Below the bar" is not a kill — park it.

**One-variable mutation:** change exactly one of `user_id` (IDOR), `role` (privesc), `state` (TOCTOU), `amount` (business logic), `token` (auth bypass), `method` (GET vs POST), `version` (v1 vs v2) per attempt. Never two at once — you need to attribute the result.

**Missing preconditions** are tracked by name — "need second account for cross-account proof," "need race window (10ms sleep)," "need admin role," "need sibling endpoint /v2/users/{id}," "need chain partner for ATO" — and each resolves to `missing → present | refuted | irrelevant` with evidence.

**Kill guard:** `kill_lead()` refuses unless both halves are refuted with evidence. A one-half refutation auto-parks the lead with a counted dismissal attempt.

**Trust ledger:** record the session ID, identity, and repro outcome for every finding (from Q8). Re-run the request under each identity and confirm the bug holds before writing the report. Reject "already known" and "by design" only with a recorded search or the actual document — the ledger is what lets you answer a triager's duplicate claim with "I searched, here is what I found" instead of memory.

---

## Gate 0 Validation

Run before writing the report. This is the last step of the pipeline — it filters what gets submitted, never the hunt. The 5-step methodology spine underneath every gate is: `Program policy → Scope → Security boundary → Demonstrated impact → Severity`.

### The 10 Red Team Attack Questions (BountyForge self-attack)

Before drafting, attack your own finding across all ten. A finding that cannot answer #9 and #10 is not ready:

1. **Scope** — Is the exact asset/function in scope?
2. **Policy** — Is this vulnerability class explicitly excluded?
3. **Precondition** — What does the attacker actually need?
4. **Authentication** — What credential/authorization is supposed to exist?
5. **Path A** — What is the legitimate intended flow?
6. **Path B** — What unauthorized flow was demonstrated?
7. **Boundary** — What security boundary is crossed?
8. **Impact** — What concrete capability does the attacker gain?
9. **Alternative explanation** — What is the strongest reasonable triager rebuttal?
10. **Evidence** — What observation defeats that rebuttal?

Then build the evidence chain explicitly: Code Pattern Observed → Vulnerability Type → Attack Vector → Business Impact → Risk Assessment. The Customer Validation Expert persona (budget protection) additionally runs: finding-consistency check, evidence-chain validation, contract-location verification, attack-path cross-check, severity-calibration review, economic-impact validation, technical disproof, economic disproof, exploitability testing, false-positive detection, and production-reality check — and lands on DISMISSED / QUESTIONABLE / RELUCTANTLY VALID.

### Gate 0 — Reality Check (30 seconds)
```
[ ] Bug is REAL — confirmed with actual HTTP requests, not code reading alone
[ ] Bug is IN SCOPE — program scope page checked explicitly
[ ] Reproducible from scratch — fresh session reproduces
[ ] Evidence ready — screenshot, response body, or video
```

### Gate 1 — Impact Validation (2 minutes)
```
[ ] Answer: "What can attacker DO that they couldn't before?"
[ ] Answer is more than "see non-sensitive data"
[ ] Real victim: another user's data, company's data, financial loss
[ ] Not relying on victim doing something unlikely
```

### Gate 2 — Deduplication (5 minutes)
```
[ ] HackerOne Hacktivity searched: program + similar title/endpoint
[ ] GitHub issues searched; most recent 5 disclosed reports read
[ ] Not a known issue in changelog or public docs
[ ] Google: "TARGET_NAME ENDPOINT_NAME bug bounty"
```

### Gate 3 — Report Quality (10 minutes)
```
[ ] Title: [Bug Class] in [Endpoint] allows [actor] to [impact]
[ ] Steps to Reproduce: copy-pasteable HTTP request
[ ] Evidence: screenshot/video of actual impact (not a 200 status)
[ ] Severity matches CVSS AND program's definitions
[ ] Remediation: 1–2 sentences
[ ] Never used "could potentially" / "may allow"
```

### The 7-Question Gate (web/general) — all must be YES

Q1 exploit NOW with real PoC · Q2 impact on accepted list · Q3 root cause in in-scope asset · Q4 no unattainable privileged access · Q5 not known/accepted · Q6 impact proven beyond "technically possible" (downgrade, not kill, if only possible) · Q7 not a known-invalid class without a chain · **Q8 identity check** (session ID, identity, anonymous repro, cross-identity, stale-cred).

### The 7-Question Gate (smart contract track) — all must be YES

Q1 passing `forge test` on a fork · Q2 triggerer is not the intended actor (trusted-actor-only → kill unless governance bypass) · Q3 concrete protocol-native impact (exact wei/tokens/USD, named invariant) · Q4 in-scope version verified on-chain, not `lib/`/`interfaces/`/`mocks/`/`test/` · Q5 known-issue history searched · Q6 not on the always-rejected list · Q7 a DeFi-literate judge would say "yes, that's a real bug."

### Al-Mizaan v3 — 7 deep gates for borderline / complex findings

1. Code Reading — does the code actually execute the path? 2. Reachability Chain — map external entry → vulnerable op. 3. Threat Model — who can trigger; apply counter-patterns. 4. Invariant Breach — name the property. 5. Protocol Intent — bug or feature; "documented" requires reading upstream code. 6. Impact — quantify native harm; split self-harm; verify DoS recovery. 7. Formal Proof — PoC against realistic environment.

### KILL FAST rules

- 5-minute rule: can't fill Q1's template in 5 min → move on.
- More than 2 simultaneous preconditions → kill.
- "What does attacker walk away with?" — nothing tangible → kill.
- "Admin can do X" → kill immediately. Documented behavior → kill immediately.
- 30+ min on Q6 with no reproducible PoC → kill.
- Kill guard: `kill_lead()` refuses unless BOTH TRIGGER and IMPACT are refuted with evidence. One-half refutation = auto-park with a counted dismissal attempt.

### Anti-patterns that lose money

Writing a report before confirming the bug exists · theoretical impact without proof · "returns more fields than necessary" without showing sensitivity · chaining A+B into one report (two payouts lost) · reporting B as "similar to A" without fresh Gate 0 · overclaiming severity (triagers trust you less next time) · under-describing impact.

### The 60-Second Pre-Submit Check

```
[ ] Title follows formula
[ ] First sentence states exact impact in plain English
[ ] Steps have exact copy-paste HTTP request
[ ] Response showing the bug included
[ ] Two test accounts used
[ ] CVSS calculated and included
[ ] Fix is 1–2 sentences
[ ] No typos in endpoints/parameters
[ ] Report < 600 words
[ ] Severity matches impact
[ ] No "could potentially" / "may allow"
[ ] PoC reproducible from fresh state by a triager
```

---

## Real Impact Examples

### Scenario A — IDOR via /api/users/{user_id}/orders (two-account proof)
The endpoint does not verify that the authenticated user owns the requested `user_id`. Attacker account `attacker@test.com` (ID 123) requests `/api/users/456/orders` with their own Bearer token and receives `victim@test.com`'s full order history — email, shipping address, purchase history, payment last-4. No privileges beyond a free account. With ~100K users, automated iteration is a mass PII breach. Severity: 6.5 Medium (IDOR read PII). The report wins because it shows victim data in the attacker's session, not a 200 status — and because Expected (403) vs Actual (200 with data) is explicit.

### Scenario B — Missing auth on an unauthenticated internal listener (Path A vs Path B)
The control plane (Path A) requires a Bearer token for an operation; a daemon listener on the same host (Path B) accepts the equivalent operation over raw TCP with no credential. The absent-credential evidence grid shows no Authorization header, no token in `/proc/self/environ`, no cookie, no mTLS cert. Execution of `id` returns the same UID/GID as the SDK's privileged context (Demonstrated); host escape is explicitly **Unproven** and not claimed. The boundary crossed is the authorization barrier; the report states exactly what is NOT claimed and passes triage instead of being N/A'd for overreach.

### Scenario C — Open redirect alone → ATO chain (AB-chain writeup)
An open redirect is on the never-submit list. Chained to a vulnerable OAuth `redirect_uri`, it steals the authorization code and yields full account takeover. The report is titled for the ATO, proves every hop with a request/response pair, and demonstrates the chain is attacker-triggerable end to end. A separate "open redirect found" submission would have been N/A'd; a merged "similar to my other report" B submission would have been rejected for lacking a fresh Gate 0.

### Scenario D — Smart contract: config-driven critical, not a code bug
An audited vault reads clean. The critical is at Layer 1: the rate provider points at a manipulatable spot price instead of Chainlink, so the exchange rate can be shifted to steal share value — invisible from source, visible from live addresses + fork. The report names the broken invariant (`totalAssets() == Σ(balances valued via getRate())`), quantifies exact token amounts and USD, and ships a passing `forge test` on a fork. The Q2 trap ("onlyOwner can set the provider") is defeated by showing the deployer deliberately configured the wrong feed — a trusted-actor misconfiguration with real exploitable impact.

### Scenario E — A rejected finding revived by an honest-path counter-pattern
A triager pushes back: "requires oracle misreport." Before accepting the kill, the researcher checks the honest data path and finds the same vulnerable state is reachable with legitimate oracle values (the Lido `onchainTotalValueOnRefSlot` pattern). The finding stands without the oracle caveat. This is why the anti-refutation counter-patterns are part of triage craft, not optional reading.

### Scenario F — Cache poisoning → stored XSS on a login page (PayPal pattern)
A cache layer stores a poisoned response for `paypal.com/signin`, reflecting attacker-controlled input into a script context. The report demonstrates the poisoned response being served to a second, unrelated session — not just the attacker's own view — and shows script execution in the victim's browser. The escalation line "equivalent to a full data breach of the login flow" is backed by a recorded response and a two-session reproduction, which defeats the "only affects you" rebuttal. Severity anchors at High/8.8 (stored XSS, scope changed to browser).

### Scenario G — SSRF DNS-only vs full-read (severity calibration)
An endpoint fetches a user-supplied URL. A callback to a controlled listener proves the request leaves the server — but that alone is on the never-submit list. The researcher goes further: fetches a target with a known recognizable body, sees the body returned (full-read), then body-diffs a link-local address against a public one and observes a distinct status from the metadata service. The report claims full-read SSRF to cloud credentials (Critical/9.1), not "blind SSRF," and includes the negative-control parameters that produced no callback. Correct calibration and attribution are what make the claim stick.

### Scenario H — Missing-auth vs IDOR vs permissions issue (identity discipline)
A researcher finds that changing an ID returns another user's data. Running Q8 in both directions reveals the request works with *no* authentication header at all — so the correct report is "missing authentication on `/api/resource/{id}`," not IDOR. A separate case only reproduces under one identity in one direction, so it is parked as a scoped permission boundary, not killed (one-half refutation) and not reported. Naming the bug correctly is the difference between a paid High and a N/A'd misclassification.

### Scenario I — HackenProof Need-more-info reversed with evidence
A report is set to Need more info because no commit/version evidence is attached. The researcher supplies `get_program_info`-matched scope, a concrete commit hash, the readable PoC attachment, and a short note that no equivalent duplicate exists. All four pre-validation gates now pass and the report moves to Triaged. The lesson: most "Need more info" outcomes are fixable with artifacts, not arguments — keep the PoC, commit evidence, and repro steps ready before submission.

---

## Source Skill Lineage

39 curated source skills fed this document. The full corpus (335 unique sections) is archived at `references/source-knowledge.md`. Every path below is a source-file citation — no HackerOne IDs or URLs are fabricated here. Grouped by family with each file's unique contribution.

### Family 1 — BountyForge Core Reporting & Validation

- `hunt-skills/bountyforge/references/reporting.md` — Canonical defensive-proof report format; Scope & Engagement Gate; absence-of-credential and demonstrated-vs-inferred grids; H100 high-value target profiles; always-rejected and conditionally-valid-chains tables; confidence scoring; platform adaptations.
- `hunt-skills/bountyforge/references/validation.md` — 5-layer smart-contract reasoning priority; 7-Question Gate + 10 Red Team Attack Questions; HUNT-vs-REPORT wild-mode rule; Al-Mizaan v3 gates; HackenProof workflow; Immunefi paid patterns; CVSS 3.1 guide.
- `hunt-skills/bountyforge/skills/report-writing/SKILL.md` — "Most Important Rule" (no hedging); title/impact formulas; full multi-platform report templates; CVSS metric picks; severity self-assessment; downgrade counters; 60-second checklist; CVSS 4.0 reference; human-tone guidelines.
- `hunt-skills/bountyforge/skills/triage-validation/SKILL.md` — Q1–Q8 web gate incl. identity check; SC-track gate; counter-patterns; Gate 0–3; NEVER SUBMIT / CONDITIONALLY VALID tables; kill-fast and anti-pattern rules.
- `hunt-skills/bountyforge/wiki/Lead Ledger.md` — Lead lifecycle (OPEN→MUTATING→FINDING / PARKED / KILLED); Two-Question Rule (TRIGGER/IMPACT); one-variable mutation; missing-precondition tracking; kill guard.

### Family 2 — HackenProof Triage Marketplace

- `hunt-skills/bountyforge/skills/hackenproof-triage-marketplace/SKILL.md` — Strict 12-step tool sequence; 4 pre-validation gates (commit/version, scope, duplicate, PoC); decision rules; quality bar (prefer reversible Need-more-info).
- `hunt-skills/bountyforge/skills/hackenproof-triage-marketplace/references/hackenproof-global-policy.md` — Rule priority (program overrides global); program-type→classification mapping; web/mobile, smart-contract, blockchain severity baselines and out-of-scope lists.
- `hunt-skills/bountyforge/skills/hackenproof-triage-marketplace/references/severity-mapping.md` — Generic impact→severity baseline with raise/lower adjustments; anchor to demonstrated impact.
- `hunt-skills/bountyforge/skills/hackenproof-triage-marketplace/references/triage-comment-templates.md` — Evidence-based responder templates for Triaged / Need more info / Out of scope / Duplicate.

### Family 3 — BountyForge Smart-Contract Audit (false-positive case files)

Time-unit & CPI:
- `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-11-state-management/fv-anc-11-cl5-time-unit-mismatch-in-deadline-validation.md` — Unique: seconds-vs-slot deadline confusion; FP guard = single consistent time source + documented field units.
- `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-5-cross-program-invocation-cpi/fv-anc-5-cl1-lack-of-validation-of-external-program-before-cpi.md` — Unique: dynamic CPI program ID substitution; FP guard = typed CPI helpers / address-constrained target.

Account-ownership validations (fv-anc-3):
- `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl1-trying-to-modify-an-account-without-checking-if-its-writeable.md` — Unique: mutation without writability check; FP = CPI enforces writability / read-only deserialize.
- `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl2-trying-to-access-account-data-without-ownership-checks.md` — Unique: raw borrow without owner verification; FP = typed `Account<'info,T>` auto-enforces ownership.
- `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl3-usage-of-uncheckedaccount-without-manual-ownership-check.md` — Unique: `UncheckedAccount` bypasses Anchor checks; FP = address-constrained or executable program account.
- `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl4-usage-of-uncheckedaccount-without-manual-signer-check.md` — Unique: authority without `is_signer`; FP = PDA-seed authorization / key-constrained account.
- `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl5-no-is_initialized-check-when-operating-on-an-account.md` — Unique: operating on uninitialized account; FP = `#[account(init)]` guard / documented re-init.
- `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl6-missing-account-constraints.md` — Unique: missing `has_one`/`constraint`/`address`; FP = equivalent `require!` or structurally impossible relation.
- `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl7-duplicate-mutable-accounts.md` — Unique: same account passed for two `mut` fields; FP = no-op self-transfer guard / distinct constant seeds.
- `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl8-using-ctx.remaining_accounts-without-manual-ownership-check.md` — Unique: raw remaining accounts forwarded to CPI; FP = immediate PDA derivation check / lamport-only reads.
- `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl9-using-ctx.remaining_accounts-without-manual-discriminator-check.md` — Unique: type cosplay via discriminator absence; FP = external fixed-structure account / address constraint.
- `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl10-using-ctx.remaining_accounts-without-non-zero-data-check.md` — Unique: zero-data account deserialized as zero-value struct; FP = zero is intended initial state / init before read.
- `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl11-no-reload-after-account-mutation.md` — Unique: stale in-memory read after `load_mut`/CPI; FP = separate instructions / single final write.
- `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl12-not-validating-a-set-address.md` — Unique: arbitrary treasury/authority address set; FP = on-chain PDA derivation / fixed value set.
- `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl13-init-if-needed-without-reinit-guard.md` — Unique: pre-created PDA with malicious state; FP = ATA ownership enforced / explicit no-op guards.
- `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/fv-anc-3-cl14-realloc-without-zero-init.md` — Unique: stale bytes from expanded realloc; FP = shrinking alloc / all new bytes overwritten.
- `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-3-account-ownership-validations/readme.md` — Unique: case-file index for the ownership-validation family (how to navigate the reference set).

System-account validation (fv-anc-8):
- `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-8-system-account-validation/fv-anc-8-cl1-unvalidated-sysvar-address.md` — Unique: substituted sysvar; FP = typed `Sysvar<>` wrappers / `Clock::get()`.
- `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-8-system-account-validation/fv-anc-8-cl2-instruction-introspection-using-absolute-index.md` — Unique: prepend-instruction index shifting; FP = iterate-and-match by program ID instead of absolute index.
- `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-8-system-account-validation/fv-anc-8-cl3-address-lookup-table-signer-forgery.md` — Unique: ALT position-based spoofing; FP = key comparison over positional trust.
- `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-8-system-account-validation/fv-anc-8-cl4-durable-nonce-transaction-ordering-attack.md` — Unique: withheld signed tx replayed under favorable conditions; FP = Clock-window expiry check / single-use nonce.
- `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-8-system-account-validation/readme.md` — Unique: case-file index for the system-account-validation family.

All 32 explicit source paths in the condensed digest are accounted for above. The remaining curated files from the 39-source set, plus all 335 original sections, are preserved in full at `references/source-knowledge.md`.

Triager mandate:
- `hunt-skills/bountyforge/skills/smart-contract-audit/triager.md` — Unique: Customer Validation Expert / budget-protection persona; cross-reference validation, technical/economic disproof, and DISMISSED / QUESTIONABLE / RELUCTANTLY VALID verdicts.

### Corpus Note

The condensed digest contains 32 explicit `## SOURCE:` headers; the full 39-file corpus (335 unique sections) is preserved at `references/source-knowledge.md`. No external report identifiers or URLs were invented — all citations above are source skill paths.

---

## Related Skills & Chains

- **`report-writing`** — this skill consumes its canonical templates, title/impact formulas, CVSS tables, and the Most Important Rule. Load for the platform-specific submission skeleton.
- **`triage-validation`** — compact form of the Q1–Q8 gate and NEVER SUBMIT / CONDITIONALLY VALID tables; use as the fast pre-submit gate.
- **`bountyforge` / `hunt-skills/bountyforge/references/validation.md`** — supervisor detail: 5-layer smart-contract reasoning, Red Team Triage Engine, Al-Mizaan v3 gates.
- **`hackenproof-triage-marketplace`** — platform triage workflow, tool sequence, global policy baseline, and comment templates.
- **`lead-ledger` / `trust-map`** — persistent lead objects (TRIGGER/IMPACT), missing-precondition tracking, kill guard, and trust/identity scoring across sessions.
- **`a-b-chains`** — chain construction and writeup patterns for reviving rejected classes (open redirect → ATO, SSRF DNS-only → data, self-XSS → stored).
- **`vuln-classes`** — canonical bug-class definitions and severity mappings referenced by the accepted-impact list.
- **`security-arsenal`** — payload/detection harnesses (Collaborator, interactsh, Foundry) referenced by the PoC evidence checklist.
- **Hunt skills (`hunt-ssrf`, `hunt-rce`, `hunt-cloud-misconfig`, `hunt-llm-ai`, `cloud-iam-deep`)** — upstream primitives; this skill is the final gate they all feed into. Chain primitive: any demonstrated primitive → this skill's Gate 0 → canonical report → triage rebuttal → paid finding.

---

## Summary

`hunt-reporting-triage` is the definitive from-finding-to-paid-report skill. It front-loads scope and impact gates, demands demonstrated (never inferred) evidence with two-account and absent-credential grids, calibrates severity with CVSS 3.1/4.0 and program baselines, kills false positives with the curated anchor case files, and counteracts triage pushback with a tested downgrade-counter and anti-refutation playbook. It covers Bugcrowd/HackerOne/Intigriti/Immunefi/HackenProof submission craft, AB-chain writeups, lead/trust ledgers, and the full 39-source lineage — with the complete corpus at `references/source-knowledge.md`. The governing discipline: if it cannot survive the strongest plausible triager objection, it is a lead, not a report.
