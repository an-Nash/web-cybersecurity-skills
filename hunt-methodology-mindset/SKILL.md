---
name: hunt-methodology-mindset
description: Cross-cutting META-SKILL for how to run an engagement and how to think while hunting. Distilled from 99 curated source skills (1,809 unique sections) covering bug-bounty workflow, dispatch/start-here routing, redteam mindset, trust-first hunting foundation, exceptional conditions, misc, security arsenal, wild mode, OSINT-to-hunting handoff, scope/triage, evidence, report writing, and chaining. Use at the START of every hunt session — before any hunt-* skill loads — to lock engagement mode, pick a goal, build the trust map, and set the discipline gates. All other hunt-* skills point here as their orchestration and validation backbone.
sources: github, bountyforge_repo, bountyforge_wiki, internal_engagement_notes
report_count: 0
full_reports_read: 0
source_skills: 99
---

> **What this skill is.** This is the "how to run an engagement / how to think" layer of the hunt library. It does not teach a single bug class — it teaches the orchestration, mindset, and validation discipline that every `hunt-*` skill assumes. Load it once at session start, keep it as the active frame, and defer to class-specific skills only after Phase 0 (mode confirmation) and Phase 2 (mapping) are done.
>
> **Grounding.** Every rule below is distilled from the 99 curated source skills listed in [Source Skill Lineage](#source-skill-lineage). The complete 1,809-section corpus is archived at `references/source-knowledge.md`. No HackerOne IDs or report URLs are fabricated here — contributions are cited by **source skill path** only.

---

## Crown Jewel Targets

This meta-skill targets the *engagement*, not a single asset. The "crown jewels" are the surfaces and moments where methodology determines whether a session pays or wastes 30 hours.

- **The engagement-mode decision (before anything else).** Bug bounty vs red team vs WAPT vs internal audit changes what counts as a finding. Getting this wrong is the single biggest waste of time in the whole workflow — the same target produces a different report shape depending on the mode. Write the mode as the first line of your hunt notes, or ASK once if it is not in the instruction. *(hunt-skills/bb-methodology/SKILL.md — PART 0)*
- **Trust boundaries.** Every vulnerability is a trust violation — the system trusted identity, state, input, or intent it should not have. High-impact bugs live at trust-boundary crossings (outside node → inside node over a `no_auth` / `header_based` / `ip_based` / `internal_skip` edge). *(hunt-skills/bountyforge/references/methodology.md — P2 Trust Map)*
- **The five pillars of map state.** Asset, Trust, Authorization, State, Capability maps (`asset.md`, `trust.md`, `authz.md`, `state.md`, `capability.md`, plus `invariants.md` for contract hunts). No map → no hunt. An endpoint that is not located in a map is not yet a target. *(hunt-skills/bountyforge/references/methodology.md)*
- **Identity/auth flows and role hierarchies.** Invitation links, password reset, SAML SSO, OAuth token scopes, org member/admin/service ladders — the `?` cells of the authz matrix are where IDOR/BOLA, privilege escalation, and tenant-isolation bugs emerge. *(hunt-skills/hunt-misc/SKILL.md; methodology.md — P3 Identity Map)*
- **State machines and money/authority capabilities.** Deposits, withdrawals, refunds, transfers, coupons, approvals, verification, deletion, recovery — capabilities with impact verbs have enormous bug density versus ordinary CRUD. Attack the *illegal* transitions. *(methodology.md — P4/P5)*
- **Error paths and exceptional conditions.** Well-built apps return a clean generic message; a broken app renders a developer error page with stack traces, ORM internals, file paths, and versions. That disclosure is the finding, and it arms SQLi/RCE/path attacks next. *(hunt-skills/hunt-exceptional-conditions/SKILL.md)*
- **Legacy and forgotten surface.** Deprecated APIs, legacy subdomains, v1 endpoints behind a v2, zombie APIs, debug/staging environments, cached URLs, archived forms — "old code is new attack surface." *(hunt-skills/hunting/SKILL.md — Golden Rule 7)*
- **The target's own platform weapons.** Webhooks, error messages, caches, rate limits, recovery flows, integrations, docs, and (for contracts) fallback/proxy/pause/fee functions. The most rate-limited endpoint is the most valuable target. *(hunt-skills/bountyforge/references/wild-mode.md — Rule 5)*
- **The report gate.** The moment a candidate becomes a submission. Gate 0 kills or confirms; a half-proven lead is never a kill. *(hunt-skills/bountyforge/references/judging.md; al-mizaan-gates.md)*

**Highest-value outcome:** an impact-demonstrated chain with a reproducible PoC, written in the platform's format, under 600 words, with a CVSS score that matches actual impact. Everything in this skill exists to make that outcome reliable.

---

## Attack Surface Signals

### Engagement-Mode Signals (read the scope language first)

| Signal in the scope / SOW | Mode to lock | Discipline |
|---|---|---|
| "in-scope assets" + "out-of-scope assets" + "safe harbor" | Bug bounty | Validation-heavy, OOB-required, no exfil |
| "kill chain" + "objectives" + "flag capture" + "adversary emulation" | Red team | Stealth, persistence, lateral movement valid |
| "compliance" + "PCI" + "HIPAA" + "executive report" + "remediation timeline" | WAPT | Coverage-driven, all findings count regardless of exploitability |
| Mixed / ambiguous language (common — WAPT-shaped SOWs called "red team") | **Default to bug bounty** | Most validation-strict mode; relax only on confirmation |

*(hunt-skills/bb-methodology/SKILL.md — PART 0 + Operator Notes)*

### Platform / Fingerprint → Skill Routing Signals

Fingerprint **every** live host with `curl -sSL` (follow redirects — IdP and CDN signals sit behind 30x; framework markers like `__NEXT_DATA__`, `VIEWSTATE`, `laravel_session` live in the body). Then map:

```
okta.com | auth0.com | pingidentity          →  okta-attack
login.microsoftonline.com | outlook | sts    →  m365-entra-attack
pulse | fortinet | ivanti | citrix           →  enterprise-vpn-attack
vsphere | vcenter | :9443                    →  vmware-vcenter-attack
amazonaws | azure | googleapis | gcp         →  cloud-iam-deep
github.com/<org>/                            →  supply-chain-attack-recon
.apk | play.google.com                       →  apk-redteam-pipeline
MongoDB | mongoose | CouchDB | Redis         →  hunt-nosqli
?page= | ?file= | ?path= | php wrapper       →  hunt-lfi
rO0A | VIEWSTATE | rememberMe cookie         →  hunt-deserialization
Access-Control-Allow-Origin header           →  hunt-cors
/forgot-password | /reset | X-Forwarded      →  hunt-host-header
?redirect= | ?next= | ?return= | ?url=       →  hunt-open-redirect
OTP | /verify | /2fa | no-rate-limit         →  hunt-brute-force
Set-Cookie session | PHPSESSID               →  hunt-session
Active Directory | LDAP | OpenLDAP | ADFS    →  hunt-ldap
__NEXT_DATA__ | /_next/ | buildId            →  hunt-nextjs
X-Powered-By: Express | Node.js | .js stack  →  hunt-nodejs
postMessage | dangerouslySetInnerHTML        →  hunt-dom
WebSocket | ws:// | socket.io                →  hunt-websocket
gRPC | :50051 | application/grpc             →  hunt-grpc
laravel_session | Ignition | Telescope       →  hunt-laravel
X-Application-Context | Whitelabel|/actuator →  hunt-springboot
:6443 | :10250 | :2379 | kubectl             →  hunt-k8s
.github/workflows | Jenkins | GitLab CI      →  hunt-cicd
.js.map | swagger.json | /.env               →  hunt-source-leak
HSTS missing | SPF | DMARC | AXFR            →  hunt-tls-network
```

**Load budget:** cap platform-skill loads at 8, in tier order (identity/SSO → perimeter → cloud/IAM → framework → protocol/class); print dropped matches under `deferred:`. CDN banners alone are edge fingerprints, not platform matches. *(hunt-skills/hunt-dispatch/SKILL.md — step 1)*

### Tactical Pattern-Detection Signals

| Anomaly | What it means |
|---|---|
| `userId` everywhere but suddenly `user_id` | Different dev, weaker security |
| Same 403 but different JSON structure | Different backend systems |
| Prod vs Dev/Staging | Debug headers, CSP disabled |
| JS file before/after update | New endpoints, removed params |
| Framework/library versions | Check for known CVEs |
| Stripe/Auth0/Intercom | Webhook signature missing? |
| 400 vs 404 / 415 vs 403 / 400 vs 403 | Existence oracle / parser differential / authz-bypass potential |
| Body validation before authz | Manipulate body to bypass the authz check |
| Two hosts, same app, different soft-404 sizes | Re-derive the baseline per host and per path depth |

*(hunt-skills/bountyforge/references/web-hunting-playbooks.md — Scoping-Order Analysis; hunt-skills/bb-methodology/SKILL.md — Tactical Thinking; hunt-skills/bountyforge/wiki/Wild Mode.md — Pattern Detection)*

### Discovery Signal → Phase Routing

| What you find | Next action |
|---|---|
| Live subdomains with tech stack | Phase 2 (Mapping) |
| Known software (WordPress, Jira) | Check CVEs + defaults immediately |
| Cloud resources (S3, Firebase) | Test permissions (read/write/list) |
| Nothing after 5 min on a host | Skip, try next host (5-minute rule) |
| JS files with interesting code | Taint analysis (Sink → Source) |
| OAuth/SAML authentication | OAuth/SAML checklist |
| API with ID parameters | Phase 3, target IDOR |
| Complex business logic (payment, coupon) | Phase 3, target business logic |
| Blocked by WAF/CSP/403 | Bypass techniques, then retry |
| Found one bug | A→B signal: hunt 20 min for siblings |

---

## Discovery Patterns From Curated Source Skills

### Where Researchers Start

1. **Mode confirmation, then the 404 baseline.** Before enumeration, run the cheapest false-positive kill in the toolkit: two bogus paths per host, record **status, byte length, body hash**. No path is "found" until its response differs from the control. A 200 matching the control hash is a soft 404. Re-derive per host and per path depth. Edge pages (CDN "Access Denied") are not origin findings. *(hunt-skills/hunt-dispatch/SKILL.md — step 0)*
2. **Wide recon sweep for new/wildcard scope:** subdomain enum → DNS resolution → HTTP probing → port scan → tech detect. Tool order: `subfinder` → `amass` → `puredns` → `httpx`; URLs via `gau` + `waymore` → `katana` → `uro`; JS via `jsluice` + `trufflehog --only-verified`. *(bb-methodology/SKILL.md — Phase 1 + Tool Routing)*
3. **OSINT-to-hunting handoff:** Phase 1's wide approach delegates to `offensive-osint` for the asset arsenal and `web2-recon` for the live-host + URL pipeline. Asset discovery IS the deliverable on wide external red-team engagements (40% of time); on defined-scope SaaS it should be ~10%. *(bb-methodology/SKILL.md — Related Skills + Operator Notes)*
4. **Start-here question — "Understand Before You Attack."** Spend the first 15–20 minutes mapping roles, sensitive actions, and API requests in Burp. Good recon is not hundreds of URLs — it is understanding how the application actually works. The best bugs come from business logic, not the biggest wordlist. *(hunt-skills/hunting/SKILL.md — Tip #5)*
5. **Deep recon for a single interesting host:** Google dorks → JS file download → hidden-param discovery → API mapping. Manual per-target dorks find what automation misses. *(bb-methodology/SKILL.md — Phase 1 deep approach)*
6. **Pick a goal per session.** Define one CIA/ATO/RCE target and 1–2 vuln classes, then execute only those techniques. "Just looking around" is wasted time. Route A = feature-based ("this feature is complex, deep-dive its input handling"); Route B = vuln-based ("I want IDOR, find endpoints with sequential IDs"). *(bb-methodology/SKILL.md — Phase 0)*
7. **Two accounts before authz testing.** IDOR needs attacker A and victim B. Burner identities from disposable email/phone services, never real accounts. Check greybox creds with a single `/api/me` preflight before fanning out authenticated tests (live / role / not-MFA-gated). *(web-hunting-playbooks.md — IDOR; hunt-dispatch/SKILL.md — greybox preflight)*

### Feature-Based Discovery Signals

- **Map all endpoints** (Burp/Caido sitemap + JS analysis), auth model (cookie/JWT/OAuth/SAML), business-critical flows (payment, registration, reset, export), roles/permissions, and "weird" anomalies. *(bb-methodology/SKILL.md — Phase 2)*
- **Write the five maps before probing** (asset, trust, authz, state, capability). The `gaps[]` column in P1 is the money column: same functionality with different auth/validation/versions = a lead. P3's `?` cells = the authz bugs. P4's illegal transitions = state bugs. P5's impact verbs = where the money is. *(methodology.md — P1–P5)*
- **Run the five questions on every feature:** Who is allowed? What does the server trust from the client? What if I change identity/object/state? What if I do it twice/concurrently? Can I chain it into money/data/privilege? *(methodology.md — The 5 Questions)*
- **Write every hypothesis as an intersection:** `identity × object × state × boundary × interface` (contracts: `IDENTITY × ASSET × STATE × PRICE × AUTHORITY × TRUST BOUNDARY × CALL GRAPH × TIME`). Not "an interesting endpoint." *(methodology.md — Intersection Formula + Web3 intersection)*
- **URL/param patterns that route to a class:** `?url= ?uri= ?endpoint= ?redirect= ?src= ?file= ?path= ?callback=` (SSRF/LFI/open redirect); `/api/v*/repos/*/lfs/*`, `/invitations/*`, `/-/settings/integrations/*`, `/reset-password?token=`, `/auth/saml/callback` (misc/IDOR/auth); `?page=`, `?quantity=`, `/item/{id}` (exceptional conditions). *(web-hunting-playbooks.md; hunt-misc/SKILL.md; hunt-exceptional-conditions/SKILL.md)*
- **The "Everywhere" and "Edge Case" principles:** test every parameter/endpoint/state/platform/combination; default values (`0000`, empty, null), boundaries (max/zero/negative/`0x7fffffff`), type confusion, encoding, timing. *(hunt-skills/hunting/SKILL.md)*
- **Error-first probing ladder:** send `'` / `"` / `{{7*7}}` / `${7*7}` → watch for 500s and stack traces; then time-based (`SLEEP(10)`), then OOB (interactsh), then boolean (`AND 1=1` vs `AND 1=0`). *(bb-methodology/SKILL.md — Phase 3)*

### Verbatim Hunter Clues

Direct lines from the curated source skills — treat these as working doctrine, not slogans:

> "Hunting is not 'find a bug' -- it is 'prove an attack scenario.' Think like an attacker with a specific goal, not a scanner looking for patterns." — `hunt-skills/bb-methodology/SKILL.md`

> "Map trust first. Hunt violations second." / "No trust map → no hunt." — `hunt-skills/bountyforge/references/methodology.md`

> "The API is the product. UI is a suggestion. Test endpoints, not pages." / "Every ID is a question: 'do you own this?'" / "Every redirect is a weapon" / "Every input is code" / "Client state is a lie" / "Side effects leak" / "Chain relentlessly" — `hunt-skills/hunting/SKILL.md — Golden Rules`

> "You are not a reviewer. You are a cheater. Every target is a machine with rules... The machine is never your judge." — `hunt-skills/bountyforge/references/wild-mode.md`

> "Strictness is for the report. The hunt has no ceilings. Generate the payload. Fire it. Read the 'no'. Chain the yeses." — `hunt-skills/bountyforge/references/wild-mode.md — Summary`

> "Payload-first. Every lead gets a weapon immediately." / "NO CEILINGS. Nothing is 'too unlikely' or 'too obvious.'" / "CHAIN OR DIE. Nothing reports alone." / "FAILURE IS DATA. The engine's 'no' is a fingerprint." — `hunt-skills/bountyforge/references/wild-mode.md — Rules 1,2,6,7`

> "Every response is a leak. 403 on one endpoint vs 404 on another maps the internal routing." — `hunt-skills/bountyforge/references/wild-mode.md — Rule 7`

> "What does the ENGINEER believe that I know is false?" — `hunt-skills/bountyforge/references/wild-mode.md — Cheat Question 7`

> "Automation finds mutations. Humans find assumptions. The maps tell you where to look; wild-mode tells you to never stop looking." — `hunt-skills/bountyforge/references/methodology.md — Summary`

> "A 403 often means another HTTP method might work... Sometimes a 403 is the beginning of the bug — not the end." — `hunt-skills/hunting/SKILL.md — Tip #4`

> "Documentation is aspirational; code is authoritative." / "Read the actual HTTP response/JavaScript, not the API docs." — `hunt-skills/bountyforge/references/al-mizaan-gates.md — Gate 1`

> "The discipline rules are about correctness of findings — not throttling of effort... Coverage discipline and finding-correctness discipline are orthogonal axes; you need both on full." — `hunt-skills/bb-methodology/SKILL.md — PART 4 framing`

### Probe Checklist

**Phase 0 — start**
- [ ] Engagement type written as first line of notes (bug bounty / red team / WAPT / internal audit)
- [ ] Goal defined: target `[feature/domain]` to achieve `[C/I/A/ATO/RCE]`
- [ ] 1–2 vuln classes selected; no wandering
- [ ] Route chosen: wide (new program / wildcard / scope update) or deep (>3 days / interesting subdomain)
- [ ] Authorized host list captured verbatim as data for any subagent

**Phase 1–2 — recon & mapping**
- [ ] 404 baseline recorded per host (status, byte length, body hash) and per path depth
- [ ] Every live host fingerprinted with `-L`; body markers captured; tier-cap ≤8 platform skills loaded
- [ ] Five maps created (`asset.md`, `trust.md`, `authz.md`, `state.md`, `capability.md`)
- [ ] Endpoints, auth model, roles, business flows, JS files, anomalies enumerated
- [ ] Greybox creds preflighted (live / role / not MFA-gated) before authenticated tests

**Phase 3 — discovery (per feature)**
- [ ] Five questions run; hypothesis written as an intersection with a map path
- [ ] Error-based → time-based → OOB → boolean ladder attempted
- [ ] Two accounts created; every endpoint replayed with swapped IDs and all verbs
- [ ] Illegal state transitions and "twice/concurrently" tests attempted
- [ ] Target's own platform weapons inventoried (webhooks, errors, cache, rate limits, recovery, docs)
- [ ] Nothing after 20 min on one endpoint → rotate; 45 min on one param → STOP (rabbit hole)

**Phase 4–5 — prove & report**
- [ ] Chain partners sought (read+write, low+low, sibling endpoints)
- [ ] 0–1 click prerequisite; affected role and business $ impact stated
- [ ] Critical/High reproduced in ≥2 independent tools, commands paste-into-shell ready
- [ ] Gate 0 passed (all gates below); report under 600 words, impact-first, matching CVSS
- [ ] Screenshots/HARs handed to `evidence-hygiene` before any cookie/PII appears

### Non-Linear Navigation Quick Reference

| I'm stuck because... | Go to... |
|---|---|
| Can't find any subdomains | Phase 1: different recon sources, Google dorks |
| Found subdomain but don't know what to test | Phase 2: map the app, download JS, understand auth |
| Testing but nothing works | Phase 3: switch vuln class (20-minute rotation rule) |
| Found a bug but impact is low | Phase 4: escalation paths or gadget chaining |
| WAF/CSP/403 blocking my payload | Bypass techniques, then return to current phase |
| Been stuck 45 min on one param | STOP. Rabbit hole. Move to the next endpoint. |
| New API discovered during testing | Return to Phase 2: map it before attacking |
| Found one bug | A→B signal: hunt 20 min for siblings |

*(hunt-skills/bb-methodology/SKILL.md — Non-Linear Navigation Quick Reference)*

---

## Step-by-Step Hunting Methodology

### The 5-Phase Non-Linear Flow

```
   +----------+    +----------+    +----------+
   | 1. RECON |---+| 2. MAP   |---+| 3. FIND  |
   +----------+    +-----+----+    +-----+-----+
        ^                |               |
        |                v               v
        |          +----------+    +----------+
        +----------| 4. PROVE |---+| 5. REPORT|
                   +----------+    +----------+
   NON-LINEAR: stuck at any phase -> go back one.
   New API at phase 3 -> return to phase 2. WAF at phase 4 -> origin IP from phase 1.
```
*(hunt-skills/bb-methodology/SKILL.md — The 5-Phase Non-Linear Flow)*

This is not a sequence to traverse uniformly. If you find a Critical in the first 30 minutes of recon, stop reconning, validate it, report it, then return. If recon is the work (200-asset financial parent org), spend 80% of the engagement there. If you have been hunting a candidate for 4+ hours and it will not reproduce on a second account, the candidate is dead — drop it, document the retraction, move on. *(bb-methodology/SKILL.md — Operator Notes)*

### Amateur vs Pro — The 7-Phase Comparison

| Phase | Amateur | Pro |
|---|---|---|
| Recon | Main domain only | Shadow IT, dev environments, all assets |
| Discovery | Look for errors | Look for design contradictions, business logic flaws |
| Exploit | Give up when blocked | Build filter-bypass payloads |
| Escalation | Report the phenomenon only | Chain to real harm (session steal, ATO) |
| Feasibility | Include unrealistic conditions | Minimize attack prerequisites |
| Reporting | State facts only | Quantify business risk |
| Retest | Check if the old PoC fails | Analyze the fix method, find the incomplete patch |

*(hunt-skills/bb-methodology/SKILL.md — Amateur vs Pro)*

**Two approach routes:** Route A (feature-based) — "this feature is complex" → deep-dive its input handling → find the vuln. Route B (vuln-based) — "I want IDOR" → find endpoints with sequential IDs → test access control. Pick one per session; do not drift between them. *(bb-methodology/SKILL.md — Two Approach Routes)*

### Phase Priority Shifts by Target Type

The five phases are not equal-weight. Engagement type dictates time allocation:

| Engagement | Recon | Hunt | Validate + Report |
|---|---|---|---|
| SaaS bug-bounty (defined scope) | 10% | 70% | 20% |
| External red-team (wide scope) | 40% | 30% | 30% |
| WAPT (asset list provided) | 0% | 60% | 40% |
| Enterprise on-prem (single product) | 5% | 50% | 45% |

Spending 50% of a SaaS bug-bounty engagement in recon is procrastination; spending 10% of an external red-team engagement in recon means you already lost — the attack-surface map *is* the deliverable there. *(bb-methodology/SKILL.md — Operator Notes)*

### The 11-Step Trust-First Hunt Loop

Run iteratively, not linearly — cycle until impact is proven or the surface is exhausted:

1. **MAP TRUST ENDPOINTS** — identity, input, state, service, user trust. Output: `maps/trust.md`. *(methodology.md)*
2. **OBSERVE** — send benign requests, map error behaviors, timing differences, anomalies. Build a model of what the developer *believed*.
3. **MODEL THE SYSTEM** — which endpoints are external vs internal, auth vs open, what data flows connect them, what assumptions each boundary makes. Update the five maps.
4. **GENERATE HYPOTHESES** — for each boundary: "What if this trust is misplaced?" Every hypothesis must name the trust violation it exploits.
5. **RANK BY INFORMATION GAIN** — identity trust > input validation; ATO/RCE/financial > info disclosure; one request > multi-step; untested > tested; connects-to-leads > isolated. Test the highest-gain hypothesis first.
6. **TEST MINIMALLY** — one request, one parameter change, no complex tooling. The goal is signal, not proof.
7. **INTERPRET RESPONSE** — confirmed → chain/validate; contradicted → note the lesson; ambiguous → mutate one variable; blocked → try one bypass then rotate.
8. **GENERATE NEW HYPOTHESES** — "if endpoint X has no auth, maybe sibling Y doesn't either." This is where chains emerge.
9. **CHAIN PRIMITIVES** — read + write = ATO; SSRF + internal discovery = RCE; IDOR + mass assignment = privesc; open redirect + OAuth = token theft. Two lows = one high.
10. **VALIDATE IMPACT** — Q-TRIGGER and Q-IMPACT both proven? FINDING. One? OPEN LEAD. Neither? KILL (with evidence).
11. **KILL / ESCALATE / REPORT** — kill with evidence, escalate by chaining, or report with a map path.

*(hunt-skills/bountyforge/references/methodology.md — The Hunt Loop)*

### Phase Execution Detail

**Phase 1 — RECON:** maximize attack surface. Wide: subdomain enum → DNS → HTTP → ports → tech. Deep: dorks → JS → hidden params → API map. Known software → CVEs + defaults immediately. Cloud assets → permission tests. 5-minute rule per host. *(bb-methodology/SKILL.md)*

**Phase 2 — MAPPING:** understand the app like its developer. Check endpoints, auth model, business flows, JS, roles, anomalies. JS with interesting code → taint analysis (Sink → Source). New API discovered later → return here. *(bb-methodology/SKILL.md)*

**Phase 3 — FIND:** input → class decision:

```
ID parameter (user_id, order_id) ......... IDOR checklist
Search/filter/sort field ................. SQLi, NoSQLi
URL input / webhook / PDF gen ............ SSRF checklist
Text field reflected in page ............. XSS (DOM or reflected)
File upload .............................. SVG XSS, web shell, path traversal
Price/quantity/coupon .................... Business logic, race conditions
Login / 2FA / password reset ............. Auth bypass
Profile update API ....................... Mass Assignment
Template / wiki editor ................... SSTI
Nothing obvious .......................... ffuf, error-based probing
```
*(bb-methodology/SKILL.md — Phase 3 decision flow)*

**Phase 4 — PROVE & ESCALATE:** XSS → cookie/token theft → ATO (HttpOnly? force email change; self-XSS? find CSRF). IDOR → automate scraping / change password → ATO (UUID? find the leak source). SSRF → DNS-only? don't report, try metadata; reach `169.254.169.254`? keys → RCE. SQLi → extract / INTO OUTFILE → web shell. Open redirect → OAuth token theft → ATO, or `javascript:` → XSS. *(bb-methodology/SKILL.md — Phase 4)*

**Phase 5 — VALIDATE & REPORT:** run the 7-Question Gate. Any fail → kill the finding (or demote to LEAD in wild mode). Borderline → Al-Mizaan deep validation. Then platform-specific report, impact-first summary, exact HTTP requests, <600 words, matching CVSS. After submission: escalate while waiting; re-test fixed bugs for incomplete patches; record with `/remember`. *(bb-methodology/SKILL.md — Phase 5)*

### Time & Rotation Rules

- **5-minute rule** — no signal on a surface after 5 min? Switch surfaces.
- **20-minute rotation** — "Am I making progress?" If no: endpoint → subdomain → vuln class → target.
- **45-minute rabbit hole** — stuck on one param? STOP. Move on. Sleep on it.
- **2 weeks / 30 hours** — minimum stick time per program before hopping.
- **A→B signal** — one bug means the same dev made more mistakes; hunt 20 min for siblings.

*(bb-methodology/SKILL.md — Anti-Patterns + 20-Minute Clock; bountyforge/wiki/Wild Mode.md — Timing Rules)*

### Pushback Protocol (when "find more" / "look harder")

Default assumption: **they are correct; you stopped early.** Before pushing back: (1) re-read 3 more `hunt-*` skills matching the observed surface; (2) re-attack the same surface walking every checklist step; (3) document negatives as coverage evidence; (4) only then push back with a concrete list of what was tested. *(bb-methodology/SKILL.md — Pushback Protocol)*

### Session End

Save Burp/Caido projects. Record "weird but not yet exploitable" behaviors as future gadgets. Log failed attempts so they are not re-tested with the same technique. Log findings with `/remember`. *(bb-methodology/SKILL.md — Session End Checklist)*

---

## Payload & Detection Patterns

### Marker Discipline (false-positive prevention #1)

- Markers are random alphanumeric strings, **8+ characters**, no English words or protocol keywords.
- **NEVER** use `test`, `marker`, `evil`, `attacker`, `payload`, `javascript`, `script`, `AAAA`, `BBBB`, your domain, or anything that appears naturally.
- Good: `cpmark987abc`, `x4hd2k9pq`, `dlsrcurl.<collab>.oastify.com`, `__ZZ_MARKER_<random>_ZZ__`.
- Search the **baseline** (no-marker) response for the marker before claiming reflection — this catches ~80% of false-positive reflection reports.
- Sub-tag OOB payloads so callbacks identify the specific sink.

*(bb-methodology/SKILL.md — PART 4 Marker Discipline)*

### Detection Ladder

```bash
# 1. Error-based — send ' " {{7*7}} ${7*7}, watch for 500 / stack trace
# 2. Time-based — SLEEP(10), ; sleep 10; — watch response time
# 3. OOB — interactsh-client, unique per-sink sub-tag — watch DNS/HTTP callback
# 4. Boolean — AND 1=1 vs AND 1=0 — watch content-length delta
```

### Statistical-Sample Rule (timing claims)

- Minimum **n ≥ 10 INTERLEAVED trials per group** (control + test, randomized order).
- Compute mean, median, σ for each group.
- Signal requires suspect mean **≥ 2σ above** control mean. A single 2× outlier is jitter.

*(bb-methodology/SKILL.md — PART 4 Statistical-Sample Rule)*

### Body-Diff Rule (bypass claims)

A bypass requires a response **body** differential, not just a status code. 200 OK with a byte-identical body is NOT a bypass. Always `diff` the body side-by-side. Status-code-only claims are the most common N/A category. *(bb-methodology/SKILL.md — PART 4 Body-Diff Rule)*

### Existence-Oracle Status Deltas

| Delta | Cause | Signal |
|---|---|---|
| `400` vs `404` | Body validation before resource-existence check | Existence oracle (probe IDs pre-authz) |
| `415` vs `403` | Content-Type validation before authz | Parser differential (unauthenticated schema probe) |
| `400` vs `403` | Body validation before authz | Authz-bypass potential |

*(web-hunting-playbooks.md — Scoping-Order Analysis)*

### Soft-404 Control (hunt-dispatch step 0)

```bash
for H in $HOSTS; do
  for P in /zzz-nope-12345 /qqq-other-98765; do
    printf "%-34s %-20s " "$H" "$P"
    curl -sk -m 12 -o /tmp/b -w "%{http_code} %{size_download} " "https://$H$P"
    shasum /tmp/b | cut -c1-12
  done
done
```

### Shell-Loop Ban (>5 iterations)

For any iteration >5 times, use Python with `try/except` per iteration, not shell for-loops. A zsh array expansion can silently produce zero iterations. Always count results — 100 probes should yield ~100 lines. *(bb-methodology/SKILL.md — PART 4 Shell-Loop Ban)*

### Discovery Tooling by Phase

| Phase | Tools | Why |
|---|---|---|
| Recon subdomains | `subfinder` → `amass` → `puredns` → `httpx` | Passive → resolve → probe |
| Recon URLs | `gau` + `waymore` → `katana` → `uro` | Archive → crawl → dedup |
| Recon JS | `jsluice` + `mantra` + `trufflehog --only-verified` | URLs/secrets → verified keys |
| Recon ports | `naabu` → `rustscan` | Top-1000 → full 65535 |
| Recon scan | `nuclei -tags cve` → `-tags takeover` | CVEs first → takeover |
| Mapping params | `arjun` + `paramspider` + ParamMiner | Hidden params + archives |
| Discovery fuzz | `ffuf -ac` + `cewl` custom wordlist | Auto-calibrate + target words |
| Discovery XSS | `kxss` → `dalfox` | Filter reflectors → scan |
| Discovery SQLi | `ghauri` | Blind SQLi on ID-like params |
| Discovery OOB | `interactsh-client` | Self-hosted callback listener |
| Exploit 403 | `byp4xx` / `nomore403` | 20+ bypass techniques |
| Exploit cloud | `s3scanner` + `aws` CLI | Bucket perms → metadata creds |

*(bb-methodology/SKILL.md — Tool Routing by Phase)*

### Multi-Tool Reproduction Bar (Critical/High only)

Before labeling Critical or High, reproduce via ≥2 independent tools/stacks: `curl` + Burp `send_http1_request`; Python `requests` + raw `ssl.wrap_socket`; Burp Repeater + Python `urllib`. Cross-tool consistency rules out tool artefacts. Commands must be paste-into-shell ready, with a Python alternative if curl needs special flags. *(bb-methodology/SKILL.md — Phase 5)*

---

## Common Root Causes

1. **Trust violation (the universal root).** The system trusted identity (IDOR/privesc/auth bypass), state (race/TOCTOU/state-machine bypass), input (injection/deserialization/SSTI), or intent (business logic/economic manipulation) it should not have. *(methodology.md — Core Principle)*
2. **Client-side enforcement mistaken for security.** UI restrictions, disabled buttons, hidden fields, feature flags (`enableAuthorize`, `admin_approval`, `status`) are not re-verified server-side. "Never trust the client." *(hunting/SKILL.md — Four "Never Trust" Principles)*
3. **Internal-only assumption.** "Internal" APIs, debug endpoints, and admin panels skip auth checks. "Never trust the backend." *(hunting/SKILL.md)*
4. **Parser / normalization mismatch.** Different parsers resolve the same input differently; front-end filter and origin normalize paths differently; cache and origin interpret requests differently. "Never trust the parser / the cache / the redirect." *(hunting/SKILL.md)*
5. **Developer psychology / uneven implementation.** Feature A has auth checks but newly-added sibling B does not; v2 is hardened while v1 still works; complex flows (coupon + points + refund) have unguarded edge cases. *(bb-methodology/SKILL.md — Critical Thinking)*
6. **Unhandled exceptional conditions.** Wrong type, malformed body, oversized/negative/boundary value, null byte → unhandled exception → framework error page leaking internals. Clean JSON errors are correct handling; disclosed structure is the bug. *(hunt-exceptional-conditions/SKILL.md)*
7. **Feature/protocol/library interaction.** Two "safe" features combine into a vulnerability; frontend sanitization ≠ backend sanitization; HTTP/2 + HTTP/1.1 or middleware versions disagree. *(hunting/SKILL.md — Interaction Principle)*
8. **State-modeled weakness.** Developers validate *who you are* but forget *what state your account is in* — verified vs unverified, free vs premium, owner vs member, suspended vs active. *(hunting/SKILL.md — State Transition Principle)*
9. **Overfetching / schema leakage.** REST sends everything; GraphQL misconfigured schemas leak fields the UI never displays. Sensitive fields in responses are the finding. *(hunting/SKILL.md — Overfetching Principle)*
10. **Documentation/behavior divergence.** Docs list what engineers believed; wherever docs and behavior disagree, the behavior wins and the disagreement is a bug-shaped hole. Code is authoritative, not docs. *(wild-mode.md — Rule 5; al-mizaan-gates.md — Gate 1)*
11. **Fix regression and fork.** A patch is applied to one code path, one platform, or one input type; the sibling remains vulnerable. Fixes regress and fork — retest forever. *(hunting/SKILL.md — Golden Rule 8)*

---

## Bypass Techniques

> Gates are REPORT filters, never hunting limits. Bypass attempts are probes — the hunt has no ceilings. Authorization is the only hard stop. *(wild-mode.md)*

### System Social Engineering — "What lie would make this engine act against itself?"

| Deception | The lie | Where to apply it |
|---|---|---|
| Identity | "This actor is someone else" | Token swapping, IDOR, mass assignment (`role=admin`), auth-bypass headers, JWT confusion, OAuth state theft |
| Authority | "This actor is trusted" | `X-Forwarded-For: 127.0.0.1`, internal-only endpoints, admin role claims, debug flags, `is_admin` |
| State | "A step was completed that wasn't" | Skip payment, fake webhook receipt, race two transitions, replay, double-apply a coupon |
| Time | "This happened earlier/later" | Replay signatures, expired tokens, stale cache, reused nonces |
| Perception | "This input is safe" | Double URL-encode, unicode, CRLF, parser differentials, content-type confusion, polyglot files |
| Cost | "This operation is cheap/expensive" | Negative quantities, fee-on-transfer, rounding-to-zero, dust compounding, cache-busting |
| Composability | "These two harmless things are unrelated" | Chain any two leads into one request/transaction |

*(wild-mode.md — Rule 3)*

### Concrete Bypass Moves

- **403 is not the end:** swap HTTP verbs (OPTIONS reveals supported methods); try different roles; try a related endpoint missing the same check; v2 blocked → try `/api/v1/`. Automate with `byp4xx` / `nomore403`. *(hunting/SKILL.md — Tip #4; bb-methodology Tool Routing)*
- **Frontend control disabled?** Send the request directly via proxy. `user_role=user` cookie → `admin`. `price=1000` → `1`. `<script>` blocked → `<img onerror=...>`. *(bb-methodology/SKILL.md — Critical Thinking)*
- **Skipping the happy path:** skip checkout → hit `/checkout/success`; skip 2FA → navigate to `/dashboard`; coupon request 10× simultaneously → race; replace `guid=f8a2...` with `id=100` on a sibling endpoint → IDOR. *(bb-methodology/SKILL.md — What-If experiments)*
- **Type/shape confusion:** send arrays/objects where strings/numbers expected, empty arrays, null bodies, missing fields, zero amounts, deep nesting, param pollution (batch multiple IDs). *(hunt-exceptional-conditions/SKILL.md; wild-mode.md — Cheat Questions 4/5)*
- **Illegal state transitions:** `Created→Completed` skip, `Approved→Pending` reverse, `Completed→Completed` double; replay, cancel-after-completion, refund-after-withdrawal, TOCTOU. *(methodology.md — P4)*
- **Preconditions as a spec:** "needs too many preconditions" → name each one and build a payload that satisfies every single one. "An attacker would never do that" → you are the attacker; do it. *(wild-mode.md — Rule 2)*
- **Filter/encoding:** Base64, URL, homoglyphs, zero-width chars, leetspeak, multilingual prompts, adversarial suffixes (prompt-injection contexts). *(hunt-skills/ai/offensive-ai-security/SKILL.md — Bypass Techniques)*
- **Edge vs origin:** a CDN "Access Denied" body means the request never reached the application — classify as edge behavior, not an origin bypass. *(hunt-dispatch/SKILL.md — step 0)*

### Chain-or-Die Patterns

Two mid bugs in different domains (web + contract, auth + business logic, SSRF + cache) are one Critical until proven otherwise. A read bug chains into a write bug. A bug on one endpoint chains into the identical pattern on every sibling — probe all siblings before writing anything. *(wild-mode.md — Rule 6)*

---

## Gate 0 Validation

### The Two Questions Every Lead Must Answer

1. **Q-TRIGGER** — "Can this code path fire?" Trace external entry → call path → guards/roles. Cannot fire → KILL (done).
2. **Q-IMPACT** — "If it fires, what does the VICTIM lose?" Trace harm in native terms: funds, stuck value, accounting desync, invariant breach, PII, ATO, RCE. Who loses what, how much, permanently or recoverable.

**Answering Q-TRIGGER and assuming Q-IMPACT is a process error.** A proven trigger with untraced impact is an OPEN LEAD — never a kill. Impact is victim-harm, not attacker-profit. Three verdicts only: FINDING / OPEN LEAD / KILL. KILL requires BOTH refutations with evidence. *(wild-mode.md — Rule 8)*

### The 7-Gate Framework (Al-Mizaan v3 — deep validation)

| Gate | Question | Kill if |
|---|---|---|
| 1. Code Reading | Read what code does, not what docs say | Bug exists only in docs/comments/naming |
| 2. Reachability | Full call path from external entry | No unbroken chain from an entry point |
| 3. Threat Model | Who can trigger, and what they need | Only a trusted actor with no bypass, risk accepted |
| 4. Invariant Breach | Which security/protocol invariant breaks | Behavior unexpected but not contract-breaking |
| 5. Protocol Intent | Bug or documented feature? | Behavior matches documented intent |
| 6. Impact | Quantify concrete harm | Theoretical, unquantifiable, or unrealistic conditions |
| 7. Formal Proof | Working PoC, reproducible by third party | No working PoC or unreplicable conditions |

Web/API translation: docs → actual HTTP response/JS; reachability → request path to handler; threat model → anonymous/user/admin; invariant → security boundary crossed; proof → working curl request. Use Al-Mizaan when a finding passes the quick gate but feels borderline, involves complex chains, or must survive a skeptical triager. *(hunt-skills/bountyforge/references/al-mizaan-gates.md)*

### The 4 Pre-Submission Gates (quick judgment)

Sequential — fail any → REJECTED or DEMOTED to LEAD (payload + chain partners preserved):

1. **Refutation** — strongest argument the finding is wrong; concrete guard → reject/demote; speculative "probably intended" → clears. Never kill on "probably" — fire the payload.
2. **Reachability** — vulnerable state exists in a live system; structurally impossible → reject; privileged-only → demote; normal usage → clears.
3. **Trigger** — an unprivileged actor can trigger profitably; trusted-only → demote; costs exceed extraction → reject.
4. **Impact** — material harm to an identifiable victim; self-harm only → reject; dust-level → demote; material loss → CONFIRMED.

**Severity adjustment:** specific timing / non-trivial capital / bounded impact / fix already deployed → −1 level or DEMOTE. Gate failures are demotions, not deletions. *(hunt-skills/bountyforge/references/judging.md)*

### Finding-Correctness Discipline (four hard rules)

- **Marker Discipline** — unique 8+ char markers; baseline-check before claiming reflection.
- **Body-Diff Rule** — status-code-only bypass claims are not findings; diff the bodies.
- **Statistical-Sample Rule** — timing claims need n≥10 interleaved trials and ≥2σ separation.
- **Shell-Loop Ban** — >5 iterations → Python, count results.

*(bb-methodology/SKILL.md — PART 4)*

### Gate 0 Kill-Switch Checklist

- [ ] Engagement mode fit: would this be rejected in the locked mode? (hygiene in bug bounty → N/A)
- [ ] Q-TRIGGER *and* Q-IMPACT both answered with evidence
- [ ] 7 Gates / 4 Gates passed (or demoted to LEAD with payload preserved)
- [ ] Marker / body-diff / statistical / shell-loop rules satisfied
- [ ] Reproducible in 10 minutes from scratch by a second person
- [ ] Critical/High: reproduced in ≥2 independent tools; commands paste-ready
- [ ] Prerequisites minimized (0–1 clicks); affected role stated; business $ impact quantified
- [ ] Title `[Bug Class] in [Endpoint] allows [role] to [impact]`; impact-first sentence; <600 words; CVSS matches impact
- [ ] Evidence handed to `evidence-hygiene` before any cookie/PII screenshot

---

## Real Impact Examples

These are *pattern* illustrations drawn from the curated source skills. They are intentionally cited by source path — no report IDs or URLs are invented.

### A. Legacy SOAP Login → Highest-Impact Bug in the Engagement
A first pass shipped 5 hygiene findings (EoL software, permissive CSP, stack traces) in the wrong report format for a bug-bounty engagement. After mode correction, re-reading the auth-bypass checklist end-to-end surfaced a `/_vti_bin/Authentication.asmx` legacy SOAP login — brute-forceable — the highest-impact finding of the engagement. Three Criticals (SOAP brute-force, TE.CL request smuggling, NTLM Type-2 disclosure) were each reproduced via curl + Python raw sockets + Burp tooling. **Lesson:** the user saying "find more" usually means you stopped early; pushback protocol exists for this. *(hunt-skills/bb-methodology/SKILL.md — Pushback Protocol, PART 0 lesson, Multi-Tool Reproduction lesson)*

### B. Non-Unique Marker → Retracted Reflection Finding
Initial scan flagged `X-Forwarded-Proto: javascript` reflecting into multiple pages. The "reflection" was the literal word `javascript` in legitimate help-link hrefs. A baseline check with a unique marker would have caught it. **Lesson:** 80% of false-positive reflection reports are non-unique markers. *(hunt-skills/bb-methodology/SKILL.md — Marker Discipline lesson)*

### C. Status-Code-Only "Bypass" → Byte-Identical Body
`Host: target.example:80@evil.example.com` returned 200 instead of a 403 baseline. The body was byte-identical (8341 bytes both) — the edge load balancer normalized the Host, dropping `@evil`. Not a bypass. **Lesson:** body-diff before claiming any bypass. *(hunt-skills/bb-methodology/SKILL.md — Body-Diff Rule lesson)*

### D. Single-Shot Timing → Collapsed Under Repetition
A single probe showed `Administrator` at 1527 ms vs ~700 ms control on a SOAP login — clear user-enumeration signal. Reproduction with n=80 interleaved trials across 8 groups collapsed every group to mean 685–716 ms, σ 25–74 ms. It was network jitter. Finding retracted. **Lesson:** single outliers are not signal. *(hunt-skills/bb-methodology/SKILL.md — Statistical-Sample Rule lesson)*

### E. Subagent Scope Creep → Two Real Production Writes
A subagent told "READ-ONLY" created a live production record (expecting `{}` to return a validation error) and wrote a cloud object to a bucket named only for a DNS check. **Lesson:** pass scope as data, deny by verb before allowing by verb, spell read-only as forbidden verbs, and treat discovered hosts as out of scope until re-authorized. *(hunt-skills/hunt-dispatch/SKILL.md — subagent scope inheritance lesson)*

### F. Chain Pattern: A→B Signal and Sibling Probing
A confirmed auth bypass in endpoint A enables an IDOR in endpoint B → chain and promote to a Critical finding. The same root cause confirmed in contract A promotes the identical pattern in contract B (confidence 75). A read primitive + write primitive = ATO; SSRF + internal discovery = RCE. **Lesson:** single findings get N/A'd; chained findings get paid. *(hunt-skills/bountyforge/references/judging.md — LEAD Promotion; hunt-skills/bountyforge/references/wild-mode.md — Rule 6)*

---

## Source Skill Lineage

All **99** curated source skills that contributed the 1,809 sections. Listed by family with the unique contribution each file makes to this meta-skill. The full archived corpus is `references/source-knowledge.md`.

### Family 1 — AI / LLM Offensive Security (1 file)

| Source file path | Unique contribution |
|---|---|
| `hunt-skills/ai/offensive-ai-security/SKILL.md` | AI-system recon, prompt-injection/jailbreak bypass catalog, OWASP-LLM/MITRE ATLAS methodology, excessive-agency→SSRF chains, egress/provenance guardrails |

### Family 2 — Core Hunting Methodology & BountyForge References (7 files)

| Source file path | Unique contribution |
|---|---|
| `hunt-skills/bb-methodology/SKILL.md` | The master orchestrator: mode confirmation, 5-phase non-linear workflow, critical/multi-perspective/tactical/strategic thinking, anti-patterns, tool routing, discipline rules, pushback protocol, operator notes |
| `hunt-skills/bountyforge/references/al-mizaan-gates.md` | 7-gate deep validation framework, web/API gate translation, vulnerability acceptance-rate calibration (1,032 reconciled findings) |
| `hunt-skills/bountyforge/references/judging.md` | 4 pre-submission gates (refutation/reachability/trigger/impact), severity adjustment, LEAD promotion rules, do-not-report list |
| `hunt-skills/bountyforge/references/methodology.md` | Trust-first hunt spine: 11-step hunt loop, 5 pillars/maps, 6 rules, 5 questions, intersection formula, Web3 economic-invariant track |
| `hunt-skills/bountyforge/references/web-hunting-playbooks.md` | All bug-class checklists (IDOR V1–V10, SSRF, OAuth, upload, race, XSS, logic, SQLi, GraphQL, cache, smuggling...), existence-oracle scoping order, burner-account services |
| `hunt-skills/bountyforge/references/wild-mode.md` | Cheat-system doctrine: payload-first, no ceilings, 7 social-engineering deceits, 8 cheat questions, platform weaponization, chain-or-die, failure-as-data, two-questions-per-lead |
| `hunt-skills/bountyforge/skills/bb-methodology/SKILL.md` | 3rd Eye pentesting reminder — compact pre-hunt memory aid reinforcing the core workflow |

### Family 3 — Fizz Invariant-Discovery Framework (17 files)

| Source file path | Unique contribution |
|---|---|
| `hunt-skills/bountyforge/skills/fizz/README.md` | Fizz property-based fuzzing overview and entry points |
| `hunt-skills/bountyforge/skills/fizz/SKILL.md` | Main fuzz harness: property generation, invariant checking, round-trip/state exploration loop |
| `hunt-skills/bountyforge/skills/fizz/agents/implementers/global-property-implementer.md` | Implements global (cross-state) protocol properties as fuzz checks |
| `hunt-skills/bountyforge/skills/fizz/agents/implementers/specific-property-implementer.md` | Implements per-function targeted properties from the protocol spec |
| `hunt-skills/bountyforge/skills/fizz/agents/invariant-discovery/conservation-auditor.md` | Detects value/supply conservation breaks (mint-vs-burn, total-asset drift) |
| `hunt-skills/bountyforge/skills/fizz/agents/invariant-discovery/protocol-type-specialist.md` | Maps protocol type (lending/staking/governance) to its canonical invariant set |
| `hunt-skills/bountyforge/skills/fizz/agents/invariant-discovery/roundtrip-rounding-analyst.md` | Finds round-trip and rounding-loss invariants in deposit/redeem flows |
| `hunt-skills/bountyforge/skills/fizz/agents/invariant-discovery/state-transition-mapper.md` | Maps legal/illegal state transitions as fuzzable invariants |
| `hunt-skills/bountyforge/skills/fizz/agents/invariant-discovery/synthesizer.md` | Synthesizes discovered invariants into a unified invariant set |
| `hunt-skills/bountyforge/skills/fizz/agents/protocol-analyzer.md` | Analyzes protocol code/deps to seed invariant discovery |
| `hunt-skills/bountyforge/skills/fizz/agents/report-writer.md` | Converts fuzz failures into structured finding reports |
| `hunt-skills/bountyforge/skills/fizz/references/handler-patterns.md` | Common Foundry/Hardhat handler patterns for fuzz harnesses |
| `hunt-skills/bountyforge/skills/fizz/references/property-generation.md` | Techniques for generating meaningful properties from specs/code |
| `hunt-skills/bountyforge/skills/fizz/references/setup-playbook.md` | Step-by-step fuzz environment setup |
| `hunt-skills/bountyforge/skills/fizz/references/template-map.md` | Templates mapping protocol patterns to properties |
| `hunt-skills/bountyforge/skills/fizz/skills/fizz-convert/SKILL.md` | Converts an audit target into a fuzzable property model |
| `hunt-skills/bountyforge/skills/fizz/skills/fizz-sync/SKILL.md` | Syncs fuzz harness state and findings across runs |

### Family 4 — Pashov / X-Ray Auditing (5 files)

| Source file path | Unique contribution |
|---|---|
| `hunt-skills/bountyforge/skills/pashov/.github/ISSUE_TEMPLATE/bug_report.md` | Bug-report structure template for audit findings |
| `hunt-skills/bountyforge/skills/pashov/README.md` | Pashov-style audit workflow and severity philosophy |
| `hunt-skills/bountyforge/skills/pashov/SECURITY.md` | Security policy framing for responsible disclosure |
| `hunt-skills/bountyforge/skills/pashov/x-ray/SKILL.md` | X-Ray deep code-review methodology for Solidity audit |
| `hunt-skills/bountyforge/skills/pashov/x-ray/references/templates.md` | Finding and report templates used by X-Ray reviews |

### Family 5 — Security Arsenal (2 files)

| Source file path | Unique contribution |
|---|---|
| `hunt-skills/bountyforge/skills/security-arsenal/SKILL.md` | Large catalog of payload/bypass/checklist tables (the main arsenal) |
| `hunt-skills/security-arsenal/SKILL.md` | Top-level arsenal entry point — IP bypass tables, wordlists, technique indexes |

### Family 6 — Smart Contract Audit Reference Library (58 files)

| Source file path | Unique contribution |
|---|---|
| `hunt-skills/bountyforge/skills/smart-contract-audit/finding-format.md` | Canonical finding format for smart-contract issues |
| `.../reference/anchor/fv-anc-1-arithmetic-operations/fv-anc-1-cl2-division-by-zero.md` | Division-by-zero arithmetic invariant |
| `.../fv-anc-1-cl3-arbitrary-rounding.md` | Arbitrary-rounding accounting invariant |
| `.../fv-anc-1-cl4-saturating-math-misuse-in-financial-contexts.md` | Saturating-math misuse in financial contexts |
| `.../anchor/fv-anc-10-closing-accounts/fv-anc-10-cl1-closing-accounts-without-zeroing-data-and-setting-a-closed-discriminator.md` | Account closure without zeroing state invariant |
| `.../fv-anc-10-cl3-unintended-closure-by-close-constraint.md` | Unintended account closure invariant |
| `.../fv-anc-10/readme.md` | Closing-accounts invariant family overview |
| `.../anchor/fv-anc-11-state-management/fv-anc-11-cl1-missing-slippage-tolerance-allowing-extraction.md` | Missing slippage tolerance → value extraction |
| `.../fv-anc-11-cl2-lamport-balance-invariant-violation-in-cpi.md` | Lamport balance invariant violation in CPI |
| `.../fv-anc-11-cl3-dust-account-poisoning-blocking-critical-operations.md` | Dust poisoning blocks critical ops |
| `.../fv-anc-11-cl6-reward-accumulator-updated-after-balance-change.md` | Reward-accumulator update ordering invariant |
| `.../anchor/fv-anc-2-signer-checks/readme.md` | Signer-check invariant family overview |
| `.../anchor/fv-anc-4-pda-security/fv-anc-4-cl2-pda-seed-concatenation-collision.md` | PDA seed concatenation collision |
| `.../fv-anc-4-cl3-pda-sharing-single-global-vault.md` | PDA sharing a single global vault |
| `.../fv-anc-4-cl4-pda-purpose-isolation-failure.md` | PDA purpose-isolation failure |
| `.../fv-anc-4-cl5-pda-signer-without-ownership-verification.md` | PDA signer without ownership verification |
| `.../fv-anc-4/readme.md` | PDA-security invariant family overview |
| `.../anchor/fv-anc-5-cross-program-invocation-cpi/fv-anc-5-cl3-not-unsetting-signer-status-before-a-cpi.md` | Signer status not unset before CPI |
| `.../fv-anc-5-cl4-passing-unnecessary-accounts-to-cpis.md` | Unnecessary accounts passed to CPI |
| `.../fv-anc-5-cl5-sol-balance-drain-via-cpi.md` | SOL balance drain via CPI |
| `.../fv-anc-5-cl8-cpi-to-system-program-creates-unintended-account.md` | CPI to system program creates unintended account |
| `.../fv-anc-5/readme.md` | CPI invariant family overview |
| `.../anchor/fv-anc-6-error-handling/readme.md` | Error-handling invariant family overview |
| `.../anchor/fv-anc-7-token-operations/fv-anc-7-cl3-token-2022-incompatibility.md` | Token-2022 incompatibility invariant |
| `.../fv-anc-7-cl4-token-2022-transfer-hook-bypass-or-missing.md` | Token-2022 transfer-hook bypass |
| `.../fv-anc-7-cl6-transfer-fee-extension-accounting-error.md` | Transfer-fee extension accounting error |
| `.../fv-anc-7-cl7-unconstrained-freeze-authority.md` | Unconstrained freeze authority |
| `.../fv-anc-7-cl8-mint-close-authority-exploitation.md` | Mint/close authority exploitation |
| `.../anchor/fv-anc-9-type-cosplay/readme.md` | Type-cosplay invariant family overview |
| `.../reference/anchor/protocols/governance.md` | Governance protocol invariants (quorum, timelock, voting) |
| `.../reference/anchor/protocols/lending.md` | Lending protocol invariants (solvency, collateral, liquidation) |
| `.../reference/anchor/protocols/staking.md` | Staking protocol invariants (rewards, slash, unbond) |
| `.../reference/move/fv-mov-1-object-model/fv-mov-1-cl2-drop-ability-debt-destruction.md` | Drop-ability debt destruction (Move) |
| `.../fv-mov-1-cl3-store-ability-wrapping.md` | Store-ability wrapping (Move) |
| `.../fv-mov-1-cl4-object-wrapping-lock.md` | Object-wrapping lock (Move) |
| `.../fv-mov-1/readme.md` | Object-model invariant family overview (Move) |
| `.../move/fv-mov-2-access-control/fv-mov-2-cl1-missing-capability-check.md` | Missing capability check (Move) |
| `.../fv-mov-2-cl3-entry-visibility-bypass.md` | Entry visibility bypass (Move) |
| `.../fv-mov-2-cl4-sender-spoofing.md` | Sender spoofing (Move) |
| `.../move/fv-mov-3-upgrade-safety/fv-mov-3-cl1-init-upgrade-assumptions.md` | Init/upgrade assumptions (Move) |
| `.../fv-mov-3-cl2-version-check-missing.md` | Missing version check (Move) |
| `.../fv-mov-3-cl4-upgrade-cap-security.md` | Upgrade capability security (Move) |
| `.../move/fv-mov-4-shared-objects-concurrency/fv-mov-4-cl2-hot-potato-flash-loan.md` | Hot-potato flash loan (Move) |
| `.../fv-mov-4/readme.md` | Shared-objects/concurrency invariant family (Move) |
| `.../move/fv-mov-5-arithmetic-errors/fv-mov-5-cl1-bitwise-and-custom-math.md` | Bitwise/custom-math errors (Move) |
| `.../fv-mov-5-cl3-cast-truncation.md` | Cast truncation (Move) |
| `.../fv-mov-5-cl4-rounding-and-constants.md` | Rounding and constants (Move) |
| `.../fv-mov-5/readme.md` | Arithmetic-errors invariant family (Move) |
| `.../move/fv-mov-6-token-accounting/fv-mov-6-cl2-supply-invariant-violations.md` | Supply invariant violations (Move) |
| `.../fv-mov-6-cl4-dust-and-cleanup.md` | Dust and cleanup (Move) |
| `.../fv-mov-6/readme.md` | Token-accounting invariant family (Move) |
| `.../move/fv-mov-8-advanced-patterns/fv-mov-8-cl3-flash-loan-receipt-binding.md` | Flash-loan receipt binding (Move) |
| `.../fv-mov-8-cl4-real-world-exploits.md` | Real-world Move exploit patterns |
| `.../move/protocols/governance.md` | Move governance protocol invariants |
| `.../move/protocols/lending.md` | Move lending protocol invariants |
| `.../move/protocols/oracle.md` | Move oracle/price-feed invariants |
| `.../move/protocols/staking.md` | Move staking protocol invariants |
| `hunt-skills/bountyforge/skills/smart-contract-audit/report-template.md` | Smart-contract finding report template |

### Family 7 — BountyForge Wiki (2 files)

| Source file path | Unique contribution |
|---|---|
| `hunt-skills/bountyforge/wiki/Index.md` | Wiki page graph — BountyForge → Methodology → Trust Map → Vuln Classes → Triage/Report; hunting/validation/learning flows |
| `hunt-skills/bountyforge/wiki/Wild Mode.md` | Condensed cheat-system wiki page: no ceilings, system social engineering, 8 cheat questions, timing rules, developer psychology |

### Family 8 — Exploit Development / Mitigations (1 file)

| Source file path | Unique contribution |
|---|---|
| `hunt-skills/exploit-dev/offensive-mitigations/SKILL.md` | Mitigation detection and bypass catalog: ASLR, DEP/NX, RELRO, stack canaries, CFI, sandboxing, seccomp — for hardening assessment |

### Family 9 — Hunt Dispatch & Class Skills (4 files)

| Source file path | Unique contribution |
|---|---|
| `hunt-skills/hunt-dispatch/SKILL.md` | The `/hunt` loader: engagement frame, 404 baseline, host fingerprint→skill routing, tier cap, mode taxonomy, greybox preflight, subagent scope inheritance |
| `hunt-skills/hunt-exceptional-conditions/SKILL.md` | Exceptional-condition hunting: break one assumption, error-disclosure signatures across Node/PHP/Python/Java/.NET, validation discipline |
| `hunt-skills/hunt-misc/SKILL.md` | Misc high-payout class: access control, info disclosure, session/auth logic, multi-tenant, internal APIs, crown-jewel signal patterns |
| `hunt-skills/hunting/SKILL.md` | The hunting foundation: quick workflow, four "Never Trust" principles, everywhere/edge-case/interaction principles, 10 golden rules, understand-before-attack, API-first/verb-matters/zombie-API principles |

### Family 10 — Infrastructure, Top-Level Arsenal & Parameter Pollution (3 files)

| Source file path | Unique contribution |
|---|---|
| `hunt-skills/infrastructure/offensive-edr-evasion/SKILL.md` | EDR/telemetry evasion context for authorized red-team infrastructure |
| `hunt-skills/security-arsenal/SKILL.md` | Top-level payload/technique arsenal entry (duplicate family name with 5.1 — separate corpus path) |
| `offensive-skills/offensive-parameter-pollution/SKILL.md` | HTTP parameter pollution techniques (front-end/back-end parameter divergence) |

---

## Related Skills & Chains

- **`hunt-dispatch`** — When PART 0 mode confirmation completes and the engagement type is locked. Workflow primitive: this skill answers *what counts as a finding*; `hunt-dispatch` answers *which skills to load*, fingerprints the target, prints the taxonomy, and returns control. This skill stops being the active context once dispatch prints its taxonomy. *(bb-methodology; hunt-dispatch)*
- **`redteam-mindset`** (+ `mid-engagement-ir-detection`) — When `mode=redteam`. Always-on first loads before any platform or hunt skill. The DO NOT STOP primary directive; load it if you ever catch yourself using discipline rules to justify stopping early. *(hunt-dispatch; bb-methodology PART 4 framing)*
- **`bug-bounty`** — Generic "what should I do" / new target. It is the orchestrator that names which `hunt-*` skills to load by topic; this skill is the workflow it runs against. *(bb-methodology — Related Skills)*
- **`offensive-osint`** + **`web2-recon`** — Phase 1 recon. This skill's wide approach delegates asset-arsenal work to `offensive-osint` and the live-host + URL pipeline to `web2-recon`. *(bb-methodology — Related Skills)*
- **`triage-validation`** — Phase 5. This skill's Gate 0 calls `/validate` (7-Question Gate); only findings that pass all 7 get handed to `report-writing`. Borderline → Al-Mizaan deep validation. *(bb-methodology; al-mizaan-gates)*
- **`report-writing`** / **`bugcrowd-reporting`** / **`redteam-report-template`** — Final deliverable format: `mode=wapt` → `report-writing` (or `bugcrowd-reporting`); `mode=redteam` → `redteam-report-template`. *(hunt-dispatch)*
- **`evidence-hygiene`** — Before any PoC screenshot/HAR containing a cookie or PII is captured. Hand off for the redaction protocol. *(bb-methodology; security-arsenal)*
- **`security-arsenal`** — Before testing filters or building payloads; load the IP bypass table and class checklists. *(hunt-ssrf and arsenal lineage)*
- **`hunt-ssrf`** / **`hunt-idor`** / **`hunt-auth-bypass`** / **`hunt-sqli`** / **`hunt-business-logic`** (all `hunt-*` classes) — Load only after Phase 2 mapping names the surface. Each class skill points back here for mode confirmation, the hunt loop, and Gate 0 validation.
- **`hunt-llm-ai`** — When fingerprinting reveals LLM/AI surfaces. AI skill supplies prompt-injection and excessive-agency chains; this skill supplies the trust-map and gate discipline. *(offensive-ai-security; web-hunting-playbooks)*
- **`trust-map` / `vuln-classes` / `A→B Chains` / `lead-ledger`** — BountyForge wiki primitives that back P2, hypothesis generation, chaining, and persistent OPEN LEADs. *(wiki/Index.md; methodology.md)*

**Canonical chain:** `hunt-methodology-mindset` (mode + map + gates) → `hunt-dispatch` (load skills) → `offensive-osint`/`web2-recon` (recon) → class `hunt-*` skills (find) → A→B chaining → `triage-validation` (Gate 0) → `evidence-hygiene` (redact) → `report-writing` (deliver).

---

## Summary

This is the meta-skill every hunt runs through. Confirm the **mode** first; define one **goal**; build the **five maps** before probing; hunt **trust-boundary intersections** with payload-first, no-ceiling, chain-or-die wild-mode discipline; rotate on the 5/20/45-minute clocks; then apply **Gate 0** — two questions (trigger × impact), 7 gates, 4 gates, and the four finding-correctness rules — before a single report line is written. Coverage discipline and finding-correctness discipline are orthogonal: run both at full. Automation finds mutations; humans find assumptions. The maps tell you where to look; wild mode tells you never to stop looking. Full grounding: the 99 source skills above and the 1,809-section corpus at `references/source-knowledge.md`.
