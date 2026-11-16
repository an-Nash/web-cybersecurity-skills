---
name: hunt-captcha-bypass
description: "Hunting skill for CAPTCHA / bot-check bypass, built from 1 curated source skill (0 disclosed full reports read at report level). Covers the fastest-first autonomous test ladder — omit the CAPTCHA field entirely, send empty/null/0/undefined values, replay a previously solved token, hit the unguarded sibling endpoint (/api/register vs /register, password reset, mobile API), and trigger rate/throughput gates with concurrent placeholder requests — plus the five root causes (client-side-only validation, token not tied to session/action, single-use not enforced, reactive CAPTCHA after N failures, static/predictable custom CAPTCHA) and the impact chains into brute force, account farming and token flooding. Use when a CAPTCHA/bot-check appears to be the only gate on a state-changing action — proof is the action completing without a valid CAPTCHA token."
sources: github
report_count: 0
full_reports_read: 0
source_skills: 1
---

> **Knowledge base and grounding.** This skill is derived from a single curated source skill; no individual bug-bounty reports were read at full-text level (`report_count: 0`, `full_reports_read: 0`, `source_skills: 1`). The complete merged corpus is preserved verbatim at
> `E:\webt\skill-setup\skills-extract-from-reports\hunt-captcha-bypass\references\source-knowledge.md`.
> Everything below is grounded in that digest. No HackerOne IDs, payouts, invented URLs, or fabricated case studies are introduced — impact examples are labelled scenarios derived from the source's Impact Chain, and lineage is cited by skill path.

**How to use this skill.** Work the sections in order. *Crown Jewel Targets* tells you what is worth testing; *Attack Surface Signals* tells you what to look for in the request and response; *Discovery Patterns* explains the four pattern families the source documents; *Step-by-Step Hunting Methodology* is the execution order; *Payload & Detection Patterns* gives concrete requests; *Common Root Causes* and *Bypass Techniques* help you name the bug precisely; *Gate 0 Validation* is the pre-report checklist; *Real Impact Examples* shows how severity is reasoned. Lineage and chains close the document. The single most important habit, repeated throughout, is: **capture a legitimate baseline first, then show the same action succeeding without a valid CAPTCHA token.**

---

## Crown Jewel Targets

A CAPTCHA / bot-check is only worth hunting where it is the *control that stands between an attacker and a state-changing action*. If the action is harmless, bypassing the CAPTCHA is harmless. Rank targets by what the ungated action lets you do, not by how elaborate the widget looks.

The source skill is explicit that most CAPTCHA bypass bugs are **client-side-only validation**: JavaScript hides or disables the submit button until the CAPTCHA is solved, but the server never checks the token. That single sentence defines the center of gravity — the highest-value target is any endpoint where the visible UI gate is *not mirrored by a server-side verification step*.

Priority targets, in the order the source material implies:

- **Registration / signup forms** — the source's "autonomous testing priority" uses the registration form as its baseline example. If the CAPTCHA field can be omitted and the account is still created, the gate is fictitious. Impact: **account farming** → abuse, spam, resource exhaustion.
  - Sibling path to test immediately: `POST /api/register` versus `POST /register`. The source specifically calls out apps that add CAPTCHA to the web form but forget the API endpoint or mobile API path.
- **Login endpoints** — the source's Impact Chain states that bypass on a login endpoint removes the brute-force gate and chains to `hunt-brute-force` at High/Critical. A login form that only *displays* a CAPTCHA while the POST accepts credentials without a valid token converts an unbounded password guess into a viable attack.
- **Password-reset / forgot-password endpoints** — Impact Chain: CAPTCHA bypass here enables **token flooding**, chaining to `hunt-forgot-password`. Reset flows are a named example of the "forgot the CAPTCHA" sibling-endpoint pattern.
- **Any state-changing form whose success you can observe** — the source's definition of proof is "any successful state-changing action (account created, login succeeded, form submitted) that completed without a valid CAPTCHA token." That makes observable state transitions the target: something you can check after the request (a new account, an authenticated session, a submitted record).
- **Rate/throughput-gated routes** — not all "bot checks" are challenge widgets. The source describes a class where the app defines bypass as simply exceeding a plausible human rate ("N submissions within T seconds"), enforced by middleware that counts requests reaching the route rather than successful outcomes. These are high-value because *garbage payloads work as well as valid ones* — the counter increments before the request's own validation matters.
- **Custom CAPTCHA implementations** — math CAPTCHAs (`3 + 4 = ?`), simple image CAPTCHAs, and text CAPTCHAs with a finite answer set. The source classifies these as automatable (unlike real reCAPTCHA/hCaptcha), because the answer space is small and predictable.
- **Endpoints with a comparable sibling** — the meta-target: wherever a CAPTCHA exists, enumerate the *same action* reachable through another surface (API version, mobile path, alternate content type, password-reset sibling) where the field was forgotten.

### Target Value Matrix

| Target surface | Why it is high value | Source anchor | Impact class |
|----------------|----------------------|---------------|--------------|
| Registration form | Account creation completes with no CAPTCHA field | Pattern 1 baseline example; "account farming" | Abuse / spam / resource exhaustion |
| Login endpoint | Removes the only brute-force gate | Impact Chain → `hunt-brute-force` | High/Critical when chained |
| Password reset | Reset flow protected by CAPTCHA only | Pattern 4 + Impact Chain → `hunt-forgot-password` | Token flooding |
| API / mobile sibling | Same action, CAPTCHA field forgotten | "Test without CAPTCHA on similar endpoints" | Inherits the parent action's severity |
| Throughput-gated route | Counter measures requests, not outcomes | Pattern 5 timing note | Automation-enabling (Medium base) |
| Custom CAPTCHA | Finite / computable answer space | Root Cause 5 | Depends on gated action |

### What Is NOT a Crown Jewel

Keeping the target list honest prevents wasted effort and weak reports:

- A CAPTCHA on an action with **no downstream consequence** — proving you can submit a harmless form without a token is technically a bypass but stays at the source's "Medium" floor and may not be worth reporting alone.
- A **real reCAPTCHA/hCaptcha** where Patterns 1–4 all fail and no server-side mistake is evident — the source explicitly deprioritises programmatic solving without external services.
- A **success string with no state change** — the source requires a successful state-changing action as proof; a message alone is not proof.
- A **gate you have not classified** — running concurrency tests against a challenge widget, or replay tests against a throughput counter, wastes budget. Classify first (see Step 7).

**Enumeration habit.** For every CAPTCHA you find, leave the page with two artifacts: the exact field name and the list of sibling surfaces for the same action. The source's entire "similar endpoints" pattern depends on having both.

**Severity framing from the source.** CAPTCHA bypass alone is **Medium** (it enables automation of rate-limited actions). It climbs to **High/Critical** when it removes the only gate on a login or other security-sensitive endpoint. Always score the downstream action, never the widget.

---

## Attack Surface Signals

### Endpoint Patterns to Hunt

From the source's examples, the surface is defined by *where a state-changing action lives and where its sibling might not be gated*:

```
/register                 /api/register            /signup
/login                    /api/login               (login POST endpoints)
(password reset form)     (password reset API path)
(form that renders a CAPTCHA challenge)
(mobile API path for any of the above)
(any endpoint whose middleware counts "N submissions within T seconds")
```

The source gives one explicit concrete shape — `/api/register` versus `/register` — and the general rule: apps add CAPTCHA to one surface and forget the API endpoint, the password-reset path, or the mobile API path. Treat every gated action as having an *ungated twin* until proven otherwise.

### CAPTCHA Field / Parameter Names

The source names the field names to look for when reading the form:

```
g-recaptcha-response
h-captcha-response
captcha
captcha_token
captcha_answer
```

These are the fields to omit, empty, or replay. The first two are the reCAPTCHA/hCaptcha token fields; the latter three are generic/custom names. The exact name must be learned from the real form (GET the endpoint first) — do not assume one.

### Field-Name Behavior Matrix

| Field name | Typical challenge family | Primary test from source |
|------------|--------------------------|--------------------------|
| `g-recaptcha-response` | reCAPTCHA (token-based) | Omit; replay captured token; check single-use |
| `h-captcha-response` | hCaptcha (token-based) | Omit; replay captured token |
| `captcha` | Generic / custom | Omit; empty/null/0/undefined |
| `captcha_token` | Generic token | Omit; replay; single-use check |
| `captcha_answer` | Custom (math/text/image) | Answer directly for finite answer sets |

The matrix is a starting hypothesis only. The source's step 1 is to GET the form and read the real field name, because the bypass depends on manipulating the field the server actually expects.

### Value Shapes to Send

```
(omit the field entirely)        ← Pattern 1, most common
captcha=                         ← empty string
captcha=null
captcha=0
captcha=undefined
captcha=<previously solved token> ← replay
(placeholder / garbage value)    ← for rate/throughput gates
```

### Success / Detection Signals

Per the source, a bypass is confirmed when the action succeeds after the CAPTCHA field is removed or invalidated:

```
HTTP 200
Redirect (to dashboard / success page / post-action location)
"success" message
State transition: account created / login succeeded / form submitted
```

**Always capture a baseline.** The source's Pattern 1 step 4 says to compare the bypass attempt against a baseline request that *includes* the CAPTCHA field. Without the baseline you cannot show that the field was ever required, and therefore cannot show that omitting it changed anything.

### Rate / Throughput Gate Signals

```
Challenge defined as "N submissions within T seconds"
Middleware counts REQUESTS REACHING the route (not successful outcomes)
Sliding-window counter: ~10 requests inside ~20 seconds
Failing pace example: 12 requests across ~250 seconds
Required-field validation that must be satisfied to reach the counter
  (e.g. a rating field that cannot be null)
```

### Tech / Implementation Signals

- **Client-side-only enforcement** — the submit button is hidden or disabled until the CAPTCHA is solved, with no server-side token check behind it.
- **Token validated for authenticity but not for context** — the server asks "is this a real CAPTCHA solution?" but not "is this the right solution for THIS action/session?".
- **No single-use revocation** — a token is not consumed after first verification (notably associated with reCAPTCHA v2 in the source).
- **Reactive CAPTCHA** — challenge appears only after 3–5 failed attempts; before the threshold there is no CAPTCHA at all.
- **Custom, finite-answer CAPTCHA** — math / simple image / finite text answer set, as opposed to Google/hCaptcha.

### Signal-to-Pattern Map

| Observed signal | Pattern family it points to | Section to consult |
|-----------------|-----------------------------|--------------------|
| Submit button gated; field omitted still succeeds | Client-side-only validation | Discovery A |
| Token reused with no revocation | Single-use not enforced | Discovery B |
| Token from login accepted on registration | Not tied to action/session | Discovery B |
| CAPTCHA appears only after 3–5 failures | Reactive gating | Discovery C |
| "N in T seconds" count at route | Throughput / sliding window | Discovery C |
| Math / finite text / simple image | Static predictable custom CAPTCHA | Discovery D |

### Pre-Test Enumeration Checklist

Before firing any bypass request, record:

- [ ] The form/endpoint that renders the CAPTCHA (so you know the real field name).
- [ ] The exact CAPTCHA field name from the rendered HTML.
- [ ] The method, content type, and all non-CAPTCHA fields the form submits.
- [ ] The sibling surfaces for the same action: API path, mobile API path, password-reset path.
- [ ] Whether the gate is a challenge widget or a "N in T seconds" counter.
- [ ] What observable state change would prove success (account, session, record).

### What to Skip

The source is explicit: **solving real reCAPTCHA/hCaptcha programmatically** (OCR, audio bypass) requires external services. Only attempt it if Patterns 1–4 fail and the test budget allows. This is a last resort, not a starting point.

---

## Discovery Patterns From Curated Source Skills

The single curated source skill exposes 8 unique sections. Its discovery content is organised below into four subsections that mirror the five root causes it documents. Each subsection is a pattern to test, not just a taxonomy.

### Pattern A — Client-Side-Only Validation (Field Omission / Empty Value)

The dominant pattern in the source: JavaScript hides or disables the submit button until the CAPTCHA is solved, but the server never checks the token. Direct API calls bypass the UI gate entirely.

Discovery steps, straight from the source's "Autonomous Testing Priority":

1. GET the form/endpoint that shows a CAPTCHA to learn its field name (`g-recaptcha-response`, `captcha`, `captcha_token`, `captcha_answer`, `h-captcha-response`).
2. POST the form with **all fields except the CAPTCHA field**.
3. If the action succeeds (200, redirect, or "success" message) → no server-side CAPTCHA validation.
4. Proof: the state-changing action completes without a valid CAPTCHA field — compare against a baseline request that includes it.

Variant — **empty or null value** (Pattern 2): instead of omitting the field, send it with an empty string, `null`, `0`, or `undefined`:

```
captcha=&email=test@example.com&password=test123
```

Some apps validate *field presence* but not *content*. This distinguishes two sub-cases worth separating in a report: "field not required at all" versus "field required to exist but its value is never verified."

**Automatable?** Yes — this is the most automatable test in the entire source. It should be the first thing attempted, before any token-solving effort.

**Report-worthy evidence for Pattern A:** the field name as rendered in the form; the omitted-field request; the baseline request with the field; the success responses of both; and the downstream state check proving the action actually completed.

### Pattern B — Token Binding and Replay (Not Tied to Session/Action; Single-Use Not Enforced)

Two related root causes share a discovery surface:

- **CAPTCHA not tied to session or action** — a token solved for login is accepted on the registration endpoint (or any other). The server validates "is this a real CAPTCHA solution?" but not "is this the right solution for THIS action?".
- **Single-use not enforced** — CAPTCHA tokens (especially reCAPTCHA v2) are meant to be consumed after one use. If the server does not revoke them after verification, a single human-solved token becomes reusable for many requests.

Replay discovery (Pattern 3):

1. Complete one legitimate CAPTCHA challenge and capture the `g-recaptcha-response` token.
2. Submit a second request immediately with the **same** token value.
3. If the second submission also succeeds → the token is not single-use (replay attack).
4. A replayed token can be shared across automated requests.

Cross-action discovery: take a token legitimately obtained on endpoint A (e.g. login) and replay it on endpoint B (e.g. registration). Success means the token is not bound to the action it was solved for. These two checks together — same-action replay and cross-action reuse — should be run as separate tests because they implicate different fixes (token revocation vs. context binding).

**Report-worthy evidence for Pattern B:** the captured token, the first legitimate use, the second (replayed) use, the cross-endpoint use, and a note of how many requests the same token accepted. Distinguish "not single-use" from "not action-bound" explicitly — the fixes differ.

### Pattern C — Reactive / Threshold Gating (CAPTCHA Added After N Failures)

Root cause: some apps only show CAPTCHA after 3–5 failed login attempts. Before that threshold, no CAPTCHA is required, so an attacker can make N-1 attempts per account indefinitely by **resetting state between attempts**.

Two distinct bypass angles:

- **Threshold reset** — find what the counter keys on (account, session, IP, cookie) and reset it between batches so the CAPTCHA never appears. This keeps every attempt in the pre-threshold window.
- **Throughput / sliding-window gate** (Pattern 5) — the "bot check" is simply a rate the human could not plausibly sustain, e.g. "N submissions within T seconds," checked by middleware that counts requests reaching the route rather than successful outcomes. Garbage/placeholder payloads satisfy this exactly as well as valid ones, since the counter increments regardless of whether the request's own validation passes.

**Timing note from the source (critical).** Do not solve a sliding-window gate one request at a time. A sequential pace (seconds between each request) structurally cannot land N requests inside a short sliding window, and issuing more requests serially does not fix it. The documented failing pattern is 12 requests spread across ~250 seconds when the check requires ~10 requests within 20 seconds. Instead, fire the requests **concurrently** (e.g. `"concurrency": N` on a single request call, or any parallel-request primitive your tooling offers, with `N >=` the required count) so they arrive simultaneously and satisfy the sliding window trivially.

Before firing the concurrent batch, check the endpoint's own required-field validation (e.g. a `rating` field that cannot be null) so the payload is at least well-formed enough to reach the counting middleware — even if other fields (like the CAPTCHA answer itself) are wrong or reused. A malformed request that dies in field validation never increments the gate counter and produces a false negative.

**Report-worthy evidence for Pattern C:** the determined N and T, proof the counter counts requests rather than outcomes, the required fields discovered, the concurrent burst configuration (`concurrency: N`), and the resulting success of the gated action. For reactive gating, record what state the failure counter keys on and how it was reset.

### Pattern D — Static / Predictable Custom CAPTCHA

Root cause: math CAPTCHAs (`3 + 4 = ?`), simple image CAPTCHAs, or text CAPTCHAs with a finite answer set can be automated because they are custom implementations, not Google/hCaptcha.

Discovery angle: identify that the challenge is custom (not reCAPTCHA/hCaptcha), determine the answer space, and answer it directly. A math challenge has a computable answer; a finite text/image set can be enumerated. Unlike the token-based patterns above, here the "bypass" is solving the challenge mechanically — which the source permits as in-scope for custom implementations while reserving external-service solving of real CAPTCHAs as a last resort.

**Report-worthy evidence for Pattern D:** proof the implementation is custom (not reCAPTCHA/hCaptcha), the finite/computable answer space, and a successful action using a mechanically derived answer.

### Four-Pattern Summary Matrix

| Subsection | Source section(s) | Core idea | Fast to automate? |
|------------|-------------------|-----------|-------------------|
| A — Client-side-only | Autonomous Testing Priority Patterns 1–2; Root Cause 1 | Field omitted / empty still succeeds | Yes — first test |
| B — Binding & replay | Pattern 3; Root Causes 2–3 | Token reusable or cross-endpoint | Yes, after one human solve |
| C — Reactive / throughput | Pattern 5; Root Cause 4 | Reset threshold or burst the sliding window | Yes with concurrency |
| D — Static custom | Root Cause 5 | Compute / enumerate finite answers | Yes for custom only |

---

## Step-by-Step Hunting Methodology

1. **Find every CAPTCHA-gated form and its sibling endpoints.** GET the page that renders the challenge. Record the exact CAPTCHA field name (`g-recaptcha-response`, `captcha`, `captcha_token`, `captcha_answer`, `h-captcha-response`). Then enumerate the same action through other surfaces: `/api/register` vs `/register`, the password-reset path, and any mobile API path.

2. **Capture a baseline.** Submit one fully legitimate request with a solved CAPTCHA. Record the success response (status, redirect, body message, and the downstream state change). This is the reference the bypass must be compared against.

3. **Run Pattern 1 — omit the field.** POST all fields *except* the CAPTCHA field. Compare to baseline. Success = no server-side validation. This is the fastest test and should run before anything else.

4. **Run Pattern 2 — empty/null value.** Include the field with `""`, `null`, `0`, or `undefined`. Success = presence checked but content not verified.

5. **Run Pattern 3 — replay.** Solve one legitimate challenge, capture its token, and resubmit with the same token. Then try that token on a *different* endpoint. Success = single-use not enforced and/or token not bound to session/action.

6. **Run Pattern 4 — sibling without CAPTCHA.** Attempt the same action on the API and mobile paths you mapped in step 1, with no CAPTCHA field at all.

7. **Classify the gate before speed-testing.** Decide whether you face a challenge widget (Patterns 1–4 apply) or a throughput gate (Pattern 5). For a throughput gate: determine N and T, verify the counter counts requests rather than successful outcomes, check required-field validation, then fire `N` (or more) **concurrent** placeholder requests (`"concurrency": N` or equivalent) with well-formed fields. Do not pace them sequentially.

8. **Test reactive thresholds.** Where CAPTCHA only appears after 3–5 failures, identify what state the failure counter keys on and reset it between batches to stay below the threshold.

9. **If the challenge is custom**, attempt direct answering (math computation, finite-set enumeration). Only consider external solving of real reCAPTCHA/hCaptcha if Patterns 1–4 all failed and the test budget allows.

10. **Confirm a state transition, not just a response.** The source's proof is a *successful state-changing action* — account created, login succeeded, form submitted. Verify the downstream effect (the account exists, the session is authenticated, the record was written). An alleged "success" string with no state change is not proof.

11. **Document the comparison.** Record the baseline (with CAPTCHA) and the bypass (without / with invalid CAPTCHA) side by side, plus the exact omitted or manipulated field. The delta is the finding.

### Decision Flow

```
Is the action state-changing and observable?
  ├─ No  → low value; deprioritise (source: Medium floor, possibly not reportable)
  └─ Yes → GET the form, capture the CAPTCHA field name
              ├─ Omit field → succeeds?           → Pattern A / Root Cause 1
              ├─ Empty/null value → succeeds?    → Pattern A (presence-only check)
              ├─ Replay token → succeeds?         → Pattern B / Root Cause 3
              ├─ Token on other endpoint works?   → Pattern B / Root Cause 2
              ├─ CAPTCHA only after N failures?   → Pattern C / Root Cause 4
              ├─ "N in T seconds" route counter?  → Pattern C / use concurrency
              └─ Custom finite challenge?         → Pattern D / Root Cause 5
```

### Timing and Tooling Notes

- The baseline must be captured **before** any mutation, because once you have omitted or replayed a field you may no longer be able to reproduce a clean legitimate success on the same account/session.
- Token replay is time-sensitive in practice: the source says to submit the second request "immediately" after the legitimate solve. Long delays risk the token expiring or being revoked by unrelated logic, producing a false negative.
- For concurrent bursts, use a parallel-request primitive (e.g. `"concurrency": N` on a single request call). The source stresses that adding more *sequential* requests does not help a sliding-window gate.
- When resetting reactive-threshold state, verify you actually reset the key the counter uses — otherwise the CAPTCHA will keep appearing and the test will look like a failed bypass when it is really a state-control problem.

### Common False Negatives to Avoid

- **Pacing a sliding-window gate sequentially** — the source's explicit example: 12 requests over ~250 seconds cannot satisfy a ~10-in-20-second window. Use concurrency.
- **Sending a malformed burst** — if a required field (e.g. non-null `rating`) is missing, requests die before the counter and the gate never trips; check required fields first.
- **Treating a success string as proof** — the source requires an actual state change.
- **Assuming the obvious form is the only surface** — the API / mobile / reset siblings are named hiding places for the ungated path.
- **Skipping the baseline** — without the with-CAPTCHA request, the delta that proves the bypass is missing.

---

## Payload & Detection Patterns

### Pattern 1 — Field Omission

```http
POST /register HTTP/1.1
Content-Type: application/x-www-form-urlencoded

email=test@example.com&password=test123
```

Note the absence of `g-recaptcha-response`. Compare against a baseline that includes:

```http
email=test@example.com&password=test123&g-recaptcha-response=<valid token>
```

Success signal: 200, redirect, or "success" message on the omitted-field request, and the account actually exists afterward.

### Pattern 2 — Empty / Null / Zero / Undefined

```
captcha=&email=test@example.com&password=test123
captcha=null&email=test@example.com&password=test123
captcha=0&email=test@example.com&password=test123
captcha=undefined&email=test@example.com&password=test123
```

Each value probes a different validation style: empty string, JSON-style null, numeric zero, JavaScript-style undefined. Run them individually so you can report which one the server accepted.

### Pattern 3 — Replay Token

```http
# Step 1 — legitimate solve, capture the token
POST /login
...&g-recaptcha-response=<CAPTURED_TOKEN>

# Step 2 — immediate reuse, same token
POST /login
...&g-recaptcha-response=<CAPTURED_TOKEN>

# Step 3 — cross-action reuse
POST /api/register
...&g-recaptcha-response=<CAPTURED_TOKEN>
```

If step 2 succeeds → single-use not enforced. If step 3 succeeds → token not tied to session/action.

### Pattern 4 — Ungated Sibling Endpoint

```
POST /api/register    email=...&password=...        (no CAPTCHA field)
POST /register        email=...&password=...        (CAPTCHA present — baseline)
(password reset API path) ...                        (no CAPTCHA field)
(mobile API path) ...                                (no CAPTCHA field)
```

### Pattern 5 — Concurrent Throughput Gate

```
# WRONG — sequential, cannot satisfy a sliding window
request 1 ... request 2 ... ... request 12   (spread across ~250s)

# RIGHT — simultaneous burst with N >= required count
single request call with "concurrency": N (>= 10 for a 10-in-20s gate)
payload: well-formed fields, placeholder/reused CAPTCHA answer
```

Preconditions to verify first:
- The gate counts requests **reaching the route** (not successful outcomes).
- Required non-null fields are present (e.g. a `rating` field) so the request reaches the counting middleware.
- `N >=` the required count and the window semantics are understood.

### Custom CAPTCHA Answering

```
math challenge:   "3 + 4 = ?"        → 7
finite text set:  enumerate all possible answers
simple image set: enumerate / classify the finite image set
```

### Full Request Template (Baseline vs. Bypass)

```http
# Baseline — with valid CAPTCHA
POST /register HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded

email=test@example.com&password=test123&g-recaptcha-response=<valid token>

# Bypass — field omitted, everything else identical
POST /register HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded

email=test@example.com&password=test123
```
The only difference between these two requests is the CAPTCHA field. Keeping every other byte identical is what makes the comparison defensible: any difference in outcome is attributable to the field, not to a changed parameter.

### Detection Signal Table

| Signal | Interpretation | Caveat |
|--------|----------------|--------|
| 200 / redirect / "success" on omitted-field request | No server-side CAPTCHA validation (Pattern A) | Confirm the downstream state actually changed |
| Same response with vs. without field | Field inert, not just unverified content | Still a bypass if the gated action completes |
| Replayed token accepted | Single-use not enforced (Pattern B) | Distinguish from cross-endpoint reuse |
| Cross-endpoint token accepted | Not tied to session/action (Pattern B) | Different fix than single-use |
| CAPTCHA absent for first 3–5 attempts | Reactive gating (Pattern C) | Identify what the failure counter keys on |
| Burst of N well-formed requests succeeds | Throughput gate counted requests, not outcomes (Pattern C) | Verify concurrency, not serial pacing |
| Computable / enumerable answer accepted | Static custom CAPTCHA (Pattern D) | Must be custom, not real reCAPTCHA/hCaptcha |

### Detection Checklist

- [ ] Baseline with valid CAPTCHA recorded.
- [ ] Field omitted → action compared to baseline.
- [ ] Empty/null/0/undefined tried individually.
- [ ] Token replayed (same endpoint) and reused (cross endpoint).
- [ ] All sibling endpoints (API, mobile, password reset) tried without the field.
- [ ] Gate type classified (challenge vs throughput) before speed testing.
- [ ] Concurrency used for sliding-window gates, with well-formed payloads.
- [ ] Reactive threshold reset behaviour tested.
- [ ] Downstream state transition verified, not just a success string.

---

## Common Root Causes

The source skill enumerates five root causes. Each maps to a distinct fix, so keep them separate in findings.

1. **Client-Side-Only CAPTCHA Validation** — JavaScript hides/disables the submit button until the CAPTCHA is solved, but the server never checks the CAPTCHA token. Direct API calls bypass the UI gate entirely. This is the most automatable and, per the source, the most common bypass.

2. **CAPTCHA Not Tied to Session or Action** — a token solved for login is accepted on the registration endpoint (or any other). The server validates "is this a real CAPTCHA solution?" but not "is this the right solution for THIS action?". The fix is context binding, not token verification.

3. **Single-Use Not Enforced** — CAPTCHA tokens (especially reCAPTCHA v2) are meant to be consumed after one use. If the server does not revoke them after verification, a single human-solved token becomes reusable for many requests. The fix is server-side consumption/revocation on first successful check.

4. **CAPTCHA Added Reactively (Only After N Failures)** — some apps only show CAPTCHA after 3–5 failed login attempts. Before that threshold, no CAPTCHA is required, so an attacker can make N-1 attempts per account indefinitely by resetting state between attempts. The fix requires tightening the threshold logic and the state it keys on.

5. **Static or Predictable CAPTCHA** — math CAPTCHAs (`3 + 4 = ?`), simple image CAPTCHAs, or text CAPTCHAs with a finite answer set can be automated. These are custom CAPTCHA implementations, not Google/hCaptcha. The fix is to adopt a challenge with a non-enumerable answer space.

### Root Cause → Test → Fix Map

| Root cause | Confirming test | Corrective fix (implied by the cause) |
|------------|-----------------|----------------------------------------|
| Client-side-only validation | Omit field / direct API call succeeds | Verify token server-side on every gated action |
| Not tied to session/action | Token from endpoint A works on endpoint B | Bind token to action/session/context |
| Single-use not enforced | Same token accepted twice | Consume/revoke token on first verification |
| Reactive gating | No CAPTCHA for first N−1 attempts | Correct threshold logic and counter state |
| Static/predictable | Computed/enumerated answer accepted | Use challenge with non-enumerable answer space |

**Cross-cutting observation.** Root causes 1–3 are all variations of "the control exists but is not enforced where it matters" (UI vs server, action binding, single-use). Root causes 4–5 are about the *strength and placement* of a control that does exist. This split is useful when writing the root-cause statement: is the bug absence of enforcement, or weakness of enforcement?

---

## Bypass Techniques

### Omission and Value Manipulation

- **Omit the CAPTCHA field entirely** — POST all other fields. The source's default first test.
- **Empty string / `null` / `0` / `undefined`** — defeats presence-only checks.
- **Placeholder / garbage value** — sufficient for throughput gates where the counter increments before validation.

### Replay and Reuse

- **Immediate replay** — resubmit a captured `g-recaptcha-response` within the same session.
- **Cross-endpoint reuse** — carry the token from login to registration (or any other endpoint) to expose missing action binding.
- **Shared token across automated requests** — once confirmed non-single-use, the one human-solved token seeds an automated batch.

### Surface Confusion

- **API path instead of web form** — `/api/register` vs `/register`.
- **Mobile API path** — the same action without the CAPTCHA field.
- **Password-reset sibling** — a named example of the "forgot the CAPTCHA" surface.

### Threshold and Timing

- **Reset state between attempts** — keep the reactive CAPTCHA from ever appearing by resetting whatever the 3–5 failure counter keys on.
- **Concurrent burst for sliding windows** — `N >=` required count, fired simultaneously (`"concurrency": N` or a parallel-request primitive), with well-formed fields so the requests reach the counting middleware. Never pace sequentially for a "N in T seconds" gate.
- **Satisfy required fields first** — e.g. a `rating` field that cannot be null must be populated, otherwise the payload dies before incrementing the gate.

### Custom Challenge Solving

- Compute math-challenge answers directly (`3 + 4 = ?` → `7`).
- Enumerate finite text/image answer sets.

### Explicitly Deprioritised

- **Programmatic solving of real reCAPTCHA/hCaptcha** (OCR, audio bypass) needs external services. Attempt only if Patterns 1–4 fail and the budget allows. This is a last resort, and the source frames it as outside the fast autonomous path.

### Technique Quick Reference

| Technique | Defeats | Root cause addressed |
|-----------|---------|----------------------|
| Omit field | UI-only gate | 1 |
| Empty / null / 0 / undefined | Presence-only check | 1 |
| Replay token | No revocation | 3 |
| Cross-endpoint token | No action/session binding | 2 |
| API / mobile / reset sibling | CAPTCHA added to one surface only | 1 |
| Reset threshold state | Reactive gating | 4 |
| Concurrent burst | Sliding-window throughput gate | 4 |
| Compute / enumerate answer | Static custom CAPTCHA | 5 |

### Proof Standard

Any successful state-changing action (account created, login succeeded, form submitted) that completed without a valid CAPTCHA token confirms the bypass. A success string without a corresponding state change is not proof.

---

## Gate 0 Validation

Before writing the report, confirm all three conditions — adapted from the library's Gate 0 discipline to the source's proof standard.

1. **What can the attacker DO right now?**
   - Can you show a state-changing action completing *without* a valid CAPTCHA token (account created, login succeeded, form submitted)?
   - Have you captured the baseline-with-CAPTCHA alongside the bypass-without / bypass-with-invalid-CAPTCHA so the delta is explicit?
   - For a throughput gate: can you show the required number of requests landing inside the window with placeholder payloads?
   - "The form has a CAPTCHA field" is not a finding — show the action succeeding despite the field being absent, empty, replayed, or invalid.

2. **What does the victim LOSE?**
   - Removal of a brute-force gate on login → automated credential guessing → potential ATO (chain to `hunt-brute-force`, High/Critical).
   - Ungated registration → account farming, spam, resource exhaustion.
   - Ungated password reset → token flooding (chain to `hunt-forgot-password`).
   - Bypass alone, with no sensitive downstream action → **Medium** at most; quantify what the automation actually enables rather than scoring the widget.

3. **Can it be reproduced in 10 minutes from scratch?**
   - Is the omitted field name stable, and does the bypass request still succeed on a fresh run?
   - Does the baseline comparison hold (with-CAPTCHA vs without-CAPTCHA) reliably?
   - For replay: does a *newly* solved token still replay, or did the earlier result depend on a stale token?
   - For concurrency gates: does the burst reliably land N requests inside T seconds, with well-formed payloads, on repeat?
   - Can a second person follow the steps (GET form → capture field name → POST without it → verify state change) and get the same result?

### Gate 0 Summary Table

| Question | Minimum acceptable answer | Red flag |
|----------|---------------------------|----------|
| What can the attacker do? | A named state change completes without a valid CAPTCHA | Only a "success" string; no state change |
| What does the victim lose? | A concrete chain (brute force, farming, flooding) with a severity | "It bypasses a CAPTCHA" with no downstream effect |
| Reproducible in 10 minutes? | Fresh run repeats with stable field name and baseline delta | Depends on a stale token, flaky timing, or luck |

If any of the three cannot be answered affirmatively, resolve it before submission. A CAPTCHA bypass with no demonstrated downstream impact is a weak finding; a bypass that cannot be reproduced is a false positive.

---

## Real Impact Examples

The following are **scenarios** derived from the source skill's Impact Chain and testing patterns — not individual disclosed reports. No HackerOne IDs or URLs are claimed.

### Scenario A — Omitted Field on Registration → Account Farming

An application renders a CAPTCHA on `/register`; JavaScript disables the submit button until it is solved. GETting the form reveals the field `g-recaptcha-response`. A tester POSTs all registration fields *except* that field and receives a 200 plus a redirect; the account exists on login. A baseline POST with a valid token behaves identically. This is Pattern 1 / Root Cause 1: the UI gate was never enforced server-side. Impact per the source: **account farming** — automated bulk account creation for abuse, spam, and resource exhaustion (Medium on its own; raises if the accounts unlock further privileges).

### Scenario B — Ungated API Sibling on Login → Brute-Force Gate Removed

The web login form shows a CAPTCHA, but the mobile/API path for the same login action accepts credentials with no `captcha` field. Omitting the field still yields an authenticated session. Per the source's Impact Chain, CAPTCHA bypass on a login endpoint removes the brute-force gate and chains to `hunt-brute-force` at **High/Critical**. The bypass is not the end finding — it is the primitive that makes unbounded password guessing viable; the report should carry the full chain.

### Scenario C — Non-Single-Use Token → Replay Across Requests

A tester solves one legitimate challenge, captures the `g-recaptcha-response` token, and resubmits it immediately; the action succeeds again. The same token also succeeds on a different endpoint. Root Causes 2 and 3: the token is neither single-use nor bound to the action/session it was solved for. One human solve becomes a reusable token for an automated batch — converting a per-request human check into a one-time cost.

### Scenario D — Sliding-Window Throughput Gate Beaten by Concurrency

A "prove you're automated" check requires ~10 submissions within 20 seconds, counted by middleware at the route. A sequential attempt of 12 requests spread across ~250 seconds fails. After confirming required fields are present and the counter increments on requests reaching the route, a single concurrent burst with `concurrency >= 10` and placeholder CAPTCHA values succeeds. This is Pattern 5: garbage payloads work because the counter measures throughput, not outcomes. Impact depends on what the rate-limited action is — typically the same automation-enabling Medium that climbs with the protected action's sensitivity.

### Scenario E — Reactive CAPTCHA Reset on a Login Flow

A login form shows no CAPTCHA for the first few attempts and introduces one only after 3–5 failures. By resetting the state the failure counter keys on between batches, a tester keeps every attempt in the pre-CAPTCHA window and makes N−1 attempts per account indefinitely. Root Cause 4. Chained to `hunt-brute-force`, this removes the practical brute-force limit without ever needing to solve a challenge.

### Severity Rationale Table

| Scenario | Root cause(s) | Chain | Severity driver |
|----------|---------------|-------|-----------------|
| A — registration omission | 1 | Account farming | Medium; abuse/spam/resource exhaustion |
| B — login API sibling | 1 | `hunt-brute-force` | High/Critical — brute gate removed |
| C — token replay | 2, 3 | Automation batch | Medium base, scales with gated action |
| D — throughput burst | 4 | Automation of gated action | Medium base, scales with gated action |
| E — reactive reset | 4 | `hunt-brute-force` | High/Critical when login is gated |
| F — math CAPTCHA | 5 | Account farming | Medium; same class as Scenario A |

### Scenario F — Static Math CAPTCHA Answered Directly

A custom registration form asks `3 + 4 = ?` in a `captcha_answer` field. The challenge is clearly custom — not reCAPTCHA/hCaptcha — and the answer space is computable. Submitting the computed answer `7` creates the account. Root Cause 5. Because the answer is mechanically derivable, the challenge provides no bot resistance; impact is the same account-farming class as Scenario A, with the difference that the gate is "solved" rather than "omitted."

### Impact Ladder (from the source's Impact Chain)

```
CAPTCHA bypass alone                 → Medium (automation of rate-limited actions)
+ login endpoint                     → brute-force gate removed → hunt-brute-force → High/Critical
+ registration endpoint              → account farming → abuse, spam, resource exhaustion
+ password reset endpoint            → token flooding → hunt-forgot-password
(hunt-race-condition)                 → race the validation window before token revocation
```

---

## Source Skill Lineage

This skill is derived from exactly one curated source skill. Its unique contributions are listed below by skill path, as required — no report IDs are used because none were read at full-text level.

- **`hunt-skills/hunt-captcha-bypass/SKILL.md`** — the sole source. Unique contributions:
  - The **autonomous testing priority** ladder: omit the field, empty/null value, replay a solved token, test ungated sibling endpoints, and trigger rate/throughput gates — plus the explicit "skip real reCAPTCHA/hCaptcha solving" guidance and the proof standard.
  - The five **root causes**: client-side-only validation; token not tied to session/action; single-use not enforced; reactive CAPTCHA after N failures; static/predictable custom CAPTCHA.
  - The **impact chain**: bypass alone (Medium), plus login → brute force (High/Critical), registration → account farming, password reset → token flooding.
  - The **related skills**: `hunt-brute-force`, `hunt-forgot-password`, `hunt-race-condition`.
  - The **Pattern 5 timing note**: sliding-window counters require concurrent bursts (`concurrency: N`), not sequential pacing; check required fields so requests reach the counting middleware.

- **Full merged corpus (linked, not re-derived here):** `E:\webt\skill-setup\skills-extract-from-reports\hunt-captcha-bypass\references\source-knowledge.md`. This file holds the 8 unique sections from the 1 source skill verbatim and is the authoritative reference for all claims in this document.

### Source-Section → Output-Section Mapping

The digest contains 8 unique sections; each landed in this skill as follows:

| # | Source section | Where it appears here |
|---|----------------|------------------------|
| 1 | Autonomous Testing Priority (Patterns 1–5, skip, proof) | Discovery A/B/C; Step-by-Step; Payload & Detection; Bypass Techniques; Gate 0 |
| 2 | Client-Side-Only CAPTCHA Validation | Discovery A; Common Root Causes #1; Bypass Techniques |
| 3 | CAPTCHA Not Tied to Session or Action | Discovery B; Common Root Causes #2 |
| 4 | Single-Use Not Enforced | Discovery B; Common Root Causes #3 |
| 5 | CAPTCHA Added Reactively (Only After N Failures) | Discovery C; Common Root Causes #4 |
| 6 | Static or Predictable CAPTCHA | Discovery D; Common Root Causes #5 |
| 7 | Impact Chain | Crown Jewel Targets; Real Impact Examples; Gate 0; Related Skills & Chains |
| 8 | Related Skills | Related Skills & Chains |

Lineage note: because `source_skills: 1` and `report_count: 0`, there is no multi-source corroboration and no report-level evidence. All statements trace to the single path above; where this skill adds operational detail (step ordering, matrices, detection checklists, Gate 0 questions), that detail is a restructuring of the source's own testing steps and proof standard, not new external claims.

---

## Related Skills & Chains

From the source skill's Related Skills section:

- **`hunt-brute-force`** — CAPTCHA is often the only rate-limit gate; bypass unlocks brute force. Chain primitive: omit the CAPTCHA field on a login endpoint → automated password guessing → credential stuffing / ATO. This is the highest-severity chain in the source (High/Critical).

- **`hunt-forgot-password`** — reset endpoints are sometimes protected by CAPTCHA only. Chain primitive: bypass on the password-reset endpoint → token flooding → abuse of the reset flow.

- **`hunt-race-condition`** — race the CAPTCHA validation window: submit before the token is revoked. Chain primitive: non-single-use token plus a narrow revocation window → multiple accepted uses of one solved token.

### Chain Selection Guide

```
Bypassed surface          → primary chain
login                     → hunt-brute-force (High/Critical)
registration              → account farming (abuse / spam / resource exhaustion)
password reset            → hunt-forgot-password (token flooding)
single-use token + window → hunt-race-condition (submit before revocation)
throughput gate only      → automation-enabling Medium; chain by the gated action
```

### Cross-Skill Discipline

- Always carry the **baseline comparison** into the chained skill's report — the bypass is only meaningful relative to a request where the CAPTCHA was present and valid.
- Score the **downstream action**, not the widget: a bypass on a harmless action stays Medium; a bypass that removes the only gate on login or reset inherits that endpoint's severity.
- Do not claim programmatic solving of real reCAPTCHA/hCaptcha as part of a chain — the source reserves that for a last-resort, budget-dependent effort after Patterns 1–4 fail.
- Keep the root cause explicit when handing off: "not single-use" hands to a revocation fix; "not action-bound" hands to a context-binding fix; they are not the same bug.

---

**Summary.** This skill turns the single curated source into an actionable CAPTCHA/bot-check bypass workflow: learn the field name, capture a baseline, then attempt the fast ladder — omit the field, send empty/null values, replay a solved token, hit the ungated sibling endpoint — before classifying the gate as a challenge or a throughput counter and, for the latter, firing a concurrent burst. Its five root causes and three impact chains keep findings tied to the action being protected, with a Gate 0 standard that demands a demonstrated state change and a reproducible baseline comparison. All knowledge is grounded in the linked corpus; no report IDs or external URLs are fabricated.
