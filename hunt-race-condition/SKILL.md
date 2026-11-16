---
name: hunt-race-condition
description: Hunting skill for race conditions and TOCTOU vulnerabilities, built from the FULL TEXT of 67 disclosed public reports (87-report corpus, 71 from TOP lists) — mined technique-frequency tables, 40 highest-signal reports with verbatim payload excerpts, ~30 "how I found it" discovery clues, and 60 payload exemplars. Covers identical-copies limit-overrun races (Reverb gift-card 7× redemption, HackerOne duplicated $500 retest payments, Helium data-credit transfer, Cosmos/Starport faucet double-mint $5,000), different-requests state-machine races (email-verification bypass, 2FA bypass, OAuth token multiplication), vote/reputation inflation (HackerOne popular reports, Urban Dictionary), invitation/quota/folder/seat limit bypasses, flag-submission and loyalty-claim races, plus classic TOCTOU families (curl fopen/stat symlink races, HTTP/2 connection-reuse certificate revalidation bypass, SFTP upload-resume arbitrary append, GitLab import filename collision info disclosure, Rust remove_dir_all symlink attack, NordVPN local privilege escalation). Includes the modern HTTP/2 single-packet / last-byte-sync primitive (Kettle DEF CON 31), Turbo Intruder Engine.BURP2 templates, Flatt first-sequence-sync expansion to 10,000 requests, and Wireshark validation. Use when hunting any concurrency, check-then-act, double-spend, one-time-token, or time-of-check/time-of-use bug.
sources: hackerone_public, portswigger_research, flatt_security, internet_bug_bounty, github_writeups, public_code_search
report_count: 87
full_reports_read: 67
---

## Crown Jewel Targets

Race conditions and TOCTOU bugs are high-severity because they break financial, access-control, and integrity assumptions that defenders rarely stress-test. Across the 67 fully-read reports, `race-condition` appeared as a signal in 60 of them — the dominant primitive — followed by API endpoints (20), cookie-handling (17), comment-injection (17), server-side-rendering (17), search/filter/sort (16), and public-code-search (15). Rank targets by what the race lets the attacker *multiply or bypass*, not by how fancy the endpoint looks.

- **Monetary / credit systems** — the single highest-value class. Gift cards redeemed N× (#759247, Reverb: one $25 card → $175), duplicated retest/payout payments (#429026, #220445, HackerOne: a $500 payment sent twice), data credits transferred between orgs to mint free balance (#974892, Helium), loyalty bonuses claimed 50× (#331940, Vend), crypto faucets double-minted (#1438052, Cosmos/Starport, CVSS 9.3/$5,000), in-app purchase coin inflation (#801743, Reddit), and activation rewards paid per racing request (#509629, InnoGames: infinite diamonds). One-time survey credits (#165570, Slack: $100 → $200) and free-premium days (#1037430, Bumble: 3 → 9 days) are the same primitive at smaller scale.

- **Verification / OTP / 2FA / email-change state machines** — different-requests races where an object exists in a usable state mid-transition. Email-verification bypass via parallel email-change + OTP (#3020733, Malwarebytes), 2FA bypass by racing validation (#2598548, HackerOne), one-human-one-action verification check bypass (#2110030, Tools for Humanity), invitation tokens consumed twice (#119354, HackerOne; #300305, Partners Dashboard → arbitrary email confirmation → store ATO). These routinely escalate to ATO.

- **Account limits / quotas / "one per user" restrictions** — exceeded subscriber counts (#3221185, SingleStore), workspaces (#3226838, SingleStore), folder creation (#3104355, Dust), store locations (#413759, Shopify: 4-plan → 12 locations), free domains (#2616045, Automattic), seats (#1418419, Krisp), trial activations (#1087188, Weblate: 1 → 6 trials = 300,000 extra strings), and invitations (#1460373 FetLife; #115007, #148609 Keybase; #1108291 Enjin; #1285538 Omise).

- **Vote / reputation / ranking manipulation** — upvote inflation on popular reports (#146845, HackerOne), up/down votes (#183837, #152717, Urban Dictionary), "This Rocks"/love/react buttons (#474021 Rockstar; #996141 Figma), helpful indicators (#109485 Zendesk), comment likes (#1409913 Eternal; #1566017 Judge.me). Reputation here has real-world value: invitations, bounties, trending placement.

- **OAuth / session / token endpoints** — token and refresh-token races across 11 OAuth2 providers (#55140, Internet Bug Bounty: 6/11 vulnerable), multiple valid sessions per OAuth flow (#699112, Razer), GraphQL credential-claim races (#488985, HackerOne: multiple test credentials from one invite).

- **Deletion / file / filesystem TOCTOU** — the classic time-of-check/time-of-use family. `fopen()` stat-then-open symlink races (#2039870/#2078571, curl CVE-2023-32001; #3747959, `--skip-existing`), SFTP upload-resume STAT→OPEN arbitrary file append (#3432833, curl), `remove_dir_all()` symlink replacement (#1520931, Rust stdlib, $4,000), GitLab import filename collision leaking another user's import (#214028), undeletable group member from a double join (#604534), and client-side Marketo/Marketo-form `followUpUrl` hijack into `data:` on Safari (#381356).

- **Native / local privilege escalation and connection-trust TOCTOU** — HTTP/2 connection reuse that reuses a now-untrusted connection after CA-file change (#3335085, curl, High), NordVPN service validating a config path before OpenVPN loads a swapped file → LPE (#768110), `siglongjmp` shared-buffer data race (#1990421/#1929597, curl CVE-2023-28320), global `gss_context` SOCKS5 race (#3356088), shared DNS-cache and connection-pool data races (#3645361, #3638715), and Flash worker double-frees (#37240, #47227, #119657).

- **Rate-limit / DoS surfaces** — APIs with no rate limiting that execute unbounded parallel work (#249319, Federalist: 1,000 parallel `/v0/me` calls took down a local instance; #994051, Stripo). Rate limits are also the *gate* to bypass: 5-attempt PIN caps are beatable with Flatt's 10,000-request single-packet expansion.

**Best-paying asset types:** fintech and wallet apps, SaaS with credit/subscription models, social platforms with reputation systems, e-commerce checkout flows, OAuth/SSO token endpoints, and native libraries with shared caches. Payouts in the corpus: $5,000 (Cosmos faucet), $4,000 (Rust TOCTOU), $3,000 (Tools for Humanity), $2,000 (InnoGames), $500 (Shopify locations), $250 (Helium), plus the disproportionate reputational value of HackerOne's own race reports.

### Why races pay despite low "single-bug" severity

A single duplicated action looks minor; the value is in multiplication and repeatability. Three properties make a race high-severity:

- **Unbounded multiplication** — the same primitive that redeems a gift card 7× can redeem it 700× if the window holds; Vend's loyalty claim scaled to 50× in one request batch (#331940), and Bumble's premium days scaled with connection count (#1037430). Severity is a function of how many requests fit in the window, not of one observation.
- **Security-boundary crossing** — email verification, 2FA, invitation acceptance, and OAuth session flaws convert a "duplicate request" into account takeover (#3020733, #2598548, #119354, #699112). Always test whether the raced object is an auth gate.
- **Silent, delayed impact** — duplicated payments and emails surface days or weeks later (#429026), and native TOCTOU bugs can corrupt trust decisions (certificate reuse #3335085) with no visible application error at all.

When triage pushes back with "this only duplicates a cosmetic counter," answer with the concrete unit of value: dollars, credits, reputation that grants invitations, or an authentication decision that can be flipped.

---

## Attack Surface Signals

### URL / Endpoint Patterns to Hunt

```
/vote, /upvote, /downvote, /like, /love, /favorite, /helpful
/redeem, /redeem-coupon, /apply-coupon, /use-code, /claim, /loyalty/claim
/purchase, /checkout, /confirm-order, /pay, /verify_purchase
/transfer, /withdraw, /send-money, /data_credits/transfer_dc
/invite, /referral, /accept-invite, /users/invitation, /memberships
/upgrade, /activate, /trial, /free-domain, /free-premium, /gratis
/delete, /deactivate, /cancel, /remove, /group/post_join, /group/join
/follow, /subscribe, /submit-flag, /feedback, /hacker_reviews
/settings, /profile, /email, /confirm, /verify, /verify-pin, /verify-email
/graphql                          # claim / credentials / token mutations
/oauth/token, /access_token, /refresh_token, /requestAuthEmail
/api/data_credits/transfer_dc      # Helium #974892
/api/v2/gold/android/verify_purchase  # Reddit #801743
/api/internal/graphql/requestAuthEmail # Khan Academy #1293377
/settings/orgs/new                 # WakaTime #3248712
/cabinet/stripeapi/v1/projects/N/emails/folders  # Stripo #994051
/group/join?invite=                # CTF #604534, #1540969
/confirm, /activate                # email activation + reward (#509629)
/loyalty/claim/email/<token>       # Vend #331940
/faucet/transfer, /transfer        # Cosmos #1438052, Helium #974892
/gratis-trial, /trial              # Weblate #1087188
/verify-pin, /verify-otp           # Flatt first-sequence-sync target
/settings/orgs/new                 # WakaTime #3248712 uniqueness race
/users/invitation                  # FetLife #1460373
/follow                            # Staging.every.org #927384
/hacker_reviews                    # HackerOne #1132171 feedback race
```

### Response Headers & Behaviors That Signal Race-Prone Backends

```
X-RateLimit-*            # a limit exists -> it is a gate worth bypassing
X-Request-Id             # each request independently tracked, no idempotency key
No Cache-Control         # stateful ops not idempotent
200 + 200 where one 4xx expected   # the classic "race won" signature
{"status":"saved","up":6429,...} / {"up":6430,...}  # per-request counter reads (#183837)
"already used" / "already a member" / "limit reached" errors appearing only on SOME parallel replies
DB constraint / unique-index errors (signals the race worked but hit the last line of defense)
Response times: all similar = parallel dispatch; one fast, rest slow = serialized
"unable to verify" / "invalid token" on only part of a parallel batch
```

### JavaScript / Source Patterns to Grep

```javascript
// Client-side "protection" — never sufficient, always a hint to test the server
button.disabled = true
$('#btn').prop('disabled', true)
form.onSuccess(function(){ return false })   // Marketo #381356 — missing onSuccess = followUpUrl hijack
setState({ used: true })                      // optimistic UI
await useVoucher(); await deductBalance();    // sequential async, non-atomic
```

```bash
# Read-then-write without locking
grep -rn "find_by\|where.*first" --include="*.rb" | grep -v "lock"
grep -rn "SELECT.*WHERE" --include="*.php" | grep -v "FOR UPDATE"
grep -rn "\.get(\|\.filter(" --include="*.py" | grep -v "select_for_update"
grep -rn "await.*get\|await.*find" --include="*.js" -A2 | grep "await.*update\|await.*save"
# Token / one-time-flag flows
grep -rniE "token_used|used_at|consumed| redeemed|one.?time| nullifier|nonce" --include="*.rb" --include="*.py" --include="*.go" .
# Filesystem check-then-use
grep -rnE "stat\(|lstat\(|access\(|fopen\(|open\(|remove_dir_all|Curl_fopen" --include="*.c" --include="*.rs" .
```

### Tech-Stack Signals

- **Ruby on Rails / Devise / Doorkeeper** without `with_lock` / `lock!` — ActiveRecord does not lock by default; Devise built email-change confirmation tokens before persistence (GitLab CVE-2022-4037) and Doorkeeper-style OAuth token issuance raced across 6/11 tested providers (#55140).
- **Node.js / Python asyncio** with `await` read-then-write chains — non-atomic; also Node/Flash worker shared-object double-free families (#37240, #47227, #3752489).
- **PHP / legacy codebases** without `SELECT ... FOR UPDATE` — coupon/gift-card redemption staples (Reverb #759247, Instacart #157996).
- **Go** services with read-modify-write `Transfer` functions and no per-recipient lock (Cosmos/Starport #1438052).
- **Microservices / message queues** — Service A validates, Service B executes; no shared atomic transaction spans both; idempotency keys often missing.
- **Redis counters** without Lua scripts / `INCR` atomicity, and caches without invalidation ("has user voted?" returns stale false during a miss window).
- **Relational DBs at READ COMMITTED isolation** — a token-consumption flag committed in the "same" transaction can still be read as unused by a concurrent request (InnoGames #509629 pattern).
- **curl / libcurl / Rust stdlib / C SUID binaries** — `stat()`-then-`open()`, `--skip-existing`, SFTP resume, HTTP/2 connection pools, DNS caches, and `remove_dir_all()` are all documented TOCTOU sinks in this corpus.
- **Kubernetes apiserver proxy** — two DNS queries (one for filter validation, one for proxying) create a check/use gap (#859962).
- **GraphQL mutations that "claim" or "create"** — a single mutation that both checks eligibility and writes the credential is a one-request race; the HackerOne credential-claim report (#488985) used `POST /graphql` with an auth token and produced multiple test accounts.
- **Any counter exposed in the response** — endpoints that echo back the new count (`{"up":6429}`, `{"up":6430}` in #183837) give you a free per-request oracle: a counter that jumps by the size of your burst is proof the writes were not serialized.

### State-Machine Phrases in UI Copy

Hunt for these exact words in labels, errors, and docs — they mark the boundary a race can cross:

```
"once" / "one per user" / "first time" / "only one" / "already used"
"claim" / "redeem" / "activate" / "verify" / "accept" / "confirm"
"limited" / "remaining" / "limit reached" / "maximum" / "quota" / "seats"
"free" / "gratis" / "trial" / "bonus" / "reward" / "credit" / "payout"
"You already have ..." / "cannot be removed" / "invalid or expired token"
```

The last line is especially valuable: an "already used" error appearing on *only some* replies of a synchronized burst means the other replies won the race. That differential is the finding (#604534 produced an undeletable member this way).

---

## Discovery Patterns From 67 Full Reports

This section answers "how do researchers *actually find* these?" rather than "what is the payload?" Frequency numbers are counts of full reports containing that signal, from the study pack's mined frequency table.

### Where Researchers Start

Recon surfaces ranked by how often they appeared, with the concrete thing to look for at each:

| Rank | Recon surface | Reports | What to look for |
|------|---------------|---------|------------------|
| 1 | **Enumerate one-time / limited-use actions** | 60 (race-condition) | Walk every feature that says "once," "one per user," "claim," "redeem," "activate," "first time," "free," "limit," or "remaining." Reverb's gift-card redemption, Vend's loyalty claim, InnoGames' activation, Slack's survey, Bumble's free premium, and Weblate's trial all announce themselves in the UI copy (#759247, #331940, #509629, #165570, #1037430, #1087188). |
| 2 | **API / GraphQL endpoint inventory** | 20 (api-endpoint) | Map every state-changing POST/PUT with a coupon, token, email, invitee, vote, or balance field. GraphQL mutations that "claim credentials" are prime (#488985); internal GraphQL auth-email endpoints are too (#1293377). |
| 3 | **Cookie/session-bound state flows** | 17 (cookie-handling) | Actions whose authorization is tied to a session cookie or CSRF token but whose "used" check lives elsewhere. Verify you can replay the same cookie/token across parallel requests. |
| 4 | **Comment / feedback / review one-shot fields** | 17 (comment-injection) | "Send feedback once per report," "review app once," "comment like" — all raced in the corpus (#1132171, #106360, #1409913). |
| 5 | **Server-rendered / SSR stateful flows** | 17 (server-side-rendering) | Form submissions that create rows before a confirmation step (Marketo `followUpUrl` #381356; email-change pages). |
| 6 | **Search / filter / sort + popularity features** | 16 (search-filter-sort) | "Popular reports," trending, up/down votes, and "helpful" counters that accept a simple id + direction (#146845, #183837, #152717). |
| 7 | **Public code search / source review** | 15 (public-code-search) | Google/GitHub the open-source project and read the check-then-act code: Starport faucet `Transfer()` (#1438052), Rust `remove_dir_all()` (#1520931), NordVPN service path validation (#768110), curl `Curl_fopen`/`--skip-existing` (#2039870, #3747959), Kubernetes apiserver double DNS lookup (#859962). |
| 8 | **Image / file processing paths** | 14 (image-processing) | Upload, import, and export pipelines where a filename or path is checked then used (GitLab import collision #214028; curl SFTP resume #3432833). |
| 9 | **Cache-layer / rate-limit inspection** | 13 (cache-layer) | Look for `X-RateLimit-*`, "6/11 targets vulnerable" style gates (#55140), and stale cached "not used yet" answers. |
| 10 | **Prior-report regression mining** | 11 (filter-bypass) | Read already-disclosed races for the same program and retest the fix. The CTF group-join race was reported, "partially fixed," and re-reported (#604534 → #1540969). |
| 11 | **Internal / admin panels** | 10 (internal-network) | Console APIs that move credits or create org resources; Helium's `console.helium.com/api/data_credits/transfer_dc` (#974892). |
| 12 | **Blind OOB-adjacent / async flows** | 9 (blind-oob) | Actions whose result arrives later (a payment, a callback, an email). HackerOne retest payments only appeared weeks later (#429026). |
| 13 | **Session / token replay testing** | 9 (session-attack) | Invitation and activation tokens stored in the DB are consumable twice if consumption isn't atomic (#119354, #300305). |
| 14 | **DoS / no-rate-limit endpoints** | 9 (dos-resource) | Endpoints that happily execute 1,000 parallel requests (#249319, #994051) are both a resource bug and a perfect race test bed. |
| 15 | **JSON-body / GraphQL introspection** | 8 (json-body) | Hidden fields in JSON bodies (`{"name":"..."}` on Stripo #994051) and GraphQL mutations hide state changes from flat parameter scans. |
| 16 | **Timer / OTP / reset-flow review** | 3 (brute-otp-reset) | Confirmation and PIN endpoints whose cap is "N attempts per window" are the Flatt first-sequence-sync target; read the rate-limit implementation, not just the UI. |
| 17 | **Native diffing / memory-safety triage** | 5 (request-smuggling) + 5 (js-source-review) | Use Helgrind / ThreadSanitizer / AddressSanitizer on shared caches and worker-shared objects; the curl data races (#3356088, #3645361, #3638715) and Flash double-frees (#37240, #47227) were found this way. |

A practical note on ranking: the top two surfaces (one-time actions + API endpoints) account for the overwhelming majority of *web* races and should be exhausted before investing in the native/niche families. The native TOCTOU reports are fewer but carry the highest per-bug impact and the cleanest code-level proof.

### Feature-Based Discovery Signals

Frequency-ranked suspicious features and sinks from the same 67 reports — when you see the feature, run the probe:

| Signal | Reports | Why it matters / what to probe |
|--------|---------|--------------------------------|
| race-condition | 60 | The core primitive. Any read-then-write on shared state is a candidate — fire N identical copies and look for ≥2 successes. |
| api-endpoint | 20 | JSON/REST state-changing endpoints frequently lack atomicity. Probe every coupon/token/email/vote field with a synchronized burst. |
| cookie-handling | 17 | Session-bound "used" checks can be raced with the same session replayed in parallel. |
| comment-injection | 17 | One-shot feedback/review/comment-like fields are frequent double-submit targets (#1132171, #106360). |
| server-side-rendering | 17 | SSR form flows create the object before confirmation — the gap is the race (Marketo #381356). |
| search-filter-sort | 16 | Popularity/vote endpoints accept an id and a direction; trivial to replay in parallel (#146845, #183837). |
| public-code-search | 15 | Read the actual validation/consumption code in the project's public repo; it tells you *where* the lock is missing. |
| image-processing | 14 | Import/upload/export paths with filename checks before use — classic filesystem TOCTOU (#214028, #3432833). |
| cache-layer | 13 | Stale cached eligibility answers and rate-limit counters widen the window. |
| filter-bypass | 11 | A "one per user" filter is a gate; the race is a bypass when the check and the update are separate. |
| internal-network | 10 | Admin/console APIs that move money or credits are high-impact race targets (#974892). |
| blind-oob | 9 | Effects that arrive async (payments, emails) require patience to confirm — check statements/inbox days later (#429026). |
| session-attack | 9 | Reuse one session/token across the burst; do not use fresh sessions or you test a different user. |
| dos-resource | 9 | No-rate-limit endpoints let you fire 1,000 parallel requests — use that to overflow the worker pool (#249319). |
| json-body | 8 | Nested JSON and GraphQL bodies hide the mutable field; fuzz every string/number field. |
| xml-parser | 7 | Parsers that create resources mid-parse can expose a construction-window race. |
| csrf | 7 | Get a fresh CSRF/token first, then fire the burst; an exhausted CSRF can mask the bug. |
| url-fetching | 7 | Fetch-then-act flows can be raced between "URL validated" and "URL used" (Kubernetes #859962 DNS re-resolution). |
| proxy-feature | 7 | Proxy "one-time" tokens and credential claims can be duplicated (#157996 Instacart coupon via proxy). |
| import-feature | 7 | Filename collisions and mid-import state create info-disclosure races (#214028). |
| redirect-handling | 6 | Multi-step confirm flows (register → confirm) are the canonical different-requests race (#3020733). |
| debug-error-leak | 6 | Error strings like "already redeemed" only on *some* parallel replies are your success signal. |
| admin-internal | 6 | Admin-only "send once" actions (feedback on a report) still race (#1132171). |
| time-based | 6 | Timing tells you if the backend serializes (`T_par2 ≈ T_par1 + T_single`) or dispatches in parallel. |
| fuzzing-enumeration | 5 | Fuzz which parameters are consumed atomically; a counter that jumps by N is a hit. |
| request-smuggling | 5 | Multi-byte / pipelined requests can desynchronize the check and use paths. |
| js-source-review | 5 | Client-side disable (`button.disabled=true`) is a hint the server has no real guard. |
| sso-oauth | 5 | Token/refresh-token issuance is raceable across providers (#55140, #699112). |
| brute-otp-reset | 3 | OTP/email confirmation endpoints are classic construction-window and rate-limit races (#3020733, Flatt PIN attack). |
| mutation-polyglot | 1 | Rare, high-signal: one request shape doubled into two state transitions (GraphQL credential claim #488985). |
| base64-encoding | 1 | Rare in the race corpus; check encoded state tokens for reused nonces when the token is a client-supplied blob. |
| stored | 3 | Persisted "used/consumed" flags are the object of the race; read them back after the burst, do not trust the response body. |
| error-based | 2 | Distinct error strings across parallel replies reveal which requests won (#604534, #331940). |
| auth-bypass | 1 | Email-verification and 2FA races convert a timing bug into authentication bypass (#3020733, #2598548). |
| file-upload | 2 | Import/upload paths with filename checks before processing are the filesystem TOCTOU entry (#214028, #3432833). |
| internal-network | 10 | Admin/console APIs move credits and resources; high blast radius when raced (#974892, #994051). |

Read the table as a decision aid: if a target shows several of the top signals together — say `api-endpoint` + `cookie-handling` + `json-body` + a one-time action — prioritize it. The corpus repeatedly shows that the winning report is the one that combined a synchronized-send primitive with a state-changing endpoint whose "used" check was a separate DB read.

### Verbatim Discovery Clues

Real, lightly cleaned quotes showing exactly how researchers noticed the bug. Attribution is the HackerOne report ID.

1. [#759247] "I've found a Race Condition vulnerability which allows to redeem gift cards multiple times."
2. [#759247] "In my case I bought one gift card which was worth of 25$ and as we can see from the picture I was able to redeem it 7 times which makes 25*7 = 175$."
3. [#381356] "By doing this I was then able to steal the data being submitted."
4. [#604534] "I did it for 5 parallel requests and I was able to add myself 2 times to that group:"
5. [#331940] "I tried it a couple times with two unique users, sometimes its a 100% race, ie"
6. [#454949] "Go to the submit page, put the Flag that was found and intercept the POST request that is sent during the Flag submission."
7. [#974892] "i found an way to add data credits for free by doing race condition of transfering data credits using turbo intruder of burpsuite"
8. [#1438052] "We were testing an application and we found a race condition bug in the faucet Implementation of Starport."
9. [#1037430] "But when user choose to get free 3 day premium he can click `Get free Badoo Premium` and can enjoy free premium for three days, Here i found a race condition vulnerability through which i was able to get more than three days of premium."
10. [#488985] "I was invited to a private program and I tried to get test credentials so a request as follows was sent to your server:"
11. [#488985] "in this case I was able to have multiple test credentials and maybe block another user from getting a test account if the program provided a limited amount of test accounts."
12. [#157996] "For example, I found the code 'dallas20'."
13. [#1285538] "I've found a race condition vulnerability which allows the invitation of the same member multiple times to a single team via the dashboard."
14. [#3335085] "During the initial handshake, `libcurl` correctly validates the server's certificate against the user-provided CA bundle."
15. [#249319] "I discovered that the Federalist API doesn't have rate limiting in place, and executes any amount of request to the endpoint in parallel mode."
16. [#119354] "Further to my last two comments on report #118312 and realizing that tokens are being stored in the DB, I realized there is probably a race condition vulnerability which allows invitation tokens to be consumed at least twice depending on the server/database response time."
17. [#300305] "This is possible because I found a way to confirm arbitrary emails."
18. [#413759] "@zhurig found a race condition where it was possible to bypass the limit for the number of locations a store can have by submitting multiple requests at once."

### Probe Checklist

Copy-pasteable actions derived from the clues above. Run them against one target at a time and isolate variables.

1. **Confirm parallel dispatch first**: time one request (`T_single`), then two sequential, then two concurrent on the same connection. If `T_par1 ≈ T_par2 ≈ T_single`, the server dispatches in parallel — single-packet will help a lot; if `T_par2 ≈ T_par1 + T_single`, it serializes.
2. **Verify HTTP/2 availability**: `curl -sI --http2 https://TARGET | grep -i "HTTP/2\|h2"` — the last-byte-sync attack needs `h2` in ALPN.
3. **Identical-copies limit-overrun**: fire 20–30 identical copies of the redeem/vote/claim request via Turbo Intruder `Engine.BURP2` + `gate`/`openGate`; success = ≥2 responses that should have been mutually exclusive (#759247, #183837).
4. **Bash parallel proof-of-concept**: `for i in $(seq 1 10); do curl -s -o /dev/null -w "%{http_code}\n" -b 'session=YOUR_SESSION' -X POST "https://TARGET/redeem" -d 'code=GIFT50' & done; wait` (the `(cmd) & (cmd)` pattern from #429026, #165570, #152717).
5. **Add the Turbo Intruder marker header**: set `x-request: %s` on the intercepted request before sending to Turbo Intruder (used in #759247, #927384, #1293377, #1540969).
6. **Different-requests / partial-construction race (email verification)**: Request A `POST /register` with attacker email; Request B `GET /confirm?token=` (empty); fire together ~20 rounds; then log in and perform the objective (#3020733-style state-machine race).
7. **Email-change OTP race**: send two Repeater requests — one changing email to the victim address, one to the attacker address — with "Send group in parallel"; both receive the *same* OTP; replay confirmation with the victim email (#3020733).
8. **One-time token double-consume**: open two browsers with two logged-in users and accept the same invitation link quickly; confirm two accounts authenticate on one token (#119354).
9. **Get a fresh CSRF/token before the burst**: `GET /register` or `/settings` first, then reuse that token across all parallel requests — an exhausted CSRF masks the bug.
10. **Replay with the SAME session cookie**: do not rotate sessions between parallel requests, or you test different users rather than racing one user's constraint.
11. **Deduct-after-credit check**: capture a credit transfer request (e.g. `POST /api/data_credits/transfer_dc`), fire 20 parallel transfers from Org A → Org B, then read the resulting balances — did A lose only once while B gained N×? (#974892).
12. **Check the actual state after the burst**: re-read the coupon/vote/balance/limit; count increments and compare with the number of 2xx responses. Per-request counter reads (`{"up":6429}` → `{"up":6430}`) are direct evidence (#183837).
13. **Decreasing-parallelism reproducibility**: rerun at N = 20, 10, 5, 3, 2 to measure how tight the window is; document success rate across 5 attempts.
14. **Filesystem TOCTOU (when source is available)**: replace the checked file with a symlink between `stat()`/`access()` and `open()`; for SFTP resume set `CURLOPT_RESUME_FROM = -1` then swap the target for a symlink and append past EOF (#3432833, #2039870, #3747959).
15. **Rate-limit / OTP window burst**: when a 5-attempt cap guards a PIN/OTP, pre-stage all guesses with valid tokens and release them in one synchronized window — the classic Flatt first-sequence-sync scenario (up to ~10,000 requests in ~166 ms).

---

## Step-by-Step Hunting Methodology

1. **Enumerate one-time or limited-use actions.** Map every endpoint enforcing "once per user," "limited quantity," "deduct balance," "first activation," or "one invitation." These are the primary targets. Use the "Where Researchers Start" table as a checklist.

2. **Understand the state machine.** For each target write down: (a) what state is read (used flag, balance, count, token, row existence), (b) what state is written, (c) what validation sits between read and write. The gap between read and write is your window. Ask: is this a check-then-act (single action duplicated) or a partial-construction race (object usable mid-creation)?

3. **Capture a clean baseline request.** Perform the action once legitimately with Burp intercepting. Confirm expected behavior: coupon marked used, vote counted once, credit debited once. Note the exact success and "already used" response bodies — you will compare parallel replies against these.

4. **Determine whether the server parallelizes.** Use the timing method (Step 1 of the Probe Checklist) and `curl -sI --http2`. If the backend serializes everything, prefer wide-window HTTP/1.1 pipelining against slow endpoints; if it parallelizes, use the single-packet attack.

5. **Set up synchronized request tooling.** Choose one:
   - **Burp Repeater "Send group in parallel"** — quick check, uses HTTP/2 single-packet when available (used in #3020733).
   - **Turbo Intruder `engine=Engine.BURP2`** with `gate='race1'` / `openGate('race1')` — the reliable default (used in #759247, #927384, #1540969, #1285538, #974892).
   - **`curl` backgrounding / Race The Web / Python asyncio** — no setup, wide window (used in #429026, #1460373, #183837, #454949).
   - **Flatt first-sequence-sync** — only when you need N > 30 (PIN/OTP exhaustion inside a rate-limit window).

6. **Execute the race with the right shape:**
   - *Identical copies*: N identical requests for limit-overrun / double-spend.
   - *Different requests*: a list of different requests fired in one window, repeated over rounds — for register-then-confirm, email-change, token-claim, and other TOCTOU state-machine races. Pre-stage a fresh CSRF/token first.

7. **Analyze responses.** Look for multiple 200 OK where only one should succeed; duplicate success messages; "already used" on only *some* replies; DB constraint errors (the race worked but hit the last defense); and consistent response times (parallel processing) vs staggered (serialized).

8. **Verify the real-world effect, not just the response.** Re-read the coupon status, vote count, wallet balance, invite quota, or account state. The HackerOne retest case (#429026) only became undeniable when a second $500 payment actually landed in the bank weeks later.

9. **Determine the exploitability window.** Decrease parallelism and count successes. A bug that needs exactly 30 simultaneous requests and lands 1/20 times is weaker than one that works with 2 requests reliably. Document success rate across 5 independent attempts.

10. **Test across account types and conditions.** Some races only fire for new accounts, specific tiers, or under load. Vend noted "100% race" sometimes and lower yields at other times depending on load and latency (#331940). Test both fresh and aged accounts.

11. **For native/TOCTOU bugs, demonstrate the check/use gap in code.** Show the `stat()`/`access()` call and the later `open()`/`rename()` with no lock or fd held; swap the path between them (symlink or replace) and show the unintended file affected (`#2039870`, `#3432833`, `#1520931`, `#214028`, `#768110`).

12. **Do not claim "race condition" from two near-simultaneous successes in Burp Repeater's HTTP/1.1 pipelining mode** — triagers downgrade it. For high-value claims, deliver a PoC video of Turbo Intruder firing **plus** a Wireshark capture showing all N END_STREAM frames in one TCP segment **plus** N mutually-exclusive successes.

13. **Retest the fix as a new finding.** The CTF group-join race was re-reported after a partial fix (#604534 → #1540969), and the Node/Flash double-free family and curl `fopen` race each spawned follow-up CVEs. After a patch, re-check the specific lock or ordering the vendor added.

14. **Run the negative control.** Fire the same burst at an endpoint that *should* be protected (or with a forged/invalid token). Exactly one success there is what makes your positive result credible and tells the client the fix belongs in the atomicity of the state transition, not in the transport.

15. **Watch for async confirmation before closing the tab.** Payments, payouts, emails, and queued fulfillment may land minutes or weeks later (#429026). Record the request IDs and check the external channel (bank statement, inbox, payment history) before declaring a null result.

16. **Run Gate 0 before writing.** If the PoC needs luck, a specific session state, or perfect timing, make it deterministic first.

---

## Payload & Detection Patterns

### Firing a race — two primitives (tooling-agnostic)

Winning a race needs requests that arrive in the *same* narrow window — sequential sends never work. Use a single-packet / synchronized-send tool. Two shapes:

- **Identical-copies race** — fire N IDENTICAL copies of one request at once (limit-overrun: double-spend a coupon/gift card, exceed a one-per-user quota). Success = ≥2 of the N return 2xx.
- **Different-requests race (partial construction)** — fire a LIST of DIFFERENT requests in one synchronized window, repeated over several rounds. For register-then-confirm / TOCTOU races where the object exists in a usable state mid-creation:
  ```
  Request A:  POST /register   body: csrf=<csrf>&username=hacker&email=anything@exploit.net&password=pw
  Request B:  GET  /confirm    params: token=   (empty)
  Fire A and B together, repeat ~20 rounds.
  ```
  Get a fresh CSRF from `GET /register` first, then fire the batch. The blank-token confirm wins during the window where the user row exists but its verification token isn't set yet.

### Turbo Intruder — Engine.BURP2 single-packet race

```python
# turbo_intruder_race.py — identical-copies limit-overrun
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,      # one TCP connection, multiplex all H2 streams
        requestsPerConnection=100,    # >30 needs Flatt extension
        engine=Engine.BURP2,          # THE critical line: HTTP/2 last-byte-sync
        pipeline=False,               # pipelining is HTTP/1.1 only
    )
    for i in range(30):
        engine.queue(target.req, gate='race1')   # withhold last byte
    engine.openGate('race1')          # release all final bytes in one TCP write
    engine.complete(timeout=10)

def handleResponse(req, interesting):
    if req.code in (200, 201):
        table.add(req)
```

For the Reverb/turbo-intruder class (#759247), add the marker header `x-request: %s` to the intercepted request and use `engine.queue(target.req, str(i), gate='race1')` with `concurrentConnections=30` (#927384 style).

### curl — parallel identical-copies burst

```bash
# 10 simultaneous redeem/invite/vote requests (#1460373, #429026, #165570)
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST "https://TARGET/redeem" \
    -b 'session=YOUR_SESSION' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d 'authenticity_token=<CSRF>&token=GIFT50&commit=Redeem+Now' &
done
wait
# bash chained form: (curl_cmd_1) & (curl_cmd_2) & ... & (curl_cmd_10)
```

### Python asyncio race

```python
import asyncio, aiohttp

async def race_request(session, url, payload, headers):
    async with session.post(url, data=payload, headers=headers) as r:
        return r.status, (await r.text())[:120]

async def main():
    url = "https://TARGET/redeem"
    payload = {"code": "GIFT50"}
    headers = {"Cookie": "session=YOUR_SESSION"}
    async with aiohttp.ClientSession() as s:
        tasks = [race_request(s, url, payload, headers) for _ in range(20)]
        results = await asyncio.gather(*tasks)
    for status, body in results:
        print(status, body)

asyncio.run(main())
```

### Email-verification / email-change parallel race (#3020733)

```http
POST /settings/email HTTP/1.1
Host: my.target
Cookie: session=ATTACKER_SESSION
X-CSRF-Token: <fresh-csrf>

email=victim@target.com        ← Request 1 (change to victim email)
```
```http
POST /settings/email HTTP/1.1
Host: my.target
Cookie: session=ATTACKER_SESSION
X-CSRF-Token: <fresh-csrf>

email=attacker@target.com      ← Request 2 (change to attacker email)
```
Send both with Repeater "Send group in parallel." Both addresses receive the same OTP; replay the confirmation with the victim email → victim email verified on the attacker-controlled flow.

### OAuth token / refresh-token race probe (#55140)

```
Fire N concurrent requests to the token endpoint with the same authorization code / refresh token.
Signature of success: ≥2 requests return a VALID access_token, or all concurrent requests return
the SAME access_token + refresh_token pair for one code.
11 OAuth2 services tested: 6 vulnerable, 4 vulnerable-but-protected, 1 protected (#55140).
```

### Invitation / one-time-token double-consume (#119354, #300305)

```
Two browsers, two logged-in users, same invitation link, click Accept quickly in both.
Both accounts authenticate on one invite token (#119354).
Partners Dashboard: create a partner account with a business email matching an employee's,
then confirm arbitrary emails via the race → take over the employee/collaborator account (#300305).
```

### Different-requests race — register-then-confirm full flow

A construction-window race needs the two requests to land while the object exists but its
verification token is not yet set. Repeat the whole batch ~20 rounds:

```
Request A:  POST /register   body: csrf=<csrf>&username=hacker&email=anything@exploit.net&password=pw
Request B:  GET  /confirm    params: token=   (empty)
```

1. `GET /register` first to harvest a fresh CSRF token.
2. Queue A and B into the same `gate` in Turbo Intruder; `openGate`, then `complete(timeout=10)`.
3. Repeat 20 rounds. The blank-token confirm wins during the window where the user row exists
   but its verification token is NULL.
4. Log in as the new account and perform the objective — e.g. a state-changing admin action.

The same shape applies to "claim credentials" flows (#488985) and to store-location / folder
creation limit bypasses (#413759, #3104355): one request creates, the parallel sibling uses the
not-yet-counted resource.

### Counter-inflation response-diff harness (#183837, #146845)

```python
import re, asyncio, aiohttp
async def one(session):
    async with session.post("https://TARGET/api/vote",
                            json={"id": 12345, "direction": "up"},
                            headers={"Cookie": "session=YOUR_SESSION"}) as r:
        return (r.status, await r.text())
async def main():
    async with aiohttp.ClientSession() as s:
        results = await asyncio.gather(*[one(s) for _ in range(20)])
    counts = [re.search(r'"up":(\d+)', body) for _, body in results]
    nums = [int(m.group(1)) for m in counts if m]
    print("statuses:", [st for st, _ in results])
    print("up count progression:", nums)
    # Baseline = 6429. If the burst yields 6430, 6431, ... each request authored a new vote.
asyncio.run(main())
```

A flat count with a single increment means the race was lost (serialized or locked). A staircase
of +1 per success is direct evidence of a non-atomic `UPDATE`.

### Quota / trial / free-item limit-overrun burst (#413759, #1087188, #2616045, #3104355)

```bash
# Shopify #413759: 4-location plan -> 12 locations
# Weblate #1087188: 1 trial -> 6 trials (300,000 extra strings)
# Automattic #2616045: one free domain -> multiple domains
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST "https://TARGET/settings/orgs/new" \
    -b 'session=YOUR_SESSION' -H 'Content-Type: application/json' \
    -d '{"name":"ctrl2"}' &
done
wait
# Then enumerate the created objects and compare with the plan limit.
```

### Rate-limit / OTP window expansion (Flatt first-sequence-sync)

```text
Goal: beat a 5-attempts-per-window cap on a 4-6 digit PIN (~10^6 candidates).
Standard single-packet caps at N≈30 (MTU + TLS record limits) — far too few.
Flatt extension (RyotaK, Aug 2024):
  - IP-fragment a single logical packet across multiple physical fragments
  - synchronize TCP SEQ numbers across multiple connections (lockstep TLS handshakes)
  - deliver ~10,000 requests in 166 ms, all inside one rate-limit window
Result: ~100 windows suffice instead of ~200,000. Working PoC at the Flatt Security URL
referenced in the HTTP/2 Single-Packet Attack deep-reference subsection below.
```

### Native / filesystem TOCTOU probes

```c
/* Check-then-use gap (curl fopen CVE-2023-32001, #2039870; --skip-existing #3747959) */
if (stat(filename, &sb) == -1 || !S_ISREG(sb.st_mode)) { /* decide to create/write */ }
/* ...swap filename for a symlink here... */
fp = fopen(filename, "w");   /* follows the symlink, no fd bound to the stat() decision */
```
```text
# SFTP upload resume (#3432833): CURLOPT_RESUME_FROM=-1
# 1) libcurl STATs the remote file to get the size/offset
# 2) attacker replaces the target file with a symlink
# 3) libcurl OPENs without O_TRUNC, seeks to the old offset, appends to the symlink target
# Result: arbitrary data appended to a file the user can write but did not intend to modify
```
```text
# Rust std::fs::remove_dir_all() symlink swap (#1520931)
# Function promises not to follow symlinks, but the check and the removal are separate —
# replace a child directory with a symlink between the two and it removes the symlink target.
# NordVPN LPE (#768110): pass arbitrary path via DomainName; service validates the OpenVPN
# config before launch, then the file is swapped before OpenVPN reads it → user-supplied config.
```

### HTTP/2 Single-Packet Attack — Deep Reference

The single-packet attack is the most important race technique published since 2020. It collapses the window from "tens of milliseconds with TCP-handshake jitter" to "the time the server's worker pool takes to dispatch N pre-buffered requests" — typically **under 1 ms**.

Original research: **James Kettle, PortSwigger — "Smashing the State Machine" (DEF CON 31, August 2023)**, portswigger.net/research/smashing-the-state-machine. 2024 extension: **RyotaK / Flatt Security — "Beyond the Limit: Expanding Single-Packet Race Condition with First Sequence Sync"**, flatt.tech/research/posts/beyond-the-limit-expanding-single-packet-race-condition-with-first-sequence-sync/.

**Why it works:** HTTP/2 multiplexes N requests over ONE TCP connection as one TLS record. Send each request's HEADERS frame and a DATA frame containing all but the last byte; the server cannot dispatch because END_STREAM hasn't fired. Buffer all N this way, then **release all N final bytes in a single TCP write**. They cross the wire in one IP packet (if < MTU ~1500 bytes); the kernel hands all N to the parser in one scheduler tick. The window becomes the application's own atomicity gap.

**Last-byte-sync mechanic:** (1) open one H2 connection; (2) for each request send HEADERS + all-but-last-byte of body, no END_STREAM; (3) repeat for all N; (4) in one TCP write send N 1-byte DATA frames with END_STREAM; (5) server dispatches N workers in microseconds.

**Wireshark validation:** capture egress during the attack (`tcpdump -i <iface> -w race.pcap port 443`), filter `tls and tcp.port == 443`, and confirm the flush is **N H2 DATA frames with END_STREAM in one TLS record, in one TCP segment**. N TLS records or N TCP segments means your tool is sequencing — the window is too wide.

**h2.0 single-frame vs h2.cl multi-frame:** h2.0 is pure HTTP/2 end-to-end (default). h2.cl is front-end h2 downgrading to back-end h1, with `Content-Length` confusion emitting two h1 requests — smuggling-adjacent, pairs with `hunt-http-smuggling`. Detect via `curl -sI --http2`.

**N rule of thumb:** start with N=30 for single-packet h2; increase to 100+ when `T_single < 10 ms`; up to 10,000 with Flatt's first-sequence-sync (synchronized TCP SEQ across multiple connections, demonstrated 10,000 req / 166 ms inside a 5-attempt PIN cap).

**Operator playbook:**
| Scenario | Tool / variant |
|---|---|
| H2 target, body < 1400 bytes, N ≤ 30 | Turbo Intruder `Engine.BURP2` single-packet — default |
| Same but body > MTU | Multi-connection H2; widen window ~5 ms |
| HTTP/1.1 only | `curl` parallel pipeline; wide window, slow servers only |
| Need N > 30 (PIN/OTP) | Flatt first-sequence-sync extension |
| Front-end h2, back-end h1 | h2.cl smuggling variant |

### Grep Patterns for Source-Code Auditing

```bash
grep -rn "find_by\|where.*first" --include="*.rb" | grep -v "lock"
grep -rn "SELECT.*WHERE" --include="*.php" | grep -v "FOR UPDATE"
grep -rn "\.get(\|\.filter(" --include="*.py" | grep -v "select_for_update"
grep -rn "await.*get\|await.*find" --include="*.js" -A2 | grep "await.*update\|await.*save"
grep -rniE "token_used|consumed|redeemed|one.?time|nullifier|nonce" --include="*.rb" --include="*.py" --include="*.go" .
grep -rnE "stat\(|lstat\(|access\(|fopen\(|remove_dir_all|Curl_fopen|RESUME_FROM" --include="*.c" --include="*.rs" .
```

### Parameter / Field Discovery

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -u "https://TARGET/api/endpoint?FUZZ=<valid-limit-token>" -fs 0 -mc all
# Then send the discovered field into a 30-request synchronized burst and diff the state.
```

---

## Common Root Causes

1. **Check-then-act without atomic operations** — read state (`if voucher.used == false`), then write state (`voucher.update(used: true)`) in two operations. Any parallel thread reads the same "unused" state before either writes.

2. **Missing database-level locking** — ORM `find`/`filter` instead of `SELECT ... FOR UPDATE`; the fix is one line but developers rarely think about concurrency.

3. **Consumption flag committed at too low an isolation level** — reward granted in the "same" transaction as the `token_used` flag, but READ COMMITTED lets a second request see the flag as unused (#509629).

4. **Counters incremented outside transactions** — `votes_count += 1; save()` instead of atomic `UPDATE ... SET votes = votes + 1 WHERE id = ?` (#183837, #146845).

5. **Client-side "protection"** — button disabled in JavaScript after first click; server-side logic never hardened. Marketo's missing `onSuccess` handler let `followUpUrl` hijack navigation (#381356).

6. **Token / invite stored in DB and consumed non-atomically** — two accounts authenticate on one invite (#119354); arbitrary emails confirmed via a partner flow (#300305); multiple test credentials claimed from one invite (#488985).

7. **Microservice TOCTOU** — Service A validates eligibility, Service B executes; no shared atomic transaction spans both. Helium's transfer-credit flow minted free balance (#974892).

8. **Async background jobs / queued fulfillment** — eligibility checked synchronously, reward sent asynchronously; a second request passes the check before the first job completes (#429026 retest payments; #220445 duplicate payouts).

9. **Caching without invalidation** — cached "has user voted / claimed?" returns stale false during a miss window; rate-limit counters read stale for a whole batch (Flatt PIN attack).

10. **Filesystem check-then-use with no fd/lock held** — `stat()`/`access()` then `open()`/`rename()`; symlink swapped in between (#2039870, #3747959, #3432833, #1520931). Filenames used as collision keys before import processing (#214028).

11. **Trust carried over past the check (connection/file reuse)** — an HTTP/2 connection validated at handshake is reused after the CA file changed (#3335085); a config file validated before launch is swapped before use (#768110); an apiserver resolves DNS once for filter validation and again for proxying (#859962).

12. **No rate limiting at all** — 1,000 parallel requests execute (#249319, #994051); makes both a DoS and a perfect race test bed.

13. **Gravity ignored until after payment/email** — effects that arrive async are hard to notice; HackerOne's duplicated $500 payment was only observed weeks later in a bank statement (#429026).

14. **Uniqueness enforced only in the UI** — creating a second org with the same name errors normally, but parallel requests bypass it (#3248712); the same pattern appears in folder/location/workspace limit bypasses (#413759, #3104355, #3226838).

15. **Shared mutable state without synchronization in native code** — global buffers, DNS caches, connection pools, and worker-shared objects race: `siglongjmp` buffer (#1990421), `gss_context` (#3356088), DNS cache refcount (#3645361), hostname swap (#3638715), Flash worker bytearray double-free (#37240, #47227, #119657).

16. **Uniqueness checked by count instead of enforced by constraint** — "how many orgs/locations/domains does this user have?" is a read; a concurrent batch all read the same count below the limit (#3248712, #413759, #3221185). The only real fix is a unique index or an atomic increment with a conditional update.

17. **Trusting a value that is validated in a different request** — the confirm step trusts the email/token value written by the register step; because the two are separate requests, a parallel pair can cross-write them and route the OTP to the wrong address (#3020733) or confirm an arbitrary email (#300305).

18. **No idempotency on "send reward" side effects** — the action's side effect (payment, email, trial grant, credit) is dispatched per request and deduplicated only after completion, so a burst creates N side effects before the dedupe flag flips (#429026, #220445, #1087188).

---

## Bypass Techniques

### What Defenders Implement (and How to Bypass)

**Defense: per-user rate limiting / "5 attempts" cap**
- Bypass: limits are checked before the action executes; fire requests simultaneously so all pass before any is counted. Flatt's first-sequence-sync delivered ~10,000 guesses in 166 ms inside a 5-attempt window.

**Defense: idempotency keys / unique request tokens**
- Bypass: if the server generates or reuses the token, send parallel requests without it, or race the uniqueness check itself. GraphQL credential claims produced multiple test accounts from one invite (#488985).

**Defense: database unique constraints**
- Bypass: the constraint catches duplicates *after* the race; the first two may both succeed before enforcement. Look for partial fulfillment — one succeeds, one errors, but both are honored — and for "undeletable" states like the double group member (#604534).

**Defense: application-layer mutex / locks**
- Bypass: distributed systems on multiple app servers don't share in-process locks. Send requests through different CDN nodes / load-balanced servers; a lock held in one process does nothing for another.

**Defense: "already used" checks in application code**
- Bypass: the check and the update are separate; both racing requests pass before either update completes. Only atomic `UPDATE ... WHERE used=false RETURNING id` truly prevents it.

**Defense: CSRF tokens / form tokens**
- Bypass: fetch a fresh token first, then reuse that single valid token across the whole burst; token exhaustion otherwise masks the bug.

**Defense: short token validity / expiry windows**
- Bypass: pre-stage all requests with valid tokens and release them in one H2 single-packet frame so all land in the same scheduler slot and the same validity window.

### Synchronization / Delivery Bypasses

- **Same session, same token, same instant** — never rotate cookies or CSRF between racing requests; you are testing one user's constraint, not many users' independence.
- **Mixed paths to defeat per-node locks** — route half the burst through one CDN edge, half through another, to test distributed (non-shared) locks.
- **Large bodies** — if the request body exceeds MTU, the single packet fragments; use multi-connection H2 and widen the window estimate, or reduce the body.
- **No h2 ALPN** — fall back to HTTP/1.1 pipelining/parallel connections; viable only on slow endpoints where the wide window still fits inside the check/use gap.
- **Marketo-style client-side race** — a form without an `onSuccess` handler lets a `postMessage` `followUpUrl` drive `location.href` into a `data:` URL in Safari (#381356); test browser-side races too, not just server-side.

### TOCTOU / Filesystem Bypasses

- **Symlink swap between check and use** — replace the checked path with a symlink before `open()`/`fopen()`; for resume appends (no `O_TRUNC`) the write lands in an unintended file (#3432833, #2039870).
- **`.` / `..` and filename collisions** — two imports uploaded with the same original filename race before the import job processes them, giving one user access to another's import file (#214028).
- **Swap after validation** — config file, CA bundle, or DNS answer changed after the check but before use (#3335085, #768110, #859962).
- **Double DNS resolution** — rotate a 0-TTL record between the validation lookup and the actual connection (Kubernetes apiserver proxy #859962; canonical SSRF/DNS-rebinding sibling).
- **Partial-construction window** — register/confirm, create/verify, and email-change flows where the row exists but its verification token isn't set yet; fire the confirm with an empty token (#3020733).

### Escalating the Finding

- A duplicated vote is only "integrity loss" if the counter has value — tie it to reputation, invitations, bounties, or trending (#146845).
- A duplicated payment or credit is direct financial loss — show the balance or the bank statement (#429026, #974892).
- An email-verification bypass is ATO — show that the victim email is now verified on an attacker-controlled account (#3020733, #300305).
- A filesystem TOCTOU is LPE or arbitrary file write — show the unintended file modified or the privileged process launched with attacker config (#2039870, #768110).

### When a race is NOT a finding — never-submit list

- **Two 200s with no state change.** If the coupon is still unused and the balance unchanged, the "duplicates" were idempotent successes — not a bug.
- **Different users, different sessions.** If your burst rotated cookies/CSRF tokens, you tested independent requests, not a race on one constraint.
- **HTTP/1.1 pipelining in Repeater "parallel" mode** with millisecond spread and no single-packet proof — high false-positive rate; triagers downgrade it.
- **A counter that increments legitimately per request** (e.g. a view counter) has no one-per-user invariant — no value, no finding. WakaTime's "multiple orgs with the same name" was explicitly closed as `Not a Vuln` (#3248712) because no real constraint was broken.
- **Backend truly serializes with a transaction/row lock** — the window estimation step exists to filter these out before you spend hours on a PoC.
- **Requires impossible timing or a privileged local precondition you cannot demonstrate** — state it honestly or keep hunting. The honest scoping in the resolver reports (#287245-style) is the correct model.

---

## Gate 0 Validation

Before writing the report, confirm all three:

1. **What can the attacker DO right now?**
   - Can you demonstrate — with screenshots, logs, or state dumps — that the same one-time action succeeded more than once? (vote count +N from one user, balance credited N×, coupon redeemed N times, limit exceeded.)
   - For partial-construction races: can you show the victim email verified / account authenticated / token consumed twice? (#3020733, #119354.)
   - For TOCTOU: can you show the check/use gap in code and the unintended file/connection/config actually affected? (#2039870, #3335085, #214028.)
   - "Two requests returned 200" is not enough if the state did not change — verify the effect.

2. **What does the victim LOSE?**
   - Financial loss (credits issued in excess, duplicate payments), integrity loss (manipulated rankings/votes), or security loss (access beyond entitlement — ATO, LPE, arbitrary file append).
   - "The counter went up twice" is only valid if that counter has real-world value. Quantify the blast radius: 7× a $25 gift card = $175 (#759247); 50× a loyalty bonus; 9 days vs 3 days of premium (#1037430).

3. **Can it be reproduced in 10 minutes from scratch?**
   - Can you write a ~20-line Turbo Intruder/curl script, run it against a fresh test account, and reliably show the duplicate effect in ≥3 of 5 attempts?
   - Does the PoC need perfect timing you cannot control? If so, resolve the flakiness (use single-packet delivery) before submitting.
   - Can a second person follow the steps and get the same result? Document the exact N, the success rate, and the Wireshark single-packet capture for high-value claims.

### Statistical-Sampling Gate (read first)

A single anomalous response is noise — duplicate successes can come from retries, caching, or a misread response. Require **1 baseline + N duplicate/over-quota/stale-state demonstrations** with response screenshots and a state re-read. For async effects (payments, emails), confirm via the external channel (bank statement, inbox) before claiming impact (#429026). Run the negative control: an endpoint with a real lock should show exactly one success across the whole burst — that contrast is what makes the finding credible.

---

## Real Impact Examples

### Scenario 1 — Gift Card Multi-Redemption (Reverb #759247)
A researcher bought a single $25 gift card and redeemed it at `POST /fi/redeem` with Turbo Intruder firing ~20 synchronized parallel requests. The consumption marker was written after the balance was credited, with no row-level lock on the redemption read, so multiple requests saw the card as unused. One $25 card was redeemed 7 times = $175 in goods — a direct, unlimited "free money" primitive limited only by how many parallel requests landed in the window.

### Scenario 2 — Duplicated Retest Payments (HackerOne #429026)
A malicious reporter intercepted the retest-confirmation request and executed it as `(request) & (request) & ... & (request)` — five parallel confirmations from the command line. Each was paid as a separate retest; a $500 payment appeared twice in the researcher's bank account weeks later. The impact was intentionally hard for both HackerOne and the attacker to notice, because the duplicate payment only surfaced on a bank statement long after the requests.

### Scenario 3 — Email-Verification Bypass → ATO (Malwarebytes #3020733 / Partners Dashboard #300305)
Two Repeater requests changed the account email to the victim's and the attacker's address respectively and were sent in parallel; both addresses received the same OTP. The attacker then replayed the confirmation with the victim's email, which was now verified. In the Partners Dashboard variant, confirming an arbitrary employee email allowed a partner to request access to a store and take over the matching staff account — a race converted directly into account takeover.

### Scenario 4 — Crypto Faucet Double-Mint (Cosmos / Starport #1438052)
The Starport faucet's `Transfer()` Go function performed two state-mutating actions per request, neither serialized per recipient. With `coins_max` set to 11 tokens and 5 tokens per request, two requests should cap the user at 10; by regenerating and racing requests simultaneously, the researcher fetched more than the configured maximum. Rated Critical (CVSS 9.3) and paid $5,000.

### Scenario 5 — Popular Reports / Vote Inflation (HackerOne #146845, Urban Dictionary #183837)
A multithreaded script replayed the upvote POST for a single report/definition. On Urban Dictionary, responses showed `{"status":"saved","up":6429}` then `{"up":6430}` on successive requests from one account — the counter incremented per request instead of once per user. On HackerOne's popular-reports feature, the same pattern inflated report rankings and researcher reputation, distorting the platform's crowdsourced triage prioritization.

### Scenario 6 — Native TOCTOU: Certificate Revalidation Bypass (curl #3335085)
libcurl validated a server certificate at the initial HTTP/2 handshake, then reused the persistent connection for new streams without re-checking trust. An attacker who could modify the CA file on disk after the first check caused all subsequent requests to reuse a now-untrusted connection — complete certificate-validation bypass. Confirmed on curl 8.16.0; rated High. Sibling file races: curl `fopen` CVE-2023-32001 symlink overwrite (#2039870), SFTP resume arbitrary append (#3432833), Rust `remove_dir_all()` symlink attack (#1520931, $4,000), and NordVPN config-swap LPE (#768110).

### Scenario 7 — Undeletable Group Member (HackerOne CTF #604534)
The group-join endpoint checked whether the user was already a member and then inserted a membership row in two separate operations. Five parallel `POST /group/post_join` requests let the same account join twice. Because the cleanup logic expected exactly one row, the duplicate made the member unremovable — neither the user nor the group leader could delete them. A low-severity integrity bug, but a perfect demonstration that a race can create a *persistent broken state*, not just an extra counter increment. The bug reappeared after a partial fix (#1540969).

### Scenario 8 — Unlimited Invitations via Parallel Bursts and Cancel Refunds (FetLife #1460373)
The "Invite Your Friend" feature debited one invite per `POST /users/invitation`. A chain of 10 parallel curl commands (`curl_1 & curl_2 & ... & curl_10`) sent 10 invitations at the cost of one. Because cancelling a sent invitation refunded the invite, an attacker could race to send many invites, cancel them all, and repeat — minting unlimited invitations. This is the "quota bypass + refund loop" pattern that also appears in loyalty claims (#331940) and credit transfers (#974892): look for any reversible action whose refund is not tied atomically to the original debit.

---

## Disclosed Report Citations

All IDs below are real reports present in the study pack or the TOP Race Condition list. Format: **Company — title** ([H1 #id](https://hackerone.com/reports/id)) — subclass, technique, year/bounty.

1. **Reverb.com — Race Condition allows to redeem multiple times gift cards which leads to free "money"** ([H1 #759247](https://hackerone.com/reports/759247)) — coupon/gift-card double-redemption; Turbo Intruder identical-copies race on `POST /redeem`; 2019, High.
2. **HackerOne — Race condition in performing retest allows duplicated payments** ([H1 #429026](https://hackerone.com/reports/429026)) — payment duplication; `(request) & (request)` parallel retest confirmations, $500 paid twice; 2018, Medium/CVSS 4.2.
3. **HackerOne — Race condition leads to duplicate payouts** ([H1 #220445](https://hackerone.com/reports/220445)) — duplicate payout race; no bounty recorded.
4. **Cosmos / Starport — Race condition in faucet when using starport** ([H1 #1438052](https://hackerone.com/reports/1438052)) — crypto faucet double-mint; non-serialized `Transfer()` read-modify-write; 2021, Critical/CVSS 9.3, **$5,000**.
5. **InnoGames — Race condition in activating email resulting in infinite amount of diamonds received** ([H1 #509629](https://hackerone.com/reports/509629)) — email-activation reward race; one-time token replayed before `token_used` commits; 2019, **$2,000**.
6. **Vend VDP — Race Condition: Exploiting the loyalty claim URL and gain loyalty bonus/cash** ([H1 #331940](https://hackerone.com/reports/331940)) — loyalty claim N×; 50× parallel POSTs to `/loyalty/claim`; 2018, Medium/CVSS 5.3.
7. **Helium — Race Condition of Transfer data Credits to Organization Leads to Add Extra free Data Credits** ([H1 #974892](https://hackerone.com/reports/974892)) — data-credit transfer double-credit; Turbo Intruder on `/api/data_credits/transfer_dc`; 2020, Medium, **$250**.
8. **Reddit — Race condition leads to Inflation of coins when bought via Google Play Store** ([H1 #801743](https://hackerone.com/reports/801743)) — in-app purchase coin inflation; parallel `/api/v2/gold/android/verify_purchase`; 2020, Medium.
9. **Slack — Race Condition in account survey** ([H1 #165570](https://hackerone.com/reports/165570)) — survey credit doubled; two asynchronous requests credited $200; 2016.
10. **Bumble — Race Condition on "Get free Badoo Premium" which allows more days of free premium** ([H1 #1037430](https://hackerone.com/reports/1037430)) — free-premium multiplication; 3 successful parallel requests → 9 days; 2020, Low/CVSS 2.6.
11. **Instacart — Race Condition in Redeeming Coupons** ([H1 #157996](https://hackerone.com/reports/157996)) — coupon double-redeem/stacking; asynchronous replay of promo-code request; 2016.
12. **HackerOne — Race Condition leads to undeletable group member** ([H1 #604534](https://hackerone.com/reports/604534)) — TOCTOU duplicate group join; 5 parallel `POST /group/post_join` → added twice, unremovable; 2019, Low/CVSS 2.4.
13. **HackerOne — Race Conditions in Popular reports feature** ([H1 #146845](https://hackerone.com/reports/146845)) — upvote inflation; multithreaded replay of `POST /reports/N/votes`; 2016.
14. **Urban Dictionary — Race condition in up voting and down voting** ([H1 #183837](https://hackerone.com/reports/183837)) — vote manipulation; 11-thread Intruder, per-request counter increments; 2016.
15. **HackerOne — Race Condition in Flag Submission** ([H1 #454949](https://hackerone.com/reports/454949)) — flag resubmission for points; "Race The Web" tool; 2018, Low.
16. **FetLife — Race condition in endpoint POST fetlife.com/users/invitation, allow unlimited invites** ([H1 #1460373](https://hackerone.com/reports/1460373)) — invite quota bypass; 10 chained curls + cancel-refund loop; 2022, Medium/CVSS 4.3.
17. **Keybase — Race conditions can be used to bypass invitation limit** ([H1 #115007](https://hackerone.com/reports/115007)) — invitation limit bypass; no bounty recorded.
18. **Shopify — Race condition at create new Location** ([H1 #413759](https://hackerone.com/reports/413759)) — store-location plan limit bypass; 12 locations created on a 4-location plan; **$500**.
19. **SingleStore — Exceed the maximum number of subscribers using Race Condition** ([H1 #3221185](https://hackerone.com/reports/3221185)) — subscriber limit bypass; no bounty recorded.
20. **Automattic — Race condition on add 1 free domain** ([H1 #2616045](https://hackerone.com/reports/2616045)) — one-free-domain-per-account bypass; no bounty recorded.
21. **HackerOne — Race Conditions Exist When Accepting Invitations** ([H1 #119354](https://hackerone.com/reports/119354)) — one-time invitation token consumed twice; two browsers accept one invite; 2016.
22. **HackerOne — Race condition in claiming program credentials** ([H1 #488985](https://hackerone.com/reports/488985)) — GraphQL credential-claim race; multiple test accounts from one invite; 2019, Low/CVSS 3.4.
23. **Malwarebytes — Email Verification Bypass via Race Condition** ([H1 #3020733](https://hackerone.com/reports/3020733)) — email-change OTP race; Repeater "Send group in parallel" → victim email verified; 2025.
24. **Tools for Humanity — Race Condition Enables Bypassing Verification Check** ([H1 #2110030](https://hackerone.com/reports/2110030)) — one-human-one-action verification bypass; **$3,000**.
25. **HackerOne — Bypassing HackerOne 2FA due to race condition** ([H1 #2598548](https://hackerone.com/reports/2598548)) — 2FA validation race; no bounty recorded.
26. **Internet Bug Bounty — Race Conditions in OAuth 2 API implementations** ([H1 #55140](https://hackerone.com/reports/55140)) — OAuth access/refresh-token race; 6 of 11 providers vulnerable; no bounty recorded.
27. **Razer — Race Condition in Oauth 2.0 flow can lead to malicious applications create multiple valid sessions** ([H1 #699112](https://hackerone.com/reports/699112)) — OAuth session multiplication; **$250**.
28. **GitLab — Race condition in GitLab import, giving access to other people their imports due to filename collision** ([H1 #214028](https://hackerone.com/reports/214028)) — TOCTOU info disclosure; concurrent same-name import uploads; 2017, Low/CVSS 3.7.
29. **curl — TOCTOU Race Condition in HTTP/2 Connection Reuse Leads to Certificate Validation Bypass** ([H1 #3335085](https://hackerone.com/reports/3335085)) — connection-trust TOCTOU; CA file changed after handshake, connection reused; 2025, High.
30. **Internet Bug Bounty — Time-of-check to time-of-use vulnerability in std::fs::remove_dir_all() (Rust)** ([H1 #1520931](https://hackerone.com/reports/1520931)) — symlink-replacement TOCTOU; all Rust before 1.58.1; 2022, High, **$4,000**.

---

## Related Skills & Chains

- **`hunt-business-logic`** — Race conditions are the "concurrency arm" of every business-logic state machine. Chain: coupon/promo logic + single-packet race → coupon redeemed N times → direct financial loss (Reverb, Instacart, Vend).
- **`hunt-mfa-bypass`** — OTP expiry and replay protection are classic race targets. Chain: race + MFA-validate endpoint → bypass the attempt cap / validity window (HackerOne 2FA #2598548; Flatt PIN expansion).
- **`hunt-ato`** — Races on email change, email verification, and invitation acceptance enable persistent ATO. Chain: parallel email-change + same-OTP replay → victim email verified on attacker flow (#3020733, #300305).
- **`hunt-oauth`** — Token and refresh-token endpoints are raceable across providers (#55140, #699112); OAuth flows with multiple valid sessions are a direct race primitive.
- **`hunt-file-reading` / `hunt-path-traversal`** — Filesystem TOCTOU (stat-then-open, symlink swap, upload-resume append) converts a path parameter into arbitrary read/write (#2039870, #3432833, #1520931).
- **`security-arsenal`** — Load the Turbo Intruder `Engine.BURP2` single-packet template, the `curl` parallel-burst pattern, and the h2.cl smuggling variant before testing.
- **`triage-validation`** — Apply the Statistical-Sampling gate: one anomalous response is noise. Require a baseline + N mutually-exclusive successes, a state re-read, and — for high-value claims — a Wireshark single-packet capture. Run the negative control and report it.


---

## Merged Source Knowledge

This section consolidates **87 unique knowledge blocks** from 5 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (93 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/bountyforge/references/cvss-guide.md`

# CVSS 3.1 Scoring Guide

Use this guide to compute the CVSS 3.1 vector string and base score for each finding.

### Attack Vector (AV)
| Value | Code | When to use |
|-------|------|-------------|
| Network | N | Exploitable remotely over the internet / blockchain |
| Adjacent | A | Requires access to the same network segment |
| Local | L | Requires local access to the machine |
| Physical | P | Requires physical access |

**Default for most web/smart contract findings: N**

### Attack Complexity (AC)
| Value | Code | When to use |
|-------|------|-------------|
| Low | L | No special conditions; attack succeeds reliably |
| High | H | Requires specific configuration, race condition, or difficult-to-control state |

**If the attack needs a race window, specific token type, or flash loan: consider H**

### Privileges Required (PR)
| Value | Code | When to use |
|-------|------|-------------|
| None | N | No auth required |
| Low | L | Normal user account |
| High | H | Admin / privileged role required |

### User Interaction (UI)
| Value | Code | When to use |
|-------|------|-------------|
| None | N | No victim interaction needed |
| Required | R | Victim must click a link, approve a tx, etc. |

### Scope (S)
| Value | Code | When to use |
|-------|------|-------------|
| Unchanged | U | Impact stays within the vulnerable component |
| Changed | C | Impact extends beyond (e.g., compromised server affects other users, bridge affects other chains) |

**Cross-chain attacks, XSS, and SSRF to internal networks often qualify for C**

### Confidentiality (C)
| Value | Code | Description |
|-------|------|-------------|
| None | N | No confidentiality impact |
| Low | L | Limited info disclosure |
| High | H | Full disclosure of sensitive data |

### Integrity (I)
| Value | Code | Description |
|-------|------|-------------|
| None | N | No integrity impact |
| Low | L | Some data can be modified |
| High | H | Complete loss of integrity / funds drained |

### Availability (A)
| Value | Code | Description |
|-------|------|-------------|
| None | N | No availability impact |
| Low | L | Reduced performance, partial DoS |
| High | H | Complete DoS, contract bricked |

---

## Common Patterns

| Finding Type | Typical Vector | Score Range |
|---|---|---|
| Flash loan + fund drain | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` | 7.5 |
| Single attester compromise (bridge) | `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` | 9.1 |
| Upgrade bypass (no timelock) | `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` | 9.1 |
| Reentrancy fund drain | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` | 7.5 |
| Signature replay | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` | 7.5 |
| IDOR (non-financial) | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 |
| IDOR (financial/ATO) | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | 8.1 |
| Stored XSS (admin panel) | `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N` | 8.7 |
| GraphQL introspection | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | 5.3 |
| DoS (unbounded loop) | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | 7.5 |
| Race condition (web) | `AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N` | 6.3 |
| Subdomain takeover | `AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N` | 6.1 |
| Missing zero-address check | `AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H` | 5.8 |
| Unprotected initializer | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | 10.0 |

---

## Scoring Instructions

1. Select each metric value from the definitions above.
2. Construct the vector string: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
3. Compute the base score using the CVSS 3.1 formula (or reference the common patterns table for well-known attack types).
4. In the report, show: vector string, numerical score, and a one-line justification for each metric selection.

**Example:**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0
AV:N — exploitable from the internet via any RPC node
AC:L — no race condition or special state required
PR:N — no authentication required, any address can call
UI:N — no victim interaction
S:C — compromise of the bridge affects all destination chains
C:H / I:H / A:H — attacker can drain all bridged assets and brick the contract
```


### From `hunt-skills/bountyforge/references/hacking-agents/race-condition-agent.md`

# Race Condition Agent

You are an attacker that exploits time-of-check-to-time-of-use (TOCTOU) gaps, front-running opportunities, and concurrency bugs across smart contracts and web applications.

### Smart Contract: Front-Running & Sandwich

- **Transaction front-running:** Identify functions where seeing the pending transaction in the mempool gives a profitable advantage. Key targets: DEX swaps, liquidations, oracle updates, governance votes, NFT mints.
- **Sandwich attack:** Can you insert a transaction before AND after the victim's to extract value?
- **Block stuffing:** Can you fill a block with your own transactions to delay time-sensitive operations (liquidations, auctions)?
- **Commit-reveal:** Is a commit-reveal scheme in place? Is the commit binding (hash includes secret)? Can the revealer choose not to reveal if the outcome is unfavorable?

### Smart Contract: TOCTOU

- **Check-then-act gap:** `require(balance[user] >= amount)` followed by external call before `balance[user] -= amount`. Can balance change during the external call?
- **Oracle freshness:** Price read at time T, action taken at time T+N blocks. Can the oracle value be stale or manipulated in that window?
- **Multi-step atomic requirement:** Protocol requires steps A→B→C to be atomic, but they're separate transactions. Attacker interrupts between B and C.
- **Allowance TOCTOU:** ERC20 `approve` followed by `transferFrom` in separate transactions. Classic ERC20 front-run race on allowance change.

### Smart Contract: Replace & Rotate

- **Attester/key rotation window:** `replace_attester(old, new)` — is there a window where both keys are valid? Can the attacker use `old` during the transition?
- **`replace_message` race:** In cross-chain messaging, can an attacker race a legitimate `replace_message` call and substitute their own replacement?
- **Pauser race:** `pause()` and `unpause()` called in sequence — can an attacker front-run `unpause()` to execute an attack in the unpaused window before the intended operation?

### Web/API: Concurrent Requests

- **Balance double-spend:** Send two simultaneous withdrawal requests. If the server reads balance, then deducts non-atomically, both may succeed.
- **Coupon/voucher race:** Two requests using the same single-use code simultaneously — does one-use enforcement happen atomically?
- **Inventory race:** E-commerce: check stock → reserve → purchase. Two concurrent buyers racing for last item.
- **TOCTOU in file handling:** Upload malicious file after validation but before processing (e.g., upload a safe file, replace it via race before the server reads it).
- **Account state race:** `update_email` checks if email is available, then sets it. Concurrent requests from two users claiming the same email.

### Implementation

For each race condition finding, provide:
1. **Window size:** How many blocks (on-chain) or milliseconds (web) does the race window exist?
2. **Success probability:** How reliably can the race be won? (e.g., with Flashbots, 95%+ reliable)
3. **Required setup:** What must the attacker control (tokens, accounts, MEV infrastructure)?

## Output Fields

Add to FINDINGs:

```
race_type: front-run | sandwich | toctou | concurrency | rotation-window
window: <blocks or time window>
mev_required: true | false
exploit_reliability: low (<30%) | medium (30-70%) | high (>70%)
sequence: |
  T0: [victim broadcasts tx / system state]
  T1: [attacker inserts tx before]
  T2: [victim tx executes]
  T3: [attacker cleans up / extracts]
```


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/move/fv-mov-4-shared-objects-concurrency/fv-mov-4-cl1-shared-object-races.md`

## TLDR

Concurrent transactions targeting the same shared object can interleave reads and writes without a version or sequence check. The second writer overwrites the first writer's result, causing lost updates - for example, two deposits each read `total = 100`, add their amounts independently, and both write back, erasing the first deposit.

## Detection Heuristics

- Identify all shared objects and their mutating functions
- Check whether every mutating function reads, modifies, and writes back a `version: u64` field atomically - a transaction with a stale version should abort
- Look for patterns where two independent values (e.g., `total_deposited` and `user_balance`) are both updated in the same function but neither is version-checked
- In DEX or lending protocols, the primary pool or reserve object is the critical shared state - verify it has version protection
- Also check for `sequence_number` or `nonce` fields used for ordering protection

## False Positives

- Sui's object versioning at the consensus layer prevents two transactions from writing the same object version - the second will fail automatically; assess whether this is sufficient for the specific operation
- Operations are commutative and ordering is irrelevant (e.g., incrementing a pure counter)
- Single-writer pattern enforced - only one authorized function can mutate the object


### From `hunt-skills/exploit-dev/offensive-toctou/SKILL.md`

# TOCTOU — Time-of-Check / Time-of-Use Exploitation

A TOCTOU bug exists wherever code checks a property (file owner, path target, token validity, balance) and then acts on it as if the property still holds. Between check and use is a window — your job is to widen it and swap the underlying object.

## Quick Workflow

1. Identify the **check** (syscall, function, validation step) and the **use** (the privileged action)
2. Confirm the check and use don't operate on the same kernel object (FD, inode, atomic snapshot)
3. Build a primitive that swaps the object between check and use (symlink, mount, mv, parallel request)
4. **Widen the window** with FUSE, slow filesystems, scheduler tricks, or single-packet HTTP/2
5. Run a tight loop and confirm the post-use state corresponds to the swapped target

---

## The Core Pattern

```c
// Vulnerable
if (access(path, W_OK) == 0) {     // check  — resolves "path" now
    fd = open(path, O_WRONLY);     // use    — re-resolves "path" later
    write(fd, attacker_data, n);
}
```

Between `access` and `open`, an attacker replaces `path` with a symlink to `/etc/shadow`. The check sees an attacker-owned file; the use opens shadow as root.

The fix is always: **operate on the kernel object, not the path.** Use `O_NOFOLLOW`, `openat` with `AT_SYMLINK_NOFOLLOW`, `fstat` on the FD, etc.

---

# Setup target — privileged binary that writes to user-supplied path after access() check
victim --output /tmp/.attacker/output

# Race loop
while true; do
  ln -sf /etc/passwd /tmp/.attacker/output 2>/dev/null
  ln -sf /tmp/.attacker/legit /tmp/.attacker/output 2>/dev/null
done &

### renameat2(RENAME_EXCHANGE) — Atomic Single-Frame Swap

```c
syscall(SYS_renameat2, AT_FDCWD, "good", AT_FDCWD, "bad", RENAME_EXCHANGE);
```

`RENAME_EXCHANGE` swaps two paths atomically — combined with FUSE-paused dir lookups, this is a near-deterministic primitive on Linux ≥ 3.15.

### Directory Swap (mv between two prepared trees)

When the victim resolves `parent/file`, swap `parent` itself:

```bash
mv good_dir parent && mv evil_dir parent_was_good_dir

### Bind Mount / Mount-Namespace Swap (root-only or in user-ns)

```bash
unshare -mUr
mkdir /tmp/x /tmp/y
echo benign > /tmp/x/file
mount --bind /etc/shadow /tmp/y/file

# Then: while true; do mount --move /tmp/x /tmp/m; mount --move /tmp/y /tmp/m; done
```

In containerized contexts with `CAP_SYS_ADMIN` in a user namespace, this is the foundation of multiple runc/CVE escape chains.

---

## Window-Widening Primitives

The race is always winnable in theory; in practice you need the window large enough for your swap.

### FUSE-Backed Slow Filesystem

Mount a FUSE filesystem you control. When the victim does `open` or `stat`, your handler sleeps:

```python

# fusepy
class SlowFS(Operations):
    def getattr(self, path, fh=None):
        if path == '/trigger':
            time.sleep(5)   # stretch the check
        return os.lstat(self.root + path).__dict__
```

Now the check call inside the victim blocks for 5 seconds — plenty of time to swap the post-check filename.

### Userfaultfd (kernel-level page faults)

```c
// Register a userfault region; when the victim reads the user-controlled buffer,
// pause it in the page-fault handler, swap data, then resume.
ioctl(uffd, UFFDIO_REGISTER, &reg);
```

`userfaultfd` can pause a kernel-side `copy_from_user` mid-read, enabling double-fetch wins. Linux ≥ 5.11 requires `vm.unprivileged_userfaultfd=1` (off by default in many distros).

### Cgroup Freeze

```bash
mkdir /sys/fs/cgroup/race
echo $victim_pid > /sys/fs/cgroup/race/cgroup.procs
echo 1 > /sys/fs/cgroup/race/cgroup.freeze   # pause

### Single-CPU Pinning + sched_yield

```c
cpu_set_t set; CPU_ZERO(&set); CPU_SET(0, &set);
sched_setaffinity(victim_pid, sizeof(set), &set);
// Race threads on same CPU — context switch is the only progress unit
```

---

## Kernel Double-Fetch

A kernel function reads the same userspace location twice; an attacker mutates it in between using userfaultfd or another thread.

```c
// Vulnerable kernel pattern
copy_from_user(&size, &user_arg->size, 4);   // first fetch
if (size > MAX) return -EINVAL;
copy_from_user(buf, user_arg->data, size);   // size re-fetched? Or from local? Check carefully.
```

Tooling: KFENCE, Bochspwn-Reloaded, DECAF — fuzzers and analyzers that detect double-fetches.

---

### /proc/pid/exe + ptrace

`/proc/<pid>/exe` is a magic symlink. If a privileged binary opens it after fork+exec, an attacker can race the exec to point exe at attacker-controlled binary on a slow filesystem. Foundation of CVE-2019-5736 (runc).

```c
// Sketch
fd = open("/proc/self/exe", O_RDONLY);  // by attacker, in container
// Then the host runc opens /proc/<pid>/exe to write — opens *attacker's* exe → host RCE
```

### /proc/pid/mem

`open("/proc/pid/mem")` followed by `lseek+write` historically bypassed write protections. Modern kernels enforce ptrace credentials at write time, but legacy or patched-out checks still exist in embedded kernels.

### /proc/pid/cwd / fd / root

Symlinks resolve at deref time using the target task's namespace. Cross-namespace deref of `/proc/pid/root/etc/shadow` from a sibling container is a recurring vuln class.

---

## Setuid Binary TOCTOU

```c
// Vulnerable flow in classic SUID binary
if (!access(file, R_OK)) {       // check with real UID via access()
    fd = open(file, O_RDONLY);   // open with effective UID = root
    sendfile(stdout, fd, ...);
}
```

Symlink swap between `access` and `open` makes the binary read root-readable files for unprivileged users.

**Rule of thumb when reviewing setuid/setgid binaries:** every path appearing twice in a syscall trace is a candidate.

```bash
strace -f -e openat,access,stat,lstat,readlink ./suid_binary 2>&1 | grep "$user_input"

### CVE-2019-5736 (runc) — `/proc/self/exe` Overwrite

When a container runs `docker exec`, runc opens `/proc/self/exe` from the host. By replacing the in-container binary with a symlink to `/proc/self/exe`, the host runc rewrites itself.

### CVE-2024-21626 (runc "Leaky Vessels") — Working-Directory FD Leak

A leaked file descriptor to the host filesystem could be inherited via `WORKDIR /proc/self/fd/<n>` — the container's first process held a host FD, races on namespace setup let it act on host paths.

### Symlink-on-Mount Race

When the runtime resolves a bind-mount source/target path (e.g. for tmpfs setup), a fast attacker swaps a directory in the path with a symlink to `/`. Common in Kubernetes hostPath, Docker volumes, OpenShift SCC bypasses.

---

### Auth vs Authz Split at Gateway

```
Gateway: validates JWT (signature, exp) → forwards to service
Service: trusts gateway's "X-User-Id" header
```

If the JWT is revoked between gateway cache and gateway validation, or the gateway caches "valid" results too long, you get post-revocation access. Cache-key confusion (different gateway nodes) widens the window.

# Vulnerable
def long_export(user, resource_id):
    check_access(user, resource_id)        # check
    data = stream_resource(resource_id)    # use — minutes long
    return data                            # access could have been revoked mid-stream
```

Test: revoke access while a download is mid-stream; if data continues, recheck is missing.

### Idempotency-Key Reuse with Different Body

```http
POST /api/withdraw  Idempotency-Key: K1  { "amount": 1 }
POST /api/withdraw  Idempotency-Key: K1  { "amount": 1000 }   # Same key, different body
```

Many implementations key only on the key, not key+body-hash → second request returns the first's response while still processing the second's debit.

### Single-Packet Multi-Request

```
HTTP/2: hold N requests' DATA frames, send all END_STREAM in one TCP segment.
Server schedules N handlers concurrently with sub-millisecond skew → reliable race wins.
Tool: Burp Repeater "Send group in parallel (single-packet)".
```

This is the standard primitive for web TOCTOU since 2023; old `httpie ... &` parallelism is obsolete.

# Vulnerable
if user.balance >= amount:    # check
    user.balance -= amount    # use — non-atomic read-modify-write
    pay(user, amount)
```

Send N parallel requests, each sees the same pre-decrement balance. Fix: atomic decrement with constraint (`UPDATE ... WHERE balance >= amount`).

---

### Android: Intent Redirect TOCTOU

Activity checks calling package via `getCallingPackage()` then dispatches via Intent — between check and dispatch, attacker swaps the underlying ContentProvider URI authority resolution.

### iOS: NSXPC Audit Token Confusion

`audit_token_t` should be captured at the start of each XPC message handling. If the service captures it once and reuses, an attacker can race PID reuse to impersonate.

---

## Detection & Tooling

| Tool | Layer | Use |
|------|-------|-----|
| `strace -e trace=file -f` | Linux syscall | Find duplicate path resolutions |
| `bpftrace` / `bcc` | Kernel | Probe specific syscalls' args at scale |
| ThreadSanitizer (TSan) | Userspace C/C++ | Compile-time race detection |
| Helgrind / DRD | Userspace | Pthread race detection |
| Bochspwn-Reloaded | Kernel | Double-fetch detection |
| `syzkaller` | Kernel | Coverage-guided race fuzzing |
| Burp Suite (Repeater single-packet) | Web/HTTP | Concurrent request races |
| `racepwn` | Web | Multi-thread + timing harness |
| `Turbo Intruder` | Web | Pipelined parallel requests |

```bash

# Quick filesystem TOCTOU finder against a binary
strace -f -e trace=file ./target 2>&1 | \
  awk -F'"' '/access|stat|lstat|open|readlink/ {print $2}' | \
  sort | uniq -c | sort -rn | head

### Filesystem (C)

```c
#include <sys/syscall.h>
#include <linux/fs.h>
int main() {
    pid_t p = fork();
    if (!p) { for(;;) syscall(SYS_renameat2, -100,"a",-100,"b",RENAME_EXCHANGE); }
    for(;;) execve(victim, args, env);
}
```

# Use httpx or h2 directly; pyburp or turbo-intruder for production
import httpx, anyio
async def race():
    async with httpx.AsyncClient(http2=True) as c:
        async with anyio.create_task_group() as tg:
            for _ in range(30):
                tg.start_soon(c.post, "https://app/withdraw", json={"amount": 100})
anyio.run(race)
```

For real reliability on TLS, prefer Burp's single-packet feature — it crafts an HTTP/2 last-byte synchronization.

---

## Reporting / Severity

A TOCTOU finding's severity rests on: window size (deterministic vs probabilistic), required adjacency (local user / container / authenticated remote), and the post-use primitive (file write, auth bypass, money). A "1-in-10000 race that gives root" is the same finding as a "deterministic race that gives root" once it's chained with a window-widening primitive. Always demonstrate:

1. The minimum reproducer
2. The window-widener used
3. The success rate observed
4. The post-exploit primitive achieved

---

## Key References

- MITRE CWE-367 (TOCTOU), CWE-362 (Race Condition)
- USENIX Security: "FUSE for Profit" — TOCTOU window-widening
- PortSwigger Research: "Smashing the state machine" (single-packet HTTP/2 attack)
- runc CVE-2019-5736, CVE-2024-21626 advisories
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/toctou.md


### From `hunt-skills/hunt-race-condition/SKILL.md`

## Crown Jewel Targets

Race conditions are high-severity findings because they break financial, access control, and integrity assumptions that defenders rarely stress-test. Highest payouts come from:

- **Monetary/credit systems** — double-spending gift cards, coupons, referral bonuses, promotional credits, wallet balances
- **Vote/reputation manipulation** — upvoting the same content multiple times, gaming leaderboards or trending algorithms
- **Account limits bypass** — exceeding free-tier quotas, bypassing "one per user" restrictions on invites, trial activations, or API key generation
- **Privilege escalation** — racing role assignment or permission checks during user creation/upgrade flows
- **Deletion bypass** — reading or exfiltrating data during a narrow window between "marked for deletion" and "actually deleted"
- **Payment flows** — charging a card once but receiving multiple fulfillments

**Best-paying asset types:** Fintech apps, SaaS platforms with credit/subscription models, social platforms with reputation systems, e-commerce checkout flows, OAuth/SSO token endpoints.

---

### URL Patterns
```
/vote, /upvote, /like, /favorite
/redeem, /apply-coupon, /use-code, /claim
/purchase, /checkout, /confirm-order, /pay
/transfer, /withdraw, /send-money
/invite, /referral, /accept-invite
/upgrade, /activate, /trial
/delete, /deactivate, /cancel
/follow, /subscribe
```

### Response Headers That Signal Race-Prone Backends
```
X-RateLimit-*        # rate limiting exists, but may not be atomic
X-Request-Id         # each request independently tracked
No Cache-Control     # stateful ops not idempotent
```

### JavaScript Patterns to Grep
```javascript
// Single-use action buttons with client-side disable
button.disabled = true
$('#btn').prop('disabled', true)
// Optimistic UI updates (state set before server confirms)
setState({ used: true })
// Sequential async calls without locking
await useVoucher(); await deductBalance();
```

### Tech Stack Signals
- **Ruby on Rails** without `with_lock` / `lock!` — ActiveRecord doesn't lock by default
- **Node.js** with async/await chains — non-atomic DB reads then writes
- **PHP** without `SELECT ... FOR UPDATE` — common in legacy codebases
- **Microservices** — inter-service calls introduce natural TOCTOU windows
- **Redis counters** without Lua scripts or `INCR` atomicity checks
- **Message queues** — idempotency keys often missing

---

## Step-by-Step Hunting Methodology

1. **Enumerate one-time or limited-use actions** — Map every endpoint that enforces a "once per user", "limited quantity", or "deduct balance" constraint. These are your primary targets.

2. **Understand the state machine** — For each target action, identify: (a) what state is read, (b) what state is written, (c) what validation sits between read and write. The gap between read and write is your window.

3. **Capture a clean baseline request** — Perform the action once legitimately with Burp Suite intercepting. Confirm you get the expected single-use behavior (e.g., coupon marked used, vote counted once).

4. **Set up parallel request tooling** — Use one of:
   - Burp Suite Repeater → "Send group in parallel" (Turbo Intruder for HTTP/2 single-packet attacks)
   - Turbo Intruder with `engine=Engine.BURP2` for last-byte sync
   - `curl` with `&` backgrounding
   - Python `threading` or `asyncio` with pre-built connections

5. **Execute the race** — Send 10–50 identical requests simultaneously. Key technique: **pre-connect and buffer all requests, release the final byte of all simultaneously** (single-packet attack when HTTP/2 is available).

6. **Analyze responses** — Look for:
   - Multiple `200 OK` where only one should succeed
   - Duplicate success messages
   - Database constraint errors (signals the race worked but hit the last-line-of-defense)
   - Inconsistent response times (one fast, rest slow = serialized; all same speed = parallel processing)

7. **Verify the effect** — Check the actual state: Was the credit applied twice? Did the vote count increment multiple times? Is the coupon still marked unused despite two successes?

8. **Determine exploitability window** — Re-run with decreasing parallelism (5 requests, 3 requests, 2 requests) to understand how tight the window is and reliability of exploitation.

9. **Test across account types** — Sometimes the race only works for new accounts, specific subscription tiers, or under specific server load. Test varied conditions.

10. **Document reproducibility** — Record exact timing, number of parallel requests needed, and success rate across 5 independent attempts before reporting.

---

# turbo_intruder_race.py
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)  # HTTP/2 single-packet
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    if '200' in req.status:
        table.add(req)
```

# Fire 15 simultaneous vote/redeem requests
for i in $(seq 1 15); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST "https://target.com/api/vote" \
    -H "Cookie: session=YOUR_SESSION" \
    -H "Content-Type: application/json" \
    -d '{"report_id": "12345", "vote": "up"}' &
done
wait
```

### Python asyncio Race
```python
import asyncio, aiohttp

async def race_request(session, url, payload, headers):
    async with session.post(url, json=payload, headers=headers) as r:
        return await r.text()

async def main():
    url = "https://target.com/redeem"
    payload = {"code": "GIFT50"}
    headers = {"Cookie": "session=XXXXX"}
    
    async with aiohttp.ClientSession() as session:
        tasks = [race_request(session, url, payload, headers) for _ in range(20)]
        results = await asyncio.gather(*tasks)
    
    for r in results:
        print(r[:100])  # print first 100 chars of each response

asyncio.run(main())
```

# Python Django ORM without select_for_update
grep -rn "\.get(\|\.filter(" --include="*.py" | grep -v "select_for_update"
```

# Verify target supports HTTP/2 (prerequisite for single-packet attack)
curl -sI --http2 https://target.com | grep -i "HTTP/2\|h2"
```

---

## Common Root Causes

1. **Check-Then-Act without atomic operations** — Developer reads state (`if voucher.used == false`), then writes state (`voucher.update(used: true)`) in two separate database operations. Any thread can read the same "unused" state before either writes.

2. **Missing database-level locking** — Using ORM methods like `find` or `filter` instead of `SELECT ... FOR UPDATE`. The fix is one line but developers don't think about concurrency.

3. **Optimistic concurrency without version checking** — Systems increment counters or mark records without checking if the record changed since it was read.

4. **Microservice TOCTOU** — Service A validates eligibility, Service B executes the action. No shared atomic transaction spans both services.

5. **Client-side "protection"** — Developers disable the button in JavaScript after first click, assuming that prevents duplicate submissions. Server-side logic is never hardened.

6. **Counter increments outside transactions** — `votes_count += 1; save()` instead of an atomic SQL `UPDATE SET votes = votes + 1 WHERE id = ?`.

7. **Async background jobs** — Eligibility checked synchronously, fulfillment done asynchronously. A second request passes the check before the first job completes.

8. **Caching without invalidation** — Cached "has user voted?" check returns stale `false` during a cache miss window when the first write hasn't propagated yet.

---

### What Defenders Implement (and How to Bypass)

**Defense: Per-user rate limiting**
- Bypass: Rate limits are checked before the action executes. Send requests simultaneously — all pass the rate-limit check before any is counted.

**Defense: Idempotency keys / unique request tokens**
- Bypass: If the server generates or reuses the token, try sending parallel requests without the token. Or check if the uniqueness check itself has a race window.

**Defense: Database unique constraints**
- Bypass: The constraint catches duplicates *after* the race. The first two may both succeed before DB enforces. Look for partial fulfillment — sometimes one succeeds and one errors but both are honored.

**Defense: Short time windows / expiring tokens**
- Bypass: Pre-stage all requests with valid tokens. Use single-packet HTTP/2 to release all in one TCP frame — server processes them in the same scheduler slot.

**Defense: Queue-based serialization**
- Bypass: Multiple queues (or multiple workers consuming the same queue) can pick up duplicate messages. Test by overwhelming the queue during the window.

**Defense: Application-layer mutex / locks**
- Bypass: Distributed systems running multiple app servers don't share in-process locks. Send requests to the same endpoint via different CDN nodes or load-balanced servers.

**Defense: "Already used" checks in application code**
- Bypass: The check and the update are separate. The check passes for both racing requests before either update completes. Only an atomic `UPDATE ... WHERE used=false RETURNING id` truly prevents this.

---

## Gate 0 Validation

Before writing the report, confirm all three:

1. **What can the attacker DO right now?**
   Can you demonstrate — with screenshots or logs — that the same one-time action succeeded more than once? (e.g., vote count shows +2 from one user, credit balance shows double-credit, coupon shows redeemed twice)

2. **What does the victim LOSE?**
   Is there concrete, measurable harm? Financial loss (credits issued in excess), integrity loss (manipulated rankings/votes), or security loss (access granted beyond entitlement)? "The counter went up twice" is only valid if that counter has real-world value.

3. **Can it be reproduced in 10 minutes from scratch?**
   Can you write a 20-line script, run it against a fresh test account, and reliably demonstrate the duplicate effect at least 3/5 attempts? If it requires perfect timing you cannot reliably control, the exploitability claim is weak.

---

### Scenario 1: Social Platform Vote Manipulation
A bug bounty platform's "popular reports" feature allowed upvotes to improve report visibility and researcher reputation scores. By sending ~15 parallel upvote requests for the same report using a single HTTP/2 connection (single-packet attack), a researcher was able to register 10–15 votes from a single account. This allowed artificial inflation of report rankings, manipulation of researcher reputation scores, and distortion of the platform's crowdsourced prioritization system — directly undermining trust in the platform's core feature for triaging vulnerability reports.

### Scenario 2: Major Social Network — Duplicate Promotional Actions
On a major social network (Facebook-scale), promotional or limited-use actions — such as adding a phone number for a one-time security credit, or claiming a one-time bonus — were vulnerable to simultaneous parallel requests. An attacker could race the claim endpoint and receive the promotional benefit multiple times, causing direct financial loss to the platform and allowing fraudulent accumulation of platform currency or benefits at scale. Given the user volume, even a brief window before patching represented significant financial exposure.

### Scenario 3: Cloud Infrastructure Provider — Resource Limit Bypass
A cloud hosting provider enforced limits on the number of resources (e.g., droplets, projects, or API keys) a free-tier user could create. The limit check and resource creation were non-atomic operations. By racing the creation endpoint with 20 simultaneous requests, an attacker bypassed the enforcement logic and created resources far exceeding their tier limit. This translated directly to unauthorized compute consumption, billing fraud, and abuse of infrastructure — impacting both the provider's revenue and system stability for legitimate users.

---

## Disclosed Report Citations (Backfill +9 — 2016-2024)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill. Four cases (#4, #11, #12, plus the bonus reference) use the modern **HTTP/2 single-packet attack** technique (Kettle DEF CON 31, 2023; Flatt Security expansion 2024) — the technique that makes most modern race exploits viable today.

4. **GitLab — CVE-2022-4037 email-verification race (Kettle DEF CON 31 case study)** ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-4037) · [PortSwigger Research](https://portswigger.net/research/smashing-the-state-machine))
    - Subclass: password-reset / email-change token race (TOCTOU on email verification)
    - Single-packet HTTP/2: **YES** — flagship case study in "Smashing the State Machine"
    - Payload: two concurrent `POST /-/profile` requests changing email to two different addresses; the verification token sent to address A becomes valid for address B because state transitions weren't atomic
    - Root cause: Devise (Rails auth) builds the confirmation token before the new email is persisted; concurrent updates misroute the token
    - Year: 2022 (disclosed 2023), CVSS 6.4, patched 15.7.2 / 15.6.4 / 15.5.7

5. **Worldcoin (Tools for Humanity) — World ID action-verification race** ([Medium writeup](https://medium.com/@gonzo-hacks/the-fast-and-the-curious-finding-a-race-condition-in-worldcoin-621c89bfbd61))
    - Subclass: vote/upvote inflation (one-human-one-action enforcement bypass)
    - Payload: ~20 parallel requests via Burp "Send in Parallel" against the verification endpoint
    - Root cause: `canVerifyForAction` appended to an array without DB-level locking; fix added `nullifiers` table with atomic UPSERT
    - Year: 2023 — **$3,000** (High)

6. **Stripe — Promotion code redeemed past limit** ([H1 #1717650](https://hackerone.com/reports/1717650))
    - Subclass: coupon double-redemption
    - Payload: create promo with redemption limit = 1; open two payment-link tabs of same merchant, apply coupon in both, click Pay simultaneously → both succeed
    - Root cause: redemption counter incremented post-charge, not atomically with charge; no row-level lock on `promotion_code.times_redeemed`
    - Year: 2022 — **$250**

7. **Stripe — Fee discounts redeemed many times** ([H1 #1849626](https://hackerone.com/reports/1849626))
    - Subclass: wallet/balance double-spend (Connect fee discount could be redeemed repeatedly)
    - Payload: parallel POSTs to redemption endpoint of a one-shot promotional credit before the credit-consumed flag flipped
    - Root cause: non-atomic check-then-decrement on the credit balance object
    - Year: 2023 — **$5,000**, ~$600 platform fee loss per redemption

8. **Reverb.com — Gift card multi-redemption** ([H1 #759247](https://hackerone.com/reports/759247))
    - Subclass: coupon double-redemption (gift card)
    - Payload: capture `POST /gift_cards/redeem` → duplicate N× → fire parallel → balance credited N× from a single card
    - Root cause: gift-card consumption marker written after balance credit, no `SELECT…FOR UPDATE` around the redemption read
    - Year: 2019 — **$1,500** (foundational/widely cited)

9. **Cosmos / Starport faucet — Double-mint race** ([H1 #1438052](https://hackerone.com/reports/1438052))
    - Subclass: wallet/balance double-spend (crypto faucet token issuance)
    - Payload: simultaneous `/faucet/transfer` requests; the `Transfer` Go function executes two state-mutating actions per request, both non-atomic
    - Root cause: faucet handler did not lock per-recipient; transfer() read-modify-write was not serialized
    - Year: 2022 — **$5,000** (CVSS 9.3)

10. **InnoGames — Email-activation race → unlimited diamonds** ([H1 #509629](https://hackerone.com/reports/509629))
    - Subclass: referral abuse multiplier / account-create race (one activation token → multiple "first activation bonus" payouts)
    - Payload: race the email-activation endpoint with the same one-time token before `token_used` flag committed → reward granted on every winning request
    - Root cause: token-consumption flag set in same transaction as reward grant, but transaction isolation level too low (READ COMMITTED)
    - Year: 2019 — **$2,000**

11. **RyotaK / Flatt Security — "First Sequence Sync" PIN-bruteforce (10,000-req single-packet expansion)** ([Flatt Security Research](https://flatt.tech/research/posts/beyond-the-limit-expanding-single-packet-race-condition-with-first-sequence-sync/))
    - Subclass: rate-limit bypass via race / MFA-OTP-validate race (6-digit PIN with 5-attempt cap)
    - Single-packet HTTP/2: **YES** — extends Kettle's single-packet from ~30 requests to 10,000 requests in 166 ms by splitting across IP fragments with synchronized TCP first-sequence
    - Payload: ~10,000 concurrent `POST /verify-pin` requests in 166 ms, each with a different 4-6 digit guess, all landing inside the rate-limit window
    - Root cause: rate-limit counter incremented per-request asynchronously; "5 attempts" gate read stale counter for the entire batch
    - Year: 2024 — **must-reference modern single-packet example**

12. **nopCommerce — CVE-2024-58248 gift-card double-redemption** ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-58248))
    - Subclass: coupon double-redemption (e-commerce checkout TOCTOU)
    - Single-packet HTTP/2: **YES** — single-packet attack reproduces it reliably
    - Payload: two parallel `POST /checkout/PlaceOrder` requests both applying the same gift card → both orders complete, gift card balance debited once
    - Root cause: order-placement code path did not implement locking on gift-card balance row → check-then-debit non-atomic
    - Year: 2024 (versions before 4.80.0)

---

### Why it works — architecture

A race exploit fails for two reasons that look like the same problem but aren't:
1. **Network jitter** — N requests sent sequentially over the same TCP connection arrive at the server with 0.5–5 ms spread, depending on RTT and congestion.
2. **Server-side dispatch ordering** — even if all N requests arrive in the same millisecond, the worker pool may serialise them via a load balancer or accept-queue.

The single-packet attack solves (1) by exploiting two protocol-level facts about HTTP/2:

- HTTP/2 multiplexes N requests over ONE TCP connection as ONE TLS record per request batch.
- TLS records can carry multiple HTTP/2 `HEADERS` frames, and each HEADERS frame can be the last frame of a separate stream.

So if you pre-stage N requests on a single HTTP/2 connection — **send all the HEADERS frames except the very last byte of each, then release all the final bytes in a single TCP write** — the TCP stack ships them in **one IP packet** (assuming < MTU, ~1500 bytes). The server's kernel hands all N requests to the HTTP/2 parser in the same scheduler tick. The race window is no longer the network — it's the application's own atomicity-failure window.

For (2) — server-side dispatch ordering — Kettle showed that modern backends (Node.js, Go, async Python) dispatch concurrently within microseconds when handed a packet of N pre-parsed requests. Older blocking backends (default Apache prefork, single-threaded PHP-FPM) serialise even with single-packet delivery; for those, the technique helps less but still wins over TCP-stream sequencing.

### Last-byte-sync technique

The exact mechanic Kettle documented:

1. Open one HTTP/2 connection. Negotiate TLS, send the SETTINGS frame, accept the server's.
2. For each of N requests, send its `HEADERS` frame **with the END_HEADERS flag** and a `DATA` frame containing **all but the last byte of the body**. Do NOT set END_STREAM yet.
3. The server cannot dispatch the request because END_STREAM hasn't fired — it's waiting for one more byte.
4. Repeat (2) for all N requests on the same connection. Each is now buffered at the server, parsed up to "almost done".
5. **In a single TCP write, send N tiny `DATA` frames each carrying 1 byte with END_STREAM set.** TCP coalesces them into one outbound segment. The server's HTTP/2 parser sees END_STREAM on all N streams in the same scheduler tick.
6. Server dispatches N requests to N workers in microseconds.

The race window equals the time between worker N's `SELECT ... FOR UPDATE` and worker N+1's same query — typically nanoseconds when the workers run on the same CPU.

### Wireshark validation

To confirm your attack tool is genuinely producing one-packet sync (vs accidentally fragmenting):

1. Capture the loopback or your egress interface during the attack: `sudo tcpdump -i lo0 -w race.pcap port 443` (or interface 0).
2. Open in Wireshark, filter `tls and tcp.port == 443`.
3. Find the TLS record containing the END_STREAM flush. It should contain **N H2 DATA frames with END_STREAM set, in one TLS record, in one TCP segment.**
4. If you see N TLS records or N TCP segments, your tool is sequencing. The race window is your inter-segment gap — typically too wide.

The Turbo Intruder `engine=Engine.BURP2` implementation guarantees single-packet delivery on HTTP/2 targets when the request body fits in MTU. For larger bodies, see the "Race-window estimation" subsection below.

### h2.0 single-frame vs h2.cl multi-frame race

Two variants depending on what protocol the target speaks:

- **h2.0 single-frame** (the standard Kettle attack): pure HTTP/2 end-to-end. N requests in one TLS record. Works against any modern HTTPS-fronted target where the front-end advertises `h2` in ALPN. **Default approach.**
- **h2.cl multi-frame**: front-end speaks HTTP/2 to the client, downgrades to HTTP/1.1 to the back-end. Smuggling-adjacent — you craft an HTTP/2 request whose `Content-Length` confuses the front-end into emitting two HTTP/1.1 requests to the back-end on the same connection. Pairs with HTTP request smuggling (see `hunt-http-smuggling`). Useful when single-packet HTTP/2 is filtered at the front-end but the back-end is reachable in HTTP/1.1.

Detect h2.0 viability via `curl -sI --http2 https://target.com | grep -i HTTP/2`. If the server doesn't speak h2, single-packet is not directly applicable — fall back to "parallel-pipelining" over HTTP/1.1 (much wider race window; usually loses the race against modern backends, but still useful for naive ones).

### Race-window estimation methodology

Before firing the attack, estimate the race window. This determines whether you need single-packet at all, and how many concurrent requests to send.

1. Issue a **single** request to the target endpoint. Capture the response time on the wire: `T_single`.
2. Issue **two sequential** requests. Capture both response times: `T_seq1`, `T_seq2`.
3. Issue **two concurrent** requests over the same connection (via HTTP/2 multiplex or HTTP/1.1 pipeline). Capture both: `T_par1`, `T_par2`.
4. If `T_par1 ≈ T_par2 ≈ T_single`, the server handles both in parallel — race window is `min(T_par1, T_par2)`, single-packet helps a lot.
5. If `T_par2 ≈ T_par1 + T_single`, the server serialises — race window is whatever happens between sequential workers; single-packet helps less but still wins over TCP jitter.
6. For PIN / OTP / coupon-redemption endpoints, expect `T_single` to be 10–100 ms (DB query latency). The race window inside the server is typically < 1 ms (the gap between `SELECT` and `UPDATE` on the same row).
7. **N rule of thumb:** start with `N = 30` concurrent requests for single-packet h2. Increase to 100+ if the target's `T_single` is < 10 ms (very fast endpoint = larger pre-buffer needed to overflow the worker pool). Up to **10,000** with Flatt's first-sequence-sync extension (see below).

### Single-connection-multi-stream vs Multi-connection-single-stream

A decision tree for picking the right shape:

- **Single connection, N streams** (default Kettle / Turbo Intruder BURP2 engine): N concurrent HTTP/2 streams on one TCP connection. **Use when:** target speaks HTTP/2; request body fits in MTU (~1400 bytes after TLS overhead); you need N ≤ ~30.
- **Multiple connections, one stream each** (older parallel HTTP/1.1): N TCP connections, one request per connection. **Use when:** target doesn't speak HTTP/2 OR the request body is large (> MTU). Race window widens significantly (5–50 ms TCP-handshake spread) — only viable on slow servers.
- **Multiple connections, multiple streams** (Flatt's first-sequence-sync, 2024): N TCP connections each carrying M streams. Total = N×M requests. Uses synchronized TCP first-sequence numbers across multiple connections to land all packets at the server in the same processing window. **Use when:** you need N > 30 (e.g., brute-forcing a 6-digit PIN within a 5-attempt rate-limit window — Flatt demonstrated 10,000 requests in 166 ms by splitting across IP fragments with synchronized SEQ numbers).

### Turbo Intruder `Engine.BURP2` template — explained

```python
def queueRequests(target, wordlists):
    # 1. Engine.BURP2 = HTTP/2 single-packet engine; provides the last-byte-sync primitive.
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,          # 2. One TCP connection, multiplexing all streams.
        requestsPerConnection=100,        # 3. Up to 100 concurrent H2 streams. >30 needs Flatt-extension.
        engine=Engine.BURP2,              # 4. THE critical line — selects the single-packet engine.
        pipeline=False,                   # 5. Pipelining is for HTTP/1.1; irrelevant on H2.
    )

    # 6. Build N requests. Each is identical here — racing the same endpoint.
    #    For PIN brute-force, vary the body across requests.
    for i in range(30):
        engine.queue(target.req)

    # 7. openGate(...).complete(...) is the API call that performs last-byte-sync:
    #    - Buffer all 30 requests up to "last byte not sent"
    #    - Release all final bytes in a single TCP write
    #    - openGate returns immediately; complete waits for all responses.
    engine.openGate("race1")
    engine.complete(timeout=10)
```

The `Engine.BURP2` import does the heavy lifting. Behind the scenes:
- Each `engine.queue(req)` adds a HEADERS frame to the connection's send buffer but withholds the last DATA frame byte.
- `openGate("race1")` blocks until all 30 are buffered, then issues a single `socket.send(...)` containing 30 × 1-byte DATA frames with END_STREAM. All 30 cross the wire in one IP packet (assuming < MTU).
- `complete(timeout=10)` collects responses and times.

Inspect each response object: `req.code`, `req.length`, `req.time`. The race is "won" when at least 2 requests return a success that should logically have been mutually exclusive (e.g., both coupon-applies succeed when the redemption limit was 1).

### Flatt's first-sequence-sync extension (when N > 30 is needed)

Kettle's original single-packet caps at roughly N=30 due to MTU + TLS record limits. Flatt Security's RyotaK published the extension in August 2024:

- Take advantage of IP fragmentation: a single "logical" packet at the IP layer can be split across multiple physical IP fragments.
- Force synchronized TCP SEQ numbers across multiple connections by completing the TLS handshakes in lockstep and aligning the SYN/SYN-ACK timing.
- Result: 10,000 concurrent requests delivered to the server in 166 ms, all landing inside a rate-limit window that the server thought was atomic.

Use case: brute-forcing 6-digit PINs (max 10^6 candidates) inside a 5-attempts-per-window cap. Without first-sequence-sync, you'd need ~200,000 windows. With it, ~100 windows.

Implementation: [flatt.tech/research/posts/beyond-the-limit-...](https://flatt.tech/research/posts/beyond-the-limit-expanding-single-packet-race-condition-with-first-sequence-sync/) includes a working PoC.

### Operator playbook (when to reach for what)

| Scenario | Tool / variant |
|---|---|
| Modern HTTPS target, ALPN advertises `h2`, body < 1400 bytes, need N ≤ 30 | Turbo Intruder `Engine.BURP2` single-packet — **default** |
| Same as above but body > MTU | Multi-connection HTTP/2; widen window estimate by ~5 ms |
| Target speaks HTTP/1.1 only (no h2 ALPN) | `curl --next` parallel pipeline; race window is wide; only viable on slow servers |
| Need N > 30 (PIN brute-force, OTP exhaustion within rate-limit window) | Flatt first-sequence-sync extension; manual implementation per the writeup |
| Front-end h2, back-end h1 (CDN+origin) | h2.cl smuggling variant — pairs with `hunt-http-smuggling` |
| Quick reproducibility test on a single endpoint | `curl --next --next --next --next` (4-shot parallel HTTP/1.1) — wide window but no setup |

### Anti-patterns

- **Don't claim "race condition" from observing two near-simultaneous successes in Burp Repeater "Send group in parallel" mode** — that mode pipelines over HTTP/1.1 with millisecond-spread, not single-packet. Triagers know this and downgrade.
- **Don't submit without Wireshark confirmation** for high-value race claims. The deliverable that pays best: PoC video showing Turbo Intruder firing + Wireshark capture showing all N END_STREAM frames in one TCP segment + N successful responses that should have been mutually exclusive.
- **Don't use single-packet against endpoints that genuinely don't race** (e.g., endpoints with row-level locks and transactions). The window estimation step exists to filter these out before you spend 2 hours building the PoC.

### Cross-references

- `hunt-http-smuggling` — h2.cl multi-frame variant
- `hunt-mfa-bypass` — OTP rate-limit window single-packet bypass (Flatt PIN-bruteforce class)
- `hunt-business-logic` — coupon / wallet / promo state-machine races where single-packet is the enabling primitive
- Disclosed Report Citations above — citations #4, #11, #12 are the canonical single-packet exemplars (GitLab/Devise CVE-2022-4037, Flatt 10k-req PIN brute-force, nopCommerce CVE-2024-58248)

---

## Related Skills & Chains

- **`hunt-business-logic`** — Race conditions are the "concurrency arm" of every business-logic state machine. Chain primitive: business logic (coupon/promo) + race-condition single-packet attack → coupon redeemed N times → direct financial loss.
- **`hunt-mfa-bypass`** — OTP-expiry windows and replay protection are classic race targets. Chain primitive: race + MFA-validate endpoint → bypass OTP expiry by submitting N concurrent validations within the validity window.
- **`hunt-ato`** — Race conditions on password reset, email change, and account creation enable persistent ATO. Chain primitive: race on email-change endpoint + atomic-update missing → swap victim email + read reset token before user notice.
- **`hunt-api-misconfig`** — Wallet/balance/credit endpoints without atomic UPDATE are double-spend candidates. Chain primitive: race + atomic-update missing → double-spend balance → withdraw N× user balance.
- **`security-arsenal`** — Load the Turbo Intruder single-packet template, h2.cl smuggling for atomic submit, and `curl --next` parallel multi-request patterns.
- **`triage-validation`** — Apply the Statistical-Sampling gate: a single anomalous response is noise; require 1 successful + N duplicate / over-quota / stale-state demonstrations with response screenshots before reporting.
