---
name: hunt-info-disclosure
description: Hunting skill for information disclosure vulnerabilities, built from 2,764 FULL disclosed-report texts (3,266 assigned reports). Covers GraphQL field/argument over-exposure, API hidden fields and JSON content-negotiation authorization gaps, S3/bucket and directory misconfiguration, debug/stack-trace and Laravel/Django debug-mode leaks, hardcoded API keys in JS bundles and old git commits, cache deception to session theft, CORS/JSONP cross-origin data theft, OAuth redirect_uri and IDN-homograph token leaks, IDOR document/PII exposure, verbose-error user/project enumeration, metrics and .DS_Store/.htaccess/FrontPage artifacts, and slow/unsafe file-processing leaks. Use when hunting any target — this class is frequently the precursor to account takeover, not the final finding.
sources: hackerone_public, top_information_disclosure_reports, disclosed_report_corpus
report_count: 3266
full_reports_read: 2764
---

# HUNT-INFO-DISCLOSURE — Information Disclosure

> **Operating thesis.** Information Disclosure is rarely the end goal — it is the
> key that opens every other vulnerability class. A leaked `secret_key_base`
> (#460545), an OAuth token redirected to an attacker host (#861940), a session
> cookie served from a cache (#1698316), or a private email hidden inside an API
> `activities` object (#196655) each convert an "Informational" observation into
> a full account takeover. The skill below is mined from 2,764 full public report
> texts; every probe, payload, and citation is grounded in those reports.

> **What the corpus teaches above all else:** the data is almost always *already
> in the response*. The bug is that nobody asked what the API returns versus what
> the UI displays, what the GraphQL serializer exposes versus what the user is
> allowed to see, or what the cache stores versus who it serves it to.

---

## Crown Jewel Targets

Information Disclosure is highest-value when the leaked artifact is *actionable* —
a credential, a token, a hidden field the UI never shows, or data belonging to
another user. Priority targets, ranked by what the report corpus actually paid for:

- **GraphQL endpoints (`/graphql`, `/api/graphql`, `/v1/graphql`)**
  - The single richest source in the study pack. Field-level authorization is
    routinely forgotten.
  - Private comments (#978143), `payment_transactions` counts (#707433),
    `report_sources` privacy flags (#770209), `vpn_suspended` (#715192),
    `team_member_groups` permissions (#343464), and PII on `User` nodes
    (#489146) all leaked through ordinary queries.
  - `{ __schema { types { name fields { name } } } }` enumerates every field to
    probe — never test only the queries the UI happens to send.

- **REST APIs that return more than the UI renders**
  - "Hidden field" bugs dominate the mid-severity payouts.
  - `activities.email` (#196655), a boolean `read` on chat messages (#1080437),
    `latest_activity_at` (#724944), `/wp-json/wp/v2/users/` (#753725), and a
    `/waitlist/us` endpoint echoing every registrant's mobile number (#902733).
  - Always diff the raw API response against what the browser actually displays.

- **Client-side JavaScript and source bundles**
  - Hardcoded `aviaryApiKey`/`youtubeApiKey` in a minified bundle (#983331).
  - A Google API key reused across six FetLife hosts (#1065041).
  - A Rockset key visible only in an *old commit* (#1094151).
  - An AppLovin key hardcoded in a public Android mediation repo (#674774).
  - Mine JS bundles and git history, not just the live DOM.

- **Cloud storage and attachment directories**
  - A public S3 bucket exposing every merchant's chat images (#1021906).
  - An unsecured attachment directory (#769016).
  - A Google Drive link embedded in a page exposing military orders with SSNs
    (#2926447) — a pure OSINT-style disclosure with Critical impact.

- **Cache layers**
  - Cache deception serving another user's session cookie (`HASESSIONV3`) via a
    `.jpeg` path suffix (#1698316).
  - Web-cache poisoning leaking user info (#492841, #631589).

- **CORS / JSONP on authenticated endpoints**
  - Arbitrary-origin reflection with credentials on Semrush (#235200, #629892),
    Rockstar Games (#317391), and studyroom.line.me (#924951).
  - JSONP callbacks bypassing a user's privacy settings (#361951).

- **Debug and error surfaces**
  - Sentry `/api/20/store` render UI (#697512), Laravel/Django debug mode
    (#2765259, #2965143, #2201370), Express stack traces from a URL parameter
    (#205069), verbose config stack traces (#666065), full path disclosure
    (#8090, #5073).

- **Admin/internal dashboards and metrics**
  - An exposed Apache Flink dashboard (#1262907), Grafana (#1448218), `/metrics`
    endpoints (#1365076, #981796), Spring Boot Actuators (#914719), and
    unauthenticated Jira APIs with `?maxResults=1000` (#2122964).

- **Misconfigured CRM/record permissions**
  - Salesforce Guest-user object permissions leaking PII (#2294930, #1023572,
    #1443654), with sequential Salesforce IDs enumerated via Aura controllers
    (#2294930).

- **Deceptive file/encoding processors**
  - SVG/GIF processing that leaks server memory (#284155).
  - MySQL-connection local file reads (#719875).
  - AVI GAB2 subtitle chunks triggering SSRF and `/etc/issue` reads (#237381) —
    proof that "information disclosure" also hides inside file parsers.

Severity climbs with **sensitivity × reachability**: an unauthenticated PII dump
is Critical (#2926447, #2294930); a version banner alone is Informational.
Chain upward — always ask what the leaked value unlocks.

---

## Attack Surface Signals

### URL / Endpoint Patterns to Hunt
```
/graphql                       /api/graphql               /v1/graphql
/graphql?query=                /api/v1/users              /wp-json/wp/v2/users/
/?rest_route=/wp/v2/users/      /api/waitlist/us           /api/rest/1.2/users/
/marketplace/_rpc              /api/user/{id}.json        /reports/{id}.json
/actuator                      /actuator/env              /actuator/httptrace
/debug                         /debug/vars                /metrics
/server-status                 /_vti_inf.html             /_vti_bin/
/.env                          /.git/config               /.DS_Store
/.htaccess                     /config.php                /app/subscription?connector=
/api/20/store                  /api-docs                  /swagger.json
/invitations/{token}.json      /secure/QueryComponent!Default.jspa
```

### Parameter / Field Patterns
```
?id=            ?userUuid=       ?vendorId=        ?uid=            ?user_id=
?token=         ?reset_token=    ?email=           ?next=           ?redirect_uri=
?url=           ?query=          ?filter=          ?where=          ?order=
?maxResults=    ?debug=1         ?callback=        ?format=json     Accept: application/json
```

### Response Signals (what a leak looks like on the wire)
```
"email":"victim@example.com"        ← hidden field in activities/API object
"private_comment": "..."            ← GraphQL field that should be gated
"read": true                        ← state UI never exposes
"secret_key_base" / APP_KEY          ← Rails/Laravel config leak
"payment_transactions":{"total_count":N}
"gauth_secret": "..."               ← 2FA seed in account response (#1276373)
Access-Control-Allow-Origin: https://attacker.com + Allow-Credentials: true
X-Powered-By / X-AspNet-Version / Server: nginx/1.18.0
x-amz-meta-s3cmd-attrs: ...user=root...   ← system username (#262649)
Stack trace: at java. / Traceback / Exception in thread / vendor/bundle path
```

### Tech Stack Signals (from report corpus)
- **GraphQL / Hasura**
  - Introspection on, `where`/`_or` filters, fragments.
  - Probe every field, not just queries the UI sends.
- **Laravel / Django / Rails debug mode**
  - Whoops pages, `APP_DEBUG=true`, `secret_key_base`, `DEBUG` cookie.
- **WordPress**
  - `/wp-json/wp/v2/users/`, `?rest_route=`, REST user enumeration.
- **Salesforce / Aura / Lightning**
  - Guest-user object permissions, sequential IDs, Aura `getRecord` controllers.
- **AWS S3 / GCS / Azure Blob**
  - Bucket URL in page source or JS, `ListBucketResult`, `x-amz-meta-*` headers.
- **CORS/JSONP-heavy SPAs**
  - `Origin:` reflection, `callback=` JSONP endpoints.
- **AEM / FrontPage / Jenkins**
  - `.json` suffix on any path, `/_vti_inf.html`, `/script` console, exposed
    build nodes (#388740).

---

## Discovery Patterns From 2,764 Full Reports

### Where Researchers Start (ranked recon surfaces from study pack frequency table)

Ranked by how often the signal appeared across the 2,764 full reports. "What to
look for" is the concrete recon move.

| Rank | Recon surface (study-pack signal, count) | What to look for |
|------|-------------------------------------------|------------------|
| 1 | Search/filter/sort & hidden params (`search-filter-sort`, 755) | Every sortable/filterable column and `where=` filter — GraphQL secure-schema bypasses live here (#645299). Fuzz param names; watch for error-message differences (#605608). |
| 2 | Image processing / upload (`image-processing`, 573; `file-upload`, 94; `svg-upload`, 18) | Image proxy URLs, SVG/GIF upload, EXIF/metadata retention, parser memory leaks (#284155), subtitle chunks triggering SSRF/local file read (#237381). |
| 3 | API endpoints (`api-endpoint`, 536; `json-body`, 104) | Responses with fields the UI omits; REST user lists; over-posted objects; content-negotiation differences (#1424291). |
| 4 | Server-side rendering (`server-side-rendering`, 498) | Stack traces from a URL input (#205069), reflected values in generated pages, JS-error backslashes (#179732). |
| 5 | Public code search (`public-code-search`, 357) | GitHub code search for the target's API keys, tokens, `.mailmap`, old commits (#1094151, #674774, #1785145). |
| 6 | Admin / internal panels (`admin-internal`, 327) | Flink/Grafana/Jenkins dashboards, `/admin`, `/manage`, unauthenticated APIs (#1262907, #2122964). |
| 7 | Cookie / session handling (`cookie-handling`, 321; `session-attack`, 261) | Session tokens in URLs (#76733), back-button-after-logout (#2946927), static session IDs (#1150573). |
| 8 | Redirect handling (`redirect-handling`, 320; `open-redirect`, 66) | `redirect_uri`, `return_to`, `next=` — token leakage via permissive redirect allowlists (#151058, #861940). |
| 9 | Comment / user-generated fields (`comment-injection`, 307; `stored`, 124) | SMTP errors reflected into HTML (#2956266), blind XSS in admin panels leaking tokens/PII (#878145). |
| 10 | Misconfiguration (`misconfiguration`, 285) | `.htaccess`, `.env`, `.git/config`, `.DS_Store`, directory listings (#1241849, #142549, #2784712). |
| 11 | Filter bypass (`filter-bypass`, 283) | IDN homographs (#861940), encoding tricks on `secret_key_base` (#460545), authz fix bypasses (#1024356). |
| 12 | Cache layer (`cache-layer`, 257) | `.css`/`.jpeg` path suffixes on personalized pages, `X-Cache` headers (#1698316, #492841). |
| 13 | XML parser / import (`xml-parser`, 230; `import-feature`, 85) | XXE/local-file behavior (#142562), CSV imports with PII (#1172852), SAML config files (#268382). |
| 14 | JS source review (`js-source-review`, 222) | Minified bundles and admin-functionality JS revealing endpoints and keys (#983331, #1489470). |
| 15 | Internal network (`internal-network`, 213; `cloud-metadata`, 68) | SSRF-driven local file reads (#719875, #237381), internal host disclosures (#634312). |
| 16 | Brute / OTP / reset (`brute-otp-reset`, 198) | No rate limit on password reset → PII enumeration (#2748003, #91343). |
| 17 | Debug / error leak (`debug-error-leak`, 187; `error-based`, 79; `stack-fingerprinting`, 59) | Force errors; harvest paths, versions, config (#697512, #666065, #3403450). |
| 18 | SSO/OAuth (`sso-oauth`, 149) | Token endpoints, `client_id`, scope, IDN/Unicode validation (#861940, #235200). |

### Feature-Based Discovery Signals (frequency-ranked)

| Feature (count) | Why it matters / what to probe |
|-----------------|--------------------------------|
| `search-filter-sort` (755) | Highest-frequency surface. GraphQL `where`/`_or` filters are converted to a "secure" schema inconsistently — probe the second condition (#645299); error-type differences confirm hidden records (#605608). |
| `image-processing` (573) | Image proxies fetch URLs and parse binary formats; probe memory disclosure via crafted GIF (#284155), SVG `<image href>`, and AVI subtitle features that read local files (#237381). |
| `api-endpoint` (536) | The API is the truth; the UI is a filter. Diff every response object against rendered fields; test `Accept: application/json` as an authz bypass (#1424291). |
| `server-side-rendering` (498) | Server templates reflect input into errors/rendered pages — input a backslash or URL and read the resulting stack trace or JS error (#179732, #205069). |
| `public-code-search` (357) | Search GitHub for `target-atlassian.net`, `jiraHost`, `token =`, API keys in source and history (#1785145, #1094151). |
| `admin-internal` (327) | Dashboards often sit on guessable subdomains with no auth (#1262907); enumerate subdomains and probe `/#/overview`. |
| `cookie-handling` (321) | Session in URL, cookie shared with takeover-able subdomain, missing `HttpOnly` — each is a disclosure chain (#76733, #1342422). |
| `redirect-handling` (320) | Any `redirect_uri` / `return_to` that accepts arbitrary subdomains can leak OAuth/livechat tokens (#151058, #861940). |
| `comment-injection` (307) | Error text and third-party messages (SMTP rejection strings) reflected via `html()` become disclosure or stored XSS (#2956266). |
| `misconfiguration` (285) | Probe dotfiles and version control; a single `.htaccess` reveals rewrite rules and include paths (#1241849). |
| `filter-bypass` (283) | Validation and use are separate code paths — bypass with IDN homographs, double encoding, or old commits (#861940, #460545, #1094151). |
| `cache-layer` (257) | Path-extension confusion makes personalized responses cacheable and public to the next requester (#1698316). |
| `xml-parser` (230) | Object injection via `SimpleXMLElement` callbackUrl → SSRF + LFI (#142562); check config XML files for secrets. |
| `js-source-review` (222) | Admin endpoints live in JS bundles even when the menu hides them (#1489470); grep for `ApiKey`, `token`, `secret`. |
| `internal-network` (213) | Error messages and response fields can carry private IPs and internal hostnames (#634312, #410187). |
| `debug-error-leak` (187) | Laravel/Django debug mode and verbose stack traces expose env vars and config (#2765259, #666065). |
| `sso-oauth` (149) | OAuth `scope`, `client_id`, and error flows reveal tokens or account existence (#235200, #861940). |
| `url-fetching` (130) | URL-fetch features can expose private content through a "preview" of a private resource (#174721) or a proxy anyone can abuse (#14747). |
| `subdomain` (125) | Subdomains are the most common home of forgotten debug panels and metrics (#1365076, #981796). |

### Verbatim Discovery Clues (18 real quotes from the study pack)

These are the actual "how I found it" lines from disclosed reports — note how
often discovery is *passive observation*, not exploitation:

1. `[#1065041]` "I found a bunch of endpoints that is leaking you Google Api key."
2. `[#983331]` "I found a sensitive data including authentication key written in public accessible javascript file."
3. `[#196655]` "I have found a security vulnerability that allows an attacker to disclose any user's private email."
4. `[#629892]` "I found that setting up a CORS in some places will check the protocol, but it allows using http scheme."
5. `[#1021906]` "Hello Shopify, when testing Shopify Ping share image function, I discovered an Amazon S3 bucket which has public access which allows an attacker to view all the image of other merchant & users."
6. `[#2122964]` "And now we found a directory is jira sensitive"
7. `[#902733]` "com I found a link called \"/usa\" is used to create Curve USA Waitlists by entering your name, email address, mobile number and address details."
8. `[#1276373]` "So here i found that the \"gauth_secret\" is potentially leaked in response (which is not normal and is unnecesarry to leak), which means that the attacker who got access to the account can take advantage of this information leakage..."
9. `[#1626508]` "Hey team, I have found this API endpoint leads to leaking attachments and documents of users."
10. `[#151058]` "I have found an issue through which an attacker can steal users' livechat access token and use it to login and chat with the support agents as them..."
11. `[#2586584]` "Through research, I discovered a vulnerability in DoD, that **exposes other users' email addresses through IDOR."
12. `[#389600]` "I noticed there is new field `team_profile` added and using the graphql below the latest serious report and reports received in three months were exposed"
13. `[#981796]` "Upon enumerating a subdomain content I found a directory that discloses the duration of the garbage collection cycles."
14. `[#262649]` "I noticed, that the `x-amz-meta-s3cmd-attrs` response header returns sensitive information, like system username:"
15. `[#1632104]` "I found that the server status directory on your system is open, it displays server status and sensitive information by server"
16. `[#634312]` "Further, having examined in detail the requests that came to me on the server, I saw (private) ip addresses of administrators or employees (support panel)"
17. `[#1172852]` "Using it I have enumerated almost 1000 unique endpoints and on some of them I found csv files with PII of users (Name,Email,Phone,Role,Organisation"
18. `[#91343]` "I noticed a small information leak which allows an attacker to check whether an email address is associated with an account."

**Pattern:** "I noticed / I was browsing / while enumerating" — the finding came
from *reading responses carefully*, then asking what the exposed value enables.
The highest-value skill here is not payload cleverness; it is **attention to what
the application says when it thinks no one is reading**.

### Probe Checklist (15 concrete probes)

1. **Introspect GraphQL** — `POST /graphql {"query":"{__schema{types{name fields{name type{name}}}}}"}`; enumerate every field for hidden PII/private flags (#489146).
2. **Probe GraphQL filters with `_or`** — if `where:{state:{_eq:x}}` is secure, try `_or:[{state:{_eq:x}},{state:{_eq:y}}]` — the second condition often hits the unguarded schema (#645299).
3. **Diff API vs UI** — request `/api/user/{id}` and every linked object; flag any field absent from the rendered page (`email`, `read`, `private_comment`, `gauth_secret`).
4. **Content-negotiation authz** — replay a private resource with `Accept: application/json` (or `.json` suffix) — FetLife leaked private media this way (#1424291, #1939272).
5. **Sweep dotfiles/version control** — `/.env`, `/.git/config`, `/.git/HEAD`, `/.DS_Store`, `/.htaccess`, `/.dockerignore` on every host and subdomain (#1241849, #142549, #2784712).
6. **Mine JS bundles + git history** — grep minified JS for `ApiKey|token|secret|password`; search GitHub and *old commits* for the target's keys (#983331, #1094151, #674774).
7. **Test CORS reflection** — `Origin: https://evil.com` on authenticated endpoints; check for reflected origin + `Allow-Credentials: true` (#235200, #317391).
8. **Test JSONP callbacks** — `?callback=` on data endpoints to bypass privacy settings (#361951).
9. **Force errors everywhere** — malformed JSON, `?id=[]`, bad types, `?s=test\`; harvest stack traces, paths, versions, env vars (#205069, #666065, #179732).
10. **Check debug mode on subdomains** — Laravel `?connector=` debug, Django debug pages, `/actuator`, `/metrics`, `/server-status` (#2765259, #1365076, #914719, #1632104).
11. **Enumerate unauthenticated APIs/CRMs** — Salesforce Guest permissions, Jira `?maxResults=1000`, WordPress `/wp-json/wp/v2/users/` (#2294930, #2122964, #753725).
12. **Brute password-reset / invite endpoints** — check for rate limiting and PII in responses (#2748003, #91343, #290930).
13. **Test cache deception** — request personalized page with `.css`/`.jpeg` suffix or `?x=.css`, then fetch as another user (#1698316).
14. **Probe `redirect_uri` / `return_to`** — any subdomain, IDN homograph (`šemrush.com`), or suffix trick to leak tokens (#861940, #151058).
15. **Read response headers and metadata** — `x-amz-meta-*`, `Server`, `X-Powered-By`, PDF/EXIF metadata, S3 bucket URL in page source (#262649, #1021906).

---

## Step-by-Step Hunting Methodology

1. **Baseline every response before touching anything.**
   - Capture headers, status, and body from `/`, a 404, and an API route.
   - Log `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Cache`, `Via`.
   - Compare across endpoints — inconsistencies reveal multiple backends
     (#2122964). This is passive and cannot trip WAFs.

2. **Inventory the whole surface, not just the landing page.**
   - Subdomain enumerate, then `waybackurls`/`gau` for historical paths
     (password-reset tokens leak via Wayback — #3210022).
   - Use `katana`/JS crawling for hidden endpoints and parameters.
   - The study pack repeatedly shows the finding on a *forgotten subdomain or
     directory* (#1365076, #981796, #1241849).

3. **Run GraphQL discovery first if the target exposes it.**
   - Introspect the schema; save the full type/field list.
   - Systematically query every field on `User`/`Team`/`Report` objects as an
     unauthenticated and low-priv user.
   - HackerOne's corpus alone contains a dozen field-level leaks (#489146,
     #978143, #770209, #707433, #715192, #342978, #343464, #645299, #871749,
     #724944).
   - Test filter operators (`_or`, `_and`) for schema-conversion gaps (#645299).

4. **Diff API responses against the rendered UI.**
   - For each feature, capture the browser's request and the API's raw response.
   - Anything present in the response but not shown to the user is a candidate:
     hidden emails (#196655), read receipts (#1080437), waitlist PII (#902733),
     2FA seeds (#1276373).
   - Test `Accept: application/json` and `.json` URL suffixes as authorization
     bypasses (#1424291, #1939272).

5. **Sweep static/config artifacts across all hosts.**
   - Drive a wordlist for `.env`, `.git/config`, `.git/HEAD`, `.DS_Store`,
     `.htaccess`, `.dockerignore`, `composer.lock`, `/_vti_inf.html`,
     `config.php`, and directory indexes.
   - Basecamp's `.htaccess` (#1241849) and the `.DS_Store` finding (#142549)
     were pure content discovery — no fancy exploitation required.

6. **Mine client-side code and public repositories.**
   - Download every JS bundle; grep for `apiKey`, `secret`, `token`, `AKIA`,
     `AIza`, internal hostnames.
   - GitHub-code-search the company name and domains; check commit *history*,
     not just HEAD (#1094151).
   - A leaked Google key (#1065041), Rockset key (#1094151), or Jira token
     (#1785145) is a direct finding.

7. **Force the application to confess.**
   - Fuzz each parameter with malformed types, arrays, oversized values, and
     encoding breaks.
   - Look for stack traces (file paths, framework versions, DB type), config
     dumps, and error-message differences that confirm hidden records
     (#205069, #666065, #605608, #3403450).
   - Check debug mode on every subdomain (#2765259, #520883, #2965143).

8. **Test cross-origin and cache boundaries.**
   - Send `Origin: evil.com` and JSONP `callback=` to data endpoints
     (#235200, #361951).
   - Test cache-deception suffixes (`x.jpeg`) on personalized pages and
     re-fetch unauthenticated (#1698316, #492841).

9. **Walk IDOR and object-reference surfaces.**
   - For every `{id}`, `userUuid`, `vendorId`, `uid`, `token`, or sequential
     Salesforce ID, substitute another value or decrement/increment.
   - Watch for documents and attachments (#1626508), PII records
     (#2294930, #2967032), invite tokens (#290930), and cached order/contract
     IDs found via Google (#374007).

10. **Probe authentication-adjacent leaks.**
    - Password reset and invite flows: check rate limits, error-text
      differences for account existence (#91343, #2748003).
    - Reset tokens in URLs re-exposed by Wayback (#3210022).
    - 2FA secrets returned in account responses (#1276373).
    - Back-button-after-logout cached account data (#2946927).

11. **Follow the "info leak → something bigger" chain.**
    - `secret_key_base` → Rails session forgery (#460545).
    - OAuth token → account impersonation (#861940, #151058).
    - Session cookie → account takeover (#1698316).
    - PII + weak permissions → mass account takeover (#2450685).
    - Debug mode + CVE → RCE (#2765259).

12. **Document evidence with full request/response pairs.**
    - Redact PII in the report but prove existence.
    - For a "count" leak show the exact query and response.
    - For a cache/session leak show the two-step victim/attacker reproduction
      (#1698316).
    - For an IDOR show two different IDs returning two different users' data.

---

## Payload & Detection Patterns

### GraphQL Reconnaissance & Field Probing
```bash
# Full introspection
curl -s https://target.com/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name fields{name type{name}}}}}"}' | jq .

# Probe a known object for hidden fields (PII, private comments, flags)
curl -s https://target.com/graphql -H 'Content-Type: application/json' \
  -d '{"query":"query { user(username:\"victim\"){ id name email account_recovery_phone_number totp_enabled private_comment } }"}'

# Secure-schema filter bypass via _or (second condition hits unguarded schema) — #645299
curl -s https://target.com/graphql -H 'Content-Type: application/json' \
  -d '{"query":"query { teams(where:{_or:[{state:{_eq:soft_launched}},{state:{_eq:closed}}]}){ id state } }"}'

# Cross-object node lookup that leaked private_comment — #978143
curl -s https://target.com/graphql -H 'Content-Type: application/json' \
  -d '{"query":"query { node(id:\"gid://hackerone/SurveyRatingItem/ID\"){ ... on SurveyRatingItem{ _id key private_comment recipient{email} } } }"}'

# Team-object privacy flags — #715192, #770209, #343464
curl -s https://target.com/graphql -H 'Content-Type: application/json' \
  -d '{"query":"query { team(handle:\"victim\"){ id vpn_enabled vpn_suspended report_sources team_member_groups{id name permissions} payment_transactions{total_count} } }"}'
```

### API Hidden-Field & Content-Negotiation Probes
```bash
# Content-negotiation authz bypass — #1424291 (FetLife private media)
curl -s https://target.com/users/14104003/pictures/120041856 \
  -H "Cookie: session=..." -H "Accept: application/json"

# Hidden email in API activities object — #196655
curl -s https://api.target.com/v1/reports/ID -u "api_id:token" \
  | jq '.activities.data[].attributes.email'

# Boolean state the UI never shows — #1080437 (Bumble read receipt)
curl -s 'https://am1.target.com/mwebapi.phtml?SERVER_OPEN_CHAT' -X POST \
  | jq '.chat_messages[].read'

# JSON suffix on arbitrary path — #1939272 (AEM .json reveals web-root files)
curl -s https://target.com/path/.json | jq .

# Waitlist endpoint echoing all registrants' PII — #902733
curl -s https://target.com/api/waitlist/us -X POST \
  -H 'Content-Type: application/json' -d '{"email":"you@example.com"}'
```

### Dotfile / Config / Version Control Sweep
```bash
for P in /.env /.env.local /.git/config /.git/HEAD /.git/logs/HEAD \
         /.DS_Store /.htaccess /.dockerignore /composer.lock /config.php \
         /_vti_inf.html /server-status /metrics /actuator/env; do
  code=$(curl -s -o /tmp/x -w '%{http_code}' "https://$TARGET$P")
  [ "$code" = "200" ] && echo "[HIT] $P ($(wc -c </tmp/x) bytes)"
done

# S3 bucket discovered in page source — #1021906
curl -s https://ping-api-production.s3.us-west-2.amazonaws.com | head -20

# Git history reconstruction if .git is exposed
git-dumper https://target.com/.git/ /tmp/repo/ 2>/dev/null || true
cd /tmp/repo && git log --all --oneline | head -20
```

### JS Bundle & Git-History Secret Mining
```bash
# Fetch every JS bundle referenced by the app and grep for secrets
curl -s https://target.com/ | grep -oE 'src="[^"]+\.js"' | sed 's/src="//;s/"//' \
  | while read js; do
      curl -s "https://target.com$js" \
        | grep -oE '(apiKey|api_key|secret|token|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,})["'"'"']?\s*[:=]\s*["'"'"'][^"'"'"']+' \
        && echo "  in $js"
    done

# Old-commit key that HEAD doesn't contain — #1094151
git log --all -p | grep -iE 'api[_-]?key|token|secret' | head -40

# Secret scanning across a cloned repo or bundle dump
trufflehog git https://github.com/target/repo.git --json > secrets.json
trufflehog filesystem /tmp/js_bundles/ --json > js_secrets.json
```

### CORS / JSONP Cross-Origin Theft
```bash
# Arbitrary-origin reflection with credentials — #235200, #317391
curl -s -i https://target.com/api/userdata -H 'Origin: https://evil.com' \
  | grep -iE 'access-control-allow-origin|access-control-allow-credentials'

# Null-origin variant (sandboxed iframe / file://)
curl -s -i https://target.com/api/userdata -H 'Origin: null' \
  | grep -i 'access-control-allow-origin'

# IDN homograph bypass of redirect_uri validation — #861940
# redirect_uri=https://oauth.šemrush.com/oauth2/success   (Cyrillic е/š)
# permissive return_to -> livechat token theft — #151058
# ?return_to=https://<attacker_shop>.myshopify.com/&shop=<victim>.myshopify.com

# JSONP callback wrapping private data — #361951
curl -s 'https://target.com/username/charts.json?callback=steal'
```

### Debug / Error / Enumeration Probes
```bash
# Laravel debug-mode config leak via connector param — #2765259
curl -s -i 'https://target.com/app/subscription?connector=salesforce' \
  | grep -iE 'exception|APP_KEY|stack'

# Verbose stack trace config disclosure — #666065, #205069
curl -s "https://target.com/fetch?url=https://target.com/?s=test\\"

# Account-existence via error text — #91343, #605608
for u in victim@x.com none@x.com; do
  curl -s "https://target.com/forgot?email=$u" \
    | grep -i 'already\|exist\|not found'
done

# Path disclosure / phpinfo / FrontPage config
for P in /phpinfo.php /info.php /_vti_inf.html /server-status /debug/vars; do
  curl -s -o /dev/null -w "$P %{http_code}\n" "https://target.com$P"
done
```

### Cache Deception Repro (two-step) — #1698316
```http
GET /search/keywords:x/minNightlyPrice/x.jpeg?triagethis HTTP/2
Host: www.target.com
Cookie: HASESSIONV3=<victim-session>
```
```bash
# Attacker re-fetches same path with no/session-2 cookie — gets cached victim page
curl -s 'https://www.target.com/search/keywords:x/minNightlyPrice/x.jpeg?triagethis' \
  --compressed | grep -i HASESSIONV3
```

### Detection Signatures for Traffic Mining (proxy flows.sqlite)
```sql
-- Large JSON/XML responses on hidden endpoints
SELECT url, LENGTH(response_body) size FROM flows
 WHERE path LIKE '%.json' OR path LIKE '%.xml' ORDER BY size DESC LIMIT 20;

-- Reflected CORS origins
SELECT url, response_headers FROM flows
 WHERE response_headers LIKE '%Access-Control-Allow-Origin: https%';

-- Error responses worth mining for stack traces
SELECT url, response_body FROM flows WHERE response_status=500 LIMIT 20;

-- Endpoints that return different statuses (authz / existence differentials)
SELECT path, COUNT(DISTINCT response_status) s FROM flows
 GROUP BY path HAVING s > 1;
```
```bash
# Grep captured bodies for secret patterns
grep -rE 'AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|secret_key_base|gauth_secret|"private_comment"' flows/
```

---

## Common Root Causes

1. **Field-level authorization was never applied**
   - GraphQL/API serializers expose the whole object.
   - Private comments (#978143), payment counts (#707433), 2FA seeds
     (#1276373), 2FA-config state (#770209), PII on User nodes (#489146).
   - The object is returned intact; the UI merely chooses not to render
     sensitive fields.

2. **Secure-schema conversion applied inconsistently**
   - Hasura/GraphQL filters rewrite the first condition in `_or`/`_and` to a
     safe variant but miss subsequent ones (#645299).
   - The fix exists but is incomplete.

3. **Validation and use are separate code paths**
   - A `redirect_uri` validator rejects obvious bad hosts but misses IDN
     homographs (#861940).
   - An OAuth allowlist accepts any `*.myshopify.com` (#151058).
   - A `secret_key_base` filter is bypassed with encoding characters (#460545).

4. **Debug mode left enabled in production**
   - Laravel debug + CVE-2021-3129 (#2765259), Django debug (#2965143,
     #2201370, #1434276), Mail.ru Laravel debug (#520883), verbose stack
     traces (#666065).
   - Debug surfaces return env vars, paths, and framework versions for free.

5. **Third-party products misconfigured by the customer**
   - Public S3 buckets (#1021906), open Salesforce Guest-user object
     permissions (#2294930, #1023572), exposed Sentry/Flink/Grafana/Jenkins
     panels (#697512, #1262907, #1448218, #388740).
   - The vendor is secure; the deployment is not.

6. **Authorization checked only in one content type**
   - HTML view enforces access, JSON view does not (#1424291, #1939272,
     #290930).
   - The fix covered the UI path and forgot the data path.

7. **Secrets treated as static assets**
   - API keys shipped in minified JS (#983331, #1065041), hardcoded in public
     repos (#674774), or left in git history after rotation (#1094151,
     #1613714).

8. **Cache key ignores user identity**
   - A personalized page cached under a path that ends in a static extension
     is served to the next requester (#1698316, #492841).

9. **Trusting arbitrary CORS origins / JSONP callbacks**
   - Reflects any `Origin` with credentials, or wraps private data in a
     callable JSONP response (#235200, #317391, #361951).

10. **No rate limiting on enumeration endpoints**
    - Password reset, forgot-password, invite, and login flows permit brute
      forcing that returns PII or account-existence signals (#2748003,
      #91343, #12042, #322988).

---

## Bypass Techniques

### Authorization / Content-Type Bypasses
- **Accept-header switch** — replay a gated resource with
  `Accept: application/json` to hit the unguarded serializer (#1424291).
- **URL suffix switch** — append `/.json` or `/<id>.json` to a path that is
  protected only in its HTML form (#1939272, #290930).
- **Fragmented object references** — invite token JSON readable before
  acceptance (#290930); back-button-after-logout shows cached account data
  (#2946927).
- **Method override** — `/?_method=GET` to make a write endpoint disclose data
  (#384782); enabled `OPTIONS`/`TRACE` reflect request internals (#191220).

### Filter / Validation Bypasses
- **IDN homograph** — Cyrillic `е`, `š`, `é` characters that render like Latin
  and fool a naive allowlist (`sémrush.com`, `oauth.šemrush.com`)
  (#861940, #1753226).
- **Encoding characters on secret keys** — encode parts of `secret_key_base`
  to slip past a string filter (#460545).
- **Second-condition injection** — put the forbidden value in the second
  clause of a GraphQL `_or` filter (#645299).
- **Fix bypass** — authz fixes are frequently incomplete; retest the patched
  endpoint with adjacent fields/objects (#1024356, #1074136).

### Redirect / Token-Leak Bypasses
- **Wildcard subdomain `return_to`** — any `*.shopify.com` /
  `*.myshopify.com` accepted as OAuth return target (#151058).
- **Permissive `redirect_uri`** — set to an attacker-controlled look-alike
  domain, token delivered in the redirect (#861940).
- **Livechat/support token theft** — capture the support auth token by
  controlling part of the OAuth flow, then impersonate the victim (#151058).

### Cache / Cross-Origin Bypasses
- **Extension confusion** — add `.css`, `.jpeg`, `.jpg`, `.txt` to a dynamic
  path so the cache treats it as public static content (#1698316, #631589).
- **JSONP callback** — `?callback=` wraps private data in JS, bypassing privacy
  settings cross-origin (#361951).
- **Origin suffix/HTTP origin** — trust of `http://` schemes or any subdomain
  enables MITM-driven CORS theft (#629892, #1183601).

### Source / Metadata Bypasses
- **Old commits** — rotate keys in HEAD but leave them in history (#1094151);
  non-revoked keys from a disclosed report still work (#1613714, #1047125).
- **GitHub code search** — `token =`, `jiraHost`, `.mailmap`,
  `meteor_runtime_config.js` (#1785145, #3241308, #289189).
- **Response headers** — `x-amz-meta-s3cmd-attrs` leaking the system username
  (#262649, #667032).
- **Google indexing** — contract/order IDs and password-reset tokens cached in
  search results (#374007, #322988).
- **File processors** — GIF upload recovering random server memory (#284155);
  AVI GAB2 subtitle chunks triggering SSRF + `/etc/issue` read (#237381);
  MySQL connection reading local files (#719875).

---

## Gate 0 Validation

Before reporting, confirm all three. Information Disclosure is over-reported as
"Informational" and N/A'd when the leak is theoretical.

1. **What can the attacker actually obtain right now?**
   - Show the raw response containing the specific secret, PII field, token, or
     other user's data — not just a field *name* from a schema.
   - For a "count" or "existence" leak, show two different inputs producing two
     different answers (#707433, #342978, #91343).
   - For cache/session leaks, show the two-step victim→attacker reproduction
     with the actual cookie/token value redacted (#1698316).
   - "The field exists in introspection" is not a finding; "the field returns
     another user's email" is.

2. **What does the victim lose?**
   - Quantify: how many users/records are exposed (#2294930 estimated hundreds
     of thousands; #902733 all waitlist registrants)?
   - Does the leak chain to takeover — a session, OAuth/2FA token,
     `secret_key_base`, or reset token (#460545, #861940, #1698316)?
   - PII sensitivity: SSN/military orders (#2926447), full names + phone +
     email (#2294930), or a low-value version banner (#7914). Score accordingly.
   - If the only loss is "an attacker learns the nginx version," treat as
     Informational / likely N/A.

3. **Is it reproducible and in scope?**
   - Does the endpoint still return the data on a clean request, in a second
     browser/session, in under 10 minutes?
   - Is the data genuinely unauthorized — compare an unauthenticated/low-priv
     view to an authorized one (#978143, #753725).
   - For leaked keys, verify they are live but **do not exfiltrate or use**
     beyond a benign existence check (#1065041, #1094151).
   - Redact PII in the report but retain enough to prove exposure; never dump a
     full production database.

---

## Real Impact Examples

### Scenario A — OAuth Token Leak to Account Impersonation (Semrush / Shopify patterns)
Semrush's `redirect_uri` validation compared domains textually but accepted IDN
homographs: `oauth.šemrush.com` (Cyrillic `е`/`š`) passed as "valid" while
resolving to an attacker-controlled domain, delivering the victim's access token
to the attacker (#861940, CVSS 6.4). Shopify's livechat flow went further —
`return_to` accepted any `*.myshopify.com`, so an attacker set `return_to` to
their own shop while authenticating the victim's shop, captured the livechat
token, and chatted with support *as the victim*, reading their email and name
(#151058). Root cause in both: an allowlist that checks the wrong property
(string shape, not resolved owner). Impact: full account impersonation from
what looks like a "redirect misconfiguration."

### Scenario B — Cache Deception to Session Theft and Account Takeover (Expedia pattern)
On `www.abritel.fr`, a search page rendered the victim's `HASESSIONV3` session
cookie in a cacheable response. Appending `.jpeg` to a path segment
(`.../minNightlyPrice/x.jpeg?triagethis`) made the CDN store the personalized
page as a public static asset. Any attacker requesting the same URL with no
session received the victim's page — including the `ha.crumb` token from
`/traveler/profile/edit` — and could ride the session to take over the account
(#1698316, High). The same class hit Postmates (#492841) and Lyst (#631589).
Root cause: cache key/extension confusion. Impact: unauthenticated session
hijacking, not "a caching quirk."

### Scenario C — GraphQL Field Over-Exposure at Scale (HackerOne pattern)
HackerOne's GraphQL endpoint returned PII and private metadata to any
authenticated user: email addresses, recovery phone fields, `totp_enabled`, and
backup codes on `User` nodes (#489146, CVSS 9.3); `private_comment` on
`SurveyRatingItem` (#978143); `payment_transactions.total_count` (#707433);
`vpn_suspended` and `report_sources` privacy flags revealing which external
programs had private scopes (#715192, #770209); whitelisted-hacker counts
(#342978). Individually each looks like "minor metadata"; collectively they map
private programs and leak user PII. Root cause: a serializer that exposes all
model fields by default. Impact: critical confidentiality breach on a
security-sensitive platform.

### Scenario D — Hidden API Field Exposing Millions of Records (Curve pattern)
Curve's `/api/waitlist/us` endpoint, discovered by reading JS for a `/usa`
waitlist feature, echoed not just the submitted email but *every* joined user's
mobile number and address details when queried — the UI showed only a queue
position (#902733). Combined with the Salesforce record-permission leak that
exposed hundreds of thousands of visitors' names, emails, and phones to any
registered user (#2294930), this shows the recurring pattern: the data is
already in the response; the bug is that nobody asked what the API returns
versus what the UI displays.

---

## Disclosed Report Citations

All IDs below are real HackerOne reports appearing in the study pack or the TOP
Information Disclosure list. No IDs or URLs are invented.

1. **HackerOne — Confidential data of users and limited metadata of programs and reports accessible via GraphQL** ([H1 #489146](https://hackerone.com/reports/489146)) — GraphQL field over-exposure, PII/backup codes, 2019/CVSS 9.3
2. **Uber — Sensitive user information disclosure at bonjour.uber.com/marketplace/_rpc via the 'userUuid' parameter** ([H1 #542340](https://hackerone.com/reports/542340)) — RPC parameter IDOR, user PII, 642 upvotes
3. **Postmates — Web cache poisoning attack leads to user information and more** ([H1 #492841](https://hackerone.com/reports/492841)) — cache poisoning, user data, $500
4. **HackerOne — Information Disclosure in /skills call** ([H1 #188719](https://hackerone.com/reports/188719)) — API endpoint over-exposure, $10,000
5. **GitLab — information disclosure of secret_key_base via encoding characters** ([H1 #460545](https://hackerone.com/reports/460545)) — filter bypass, Rails secret, $3,500
6. **Shopify — S3 Bucket of Shopify Ping (iOS) has public access of other users' image** ([H1 #1021906](https://hackerone.com/reports/1021906)) — S3 misconfiguration, cross-user images, $2,900
7. **Eternal — Information Disclosure through Sentry Instance** ([H1 #697512](https://hackerone.com/reports/697512)) — debug info exposure, 2019/$750
8. **FetLife — Google API key leaked to Public** ([H1 #1065041](https://hackerone.com/reports/1065041)) — hardcoded API key, multi-host, 2020/Low
9. **Stripo Inc — Public and secret api key leaked in JavaScript source** ([H1 #983331](https://hackerone.com/reports/983331)) — JS bundle secret mining, 2020/Medium
10. **Expedia Group — Cache Deception Allows Account Takeover** ([H1 #1698316](https://hackerone.com/reports/1698316)) — cache deception, session cookie theft, 2022/High
11. **Semrush — OAuth `redirect_uri` bypass using IDN homograph attack resulting in user's access token leakage** ([H1 #861940](https://hackerone.com/reports/861940)) — OAuth redirect, IDN homograph, 2020/CVSS 6.4
12. **Superhuman (formerly Grammarly) — Lack of CSRF header validation at g-mail.grammarly.com/profile** ([H1 #629892](https://hackerone.com/reports/629892)) — CORS misconfiguration, 2019/CVSS 4.2
13. **Semrush — Cross-origin resource sharing misconfig | steal user information** ([H1 #235200](https://hackerone.com/reports/235200)) — CORS reflection with credentials, 2017/CVSS 5.7
14. **HackerOne — Team object in GraphQL disclosed `private_comment`** ([H1 #978143](https://hackerone.com/reports/978143)) — GraphQL private field, 2020/$2,500
15. **HackerOne — Private information exposed through GraphQL filters** ([H1 #645299](https://hackerone.com/reports/645299)) — GraphQL `_or` filter bypass, 2019/CVSS 6.1
16. **FetLife — Able to access private picture/video/writing when requesting for their JSON response** ([H1 #1424291](https://hackerone.com/reports/1424291)) — content-negotiation authz bypass, 2021/CVSS 6.5
17. **U.S. Dept Of Defense — IDOR leading unauthenticated attacker to download documents discloses PII of users and soldiers** ([H1 #1626508](https://hackerone.com/reports/1626508)) — IDOR, document/PII exposure, $500/CVSS 7.5
18. **U.S. Dept Of Defense — Lack of rate limiting in PKI/PassReset.aspx leads to PII disclosure and potential account takeover** ([H1 #2748003](https://hackerone.com/reports/2748003)) — brute-force PII, 2024/Critical
19. **U.S. Dept Of Defense — Public google drive link exposes Military Orders Containing PII (Name, SSN etc.)** ([H1 #2926447](https://hackerone.com/reports/2926447)) — OSINT/PII exposure, 2025/Critical
20. **U.S. Dept Of Defense — leaking PII of tour visitors (names, email addresses, phone numbers) via misconfigured record permissions** ([H1 #2294930](https://hackerone.com/reports/2294930)) — Salesforce permissions, 2023/Critical
21. **Curve — Sensitive Info Leak — All users Mobile Numbers at /api/waitlist/us** ([H1 #902733](https://hackerone.com/reports/902733)) — hidden API field, mass PII, 2020/Medium
22. **Bumble — Bumble API exposes read status of chat messages** ([H1 #1080437](https://hackerone.com/reports/1080437)) — hidden boolean field, 2021/$600
23. **Shopify — Stealing livechat token and using it to chat as the user** ([H1 #151058](https://hackerone.com/reports/151058)) — OAuth `return_to` token theft, 2016
24. **Nord Security — Disclosure of User Information via wp-json/wp/v2/users/** ([H1 #753725](https://hackerone.com/reports/753725)) — WordPress REST enumeration, 2019/Low
25. **Basecamp — Information Disclosure .htaccess accessible for public** ([H1 #1241849](https://hackerone.com/reports/1241849)) — config file misconfiguration, 2021/Low
26. **Basecamp — Information Disclosure of Garbage Collection Cycle** ([H1 #981796](https://hackerone.com/reports/981796)) — subdomain metrics leak, $100
27. **8x8 — Information Disclosure of metrics fax.wavecell.com/metrics** ([H1 #1365076](https://hackerone.com/reports/1365076)) — metrics endpoint, 2021/Low
28. **MTN Group — Information disclosure due to debug mode enabled at Laravel instance** ([H1 #2765259](https://hackerone.com/reports/2765259)) — Laravel debug / CVE-2021-3129, 2021
29. **X / xAI — Information Disclosure through .DS_Store** ([H1 #142549](https://hackerone.com/reports/142549)) — dotfile exposure, $560
30. **Acronis — IDOR on www.acronis.com API lead to steal private business user information** ([H1 #1182465](https://hackerone.com/reports/1182465)) — API IDOR, business PII, $100

---

## Related Skills & Chains

- **`hunt-source-leak`**
  - Information Disclosure's closest sibling.
  - Source maps, `.git`, Swagger specs, and `asset-manifest.json` are
    *disclosure primitives*; run it first to find the endpoints and keys that
    this skill then validates for real data exposure.
  - Chain: source map → internal endpoint → hidden-field API leak (#1489470).

- **`hunt-idor`**
  - Object-reference substitution is the delivery mechanism for most PII
    disclosure findings (#1626508, #1182465, #2967032).
  - Chain: sequential ID → document/PII dump.

- **`hunt-ssrf`**
  - File processors and URL fetchers that leak `/etc/issue` or local files
    (#237381, #719875) are dual-class.
  - Chain: image-processing leak → SSRF → internal metadata.

- **`hunt-cors` / `hunt-oauth`**
  - Cross-origin reflection and permissive redirect allowlists turn a
    disclosure into account impersonation (#235200, #861940, #151058).

- **`hunt-debug-error`**
  - Verbose errors and debug mode (#2765259, #666065) are the highest-yield
    recon output; chain a stack trace's version string to a known CVE for RCE.

- **`hunt-cloud-misconfig`**
  - Public S3/GCS buckets, Salesforce Guest permissions, and exposed dashboards
    (#1021906, #2294930, #1262907) are deployment-level disclosure.

- **`triage-validation`**
  - Apply the Gate 0 test before submission: prove the leaked *value*, quantify
    the victim loss, and confirm a 10-minute clean reproduction.
  - A field name in a schema is never a finding.
