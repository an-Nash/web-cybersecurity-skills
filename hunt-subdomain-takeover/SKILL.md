---
name: hunt-subdomain-takeover
description: Hunting skill for subdomain takeover, built from 195 assigned reports of which 148 full disclosed HackerOne report texts were mined verbatim. Covers the full provider fingerprint spectrum seen in the corpus — unclaimed AWS S3 buckets, dangling CloudFront / EC2-EIP / Route53-NS records, Azure cloudapp / cloudapp.net / trafficmanager.net / cloud-services re-issue, Fastly CDN service re-attach, Heroku / Netlify / GitLab-Pages / GitHub-Pages, Unbounce / Zendesk / UserVoice / WordPress / Brandpad / Kajabi / Desk.com / Mashery / HubSpot / Wix / Tumblr help-desk and marketing takeovers — plus the high-severity ATO chains (auth.uber.com via saostatic.uber.com, sso.ubnt.com via ping.ubnt.com, devrel.roblox.com CORS + cookie, GitLab CSP allowlist). Use when hunting stale DNS / dangling CNAME / NS / A records; always escalate a bare takeover through cookie-domain, OAuth, CSP, or email-DNS chains before reporting.
sources: github, hackerone_public, binarysecurity_research, can-i-take-over-xyz_research, detectify_research, portswigger_research
report_count: 195
full_reports_read: 148
---

## Crown Jewel Targets

Subdomain takeover is high-value because it hands an attacker content control on a
**trusted, company-owned domain** — bypassing browser same-origin trust,
domain-reputation phishing filters, and user skepticism at once. Across the 148
mined reports, severity is driven far more by *what the hostname is trusted for*
than by the defacement itself. A defacement on an obscure staging host is Low;
the same takeover on an SSO-cookie-bearing or CSP-allowlisted host is Critical.

**Highest-value trust contexts (escalate every takeover through these):**

- **SSO / OAuth hosts.** A takeover of a sibling that shares parent-scoped cookies
  or sits in an OAuth `redirect_uri` allowlist yields 1-click ATO. Real cases:
  - `saostatic.uber.com` → `*.uber.com` SSO cookies and `auth.uber.com` bypass
    (H1 #219205 — Uber added IP restrictions to its SSO cookies in response).
  - `ping.ubnt.com` → `sso.ubnt.com` via `domain=.ubnt.com` (H1 #172137).
  - `devrel.roblox.com` → CORS to `chat.roblox.com` + cookie capture (H1 #335330).

- **CDN hosts named in a CSP allowlist.** These convert takeover into persistent
  same-origin script execution on the main app:
  - `gl-canary.freetls.fastly.net` was whitelisted in gitlab.com's
    `Content-Security-Policy` (H1 #716677).
  - `addons-preview-cdn.mozilla.net` via unregistered Fastly domain
    (H1 #2706358).

- **Staging / preview / dev / launch subdomains.** Abandoned after a feature
  launch or campaign. In the corpus: `fly.staging.shipt.com` (#576857),
  `de-headless.staging.gymshark.com` (#1711890), `new.rubyonrails.org`
  (#1429148), `course.oberlo.com` (#1690951), `delivey.yelp.com` (#1715538),
  `addons-preview.` (#2706358).

- **Help-desk / support / feedback hosts.** Zendesk, UserVoice, Desk.com and
  similar instances enable email interception and password-reset capture:
  `support.scan.me` (#114134), `help.tictail.com` (#869605),
  `feedback.screenhero.com` (#142096), a `razorzone.com` Zendesk (#810807),
  and `support.urbandictionary.com` (#103432).

- **Brand acquisitions / divested properties.** Post-acquisition DNS is rarely
  cleaned. `obviousengine.com` (Snapchat, #392785), `help.cloudup.com` (Desk.com,
  #201796), `3737signals.com` (Basecamp, #1253926), `www.cyberlynx.lu` (Acronis,
  #1256389), `images.crossinstall.com` (Twitter, #1406335), `screenhero.com`
  (Slack, #142096), `trendrr.com` (Twitter, #44578).

- **High-traffic / convincing-for-phishing hosts.** The DoD policy quoted in
  #1182864 explicitly rates takeover "on a domain that sees heavy traffic or
  would be a convincing candidate for a phishing attack" as High.

**Asset types that matter most (ranked by corpus frequency):**

1. `CNAME` pointing at a third-party provider whose resource is unclaimed — by
   far the dominant pattern (138 full reports carry the "subdomain-takeover"
   signal, 133 "subdomain").
2. Dangling `NS` delegations to an unclaimed zone — `us-east4.37signals.com`
   (#1342422), `test-cncf-aws.canary.k8s.io` (#746000, #794382).
3. `A` records pointing at an unallocated/reclaimable cloud IP — EC2 EIP
   takeovers `fr1.vpn.zomans.com` (#1182864), `v.zego.com` (#1180697),
   `max1.liveplan.com` (#1294492), `████.jitsi.net` (#1197013).
4. A *registered-but-available* target domain (expired domain / unregistered
   TLD) — `.mil` targets (#2499178, #2552243), `3737signals.com` (#1253926),
   unregistered TLD CNAME target (#1312365).
5. Host-header-injection-assisted takeover — `www.█████` (#2188240).

Payouts in the corpus range from $0 (many high-upvote reports on mature programs)
to $3,000 (Snapchat Fastly, #154425) and $500–$1,000 for many provider-specific
claims. Reported **severity** tracks the chain, not the provider: standalone
defacements are Low/Informational; SSO/CSP/cookie chains are Critical (Roblox
CVSS 9.4, Starbucks `svcgatewayus` CVSS 9.3, DoD Critical #2499178).

---

## Attack Surface Signals

### DNS signals

```
CNAME -> *.s3.amazonaws.com / *.s3-website-<region>.amazonaws.com   (S3 bucket)
CNAME -> *.cloudfront.net                                           (CloudFront)
CNAME -> *.azurewebsites.net / *.cloudapp.net / *.cloudapp.azure.com (Azure)
CNAME -> *.trafficmanager.net  (chained again to *.cloudapp.net)     (Azure TM)
CNAME -> *.herokudns.com / *.herokuapp.com                          (Heroku)
CNAME -> *.github.io / *.gitlab.io                                  (Pages)
CNAME -> *.fastly.net / *.freetls.fastly.net                        (Fastly)
CNAME -> read.uberflip.com / brandpad.io / unbouncepages.com
CNAME -> *.zendesk.com / *.uservoice.com / *.desk.com / domains.tumblr.com
CNAME -> *.wixdns.net / *.webflow.io / *.netlify.app / *.kajabi.com
NS    -> deleted authoritative zone (ns-*.awsdns-*.com, no longer assigned)
A     -> EC2 public IP / public DNS (ec2-N-N-N-N.<region>.compute.amazonaws.com)
NXDOMAIN or SERVFAIL on the target while the parent domain still resolves
Trailing-dot FQDN (e.g. `rider.uber.com.`) that evades naive CNAME matchers
```

### HTTP response / body signals (verbatim from reports)

```
"There isn't a GitHub Pages site here"              (GitHub Pages)
"NoSuchBucket" / "The specified bucket does not exist"   (S3)
"No such app"                                         (Heroku)
"Sorry, this shop is currently unavailable"            (Shopify)
"This UserVoice subdomain is available"               (UserVoice)
"Non-hub domain, The URL you've accessed does not provide a hub."  (#863551)
"Fastly error: unknown domain. Please check that this domain has been added
 to a service"                                        (Fastly)
"404 Web Site not found" / "Error 404 - Web app not found"  (Azure)
"Not Found" + CNAME to brandpad.io                    (#1474784)
"DEPLOYMENT_NOT_FOUND"                                (Vercel)
Generic provider 404 with a `Server:` / `X-Served-By:` header naming provider
```

### Tech-stack / header signals

- `X-Served-By: cache-*`, `X-Cache`, `Via: fastly` — Fastly/CDN fingerprint.
- `Server: Mashery Proxy` — the Starbucks `developer.openapi.starbucks.com`
  takeover (H1 #275714); registering a Mashery trial let the researcher add the
  domain and serve `alert(document.domain)`.
- `Server: Netlify`, `X-GitHub-Request-Id`, `Server: cloudflare` combined with a
  provider 404 — identify the claimable namespace.
- TLS certificate issued to a provider wildcard (`*.fastly.net`,
  `*.azurewebsites.net`) rather than the company domain — Snapchat confirmed
  ownership of `fastly.sc-cdn.net` via a Censys certificate search (#154425).
- A certificate-transparency entry for a hostname that no longer resolves in
  DNS — the classic "ghost subdomain" source (#1294492 used SSLEnum + CT).

### Provider → claim primitive quick-reference (all observed in the corpus)

| Provider / service | Fingerprint CNAME | Claim primitive |
|---|---|---|
| AWS S3 | `*.s3.amazonaws.com`, `*.s3-website-*` | Create bucket with exact name, enable static hosting |
| AWS CloudFront | `*.cloudfront.net` | Create distribution with the domain as alternate CNAME |
| AWS EC2 (EIP) | `A` → public IP / `ec2-*.compute.amazonaws.com` | Allocate the same EIP / re-launch instance |
| AWS Route53 (NS) | `NS` → `ns-*.awsdns-*.com` | Create matching hosted zone in Route53 |
| Azure Web / Cloud Service | `*.azurewebsites.net`, `*.cloudapp.net` | Create app/service with the exact released name |
| Azure Traffic Manager | `*.trafficmanager.net` | Create profile with the name (chains to cloudapp) |
| Azure CDN | `*.azureedge.net`, CDN profiles | Create CDN profile with the released name (#900062) |
| Fastly | `*.fastly.net`, `*.freetls.fastly.net` | New service, attach the dangling hostname as a domain |
| Heroku | `*.herokudns.com`, `*.herokuapp.com` | Create app / add custom domain |
| GitHub Pages | `*.github.io` | Create repo/org page at the unclaimed namespace |
| GitLab Pages | `*.gitlab.io` | Create project; no ownership verification (#2523654) |
| Netlify | `*.netlify.app` | Deploy new project; add custom domain (#197489) |
| Unbounce | `unbouncepages.com`, `app.unbounce.com` | Register page + add domain (API flaws #202767) |
| Zendesk / UserVoice / Desk.com | `*.zendesk.com`, `*.uservoice.com`, `*.desk.com` | Free trial, add subdomain, enable host-mapping |
| WordPress / Tumblr / Medium | `*.wordpress.com`, `domains.tumblr.com` | Claim abandoned site / connect custom domain |
| Brandpad / Kajabi / Wix / Webflow / HubSpot / Mashery / Uberflip / Feed.Press / UptimeRobot / Squarespace | vendor-specific CNAME | Register account, add hostname as custom domain |

---

## Discovery Patterns From 148 Full Reports

### Where Researchers Start (ranked recon surfaces w/ "what to look for")

Ranked by how frequently the mined reports actually started from each surface.
Each entry states **what to look for** — this is the recon priority order that
the corpus supports.

1. **Passive subdomain enumeration of the whole domain.** The single most common
   starting point. Researchers used `subfinder`, `amass`, `knockpy`, `assetfinder`.
   *What to look for:* any hostname whose DNS record is stale, NXDOMAIN, or points
   into a third-party provider namespace. Evidence: "I scanned gratipay.com using
   knockpy to find the sub domains" (#257331); "find its sub-domains using
   Subfinder" (#1717626).

2. **Certificate transparency logs.** `crt.sh/?q=%.target.com`, Censys, SSLEnum.
   *What to look for:* a cert for a hostname that no longer resolves, or resolves
   to a provider wildcard. Snapchat's `fastly.sc-cdn.net` was confirmed as company
   property via Censys (#154425); SSLEnum pulled cert data for `max1.liveplan.com`
   (#1294492).

3. **Direct DNS record inspection (`dig CNAME` / `dig NS` / `dig A`).** Researchers
   repeatedly say "Using dig, I was able to determine that the subdomain ...
   was vulnerable" (#661751, #900062, #874482). *What to look for:* CNAME chain
   terminating at an unclaimed provider resource, NS zone that has been deleted,
   A record at a released EC2 IP. "dig CNAME sub.target.com" is the single highest
   yield action in the corpus.

4. **Vendor / service-specific username & subdomain availability checks.**
   "username availability check at zendesk" (#869605); "I tried adding the
   specific domain, but it said it was already added somewhere" (#148770);
   "it can be added to any account" (#863551, #1474784). *What to look for:*
   provider onboarding that accepts a domain belonging to someone else without
   verifying ownership.

5. **Acquisition / divestiture OSINT.** Crunchbase, Wikipedia, public acquisition
   lists. "while searching in snapchat acquisitions i found `obviousengine`"
   (#392785); "the acquisition where I found this domain is trendrr" (#44578).
   *What to look for:* acquired brands whose subdomains still CNAME to lapsed
   services; whole acquired domains that expired (#1256389, #392785).

6. **Disclosed-report pivot.** Reading an existing report and testing the same
   asset/provider elsewhere. "I was looking at recent disclosed report #1297689
   and I was thinking to take a look for the same issue on this asset" (#1312365);
   "same issue of report #32825" (#42236); "this report is same as of this one"
   (#407355). *What to look for:* sibling subdomains, sibling acquisitions, the
   same provider across the whole asset list.

7. **Mobile app / JS / source-code review.** "While i was analyzing the `Basecamp3`
   Android app i found `3737signals.com` on the source code" (#1253926); "Recently
   I found a new subdomain pushed" (#1034023); leaked base64 config with
   `SECRET_KEY` on a dangling Shopify host (#1590115). *What to look for:*
   hardcoded domains, `intent` URLs, config files, encoded settings that name
   forgotten hosts.

8. **Public-code / GitHub search.** "public-code-search" appears in 23 full
   reports. `dev.rbk.money` pointed to GitHub but was unused (#363778);
   `engineering.udemy.com` → ghost.io (#368119). *What to look for:* CNAME targets
   referenced in public repos but no longer owned by the company.

9. **Wayback / archive.org.** Checking what a host used to serve to identify the
   provider and the original claim flow (#1690951 used a web.archive.org snapshot
   for `course.oberlo.com`; #746000 for the Route53 zone). *What to look for:*
   the historical provider behind a now-404 hostname.

10. **Casual browsing / "unusual hostname" discovery.** "A few days ago, I was
    looking at Roblox subdomains, and I noticed an unusual one called creatorforum"
    (#264494); "I had never seen that domain before, so I decided to find out what
    else was running on it" (#195350). *What to look for:* weird, old, or
    inconsistent subdomain names in the cert set.

11. **Internet search-engine dorking / asset lists.** "internet-search-engine"
    and "stack-fingerprinting" signals appear in the frequency table; DoD targets
    were found "from the DoD websites list" (#918946). *What to look for:* indexed
    but forgotten hosts, public asset lists, bug-bounty scope lists.

12. **Bug-bounty scope / asset-list sweep.** Many reports begin by systematically
    testing every in-scope wildcard — e.g. the Mozilla `mozaws.net` / `mozgcp.net`
    families produced a dozen separate reports (#2269867, #2545012, #2140976,
    #2286867, #2209571, and more). *What to look for:* `*.target.com` wildcards
    whose individual hosts are unmonitored.

### Feature-Based Discovery Signals (frequency-ranked table w/ "why it matters / what to probe")

Frequencies are counts of full reports containing the signal (out of 148 mined).
This is where to spend recon effort.

| Rank | Signal (reports) | Why it matters / what to probe |
|---|---|---|
| 1 | `subdomain-takeover` (138) | Core pattern — enumerate → resolve → classify dangling record. Probe every NXDOMAIN CNAME. |
| 2 | `subdomain` (133) | Any forgotten hostname is a candidate. Probe the full CT + passive set, not just the main site. |
| 3 | `image-processing` (47) | Co-occurs with `images.`/`cdn.`/`assets.` hosts pointing at S3/Fastly. Probe static-asset hosts first — `images.crossinstall.com` (#1406335), `news-static.semrush.com` (#294201). |
| 4 | `cookie-handling` (42) | The escalation signal: parent-scoped cookies (`Domain=.target.com`) turn a takeover into ATO. Probe `Set-Cookie` on the main app for sibling bleed. |
| 5 | `search-filter-sort` (41) | Co-occurs with multi-subdomain sweeps (Shipt fly.*). Probe for several stale records at once, not just one. |
| 6 | `filter-bypass` (36) | Provider validation bypasses (Unbounce endpoints, Fastly no-ownership, trailing dot). Probe alternate onboarding endpoints/params when the normal claim is blocked. |
| 7 | `public-code-search` (23) | Repos/configs leak forgotten hostnames and CNAME targets (#363778, #392785). Probe GitHub/code search for the target's domains. |
| 8 | `redirect-handling` (22) | S3 buckets used as redirects + open-redirect chains (#230525, #189548). Probe the takeover host for redirect behavior. |
| 9 | `auth-bypass` (18) | The money chain. Probe SSO hosts and cookie domain attributes (#335330, #219205). |
| 10 | `server-side-rendering` (18) | Co-occurs with stale CDN/asset hosts; relevant to CSP-script-src chains. Probe CSP headers. |
| 11 | `cache-layer` (17) | Fastly/CloudFront fingerprints. Probe `X-Served-By`/`X-Cache` and provider error text. |
| 12 | `api-endpoint` (16) | Provider APIs used to claim domains (Unbounce POST endpoints #209004, #220002). Probe the provider API, not only the UI. |
| 13 | `sso-oauth` (12) | Query redirect_uri/SSO allowlists for the candidate (#1182864, #1180697). Probe `/oauth/authorize`. |
| 14 | `session-attack` (11) | Session-cookie theft via shared parent domain. Probe cookie scope and session fixation. |
| 15 | `proxy-feature` (11) | Webflow/Fastly proxy hosts that 404 (#233402, #172137). Probe proxy-style CNAMEs. |
| 16 | `cloud-metadata` (8) | EC2 EIP/IP takeovers where metadata + TLS cert are obtainable. Probe released cloud IPs. |
| 17 | `admin-internal` (7) | `dev-admin.`/`admin.` hosts often left dangling (#531890). Probe admin-named subdomains. |
| 18 | `cors-misconfig` (6) | `devrel.roblox.com` allowlisted for CORS to `chat.roblox.com` (#335330). Probe `Access-Control-Allow-Origin`. |
| 19 | `dos-resource` (6) | Claimed resources abused for traffic/resource exhaustion on the trusted host. |
| 20 | `stored` (5) | Stored XSS on the takeover host (`storybook.lystit.com` /asdjklkas...html #779442). Probe file upload to the claimed resource. |
| 21 | `csrf` (5) / `file-upload` (5) | Co-occurring primitives on SSO chains and claimed buckets. |
| 22 | `open-redirect` (4) / `url-fetching` (3) | Redirect-chain abuse from a claimed S3 bucket (#230525, #189548). |
| 23 | `blind-oob` (3) / `js-source-review` (3) / `misconfiguration` (3) | Secondary signals; include in broad sweeps. |
| 24 | `wayback-machine` (2) / `host-header` (2) / `debug-error-leak` (2) / `xml-parser` (2) | Historical provider ID, Host-header injection, verbose error/key leaks (#1590115). |
| 25 | `dom-based` / `clickjacking` / `port-scanning` / `null-byte` / `template-engine` / `internet-search-engine` / `stack-fingerprinting` / `deserialization` / `base64-encoding` (1 each) | One-off signals; check when the above are exhausted. |

### Verbatim Discovery Clues (18 real `[#id]` quotes)

Verbatim "how I found it" lines from the 148 full reports (truncations are exactly
as they appear in the corpus):

1. `[#665398]` "I noticed the dangling CNAME record of datacafe-cert."
2. `[#779442]` "I was able to register a S3 bucket with this name in AWS."
3. `[#779442]` "After enabling static website hosting I was able to takeover the subdomain and serve arbitrary content."
4. `[#352869]` "I was able to take over the domain:"
5. `[#202767]` "While testing UnbouncePage services i saw that they block any domain that was already claimed, but i decided go deeper and I found an 0day in their API which allows any user to claim any domain with a DNS entry pointing to -> __unbouncepages."
6. `[#661751]` "Using dig, I was able to determine that the subdomain 'd02-1-ag."
7. `[#154425]` "I've found a snapchat cdn domain here which had a test instance of fastly setup but did not remove the dns record when the service was cancelled."
8. `[#1182864]` "I was able to take control of this IP address and run my own EC2 instance."
9. `[#264494]` "A few days ago, I was looking at Roblox subdomains, and I noticed an unusual one called creatorforum."
10. `[#121461]` "I started looking for DNS entries that were still pointing to S3 buckets that however no longer exist."
11. `[#1406335]` "I was able to take control of this bucket and put my own content onto it."
12. `[#746000]` "These name server records have been deleted, I was able to create a matching zone file, and takeover full control of the domain, and all DNS records."
13. `[#1312365]` "I was looking at recent disclosed report #1297689 and I was thinking to take a look for the same issue on this asset as I love to test for subdomain takeover vulnerabilities."
14. `[#1253926]` "While i was analyzing the `Basecamp3` Android app i found `3737signals."
15. `[#340580]` "Fastly doesn't require any proof of DNS ownership to register new distributions that use a given domain, so I was able to effectively take it over."
16. `[#392785]` "while searching in snapchat acquisitions i found ` obviousengine ` moe information here https://www."
17. `[#1527405]` "+ While testing ** Imgur ** I found an unclaimed subdomain which is; "8ybhy85kld9zp9xf84x6."
18. `[#869605]` "Using dig and and username availability check at zendesk, I was able to determine that the subdomain https://help."

### Probe Checklist (15 concrete probes)

Run these in order on every candidate host. Each is a concrete action derived
from the reports.

1. **Resolve the record.** `dig +short CNAME sub.target.com` — confirm a CNAME
   exists (not just an A record).
2. **Walk the CNAME chain.** `dig +short CNAME <cname-target>` repeatedly — the
   Starbucks/Ford cases chained `trafficmanager.net → cloudapp.net`
   (#325336, #484420, #380158).
3. **Check the terminal target.** `dig +short A <final-target>` — look for
   NXDOMAIN / no A record (unclaimed provider resource).
4. **Probe the NS case.** `dig NS sub.target.com` — if delegated to a deleted
   Route53 zone, plan a matching hosted zone (#746000, #794382).
5. **Probe the A/EIP case.** `dig +short sub.target.com` → IP; `whois <ip>` /
   `dig -x <ip>` to see if it is a released EC2 EIP (#1180697, #1294492).
6. **Fetch over both HTTP and HTTPS.** `curl -sk http://sub.target.com` and
   `curl -sk https://sub.target.com` — providers show different errors per scheme.
7. **Match provider error strings** against the fingerprint table above
   (`NoSuchBucket`, `no such app`, `Fastly error: unknown domain`,
   `DEPLOYMENT_NOT_FOUND`, etc.).
8. **Inspect response headers.** `curl -sI` for `Server:`, `X-Served-By:`,
   `X-Cache:`, `Via:` to fingerprint the provider.
9. **Test the trailing-dot variant.** `dig +short sub.target.com.` — the
   `rider.uber.com.` pattern (#175070); claim UIs may accept/reject dotted forms
   differently.
10. **Check claimability at the provider.** Visit the provider's onboarding URL
    and try to add `sub.target.com` as a custom domain — confirm no ownership
    verification (#863551, #1474784, #148770).
11. **Probe provider API endpoints too.** If the UI blocks, intercept onboarding
    and replay with modified body params/endpoints (Unbounce POST
    `/[account]/pages/[id]/url` #220002, `/[account]/pages/[id]` #209004).
12. **Search CT and archives.** `curl -s "https://crt.sh/?q=%.target.com&output=json"`
    and the Wayback Machine — identify the historical provider and other ghost
    hosts.
13. **Read the CSP on the main app.** `curl -s https://target.com | grep -i
    content-security-policy` — is the candidate allowlisted in `script-src` /
    `connect-src`? (#716677).
14. **Read Set-Cookie on the main app.** `curl -sI https://app.target.com | grep -i
    '^set-cookie'` — look for `Domain=.target.com` bleed (#219205, #172137).
15. **Read the OAuth flow.** `GET /oauth/authorize?...` and check the
    `redirect_uri` allowlist for the candidate host; also grep JS for
    `postMessage` `targetOrigin` checks that name the host.

---

## Step-by-Step Hunting Methodology

1. **Define scope and collect the full asset set.** Confirm whether
   `*.target.com` is implicitly in scope. Run passive-only enumeration first to
   avoid WAF/IDS triggers:
   ```bash
   subfinder -d target.com -all -o subs.txt
   amass enum -passive -d target.com >> subs.txt
   assetfinder --subs-only target.com >> subs.txt
   curl -s "https://crt.sh/?q=%.target.com&output=json" \
     | jq -r '.[].name_value' >> subs.txt
   sort -u subs.txt -o subs.txt
   ```

2. **Resolve and classify every host.** Flag NXDOMAIN, CNAME-to-provider,
   dangling NS, and released-A records:
   ```bash
   cat subs.txt | dnsx -a -cname -ns -o resolved.txt
   while read s; do
     echo "== $s"
     dig +short CNAME "$s"
     dig +short NS "$s"
     dig +short A "$s"
   done < subs.txt
   ```

3. **Kill false positives first.** A CNAME that still resolves to a live provider
   resource serving the company's real content is NOT a takeover. Confirm the
   resource is genuinely unclaimed (error string / NXDOMAIN / provider "add
   domain" acceptance). Do not report on a host that simply returns a 404 from a
   healthy origin.

4. **Fingerprint the provider** from the CNAME target + error body + headers (see
   Attack Surface Signals). Map it to the claim primitive in the quick-reference
   table. Many chains matter here: `trafficmanager.net → cloudapp.net`,
   `CNAME → s3-website-<region>`, `CNAME → wixdns.net → ...`.

5. **Confirm claimability without causing harm.** Attempt to register/add the
   hostname at the provider. For S3:
   `aws s3api head-bucket --bucket <name>` should return 404 / NoSuchBucket. For
   provider UIs: attempt to add the custom domain and observe acceptance
   (#863551 "it can be added to any account"; #1474784 "it can be added to any
   account" via Brandpad).

6. **Claim only enough to prove control.** Host a minimal page containing your
   HackerOne username and a unique timestamp token. Do NOT serve phishing,
   malware, or credential harvesters. Real reporters used an HTML comment
   `<!-- hackerone.com/ian -->` (#1180697, #1406335) and simple `poc.html` /
   `takeover.html` / `proof-<uuid>.txt` files (#531890, #2552243).
   - **TLS:** many providers (GitHub Pages, Netlify, Vercel, Fastly) auto-issue
     TLS on claim. If HTTPS still errors, demonstrate over HTTP and note that TLS
     resolves post-claim — #201796 showed full CNAME control despite an expired
     certificate blocking the HTTPS proof.

7. **Screenshot the three proof points immediately:**
   - (a) `dig` showing the dangling record;
   - (b) `curl` showing the provider error before claim;
   - (c) your marker content served on the host after claim.
   Record a short video if the claim window is short.

8. **Escalate through the five chains before writing the report** (see Related
   Skills & Chains). Run the Gate 0 checklist. A bare defacement is Low; a chain
   is High/Critical. The corpus is unambiguous: Roblox (CVSS 9.4), Uber SSO
   bypass, Ubiquiti SSO bypass, and GitLab CSP are all chain cases.

9. **Check severity drivers.** Is the host in a CSP allowlist? Does it share
   parent-domain cookies? Is it in an OAuth redirect allowlist? Does it receive
   email (MX/SPF/DKIM)? Is it high-traffic/convincing for phishing (the policy
   quoted in #1182864)? Each yes raises severity.

10. **Write the report with the full chain** — DNS record → provider target →
    unclaimed resource → claim proof → downstream impact. Include remediation:
    remove the stale DNS record and reclaim it at the provider before releasing
    the claim (#325336, #388622 gave exactly this two-step remediation).

11. **Release the claim only after triage** where required. Some programs ask to
    verify first; keep the marker live until the report is acknowledged, then
    release so the company can reclaim the name.

12. **Pivot to sibling assets.** Once one takeover is confirmed, sweep the same
    provider/brand for more. Shipt #576857 found three `fly.*` hosts; Mozilla
    `mozaws.net` produced a dozen reports; Starbucks produced 10+ (665398,
    661751, 325336, 186766, 388622, 484420, 380158, 275714, 383564, 570651).

---

## Payload & Detection Patterns

### Bulk CNAME extraction + NXDOMAIN detection

```bash
while read sub; do
  cname=$(dig +short CNAME "$sub" | head -1)
  if [ -n "$cname" ]; then
    result=$(dig +short A "$cname" | head -1)
    if [ -z "$result" ]; then
      echo "[POTENTIAL] $sub -> $cname (NXDOMAIN)"
    fi
  fi
done < subs.txt | tee potential.txt
```

### Provider fingerprint grep (run against every candidate)

```bash
curl -sk "https://$sub" | grep -iE \
  "there isn't a github pages|no such bucket|the specified bucket does not exist|no such app|this uservoice|fastly error: unknown domain|non-hub domain|deployment_not_found|do you want to register|sorry, this shop|project not found|404 web site not found|not found|unclaimed"
```

### Automated scanners

```bash
subjack -w subs.txt -t 100 -timeout 30 -ssl -c fingerprints.json -v
nuclei -l subs.txt -t ~/nuclei-templates/http/takeovers/ -severity medium,high,critical
subzy run --targets subs.txt --concurrency 100
# knockpy was the tool of choice in #257331
knockpy target.com
```

### S3-specific

```bash
dig +short CNAME sub.target.com
# e.g. assets.target.com.s3.amazonaws.com. -> s3-1-w.amazonaws.com. -> <IP>
aws s3api head-bucket --bucket <bucket-name> 2>&1 | grep -iE "NoSuchBucket|404|403"
curl -s http://sub.target.com | grep -i "NoSuchBucket"
# region quirk: a bucket in us-east-1 addressed via another region returns a
# redirect error (#1297689 — "S3 has a weird quirk where the bucket's region
# may cause errors if a request to a bucket is addressed to the wrong region")
```

### CloudFront-specific

```bash
dig +short CNAME cdn.target.com   # -> d123abc.cloudfront.net
curl -sI https://cdn.target.com   # -> provider 404 / "The request could not be satisfied"
# CloudFront does not validate which account connects a CNAME as an alternate
# domain (#145224, #352869, #175070)
```

### Azure-specific (cloudapp / trafficmanager / cloud services / CDN)

```bash
dig +short CNAME sub.target.com
# svcgatewayus.starbucks.com -> s00197tmp0crdfulprod0.trafficmanager.net
#                            -> 1fd05821-7501-40de-9e44-17235e7ab48b.cloudapp.net
# NXDOMAIN on the cloudapp target = claimable by creating a resource with that
# exact name (#325336, #484420, #661751, #388622, #380158, #900062)
dig +short CNAME sub.target.com | grep -E "azurewebsites|cloudapp|trafficmanager"
```

### Fastly-specific

```bash
curl -sI https://sub.target.com -H "Host: sub.target.com" | grep -iE "fastly|x-served-by|x-cache"
curl -sk https://sub.target.com | grep -i "fastly error: unknown domain"
# claim: sign up for Fastly, create a new service, attach the dangling hostname
# as a service domain — Fastly historically required no proof of DNS ownership
# (#340580, #2706358, #716677, #165309, #154425)
```

### NS-delegation takeover

```bash
dig NS sub.target.com
# e.g. ns-265.awsdns-33.com. ... (#794382)
# claim: create a Route53 hosted zone with the exact name; AWS assigns these NS
# prove by creating a TXT/A record and resolving it (#746000)
```

### EC2 EIP / dangling A record

```bash
dig +short sub.target.com            # -> 52.214.138.192
dig -x 52.214.138.192                # check reverse DNS
curl -s https://crt.sh/?q=sub.target.com  # cert may still be valid for the host
# claim: allocate the released EIP in the same region and serve a marker
# (#1180697, #1182864, #1197013, #1296366)
```

---

## Common Root Causes

1. **Service offboarding without DNS cleanup.** The dominant cause. An Azure
   webservice, Heroku app, Shopify store, UserVoice/Zendesk/Desk.com account, or
   WordPress site is deleted while the CNAME lives forever (#665398, #424669,
   #142096, #269109, #274336, #201796).

2. **Staging / preview / campaign infrastructure abandoned after launch.**
   `fly.staging.shipt.com` (#576857), `addons-preview-cdn.mozilla.net`
   (#2706358), `new.rubyonrails.org` (#1429148), `course.oberlo.com`
   (#1690951), `de-headless.staging.gymshark.com` (#1711890),
   `delivey.yelp.com` (#1715538).

3. **Third-party-owned DNS split from service ownership.** Marketing sets up a
   Zendesk/Unbounce/Mashery subdomain, product sunsets it, engineering owns DNS
   and never hears about it (#275714, #407355, #148770).

4. **Providers that do not verify domain ownership.** Fastly historically let
   any CNAME into its anycast be attached to a new service (#340580, #2706358,
   #716677); CloudFront did not validate who connects a CNAME (#145224,
   #352869); GitLab Pages added subdomains with no ownership verification
   (#2523654, #2523677); Unbounce/Mashery/Brandpad/Uberflip accepted arbitrary
   domains (#202767, #275714, #1474784, #863551).

5. **Cloud resources released but DNS left pointing.** EC2 EIPs unallocated,
   Azure Cloud Services released, Route53 zones deleted (#1180697, #661751,
   #746000, #794382, #2552243).

6. **Using public EC2 DNS instead of an Elastic IP in a CNAME.** When the
   instance dies, the public DNS name can be reclaimed by another customer
   (#1294492: "due to using EC2 public DNS instead of using Elastic IPs").

7. **Acquisitions / divestitures with no DNS hygiene.** Former-brand subdomains
   retained after the company is bought or sold (#392785, #1256389, #1406335,
   #44578, #1183296).

8. **Expired or never-registered target domains / TLDs.** A CNAME to a domain
   whose registration lapsed, or to an unregistered TLD, becomes claimable by
   registering it (#1312365, #1253926, #2499178, #2552243).

9. **Trailing-dot normalization gaps.** Scanners/validators that strip the
   trailing dot miss dangling records that still resolve (`rider.uber.com.`
   #175070, `coding-exercises.udemy.com` #223625).

10. **Wildcard DNS entries.** `*.target.com` pointing into a provider means any
    unclaimed name under it can be caught; combined with CSP/CORS wildcards this
    widens the blast radius.

---

## Bypass Techniques

**When the provider UI blocks claiming a domain:**

- **Use the provider's API / an alternate endpoint.** Unbounce blocked
  already-claimed domains in the UI but an API flaw let a researcher claim any
  domain with an `unbouncepages.com` CNAME (#202767). After the fix, researchers
  bypassed via POST body params and alternate URL endpoints (#209004, #220002).
  Intercept onboarding in Burp and replay with modified `page[url]` params and
  endpoint paths.

- **Try free-trial and "add existing domain" flows.** Zendesk and Desk.com trials
  let you add a hostname and enable host-mapping without ownership proof
  (#201796, #810807, #869605, #1486670).

- **Try a different region / account namespace.** S3 regional quirks (#1297689)
  and Azure regional pools mean a resource released in one region/account may be
  claimable in another.

**When fingerprinting fails:**

- **Test HTTP and HTTPS separately.** Providers return different errors per
  scheme; some show the takeover page only on HTTP (#201796).

- **Use historical fingerprints.** Providers change their 404 pages; keep an
  updated fingerprint list and corroborate with CNAME + headers rather than the
  body alone.

- **Trailing-dot bypass.** Try both `sub.target.com` and `sub.target.com.`;
  claim UIs and CDNs may treat them differently (#175070, #223625).

- **Host-header manipulation.** A takeover can be enabled by Host-header
  injection on the upstream (#2188240).

**Defense / scope bypasses:**

- **"Only main domain in scope."** Many programs implicitly include
  `*.target.com`; verify the scope wording and escalate impact to justify
  inclusion. Some programs accepted serious out-of-scope cases (Basecamp
  #1253926 "I know it's OOS but the issue is pretty serious"; GitLab #716677
  used a CSP-allowlisted `freetls.fastly.net` host).

- **"Low severity / no impact."** Demonstrate a chain: cookie theft, OAuth
  redirect abuse, CSP bypass, stored XSS, or email interception. The GitLab CSP
  case (#716677) and Roblox CORS case (#335330) are the model.

- **"Can't reproduce" due to timing.** Claims can be taken by others quickly;
  screenshot immediately, record a video, and keep the marker until triage.

- **TLS mismatch blocking proof.** Demonstrate over HTTP and note that the
  provider auto-issues TLS on claim (GitHub Pages/Netlify/Vercel/Fastly); if not,
  state that a legitimate claim resolves it (#201796).

- **Rate limiting on enumeration.** Use passive sources (CT logs, Censys,
  SecurityTrails, Shodan, VirusTotal); DNS resolution does not touch the web
  server.

---

## Gate 0 Validation

Before writing the report, confirm all three:

1. **What can the attacker DO right now?**
   - Show the *current* dangling DNS record (`dig`), the provider error, and your
     unique marker served on the host. "It 404s" is not enough — prove the
     resource is unclaimable by the owner but claimable by you.
   - Demonstrate at least one concrete capability: arbitrary content hosting, a
     cookie-capture script (Roblox #335330), an OAuth callback receiver,
     CSP-allowlisted JS (GitLab #716677), or email send/receive on the delegated
     zone (#746000).

2. **What does the victim LOSE?**
   - Quantify the chain: session cookies if `Domain=.target.com`; SSO/auth-code
     theft if in an OAuth allowlist; stored XSS if CSP-allowlisted; email
     interception / password-reset capture if MX/SPF/DKIM or a help-desk host;
     brand/phishing trust on a high-traffic host (DoD policy quoted in #1182864).
   - If the only impact is "attacker can host a page on an obscure subdomain,"
     file at Low/Informational — do not claim Critical without a chain.

3. **Can it be reproduced in 10 minutes from scratch?**
   - `dig CNAME sub.target.com` → dangling record;
   - `curl -sk https://sub.target.com` → provider error;
   - provider onboarding → accepts the domain;
   - your marker → visible on the hostname.
   Four steps, screenshots for each.
   - Confirm the claim is stable (not a race) and that a second person can follow
     your steps. Resolve flakiness before submitting.

**Never-submit list:**

- A CNAME that still serves the company's real content.
- A provider 404 on a healthy, claimed origin.
- A host out of scope with no serious chain.
- Any report where you cannot show the resource is genuinely unclaimed.

---

## Real Impact Examples

### Scenario A — SSO Cookie Theft → Full Authentication Bypass (Uber / Ubiquiti / Roblox pattern)

`saostatic.uber.com` pointed to an unclaimed resource. The SSO session cookie for
`auth.uber.com` was scoped with `domain=.uber.com`, so a takeover let the attacker
harvest `*.uber.com` cookies and bypass SSO entirely (H1 #219205 — Uber
immediately fixed the takeover and added IP restrictions to the SSO cookies).
The identical shape appears at `ping.ubnt.com` → `sso.ubnt.com` via
`domain=.ubnt.com` (#172137), and at `devrel.roblox.com`, where the takeover page
captured cookies and was also allowlisted for CORS to `chat.roblox.com`, letting
the attacker read chat messages cross-origin (#335330, CVSS 9.4). These are the
highest-severity cases in the corpus.

### Scenario B — CSP-Allowlisted CDN Host → Persistent Same-Origin Script Execution (GitLab / Mozilla pattern)

`gl-canary.freetls.fastly.net` was explicitly whitelisted in gitlab.com's
`Content-Security-Policy` (H1 #716677). An attacker who re-attached the dangling
Fastly hostname could serve JavaScript that the browser treats as trusted per
CSP, executing with gitlab.com origin on every page that loads it. Likewise
`addons-preview-cdn.mozilla.net` was takeable via an unregistered Fastly domain
(H1 #2706358) — a CDN host under `mozilla.net` that CSP/CORS may trust. This
converts a Low defacement into Critical stored-XSS-equivalent.

### Scenario C — Help-Desk Takeover → Email Interception → Password Reset (Zendesk / UserVoice / Desk pattern)

`support.scan.me`, `help.tictail.com`, `feedback.screenhero.com`, and a
`razorzone.com` Zendesk instance were all takeable help-desk hosts
(H1 #114134, #869605, #142096, #810807). Once the attacker controls the
Zendesk/UserVoice instance, they can configure email forwarding, intercept
tickets sent to `support@target.com`, and capture password-reset or payment
emails. This escalates from defacement to account takeover and payment-info
theft without ever touching the main app. #269109 and #274336 show the same
pattern via unclaimed UserVoice and WordPress instances.

### Scenario D — Dangling NS / EC2 EIP → Full DNS or TLS Control (Kubernetes / DoD pattern)

`api.e2e-kops-aws-canary.test-cncf-aws.canary.k8s.io` delegated to deleted Route53
nameservers; the researcher created a matching zone and gained control of *all*
records including MX, enabling email addresses at the domain and admin-panel
access that only required an email-at-domain proof (#746000, #794382). EC2 EIP
takeovers (`fr1.vpn.zomans.com`, `v.zego.com`, `images.crossinstall.com`) let the
attacker serve content and obtain a valid TLS certificate for the trusted
hostname via file-based verification (#1180697, #1182864, #1406335). The `.mil`
targets (#2499178, #2552243) show the extreme: a CNAME to an available domain
that an attacker could register to host content, receive email, and execute XSS
on a government-branded host.

### Scenario E — Abandoned SaaS → Trusted-Brand Phishing (Snapchat / Starbucks pattern)

`fastly.sc-cdn.net` was a Fastly test instance whose DNS record survived
cancellation; the researcher created a new Fastly instance and served arbitrary
content (H1 #154425, $3,000). `happymondays.starbucks.com` pointed to a deleted
S3 bucket; the researcher registered it, served content, and noted they could
even fetch httpOnly cookies and register a Let's Encrypt certificate (#186766).
On a trusted brand domain, users cannot distinguish attacker content from
legitimate content — ideal for credential-harvesting and spear-phishing, exactly
as multiple reporters described (#779442, #352869, #186766, #424669).

---

## Disclosed Report Citations (30 verified IDs — all present in the study pack or TOPS list)

1. **Roblox — Subdomain Takeover to Authentication bypass** ([H1 #335330](https://hackerone.com/reports/335330)) — CNAME takeover → cookie capture + CORS to `chat.roblox.com`, 2018, Critical CVSS 9.4, $0.
2. **Starbucks — Subdomain takeover of datacafe-cert.starbucks.com** ([H1 #665398](https://hackerone.com/reports/665398)) — dangling CNAME to unclaimed Azure webservice (`azurewebsites.net`), 2019, High CVSS 7.5, $0.
3. **Uber — Authentication bypass on auth.uber.com via subdomain takeover of saostatic.uber.com** ([H1 #219205](https://hackerone.com/reports/219205)) — SSO `domain=.uber.com` cookie chain → ATO, $0.
4. **Lyst — Subdomain takeover of storybook.lystit.com** ([H1 #779442](https://hackerone.com/reports/779442)) — unclaimed S3 bucket → stored XSS, 2020, High CVSS 7.3, $1,000.
5. **Grab — Subdomain Takeover Via Insecure CloudFront Distribution cdn.grab.com** ([H1 #352869](https://hackerone.com/reports/352869)) — unclaimed CloudFront alternate CNAME, 2018, Medium, $1,000.
6. **HackerOne — Subdomain takeover at info.hacker.one** ([H1 #202767](https://hackerone.com/reports/202767)) — Unbounce pages API 0day, 2017, Low CVSS 3.5, $0.
7. **Starbucks — Subdomain takeover of d02-1-ag.productioncontroller.starbucks.com** ([H1 #661751](https://hackerone.com/reports/661751)) — NXDOMAIN CNAME → Azure Cloud Service (`cloudapp.net`), 2019, High CVSS 8.4, $0.
8. **Snapchat — Subdomain takeover on fastly.sc-cdn.net** ([H1 #154425](https://hackerone.com/reports/154425)) — abandoned Fastly instance, confirmed via Censys cert, 2016, $3,000.
9. **Starbucks — Subdomain takeover on svcgatewayus.starbucks.com** ([H1 #325336](https://hackerone.com/reports/325336)) — `trafficmanager.net → cloudapp.net` unclaimed Azure, 2018, Critical CVSS 9.3, $0.
10. **Starbucks — Subdomain takeover on happymondays.starbucks.com due to non-used AWS S3 DNS record** ([H1 #186766](https://hackerone.com/reports/186766)) — unclaimed S3 bucket, httpOnly-cookie/TLS impact, 2016, High, $0.
11. **Ford — Subdomain takeover on usclsapipma.cv.ford.com** ([H1 #484420](https://hackerone.com/reports/484420)) — `trafficmanager.net → cloudapp.azure.com` unclaimed, 2019, High, $0.
12. **Eternal — Subdomain takeover of fr1.vpn.zomans.com** ([H1 #1182864](https://hackerone.com/reports/1182864)) — dangling EC2 EIP A record, TLS + phishing impact, 2021, Medium, $350.
13. **HackerOne — Subdomain takeover of resources.hackerone.com** ([H1 #863551](https://hackerone.com/reports/863551)) — Uberflip `read.uberflip.com` "can be added to any account", 2020, Low CVSS 3.6, $500.
14. **Roblox — Subdomain Takeover at creatorforum.roblox.com** ([H1 #264494](https://hackerone.com/reports/264494)) — CNAME to nonexistent Discourse site, 2017, High, $0.
15. **Starbucks — Subdomain takeover on wfmnarptpc.starbucks.com** ([H1 #388622](https://hackerone.com/reports/388622)) — unclaimed Azure Traffic Manager profile, 2018, High, $0.
16. **Zego — Subdomain takeover of v.zego.com** ([H1 #1180697](https://hackerone.com/reports/1180697)) — dangling EC2 EIP A record, 2021, High, $0.
17. **Paragon Initiative Enterprises — Subdomain Takeover** ([H1 #180393](https://hackerone.com/reports/180393)) — CNAME to `domains.tumblr.com`, 2016, Critical, $0.
18. **Uber — Subdomain takeover at signup.uber.com** ([H1 #197489](https://hackerone.com/reports/197489)) — unclaimed Netlify domain, $0.
19. **Bime — Subdomain takeover due to unclaimed Amazon S3 bucket on a2.bime.io** ([H1 #121461](https://hackerone.com/reports/121461)) — S3 bucket → XSS, 2016, $0.
20. **Basecamp — Subdomain Takeover due to NS records at us-east4.37signals.com** ([H1 #1342422](https://hackerone.com/reports/1342422)) — dangling NS zone → cookie/XSS/phishing, 2021, Medium CVSS 6.1, $0.
21. **Greenhouse.io — Subdomain Takeover on demo.greenhouse.io pointing to unbouncepages** ([H1 #407355](https://hackerone.com/reports/407355)) — Unbounce custom domain → fake login, 2018, High, $0.
22. **X / xAI — Subdomain takeover of images.crossinstall.com** ([H1 #1406335](https://hackerone.com/reports/1406335)) — unclaimed S3 bucket (Twitter acquisition), 2021, High, $0.
23. **Acronis — Subdomain takeover of main domain of www.cyberlynx.lu** ([H1 #1256389](https://hackerone.com/reports/1256389)) — Wix `wixdns.net` chain, acquisition, 2021, Medium, $100.
24. **Uber — Subdomain takeover on rider.uber.com due to non-existent distribution on Cloudfront** ([H1 #175070](https://hackerone.com/reports/175070)) — dangling CloudFront with trailing-dot nuance, 2016, $0.
25. **Shopify — Subdomain Takeover Via unclaimed Heroku Instance tim-exclusive.shopify.com** ([H1 #424669](https://hackerone.com/reports/424669)) — unclaimed Heroku, 2018, $500.
26. **Mozilla — addons-preview-cdn.mozilla.net unregistered domain in Fastly** ([H1 #2706358](https://hackerone.com/reports/2706358)) — Fastly service re-attach, CSP/CDN trust, $500.
27. **Kubernetes — Dangling NS records on Amazon Route 53 (api.e2e-kops-aws-canary...)** ([H1 #746000](https://hackerone.com/reports/746000)) — Route53 NS zone claim → email/admin impact, 2019, Medium CVSS 6.4, $250.
28. **U.S. Dept Of Defense — Subdomain Takeover ████████.mil** ([H1 #2499178](https://hackerone.com/reports/2499178)) — CNAME to registrable `.mil`-adjacent domain, 2024, Critical, $0.
29. **Zenly — Subdomain Takeover of brand.zen.ly** ([H1 #1474784](https://hackerone.com/reports/1474784)) — CNAME to `brandpad.io`, registered at Brandpad, 2022, Medium, $0.
30. **Ubiquiti Inc. — Authentication bypass on sso.ubnt.com via subdomain takeover of ping.ubnt.com** ([H1 #172137](https://hackerone.com/reports/172137)) — CloudFront takeover + `domain=.ubnt.com` cookie chain → SSO ATO, $0.

---

## Related Skills & Chains

Subdomain takeover alone is Low/Informational on most mature programs. The chain
payout is 10–100× the standalone. **Every takeover must be evaluated against the
five chains below before submission.** If none apply, file Low; if one applies,
High; if two compose, Critical.

### Chain 1 — Takeover + OAuth `redirect_uri` Whitelist → Auth-Code Theft → 1-Click ATO

- **A.** Enumerate the OAuth `redirect_uri` allowlist via `/oauth/authorize`; look
  for wildcards `*.target.com` or a takeover-candidate hostname in the static list.
- **B.** Claim the takeover-able subdomain (Vercel/Fastly/Azure cloudapp/S3/
  Heroku/Zendesk — see Citations).
- **C.** Host an OAuth callback receiver there; send the victim to
  `/oauth/authorize?redirect_uri=https://<claimed>/cb&response_type=code&client_id=<legit>`.
  Transparent auth via the victim's session → code lands on attacker host →
  exchange for token → ATO.
- **Real shape:** Azure DevOps wildcard `*.visualstudio.com` reply_to → 1-click
  ATO (Binary Security); `fr1.vpn.zomans.com` / `v.zego.com` reporters explicitly
  note "if your domain whitelists your own domain for OAuth" (#1182864,
  #1180697).

### Chain 2 — Takeover at Sibling + Cookie-Domain Wildcard → Session Fixation / ATO

- **A.** Check the main app's `Set-Cookie` for `Domain=.target.com` (parent-scoped)
  rather than host-only.
- **B.** Take over any sibling; the taken-over host can now `Set-Cookie` for the
  parent domain.
- **C.** Plant `Set-Cookie: SESSIONID=<attacker>; Domain=.target.com` so the
  victim's main-app requests carry the attacker's session.
- **Real shape:** `saostatic.uber.com` → `auth.uber.com` SSO bypass (#219205);
  `ping.ubnt.com` → `sso.ubnt.com` (#172137); Roblox cookie capture (#335330).

### Chain 3 — Takeover + CSP `script-src` Allowlist → Persistent Stored XSS on Main App

- **A.** Read the CSP header on the main app; look for the candidate host in
  `script-src` / `connect-src`.
- **B.** Take over the allowlisted host (stale CDN/Fastly/analytics/Vercel project).
- **C.** Serve attacker JS there — it executes with main-app origin on every
  page, bypassing all input sanitizers.
- **Real shape:** `gl-canary.freetls.fastly.net` whitelisted in gitlab.com CSP
  (#716677); Sifchain `proxies.sifchain.finance` Vercel takeover used for
  wallet-drain phishing (also H1 #1183296 main-domain takeover).

### Chain 4 — Takeover + CORS `Access-Control-Allow-Origin` Regex → Credentialed API Read

- **A.** Inspect the API's CORS config for `*.target.com` / suffix-match regexes.
- **B.** Take over a host the regex accepts.
- **C.** From a page on the taken-over host,
  `fetch('https://api.target.com/account',{credentials:'include'})` → credentialed
  cross-origin read.
- **Real shape:** `devrel.roblox.com` allowlisted for CORS to `chat.roblox.com` →
  chat messages read cross-origin (#335330).

### Chain 5 — Takeover at Email DNS / Help-Desk → Email Spoofing → Password Reset ATO

- **A.** Enumerate email DNS: DKIM selectors, SPF `include:`, MX records, and
  help-desk subdomains (`support.`, `help.`, `feedback.`).
- **B.** Take over the delegated zone or help-desk instance (#746000 demonstrated
  MX/email control via NS takeover; Zendesk cases #114134, #810807, #869605).
- **C.** Publish DKIM/SPF records authorizing your server, or configure
  forwarding on the help desk → send `From: support@target.com` that passes all
  checks, or intercept password-reset emails → ATO.

### Operator-level checklist (run before reporting)

1. OAuth `redirect_uri` allowlist contains the host? → Chain 1, Critical.
2. Main app sets `Domain=.target.com`? → Chain 2, High.
3. CSP `script-src` contains the host? → Chain 3, Critical.
4. CORS regex matches the host? → Chain 4, High.
5. Email DNS / help-desk host controlled? → Chain 5, High.
If none apply, file Low/Informational — do not file at Critical without a
demonstrated chain (triagers downgrade fast).

### Cross-references

- **`hunt-oauth`** — Chain 1 (`redirect_uri` bypass class).
- **`hunt-auth-bypass`** — Chain 2 (cookie-domain scoping → session fixation/ATO).
- **`hunt-xss`** — Chain 3 (CSP bypass via trusted-origin JS).
- **`hunt-api-misconfig`** — Chain 4 (CORS regex enumeration).
- **`hunt-cloud-misconfig`** — stale CNAMEs point at deleted S3/CloudFront/Heroku/
  Azure assets; claim primitive overlaps.
- **`security-arsenal`** — subdomain takeover fingerprint table, `subjack`/`subzy`/
  `nuclei` automation, provider claim flows.
- **`triage-validation`** — apply the unique-marker + downstream-impact gate;
  never submit a bare defacement as Critical.
