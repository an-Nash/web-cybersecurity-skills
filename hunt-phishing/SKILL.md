---
name: hunt-phishing
description: Hunting skill for PHISHING / abuse-of-trust vulnerabilities in bug bounty scope — where a platform is tricked into producing a trusted artifact that misleads its own users. Built from 58 assigned reports / 52 full disclosed reports: subdomain & expired-domain takeover used for fake login pages (Greenhouse #407355, Yelp #1715538, Basecamp #1253926, Rocket.Chat #1390782, GitLab custom-domain abuse #296907), OAuth/post-login open redirects (Lichess #3099816, lovable.dev #3581815), platform-hosted content/text injection on trusted domains (Acronis #841630, Reddit #1165919, withinsecurity #106350), markdown/link spoofing (Slack #481472, #66994), CSS/UI overlay & tabnabbing (Nextcloud #3590586, Liberapay #361054, Paragon #181225), IDN/Unicode/address-bar spoofing (Brave #1819329, Tor #275960, Twitter #785243), notification & mail abuse (OpenMage #1083923, HackerOne sandbox reports #1128701, WordPress Gutenberg open relay #3460138, Nextcloud SPF #793532), login CSRF (Liberapay #1124540), and wallet transaction-parsing deception (MetaMask #1651429). Use when hunting any feature where user-controlled input is rendered on, redirected through, or sent from infrastructure the victim already trusts.
sources: hackerone_public, github, portswigger_research
report_count: 58
full_reports_read: 52
---

## Crown Jewel Targets

Phishing / abuse-of-trust bugs are not "find a login form." In bug bounty scope they are **trust-boundary violations**: the platform is induced to produce an artifact that a victim reasonably believes is official, but that artifact carries attacker-controlled content, destination, or sender. The highest-value targets are the surfaces where the platform lends its own reputation, domain, or delivery channel to attacker input. Prioritize, in descending order of demonstrated impact in the corpus:

- **Dangling / unclaimed subdomains and expired domains** — CNAMEs pointing at GitHub Pages, Unbouncer, S3 static sites, AWS ELBs, Heroku, or any PaaS where the backing resource can be re-registered. Researchers turned `demo.greenhouse.io` → Unbounce (#407355), `delivery.yelp.com` → S3 (#1715538), `3737signals.com` → expired domain found in Android app source (#1253926), and `traefik-livedemo.rocket.chat` → AWS ELB (#1390782). These are the most consistent High-severity phishing findings: a real company subdomain serving a fake login page. The victim's browser shows the legitimate hostname, so no amount of user caution helps.
- **Custom-domain / Pages assignment features** — any "add your own domain" or custom-domain-to-hosting mapping that does not verify ownership. GitLab Pages let any domain whose DNS already pointed at `52.167.214.135` be claimed by an attacker's repo (#296907): 1,953 candidate domains, 115 takeover-able. This is the scalable version of subdomain takeover — one misconfiguration yields a fleet of trusted hosts.
- **Post-login / OAuth redirect parameters** — `redirect`, `redirect_uri`, `next`, `return_to`, `post-login` values that allow off-origin destinations. Lichess OAuth `redirect_uri` (#3099816) and lovable.dev `/auth/post-login?redirect=/\google.com` (#3581815) weaponize a trusted login flow into an external landing page. The authenticity of the preceding login is what makes the follow-up page convincing.
- **Trusted-domain content reflection (content/text injection)** — 404 pages and error/redirect endpoints that echo attacker text inside the company's own origin. withinsecurity, Algolia, Veris (#106350, #106348, #138786), Acronis (#841630), Reddit (#1165919), Nextcloud (#213056). The trusted origin is the entire vulnerability: the same text on `attacker.com` would be worthless, but on a payment or registration domain it becomes a credible notice.
- **Any surface that renders user content as links** — chat messages, comments, profiles, shared-file comments. Slack `chat.postMessage` displayed `http://example.com` but linked to `evil.com` via `<http://evil.com|http://example.com>` (#481472); custom profile URL columns accepted `tel://` via client-side-validation bypass (#500348); soft-hyphen `%c2%ad` split one link into two clickable areas (#66994). The danger is amplified on desktop/mobile clients that hide status bars and hover previews.
- **Notification / email pipelines** — transactional email, contact forms, share-via-email, mail-relay, and "share product by mail" features where attacker-controlled fields land in a message sent from a trusted sender or to an arbitrary recipient. WordPress Gutenberg open email relay via unauthenticated `wp_ajax_nopriv_*` + unvalidated `formAction` (#3460138); OpenMage arbitrary sender on sendfriend (#1083923); HackerOne sandbox report emails that look like real verification mail (#1128701); Nextcloud missing SPF/DMARC (#793532). Email is the delivery channel that makes all the other primitives reach victims at scale.
- **Browser/UI trust indicators** — IDN homograph panels, address bar, tab titles, modal overlays, `target=_blank` tabs, `sms:`/`tel:` dialogs. Brave Shield showing `apple.com` for `xn--80ak6aa92e.com` (#1819329); Tor address bar spoofing with Armenian `ո` U+0578 (#275960); Roundcube CSS `position: fixed !important` full-viewport overlay (#3590586); `window.opener.location` reverse tabnabbing (#181225, #361054); origin-less `sms:`/`tel:` dialog drawn over another tab (#1819652). These bugs deceive without hosting any fake page at all.
- **Wallet / transaction confirmation UIs** — anything that summarizes what a user is signing. MetaMask could be made to omit the token amount for malformed ERC20 calldata so a phishing site could drain approvals without an alert (#1651429). Here the trusted confirmation UI itself becomes the payload — a different class from text injection but the same trust story.
- **Invisible-identity / unique-name fields** — app names, usernames, source labels, repo/org names that are assumed unique but accept zero-width/invisible Unicode. Twitter source label accepted Mongolian vowel separator U+180E and even a blank app name (#785243); a claimable broken `@HunterLarco` link in Twitter's developer docs (#1031321); a claimable Liberapay member's Twitter handle (#2125346). Faking identity is the cheapest phishing primitive when injection is blocked.

Payouts in this corpus are modest individually (many $100–$1,000: #500348 $100, #481472 $250, #1068505 $250, #106350 $250, #106348 $100, #1651429 $1,000) but **domain takeovers and authentication-flow phishing rate High/Medium** and are the reliable reporters. Severity hinges on trust: a reflected string is Low/NA on a random host, Medium on a money/branded domain, Critical when it harvests credentials or drives a payment. Always ask "whose trust is being borrowed?" before scoring.

### Severity Calibration From the Corpus

Not all trust bugs are equal. Use these anchors when deciding whether a finding is worth submitting and how to score it:

- **High / Critical (domain-level trust, direct credential capture)** — a claimable company subdomain serving a fake login page (#407355 Greenhouse, #1715538 Yelp, #1390782 Rocket.Chat, #804080 DoD), or an expired primary domain still linked from official material (#1253926 Basecamp). The victim is on the real hostname; there is no visual tell.
- **Medium (authenticated-flow or branded-content deception)** — OAuth/post-login open redirects that land victims on attacker pages after a genuine login (#3099816, #3581815), custom-domain abuse at scale (#296907 GitLab), CSS overlays over a trusted mail UI (#3590586), task hijacking of a real app (#1325649), and missing SPF/DMARC on a mail domain (#325734, #793532).
- **Low / small bounty (spoofing with a clear scope limit)** — reflected text in 404/error pages (#106350 $250, #106348 $100, #138786), markdown link desync in chat (#481472 $250), scheme filter bypass in a profile column (#500348 $100), invisible Unicode in a name field (#785243), and UI-spoofing novelties (#1819329, #1819652).
- **Variable / impact-driven** — mail-relay and notification abuse (#3460138, #1083923, #1128701) scale from nuisance spam to targeted phishing depending on whether arbitrary recipients and senders are accepted.
- **Often NA without a pretext** — "the page echoes my text" on a low-value or off-scope host. The corpus's accepted text-injection cases all sit on recognizable, in-scope branded origins (Acronis #841630, Reddit #1165919), which is the differentiator.

---

## Attack Surface Signals

### URL / Parameter Patterns to Hunt
```
?redirect=        ?redirect_uri=    ?next=            ?return_to=
?url=             ?target=          ?dest=            ?destination=
?continue=        ?callback=        ?goto=            ?r=
?ref=             ?returnUrl=       ?post_login=      ?redirect_url=
/redirect         /auth/post-login  /oauth/authorize  /login/v2
/authorize        /logout           /sso              /saml/acs
/sendfriend       /contacts/email   /share            /send
/pages            /custom_domain    /dns              /admin
/404              /error            /not-found        /proxy

# Sub-domain / hosted-content name patterns
*.github.io       *.herokuapp.com   *.unbouncepages.com
*.s3-website-*.amazonaws.com        *.elb.amazonaws.com
go.<brand>.com    demo.<brand>.com  docs.<brand>.com
```

### Feature-Based Signals (what the feature does, not what it is called)
- **Anything that stores and later renders a URL supplied by a user** — profile fields with "URL + display text," chat message bodies, comment fields, wiki text, and file-comment links. `#481472` and `#500348` abused Slack profile/message APIs; `#252894` shows Dropbox shared-file comments where link text and target diverge; `#459634` shows GitHub wiki misconfigurations where outside users could edit content.
- **Anything that sends email on a user's behalf or with user-controlled fields** — contact forms, "share by email," report-share, invite, notification, password reset, and sendfriend flows. `#3802451` (contact form with `firstName` reflected into SendGrid mail), `#1083923` (arbitrary sender), `#1128701` (sandbox report mail), `#278220` (company name in invite templates).
- **Anything that maps a name/domain to hosted content** — custom domains, GitHub/GitLab Pages, hosted wikis, help centers, demo/docs subdomains, and campaign microsites. `#296907`, `#515574`, `#459634`.
- **Anything that changes origin after an action** — login/logout, OAuth consent, password reset, "continue to," mobile deep links, and `_blank` links. `#3099816`, `#3581815`, `#181225`, `#1169033`.
- **Trusted-location error handling** — 404 pages, "page not found," invalid-request handlers that build a message from the request path. `#106350`, `#106348`, `#138786`, `#213056`.
- **Rendering of HTML/CSS from mail or rich text** — email body sanitizers, CSS filters, markdown renderers, and template engines. `#3590586`, `#3802451`, `#278220`, `#422279`.
- **Client-side-only validation** — scheme allowlists, URL-pattern checks, and Unicode filters enforced only in JS then trusted server-side. `#500348`, `#1068505`, `#785243`.
- **"Broken link" surfaces** — press pages, news posts, "tools and libraries" directories, and docs that point at third-party handles or domains. `#276244`, `#279717`, `#1031321`, `#515574`, `#2125346`.
- **Uniqueness-assumed identity fields** — app names, usernames, source labels, and display names where two values that render identically are accepted as distinct. `#785243`, `#1031321`.

### Code / Config Signals (source review & public-code search)
```
# URL values flowing into redirects / mail / templates
redirect_uri = req.query.redirect
Location: <user input>
window.opener.location / window.open(..., '_blank')
target="_blank"            # without rel=noopener noreferrer
formAction / action from client POST
str_replace('mailto:', '', $params['formAction'])   # WordPress Gutenberg #3460138
wp_ajax_nopriv_*           # unauthenticated AJAX handler
innerHTML / raw template interpolation of user fields
CSS sanitizer: strcasecmp($value, 'fixed') === 0    # Nextcloud/Roundcube #3590586
wp_create_nonce('wp-block-form'); admin_url('admin-ajax.php')  # #3460138
GraphQL ShareReportViaEmail mutation                  # HackerOne #1128701
```
- **DNS/asset recon signals** — CNAMEs to `*.github.io`, `*.herokuapp.com`, `*.unbouncepages.com`, `*.s3-website-*.amazonaws.com`, `*.elb.amazonaws.com`, expired registration dates, and `NXDOMAIN` on names still referenced in source/docs (#407355, #1715538, #1390782, #1253926, #276244, #279717).
- **Email-auth signals** — `dig <domain> txt` returning no SPF/DMARC TXT record, or `nslookup -type=txt` showing only an SOA (#325734, #793532).

### Victim-Delivery Signals
- Link can be sent to a victim and still "look right" — the trusted domain appears in the visible left-hand portion of the URL (#407355, #384101).
- Message appears to originate from a known sender or system address — verification-style, no warning label (#1128701, #793532, #3460138).
- The deceptive artifact is reachable on mobile/desktop clients that hide status bars and hover previews, so a mismatch that would be obvious in a browser is invisible in an app (#481472).
- The target action involves money, credentials, or token approvals — these are where a successful deception pays off (#186862, #1651429, #481472).

### Recon Surface → Expected Phishing Primitive

Quick reference mapping each recon surface to the class of finding it most often produces in this corpus:

| Recon surface | Primitive to expect | Representative reports |
|---|---|---|
| Subdomain/PaaS CNAME inventory | Trusted-host fake login page | #407355, #1715538, #1390782, #804080 |
| Expired-domain / broken-link sweep | Impersonation, misinformation, malware serving | #1253926, #276244, #279717, #1031321, #2125346 |
| Pages/custom-domain settings | Bulk domain abuse | #296907, #515574, #459634 |
| Login/OAuth URL params | Post-auth redirect to attacker page | #3099816, #3581815, #422279, #1169033 |
| Chat/comment/profile fields | Link label/destination desync | #481472, #500348, #66994, #252894 |
| 404/invalid-request paths | On-origin content spoofing | #106350, #106348, #138786, #213056 |
| Mail/contact/invite endpoints | Trusted-sender phishing, open relay | #3802451, #1083923, #1128701, #3460138 |
| DNS TXT records | Domain spoofability | #325734, #793532 |
| Identity/name fields | Invisible-character impersonation | #785243, #1031321 |
| Mobile/browser UI | Homograph, tabnabbing, overlay, task hijack | #1819329, #275960, #181225, #3590586, #1325649 |

Use this table as a triage aid: pick the primitive first, then the probe. It prevents the common mistake of running reflection tests against a host whose only realistic bug is a takeover, or hunting redirects on a feature whose only risk is mail abuse.

---

## Discovery Patterns From 52 Full Reports

Every pattern below is derived from the 52 full reports in the study pack. The ranking is not theoretical: it is the literal count of full reports containing each signal, and it should drive how you budget recon time. The dominant lesson is that phishing bugs are usually **found by noticing something that looks slightly wrong** — a dead link, an odd hostname, a mismatched URL — rather than by blind fuzzing.

### Corpus-Level Statistics & What They Teach

- **Top four signals dominate.** `search-filter-sort` (17), `api-endpoint` (14), `public-code-search` (13), and `server-side-rendering` (10) account for the majority of discovery paths. Spend the first hour of recon on link inventories, API request/response diffs, and source-code/grep sweeps — not on edge-case payloads.
- **Redirects and OAuth are disproportionately high-value.** Only 9 `redirect-handling` and 5 `sso-oauth` reports exist, but they include two of the cleanest auth-flow phishing cases (#3099816, #3581815). Low frequency, high trust yield.
- **Subdomain takeover is the reliability champion.** Six `subdomain-takeover` + two `subdomain` reports, almost all rated High or Medium, with a simple, repeatable test (CNAME → claimable PaaS). If you only have time for one hunt, do this one.
- **Mail abuse is the growth category.** The 2026 reports (#3590586, #3581815, #3460138, #3802451) cluster around HTML emails, CSS sanitizers, and unauthenticated mail handlers — modern targets are notification/rendering pipelines, not just 404 pages.
- **Content spoofing is the most-reported but most-rejected class.** It appears across many reports (#841630, #1165919, #106350, #106348, #138786, #213056) precisely because it is easy to find and easy to N/A. The trusted origin is the entire finding — never omit it from the report.
- **Bounties are small but consistent.** Where published: $100 (#500348, #106348), $250 (#481472, #1068505, #106350), $1,000 (#1651429). Treat this class as volume + reliability rather than jackpot hunting, except for takeovers.
- **The same technique recurs across vendors.** The identical 404 text-injection PoC (`/test/%2f../It has been changed...`) was accepted at withinsecurity, Algolia, and Veris (#106350, #106348, #138786). Once you find a working primitive, check every in-scope asset for it.

### Where Researchers Start (ranked recon surfaces w/ "what to look for")

1. **Public code / app source & docs** (13 reports: `public-code-search`) — *What to look for:* domains, profile URLs, and vendor links hardcoded in repositories, mobile apps, and documentation. `#1253926` found `3737signals.com` while "analyzing the Basecamp3 Android app"; `#1031321` found a broken `@HunterLarco` link on developer.twitter.com; `#515574` found `simple-api.github.io/api-offices/` on data.gov/labs; `#2125346` found a claimable Twitter handle of a Liberapay member in public material. The common thread: a link that was valid once but now points at unclaimed space.
2. **Search / filter / sort & link-index pages** (17 reports: `search-filter-sort` — the single most frequent signal) — *What to look for:* outbound links in lists, press/news pages, "tools & libraries" directories, and generated result rows that point at unclaimed or typo'd destinations. `#276244` (legalrobot press link to expired `ecotechfoundation.net`), `#279717` (`.comg` typo on nextcloud.com), `#106350`/`#106348`/`#138786` (attacker text in 404 via `/test/%2f../<text>`). Treat every outbound link as a takeover candidate until proven otherwise.
3. **API endpoint inspection** (14 reports: `api-endpoint`) — *What to look for:* POST bodies where the display value and destination differ, and unauthenticated or over-privileged handlers. `#481472` and `#500348` abused `POST /api/chat.postMessage` and `/api/users.profile.set`; `#3460138` abused `wp_ajax_nopriv_wp_block_form_email_submit`; `#3802451` used an unauthenticated `/contacts/email` JSON endpoint. Always compare the request body to the rendered artifact.
4. **Server-side rendering / reflection** (10 reports: `server-side-rendering`) — *What to look for:* user fields reflected into a page or email on a trusted origin. `#841630`, `#1165919`, `#213056`, `#275960`, `#3590586`. Inject a unique marker into every field and find where it lands.
5. **Redirect handling & OAuth/SSO flows** (9 `redirect-handling`, 5 `sso-oauth`) — *What to look for:* `redirect_uri`/`redirect` accepting external schemes or `/\`, `//`, backslash confusion. `#3099816`, `#3581815`, `#422279`, `#384101`, `#1169033`. Walk a real flow in an intercepting proxy and edit each hop.
6. **JS source review** (6 reports: `js-source-review`) — *What to look for:* client-side-only scheme/URL validation, `_blank` without `rel`, and exposed nonces/ajaxUrl/action in scripts. `#181225`, `#500348`, `#3460138`. A filter in JS is a hint that the server forgot one.
7. **Image-processing / rendering pipelines** (6 reports: `image-processing`) — *What to look at:* rendered templates, screenshots, PDF/email renderers where injected markup survives. `#3590586`, `#407355`, `#793532`.
8. **Subdomain / domain inventory** (6 `subdomain-takeover`, 2 `subdomain`) — *What to look for:* CNAMEs/Ptr records to PaaS with re-registerable names, expired domains, and nameservers returning `NXDOMAIN`. `#407355`, `#1715538`, `#1390782`, `#804080`, `#1253926`. This is the highest-yield recon for High-severity phishing findings.
9. **Template engines & email templates** (5 reports: `template-engine`) — *What to look for:* fields like Company Name injected into invite emails with wide ASCII ranges. `#278220`, `#422279`, `#1128701`.
10. **Filter-bypass testing** (4 reports: `filter-bypass`) — *What to look for:* trailing dots, `!important`, invisible Unicode, and `javascript:`/`tel:`/`data:` schemes slipping past regexes. `#1068505`, `#3590586`, `#785243`, `#500348`. A blocklist tells you exactly what the developer modeled — attack the edges.
11. **Import / file-upload / dependency & package namespaces** (4 `import-feature`, 3 `dependency-confusion`, 3 `file-upload`) — *What to look for:* unclaimed org/repo names and packages colliding with core names. `#333459` (npm packages overlapping core node packages — "easy social engineering trick"), `#515574`, `#1715538`.
12. **Mobile / browser UI behavior** — *What to look for:* tabnabbing, task hijacking, IDN panels, and cross-tab dialogs. `#1325649` (StrandHogg task hijacking), `#1819329`, `#275960`, `#1819652`, `#361054`.

### Feature-Based Discovery Signals (frequency-ranked table w/ "why it matters / what to probe")

Ranked by the number of full reports in the corpus containing each signal (Section 1 frequency table). The top four account for the majority of discovery paths — start there.

| Signal (from 52 full reports) | # reports | Why it matters | What to probe |
|---|---:|---|---|
| search-filter-sort | 17 | Link-bearing result rows and index pages are where stale/dangling third-party URLs live | Click & inspect every outbound link on search, press, docs, "libraries" pages; run `dig`/WHOIS on each |
| api-endpoint | 14 | APIs trust POST fields for both display text and destination; unauthenticated handlers are common | Diff request vs rendered link; check `wp_ajax_nopriv_*`, role checks, hidden params |
| public-code-search | 13 | Source/mobile code leaks unclaimed domains and profile URLs | Grep repos & APKs for `http(s)://`, `@handle`, `.github.io`, vendor links |
| server-side-rendering | 10 | Reflected text on a trusted origin is the whole phishing primitive | Inject a unique marker into every user field; view where it lands in HTML/email |
| redirect-handling | 9 | Trusted-origin redirects launder attacker destinations | Fuzz `redirect*` with `https://evil`, `//evil`, `/\evil`, `\\\\evil` |
| image-processing | 6 | Rendered templates/screenshots preserve injected markup | Inject HTML/CSS into fields that later render in an email/PDF/screenshot |
| subdomain-takeover | 6 | A claimed company subdomain is a turnkey credential-harvest host | Enumerate CNAMEs → PaaS; test for "site not found"/NXDOMAIN fingerprints |
| js-source-review | 6 | Client-side validation is not a security boundary | Find allowlists in JS; replay the request with the forbidden scheme/URL |
| sso-oauth | 5 | OAuth trust is especially potent — users expect the real login screen | Manipulate `redirect_uri`, `state`, `client_id` after authorization |
| template-engine | 5 | Email templates interpolate names with loose character sets | Put `<`, `"`, and long ASCII strings in name/company fields |
| filter-bypass | 4 | A blocklist implies a modeled filter with edge cases | Add trailing dot, `!important`, zero-width chars, scheme variants |
| admin-internal | 4 | Internal/admin surfaces generate trusted notifications | Look at sandbox/admin tooling ("share report via email") |
| import-feature | 4 | Import paths accept remote names/domains without ownership proof | Test custom-domain mapping, repo claims, URL imports |
| xml-parser | 3 | Parsers feed rich content into mail/render pipelines | Feed HTML/CSS through XML/email parsers |
| session-attack | 3 | Session/flow semantics can be impersonated | Target login-flow v2 tokens and authenticated mail flows |
| misconfiguration | 3 | Mail relays and missing auth are pure config bugs | Test arbitrary sender, open relay, unauthenticated AJAX |
| path-traversal-lfi | 3 | 404 handlers build text from the request path | `/test/%2f../<your text>` on error pages |
| dependency-confusion | 3 | Package namespaces are trust channels | Look for org names/npm packages that can be registered |
| brute-otp-reset | 3 | Mail endpoints often lack rate limits/CAPTCHA | Check for no CAPTCHA/rate-limit on email-sending routes |
| dos-resource | 3 | Same unauthenticated mail endpoints enable flooding | Confirm no throttling on notification routes |
| subdomain | 2 | Expired primary domains referenced by the site | WHOIS expiring soon; links to for-sale domains |
| blind-oob | 2 | Secondary fetch/primitives that feed content | Confirm whether fetched content is reflected |
| open-redirect | 2 | Core laundering primitive for phishing links | Post-login and `redirect` params |
| csrf | 2 | Login CSRF makes a victim use the attacker's account | Absence of CSRF token on login form |
| file-upload | 2 | Uploaded artifacts can host phishing pages | Test where uploaded HTML is served and under what origin |
| link-preview | 2 | Preview/link expansion can desync label and destination | Compare displayed title/URL to actual target |
| internal-network | 2 | Internal surfaces generate trusted artifacts | Check admin/internal mail and notification paths |
| proxy-feature | 2 | Proxying can hide the true destination | Test whether proxied links preserve or strip the target |
| json-body | 2 | JSON APIs are common mail/redirect sinks | Send JSON with attacker content in every field |
| auth-bypass | 1 | Missing auth enables mail/notification abuse | Test unauthenticated access to mail handlers |
| graphql | 1 | GraphQL mutations can send trusted mail | Probe `ShareReportViaEmail` and similar mutations |
| mutation-polyglot / graphql-technique | 1 | Mutation abuse via crafted variables | Fuzz mutation arguments for arbitrary recipients/assets |
| unicode-normalization | 1 | Invisible characters defeat uniqueness | Inject U+180E/U+200B/U+0578 into identity fields |
| double-encoding | 1 | Encoded traversal hides targets from filters | `%252e%252e%2f` on go-link/redirect endpoints |
| time-based | 1 | Timing reveals asset claimability/state | Compare responses before/after claiming a resource |
| stack-fingerprinting | 1 | Tech stack shapes available exploits | Fingerprint to pick the right PaaS takeover technique |
| url-fetching | 1 | Fetched content may be reflected | Test whether remote content lands on a trusted origin |
| template-injection | 1 | Template fragments render attacker markup | Inject into template fields rendered server-side |
| request-smuggling | 1 | Parser差异 can bypass route filters | Test front/back-end disagreement on path/params |

### Verbatim Discovery Clues (18 real `[#id]` quotes)

These are verbatim "how I found it" lines from the disclosed reports. Each is followed by the discovery lesson it encodes.

- [#1253926] "While i was analyzing the `Basecamp3` Android app i found `3737signals.com` on the source code as i understand you are passing it to the `intent`to view it on some case."
  → *Lesson:* mobile apps leak domains; any hardcoded domain is a takeover candidate.
- [#3099816] "By manipulating the redirect_uri parameter during the OAuth authorization process with Lichess, an attacker can redirect users to an arbitrary external domain"
  → *Lesson:* edit the OAuth flow after login, not just at the entry URL.
- [#1083923] "I found a part that could cause a phishing attack."
  → *Lesson:* the bug was a mail-share misconfiguration — hunt features, not payloads.
- [#515574] "I found a Vulnerability in your website where in one of your domain https://www.data.gov/labs"
  → *Lesson:* docs pages link to claimable repos; a 404 on a linked asset is a signal.
- [#213056] "I found that site have invalid request may lead to content spoof."
  → *Lesson:* invalid-request handlers are reflection surfaces on trusted origins.
- [#186862] "I discovered the endpoint, which allows the attacker conduct the fishing attack to other users and they can pay for attacker's order."
  → *Lesson:* a POST→GET parameter override turned a payment endpoint into a phishing link.
- [#66994] "While copy-pasting a link from a pdf to slack (desktop/web), i noticed that the resulting link(s) looked a bit messed up"
  → *Lesson:* ordinary usage ("link looked messed up") led to a Unicode link-splitting bug.
- [#361054] "I was create a PR on github https://github.com/liberapay/liberapay.com/pull/1127"
  → *Lesson:* public code review of the target's own repo revealed missing `rel=noopener`.
- [#2125346] "So i found a twitter account of one of the members of **liberapay** which is **Andy Costanza** is broken, anyone can claim that account and can scam with it"
  → *Lesson:* broken identity links are impersonation primitives.
- [#785243] "By exploiting this flaw I was also able to create a twitter-application without any (shown) name at all."
  → *Lesson:* invisible Unicode lets you fake or blank a "unique" name.
- [#1031321] "A link in https://developer.twitter.com/en/docs/twitter-api/tools-and-libraries was broken and anyone could create that account which leads to account impersonate"
  → *Lesson:* a single broken doc link can be turned into an impersonation campaign.
- [#106350] "Hello i want to report a text injection and a missconfiguration of the 404 page which can be used in phishing"
  → *Lesson:* 404 pages that echo request text are a classic trusted-origin spoof.
- [#279717] "It seems like a typo and makes the tld as .comg instead of .com."
  → *Lesson:* typo'd TLDs in links are takeover/misinformation vectors.
- [#275960] "Address bar fails to parse character \"ո\"(U+0578 Armenian Small Letter)."
  → *Lesson:* character-level UI parsing failures defeat domain visual verification.
- [#296907] "There are currently 1953 unique domain names with DNS records pointing to the above mentioned IP, and 115 domains could be taken over."
  → *Lesson:* bulk DNS dataset analysis scales a single misconfiguration into hundreds of findings.
- [#422279] "The `incontext_app_link` is checked server-side if it's a correct `shopifycloud.com`-URL. The problem however is that userdata inside the URL is allowed."
  → *Lesson:* server-side checks that only validate the domain prefix miss userinfo/backslash tricks.
- [#3460138] "The AJAX handler `wp_block_form_email_submit` is registered for both authenticated (`wp_ajax_*`) and **unauthenticated** (`wp_ajax_nopriv_*`) requests"
  → *Lesson:* public-code review of a plugin found an unauthenticated mail relay.
- [#481472] "However, we can spoof the link destination by changing the message post request."
  → *Lesson:* the display/href mismatch lives in the POST body — inspect raw requests.

### Probe Checklist (15 concrete probes)

1. **Reflect a unique marker** into every user-controlled field that is later rendered on a company origin or email (`<h1>MARKER</h1>`, `https://attacker.test`). *Success:* the marker survives unescaped in HTML or delivered mail (#841630, #1165919, #3802451).
2. **Diff display text vs. href**: in chat/comments/profiles, set the label to a benign URL and the actual destination to `attacker.com`. *Success:* rendered `href` differs from visible text (#481472, #252894).
3. **Fuzz redirect params** with `https://evil.com`, `//evil.com`, `/\evil.com`, `\\\\evil.com`, `https://trusted.com@evil.com`, encoded `%2f%5c`. *Success:* final `Location` is off-origin (#3581815, #3099816, #422279).
4. **Enumerate every subdomain** (amass/subfinder/CRT/DNSdumpster) and flag CNAMEs to GitHub Pages, Unbounce, S3, ELB, Heroku; test each for a claimable fingerprint. *Success:* you can serve content on the real company name (#407355, #1715538, #1390782).
5. **Check registration status** of any domain referenced in source/docs/press links — expired or for-sale domains are takeover candidates. *Success:* the domain can be purchased or claimed (#276244, #1253926, #279717).
6. **Test custom-domain assignment** features with a domain you control that already points at the host's IP; verify no TXT/ownership check. *Success:* the domain binds to your repo (#296907).
7. **Send a contact-form / share-by-mail request with arbitrary From and To** and inspect the raw received headers for spoofed sender and open-relay behavior. *Success:* mail is accepted from/to arbitrary addresses (#1083923, #3460138).
8. **Inject `<a>` and `<img>` into name/firstName fields** of email templates and inspect the delivered HTML email. *Success:* `<a>` with inline style survives sanitization (#3802451, #278220).
9. **Check SPF/DMARC**: `dig <target>.com txt` — absent records mean the domain can be spoofed in phishing mail. *Success:* no SPF/DMARC TXT record (#325734, #793532).
10. **Probe OAuth `redirect_uri`**, `state`, and post-login `redirect` after a real login; record the final `Location`. *Success:* off-origin redirect after a legitimate auth (#3099816, #3581815).
11. **Replay client-side-blocked values server-side**: `tel://`, `javascript:`, `data:`, `sms:` in URL fields. *Success:* the forbidden scheme is accepted by the server (#500348, #1819652).
12. **Test invisible Unicode** (U+180E, U+200B, U+0578, homoglyphs) in app names, usernames, source labels, and domain-rendering UI. *Success:* two visually identical names are accepted as distinct or a domain renders as a different brand (#785243, #275960, #1819329).
13. **Inspect `target="_blank"` links** for missing `rel=noopener noreferrer` and confirm `window.opener.location` reassignment. *Success:* the opener tab can be navigated to a phishing page (#181225, #361054).
14. **Fuzz 404 / invalid-request handlers** with `/test/%2f../<your text>` and check whether the text is echoed in the error body. *Success:* attacker text appears on the trusted origin (#106350, #106348, #138786, #213056).
15. **Check unauthenticated AJAX/API handlers** (`wp_ajax_nopriv_*`, GraphQL mutations like `ShareReportViaEmail`) for abuse in sending trusted-looking notifications. *Success:* an anonymous request causes a mail to be sent (#3460138, #1128701).

### Common Discovery Mistakes (from the corpus)

- **Chasing the fake login page instead of the takeover.** In #407355 and #1715538 the whole finding is that content can be served on the company name; the attacker's HTML is incidental. Confirm claimability first, then dress the PoC.
- **Reporting a redirect that only fires pre-auth.** #3099816 and #3581815 matter because the redirect happens *after* a real login. A link that simply leaves an unauthenticated site is usually expected behavior.
- **Treating "accepted risk" as a bug.** Dropbox's response in #252894 notes that link text differing from the target is a risk they have always accepted; check whether the program already acknowledges the behavior before reporting it.
- **Ignoring the client channel.** #481472 stresses that desktop/mobile Slack apps have no status bar, so a link mismatch invisible in a browser is exploitable in the app. Test every client, not just Chrome.
- **Stopping at the first stripped tag.** In #3802451 `<img>` was removed but styled `<a>` persisted; testing only one tag would have missed the finding.
- **Using a blank or clearly fake pretext.** #1128701's whole argument is that the mail had no sandbox warning label; #1169033's user-agent spoofing ("Company X verification") made the login URL trustworthy. The pretext is part of the technical finding.
- **Forgetting the 404 handler family.** The identical `/test/%2f../<text>` PoC worked at three separate companies (#106350, #106348, #138786). If one host reflects, test them all.
- **Assuming uniqueness means visual uniqueness.** #785243 and #1031321 show that invisible characters and claimable handles defeat name uniqueness without any injection.

---

## Step-by-Step Hunting Methodology

The workflow below is organized as four phases. Do not skip Phase 0 — most rejected phishing reports fail there, not at the technical stage.

### Phase 0 — Frame the Trust Story
Before touching the target, write a one-sentence hypothesis in the form: **"Victims trust [surface] because [reason]; if an attacker can [action], the victim will [loss]."** Valid surfaces from the corpus: a branded hostname (#407355), a real verification email (#1128701), a genuine login screen (#3099816), a wallet confirmation dialog (#1651429), a security panel (#1819329). If your hypothesis has no trusted surface, discard it.

### Phase 1 — Surface Discovery (recon)
Inventory subdomains, hosted-content mappings, link-bearing pages, mail handlers, and identity fields. Run this in the frequency order of the discovery table. Outcome: a ranked list of candidate surfaces, each tagged with a likely primitive.

### Phase 2 — Prove the Primitive
For each candidate, run the single cheapest probe that would confirm it (marker reflection, `href` diff, redirect `Location`, CNAME claimability, raw mail capture, scheme replay). Stop as soon as one confirms — then invest in a realistic pretext and screenshots.

### Phase 3 — Weaponize & Report
Build the deception (fake page, styled link, overlay, redirect chain), demonstrate victim impact, calibrate severity against the corpus, and document a 10-minute reproduction with a teardown path for takeover PoCs.

1. **Define the trust boundary first.** Write down *why* a victim would believe the artifact: the domain in the URL bar, the sender of the email, the app's login screen, the wallet's confirmation dialog. If you cannot name the trusted element you are borrowing, there is no phishing bug — keep hunting.
2. **Build a target inventory of trust channels.** Subdomains and alias domains; custom-domain/Pages features; login/OAuth/SSO flows; mail/notification senders; link-rendering features (chat, comments, profiles, wikis); error/404 handlers; browser/UI surfaces; and wallet/transaction confirmers.
3. **Run reconnaissance in the frequency order above.** Start with public code + search/link pages (17 + 13 signals), then API endpoints (14), then rendering/redirect features. The corpus shows researchers most often start from a *link that looks wrong* or a *domain that looks dead*, not from a fuzzer. Let the frequency table drive your time allocation.
4. **Enumerate and fingerprint dangling assets.** For each CNAME to a PaaS, try to register the backing resource and serve a page; for expired domains, check WHOIS and registrars. A confirmed "I can host content on your subdomain" is a complete finding (#407355, #1715538) — do not wait to build an elaborate fake page.
5. **Establish a controlled probe account and a listener.** Use a domain you own (e.g. `attacker.test`) to host fake login pages, redirect targets, and callback URLs; use Burp Collaborator/interactsh if you need OOB confirmation that a notification was delivered. Never point live PoCs at real user data.
6. **Test reflection and link spoofing.** Inject unique markers into all rendered fields; diff label vs. destination; capture rendered HTML from both web and mobile clients, because status bars and hover are absent there (#481472). Check both the DOM and the raw HTTP response.
7. **Weaponize redirects.** Walk a real login/OAuth flow in Burp, modify `redirect_uri`/`redirect` at each hop, and record the final `Location`. Test charset/backslash/protocol-relative variants (#3099816, #3581815, #422279, #384101). Also test modification *after* consent, not before.
8. **Audit mail pipelines end-to-end.** Submit to contact/share/invite endpoints, capture the raw email, and check From/Reply-To, HTML body, SPF/DMARC alignment, and whether arbitrary recipients are accepted (#3802451, #1083923, #1128701, #325734). Look for the absence of CAPTCHA/rate limits as an aggravating factor (#3460138).
9. **Probe browser/UI trust indicators.** IDN homographs in the address bar and security panel, cross-tab dialogs, tabnabbing via `window.opener`, and CSS overlays that cover the viewport (#1819329, #275960, #1819652, #181225, #3590586). These require no hosting infrastructure and are often overlooked.
10. **Probe transaction/identity summaries.** For wallet or financial UIs, feed malformed/edge-case data and compare the rendered warning to the real action; the MetaMask report (#1651429) shows that *omitted* warnings are the vuln. For identity fields, check whether invisible characters produce duplicate-looking names (#785243).
11. **Attempt every relevant bypass** from the Bypass Techniques section before concluding a filter is safe. A trailing dot, `!important`, or backslash is often all that separates an NA from a Medium.
12. **Prove the deception, not just the mechanics.** Produce a screenshot/PoC showing the victim's view: the trusted domain, the misleading text/link, and the destination or harvested credential. For takeovers, show content actually served on the company origin (#407355, #296907).
13. **Assess scope and severity honestly.** A reflected string on a low-value path is often NA; the same on a payment, auth, or money domain is reportable. Anchor to comparable corpus reports (#106350 $250 vs. domain takeovers rated High). Check that the affected host is in scope.
14. **Document a 10-minute reproduction.** Record exact URLs, params, account setup, and screenshots. For takeovers, note that registration/claiming is reversible — provide a teardown-safe PoC and do not leave malicious content live.
15. **Write the report around the trust story.** Lead with "victims see X on our trusted surface, but Y happens," then the technical steps, then realistic impact (credential capture, payment redirection, impersonation). Cite comparable disclosed reports where useful.

---

## Payload & Detection Patterns

### Content / Text Injection on Trusted Origins
```
# 404 / invalid-request reflection (withinsecurity #106350, Algolia #106348, Veris #138786)
GET /test/%2f../It%20has%20been%20changed%20by%20a%20new%20one%20https://attacker.com
# reflected: "It has been changed by a new one https://attacker.com so go to the new one..."

# Content spoofing URL (Acronis #841630, Reddit #1165919)
GET /%20we%20are%20facing%20a%20heavy%20traffic,%20please%20visit%20https://attacker.com
GET /redirect_uri?And_move_t0_malicioussite.com        # Nextcloud #213056
```

### Display-text / Destination Desync (links that lie)
```
# Slack markdown link spoofing (#481472) — POST /api/chat.postMessage
- text=http://example.com
+ text=<http://evil.com|http://example.com>

# Slack profile URL column with forbidden scheme (#500348) — POST /api/users.profile.set
- {"fields":{"XfABVBP467":{"value":"https://www.mcdonalds.com","alt":"McDonald's"}}}
+ {"fields":{"XfABVBP467":{"value":"tel://03-9999-0000","alt":"McDonald's"}}}

# Soft-hyphen link splitting (#66994) — insert %c2%ad inside a URL
http://google.com<soft-hyphen>123.com    -> renders as two clickable areas

# Shopify incontext_app_link backslash confusion (#422279)
https://merchant.myshopify.com\\attacker.com/  -> browser loads before @ / domain
```

### Redirect / Open-Redirect Payloads
```
redirect_uri=https://example.com/auth/lichess/            # Lichess #3099816
https://lovable.dev/auth/post-login?redirect=/\google.com # lovable.dev #3581815
https://lovable.dev/purchase-success?redirect=/%5Cgoogle.com
https://target/redirect?url=https://trusted.com@evil.com
https://target/redirect?url=//evil.com
# Go.imgur.com double-encoded traversal (#384101)
http://go.imgur.com/account-verification/%252e%252e%2f%252e%252e%2f%67%69%74%68%75%62%2e%63%6f%6d/...
```

### CSS / UI Overlay & Tab Payloads
```
/* Nextcloud / Roundcube full-viewport overlay (#3590586) */
.overlay { position: fixed !important; top:0; left:0; width:100%; height:100%;
           background:#fff; z-index:9999; }
<div class="overlay"><div class="dialog"><h2>Session Expired</h2>
  <p>Your session has expired. Re-enter credentials at https://attacker.com</p></div></div>

// Reverse tabnabbing (#181225, #361054)
window.opener.location = 'http://phishingsite.com/';

// Cross-tab sms:/tel: dialog (#1819652)
location = 'sms:?&body=Verify at https://attacker.com';
```

### Unicode / IDN / Identity Spoofing Payloads
```
U+180E  MONGOLIAN VOWEL SEPARATOR  -> invisible char in app name (#785243)
U+200B  ZERO WIDTH SPACE            -> rejected by Twitter, test elsewhere
U+0578  ARMENIAN SMALL LETTER Ո     -> "ոokia.com" -> xn--okia-zgf.com (#275960)
xn--80ak6aa92e.com                  -> renders apple.com in Brave Shield (#1819329)
```

### Mail / Notification Abuse Payloads
```
# HTML injection in transactional email (#3802451)
POST /contacts/email  {"email":"victim@x.com","firstName":"<a href='https://attacker.com'
                       style='...'>Verify your account</a>"}
# arbitrary sender / open relay (#1083923, #3460138)
sendfriend: choose Sender = sharefriend@<target> ; To = any victim
POST /wp-admin/admin-ajax.php  action=wp_block_form_email_submit&formAction=<attacker mailto>
# SPF/DMARC check (#325734, #793532)
dig <target>.com txt        # no SPF TXT -> spoofable sender
# Sandbox email social engineering (#1128701)
GraphQL ShareReportViaEmail on a sandbox report with asset = https://hackerone.com
```

### Login CSRF / Flow Abuse
```
<!-- Liberapay #1124540: log victim into attacker's account -->
<form action="https://liberapay.com/about/">
 <input type="hidden" name="log&#45;in&#46;id" value="..." />
 <input type="hidden" name="log&#45;in&#46;key" value="..." />
 <input type="hidden" name="log&#45;in&#46;token" value="..." />
 <input type="submit" value="Submit request" />
</form>

# Nextcloud Login Flow v2 (#1169033)
POST /index.php/login/v2  User-Agent: "Company X verification"
-> receive poll token + login URL, send that trusted login URL to victim
```

### Domain / Subdomain Takeover Fingerprints
```
# Query CNAMEs, then look for these "unclaimed" responses:
"Site not found" / "There isn't a GitHub Pages site here"
"No such bucket" (S3) / "The specified bucket does not exist"
Unbounce, Heroku, AWS ELB NXDOMAIN -> re-register the resource (#407355, #1715538, #1390782)
# Claim a Pages repo matching a docs link (#515574):
register user "simple-api", create repo "api-offices", add index.html
```

### Detection / Validation Snippets
```
# Confirm reflected attacker content actually reaches a trusted origin / email
curl -s "https://target/404/%2f..%2fMARKER" | grep -i MARKER
# Diff two link-bearing responses to find href/desync
diff <(curl ... -d 'text=<http://evil.com|http://example.com>') <(baseline)
# Check for open redirect final Location
curl -sI "https://target/redirect?url=/\evil.com" | grep -i '^Location:'
# Bulk-check candidate takeover domains from DNS dataset (#296907)
for d in $(cat domains.txt); do dig +short CNAME $d; done
```

### Triage-Facing Detection Checklist

When reviewing your own finding before submission, verify each item — a single failure here is the difference between a report and an N/A:

- [ ] The trusted surface is named explicitly and in scope (hostname, sender, login screen, wallet UI).
- [ ] The attacker-controlled content/destination actually renders on that surface, confirmed by a raw response or delivered email.
- [ ] The deception is visible in a screenshot showing what the victim sees, not just a diff or a header.
- [ ] The destination, sender, or harvested data is attacker-controlled and demonstrably different from the legitimate one.
- [ ] A realistic pretext is described (why the victim would click/enter/pay) — compare to #186862 and #1169033.
- [ ] The PoC does not leave live malicious content or send real phishing mail.
- [ ] Severity is anchored to a comparable corpus report (see Severity Calibration above).
- [ ] The reproduction is stable: a second person can repeat it in 10 minutes without special timing or insider state.

### Evidence Capture Notes (what triage needs to see)

- **Takeover** — a screenshot of your own content served at `https://<company-subdomain>/`, plus the CNAME/DNS record showing why it resolves to a claimable resource (#407355, #1715538, #296907).
- **Open redirect** — a full flow recording: the legitimate login URL, the modified `redirect` parameter, and the final `Location` header pointing off-origin (#3099816, #3581815).
- **Content spoofing** — a single screenshot of the rendered page on the trusted domain with the attacker string visible in context, plus the exact URL that produced it (#841630, #106350).
- **Link desync** — the raw request body and the rendered HTML showing label ≠ `href`, ideally from both web and mobile clients (#481472, #66994).
- **Mail abuse** — the delivered message's raw headers (From/Reply-To/Return-Path), the rendered HTML body, and the absence of CAPTCHA/rate limiting on the endpoint (#3802451, #3460138).
- **SPF/DMARC** — the literal `dig <domain> txt` output showing no SPF TXT record, alongside a forged-mail demonstration (#325734, #793532).
- **UI/identity spoofing** — a side-by-side of the real and spoofed name/panel/domain, with the exact Unicode code points or homograph string annotated (#785243, #275960, #1819329).
- **Wallet/tx parsing** — the crafted calldata, the real on-chain effect, and a screenshot showing which warning was suppressed (#1651429).

---

## Common Root Causes

1. **Trusting user input as a destination** — the platform renders or redirects to a user-supplied URL without validating the destination, so the trusted origin launders an attacker destination (#481472, #3099816, #3581815, #422279). The feature is legitimate; the missing destination validation is the bug.
2. **Display value and destination are separate fields, only one is validated** — the label is checked but the `href`/`formAction`/`redirect` is not (#481472, #3460138, #252894). Any feature with "display text" plus "link" is a candidate.
3. **Client-side-only validation** — scheme and URL allowlists exist in JS but are not enforced server-side, so replaying the request bypasses them (#500348, #1068505, #422279, #181225). If a filter only exists in the browser, it is not a filter.
4. **Dangling DNS / unclaimed hosting resources** — a CNAME or registration outlives the service it points to, leaving a trusted name that can be claimed (#407355, #1715538, #1390782, #804080, #1253926). This is a lifecycle/asset-management failure, not a code bug.
5. **Custom-domain mapping without ownership verification** — any domain already pointing at the host IP can be locked to an attacker's repo (#296907). The trust assumption "if it points here, we own it" is inverted.
6. **Error handlers that reflect request data** — 404/invalid-request pages build their message from the attacker-controlled path (#106350, #106348, #138786, #213056). Convenience debugging output becomes a phishing surface on a trusted origin.
7. **Unescaped interpolation into mail/HTML templates** — names and fields are combined into trusted-looking emails without output encoding (#3802451, #278220, #1128701). The `<img>` tag may be stripped but styled `<a>` survives (#3802451).
8. **Over-privileged or unauthenticated mail handlers** — `wp_ajax_nopriv_*`, share-via-email, and sendfriend routes let anyone send mail as/from the platform (#3460138, #1083923, #1128701, #325734). The nonce/ajaxUrl/action are often exposed in a public script tag (#3460138).
9. **Missing email authentication (SPF/DMARC)** — the org's domain can be forged by anyone, making phishing mail indistinguishable (#325734, #793532). The `dig` output in #325734 shows only an SOA, no TXT/SPF.
10. **Reliance on visual identity that can be faked** — invisible Unicode, IDN homoglyphs, and homograph rendering defeat uniqueness assumptions (#785243, #275960, #1819329). "Looks unique" and "is unique" diverge.
11. **Missing anti-tabnabbing / UI isolation** — `_blank` without `rel=noopener noreferrer`, cross-tab dialogs, and CSS overlays let an attacker relabel a trusted tab (#181225, #361054, #1819652, #3590586). The browser trusts the opener relationship that the app failed to sever.
12. **Incomplete semantic parsing in confirmation UIs** — malformed data causes a wallet to omit the very warning that protects the user (#1651429). When the input does not match an expected shape, the safe default should be to warn, not to silently drop the warning.
13. **Broken/claimable third-party identity links** — docs and directories link to handles, repos, and domains that anyone can register (#1031321, #515574, #2125346, #276244, #279717). Content becomes stale but the trust in the linking page persists.
14. **No warning label on sensitive notifications** — sandbox-origin mail that looks identical to production verification mail invites confusion (#1128701). Absence of provenance metadata is itself the vulnerability.

### Root-Cause → Fastest-Confirming Probe

Each root cause has a characteristic minimal test. Use this to convert a hypothesis into a confirmed finding quickly:

| Root cause | One probe that confirms it | Evidence to capture |
|---|---|---|
| Unvalidated destination (#481472, #3099816) | Diff rendered `href`/`Location` against visible label | Raw HTML with both values |
| Client-side-only validation (#500348, #1068505) | Replay the exact request with the forbidden value | Server response accepting it |
| Dangling CNAME (#407355, #1390782) | Register/claim backing resource and fetch the hostname | Screenshot of your page on their name |
| Custom-domain trust (#296907) | Bind a domain you control with no TXT check | Pages settings showing it bound |
| Error-path reflection (#106350, #138786) | `GET /test/%2f..%2fMARKER` and grep the body | Response containing MARKER |
| Mail-template injection (#3802451, #278220) | Submit `<a style>...</a>` as a name field | Delivered email HTML |
| Unauthenticated mail handler (#3460138, #1083923) | Anonymous POST with arbitrary recipient/sender | Raw received headers |
| Missing SPF/DMARC (#325734, #793532) | `dig <domain> txt` | Output showing no TXT/SPF |
| Faked identity (#785243, #275960) | Inject invisible/homoglyph char, observe rendering | Two visually identical names |
| Broken tabnabbing isolation (#181225, #361054) | Read `rel` attribute on `_blank` links | HTML showing missing attribute |
| Incomplete UI parsing (#1651429) | Submit malformed calldata, read rendered warning | Before/after confirmation screens |

---

## Bypass Techniques

### URL / Redirect Parser Confusion
```
https://trusted.com@evil.com             # userinfo trick
https://trusted.com\\evil.com            # backslash before @ (#422279)
/\evil.com                               # slash-backslash authority (#3581815)
/%5Cevil.com                             # encoded backslash
//evil.com                               # protocol-relative redirect
https://evil.com%2f.trusted.com
%252e%252e%2f                            # double-encoded traversal (#384101)
```

### Filter / Sanitizer Bypasses
```
3e1.cn.                   # trailing dot defeats malware-list match (#1068505)
position: fixed !important  # exact-match check misses "!important" (#3590586)
U+180E / U+200B           # invisible char in "unique" name (#785243)
 tel:// , javascript: , data: , sms:   # alternate schemes (#500348, #1819652)
<div style="...">         # <img> stripped but <a> with inline style survives (#3802451)
case / encoding variants of blacklisted hostnames
```

### Identity / Trust-Signal Bypasses
```
xn--80ak6aa92e.com        # IDN homograph renders apple.com (#1819329)
www.ոokia.com             # Armenian 'ո' → xn--okia-zgf.com (#275960)
register the broken @handle / repo / expired domain a docs page links to (#1031321, #515574, #276244)
window.opener.location = 'phish'  # _blank tabnabbing when rel missing (#181225, #361054)
sms:/tel: dialog drawn with no origin label over another tab (#1819652)
```

### Delivery / Mail Bypasses
```
arbitrary From via sendfriend / formAction  (#1083923, #3460138)
no SPF/DMARC -> forge org sender outright  (#325734, #793532)
sandbox/sandbox-mode email that looks like real verification mail (#1128701)
no CAPTCHA / no rate limit -> bulk phishing/spam (#3802451, #3460138)
HTML email with <a style> links styled as buttons (#3802451)
```

### Validation-Timing / State Bypasses
```
modify redirect_uri AFTER OAuth consent, not before (#3099816)
login CSRF: force victim into attacker's account to capture entered data (#1124540)
malformed calldata length -> warning silently dropped (#1651429)
replay a client-validated value directly to the API (#500348)
```

### Bypass Decision Tree

Work from the filter's model outward — the bypass usually lives one step past what the developer anticipated:

1. **Is there a domain allowlist?** → try userinfo (`trusted@evil`), backslash (`trusted\evil`), protocol-relative (`//evil`), and `/\evil` forms (#422279, #3581815); then subdomain/encoding tricks.
2. **Is there a scheme allowlist?** → try `tel://`, `sms:`, `data:`, `javascript:`, and case/encoding variants (#500348, #1819652); replay server-side what JS blocked.
3. **Is there a string blocklist?** → trailing dot (#1068505), Unicode lookalikes (#785243, #275960), invisible separators, and `!important` for CSS value checks (#3590586).
4. **Is user content rendered as HTML/mail?** → test which tags survive; in #3802451 `<img>` was stripped but styled `<a>` persisted, so the surviving tag is the payload.
5. **Is the check on a path prefix?** → #422279 validated a `shopifycloud.com` prefix but allowed userdata containing backslashes; put your destination inside the "allowed" portion.
6. **Is there a name/identity uniqueness check?** → invisible characters (#785243) and claimable links (#1031321, #515574) beat the check without triggering it.
7. **Is there a timing/state dependency?** → modify the redirect after OAuth consent (#3099816), or exploit a parser that drops warnings on unexpected shapes (#1651429).

Each bypass should end with the same question: *does the victim now see a trusted surface while the attacker controls the outcome?* If not, the bypass is academic.

---

## Gate 0 Validation

Before writing the report, confirm all three. These gates exist because content spoofing and "I can put text in a URL" are the most frequently N/A'd submissions in this vulnerability class.

1. **Is a genuine trust boundary crossed?**
   - Does the deceptive artifact appear on a *trusted* surface: the company's own origin, a company subdomain, a company-branded email/sender, or the company's login/wallet UI?
   - Would a reasonable user believe it is official? Cite the trust element (domain, sender, logo, login screen) explicitly.
   - If the artifact only exists on attacker-controlled infrastructure, or the "spoof" is just URL text a user must visit anyway, it is not a finding.
   - For takeovers: is the affected name actually in scope, and does it currently resolve to a claimable resource (#407355, #296907)?

2. **What can the attacker DO, and what does the victim LOSE?**
   - Credential capture via a fake login page on a real subdomain (#407355, #1715538)?
   - Payment redirection to the attacker's order (#186862) or token approval without warning (#1651429)?
   - Impersonation / malicious mail from the org's own domain or as the org (#793532, #1083923, #3460138)?
   - Account impersonation via a claimable identity link (#1031321, #2125346)?
   - If the answer is only "text is reflected" or "a URL redirects," quantify the realistic pretext and impact or downgrade.

3. **Can it be reproduced in 10 minutes from scratch by someone else?**
   - For takeovers: is the resource still claimable, and can you show content served on the real company name (#407355, #296907)?
   - For reflection/redirect/mail: are the exact URL, params, and screenshots captured (#841630, #3099816, #3802451)?
   - Is the PoC safe to demonstrate and leave behind (no live credential harvesting, no spam blast)? Provide a teardown/revert path.
   - Does the finding have a stable trusted origin — not a test/staging host out of scope?

**Reality check from the corpus:** Many accepted reports here are Low/Medium with small bounties (#500348 $100, #481472 $250, #106350 $250, #106348 $100, #1651429 $1,000). The strongest are domain takeovers and auth-flow phishing rated High/Medium. Calibrate severity to the trust surface and the demonstrated victim harm, not to the effort of the trick. When in doubt, compare your finding to the closest cited report above.

### Red Flags That Get a Phishing Report N/A'd

- **No trusted origin** — the artifact only exists on your own domain, or on a staging/out-of-scope host.
- **No pretext** — you can reflect text, but cannot explain why a victim would see it and act.
- **No destination control** — the "spoof" points to a fixed or benign target you do not own.
- **User must already be on attacker infrastructure** — e.g. a fake page reachable only by directly visiting attacker.com.
- **Expected behavior** — link text differing from the target is an accepted risk in some products (see Dropbox's response in #252894); check whether the program has already acknowledged it.
- **Pure typo / usability** — a broken link with no claimable destination and no trusted-origin content is often closed as informational (though the corpus shows many were accepted when an expired domain or claimable handle existed, e.g. #276244, #279717).
- **No reproduction** — takeover PoCs where the resource is already claimed, or mail PoCs where the endpoint requires state you cannot share.

If any of these apply, strengthen the trust story or move on; do not submit on mechanics alone.

---

## Real Impact Examples

### Scenario A: Dangling Subdomain → Fake Login Page → Credential Harvest (Greenhouse / Yelp / Rocket.Chat Pattern)
An attacker enumerates a company's subdomains and finds `demo.greenhouse.io` CNAME'd to an Unbounce page that no longer exists (#407355), or `delivery.yelp.com` CNAME'd to an S3 static-site bucket that can be recreated (#1715538), or `traefik-livedemo.rocket.chat` pointing at a deleted AWS ELB whose name can be re-registered (#1390782). The attacker claims the backing resource and hosts a pixel-perfect copy of the company's login portal on the still-trusted company subdomain. Victims who received a link — or who simply recognize the brand in the hostname — enter corporate credentials, which the attacker captures. Because the origin is a legitimate subdomain, browser trust indicators and user suspicion are defeated; the impact is account takeover, malware distribution, and reputational damage. GitLab's custom-domain abuse (#296907) scales the same primitive across 115 takeover-able domains at once, and expired domains found in docs/press links (#276244, #279717, #1031321) extend it to primary domains and social identities.

### Scenario B: OAuth Open Redirect Launders a Trusted Login Flow (Lichess / lovable.dev Pattern)
A victim clicks a link to a real login page on `lichess4545.com` and completes OAuth with Lichess as expected (#3099816). The attacker has altered `redirect_uri=https://example.com/auth/lichess/`, so after a successful, legitimate-looking authorization the victim is landed on an attacker-controlled page — primed to ask for "verification" details. lovable.dev (#3581815) achieved the same with `redirect=/\google.com` on the post-login endpoint. The trust is in the authentic login experience that precedes the redirect, which makes the follow-up phishing page far more convincing than a cold email link. Shopify's `incontext_app_link` backslash confusion (#422279) is the same idea in a modal: a trusted-domain check is satisfied while the browser navigates elsewhere.

### Scenario C: Trusted-Origin Text Injection & Mail Abuse (Acronis / Reddit / HackerOne / WordPress Pattern)
An attacker injects "we are facing heavy traffic, please visit https://attacker.com" into a URL that is reflected on `registration.acronis.com` (#841630) or `ads-api.reddit.com` (#1165919) — the message appears on a company domain, so victims trust it. The 404-page variants (#106350, #106348, #138786) use `/test/%2f../<text>` to the same effect. In the email channel, HackerOne's `ShareReportViaEmail` on a sandbox report produced mail indistinguishable from genuine verification email (#1128701); OpenMage's sendfriend let the attacker choose a company-looking sender (#1083923); and WordPress Gutenberg's unauthenticated `formAction` handler turned any site running the plugin into an open mail relay for phishing and spam (#3460138). Missing SPF/DMARC (#325734, #793532) lets an attacker forge the org's sender outright, so the phishing mail passes every visual check.

### Scenario D: UI Deception Without a Fake Page (Brave / Tor / Nextcloud / MetaMask Pattern)
Some of the strongest trust bugs never host a clone. Brave Shield displayed `apple.com` for the homograph `xn--80ak6aa92e.com` (#1819329), Tor's address bar failed to punycode the Armenian `ո` in `ոokia.com` (#275960), and a Roundcube CSS overlay using `position: fixed !important` covered the whole trusted mail viewport with a "Session Expired / re-enter credentials" dialog (#3590586). Reverse tabnabbing silently rewrote a trusted tab via `window.opener.location` (#181225, #361054), a cross-tab `sms:` dialog was drawn with no origin label over google.com (#1819652), and Android task hijacking (StrandHogg) let a malicious app inherit Reddit's task to phish logins (#1325649). MetaMask (#1651429) shows the financial stakes: malformed ERC20 calldata caused the wallet to omit the token amount, so a phishing site could drain a user's approvals without any alert — the trusted confirmation UI itself became the deception.

### Scenario E: Broken Link / Expired Domain → Impersonation & Misinformation (Legal Robot / Nextcloud / Twitter Docs Pattern)
A link on an official press page points at `ecotechfoundation.net`, an expired domain now available for sale (#276244). A nextcloud.com news post links to `conf.nextcloud.comg/` — a `.comg` typo in a namespace that can be claimed or hijacked (#279717). Twitter's developer docs link to a `@HunterLarco` GitHub identity that anyone can register as `HunterLarcol` (#1031321), and a Liberapay member's Twitter handle was similarly broken and claimable (`#2125346`). In each case the attacker does not need to compromise the company at all — they only need to claim the destination that an authoritative page already vouches for. Victims arriving from the trusted page see a legitimate referral, then receive malicious content, a fake login, or misinformation. data.gov/labs' link to an unclaimed `simple-api` GitHub repo (#515574) is the same pattern in source-controlled hosting.

### Scenario F: Notification & Login-Flow Impersonation (HackerOne / Liberapay / PortSwigger Pattern)
An attacker with a sandbox program creates a report whose "asset" is the real `https://hackerone.com` and uses GraphQL `ShareReportViaEmail` to send a mail that looks like an official verification message, with no sandbox warning label (#1128701). A victim cannot distinguish it from genuine HackerOne correspondence. Liberapay (#1124540) shows the inverse: with no CSRF token on login, an attacker crafts a page that silently signs the victim into the **attacker's** account, so any payment details the victim then enters are captured by the attacker. PortSwigger (#186862) turned an order ID into a GET parameter on `CCPayment.aspx`, so a link on any site could make a victim pay an attacker's order. All three share the same shape: a legitimate platform flow is reused so that the victim's trust in the platform produces the loss.

### Scenario G: Mail-Channel Trust Failure (OpenMage / WordPress / Nextcloud / MyCrypto Pattern)
OpenMage's `sendfriend` flow let a user choose an arbitrary sender address, producing mail that appears to come from the shop (#1083923). WordPress Gutenberg's `wp_block_form_email_submit` was registered with `wp_ajax_nopriv_*` and trusted a client-supplied `formAction`, so any visitor could turn a legitimate site into a phishing/spam relay (#3460138). Nextcloud (#793532) and MyCrypto (#325734) showed missing SPF/DMARC records on the in-scope domains: with no SPF TXT record, an attacker can forge mail *as the organization* and ask victims for passwords or wallet seeds. For a crypto brand, a forged "download the new wallet / change your password at https://attacker.com" message (#325734) is a direct asset-theft vector. The common failure is treating email as a trusted channel without configuring the DNS-level controls that make trust possible.

---

## Disclosed Report Citations (30, all IDs present in study pack)

The following real, verified bug-bounty / coordinated-disclosure cases ground every pattern above. Each entry names the company, title, report ID, subclass, technique, and year/bounty exactly as recorded in the study pack. Where a bounty is not published, it is omitted rather than guessed.

1. **Greenhouse.io — Subdomain Takeover on demo.greenhouse.io pointing to unbouncepages** ([H1 #407355](https://hackerone.com/reports/407355)) — subdomain takeover → fake login page, CNAME to Unbounce, 2018.
2. **Lichess — Open Redirect Vulnerability in OAuth Flow Leading to Potential Phishing Attack** ([H1 #3099816](https://hackerone.com/reports/3099816)) — OAuth `redirect_uri` manipulation, CVSS 3.6, 2025.
3. **Basecamp — Domain Takeover [3737signals.com]** ([H1 #1253926](https://hackerone.com/reports/1253926)) — expired domain discovered via Android app source review, 2021.
4. **Liberapay — Login CSRF: Login Authentication Flaw on https://liberapay.com/** ([H1 #1124540](https://hackerone.com/reports/1124540)) — login CSRF → victim signs into attacker's account, 2021.
5. **Brave Software — Phishing/Malware site blocking on Brave iOS can be bypassed with trailing dot in hostname** ([H1 #1068505](https://hackerone.com/reports/1068505)) — trailing-dot filter bypass, CVSS 6.1, **$250**, 2020.
6. **Rocket.Chat — Possible Domain Takeover on AWS Instance** ([H1 #1390782](https://hackerone.com/reports/1390782)) — AWS ELB CNAME takeover → credential phishing form, 2021.
7. **Yelp — Subdomain Takeover on delivey.yelp.com** ([H1 #1715538](https://hackerone.com/reports/1715538)) — S3 static-site bucket takeover → fake website, 2022.
8. **nextcloud — position: fixed !important bypasses CSS sanitizer's fixed-position mitigation, enabling full-viewport phishing overlays** ([H1 #3590586](https://hackerone.com/reports/3590586)) — CSS sanitizer bypass → session-expired overlay, 2026.
9. **lovable-vdp — Open Redirect on lovable.dev via redirect parameter leads to phishing attacks** ([H1 #3581815](https://hackerone.com/reports/3581815)) — post-login `redirect=/\google.com` open redirect, 2026.
10. **Brave — Brave Shield for iOS is weak against IDN homograph attacks** ([H1 #1819329](https://hackerone.com/reports/1819329)) — IDN homograph renders `apple.com`, 2023.
11. **Slack — URL link spoofing** ([H1 #481472](https://hackerone.com/reports/481472)) — markdown link label/destination desync via `chat.postMessage`, CVSS 3.5, **$250**, 2019.
12. **X / xAI — Github Account hijack through broken link in developer.twitter.com** ([H1 #1031321](https://hackerone.com/reports/1031321)) — claimable broken handle → account impersonation, High, 2020.
13. **OpenMage — Sharing products with Mail allows phishing attacks due to misconfiguration** ([H1 #1083923](https://hackerone.com/reports/1083923)) — arbitrary sender on sendfriend, Medium, 2021.
14. **HackerOne — Lack warning label when receiving a letter** ([H1 #1128701](https://hackerone.com/reports/1128701)) — sandbox-report email social engineering via GraphQL `ShareReportViaEmail`, CVSS 3.1, 2021.
15. **MetaMask — Bypass parsing of transaction data, users on the phishing site will transfer/approve ERC20 tokens without being alerted** ([H1 #1651429](https://hackerone.com/reports/1651429)) — malformed calldata suppresses amount warning, CVSS 3.3, **$1,000**, 2022.
16. **Slack — URL filter bypass in Enterprise Grid** ([H1 #500348](https://hackerone.com/reports/500348)) — client-side validation bypass to `tel://`, **$100**, 2019.
17. **Shopify — H1514 Simple phishing using auto-created modal with weak URL-pattern check in incontext_app_link** ([H1 #422279](https://hackerone.com/reports/422279)) — backslash URL-pattern confusion, Medium CVSS 5.4, 2018.
18. **X / xAI — Twitter Source Label allow 'mongolian vowel separator' U+180E (app name)** ([H1 #785243](https://hackerone.com/reports/785243)) — invisible Unicode in unique app name, 2020.
19. **GSA Bounty — Unclaimed Github Repository Takeover on https://www.data.gov/labs** ([H1 #515574](https://hackerone.com/reports/515574)) — claimable GitHub Pages repo from docs link, 2019.
20. **Imgur — Go.imgur.com can be used to phish for account information** ([H1 #384101](https://hackerone.com/reports/384101)) — double-encoded path traversal redirect on a go-link domain, 2018.
21. **withinsecurity — text injection can be used in phishing 404 page should not include attacker text** ([H1 #106350](https://hackerone.com/reports/106350)) — 404 text injection, **$250**, 2015.
22. **Tor — Address Bar Spoofing on TOR Browser** ([H1 #275960](https://hackerone.com/reports/275960)) — Unicode/IDN address-bar spoofing (Armenian `ո`), High, 2017.
23. **Nextcloud — Invalid request may lead content spoofing for phishing** ([H1 #213056](https://hackerone.com/reports/213056)) — content spoofing via `redirect_uri`, 2017.
24. **Acronis — Content Spoofing** ([H1 #841630](https://hackerone.com/reports/841630)) — trusted-domain text injection, 2020.
25. **Nextcloud — Targeted phishing attacks in Login flow v2** ([H1 #1169033](https://hackerone.com/reports/1169033)) — login-flow v2 token/URL abuse, Medium CVSS 6.8, 2021.
26. **PortSwigger Web Security — Order-phishing via Payment ID URL** ([H1 #186862](https://hackerone.com/reports/186862)) — POST→GET order-id override, victim pays attacker's order, 2016.
27. **Nextcloud — Email Spoofing** ([H1 #793532](https://hackerone.com/reports/793532)) — missing SPF/DMARC → org-domain email forgery, Medium, 2020.
28. **GitLab — Lack of validation before assigning custom domain names leading to abuse of GitLab pages service** ([H1 #296907](https://hackerone.com/reports/296907)) — custom-domain ownership bypass (115 takeover-able domains), Medium, 2017.
29. **Reddit — com.reddit.frontpage vulnerable to Task Hijacking (aka StrandHogg Attack)** ([H1 #1325649](https://hackerone.com/reports/1325649)) — Android task/affinity hijacking for credential phishing, Medium, 2021.
30. **WordPress — Open Email Relay on WordPress Gutenberg Plugin via formAction parameter leads to phishing and spam campaigns** ([H1 #3460138](https://hackerone.com/reports/3460138)) — unauthenticated `wp_ajax_nopriv_*` + unvalidated `formAction`, 2026.

### Citation Index by Discovery Signal

For fast triage, the reports below are grouped by the signal that surfaced them. The 30 numbered citations above are the primary set; a few additional real reports referenced earlier in this skill (all IDs present in the study pack) are included here as supporting precedents. Use the table to find a comparable case for your own finding.

| Report | Company | Discovery signal | Trust surface abused |
|---|---|---|---|
| #407355 | Greenhouse.io | subdomain inventory / PaaS CNAME | company subdomain |
| #1715538 | Yelp | subdomain inventory / S3 CNAME | company subdomain |
| #1390782 | Rocket.Chat | subdomain inventory / ELB CNAME | company subdomain |
| #804080 | U.S. DoD | expired subscription / domain | primary domain |
| #1253926 | Basecamp | Android app source review | expired domain |
| #296907 | GitLab | custom-domain settings / DNS dataset | hosted Pages domain |
| #515574 | GSA Bounty | docs link → claimable repo | GitHub Pages repo |
| #3099816 | Lichess | OAuth `redirect_uri` manipulation | real login flow |
| #3581815 | lovable-vdp | post-login `redirect` fuzz | real login flow |
| #422279 | Shopify | URL-pattern check review (backslash) | auto-created modal |
| #384101 | Imgur | go-link double encoding | go.<brand> redirect domain |
| #1169033 | Nextcloud | login-flow v2 docs | desktop-client login flow |
| #481472 | Slack | `chat.postMessage` body diff | chat link rendering |
| #500348 | Slack | profile API client-side validation | profile URL column |
| #66994 | Slack | copy-paste from PDF observation | chat link parser |
| #841630 | Acronis | content-reflection URL | registration domain |
| #1165919 | Reddit | content-reflection URL | ads API domain |
| #106350 | withinsecurity | 404 path injection | 404 page |
| #106348 | Algolia | 404 path injection | 404 page |
| #138786 | Veris | 404 path injection | 404 page |
| #213056 | Nextcloud | invalid-request handler | error page |
| #3590586 | nextcloud | CSS sanitizer source review | mail-viewport overlay |
| #1128701 | HackerOne | GraphQL `ShareReportViaEmail` | verification-style email |
| #1083923 | OpenMage | sendfriend configuration | arbitrary sender |
| #3460138 | WordPress | plugin `wp_ajax_nopriv_*` source review | open mail relay |
| #325734 | MyCrypto | `dig <domain> txt` | SPF/DMARC absence |
| #793532 | Nextcloud | SPF/DMARC record check | org-domain forgery |
| #785243 | X / xAI | invisible Unicode in app name | source-label identity |
| #275960 | Tor | Unicode address-bar behavior | address bar |
| #1819329 | Brave | IDN homograph panel | security panel |
| #1325649 | Reddit | Android taskAffinity review | app task stack |
| #1124540 | Liberapay | missing CSRF token on login | login flow |
| #186862 | PortSwigger | POST→GET order-id override | payment page |
| #1651429 | MetaMask | malformed calldata parsing | wallet confirmation |
| #181225 | Paragon | `target="_blank"` source review | opener tab |

---

## Related Skills & Chains

- **`hunt-open-redirect`** — open redirect is the laundering primitive for post-login phishing; use this skill's redirect payloads (#3099816, #3581815) as the first hop in a credential-harvest chain. Chain primitive: trusted login → open redirect → fake verification page.
- **`hunt-subdomain-takeover`** — the canonical source of "trusted domain serving attacker content"; chain a takeover (#407355, #1715538, #296907) into a hosted fake-login page and a mass-email campaign. Chain primitive: dangling CNAME → claim PaaS resource → credential capture.
- **`hunt-xss` / `hunt-content-injection`** — content injection is the on-origin cousin of XSS; when reflected markup is blocked, test text-only spoofing on a trusted domain (#841630, #106350, #213056) and CSS-overlay escapes like `position: fixed !important` (#3590586). Chain: marker reflection → styled overlay → fake login dialog.
- **`hunt-csrf`** — login CSRF (#1124540) and state-changing GETs (#186862) convert a victim's own session into the attacker's benefit; pair with a fake page or redirection to complete the phishing chain. Chain primitive: forced login/payment → attacker-controlled account/order.
- **`hunt-email-abuse` / `hunt-smtp`** — mail pipelines (SPF/DMARC gaps #325734/#793532, open relays #3460138, arbitrary senders #1083923) are the delivery channel; validate email headers as rigorously as web responses. Chain: unauthenticated mail handler → trusted sender → mass phishing.
- **`hunt-idn-unicode`** — IDN/Unicode spoofing (#785243, #275960, #1819329) supplies identity deception when no injection is possible; combine with homograph domains and invisible characters. Chain: homograph registration → trusted-looking UI → credential capture.
- **`hunt-browser-platform`** — tabnabbing (#181225, #361054), cross-tab dialogs (#1819652), and address-bar/UI spoofing (#275960) live at the browser trust layer; these need no server-side bug. Chain: `_blank` link → `window.opener` rewrite → user re-enters secrets.
- **`hunt-crypto-wallet`** — transaction-summary deception (#1651429) turns the wallet's own confirmation UI into the phishing surface; audit parsers and warning logic, not just smart contracts. Chain: phishing dApp → malformed calldata → silent unlimited approval.
- **`triage-validation`** — apply the Gate 0 trust-boundary check before submitting: every phishing claim must show a genuine trusted surface, a concrete victim loss, and a 10-minute reproduction; calibrate severity to comparable corpus reports.

### Multi-Skill Chains Worth Testing

The highest-impact outcomes in this corpus come from chaining a trust bug with another primitive:

1. **Takeover → hosted phishing → mail delivery** — claim a dangling subdomain (#407355, #1715538), host a fake login page, then use an unauthenticated mail handler (#3460138, #1083923) to drive traffic to it. Each piece is independently reportable; together they are a full campaign.
2. **Open redirect → OAuth token → account takeover** — an open redirect on a trusted login (#3099816, #3581815) can be combined with stolen OAuth parameters or a crafted authorization URL to harvest tokens, then pivot into the victim's account.
3. **Content injection → CSS overlay → credential capture** — reflected HTML on a trusted origin (#841630, #106350) plus a `position: fixed !important` overlay (#3590586) produces a believable in-page login dialog without hosting any external page.
4. **Login CSRF → payment detail capture** — force the victim into the attacker's account (#1124540), then rely on the platform's normal payment flow to collect whatever the victim enters.
5. **SPF/DMARC gap → domain forgery → wallet drain** — forge mail as a crypto brand (#325734, #793532) with a convincing wallet-update link, then rely on a confirmation-UI weakness (#1651429) to make the resulting approval silent.
6. **Broken doc link → claimable identity → brand impersonation** — claim the handle or repo an official docs page links to (#1031321, #515574), then publish malicious content under the implied endorsement.
7. **Invisible Unicode → duplicate identity → confusion** — register a visually identical app name with U+180E (#785243) or a homograph domain (#1819329, #275960), then wait for victims to confuse the two.

When chaining, report each link in the chain with its own evidence, and state clearly which step is the root cause and which is the amplification. Triage teams prefer a clean, well-attributed primitive over a tangled narrative.
