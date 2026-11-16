---
name: hunt-authorization
description: Hunting skill for the authorization / broken access control / privilege-escalation class. Built from a study pack of 1,306 FULL disclosed reports (1,660 assigned) covering horizontal and vertical privilege escalation, IDOR/BOLA, forced browsing, function-level access control, RBAC and mass-assignment abuse, email-verification and SSO/OAuth/SCIM trust bypasses, GraphQL authorization gaps, subdomain takeover to session and cookie theft, exposed admin panels and Spring Boot actuator and memory-dump endpoints, OTP and password-reset token flaws, and business-logic state-machine violations. Use when hunting ANY access-control finding: prove a concrete cross-user or cross-role impact, never just a hidden endpoint.
sources: github, hackerone_public, portswigger_research, owasp, apisecurity_research
report_count: 1660
full_reports_read: 1306
---

## Crown Jewel Targets

Authorization bugs are the highest-frequency, highest-paying class in this corpus. Researchers repeatedly converge on a small set of surfaces. Prioritize these, roughly in this order.

- **Partner, reseller, and staff portals on a separate subdomain.**
  - These are externally reachable, carry elevated privileges, and receive far less scrutiny than the main product.
  - A limited-privilege partner user created referrals and POS leads at `partners.shopify.com/partner_id/referrals/` and `/partner_leads/pos` (#1457471).
  - A staff-with-no-permissions account copied another store's file assets through an undocumented GraphQL `fileCopy` API (#981472).
  - Low-privilege staff extended a trial period without admin approval (#947728).
  - An admin created an undetectable hidden admin account that could not be seen in the members list (#1596663).

- **Admin panels and management interfaces exposed without authentication.**
  - `plus-website.shopifycloud.com/admin.php?_page=1` was reachable with no auth and allowed data destruction (#1417288).
  - Another admin panel had all functions accessible anonymously (#1394910).
  - A "slinky admin panel" controlling URL redirection was found on a forgotten host (#808762).
  - An unauthenticated development server leaked user data and internal dashboards (#271407).
  - A WordPress `wp-json/wp/v2/users/15` endpoint leaked PII anonymously and led to administrator account takeover (#2450685).

- **GraphQL endpoints with field-level and object-level authorization gaps.**
  - This is the single richest source of subtle authorization disclosures in the pack.
  - HackerOne's `addReportParticipant` mutation returned any user's email given a username and a base64-encoded report ID (#792927).
  - The `report_retests` object on the `User` node leaked asset name, severity, and weakness of undisclosed reports (#871749).
  - The `team` object's `report_sources` field revealed whether a program was private (#770209).
  - A deactivated user could still read data through GraphQL even though REST correctly blocked them (#1192460).
  - A modified query fetched other accounts' address-book entries (#473742).

- **SSO, OAuth, and OIDC trust boundaries.**
  - Email verification and cross-provider trust are the recurring theme here.
  - Bypassing email confirmation in `*.myshopify.com` allowed an attacker to confirm arbitrary emails and take over stores through Shopify SSO (#791775, #796808, #910300).
  - Gitlab OAuth grants could be completed with an unvalidated email, taking over third-party accounts (#922456).
  - A one-click Apple-sign-in account hijack used a `response_type` switch plus `postMessage` and XSS on a sandbox subdomain (#1567186).
  - A Reverb iOS API accepted a token from any Facebook app, not only Reverb's (#314808).
  - An SMS short-code flow allowed actions on any Twitter account that had SMS enabled (#470749).

- **SCIM and user-provisioning features.**
  - A Gitlab group owner could create users with pre-verified `@gitlab.com` emails through SCIM (#565883).
  - This unlocked internal services that gate access on the email domain.
  - Provisioning paths are trusted implicitly; treat every one as a privilege primitive.

- **Internal-only services and localhost admin APIs.**
  - An unauthenticated evostream API on `localhost:7440` executed commands as SYSTEM (#544928).
  - A Docker Registry on port 5000 in a sandbox build environment exposed the `lgtm/top` repository (#347296).
  - A Mapbox internal portal had an OAuth authentication bypass that produced a valid session (#294911).
  - Path traversal on `uberinternal.com` bypassed OneLogin authentication (#326080).

- **Subdomains with dangling DNS records, leading to takeover.**
  - The corpus contains takeovers of Azure, AWS S3 and EC2, Netlify, Unbounce, and Fastly hosts.
  - Confirmed targets include Starbucks subdomains (#665398, #661751, #325336, #186766), Lyst (#779442), HackerOne (#202767), and Gitlab's CSP-allowlisted Fastly host (#716677).
  - A takeover on a parent or sibling domain often defeats cookie scoping, CSP allowlists, and OAuth redirect validation.

- **Spring Boot actuator and memory-dump endpoints.**
  - A public `/actuator/heapdump` leaked secrets, credentials, JWT signing keys, and tokens across three Stripo domains (#783360).
  - With the signing key, an attacker can mint a token for any user.

- **OTP, PIN, and password-reset token endpoints.**
  - Non-expiring login tokens allowed unlimited OTP brute-force (#766578).
  - Adding a second email to a forgot-password request made both recipients receive the same reset token (#1175081).
  - OTP manipulation let an attacker claim an unclaimed restaurant (#1330529).
  - A Shopify preview password page was bypassable (#961929).
  - A phone-number-only path enabled horizontal escalation and account takeover (#205000).

- **File, asset, and terminal reference endpoints with write impact.**
  - Changing a gatekeeper ID read or set anyone's terminal data (#120289, #120291).
  - Arbitrary images, descriptions, and titles were added to other users' issues through IDOR (#1096560).
  - Attacker-chosen UUIDs produced stored XSS executed on admin panels (#249131).

Payouts are highest when an authorization bug yields account takeover of arbitrary users, cross-tenant data access, privileged function execution, or a chain to RCE such as unauthenticated internal command execution or heap-dump key theft.

---

## Attack Surface Signals

### URL and Endpoint Patterns to Hunt

```
/graphql
/api/graphql
/api/v1/users/{id}
/api/v*/users
/wp-json/wp/v2/users
/?rest_route=/wp/v2/users
/rest/api/2/myself
/_api/contextinfo
/admin
/admin.php
/actuator/heapdump
/actuator/env
/partners/*/referrals
/partners/*/partner_leads/*
/ads/*/dashboard
/groups.json
/teams.json
/admin/internal/web/graphql
/api/scim/v2/groups/*/Users
/voyager/api/voyager*
/s/sfsites/aura
/restaurant-onboard-diy/v2/*
/api/v3/login/phone/*
/api/auth/facebook
/user/{id}/orders
/download?file=
/export?user_id=
/wp-json/wp/v2/users/15
/xmlrpc.php
/_vti_bin/Authentication.asmx
/api/*/invitation
/api/*/invite
/report/*/participants
/apply
/coupon/redeem
/order/complete
```

### ID and Reference Parameter Names

```
id
user_id
uid
uuid
guid
pid
post_id
order_id
oid
org_id
team_id
group_id
role_id
doc_id
file_id
msg_id
thread_id
account_id
report_id
resId
terminal_id
gatekeeper_id
conv_id
ref
reference
key
token
hash
cursor
owner
owner_id
email
report_sources
role
is_admin
is_staff
permissions
privilege
scope
account_type
status
isdCode
number
address
```

### Response and Header Signals

```
X-Original-URL or X-Rewrite-URL echoed in an auth decision
Set-Cookie with a wildcard domain such as .target.com
Access-Control-Allow-Origin reflecting the attacker origin with credentials
Location: /admin on a response with an unexpectedly long body
HTTP 200 on a path that should require authentication
HTTP 302 to login that is not actually enforced on the target resource
Content-Security-Policy allowlisting a takeover-able domain
wp-json or wp/v2 or X-WP-Nonce revealing the WordPress REST surface
SAMLResponse, id_token, openid_connect, or RelayState in POST bodies
X-CSRF-Token accepted from a lower-privilege context
```

### JavaScript and Source-Review Patterns

```javascript
fetch('/api/...?id=' + userId)          // client-side ID taken from user input
addReportParticipant / addReportParticipantInput
fileCopy / report_retests / report_sources / ListMembers
is_admin / isAdmin / role === 'admin' / permissions.includes(...)
window.name + postMessage + 'response_type'   // OAuth code theft
loadDataWithBaseURL(...)                       // WebView universal XSS
window.location = '/dashboard/#settings'       // hash-route admin surface
```

### Technology-Stack Signals From the Mined Reports

- **Ruby on Rails and GitLab-style REST plus GraphQL.**
  - Watch for SCIM provisioning, impersonation sessions, deactivated-user policy gaps, and OAuth flows.
- **Shopify-style multi-tenant SaaS.**
  - Watch for `*.myshopify.com` subdomains, partner portals, email-as-identity SSO, and undocumented internal GraphQL mutations.
- **WordPress and PHP.**
  - XMLRPC, REST user enumeration, and path traversal to RCE as seen in "RCE as Admin defeats WordPress hardening" (#436928).
- **Node.js and React admin panels.**
  - Hash-based routing, role models with hidden menu items, and `voyager` internal APIs.
- **Spring Boot.**
  - Exposed actuator endpoints and heap dumps carrying JWT signing keys.
- **Salesforce Experience Cloud and Aura.**
  - The `/s/sfsites/aura` endpoint with `aura.token` enabled BAC and IDOR over candidate PII (#2968391).
- **Any application with a member role, internal visibility, or "only team members" setting.**
  - In these apps the access-control decision is very often enforced only in the UI.

---

## Discovery Patterns From 1,306 Full Reports

### Where Researchers Start (ranked recon surfaces from the study pack frequency table, with what to look for)

The numbers below are counts of full reports containing each signal. They form an empirical ranking of where researchers actually find authorization bugs.
1. **admin-internal — 461 reports.**
   - What to look for: any path or subdomain named admin, internal, dev, staging, or partner.
   - Check admin panels reachable with no auth or with a low-privilege session.
   - Examples: `/admin.php?_page=1` (#1417288), an anonymous admin panel (#1394910), a development server leaking internal dashboards (#271407).
   - Also check localhost-only admin APIs such as `localhost:7440` (#544928) and hidden menu items whose endpoints still work (#605720).
2. **api-endpoint — 395 reports.**
   - What to look for: REST endpoints taking object IDs or role fields, and internal GraphQL mutations absent from public docs.
   - Examples: undocumented `fileCopy` (#981472), API keys surviving a ban (#1577940), and cross-app token substitution at `/api/auth/facebook` (#314808).
3. **search-filter-sort — 345 reports.**
   - What to look for: query parameters that filter or list objects, since these often drop the ownership predicate.
   - The Twitter private-list disclosure brute-forced snowflake IDs in a `ListMembers` query (#885539).
   - HackerOne's invitation mutation leaked an email via a report ID (#792927).
4. **image-processing — 287 reports.**
   - What to look for: upload and avatar endpoints where changing an email or UUID mid-request changes the account context.
   - Shopify's "Upload photo" step was central to a verification bypass (#910300).
   - Static admin pages inside a media interface were left unrestricted (#725711).
5. **filter-bypass — 281 reports.**
   - What to look for: controls the app believes it enforces, such as email confirmation, password pages, approval state, and trial limits.
   - Examples: arbitrary email confirmation (#791775), Shopify preview password bypass (#961929), ad status changed to ACTIVE (#1543159), trial extension (#947728).
6. **server-side-rendering — 246 reports.**
   - What to look for: server-rendered fragments and WebViews that load externally controlled data.
   - `loadDataWithBaseURL` produced universal XSS leading to account takeover (#1455987).
   - An SMS-command interface drove account actions unauthenticated (#470749).
7. **cookie-handling — 213 reports.**
   - What to look for: wildcard cookie domains, impersonation sessions visible in Active sessions, stale API tokens after a ban, and subdomain takeover enabling cookie theft.
   - Key reports: #493324, #1577940, #1570591.
8. **public-code-search — 196 reports.**
   - What to look for: GitHub repositories, wikis, and CI configs revealing forgotten endpoints and hidden validation logic.
   - Default public wiki editing was enabled on some repos (#457009); OAuth email-validation logic was exposed in source (#922456).
9. **comment-injection — 177 reports.**
   - What to look for: notification and email pipelines that leak private content to subscribers.
   - A non-member received private Gitlab commit comments by email (#502593).
   - Notes were accessible without permission (#3241304), and deleted comments were readable by forum non-members (#308610).
10. **subdomain-takeover — 156 reports.**
    - What to look for: dangling CNAME and A records pointing to Azure, AWS S3 or EC2, Netlify, Unbounce, Fastly, or GitHub Pages.
    - Enumerate with `dig`, claim the resource, host a PoC, and demonstrate cookie theft or CSP and redirect trust abuse.
11. **redirect-handling — 156 reports.**
    - What to look for: `next=`, `redirect_uri`, `RelayState`, and SSO post-login redirects that move credentials or assertions across trust boundaries.
    - See the cross-IdP reuse and OAuth code theft cases in #1567186 and #976603.
12. **session-attack — 149 reports.**
    - What to look for: session fixation, non-expiring tokens, impersonation session IDs, and token brute-force paths.
    - Key reports: #766578, #493324, #294911.
13. **json-body and graphql — 132 and 64 reports.**
    - What to look for: mass-assignment fields such as `role`, `is_admin`, and `permissions`, plus GraphQL fields that expose PII.
    - Mutations frequently lack any ownership check.

### Feature-Based Discovery Signals (frequency-ranked)

The following table ranks features by how often they appear in full reports, with why each matters and what to probe.

| Signal (count) | Why it matters | What to probe |
|---|---|---|
| admin-internal (461) | Highest yield; auth often only hides the menu | Direct GET to admin paths; low-priv replay; `groups.json`, `/actuator`, `/admin.php` |
| api-endpoint (395) | APIs get auth bolted on and miss object checks | Swap IDs across tenants; call internal endpoints; replay stale tokens |
| search-filter-sort (345) | List filters frequently omit the owner predicate | Enumerate IDs in list APIs; try owner-id or undefined values |
| image-processing (287) | Upload flows mutate account state mid-request | Change email or UUID before save; re-upload a photo |
| filter-bypass (281) | Confirmation and approval gates are trusted | Confirm arbitrary email; set status ACTIVE; extend a trial |
| server-side-rendering (246) | Rendered contexts bridge trust boundaries | Inject into WebView data; abuse postMessage and response_type |
| cookie-handling (213) | Session equals identity and is bound to a domain | Replay cookies cross-subdomain; test ban-token reuse |
| public-code-search (196) | Source reveals hidden logic and endpoints | Search GitHub for wikis and repos; grep for OAuth validation |
| comment-injection (177) | Notification emails bypass visibility settings | Subscribe as a non-member; read private comments via email |
| subdomain-takeover (156) | Takeover defeats cookie, CSP, and redirect trust | `dig` for dangling records; claim Azure, S3, EC2, or Netlify |
| redirect-handling (156) | Redirects move credentials across trust zones | Manipulate `redirect_uri`, `RelayState`, and `state` |
| session-attack (149) | Session lifecycle flaws produce identity theft | Test token expiry, OTP brute-force, and session ID theft |
| json-body (132) | Mass assignment and type confusion hide in JSON | Add role fields; try array and object type confusion |
| sso-oauth (108) | Email and domain gates are the new perimeter | Unvalidated-email grants, SCIM emails, third-party app tokens |
| misconfiguration (108) | Debug and actuator endpoints leak keys | `/actuator/heapdump`, `/actuator/env`, default credentials |
| csrf (90) | State changes may lack token verification | GET-based escalate; JSON CSRF; OAuth authorize without a token |
| brute-otp-reset (85) | Token endpoints may lack rate limits or expiry | Brute OTP on a non-expiring token; add a second email |
| idor-object-ref (67) | Direct object references lack owner checks | ±1 on IDs; write-capable PUT and DELETE; terminal IDs |
| graphql (64) | Field-level authorization is commonly missing | Introspect; query email and privacy fields; alias batching |
| path-traversal-lfi (58) | Filesystem access bypasses app-level controls | Symlink build artifacts; traverse on internal subdomains |

### Verbatim Discovery Clues (18 real quotes from the study pack)

These are exact "how I found it" lines from disclosed reports. They show the reasoning paths that pay off.
- [#791775] I found a way to confirm arbitrary emails, and after confirming arbitrary email in *.
- [#796808] Then I found user can change their email prior to receiving the verification message on their original email.
- [#1567186] I've been researching new ways to steal OAuth codes and access-tokens using postMessage, and I found a way for me to steal the code and/or access-token from Apple-sign-in on reddit.
- [#423467] I was able to build a relay server for the WebSocket and could snoop on the raw messages without any issue.
- [#665398] I noticed the dangling CNAME record of datacafe-cert.
- [#605720] I didn't research this further, however, I was able to grant all permissions to the user assigned to a group with `Program` permission.
- [#565883] Hi, I found the new SCIM provisioning function allows any group owner in gitlab to create any user with verified email address.
- [#249131] I found an interesting bug where the system allows a user to create their own UUIDs.
- [#1596663] So, taking advantage of this behavior I found the admin as an attacker can create an `undetectable/hidden admin account` and do administrative actions on the organization like remove other users and invite other users.
- [#779442] I was able to register a S3 bucket with this name in AWS.
- [#981472] jack_mccracken is a skilled attacker he found an undocumented GraphQL API called `fileCopy`, he used this API to try to copy a file from his store `StorB` to `StoreA` (where he is a staff member).
- [#766578] While doing the testing for the mobile app, I observed out that it is possible to bypass the authentication and gain unauthorized access to the user's account bu brute-forcing the PIN due to lack of login token expiry.
- [#1417288] I found the admin panel at https://plus-website.
- [#1490470] I found that i can bypass the login page of the Admin account by intercepting the respone of the login request of ```█████``` subdomain and change ```status``` from ```false``` to ```true```
- [#1174527] so i tried to navigate to `dashboard/#settings` and i was able to access MrX's account settings!
- [#144000] Chat Logs" button on one of my past orders, I noticed it triggered the following API request:
- [#308610] I have found an issue where a ` member `(who is not allowed to view deleted comments) can get read access to the deleted comments on a forum's discussion.
- [#961929] I have found a way to bypass the password page of a shopify preview URL for new development stores created as of August 17, 2020.

### Probe Checklist (15 concrete probes)

1. **Direct-admin forced browse.**
   - GET `/admin`, `/admin.php?_page=1`, `/manage`, and `/console` with no session.
   - Repeat with a low-privilege session and compare against the UI-hidden menus.
2. **Low-privilege-to-admin role replay.**
   - As a Program or readonly member, GET the groups and permissions JSON endpoint.
   - Try granting yourself Admin, as in #605720.
3. **ID walk.**
   - Request ±1 and ±1000 around every object ID: orders, reports, terminals, invoices, and lists.
   - Flag any 200 response with different data as in #120289 and #144000.
4. **GraphQL field sweep.**
   - Introspect the schema and query `email`, `invitation{email,token}`, `report_sources`, `report_retests`, and `ListMembers`.
   - See #792927, #770209, and #885539.
5. **Cross-tenant write IDOR.**
   - PUT, POST, or DELETE another user's object and change the owner field.
   - Test terminal and gatekeeper IDs in a PUT request as in #120291.
6. **Email-confirmation bypass.**
   - Change the email before confirmation so the confirmation goes to your signup address.
   - Confirm and then exploit the shared-email SSO integration as in #791775.
7. **SCIM verified-email provisioning.**
   - Create a user with a privileged-domain email through SCIM.
   - Log into a service that gates on that email domain as in #565883.
8. **OAuth token substitution.**
   - Replay a token from another app of the same provider into the login API as in #314808.
   - Test an unvalidated-email grant as in #922456.
9. **Session and impersonation theft.**
   - Inspect Active sessions during an admin impersonation and capture the session ID as in #493324.
10. **Non-expiring token and OTP brute-force.**
    - Capture the login-token endpoint and replay with unbounded OTP attempts as in #766578.
    - Add a second email to a reset request as in #1175081.
11. **Dangling DNS takeover.**
    - Run `dig` over all subdomains looking for CNAMEs to Azure, S3, EC2, Netlify, Unbounce, or Fastly.
    - Claim the resource and host a PoC as in #665398 and #779442.
12. **Actuator and heap dump.**
    - GET `/actuator/heapdump` and `/actuator/env`.
    - Mine the dump for JWT secrets and tokens as in #783360.
13. **Notification-pipeline leak.**
    - Subscribe as a non-member to commit or list events and read private content from email as in #502593.
14. **Hidden hash-route and stale token.**
    - Navigate to `/dashboard/#settings` directly as in #1174527.
    - Check ban bypass with a previously issued API key as in #1577940.
15. **Business-logic state skip.**
    - Change ad or campaign status to ACTIVE without payment or approval.
    - Apply a coupon repeatedly and extend a trial as in #1543159 and #947728.

---

## Step-by-Step Hunting Methodology

1. **Establish two identities before touching anything.**
   - Create attacker A and victim B accounts.
   - Add a low-privilege or role-limited account wherever roles exist.
   - Authorization is about relationships between principals and objects, so you need a second principal to prove a violation.
   - The corpus repeatedly uses two accounts, for example Gitlab project visibility tests (#502593) and Shopify staff and stores (#981472).
2. **Map every object-reference surface.**
   - Spider the target, mine JS bundles, and review archived URLs for endpoints accepting an ID, UUID, email, filename, token, or role field.
   - Use `gau` and `waybackurls`, then extract the parameter names.
   - Pay special attention to list, search, and filter endpoints and to internal GraphQL mutations not in public docs (#981472).
3. **Build an authorization matrix.**
   - For each endpoint crossed with each role, record the status code and response length.
   - Use anonymous, user, low-privilege staff, admin, and partner roles.
   - Endpoints returning 200 to the wrong role are your candidates.
   - Automate with Burp Autorize or AuthMatrix by replaying high-privilege requests with a low-privilege token, matching the #605720 pattern.
4. **Run the IDOR differential.**
   - For each object ID, request your own object, a neighbor's object, and a non-existent object.
   - Interpret results carefully:
     - 200 with different data means confirmed IDOR.
     - 200 with the same data suggests a self-reference fallback or cache.
     - 403 means authorization exists but may be bypassable.
     - 404 means the object does not exist or you have no access; enumerate to confirm.
     - A response-size delta can reveal hidden fields.
   - Escalate read IDORs to write impact with PUT, DELETE, transfer, and owner change.
5. **Attack the trust gate, not only the object.**
   - If the app gates on email confirmation, provider, or domain, attack that gate.
   - Confirm an arbitrary email as in #791775.
   - Provision a verified email through SCIM as in #565883.
   - Use a token from the wrong OAuth app as in #314808.
   - These bypasses yield account takeover rather than a single-object leak.
6. **Probe GraphQL separately.**
   - Introspect the schema.
   - Look for fields returning PII or privacy state, such as `email`, `report_sources`, and `report_retests`.
   - Look for mutations with no ownership check.
   - Test alias batching and ID substitution.
   - A deactivated user reaching GraphQL when REST blocks them is a classic finding (#1192460).
7. **Enumerate SSO and OAuth flows end to end.**
   - Capture the full request chain and inspect `state`, `redirect_uri`, `response_type`, `RelayState`, and email-verification assumptions.
   - Test removing `state`, switching the response type, reusing assertions cross-provider, and logging in with an unvalidated email.
   - See #1567186, #976603, and #922456.
8. **Hunt subdomain takeovers systematically.**
   - Run `dig CNAME` over all discovered subdomains.
   - Look for records pointing to unclaimed Azure `cloudapp.net` or `azurewebsites.net`, S3 buckets, EC2 A records, Netlify, Unbounce, Fastly, or GitHub Pages.
   - Claim the resource and demonstrate cookie theft or CSP and redirect trust abuse as in #661751, #716677, and #1296366.
9. **Probe internal and management surfaces.**
   - Try `/actuator/heapdump`, `/admin`, localhost-bound APIs, and legacy protocol endpoints such as XMLRPC, SharePoint `_vti_bin`, and Atlassian REST.
   - Also try hash-based admin routes.
   - A hidden menu item is not a control; navigate to it directly as in #1174527, #544928, and #808762.
10. **Check session lifecycle and token strength.**
    - Test token expiry, impersonation sessions, non-expiring OTP tokens, stale API keys after a ban, and reset-token reuse.
    - See #766578, #493324, #1175081, and #1577940.
11. **Test business-logic state machines.**
    - Identify pending-to-approved transitions for ads, referrals, trials, orders, and coupons.
    - Try to set the terminal state directly or through a low-privilege role as in #1543159, #947728, and #1330529.
12. **Verify with a clean reproduction.**
    - Start a fresh browser and session.
    - Follow your exact steps and land in a protected resource as the wrong principal.
    - Capture the full request and response pair showing the victim's data or a privileged action.
    - If you only show that an endpoint exists, keep working.
13. **Chain for critical impact.**
    - Combine subdomain takeover with cookie theft and an admin session.
    - Combine IDOR with reading an admin user, changing their password, and account takeover.
    - Combine email-confirmation bypass with SSO integration and cross-store takeover.
    - Combine heap-dump key leak with forged JWT and any account.
    - The highest payouts in this corpus are chains, including #791775 and #783360.

---

## Payload & Detection Patterns

### IDOR and BOLA Request Mutations

```bash
# Read another object
GET /api/user/123   ->  GET /api/user/124
GET /api/orders/456 ->  GET /api/orders/457
GET /api/v1/accounts/123/documents/789 -> /api/v1/accounts/124/documents/789

# Write IDOR - escalating read to impact
PUT /api/terminal/261972220  {"data":"..."}   # set anyone's terminal data (#120291)
DELETE /api/posts/789
POST /api/transfer  {"from_account":"victim","to_account":"attacker","amount":10000}

# Object reference in every location
?id=124
?user_id=124
?resId=124
Cookie: id=124
```

### GraphQL Authorization Probes

```graphql
# Email disclosure via invitation mutation (#792927)
mutation {
  addReportParticipant(input:{report_id:"<base64 gid>", login:"victim"}) {
    invitation { email token }
    errors { nodes { message } }
  }
}

# Privacy-state and PII fields (#770209, #871749, #792927)
query { team(handle:"victim") { _id report_sources } }
query { user(username:"victim") { id report_retests { asset_name severity_rating weakness_name } } }

# Cross-user object via snowflake brute-force (#885539)
query { ListMembers(list_id:<victim_snowflake>) { members { id } } }
```

### Mass Assignment and Role Tampering in JSON Bodies

```json
{"email":"user@target.com","password":"pass","role":"admin"}
{"name":"John","role":"admin","is_admin":true,"permissions":["all"],"is_staff":true}
{"is_admin":false}
{"is_admin":"true"}
{"role":"user"}
{"role":["user","admin"]}
{"__proto__":{"isAdmin":true}}
{"constructor":{"prototype":{"isAdmin":true}}}
```
```bash
# HTTP parameter pollution
?id=123&id=124
?role=user&role=admin
```

### Header-Based Authorization Bypasses

```
X-Original-URL: /admin/users
X-Rewrite-URL: /admin/users
X-User-Id: 124
X-Role: admin
X-Admin: true
X-Original-User: admin
X-Forwarded-For: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
Host: admin.target.com
```

### HTTP Method and Path Normalization Bypasses

```
GET /admin  ->  POST /admin
GET /admin  ->  PUT /admin
GET /admin  ->  PATCH /admin
GET /admin  ->  OPTIONS /admin
POST /api/users/123?_method=PUT
X-HTTP-Method-Override: DELETE
/admin/..;/user
/admin//
/admin%20
/admin.
admin/#/settings
dashboard/#settings
```

### Email-Confirmation and Identity-Provider Bypasses

```
# Change email before confirmation so the link goes to the signup address
# (#791775, #910300)
1. Register account with attacker email E1.
2. Before confirming, change account email to victim E2.
3. Confirmation link for E2 is delivered to E1.
4. Confirm; SSO now treats the attacker as owner of E2.
```
```bash
# SCIM verified-email provisioning (#565883)
POST /api/scim/v2/groups/GROUP/Users
{"emails":[{"value":"ngalog@gitlab.com"}],"userName":"ngalog","active":true}
```

### SSO, OAuth, and Session Probes

```
# Token substitution across apps (#314808)
POST /api/auth/facebook  {"fb_token":"<token from ANY Facebook app>"}

# Response manipulation of login (#1490470)
Intercept login response; change "status": false to "status": true

# Non-expiring login token OTP brute-force (#766578)
POST /api/v3/login/phone/<SOMETOKEN>  {"response":"0000"}

# Reset token to two recipients (#1175081)
{"email":"victim@target.com","email":"attacker@target.com"}
```

### Exposed Management and Secret-Leak Endpoints

```bash
curl -s https://target/actuator/heapdump -o heap.bin
curl -s https://target/actuator/env
curl -s https://target/admin.php?_page=1
curl -s https://target/wp-json/wp/v2/users/15
curl -s https://target/groups.json
curl -s https://target/teams.json
```

### Subdomain-Takeover Reconnaissance

```bash
subfinder -d target.com | dnsx -a -cname -resp
# Look for CNAME to *.azurewebsites.net / *.cloudapp.net / *.s3.amazonaws.com
# Look for unbouncepages.com / *.netlify.app / *.freetls.fastly.net
dig dangling-sub.target.com CNAME
# Claim the resource, host a PoC, demonstrate cookie capture or CSP abuse
```

### Automation Snippets

```bash
# Parallel IDOR differential; redact victim data in any saved output
seq 1 1000 | xargs -P 20 -I {} curl -s -o /dev/null \
  -w '%{http_code} %{size_download}\n' \
  "https://target.com/api/orders/{}" -H "Authorization: Bearer $TOKEN"

# gau to parameter extraction
gau target.com | grep -E '(=id=|user_id=|/api/|/graphql|/admin)' | sort -u
```

---

## Common Root Causes

1. **Authorization is decided in the UI, not on the server.**
   - Hidden menus, disabled buttons, and invisible Group Management links are not controls.
   - The underlying endpoint still grants access as in #605720, #1174527, and #1457471.
2. **Missing per-object ownership check.**
   - A record is fetched by primary key and returned without verifying it belongs to the current principal.
   - This is the definition of IDOR and BOLA as seen in #120289, #144000, and #1096560.
3. **Email is treated as an identity proof without verifying mailbox control.**
   - Arbitrary-email confirmation, SCIM pre-verified emails, and OAuth flows that trust an unvalidated email all collapse identity.
   - See #791775, #565883, and #922456.
4. **Trust is inherited across contexts.**
   - A token, assertion, or cookie issued in a low-trust context is accepted in a high-trust context.
   - Only the signature or format is checked, not the issuance context.
   - See #314808, #976603, #1192460, and #1577940.
5. **State gates are enforced at only one step.**
   - Payment, approval, trial, and confirmation states can be set directly through an API that does not re-check the transition.
   - See #1543159, #947728, and #1330529.
6. **Key material and debug surfaces are exposed.**
   - Public actuator and heap-dump endpoints leak the JWT signing key or tokens.
   - Any authorization decision based on a signed token becomes forgeable as in #783360.
7. **Dangling infrastructure creates a trusted origin.**
   - Unclaimed CNAME targets on parent or allowlisted subdomains defeat cookie scoping, CSP, and redirect validation.
   - See #716677 and #186766.
8. **Notification and aggregation paths bypass visibility.**
   - Emails and event streams are generated from a different authorization path than the UI.
   - This leaks private comments and member lists as in #502593 and #308610.
9. **Secrets are non-expiring and reusable.**
   - OTP tokens, reset tokens, and API keys that never expire or are not revoked on a ban turn one interception into persistent unauthorized access.
   - See #766578, #1175081, and #1577940.
10. **Enforcement differs between protocol surfaces.**
    - REST blocks a deactivated user but GraphQL does not.
    - SSO protects the login form but legacy endpoints accept native credentials.
    - The main domain is hardened but a sibling subdomain is takeover-able.
    - See #1192460, #326080, and #202767.

---

## Bypass Techniques

### Bypassing Hidden-Menu and Role Restrictions

| Defense | Bypass |
|---|---|
| Admin menu hidden for low-priv role | Direct GET to `groups.json`, `/admin.php?_page=1`, `/partners/*/referrals` |
| UI shows no permission | Call the underlying POST or GET endpoint directly |
| Role field not in the normal form | Add `role`, `is_admin`, and `permissions` to the JSON body |
| Button is disabled | Remove the `disabled` attribute or replay the captured request |
| Hash route hides settings | Navigate to `dashboard/#settings` directly (#1174527) |

### Bypassing Object-Level Checks

| Defense | Bypass |
|---|---|
| Opaque ID assumed unguessable | Enumerate snowflakes and time-based IDs within a second's window (#885539) |
| ID hashed or encoded | Decode the base64 report gid, increment, and re-encode (#792927) |
| Ownership enforced on GET only | Use PUT, POST, or DELETE with another user's ID (#120291) |
| Single-object check | Use a batch or bulk endpoint with an array including the victim's ID |
| Nested resource check | Remove intermediate path nodes, for example to `/tasks/4` |

### Bypassing Verification and Email Gates

| Defense | Bypass |
|---|---|
| Email must be confirmed | Change email before confirmation; the link goes to the signup address (#791775) |
| Confirmation sent to new address | Use Burp match-and-replace on the account page plus photo upload (#910300) |
| Service gates on `@company.com` | SCIM-provision a user with a verified `@company.com` email (#565883) |
| OAuth requires validated email | Sign in on a provider with an unvalidated email and complete the grant (#922456) |
| Preview password page | Bypass the preview password for development stores (#961929) |

### Bypassing SSO and Token Trust

| Defense | Bypass |
|---|---|
| Only own provider's token accepted | Use a token from any app of that provider in the login API (#314808) |
| MFA or SSO enforced on the UI | Probe legacy endpoints such as XMLRPC, `_vti_bin`, and Atlassian REST |
| Assertion tied to one IdP | Reuse the assertion cross-IdP or switch response type with postMessage theft (#1567186, #976603) |
| Signature-based token trust | Forge a JWT using a key leaked from a heap dump (#783360) |
| Login response controls access | Flip `status:false` to `true` in the intercepted response (#1490470) |

### Bypassing DNS and Cookie Trust

| Defense | Bypass |
|---|---|
| Cookie scoped to parent domain | Take over a sibling subdomain and harvest cookies (#186766, #1570591) |
| CSP allowlist includes a subdomain | Take over that subdomain to bypass CSP (#716677) |
| OAuth redirect restricted to `*.target.com` | Take over a subdomain in the wildcard to receive the code |
| Rate limit on main login | Use an alternate API or legacy endpoint with no throttling (#341074, #819930) |

---

## Gate 0 Validation

Before writing any report, answer all three questions. A finding that fails any of them is not ready.
1. **What can the attacker do right now?**
   - It must be concrete: read another user's data, modify or delete another user's object, assume another identity, or execute a privileged action.
   - Merely discovering an admin endpoint, an error message, or an ID that exists is not authorization impact.
   - Show the victim's record or the privileged action in the response.
2. **What does the victim lose?**
   - Name the concrete asset: account takeover of a specific user, cross-tenant data such as PII or payment records, admin function execution, or a chain to RCE.
   - Strong examples include unauthenticated command execution as SYSTEM (#544928) and heap dump to forged JWT (#783360).
   - Quantify the blast radius, meaning how many users or tenants are affected, rather than assigning a generic CVSS score.
3. **Can it be reproduced in 10 minutes from scratch?**
   - Start a fresh browser and session and follow the exact steps to reach the protected resource as the wrong principal.
   - If reproduction depends on a specific victim's active session, a timing window, or luck, stabilize it first.
   - Include the full request and response pair with the victim's identity redacted but the differential still visible.

Never submit a claim whose only evidence is that a menu was hidden but the path exists, without showing data or action impact. Triage routinely closes those as informational.

---

## Real Impact Examples

### Scenario A: Email Confirmation Bypass to Cross-Store Owner Takeover via SSO

- Pattern: Shopify, reports #791775, #796808, #910300.
- An attacker signs up for a store with their own email.
- Before confirming, they change the account email to the victim's address.
- Shopify mistakenly sends the confirmation link for the new email to the original signup inbox.
- The attacker confirms the victim's email.
- They then use the shared-email SSO integration to connect to any store whose owner uses that email.
- Impact: full privilege escalation to owner of arbitrary stores.
- This is the highest-severity shape in the corpus: a small verification flaw chained through SSO into cross-tenant takeover.

### Scenario B: GraphQL Field-Level Disclosure to PII of Every User

- Pattern: HackerOne, report #792927, plus #871749 and #770209.
- A GraphQL `addReportParticipant` mutation returned an `invitation` object with the invited user's email and token.
- Supplying a username and a base64-encoded report ID produced `was_successful:true` with the victim's email.
- The result was the email addresses of arbitrary users given only a username, rated High at CVSS 8.3.
- Related fields such as `report_retests` and `report_sources` leaked undisclosed-report metadata and private-program status.
- Impact: systematic PII harvesting and confidentiality loss at platform scale.

### Scenario C: SCIM Verified-Email Provisioning to Internal Service Access

- Pattern: Gitlab, report #565883.
- A group owner used the SCIM provisioning API to create a user with a `@gitlab.com` email marked as verified.
- Many internal services gate access on the email domain matching `@gitlab.com`.
- The attacker could therefore authenticate to those internal services as a verified insider.
- Impact: bypass of a domain-based trust boundary to reach internal-only infrastructure.

### Scenario D: Public Heap Dump to Forged JWT to Any Account

- Pattern: Stripo, report #783360, CVSS 10.0.
- Three domains exposed Spring Boot `/actuator/heapdump`.
- The dump contained secrets, credentials, URLs, JWT tokens, and the JWT signing key.
- With the key, an attacker could mint a valid token for any user.
- Impact: complete collapse of authentication and authorization across all users and microservices.

### Scenario E: Subdomain Takeover to Cookie, CSP, and Redirect Trust Defeat

- Pattern: Starbucks, Lyst, Gitlab, reports #665398, #779442, #716677, #186766.
- Dangling CNAMEs to unclaimed Azure services, S3 buckets, and a Fastly host allowlisted in CSP were claimable.
- Once an attacker serves content on a trusted sibling or allowlisted subdomain, they can capture parent-scoped cookies.
- The same position defeats CSP and intercepts OAuth redirects.
- Impact: credential and session theft and highly convincing phishing under the organization's genuine domain.

---

## Disclosed Report Citations

The following 30 entries are real, verified reports present in the 1,306-report study pack and/or `TOPAUTHORIZATION.md`. IDs and URLs are exact.
1. **Shopify — Email Confirmation Bypass in myshop.myshopify.com that Leads to Full Privilege Escalation to Any Shop Owner by Taking Advantage of the Shopify SSO** ([H1 #791775](https://hackerone.com/reports/791775)) — email-confirmation bypass to SSO cross-store ATO, arbitrary-email confirmation, 2020, Critical.
2. **Shopify — [Part II] Email Confirmation Bypass in myshop.myshopify.com that Leads to Full Privilege Escalation** ([H1 #796808](https://hackerone.com/reports/796808)) — verification bypass retest, pre-confirmation email change, 2020, Critical.
3. **HackerOne — Email address of any user can be queried on Report Invitation GraphQL type when username is known** ([H1 #792927](https://hackerone.com/reports/792927)) — GraphQL field-level auth, invitation mutation and base64 report id, 2020, High, CVSS 8.3.
4. **Shopify — Email Confirmation Bypass in your-store.myshopify.com which leads to privilege escalation** ([H1 #910300](https://hackerone.com/reports/910300)) — verification bypass via Burp match-and-replace plus photo upload, 2020, Critical.
5. **Ubiquiti Inc. — Privilege Escalation From user to SYSTEM via unauthenticated command execution** ([H1 #544928](https://hackerone.com/reports/544928)) — unauthenticated internal admin API on localhost evostream, 2019, Critical, CVSS 9.6.
6. **Reddit — One-click account hijack for anyone using Apple sign-in with Reddit, due to response-type switch + leaking href to XSS on www.redditmedia.com** ([H1 #1567186](https://hackerone.com/reports/1567186)) — OAuth response-type switch, postMessage and XSS code theft, 2022, Critical.
7. **Reverb.com — Full account takeover** ([H1 #314808](https://hackerone.com/reports/314808)) — OAuth token substitution, login API accepts any provider app token, 2018, High.
8. **GitLab — Attacker is able to access commit title and team member comments which are supposed to be private** ([H1 #502593](https://hackerone.com/reports/502593)) — notification-pipeline access control, non-member subscription leak, 2019, High.
9. **X / xAI — Private list members disclosure via GraphQL** ([H1 #885539](https://hackerone.com/reports/885539)) — GraphQL object authorization, snowflake ID brute-force, 2020, Low.
10. **Starbucks — Subdomain takeover of datacafe-cert.starbucks.com** ([H1 #665398](https://hackerone.com/reports/665398)) — dangling CNAME to Azure app service takeover, 2019, High, CVSS 7.5.
11. **HackerOne — Team member with Program permission only can escalate to Admin permission** ([H1 #605720](https://hackerone.com/reports/605720)) — RBAC bypass via groups endpoint and groups.json, 2019, Medium, CVSS 4.8.
12. **GitLab — Ability to bypass email verification for OAuth grants results in accounts takeovers on 3rd parties** ([H1 #922456](https://hackerone.com/reports/922456)) — unvalidated-email OAuth grant bypass, 2020, High, $3,000.
13. **Superhuman (formerly Grammarly) — Ability to DOS any organization's SSO and open up the door to account takeovers** ([H1 #976603](https://hackerone.com/reports/976603)) — cross-IdP SSO trust confusion and ATO, 2020, High, $10,500.
14. **GitLab — Privilege escalation from any user (including external) to gitlab admin when admin impersonates you** ([H1 #493324](https://hackerone.com/reports/493324)) — impersonation session ID theft via Active sessions, 2019, Critical.
15. **GitLab — Bypass Email Verification, Able to Access Internal Gitlab Services that use Login with Gitlab and Perform Check on email domain** ([H1 #565883](https://hackerone.com/reports/565883)) — SCIM verified-email provisioning, 2019, Medium.
16. **GitLab — Unauthenticated blind SSRF in OAuth Jira authorization controller** ([H1 #398799](https://hackerone.com/reports/398799)) — OAuth controller Host-header SSRF found via public code, 2018, High, CVSS 7.5, $4,000.
17. **GitLab — Ability To Delete User(s) Account Without User Interaction** ([H1 #928255](https://hackerone.com/reports/928255)) — unauthenticated identity-spoofed GDPR deletion, 2020, High, CVSS 7.5.
18. **HackerOne — HackerOne Jira integration plugin Leaked JWT to unauthorized jira users** ([H1 #1103582](https://hackerone.com/reports/1103582)) — cross-role token and JWT leakage in an integration, 2021, Medium, CVSS 4.8, $3,000.
19. **Semmle — Privilege escalation in workers container** ([H1 #692603](https://hackerone.com/reports/692603)) — malicious build package gives root in container, 2019, High, $1,500.
20. **Upserve — Ability to create own account UUID leads to stored XSS** ([H1 #249131](https://hackerone.com/reports/249131)) — attacker-controlled identifier executed on admin panels, 2017, High, $1,500.
21. **HackerOne — Unauthorized access to metadata of undisclosed reports that were retested** ([H1 #871749](https://hackerone.com/reports/871749)) — GraphQL report_retests field disclosure, 2020, Medium, CVSS 5.0.
22. **Reddit — Able to approve admin approval and change effective status without adding payment details** ([H1 #1543159](https://hackerone.com/reports/1543159)) — business-logic state-machine bypass, 2022, High, $5,000.
23. **Reddit — Admin can create a hidden admin account which even the owner can not detect and remove and do administrative actions on the application** ([H1 #1596663](https://hackerone.com/reports/1596663)) — role-model abuse, undetectable admin, 2022, High.
24. **Semmle — Worker container escape lead to arbitrary file reading in host machine [again]** ([H1 #697055](https://hackerone.com/reports/697055)) — symlink build artifact gives host file read, 2019, Critical, CVSS 9.3, $2,000.
25. **Shopify — Limited Privilege User Can Create Unauthorized Referrals on partners.shopify.com** ([H1 #1457471](https://hackerone.com/reports/1457471)) — partner-portal function-level BAC, 2022, Medium, CVSS 4.3.
26. **WordPress — RCE as Admin defeats WordPress hardening and file permissions** ([H1 #436928](https://hackerone.com/reports/436928)) — path traversal and upload to RCE as admin, 2018, Critical.
27. **Lyst — Subdomain takeover of storybook.lystit.com** ([H1 #779442](https://hackerone.com/reports/779442)) — dangling CNAME to S3 bucket takeover plus stored XSS, 2020, High, CVSS 7.3, $1,000.
28. **Stripo Inc — Open memory dump method leaking customer information, secret keys, password, source code & admin accounts** ([H1 #783360](https://hackerone.com/reports/783360)) — exposed actuator heapdump to JWT key theft to ATO, 2020, Critical, CVSS 10.0.
29. **Shopify — Undocumented `fileCopy` GraphQL API** ([H1 #981472](https://hackerone.com/reports/981472)) — undocumented mutation copies cross-store assets as no-permission staff, 2020, Medium, CVSS 4.2, $2,000.
30. **Affirm — Absence of Token expiry leads to Unauthorized login Access** ([H1 #766578](https://hackerone.com/reports/766578)) — non-expiring OTP login token enables brute-force auth bypass, 2019, Critical.

---

## Related Skills & Chains

- **`broken-access-control-idor-bola`.**
  - The deep methodology companion covering IDOR/BOLA enumeration, path traversal, CSRF, business logic, and reporting templates.
  - Load it once this skill's frequency-ranked signals have pointed you at a surface.

- **`hunt-auth-bypass`.**
  - Owns the SAML, JWT, and SSO-protocol bypass taxonomy, including XSW, signature stripping, alg-confusion, and the legacy-protocol matrix.
  - Chain: authorization finds the trust boundary, and auth bypass supplies the protocol-level forgery technique as in #1567186 and #976603.

- **`hunt-ssrf`.**
  - Chain primitive: a BAC or function-level bypass reaching an internal admin API or hostile Host header becomes full-read SSRF and cloud metadata access.
  - See #398799 and #544928.

- **`hunt-jwt-crypto` and `hunt-saml`.**
  - When the authorization decision rests on a signed token, these skills cover forging it through algorithm confusion, key confusion, or XSW.
  - Keys may come from exposed management endpoints as in #783360.

- **`hunt-cloud-misconfig` and `cloud-iam-deep`.**
  - Subdomain takeover and exposed actuators are cloud misconfigurations.
  - Chain stolen credentials and tokens into cloud privilege escalation.

- **`hunt-rce`.**
  - Several authorization findings terminate in code execution: unauthenticated SYSTEM command execution (#544928), container escape (#697055, #692603), and RCE as Admin (#436928).

- **`triage-validation`.**
  - Apply Gate 0 before submission: show the victim's data or a privileged action, not merely a reachable endpoint.
  - Subdomain-takeover and hidden-menu claims are frequent N/A's without demonstrated impact.

- **`security-arsenal`.**
  - Load the ID and encoding bypass tables plus the header-bypass patterns before testing filters.

---

## Merged Source Knowledge

This section consolidates **108 unique knowledge blocks** from 15 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (112 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/bountyforge/references/hacking-agents/access-control-agent.md`

# Access Control Agent

You are an attacker that breaks permission models. Your target: every role, modifier, guard, and access check in the codebase or API.

Other agents cover math, economics, and web injection. You own: role bypass, privilege escalation, initialization hijack, proxy admin, and confused deputy.

### Map the Permission Surface

Before attacking, build a complete permission map:
- Every role, group, or capability: `owner`, `admin`, `minter`, `relayer`, `pauser`, `operator`, `manager`, etc.
- Every function and its guard (or lack thereof).
- Every role-granting path: who can grant/revoke what.
- Every initializer, constructor, and one-time setup function.

This map is your attack surface. Everything below targets it.

### Inconsistent Guards

For every storage variable written by 2+ functions:
- Find the one with the weakest (or no) guard.
- If function A requires `onlyOwner` but function B writes the same state without it — exploit B.
- Check inherited functions: parent contract functions sometimes lack child-added guards.
- Check `internal` helpers reachable from differently-guarded `external` functions.

### Initialization Hijack

- Call `initialize()` on the implementation contract directly (proxy targets).
- Front-run deployment transactions to initialize with your own address before the deployer.
- Pass `address(0)` or null as a privileged role parameter → permanent admin lockout.
- Find re-initialization: is `initialized` flag checked before every `initialize` call?
- Aptos: can `init_module` be called externally via a wrapper function?

### Privilege Escalation Chains

- Role A can grant Role B → Role B can call `grantRole` → escalate to admin.
- Timelock bypass: can you trigger an upgrade or sensitive action without waiting?
- Find `renounceRole` / `removeAdmin` that leaves the system in an unrecoverable state (griefing).
- Operator chains: if contract A delegates to contract B, can you control B to make A do unauthorized things?

### Confused Deputy

- Contract A calls contract B using A's permissions/approvals.
- Find functions in A that accept arbitrary addresses and call them with A's stored approvals.
- ERC20 allowance abuse: contract holds a standing approval → find unguarded function that calls `transferFrom` on behalf of the contract.
- Anchor/Solana: CPI where the calling program's signer seeds are passed without validation.

### Proxy & Delegatecall Abuse

- Storage slot collision between proxy admin storage and implementation storage.
- `delegatecall` to user-supplied address.
- Implementation contract callable directly (bypasses proxy's access control wrapper).
- UUPS: `_authorizeUpgrade` not guarded or reachable via unexpected path.

### Web/API Access Control

- Forced browsing: enumerate admin routes (`/admin`, `/internal`, `/api/v1/admin`).
- Token privilege confusion: JWT role claim modifiable (weak signature, `alg:none`).
- Function-level authorization: API that checks auth at middleware but not at handler level for specific actions.
- Object-level: IDOR where resource ownership not verified per-request.
- Tenant isolation: multi-tenant API where tenant ID from JWT not validated against resource's tenant.

### Email Confirmation Bypass → SSO Takeover (H100 Proven)

This pattern appeared 3 times in the top 100 reports against a major e-commerce platform.

**Exploitation steps:**
1. Create trial account with your-controlled email
2. Go to profile → change email to victim's email
3. Confirmation link sent to YOUR email (not victim's)
   - Bug: confirmation goes to the "current" email, not the "new" email
4. Click confirmation link → your account now has victim's email confirmed
5. Use SSO: your account = victim's email across all stores/services
6. Set master password via SSO → take over all accounts using that email

**How to test this on any platform:**
- Create account with email A
- Change email to email B (victim)
- Where does confirmation link go? A or B?
- If it goes to A → email confirmation bypass
- Check if SSO/OAuth links accounts by email
- Can you set password for accounts that used OAuth-only login?

### OAuth Account Linking Abuse (H100 Proven)

**Exploitation steps:**
1. Attacker initiates OAuth flow with victim's email
2. OAuth provider sends code to victim (if they have access)
3. OR: Attacker already has OAuth account linked to victim's email
4. Exchange code for token → link to attacker's primary account
5. Now attacker has victim's OAuth data on their account

### Password Reset Without User Interaction (H100 Proven)

**Exploitation steps:**
1. Find password reset endpoint that doesn't require email confirmation
2. Directly set new password via API
3. Account takeover without any user interaction

## Output Fields

Add to FINDINGs:

```
guard_gap: <the missing guard — show parallel function that has it>
escalation_chain: <step-by-step role escalation path>
proof: <concrete call sequence / HTTP request achieving unauthorized access>
```


### From `hunt-skills/bountyforge/references/supervisor.md`

# Supervisor — Finding Triage & Vetting System

The supervisor is the quality gate between raw scanner output and a submitted report. Every finding must pass through this triage pipeline before being written up. The supervisor is NOT a human — it is the agent's own critical reasoning applied systematically.

---

## Triage Pipeline Overview

```
Raw Finding → Gate 0 (Reality) → Gate 1 (Impact) → Gate 2 (Dedup) → Gate 3 (Quality) → Report
                                ↓ FAIL            ↓ FAIL          ↓ FAIL
                             KILL / DEMOTE      KILL / DEMOTE   KILL / DEMOTE
                OPEN LEAD (trigger proven, impact untraced) → persisted as a lead
                object in leads.jsonl with missing preconditions; mutated one
                variable at a time and retested next pass; parked leads stay
                in the chain pool (tools/leads.py)
```

---

## The 5-Step Methodology Spine

All triage and evaluation flows strictly follow this 5-step sequence:

```
Program Policy ──► Scope ──► Security Boundary ──► Demonstrated Impact ──► Severity
```

1. **Program Policy:** What are the exact terms, rules, and eligibility thresholds stated in the program policy?
2. **Scope:** Is the exact asset, subdomain, endpoint, repo, or binary listed as in-scope?
3. **Security Boundary:** What specific authorization check, isolation barrier, or trust assumption is crossed?
4. **Demonstrated Impact:** What capability was *proven* through direct execution (never inferred or assumed)?
5. **Severity:** What is the calibrated severity level derived strictly from demonstrated impact + program policy?

---

## Red Team Adversarial Triage Engine

Before drafting a report, BountyForge must **attack its own finding**. Switch mindsets to a hostile platform triager trying to reject the submission.

Run the **10 Red Team Attack Questions**:

1. **Scope:** Is the exact asset/function in scope?
2. **Policy:** Is this vulnerability class explicitly excluded?
3. **Precondition:** What does the attacker actually need?
4. **Authentication:** What credential/authorization is supposed to exist?
5. **Path A:** What is the legitimate intended flow?
6. **Path B:** What unauthorized flow was demonstrated?
7. **Boundary:** What security boundary is crossed?
8. **Impact:** What concrete capability does the attacker gain?
9. **Alternative explanation:** What is the strongest reasonable triager rebuttal?
10. **Evidence:** What observation defeats that rebuttal?

> **THE RED TEAM RULE:**
> **If the finding cannot survive the strongest plausible triager objection, DO NOT promote it to a report.** Demote to an OPEN LEAD in `leads.jsonl`, mutate preconditions, or park it.

---

## Demonstrated vs. Inferred vs. Unproven Classification

To prevent report drift (e.g. inflating a "powerful guest execution primitive" into an "unproven sandbox host escape"), every claim in a finding MUST be categorized into an explicit verification status:

| Status Tag | Definition | Example |
|------------|------------|---------|
| **Demonstrated** | Verified directly via executed PoC with observable output | `ControllerService` accepts unauthenticated TCP connections; returns `uid=0` output |
| **Inferred** | Logically suggested by code structure or system architecture but not directly executed | User namespace isolation is active inside container based on `/proc/self/uid_map` |
| **Unproven** | Speculative impact requiring unexecuted exploits or unverified preconditions | User namespace permits host kernel escape; host compromise achieved |

### Drift Audit Matrix (Run Before Report Writing)

```markdown
| Claim | Status | Verification Evidence / Reason |
|-------|--------|---------------------------------|
| Target endpoint accepts unauthenticated requests | Demonstrated | TCP connect + h2c request succeed with zero headers |
| SDK credential isn't supplied | Demonstrated | No TOKEN/KEY header, `/proc/self/environ` clean |
| Execution context equals SDK capability | Demonstrated | Executed `id; uname -a` returning same UID/GID as SDK exec |
| User namespace gives root inside container | Demonstrated | `id` returns `uid=0(root)` inside guest namespace |
| User namespace permits host escape | Inferred / Unproven | No host-side execution demonstrated |
| Host compromise achieved | Unproven | No host-side read/write demonstrated |
| Critical severity claimed | Unproven | Severity MUST be calibrated to demonstrated primitive only |
```

---

## Scope & Engagement Gate

BountyForge supports three engagement modes depending on how the hunt is conducted:

| Engagement Mode | Context & Target | Scope Source | Primary Goal |
|-----------------|------------------|--------------|--------------|
| **Bug Bounty Platform (BBP / VDP)** | HackerOne, Bugcrowd, Intigriti, Immunefi | Program Policy Page & Rules | Policy compliance, platform triage pass, bounty reward |
| **Direct Vendor / Independent Research** | Security advisory, private disclosure, open-source | Vendor Security Policy / Security Boundary | Responsible disclosure, vendor security advisory, patch verification |
| **Internal Red Team / Pentest / Audit** | Corporate network, codebase audit, internal target | Rules of Engagement / Audit Scope | System hardening, risk assessment, executive report |

```markdown

## Scope & Engagement Gate

- **Engagement Context:** [BBP | VDP | Direct Vendor Disclosure | Internal Red Team / Pentest]
- **Target Asset:** [Exact domain, IP, repo, contract, or binary]
- **In Scope:** [Yes / N/A (Independent Research)]
- **Explicit Exclusions:** [Check program/vendor policy for excluded assets or classes; None if self-hosted/pentest]
- **Governing Rule / Policy:** [Quote program policy clause, security advisory terms, or Audit Rules of Engagement]
- **Impact & Boundary Threshold:** [Demonstrated security boundary crossed or business risk proven]
- **Evidence Supporting Eligibility:** [Concrete demonstrated observations proving impact]
```

### Scope & Policy Derivation Rules

1. **Platform Hunts (BBP / VDP):** Extract explicit policy terms. Verify asset is listed in-scope and vulnerability class is not excluded.
2. **Direct Vendor / Independent Research:** Verify target belongs to vendor infrastructure/software. Ensure research adheres to standard safe-harbor / vulnerability disclosure guidelines.
3. **Internal Pentest / Red Team:** Align finding to engagement Rules of Engagement (RoE) and technical risk impact.

---

## Defensive-Proof Wording & Anti-Triager Blueprint

Triagers look for reasons to reject. Eliminate their arguments before they type them:

### 1. Path A (Intended) vs Path B (Unintended) Framing

When reporting unauthenticated access to a daemon, API, or listener:
- **Path A (Authenticated / Intended Flow):** Show that the primary control plane *requires* authentication (API key, OAuth, Bearer token).
- **Path B (Unintended / Unauthorized Flow):** Show that the secondary / internal listener accepts equivalent operations *without* presenting any credential.
- **Boundary Crossed:** Contrast Path A and Path B to prove an unauthenticated bypass of the intended control plane authorization barrier.

### 2. Absent Credential Evidence Grid (Mandatory for Unauth Findings)

Every unauthenticated vulnerability report MUST include an explicit evidence table:

```markdown
| Credential / Artifact | Present in Attack Request? | Verification Evidence |
|-----------------------|---------------------------|-----------------------|
| Authorization Header  | ❌ No | HEADERS frame contains only standard HTTP pseudo-headers |
| Bearer / API Token    | ❌ No | `/proc/self/environ` contains no TOKEN/KEY/SECRET variables |
| Session Cookie        | ❌ No | No Cookie header; cookie jar empty |
| Session File          | ❌ No | No token files in local filesystem or shared run directories |
| mTLS Certificate      | ❌ No | Connection opened over standard unauthenticated cleartext TCP / TLS |
| Capability Token      | ❌ No | No capability payload or signed request headers |
```

### 3. Overclaim Prevention Table

| Overclaimed Title (Triggers Triager Rejection) | Bulletproof Defensive Title (Triager Accepts) |
|-----------------------------------------------|-----------------------------------------------|
| "Host Escape / Container Breakout in Sandbox" | "Unauthenticated `ControllerService` Listener Exposes Command Execution to Guest Workload Processes" |
| "Full Account Takeover via API" | "IDOR in `/api/v2/users/{id}/email` Allows Authenticated User to Modify Secondary Account Email" |
| "Remote Code Execution via File Upload" | "Arbitrary File Upload to Web-Accessible Directory Enables Script Execution in Web Server Context" |
| "Authentication Bypass in OAuth Flow" | "Missing `state` Validation in `/oauth2callback` Enables Cross-Site Request Forgery (Login CSRF)" |

---

## Gate 0: Reality Check (30 seconds)

The finding must be REAL — confirmed with actual HTTP requests or code execution, not speculation from reading code.

### Required Evidence (at least ONE must be present)

| Evidence Type | What Counts | What Doesn't |
|--------------|-------------|--------------|
| HTTP response | Full request + response with status code and body | "The server would probably..." |
| Screenshot | Shows actual impact (changed data, exposed PII) | Screenshot of a form field existing |
| Code trace | Exact line numbers showing unguarded path | "This pattern is dangerous in general" |
| Reproduction | Same result from 2+ different starting states | "It worked once but I can't reproduce" |

### Fail Conditions (KILL immediately)
- "I read the code and it looks like..." — no live confirmation
- "This type of endpoint is often vulnerable to..." — pattern matching without testing
- "The response was different so there might be..." — ambiguous signal
- Only tested with your own data (IDOR needs cross-account proof)
- Tested on a dev/staging environment not in scope

### Demote Conditions
- Finding is real but only on a non-production environment explicitly out of scope → DEMOTE to note, do not report
- Finding requires a specific browser/OS version → note the constraint

---

### The Impact Litmus Test

Answer this question with a single concrete sentence:

> "An attacker can __________, resulting in __________."

The first blank must be a specific action. The second must be a specific harm.

**PASSES:**
- "An attacker can read any user's booking confirmation emails, resulting in exposure of full traveler PII including passport numbers."
- "An attacker can redeem the same gift card 50 times concurrently, resulting in $5,000 theft from a $100 card."
- "An attacker can write arbitrary telemetry to the production Azure App Insights instance, resulting in false SOC alerts and masked real attacks."

**FAILS (kill immediately):**
- "An attacker can potentially access data" — what data? whose?
- "An attacker could theoretically..." — theoretically is not a finding
- "This could be used in a chain" — build the chain first, then report
- "This is a security misconfiguration" — describe the actual harm, not the category
- "This violates best practice" — best practice violations without exploit impact are not bugs

### Trigger vs Impact — the two-halves rule (read before ANY kill)

The Impact Litmus Test answers ONE half of every lead. A kill is legal only
after BOTH halves are resolved:

- **Q-TRIGGER** — "Can the path fire?" If refuted (unreachable, trusted-actor-only with no bypass) → KILL.
- **Q-IMPACT** — "If it fires, what does the VICTIM lose?" If untraced → **DEMOTE to OPEN LEAD**, not KILL. The lead becomes a persistent research object (`tools/leads.py`): decompose the block into named missing preconditions, mutate one variable at a time until impact is provable, and keep the payload. If it still cannot prove impact, PARK it into the chain pool — never drop it. A kill without BOTH refutations is refused by the ledger and auto-parks instead.

**Conflation is the failure mode.** Answering "can it fire?" and moving on
because the impact "seems below the bar" is the mistake this gate exists to
prevent. And impact is victim-harm, not attacker-profit: "this doesn't make an
attacker money" refutes nothing — an accounting desync that strands or
misdirects account value is account-owner loss, a Medium floor on Immunefi on
its own. Whether it chains into attacker profit is a separate trace, never a
precondition for keeping the lead alive. Severity estimation never precedes
the impact trace.

### Impact Tiers

| Tier | Impact | Examples | Severity Floor |
|------|--------|----------|----------------|
| T0 | Critical | RCE, auth bypass → admin, cloud credential theft, fund drain | Critical (9.0+) |
| T1 | High | PII/PHI exposure, ATO, financial manipulation, data destruction | High (7.0+) |
| T2 | Medium | Non-sensitive data exposure, limited IDOR (read-only, non-PII), stored XSS on low-value page | Medium (4.0+) |
| T3 | Low | Info disclosure (non-sensitive), missing security headers, clickjacking on static page | Low (0.1+) |
| T4 | None | CSP report-only, banner version without exploit, self-XSS, logout CSRF | Informational (0.0) — DO NOT REPORT |

### Common Impact Inflation (reject these)

| Claim | Reality |
|-------|---------|
| "Session hijacking" via XSS | Is HttpOnly set? If yes, you can't steal the session cookie. |
| "Account takeover" via open redirect | Do you have a full OAuth chain? If not, it's just an open redirect. |
| "Data breach" via API exposing counts | A count is not a breach. You need actual PII/credentials. |
| "RCE" via file upload | Did you actually execute code on the server? Or just upload a .php file to a static CDN? |
| "Denial of service" via one slow request | Can you actually take the service offline? If the request just times out, that's not DoS. |

---

# HackerOne Hacktivity
curl -s "https://hackerone.com/hacktivity?querystring=PROGRAM_NAME+BUG_CLASS"

### Step 2: Check These Sources

- [ ] HackerOne Hacktivity for this program (last 90 days)
- [ ] Bugcrowd Crowdstream for this program
- [ ] Program's public changelog / release notes
- [ ] GitHub Issues for the target repo (search: "security", "vuln", bug class name)
- [ ] The program's "known issues" or "out of scope" page
- [ ] Google: `site:target.com "security" "fixed"`

### Step 3: Duplicate Decision

| Situation | Action |
|-----------|--------|
| Same endpoint, same bug class, same impact → exact duplicate | KILL |
| Same endpoint, different bug class → not a duplicate | CONTINUE |
| Different endpoint, same bug class and root cause | Group into ONE report mentioning all affected endpoints |
| Same bug but your impact is significantly higher | REPORT with escalation language |

---

### Title Quality

The title must contain: **vuln class + location + attacker role + impact + victim scope**.

```
FORMAT: [Bug Class] in [Exact Endpoint] allows [attacker] to [action] [victim]
GOOD:   IDOR in /api/v2/bookings/{id} allows any authenticated user to read any traveler's passport data
BAD:    IDOR vulnerability found
BAD:    Possible authorization issue in booking API
```

### PoC Quality

The PoC must be:
1. **Copy-pasteable** — the triager can run your curl command and see the same result
2. **Self-contained** — no "set up a VPS first" or "install this toolchain"
3. **Minimal** — the shortest sequence that demonstrates the impact
4. **Reproducible** — works every time, not just once

### Evidence Quality

- Screenshots must show the impact, not just the request
- For IDOR: show victim's data accessed from attacker's session
- For XSS: show the alert popup OR DOM manipulation result
- For SSRF: show the callback received OR metadata response
- For race conditions: show both successful responses

### Impact Statement Quality

Must answer ALL of:
1. What can the attacker do? (specific action)
2. To whom? (identifiable victim — user, company, system)
3. What's the worst case? (quantify: $ amount, number of users, type of data)
4. What does the attacker need? (nothing, free account, paid account, admin approval)
5. Is it detectable? (audit log? alert? or silent?)

---

### Pattern 1: Missing Auth Header Returns Different Status
```
GET /api/admin/users → 401 (expected: auth required)
GET /api/admin/users -H "Authorization: Bearer USER_TOKEN" → 200 (expected: user list)
```
If 401 without token, auth IS working. The lack of 403 for user token might be a finding, but 401 without token is correct behavior.

### Pattern 2: Parameter Reflection Without Execution
```
GET /search?q=<script>alert(1)</script> → Response contains: <script>alert(1)</script>
```
Reflection alone is not XSS. Is it reflected in HTML context without encoding? In a JSON string? In a header? Context matters.

### Pattern 3: CORS Reflects Origin Without Credentials
```
Origin: https://evil.com → Access-Control-Allow-Origin: https://evil.com
```
If `Access-Control-Allow-Credentials: true` is NOT present, this is not exploitable for credentialed data theft.

### Pattern 4: CSP Report-Only
A `content-security-policy-report-only` header DOES NOT block anything. It only reports violations. This is not a finding unless the report-uri is attacker-controllable.

### Pattern 5: Rate Limiting "Bypass" That Doesn't Scale
If you need 100 different IP addresses to bypass rate limiting, and the harm requires 10,000 requests... that's not a practical attack.

---

## Severity Escalation Pattern

When a triager pushes back with a lower severity, use these counter-arguments:

| Triager Says | You Respond |
|-------------|-------------|
| "This requires authentication" | "Authentication requires only a free account — no special role, no approval, no payment. The program's threat model includes malicious authenticated users." |
| "The impact is limited to one user" | "The attack is repeatable against ALL users. An attacker can enumerate every user ID and exfiltrate all PII. This is not one victim — it's the entire user base." |
| "This is by design" | "Please point me to the documentation that states users should be able to access other users' private data. If this is intended, it's not documented." |
| "The CVSS score is lower" | "CVSS doesn't capture business context. This endpoint exposes passport numbers — regulatory fines for PII exposure exceed $X. The business impact is higher than the technical score." |
| "We already know about this" | "Can you share the internal ticket ID or previous report number? I searched disclosed reports and found nothing." |
| "This is informational" | "I can demonstrate actual data exposure (see PoC). Informational findings don't have demonstrable impact — this does." |

---

## Triage Decision Tree (Quick Reference)

```
Finding received:
│
├─ Is it confirmed with a real HTTP request?
│  └─ NO → KILL
│
├─ Does it affect a real victim with real harm?
│  └─ NO → KILL
│
├─ Is the harm one of: money stolen, PII leaked, ATO, RCE, data destruction?
│  └─ NO → DEMOTE to informational or KILL
│
├─ Is the endpoint in scope?
│  └─ NO → KILL (or note as out-of-scope lead)
│
├─ Has this exact bug been reported before?
│  └─ YES → KILL (duplicate)
│
├─ Is this on the "always rejected" list?
│  └─ YES and no chain → KILL
│
├─ Can a triager reproduce this from my PoC in under 5 minutes?
│  └─ NO → Improve PoC before submitting
│
└─ All checks pass → WRITE REPORT
```

---

## Batch Triage Mode

When given a list of findings (from a scan, another tool, or manual testing), triage in this order:

1. **Group** — cluster by endpoint/feature. Same endpoint bugs go together.
2. **Sort** — highest impact first. T0 before T1 before T2.
3. **Dedup within batch** — if findings #3 and #7 are the same root cause, merge them.
4. **Gate each** — run each unique finding through all 4 gates.
5. **Output** — three lists: CONFIRMED (ready for report), LEADS (needs more testing), KILLED (dead ends).

### CONFIRMED (Ready for Report)
| # | Title | Severity | CVSS | Confidence |
|---|-------|----------|------|------------|
| 1 | IDOR in /api/bookings/{id} — read traveler PII | High | 7.5 | 90 |
| 2 | Race condition in /redeem — double-spend gift cards | Critical | 9.0 | 85 |

### LEADS (Needs More Testing)
| # | Description | What's Missing |
|---|-------------|----------------|
| 1 | /api/export returns 200 without auth cookie — possible unauth data export | Need to confirm what data is returned |
| 2 | GraphQL introspection enabled — field-level auth may be missing | Need to test node() queries across types |

### KILLED (Do Not Revisit)
| # | Description | Kill Reason |
|---|-------------|-------------|
| 1 | Missing CSP header | Always rejected — no exploit impact |
| 2 | Cloudflare blocks POST without cookie | Working as intended — WAF doing its job |
```

---

## Integration with SKILL.md

The main SKILL.md Phase 4 (Validate) references this supervisor. The 7-Question Gate is the quick version. This document is the detailed version. Use the 7-Question Gate for fast triage during hunting; use this full supervisor for findings you intend to report.


### From `hunt-skills/bountyforge/skills/pashov/solidity-auditor/references/hacking-agents/access-control-agent.md`

# Access Control Agent

You are an attacker that exploits permission models. Map the complete access control surface, then exploit every gap: unprotected functions, escalation chains, broken initialization, inconsistent guards.

Other agents cover known patterns, math, state consistency, and economics. You break the permission model.

## Attack plan

**Map the permission model.** Every role, modifier, and inline access check. Who grants what to whom. This map is your weapon — every attack below references it.

**Exploit inconsistent guards.** For every storage variable written by 2+ functions, find the one with the weakest guard. If function A requires `onlyOwner` but function B writes the same variable unguarded — use B. Check inherited functions, overrides, and `internal` helpers reachable from differently-guarded `external` functions.

**Hijack initialization.** Call `initialize()` on the implementation contract directly. Front-run deployment to initialize with your own roles. Pass `address(0)` as a role parameter to permanently lock out admins.

**Escalate privileges.** Find routes where role A grants role B to itself. Chain grant/revoke paths to reach `grantRole` without triggering guards. Find upgrade paths that bypass timelock. Trigger `renounceRole` to leave the system unrecoverable.

**Exploit confused deputies.** When contract A calls contract B with A's privileges, trigger that path to make A act on your behalf. Find contracts holding token approvals and exploit unguarded functions to spend them.

**Abuse delegatecall/proxy.** Collide storage layouts. Self-destruct implementation contracts. Collide admin slots with business logic storage.

## Output fields

Add to FINDINGs:
```
guard_gap: the guard that's missing — show the parallel function that has it
proof: concrete call sequence achieving unauthorized access
```


### From `hunt-skills/bountyforge/skills/smart-contract-audit/multi-expert.md`

**EXECUTION INSTRUCTION:** You must perform THREE SEPARATE ANALYSIS ROUNDS, adopting a completely different persona and approach for each expert. Do not blend their perspectives - maintain strict separation between each expert's analysis.

### ROUND 1: Security Expert 1 Analysis
**PERSONA:** Primary Smart Contract Auditor
**MINDSET:** Systematic, methodical, focused on core vulnerabilities

**ANALYSIS APPROACH:**
```markdown
1. SYSTEMATIC CODE REVIEW:
   - Start with highest-risk functions (payable, external calls, admin functions)
   - Map all fund flow paths and state changes
   - Analyze external dependencies and oracle integrations
   - Document findings with precise business impact context

2. VULNERABILITY PATTERN MATCHING:
   - Check for reentrancy vulnerabilities (all variants)
   - Validate access control mechanisms and permissions
   - Analyze arithmetic operations for precision/overflow issues
   - Review external call safety and return value handling
```

**OUTPUT REQUIREMENT:** Complete your full analysis as Expert 1, document all findings, then explicitly state: "--- END OF EXPERT 1 ANALYSIS ---"

### ROUND 2: Security Expert 2 Analysis  
**PERSONA:** Secondary Smart Contract Auditor
**MINDSET:** Fresh perspective, economic focus, integration specialist
**CRITICAL:** Do NOT reference or build upon Expert 1's findings. Approach as if you've never seen their analysis.

**ANALYSIS APPROACH:**
```markdown
1. INDEPENDENT PROTOCOL ANALYSIS:
   - Fresh review of all smart contract components
   - Different perspective on economic attack vectors
   - Alternative vulnerability assessment methodologies
   - Cross-validation of tokenomics and governance mechanisms

2. INTEGRATION SECURITY FOCUS:
   - Inter-contract communication security
   - External protocol integration risks
   - Composability and flash loan attack scenarios
   - Long-term protocol sustainability and upgrade risks
```

**OUTPUT REQUIREMENT:** Complete your independent analysis as Expert 2, then provide oversight analysis of Expert 1's findings and explicitly state: "--- END OF EXPERT 2 ANALYSIS ---"

**OVERSIGHT ANALYSIS RESPONSIBILITY:**
After completing your independent analysis, review Expert 1's findings and provide honest self-reflection:
- Do you disagree that it's a valid vulnerability? Explain your reasoning
- Did you miss it due to different analysis focus or methodology?
- Was it an oversight in your systematic review process?
- Would you have caught it with more time or different approach?

### ROUND 3: Triager Validation
**PERSONA:** Customer Validation Expert (Budget Protector)
**MINDSET:** Financially motivated skeptic who must protect the security budget
**APPROACH:** Actively challenge and attempt to disprove BOTH Expert 1 and Expert 2 findings


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-2-signer-checks/fv-anc-2-cl1-unvalidated-signers.md`

## TLDR

Declaring an account as `AccountInfo<'info>` rather than `Signer<'info>` in an Anchor context struct means the framework does not enforce that the account signed the transaction. Any public key can be passed as the authority without authorization.

## Detection Heuristics

**AccountInfo Used Where a Signer Is Required**
- Account declared as `pub authority: AccountInfo<'info>` in a context struct for an instruction that performs privileged operations
- Account used to authorize transfers, mutations, or admin actions but typed as `AccountInfo` instead of `Signer`

**No Supplemental is_signer Check**
- `AccountInfo` account used in a privileged path without a subsequent `require!(ctx.accounts.authority.is_signer, ...)` check in the instruction body
- `has_one` constraint on a vault pointing to an `AccountInfo` authority without signer enforcement

**Signer Constraint Missing on PDA-Signed Paths**
- Instruction accepts a user-provided authority for a PDA operation but does not enforce signing from that authority before deriving or using the PDA

## False Positives

- `AccountInfo` is used for read-only informational accounts (e.g., sysvars, program IDs) where signing is not required
- Account is a PDA that cannot sign transactions; signer seeds are instead validated via `invoke_signed` or Anchor seeds constraint


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-2-signer-checks/fv-anc-2-cl2-no-is_signer-check.md`

## TLDR

When using raw `AccountInfo` or native Solana program patterns, the `is_signer` field on the account info must be explicitly checked. Omitting this check means an instruction accepts any account as an authority without verifying it signed the transaction.

## Detection Heuristics

**Key Comparison Without Signer Verification**
- Code that checks `authority.key != expected_key` or `authority.key() == expected_key` but never checks `authority.is_signer`
- Authorization based solely on account key equality, allowing a known-public-key account to be passed without a signature

**Missing is_signer Guard in Instruction Body**
- Instruction using raw `AccountInfo` for an authority account without `if !account.is_signer { return Err(...) }`
- `require!(account.is_signer, ...)` absent from all code paths that perform privileged operations

**AccountInfo in Context Struct Without Signer Wrapper**
- Multiple `AccountInfo` accounts in a context struct where at least one is treated as an authorizing party in the instruction body, but none have `is_signer` verified

## False Positives

- Account is a PDA controlled by the program; PDAs cannot be signers and authorization is instead proven through seed derivation
- Account is a read-only system account or sysvar where signing is not meaningful


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-4-pda-security/fv-anc-4-cl1-using-create_program_address.md`

## TLDR

`Pubkey::create_program_address` requires a caller-supplied bump seed and does not find the canonical bump. An attacker can supply a non-canonical bump that produces a valid but unintended PDA, bypassing seed-based access controls or creating collisions with legitimate PDAs.

## Detection Heuristics

**create_program_address Without Canonical Bump Verification**
- `Pubkey::create_program_address(&[seed, &[bump]], program_id)` where `bump` comes from instruction data or an account field without verifying it is the canonical bump returned by `find_program_address`
- No comparison of the derived PDA against `Pubkey::find_program_address` output to confirm canonicity

**Bump Stored Without Derivation Check**
- Bump value stored in an account during initialization without verifying it was obtained from `find_program_address`
- Instruction accepts a `bump: u8` parameter and uses it directly in `create_program_address` without on-chain verification

**Missing seeds Constraint in Anchor**
- PDA account declared in a context struct without `#[account(seeds = [...], bump)]`, which would have Anchor enforce canonical bump derivation

## False Positives

- Bump is stored in the PDA account itself during `init` using Anchor's `bump` constraint, and subsequent instructions read it with `#[account(seeds = [...], bump = account.bump)]`, which enforces the canonical value
- `find_program_address` is called in the same instruction and the result is immediately compared, making the use of `create_program_address` equivalent


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-5-cross-program-invocation-cpi/fv-anc-5-cl2-cpi-without-signer-seeds.md`

## TLDR

When a CPI requires a PDA to sign on behalf of the program, `invoke_signed` must be called with the correct signer seeds. Using `invoke` or passing empty seeds to `invoke_signed` causes the CPI to fail or to execute without the PDA's authority, breaking the intended access control.

## Detection Heuristics

**invoke Used Where PDA Signature Is Required**
- `invoke(&instruction, &accounts)?` called when one of the accounts listed is a PDA that needs to sign; the PDA will not be recognized as a signer by the callee
- CPI to the Token Program for a PDA-owned token account using `invoke` instead of `invoke_signed`

**invoke_signed With Empty Seeds**
- `invoke_signed(&instruction, &accounts, &[])` where one of the accounts is a PDA, providing no signing authority
- Seeds array passed to `invoke_signed` does not include the seeds for all PDAs that must sign

**Incorrect or Incomplete Seeds**
- Signer seeds passed to `invoke_signed` do not match the seeds used to derive the PDA, causing signature verification to fail at the callee
- Bump seed omitted from the signer seeds array

## False Positives

- CPI is initiated on behalf of a user who signed the transaction; the user's `AccountInfo` carries `is_signer = true` and no PDA signature is needed
- `invoke` is correct when none of the accounts in the CPI need to be PDAs signing on behalf of the program


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-5-cross-program-invocation-cpi/fv-anc-5-cl7-invoke-signed-with-wrong-or-partial-seeds.md`

## TLDR

If the seeds array passed to `invoke_signed` does not exactly match the seeds used to derive the PDA that is expected to sign, the call will fail or sign under the wrong identity. More critically, when multiple seed combinations can resolve to valid program addresses, using an incorrect subset can authorize operations under an unintended signer identity, bypassing intended access controls.

## Detection Heuristics

**Seeds Mismatch Between Derivation and Signing**
- Seeds list in `invoke_signed` call differs from seeds used in the corresponding `Pubkey::find_program_address` or `Pubkey::create_program_address` call
- `bump` seed omitted from the `invoke_signed` seeds while the PDA derivation included it, or vice versa
- Seed values sourced from user-supplied accounts without validation used in the signing call

**Incomplete Seed Validation**
- Program dynamically constructs the seeds array at runtime from account fields without asserting the resulting address matches the expected PDA key
- Seeds array passed as a slice reference where individual seed byte arrays come from attacker-controlled instruction data
- No `Pubkey::create_program_address(seeds, program_id) == expected_pda` assertion before the invoke_signed call

**Shared Seed Prefix Ambiguity**
- Multiple PDA types share a seed prefix, and the wrong type can be used as a signer because the seeds are checked by inclusion not exact match
- Bump stored in an account field can be manipulated to produce a different valid PDA address

## False Positives

- Seeds are compile-time constant byte slices that are identical in both derivation and signing call sites; compiler ensures they cannot diverge
- Program verifies the derived address from seeds matches the account key before using it in invoke_signed


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-5-cross-program-invocation-cpi/fv-anc-5-cl9-cpi-privilege-escalation-via-account-authority.md`

## TLDR

When accounts passed into a CPI carry `is_writable` or `is_signer` flags that originated from the outer transaction context, an attacker can escalate privileges inside the CPI by crafting the outer transaction's account flags. Anchor's `CpiContext` does not automatically strip or re-derive account privilege flags; the program must construct them from protocol logic rather than forwarding them from the incoming accounts.

## Detection Heuristics

**Raw AccountInfo Forwarded to CPI**
- `account.to_account_info()` called directly on an incoming account and the result passed to a CPI without explicitly setting `is_signer: false` or `is_writable: false` where those privileges should not be forwarded
- `CpiContext::new` constructed from accounts list built by iterating `ctx.remaining_accounts` and passing each entry through without flag validation
- Program does not verify that an account's `is_signer` flag in the incoming transaction context corresponds to an expected signer key before relying on it inside a CPI

**Authority Account Not Key-Validated**
- Account is accepted as an authority in the CPI accounts list without comparing its key against a stored expected authority address
- Writable flag forwarded to an account that should only be read during the inner CPI, allowing the CPI target to modify it

**Elevated CPI Privilege Without Explicit Grant**
- Inner CPI receives signer authority over accounts not owned by the calling program, derived from outer transaction signer flags the calling program did not explicitly grant
- `invoke` (not `invoke_signed`) called with accounts carrying signer flags set to true from the outer transaction, propagating caller-level authority into the CPI

## False Positives

- Anchor typed CPI helpers (e.g., `token::transfer`, `system_program::create_account`) construct the account list with explicit flag values and do not forward raw AccountInfo flags from the context
- Program explicitly reconstructs each account's `AccountMeta` with hardcoded `is_signer` and `is_writable` values appropriate to the inner CPI's expected interface


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/move/fv-mov-2-access-control/readme.md`

# FV-MOV-2: Access Control and Capabilities

Sui Move uses the capability object pattern as its primary access control mechanism. This category covers missing capability checks, incorrect visibility modifiers, phantom type bypass, and sender address spoofing.

## Cases

- [fv-mov-2-cl1-missing-capability-check.md](fv-mov-2-cl1-missing-capability-check.md) - Privileged function callable without a capability object
- [fv-mov-2-cl2-capability-lifecycle.md](fv-mov-2-cl2-capability-lifecycle.md) - Capability created outside `init` or OTW pattern missing
- [fv-mov-2-cl3-entry-visibility-bypass.md](fv-mov-2-cl3-entry-visibility-bypass.md) - `public(package) entry` overrides package-only restriction
- [fv-mov-2-cl4-sender-spoofing.md](fv-mov-2-cl4-sender-spoofing.md) - Caller address accepted as parameter instead of from TxContext


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/solidity/fv-sol-4-bad-access-control/fv-sol-4-c1-using-tx.origin-for-authorization.md`

## TLDR

`tx.origin` always resolves to the original EOA that initiated the transaction, regardless of how many contracts the call passed through. A malicious contract invoked by a privileged user can exploit this to impersonate that user in any contract that relies on `tx.origin` for access control.

## Detection Heuristics

**tx.origin Used as Access Guard**
- `require(tx.origin == admin)` or `require(tx.origin == owner)` as the sole authorization check
- `if (tx.origin != trustedAddress) revert` pattern in state-changing functions
- `tx.origin` compared against any stored address to gate privileged operations

**Combination Patterns That Still Fail**
- `tx.origin` used as a fallback when `msg.sender` check fails - still exploitable via phishing
- `tx.origin` used to set an owner or beneficiary address during initialization, then later compared for authorization

## False Positives

- `msg.sender` is used instead of `tx.origin` for the authorization check
- `tx.origin` appears only in event emissions or logging, not in require/revert guards
- `tx.origin == msg.sender` used to assert caller is an EOA with no downstream privileged action gated solely on that check


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/solidity/fv-sol-4-bad-access-control/fv-sol-4-c5-callback-authorization-bypass.md`

## TLDR

External callback functions (`onFlashLoan`, `onERC721Received`, `onERC1155Received`) are invoked by third-party contracts. If the callback does not verify `msg.sender` is the expected caller, anyone can invoke it directly with fabricated parameters, bypassing intended access control. ERC4626 `withdraw`/`redeem` has a related variant: when `msg.sender != owner`, allowance must be checked and decremented or any address can burn an arbitrary owner's shares.

## Detection Heuristics

**Flash Loan Callback**
- `onFlashLoan` does not verify `msg.sender == address(lendingPool)`
- Initiator, token, or amount parameters unchecked - callable directly without a real flash loan
- State changes or fund transfers triggered solely by caller-supplied parameters

**ERC721 onERC721Received Spoofing**
- `onERC721Received` uses `from` or `tokenId` to update state without checking `msg.sender == address(expectedNFT)`
- Any caller can invoke directly with fabricated parameters to trigger unintended state changes

**ERC1155 Burn Without Authorization**
- Public `burn(address from, ...)` callable by anyone without `msg.sender == from` or operator approval check
- Any caller can burn another user's tokens

**ERC4626 Missing Allowance Check**
- `withdraw(assets, receiver, owner)` or `redeem(shares, receiver, owner)` where `msg.sender != owner` but no `_spendAllowance` call present

**ERC1155 setApprovalForAll Over-Permission**
- Protocol requires `setApprovalForAll(protocol, true)` for deposits - operator can transfer any token ID at full balance, not just the deposited amount

## False Positives

- `require(msg.sender == address(lendingPool))` and `initiator == address(this)` both validated in flash loan callback
- `require(msg.sender == address(nft))` present before state update in `onERC721Received`
- `require(from == msg.sender || isApprovedForAll(from, msg.sender))` in custom burn
- OZ `ERC4626` used without custom overrides (allowance check is built in)
- Protocol uses direct `safeTransferFrom` with user as `msg.sender` (no `setApprovalForAll` needed)


### From `hunt-skills/bountyforge/skills/smart-contract-audit/reference/ton/fv-ton-2-access-control/fv-ton-2-cl3-admin-authorization.md`

## TLDR

Administrative operations (parameter updates, fund withdrawals, pausing, upgrading) that lack a sender address check against the stored admin/owner address allow any contract or wallet to invoke privileged functions.

## Detection Heuristics

**Missing sender validation on privileged opcodes**
- Handler for ops like `op::change_admin`, `op::withdraw`, `op::upgrade`, `op::set_params` has no `throw_unless(error::not_owner, equal_slices(sender_address, admin_address))`
- `admin_address` loaded from storage but the comparison is skipped or commented out
- Authorization check present only on some admin ops but not all - inconsistent coverage

**No admin transfer mechanism or insecure one**
- No `op::change_admin` or `op::transfer_ownership` handler - admin key loss permanently locks privileged functions
- Admin address change in a single step with no pending/confirm pattern - sending to a wrong address is irreversible
- Admin address stored in code cell (c3) instead of data cell (c4), requiring a full code upgrade to change it

**Tact contracts**
- Tact contract uses `Ownable` trait but one or more `receive()` handlers for administrative messages do not call `self.requireOwner()` before executing

## False Positives

- Contract is intentionally permissionless for the audited operation; confirm this is by design and there is no way to escalate to fund extraction
- Admin check implemented via a helper function - verify the helper performs `equal_slices(sender_address, admin_address)` and throws on mismatch


### From `hunt-skills/bountyforge/skills/web3/web3-case-study-role-misconfig/SKILL.md`

# CASE STUDY: ROLE MISCONFIGURATION IN A YIELD AGGREGATOR

Bug Class: Access Control | Severity: Critical/Medium | Payout Range: $10K–$50K

See also: [[Web3 Audit]], [[Web3 Bug Classes]], [[Methodology]], [[Trust Map]], [[A→B Chains]]

---

## TARGET PROFILE (Anonymized)

| Field | Value |
|-------|-------|
| Protocol Type | Yield aggregator — stablecoin → lending protocol → harvest → DEX → reward token |
| Max Bounty | $50K (Critical) |
| TVL | Low (fresh program, under $100K) |
| Core Contracts | Vault.sol, RewardsDistributor.sol |
| Program Age | ~5 days when hunted (fresh = low competition) |
| Prior Audits | Firm A (16 findings, all Risk Accepted) + Firm B (18 findings, all Risk Accepted) |

**Scorecard:** Max bounty (+2) + custom math (+1) + recent code (+1) + known prior audits (+1) + public source (+1) + program new (+2) = **8/10 → HUNT**

**Why this scores high:** Fresh program on a live bounty platform + prior audits that accepted all risk = team is aware of issues but hasn't patched them. Hunt for what auditors missed or flagged but accepted.

---

## ARCHITECTURE + FUND FLOW

```
User deposits Stablecoin
    ↓ deposit(uint256 amount)
Vault.sol stores:
  - deposits[user] += amount
  - totalDeposited += amount
  - depositTimestamp[user] = block.timestamp
    ↓ safeTransferFrom(user, address(this), amount)
    ↓ lendingProtocol.supply(stablecoin, amount, address(this), 0)
  Interest-bearing token accrues in Vault.sol balance
    ↓ (periodic) _performHarvest()
  aToken balance > totalDeposited + DUST_THRESHOLD
    ↓ lendingProtocol.withdraw(stablecoin, harvestAmount - 1, address(this))
    ↓ dex.exactInputSingle(stablecoin → rewardToken)
    ↓ RewardsDistributor.distribute(rewardToken, amount)
  RewardsDistributor tracks:
  - cumulativeRewardPerShare updates
  - users can call claimFor(user) to collect rewardToken

User withdraws:
    ↓ withdraw(uint256 amount)
  if block.timestamp < depositTimestamp[user] + LOCK_PERIOD:
    withdrawFee applies (e.g. 0.5%)
  lendingProtocol.withdraw(stablecoin, amount, user)
```

**Key state variables:**
- `deposits[user]` — user principal (stablecoin)
- `totalDeposited` — sum of all principals
- `depositTimestamp[user]` — last deposit time (affects withdrawal fee)
- `cumulativeRewardPerShare` — reward index in RewardsDistributor
- `lastClaimedReward[user]` — user's last reward index

---

### Firm A Findings (16 total, all Risk Accepted)
All standard: missing events, gas optimizations, reentrancy guards present (CEI followed), centralization risks (owner can pause), single oracle (DEX swap is operational, not security-critical).

### Firm B Findings (18 total, all Risk Accepted)
Including:
- HAL-01: withdrawFee can be changed by owner (centralization)
- HAL-05: deposit() resets depositTimestamp even on partial top-ups → **extends lock period for existing deposits**
- HAL-08: Missing check for DISTRIBUTOR_ROLE being set *(flagged but did NOT verify it was never granted)*
- Various gas and event issues

**Pattern:** Firm B flagged "missing check" but didn't verify the role was actually ungranted. This is the gap to exploit.

---

### 1. Accounting Desync — 2 FINDINGS

**Finding 1: The `-1` Stranding Pattern**
```solidity
// In _performHarvest():
harvestAmount = aToken.balanceOf(address(this)) - totalDeposited - 1; // strands 1 wei
```
The hardcoded `-1` strands 1 wei of stablecoin per harvest permanently. Over thousands of harvests, this accumulates. Severity: LOW/INFORMATIONAL (no user loss, just protocol dust accumulation).

**Finding 2: Dust Harvest DoS** ← VALID MEDIUM
```
Scenario: Accumulated harvest amount is very tiny (< DEX minimum swap)
1. harvest() calls dex.exactInputSingle(stablecoin → rewardToken)
2. DEX returns 0 (amount too small to produce any output)
3. RewardsDistributor.distribute(0) is called
4. If distribute() reverts on 0 amount → harvest is permanently frozen
5. Users can still withdraw principal but all future yield is lost

Verification: Check if distribute(0) reverts. Check DEX minimum swap threshold.
```

### 2. Access Control — 1 FINDING (CRITICAL/HIGH)
**Finding: DISTRIBUTOR_ROLE Never Granted** ← MAIN FINDING

```solidity
// RewardsDistributor.sol
bytes32 public constant DISTRIBUTOR_ROLE = keccak256("DISTRIBUTOR_ROLE");

function claimFor(address user) external {
    require(hasRole(DISTRIBUTOR_ROLE, msg.sender), "Not distributor");
    // ... distribute rewardToken to user
}
```

**Problem:** `DISTRIBUTOR_ROLE` is defined but NEVER granted in the constructor or any initialization function. No address holds this role. `claimFor()` can never succeed — all reward tokens are permanently locked.

**How Firm B missed it:** They flagged "missing check for whether role is set" — but their fix recommendation was "add a require that checks the role exists." They didn't verify that `getRoleMemberCount(DISTRIBUTOR_ROLE) == 0` on the live deployment.

**Severity Assessment:**
- If harvest HAS already happened: CRITICAL (funds locked forever)
- If harvest never happened yet: HIGH (permanent lock when it does happen)
- Impact × Likelihood × Exploitability: 3 × 3 × 3 = 27 → CRITICAL

**Verification commands:**
```bash

# Check if any address has DISTRIBUTOR_ROLE (replace with actual address)
cast call <REWARDS_DISTRIBUTOR_ADDR> \
  "getRoleMemberCount(bytes32)(uint256)" \
  "$(cast keccak 'DISTRIBUTOR_ROLE')"

### 3. Incomplete Path — Known (Risk Accepted)
Firm B HAL-05: `deposit()` resets `depositTimestamp[user]` even on partial top-ups, extending the lock period for all existing deposits. Risk Accepted by team.

### 5. Oracle Price — CLEAN
Protocol does NOT use price oracles for security decisions (no lending, no liquidation, no collateral). The DEX swap is operational (converting yield), not security-critical. MEV/sandwich risk exists but is a griefing/efficiency issue, not a theft vulnerability.

### 6. ERC4626 Vaults — NOT APPLICABLE
Uses a custom 1:1 share model, NOT ERC4626:
- `deposits[user]` tracks exact principal
- No share price, no share-based rounding
- Transfers between users are blocked
- First depositor inflation attack does NOT apply

### 7. Reentrancy — CLEAN
Follows CEI (Checks-Effects-Interactions) correctly:
- `deposits[user] += amount` BEFORE `lendingProtocol.supply()`
- `deposits[user] -= amount` BEFORE `lendingProtocol.withdraw()`
- Missing `nonReentrant` guard, but CEI makes it safe. Not submittable without PoC.

### 8. Flash Loan — CLEAN (Economically)
Flash loan attack would attempt: deposit → dilute harvest → withdraw to steal yield.
The `withdrawFee` makes this unprofitable:
- Attacker deposits $1M → harvest dilutes → attacker gains $0 extra yield
- But: attacker pays withdrawal fee to exit
- Net: negative expected value → NOT PROFITABLE

### SUBMIT (2 findings):

**Finding 1 — CRITICAL/HIGH:**
```
Title: DISTRIBUTOR_ROLE never granted in RewardsDistributor.sol,
       permanently locking all reward tokens

Root Cause: DISTRIBUTOR_ROLE is defined but grantRole() is never called
            in constructor or initialization. No address holds this role.

Impact: All rewards distributed by harvest() are permanently locked —
        claimFor() always reverts.
        Users receive zero yield despite depositing and paying withdrawFee.

Attack Path: Not an attack — passive failure. Any harvest → rewards locked forever.

Severity: Critical (if harvest has occurred) / High (if not yet)
```

**Finding 2 — MEDIUM:**
```
Title: _performHarvest() dust harvest causes permanent DoS on yield distribution

Root Cause: When accumulated yield rounds to < DEX minimum swap amount,
            exactInputSingle() returns 0 output. distribute(0) may revert or
            permanently advance the reward index with no rewards.

Impact: After a dust harvest, all subsequent harvests may fail permanently.

Severity: Medium (requires specific conditions but permanently impacts yield)
```

### DO NOT SUBMIT:
- The `-1` stranding (informational, design choice)
- depositTimestamp reset (Risk Accepted by team)
- Missing nonReentrant (CEI is followed; no PoC = no submission)
- Owner centralization (excluded by design in Immunefi SC programs)
- Any of the already-acknowledged findings from prior audits

---

## COMPLETE POC TEMPLATE: ROLE NEVER GRANTED

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import "forge-std/Test.sol";
import "forge-std/console.sol";

interface IRewardsDistributor {
    function DISTRIBUTOR_ROLE() external view returns (bytes32);
    function hasRole(bytes32 role, address account) external view returns (bool);
    function getRoleMemberCount(bytes32 role) external view returns (uint256);
    function claimFor(address user) external;
}

contract RoleNeverGrantedTest is Test {
    // Replace with actual deployed address from target
    address constant REWARDS_DISTRIBUTOR = address(0xYOUR_TARGET_ADDRESS);

    IRewardsDistributor distributor;

    function setUp() public {
        // Fork at current block
        vm.createSelectFork(vm.envString("MAINNET_RPC_URL"));
        distributor = IRewardsDistributor(REWARDS_DISTRIBUTOR);
    }

    function testDistributorRoleNeverGranted() public {
        bytes32 DISTRIBUTOR_ROLE = distributor.DISTRIBUTOR_ROLE();

        uint256 memberCount = distributor.getRoleMemberCount(DISTRIBUTOR_ROLE);
        console.log("Addresses with DISTRIBUTOR_ROLE:", memberCount);

        // Should be 0 — proving no one can call claimFor()
        assertEq(memberCount, 0, "DISTRIBUTOR_ROLE has 0 members (confirmed bug)");

        // Verify claimFor() reverts for any user
        address testUser = address(0x1234);
        vm.expectRevert(); // "AccessControl: account does not have role"
        distributor.claimFor(testUser);

        console.log("CONFIRMED: claimFor() reverts for all users.");
        console.log("All rewards permanently locked.");
    }
}
```

**Run:**
```bash
forge test --match-test testDistributorRoleNeverGranted -vvvv \
  --fork-url $MAINNET_RPC_URL
```

**Expected output:**
```
Addresses with DISTRIBUTOR_ROLE: 0
CONFIRMED: claimFor() reverts for all users.
All rewards permanently locked.

[PASS] testDistributorRoleNeverGranted()
```

---

## REPORT TEMPLATE

**Title:** Missing DISTRIBUTOR_ROLE grant permanently locks all rewards for all users

**Bug Description:**
`RewardsDistributor.sol` defines `DISTRIBUTOR_ROLE` and requires it to call `claimFor()`. However, `grantRole(DISTRIBUTOR_ROLE, ...)` is never called in the constructor, any initialization function, or any privileged setter. No address holds this role. `claimFor()` always reverts.

The Vault contract calls `RewardsDistributor.distribute()` after each harvest, successfully depositing reward tokens into the distributor. However, these tokens can never be claimed — permanently locked.

**Root Cause:** Constructor is missing `grantRole(DISTRIBUTOR_ROLE, vaultContract)`.

**Impact:** All yield earned by all depositors is permanently locked in RewardsDistributor.sol. Users cannot receive any return from their deposits.

*Impact category:* **Permanent freezing of funds**

**Proof of Concept:** [Run PoC above against deployed contract]

**Remediation:** Add `grantRole(DISTRIBUTOR_ROLE, address(vault))` in RewardsDistributor constructor, OR add a `setDistributor(address)` function callable only by admin.

---

## VALIDATION CHECKLIST (7-Question Gate)

| Question | DISTRIBUTOR_ROLE | Dust Harvest DoS |
|----------|-----------------|-----------------|
| Can attacker use it NOW? | Yes (passive — already locked) | Yes (needs small harvest) |
| Impact in program's list? | Permanent freezing of funds ✓ | Temporary/permanent DoS ✓ |
| In-scope contract? | RewardsDistributor.sol ✓ | Vault.sol ✓ |
| Requires admin access? | No — passive ✓ | No — anyone can trigger ✓ |
| Already known/acknowledged? | No ✓ | No ✓ |
| Economically viable? | Yes — passive lock ✓ | Yes — dust accumulates ✓ |
| Already public? | No ✓ | No ✓ |
| **VERDICT** | **SUBMIT** | **SUBMIT** |

---

## LESSONS: WHAT TO LOOK FOR ON SIMILAR TARGETS

This pattern (role defined, never granted) appears frequently in:

1. **Any contract using OpenZeppelin AccessControl** — check every `bytes32 public constant *_ROLE` — verify each one has a corresponding `grantRole()` call in constructor
2. **Distributor/reward contracts** — these are often deployed separately and the grant is "supposed to happen" during deployment setup
3. **Contracts with multiple initialization steps** — if setup requires calling multiple functions in sequence, the grant is often missed

**Grep to find candidates:**
```bash

# If roles > grantRole calls → investigate each missing grant
```

**Protocols to check for this pattern:** Any protocol where `RewardsDistributor`, `FeeDistributor`, `YieldDistributor`, or `Distributor` is a separate contract from the main vault.

---

→ NEXT: [08-ai-tools.md](08-ai-tools.md)
