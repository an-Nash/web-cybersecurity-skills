# MERGED SOURCE KNOWLEDGE: osint-recon

574 unique sections from 21 source files. Each section appears in exactly one target.


## SOURCE: hunt-skills/bountyforge/references/hacking-agents/recon-agent.md

# Recon Agent

You are an attacker performing passive and active reconnaissance on an external attack surface. You identify exposed assets, misconfigurations, leaked credentials, and dangling infrastructure.

This agent is used when the target is a live application or when a scope description (domains, IP ranges, GitHub org) is provided rather than source code.

### Subdomain Enumeration

When given a root domain:
- Enumerate subdomains via: certificate transparency logs (crt.sh), brute force (common wordlists), DNS zone transfer attempts.
- For each discovered subdomain, identify: IP, hosting provider, technology stack, response headers.
- Flag subdomains pointing to unclaimed cloud assets (S3, GitHub Pages, Heroku, Azure, Netlify, Fastly, Vercel) → subdomain takeover candidates.

### HTTP Surface Mapping

- Check all subdomains for: open redirect params, login pages, API v1/v2/v3 enumeration, admin paths (`/admin`, `/dashboard`, `/internal`, `/ops`).
- Spider JS bundles for: hardcoded API keys, internal URLs, commented-out endpoints, sensitive variable names.
- Check HTTP response headers: `Server`, `X-Powered-By`, `X-AspNet-Version` → technology fingerprinting.
- `/.well-known/`, `/robots.txt`, `/sitemap.xml` → path disclosure.

### Secrets & Credential Exposure

- GitHub org: search for hardcoded secrets in public repos (`*.env`, `config.js`, `secrets.yaml`).
- Wayback Machine / CommonCrawl: historical snapshots may contain API keys or tokens since rotated.
- npm/PyPI packages published by the org: check for accidental secret inclusion in package tarballs.
- Error messages in responses: stack traces, DB connection strings, internal IP addresses.

### API & GraphQL Surface

- Check for GraphQL introspection: `POST /graphql` with `{"query":"{__schema{types{name}}}"}`.
- REST API versioning: if v2 is in scope, check if v1 still responds (often less hardened).
- Swagger/OpenAPI exposure: `/api-docs`, `/swagger.json`, `/openapi.json`.
- Mass assignment candidates: send extra JSON fields (`role`, `admin`, `is_verified`) in POST/PUT requests.

### Cloud & Infrastructure

- S3 bucket enumeration: `<company>.s3.amazonaws.com`, `s3.amazonaws.com/<company>`. Test read/write access.
- GCS bucket: `storage.googleapis.com/<bucket>`.
- Azure blob: `<account>.blob.core.windows.net/<container>`.
- Elasticsearch/Kibana: port 9200, 5601 on discovered IPs. Check for unauthenticated access.
- Jenkins/Gitlab/Jira on subdomains: default credentials, CVE checks for exposed versions.

### Infrastructure Hunting (H100 Proven — $10-25K per finding)

Exposed infrastructure appeared 5 times in the top 100 reports.

**Exposed CI/CD:**
```bash

# Jenkins — often no auth required
curl -s "https://jenkins.target.com/api/json" | jq '.jobs[].name'
curl -s "https://jenkins.target.com/script"  # Script console = RCE

# Check for open build systems
for sub in jenkins ci build buildkite travis drone; do
  curl -s -o /dev/null -w "$sub: %{http_code}\n" "https://$sub.target.com/"
done
```

**Exposed Grafana:**
```bash
curl -s "https://grafana.target.com/api/search" | jq '.[].title'
curl -s "https://grafana.target.com/api/dashboards/db/home" | jq '.dashboard.panels[].targets'

# Dashboards often contain: DB queries, internal URLs, API keys, credentials
```

**Exposed Kubernetes API:**
```bash
curl -sk "https://target.com:6443/api/v1/namespaces"
curl -sk "https://target.com:6443/api/v1/pods"
curl -sk "https://target.com:6443/api/v1/secrets"

# If 200 → full cluster access, no auth needed
```

**Exposed Spring Actuators:**
```bash
curl -s "https://target.com/actuator/env" | jq '.propertySources[].properties | to_entries[] | select(.key | test("password|secret|key"))'
curl -s "https://target.com/actuator/heapdump" -o heapdump

# Analyze heapdump for secrets
```

**Exposed admin panels from leaked certificates:**
- Check git history for leaked VPN/SSH/TLS certificates
- Use certificates to access internal services (Phabricator, Confluence, Jira)
- Internal wikis often contain architecture docs, credentials, API keys

### Web3 / Blockchain Surface

- Contract source verification on Etherscan/Aptos Explorer/Solana Explorer — check if unverified (binary-only).
- Proxy contract admin: check if `proxyAdmin` is an EOA (single point of failure) vs multisig.
- Timelock: check timelock delay on upgrades — is it 0 or very short?
- Deployed contract vs audited commit: check if deployed bytecode matches the audited source hash.
- Event logs: historical events for role grants, emergency actions, pauses — pattern for admin key usage.

## Output Fields

Add to FINDINGs:

```
asset_type: subdomain | s3-bucket | api-endpoint | github-secret | contract | infrastructure
discovery_method: <how it was found>
evidence: <URL, response snippet, or log entry proving the exposure>
takeover_possible: true | false | unknown
```


## SOURCE: hunt-skills/bountyforge/references/recon-and-leaks.md

# Recon, Credential Leaks & Source Recon

> Split from SKILL.md v4.1.0. Load at hunt start for any external target. Pipeline counterpart: `skills/web2-recon/SKILL.md`.

---

## Technology Fingerprinting

| Signal | Technology |
|---|---|
| Cookie: `XSRF-TOKEN` + `*_session` | Laravel |
| Cookie: `PHPSESSID` | PHP |
| Header: `X-Powered-By: Express` | Node.js/Express |
| Response: `wp-json`/`wp-content` | WordPress |
| Response: `{"errors":[{"message":` | GraphQL |
| Cookie: `ARRAffinity` | Azure App Service |
| Header: `cf-ray` | Cloudflare |
| Header: `x-akamai-*` | Akamai |

## Quick Wins Checklist
- [ ] Subdomain takeover (`subjack`, `subzy`)
- [ ] Exposed `.git` (`/.git/config`)
- [ ] Exposed env files (`/.env`, `/.env.local`)
- [ ] Default credentials on admin panels
- [ ] JS secrets (SecretFinder, jsluice)
- [ ] Open redirects (`?redirect=`, `?next=`, `?url=`)
- [ ] CORS misconfig (test `Origin: https://evil.com` + credentials)
- [ ] S3/cloud buckets
- [ ] GraphQL introspection enabled
- [ ] Spring actuators (`/actuator/env`, `/actuator/heapdump`)
- [ ] Firebase open read (`/.json`)
- [ ] Hardcoded API keys in JS bundles
- [ ] Credentials in public Git repos (GitHub, GitLab, Bitbucket)
- [ ] Exposed CI/CD dashboards (Jenkins, CircleCI, Travis CI)

## Credential Leak Hunting (H100 Pattern — 7 reports, $50K+ total)

5 of the Top 100 reports involved leaked credentials in code repos or build artifacts.

### Token Types That Pay

| Token Type | How to Find | Impact |
|------------|-------------|--------|
| GitHub Personal Access Token | `grep -r "ghp_\|github_pat_" --include="*.env" --include="*.json"` | Read/write all org repos |
| npm token | `grep -r "npm_" --include="*.npmrc" --include="*.env"` | Publish to org's npm scope |
| AWS Access Key | `grep -r "AKIA" --include="*.env" --include="*.py" --include="*.js"` | Full AWS access |
| Slack webhook | `grep -r "hooks.slack.com" --include="*.env" --include="*.yml"` | Post to any channel |
| Stripe key | `grep -r "sk_live_\|pk_live_" --include="*.env" --include="*.js"` | Payment processing |
| Docker Hub token | `grep -r "dckr_pat_" --include="*.env"` | Container registry access |
| Google API key | `grep -r "AIza" --include="*.env" --include="*.js"` | Various GCP services |

# Search target's GitHub org for secrets
gh api -X GET "search/code?q=org:TARGET+filename:.env" --jq '.items[].repository.full_name'
gh api -X GET "search/code?q=org:TARGET+AKIA" --jq '.items[].html_url'

# Check for .env in compiled apps
asar extract app.asar /tmp/app
grep -r "TOKEN\|SECRET\|KEY\|PASSWORD" /tmp/app/
```

**Build logs:**
```bash

# Travis CI (Superhuman #496937 — $5K)
curl -s "https://api.travis-ci.org/repos/TARGET/REPO/builds" | jq '.[].config.raw_config'

# GitHub Actions logs
gh run list --repo TARGET/REPO --limit 5
gh run view RUN_ID --repo TARGET/REPO --log | grep -i "token\|secret\|key"
```

**Docker images:**
```bash

# Pull and inspect
docker pull TARGET/app:latest
docker run --rm -it TARGET/app:latest env
docker run --rm -it TARGET/app:latest cat /app/.env
```

# AWS key
aws sts get-caller-identity --access-key-id AKIAxxxx --secret-access-key xxxx

# Security surface
git log --oneline --all --grep="security\|CVE\|fix\|vuln" | head -20
grep -rn "TODO\|FIXME\|HACK\|UNSAFE" --include="*.ts" --include="*.js" | grep -iv "test"

# Dangerous patterns (JS/TS)
grep -rn "eval(\|innerHTML\|dangerouslySetInner\|execSync" --include="*.ts" --include="*.js" | grep -v node_modules
grep -rn "__proto__\|constructor\[" --include="*.js" --include="*.ts" | grep -v node_modules

# Python
grep -rn "pickle\.loads\|yaml\.load\|eval(" --include="*.py" | grep -v test
grep -rn "subprocess\|os\.system\|os\.popen" --include="*.py" | grep -v test

# PHP
grep -rn "unserialize\|eval(\|preg_replace.*e" --include="*.php"
grep -rn "\$_GET\|\$_POST\|\$_REQUEST" --include="*.php" | grep "include\|require\|file_get"

# Rust (network-facing only)
grep -rn "\.unwrap()\|\.expect(" --include="*.rs" | grep -v "test\|encode\|to_bytes\|serialize"
grep -rn "unsafe {" --include="*.rs" -B5 | grep "read\|recv\|parse\|decode"
```

---


## SOURCE: hunt-skills/bountyforge/skills/web2-recon/SKILL.md

# WEB2 RECON — Trust-First Asset Discovery

Map the attack surface before hunting. Every endpoint is a trust boundary. Find them all.

See also: [[BountyForge]], [[Trust Map]], [[Methodology]], [[Vuln Classes]], [[3rd Eye]]

---

# Mail.tm API (free, programmatic)
for i in 1 2 3; do
  DOMAIN=$(curl -s https://api.mail.tm/domains | jq -r '.[0].domain')
  EMAIL="hunter${i}_$(date +%s)@${DOMAIN}"
  PASSWORD="HuntPass${i}!"
  curl -s -X POST https://api.mail.tm/accounts \
    -H "Content-Type: application/json" \
    -d "{\"address\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" > /dev/null
  echo "Account $i: $EMAIL / $PASSWORD"
done
```

---

## STANDARD RECON PIPELINE

```bash
TARGET="target.com"
RECON_DIR="recon/$TARGET"
mkdir -p $RECON_DIR

# 1. Passive subdomain enum
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > /tmp/subs.txt

# 2. Multi-source (Chaos API + subfaster)
curl -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" \
  -H "Authorization: $CHAOS_API_KEY" | jq -r '.[]' >> /tmp/subs.txt
subfaster -d $TARGET -silent | anew /tmp/subs.txt

# 3. DNS + live check
cat /tmp/subs.txt | dnsx -silent | httpx -silent -status-code -title -tech-detect | tee /tmp/live.txt

# 4. URL crawl
cat /tmp/live.txt | awk '{print $1}' | katana -d 3 -jc -kf all -silent | anew /tmp/urls.txt
echo $TARGET | waybackurls | anew /tmp/urls.txt
gau $TARGET --subs | anew /tmp/urls.txt

# 5. Nuclei
nuclei -l /tmp/live.txt -t ~/nuclei-templates/ -severity critical,high,medium -o /tmp/nuclei.txt

# 6. Save to organized directory
cp /tmp/subs.txt $RECON_DIR/subdomains.txt
cp /tmp/live.txt $RECON_DIR/live-hosts.txt
cp /tmp/urls.txt $RECON_DIR/urls.txt
cp /tmp/nuclei.txt $RECON_DIR/nuclei.txt
```

---

## TRUST BOUNDARY DISCOVERY

These are the endpoints that matter most — where the system trusts something:

```bash

# ID parameters → IDOR candidates (identity trust)
cat /tmp/urls.txt | grep -E "[?&](id|user|file|path|url|redirect|next|src|token|key|api_key)=" | tee /tmp/idor-candidates.txt

# API endpoints → injection candidates (input trust)
cat /tmp/urls.txt | grep -E "/api/|/v1/|/v2/|/graphql|/rest/" | tee /tmp/api-endpoints.txt

# Auth endpoints → bypass candidates (identity trust)
cat /tmp/urls.txt | grep -E "/oauth|/login|/auth|/sso|/saml|/token" | tee /tmp/auth-paths.txt

# Admin/debug → privesc candidates (authority trust)
cat /tmp/urls.txt | grep -E "/admin|/internal|/debug|/actuator|/console" | tee /tmp/admin-paths.txt

# File upload → XSS/RCE candidates (input trust)
cat /tmp/urls.txt | grep -E "upload|file|attachment|document|image|avatar" | tee /tmp/upload-candidates.txt

# SSRF candidates (service trust)
cat /tmp/urls.txt | grep -E "webhook|import|export|pdf|generate|fetch|proxy" | tee /tmp/ssrf-candidates.txt

# SQLi candidates (input trust)
cat /tmp/urls.txt | grep -E "search|filter|sort|order|where|query|list" | tee /tmp/sqli-candidates.txt

# Sensitive paths (state trust)
cat /tmp/urls.txt | grep -E "\.env|\.git|config|backup|dump|export|download|log" | tee /tmp/sensitive-paths.txt
```

Build the full trust graph: [[Trust Map]]

---

## JS ANALYSIS — Where Hidden Bugs Live

```bash
mkdir -p /tmp/js-deep
cat /tmp/urls.txt | grep "\.js$" | sort -u | head -100 | while read url; do
  fname=$(echo "$url" | md5sum | cut -d' ' -f1).js
  curl -s "$url" -o "/tmp/js-deep/$fname" 2>/dev/null
done

# API calls → endpoints the frontend trusts
grep -rn "fetch(\|axios\.\|\.get(\|\.post(\|\.put(\|\.delete(" /tmp/js-deep/ | tee /tmp/js-api-calls.txt

# Auth code → tokens, cookies, headers
grep -rn "Authorization\|Bearer\|token\|cookie\|session\|localStorage" /tmp/js-deep/ | tee /tmp/js-auth-code.txt

# Secrets → hardcoded keys
grep -rn "api_key\|apiKey\|client_secret\|access_token\|private_key\|AKIA\|sk_live" /tmp/js-deep/ | tee /tmp/js-secrets.txt

# Dangerous sinks → XSS/SSRF vectors
grep -rn "innerHTML\|outerHTML\|document\.write\|eval(\|dangerouslySetInnerHTML" /tmp/js-deep/ | tee /tmp/js-dangerous-sinks.txt

# postMessage → DOM XSS vectors
grep -rn "postMessage\|addEventListener.*message\|onmessage" /tmp/js-deep/ | tee /tmp/js-postmessage.txt

# URL construction → SSRF vectors
grep -rn "new URL\|location\.href\|location\.assign\|location\.replace" /tmp/js-deep/ | tee /tmp/js-url-construction.txt
```

---

# Standard directory discovery
ffuf -u "https://target.com/FUZZ" \
     -w ~/wordlists/common.txt \
     -mc 200,201,204,301,302,401,403 \
     -ac -t 40 -o /tmp/ffuf-dirs.json

# API endpoint discovery
ffuf -u "https://target.com/api/FUZZ" \
     -w ~/wordlists/api-endpoints.txt \
     -mc 200,201,204,301,302 -ac -t 20

# Backup files
ffuf -u "https://target.com/FUZZ" \
     -w ~/wordlists/common.txt \
     -e .bak,.old,.orig,.save,.swp,.tmp,.backup \
     -mc 200 -ac
```

---

## TECH STACK → BUG CLASS MAP

| Stack | Hunt First | Hunt Second |
|-------|------------|-------------|
| Ruby on Rails | Mass assignment | IDOR |
| Django | IDOR | SSTI |
| Flask | SSTI | SSRF |
| Laravel | Mass assignment | IDOR |
| Express | Prototype pollution | Path traversal |
| Spring Boot | Actuator endpoints | SSTI |
| ASP.NET | ViewState deser | Open redirect |
| Next.js | SSRF via Server Actions | Open redirect |
| GraphQL | Introspection → auth bypass | IDOR via node(id:) |
| WordPress | Plugin SQLi | REST API auth bypass |

More bug classes: [[Vuln Classes]]

---

## 5-MINUTE RULE

If a target shows nothing interesting after 5 minutes, move on. Don't burn hours on dead surface.

**Kill signals:** All 403/static pages, no APIs, no interesting JS, no forms/auth/user data.

---

## TARGET SCORING

| Criterion | Points |
|-----------|--------|
| Max bounty >= $5K | +2 |
| Large user base or handles money | +2 |
| Program launched < 60 days | +2 |
| Complex features (API, OAuth, GraphQL) | +1 |
| Recent code changes | +1 |
| Private program | +1 |
| Tech stack you know | +1 |
| Source code available | +1 |

**< 4:** Skip | **4-5:** If nothing better | **6-8:** 1-3 days | **>= 9:** Up to 1 week

Next step: [[Trust Map]] → [[Methodology]]


## SOURCE: hunt-skills/offensive-osint/README.md

# `offensive-osint` skill

The "what to reach for" operational arsenal for external red-team OSINT and bug-bounty reconnaissance.

| Field | Value |
|---|---|
| Name | `offensive-osint` |
| Version | 2.1 |
| Lines | ~3,800 |
| Top-level sections | 51 |
| Subsections | ~135 |
| Companion skill | [`osint-methodology`](../osint-methodology/) |

## When this skill triggers

Auto-triggers on prompts containing any of ~110 trigger phrases. Common ones:

- All triggers from `osint-methodology` (most prompts pull both)
- `swagger discovery`, `openapi discovery`, `graphql introspection`, `graphql field suggestion`
- `subdomain enumeration`, `subdomain takeover`, `cloud bucket enum`, `S3 enum`, `GCS enum`, `Azure blob enum`
- `okta enum`, `entra enum`, `azure AD enum`, `ADFS enum`, `SAML metadata`
- `mobile recon`, `APK analysis`, `Microsoft 365 deep`, `Teams federation`, `SharePoint enum`, `OneDrive enum`
- `secret scanning`, `secret leak`, `leaked credential`, `JWT triage`, `AWS key triage`
- `github dorking`, `google dorking`, `postman workspace`, `stack exchange OSINT`
- `breach lookup`, `have I been pwned`, `HudsonRock cavalier`, `infostealer`, `dehashed`, `intelx`
- `shodan recon`, `censys recon`, `certificate transparency`, `crt.sh`, `JARM`, `favicon mmh3`
- `JS endpoint extraction`, `sourcemap leak`
- `copy paste probes`, `curl one-liner`
- `email security analysis`, `SPF DMARC DKIM`
- `origin discovery`, `CDN bypass`, `WAF bypass`
- `vendor product fingerprints`, `Citrix Netscaler`, `F5 BIG-IP`, `Pulse Secure`, `FortiGate`, `PaloAlto GlobalProtect`, `Cisco AnyConnect`, `VMware vCenter`
- `cloud native fingerprint`, `Lambda function URL`, `Cloud Run`
- `kubernetes exposure`, `kubelet`, `etcd`
- `CI CD exposure`, `Jenkins recon`, `GitLab self-hosted`, `GitHub Actions secrets`
- `documentation leak`, `Notion public`, `Confluence anonymous`, `Trello board`
- `WHOIS RDAP`, `DNS record catalog`, `Wayback CDX`
- `LinkedIn enumeration`, `job posting tech stack`
- `Slack workspace discovery`, `Discord server discovery`
- `npm token leak`, `PyPI token leak`, `Docker Hub leak`
- `sat imagery physical recon`
- `TLS deep audit`, `JA3 JA4`, `reverse DNS sweep`, `IPv6 enumeration`
- `CVE prioritization`, `EPSS scoring`, `CISA KEV`, `vulnerability prioritization`
- `tooling install`
- `sector specific recon`, `healthcare DICOM`, `finance SWIFT`, `ICS SCADA`, `Modbus`, `BACnet`
- `post discovery workflow`
- `Anthropic API key`, `OpenAI API key`

Full trigger list in the SKILL.md frontmatter.

## What's in it

See the parent [README's "What's in the box" table](../../README.md#whats-in-the-box) for the full §-by-§ breakdown.

Highlights:

- **§16 — Pre-built wordlists & probe paths** including 28 Swagger paths, 13 GraphQL paths + introspection POST body, 35 high-risk ports, 6 missing security headers, 15 always-on HTTP checks, 5 SAML metadata paths, 8 SSO subdomain prefixes, cloud-bucket arsenal (6 prefixes × 15 suffixes × 47 stems × 3 providers), JS guess-paths, endpoint-extraction regex tiers, internal-host leakage regexes, 27 takeover provider fingerprints, copy-paste curl probes, email security analysis, origin discovery / CDN bypass, vendor product fingerprints, cloud-native fingerprints, container/K8s exposure, CI/CD exposure, doc/wiki leak paths, WHOIS/RDAP, DNS catalog with TXT verification token table, Wayback CDX deep usage.
- **§17 — Secret-pattern catalog (48 patterns)** with severity, category, false-positive notes.
- **§18 — Dork corpus (80+ templates, 9 categories)**.
- **§20 — Endpoint interest score (0–100 rubric)**.
- **§21 — Mobile app ownership confidence (0–100 rubric)**.
- **§22 — Identity-fabric concrete endpoints** (incl. M365 Deep + GraphQL field-suggestion enum).
- **§23 — 9 read-only secret validators** + post-discovery enumeration workflows.
- **§39 — 27 attack-path hint templates**.
- **§40 — Severity decision matrix (80+ worked examples)**.
- **§41–§47 — LinkedIn enum, job posting analysis, Slack/Discord discovery, package registry leaks, sat imagery, tooling install, sector notes**.
- **§48 — Runnable secret-scan helper** (stdlib-only Python, available standalone at [`scripts/secret_scan.py`](scripts/secret_scan.py)).

# Local Claude Code install
cp SKILL.md ~/.claude/skills/offensive-osint/SKILL.md
cp scripts/secret_scan.py ~/.claude/skills/offensive-osint/scripts/secret_scan.py

# Or attach to a Claude.ai project / Claude API system prompt
```

The full content lives in this `SKILL.md` (or in `docs/full-skills/offensive-osint.SKILL.full.md` if this file is the structured-outline variant).

## Helper script

[`scripts/secret_scan.py`](scripts/secret_scan.py) — stdlib-only Python scanner mirroring the §17 secret-pattern catalog. Run standalone:

```bash
python3 scripts/secret_scan.py path/to/repo/        # scan a directory tree
python3 scripts/secret_scan.py file1 file2 file3    # scan specific files
cat my.log | python3 scripts/secret_scan.py         # pipe stdin
```

Output: JSONL — one finding per line — `jq`-friendly.

## Self-test

Run the prompts in [`../../tests/smoke-test-prompts.md`](../../tests/smoke-test-prompts.md). Arsenal-targeted prompts are tagged in the test file.


## SOURCE: hunt-skills/offensive-osint/SKILL.md

# Offensive OSINT — External Red-Team Arsenal

> **v3.0** — Refactored 2026-05-02 from a 4,168-line monolith into a lean SKILL.md (~400 lines) plus 15 modular reference files in `references/`. Detail content loads on demand — Claude reads only the reference files relevant to the current task.

## 0. When to use / When NOT

**Use this skill when:**
- You need concrete probe paths, wordlists, regexes, payloads, scoring rules, or tool URLs.
- You're executing reconnaissance and need the actual technical reference (vs. methodology).
- You're building a recon automation and need specific lists to seed it.

**Do NOT use this skill when:**
- The user is asking for active exploitation, post-exploitation, or anything past reconnaissance.
- The user is asking for defensive / blue-team detections.
- The target's authorization isn't established — see §1.

---

## 1. Authorization & Legal Posture

For assets the operator owns or has written authorization to assess. Soft scope check before acting against an unverified third-party target — see methodology skill §1 for the full posture.

---

## 2. Confidence Levels

- **TENTATIVE** — plausible based on indirect evidence (snippet-only dork match, single-source asset, inferred email pattern).
- **FIRM** — directly observed (subdomain resolves, HEAD-confirmed bucket exists, banner returned).
- **CONFIRMED** — verified via independent corroboration OR direct verification (live PMAK validation, multiple sources agree, listable bucket with object retrieval).

---

## 3. Output Format Conventions

Findings should carry: `id`, `module`, `asset_key`, `category`, `severity` (info/low/medium/high/critical), `confidence`, `title`, `description`, `evidence` (url + UTC timestamp + sha256 + raw ≤ 2 KiB), `references`, `remediation`. UTC timestamps everywhere.

---

## 4. Source Hygiene & Citations

URL + UTC timestamp + SHA-256 + tool version + run_id, every artifact. PNG screenshots, JSONL run logs, raw HTTP captures capped at 2 KiB body.

---

## 5. Do NOT

- Don't paste creds/PII/session tokens into cloud LLMs.
- Don't run destructive probes outside DEEP/`--aggressive`.
- Don't use validated credentials for anything except read-only liveness check.
- Don't single-source attribute.
- Don't assume vendor labels are ground truth.

---

## 6. General OSINT (curated tool refs)

- [OSINT Bookmarks](https://tools.myosint.training/) — comprehensive bookmarks.
- [OSINT Framework](https://osintframework.com/) — tool/resource directory.
- [IntelTechniques Tools](https://inteltechniques.com/tools/) — investigative suite.
- [Bellingcat Toolkit](https://www.bellingcat.com/resources/2024/09/24/bellingcat-online-investigations-toolkit/) — investigative journalism.
- [CyberSudo OSINT Toolkit](https://docs.google.com/spreadsheets/d/1EC0sKA_W9znzsxUt0wye9UYtyATXw5m8) — OSINT websites list.
- [Google Dorks](https://dorksearch.com/) — efficient Google searching.
- [Distributed Denial of Secrets](https://ddosecrets.com/) — leaked datasets.
- [Country-Specific Resources](https://digitaldigging.org/osint/) — country-targeted OSINT.


---

## How to use this skill

This skill is a **lean operational index**. Most concrete data (wordlists, regexes, dorks, endpoint catalogs, severity examples) lives in the `references/` subfolder, organized by topic.

**Workflow when this skill triggers:**

1. Read this SKILL.md to anchor on principles (§0-5), scoring rubrics (§20-21), attack-path templates (§39), and the references index below.
2. For task-specific data, **read only the reference file(s) you need** — do NOT pull all 15. Each reference is self-contained.
3. Use the `bug-bounty` skill for the local toolkit at `~/security-research/bug-bounty-resources/` and `osint-methodology` for the planning framework.

**Loading rules of thumb:**
- Single-class question (e.g., "what's the regex for AWS keys?") → load `secret-patterns.md` only.
- Multi-class engagement (e.g., "do an external recon on target.com") → load `probes-and-wordlists.md` first, then add others as the engagement narrows.
- Severity / triage question → load `severity-matrix.md`.

---

## References Index

| File | Coverage | Trigger phrases |
|---|---|---|
| `probes-and-wordlists.md` | API/Swagger/GraphQL paths, cloud-bucket arsenal, JS guess-paths, vendor & cloud-native fingerprints, K8s/CI-CD exposure, doc/wiki leaks, WHOIS/RDAP, DNS catalog, Wayback CDX, copy-paste curl probes, email security analysis, origin/CDN bypass | swagger discovery, graphql introspection, subdomain takeover, cloud bucket enum, S3/GCS/Azure enum, kubernetes exposure, CI CD exposure, vendor fingerprint, WHOIS RDAP, Wayback CDX, copy paste probes, curl one-liner |
| `identity-fabric.md` | Concrete endpoints for Entra/Okta/ADFS/Google/SAML, M365 deep (Teams federation, SharePoint, OneDrive), GraphQL field-suggestion enumeration, user-enum patterns | identity fabric, SSO discovery, IdP fingerprinting, okta enum, entra enum, azure AD enum, ADFS enum, SAML metadata, Microsoft 365 deep, Teams federation, SharePoint enum, OneDrive enum, graphql field suggestion |
| `secret-patterns.md` | 48-pattern secret-regex catalog (AWS, GCP, GitHub PATs, Stripe, Slack, JWT, private keys, Anthropic/OpenAI/HuggingFace, Cloudflare, DigitalOcean, npm, PyPI, Docker Hub, Atlassian, DataDog, Sentry, ngrok) with severity & FP notes | secret scanning, secret leak, leaked credential, JWT triage, AWS key triage, Anthropic API key, OpenAI API key |
| `secret-validators.md` | 9 read-only secret validators + post-discovery enumeration workflows for AWS/GitHub/Slack/Postman/JWT/Anthropic/OpenAI/npm/Atlassian/DataDog | secret validation, post discovery workflow, AWS key triage, JWT triage |
| `dork-corpus.md` | 80+ Google/Bing/DDG dork templates across 9 categories + 13 GitHub code-search dorks tailored for targets | google dorking, bing dorking, github dorking, dork corpus |
| `recon-stack.md` | Subdomain-source stack (passive & active), infrastructure & attack-surface OSINT (Shodan/Censys/crt.sh/JARM/favicon mmh3), TLS deep audit, reverse DNS, IPv6 enumeration | subdomain enumeration, certificate transparency, crt.sh, shodan recon, censys recon, JARM, favicon mmh3, TLS deep audit, JA3 JA4, reverse DNS sweep, IPv6 enumeration |
| `breach-and-credentials.md` | Breach & leak data sources (HudsonRock, HIBP, DeHashed, IntelX, infostealer logs), email-pattern inference, email-harvest source stack | breach lookup, have I been pwned, HudsonRock cavalier, infostealer, dehashed, intelx, email harvest |
| `people-osint.md` | Search engines, username & email investigation, people search, phone OSINT, social media, public records & company info | username investigation, people search, phone OSINT, social media OSINT, public records |
| `saas-public-surfaces.md` | Postman public workspace search (verified endpoint), Stack Exchange OSINT sweep, public SaaS dork stack (Notion, Confluence, Trello) | postman workspace, stack exchange OSINT, Notion public, Confluence anonymous, Trello board |
| `specialized-osint.md` | Threat intel & IOCs, cryptocurrency OSINT, media intelligence, geospatial intelligence, regional search engines, Telegram & messaging intelligence | threat intel, IOCs, cryptocurrency OSINT, media intelligence, geospatial OSINT, regional search, Telegram intelligence |
| `recon-techniques.md` | LinkedIn employee enumeration, job-posting tech-stack analysis, Slack/Discord/Telegram workspace discovery, package-registry leak hunting (npm/PyPI/Docker Hub/Quay/GHCR), sat imagery for physical recon | LinkedIn enumeration, job posting tech stack, Slack workspace discovery, Discord server discovery, npm token leak, PyPI token leak, Docker Hub leak, sat imagery physical recon |
| `severity-matrix.md` | 80+ worked examples mapping observed conditions → finding severity (CRITICAL/HIGH/MEDIUM/LOW/INFO) | severity decision, finding severity, severity matrix |
| `sector-notes.md` | Recon notes for healthcare (DICOM), finance (SWIFT), ICS/SCADA (Modbus/BACnet), IoT, government | sector specific recon, healthcare DICOM, finance SWIFT, ICS SCADA, Modbus, BACnet |
| `tooling-install.md` | Quick-install one-liners for Subfinder, Amass, httpx, nuclei, gau, katana, gowitness, dnsx, mapcidr, naabu, sslyze, testssl.sh, etc. | tooling install, install subfinder, install nuclei, install httpx |
| `helpers-and-automation.md` | AI-assisted OSINT, archiving & evidence preservation, automation & workflow patterns, cross-module sidecar coordination, runnable secret_scan.py / h1_reference.py / dashboard.py helper notes | AI-assisted OSINT, evidence preservation, automation, sidecar, hacktivity reference, recon console |


---

## 20. Endpoint Interest Score — 0–100 rubric

For every classified endpoint (§22 in methodology skill), apply this rubric:

| Signal | Points | Conditions |
|---|---|---|
| **Unauth write** | +40 | POST/PUT/DELETE/PATCH endpoint returns 200/201/202/204 anonymously. |
| **Open GraphQL introspection** | +35 | `__schema` query returns full type list anonymously. |
| **Verb tampering bypass** | +30 | OPTIONS reveals method not documented; that method is accessible. |
| **Reflected CORS + credentials** | +25 | `Access-Control-Allow-Origin` reflects request `Origin` AND `Access-Control-Allow-Credentials: true`. |
| **Sensitive keyword in path** | +20 | Path matches one of: `admin`, `internal`, `debug`, `user`, `password`, `token`, `key`, `export`, `upload`, `backup`, `config`, `secret`, `private`, `delete`, `purge`, `wipe`. |
| **Schema leak in error** | +20 | Response body contains stack trace, ORM error class, framework signature (e.g., `ActiveRecord::RecordNotFound`, `org.hibernate.exception.*`, `django.db.utils.IntegrityError`). |
| **API key in URL** | +15 | Path or query string contains `api_key=`, `apikey=`, `token=`, `access_token=`. |
| **Wildcard CORS** | +10 | `Access-Control-Allow-Origin: *`. |
| **Missing rate-limit headers** | +10 | No `RateLimit-*` / `X-RateLimit-*` headers; no `Retry-After` after rapid requests. |

**Thresholds:**

| Score | Severity |
|---|---|
| ≥ 90 | **CRITICAL** |
| 70–89 | **HIGH** |
| 50–69 | MEDIUM |
| 25–49 | LOW |
| < 25 | INFO |

For score ≥ 70, attach an `attack_path_hint` in evidence (see §29).

---

## 21. Mobile App Ownership Confidence — 0–100 rubric

Before running deep APK static analysis, score whether the discovered app actually belongs to the target. Threshold: **≥70 = accept**.

| Signal | Points |
|---|---|
| Package reverse-DNS matches target domain (e.g., `com.acme.android` ⟂ `acme.com`) | +40 |
| Developer email is `<anything>@<target-domain>` | +25 |
| Developer website URL is the target domain (or a confirmed sibling brand domain) | +20 |
| App name contains a brand keyword from operator-supplied brand list | +10 |
| App has ≥ minimum review-score threshold (default 20 reviews) | +5 |

Apps below threshold are tagged `mobile_review_pending` and shown but not analyzed. Operator can re-score with `--mobile-ownership-threshold 50` for noisier collection.

---


---

## 39. Attack-Path Hint Patterns

When emitting a HIGH/CRITICAL API endpoint finding (score ≥ 70), include a one-sentence `attack_path_hint` in evidence so the operator knows where to start exploiting. Templates:

| Trigger | Attack-path hint |
|---|---|
| Unauth POST / PUT / DELETE | *"Unauthenticated {method} {path} — try IDOR + privilege escalation; check whether numeric IDs are sequential or guessable."* |
| Open GraphQL introspection | *"Open GraphQL introspection on {path} — enumerate mutations, look for `createUser`, `setRole`, `transferFunds`-shaped names; pivot to broken-auth or business-logic flaws."* |
| Reflected CORS + creds | *"Reflected CORS with credentials on {path} — host CSRF page on attacker-controlled origin; victim's browser will leak {sensitive-data-hint}."* |
| Wildcard CORS + sensitive | *"Wildcard CORS on {path} returning user-tied data without creds — exfiltrate via cross-origin fetch from any page victim visits."* |
| Verb tampering | *"Verb tampering: {hidden-method} allowed on documented-{visible-method}-only endpoint → likely missing-method-check authz bug; try {hidden-method} {path} with valid auth."* |
| API key in URL | *"API key in URL: `?{param}=...` — token leaks to access logs, browser history, Referer headers, third-party CDNs. Check Wayback / Google for cached copies."* |
| Schema leak in error | *"Schema leak in error response — framework signature `{framework}` exposed; map to known {framework} vulns and craft targeted payloads."* |
| Sensitive keyword | *"Path contains '{keyword}' — review for direct object reference, mass-assignment, or hidden admin functionality."* |
| Open RTDB Firebase | *"Open Firebase RTDB at https://{project}.firebaseio.com/.json — read everything, then test write at `/<random-key>.json` with PUT to gauge ACL scope."* |
| Listable cloud bucket | *"Listable {provider} bucket `{bucket}` — recursive object listing + content-type analysis; look for backups, logs, customer data, AWS keys in JSON configs."* |
| .git exposed | *"Exposed .git/config on {host} — reconstruct repository with git-dumper or githacker; full source history."* |
| .env exposed | *"Exposed .env on {host} — grep for `_KEY`, `_SECRET`, `_TOKEN`, `_PASSWORD`; validate all credentials read-only via §23 validators."* |
| /actuator/env | *"Spring Boot /actuator/env exposed — dump environment variables; look for `spring.datasource.password`, JWT secrets, cloud creds."* |
| /actuator/heapdump | *"Spring Boot /actuator/heapdump exposed — download HPROF, run `jhat` or VisualVM, search for cleartext secrets in heap strings."* |
| Open Elasticsearch | *"Open Elasticsearch on {host}:9200 — `/_cat/indices?v` for index list; sample documents from each high-value index; test write to `/test-idx/_doc` to gauge ACL."* |
| Open Redis | *"Open Redis on {host}:6379 — `INFO`, `KEYS *`, sample reads; check for write access via `CONFIG SET` then `BGSAVE` to write `authorized_keys`."* |
| Open MongoDB | *"Open MongoDB on {host}:27017 — `show dbs`, `show collections`, sample find queries; check user collection for password hashes."* |
| Subdomain takeover | *"CNAME for {host} points to unclaimed {provider} resource → register `{takeover-target}` on {provider} to serve content from {host}; pivot to phishing or content injection on the trusted domain."* |
| Open kubelet | *"Open kubelet on {host}:10250 — `GET /pods` to list; `POST /run/<ns>/<pod>/<container>` for in-container exec without K8s API auth."* |
| Open etcd | *"Open etcd on {host}:2379 — `etcdctl get / --prefix --keys-only` for full cluster state; secrets stored under `/registry/secrets/`."* |
| K8s API anonymous | *"Kubernetes API on {host}:6443 with anonymous-auth — `kubectl --server=https://{host}:6443 --insecure-skip-tls-verify get pods --all-namespaces`."* |
| Citrix unpatched | *"Citrix NetScaler version {ver} on {host} — vulnerable to CVE-{cve} (KEV-listed); see vendor advisory; do not exploit but flag for client immediate patching."* |
| F5 BIG-IP TMUI exposed | *"F5 BIG-IP TMUI on {host} reachable; CVE-2022-1388 / CVE-2023-46747 KEV applicable; advise immediate patching to vendor-released hotfix."* |
| VMware vCenter accessible | *"vCenter at {host} accessible without VPN; CVE-2021-21972 RCE if unpatched; check version banner."* |
| Cloud function URL unauth | *"AWS Lambda Function URL at {url} accessible anonymously — review IAM auth configuration; if unauthenticated by design, audit input validation aggressively."* |
| npm typosquat candidate | *"Package name `{candidate}` is unregistered + similar to target's published `{official}` — typosquat takeover risk; advise client to defensively register."* |
| DMARC missing/permissive | *"DMARC `p=none` on {domain} — spoof of `{anything}@{domain}` deliverable to recipients; recommend enforcement to `p=quarantine` or `p=reject` after observing reports."* |
| Live AI API key (Anthropic/OpenAI) | *"Validated `sk-{provider}-...` key with model access — quota cost can be exfiltrated; rotate immediately + audit usage logs in provider console."* |
| Public Slack invite link | *"Slack workspace invite link discoverable via search engine — anyone can join the workspace without approval; trivially access internal channels."* |
| Open Docker registry | *"Public Docker registry at {host} — `GET /v2/_catalog` lists images; pull and scan layers for embedded secrets."* |
| Telegram bot token live | *"Telegram bot token validated — `getUpdates` reveals bot recipients (admin chats); if `getMe` shows bot is in channels, full message read access."* |
| Sourcemap with `sourcesContent[]` | *"Sourcemap on {host} includes embedded original sources — full frontend code reconstructable; grep for inline secrets and internal hostnames."* |

---


---

## 49. Skill Self-Test

Drop these prompts into a fresh Claude session to verify the skill loads correctly.

1. *"What paths should I probe to find Swagger or OpenAPI specs on a webapp?"* → §16.1.
2. *"Give me the GraphQL introspection query I should POST."* → §16.2.
3. *"What are the high-risk ports to flag from a Shodan scan?"* → §16.3.
4. *"Show me the secret regex catalog."* → §17 (48 patterns) + §48 (runnable Python).
5. *"How do I score an API endpoint by attack interest?"* → §20.
6. *"Validate a leaked Postman API key — what URL?"* → §23.1.
7. *"Give me dorks for pastebin/gist/ghostbin leaks for a target."* → §18.3.
8. *"What endpoints fingerprint a Microsoft Entra tenant?"* → §22.1 + §22.8 for M365 deep.
9. *"How do I score whether a discovered Android app belongs to my target?"* → §21.
10. *"What attack-path hint when I find unauth POST on `/api/users`?"* → §39 (first row).
11. *"Curl one-liner to test for `/actuator/env`."* → §16.13.
12. *"Show me the GraphQL field-suggestion enumeration trick when introspection is disabled."* → §22.9.
13. *"Found a hard-coded JWT in JS. Walk me through full triage."* → §23.12 (JWT workflow).
14. *"Generate cloud bucket candidates for `<Client Brand Ltd>` with subdomains api/billing/hr."* → §16.8.
15. *"How do I find Microsoft 365 Teams federation status + SharePoint subdomains?"* → §22.8.
16. *"Probe paths for Citrix Netscaler / F5 BIG-IP / Pulse Secure."* → §16.16.
17. *"Find the origin behind Cloudflare on `target.example`."* → §16.15 + companion methodology §27.
18. *"What ports/paths probe for Kubernetes/etcd/kubelet exposure?"* → §16.18.
19. *"Audit `acme.com`'s SPF/DMARC for spoof feasibility."* → §16.14.
20. *"List wordlist sources for subdomain bruteforce + content discovery."* → §27.1.
21. *"Run reverse-DNS sweep across a /22 the target owns."* → §28.5.
22. *"Validate an OpenAI API key without burning quota."* → §23.6 + §23.12.
23. *"Find leaked secrets across npm/PyPI/Docker Hub for the target."* → §44.
24. *"How do I enumerate target employees on LinkedIn for a phishing list?"* → §41.
25. *"What's a Slack invite link enumeration technique?"* → §43.1.
26. *"What's the EPSS score and KEV status for CVE-2024-3400?"* → §29.2.
27. *"What modern AI API keys (Anthropic / OpenAI / HuggingFace / Cloudflare) match catalog patterns?"* → §17 rows 30–48.
28. *"Severity matrix for `android:debuggable=true` on prod app?"* → §40.
29. *"Install commands for the standard recon toolkit (subfinder/httpx/nuclei/etc.)?"* → §46.
30. *"For a healthcare engagement, what additional ports / protocols matter?"* → §47.1.
31. *"Pull HudsonRock breach corpus for `target.com` via direct API (no UI)."* → §15.0.1.
32. *"Run the full §16.14 email security audit from a Windows box (PowerShell)."* → §16.14 PowerShell parallel.
33. *"crt.sh just 502'd. What's the fallback chain?"* → §27.0.1.
34. *"Bulk IP → ASN lookup for 200 IPs without burning bgpview rate limit."* → §28.1 (Cymru bulk).
35. *"Common-prefix subdomain sweep for `target.example` covering vpn / api / staging / portal / intranet."* → §16.24.
36. *"Legacy mail (`mail.<domain>`) is NXDOMAIN today but breach corpus has employee URLs against it. What's the finding?"* → §15.2 legacy-mail-decommissioned pattern.
37. *"Confirm M365 tenancy when MX is wrapped by Mimecast (so MX doesn't reveal underlying mail platform)."* → §22.1 autodiscover IP correlation + §16.22 autodiscover-as-confirmation.
38. *"DMARC RUA points to `kdmarc.com` — what does that tell me?"* → §16.14 DMARC reporting-vendor table.
39. *"SharePoint HEAD probe returns HTTP 200. Does that mean anonymous access is granted?"* → §22.8 (no — tenant exists, not anonymous access; distinguish).
40. *"Wayback `*.js` query returned empty for a brochure-ware site. Pivot?"* → §16.23 legacy-app pivot (.asp / .php / .jsp / .cfm / .aspx).

---

## 50. Changelog

- **v2.1.1 (2026-04-27)** — battle-test gap fixes from real-engagement smoke run. Added: §15.0.1 HudsonRock Cavalier direct-API recipe (curl + PowerShell, full JSON shape, free-tier redaction caveats, rate-limit guidance). §15.2 expanded with legacy-mail-decommissioned escalation pattern (NXDOMAIN legacy mail + breach corpus + autodiscover-confirmed cloud migration → CRITICAL SSO_EXPOSURE). §16.14 expanded with DMARC reporting-vendor table (Kratikal kdmarc / dmarcian / Valimail / Agari / EasyDMARC / DMARC Analyzer / Postmark) + full Windows/PowerShell parallel for the entire email security audit + caveat that PS 5.1 `Resolve-DnsName -Type CAA` errors (use PS 7+ or `nslookup -type=CAA`). §16.22 expanded TXT verification token catalog with 17 new tokens (zscaler-verification, cloudflare-verify, autosect, cisco-site-verification, mscid, _amazonses, salesforce-domain-verification, workday/shopify/klaviyo/mailchimp/hubspot/zendesk/freshworks/intercom/loom/miro/gitlab) + new "Autodiscover-as-confirmation" pattern for M365 detection when MX is wrapped by Mimecast/Proofpoint/Barracuda. §22.1 added passive Autodiscover IP correlation pattern with Microsoft Exchange Online IP ranges. §22.8 added clarification: SharePoint HEAD HTTP 200 = tenant exists, NOT anonymous access granted (operators commonly misread). New §16.23 legacy-app pivot block (when Wayback `*.js` returns empty for brochure-ware sites, pivot to .asp/.php/.jsp/.cfm/.aspx/.json/.xml/.yml/.ini/.conf — with full broad-sweep one-liner). New §16.24 Common-Prefix Subdomain Sweep — formalized active prefix-probe technique with 100+ ordered prefix list, PowerShell + bash + puredns recipes, and real-engagement validation note (passive enum misses 20-40% of high-value subdomains; always pair with active prefix probe). §27.0.1 added crt.sh fallback chain (Censys, CertSpotter, Calidog, Subfinder, OTX, ThreatMiner, URLScan, Anubis-DB) with PowerShell wrapper that retries crt.sh 3× then falls back to Subfinder. §28.1 added Bulk IP→ASN recipes (Cymru bulk WHOIS, RIPEstat, bgp.tools, IPinfo Lite) + caveat that bgpview.io API has aggressive rate limits unsuitable for bulk. §40 severity matrix gained 8 rows: vendor procurement portal exposed + breach corpus hits (HIGH), PII-collection portal over plain HTTP (HIGH), decommissioned legacy mail + breach + cloud migration (CRITICAL), public-facing intranet without VPN (MEDIUM), staging/preprod publicly resolvable (MEDIUM), vpn.<domain> resolves but vendor unknown (INFO escalating to HIGH-CRITICAL on KEV match), DMARC RUA → third-party vendor (INFO). §49 self-test expanded from 30 → 40 prompts targeting all new content.
- **v2.1 (2026-04-27)** — comprehensive expansion based on 32-test smoke-test gap analysis. Added: copy-paste curl probes for every check (§16.13), email security analysis with SPF/DMARC/DKIM/BIMI/MTA-STS/DNSSEC parsing + SaaS tenant inference (§16.14), origin discovery / CDN bypass via DNS history + cert SAN + favicon hash + JARM + Host-header probe (§16.15), vendor product fingerprints for Citrix/F5/Pulse/Fortinet/PaloAlto/Cisco/VMware/Exchange + KEV CVE associations (§16.16), cloud-native service URL fingerprints — Lambda Function URLs, Cloud Run, Cloud Functions, Azure Functions, Vercel, Netlify, Cloudflare Workers, etc. (§16.17), container & Kubernetes exposure (kubelet, etcd, K8s API, dashboard, Helm Tiller, container registries) (§16.18), CI/CD platform exposure (Jenkins deeper, GitLab, GitHub Actions, CircleCI, TeamCity, Argo CD, Spinnaker) (§16.19), documentation/wiki leak paths (Notion, Confluence, Trello, Miro, Lucidchart, Figma, ReadTheDocs, GitBook, Slab, Coda, etc.) (§16.20), WHOIS/RDAP/historical-WHOIS recipes + reverse-WHOIS pivots (§16.21), DNS record catalog with TXT verification token table → SaaS tenant inference (§16.22), Wayback CDX deep usage with all filter parameters (§16.23). Expanded: §17 secret catalog from 29 → 48 patterns adding modern AI API keys (Anthropic, OpenAI legacy + project, HuggingFace), infra (Cloudflare, DigitalOcean), package registries (npm, PyPI, Docker Hub), SaaS (Atlassian, Linear), observability (New Relic, DataDog, Sentry DSN), bot tokens (Discord, Telegram), and ngrok. Expanded §18 dork corpus from 50+ → 80+ with internal-tool exposure (Splunk/Grafana/Kibana/Argo CD/Sonarqube/Confluence/Jira/GitLab/Gitea), backup-file extensions, and sector-specific dorks (healthcare/finance/gov). Added §22.8 Microsoft 365 deep enumeration (Teams federation, SharePoint subdomain probe, OneDrive personal-site probe, OAuth client_id discovery, device-code phishing target check, Power Platform). Added §22.9 GraphQL field-suggestion enumeration recipe + alias batching, query-depth bypass, subscription enumeration, batched-query bypass. Added §23.5–23.9 read-only validators for Anthropic, OpenAI, npm, Atlassian, DataDog (5 new). Added §23.12 post-discovery enumeration workflows (AWS IAM enum, GitHub PAT scope/repo enum, Slack workspace enum, JWT full triage with algorithm-confusion + brute-force + none-bypass, Postman PMAK workspace enum, Anthropic + OpenAI usage enum, generic key provenance enum). Pinned §24 Postman search endpoint with verified shape + DevTools fallback recipe. Added §27.1 wordlist sources (Assetnote, SecLists, jhaddix, OneListForAll, raft-large-words, fuzzdb, etc.) + size guidance. Added §28.4 TLS deep audit (sslyze + testssl.sh + nmap + JA3/JA4 + cipher/protocol/cert checks). Added §28.5 reverse DNS sweep + IPv6 enumeration + BGP route observation. Added §29.2 vulnerability prioritization data sources (NVD/EPSS/CISA KEV/ExploitDB/Metasploit/InTheWild/OpenCVE/Trickest CVE+POC mapping/OSV.dev/VulnCheck KEV) + bulk prioritization workflow. Expanded §39 attack-path hints with 15 more templates (open kubelet/etcd, K8s API anonymous, Citrix/F5/vCenter/Cloud Function unauth, npm typosquat, DMARC missing, live AI keys, Slack invite, sourcemap with sourcesContent). Expanded §40 severity matrix with 30 more worked examples covering Kubernetes/container, vendor products with KEV CVEs, M365/cloud-native, CI/CD misconfig, documentation leaks, email-security gaps, AI/package-registry credentials, TLS issues. Added §41 LinkedIn employee enumeration tradecraft (search techniques + role inference + email-pattern derivation + sock-puppet considerations). Added §42 job posting tech-stack analysis (sources + extraction + tooling). Added §43 Slack/Discord/Telegram/Mattermost workspace discovery. Added §44 package registry leak hunting (npm/PyPI/RubyGems/Cargo/Packagist/NuGet/Maven Central + workflow + typosquat surveillance). Added §45 sat imagery for physical recon (sources + extraction + LinkedIn/Glassdoor/Instagram/conference intel + vehicle/fleet intel). Added §46 tooling quick-install (subdomain, HTTP probing, vuln scanning, content discovery, JS extraction, Wayback, cloud, identity, mobile, TLS, utilities, frameworks). Added §47 sector-specific recon notes (healthcare DICOM/HL7/FHIR/EHR + finance SWIFT/FIX/Bloomberg/banking middleware + ICS-SCADA Modbus/BACnet/S7/DNP3 + IoT MQTT/CoAP/UPnP + government FedRAMP/FISMA + maritime/aviation/auto). Renumbered Runnable Helper → §48, Self-Test → §49 (refreshed for v2.1), Changelog → §50.
- **v2.0 (2026-04-27)** — major rewrite for external red-team posture. Added: pre-built wordlists (§16), 29-pattern secret catalog (§17), 50+ dork corpus (§18), GitHub code-search dorks (§19), endpoint interest score (§20), mobile ownership confidence (§21), identity-fabric concrete endpoints (§22), read-only secret validators (§23), Postman workspace search (§24), Stack Exchange sweep (§25), public SaaS dorks (§26), subdomain-source stack (§27), domain-level breach severity (§15.1), L2 explorer table (§30.2), USCC + ICP workflow (§14.2), cross-module sidecar coordination (§36), attack-path hint patterns (§39), severity decision matrix (§40), runnable secret-scan helper (§41). Strengthened: confidence levels (§2), output format (§3), do-not rules (§5). Original tool tables retained and lightly reorganized.

---

## Related Skills & Chains

- **`web2-recon`** — When the arsenal needs to be executed against a live host set. Workflow primitive: this skill provides the probe paths and wordlists; `web2-recon` runs the actual subfinder → dnsx → httpx → katana pipeline that consumes them.
- **`osint-methodology`** — When this skill's concrete probes need a planning framework. Workflow primitive: `osint-methodology` is the planning skeleton (5-stage pipeline, asset graph, findings rubric); this skill is the operational arsenal that fills each stage with curl one-liners and regexes.
- **`hunt-subdomain`** — When this skill's subdomain enumeration finds stale CNAMEs. Workflow primitive: subdomains discovered via §27 / `references/recon-stack.md` get auto-routed to `hunt-subdomain` for takeover validation.
- **`hunt-cloud-misconfig`** — When this skill's cloud-bucket enum surfaces listable buckets / Firebase / actuator endpoints. Workflow primitive: §39 attack-path hints (listable bucket, /actuator/env, open Elasticsearch) hand off to `hunt-cloud-misconfig` for exploitation.
- **`m365-entra-attack`** / **`okta-attack`** — When identity-fabric fingerprinting finds Entra/Okta. Workflow primitive: `references/identity-fabric.md` fingerprints the IdP; matched platform skill (loaded by `hunt-dispatch`) takes over for active enumeration.


## SOURCE: hunt-skills/offensive-osint/references/dork-corpus.md

# Dork Corpus & GitHub Code-Search Dorks

> Reference content for the `offensive-osint` skill. Originally §18 + §19 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 18. Dork Corpus — 80+ templates, 9 categories

Substitute `{domain}` with the target domain (e.g., `example.com`) and `{company}` with the company name (e.g., `Acme Corporation`). Run via Google, Bing, Brave, DuckDuckGo, Yandex, Baidu — engines surface different results.

### 18.1 Files

```
site:{domain} filetype:env
site:{domain} ext:env OR ext:ini OR ext:cfg OR ext:conf
site:{domain} ext:sql OR ext:sqlite OR ext:dump OR ext:bak
site:{domain} ext:pem OR ext:key OR ext:p12 OR ext:pfx
site:{domain} ext:log
site:{domain} intitle:"index of"
site:{domain} inurl:.git OR inurl:/.git/
site:{domain} inurl:backup OR inurl:.bak OR inurl:old
site:{domain} ext:yml OR ext:yaml
site:{domain} ext:properties
```

### 18.2 Admin / login panels

```
site:{domain} inurl:admin OR inurl:login OR inurl:sso OR inurl:dashboard
site:{domain} intitle:"phpMyAdmin"
site:{domain} intitle:"Jenkins"
site:{domain} intitle:"Grafana"
site:{domain} intitle:"Kibana"
site:{domain} intitle:"Splunk"
site:{domain} (intitle:"login" OR intitle:"sign in")
site:{domain} intitle:"GitLab"
site:{domain} intitle:"Swagger" OR intitle:"OpenAPI"
site:{domain} inurl:phpinfo
```

### 18.3 Secrets / credential leakage

```
"{domain}" ("api_key" OR "apikey" OR "access_token")
"{domain}" (password OR passwd OR pwd)
site:pastebin.com "{domain}"
site:ghostbin.com "{domain}"
site:rentry.co "{domain}"
site:gist.github.com "{domain}"
site:hastebin.com "{domain}"
"{domain}" "BEGIN RSA PRIVATE KEY"
```

### 18.4 Cloud / CI / shadow-IT

```
site:s3.amazonaws.com "{domain}"
site:storage.googleapis.com "{domain}"
site:blob.core.windows.net "{domain}"
site:digitaloceanspaces.com "{domain}"
site:trello.com "{domain}"
site:*.atlassian.net "{domain}"
site:dev.azure.com "{domain}"
site:bitbucket.org "{domain}"
site:firebaseio.com "{domain}"
site:herokuapp.com "{domain}"
```

### 18.5 Docs / intel mining

```
site:{domain} filetype:pdf (confidential OR internal OR restricted)
site:{domain} filetype:xlsx OR filetype:csv
site:{domain} filetype:docx
site:scribd.com "{company}"
"{company}" filetype:pdf (salary OR payroll OR org-chart OR "organization chart")
site:linkedin.com/in "{company}"
site:slideshare.net "{company}"
```

### 18.6 Vuln indicators

```
site:{domain} intext:"sql syntax" OR intext:"you have an error in your sql"
site:{domain} intext:"Warning: mysql_"
site:{domain} intext:"Fatal error:" intext:"on line"
site:{domain} intext:"stack trace" OR intext:"Traceback (most recent call last)"
"Apache/2.4.49" site:{domain}
"Server: nginx/1.14" site:{domain}
site:{domain} inurl:wp-content OR inurl:wp-includes
```

### 18.7 Internal tool exposure

```
site:{domain} intitle:"Splunk"
site:{domain} intitle:"Grafana"
site:{domain} intitle:"Kibana"
site:{domain} intitle:"Prometheus Time Series"
site:{domain} intitle:"Jaeger UI"
site:{domain} intitle:"AlertManager"
site:{domain} intitle:"Argo CD"
site:{domain} intitle:"Sonarqube"
site:{domain} intitle:"Sentry"
site:{domain} intitle:"Confluence"
site:{domain} intitle:"Jira"
site:{domain} intitle:"GitLab"
site:{domain} intitle:"Gitea"
site:{domain} intitle:"Drone CI"
site:{domain} inurl:"/jenkins/"
```

### 18.8 Backup / dump file extensions

```
site:{domain} ext:bak OR ext:backup OR ext:old OR ext:orig OR ext:save OR ext:swp
site:{domain} ext:tar OR ext:tar.gz OR ext:tgz OR ext:zip OR ext:rar OR ext:7z
site:{domain} ext:db OR ext:sqlite OR ext:sqlite3 OR ext:mdb
site:{domain} ext:dump OR ext:rdb OR ext:bson
site:{domain} (intext:"-- MySQL dump" OR intext:"PostgreSQL database dump")
site:{domain} ext:pcap OR ext:pcapng OR ext:cap
site:{domain} ext:core OR ext:hprof OR ext:dmp
```

# Healthcare
site:{domain} (filetype:pdf OR filetype:xlsx) (HIPAA OR PHI OR "patient records")
site:{domain} ("DICOM" OR "HL7" OR "ICD-10")

# Finance
site:{domain} (filetype:pdf OR filetype:xlsx) (SOC OR "audit report" OR "internal control")
site:{domain} (filetype:pdf OR filetype:xlsx) ("Form 10-K" OR "Form 10-Q" OR earnings)
site:{domain} ("SWIFT" OR "BIC" OR IBAN OR "wire transfer")

# Gov / public sector
site:{domain} (filetype:pdf OR filetype:doc) (FOUO OR "controlled unclassified" OR CUI)
site:{domain} (filetype:pdf OR filetype:xlsx) ("personnel security" OR clearance)
```

### 18.10 Result classification

After running, score each result via URL signature → title hint → snippet regex:
- **CRITICAL URL signatures:** `.pem`, `.p12`, `.pfx`, `.key` extensions; `id_rsa` filename.
- **HIGH URL signatures:** `/.env`, `/.git/`, database dumps, `wp-config.bak`, `/phpmyadmin`, `/jenkins`, `/phpinfo.php`.
- **MEDIUM URL signatures:** `/admin`, `/login`, `/swagger`, `.log`, `/backup`, `.DS_Store`.
- Snippet content (e.g., a secret regex hit in the snippet) overrides URL signature only if higher severity.
- Confidence: snippet-only match = TENTATIVE (operator must visit URL to confirm; tag detectability=medium).

---

## 19. GitHub Code-Search Dorks for Targets — 13 dorks

Apply each template to `{target}` (root domain stem like `acme`), `{domain}` (full root domain like `acme.com`), and optionally `{company}` (`Acme Corporation`):

```
"{target}" filename:.env
"{target}" filename:.env.example
"{target}" filename:config
"{target}" AWS_ACCESS_KEY_ID
"{target}" AWS_SECRET_ACCESS_KEY
"{target}" password
"{target}" api_key
"{target}" secret
"{target}" authorization: Bearer
"{target}" filename:id_rsa
"{target}" filename:.git-credentials
"{target}" filename:wp-config.php
"@{domain}" password                        # emails + password context
```

**Requirements:** GitHub personal access token (any scope; recommend a fine-grained PAT with read-only repo access). Rate limit per token; concurrency cap ≤5.

**For each result:**
1. Fetch the file (or relevant fragment) via the GitHub Contents API.
2. Run the secret catalog (§17).
3. If a secret hits → `SECRET_LEAK` finding with catalog severity, evidence = repo URL + file path + matched secret (truncated, last 4 chars only).
4. Optional: clone the repo to a tempdir, run `trufflehog`/`gitleaks` for full history scan.

---


## SOURCE: hunt-skills/offensive-osint/references/helpers-and-automation.md

# AI-Assisted OSINT, Archiving, Automation, Sidecar, Helpers

> Reference content for the `offensive-osint` skill. Originally §33 + §34 + §35 + §36 + §48 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 33. AI-Assisted OSINT

> **Warning:** Never paste PII, sensitive IOCs, or unique pivots into cloud LLMs. They log inputs and may use them for training. Use local models for sensitive analysis.

| Tool | Strength |
|------|---------|
| [ChatGPT](https://chat.openai.com/) (paid) | Log parsing, dataset analysis, Code Interpreter for CSV/JSON, Vision OCR. |
| [Claude](https://claude.ai/) (paid) | 200K-token context for large doc dumps + report synthesis. |
| [Gemini](https://gemini.google.com/) | Long-context; Deep Research mode with citations. |
| [Perplexity Pro](https://www.perplexity.ai/) (paid) | Real-time web search + reasoning. |

**Local / privacy-preserving:** [Ollama](https://ollama.com/), [LM Studio](https://lmstudio.ai/), [GPT4All](https://gpt4all.io/).

### 33.1 Commercial AI OSINT Platforms

- [Cylect](https://www.cylect.io/) — entity extraction + link analysis.
- [Fivecast Matrix](https://www.fivecast.com/products/matrix/) — generative-AI triage for social-media datasets.
- [Recorded Future](https://www.recordedfuture.com/) — AI-driven threat intel.
- [DarkOwl Vision](https://www.darkowl.com/) — darknet data analysis.

### 33.2 Deepfake & Synthetic Media Detection

- [Sensity AI](https://sensity.ai/), [Reality Defender](https://realitydefender.com/), [Adobe Content Credentials Verify](https://contentcredentials.org/verify), [CarNet](https://carnet.ai/).

---

## 34. Archiving & Evidence Preservation

- [archive.today](https://archive.today/) — one-page archiver + screenshot.
- [URLScan.io](https://urlscan.io/) — webpage scan + resource map.
- [ArchiveBox](https://archivebox.io/) — self-hosted (HTML, PDF, screenshots, media).
- [Hunchly](https://www.hunch.ly/) — investigator evidence capture (paid).
- Wayback SavePageNow API v3 — on-demand archiving with job IDs.
- [SingleFileZ](https://github.com/gildas-lormeau/SingleFileZ) — browser ext for offline HTML.
- [Kasm Workspaces](https://kasmweb.com/) — containerized OSINT browser isolation.

**Evidence handling:** URL + UTC timestamp + PNG + WARC/SingleFileZ archive, SHA-256 hash all downloads, separate work profiles per case, store evidence read-only, JSONL run logs with `run_id` + tool versions.

---

## 35. Automation & Workflows

- [n8n](https://n8n.io/) — self-hosted workflow automation (RSS → scrape → alert pipelines).
- [Huginn](https://github.com/huginn/huginn) — agent-based monitoring/scraping/alerting.
- [Playwright](https://playwright.dev/) — headless browser automation with stealth plugins.
- [Browsertrix Crawler](https://github.com/webrecorder/browsertrix-crawler) — archival crawling with WARC export.
- [Prefect](https://www.prefect.io/) / [Apache Airflow](https://airflow.apache.org/) — workflow orchestration.

---

## 36. Cross-Module Sidecar Coordination

When you run a multi-module recon, late-arriving outputs need to feed into already-running modules. The pattern:

1. Each module writes a sidecar JSON to a known location when it finishes:
   - `<scan>/mobile_endpoints.json` — endpoints + hostnames extracted from APK static analysis.
   - `<scan>/secrets_sidecar.json` — hostnames + endpoints + Firebase project IDs from secrets-beyond-github sweep.
   - `<scan>/sso_tenants.json` — discovered IdP tenants for breach correlation.
2. Downstream modules check for sidecars on start; if present, ingest.
3. Cross-feed: API discovery consumes both `mobile_endpoints.json` and `secrets_sidecar.json`; SSO×breach correlation consumes `sso_tenants.json` and the breach DB.

**Sidecar shape (mobile_endpoints.json example):**
```json
{
  "endpoints": [
    {"method": "GET", "url": "https://api.acme.com/v1/users", "source": "apk:com.acme.android"},
    {"method": "POST", "url": "https://api.acme.com/v1/login", "source": "apk:com.acme.android"}
  ],
  "hostnames": ["api.acme.com", "cdn.acme.com"],
  "firebase_project_ids": ["acme-prod-12345"]
}
```

When you implement an ad-hoc multi-tool recon (no platform), use a `tmpdir + JSON sidecars + a one-line manifest` pattern. Composable, debuggable, replay-able.

---

## 48. Runnable Helper — `secret_scan.py`

Drop-in Python helper that mirrors the 29-pattern catalog from §17. Pure stdlib, no dependencies. For operator use against captured text.

```python
#!/usr/bin/env python3
"""Stdlib-only secret scanner. Mirrors the 29-pattern catalog.

Usage:
  echo "AKIAIOSFODNN7EXAMPLE" | python3 secret_scan.py
  python3 secret_scan.py file1.txt file2.js dir/

Output: one JSON object per line: {pattern, severity, category, match, file, line}
"""
import json
import os
import re
import sys

SEV_CRITICAL = "critical"
SEV_HIGH = "high"
SEV_MEDIUM = "medium"
SEV_LOW = "low"

PATTERNS = [
    ("AWS_ACCESS_KEY",       SEV_CRITICAL, "aws",         r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("AWS_SECRET_TYPED",     SEV_CRITICAL, "aws",         r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key['\"\s:=]+([A-Za-z0-9/+=]{40})"),
    ("AWS_SECRET_LOOSE",     SEV_HIGH,     "aws",         r"(?i)aws(.{0,20})?(secret|sk)[\"'=: ]+([0-9a-z/+=]{40})"),
    ("GCP_SERVICE_ACCOUNT",  SEV_CRITICAL, "gcp",         r'"type"\s*:\s*"service_account"'),
    ("GOOGLE_API_KEY",       SEV_HIGH,     "gcp",         r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("GH_PAT_CLASSIC",       SEV_CRITICAL, "github",      r"\bghp_[A-Za-z0-9]{36}\b"),
    ("GH_PAT_FINEGRAINED",   SEV_CRITICAL, "github",      r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    ("GH_OAUTH",             SEV_HIGH,     "github",      r"\bgho_[A-Za-z0-9]{36}\b"),
    ("GH_S2S",               SEV_HIGH,     "github",      r"\bgh[usr]_[A-Za-z0-9]{36,}\b"),
    ("STRIPE_LIVE",          SEV_CRITICAL, "stripe",      r"\bsk_live_[0-9A-Za-z]{24,}\b"),
    ("STRIPE_TEST",          SEV_LOW,      "stripe",      r"\bsk_test_[0-9A-Za-z]{24,}\b"),
    ("SLACK_TOKEN",          SEV_HIGH,     "slack",       r"\bxox[abpors]-[0-9A-Za-z\-]{10,48}\b"),
    ("SLACK_WEBHOOK",        SEV_MEDIUM,   "slack",       r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ("SENDGRID",             SEV_HIGH,     "email_svc",   r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    ("MAILGUN_V1",           SEV_HIGH,     "email_svc",   r"\bkey-[0-9a-zA-Z]{32}\b"),
    ("MAILGUN_LOOSE",        SEV_HIGH,     "email_svc",   r"\bkey-[0-9a-f]{32}\b"),
    ("TWILIO_API",           SEV_HIGH,     "twilio",      r"\bSK[0-9a-fA-F]{32}\b"),
    ("TWILIO_SID",           SEV_MEDIUM,   "twilio",      r"\bAC[a-f0-9]{32}\b"),
    ("TWILIO_AUTH",          SEV_HIGH,     "twilio",      r"(?i)twilio(.{0,20})?(auth|token)[\"'=: ]+([a-f0-9]{32})"),
    ("HEROKU_API",           SEV_MEDIUM,   "paas",        r"(?i)heroku(.{0,20})?api[\"'=: ]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"),
    ("FIREBASE_URL",         SEV_LOW,      "firebase",    r"\bhttps?://[a-z0-9\-]+\.firebaseio\.com\b"),
    ("JWT",                  SEV_MEDIUM,   "jwt",         r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ("BEARER_AUTH",          SEV_MEDIUM,   "bearer",      r"(?i)authorization[\"'=: ]+bearer\s+[A-Za-z0-9._\-]{20,}"),
    ("BASIC_AUTH_URL",       SEV_MEDIUM,   "basic_auth",  r"https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+"),
    ("RSA_PRIVKEY",          SEV_CRITICAL, "private_key", r"-----BEGIN RSA PRIVATE KEY-----"),
    ("EC_PRIVKEY",           SEV_CRITICAL, "private_key", r"-----BEGIN EC PRIVATE KEY-----"),
    ("OPENSSH_PRIVKEY",      SEV_CRITICAL, "private_key", r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("GENERIC_PRIVKEY",      SEV_CRITICAL, "private_key", r"-----BEGIN (DSA |PGP |)PRIVATE KEY-----"),
    ("GENERIC_API_KEY",      SEV_MEDIUM,   "generic",     r"(?i)(?:api[_\-]?key|apikey|api_secret|access_token|secret[_\-]?token)['\"\s:=]+[\"']([A-Za-z0-9+/=_\-]{24,})[\"']"),
]

COMPILED = [(n, s, c, re.compile(p)) for (n, s, c, p) in PATTERNS]

def scan_text(text: str, source: str = "<stdin>"):
    for line_no, line in enumerate(text.splitlines(), start=1):
        for name, sev, cat, rx in COMPILED:
            for m in rx.finditer(line):
                yield {
                    "pattern": name,
                    "severity": sev,
                    "category": cat,
                    "match": m.group(0)[:80],   # truncate to avoid huge dumps
                    "source": source,
                    "line": line_no,
                }

def scan_path(path: str):
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for f in files:
                p = os.path.join(root, f)
                yield from scan_path(p)
        return
    try:
        with open(path, "r", errors="replace") as fh:
            yield from scan_text(fh.read(), source=path)
    except Exception:
        return

def main():
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            for hit in scan_path(arg):
                print(json.dumps(hit))
    else:
        data = sys.stdin.read()
        for hit in scan_text(data):
            print(json.dumps(hit))

if __name__ == "__main__":
    main()
```

Save as `secret_scan.py`, then:
```bash
python3 secret_scan.py path/to/repo/        # scan a directory tree
python3 secret_scan.py file1 file2 file3    # scan specific files
cat my.log | python3 secret_scan.py         # pipe stdin
```

Output is JSONL — one finding per line — drops cleanly into `jq` for filtering or directly into a finding store.

---

## 49. Runnable Helper — `h1_reference.py`

HackerOne Hacktivity reference agent. Queries HackerOne's **public** GraphQL API for
disclosed reports during recon — no API key required (max 50 results/page). Use it to
surface validated techniques and business-impact framing for the target's tech stack
before you hunt. Pure stdlib.

```bash

# Best-validated techniques to start from
python3 h1_reference.py --top-voted --limit 25

# Highest-bounty reports (signal for impact framing)
python3 h1_reference.py --top-bounty --limit 25

# Scope to a class / CWE / program
python3 h1_reference.py --query "idor" --severity high critical
python3 h1_reference.py --cwe "CWE-918" --program <handle>
python3 h1_reference.py --lookup-program <handle>
```

Pairs with the bundled `docs/disclosed-reports/` pattern libraries: `h1_reference.py`
pulls live disclosed reports; the pattern libraries are the curated per-class digests.

## 50. Runnable Helper — `dashboard.py`

Zero-dependency localhost recon console that wraps `secret_scan.py` and
`h1_reference.py` behind a stdlib web UI. Binds to `127.0.0.1` by default — the scan
surface can read arbitrary local files you point it at, so it is never exposed to the
network.

```bash
python3 dashboard.py                 # http://127.0.0.1:8765
python3 dashboard.py --port 9000     # custom port
```

Use it for a fast visual pass — paste a blob or point at a path to aggregate secrets by
severity/category, and browse disclosed-report references — without leaving the box.

---


## SOURCE: hunt-skills/offensive-osint/references/identity-fabric.md

# Identity Fabric — Concrete Endpoints

> Reference content for the `offensive-osint` skill. Originally §22 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 22. Identity Fabric — Concrete Endpoints

Methodology lives in the companion `osint-methodology` skill §11. This is the URL/payload reference.

### 22.1 Microsoft Entra (Azure AD)

**OIDC metadata + tenant GUID extraction:**
```
GET https://login.microsoftonline.com/{tenant-or-domain}/.well-known/openid-configuration
```
Response field `issuer` contains the tenant GUID. GUID regex:
```regex
\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b
```
Detectability: low.

**getuserrealm.srf — managed vs federated probe:**
```
GET https://login.microsoftonline.com/getuserrealm.srf?login=<probe-user>@<domain>
```
Response: JSON with `NameSpaceType` field (`Managed` / `Federated` / `Unknown`). Federated also includes `FederationBrandName` and `AuthURL` (the upstream IdP URL). Detectability: low.

**Autodiscover v2:**
```
POST https://autodiscover-s.outlook.com/autodiscover/metadata/json/1
Body: {"Email": "<probe-user>@<domain>"}
```
Returns the protocol endpoint for the user; presence indicates tenant membership. Detectability: low.

**Autodiscover IP correlation (passive M365 confirmation):**

Resolve `autodiscover.<domain>` and check if it lands in Microsoft Exchange Online IP space. This works even when MX is wrapped by Mimecast/Proofpoint/Barracuda inbound filtering, where MX alone doesn't reveal the underlying mail platform.

```bash
dig +short A autodiscover.target.example
```
```powershell
Resolve-DnsName "autodiscover.$D" -Type A | Select Name,IPAddress
```

Microsoft Exchange Online IPs (truncated common ranges): `40.96.0.0/13`, `52.96.0.0/14`, `13.107.6.152/31`, `13.107.18.10/31`, `40.99.0.0/16`, `40.104.0.0/15`, `52.98.0.0/15`. Full list: [Office 365 URLs and IP address ranges](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges).

If `autodiscover.<domain>` lands in that space → `M365_CONFIRMED` even when nothing else does. Detectability: low (passive DNS).

**GetCredentialType — user-enum (deep mode only):**
```
POST https://login.microsoftonline.com/common/GetCredentialType
Content-Type: application/json
Body:
{
  "username": "<email>",
  "isOtherIdpSupported": true,
  "checkPhones": false,
  "isRemoteNGCSupported": true,
  "isCookieBannerShown": false,
  "isFidoSupported": true,
  "originalRequest": "",
  "country": "US",
  "forceotclogin": false,
  "isExternalFederationDisallowed": false,
  "isRemoteConnectSupported": false,
  "federationFlags": 0
}
```
Response field `IfExistsResult` indicates user existence: `0` = exists, `1` = doesn't exist, `5` = exists in federated tenant. Detectability: medium (logged in tenant audit). Cap at 20 attempts per tenant.

### 22.2 Okta

**Org slug derivation:** start with stems from discovered subdomains and root-domain stem. Probe `<slug>.okta.com` and `<slug>.oktapreview.com`. Slug regex:
```regex
[a-z0-9][a-z0-9-]{1,40}\.okta(?:preview)?\.com
```

**OIDC fingerprint:**
```
GET https://<slug>.okta.com/.well-known/openid-configuration
```

**/api/v1/authn user-enum (deep mode):**
```
POST https://<slug>.okta.com/api/v1/authn
Content-Type: application/json
Body: {"username": "<email>", "password": "invalid_password_for_enum"}
```
Response distinguishes user existence:
- `400` with `errorCode: E0000004` → user doesn't exist (or generic password error in some configs).
- `401` with `status: PASSWORD_WARN` / `LOCKED_OUT` / `MFA_REQUIRED` → user exists.
Detectability: medium (audit-log per attempt). Cap at 20 attempts per tenant.

### 22.3 ADFS

**Passive fingerprint:**
```
GET https://{domain}/adfs/idpinitiatedsignon.aspx
```
A `200 OK` with a `urn:com:microsoft:ADFS:` reference in HTML indicates ADFS. Version-string greppable in HTML resource references.

**Mex endpoint (deep mode):**
```
GET https://{domain}/adfs/Services/Trust/mex
```
Returns SOAP federation metadata including endpoint URLs, signing certs, and supported claim types.

### 22.4 Google Workspace

**OIDC discovery:**
```
GET https://{domain}/.well-known/openid-configuration
```
Google-Workspace-hosted-domain customers expose discovery endpoints with characteristic `issuer` URI (`https://accounts.google.com`) and JWKS URI. MX records pointing to `aspmx.l.google.com` are a corroborating signal.

### 22.5 Generic OIDC (Keycloak / Auth0 / Ping / OneLogin / Duo)

**Discovery:** probe `/.well-known/openid-configuration` on every alive subdomain. The `issuer` and `authorization_endpoint` field URLs fingerprint the product:

| Product | URL pattern in `issuer` |
|---|---|
| Auth0 | `https://*.auth0.com` |
| OneLogin | `https://*.onelogin.com` |
| Ping | `https://*.pingone.com`, `https://*.pingidentity.com` |
| Duo | `https://*.duosecurity.com` |
| Keycloak | URL contains `/realms/<realm>` |
| OneLogin | `https://*.onelogin.com` |

### 22.7 AWS account-ID extraction

**S3 bucket region header (passive):**
```
HEAD https://<known-bucket>.s3.amazonaws.com/
```
Response includes `x-amz-bucket-region`. Cross-reference with bucket name entropy and known patterns to scope the account.

**ARN regex (in any JSON / HTML / JS response):**
```regex
arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:([0-9]{12}):
```
Capture group: 12-digit AWS account ID.

**`AccountId` property pattern:**
```regex
(?i)["']?account[_\-]?id["']?\s*[:=]\s*["']([0-9]{12})["']
```

**Google OAuth client_id:**
```regex
\b\d{8,}-[a-z0-9]{10,40}\.apps\.googleusercontent\.com\b
```

**MSAL / Microsoft client_id (GUID property):**
```regex
(?i)["']?client[_\-]?id["']?\s*[:=]\s*["']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']
```

**OAuth scope extraction:**
```regex
(?i)["']?scope["']?\s*[:=]\s*["']([^"']+)["']
```

### 22.8 Microsoft 365 Deep Enumeration (Teams / SharePoint / OneDrive / OAuth)

**Teams federation status:**
```bash

# Resolve tenant first
curl -sk -m 10 "https://login.microsoftonline.com/${TARGET_DOMAIN}/.well-known/openid-configuration" | jq -r '.issuer'

# Federation API requires authenticated request from a federated tenant; presence of error pattern reveals fed status
curl -sk -m 10 "https://teams.microsoft.com/api/mt/emea/beta/users/<email>/externalsearchv3"
```

**SharePoint subdomain probe:**
```bash
STEM=$(echo $TARGET_DOMAIN | cut -d. -f1)
for sub in "" "-my" "-admin"; do
  echo "=== ${STEM}${sub}.sharepoint.com ==="
  curl -sk -m 10 -I "https://${STEM}${sub}.sharepoint.com/" -w '%{http_code}\n'
done
```

**Reading the result correctly:** `HTTP 200` from these probes means **the tenant exists** (Microsoft serves a generic redirect-to-auth page) — it does **NOT** mean anonymous access is granted to the tenant's content. Distinguish:
- 200 → tenant provisioned (INFO).
- 200 + redirect to a custom anonymous-share URL (`/sites/<x>/Lists/<y>/AllItems.aspx?guestaccesstoken=...`) discovered via dorks → HIGH (data exposure).
- 401/403 → tenant exists but auth required (INFO).
- 404 / NXDOMAIN → tenant not provisioned at this stem (or vanity-named — check known stems from cert transparency).

PowerShell:
```powershell
$STEM = ($D -split '\.')[0]
foreach ($s in @("","-my","-admin")) {
  try {
    $r = Invoke-WebRequest -Uri "https://${STEM}${s}.sharepoint.com/" -Method Head -UseBasicParsing -TimeoutSec 10
    "${STEM}${s}.sharepoint.com -> HTTP $($r.StatusCode) (tenant exists)"
  } catch {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code) { "${STEM}${s}.sharepoint.com -> HTTP $code" } else { "${STEM}${s}.sharepoint.com -> no host" }
  }
}
```

**OneDrive personal site probe** (for a known email `alice@acme.com`):
```bash
USER_TOKEN=$(echo "alice@acme.com" | tr '@.' '__')
STEM="acme"
curl -sk -m 10 -I "https://${STEM}-my.sharepoint.com/personal/${USER_TOKEN}/Documents/" -w '%{http_code}\n'

# 401 = exists; 404 = not provisioned
```

**M365 OAuth client_id discovery in JS:**
```bash
curl -sk -m 10 "https://app.target.example/main.js" | \
  grep -oE 'clientId["'\''[:=]+ ?["'\'']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
```

**Device-code phishing target check** (look for `device_authorization_endpoint` in OIDC metadata):
```bash
curl -sk -m 10 "https://login.microsoftonline.com/${TARGET_DOMAIN}/v2.0/.well-known/openid-configuration" | \
  jq '.device_authorization_endpoint'
```
If non-null and tenant doesn't restrict device-code: MEDIUM finding (device-code phishing feasible).

**Power Platform / Dynamics URLs to check:**
- `*.crm.dynamics.com` (per-region: `crm`, `crm2`-`crm15`, `crm.dynamics.com`).
- `*.api.crm.dynamics.com` (Web API).
- `make.powerapps.com` / `flow.microsoft.com` (auth-required dashboards).

**Severity:**
- Discovered SharePoint/OneDrive tenants → INFO (asset only).
- Anonymous SharePoint anonymous-share link → HIGH (data exposure).
- `device_authorization_endpoint` enabled on tenant → MEDIUM (operational risk).
- Multi-tenant OAuth app with broad Graph scopes published by target → HIGH.

### 22.9 GraphQL Field-Suggestion Enumeration (when introspection disabled)

When the standard introspection query (§16.2) returns `"errors":[{"message":"GraphQL introspection is disabled"}]`, fall back to field-suggestion enumeration. Apollo and most GraphQL libraries enable "did you mean" suggestions by default.

**Detection probe:**
```bash
curl -sk -m 10 -X POST "$T/graphql" \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { types { name } } }"}' | jq -r '.errors[0].message'

# If "introspection disabled" → proceed.
```

**Field-suggestion probe** (intentionally typo a field name to trigger suggestions):
```bash
curl -sk -m 10 -X POST "$T/graphql" \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ usre { id } }"}' | jq -r '.errors[].message'

# Expected: "Cannot query field \"usre\" on type \"Query\". Did you mean \"user\", \"users\", \"userById\"?"
```

Iterate over a candidate-field wordlist (use SecLists `Discovery/Web-Content/graphql.txt` or `clairvoyance` library's seed list). Each suggestion reveals real field names. Continue until no new suggestions emerge.

**Tooling:**
- **Clairvoyance** (`pip install clairvoyance`) — automated field-suggestion enumerator. `clairvoyance -w wordlist.txt -o schema.json https://target.example/graphql`.
- **GraphQL-Cop** — auditor that probes for introspection, batching, depth-limit, suggestion config. `pip install graphql-cop`.
- **InQL** (Burp extension) — Burp Suite extension for GraphQL endpoint analysis.
- **GraphQL Voyager** — visualize once schema is reconstructed.

**Other GraphQL-when-introspection-disabled techniques:**

- **Alias-based query batching** (rate-limit / auth-bypass surface):
  ```json
  {
    "query": "{ a:user(id:1){name} b:user(id:2){name} c:user(id:3){name} ... }"
  }
  ```
  Many APIs rate-limit per-request, not per-alias. Test 100+ aliases per request.

- **Query-depth-limit bypass** (DoS / introspection bypass):
  ```json
  {
    "query": "{ user { friends { friends { friends { friends { id } } } } } }"
  }
  ```
  If server allows arbitrary depth → DoS surface; if depth-limited but doesn't strip nested `__type`/`__schema` → introspection-via-depth.

- **Subscription enumeration via WebSocket:**
  ```bash
  wscat -c "wss://target.example/graphql" -s graphql-ws
  > {"type":"connection_init"}
  > {"id":"1","type":"start","payload":{"query":"subscription { __schema { types { name } } }"}}
  ```

- **Batched query bypass** (some servers process all queries in batch even if first fails):
  ```json
  [
    {"query":"{ __schema { types { name } } }"},
    {"query":"{ user(id:1) { name } }"}
  ]
  ```

**Severity:**
- Field-suggestion enumeration succeeds (50+ fields recoverable) → MEDIUM `MISCONFIG`.
- Alias batching not rate-limited → MEDIUM (rate-limit-bypass surface).
- Subscription endpoint exposed without auth → MEDIUM (often used for real-time data exfil).

---


## SOURCE: hunt-skills/offensive-osint/references/people-osint.md

# People, Username, Phone, Social, Public Records OSINT

> Reference content for the `offensive-osint` skill. Originally §7 + §8 + §9 + §10 + §13 + §14 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 7. Search Engines

| Tool | Notes |
|------|-------|
| [Carrot2](https://search.carrot2.org/#/search/web) | Clusters results by topic |
| [etools](https://www.etools.ch/) | Metasearch |
| [Kagi](https://kagi.com/) | Privacy-first, non-personalized |
| [Brave Search](https://search.brave.com/) | Independent index; Goggles for custom ranking |
| [PDF Search](https://www.pdfsearch.io/) | PDF + table of contents |
| [Google Fact Check Explorer](https://toolbox.google.com/factcheck/explorer) | Cross-site fact-check |

---

## 8. Username & Email Investigation

| Tool | Purpose |
|------|---------|
| [Sherlock](https://github.com/sherlock-project/sherlock) | Username search across social networks |
| [Maigret](https://github.com/soxoj/maigret) | Profile collector by username |
| [What's My Name](https://whatsmyname.app/) | Username search |
| [Holehe](https://github.com/megadose/holehe) | Email registration check |
| [Epieos](https://epieos.com/) | Email pivots and metadata |
| [OSINT Industries](https://osint.industries/) | Email/username/phone lookups |
| [Hunter.io](https://hunter.io/) | Domain → emails |
| [EmailRep](https://emailrep.io/) | Email reputation |
| [Emailable](https://emailable.com/) | Email verification |
| [Mugetsu](https://mugetsu.io/) | X/Twitter username history |
| [RocketReach](https://rocketreach.co/) / [Apollo](https://www.apollo.io/) | Email enrichment + pattern guessing |
| [PhoneInfoga](https://github.com/sundowndev/phoneinfoga) | Phone number intelligence |

Browser extensions: [GetProspect](https://chromewebstore.google.com/detail/email-finder-getprospect/bhbcbkonalnjkflmdkdodieehnmmeknp), [SignalHire](https://chrome.google.com/webstore/detail/signalhire-find-email-or/aeidadjdhppdffggfgjpanbafaedankd).

---

## 9. People Search

- [TruePeopleSearch](https://www.truepeoplesearch.com/) — free U.S. people search.
- [WhitePages](https://www.whitepages.com/), [Spokeo](https://www.spokeo.com/), [Webmii](https://webmii.com/), [Pipl](https://pipl.com/) (paid).
- [Clearbit](https://clearbit.com/) — company/individual data enrichment.
- [FaceCheck](https://facecheck.id/) / [FaceSeek](https://faceseek.online/) — reverse face search.

---

## 10. Phone Number OSINT

- [TrueCaller](https://www.truecaller.com/) — caller ID + spam blocking.
- [ThatsThem](https://thatsthem.com/) — reverse phone search.
- [Infobel](https://infobel.com/) — non-USA phone search.
- [FreeCarrierLookup](https://freecarrierlookup.com/) — carrier/type (US).
- [NumlookupAPI](https://numlookupapi.com/) [Freemium] — programmatic carrier checks.
- [CallerIDTest](https://calleridtest.com/), [Advanced Background Checks](https://www.advancedbackgroundchecks.com/).

---

## 13. Social Media

| Platform | Tool |
|----------|------|
| Instagram | [Picuki](https://www.picuki.com/) — profile view without account |
| X/Twitter | [snscrape](https://github.com/snscrape/snscrape) — preferred CLI scraper; Twint as fallback |
| Facebook | [Graph Search](https://inteltechniques.com/tools/Facebook.html), [sowsearch.info](https://sowsearch.info/), [lookup-id.com](https://lookup-id.com/), [whopostedwhat.com](https://whopostedwhat.com/) |
| Facebook (research) | [Meta Content Library](https://transparency.meta.com/researcher) — CrowdTangle successor (researcher-gated) |
| YouTube/Twitch | [Social Blade](https://socialblade.com/) — analytics |
| TikTok | [Tokboard](https://tokboard.com/) — trends + profile analytics |
| Reddit | [Reveddit](https://www.reveddit.com/) — removed content; [RedTrack.social](https://redtrack.social/) — user history |
| Bluesky | [Firesky](https://firesky.tv/) — real-time firehose; [SkyView](https://bsky.jazco.dev/) — follower graphs |
| Mastodon | [FediSearch](https://fedisearch.skorpil.cz/) — cross-instance search; [Fedifinder](https://fedifinder.glitch.me/) — find Twitter users on Mastodon |
| Faces | [Search4Faces](https://search4faces.com/) |

---

## 14. Public Records & Company Information

- [OpenCorporates](https://opencorporates.com/) — world's largest open company DB.
- [SEC EDGAR](https://www.sec.gov/edgar.shtml) — U.S. company filings.
- [OpenOwnership Register](https://register.openownership.org/) — beneficial ownership.
- [MuckRock](https://www.muckrock.com/) — FOIA repository + request tracking.
- [EU Tenders (TED)](https://ted.europa.eu/) — EU procurement notices.
- [World Bank Projects](https://projects.worldbank.org/) — project + procurement records.
- [UK Companies House](https://find-and-update.company-information.service.gov.uk/) — UK companies + officers + filings.

### 14.1 RU registries

[Rusprofile](https://www.rusprofile.ru/), [Kontur.Focus](https://focus.kontur.ru/) (freemium), [zakupki.gov.ru](https://zakupki.gov.ru/) (procurement), EGRUL/EGRIP (official, captcha-gated).

### 14.2 CN registries + USCC + ICP

- **GSXT** — [gsxt.gov.cn](https://www.gsxt.gov.cn/) National Enterprise Credit Info; cross-check with Tianyancha / Qichacha.
- **USCC (Unified Social Credit Code)** — 18-character entity ID assigned to all CN legal entities. Format: `<region:6><authority:2><type:1><serial:9>`. Useful for joining GSXT records to ICP filings.
- **ICP Beian** — [beian.miit.gov.cn](https://beian.miit.gov.cn/) — every domain serving traffic in mainland CN must register an ICP filing; the filing links the domain to a USCC, which links to the legal entity in GSXT.
- Workflow: `target.cn` domain → ICP lookup → USCC → GSXT → entity name + officers + adjacent registered entities.

### 14.3 Sanctions & Compliance

- [OFAC SDN List](https://sanctionssearch.ofac.treas.gov/), [EU Sanctions Map](https://www.sanctionsmap.eu/).
- [OpenSanctions](https://www.opensanctions.org/) — aggregated.
- [OCCRP Aleph](https://aleph.occrp.org/) — investigative documents, leaks, company records.

---


## SOURCE: hunt-skills/offensive-osint/references/probes-and-wordlists.md

# Probes & Wordlists

> Reference content for the `offensive-osint` skill. Originally §16 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 16. Pre-built Wordlists & Probe Paths

Copy-pasteable arsenals, severity-annotated where relevant.

### 16.1 Swagger / OpenAPI discovery — 28 paths

Probe each path on every alive webapp. GET (or HEAD if rate-limited).

```
swagger.json
swagger.yaml
swagger/v1/swagger.json
swagger/v2/swagger.json
swagger-ui.html
swagger-ui/
swagger-resources
api-docs
api-docs.json
api/swagger
api/swagger.json
api/swagger-ui.html
api/v1/swagger.json
api/v2/swagger.json
api/v3/api-docs
v2/api-docs
v3/api-docs
openapi.json
openapi.yaml
openapi/v1
openapi/v3
docs
redoc
rapidoc
api/docs
api/documentation
.well-known/openapi
```

**Severity:**
- Reachable Swagger/OpenAPI spec without auth → **HIGH** `LEAKY_API_SPEC` (full endpoint enumeration leaks; often reveals undocumented internal APIs).
- Behind auth but accessible to any authenticated user → MEDIUM (still discloses internal API surface).

### 16.2 GraphQL discovery — 13 paths

```
graphql
graphiql
api/graphql
v1/graphql
v2/graphql
query
api/query
gql
altair
playground
subscriptions
graphql/console
api/v1/graphql
```

**Standard introspection POST body:**
```json
{
  "operationName": "IntrospectionQuery",
  "query": "query IntrospectionQuery { __schema { types { name kind fields { name type { name kind } } } queryType { name } mutationType { name } subscriptionType { name } } }"
}
```

**Severity:**
- Introspection returns schema without auth → **HIGH** `OPEN_GRAPHQL_API`.
- Field-suggestion enumeration possible (server returns "did you mean" for typo'd field names) → **MEDIUM** (re-derive partial schema even when introspection is disabled).
- `/graphql` accepts batched queries (`[...]` request body) → MEDIUM (rate-limit bypass surface; auth bypass via mixed batches).

UI markers (lower severity but still discoverable):
- HTML response contains `graphiql`, `playground`, `apollo studio`, `altair` → GraphiQL UI exposed (often shipped accidentally on prod).

### 16.3 High-risk ports — 35 services

For each open port, emit a finding with the severity and "why an attacker cares" below. Source for the open-port observation: Shodan InternetDB (free, 1 req/sec) is the recommended starting point.

| Port | Service | Severity | Why it matters |
|---|---|---|---|
| 21 | FTP | HIGH | Anonymous read often enabled; cleartext creds. |
| 22 | SSH | LOW | Banner discloses version; brute-force surface. |
| 23 | Telnet | HIGH | Cleartext protocol; should never be exposed. |
| 25 | SMTP | LOW | Open relay risk; version banner. |
| 53 | DNS | LOW | Recursion = DDoS amplifier; AXFR opportunism. |
| 80 | HTTP | INFO | Standard. |
| 110 | POP3 | LOW | Cleartext if no STARTTLS. |
| 111 | rpcbind | MEDIUM | NFS exports enumeration. |
| 135 | MS RPC | HIGH | Enum via Impacket. |
| 139 | NetBIOS-SSN | HIGH | File/printer enum. |
| 143 | IMAP | LOW | Cleartext if no STARTTLS. |
| 161 | SNMP | HIGH | Community strings often `public`/`private`; full device enum. |
| 389 | LDAP | HIGH | Anonymous bind = full directory dump. |
| 443 | HTTPS | INFO | Standard. |
| 445 | SMB | **CRITICAL** | EternalBlue, SMB relay, anonymous shares. |
| 465 | SMTPS | LOW | Banner. |
| 514 | rsyslog | MEDIUM | Log injection / DoS. |
| 587 | SMTP-MSA | LOW | Banner. |
| 631 | IPP/CUPS | MEDIUM | Print server enum / RCE in old CUPS. |
| 873 | rsync | HIGH | Modules often listable; backup data exposure. |
| 1433 | MSSQL | HIGH | Brute-force; xp_cmdshell. |
| 1521 | Oracle TNS | HIGH | Brute-force; SID enum. |
| 2049 | NFS | HIGH | World-readable exports. |
| 2375 | Docker API (unencrypted) | **CRITICAL** | Unauthenticated container/host takeover. |
| 2376 | Docker API (TLS) | HIGH | Cert validation bypass risk. |
| 3000 | Common dev / Grafana | MEDIUM | Often Grafana / Express dev with default creds. |
| 3306 | MySQL | HIGH | Brute-force; default `root:""`. |
| 3389 | RDP | **CRITICAL** | BlueKeep / DejaBlue / NLA bypass. |
| 5432 | PostgreSQL | HIGH | Brute-force; default `postgres:postgres`. |
| 5601 | Kibana | HIGH | Often unauthenticated; Elasticsearch pivot. |
| 5900 | VNC | HIGH | Often unauthenticated or weak password. |
| 5984 | CouchDB | HIGH | Default no auth; admin party. |
| 6379 | Redis | **CRITICAL** | No auth default; write `authorized_keys` for SSH. |
| 7001 | WebLogic | HIGH | Frequent CVEs (CVE-2020-14882, etc.). |
| 8000 | Common dev | MEDIUM | Django, common dev servers. |
| 8080 | HTTP-alt | MEDIUM | Tomcat, Jenkins, common proxy. |
| 8443 | HTTPS-alt | MEDIUM | Same as 8080. |
| 8888 | Common dev / Jupyter | HIGH | Jupyter often exposes interactive shell. |
| 9090 | Cockpit / Prometheus | HIGH | Server admin UI / metrics scraping. |
| 9200 | Elasticsearch | **CRITICAL** | Typically no auth. |
| 9300 | Elasticsearch transport | HIGH | Cluster join + RCE. |
| 11211 | memcached | MEDIUM | UDP DDoS amp; data dump. |
| 27017 | MongoDB | **CRITICAL** | No auth by default. |
| 50070 | Hadoop NameNode | HIGH | HDFS browse. |

When Shodan InternetDB returns `vulns[]` for a port, escalate the finding severity by one tier and include the CVE list in evidence.

### 16.4 Missing security headers — 6 findings

For every alive webapp, audit response headers. Each missing header below = one finding.

| Header | Severity (default) | Severity (sensitive path) | Notes |
|---|---|---|---|
| `Strict-Transport-Security` | MEDIUM | **HIGH** | Sensitive paths: `/login`, `/signin`, `/sso`, `/admin`, `/auth`. |
| `Content-Security-Policy` | MEDIUM | MEDIUM | XSS impact mitigation gone. |
| `X-Frame-Options` | LOW | LOW | Clickjacking. (CSP `frame-ancestors` is the modern replacement.) |
| `X-Content-Type-Options` | LOW | LOW | MIME-sniff XSS. |
| `Referrer-Policy` | INFO | INFO | Outbound link leakage. |
| `Permissions-Policy` | INFO | INFO | Feature-policy hardening. |

### 16.5 Always-on HTTP checks — 15 paths

Run these against every alive webapp regardless of Nuclei availability. Cheap; high signal.

| Path | Finding | Severity | Match logic |
|---|---|---|---|
| `/.git/config` | Exposed `.git` repo | **CRITICAL** | Body contains `[core]`, `[remote`, `repositoryformatversion` |
| `/.git/HEAD` | Exposed `.git/HEAD` | HIGH | Body matches `^ref:\s` |
| `/.env` | Exposed `.env` | **CRITICAL** | Multiline regex `^\s*[A-Z_][A-Z0-9_]*\s*=` |
| `/server-status` | Apache server-status | MEDIUM | Body contains `Apache Server Status` or matching title |
| `/server-info` | Apache mod_info | MEDIUM | Body contains `Apache Server Information` |
| `/.DS_Store` | Exposed `.DS_Store` | LOW | Byte signature `\x00\x00\x00\x01Bud1` |
| `/phpinfo.php` | phpinfo() leak | HIGH | Body contains `phpinfo()`, `PHP Version`, or matching title |
| `/info.php` | phpinfo() (alt path) | HIGH | Same as above |
| `/actuator/env` | Spring Boot `/actuator/env` | **CRITICAL** | Body contains `"propertySources"`, `systemProperties`, `systemEnvironment` |
| `/actuator/heapdump` | Spring Boot heapdump | **CRITICAL** | HPROF magic bytes / large binary download |
| `/_cat/indices` | Elasticsearch open | HIGH | Returns index list |
| `/console` | Jenkins script console | HIGH | Body contains `Jenkins`/`Script Console` |
| `/manager/html` | Tomcat Manager | HIGH | Body contains `Tomcat Web Application Manager` |
| `/wp-admin/install.php` | Orphaned WP install | LOW | Body contains `WordPress Installation` |
| `/.well-known/security.txt` | Disclosure policy info | INFO | Parse contact + policy fields |

Plus parse `/robots.txt` for `Disallow:` paths — those become the next-tier wordlist for that target.

### 16.6 SAML metadata — 5 paths

```
/saml/metadata
/FederationMetadata/2007-06/FederationMetadata.xml
/federationmetadata/2007-06/federationmetadata.xml
/simplesaml/saml2/idp/metadata.php
/auth/saml2/metadata
```

Reachable SAML metadata XML reveals: `EntityID`, signing certs (often pinned → cert-reuse pivot), `SingleSignOnService` URL, `NameIDFormat`. Mark as `MISCONFIG` (LOW severity unless metadata leaks internal hostnames or non-public certs, then MEDIUM).

### 16.7 SSO subdomain prefixes — 8 prefixes

Probe each against root domain + every sibling brand domain:
```
auth.{domain}
login.{domain}
sso.{domain}
idp.{domain}
iam.{domain}
identity.{domain}
accounts.{domain}
oauth.{domain}
```

Plus probe `/.well-known/openid-configuration` on every alive subdomain (regardless of prefix).

### 16.8 Cloud bucket permutation arsenal

**6 prefixes:**
```
""           # bare candidate
backup-
assets-
static-
dev-
prod-
```

**15 suffixes:**
```
""           # bare candidate
-backup
-assets
-static
-media
-data
-uploads
-dev
-prod
-staging
-logs
-private
-public
-dump
-archive
```

**47 generic stems** (filter unless combined with target-identifying token):
```
www, mail, email, app, apps, web, webmail, ftp, cdn, static, assets, media, img, images,
videos, download, downloads, upload, uploads, data, files, docs, support, help, kb,
blog, news, dev, test, staging, stg, qa, uat, sandbox, preprod, preview, vpn,
mx, smtp, imap, pop, dns, ns, ns1, ns2, mx1, mx2
```

**Provider URL templates:**

S3:
```
https://{candidate}.s3.amazonaws.com/
https://{candidate}.s3-{region}.amazonaws.com/      # try us-east-1, us-west-2, eu-west-1, ap-southeast-1 first
https://s3.{region}.amazonaws.com/{candidate}/
```

GCS:
```
https://{candidate}.storage.googleapis.com/
https://storage.googleapis.com/{candidate}/
```

Azure Blob:
```
https://{candidate}.blob.core.windows.net/
```

**Probe technique:** HEAD first → 200/301 = exists, 403 = exists private, 404 = skip. On exists, GET root → if XML/JSON object listing returns, **CRITICAL** `PUBLIC_CLOUD_BUCKET`. Direct-URL object reads but not listable → **HIGH** `PUBLIC_CLOUD_BUCKET_OBJECT_READ`.

### 16.9 JS guess-paths for endpoint discovery

Probe these paths on every alive webapp (in addition to scraped `<script src=...>`):

```
/main.js
/app.js
/bundle.js
/runtime.js
/index.js
/vendor.js
/_next/static/_buildManifest.js
/_next/static/_ssgManifest.js
/static/js/main.js
/static/js/bundle.js
/assets/index.js
/static/js/main.<hash>.js                 # try hash discovery via 404 patterns
```

For every found JS, also try `<jsfile>.map` for sourcemap leaks (HIGH `INFO_DISCLOSURE`).

### 16.10 Endpoint extraction regex tiers

Three tiers, run in order on every JS body + every sourcesContent[] blob:

**Tier 1 — generic quoted paths:**
```regex
['"`](/[A-Za-z0-9_\-./{}\[\]?=&%:]+)['"`]
```
Match group: the path. High recall, lots of false positives — apply allowlist downstream.

**Tier 2 — API-ish paths (biased filter on tier 1):**
```regex
['"`](/(?:api|graphql|gql|v\d+|swagger|openapi|rest|services|internal|admin|auth|oauth|user|users|account|accounts|search|export|upload|file|files|download|webhook|hooks|callback|admin)/[A-Za-z0-9_\-./{}\[\]?=&%:]+)['"`]
```

**Tier 3 — fully-qualified URLs:**
```regex
\bhttps?://[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(?::\d+)?[/A-Za-z0-9_\-./{}\[\]?=&%:#]*
```

Dedup on `(method, normalized-path-template)` where the template replaces `/123/` with `/{id}/` etc.

### 16.11 Internal-host leakage regexes

Run on every JS body + sourcesContent + APK strings + manifest:

**RFC1918:**
```regex
\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3})\.(?:\d{1,3})|192\.168\.(?:\d{1,3})\.(?:\d{1,3})|127\.(?:\d{1,3}\.){2}\d{1,3})\b
```

**Internal DNS suffixes:**
```regex
\b[A-Za-z0-9][A-Za-z0-9\-]{0,62}\.(?:internal|corp|lan|intranet|local|prod|staging|dev|qa|test)\b
```

**Kubernetes service DNS:**
```regex
\b[A-Za-z0-9\-]+\.[A-Za-z0-9\-]+\.svc(?:\.cluster\.local)?\b
```

Each match → MEDIUM `INFO_DISCLOSURE`. Aggregate per host: if many matches share the same internal subdomain, that's a recon seed for any future internal phase.

### 16.12 Subdomain-takeover provider fingerprints (summary, 27 providers)

Watch for these CNAME targets + the corresponding "available for claim" response signature:

| Provider | CNAME pattern | Takeover signature |
|---|---|---|
| GitHub Pages | `*.github.io` | `There isn't a GitHub Pages site here.` |
| Heroku | `*.herokuapp.com` | `No such app` |
| AWS S3 | `*.s3*.amazonaws.com` | `NoSuchBucket` |
| AWS CloudFront | `*.cloudfront.net` | `Bad request` w/ specific X-Amz error |
| Azure (multiple) | `*.azurewebsites.net`, `*.blob.core.windows.net`, `*.cloudapp.net`, `*.trafficmanager.net` | Various per-product 404 patterns |
| Shopify | `shops.myshopify.com` | `Sorry, this shop is currently unavailable.` |
| Squarespace | `*.squarespace.com` | `No Such Account` |
| Tumblr | `*.tumblr.com` | `Whatever you were looking for doesn't currently exist.` |
| WordPress | `*.wordpress.com` | `Do you want to register *.wordpress.com?` |
| Fastly | various | Fastly-specific 404 |
| Pantheon | `*.pantheonsite.io` | `The gods are wise, but do not know of the site...` |
| Surge.sh | `*.surge.sh` | `project not found` |
| Bitbucket Pages | `*.bitbucket.io` | Repository not found |
| Tilda | `*.tilda.ws` | `Please renew your subscription` |
| Strikingly | `*.s.strikinglydns.com` | `PAGE NOT FOUND` |
| Smartling | `*.smartling.com` | Domain is not configured |
| Ngrok | `*.ngrok.io` | Tunnel not found |
| Webflow | `*.webflow.io` | Site not found |
| Zendesk | `*.zendesk.com` | `Help Center Closed` |
| Cargo | `*.cargocollective.com` | `404 Not Found` (with cargo branding) |
| Statuspage | `*.statuspage.io` | Not found |
| Intercom | `*.intercom.help` | Not found |
| Helpjuice | `*.helpjuice.com` | Not found |
| Helpscout | `*.helpscoutdocs.com` | Not found |
| Tictail | `*.tictail.com` | Not found |
| Brightcove | `*.brightcovegallery.com` | Not found |
| Smugmug | various | Not found |

For full per-provider detection signatures + edge cases, use SubdomainX or Subzy/Subjack against a freshly-fetched fingerprint database.

---

### 16.13 Copy-Paste Probes (curl one-liners)

Every probe path in §16.1–16.12 with a runnable curl. Defaults: `-sk` (silent + ignore TLS errors), `-m 10` (10s max), `-o /tmp/r` (response body to disk), `-w '%{http_code}\n'` (print status code), `-A "Mozilla/5.0"` (UA — change per persona).

**Always-on HTTP checks (§16.5):**

```bash
T="https://target.example"

# .git/config (CRITICAL)
curl -sk -m 10 "$T/.git/config" | grep -E '\[core\]|\[remote|repositoryformatversion'

# Apache /server-status (MEDIUM)
curl -sk -m 10 "$T/server-status" | grep -i 'Apache Server Status'

# Apache /server-info (MEDIUM)
curl -sk -m 10 "$T/server-info" | grep -i 'Apache Server Information'

# .DS_Store (LOW)
curl -sk -m 10 "$T/.DS_Store" -o /tmp/dsstore && file /tmp/dsstore | grep -i 'data'

# phpinfo.php (HIGH)
curl -sk -m 10 "$T/phpinfo.php" | grep -E 'phpinfo\(\)|PHP Version'

# Spring Boot /actuator/env (CRITICAL)
curl -sk -m 10 "$T/actuator/env" | grep -E '"propertySources"|systemProperties|systemEnvironment'

# Spring Boot /actuator/heapdump (CRITICAL — saves binary; check size)
curl -sk -m 30 "$T/actuator/heapdump" -o /tmp/heap && file /tmp/heap | grep -i 'HPROF\|data'

# Jenkins script console (HIGH)
curl -sk -m 10 "$T/script" | grep -iE 'Jenkins|Script Console'

# Tomcat manager (HIGH)
curl -sk -m 10 "$T/manager/html" -w '%{http_code}\n' | tail -1     # 401 = present + auth-gated; 200 = no auth

# WordPress orphan installer (LOW)
curl -sk -m 10 "$T/wp-admin/install.php" | grep -i 'WordPress Installation'

# security.txt (INFO)
curl -sk -m 10 "$T/.well-known/security.txt"
```

**SSO subdomain prefixes (§16.7):**

```bash
D="target.example"
for prefix in auth login sso idp iam identity accounts oauth; do
  echo "=== ${prefix}.${D} ==="
  curl -sk -m 10 "https://${prefix}.${D}/.well-known/openid-configuration" -o /dev/null -w '%{http_code}\n'
done

# Generic OIDC discovery on any host:
curl -sk -m 10 "https://${HOST}/.well-known/openid-configuration" | jq .
```

**SAML metadata paths (§16.6):**

```bash
H="target.example.com"
for p in /saml/metadata \
         /FederationMetadata/2007-06/FederationMetadata.xml \
         /federationmetadata/2007-06/federationmetadata.xml \
         /simplesaml/saml2/idp/metadata.php \
         /auth/saml2/metadata; do
  echo "=== $p ==="
  curl -sk -m 10 "https://${H}${p}" -o /dev/null -w '%{http_code} %{size_download}\n'
done
```

**Cloud bucket probes (§16.8):**

```bash
B="candidate-bucket-name"

# S3 (us-east-1 first)
curl -sk -m 10 -I "https://${B}.s3.amazonaws.com/" -w 'STATUS:%{http_code}\n' | head -20

# If 200/301: list objects
curl -sk -m 10 "https://${B}.s3.amazonaws.com/?list-type=2" | head -50

# S3 region-specific
for r in us-east-1 us-west-2 eu-west-1 ap-southeast-1; do
  curl -sk -m 10 -I "https://${B}.s3-${r}.amazonaws.com/" -w "${r}: %{http_code}\n"
done

# GCS
curl -sk -m 10 -I "https://${B}.storage.googleapis.com/"
curl -sk -m 10 "https://storage.googleapis.com/${B}/"

# Azure Blob
curl -sk -m 10 -I "https://${B}.blob.core.windows.net/"
curl -sk -m 10 "https://${B}.blob.core.windows.net/?comp=list"
```

**GraphQL introspection POST (§16.2):**

```bash
H="https://target.example/graphql"

curl -sk -m 15 -X POST "$H" \
  -H 'Content-Type: application/json' \
  -d '{
    "operationName":"IntrospectionQuery",
    "query":"query IntrospectionQuery { __schema { types { name kind fields { name type { name kind } } } queryType { name } mutationType { name } subscriptionType { name } } }"
  }' | jq '.data.__schema.types | length'
```

**Read-only secret validators (§23):**

```bash

# Postman PMAK
curl -sk -m 10 -H "X-Api-Key: PMAK-..." https://api.getpostman.com/me | jq .

# AWS (use boto3 instead of curl — pre-signing complexity)
python3 -c "import boto3; print(boto3.client('sts', aws_access_key_id='AKIA...', aws_secret_access_key='...').get_caller_identity())"

# GitHub PAT (note scope header)
curl -sk -m 10 -H "Authorization: token ghp_..." https://api.github.com/user -D /tmp/h | jq -r '.login,.email'
grep -i 'X-OAuth-Scopes' /tmp/h

# Slack
curl -sk -m 10 -H "Authorization: Bearer xoxb-..." -X POST https://slack.com/api/auth.test | jq .

# Anthropic (read-only validation)
curl -sk -m 10 -H "x-api-key: sk-ant-..." -H "anthropic-version: 2023-06-01" https://api.anthropic.com/v1/models | jq '.data | length'

# OpenAI
curl -sk -m 10 -H "Authorization: Bearer sk-..." https://api.openai.com/v1/models | jq '.data | length'

# npm
curl -sk -m 10 -H "Authorization: Bearer npm_..." https://registry.npmjs.org/-/whoami | jq .

# Atlassian (account)
curl -sk -m 10 -u "email:ATATT3xFfGF0_..." https://your-domain.atlassian.net/rest/api/3/myself | jq .

# DataDog (API + APP key both required)
curl -sk -m 10 -H "DD-API-KEY: ..." -H "DD-APPLICATION-KEY: ..." https://api.datadoghq.com/api/v1/validate | jq .
```

**Bulk webapp triage (httpx, faster than curl loop):**

```bash

# Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest
echo "target.example" | httpx -sc -title -tech-detect -web-server -ip -cdn -follow-redirects

# With probe list
cat subdomains.txt | httpx -sc -title -tech-detect -path /actuator/env,/.git/config,/.env -mc 200,301,403
```

**Save responses for evidence:**

```bash
mkdir -p evidence/$(date -u +%Y%m%d)
T="https://target.example"
P="/actuator/env"
TS=$(date -u +%Y%m%dT%H%M%SZ)
SAFE_NAME=$(echo "${T}${P}" | tr '/:' '_')
curl -sk -m 10 "$T$P" -o "evidence/$(date -u +%Y%m%d)/${TS}_${SAFE_NAME}.body" \
  -D "evidence/$(date -u +%Y%m%d)/${TS}_${SAFE_NAME}.headers"
sha256sum "evidence/$(date -u +%Y%m%d)/${TS}_${SAFE_NAME}".* > "evidence/$(date -u +%Y%m%d)/${TS}_${SAFE_NAME}.sha256"
```

---

### 16.14 Email Security Analysis (SPF/DMARC/DKIM/BIMI/MTA-STS/DNSSEC)

Spoof feasibility + SaaS tenant inference from a target's email DNS.

**SPF lookup + parsing:**

```bash
D="target.example"
dig +short TXT "$D" | grep -i 'v=spf1'
```

**Common SPF parsing checklist:**
- Ends in `-all` (hardfail) → strict; major providers reject spoofs.
- Ends in `~all` (softfail) → spam folder for spoofs.
- Ends in `?all` or no `all` → permissive; spoofs likely deliver.
- Includes (`include:`) reveal SaaS tenants:
  - `include:_spf.google.com` → Google Workspace.
  - `include:spf.protection.outlook.com` → Microsoft 365.
  - `include:_spf.salesforce.com` → Salesforce.
  - `include:mail.zendesk.com` → Zendesk customer.
  - `include:sendgrid.net` → SendGrid customer.
  - `include:mailgun.org` → Mailgun customer.
  - `include:_spf.atlassian.net` → Atlassian Cloud.
  - `include:amazonses.com` → AWS SES.
  - `include:mktomail.com` → Marketo.
  - `include:_spf.intuit.com` → Intuit (QuickBooks/Mailchimp).
  - `include:spf.mandrillapp.com` → Mandrill.
  - `include:_spf.workday.com` → Workday.

If SPF includes ≥10 mechanisms (max-lookups limit) → SPF eval likely fails → spoofs may pass. Tools: `spfquery`, `spftools` (online), `dig +trace`.

**DMARC policy + alignment:**

```bash
dig +short TXT "_dmarc.${D}"
```

Parse for:
- `p=` → primary policy (`none`, `quarantine`, `reject`).
- `sp=` → subdomain policy (defaults to `p=`).
- `aspf=` / `adkim=` → alignment mode (`r`=relaxed, `s`=strict).
- `pct=` → percentage of mail to which policy applies.
- `rua=` / `ruf=` → reporting addresses (often reveals SaaS DMARC vendors: dmarcian, valimail, Agari, easydmarc).

**Severity:**
- `p=none` → spoof-feasible, downgrade trust → MEDIUM finding.
- `p=quarantine pct<100` → partial enforcement → LOW.
- `p=reject` + `aspf=s` + `adkim=s` → well-postured → no finding.

**DKIM key discovery:**

DKIM selectors aren't well-known; common patterns:
```bash
for selector in default google selector1 selector2 mail email k1 dkim s1 s2 mta1 mta2 \
                amazonses 20240101 20230101 mailchimp sendgrid mxvault; do
  echo "=== ${selector} ==="
  dig +short TXT "${selector}._domainkey.${D}"
done
```

If a key returns: extract `p=<base64>` and check key length. RSA-1024 → MEDIUM (deprecated; should be 2048+). Missing or rotated infrequently → LOW finding.

**BIMI (Brand Indicators for Message Identification):**

```bash
dig +short TXT "default._bimi.${D}"
```

If present + `p=reject` DMARC → brand-impersonation defense in inbox UI. Absence is LOW only (operational, not exploitable).

**MTA-STS (Mail Transfer Agent Strict Transport Security):**

```bash
dig +short TXT "_mta-sts.${D}"
curl -sk -m 10 "https://mta-sts.${D}/.well-known/mta-sts.txt"
```

If neither responds → MX-server TLS not enforced; MITM-able. LOW finding. If `mode=enforce` present and policy file matches → well-postured.

**TLS-RPT (TLS Reporting):**
```bash
dig +short TXT "_smtp._tls.${D}"
```

**DNSSEC validation:**

```bash
dig +dnssec "${D}" SOA | grep -E 'flags|RRSIG'
delv "${D}" 2>&1 | grep -i 'fully validated\|insecur'
```

If `delv` returns "insecure" → DNSSEC not enabled (LOW finding; doesn't enable spoof but is hardening gap).

**MX → IdP / mail-host inference:**

```bash
dig +short MX "${D}"
```

| MX pattern | IdP / hosting |
|---|---|
| `aspmx.l.google.com`, `*.googlemail.com` | Google Workspace |
| `*.mail.protection.outlook.com` | Microsoft 365 |
| `*.mail.eo.outlook.com` | Microsoft 365 (older) |
| `*.zoho.com` | Zoho Mail |
| `*.yandex.net` | Yandex 360 |
| `*.fastmail.com` | Fastmail |
| `*.proofpoint.com`, `*.pphosted.com` | Proofpoint (M365 user with Proofpoint inbound) |
| `*.mimecast.com`, `*.mimecast-eu.com` | Mimecast |
| `*.barracudanetworks.com` | Barracuda |
| Self-hosted IPs in target ASN | On-prem mail server (often Exchange) |

**DMARC reporting-vendor inference (parse `rua=` / `ruf=`):**

| RUA/RUF host | Vendor | Implication |
|---|---|---|
| `*.dmarcian.com` | dmarcian | DMARC reporting customer |
| `*.valimail.com`, `*.dmarc-rua.com` | Valimail | DMARC reporting customer |
| `*.kdmarc.com` | Kratikal kDMARC | Indian DMARC vendor; common in IN orgs |
| `*.agari.com` | Agari (Fortra) | Email security vendor |
| `*.easydmarc.com` | EasyDMARC | DMARC reporting customer |
| `*.dmarcanalyzer.com` | DMARC Analyzer | Reporting customer |
| `*.postmarkapp.com` | Postmark | DMARC reporting addon |
| `<addr>@<target-domain>` | Self-hosted reporting | Internal mailbox; sometimes leaks team-name (`itg@`, `secops@`, `dmarc@`) |

Capture the vendor + the internal RUA mailbox. Both are leak surfaces (vendor compromise = DMARC bypass; internal mailbox = phishing target).

**Windows / PowerShell parallel for the entire §16.14 audit:**

PS 5.1 `Resolve-DnsName` does **not** accept `-Type CAA` (use PowerShell 7+ or `nslookup -type=CAA <domain>`). Otherwise:

```powershell
$D = "target.example"
"=== SPF ==="; (Resolve-DnsName $D -Type TXT -EA SilentlyContinue | ? { $_.Strings -match 'v=spf1' }).Strings
"=== DMARC ==="; (Resolve-DnsName "_dmarc.$D" -Type TXT -EA SilentlyContinue).Strings
"=== MTA-STS ==="; (Resolve-DnsName "_mta-sts.$D" -Type TXT -EA SilentlyContinue).Strings
"=== TLS-RPT ==="; (Resolve-DnsName "_smtp._tls.$D" -Type TXT -EA SilentlyContinue).Strings
"=== BIMI ==="; (Resolve-DnsName "default._bimi.$D" -Type TXT -EA SilentlyContinue).Strings
"=== MX ==="; Resolve-DnsName $D -Type MX -EA SilentlyContinue | Select NameExchange,Preference
"=== DKIM common selectors ==="
foreach ($s in @("default","google","selector1","selector2","mail","email","k1","dkim","s1","s2","amazonses","mailchimp","sendgrid","mxvault","20240101","zoho","zmail","outlook","o365")) {
  $r = Resolve-DnsName "$s._domainkey.$D" -Type TXT -EA SilentlyContinue
  if ($r) { "${s}: FOUND" }
}
"=== CAA (PS 5.1 fallback) ==="; nslookup -type=CAA $D 2>$null
```

### 16.15 Origin Discovery / CDN Bypass

If the target is behind Cloudflare/Akamai/Fastly/CloudFront, their CDN IPs are well-defined. Find IPs **not** in those ranges that serve the same site = origin.

**Cloudflare IPv4 ranges:**
```
https://www.cloudflare.com/ips-v4
```
**Akamai ASNs:** AS16625, AS20940, AS21342, AS21357.
**Fastly:** AS54113.
**AWS CloudFront:** published in `https://ip-ranges.amazonaws.com/ip-ranges.json` filter `service:CLOUDFRONT`.

**Origin discovery via DNS history:**

```bash

# SecurityTrails (paid)
curl -sk -H "APIKEY: ..." \
  "https://api.securitytrails.com/v1/history/${D}/dns/a" | jq '.records[] | {ip:.values[].ip, first_seen, last_seen}'
```

Free alternatives:
```bash

# RiskIQ Community (free tier; auth required)
curl -sk -u "user:apikey" "https://api.riskiq.net/pt/v2/dns/passive?query=${D}" | jq .
```

Filter the result: any historical A record IP **not** in current CDN ranges = origin candidate.

**Origin via certificate SAN pivot (Censys):**

```bash

# Censys (free 250 queries/month with key)
censys search "services.tls.certificates.leaf_data.subject.common_name:${D} AND NOT services.tls.certificates.leaf_data.issuer.common_name:'Cloudflare'"
```

Or via crt.sh + manual IP check:
```bash
curl -sk "https://crt.sh/?q=%25.${D}&output=json" | jq -r '.[].name_value' | sort -u
```

**Origin via favicon hash (Shodan):**

```bash

# Compute favicon mmh3
python3 -c "
import urllib.request, codecs, mmh3
data = urllib.request.urlopen('https://target.example/favicon.ico').read()
b64 = codecs.encode(data, 'base64')
print(mmh3.hash(b64))"

# Search Shodan
shodan search "http.favicon.hash:<computed-hash>" --fields ip_str,port,org
```

Cross-reference with CDN ranges; non-CDN matches = origin candidates.

**Origin via JARM:**

```bash

# Compute JARM
python3 -c "
import jarm
print(jarm.scan('target.example'))
" 2>/dev/null || echo "Install: pip install pyjarm"

# Search Shodan for matching JARM
shodan search "ssl.jarm:<jarm-hash>" --fields ip_str,port
```

**Origin via Host-header probe (validate candidate):**

```bash
CANDIDATE_IP="203.0.113.42"
curl -sk -m 10 -H "Host: target.example.com" "https://${CANDIDATE_IP}/" -o /tmp/candidate.html
diff <(curl -sk -m 10 https://target.example.com/) /tmp/candidate.html | head -50
```

If small/no diff → confirmed origin. Document with detectability=low.

**Origin via auxiliary subdomains (often skip CDN):**

```bash
for sub in mail smtp ftp sftp cpanel webmail direct origin direct-connect noproxy \
           dev staging stg uat preprod sandbox preview origin-www old-www legacy \
           server srv host1 host2 vps server1; do
  echo "=== ${sub}.${D} ==="
  dig +short A "${sub}.${D}"
done | grep -vE '^(===|$)' | sort -u
```

Cross-reference any returned IP against CDN ranges.

**Origin via email-header bounce:**

Send mail to `<random>@${D}` from a sock-puppet account. The bounce often includes `Received:` headers showing the inbound mail server's actual IP — sometimes co-located with web origin.

**Origin via misconfigured CDN error pages:**

Some CDN 5xx error pages historically leaked upstream details. Trigger errors and inspect:
```bash

# Trigger CDN-side 5xx (oversized request, malformed Host)
curl -sk -m 10 -H "Host: " "https://target.example/" -o /tmp/err.html
curl -sk -m 10 -H "X-Forwarded-For: $(python3 -c 'print("a"*8000)')" "https://target.example/"
grep -iE 'origin|upstream|server|backend|cf-ray' /tmp/err.html
```

### 16.16 Vendor Product Fingerprints

Common edge appliances / products on the target's perimeter, with fingerprint paths and notes on common CVEs.

| Product | Fingerprint paths | Notes |
|---|---|---|
| **Citrix Netscaler / Gateway** | `/vpn/index.html`, `/logon/LogonPoint/tmindex.html`, `/citrix/` | Version in HTML; CVE-2023-3519 (RCE), CVE-2019-19781 (path traversal RCE) — both KEV-listed. |
| **F5 BIG-IP TMUI** | `/tmui/login.jsp`, `/mgmt/tm/sys/` | Banner reveals version; CVE-2022-1388 (auth bypass), CVE-2023-46747 — KEV-listed. |
| **Cisco ASA / AnyConnect** | `/+CSCOE+/`, `/CSCOE/index.html`, `/webvpn.html`, `/+CSCOE+/portal.html` | CVE-2020-3452 (file read), CVE-2018-0101 (RCE). |
| **Pulse Secure / Ivanti Connect** | `/dana-na/`, `/dana-na/auth/url_default/welcome.cgi`, `/api/v1/` | CVE-2024-21887 (KEV), CVE-2023-46805 (KEV) — chained command injection. |
| **FortiGate / FortiOS** | `/remote/login`, `/remote/info`, `/api/v2/` | CVE-2022-42475 (RCE, KEV), CVE-2024-21762 (RCE, KEV). |
| **PaloAlto GlobalProtect** | `/global-protect/`, `/global-protect/portal/css/login.css`, `/api/?type=keygen` | CVE-2024-3400 (RCE, KEV), CVE-2019-1579. |
| **VMware Horizon** | `/portal/info.jsp`, `/broker/xml`, `/login.jsp` | log4shell exposure (CVE-2021-44228, KEV). |
| **VMware vCenter** | `/sdk`, `/ui/`, `/vsphere-client/`, `/websso/SAML2/` | CVE-2021-21972 (RCE, KEV), CVE-2021-22005. |
| **VMware ESXi** | `/sdk`, `/ui/`, `/folder` | CVE-2021-21974 (heap overflow → ESXiArgs ransomware, KEV). |
| **Microsoft Exchange OWA** | `/owa/`, `/ews/exchange.asmx`, `/ecp/` | ProxyShell (CVE-2021-34473), ProxyLogon (CVE-2021-26855), ProxyNotShell (CVE-2022-41040) — all KEV. |
| **WatchGuard Firebox** | `/auth/`, `/wgcgi.cgi` | CVE-2022-26318 (CGI). |
| **SonicWall SMA** | `/cgi-bin/welcome`, `/__api__/v1/`, `/diagnostics/` | CVE-2021-20016, CVE-2024-40766 (KEV). |
| **Sophos UTM/XG/XGS** | `/userportal/`, `/webconsole/`, `/cgi-bin/` | CVE-2022-1040 (RCE, KEV). |
| **Check Point R80/R81** | `/sslvpn/portal/`, `/clients/` | CVE-2024-24919 (KEV). |
| **Zoho ManageEngine** | `/RestAPI/Login`, `/api/json/v2/` | Multiple RCE CVEs; check version. |
| **Atlassian Confluence** | `/confluence/`, `/login.action`, `/rest/api/space` | CVE-2022-26134 (OGNL RCE, KEV), CVE-2023-22515 (KEV). |
| **Atlassian Jira** | `/secure/Dashboard.jspa`, `/rest/api/2/serverInfo` | Multiple CVEs; check version. |
| **GitLab self-hosted** | `/users/sign_in`, `/-/oauth/applications`, `/help` | Version in HTML footer; CVE-2021-22205 (RCE, KEV). |
| **Telerik UI** | `/Telerik.Web.UI.WebResource.axd?type=rau` | CVE-2017-9248, CVE-2019-18935 — old but still found. |
| **ConnectWise ScreenConnect** | `/SetupWizard.aspx`, `/Bin/SetupWizard.aspx` | CVE-2024-1709 (auth bypass, KEV). |
| **SolarWinds Orion** | `/Orion/Login.aspx` | SUNBURST supply-chain (CVE-2020-10148). |
| **Kaseya VSA** | `/dl.asp`, `/userFilterTableRpt.asp` | CVE-2021-30116 (REvil supply-chain). |
| **Microsoft IIS / OWA misc** | `Server: Microsoft-IIS/<version>` | Old versions = old CVEs; check. |
| **Cisco Smart Install** | port 4786 open | CVE-2018-0171 (smart install client mode RCE). |

**Per-vendor probe pattern:**

```bash
T="https://target.example"

# Citrix
curl -sk -m 10 "$T/vpn/index.html" -o /tmp/c1 -w '%{http_code}\n'
grep -iE 'NetScaler|Citrix|version' /tmp/c1

# F5
curl -sk -m 10 "$T/tmui/login.jsp" -o /tmp/c2 -w '%{http_code}\n'
grep -iE 'BIG-IP|version' /tmp/c2

# (etc — repeat per product)
```

**Auto-fingerprint with Nuclei:**

```bash
nuclei -u $T -t http/technologies/ -severity info,low,medium,high,critical
nuclei -u $T -t http/cves/ -severity high,critical -etags fuzz
```

### 16.17 Cloud-Native Service Fingerprints

Modern apps deploy on serverless / managed services. Fingerprint the platform from the URL pattern.

| Provider | URL pattern | Notes |
|---|---|---|
| **AWS Lambda Function URL** | `*.lambda-url.<region>.on.aws` | Direct invocation; check IAM auth posture. |
| **AWS App Runner** | `*.<region>.awsapprunner.com` | Managed container; usually behind auth. |
| **AWS API Gateway** | `*.execute-api.<region>.amazonaws.com` | REST/HTTP/WebSocket; check authorizer config. |
| **AWS CloudFront** | `d{14}\.cloudfront\.net` | Distribution; origin behind it (see §16.15). |
| **AWS ALB / ELB** | `*.elb.<region>.amazonaws.com` | Behind = EC2 / ECS. |
| **AWS Amplify** | `*.amplifyapp.com` | Static + Lambda backend. |
| **Google Cloud Run** | `*.run.app` (and `*.<region>.run.app`) | Container; check public-vs-IAM auth. |
| **Google Cloud Functions** | `*.cloudfunctions.net`, `*.<region>-<project>.cloudfunctions.net` | Serverless. |
| **Google App Engine** | `*.appspot.com` | Older serverless. |
| **Azure Functions** | `*.azurewebsites.net` (also App Service) | Function App behind same domain pattern. |
| **Azure Container Apps** | `*.azurecontainerapps.io` | Containers. |
| **Azure Static Web Apps** | `*.azurestaticapps.net` | Static + Functions. |
| **Vercel** | `*.vercel.app`, `*.now.sh` (legacy) | Frontend + serverless. |
| **Netlify** | `*.netlify.app`, `*.netlify.com` | Frontend + functions. |
| **Cloudflare Workers** | `*.workers.dev` | Edge functions. |
| **Cloudflare Pages** | `*.pages.dev` | Static + functions. |
| **Heroku** | `*.herokuapp.com` | Dynos. |
| **Render** | `*.onrender.com` | Container/static. |
| **Fly.io** | `*.fly.dev` | Edge containers. |
| **Railway** | `*.railway.app` | App platform. |
| **DigitalOcean App Platform** | `*.ondigitalocean.app` | Static + container. |

**For each pattern:**
- Confirm public vs auth-required (HEAD / GET).
- Check CORS posture.
- For Lambda Function URLs / Cloud Run / Cloud Functions: check whether IAM auth is enforced (anonymous invocation = HIGH finding).
- For static + functions hybrids (Vercel/Netlify/Cloudflare Pages): the function paths are usually `/api/*`; enumerate via JS extraction.

### 16.18 Container & Kubernetes Exposure

Increasingly common; often forgotten when behind a NAT.

| Target | Port | Probe | Severity if exposed |
|---|---|---|---|
| **Docker API (unencrypted)** | 2375 | `curl -sk -m 5 http://${IP}:2375/v1.40/info` | CRITICAL (container/host takeover) |
| **Docker API (TLS)** | 2376 | `curl -sk -m 5 https://${IP}:2376/v1.40/info` | HIGH (cert validation bypass possible) |
| **Kubernetes API server** | 6443 / 8443 | `curl -sk -m 5 https://${IP}:6443/api` | HIGH if `system:anonymous` returns non-403 |
| **Kubernetes Dashboard** | 8001 / 9090 / 30000+ | `curl -sk -m 5 http://${IP}:8001/api/v1/namespaces/kube-system/services/kubernetes-dashboard` | HIGH if reachable |
| **kubelet** | 10250 (HTTPS), 10255 (HTTP, deprecated) | `curl -sk -m 5 https://${IP}:10250/pods` | CRITICAL (no auth = pod exec) |
| **etcd** | 2379 (client), 2380 (peer) | `curl -sk -m 5 https://${IP}:2379/v2/keys/` (v2) or `etcdctl --endpoints=${IP}:2379 get /` (v3) | CRITICAL (cluster state + secrets) |
| **kube-proxy** | 10256 | `curl http://${IP}:10256/healthz` | INFO |
| **kube-controller-manager** | 10257 | `curl https://${IP}:10257/metrics` | MEDIUM |
| **kube-scheduler** | 10259 | `curl https://${IP}:10259/metrics` | MEDIUM |
| **cAdvisor** | 4194 (deprecated) | `curl http://${IP}:4194/metrics` | LOW (resource metrics) |
| **Helm Tiller** (Helm 2 — deprecated but found) | 44134 | `helm --host ${IP}:44134 list` | HIGH (Tiller had cluster-admin) |

**Public container registries to check for leaks:**

| Registry | Search pattern |
|---|---|
| Docker Hub | `https://hub.docker.com/search?q=<target-keyword>&type=image` |
| Quay (Red Hat) | `https://quay.io/search?q=<target-keyword>` |
| GitHub Container Registry (GHCR) | enumerable via GitHub API: `https://api.github.com/orgs/<org>/packages?package_type=container` |
| Amazon ECR Public | `https://gallery.ecr.aws/?searchTerm=<keyword>` |
| Azure Container Registry (public) | varies; check for `*.azurecr.io` |
| Google Container Registry (public) | `https://console.cloud.google.com/gcr/images/<project>?project=<project>` |

**Per-image scan workflow:**
1. `docker pull <registry>/<image>:<tag>` (or `skopeo inspect`).
2. `docker save <image> -o /tmp/img.tar`.
3. Extract layers; scan with secret catalog (§17).
4. Inspect `Dockerfile` history (`docker history <image>`) — sometimes reveals build args or COPY of secrets.

### 16.19 CI/CD Platform Exposure

| Platform | Common exposure | Probe |
|---|---|---|
| **Jenkins** | `/script` (Groovy console = RCE if no auth), `/asynchPeople/`, `/jnlpJars/jenkins-cli.jar`, `/computer/`, `/job/<name>/api/json` | `curl -sk -m 10 "${T}/script"` and `curl -sk -m 10 "${T}/asynchPeople/api/json"` |
| **GitLab self-hosted** | `/users/sign_in` (version in HTML), `/-/oauth/applications` (auth-required), `/api/v4/version`, `/-/snippets/<id>/raw` | `curl -sk -m 10 "${T}/api/v4/version"` |
| **GitHub Actions workflow files** | `.github/workflows/*.yml` in any public repo | Search via GitHub code search: `path:.github/workflows extension:yml secrets` |
| **CircleCI config** | `.circleci/config.yml` in any repo | Search: `path:.circleci/config.yml` |
| **TeamCity** | `/login.html`, `/agent.html?agentId=*`, `/admin/admin.html` | `curl -sk -m 10 "${T}/login.html" \| grep -i 'TeamCity'` — version disclosure. CVE-2024-27198 (KEV). |
| **Bamboo (Atlassian)** | `/userlogin.action`, `/rest/api/latest/info` | `curl -sk -m 10 "${T}/rest/api/latest/info"` |
| **Drone CI** | `/api/info`, `/login` | `curl -sk -m 10 "${T}/api/info"` |
| **Travis CI (legacy)** | `.travis.yml` in repos; `https://api.travis-ci.com/repos/<owner>/<repo>` | API often exposes build env. |
| **Argo CD** | `/api/version`, `/applications` | `curl -sk -m 10 "${T}/api/version"`. Check anonymous-auth posture. |
| **Tekton** | `/apis/tekton.dev/v1beta1/pipelineruns` (K8s native) | Enumerate via K8s API. |
| **Spinnaker** | `/gate/info`, `/applications` | `curl -sk -m 10 "${T}/gate/info"` |
| **Buildkite** | per-org dashboards; usually behind auth. | Check public agents page. |

**GitHub Actions secret-leak patterns to look for in workflows:**

```yaml

# Anti-pattern: secret in environment without mask
env:
  KEY: ${{ secrets.MY_API_KEY }}
run: ./deploy.sh   # script may echo $KEY

# Anti-pattern: pull_request_target with checkout of fork code (CVE class)
on: pull_request_target
jobs:
  test:
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # checks out fork code with secrets in env
```

### 16.20 Documentation / Wiki Leak Paths

Public-share features on collaboration platforms regularly leak.

| Platform | URL pattern | What's exposed |
|---|---|---|
| **Notion (publish page)** | `*.notion.site/<slug>` or `notion.so/<workspace>/<page-id>` | Public page; sometimes whole workspaces published by accident. |
| **Confluence Cloud (anonymous)** | `<target>.atlassian.net/wiki/spaces/` | Public spaces; check `/wiki/display/<SPACE>/`. |
| **Atlassian Service Desk** | `<target>.atlassian.net/servicedesk/customer/portal/<N>` | Sometimes lists all internal request types. |
| **Trello board** | `https://trello.com/b/<id>/<slug>` | Public board with cards; check via Google `site:trello.com "${target}"`. |
| **Asana public project** | `https://app.asana.com/0/<id>/<id>` | Public project view. |
| **ReadTheDocs** | `<project>.readthedocs.io` | Hosted docs; "private builds" sometimes default to public. |
| **GitBook** | `<workspace>.gitbook.io/<book>/` | Published docs; sometimes contain internal SOPs. |
| **MkDocs / Docusaurus on subdomain** | `docs.<target>` | Often contains internal architecture diagrams + setup notes. |
| **Slab** | `<workspace>.slab.com/posts/<id>` | Published posts. |
| **Coda** | `coda.io/d/<doc-id>` | Public docs. |
| **Miro** | `https://miro.com/app/board/<id>/` | Public boards (often architecture diagrams). |
| **Lucidchart** | `https://lucid.app/lucidchart/<id>/view` | Public diagrams. |
| **Figma** | `https://www.figma.com/file/<key>/` | Public design files; sometimes leak product spec. |
| **GitHub Wiki** | `github.com/<org>/<repo>/wiki` | Public wikis; check stale ones. |
| **Linear** | `linear.app/<workspace>/issue/<id>` | Public issues (rare but happens). |
| **Confluence anonymous server** | `<target>/confluence/`, `<target>/wiki/` (self-hosted) | Anonymous read sometimes left on. |
| **Monday.com** | `view.monday.com/<id>` | Shared boards. |
| **Wrike** | `app.wrike.com/external/<id>` | External-shared spaces. |

**Dork-driven discovery:**
```
site:notion.site "{target}"
site:notion.so "{target}"
site:atlassian.net "{target}"
site:trello.com "{target}"
site:miro.com "{target}"
site:lucid.app "{target}"
site:figma.com "{target}"
site:asana.com "{target}"
site:gitbook.io "{target}"
site:readthedocs.io "{target}"
```

### 16.21 WHOIS / RDAP / Historical

WHOIS gives current registrant; RDAP is the structured replacement; historical WHOIS is the pivot gold.

**Current WHOIS:**

```bash
whois target.example                              # standard CLI
curl -sk -m 10 "https://www.whois.com/whois/${D}"  # web fallback
```

**RDAP (RFC 7480, structured JSON):**

```bash

# IANA bootstrap → returns the registry RDAP server
curl -sk "https://rdap.org/domain/${D}" | jq .
curl -sk "https://www.iana.org/rdap" | jq .   # bootstrap registry
```

What to extract from WHOIS / RDAP:
- Registrant: name, org, email, phone, address (often redacted post-GDPR but not always for non-EU registrants).
- Registrar: enables registrar-account pivot for related domains.
- Created / updated / expiry dates: pattern of bulk registrations = same registrant.
- Nameservers: NS reuse pivot.
- Status flags (`clientHold`, `clientTransferProhibited`, etc.) = posture indicators.
- Abuse contact: useful for responsible disclosure (§30).

**Historical WHOIS:**

Pre-GDPR records often have unredacted contact info. Sources:

| Source | Notes |
|---|---|
| **DomainTools** | Paid; gold-standard; full WHOIS history. |
| **WhoisXML API** | Paid; bulk + history. |
| **SecurityTrails** | Paid; WHOIS + DNS history. |
| **viewdns.info** | Free WHOIS history (limited). |
| **whoisology.com** | Paid; reverse WHOIS by registrant email. |

**Reverse-WHOIS pivots:**

If you have a registrant email, search "every domain registered by this email":
```bash

# DomainTools (paid)
curl -sk -H "X-API-Username: ..." -H "X-API-Key: ..." \
  "https://api.domaintools.com/v1/reverse-whois/?terms=admin@target.example"
```

This finds adjacent corporate assets (subsidiary domains, brand variations, employee personal projects on corp email).

### 16.22 DNS Record Catalog (TXT verification tokens, MX→IdP)

For every target domain, dump all common record types:

```bash
D="target.example"
for rtype in A AAAA MX TXT NS SOA CAA SRV CNAME PTR; do
  echo "=== ${rtype} ==="
  dig +short "${D}" "${rtype}"
done
```

**TXT record verification token catalog** (each token reveals a SaaS tenancy):

| TXT pattern | SaaS / service | Implication |
|---|---|---|
| `google-site-verification=<token>` | Google Workspace / Search Console / Analytics | Google tenancy. |
| `MS=ms<digits>` | Microsoft 365 (older) | M365 tenancy. |
| `apple-domain-verification=<token>` | Apple Business Manager / iCloud Calendar | Apple ecosystem. |
| `atlassian-domain-verification=<token>` | Atlassian Cloud (Jira/Confluence/etc.) | Atlassian customer. |
| `facebook-domain-verification=<token>` | Facebook Business / Pixel | FB Business. |
| `adobe-idp-site-verification=<token>` | Adobe Sign / Creative Cloud | Adobe customer. |
| `docusign=<token>` | DocuSign | DocuSign customer. |
| `dropbox-domain-verification=<token>` | Dropbox Business | Dropbox customer. |
| `box-verification=<token>` | Box | Box customer. |
| `webexdomainverification.<id>` | Webex | Cisco Webex. |
| `zoom_verify_<id>` | Zoom | Zoom customer (admin domain). |
| `notion=<token>` (rare) | Notion workspace | Notion enterprise. |
| `slack-domain-verification=<token>` | Slack Enterprise Grid | Slack EG. |
| `asana-domain-verification=<token>` | Asana Enterprise | Asana customer. |
| `mongodb-site-verification=<token>` | MongoDB Atlas | DB tenant. |
| `_dnsauth.<token>` | Many ACME / Let's Encrypt CAs | DNS-01 challenge in progress. |
| `pinterest-site-verification=<token>` | Pinterest Business | Marketing surface. |
| `cisco-ci-domain-verification=<token>` | Cisco Spark / Webex | Cisco. |
| `_globalsign-domain-verification=<token>` | GlobalSign cert authority | Cert provider. |
| `mailru-verification:<token>` | Mail.ru | RU presence. |
| `yandex-verification:<token>` | Yandex services | RU presence. |
| `zscaler-verification-<id>-<date>-<random>` | Zscaler (ZIA / ZPA / ZDX) | **Web SSE / SASE customer**; the date suffix is the verification-issued date. |
| `cloudflare-verify=<token>` | Cloudflare (Zero Trust / Access / WARP) | Cloudflare org-tier customer. |
| `autosect-site-verification=<token>` | AutoSect (security tooling) | Security vendor on tenant. |
| `cisco-site-verification=<token>` | Cisco (various products) | Cisco vendor. |
| `mscid=<token>` | Microsoft (newer M365 verification) | M365 tenancy (newer format). |
| `_amazonses=<token>` | AWS SES sender verification | SES sender. |
| `salesforce-domain-verification=<token>` | Salesforce | SF customer. |
| `workday-domain-verification=<token>` | Workday | Workday customer (HR + Finance). |
| `shopify-domain-verification=<token>` | Shopify | E-commerce customer. |
| `klaviyo-domain-verification=<token>` | Klaviyo | Marketing automation. |
| `mailchimp-domain-verification=<token>` | Mailchimp | Marketing email. |
| `hubspot-domain-verification=<token>` | HubSpot | CRM / marketing. |
| `zendesk-verification=<token>` | Zendesk | Support tenancy (also see §43). |
| `freshworks-verification=<token>` | Freshworks | Support / CRM customer. |
| `intercom-verification=<token>` | Intercom | Messaging tenancy. |
| `loom-site-verification=<token>` | Loom | Video. |
| `miro-site-verification=<token>` | Miro | Whiteboard tenancy. |
| `gitlab-domain-verification=<token>` | GitLab | Self-hosted or cloud verification. |

Each discovered tenancy is a separate attack surface (own credentials, own MFA posture, own data).

**Autodiscover-as-confirmation pattern:**

`autodiscover.<domain>` resolving to Microsoft IP space (`40.96.0.0/13`, `52.96.0.0/14`, `13.107.0.0/16`) is **definitive proof** of M365 Exchange Online tenancy — even when MX records are obscured by Mimecast/Proofpoint/Barracuda inbound filtering. Probe:

```powershell
Resolve-DnsName "autodiscover.$D" -Type A | Select Name,IPAddress
```

If IPs are in Microsoft ranges → `M365_CONFIRMED`. Cross-reference with `getuserrealm.srf` (§22.1) for tenant GUID extraction.

**CAA records:**
```bash
dig +short CAA "${D}"
```
Lists which CAs are allowed to issue certs. Absence = LOW finding (any CA can mis-issue). Presence + restrictive list = good posture.

**SOA serial pattern analysis:**
```bash
dig +short SOA "${D}"
```
Serial format `YYYYMMDDNN` reveals last-edit date. Pattern across multiple zones can correlate ownership.

### 16.23 Wayback CDX Deep Usage

The Wayback Machine has a structured query API.

**Basic CDX query:**
```bash
D="target.example"
curl -sk "https://web.archive.org/cdx/search/cdx?url=${D}/*&output=json&fl=timestamp,original&limit=10000"
```

Returns JSON array of `[timestamp, original_url]` tuples.

**Useful filters:**
- `&from=20200101&to=20231231` — date range.
- `&filter=mimetype:application/json` — only JSON responses (often APIs).
- `&filter=mimetype:application/javascript` — JS bundles.
- `&filter=statuscode:200` — only successful captures.
- `&filter=urlkey:.*api.*` — only URLs containing "api".
- `&collapse=urlkey` — dedup by URL.
- `&collapse=digest` — dedup by content (catches identical pages re-archived).

**Get specific snapshot:**
```bash
TS="20231215120000"
URL="https://target.example/admin/dashboard"
curl -sk "https://web.archive.org/web/${TS}/${URL}"
```

**Diff snapshot vs live:**
```bash
LIVE=$(curl -sk -m 10 "${URL}")
ARCHIVED=$(curl -sk -m 10 "https://web.archive.org/web/${TS}/${URL}")
diff <(echo "$LIVE") <(echo "$ARCHIVED") | head -100
```

**Save current page:**
```bash
curl -sk -X POST "https://pragma.archivelab.org/" \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://target.example/admin"}'
```

**Find every archived JS:**
```bash
curl -sk "https://web.archive.org/cdx/search/cdx?url=${D}/*.js&output=json&fl=timestamp,original&filter=statuscode:200" | \
  jq -r '.[1:][] | "\(.[0]) \(.[1])"'
```

For each, fetch the archived JS and run the secret catalog (§17). Old JS often had hard-coded keys later removed.

**Legacy-app pivot (when `*.js` returns empty):**

Static brochure-ware sites (older corporate sites, especially pre-2015) often have **zero archived JS** because the frontend was server-rendered. Pivot to legacy file extensions:

```bash

# ASP / ASP.NET classic
curl -sk "https://web.archive.org/cdx/search/cdx?url=${D}/*.asp&output=json&fl=timestamp,original&filter=statuscode:200&collapse=urlkey&limit=500"

# PHP
curl -sk "https://web.archive.org/cdx/search/cdx?url=${D}/*.php&output=json&fl=timestamp,original&filter=statuscode:200&collapse=urlkey&limit=500"

# JSP / .NET aspx / CGI / Coldfusion
for ext in aspx jsp cgi cfm; do
  echo "=== .$ext ==="
  curl -sk "https://web.archive.org/cdx/search/cdx?url=${D}/*.${ext}&output=json&fl=timestamp,original&filter=statuscode:200&collapse=urlkey&limit=200"
done

# JSON / XML config (sometimes leaks endpoints + creds)
for ext in json xml yml yaml ini conf; do
  echo "=== .$ext ==="
  curl -sk "https://web.archive.org/cdx/search/cdx?url=${D}/*.${ext}&output=json&fl=timestamp,original&filter=statuscode:200&collapse=urlkey&limit=100"
done

# Anything indexed (broad sweep — useful for legacy enumeration)
curl -sk "https://web.archive.org/cdx/search/cdx?url=${D}/*&output=json&fl=timestamp,original&filter=statuscode:200&collapse=urlkey&limit=10000"
```

Legacy `.asp` / `.cfm` / `.jsp` URLs often reveal: forgotten admin panels, old user-enum endpoints, legacy auth flows, SQL-injection-prone parameters. Cross-reference with current DNS — many legacy hosts now NXDOMAIN but the URL paths sometimes survive on a renamed host.

### 16.24 Common-Prefix Subdomain Sweep (active, low-detectability)

Empirically: **passive cert-transparency enumeration (crt.sh / VirusTotal / Subfinder) misses 20–40% of high-value subdomains** because (a) many internal hosts use wildcard certs that don't expose the FQDN, (b) some hosts have never been issued public certs (HTTP-only or self-signed), (c) very-recently-provisioned hosts haven't propagated to CT log mirrors yet.

**Always pair passive enum with an active prefix-probe.** Detectability: low (single A-record query per host; no port scan, no HTTP).

**The high-yield prefix list (ordered by hit-rate from real engagements):**

```
www, mail, webmail, smtp, imap, pop, owa, autodiscover, ftp, sftp,
vpn, sslvpn, gateway, gp, globalprotect, citrix, fortinet, anyconnect,
api, app, apps, mobile, m,
portal, login, sso, idp, iam, identity, accounts, oauth, auth, adfs,
admin, manage, console, dashboard, cp, cpanel,
intranet, internal, hr, payroll, finance, sap, erp, crm, helpdesk, servicedesk,
support, help, kb, status, monitoring, grafana, kibana, prometheus,
docs, wiki, confluence, jira, bitbucket, gitlab, jenkins, sonar, nexus,
git, svn, repo, code,
dev, test, staging, stg, qa, uat, sandbox, preprod, preview, demo,
careers, jobs, vacancies, recruit, eapps,
shop, store, ecommerce, checkout, payments, pay, billing,
old, legacy, archive, backup, beta, v1, v2, classic,
cdn, static, assets, media, img, files, downloads, public,
ns, ns1, ns2, dns, mx, mx1, mx2,
zoom, teams, slack, lync, sip, voice, meet,
eproc, tender, tenders, suppliers, vendor, vendors, procurement, purchase
```

**One-liner (PowerShell):**
```powershell
$D = "target.example"
$prefixes = @("www","mail","webmail","owa","autodiscover","ftp","vpn","sslvpn","gateway","api","app","portal","login","sso","idp","iam","identity","accounts","oauth","auth","adfs","admin","intranet","hr","sap","erp","crm","support","help","status","grafana","kibana","docs","wiki","jira","jenkins","gitlab","dev","test","staging","stg","qa","uat","sandbox","preprod","preview","careers","jobs","eapps","old","legacy","beta","tender","suppliers","procurement")
foreach ($p in $prefixes) {
  $r = Resolve-DnsName "$p.$D" -Type A -ErrorAction SilentlyContinue
  if ($r) {
    $ips = ($r | ? {$_.IPAddress}).IPAddress -join ","
    "$p.$D -> $ips"
  }
}
```

**One-liner (bash + dig):**
```bash
D="target.example"
for p in www mail webmail owa autodiscover ftp vpn sslvpn gateway api app portal login sso idp iam identity accounts oauth auth adfs admin intranet hr sap erp crm support help status grafana kibana docs wiki jira jenkins gitlab dev test staging stg qa uat sandbox preprod preview careers jobs eapps old legacy beta tender suppliers procurement; do
  IP=$(dig +short A "$p.$D" | head -1)
  [ -n "$IP" ] && echo "$p.$D -> $IP"
done
```

**Mass DNS approach (faster for large prefix lists):**
```bash

# Generate candidate FQDNs from a wordlist; resolve in parallel via puredns
puredns resolve <(awk -v d="$D" '{print $1"."d}' assetnote-best-dns-wordlist.txt) -r resolvers.txt
```

**What to extract from each hit:**
- IP / IP block → ASN lookup (§28.1) → confirms target-owned vs hosted-elsewhere.
- For `vpn.*` / `gateway.*` / `gp.*` / `globalprotect.*` / `citrix.*` → flag for active vendor fingerprint (§16.16) under separate engagement scope.
- For `api.*` / `app.*` → seed for §16.1–16.10 webapp probes.
- For `staging.*` / `dev.*` / `uat.*` → seed for §16.5 always-on HTTP checks (often weaker auth + debug endpoints).
- For `intranet.*` / `eapps.*` / `eproc.*` / similar internal-app shortnames → public-intranet finding (often MEDIUM; per §40).

**Real-engagement validation:** in an internal smoke test, prefix-sweep found `vpn.`, `api.`, `intranet.`, `staging.`, `support.`, `eapps.`, `eproc.`, `autodiscover.` — all of which crt.sh missed (or returned 502 for). Treat passive + active as **complementary, not alternatives**.

---


## SOURCE: hunt-skills/offensive-osint/references/recon-stack.md

# Subdomain & Infrastructure Recon

> Reference content for the `offensive-osint` skill. Originally §27 + §28 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 27. Subdomain-Source Stack (Passive)

Practical "what actually returns useful data in 2026" reference, ordered by recall:

| Source | Tier | Notes |
|---|---|---|
| crt.sh | Free | Best single source for cert-derived subdomains; **frequently 502s during peak hours — see fallback chain below**. |
| VirusTotal | Freemium | Domain → passive DNS history. |
| AlienVault OTX | Free | Passive DNS + URL data. |
| Shodan | Paid (low tier) | Subdomain enum via `domain:` filter. |
| BinaryEdge | Paid | Comparable to Shodan. |
| FOFA | Freemium | Strong China-side coverage. |
| ZoomEye | Freemium | Comparable to Shodan; CN-strong. |
| Netlas | Paid | Large-scale HTTP/DNS/cert pivots. |
| SecurityTrails | Paid | Passive DNS + asset discovery. |
| RapidDNS | Free | Public passive DNS. |
| Subfinder bundled | Free | Aggregates 30+ free sources via one CLI. |
| Amass | Free | Comparable, more thorough, slower. |
| Recon-ng | Free | Modular framework; many free providers built in. |

**DNS AXFR opportunism:** for every name server discovered, attempt zone transfer:
```
dig @<ns-host> <target-domain> AXFR
```
Most NSs reject; those that don't = full zone disclosure (CRITICAL).

**Brute-force tier:** Subfinder/Subbrute against `assetnote.io` wordlists (best-curated public wordlist source).

### 27.0.1 crt.sh down? Fallback chain (try in order)

crt.sh runs on a single nginx in front of a busy Postgres; 502 / 503 / timeout in peak hours is routine. Don't retry-loop — pivot:

```bash
D="target.example"

# 1. Censys cert search (free 250 queries/month with key) — same data, different infra
censys search "names: ${D}" --index-type certificates --fields names | jq -r '.names[]' | sort -u

# 2. Cert Spotter API (sslmate) — free w/ rate limits
curl -sk "https://api.certspotter.com/v1/issuances?domain=${D}&include_subdomains=true&expand=dns_names" | \
  jq -r '.[].dns_names[]' | sort -u

# 3. CertStream archive (Calidog) — historical CT log mirror
curl -sk "https://crt.calidog.io/?q=${D}" | jq -r '.[].name_value' | sort -u

# 4. Subfinder bundled aggregator (uses 30+ sources internally — Chaos, Anubis, BinaryEdge, BufferOver, Censys, CertSpotter, Crobat, Crtsh, DNSDumpster, FOFA, Fullhunt, GitHub, HackerTarget, IntelX, PassiveTotal, Quake, Rapiddns, Shodan, Spyse, ThreatBook, ThreatMiner, URLScan, VirusTotal, WhoisXML, ZoomEye, etc.)
subfinder -d ${D} -all -recursive -silent

# 5. AlienVault OTX — free, no key
curl -sk "https://otx.alienvault.com/api/v1/indicators/domain/${D}/passive_dns" | \
  jq -r '.passive_dns[].hostname' | sort -u

# 6. ThreatMiner — free
curl -sk "https://api.threatminer.org/v2/domain.php?q=${D}&rt=5" | jq -r '.results[]'

# 7. URLScan — passive DNS via past scans
curl -sk "https://urlscan.io/api/v1/search/?q=domain:${D}" | \
  jq -r '.results[].page.domain' | sort -u

# 8. Anubis-DB / DNSDumpster (HTML scrape, last resort)
curl -sk -A "Mozilla/5.0" "https://anubisdb.com/anubis/subdomains/${D}" | jq -r '.[]'
```

PowerShell crt.sh wrapper with retry + fallback to Subfinder:

```powershell
function Get-Subs {
  param($D)
  for ($i=0; $i -lt 3; $i++) {
    try {
      $r = Invoke-WebRequest -Uri "https://crt.sh/?q=%25.$D&output=json" -UseBasicParsing -TimeoutSec 90 -UserAgent "Mozilla/5.0"
      return ($r.Content | ConvertFrom-Json | %{ $_.name_value -split "`n" } | %{ $_.Trim().ToLower() } | ?{ $_ -and $_ -notlike "*@*" -and $_ -notmatch "^\*\." } | Sort -Unique)
    } catch {
      "crt.sh attempt $($i+1) failed; sleep 5s..." | Out-Host
      Start-Sleep -Seconds 5
    }
  }
  "crt.sh down — pivot to Subfinder: subfinder -d $D -all -silent" | Out-Host
  return @()
}
```

### 27.1 Wordlist Sources for Subdomain + Content Brute-Force

| Source | URL | Notes |
|---|---|---|
| **Assetnote Wordlists** | `https://wordlists.assetnote.io/` | Best-curated; updated regularly. Subdomain top-N (1k, 10k, 100k, 1M, 10M); content-paths per CMS/framework; per-vendor (AWS, Azure, GitLab, etc.). |
| **SecLists** | `https://github.com/danielmiessler/SecLists` | Massive collection. Subdomains: `Discovery/DNS/subdomains-top1million-110000.txt`. Content: `Discovery/Web-Content/`. |
| **jhaddix all.txt** | `https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056` | Long-running curated list. |
| **OneListForAll** | `https://github.com/six2dez/OneListForAll` | Aggregated; very large (millions). |
| **dirsearch wordlists** | `https://github.com/maurosoria/dirsearch` | Bundled with the tool. |
| **raft-large-words.txt** | inside SecLists `Discovery/Web-Content/raft-large-words.txt` | Time-tested content wordlist. |
| **bo0om wordlist** | `https://github.com/bo0om/wordlists` | Russian-language-aware. |
| **commonspeak2** | `https://github.com/assetnote/commonspeak2-wordlists` | Generated from BigQuery commit data. |
| **fuzzdb** | `https://github.com/fuzzdb-project/fuzzdb` | Fuzzing payloads + wordlists. |
| **PayloadsAllTheThings** | `https://github.com/swisskyrepo/PayloadsAllTheThings` | Per-vuln-class payloads (less for enum, more for follow-on). |
| **Custom per-target** | n/a | Best practice: derive a custom wordlist from the target's own content (extract every word from their public website + LinkedIn + careers page → unique → use as seed). |

**Size guidance:**
- **<10k entries** → fast subdomain check (1–2 min); use for opportunistic/passive-supplement.
- **10k–100k entries** → standard depth (10–30 min); use as default brute-force.
- **100k–1M entries** → thorough; use when the target is a known high-value engagement (1–4 hours).
- **>1M entries** → exhaustive; reserve for week-long engagements; expect rate-limiting.

**Tooling:**
```bash

# Subfinder + brute-force with assetnote 100k
subfinder -d target.example -all -recursive | tee passive.txt
puredns bruteforce assetnote-best-dns-wordlist.txt target.example -r resolvers.txt | tee brute.txt
cat passive.txt brute.txt | sort -u > all-subs.txt

# Content brute-force on alive hosts
ffuf -u "https://target.example/FUZZ" -w raft-large-words.txt -mc 200,301,403 -t 50 -ac
```

---

## 28. Infrastructure & Attack-Surface OSINT

- [Shodan](https://www.shodan.io/), [Censys](https://search.censys.io/) — internet device + cert search.
- [GreyNoise](https://viz.greynoise.io/) — distinguish background noise from targeted scans.
- [SecurityTrails](https://securitytrails.com/) — passive DNS + asset discovery.
- [SpiderFoot](https://www.spiderfoot.net/) — automated recon + correlation.
- [theHarvester](https://github.com/laramies/theHarvester) — subdomain, email, metadata.
- [Recon-ng](https://github.com/lanmaster53/recon-ng) — web recon framework.
- [Amass](https://github.com/owasp-amass/amass) / [Subfinder](https://github.com/projectdiscovery/subfinder) — passive subdomain.
- [BuiltWith](https://builtwith.com/) — tech stack enumeration.
- [Netlas](https://netlas.io/) — large-scale HTTP/DNS/cert pivots.
- [BinaryEdge](https://www.binaryedge.io/) / [FOFA](https://fofa.so/) / [ZoomEye](https://www.zoomeye.org/) — Shodan/Censys complements.
- [RiskIQ PassiveTotal](https://community.riskiq.com/) — passive DNS/cert/host pivots.
- [Spur](https://spur.us/) — IP lookups.
- [Robtex](https://www.robtex.com/) — passive DNS + infrastructure.

### 28.1 ASN/BGP & Internet Measurement

- [Hurricane Electric BGP Toolkit](https://bgp.he.net/), [RIPEstat](https://stat.ripe.net/), [BGPView](https://bgpview.io/), [bgp.tools](https://bgp.tools/), [PeeringDB](https://www.peeringdb.com/).

**Bulk IP → ASN — recipes that actually work in 2026:**

```bash

# Cymru bulk WHOIS (fastest; no rate-limit issues; no key required)
echo -e "begin\nverbose\n8.8.8.8\n1.1.1.1\nend" | nc whois.cymru.com 43

# RIPEstat (free; CORS-friendly; ~1 req/sec polite limit)
curl -sk "https://stat.ripe.net/data/network-info/data.json?resource=8.8.8.8" | jq '.data'

# bgp.tools per-IP API (free; light rate-limit; requires UA)
curl -sk -A "osint-recon/1.0 (contact@example.com)" "https://bgp.tools/api/ip/8.8.8.8" | jq .

# IPinfo Lite (free 50k req/month with free key)
curl -sk "https://ipinfo.io/8.8.8.8?token=<key>" | jq .
```

**Watch out:**
- `bgpview.io` API has aggressive undocumented rate limits (~1 req/min/IP); not suitable for bulk.
- `bgp.he.net` has no public API; HTML scraping only — fragile.
- `PeeringDB` is for facility/IX info, not per-IP ASN lookup.
- For bulk (>50 IPs): use the **Cymru bulk format** above; it accepts hundreds of IPs in one TCP session.

### 28.2 Certificates & CT Monitoring

- [crt.sh](https://crt.sh/), [Censys Certificates](https://search.censys.io/certificates), [CertStream](https://certstream.calidog.io/) (real-time CT WebSocket), [Rapid7 Open Data](https://opendata.rapid7.com/), [Cert Spotter](https://sslmate.com/certspotter) (freemium).
- **Favicon mmh3 hash:** cluster infrastructure across hosts; pair with Shodan/Censys favicon search for shared-infra discovery.

### 28.3 Web tech / TLS / fingerprinting

- **httpx (ProjectDiscovery)** — Wappalyzer-compatible ~600 signatures, JARM, favicon mmh3, TLS cert SHA256, security headers, screenshots. Recommended one-shot probe wrapper for thousands of hosts.
- **JARM** — TLS handshake hash; stable per server config; useful for clustering.
- **Wappalyzer** browser extension or CLI for tech enumeration.

### 28.4 TLS Deep Audit

Beyond the cert SAN + JARM, inspect cipher suites, protocols, and config quality.

**sslyze (most thorough):**
```bash
pip install sslyze
sslyze --regular target.example:443
sslyze --json_out=tls.json target.example:443
```
Reports: protocols supported (TLS 1.0/1.1/1.2/1.3), cipher suites per protocol, cert chain, OCSP, key info, robot/heartbleed/lucky13/poodle/freak/logjam/drown/ccs/ticketbleed.

**testssl.sh (thorough + readable output):**
```bash
docker run --rm -ti drwetter/testssl.sh https://target.example

# Or native install: https://github.com/drwetter/testssl.sh
testssl.sh --jsonfile-pretty=tls-report.json target.example:443
```

**nmap script alternative (lighter):**
```bash
nmap --script ssl-enum-ciphers,ssl-cert -p 443 target.example
```

**Check for these issues:**

| Issue | Severity | What to look for |
|---|---|---|
| TLS 1.0 / 1.1 supported | MEDIUM | Deprecated; PCI-DSS forbids TLS 1.0. |
| SSL 3.0 / 2.0 supported | HIGH | Critically deprecated. |
| Weak ciphers (RC4, 3DES, CBC modes) | MEDIUM | RC4 = NOMORE attack; 3DES = SWEET32. |
| Anonymous DH | HIGH | No authentication. |
| Self-signed cert on production | MEDIUM | Trust failure. |
| Expired cert | MEDIUM | Operational + trust failure. |
| Cert valid for too long (>397 days) | LOW | Browser warnings since 2020. |
| Wildcard cert covering critical hosts | INFO | Operational risk if private key compromised. |
| Weak key size (<2048 RSA, <256 ECDSA) | HIGH | Cryptographically weak. |
| Heartbleed (CVE-2014-0160) | CRITICAL | Memory disclosure. |
| ROBOT (CVE-2017-13099) | HIGH | Bleichenbacher. |
| CCS injection (CVE-2014-0224) | HIGH | OpenSSL specific. |
| Ticketbleed (CVE-2016-9244) | HIGH | F5-specific memory disclosure. |
| HSTS not present (covered §16.4) | MEDIUM | Header audit. |

**JA3 / JA4 reference databases:**

- [ja3er.com](https://ja3er.com) — community-curated JA3 → client-software mapping.
- [TLS Fingerprint DB](https://tlsfingerprint.io/) — research aggregator.
- For server JARM: search Shodan `ssl.jarm:<hash>` to find shared infrastructure / origin candidates (see §16.15).

### 28.5 Reverse DNS Sweep & IPv6 Enumeration

When a target owns an IP range (their ASN), enumerate it.

**Reverse DNS sweep (within scope):**
```bash

# Single /24
for i in $(seq 1 254); do
  IP="203.0.113.$i"
  PTR=$(dig +short -x $IP)
  [ -n "$PTR" ] && echo "$IP -> $PTR"
done

# Larger range with parallelism
prips 203.0.113.0/22 | xargs -I {} -P 50 sh -c 'PTR=$(dig +short -x {}); [ -n "$PTR" ] && echo "{} -> $PTR"'
```

**Mass DNS approach (better for large ranges):**
```bash

# zdns: install via go install github.com/zmap/zdns/cmd/zdns@latest
prips 203.0.113.0/22 | zdns PTR
```

**Banner-only sweep (no DNS round trip):**
```bash

# masscan + banner-grab
sudo masscan -p80,443 203.0.113.0/22 --rate=1000 --banners -oX masscan.xml
```

**IPv6 enumeration:**

IPv6 has weaker enumeration tradition (huge address space precludes brute-force) but the AAAA records and known-allocation prefixes are still useful.

```bash

# AAAA records for every discovered subdomain
for sub in $(cat all-subs.txt); do
  AAAA=$(dig +short AAAA $sub)
  [ -n "$AAAA" ] && echo "$sub -> $AAAA"
done

# Instead: extract IPv6 prefixes from the target's allocations
whois -h whois.cymru.com " -v target.example.com"   # gets ASN; then look up prefix
```

**BGP route observation:**

- **RouteViews** — `http://archive.routeviews.org/` (free; historical BGP routing table snapshots).
- **RIPE RIS** — `https://ris.ripe.net/` (free; route collectors).
- Use these to detect route hijacks against the target's prefixes (defensive intel; sometimes IOC).

**Reverse DNS pivots from third-party IPs:**

If a third-party shows the target's domain in PTR records (e.g., a hosting provider's IP has PTR `customer-acme.example.com.hostingprovider.net`), that's a pivot for adjacent customer infrastructure on the same provider/datacenter.

---


## SOURCE: hunt-skills/offensive-osint/references/recon-techniques.md

# Specialized Recon Techniques

> Reference content for the `offensive-osint` skill. Originally §41 + §42 + §43 + §44 + §45 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 41. LinkedIn Employee Enumeration

LinkedIn is the highest-signal source for employee enumeration during external red-team work. Use it for: target list generation, role prioritization, email-pattern derivation, pretext development.

### 41.1 Search techniques

**Free LinkedIn (no Sales Navigator):**
- People-search by company: `https://www.linkedin.com/search/results/people/?currentCompany=["<company-id>"]`. Get company-id from the company's LinkedIn URL or profile JSON.
- Bypass connection-degree filter: search shows 1st/2nd-degree only by default; use Google dorking instead.

**Google dork for LinkedIn employee enum:**
```
site:linkedin.com/in "<company name>"
site:linkedin.com/in "<company name>" "engineer"   # role filter
site:linkedin.com/in "<company name>" "<location>" # location filter
site:linkedin.com/in "<company name>" -inurl:/posts
```

**Bing/DuckDuckGo equivalents** — sometimes return different result sets; cross-engine union.

**LinkedIn Sales Navigator (paid):**
- Most efficient if available. Lead lists by company × role × seniority. Export CSV.

**Tools:**
- **theHarvester** with `-b linkedin` source (uses search-engine-driven enum).
- **CrossLinked** — `https://github.com/m8r0wn/CrossLinked` — CLI tool that does the LinkedIn dorking.
- **LinkedInDumper** / **Linkook** — open-source enum tools (verify currency; they break frequently).
- **PhantomBuster** / **Apollo.io** / **RocketReach** / **Hunter.io Email Finder** — paid SaaS that does the enum + email derivation in one workflow.

### 41.2 Role inference for prioritization

For each enumerated employee, capture:
- **Name** (canonical form: First Last; remove suffixes like "PMP", "PhD" for email-pattern matching).
- **Job title** (raw + normalized to a role tier).
- **Tenure** (years at company; longer = more access typically).
- **Location** (city / region; informs phishing time-of-day).
- **Recent activity** (posts, comments, articles — informs pretext).

**Role priority for breach lookup + phishing target list:**

| Role tier | Examples | Why |
|---|---|---|
| **P0** | CEO, CFO, CTO, CISO, CIO, COO, GC, CRO | Exec accounts; BEC + finance + legal authority. |
| **P1** | VP / Director of IT / Security / Engineering / Finance / HR | Privileged tool access; reset workflows. |
| **P2** | DevOps, SRE, Platform, Security Engineer, DBA | GitHub / cloud / CI access; secrets in their accounts. |
| **P3** | Software Engineer, Architect, Senior Developer | Code + occasional cloud access. |
| **P4** | Sales, Marketing, HR, Finance Analyst, Customer Support | SaaS access (Salesforce, HubSpot, Workday); BEC enabler. |
| **P5** | Generic individual contributor, intern, contractor | Lowest single-account value but breadth matters. |

### 41.3 Email-pattern derivation from confirmed names

For each captured name, derive candidate emails using §11 templates. Cross-reference against:
- Hunter.io `domain-search` to confirm pattern.
- Breach corpus (HudsonRock + HIBP + DeHashed + IntelX) to find matches.

### 41.4 Sock-puppet considerations

- **Never connect from the corporate persona.** LinkedIn shows "viewed your profile" notifications.
- **Use a sock puppet** with a plausible profile (5+ years built history, similar industry, mutual connections to throw off correlation). Tools: persona-builder workflows.
- **LinkedIn "private mode" (anonymous viewing)** — toggle in settings; reduces one signal but Sales Navigator can still see anonymized "someone viewed your profile."
- **Connection requests are detectable.** Don't send any during recon.
- **Profile views accumulate suspicion** if you view 100+ employees of one company in a day. Throttle: <20/day per persona.

### 41.5 Output

Per discovered employee:
```
Person:
  name:        "Alice Doe"
  title:       "Senior DevOps Engineer"
  role_tier:   P2
  company:     "Acme Corp"
  location:    "Boston, MA"
  linkedin_url: https://www.linkedin.com/in/alicedoe
  derived_emails:
    - alice.doe@acme.com    (TENTATIVE)
    - adoe@acme.com         (TENTATIVE)
    - alice@acme.com        (TENTATIVE)
  breach_hits:
    - alice.doe@acme.com    (HudsonRock; cleartext password redacted; FIRM)
  pretext_hooks:
    - "DevOps tooling vendor evaluation" (recent posts)
    - "Boston DevOps Days speaker" (conference activity)
```

---

## 42. Job Posting Tech-Stack Analysis

Job postings reveal the target's internal tech stack with surprising precision. Free, public, and they include the exact vendor names.

### 42.1 Sources

| Platform | URL | Notes |
|---|---|---|
| LinkedIn Jobs | `https://www.linkedin.com/jobs/search/?keywords=&f_C=<company-id>` | Most current; require LI account. |
| Indeed | `https://www.indeed.com/cmp/<company>` | Company page with job feed. |
| Glassdoor | `https://www.glassdoor.com/Jobs/<company>-Jobs-E<id>.htm` | Plus salary data + employee reviews. |
| Lever (ATS) | `https://jobs.lever.co/<company>` | Direct ATS — full job descriptions. |
| Greenhouse (ATS) | `https://boards.greenhouse.io/<company>` | Direct ATS. |
| Workable (ATS) | `https://apply.workable.com/<company>/` | Direct ATS. |
| AshbyHQ (ATS) | `https://jobs.ashbyhq.com/<company>` | Direct ATS. |
| AngelList / Wellfound | `https://wellfound.com/company/<company>/jobs` | Startup-focused. |
| BuiltIn | `https://builtin.com/companies/view/<company>` | Tech-focused. |
| Stack Overflow Jobs | (deprecated 2022 but archive available) | Historical tech-stack data. |
| Company careers page | `https://careers.<target>.com` or `https://<target>.com/careers` | Direct source; sometimes more detail than ATS. |

### 42.2 What to extract

For each job posting, harvest:
- **Required technologies** ("must have experience with X, Y, Z") → confirmed in-use.
- **Nice-to-have technologies** → likely in use but maybe in transition.
- **Vendor names** (Workday, Salesforce, Snowflake, Databricks, Datadog, etc.) → SaaS tenants.
- **Internal tool / project codenames** (often slip into "you'll work on Project Aurora") → recon vocabulary.
- **Team size hints** ("part of a 12-person platform team") → org-structure intel.
- **Office locations** ("hybrid 3 days in Boston office") → physical recon.
- **Cloud + on-prem ratio hints** ("migrating from on-prem to AWS") → posture intel.
- **Compliance frameworks mentioned** (SOC2, FedRAMP, HIPAA, PCI) → defensive priorities + reporting context.

### 42.3 Tooling

- **scrapy / BeautifulSoup** — custom scrapers per ATS.
- **theHarvester** with appropriate sources.
- **JobScraper** scripts on GitHub.
- **Manual** — for small targets, manual review of 20–30 postings is fast and high-fidelity.

### 42.4 Output

Per discovered tech mention:
```
Tech_inferred:
  product:     "Snowflake"
  category:    "data warehouse"
  source:      "linkedin job posting #<id>"
  source_url:  https://www.linkedin.com/jobs/view/...
  confidence:  TENTATIVE  (job listing implies in-use; not yet confirmed by direct probe)
  posting_date: 2026-03-15
  required_or_nice: "required"
```

Aggregate to a **target tech-stack profile** that informs:
- Which secret patterns to look for (Snowflake-specific keys, Databricks tokens).
- Which SaaS tenants to fingerprint (Snowflake account URL pattern).
- Which vendor-product fingerprints to probe (Snowflake DSN paths in JS).

---

### 43.1 Slack

- **Public workspace search** (limited; Slack used to have one but deprecated):
  - **Slofile** (third-party): `https://slofile.com/` — community Slack workspace directory.
  - **Slacklist** / **Slack Communities** — community-curated lists.
- **Invite-link enumeration** — Slack invite URLs follow `https://join.slack.com/t/<workspace-slug>/shared_invite/<token>`. Common discovery:
  - Google: `site:join.slack.com "{target}"` or `inurl:slack.com inurl:shared_invite "{target}"`.
  - GitHub: `"join.slack.com/t/<target-stem>"` filename:README.
  - Twitter/X / Reddit: search for shared invite links.
- **Confirm workspace exists**: visit `https://<slug>.slack.com/api/auth.test` (returns workspace metadata when called by an authenticated session, but the page itself returns differently per workspace existence).
- **High-value finding**: any open invite link that bypasses the target's normal member-approval flow → operator can join workspace without authorization → MEDIUM/HIGH finding (depending on what's in the workspace).

### 43.2 Discord

- **Discord server discovery** is harder (no central public directory).
- **DiscordServers.com** — third-party directory.
- **Discord.me** / **Top.gg** — community directories.
- Google: `site:discord.gg "{target}"` or `site:discord.com "{target}"`.
- **Confirm server**: invite URLs `https://discord.gg/<token>` resolve to a JSON via `https://discord.com/api/v9/invites/<token>?with_counts=true`. Returns server name, ID, member count, channel info.
- **Bot enumeration**: if you find a bot token (catalog §17 row 47), use `getMe` to get bot identity + servers it's joined to (read-only check).

### 43.3 Telegram

Already covered in §38. Quick reference:
- TGStat — channel analytics + search.
- Telemetr — channel growth + overlaps.
- Combot — group analytics.
- View public channels: `https://t.me/s/<channel>`.
- Invite link enum: search Google `site:t.me "{target}"`.

### 43.4 Microsoft Teams (federation)

- See companion methodology skill §11.10.
- Federation status check via Microsoft Graph (auth-required).
- Open-federation default = anyone can chat target's users with `<email>@<target>` lookup.

### 43.5 Mattermost / Rocket.Chat / self-hosted

- `https://mattermost.<target>.com` or `chat.<target>` patterns.
- Open registration check: probe `/signup` page; if accessible without invite → anyone joins.
- Check version disclosure (`/api/v4/system/ping`) for known CVEs.

---

## 44. Package Registry Leak Hunting

Public package registries (npm, PyPI, RubyGems, Docker Hub, etc.) often contain inadvertent secrets in published packages.

### 44.1 npm

- **Search packages by org / scope:**
  ```bash
  npm search "<target-keyword>"
  npm view @<scope>/<package-name>
  ```
- **List org's packages:** `https://www.npmjs.com/org/<org>` or `https://registry.npmjs.org/-/org/<org>/package`.
- **Per-package historical versions:** `https://registry.npmjs.org/<package>` — JSON with all versions.
- **Tarball download for scan:**
  ```bash
  npm pack <package>@<version>
  tar -xzf package-version.tgz
  # Run secret catalog (§17) on extracted files
  ```
- **Common leaks:** `.env` files included in published tarball, `package.json` `scripts` references to internal CI secrets, hardcoded API keys in `dist/` builds.

### 44.2 PyPI

- **Search packages:** `https://pypi.org/search/?q=<target>`.
- **Per-package metadata + history:** `https://pypi.org/pypi/<package>/json`.
- **Download wheel/sdist for scan:**
  ```bash
  pip download <package>==<version> --no-deps -d /tmp/pkg
  unzip /tmp/pkg/*.whl -d /tmp/pkg/extracted
  # Run secret catalog
  ```
- **Common leaks:** `setup.py` with hardcoded URLs, embedded test fixtures with real credentials, accidentally-included `.pypirc` files.

### 44.3 RubyGems

- **Search:** `https://rubygems.org/search?query=<target>`.
- **Per-gem metadata:** `https://rubygems.org/api/v1/gems/<gem-name>.json`.
- **Download:**
  ```bash
  gem fetch <gem-name>
  gem unpack <gem-name>-<version>.gem
  ```

### 44.4 Cargo (Rust crates)

- **Search:** `https://crates.io/search?q=<target>`.
- **Per-crate metadata:** `https://crates.io/api/v1/crates/<crate-name>`.

### 44.5 Packagist (PHP / Composer)

- **Search:** `https://packagist.org/search/?q=<target>`.
- **Per-package metadata:** `https://packagist.org/packages/<vendor>/<package>.json`.

### 44.8 Docker Hub / Quay / GHCR / ECR Public

Already covered in §16.18; worth noting for completeness as part of registry-sweep workflow.

### 44.9 Workflow

For each registry, for each candidate package owned-by-target:
1. List all historical versions (often `<package>@1.0.0` was clean but `<package>@0.9.0` had a leaked key).
2. Download each version's archive.
3. Extract; run secret catalog (§17) over all files.
4. Note `.env`, `package.json`/`setup.py`/`Cargo.toml` for hardcoded values.
5. For Docker images: scan each layer (use `dive` or `skopeo` + `docker save` + extract layers).

### 44.10 Typosquat surveillance

For every published package the target owns, generate typosquat candidates (similar names, common substitutions) and check whether they're already taken by attackers (supply-chain attack surface).

```bash

# Candidates: acme-util, acmeutils, acme_utils, acme.utils, ac-me-utils, etc.
for candidate in acme-util acmeutils acme_utils acme.utils ac-me-utils; do
  npm view $candidate 2>&1 | head -3
done
```

If a candidate is registered to a non-target party → MEDIUM finding (typosquat, possible supply-chain attack vector).

---

## 45. Sat Imagery for Physical Recon

For engagements that include a physical-touch component (badge access, tailgating, dumpster diving, on-site network), public imagery helps scout the target.

### 45.1 Sat imagery sources

| Source | URL | Notes |
|---|---|---|
| **Google Earth Pro** | desktop app | Historical timeline; high resolution (sub-meter) for major cities. |
| **Google Maps** | maps.google.com | Current; satellite layer; street view inside building lobbies sometimes. |
| **Bing Maps Bird's Eye** | bing.com/maps | Oblique/45-degree imagery for many regions; sometimes shows building facades better than top-down. |
| **Apple Maps Look Around** | (iOS / Mac) | Street-level; 3D in major cities. |
| **Yandex Maps Panorama** | yandex.com/maps | Russia + global; sometimes higher-resolution street-level than Google. |
| **NearMap** (paid) | nearmap.com | Highest-resolution commercial; updated frequently in served regions (US/AU/NZ/CA mostly). |
| **Maxar / Planet Labs** (paid) | maxar.com / planet.com | Tasking + recent imagery. |
| **Sentinel Hub EO Browser** | apps.sentinel-hub.com | Free Sentinel-2 (10m); good for change detection. |
| **NASA Worldview** | worldview.earthdata.nasa.gov | Free; multiple sensors. |
| **Wayback ArcGIS** | livingatlas.arcgis.com/wayback/ | Historical satellite. |
| **OpenStreetMap** | openstreetmap.org | Crowd-sourced map data with building outlines. |

### 45.2 What to extract for physical recon

- **Building entrance count + locations** — main entrance, employee entrances, loading docks, fire exits.
- **Parking lot ingress / egress** — single guarded entry vs open lot.
- **Fence lines + camera locations** — physical perimeter.
- **HVAC / utility access** — roof access, service entries.
- **Adjacent occupants** — neighboring tenants in same building / business park.
- **Vehicle types in lot** — proxy for executive presence + employee count.
- **Smoking area locations** — common social-engineering staging area.

### 45.3 OSINT-derived physical intel beyond satellites

- **LinkedIn employee photos** — badge templates often visible in profile photos taken at the office.
- **Glassdoor "office tour" photos** — employees post interior photos.
- **Indeed / Glassdoor reviews** — sometimes describe security culture ("loose badge enforcement", "tailgating common").
- **Instagram geotagged photos** — at the office address; reveals interior layout, badge designs, kitchen / common-area locations.
- **Public press releases** — often contain "ribbon cutting" photos of new offices showing layout + executive faces.
- **Conference talks by IT/security staff** — sometimes describe physical security setup.
- **Meetup / workshop event listings** — at the target's office; may include photos.

### 45.4 Vehicle / fleet intel

- **License plates** in LinkedIn/Instagram backgrounds — sometimes correlates to specific exec.
- **Company-branded vehicles** in sat imagery — fleet count + location.
- **Helicopter pad** / **executive parking** — clue to senior-leadership routine.

### 45.5 Discipline

- Document that imagery + photos are public-source.
- Don't trespass for "verification" — physical recon during OSINT phase = look only.
- Note imagery date — buildings change.

---


## SOURCE: hunt-skills/offensive-osint/references/saas-public-surfaces.md

# Public SaaS Collaboration Surfaces

> Reference content for the `offensive-osint` skill. Originally §24 + §25 + §26 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 24. Postman Public Workspace Universal Search

Postman's public-search endpoint is unauthenticated and indexes every workspace marked public.

**Verified endpoint shape (mid-2025 onward):**

```bash
curl -sk -m 15 \
  "https://www.postman.com/_api/ws/proxy" \
  -H 'Content-Type: application/json' \
  -H 'X-Entity-Team-Id: 0' \
  -d '{
    "service":"search",
    "method":"POST",
    "path":"/search-all",
    "body":{
      "queryIndices":["collaboration.workspace","runtime.collection","runtime.request"],
      "queryText":"acme.com",
      "size":100,
      "from":0,
      "clientTraceId":"",
      "queryAllIndices":false,
      "domain":"public"
    }
  }' | jq '.data[]'
```

This proxies through Postman's web app to their internal search service. Pagination via `from` (0, 100, 200, ...).

**If the proxy shape changes** (it has historically): inspect a real search request from the Postman web UI:
1. Open `https://www.postman.com/explore` in a browser.
2. Open DevTools → Network tab.
3. Search for any term.
4. Find the request to `_api/...` — copy as cURL — adapt.

**Per-workspace walk:**

For each matching workspace ID:

```bash
WS_ID="<workspace-id>"

# Workspace metadata (name, description, team, visibility)
curl -sk -m 10 "https://www.postman.com/_api/workspace/$WS_ID" | jq .

# List collections + environments + monitors in workspace
curl -sk -m 10 "https://www.postman.com/_api/workspace/$WS_ID/collection" | jq '.[].id'
curl -sk -m 10 "https://www.postman.com/_api/workspace/$WS_ID/environment" | jq '.[].id'

# Per-collection: full content (requests, headers, scripts, env vars)
COL_ID="<collection-id>"
curl -sk -m 10 "https://www.postman.com/_api/collection/$COL_ID" | jq '.collection.item[]'
```

**Ownership scoring signals:**
- Creator/team name mentions target domain or brand → strong.
- Workspace name/description mentions target → strong.
- Request URLs contain `*.target.com` → strongest signal (workspace is actively used against target's APIs).

**Run secret catalog (§17) over every text blob extracted** from the requests, env vars, pre-request scripts, and test scripts.

---

## 25. Stack Exchange OSINT Sweep

Stack Exchange and its sister sites collect code paste-ins from developers — many include secrets, internal hostnames, and proprietary code excerpts.

**Sites to query (8 with highest signal):**
```
stackoverflow.com
serverfault.com
dba.stackexchange.com
devops.stackexchange.com
security.stackexchange.com
superuser.com
sharepoint.stackexchange.com
salesforce.stackexchange.com
```

**API:**
```
GET https://api.stackexchange.com/2.3/search/advanced
   ?site=<site>
   &q=<target>
   &filter=withbody
   &pagesize=100
```

**Code block extraction regex:**
```regex
<pre><code>([\s\S]*?)</code></pre>
```
(Stack Exchange wraps code in `<pre><code>` HTML.)

**Pipeline:**
1. Search each site for the target name, brand, root domain.
2. Extract code blocks from `body` HTML.
3. Run secret catalog (§17) over each block.
4. Cross-reference post author email (where exposed in profile) against email_osint discoveries — confirms employee posting target's internal code.
5. Extract hostnames from code blocks → upsert as `subdomain` assets.

**Quota:** Stack Exchange API permits 30 requests/day without a key; with a free key, 10,000/day. Throttle with 2-second min interval per call.

---

## 26. Public SaaS Collaboration Surfaces

Many SaaS collaboration tools allow public sharing. Dork them like search engines.

**Platforms with high incident rate:**
```
trello.com
notion.so / notion.site
*.atlassian.net           (Jira / Confluence)
miro.com
asana.com
clickup.com
airtable.com
```

**Dork template:**
```
site:{platform} "{target-keyword}"
```

**Run via search-engine adapter** (DDG default; Bing / Brave / Yandex / SerpAPI optional). The same classification logic from §18.7 applies.

**Common findings:**
- Public Trello board with credentials in card titles or attached config files.
- Public Notion page with internal SOPs, API keys in code blocks, customer data.
- Public Confluence space with onboarding docs containing seed creds.
- Public Miro board with architecture diagrams revealing internal hostnames.

---


## SOURCE: hunt-skills/offensive-osint/references/sector-notes.md

# Sector-Specific Recon Notes

> Reference content for the `offensive-osint` skill. Originally §47 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 47. Sector-Specific Recon Notes

Most recon generalizes; some sectors have unique attack-surface elements worth flagging.

### 47.1 Healthcare

- **DICOM** (medical imaging) — port 11112, sometimes 4242 (testing).
- **HL7 v2** (clinical messaging) — port 2575 (TCP, often plaintext).
- **HL7 FHIR** (modern REST API) — typically `/fhir/R4/<resource>` paths; OAuth / SMART-on-FHIR auth posture varies wildly.
- **PACS / RIS / EHR systems** — Epic (`*.epic.com` SaaS), Cerner/Oracle Health, Allscripts/Veradigm, Athenahealth, NextGen, Meditech, eClinicalWorks. Each has known CVE history.
- **Searches:** `site:{domain} ("EHR" OR "PACS" OR "PHI" OR "HIPAA")`, `intitle:"Epic Systems" "{target}"`.
- **Severity escalation:** any PHI exposure → CRITICAL (regulatory + reputational); HL7/DICOM open without auth → CRITICAL.

### 47.2 Finance

- **SWIFT terminals** — typically internal-only; if external-facing, CRITICAL. Look for SWIFT Alliance Web Platform.
- **FIX protocol** (electronic trading) — port 9876 (common); cleartext.
- **Bloomberg terminals** — typically VDI; check for `bloomberg.com`-related auth surfaces.
- **Trading platform vendors** — Fidessa, Charles River, Eze Software, Aladdin (BlackRock).
- **Banking middleware** — Temenos T24, Finacle (Infosys), FIS, Jack Henry, Fiserv. Each has known CVE history.
- **Searches:** `site:{domain} ("PCI" OR "SOX" OR "GLBA" OR "MAS")`, `intitle:"Temenos" "{target}"`.
- **Severity escalation:** any account/balance data exposure → CRITICAL; SWIFT exposure → CRITICAL; trade-execution surface exposure → CRITICAL.

### 47.3 ICS / SCADA / OT

> **Caution:** ICS/SCADA assets often run on legacy systems where even passive scanning can cause disruption. **Do not actively probe ICS without explicit RoE coverage and operator coordination with the OT team.**

- **Modbus** — port 502 (TCP).
- **BACnet** — port 47808 (UDP).
- **Siemens S7** — port 102 (ISO-TSAP).
- **DNP3** — port 20000 (TCP).
- **EtherNet/IP** — port 44818 (TCP).
- **Niagara Framework** — port 1911, 4911, 5011, 502.
- **Honeywell EBI / Tridium** — varies.
- **GE Proficy / iFIX** — varies.
- **Common findings:** unauthenticated read access (BACnet point list, Modbus register read), default credentials on HMI panels, public-facing engineering workstations.
- **Sources:** Shodan ICS-specific filters (`port:502`, `tag:ics`), Censys, Onyphe.
- **Detectability:** medium-to-high; ICS networks often have low background traffic and are heavily monitored.

### 47.4 IoT / Consumer / SOHO

- **MQTT** — port 1883 (cleartext), 8883 (TLS). Topics often readable without auth.
- **CoAP** — port 5683 (UDP).
- **UPnP / SSDP** — port 1900 (UDP); often discloses internal device map.
- **Common router admin patterns:** `/cgi-bin/`, `/setup.cgi`, `/admin/index.html`. Default creds are the norm.
- **Camera DVRs / NVRs** — Hikvision, Dahua, Axis. Multiple CVEs.
- **Smart-home hubs** — exposed APIs sometimes leak auth tokens.

### 47.5 Government

- **`.gov` and `.mil` domains** require special engagement-scope discipline.
- **FedRAMP / FISMA / DoD CMMC** — defensive posture is generally above baseline.
- **OSINT data sources:** USAspending.gov, SAM.gov (System for Award Management), FBO.gov / sam.gov (procurement).
- **Common findings:** vendor of record disclosed in public contracts → adjacent-vendor pivot.
- **Severity:** as high or higher than commercial; political sensitivity layered on top of technical impact.

### 47.6 Maritime / Aviation / Auto

- **Maritime:** AIS (Automatic Identification System) — vessel positions; tools MarineTraffic, VesselFinder. Engine telemetry sometimes exposed via VSAT.
- **Aviation:** ADS-B (already covered §32.3); operator/airline-specific OPS data sometimes exposed.
- **Automotive:** OEM telematics backends (Tesla, GM OnStar, etc.) — typically authenticated, but APIs leak via mobile-app reverse engineering.

### 47.7 Universal sector caveat

**Most external recon techniques apply universally.** Sector-specific protocols add attack surface; sector-specific compliance regimes add reporting requirements. Don't assume "healthcare/finance/etc. has different OSINT" — the OSINT is the same; the targeted services differ.

---


## SOURCE: hunt-skills/offensive-osint/references/severity-matrix.md

# Severity Decision Matrix

> Reference content for the `offensive-osint` skill. Originally §40 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 40. Severity Decision Matrix — Worked Examples

When in doubt, anchor on these worked examples (drawn from real engagements):

| Finding | Severity | Why |
|---|---|---|
| `/.git/config` reachable on prod webapp | **CRITICAL** | Full source-code disclosure; secret history reconstructable. |
| `/.env` reachable on prod webapp | **CRITICAL** | Plaintext creds (DB, cloud, API). |
| Open Firebase RTDB returning data | **CRITICAL** | All app data readable; often writable. |
| Listable S3 bucket containing PII | **CRITICAL** | Direct data exfil. |
| Listable S3 bucket containing logs only | HIGH | Internal hostnames + paths in logs; pivot data. |
| Spring Boot `/actuator/env` exposed | **CRITICAL** | DB creds, JWT secrets, cloud keys in env. |
| Spring Boot `/actuator/heapdump` exposed | **CRITICAL** | Heap contains live secrets in string form. |
| Open Elasticsearch (`/_cat/indices` returns) | **CRITICAL** | Full data reads; often writable. |
| Open MongoDB (no auth) | **CRITICAL** | Full data + password-hash collection. |
| Open Redis (no AUTH) | **CRITICAL** | Write `authorized_keys` → SSH foothold. |
| Open Docker API (port 2375) | **CRITICAL** | Container/host takeover. |
| Public PMAK validated live with broad scope | **CRITICAL** | Full Postman account + all team workspaces. |
| Public AWS root access key validated live | **CRITICAL** | Full account compromise. |
| Live AWS IAM-user key found on GitHub | HIGH | Limited scope (depends on IAM policy); often elevatable. |
| Live GitHub PAT found in JS bundle | HIGH | Repo write access (depends on scope). |
| Live Slack token in pastebin | HIGH | Workspace data + history; sometimes channel post. |
| Sourcemap (`.js.map`) accessible on prod | HIGH | Frontend source disclosure. |
| Open GraphQL introspection on prod | HIGH | Full schema → mutations + business-logic discovery. |
| Subdomain takeover possible (Heroku / GitHub Pages / etc.) | HIGH | Takeover → phishing on trusted domain. |
| Reflected CORS with credentials on `/api/billing` | HIGH | CSRF-via-CORS for billing data. |
| Verb tampering: DELETE allowed on documented-GET-only endpoint | HIGH | Authz bypass; potentially destructive. |
| `phpinfo.php` reachable on prod | HIGH | Discloses paths, env vars, modules → vuln-version pivot. |
| Tomcat `/manager/html` reachable | HIGH | Often default creds; WAR upload = RCE. |
| Jenkins script console accessible | HIGH | Groovy script execution = RCE. |
| Missing HSTS on `/login` | HIGH (escalated from MED) | Login pages must enforce HSTS. |
| Missing HSTS on standard pages | MEDIUM | Hardening gap. |
| Missing CSP | MEDIUM | XSS impact mitigation gone. |
| Internal IP / K8s service DNS in JS | MEDIUM | Internal topology disclosure. |
| Apache `/server-status` reachable | MEDIUM | Live request visibility. |
| `android:debuggable=true` on prod app | **CRITICAL** | Production debug-build → full client compromise. |
| `android:allowBackup=true` (no whitelist) | MEDIUM | App data exfil via `adb backup`. |
| `android:usesCleartextTraffic=true` | MEDIUM | MITM-able on hostile networks. |
| Sensitive deep-link handler (`myapp://reset-password`) | HIGH | Other apps can trigger sensitive flows. |
| Exported Android component without permission | MEDIUM | IPC attack surface. |
| Slack webhook URL leaked | MEDIUM | Send to channel; can be used for social-eng. |
| Twilio Account SID leaked (no auth token) | MEDIUM | Half a credential pair; plus account enumeration. |
| Wildcard CORS on data-returning API | MEDIUM | Lower than reflected+creds but still exfil-able. |
| Missing `X-Frame-Options` | LOW | Clickjacking. |
| `.DS_Store` exposed | LOW | Directory listing of dev's machine. |
| Stripe **test** key leaked | LOW | No real money risk. |
| Firebase URL exposed (no open RTDB) | LOW | Project-ID disclosure only. |
| Cert pinning missing in mobile app | LOW | MITM possible on hostile networks. |
| Outdated WordPress install detected | LOW | Pending CVE confirmation. |
| Missing `Referrer-Policy` / `Permissions-Policy` | INFO | Hardening, not an exposure. |
| `/.well-known/security.txt` discovered | INFO | Useful contact info only. |
| Domain in breach with 0 named accounts | INFO | Contextual only. |
| Private bucket exists (HEAD 403) | INFO | Asset only, no finding. |
| Open kubelet on 10250 | **CRITICAL** | Pod exec without K8s API auth. |
| Open etcd on 2379 | **CRITICAL** | Cluster state + secrets. |
| K8s API on 6443 with anonymous-auth | HIGH | Cluster recon; sometimes pod exec. |
| K8s dashboard exposed without auth | HIGH | Cluster admin UI. |
| Helm Tiller (Helm 2) on 44134 | HIGH | Cluster-admin scope. |
| Citrix Netscaler with KEV CVE | **CRITICAL** | Patch immediately; actively exploited. |
| F5 BIG-IP TMUI accessible | HIGH | TMUI = admin panel; CVE-2022-1388 if unpatched = CRIT. |
| Pulse Secure with CVE-2024-21887 | **CRITICAL** | KEV; chained command injection. |
| FortiGate with CVE-2024-21762 | **CRITICAL** | KEV; auth bypass + RCE. |
| PaloAlto GlobalProtect with CVE-2024-3400 | **CRITICAL** | KEV; pre-auth RCE. |
| VMware vCenter with CVE-2021-21972 | **CRITICAL** | KEV; pre-auth RCE. |
| VMware ESXi exposed without VPN | HIGH | Multiple CVEs (ESXiArgs ransomware vector). |
| MS Exchange with ProxyShell/Logon/NotShell unpatched | **CRITICAL** | KEV chain; RCE + mailbox dump. |
| AWS Lambda Function URL accessible anonymously | HIGH | Direct invocation; check IAM auth posture. |
| Public Cloud Run / Cloud Function unauthenticated | HIGH | Same. |
| Public Docker registry (anonymous catalog) | MEDIUM | Image enum + secret hunt in layers. |
| GitHub Actions secrets echoed in workflow logs | HIGH | Secret-in-log = full secret disclosure. |
| GitHub Actions `pull_request_target` checkout of fork code | HIGH | Class of bug; secrets accessible to attacker PRs. |
| GitLab self-hosted with CVE-2021-22205 | **CRITICAL** | KEV; ExifTool RCE. |
| Jenkins with `pull_request_target`-equivalent misconfig | HIGH | Build secrets accessible to PRs. |
| Public Notion page with internal SOPs | MEDIUM | Operational intel; sometimes credentials. |
| Public Trello board with credentials in cards | HIGH | Often plaintext API keys. |
| Public Confluence space with onboarding docs | MEDIUM | Seed creds + tech-stack reveal. |
| Public Miro board with architecture diagrams | LOW | Internal-host disclosure. |
| DMARC policy `p=none` on production sending domain | MEDIUM | Spoof feasible (escalated from LOW for risk surface). |
| SPF `~all` (softfail) without strict DMARC | MEDIUM | Spoofs land in spam, but land. |
| MX server allows open relay (test with 250 OK to RCPT TO foreign domain) | HIGH | Spam + spoof feasibility. |
| Live Anthropic / OpenAI API key with broad scope | **CRITICAL** | Quota cost + potential PII in past responses. |
| Live npm token with `publish` scope | **CRITICAL** | Supply-chain compromise of all maintained packages. |
| Live PyPI / Docker Hub / GHCR token with publish scope | **CRITICAL** | Supply-chain compromise. |
| Atlassian token with admin scope | HIGH | Workspace-wide read; sometimes write. |
| Subdomain takeover candidate confirmed | HIGH | Trusted-domain phishing surface. |
| Sensitive CI/CD wordlist hits (Jenkinsfile, .gitlab-ci.yml on public repo) | MEDIUM | Build-script intel; often references secret names. |
| Public Postman workspace with internal API endpoints | MEDIUM | API attack surface mapped. |
| WAF/CDN trivially bypassable (origin discoverable via §16.15) | HIGH | All WAF protections null. |
| TLS 1.0/1.1 supported on prod | MEDIUM | Compliance gap; PCI-DSS forbids TLS 1.0. |
| RC4 / 3DES cipher accepted | MEDIUM | NOMORE / SWEET32 attacks. |
| Cert about to expire (<30 days) | LOW | Operational risk; not exploitable. |
| Self-signed cert on prod | MEDIUM | Trust failure for users. |
| Heartbleed (CVE-2014-0160) detected | **CRITICAL** | Memory disclosure including session tokens + keys. |
| Public Slack invite link discoverable | HIGH | Anyone joins workspace; full DM/channel access. |
| Vendor / supplier / e-procurement portal publicly exposed + breach corpus shows vendor accounts compromised | **HIGH** | Vendor impersonation + procurement fraud (BEC vector); regulatory exposure if PII/payment data flows. |
| Job-application / careers portal collects PII over plain HTTP (no TLS) | **HIGH** | Cleartext PII at scale; regulatory exposure under GDPR / CCPA / India DPDP Act / LGPD. |
| Decommissioned legacy mail (NXDOMAIN today) + breach corpus has historical employee URLs against it + cloud SSO migration confirmed via autodiscover IPs | **CRITICAL** | Stolen passwords almost certainly survived migration via reuse; SSO_EXPOSURE escalates regardless of the legacy host being dead. |
| Public-facing intranet (`intranet.<domain>` resolves and returns content without VPN) | MEDIUM | Internal-staff portal exposed; often leaks org structure, employee directory, internal apps. |
| Staging / preprod / UAT / sandbox subdomain publicly resolvable | MEDIUM | Often weak
[... truncated for digest; original source remains in the source folder ...]


## SOURCE: hunt-skills/offensive-osint/references/specialized-osint.md

# Threat Intel, Crypto, Media, Geo, Regional, Telegram OSINT

> Reference content for the `offensive-osint` skill. Originally §29 + §30 + §31 + §32 + §37 + §38 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 29. Threat Intel & IOCs

- Vendor / CERT advisories: CISA/NSA/CSA joint advisories, CERT-EU, NCSC-UK, JPCERT/CC, CERT-UA.
- [MISP Project](https://www.misp-project.org/) and public MISP feeds.
- [OpenCTI](https://www.opencti.io/) — CTI knowledge graph.
- [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) — malware families, YARA, references.
- [ThreatFox](https://threatfox.abuse.ch/), [URLHaus](https://urlhaus.abuse.ch/), [SSLBL](https://sslbl.abuse.ch/).
- [MalwareBazaar](https://bazaar.abuse.ch/) — hash-based sample sharing.
- [PhishTank](https://www.phishtank.com/), [OpenPhish](https://openphish.com/).

### 29.1 Malware Analysis & Sandboxes

- Static: [pefile](https://github.com/erocarrera/pefile), [FLOSS](https://github.com/mandiant/flare-floss), [capa](https://github.com/mandiant/capa).
- Similarity: SSDEEP, TLSH.
- Sandboxes: [ANY.RUN](https://any.run/), [Hybrid Analysis](https://www.hybrid-analysis.com/), [CAPE](https://capesandbox.com/), [Tria.ge](https://tria.ge/).
- Intelligence: [Intezer](https://analyze.intezer.com/) (code reuse), [VirusTotal](https://www.virustotal.com/) — **caution: uploads become public**.
- TLS: [JA3](https://github.com/salesforce/ja3), [JA4](https://github.com/FingerprinTLS/ja4).

### 29.2 Vulnerability Prioritization Data Sources

Methodology in companion skill §28. Concrete data sources here.

| Source | URL | What it tells you |
|---|---|---|
| **NVD** | `https://nvd.nist.gov/vuln/search` (or API `services.nvd.nist.gov/rest/json/cves/2.0`) | Base CVE catalog with CVSS v2/v3 scores. |
| **EPSS** | `https://www.first.org/epss/` (CSV at `https://epss.cyentia.com/epss_scores-current.csv.gz`) | 0.0-1.0 probability of exploit in next 30 days. Updated daily. |
| **CISA KEV** | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | CVEs proven exploited in the wild + federal-agency due-by dates. |
| **ExploitDB** | `https://www.exploit-db.com/`; offline DB via `searchsploit` | POC code presence (Metasploit, Python, shell). |
| **Metasploit module catalog** | `https://www.rapid7.com/db/modules/` (or `msfconsole > search cve:CVE-2024-XXXX`) | Automation availability. |
| **InTheWild.io** | `https://inthewild.io/` | Community-curated "actively exploited" tracker. |
| **OpenCVE** | `https://www.opencve.io/` | Timeline + watchlist + alerts. |
| **Trickest CVE → POC mapping** | `https://github.com/trickest/cve` | Auto-generated CVE → public POC repo links. |
| **GitHub Security Advisories** | `https://github.com/advisories` | Per-language / per-ecosystem advisories. |
| **MITRE CVE List** | `https://cve.mitre.org/cve/` | Official CVE registry. |
| **VulnDB** | `https://vulndb.cyberriskanalytics.com/` | Paid; commercial enrichment. |
| **OSV.dev** | `https://osv.dev/` | Open-source vulnerability DB; JSON API. |
| **Vulncheck KEV** | `https://vulncheck.com/kev` | Expanded KEV feed (more than CISA). |
| **Tenable Research** | `https://www.tenable.com/research` | Tenable's CVE detail enrichment. |
| **Qualys ThreatPROTECT** | `https://threatprotect.qualys.com/` | Qualys' threat-context enrichment. |

**Workflow:**
```bash

# 1. Get EPSS score for a CVE
curl -sk "https://api.first.org/data/v1/epss?cve=CVE-2024-3400" | jq '.data[0]'

# 2. Check if in CISA KEV
curl -sk https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | \
  jq '.vulnerabilities[] | select(.cveID == "CVE-2024-3400")'

# 4. Check Metasploit
msfconsole -q -x "search cve:2024-3400; exit"
```

**Bulk prioritization** (given a Nuclei scan output with N CVEs):
```bash

# Extract CVEs from nuclei JSON output
jq -r '.info.classification.["cve-id"][]?' nuclei-results.json | sort -u > cves.txt

# Annotate each with EPSS + KEV
while IFS= read -r CVE; do
  EPSS=$(curl -sk "https://api.first.org/data/v1/epss?cve=$CVE" | jq -r '.data[0].epss // "N/A"')
  KEV=$(curl -sk https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | \
    jq --arg c "$CVE" '.vulnerabilities[] | select(.cveID == $c) | .vulnerabilityName // empty')
  KEV_FLAG=$([ -n "$KEV" ] && echo "KEV" || echo "")
  echo "$CVE | EPSS:$EPSS | $KEV_FLAG"
done < cves.txt | sort -t: -k2 -nr

---

### 30.1 Blockchain Explorers

| Chain | Explorer |
|-------|---------|
| Bitcoin | [Blockchain.com](https://www.blockchain.com/explorer), [Blockchair](https://blockchair.com/) |
| Ethereum | [Etherscan](https://etherscan.io/) |
| BNB Chain | [BSCScan](https://bscscan.com/) |
| Polygon PoS | [PolygonScan](https://polygonscan.com/) |
| Solana | [Solscan](https://solscan.io/) |
| Multi-chain | [OKLink](https://www.oklink.com/) (freemium), [Cielo](https://cielo.io/) |

### 30.2 L2 / Rollup Explorers

| L2 | Explorer | Notes |
|---|---|---|
| Arbitrum | [Arbiscan](https://arbiscan.io/) | Optimistic rollup; 7-day challenge window. |
| Optimism | [Optimistic Etherscan](https://optimistic.etherscan.io/) | Optimistic rollup; 7-day challenge window. |
| Base | [BaseScan](https://basescan.org/) | OP Stack. |
| Blast | [Blastscan](https://blastscan.io/) | OP Stack derivative. |
| Scroll | [Scrollscan](https://scrollscan.com/) | zkEVM. |
| zkSync Era | [zkSync Era Block Explorer](https://explorer.zksync.io/) | zkRollup; faster finality. |
| Polygon zkEVM | [PolygonScan zkEVM](https://zkevm.polygonscan.com/) | zkEVM. |
| StarkNet | [Voyager](https://voyager.online/), [StarkScan](https://starkscan.co/) | Cairo VM; different address derivation. |
| Cross-L2 | [L2Beat](https://l2beat.com/) | Risk framework + TVL comparison. |

### 30.3 Transaction Tracking & Analytics

- [Arkham](https://www.arkhamintelligence.com/) — multichain, entity labels, graphs, alerts.
- [TRM](https://www.trmlabs.com/) — address/tx graphs.
- [MetaSleuth](https://metasleuth.io/) — visual flow.
- [Breadcrumbs](https://www.breadcrumbs.app/) (freemium) — visual graphing + labels.
- [Bubblemaps](https://bubblemaps.io/) — holder concentration.
- [Whale Alert](https://whale-alert.io/) — large transaction monitoring.
- [Chainalysis](https://www.chainalysis.com/) / [Crystal Blockchain](https://crystalblockchain.com/) — pro analytics.
- [GraphSense](https://graphsense.info/) — open-source crypto analytics.
- [Nansen](https://www.nansen.ai/) — Smart Money labels (paid).
- [Dune](https://dune.com/) — custom queries.
- [Token Sniffer](https://tokensniffer.com/) — honeypot/scam detection.

### 30.4 NFT / Exchange / Bridges

- [OpenSea](https://opensea.io/), [NFTScan](https://www.nftscan.com/), [DappRadar](https://dappradar.com/), [CoinGecko](https://www.coingecko.com/), [CoinMarketCap](https://coinmarketcap.com/), [Glassnode](https://glassnode.com/).
- Bridges: [Socketscan](https://socketscan.io/), [L2Beat Bridges](https://l2beat.com/bridges), [Pulsy](https://pulsy.io/).

---

### 31.1 Reverse Image & Facial Search

- [Google Images](https://images.google.com/), [TinEye](https://tineye.com/), [Yandex Images](https://yandex.com/images/) (Russian/East European strong), [PimEyes](https://pimeyes.com/en), [FaceCheck](https://facecheck.id/).

### 31.2 Image Forensics

- [Forensically](https://29a.ch/photo-forensics/), [ExifTool](https://exiftool.org/), [Jimpl](https://jimpl.com/), [Jeffrey's EXIF Viewer](http://exif.regex.info/exif.cgi), [FOCA](https://www.elevenpaths.com/labstools/foca), [Metagoofil](https://www.edge-security.com/metagoofil.php), [C2PA Verify](https://verify.contentauthenticity.org/).

### 31.3 Video Analysis

- [YouTube Data Viewer](https://citizenevidence.amnestyusa.org/), [InVID & WeVerify](https://www.invid-project.eu/tools-and-services/invid-verification-plugin/), [YouTube Geo Tag](https://mattw.io/youtube-geofind/location), [MediaInfo](https://mediaarea.net/en/MediaInfo), Snap Map.

### 31.4 Browser Extensions for Media

- [Fake News Debunker (InVID & WeVerify)](https://chrome.google.com/webstore/detail/fake-news-debunker-by-inv/mhccpoafgdgbhnjfhkcmgknndkeenfhe).
- [RevEye Reverse Image Search](https://chrome.google.com/webstore/detail/reveye-reverse-image-sear/kejaocbebojdmebagkjghljkeefgimdj).
- [EXIF Viewer Pro](https://chrome.google.com/webstore/detail/exif-viewer-pro/mmbhfeiddhndihdjeganjggkmjapkffm).
- [Wayback Machine Extension](https://chrome.google.com/webstore/detail/wayback-machine/fpnmgdkabkmnadcjpehmlllkndpkmiak).
- [Search by Image](https://chromewebstore.google.com/detail/search-by-image/cnojnbdhbhnkbcieeekonklommdnndci).

---

### 32.1 Satellite & Mapping

- [Google Maps](https://www.google.com/maps), [Bing Maps](https://www.bing.com/maps/).
- [Sentinel Hub EO Browser](https://apps.sentinel-hub.com/eo-browser/), [NASA Worldview](https://worldview.earthdata.nasa.gov/), [Zoom Earth](https://zoom.earth/).
- [Wayback Imagery](https://livingatlas.arcgis.com/wayback/) — historical satellite.
- [NASA FIRMS](https://firms.modaps.eosdis.nasa.gov/map/), [Open Infrastructure Map](https://openinframap.org/), [Windy](https://www.windy.com/).

### 32.2 Geolocation Tools

- [Mapillary](https://www.mapillary.com/app), [KartaView](https://kartaview.org/), [Overpass Turbo](https://overpass-turbo.eu/), [SunCalc](https://www.suncalc.org/), [GeoNames](https://www.geonames.org/), [PeakVisor](https://peakvisor.com/), [GeoGuesser tips](https://somerandomstuff1.wordpress.com/2019/02/08/geoguessr-the-top-tips-tricks-and-techniques/).

**Street View:** Google Street View, [Apple Maps](https://maps.apple.com/), [Yandex Maps](https://yandex.com/maps/), [Baidu Maps](https://map.baidu.com/).

### 32.3 Flight OSINT

- [FlightRadar24](https://www.flightradar24.com/), [FlightAware](https://www.flightaware.com/), [RadarBox](https://www.radarbox.com/).
- [ADSBExchange](https://www.adsbexchange.com/) — unfiltered.
- [Planespotters](https://www.planespotters.net/) — fleet/airframe history.
- [AirFrames](https://www.airframes.org/), [JetPhotos](https://www.jetphotos.com/).

### 32.4 Maritime OSINT

- [MarineTraffic](https://www.marinetraffic.com/), [VesselFinder](https://www.vesselfinder.com/), [FleetMon](https://www.fleetmon.com/).
- [Global Fishing Watch](https://globalfishingwatch.org/map/) — vessel behavior + AIS gap analysis.

---

## 37. Regional Search Engines

- **Russia / CIS:** [Yandex](https://yandex.com/), [Mail.ru Search](https://go.mail.ru/).
- **China:** [Baidu](https://www.baidu.com/), [Sogou](https://www.sogou.com/), [360 Search](https://www.so.com/).
- **Russia social:** [VK](https://vk.com/), [OK.ru](https://ok.ru/).
- **China social:** [Weibo](https://weibo.com/), [Bilibili](https://www.bilibili.com/), [Zhihu](https://www.zhihu.com/), [Douyin](https://www.douyin.com/).

---

## 38. Telegram & Messaging Intelligence

- [TGStat](https://tgstat.com/) — channel analytics + search.
- [Telemetr](https://telemetr.io/) — channel growth, overlaps, forwards.
- [Combot](https://combot.org/) — group analytics (partial paid).
- [TelegramDB Search Bot](https://t.me/TGdb_bot) — basic Telegram OSINT.
- [Discord ID](https://discord.id/) — basic Discord account info.
- [Sogou Weixin search](https://weixin.sogou.com/) — WeChat Official Accounts.
- View public Telegram channels: `https://t.me/s/<channel>`.

---


## SOURCE: hunt-skills/offensive-osint/references/tooling-install.md

# Tooling Quick-Install

> Reference content for the `offensive-osint` skill. Originally §46 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 46. Tooling Quick-Install

One-liner installs for the most-used external recon tools. All assume Linux/Mac with go/python/git installed.

# Subfinder (passive, fast)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# DNSx (resolution + brute)
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Puredns (brute-force with wildcard handling)
go install github.com/d3mondev/puredns/v2@latest
```

# httpx (tech-detect, status, JARM, favicon)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Aquatone (screenshots + clustering)
go install github.com/michenriksen/aquatone@latest
```

# Nuclei (template scanner)
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -ut    # update templates

# Naabu (port scan)
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Masscan (fast port scan; requires sudo)
git clone https://github.com/robertdavidgraham/masscan && cd masscan && make
```

# Katana (crawler)
go install github.com/projectdiscovery/katana/cmd/katana@latest

# LinkFinder (JS endpoint regex)
git clone https://github.com/GerbenJavado/LinkFinder && cd LinkFinder && pip install -r requirements.txt

# gau (get all urls from Wayback + others)
go install github.com/lc/gau/v2/cmd/gau@latest

# Cloud_enum (S3/Azure/GCP enum)
git clone https://github.com/initstring/cloud_enum && cd cloud_enum && pip install -r requirements.txt

# CloudSploit
git clone https://github.com/aquasecurity/cloudsploit && cd cloudsploit && npm install
```

# CredMaster (per-protocol auth probe)
git clone https://github.com/knavesec/CredMaster
```

# Trufflehog (secret scanner)
go install github.com/trufflesecurity/trufflehog@latest

# ProjectDiscovery's "PDTM" (manages the full PD toolkit)
go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
pdtm -install-all

# reconftw (scripted recon framework)
git clone https://github.com/six2dez/reconftw && cd reconftw && ./install.sh

# Axiom (distributed recon on cloud nodes)
git clone https://github.com/pry0cc/axiom && cd axiom && ./interact/axiom-configure
```

---


## SOURCE: hunt-skills/osint-methodology/README.md

# `osint-methodology` skill

The "how to think" reference for external red-team OSINT and bug-bounty reconnaissance.

| Field | Value |
|---|---|
| Name | `osint-methodology` |
| Version | 2.1 |
| Lines | ~1,700 |
| Top-level sections | 33 |
| Subsections | ~125 |
| Companion skill | [`offensive-osint`](../offensive-osint/) |

## When this skill triggers

Auto-triggers on prompts containing any of ~55 trigger phrases. Common ones:

- `external recon`, `external red team`, `bug bounty recon`, `attack surface management`, `ASM`, `perimeter recon`
- `OSINT methodology`, `recon methodology`, `target reconnaissance`, `asset discovery`, `attack path`
- `identity fabric`, `SSO discovery`, `IdP fingerprinting`, `M365 enumeration`
- `phishing infrastructure`, `pretext development`, `bug bounty submission`, `responsible disclosure`
- `client report`, `exec summary`, `risk translation`
- `confidence upgrade`, `time budget`, `engagement profile`, `asset triage`
- `detection-aware probing`, `back-off strategy`, `persona rotation`
- `WAF bypass`, `CDN bypass`, `origin discovery`
- `vulnerability prioritization`, `CVE prioritization`, `EPSS`, `CISA KEV`
- `threat actor investigation`, `attribution`

Full trigger list in the SKILL.md frontmatter.

## What's in it

See the parent [README's "What's in the box" table](../../README.md#whats-in-the-box) for the full §-by-§ breakdown.

Highlights:

- **§7 — 5-stage recon pipeline** + priority order + time budgeting (1h / 4h / 1d / 1w profiles)
- **§8 — Asset graph discipline** with 29 typed asset types + 23 typed edges + per-asset-type triage
- **§9 — Findings rubric** anchored on examples (CRITICAL → INFO + escalation rules)
- **§11 — Identity fabric mapping** (Entra, Okta, ADFS, Google, SAML, AWS, M365 deep)
- **§22 — Breach × identity correlation** (HudsonRock + HIBP + DeHashed + IntelX → SSO_EXPOSURE finding)
- **§27 — WAF/CDN bypass + origin discovery** (8 techniques)
- **§28 — Vulnerability prioritization** (CVE × EPSS × KEV × Metasploit rubric)
- **§29 — Phishing infrastructure & pretext development**
- **§30 — Bug bounty submission templates** (HackerOne, Bugcrowd, Intigriti, etc.)
- **§31 — Client deliverable templates** (exec summary + risk translation matrix + reporting cadence)

# Local Claude Code install
cp SKILL.md ~/.claude/skills/osint-methodology/SKILL.md

# (paste contents of SKILL.md as project knowledge)
```

The full content lives in this `SKILL.md` (or in `docs/full-skills/osint-methodology.SKILL.full.md` if this file is the structured-outline variant — see repo root for sync instructions).

## Self-test

Run the prompts in [`../../tests/smoke-test-prompts.md`](../../tests/smoke-test-prompts.md) to verify skill behavior after install. Methodology-targeted prompts are tagged in the test file.


## SOURCE: hunt-skills/osint-methodology/SKILL.md

## 0. When to use this skill / When NOT

**Use this skill when:**
- Planning or executing external reconnaissance against an authorized target (red team, bug bounty in-scope, ASM engagement).
- Mapping an organization's external attack surface end-to-end (subdomains → assets → exposure → attack paths).
- Investigating a person, entity, or threat actor where evidence discipline matters.
- Tracing cryptocurrency flows, geolocating media, performing image/video forensics, or chronolocating events.
- Building a structured OSINT campaign that needs reproducibility, severity grading, and clean handoffs.
- Producing client-facing deliverables (exec summaries, technical reports, reproduction packages) from offensive engagements.

**Do NOT use this skill when:**
- The user is asking for active exploitation, post-exploitation, lateral movement, AD privilege escalation, malware development, or anything beyond reconnaissance — those are out of scope.
- The user is asking for blue-team / defensive content (SIEM rules, detection engineering) — different domain.
- The target's authorization is unclear and the user is asking you to act against a third-party asset they don't own — see §1 below; gently surface the scope question before proceeding.

---

## 1. Authorization & Legal Posture

This skill is intended for assets the operator owns or has written authorization to assess (red-team rules of engagement, bug-bounty in-scope assets, ASM contracts).

**Soft scope check:** when a user asks you to act against a target whose authorization isn't established earlier in the conversation, ask once before proceeding:

> *"Quick scope check: is this a target you own or have written authorization to assess (e.g., a red-team engagement, in-scope bug-bounty asset, or your own infrastructure)? I want to make sure we stay on the right side of the engagement boundary."*

Once authorization is asserted, proceed without re-asking. If the user explicitly states the engagement type (e.g., "this is for our pentest of acme.com under contract"), you don't need to ask again.

**Always-on guardrails (regardless of authorization):**
- Never weaken auth, rate limits, banners, or any safety control that enforces scope on the target side.
- Never run destructive probes (true SYN scans on production, masscan at line rate, fuzzing/brute-force) outside an explicit DEEP / `--aggressive` mode.
- Never paste real PII, valid credentials, session tokens, API keys, or other secrets into cloud-hosted LLMs or third-party services.
- Never take action against assets outside the documented scope, even if "obviously related" (subsidiaries, vendors, employees' personal accounts, etc.).

---

## 2. Confidence Levels

Every assertion you make during an engagement should carry a confidence level. Three levels:

| Level | Meaning | Examples |
|---|---|---|
| **TENTATIVE** | Plausible based on indirect evidence; unverified. | Snippet-only Google dork match; email pattern inferred from name; subdomain returned by one passive source only; favicon-hash overlap (two hosts share a favicon — could be shared infra, could be a coincidence). |
| **FIRM** | Directly observed but uncorroborated. | Subdomain that resolves to an IP; HEAD-confirmed bucket exists (private); CT-log entry shows certificate; Shodan banner returned. |
| **CONFIRMED** | Multiple independent corroborations OR directly verified. | Live-validated PMAK token (read-only `/me` returned 200); breach corpus + crt.sh + DNS all agree; bucket listable AND files retrievable; user enumerated AND password reset flow returns valid hint. |

**Rule of three for attribution:** require three independent weak signals, OR one strong + one weak, before asserting linkage. Don't single-source attribute.

### 2.1 Confidence Upgrade Workflows

Confidence isn't static — every TENTATIVE asset should have a documented path to FIRM and to CONFIRMED. Use these per-asset-type rules.

| Asset type | TENTATIVE → FIRM | FIRM → CONFIRMED |
|---|---|---|
| **Subdomain** | Returned by ≥2 independent passive sources, OR DNS A/AAAA/CNAME resolves successfully. | Serves on a standard port (80/443/22/etc.) AND HTTP banner / TLS cert / SSH banner returned. |
| **IP** | Discovered via ≥2 sources (passive DNS, ASN lookup, Shodan). | Active probe responds (TCP SYN-ACK on at least one port, or ICMP echo reply). |
| **WebApp** | URL extracted from JS / API / archive but not yet hit. | HTTP request returns 2xx/3xx/4xx (any non-network-error response) AND content-length > 0. |
| **Email** | Generated from a name pattern OR returned by snippet-only dork. | Listed in Hunter.io / EmailRep / IntelX / breach corpus, OR `MAIL FROM`/`RCPT TO` SMTP probe returns 250 (without delivery — abort at DATA). |
| **Bucket (S3/GCS/Azure)** | Permutation candidate; no probe yet. | HEAD returns 200, 301, or 403 (existence confirmed). Then CONFIRMED when GET returns object listing or known object retrieval. |
| **Endpoint (API / wayback)** | Extracted from JS regex / Wayback / Postman. | HTTP request returns non-404 (route exists). Then CONFIRMED when the endpoint's behavior is fingerprinted (auth posture, response shape, rate limits). |
| **Credential / secret** | Matches catalog regex in captured text. | Read-only validator (`/me`, `auth.test`, `sts:GetCallerIdentity`, `/user`) returns success. Then CONFIRMED with documented scope + account ID. |
| **Person** | Name extracted from a single source (LinkedIn / breach / GitHub commit). | Confirmed by a second source (Hunter.io role + LinkedIn profile, or two breach sources with same email). |
| **Repo** | Name match on org keyword in GitHub search. | Repo metadata shows confirmed org/email/website match. Then CONFIRMED when commit-history shows employee involvement. |
| **Mobile app** | Name match in app store. | Ownership-confidence score ≥70 (see companion skill §21). Then CONFIRMED when binary metadata (signing cert, package name, dev account) ties back to target. |
| **Certificate** | Returned by crt.sh once. | CT-log entry confirmed in ≥2 logs. Then CONFIRMED when serving on a discovered host. |
| **SSO tenant** | Discovery-endpoint returns OIDC metadata. | Tenant GUID extracted AND domain resolves through the tenant's expected MX / autodiscover / SP record. |

**Default reporting posture:** never claim CONFIRMED without explicit corroboration. When in doubt, downgrade. Operators trust under-claims more than over-claims.

---

## 3. Output Format Conventions

When you produce findings during an active session, structure each finding to match the schema below — it drops cleanly into asset-management tools.

```
Finding:
  id:           <stable hash or UUID>
  module:       <which technique discovered it; "manual" if hand-found>
  asset_key:    <typed key, e.g. sub:api.example.com or webapp:https://example.com/admin>
  category:     <e.g. SECRET_LEAK, MISSING_HSTS, OPEN_GRAPHQL_API, LEAKED_CRED, SSO_EXPOSURE>
  severity:     <info|low|medium|high|critical>
  confidence:   <tentative|firm|confirmed>
  title:        <one-line summary>
  description:  <2-5 sentences>
  evidence:
    url:        <where it was found>
    timestamp:  <UTC ISO8601>
    sha256:     <hash of any downloaded artifact>
    raw:        <truncated to 2 KiB>
  references:
    - <CVE-ID, advisory URL, vendor doc>
  remediation:  <action the asset owner can take>
```

**Always use UTC timestamps**. Local time creates correlation bugs across notes/screenshots/logs.

---

## 4. Source Hygiene & Citations

For every artifact you capture, record: **URL + UTC timestamp + SHA-256 hash + tool version + run_id**.

- Hash all downloaded files with SHA-256.
- Screenshot in PNG (lossless, smaller than full-page WARC for evidence packs).
- Capture raw HTTP requests/responses, capped at 2 KiB body to keep evidence packs small.
- Use JSONL (NDJSON) logs, one line per event, with a `run_id` so the entire engagement is replayable.
- Separate evidence read-only from working copies; never edit captured artifacts.

When citing a source in your output, prefer durable references (CVE, vendor advisory, ATT&CK technique ID, RFC) over ephemeral ones (a Twitter post, a forum thread). If the only source is ephemeral, archive it (archive.today, Wayback SavePageNow) before citing.

---

## 5. Do NOT (hard rules)

- DO NOT paste creds, session tokens, API keys, real PII, infostealer logs, or unique pivots into cloud LLMs (ChatGPT, Claude.ai, Gemini, Perplexity). Use local models (Ollama, LM Studio, GPT4All) for sensitive analysis.
- DO NOT assume vendor labels are ground truth. Cross-label sanity: TRM, Chainalysis, Arkham can disagree. Treat every label as a hypothesis.
- DO NOT assume 1:1 bridge flows. Bridges/mixers/wrappers introduce mint/burn semantics; validate with on-chain proofs.
- DO NOT assert ownership from a single signal. Favicon-hash overlap, shared CT issuer, shared NS — each is a hypothesis. Need rule-of-three.
- DO NOT run fuzzing, SYN scans, masscan, or `nuclei fuzzing/*` templates outside an explicit DEEP / `--aggressive` mode.
- DO NOT use a credential validator to do anything except read-only verification (no create/delete/send).
- DO NOT mirror-image (assume the target thinks like you do). Separate capability from intent and sponsorship.
- DO NOT confuse correlation with control.
- DO NOT escalate when you encounter active defenses; back off and document (see §6.4).

---

### 6.1 Sock Puppets

A sock puppet is a fake account that cannot be linked to you. Build a posting history, age the account, use it from a separate browser profile.

Resources & techniques:
- Persona generation: [Fake Name Generator](https://www.fakenamegenerator.com/), [This Person Does Not Exist](https://thispersondoesnotexist.com/).
- Browser isolation: [Firefox Multi-Account Containers](https://addons.mozilla.org/firefox/addon/multi-account-containers/), or dedicated profiles per persona.
- Disposable phone numbers: Burner, Silent Link (some platforms reject VoIP — keep a backlog of numbers).
- Hardware passkeys for any high-value persona; store recovery codes offline.
- Audit every browser extension before installation. Supply-chain attacks on popular extensions have repeatedly targeted investigators — assume the popular ones are at higher risk, not lower.
- Maintain chain-of-custody: timestamp every action, hash every key artifact, record tool versions per case.
- Personas should look like real low-engagement accounts: profile photo (synthetic), bio, a few low-effort posts spread across weeks before the persona is "used."

References:
- [Effective Sock Puppets](https://medium.com/@unseeable06/creating-an-effective-sock-puppet-for-your-osint-investigation-95fdbb8b075a)
- [Ultimate Guide to Sock Puppets](https://osintteam.blog/the-ultimate-guide-to-sockpuppets-in-osint-how-to-create-and-utilize-them-effectively-d088c2ed6e36)

### 6.2 Detectability & OpSec Tagging

Every probe leaves a footprint. Tag every operation in your notes with a detectability level so you can reason about the SIEM trail you're leaving on the target's side.

| Tag | Examples |
|---|---|
| **Low** | Passive Shodan InternetDB; CT-log queries (crt.sh); Wayback CDX; passive DNS (SecurityTrails); Hunter.io email enrichment; HTTP HEAD on public buckets; `getuserrealm.srf`; Microsoft OIDC metadata fetch. |
| **Medium** | Microsoft `GetCredentialType` user-enum; Okta `/api/v1/authn` user-enum; Postman API key validation; AWS `sts:GetCallerIdentity` (logs to CloudTrail); Slack `auth.test`; full-page screenshots; Swagger/GraphQL probes against a 28/13-path wordlist; targeted favicon-hash + JARM fingerprinting. |
| **High** | Active port scans (naabu / masscan / nmap); Nuclei full template runs against production; subdomain brute-force at scale; APK download from third-party mirrors; deep-mode user enumeration past N attempts per tenant; SMTP `RCPT TO` enumeration; web fuzzing (ffuf/gobuster). |

When working with a client, document the operations actually run and their detectability tag in the engagement report — clients appreciate knowing what their detection stack should have caught.

**Defaults:** passive by default. Active probes only when (a) explicitly authorized, (b) within agreed maintenance windows, and (c) with the operator's awareness of the resulting log volume.

### 6.3 Validator Discipline

When you discover a credential in the wild (a leaked API key, a sourcemap-exposed token, a hard-coded PMAK in a public Postman workspace), you may want to confirm it's live. Do this with **read-only validators only**.

Discipline:
- Read-only endpoint only (e.g., `/me`, `/whoami`, `auth.test`, `sts:GetCallerIdentity`).
- Never use the validated credential to create, modify, delete, or send anything.
- Tag the validation attempt with detectability — every validator generates an audit-log entry on the provider side.
- Record `checked_at` (UTC), the response (truncated), and the scope/account-ID returned.
- If the operator's rules of engagement forbid validation, mark the credential `validation_skipped_by_policy` and stop.

Concrete validator endpoints (Postman, AWS, GitHub, Slack, Anthropic, OpenAI, npm, Atlassian, DataDog) live in the companion `offensive-osint` skill.

### 6.4 Detection-Aware Probing (signs of detection + back-off)

Your probes will eventually hit detection. Recognize the signs and back off **before** you trip an active response.

**Signs you've been detected (in roughly increasing severity):**

1. **Rate-limit responses** — `429 Too Many Requests`, `Retry-After` header set, `X-RateLimit-Remaining: 0`.
2. **Captcha interstitials** — Cloudflare interstitial page, hCaptcha challenge, AWS WAF page.
3. **WAF page** — explicit "Access denied" with provider branding (Cloudflare, Akamai, Imperva, F5 ASM, AWS WAF, Sucuri).
4. **Status code drift** — endpoints that previously returned 200/401 now return 403 only from your IP.
5. **Banner change** — server header shape or response timing changes consistently.
6. **DNS poisoning back to NXDOMAIN** — target's authoritative servers stop resolving subdomains (probably their CDN took over).
7. **Honeypot bait** — endpoints that look too good (`/admin/db_dump.sql`, exposed `.env` with credentials that don't validate). Real exposures rarely look this clean.
8. **Direct contact** — your sock-puppet email gets a "we noticed unusual activity" message; or, in extreme cases, your IP gets a courtesy abuse-contact email.

**Back-off ladder:**

1. **Slow down.** Halve your concurrency. Add 2–10s jitter between requests.
2. **Switch endpoints.** Stop hitting the path that triggered. Move to a different module of the recon pipeline.
3. **Switch persona.** New User-Agent (rotate among realistic browsers), new TLS fingerprint (different httpx/curl version).
4. **Switch IP.** Rotate to a new egress (residential proxy, Tor for sensitive lookups, a different cloud region).
5. **Pause.** Wait 1–24 hours. Many WAFs have rolling-window IP-based reputation; passive time often resets it.
6. **Document and consult.** If you've hit (3) WAF, (4) status drift, or (8) direct contact, **stop active probing and consult the engagement lead**. Continued probing past these signals risks scope violation.

**Persona / IP rotation rules:**
- Never rotate persona to one that's been used in a prior engagement against the same target.
- Use residential proxies (Bright Data, Smartproxy, IPRoyal) for high-detectability work — but be aware they're sometimes IP-blocklisted by Cloudflare.
- Tor exit nodes are useful for **passive lookups** (CT logs, archive sites) but are blocked by most active-probe targets.
- Cloud egress IPs (AWS / GCP / Azure) are often blocklisted aggressively for recon. Use sparingly.
- Document every rotation with timestamp + reason; reviewers will ask.

**Don't:**
- Don't try to "outsmart" a confirmed WAF block by sending more aggressive payloads. That's how clients get extra logs and how you get caught.
- Don't switch source IPs to evade an explicit block-list — that crosses into evasion territory and may breach the rules of engagement.
- Don't ignore signals because the dashboard says "still up." The probe is being silently logged; the response will come later.

---

## 7. External Red-Team Recon Pipeline

A 5-stage pipeline for any authorized external assessment. Stages are sequential; modules within a stage can run concurrently.

### Stage 1 — Seed Discovery
Establish the ground truth of who/what the target is.

- WHOIS on the seed domain (registrant, dates, name servers).
- ASN enumeration: which AS does the org own/use? (Hurricane Electric BGP Toolkit, RIPEstat, BGPView.)
- DNS records (A/AAAA/MX/TXT/NS/SOA/CAA) — records-only, no walking yet.
- Certificate Transparency history for the root domain (crt.sh, Censys).

### Stage 2 — Asset Expansion
Discover everything that might belong to the target.

- Subdomain enumeration (passive sources first: crt.sh, VirusTotal, AlienVault OTX, Shodan, then permutations and bruteforce).
- Cloud bucket enumeration (S3/GCS/Azure permutations from company name + subdomain stems — see §15).
- Typosquat domain generation (dnstwist variants → resolve → WHOIS) — for both phishing risk and adjacent corp assets.
- Wayback CDX archive endpoints for forgotten paths.
- Mobile app discovery (Android via google-play-scraper, iOS via iTunes Search API — see §14).
- DNS deep walking (NSEC walk on misconfigured zones, AXFR opportunism).
- LinkedIn employee enumeration → email-pattern derivation.

### Stage 3 — Enrichment
Add depth to the discovered assets.

- Port + service detection (Shodan InternetDB free → naabu/masscan if authorized).
- Live TLS handshakes (cert chain, JARM, favicon mmh3 hash).
- Web tech detection (Wappalyzer-style ~600 signatures via httpx).
- WAF/CDN inference (header markers).
- Origin discovery if behind CDN (see §27).
- Security header audit.
- Bulk screenshots (triage 1000s of hosts visually).
- Email harvesting (6 parallel sources).
- Email security audit (SPF/DMARC/DKIM/BIMI/MTA-STS).
- GitHub code-search dorking (13 dork templates × 29+ secret regexes).
- JavaScript deep analysis (sourcemaps, secrets, endpoints, internal-host leakage).
- SSO/IdP tenant fingerprinting (Entra, Okta, ADFS, Google, SAML, M365 Teams/SharePoint/OAuth — see §11).
- API & auth-map discovery (Swagger/OpenAPI, GraphQL, Postman).
- Secrets-beyond-GitHub sweep (Postman public workspaces, Stack Exchange, Trello/Notion/Atlassian dorks).
- Vendor product fingerprinting (Citrix/F5/PaloAlto/Pulse/Fortinet/Cisco/VMware/Exchange).
- Container / CI-CD / cloud-native exposure check.
- Job posting harvest for tech-stack inference.

### Stage 4 — Exposure Analysis
Convert assets into findings.

- Nuclei (15 always-on built-in checks + optional binary).
- TLS deep audit (sslyze / testssl.sh).
- Breach × identity correlation (HudsonRock Cavalier, HIBP, DeHashed, IntelX, local corpus → SSO_EXPOSURE findings).
- Targeted misconfiguration probes (`.git/config`, `.env`, `phpinfo.php`, `/actuator/env`, `/actuator/heapdump`, `_cat/indices`, `/console`, `/manager/html`).
- Vulnerability prioritization (CVE × EPSS × CISA KEV × public-POC availability — see §28).

### Stage 5 — Reporting
Make the work usable.

- Risk scoring per finding (CVSS + program-specific weights).
- Asset graph export (D3-friendly nodes/links, GraphML, JSON).
- Client-facing report (executive summary + technical detail + remediation — see §31).
- Reproduction package (run_id, tool versions, raw evidence, JSONL log).
- Bug bounty submission (if applicable — see §30).

### 7.5 Pipeline Priority Order (highest signal density first)

When budget is constrained, work in this order:

1. **Breaches** — infostealer logs (HudsonRock Cavalier free tier) + HIBP + DeHashed. Highest ROI for red teams; often gives valid plaintext creds for corp SSO. Requires emails as input.
2. **GitHub recon** — code-search dorks. Finds AWS keys, Slack tokens, JWT secrets, `.env` files. Fastest path to cloud pivot.
3. **Nuclei misconfig sweep** — exposed admin panels, CVEs with public POCs.
4. **Cloud buckets** — permutate company name + subdomain stems. Listable bucket = CRITICAL.
5. **Ports** — Shodan InternetDB first (free, keyless). VPN concentrators, RDP, Jenkins, GitLab-CE, Elasticsearch are the high-value pivot points.
6. **Email OSINT** — feeds breaches; feeds phishing list.
7. **Web tech / WAF / screenshots** — triage thousands of hosts; know the stack before probing.
8. **Wayback** — archived JS often has hard-coded keys; archived endpoints reveal removed admin/dev paths.
9. **DNS deep + email security** — SPF/DMARC gaps enable email spoofing; TXT verification tokens reveal SaaS tenancies.
10. **Certificates** — CT-log timeline catches forgotten subdomains; weak ciphers = cheap findings.
11. **ASN + reverse DNS** — corporate IP space hosts unadvertised infra.
12. **WHOIS** — registrant PII reveals adjacent corp assets.
13. **Typosquat** — actively-registered squats are findings; unregistered ones go on the phishing-domain shortlist.
14. **Security headers** — low standalone value but required for client reports.

### 7.6 Time Budgeting & Engagement Profiles

Stage and asset count drive how long a recon takes. Rough estimates (single operator on a typical SaaS-style target):

| Stage | Small org (<100 employees) | Medium (100–1K) | Large (1K+) |
|---|---|---|---|
| 1. Seed discovery | 30 min | 30 min | 30 min |
| 2. Asset expansion | 1–2 h | 2–4 h | 4–8 h |
| 3. Enrichment (per 100 alive webapps) | ~1 h | ~1 h | ~1 h |
| 4. Exposure analysis | 1–3 h | 3–6 h | 6–12 h |
| 5. Reporting | 2–4 h | 4–8 h | 1–2 days |

**Engagement profiles:**

- **1-hour rapid recon ("how exposed is X?")** — Stage 1 (15 min) → passive subdomain (crt.sh + Subfinder, 10 min) → Shodan InternetDB on resolved IPs (5 min) → email harvest via Hunter+IntelX (10 min) → breach lookup on emails (10 min) → executive-summary-only output (10 min).
- **4-hour focused recon ("phish-readiness check")** — adds: full email harvest, LinkedIn employee enum, SPF/DMARC analysis, typosquat candidate generation, SSO/IdP fingerprinting. Output: phishing-feasibility report + target email list.
- **1-day standard recon** — full Stages 1–4 with the priority order above. Output: per-asset finding list + asset graph + exec summary.
- **1-week deep recon** — all of standard, plus: deep-mode user enumeration, JS deep analysis at full budget, mobile attack surface, cloud-native fingerprinting, vendor product fingerprinting, package registry leak hunting, vulnerability prioritization. Output: full client deliverable package + reproduction bundle.
- **Ongoing monitoring (weekly diff)** — re-run Stages 1–3 weekly; diff against baseline; alert on new asset / new finding / asset disappeared.

**When to abort early:**
- After Stage 1 if scope is wrong (target turns out to be subsidiary of unrelated corp; rules of engagement need clarification).
- After Stage 2 if attack surface is below threshold (no public webapps + no exposed services + no leaked emails → little to find externally).
- During any stage if you hit the WAF / detection signs in §6.4.

---

## 8. Asset Graph Discipline

Treat every discovery as a typed asset in a graph, not a free-floating string.

### 8.1 Asset Taxonomy (29 types)

| Category | Asset Types |
|---|---|
| **DNS / Network** | `domain`, `subdomain`, `ip`, `netblock`, `asn` |
| **Service** | `port`, `service`, `certificate` |
| **Identity** | `email`, `person`, `credential` |
| **Code / Config** | `repo`, `secret` |
| **Cloud / Storage** | `bucket`, `firebase_project` |
| **Web** | `webapp`, `wayback_endpoint`, `api_endpoint`, `api_spec`, `graphql_schema` |
| **Mobile** | `mobile_app`, `deep_link`, `exported_component` |
| **Phishing / Adversarial** | `typosquat_domain` |
| **Collaboration / SaaS** | `postman_collection`, `postman_workspace`, `postman_api_key`, `stack_post`, `saas_public_surface` |

### 8.2 Asset Schema

Every asset carries:
- `type` — one of the 29 above.
- `key` — unique dedup id (typed prefix, e.g. `sub:api.example.com`, `email:alice@example.com`).
- `value` — the actual string/object.
- `sources[]` — every source that confirmed this asset (deduplicated).
- `confidence` — TENTATIVE / FIRM / CONFIRMED.
- `first_seen`, `last_seen` — UTC timestamps.
- `attrs{}` — type-specific metadata (e.g., for a `webapp`: status_code, title, tech-stack list, JARM, favicon mmh3, screenshot path).

### 8.3 Edge Taxonomy

Relationships are typed edges, not text:
`RESOLVES_TO`, `HOSTED_ON`, `IN_NETBLOCK`, `BELONGS_TO_ASN`, `LISTED_IN_CERT`, `OWNED_BY`, `ALIAS_OF`, `BREACHED_FROM`, `EMPLOYED_BY`, `HOSTS_REPO`, `TYPOSQUAT_OF`, `EXPOSES`, `DOCUMENTED_BY`, `BELONGS_TO_HOST`, `REQUIRES_AUTH`, `LEAKS_SCHEMA`, `SHIPPED_BY_ORG`, `CONTAINS_SECRET`, `TALKS_TO_HOST`, `EXPOSES_DEEPLINK`, `HAS_EXPORTED_COMPONENT`, `USES_FIREBASE_PROJECT`, `LACKS_PINNING_FOR`.

### 8.4 Discipline rules

- **Every discovery is an asset.** Don't write findings against free-floating strings; create the asset first, then attach the finding.
- **Dedup by key, not by value.** Same value, different type ≠ same asset (`sub:api.example.com` and `webapp:https://api.example.com/` are different assets with a `BELONGS_TO_HOST` edge).
- **Provenance is non-negotiable.** `sources[]` must list every source. If two sources confirmed it, both go in.
- **Confidence is per-source, then aggregated.** A subdomain returned by 3 passive sources is FIRM; one returned by snippet-only Bing is TENTATIVE.
- **Late binding via sidecars.** When module A produces output that module B needs, write a JSON sidecar (`mobile_endpoints.json`, `secrets_sidecar.json`) — don't block module B on module A. See §24.

### 8.5 Asset-Level Triage Rules

When you have a mixed bag of assets and limited probe budget, prioritize by what each asset *enables*:

**WebApp priority by hostname signal (highest first):**

1. Auth-related hostnames (`auth.`, `login.`, `sso.`, `idp.`, `accounts.`, `oauth.`).
2. Admin paths (`/admin`, `/dashboard`, `/console`, `/manager`, `/wp-admin`, `/phpmyadmin`).
3. Dev/staging hosts (`dev.`, `staging.`, `stg.`, `qa.`, `uat.`, `test.`, `sandbox.`, `preprod.`, `preview.`) — lower defenses, often dump prod data.
4. API hostnames (`api.`, `services.`, `gateway.`, `graph.`).
5. Customer-facing hostnames (`portal.`, `app.`, `my.`, `account.`).
6. Marketing / content (`www.`, `blog.`, `news.`, `careers.`, `support.`).

**Subdomain priority by inferred function:**

- API > Admin > Dev > Auth > Prod-app > Marketing.

**IP priority by netblock:**

- Corporate ASN-owned (most likely to host unadvertised internal infra).
- Cloud netblocks (AWS / GCP / Azure / DO / OVH) — high turnover but interesting for cloud-native services.
- CDN ranges (Cloudflare / Akamai / Fastly) — usually edge, not origin; defer unless doing origin discovery.

**Email priority by role hint:**

| Role indicator | Priority | Why |
|---|---|---|
| `ceo@`, `cfo@`, `cto@`, `ciso@` | HIGHEST | Exec accounts have highest breach value (BEC, finance authority, board access). |
| `it@`, `helpdesk@`, `support@`, `security@` | HIGH | IT/security accounts have privileged tool access; helpdesk accounts handle reset workflows. |
| `dev`, `engineer`, `architect`, `dba` | MEDIUM | Developer accounts often have GitHub / cloud / CI access. |
| `sales`, `marketing`, `hr`, `finance` | MEDIUM | SaaS access (Salesforce, HubSpot, Workday); finance enables BEC. |
| Generic role accounts (`info@`, `noreply@`, `contact@`) | LOW | Often unmonitored or alias forwarded; less personal context. |

**Repo priority by recency + naming:**

- Recently-pushed (last 30 days) > stale.
- Public repo with target name in description > target name only in code.
- Forked from internal-looking parent > standalone.
- Mentions `prod`, `internal`, `private`, `secret` in name → priority HIGH despite being public (may be misnamed or accidentally exposed).

**Application order:** when you have N assets and budget for M probes (M < N), apply asset-type priority first, then within-type priority. E.g.: 50 subdomains → probe API + admin + dev first (~15), then auth + prod-app (~20), defer marketing/content to a later pass.

---

## 9. Findings Rubric & Severity Mapping

Severity is operational, not subjective. Use these anchors:

### 9.1 CRITICAL

Pre-auth code execution, confirmed valid credentials, listable production data, fundamental trust violations.

Examples:
- `.git/config` exposed on production webapp (full source-code disclosure).
- `/.env` exposed (credentials in plaintext, often DB / cloud / API).
- Spring Boot `/actuator/env` or `/actuator/heapdump` reachable unauthenticated.
- Listable S3 / GCS / Azure bucket containing user data.
- Unauthenticated POST/PUT/DELETE to a write endpoint that mutates state.
- Open Firebase Realtime Database (`https://{project}.firebaseio.com/.json` returns data).
- `android:debuggable=true` in a production Android app.
- Live-validated credential (PMAK, AWS key, Anthropic/OpenAI key) with broad scope.
- ≥10 employees compromised in a breach corpus + their tenant identified (SSO_EXPOSURE).
- Open Elasticsearch cluster (`/_cat/indices` returns data).
- Open Docker API (`/v1.40/containers/json` returns containers).
- Open Redis (no AUTH; can write `authorized_keys`).
- Open Kubernetes API server with anonymous-auth enabled.
- Open kubelet on 10250 (pod exec without auth).
- Open etcd on 2379 (cluster state and secrets).
- BlueKeep-vulnerable RDP, EternalBlue-vulnerable SMB.
- Citrix Netscaler / F5 BIG-IP with version-specific RCE CVE.

### 9.2 HIGH

Significant exposure but not yet RCE; clear path to escalation; high-value information disclosure.

Examples:
- Public secret in a GitHub repo (PAT, AWS key, Slack token, etc.).
- Sourcemap (`.js.map`) accessible — full original-source disclosure of frontend.
- Open GraphQL introspection on production (full schema leaked → mutations to enum).
- Subdomain takeover possible (CNAME points to unclaimed Heroku/Shopify/etc.).
- Reflected CORS with credentials (`Access-Control-Allow-Origin: <reflected>` + `Access-Control-Allow-Credentials: true`).
- Verb tampering: hidden DELETE/PATCH on an endpoint that publicly only allows GET.
- Missing HSTS on a sensitive path (`/login`, `/sso`, `/admin`, `/auth`) — escalated from MED.
- Exposed Jenkins/Tomcat-Manager/phpMyAdmin admin UI (no auth or default creds).
- Telnet (port 23) reachable.
- WebView with JS bridge in a mobile app (XSS → RCE potential).
- Sensitive deep-link handler in a mobile app.
- DMARC policy `p=none` on production sending domain (spoof-feasible).
- Vendor product banner with known unpatched CVE (KEV-listed).

### 9.3 MEDIUM

Information disclosure, hardening gaps, brute-force exposure.

Examples:
- Missing security headers on standard pages: HSTS, CSP.
- Apache `/server-status` or `/server-info` reachable.
- `phpinfo()` or `/info.php` reachable on dev/staging only.
- Internal IP / hostname / K8s service DNS leaked in JS.
- Schema leakage in error pages (stack traces, ORM signatures).
- `android:allowBackup=true` in Android app.
- `android:usesCleartextTraffic=true` in Android app.
- Exported activity/service without `android:permission` protection.
- Missing rate-limit on an API endpoint.
- Wildcard CORS (`Access-Control-Allow-Origin: *`) on an API that returns user-tied data (no creds).
- Slack webhook URL leaked.
- Twilio Account SID leaked (without auth token).
- SPF record permissive (`+all` or many includes).

### 9.4 LOW

Cosmetic or marginal hardening gaps.

Examples:
- Missing `X-Frame-Options`.
- Missing `X-Content-Type-Options`.
- `.DS_Store` exposed.
- Stripe **test** key leaked.
- Firebase URL exposed (URL only, no open RTDB).
- Certificate pinning missing in mobile app.
- Outdated WordPress install detected (no known exploit yet).
- BIMI not configured (brand impersonation risk only).

### 9.5 INFO

Worth recording, no action required immediately.

Examples:
- Missing `Referrer-Policy` / `Permissions-Policy`.
- Discovered `/.well-known/security.txt`.
- `robots.txt` reveals interesting paths.
- Private bucket exists but is locked down.
- Domain detected in a breach corpus with 0 employee accounts.
- DNSSEC not enabled.

### 9.6 Severity escalation rules

- HSTS missing on auth/login/SSO/admin path → **MED → HIGH**.
- Wildcard CORS + credentials → **MED → HIGH**.
- Wildcard CORS + sensitive endpoint → **LOW → MED**.
- API endpoint with score ≥70 on the interest rubric (companion skill §20) → at least **HIGH**.
- Domain breach severity ≥10 employees → **CRITICAL** regardless of stale-data caveats.
- Vendor product version matches CISA KEV entry → **CRITICAL**.
- DMARC `p=reject` + SPF strict + DKIM rotated → no escalation; well-postured.

---

## 10. Bug-Bounty / Red-Team Pivot Modes

Existing investigative work (threat-actor research, doxxing investigations, attribution) operates under different posture than offensive recon. Switch posture explicitly.

| Aspect | Investigative Mode | Offensive Recon Mode |
|---|---|---|
| **Probing rate** | Slow, single-threaded, blend with normal traffic. | Bursts, parallel, but rate-limited per provider. |
| **OpSec posture** | Sock-puppet only, never reveal investigator. | Persona may be the engagement persona; team may notify SOC. |
| **Evidence handling** | Court-grade chain of custody; hashes, timestamps, screenshots. | Engagement-grade; same hashing/timestamp discipline but evidence is for the client report. |
| **Severity in scope** | All severity levels relevant for context. | CRIT/HIGH/MED matter; LOW/INFO often dropped from exec summary. |
| **Authorization posture** | Public-record / OSINT-only; no probing private resources without authorization. | Written rules of engagement; explicit scope; explicit out-of-scope list. |
| **Reporting format** | Narrative + sourced timeline. | Per-asset findings + remediation + reproduction steps. |
| **Stop conditions** | When the question is answered. | When the engagement window closes OR when the report is delivered. |

When you're working with the user, ask which mode they're in if it's unclear from context.

### 10.1 Scale-Based Tactics

Org size shapes which techniques pay off.

**Small org (< 100 employees):**
- Executive accounts disproportionately matter; one CEO/CFO compromise often hands you the keys.
- Email harvest is small enough to enumerate exhaustively (10–50 emails total).
- Likely Microsoft 365 or Google Workspace; identity fabric is one tenant.
- Code repos often public on GitHub under personal accounts (founders moved from solo dev).
- Cloud presence often single-account AWS or GCP project.
- Tactics: deep on every email + every identity-fabric finding; full LinkedIn enum; check founders' personal GitHub orgs.

**Medium org (100–1K):**
- Balanced enumeration. Email list is enumerable but not exhaustive.
- Identity fabric likely one IdP but with multiple SaaS tenants (Slack workspace, Notion org, GitHub org).
- Mobile apps possible; check both stores.
- Cloud presence multi-account or multi-region.
- Tactics: full pipeline at standard depth; sample-and-deepen on each asset class; LinkedIn priority by role.

**Large org (1K–10K):**
- Email enum becomes lossy (sample top roles); breach hits scale up.
- Multi-tenant identity fabric (often Entra + Okta + multiple Auth0 customers).
- Mobile apps, multiple Android packages from different teams.
- Cloud presence sprawling; subsidiaries / acquisitions complicate scope.
- Tactics: breadth-first; rely on automation for asset discovery; manual triage on findings.

**Very large org (10K+) or conglomerate:**
- Brand-pivot maps before anything else: enumerate every brand domain, every subsidiary.
- Breach corpus dominates: 10K+ employees mean significant past-breach exposure.
- Identity fabric may differ per business unit (legal entity boundaries).
- Tactics: scope pruning is the most important step; sampling + automation throughout; deep dive only on high-priority findings.

**Cross-scale principle:** the smaller the org, the more individual-account focus pays off. The larger the org, the more systemic posture findings (DMARC gaps, SSO_EXPOSURE breadth, vendor-product version sweeps) pay off.

---

## 11. Identity Fabric Mapping

An organization's IdP/SSO posture is a high-value target: compromise the identity fabric and you don't need to break into individual apps. Map it methodically.

### 11.1 Subdomain prefix enumeration

Probe these prefixes against the target's root domain (and any sibling brand domains discovered):

```
auth.{domain}
login.{domain}
sso.{domain}
idp.{domain}
iam.{domain}
identity.{domain}
accounts.{domain}
oauth.{domain}
```

Plus generic OIDC discovery on every alive subdomain:
```
{any-host}/.well-known/openid-configuration
```

### 11.2 Microsoft Entra (Azure AD)

- **OIDC metadata + tenant GUID extraction** — fetch `https://login.microsoftonline.com/{tenant-or-domain}/.well-known/openid-configuration`. The `issuer` field returns a URL containing the tenant GUID (8-4-4-4-12 hex format). Tenant GUID + domain = stable tenant fingerprint.
- **getuserrealm.srf** — `https://login.microsoftonline.com/getuserrealm.srf?login=<user>@<domain>` returns NameSpaceType: `Managed` (cloud-native), `Federated` (on-prem ADFS / external IdP), or `Unknown`. Detectability: low.
- **Autodiscover v2** — `https://autodiscover-s.outlook.com/autodiscover/metadata/json/1` POST with email; detects tenant membership.
- **GetCredentialType** (deep-mode user-enum) — `https://login.microsoftonline.com/common/GetCredentialType` POST `{"username": "<email>"}`. Response indicates whether email exists in tenant. Detectability: medium. Cap attempts at 20 per tenant.

### 11.3 Okta

- **Org slug derivation** — derive candidate slugs from subdomains + root domain stem; Okta tenants live at `<slug>.okta.com` (or `<slug>.oktapreview.com`).
- **OIDC fingerprint** — `https://<slug>.okta.com/.well-known/openid-configuration`.
- **/api/v1/authn user-enum** (deep-mode) — POST `{"username": "<email>", "password": "invalid"}`. 400 vs 401 response code indicates user existence. Detectability: medium. Cap at 20 per tenant.

### 11.4 ADFS

- **Passive fingerprint** — GET `https://{domain}/adfs/idpinitiatedsignon.aspx` → 200 indicates ADFS present.
- **Active mex endpoint** (deep-mode) — `https://{domain}/adfs/Services/Trust/mex` returns SOAP metadata.

### 11.5 Google Workspace

- `https://{domain}/.well-known/openid-configuration` — Google-hosted-domain customers expose discovery endpoints with characteristic issuer/JWKS URIs.
- MX records pointing to `*.googlemail.com` / `aspmx.l.google.com` is a strong Google Workspace signal.

### 11.6 Generic OIDC (Keycloak / Auth0 / Ping / OneLogin / Duo)

- Probe every alive subdomain for `/.well-known/openid-configuration`.
- The `issuer` and `authorization_endpoint` fields fingerprint the IdP product.
- `*.auth0.com`, `*.onelogin.com`, `*.pingone.com`, `*.duosecurity.com` patterns are characteristic.

### 11.7 SAML metadata

Probe these paths on every alive webapp:

```
/saml/metadata
/FederationMetadata/2007-06/FederationMetadata.xml
/federationmetadata/2007-06/federationmetadata.xml
/simplesaml/saml2/idp/metadata.php
/auth/saml2/metadata
```

SAML metadata XML contains: `EntityID`, signing certs, `SingleSignOnService` URL, `NameIDFormat`.

### 11.8 AWS account-ID extraction

- **S3 bucket region header** — HEAD on a known target bucket returns `x-amz-bucket-region`; correlate with bucket-name entropy to infer account.
- **ARN regex in JSON / HTML responses** — search for `arn:aws:[a-z0-9-]+:[a-z0-9-]*:([0-9]{12}):` (the 12-digit AWS account ID is the capture group).
- **`AccountId` property in JS / API responses** — common in IAM-related error messages and CloudFormation outputs.
- **OAuth client_id leaks** — Google OAuth: `<digits>-<chars>.apps.googleusercontent.com`; MSAL: GUID in `clientId` property.

### 11.9 Output

Each discovered IdP becomes a `Service` asset with `attrs.product`, `attrs.tenant_id`, `attrs.discovery_endpoint`. Then in Stage 4, correlate with breach data: every compromised user under a discovered tenant becomes an SSO_EXPOSURE finding (CRITICAL — see §22.3).

### 11.10 Microsoft 365 Deep Surface

Beyond plain Entra fingerprinting, M365 exposes a wider attack surface that's worth enumerating in depth.

**Teams Federation:**

- `https://login.microsoftonline.com/<target-domain>/.well-known/openid-configuration` confirms tenant.
- Teams federation status: `https://teams.microsoft.com/api/mt/<region>/beta/users/<email>/externalsearchv3` (requires authenticated request from a federated tenant; useful for confirming whether external Teams chat is allowed).
- **External chat enabled** = soft-attack surface (vishing, smishing, "from-IT" pretexts via Teams chat).
- **Open Federation** (any tenant can chat) is the default; check whether the target restricted it.

**SharePoint subdomains:**

- `<target-stem>.sharepoint.com` — main tenant SharePoint.
- `<target-stem>-my.sharepoint.com` — OneDrive-for-Business URLs (per-user personal sites).
- `<target-stem>-admin.sharepoint.com` — SharePoint admin center (auth-required, but presence confirms tenancy).
- Where `<target-stem>` is derived from the company name (often the part before `.com`).

**OneDrive personal site enumeration:**

- Per-user OneDrive URL: `https://<target-stem>-my.sharepoint.com/personal/<user_email_with_underscore>/Documents/`.
- Replace `@` with `_` and `.` with `_` in the email (e.g., `alice@acme.com` → `alice_acme_com`).
- Authenticated probe; useful for confirming whether the OneDrive personal site has been provisioned (which itself is a presence indicator).

**M365 OAuth client_id discovery:**

- Many internal apps register OAuth client_ids in Entra. Search JS bundles, mobile-app strings, and API responses for `client_id=<GUID>` patterns.
- Microsoft's well-known first-party client_ids (for Office, Graph, etc.) are documented; finding non-Microsoft GUIDs reveals custom internal apps.
- The endpoint `https://login.microsoftonline.com/<tenant>/v2.0/.well-known/openid-configuration` lists supported endpoints; some tenants leave `device_authorization_endpoint` enabled (device-code phishing target).

**Power Platform / Power Apps:**

- `https://make.powerapps.com/environments` (auth-required); environment IDs sometimes leak in URLs.
- `*.crm.dynamics.com` (Dynamics 365 / Power Apps default URLs).
- `*.azurewebsites.net` for App Service deployments.

**M365 OAuth misconfig findings to look for:**

- `device_authorization_endpoint` enabled on `common` tenant (device-code phishing target) → **MEDIUM** (operational risk; not directly exploitable but enables attack).
- Custom OAuth app with `Public client` flow enabled and broad scopes (offline_access, Mail.Read, Files.Read.All) → **HIGH** if app is approved for the tenant.
- Multi-tenant OAuth app published by the target (others can consent) → check whether scopes include sensitive Graph permissions.

**Detectability:** all M365 endpoint probes log to Entra sign-in logs / audit logs (medium-low for fetch-only; medium for any auth attempt).

---

## 12. API & Auth-Map Methodology

Modern targets expose REST, GraphQL, and undocumented internal APIs. The OSINT goal is to enumerate them, classify them, and rank by attack interest.

### 12.1 Discovery paths

- **Swagger / OpenAPI** — probe a 28-path wordlist (companion skill §16.1) on every alive webapp. Parse YAML/JSON; extract every endpoint (method + path).
- **GraphQL** — probe a 13-path wordlist (companion skill §16.2). POST a standard introspection query. If schema returns, you have full type/query/mutation/subscription enumeration.
- **GraphQL when introspection is disabled** — fall back to field-suggestion enumeration (companion skill §22.9).
- **Postman** — query Postman's public universal-search endpoint with the target name; walk each matching workspace; extract requests, headers, pre-request scripts, test scripts, env vars.
- **JS-extracted endpoints** — every endpoint extracted from JavaScript bundles feeds into the same classifier.
- **Mobile-extracted endpoints** — every endpoint from APK static analysis feeds in via sidecar (`mobile_endpoints.json`).

### 12.2 Classification

For each endpoint, capture:

```
url, method, source[], auth_required, auth_type, auth_location,
rate_limited, cors_policy, sensitive_path_keywords[], schema_leaks,
verb_tampering_possible, interest_score (0..100), interest_reasons[]
```

How to determine each field:
- Send `OPTIONS` → `Allow` header reveals supported methods (verb tampering check).
- Send `GET` without auth → 200 = `auth_required=false`; 401/403 = `auth_required=true`.
- Capture response headers for `WWW-Authenticate` (auth_type), `RateLimit-*` / `X-RateLimit-*`.
- Send a request with `Origin: https://attacker.example` → response `Access-Control-Allow-Origin` reflected = `cors_policy=reflected`.
- Trigger an error → check response for stack traces, ORM hints.

### 12.3 Interest score (0–100)

See companion skill §20 for the full rubric. **Score ≥ 70 → HIGH/CRITICAL finding** with `attack_path_hint` in evidence.

### 12.4 Attack-path hints

When emitting a HIGH/CRITICAL finding, include a one-sentence attack-path hint in the evidence so the operator knows where to start exploiting. Templates in companion skill §39.

---

## 13. JavaScript Deep Analysis

For every alive webapp, scrape its JS — it's where modern frontends leak.

### 13.1 Script discovery

- Parse HTML for `<script src="...">` and `<link rel="modulepreload" href="...">`.
- Probe a guess-path list (companion skill §16.9) for common bundlers.

### 13.2 Sourcemap detection (HIGH info disclosure)

- Inline reference: regex `//[#@]\s*sourceMappingURL=` at end of bundle.
- Sibling fetch: try `<bundle>.map` next to every discovered JS.
- If accessible: parse the sourcemap's `sources[]` (leaks repo structure) and `sourcesContent[]` (full original source code embedded). Run the secret catalog over `sourcesContent[]`.
- Severity: HIGH `INFO_DISCLOSURE`.

### 13.3 Secret scanning

Run the 29+-pattern catalog (companion skill §17) over every JS body and every parsed `sourcesContent[]` blob. Each hit = `SECRET_LEAK` finding with the catalog's per-pattern severity.

### 13.4 Endpoint extraction

Three regex tiers (companion skill §16.10). Each unique endpoint becomes a `wayback_endpoint` asset and feeds into the API classifier in §12.

### 13.5 Internal-host leakage detection

Three patterns (companion skill §16.11): RFC1918, internal DNS suffixes, K8s service DNS. Each match = MEDIUM `INFO_DISCLOSURE`.

### 13.6 GraphQL introspection probe

When an extracted endpoint ends in `/graphql` or `/graphiql`, POST the standard introspection query. If schema returns → HIGH `MISCONFIG`. Then enumerate mutations and subscriptions for high-value targets.

### 13.7 Next.js manifest parsing

`_buildManifest.js` and `_ssgManifest.js` enumerate every Next.js page route — exposes the application's full route structure.

### 13.8 Budget guidelines

- Cap webapps analyzed per engagement: 40 default, 120 with `--deep`.
- Cap JS files per webapp: 40 default, 80 with `--deep`.
- Cap individual JS file size: 2 MiB.
- Per-file timeout: 10 seconds.

---

### 14.1 App discovery

- **Android** — google-play-scraper. Search by company name, brand keywords, root domain stem.
- **iOS** — iTunes Search API.

### 14.2 Ownership confidence (0–100)

See companion skill §21. Threshold: **≥70** for deep analysis.

### 14.3 APK acquisition + static analysis

- Download via APKPure HTML scrape.
- Extract via `zipfile` + optional `androguard`.
- Pull: `AndroidManifest.xml`, resource strings, asset files, native `.so` files, `classes*.dex` (string-extract).

### 14.4 Secret scanning

Run the catalog over manifest, resources, asset files, dex string-extract output.

### 14.5 Backend hostname extraction

Every discovered hostname becomes a `subdomain` asset. Write sidecar `mobile_endpoints.json` for the API discovery module to consume.

### 14.6 Manifest misconfig findings

| Manifest attribute | Severity |
|---|---|
| `android:debuggable="true"` | CRITICAL |
| `android:allowBackup="true"` (without whitelist) | MEDIUM |
| `android:usesCleartextTraffic="true"` | MEDIUM |
| Exported activity/service/receiver without `android:permission` | MEDIUM |
| Sensitive deep-link handler | HIGH |
| WebView with `setJavaScriptEnabled(true)` + `addJavascriptInterface(...)` | HIGH |
| Certificate pinning absent | LOW |

### 14.7 Firebase canonical probe

For every Firebase project ID extracted:
- **Realtime DB** — GET `https://{project-id}.firebaseio.com/.json`. Returns JSON tree → CRITICAL `OPEN_FIREBASE_RTDB`.
- **Firestore** — `https://{project-id}.firebaseapp.com/`.
- **Storage** — corresponding GCS bucket.
- **Remote Config** — only readable with extracted API key + app ID.

### 14.8 iOS path

- Discovery only via iTunes Search API.
- ITMS link extraction: `https://apps.apple.com/<region>/app/<slug>/id<bundle-id>`.
- Privacy nutrition labels (App Store Connect): publicly published; useful for understanding what data the app touches.
- Don't recommend auto-download (DMCA / DRM considerations).

---

### 15.1 Bucket permutation

Build candidate bucket names from: target's root domain, subdomain stems, optional brand/company name. Filter generic stems unless combined with target-identifying tokens. Apply 6 prefixes × 15 suffixes (companion skill §16.8 has the lists).

### 15.2 Provider URL templates

S3, GCS, Azure Blob templates — see companion skill §16.8.

### 15.3 Probe technique

- HEAD first. Status code 200/301 = exists; 403 = exists, private; 404 = skip.
- If exists, GET on bucket root. Listable XML/JSON listing → **CRITICAL**.

### 15.4 Severity mapping

| Outcome | Severity |
|---|---|
| Bucket listable | CRITICAL |
| Bucket exists, objects readable by direct URL but not listable | HIGH |
| Bucket exists, ACL private | INFO |

### 15.5 Adjacent cloud signals

Extract AWS account-ID from S3 region/error responses. GCP project ID from GCS error responses. Azure tenant ID from blob URL patterns.

---

### 16.1 Transaction Analysis

- Track flows between wallets; identify clusters of related addresses; monitor large transfers.

Tools: Cielo (multi-chain), TRM (graphs), Arkham (multichain + entity labels), MetaSleuth (visual), Range (CCTP), Socketscan (EVM bridge), Pulsy (bridge aggregator), Chainalysis Horizon 2.0 (paid), Elliptic Lens.

### 16.2 Layer 2 / Rollup Analysis

- **zkSync Era / Polygon zkEVM** — ZK proofs hide L2 details; only L1 bridge events visible.
- **Arbitrum / Optimism** — batched/compressed; L2 state from L1 calldata.
- **StarkNet** — Cairo VM; different address derivation.
- **Base / Blast / Scroll** — OP Stack or ZK.
- **Privacy protocols on L2** — Aztec (programmable privacy), Railgun (shielded pools), Privacy Pools (Tornado Cash successor).

**Methodology:** start with L1 bridge events; use L2 explorers for in-rollup activity; for privacy protocols focus on timing analysis and clustering.

### 16.3 Cautions

- Bridges introduce mint/burn semantics; avoid 1:1 flow assumptions.
- MEV/aggregator paths create false "direct" trails.
- L2 finality: optimistic rollups have 7-day challenge periods.

### 16.4 Wallet / Exchange / NFT Profiling

Same patterns: age + activity + connections + balance over time + linked accounts. NFTs add ownership history + metadata + connected wallets.

---

### 17.1 Reverse Image Search

- Google Images / Lens (Lens may require auth — use sock-puppet incognito).
- Yandex Images (strongest for RU/East-European content).
- Bing Image Match, TinEye, Copyseeker, Perplexity Pro.
- Browser extensions: RevEye, Search by Image (multi-engine).
- Picarta for AI geolocation.

### 17.2 Metadata (EXIF)

ExifTool, Jeffrey's Image Metadata Viewer, EXIF Viewer Pro.

### 17.3 Image Forensics

Forensically, FotoForensics, Bellingcat Photo Checker, Sensity AI, Exposing.ai, Adobe Content Credentials Verify, c2patool. Techniques: ELA, metadata, clone detection, noise analysis.

### 17.4 Geolocation Workflow

- **Foreground** — signs, license plates, clothing, vegetation, weather.
- **Background** — landmarks, unique buildings, mountains, water, infrastructure.
- **Map markings** — flora/fauna, seasonal indicators.
- **Trial and error** — Google Street View, Bing Streetside, Yandex Panorama.
- **Overpass Turbo** for OpenStreetMap queries.
- **Mountain ID** — PeakVisor, Peakfinder, PeakLens AR.
- **OCR** — Google or Yandex OCR.
- **Video transcripts** — YouTube captions improve keyword search.

### 17.5 Specialized

- **Fire identification** — NASA FIRMS, Sentinel Hub, Global Forest Watch, Copernicus EFFIS.
- **Plane tracking** — Apollo Hunter, FlightRadar, ADS-B Exchange.

---

### 18.1 Context extraction

Signs/banners, architecture, road markings, license plates, clothing, cross-platform snippet search.

### 18.3 Platform-specific

- **TikTok / Instagram** — APIs change often; prefer platform exports; sample 1–4h cadence.
- **Bluesky AT Protocol** — DID resolution via `bsky.social/xrpc/com.atproto.identity.resolveHandle`; identity doc via `plc.directory/<did>`; firehose at Firesky; SkyView for graphs. Archive early — handle migration / post deletion.
- **Mastodon / Fediverse** — instance matters (jurisdiction, logging); WebFinger for discovery; FediSearch cross-instance; instance enumeration via Fediverse Observer; ActivityPub objects are JSON-LD.
- **Threads** — IG-API-similar limitations.

### 18.4 Auditory clues

Languages, dialects, background noises (train horns, prayer calls, wildlife). Tools: Audacity, Sonic Visualiser, SoundCMD. Spectrograms for unique patterns; Shazam/SoundHound for music.

### 18.5 Frame extraction

FFmpeg, VLC. Stitch panoramas; stabilize panning footage (FFmpeg `deshake` or Blender VSE). Prefer original uploads over re-encodes.

---

### 19.1 Shadow Analysis

Tools: SunCalc, ShadeMap, Bellingcat Shadow-Finder, NOAA Solar Calculator.

### 19.2 Astronomical Calculations

Stellarium, SkyMap, MoonCalc to simulate sky at different times/locations.

### 19.3 Satellite Imagery Time

Google Earth Pro (historical imagery slider), Sentinel Hub EO Browser (Sentinel + Landsat with timelapse). Record coordinates in WKT; hash cached tilesets.

---

### 20.1 Actor-Centric Workflow

- **Scoping** — actor hypothesis (APT28/29, Turla, Sandworm; APT10/41, Mustang Panda, Volt Typhoon). Seed reports from CERTs/vendors.
- **Indicator harvesting** — IOCs (domains, IPs, hashes, JA3/JA4, user-agents). Validate with passive DNS, CT logs, sandbox submissions.
- **Infrastructure mapping** — pivot from CT logs (SANs, issuer, serials), shared hosting, NS reuse, registrar accounts, HTML fingerprints. Enrich with ASN/WHOIS history, RPKI/ROA, geolocation.
- **Artifact profiling** — PE/ELF metadata (PDB paths, compile timestamps, Rich headers, code-signing). Cluster with SSDEEP/TLSH; YARA matches.
- **Social / procurement pivots** — developer handles, code snippets, academic theses, job posts, procurement records.
- **Falsification + reporting** — weigh each linkage; document alternatives; map TTPs to MITRE ATT&CK; cite sources with sections/pages.

### 20.2 Attribution Discipline

- Separate capability from intent and sponsorship.
- Rule of three: 3 weak OR 1 strong + 1 weak.
- Prefer durable pivots (registrar accounts, code-signing certs, build path idioms) over ephemeral (resolving IPs).
- Mark uncertainty levels; distinguish correlation from control.

### 20.3 Russia-Specific Pivots

- **Corporate / people** — EGRUL/EGRIP (captcha-gated), Rusprofile, Kontur.Focus, zakupki.gov.ru, hh.ru.
- **Infrastructure** — RU WHOIS via `whois.tcinet.ru`; Telegram for channels/admins/cross-posts.
- **Media** — VKontakte, Odnoklassniki, Rutube; search in Russian and transliterations.

### 20.4 China-Specific Pivots

- **Corporate / people** — gsxt.gov.cn (national enterprise credit); Tianyancha / Qichacha; ICP filings on beian.miit.gov.cn → USCC linkage.
- **Infrastructure** — CNNIC WHOIS; common domestic clouds (Aliyun, Tencent, Huawei).
- **Media** — Weibo, WeChat (via weixin.sogou.com), Zhihu, Bilibili, Douyin, Xiaohongshu; Chinese + Pinyin.

### 20.5 Infrastructure & Internet Measurement

- IP→ASN (HE BGP Toolkit, RIPEstat, BGPView).
- CT logs (crt.sh) for cert reuse and issuance cadence; pivot on subjects/issuers/serials.
- URLScan for HTML fingerprints, favicons (mmh3), script hashes.
- DNS over time (SecurityTrails PDNS, DNSDB) for subdomain churn and staging domains.

---

### 21.2 Profile Picture & Face Search

PimEyes, Exposing.ai, Azure Face API (compliance).

### 21.3 Social Graph & Content Analysis

Maltego, snscrape, SocialBlade. Bluesky / Mastodon: instance explorers + handle resolvers.

---

## 22. Breach × Identity Correlation

This is the highest-ROI single technique for external red teams. Execute it on every engagement.

### 22.1 Source stack

| Source | Tier | Notes |
|---|---|---|
| **Hudson Rock Cavalier** | FREE | Infostealer-log corpus; very high signal for corp SSO. |
| **Have I Been Pwned** | Free + paid | Domain-wide existence + Pwned Passwords (k-anonymity). |
| **DeHashed** | Paid | Searchable per-record API. |
| **IntelX** | Free + paid | Aggregator; phonebook search. |
| **Local breach corpus** | Operator-supplied | Whatever's on disk. |

### 22.2 Domain-level severity

| Stat | Severity |
|---|---|
| ≥10 employees compromised | CRITICAL |
| 1–9 employees compromised | HIGH |
| ≥1 end-user (non-employee) compromised | MEDIUM |
| Domain seen in breach with 0 named accounts | INFO |

### 22.3 SSO_EXPOSURE correlation

After Stage 3 has run identity-fabric mapping AND breach lookups have completed: for every discovered IdP tenant, intersect with breach corpus on the tenant's domain. Non-empty intersection → `SSO_EXPOSURE` finding, severity **CRITICAL**. Evidence: tenant ID + product + employee count + per-account source attribution.

### 22.4 Operational handling of stealer logs

- Treat as PII; encrypt at rest.
- SHA-256 every artifact; record source URL + acquisition timestamp.
- Never paste plaintext passwords into cloud LLMs.
- Document chain of custody.
- For client reports: redact passwords by default; offer the operator a separate encrypted credential bundle for raw data.

---

### 23.3 Malware & Artifact Analysis Workflow

- **Static triage** — SHA-256, strings, import tables, PDB path, Rich header. Don't rely solely on AV labels.
- **Dynamic / sandbox** — ANY.RUN, Hybrid Analysis, CAPE, Tria.ge.
- **Clustering** — SSDEEP/TLSH, YARA matches.
- **Reporting** — STIX 2.1 IOCs; ATT&CK technique IDs; reproduction steps.

### 23.4 Telegram / WeChat Investigation

- **Telegram** — public analytics (TGStat, Telemetr, Combot); export channels with Telegram Desktop; preserve message IDs, UTC timestamps, media hashes.
- **WeChat** — Sogou Weixin search; archive articles (PNG + WARC); capture `__biz` IDs. Expect link rot.

---

### 24.2 Cross-Module Coordination Patterns

When multiple OSINT tools (or modules) run, late-arriving outputs need to feed into earlier-running consumers. Three patterns:

1. **Sidecar JSON drops** — module writes `<scan>/mobile_endpoints.json` or `<scan>/secrets_sidecar.json`; later modules read on start. No blocking.
2. **Asset-graph upserts** — shared graph store; new assets trigger downstream modules via event bus.
3. **Late-binding queues** — long-running enumeration emits assets continuously; enrichment workers pull.

In ad-hoc engagement: `tmpdir + JSON sidecars + one-line manifest` makes operations composable.

### 24.3 Multi-Engine Corpus Run Methodology

Running a large dork corpus across multiple engines:

- **Pluggable engines** — wrap each engine (DDG, Bing, Brave, SerpAPI, Yandex, Baidu) behind a common interface. Default DDG (keyless); fall back to others when keys available.
- **Per-engine rate-limiting** — each engine has its own quota and ban posture. Use a token bucket per engine.
- **Result classification** — URL-signature → title-hint → snippet-regex pipeline. Output: `(severity, category, confidence)`.
- **Dedup by URL** — different engines surface duplicates.
- **Confidence rule** — snippet-only = TENTATIVE.
- **Persistence** — corpus DB so re-runs across engagements deduplicate.

### 24.4 Evidence Preservation for Offensive Engagements

- Per-engagement / per-scan SQLite store.
- JSONL run log with `run_id`, every event one line, UTC timestamps, tool versions.
- SHA-256 every downloaded artifact.
- PNG screenshots.
- Raw HTTP requests/responses, capped at 2 KiB body per side.
- Evidence served read-only from operator's machine.
- Reproduction package: `run_id` + tool versions + JSONL log + asset/findings DB.

---

## 25. Synthetic Media Verification

Sensity AI, Hive Moderation, Reality Defender, Adobe Content Credentials Verify, CarNet (AI car-model identification for geolocation aid).

---

## 26. Anti-Patterns & Common Failure Modes

A non-exhaustive list of mistakes that come up often.

- **Single-source attribution.** Three weak OR one strong + one weak.
- **Trusting vendor labels as ground truth.** Treat labels as hypotheses.
- **Assuming favicon-hash = ownership.** Shared infra, shared CMS templates, shared CDN.
- **Asserting 1:1 bridge flows.** Bridges mint and burn; aggregators rebalance.
- **Treating snippet-only Google dorks as confirmed.** TENTATIVE until you visit.
- **Pasting real PII / creds into cloud LLMs.** Local models for sensitive analysis.
- **Mirror-imaging the threat actor.** They don't think like you.
- **Attribution by IP geolocation.** IPs lie; VPNs and residential proxies exist.
- **Ignoring the 7-day optimistic-rollup challenge window.** L2 finality is delayed.
- **Ignoring CT-log lag.** New certs take minutes-to-hours to surface; absence ≠ doesn't exist.
- **Counting Wayback snapshots as "the site at time T."** Best-effort; many requests fail.
- **Trusting `whoami` from a discovered API.** Could be a honeypot.
- **Letting the asset graph carry untyped strings.** Every discovery is an asset.
- **Skipping the scope check.** Ask once when in doubt.
- **Forgetting UTC.** Local time creates correlation bugs.
- **Continuing to probe after a WAF block.** See §6.4 — back off.
- **Skipping confidence-upgrade documentation.** TENTATIVE assets need a path to CONFIRMED.
- **Treating exec-summary writing as an afterthought.** See §31 — plan deliverables at engagement start, not at the end.

---

## 27. WAF / CDN Bypass & Origin Discovery

Web targets are increasingly behind Cloudflare / Akamai / Fastly / AWS CloudFront. The CDN itself is hard to attack; the **origin server** is often softly defended. Six techniques to find it.

### 27.1 DNS history pivot

The target's domain may have pointed directly at the origin IP **before** the CDN was deployed. Query historical passive DNS:

- **SecurityTrails** — `https://api.securitytrails.com/v1/history/<domain>/dns/a` (paid; the most complete).
- **RiskIQ PassiveTotal** — passive DNS lookups; freemium.
- **DNSDB** (Farsight) — paid; long history.
- **Validin.com** — newer, has free tier.
- **Censys host search** — historical IP-cert mapping.

What to look for: an IP that resolved 1–5 years ago and is **not** in the current CDN's published IP ranges (Cloudflare / Akamai / etc.). Cross-check the IP's current banner — if it serves the same site without the CDN, you've got the origin.

### 27.2 Certificate SAN pivot

Certificates often get re-issued with the same SAN list across origin and CDN. Search CT logs:

- crt.sh `?q=%.<target.com>&exclude=expired` — find certs with the target's domain in SAN.
- Cross-reference issued certs against current CDN-fronted cert. The "extra" cert (not the CDN one) often points to origin via its CN/SAN.
- Tools like `cero` (`go install github.com/glebarez/cero@latest`) crawl IPs and pull certs; correlate IPs whose certs include the target's hostname.

### 27.3 Favicon hash + JARM origin clustering

If the target has a unique favicon, the origin server still serves it (CDNs proxy but don't strip the favicon). Compute the favicon's mmh3 hash and search:

- Shodan: `http.favicon.hash:<mmh3-hash>`.
- Censys: `services.http.response.favicons.hashes:<mmh3-hash>`.

Returned IPs that are **not** in CDN ranges are origin candidates.

JARM (TLS handshake hash) works similarly: compute the target's JARM via `jarm`, search Shodan `ssl.jarm:<jarm-hash>`. Origin servers usually have a different JARM than CDNs.

### 27.4 Direct IP probe with Host header

If you have an origin candidate IP from steps 27.1–27.3:

```bash
curl -sk -H "Host: target.example.com" https://<candidate-IP>/
```

If the response matches the public site (same title, same body fingerprint) — you've found the origin. CDN-only IPs return generic CDN error pages or 403 to wrong Host.

### 27.5 mail.* / ftp.* / cpanel.* exception

Targets often forget to put auxiliary subdomains behind the CDN:

- `mail.<target>` — often points at the actual mail server, sometimes co-located with web origin.
- `ftp.<target>`, `sftp.<target>` — likewise.
- `cpanel.<target>`, `whm.<target>`, `webmail.<target>` — shared hosting controls; same IP as web origin.
- `direct.<target>`, `origin.<target>`, `direct-connect.<target>`, `noproxy.<target>` — ironic admin labels.
- `dev.<target>`, `staging.<target>` — dev environments often skip CDN.

Probe each. If any resolves to a non-CDN IP, that IP often hosts the prod origin too.

### 27.6 Error page / misconfig leakage

When the CDN throws an error (request triggers WAF, origin is down, configuration mismatch), it sometimes leaks the origin IP in the error body:

- Cloudflare 5xx error pages historically included a `cf-ray` and sometimes the underlying upstream details.
- 502/504 from CDN tells you the origin exists but is unreachable from the CDN — useful confirmation it's not just NXDOMAIN.
- `X-Cache: MISS from <origin-host>` headers.
- HTTP response with origin headers leaking through (`X-Powered-By`, `Server`, `X-Backend-Server`).

### 27.7 Email-header bounce trick (for email-server origin)

Send an email to a non-existent address at the target. The bounce often reveals origin mail server IPs in the `Received:` headers — these mail servers are sometimes on the same IP / netblock as the web origin. (Use a sock-puppet email; never your real engagement persona.)

### 27.8 Confidence rules

- Origin IP found via DNS history: **TENTATIVE** until corroborated by direct probe.
- Origin IP corroborated by Host-header probe matching content: **FIRM**.
- Origin IP corroborated by Host-header probe + cert SAN match + favicon match: **CONFIRMED**.

When unsure, document the hypothesis in the asset attrs — don't claim origin discovery without ≥2 corroborating signals.

---

## 28. Vulnerability Prioritization (CVE / EPSS / KEV)

A Nuclei scan can return 100+ CVEs against a target. You can't validate all of them. Prioritize by exploitability.

### 28.1 Data sources (companion skill §29.2 has the URLs)

- **NVD** (National Vulnerability Database) — base CVE catalog, CVSS scores.
- **EPSS** (Exploit Prediction Scoring System) — probability of exploit in the next 30 days, scale 0.0–1.0.
- **CISA KEV** (Known Exploited Vulnerabilities) — vulnerabilities proven exploited in the wild; includes federal-agency due-by dates.
- **ExploitDB** — POC code presence.
- **Metasploit module catalog** — automation availability.
- **InTheWild.io** — community-curated "actively exploited" tracker.
- **OpenCVE** — timeline + watchlist + alerts.
- **Trickest CVE → POC mapping** — community-maintained mapping of CVEs to public POCs.

### 28.2 Prioritization rubric

For each CVE in your list, score:

| Signal | Weight |
|---|---|
| Listed in CISA KEV | **+50** (proven exploited; treat as immediate) |
| EPSS score ≥ 0.7 | **+30** |
| EPSS score 0.3–0.69 | **+15** |
| Public Metasploit module exists | **+25** |
| Public POC on ExploitDB / GitHub | **+15** |
| Vendor-issued advisory + patch | **+10** (means the vuln is real and patchable; not always exploitable) |
| Auth-required vs unauth-required | unauth +20, post-auth +0 |
| Network-vector (network) vs adjacent / local | network +15, adjacent +5, local +0 |
| CVSS v3 base ≥ 9.0 | **+15** |

**Total score → priority tier:**

| Score | Tier | Action |
|---|---|---|
| ≥ 100 | P0 | Immediate validation; surface in engagement summary now. |
| 70–99 | P1 | Validate this engagement; include in technical report. |
| 40–69 | P2 | Mention in technical report; validate if time permits. |
| < 40 | P3 | List in appendix; no validation expected. |

### 28.3 Validation discipline

- **Validate** = run a single read-only proof (e.g., a version banner check, a static-page fetch that confirms the vulnerable component) **without** triggering exploitation.
- **Do NOT** run the actual exploit unless the rules of engagement explicitly permit. Many bug bounty programs forbid PoC execution against production.
- For client engagements: deliver the prioritized list with reproduction commands but defer actual exploitation to a follow-on assessment if needed.

### 28.4 Handle CVE-less findings

Many real-world findings (sourcemap exposure, open GraphQL introspection, public bucket) don't have a CVE. Score them by their independent interest score (companion skill §20 for endpoints; §40 for severity-mapping examples). Don't gate on CVE availability.

---

## 29. Phishing Infrastructure & Pretext Development

Authorized red team engagements often include phishing. The **OSINT side** of phishing — building the phishing-feasibility shortlist and the pretext list — is in scope here. Crafting actual phishing payloads is **out of scope** (operational tradecraft, separate domain).

### 29.1 Phishing-feasibility shortlist

For an authorized engagement, the operator typically wants three lists:

**A. Already-registered typosquats** — these are *findings* (someone is squatting; client should know).

**B. Available-for-registration typosquats** — these are the *operator's phishing-domain shortlist* for the engagement.

**C. Cert-SAN impersonation patterns** — domains the operator could register that would make convincing certs (e.g., `acme-secure.com`, `acme-login.com`, `acme-vpn-portal.com`).

**Generation pattern:**
1. Run dnstwist (or equivalent) on the target's primary domain → get all variations (homoglyph, typosquatting, bit-flip, hyphenation, addition).
2. Check WHOIS for each: registered = list A, unregistered = list B.
3. For list C: combine target stem + plausible service words (`secure`, `login`, `vpn`, `portal`, `mail`, `helpdesk`, `it`, `account`, `verify`, `support`, `password`, `auth`, `sso`).

### 29.2 Subdomain takeover for trusted-domain phishing

If you found a takeover-able subdomain (companion skill §16.12), you can host phishing content **on a subdomain of the actual target**. This bypasses every brand-impersonation defense the user has.

**Procedure:**
1. Confirm takeover signature on the candidate (`<sub>.target.com` CNAMEd to unclaimed `<x>.herokuapp.com`).
2. Register the unclaimed resource (`<x>.herokuapp.com` on Heroku).
3. Now `<sub>.target.com` serves your content.
4. **Stop and consult the engagement lead before going live with phishing content.** Even in authorized engagements, the takeover step itself may need explicit client sign-off.

### 29.3 Email spoof feasibility

Use email security analysis (companion skill §16.14) to determine spoof feasibility:

| SPF policy | DMARC policy | Spoof feasibility |
|---|---|---|
| `~all` (softfail) or absent | `p=none` or absent | **HIGH** — direct spoof of `<anything>@<target>` likely lands. |
| `~all` | `p=quarantine` | MEDIUM — lands in spam folder, but lands. |
| `-all` (hardfail) | `p=quarantine` | LOW — most providers reject; some still deliver to spam. |
| `-all` | `p=reject` | VERY LOW — spoof rejected by major providers. Requires lookalike domain. |

If spoof is hard, fall back to lookalike (list B) or compromised-third-party (different engagement). Document the postural finding regardless.

### 29.4 Pretext development from OSINT

Pretexts work when they tap a target's existing context. Build pretexts from harvested OSINT.

**Pretext sources:**

- **Job titles + reporting structure** (LinkedIn) — "Hi <name>, this is <CFO-name>'s assistant; can you look at this finance file?"
- **Recent corporate events** (press releases, news, careers page) — "We're following up on the layoffs / new acquisition; please confirm your benefits info."
- **Vendor relationships** (job postings mentioning "experience with Workday/Salesforce/etc.") — "Workday password reset required by EOD."
- **Public conferences / travel** (LinkedIn posts, conference pages) — "Hi <name>, we met at <conference last week>; following up on what we discussed."
- **GitHub commits / open-source work** — "I saw your fix in <repo>; want to collaborate on a related PR?"
- **Office locations** (LinkedIn) — "On-site IT for the <city> office requires a quick auth check."

**Per-role pretext templates** (the ones operators use most):

- **End-users (general staff):** IT helpdesk password reset, Workday HR action required, Microsoft 365 storage full, package delivery confirmation.
- **Executives:** finance authority (BEC-style "wire approval needed"), board materials shared, M&A NDA review, executive assistant request.
- **Developers / engineers:** GitHub security alert, CI build failed, package security advisory, conference CFP follow-up.
- **HR / Finance:** payroll vendor change, expense report rejection, benefits enrollment deadline, vendor invoice discrepancy.
- **IT / Security:** vendor security update notification, on-call escalation, monitoring tool alert.

### 29.5 Operational discipline for phishing infrastructure

- All phishing infrastructure must be approved by the engagement lead **before** going live.
- Document every domain registered + every email sent (sender, recipient, subject, timestamp UTC).
- Keep phishing infrastructure isolated from your normal recon infrastructure (different IPs, different personas, different domain registrar accounts).
- Use dedicated payment methods for phishing-domain registration (engagement-specific corporate card; don't use personal).
- Tear down promptly after engagement; transfer/expire all domains; close all hosting accounts.

---

## 30. Bug Bounty Submission & Responsible Disclosure

When you find an issue on a bug-bounty target (HackerOne, Bugcrowd, Intigriti, YesWeHack) or on a non-program target where you choose to disclose responsibly.

### 30.1 Platform-specific basics

| Platform | URL | Notes |
|---|---|---|
| HackerOne | hackerone.com | Largest; strong scope-tracking; CVSS-based reward calc. |
| Bugcrowd | bugcrowd.com | VRT (Vulnerability Rating Taxonomy) instead of CVSS for severity. |
| Intigriti | intigriti.com | EU-strong; flexible scope models. |
| YesWeHack | yeswehack.com | EU-headquartered; growing. |
| HackenProof | hackenproof.com | Crypto/blockchain-focused programs. |
| Open Bug Bounty | openbugbounty.org | Free for sites without official programs (only XSS/SSRF disclosure). |
| security.txt | rfc9116 | Universal: every site should publish `/.well-known/security.txt`. |

### 30.2 Report structure (works on any platform)

```
Title: [Severity] [Affected component] Brief description
   Example: [HIGH] [api.acme.com] Unauthenticated SSRF via /v1/proxy

Summary
   2-3 sentences explaining what was found and why it matters.

Steps to Reproduce
   1. Numbered, copy-pasteable.
   2. Include exact URLs, payloads, expected vs actual response.
   3. Reproduce the issue from a fresh state where possible.

Proof of Concept
   - Screenshot showing the vulnerability triggered.
   - HTTP request/response (sanitize sensitive data; redact other users' data).
   - Or short video/GIF for complex multi-step issues.

Impact
   Quantify: what data is at risk, how many users, what business functions break.
   Tie to the program's impact criteria where defined.

Severity (per program criteria)
   - CVSS v3 vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
   - Score: 9.8 (Critical)
   - Justification: <1-2 sentence reasoning>

Remediation
   - Concrete recommendation. "Validate the URL parameter against an allowlist before fetching."
   - If a quick fix: WAF rule, header check.
   - If a structural fix: refactor recommendation.

Affected component
   - URL: https://api.acme.com/v1/proxy
   - Date discovered: 2026-04-27 14:23 UTC
   - Method: HTTP GET / POST / etc.
```

### 30.3 Severity inference per program

- HackerOne uses CVSS v3 with program-specific multipliers (some programs cap at HIGH; some pay 10x for CRITICAL).
- Bugcrowd VRT: P1 (Critical) → P5 (Informational); maps roughly to CRIT/HIGH/MED/LOW/INFO.
- Intigriti uses `Exceptional / Critical / High / Medium / Low` tiers.
- For programs that pay flat rates per severity tier, **don't inflate**. Conservative severity → trust → repeat awards.

### 30.4 Disclosure for unprogrammed targets (CVD)

If the target has no bug bounty program but you found a real vulnerability during authorized testing (e.g., a customer's external assessment surfacing a third-party vendor's bug):

1. Check for `<target>/.well-known/security.txt` — if present, follow its `Contact:` and `Encryption:` (PGP) instructions.
2. If absent, try `security@<target>` then `abuse@<target>`.
3. If those bounce, escalate via the registered abuse contact in WHOIS.
4. CERT/CC (cert.org) and national CERTs (CISA, CERT-EU, JPCERT) for coordination if vendor unresponsive.
5. Standard 90-day disclosure window before public release (Project Zero norm).

### 30.5 Cloud provider / SaaS-specific channels

- AWS abuse: `aws-security@amazon.com`. For exposed AWS keys: also notify the account owner if discoverable via WHOIS/contact.
- GCP: `google-cloud-trust@google.com`.
- Azure: Microsoft Security Response Center (MSRC) at `https://msrc.microsoft.com/`.
- GitHub: secret-scanning auto-revokes most published secrets via GitHub's partner program; if you find one, the scanning is usually faster than manual disclosure but back-up notify GitHub at `security@github.com`.
- npm / PyPI / Docker Hub: each has an `abuse@` or `security@` channel; npm specifically auto-revokes leaked tokens via their secret scanner.

### 30.6 Things to avoid in reports

- Don't include anyone else's PII / passwords / data in the report (redact).
- Don't post the report or PoC publicly until the disclosure window expires.
- Don't escalate via social media first (always direct channel first).
- Don't demand a specific bounty amount; let the program decide.
- Don't submit the same finding to multiple programs (duplicates can hurt your reputation).

---

## 31. Client Deliverable Templates

Operator-facing artifacts (asset graph, JSONL log, finding DB) are not the same as **client-facing artifacts** (exec summary, technical report). Build deliverables intentionally.

### 31.1 Executive summary template

```
ENGAGEMENT: <Client Name>
ASSESSMENT TYPE: External Attack Surface Assessment
ENGAGEMENT WINDOW: <start date> – <end date>
SCOPE: <one-line scope description, e.g., "All internet-facing assets of acme.com and its 3 brand domains">
LEAD: <your name / team>

----- KEY FINDINGS -----

1. [CRITICAL] <One-line title>
   Business impact: <one sentence in business language>
   Estimated remediation effort: <hours / days / weeks>
   Recommended action: <verb + object, e.g., "Rotate the exposed AWS access key and audit CloudTrail">

2. [CRITICAL] <One-line title>
   …

3. [HIGH] <One-line title>
   …

(Top 3-5 findings only; full list in technical report)

----- POSTURAL OBSERVATIONS -----

- Email security (SPF/DMARC): <2-3 sentences on posture, e.g., "DMARC is set to p=none, allowing spoof of <target>.com email; tightening to p=reject would block external spoofing.">
- Identity fabric (SSO): <2-3 sentences>
- Cloud surface (S3/GCS/Azure): <2-3 sentences>
- Mobile attack surface: <2-3 sentences if applicable>

----- AGGREGATE METRICS -----

- Assets discovered: <N> (<breakdown>)
- Findings: <N CRIT, M HIGH, P MED, Q LOW, R INFO>
- Live credentials confirmed: <N>
- Detectability of our operations: <90% low / 8% medium / 2% high>

----- RECOMMENDED NEXT STEPS -----

1. Address P0 findings in next 7 days.
2. Address P1 findings in next 30 days.
3. Schedule re-test for: <date>.
4. Consider follow-on assessments: <if applicable, e.g., authenticated app testing, internal pentest>.
```

### 31.2 Per-finding report card template

Each finding in the technical report uses this card:

```
═══════════════════════════════════════════════════════════
FINDING #<N>: <Title>
SEVERITY: <CRIT / HIGH / MED / LOW / INFO>
CONFIDENCE: <CONFIRMED / FIRM / TENTATIVE>
ASSET: <typed asset key>
DISCOVERED: <UTC timestamp>
═══════════════════════════════════════════════════════════

DESCRIPTION
  <2-5 sentence technical explanation>

EVIDENCE
  - URL: <where it was found>
  - Tool: <how it was discovered>
  - Screenshot: <attachment ref>
  - Raw HTTP: <sanitized capture>
  - Hash (SHA-256): <of any downloaded artifact>

REPRODUCTION
  Step 1: <command or action>
    Expected: <output>
  Step 2: …

IMPACT
  <Business-language impact statement>
  Affected systems: <list>
  Affected user populations: <if applicable>

REMEDIATION
  Immediate (within hours):
    - <action>
  Short-term (within days):
    - <action>
  Long-term (within weeks):
    - <action>

REFERENCES
  - <CVE-ID, advisory URL, OWASP top-10 link, vendor doc>

ATTACK PATH HINT
  <If applicable, the one-sentence hint from companion skill §39>
```

### 31.3 Risk translation matrix

Engineers think in CVSS. Executives think in business outcomes. Translate.

| Technical finding | Business-language impact |
|---|---|
| Listable S3 bucket with PII | "Customer records publicly downloadable. Potential GDPR/CCPA notification trigger if accessed. Estimated cost of disclosure: 30-day notification + credit monitoring + legal review." |
| Exposed `.env` with DB credentials | "Database access to all customer data. Pivots to backups, billing systems, employee PII. If exploited: full data breach scope." |
| Live AWS access key with admin scope | "Full cloud account compromise. Attacker can spin up cryptominers, exfiltrate all data, lateral-move to connected accounts. If exploited: 6-figure cloud bill + complete environment rebuild." |
| Open GraphQL introspection on prod | "API attack surface fully mapped by attackers. Enables more precise follow-on attacks; not directly exploitable but attacker reconnaissance is now zero-effort." |
| Subdomain takeover possible | "Attackers can host content under your trusted domain. Phishing emails from this domain bypass brand-impersonation defenses; users will trust them." |
| Open Firebase Realtime Database | "Mobile app's backend database is publicly readable. All user data, possibly writable. If exploited: full data breach + potential service disruption." |
| Missing HSTS on /login | "Login pages can be downgraded to HTTP via active network attacks. Credentials potentially captured by anyone with network access (coffee shop, conference WiFi)." |
| DMARC `p=none` | "Anyone on the internet can send email appearing to be from your domain. Phishing campaigns become trivially convincing for both customers and employees." |
| ≥10 employees in breach corpus | "Stolen credentials for your staff are circulating; attackers can attempt these against your SSO. Even if SSO has MFA, password reuse against other services puts those at risk." |
| `android:debuggable=true` | "Mobile app can be reverse-engineered and modified by anyone. Trust boundary between app and server is undermined; backend assumes app integrity that doesn't exist." |
| Vendor product (Citrix/F5/Pulse) version with KEV CVE | "Network appliance has a known-exploited vulnerability. Attackers are actively scanning the internet for this exact issue. Patch immediately." |

### 31.4 Reporting cadence for engagements > 1 day

- **Day 1 EOD** — short kickoff confirmation: "Stage 1 complete. Identified <N> assets so far. Initial posture: <one paragraph>."
- **Mid-engagement check-in** — when you find your first CRITICAL OR at the 50% time mark, whichever first. Heads-up to engagement lead: "Found <CRIT description>; recommend you alert <client contact> now to begin remediation prep."
- **End-of-engagement preliminary** — same day as last probe: top 5 findings + plan for full report delivery within X business days.
- **Final report** — formal deliverable; both exec summary + technical report.
- **Re-test offer** — proactive: "We're available for a re-test in <window>; recommend re-testing CRITICAL/HIGH findings after remediation."

### 31.5 Reproduction package contents

Deliver alongside the report:

```
<engagement-id>-reproduction-package.zip
├── README.md                    # how to use the package
├── engagement-metadata.json     # client, dates, scope, lead
├── tools-used.txt               # tool name + version, one per line
├── run-log.jsonl                # every event during engagement
├── assets.db                    # SQLite of all discovered assets
├── findings.db                  # SQLite of all findings
├── evidence/
│   ├── screenshots/             # PNG, named by finding-id
│   ├── http/                    # raw HTTP captures (sanitized)
│   ├── downloads/               # any binary artifacts (with .sha256 alongside)
│   └── code/                    # any extracted source (sanitized)
├── re-test-script.sh            # reruns probes for the CRIT/HIGH findings
└── disclosure/                  # if applicable: bounty submissions, vendor notifications
```

The package is the source of truth — the report is the human-readable view. Anyone with the package can reproduce the engagement and verify findings.

---

## 32. Skill Self-Test

Drop these prompts into a fresh Claude session to verify the skill loads and behaves correctly. Pass criteria: expected sections referenced, no hallucinated content, scope-check invoked when needed.

1. *"I'm doing external recon on acme.com (in-scope bug bounty). Where do I start?"* → §0, §1, §7, §7.5, §11.
2. *"How do I tell if a target uses Entra, Okta, or ADFS without active probing?"* → §11.2-11.4 + companion skill §22.
3. *"What should I look for when I scrape JS bundles?"* → §13.
4. *"What's the workflow for finding and analyzing a target's Android apps?"* → §14.
5. *"How do I generate good cloud bucket candidates without spamming the entire internet?"* → §15.
6. *"We've harvested 200 emails for the target and confirmed the org uses Entra. Highest-ROI next step?"* → §22.
7. *"I found a live AWS access key in a public GitHub repo. Should I check if it works?"* → §6.3 + companion skill §23.2.
8. *"Our team just acquired a 4GB stealer-log dump. How do we handle it?"* → §22.4.
9. *"I found three indicators that look like APT28 — does that confirm it?"* → §20.2 + §2.
10. *"Investigating a Russian cybercrime actor. What corporate/people pivots?"* → §20.3.
11. *"How do I link a `.cn` domain to its operating company?"* → §20.4 + companion skill §14.2.
12. *"List the most common mistakes red teamers make during external recon."* → §26.
13. *"Run a full subdomain enum on chase.com."* → §1 (scope check; should NOT run).
14. *"My subdomain marked TENTATIVE — how to upgrade?"* → §2.1.
15. *"How long should a 1-week recon engagement take across the 5 stages?"* → §7.6.
16. *"50 subdomains, 12 webapps, 4 IPs, 23 emails — triage order?"* → §8.5 + §7.5.
17. *"Probing a 50-employee SaaS company with M365 + GitHub + AWS. Where to focus?"* → §10.1 + §11.10 + §22.
18. *"Target is fully behind Cloudflare. How do I find the origin?"* → §27.
19. *"100 CVEs from a Nuclei scan. How do I prioritize?"* → §28.
20. *"My probes are getting 429s and a Cloudflare interstitial. What now?"* → §6.4.
21. *"Authorized engagement asks for phishing-feasibility shortlist. Walk me through it."* → §29.
22. *"Found unauth POST endpoint on a HackerOne target. Write me the report."* → §30.2.
23. *"Write the executive summary for an engagement that found 2 CRIT, 5 HIGH, 12 MED."* → §31.1 + §31.3.

---

## 33. Changelog

- **v2.1 (2026-04-27)** — comprehensive expansion based on 32-test smoke-test gap analysis. Added: confidence upgrade workflows (§2.1), detection-aware probing (§6.4), time budgeting & engagement profiles (§7.6), asset-level triage rules (§8.5), scale-based tactics (§10.1), Microsoft 365 deep surface (§11.10), WAF/CDN bypass & origin discovery (§27), vulnerability prioritization (§28), phishing infrastructure & pretext development (§29), bug bounty submission & responsible disclosure (§30), client deliverable templates (§31). Self-Test section refreshed with v2.1 prompts.
- **v2.0 (2026-04-27)** — major rewrite for external red-team posture. Added: 5-stage pipeline, asset-graph discipline, findings rubric, bug-bounty pivot modes, identity-fabric mapping, API & auth-map methodology, JS deep analysis, mobile attack surface, cloud attack surface, breach × identity correlation, detectability tagging, validator discipline, cross-module coordination, multi-engine corpus run, evidence preservation, anti-patterns. Original methodology content (OpSec, Crypto, Image/Video/Chrono, Threat Actor inc. RU/CN, Synthetic Media) retained.
- **v1.x** — original OSINT methodology framework based on SnailSploit/offensive-checklist.

---

## Related Skills & Chains

- **`offensive-osint`** — When the methodology needs to be executed with concrete probes. Workflow primitive: this skill is the planning skeleton (5-stage pipeline, asset graph, findings rubric); `offensive-osint` is the operational arsenal that fills each stage with curl one-liners, wordlists, and regexes.
- **`web2-recon`** — When asset discovery moves from planning to running. Workflow primitive: after this skill's §7 pipeline is scoped, `web2-recon` runs the subfinder → dnsx → httpx → katana commands and produces the URL set.
- **`hunt-subdomain`** — When the asset graph surfaces stale CNAMEs. Workflow primitive: §8 Asset Graph entries with CNAME pointing to S3 / GitHub Pages / Heroku / Shopify / Azure auto-route to `hunt-subdomain` for takeover validation.
- **`hunt-cloud-misconfig`** — When the asset graph surfaces exposed buckets / actuators / Firebase. Workflow primitive: §15 Cloud Attack Surface findings (open S3, /actuator/env, /firebaseio.com/.json) hand off to `hunt-cloud-misconfig` for exploitation.
- **`bb-methodology`** — When the engagement mode is bug-bounty rather than pure recon. Workflow primitive: this skill's §10 bug-bounty pivot modes are the bridge; once mode is confirmed, `bb-methodology` PART 0 + 5-phase workflow takes over.


## SOURCE: hunt-skills/recon-scope-triage/SKILL.md

## When to use this skill

Trigger when:
- The target brand is a common/dictionary word or shared term (e.g. `apex`, `summit`, `vertex`, `nova`, `core`, `orbit`, `pulse`, `unity`…)
- You receive an ASM report, recon export, breach combo, repo list, bucket list, or mobile-app list to act on
- A "Critical" count looks implausibly high (hundreds) for the org's size
- Any asset's ownership is asserted by the tool but not *proven*

The two failure modes this skill prevents:
1. **Wasting the engagement** testing/triaging assets that aren't the target's.
2. **Attacking an innocent third party** that merely shares the name — out of scope, and real harm.

**Rule: ownership is guilty-until-proven. An asset is the target's only when a concrete ownership signal ties it to the target — never because a scanner's keyword matched.**

---

## The collision sources (where keyword-matching lies)

| Recon source | How it collides | Verify ownership by |
|---|---|---|
| **GitHub repos** | Search matched the brand word in repo name / topic / a string | Repo owner is the org's GH org; commits from org emails; code references the org's real domains/infra. A repo named `<word>-backend` by a random user = noise. |
| **Cloud buckets** (S3/GCS) | Bucket names are a **global namespace**; `<word>-static`, `<word>-data`, `<word>-public` exist for *someone* | Bucket content references the target; bucket name correlates with a *confirmed* target subdomain (`x.target.com` ↔ `x-public`) AND content matches; ACL/owner metadata. Generic content (other-language, other-industry) = not theirs. |
| **Mobile apps** | Store search matched the brand word in app name / package | Publisher account = the org; package reverse-DNS = an owned domain (`com.<owneddomain>.app`); dev cert; app calls owned API hosts. Mature ASM tools emit an "apps_accepted=0" / ownership-confidence field — read it. |
| **Breach corpora / combos** | Email local-or-domain contains the brand word | **Exact** owned-domain match only (`@target.com`), not `@<word>group.com` / `@something<word>.com`. A different domain that contains the word is a different org. |
| **Typosquats** | Generated permutations of the name | These are *defensive*/brand-protection findings, not offensive scope — note and move on. |
| **Stack/forum/paste hits** | Brand word in body | Body references the target's real domain/subdomain/employee/secret. Ownership-confidence < threshold = drop. |

---

## Web "Critical" triage — the soft-404 control

Automated `.env` / `.git` / `actuator` / admin-panel "Criticals" are overwhelmingly **soft-404s**: SPA/framework catch-alls returning HTTP 200 (or 403) for *every* path. Verify EACH before believing it:
```bash

# the "finding"
curl -s -o /tmp/a -w "%{http_code} %{size_download}\n" https://host.target.com/.env

# a junk control on the same host
curl -s -o /tmp/b -w "%{http_code} %{size_download}\n" https://host.target.com/zzz-nonsense-$RANDOM

# identical byte length / body  →  FALSE POSITIVE (catch-all), discard
cmp -s /tmp/a /tmp/b && echo "SOFT-404 false positive" || echo "differs — investigate"
```
Real exposures have a content-type + signature that differs from the catch-all (`.git/config` starts `[core]`; `.env` has `KEY=value`; phpinfo has the XHTML-transitional doctype + `PHP Version`). A physical `.php`/`phpinfo.php` that returns a *bigger/different* body than the junk control is the real-vs-soft-404 tell.

---

## The triage workflow

1. **Confirm the canonical owned-domain set first** (the SOW/program domain + its verified subdomains + the verified Entra/Okta/Google tenant brand name). This is your ownership anchor.
2. **For each asset class, apply the verify-by column above.** No signal → quarantine, don't test.
3. **Re-baseline the severity counts** against only-owned assets. Report the *delta* — "N Criticals → M after ownership + soft-404 triage" is itself a finding about the ASM program.
4. **Quarantine collisions explicitly** (a `loot/quarantined_<source>.txt`) so it's auditable that you saw them and chose not to target them.
5. **Surface the meta-finding:** if the supplied ASM/recon feed is mostly false-positive, that misallocates the owner's remediation budget and buries real risk — write it up (Medium/Strategic).

---

## Anti-patterns

- **Trusting the tool's "owned" label.** Tools keyword-match; they don't prove ownership. Verify.
- **Targeting a same-named third party** because it was "in the report." Out of scope + real harm. A combo line `user@<word>company.com` is a different company's employee.
- **Reporting soft-404s as exposures.** Always run the junk-path control.
- **Counting typosquats / missing-headers / brand-collision repos as offensive findings.** They're defensive/hygiene/noise — they pad the report and erode credibility.
- **Skipping triage "to save time."** Untriaged, you spend the whole engagement on other people's assets and find nothing real.

---

## Why this matters (calibration)

For a target whose brand is a common word, expect the bulk of automated "owned" assets to be collisions:
- **Repos** that are unrelated open-source projects (ad-block lists, scrapers, student projects, a different company's SDK) merely containing the word.
- **Mobile apps** published by entirely different companies that share the name — banks, credit unions, dating apps, dispensaries, home-care services are all real-world collision categories. (Good ASM tooling will tell you it accepted *zero* as owned.)
- **Cloud buckets** in the global namespace holding some unrelated org's content (other-language documents, demo/sample data, another industry's files).
- **Breach combos** full of emails from sibling-named-but-different companies (`<word>group.com`, `<region><word>.com`).

On a real engagement against a dictionary-word brand, after clearing this noise the only genuinely-owned high-severity finding was discoverable solely by manual tradecraft (a JS-bundle → API discovery, see `hunt-spa-api`) — it was nowhere in the hundreds of scanner "Criticals." Triage-first is what made the engagement productive instead of a goose chase.

---

## Related Skills & Chains

- **`triage-validation`** — asset-ownership triage (this skill) precedes finding-validity triage (the 7-Question Gate). Ownership first, then validity.
- **`redteam-mindset`** — "aggressive default" means probe every *owned* live surface; this skill defines which surfaces are owned so persistence isn't wasted on collisions.
- **`hunt-spa-api`** — once an API host passes ownership triage, this is how you test it.
- **`offensive-osint` / `osint-methodology`** — feed ownership anchors (verified domains, tenant brand, dev accounts) from OSINT into this triage.


## SOURCE: hunt-skills/web2-recon/SKILL.md

# WEB2 RECON PIPELINE

Full asset discovery from nothing to a prioritized URL list ready for hunting.

---

# 1. Set your Chaos API key (get free key at chaos.projectdiscovery.io)
export CHAOS_API_KEY="your-key-here"

# Add to ~/.zshrc or ~/.bashrc for persistence:
echo 'export CHAOS_API_KEY="your-key-here"' >> ~/.zshrc

# 3. Configure subfinder with API keys for more sources
mkdir -p ~/.config/subfinder
cat > ~/.config/subfinder/config.yaml << 'EOF'

# Get free keys at: virustotal.com, securitytrails.com, censys.io, shodan.io
virustotal: [YOUR_VT_KEY]
securitytrails: [YOUR_ST_KEY]
censys_apiid: YOUR_CENSYS_ID
censys_secret: YOUR_CENSYS_SECRET
shodan: [YOUR_SHODAN_KEY]
EOF

# 4. Verify all tools installed
which subfinder httpx dnsx nuclei katana waybackurls gau dalfox ffuf anew gf interactsh-client
```

---

## THE 5-MINUTE RULE

> If a target shows nothing interesting after 5 minutes of recon, move on. Don't burn hours on dead surface.

**5-minute kill signals:**
- All subdomains return 403 or static marketing pages
- No API endpoints visible in URLs
- No JavaScript bundles with interesting endpoint paths
- nuclei returns 0 medium/high findings
- No forms, no authentication, no user data

---

# Step 0: Passive — crt.sh certificate transparency (no API key needed)
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | sort -u > /tmp/subs.txt
echo "[+] crt.sh: $(wc -l < /tmp/subs.txt) subdomains"

# Step 1: Chaos API (ProjectDiscovery — most comprehensive source)
curl -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" \
  -H "Authorization: $CHAOS_API_KEY" \
  | jq -r '.[]' >> /tmp/subs.txt

echo "[+] Chaos returned $(wc -l < /tmp/subs.txt) subdomains"

# Step 2: subfinder (passive multi-source)
subfinder -d $TARGET -silent | anew /tmp/subs.txt
assetfinder --subs-only $TARGET | anew /tmp/subs.txt

echo "[+] Total subdomains after all sources: $(wc -l < /tmp/subs.txt)"

# Step 3: DNS resolution + live host check
cat /tmp/subs.txt | dnsx -silent | httpx -silent -status-code -title -tech-detect | tee /tmp/live.txt

echo "[+] Live hosts: $(wc -l < /tmp/live.txt)"

# Step 4: URL crawl
cat /tmp/live.txt | awk '{print $1}' | katana -d 3 -jc -kf all -silent | anew /tmp/urls.txt

# Step 5: Historical URLs
echo $TARGET | waybackurls | anew /tmp/urls.txt
gau $TARGET --subs | anew /tmp/urls.txt

echo "[+] Total URLs: $(wc -l < /tmp/urls.txt)"

# Step 6: Nuclei scan
nuclei -l /tmp/live.txt -t ~/nuclei-templates/ -severity critical,high,medium -o /tmp/nuclei.txt
```

### Output to Organized Directory

```bash
TARGET="target.com"
RECON_DIR="recon/$TARGET"
mkdir -p $RECON_DIR

# All outputs go here:
/tmp/subs.txt         → $RECON_DIR/subdomains.txt
/tmp/live.txt         → $RECON_DIR/live-hosts.txt
/tmp/urls.txt         → $RECON_DIR/urls.txt
/tmp/nuclei.txt       → $RECON_DIR/nuclei.txt
```

---

# Parameters worth testing
cat /tmp/urls.txt | grep -E "[?&](id|user|file|path|url|redirect|next|src|token|key|api_key)=" | tee /tmp/interesting-params.txt

# API endpoints
cat /tmp/urls.txt | grep -E "/api/|/v1/|/v2/|/v3/|/graphql|/rest/|/gql" | tee /tmp/api-endpoints.txt

# File upload endpoints
cat /tmp/urls.txt | grep -E "upload|file|attachment|document|image|avatar|photo|media" | tee /tmp/uploads.txt

# Admin/internal paths
cat /tmp/urls.txt | grep -E "/admin|/internal|/debug|/test|/staging|/dev|/management|/console" | tee /tmp/admin-paths.txt

# Authentication endpoints
cat /tmp/urls.txt | grep -E "/oauth|/login|/auth|/sso|/saml|/oidc|/callback|/token" | tee /tmp/auth-paths.txt
```

# Install gf patterns: https://github.com/tomnomnom/gf
cat /tmp/urls.txt | gf xss | tee /tmp/xss-candidates.txt
cat /tmp/urls.txt | gf ssrf | tee /tmp/ssrf-candidates.txt
cat /tmp/urls.txt | gf idor | tee /tmp/idor-candidates.txt
cat /tmp/urls.txt | gf sqli | tee /tmp/sqli-candidates.txt
cat /tmp/urls.txt | gf redirect | tee /tmp/redirect-candidates.txt
cat /tmp/urls.txt | gf lfi | tee /tmp/lfi-candidates.txt
cat /tmp/urls.txt | gf rce | tee /tmp/rce-candidates.txt
```

---

# Scan a single JS file
python3 ~/tools/SecretFinder/SecretFinder.py -i "https://target.com/static/js/main.js" -o cli

# Scan all JS URLs found in recon
cat /tmp/urls.txt | grep "\.js$" | head -50 | while read url; do
  echo "=== $url ==="
  python3 ~/tools/SecretFinder/SecretFinder.py -i "$url" -o cli 2>/dev/null
done

deactivate
```

### LinkFinder (Endpoints hidden in JS)

```bash
source ~/tools/LinkFinder/.venv/bin/activate

# Single JS file
python3 ~/tools/LinkFinder/linkfinder.py -i "https://target.com/app.js" -o cli

# All pages (crawls JS from HTML)
python3 ~/tools/LinkFinder/linkfinder.py -i "https://target.com" -d -o cli

deactivate
```

---

# Directory discovery on a live host
ffuf -u "https://target.com/FUZZ" \
     -w ~/wordlists/common.txt \
     -mc 200,201,204,301,302,307,401,403 \
     -ac \
     -t 40 \
     -o /tmp/ffuf-dirs.json

# Create req.txt with Authorization: Bearer TOKEN
ffuf -request /tmp/req.txt \
     -request-proto https \
     -w <(seq 1 10000) \
     -fc 404 \
     -ac \
     -t 10
```

---

## TARGET SCORING — GO / NO-GO

Score before spending time. Skip if score < 4.

| Criterion | Points |
|---|---|
| Max bounty >= $5K | +2 |
| Large user base (>100K) or handles money | +2 |
| Program launched < 60 days ago | +2 |
| Complex features: API, OAuth, file upload, GraphQL | +1 |
| Recent code/feature changes (GitHub, changelog) | +1 |
| Private program (less competition) | +1 |
| Tech stack you know | +1 |
| Source code available | +1 |
| Prior disclosed reports to study | +1 |

**< 4:** Skip
**4-5:** Only if nothing better available
**6-8:** Good — spend 1-3 days
**>= 9:** Excellent — spend up to 1 week

### Pre-Dive Hard Kill Signals

1. Max bounty < $500 → not worth your time
2. All recent reports are N/A or duplicate → hunters saturated it
3. Scope is only a static marketing page → no attack surface
4. Company < 5 employees with no revenue → won't pay
5. Explicitly excludes your planned bug class in rules

---

# Response headers reveal backend
curl -sI https://target.com | grep -iE "server|x-powered-by|x-aspnet|x-runtime|x-generator"

### Stack → Primary Bug Class Map

| Stack | Hunt First | Hunt Second |
|---|---|---|
| Ruby on Rails | Mass assignment | IDOR (`:id` routes) |
| Django | IDOR (ModelViewSet, no object perms) | SSTI (mark_safe) |
| Flask | SSTI (render_template_string) | SSRF (requests lib) |
| Laravel | Mass assignment ($fillable) | IDOR (Eloquent, no ownership) |
| Express (Node.js) | Prototype pollution | Path traversal |
| Spring Boot | Actuator endpoints (/actuator/env) | SSTI (Thymeleaf) |
| ASP.NET | ViewState deserialization | Open redirect (ReturnUrl) |
| Next.js | SSRF via Server Actions | Open redirect via redirect() |
| GraphQL | Introspection → auth bypass on mutations | IDOR via node(id:) |
| WordPress | Plugin SQLi | REST API auth bypass |

---

## CONTINUOUS MONITORING SETUP

Set up once per target. Alerts you before other hunters.

### New Subdomain Alerts (daily cron)

```bash
#!/bin/bash
TARGET="target.com"
KNOWN="/tmp/$TARGET-subs-known.txt"

subfinder -d $TARGET -silent > /tmp/$TARGET-subs-fresh.txt
curl -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" \
  -H "Authorization: $CHAOS_API_KEY" \
  | jq -r '.[]' >> /tmp/$TARGET-subs-fresh.txt

# Diff against known
NEW=$(comm -23 <(sort /tmp/$TARGET-subs-fresh.txt) <(sort $KNOWN 2>/dev/null))

if [ -n "$NEW" ]; then
  echo "NEW SUBDOMAINS: $NEW"
  echo "$NEW" >> $KNOWN
fi

### GitHub Commit Watch

```bash
#!/bin/bash
REPO="TargetOrg/target-app"
LAST_SHA="/tmp/$REPO-last-sha.txt"

CURRENT=$(curl -s "https://api.github.com/repos/$REPO/commits?per_page=1" | jq -r '.[0].sha')
KNOWN=$(cat $LAST_SHA 2>/dev/null)

if [ "$CURRENT" != "$KNOWN" ]; then
  echo "New commit on $REPO: $CURRENT"
  echo $CURRENT > $LAST_SHA
  # Get changed files
  curl -s "https://api.github.com/repos/$REPO/commits/$CURRENT" \
    | jq -r '.files[].filename' | grep -E "auth|middleware|route|permission|role|admin"
fi

# Finds non-standard ports: 8080, 8443, 3000, 8888, 9000, etc.
cat /tmp/live.txt | awk '{print $1}' | naabu -port 80,443,8080,8443,3000,4000,5000,8000,8888,9000,9090,9200,6379 -silent | tee /tmp/open-ports.txt

# Why this matters: admin panels, debug services, internal APIs often run on alt ports

# Example wins: :8080/actuator/env (Spring Boot), :9200/_cat/indices (Elasticsearch), :6379 (Redis)
```

# Scans JS files and git repos
pip install trufflehog3 2>/dev/null || true
trufflehog filesystem --only-verified recon/$TARGET/ 2>/dev/null

# SecretFinder — manual JS bundle scan (already in tools/)
source ~/tools/SecretFinder/.venv/bin/activate
cat /tmp/urls.txt | grep "\.js$" | head -100 | while read url; do
  python3 ~/tools/SecretFinder/SecretFinder.py -i "$url" -o cli 2>/dev/null
done
deactivate

# Quick grep for common patterns in downloaded JS
wget -q -r -l 1 -A "*.js" -P /tmp/js-files/ "https://$TARGET" 2>/dev/null
grep -rn "api_key\|apiKey\|client_secret\|access_token\|private_key\|AWS_SECRET\|AKIA" /tmp/js-files/ 2>/dev/null
```

# Search GitHub for hardcoded secrets before hunting the app
TARGET_ORG="TargetOrgName"  # Check their GitHub org

# CLI with gh (GitHub CLI):
gh search code "api_key" --owner "$TARGET_ORG" --json path,repository 2>/dev/null | jq '.'
gh search code "password" --owner "$TARGET_ORG" --json path,repository 2>/dev/null | head -20

# GitDorker (if installed):
python3 ~/tools/GitDorker/GitDorker.py -t GITHUB_TOKEN -d ~/tools/GitDorker/Dorks/alldorksv3 -q "$TARGET" -org
```

### Minutes 0-5: Read Program Page

```
Note:
- ALL in-scope assets (every domain listed)
- Out-of-scope list (read carefully — common trap)
- Safe harbor statement
- Impact types accepted (some exclude "low")
- Average bounty amount (signals program generosity)
```

### Minutes 5-15: Asset Discovery

Run the standard pipeline above. Focus on live.txt output.

### Minutes 15-25: Surface Map

Run gf patterns and the interesting-params grep above.

### Minutes 25-30: Manual Exploration

Open Burp Suite. Browse the app with proxy on:
1. Register an account
2. Perform main user actions (create/read/update/delete resources)
3. Note all API calls in Burp history
4. Look for endpoints not in your URL list

### After 30 min: Prioritize

```
Priority 1: API endpoints with ID parameters → IDOR candidates
Priority 2: File upload features → XSS/RCE candidates
Priority 3: OAuth/SSO flows → auth bypass candidates
Priority 4: Search/filter with user input → SQLi/SSRF/SSTI candidates
Priority 5: Admin/debug endpoints → auth bypass candidates
```

---

## Toolchain fallback (when `dnsx` / `httpx` crash)

The projectdiscovery Go binaries (`dnsx`, `httpx`, `naabu`) occasionally `SIGSEGV` on macOS arm64 due to a cgo / system-resolver interaction. The crash signature is identical regardless of install method — both `brew install` and `go install github.com/projectdiscovery/<tool>@latest` produce binaries that segfault at the same address. Smoke-test once before relying on them in a real engagement:

```bash
dnsx -version   # if SIGSEGV: use the dig fallback below
httpx -version  # if SIGSEGV: use the curl fallback below
```

# Replaces: dnsx -l subs.txt -a -resp -silent
while read s; do
  ips=$(dig +short +tries=1 +time=3 "$s" \
    | grep -E '^[0-9.]+$' \
    | paste -sd, -)
  [ -n "$ips" ] && echo "$s|$ips"
done < subs.txt
```

# Replaces: httpx -l subs.txt -silent -status-code -title -tech-detect
while read s; do
  resp=$(curl -s -L -m 5 -o /tmp/body \
    -w "%{http_code}|%{url_effective}|%{header_server}" \
    "https://$s")
  code=$(echo "$resp" | cut -d'|' -f1)
  if [ "$code" != "000" ]; then
    title=$(grep -oE '<title[^>]*>[^<]*</title>' /tmp/body | head -1 | sed 's/<[^>]*>//g')
    echo "$s|$resp|$title"
  fi
done < subs.txt
```

**Trade-off:** Serial vs. concurrent. The fallback handles ~24 subdomains in 14 seconds; the same workload on `httpx` with default 50 threads finishes in 2-3 seconds. For VDP-scale recon (< 100 subdomains) the fallback is fine. For mass recon (1000+) fix the toolchain first.

Verified against HackerOne's own VDP in `docs/verification/recon-hackerone-vdp.md`.

---

## API Spec / Swagger / OpenAPI Discovery (2024-2026 surface)

API spec endpoints are the single highest-leverage recon target on any modern .NET / Node / Python / Java backend. The spec discloses every endpoint, HTTP methods, parameter names + types + formats, models, validation rules — a complete attack-map in JSON. Default routes are commonly left enabled in production. **Add this wordlist to the directory-fuzzing phase** (after the standard `common.txt` pass).

# NSwag / Swashbuckle (ASP.NET Core)
/swagger
/swagger/
/swagger/index.html
/swagger/ui/index.html
/swagger/v1/swagger.json
/swagger/v2/swagger.json
/swagger/v3/swagger.json
/swagger/docs/v1
/swagger/docs/v2
/swagger-ui
/swagger-ui/
/swagger-ui.html
/swagger-resources
/swagger-resources/configuration/ui
/nswag
/nswag/index.html
/api/swagger
/api/swagger.json
/api/swagger/v1/swagger.json
/api/openapi
/api/openapi.json
/api/v1/swagger.json
/api/v2/swagger.json
/api-docs
/api-docs/swagger.json

# OpenAPI generic
/openapi
/openapi.json
/openapi.yaml
/openapi.yml
/openapi/v1.json
/openapi/v2.json
/openapi/v3.json
/.well-known/openapi.json

# Java / Spring (Springfox / springdoc)
/v2/api-docs
/v3/api-docs
/v3/api-docs.yaml
/v3/api-docs/swagger-config
/swagger-ui/index.html

# Python (FastAPI / Flask-RESTPlus / Connexion / DRF)
/docs
/docs/
/redoc
/redoc/
/openapi.json
/swagger.json
/swagger/?format=openapi
/swagger.yaml

# Express / Node / Hapi
/api-docs
/api-docs.json
/swagger.json
/swagger-stats
/graphql-docs

# GraphQL adjacent (often co-located)
/graphql
/graphiql
/playground
/altair
/voyager
/graphql/console
/graphql-explorer

# ReDoc / RapiDoc / Stoplight / alt UIs
/redoc
/redoc.html
/redoc-ui.html
/rapidoc
/rapidoc.html
/stoplight
/elements

# Misc / dev-leftover
/actuator
/actuator/openapi
/actuator/mappings
/q/openapi
/q/swagger-ui
/docs/swagger.json
/api/v1/docs
/api/v2/docs
/internal/swagger
/admin/swagger
/management/swagger
```

# After live-hosts.txt is built (Phase 1 / 2), run:
ffuf -w swagger-paths.txt -u "https://FUZZ.target.com" -mc 200,302 -fs 0 -t 50 -o swagger-hits.json

# Or with httpx for content-aware filtering:
httpx -l live-hosts.txt -path swagger-paths.txt -mc 200 -mr "swagger|openapi" -json | tee swagger-hits.jsonl

# For every hit:
jq '.paths | keys' swagger.json > endpoints.txt
jq '.components.schemas' swagger.json > schemas.json   # mass-assignment field candidates
```

### Why this matters for recon-to-hunting handoff

- **Spec → mass IDOR/BOLA** — `jq '.paths | keys' swagger.json` becomes the input list for `Autorize`/`ffuf` per-user testing.
- **Spec → mass-assignment payload construction** — `components.schemas.UserUpdateDto` enumerates `isAdmin`, `emailVerified`, `tenantId`, `role`.
- **Spec → hidden endpoint discovery** — `/internal/*`, `/debug/*`, `/v0/*`, `/legacy/*` routes documented but never auth-gated.
- **Spec → injection-class seeding** — every parameter's type + format + enum + max-length means payloads pass validation before reaching the sink. Especially valuable against ASP.NET Core where the model binder rejects malformed input before any controller logic.

### Tools

- `kiterunner` — natively ingests OpenAPI spec, generates requests against the API.
- `sj` (Swagger Jacker) — purpose-built for Swagger spec exploitation.
- `apidetector` (brinhosa) — Swagger-UI mass scanner.
- `XSSwagger` (vavkamil) — detects vulnerable Swagger UI versions (CVE-2018-25031 family).
- `nuclei -t http/exposures/apis/` — built-in templates for default spec paths.

### Anti-pattern reminder

A 404/403 on `/swagger` does NOT mean no spec is exposed. Many .NET projects route the spec under `/api/swagger/v1/swagger.json` rather than `/swagger`. Always test the full path list, not just the root.

Full attack-chain analysis is in `hunt-api-misconfig` → `NSwag / Swagger / OpenAPI Spec Exposure`.

---

## Related Skills & Chains

- **`offensive-osint`** — When recon needs concrete probes / wordlists / regexes beyond the basic pipeline. Workflow primitive: this skill produces the URL set; `offensive-osint` provides the secret regexes, GraphQL/Swagger paths, and identity-fabric probes you apply to that URL set.
- **`osint-methodology`** — When you need a severity rubric for what you discovered. Workflow primitive: after recon outputs `subdomains.txt` / `live-hosts.txt` / `urls.txt`, score each asset against `osint-methodology`'s findings rubric to decide what gets a finding versus what stays in the asset graph.
- **`hunt-subdomain`** — When recon surfaces stale CNAMEs / dangling DNS. Workflow primitive: any subdomain in `subdomains.txt` whose CNAME points to S3 / GitHub Pages / Heroku / Shopify / Azure should auto-route to `hunt-subdomain` for takeover validation.
- **`security-arsenal`** — When the URL set is classified by `gf` and ready for active testing. Workflow primitive: `gf xss/ssrf/sqli/idor` output names become payload-class queries against `security-arsenal`'s payload library.
- **`bb-methodology`** — When recon completes and Phase 1 transitions to Phase 2 (Mapping). Workflow primitive: hand the live host + URL set back to `bb-methodology` Phase 2 for endpoint mapping and Phase 3 vulnerability discovery routing.

---

## Operator Notes (Claude-BugHunter)

> Engagement-derived + 2026-specific additions to the vendored foundation.
> Wisdom from real authorized engagements + Phase 2 verification across
> this repo's 31+ skill-area live tests. The upstream pipeline covers the WHAT;
> this layer covers the WHEN-IT-WORKS-vs-WHEN-IT-DOESN'T.

### Cross-TLD pivot discipline

Phase 2C's HackerOne VDP recon walked from `hackerone.com` (24 subdomains) into a sister TLD `hacker.one` (12 more subdomains found in JS bundle references). Operators who only enumerate `*.target.com` miss attack surface that the target legitimately operates on a different domain.

Always grep JS bundles for plausible sibling TLDs:

```bash

# pull all JS, grep for sibling-TLD candidates
for url in $(cat live-hosts.txt); do
  curl -s "$url" | grep -oE 'src="[^"]+\.js"' | sed 's/src="//;s/"//'
done | sort -u > js-urls.txt

# then on each JS file
for j in $(cat js-urls.txt); do
  curl -s "$j" | grep -oE '[a-z0-9.-]+\.(io|app|one|dev|test|cloud|ai|co)' | sort -u
done | sort -u > sibling-tld-candidates.txt
```

Common sibling-TLD patterns: `target.com → target.io / target.app / target.one / target.dev / target.test / target-corp.com / target-cdn.net`. Always validate via WHOIS or by checking if the cert chain trusts the same internal CA before treating the sister TLD as in-scope.

### Subdomain wordlist priorities by 2026

Top discovery prefixes by hit rate against enterprise VDPs in our 2024-2026 corpus:

```
mta-sts.*          api.*              docs.*
dev-*              staging-*          *-qa
*-stage            *-uat              events.*
portal.*           customer.*         partner.*
vendor.*           internal-*         admin-*
employee-*         hr.*               jobs.*
sso.*              auth.*             id.*
```

Internal-looking subdomains often expose more surface than the marketing site — `partner.target.com` and `vendor-portal.target.com` frequently have weaker auth than the main app because they're scoped for "trusted" external users. Always send a probe to the long-tail wordlist after the standard subfinder run completes.

### Live-host probe: how to fingerprint stack quickly

`curl -sI <host>` headers are 80% of the fingerprint:

- `Server:` — apache / nginx / cloudflare / kestrel (= .NET Core) / openresty / envoy
- `X-Powered-By:` — PHP version, ASP.NET version, Express.js
- `X-Drupal-Cache`, `X-Generator: Drupal 9` — Drupal
- `X-Generator: WordPress` — WordPress
- `Via:` — CDN chain (1.1 varnish, 1.1 cloudfront)
- `Set-Cookie:` names — `JSESSIONID` (Java), `PHPSESSID` (PHP), `ASP.NET_SessionId` (.NET), `connect.sid` (Express), `laravel_session` (Laravel)

JS bundle filename patterns:

- `/_next/static/` = Next.js
- `/_nuxt/` = Nuxt
- `/assets/static/` with hash filenames = Vite
- `/static/js/main.*.chunk.js` = Create React App
- `runtime.*.js + polyfills.*.js + main.*.js` = Angular CLI

The first 10s of recon should yield a stack guess; the rest is targeting. If your fingerprint contradicts itself (Server says nginx, Set-Cookie says ASP.NET) you've found a reverse proxy front-end — note the origin app for later smuggling/cache attacks.

### GitHub Pages 404 vs takeover signal

Critical distinction operators get wrong:

- **"Page not found · GitHub Pages"** with HTTP 404 means the repo EXISTS — NOT a takeover.
- **"There isn't a GitHub Pages site here"** means the repo was deleted — TAKEOVER candidate.

Same distinction for CloudFront:

- **"Error - 404"** with `Server: CloudFront` = distribution exists, origin returned 404 — NOT a takeover.
- **"The request could not be satisfied"** with `X-Cache: Error from cloudfront` = origin missing entirely — potential takeover.

Phase 2C verified both patterns live. Always check the EXACT response body string before filing a takeover finding — the takeover-scanner tools (subzy, subjack) match on multiple fingerprints and frequently false-positive on the "still owned, just empty" case.

### Toolchain fallback

Already covered in this file's Phase 2C addition. Quick reminder: dnsx/httpx may segfault on macOS arm64; the dig+curl fallback works for < 100-host runs in ~14 seconds. Don't burn an hour debugging Go binary panics when the fallback gets you to the same URL set.
