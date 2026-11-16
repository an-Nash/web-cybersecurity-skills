---
name: hunt-osint-recon
description: Hunting skill for OSINT / reconnaissance — passive and active external attack-surface mapping, dork corpora, identity-fabric fingerprinting, breach/credential correlation, people OSINT, secret discovery and read-only validation, public SaaS surfaces, sector notes, recon tooling stack, confidence/scoring rubrics, and scope triage. Built from 21 curated source skills (0 bug-bounty reports read). Covers the web2-to-web3 methodology handoff and the recon-to-hunting pipeline. Full corpus archived at references/source-knowledge.md. Use when starting any external target, when handed an ASM/recon/breach export, or when you need to decide which discovered assets are actually owned before hunting them.
sources: curated_source_skills, public_osint_tooling, redteam_methodology
report_count: 0
full_reports_read: 0
source_skills: 21
---

## Crown Jewel Targets

OSINT/recon is highest-value when it finds a **trust boundary you can cross** — an asset the organization exposes but does not protect as an internal system. Priority targets, ordered by the payoffs observed across the curated source skills:

- **Identity fabric** — Entra/Azure AD, Okta, ADFS, Google Workspace, generic OIDC, SAML, Microsoft 365 deep surface (Teams federation, SharePoint, OneDrive, device-code endpoint). Compromising the IdP removes the need to break individual apps. Source: `hunt-skills/offensive-osint/references/identity-fabric.md`, `hunt-skills/osint-methodology/SKILL.md`.
- **Breach × identity correlation** — infostealer logs + HIBP + DeHashed + IntelX intersected with a discovered tenant → `SSO_EXPOSURE`. The highest-ROI single technique; severity CRITICAL at ≥10 employees. Source: `hunt-skills/osint-methodology/SKILL.md`.
- **Leaked credentials in code and build artifacts** — GitHub org secrets, npm/PyPI/Docker Hub package tarballs, CI build logs, public Postman workspaces, Stack Exchange code blocks. Source: `hunt-skills/bountyforge/references/recon-and-leaks.md`, `hunt-skills/offensive-osint/references/saas-public-surfaces.md`.
- **Exposed CI/CD and admin infrastructure** — Jenkins script console (= RCE), Grafana dashboards (contain DB queries, internal URLs, API keys), unauthenticated Kubernetes API (`:6443`), Spring actuators (`/actuator/env`, `/actuator/heapdump`). Source: `hunt-skills/bountyforge/references/hacking-agents/recon-agent.md`.
- **Listable cloud storage / open datastores** — S3/GCS/Azure Blob buckets, Firebase RTDB (`/.json`), Elasticsearch (`/_cat/indices`), MongoDB, Redis, Docker API (`:2375`). Full data exposure; frequently writable.
- **Dangling cloud assets / stale CNAMEs** — subdomains pointing at unclaimed Heroku/GitHub Pages/S3/Azure/Netlify/Fastly/Vercel → takeover → phishing on a trusted domain. Source: `hunt-skills/offensive-osint/references/probes-and-wordlists.md`.
- **API specs and GraphQL** — Swagger/OpenAPI specs (complete attack map), GraphQL introspection, Postman collections. Every parameter becomes a payload-shaped input.
- **Mobile apps and their backends** — APK static analysis → endpoints, secrets, Firebase project IDs, manifest misconfigs (`android:debuggable=true` = CRITICAL). Source: `hunt-skills/osint-methodology/SKILL.md`.
- **Public collaboration surfaces** — Trello, Notion, Confluence, Miro boards holding SOPs, seed creds, architecture diagrams.
- **Web3 contract surfaces** — unverified bytecode, EOA `proxyAdmin`, near-zero timelock delay, deployed bytecode ≠ audited commit hash. Source: `hunt-skills/bountyforge/references/hacking-agents/recon-agent.md`.

Severity anchors (from `hunt-skills/offensive-osint/references/severity-matrix.md`): CRITICAL = `.git`/`.env` exposed, listable bucket with PII, `/actuator/env` or heapdump, open Elasticsearch/MongoDB/Redis/Docker API, live-validated broad-scope key, ≥10 breached employees under a known tenant, KEV-matched appliance, open kubelet/etcd. HIGH = public repo secret, sourcemap, open GraphQL introspection, takeover candidate, reflected CORS with credentials, exposed Jenkins/Tomcat manager, `p=none` DMARC. MEDIUM = internal hostname/IP in JS, `/server-status`, permissive SPF, leaked Slack webhook. LOW/INFO = `.DS_Store`, Stripe test key, private bucket, `security.txt`.

---

## Attack Surface Signals

### Technology Fingerprinting (fast, passive)

| Signal | Technology |
|---|---|
| Cookie `XSRF-TOKEN` + `*_session` | Laravel |
| Cookie `PHPSESSID` | PHP |
| Header `X-Powered-By: Express` | Node.js/Express |
| Body `wp-json` / `wp-content` | WordPress |
| Body `{"errors":[{"message":` | GraphQL |
| Cookie `ARRAffinity` | Azure App Service |
| Header `cf-ray` | Cloudflare |
| Header `x-akamai-*` | Akamai |
| Set-Cookie `JSESSIONID` / `ASP.NET_SessionId` / `connect.sid` / `laravel_session` | Java / .NET / Express / Laravel |
| JS path `/_next/static/` / `/_nuxt/` / `/assets/static/` / `/static/js/main.*.chunk.js` | Next.js / Nuxt / Vite / CRA |

Source: `hunt-skills/bountyforge/references/recon-and-leaks.md`, `hunt-skills/web2-recon/SKILL.md` (operator notes).

### URL / Parameter Patterns to Hunt

```
[?&](id|user|file|path|url|redirect|next|src|token|key|api_key)=
/api/ | /v1/ | /v2/ | /v3/ | /graphql | /gql | /rest/ | /services/
/oauth | /login | /auth | /sso | /saml | /oidc | /callback | /token
/admin | /internal | /debug | /actuator | /console | /manager | /wp-admin
upload | file | attachment | document | image | avatar | photo | media
webhook | import | export | pdf | generate | fetch | proxy
search | filter | sort | order | where | query | list
\.env | \.git | config | backup | dump | export | download | log
```

### Response / Infrastructure Signals

```
Server: internal-service / kestrel / envoy / openresty
Via: 1.1 varnish / 1.1 cloudfront          → CDN chain
X-Cache: MISS from <origin-host>            → origin leak
X-Powered-By / X-AspNet-Version / X-Generator → framework + version
X-Drupal-Cache / X-Generator: Drupal 9     → Drupal
X-Forwarded-For echoed back                 → trust boundary
```

High-risk services from Shodan InternetDB (free, 1 req/s) — escalate one tier when `vulns[]` is present: `445` SMB, `2375` Docker API, `3389` RDP, `6379` Redis, `9200` Elasticsearch, `9300` ES transport, `27017` MongoDB, `5984` CouchDB, `5601` Kibana, `6443` K8s API, `10250` kubelet, `2379` etcd, `161` SNMP, `389` LDAP, `873` rsync, `1433` MSSQL, `3306` MySQL, `5432` PostgreSQL, `8888` Jupyter, `9090` Cockpit/Prometheus. Source: `hunt-skills/offensive-osint/references/probes-and-wordlists.md`.

### Stack → Bug-Class Map

| Stack | Hunt First | Hunt Second |
|---|---|---|
| Ruby on Rails | Mass assignment | IDOR (`:id` routes) |
| Django | IDOR (no object perms) | SSTI (`mark_safe`) |
| Flask | SSTI (`render_template_string`) | SSRF (`requests`) |
| Laravel | Mass assignment (`$fillable`) | IDOR |
| Express | Prototype pollution | Path traversal |
| Spring Boot | Actuator endpoints | SSTI (Thymeleaf) |
| ASP.NET | ViewState deserialization | Open redirect (`ReturnUrl`) |
| Next.js | SSRF via Server Actions | Open redirect via `redirect()` |
| GraphQL | Introspection → mutation auth bypass | IDOR via `node(id:)` |
| WordPress | Plugin SQLi | REST API auth bypass |

### Always-On Misconfiguration Checks

`/.git/config` (CRITICAL), `/.env` (CRITICAL), `/actuator/env` + `/actuator/heapdump` (CRITICAL), `/_cat/indices` (HIGH), `/phpinfo.php` (HIGH), `/script` Jenkins console (HIGH), `/manager/html` (HIGH), `/server-status` (MEDIUM), `/server-info` (MEDIUM), `/.DS_Store` (LOW), `/wp-admin/install.php` (LOW), `/.well-known/security.txt` (INFO). Parse `/robots.txt` `Disallow:` paths as a per-target wordlist. Source: `hunt-skills/offensive-osint/references/probes-and-wordlists.md`, `hunt-skills/bountyforge/skills/web2-recon/SKILL.md`.

### Infrastructure Hunting Commands

```bash
# Exposed CI/CD — Jenkins often needs no auth; script console = RCE
curl -s "https://jenkins.target.com/api/json" | jq '.jobs[].name'
curl -s "https://jenkins.target.com/script"          # Script Console = RCE
for sub in jenkins ci build buildkite travis drone; do
  curl -s -o /dev/null -w "$sub: %{http_code}\n" "https://$sub.target.com/"
done

# Exposed Grafana — dashboards contain DB queries, internal URLs, API keys
curl -s "https://grafana.target.com/api/search" | jq '.[].title'
curl -s "https://grafana.target.com/api/dashboards/db/home" \
  | jq '.dashboard.panels[].targets'

# Exposed Kubernetes API — 200 on secrets = full cluster access, no auth
curl -sk "https://target.com:6443/api/v1/namespaces"
curl -sk "https://target.com:6443/api/v1/pods"
curl -sk "https://target.com:6443/api/v1/secrets"

# Spring actuators — filter env for secrets; heapdump holds cleartext creds
curl -s "https://target.com/actuator/env" \
  | jq '.propertySources[].properties | to_entries[] | select(.key | test("password|secret|key"))'
curl -s "https://target.com/actuator/heapdump" -o heapdump   # analyze for secrets

# Leaked certs in git history → internal services (Phabricator/Confluence/Jira)
# Internal wikis often hold architecture docs, credentials, API keys
```
Source: `hunt-skills/bountyforge/references/hacking-agents/recon-agent.md`.

---

## Discovery Patterns From Curated Source Skills

### Where Researchers Start

1. **Scope check first.** Ask once if authorization is not established; proceed once asserted. Never act outside documented scope. Source: `hunt-skills/osint-methodology/SKILL.md` §1.
2. **Ownership triage before testing.** For dictionary-word brands, most scanner "owned" assets are collisions — repos, buckets, apps, combos that merely share the word. Confirm the canonical owned-domain set, then verify each asset class. Source: `hunt-skills/recon-scope-triage/SKILL.md`.
3. **5-stage pipeline** (`osint-methodology/SKILL.md` §7): Seed Discovery → Asset Expansion → Enrichment → Exposure Analysis → Reporting. Modules within a stage run concurrently; stages are sequential.
4. **Priority order when budget is tight** (§7.5): breaches → GitHub recon → Nuclei misconfig sweep → cloud buckets → ports → email OSINT → web tech/WAF/screenshots → Wayback → DNS deep + email security → certificates → ASN/reverse DNS → WHOIS → typosquat → headers.
5. **Time budgets** (§7.6): 1h rapid (seed + passive subs + Shodan InternetDB + email harvest + breach lookup), 4h phish-readiness (adds LinkedIn, SPF/DMARC, typosquats, IdP), 1d standard, 1w deep (adds deep user-enum, JS deep, mobile, cloud-native, package-registry, CVE prioritization).
6. **5-minute rule** (`web2-recon/SKILL.md`, `bountyforge/skills/web2-recon/SKILL.md`): if a target shows nothing interesting after 5 minutes, move on. Kill signals: all 403/static, no APIs, no interesting JS, no forms/auth/user data.
7. **Target scoring GO/NO-GO** (`web2-recon/SKILL.md`): max bounty ≥ $5K +2, large user base/handles money +2, program < 60 days +2, complex features +1, recent code changes +1, private program +1, known stack +1, source available +1, prior disclosed reports +1. `<4` skip, `4–5` only if nothing better, `6–8` 1–3 days, `≥9` up to 1 week. Hard kills: max bounty < $500, all recent reports N/A/duplicate, static-page-only scope, <5 employees with no revenue, planned class explicitly excluded.
8. **Scale-based tactics** (`osint-methodology/SKILL.md` §10.1): small org → deep on every email/identity finding; large org → breadth-first automation, manual triage; conglomerate → scope pruning + brand-domain mapping first.
9. **Asset graph discipline** (§8): every discovery is a typed asset (29 types) with `key`, `sources[]`, `confidence`, timestamps; dedup by key not value; typed edges (`RESOLVES_TO`, `BREACHED_FROM`, `CONTAINS_SECRET`, …). Late-bind via JSON sidecars.

### Feature-Based Discovery Signals

Map each observed feature to the asset class it creates and the finding it can become:

| Feature / source | Discovery signal | Likely finding |
|---|---|---|
| `auth./login./sso./idp./iam./identity./accounts./oauth.` subdomains | IdP presence | Identity fabric asset → `SSO_EXPOSURE` on breach correlation |
| `/.well-known/openid-configuration` on any host | `issuer` fingerprints product + tenant GUID | Tenant mapped; device-code endpoint → MEDIUM |
| `SharePoint -my/-admin` subdomains, OneDrive `/personal/` | M365 tenancy | INFO tenant; anonymous-share link via dork → HIGH |
| Swagger path hit (`/swagger/v1/swagger.json`, `/v3/api-docs`, `/docs`, …) | Full endpoint map | HIGH `LEAKY_API_SPEC`; mass IDOR / mass-assignment seeding |
| GraphQL path hit + introspection returns | Full schema | HIGH `OPEN_GRAPHQL_API`; disabled introspection → field-suggestion enum (MEDIUM) |
| `.js` / `.js.map` with `sourcesContent[]` | Endpoints + secrets + internal hosts | HIGH `INFO_DISCLOSURE` / `SECRET_LEAK`; internal IP → MEDIUM |
| GitHub org repo with `.env`, `AKIA`, `ghp_` | Credential leak | HIGH/CRITICAL `SECRET_LEAK`; live AWS key → CRITICAL |
| npm/PyPI/Docker package tarball | Accidental secret inclusion | Secret by catalog severity; publish-scope token → CRITICAL |
| CI build log echoing token | Secret-in-log | HIGH (`recon-and-leaks.md`) |
| Cloud bucket permutation returns 200/301/403 | Bucket exists | Listable → CRITICAL; object-read-only → HIGH; private → INFO |
| Firebase `https://<project>.firebaseio.com/.json` | Open RTDB | CRITICAL |
| Dangling CNAME to Heroku/GitHub Pages/S3/Azure | Takeover candidate | HIGH takeover |
| Job postings naming Workday/Salesforce/Snowflake | SaaS tenants + tech stack | Tech-stack profile → which secret patterns/probes to run |
| LinkedIn employees + derived emails | Phishing list + breach input | Role-tiered target list; breach hits → `SSO_EXPOSURE` |
| SPF includes / MX / DMARC `rua=` | SaaS tenants, spoof posture | `p=none` → MEDIUM; vendor + internal mailbox leak |
| Public Trello/Notion/Confluence/Miro | Docs with seed creds | MEDIUM–HIGH depending on content |
| Job posts / press releases / sat imagery (sector) | Physical + org intel | Sector escalation: PHI/SWIFT/ICS → CRITICAL (caution on ICS) |
| Unverified contract / EOA proxyAdmin / 0 timelock | Web3 governance risk | Web3 methodology handoff (see `specialized-osint.md`) |

### Verbatim Hunter Clues

Short, directly-grounded rules from the source skills — keep these in mind while triaging:

- "Every endpoint is a trust boundary. Find them all." — `hunt-skills/bountyforge/skills/web2-recon/SKILL.md`.
- "Ownership is guilty-until-proven. An asset is the target's only when a concrete ownership signal ties it to the target — never because a scanner's keyword matched." — `hunt-skills/recon-scope-triage/SKILL.md`.
- "Snippet-only match = TENTATIVE (operator must visit URL to confirm)." — `hunt-skills/offensive-osint/references/dork-corpus.md`.
- "Rule of three for attribution: require three independent weak signals, OR one strong + one weak. Don't single-source attribute." — `hunt-skills/osint-methodology/SKILL.md` §2.
- "Default reporting posture: never claim CONFIRMED without explicit corroboration. When in doubt, downgrade. Operators trust under-claims more than over-claims." — `osint-methodology/SKILL.md` §2.1.
- "SharePoint HEAD HTTP 200 = tenant exists, NOT anonymous access granted (operators commonly misread)." — `hunt-skills/offensive-osint/SKILL.md` changelog / `identity-fabric.md`.
- "If a target shows nothing interesting after 5 minutes of recon, move on." — `web2-recon/SKILL.md`.
- "Origin IP found via DNS history: TENTATIVE until corroborated by direct probe." — `osint-methodology/SKILL.md` §27.8.
- "A 404/403 on `/swagger` does NOT mean no spec is exposed." — `hunt-skills/web2-recon/SKILL.md`.
- "**'Page not found · GitHub Pages'** with HTTP 404 means the repo EXISTS — NOT a takeover. **'There isn't a GitHub Pages site here'** means the repo was deleted — TAKEOVER candidate." — `web2-recon/SKILL.md` operator notes.
- "Passive by default. Active probes only when (a) explicitly authorized, (b) within agreed maintenance windows, and (c) with the operator's awareness of the resulting log volume." — `osint-methodology/SKILL.md` §6.2.
- "Never paste creds, session tokens, API keys, real PII, infostealer logs, or unique pivots into cloud-hosted LLMs. Use local models for sensitive analysis." — `osint-methodology/SKILL.md` §5.
- "Most external recon techniques apply universally… the targeted services differ." — `hunt-skills/offensive-osint/references/sector-notes.md`.

### Probe Checklist

**Quick wins (check every target)** — from `recon-and-leaks.md`:
```
[ ] Subdomain takeover (subjack, subzy)
[ ] Exposed .git (/.git/config)
[ ] Exposed env files (/.env, /.env.local)
[ ] Default credentials on admin panels
[ ] JS secrets (SecretFinder, jsluice)
[ ] Open redirects (?redirect=, ?next=, ?url=)
[ ] CORS misconfig (Origin: https://evil.com + credentials)
[ ] S3/cloud buckets
[ ] GraphQL introspection enabled
[ ] Spring actuators (/actuator/env, /actuator/heapdump)
[ ] Firebase open read (/.json)
[ ] Hardcoded API keys in JS bundles
[ ] Credentials in public Git repos (GitHub, GitLab, Bitbucket)
[ ] Exposed CI/CD dashboards (Jenkins, CircleCI, Travis CI)
```

**Ownership + soft-404 control (before any active probe)** — from `recon-scope-triage/SKILL.md`:
```
[ ] Canonical owned-domain set confirmed (SOW/program domain + verified subs + tenant brand)
[ ] Each asset class verified by its verify-by rule; unknowns quarantined
[ ] Junk-path control run for every automated "Critical" (.env/.git/actuator/admin)
       cmp -s /tmp/a /tmp/b && echo "SOFT-404 false positive" || echo "differs — investigate"
[ ] Severity counts re-baselined against only-owned assets
```

**Enrichment probes** — SSO prefixes (`auth login sso idp iam identity accounts oauth`), SAML metadata paths, 28 Swagger paths, 13 GraphQL paths, cloud-bucket permutations, JS guess-paths + `.map`, high-risk ports, security headers, TXT verification tokens, Wayback CDX, email security (SPF/DMARC/DKIM/BIMI/MTA-STS/TLS-RPT/DNSSEC).

**Exposure + correlation probes** — secret catalog over JS/repos/packages/pastes; 9 read-only validators; breach sources (HudsonRock Cavalier, HIBP, DeHashed, IntelX); identity-fabric OIDC endpoints; Postman public workspace search; Stack Exchange sweep; job-posting harvest.

---

## Step-by-Step Hunting Methodology

1. **Establish authorization and mode.** Recon-only vs bug-bounty; ask once if unclear. Record rules of engagement, in-scope list, safe harbor, accepted impact types, average bounty. Source: `osint-methodology/SKILL.md` §1, §10; `web2-recon/SKILL.md` minutes 0–5.

2. **Triage ownership before spending probes.** Confirm the canonical domain set; verify each asset class against its ownership signal; quarantine collisions to `loot/quarantined_<source>.txt`; re-baseline "Critical" counts and surface the meta-finding if the feed is mostly noise. Source: `recon-scope-triage/SKILL.md`.

3. **Stage 1 — Seed discovery.** WHOIS, ASN enumeration (HE BGP Toolkit / RIPEstat / BGPView), DNS records A/AAAA/MX/TXT/NS/SOA/CAA (records only), CT history (crt.sh). `dig @<ns> <domain> AXFR` opportunistically — most reject; those that don't = full zone disclosure (CRITICAL).

4. **Stage 2 — Asset expansion.** Passive subdomain sources first (crt.sh, VirusTotal, OTX, Shodan, Subfinder/Amass); then permutations/bruteforce (puredns + Assetnote wordlists); cloud buckets (6 prefixes × 15 suffixes × target stems); typosquats (dnstwist); Wayback CDX; mobile apps (Google Play scraper / iTunes API); LinkedIn employee enum → email patterns. Cross-TLD pivot: grep JS for sibling TLDs (`target.com → target.io/.app/.one/.dev`) and validate via WHOIS/cert chain. Source: `web2-recon/SKILL.md` operator notes.

5. **Stage 3 — Enrichment.** Resolve + live-check (dnsx → httpx with `-sc -title -tech-detect -ip -cdn`); port/service (Shodan InternetDB free → naabu if authorized); TLS handshake (JARM, cert SHA256, favicon mmh3); WAF/CDN inference; origin discovery if behind CDN; security-header audit; bulk screenshots; email harvest + email security audit; GitHub code-search dorks; JS deep analysis; SSO/IdP fingerprinting; Swagger/GraphQL/Postman discovery; secrets-beyond-GitHub sweep; vendor product fingerprints; CI/CD and cloud-native exposure; job-posting harvest.

6. **Stage 4 — Exposure analysis.** Nuclei (15 always-on checks + templates); TLS deep audit (sslyze/testssl.sh); breach × identity correlation; targeted misconfig probes; secret validation (read-only); CVE prioritization (CISA KEV +50, EPSS ≥0.7 +30, Metasploit +25, public POC +15, unauth +20 → P0 ≥100). Source: `osint-methodology/SKILL.md` §28.

7. **Run dork corpora multi-engine.** 80+ templates across 9 categories + 13 GitHub code-search dorks. Wrap each engine (DDG default, Bing/Brave/Yandex/Baidu/SerpAPI) behind a common interface with a per-engine token bucket; dedup by URL; classify URL-signature → title-hint → snippet-regex; snippet-only = TENTATIVE; archive ephemeral results. Source: `offensive-osint/references/dork-corpus.md`, `osint-methodology/SKILL.md` §24.3.

8. **Validate credentials read-only.** For each discovered secret, use only `/me`, `whoami`, `auth.test`, `sts:GetCallerIdentity`, `/v1/models`; record UTC `checked_at`, truncated response, scope/account ID; tag detectability; never create/modify/delete/send. Source: `osint-methodology/SKILL.md` §6.3, `offensive-osint/SKILL.md`.

9. **Correlate breach × identity.** Resolve IdP tenants; intersect tenant domains with breach corpus; non-empty intersection → `SSO_EXPOSURE` CRITICAL with tenant ID + product + employee count. Domain-level severity: ≥10 employees CRITICAL, 1–9 HIGH, ≥1 end-user MEDIUM, 0 named accounts INFO. Source: `osint-methodology/SKILL.md` §22.

10. **Classify endpoints by interest score (0–100).** Unauth write +40, open introspection +35, verb tampering +30, reflected CORS+creds +25, sensitive keyword +20, schema leak in error +20, API key in URL +15, wildcard CORS +10, missing rate-limit +10. ≥90 CRITICAL, 70–89 HIGH, 50–69 MEDIUM, 25–49 LOW, <25 INFO. Attach a one-sentence `attack_path_hint` for score ≥70. Source: `offensive-osint/SKILL.md` §20, §39.

11. **Hand off by asset type.** Stale CNAME → `hunt-subdomain`; bucket/actuator/Firebase → `hunt-cloud-misconfig`; API host passing ownership → `hunt-spa-api` / `hunt-api-misconfig`; matched IdP → `m365-entra-attack` / `okta-attack`; URL set with classified params → `security-arsenal` payload classes; recon complete → `bb-methodology` Phase 2. Web3 targets (contracts/explorers) → `specialized-osint.md` §30 + web3 methodology.

12. **Report.** Per-finding schema with `id/module/asset_key/category/severity/confidence/evidence (url+UTC+sha256+raw≤2KiB)/references/remediation`; exec summary + risk-translation matrix; reproduction package (`run_id`, tool versions, JSONL log, SQLite asset/finding DB, PNG screenshots). Apply Gate 0 before submitting. Source: `osint-methodology/SKILL.md` §3, §4, §31.

13. **Detectability discipline throughout.** Tag each operation Low/Medium/High; on detection signs (429, captcha, WAF page, status drift, banner change, NXDOMAIN poisoning, honeypot bait, direct contact) follow the back-off ladder: slow → switch endpoint → switch persona → switch IP → pause → consult lead. Do not try to outsmart a confirmed WAF block or evade an explicit block-list. Source: `osint-methodology/SKILL.md` §6.4.

---

## Payload & Detection Patterns

### Dork Corpus (9 categories)

Substitute `{domain}` (root domain) and `{company}`; run across Google, Bing, Brave, DuckDuckGo, Yandex, Baidu.

```
# Files
site:{domain} filetype:env
site:{domain} ext:env OR ext:ini OR ext:cfg OR ext:conf
site:{domain} ext:sql OR ext:sqlite OR ext:dump OR ext:bak
site:{domain} ext:pem OR ext:key OR ext:p12 OR ext:pfx
site:{domain} ext:log
site:{domain} inurl:.git OR inurl:/.git/
site:{domain} intitle:"index of"

# Admin / login panels
site:{domain} inurl:admin OR inurl:login OR inurl:sso OR inurl:dashboard
site:{domain} intitle:"phpMyAdmin" | intitle:"Jenkins" | intitle:"Grafana"
site:{domain} intitle:"Kibana" | intitle:"Splunk" | intitle:"Swagger"
site:{domain} inurl:phpinfo

# Secrets / credential leakage
"{domain}" ("api_key" OR "apikey" OR "access_token")
"{domain}" (password OR passwd OR pwd)
site:pastebin.com "{domain}"
site:ghostbin.com "{domain}"
site:rentry.co "{domain}"
site:gist.github.com "{domain}"
site:hastebin.com "{domain}"
"{domain}" "BEGIN RSA PRIVATE KEY"

# Cloud / CI / shadow IT
site:s3.amazonaws.com "{domain}"
site:storage.googleapis.com "{domain}"
site:blob.core.windows.net "{domain}"
site:*.atlassian.net "{domain}"
site:dev.azure.com "{domain}"
site:firebaseio.com "{domain}"
site:herokuapp.com "{domain}"

# Docs / intel mining
site:{domain} filetype:pdf (confidential OR internal OR restricted)
site:{domain} filetype:xlsx OR filetype:csv
"{company}" filetype:pdf (salary OR payroll OR org-chart)
site:linkedin.com/in "{company}"
site:slideshare.net "{company}"

# Vuln indicators
site:{domain} intext:"sql syntax" OR intext:"you have an error in your sql"
site:{domain} intext:"Warning: mysql_"
site:{domain} intext:"stack trace" OR intext:"Traceback (most recent call last)"
site:{domain} inurl:wp-content OR inurl:wp-includes

# Internal tool exposure
site:{domain} intitle:"Splunk" | "Grafana" | "Kibana" | "Prometheus Time Series"
site:{domain} intitle:"Jaeger UI" | "AlertManager" | "Argo CD" | "Sonarqube"
site:{domain} intitle:"Sentry" | "Confluence" | "Jira" | "GitLab" | "Gitea"
site:{domain} inurl:"/jenkins/"

# Backup / dump extensions
site:{domain} ext:bak OR ext:backup OR ext:old OR ext:orig OR ext:save OR ext:swp
site:{domain} ext:tar OR ext:tar.gz OR ext:tgz OR ext:zip OR ext:rar
site:{domain} ext:db OR ext:sqlite OR ext:mdb OR ext:dump OR ext:bson
site:{domain} (intext:"-- MySQL dump" OR intext:"PostgreSQL database dump")
site:{domain} ext:pcap OR ext:pcapng OR ext:core OR ext:hprof

# Sector-specific
site:{domain} (filetype:pdf OR filetype:xlsx) (HIPAA OR PHI OR "patient records")
site:{domain} ("DICOM" OR "HL7" OR "ICD-10")
site:{domain} ("SWIFT" OR "BIC" OR IBAN OR "wire transfer")
site:{domain} (filetype:pdf OR filetype:doc) (FOUO OR "controlled unclassified" OR CUI)
```

**GitHub code-search dorks (13)** — needs a PAT (fine-grained read-only recommended), concurrency ≤5:
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
"@{domain}" password
```
For each hit: fetch via Contents API, run secret catalog, emit `SECRET_LEAK` with repo + path + last 4 chars only; optionally clone and run `trufflehog`/`gitleaks` over full history. Source: `offensive-osint/references/dork-corpus.md`.

### Standard Recon Pipeline

```bash
TARGET="target.com"; RECON_DIR="recon/$TARGET"; mkdir -p $RECON_DIR

# 1. Passive subdomain enum
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > /tmp/subs.txt

# 2. Multi-source
curl -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" \
  -H "Authorization: $CHAOS_API_KEY" | jq -r '.[]' >> /tmp/subs.txt
subfaster -d $TARGET -silent | anew /tmp/subs.txt
# or: subfinder -d $TARGET -all -recursive -silent | anew /tmp/subs.txt

# 3. DNS + live check
cat /tmp/subs.txt | dnsx -silent | httpx -silent -status-code -title -tech-detect | tee /tmp/live.txt

# 4. URL crawl + archive
cat /tmp/live.txt | awk '{print $1}' | katana -d 3 -jc -kf all -silent | anew /tmp/urls.txt
echo $TARGET | waybackurls | anew /tmp/urls.txt
gau $TARGET --subs | anew /tmp/urls.txt

# 5. Nuclei
nuclei -l /tmp/live.txt -t ~/nuclei-templates/ -severity critical,high,medium -o /tmp/nuclei.txt

# 6. Save organized evidence
cp /tmp/subs.txt $RECON_DIR/subdomains.txt
cp /tmp/live.txt $RECON_DIR/live-hosts.txt
cp /tmp/urls.txt $RECON_DIR/urls.txt
cp /tmp/nuclei.txt $RECON_DIR/nuclei.txt
```
Source: `hunt-skills/bountyforge/skills/web2-recon/SKILL.md`, `hunt-skills/web2-recon/SKILL.md`.

crt.sh 502 fallback chain (try in order, don't retry-loop): Censys cert search → Cert Spotter API → CertStream archive (Calidog) → `subfinder -all -recursive` → AlienVault OTX passive DNS → ThreatMiner → URLScan → Anubis-DB. Source: `offensive-osint/references/recon-stack.md` §27.0.1.

### Wordlists & Probe Paths

```
# Swagger/OpenAPI — 28 paths (sample)
swagger.json  swagger/v1/swagger.json  swagger-ui.html  api-docs
v2/api-docs   v3/api-docs  openapi.json  openapi.yaml  docs redoc
/.well-known/openapi  /api/swagger/v1/swagger.json  /actuator/openapi
# GraphQL — 13 paths
graphql graphiql api/graphql v1/graphql v2/graphql query gql altair
playground subscriptions graphql/console api/v1/graphql
# SAML metadata — 5 paths
/saml/metadata  /FederationMetadata/2007-06/FederationMetadata.xml
/simplesaml/saml2/idp/metadata.php  /auth/saml2/metadata
# SSO prefixes — 8
auth login sso idp iam identity accounts oauth  (+ OIDC on every alive host)
# JS guess-paths
/main.js /app.js /bundle.js /runtime.js /_next/static/_buildManifest.js
/static/js/main.js /assets/index.js  then try <jsfile>.map
# Cloud bucket arsenal
6 prefixes: "" backup- assets- static- dev- prod-
15 suffixes: "" -backup -assets -static -media -data -uploads -dev -prod
             -staging -logs -private -public -dump -archive
47 stems: www mail email app web cdn static assets media img download upload
          data files docs support blog dev test staging qa uat sandbox vpn mx smtp…
```
Sources: `offensive-osint/references/probes-and-wordlists.md` §16.1–16.9, `web2-recon/SKILL.md` Swagger section.

Subdomain wordlist sources: Assetnote Wordlists (best-curated), SecLists (`subdomains-top1million-110000.txt`), jhaddix all.txt, OneListForAll, dirsearch, raft-large-words, bo0om, commonspeak2, fuzzdb, PayloadsAllTheThings. Size guidance: <10k fast, 10k–100k standard, 100k–1M thorough, >1M exhaustive. Source: `offensive-osint/references/recon-stack.md` §27.1.

### Cloud Bucket Probe Commands

```bash
B="candidate-bucket-name"
# S3 — HEAD first: 200/301 exists, 403 exists+private, 404 skip
curl -sk -m 10 -I "https://${B}.s3.amazonaws.com/" -w 'STATUS:%{http_code}\n' | head -20
curl -sk -m 10 "https://${B}.s3.amazonaws.com/?list-type=2" | head -50   # list objects
for r in us-east-1 us-west-2 eu-west-1 ap-southeast-1; do
  curl -sk -m 10 -I "https://${B}.s3-${r}.amazonaws.com/" -w "${r}: %{http_code}\n"
done
curl -sk -m 10 -I "https://${B}.s3.amazonaws.com/" -D - -o /dev/null | grep -i 'x-amz-bucket-region'
# GCS
curl -sk -m 10 -I "https://${B}.storage.googleapis.com/"
curl -sk -m 10 "https://storage.googleapis.com/${B}/"
# Azure Blob
curl -sk -m 10 -I "https://${B}.blob.core.windows.net/"
curl -sk -m 10 "https://${B}.blob.core.windows.net/?comp=list"
# cloud_enum / CloudSploit for broad permutation sweeps
```
Severity: listable bucket CRITICAL, direct-URL object reads but not listable HIGH, private (HEAD 403) INFO. Source: `offensive-osint/references/probes-and-wordlists.md` §16.8, `osint-methodology/SKILL.md` §15.

### People, Email & Breach Source Stack

```
# Email derivation + verification
Sherlock / Maigret (username) · Holehe (email registration) · Epieos (email pivots)
Hunter.io / RocketReach / Apollo (domain→emails + pattern guessing)
EmailRep / Emailable (reputation + verification) · PhoneInfoga (phone)
# People / social
TruePeopleSearch · WhitePages · Spokeo · Pipl · FaceCheck (reverse face)
snscrape (X/Twitter) · Picuki (Instagram) · Reveddit (removed Reddit) · Firesky (Bluesky)
# Company / registries
OpenCorporates · SEC EDGAR · UK Companies House · OpenSanctions · OCCRP Aleph
CN: GSXT → ICP (beian.miit.gov.cn) → USCC (18-char entity ID) → GSXT entity + officers
# Breach sources (highest ROI)
Hudson Rock Cavalier (FREE infostealer logs) · HIBP (+ Pwned Passwords)
DeHashed (paid per-record API) · IntelX (aggregator/phonebook) · local corpus
# HudsonRock direct API (curl + PowerShell recipes in the source skill)
```
Treat stealer logs as PII: encrypt at rest, SHA-256 every artifact, record source URL + acquisition timestamp, redact passwords in client reports, never paste plaintext into cloud LLMs. Email priority by role: `ceo/cfo/cto/ciso@` HIGHEST → `it/helpdesk/security@` HIGH → `dev/engineer/dba` MEDIUM → generic `info/noreply@` LOW. Source: `offensive-osint/references/people-osint.md`, `osint-methodology/SKILL.md` §22, §8.5.

### Mobile / APK Surface Probes

```bash
# Discover: google-play-scraper (Android) / iTunes Search API (iOS)
# Ownership score ≥70 before deep analysis: reverse-DNS package match +40, dev email +25,
#   dev website +20, brand keyword +10, ≥20 reviews +5
# APK: download via APKPure; unzip; extract AndroidManifest.xml, strings, assets, dex
# Secret catalog over manifest + resources + assets + dex strings → mobile_endpoints.json sidecar
# Firebase canonical probe
curl -sk "https://${PROJECT}.firebaseio.com/.json"        # open RTDB → CRITICAL
curl -sk "https://${PROJECT}.firebaseapp.com/"             # Firestore host
# Manifest misconfigs: debuggable=true CRITICAL; allowBackup/cleartext/exported MEDIUM;
#   sensitive deep link + WebView JS bridge HIGH; no cert pinning LOW
```
Source: `hunt-skills/osint-methodology/SKILL.md` §14, `hunt-skills/offensive-osint/SKILL.md` §21.

### Internal-Host Leakage & Sourcemap Detection

```regex
# RFC1918 in JS / sourcesContent / APK strings
\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3})\.(?:\d{1,3})|192\.168\.(?:\d{1,3})\.(?:\d{1,3})|127\.(?:\d{1,3}\.){2}\d{1,3})\b
# Internal DNS suffixes
\b[A-Za-z0-9][A-Za-z0-9\-]{0,62}\.(?:internal|corp|lan|intranet|local|prod|staging|dev|qa|test)\b
# Kubernetes service DNS
\b[A-Za-z0-9\-]+\.[A-Za-z0-9\-]+\.svc(?:\.cluster\.local)?\b
# sourcemap reference
//[#@]\s*sourceMappingURL=
```
Each RFC1918/DNS/K8s match = MEDIUM `INFO_DISCLOSURE`; aggregate matches sharing an internal subdomain as a seed for later phases. Sourcemap with `sourcesContent[]` = HIGH; parse `sources[]` for repo structure. Source: `offensive-osint/references/probes-and-wordlists.md` §16.11, `osint-methodology/SKILL.md` §13.

### Secret Patterns (catalog subset — full 48-pattern catalog in source skill)

```regex
\b(AKIA|ASIA)[0-9A-Z]{16}\b                          # AWS access key (CRITICAL)
(?i)aws[_\-]?secret[_\-]?access[_\-]?key['\"\s:=]+([A-Za-z0-9/+=]{40})
"type"\s*:\s*"service_account"                        # GCP SA (CRITICAL)
\bAIza[0-9A-Za-z_\-]{35}\b                           # Google API key (HIGH)
\bghp_[A-Za-z0-9]{36}\b                               # GitHub PAT classic (CRITICAL)
\bgithub_pat_[A-Za-z0-9_]{82}\b                       # GitHub fine-grained (CRITICAL)
\bsk_live_[0-9A-Za-z]{24,}\b                         # Stripe live (CRITICAL)
\bsk-ant-[A-Za-z0-9_\-]{10,}\b                       # Anthropic (CRITICAL live)
\bsk-[A-Za-z0-9]{20,}\b                              # OpenAI (CRITICAL live)
\bnpm_[A-Za-z0-9]{36}\b                              # npm token
\xox[abpors]-[0-9A-Za-z\-]{10,48}\b                  # Slack token (HIGH)
https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+
\b-----BEGIN (RSA |EC |OPENSSH |DSA |PGP |)PRIVATE KEY-----
\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}  # JWT
(?i)authorization['\"=: ]+bearer\s+[A-Za-z0-9._\-]{20,}
https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+                 # basic-auth URL
```
Run `python3 scripts/secret_scan.py <path>` (stdlib-only, JSONL output) — mirrors the catalog; also `trufflehog filesystem --only-verified`, `gitleaks`, `SecretFinder`, `jsluice`. Source: `offensive-osint/references/helpers-and-automation.md` §48, `recon-and-leaks.md`.

### Read-Only Secret Validators (9)

```bash
curl -sk -H "X-Api-Key: PMAK-..." https://api.getpostman.com/me | jq .           # Postman
python3 -c "import boto3; print(boto3.client('sts', aws_access_key_id='AKIA...', \
  aws_secret_access_key='...').get_caller_identity())"                          # AWS (CloudTrail log)
curl -sk -H "Authorization: token ghp_..." https://api.github.com/user -D /tmp/h \
  | jq -r '.login,.email'; grep -i 'X-OAuth-Scopes' /tmp/h                      # GitHub
curl -sk -H "Authorization: Bearer xoxb-..." -X POST https://slack.com/api/auth.test | jq .
curl -sk -H "x-api-key: sk-ant-..." -H "anthropic-version: 2023-06-01" \
  https://api.anthropic.com/v1/models | jq '.data | length'
curl -sk -H "Authorization: Bearer sk-..." https://api.openai.com/v1/models | jq '.data | length'
curl -sk -H "Authorization: Bearer npm_..." https://registry.npmjs.org/-/whoami | jq .
curl -sk -u "email:ATATT3xFfGF0_..." https://<domain>.atlassian.net/rest/api/3/myself | jq .
curl -sk -H "DD-API-KEY: ..." -H "DD-APPLICATION-KEY: ..." \
  https://api.datadoghq.com/api/v1/validate | jq .
```
Source: `offensive-osint/references/probes-and-wordlists.md` §16.13, `secret-validators.md` (indexed in `offensive-osint/SKILL.md`).

### Identity Fabric Probes

```bash
# Entra tenant GUID + managed/federated
curl -sk "https://login.microsoftonline.com/${DOMAIN}/.well-known/openid-configuration" | jq -r '.issuer'
curl -sk "https://login.microsoftonline.com/getuserrealm.srf?login=<user>@${DOMAIN}" | jq .
# Okta: <slug>.okta.com/.well-known/openid-configuration ; POST /api/v1/authn (deep)
# Generic OIDC: probe /.well-known/openid-configuration on every alive subdomain
# SAML: /saml/metadata, /FederationMetadata/2007-06/FederationMetadata.xml
# M365: SharePoint stems, OneDrive /personal/<email with @ . → _>, device-code endpoint
curl -sk "https://login.microsoftonline.com/${DOMAIN}/v2.0/.well-known/openid-configuration" \
  | jq '.device_authorization_endpoint'
# AWS account ID: ARN regex arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:([0-9]{12}):
# GraphQL field-suggestion when introspection is disabled:
curl -sk -X POST "$T/graphql" -H 'Content-Type: application/json' \
  -d '{"query":"{ usre { id } }"}' | jq -r '.errors[].message'
```
Detectability: low for OIDC/`getuserrealm`/autodiscover; medium (audit-logged) for `GetCredentialType`, Okta `/api/v1/authn`, validators — cap at 20 attempts per tenant. SharePoint HTTP 200 = tenant exists, not anonymous access. Source: `offensive-osint/references/identity-fabric.md`.

### Email Security Audit

```bash
dig +short TXT "$D" | grep -i 'v=spf1'          # -all strict / ~all soft / ?all permissive
dig +short TXT "_dmarc.${D}"                    # p=none → MEDIUM; p=reject+strict → OK
for s in default google selector1 selector2 mail k1 dkim s1; do
  dig +short TXT "${s}._domainkey.${D}"; done   # RSA-1024 → MEDIUM
dig +short TXT "_mta-sts.${D}"; curl -sk "https://mta-sts.${D}/.well-known/mta-sts.txt"
dig +short TXT "_smtp._tls.${D}"                # TLS-RPT
delv "${D}" 2>&1 | grep -i 'fully validated\|insecur'
dig +short MX "${D}"                            # aspmx.l.google.com → Google; *.outlook.com → M365
```
SPF `include:` values reveal SaaS tenants (Google, M365, Salesforce, Zendesk, SendGrid, Atlassian, AWS SES, Workday). DMARC `rua=` reveals vendors (dmarcian, Valimail, kdmarc, Agari) and sometimes an internal mailbox. Source: `offensive-osint/references/probes-and-wordlists.md` §16.14.

### Tooling Install

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest; nuclei -ut
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/d3mondev/puredns/v2@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/trufflesecurity/trufflehog@latest
git clone https://github.com/initstring/cloud_enum && cd cloud_enum && pip install -r requirements.txt
# macOS arm64 dnsx/httpx SIGSEGV fallback: dig + curl loop (finite for <100 hosts)
```
Source: `offensive-osint/references/tooling-install.md`, `web2-recon/SKILL.md`.

### Public SaaS Surfaces (Postman / Stack Exchange / docs)

```bash
# Postman public universal search (unauthenticated, verified endpoint shape)
curl -sk -m 15 "https://www.postman.com/_api/ws/proxy" \
  -H 'Content-Type: application/json' -H 'X-Entity-Team-Id: 0' \
  -d '{"service":"search","method":"POST","path":"/search-all","body":{
       "queryIndices":["collaboration.workspace","runtime.collection","runtime.request"],
       "queryText":"acme.com","size":100,"from":0,"clientTraceId":"",
       "queryAllIndices":false,"domain":"public"}}' | jq '.data[]'
# Per-workspace walk: /_api/workspace/<id>, /collection/<id> → requests, headers, scripts, env vars
# Ownership: request URLs containing *.target.com = strongest signal
# Run the secret catalog over every extracted text blob

# Stack Exchange sweep (8 high-signal sites)
# GET https://api.stackexchange.com/2.3/search/advanced?site=<site>&q=<target>&filter=withbody&pagesize=100
# Extract code blocks: <pre><code>([\s\S]*?)</code></pre> → run secret catalog
# Cross-reference author email against email OSINT; hostnames → subdomain assets
# Quota: 30 req/day keyless, 10,000/day with free key; 2s min interval

# Public collaboration dorks: site:trello.com / notion.so / *.atlassian.net / miro.com "{target}"
```
Common findings: public Trello board with credentials in card titles, Notion page with internal SOPs/API keys, Confluence onboarding docs with seed creds, Miro architecture diagrams with internal hostnames. Source: `offensive-osint/references/saas-public-surfaces.md`.

### Infrastructure & TLS Audit Recipes

```bash
# Bulk IP → ASN: Cymru bulk WHOIS (fastest, no key, no rate limit)
echo -e "begin\nverbose\n8.8.8.8\n1.1.1.1\nend" | nc whois.cymru.com 43
curl -sk "https://stat.ripe.net/data/network-info/data.json?resource=8.8.8.8" | jq '.data'
# Reverse DNS sweep (in-scope ranges only)
prips 203.0.113.0/22 | xargs -I {} -P 50 sh -c \
  'PTR=$(dig +short -x {}); [ -n "$PTR" ] && echo "{} -> $PTR"'
# TLS deep audit
pip install sslyze && sslyze --regular target.example:443
docker run --rm -ti drwetter/testssl.sh https://target.example
# Flag: TLS 1.0/1.1 (MED), SSLv3 (HIGH), RC4/3DES (MED), weak key <2048 (HIGH),
#       Heartbleed (CRIT), ROBOT/CCS/Ticketbleed (HIGH), expired cert (MED)
# JARM clustering: jarm <host>:443 → search Shodan ssl.jarm:<hash> for shared infra/origin
```
Source: `offensive-osint/references/recon-stack.md` §28.

---

## Common Root Causes

1. **Keyword-matched ownership.** ASM/scanner tooling matches a brand word in a repo/bucket/app/combo name and labels it "owned." Bucket names are a global namespace; breach combos contain sibling-named-but-different companies. Source: `recon-scope-triage/SKILL.md`.
2. **Soft-404 catch-alls.** SPAs/frameworks return HTTP 200/403 for every path, so `.env`/`.git`/`actuator` "Criticals" are false. Always run the junk-path control. Source: `recon-scope-triage/SKILL.md`.
3. **Secrets committed to repos and artifacts.** `.env`, config files, build logs, package tarballs, sourcemaps, Postman workspaces, Stack Exchange pastes. 5 of the Top 100 reports involved leaked credentials in code/build artifacts. Source: `recon-and-leaks.md`.
4. **Debug/admin defaults left enabled.** Jenkins script console, Tomcat manager, Spring actuators, phpinfo, unauthenticated Elasticsearch/MongoDB/Redis/Docker API, open K8s API/kubelet/etcd.
5. **Forgotten trust surfaces.** Staging/preprod/UAT/sandbox and partner/vendor portals with weaker auth; `mail.`/`ftp.`/`cpanel.`/`dev.` outside the CDN; cross-TLD sibling domains missed by `*.target.com`-only enumeration.
6. **Permissive email posture.** DMARC `p=none` or absent + SPF `~all` → spoof feasible; ≥10-mechanism SPF exceeds lookup limit. Source: `osint-methodology/SKILL.md` §16.14.
7. **Dangling DNS / unclaimed cloud resources.** Stale CNAMEs → takeover → trusted-domain phishing. Scanner fingerprints false-positive on "still owned, just empty" (GitHub Pages 404 vs "There isn't a GitHub Pages site here").
8. **Schema disclosure by default.** Swagger/OpenAPI routes left enabled in production; GraphQL introspection on; field-suggestion ("did you mean") enabled even when introspection is disabled.
9. **Single-source attribution.** Favicon-hash overlap, shared CT issuer, shared NS, JARM match treated as ownership; vendor labels treated as ground truth; 1:1 bridge-flow assumptions in web3.
10. **CT-log and archive lag.** New certs take minutes-to-hours to surface; Wayback snapshots are best-effort — absence ≠ nonexistence.
11. **Untyped asset strings.** Findings written against free-floating strings instead of typed assets with provenance; no confidence-upgrade path documented.
12. **Detection ignored.** Continuing to probe after 429/captcha/WAF/status drift; pasting real PII/creds into cloud LLMs. Source: `osint-methodology/SKILL.md` §6.4, §26.

---

## Bypass Techniques (WAF/CDN/asset-hiding defeats)

### Origin Discovery Behind CDN (8 techniques — `osint-methodology/SKILL.md` §27)

1. **Historical DNS pivot** — SecurityTrails / PassiveTotal / DNSDB / Validin / Censys host search: find an IP that resolved 1–5 years ago and is *not* in the current CDN's ranges.
2. **Certificate SAN pivot** — crt.sh `?q=%.<target>&exclude=expired`; cross-reference certs; `cero` to pull certs from candidate IPs.
3. **Favicon mmh3 + JARM clustering** — Shodan `http.favicon.hash:<h>` / Censys `services.http.response.favicons.hashes:<h>`; `ssl.jarm:<hash>`; IPs outside CDN ranges = origin candidates.
4. **Direct IP + Host header** — `curl -sk -H "Host: target.example" https://<candidate-IP>/`; matching title/body fingerprint confirms origin.
5. **`mail.*` / `ftp.*` / `cpanel.*` / `direct.*` / `origin.*` / `dev.*` exceptions** — auxiliary subdomains often skip the CDN and share the origin IP.
6. **Error-page / header leakage** — Cloudflare 5xx details, 502/504 confirms live origin, `X-Cache: MISS from <origin-host>`, leaked `X-Powered-By` / `X-Backend-Server`.
7. **Email-bounce trick** — send to a nonexistent address from a sock puppet; `Received:` headers reveal mail-server IPs sometimes co-located with the origin.
8. **Confidence rule** — DNS history alone TENTATIVE; Host-header content match FIRM; + cert SAN + favicon match CONFIRMED.

### Asset-Hiding / Scanner Defeats

- **Junk-path control** defeats soft-404s and catch-all "Criticals" (see `recon-scope-triage/SKILL.md`).
- **Exact-response-string check** for takeover: GitHub Pages "There isn't a GitHub Pages site here" = takeover; "Page not found · GitHub Pages" = still owned. CloudFront "The request could not be satisfied" + `X-Cache: Error from cloudfront` = candidate; "Error - 404" = exists.
- **CT fallback chain** defeats crt.sh 502/503 (see pipeline above).
- **Toolchain fallback** for `dnsx`/`httpx` SIGSEGV on macOS arm64: `dig + curl` loop (~24 hosts/14s; fine for <100 hosts, fix toolchain for 1000+).
- **Full Swagger path list** defeats "404 on `/swagger`"; .NET specs route under `/api/swagger/v1/swagger.json`, Java under `/v3/api-docs`, Python under `/docs`.
- **Field-suggestion enumeration** (`clairvoyance`, GraphQL-Cop, InQL) defeats disabled introspection; alias batching and nested-depth probes defeat rate limits/depth checks.
- **Multi-engine dork corpus** with per-engine token buckets defeats single-engine coverage gaps and bans.

### Detection-Aware Back-Off (`osint-methodology/SKILL.md` §6.4)

Signs: 429 / `Retry-After` → captcha interstitial → WAF page → status drift (403 only from your IP) → banner change → NXDOMAIN poisoning → honeypot bait → direct contact. Ladder: halve concurrency + jitter → switch endpoint → switch persona/UA/TLS fingerprint → switch egress → pause 1–24h → stop and consult lead. Never outsmart a confirmed WAF block or switch IPs to evade an explicit block-list; that risks scope violation. Use sock puppets with aged history for people-OSINT; LinkedIn profile views accumulate suspicion — throttle <20/day per persona, never connect from the corporate persona.

### Sector Caution

ICS/SCADA assets (Modbus `:502`, BACnet `:47808`, S7 `:102`, DNP3 `:20000`) run on legacy systems where even passive scanning can disrupt — do not actively probe without explicit RoE coverage and OT-team coordination. Source: `offensive-osint/references/sector-notes.md`.

---

## Gate 0 Validation

Before writing any finding, confirm all of the following:

1. **Is the asset actually owned by the target?**
   - Concrete ownership signal tied to the canonical domain set (repo owner/org email, bucket content + matching subdomain, package reverse-DNS/dev cert, exact `@target.com` domain).
   - Unknowns quarantined, not tested. Soft-404 junk control run. Source: `recon-scope-triage/SKILL.md`.

2. **What can the attacker DO right now?**
   - Show the exposed secret validated read-only (scope/account ID), or the listable bucket's object listing, or the reachable admin console/spec — not just "a scanner flagged it."
   - For takeover: exact "available for claim" response string, not a generic 404.

3. **What does the victim LOSE?**
   - Quantify: credentials → account/cloud compromise; PII → regulatory notification; takeover → trusted-domain phishing; `SSO_EXPOSURE` → staff credential reuse at the IdP. Score against the 0–100 endpoint interest rubric and severity matrix; escalate per the rules (`p=none` MEDIUM, KEV CRITICAL, ≥10 breached employees CRITICAL).

4. **What is the confidence level?**
   - TENTATIVE (one weak signal / snippet-only) → FIRM (directly observed) → CONFIRMED (independent corroboration). Rule of three: 3 weak OR 1 strong + 1 weak. Never claim CONFIRMED on a single source; downgrade when in doubt.

5. **Can it be reproduced in 10 minutes from scratch?**
   - Still live, control path differs from junk path, validator response stable, second person can follow the steps. Record URL + UTC + SHA-256 + tool version + `run_id`.

6. **Was the work within scope and detectability?** Passive by default; active only if authorized; validator read-only; no PII/creds pasted into cloud LLMs; back-off signals respected. If RoE forbids validation, mark `validation_skipped_by_policy` and stop.

---

## Real Impact Examples

All scenarios are grounded in the curated source skills; no report IDs are asserted.

**Scenario A — Breach × identity → SSO_EXPOSURE (CRITICAL).** Recon enumerated employees on LinkedIn, derived `alice.doe@acme.com`, and fingerprinted an Entra tenant via OIDC metadata (tenant GUID). HudsonRock Cavalier + HIBP returned the derived email with a cleartext password. Intersecting the tenant domain with the breach corpus produced 14 employee hits → `SSO_EXPOSURE` CRITICAL. Even with MFA, password reuse against other services persists; legacy-mail NXDOMAIN plus confirmed cloud migration escalates regardless of the dead host. Source: `hunt-skills/osint-methodology/SKILL.md` §22, `hunt-skills/offensive-osint/references/recon-techniques.md` §41.

**Scenario B — Live AWS key from a public repo → cloud pivot.** A GitHub code-search dork (`"{target}" AWS_ACCESS_KEY_ID`) matched a `.env`. The regex catalog flagged `AKIA…`; `sts:GetCallerIdentity` (read-only) returned an account ID → CRITICAL. Pivots: S3 bucket enumeration scoped by that account, IAM policy review, CloudTrail audit. Source: `hunt-skills/bountyforge/references/recon-and-leaks.md`, `hunt-skills/offensive-osint/SKILL.md` §23.

**Scenario C — Exposed Jenkins script console → RCE.** A subdomain `jenkins.<target>` responded to `/script` with "Script Console"; Groovy script execution = code execution in the CI context, which typically holds deploy keys and cloud creds. Same class: Grafana `/api/search` dashboards leaking DB queries/API keys; `curl /api/json | jq '.jobs[].name'` enumerating pipeline names. Source: `hunt-skills/bountyforge/references/hacking-agents/recon-agent.md`.

**Scenario D — Dictionary-word brand collision → triage meta-finding.** An ASM export showed hundreds of "Critical" findings for a brand named "apex." Repo, bucket, app, and combo checks showed most were other companies sharing the word; `.env` "Criticals" were soft-404s. After ownership + soft-404 triage, the real count collapsed to a handful; the misallocated remediation budget was itself written up as a Medium/Strategic meta-finding. The one genuine high-severity issue came from manual JS-bundle → API discovery, not the scanner feed. Source: `hunt-skills/recon-scope-triage/SKILL.md`.

**Scenario E — Stale CNAME → trusted-domain phishing (HIGH).** `old.<target>` resolved to an unclaimed `<x>.herokuapp.com` returning the exact "No such app" signature. Registering the resource would serve content on the target's trusted domain, bypassing brand-impersonation defenses. Procedure stops and consults the engagement lead before going live with phishing content. Source: `hunt-skills/offensive-osint/references/probes-and-wordlists.md` §16.12, `hunt-skills/osint-methodology/SKILL.md` §29.2.

**Scenario F — Public Postman workspace → API map + secrets (MEDIUM/HIGH).** Postman universal-search for the target domain returned a public workspace; walking collections exposed internal request URLs, pre-request scripts, and env vars. The secret catalog hit an internal API token, and request URLs containing `*.target.com` gave the strongest ownership signal. Source: `hunt-skills/offensive-osint/references/saas-public-surfaces.md` §24.

**Scenario G — Sourcemap exposure → full frontend reconstruction (HIGH).** Probe `<bundle>.js.map` returned `sourcesContent[]` with original sources; grep revealed internal hostnames, an AWS key, and a GraphQL client_id. Internal IP matches in JS = MEDIUM `INFO_DISCLOSURE`; key validated read-only = HIGH/CRITICAL `SECRET_LEAK`. Source: `hunt-skills/osint-methodology/SKILL.md` §13, `hunt-skills/bountyforge/skills/web2-recon/SKILL.md`.

---

## Source Skill Lineage

Full corpus: `E:\webt\skill-setup\skills-extract-from-reports\hunt-osint-recon\references\source-knowledge.md`. All 21 source file paths are listed below, grouped by family with the unique contribution each made.

**BountyForge family (3 files)**

- `hunt-skills/bountyforge/references/hacking-agents/recon-agent.md` — Passive/active recon agent framing; subdomain enum, HTTP surface mapping, secret exposure, API/GraphQL, cloud/infrastructure hunting (exposed CI/CD, Grafana, K8s API, Spring actuators), Web3 contract surface checks, and the `asset_type/discovery_method/evidence/takeover_possible` output fields.
- `hunt-skills/bountyforge/references/recon-and-leaks.md` — Technology-fingerprinting table, 14-item quick-wins checklist, credential-leak hunting token-type table, GitHub `gh api` search recipes, Travis/GitHub Actions build-log secrets, Docker image inspection, and language-specific dangerous-code grep patterns.
- `hunt-skills/bountyforge/skills/web2-recon/SKILL.md` — "Trust-first" asset discovery; standard recon pipeline, trust-boundary discovery grep tiers, JS deep-analysis greps, tech-stack→bug-class map, 5-minute rule, and target scoring table.

**Offensive-OSINT family (14 files)**

- `hunt-skills/offensive-osint/README.md` — Trigger-phrase inventory, reference-file index, helper-script (`secret_scan.py`) and self-test pointers; scope of the 51-section arsenal.
- `hunt-skills/offensive-osint/SKILL.md` — Principles (authorization, confidence, output/hygiene, Do-NOT), reference index, §20 endpoint interest score, §21 mobile ownership confidence, §39 attack-path hint templates, §49 self-test.
- `hunt-skills/offensive-osint/references/dork-corpus.md` — 80+ dork templates in 9 categories, result classification by URL signature/title/snippet, and 13 GitHub code-search dorks with rate-limit guidance.
- `hunt-skills/offensive-osint/references/helpers-and-automation.md` — AI-assisted OSINT, archiving/evidence preservation, automation workflows, cross-module JSON sidecar coordination, and runnable `secret_scan.py` / `h1_reference.py` / `dashboard.py` helpers.
- `hunt-skills/offensive-osint/references/identity-fabric.md` — Concrete Entra/Okta/ADFS/Google/generic-OIDC endpoints, AWS account-ID extraction regexes, M365 deep enumeration (Teams/SharePoint/OneDrive/OAuth), and GraphQL field-suggestion enumeration.
- `hunt-skills/offensive-osint/references/people-osint.md` — Search engines, username/email investigation tools, people search, phone OSINT, social-media tooling, and public-records/company registries incl. RU/CN registries and USCC+ICP workflow.
- `hunt-skills/offensive-osint/references/probes-and-wordlists.md` — Pre-built probe paths: 28 Swagger, 13 GraphQL, 35 high-risk ports, 6 security headers, 15 always-on checks, 5 SAML paths, 8 SSO prefixes, cloud-bucket arsenal, JS guess-paths, endpoint-extraction tiers, internal-host leakage regexes, 27 takeover fingerprints, curl one-liners, email-security analysis, origin/CDN bypass.
- `hunt-skills/offensive-osint/references/recon-stack.md` — Subdomain-source stack, crt.sh fallback chain, wordlist sources/size guidance, ASN/BGP bulk recipes, CT monitoring, JARM/TLS deep audit, reverse-DNS sweep, IPv6 enumeration.
- `hunt-skills/offensive-osint/references/recon-techniques.md` — LinkedIn employee enumeration and role tiers, job-posting tech-stack analysis, Slack/Discord/Teams workspace discovery, package-registry leak hunting + typosquat surveillance, and satellite imagery for physical recon.
- `hunt-skills/offensive-osint/references/saas-public-surfaces.md` — Postman public-workspace universal search (verified endpoint shape), Stack Exchange OSINT sweep with API + code-block regex, and public Trello/Notion/Confluence/Miro dork stack.
- `hunt-skills/offensive-osint/references/sector-notes.md` — Sector recon for healthcare (DICOM/HL7/FHIR), finance (SWIFT/FIX), ICS/SCADA (Modbus/BACnet, with caution), IoT, government, maritime/aviation/auto, and the universal-sector caveat.
- `hunt-skills/offensive-osint/references/severity-matrix.md` — 80+ worked examples mapping observed conditions to CRITICAL/HIGH/MEDIUM/LOW/INFO, incl. escalation rules and legacy-mail/SSO exposure patterns.
- `hunt-skills/offensive-osint/references/specialized-osint.md` — Threat intel/IOC feeds, CVE prioritization data sources, blockchain/L2 explorers, reverse-image/media/geo/regional/messaging OSINT, and threat-actor attribution discipline.
- `hunt-skills/offensive-osint/references/tooling-install.md` — Quick-install one-liners for Subfinder, Amass, httpx, nuclei, naabu, masscan, katana, gau, cloud_enum, trufflehog, PDTM, reconftw, Axiom.

**OSINT-Methodology family (2 files)**

- `hunt-skills/osint-methodology/README.md` — "How to think" overview: 5-stage pipeline, asset graph, findings rubric, breach×identity correlation, WAF/CDN bypass, vulnerability prioritization, phishing infra, reporting templates.
- `hunt-skills/osint-methodology/SKILL.md` — Authorization/confidence/output/hygiene/Do-NOT rules, sock puppets and detectability tagging, validator discipline, back-off ladder, 5-stage pipeline + priority order + time budgets, asset taxonomy, findings rubric, scale-based tactics, identity-fabric/API/JS/mobile/cloud methodology, breach correlation, WAF/CDN origin discovery, CVE prioritization, phishing/pretext, bug-bounty and client-deliverable templates, anti-patterns.

**Scope-Triage family (1 file)**

- `hunt-skills/recon-scope-triage/SKILL.md` — Ownership-guilty-until-proven rule, collision sources by asset class, soft-404 junk-path control, triage workflow, anti-patterns, and the dictionary-word-brand calibration note.

**Web2-Recon family (1 file)**

- `hunt-skills/web2-recon/SKILL.md` — Executable web2 pipeline (Chaos key, crt.sh, subfinder, dnsx, httpx, katana, gau, nuclei), parameter/endpoint greps, gf candidate classes, SecretFinder/LinkFinder, ffuf, target scoring GO/NO-GO, stack→bug-class map, continuous monitoring, 2024–2026 Swagger/OpenAPI path corpus, recon-to-hunting handoff, and operator notes (cross-TLD pivot, 2026 subdomain prefixes, soft-404/takeover response-string distinctions, toolchain fallback).

---

## Related Skills & Chains

- **`web2-recon`** — Execute the pipeline this skill scopes. Primitive: this skill produces the verified asset set and scoring; `web2-recon` runs subfinder → dnsx → httpx → katana → nuclei and outputs `live-hosts.txt` / `urls.txt`.
- **`offensive-osint`** — Load when concrete probes, dorks, regexes, or validators are needed. Primitive: `osint-methodology` plans, `offensive-osint` fills each stage with curl one-liners; this skill is the compact entry point to both.
- **`osint-methodology`** — Load for the full planning framework, findings rubric, confidence-upgrade workflows, and reporting templates.
- **`hunt-subdomain`** — Route any verified stale CNAME / dangling DNS (S3, GitHub Pages, Heroku, Shopify, Azure) auto-routed from the asset graph for takeover validation.
- **`hunt-cloud-misconfig`** — Route listable buckets, `/actuator/env`, open Firebase/Elasticsearch/Redis findings for exploitation-class follow-up.
- **`hunt-spa-api`** / **`hunt-api-misconfig`** — Once an API host passes ownership triage and a Swagger/GraphQL spec is found, hand off for IDOR/BOLA and mass-assignment testing; NSwag/Swagger/OpenAPI exposure chains to `hunt-api-misconfig`.
- **`m365-entra-attack`** / **`okta-attack`** — When identity-fabric fingerprinting identifies Entra/Okta, the matched platform skill takes over active enumeration.
- **`triage-validation`** — Ownership triage (this skill) precedes finding-validity triage; apply the Gate 0 checks before submission.
- **`security-arsenal`** — `gf xss/ssrf/sqli/idor/redirect/lfi/rce` output becomes payload-class queries against the payload library.
- **`cloud-iam-deep`** — A validated cloud key from the secret sweep hands off to IAM privilege escalation.
- **`bb-methodology`** — When recon completes, hand the live host + URL set to Phase 2 (Mapping) and Phase 3 (vulnerability discovery routing).
- **`redteam-mindset`** — "Aggressive default" applies only to *owned* live surfaces; this skill defines which surfaces are owned.
- **Web2 → Web3 handoff** — Web2 recon (domains, subs, JS, repos, packages) establishes the project's web presence; Web3 targets (unverified contracts, EOA proxyAdmin, timelock delay, bridge/L2 flows) continue in `hunt-skills/offensive-osint/references/specialized-osint.md` §30 with the methodology's §16 transaction-analysis cautions (bridges mint/burn; optimistic rollups have a 7-day challenge window; don't assume 1:1 flows).

---

**Summary.** `hunt-osint-recon` is a compact entry point to 21 curated OSINT/recon source skills. It front-loads scope and ownership triage, then runs a 5-stage pipeline (seed → expand → enrich → expose → report) across subdomains, cloud buckets, identity fabric, API specs, JS bundles, secrets, breach corpora, and people/SaaS surfaces. Findings are confidence-tagged, severity-scored, read-only validated, and gated on ownership + reproducibility before handoff to exploitation skills. No bug-bounty reports were read; every technique is cited to its source skill path, and the full corpus is archived in `references/source-knowledge.md`.
